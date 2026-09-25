//! HTTP client factory with optional proxy support.
//!
//! Centralises `reqwest` client construction so that every outbound HTTP call
//! (anchor discovery, webhook delivery, SEP-6 status) honours the same proxy
//! configuration without duplicating builder logic.
//!
//! # Proxy configuration
//!
//! [`ProxyConfig`] carries an optional catch-all `proxy_url` (e.g.
//! `"http://proxy.corp:3128"`), optional per-scheme `http_proxy_url` /
//! `https_proxy_url` overrides, an optional `no_proxy` bypass list, and
//! optional [`ProxyCredentials`] for proxies requiring Basic authentication.
//! Pass it to [`build_client`] to get a `reqwest::blocking::Client` that
//! routes requests through the selected proxy.
//!
//! Selection precedence for a given request: the scheme-specific proxy
//! (`http_proxy_url` / `https_proxy_url`) wins over `proxy_url`; hosts on the
//! `no_proxy` list bypass all proxies. [`ProxyConfig::select_proxy_url`]
//! exposes this decision as a pure function for testing and logging.
//!
//! When no proxy URL is configured the returned client uses the system
//! default (respects `HTTP_PROXY` / `HTTPS_PROXY` environment variables).
//!
//! # Credential handling
//!
//! Two kinds of credentials are supported, both designed to stay out of logs:
//!
//! - [`ProxyCredentials`] — username/password sent to the *proxy* via
//!   `Proxy-Authorization` (Basic). Set on [`ProxyConfig::credentials`].
//! - [`RequestCredentials`] — bearer token, Basic auth, or a custom header
//!   sent to the *target* endpoint. Set on
//!   [`OutboundRequestOptions::credentials`].
//!
//! Both types redact secrets from their `Debug` output and zeroize their
//! memory on drop. Prefer these fields over embedding `user:pass@` in URLs,
//! which end up in error messages verbatim.
//!
//! Call [`ProxyConfig::validate`] (done automatically by [`build_client`] and
//! the runtime-config loader) to reject malformed URLs and credential
//! combinations early.
//!
//! # Examples
//!
//! ```rust
//! use anchorkit::http_client::{ProxyConfig, ProxyCredentials};
//!
//! // Explicit proxy with credentials and an HTTPS-specific override.
//! let proxy = ProxyConfig {
//!     proxy_url: Some("http://proxy.corp.example.com:3128".to_string()),
//!     https_proxy_url: Some("http://tls-proxy.corp.example.com:3129".to_string()),
//!     no_proxy: Some("localhost,127.0.0.1".to_string()),
//!     credentials: Some(ProxyCredentials {
//!         username: "svc-anchor".to_string(),
//!         password: "hunter2".to_string(),
//!     }),
//!     ..ProxyConfig::default()
//! };
//! assert!(proxy.validate().is_ok());
//! assert_eq!(
//!     proxy.select_proxy_url("https://anchor.example.com/sep6"),
//!     Some("http://tls-proxy.corp.example.com:3129"),
//! );
//! assert_eq!(proxy.select_proxy_url("http://localhost/health"), None);
//! ```
//!
//! On `std` builds, pass the config to [`build_client`] /
//! [`build_client_with_policy`] to obtain a `reqwest::blocking::Client` that
//! applies the same routing (`build_client(None, 30)` uses system defaults).

#[cfg(feature = "std")]
extern crate std;

extern crate alloc;
use alloc::string::String;

use crate::trace_context::TraceContext;

// ---------------------------------------------------------------------------
// Idempotency and request signing support
// ---------------------------------------------------------------------------

/// Options for idempotency and signing on a single outbound request.
///
/// Attach this to any outbound HTTP call to get:
/// - An `Idempotency-Key` header that lets the server safely deduplicate
///   replayed submissions.
/// - An `X-Request-Id` header that threads the same identifier through logs
///   and downstream services for correlation.
/// - HMAC-SHA256 signing via `X-Anchor-Signature: sha256=<hex>`, identical
///   to the webhook signing mechanism so verification helpers are shared.
///
/// All fields are optional; omit those you do not need.
///
/// # Examples
///
/// ```rust
/// use anchorkit::http_client::OutboundRequestOptions;
///
/// // Auto-generate an idempotency key from a stable seed (e.g. txn ID).
/// let opts = OutboundRequestOptions::with_idempotency_key("txn-001-deposit");
///
/// // Add HMAC signing on top.
/// let opts = OutboundRequestOptions::with_idempotency_key("txn-001-deposit")
///     .with_signing_key(b"my-secret-key");
///
/// // Authenticate against the anchor with a bearer token.
/// let opts = OutboundRequestOptions::with_idempotency_key("txn-001-deposit")
///     .with_bearer_token("sep10-jwt-token");
/// ```
#[derive(Clone, Default)]
pub struct OutboundRequestOptions {
    /// Idempotency key sent as `Idempotency-Key: <value>`.
    /// When `Some`, also sent as `X-Request-Id: <value>` for correlation.
    pub idempotency_key: Option<String>,
    /// HMAC-SHA256 signing key. When `Some`, adds
    /// `X-Anchor-Signature: sha256=<hex>` computed over the request body.
    pub signing_key: Option<alloc::vec::Vec<u8>>,
    /// Trace context for this request. When `Some`, adds `traceparent`,
    /// `X-Trace-Id` and `X-Span-Id` headers so the anchor's logs can be
    /// correlated with ours.
    pub trace: Option<TraceContext>,
    /// Endpoint authentication credentials. When `Some`, adds an
    /// `Authorization` (or custom) header computed via
    /// [`RequestCredentials::to_header`].
    pub credentials: Option<RequestCredentials>,
}

/// `Debug` keeps secret-bearing fields out of formatted output: the HMAC
/// `signing_key` is shown only as a presence marker, and `credentials` is
/// rendered through [`RequestCredentials`]'s own redacting `Debug`, so an
/// `Authorization` (bearer/basic) or custom auth header value never appears —
/// even when options are logged on an outbound failure. Non-secret fields
/// (idempotency key, trace, Basic username, custom header name) stay visible
/// for diagnostics. The header actually sent on the wire is unaffected.
impl core::fmt::Debug for OutboundRequestOptions {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OutboundRequestOptions")
            .field("idempotency_key", &self.idempotency_key)
            .field("signing_key", &self.signing_key.as_ref().map(|_| "<redacted>"))
            .field("trace", &self.trace)
            .field("credentials", &self.credentials)
            .finish()
    }
}

impl OutboundRequestOptions {
    /// Create options with a caller-supplied idempotency key.
    pub fn with_idempotency_key(key: impl Into<String>) -> Self {
        OutboundRequestOptions {
            idempotency_key: Some(key.into()),
            signing_key: None,
            trace: None,
            credentials: None,
        }
    }

    /// Attach an HMAC-SHA256 signing key to this options set.
    pub fn with_signing_key(mut self, key: &[u8]) -> Self {
        self.signing_key = Some(key.to_vec());
        self
    }

    /// Attach an explicit [`RequestCredentials`] value to this options set.
    ///
    /// The `with_bearer_token` / `with_basic_auth` / `with_header_credential`
    /// helpers are shorthands for the common variants.
    pub fn with_credentials(mut self, credentials: RequestCredentials) -> Self {
        self.credentials = Some(credentials);
        self
    }

    /// Attach a bearer-token credential to this options set.
    pub fn with_bearer_token(mut self, token: impl Into<String>) -> Self {
        self.credentials = Some(RequestCredentials::Bearer(token.into()));
        self
    }

    /// Attach an HTTP Basic-auth credential to this options set.
    pub fn with_basic_auth(mut self, username: impl Into<String>, password: impl Into<String>) -> Self {
        self.credentials = Some(RequestCredentials::Basic {
            username: username.into(),
            password: password.into(),
        });
        self
    }

    /// Attach an arbitrary header credential (e.g. `X-Api-Key`) to this options set.
    pub fn with_header_credential(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.credentials = Some(RequestCredentials::Header {
            name: name.into(),
            value: value.into(),
        });
        self
    }

    /// Attach a trace context to this options set.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use anchorkit::http_client::OutboundRequestOptions;
    /// use anchorkit::trace_context::TraceContext;
    ///
    /// let trace = TraceContext::root_from_seed("txn-001");
    /// let opts = OutboundRequestOptions::with_idempotency_key("txn-001")
    ///     .with_trace(&trace);
    ///
    /// let names: Vec<String> = opts.build_headers("{}").into_iter().map(|(k, _)| k).collect();
    /// assert!(names.contains(&"traceparent".to_string()));
    /// ```
    pub fn with_trace(mut self, trace: &TraceContext) -> Self {
        self.trace = Some(trace.clone());
        self
    }

    /// Derive a deterministic idempotency key from `seed` using a short
    /// hex prefix of `SHA-256(seed_bytes)`.
    ///
    /// This is useful when you want a stable key derived from a transaction ID
    /// or other stable identifier without storing state.
    pub fn from_seed(seed: &str) -> Self {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(seed.as_bytes());
        let digest = hasher.finalize();
        // Use first 16 bytes (32 hex chars) as the key — short but collision-resistant.
        let hex: String = digest[..16]
            .iter()
            .fold(String::new(), |mut s, b| {
                s.push_str(&alloc::format!("{:02x}", b));
                s
            });
        OutboundRequestOptions {
            idempotency_key: Some(hex),
            signing_key: None,
            trace: None,
            credentials: None,
        }
    }

    /// Build the extra headers that should be sent with an outbound request.
    ///
    /// Returns a list of `(header_name, header_value)` pairs.
    /// - `Idempotency-Key` — when `idempotency_key` is set to a non-empty value.
    /// - `X-Request-Id` — same value as `Idempotency-Key` (correlation).
    /// - `X-Anchor-Signature: sha256=<hex>` — when `signing_key` is set.
    /// - `traceparent`, `X-Trace-Id`, `X-Span-Id` — when `trace` is set.
    pub fn build_headers(&self, body: &str) -> alloc::vec::Vec<(String, String)> {
        let mut headers = alloc::vec::Vec::new();
        // Only emit the idempotency key when it is non-empty, consistent with
        // `has_idempotency_key`.  An empty `Some("")` is treated the same as
        // `None` — it would produce an `Idempotency-Key: ` header with a blank
        // value, which is useless for deduplication and inconsistent with how
        // `has_idempotency_key` reports the key's presence.
        if let Some(ref key) = self.idempotency_key {
            if !key.is_empty() {
                headers.push(("Idempotency-Key".into(), key.clone()));
                headers.push(("X-Request-Id".into(), key.clone()));
            }
        }
        if let Some(ref sk) = self.signing_key {
            let sig = compute_hmac_hex(sk, body);
            headers.push(("X-Anchor-Signature".into(), alloc::format!("sha256={}", sig)));
        }
        if let Some(ref trace) = self.trace {
            headers.extend(trace.header_pairs());
        }
        if let Some(ref creds) = self.credentials {
            headers.push(creds.to_header());
        }
        headers
    }

    /// Return `true` when this options set carries a trace context.
    pub fn has_trace(&self) -> bool {
        self.trace.is_some()
    }

    /// Return `true` when this options set includes an idempotency key.
    pub fn has_idempotency_key(&self) -> bool {
        self.idempotency_key.as_deref().map(|s| !s.is_empty()).unwrap_or(false)
    }

    /// Return `true` when this options set includes a signing key.
    pub fn has_signing_key(&self) -> bool {
        self.signing_key.as_ref().map(|k| !k.is_empty()).unwrap_or(false)
    }

    /// Return `true` when this options set includes endpoint credentials.
    pub fn has_credentials(&self) -> bool {
        self.credentials.is_some()
    }

    /// Validate the options, rejecting credential values that would produce
    /// malformed or header-injecting requests. See
    /// [`RequestCredentials::validate`].
    pub fn validate(&self) -> Result<(), String> {
        if let Some(ref creds) = self.credentials {
            creds.validate()?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// RequestCredentials — endpoint authentication
// ---------------------------------------------------------------------------

/// Credentials injected into outbound requests to the *target* endpoint
/// (as opposed to [`ProxyCredentials`], which authenticate to the proxy).
///
/// Secrets are redacted from `Debug` output and zeroized on drop.
///
/// # Variants
///
/// - `Bearer` — `Authorization: Bearer <token>` (e.g. a SEP-10 JWT).
/// - `Basic` — `Authorization: Basic <base64(user:pass)>`.
/// - `Header` — an arbitrary header, e.g. `X-Api-Key: <value>`, for anchors
///   with non-standard authentication schemes.
///
/// # Examples
///
/// ```rust
/// use anchorkit::http_client::RequestCredentials;
///
/// let bearer = RequestCredentials::Bearer("jwt-token".into());
/// assert_eq!(bearer.to_header().0, "Authorization");
///
/// // Secrets never appear in Debug output.
/// let shown = format!("{:?}", bearer);
/// assert!(!shown.contains("jwt-token"));
/// ```
#[derive(Clone, PartialEq, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub enum RequestCredentials {
    /// Bearer token sent as `Authorization: Bearer <token>`.
    Bearer(String),
    /// HTTP Basic credentials sent as `Authorization: Basic <base64>`.
    Basic {
        /// Basic-auth username. Must not contain `:`.
        username: String,
        /// Basic-auth password.
        password: String,
    },
    /// Arbitrary authentication header, e.g. `X-Api-Key`.
    Header {
        /// Header name (RFC 7230 token characters only).
        name: String,
        /// Header value.
        value: String,
    },
}

/// `Debug` redacts every secret; only usernames and header names are shown.
impl core::fmt::Debug for RequestCredentials {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RequestCredentials::Bearer(_) => f.debug_tuple("Bearer").field(&"<redacted>").finish(),
            RequestCredentials::Basic { username, .. } => f
                .debug_struct("Basic")
                .field("username", username)
                .field("password", &"<redacted>")
                .finish(),
            RequestCredentials::Header { name, .. } => f
                .debug_struct("Header")
                .field("name", name)
                .field("value", &"<redacted>")
                .finish(),
        }
    }
}

impl RequestCredentials {
    /// Produce the `(header_name, header_value)` pair for this credential.
    pub fn to_header(&self) -> (String, String) {
        use base64::Engine as _;
        match self {
            RequestCredentials::Bearer(token) => {
                ("Authorization".into(), alloc::format!("Bearer {}", token))
            }
            RequestCredentials::Basic { username, password } => {
                let raw = alloc::format!("{}:{}", username, password);
                let encoded = base64::engine::general_purpose::STANDARD.encode(raw.as_bytes());
                ("Authorization".into(), alloc::format!("Basic {}", encoded))
            }
            RequestCredentials::Header { name, value } => (name.clone(), value.clone()),
        }
    }

    /// Validate the credential material.
    ///
    /// Rejects empty tokens/usernames/header names, `:` in Basic usernames
    /// (ambiguous per RFC 7617), non-token characters in header names, and
    /// CR/LF anywhere (header injection).
    pub fn validate(&self) -> Result<(), String> {
        match self {
            RequestCredentials::Bearer(token) => {
                if token.is_empty() {
                    return Err("credentials: bearer token cannot be empty".into());
                }
                reject_ctl("bearer token", token)?;
            }
            RequestCredentials::Basic { username, password } => {
                if username.is_empty() {
                    return Err("credentials: username cannot be empty".into());
                }
                if username.contains(':') {
                    return Err("credentials: username cannot contain ':'".into());
                }
                reject_ctl("username", username)?;
                reject_ctl("password", password)?;
            }
            RequestCredentials::Header { name, value } => {
                if name.is_empty() {
                    return Err("credentials: header name cannot be empty".into());
                }
                let is_token_char = |c: char| {
                    c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '!' | '#' | '$' | '%' | '&' | '\'' | '*' | '+' | '^' | '`' | '|' | '~')
                };
                if !name.chars().all(is_token_char) {
                    return Err(alloc::format!(
                        "credentials: header name '{}' contains invalid characters", name
                    ));
                }
                reject_ctl("header value", value)?;
            }
        }
        Ok(())
    }
}

/// Reject control characters (notably CR/LF) that would allow header injection.
fn reject_ctl(what: &str, value: &str) -> Result<(), String> {
    if value.chars().any(|c| c.is_ascii_control()) {
        return Err(alloc::format!(
            "credentials: {} contains control characters", what
        ));
    }
    Ok(())
}

/// Compute `HMAC-SHA256(key, payload)` and return a lowercase hex string.
fn compute_hmac_hex(key: &[u8], payload: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(payload.as_bytes());
    let result = mac.finalize().into_bytes();
    result.iter().fold(String::new(), |mut s, b| {
        s.push_str(&alloc::format!("{:02x}", b));
        s
    })
}

/// Verify an `X-Anchor-Signature: sha256=<hex>` header value against a known
/// signing key and request body.
///
/// Uses constant-time comparison (XOR-fold) to prevent timing attacks.
///
/// # Arguments
///
/// * `body` — The raw request body that was signed.
/// * `signature_header` — The full header value, e.g. `"sha256=deadbeef..."`.
/// * `key` — The HMAC-SHA256 signing key.
///
/// # Returns
///
/// `true` when the signature matches; `false` otherwise.
pub fn verify_outbound_signature(body: &str, signature_header: &str, key: &[u8]) -> bool {
    let hex_digest = match signature_header.strip_prefix("sha256=") {
        Some(h) => h,
        None => return false,
    };
    if hex_digest.len() % 2 != 0 {
        return false;
    }
    let mut received: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(hex_digest.len() / 2);
    let mut chars = hex_digest.chars();
    loop {
        match (chars.next(), chars.next()) {
            (Some(a), Some(b)) => {
                let byte = match (a.to_digit(16), b.to_digit(16)) {
                    (Some(hi), Some(lo)) => (hi << 4 | lo) as u8,
                    _ => return false,
                };
                received.push(byte);
            }
            (None, None) => break,
            _ => return false,
        }
    }
    let expected_hex = compute_hmac_hex(key, body);
    let expected_bytes: alloc::vec::Vec<u8> = {
        let mut bytes = alloc::vec::Vec::with_capacity(expected_hex.len() / 2);
        let mut ec = expected_hex.chars();
        loop {
            match (ec.next(), ec.next()) {
                (Some(a), Some(b)) => {
                    if let (Some(hi), Some(lo)) = (a.to_digit(16), b.to_digit(16)) {
                        bytes.push((hi << 4 | lo) as u8);
                    } else {
                        return false;
                    }
                }
                (None, None) => break,
                _ => return false,
            }
        }
        bytes
    };
    if received.len() != expected_bytes.len() {
        return false;
    }
    let diff: u8 = received
        .iter()
        .zip(expected_bytes.iter())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b));
    diff == 0
}

/// Perform a signed and idempotent HTTP POST using an injectable transport closure.
///
/// This is the low-level building block for feature-b compliance. Production code
/// should use the higher-level `deliver_webhook_with_proxy` which wraps reqwest;
/// this function exists for testability without a live HTTP stack.
///
/// # Arguments
///
/// * `url` — The target URL.
/// * `body` — The request payload (typically JSON).
/// * `opts` — Optional [`OutboundRequestOptions`] adding idempotency/signing headers.
/// * `http_post` — Injectable transport: `(url, body, headers) -> Result<u16, String>`.
///
/// # Returns
///
/// HTTP status code on success, transport error string on failure.
pub fn post_with_options<H>(
    url: &str,
    body: &str,
    opts: Option<&OutboundRequestOptions>,
    mut http_post: H,
) -> Result<u16, String>
where
    H: FnMut(&str, &str, &[(String, String)]) -> Result<u16, String>,
{
    // Enforce the HTTPS transport requirement at the client boundary so a
    // direct caller cannot bypass it by handing us a cleartext endpoint.
    // This is a scheme-only guard: host shape, path, and IP-literal checks
    // remain the job of the shared domain validator and are not duplicated
    // here.
    if !is_https_endpoint(url) {
        return Err("outbound request rejected: endpoint URL must use the https:// scheme".into());
    }
    let headers = opts.map(|o| o.build_headers(body)).unwrap_or_default();
    http_post(url, body, &headers)
}

/// Returns `true` when `url` uses the `https://` scheme (case-insensitive).
///
/// Used to keep cleartext HTTP endpoints out of [`post_with_options`] and
/// [`post_with_options_metered`]; mirrors the scheme handling in
/// [`ProxyConfig::select_proxy_url`].
fn is_https_endpoint(url: &str) -> bool {
    url.get(.."https://".len())
        .map(|s| s.eq_ignore_ascii_case("https://"))
        .unwrap_or(false)
}

/// Like [`post_with_options`], additionally recording request metrics.
///
/// Emitted counters (see [`crate::metrics::names`]):
///
/// * [`names::HTTP_REQUESTS`] — one per call.
/// * [`names::HTTP_SUCCESSES`] — status below 400.
/// * [`names::HTTP_ERROR_RESPONSES`] — status 400 or above.
/// * [`names::HTTP_TRANSPORT_ERRORS`] — transport failure, no status received.
///
/// Delegates to [`post_with_options`] so request semantics stay identical.
///
/// [`names::HTTP_REQUESTS`]: crate::metrics::names::HTTP_REQUESTS
/// [`names::HTTP_SUCCESSES`]: crate::metrics::names::HTTP_SUCCESSES
/// [`names::HTTP_ERROR_RESPONSES`]: crate::metrics::names::HTTP_ERROR_RESPONSES
/// [`names::HTTP_TRANSPORT_ERRORS`]: crate::metrics::names::HTTP_TRANSPORT_ERRORS
pub fn post_with_options_metered<H>(
    url: &str,
    body: &str,
    opts: Option<&OutboundRequestOptions>,
    http_post: H,
    metrics: &crate::metrics::MetricsRegistry,
) -> Result<u16, String>
where
    H: FnMut(&str, &str, &[(String, String)]) -> Result<u16, String>,
{
    use crate::metrics::names;

    metrics.incr(names::HTTP_REQUESTS);
    let result = post_with_options(url, body, opts, http_post);
    match &result {
        Ok(status) if *status < 400 => metrics.incr(names::HTTP_SUCCESSES),
        Ok(_) => metrics.incr(names::HTTP_ERROR_RESPONSES),
        Err(_) => metrics.incr(names::HTTP_TRANSPORT_ERRORS),
    }
    result
}

// ---------------------------------------------------------------------------
// ConnectionPolicy — timeout and failure classification
// ---------------------------------------------------------------------------

/// Connection and timeout policy for outbound HTTP requests.
///
/// Controls how long the HTTP client waits at each phase of a connection.
/// All timeouts are in seconds; `0` means "no limit" for that phase.
///
/// # Design
///
/// Deterministic timeout behaviour prevents slow or misbehaving anchors from
/// hanging the caller indefinitely.  Each timeout targets a specific phase:
///
/// | Field | Phase | Default |
/// |---|---|---|
/// | `connect_timeout_secs` | TCP handshake + TLS negotiation | 10 s |
/// | `read_timeout_secs`    | Intended read budget (informational; not applied by reqwest 0.12 blocking) | 30 s |
/// | `total_timeout_secs`   | Total wall-clock budget (connect + read + transfer) | 60 s |
///
/// # Examples
///
/// ```rust
/// use anchorkit::http_client::ConnectionPolicy;
///
/// // Aggressive policy for time-sensitive flows.
/// let policy = ConnectionPolicy::aggressive();
/// assert_eq!(policy.connect_timeout_secs, 5);
///
/// // Conservative policy for batch / background fetches.
/// let policy = ConnectionPolicy::conservative();
/// assert_eq!(policy.total_timeout_secs, 120);
/// ```
#[derive(Clone, Debug, PartialEq)]
pub struct ConnectionPolicy {
    /// Maximum time in seconds to wait for the TCP connection + TLS handshake.
    /// Use `0` to rely on the OS default (not recommended in production).
    pub connect_timeout_secs: u64,
    /// Maximum time in seconds to wait for the first byte of the response after
    /// the request has been sent. Use `0` for no limit.
    pub read_timeout_secs: u64,
    /// Total wall-clock budget in seconds for the entire request lifecycle
    /// (connect + send + receive). Use `0` for no limit.
    pub total_timeout_secs: u64,
    /// When `true`, the client follows HTTP 3xx redirects automatically.
    /// Set to `false` to treat redirects as errors (useful for strict anchor
    /// endpoint compliance).
    pub follow_redirects: bool,
    /// Maximum number of redirects to follow when `follow_redirects` is `true`.
    /// Ignored when `follow_redirects` is `false`.
    pub max_redirects: usize,
}

impl Default for ConnectionPolicy {
    fn default() -> Self {
        ConnectionPolicy {
            connect_timeout_secs: 10,
            read_timeout_secs: 30,
            total_timeout_secs: 60,
            follow_redirects: true,
            max_redirects: 3,
        }
    }
}

impl ConnectionPolicy {
    /// Aggressive policy — suitable for interactive / latency-sensitive paths.
    ///
    /// Connect: 5 s, read: 15 s, total: 20 s. Redirects: disabled.
    pub fn aggressive() -> Self {
        ConnectionPolicy {
            connect_timeout_secs: 5,
            read_timeout_secs: 15,
            total_timeout_secs: 20,
            follow_redirects: false,
            max_redirects: 0,
        }
    }

    /// Conservative policy — for background discovery or batch operations.
    ///
    /// Connect: 20 s, read: 60 s, total: 120 s. Redirects: up to 5.
    pub fn conservative() -> Self {
        ConnectionPolicy {
            connect_timeout_secs: 20,
            read_timeout_secs: 60,
            total_timeout_secs: 120,
            follow_redirects: true,
            max_redirects: 5,
        }
    }

    /// Strict policy — no redirects, tight timeouts.
    /// Useful for SEP-10 auth flows where redirects would be suspicious.
    pub fn strict() -> Self {
        ConnectionPolicy {
            connect_timeout_secs: 8,
            read_timeout_secs: 20,
            total_timeout_secs: 30,
            follow_redirects: false,
            max_redirects: 0,
        }
    }
}

/// Classify a transport error string into `Timeout`, `ConnectionRefused`, or `Other`.
///
/// This enables deterministic retry behaviour: callers can branch on the failure
/// kind rather than parsing error messages ad hoc.
///
/// # Examples
///
/// ```rust
/// use anchorkit::http_client::{classify_transport_error, TransportErrorKind};
///
/// assert_eq!(
///     classify_transport_error("connection timed out"),
///     TransportErrorKind::Timeout,
/// );
/// assert_eq!(
///     classify_transport_error("connection refused"),
///     TransportErrorKind::ConnectionRefused,
/// );
/// assert_eq!(
///     classify_transport_error("DNS lookup failed for example.com"),
///     TransportErrorKind::DnsFailure,
/// );
/// ```
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum TransportErrorKind {
    /// The request timed out at any phase (connect, read, or total).
    Timeout,
    /// The remote refused the connection.
    ConnectionRefused,
    /// DNS resolution failed.
    DnsFailure,
    /// TLS handshake or certificate error.
    TlsError,
    /// Any other transport failure.
    Other,
}

/// Classify a transport error message into a [`TransportErrorKind`].
///
/// The classification is heuristic — it inspects the lowercase error string
/// for well-known substrings. This is sufficient for reqwest error messages,
/// which embed the reason in human-readable form.
pub fn classify_transport_error(msg: &str) -> TransportErrorKind {
    let lower = msg.to_ascii_lowercase();
    if lower.contains("timed out") || lower.contains("timeout") || lower.contains("deadline") {
        TransportErrorKind::Timeout
    } else if lower.contains("connection refused") || lower.contains("refused") {
        TransportErrorKind::ConnectionRefused
    } else if lower.contains("dns") || lower.contains("resolve") || lower.contains("no such host") {
        TransportErrorKind::DnsFailure
    } else if lower.contains("tls") || lower.contains("ssl") || lower.contains("certificate") || lower.contains("handshake") {
        TransportErrorKind::TlsError
    } else {
        TransportErrorKind::Other
    }
}

/// Returns `true` when a [`TransportErrorKind`] should trigger a retry.
///
/// Timeouts and DNS failures are transient; connection refused and TLS errors
/// are typically persistent and should not be retried blindly.
pub fn is_transport_error_retryable(kind: TransportErrorKind) -> bool {
    matches!(kind, TransportErrorKind::Timeout | TransportErrorKind::DnsFailure)
}

/// Retry classification for an HTTP response status code.
///
/// This is the response-status counterpart to [`TransportErrorKind`]: it lets
/// callers branch on whether a completed HTTP exchange should be retried under
/// their configured policy instead of hard-coding status checks at each call
/// site.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HttpStatusClass {
    /// 2xx / 3xx — the exchange completed without a server- or client-side error.
    Success,
    /// A transient failure. Retrying the same request may succeed. Covers
    /// `408 Request Timeout`, `429 Too Many Requests` (rate limiting is
    /// inherently temporary), and the transient `500`, `502`, `503`, `504`
    /// server errors.
    Retryable,
    /// A permanent failure. The request will keep failing until it is changed
    /// (most `4xx` client errors and non-transient `5xx` such as `501`).
    Permanent,
}

/// Classify an HTTP response status code into an [`HttpStatusClass`].
///
/// `429 Too Many Requests` maps to [`HttpStatusClass::Retryable`] — rate
/// limiting is a transient condition, not a permanent server error — so callers
/// applying [`is_http_status_retryable`] back off and retry rather than failing
/// the operation outright. Only the status code is inspected; any response body
/// or headers the caller has already captured are left untouched.
///
/// # Examples
///
/// ```rust
/// use anchorkit::http_client::{classify_http_status_code, HttpStatusClass};
///
/// assert_eq!(classify_http_status_code(200), HttpStatusClass::Success);
/// assert_eq!(classify_http_status_code(429), HttpStatusClass::Retryable);
/// assert_eq!(classify_http_status_code(503), HttpStatusClass::Retryable);
/// assert_eq!(classify_http_status_code(404), HttpStatusClass::Permanent);
/// ```
pub fn classify_http_status_code(status: u16) -> HttpStatusClass {
    match status {
        200..=399 => HttpStatusClass::Success,
        408 | 429 | 500 | 502 | 503 | 504 => HttpStatusClass::Retryable,
        _ => HttpStatusClass::Permanent,
    }
}

/// Returns `true` when an HTTP response status should trigger a retry.
///
/// Convenience predicate over [`classify_http_status_code`]; `true` exactly when
/// the status classifies as [`HttpStatusClass::Retryable`] (including `429`).
pub fn is_http_status_retryable(status: u16) -> bool {
    matches!(classify_http_status_code(status), HttpStatusClass::Retryable)
}

// ---------------------------------------------------------------------------
// ProxyConfig
// ---------------------------------------------------------------------------

/// Credentials for authenticating to a proxy (HTTP Basic).
///
/// Sent as `Proxy-Authorization: Basic <base64>` on connections through the
/// configured proxy. The password is redacted from `Debug` output and the
/// whole struct is zeroized on drop.
///
/// Prefer this field over embedding `user:pass@` in the proxy URL: URLs are
/// echoed verbatim into error messages and logs, credentials here are not.
#[derive(Clone, Default, PartialEq, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
#[cfg_attr(
    feature = "std",
    derive(serde::Serialize, serde::Deserialize),
    serde(deny_unknown_fields)
)]
pub struct ProxyCredentials {
    /// Proxy username. Must be non-empty and must not contain `:`.
    pub username: String,
    /// Proxy password.
    pub password: String,
}

/// `Debug` shows the username but always redacts the password.
impl core::fmt::Debug for ProxyCredentials {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ProxyCredentials")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .finish()
    }
}

/// Proxy settings for outbound HTTP requests.
///
/// Used by [`build_client`], [`fetch_stellar_toml_with_proxy`], and
/// [`deliver_webhook_with_proxy`] to route discovery and delivery traffic
/// through a corporate or gateway proxy.
///
/// # Fields
///
/// - `proxy_url` — Catch-all proxy URL including scheme and port, e.g.
///   `"http://proxy.corp.example.com:3128"` or `"https://proxy.example.com:8080"`.
///   When no proxy URL is set the client falls back to `HTTP_PROXY` /
///   `HTTPS_PROXY` env vars.
/// - `http_proxy_url` — Proxy used only for plain-HTTP target URLs.
///   Takes precedence over `proxy_url` for those requests.
/// - `https_proxy_url` — Proxy used only for HTTPS target URLs.
///   Takes precedence over `proxy_url` for those requests.
/// - `no_proxy`  — Comma-separated list of hosts / CIDR ranges that bypass the
///   proxy, e.g. `"localhost,127.0.0.1,.internal.example.com"`.
///   When `None` no bypass list is applied.
/// - `credentials` — Optional [`ProxyCredentials`] for proxies requiring
///   Basic authentication. Applied to every configured proxy URL.
///
/// All URL fields treat an empty string the same as `None` (not configured).
#[derive(Clone, Debug, Default, PartialEq)]
#[cfg_attr(
    feature = "std",
    derive(serde::Serialize, serde::Deserialize),
    serde(deny_unknown_fields)
)]
pub struct ProxyConfig {
    /// Catch-all proxy endpoint URL (e.g. `"http://proxy.corp.example.com:3128"`).
    pub proxy_url: Option<String>,
    /// Proxy for plain-HTTP targets; overrides `proxy_url` for those requests.
    pub http_proxy_url: Option<String>,
    /// Proxy for HTTPS targets; overrides `proxy_url` for those requests.
    pub https_proxy_url: Option<String>,
    /// Comma-separated no-proxy bypass list.
    pub no_proxy: Option<String>,
    /// Optional proxy Basic-auth credentials.
    pub credentials: Option<ProxyCredentials>,
}

impl ProxyConfig {
    /// Returns `true` when at least one proxy URL has been configured.
    pub fn is_configured(&self) -> bool {
        non_empty(&self.proxy_url).is_some()
            || non_empty(&self.http_proxy_url).is_some()
            || non_empty(&self.https_proxy_url).is_some()
    }

    /// Returns `true` when proxy credentials have been supplied.
    pub fn has_credentials(&self) -> bool {
        self.credentials.is_some()
    }

    /// Validate the configuration.
    ///
    /// Rejected configurations:
    /// - a proxy URL that does not start with `http://` or `https://`,
    ///   has no host, or contains whitespace / control characters;
    /// - credentials with an empty username, a username containing `:`,
    ///   or control characters in either field (header injection);
    /// - credentials supplied without any proxy URL (almost certainly a
    ///   mistake — they would silently never be used);
    /// - control characters in the `no_proxy` list.
    ///
    /// [`build_client`] / [`build_client_with_policy`] and the runtime-config
    /// loader call this automatically.
    pub fn validate(&self) -> Result<(), String> {
        for (field, url) in [
            ("proxy_url", &self.proxy_url),
            ("http_proxy_url", &self.http_proxy_url),
            ("https_proxy_url", &self.https_proxy_url),
        ] {
            if let Some(url) = url.as_deref() {
                if !url.is_empty() {
                    validate_proxy_url(field, url)?;
                }
            }
        }

        if let Some(ref creds) = self.credentials {
            if creds.username.is_empty() {
                return Err("proxy credentials: username cannot be empty".into());
            }
            if creds.username.contains(':') {
                return Err("proxy credentials: username cannot contain ':'".into());
            }
            if creds.username.chars().any(|c| c.is_ascii_control())
                || creds.password.chars().any(|c| c.is_ascii_control())
            {
                return Err("proxy credentials: username/password cannot contain control characters".into());
            }
            if !self.is_configured() {
                return Err("proxy credentials supplied but no proxy URL configured".into());
            }
        }

        if let Some(ref no_proxy) = self.no_proxy {
            if no_proxy.chars().any(|c| c.is_ascii_control()) {
                return Err("no_proxy cannot contain control characters".into());
            }
        }

        Ok(())
    }

    /// Pure proxy-selection logic: which configured proxy URL applies to
    /// `target_url`?
    ///
    /// Returns `None` when no proxy applies — either nothing is configured
    /// for the target's scheme or the target host matches the `no_proxy`
    /// list. Scheme-specific proxies take precedence over `proxy_url`.
    ///
    /// `no_proxy` host matching: `*` bypasses everything; an entry starting
    /// with `.` matches any subdomain; a bare host matches itself and its
    /// subdomains. Matching is case-insensitive and ignores the target port.
    /// (CIDR ranges are honoured by the underlying transport but compared
    /// textually here.)
    ///
    /// This mirrors the routing the built client performs and exists so the
    /// decision can be unit-tested and logged without a live HTTP stack.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use anchorkit::http_client::ProxyConfig;
    ///
    /// let cfg = ProxyConfig {
    ///     proxy_url: Some("http://proxy.corp:3128".into()),
    ///     https_proxy_url: Some("http://tls-proxy.corp:3129".into()),
    ///     no_proxy: Some("localhost,.internal.corp".into()),
    ///     ..ProxyConfig::default()
    /// };
    ///
    /// assert_eq!(cfg.select_proxy_url("https://anchor.example.com/sep6"),
    ///            Some("http://tls-proxy.corp:3129"));
    /// assert_eq!(cfg.select_proxy_url("http://anchor.example.com/sep6"),
    ///            Some("http://proxy.corp:3128"));
    /// assert_eq!(cfg.select_proxy_url("https://api.internal.corp/health"), None);
    /// ```
    pub fn select_proxy_url(&self, target_url: &str) -> Option<&str> {
        let scheme_is = |prefix: &str| {
            target_url
                .get(..prefix.len())
                .map(|s| s.eq_ignore_ascii_case(prefix))
                .unwrap_or(false)
        };
        let is_https = if scheme_is("https://") {
            true
        } else if scheme_is("http://") {
            false
        } else {
            // Unknown scheme — only the catch-all proxy could apply.
            return if self.host_bypasses_proxy(target_url) {
                None
            } else {
                non_empty(&self.proxy_url)
            };
        };

        if self.host_bypasses_proxy(target_url) {
            return None;
        }

        if is_https {
            non_empty(&self.https_proxy_url).or_else(|| non_empty(&self.proxy_url))
        } else {
            non_empty(&self.http_proxy_url).or_else(|| non_empty(&self.proxy_url))
        }
    }

    /// Returns `true` when the host of `target_url` matches the `no_proxy` list.
    fn host_bypasses_proxy(&self, target_url: &str) -> bool {
        let list = match self.no_proxy.as_deref() {
            Some(l) if !l.is_empty() => l,
            _ => return false,
        };
        let host = match extract_host(target_url) {
            Some(h) => h,
            None => return false,
        };
        list.split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .any(|entry| {
                if entry == "*" {
                    return true;
                }
                let entry_lower = entry.to_ascii_lowercase();
                let host_lower = host.to_ascii_lowercase();
                if let Some(suffix) = entry_lower.strip_prefix('.') {
                    host_lower.ends_with(&entry_lower) || host_lower == suffix
                } else {
                    host_lower == entry_lower
                        || host_lower.ends_with(&alloc::format!(".{}", entry_lower))
                }
            })
    }
}

/// Return the URL as `Some(&str)` only when present and non-empty.
fn non_empty(url: &Option<String>) -> Option<&str> {
    url.as_deref().filter(|s| !s.is_empty())
}

/// Extract the host portion of a URL: strips scheme, userinfo, port, path,
/// query, and fragment. Handles bracketed IPv6 literals.
fn extract_host(url: &str) -> Option<&str> {
    let after_scheme = match url.find("://") {
        Some(idx) => &url[idx + 3..],
        None => url,
    };
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    // Drop userinfo if present.
    let host_port = match authority.rfind('@') {
        Some(idx) => &authority[idx + 1..],
        None => authority,
    };
    // Bracketed IPv6 literal: [::1]:8080 → ::1
    if let Some(rest) = host_port.strip_prefix('[') {
        return rest.find(']').map(|end| &rest[..end]);
    }
    let host = match host_port.rfind(':') {
        Some(idx) => &host_port[..idx],
        None => host_port,
    };
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

/// Validate a single proxy URL string.
fn validate_proxy_url(field: &str, url: &str) -> Result<(), String> {
    let rest = if let Some(rest) = url.strip_prefix("http://") {
        rest
    } else if let Some(rest) = url.strip_prefix("https://") {
        rest
    } else {
        return Err(alloc::format!(
            "invalid proxy URL '{}' in {}: must start with http:// or https://",
            url, field
        ));
    };
    if extract_host(rest).is_none() {
        return Err(alloc::format!(
            "invalid proxy URL '{}' in {}: missing host", url, field
        ));
    }
    if url.chars().any(|c| c.is_ascii_whitespace() || c.is_ascii_control()) {
        return Err(alloc::format!(
            "invalid proxy URL '{}' in {}: contains whitespace or control characters",
            url, field
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Client builder
// ---------------------------------------------------------------------------

/// Build a `reqwest::blocking::Client` with optional proxy and a configurable
/// timeout.
///
/// # Arguments
///
/// * `proxy`       — Optional [`ProxyConfig`]. When `None` the client uses
///   system proxy environment variables.
/// * `timeout_secs` — Per-request timeout in seconds. Use `0` for no timeout.
///
/// # Errors
///
/// Returns a `String` error if the proxy URL is malformed or the client cannot
/// be constructed.
#[cfg(feature = "std")]
pub fn build_client(
    proxy: Option<&ProxyConfig>,
    timeout_secs: u64,
) -> Result<reqwest::blocking::Client, String> {
    let timeout = if timeout_secs > 0 {
        Some(std::time::Duration::from_secs(timeout_secs))
    } else {
        None
    };
    build_client_with_timeout(proxy, timeout)
}

/// Shared client construction for the seconds-based [`build_client`] and the
/// millisecond-precise webhook delivery path.
///
/// `timeout` is the total per-request budget as an already-constructed
/// [`Duration`](std::time::Duration); `None` disables the timeout. Building the
/// `Duration` at the call site keeps each conversion next to the public option
/// that names its unit (see [`webhook_timeout`]) instead of forcing every
/// caller through a seconds-only integer boundary that silently truncates
/// sub-second budgets.
///
/// The redirect chain is always bounded explicitly by
/// [`ConnectionPolicy::default()`]'s `max_redirects` rather than left to
/// `reqwest`'s built-in default, so a dependency-side change to that default
/// cannot widen (or an explicit builder tweak elsewhere disable) the cap.
#[cfg(feature = "std")]
fn build_client_with_timeout(
    proxy: Option<&ProxyConfig>,
    timeout: Option<std::time::Duration>,
) -> Result<reqwest::blocking::Client, String> {
    let mut builder = reqwest::blocking::Client::builder();

    if let Some(timeout) = timeout {
        builder = builder.timeout(timeout);
    }

    // Enforce the configured redirect limit at construction time.
    let redirect_cap = ConnectionPolicy::default().max_redirects;
    builder = builder.redirect(reqwest::redirect::Policy::limited(redirect_cap));

    if let Some(cfg) = proxy {
        builder = apply_proxy_config(builder, cfg)?;
    }

    builder
        .build()
        .map_err(|e| alloc::format!("failed to build HTTP client: {}", e))
}

/// Default total request timeout for webhook delivery when the caller leaves
/// [`WebhookDeliveryConfig::timeout_ms`](crate::webhook::WebhookDeliveryConfig::timeout_ms)
/// at `0` ("unset").
#[cfg(feature = "std")]
const DEFAULT_WEBHOOK_TIMEOUT_SECS: u64 = 30;

/// Convert the public millisecond `timeout_ms` webhook option into a
/// [`Duration`](std::time::Duration).
///
/// The value is interpreted as **milliseconds** — the unit named by the option
/// and the config schema — so fractional-second budgets are preserved exactly
/// rather than being floored (and, for values below `1000`, rounded up) by an
/// integer division to whole seconds. `0` selects
/// [`DEFAULT_WEBHOOK_TIMEOUT_SECS`].
#[cfg(feature = "std")]
fn webhook_timeout(timeout_ms: u64) -> std::time::Duration {
    if timeout_ms == 0 {
        std::time::Duration::from_secs(DEFAULT_WEBHOOK_TIMEOUT_SECS)
    } else {
        std::time::Duration::from_millis(timeout_ms)
    }
}

/// Validate `cfg` and register its proxies on a reqwest client builder.
///
/// Scheme-specific proxies are registered before the catch-all so reqwest's
/// first-match interception gives them precedence, matching
/// [`ProxyConfig::select_proxy_url`]. Credentials and the `no_proxy` bypass
/// list are applied to every registered proxy.
#[cfg(feature = "std")]
fn apply_proxy_config(
    mut builder: reqwest::blocking::ClientBuilder,
    cfg: &ProxyConfig,
) -> Result<reqwest::blocking::ClientBuilder, String> {
    cfg.validate()?;

    // Attach credentials and the bypass list to a freshly built proxy.
    let finish = |mut proxy_obj: reqwest::Proxy| {
        if let Some(ref creds) = cfg.credentials {
            proxy_obj = proxy_obj.basic_auth(&creds.username, &creds.password);
        }
        if let Some(no_proxy) = cfg.no_proxy.as_deref().filter(|s| !s.is_empty()) {
            proxy_obj = proxy_obj.no_proxy(reqwest::NoProxy::from_string(no_proxy));
        }
        proxy_obj
    };
    let bad_url = |url: &str, e: reqwest::Error| {
        alloc::format!("invalid proxy URL '{}': {}", url, e)
    };

    if let Some(url) = non_empty(&cfg.http_proxy_url) {
        let proxy_obj = reqwest::Proxy::http(url).map_err(|e| bad_url(url, e))?;
        builder = builder.proxy(finish(proxy_obj));
    }
    if let Some(url) = non_empty(&cfg.https_proxy_url) {
        let proxy_obj = reqwest::Proxy::https(url).map_err(|e| bad_url(url, e))?;
        builder = builder.proxy(finish(proxy_obj));
    }
    if let Some(url) = non_empty(&cfg.proxy_url) {
        let proxy_obj = reqwest::Proxy::all(url).map_err(|e| bad_url(url, e))?;
        builder = builder.proxy(finish(proxy_obj));
    }

    Ok(builder)
}

/// Build a `reqwest::blocking::Client` with full [`ConnectionPolicy`] control.
///
/// This is the recommended constructor for production use. It exposes all
/// timeout phases (connect, read, total) and redirect controls, making the
/// client's behaviour explicit and deterministic against slow or misbehaving
/// anchors.
///
/// # Arguments
///
/// * `proxy`  — Optional [`ProxyConfig`].
/// * `policy` — [`ConnectionPolicy`] describing timeout phases and redirect limits.
///   Pass `&ConnectionPolicy::default()` for sensible production defaults.
///
/// # Errors
///
/// Returns a `String` error if the proxy URL is malformed or the client cannot
/// be constructed.
///
/// # Examples
///
/// ```rust,no_run
/// use anchorkit::http_client::{ConnectionPolicy, ProxyConfig, build_client_with_policy};
///
/// let client = build_client_with_policy(None, &ConnectionPolicy::default()).unwrap();
/// let strict = build_client_with_policy(None, &ConnectionPolicy::strict()).unwrap();
/// ```
#[cfg(feature = "std")]
pub fn build_client_with_policy(
    proxy: Option<&ProxyConfig>,
    policy: &ConnectionPolicy,
) -> Result<reqwest::blocking::Client, String> {
    let mut builder = reqwest::blocking::Client::builder();

    // Connect timeout
    if policy.connect_timeout_secs > 0 {
        builder = builder.connect_timeout(std::time::Duration::from_secs(policy.connect_timeout_secs));
    }
    // Total request timeout covers connect + send + receive.
    // reqwest 0.12 blocking client does not expose a separate read_timeout;
    // total_timeout_secs is the single wall-clock cap for the entire request.
    // read_timeout_secs is stored on ConnectionPolicy for documentation and
    // future use but not applied here.
    if policy.total_timeout_secs > 0 {
        builder = builder.timeout(std::time::Duration::from_secs(policy.total_timeout_secs));
    }
    // Redirect policy
    if policy.follow_redirects {
        builder = builder.redirect(reqwest::redirect::Policy::limited(policy.max_redirects));
    } else {
        builder = builder.redirect(reqwest::redirect::Policy::none());
    }

    // Proxy
    if let Some(cfg) = proxy {
        builder = apply_proxy_config(builder, cfg)?;
    }

    builder
        .build()
        .map_err(|e| alloc::format!("failed to build HTTP client: {}", e))
}
// ---------------------------------------------------------------------------
// Proxy-aware stellar.toml fetcher
// ---------------------------------------------------------------------------

/// Fetch and parse a `stellar.toml` file through an optional proxy.
///
/// Constructs the well-known URL via [`fetch_stellar_toml_url`], performs an
/// HTTP GET (routing through `proxy` when configured), and parses the response
/// body with [`parse_stellar_toml`].
///
/// # Arguments
///
/// * `domain`      — Anchor base URL, e.g. `"https://anchor.example.com"`.
/// * `proxy`       — Optional proxy configuration.
/// * `timeout_secs` — Per-request timeout in seconds.
///
/// # Errors
///
/// Returns a `String` error on network failure, non-2xx HTTP status, or TOML
/// parse failure.
///
/// # Examples
///
/// ```rust,no_run
/// use anchorkit::http_client::{ProxyConfig, fetch_stellar_toml_with_proxy};
///
/// let proxy = ProxyConfig {
///     proxy_url: Some("http://proxy.corp.example.com:3128".to_string()),
///     no_proxy: None,
///     ..ProxyConfig::default()
/// };
/// let toml = fetch_stellar_toml_with_proxy("https://anchor.example.com", Some(&proxy), 30).unwrap();
/// println!("Supports SEP-6: {}", toml.supports_sep6());
/// ```
#[cfg(feature = "std")]
pub fn fetch_stellar_toml_with_proxy(
    domain: &str,
    proxy: Option<&ProxyConfig>,
    timeout_secs: u64,
) -> Result<crate::stellar_toml::ParsedStellarToml, String> {
    let url = crate::stellar_toml::fetch_stellar_toml_url(domain)
        .map_err(|e| alloc::format!("invalid domain '{}': {:?}", domain, e))?;

    let client = build_client(proxy, timeout_secs)?;

    let response = client
        .get(&url)
        .send()
        .map_err(|e| alloc::format!("GET {} failed: {}", url, e))?;

    if !response.status().is_success() {
        return Err(alloc::format!(
            "GET {} returned HTTP {}",
            url,
            response.status()
        ));
    }

    let body = response
        .text()
        .map_err(|e| alloc::format!("failed to read response body: {}", e))?;

    crate::stellar_toml::parse_stellar_toml(&body)
        .map_err(|e| alloc::format!("failed to parse stellar.toml: {:?}", e))
}

// ---------------------------------------------------------------------------
// Proxy-aware webhook delivery
// ---------------------------------------------------------------------------

/// Deliver a webhook payload through an optional proxy.
///
/// This is a thin wrapper around [`deliver_webhook`] that constructs the
/// `http_post` transport function using a proxy-aware `reqwest` client.
///
/// # Arguments
///
/// * `config`      — Webhook delivery configuration (endpoint, retries, DLQ key).
/// * `payload`     — JSON payload string to POST.
/// * `dlq`         — Dead-letter queue map for failed deliveries.
/// * `proxy`       — Optional proxy configuration.
/// * `now_fn`      — Returns the current Unix timestamp in seconds.
///
/// # Errors
///
/// Returns [`AnchorKitError`] with code [`ErrorCode::WebhookDeliveryFailed`]
/// after all retry attempts are exhausted.
///
/// # Examples
///
/// ```rust,no_run
/// use std::collections::BTreeMap;
/// use anchorkit::http_client::{ProxyConfig, deliver_webhook_with_proxy};
/// use anchorkit::webhook::{WebhookDeliveryConfig, DlqEntry};
/// use anchorkit::retry::RetryConfig;
///
/// let config = WebhookDeliveryConfig {
///     endpoint_url: "https://hooks.example.com/anchor".to_string(),
///     timeout_ms: 5000,
///     retry_config: RetryConfig::default(),
///     dead_letter_storage_key: "anchor-hook".to_string(),
///     signing_key: None,
/// };
/// let proxy = ProxyConfig {
///     proxy_url: Some("http://proxy.corp.example.com:3128".to_string()),
///     no_proxy: None,
///     ..ProxyConfig::default()
/// };
/// let mut dlq = BTreeMap::new();
/// deliver_webhook_with_proxy(&config, r#"{"event":"deposit"}"#, &mut dlq, Some(&proxy), || 0).unwrap();
/// ```
#[cfg(feature = "std")]
pub fn deliver_webhook_with_proxy(
    config: &crate::webhook::WebhookDeliveryConfig,
    payload: &str,
    dlq: &mut alloc::collections::BTreeMap<String, alloc::vec::Vec<crate::webhook::DlqEntry>>,
    proxy: Option<&ProxyConfig>,
    now_fn: impl Fn() -> u64,
) -> Result<(), crate::errors::AnchorKitError> {
    let client = build_client_with_timeout(proxy, Some(webhook_timeout(config.timeout_ms)))
        .map_err(|e| {
            crate::errors::AnchorKitError::with_context(
                crate::errors::ErrorCode::WebhookDeliveryFailed,
                "failed to build HTTP client for webhook delivery",
                &e,
            )
        })?;

    crate::webhook::deliver_webhook(
        config,
        payload,
        dlq,
        move |url, body, sig_header| {
            let mut req = client
                .post(url)
                .header("Content-Type", "application/json")
                .body(alloc::string::String::from(body));
            if let Some(sig) = sig_header {
                req = req.header("X-Anchor-Signature", sig);
            }
            req.send()
                .map(|r| r.status().as_u16())
                .map_err(|e| alloc::format!("HTTP POST failed: {}", e))
        },
        |_| {},
        now_fn,
    )
}

/// Deliver a webhook through the proxy-aware client, propagating `trace`.
///
/// Same as [`deliver_webhook_with_proxy`] but every delivery attempt — including
/// retries — carries the attempt's trace headers (`traceparent`, `X-Trace-Id`,
/// `X-Span-Id`), and the DLQ entry written on exhaustion records the trace.
///
/// Use this when the webhook is delivered as part of a traced request; the
/// receiving system then logs the same trace ID the anchor did.
///
/// # Errors
///
/// Returns [`ErrorCode::WebhookDeliveryFailed`](crate::errors::ErrorCode::WebhookDeliveryFailed)
/// when the client cannot be built or every delivery attempt fails.
///
/// # Examples
///
/// ```rust,no_run
/// use std::collections::BTreeMap;
/// use anchorkit::http_client::deliver_webhook_with_proxy_traced;
/// use anchorkit::retry::RetryConfig;
/// use anchorkit::trace_context::TraceContext;
/// use anchorkit::webhook::WebhookDeliveryConfig;
///
/// let config = WebhookDeliveryConfig {
///     endpoint_url: "https://hooks.example.com/anchor".to_string(),
///     timeout_ms: 5_000,
///     retry_config: RetryConfig::default(),
///     dead_letter_storage_key: "webhook_dlq".to_string(),
///     signing_key: None,
///     max_payload_age_seconds: None,
///     require_nonce_for_replay_protection: false,
/// };
/// let trace = TraceContext::root_from_seed("deposit:txn-001");
/// let mut dlq = BTreeMap::new();
/// deliver_webhook_with_proxy_traced(
///     &config,
///     r#"{"event":"deposit"}"#,
///     &trace,
///     &mut dlq,
///     None,
///     || 0,
/// ).unwrap();
/// ```
#[cfg(feature = "std")]
pub fn deliver_webhook_with_proxy_traced(
    config: &crate::webhook::WebhookDeliveryConfig,
    payload: &str,
    trace: &TraceContext,
    dlq: &mut alloc::collections::BTreeMap<String, alloc::vec::Vec<crate::webhook::DlqEntry>>,
    proxy: Option<&ProxyConfig>,
    now_fn: impl Fn() -> u64,
) -> Result<(), crate::errors::AnchorKitError> {
    let client = build_client_with_timeout(proxy, Some(webhook_timeout(config.timeout_ms)))
        .map_err(|e| {
            crate::errors::AnchorKitError::with_context(
                crate::errors::ErrorCode::WebhookDeliveryFailed,
                "failed to build HTTP client for webhook delivery",
                &e,
            )
        })?;

    crate::webhook::deliver_webhook_traced(
        config,
        payload,
        trace,
        dlq,
        move |url, body, sig_header, attempt_trace| {
            let mut req = client
                .post(url)
                .header("Content-Type", "application/json")
                .body(alloc::string::String::from(body));
            if let Some(sig) = sig_header {
                req = req.header("X-Anchor-Signature", sig);
            }
            // Each attempt carries its own span, so the receiver can tell a
            // retry apart from the original delivery.
            for (name, value) in attempt_trace.header_pairs() {
                req = req.header(name, value);
            }
            req.send()
                .map(|r| r.status().as_u16())
                .map_err(|e| alloc::format!("HTTP POST failed: {}", e))
        },
        |_| {},
        now_fn,
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn proxy_config_default_is_unconfigured() {
        let cfg = ProxyConfig::default();
        assert!(!cfg.is_configured());
    }

    #[test]
    fn proxy_config_with_url_is_configured() {
        let cfg = ProxyConfig {
            proxy_url: Some("http://proxy.example.com:3128".to_string()),
            no_proxy: None,
            ..ProxyConfig::default()
        };
        assert!(cfg.is_configured());
    }

    #[test]
    fn proxy_config_empty_url_is_not_configured() {
        let cfg = ProxyConfig {
            proxy_url: Some(String::new()),
            no_proxy: None,
            ..ProxyConfig::default()
        };
        assert!(!cfg.is_configured());
    }

    #[test]
    fn proxy_config_none_url_is_not_configured() {
        let cfg = ProxyConfig {
            proxy_url: None,
            no_proxy: Some("localhost".to_string()),
            ..ProxyConfig::default()
        };
        assert!(!cfg.is_configured());
    }

    #[test]
    fn proxy_config_clone_and_eq() {
        let a = ProxyConfig {
            proxy_url: Some("http://proxy.example.com:3128".to_string()),
            no_proxy: Some("localhost".to_string()),
            ..ProxyConfig::default()
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[cfg(feature = "std")]
    #[test]
    fn build_client_no_proxy_succeeds() {
        let client = build_client(None, 10);
        assert!(client.is_ok(), "client without proxy should build successfully");
    }

    #[cfg(feature = "std")]
    #[test]
    fn build_client_with_valid_proxy_url_succeeds() {
        let proxy = ProxyConfig {
            proxy_url: Some("http://proxy.example.com:3128".to_string()),
            no_proxy: None,
            ..ProxyConfig::default()
        };
        let client = build_client(Some(&proxy), 10);
        assert!(client.is_ok(), "client with valid proxy URL should build successfully");
    }

    #[cfg(feature = "std")]
    #[test]
    fn build_client_with_proxy_and_no_proxy_list_succeeds() {
        let proxy = ProxyConfig {
            proxy_url: Some("http://proxy.example.com:3128".to_string()),
            no_proxy: Some("localhost,127.0.0.1,.internal.example.com".to_string()),
            ..ProxyConfig::default()
        };
        let client = build_client(Some(&proxy), 30);
        assert!(client.is_ok(), "client with proxy + no_proxy list should build successfully");
    }

    #[cfg(feature = "std")]
    #[test]
    fn build_client_with_invalid_proxy_url_returns_error() {
        let proxy = ProxyConfig {
            proxy_url: Some("not-a-valid-url".to_string()),
            no_proxy: None,
            ..ProxyConfig::default()
        };
        let result = build_client(Some(&proxy), 10);
        assert!(result.is_err(), "invalid proxy URL should return an error");
        let msg = result.unwrap_err();
        assert!(
            msg.contains("invalid proxy URL"),
            "error message should mention invalid proxy URL, got: {msg}"
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn build_client_unconfigured_proxy_uses_system_defaults() {
        // An unconfigured ProxyConfig (no URL) should behave like no proxy at all.
        let proxy = ProxyConfig::default();
        let client = build_client(Some(&proxy), 10);
        assert!(client.is_ok(), "unconfigured proxy should fall through to system defaults");
    }

    #[cfg(feature = "std")]
    #[test]
    fn build_client_zero_timeout_builds_successfully() {
        // timeout_secs = 0 means no timeout — client should still build.
        let client = build_client(None, 0);
        assert!(client.is_ok(), "zero timeout should build successfully");
    }

    #[cfg(feature = "std")]
    #[test]
    fn build_client_https_proxy_url_succeeds() {
        let proxy = ProxyConfig {
            proxy_url: Some("https://secure-proxy.example.com:8080".to_string()),
            no_proxy: None,
            ..ProxyConfig::default()
        };
        let client = build_client(Some(&proxy), 10);
        assert!(client.is_ok(), "HTTPS proxy URL should build successfully");
    }

    // ── Webhook delivery with proxy (unit-level, injected transport) ──────────

    #[cfg(feature = "std")]
    #[test]
    fn deliver_webhook_with_proxy_succeeds_on_200() {
        use crate::webhook::{WebhookDeliveryConfig, DlqEntry, get_dead_letter_webhooks};
        use crate::retry::RetryConfig;
        use alloc::collections::BTreeMap;

        // Use the base deliver_webhook directly with an injected transport to
        // avoid real network calls in unit tests.
        let config = WebhookDeliveryConfig {
            endpoint_url: "https://hooks.example.com/anchor".to_string(),
            timeout_ms: 1000,
            retry_config: RetryConfig {
                max_attempts: 3,
                base_delay_ms: 0,
                max_delay_ms: 0,
                backoff_multiplier: 1,
                strategy: crate::retry::BackoffStrategy::Exponential,
                jitter_policy: crate::retry::JitterPolicy::None,
            },
            dead_letter_storage_key: "proxy-test".to_string(),
            signing_key: None,
            max_payload_age_seconds: None,
            require_nonce_for_replay_protection: false,
        };

        let mut dlq: BTreeMap<String, alloc::vec::Vec<DlqEntry>> = BTreeMap::new();

        // Inject a mock transport that always returns 200.
        let result = crate::webhook::deliver_webhook(
            &config,
            r#"{"event":"deposit_completed"}"#,
            &mut dlq,
            |_url, _body, _sig| Ok(200u16),
            |_| {},
            || 1_000_000u64,
        );

        assert!(result.is_ok(), "delivery should succeed with 200 response");
        assert!(
            get_dead_letter_webhooks(&dlq, "proxy-test").is_empty(),
            "DLQ should be empty on success"
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn deliver_webhook_with_proxy_stores_dlq_on_failure() {
        use crate::webhook::{WebhookDeliveryConfig, DlqEntry, get_dead_letter_webhooks};
        use crate::retry::RetryConfig;
        use alloc::collections::BTreeMap;

        let config = WebhookDeliveryConfig {
            endpoint_url: "https://hooks.example.com/anchor".to_string(),
            timeout_ms: 1000,
            retry_config: RetryConfig {
                max_attempts: 2,
                base_delay_ms: 0,
                max_delay_ms: 0,
                backoff_multiplier: 1,
                strategy: crate::retry::BackoffStrategy::Exponential,
                jitter_policy: crate::retry::JitterPolicy::None,
            },
            dead_letter_storage_key: "proxy-fail-test".to_string(),
            signing_key: None,
            max_payload_age_seconds: None,
            require_nonce_for_replay_protection: false,
        };

        let mut dlq: BTreeMap<String, alloc::vec::Vec<DlqEntry>> = BTreeMap::new();

        // Inject a mock transport that always returns 503.
        let result = crate::webhook::deliver_webhook(
            &config,
            r#"{"event":"deposit_failed"}"#,
            &mut dlq,
            |_url, _body, _sig| Ok(503u16),
            |_| {},
            || 9_999_999u64,
        );

        assert!(result.is_err(), "delivery should fail after exhausting retries");
        let entries = get_dead_letter_webhooks(&dlq, "proxy-fail-test");
        assert_eq!(entries.len(), 1, "one DLQ entry should be written");
        assert_eq!(entries[0].last_status_code, 503);
        assert_eq!(entries[0].attempts_made, 2);
        assert_eq!(entries[0].failed_at_timestamp, 9_999_999);
    }

    // ── ProxyConfig serialization (std only) ──────────────────────────────────

    #[cfg(feature = "std")]
    #[test]
    fn proxy_config_serializes_to_json() {
        let cfg = ProxyConfig {
            proxy_url: Some("http://proxy.example.com:3128".to_string()),
            no_proxy: Some("localhost".to_string()),
            ..ProxyConfig::default()
        };
        let json = serde_json::to_string(&cfg).expect("serialization should succeed");
        assert!(json.contains("proxy_url"));
        assert!(json.contains("proxy.example.com"));
    }

    #[cfg(feature = "std")]
    #[test]
    fn proxy_config_deserializes_from_json() {
        let json = r#"{"proxy_url":"http://proxy.example.com:3128","no_proxy":"localhost"}"#;
        let cfg: ProxyConfig = serde_json::from_str(json).expect("deserialization should succeed");
        assert_eq!(cfg.proxy_url.as_deref(), Some("http://proxy.example.com:3128"));
        assert_eq!(cfg.no_proxy.as_deref(), Some("localhost"));
    }

    #[cfg(feature = "std")]
    #[test]
    fn proxy_config_deserializes_with_null_fields() {
        let json = r#"{"proxy_url":null,"no_proxy":null}"#;
        let cfg: ProxyConfig = serde_json::from_str(json).expect("deserialization should succeed");
        assert!(cfg.proxy_url.is_none());
        assert!(cfg.no_proxy.is_none());
        assert!(!cfg.is_configured());
    }

    // ── Idempotency and signing (OutboundRequestOptions) ──────────────────────

    #[test]
    fn outbound_options_default_has_no_headers() {
        let opts = OutboundRequestOptions::default();
        let headers = opts.build_headers("body");
        assert!(headers.is_empty());
        assert!(!opts.has_idempotency_key());
        assert!(!opts.has_signing_key());
    }

    #[test]
    fn outbound_options_with_idempotency_key_emits_two_headers() {
        let opts = OutboundRequestOptions::with_idempotency_key("txn-001");
        let headers = opts.build_headers("payload");
        let names: alloc::vec::Vec<&str> = headers.iter().map(|(k, _)| k.as_str()).collect();
        assert!(names.contains(&"Idempotency-Key"), "should include Idempotency-Key");
        assert!(names.contains(&"X-Request-Id"), "should include X-Request-Id");
        // Both should carry the same value
        let ik = headers.iter().find(|(k, _)| k == "Idempotency-Key").unwrap();
        let ri = headers.iter().find(|(k, _)| k == "X-Request-Id").unwrap();
        assert_eq!(ik.1, "txn-001");
        assert_eq!(ri.1, "txn-001");
        assert!(opts.has_idempotency_key());
    }

    #[test]
    fn outbound_options_with_signing_key_emits_signature_header() {
        let opts = OutboundRequestOptions::default().with_signing_key(b"secret");
        let body = r#"{"event":"deposit"}"#;
        let headers = opts.build_headers(body);
        let sig_header = headers.iter().find(|(k, _)| k == "X-Anchor-Signature");
        assert!(sig_header.is_some(), "should include X-Anchor-Signature");
        let (_, sig_val) = sig_header.unwrap();
        assert!(sig_val.starts_with("sha256="), "signature header must start with sha256=");
        assert!(opts.has_signing_key());
    }

    #[test]
    fn outbound_options_signature_is_verifiable() {
        let key = b"my-hmac-key";
        let body = r#"{"event":"withdrawal","amount":100}"#;
        let opts = OutboundRequestOptions::default().with_signing_key(key);
        let headers = opts.build_headers(body);
        let sig_val = &headers.iter()
            .find(|(k, _)| k == "X-Anchor-Signature")
            .unwrap().1;
        assert!(verify_outbound_signature(body, sig_val, key),
            "signature should verify correctly");
    }

    #[test]
    fn outbound_options_wrong_key_fails_verification() {
        let key = b"correct-key";
        let wrong_key = b"wrong-key";
        let body = "payload";
        let opts = OutboundRequestOptions::default().with_signing_key(key);
        let headers = opts.build_headers(body);
        let sig_val = &headers.iter()
            .find(|(k, _)| k == "X-Anchor-Signature")
            .unwrap().1;
        assert!(!verify_outbound_signature(body, sig_val, wrong_key),
            "verification with wrong key should fail");
    }

    #[test]
    fn outbound_options_tampered_body_fails_verification() {
        let key = b"hmac-key";
        let body = "original body";
        let opts = OutboundRequestOptions::default().with_signing_key(key);
        let headers = opts.build_headers(body);
        let sig_val = &headers.iter()
            .find(|(k, _)| k == "X-Anchor-Signature")
            .unwrap().1;
        assert!(!verify_outbound_signature("tampered body", sig_val, key),
            "verification should fail when body is tampered");
    }

    #[test]
    fn outbound_options_from_seed_is_deterministic() {
        let opts1 = OutboundRequestOptions::from_seed("txn-123");
        let opts2 = OutboundRequestOptions::from_seed("txn-123");
        assert_eq!(opts1.idempotency_key, opts2.idempotency_key,
            "same seed must produce same idempotency key");
        assert!(opts1.has_idempotency_key());
    }

    #[test]
    fn outbound_options_from_seed_different_seeds_produce_different_keys() {
        let opts1 = OutboundRequestOptions::from_seed("txn-001");
        let opts2 = OutboundRequestOptions::from_seed("txn-002");
        assert_ne!(opts1.idempotency_key, opts2.idempotency_key,
            "different seeds must produce different idempotency keys");
    }

    #[test]
    fn post_with_options_passes_headers_to_transport() {
        let key = b"signing-key";
        let opts = OutboundRequestOptions::with_idempotency_key("idem-42")
            .with_signing_key(key);
        let body = r#"{"amount":50}"#;

        let mut captured_headers: alloc::vec::Vec<(String, String)> = alloc::vec::Vec::new();
        let result = post_with_options(
            "https://example.com/sep6",
            body,
            Some(&opts),
            |_url, _body, hdrs| {
                captured_headers.extend(hdrs.iter().cloned());
                Ok(200u16)
            },
        );

        assert_eq!(result, Ok(200));
        let names: alloc::vec::Vec<&str> = captured_headers.iter().map(|(k, _)| k.as_str()).collect();
        assert!(names.contains(&"Idempotency-Key"));
        assert!(names.contains(&"X-Request-Id"));
        assert!(names.contains(&"X-Anchor-Signature"));
    }

    // -----------------------------------------------------------------------
    // Issue #610 — trace context on outbound requests
    // -----------------------------------------------------------------------

    #[test]
    fn outbound_options_emit_trace_headers() {
        let trace = TraceContext::root_from_seed("txn-trace-1");
        let opts = OutboundRequestOptions::with_idempotency_key("idem-1").with_trace(&trace);
        assert!(opts.has_trace());

        let headers = opts.build_headers("{}");
        let find = |name: &str| {
            headers
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.as_str())
        };

        assert_eq!(find("traceparent"), Some(trace.to_traceparent().as_str()));
        assert_eq!(find("X-Trace-Id"), Some(trace.trace_id()));
        assert_eq!(find("X-Span-Id"), Some(trace.span_id()));
    }

    #[test]
    fn outbound_options_without_trace_emit_no_trace_headers() {
        let opts = OutboundRequestOptions::with_idempotency_key("idem-1");
        assert!(!opts.has_trace());
        let headers = opts.build_headers("{}");
        assert!(!headers.iter().any(|(k, _)| k == "traceparent"));
        assert!(!headers.iter().any(|(k, _)| k == "X-Trace-Id"));
    }

    #[test]
    fn post_with_options_forwards_trace_headers_to_transport() {
        let trace = TraceContext::root_from_seed("txn-trace-2");
        let opts = OutboundRequestOptions::with_idempotency_key("idem-2").with_trace(&trace);

        let mut captured: alloc::vec::Vec<(String, String)> = alloc::vec::Vec::new();
        let result = post_with_options(
            "https://example.com/sep6",
            r#"{"amount":50}"#,
            Some(&opts),
            |_url, _body, hdrs| {
                captured.extend(hdrs.iter().cloned());
                Ok(200u16)
            },
        );

        assert_eq!(result, Ok(200));
        let traceparent = captured
            .iter()
            .find(|(k, _)| k == "traceparent")
            .map(|(_, v)| v.clone())
            .expect("traceparent should reach the transport");
        assert!(traceparent.contains(trace.trace_id()));
    }

    #[test]
    fn post_with_options_no_options_still_works() {
        let result = post_with_options(
            "https://example.com/sep6",
            "body",
            None,
            |_url, _body, hdrs| {
                assert!(hdrs.is_empty(), "no extra headers when options is None");
                Ok(201u16)
            },
        );
        assert_eq!(result, Ok(201));
    }

    #[test]
    fn duplicate_submissions_with_same_idempotency_key_are_deduplicated() {
        // Simulate a server that recognises duplicate Idempotency-Key values
        // and returns 200 on first call and 200 (idempotent) on second.
        let opts = OutboundRequestOptions::with_idempotency_key("idem-dedup");
        let body = r#"{"event":"deposit"}"#;
        let call_count = core::cell::Cell::new(0u32);

        let make_call = |count: &core::cell::Cell<u32>| {
            let headers = opts.build_headers(body);
            let idem_key = headers.iter()
                .find(|(k, _)| k == "Idempotency-Key")
                .map(|(_, v)| v.clone())
                .unwrap_or_default();
            count.set(count.get() + 1);
            (idem_key, 200u16)
        };

        let (key1, status1) = make_call(&call_count);
        let (key2, status2) = make_call(&call_count);

        assert_eq!(key1, key2, "idempotency key must be stable across calls");
        assert_eq!(status1, 200);
        assert_eq!(status2, 200);
        assert_eq!(call_count.get(), 2);
    }

    // ── ConnectionPolicy and error classification ─────────────────────────────

    #[test]
    fn connection_policy_default_values() {
        let p = ConnectionPolicy::default();
        assert_eq!(p.connect_timeout_secs, 10);
        assert_eq!(p.read_timeout_secs, 30);
        assert_eq!(p.total_timeout_secs, 60);
        assert!(p.follow_redirects);
        assert_eq!(p.max_redirects, 3);
    }

    #[test]
    fn connection_policy_aggressive() {
        let p = ConnectionPolicy::aggressive();
        assert!(p.connect_timeout_secs < 10, "aggressive connect should be < 10s");
        assert!(!p.follow_redirects, "aggressive should not follow redirects");
    }

    #[test]
    fn connection_policy_conservative() {
        let p = ConnectionPolicy::conservative();
        assert!(p.total_timeout_secs > 60, "conservative total should be > 60s");
        assert!(p.follow_redirects, "conservative should follow redirects");
        assert!(p.max_redirects >= 3, "conservative should allow multiple redirects");
    }

    #[test]
    fn connection_policy_strict_no_redirects() {
        let p = ConnectionPolicy::strict();
        assert!(!p.follow_redirects);
        assert_eq!(p.max_redirects, 0);
    }

    #[test]
    fn classify_transport_error_timeout() {
        assert_eq!(classify_transport_error("connection timed out"), TransportErrorKind::Timeout);
        assert_eq!(classify_transport_error("request timeout"), TransportErrorKind::Timeout);
        assert_eq!(classify_transport_error("DEADLINE exceeded"), TransportErrorKind::Timeout);
    }

    #[test]
    fn classify_transport_error_connection_refused() {
        assert_eq!(classify_transport_error("connection refused"), TransportErrorKind::ConnectionRefused);
        assert_eq!(classify_transport_error("Connection REFUSED by server"), TransportErrorKind::ConnectionRefused);
    }

    #[test]
    fn classify_transport_error_dns_failure() {
        assert_eq!(classify_transport_error("DNS lookup failed"), TransportErrorKind::DnsFailure);
        assert_eq!(classify_transport_error("failed to resolve hostname"), TransportErrorKind::DnsFailure);
        assert_eq!(classify_transport_error("no such host"), TransportErrorKind::DnsFailure);
    }

    #[test]
    fn classify_transport_error_tls() {
        assert_eq!(classify_transport_error("TLS handshake failed"), TransportErrorKind::TlsError);
        assert_eq!(classify_transport_error("SSL certificate verification error"), TransportErrorKind::TlsError);
        assert_eq!(classify_transport_error("certificate expired"), TransportErrorKind::TlsError);
    }

    #[test]
    fn classify_transport_error_other() {
        assert_eq!(classify_transport_error("unexpected end of stream"), TransportErrorKind::Other);
        assert_eq!(classify_transport_error("broken pipe"), TransportErrorKind::Other);
    }

    #[test]
    fn is_transport_error_retryable_timeouts_and_dns() {
        assert!(is_transport_error_retryable(TransportErrorKind::Timeout));
        assert!(is_transport_error_retryable(TransportErrorKind::DnsFailure));
    }

    #[test]
    fn is_transport_error_not_retryable_refused_and_tls() {
        assert!(!is_transport_error_retryable(TransportErrorKind::ConnectionRefused));
        assert!(!is_transport_error_retryable(TransportErrorKind::TlsError));
        assert!(!is_transport_error_retryable(TransportErrorKind::Other));
    }

    #[cfg(feature = "std")]
    #[test]
    fn build_client_with_policy_default_succeeds() {
        let client = build_client_with_policy(None, &ConnectionPolicy::default());
        assert!(client.is_ok(), "client with default policy should build successfully");
    }

    #[cfg(feature = "std")]
    #[test]
    fn build_client_with_policy_aggressive_succeeds() {
        let client = build_client_with_policy(None, &ConnectionPolicy::aggressive());
        assert!(client.is_ok());
    }

    #[cfg(feature = "std")]
    #[test]
    fn build_client_with_policy_strict_succeeds() {
        let client = build_client_with_policy(None, &ConnectionPolicy::strict());
        assert!(client.is_ok());
    }

    #[cfg(feature = "std")]
    #[test]
    fn build_client_with_policy_invalid_proxy_fails() {
        let proxy = ProxyConfig {
            proxy_url: Some("not-a-url".into()),
            no_proxy: None,
            ..ProxyConfig::default()
        };
        let result = build_client_with_policy(Some(&proxy), &ConnectionPolicy::default());
        assert!(result.is_err());
    }

    // ── ProxyConfig validation (#606) ─────────────────────────────────────────

    fn full_proxy_config() -> ProxyConfig {
        ProxyConfig {
            proxy_url: Some("http://proxy.corp:3128".to_string()),
            http_proxy_url: Some("http://http-proxy.corp:3128".to_string()),
            https_proxy_url: Some("http://tls-proxy.corp:3129".to_string()),
            no_proxy: Some("localhost,127.0.0.1,.internal.corp".to_string()),
            credentials: Some(ProxyCredentials {
                username: "svc-anchor".to_string(),
                password: "s3cret".to_string(),
            }),
        }
    }

    #[test]
    fn validate_accepts_full_configuration() {
        assert_eq!(full_proxy_config().validate(), Ok(()));
    }

    #[test]
    fn validate_accepts_empty_configuration() {
        assert_eq!(ProxyConfig::default().validate(), Ok(()));
    }

    #[test]
    fn validate_rejects_bad_scheme_in_per_scheme_url() {
        let cfg = ProxyConfig {
            http_proxy_url: Some("socks5://proxy.corp:1080".to_string()),
            ..ProxyConfig::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("invalid proxy URL"), "got: {err}");
        assert!(err.contains("http_proxy_url"), "error should name the field, got: {err}");
    }

    #[test]
    fn validate_rejects_url_without_host() {
        let cfg = ProxyConfig {
            proxy_url: Some("http://".to_string()),
            ..ProxyConfig::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("missing host"), "got: {err}");
    }

    #[test]
    fn validate_rejects_url_with_whitespace() {
        let cfg = ProxyConfig {
            proxy_url: Some("http://proxy.corp:3128 evil".to_string()),
            ..ProxyConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_rejects_empty_username() {
        let mut cfg = full_proxy_config();
        cfg.credentials = Some(ProxyCredentials {
            username: String::new(),
            password: "pw".to_string(),
        });
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("username cannot be empty"), "got: {err}");
    }

    #[test]
    fn validate_rejects_username_with_colon() {
        let mut cfg = full_proxy_config();
        cfg.credentials = Some(ProxyCredentials {
            username: "user:name".to_string(),
            password: "pw".to_string(),
        });
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("':'"), "got: {err}");
    }

    #[test]
    fn validate_rejects_control_characters_in_password() {
        let mut cfg = full_proxy_config();
        cfg.credentials = Some(ProxyCredentials {
            username: "user".to_string(),
            password: "pw\r\nX-Injected: 1".to_string(),
        });
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("control characters"), "got: {err}");
    }

    #[test]
    fn validate_rejects_credentials_without_proxy() {
        let cfg = ProxyConfig {
            credentials: Some(ProxyCredentials {
                username: "user".to_string(),
                password: "pw".to_string(),
            }),
            ..ProxyConfig::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("no proxy URL configured"), "got: {err}");
    }

    #[test]
    fn validate_rejects_control_characters_in_no_proxy() {
        let cfg = ProxyConfig {
            proxy_url: Some("http://proxy.corp:3128".to_string()),
            no_proxy: Some("localhost\r\nevil".to_string()),
            ..ProxyConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn is_configured_true_for_scheme_specific_only() {
        let cfg = ProxyConfig {
            https_proxy_url: Some("http://tls-proxy.corp:3129".to_string()),
            ..ProxyConfig::default()
        };
        assert!(cfg.is_configured());
        assert!(!cfg.has_credentials());
    }

    // ── Proxy selection (#606) ────────────────────────────────────────────────

    #[test]
    fn select_prefers_scheme_specific_proxy() {
        let cfg = full_proxy_config();
        assert_eq!(
            cfg.select_proxy_url("https://anchor.example.com/sep6"),
            Some("http://tls-proxy.corp:3129")
        );
        assert_eq!(
            cfg.select_proxy_url("http://anchor.example.com/sep6"),
            Some("http://http-proxy.corp:3128")
        );
    }

    #[test]
    fn select_falls_back_to_catch_all_proxy() {
        let cfg = ProxyConfig {
            proxy_url: Some("http://proxy.corp:3128".to_string()),
            ..ProxyConfig::default()
        };
        assert_eq!(
            cfg.select_proxy_url("https://anchor.example.com"),
            Some("http://proxy.corp:3128")
        );
        assert_eq!(
            cfg.select_proxy_url("http://anchor.example.com"),
            Some("http://proxy.corp:3128")
        );
    }

    #[test]
    fn select_returns_none_when_unconfigured() {
        assert_eq!(
            ProxyConfig::default().select_proxy_url("https://anchor.example.com"),
            None
        );
    }

    #[test]
    fn select_returns_none_for_scheme_without_proxy() {
        // Only an HTTPS proxy is configured — plain HTTP goes direct.
        let cfg = ProxyConfig {
            https_proxy_url: Some("http://tls-proxy.corp:3129".to_string()),
            ..ProxyConfig::default()
        };
        assert_eq!(cfg.select_proxy_url("http://anchor.example.com"), None);
    }

    #[test]
    fn select_honours_no_proxy_exact_host() {
        let cfg = full_proxy_config();
        assert_eq!(cfg.select_proxy_url("https://localhost/health"), None);
        assert_eq!(cfg.select_proxy_url("http://127.0.0.1:8080/health"), None);
    }

    #[test]
    fn select_honours_no_proxy_subdomain_suffix() {
        let cfg = full_proxy_config();
        // ".internal.corp" matches subdomains and the bare domain itself.
        assert_eq!(cfg.select_proxy_url("https://api.internal.corp/v1"), None);
        assert_eq!(cfg.select_proxy_url("https://internal.corp/v1"), None);
        // A lookalike host must NOT bypass.
        assert!(cfg.select_proxy_url("https://notinternal.corp.example.com").is_some());
    }

    #[test]
    fn select_bare_no_proxy_entry_matches_subdomains() {
        let cfg = ProxyConfig {
            proxy_url: Some("http://proxy.corp:3128".to_string()),
            no_proxy: Some("example.com".to_string()),
            ..ProxyConfig::default()
        };
        assert_eq!(cfg.select_proxy_url("https://example.com"), None);
        assert_eq!(cfg.select_proxy_url("https://api.example.com"), None);
        assert!(cfg.select_proxy_url("https://badexample.com").is_some());
    }

    #[test]
    fn select_no_proxy_wildcard_bypasses_everything() {
        let cfg = ProxyConfig {
            proxy_url: Some("http://proxy.corp:3128".to_string()),
            no_proxy: Some("*".to_string()),
            ..ProxyConfig::default()
        };
        assert_eq!(cfg.select_proxy_url("https://anywhere.example.com"), None);
    }

    #[test]
    fn select_is_case_insensitive_and_ignores_port() {
        let cfg = ProxyConfig {
            proxy_url: Some("http://proxy.corp:3128".to_string()),
            no_proxy: Some("Anchor.Example.COM".to_string()),
            ..ProxyConfig::default()
        };
        assert_eq!(cfg.select_proxy_url("HTTPS://anchor.example.com:8443/x"), None);
    }

    #[test]
    fn select_handles_userinfo_and_ipv6_hosts() {
        let cfg = ProxyConfig {
            proxy_url: Some("http://proxy.corp:3128".to_string()),
            no_proxy: Some("::1".to_string()),
            ..ProxyConfig::default()
        };
        assert_eq!(cfg.select_proxy_url("http://[::1]:8080/health"), None);
        // Userinfo must not confuse host extraction.
        assert_eq!(
            cfg.select_proxy_url("https://user:pw@anchor.example.com/x"),
            Some("http://proxy.corp:3128")
        );
    }

    // ── Secret redaction (#606) ───────────────────────────────────────────────

    #[test]
    fn proxy_credentials_debug_redacts_password() {
        let creds = ProxyCredentials {
            username: "svc-anchor".to_string(),
            password: "super-secret-pw".to_string(),
        };
        let shown = alloc::format!("{:?}", creds);
        assert!(shown.contains("svc-anchor"), "username should be visible: {shown}");
        assert!(!shown.contains("super-secret-pw"), "password must be redacted: {shown}");
        assert!(shown.contains("<redacted>"), "got: {shown}");
    }

    #[test]
    fn proxy_config_debug_redacts_password() {
        let shown = alloc::format!("{:?}", full_proxy_config());
        assert!(!shown.contains("s3cret"), "password must be redacted: {shown}");
    }

    #[test]
    fn request_credentials_debug_redacts_secrets() {
        let bearer = RequestCredentials::Bearer("jwt-secret-token".to_string());
        let basic = RequestCredentials::Basic {
            username: "user".to_string(),
            password: "basic-secret".to_string(),
        };
        let header = RequestCredentials::Header {
            name: "X-Api-Key".to_string(),
            value: "api-key-secret".to_string(),
        };
        for (creds, secret) in [
            (&bearer, "jwt-secret-token"),
            (&basic, "basic-secret"),
            (&header, "api-key-secret"),
        ] {
            let shown = alloc::format!("{:?}", creds);
            assert!(!shown.contains(secret), "secret must be redacted: {shown}");
            assert!(shown.contains("<redacted>"), "got: {shown}");
        }
    }

    #[test]
    fn outbound_options_debug_redacts_signing_key_and_credentials() {
        let opts = OutboundRequestOptions::with_idempotency_key("idem-1")
            .with_signing_key(b"hmac-secret")
            .with_bearer_token("bearer-secret");
        let shown = alloc::format!("{:?}", opts);
        assert!(shown.contains("idem-1"), "idempotency key is not a secret: {shown}");
        assert!(!shown.contains("hmac-secret"), "got: {shown}");
        assert!(!shown.contains("bearer-secret"), "got: {shown}");
    }

    // ── RequestCredentials headers and validation (#606) ──────────────────────

    #[test]
    fn bearer_credentials_emit_authorization_header() {
        let creds = RequestCredentials::Bearer("my-jwt".to_string());
        assert_eq!(
            creds.to_header(),
            ("Authorization".to_string(), "Bearer my-jwt".to_string())
        );
    }

    #[test]
    fn basic_credentials_emit_base64_authorization_header() {
        let creds = RequestCredentials::Basic {
            username: "user".to_string(),
            password: "pass".to_string(),
        };
        // base64("user:pass") == "dXNlcjpwYXNz"
        assert_eq!(
            creds.to_header(),
            ("Authorization".to_string(), "Basic dXNlcjpwYXNz".to_string())
        );
    }

    #[test]
    fn header_credentials_emit_custom_header() {
        let creds = RequestCredentials::Header {
            name: "X-Api-Key".to_string(),
            value: "key-123".to_string(),
        };
        assert_eq!(creds.to_header(), ("X-Api-Key".to_string(), "key-123".to_string()));
    }

    #[test]
    fn request_credentials_validation_rejects_bad_values() {
        assert!(RequestCredentials::Bearer(String::new()).validate().is_err());
        assert!(RequestCredentials::Bearer("tok\r\nen".to_string()).validate().is_err());
        assert!(RequestCredentials::Basic {
            username: String::new(),
            password: "pw".to_string(),
        }
        .validate()
        .is_err());
        assert!(RequestCredentials::Basic {
            username: "a:b".to_string(),
            password: "pw".to_string(),
        }
        .validate()
        .is_err());
        assert!(RequestCredentials::Header {
            name: "Bad Header".to_string(),
            value: "v".to_string(),
        }
        .validate()
        .is_err());
        assert!(RequestCredentials::Header {
            name: "X-Api-Key".to_string(),
            value: "v\nv".to_string(),
        }
        .validate()
        .is_err());
    }

    #[test]
    fn request_credentials_validation_accepts_good_values() {
        assert_eq!(RequestCredentials::Bearer("jwt".to_string()).validate(), Ok(()));
        assert_eq!(
            RequestCredentials::Basic {
                username: "user".to_string(),
                password: "pw".to_string(),
            }
            .validate(),
            Ok(())
        );
        assert_eq!(
            RequestCredentials::Header {
                name: "X-Api-Key".to_string(),
                value: "key-123".to_string(),
            }
            .validate(),
            Ok(())
        );
    }

    #[test]
    fn outbound_options_validate_delegates_to_credentials() {
        assert_eq!(OutboundRequestOptions::default().validate(), Ok(()));
        let good = OutboundRequestOptions::default().with_bearer_token("jwt");
        assert_eq!(good.validate(), Ok(()));
        let bad = OutboundRequestOptions::default().with_bearer_token("");
        assert!(bad.validate().is_err());
    }

    #[test]
    fn build_headers_includes_credentials_alongside_existing_headers() {
        let opts = OutboundRequestOptions::with_idempotency_key("idem-7")
            .with_signing_key(b"sk")
            .with_basic_auth("user", "pass");
        let headers = opts.build_headers("body");
        let names: alloc::vec::Vec<&str> = headers.iter().map(|(k, _)| k.as_str()).collect();
        assert!(names.contains(&"Idempotency-Key"));
        assert!(names.contains(&"X-Request-Id"));
        assert!(names.contains(&"X-Anchor-Signature"));
        assert!(names.contains(&"Authorization"));
        assert!(opts.has_credentials());
    }

    #[test]
    fn post_with_options_passes_authorization_to_transport() {
        let opts = OutboundRequestOptions::default().with_bearer_token("sep10-jwt");
        let mut captured: alloc::vec::Vec<(String, String)> = alloc::vec::Vec::new();
        let result = post_with_options(
            "https://anchor.example.com/sep6/deposit",
            r#"{"amount":10}"#,
            Some(&opts),
            |_url, _body, hdrs| {
                captured.extend(hdrs.iter().cloned());
                Ok(200u16)
            },
        );
        assert_eq!(result, Ok(200));
        let auth = captured.iter().find(|(k, _)| k == "Authorization");
        assert_eq!(auth.map(|(_, v)| v.as_str()), Some("Bearer sep10-jwt"));
    }

    // ── Client construction with credentials (std) ────────────────────────────

    #[cfg(feature = "std")]
    #[test]
    fn build_client_with_full_proxy_config_succeeds() {
        let client = build_client(Some(&full_proxy_config()), 10);
        assert!(client.is_ok(), "full proxy config should build: {:?}", client.err());
    }

    #[cfg(feature = "std")]
    #[test]
    fn build_client_rejects_credentials_without_proxy() {
        let cfg = ProxyConfig {
            credentials: Some(ProxyCredentials {
                username: "user".to_string(),
                password: "pw".to_string(),
            }),
            ..ProxyConfig::default()
        };
        let result = build_client(Some(&cfg), 10);
        assert!(result.is_err());
    }

    #[cfg(feature = "std")]
    #[test]
    fn build_client_rejects_invalid_per_scheme_proxy() {
        let cfg = ProxyConfig {
            https_proxy_url: Some("ftp://proxy.corp:21".to_string()),
            ..ProxyConfig::default()
        };
        let result = build_client(Some(&cfg), 10);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid proxy URL"));
    }

    #[cfg(feature = "std")]
    #[test]
    fn build_client_with_policy_accepts_full_proxy_config() {
        let client = build_client_with_policy(Some(&full_proxy_config()), &ConnectionPolicy::strict());
        assert!(client.is_ok());
    }

    #[cfg(feature = "std")]
    #[test]
    fn proxy_credentials_serde_round_trip() {
        let cfg = full_proxy_config();
        let json = serde_json::to_string(&cfg).expect("serialize");
        let back: ProxyConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(cfg, back);
    }

    #[cfg(feature = "std")]
    #[test]
    fn proxy_config_rejects_unknown_fields() {
        let json = r#"{"proxy_url":"http://proxy.corp:3128","proxy_password":"oops"}"#;
        let result: Result<ProxyConfig, _> = serde_json::from_str(json);
        assert!(result.is_err(), "unknown fields (likely typos) must be rejected");
    }

    // ── Issue #828: HTTP 429 is a retryable status ────────────────────────────

    #[test]
    fn http_status_429_is_retryable() {
        assert_eq!(classify_http_status_code(429), HttpStatusClass::Retryable);
        assert!(is_http_status_retryable(429), "rate limiting is transient");
    }

    #[test]
    fn http_status_permanent_codes_stay_permanent() {
        for status in [400u16, 401, 403, 404, 405, 409, 410, 422, 451, 501, 505] {
            assert_eq!(
                classify_http_status_code(status),
                HttpStatusClass::Permanent,
                "HTTP {status} should classify as permanent"
            );
            assert!(!is_http_status_retryable(status));
        }
    }

    #[test]
    fn http_status_success_and_transient_server_errors() {
        for status in [200u16, 201, 204, 301, 302, 304, 399] {
            assert_eq!(classify_http_status_code(status), HttpStatusClass::Success);
            assert!(!is_http_status_retryable(status));
        }
        for status in [408u16, 500, 502, 503, 504] {
            assert_eq!(classify_http_status_code(status), HttpStatusClass::Retryable);
            assert!(is_http_status_retryable(status));
        }
    }

    // ── Issue #827: webhook timeout keeps its millisecond unit ────────────────

    #[cfg(feature = "std")]
    #[test]
    fn webhook_timeout_preserves_millisecond_unit() {
        use std::time::Duration;
        // 0 means "unset" → default budget.
        assert_eq!(webhook_timeout(0), Duration::from_secs(DEFAULT_WEBHOOK_TIMEOUT_SECS));
        // Whole-second values are unchanged.
        assert_eq!(webhook_timeout(30_000), Duration::from_secs(30));
        assert_eq!(webhook_timeout(5_000), Duration::from_secs(5));
        // Sub-second and non-whole-second values are preserved exactly, not
        // truncated (250ms used to become 1s, 1500ms used to become 1s).
        assert_eq!(webhook_timeout(1_500), Duration::from_millis(1_500));
        assert_eq!(webhook_timeout(250), Duration::from_millis(250));
        assert_eq!(webhook_timeout(1), Duration::from_millis(1));
    }

    // ── Issue #826: the redirect chain is bounded at client construction ──────

    #[cfg(feature = "std")]
    #[test]
    fn build_client_bounds_the_redirect_chain() {
        use std::io::{Read, Write};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let hits_srv = std::sync::Arc::clone(&hits);

        // A mock server that answers *every* request with a 302 back to itself:
        // an endless redirect chain if the client does not cap it.
        let response = b"HTTP/1.1 302 Found\r\nLocation: /a\r\nContent-Length: 0\r\n\r\n";
        let server = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            while std::time::Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        hits_srv.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        let mut buf = [0u8; 512];
                        let _read = stream.read(&mut buf);
                        let _ = stream.write_all(response);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });

        let client = build_client(None, 5).expect("client builds");
        let result = client.get(alloc::format!("http://{addr}/start")).send();
        let _ = server.join();

        let err = result.expect_err("an endless redirect chain must be stopped, not followed");
        assert!(
            err.is_redirect() || err.to_string().to_lowercase().contains("redirect"),
            "expected a redirect-limit error, got: {err}"
        );

        let cap = ConnectionPolicy::default().max_redirects;
        let total = hits.load(std::sync::atomic::Ordering::SeqCst);
        assert!(
            (2..=cap + 1).contains(&total),
            "requests should stop at the configured redirect cap ({cap}); saw {total}"
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn build_client_still_allows_redirects_within_the_cap() {
        // The cap bounds the chain; it does not disable redirects and it does
        // not touch a direct request. The default policy keeps a non-zero
        // allowance, and clients still build with and without a timeout.
        assert!(ConnectionPolicy::default().max_redirects >= 1);
        assert!(build_client(None, 5).is_ok());
        assert!(build_client(None, 0).is_ok());
    }

    // ── Idempotency-Key empty-key consistency (Bug 4) ─────────────────────────

    /// `build_headers` must not emit an `Idempotency-Key` header when the key
    /// is `Some("")` — consistent with `has_idempotency_key` which already
    /// treats an empty `Some` as absent.
    #[test]
    fn build_headers_empty_some_idempotency_key_emits_no_header() {
        let opts = OutboundRequestOptions {
            idempotency_key: Some(alloc::string::String::new()),
            signing_key: None,
            trace: None,
            credentials: None,
        };
        // has_idempotency_key must agree: empty key is absent.
        assert!(!opts.has_idempotency_key(), "has_idempotency_key should be false for Some(\"\")");
        let headers = opts.build_headers("body");
        let names: alloc::vec::Vec<&str> = headers.iter().map(|(k, _)| k.as_str()).collect();
        assert!(
            !names.contains(&"Idempotency-Key"),
            "build_headers must not emit Idempotency-Key for an empty key, got: {names:?}"
        );
        assert!(
            !names.contains(&"X-Request-Id"),
            "build_headers must not emit X-Request-Id for an empty key, got: {names:?}"
        );
    }

    /// A non-empty idempotency key must still be emitted exactly once.
    #[test]
    fn build_headers_non_empty_idempotency_key_emits_header_once() {
        let opts = OutboundRequestOptions::with_idempotency_key("txn-xyz");
        assert!(opts.has_idempotency_key());
        let headers = opts.build_headers("body");
        let ik_count = headers.iter().filter(|(k, _)| k == "Idempotency-Key").count();
        let ri_count = headers.iter().filter(|(k, _)| k == "X-Request-Id").count();
        assert_eq!(ik_count, 1, "Idempotency-Key should appear exactly once");
        assert_eq!(ri_count, 1, "X-Request-Id should appear exactly once");
        // The value must be the key itself.
        let val = headers.iter().find(|(k, _)| k == "Idempotency-Key").map(|(_, v)| v.as_str());
        assert_eq!(val, Some("txn-xyz"));
    }

    /// `has_idempotency_key` and `build_headers` must agree: if `has_idempotency_key`
    /// returns `false`, no `Idempotency-Key` header is emitted and vice versa.
    #[test]
    fn has_idempotency_key_and_build_headers_are_consistent() {
        for key in &[None, Some(""), Some("txn-001")] {
            let opts = OutboundRequestOptions {
                idempotency_key: key.map(|s| s.to_string()),
                signing_key: None,
                trace: None,
                credentials: None,
            };
            let reported = opts.has_idempotency_key();
            let emitted = opts.build_headers("x")
                .iter()
                .any(|(k, _)| k == "Idempotency-Key");
            assert_eq!(
                reported, emitted,
                "has_idempotency_key={reported} but Idempotency-Key emitted={emitted} for key={key:?}"
            );
        }
    }
}
