# SEP-24 Origin Pinning

SEP-24 interactive flows return a redirect URL that the client must open in a
browser. The origin-pinning functions let callers lock that URL to a specific
origin — typically the value of `transfer_server_sep0024` from
`stellar.toml` — so a compromised or misconfigured anchor cannot redirect users
to a different host.

## Functions

```
initiate_interactive_deposit(raw) -> Result<InteractiveDepositResponse, AnchorKitError>
initiate_interactive_deposit_with_origin(raw, expected_origin) -> Result<...>

initiate_interactive_withdrawal(raw) -> Result<InteractiveWithdrawalResponse, AnchorKitError>
initiate_interactive_withdrawal_with_origin(raw, expected_origin) -> Result<...>

validate_interactive_url(url, allowed_origin) -> Result<(), AnchorKitError>
```

Source: `src/sep24.rs`

## The `expected_origin` / `allowed_origin` parameter

**Type:** `Option<&str>`

**What it must be:** A full origin in the form `scheme://host` or
`scheme://host:port`. The value must include the scheme and host; a bare
hostname or path is not accepted.

```
// Correct — full origin
Some("https://anchor.example.com")

// Correct — non-default port included
Some("https://anchor.example.com:8443")

// Wrong — bare hostname, will be rejected
Some("anchor.example.com")
```

When `None` is passed the origin check is skipped entirely and any valid HTTPS
URL is accepted.

## Normalization

Before the origin comparison, both the redirect URL and the allowed origin are
normalized via `normalize_url` (`src/url_normalizer.rs`):

1. Scheme and host are lowercased.
2. The default HTTPS port (443) is stripped.
3. A bare trailing slash is removed.

The comparison therefore covers three components — **scheme, host, and
effective port** — in a case-insensitive way. The path, query string, and
fragment of the redirect URL are not checked; they may differ freely from the
allowed origin.

| Redirect URL | Allowed origin | Result |
|---|---|---|
| `https://anchor.example.com/sep24/deposit?asset=USDC` | `https://anchor.example.com` | ✅ accepted |
| `HTTPS://Anchor.Example.COM:443/dep` | `https://anchor.example.com` | ✅ accepted (normalized) |
| `https://anchor.example.com:8443/dep` | `https://anchor.example.com` | ❌ rejected — port differs |
| `https://evil.example.com/dep` | `https://anchor.example.com` | ❌ rejected — host differs |
| `http://anchor.example.com/dep` | `https://anchor.example.com` | ❌ rejected — scheme differs |

The last row illustrates that the scheme is part of the comparison: an HTTP URL
is rejected even when the host matches, because cleartext redirects are not
permitted regardless of origin pinning.

## Mismatch behavior

When the redirect URL's origin does not match `expected_origin`, both
`initiate_interactive_deposit_with_origin` and
`initiate_interactive_withdrawal_with_origin` return:

```
Err(AnchorKitError {
    code: ErrorCode::InvalidEndpointFormat,   // numeric value 12
    message: "interactive URL origin does not match allowed origin",
    context: Some("<normalized redirect URL>"),
})
```

The `context` field holds the normalized form of the redirect URL — not the
raw input — so it reflects what the validator actually compared. No separate
"cross-origin" error code exists; the mismatch is a subcase of
`InvalidEndpointFormat`.

## Examples

### Same-origin deposit (success)

```rust
use anchorkit::sep24::{
    initiate_interactive_deposit_with_origin, RawInteractiveDepositResponse,
};

let raw = RawInteractiveDepositResponse {
    url: "https://anchor.example.com/sep24/deposit?asset=USDC&token=abc".into(),
    id:  "txn-001".into(),
};

let resp = initiate_interactive_deposit_with_origin(
    raw,
    Some("https://anchor.example.com"),
)
.expect("same-origin redirect must be accepted");

assert_eq!(resp.url, "https://anchor.example.com/sep24/deposit?asset=USDC&token=abc");
assert_eq!(resp.id,  "txn-001");
```

### Cross-origin redirect (rejected)

```rust
use anchorkit::sep24::{
    initiate_interactive_deposit_with_origin, RawInteractiveDepositResponse,
};
use anchorkit::ErrorCode;

let raw = RawInteractiveDepositResponse {
    url: "https://other.example.com/sep24/deposit".into(),
    id:  "txn-002".into(),
};

let err = initiate_interactive_deposit_with_origin(
    raw,
    Some("https://anchor.example.com"),
)
.unwrap_err();

assert_eq!(err.code, ErrorCode::InvalidEndpointFormat);
```

### No pinning (unpinned HTTPS accepted)

```rust
use anchorkit::sep24::{
    initiate_interactive_deposit_with_origin, RawInteractiveDepositResponse,
};

let raw = RawInteractiveDepositResponse {
    url: "https://any-anchor.example.org/sep24/deposit".into(),
    id:  "txn-003".into(),
};

// None skips the origin check; any valid HTTPS URL is accepted.
let resp = initiate_interactive_deposit_with_origin(raw, None).unwrap();
assert!(resp.url.starts_with("https://"));
```

## Additional constraints enforced unconditionally

Origin pinning is layered on top of a set of checks that always apply:

- Scheme must be `https`. HTTP is rejected unconditionally.
- Userinfo (e.g. `user:pass@`) is rejected.
- IP literals (e.g. `[::1]`, `192.168.1.1`) are rejected.
- Open-redirect patterns are rejected: a query parameter whose name matches
  `redirect`, `callback`, `next`, `return_url`, `return_uri`, `dest`, etc.,
  and whose value contains `://`, is treated as an open redirect and rejected.
  A relative path value (no `://`) is allowed.
- Both `url` and `id` must be non-empty (non-whitespace).

Wildcards in the `expected_origin` value are not supported. The allowed origin
must be an exact, fully specified origin.

## Related tests

- `tests/sep24_origin_pinning_tests.rs` — origin comparison, case insensitivity,
  port mismatch, cleartext rejection, invalid allowed-origin format.
- `src/sep24.rs` (inline `#[cfg(test)]`) — open-redirect patterns, URL
  normalization, transaction ID validation.
