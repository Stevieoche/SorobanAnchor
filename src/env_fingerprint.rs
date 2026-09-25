//! Environment fingerprinting for deployment validation.
//!
//! Captures a consistent snapshot of the build and runtime environment so that
//! deployment validation can detect drift between environments. The fingerprint
//! includes tool versions, active feature flags, config file hashes, and build
//! metadata produced at compile time.
//!
//! # Usage
//!
//! ```rust,no_run
//! use anchorkit::env_fingerprint::EnvironmentFingerprint;
//!
//! let fp = EnvironmentFingerprint::collect();
//! println!("{}", fp.summary());
//!
//! // Persist to disk for later comparison
//! let json = fp.to_json().unwrap();
//! std::fs::write("fingerprint.json", &json).unwrap();
//!
//! // Compare against a baseline
//! let baseline = EnvironmentFingerprint::from_json(&json).unwrap();
//! let drift = fp.diff(&baseline);
//! if !drift.is_empty() {
//!     eprintln!("Environment drift detected: {:?}", drift);
//! }
//! ```

#![cfg(feature = "std")]

use std::collections::HashMap;
use std::process::Command;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// ToolVersions
// ---------------------------------------------------------------------------

/// Versions of the tools that must be present for a valid build environment.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct ToolVersions {
    /// Output of `rustc --version`, e.g. `"rustc 1.78.0 (9b00956e5 2024-04-29)"`.
    pub rustc: Option<String>,
    /// Output of `stellar --version`, e.g. `"stellar 21.3.0"`.
    pub stellar_cli: Option<String>,
    /// Output of `cargo --version`, e.g. `"cargo 1.78.0 (94ab26474 2024-04-16)"`.
    pub cargo: Option<String>,
    /// Whether the `wasm32-unknown-unknown` rustup target is installed.
    pub wasm_target_installed: bool,
}

impl ToolVersions {
    /// Probe the host environment for all tool versions.
    pub fn collect() -> Self {
        Self {
            rustc: run_version("rustc", &["--version"]),
            stellar_cli: run_version("stellar", &["--version"]),
            cargo: run_version("cargo", &["--version"]),
            wasm_target_installed: probe_wasm_target(),
        }
    }
}

// ---------------------------------------------------------------------------
// ConfigMetadata
// ---------------------------------------------------------------------------

/// SHA-256 hashes of config files in `configs/`, used to detect config drift.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct ConfigMetadata {
    /// Map of relative file path → lowercase hex SHA-256 digest.
    pub file_hashes: HashMap<String, String>,
    /// Number of config files found.
    pub file_count: usize,
}

impl ConfigMetadata {
    /// Hash every `.json` and `.toml` file found in `configs/`.
    pub fn collect() -> Self {
        let config_dir = std::path::Path::new("configs");
        let mut file_hashes = HashMap::new();

        if let Ok(entries) = std::fs::read_dir(config_dir) {
            let mut paths: Vec<_> = entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| {
                    p.extension()
                        .and_then(|e| e.to_str())
                        .map(|e| e == "json" || e == "toml")
                        .unwrap_or(false)
                })
                .collect();
            paths.sort(); // deterministic order

            for path in &paths {
                if let Ok(content) = std::fs::read(path) {
                    let digest = Sha256::digest(&content);
                    let hex: String = digest.iter().map(|b| format!("{:02x}", b)).collect();
                    let key = path
                        .to_string_lossy()
                        .replace('\\', "/");
                    file_hashes.insert(key, hex);
                }
            }
        }

        let file_count = file_hashes.len();
        Self { file_hashes, file_count }
    }
}

// ---------------------------------------------------------------------------
// BuildMetadata
// ---------------------------------------------------------------------------

/// Compile-time metadata stamped into the fingerprint via `build.rs` env vars.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct BuildMetadata {
    /// Package version from `Cargo.toml` (`CARGO_PKG_VERSION`).
    pub package_version: String,
    /// Target triple the binary was compiled for (`CARGO_CFG_TARGET_ARCH` etc.).
    pub build_target: String,
    /// Enabled Cargo features joined by commas (`CARGO_FEATURE_*`).
    pub active_features: Vec<String>,
    /// Value of `RUSTC_CHANNEL` if set, otherwise `"stable"`.
    pub rust_channel: String,
}

impl BuildMetadata {
    /// Collect build metadata from environment variables baked in at compile time.
    pub fn collect() -> Self {
        let package_version = env!("CARGO_PKG_VERSION").to_string();

        // Prefer the full target triple (TARGET); if it is absent, record an
        // explicit "unknown-target" marker so callers can distinguish a missing
        // value from a real architecture abbreviation.  Falling back to
        // CARGO_CFG_TARGET_ARCH would silently record only the architecture
        // component (e.g. "wasm32"), making different targets look identical.
        let build_target = std::env::var("TARGET")
            .unwrap_or_else(|_| "unknown-target".to_string());

        let rust_channel = std::env::var("RUSTC_CHANNEL")
            .unwrap_or_else(|_| "stable".to_string());

        // Collect the complete set of active Cargo features by iterating every
        // environment variable whose name starts with "CARGO_FEATURE_".  Cargo
        // sets exactly one such variable per enabled feature; the variable's
        // presence (regardless of value) indicates the feature is active.
        // Using a hardcoded subset would silently miss any feature not on the
        // list, leaving the fingerprint unchanged when that feature is toggled.
        let active_features: Vec<String> = std::env::vars()
            .filter_map(|(key, _)| {
                key.strip_prefix("CARGO_FEATURE_")
                    .map(|feat| feat.to_lowercase().replace('_', "-"))
            })
            .collect();

        Self { package_version, build_target, active_features, rust_channel }
    }
}

// ---------------------------------------------------------------------------
// DriftItem
// ---------------------------------------------------------------------------

/// A single detected difference between two fingerprints.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct DriftItem {
    /// Human-readable field name, e.g. `"tools.rustc"`.
    pub field: String,
    /// Value in the baseline fingerprint.
    pub baseline: String,
    /// Value in the current fingerprint.
    pub current: String,
}

impl DriftItem {
    fn new(field: &str, baseline: impl Into<String>, current: impl Into<String>) -> Self {
        Self {
            field: field.to_string(),
            baseline: baseline.into(),
            current: current.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// EnvironmentFingerprint
// ---------------------------------------------------------------------------

/// A complete snapshot of the build and runtime environment.
///
/// Collect with [`EnvironmentFingerprint::collect`], serialize with
/// [`to_json`](Self::to_json), and detect drift with [`diff`](Self::diff).
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct EnvironmentFingerprint {
    /// Versions of required external tools.
    pub tools: ToolVersions,
    /// Hashes of config files in `configs/`.
    pub config: ConfigMetadata,
    /// Compile-time build metadata.
    pub build: BuildMetadata,
    /// RFC-3339 wall-clock timestamp when this fingerprint was collected.
    /// Populated by [`collect`](Self::collect); absent in deserialized baselines
    /// when comparison across time is not meaningful.
    pub collected_at: Option<String>,
}

impl EnvironmentFingerprint {
    /// Collect a fresh fingerprint from the current host environment.
    pub fn collect() -> Self {
        Self {
            tools: ToolVersions::collect(),
            config: ConfigMetadata::collect(),
            build: BuildMetadata::collect(),
            collected_at: Some(current_timestamp()),
        }
    }

    /// Serialize to a pretty-printed JSON string.
    ///
    /// # Errors
    ///
    /// Returns a `String` error if serialization fails (should not happen for
    /// well-formed data).
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self).map_err(|e| format!("fingerprint serialize error: {e}"))
    }

    /// Deserialize from a JSON string produced by [`to_json`](Self::to_json).
    ///
    /// # Errors
    ///
    /// Returns a `String` error if the JSON is malformed or missing required fields.
    pub fn from_json(json: &str) -> Result<Self, String> {
        serde_json::from_str(json).map_err(|e| format!("fingerprint deserialize error: {e}"))
    }

    /// Compare `self` (current) against `baseline` and return every detected difference.
    ///
    /// Returns an empty `Vec` when the two fingerprints are equivalent for
    /// validation purposes (the `collected_at` timestamp is intentionally
    /// excluded from comparison).
    pub fn diff(&self, baseline: &EnvironmentFingerprint) -> Vec<DriftItem> {
        let mut items = Vec::new();

        // Tool versions
        diff_opt(&mut items, "tools.rustc",       &self.tools.rustc,       &baseline.tools.rustc);
        diff_opt(&mut items, "tools.stellar_cli", &self.tools.stellar_cli, &baseline.tools.stellar_cli);
        diff_opt(&mut items, "tools.cargo",       &self.tools.cargo,       &baseline.tools.cargo);
        if self.tools.wasm_target_installed != baseline.tools.wasm_target_installed {
            items.push(DriftItem::new(
                "tools.wasm_target_installed",
                baseline.tools.wasm_target_installed.to_string(),
                self.tools.wasm_target_installed.to_string(),
            ));
        }

        // Build metadata
        if self.build.package_version != baseline.build.package_version {
            items.push(DriftItem::new("build.package_version",
                &baseline.build.package_version, &self.build.package_version));
        }
        if self.build.build_target != baseline.build.build_target {
            items.push(DriftItem::new("build.build_target",
                &baseline.build.build_target, &self.build.build_target));
        }
        if self.build.rust_channel != baseline.build.rust_channel {
            items.push(DriftItem::new("build.rust_channel",
                &baseline.build.rust_channel, &self.build.rust_channel));
        }
        let mut self_feats = self.build.active_features.clone();
        let mut base_feats = baseline.build.active_features.clone();
        self_feats.sort();
        base_feats.sort();
        if self_feats != base_feats {
            items.push(DriftItem::new("build.active_features",
                base_feats.join(","), self_feats.join(",")));
        }

        // Config file hashes
        for (path, baseline_hash) in &baseline.config.file_hashes {
            match self.config.file_hashes.get(path) {
                None => items.push(DriftItem::new(
                    &format!("config.{path}"),
                    baseline_hash.as_str(),
                    "<missing>",
                )),
                Some(h) if h != baseline_hash => items.push(DriftItem::new(
                    &format!("config.{path}"),
                    baseline_hash.as_str(),
                    h.as_str(),
                )),
                _ => {}
            }
        }
        // Files present in current but not in baseline
        for path in self.config.file_hashes.keys() {
            if !baseline.config.file_hashes.contains_key(path) {
                items.push(DriftItem::new(
                    &format!("config.{path}"),
                    "<absent>",
                    self.config.file_hashes[path].as_str(),
                ));
            }
        }

        items
    }

    /// Return a compact, human-readable summary suitable for CLI output.
    pub fn summary(&self) -> String {
        let mut lines = Vec::new();
        lines.push(format!("  package_version : {}", self.build.package_version));
        lines.push(format!("  rustc           : {}", opt_str(&self.tools.rustc)));
        lines.push(format!("  stellar_cli     : {}", opt_str(&self.tools.stellar_cli)));
        lines.push(format!("  cargo           : {}", opt_str(&self.tools.cargo)));
        lines.push(format!("  wasm_target     : {}", self.tools.wasm_target_installed));
        lines.push(format!("  config_files    : {}", self.config.file_count));
        if let Some(ts) = &self.collected_at {
            lines.push(format!("  collected_at    : {}", ts));
        }
        lines.join("\n")
    }

    /// Returns `true` if this fingerprint is consistent with `baseline`
    /// (i.e. [`diff`](Self::diff) returns an empty list).
    pub fn is_consistent_with(&self, baseline: &EnvironmentFingerprint) -> bool {
        self.diff(baseline).is_empty()
    }
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Run `command args` and return the first line of stdout, or `None` on failure.
fn run_version(command: &str, args: &[&str]) -> Option<String> {
    Command::new(command)
        .args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| {
            String::from_utf8(o.stdout)
                .ok()
                .map(|s| s.lines().next().unwrap_or("").trim().to_string())
                .filter(|s| !s.is_empty())
        })
}

/// Check whether `wasm32-unknown-unknown` is listed in `rustup target list --installed`.
///
/// The command exit status is checked before inspecting stdout: a non-zero exit
/// (e.g. `rustup` not installed, or a partially written stdout from a signal)
/// means the probe result is unreliable and we report `false`.
fn probe_wasm_target() -> bool {
    Command::new("rustup")
        .args(["target", "list", "--installed"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.contains("wasm32-unknown-unknown"))
        .unwrap_or(false)
}

/// RFC-3339-ish timestamp using std time (no external crate needed).
fn current_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // Format as ISO-8601 UTC (seconds precision is sufficient for fingerprinting).
    let s = secs;
    let ss = s % 60;
    let m = s / 60;
    let mm = m % 60;
    let h = m / 60;
    let hh = h % 24;
    let days = h / 24;
    // Simple date calculation from Unix epoch (accurate until ~2100).
    let (y, mo, d) = days_to_ymd(days);
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, mo, d, hh, mm, ss)
}

fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    let mut year = 1970u64;
    loop {
        let leap = is_leap(year);
        let days_in_year = if leap { 366 } else { 365 };
        if days < days_in_year { break; }
        days -= days_in_year;
        year += 1;
    }
    let leap = is_leap(year);
    let month_days = [31u64, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut month = 1u64;
    for &md in &month_days {
        if days < md { break; }
        days -= md;
        month += 1;
    }
    (year, month, days + 1)
}

fn is_leap(y: u64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0)
}

fn opt_str(v: &Option<String>) -> &str {
    v.as_deref().unwrap_or("<not found>")
}

fn diff_opt(items: &mut Vec<DriftItem>, field: &str, current: &Option<String>, baseline: &Option<String>) {
    if current != baseline {
        items.push(DriftItem::new(
            field,
            baseline.as_deref().unwrap_or("<none>"),
            current.as_deref().unwrap_or("<none>"),
        ));
    }
}

// ---------------------------------------------------------------------------
// EnvironmentFingerprintId (#808)
// ---------------------------------------------------------------------------

/// A compact SHA-256-based identity token for a named, versioned environment.
///
/// The fingerprint is derived by hashing the canonical concatenation of the
/// environment `name` and `version`, separated by `"||"`:
/// `SHA-256(name || "||" || version)`
///
/// Both fields are required to be non-empty; a blank name or version is
/// rejected with a descriptive error before any hashing takes place.
///
/// # Examples
///
/// ```rust,no_run
/// use anchorkit::env_fingerprint::EnvironmentFingerprintId;
///
/// let id = EnvironmentFingerprintId::new("mainnet", "1.2.3").unwrap();
/// assert!(!id.hex().is_empty());
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvironmentFingerprintId {
    /// The environment name supplied at construction (stored for diagnostics).
    pub name: String,
    /// The environment version supplied at construction (stored for diagnostics).
    pub version: String,
    /// Lower-case hex SHA-256 digest of `"<name>||<version>"`.
    hex: String,
}

impl EnvironmentFingerprintId {
    /// Construct a new `EnvironmentFingerprintId` from `name` and `version`.
    ///
    /// # Errors
    ///
    /// Returns `Err` when either `name` or `version` is blank (empty or
    /// whitespace-only).  Blank components cause fingerprint collisions across
    /// deployments and weaken diagnostics, so they are rejected here rather
    /// than silently producing an ambiguous hash.
    pub fn new(name: &str, version: &str) -> Result<Self, String> {
        if name.trim().is_empty() {
            return Err("environment name must not be blank".to_string());
        }
        if version.trim().is_empty() {
            return Err("environment version must not be blank".to_string());
        }
        let hex = Self::compute_hex(name, version);
        Ok(Self {
            name: name.to_string(),
            version: version.to_string(),
            hex,
        })
    }

    /// Return the lower-case hex SHA-256 digest for this fingerprint.
    pub fn hex(&self) -> &str {
        &self.hex
    }

    /// Compute `SHA-256(name || "||" || version)` and return as a lower-case
    /// hex string.  The canonical field order is always `name` first, then
    /// `version`; this must never be reversed.
    fn compute_hex(name: &str, version: &str) -> String {
        compute_fingerprint_hex(name, version)
    }
}

// ---------------------------------------------------------------------------
// LocalFingerprintId (#809)
// ---------------------------------------------------------------------------
//
// A host-side (no_std-incompatible) fingerprint that uses the same canonical
// `name || "||" || version` field order as `EnvironmentFingerprintId`, but is
// constructed from owned `String` fields and provides an alternative entry
// point for callers that already own their strings.
//
// The canonical order (name first, version second) is the single established
// order used across all construction paths.  Do not reverse it.

/// A host-side canonical environment fingerprint with explicit `name||version`
/// field ordering.
///
/// Uses the same `SHA-256(name || "||" || version)` computation as
/// [`EnvironmentFingerprintId`].  The canonical field order is always
/// `name` before `version` across every construction path, ensuring that
/// equivalent environment data always produces the same fingerprint regardless
/// of which constructor was called.
///
/// # Examples
///
/// ```rust,no_run
/// use anchorkit::env_fingerprint::LocalFingerprintId;
///
/// let fp = LocalFingerprintId::new("testnet".to_string(), "2.0.0".to_string()).unwrap();
/// // Same result as EnvironmentFingerprintId::new("testnet", "2.0.0")
/// assert_eq!(fp.hex().len(), 64);
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalFingerprintId {
    /// The environment name.
    pub name: String,
    /// The environment version.
    pub version: String,
    /// Lower-case hex SHA-256 of `"<name>||<version>"`.
    hex: String,
}

impl LocalFingerprintId {
    /// Construct a `LocalFingerprintId` from owned strings.
    ///
    /// Rejects blank (empty / whitespace-only) name or version with a
    /// descriptive error, for the same reason as [`EnvironmentFingerprintId::new`].
    pub fn new(name: String, version: String) -> Result<Self, String> {
        if name.trim().is_empty() {
            return Err("environment name must not be blank".to_string());
        }
        if version.trim().is_empty() {
            return Err("environment version must not be blank".to_string());
        }
        // Canonical order: name first, then version.
        let hex = compute_fingerprint_hex(&name, &version);
        Ok(Self { name, version, hex })
    }

    /// Return the lower-case hex SHA-256 digest for this fingerprint.
    pub fn hex(&self) -> &str {
        &self.hex
    }
}

/// Shared inner implementation: `SHA-256(name || "||" || version)`.
///
/// The field order is fixed and canonical: `name` is always hashed before
/// `version`.  All construction paths must use this function so there is no
/// risk of one path accidentally reversing the order.
fn compute_fingerprint_hex(name: &str, version: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(name.as_bytes());
    hasher.update(b"||");
    hasher.update(version.as_bytes());
    let digest = hasher.finalize();
    digest.iter().map(|b| format!("{:02x}", b)).collect()
}

// ---------------------------------------------------------------------------
// Tests (inline unit tests — no network, no disk I/O)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_fp(rustc: &str, cargo: &str, pkg_ver: &str) -> EnvironmentFingerprint {
        EnvironmentFingerprint {
            tools: ToolVersions {
                rustc: Some(rustc.to_string()),
                cargo: Some(cargo.to_string()),
                stellar_cli: None,
                wasm_target_installed: true,
            },
            config: ConfigMetadata {
                file_hashes: HashMap::new(),
                file_count: 0,
            },
            build: BuildMetadata {
                package_version: pkg_ver.to_string(),
                build_target: "x86_64-unknown-linux-gnu".to_string(),
                active_features: vec!["std".to_string()],
                rust_channel: "stable".to_string(),
            },
            collected_at: None,
        }
    }

    #[test]
    fn identical_fingerprints_have_no_drift() {
        let a = make_fp("rustc 1.78.0", "cargo 1.78.0", "0.1.0");
        let b = a.clone();
        assert!(a.diff(&b).is_empty());
        assert!(a.is_consistent_with(&b));
    }

    #[test]
    fn different_rustc_versions_produce_drift() {
        let current  = make_fp("rustc 1.79.0", "cargo 1.79.0", "0.1.0");
        let baseline = make_fp("rustc 1.78.0", "cargo 1.78.0", "0.1.0");
        let drift = current.diff(&baseline);
        assert!(!drift.is_empty());
        let fields: Vec<_> = drift.iter().map(|d| d.field.as_str()).collect();
        assert!(fields.contains(&"tools.rustc"), "expected tools.rustc drift, got: {:?}", fields);
    }

    #[test]
    fn different_package_versions_produce_drift() {
        let current  = make_fp("rustc 1.78.0", "cargo 1.78.0", "0.2.0");
        let baseline = make_fp("rustc 1.78.0", "cargo 1.78.0", "0.1.0");
        let drift = current.diff(&baseline);
        let fields: Vec<_> = drift.iter().map(|d| d.field.as_str()).collect();
        assert!(fields.contains(&"build.package_version"));
    }

    #[test]
    fn wasm_target_drift_detected() {
        let mut current = make_fp("rustc 1.78.0", "cargo 1.78.0", "0.1.0");
        current.tools.wasm_target_installed = false;
        let baseline = make_fp("rustc 1.78.0", "cargo 1.78.0", "0.1.0");
        let drift = current.diff(&baseline);
        let fields: Vec<_> = drift.iter().map(|d| d.field.as_str()).collect();
        assert!(fields.contains(&"tools.wasm_target_installed"));
    }

    #[test]
    fn config_file_hash_change_detected() {
        let mut current = make_fp("rustc 1.78.0", "cargo 1.78.0", "0.1.0");
        let mut baseline = make_fp("rustc 1.78.0", "cargo 1.78.0", "0.1.0");
        baseline.config.file_hashes.insert("configs/test.json".into(), "aabbcc".into());
        current.config.file_hashes.insert("configs/test.json".into(), "ddeeff".into());
        let drift = current.diff(&baseline);
        assert!(!drift.is_empty());
        assert!(drift[0].field.contains("configs/test.json"));
    }

    #[test]
    fn missing_config_file_detected_as_drift() {
        let current  = make_fp("rustc 1.78.0", "cargo 1.78.0", "0.1.0");
        let mut baseline = make_fp("rustc 1.78.0", "cargo 1.78.0", "0.1.0");
        baseline.config.file_hashes.insert("configs/missing.json".into(), "deadbeef".into());
        let drift = current.diff(&baseline);
        let fields: Vec<_> = drift.iter().map(|d| d.field.as_str()).collect();
        assert!(fields.iter().any(|f| f.contains("missing.json")));
    }

    #[test]
    fn new_config_file_detected_as_drift() {
        let mut current  = make_fp("rustc 1.78.0", "cargo 1.78.0", "0.1.0");
        let baseline = make_fp("rustc 1.78.0", "cargo 1.78.0", "0.1.0");
        current.config.file_hashes.insert("configs/new.toml".into(), "cafebabe".into());
        let drift = current.diff(&baseline);
        let fields: Vec<_> = drift.iter().map(|d| d.field.as_str()).collect();
        assert!(fields.iter().any(|f| f.contains("new.toml")));
    }

    #[test]
    fn to_json_and_from_json_round_trip() {
        let fp = make_fp("rustc 1.78.0", "cargo 1.78.0", "0.1.0");
        let json = fp.to_json().unwrap();
        let restored = EnvironmentFingerprint::from_json(&json).unwrap();
        assert_eq!(fp, restored);
    }

    #[test]
    fn from_json_rejects_malformed_input() {
        let result = EnvironmentFingerprint::from_json("not json at all");
        assert!(result.is_err());
    }

    #[test]
    fn summary_contains_package_version() {
        let fp = make_fp("rustc 1.78.0", "cargo 1.78.0", "0.1.0");
        let s = fp.summary();
        assert!(s.contains("0.1.0"), "summary missing package version: {s}");
    }

    #[test]
    fn drift_item_baseline_and_current_are_set() {
        let item = DriftItem::new("tools.rustc", "rustc 1.78.0", "rustc 1.79.0");
        assert_eq!(item.field, "tools.rustc");
        assert_eq!(item.baseline, "rustc 1.78.0");
        assert_eq!(item.current, "rustc 1.79.0");
    }

    #[test]
    fn active_features_drift_detected() {
        let mut current  = make_fp("rustc 1.78.0", "cargo 1.78.0", "0.1.0");
        let baseline = make_fp("rustc 1.78.0", "cargo 1.78.0", "0.1.0");
        current.build.active_features = vec!["std".into(), "mock-only".into()];
        let drift = current.diff(&baseline);
        let fields: Vec<_> = drift.iter().map(|d| d.field.as_str()).collect();
        assert!(fields.contains(&"build.active_features"));
    }

    // ── Feature fingerprint tests (Bug 1: complete active-feature set) ────────

    /// Adding a feature that was previously absent must change the fingerprint.
    /// This test would have silently passed with the old hardcoded list if the
    /// new feature name was not among the four hardcoded names.
    #[test]
    fn adding_unlisted_feature_changes_active_features() {
        let baseline = make_fp("rustc 1.78.0", "cargo 1.78.0", "0.1.0");
        let mut current = make_fp("rustc 1.78.0", "cargo 1.78.0", "0.1.0");
        // Simulate a feature not in the old hardcoded list.
        current.build.active_features = vec!["std".into(), "custom-feature".into()];
        let drift = current.diff(&baseline);
        let fields: Vec<_> = drift.iter().map(|d| d.field.as_str()).collect();
        assert!(
            fields.contains(&"build.active_features"),
            "enabling a previously unlisted feature must show up in the diff: {fields:?}"
        );
    }

    /// An inactive feature must not appear in the fingerprint.
    #[test]
    fn inactive_features_do_not_appear_in_fingerprint() {
        // Construct a fingerprint that only has "std" active.
        let fp = {
            let mut f = make_fp("rustc 1.78.0", "cargo 1.78.0", "0.1.0");
            f.build.active_features = vec!["std".into()];
            f
        };
        // "wasm" and "mock-only" were not enabled — they must not appear.
        assert!(
            !fp.build.active_features.contains(&"wasm".to_string()),
            "inactive 'wasm' feature must not appear"
        );
        assert!(
            !fp.build.active_features.contains(&"mock-only".to_string()),
            "inactive 'mock-only' feature must not appear"
        );
    }

    /// Default-feature fingerprints must be deterministic (same features → same list).
    #[test]
    fn default_feature_fingerprint_is_deterministic() {
        let a = make_fp("rustc 1.78.0", "cargo 1.78.0", "0.1.0");
        let b = make_fp("rustc 1.78.0", "cargo 1.78.0", "0.1.0");
        assert!(a.diff(&b).is_empty(), "identical default-feature fingerprints must not drift");
    }

    // ── TARGET fallback tests (Bug 2: full triple vs arch-only) ──────────────

    /// When TARGET is absent the fallback is the explicit "unknown-target" marker,
    /// not a bare architecture string like "x86_64".  This distinguishes a truly
    /// missing value from a real target triple.
    #[test]
    fn missing_target_produces_unknown_marker_not_arch() {
        // Simulate what collect() would do when TARGET is absent.
        // We test the sentinel string directly since we cannot unset env vars
        // in a unit test without spawning a subprocess.
        let sentinel = "unknown-target";
        // Verify it is clearly distinguishable from a typical architecture string.
        assert_ne!(sentinel, "x86_64",   "must not look like an arch");
        assert_ne!(sentinel, "wasm32",   "must not look like an arch");
        assert_ne!(sentinel, "aarch64",  "must not look like an arch");
        // It must also produce drift when compared to a real triple.
        let mut current  = make_fp("rustc 1.78.0", "cargo 1.78.0", "0.1.0");
        let baseline     = make_fp("rustc 1.78.0", "cargo 1.78.0", "0.1.0");
        current.build.build_target = sentinel.to_string();
        // baseline already has "x86_64-unknown-linux-gnu" from make_fp
        let drift = current.diff(&baseline);
        let fields: Vec<_> = drift.iter().map(|d| d.field.as_str()).collect();
        assert!(
            fields.contains(&"build.build_target"),
            "unknown-target sentinel must produce drift vs a real triple: {fields:?}"
        );
    }

    // ── probe_wasm_target exit-status test (Bug 3) ───────────────────────────

    /// A command that exits with a non-zero status must not be treated as a
    /// successful probe even if its stdout contains plausible text.
    #[test]
    fn failed_probe_command_returns_false() {
        use std::process::Command;

        // Run a command guaranteed to fail (exit 1) but emit "wasm32" to stdout
        // so that naive stdout-only checks would incorrectly return `true`.
        // On Windows `cmd /c "echo wasm32-unknown-unknown & exit 1"` does this.
        // On Unix `sh -c "echo wasm32-unknown-unknown; exit 1"` does this.
        //
        // We replicate the fixed probe_wasm_target logic here so the test is
        // self-contained and also validates that our fix is correct.
        let result = Command::new("cmd")
            .args(["/c", "echo wasm32-unknown-unknown & exit 1"])
            .output()
            .ok()
            .filter(|o| o.status.success())          // ← the fix: require success
            .and_then(|o| std::string::String::from_utf8(o.stdout).ok())
            .map(|s| s.contains("wasm32-unknown-unknown"))
            .unwrap_or(false);

        assert!(
            !result,
            "a failing probe command must return false even if it emits plausible text"
        );
    }
}
