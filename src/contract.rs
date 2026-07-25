use soroban_sdk::{
    contract, contractimpl, contracttype, panic_with_error, symbol_short, Address,
    xdr::ToXdr, Bytes, BytesN, Env, IntoVal, String, Symbol, Vec,
};
extern crate alloc;
use alloc::string::String as RustString;
use alloc::string::ToString;
use alloc::vec::Vec as RustVec;

use crate::deterministic_hash::{compute_payload_hash, make_storage_key, verify_payload_hash};
use crate::errors::ErrorCode;
use crate::rate_limiter::RateLimiter;
use crate::rate_limiter::RateLimitConfig;
use crate::sep10_jwt;
use crate::transaction_state_tracker::{OptRecovery, TransactionState, TransactionStateRecord};
use crate::replay_detection::{self, ReplayMetrics};
use crate::admin_audit_log::AdminAuditLog;
use crate::service_management::ServiceManager;
use crate::sep38;
use crate::session_quota::{SessionQuotaEnforcer, SessionQuotaPolicy, SessionQuotaState};

/// Score penalty (in [0,1] units) applied to anomalous anchors in `score_anchor_with_anomaly`.
/// Default: 0.20 (equivalent to 20 out of 100 score points).
const ANOMALY_SCORE_PENALTY: f32 = 0.20_f32;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone)]
pub struct Session {
    pub session_id: u64,
    pub initiator: Address,
    pub created_at: u64,
    pub nonce: u64,
    pub operation_count: u64,
    pub session_ttl_seconds: u64,
    pub closed: bool,
}

#[contracttype]
#[derive(Clone)]
pub struct Quote {
    pub quote_id: u64,
    pub anchor: Address,
    pub base_asset: String,
    pub quote_asset: String,
    pub rate: u64,
    pub fee_percentage: u32,
    pub minimum_amount: u64,
    pub maximum_amount: u64,
    pub valid_until: u64,
    /// Schema version for this record. See [`SCHEMA_V1`].
    pub schema_version: u32,
    /// Optional routing reason or referral code explaining why this route/anchor
    /// was chosen (e.g. `"lowest_fee"`, `"preferred_anchor"`, `"referral"`).
    /// `None` when no reason was recorded.
    pub routing_reason: Option<String>,
}

/// Pre-v2 quote layout without `routing_reason`. Used when reading legacy records
/// that were persisted before the field was added to the schema.
#[contracttype]
#[derive(Clone)]
pub struct QuoteV1 {
    pub quote_id: u64,
    pub anchor: Address,
    pub base_asset: String,
    pub quote_asset: String,
    pub rate: u64,
    pub fee_percentage: u32,
    pub minimum_amount: u64,
    pub maximum_amount: u64,
    pub valid_until: u64,
    pub schema_version: u32,
}

#[contracttype]
#[derive(Clone)]
pub struct OperationContext {
    pub session_id: u64,
    pub operation_index: u64,
    pub operation_type: String,
    pub timestamp: u64,
    pub status: String,
    pub result_data: u64,
}

#[contracttype]
#[derive(Clone)]
pub struct AuditLog {
    pub log_id: u64,
    pub session_id: u64,
    pub actor: Address,
    pub operation: OperationContext,
}

#[contracttype]
#[derive(Clone)]
pub struct RequestId {
    pub id: Bytes,
    pub created_at: u64,
}

/// Carries the root request ID and the ordered chain of operation names
/// performed under that root request. Every sub-operation appends its name
/// to `operation_chain` rather than creating a new root ID.
#[contracttype]
#[derive(Clone)]
pub struct RequestContext {
    /// The root request ID that initiated this chain of operations.
    pub root_request_id: RequestId,
    /// Ordered list of operation names performed under this root request.
    pub operation_chain: Vec<String>,
    /// Ledger timestamp when this context was first created.
    pub created_at: u64,
}

#[contracttype]
#[derive(Clone)]
pub struct Attestation {
    pub id: u64,
    pub issuer: Address,
    pub subject: Address,
    pub timestamp: u64,
    pub payload_hash: Bytes,
    pub signature: Bytes,
    /// Schema version for this record. See [`SCHEMA_V1`].
    pub schema_version: u32,
}

/// Input record for [`AnchorKitContract::submit_attestation_batch`].
#[contracttype]
#[derive(Clone)]
pub struct AttestationInput {
    pub issuer: Address,
    pub subject: Address,
    pub timestamp: u64,
    pub payload_hash: Bytes,
    pub signature: Bytes,
}

#[contracttype]
#[derive(Clone)]
pub struct TracingSpan {
    pub request_id: RequestId,
    pub operation: String,
    pub actor: Address,
    pub started_at: u64,
    pub completed_at: u64,
    pub status: String,
    /// Raw bytes of the parent span's request_id.id, or empty Bytes if this is a root span.
    pub parent_request_id_bytes: Bytes,
    /// Zero-based index of this span within the trace, used for ordering.
    pub span_index: u32,
}

/// Holds the root request ID bytes and the current span index counter for a trace.
#[contracttype]
#[derive(Clone)]
pub struct TracingContext {
    pub root_request_id_bytes: Bytes,
    pub next_span_index: u32,
}

/// Unified attestor profile — single source of truth for all attestor metadata.
///
/// Replaces the separate `ENDPOINT`, `WEBHOOK`, and `SERVICES` storage keys.
/// All profile fields are updated atomically through `set_endpoint`,
/// `register_webhook`, and `configure_services`.
#[contracttype]
#[derive(Clone)]
pub struct AttestorProfile {
    pub attestor: Address,
    /// HTTPS endpoint URL (empty string = not set).
    pub endpoint: String,
    /// Webhook URL (empty string = not set).
    pub webhook_url: String,
    /// Supported service type codes (see `SERVICE_*` constants).
    pub services: Vec<u32>,
    /// Whether this attestor is currently enabled.
    pub enabled: bool,
    /// Ledger timestamp of the last profile update.
    pub updated_at: u64,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct ServiceRetirementInfo {
    pub service_code: u32,
    pub retired: bool,
    pub retirement_timestamp: Option<u64>,
    pub deprecation_notice: Option<String>,
}

#[contracttype]
#[derive(Clone)]
pub struct AnchorServices {
    pub anchor: Address,
    pub services: Vec<u32>,
    /// Schema version of the service-capability set (#239). Records are always
    /// stamped with the version under which they were configured so capability
    /// discovery is explicit and forward-compatible.
    pub service_capability_version: u32,
    /// Retirement metadata for services, indicating if they are deprecated or retired.
    pub service_retirements: Vec<ServiceRetirementInfo>,
}

pub const SERVICE_DEPOSITS: u32 = 1;
pub const SERVICE_WITHDRAWALS: u32 = 2;
pub const SERVICE_QUOTES: u32 = 3;
pub const SERVICE_KYC: u32 = 4;
pub const SERVICE_SEP31: u32 = 5;

// ---------------------------------------------------------------------------
// #344 — Admin permission model
//
// Every admin-gated method maps to one of the categories below. The primary
// admin (set during `initialize`) has implicit access to ALL categories.
// Additional addresses may be granted category-scoped roles via `grant_role`.
//
// | Category / Role   | Protected operations                                    |
// |-------------------|---------------------------------------------------------|
// | (primary admin)   | initialize, upgrade, migrate, set_cache_config,         |
// |                   | set_sep10_jwt_verifying_key, rotate_sep10_key,          |
// |                   | set_jwt_max_len, set_jwt_skew, set_rate_limit_config,   |
// |                   | set_anchor_metadata, reactivate_anchor                  |
// | KycAdmin          | approve_kyc, reject_kyc                                 |
// | AttestorAdmin     | register_attestor, revoke_attestor,                     |
// |                   | register_attestor_with_session,                         |
// |                   | revoke_attestor_with_session                            |
// | CacheAdmin        | cache_metadata, cache_metadata_swr, force_refresh_metadata,|
// |                   | refresh_metadata_cache, refresh_metadata_cache_swr,     |
// |                   | cache_capabilities, refresh_capabilities_cache          |
// ---------------------------------------------------------------------------

/// Role-based access control for delegatable admin operations (#345).
///
/// Addresses may be granted a role by the primary admin via [`AnchorKitContract::grant_role`].
/// Role holders can call the operations associated with their role without being
/// the primary admin. The primary admin always passes any role check regardless
/// of explicit grants.
#[contracttype]
#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u32)]
pub enum AdminRole {
    /// May call `approve_kyc` and `reject_kyc`.
    KycAdmin      = 0,
    /// May call `register_attestor`, `revoke_attestor`, and their session variants.
    AttestorAdmin = 1,
    /// May call all `cache_*` and `refresh_*_cache*` methods.
    CacheAdmin    = 2,
}

/// Current on-chain service-capability schema version (#239).
///
/// This constant gates which service codes the contract recognises and is the
/// anchor point for backwards-compatible evolution of the capability set:
///
/// - **Adding a service identifier** — extend the recognised code range
///   ([`MAX_KNOWN_SERVICE_CODE`]) and bump this constant. New codes then become
///   acceptable to [`configure_services_versioned`].
/// - **Forward safety** — `configure_services_versioned` rejects any version
///   *newer* than this constant, so a contract never stores a capability set it
///   cannot interpret.
/// - **Preserving existing anchors** — records written under an older version
///   stay readable and usable: their codes are always a subset of the current
///   recognised range, so [`supports_service`] and routing keep working without
///   a forced re-configuration.
pub const SERVICE_CAPABILITY_VERSION: u32 = 1;

/// Highest service code recognised by [`SERVICE_CAPABILITY_VERSION`]. Codes
/// outside `SERVICE_DEPOSITS..=MAX_KNOWN_SERVICE_CODE` are rejected by
/// [`configure_services_versioned`]. Extend this (and bump the version) to
/// introduce new service identifiers.
const MAX_KNOWN_SERVICE_CODE: u32 = SERVICE_SEP31;

/// Typed representation of a service capability an anchor can support.
///
/// Each variant maps to a stable `u32` discriminant stored on-chain.
/// Use [`ServiceType::as_u32`] to convert before passing to contract functions.
#[derive(Clone, PartialEq)]
pub enum ServiceType {
    Deposits,
    Withdrawals,
    Quotes,
    KYC,
    Sep31,
}

impl ServiceType {
    pub fn as_u32(&self) -> u32 {
        match self {
            ServiceType::Deposits => SERVICE_DEPOSITS,
            ServiceType::Withdrawals => SERVICE_WITHDRAWALS,
            ServiceType::Quotes => SERVICE_QUOTES,
            ServiceType::KYC => SERVICE_KYC,
            ServiceType::Sep31 => SERVICE_SEP31,
        }
    }
}

// ---------------------------------------------------------------------------
// Routing types
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone)]
pub struct RoutingAnchorMeta {
    pub anchor: Address,
    pub reputation_score: u32,
    pub average_settlement_time: u64,
    pub liquidity_score: u32,
    pub uptime_percentage: u32,
    pub total_volume: u64,
    pub is_active: bool,
}

#[contracttype]
#[derive(Clone)]
pub struct RoutingRequest {
    pub base_asset: String,
    pub quote_asset: String,
    pub amount: u64,
    pub operation_type: u32,
}

#[contracttype]
#[derive(Clone)]
pub struct RoutingOptions {
    pub request: RoutingRequest,
    pub strategy: Vec<Symbol>,
    pub min_reputation: u32,
    pub max_anchors: u32,
    pub require_kyc: bool,
    pub require_compliance: bool,
    pub subject: Address,
    pub fee_weight: u32,       // Issue #469: scaled ×1000
    pub speed_weight: u32,
    pub reputation_weight: u32,
}

/// Composite weighted routing strategy.
/// `fee_weight + speed_weight + reputation_weight` must equal 1.0.
pub struct WeightedRoutingStrategy {
    pub fee_weight: f32,
    pub speed_weight: f32,
    pub reputation_weight: f32,
}

const WEIGHT_SUM_TOLERANCE: f32 = 0.01_f32;

impl WeightedRoutingStrategy {
    /// Validate that weights sum to 1.0 (within floating-point tolerance) and are non-negative.
    pub fn validate(&self) -> bool {
        if self.fee_weight < 0.0 || self.speed_weight < 0.0 || self.reputation_weight < 0.0 {
            return false;
        }
        let sum = self.fee_weight + self.speed_weight + self.reputation_weight;
        (sum - 1.0_f32).abs() < WEIGHT_SUM_TOLERANCE
    }

    /// Compute a normalized composite score in [0.0, 1.0].
    /// Lower fee and faster settlement are better; higher reputation is better.
    /// Each dimension is normalised against the provided max values.
    ///
    /// When `anomaly_report` is `Some` and `anchor_id` appears in
    /// `anomalous_anchors`, a penalty of `anomaly_penalty / 100.0` is
    /// subtracted from the final score (default 0.20).
    pub fn score_anchor(
        &self,
        fee_pct: u32,
        settlement_time: u64,
        reputation: u32,
        max_fee: u32,
        max_settlement: u64,
        max_reputation: u32,
    ) -> f32 {
        self.score_anchor_with_anomaly(
            fee_pct, settlement_time, reputation,
            max_fee, max_settlement, max_reputation,
            None, None,
        )
    }

    /// Like [`score_anchor`] but applies a fee-anomaly penalty when the anchor
    /// is flagged in `anomaly_report`.
    ///
    /// * `anchor_id` – the string ID used in the [`FeeAnomalyReport`].
    /// * `anomaly_report` – optional pre-computed report; pass `None` to skip.
    pub fn score_anchor_with_anomaly(
        &self,
        fee_pct: u32,
        settlement_time: u64,
        reputation: u32,
        max_fee: u32,
        max_settlement: u64,
        max_reputation: u32,
        anchor_id: Option<&str>,
        anomaly_report: Option<&sep38::FeeAnomalyReport>,
    ) -> f32 {
        let fee_score = if max_fee == 0 {
            1.0_f32
        } else {
            1.0_f32 - (fee_pct as f32 / max_fee as f32)
        };
        let speed_score = if max_settlement == 0 {
            1.0_f32
        } else {
            1.0_f32 - (settlement_time as f32 / max_settlement as f32)
        };
        let rep_score = if max_reputation == 0 {
            0.0_f32
        } else {
            reputation as f32 / max_reputation as f32
        };
        let base = self.fee_weight * fee_score
            + self.speed_weight * speed_score
            + self.reputation_weight * rep_score;

        // Apply anomaly penalty when report flags this anchor.
        let penalty = if let (Some(id), Some(report)) = (anchor_id, anomaly_report) {
            if report.anomalous_anchors.iter().any(|(aid, _)| aid == id) {
                ANOMALY_SCORE_PENALTY
            } else {
                0.0_f32
            }
        } else {
            0.0_f32
        };

        (base - penalty).clamp(0.0_f32, 1.0_f32)
    }
}

// ---------------------------------------------------------------------------
// KYC and Compliance types
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct CompliancePolicy {
    pub minimum_score: Option<u32>,
}

impl CompliancePolicy {
    pub fn default_policy() -> Self {
        CompliancePolicy { minimum_score: None }
    }
}

#[contracttype]
#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u32)]
pub enum KycStatus {
    NotSubmitted = 0,
    Pending = 1,
    Approved = 2,
    Rejected = 3,
    Expired = 4,
}

#[contracttype]
#[derive(Clone)]
pub struct ComplianceCheck {
    pub subject: Address,
    pub check_type: String,
    pub result: u32,
    pub score: Option<u32>,
    pub timestamp: u64,
}

#[contracttype]
#[derive(Clone)]
pub struct KycRecord {
    pub subject: Address,
    pub status: u32,
    pub submitted_at: u64,
    pub reviewed_at: Option<u64>,
    pub expiry: Option<u64>,
    pub rejection_reason_hash: Option<Bytes>,
    /// Schema version for this record. See [`SCHEMA_V1`].
    pub schema_version: u32,
}

// ---------------------------------------------------------------------------
// Anchor Blacklist and Clustering (#296)
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone)]
pub struct AnchorBlacklistEntry {
    pub anchor: Address,
    pub reason: String,
    pub blacklisted_at: u64,
}

#[contracttype]
#[derive(Clone)]
pub struct AnchorCluster {
    pub cluster_id: String,
    pub name: String,
    pub anchors: Vec<Address>,
    pub created_at: u64,
}

// ---------------------------------------------------------------------------
// Health check types (#268)
// ---------------------------------------------------------------------------

/// Overall contract health state returned by [`AnchorKitContract::get_health_status`].
#[contracttype]
#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u32)]
pub enum HealthStatus {
    /// Contract is initialized and all subsystems are operational.
    Healthy = 0,
    /// Contract is initialized but one or more subsystems are using fallback defaults.
    Degraded = 1,
    /// Contract has not been initialized.
    Unavailable = 2,
}

/// Metadata freshness report returned by [`AnchorKitContract::get_metadata_freshness`].
#[contracttype]
#[derive(Clone)]
pub struct MetadataFreshnessReport {
    pub anchor: Address,
    pub state: MetadataCacheState,
    /// Age of the cached entry in seconds (0 when missing).
    pub age_seconds: u64,
    /// Whether a background refresh is recommended.
    pub needs_refresh: bool,
}

/// Rate limiter health report returned by [`AnchorKitContract::get_rate_limiter_health`].
#[contracttype]
#[derive(Clone)]
pub struct RateLimiterHealth {
    pub attestor: Address,
    /// Effective submission count in the current window (0 if window expired).
    pub submission_count: u32,
    pub max_submissions: u32,
    pub window_length: u32,
    pub window_start_ledger: u32,
    /// `true` when the attestor has reached the submission limit.
    pub is_throttled: bool,
}

// ---------------------------------------------------------------------------
// Metadata cache types
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone, PartialEq)]
pub struct AnchorMetadata {
    pub anchor: Address,
    pub reputation_score: u32,
    pub liquidity_score: u32,
    pub uptime_percentage: u32,
    pub total_volume: u64,
    pub average_settlement_time: u64,
    pub is_active: bool,
}

#[contracttype]
#[derive(Clone)]
pub struct MetadataCache {
    pub metadata: AnchorMetadata,
    pub cached_at: u64,
    pub ttl_seconds: u64,
    /// Grace period after `ttl_seconds` during which stale data may be served.
    pub stale_ttl_seconds: u64,
    /// Set to `true` when the entry is within the stale window; caller should refresh.
    pub needs_refresh: bool,
}

/// Explicit lifecycle state of a metadata cache entry under the
/// stale-while-revalidate (SWR) policy. Returned by
/// [`AnchorKitContract::get_metadata_cache_state`] so callers can branch on
/// freshness without triggering a panic on an expired/absent entry.
#[contracttype]
#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u32)]
pub enum MetadataCacheState {
    /// No entry exists for the anchor.
    Missing = 0,
    /// Within the primary TTL — safe to use as-is.
    Fresh = 1,
    /// Past the primary TTL but within the stale grace window — usable, but the
    /// caller should kick off a background refresh.
    Stale = 2,
    /// Past both the primary TTL and the stale window — must not be served.
    Expired = 3,
}

#[contracttype]
#[derive(Clone)]
pub struct CapabilitiesCache {
    pub toml_url: String,
    pub capabilities: String,
    pub cached_at: u64,
    pub ttl_seconds: u64,
}

#[contracttype]
#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u32)]
pub enum RefreshStatus {
    Success = 1,
    Failed = 2,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct RefreshDiagnostic {
    pub operation: String,
    pub status: RefreshStatus,
    pub attempted_at: u64,
    pub had_cached_entry: bool,
    pub detail: String,
}

// ---------------------------------------------------------------------------
// Anchor Info Discovery types
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone)]
pub struct AssetInfo {
    pub code: String,
    pub issuer: String,
    pub deposit_enabled: bool,
    pub withdrawal_enabled: bool,
    pub deposit_fee_fixed: u64,
    pub deposit_fee_percent: u32,
    pub withdrawal_fee_fixed: u64,
    pub withdrawal_fee_percent: u32,
    pub deposit_min_amount: u64,
    pub deposit_max_amount: u64,
    pub withdrawal_min_amount: u64,
    pub withdrawal_max_amount: u64,
}

#[contracttype]
#[derive(Clone)]
pub struct StellarToml {
    pub version: String,
    pub network_passphrase: String,
    pub accounts: Vec<String>,
    pub signing_key: String,
    pub currencies: Vec<AssetInfo>,
    pub transfer_server: String,
    pub transfer_server_sep0024: String,
    pub kyc_server: String,
    pub web_auth_endpoint: String,
    pub direct_payment_server: String,
}

#[contracttype]
#[derive(Clone)]
pub struct CachedToml {
    pub toml: StellarToml,
    pub cached_at: u64,
    pub ttl_seconds: u64,
    /// URI from which this TOML data was sourced (e.g. the stellar.toml URL).
    /// Set by the caller via `fetch_anchor_info`; empty when not provided.
    pub source_uri: String,
    /// Ledger timestamp when the entry was last successfully refreshed.
    /// Equals `cached_at` on first write; updated on each successful refresh.
    pub last_refreshed_at: u64,
}

/// Provenance metadata for a cached anchor TOML entry.
///
/// Returned by [`AnchorKitContract::get_anchor_toml_provenance`] so callers
/// can verify where anchor metadata came from and how fresh it is without
/// needing to decode the full cached entry.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct AnchorTomlProvenance {
    /// The anchor address this provenance record belongs to.
    pub anchor: Address,
    /// URI from which the TOML data was fetched (empty if not provided).
    pub source_uri: String,
    /// Ledger timestamp when the entry was first stored (`cached_at`).
    pub cached_at: u64,
    /// Ledger timestamp of the most recent successful refresh.
    pub last_refreshed_at: u64,
    /// Configured lifetime of the entry in seconds.
    pub ttl_seconds: u64,
    /// Age of the cached entry in seconds (relative to current ledger time).
    pub age_seconds: u64,
}

const MIN_TEMP_TTL: u32 = 15; // min_temp_entry_ttl - 1

// ---------------------------------------------------------------------------
// #244 — Contract-level cache configuration
// ---------------------------------------------------------------------------

/// Central cache TTL configuration stored in contract instance storage.
///
/// All cache operations read these values as defaults. Callers may still pass
/// an explicit TTL override (non-zero) to `cache_metadata` / `cache_capabilities`
/// / `fetch_anchor_info`; a zero override means "use the configured default".
///
/// Fields:
/// - `metadata_ttl_seconds`     — primary TTL for anchor metadata entries.
/// - `capabilities_ttl_seconds` — primary TTL for capabilities / stellar.toml entries.
/// - `swr_ttl_seconds`          — stale-while-revalidate grace period appended after
///                                the primary TTL before an entry is fully expired.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct CacheConfig {
    pub metadata_ttl_seconds: u64,
    pub capabilities_ttl_seconds: u64,
    pub swr_ttl_seconds: u64,
}

impl CacheConfig {
    /// Sensible production defaults: 1 h metadata, 6 h capabilities, 5 min SWR.
    pub fn default_config() -> Self {
        CacheConfig {
            metadata_ttl_seconds: 3_600,
            capabilities_ttl_seconds: 21_600,
            swr_ttl_seconds: 300,
        }
    }
}

/// Capacity limits for registrations and caches.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct CapacityConfig {
    pub max_attestors: u64,
    pub max_cache_entries: u64,
}

impl CapacityConfig {
    /// Sensible production defaults: 1000 attestors, 10000 cache entries.
    pub fn default_config() -> Self {
        CapacityConfig {
            max_attestors: 1000,
            max_cache_entries: 10000,
        }
    }
}

// ---------------------------------------------------------------------------
// #348 — Anchor health and service readiness types
// ---------------------------------------------------------------------------

/// Readiness snapshot for an anchor, indicating which services are available.
#[contracttype]
#[derive(Clone)]
pub struct AnchorReadinessReport {
    pub anchor: Address,
    /// True when the anchor is a registered attestor.
    pub is_registered: bool,
    /// True when the anchor has the deposit service configured.
    pub deposit_ready: bool,
    /// True when the anchor has the withdrawal service configured.
    pub withdrawal_ready: bool,
    /// True when the anchor has the quote service configured and holds a
    /// currently valid (non-expired) quote.
    pub quote_ready: bool,
    /// True when the anchor has the KYC service configured.
    pub kyc_ready: bool,
    /// Ledger timestamp when this report was generated.
    pub checked_at: u64,
}

// ---------------------------------------------------------------------------
// #350 — Read-only diagnostic types
// ---------------------------------------------------------------------------

/// Read-only snapshot of the rate limiter state for a specific attestor.
#[contracttype]
#[derive(Clone)]
pub struct RateLimiterDiagnostics {
    pub attestor: Address,
    /// Submissions recorded in the current window.
    pub submission_count: u32,
    /// Ledger sequence number when the current window started.
    pub window_start_ledger: u32,
    /// Maximum submissions allowed per window.
    pub max_submissions: u32,
    /// Length of the sliding window in ledgers.
    pub window_length: u32,
    /// True when the attestor has reached the per-window limit.
    pub is_at_limit: bool,
    /// Ledger timestamp when this snapshot was taken.
    pub checked_at: u64,
}

/// Read-only snapshot of the metadata and capabilities cache for an anchor.
#[contracttype]
#[derive(Clone)]
pub struct CacheDiagnostics {
    pub anchor: Address,
    /// True when a metadata entry is present in the cache.
    pub metadata_cached: bool,
    /// Seconds elapsed since the metadata entry was cached (0 if absent).
    pub metadata_age_seconds: u64,
    /// Configured TTL for the metadata entry (0 if absent).
    pub metadata_ttl_seconds: u64,
    /// True when a capabilities entry is present in the cache.
    pub capabilities_cached: bool,
    /// Seconds elapsed since the capabilities entry was cached (0 if absent).
    pub capabilities_age_seconds: u64,
    /// Configured TTL for the capabilities entry (0 if absent).
    pub capabilities_ttl_seconds: u64,
    /// Ledger timestamp when this snapshot was taken.
    pub checked_at: u64,
}

/// Read-only snapshot of session counters.
#[contracttype]
#[derive(Clone)]
pub struct SessionDiagnostics {
    /// Total number of sessions created since contract initialization.
    pub total_sessions_created: u64,
    /// Ledger timestamp when this snapshot was taken.
    pub checked_at: u64,
}

/// Aggregated read-only health snapshot for the contract's key subsystems.
#[contracttype]
#[derive(Clone)]
pub struct ContractDiagnostics {
    /// True when the contract has been initialized.
    pub is_initialized: bool,
    /// Total attestations submitted since initialization.
    pub total_attestations: u64,
    /// Total quotes submitted since initialization.
    pub total_quotes: u64,
    /// Total sessions created since initialization.
    pub total_sessions: u64,
    /// Active rate limit: max submissions per window.
    pub rate_limit_max_submissions: u32,
    /// Active rate limit: window length in ledgers.
    pub rate_limit_window_length: u32,
    /// Ledger timestamp when this snapshot was taken.
    pub checked_at: u64,
}

// ---------------------------------------------------------------------------
// Anchor health metrics types
// ---------------------------------------------------------------------------

/// Accumulated endpoint health counters for a single anchor.
///
/// Written by [`AnchorKitContract::record_health_event`] and read by
/// [`AnchorKitContract::get_anchor_health`].
///
/// `uptime_bps` is derived on read: `success_count * 10_000 / total_calls`
/// (basis points, 0–10 000). Returns 0 when `total_calls == 0`.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct AnchorHealthMetrics {
    pub anchor: Address,
    /// Total successful endpoint calls recorded.
    pub success_count: u64,
    /// Total failed endpoint calls recorded.
    pub failure_count: u64,
    /// Total calls (`success_count + failure_count`).
    pub total_calls: u64,
    /// Uptime in basis points (0–10 000). 10 000 = 100 %.
    pub uptime_bps: u32,
    /// Ledger timestamp of the most recent recorded event (0 if none).
    pub last_event_at: u64,
}

// ---------------------------------------------------------------------------
// Proof-of-possession types
// ---------------------------------------------------------------------------

/// On-chain record of an anchor's proof-of-possession for an endpoint.
///
/// The anchor submits a SHA-256 hash of `challenge || endpoint` (where
/// `challenge` is a nonce the anchor fetches from its own stellar.toml or
/// metadata endpoint). The contract stores the hash; callers verify by
/// recomputing it off-chain and calling
/// [`AnchorKitContract::verify_endpoint_proof`].
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct AnchorProofRecord {
    pub anchor: Address,
    /// The endpoint URL this proof covers.
    pub endpoint: String,
    /// SHA-256(challenge_bytes || endpoint_bytes) submitted by the anchor.
    pub proof_hash: BytesN<32>,
    /// Ledger timestamp when the proof was registered.
    pub registered_at: u64,
    /// True once the proof has been successfully verified by a caller.
    pub verified: bool,
}

// ---------------------------------------------------------------------------
// #247 — on-chain schema versioning
//
// Each persistent contract type carries a `schema_version: u32` field.
// The version is bumped only when the serialized shape changes in a way that
// is incompatible with old stored values (e.g. a field is added or removed).
//
// Version history:
//   SCHEMA_V1 = 1  — initial versioned layout (introduced in this release)
//   SCHEMA_V2 = 2  — adds `routing_reason: Option<String>` to [`Quote`]
//
// Migration strategy:
//   After a WASM upgrade that increments a schema version, call `migrate()`
//   as admin. The migrate function reads entries with the old schema version
//   and rewrites them with the new one.  Because Soroban XDR decoding is
//   strict, old unversioned values (implicitly "V0") will fail to decode into
//   the new type; the migration must handle that by catching panics or by
//   storing a versioned wrapper enum around the concrete type.
// ---------------------------------------------------------------------------

/// Schema version written into every new [`Attestation`], [`Quote`], and
/// [`KycRecord`].  Consumers should compare against this constant when reading
/// stored data to detect version skew.
pub const SCHEMA_V1: u32 = 1;

/// Schema version for [`Quote`] records that include `routing_reason`.
pub const SCHEMA_V2: u32 = 2;

// ---------------------------------------------------------------------------
// Supported SEP versions (#353)
// ---------------------------------------------------------------------------

/// SEP-6: Non-interactive deposit and withdrawal
pub const SEP_6: u32 = 6;
/// SEP-10: Stellar Web Authentication (JWT)
pub const SEP_10: u32 = 10;
/// SEP-24: Interactive deposit and withdrawal
pub const SEP_24: u32 = 24;
/// SEP-31: Direct payment
pub const SEP_31: u32 = 31;
/// SEP-38: Anchor Request for Quote (RFQ)
pub const SEP_38: u32 = 38;

/// Feature flags indicating which SEP capabilities this contract supports.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct SepFeatureFlags {
    /// SEP-6 non-interactive deposit/withdrawal support.
    pub sep6: bool,
    /// SEP-10 JWT authentication support.
    pub sep10: bool,
    /// SEP-24 interactive deposit/withdrawal support.
    pub sep24: bool,
    /// SEP-31 direct payment support.
    pub sep31: bool,
    /// SEP-38 RFQ / firm quote support.
    pub sep38: bool,
}

/// Aggregated transaction counts returned by
/// [`AnchorKitContract::summarize_transactions_by_status`].
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct TransactionStatusSummary {
    pub pending_count: u64,
    pub in_progress_count: u64,
    pub completed_count: u64,
    pub failed_count: u64,
    pub total_count: u64,
}

/// A single versioned snapshot of anchor metadata, stored in the history log.
///
/// Written by [`AnchorKitContract::set_anchor_metadata`] each time the metadata
/// changes. The `version` field is a monotonically increasing counter scoped to
/// the anchor; `updated_at` is the ledger timestamp of the write.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct AnchorMetadataVersion {
    /// Monotonically increasing version number (1-based).
    pub version: u32,
    /// Ledger timestamp when this version was written.
    pub updated_at: u64,
    pub reputation_score: u32,
    pub average_settlement_time: u64,
    pub liquidity_score: u32,
    pub uptime_percentage: u32,
    pub total_volume: u64,
    pub is_active: bool,
}

// ---------------------------------------------------------------------------
// Event structs
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone)]
struct SessionCreatedEvent {
    session_id: u64,
    initiator: Address,
    timestamp: u64,
}

#[contracttype]
#[derive(Clone)]
struct SessionClosedEvent {
    session_id: u64,
    initiator: Address,
    timestamp: u64,
}

#[contracttype]
#[derive(Clone)]
struct QuoteSubmitEvent {
    quote_id: u64,
    anchor: Address,
    base_asset: String,
    quote_asset: String,
    rate: u64,
    valid_until: u64,
    /// Optional routing reason recorded at quote submission time.
    routing_reason: Option<String>,
}

#[contracttype]
#[derive(Clone)]
struct QuoteReceivedEvent {
    quote_id: u64,
    receiver: Address,
    timestamp: u64,
}

#[contracttype]
#[derive(Clone)]
struct AuditLogEvent {
    log_id: u64,
    session_id: u64,
    operation_index: u64,
    operation_type: String,
    status: String,
    result_data: u64,
}

#[contracttype]
#[derive(Clone)]
struct AttestEvent {
    payload_hash: Bytes,
    timestamp: u64,
}

#[contracttype]
#[derive(Clone)]
pub struct EndpointUpdated {
    pub attestor: Address,
    pub endpoint: String,
}

#[contracttype]
#[derive(Clone)]
struct TxStateChangedEvent {
    transaction_id: u64,
    old_state: u32,
    new_state: u32,
    timestamp: u64,
}

#[contracttype]
#[derive(Clone)]
struct WebhookEvent {
    event_type: String,
    transaction_id: u64,
    timestamp: u64,
    payload_hash: Bytes,
}

#[contracttype]
#[derive(Clone)]
struct KycStatusChangedEvent {
    subject: Address,
    new_status: u32,
    timestamp: u64,
}

#[contracttype]
#[derive(Clone)]
struct KycEvent {
    subject: Address,
    submitted_at: u64,
    data_hash: Bytes,
}

// ---------------------------------------------------------------------------
// Contract upgrade types (#200)
// Provides admin-controlled WASM upgrade with version tracking and audit events.
// ---------------------------------------------------------------------------

/// Semantic version stored in persistent contract storage after each upgrade.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct ContractVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
    /// Ledger timestamp of the most recent upgrade (0 = never upgraded).
    pub upgraded_at: u64,
}

impl ContractVersion {
    /// Increment the patch component and record the upgrade timestamp.
    pub fn bump_patch(self, upgraded_at: u64) -> Self {
        ContractVersion {
            major: self.major,
            minor: self.minor,
            patch: self.patch + 1,
            upgraded_at,
        }
    }
}

/// Event emitted after a successful contract upgrade.
#[contracttype]
#[derive(Clone)]
struct UpgradeEvent {
    old_wasm_hash: BytesN<32>,
    new_wasm_hash: BytesN<32>,
    new_major: u32,
    new_minor: u32,
    new_patch: u32,
    upgraded_at: u64,
}

// ---------------------------------------------------------------------------
// TTLs (in ledgers)
// ---------------------------------------------------------------------------
const PERSISTENT_TTL: u32 = 1_555_200;
const SPAN_TTL: u32 = 1_555_200;
const INSTANCE_TTL: u32 = 518_400;

/// Default session lifetime in seconds (1 hour). Used when session_ttl_seconds is zero.
pub const DEFAULT_SESSION_TTL: u64 = 3600;

/// Maximum operations allowed per session before it is considered exhausted.
pub const MAX_OPS_PER_SESSION: u64 = 100;

/// Maximum number of attestations allowed in a single batch submission.
const MAX_BATCH_SIZE: usize = 50;

/// Rate-limit slots consumed per attestation in a batch submission.
/// Each batch item counts as this many individual submissions.
const BATCH_ATTESTATION_RATE_MULTIPLIER: u32 = 1;

/// Minimum TTL for replay-protection entries (7 days in ledgers at ~5 s/ledger).
pub const REPLAY_TTL: u32 = 120_960;

/// Inclusive lower bound for the configurable JWT max-length (set_jwt_max_len).
const MIN_JWT_MAX_LEN: u32 = 2048;
/// Inclusive upper bound for the configurable JWT max-length (set_jwt_max_len).
const MAX_JWT_MAX_LEN: u32 = 16384;

/// Default lifetime for an approved KYC record before the approval expires.
const KYC_EXPIRY_SECONDS: u64 = 30 * 24 * 60 * 60; // 30 days

fn current_kyc_status(env: &Env, record: &KycRecord) -> KycStatus {
    if let Some(expiry) = record.expiry {
        if env.ledger().timestamp() > expiry {
            return KycStatus::Expired;
        }
    }
    match record.status {
        0 => KycStatus::NotSubmitted,
        1 => KycStatus::Pending,
        2 => KycStatus::Approved,
        3 => KycStatus::Rejected,
        4 => KycStatus::Expired,
        _ => KycStatus::NotSubmitted,
    }
}

fn validate_kyc_transition(current: KycStatus, next: KycStatus, record: &KycRecord, now: u64) -> bool {
    if next == KycStatus::Pending && now.saturating_sub(record.submitted_at) < 86400 {
        return false;
    }

    match (current, next) {
        (KycStatus::NotSubmitted, KycStatus::Pending) => true,
        (KycStatus::Expired, KycStatus::Pending) => true,
        (KycStatus::Rejected, KycStatus::Pending) => true,
        (KycStatus::Pending, KycStatus::Approved) => true,
        (KycStatus::Pending, KycStatus::Rejected) => true,
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Storage key helpers — all keys go through make_storage_key for collision
// resistance (#229). Each namespace uses a unique prefix byte slice.
// ---------------------------------------------------------------------------

fn admin_key(env: &Env) -> BytesN<32> {
    make_storage_key(env, &[b"ADMIN"])
}

fn pending_admin_key(env: &Env) -> BytesN<32> {
    make_storage_key(env, &[b"PENDADMIN"])
}

fn initialized_key(env: &Env) -> BytesN<32> {
    make_storage_key(env, &[b"INITIALIZED"])
}

fn kyc_record_key(env: &Env, subject: &Address) -> BytesN<32> {
    let xdr = subject.clone().to_xdr(env);
    let raw = xdr_to_vec(&xdr);
    make_storage_key(env, &[b"KYC", &raw])
}

fn compliance_check_key(env: &Env, subject: &Address, check_type: &String) -> BytesN<32> {
    let xdr = subject.clone().to_xdr(env);
    let raw = xdr_to_vec(&xdr);
    let ct_xdr = check_type.clone().to_xdr(env);
    let ct_bytes = xdr_to_vec(&ct_xdr);
    make_storage_key(env, &[b"COMP", &raw, &ct_bytes])
}

fn compliance_history_count_key(env: &Env, subject: &Address, check_type: &String) -> BytesN<32> {
    let xdr = subject.clone().to_xdr(env);
    let raw = xdr_to_vec(&xdr);
    let ct_xdr = check_type.clone().to_xdr(env);
    let ct_bytes = xdr_to_vec(&ct_xdr);
    make_storage_key(env, &[b"COMPHCNT", &raw, &ct_bytes])
}

fn compliance_history_entry_key(env: &Env, subject: &Address, check_type: &String, idx: u64) -> BytesN<32> {
    let xdr = subject.clone().to_xdr(env);
    let raw = xdr_to_vec(&xdr);
    let ct_xdr = check_type.clone().to_xdr(env);
    let ct_bytes = xdr_to_vec(&ct_xdr);
    make_storage_key(env, &[b"COMPHIST", &raw, &ct_bytes, &idx.to_be_bytes()])
}

fn compliance_subject_index_key(env: &Env, subject: &Address) -> BytesN<32> {
    let xdr = subject.clone().to_xdr(env);
    let raw = xdr_to_vec(&xdr);
    make_storage_key(env, &[b"COMPIDX", &raw])
}

fn audit_retention_key(env: &Env) -> BytesN<32> {
    make_storage_key(env, &[b"AUDITRET"])
}

fn anchor_meta_key(env: &Env, anchor: &Address) -> BytesN<32> {
    let xdr = anchor.clone().to_xdr(env);
    let raw = xdr_to_vec(&xdr);
    make_storage_key(env, &[b"ANCHMETA", &raw])
}

fn anchor_blacklist_key(env: &Env, anchor: &Address) -> BytesN<32> {
    let xdr = anchor.clone().to_xdr(env);
    let raw = xdr_to_vec(&xdr);
    make_storage_key(env, &[b"BLACKLIST", &raw])
}

fn blacklist_index_key(env: &Env) -> BytesN<32> {
    make_storage_key(env, &[b"BLKIDX"])
}

fn anchor_cluster_key(env: &Env, cluster_id: &String) -> BytesN<32> {
    let xdr = cluster_id.clone().to_xdr(env);
    let raw = xdr_to_vec(&xdr);
    make_storage_key(env, &[b"CLUSTER", &raw])
}

fn anchor_cluster_list_key(env: &Env) -> BytesN<32> {
    make_storage_key(env, &[b"CLUSTERLIST"])
}

/// Convert a Soroban `Bytes` value to a native `Vec<u8>` for use in key helpers.
fn xdr_to_vec(b: &Bytes) -> alloc::vec::Vec<u8> {
    let mut v = alloc::vec::Vec::with_capacity(b.len() as usize);
    for i in 0..b.len() {
        v.push(b.get(i).expect("xdr_to_vec: index out of range"));
    }
    v
}

fn quote_index_key(env: &Env) -> Symbol {
    Symbol::new(env, "QUOTE_INDEX")
}

fn migrate_quotes_v2_cursor_key(env: &Env) -> Symbol {
    Symbol::new(env, "MIGRATE_QUOTES_V2_CURSOR")
}

fn quote_anchor_ref_key(env: &Env, quote_id: u64) -> BytesN<32> {
    make_storage_key(env, &[b"QANCH", &quote_id.to_be_bytes()])
}

/// Storage key for a specific `(role, grantee)` pair.
fn role_key(env: &Env, role: AdminRole, grantee: &Address) -> BytesN<32> {
    let xdr = grantee.clone().to_xdr(env);
    let raw = xdr_to_vec(&xdr);
    let role_byte = [role as u32 as u8];
    make_storage_key(env, &[b"ROLESET", &role_byte, &raw])
}

fn anchor_meta_opt(env: &Env, anchor: &Address) -> Option<RoutingAnchorMeta> {
    env.storage().persistent().get(&anchor_meta_key(env, anchor))
}

// ---------------------------------------------------------------------------
// #245 — fee and limit validation helpers
//
// These are free functions (not contract methods) so they can be called from
// multiple contract entry-points without requiring `Self`.
// ---------------------------------------------------------------------------

/// Panic with [`ErrorCode::InvalidQuote`] when `fee` exceeds 100 % (10 000 bps).
fn validate_fee_percent(env: &Env, fee: u32) {
    if fee > 10_000 {
        panic_with_error!(env, ErrorCode::InvalidQuote);
    }
}

/// Panic with [`ErrorCode::InvalidQuote`] when `max_amount` is non-zero and
/// less than `min_amount` (inverted limit range).
fn validate_amount_limits(env: &Env, min_amount: u64, max_amount: u64) {
    if max_amount != 0 && min_amount > max_amount {
        panic_with_error!(env, ErrorCode::InvalidQuote);
    }
}

/// Panic with [`ErrorCode::InvalidAssetCode`] when `code` is empty, longer
/// than 12 characters, or contains non-alphanumeric characters.
fn validate_currency_code(env: &Env, code: &String) {
    let len = code.len();
    if len == 0 || len > 12 {
        panic_with_error!(env, ErrorCode::InvalidAssetCode);
    }
}

/// Validate all fee and limit fields of a single [`AssetInfo`] record.
fn validate_asset_info(env: &Env, asset: &AssetInfo) {
    validate_currency_code(env, &asset.code);
    validate_fee_percent(env, asset.deposit_fee_percent);
    validate_fee_percent(env, asset.withdrawal_fee_percent);
    validate_amount_limits(env, asset.deposit_min_amount, asset.deposit_max_amount);
    validate_amount_limits(env, asset.withdrawal_min_amount, asset.withdrawal_max_amount);
}

// ---------------------------------------------------------------------------
// Contract
// ---------------------------------------------------------------------------

#[contract]
pub struct AnchorKitContract;

#[contractimpl]
impl AnchorKitContract {
    // -----------------------------------------------------------------------
    // Initialization
    // -----------------------------------------------------------------------

    /// Initialize the contract with an admin address.
    ///
    /// Sets up the contract instance and persistent storage. Must be called exactly once
    /// before any other contract operations. Subsequent calls will panic.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment context.
    /// * `admin` - The address that will have admin privileges. Must authorize this call.
    ///
    /// # Authorization
    ///
    /// Requires the `admin` address to sign the transaction.
    ///
    /// # Errors
    ///
    /// Panics with [`ErrorCode::AlreadyInitialized`] if the contract has already been initialized.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use soroban_sdk::{Address, Env};
    /// use anchorkit::AnchorKitContract;
    ///
    /// let env = Env::default();
    /// let admin = Address::generate(&env);
    /// AnchorKitContract::initialize(env, admin);
    /// ```
    pub fn initialize(env: Env, admin: Address) {
        admin.require_auth();
        // #228: dedicated initialized flag in persistent storage prevents
        // re-initialization after upgrade.
        let init_key = initialized_key(&env);
        if env.storage().persistent().has(&init_key) {
            panic_with_error!(&env, ErrorCode::AlreadyInitialized);
        }
        env.storage().persistent().set(&init_key, &true);
        env.storage().persistent().extend_ttl(&init_key, PERSISTENT_TTL, PERSISTENT_TTL);
        env.storage().instance().set(&admin_key(&env), &admin);
        let schema_key = make_storage_key(&env, &[b"SCHEMAVER"]);
        env.storage().instance().set(&schema_key, &SCHEMA_V1);
        env.storage().instance().extend_ttl(INSTANCE_TTL, INSTANCE_TTL);
    }

    /// Check if the contract has been initialized.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment context.
    ///
    /// # Returns
    ///
    /// `true` if [`initialize`](Self::initialize) has been called successfully, `false` otherwise.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use soroban_sdk::Env;
    /// use anchorkit::AnchorKitContract;
    ///
    /// let env = Env::default();
    /// let initialized = AnchorKitContract::is_initialized(env);
    /// assert!(initialized);
    /// ```
    pub fn is_initialized(env: Env) -> bool {
        env.storage().persistent().has(&initialized_key(&env))
    }

    /// Retrieve the current admin address.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment context.
    ///
    /// # Returns
    ///
    /// The [`Address`] of the current admin.
    ///
    /// # Errors
    ///
    /// Panics with [`ErrorCode::NotInitialized`] if the contract has not been initialized.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use soroban_sdk::Env;
    /// use anchorkit::AnchorKitContract;
    ///
    /// let env = Env::default();
    /// let admin = AnchorKitContract::get_admin(env);
    /// ```
    pub fn get_admin(env: Env) -> Address {
        env.storage()
            .instance()
            .get::<_, Address>(&admin_key(&env))
            .unwrap_or_else(|| panic_with_error!(&env, ErrorCode::NotInitialized))
    }

    /// Begin a two-step admin transfer by recording `new_admin` as the pending
    /// admin. The transfer is not final until `new_admin` calls
    /// [`accept_admin_transfer`](Self::accept_admin_transfer).
    ///
    /// Only the current admin may call this. Overwrites any previously pending
    /// transfer without confirmation.
    pub fn propose_admin_transfer(env: Env, new_admin: Address) {
        Self::require_admin(&env);
        env.storage().instance().set(&pending_admin_key(&env), &new_admin);
        env.storage().instance().extend_ttl(INSTANCE_TTL, INSTANCE_TTL);
        env.events().publish(
            (symbol_short!("admin"), symbol_short!("proposed")),
            new_admin,
        );
    }

    /// Complete a pending admin transfer. Must be called by the address that
    /// was nominated via [`propose_admin_transfer`](Self::propose_admin_transfer).
    ///
    /// After this call the caller becomes the new admin and the pending-admin
    /// slot is cleared.
    ///
    /// Panics with [`ErrorCode::NotInitialized`] when no transfer has been
    /// proposed.
    pub fn accept_admin_transfer(env: Env) {
        let new_admin: Address = env
            .storage()
            .instance()
            .get::<_, Address>(&pending_admin_key(&env))
            .unwrap_or_else(|| panic_with_error!(&env, ErrorCode::NotInitialized));
        new_admin.require_auth();
        env.storage().instance().set(&admin_key(&env), &new_admin);
        env.storage().instance().remove(&pending_admin_key(&env));
        env.storage().instance().extend_ttl(INSTANCE_TTL, INSTANCE_TTL);
        env.events().publish(
            (symbol_short!("admin"), symbol_short!("accepted")),
            new_admin,
        );
    }

    // -----------------------------------------------------------------------
    // Role-based access control (#345)
    // -----------------------------------------------------------------------

    /// Grant `role` to `grantee`. Only the primary admin may call this.
    ///
    /// After this call `grantee` may invoke the operations protected by `role`
    /// without being the primary admin.  Granting a role that is already held
    /// is a no-op.
    pub fn grant_role(env: Env, grantee: Address, role: AdminRole) {
        Self::require_admin(&env);
        let key = role_key(&env, role, &grantee);
        env.storage().persistent().set(&key, &true);
        env.storage().persistent().extend_ttl(&key, PERSISTENT_TTL, PERSISTENT_TTL);
        AdminAuditLog::log_action(
            &env,
            &Self::get_admin_internal(&env),
            "grant_role",
            grantee.to_string(),
            "",
            Self::role_name(role),
        );
        env.events().publish(
            (symbol_short!("role"), symbol_short!("granted"), grantee),
            role as u32,
        );
    }

    /// Revoke `role` from `grantee`. Only the primary admin may call this.
    ///
    /// Revoking a role that was never granted is a no-op.
    pub fn revoke_role(env: Env, grantee: Address, role: AdminRole) {
        Self::require_admin(&env);
        let key = role_key(&env, role, &grantee);
        if env.storage().persistent().has(&key) {
            env.storage().persistent().remove(&key);
        }
        AdminAuditLog::log_action(
            &env,
            &Self::get_admin_internal(&env),
            "revoke_role",
            grantee.to_string(),
            Self::role_name(role),
            "",
        );
        env.events().publish(
            (symbol_short!("role"), symbol_short!("revoked"), grantee),
            role as u32,
        );
    }

    /// Returns `true` if `address` holds `role` or is the primary admin.
    pub fn has_role(env: Env, address: Address, role: AdminRole) -> bool {
        Self::has_role_internal(&env, &address, role)
    }

    // -----------------------------------------------------------------------
    // Contract upgrade (#200)
    // -----------------------------------------------------------------------

    /// Storage key for the contract version record.
    fn version_key(env: &Env) -> BytesN<32> {
        make_storage_key(env, &[b"VERSION"])
    }

    /// Retrieve the current contract version.
    ///
    /// Returns semantic version information and the timestamp of the last upgrade.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment context.
    ///
    /// # Returns
    ///
    /// A [`ContractVersion`] struct containing:
    /// - `major`, `minor`, `patch` - semantic version components
    /// - `upgraded_at` - ledger timestamp of the last upgrade (0 if never upgraded)
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use soroban_sdk::Env;
    /// use anchorkit::AnchorKitContract;
    ///
    /// let env = Env::default();
    /// let version = AnchorKitContract::get_version(env);
    /// println!("Version: {}.{}.{}", version.major, version.minor, version.patch);
    /// ```
    pub fn get_version(env: Env) -> ContractVersion {
        env.storage()
            .instance()
            .get::<_, ContractVersion>(&Self::version_key(&env))
            .unwrap_or(ContractVersion {
                major: 0,
                minor: 1,
                patch: 0,
                upgraded_at: 0,
            })
    }

    /// Upgrade the contract WASM code to a new version.
    ///
    /// Atomically updates the contract bytecode, increments the patch version, and emits
    /// an upgrade event. The contract must be initialized and the caller must be the admin.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment context.
    /// * `new_wasm_hash` - The SHA-256 hash of the new WASM bytecode.
    ///
    /// # Authorization
    ///
    /// Requires admin authorization.
    ///
    /// # Errors
    ///
    /// Panics with:
    /// - [`ErrorCode::NotInitialized`] if the contract has not been initialized.
    /// - [`ErrorCode::UnauthorizedAttestor`] if the caller is not the admin.
    ///
    /// # Side effects
    ///
    /// - Increments the patch version component.
    /// - Records the upgrade timestamp.
    /// - Emits an `UpgradeEvent` with old/new WASM hashes and version info.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use soroban_sdk::{Env, BytesN};
    /// use anchorkit::AnchorKitContract;
    ///
    /// let env = Env::default();
    /// let new_hash = BytesN::from_array(&env, &[0u8; 32]);
    /// AnchorKitContract::upgrade(env, new_hash);
    /// ```
    pub fn upgrade(env: Env, new_wasm_hash: BytesN<32>) {
        // #228: must be initialized before upgrade is permitted
        if !env.storage().persistent().has(&initialized_key(&env)) {
            panic_with_error!(&env, ErrorCode::NotInitialized);
        }
        Self::require_admin(&env);

        let now = env.ledger().timestamp();
        let old_version = Self::get_version_internal(&env);

        let old_hash_key = make_storage_key(&env, &[b"OLDHASH"]);
        let old_wasm_hash: BytesN<32> = env
            .storage()
            .instance()
            .get::<_, BytesN<32>>(&old_hash_key)
            .unwrap_or_else(|| BytesN::from_array(&env, &[0u8; 32]));

        env.deployer().update_current_contract_wasm(new_wasm_hash.clone());

        let new_version = old_version.bump_patch(now);
        env.storage()
            .instance()
            .set(&Self::version_key(&env), &new_version);
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_TTL, INSTANCE_TTL);

        env.storage()
            .instance()
            .set(&old_hash_key, &new_wasm_hash.clone());

        env.events().publish(
            (symbol_short!("contract"), symbol_short!("upgraded")),
            UpgradeEvent {
                old_wasm_hash,
                new_wasm_hash,
                new_major: new_version.major,
                new_minor: new_version.minor,
                new_patch: new_version.patch,
                upgraded_at: now,
            },
        );
    }

    /// Run post-upgrade migration and advance the on-chain schema version.
    ///
    /// Must be called after each WASM upgrade to explicitly record the new schema
    /// version. The version counter is monotonically increasing — each call must
    /// supply a version strictly greater than the currently stored one.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment context.
    /// * `new_schema_version` - The schema version to advance to. Must be > 0 and
    ///   greater than the currently stored version (returned by `get_schema_version`).
    /// * `batch_size` - Maximum number of legacy quote records to rewrite per call
    ///   when migrating to schema v2.
    ///
    /// # Authorization
    ///
    /// Requires admin authorization.
    ///
    /// # Errors
    ///
    /// Panics with [`ErrorCode::NotInitialized`] if the contract has not been initialized.
    /// Panics with [`ErrorCode::ValidationError`] if `new_schema_version == 0` or
    /// `new_schema_version <= current_stored_version`.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use soroban_sdk::Env;
    /// use anchorkit::AnchorKitContract;
    ///
    /// let env = Env::default();
    /// AnchorKitContract::migrate(env, 1u32, 100u32);
    /// ```
    pub fn migrate(env: Env, new_schema_version: u32, batch_size: u32) {
        // migrate must not run before initialization
        if !env.storage().persistent().has(&initialized_key(&env)) {
            panic_with_error!(&env, ErrorCode::NotInitialized);
        }
        Self::require_admin(&env);

        // Version must be positive
        if new_schema_version == 0 {
            panic_with_error!(&env, ErrorCode::ValidationError);
        }

        // Version must advance
        let schema_key = make_storage_key(&env, &[b"SCHEMAVER"]);
        let current: u32 = env.storage().instance().get(&schema_key).unwrap_or(0);
        if new_schema_version <= current {
            panic_with_error!(&env, ErrorCode::ValidationError);
        }

        let cursor_key = migrate_quotes_v2_cursor_key(&env);
        let v2_migration_pending = env.storage().persistent().has(&cursor_key);

        if new_schema_version >= SCHEMA_V2
            && (current < SCHEMA_V2 || v2_migration_pending)
        {
            let migrated = Self::migrate_quotes_to_v2(&env, batch_size);
            if migrated > 0 {
                let admin = Self::get_admin_internal(&env);
                let new_value =
                    RustString::from("v2 (") + &migrated.to_string() + ")";
                AdminAuditLog::log_action(
                    &env,
                    &admin,
                    "schema_migration",
                    String::from_str(&env, "quotes"),
                    "v1",
                    &new_value,
                );
            }
            if env.storage().persistent().has(&cursor_key) {
                return;
            }
        }

        env.storage().instance().set(&schema_key, &new_schema_version);
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_TTL, INSTANCE_TTL);
    }

    /// Rewrite legacy [`Quote`] records to schema v2, processing at most
    /// `batch_size` entries per call. Returns the number of records migrated.
    fn migrate_quotes_to_v2(env: &Env, batch_size: u32) -> u32 {
        if batch_size == 0 {
            panic_with_error!(env, ErrorCode::ValidationError);
        }

        let idx_key = quote_index_key(env);
        let ids: Vec<u64> = env
            .storage()
            .persistent()
            .get(&idx_key)
            .unwrap_or_else(|| Vec::new(env));

        let cursor_key = migrate_quotes_v2_cursor_key(env);
        let resume_after: u64 = env
            .storage()
            .persistent()
            .get(&cursor_key)
            .unwrap_or(0u64);

        let mut migrated: u32 = 0;
        let mut last_processed: u64 = resume_after;

        for quote_id in ids.iter() {
            let id = quote_id;
            if id <= resume_after {
                continue;
            }
            if migrated >= batch_size {
                env.storage()
                    .persistent()
                    .set(&cursor_key, &last_processed);
                env.storage().persistent().extend_ttl(
                    &cursor_key,
                    PERSISTENT_TTL,
                    PERSISTENT_TTL,
                );
                return migrated;
            }

            let ref_key = quote_anchor_ref_key(env, id);
            let anchor: Address = match env.storage().persistent().get(&ref_key) {
                Some(a) => a,
                None => {
                    last_processed = id;
                    continue;
                }
            };

            let anchor_raw = xdr_to_vec(&anchor.to_xdr(env));
            let q_key = make_storage_key(env, &[b"QUOTE", &anchor_raw, &id.to_be_bytes()]);

            let needs_write = if let Some(quote) = env.storage().persistent().get::<_, Quote>(&q_key)
            {
                if quote.schema_version >= SCHEMA_V2 {
                    last_processed = id;
                    continue;
                }
                let updated = Quote {
                    routing_reason: None,
                    schema_version: SCHEMA_V2,
                    ..quote
                };
                env.storage().persistent().set(&q_key, &updated);
                true
            } else if let Some(v1) = env.storage().persistent().get::<_, QuoteV1>(&q_key) {
                if v1.schema_version >= SCHEMA_V2 {
                    last_processed = id;
                    continue;
                }
                let updated = Quote {
                    quote_id: v1.quote_id,
                    anchor: v1.anchor,
                    base_asset: v1.base_asset,
                    quote_asset: v1.quote_asset,
                    rate: v1.rate,
                    fee_percentage: v1.fee_percentage,
                    minimum_amount: v1.minimum_amount,
                    maximum_amount: v1.maximum_amount,
                    valid_until: v1.valid_until,
                    schema_version: SCHEMA_V2,
                    routing_reason: None,
                };
                env.storage().persistent().set(&q_key, &updated);
                true
            } else {
                last_processed = id;
                continue;
            };

            if needs_write {
                env.storage()
                    .persistent()
                    .extend_ttl(&q_key, PERSISTENT_TTL, PERSISTENT_TTL);
                migrated += 1;
            }
            last_processed = id;
        }

        env.storage().persistent().remove(&cursor_key);
        migrated
    }

    fn append_quote_index(env: &Env, quote_id: u64, anchor: &Address) {
        let idx_key = quote_index_key(env);
        let mut ids: Vec<u64> = env
            .storage()
            .persistent()
            .get(&idx_key)
            .unwrap_or_else(|| Vec::new(env));
        ids.push_back(quote_id);
        env.storage().persistent().set(&idx_key, &ids);
        env.storage()
            .persistent()
            .extend_ttl(&idx_key, PERSISTENT_TTL, PERSISTENT_TTL);

        let ref_key = quote_anchor_ref_key(env, quote_id);
        env.storage().persistent().set(&ref_key, anchor);
        env.storage()
            .persistent()
            .extend_ttl(&ref_key, PERSISTENT_TTL, PERSISTENT_TTL);
    }

    /// Get the current on-chain data schema version.
    ///
    /// Returns the stored schema version (set via `migrate`), or 0 before any
    /// migration has been run.
    pub fn get_schema_version(env: Env) -> u32 {
        let schema_key = make_storage_key(&env, &[b"SCHEMAVER"]);
        env.storage().instance().get(&schema_key).unwrap_or(0)
    }

    // -----------------------------------------------------------------------
    // Cache configuration (#244)
    // -----------------------------------------------------------------------

    fn cache_config_key(env: &Env) -> soroban_sdk::Vec<soroban_sdk::Symbol> {
        soroban_sdk::vec![env, symbol_short!("CACHCFG")]
    }

    fn compliance_policy_key(env: &Env) -> soroban_sdk::Vec<soroban_sdk::Symbol> {
        soroban_sdk::vec![env, symbol_short!("COMPPOL")]
    }

    /// Set the global compliance policy.
    ///
    /// Configures minimum score requirements for compliance checks.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment context.
    /// * `policy` - A [`CompliancePolicy`] struct with:
    ///   - `minimum_score` - Optional minimum score requirement for compliance checks
    ///
    /// # Authorization
    ///
    /// Requires admin authorization.
    pub fn set_compliance_policy(env: Env, policy: CompliancePolicy) {
        Self::require_admin(&env);
        env.storage().instance().set(&Self::compliance_policy_key(&env), &policy);
        env.storage().instance().extend_ttl(INSTANCE_TTL, INSTANCE_TTL);
    }

    /// Get the current global compliance policy.
    ///
    /// Returns the active compliance policy, or the default policy if no
    /// configuration has been set.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment context.
    ///
    /// # Returns
    ///
    /// A [`CompliancePolicy`] struct with the current policy settings.
    pub fn get_compliance_policy(env: Env) -> CompliancePolicy {
        env.storage()
            .instance()
            .get::<_, CompliancePolicy>(&Self::compliance_policy_key(&env))
            .unwrap_or_else(CompliancePolicy::default_policy)
    }

    /// Set the global cache configuration.
    ///
    /// Configures default TTL values for metadata and capabilities caching. These values
    /// are used as fallbacks when cache operations are called without an explicit TTL override.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment context.
    /// * `config` - A [`CacheConfig`] struct with:
    ///   - `metadata_ttl_seconds` - primary TTL for anchor metadata entries
    ///   - `capabilities_ttl_seconds` - primary TTL for capabilities/stellar.toml entries
    ///   - `swr_ttl_seconds` - stale-while-revalidate grace period
    ///
    /// # Authorization
    ///
    /// Requires admin authorization.
    ///
    /// # Errors
    ///
    /// Panics with [`ErrorCode::UnauthorizedAttestor`] if the caller is not the admin.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use soroban_sdk::Env;
    /// use anchorkit::{AnchorKitContract, CacheConfig};
    ///
    /// let env = Env::default();
    /// let config = CacheConfig {
    ///     metadata_ttl_seconds: 3600,
    ///     capabilities_ttl_seconds: 21600,
    ///     swr_ttl_seconds: 300,
    /// };
    /// AnchorKitContract::set_cache_config(env, config);
    /// ```
    pub fn set_cache_config(env: Env, config: CacheConfig) {
        Self::require_admin(&env);

        // Zero TTL values would cause every cache entry to expire immediately,
        // making the SWR window meaningless and every read a cache miss.
        if config.metadata_ttl_seconds == 0
            || config.capabilities_ttl_seconds == 0
            || config.swr_ttl_seconds == 0
        {
            panic_with_error!(&env, ErrorCode::ValidationError);
        }

        env.storage().instance().set(&Self::cache_config_key(&env), &config);
        env.storage().instance().extend_ttl(INSTANCE_TTL, INSTANCE_TTL);
    }

    /// Get the current global cache configuration.
    ///
    /// Returns the active cache TTL settings, or sensible production defaults if no
    /// configuration has been set.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment context.
    ///
    /// # Returns
    ///
    /// A [`CacheConfig`] struct with the current TTL settings.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use soroban_sdk::Env;
    /// use anchorkit::AnchorKitContract;
    ///
    /// let env = Env::default();
    /// let config = AnchorKitContract::get_cache_config(env);
    /// println!("Metadata TTL: {} seconds", config.metadata_ttl_seconds);
    /// ```
    pub fn get_cache_config(env: Env) -> CacheConfig {
        env.storage()
            .instance()
            .get::<_, CacheConfig>(&Self::cache_config_key(&env))
            .unwrap_or_else(CacheConfig::default_config)
    }

    /// Resolve the effective TTL: use `override_ttl` when non-zero, otherwise
    /// fall back to `configured`.
    fn effective_ttl(override_ttl: u64, configured: u64) -> u64 {
        if override_ttl != 0 { override_ttl } else { configured }
    }

    // -----------------------------------------------------------------------
    // Capacity configuration and counters
    // -----------------------------------------------------------------------

    fn capacity_config_key(env: &Env) -> soroban_sdk::Vec<soroban_sdk::Symbol> {
        soroban_sdk::vec![env, symbol_short!("CAPCFG")]
    }

    fn attestor_count_key(env: &Env) -> soroban_sdk::Vec<soroban_sdk::Symbol> {
        soroban_sdk::vec![env, symbol_short!("ATCNT")]
    }

    fn attestor_list_key(env: &Env) -> soroban_sdk::Vec<soroban_sdk::Symbol> {
        soroban_sdk::vec![env, symbol_short!("ATLIST")]
    }

    fn cache_count_key(env: &Env) -> soroban_sdk::Vec<soroban_sdk::Symbol> {
        soroban_sdk::vec![env, symbol_short!("CACNT")]
    }

    /// Set the global capacity configuration.
    ///
    /// Configures maximum limits for registered attestors and cache entries.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment context.
    /// * `config` - A [`CapacityConfig`] struct with:
    ///   - `max_attestors` - maximum number of registered attestors
    ///   - `max_cache_entries` - maximum number of cache entries
    ///
    /// # Authorization
    ///
    /// Requires admin authorization.
    pub fn set_capacity_config(env: Env, config: CapacityConfig) {
        Self::require_admin(&env);
        env.storage().instance().set(&Self::capacity_config_key(&env), &config);
        env.storage().instance().extend_ttl(INSTANCE_TTL, INSTANCE_TTL);
    }

    /// Get the current global capacity configuration.
    ///
    /// Returns the active capacity limits, or sensible production defaults if no
    /// configuration has been set.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment context.
    ///
    /// # Returns
    ///
    /// A [`CapacityConfig`] struct with the current capacity limits.
    pub fn get_capacity_config(env: Env) -> CapacityConfig {
        env.storage()
            .instance()
            .get::<_, CapacityConfig>(&Self::capacity_config_key(&env))
            .unwrap_or_else(CapacityConfig::default_config)
    }

    /// Get the current number of registered attestors.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment context.
    ///
    /// # Returns
    ///
    /// The current number of registered attestors.
    pub fn get_attestor_count(env: Env) -> u64 {
        env.storage()
            .instance()
            .get::<_, u64>(&Self::attestor_count_key(&env))
            .unwrap_or(0)
    }

    /// List all registered attestor addresses.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment context.
    ///
    /// # Returns
    ///
    /// A vector containing the addresses of all registered attestors.
    pub fn list_registered_attestors(env: Env) -> soroban_sdk::Vec<Address> {
        env.storage()
            .instance()
            .get::<_, soroban_sdk::Vec<Address>>(&Self::attestor_list_key(&env))
            .unwrap_or_else(|| soroban_sdk::Vec::new(&env))
    }

    /// Get the current number of cache entries.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment context.
    ///
    /// # Returns
    ///
    /// The current number of cache entries.
    pub fn get_cache_count(env: Env) -> u64 {
        env.storage()
            .instance()
            .get::<_, u64>(&Self::cache_count_key(&env))
            .unwrap_or(0)
    }

    fn refresh_diagnostic_key(
        env: &Env,
        anchor: &Address,
        operation: &String,
    ) -> soroban_sdk::Vec<soroban_sdk::Val> {
        soroban_sdk::vec![
            env,
            symbol_short!("REFDIAG").into_val(env),
            anchor.clone().into_val(env),
            operation.clone().into_val(env),
        ]
    }

    fn record_refresh_diagnostic(
        env: &Env,
        anchor: &Address,
        operation: String,
        status: RefreshStatus,
        had_cached_entry: bool,
        detail: String,
    ) {
        let diagnostic = RefreshDiagnostic {
            operation: operation.clone(),
            status,
            attempted_at: env.ledger().timestamp(),
            had_cached_entry,
            detail,
        };
        let key = Self::refresh_diagnostic_key(env, anchor, &operation);
        env.storage().temporary().set(&key, &diagnostic);
        env.storage().temporary().extend_ttl(&key, MIN_TEMP_TTL, MIN_TEMP_TTL);
    }

    pub fn get_refresh_diagnostic(
        env: Env,
        anchor: Address,
        operation: String,
    ) -> RefreshDiagnostic {
        let key = Self::refresh_diagnostic_key(&env, &anchor, &operation);
        env.storage()
            .temporary()
            .get(&key)
            .unwrap_or_else(|| panic_with_error!(&env, ErrorCode::CacheNotFound))
    }

    // -----------------------------------------------------------------------
    // Request ID generation
    // -----------------------------------------------------------------------

    /// Generate a unique request ID: sha256(timestamp_u64_be || sequence_u32_be || counter_u64_be)[:16]
    ///
    /// A contract-level counter is included so that two calls within the same
    /// ledger (same timestamp and sequence) always produce distinct IDs.
    pub fn generate_request_id(env: Env) -> RequestId {
        let ts = env.ledger().timestamp();
        let seq = env.ledger().sequence() as u32;

        // Increment a per-contract call counter to disambiguate same-ledger calls.
        let counter_key = make_storage_key(&env, &[b"REQIDCNT"]);
        let counter: u64 = env.storage().instance().get(&counter_key).unwrap_or(0u64);
        env.storage().instance().set(&counter_key, &(counter + 1));
        env.storage().instance().extend_ttl(INSTANCE_TTL, INSTANCE_TTL);

        // Build input: 8-byte timestamp || 4-byte sequence || 8-byte counter (big-endian)
        let mut input = Bytes::new(&env);
        for b in ts.to_be_bytes().iter() {
            input.push_back(*b);
        }
        for b in seq.to_be_bytes().iter() {
            input.push_back(*b);
        }
        for b in counter.to_be_bytes().iter() {
            input.push_back(*b);
        }

        let hash = env.crypto().sha256(&input);
        let mut id = Bytes::new(&env);
        let hash_bytes = hash.to_array();
        for b in hash_bytes.iter().take(16) {
            id.push_back(*b);
        }

        RequestId { id, created_at: ts }
    }

    /// Generate a deterministic child request ID from a root request's bytes and a nonce.
    ///
    /// ID = sha256(root_bytes || nonce_u64_be || ledger_timestamp_u64_be)[:16]
    ///
    /// This ensures child IDs are:
    /// - deterministic given the same inputs
    /// - unique across different nonces / timestamps
    /// - cryptographically bound to the root request
    pub fn generate_child_request_id(env: Env, root_bytes: Bytes, nonce: u64) -> RequestId {
        let ts = env.ledger().timestamp();
        let mut input = root_bytes;
        for b in nonce.to_be_bytes().iter() {
            input.push_back(*b);
        }
        for b in ts.to_be_bytes().iter() {
            input.push_back(*b);
        }
        let hash = env.crypto().sha256(&input);
        let mut id = Bytes::new(&env);
        let hash_bytes = hash.to_array();
        for b in hash_bytes.iter().take(16) {
            id.push_back(*b);
        }
        RequestId { id, created_at: ts }
    }

    // -----------------------------------------------------------------------
    // Attestor management
    // -----------------------------------------------------------------------

    /// Stores the 32-byte Ed25519 public key used to verify SEP-10 JWTs for `issuer`
    /// (the anchor identity whose signing key appears in stellar.toml / SEP-10 flow).
    pub fn set_sep10_jwt_verifying_key(env: Env, issuer: Address, public_key: Bytes) {
        Self::require_admin(&env);
        if public_key.len() != 32 {
            panic_with_error!(&env, ErrorCode::ValidationError);
        }
        let xdr = issuer.clone().to_xdr(&env);
        let raw = xdr_to_vec(&xdr);
        let storage_key = make_storage_key(&env, &[b"SEP10KEY", &raw]);
        env.storage().persistent().set(&storage_key, &public_key);
        env.storage()
            .persistent()
            .extend_ttl(&storage_key, PERSISTENT_TTL, PERSISTENT_TTL);
    }

    /// Rotate the SEP-10 issuer key for `issuer` to `new_public_key`.
    ///
    /// Requires admin authorization. The old key is replaced atomically; any
    /// subsequent `verify_sep10_token` call will use the new key. The previous
    /// key is stored under `"SEP10OLD"` for one TTL period to allow in-flight
    /// tokens signed with the old key to drain gracefully.
    pub fn rotate_sep10_key(env: Env, issuer: Address, new_public_key: Bytes) {
        Self::require_admin(&env);
        if new_public_key.len() != 32 {
            panic_with_error!(&env, ErrorCode::ValidationError);
        }
        let xdr = issuer.clone().to_xdr(&env);
        let raw = xdr_to_vec(&xdr);
        let storage_key = make_storage_key(&env, &[b"SEP10KEY", &raw]);
        // Preserve old key for graceful drain
        if let Some(old_key) = env.storage().persistent().get::<_, Bytes>(&storage_key) {
            let old_key_storage = make_storage_key(&env, &[b"SEP10OLD", &raw]);
            env.storage().persistent().set(&old_key_storage, &old_key);
            env.storage()
                .persistent()
                .extend_ttl(&old_key_storage, PERSISTENT_TTL, PERSISTENT_TTL);
        }
        env.storage().persistent().set(&storage_key, &new_public_key);
        env.storage()
            .persistent()
            .extend_ttl(&storage_key, PERSISTENT_TTL, PERSISTENT_TTL);
        env.events().publish(
            (symbol_short!("sep10key"), symbol_short!("rotated"), issuer),
            (),
        );
    }

    /// Return the current SEP-10 verifying key for `issuer`, or `None` if not set.
    pub fn get_sep10_key(env: Env, issuer: Address) -> Option<Bytes> {
        let xdr = issuer.clone().to_xdr(&env);
        let raw = xdr_to_vec(&xdr);
        env.storage()
            .persistent()
            .get(&make_storage_key(&env, &[b"SEP10KEY", &raw]))
    }

    /// Configure the maximum JWT length accepted by `verify_sep10_jwt` (issue #64).
    /// Must be between 2048 and 16384. Admin-only.
    pub fn set_jwt_max_len(env: Env, max_len: u32) {
        Self::require_admin(&env);
        if max_len < MIN_JWT_MAX_LEN || max_len > MAX_JWT_MAX_LEN {
            panic_with_error!(&env, ErrorCode::ValidationError);
        }
        env.storage()
            .instance()
            .set(&symbol_short!("JWTMAXLEN"), &max_len);
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_TTL, INSTANCE_TTL);
    }

    /// Return the currently configured JWT max length (defaults to 2048).
    pub fn get_jwt_max_len(env: Env) -> u32 {
        env.storage()
            .instance()
            .get::<_, u32>(&symbol_short!("JWTMAXLEN"))
            .unwrap_or(sep10_jwt::MAX_JWT_LEN)
    }

    /// Configure the clock skew tolerance (seconds) used by `verify_sep10_jwt`. Admin-only.
    /// Falls back to 60 s when not set. Maximum allowed value is 300 s.
    pub fn set_jwt_skew(env: Env, skew_seconds: u64) {
        Self::require_admin(&env);
        if skew_seconds > 300 {
            panic_with_error!(&env, ErrorCode::ValidationError);
        }
        env.storage()
            .instance()
            .set(&symbol_short!("JWTSKEW"), &skew_seconds);
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_TTL, INSTANCE_TTL);
    }

    /// Return the currently configured JWT clock skew tolerance in seconds (defaults to 60).
    pub fn get_jwt_skew(env: Env) -> u64 {
        env.storage()
            .instance()
            .get::<_, u64>(&symbol_short!("JWTSKEW"))
            .unwrap_or(sep10_jwt::DEFAULT_CLOCK_SKEW)
    }

    /// Admin-only: remove all JTI entries from persistent storage whose TTL
    /// has lapsed. This is a manual cleanup for environments where automatic
    /// Soroban TTL expiry is not guaranteed.
    ///
    /// Iterates the JTI index stored under key `"JTIIDX"` and removes entries
    /// that are no longer present in persistent storage (already expired).
    pub fn purge_expired_jtis(env: Env) {
        Self::require_admin(&env);
        let idx_key = symbol_short!("JTIIDX");
        let keys: Vec<Bytes> = env
            .storage()
            .persistent()
            .get(&idx_key)
            .unwrap_or_else(|| Vec::new(&env));
        let mut live: Vec<Bytes> = Vec::new(&env);
        for k in keys.iter() {
            if env.storage().persistent().has(&k) {
                live.push_back(k);
            }
        }
        if live.len() < keys.len() {
            env.storage().persistent().set(&idx_key, &live);
        }
    }

    /// Verifies a SEP-10 JWT (JWS compact, EdDSA) using the stored key for `issuer`: signature, `exp`, and `sub`.
    pub fn verify_sep10_token(env: Env, token: String, issuer: Address) {
        let xdr = issuer.clone().to_xdr(&env);
        let raw = xdr_to_vec(&xdr);
        let pk: Bytes = env
            .storage()
            .persistent()
            .get(&make_storage_key(&env, &[b"SEP10KEY", &raw]))
            .unwrap_or_else(|| panic_with_error!(&env, ErrorCode::InvalidSep10Token));
        if sep10_jwt::verify_sep10_jwt(&env, &token, &pk, None).is_err() {
            panic_with_error!(&env, ErrorCode::InvalidSep10Token);
        }
    }

    fn verify_sep10_token_matches_attestor(
        env: &Env,
        token: &String,
        issuer: &Address,
        attestor: &Address,
    ) {
        let xdr = issuer.clone().to_xdr(env);
        let raw = xdr_to_vec(&xdr);
        let pk: Bytes = env
            .storage()
            .persistent()
            .get(&make_storage_key(env, &[b"SEP10KEY", &raw]))
            .unwrap_or_else(|| panic_with_error!(env, ErrorCode::InvalidSep10Token));
        let expected = attestor.to_string();
        if sep10_jwt::verify_sep10_jwt(env, token, &pk, Some(&expected)).is_err() {
            panic_with_error!(env, ErrorCode::InvalidSep10Token);
        }
    }

    pub fn verify_sep10_token_for_subject(
        env: Env,
        token: String,
        issuer: Address,
        subject: Address,
    ) {
        let xdr = issuer.clone().to_xdr(&env);
        let raw = xdr_to_vec(&xdr);
        let pk: Bytes = env
            .storage()
            .persistent()
            .get(&make_storage_key(&env, &[b"SEP10KEY", &raw]))
            .unwrap_or_else(|| panic_with_error!(&env, ErrorCode::InvalidSep10Token));
        let expected = subject.to_string();
        if sep10_jwt::verify_sep10_jwt(&env, &token, &pk, Some(&expected)).is_err() {
            panic_with_error!(&env, ErrorCode::InvalidSep10Token);
        }
    }

    /// Register a new attestor with SEP-10 verification.
    ///
    /// Adds an attestor to the registry after verifying a SEP-10 JWT token.
    /// The attestor's Ed25519 public key is stored for signature verification.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment context.
    /// * `attestor` - Address of the attestor to register.
    /// * `sep10_token` - SEP-10 JWT token for verification.
    /// * `sep10_issuer` - Issuer address for SEP-10 token validation.
    /// * `public_key` - Ed25519 public key for attestation signature verification.
    ///
    /// # Authorization
    ///
    /// Requires admin authorization.
    ///
    /// # Errors
    ///
    /// Panics with:
    /// - [`ErrorCode::AttestorAlreadyRegistered`] if attestor already registered
    /// - [`ErrorCode::InvalidSep10Token`] if token is invalid or expired
    /// - [`ErrorCode::UnauthorizedAttestor`] if caller not authorized
    ///
    /// # Side effects
    ///
    /// - Stores attestor in registry
    /// - Stores public key for signature verification
    /// - Emits attestor.added event
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use soroban_sdk::{Address, BytesN, Env, String};
    /// use anchorkit::AnchorKitContract;
    ///
    /// let env = Env::default();
    /// let attestor = Address::generate(&env);
    /// let issuer = Address::generate(&env);
    /// let token = String::from_str(&env, "eyJ...");
    /// let pubkey = BytesN::from_array(&env, &[0u8; 32]);
    /// AnchorKitContract::register_attestor(env, attestor, token, issuer, pubkey);
    /// ```
    pub fn register_attestor(env: Env, attestor: Address, sep10_token: String, sep10_issuer: Address, public_key: BytesN<32>) {
        Self::require_admin(&env);
        Self::verify_sep10_token_matches_attestor(&env, &sep10_token, &sep10_issuer, &attestor);
        
        // Check capacity
        let config = Self::get_capacity_config_internal(&env);
        let current_count = Self::get_attestor_count_internal(&env);
        if current_count >= config.max_attestors {
            panic_with_error!(&env, ErrorCode::AttestorCapacityExceeded);
        }

        let xdr = attestor.clone().to_xdr(&env);
        let raw = xdr_to_vec(&xdr);
        let key = make_storage_key(&env, &[b"ATTESTOR", &raw]);
        if env.storage().persistent().has(&key) {
            panic_with_error!(&env, ErrorCode::AttestorAlreadyRegistered);
        }
        env.storage().persistent().set(&key, &true);
        env.storage()
            .persistent()
            .extend_ttl(&key, PERSISTENT_TTL, PERSISTENT_TTL);
        let pk_key = make_storage_key(&env, &[b"ATPUBKEY", &raw]);
        env.storage().persistent().set(&pk_key, &public_key);
        env.storage()
            .persistent()
            .extend_ttl(&pk_key, PERSISTENT_TTL, PERSISTENT_TTL);
        
        // Increment count
        env.storage().instance().set(&Self::attestor_count_key(&env), &(current_count + 1));
        
        let mut attestors_list = env.storage().instance().get::<_, soroban_sdk::Vec<Address>>(&Self::attestor_list_key(&env)).unwrap_or_else(|| soroban_sdk::Vec::new(&env));
        if !attestors_list.contains(&attestor) {
            attestors_list.push_back(attestor.clone());
            env.storage().instance().set(&Self::attestor_list_key(&env), &attestors_list);
        }
        
        env.storage().instance().extend_ttl(INSTANCE_TTL, INSTANCE_TTL);

        AdminAuditLog::log_action(
            &env,
            &Self::get_admin_internal(&env),
            "register_attestor",
            attestor.to_string(),
            "",
            "registered",
        );

        env.events().publish(
            (symbol_short!("attestor"), symbol_short!("added"), attestor),
            (),
        );
    }

    /// Revoke an attestor's registration.
    ///
    /// Removes an attestor from the registry, preventing them from issuing new attestations.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment context.
    /// * `attestor` - Address of attestor to revoke.
    ///
    /// # Authorization
    ///
    /// Requires admin authorization.
    ///
    /// # Errors
    ///
    /// Panics with:
    /// - [`ErrorCode::AttestorNotRegistered`] if attestor not registered
    /// - [`ErrorCode::UnauthorizedAttestor`] if caller not authorized
    ///
    /// # Side effects
    ///
    /// - Removes attestor from registry
    /// - Removes stored public key
    /// - Emits attestor.removed event
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use soroban_sdk::{Address, Env};
    /// use anchorkit::AnchorKitContract;
    ///
    /// let env = Env::default();
    /// let attestor = Address::generate(&env);
    /// AnchorKitContract::revoke_attestor(env, attestor);
    /// ```
    pub fn revoke_attestor(env: Env, attestor: Address) {
        Self::require_admin(&env);
        let xdr = attestor.clone().to_xdr(&env);
        let raw = xdr_to_vec(&xdr);
        let key = make_storage_key(&env, &[b"ATTESTOR", &raw]);
        if !env.storage().persistent().has(&key) {
            panic_with_error!(&env, ErrorCode::AttestorNotRegistered);
        }
        env.storage().persistent().remove(&key);
        let pk_key = make_storage_key(&env, &[b"ATPUBKEY", &raw]);
        env.storage().persistent().remove(&pk_key);
        
        // Decrement count
        let current_count = Self::get_attestor_count_internal(&env);
        if current_count > 0 {
            env.storage().instance().set(&Self::attestor_count_key(&env), &(current_count - 1));
            
            let mut attestors_list = env.storage().instance().get::<_, soroban_sdk::Vec<Address>>(&Self::attestor_list_key(&env)).unwrap_or_else(|| soroban_sdk::Vec::new(&env));
            if let Some(idx) = attestors_list.first_index_of(&attestor) {
                attestors_list.remove(idx);
                env.storage().instance().set(&Self::attestor_list_key(&env), &attestors_list);
            }
            
            env.storage().instance().extend_ttl(INSTANCE_TTL, INSTANCE_TTL);
        }

        AdminAuditLog::log_action(
            &env,
            &Self::get_admin_internal(&env),
            "revoke_attestor",
            attestor.to_string(),
            "registered",
            "revoked",
        );

        env.events().publish(
            (symbol_short!("attestor"), symbol_short!("removed"), attestor),
            (),
        );
    }

    /// Check if an address is a registered attestor.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment context.
    /// * `attestor` - Address to check.
    ///
    /// # Returns
    ///
    /// `true` if the address is registered as an attestor, `false` otherwise.
    ///
    /// # Errors
    ///
    /// None
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use soroban_sdk::{Address, Env};
    /// use anchorkit::AnchorKitContract;
    ///
    /// let env = Env::default();
    /// let attestor = Address::generate(&env);
    /// let is_registered = AnchorKitContract::is_attestor(env, attestor);
    /// ```
    pub fn is_attestor(env: Env, attestor: Address) -> bool {
        let xdr = attestor.clone().to_xdr(&env);
        let raw = xdr_to_vec(&xdr);
        env.storage()
            .persistent()
            .get::<_, bool>(&make_storage_key(&env, &[b"ATTESTOR", &raw]))
            .unwrap_or(false)
    }

    // -----------------------------------------------------------------------
    // Attestor profile helpers
    // -----------------------------------------------------------------------

    fn profile_key(attestor: &Address) -> (Symbol, Address) {
        (symbol_short!("PROFILE"), attestor.clone())
    }

    fn load_or_init_profile(env: &Env, attestor: &Address) -> AttestorProfile {
        let key = Self::profile_key(attestor);
        env.storage()
            .persistent()
            .get::<_, AttestorProfile>(&key)
            .unwrap_or(AttestorProfile {
                attestor: attestor.clone(),
                endpoint: String::from_str(env, ""),
                webhook_url: String::from_str(env, ""),
                services: Vec::new(env),
                enabled: true,
                updated_at: 0,
            })
    }

    fn save_profile(env: &Env, profile: &AttestorProfile) {
        let key = Self::profile_key(&profile.attestor);
        env.storage().persistent().set(&key, profile);
        env.storage()
            .persistent()
            .extend_ttl(&key, PERSISTENT_TTL, PERSISTENT_TTL);
    }

    /// Get the complete profile for an attestor.
    ///
    /// Returns all profile information including endpoint, webhook URL, supported services,
    /// and enabled status.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment context.
    /// * `attestor` - Address of the attestor.
    ///
    /// # Returns
    ///
    /// [`AttestorProfile`] with endpoint, webhook_url, services, enabled, updated_at
    ///
    /// # Errors
    ///
    /// Panics with [`ErrorCode::AttestorNotRegistered`] if attestor not registered.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use soroban_sdk::{Address, Env};
    /// use anchorkit::AnchorKitContract;
    ///
    /// let env = Env::default();
    /// let attestor = Address::generate(&env);
    /// let profile = AnchorKitContract::get_attestor_profile(env, attestor);
    /// println!("Endpoint: {}", profile.endpoint);
    /// ```
    pub fn get_attestor_profile(env: Env, attestor: Address) -> AttestorProfile {
        Self::check_attestor(&env, &attestor);
        Self::load_or_init_profile(&env, &attestor)
    }

    // -----------------------------------------------------------------------
    // Attestor endpoint management
    // -----------------------------------------------------------------------

    /// Set the HTTPS endpoint URL for an attestor.
    ///
    /// Updates the attestor's endpoint URL used for external API calls.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment context.
    /// * `attestor` - Address of the attestor.
    /// * `endpoint` - HTTPS URL for the attestor's API.
    ///
    /// # Authorization
    ///
    /// Requires the attestor to authorize this call.
    ///
    /// # Errors
    ///
    /// Panics with:
    /// - [`ErrorCode::AttestorNotRegistered`] if attestor not registered
    /// - [`ErrorCode::InvalidEndpointFormat`] if endpoint URL format invalid
    ///
    /// # Side effects
    ///
    /// - Updates attestor profile
    /// - Records update timestamp
    /// - Emits endpoint.updated event
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use soroban_sdk::{Address, Env, String};
    /// use anchorkit::AnchorKitContract;
    ///
    /// let env = Env::default();
    /// let attestor = Address::generate(&env);
    /// let endpoint = String::from_str(&env, "https://api.example.com");
    /// AnchorKitContract::set_endpoint(env, attestor, endpoint);
    /// ```
    pub fn set_endpoint(env: Env, attestor: Address, endpoint: String) {
        attestor.require_auth();
        Self::check_attestor(&env, &attestor);
        let endpoint_str = Self::soroban_string_to_rust_string(&env, &endpoint);
        crate::validate_anchor_domain(&endpoint_str)
            .unwrap_or_else(|_| panic_with_error!(&env, ErrorCode::InvalidEndpointFormat));
        let now = env.ledger().timestamp();
        let mut profile = Self::load_or_init_profile(&env, &attestor);
        profile.endpoint = endpoint.clone();
        profile.updated_at = now;
        Self::save_profile(&env, &profile);
        AdminAuditLog::log_action(
            &env,
            &attestor,
            "set_endpoint",
            attestor.to_string(),
            "",
            "updated",
        );
        env.events().publish(
            (symbol_short!("endpoint"), symbol_short!("updated")),
            EndpointUpdated { attestor, endpoint },
        );
    }

    /// Get the HTTPS endpoint URL for an attestor.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment context.
    /// * `attestor` - Address of the attestor.
    ///
    /// # Returns
    ///
    /// The endpoint URL string (empty if not set).
    ///
    /// # Errors
    ///
    /// Panics with [`ErrorCode::AttestorNotRegistered`] if attestor not registered.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use soroban_sdk::{Address, Env};
    /// use anchorkit::AnchorKitContract;
    ///
    /// let env = Env::default();
    /// let attestor = Address::generate(&env);
    /// let endpoint = AnchorKitContract::get_endpoint(env, attestor);
    /// ```
    pub fn get_endpoint(env: Env, attestor: Address) -> String {
        Self::check_attestor(&env, &attestor);
        let profile = Self::load_or_init_profile(&env, &attestor);
        if profile.endpoint.len() == 0 {
            panic_with_error!(&env, ErrorCode::EndpointNotSet);
        }
        profile.endpoint
    }

    /// Register a webhook URL for an attestor.
    ///
    /// Sets the URL where webhook events will be delivered for this attestor.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment context.
    /// * `attestor` - Address of the attestor.
    /// * `webhook_url` - URL where webhooks will be delivered.
    ///
    /// # Authorization
    ///
    /// Requires the attestor to authorize this call.
    ///
    /// # Errors
    ///
    /// Panics with [`ErrorCode::AttestorNotRegistered`] if attestor not registered.
    ///
    /// # Side effects
    ///
    /// - Updates attestor profile with webhook URL
    /// - Records update timestamp
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use soroban_sdk::{Address, Env, String};
    /// use anchorkit::AnchorKitContract;
    ///
    /// let env = Env::default();
    /// let attestor = Address::generate(&env);
    /// let webhook = String::from_str(&env, "https://api.example.com/webhooks");
    /// AnchorKitContract::register_webhook(env, attestor, webhook);
    /// ```
    pub fn register_webhook(env: Env, attestor: Address, webhook_url: String) {
        attestor.require_auth();
        Self::check_attestor(&env, &attestor);
        let webhook_url_str = Self::soroban_string_to_rust_string(&env, &webhook_url);
        crate::validate_anchor_domain(&webhook_url_str)
            .unwrap_or_else(|_| panic_with_error!(&env, ErrorCode::InvalidEndpointFormat));
        let now = env.ledger().timestamp();
        let mut profile = Self::load_or_init_profile(&env, &attestor);
        profile.webhook_url = webhook_url.clone();
        profile.updated_at = now;
        Self::save_profile(&env, &profile);
        env.events().publish(
            (symbol_short!("webhook"), symbol_short!("reg")),
            EndpointUpdated {
                attestor,
                endpoint: webhook_url,
            },
        );
    }

    /// Get the webhook URL for an attestor.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment context.
    /// * `attestor` - Address of the attestor.
    ///
    /// # Returns
    ///
    /// The webhook URL string (empty if not set).
    ///
    /// # Errors
    ///
    /// Panics with [`ErrorCode::AttestorNotRegistered`] if attestor not registered.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use soroban_sdk::{Address, Env};
    /// use anchorkit::AnchorKitContract;
    ///
    /// let env = Env::default();
    /// let attestor = Address::generate(&env);
    /// let webhook = AnchorKitContract::get_webhook_url(env, attestor);
    /// ```
    pub fn get_webhook_url(env: Env, attestor: Address) -> String {
        Self::check_attestor(&env, &attestor);
        let profile = Self::load_or_init_profile(&env, &attestor);
        if profile.webhook_url.len() == 0 {
            panic_with_error!(&env, ErrorCode::WebhookUrlNotSet);
        }
        profile.webhook_url
    }

    // -----------------------------------------------------------------------
    // Service configuration
    // -----------------------------------------------------------------------

    /// Configure an anchor's supported services using the contract's current
    /// capability version ([`SERVICE_CAPABILITY_VERSION`]). Equivalent to
    /// [`configure_services_versioned`](Self::configure_services_versioned) with
    /// `version = SERVICE_CAPABILITY_VERSION`.
    /// Configure which services an anchor supports.
    ///
    /// Registers the service types (deposits, withdrawals, quotes, KYC) that an anchor
    /// can provide. Uses the current schema version.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment context.
    /// * `anchor` - Address of the anchor.
    /// * `services` - Vector of service type codes:
    ///   - 1 = Deposits
    ///   - 2 = Withdrawals
    ///   - 3 = Quotes
    ///   - 4 = KYC
    ///
    /// # Errors
    ///
    /// Panics with [`ErrorCode::InvalidServiceType`] if any service code is not recognized.
    ///
    /// # Side effects
    ///
    /// - Stores service configuration with current schema version
    /// - Overwrites previous configuration
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use soroban_sdk::{Address, Env, Vec};
    /// use anchorkit::AnchorKitContract;
    ///
    /// let env = Env::default();
    /// let anchor = Address::generate(&env);
    /// let services = Vec::from_array(&env, [1u32, 3u32]); // deposits + quotes
    /// AnchorKitContract::configure_services(env, anchor, services);
    /// ```
    pub fn configure_services(env: Env, anchor: Address, services: Vec<u32>) {
        let retirements = Vec::new(&env);
        Self::configure_services_versioned(env, anchor, services, retirements, SERVICE_CAPABILITY_VERSION);
    }

    /// Configure an anchor's supported services and retirement metadata (simple version).
    pub fn configure_services_with_retire(env: Env, anchor: Address, services: Vec<u32>, service_retirements: Vec<ServiceRetirementInfo>) {
        Self::configure_services_versioned(env, anchor, services, service_retirements, SERVICE_CAPABILITY_VERSION);
    }

    /// Configure an anchor's supported services under an explicit capability
    /// version (#239).
    ///
    /// Rejects (panics) when:
    /// - the anchor is not a registered attestor (`AttestorNotRegistered`)
    /// - `version` is `0` or newer than [`SERVICE_CAPABILITY_VERSION`]
    ///   (`UnsupportedCapabilityVersion`) — the contract refuses capability sets
    ///   it cannot interpret
    /// - the service list is empty, contains duplicates, or contains a code the
    ///   current version does not recognise (`InvalidServiceType`)
    ///
    /// Services are stored in deterministic sorted order (ascending) regardless
    /// of submission order, ensuring consistent storage and event emission (#258).
    ///
    /// On success the record is stored stamped with `version` so capability
    /// discovery is explicit. Re-configuring overwrites the previous record,
    /// which is how an anchor migrates to a newer version.
    /// Configure services with explicit schema version.
    ///
    /// Registers service types with a specific schema version for forward compatibility.
    /// Rejects versions newer than the current contract version.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment context.
    /// * `anchor` - Address of the anchor.
    /// * `services` - Vector of service type codes.
    /// * `version` - Schema version for this configuration.
    ///
    /// # Errors
    ///
    /// Panics with:
    /// - [`ErrorCode::InvalidServiceType`] if any service code not recognized
    /// - [`ErrorCode::UnsupportedCapabilityVersion`] if version newer than current
    ///
    /// # Side effects
    ///
    /// - Stores versioned service configuration
    /// - Overwrites previous configuration
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use soroban_sdk::{Address, Env, Vec};
    /// use anchorkit::AnchorKitContract;
    ///
    /// let env = Env::default();
    /// let anchor = Address::generate(&env);
    /// let services = Vec::from_array(&env, [1u32, 2u32]); // deposits + withdrawals
    /// AnchorKitContract::configure_services_versioned(env, anchor, services, 1);
    /// ```
    pub fn configure_services_versioned(
        env: Env,
        anchor: Address,
        services: Vec<u32>,
        service_retirements: Vec<ServiceRetirementInfo>,
        version: u32,
    ) {
        anchor.require_auth();
        let xdr = anchor.clone().to_xdr(&env);
        let raw = xdr_to_vec(&xdr);
        if !env.storage().persistent().has(&make_storage_key(&env, &[b"ATTESTOR", &raw])) {
            panic_with_error!(&env, ErrorCode::AttestorNotRegistered);
        }
        if version == 0 || version > SERVICE_CAPABILITY_VERSION {
            panic_with_error!(&env, ErrorCode::UnsupportedCapabilityVersion);
        }
        if services.is_empty() {
            panic_with_error!(&env, ErrorCode::InvalidServiceType);
        }
        
        // Validate and normalize services: check for duplicates, validate codes,
        // and sort deterministically for consistent storage and event emission.
        let mut seen = Vec::new(&env);
        let mut normalized = Vec::new(&env);
        
        for s in services.iter() {
            if seen.contains(&s) {
                panic_with_error!(&env, ErrorCode::InvalidServiceType);
            }
            if !Self::is_known_service_code(s) {
                panic_with_error!(&env, ErrorCode::InvalidServiceType);
            }
            seen.push_back(s);
            normalized.push_back(s);
        }
        
        // Validate service retirements
        let mut seen_retirements = Vec::new(&env);
        for retirement in service_retirements.iter() {
            if seen_retirements.contains(&retirement.service_code) {
                panic_with_error!(&env, ErrorCode::InvalidServiceType);
            }
            if !Self::is_known_service_code(retirement.service_code) {
                panic_with_error!(&env, ErrorCode::InvalidServiceType);
            }
            seen_retirements.push_back(retirement.service_code);
        }
        
        // Sort services deterministically (ascending order) for consistent storage
        // and predictable behavior regardless of submission order.
        Self::sort_services(&env, &mut normalized);
        
        let record = AnchorServices {
            anchor: anchor.clone(),
            services: normalized.clone(),
            service_capability_version: version,
            service_retirements,
        };
        let key = make_storage_key(&env, &[b"SERVICES", &raw]);
        env.storage().persistent().set(&key, &record);
        env.storage().persistent().extend_ttl(&key, PERSISTENT_TTL, PERSISTENT_TTL);

        // Also sync services into the unified AttestorProfile.
        let mut profile = Self::load_or_init_profile(&env, &anchor);
        profile.services = normalized;
        profile.updated_at = env.ledger().timestamp();
        Self::save_profile(&env, &profile);

        env.events().publish((symbol_short!("services"), symbol_short!("config")), record);
    }

    /// The service-capability schema version this contract understands.
    /// Off-chain capability discovery can read this to learn which service
    /// codes the contract will accept.
    /// Get the current service capability schema version.
    ///
    /// Returns the version constant that the contract recognizes for service configurations.
    ///
    /// # Arguments
    ///
    /// * `_env` - The Soroban environment context.
    ///
    /// # Returns
    ///
    /// Current capability version (currently 1).
    ///
    /// # Errors
    ///
    /// None
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use soroban_sdk::Env;
    /// use anchorkit::AnchorKitContract;
    ///
    /// let env = Env::default();
    /// let version = AnchorKitContract::current_capability_version(env);
    /// assert_eq!(version, 1);
    /// ```
    pub fn current_capability_version(_env: Env) -> u32 {
        SERVICE_CAPABILITY_VERSION
    }

    /// Return the capability version an anchor's stored service set was
    /// configured under. Panics with `ServicesNotConfigured` if absent.
    /// Get the schema version of an anchor's service configuration.
    ///
    /// Returns the version under which the anchor's service configuration was stored.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment context.
    /// * `anchor` - Address of the anchor.
    ///
    /// # Returns
    ///
    /// Schema version of the anchor's service configuration (0 if not configured).
    ///
    /// # Errors
    ///
    /// None
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use soroban_sdk::{Address, Env};
    /// use anchorkit::AnchorKitContract;
    ///
    /// let env = Env::default();
    /// let anchor = Address::generate(&env);
    /// let version = AnchorKitContract::get_service_capability_version(env, anchor);
    /// ```
    pub fn get_service_capability_version(env: Env, anchor: Address) -> u32 {
        let xdr = anchor.clone().to_xdr(&env);
        let raw = xdr_to_vec(&xdr);
        env.storage()
            .persistent()
            .get::<_, AnchorServices>(&make_storage_key(&env, &[b"SERVICES", &raw]))
            .map(|r| r.service_capability_version)
            .unwrap_or_else(|| panic_with_error!(&env, ErrorCode::ServicesNotConfigured))
    }

    /// Get all services supported by an anchor.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment context.
    /// * `anchor` - Address of the anchor.
    ///
    /// # Returns
    ///
    /// [`AnchorServices`] with service codes and schema version.
    ///
    /// # Errors
    ///
    /// None
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use soroban_sdk::{Address, Env};
    /// use anchorkit::AnchorKitContract;
    ///
    /// let env = Env::default();
    /// let anchor = Address::generate(&env);
    /// let services = AnchorKitContract::get_supported_services(env, anchor);
    /// ```
    pub fn get_supported_services(env: Env, anchor: Address) -> AnchorServices {
        let xdr = anchor.clone().to_xdr(&env);
        let raw = xdr_to_vec(&xdr);
        env.storage()
            .persistent()
            .get::<_, AnchorServices>(&make_storage_key(&env, &[b"SERVICES", &raw]))
            .unwrap_or_else(|| panic_with_error!(&env, ErrorCode::ServicesNotConfigured))
    }

    /// Get active (non-retired) services for an anchor.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment context.
    /// * `anchor` - Address of the anchor.
    ///
    /// # Returns
    ///
    /// Vector of active service type codes.
    pub fn get_active_services(env: Env, anchor: Address) -> Vec<u32> {
        let record = Self::get_supported_services_internal(&env, &anchor);
        let mut active = Vec::new(&env);
        for service in record.services.iter() {
            if !Self::is_service_retired(&record, service) {
                active.push_back(service);
            }
        }
        active
    }

    /// Helper to check if a service is retired in an AnchorServices record.
    fn is_service_retired(record: &AnchorServices, service: u32) -> bool {
        for retirement in record.service_retirements.iter() {
            if retirement.service_code == service && retirement.retired {
                return true;
            }
        }
        false
    }

    /// Check if an anchor supports a specific service and it is not retired.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment context.
    /// * `anchor` - Address of the anchor.
    /// * `service` - Service type code to check (1=deposits, 2=withdrawals, 3=quotes, 4=kyc).
    ///
    /// # Returns
    ///
    /// `true` if the anchor supports the service and it is not retired, `false` otherwise.
    ///
    /// # Errors
    ///
    /// None
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use soroban_sdk::{Address, Env};
    /// use anchorkit::AnchorKitContract;
    ///
    /// let env = Env::default();
    /// let anchor = Address::generate(&env);
    /// let supports_deposits = AnchorKitContract::supports_service(env, anchor, 1);
    /// ```
    pub fn supports_service(env: Env, anchor: Address, service: u32) -> bool {
        let xdr = anchor.clone().to_xdr(&env);
        let raw = xdr_to_vec(&xdr);
        let record = env
            .storage()
            .persistent()
            .get::<_, AnchorServices>(&make_storage_key(&env, &[b"SERVICES", &raw]))
            .unwrap_or_else(|| panic_with_error!(&env, ErrorCode::ServicesNotConfigured));
        record.services.contains(&service) && !Self::is_service_retired(&record, service)
    }

    /// Get retirement info for a specific service.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment context.
    /// * `anchor` - Address of the anchor.
    /// * `service` - Service type code to check.
    ///
    /// # Returns
    ///
    /// `Option<ServiceRetirementInfo>` with retirement metadata if found.
    pub fn get_service_retirement_info(env: Env, anchor: Address, service: u32) -> Option<ServiceRetirementInfo> {
        let record = Self::get_supported_services_internal(&env, &anchor);
        for retirement in record.service_retirements.iter() {
            if retirement.service_code == service {
                return Some(retirement);
            }
        }
        None
    }

    /// Retire a specific service for an anchor.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment context.
    /// * `anchor` - Address of the anchor.
    /// * `service` - Service type code to retire.
    /// * `retirement_timestamp` - Optional timestamp when retirement takes effect.
    /// * `deprecation_notice` - Optional notice about the retirement.
    pub fn retire_service(env: Env, anchor: Address, service: u32, retirement_timestamp: Option<u64>, deprecation_notice: Option<String>) {
        anchor.require_auth();
        let xdr = anchor.clone().to_xdr(&env);
        let raw = xdr_to_vec(&xdr);
        let key = make_storage_key(&env, &[b"SERVICES", &raw]);
        let mut record = env
            .storage()
            .persistent()
            .get::<_, AnchorServices>(&key)
            .unwrap_or_else(|| panic_with_error!(&env, ErrorCode::ServicesNotConfigured));
        
        // Check if retirement info already exists for this service
        let mut found = false;
        let mut new_retirements = Vec::new(&env);
        for retirement in record.service_retirements.iter() {
            if retirement.service_code == service {
                // Update existing retirement info
                new_retirements.push_back(ServiceRetirementInfo {
                    service_code: service,
                    retired: true,
                    retirement_timestamp: retirement_timestamp.or(retirement.retirement_timestamp),
                    deprecation_notice: deprecation_notice.clone().or(retirement.deprecation_notice),
                });
                found = true;
            } else {
                new_retirements.push_back(retirement);
            }
        }

        if !found {
            // Add new retirement info
            new_retirements.push_back(ServiceRetirementInfo {
                service_code: service,
                retired: true,
                retirement_timestamp,
                deprecation_notice,
            });
        }
        
        record.service_retirements = new_retirements;
        env.storage().persistent().set(&key, &record);
        env.storage().persistent().extend_ttl(&key, PERSISTENT_TTL, PERSISTENT_TTL);
        env.events().publish((symbol_short!("services"), symbol_short!("retire")), (anchor, service));
    }

    /// Unretire a specific service for an anchor.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment context.
    /// * `anchor` - Address of the anchor.
    /// * `service` - Service type code to unretire.
    pub fn unretire_service(env: Env, anchor: Address, service: u32) {
        anchor.require_auth();
        let xdr = anchor.clone().to_xdr(&env);
        let raw = xdr_to_vec(&xdr);
        let key = make_storage_key(&env, &[b"SERVICES", &raw]);
        let mut record = env
            .storage()
            .persistent()
            .get::<_, AnchorServices>(&key)
            .unwrap_or_else(|| panic_with_error!(&env, ErrorCode::ServicesNotConfigured));
        
        let mut new_retirements = Vec::new(&env);
        for retirement in record.service_retirements.iter() {
            if retirement.service_code == service {
                // Mark as not retired but keep the metadata for history
                new_retirements.push_back(ServiceRetirementInfo {
                    service_code: service,
                    retired: false,
                    retirement_timestamp: None,
                    deprecation_notice: retirement.deprecation_notice,
                });
            } else {
                new_retirements.push_back(retirement);
            }
        }
        
        record.service_retirements = new_retirements;
        env.storage().persistent().set(&key, &record);
        env.storage().persistent().extend_ttl(&key, PERSISTENT_TTL, PERSISTENT_TTL);
        env.events().publish((symbol_short!("services"), symbol_short!("unretire")), (anchor, service));
    }

    // -----------------------------------------------------------------------
    // Service enable/disable toggles & rollback (#449)
    //
    // These entry points expose the [`ServiceManager`] toggle/snapshot store
    // on-chain. They complement `configure_services` (which records an anchor's
    // declared capability set) by letting admins flip individual services on or
    // off at runtime and roll back to a prior snapshot without re-declaring the
    // whole set.
    // -----------------------------------------------------------------------

    /// Enable a single service for `anchor`. Returns `false` if it was already
    /// enabled. Requires the primary admin.
    pub fn enable_service(env: Env, anchor: Address, service_code: u32) -> bool {
        Self::require_admin(&env);
        let changed = ServiceManager::enable_service(&env, &anchor, service_code);
        AdminAuditLog::log_action(
            &env,
            &Self::get_admin_internal(&env),
            "enable_service",
            anchor.to_string(),
            "disabled",
            "enabled",
        );
        changed
    }

    /// Disable a single service for `anchor`. Returns `false` if it was already
    /// disabled. Requires the primary admin.
    pub fn disable_service(env: Env, anchor: Address, service_code: u32) -> bool {
        Self::require_admin(&env);
        let changed = ServiceManager::disable_service(&env, &anchor, service_code);
        AdminAuditLog::log_action(
            &env,
            &Self::get_admin_internal(&env),
            "disable_service",
            anchor.to_string(),
            "enabled",
            "disabled",
        );
        changed
    }

    /// Returns `true` if `service_code` is currently enabled for `anchor` in the
    /// [`ServiceManager`] toggle store.
    pub fn is_service_enabled(env: Env, anchor: Address, service_code: u32) -> bool {
        ServiceManager::is_service_enabled(&env, &anchor, service_code)
    }

    /// Read the full toggle state (enabled + disabled services) for `anchor`.
    pub fn get_service_toggle_state(
        env: Env,
        anchor: Address,
    ) -> crate::service_management::ServiceToggleState {
        ServiceManager::get_service_state(&env, &anchor)
    }

    /// Take a snapshot of `services` for `anchor` so it can later be restored
    /// via [`Self::rollback_services`]. Returns the new snapshot id. Requires
    /// the primary admin.
    pub fn snapshot_services(
        env: Env,
        anchor: Address,
        services: Vec<u32>,
        description: String,
    ) -> u64 {
        Self::require_admin(&env);
        let desc = Self::soroban_string_to_rust_string(&env, &description);
        let snapshot_id = ServiceManager::create_snapshot(&env, &anchor, &services, desc.as_str());
        AdminAuditLog::log_action(
            &env,
            &Self::get_admin_internal(&env),
            "snapshot_services",
            anchor.to_string(),
            "",
            "snapshot_taken",
        );
        snapshot_id
    }

    /// Restore the service toggle state captured in `snapshot_id`. Returns
    /// `false` if no such snapshot exists. Requires the primary admin.
    pub fn rollback_services(env: Env, snapshot_id: u64) -> bool {
        Self::require_admin(&env);
        let restored = ServiceManager::rollback_to_snapshot(&env, snapshot_id);
        AdminAuditLog::log_action(
            &env,
            &Self::get_admin_internal(&env),
            "rollback_services",
            String::from_str(&env, "service_snapshot"),
            "",
            "rolled_back",
        );
        restored
    }

    /// Fetch a previously taken service snapshot by id, if it exists.
    pub fn get_service_snapshot(
        env: Env,
        snapshot_id: u64,
    ) -> Option<crate::service_management::ServiceConfigSnapshot> {
        ServiceManager::get_snapshot(&env, snapshot_id)
    }

    // -----------------------------------------------------------------------
    // Attestation submission (plain)
    // -----------------------------------------------------------------------

    pub fn submit_attestation(
        env: Env,
        issuer: Address,
        subject: Address,
        timestamp: u64,
        payload_hash: Bytes,
        signature: Bytes,
    ) -> u64 {
        // --- Phase 1: authentication & read-only precondition checks ---
        // All checks that do NOT write to storage run first. If any fails the
        // function panics before any storage mutation occurs, leaving the
        // contract in a consistent state.
        issuer.require_auth();
        Self::check_attestor(&env, &issuer);
        Self::verify_attestation_signature(&env, &issuer, &payload_hash, &signature);
        Self::check_timestamp(&env, timestamp);

        // Replay check (read-only).
        // The USED/(issuer, hash) key written below is also checked by
        // submit_attestation_with_session, so a non-session submission of a
        // given (issuer, hash) pair blocks any future session submission of
        // the same pair.  The SESSREQ key is session-scoped and has no
        // analogue in this sessionless path; the global USED key provides
        // equivalent cross-path replay protection.
        let issuer_xdr = issuer.clone().to_xdr(&env);
        let issuer_raw = xdr_to_vec(&issuer_xdr);
        let hash_raw = xdr_to_vec(&payload_hash);
        let used_key = make_storage_key(&env, &[b"USED", &issuer_raw, &hash_raw]);
        if env.storage().persistent().has(&used_key) {
            // Record replay detection event and metrics before panicking
            let replay_event =
                replay_detection::record_replay_detection(&env, &payload_hash, &issuer);
            replay_detection::emit_replay_detection_log(&env, &replay_event);
            panic_with_error!(&env, ErrorCode::ReplayAttack);
        }

        // Rate-limit check: `enforce_rate_limit` calls `check_and_increment`
        // which also writes. It comes last among the precondition checks so the
        // counter is only incremented when every guard has already passed.
        Self::enforce_rate_limit(&env, &issuer);

        // --- Phase 2: all writes together ---
        // We reach here only when every precondition is satisfied. Any
        // out-of-storage budget failure below will abort the entire transaction
        // and roll back the rate-limit increment along with every other write.
        let id = Self::next_attestation_id(&env);
        Self::store_attestation(
            &env,
            id,
            issuer.clone(),
            subject.clone(),
            timestamp,
            payload_hash.clone(),
            signature,
        );
        env.storage().persistent().set(&used_key, &id);
        env.storage()
            .persistent()
            .extend_ttl(&used_key, REPLAY_TTL, REPLAY_TTL);

        env.events().publish(
            (symbol_short!("attest"), symbol_short!("recorded"), id, subject),
            AttestEvent {
                payload_hash,
                timestamp,
            },
        );
        id
    }

    // -----------------------------------------------------------------------
    // Batch attestation submission (#564)
    // -----------------------------------------------------------------------

    /// Submit multiple attestations atomically.
    ///
    /// Either every attestation in the batch is committed or none are.
    /// Phase 1 validates all inputs without writing. Phase 2 writes only after
    /// all checks pass. Rate limit is consumed proportionally
    /// (`batch_size * BATCH_ATTESTATION_RATE_MULTIPLIER` slots).
    pub fn submit_attestation_batch(
        env: Env,
        caller: Address,
        attestations: Vec<AttestationInput>,
    ) -> Vec<u64> {
        caller.require_auth();
        Self::check_attestor(&env, &caller);

        let batch_size = attestations.len() as usize;
        if batch_size > MAX_BATCH_SIZE {
            panic_with_error!(&env, ErrorCode::ValidationError);
        }

        if batch_size == 0 {
            return Vec::new(&env);
        }

        // Consume rate-limit slots proportionally (batch_size * multiplier).
        {
            let config = RateLimiter::get_config(&env);
            let slots = (batch_size as u32).saturating_mul(BATCH_ATTESTATION_RATE_MULTIPLIER);
            let state_key = RateLimiter::state_key(&env, &caller);
            let current_ledger = env.ledger().sequence();
            let mut state = env
                .storage()
                .persistent()
                .get::<_, crate::rate_limiter::RateLimitState>(&state_key)
                .unwrap_or(crate::rate_limiter::RateLimitState {
                    submission_count: 0,
                    window_start_ledger: current_ledger,
                });
            if RateLimiter::is_window_expired(current_ledger, state.window_start_ledger, config.window_length) {
                state = crate::rate_limiter::RateLimitState {
                    submission_count: 0,
                    window_start_ledger: current_ledger,
                };
            }
            if state.submission_count.saturating_add(slots) > config.max_submissions {
                panic_with_error!(&env, ErrorCode::RateLimitExceeded);
            }
            state.submission_count = state.submission_count.saturating_add(slots);
            env.storage().persistent().set(&state_key, &state);
        }

        // ── Phase 1: validate all inputs, no attestation writes ──────────
        let mut used_keys: RustVec<soroban_sdk::BytesN<32>> = RustVec::new();
        for entry in attestations.iter() {
            Self::verify_attestation_signature(&env, &entry.issuer, &entry.payload_hash, &entry.signature);
            Self::check_timestamp(&env, entry.timestamp);
            let issuer_xdr = entry.issuer.clone().to_xdr(&env);
            let issuer_raw = xdr_to_vec(&issuer_xdr);
            let hash_raw = xdr_to_vec(&entry.payload_hash);
            let used_key = make_storage_key(&env, &[b"USED", &issuer_raw, &hash_raw]);
            if env.storage().persistent().has(&used_key) {
                panic_with_error!(&env, ErrorCode::ReplayAttack);
            }
            used_keys.push(used_key);
        }

        // ── Phase 2: write atomically ─────────────────────────────────────
        let mut ids = Vec::new(&env);
        for (i, entry) in attestations.iter().enumerate() {
            let id = Self::next_attestation_id(&env);
            Self::store_attestation(
                &env,
                id,
                entry.issuer.clone(),
                entry.subject.clone(),
                entry.timestamp,
                entry.payload_hash.clone(),
                entry.signature.clone(),
            );
            let used_key = &used_keys[i];
            env.storage().persistent().set(used_key, &id);
            env.storage().persistent().extend_ttl(used_key, REPLAY_TTL, REPLAY_TTL);
            ids.push_back(id);
        }
        ids
    }

    // -----------------------------------------------------------------------
    // Attestation submission with KYC enforcement
    // -----------------------------------------------------------------------

    pub fn submit_attestation_kyc_check(
        env: Env,
        issuer: Address,
        subject: Address,
        timestamp: u64,
        payload_hash: Bytes,
        signature: Bytes,
        require_kyc: bool,
    ) -> u64 {
        // --- Phase 1: authentication & read-only precondition checks ---
        issuer.require_auth();
        Self::check_attestor(&env, &issuer);
        Self::verify_attestation_signature(&env, &issuer, &payload_hash, &signature);
        Self::check_timestamp(&env, timestamp);

        if require_kyc {
            let kyc_status = Self::get_kyc_status_internal(&env, &subject);
            if kyc_status != KycStatus::Approved {
                match kyc_status {
                    KycStatus::Pending => panic_with_error!(&env, ErrorCode::KycPending),
                    KycStatus::Rejected => panic_with_error!(&env, ErrorCode::KycRejected),
                    KycStatus::Expired => panic_with_error!(&env, ErrorCode::ComplianceNotMet),
                    KycStatus::NotSubmitted => panic_with_error!(&env, ErrorCode::KycNotFound),
                    _ => panic_with_error!(&env, ErrorCode::ComplianceNotMet),
                }
            }
        }

        // Replay check (read-only)
        let issuer_xdr = issuer.clone().to_xdr(&env);
        let issuer_raw = xdr_to_vec(&issuer_xdr);
        let hash_raw = xdr_to_vec(&payload_hash);
        let used_key = make_storage_key(&env, &[b"USED", &issuer_raw, &hash_raw]);
        if env.storage().persistent().has(&used_key) {
            let replay_event =
                replay_detection::record_replay_detection(&env, &payload_hash, &issuer);
            replay_detection::emit_replay_detection_log(&env, &replay_event);
            panic_with_error!(&env, ErrorCode::ReplayAttack);
        }

        // Rate-limit check (single call; the earlier double-count was a bug).
        Self::enforce_rate_limit(&env, &issuer);

        // --- Phase 2: all writes together ---
        let id = Self::next_attestation_id(&env);
        Self::store_attestation(
            &env,
            id,
            issuer.clone(),
            subject.clone(),
            timestamp,
            payload_hash.clone(),
            signature,
        );
        env.storage().persistent().set(&used_key, &id);
        env.storage()
            .persistent()
            .extend_ttl(&used_key, REPLAY_TTL, REPLAY_TTL);

        let _now = env.ledger().timestamp();
        env.events().publish(
            (symbol_short!("attest"), symbol_short!("recorded"), id, subject),
            AttestEvent {
                payload_hash: payload_hash.clone(),
                timestamp,
            },
        );
        env.events().publish(
            (symbol_short!("webhook"), symbol_short!("event")),
            WebhookEvent {
                event_type: String::from_str(&env, "attestation_submitted"),
                transaction_id: id,
                timestamp,
                payload_hash,
            },
        );
        id
    }

    // -----------------------------------------------------------------------
    // Attestation submission with request ID + tracing span
    // -----------------------------------------------------------------------

    pub fn submit_with_request_id(
        env: Env,
        request_id: RequestId,
        issuer: Address,
        subject: Address,
        timestamp: u64,
        payload_hash: Bytes,
        signature: Bytes,
    ) -> u64 {
        issuer.require_auth();
        Self::check_attestor(&env, &issuer);
        Self::verify_attestation_signature(&env, &issuer, &payload_hash, &signature);
        Self::enforce_rate_limit(&env, &issuer);
        Self::check_timestamp(&env, timestamp);

        let issuer_xdr = issuer.clone().to_xdr(&env);
        let issuer_raw = xdr_to_vec(&issuer_xdr);
        let hash_raw = xdr_to_vec(&payload_hash);
        let used_key = make_storage_key(&env, &[b"USED", &issuer_raw, &hash_raw]);
        if env.storage().persistent().has(&used_key) {
            // Record replay detection event and metrics before panicking
            let replay_event = replay_detection::record_replay_detection(&env, &payload_hash, &issuer);
            replay_detection::emit_replay_detection_log(&env, &replay_event);
            panic_with_error!(&env, ErrorCode::ReplayAttack);
        }

        let id = Self::next_attestation_id(&env);
        Self::store_attestation(
            &env, id, issuer.clone(), subject.clone(), timestamp,
            payload_hash.clone(), signature,
        );

        env.storage().persistent().set(&used_key, &id);
        env.storage().persistent().extend_ttl(&used_key, REPLAY_TTL, REPLAY_TTL);

        let now = env.ledger().timestamp();
        Self::store_span(
            &env, &request_id,
            String::from_str(&env, "submit_attestation"),
            issuer.clone(), now,
            String::from_str(&env, "success"),
        );

        // Propagate operation name into RequestContext
        Self::record_operation_in_context(&env, &request_id.id, String::from_str(&env, "submit_attestation"));

        env.events().publish(
            (symbol_short!("attest"), symbol_short!("recorded"), id, subject),
            AttestEvent { payload_hash: payload_hash.clone(), timestamp },
        );
        env.events().publish(
            (symbol_short!("webhook"), symbol_short!("event")),
            WebhookEvent {
                event_type: String::from_str(&env, "attestation_submitted"),
                transaction_id: id, timestamp, payload_hash,
            },
        );
        id
    }

    // -----------------------------------------------------------------------
    // Quote submission with request ID + tracing span
    // -----------------------------------------------------------------------

    #[allow(unused_variables)]
    pub fn quote_with_request_id(
        env: Env,
        request_id: RequestId,
        anchor: Address,
        from_asset: String,
        to_asset: String,
        amount: u64,
        fee_bps: u32,
        min_amount: u64,
        max_amount: u64,
        expires_at: u64,
    ) {
        anchor.require_auth();
        let xdr = anchor.clone().to_xdr(&env);
        let raw = xdr_to_vec(&xdr);
        let services_record = env
            .storage()
            .persistent()
            .get::<_, AnchorServices>(&make_storage_key(&env, &[b"SERVICES", &raw]))
            .unwrap_or_else(|| panic_with_error!(&env, ErrorCode::ServicesNotConfigured));
        if !services_record.services.contains(&SERVICE_QUOTES) {
            panic_with_error!(&env, ErrorCode::ServicesNotConfigured);
        }
        let now = env.ledger().timestamp();
        
        // Store the actual quote
        Self::submit_quote(env.clone(), anchor.clone(), from_asset, to_asset, amount, fee_bps, min_amount, max_amount, expires_at);
        
        // Then store the span
        Self::store_span(
            &env, &request_id,
            String::from_str(&env, "submit_quote"),
            anchor, now,
            String::from_str(&env, "success"),
        );

        // Propagate operation name into RequestContext
        Self::record_operation_in_context(&env, &request_id.id, String::from_str(&env, "submit_quote"));
    }

    /// Record a tracing span for a quote submission, including optional routing
    /// reason metadata in the span operation name (#298).
    ///
    /// Behaves exactly like [`quote_with_request_id`] but when `routing_reason`
    /// is `Some`, the span operation is annotated as
    /// `"submit_quote_with_reason"` and the reason is recorded in the
    /// [`RequestContext`] operation chain so downstream audit consumers can
    /// correlate the reason with the request.
    ///
    /// # Arguments
    ///
    /// * `routing_reason` – Optional routing reason to attach to the span.
    ///   When `None` the behaviour is identical to [`quote_with_request_id`].
    pub fn quote_with_request_id_and_reason(
        env: Env,
        request_id: RequestId,
        anchor: Address,
        from_asset: String,
        to_asset: String,
        amount: u64,
        fee_bps: u32,
        min_amount: u64,
        max_amount: u64,
        expires_at: u64,
        routing_reason: Option<String>,
    ) {
        anchor.require_auth();
        let xdr = anchor.clone().to_xdr(&env);
        let raw = xdr_to_vec(&xdr);
        let services_record = env
            .storage()
            .persistent()
            .get::<_, AnchorServices>(&make_storage_key(&env, &[b"SERVICES", &raw]))
            .unwrap_or_else(|| panic_with_error!(&env, ErrorCode::ServicesNotConfigured));
        if !services_record.services.contains(&SERVICE_QUOTES) {
            panic_with_error!(&env, ErrorCode::ServicesNotConfigured);
        }
        let now = env.ledger().timestamp();

        // Store the actual quote
        Self::submit_quote_with_reason(env.clone(), anchor.clone(), from_asset, to_asset, amount, fee_bps, min_amount, max_amount, expires_at, routing_reason.clone());

        // Choose the operation label based on whether a reason was supplied so
        // the span is self-describing in audit queries.
        let operation = if routing_reason.is_some() {
            String::from_str(&env, "submit_quote_with_reason")
        } else {
            String::from_str(&env, "submit_quote")
        };

        Self::store_span(
            &env, &request_id,
            operation.clone(),
            anchor, now,
            String::from_str(&env, "success"),
        );

        Self::record_operation_in_context(&env, &request_id.id, operation);
    }

    // -----------------------------------------------------------------------
    // Tracing span retrieval
    // -----------------------------------------------------------------------

    pub fn get_tracing_span(env: Env, request_id_bytes: Bytes) -> Option<TracingSpan> {
        env.storage()
            .temporary()
            .get::<_, TracingSpan>(&(symbol_short!("SPAN"), request_id_bytes))
    }

    /// Create a child span under a parent span, setting parent_request_id and
    /// incrementing the span_index from the TracingContext stored for the root.
    ///
    /// The TracingContext for the root must have been initialised by a prior
    /// `submit_with_request_id` call (which stores span_index = 0).
    ///
    /// Panics with `ValidationError` if:
    /// - the parent span does not exist (no root context found)
    /// - `child_request_id` bytes are identical to `parent_request_id` bytes
    /// - the child span index would not increment correctly
    pub fn propagate_span(
        env: Env,
        parent_request_id: RequestId,
        child_request_id: RequestId,
        operation: String,
        actor: Address,
    ) {
        actor.require_auth();

        // Validate: child must differ from parent
        if child_request_id.id == parent_request_id.id {
            panic_with_error!(&env, ErrorCode::ValidationError);
        }

        // Validate: a root context must exist for the parent (i.e. the parent
        // span was created by submit_with_request_id or a prior propagate_span).
        let ctx_key = (symbol_short!("TRACECTX"), parent_request_id.id.clone());
        let mut ctx: TracingContext = env
            .storage()
            .temporary()
            .get(&ctx_key)
            .unwrap_or_else(|| panic_with_error!(&env, ErrorCode::ValidationError));

        let span_index = ctx.next_span_index;
        ctx.next_span_index = ctx.next_span_index
            .checked_add(1)
            .unwrap_or_else(|| panic_with_error!(&env, ErrorCode::SessionOperationLimitExceeded));

        let now = env.ledger().timestamp();
        env.storage().temporary().set(&ctx_key, &ctx);
        env.storage().temporary().extend_ttl(&ctx_key, SPAN_TTL, SPAN_TTL);

        // Register child span ID under the root so get_trace can find it
        let child_list_key = (symbol_short!("TRACEIDS"), parent_request_id.id.clone(), span_index);
        env.storage().temporary().set(&child_list_key, &child_request_id.id.clone());
        env.storage().temporary().extend_ttl(&child_list_key, SPAN_TTL, SPAN_TTL);

        Self::store_span_with_parent(
            &env,
            &child_request_id,
            operation,
            actor,
            now,
            String::from_str(&env, "success"),
            parent_request_id.id.clone(),
            span_index,
        );
    }

    /// Retrieve all spans associated with a root request ID, ordered by span_index.
    /// Returns the root span first, followed by child spans in creation order.
    pub fn get_trace(env: Env, root_request_id_bytes: Bytes) -> Vec<TracingSpan> {
        let mut spans = Vec::new(&env);

        // Root span (span_index = 0)
        if let Some(root_span) = env
            .storage()
            .temporary()
            .get::<_, TracingSpan>(&(symbol_short!("SPAN"), root_request_id_bytes.clone()))
        {
            spans.push_back(root_span);
        }

        // Child spans registered via propagate_span
        let ctx_key = (symbol_short!("TRACECTX"), root_request_id_bytes.clone());
        let ctx: Option<TracingContext> = env.storage().temporary().get(&ctx_key);
        if let Some(ctx) = ctx {
            for i in 1..ctx.next_span_index {
                let child_list_key = (symbol_short!("TRACEIDS"), root_request_id_bytes.clone(), i);
                if let Some(child_id) = env
                    .storage()
                    .temporary()
                    .get::<_, Bytes>(&child_list_key)
                {
                    if let Some(child_span) = env
                        .storage()
                        .temporary()
                        .get::<_, TracingSpan>(&(symbol_short!("SPAN"), child_id))
                    {
                        spans.push_back(child_span);
                    }
                }
            }
        }

        spans
    }

    // -----------------------------------------------------------------------
    // RequestContext — propagation and querying
    // -----------------------------------------------------------------------

    /// Create a new `RequestContext` for a root request ID.
    ///
    /// Panics with `ValidationError` if `root_request_id.id` is empty.
    pub fn create_request_context(env: Env, root_request_id: RequestId) -> RequestContext {
        if root_request_id.id.is_empty() {
            panic_with_error!(&env, ErrorCode::ValidationError);
        }
        Self::require_valid_timestamp(&env, root_request_id.created_at);
        let now = env.ledger().timestamp();
        let ctx = RequestContext {
            root_request_id: root_request_id.clone(),
            operation_chain: Vec::new(&env),
            created_at: now,
        };
        let key = (symbol_short!("REQCTX"), root_request_id.id.clone());
        env.storage().temporary().set(&key, &ctx);
        env.storage()
            .temporary()
            .extend_ttl(&key, SPAN_TTL, SPAN_TTL);
        ctx
    }

    /// Append `operation_name` to the `operation_chain` of the context identified
    /// by `root_request_id_bytes`. Creates the context if it does not yet exist.
    ///
    /// Panics with `ValidationError` if `operation_name` is empty.
    pub fn append_operation(
        env: Env,
        root_request_id_bytes: Bytes,
        operation_name: String,
    ) {
        Self::require_non_empty_string(&env, &operation_name);
        let key = (symbol_short!("REQCTX"), root_request_id_bytes.clone());
        let mut ctx: RequestContext = env
            .storage()
            .temporary()
            .get(&key)
            .unwrap_or_else(|| {
                // Auto-create a minimal context if none exists yet
                let now = env.ledger().timestamp();
                RequestContext {
                    root_request_id: RequestId {
                        id: root_request_id_bytes.clone(),
                        created_at: now,
                    },
                    operation_chain: Vec::new(&env),
                    created_at: now,
                }
            });
        ctx.operation_chain.push_back(operation_name);
        env.storage().temporary().set(&key, &ctx);
        env.storage()
            .temporary()
            .extend_ttl(&key, SPAN_TTL, SPAN_TTL);
    }

    /// Return the full `RequestContext` (including `operation_chain`) for a
    /// given root request ID, or `None` if no context has been stored.
    pub fn get_request_context(env: Env, root_request_id_bytes: Bytes) -> Option<RequestContext> {
        env.storage()
            .temporary()
            .get::<_, RequestContext>(&(symbol_short!("REQCTX"), root_request_id_bytes))
    }

    // -----------------------------------------------------------------------
    // Attestation retrieval
    // -----------------------------------------------------------------------

    pub fn get_attestation(env: Env, id: u64) -> Attestation {
        env.storage()
            .persistent()
            .get::<_, Attestation>(&make_storage_key(&env, &[b"ATTEST", &id.to_be_bytes()]))
            .unwrap_or_else(|| panic_with_error!(&env, ErrorCode::AttestationNotFound))
    }

    pub fn get_attestation_by_hash(env: Env, issuer: Address, payload_hash: Bytes) -> u64 {
        let issuer_xdr = issuer.clone().to_xdr(&env);
        let issuer_raw = xdr_to_vec(&issuer_xdr);
        let hash_raw = xdr_to_vec(&payload_hash);
        let used_key = make_storage_key(&env, &[b"USED", &issuer_raw, &hash_raw]);
        env.storage()
            .persistent()
            .get::<_, u64>(&used_key)
            .unwrap_or_else(|| panic_with_error!(&env, ErrorCode::AttestationNotFound))
    }

    // -----------------------------------------------------------------------
    // Deterministic hash utilities (#192)
    // -----------------------------------------------------------------------

    /// Compute a canonical SHA-256 hash for an attestation payload.
    /// Field order: subject || timestamp (8-byte BE) || data.
    pub fn compute_payload_hash(
        env: Env,
        subject: Address,
        timestamp: u64,
        data: Bytes,
    ) -> BytesN<32> {
        compute_payload_hash(&env, &subject, timestamp, &data)
    }

    /// Verify that the hash stored in an attestation matches the expected hash.
    pub fn verify_payload_hash(env: Env, attestation_id: u64, expected_hash: BytesN<32>) -> bool {
        let attestation = env
            .storage()
            .persistent()
            .get::<_, Attestation>(&make_storage_key(&env, &[b"ATTEST", &attestation_id.to_be_bytes()]))
            .unwrap_or_else(|| panic_with_error!(&env, ErrorCode::AttestationNotFound));

        let stored: BytesN<32> = attestation.payload_hash.try_into()
            .unwrap_or_else(|_| panic_with_error!(&env, ErrorCode::ValidationError));
        verify_payload_hash(&stored, &expected_hash)
    }

    // -----------------------------------------------------------------------
    // Session management
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // KYC data management
    // -----------------------------------------------------------------------

    pub fn submit_kyc(env: Env, subject: Address, data_hash: Bytes, attestor: Address) {
        attestor.require_auth();
        Self::check_attestor(&env, &attestor);
        let now = env.ledger().timestamp();
        let key = kyc_record_key(&env, &subject);
        if env.storage().persistent().has(&key) {
            let existing: KycRecord = env.storage().persistent().get(&key)
                .unwrap_or_else(|| panic_with_error!(&env, ErrorCode::ComplianceNotMet));
            let current_status = current_kyc_status(&env, &existing);
            if !validate_kyc_transition(current_status, KycStatus::Pending, &existing, now) {
                panic_with_error!(&env, ErrorCode::ComplianceNotMet);
            }
        }
        let record = KycRecord {
            subject: subject.clone(), status: KycStatus::Pending as u32,
            submitted_at: now, reviewed_at: None, expiry: None,
            rejection_reason_hash: None,
            schema_version: SCHEMA_V1,
        };
        env.storage().persistent().set(&key, &record);
        env.storage().persistent().extend_ttl(&key, PERSISTENT_TTL, PERSISTENT_TTL);
        let data_key = make_storage_key(&env, &[b"KYCDATA", &xdr_to_vec(&subject.clone().to_xdr(&env))]);
        env.storage().persistent().set(&data_key, &data_hash);
        env.storage().persistent().extend_ttl(&data_key, PERSISTENT_TTL, PERSISTENT_TTL);
        env.events().publish(
            (symbol_short!("kyc"), symbol_short!("submitted"), subject.clone()),
            KycEvent {
                subject: subject.clone(),
                submitted_at: now,
                data_hash,
            },
        );
    }

    pub fn get_kyc_data_hash(env: Env, subject: Address) -> Option<Bytes> {
        let data_key = make_storage_key(&env, &[b"KYCDATA", &xdr_to_vec(&subject.clone().to_xdr(&env))]);
        env.storage().persistent().get(&data_key)
    }

    /// Approve a pending KYC record.
    ///
    /// `operator` must be the primary admin or hold [`AdminRole::KycAdmin`].
    pub fn approve_kyc(env: Env, operator: Address, subject: Address) {
        Self::require_admin_or_role(&env, &operator, AdminRole::KycAdmin);
        let now = env.ledger().timestamp();
        let key = kyc_record_key(&env, &subject);
        let mut record: KycRecord = env.storage().persistent().get(&key)
            .unwrap_or_else(|| panic_with_error!(&env, ErrorCode::KycNotFound));
        let current_status = current_kyc_status(&env, &record);
        if !validate_kyc_transition(current_status, KycStatus::Approved, &record, now) {
            panic_with_error!(&env, ErrorCode::IllegalTransition);
        }
        record.status = KycStatus::Approved as u32;
        record.reviewed_at = Some(now);
        record.expiry = Some(now + KYC_EXPIRY_SECONDS);
        env.storage().persistent().set(&key, &record);
        env.storage().persistent().extend_ttl(&key, PERSISTENT_TTL, PERSISTENT_TTL);
        AdminAuditLog::log_action(
            &env,
            &operator,
            "approve_kyc",
            subject.to_string(),
            "Pending",
            "Approved",
        );
        env.events().publish(
            (symbol_short!("kyc"), symbol_short!("approved"), subject.clone()),
            KycStatusChangedEvent {
                subject,
                new_status: KycStatus::Approved as u32,
                timestamp: now,
            },
        );
    }

    /// Reject a pending KYC record.
    ///
    /// `operator` must be the primary admin or hold [`AdminRole::KycAdmin`].
    pub fn reject_kyc(env: Env, operator: Address, subject: Address, reason_hash: Bytes) {
        Self::require_admin_or_role(&env, &operator, AdminRole::KycAdmin);
        let now = env.ledger().timestamp();
        let key = kyc_record_key(&env, &subject);
        let mut record: KycRecord = env.storage().persistent().get(&key)
            .unwrap_or_else(|| panic_with_error!(&env, ErrorCode::KycNotFound));
        let current_status = current_kyc_status(&env, &record);
        if !validate_kyc_transition(current_status, KycStatus::Rejected, &record, now) {
            panic_with_error!(&env, ErrorCode::IllegalTransition);
        }
        record.status = KycStatus::Rejected as u32;
        record.reviewed_at = Some(now);
        record.expiry = None;
        record.rejection_reason_hash = Some(reason_hash.clone());
        env.storage().persistent().set(&key, &record);
        env.storage().persistent().extend_ttl(&key, PERSISTENT_TTL, PERSISTENT_TTL);
        AdminAuditLog::log_action(
            &env,
            &operator,
            "reject_kyc",
            subject.to_string(),
            "Pending",
            "Rejected",
        );
        env.events().publish(
            (symbol_short!("kyc"), symbol_short!("rejected"), subject.clone()),
            KycStatusChangedEvent {
                subject,
                new_status: KycStatus::Rejected as u32,
                timestamp: now,
            },
        );
    }

    pub fn get_kyc_status(env: Env, subject: Address) -> KycStatus {
        let key = kyc_record_key(&env, &subject);
        if !env.storage().persistent().has(&key) {
            return KycStatus::NotSubmitted;
        }
        let record: KycRecord = env.storage().persistent().get(&key)
            .unwrap_or_else(|| panic_with_error!(&env, ErrorCode::KycNotFound));
        if let Some(expiry) = record.expiry {
            if env.ledger().timestamp() > expiry {
                return KycStatus::Expired;
            }
        }
        match record.status {
            0 => KycStatus::NotSubmitted,
            1 => KycStatus::Pending,
            2 => KycStatus::Approved,
            3 => KycStatus::Rejected,
            4 => KycStatus::Expired,
            _ => KycStatus::NotSubmitted,
        }
    }

    // -----------------------------------------------------------------------
    // Compliance check recording (#37)
    // -----------------------------------------------------------------------

    /// Record a compliance check result for a subject (admin-only).
    /// Stores the latest `ComplianceCheck` record, appends to history, and updates the
    /// per-subject check-type index so auditors can query decision histories.
    pub fn record_compliance_check(
        env: Env,
        subject: Address,
        check_type: String,
        passed: bool,
        score: Option<u32>,
    ) {
        Self::require_admin(&env);
        let now = env.ledger().timestamp();
        let record = ComplianceCheck {
            subject: subject.clone(),
            check_type: check_type.clone(),
            result: if passed { 1u32 } else { 0u32 },
            score,
            timestamp: now,
        };

        // Store latest (keyed by subject + check_type)
        let key = compliance_check_key(&env, &subject, &check_type);
        env.storage().persistent().set(&key, &record);
        env.storage().persistent().extend_ttl(&key, PERSISTENT_TTL, PERSISTENT_TTL);

        // Append to ordered history
        let hist_cnt_key = compliance_history_count_key(&env, &subject, &check_type);
        let idx: u64 = env
            .storage()
            .persistent()
            .get::<_, u64>(&hist_cnt_key)
            .unwrap_or(0u64);
        let hist_key = compliance_history_entry_key(&env, &subject, &check_type, idx);
        env.storage().persistent().set(&hist_key, &record);
        env.storage().persistent().extend_ttl(&hist_key, PERSISTENT_TTL, PERSISTENT_TTL);
        env.storage().persistent().set(&hist_cnt_key, &(idx + 1));
        env.storage().persistent().extend_ttl(&hist_cnt_key, PERSISTENT_TTL, PERSISTENT_TTL);

        // Update per-subject check-type index
        let idx_key = compliance_subject_index_key(&env, &subject);
        let mut check_types: Vec<String> = env
            .storage()
            .persistent()
            .get::<_, Vec<String>>(&idx_key)
            .unwrap_or_else(|| Vec::new(&env));
        if !check_types.contains(&check_type) {
            check_types.push_back(check_type.clone());
            env.storage().persistent().set(&idx_key, &check_types);
            env.storage().persistent().extend_ttl(&idx_key, PERSISTENT_TTL, PERSISTENT_TTL);
        }

        env.events().publish(
            (symbol_short!("comp"), symbol_short!("checked"), subject),
            record,
        );
    }

    /// Return the most recent compliance check record for `(subject, check_type)`, or
    /// `None` if no check has been recorded.
    pub fn get_latest_compliance_check(
        env: Env,
        subject: Address,
        check_type: String,
    ) -> Option<ComplianceCheck> {
        let key = compliance_check_key(&env, &subject, &check_type);
        env.storage().persistent().get(&key)
    }

    /// Return the ordered history of compliance checks for `(subject, check_type)`.
    /// Returns up to `limit` records (capped at 50), most-recent last.
    pub fn get_compliance_check_history(
        env: Env,
        subject: Address,
        check_type: String,
        limit: u64,
    ) -> Vec<ComplianceCheck> {
        let hist_cnt_key = compliance_history_count_key(&env, &subject, &check_type);
        let total: u64 = env
            .storage()
            .persistent()
            .get::<_, u64>(&hist_cnt_key)
            .unwrap_or(0u64);
        let effective_limit = limit.min(50);
        let start = if total > effective_limit { total - effective_limit } else { 0 };
        let mut results = Vec::new(&env);
        for i in start..total {
            let hist_key = compliance_history_entry_key(&env, &subject, &check_type, i);
            if let Some(entry) = env.storage().persistent().get::<_, ComplianceCheck>(&hist_key) {
                results.push_back(entry);
            }
        }
        results
    }

    /// Return all check types that have been recorded for a given subject.
    pub fn list_subject_compliance_checks(env: Env, subject: Address) -> Vec<String> {
        let idx_key = compliance_subject_index_key(&env, &subject);
        env.storage()
            .persistent()
            .get::<_, Vec<String>>(&idx_key)
            .unwrap_or_else(|| Vec::new(&env))
    }

    // -----------------------------------------------------------------------
    // Input validation helpers (#243)
    // -----------------------------------------------------------------------

    /// Panic with `ValidationError` if `s` is empty.
    fn require_non_empty_string(env: &Env, s: &String) {
        if s.len() == 0 {
            panic_with_error!(env, ErrorCode::ValidationError);
        }
    }

    /// Panic with `InvalidTimestamp` if `ts` is zero.
    fn require_valid_timestamp(env: &Env, ts: u64) {
        if ts == 0 {
            panic_with_error!(env, ErrorCode::InvalidTimestamp);
        }
    }

    pub fn create_session(env: Env, initiator: Address) -> u64 {
        initiator.require_auth();
        let inst = env.storage().instance();
        let scnt_key = make_storage_key(&env, &[b"SCNT"]);
        let session_id: u64 = inst.get(&scnt_key).unwrap_or(0u64);
        inst.set(&scnt_key, &(session_id + 1));
        inst.extend_ttl(INSTANCE_TTL, INSTANCE_TTL);

        let now = env.ledger().timestamp();
        let session = Session {
            session_id,
            initiator: initiator.clone(),
            created_at: now,
            nonce: 0,
            operation_count: 0,
            session_ttl_seconds: DEFAULT_SESSION_TTL,
            closed: false,
        };
        let sess_key = make_storage_key(&env, &[b"SESS", &session_id.to_be_bytes()]);
        env.storage().persistent().set(&sess_key, &session);
        env.storage().persistent().extend_ttl(&sess_key, PERSISTENT_TTL, PERSISTENT_TTL);

        env.events().publish(
            (symbol_short!("session"), symbol_short!("created"), session_id),
            SessionCreatedEvent { session_id, initiator, timestamp: now },
        );
        session_id
    }

    pub fn close_session(env: Env, session_id: u64, initiator: Address) {
        initiator.require_auth();
        let sess_key = make_storage_key(&env, &[b"SESS", &session_id.to_be_bytes()]);
        let mut session: Session = env
            .storage()
            .persistent()
            .get(&sess_key)
            .unwrap_or_else(|| panic_with_error!(&env, ErrorCode::SessionNotFound));
        // #447: only the address that created the session may close it.
        // `initiator.require_auth()` alone proves the *supplied* address signed,
        // not that it owns this session, so verify ownership explicitly.
        if initiator != session.initiator {
            panic_with_error!(&env, ErrorCode::UnauthorizedAttestor);
        }
        Self::validate_session(&env, &session);
        session.closed = true;
        env.storage().persistent().set(&sess_key, &session);
        let now = env.ledger().timestamp();
        env.events().publish(
            (symbol_short!("session"), symbol_short!("closed"), session_id),
            SessionClosedEvent { session_id, initiator, timestamp: now },
        );
    }

    fn require_session_open(env: &Env, session_id: u64) {
        let sess_key = make_storage_key(env, &[b"SESS", &session_id.to_be_bytes()]);
        let session: Session = env
            .storage()
            .persistent()
            .get(&sess_key)
            .unwrap_or_else(|| panic_with_error!(env, ErrorCode::SessionNotFound));
        Self::validate_session(env, &session);
        // Delegate quota enforcement to SessionQuotaEnforcer so that the
        // effective limit respects per-session overrides and the global policy
        // rather than the hard-coded MAX_OPS_PER_SESSION constant.
        SessionQuotaEnforcer::check_and_increment(env, session_id);
    }

    // -----------------------------------------------------------------------
    // Quote management
    // -----------------------------------------------------------------------

    pub fn submit_quote(
        env: Env,
        anchor: Address,
        base_asset: String,
        quote_asset: String,
        rate: u64,
        fee_percentage: u32,
        minimum_amount: u64,
        maximum_amount: u64,
        valid_until: u64,
    ) -> u64 {
        Self::submit_quote_with_reason(
            env, anchor, base_asset, quote_asset,
            rate, fee_percentage, minimum_amount, maximum_amount,
            valid_until, None,
        )
    }

    /// Submit a quote with optional routing reason metadata (#298).
    ///
    /// Identical to [`submit_quote`] but records an optional `routing_reason`
    /// alongside the quote for audit and customer-support purposes. The reason
    /// is persisted in the [`Quote`] record and emitted in the submit event so
    /// it is available for off-chain audit consumers.
    ///
    /// # Arguments
    ///
    /// * `routing_reason` – Human-readable code explaining why this anchor/route
    ///   was chosen (e.g. `"lowest_fee"`, `"referral"`, `"preferred_anchor"`).
    ///   Pass `None` when no reason applies.
    pub fn submit_quote_with_reason(
        env: Env,
        anchor: Address,
        base_asset: String,
        quote_asset: String,
        rate: u64,
        fee_percentage: u32,
        minimum_amount: u64,
        maximum_amount: u64,
        valid_until: u64,
        routing_reason: Option<String>,
    ) -> u64 {
        anchor.require_auth();
        validate_currency_code(&env, &base_asset);
        validate_currency_code(&env, &quote_asset);
        validate_fee_percent(&env, fee_percentage);
        validate_amount_limits(&env, minimum_amount, maximum_amount);

        // Reject quotes that are already expired or set in the past.
        let now = env.ledger().timestamp();
        if valid_until <= now {
            panic_with_error!(&env, ErrorCode::InvalidQuote);
        }
        // Reject quotes expiring more than 30 days in the future to prevent
        // unbounded validity windows that make routing unpredictable.
        const MAX_QUOTE_VALIDITY: u64 = 30 * 24 * 60 * 60;
        if valid_until.saturating_sub(now) > MAX_QUOTE_VALIDITY {
            panic_with_error!(&env, ErrorCode::InvalidQuote);
        }
        let inst = env.storage().instance();
        let qcnt_key = make_storage_key(&env, &[b"QCNT"]);
        let next: u64 = inst.get(&qcnt_key).unwrap_or(0u64) + 1;
        inst.set(&qcnt_key, &next);
        inst.extend_ttl(INSTANCE_TTL, INSTANCE_TTL);

        let anchor_xdr = anchor.clone().to_xdr(&env);
        let anchor_raw = xdr_to_vec(&anchor_xdr);
        let quote = Quote {
            quote_id: next, anchor: anchor.clone(),
            base_asset: base_asset.clone(), quote_asset: quote_asset.clone(),
            rate, fee_percentage, minimum_amount, maximum_amount, valid_until,
            schema_version: SCHEMA_V1,
            routing_reason: routing_reason.clone(),
        };
        let q_key = make_storage_key(&env, &[b"QUOTE", &anchor_raw, &next.to_be_bytes()]);
        env.storage().persistent().set(&q_key, &quote);
        env.storage().persistent().extend_ttl(&q_key, PERSISTENT_TTL, PERSISTENT_TTL);
        Self::append_quote_index(&env, next, &anchor);

        let lq_key = make_storage_key(&env, &[b"LATESTQ", &anchor_raw]);
        env.storage().persistent().set(&lq_key, &next);
        env.storage().persistent().extend_ttl(&lq_key, PERSISTENT_TTL, PERSISTENT_TTL);

        env.events().publish(
            (symbol_short!("quote"), symbol_short!("submit"), next),
            QuoteSubmitEvent { quote_id: next, anchor, base_asset, quote_asset, rate, valid_until, routing_reason },
        );
        next
    }

    /// Retrieve the routing reason stored with a quote (#298).
    ///
    /// Returns `None` when the quote was submitted without a reason or does not
    /// exist. Callers that need the full quote record should use [`get_quote`].
    pub fn get_quote_routing_reason(env: Env, anchor: Address, quote_id: u64) -> Option<String> {
        let anchor_xdr = anchor.to_xdr(&env);
        let anchor_raw = xdr_to_vec(&anchor_xdr);
        let key = make_storage_key(&env, &[b"QUOTE", &anchor_raw, &quote_id.to_be_bytes()]);
        env.storage()
            .persistent()
            .get::<_, Quote>(&key)
            .and_then(|q| q.routing_reason)
    }

    pub fn receive_quote(env: Env, receiver: Address, anchor: Address, quote_id: u64) -> Quote {
        receiver.require_auth();
        let anchor_xdr = anchor.clone().to_xdr(&env);
        let anchor_raw = xdr_to_vec(&anchor_xdr);
        let q_key = make_storage_key(&env, &[b"QUOTE", &anchor_raw, &quote_id.to_be_bytes()]);
        let quote: Quote = env.storage().persistent().get(&q_key)
            .unwrap_or_else(|| panic_with_error!(&env, ErrorCode::QuoteNotFound));
        env.events().publish(
            (symbol_short!("quote"), symbol_short!("received"), quote_id),
            QuoteReceivedEvent { quote_id, receiver, timestamp: env.ledger().timestamp() },
        );
        quote
    }

    /// Accept a quote with compliance gating (#297).
    ///
    /// Verifies that the subject has passed compliance checks before accepting the quote.
    /// If the subject or corridor requires compliance checks, they must be passed first.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment context.
    /// * `receiver` - The address accepting the quote.
    /// * `anchor` - The anchor providing the quote.
    /// * `quote_id` - The quote identifier.
    /// * `require_compliance` - Whether to enforce compliance checks.
    ///
    /// # Returns
    ///
    /// The accepted [`Quote`].
    ///
    /// # Errors
    ///
    /// Panics with [`ErrorCode::ComplianceNotMet`] if compliance is required but not passed.
    pub fn accept_quote_with_compliance(
        env: Env,
        receiver: Address,
        anchor: Address,
        quote_id: u64,
        require_compliance: bool,
    ) -> Quote {
        receiver.require_auth();
        
        // Get the quote
        let anchor_xdr = anchor.clone().to_xdr(&env);
        let anchor_raw = xdr_to_vec(&anchor_xdr);
        let q_key = make_storage_key(&env, &[b"QUOTE", &anchor_raw, &quote_id.to_be_bytes()]);
        let quote: Quote = env.storage().persistent().get(&q_key)
            .unwrap_or_else(|| panic_with_error!(&env, ErrorCode::QuoteNotFound));

        // #297: Enforce compliance gating if required
        if require_compliance {
            let comp_key = compliance_check_key(&env, &receiver, &String::from_str(&env, "kyc"));
            let passed = env.storage().persistent()
                .get::<_, ComplianceCheck>(&comp_key)
                .map(|r| r.result == 1u32)
                .unwrap_or(false);
            if !passed {
                panic_with_error!(&env, ErrorCode::ComplianceNotMet);
            }
        }

        env.events().publish(
            (symbol_short!("quote"), symbol_short!("accepted"), quote_id),
            QuoteReceivedEvent { quote_id, receiver, timestamp: env.ledger().timestamp() },
        );
        quote
    }

    // -----------------------------------------------------------------------
    // Session-aware attestation
    // -----------------------------------------------------------------------

    pub fn submit_attestation_with_session(
        env: Env,
        session_id: u64,
        issuer: Address,
        subject: Address,
        timestamp: u64,
        payload_hash: Bytes,
        signature: Bytes,
    ) -> u64 {
        issuer.require_auth();
        Self::require_session_open(&env, session_id);
        Self::check_attestor(&env, &issuer);
        Self::verify_attestation_signature(&env, &issuer, &payload_hash, &signature);
        Self::enforce_rate_limit(&env, &issuer);
        Self::check_timestamp(&env, timestamp);

        // #232: per-session request-ID replay protection
        let hash_raw = xdr_to_vec(&payload_hash);
        let sess_req_key = make_storage_key(
            &env, &[b"SESSREQ", &session_id.to_be_bytes(), &hash_raw],
        );
        if env.storage().persistent().has(&sess_req_key) {
            // Record replay detection event and metrics before panicking
            let replay_event = replay_detection::record_replay_detection(&env, &payload_hash, &issuer);
            replay_detection::emit_replay_detection_log(&env, &replay_event);
            panic_with_error!(&env, ErrorCode::ReplayAttack);
        }
        env.storage().persistent().set(&sess_req_key, &true);
        env.storage().persistent().extend_ttl(&sess_req_key, REPLAY_TTL, REPLAY_TTL);

        let issuer_xdr = issuer.clone().to_xdr(&env);
        let issuer_raw = xdr_to_vec(&issuer_xdr);
        let used_key = make_storage_key(&env, &[b"USED", &issuer_raw, &hash_raw]);
        if env.storage().persistent().has(&used_key) {
            // Record replay detection event and metrics before panicking
            let replay_event = replay_detection::record_replay_detection(&env, &payload_hash, &issuer);
            replay_detection::emit_replay_detection_log(&env, &replay_event);
            panic_with_error!(&env, ErrorCode::ReplayAttack);
        }

        let id = Self::next_attestation_id(&env);
        Self::store_attestation(
            &env, id, issuer.clone(), subject.clone(), timestamp,
            payload_hash.clone(), signature,
        );

        env.storage().persistent().set(&used_key, &id);
        env.storage().persistent().extend_ttl(&used_key, REPLAY_TTL, REPLAY_TTL);

        // Increment session nonce
        let sess_key = make_storage_key(&env, &[b"SESS", &session_id.to_be_bytes()]);
        let mut session: Session = env
            .storage().persistent().get(&sess_key)
            .unwrap_or_else(|| panic_with_error!(&env, ErrorCode::SessionNotFound));
        session.nonce += 1;
        env.storage().persistent().set(&sess_key, &session);
        env.storage().persistent().extend_ttl(&sess_key, PERSISTENT_TTL, PERSISTENT_TTL);

        let sopcnt_key = make_storage_key(&env, &[b"SOPCNT", &session_id.to_be_bytes()]);
        let op_index: u64 = env.storage().persistent().get(&sopcnt_key).unwrap_or(0u64);
        env.storage().persistent().set(&sopcnt_key, &(op_index + 1));
        env.storage().persistent().extend_ttl(&sopcnt_key, PERSISTENT_TTL, PERSISTENT_TTL);

        let inst = env.storage().instance();
        let acnt_key = make_storage_key(&env, &[b"ACNT"]);
        let log_id: u64 = inst.get(&acnt_key).unwrap_or(0u64);
        inst.set(&acnt_key, &(log_id + 1));
        inst.extend_ttl(INSTANCE_TTL, INSTANCE_TTL);

        let now = env.ledger().timestamp();
        let audit = AuditLog {
            log_id, session_id, actor: issuer.clone(),
            operation: OperationContext {
                session_id, operation_index: op_index,
                operation_type: String::from_str(&env, "attest"),
                timestamp: now, status: String::from_str(&env, "success"),
                result_data: id,
            },
        };
        let audit_key = make_storage_key(&env, &[b"AUDIT", &log_id.to_be_bytes()]);
        env.storage().persistent().set(&audit_key, &audit);
        env.storage().persistent().extend_ttl(&audit_key, PERSISTENT_TTL, PERSISTENT_TTL);
        let slog_key = make_storage_key(&env, &[b"SLOG", &session_id.to_be_bytes(), &op_index.to_be_bytes()]);
        env.storage().persistent().set(&slog_key, &log_id);
        env.storage().persistent().extend_ttl(&slog_key, PERSISTENT_TTL, PERSISTENT_TTL);

        env.events().publish(
            (symbol_short!("attest"), symbol_short!("recorded"), id, subject),
            AttestEvent { payload_hash, timestamp },
        );
        env.events().publish(
            (symbol_short!("audit"), symbol_short!("logged"), log_id),
            AuditLogEvent {
                log_id, session_id, operation_index: op_index,
                operation_type: String::from_str(&env, "attest"),
                status: String::from_str(&env, "success"),
                result_data: 0,
            },
        );
        id
    }

    /// Register an attestor within a session.
    ///
    /// `operator` must be the primary admin or hold [`AdminRole::AttestorAdmin`].
    pub fn register_attestor_with_session(env: Env, operator: Address, session_id: u64, attestor: Address, public_key: BytesN<32>) {
        Self::require_admin_or_role(&env, &operator, AdminRole::AttestorAdmin);
        Self::require_session_open(&env, session_id);
        let xdr = attestor.clone().to_xdr(&env);
        let raw = xdr_to_vec(&xdr);
        let key = make_storage_key(&env, &[b"ATTESTOR", &raw]);
        if env.storage().persistent().has(&key) {
            panic_with_error!(&env, ErrorCode::AttestorAlreadyRegistered);
        }
        env.storage().persistent().set(&key, &true);
        env.storage().persistent().extend_ttl(&key, PERSISTENT_TTL, PERSISTENT_TTL);
        let pk_key = make_storage_key(&env, &[b"ATPUBKEY", &raw]);
        env.storage().persistent().set(&pk_key, &public_key);
        env.storage().persistent().extend_ttl(&pk_key, PERSISTENT_TTL, PERSISTENT_TTL);

        let mut attestors_list = env.storage().instance().get::<_, soroban_sdk::Vec<Address>>(&Self::attestor_list_key(&env)).unwrap_or_else(|| soroban_sdk::Vec::new(&env));
        if !attestors_list.contains(&attestor) {
            attestors_list.push_back(attestor.clone());
            env.storage().instance().set(&Self::attestor_list_key(&env), &attestors_list);
        }
        
        let sopcnt_key = make_storage_key(&env, &[b"SOPCNT", &session_id.to_be_bytes()]);
        let op_index: u64 = env.storage().persistent().get(&sopcnt_key).unwrap_or(0u64);
        env.storage().persistent().set(&sopcnt_key, &(op_index + 1));
        env.storage().persistent().extend_ttl(&sopcnt_key, PERSISTENT_TTL, PERSISTENT_TTL);

        let inst = env.storage().instance();
        let acnt_key = make_storage_key(&env, &[b"ACNT"]);
        let log_id: u64 = inst.get(&acnt_key).unwrap_or(0u64);
        inst.set(&acnt_key, &(log_id + 1));
        inst.extend_ttl(INSTANCE_TTL, INSTANCE_TTL);

        let now = env.ledger().timestamp();
        let audit = AuditLog {
            log_id, session_id, actor: operator.clone(),
            operation: OperationContext {
                session_id, operation_index: op_index,
                operation_type: String::from_str(&env, "register"),
                timestamp: now, status: String::from_str(&env, "success"),
                result_data: 0,
            },
        };
        let audit_key = make_storage_key(&env, &[b"AUDIT", &log_id.to_be_bytes()]);
        env.storage().persistent().set(&audit_key, &audit);
        env.storage().persistent().extend_ttl(&audit_key, PERSISTENT_TTL, PERSISTENT_TTL);
        let slog_key = make_storage_key(&env, &[b"SLOG", &session_id.to_be_bytes(), &op_index.to_be_bytes()]);
        env.storage().persistent().set(&slog_key, &log_id);
        env.storage().persistent().extend_ttl(&slog_key, PERSISTENT_TTL, PERSISTENT_TTL);

        env.events().publish((symbol_short!("attestor"), symbol_short!("added"), attestor), ());
        env.events().publish(
            (symbol_short!("audit"), symbol_short!("logged"), log_id),
            AuditLogEvent {
                log_id, session_id, operation_index: op_index,
                operation_type: String::from_str(&env, "register"),
                status: String::from_str(&env, "success"),
                result_data: 0,
            },
        );
    }

    /// Revoke an attestor within a session.
    ///
    /// `operator` must be the primary admin or hold [`AdminRole::AttestorAdmin`].
    pub fn revoke_attestor_with_session(env: Env, operator: Address, session_id: u64, attestor: Address) {
        Self::require_admin_or_role(&env, &operator, AdminRole::AttestorAdmin);
        Self::require_session_open(&env, session_id);
        let xdr = attestor.clone().to_xdr(&env);
        let raw = xdr_to_vec(&xdr);
        let key = make_storage_key(&env, &[b"ATTESTOR", &raw]);
        if !env.storage().persistent().has(&key) {
            panic_with_error!(&env, ErrorCode::AttestorNotRegistered);
        }
        env.storage().persistent().remove(&key);
        let pk_key = make_storage_key(&env, &[b"ATPUBKEY", &raw]);
        env.storage().persistent().remove(&pk_key);

        let mut attestors_list = env.storage().instance().get::<_, soroban_sdk::Vec<Address>>(&Self::attestor_list_key(&env)).unwrap_or_else(|| soroban_sdk::Vec::new(&env));
        if let Some(idx) = attestors_list.first_index_of(&attestor) {
            attestors_list.remove(idx);
            env.storage().instance().set(&Self::attestor_list_key(&env), &attestors_list);
        }

        let sopcnt_key = make_storage_key(&env, &[b"SOPCNT", &session_id.to_be_bytes()]);
        let op_index: u64 = env.storage().persistent().get(&sopcnt_key).unwrap_or(0u64);
        env.storage().persistent().set(&sopcnt_key, &(op_index + 1));
        env.storage().persistent().extend_ttl(&sopcnt_key, PERSISTENT_TTL, PERSISTENT_TTL);

        let inst = env.storage().instance();
        let acnt_key = make_storage_key(&env, &[b"ACNT"]);
        let log_id: u64 = inst.get(&acnt_key).unwrap_or(0u64);
        inst.set(&acnt_key, &(log_id + 1));
        inst.extend_ttl(INSTANCE_TTL, INSTANCE_TTL);

        let now = env.ledger().timestamp();
        let audit = AuditLog {
            log_id, session_id, actor: operator.clone(),
            operation: OperationContext {
                session_id, operation_index: op_index,
                operation_type: String::from_str(&env, "revoke"),
                timestamp: now, status: String::from_str(&env, "success"),
                result_data: 0,
            },
        };
        let audit_key = make_storage_key(&env, &[b"AUDIT", &log_id.to_be_bytes()]);
        env.storage().persistent().set(&audit_key, &audit);
        env.storage().persistent().extend_ttl(&audit_key, PERSISTENT_TTL, PERSISTENT_TTL);
        let slog_key = make_storage_key(&env, &[b"SLOG", &session_id.to_be_bytes(), &op_index.to_be_bytes()]);
        env.storage().persistent().set(&slog_key, &log_id);
        env.storage().persistent().extend_ttl(&slog_key, PERSISTENT_TTL, PERSISTENT_TTL);

        env.events().publish((symbol_short!("attestor"), symbol_short!("removed"), attestor), ());
        env.events().publish(
            (symbol_short!("audit"), symbol_short!("logged"), log_id),
            AuditLogEvent {
                log_id, session_id, operation_index: op_index,
                operation_type: String::from_str(&env, "revoke"),
                status: String::from_str(&env, "success"),
                result_data: 0,
            },
        );
    }

    pub fn get_session(env: Env, session_id: u64) -> Session {
        env.storage()
            .persistent()
            .get::<_, Session>(&make_storage_key(&env, &[b"SESS", &session_id.to_be_bytes()]))
            .unwrap_or_else(|| panic_with_error!(&env, ErrorCode::SessionNotFound))
    }

    pub fn get_audit_log(env: Env, log_id: u64) -> AuditLog {
        env.storage()
            .persistent()
            .get::<_, AuditLog>(&make_storage_key(&env, &[b"AUDIT", &log_id.to_be_bytes()]))
            .unwrap_or_else(|| panic_with_error!(&env, ErrorCode::AuditLogNotFound))
    }

    pub fn get_session_audit_logs(env: Env, session_id: u64, limit: u64) -> Vec<AuditLog> {
        let total: u64 = env
            .storage()
            .persistent()
            .get(&make_storage_key(&env, &[b"SOPCNT", &session_id.to_be_bytes()]))
            .unwrap_or(0u64);
        let mut results = Vec::new(&env);
        let start = if total > limit { total - limit } else { 0 };
        for i in start..total {
            let slog_key = make_storage_key(&env, &[b"SLOG", &session_id.to_be_bytes(), &i.to_be_bytes()]);
            if let Some(log_id) = env.storage().persistent().get::<_, u64>(&slog_key) {
                let audit_key = make_storage_key(&env, &[b"AUDIT", &log_id.to_be_bytes()]);
                if let Some(entry) = env.storage().persistent().get::<_, AuditLog>(&audit_key) {
                    results.push_back(entry);
                }
            }
        }
        results
    }

    pub fn get_session_operation_count(env: Env, session_id: u64) -> u64 {
        env.storage()
            .persistent()
            .get::<_, u64>(&make_storage_key(&env, &[b"SOPCNT", &session_id.to_be_bytes()]))
            .unwrap_or(0)
    }

    // -----------------------------------------------------------------------
    // Audit log retention and pagination (#251)
    // -----------------------------------------------------------------------

    /// Set the audit log retention policy in days (admin-only).
    /// A value of 0 means no automatic retention limit is enforced.
    pub fn set_audit_log_retention(env: Env, retention_days: u64) {
        Self::require_admin(&env);
        let key = audit_retention_key(&env);
        env.storage().instance().set(&key, &retention_days);
        env.storage().instance().extend_ttl(INSTANCE_TTL, INSTANCE_TTL);
    }

    /// Return the configured audit log retention policy in days (0 = unlimited).
    pub fn get_audit_log_retention(env: Env) -> u64 {
        let key = audit_retention_key(&env);
        env.storage().instance().get::<_, u64>(&key).unwrap_or(0u64)
    }

    /// Return the total number of audit log entries ever written.
    pub fn get_audit_log_count(env: Env) -> u64 {
        let acnt_key = make_storage_key(&env, &[b"ACNT"]);
        let count = env.storage().instance().get::<_, u64>(&acnt_key).unwrap_or(0u64);
        
        let threshold_key = symbol_short!("AUTOPRUNE");
        let threshold = env.storage().instance().get::<_, u32>(&threshold_key).unwrap_or(0);
        if threshold > 0 && count > threshold as u64 {
            let retention_days = Self::get_audit_log_retention(env.clone());
            let before_timestamp = env.ledger().timestamp().saturating_sub(retention_days * 86400);
            let pruned = Self::prune_audit_logs_internal(&env, before_timestamp);
            if pruned > 0 {
                env.events().publish(
                    (symbol_short!("audit"), symbol_short!("pruned")),
                    AuditLogEvent {
                        log_id: 0,
                        session_id: 0,
                        operation_index: 0,
                        operation_type: String::from_str(&env, "auto_prune"),
                        status: String::from_str(&env, "success"),
                        result_data: pruned,
                    },
                );
            }
        }
        count
    }

    /// Return a page of audit log entries starting at `offset`, up to `limit` entries
    /// (capped at 50 per call to bound WASM execution).
    pub fn get_audit_logs_paginated(env: Env, offset: u64, limit: u64) -> Vec<AuditLog> {
        let acnt_key = make_storage_key(&env, &[b"ACNT"]);
        let total: u64 = env.storage().instance().get::<_, u64>(&acnt_key).unwrap_or(0u64);
        let effective_limit = limit.min(50);
        let end = offset.saturating_add(effective_limit).min(total);
        let mut results = Vec::new(&env);
        for i in offset..end {
            let audit_key = make_storage_key(&env, &[b"AUDIT", &i.to_be_bytes()]);
            if let Some(entry) = env.storage().persistent().get::<_, AuditLog>(&audit_key) {
                results.push_back(entry);
            }
        }
        results
    }

    /// Paginated retrieval of audit logs scoped to a specific session.
    /// Returns up to `limit` entries (capped at 50) starting at `offset` within the session.
    pub fn get_session_logs_paginated(
        env: Env,
        session_id: u64,
        offset: u64,
        limit: u64,
    ) -> Vec<AuditLog> {
        let total: u64 = env
            .storage()
            .persistent()
            .get(&make_storage_key(&env, &[b"SOPCNT", &session_id.to_be_bytes()]))
            .unwrap_or(0u64);
        let effective_limit = limit.min(50);
        let end = offset.saturating_add(effective_limit).min(total);
        let mut results = Vec::new(&env);
        for i in offset..end {
            let slog_key = make_storage_key(&env, &[b"SLOG", &session_id.to_be_bytes(), &i.to_be_bytes()]);
            if let Some(log_id) = env.storage().persistent().get::<_, u64>(&slog_key) {
                let audit_key = make_storage_key(&env, &[b"AUDIT", &log_id.to_be_bytes()]);
                if let Some(entry) = env.storage().persistent().get::<_, AuditLog>(&audit_key) {
                    results.push_back(entry);
                }
            }
        }
        results
    }

    fn prune_audit_logs_internal(env: &Env, before_timestamp: u64) -> u64 {
        let acnt_key = make_storage_key(env, &[b"ACNT"]);
        let total: u64 = env.storage().instance().get::<_, u64>(&acnt_key).unwrap_or(0u64);
        let scan_limit = total.min(100);
        let mut pruned: u64 = 0;
        for i in 0..scan_limit {
            let audit_key = make_storage_key(env, &[b"AUDIT", &i.to_be_bytes()]);
            if let Some(entry) = env.storage().persistent().get::<_, AuditLog>(&audit_key) {
                if entry.operation.timestamp < before_timestamp {
                    env.storage().persistent().remove(&audit_key);
                    pruned += 1;
                }
            }
        }
        pruned
    }

    /// Remove audit log entries whose `operation.timestamp` is strictly before
    /// `before_timestamp`. Scans up to the first 100 log IDs to remain WASM-safe.
    /// Returns the number of entries pruned.
    pub fn prune_audit_logs(env: Env, before_timestamp: u64) -> u64 {
        Self::require_admin(&env);
        Self::prune_audit_logs_internal(&env, before_timestamp)
    }

    pub fn set_auto_prune_threshold(env: Env, n: u32) {
        Self::require_admin(&env);
        let key = symbol_short!("AUTOPRUNE");
        env.storage().instance().set(&key, &n);
        env.storage().instance().extend_ttl(INSTANCE_TTL, INSTANCE_TTL);
    }

    pub fn export_audit_log_batch(env: Env, start_id: u64, limit: u32) -> Bytes {
        let acnt_key = make_storage_key(&env, &[b"ACNT"]);
        let total: u64 = env.storage().instance().get::<_, u64>(&acnt_key).unwrap_or(0u64);
        
        let effective_limit = limit.min(50);
        let end_id = start_id.saturating_add(effective_limit as u64).min(total);
        
        let mut json = alloc::string::String::new();
        json.push('[');
        
        let mut first = true;
        for i in start_id..end_id {
            let audit_key = make_storage_key(&env, &[b"AUDIT", &i.to_be_bytes()]);
            if let Some(entry) = env.storage().persistent().get::<_, AuditLog>(&audit_key) {
                if !first {
                    json.push(',');
                }
                first = false;
                
                let raw_xdr = xdr_to_vec(&entry.to_xdr(&env));
                json.push('"');
                for b in raw_xdr {
                    use core::fmt::Write;
                    write!(&mut json, "{:02x}", b).unwrap();
                }
                json.push('"');
            }
        }
        json.push(']');
        Bytes::from_slice(&env, json.as_bytes())
    }

    // -----------------------------------------------------------------------
    // Metadata cache
    // -----------------------------------------------------------------------

    pub fn cache_metadata(env: Env, anchor: Address, metadata: AnchorMetadata, ttl_seconds: u64) {
        Self::require_admin(&env);
        let key = (symbol_short!("METACACHE"), anchor.clone());
        let entry_exists = env.storage().temporary().has(&key);
        
        // Check capacity only if adding a new entry
        if !entry_exists {
            let config = Self::get_capacity_config_internal(&env);
            let current_count = Self::get_cache_count_internal(&env);
            if current_count >= config.max_cache_entries {
                panic_with_error!(&env, ErrorCode::CacheCapacityExceeded);
            }
        }

        let now = env.ledger().timestamp();
        let cfg = Self::get_cache_config_internal(&env);
        let ttl = Self::effective_ttl(ttl_seconds, cfg.metadata_ttl_seconds);
        let stale = cfg.swr_ttl_seconds;
        let entry = MetadataCache {
            metadata,
            cached_at: now,
            ttl_seconds: ttl,
            stale_ttl_seconds: stale,
            needs_refresh: false,
        };
        let ledger_ttl = if ttl as u32 > MIN_TEMP_TTL { ttl as u32 } else { MIN_TEMP_TTL };
        env.storage().temporary().set(&key, &entry);
        env.storage().temporary().extend_ttl(&key, ledger_ttl, ledger_ttl);

        // Increment count if new entry
        if !entry_exists {
            let current_count = Self::get_cache_count_internal(&env);
            env.storage().instance().set(&Self::cache_count_key(&env), &(current_count + 1));
            env.storage().instance().extend_ttl(INSTANCE_TTL, INSTANCE_TTL);
        }
    }

    pub fn get_cached_metadata(env: Env, anchor: Address) -> AnchorMetadata {
        let key = (symbol_short!("METACACHE"), anchor);
        let entry: MetadataCache = env.storage().temporary().get(&key)
            .unwrap_or_else(|| panic_with_error!(&env, ErrorCode::CacheNotFound));
        let now = env.ledger().timestamp();
        if entry.cached_at + entry.ttl_seconds <= now {
            panic_with_error!(&env, ErrorCode::CacheExpired);
        }
        entry.metadata
    }

    pub fn refresh_metadata_cache(env: Env, anchor: Address, new_metadata: AnchorMetadata, ttl_seconds: u64) {
        Self::require_admin(&env);
        Self::cache_metadata(env.clone(), anchor.clone(), new_metadata, ttl_seconds);
        Self::record_refresh_diagnostic(
            &env,
            &anchor,
            String::from_str(&env, "metadata"),
            RefreshStatus::Success,
            true,
            String::from_str(&env, "metadata cache refreshed successfully"),
        );
    }

    /// Store a metadata entry with a stale-while-revalidate grace period.
    /// After `ttl_seconds` the entry becomes stale; after `ttl_seconds + stale_ttl_seconds`
    /// it is fully expired and `get_cached_metadata_swr` will return an error.
    pub fn cache_metadata_swr(
        env: Env,
        anchor: Address,
        metadata: AnchorMetadata,
        ttl_seconds: u64,
        stale_ttl_seconds: u64,
    ) {
        Self::require_admin(&env);
        let key = (symbol_short!("METACACHE"), anchor.clone());
        let entry_exists = env.storage().temporary().has(&key);
        
        // Check capacity only if adding a new entry
        if !entry_exists {
            let config = Self::get_capacity_config_internal(&env);
            let current_count = Self::get_cache_count_internal(&env);
            if current_count >= config.max_cache_entries {
                panic_with_error!(&env, ErrorCode::CacheCapacityExceeded);
            }
        }

        let now = env.ledger().timestamp();
        let cfg = Self::get_cache_config_internal(&env);
        let ttl = Self::effective_ttl(ttl_seconds, cfg.metadata_ttl_seconds);
        let stale = Self::effective_ttl(stale_ttl_seconds, cfg.swr_ttl_seconds);
        let entry = MetadataCache {
            metadata,
            cached_at: now,
            ttl_seconds: ttl,
            stale_ttl_seconds: stale,
            needs_refresh: false,
        };
        let total_ttl = ttl.saturating_add(stale);
        let ledger_ttl = if total_ttl as u32 > MIN_TEMP_TTL { total_ttl as u32 } else { MIN_TEMP_TTL };
        env.storage().temporary().set(&key, &entry);
        env.storage().temporary().extend_ttl(&key, ledger_ttl, ledger_ttl);

        // Increment count if new entry
        if !entry_exists {
            let current_count = Self::get_cache_count_internal(&env);
            env.storage().instance().set(&Self::cache_count_key(&env), &(current_count + 1));
            env.storage().instance().extend_ttl(INSTANCE_TTL, INSTANCE_TTL);
        }
    }

    /// Retrieve a metadata entry using the stale-while-revalidate policy.
    ///
    /// Returns `(metadata, needs_refresh)`:
    /// - `needs_refresh = false` → entry is fresh (within primary TTL)
    /// - `needs_refresh = true`  → entry is stale (within grace period); caller should refresh
    ///
    /// Panics with `CacheExpired` once both TTLs have elapsed, or `CacheNotFound` if absent.
    pub fn get_cached_metadata_swr(env: Env, anchor: Address) -> (AnchorMetadata, bool) {
        let key = (symbol_short!("METACACHE"), anchor.clone());
        let mut entry: MetadataCache = env.storage().temporary().get(&key)
            .unwrap_or_else(|| panic_with_error!(&env, ErrorCode::CacheNotFound));
        let now = env.ledger().timestamp();
        let age = now.saturating_sub(entry.cached_at);

        if age <= entry.ttl_seconds {
            // Fresh
            (entry.metadata, false)
        } else if age <= entry.ttl_seconds.saturating_add(entry.stale_ttl_seconds) {
            // Stale — mark needs_refresh and persist the flag
            entry.needs_refresh = true;
            env.storage().temporary().set(&key, &entry);
            (entry.metadata, true)
        } else {
            panic_with_error!(&env, ErrorCode::CacheExpired);
        }
    }

    /// Unconditionally replace the cached metadata entry, resetting both TTL clocks.
    pub fn force_refresh_metadata(
        env: Env,
        anchor: Address,
        metadata: AnchorMetadata,
        ttl_seconds: u64,
        stale_ttl_seconds: u64,
    ) {
        Self::require_admin(&env);
        let now = env.ledger().timestamp();
        let cfg = Self::get_cache_config_internal(&env);
        let ttl = Self::effective_ttl(ttl_seconds, cfg.metadata_ttl_seconds);
        let stale = Self::effective_ttl(stale_ttl_seconds, cfg.swr_ttl_seconds);
        let entry = MetadataCache {
            metadata,
            cached_at: now,
            ttl_seconds: ttl,
            stale_ttl_seconds: stale,
            needs_refresh: false,
        };
        let key = (symbol_short!("METACACHE"), anchor.clone());
        let total_ttl = ttl.saturating_add(stale);
        let ledger_ttl = if total_ttl as u32 > MIN_TEMP_TTL { total_ttl as u32 } else { MIN_TEMP_TTL };
        env.storage().temporary().set(&key, &entry);
        env.storage().temporary().extend_ttl(&key, ledger_ttl, ledger_ttl);
    }

    // --- Cache Invalidation Governance (#555) ---

    /// Submit a proposal to invalidate a specific anchor's capability cache.
    /// Any registered attestor may call this; returns the new proposal_id.
    pub fn propose_cache_invalidation(env: Env, caller: Address, anchor: Address) -> u64 {
        caller.require_auth();
        Self::check_attestor(&env, &caller);
        crate::cache_governance::propose(&env, &caller, &anchor)
    }

    /// Endorse an existing cache invalidation proposal (registered attestors only).
    /// Duplicate endorsements from the same address are silently ignored.
    pub fn endorse_cache_invalidation(env: Env, caller: Address, proposal_id: u64) {
        caller.require_auth();
        Self::check_attestor(&env, &caller);
        crate::cache_governance::endorse(&env, &caller, proposal_id)
            .unwrap_or_else(|_| panic_with_error!(&env, ErrorCode::ValidationError));
    }

    /// Execute a proposal that has reached quorum, clearing the anchor's cache entries.
    /// Callable by anyone once quorum is met and the proposal has not expired.
    pub fn execute_cache_invalidation(env: Env, proposal_id: u64) {
        let anchor = crate::cache_governance::execute(&env, proposal_id)
            .unwrap_or_else(|_| panic_with_error!(&env, ErrorCode::ValidationError));
        let cap_key = (symbol_short!("CAPCACHE"), anchor.clone());
        env.storage().temporary().remove(&cap_key);
        let meta_key = (symbol_short!("METACACHE"), anchor);
        env.storage().temporary().remove(&meta_key);
    }

    /// Get a cache invalidation proposal by ID.
    pub fn get_cache_invalidation_proposal(
        env: Env,
        proposal_id: u64,
    ) -> crate::cache_governance::CacheInvalidationProposal {
        crate::cache_governance::get_proposal(&env, proposal_id)
            .unwrap_or_else(|| panic_with_error!(&env, ErrorCode::CacheNotFound))
    }

    /// Set quorum threshold for cache invalidation proposals (admin only).
    pub fn set_cache_quorum_threshold(env: Env, n: u32) {
        Self::require_admin(&env);
        let mut cfg = crate::cache_governance::get_config(&env);
        cfg.quorum_threshold = n;
        crate::cache_governance::set_config(&env, cfg);
    }

    /// Set proposal expiry in ledgers (admin only).
    pub fn set_cache_proposal_expiry(env: Env, ledgers: u32) {
        Self::require_admin(&env);
        let mut cfg = crate::cache_governance::get_config(&env);
        cfg.proposal_expiry_ledgers = ledgers;
        crate::cache_governance::set_config(&env, cfg);
    }


    /// Report the SWR lifecycle state of an anchor's metadata cache entry
    /// without panicking. This makes both fresh and stale availability explicit:
    /// callers can distinguish `Fresh`, `Stale` (serve-but-refresh), `Expired`
    /// (do not serve), and `Missing` rather than relying on a thrown error.
    ///
    /// Unlike [`get_cached_metadata_swr`](Self::get_cached_metadata_swr) this is a
    /// pure read — it never mutates the stored `needs_refresh` flag.
    pub fn get_metadata_cache_state(env: Env, anchor: Address) -> MetadataCacheState {
        let key = (symbol_short!("METACACHE"), anchor);
        let entry: MetadataCache = match env.storage().temporary().get(&key) {
            Some(e) => e,
            None => return MetadataCacheState::Missing,
        };
        let now = env.ledger().timestamp();
        let age = now.saturating_sub(entry.cached_at);
        if age <= entry.ttl_seconds {
            MetadataCacheState::Fresh
        } else if age <= entry.ttl_seconds.saturating_add(entry.stale_ttl_seconds) {
            MetadataCacheState::Stale
        } else {
            MetadataCacheState::Expired
        }
    }

    /// Complete an in-flight stale-while-revalidate refresh with freshly-fetched
    /// metadata, preserving the last-known-good entry until the new data is
    /// validated.
    ///
    /// Refresh semantics (issue #236):
    /// - **Last-known-good preservation** — incoming metadata is validated
    ///   *before* any storage write (see [`validate_metadata`]). If validation
    ///   fails the call panics and the previously cached entry is left
    ///   untouched, so a failed refresh never drops a usable cache entry.
    /// - **Idempotent** — if the supplied metadata is byte-for-byte identical to
    ///   the currently cached metadata *and* the entry is still `Fresh`, the call
    ///   is a no-op: the `cached_at` clock is not reset, so repeated refreshes
    ///   with unchanged data are stable. A refresh of a `Stale`/`Expired` entry
    ///   (or with changed data) always rewrites and resets both TTL clocks.
    ///
    /// This is the SWR-aware counterpart to the destructive
    /// [`refresh_metadata_cache`](Self::refresh_metadata_cache), which only
    /// invalidates. Prefer this when you have replacement data in hand.
    pub fn refresh_metadata_cache_swr(
        env: Env,
        anchor: Address,
        metadata: AnchorMetadata,
        ttl_seconds: u64,
        stale_ttl_seconds: u64,
    ) {
        Self::require_admin(&env);
        // Validate before touching storage so last-known-good survives a bad refresh.
        Self::validate_metadata(&env, &anchor, &metadata);

        let key = (symbol_short!("METACACHE"), anchor.clone());
        let now = env.ledger().timestamp();

        if let Some(existing) = env
            .storage()
            .temporary()
            .get::<_, MetadataCache>(&key)
        {
            let age = now.saturating_sub(existing.cached_at);
            let still_fresh = age <= existing.ttl_seconds;
            if still_fresh && existing.metadata == metadata {
                // Idempotent no-op: nothing changed and the entry is still fresh.
                return;
            }
        }

        let entry = MetadataCache {
            metadata,
            cached_at: now,
            ttl_seconds,
            stale_ttl_seconds,
            needs_refresh: false,
        };
        let total_ttl = ttl_seconds.saturating_add(stale_ttl_seconds);
        let ledger_ttl = if total_ttl as u32 > MIN_TEMP_TTL { total_ttl as u32 } else { MIN_TEMP_TTL };
        env.storage().temporary().set(&key, &entry);
        env.storage().temporary().extend_ttl(&key, ledger_ttl, ledger_ttl);
    }

    // -----------------------------------------------------------------------
    // Capabilities cache
    // -----------------------------------------------------------------------

    pub fn cache_capabilities(env: Env, anchor: Address, toml_url: String, capabilities: String, ttl_seconds: u64) {
        Self::require_admin(&env);
        let key = (symbol_short!("CAPCACHE"), anchor.clone());
        let entry_exists = env.storage().temporary().has(&key);
        
        // Check capacity only if adding a new entry
        if !entry_exists {
            let config = Self::get_capacity_config_internal(&env);
            let current_count = Self::get_cache_count_internal(&env);
            if current_count >= config.max_cache_entries {
                panic_with_error!(&env, ErrorCode::CacheCapacityExceeded);
            }
        }

        let now = env.ledger().timestamp();
        let cfg = Self::get_cache_config_internal(&env);
        let ttl = Self::effective_ttl(ttl_seconds, cfg.capabilities_ttl_seconds);
        let entry = CapabilitiesCache { toml_url, capabilities, cached_at: now, ttl_seconds: ttl };
        let ledger_ttl = if ttl as u32 > MIN_TEMP_TTL { ttl as u32 } else { MIN_TEMP_TTL };
        env.storage().temporary().set(&key, &entry);
        env.storage().temporary().extend_ttl(&key, ledger_ttl, ledger_ttl);

        // Increment count if new entry
        if !entry_exists {
            let current_count = Self::get_cache_count_internal(&env);
            env.storage().instance().set(&Self::cache_count_key(&env), &(current_count + 1));
            env.storage().instance().extend_ttl(INSTANCE_TTL, INSTANCE_TTL);
        }
    }

    pub fn get_cached_capabilities(env: Env, anchor: Address) -> CapabilitiesCache {
        let key = (symbol_short!("CAPCACHE"), anchor);
        let entry: CapabilitiesCache = env.storage().temporary().get(&key)
            .unwrap_or_else(|| panic_with_error!(&env, ErrorCode::CacheNotFound));
        let now = env.ledger().timestamp();
        if entry.cached_at + entry.ttl_seconds <= now {
            panic_with_error!(&env, ErrorCode::CacheExpired);
        }
        entry
    }

    pub fn refresh_capabilities_cache(env: Env, anchor: Address, toml_url: String, capabilities: String, ttl_seconds: u64) {
        Self::require_admin(&env);
        Self::cache_capabilities(env.clone(), anchor.clone(), toml_url, capabilities, ttl_seconds);
        Self::record_refresh_diagnostic(
            &env,
            &anchor,
            String::from_str(&env, "capabilities"),
            RefreshStatus::Success,
            true,
            String::from_str(&env, "capabilities cache refreshed successfully"),
        );
    }

    // -----------------------------------------------------------------------
    // Routing
    // -----------------------------------------------------------------------

    pub fn get_quote(env: Env, anchor: Address, quote_id: u64) -> Quote {
        let anchor_xdr = anchor.clone().to_xdr(&env);
        let anchor_raw = xdr_to_vec(&anchor_xdr);
        let key = make_storage_key(&env, &[b"QUOTE", &anchor_raw, &quote_id.to_be_bytes()]);
        env.storage().persistent().get::<_, Quote>(&key)
            .unwrap_or_else(|| panic_with_error!(&env, ErrorCode::QuoteNotFound))
    }

    pub fn set_anchor_metadata(
        env: Env,
        anchor: Address,
        reputation_score: u32,
        average_settlement_time: u64,
        liquidity_score: u32,
        uptime_percentage: u32,
        total_volume: u64,
    ) {
        Self::require_admin(&env);
        let meta = RoutingAnchorMeta {
            anchor: anchor.clone(),
            reputation_score,
            average_settlement_time,
            liquidity_score,
            uptime_percentage,
            total_volume,
            is_active: true,
        };
        let meta_key = anchor_meta_key(&env, &anchor);
        env.storage().persistent().set(&meta_key, &meta);
        env.storage().persistent().extend_ttl(&meta_key, PERSISTENT_TTL, PERSISTENT_TTL);

        // ── Version history ──────────────────────────────────────────────────
        // Increment the per-anchor version counter and append a history entry.
        let xdr = anchor.clone().to_xdr(&env);
        let raw = xdr_to_vec(&xdr);
        let vcnt_key = make_storage_key(&env, &[b"METAVCNT", &raw]);
        let version: u32 = env
            .storage()
            .persistent()
            .get::<_, u32>(&vcnt_key)
            .unwrap_or(0)
            + 1;
        env.storage().persistent().set(&vcnt_key, &version);
        env.storage().persistent().extend_ttl(&vcnt_key, PERSISTENT_TTL, PERSISTENT_TTL);

        let history_entry = AnchorMetadataVersion {
            version,
            updated_at: env.ledger().timestamp(),
            reputation_score,
            average_settlement_time,
            liquidity_score,
            uptime_percentage,
            total_volume,
            is_active: true,
        };
        let hkey = make_storage_key(&env, &[b"METAHIST", &raw, &version.to_be_bytes()]);
        env.storage().persistent().set(&hkey, &history_entry);
        env.storage().persistent().extend_ttl(&hkey, PERSISTENT_TTL, PERSISTENT_TTL);

        // Maintain ANCHLIST — stored under a deterministic key (#229)
        let list_key = make_storage_key(&env, &[b"ANCHLIST"]);
        let mut list: Vec<Address> = env.storage().persistent()
            .get::<_, Vec<Address>>(&list_key)
            .unwrap_or_else(|| Vec::new(&env));
        if !list.contains(&anchor) {
            list.push_back(anchor);
            env.storage().persistent().set(&list_key, &list);
            env.storage().persistent().extend_ttl(&list_key, PERSISTENT_TTL, PERSISTENT_TTL);
        }
    }

    // -----------------------------------------------------------------------
    // Anchor metadata version history
    // -----------------------------------------------------------------------

    /// Return the current version number for an anchor's metadata history.
    ///
    /// Returns `0` when no metadata has ever been set for the anchor.
    pub fn get_anchor_meta_version_count(env: Env, anchor: Address) -> u32 {
        let xdr = anchor.clone().to_xdr(&env);
        let raw = xdr_to_vec(&xdr);
        let vcnt_key = make_storage_key(&env, &[b"METAVCNT", &raw]);
        env.storage()
            .persistent()
            .get::<_, u32>(&vcnt_key)
            .unwrap_or(0)
    }

    /// Retrieve a specific historical version of an anchor's metadata.
    ///
    /// Versions are 1-based and increase monotonically with each call to
    /// [`set_anchor_metadata`](Self::set_anchor_metadata).
    ///
    /// # Errors
    ///
    /// Panics with [`ErrorCode::AttestorNotRegistered`] when the requested
    /// version does not exist (never written or TTL expired).
    pub fn get_anchor_metadata_at_version(
        env: Env,
        anchor: Address,
        version: u32,
    ) -> AnchorMetadataVersion {
        let xdr = anchor.clone().to_xdr(&env);
        let raw = xdr_to_vec(&xdr);
        let hkey = make_storage_key(&env, &[b"METAHIST", &raw, &version.to_be_bytes()]);
        env.storage()
            .persistent()
            .get::<_, AnchorMetadataVersion>(&hkey)
            .unwrap_or_else(|| panic_with_error!(&env, ErrorCode::AttestorNotRegistered))
    }

    /// Return the full ordered metadata history for an anchor, from version 1
    /// to the current version, capped at 50 entries to prevent unbounded reads.
    ///
    /// Entries are returned in ascending version order (oldest first).
    /// Versions whose storage entries have expired are silently omitted.
    ///
    /// # Returns
    ///
    /// A [`Vec`] of [`AnchorMetadataVersion`] records, oldest first.
    pub fn get_anchor_metadata_history(
        env: Env,
        anchor: Address,
    ) -> Vec<AnchorMetadataVersion> {
        const MAX_HISTORY: u32 = 50;
        let xdr = anchor.clone().to_xdr(&env);
        let raw = xdr_to_vec(&xdr);
        let vcnt_key = make_storage_key(&env, &[b"METAVCNT", &raw]);
        let total: u32 = env
            .storage()
            .persistent()
            .get::<_, u32>(&vcnt_key)
            .unwrap_or(0);

        let mut history = Vec::new(&env);
        // Start from the oldest version that fits within the cap.
        let start = if total > MAX_HISTORY { total - MAX_HISTORY + 1 } else { 1 };
        for v in start..=total {
            let hkey = make_storage_key(&env, &[b"METAHIST", &raw, &v.to_be_bytes()]);
            if let Some(entry) = env
                .storage()
                .persistent()
                .get::<_, AnchorMetadataVersion>(&hkey)
            {
                history.push_back(entry);
            }
        }
        history
    }

    /// Deactivate an anchor (admin-only). Sets `is_active = false` without blacklisting.
    pub fn deactivate_anchor(env: Env, anchor: Address) {
        Self::require_admin(&env);
        let meta_key = anchor_meta_key(&env, &anchor);
        let mut meta: RoutingAnchorMeta = env
            .storage()
            .persistent()
            .get(&meta_key)
            .unwrap_or_else(|| panic_with_error!(&env, ErrorCode::AttestorNotRegistered));
        meta.is_active = false;
        env.storage().persistent().set(&meta_key, &meta);
        env.storage()
            .persistent()
            .extend_ttl(&meta_key, PERSISTENT_TTL, PERSISTENT_TTL);
    }

    /// Reactivate a previously deactivated anchor (admin-only). Sets `is_active = true`.
    pub fn reactivate_anchor(env: Env, anchor: Address) {
        Self::require_admin(&env);
        let meta_key = anchor_meta_key(&env, &anchor);
        let mut meta: RoutingAnchorMeta = env
            .storage()
            .persistent()
            .get(&meta_key)
            .unwrap_or_else(|| panic_with_error!(&env, ErrorCode::AttestorNotRegistered));
        meta.is_active = true;
        env.storage().persistent().set(&meta_key, &meta);
        env.storage()
            .persistent()
            .extend_ttl(&meta_key, PERSISTENT_TTL, PERSISTENT_TTL);
    }

    /// Return the full `RoutingAnchorMeta` for an anchor.
    pub fn get_anchor_metadata(env: Env, anchor: Address) -> RoutingAnchorMeta {
        env.storage()
            .persistent()
            .get::<_, RoutingAnchorMeta>(&anchor_meta_key(&env, &anchor))
            .unwrap_or_else(|| panic_with_error!(&env, ErrorCode::AttestorNotRegistered))
    }

    /// Return all anchors in ANCHLIST where `is_active == true`.
    pub fn list_active_anchors(env: Env) -> Vec<Address> {
        let list_key = make_storage_key(&env, &[b"ANCHLIST"]);
        let anchors: Vec<Address> = env
            .storage()
            .persistent()
            .get::<_, Vec<Address>>(&list_key)
            .unwrap_or_else(|| Vec::new(&env));
        let mut active = Vec::new(&env);
        for anchor in anchors.iter() {
            if let Some(meta) = env
                .storage()
                .persistent()
                .get::<_, RoutingAnchorMeta>(&anchor_meta_key(&env, &anchor))
            {
                if meta.is_active {
                    active.push_back(anchor);
                }
            }
        }
        active
    }

    // -----------------------------------------------------------------------
    // Anchor Blacklist Management (#296)
    // -----------------------------------------------------------------------

    /// Add an anchor to the blacklist.
    ///
    /// Blacklisted anchors are excluded from routing and quote selection.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment context.
    /// * `anchor` - Address of the anchor to blacklist.
    /// * `reason` - Reason for blacklisting.
    ///
    /// # Authorization
    ///
    /// Requires admin privileges.
    pub fn blacklist_anchor(env: Env, anchor: Address, reason: String) {
        Self::require_admin(&env);
        let entry = AnchorBlacklistEntry {
            anchor: anchor.clone(),
            reason,
            blacklisted_at: env.ledger().timestamp(),
        };
        let key = anchor_blacklist_key(&env, &anchor);
        env.storage().persistent().set(&key, &entry);
        env.storage()
            .persistent()
            .extend_ttl(&key, PERSISTENT_TTL, PERSISTENT_TTL);

        let idx_key = blacklist_index_key(&env);
        let mut index: Vec<Address> = env
            .storage()
            .persistent()
            .get(&idx_key)
            .unwrap_or_else(|| Vec::new(&env));
        if !index.contains(&anchor) {
            index.push_back(anchor.clone());
        }
        env.storage().persistent().set(&idx_key, &index);
        env.storage()
            .persistent()
            .extend_ttl(&idx_key, PERSISTENT_TTL, PERSISTENT_TTL);

        AdminAuditLog::log_action(
            &env,
            &Self::get_admin_internal(&env),
            "blacklist_anchor",
            anchor.to_string(),
            "active",
            "blacklisted",
        );
        env.events().publish(
            (symbol_short!("anchor"), symbol_short!("blacklist")),
            anchor,
        );
    }

    /// Remove an anchor from the blacklist.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment context.
    /// * `anchor` - Address of the anchor to remove from blacklist.
    ///
    /// # Authorization
    ///
    /// Requires admin privileges.
    pub fn remove_from_blacklist(env: Env, anchor: Address) {
        Self::require_admin(&env);
        let key = anchor_blacklist_key(&env, &anchor);
        env.storage().persistent().remove(&key);

        let idx_key = blacklist_index_key(&env);
        let index: Vec<Address> = env
            .storage()
            .persistent()
            .get(&idx_key)
            .unwrap_or_else(|| Vec::new(&env));
        let mut new_index: Vec<Address> = Vec::new(&env);
        for entry in index.iter() {
            if entry != anchor {
                new_index.push_back(entry);
            }
        }
        env.storage().persistent().set(&idx_key, &new_index);
        env.storage()
            .persistent()
            .extend_ttl(&idx_key, PERSISTENT_TTL, PERSISTENT_TTL);

        AdminAuditLog::log_action(
            &env,
            &Self::get_admin_internal(&env),
            "remove_from_blacklist",
            anchor.to_string(),
            "blacklisted",
            "active",
        );
        env.events().publish(
            (symbol_short!("anchor"), symbol_short!("unblklist")),
            anchor,
        );
    }

    /// Check if an anchor is blacklisted.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment context.
    /// * `anchor` - Address to check.
    ///
    /// # Returns
    ///
    /// `true` if the anchor is blacklisted, `false` otherwise.
    pub fn is_anchor_blacklisted(env: Env, anchor: Address) -> bool {
        let key = anchor_blacklist_key(&env, &anchor);
        env.storage()
            .persistent()
            .get::<_, AnchorBlacklistEntry>(&key)
            .is_some()
    }

    /// Return the list of all currently blacklisted anchor addresses.
    pub fn get_blacklisted_anchors(env: Env) -> Vec<Address> {
        let idx_key = blacklist_index_key(&env);
        env.storage()
            .persistent()
            .get(&idx_key)
            .unwrap_or_else(|| Vec::new(&env))
    }

    // -----------------------------------------------------------------------
    // Anchor Cluster Management (#296)
    // -----------------------------------------------------------------------

    /// Create a new anchor cluster.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment context.
    /// * `cluster_id` - Unique identifier for the cluster.
    /// * `name` - Human-readable name for the cluster.
    /// * `anchors` - Initial list of anchors in the cluster.
    ///
    /// # Authorization
    ///
    /// Requires admin privileges.
    pub fn create_anchor_cluster(env: Env, cluster_id: String, name: String, anchors: Vec<Address>) {
        Self::require_admin(&env);
        let cluster = AnchorCluster {
            cluster_id: cluster_id.clone(),
            name,
            anchors,
            created_at: env.ledger().timestamp(),
        };
        let key = anchor_cluster_key(&env, &cluster_id);
        if env.storage().persistent().has(&key) {
            panic_with_error!(&env, ErrorCode::AlreadyInitialized);
        }
        env.storage().persistent().set(&key, &cluster);
        env.storage()
            .persistent()
            .extend_ttl(&key, PERSISTENT_TTL, PERSISTENT_TTL);

        // Add to cluster list (deduplicated)
        let list_key = anchor_cluster_list_key(&env);
        let mut cluster_ids: Vec<String> = env
            .storage()
            .persistent()
            .get(&list_key)
            .unwrap_or_else(|| Vec::new(&env));
        if !cluster_ids.contains(&cluster_id) {
            cluster_ids.push_back(cluster_id);
        }
        env.storage().persistent().set(&list_key, &cluster_ids);
        env.storage()
            .persistent()
            .extend_ttl(&list_key, PERSISTENT_TTL, PERSISTENT_TTL);

        env.events().publish(
            (symbol_short!("cluster"), symbol_short!("created")),
            (),
        );
    }

    /// Get a cluster by ID.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment context.
    /// * `cluster_id` - The cluster identifier.
    ///
    /// # Returns
    ///
    /// The [`AnchorCluster`] if found.
    pub fn get_anchor_cluster(env: Env, cluster_id: String) -> AnchorCluster {
        let key = anchor_cluster_key(&env, &cluster_id);
        env.storage()
            .persistent()
            .get(&key)
            .unwrap_or_else(|| panic_with_error!(&env, ErrorCode::ValidationError))
    }

    /// List all anchor clusters.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment context.
    ///
    /// # Returns
    ///
    /// Vector of cluster IDs.
    pub fn list_anchor_clusters(env: Env) -> Vec<String> {
        let list_key = anchor_cluster_list_key(&env);
        env.storage()
            .persistent()
            .get(&list_key)
            .unwrap_or_else(|| Vec::new(&env))
    }

    /// Delete an anchor cluster by ID.
    ///
    /// Removes the cluster record from persistent storage and removes its ID
    /// from the cluster list. Panics with `ValidationError` if the cluster
    /// does not exist.
    ///
    /// # Authorization
    ///
    /// Requires admin privileges.
    pub fn delete_anchor_cluster(env: Env, cluster_id: String) {
        Self::require_admin(&env);
        let key = anchor_cluster_key(&env, &cluster_id);
        if !env.storage().persistent().has(&key) {
            panic_with_error!(&env, ErrorCode::ValidationError);
        }
        env.storage().persistent().remove(&key);

        let list_key = anchor_cluster_list_key(&env);
        let cluster_ids: Vec<String> = env
            .storage()
            .persistent()
            .get(&list_key)
            .unwrap_or_else(|| Vec::new(&env));
        let mut new_ids: Vec<String> = Vec::new(&env);
        for id in cluster_ids.iter() {
            if id != cluster_id {
                new_ids.push_back(id);
            }
        }
        env.storage().persistent().set(&list_key, &new_ids);
        env.storage()
            .persistent()
            .extend_ttl(&list_key, PERSISTENT_TTL, PERSISTENT_TTL);

        env.events().publish(
            (symbol_short!("cluster"), symbol_short!("deleted")),
            cluster_id,
        );
    }

    /// Replace the anchors list of an existing cluster.
    ///
    /// Updates the `anchors` field of the identified cluster in place.
    /// Panics with `ValidationError` if the cluster does not exist.
    ///
    /// # Authorization
    ///
    /// Requires admin privileges.
    pub fn update_anchor_cluster_anchors(env: Env, cluster_id: String, anchors: Vec<Address>) {
        Self::require_admin(&env);
        let key = anchor_cluster_key(&env, &cluster_id);
        let mut cluster: AnchorCluster = env
            .storage()
            .persistent()
            .get(&key)
            .unwrap_or_else(|| panic_with_error!(&env, ErrorCode::ValidationError));
        cluster.anchors = anchors;
        env.storage().persistent().set(&key, &cluster);
        env.storage()
            .persistent()
            .extend_ttl(&key, PERSISTENT_TTL, PERSISTENT_TTL);

        env.events().publish(
            (symbol_short!("cluster"), symbol_short!("updated")),
            cluster_id,
        );
    }

    pub fn route_transaction(env: Env, options: RoutingOptions) -> Quote {
        validate_currency_code(&env, &options.request.base_asset);
        validate_currency_code(&env, &options.request.quote_asset);
        let now = env.ledger().timestamp();
        let list_key = make_storage_key(&env, &[b"ANCHLIST"]);
        let anchors: Vec<Address> = env.storage().persistent()
            .get::<_, Vec<Address>>(&list_key)
            .unwrap_or_else(|| Vec::new(&env));

        // Collect valid quotes from active anchors
        let mut candidates: Vec<Quote> = Vec::new(&env);
        for anchor in anchors.iter() {
            // #296: Skip blacklisted anchors
            if Self::is_anchor_blacklisted_internal(&env, &anchor) {
                continue;
            }

            // Check reputation filter
            let meta: RoutingAnchorMeta = match env.storage().persistent().get(&anchor_meta_key(&env, &anchor)) {
                Some(m) => m,
                None => continue,
            };
            if !meta.is_active { continue; }
            if meta.reputation_score < options.min_reputation { continue; }

            // Get latest quote for this anchor
            let anchor_xdr = anchor.clone().to_xdr(&env);
            let anchor_raw = xdr_to_vec(&anchor_xdr);
            let lq_key = make_storage_key(&env, &[b"LATESTQ", &anchor_raw]);
            let quote_id: u64 = match env.storage().persistent().get(&lq_key) {
                Some(id) => id,
                None => continue,
            };
            let q_key = make_storage_key(&env, &[b"QUOTE", &anchor_raw, &quote_id.to_be_bytes()]);
            let quote: Quote = match env.storage().persistent().get(&q_key) {
                Some(q) => q,
                None => continue,
            };

            // #238: the anchor must advertise the quote service. An anchor that
            // never configured SERVICE_QUOTES is excluded before scoring even if
            // a stale quote happens to be stored for it.
            if !Self::advertises_quote_service(&env, &anchor) {
                continue;
            }

            // #238: the quote must be for the requested asset pair. Quotes whose
            // base/quote assets differ from the request are not a valid route.
            if quote.base_asset != options.request.base_asset
                || quote.quote_asset != options.request.quote_asset
            {
                continue;
            }

            // Filter expired quotes
            if quote.valid_until <= now { continue; }

            // Filter by amount limits
            if options.request.amount < quote.minimum_amount
                || (quote.maximum_amount != 0 && options.request.amount > quote.maximum_amount)
            {
                continue;
            }

            candidates.push_back(quote);
        }

        if candidates.is_empty() {
            panic_with_error!(&env, ErrorCode::NoQuotesAvailable);
        }

        // Enforce compliance check (#38)
        if options.require_compliance {
            // Look for any passing compliance record for this subject
            // We check the generic "kyc" check_type as the standard compliance gate
            let comp_key = compliance_check_key(&env, &options.subject, &String::from_str(&env, "kyc"));
            let passed = env.storage().persistent()
                .get::<_, ComplianceCheck>(&comp_key)
                .map(|r| r.result == 1u32)
                .unwrap_or(false);
            if !passed {
                panic_with_error!(&env, ErrorCode::ComplianceNotMet);
            }
        }

        // Enforce KYC check (#439)
        if options.require_kyc {
            let kyc_status = Self::get_kyc_status_internal(&env, &options.subject);
            if kyc_status != KycStatus::Approved {
                match kyc_status {
                    KycStatus::Pending      => panic_with_error!(&env, ErrorCode::KycPending),
                    KycStatus::Rejected     => panic_with_error!(&env, ErrorCode::KycRejected),
                    KycStatus::Expired      => panic_with_error!(&env, ErrorCode::ComplianceNotMet),
                    KycStatus::NotSubmitted => panic_with_error!(&env, ErrorCode::KycNotFound),
                    _ => panic_with_error!(&env, ErrorCode::ComplianceNotMet),
                }
            }
        }

        // Apply strategy: pick best candidate
        let strategy_sym = options.strategy.get(0)
            .unwrap_or_else(|| panic_with_error!(&env, ErrorCode::NoQuotesAvailable));

        let lowest_fee_sym = Symbol::new(&env, "LowestFee");
        let fastest_sym = Symbol::new(&env, "FastestSettlement");
        let reputation_sym = Symbol::new(&env, "HighestReputation");

        let mut best: Quote = match candidates.get(0) {
            Some(q) => q,
            None => panic_with_error!(&env, ErrorCode::NoQuotesAvailable),
        };

        if strategy_sym == lowest_fee_sym {
            for q in candidates.iter() {
                if q.fee_percentage < best.fee_percentage {
                    best = q;
                }
            }
        } else if strategy_sym == fastest_sym {
            // Need settlement time from metadata
            let mut best_time: u64 = anchor_meta_opt(&env, &best.anchor)
                .map(|m| m.average_settlement_time)
                .unwrap_or(u64::MAX);
            for q in candidates.iter() {
                let t = anchor_meta_opt(&env, &q.anchor)
                    .map(|m| m.average_settlement_time)
                    .unwrap_or(u64::MAX);
                if t < best_time {
                    best_time = t;
                    best = q;
                }
            }
        } else if strategy_sym == reputation_sym {
            let mut best_rep: u32 = anchor_meta_opt(&env, &best.anchor)
                .map(|m| m.reputation_score)
                .unwrap_or(0);
            for q in candidates.iter() {
                let rep = anchor_meta_opt(&env, &q.anchor)
                    .map(|m| m.reputation_score)
                    .unwrap_or(0);
                if rep > best_rep {
                    best_rep = rep;
                    best = q;
                }
            }
        } else if strategy_sym == Symbol::new(&env, "WeightedScore") {
            // Issues #469, #470: use actual weights from options and properly scale fee to basis points
            // Normalize scores similar to route_anchors
            let mut max_fee: u32 = 0;
            let mut max_settlement: u64 = 0;
            let mut max_reputation: u32 = 0;
            
            for q in candidates.iter() {
                if q.fee_percentage > max_fee { max_fee = q.fee_percentage; }
                let meta = anchor_meta_opt(&env, &q.anchor);
                if let Some(m) = &meta {
                    if m.average_settlement_time > max_settlement { max_settlement = m.average_settlement_time; }
                    if m.reputation_score > max_reputation { max_reputation = m.reputation_score; }
                }
            }
            
            let fw = options.fee_weight as f32 / 1000.0_f32;
            let sw = options.speed_weight as f32 / 1000.0_f32;
            let rw = options.reputation_weight as f32 / 1000.0_f32;
            
            let weighted_score = |q: &Quote| -> f32 {
                let meta = anchor_meta_opt(&env, &q.anchor).unwrap_or_else(|| RoutingAnchorMeta {
                    anchor: q.anchor.clone(),
                    is_active: false,
                    reputation_score: 0,
                    liquidity_score: 0,
                    uptime_percentage: 0,
                    average_settlement_time: u64::MAX,
                    total_volume: 0,
                });
                let fee_score = if max_fee == 0 { 1.0_f32 } else { 1.0_f32 - (q.fee_percentage as f32 / max_fee as f32) };
                let speed_score = if max_settlement == 0 { 1.0_f32 } else { 1.0_f32 - (meta.average_settlement_time as f32 / max_settlement as f32) };
                let rep_score = if max_reputation == 0 { 0.0_f32 } else { meta.reputation_score as f32 / max_reputation as f32 };
                fw * fee_score + sw * speed_score + rw * rep_score
            };
            
            let mut best_score: f32 = weighted_score(&best);
            for q in candidates.iter() {
                let score = weighted_score(&q);
                if score > best_score {
                    best_score = score;
                    best = q;
                }
            }
        }

        env.events().publish(
            (symbol_short!("route"), symbol_short!("selected")),
            WebhookEvent {
                event_type: String::from_str(&env, "transaction_routed"),
                transaction_id: best.quote_id,
                timestamp: now,
                payload_hash: Bytes::new(&env),
            },
        );

        best
    }

    /// Return up to `max_results` quotes sorted by descending weighted composite score.
    /// Weights (scaled ×1000) must sum to 1000; panics with `InvalidWeights` otherwise.
    pub fn route_anchors(
        env: Env,
        fee_weight: u32,       // scaled ×1000, e.g. 333 = 0.333
        speed_weight: u32,
        reputation_weight: u32,
        max_results: u32,
        min_reputation: u32,
    ) -> Vec<Quote> {
        if fee_weight
            .checked_add(speed_weight)
            .and_then(|sum| sum.checked_add(reputation_weight))
            != Some(1000)
        {
            panic_with_error!(&env, ErrorCode::InvalidWeights);
        }

        let fw = fee_weight as f32 / 1000.0_f32;
        let sw = speed_weight as f32 / 1000.0_f32;
        let rw = reputation_weight as f32 / 1000.0_f32;
        let strategy = WeightedRoutingStrategy {
            fee_weight: fw,
            speed_weight: sw,
            reputation_weight: rw,
        };
        if !strategy.validate() {
            panic_with_error!(&env, ErrorCode::InvalidWeights);
        }

        let now = env.ledger().timestamp();
        let list_key = make_storage_key(&env, &[b"ANCHLIST"]);
        let anchors: Vec<Address> = env.storage().persistent()
            .get::<_, Vec<Address>>(&list_key)
            .unwrap_or_else(|| Vec::new(&env));

        // First pass: find max values for normalisation
        let mut max_fee: u32 = 0;
        let mut max_settlement: u64 = 0;
        let mut max_reputation: u32 = 0;

        for anchor in anchors.iter() {
            let meta: RoutingAnchorMeta = match anchor_meta_opt(&env, &anchor) {
                Some(m) if m.is_active && m.reputation_score >= min_reputation => m,
                _ => continue,
            };
            let anchor_xdr = anchor.clone().to_xdr(&env);
            let anchor_raw = xdr_to_vec(&anchor_xdr);
            let lq_key = make_storage_key(&env, &[b"LATESTQ", &anchor_raw]);
            let quote_id: u64 = match env.storage().persistent().get(&lq_key) {
                Some(id) => id,
                None => continue,
            };
            let q_key = make_storage_key(&env, &[b"QUOTE", &anchor_raw, &quote_id.to_be_bytes()]);
            let quote: Quote = match env.storage().persistent().get(&q_key) {
                Some(q) => q,
                None => continue,
            };
            if quote.valid_until <= now { continue; }
            if meta.average_settlement_time > max_settlement { max_settlement = meta.average_settlement_time; }
            if meta.reputation_score > max_reputation { max_reputation = meta.reputation_score; }
            if quote.fee_percentage > max_fee { max_fee = quote.fee_percentage; }
        }

        // Second pass: score into a native vec, then sort
        let mut scored: alloc::vec::Vec<(u32, Quote)> = alloc::vec::Vec::new();

        for anchor in anchors.iter() {
            let meta: RoutingAnchorMeta = match anchor_meta_opt(&env, &anchor) {
                Some(m) if m.is_active && m.reputation_score >= min_reputation => m,
                _ => continue,
            };
            let anchor_xdr = anchor.clone().to_xdr(&env);
            let anchor_raw = xdr_to_vec(&anchor_xdr);
            let lq_key = make_storage_key(&env, &[b"LATESTQ", &anchor_raw]);
            let quote_id: u64 = match env.storage().persistent().get(&lq_key) {
                Some(id) => id,
                None => continue,
            };
            let q_key = make_storage_key(&env, &[b"QUOTE", &anchor_raw, &quote_id.to_be_bytes()]);
            let quote: Quote = match env.storage().persistent().get(&q_key) {
                Some(q) => q,
                None => continue,
            };
            if quote.valid_until <= now { continue; }

            let score = strategy.score_anchor(
                quote.fee_percentage,
                meta.average_settlement_time,
                meta.reputation_score,
                max_fee,
                max_settlement,
                max_reputation,
            );
            scored.push(((score.clamp(0.0, 1.0) * 1_000_000.0_f32) as u32, quote));
        }

        // Sort descending by score
        scored.sort_unstable_by(|a, b| b.0.cmp(&a.0));

        // Return top max_results quotes as a Soroban Vec (issue #467: 0 means no limit)
        let limit = if max_results == 0 { u32::MAX } else { max_results };
        let mut result: Vec<Quote> = Vec::new(&env);
        for (_, quote) in scored.into_iter().take(limit as usize) {
            result.push_back(quote);
        }
        result
    }

    // -----------------------------------------------------------------------
    // Anchor Info Discovery
    // -----------------------------------------------------------------------

    /// Cache the anchor's stellar.toml data along with provenance information.
    ///
    /// # Arguments
    ///
    /// * `anchor` - The anchor whose metadata is being cached.
    /// * `toml_data` - Parsed stellar.toml payload.
    /// * `ttl_seconds` - How long (in seconds) the entry is considered fresh.
    ///   Pass `0` to use the contract-level `capabilities_ttl_seconds`.
    /// * `source_uri` - The URL from which `toml_data` was fetched. Pass an
    ///   empty string if the source is unknown or not applicable.
    pub fn fetch_anchor_info(
        env: Env,
        anchor: Address,
        toml_data: StellarToml,
        ttl_seconds: u64,
        source_uri: String,
    ) {
        anchor.require_auth();
        for asset in toml_data.currencies.iter() {
            validate_asset_info(&env, &asset);
        }
        let now = env.ledger().timestamp();
        let cfg = Self::get_cache_config_internal(&env);
        let ttl = Self::effective_ttl(ttl_seconds, cfg.capabilities_ttl_seconds);
        let cached = CachedToml {
            toml: toml_data,
            cached_at: now,
            ttl_seconds: ttl,
            source_uri,
            last_refreshed_at: now,
        };
        let key = (symbol_short!("TOMLCACHE"), anchor.clone());
        let ledger_ttl = if ttl as u32 > MIN_TEMP_TTL {
            ttl as u32
        } else {
            MIN_TEMP_TTL
        };
        env.storage().temporary().set(&key, &cached);
        env.storage()
            .temporary()
            .extend_ttl(&key, ledger_ttl, ledger_ttl);
    }

    pub fn get_anchor_toml(env: Env, anchor: Address) -> StellarToml {
        let key = (symbol_short!("TOMLCACHE"), anchor);
        let cached: CachedToml = env
            .storage()
            .temporary()
            .get(&key)
            .unwrap_or_else(|| panic_with_error!(&env, ErrorCode::CacheNotFound));
        let now = env.ledger().timestamp();
        if cached.cached_at + cached.ttl_seconds <= now {
            panic_with_error!(&env, ErrorCode::CacheExpired);
        }
        cached.toml
    }

    /// Return provenance metadata for the anchor's cached stellar.toml entry.
    ///
    /// Panics with `CacheNotFound` when no entry exists, or `CacheExpired`
    /// when the entry has passed its TTL. Callers should check freshness
    /// first, or use `try_get_anchor_toml_provenance` via the SDK client.
    pub fn get_anchor_toml_provenance(env: Env, anchor: Address) -> AnchorTomlProvenance {
        let key = (symbol_short!("TOMLCACHE"), anchor.clone());
        let cached: CachedToml = env
            .storage()
            .temporary()
            .get(&key)
            .unwrap_or_else(|| panic_with_error!(&env, ErrorCode::CacheNotFound));
        let now = env.ledger().timestamp();
        if cached.cached_at + cached.ttl_seconds <= now {
            panic_with_error!(&env, ErrorCode::CacheExpired);
        }
        let age_seconds = now.saturating_sub(cached.cached_at);
        AnchorTomlProvenance {
            anchor,
            source_uri: cached.source_uri,
            cached_at: cached.cached_at,
            last_refreshed_at: cached.last_refreshed_at,
            ttl_seconds: cached.ttl_seconds,
            age_seconds,
        }
    }

    pub fn refresh_anchor_info(env: Env, anchor: Address, toml_data: StellarToml, ttl_seconds: u64, source_uri: String) {
        anchor.require_auth();
        let key = (symbol_short!("TOMLCACHE"), anchor.clone());
        let had_cached_entry = env.storage().temporary().has(&key);
        Self::fetch_anchor_info(env.clone(), anchor.clone(), toml_data, ttl_seconds, source_uri);
        Self::record_refresh_diagnostic(
            &env,
            &anchor,
            String::from_str(&env, "anchor_info"),
            RefreshStatus::Success,
            had_cached_entry,
            String::from_str(&env, "anchor info cache refreshed successfully"),
        );
    }

    pub fn get_anchor_assets(env: Env, anchor: Address) -> Vec<String> {
        let toml = Self::get_anchor_toml_internal(&env, &anchor);
        let mut assets = Vec::new(&env);
        for asset in toml.currencies.iter() {
            assets.push_back(asset.code.clone());
        }
        assets
    }

    pub fn get_anchor_asset_info(
        env: Env,
        anchor: Address,
        asset_code: String,
    ) -> AssetInfo {
        let toml = Self::get_anchor_toml_internal(&env, &anchor);
        for asset in toml.currencies.iter() {
            if asset.code == asset_code {
                return asset;
            }
        }
        panic_with_error!(&env, ErrorCode::ValidationError);
    }

    pub fn get_anchor_deposit_limits(
        env: Env,
        anchor: Address,
        asset_code: String,
    ) -> (u64, u64) {
        let asset = Self::get_anchor_asset_info(env, anchor, asset_code);
        (asset.deposit_min_amount, asset.deposit_max_amount)
    }

    pub fn get_anchor_withdrawal_limits(
        env: Env,
        anchor: Address,
        asset_code: String,
    ) -> (u64, u64) {
        let asset = Self::get_anchor_asset_info(env, anchor, asset_code);
        (asset.withdrawal_min_amount, asset.withdrawal_max_amount)
    }

    pub fn get_anchor_deposit_fees(
        env: Env,
        anchor: Address,
        asset_code: String,
    ) -> (u64, u32) {
        let asset = Self::get_anchor_asset_info(env, anchor, asset_code);
        (asset.deposit_fee_fixed, asset.deposit_fee_percent)
    }

    pub fn get_anchor_withdrawal_fees(
        env: Env,
        anchor: Address,
        asset_code: String,
    ) -> (u64, u32) {
        let asset = Self::get_anchor_asset_info(env, anchor, asset_code);
        (asset.withdrawal_fee_fixed, asset.withdrawal_fee_percent)
    }

    pub fn anchor_supports_deposits(
        env: Env,
        anchor: Address,
        asset_code: String,
    ) -> bool {
        match Self::get_anchor_asset_info(env, anchor, asset_code) {
            asset => asset.deposit_enabled,
        }
    }

    pub fn anchor_supports_withdrawals(
        env: Env,
        anchor: Address,
        asset_code: String,
    ) -> bool {
        match Self::get_anchor_asset_info(env, anchor, asset_code) {
            asset => asset.withdrawal_enabled,
        }
    }

    /// Return `true` when the anchor's cached stellar.toml advertises a
    /// `DIRECT_PAYMENT_SERVER` endpoint (SEP-31).
    pub fn supports_sep31(env: Env, anchor: Address) -> bool {
        let key = (symbol_short!("TOMLCACHE"), anchor);
        if !env.storage().temporary().has(&key) {
            return false;
        }
        let cached: CachedToml = env.storage().temporary().get(&key).unwrap();
        let now = env.ledger().timestamp();
        if cached.cached_at + cached.ttl_seconds <= now {
            return false;
        }
        !cached.toml.direct_payment_server.is_empty()
    }

    // -----------------------------------------------------------------------
    // Transaction state
    // -----------------------------------------------------------------------

    /// Admin-only: configure the auto-eviction policy for the transaction state tracker.
    ///
    /// When `enabled` is `true`, `create_transaction_record` will proactively
    /// evict the oldest terminal transactions when storage budget is at Warning
    /// or Critical. `max_per_call` bounds the number of evictions per call.
    pub fn set_eviction_policy(env: Env, enabled: bool, max_per_call: u32) {
        Self::require_admin(&env);
        env.storage().instance().set(&symbol_short!("EVICTEN"), &enabled);
        env.storage().instance().set(&symbol_short!("EVICTMAX"), &max_per_call);
        env.storage().instance().extend_ttl(INSTANCE_TTL, INSTANCE_TTL);
    }

    pub fn create_transaction_record(
        env: Env,
        transaction_id: u64,
        initiator: Address,
    ) -> TransactionStateRecord {
        Self::create_transaction_record_internal(&env, transaction_id, initiator, None)
    }

    /// Create a transaction record with optional routing reason metadata (#298).
    ///
    /// Identical to [`create_transaction_record`] but attaches an optional
    /// `routing_reason` to the record so callers can store why a particular
    /// route or anchor was chosen. The reason persists through all subsequent
    /// state transitions and can be retrieved for auditing via
    /// [`get_transaction_record`].
    ///
    /// # Arguments
    ///
    /// * `routing_reason` – Human-readable code or description explaining why
    ///   this route was chosen (e.g. `"referral"`, `"lowest_fee"`). `None`
    ///   when no reason applies.
    pub fn create_txn_record_with_reason(
        env: Env,
        transaction_id: u64,
        initiator: Address,
        routing_reason: Option<String>,
    ) -> TransactionStateRecord {
        Self::create_transaction_record_internal(&env, transaction_id, initiator, routing_reason)
    }

    fn create_transaction_record_internal(
        env: &Env,
        transaction_id: u64,
        initiator: Address,
        routing_reason: Option<String>,
    ) -> TransactionStateRecord {
        // Apply eviction policy from storage before inserting a new record.
        let eviction_enabled: bool = env
            .storage()
            .instance()
            .get(&symbol_short!("EVICTEN"))
            .unwrap_or(false);
        if eviction_enabled {
            let max_per_call: u32 = env
                .storage()
                .instance()
                .get(&symbol_short!("EVICTMAX"))
                .unwrap_or(10u32);
            Self::run_auto_eviction(env, max_per_call);
        }

        let now = env.ledger().timestamp();
        let current_ledger = env.ledger().sequence();
        let mut history = soroban_sdk::Vec::new(env);
        history.push_back((TransactionState::Pending, now));
        let record = TransactionStateRecord {
            transaction_id,
            state: TransactionState::Pending,
            initiator,
            timestamp: now,
            last_updated: now,
            last_updated_ledger: current_ledger,
            error_message: None,
            state_history: history,
            recovery_metadata: OptRecovery::None,
            routing_reason,
        };
        let key = (symbol_short!("TXSTATE"), transaction_id);
        env.storage().persistent().set(&key, &record);
        env.storage().persistent().extend_ttl(&key, PERSISTENT_TTL, PERSISTENT_TTL);
        // Track in TXIDS list for summarize_transactions_by_status
        let ids_key = symbol_short!("TXIDS");
        let mut ids: soroban_sdk::Vec<u64> = env
            .storage().persistent().get(&ids_key)
            .unwrap_or_else(|| soroban_sdk::Vec::new(env));
        ids.push_back(transaction_id);
        env.storage().persistent().set(&ids_key, &ids);
        env.storage().persistent().extend_ttl(&ids_key, PERSISTENT_TTL, PERSISTENT_TTL);
        record
    }

    /// Evict the oldest terminal transactions from persistent storage.
    /// Called by `create_transaction_record_internal` when eviction is enabled.
    fn run_auto_eviction(env: &Env, max_per_call: u32) {
        let ids_key = symbol_short!("TXIDS");
        let ids: soroban_sdk::Vec<u64> = env
            .storage()
            .persistent()
            .get(&ids_key)
            .unwrap_or_else(|| soroban_sdk::Vec::new(env));

        let mut terminal: alloc::vec::Vec<(u64, u64)> = alloc::vec::Vec::new();
        for id in ids.iter() {
            let key = (symbol_short!("TXSTATE"), id);
            if let Some(rec) = env
                .storage()
                .persistent()
                .get::<_, TransactionStateRecord>(&key)
            {
                if rec.state.is_terminal() {
                    terminal.push((rec.timestamp, id));
                }
            }
        }
        terminal.sort_unstable_by_key(|&(ts, _)| ts);

        let limit = max_per_call as usize;
        let mut evicted_ids: alloc::vec::Vec<u64> = alloc::vec::Vec::new();
        for (_, id) in terminal.iter().take(limit) {
            let key = (symbol_short!("TXSTATE"), *id);
            env.storage().persistent().remove(&key);
            evicted_ids.push(*id);
        }
        if !evicted_ids.is_empty() {
            let mut live: soroban_sdk::Vec<u64> = soroban_sdk::Vec::new(env);
            for id in ids.iter() {
                if !evicted_ids.contains(&id) {
                    live.push_back(id);
                }
            }
            env.storage().persistent().set(&ids_key, &live);
            env.events().publish(
                (symbol_short!("EVICT"), symbol_short!("budget")),
                evicted_ids.len() as u32,
            );
        }
    }

    /// Advance a transaction from Pending to InProgress.
    pub fn start_transaction_record(env: Env, transaction_id: u64) -> TransactionStateRecord {
        Self::advance_transaction_state_internal(&env, transaction_id, TransactionState::InProgress, None)
    }

    /// Advance a transaction from InProgress to Completed.
    pub fn complete_transaction_record(env: Env, transaction_id: u64) -> TransactionStateRecord {
        Self::advance_transaction_state_internal(&env, transaction_id, TransactionState::Completed, None)
    }

    /// Advance a transaction to Failed with an error message.
    pub fn fail_transaction_record(env: Env, transaction_id: u64, error_message: String) -> TransactionStateRecord {
        Self::advance_transaction_state_internal(&env, transaction_id, TransactionState::Failed, Some(error_message))
    }

    /// Return the full state-transition history for a transaction record.
    ///
    /// Each entry is `(state, ledger_timestamp)` in chronological order.
    /// Panics with [`ErrorCode::AttestationNotFound`] if no record exists for
    /// `transaction_id`.
    pub fn get_txn_state_history(
        env: Env,
        transaction_id: u64,
    ) -> soroban_sdk::Vec<(TransactionState, u64)> {
        let key = (symbol_short!("TXSTATE"), transaction_id);
        let record: TransactionStateRecord = env
            .storage()
            .persistent()
            .get(&key)
            .unwrap_or_else(|| panic_with_error!(&env, ErrorCode::AttestationNotFound));
        record.state_history
    }

    fn advance_transaction_state_internal(
        env: &Env,
        transaction_id: u64,
        new_state: TransactionState,
        error_message: Option<String>,
    ) -> TransactionStateRecord {
        let key = (symbol_short!("TXSTATE"), transaction_id);
        let mut record: TransactionStateRecord = env
            .storage()
            .persistent()
            .get(&key)
            .unwrap_or_else(|| panic_with_error!(env, ErrorCode::TransactionNotFound));

        let from_state = record.state;
        if !from_state.is_valid_transition(new_state) {
            panic_with_error!(env, ErrorCode::IllegalTransition);
        }

        let now = env.ledger().timestamp();
        let current_ledger = env.ledger().sequence();
        record.state = new_state;
        record.last_updated = now;
        record.last_updated_ledger = current_ledger;
        record.error_message = error_message.clone();
        record.state_history.push_back((new_state, now));

        if new_state == TransactionState::Failed {
            let reason = error_message
                .unwrap_or_else(|| String::from_str(env, "unspecified failure"));
            record.recovery_metadata = OptRecovery::Some(
                crate::transaction_state_tracker::RecoveryMetadata {
                    failure_reason: reason,
                    last_updated_ledger: current_ledger,
                    failed_from_state: from_state,
                    retry_count: 0,
                },
            );
        }

        let ttl = if new_state.is_terminal() {
            518_400u32 // ~30 days terminal TTL (matches TXSTATE_TTL_TERMINAL)
        } else {
            PERSISTENT_TTL
        };
        env.storage().persistent().set(&key, &record);
        env.storage().persistent().extend_ttl(&key, ttl, ttl);
        record
    }

    // -----------------------------------------------------------------------
    // Rate limit configuration
    // -----------------------------------------------------------------------

    pub fn set_rate_limit_config(env: Env, max_submissions: u32, window_length: u32) {
        Self::require_admin(&env);
        let config = crate::rate_limiter::RateLimitConfig { max_submissions, window_length };
        let admin = Self::get_admin_internal(&env);
        RateLimiter::update_config(&env, &admin, &config)
            .unwrap_or_else(|_| panic_with_error!(&env, ErrorCode::ValidationError));
        AdminAuditLog::log_action(
            &env,
            &admin,
            "set_rate_limit_config",
            String::from_str(&env, "rate_limiter"),
            "",
            "updated",
        );
    }

    /// Set a per-role rate limit override (admin only).
    pub fn set_role_rate_limit(env: Env, role: Symbol, config: RateLimitConfig) {
        Self::require_admin(&env);
        RateLimiter::validate_config(&config)
            .unwrap_or_else(|_| panic_with_error!(&env, ErrorCode::ValidationError));
        RateLimiter::set_role_override(&env, role.clone(), config);
        let admin = Self::get_admin_internal(&env);
        AdminAuditLog::log_action(&env, &admin, "set_role_rate_limit", soroban_sdk::String::from_str(&env, "role"), "", "updated");
    }

    /// Get per-role rate limit override, or None if not set.
    pub fn get_role_rate_limit(env: Env, role: Symbol) -> Option<RateLimitConfig> {
        RateLimiter::get_role_override(&env, role)
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Validate that a session is neither expired nor closed.
    /// Panics with `SessionExpired` if `current_time > created_at + ttl`,
    /// or `SessionClosed` if `session.closed == true`.
    fn validate_session(env: &Env, session: &Session) {
        let ttl = if session.session_ttl_seconds == 0 {
            DEFAULT_SESSION_TTL
        } else {
            session.session_ttl_seconds
        };
        let now = env.ledger().timestamp();
        let expiry = session.created_at.saturating_add(ttl);
        if now > expiry {
            panic_with_error!(env, ErrorCode::SessionExpired);
        }
        if session.closed {
            panic_with_error!(env, ErrorCode::SessionClosed);
        }
    }

    fn enforce_rate_limit(env: &Env, attestor: &Address) {
        let role = [AdminRole::KycAdmin, AdminRole::AttestorAdmin, AdminRole::CacheAdmin]
            .iter()
            .find(|&&r| Self::has_role_internal(env, attestor, r))
            .map(|r| Symbol::new(env, Self::role_name(*r)));
        let config = RateLimiter::resolve_config(env, attestor, role);
        if RateLimiter::check_and_increment(env, attestor, &config).is_err() {
            panic_with_error!(env, ErrorCode::RateLimitExceeded);
        }
    }

    fn require_admin(env: &Env) {
        let admin: Address = env
            .storage()
            .instance()
            .get::<_, Address>(&admin_key(env))
            .unwrap_or_else(|| panic_with_error!(env, ErrorCode::NotInitialized));
        admin.require_auth();
    }

    /// Stable human-readable name for an [`AdminRole`], used in audit entries.
    fn role_name(role: AdminRole) -> &'static str {
        match role {
            AdminRole::KycAdmin => "KycAdmin",
            AdminRole::AttestorAdmin => "AttestorAdmin",
            AdminRole::CacheAdmin => "CacheAdmin",
        }
    }

    /// Returns `true` if `address` holds `role` OR is the primary admin.
    fn has_role_internal(env: &Env, address: &Address, role: AdminRole) -> bool {
        // Primary admin implicitly has every role.
        if let Some(admin) = env.storage().instance().get::<_, Address>(&admin_key(env)) {
            if *address == admin {
                return true;
            }
        }
        env.storage()
            .persistent()
            .get::<_, bool>(&role_key(env, role, address))
            .unwrap_or(false)
    }

    /// Require that `caller` is either the primary admin or holds `role`.
    ///
    /// Panics with `NotInitialized` if the contract has not been initialised,
    /// or with `Unauthorized` if the caller has neither admin status nor the
    /// required role.
    fn require_admin_or_role(env: &Env, caller: &Address, role: AdminRole) {
        if !Self::has_role_internal(env, caller, role) {
            panic_with_error!(env, ErrorCode::Unauthorized);
        }
        caller.require_auth();
    }

    /// Validate freshly-fetched anchor metadata before it is written to the
    /// SWR cache. Panics with `ValidationError` on any problem so the caller's
    /// last-known-good entry is preserved (no partial writes occur).
    ///
    /// Checks:
    /// - the embedded `metadata.anchor` matches the key `anchor`
    /// - `uptime_percentage` is within range (basis points, 0..=10000)
    fn validate_metadata(env: &Env, anchor: &Address, metadata: &AnchorMetadata) {
        if metadata.anchor != *anchor {
            panic_with_error!(env, ErrorCode::ValidationError);
        }
        if metadata.uptime_percentage > 10_000 {
            panic_with_error!(env, ErrorCode::ValidationError);
        }
    }

    /// Returns `true` if `code` is a service identifier recognised by the
    /// current [`SERVICE_CAPABILITY_VERSION`] (#239).
    fn is_known_service_code(code: u32) -> bool {
        code >= SERVICE_DEPOSITS && code <= MAX_KNOWN_SERVICE_CODE
    }

    /// Sort services in ascending order for deterministic storage.
    /// This ensures consistent behavior regardless of submission order.
    fn sort_services(_env: &Env, services: &mut Vec<u32>) {
        let mut native: alloc::vec::Vec<u32> = services.iter().collect();
        native.sort_unstable();
        for (i, val) in native.iter().enumerate() {
            services.set(i as u32, *val);
        }
    }

    /// Returns `true` iff `anchor` has configured services that include
    /// `SERVICE_QUOTES`. Used by routing (#238) to exclude anchors that do not
    /// advertise the quote service before scoring.
    fn advertises_quote_service(env: &Env, anchor: &Address) -> bool {
        let xdr = anchor.clone().to_xdr(env);
        let raw = xdr_to_vec(&xdr);
        env.storage()
            .persistent()
            .get::<_, AnchorServices>(&make_storage_key(env, &[b"SERVICES", &raw]))
            .map(|s| s.services.contains(&SERVICE_QUOTES))
            .unwrap_or(false)
    }

    fn check_attestor(env: &Env, attestor: &Address) {
        let xdr = attestor.clone().to_xdr(env);
        let raw = xdr_to_vec(&xdr);
        if !env
            .storage()
            .persistent()
            .has(&make_storage_key(env, &[b"ATTESTOR", &raw]))
        {
            panic_with_error!(env, ErrorCode::AttestorNotRegistered);
        }
    }

    // ------------------------------------------------------------------
    // Private &Env helpers — avoid env.clone() at internal call sites
    // ------------------------------------------------------------------

    fn get_version_internal(env: &Env) -> ContractVersion {
        env.storage()
            .instance()
            .get::<_, ContractVersion>(&Self::version_key(env))
            .unwrap_or(ContractVersion { major: 0, minor: 1, patch: 0, upgraded_at: 0 })
    }

    fn get_admin_internal(env: &Env) -> Address {
        env.storage()
            .instance()
            .get::<_, Address>(&admin_key(env))
            .unwrap_or_else(|| panic_with_error!(env, ErrorCode::NotInitialized))
    }

    fn get_capacity_config_internal(env: &Env) -> CapacityConfig {
        env.storage()
            .instance()
            .get::<_, CapacityConfig>(&Self::capacity_config_key(env))
            .unwrap_or_else(CapacityConfig::default_config)
    }

    fn get_attestor_count_internal(env: &Env) -> u64 {
        env.storage()
            .instance()
            .get::<_, u64>(&Self::attestor_count_key(env))
            .unwrap_or(0)
    }

    fn get_cache_count_internal(env: &Env) -> u64 {
        env.storage()
            .instance()
            .get::<_, u64>(&Self::cache_count_key(env))
            .unwrap_or(0)
    }

    fn get_cache_config_internal(env: &Env) -> CacheConfig {
        env.storage()
            .instance()
            .get::<_, CacheConfig>(&Self::cache_config_key(env))
            .unwrap_or_else(CacheConfig::default_config)
    }

    fn is_attestor_internal(env: &Env, attestor: &Address) -> bool {
        let xdr = attestor.clone().to_xdr(env);
        let raw = xdr_to_vec(&xdr);
        env.storage()
            .persistent()
            .get::<_, bool>(&make_storage_key(env, &[b"ATTESTOR", &raw]))
            .unwrap_or(false)
    }

    fn get_supported_services_internal(env: &Env, anchor: &Address) -> AnchorServices {
        let xdr = anchor.clone().to_xdr(env);
        let raw = xdr_to_vec(&xdr);
        env.storage()
            .persistent()
            .get::<_, AnchorServices>(&make_storage_key(env, &[b"SERVICES", &raw]))
            .unwrap_or_else(|| panic_with_error!(env, ErrorCode::ServicesNotConfigured))
    }

    fn get_kyc_status_internal(env: &Env, subject: &Address) -> KycStatus {
        let key = kyc_record_key(env, subject);
        if !env.storage().persistent().has(&key) {
            return KycStatus::NotSubmitted;
        }
        let record: KycRecord = env
            .storage()
            .persistent()
            .get(&key)
            .unwrap_or_else(|| panic_with_error!(env, ErrorCode::KycNotFound));
        if let Some(expiry) = record.expiry {
            if env.ledger().timestamp() > expiry {
                return KycStatus::Expired;
            }
        }
        match record.status {
            0 => KycStatus::NotSubmitted,
            1 => KycStatus::Pending,
            2 => KycStatus::Approved,
            3 => KycStatus::Rejected,
            4 => KycStatus::Expired,
            _ => KycStatus::NotSubmitted,
        }
    }

    fn is_anchor_blacklisted_internal(env: &Env, anchor: &Address) -> bool {
        let key = anchor_blacklist_key(env, anchor);
        env.storage()
            .persistent()
            .get::<_, AnchorBlacklistEntry>(&key)
            .is_some()
    }

    fn get_anchor_toml_internal(env: &Env, anchor: &Address) -> StellarToml {
        let key = (symbol_short!("TOMLCACHE"), anchor.clone());
        let cached: CachedToml = env
            .storage()
            .temporary()
            .get(&key)
            .unwrap_or_else(|| panic_with_error!(env, ErrorCode::CacheNotFound));
        let now = env.ledger().timestamp();
        if cached.cached_at + cached.ttl_seconds <= now {
            panic_with_error!(env, ErrorCode::CacheExpired);
        }
        cached.toml
    }

    fn soroban_string_to_rust_string(env: &Env, value: &String) -> RustString {
        let len = value.len() as usize;
        let mut buffer = RustVec::new();
        buffer.resize(len, 0u8);
        value.copy_into_slice(&mut buffer);
        RustString::from_utf8(buffer).unwrap_or_else(|_| {
            panic_with_error!(env, ErrorCode::InvalidEndpointFormat)
        })
    }

    fn verify_attestation_signature(env: &Env, issuer: &Address, payload_hash: &Bytes, signature: &Bytes) {
        let xdr = issuer.clone().to_xdr(env);
        let raw = xdr_to_vec(&xdr);
        let pk: BytesN<32> = env
            .storage()
            .persistent()
            .get(&make_storage_key(env, &[b"ATPUBKEY", &raw]))
            .unwrap_or_else(|| panic_with_error!(env, ErrorCode::UnauthorizedAttestor));
        if signature.len() != 64 {
            panic_with_error!(env, ErrorCode::UnauthorizedAttestor);
        }
        let signature_bytes: BytesN<64> = signature.clone().try_into().unwrap_or_else(|_| {
            panic_with_error!(env, ErrorCode::UnauthorizedAttestor)
        });
        env.crypto()
            .ed25519_verify(&pk, payload_hash, &signature_bytes);
    }

    fn check_timestamp(env: &Env, timestamp: u64) {
        if timestamp == 0 {
            panic_with_error!(env, ErrorCode::InvalidTimestamp);
        }
    }

    fn next_attestation_id(env: &Env) -> u64 {
        let inst = env.storage().instance();
        let ck = soroban_sdk::vec![env, symbol_short!("COUNTER")];
        let id: u64 = inst.get(&ck).unwrap_or(0u64);
        inst.set(&ck, &(id + 1));
        inst.extend_ttl(INSTANCE_TTL, INSTANCE_TTL);
        id
    }

    fn store_attestation(
        env: &Env,
        id: u64,
        issuer: Address,
        subject: Address,
        timestamp: u64,
        payload_hash: Bytes,
        signature: Bytes,
    ) {
        let attestation = Attestation {
            id,
            issuer,
            subject,
            timestamp,
            payload_hash,
            signature,
            schema_version: SCHEMA_V1,
        };
        let key = make_storage_key(env, &[b"ATTEST", &id.to_be_bytes()]);
        env.storage().persistent().set(&key, &attestation);
        env.storage().persistent().extend_ttl(&key, PERSISTENT_TTL, PERSISTENT_TTL);
    }

    fn store_span(
        env: &Env,
        request_id: &RequestId,
        operation: String,
        actor: Address,
        now: u64,
        status: String,
    ) {
        Self::store_span_with_parent(env, request_id, operation, actor, now, status, Bytes::new(env), 0);
    }

    fn store_span_with_parent(
        env: &Env,
        request_id: &RequestId,
        operation: String,
        actor: Address,
        now: u64,
        status: String,
        parent_request_id_bytes: Bytes,
        span_index: u32,
    ) {
        let span = TracingSpan {
            request_id: request_id.clone(),
            operation,
            actor,
            started_at: now,
            completed_at: now,
            status,
            parent_request_id_bytes,
            span_index,
        };
        let key = (symbol_short!("SPAN"), request_id.id.clone());
        env.storage().temporary().set(&key, &span);
        env.storage()
            .temporary()
            .extend_ttl(&key, SPAN_TTL, SPAN_TTL);
    }

    // -----------------------------------------------------------------------
    // Health check APIs (#268)
    // -----------------------------------------------------------------------

    /// Overall service health status.
    ///
    /// Returns `Healthy` when the contract is initialized and the rate limiter
    /// config is present. Returns `Degraded` when initialized but the rate
    /// limiter config is missing (default fallback in use). Returns
    /// `Unavailable` when the contract has not been initialized.
    pub fn get_health_status(env: Env) -> HealthStatus {
        if !env.storage().persistent().has(&initialized_key(&env)) {
            return HealthStatus::Unavailable;
        }
        let rl_key = make_storage_key(&env, &[b"RL_CONFIG"]);
        if env.storage().persistent().has(&rl_key) {
            HealthStatus::Healthy
        } else {
            HealthStatus::Degraded
        }
    }

    /// Metadata freshness report for a given anchor.
    ///
    /// Returns the cache state together with the age of the entry in seconds
    /// (zero when missing). Callers can use this to detect stale or expired
    /// metadata without triggering a panic.
    pub fn get_metadata_freshness(env: Env, anchor: Address) -> MetadataFreshnessReport {
        let key = (symbol_short!("METACACHE"), anchor.clone());
        match env.storage().temporary().get::<_, MetadataCache>(&key) {
            None => MetadataFreshnessReport {
                anchor,
                state: MetadataCacheState::Missing,
                age_seconds: 0,
                needs_refresh: false,
            },
            Some(entry) => {
                let now = env.ledger().timestamp();
                let age = now.saturating_sub(entry.cached_at);
                let state = if age <= entry.ttl_seconds {
                    MetadataCacheState::Fresh
                } else if age <= entry.ttl_seconds.saturating_add(entry.stale_ttl_seconds) {
                    MetadataCacheState::Stale
                } else {
                    MetadataCacheState::Expired
                };
                MetadataFreshnessReport {
                    anchor,
                    state,
                    age_seconds: age,
                    needs_refresh: entry.needs_refresh || state != MetadataCacheState::Fresh,
                }
            }
        }
    }

    /// Rate limiter health for a given attestor.
    ///
    /// Returns the current submission count, window start ledger, configured
    /// limits, and whether the attestor is currently throttled.
    pub fn get_rate_limiter_health(env: Env, attestor: Address) -> RateLimiterHealth {
        let config = RateLimiter::get_config(&env);
        let state = RateLimiter::get_state(&env, &attestor);
        let current_ledger = env.ledger().sequence();
        let window_expired = state.window_start_ledger.saturating_add(config.window_length) <= current_ledger;
        let effective_count = if window_expired { 0 } else { state.submission_count };
        RateLimiterHealth {
            attestor,
            submission_count: effective_count,
            max_submissions: config.max_submissions,
            window_length: config.window_length,
            window_start_ledger: state.window_start_ledger,
            is_throttled: !window_expired && effective_count >= config.max_submissions,
        }
    }

    /// Append `operation_name` to the `RequestContext` stored under `root_id_bytes`.
    /// Creates a minimal context if none exists yet (e.g. for the root operation itself).
    fn record_operation_in_context(env: &Env, root_id_bytes: &Bytes, operation_name: String) {
        let key = (symbol_short!("REQCTX"), root_id_bytes.clone());
        let now = env.ledger().timestamp();
        let mut ctx: RequestContext = env
            .storage()
            .temporary()
            .get(&key)
            .unwrap_or_else(|| RequestContext {
                root_request_id: RequestId {
                    id: root_id_bytes.clone(),
                    created_at: now,
                },
                operation_chain: Vec::new(env),
                created_at: now,
            });
        ctx.operation_chain.push_back(operation_name);
        env.storage().temporary().set(&key, &ctx);
        env.storage()
            .temporary()
            .extend_ttl(&key, SPAN_TTL, SPAN_TTL);
    }

    // -----------------------------------------------------------------------
    // Anchor health and service readiness (#348)
    // -----------------------------------------------------------------------

    /// Return a readiness snapshot for `anchor`, aggregating registration status
    /// and per-service availability. Does not mutate any contract state.
    pub fn get_anchor_readiness(env: Env, anchor: Address) -> AnchorReadinessReport {
        let now = env.ledger().timestamp();
        let is_registered = Self::is_attestor_internal(&env, &anchor);

        let xdr = anchor.clone().to_xdr(&env);
        let raw = xdr_to_vec(&xdr);
        let services_opt: Option<AnchorServices> = env
            .storage()
            .persistent()
            .get(&make_storage_key(&env, &[b"SERVICES", &raw]));

        let deposit_ready = services_opt
            .as_ref()
            .map(|s| s.services.contains(&SERVICE_DEPOSITS))
            .unwrap_or(false);
        let withdrawal_ready = services_opt
            .as_ref()
            .map(|s| s.services.contains(&SERVICE_WITHDRAWALS))
            .unwrap_or(false);
        let kyc_ready = services_opt
            .as_ref()
            .map(|s| s.services.contains(&SERVICE_KYC))
            .unwrap_or(false);

        let advertises_quotes = services_opt
            .as_ref()
            .map(|s| s.services.contains(&SERVICE_QUOTES))
            .unwrap_or(false);
        let quote_ready = if advertises_quotes {
            let lq_key = make_storage_key(&env, &[b"LATESTQ", &raw]);
            if let Some(quote_id) = env.storage().persistent().get::<_, u64>(&lq_key) {
                let q_key = make_storage_key(&env, &[b"QUOTE", &raw, &quote_id.to_be_bytes()]);
                env.storage()
                    .persistent()
                    .get::<_, Quote>(&q_key)
                    .map(|q| q.valid_until > now)
                    .unwrap_or(false)
            } else {
                false
            }
        } else {
            false
        };

        AnchorReadinessReport {
            anchor,
            is_registered,
            deposit_ready,
            withdrawal_ready,
            quote_ready,
            kyc_ready,
            checked_at: now,
        }
    }

    /// Return `true` when `anchor` has the deposit service configured.
    /// Does not require the anchor to hold an active quote.
    pub fn is_deposit_ready(env: Env, anchor: Address) -> bool {
        let xdr = anchor.clone().to_xdr(&env);
        let raw = xdr_to_vec(&xdr);
        env.storage()
            .persistent()
            .get::<_, AnchorServices>(&make_storage_key(&env, &[b"SERVICES", &raw]))
            .map(|s| s.services.contains(&SERVICE_DEPOSITS))
            .unwrap_or(false)
    }

    /// Return `true` when `anchor` advertises the quote service AND holds a
    /// currently valid (non-expired) quote on-chain.
    pub fn is_quote_ready(env: Env, anchor: Address) -> bool {
        let now = env.ledger().timestamp();
        let xdr = anchor.clone().to_xdr(&env);
        let raw = xdr_to_vec(&xdr);
        let advertises = env
            .storage()
            .persistent()
            .get::<_, AnchorServices>(&make_storage_key(&env, &[b"SERVICES", &raw]))
            .map(|s| s.services.contains(&SERVICE_QUOTES))
            .unwrap_or(false);
        if !advertises {
            return false;
        }
        let lq_key = make_storage_key(&env, &[b"LATESTQ", &raw]);
        if let Some(quote_id) = env.storage().persistent().get::<_, u64>(&lq_key) {
            let q_key = make_storage_key(&env, &[b"QUOTE", &raw, &quote_id.to_be_bytes()]);
            env.storage()
                .persistent()
                .get::<_, Quote>(&q_key)
                .map(|q| q.valid_until > now)
                .unwrap_or(false)
        } else {
            false
        }
    }

    // -----------------------------------------------------------------------
    // Batch transaction queries and summaries
    // -----------------------------------------------------------------------

    /// Return up to `limit` transaction records whose IDs fall in the inclusive
    /// range `[from_id, to_id]`, ordered by ID ascending.
    ///
    /// The batch size is capped at 100 to prevent unbounded on-chain iteration.
    /// This method reads directly from persistent storage and skips IDs that
    /// have expired (TTL elapsed).
    ///
    /// # Arguments
    ///
    /// * `from_id` - Inclusive lower bound of the transaction ID range.
    /// * `to_id`   - Inclusive upper bound of the transaction ID range.
    /// * `limit`   - Maximum records to return (capped at 100).
    ///
    /// # Returns
    ///
    /// A [`Vec`] of [`TransactionStateRecord`]s sorted by ID ascending.
    pub fn get_transactions_in_range(
        env: Env,
        from_id: u64,
        to_id: u64,
        limit: u32,
    ) -> Vec<TransactionStateRecord> {
        const MAX_BATCH: u32 = 100;
        let effective_limit = limit.min(MAX_BATCH);
        let mut results = Vec::new(&env);

        if from_id > to_id {
            return results;
        }

        let mut id = from_id;
        let mut count = 0u32;
        while id <= to_id && count < effective_limit {
            let key = (symbol_short!("TXSTATE"), id);
            if let Some(record) = env
                .storage()
                .persistent()
                .get::<_, TransactionStateRecord>(&key)
            {
                results.push_back(record);
                count += 1;
            }
            id += 1;
        }
        results
    }

    /// Return aggregated transaction counts grouped by current state.
    ///
    /// Reads the known-IDs list from persistent storage and counts each live
    /// record by its current [`TransactionState`]. Records whose TTL has
    /// elapsed are silently excluded from the totals.
    ///
    /// # Returns
    ///
    /// A [`TransactionStatusSummary`] with per-state counts and a `total_count`.
    pub fn summarize_transactions_by_status(env: Env) -> TransactionStatusSummary {
        use crate::transaction_state_tracker::TransactionState as TxState;

        let ids_key = symbol_short!("TXIDS");
        let ids: Vec<u64> = env
            .storage()
            .persistent()
            .get(&ids_key)
            .unwrap_or_else(|| Vec::new(&env));

        let mut pending_count: u64 = 0;
        let mut in_progress_count: u64 = 0;
        let mut completed_count: u64 = 0;
        let mut failed_count: u64 = 0;
        let mut total_count: u64 = 0;

        for id in ids.iter() {
            let key = (symbol_short!("TXSTATE"), id);
            if let Some(record) = env
                .storage()
                .persistent()
                .get::<_, TransactionStateRecord>(&key)
            {
                match record.state {
                    TxState::Pending    => pending_count += 1,
                    TxState::InProgress => in_progress_count += 1,
                    TxState::Completed  => completed_count += 1,
                    TxState::Failed     => failed_count += 1,
                }
                total_count += 1;
            }
        }

        TransactionStatusSummary {
            pending_count,
            in_progress_count,
            completed_count,
            failed_count,
            total_count,
        }
    }

    // -----------------------------------------------------------------------
    // Read-only diagnostics (#350)
    // -----------------------------------------------------------------------

    /// Return a rate-limiter snapshot for `attestor`. Does not consume a
    /// submission slot or modify any state.
    pub fn get_rate_limiter_diagnostics(env: Env, attestor: Address) -> RateLimiterDiagnostics {
        let config = RateLimiter::get_config(&env);
        let state = RateLimiter::get_state(&env, &attestor);
        let is_at_limit = state.submission_count >= config.max_submissions;
        RateLimiterDiagnostics {
            attestor,
            submission_count: state.submission_count,
            window_start_ledger: state.window_start_ledger,
            max_submissions: config.max_submissions,
            window_length: config.window_length,
            is_at_limit,
            checked_at: env.ledger().timestamp(),
        }
    }

    /// Return cache freshness information for `anchor`. Does not modify any
    /// cache entries.
    pub fn get_cache_diagnostics(env: Env, anchor: Address) -> CacheDiagnostics {
        let now = env.ledger().timestamp();
        let meta_key = (symbol_short!("METACACHE"), anchor.clone());
        let (metadata_cached, metadata_age_seconds, metadata_ttl_seconds) =
            if let Some(entry) = env
                .storage()
                .temporary()
                .get::<_, MetadataCache>(&meta_key)
            {
                let age = now.saturating_sub(entry.cached_at);
                (true, age, entry.ttl_seconds)
            } else {
                (false, 0u64, 0u64)
            };

        let cap_key = (symbol_short!("CAPCACHE"), anchor.clone());
        let (capabilities_cached, capabilities_age_seconds, capabilities_ttl_seconds) =
            if let Some(entry) = env
                .storage()
                .temporary()
                .get::<_, CapabilitiesCache>(&cap_key)
            {
                let age = now.saturating_sub(entry.cached_at);
                (true, age, entry.ttl_seconds)
            } else {
                (false, 0u64, 0u64)
            };

        CacheDiagnostics {
            anchor,
            metadata_cached,
            metadata_age_seconds,
            metadata_ttl_seconds,
            capabilities_cached,
            capabilities_age_seconds,
            capabilities_ttl_seconds,
            checked_at: now,
        }
    }

    /// Return session creation counters. Does not modify any session state.
    pub fn get_session_diagnostics(env: Env) -> SessionDiagnostics {
        let scnt_key = make_storage_key(&env, &[b"SCNT"]);
        let total_sessions_created: u64 = env
            .storage()
            .instance()
            .get(&scnt_key)
            .unwrap_or(0u64);
        SessionDiagnostics {
            total_sessions_created,
            checked_at: env.ledger().timestamp(),
        }
    }

    // -----------------------------------------------------------------------
    // Anchor health metrics
    // -----------------------------------------------------------------------

    /// Storage key for an anchor's health metric counters.
    fn health_metrics_key(env: &Env, anchor: &Address) -> BytesN<32> {
        let xdr = anchor.clone().to_xdr(env);
        let raw = xdr_to_vec(&xdr);
        make_storage_key(env, &[b"HLTHCNT", &raw])
    }

    /// Record a single endpoint health event for `anchor`.
    ///
    /// Pass `success = true` for a successful call (discovery, quote fetch,
    /// capability check) and `false` for a failure. Counters are accumulated
    /// persistently so uptime percentages survive across ledgers.
    ///
    /// Admin-only — callers that integrate AnchorKit into a monitoring loop
    /// should call this after every outbound anchor interaction.
    pub fn record_health_event(env: Env, anchor: Address, success: bool) {
        Self::require_admin(&env);
        anchor.require_auth();
        Self::check_attestor(&env, &anchor);
        let key = Self::health_metrics_key(&env, &anchor);
        let now = env.ledger().timestamp();

        let mut metrics: AnchorHealthMetrics = env
            .storage()
            .persistent()
            .get(&key)
            .unwrap_or(AnchorHealthMetrics {
                anchor: anchor.clone(),
                success_count: 0,
                failure_count: 0,
                total_calls: 0,
                uptime_bps: 0,
                last_event_at: 0,
            });

        if success {
            metrics.success_count += 1;
        } else {
            metrics.failure_count += 1;
        }
        metrics.total_calls = metrics.success_count + metrics.failure_count;
        metrics.uptime_bps = if metrics.total_calls == 0 {
            0
        } else {
            (metrics.success_count.saturating_mul(10_000) / metrics.total_calls) as u32
        };
        metrics.last_event_at = now;

        env.storage().persistent().set(&key, &metrics);
        env.storage()
            .persistent()
            .extend_ttl(&key, PERSISTENT_TTL, PERSISTENT_TTL);

        env.events().publish(
            (symbol_short!("health"), symbol_short!("event"), anchor),
            (success, metrics.uptime_bps),
        );
    }

    /// Return the accumulated health metrics for `anchor`.
    ///
    /// Returns a zeroed [`AnchorHealthMetrics`] when no events have been
    /// recorded yet (never panics).
    pub fn get_anchor_health(env: Env, anchor: Address) -> AnchorHealthMetrics {
        let key = Self::health_metrics_key(&env, &anchor);
        env.storage()
            .persistent()
            .get(&key)
            .unwrap_or(AnchorHealthMetrics {
                anchor: anchor.clone(),
                success_count: 0,
                failure_count: 0,
                total_calls: 0,
                uptime_bps: 0,
                last_event_at: 0,
            })
    }

    /// Reset all health counters for `anchor` to zero. Admin-only.
    ///
    /// Useful after a maintenance window or anchor migration where historical
    /// failure counts should not skew the new baseline.
    pub fn reset_anchor_health(env: Env, anchor: Address) {
        Self::require_admin(&env);
        let key = Self::health_metrics_key(&env, &anchor);
        let now = env.ledger().timestamp();
        let metrics = AnchorHealthMetrics {
            anchor: anchor.clone(),
            success_count: 0,
            failure_count: 0,
            total_calls: 0,
            uptime_bps: 0,
            last_event_at: now,
        };
        env.storage().persistent().set(&key, &metrics);
        env.storage()
            .persistent()
            .extend_ttl(&key, PERSISTENT_TTL, PERSISTENT_TTL);
    }

    // -----------------------------------------------------------------------
    // Proof-of-possession for anchor endpoints
    // -----------------------------------------------------------------------

    /// Storage key for an anchor's proof-of-possession record.
    fn pop_key(env: &Env, anchor: &Address) -> BytesN<32> {
        let xdr = anchor.clone().to_xdr(env);
        let raw = xdr_to_vec(&xdr);
        make_storage_key(env, &[b"ANCHPOP", &raw])
    }

    /// Register a proof-of-possession for `anchor`'s `endpoint`.
    ///
    /// The anchor computes `proof_hash = SHA-256(challenge_bytes || endpoint_bytes)`
    /// where `challenge_bytes` is a nonce the anchor controls (e.g. a value
    /// published in its `stellar.toml` under `ANCHOR_PROOF_CHALLENGE`).
    /// Storing the hash on-chain binds the anchor's Stellar identity to the
    /// endpoint URL without revealing the raw challenge.
    ///
    /// The anchor must authorize this call (`anchor.require_auth()`).
    ///
    /// # Errors
    ///
    /// Panics with [`ErrorCode::AttestorNotRegistered`] when `anchor` is not
    /// a registered attestor.
    /// Panics with [`ErrorCode::InvalidEndpointFormat`] when `endpoint` fails
    /// HTTPS domain validation.
   pub fn register_endpoint_proof(
    env: Env,
    anchor: Address,
    endpoint: String,
    proof_hash: BytesN<32>,
) {
    anchor.require_auth();
    Self::check_attestor(&env, &anchor);

    // Validate the endpoint URL before storing.
    let endpoint_str = Self::soroban_string_to_rust_string(&env, &endpoint);
    crate::validate_anchor_domain(&endpoint_str)
        .unwrap_or_else(|_| panic_with_error!(&env, ErrorCode::InvalidEndpointFormat));

    // SECURITY FIX (#420):
    // Ensure the proof is registered for the same endpoint configured
    // in the attestor profile via set_endpoint(), when an endpoint has
    // already been configured.
    let profile = Self::load_or_init_profile(&env, &anchor);

    if profile.endpoint.len() != 0 && profile.endpoint != endpoint {
        panic_with_error!(&env, ErrorCode::ValidationError);
    }

    let now = env.ledger().timestamp();
    let record = AnchorProofRecord {
        anchor: anchor.clone(),
        endpoint,
        proof_hash,
        registered_at: now,
        verified: false,
    };

    let key = Self::pop_key(&env, &anchor);
    env.storage().persistent().set(&key, &record);
    env.storage()
        .persistent()
        .extend_ttl(&key, PERSISTENT_TTL, PERSISTENT_TTL);

    env.events().publish(
        (symbol_short!("pop"), symbol_short!("register"), anchor),
        now,
    );
}

    /// Verify a proof-of-possession by comparing `proof_hash` against the
    /// stored record for `anchor`.
    ///
    /// Returns `true` and marks the record as `verified = true` when the
    /// supplied hash matches the stored one. Returns `false` on mismatch or
    /// when no proof has been registered.
    ///
    /// This is a pure verification call — it does **not** require admin auth
    /// so that off-chain monitors can call it freely.
    pub fn verify_endpoint_proof(
        env: Env,
        anchor: Address,
        proof_hash: BytesN<32>,
    ) -> bool {
        let key = Self::pop_key(&env, &anchor);
        let mut record: AnchorProofRecord = match env.storage().persistent().get(&key) {
            Some(r) => r,
            None => return false,
        };

        if record.proof_hash != proof_hash {
            env.events().publish(
                (symbol_short!("pop"), symbol_short!("failed"), anchor),
                env.ledger().timestamp(),
            );
            return false;
        }

        // Mark as verified and persist.
        record.verified = true;
        env.storage().persistent().set(&key, &record);
        env.storage()
            .persistent()
            .extend_ttl(&key, PERSISTENT_TTL, PERSISTENT_TTL);

        env.events().publish(
            (symbol_short!("pop"), symbol_short!("verified"), anchor),
            env.ledger().timestamp(),
        );
        true
    }

    /// Return the stored proof-of-possession record for `anchor`, or `None`
    /// when no proof has been registered.
    pub fn get_endpoint_proof(env: Env, anchor: Address) -> Option<AnchorProofRecord> {
        env.storage()
            .persistent()
            .get(&Self::pop_key(&env, &anchor))
    }

    /// Return an aggregated health snapshot for the contract's key subsystems.
    /// Does not modify any contract state.
    ///
    /// Key consistency (issue #489):
    ///   - COUNTER: written by `next_attestation_id` as `vec![env, symbol_short!("COUNTER")]`
    ///              and read here with the identical key — consistent.
    ///   - QCNT:    written by `submit_quote` via `make_storage_key(&env, &[b"QCNT"])`
    ///              and read here with the identical call — consistent.
    ///   - SCNT:    written by `create_session` via `make_storage_key(&env, &[b"SCNT"])`
    ///              and read here with the identical call — consistent.
    pub fn get_contract_diagnostics(env: Env) -> ContractDiagnostics {
        let now = env.ledger().timestamp();
        let is_initialized = env.storage().persistent().has(&initialized_key(&env));

        let ck = soroban_sdk::vec![&env, symbol_short!("COUNTER")];
        let total_attestations: u64 = env.storage().instance().get(&ck).unwrap_or(0u64);

        let qcnt_key = make_storage_key(&env, &[b"QCNT"]);
        let total_quotes: u64 = env.storage().instance().get(&qcnt_key).unwrap_or(0u64);

        let scnt_key = make_storage_key(&env, &[b"SCNT"]);
        let total_sessions: u64 = env.storage().instance().get(&scnt_key).unwrap_or(0u64);

        let config = RateLimiter::get_config(&env);

        ContractDiagnostics {
            is_initialized,
            total_attestations,
            total_quotes,
            total_sessions,
            rate_limit_max_submissions: config.max_submissions,
            rate_limit_window_length: config.window_length,
            checked_at: now,
        }
    }

    /// Retrieve current replay detection metrics.
    /// Returns aggregated statistics about detected replay attacks.
    pub fn get_replay_metrics(env: Env) -> ReplayMetrics {
        replay_detection::get_replay_metrics(&env)
    }

    /// Retrieve the attempt count for a specific request ID that was replayed.
    /// Returns 0 if no replay attempts have been recorded for this ID.
    pub fn get_replay_count_for_id(env: Env, request_id: Bytes) -> u64 {
        replay_detection::get_replay_count_for_id(&env, &request_id)
    }

    // -----------------------------------------------------------------------
    // SEP version & feature flag introspection (#353)
    // -----------------------------------------------------------------------

    /// Return the list of SEP version numbers explicitly supported by this contract.
    ///
    /// # Returns
    ///
    /// A [`Vec<u32>`] containing the SEP numbers: `[6, 10, 24, 31, 38]`.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use soroban_sdk::Env;
    /// use anchorkit::contract::{AnchorKitContract, SEP_6, SEP_10, SEP_24, SEP_38};
    ///
    /// let env = Env::default();
    /// let seps = AnchorKitContract::supported_seps(env);
    /// assert!(seps.contains(&SEP_6));
    /// ```
    pub fn supported_seps(env: Env) -> Vec<u32> {
        let mut v = Vec::new(&env);
        v.push_back(SEP_6);
        v.push_back(SEP_10);
        v.push_back(SEP_24);
        v.push_back(SEP_31);
        v.push_back(SEP_38);
        v
    }

    /// Return a [`SepFeatureFlags`] struct indicating which SEP capabilities
    /// this contract supports.
    ///
    /// # Returns
    ///
    /// A [`SepFeatureFlags`] with all current support flags set.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use soroban_sdk::Env;
    /// use anchorkit::contract::AnchorKitContract;
    ///
    /// let env = Env::default();
    /// let flags = AnchorKitContract::supported_sep_feature_flags(env);
    /// assert!(flags.sep10);
    /// ```
    pub fn supported_sep_feature_flags(env: Env) -> SepFeatureFlags {
        let _ = env;
        SepFeatureFlags {
            sep6: true,
            sep10: true,
            sep24: true,
            sep31: true,
            sep38: true,
        }
    }

    // -----------------------------------------------------------------------
    // Session quota management
    // -----------------------------------------------------------------------

    /// Set the global session operation quota policy.
    ///
    /// All sessions that do not have a per-session override will be governed by
    /// this policy. A `max_operations` value of `0` disables enforcement
    /// (unlimited operations).
    ///
    /// # Authorization
    ///
    /// Admin-only.
    ///
    /// # Arguments
    ///
    /// * `max_operations` - Maximum operations per session (`0` = unlimited).
    pub fn set_session_quota_policy(env: Env, max_operations: u64) {
        Self::require_admin(&env);
        let policy = SessionQuotaPolicy::with_limit(max_operations);
        SessionQuotaEnforcer::set_global_policy(&env, &policy);
        AdminAuditLog::log_change(
            &env,
            &Self::get_admin_internal(&env),
            "set_session_quota_policy",
            "global",
            "",
            &alloc::format!("{}", max_operations),
        );
        env.events().publish(
            (symbol_short!("sess_qt"), symbol_short!("policy")),
            max_operations,
        );
    }

    /// Return the global session quota policy currently in effect.
    pub fn get_session_quota_policy(env: Env) -> SessionQuotaPolicy {
        SessionQuotaEnforcer::get_global_policy(&env)
    }

    /// Override the session quota for a specific session.
    ///
    /// The per-session override takes precedence over the global policy for
    /// `session_id` only. Useful for granting trusted callers a higher limit
    /// without raising the global cap.
    ///
    /// # Authorization
    ///
    /// Admin-only.
    ///
    /// # Arguments
    ///
    /// * `session_id`     - Target session.
    /// * `max_operations` - Maximum operations for this session (`0` = unlimited).
    pub fn set_session_quota_override(env: Env, session_id: u64, max_operations: u64) {
        Self::require_admin(&env);
        let policy = SessionQuotaPolicy::with_limit(max_operations);
        SessionQuotaEnforcer::set_session_override(&env, session_id, &policy);
        AdminAuditLog::log_change(
            &env,
            &Self::get_admin_internal(&env),
            "set_session_quota_override",
            &alloc::format!("{}", session_id),
            "",
            &alloc::format!("{}", max_operations),
        );
        env.events().publish(
            (symbol_short!("sess_qt"), symbol_short!("override"), session_id),
            max_operations,
        );
    }

    /// Remove the per-session quota override for `session_id`, reverting to the
    /// global policy.
    ///
    /// # Authorization
    ///
    /// Admin-only.
    pub fn clear_session_quota_override(env: Env, session_id: u64) {
        Self::require_admin(&env);
        SessionQuotaEnforcer::clear_session_override(&env, session_id);
        AdminAuditLog::log_change(
            &env,
            &Self::get_admin_internal(&env),
            "clear_session_quota_override",
            &alloc::format!("{}", session_id),
            "",
            "",
        );
    }

    /// Reset the operation counter for `session_id` to zero.
    ///
    /// After a reset the session can accept up to its configured `max_operations`
    /// additional operations. Each reset is recorded in the quota state so callers
    /// can audit how many times a session has been freed.
    ///
    /// # Authorization
    ///
    /// Admin-only.
    ///
    /// # Errors
    ///
    /// Panics with [`ErrorCode::SessionNotFound`] when `session_id` does not exist.
    pub fn reset_session_quota(env: Env, session_id: u64) {
        Self::require_admin(&env);
        // Verify the session exists before touching quota state.
        let sess_key = make_storage_key(&env, &[b"SESS", &session_id.to_be_bytes()]);
        if !env.storage().persistent().has(&sess_key) {
            panic_with_error!(&env, ErrorCode::SessionNotFound);
        }
        SessionQuotaEnforcer::reset(&env, session_id);
        AdminAuditLog::log_change(
            &env,
            &Self::get_admin_internal(&env),
            "reset_session_quota",
            &alloc::format!("{}", session_id),
            "",
            "0",
        );
    }

    /// Return a snapshot of the quota state for `session_id`.
    ///
    /// Includes the effective policy, current operation count, remaining
    /// capacity, reset count, and exhaustion flag. Does not modify any state.
    ///
    /// # Errors
    ///
    /// Panics with [`ErrorCode::SessionNotFound`] when `session_id` does not exist.
    pub fn get_session_quota_state(env: Env, session_id: u64) -> SessionQuotaState {
        let sess_key = make_storage_key(&env, &[b"SESS", &session_id.to_be_bytes()]);
        if !env.storage().persistent().has(&sess_key) {
            panic_with_error!(&env, ErrorCode::SessionNotFound);
        }
        SessionQuotaEnforcer::get_state(&env, session_id)
    }
}