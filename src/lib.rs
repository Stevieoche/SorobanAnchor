//! # AnchorKit
//!
//! AnchorKit is a Soroban smart-contract library for building and interacting with
//! Stellar anchor services. It provides both an on-chain contract layer and an
//! off-chain service layer that normalises responses from anchors implementing the
//! [Stellar Ecosystem Proposals (SEPs)](https://github.com/stellar/stellar-protocol/tree/master/ecosystem).
//!
//! ## Architecture
//!
//! The library is split into two logical layers:
//!
//! ### On-chain contract layer (`contract` module)
//! The [`contract::AnchorKitContract`] Soroban contract manages:
//! - Attestor registration and revocation (with SEP-10 JWT verification)
//! - Attestation submission with replay protection and rate limiting
//! - Session-based multi-step operations with audit logging
//! - Quote routing across multiple anchors
//! - KYC / compliance record tracking
//! - Anchor metadata and capability caching
//! - Anchor discovery via `stellar.toml`
//!
//! ### Off-chain service layer (SEP modules)
//! Four thin normalisation modules translate raw anchor HTTP responses into
//! typed Rust structs so callers never have to parse raw JSON themselves:
//!
//! | Module | SEP | Purpose |
//! |--------|-----|---------|
//! | [`sep6`] | SEP-6 | Non-interactive deposit / withdrawal |
//! | [`sep24`] | SEP-24 | Interactive deposit / withdrawal |
//! | [`sep31`] | SEP-31 | Direct payment |
//! | [`sep38`] | SEP-38 | Anchor RFQ / firm quotes |
//!
//! ### Cross-cutting utilities
//! | Module | Purpose |
//! |--------|---------|
//! | `domain_validator` | HTTPS-only URL validation before any outbound request |
//! | `errors` | Unified [`AnchorKitError`] / [`ErrorCode`] type hierarchy |
//! | `rate_limiter` | Per-attestor sliding-window rate limiting |
//! | `retry` | Exponential-backoff retry for transient failures |
//! | `sep10_jwt` | EdDSA JWT verification (SEP-10 authentication) |
//! | `deterministic_hash` | Canonical SHA-256 hashing for attestation payloads |
//! | `transaction_state_tracker` | State-machine tracking for on-chain transactions |
//! | `response_validator` | Schema validation for anchor API responses |
//!
//! ## Quick-start example
//!
//! ```rust,no_run
//! use anchorkit::{
//!     validate_anchor_domain,
//!     sep6::{initiate_deposit, RawDepositResponse},
//!     sep24::{initiate_interactive_deposit, RawInteractiveDepositResponse},
//!     retry::{retry_with_backoff, RetryConfig},
//! };
//!
//! // 1. Validate the anchor domain before making any requests.
//! validate_anchor_domain("https://anchor.example.com").expect("invalid domain");
//!
//! // 2. Normalise a SEP-6 deposit response received from the anchor's HTTP API.
//! let raw = RawDepositResponse {
//!     transaction_id: "txn-001".into(),
//!     how: "Send to bank account 1234".into(),
//!     extra_info: None,
//!     min_amount: Some(10),
//!     max_amount: Some(10_000),
//!     fee_fixed: Some(1),
//!     status: Some("pending_external".into()),
//!     clawback_enabled: None,
//!     stellar_memo: None,
//!     stellar_memo_type: None,
//!     asset_code: None,
//! };
//! let deposit = initiate_deposit(raw).expect("invalid deposit response");
//! println!("Transaction ID: {}", deposit.transaction_id);
//!
//! // 3. Normalise a SEP-24 interactive deposit response.
//! let raw24 = RawInteractiveDepositResponse {
//!     url: "https://anchor.example.com/interactive/deposit".into(),
//!     id: "txn-002".into(),
//! };
//! let interactive = initiate_interactive_deposit(raw24).expect("invalid response");
//! println!("Redirect user to: {}", interactive.url);
//!
//! // 4. Wrap any fallible call with exponential-backoff retry.
//! let config = RetryConfig::default();
//! let mut js = anchorkit::retry::MockJitterSource::new(vec![0]);
//! let result = retry_with_backoff(
//!     &config,
//!     |_attempt| -> Result<&str, u32> { Ok("success") },
//!     |_err| false,
//!     |_ms| {},
//!     &mut js,
//! );
//! assert_eq!(result, Ok("success"));
//! ```
//!
//! ## Feature flags
//!
//! | Flag | Default | Build command | What it gates |
//! |------|---------|---------------|---------------|
//! | `std` | ✓ | `cargo build` | Filesystem config loader ([`load_runtime_config_file`]), `config` module |
//! | `wasm` | — | `cargo build --no-default-features --features wasm --target wasm32-unknown-unknown` | Excludes all HTTP/host modules; only on-chain contract code is compiled |
//! | `mock-only` | — | `cargo test --features mock-only` | Enables the [`mock`] module with pre-built response fixtures for testing without a live anchor |
//! | `stress-tests` | — | `cargo test --features stress-tests` | Enables the load-simulation integration test suite (excluded from normal CI) |
//!
//! ### Combining features
//!
//! ```text
//! # Native development (default)
//! cargo build
//!
//! # Soroban on-chain deployment (excludes all host-only modules)
//! cargo build --release --target wasm32-unknown-unknown --no-default-features --features wasm
//!
//! # Testing with mocks (no live anchor required)
//! cargo test --features mock-only
//!
//! # Full test suite including stress tests
//! cargo test --features std,mock-only,stress-tests
//! ```

#![no_std]
extern crate alloc;

// ── Core modules (all build variants) ────────────────────────────────────────
pub mod deterministic_hash;
mod domain_validator;
pub mod errors;
pub mod sep10_jwt;
pub mod rate_limiter;
pub mod retry;
pub mod replay_detection;
pub mod transaction_state_tracker;
pub mod contract;
#[cfg(not(feature = "wasm"))]
pub mod anchor_health;
pub mod service_management;
pub mod admin_audit_log;
pub mod cache_governance;
pub mod session_quota;
pub mod request_context;

// ── std-only modules (filesystem, runtime config) ─────────────────────────────
#[cfg(feature = "std")]
pub mod config;

// ── Host-only modules (HTTP, threading) ───────────────────────────────────────
// Excluded from `wasm` builds: on-chain Soroban contracts have no network access.
#[cfg(not(feature = "wasm"))]
mod response_validator;
#[cfg(not(feature = "wasm"))]
pub mod http_client;
#[cfg(not(feature = "wasm"))]
pub mod webhook;
#[cfg(not(feature = "wasm"))]
pub mod sep6;
#[cfg(not(feature = "wasm"))]
pub mod sep24;
#[cfg(not(feature = "wasm"))]
pub mod sep31;
#[cfg(not(feature = "wasm"))]
pub mod sep38;
#[cfg(not(feature = "wasm"))]
pub mod stellar_toml;
#[cfg(not(feature = "wasm"))]
pub mod streaming_monitor;

// ── Mock helpers (test / CI without live anchor) ──────────────────────────────
#[cfg(feature = "mock-only")]
pub mod mock;

// ── Core re-exports ───────────────────────────────────────────────────────────
pub use domain_validator::validate_anchor_domain;
pub use errors::{AnchorKitError, ErrorCode};
pub use errors::normalize_asset_code;
/// Backward-compatible alias. Prefer [`AnchorKitError`] for new code.
pub use errors::Error;
pub use rate_limiter::{RateLimiter, RateLimitConfig, RateLimitState};
pub use retry::{retry_with_backoff, is_retryable, RetryConfig, JitterSource, LedgerJitterSource, MockJitterSource};
pub use deterministic_hash::{compute_payload_hash, verify_payload_hash};
pub use contract::{AnchorKitContract, AnchorTomlProvenance, EndpointUpdated, CacheConfig};
pub use transaction_state_tracker::{TransactionState, TransactionStateRecord, RecoveryMetadata, OptRecovery};
pub use transaction_state_tracker::{StorageBudgetMonitor, TransactionStateTracker};
pub use transaction_state_tracker::TransactionSummary;

// ── std-only re-exports ───────────────────────────────────────────────────────
#[cfg(feature = "std")]
pub use config::{load_runtime_config_file, parse_runtime_config_str, ConfigFormat, RuntimeConfig};

// ── Host-only re-exports ──────────────────────────────────────────────────────
#[cfg(not(feature = "wasm"))]
pub use http_client::{ProxyConfig, build_client, fetch_stellar_toml_with_proxy, deliver_webhook_with_proxy};
#[cfg(not(feature = "wasm"))]
pub use response_validator::{
    validate_anchor_info_response, validate_deposit_response, validate_quote_response,
    validate_sep38_quote_response, validate_withdraw_response, validate_stellar_asset,
    validate_stellar_account_id, normalize_stellar_account_id,
    AnchorInfoResponse, DepositResponse as ValidatorDepositResponse, QuoteResponse,
    Sep38QuoteResponse, WithdrawResponse,
};
#[cfg(not(feature = "wasm"))]
pub use webhook::{deliver_webhook, get_dead_letter_webhooks, query_dlq, verify_webhook_signature, WebhookDeliveryConfig, DlqEntry};
#[cfg(not(feature = "wasm"))]
pub use stellar_toml::{ParsedCurrency, ParsedStellarToml, parse_stellar_toml, fetch_stellar_toml_url};
#[cfg(not(feature = "wasm"))]
pub use sep6::{
    fetch_transaction_status, initiate_deposit, initiate_withdrawal, DepositResponse,
    RawDepositResponse, RawTransactionResponse, RawWithdrawalResponse, TransactionKind,
    TransactionStatus, TransactionStatusResponse, WithdrawalResponse,
    poll_transaction_status, PollConfig, PollResult,
};
#[cfg(not(feature = "wasm"))]
pub use sep31::{
    initiate_sep31_payment, RawSep31PaymentResponse, Sep31PaymentResponse,
};
#[cfg(not(feature = "wasm"))]
pub use sep24::{
    initiate_interactive_deposit, initiate_interactive_deposit_with_origin,
    initiate_interactive_withdrawal, initiate_interactive_withdrawal_with_origin,
    fetch_sep24_transaction_status,
    validate_interactive_url, validate_transaction_id,
    InteractiveDepositResponse, InteractiveWithdrawalResponse, Sep24TransactionStatusResponse,
    RawInteractiveDepositResponse, RawInteractiveWithdrawalResponse, RawSep24TransactionResponse,
};
pub use contract::{ServiceRetirementInfo, AnchorServices};
pub use service_management::{ServiceManager, ServiceToggleState, ServiceConfigSnapshot};
pub use admin_audit_log::{AdminAuditLog, AdminConfigChangeEvent, AdminAuditLogConfig};
pub use contract::{HealthStatus, MetadataFreshnessReport, RateLimiterHealth};
pub use contract::{AnchorHealthMetrics, AnchorProofRecord};
pub use transaction_state_tracker::{BudgetStatus, BudgetAlert};
pub use session_quota::{SessionQuotaEnforcer, SessionQuotaPolicy, SessionQuotaState};
#[cfg(not(feature = "wasm"))]
pub use sep38::{CrossAnchorFeeAggregator, FeeAnomalyReport};
#[cfg(not(feature = "wasm"))]
pub use streaming_monitor::{StreamingTransactionMonitor, TransactionStatusUpdate};

#[cfg(all(test, not(feature = "wasm")))]
mod stellar_toml_tests;

