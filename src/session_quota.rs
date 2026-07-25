//! Per-session operation quota enforcement.
//!
//! This module provides configurable operation quotas for sessions so that
//! long-running or abusive flows cannot consume disproportionate resources.
//! Every session is limited to a maximum number of operations per configurable
//! policy; exceeding the limit immediately fails the call with
//! [`ErrorCode::SessionOperationLimitExceeded`].
//!
//! # Design
//!
//! - The **global quota policy** is stored in contract instance storage under
//!   the key `SESS_QUOTA`. Admins update it via the contract's
//!   `set_session_quota_policy` method.
//! - A **per-session override** (`SESS_QUOTA_<session_id>`) wins over the
//!   global policy for that specific session only. This lets admins grant
//!   elevated limits to high-trust callers without raising the global cap.
//! - `SessionQuotaEnforcer::check_and_increment` reads the effective quota,
//!   reads the current operation count stored under `SOPCNT_<session_id>`, and
//!   panics with `SessionOperationLimitExceeded` when the count has reached the
//!   limit. On success it increments and persists the counter atomically.
//! - `SessionQuotaEnforcer::reset` zeroes the operation counter for a session.
//!   This enables recovery flows where a quota-exceeded session should be
//!   allowed to continue after an admin action.
//!
//! # Quota reset
//!
//! After a quota reset the session can accept up to `max_operations` additional
//! operations. The reset is recorded so callers can audit how many times a
//! session has been freed.
//!
//! # Storage keys
//!
//! | Symbol             | Content                            |
//! |--------------------|------------------------------------|
//! | `SESS_QUOTA`       | Global `SessionQuotaPolicy`        |
//! | `(SESS_QUOTA, id)` | Per-session `SessionQuotaPolicy`   |
//! | `(SOPCNT, id)`     | `u64` — current op count           |
//! | `(SQRST, id)`      | `u32` — number of quota resets     |

use soroban_sdk::{contracttype, symbol_short, Env};
use crate::errors::ErrorCode;

// ---------------------------------------------------------------------------
// Policy type
// ---------------------------------------------------------------------------

/// Configurable quota policy for a session or as the global default.
///
/// `max_operations = 0` is treated as "unlimited" — the check is skipped.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionQuotaPolicy {
    /// Maximum number of operations permitted within the session.
    /// `0` means unlimited (no quota enforced).
    pub max_operations: u64,
    /// Ledger timestamp when this policy was last written.
    pub updated_at: u64,
}

impl SessionQuotaPolicy {
    /// Return the built-in default: 100 operations (mirrors `MAX_OPS_PER_SESSION`).
    pub fn default_policy() -> Self {
        SessionQuotaPolicy {
            max_operations: 100,
            updated_at: 0,
        }
    }

    /// Return a policy with an explicit limit and a zero timestamp.
    pub fn with_limit(max_operations: u64) -> Self {
        SessionQuotaPolicy {
            max_operations,
            updated_at: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Snapshot
// ---------------------------------------------------------------------------

/// Point-in-time view of a session's quota state.  Returned by
/// [`SessionQuotaEnforcer::get_state`] so callers can inspect without mutating.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionQuotaState {
    /// The session this snapshot belongs to.
    pub session_id: u64,
    /// Effective policy at the time of the query.
    pub policy: SessionQuotaPolicy,
    /// Operations consumed so far.
    pub operations_used: u64,
    /// Operations remaining (`max_operations - operations_used`).
    /// `u64::MAX` when the quota is unlimited.
    pub operations_remaining: u64,
    /// Number of times the quota counter has been reset.
    pub reset_count: u32,
    /// `true` when the session has reached its quota.
    pub is_exhausted: bool,
}

// ---------------------------------------------------------------------------
// Enforcer
// ---------------------------------------------------------------------------

/// Stateless helper that enforces per-session operation quotas.
///
/// All methods operate directly on Soroban storage — no instance state is kept.
pub struct SessionQuotaEnforcer;

impl SessionQuotaEnforcer {
    // -----------------------------------------------------------------------
    // Storage key builders
    // -----------------------------------------------------------------------

    /// Storage key for the global quota policy.
    fn global_policy_key() -> soroban_sdk::Symbol {
        symbol_short!("SESS_QT")
    }

    /// Storage key for a per-session quota policy override.
    fn session_policy_key(session_id: u64) -> (soroban_sdk::Symbol, u64) {
        (symbol_short!("SQ_OVR"), session_id)
    }

    /// Storage key for the operation counter of `session_id`.
    fn op_count_key(session_id: u64) -> (soroban_sdk::Symbol, u64) {
        (symbol_short!("SOPCNT"), session_id)
    }

    /// Storage key for the reset counter of `session_id`.
    fn reset_count_key(session_id: u64) -> (soroban_sdk::Symbol, u64) {
        (symbol_short!("SQRST"), session_id)
    }

    // -----------------------------------------------------------------------
    // Policy management
    // -----------------------------------------------------------------------

    /// Persist the global quota policy.  Admin callers must enforce access
    /// control before calling this.
    pub fn set_global_policy(env: &Env, policy: &SessionQuotaPolicy) {
        let mut p = policy.clone();
        p.updated_at = env.ledger().timestamp();
        env.storage()
            .instance()
            .set(&Self::global_policy_key(), &p);
        env.storage()
            .instance()
            .extend_ttl(518_400, 518_400);
    }

    /// Return the global quota policy, or the built-in default when none has
    /// been configured.
    pub fn get_global_policy(env: &Env) -> SessionQuotaPolicy {
        env.storage()
            .instance()
            .get::<_, SessionQuotaPolicy>(&Self::global_policy_key())
            .unwrap_or_else(SessionQuotaPolicy::default_policy)
    }

    /// Persist a per-session quota override for `session_id`.
    pub fn set_session_override(env: &Env, session_id: u64, policy: &SessionQuotaPolicy) {
        let mut p = policy.clone();
        p.updated_at = env.ledger().timestamp();
        let key = Self::session_policy_key(session_id);
        env.storage().persistent().set(&key, &p);
        env.storage()
            .persistent()
            .extend_ttl(&key, 1_555_200, 1_555_200);
    }

    /// Remove the per-session override for `session_id`, reverting to the
    /// global policy.
    pub fn clear_session_override(env: &Env, session_id: u64) {
        let key = Self::session_policy_key(session_id);
        if env.storage().persistent().has(&key) {
            env.storage().persistent().remove(&key);
        }
    }

    /// Return the per-session override for `session_id`, or `None` when no
    /// override has been configured.
    pub fn get_session_override(env: &Env, session_id: u64) -> Option<SessionQuotaPolicy> {
        env.storage()
            .persistent()
            .get::<_, SessionQuotaPolicy>(&Self::session_policy_key(session_id))
    }

    /// Resolve the effective policy for `session_id`.
    ///
    /// Resolution order: per-session override → global policy → built-in default.
    pub fn resolve_policy(env: &Env, session_id: u64) -> SessionQuotaPolicy {
        if let Some(override_policy) = Self::get_session_override(env, session_id) {
            return override_policy;
        }
        Self::get_global_policy(env)
    }

    // -----------------------------------------------------------------------
    // Enforcement
    // -----------------------------------------------------------------------

    /// Check that `session_id` has not reached its operation quota and
    /// atomically increment the counter.
    ///
    /// When `policy.max_operations == 0` the check is skipped (unlimited).
    ///
    /// # Panics
    ///
    /// Panics with [`ErrorCode::SessionOperationLimitExceeded`] when the
    /// session has reached its configured quota.
    pub fn check_and_increment(env: &Env, session_id: u64) {
        let policy = Self::resolve_policy(env, session_id);
        if policy.max_operations == 0 {
            // Unlimited — just bump the counter for observability.
            Self::increment_counter(env, session_id);
            return;
        }

        let key = Self::op_count_key(session_id);
        let current: u64 = env
            .storage()
            .persistent()
            .get::<_, u64>(&key)
            .unwrap_or(0u64);

        if current >= policy.max_operations {
            soroban_sdk::panic_with_error!(env, ErrorCode::SessionOperationLimitExceeded);
        }

        let new_count = current + 1;
        env.storage().persistent().set(&key, &new_count);
        env.storage()
            .persistent()
            .extend_ttl(&key, 1_555_200, 1_555_200);

        // Emit an observable event so off-chain monitors can track quota usage.
        env.events().publish(
            (
                symbol_short!("sess_qt"),
                symbol_short!("used"),
                session_id,
            ),
            (new_count, policy.max_operations),
        );
    }

    /// Return the current operation count for `session_id` without modifying
    /// any state.
    pub fn get_operation_count(env: &Env, session_id: u64) -> u64 {
        env.storage()
            .persistent()
            .get::<_, u64>(&Self::op_count_key(session_id))
            .unwrap_or(0u64)
    }

    /// Reset the operation counter for `session_id` to zero and increment the
    /// reset counter.  Admin callers must enforce access control before calling.
    ///
    /// This enables recovery flows where a quota-exceeded session should be
    /// allowed to continue.
    pub fn reset(env: &Env, session_id: u64) {
        // Zero the op counter.
        let op_key = Self::op_count_key(session_id);
        env.storage().persistent().set(&op_key, &0u64);
        env.storage()
            .persistent()
            .extend_ttl(&op_key, 1_555_200, 1_555_200);

        // Bump the reset counter so callers can audit how often this happened.
        let rst_key = Self::reset_count_key(session_id);
        let resets: u32 = env
            .storage()
            .persistent()
            .get::<_, u32>(&rst_key)
            .unwrap_or(0u32)
            .saturating_add(1);
        env.storage().persistent().set(&rst_key, &resets);
        env.storage()
            .persistent()
            .extend_ttl(&rst_key, 1_555_200, 1_555_200);

        env.events().publish(
            (
                symbol_short!("sess_qt"),
                symbol_short!("reset"),
                session_id,
            ),
            resets,
        );
    }

    /// Return a full snapshot of the quota state for `session_id`.
    pub fn get_state(env: &Env, session_id: u64) -> SessionQuotaState {
        let policy = Self::resolve_policy(env, session_id);
        let operations_used = Self::get_operation_count(env, session_id);
        let rst_key = Self::reset_count_key(session_id);
        let reset_count: u32 = env
            .storage()
            .persistent()
            .get::<_, u32>(&rst_key)
            .unwrap_or(0u32);

        let (operations_remaining, is_exhausted) = if policy.max_operations == 0 {
            (u64::MAX, false)
        } else {
            let remaining = policy.max_operations.saturating_sub(operations_used);
            (remaining, operations_used >= policy.max_operations)
        };

        SessionQuotaState {
            session_id,
            policy,
            operations_used,
            operations_remaining,
            reset_count,
            is_exhausted,
        }
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Increment the counter without checking the policy.
    fn increment_counter(env: &Env, session_id: u64) {
        let key = Self::op_count_key(session_id);
        let current: u64 = env
            .storage()
            .persistent()
            .get::<_, u64>(&key)
            .unwrap_or(0u64);
        env.storage().persistent().set(&key, &(current + 1));
        env.storage()
            .persistent()
            .extend_ttl(&key, 1_555_200, 1_555_200);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::{Ledger, LedgerInfo};
    use crate::contract::AnchorKitContract;

    fn make_env() -> (Env, soroban_sdk::Address) {
        let env = Env::default();
        env.mock_all_auths();
        env.ledger().set(LedgerInfo {
            timestamp: 2_000_000,
            protocol_version: 21,
            sequence_number: 200,
            network_id: Default::default(),
            base_reserve: 0,
            min_persistent_entry_ttl: 4096,
            min_temp_entry_ttl: 16,
            max_entry_ttl: 6_312_000,
        });
        let cid = env.register_contract(None, AnchorKitContract);
        (env, cid)
    }

    // -----------------------------------------------------------------------
    // Global policy
    // -----------------------------------------------------------------------

    #[test]
    fn test_default_global_policy() {
        let (env, cid) = make_env();
        let policy = env.as_contract(&cid, || SessionQuotaEnforcer::get_global_policy(&env));
        assert_eq!(policy.max_operations, 100);
    }

    #[test]
    fn test_set_and_get_global_policy() {
        let (env, cid) = make_env();
        let new_policy = SessionQuotaPolicy::with_limit(50);
        env.as_contract(&cid, || {
            SessionQuotaEnforcer::set_global_policy(&env, &new_policy);
        });
        let read_back = env.as_contract(&cid, || SessionQuotaEnforcer::get_global_policy(&env));
        assert_eq!(read_back.max_operations, 50);
    }

    // -----------------------------------------------------------------------
    // Per-session override
    // -----------------------------------------------------------------------

    #[test]
    fn test_session_override_wins_over_global() {
        let (env, cid) = make_env();
        let session_id = 42u64;

        env.as_contract(&cid, || {
            SessionQuotaEnforcer::set_global_policy(&env, &SessionQuotaPolicy::with_limit(20));
            SessionQuotaEnforcer::set_session_override(
                &env,
                session_id,
                &SessionQuotaPolicy::with_limit(5),
            );
        });

        let effective = env.as_contract(&cid, || {
            SessionQuotaEnforcer::resolve_policy(&env, session_id)
        });
        assert_eq!(effective.max_operations, 5);
    }

    #[test]
    fn test_clear_override_reverts_to_global() {
        let (env, cid) = make_env();
        let session_id = 7u64;

        env.as_contract(&cid, || {
            SessionQuotaEnforcer::set_global_policy(&env, &SessionQuotaPolicy::with_limit(30));
            SessionQuotaEnforcer::set_session_override(
                &env,
                session_id,
                &SessionQuotaPolicy::with_limit(3),
            );
            SessionQuotaEnforcer::clear_session_override(&env, session_id);
        });

        let effective = env.as_contract(&cid, || {
            SessionQuotaEnforcer::resolve_policy(&env, session_id)
        });
        assert_eq!(effective.max_operations, 30);
    }

    // -----------------------------------------------------------------------
    // check_and_increment — normal operation
    // -----------------------------------------------------------------------

    #[test]
    fn test_normal_operations_succeed_up_to_limit() {
        let (env, cid) = make_env();
        let session_id = 1u64;

        env.as_contract(&cid, || {
            SessionQuotaEnforcer::set_global_policy(&env, &SessionQuotaPolicy::with_limit(3));
            // First three ops succeed.
            SessionQuotaEnforcer::check_and_increment(&env, session_id);
            SessionQuotaEnforcer::check_and_increment(&env, session_id);
            SessionQuotaEnforcer::check_and_increment(&env, session_id);
        });

        let count = env.as_contract(&cid, || {
            SessionQuotaEnforcer::get_operation_count(&env, session_id)
        });
        assert_eq!(count, 3);
    }

    // -----------------------------------------------------------------------
    // check_and_increment — limit exceeded
    // -----------------------------------------------------------------------

    #[test]
    #[should_panic]
    fn test_exceeding_limit_panics() {
        let (env, cid) = make_env();
        let session_id = 2u64;

        env.as_contract(&cid, || {
            SessionQuotaEnforcer::set_global_policy(&env, &SessionQuotaPolicy::with_limit(2));
            SessionQuotaEnforcer::check_and_increment(&env, session_id);
            SessionQuotaEnforcer::check_and_increment(&env, session_id);
            // Third call must panic.
            SessionQuotaEnforcer::check_and_increment(&env, session_id);
        });
    }

    // -----------------------------------------------------------------------
    // check_and_increment — unlimited (max_operations == 0)
    // -----------------------------------------------------------------------

    #[test]
    fn test_unlimited_policy_never_panics() {
        let (env, cid) = make_env();
        let session_id = 3u64;

        env.as_contract(&cid, || {
            SessionQuotaEnforcer::set_global_policy(&env, &SessionQuotaPolicy::with_limit(0));
            // Call many times — must not panic.
            for _ in 0..200 {
                SessionQuotaEnforcer::check_and_increment(&env, session_id);
            }
        });

        let count = env.as_contract(&cid, || {
            SessionQuotaEnforcer::get_operation_count(&env, session_id)
        });
        assert_eq!(count, 200);
    }

    // -----------------------------------------------------------------------
    // reset — recovery after limit exceeded
    // -----------------------------------------------------------------------

    #[test]
    fn test_reset_allows_operations_to_resume() {
        let (env, cid) = make_env();
        let session_id = 4u64;

        // Fill to the limit.
        env.as_contract(&cid, || {
            SessionQuotaEnforcer::set_global_policy(&env, &SessionQuotaPolicy::with_limit(2));
            SessionQuotaEnforcer::check_and_increment(&env, session_id);
            SessionQuotaEnforcer::check_and_increment(&env, session_id);
        });

        // Reset.
        env.as_contract(&cid, || {
            SessionQuotaEnforcer::reset(&env, session_id);
        });

        // Should succeed again after reset.
        env.as_contract(&cid, || {
            SessionQuotaEnforcer::check_and_increment(&env, session_id);
        });

        let count = env.as_contract(&cid, || {
            SessionQuotaEnforcer::get_operation_count(&env, session_id)
        });
        assert_eq!(count, 1);
    }

    #[test]
    fn test_reset_counter_increments() {
        let (env, cid) = make_env();
        let session_id = 5u64;

        env.as_contract(&cid, || {
            SessionQuotaEnforcer::reset(&env, session_id);
            SessionQuotaEnforcer::reset(&env, session_id);
        });

        let state = env.as_contract(&cid, || SessionQuotaEnforcer::get_state(&env, session_id));
        assert_eq!(state.reset_count, 2);
    }

    // -----------------------------------------------------------------------
    // get_state snapshot
    // -----------------------------------------------------------------------

    #[test]
    fn test_get_state_reflects_current_usage() {
        let (env, cid) = make_env();
        let session_id = 6u64;

        env.as_contract(&cid, || {
            SessionQuotaEnforcer::set_global_policy(&env, &SessionQuotaPolicy::with_limit(10));
            SessionQuotaEnforcer::check_and_increment(&env, session_id);
            SessionQuotaEnforcer::check_and_increment(&env, session_id);
            SessionQuotaEnforcer::check_and_increment(&env, session_id);
        });

        let state = env.as_contract(&cid, || SessionQuotaEnforcer::get_state(&env, session_id));
        assert_eq!(state.operations_used, 3);
        assert_eq!(state.operations_remaining, 7);
        assert!(!state.is_exhausted);
    }

    #[test]
    fn test_get_state_shows_exhausted_when_at_limit() {
        let (env, cid) = make_env();
        let session_id = 8u64;

        env.as_contract(&cid, || {
            SessionQuotaEnforcer::set_global_policy(&env, &SessionQuotaPolicy::with_limit(2));
            SessionQuotaEnforcer::check_and_increment(&env, session_id);
            SessionQuotaEnforcer::check_and_increment(&env, session_id);
        });

        let state = env.as_contract(&cid, || SessionQuotaEnforcer::get_state(&env, session_id));
        assert!(state.is_exhausted);
        assert_eq!(state.operations_remaining, 0);
    }

    #[test]
    fn test_get_state_unlimited_shows_max_remaining() {
        let (env, cid) = make_env();
        let session_id = 9u64;

        env.as_contract(&cid, || {
            SessionQuotaEnforcer::set_global_policy(&env, &SessionQuotaPolicy::with_limit(0));
            SessionQuotaEnforcer::check_and_increment(&env, session_id);
        });

        let state = env.as_contract(&cid, || SessionQuotaEnforcer::get_state(&env, session_id));
        assert_eq!(state.operations_remaining, u64::MAX);
        assert!(!state.is_exhausted);
    }

    // -----------------------------------------------------------------------
    // Per-session override enforced at check_and_increment level
    // -----------------------------------------------------------------------

    #[test]
    #[should_panic]
    fn test_session_override_limit_enforced() {
        let (env, cid) = make_env();
        let session_id = 10u64;

        env.as_contract(&cid, || {
            // Global is generous (100).
            SessionQuotaEnforcer::set_global_policy(&env, &SessionQuotaPolicy::with_limit(100));
            // Per-session override is tight (1).
            SessionQuotaEnforcer::set_session_override(
                &env,
                session_id,
                &SessionQuotaPolicy::with_limit(1),
            );
            SessionQuotaEnforcer::check_and_increment(&env, session_id);
            // Second call must panic.
            SessionQuotaEnforcer::check_and_increment(&env, session_id);
        });
    }
}
