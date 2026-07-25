//! Explicit request-context propagation helpers.
//!
//! This module provides lightweight utilities for **correlating logs, events,
//! and state transitions** across the contract, host modules, and webhook
//! delivery.  All helpers are intentionally thin so that the overhead per
//! call is bounded and the storage layout stays stable.
//!
//! # Why this module exists
//!
//! The contract already stores [`RequestContext`] and [`TracingSpan`] values in
//! temporary Soroban storage, and emits Soroban events that can be indexed
//! off-chain.  However, the original code scattered the propagation logic
//! across multiple `impl` blocks in `contract.rs`, making it hard to reason
//! about which storage keys are involved and whether every operation correctly
//! threads its trace identifier through.
//!
//! This module consolidates the *off-chain* (host-side, `no_std`-incompatible)
//! propagation primitives that webhook delivery and streaming monitors need.
//! The on-chain portion remains in `contract.rs`; this module adds:
//!
//! - [`TraceMetadata`] — a compact, heap-allocated struct that carries a root
//!   request ID string and an optional parent span ID through off-chain call
//!   chains (webhook delivery, SEP-6/24/31/38 calls, health events).
//! - [`ContextHeader`] — converts `TraceMetadata` to/from HTTP header pairs
//!   so that trace IDs flow through outbound anchor HTTP calls.
//! - Helpers for embedding trace metadata in webhook payloads and DLQ entries.
//!
//! # Thread safety
//!
//! All types are `Send + Sync` because they only contain owned `String` values
//! and primitive integers.

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::vec;

// ---------------------------------------------------------------------------
// TraceMetadata — compact off-chain context carrier
// ---------------------------------------------------------------------------

/// Compact trace-context carrier used in off-chain (host-side) call chains.
///
/// Attach one of these to every off-chain operation that originates from, or
/// is triggered by, an on-chain request so that logs from webhook delivery,
/// SEP interactions, and streaming monitors can be correlated with the
/// originating on-chain request.
///
/// # Example
///
/// ```rust
/// use anchorkit::request_context::TraceMetadata;
///
/// // Create at the top of an operation (e.g. when processing a deposit event).
/// let meta = TraceMetadata::new("req-abc-123".to_string());
///
/// // Propagate into a child operation.
/// let child = meta.child("webhook-deliver");
/// assert_eq!(child.root_request_id, "req-abc-123");
/// assert_eq!(child.operation, "webhook-deliver");
/// assert_eq!(child.parent_request_id.as_deref(), Some("req-abc-123"));
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TraceMetadata {
    /// Stable root request ID that originated this trace chain.
    /// Typically the hex string of the on-chain `RequestId.id` bytes.
    pub root_request_id: String,
    /// Name of the current operation (e.g. `"deliver_webhook"`, `"submit_attestation"`).
    pub operation: String,
    /// Optional parent request ID when this is a child span.
    pub parent_request_id: Option<String>,
    /// Zero-based depth of this span within the trace tree.
    pub depth: u32,
}

impl TraceMetadata {
    /// Create a root-level trace context for `root_request_id`.
    ///
    /// `operation` is set to `"root"` and `parent_request_id` is `None`.
    pub fn new(root_request_id: String) -> Self {
        TraceMetadata {
            root_request_id,
            operation: "root".to_string(),
            parent_request_id: None,
            depth: 0,
        }
    }

    /// Create a root trace with an explicit operation name.
    pub fn with_operation(root_request_id: String, operation: &str) -> Self {
        TraceMetadata {
            root_request_id,
            operation: operation.to_string(),
            parent_request_id: None,
            depth: 0,
        }
    }

    /// Derive a child `TraceMetadata` for a sub-operation.
    ///
    /// The `root_request_id` is inherited from `self`; `parent_request_id` is
    /// set to the current `root_request_id`; and `depth` is incremented by 1.
    pub fn child(&self, operation: &str) -> Self {
        TraceMetadata {
            root_request_id: self.root_request_id.clone(),
            operation: operation.to_string(),
            parent_request_id: Some(self.root_request_id.clone()),
            depth: self.depth.saturating_add(1),
        }
    }

    /// Return `true` when this is a root span (no parent).
    pub fn is_root(&self) -> bool {
        self.parent_request_id.is_none()
    }

    /// Format this context as a log-prefix string.
    ///
    /// Suitable for prepending to log lines so every entry in a log file can be
    /// searched by request ID.
    ///
    /// # Output format
    ///
    /// ```text
    /// [trace req-abc-123 op=deliver_webhook depth=1]
    /// ```
    pub fn log_prefix(&self) -> String {
        alloc::format!(
            "[trace {} op={} depth={}]",
            self.root_request_id,
            self.operation,
            self.depth
        )
    }
}

// ---------------------------------------------------------------------------
// ContextHeader — HTTP header bridge
// ---------------------------------------------------------------------------

/// A pair of HTTP header name and value for propagating trace context through
/// outbound anchor API calls.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContextHeader {
    pub name: String,
    pub value: String,
}

/// Standard HTTP header names used for trace propagation.
pub const HEADER_TRACE_ID: &str = "X-Anchor-Trace-Id";
pub const HEADER_PARENT_SPAN: &str = "X-Anchor-Parent-Span";
pub const HEADER_OPERATION: &str = "X-Anchor-Operation";

/// Convert [`TraceMetadata`] into a `Vec` of [`ContextHeader`]s suitable for
/// inclusion in outbound HTTP requests.
///
/// # Headers emitted
///
/// | Header name              | Content                          |
/// |--------------------------|----------------------------------|
/// | `X-Anchor-Trace-Id`      | `root_request_id`                |
/// | `X-Anchor-Parent-Span`   | `parent_request_id` (if present) |
/// | `X-Anchor-Operation`     | `operation`                      |
pub fn trace_to_headers(meta: &TraceMetadata) -> Vec<ContextHeader> {
    let mut headers = Vec::new();
    headers.push(ContextHeader {
        name: HEADER_TRACE_ID.to_string(),
        value: meta.root_request_id.clone(),
    });
    headers.push(ContextHeader {
        name: HEADER_OPERATION.to_string(),
        value: meta.operation.clone(),
    });
    if let Some(parent) = &meta.parent_request_id {
        headers.push(ContextHeader {
            name: HEADER_PARENT_SPAN.to_string(),
            value: parent.clone(),
        });
    }
    headers
}

/// Reconstruct a [`TraceMetadata`] from HTTP response / request headers.
///
/// Returns `None` when the required `X-Anchor-Trace-Id` header is absent.
pub fn headers_to_trace(headers: &[ContextHeader]) -> Option<TraceMetadata> {
    let root = headers
        .iter()
        .find(|h| h.name == HEADER_TRACE_ID)?
        .value
        .clone();

    let operation = headers
        .iter()
        .find(|h| h.name == HEADER_OPERATION)
        .map(|h| h.value.clone())
        .unwrap_or_else(|| "unknown".to_string());

    let parent = headers
        .iter()
        .find(|h| h.name == HEADER_PARENT_SPAN)
        .map(|h| h.value.clone());

    Some(TraceMetadata {
        root_request_id: root,
        operation,
        parent_request_id: parent,
        depth: 0,
    })
}

// ---------------------------------------------------------------------------
// Webhook context helpers
// ---------------------------------------------------------------------------

/// Enrich a webhook payload string by prepending trace metadata as a JSON-
/// comment-style header comment.
///
/// The prefix is structured so that webhook consumers can strip it or parse it:
///
/// ```text
/// [anchor-trace id=<root_request_id> op=<operation>]
/// <original payload>
/// ```
///
/// This preserves backward compatibility with consumers that only look at the
/// body after the first newline while still embedding trace context for
/// consumers that do parse it.
pub fn enrich_webhook_payload(payload: &str, meta: &TraceMetadata) -> String {
    alloc::format!(
        "[anchor-trace id={} op={} depth={}]\n{}",
        meta.root_request_id,
        meta.operation,
        meta.depth,
        payload
    )
}

/// Extract the `TraceMetadata` embedded in a payload by
/// [`enrich_webhook_payload`].
///
/// Returns `None` when the payload does not start with the expected prefix.
pub fn extract_trace_from_payload(payload: &str) -> Option<TraceMetadata> {
    let first_line = payload.lines().next()?;
    if !first_line.starts_with("[anchor-trace ") {
        return None;
    }
    let inner = first_line
        .trim_start_matches("[anchor-trace ")
        .trim_end_matches(']');

    let mut root_request_id = String::new();
    let mut operation = "unknown".to_string();
    let mut depth = 0u32;

    for part in inner.split_whitespace() {
        if let Some(v) = part.strip_prefix("id=") {
            root_request_id = v.to_string();
        } else if let Some(v) = part.strip_prefix("op=") {
            operation = v.to_string();
        } else if let Some(v) = part.strip_prefix("depth=") {
            depth = v.parse().unwrap_or(0);
        }
    }

    if root_request_id.is_empty() {
        return None;
    }

    Some(TraceMetadata {
        root_request_id,
        operation,
        parent_request_id: None,
        depth,
    })
}

// ---------------------------------------------------------------------------
// AuditEntry — context-enriched audit record for off-chain consumers
// ---------------------------------------------------------------------------

/// A structured audit record that carries full trace context alongside the
/// operation details.  Off-chain indexers should store these records and expose
/// them for debugging.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditEntry {
    /// Trace context linking this entry to its originating request.
    pub trace: TraceMetadata,
    /// Session ID (`None` for operations outside a session).
    pub session_id: Option<u64>,
    /// Actor (Stellar account ID string).
    pub actor: String,
    /// Name of the operation (e.g. `"submit_attestation"`, `"approve_kyc"`).
    pub operation: String,
    /// Unix timestamp in seconds.
    pub timestamp: u64,
    /// Status string: `"success"` or `"failed"`.
    pub status: String,
    /// Optional error detail when `status == "failed"`.
    pub error: Option<String>,
}

impl AuditEntry {
    /// Create a successful audit entry with trace metadata.
    pub fn success(
        trace: TraceMetadata,
        session_id: Option<u64>,
        actor: String,
        operation: String,
        timestamp: u64,
    ) -> Self {
        AuditEntry {
            trace,
            session_id,
            actor,
            operation,
            timestamp,
            status: "success".to_string(),
            error: None,
        }
    }

    /// Create a failed audit entry with an error description.
    pub fn failed(
        trace: TraceMetadata,
        session_id: Option<u64>,
        actor: String,
        operation: String,
        timestamp: u64,
        error: String,
    ) -> Self {
        AuditEntry {
            trace,
            session_id,
            actor,
            operation,
            timestamp,
            status: "failed".to_string(),
            error: Some(error),
        }
    }

    /// Return a one-line summary suitable for log output.
    ///
    /// Format:
    /// ```text
    /// [trace req-abc op=submit_attestation depth=0] actor=G... session=42 status=success ts=1000000
    /// ```
    pub fn summary(&self) -> String {
        let sess_part = self
            .session_id
            .map(|s| alloc::format!(" session={}", s))
            .unwrap_or_default();
        alloc::format!(
            "{} actor={}{} status={} ts={}",
            self.trace.log_prefix(),
            self.actor,
            sess_part,
            self.status,
            self.timestamp
        )
    }
}

// ---------------------------------------------------------------------------
// TransactionContextRecord — context-aware wrapper for transaction state
// ---------------------------------------------------------------------------

/// Enriches a [`TransactionStateRecord`] with trace metadata so that every
/// state transition (Pending → InProgress → Completed/Failed) can be
/// correlated with the originating request in off-chain logs.
///
/// Off-chain monitors should use this when persisting transaction state
/// snapshots to an external store (database, log stream, etc.).
#[derive(Clone, Debug)]
pub struct TransactionContextRecord {
    /// The on-chain transaction ID.
    pub transaction_id: u64,
    /// Current state string (`"pending"`, `"in_progress"`, `"completed"`, `"failed"`).
    pub state: String,
    /// Trace context from the request that initiated this transaction.
    pub trace: TraceMetadata,
    /// Actor (Stellar account ID string).
    pub initiator: String,
    /// Unix timestamp of the most recent state change.
    pub last_updated: u64,
    /// Optional routing reason recorded at creation time.
    pub routing_reason: Option<String>,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // TraceMetadata
    // -----------------------------------------------------------------------

    #[test]
    fn test_new_trace_is_root() {
        let meta = TraceMetadata::new("req-001".to_string());
        assert!(meta.is_root());
        assert_eq!(meta.root_request_id, "req-001");
        assert_eq!(meta.depth, 0);
    }

    #[test]
    fn test_child_inherits_root_and_increments_depth() {
        let root = TraceMetadata::with_operation("req-001".to_string(), "create_session");
        let child = root.child("submit_attestation");
        assert_eq!(child.root_request_id, "req-001");
        assert_eq!(child.parent_request_id.as_deref(), Some("req-001"));
        assert_eq!(child.depth, 1);
        assert_eq!(child.operation, "submit_attestation");
    }

    #[test]
    fn test_grandchild_depth_increments() {
        let root = TraceMetadata::new("req-002".to_string());
        let child = root.child("op-a");
        let grandchild = child.child("op-b");
        assert_eq!(grandchild.depth, 2);
        assert_eq!(grandchild.root_request_id, "req-002");
    }

    #[test]
    fn test_log_prefix_format() {
        let meta = TraceMetadata::with_operation("req-xyz".to_string(), "deliver_webhook");
        let prefix = meta.log_prefix();
        assert!(prefix.starts_with("[trace req-xyz"));
        assert!(prefix.contains("op=deliver_webhook"));
        assert!(prefix.contains("depth=0"));
    }

    // -----------------------------------------------------------------------
    // ContextHeader round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn test_headers_round_trip() {
        let meta = TraceMetadata {
            root_request_id: "req-abc".to_string(),
            operation: "submit_quote".to_string(),
            parent_request_id: Some("req-parent".to_string()),
            depth: 1,
        };
        let headers = trace_to_headers(&meta);
        let recovered = headers_to_trace(&headers).expect("should parse headers");
        assert_eq!(recovered.root_request_id, "req-abc");
        assert_eq!(recovered.operation, "submit_quote");
        assert_eq!(recovered.parent_request_id.as_deref(), Some("req-parent"));
    }

    #[test]
    fn test_headers_without_parent_span() {
        let meta = TraceMetadata::with_operation("req-no-parent".to_string(), "root_op");
        let headers = trace_to_headers(&meta);
        assert!(!headers.iter().any(|h| h.name == HEADER_PARENT_SPAN));
        let recovered = headers_to_trace(&headers).expect("should parse");
        assert!(recovered.parent_request_id.is_none());
    }

    #[test]
    fn test_missing_trace_id_returns_none() {
        let headers = vec![ContextHeader {
            name: HEADER_OPERATION.to_string(),
            value: "some-op".to_string(),
        }];
        assert!(headers_to_trace(&headers).is_none());
    }

    // -----------------------------------------------------------------------
    // Webhook payload enrichment
    // -----------------------------------------------------------------------

    #[test]
    fn test_enrich_and_extract_webhook_payload() {
        let payload = r#"{"event":"deposit","amount":100}"#;
        let meta = TraceMetadata::with_operation("req-wh-001".to_string(), "deliver_webhook");
        let enriched = enrich_webhook_payload(payload, &meta);

        assert!(enriched.starts_with("[anchor-trace "));
        assert!(enriched.contains(payload));

        let extracted = extract_trace_from_payload(&enriched).expect("should extract");
        assert_eq!(extracted.root_request_id, "req-wh-001");
        assert_eq!(extracted.operation, "deliver_webhook");
    }

    #[test]
    fn test_extract_from_plain_payload_returns_none() {
        let payload = r#"{"event":"deposit"}"#;
        assert!(extract_trace_from_payload(payload).is_none());
    }

    #[test]
    fn test_enriched_payload_survives_multi_step_chain() {
        let meta = TraceMetadata::new("req-chain".to_string());
        let child = meta.child("step-1");
        let grandchild = child.child("step-2");

        let payload = "original_payload";
        let enriched = enrich_webhook_payload(payload, &grandchild);
        let extracted = extract_trace_from_payload(&enriched).unwrap();

        // root_request_id must survive the full chain.
        assert_eq!(extracted.root_request_id, "req-chain");
        assert_eq!(extracted.depth, 2);
    }

    // -----------------------------------------------------------------------
    // AuditEntry
    // -----------------------------------------------------------------------

    #[test]
    fn test_audit_entry_success_summary_contains_trace_id() {
        let meta = TraceMetadata::with_operation("req-audit".to_string(), "approve_kyc");
        let entry = AuditEntry::success(
            meta,
            Some(7),
            "GABC123".to_string(),
            "approve_kyc".to_string(),
            1_000_000,
        );
        let summary = entry.summary();
        assert!(summary.contains("req-audit"));
        assert!(summary.contains("session=7"));
        assert!(summary.contains("status=success"));
    }

    #[test]
    fn test_audit_entry_failed_carries_error() {
        let meta = TraceMetadata::new("req-fail".to_string());
        let entry = AuditEntry::failed(
            meta,
            None,
            "GXYZ".to_string(),
            "submit_attestation".to_string(),
            2_000_000,
            "replay attack".to_string(),
        );
        assert_eq!(entry.status, "failed");
        assert_eq!(entry.error.as_deref(), Some("replay attack"));
    }

    // -----------------------------------------------------------------------
    // Context ID survival across multi-step operations
    // -----------------------------------------------------------------------

    #[test]
    fn test_root_id_survives_three_level_chain() {
        let root_id = "root-persistent-id".to_string();
        let root = TraceMetadata::new(root_id.clone());
        let step1 = root.child("create_session");
        let step2 = step1.child("submit_attestation");
        let step3 = step2.child("deliver_webhook");

        // Root ID must be the same at every level.
        assert_eq!(step1.root_request_id, root_id);
        assert_eq!(step2.root_request_id, root_id);
        assert_eq!(step3.root_request_id, root_id);

        // Each step knows its parent.
        assert_eq!(step1.parent_request_id.as_deref(), Some(root_id.as_str()));
        assert_eq!(step2.parent_request_id.as_deref(), Some(root_id.as_str()));
        assert_eq!(step3.parent_request_id.as_deref(), Some(root_id.as_str()));
    }

    #[test]
    fn test_context_id_in_audit_entries_chain() {
        let root_id = "req-audit-chain".to_string();
        let meta = TraceMetadata::new(root_id.clone());

        let entries: Vec<AuditEntry> = ["create_session", "submit_attestation", "deliver_webhook"]
            .iter()
            .enumerate()
            .map(|(i, op)| {
                let span = meta.child(op);
                AuditEntry::success(span, Some(1), "GACTOR".to_string(), op.to_string(), 1000 + i as u64)
            })
            .collect();

        // Every entry must carry the same root request ID.
        for entry in &entries {
            assert_eq!(entry.trace.root_request_id, root_id);
        }
    }

    #[test]
    fn test_header_propagation_preserves_root_across_service_boundary() {
        // Simulate passing context from the contract host to a webhook endpoint.
        let original = TraceMetadata::with_operation("req-boundary".to_string(), "notify_webhook");
        let headers = trace_to_headers(&original);

        // Simulate the receiving end reconstructing the context.
        let reconstructed = headers_to_trace(&headers).expect("header parse");
        assert_eq!(reconstructed.root_request_id, "req-boundary");

        // The receiver can create a child for its own work.
        let receiver_span = reconstructed.child("process_notification");
        assert_eq!(receiver_span.root_request_id, "req-boundary");
    }
}
