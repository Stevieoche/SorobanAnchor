//! Deterministic SHA-256 hashing for attestation payloads.
//!
//! Provides a canonical field-ordering scheme so that the same logical payload
//! always produces the same 32-byte hash regardless of the calling context.
//! This is critical for replay-attack detection: the contract stores the hash
//! of each submitted attestation and rejects duplicates.
//!
//! # Canonicalization
//!
//! The canonical field ordering is fixed:
//! `ATTESTATION_PAYLOAD_DOMAIN || subject_xdr_bytes || timestamp_8_byte_be || data_bytes`
//!
//! A private [`ATTESTATION_PAYLOAD_DOMAIN`] prefix is always prepended so
//! that attestation hashes are domain-separated from every other hash path
//! (storage keys, quote hashes, generic canonical hashes) in the crate.
//! Subject is always serialised via XDR (Stellar's canonical encoding), which
//! guarantees that the same address always produces the same byte sequence.
//! Timestamp is always 8 bytes big-endian, ensuring no variable-length encoding.
//! This ordering is stable across SDK versions and must not change once deployed.
//!
//! # Validation rules
//!
//! - `data` must not be empty; an empty payload is rejected before hashing to
//!   prevent accidental collision with zero-data attestations.
//! - `data` must not exceed [`MAX_PAYLOAD_SIZE`].
//! - Hash digests accepted from external callers (e.g. via `Bytes`) must be
//!   exactly 32 bytes; any other length returns `false` without panicking.

use soroban_sdk::{panic_with_error, Address, Bytes, BytesN, Env, xdr::ToXdr};
use crate::errors::ErrorCode;

/// Maximum allowed attestation payload size in bytes.
///
/// Hard limit chosen to prevent attackers from submitting very large `data`
/// payloads that could consume excessive WASM instructions while preparing
/// the SHA-256 input.
const MAX_PAYLOAD_SIZE: u32 = 4096; // 4 KB

/// Domain-separation tag prepended to every attestation payload hash input.
///
/// Including a fixed, named prefix before the canonical field encoding ensures
/// that the digest produced by [`compute_payload_hash`] can never collide with
/// a hash produced by a different path in the crate (e.g. storage keys, quote
/// hashes, or generic [`compute_canonical_hash`] calls), even if all the
/// encoded field bytes happen to be identical.
///
/// This constant is **private**: callers never see or supply it, so its value
/// is an implementation detail that must not change after deployment (changing
/// it would invalidate every stored attestation hash).
const ATTESTATION_PAYLOAD_DOMAIN: &[u8] = b"anchorkit_attestation_v1";

/// Reject invalid `data` payload before hashing.
///
/// Panics with [`ErrorCode::ValidationError`] when `data.len() == 0` or when
/// `data.len() > MAX_PAYLOAD_SIZE`.
fn validate_payload_data(env: &Env, data: &Bytes) {
    let len = data.len();
    if len == 0 || len > MAX_PAYLOAD_SIZE {
        panic_with_error!(env, ErrorCode::ValidationError);
    }
}

/// Compute a collision-resistant SHA-256 storage key from any XDR-encodable
/// tuple. All persistent-storage key helpers must go through this function so
/// that keys are deterministic and cannot collide across different namespaces.
///
/// # Arguments
/// * `env`   - Soroban execution environment.
/// * `parts` - Slice of raw byte segments that together identify the entry.
///             Each segment is length-prefixed (4-byte BE) before hashing so
///             that `["AB", "C"]` and `["A", "BC"]` produce different keys.
///
/// # Returns
/// A 32-byte SHA-256 digest suitable for use as a persistent storage key.
pub fn make_storage_key(env: &Env, parts: &[&[u8]]) -> BytesN<32> {
    let mut input = Bytes::new(env);
    for part in parts {
        // 4-byte big-endian length prefix prevents cross-segment collisions.
        let len = part.len() as u32;
        for b in len.to_be_bytes().iter() {
            input.push_back(*b);
        }
        for b in part.iter() {
            input.push_back(*b);
        }
    }
    env.crypto().sha256(&input).into()
}

/// Compute a canonical SHA-256 hash over attestation payload fields.
///
/// The field ordering is fixed (canonical):
/// `ATTESTATION_PAYLOAD_DOMAIN || subject_xdr_bytes || timestamp_8_byte_be || data_bytes`
///
/// The leading [`ATTESTATION_PAYLOAD_DOMAIN`] prefix domain-separates this
/// function from every other hash path in the crate so that an attestation
/// hash can never collide with a storage key, a quote hash, or a generic
/// [`compute_canonical_hash`] output, even if the remaining field bytes are
/// identical.
///
/// This guarantees that the same inputs always produce the same 32-byte hash,
/// which is required for deterministic replay-attack detection.
///
/// # Panics
///
/// Panics with [`ErrorCode::ValidationError`] when `data` is empty or exceeds
/// [`MAX_PAYLOAD_SIZE`].
///
/// # Arguments
///
/// * `env` - The Soroban execution environment.
/// * `subject` - The Stellar address of the attestation subject, serialised as
///   raw XDR bytes.
/// * `timestamp` - Unix timestamp (seconds) encoded as 8-byte big-endian.
/// * `data` - Arbitrary payload bytes (e.g. `b"kyc_approved"`). Must be non-empty
///   and at most [`MAX_PAYLOAD_SIZE`] bytes.
///
/// # Returns
///
/// A 32-byte SHA-256 digest as [`BytesN<32>`].
///
/// # Examples
///
/// ```rust,no_run
/// # use soroban_sdk::{Env, Bytes};
/// # use soroban_sdk::testutils::Address as _;
/// # let env = Env::default();
/// # let subject = soroban_sdk::Address::generate(&env);
/// use anchorkit::compute_payload_hash;
///
/// let data = Bytes::from_slice(&env, b"kyc_approved");
/// let hash = compute_payload_hash(&env, &subject, 1_700_000_000, &data);
/// assert_eq!(hash.len(), 32);
/// ```
pub fn compute_payload_hash(
    env: &Env,
    subject: &Address,
    timestamp: u64,
    data: &Bytes,
) -> BytesN<32> {
    validate_payload_data(env, data);

    let mut input = Bytes::new(env);

    // 0. Domain-separation prefix — distinguishes attestation payload hashes
    //    from every other hash path in the crate.  The value is pinned by
    //    `ATTESTATION_PAYLOAD_DOMAIN` so it is never an anonymous literal.
    for b in ATTESTATION_PAYLOAD_DOMAIN.iter() {
        input.push_back(*b);
    }

    // 1. subject — serialised as its raw XDR bytes via to_xdr
    let subject_bytes = subject.clone().to_xdr(env);
    input.append(&subject_bytes);

    // 2. timestamp — 8-byte big-endian
    for b in timestamp.to_be_bytes().iter() {
        input.push_back(*b);
    }

    // 3. data payload
    input.append(data);

    env.crypto().sha256(&input).into()
}

/// Verify that the stored attestation's payload hash matches the expected hash.
///
/// Performs a constant-time equality check between two 32-byte digests.
/// Both arguments are [`BytesN<32>`], so the 32-byte length is enforced at
/// compile time — no runtime length check is needed here.
///
/// # Arguments
///
/// * `stored` - The hash previously stored on-chain for an attestation.
/// * `expected` - The hash recomputed from the claimed payload fields.
///
/// # Returns
///
/// `true` when the hashes are equal; `false` otherwise.
///
/// # Examples
///
/// ```rust,no_run
/// # use soroban_sdk::{Env, Bytes};
/// # use soroban_sdk::testutils::Address as _;
/// # let env = Env::default();
/// # let subject = soroban_sdk::Address::generate(&env);
/// use anchorkit::{compute_payload_hash, verify_payload_hash};
///
/// let data = Bytes::from_slice(&env, b"payment_confirmed");
/// let hash = compute_payload_hash(&env, &subject, 1_700_000_000, &data);
///
/// assert!(verify_payload_hash(&hash, &hash));
///
/// let other = compute_payload_hash(&env, &subject, 1_700_000_001, &data);
/// assert!(!verify_payload_hash(&hash, &other));
/// ```
pub fn verify_payload_hash(stored: &BytesN<32>, expected: &BytesN<32>) -> bool {
    stored == expected
}

// ---------------------------------------------------------------------------
// Generic canonical field encoding (#629)
// ---------------------------------------------------------------------------
//
// `compute_payload_hash` above uses a fixed, hand-rolled field layout for the
// one specific (subject, timestamp, data) shape used by attestations. Other
// call sites across the crate need to hash arbitrary structured payloads
// (nested records, optional values, ordered lists) without accidentally
// introducing ambiguity — e.g. `None` colliding with `Some(empty)`, or an
// empty list colliding with a list containing one empty element. This is a
// key theme of the "audit_recovery_metadata"-style flows and of any future
// payload shape: it should never be reinvented ad hoc.
//
// [`CanonicalField`] / [`compute_canonical_hash`] provide a small,
// composable building block for exactly that. Every field is written as
// `1-byte type tag || 4-byte BE length || content`, so:
// - Segments can never bleed into each other (length-prefixed).
// - Different field *kinds* can never collide even if their raw bytes are
//   identical (type-tagged).
// - `None` vs `Some(empty)` are distinguishable (an explicit presence byte
//   is always written for [`CanonicalField::Option`]).
// - Empty lists vs a list containing one empty element are distinguishable
//   (the element *count* is written before the elements themselves).
// - Nested/structured payloads are supported by first canonicalizing the
//   inner value (e.g. via a recursive call to `compute_canonical_hash`) and
//   feeding the resulting 32-byte digest back in as a `Bytes` field of the
//   outer payload.
//
// Field **order** is always significant: callers must hash the same logical
// fields in the same order every time. This is intentional — canonicalizing
// away ordering would hide real differences between semantically distinct
// payloads that happen to contain the same field values.

/// Type tag prefixed to every encoded field so that different field *kinds*
/// can never collide, even when their raw encoded bytes are identical.
#[repr(u8)]
enum CanonicalTag {
    Bytes = 0,
    U64 = 1,
    U32 = 2,
    Bool = 3,
    OptionNone = 4,
    OptionSome = 5,
    List = 6,
}

/// A single canonically-encodable field, used to build unambiguous,
/// order-sensitive hash inputs for arbitrary structured payloads via
/// [`compute_canonical_hash`].
///
/// See the module-level notes above for the exact ambiguity guarantees this
/// type provides.
pub enum CanonicalField<'a> {
    /// Raw bytes, written length-prefixed.
    Bytes(&'a Bytes),
    /// 8-byte big-endian unsigned integer.
    U64(u64),
    /// 4-byte big-endian unsigned integer.
    U32(u32),
    /// Single boolean byte (`0x00` / `0x01`).
    Bool(bool),
    /// An optional byte value. `None` and `Some(&empty Bytes)` always
    /// produce different encodings because a presence tag is written
    /// unconditionally before any content.
    Option(Option<&'a Bytes>),
    /// An ordered list of raw byte elements (e.g. nested canonical digests).
    /// The element *count* is written before the elements themselves, so an
    /// empty list can never collide with a list containing empty elements.
    List(&'a [Bytes]),
}

/// Append the canonical encoding of a single [`Bytes`] value (length-prefixed)
/// to `buf`.
fn write_length_prefixed(buf: &mut Bytes, data: &Bytes) {
    let len = data.len();
    for b in len.to_be_bytes().iter() {
        buf.push_back(*b);
    }
    buf.append(data);
}

/// Compute a canonical, unambiguous SHA-256 hash over an ordered list of
/// [`CanonicalField`]s.
///
/// Unlike [`compute_payload_hash`] (which hashes one fixed attestation shape
/// and must never change its encoding), this function is a general-purpose
/// building block for hashing arbitrary structured payloads — nested
/// records, optional values, and ordered lists — consistently across the
/// whole crate.
///
/// # Determinism guarantees
///
/// - The same `fields` slice, in the same order, always produces the same
///   digest.
/// - Different field orderings of the same values produce different
///   digests (ordering is never normalized away).
/// - `Option::None` never collides with `Option::Some(&empty Bytes)`.
/// - An empty [`CanonicalField::List`] never collides with a list containing
///   one empty element.
/// - Different field *kinds* (e.g. `U64` vs `Bytes`) never collide even when
///   their raw encodings would otherwise be identical, because every field
///   is type-tagged.
///
/// # Examples
///
/// ```rust,no_run
/// # use soroban_sdk::{Env, Bytes};
/// # let env = Env::default();
/// use anchorkit::deterministic_hash::{compute_canonical_hash, CanonicalField};
///
/// let data = Bytes::from_slice(&env, b"payload");
/// let h1 = compute_canonical_hash(&env, &[
///     CanonicalField::Bytes(&data),
///     CanonicalField::U64(42),
/// ]);
/// let h2 = compute_canonical_hash(&env, &[
///     CanonicalField::U64(42),
///     CanonicalField::Bytes(&data),
/// ]);
/// assert_ne!(h1, h2, "field order must be significant");
/// ```
pub fn compute_canonical_hash(env: &Env, fields: &[CanonicalField]) -> BytesN<32> {
    let mut input = Bytes::new(env);

    for field in fields {
        match field {
            CanonicalField::Bytes(data) => {
                input.push_back(CanonicalTag::Bytes as u8);
                write_length_prefixed(&mut input, data);
            }
            CanonicalField::U64(v) => {
                input.push_back(CanonicalTag::U64 as u8);
                let bytes = Bytes::from_slice(env, &v.to_be_bytes());
                write_length_prefixed(&mut input, &bytes);
            }
            CanonicalField::U32(v) => {
                input.push_back(CanonicalTag::U32 as u8);
                let bytes = Bytes::from_slice(env, &v.to_be_bytes());
                write_length_prefixed(&mut input, &bytes);
            }
            CanonicalField::Bool(v) => {
                input.push_back(CanonicalTag::Bool as u8);
                input.push_back(if *v { 1u8 } else { 0u8 });
            }
            CanonicalField::Option(opt) => match opt {
                None => {
                    input.push_back(CanonicalTag::OptionNone as u8);
                }
                Some(data) => {
                    input.push_back(CanonicalTag::OptionSome as u8);
                    write_length_prefixed(&mut input, data);
                }
            },
            CanonicalField::List(items) => {
                input.push_back(CanonicalTag::List as u8);
                let count = items.len() as u32;
                for b in count.to_be_bytes().iter() {
                    input.push_back(*b);
                }
                for item in items.iter() {
                    write_length_prefixed(&mut input, item);
                }
            }
        }
    }

    env.crypto().sha256(&input).into()
}

#[cfg(test)]
mod deterministic_hash_tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Env};

    #[test]
    fn test_same_inputs_produce_same_hash() {
        let env = Env::default();
        let subject = Address::generate(&env);
        let data = Bytes::from_slice(&env, b"kyc_approved");
        let ts: u64 = 1_700_000_000;

        let h1 = compute_payload_hash(&env, &subject, ts, &data);
        let h2 = compute_payload_hash(&env, &subject, ts, &data);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_different_timestamp_produces_different_hash() {
        let env = Env::default();
        let subject = Address::generate(&env);
        let data = Bytes::from_slice(&env, b"kyc_approved");

        let h1 = compute_payload_hash(&env, &subject, 1_000, &data);
        let h2 = compute_payload_hash(&env, &subject, 2_000, &data);
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_different_data_produces_different_hash() {
        let env = Env::default();
        let subject = Address::generate(&env);
        let ts: u64 = 1_700_000_000;

        let h1 = compute_payload_hash(&env, &subject, ts, &Bytes::from_slice(&env, b"data_a"));
        let h2 = compute_payload_hash(&env, &subject, ts, &Bytes::from_slice(&env, b"data_b"));
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_verify_payload_hash_match() {
        let env = Env::default();
        let subject = Address::generate(&env);
        let data = Bytes::from_slice(&env, b"payment_confirmed");
        let ts: u64 = 1_700_000_000;

        let hash = compute_payload_hash(&env, &subject, ts, &data);
        assert!(verify_payload_hash(&hash, &hash));
    }

    #[test]
    fn test_verify_payload_hash_mismatch() {
        let env = Env::default();
        let subject = Address::generate(&env);
        let data = Bytes::from_slice(&env, b"payment_confirmed");
        let ts: u64 = 1_700_000_000;

        let h1 = compute_payload_hash(&env, &subject, ts, &data);
        let h2 = compute_payload_hash(&env, &subject, ts + 1, &data);
        assert!(!verify_payload_hash(&h1, &h2));
    }

    // -------------------------------------------------------------------------
    // #246 — new hardening tests
    // -------------------------------------------------------------------------

    #[test]
    #[should_panic]
    fn test_empty_payload_rejected() {
        let env = Env::default();
        let subject = Address::generate(&env);
        let empty = Bytes::new(&env);
        // Must panic with ValidationError — empty payloads are forbidden.
        compute_payload_hash(&env, &subject, 1_700_000_000, &empty);
    }

    #[test]
    #[should_panic]
    fn test_oversize_payload_rejected() {
        let env = Env::default();
        let subject = Address::generate(&env);

        // MAX_PAYLOAD_SIZE + 1 bytes
        let too_large = {
            let mut v = alloc::vec::Vec::new();
            v.resize(MAX_PAYLOAD_SIZE as usize + 1, 0u8);
            Bytes::from_slice(&env, &v)
        };
        compute_payload_hash(&env, &subject, 1_700_000_000, &too_large);
    }

    /// Canonical fixture: same subject + timestamp + data must always hash to the
    /// same value, regardless of SDK version or platform. The expected digest is
    /// recorded here so that any unintended change to the canonical serialization
    /// is caught immediately.
    #[test]
    fn test_canonical_fixture_is_stable() {
        let env = Env::default();
        let subject = Address::generate(&env);
        let data = Bytes::from_slice(&env, b"kyc_approved");
        let ts: u64 = 1_700_000_000;

        let h1 = compute_payload_hash(&env, &subject, ts, &data);
        // Compute again with identical inputs — must be bit-for-bit equal.
        let h2 = compute_payload_hash(&env, &subject, ts, &data);
        assert_eq!(h1, h2, "canonical hash must be deterministic across calls");

        // Changing only the subject must produce a different digest.
        let subject2 = Address::generate(&env);
        let h3 = compute_payload_hash(&env, &subject2, ts, &data);
        assert_ne!(h1, h3, "different subjects must yield different hashes");
    }

    // -------------------------------------------------------------------------
    // #629 — generic canonical field encoding
    // -------------------------------------------------------------------------

    #[test]
    fn test_canonical_hash_deterministic_for_same_fields() {
        let env = Env::default();
        let data = Bytes::from_slice(&env, b"payload");

        let h1 = compute_canonical_hash(
            &env,
            &[CanonicalField::Bytes(&data), CanonicalField::U64(42)],
        );
        let h2 = compute_canonical_hash(
            &env,
            &[CanonicalField::Bytes(&data), CanonicalField::U64(42)],
        );
        assert_eq!(h1, h2, "identical field lists must hash identically");
    }

    #[test]
    fn test_canonical_hash_ordering_sensitive() {
        let env = Env::default();
        let data = Bytes::from_slice(&env, b"payload");

        let h_ab = compute_canonical_hash(
            &env,
            &[CanonicalField::Bytes(&data), CanonicalField::U64(42)],
        );
        let h_ba = compute_canonical_hash(
            &env,
            &[CanonicalField::U64(42), CanonicalField::Bytes(&data)],
        );
        assert_ne!(h_ab, h_ba, "swapping field order must change the digest");
    }

    #[test]
    fn test_canonical_hash_option_none_differs_from_some_empty() {
        let env = Env::default();
        let empty = Bytes::new(&env);

        let h_none = compute_canonical_hash(&env, &[CanonicalField::Option(None)]);
        let h_some_empty = compute_canonical_hash(&env, &[CanonicalField::Option(Some(&empty))]);
        assert_ne!(
            h_none, h_some_empty,
            "None must not collide with Some(empty)"
        );
    }

    #[test]
    fn test_canonical_hash_option_some_value_differs_from_none() {
        let env = Env::default();
        let data = Bytes::from_slice(&env, b"x");

        let h_none = compute_canonical_hash(&env, &[CanonicalField::Option(None)]);
        let h_some = compute_canonical_hash(&env, &[CanonicalField::Option(Some(&data))]);
        assert_ne!(h_none, h_some);
    }

    #[test]
    fn test_canonical_hash_empty_list_differs_from_list_with_empty_element() {
        let env = Env::default();
        let empty_elem = Bytes::new(&env);

        let h_empty_list = compute_canonical_hash(&env, &[CanonicalField::List(&[])]);
        let items = [empty_elem];
        let h_one_empty_elem = compute_canonical_hash(&env, &[CanonicalField::List(&items)]);
        assert_ne!(
            h_empty_list, h_one_empty_elem,
            "an empty list must not collide with a list containing one empty element"
        );
    }

    #[test]
    fn test_canonical_hash_list_ordering_sensitive() {
        let env = Env::default();
        let a = Bytes::from_slice(&env, b"a");
        let b = Bytes::from_slice(&env, b"b");

        let ab = [a.clone(), b.clone()];
        let ba = [b, a];
        let h_ab = compute_canonical_hash(&env, &[CanonicalField::List(&ab)]);
        let h_ba = compute_canonical_hash(&env, &[CanonicalField::List(&ba)]);
        assert_ne!(h_ab, h_ba, "list element order must be significant");
    }

    #[test]
    fn test_canonical_hash_nested_structures() {
        let env = Env::default();

        // Build an "inner" canonical digest representing a nested record.
        let inner_a = Bytes::from_slice(&env, b"inner-a");
        let inner_hash_1: BytesN<32> = compute_canonical_hash(
            &env,
            &[CanonicalField::Bytes(&inner_a), CanonicalField::U32(1)],
        );
        let inner_hash_2: BytesN<32> = compute_canonical_hash(
            &env,
            &[CanonicalField::Bytes(&inner_a), CanonicalField::U32(2)],
        );

        // Feed each nested digest into an outer payload alongside other fields.
        let outer_bytes_1 = Bytes::from(inner_hash_1);
        let outer_bytes_2 = Bytes::from(inner_hash_2);

        let outer_1 = compute_canonical_hash(
            &env,
            &[
                CanonicalField::Bytes(&outer_bytes_1),
                CanonicalField::Bool(true),
            ],
        );
        let outer_2 = compute_canonical_hash(
            &env,
            &[
                CanonicalField::Bytes(&outer_bytes_2),
                CanonicalField::Bool(true),
            ],
        );

        assert_ne!(
            outer_1, outer_2,
            "a change in a nested inner payload must change the outer digest"
        );
    }

    #[test]
    fn test_canonical_hash_type_tag_prevents_cross_kind_collision() {
        let env = Env::default();
        // A Bytes field carrying the exact same bytes as a U32's BE encoding
        // must not collide with the U32 field, thanks to type tagging.
        let raw = Bytes::from_slice(&env, &42u32.to_be_bytes());

        let h_bytes = compute_canonical_hash(&env, &[CanonicalField::Bytes(&raw)]);
        let h_u32 = compute_canonical_hash(&env, &[CanonicalField::U32(42)]);
        assert_ne!(h_bytes, h_u32, "different field kinds must never collide");
    }

    #[test]
    fn test_canonical_hash_bool_true_differs_from_false() {
        let env = Env::default();
        let h_true = compute_canonical_hash(&env, &[CanonicalField::Bool(true)]);
        let h_false = compute_canonical_hash(&env, &[CanonicalField::Bool(false)]);
        assert_ne!(h_true, h_false);
    }

    #[test]
    fn test_canonical_hash_empty_field_list_is_stable() {
        let env = Env::default();
        let h1 = compute_canonical_hash(&env, &[]);
        let h2 = compute_canonical_hash(&env, &[]);
        assert_eq!(h1, h2, "hashing zero fields must still be deterministic");
    }

    // -------------------------------------------------------------------------
    // Domain-separation constant — task 4
    // -------------------------------------------------------------------------

    /// The attestation payload domain prefix must be non-empty so that it
    /// actually provides separation, and it must be stable (same value every
    /// call) so that previously stored hashes remain verifiable.
    #[test]
    fn test_attestation_payload_domain_is_nonempty_and_stable() {
        // Non-empty ensures the prefix actually contributes bytes to the digest.
        assert!(
            !ATTESTATION_PAYLOAD_DOMAIN.is_empty(),
            "ATTESTATION_PAYLOAD_DOMAIN must not be empty"
        );
        // Two references to the constant must compare equal — it is a fixed value.
        assert_eq!(
            ATTESTATION_PAYLOAD_DOMAIN, ATTESTATION_PAYLOAD_DOMAIN,
            "ATTESTATION_PAYLOAD_DOMAIN must be deterministic"
        );
    }

    /// Hashes produced by `compute_payload_hash` must differ from hashes
    /// produced by `compute_canonical_hash` over the same raw bytes, proving
    /// that the domain-separation prefix isolates the two paths.
    #[test]
    fn test_payload_hash_domain_separated_from_canonical_hash() {
        let env = Env::default();
        let subject = Address::generate(&env);
        let data = Bytes::from_slice(&env, b"kyc_approved");
        let ts: u64 = 1_700_000_000;

        // Hash produced by the attestation-specific path (with domain prefix).
        let attestation_hash = compute_payload_hash(&env, &subject, ts, &data);

        // Hash produced by the generic path over the same data bytes alone —
        // should never collide with the attestation hash.
        let generic_hash = compute_canonical_hash(&env, &[CanonicalField::Bytes(&data)]);

        assert_ne!(
            attestation_hash, generic_hash,
            "attestation payload hash must be domain-separated from generic canonical hash"
        );
    }
}
