# SEP-31 Field Reference

SEP-31 is the direct-payment protocol. AnchorKit normalizes anchor responses
through `initiate_sep31_payment` in `src/sep31.rs`. This page maps each raw
field to its internal representation, validation boundary, and normalization
rule.

## Entry point

```rust
pub fn initiate_sep31_payment(
    raw: RawSep31PaymentResponse,
) -> Result<Sep31PaymentResponse, Error>
```

Source: `src/sep31.rs`  
Tests: `tests/sep31_tests.rs`

---

## Field reference

### Required fields

#### `id`

**Type:** `String`  
**Constraint:** Non-empty (after `trim()`), at most 64 characters.  
**Normalization:** Stored verbatim — no case change or other transform.

| Input | Result |
|---|---|
| `"pay-001"` | accepted; `resp.id == "pay-001"` |
| `""` | `Err(InvalidTransactionIntent)` |
| `"   "` | `Err(InvalidTransactionIntent)` (whitespace-only rejected) |
| 65-character string | `Err(ValidationError)` |

---

#### `stellar_account_id`

**Type:** `String`  
**Constraint:** Must pass `validate_stellar_account_id` (implemented in
`src/response_validator.rs`). This checks the Ed25519 Stellar account format —
a 56-character base32 string beginning with `G`.

| Input | Result |
|---|---|
| `"GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5"` | accepted |
| `"not-a-valid-account"` | `Err(...)` |

---

#### `sender`

**Type:** `String`  
**Constraint:** Non-empty after `trim()`.  
**Normalization:** Stored verbatim.

| Input | Result |
|---|---|
| `"sender-001"` | accepted |
| `""` | `Err(InvalidTransactionIntent)` |
| `"   "` | `Err(InvalidTransactionIntent)` |

---

### Optional fields

Optional fields are `None` in `RawSep31PaymentResponse` when absent. When
absent they are `None` in the output — the parser never injects defaults.

#### `stellar_memo` and `stellar_memo_type`

Both fields are optional, but they are validated as a **pair**:

- If `stellar_memo` is `Some`, then `stellar_memo_type` must also be `Some`
  and must be one of `"text"`, `"id"`, or `"hash"` exactly. Any other string
  returns `Err(InvalidTransactionIntent)`.
- If `stellar_memo` is `None`, `stellar_memo_type` is ignored.
- When present, `stellar_memo` must not exceed 256 bytes.

| `stellar_memo` | `stellar_memo_type` | Result |
|---|---|---|
| `None` | `None` | accepted |
| `Some("12345")` | `Some("id")` | accepted |
| `Some("12345")` | `None` | `Err(InvalidTransactionIntent)` |
| `Some("12345")` | `Some("fax")` | `Err(InvalidTransactionIntent)` |
| `Some("x" × 257)` | `Some("text")` | `Err(ValidationError)` |

---

#### `amount`

**Type:** `Option<String>`  
**Constraint:** When present, must be a syntactically valid positive decimal.
The grammar is:

```
positive-decimal = 1*DIGIT [ "." 1*DIGIT ]
```

A leading decimal point (`.5`) or trailing decimal point (`5.`) is rejected.
Negative values and zero are rejected.

| Input | Result |
|---|---|
| `None` | accepted; `resp.amount == None` |
| `Some("100")` | accepted; `resp.amount == Some("100")` |
| `Some("100.50")` | accepted |
| `Some("0.01")` | accepted |
| `Some("0")` | `Err(ValidationError)` — zero |
| `Some("0.00")` | `Err(ValidationError)` — zero |
| `Some("-50.00")` | `Err(ValidationError)` — negative |
| `Some(".5")` | `Err(ValidationError)` — leading decimal point |
| `Some("5.")` | `Err(ValidationError)` — trailing decimal point |

---

#### `asset_code`

**Type:** `Option<String>`  
**Constraint:** When present, must satisfy `normalize_asset_code`
(`src/errors.rs`): non-empty, at most 12 ASCII alphanumeric characters.  
**Normalization:** Uppercased. The reserved keyword `"native"` (case-insensitive)
is preserved in lowercase.

| Input | Result |
|---|---|
| `None` | accepted; `resp.asset_code == None` |
| `Some("usdc")` | accepted; `resp.asset_code == Some("USDC")` |
| `Some("XLM")` | accepted; `resp.asset_code == Some("XLM")` |
| `Some("native")` | accepted; `resp.asset_code == Some("native")` |
| `Some("NATIVE")` | accepted; `resp.asset_code == Some("native")` |
| `Some("")` | `Err(InvalidAssetCode)` |
| `Some("TOOLONG13CHARS")` | `Err(InvalidAssetCode)` |

---

#### `idempotency_key`

**Type:** `Option<String>`  
**Constraint:** When present, must be non-empty, at most 64 characters, and
contain only printable ASCII characters or spaces (no control characters or
null bytes).

| Input | Result |
|---|---|
| `None` | accepted |
| `Some("unique-key-001")` | accepted |
| `Some("key with spaces")` | accepted |
| `Some("")` | `Err(ValidationError)` |
| `Some("k" × 65)` | `Err(ValidationError)` |
| `Some("key\x00null")` | `Err(ValidationError)` |

---

## Supported status values

SEP-31 direct-payment transactions share the `TransactionStatus` enum defined
in `src/sep6.rs`. When you poll a SEP-31 transaction through a SEP-24 or
SEP-6 compatible endpoint, the recognized values are the same as for other
Stellar SEPs (`pending_external`, `pending_anchor`, `completed`, `error`, etc.).

SEP-31-specific server-side state management (e.g. `receiver_pending`,
`receiver_payment_complete`) is outside the scope of this library's current
implementation. The contract's `configure_services` accepts service type
`SERVICE_SEP31` (constant from `src/contract.rs`), which flags the anchor as
SEP-31-capable for routing purposes.

---

## Out of scope

The following SEP-31 protocol options are not implemented and should not be
assumed from this reference:

- Callback URL fields
- Sender / receiver KYC info delivery in the payment request body
- Multi-hop routing through intermediary anchors

---

## Related tests

Linked test cases from `tests/sep31_tests.rs` and `src/sep31.rs`:

| Scenario | Test |
|---|---|
| Valid minimal payload (all optionals absent) | `optional_party_fields_absent_shape_accepted` |
| Valid fully-populated payload | `optional_party_fields_present_shape_values_preserved` |
| Empty `id` rejected | `empty_id_rejected` |
| Whitespace-only `id` rejected | `whitespace_only_id_rejected` |
| Memo without memo type rejected | `memo_without_memo_type_rejected` |
| Invalid memo type rejected | `memo_with_invalid_type_rejected` |
| Zero amount rejected | `amount_zero_rejected` |
| Leading decimal point rejected | `amount_leading_dot_rejected` |
| Asset code normalized to uppercase | `test_initiate_sep31_payment_normalizes_asset_code` |
