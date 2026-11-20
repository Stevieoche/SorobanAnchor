# SEP-24 Response Troubleshooting

SEP-24 interactive flows involve two required fields — a redirect `url` and a
transaction `id` — that anchors sometimes omit or format incorrectly. This
page documents common response-shape mistakes and shows how to identify them
from the error values returned by `src/sep24.rs`.

Error names and codes are defined in `src/errors.rs` and listed in
`docs/error-codes.md`.

---

## Parsing functions

| Function | Parses |
|---|---|
| `initiate_interactive_deposit(raw)` | `/transactions/deposit/interactive` response |
| `initiate_interactive_withdrawal(raw)` | `/transactions/withdraw/interactive` response |
| `fetch_sep24_transaction_status(raw)` | `/transaction` polling response |

---

## Common mistakes

### 1. Missing redirect URL

**Symptom:** The anchor returns a response body with no `url` field, or the
field is present but empty or whitespace-only.

```json
{ "id": "txn-001" }
```

```json
{ "url": "",  "id": "txn-001" }
```

**Error returned:**

```
AnchorKitError {
    code:    ValidationError,   // 15
    message: "SEP-24 interactive redirect URL must not be blank",
    context: None,
}
```

**Next step:** Confirm the anchor's `/transactions/deposit/interactive`
endpoint is returning a `url` field. The SEP-24 specification requires it in
every successful `200` response.

---

### 2. Missing or empty transaction ID

**Symptom:** The anchor returns a response body with no `id` field, or the
`id` is an empty string or whitespace.

```json
{ "url": "https://anchor.example.com/sep24/deposit?token=abc" }
```

```json
{ "url": "https://anchor.example.com/sep24/deposit?token=abc", "id": "   " }
```

**Error returned:**

```
AnchorKitError {
    code:    ValidationError,   // 15
    message: "SEP-24 transaction ID must not be empty",
    context: None,
}
```

**Next step:** The `id` is the opaque token you need for all subsequent
`/transaction?id=...` polling calls. If the anchor is omitting it, check
whether the endpoint is returning a `201` or `200` with the correct body
shape; some anchors return the ID under a different field name (e.g.
`transaction_id`).

---

### 3. HTTP (non-HTTPS) redirect URL

**Symptom:** The anchor returns a cleartext HTTP URL for the interactive
redirect.

```json
{ "url": "http://anchor.example.com/sep24/deposit?token=abc", "id": "txn-002" }
```

**Error returned:**

```
AnchorKitError {
    code:    InvalidEndpointFormat,   // 12
    message: "Endpoint format is invalid",
    context: None,
}
```

**Next step:** SEP-24 mandates HTTPS for interactive redirect URLs. Report the
issue to the anchor; cleartext redirects expose the session token in transit.

---

### 4. Missing `status` field in transaction status response

**Symptom:** The `/transaction` endpoint returns a body without a `status`
field, or the field value is an empty string.

```json
{ "transaction": { "id": "txn-001" } }
```

```json
{ "transaction": { "id": "txn-001", "status": "" } }
```

**Error returned:**

```
AnchorKitError {
    code:    ValidationError,   // 15
    message: "Missing status field in SEP-24 transaction response",
    context: None,
}
```

**Next step:** `status` is required in every `/transaction` response per
SEP-24. Verify the transaction ID you are polling with; some anchors return
`404` when the ID is from a different SEP (e.g. a SEP-6 ID passed to a
SEP-24 endpoint).

---

### 5. HTTP `more_info_url`

**Symptom:** The `/transaction` response includes a `more_info_url` with an
HTTP scheme.

```json
{
  "transaction": {
    "id": "txn-003",
    "status": "pending_anchor",
    "more_info_url": "http://anchor.example.com/sep24/transaction?id=txn-003"
  }
}
```

**Error returned:**

```
AnchorKitError {
    code:    InvalidEndpointFormat,   // 12
    message: "Endpoint format is invalid",
    context: None,
}
```

**Next step:** `more_info_url`, when present, must also be an HTTPS URL.
Omit the field rather than providing a cleartext URL — the field is optional.

---

### 6. Unknown `status` value

**Symptom:** The anchor sends a status string that the parser does not
recognize (for example a future SEP-24 status not yet in `TransactionStatus`).

```json
{ "transaction": { "id": "txn-004", "status": "some_future_status" } }
```

**Behavior:** `fetch_sep24_transaction_status` succeeds but maps the value to
`TransactionStatus::Error`. No error is returned.

**Next step:** Check `src/sep6.rs` (`TransactionStatus::from_str`) for the
complete list of recognized values. If you are polling and find the status is
`Error` unexpectedly, log the raw `status` string before parsing to confirm
whether it is a known value that maps to `Error` or an unrecognized string.

---

## Quick reference: required fields

| Response type | Required fields | Optional fields |
|---|---|---|
| Deposit / Withdrawal initiation | `url` (non-empty HTTPS), `id` (non-empty) | — |
| Transaction status | `id` (non-empty), `status` (non-empty) | `more_info_url`, `stellar_transaction_id`, `asset_code` |

Optional fields are ignored when absent. When present they are validated:
`more_info_url` is normalized and checked for HTTPS; `asset_code` is
normalized to uppercase.

---

## Error code summary

| Code | Name | Trigger |
|---|---|---|
| 15 | `ValidationError` | Empty `url`, empty `id`, empty `status` |
| 12 | `InvalidEndpointFormat` | HTTP scheme, relative URL, IP literal, open redirect |

Both codes are defined in `src/errors.rs`. Full descriptions are in
`docs/error-codes.md`.

---

## Focused tests

The inline test module in `src/sep24.rs` covers every case above:

- `test_initiate_interactive_deposit_missing_url`
- `test_initiate_interactive_deposit_missing_id`
- `test_initiate_interactive_deposit_rejects_http_url`
- `test_fetch_sep24_transaction_status_missing_id`
- `test_fetch_sep24_transaction_status_missing_status`
- `test_fetch_sep24_transaction_status_rejects_http_more_info_url`
- `test_sep24_unknown_status_maps_to_error_variant`
