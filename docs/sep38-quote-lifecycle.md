# SEP-38 Quote Lifecycle

SEP-38 is the anchor RFQ (request-for-quote) protocol. This guide walks through
the quote lifecycle using existing APIs and mock fixtures so you can follow the
sequence without a live anchor.

Source files: `src/sep38.rs`, `src/mock.rs`  
Contract-level tests: `tests/quote_lifecycle_tests.rs`

---

## Lifecycle states

A SEP-38 firm quote moves through three observable states:

| State | Meaning |
|---|---|
| **Active** | Quote has been submitted; `valid_until` is in the future; eligible for routing. |
| **Invalidated** | Explicitly invalidated before expiry; excluded from routing. |
| **Expired** | `valid_until <= ledger_timestamp`; `receive_quote` panics with `QuoteExpired`. |

The on-chain side uses `QuoteLifecycleState` (from `src/contract.rs`). The
off-chain parsing layer uses `FirmQuote` and the helpers in `src/sep38.rs`.

---

## Step 1 — Retrieve a price indication

Before requesting a firm quote, callers typically fetch indicative pricing via
`fetch_prices`.

```rust
use anchorkit::sep38::{fetch_prices, RawPrice};

let raw = RawPrice {
    buy_asset:  "USDC".into(),
    sell_asset: "XLM".into(),
    price:      "1.02".into(),
};

let price = fetch_prices(raw).expect("price must be valid");
// price.buy_asset  == "USDC"
// price.sell_asset == "XLM"
// price.price      == "1.02"
```

Using the mock fixture:

```rust
#[cfg(feature = "mock-only")]
{
    use anchorkit::mock::mock_price;
    use anchorkit::sep38::fetch_prices;

    let price = fetch_prices(mock_price()).expect("mock price must be valid");
    assert_eq!(price.sell_asset, "XLM");
    assert_eq!(price.buy_asset,  "USDC");
}
```

`fetch_prices` normalizes both asset codes to uppercase and rejects zero or
non-numeric price strings with `Err(InvalidQuote)`.

---

## Step 2 — Request a firm quote

A firm quote is a binding commitment from the anchor to exchange at the stated
price until `expires_at`.

```rust
use anchorkit::sep38::{request_firm_quote, RawFirmQuote};

let raw = RawFirmQuote {
    id:          "quote-abc".into(),
    expires_at:  "1800000000".into(),   // Unix timestamp (future)
    price:       "1.02".into(),
    sell_amount: "100".into(),
    buy_amount:  "102".into(),
    sell_asset:  "XLM".into(),
    buy_asset:   "USDC".into(),
};

let now: u64 = 1_705_276_800;   // current ledger timestamp
let quote = request_firm_quote(raw, now).expect("quote must be valid");

assert_eq!(quote.id,          "quote-abc");
assert_eq!(quote.sell_asset,  "XLM");
assert_eq!(quote.buy_asset,   "USDC");
assert_eq!(quote.expires_at,  1_800_000_000);
```

Using the mock fixture (note: `MOCK_EXPIRES_AT = 1_705_276_800`; the mock
expires_at is set to that timestamp so the mock is always "expired" relative to
real wall-clock time — pass a `current_timestamp` lower than
`MOCK_EXPIRES_AT` in tests):

```rust
#[cfg(feature = "mock-only")]
{
    use anchorkit::mock::{mock_firm_quote, MOCK_EXPIRES_AT};
    use anchorkit::sep38::request_firm_quote;

    // Use a timestamp before the mock expiry.
    let quote = request_firm_quote(mock_firm_quote(), MOCK_EXPIRES_AT - 1)
        .expect("mock quote must be valid before its expiry");
    assert_eq!(quote.id, "mock-quote-001");
}
```

**Field validation performed by `request_firm_quote`:**

- `id` must be non-empty (non-whitespace).
- `expires_at` must be a non-zero integer no more than 10 years in the future.
- `price`, `sell_amount`, `buy_amount` must be positive decimal strings.
- `sell_asset` and `buy_asset` must be valid asset codes and must differ from
  each other (case-insensitive).

---

## Step 3 — Check whether a quote is still active

After receiving a firm quote, the client can check its freshness before
submitting a transaction.

```rust
use anchorkit::sep38::{is_quote_expired, get_quote_freshness, QuoteFreshness};

// quote.expires_at = 1_800_000_000
// current ledger time = 1_799_999_940 (60 seconds before expiry)
let now = 1_799_999_940u64;

if is_quote_expired(&quote, now) {
    // Re-request a new firm quote before proceeding.
}

match get_quote_freshness(&quote, now, Some(120)) {
    QuoteFreshness::Fresh      => { /* safe to use */ }
    QuoteFreshness::NearStale  => { /* consider refreshing */ }
    QuoteFreshness::Stale      => { /* must re-request */ }
    QuoteFreshness::Invalid    => { /* should not occur for a parsed quote */ }
}
```

**Expiry boundary:** The condition `expires_at <= current_timestamp` is
expired. A quote is usable up to and including `expires_at - 1`; at exactly
`expires_at` it is treated as expired. This boundary is verified by
`quote_expired_at_exact_boundary_timestamp` and
`quote_still_valid_one_second_before_expiry` in
`tests/quote_lifecycle_tests.rs`.

---

## Step 4 — Distinguish firm quote expiry from transaction status

This is the most common source of confusion in SEP-38 integrations.

**Firm quote expiry** (`expires_at`) is a property of the off-chain quote
record returned by the anchor's `/quote` endpoint. If the client tries to use
a quote after `expires_at`, `receive_quote` on-chain panics with
`QuoteExpired` (error code 60). This is distinct from a *transaction* being in
an error state.

**Transaction status** reflects the on-chain or anchor-side processing of a
payment that has already been submitted. A transaction can be `pending_anchor`
or `completed` long after the original firm quote has expired — once the
transaction is accepted, quote expiry is no longer relevant.

```
  t=0           t=expiry       t=expiry+1
   │                │               │
   ├── Active ──────┤               │
   │             receive_quote      │
   │             must succeed       │
   │                                ├── receive_quote panics (QuoteExpired)
   │
   │  Transaction submitted at t=10
   │  Transaction status: pending_anchor at t=100
   │  Transaction status: completed     at t=500
   │
   │  → Transaction status is independent of quote expiry
```

| Property | Type | What it means |
|---|---|---|
| `quote.expires_at` | `u64` Unix timestamp | When the price commitment lapses |
| `transaction.status` | `TransactionStatus` enum | Current processing state of a submitted payment |

---

## Step 5 — Invalidation (on-chain)

The contract provides `invalidate_quote` for anchors that need to revoke a
quote early. After invalidation, `get_quote_lifecycle_state` returns
`QuoteLifecycleState::Invalidated` and the quote is excluded from routing.

```rust
// From tests/quote_lifecycle_tests.rs:
// client.invalidate_quote(&anchor, &qid);
// assert_eq!(
//     client.get_quote_lifecycle_state(&anchor, &qid),
//     QuoteLifecycleState::Invalidated,
// );
```

Invalidating a quote that does not exist panics — there is no silent no-op
(verified by `test_invalidate_nonexistent_quote_panics`).

---

## Real anchor integration

All examples above use in-process fixtures or mock data. Calling a real
anchor's `/prices` or `/quote` endpoint requires HTTP infrastructure not
provided by this library. The workflow is:

1. Make an HTTP `GET` to `https://anchor.example.com/sep38/prices`.
2. Deserialize the JSON body into `RawPrice` and pass to `fetch_prices`.
3. Make an HTTP `POST` to `https://anchor.example.com/sep38/quote`.
4. Deserialize the response into `RawFirmQuote` and pass to
   `request_firm_quote` with the current Unix timestamp.

No real service endpoint or credential is required to run the library's tests.

---

## Mock fixtures summary

All fixtures are in `src/mock.rs` under the `mock-only` feature.

| Fixture | Use |
|---|---|
| `mock_price()` | Valid `RawPrice` for `fetch_prices` |
| `mock_firm_quote()` | Valid `RawFirmQuote`; expires at `MOCK_EXPIRES_AT` |
| `mock_firm_quote_expired()` | `RawFirmQuote` with a past timestamp (2021-01-01) |
| `mock_firm_quote_minimal()` | Minimal valid quote (`price = "1.0"`) |
| `mock_firm_quote_high_precision()` | High-precision decimal amounts |

## Related tests

| Test | Location | Covers |
|---|---|---|
| `test_new_quote_is_active` | `tests/quote_lifecycle_tests.rs` | Quote state after submission |
| `test_invalidate_quote_changes_state` | same | Invalidation state transition |
| `quote_expired_at_exact_boundary_timestamp` | same | Expiry boundary (inclusive) |
| `quote_still_valid_one_second_before_expiry` | same | One second before boundary |
| `test_invalidated_quote_excluded_from_routing` | same | Routing skips invalidated quotes |
| `test_purge_expired_quotes_removes_stale_entries` | same | Purge behavior |
| `test_request_firm_quote_valid` | `src/sep38.rs` | Off-chain parsing happy path |
| `test_expired_quote_rejected` | same | `StaleQuote` error |
| `test_quote_at_exact_expiry_rejected` | same | Expiry boundary (off-chain) |
