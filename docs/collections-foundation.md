# Collection key contract and canonical collection order

`SPEC.md` Section 39 (`GNT-39.0` .. `GNT-39.3`) fixes the key contract a source collection
consumes: the admitted key domain, the canonical order, and duplicate-key identity. The pure model
is `crates/gantry-ir/src/collections.rs`, published through `gantry::ir`, and its machine-checked
evidence is `crates/gantry-conformance/tests/collections_foundation.rs`, one lane per claim. This
note is documentation: it names what the model declares and what it refuses, and it grants nothing.

The section admits no collection type yet. `Map`, `Set`, and `Range`, traversal, iterators, quotas,
schemas, and durability remain later phases of the owning issue, and the canonical scalar-key
contract itself is documented separately in `docs/canonical-scalar-keys.md`.

## Declared clauses

| Clause anchor | What it owns |
| --- | --- |
| `GNT-39.0-collection-key-and-order-scope` | the section scope, its frozen diagnostics, and the boundary against `GNT-5.15-canonical-scalar-keys` |
| `GNT-39.1-admitted-collection-keys` | the admitted key domain and the refusal that names the refused kind |
| `GNT-39.2-canonical-collection-order-and-duplicate-identity` | the canonical order and identity-based duplicate rejection |
| `GNT-39.3-collection-foundation-non-claims` | the frozen non-claims listed below |

## What the model decides

- A collection key is exactly one admitted canonical scalar key of format version 1.0: normalized
  `Unit`, `Bool`, `Int`, finite normalized `Float`, or `String`. `CollectionKeyPolicy::admit`
  delegates the domain to `gantry_core::canonical_key`, so an admitted key carries the canonical
  frame, identity, and stable content hash unchanged and gains no hashability of its own.
- A candidate of any other kind — `Decision`, `OperationError`, an option or result value, a list, a
  tuple, a struct, an enum, or any other ineligible kind — is refused as `collection-invalid-key`,
  naming the refused kind. Nothing is coerced, encoded structurally, or admitted through an
  application codec.
- Refusals the canonical scalar-key contract owns pass through unchanged as
  `CollectionKeyRefusal::Canonical`, so no refusal spelling is shared between the two contracts.
  The reachable case through this policy is the canonical byte limit: framing, length, scalar-range,
  and UTF-8 violations cannot arise from an already-normalized logical value.
- `canonical_order` is the admitted logical value order — `Unit < Bool < Int < Float < String`,
  `false` before `true`, `Int` and `Float` numerically and independently, `String`
  lexicographically — and equality is value equality, so normalized signed zeros have one `Float`
  key. Frame-byte order is not the contract.
- `CollectionKeyPolicy::admit_batch` admits every candidate in input order and refuses a batch whose
  admitted keys do not have unique identity as `collection-duplicate-key`, reporting the zero-based
  first and first-repeated input indices; it publishes no output unless every key is admitted and
  every identity is unique.
- `check_collection_non_claims` refuses an unasserted declared non-claim and a non-claim presented
  as a guarantee, both under `collection-non-claim-as-guarantee`.

## Diagnostics

| Spelling | Owning clause | Condition |
| --- | --- | --- |
| `collection-invalid-key` | `GNT-39.1-admitted-collection-keys` | the candidate kind is not an admitted collection key |
| `collection-duplicate-key` | `GNT-39.2-canonical-collection-order-and-duplicate-identity` | two admitted keys share one identity in one batch |
| `collection-non-claim-as-guarantee` | `GNT-39.3-collection-foundation-non-claims` | a declared non-claim is unasserted or presented as a guarantee |

## Declared non-claims

- no source collection type or collection API
- no range, iterator, traversal, quota, schema, recovery, or durable behavior
- no family behavior
- no storage layout or physical representation
- no performance claim
- no boundary encoding beyond the canonical key frame
