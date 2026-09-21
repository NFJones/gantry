# The `std.text` foundation

This note documents the pure text foundation `SPEC.md` Section 41 publishes: the canonical text
value, its admission from octets, its scalar count and canonical octets, and scalar-boundary
slicing, over the scalar and octet contracts of Section 35. It is documentation: it grants
nothing, and where it and the specification differ the specification decides.

## Declared clauses

| Clause | What it publishes |
| --- | --- |
| `GNT-41.0-text-foundation-scope` | the section scope, its purity, its model (`crates/gantry-ir/src/text.rs`) and evidence (`crates/gantry-conformance/tests/text_foundation.rs`) paths, and its one frozen diagnostic |
| `GNT-41.1-canonical-text-values` | the canonical text value as a finite scalar sequence, exact UTF-8 admission, the scalar count and canonical octets, scalar-boundary slicing, and value immutability |

## Registered diagnostic

| Spelling | Owning clause | Condition |
| --- | --- | --- |
| `text-invalid-utf8` | `GNT-41.1-canonical-text-values` | an octet sequence is not well-formed UTF-8; the refusal names the zero-based octet index at which well-formed decoding fails |

## Model surface (`crates/gantry-ir/src/text.rs`)

`TextValue::empty`, `TextValue::from_octets`, `TextValue::from_scalars`, `TextValue::scalar_count`,
`TextValue::canonical_octets`, `TextValue::is_empty`, `TextValue::scalar_at`, and
`TextValue::slice_scalars` publish exactly the value contract of
`GNT-41.1-canonical-text-values`, together with `TextDiagnosticCode` and `TextError` for its one
refusal. `TEXT_CLAUSES` names the two declared clause anchors in specification order.

## Declared non-claims

The section declares no grapheme-cluster segmentation or cluster identity, no normalization, no
case mapping or folding, no collation or locale-aware comparison, no text builder or
interpolation, no formatting, parsing, or numbering of any type, no regular expression or matching
contract, no Unicode data version, no locale value or catalog, no boundary schema, no source text
literal grammar, and no work limit, cancellation safe point, quota, suspension, schema, recovery,
durability, boundary encoding, lowering, machine representation, or family behavior. It claims no
performance, storage layout, or physical representation.
