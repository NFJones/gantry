# The `std.text` foundation

This note documents the pure text foundation `SPEC.md` Section 41 publishes: the canonical text
value, its admission from octets, its scalar count and canonical octets, its scalar-boundary
slicing, its two canonical normalization forms, its two full default case mappings over the pinned
Unicode 16.0.0 data, its forward scalar traversal, its canonical scalar comparison, its canonical
grapheme clusters, its bounded text matching, its declared canonical conversions, and an explicitly bounded text builder, over the scalar and octet contracts of
Section 35. It is documentation: it grants nothing, and where it and the specification differ the
specification decides.

## Declared clauses

| Clause | What it publishes |
| --- | --- |
| `GNT-41.0-text-foundation-scope` | the section scope, its purity, its model (`crates/gantry-ir/src/text.rs`) and evidence (`crates/gantry-conformance/tests/text_foundation.rs`, `crates/gantry-conformance/tests/text_normalization.rs`, `crates/gantry-conformance/tests/text_case_mapping.rs`, `crates/gantry-conformance/tests/text_builders.rs`, `crates/gantry-conformance/tests/text_traversal.rs`, `crates/gantry-conformance/tests/text_comparison.rs`, `crates/gantry-conformance/tests/text_graphemes.rs`, `crates/gantry-conformance/tests/text_matching.rs`, `crates/gantry-conformance/tests/text_conversions.rs`) paths, and its six frozen diagnostics |
| `GNT-41.1-canonical-text-values` | the canonical text value as a finite scalar sequence, exact UTF-8 admission, the scalar count and canonical octets, scalar-boundary slicing, and value immutability |
| `GNT-41.2-canonical-text-normalization` | the two canonical normalization forms of a text value over the pinned Unicode 16.0.0 data: Normalization Form D (`nfd`) and Normalization Form C (`nfc`), totality, idempotence, non-mutation, and the boundary that admission never normalizes |
| `GNT-41.3-canonical-text-case-mapping` | the two locale-independent full default case mappings of a text value over the pinned Unicode 16.0.0 data: the lowercase mapping (`lower`) and the uppercase mapping (`upper`), totality, per-scalar sequence order, and the boundary that a mapping is neither a case fold nor an identity |
| `GNT-41.4-canonical-text-builders` | the explicitly bounded text builder: a caller-declared octet bound, ordered and atomic appends refused under `text-builder-bound` without changing the builder, the accumulated sequence as the exact concatenation in append order, and a `build` that publishes one immutable value independent of later appends |
| `GNT-41.5-canonical-text-traversal` | forward scalar traversal: a cursor that publishes a value's scalars one at a time in sequence order with a remaining count, never publishes a partial scalar, never modifies the value, and holds no identity |
| `GNT-41.6-canonical-text-comparison` | the canonical three-way comparison of two text values that their identity already decides, published as `less`, `equal`, or `greater`: `equal` exactly when the values are equal, otherwise the first differing scalar decides, a proper prefix orders first, and the comparison is total, antisymmetric, transitive, case-sensitive, and never normalizes |
| `GNT-41.7-canonical-grapheme-clusters` | forward extended grapheme cluster segmentation over the pinned `Grapheme_Cluster_Break`, `Extended_Pictographic`, and `Indic_Conjunct_Break` data: a cursor that publishes each cluster as a text value in sequence order with a remaining count, an exact partition of the value's scalar sequence, no partial or empty cluster, and segmentation that never normalizes or case-maps the value it segments |
| `GNT-41.8-bounded-text-matching` | bounded pattern matching over admitted patterns: `Pattern::admit` under a caller-declared step budget, `is_match`, and the leftmost-longest `find_first` span as a `TextRange` (`start`, `end`, `is_empty`, `slice`), with exact admission and bound refusals (`text-pattern-syntax`, `text-pattern-bound`), atomic refusal when a match exhausts its budget (`text-match-budget`), and matching that never normalizes or case-maps |
| `GNT-41.9-canonical-text-conversions` | the declared explicit conversions: canonical UTF-16 code units and their exact admission (`from_utf16_code_units`, `utf16_code_units`), the total lossless octet-text mapping (`from_lossless_octets`, `lossless_octets`), round-trip exactness in both directions, and refusal of unpaired surrogates under `text-invalid-utf16` |

## Registered diagnostics

| Spelling | Owning clause | Condition |
| --- | --- | --- |
| `text-invalid-utf8` | `GNT-41.1-canonical-text-values` | an octet sequence is not well-formed UTF-8; the refusal names the zero-based octet index at which well-formed decoding fails |
| `text-builder-bound` | `GNT-41.4-canonical-text-builders` | appending one text value would push the builder past its declared octet bound; the refusal names the appended and accumulated octet counts and the bound, and the builder is unchanged |
| `text-pattern-syntax` | `GNT-41.8-bounded-text-matching` | a pattern construct is not admitted by the declared pattern syntax; the refusal names the scalar position at which admission failed |
| `text-pattern-bound` | `GNT-41.8-bounded-text-matching` | a pattern exceeds a declared pattern bound or the declared step budget is zero; the refusal names the bound |
| `text-match-budget` | `GNT-41.8-bounded-text-matching` | a match spent more steps than the declared step budget; no span, partial span, or prefix state is published |
| `text-invalid-utf16` | `GNT-41.9-canonical-text-conversions` | a code-unit sequence is not a well-formed UTF-16 encoding of scalar values; the refusal names the zero-based code-unit index of the lone or unpaired surrogate |

## Model surface (`crates/gantry-ir/src/text.rs`)

`TextValue::empty`, `TextValue::from_octets`, `TextValue::from_scalars`, `TextValue::scalar_count`,
`TextValue::canonical_octets`, `TextValue::is_empty`, `TextValue::scalar_at`, and
`TextValue::slice_scalars` publish exactly the value contract of
`GNT-41.1-canonical-text-values`, together with `TextDiagnosticCode` and `TextError` for its one
refusal. `TextValue::normalize` and `NormalizationForm` (`nfd`, `nfc`) publish exactly the two
canonical forms of `GNT-41.2-canonical-text-normalization`. `TextValue::map_case` and
`CaseMapping` (`lower`, `upper`) publish exactly the two full default case mappings of
`GNT-41.3-canonical-text-case-mapping`. `TextBuilder` (`with_octet_bound`, `octet_bound`, `len`,
`is_empty`, `append`, `build`) publishes exactly the bounded builder of
`GNT-41.4-canonical-text-builders`. `TextValue::scalars` and `TextScalars` (`next_scalar`,
`remaining`) publish exactly the forward cursor of `GNT-41.5-canonical-text-traversal`.
`TextValue::compare` and `TextOrdering` (`less`, `equal`, `greater`) publish exactly the canonical
comparison of `GNT-41.6-canonical-text-comparison`. `TextValue::graphemes` and `TextGraphemes` (`next_cluster`, `remaining`) publish exactly the forward extended grapheme cluster cursor of `GNT-41.7-canonical-grapheme-clusters`, whose clusters are decided by `gantry_core::unicode` `grapheme_cluster_boundaries` over the pinned data. `Pattern::admit`, `Pattern::steps`, `Pattern::is_match`, `Pattern::find_first`, `TextRange` (`start`, `end`, `is_empty`, `slice`), and the declared bounds `PATTERN_SCALAR_BOUND`, `PATTERN_REPEAT_BOUND`, and `PATTERN_INSTRUCTION_BOUND` publish exactly the bounded matching of `GNT-41.8-bounded-text-matching`. `TextValue::from_utf16_code_units`, `TextValue::utf16_code_units`, `TextValue::from_lossless_octets`, and `TextValue::lossless_octets` publish exactly the canonical conversions of `GNT-41.9-canonical-text-conversions`. `TEXT_CLAUSES` names the ten declared clause
anchors in specification order.

## Declared non-claims

The section declares no grapheme-cluster identity beyond the text-value identity of `GNT-41.1-canonical-text-values`, no word, sentence, or line segmentation, no case folding, no
collation or locale-aware comparison, no interpolation, no formatting,
parsing, or numbering of any type, no regular expression or matching contract, no locale value or
catalog, no boundary schema, no source text literal grammar, and no work limit, cancellation safe
point, quota, suspension, schema, recovery, durability, boundary encoding, lowering, machine
representation, or family behavior. Normalization is published only by
`GNT-41.2-canonical-text-normalization`, and only for the two canonical forms over the pinned
Unicode 16.0.0 data: no compatibility form, compatibility decomposition, case folding, or
full-width mapping is published, no form is inferred from a locale, and no `String` method is
added. Case mapping is published only by `GNT-41.3-canonical-text-case-mapping`, and only as the
locale-independent full default mappings: no locale-specific tailoring such as the Turkish or
Azeri mappings is published, no title case is published, no case-insensitive comparison or case
fold is published, and no `String` method is added. The section claims no performance, storage
layout, or physical representation. A builder is published only by
`GNT-41.4-canonical-text-builders`, and only as an explicitly bounded construction state: no
unbounded builder, no implicit or ambient builder, no builder identity, comparison, or ordering,
no builder sharing mutable storage with another builder or with a published value, and no partial
publication is published, and the declared octet bound is a semantic limit of that construction
state rather than a quota, a resource-accounting contract, a work limit, or a cancellation safe
point. Traversal is published only by `GNT-41.5-canonical-text-traversal`, and only as forward
scalar traversal: no grapheme-cluster segmentation, no backward or random-access traversal, and no
cursor identity, comparison, ordering, serialization, or durability is published. Comparison is
published only by `GNT-41.6-canonical-text-comparison`, and only as the canonical scalar
comparison: no locale-aware collation or ordering, no comparison that consults a locale, a catalog,
or host collation data, no case-insensitive or fold-based comparison, no comparison that normalizes
its operands first, and no collation or sort keys are published. Grapheme clusters are published only by `GNT-41.7-canonical-grapheme-clusters`, and only as forward extended grapheme cluster segmentation: no cluster identity beyond the text-value identity, no word, sentence, or line segmentation, no tailoring, dictionary, or locale-aware segmentation, no normalization or case mapping before segmentation, and no work limit or cancellation safe point is published. Bounded matching is published only by `GNT-41.8-bounded-text-matching`, and only as matching over the declared pattern syntax: no host regular-expression semantics, no capture groups, captures, backreferences, or replacement template, no anchors or lookaround, no case-insensitive, locale-aware, or Unicode-property matching, no matching that normalizes or case-maps first, no streaming, incremental, or resumable match, no cancellation safe point or suspension, no work, memory, or time limit beyond the declared step budget, and no resource accounting, quota, or release rule is published. Canonical conversions are published only by `GNT-41.9-canonical-text-conversions`: no byte-order-mark handling, no platform, code-page, or locale encoding, no lossy or replacement-character conversion, no UTF-32 or platform-allocation conversion, no normalization or case mapping during conversion, no streaming or partial conversion, no codec or serialization contract, and no work limit or cancellation safe point is published.

## Declared ownership and handoff

The clauses this section publishes, in specification order: `GNT-41.0-text-foundation-scope`, `GNT-41.1-canonical-text-values`, `GNT-41.2-canonical-text-normalization`, `GNT-41.3-canonical-text-case-mapping`, `GNT-41.4-canonical-text-builders`, `GNT-41.5-canonical-text-traversal`, `GNT-41.6-canonical-text-comparison`, `GNT-41.7-canonical-grapheme-clusters`, `GNT-41.8-bounded-text-matching`, and `GNT-41.9-canonical-text-conversions`; every one of them is review-closed in the reviewed requirement ledger, and the declared diagnostics of the section are `text-invalid-utf8`, `text-builder-bound`, `text-pattern-syntax`, `text-pattern-bound`, `text-match-budget`, and `text-invalid-utf16`.

| Family item | Owning surface | State |
| --- | --- | --- |
| scalar and grapheme traversal, normalization, case mapping, builders, comparison | this section, `GNT-41.1-canonical-text-values` through `GNT-41.8-bounded-text-matching` | published |
| explicit UTF-8, UTF-16, and lossless octet conversions | this section, `GNT-41.9-canonical-text-conversions` | published |
| numeric parsing and formatting | `std.num`, `GNT-40.6-canonical-numeric-text` | published outside this section |
| civil-time formatting and parsing | `TIME-001` (`4cf122ef`) | owned elsewhere, open |
| locale-aware collation, number and date formatting, plural selection, and message formatting | explicit locale and time packages | owned elsewhere |
| cancellation safe points, memory and time limits beyond a declared bound or budget, resource accounting and quotas, suspension, durable continuation, and codec or serialization contracts | `RESOURCE-001` (`926a4a0f`) with the Phase 1 gate `GATE-200` (`916d98cf`) | gated |
| family interface rows and publication membership | `STDLIB-001` (`f3908168`) or `PUB-001` (`624db3b4`) | gated |

Every clause of this section is pure and target-independent: no clause consults a host locale, host encoding, host regular-expression behavior, host math library, ambient time, or global mutable state. Only two kernels of the section declare an exact bound or budget: the octet bound of `GNT-41.4-canonical-text-builders` and the pattern bounds with the match step budget of `GNT-41.8-bounded-text-matching`; the admission refusals of `GNT-41.1-canonical-text-values` and `GNT-41.9-canonical-text-conversions` are exact validity rules for their inputs, not work limits. Every other input-dependent kernel of the section — admission and slicing, normalization, case mapping, scalar and grapheme traversal, and comparison — publishes no work limit and no cancellation safe point, so the exact limits and safe points that this issue's completion statement requires for those kernels remain gated on the runtime owners named above, and this record is their retry condition. Beyond the builder's octet bound and the matcher's pattern bounds and step budget, the section publishes no memory or time limit, no resource accounting or quota, no suspension, no durable continuation, and no codec or serialization contract; those remain the runtime's contracts under the owners named above.

