# Collection key contract and canonical collection order

`SPEC.md` Section 39 (`GNT-39.0` .. `GNT-39.8`) fixes the key contract and the collection type
identities a source collection consumes: the admitted key domain, the canonical order, duplicate-key
identity, the identities of the recognised `Map<K, V>`, `Set<K>`, and `Range<T>` forms, the sealed
range step contract, and the `Map`, `Set`, and `Range` value model. The pure model
is `crates/gantry-ir/src/collections.rs`, published through `gantry::ir`, and its machine-checked
evidence is `crates/gantry-conformance/tests/collections_foundation.rs`, one lane per claim. This
note is documentation: it names what the model declares and what it refuses, and it grants nothing.

The section admits no source collection value, operation, or collection API and no collection type
whose form `GNT-39.4-map-type-form-recognition` does not recognise, and it claims no range stepping,
iterator ownership or invalidation, traversal, mutation, exhaustion, suspension, quota, schema,
recovery, or durable behavior. The canonical scalar-key contract it consumes is documented
separately in `docs/canonical-scalar-keys.md`.

## Declared clauses

| Clause anchor | What it owns |
| --- | --- |
| `GNT-39.0-collection-key-and-order-scope` | the section scope, its frozen diagnostics, and the boundary against `GNT-5.15-canonical-scalar-keys` |
| `GNT-39.1-admitted-collection-keys` | the admitted key domain and the refusal that names the refused kind |
| `GNT-39.2-canonical-collection-order-and-duplicate-identity` | the canonical order and identity-based duplicate rejection |
| `GNT-39.3-collection-foundation-non-claims` | the frozen non-claims listed below |
| `GNT-39.4-map-type-form-recognition` | the three recognised collection type forms, `Map<K, V>`, `Set<K>`, and `Range<T>`, admitted as constructed value types, and the positions where their `collection-type-unadmitted` refusal still applies |
| `GNT-39.5-map-type-identity` | the identity of the recognised form: its two argument types in order, the five admitted key types, and the key-domain refusal of every other resolved key argument |
| `GNT-39.6-set-and-range-type-identities` | the `Set<K>` element identity over the same five admitted key types and the `Range<T>` element identity over any admitted value type that names no collection type anywhere inside it, with their canonical texts and refusals |
| `GNT-39.7-range-step-contract` | the sealed step contract: exactly `Int` steps, by one value toward the bound with checked arithmetic, under an inclusive start bound and an exclusive end bound |
| `GNT-39.8-collection-value-model` | the admitted `Map` and `Set` values (finite entries or elements over the five admitted key types, in canonical collection order, with repeated keys refused as `collection-duplicate-key`) and the admitted `Range` value (two bound positions under the sealed step contract of `GNT-39.7`) |

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
- The grammar recognises exactly three collection type forms (`GNT-39.4`): `Map<K, V>` with two
  value-type arguments, and `Set<K>` and `Range<T>` with one each; analysis builds no descriptor
  or type expression for any of them, so no collection value, operation, lowering, or machine
  representation exists in this edition, and every malformed argument list is refused by the
  grammar.
- `MapTypeIdentity::admit` publishes the identity of the recognised form (`GNT-39.5`): the key
  argument then the value argument, rendered as the canonical constructed-type text `Map<K,V>` over
  the canonical text of each argument. `CollectionKeyType::from_descriptor` admits exactly the five key
  types of `GNT-39.1` — `Unit`, `Bool`, `Int`, `Float`, `String` — and refuses every other resolved
  key argument as `collection-invalid-key`, naming the refused argument (`List<Int>`,
  `Result<Int,String>`, `Decision`, or a declared type), before the clause-owned
  `collection-type-unadmitted` refusal; an
  occurrence whose key argument is admitted is admitted as the identity's constructed value type,
  while an occurrence whose key argument or value argument resolves to no type at all (an unresolved
  name or a type parameter), whose annotation appears in a boundary or signature position, or whose
  value member names a collection type the identity refuses, is refused as
  `collection-type-unadmitted` and publishes no fact or descriptor. The same canonical text is exact in both directions:
  `MapTypeIdentity::from_canonical_text` admits exactly the five key member texts and the canonical
  text of one admitted value type, refuses a key member of any other type as `collection-invalid-key`
  naming the whole refused member before the general rule (even when the text is also non-canonical
  or carries a member this edition does not admit), and refuses every other non-canonical or
  unadmitted text — including a nested `Map` in value position — as `collection-type-unadmitted`.
  `MapTypeIdentity::admit` applies that same member rule to resolved arguments, so an admitted
  identity and a refused one are one decision on both paths, and a value member that names a
  collection type at any depth — the member itself, or a collection inside a member of any other
  kind — is unadmitted.
- `SetTypeIdentity::admit` publishes the `Set<K>` element identity (`GNT-39.6`): a set element is a
  collection key, so exactly the five key types of `GNT-39.1` are admitted, and the shared key
  vocabulary — `CollectionKeyType::classify` for a member text and `from_descriptor` for a resolved
  descriptor — refuses every other element as `collection-invalid-key`
  naming the whole refused argument, applying the key rule first exactly as the `Map` key rule does —
  even when the member text is also non-canonical or carries a member this edition does not admit —
  and any other text that is not the canonical rendering of one identity is refused as
  `collection-type-unadmitted`. `RangeTypeIdentity::new` publishes the `Range<T>` element identity
  over any admitted value type that names no collection type anywhere inside it, and publishes no
  stepping, bounds, ordering, or iteration rule: the constructor applies the identity's one member
  rule, which its decoder applies too, so a collection element at any depth is refused as
  `collection-type-unadmitted` on both paths, and the decoder admits exactly the canonical text of
  one such type and has no key-domain path, so `Range<Decision>` is a legitimate identity while
  `Range<Missing>` and `Range<Map<Int,String>>` are refused. Both identities render as `Set<K>` and
  `Range<T>` over the canonical text of the argument.
- The three collection kinds are published by the closed type-kind vocabulary of the canonical-IR
  contract: `Map`, `Set`, and `Range` are appended after `Never`, each citing the clause that
  identifies it (`GNT-39.5`, `GNT-39.6`), and the type algebra constructs, renders, and decodes the
  three canonical descriptors exactly. `TypeDescriptor::map`, `set`, and `range` apply each
  identity's own member rule: a key member outside the key domain is refused as
  `TypeDescriptorError::InvalidCollectionKey`, and an unadmitted collection member as
  `TypeDescriptorError::InvalidCollectionMember`, so the algebra reports which clause refused.
  Every collection kind is structural, carrying no independent primitive properties, and none
  admits a value: the kinds are vocabulary and descriptor algebra only.
- `RangeStepContract::sealed` publishes the sealed step contract (`GNT-39.7`): exactly `Int` admits
  stepping in this edition, `successor` and `predecessor` are the element type's checked steps over
  the canonical `Int` range, and `forward_within` and `backward_within` report whether the step from
  the value lands strictly below the exclusive end bound or at or above the inclusive start bound,
  so the step that lands on the exclusive end bound, crosses the inclusive start bound, or leaves the
  canonical value range is exhaustion rather than a refusal, a wrap, or a trap. The contract is sealed: no package, adapter, host, or later declaration
  may define, extend, override, or infer one, and the clause publishes no traversal, iteration, loop
  integration, an exhaustion diagnostic, mutation, quota, schema, recovery, durability, lowering,
  or machine representation, and admits no `Range` value of its own — the `Range` type identity
  belongs to `GNT-39.6` and the value model to `GNT-39.8`.
- `MapValue::admit` and `SetValue::admit` publish the two keyed value models (`GNT-39.8`): a `Map`
  value is its finite entries and a `Set` value its finite elements, every candidate admitted under
  the key contract of `GNT-39.1`, a repeated key refused as `collection-duplicate-key` before
  anything is published, and the admitted entries or elements published in the canonical collection
  order of `GNT-39.2`, so a value's observable content is that order, two values with equal entries
  are one value whatever order their candidates arrived in, and an empty value is admitted rather
  than special-cased. `RangeValue::new` publishes the `Range` value over its two bound positions and
  is total over `Option<GantryInt>`: `start` and `end` report the bounds, `admits` is the bound rule
  — at or above the inclusive start bound and strictly below the exclusive end bound — while
  `forward` and `backward` are the sealed contract's result-side rule followed by the checked step,
  so a step is reported for a source position the value does not admit, and a value whose start
  bound is not less than its end bound admits no position while no rule refuses it. No value model
  publishes traversal, iteration, mutation, ownership, invalidation, an exhaustion diagnostic,
  quotas, schemas, recovery, durability, boundary encoding, lowering, or machine representation:
  a step reports exhaustion to its caller only as the absence of a step.
  The value-layer accounting of the model (`GNT-39.8`): the value is one aggregate node, a `Map`
  entry is one node for its admitted key plus the nodes of the value that key resolves to, a `Set`
  element is one node, and a bound position is one node — all charged against the carrying layer's
  own node and nesting budgets, which refuse over-budget content under that layer's resource-limit
  refusal; this section publishes no per-collection bound and no charge.

## Diagnostics

| Spelling | Owning clause | Condition |
| --- | --- | --- |
| `collection-invalid-key` | `GNT-39.1-admitted-collection-keys` | the candidate kind, or a recognised `Map` key or `Set` element argument, is not an admitted collection key |
| `collection-duplicate-key` | `GNT-39.2-canonical-collection-order-and-duplicate-identity` | two admitted keys share one identity in one batch |
| `collection-non-claim-as-guarantee` | `GNT-39.3-collection-foundation-non-claims` | a declared non-claim is unasserted or presented as a guarantee |
| `collection-type-unadmitted` | `GNT-39.4-map-type-form-recognition` | a recognised collection type form's argument resolves to no type, its annotation is a boundary or signature position, or its value member names a collection type the owning identity refuses |

## Declared non-claims

- no source collection value, operation, or collection API
- no range stepping, iterator ownership or invalidation, traversal, mutation, exhaustion, suspension, quotas, schemas, recovery, or durable behavior
- no family behavior
- no storage layout or physical representation
- no performance claim
- no boundary encoding beyond the canonical key frame
