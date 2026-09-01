# Canonical protocol inputs

This directory is the checked-in source of truth for Gantry protocol inputs.
Rust bindings are generated one way from these files; Rust types and derives
must never be used to recreate or redefine them.

- `catalogs/` contains closed vocabularies and dependency catalogs.
- `schemas/` contains their versioned JSON Schemas.
- `goldens/` contains exact canonical encodings and negative fixtures.
- `publication/` contains inputs used to assemble, but not impersonate, a
  complete publication index.
- `conformance/` contains digest-bound gate evidence assembled from canonical
  inputs and independently checked public surfaces.
- `requirements/` contains reviewed normative-span, applicability, clause,
  and Section 14 excerpt classifications plus their generated digest inventory.

Run `cargo run --locked -p xtask -- generate protocol` after an approved input
change. Run `cargo run --locked -p xtask -- check generated` to verify that all
checked-in outputs match their canonical inputs without modifying the tree.
Every protocol change requires explicit version, schema, golden, generated
binding, and publication-impact review.

Analyzer/runtime contract inputs live in `catalogs/ir-contracts-v1.json`.
Its canonical catalog golden and generated Rust binding freeze closed IR,
generic type-expression, analysis-fact, executable-fact, and template-kind
vocabularies. The canonical IR schema admits ordinal-based open expressions
only in analysis-template records and requires the distinct executable
projection to contain closed descriptors and direct callable identities. The
source-map schema separately carries sorted, deduplicated multi-origin records
for interned concrete nodes; source spans do not participate in canonical IR
identity. The four artifact schemas and
`goldens/ir-artifact-vectors-v1.json` separately freeze canonical IR,
source-map, package-source-manifest, and generated-schema-object encodings.
`conformance/generics-traits-ir-v1.json` records only this bounded contract
slice; analyzer solving, runtime execution, and durable reconstruction remain
with their owning issues.

Module-graph, symbol, import-resolution, no-shadowing, and Unicode-security
evidence is recorded separately in `conformance/analyzer-symbols-v1.json`.
That manifest covers only the clauses exercised through the public analyzer
facade. Type and receiver evidence is recorded in
`conformance/analyzer-types-v1.json`; it likewise covers only clauses exercised
through the public analyzer facade. Ownership, effects, generated schemas, and
workflow/action/entry inventories are recorded in
`conformance/analyzer-workflows-v1.json`. Canonical lowering, source-map and
package-manifest boundaries, portable artifact limits, prompt phases, and
identity evidence are recorded in `conformance/analyzer-lowering-v1.json`.
Public `AnalyzePackage` sequencing, parse/analysis activity events, optional
delivery barriers, source judgments, bounded artifact exposure, and the
external facade boundary are recorded in
`conformance/analyzer-package-v1.json`.
The profile-scoped written argument and bounded six-obligation model are bound
by `conformance/analyzer-validity-v1.json`, with reviewed replay inputs in
`goldens/analyzer-validity-model-v1.json`. The model states its assumptions and
bounds explicitly and is not presented as an exhaustive proof over all source.

The nondurable evaluator's written refinement argument, bounded lifecycle and
operation model, invalid-trace replay, and exact public trace links are bound by
`conformance/sequential-evaluator-refinement-v1.json`, with reviewed model data
in `goldens/sequential-evaluator-model-v1.json`. Genuine host waits, fairness
assumptions, concurrency exclusions, and recovery exclusions remain explicit.

Portable value-kernel vectors in `goldens/value-kernel-v1.json` exercise the
Gantry-owned strict JSON decoder, exact numeric normalization and primitives,
generated-schema validator, RFC 8785 encoding, and exact SHA-256 boundary. The
paired `schemas/value-kernel-v1.schema.json` freezes that vector envelope, and
`conformance/value-kernel-v1.json` maps the implemented portable subset to its
profile-specific reviewed clauses without closing later runtime obligations.

Persistent-value vectors in `goldens/persistent-values-v1.json` exercise
immutable logical values, representation-independent equality, hashing and
canonical bytes, atomic path-copy replacement, exact per-value limits,
generated-schema validation, thread-safe sharing, and depth-safe copy and
reclamation. The paired `schemas/persistent-values-v1.schema.json` freezes the
vector envelope, while `conformance/persistent-values-v1.json` deliberately
maps only the directly exercised automatic-storage clauses; runtime retention,
transcript, journal, recovery, and host-exhaustion obligations remain with
their owning issues.

Sequential-machine vectors in `goldens/sequential-machine-v1.json` exercise
the public explicit-frame runtime, deep workflow calls, typed bindings and
atomic root replacement, deterministic primitives and failure codes, finite
budgets, cancellation nonconsumption, stable dynamic operation paths, and the
base root settlement/foreground/terminal sequence. The paired
`schemas/sequential-machine-v1.schema.json` freezes the vector envelope, while
`conformance/sequential-machine-v1.json` maps only evaluator clauses directly
covered by this foundation; host dispatch, complete operation policy,
concurrent scheduling, durability, and profile closeout remain with later
issues.

Executor-service vectors in `goldens/executor-services-v1.json` freeze checked
whole-microsecond bounds, inclusive jitter endpoints, deadline outcomes,
executor failure classification, and the caller-owned Tokio runtime variants.
The paired `schemas/executor-services-v1.schema.json` freezes only that narrow
envelope, while `conformance/executor-services-v1.json` records direct public
contract and adapter evidence. Evaluator composition, concurrent spawn/join/
abort, durable persistence, and provider-specific timeout behavior remain with
their owning issues.

Diagnostic fixtures deliberately separate machine contracts from presentation:
`goldens/diagnostic-machine-v1.json` freezes structured fields and spans, while
`goldens/diagnostic-presentation-v1.json` freezes terminal text and its explicit
source-disclosure variants. There is no command that rewrites either fixture.
Update them manually, review the machine fixture independently before changing
presentation wording, and run
`cargo test --locked -p gantry-conformance --test diagnostic_presentation`.
The conformance test contains stable assertions for portable fields so a
presentation-only update cannot silently rename a code, category, severity, or
repair field.

Run `cargo run --locked -p xtask -- generate requirements` only after reviewing
the complete `SPEC.md` revision and updating the requirement sidecars. Any
specification-byte change invalidates the recorded review digest.

Each reviewed clause has one `profile_reviews` entry for every profile in its
applicability list, in the same canonical order. Status, executable evidence,
and any exclusion rationale belong to that profile entry rather than to the
clause globally. This permits an earlier profile to close without claiming
unfinished behavior owned by a later profile. A covered profile review requires
at least one evidence anchor; `not-applicable` and `unresolved` reviews require
an explicit profile-based rationale.
