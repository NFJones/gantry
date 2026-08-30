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
Its canonical catalog golden and generated Rust binding freeze the closed IR
vocabularies. The four artifact schemas and `goldens/ir-artifact-vectors-v1.json`
separately freeze canonical IR, source-map, package-source-manifest, and
generated-schema-object encodings; `conformance/analyzer-ir-v1.json` records
only the analyzer clauses covered by the public contract suite.

Module-graph, symbol, import-resolution, no-shadowing, and Unicode-security
evidence is recorded separately in `conformance/analyzer-symbols-v1.json`.
That manifest covers only the clauses exercised through the public analyzer
facade; typing, ownership/effects, lowering, artifacts, and package validity
remain owned by later analyzer issues.

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
