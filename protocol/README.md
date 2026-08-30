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
