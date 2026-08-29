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

Run `cargo run --locked -p xtask -- generate requirements` only after reviewing
the complete `SPEC.md` revision and updating the requirement sidecars. Any
specification-byte change invalidates the recorded review digest.
