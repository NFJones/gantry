# Canonical protocol inputs

This directory is the checked-in source of truth for Gantry protocol inputs.
Rust bindings are generated one way from these files; Rust types and derives
must never be used to recreate or redefine them.

- `catalogs/` contains closed vocabularies and dependency catalogs.
- `schemas/` contains their versioned JSON Schemas.
- `goldens/` contains exact canonical encodings and negative fixtures.
- `publication/` contains inputs used to assemble, but not impersonate, a
  complete publication index.

Run `cargo run --locked -p xtask -- generate protocol` after an approved input
change. Run `cargo run --locked -p xtask -- check generated` to verify that all
checked-in outputs match their canonical inputs without modifying the tree.
Every protocol change requires explicit version, schema, golden, generated
binding, and publication-impact review.
