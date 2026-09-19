# Standard-library architecture

This note records the canonical logical standard-library hierarchy declared by
`canonical_pure_hierarchy` in `crates/gantry-ir/src/stdlib.rs`, and the edition prelude
that accompanies it. It summarises `SPEC.md` Section 34; the specification is normative
and this note is descriptive.

## Pure hierarchy

The pure families are `std.core` (the foundational root, `StabilityTier::Foundational`)
and the stable families that build on it: `std.collections`, `std.text`, `std.num`,
`std.codec`, `std.crypto`, and `std.data`.

Dependency edges follow the reviewed roadmap and are enforced from the canonical package
declarations (`GNT-34.3-acyclic-internal-dependency-dag`):

- `std.collections` and `std.num` depend only on `std.core`;
- `std.text` may additionally depend on `std.collections`;
- `std.codec` may depend on `std.core`, `std.collections`, and `std.text`;
- `std.crypto` may depend on `std.core`, `std.num`, and `std.codec`;
- `std.data` may depend on `std.core`, `std.collections`, `std.text`, and `std.codec`.

A pure family never depends on a capability-backed family, and no standard package
depends on a host adapter. Physical Rust crate layout is nonsemantic: splitting or
combining crates does not change logical source identity
(`GNT-34.8-defining-identity-and-interface-digest`).

The declaration carries package identities, applicability, and edges, plus the two
enumerated prelude items of `std.core` (the explicit exception below). Every other item
belongs to the family that owns its API surface, so the non-core families declare no
items yet: `std.collections`, for example, declares none until its collection API rows are
normative (`GNT-GP-COLL-001`).

## Edition prelude

The automatic prelude is one closed, edition-versioned, enumerated set
(`GNT-34.4-edition-prelude-and-explicit-imports`). Edition `2026` enumerates exactly the
foundational `std.core` items `std.core::option` and `std.core::result`; adding or removing
a member is an edition change with exact compatibility consequences, and an implicit
wildcard import is refused.

## Evidence

- Model and declaration: `crates/gantry-ir/src/stdlib.rs` (`canonical_pure_hierarchy`,
  `StdPackage`, `StdItem`, `Prelude`, `StdGraph`).
- Machine-checked conformance: `crates/gantry-conformance/tests/stdlib_architecture.rs`
  (`canonical_pure_hierarchy_declares_each_pure_family_once`).
- Refusals: `std-invalid-package-name`, `std-duplicate-package`,
  `std-invalid-name-classification`, `std-unknown-edge`, `std-dependency-cycle`,
  `std-pure-to-capability-edge`, `std-package-to-adapter-edge`,
  `std-unenumerated-prelude-member`, `std-wildcard-prelude-refused`,
  `std-facade-identity-loss`, `std-invalid-stability-transition`,
  `std-unsupported-applicability`, `std-feature-mutates-instance`,
  `std-layout-derived-identity`, `std-contract-version-mismatch`,
  `std-invalid-relocation`, `std-publication-drift`, and `std-non-claim-as-guarantee`.

## Non-claims

The declaration resolves, downloads, loads, generates, links, and publishes nothing; it
introduces no family behavior, no package downloader, no generator, and no publication
mechanism. Family APIs and capability-backed packages remain the responsibility of the
issues that own them.
