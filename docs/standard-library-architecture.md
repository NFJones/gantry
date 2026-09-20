# Standard-library architecture

This note records the canonical logical standard-library hierarchy declared by
`canonical_pure_hierarchy` in `crates/gantry-ir/src/stdlib.rs`, and the edition prelude
that accompanies it. It summarises `SPEC.md` Section 34; the specification is normative
and this note is descriptive.

## Pure hierarchy

### Declared clauses

`STDLIB_CLAUSES` in `crates/gantry-ir/src/stdlib.rs` declares the anchors of `SPEC.md` Section 34,
in specification order:

| Clause anchor | What it owns |
| --- | --- |
| `GNT-34.0-standard-library-package-architecture` | the section scope: an analyzer-only declaration model for the canonical logical hierarchy, its internal dependency DAG, its edition prelude, facade identity, stability tiers, applicability, and contract versioning |
| `GNT-34.1-canonical-hierarchy-and-package-names` | the canonical hierarchy — the exact pure and capability-backed logical families — and package-name syntax with its malformed, non-rooted, and duplicate refusals |
| `GNT-34.2-name-classification` | the closed name classes and the classification each name receives |
| `GNT-34.3-acyclic-internal-dependency-dag` | the acyclic internal dependency DAG and which edges a pure family may declare |
| `GNT-34.4-edition-prelude-and-explicit-imports` | the closed per-edition prelude and explicit imports; no glob import and no implicit transitive access |
| `GNT-34.5-facade-and-reexport-identity` | facade and re-export paths preserve the defining package identity |
| `GNT-34.6-stability-tiers` | stability tiers and the admitted transitions between them |
| `GNT-34.7-applicability-and-feature-granularity` | target and mode applicability, and feature granularity |
| `GNT-34.8-defining-identity-and-interface-digest` | defining identity and the interface digest; repository layout is never identity |
| `GNT-34.9-standard-library-contract-versioning` | contract versions and their compatibility consequences |
| `GNT-34.10-relocation-and-deprecation` | relocation and deprecation rules |
| `GNT-34.11-aggregate-manifests-and-publication-inputs` | aggregate manifests and the publication inputs built from them |
| `GNT-34.12-standard-library-architecture-non-claims` | the frozen non-claims, listed below |

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

The enumeration is a declaration, and name resolution in this tree does not consult it:
source lookup admits the compiler's reserved built-in type words, so compiler prelude
injection is not implemented and a member here neither injects nor withholds a source
name yet.
An ordinary standard-package import such as `use std::core::option;` is refused with
`unresolved-import`, so the model-level `std-unenumerated-prelude-member` refusal is a
declaration check rather than a source diagnostic.

## Compiler-owned vocabulary

The enumeration is not the only source of automatic names. The compiler front end reserves the
following capitalized spellings, and the analyzer resolves them without any package declaration:

- type words: `Unit`, `Bool`, `Int`, `Float`, `String`, `List`, `Tuple`, `Never`, `Decision`,
  `OperationError`, `Option`, `Result`, where `Never` is additionally refused at entry and
  action boundary declarations with `never-boundary-refused` and in signature positions with
  `never-signature-refused`;
- constructor spellings: `Some`, `None`, `Ok`, `Err`;
- the contextual type word `Self`.

These spellings are owned by the compiler — the front-end reserved-word table and the analyzer's
built-in type descriptors — not by any `std` package: the hierarchy above declares no item for
them, and no package identity, interface digest, or facade path defines them. They are therefore
a third automatic source beside the declared prelude members and explicit imports, and renaming
or removing one is a compiler change rather than an edition change.

## Evidence

- Model and declaration: `crates/gantry-ir/src/stdlib.rs` (`canonical_pure_hierarchy`,
  `StdPackage`, `StdItem`, `Prelude`, `StdGraph`).
- Machine-checked conformance: `crates/gantry-conformance/tests/stdlib_architecture.rs`
  (`canonical_pure_hierarchy_declares_each_pure_family_once`).
- Note-binding lanes: `crates/gantry-conformance/tests/stdlib_architecture.rs`
  (`standard_library_architecture_note_discloses_the_prelude_resolution_boundary`,
  `standard_library_architecture_note_separates_compiler_owned_type_words`).
- Source boundary of the enumerated members:
  `crates/gantry-conformance/tests/analyzer_types.rs`
  (`edition_prelude_source_boundary_matches_the_enumerated_declaration`) pins the built-in
  spelling boundary and the refused standard-package import.
- Refusals: `std-invalid-package-name`, `std-duplicate-package`,
  `std-invalid-name-classification`, `std-unknown-edge`, `std-dependency-cycle`,
  `std-pure-to-capability-edge`, `std-package-to-adapter-edge`,
  `std-unenumerated-prelude-member`, `std-wildcard-prelude-refused`,
  `std-facade-identity-loss`, `std-invalid-stability-transition`,
  `std-unsupported-applicability`, `std-feature-mutates-instance`,
  `std-layout-derived-identity`, `std-contract-version-mismatch`,
  `std-invalid-relocation`, `std-publication-drift`, and `std-non-claim-as-guarantee`.

## Non-claims

The declaration is a claim about architecture only. Its declared non-claims are:

- No adapter presence: the model declares packages and claims nothing about the existence of any
  adapter.
- No capability or provider existence: declaring a capability package promises no implementation.
- No documentation rendering: documentation generation and publication are downstream owners.
- No durable execution: durability contracts remain owned by other sections.
- No family behavior: this section declares architecture and implements none of the families it
  names.
- No permanently frozen prelude: the prelude is closed per edition and may change with an edition
  transition.
- No host behavior: nothing about host services, adapters, or platform behavior is promised.
- No layout as identity: repository layout, crate names, file names, build arrangement, and paths
  are never source identity.
- No package acquisition or registry trust: acquisition, resolution, and trust are owned by other
  issues.
- No parser, formatter, linker, or tooling behavior: this section defines architecture only.
- No performance or cost promise: semantic cost and performance remain owned by other sections.
- No release policy: publication, qualification, and claims are owned by release issues.

The declaration resolves, downloads, loads, generates, links, and publishes nothing, and model
facts and tests must never be presented as those guarantees.
