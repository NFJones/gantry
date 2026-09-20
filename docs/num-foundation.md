# The declared `std.num` surface

This note records the `std.num` surface that the model already declares: its canonical package
identity, its purity within the frozen standard-library dependency graph, the applicability,
stability, and identity rules that bound it, the scalar clauses whose semantics it must preserve,
its separation from the capability-backed randomness owned by `std.random`, and what the surface
does not claim. It records declarations and adds no normative row: no algorithm, no algorithm or
PRNG version, no parsing or formatting row, no work limit, and no package interface is published
here.

## Package identity

`crates/gantry-ir/src/stdlib.rs` declares the pure family `PackageFamily::Num` with the canonical
logical package name `std.num` and the wire spelling `num`. The family is one of the twenty entries
of `PackageFamily::ALL`, so the identity is a declared logical family rather than a repository
path, and `GNT-34.1-canonical-hierarchy-and-package-names` fixes the closed hierarchy it belongs
to.

## Purity and the frozen dependency graph

`PackageFamily::Num.is_pure()` is true, which places the family in the pure set with `Core`,
`Collections`, `Text`, `Codec`, `Crypto`, and `Data`. Under `GNT-34.3-acyclic-internal-dependency-dag`
the pure standard-library dependency graph is acyclic and frozen: the family may depend only on
permitted pure foundations and may depend on no capability package, no adapter, and no repository
layout, so no `std.num` result may be produced by host entropy, a host math library, or an ambient
rounding mode.

## Applicability, stability, and identity

`GNT-34.7-applicability-and-feature-granularity` governs where the family applies and which features
select it; a pure family is target- and mode-independent wherever its declared features are, and
this note claims no target-specific variation of any numeric result.
`GNT-34.6-stability-tiers` fixes the stability tier of every public item,
`GNT-34.8-defining-identity-and-interface-digest` fixes its defining package identity and interface
digest, `GNT-34.9-standard-library-contract-versioning` fixes how the family's contracts version,
`GNT-34.10-relocation-and-deprecation` fixes relocation and deprecation, and
`GNT-34.11-aggregate-manifests-and-publication-inputs` fixes the aggregate manifests this family
must appear in.

## Scalar semantics the family must preserve

- `GNT-35.1-declared-widths-and-identity` fixes declared widths and value identity;
  `GNT-35.2-literal-formation-and-canonical-text` fixes literal formation and canonical text;
  `GNT-35.3-checked-arithmetic-and-overflow-modes` fixes checked arithmetic and the explicit
  overflow modes; `GNT-35.4-division-remainder-and-signed-semantics` fixes division, remainder, and
  signed semantics; and `GNT-35.5-shifts-and-numeric-bounds` fixes shifts and numeric bounds.
- `GNT-35.9-equality-order-and-stable-hash` fixes equality, order, and the stable hash, so numeric
  equality and ordering are logical rather than host-dependent; and
  `GNT-35.11-storage-strategy-equivalence-and-round-trips` requires that every admitted storage
  strategy preserve the same numeric results and round trips.
- `GNT-35.10-allocation-quotas-and-cancellation` fixes allocation quotas and cancellation, so every
  input-dependent numeric kernel is bounded and cancellable; and
  `GNT-35.12-scalar-and-binary-non-claims` fixes the scalar section's non-claims, which this family
  inherits unchanged: no raw memory access, no address-space identity, and no host representation
  as a numeric result.

## Separation from secure randomness

Versioned deterministic PRNG values, their algorithm versions, and their copy, move, and fork
semantics belong to `std.num` (`docs/reference/general-purpose-refactor.md`). `std.random` is the
capability-backed counterpart: `PackageFamily::Random` is not pure, its host-domain family is
application-only (`GNT-29.10`), and it must not be substituted for a deterministic draw. The
separation holds in both directions: no `std.num` API may present deterministic output as secure or
consume host entropy, and no `std.random` API may replace a deterministic PRNG value.

## Declared non-claims

The architecture's declared non-claims hold for this family unchanged: `GNT-34.12` and the twelve
entries of `STDLIB_NON_CLAIMS` state that the standard-library architecture grants no runtime
behavior, no adapter, no host capability, no durability, and no performance claim. This note adds
no normative row, so it claims no implemented algorithm, no PRNG algorithm or version, no parsing or
formatting behavior, no work limit, no cancellation safe point, no cross-strategy equivalence
result, no host math-library independence test, and no package interface or digest beyond the
declared family identity above.
