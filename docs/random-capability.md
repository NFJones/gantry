# The `std.random` capability surface

This note records the `std.random` surface that the model already declares: its canonical package
identity, its host-domain family and target applicability, the normative clauses that bound it, its
separation from the deterministic randomness owned by `std.num`, and what the surface does not claim.
It records declarations; it does not add a draw API, a byte bound, or a settlement rule.

## Package identity

`crates/gantry-ir/src/stdlib.rs` declares the capability family `PackageFamily::Random` with the
canonical logical package name `std.random` and the wire spelling `random`. The family is one of the
twenty entries of `PackageFamily::ALL`, so the identity is a declared logical family rather than a
repository path, and `GNT-34.1` fixes the closed hierarchy it belongs to.

## Host-domain family and applicability

`crates/gantry-ir/src/generated/host_domain.rs` declares the host-domain family
`HostDomainFamily::Randomness` with the wire spelling `randomness`. Under `GNT-29.10` randomness
applies to the application target only: a mapping that declares randomness for another target is
refused rather than substituted, deferred, or inferred from the host.

## Normative bounds already in force

- `GNT-29.8` declares the randomness error categories `entropy-unavailable`, `invalid-request`, and
  `unclassified`, and states that those declarations grant neither clock access, entropy, secret
  material, credential authority, nor durable access to a secret.
- `GNT-29.15` is the host-contract non-claim: the section promises no runtime adapter, host trait,
  host operation, randomness, secret access, checkpoint, evaluator behavior, durable recovery, or
  external or durable grant, and its model facts and tests must not be presented as such a
  guarantee.
- `GNT-32.3` refuses secure-random draws in constant initializers: a declaration whose initializer
  reaches a secure-random draw must not evaluate.

## Separation from deterministic randomness

Versioned deterministic PRNG values, their algorithm versions, and their copy and fork semantics
belong to `std.num` (`docs/reference/general-purpose-refactor.md`); `std.random` is the
capability-backed counterpart and must not be substituted for it or present deterministic output as
secure. `GNT-29.8` and `GNT-29.15` grant no randomness, entropy, or secret access, and the roadmap
records that durable code must record returned values instead of drawing again on recovery; that
recording is a requirement awaiting normative interface rows, not behavior this surface ships.

## What this surface does not claim

- It declares no draw API, no request or byte bound, no adapter failure mapping, no cancellation or
  concurrency rule, no accepted-draw settlement, and no durable-recording rule; those need normative
  interface rows before an implementation may claim them.
- It grants no entropy, no host adapter, and no portable or durable applicability for randomness
  itself. Whether a drawn value may enter durable state is undecided until the draw result type and
  the durable interface are normative.
