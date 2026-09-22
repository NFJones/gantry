# The `std.io` common I/O surface

This note records the `std.io` surface that the model already declares: its canonical package
identity, the host-domain progress and error contract every Reader, Writer, and Seek operation
consumes, the normative clauses already in force, and what the surface does not claim. It records
declarations; it adds no operation, no per-call bound, and no adapter, and any operation a later
clause declares must consume the landed host-domain facts below.

## Package identity

`crates/gantry-ir/src/stdlib.rs` declares the capability-backed family `PackageFamily::Io` with the
canonical logical package name `std.io` and the wire spelling `io`. The family is one of the twenty
entries of `PackageFamily::ALL`, so the identity is a declared logical family rather than a
repository path, and `GNT-34.1-canonical-hierarchy-and-package-names` fixes the closed hierarchy it
belongs to. Because the family is capability-backed, `GNT-34.3-acyclic-internal-dependency-dag`
forbids any pure family from depending on it and forbids it from depending on a host adapter.

## Progress and error contract already in force

`GNT-29.2-reader-writer-seek-progress` fixes the progress vocabulary a reader, writer, or seek
operation reports, and `crates/gantry-ir/src/host_domain.rs` implements exactly that mapping:
`HostProgress::Eof` maps to `eof`, `HostProgress::ShortRead` maps to `short-read`,
`HostProgress::ShortWrite` maps to `short-write`, `HostProgress::NotStarted` maps to
`not-started`, and `HostProgress::Complete` maps to `committed-progress`. EOF, short progress,
interruption, cancellation, and ambiguous settlement remain distinct.

Three further declared rules bound every such operation:

- `GNT-29.1-channel-separation` makes one host operation outcome exactly success, one
  source-visible portable domain error, or one operational adapter failure, and forbids either
  failure channel from being reclassified as the other.
- `GNT-29.3-portable-domain-error-envelope` fixes the envelope: exactly one closed family, one
  category admitted by that family, and one bounded portable message; every family category matrix
  row ends in `unclassified`, and unknown or foreign categories are refused rather than guessed.
- `GNT-29.14-native-detail-exclusion` keeps native codes, messages, handles, and platform detail
  out of portable fields, and `GNT-29.15-host-contract-non-claims` states that Section 29 promises
  no host adapter, host trait, host operation, runtime availability, or capability grant, and that
  its model facts and tests must not be presented as any such guarantee.

## No `io` host-domain family is declared

The host-domain family matrix of `GNT-29.4-console-contract` through
`GNT-29.9-codec-contract` declares twelve families in canonical order: `codec`, `console`, `dns`,
`environment`, `filesystem`, `http`, `process`, `randomness`, `secret`, `socket`, `time`, and
`tls`. Those are exactly the entries of `HostDomainFamily::ALL`, and the matrix carries no `io`
row. The common I/O layer therefore consumes the categories of the family an operation belongs to
through the `GNT-29.3-portable-domain-error-envelope` envelope, and this surface claims no `io`
category, no `io` target mapping, and no thirteenth host-domain family.

## What this surface does not claim

- It declares no concrete Reader, Writer, or Seek operation contract beyond the landed progress
  mapping of `GNT-29.2-reader-writer-seek-progress`: no operation kinds, no signatures or items, no
  per-call bound, no interruption, cancellation, or backpressure rule, no post-failure ownership
  rule, and no refusal vocabulary of its own. Those need normative clauses before an implementation
  may claim them.
- It declares no item or interface row for `std.io`, no interface digest, and no stability tier;
  `GNT-34.8-defining-identity-and-interface-digest` requires an item surface before either exists.
- It grants no adapter, no host trait, no runtime availability, and no capability: adapters remain
  leaves, and `GNT-29.11-adapter-declaration-obligations` keeps an adapter declaration evidence
  only rather than an implementation or availability claim.
