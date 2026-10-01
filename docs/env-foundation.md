# Environment package foundation

`SPEC.md` Section 49 owns the declaration-only `std.env` surface. This foundation
is not an environment provider or a launcher integration.

## Identity and applicability

`GNT-49.0-environment-foundation-scope` identifies the capability-backed family.
`GNT-49.1-environment-modules-and-item-rows` declares exactly three stable modules,
in canonical name order:

- `std.env::arguments`
- `std.env::environment`
- `std.env::working_directory`

Every row applies only to application mode over library and binary targets.
`ENV_ITEMS` publishes the rows; `declare_env_surface` and `admit_env_surface`
refuse missing, partial, extra, or mismatched surfaces instead of repairing them.
`canonical_env_hierarchy` composes the family with the pure hierarchy, and
`canonical_std_hierarchy` includes the same defining package and item identity.
The aggregate catalog records the package interface digest. Repository module
paths and host adapters are not the source-level package identity.

## Authority and runtime boundaries

Section 30 continues to own launch snapshots and attenuation through
`GNT-30.2-bounded-launch-snapshot-and-capability-closure` and
`GNT-30.3-arguments-environment-and-logical-cwd`. Logical working-directory data
is not directory authority. Declaring a module grants no capability and reads
or mutates no ambient process state.

This foundation declares no encoding or case policy, environment lookup,
enumeration or mutation operation, native directory handle, child-process
inheritance, protected-value release, host trait, adapter, launcher, or runtime
availability. It provides no credential access and no durable native handle.
Those behavior and authority surfaces require their own reviewed contracts and
runtime integration; declaration coverage is not evidence that they work.

## Evidence and qualification

`crates/gantry-conformance/tests/env_foundation.rs` checks the closed rows,
applicability, exact admission, and refusal boundaries.
`crates/gantry-conformance/tests/stdlib_architecture.rs` checks aggregate
composition and catalog identity. These tests do not perform host I/O.

Passing these lanes does not qualify a specification revision, publication,
release, target adapter, or environment runtime. Generated and revision-bound
checks must still agree with genuinely reviewed adoption evidence before any
such qualification is claimed.
