# The `std.test` package

This note indexes the `GNT-GP-TEST-001` testing-support contract as it is declared by the landed
model `crates/gantry-ir/src/test_support.rs`: tests are first-class package targets of the
standard-library hierarchy. The note is pinned by
`crates/gantry-conformance/tests/test_support.rs#testing_support_note_is_current`, which requires
every vocabulary section below to name exactly the live members, so the note cannot drift from the
model.

## Package identity

`std.test` is the target-qualified logical test package of `GNT-GP-TEST-001`: class `package`,
tier `stable`, family `test`. Every test kind is qualified by the single non-shipping `test`
target kind, which admits exactly the `portable` semantic mode. `std.test` is never shipping
authority, and its capability ceiling is bounded by the declared ceiling of the shipping target
each test exercises through `bound_test_requirement`. A test run never acquires ambient
authority: `may_acquire_ambient_authority` answers `false`.

## Test kinds

- `benchmark`
- `compile-fail`
- `durable-recovery`
- `example`
- `integration`
- `property`
- `replay`
- `snapshot`
- `unit`

## Declared substitutions

- `capability` — a declared capability grant supplies the authority a test uses.
- `clock` — a deterministic clock supplies the time a test observes.
- `prng` — a deterministic pseudo-random source supplies generated values.
- `provider` — a deterministic provider or recorded transcript supplies model results.
- `scheduler` — a controlled scheduler supplies interleaving and wake order.
- `storage-fault` — a deterministic storage fault supplies failure injection.

A run declares its substitutions with `declare_test_substitutions`, which refuses unknown and
duplicate spellings and returns them in canonical declaration order.

## Harness capabilities

- `deterministic-test-ordering-and-isolation` — deterministic test ordering and isolation.
- `assertion-and-comparison-diagnostics` — assertion and comparison diagnostics.
- `fixtures-and-temporary-capability-roots` — fixtures and temporary capability roots.
- `fake-clocks-random-sources-and-host-capabilities` — fake clocks, random sources, and host
  capabilities.
- `expected-failure-and-timeout-support` — expected-failure and timeout support.
- `property-test-shrinking-contracts` — property-test shrinking contracts.
- `durable-replay-and-recovery-test-harnesses` — durable replay and recovery test harnesses.

## Execution rules

Every declared plan obeys the whole closed rule set, and no kind opts out:

- `deterministic-discovery-and-ordering` — deterministic discovery and ordering.
- `per-test-isolation` — per-test isolation.
- `bounded-parallelism` — bounded parallelism.
- `timeouts` — timeouts.
- `fixtures` — fixtures.
- `temporary-capability-roots` — temporary capability roots.
- `structured-assertions` — structured assertions.
- `shrinking` — shrinking.
- `replay` — replay.

A run declares the kinds it contains and the substitutions it consumes with `declare_test_run`,
which canonicalizes both sets and refuses unknown or twice-declared members; a discovery set is
enumerated in canonical order with `declare_test_discovery`.

## Non-claims

- `ambient-authority`
- `oracle-provider`
- `test-only-semantics`
- `wildcard-prelude`

## Published metadata and evidence

The surface is published as `protocol/catalogs/std-test-surface-v1.json` with format
`gantry-std-test-surface-v1`, registered under the `gantry.ir` protocol owner and embedded in the
generated IR publication. The focused lane `crates/gantry-conformance/tests/test_support.rs`
compares that catalog field by field with the live model and checks every requirement-backed
spelling with the executable identity rule `canonical_wire_name`.
