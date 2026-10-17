# Environment value snapshots

This note describes the pure bounded launch-value model in
`crates/gantry-ir/src/env.rs`. It implements the value rules already stated by
`GNT-30.2-bounded-launch-snapshot-and-capability-closure` and
`GNT-30.3-arguments-environment-and-logical-cwd`, within the intended domain of
`GNT-49.0-environment-foundation-scope`. It publishes no new requirement row and
no new `std.env` module or item row; that vocabulary remains owned by its own
contract.

The model is not an environment provider, launcher, adapter, or runtime store.
It performs no host I/O and makes no ambient process read: every argument and
environment value it holds was passed in explicitly by the caller. Logical
working-directory values and native directory handles are outside this slice.

## Exact bounds

One `EnvLimits` value declares five finite, nonzero bounds: argument count,
environment entry count, environment name bytes, per-value and per-argument
bytes, and total snapshot bytes. A zero bound is refused because it admits no
exact domain. The declared defaults are `ENV_DEFAULT_MAX_ARGUMENTS`,
`ENV_DEFAULT_MAX_ENTRIES`, `ENV_DEFAULT_MAX_NAME_BYTES`,
`ENV_DEFAULT_MAX_VALUE_BYTES`, and `ENV_DEFAULT_MAX_TOTAL_BYTES`.

`ArgumentSnapshot` preserves argument order exactly and enforces the count,
per-argument, and total byte bounds. `EnvironmentSnapshot` admits bounded
immutable argument and environment snapshots: an environment name is nonempty
UTF-8 without a NUL octet, an `=` octet, or a control character, names are
compared byte for byte and are never case-folded, a duplicate name is refused,
and the entry count and total byte bounds are checked after every entry is
admitted. A name or value presented as raw bytes must also be valid UTF-8.
Every refusal carries one closed `EnvDiagnosticCode`; a refusal detail names
the condition and never echoes a protected value.

## Lookup, enumeration, and update

Explicit lookup and enumeration operate over one admitted snapshot: `get`,
`contains`, and `iter` in canonical ascending name order. No operation
consults process globals, a host environment block, or a credential source, and
protection is never inferred from a name or from a value's shape.

An update produces a new snapshot. `with_entry` adds or replaces one entry and
`without_entry` omits one name; neither mutates the original snapshot nor any
sibling snapshot. A refused update leaves every held snapshot at its exact
prior values, and a snapshot's total byte accounting is recomputed exactly for
an addition, replacement, or removal.

## Protection

Protected entries are present in the exact snapshot and survive lookup,
enumeration, attenuation, injection, and durable recovery. Their values are
redacted from ordinary output: `Debug` and `Display` render a fixed redaction
marker, so a diagnostic, log line, or debug rendering cannot disclose the
bytes. The explicit `EnvironmentValue::expose` accessor is the only
non-ordinary read, and a launcher or projection path calls it deliberately.

## Child attenuation and injection

Child inheritance is never ambient. A `ChildEnvironmentGrant` names exactly the
entries a child may receive, and `project_child` returns exactly the granted
names the parent holds, byte for byte. An empty grant inherits nothing, a grant
cannot create an entry, and a projection can never widen a value or convert a
protected value to an ordinary one.

Standalone and embedded injection present one identical plan. The same
arguments and the same attenuated child projection are built for either launch
arrangement, and `admit_injection_parity` refuses any divergent argument or
environment entry instead of normalizing it away.

## Durable admission

A committed eligible snapshot recovers its exact values through
`DurableEnvironmentRecord` and `admit_durable_environment`, including protected
values and their protection. The declared durable contract version is
`ENV_VALUE_CONTRACT_VERSION`; another version is refused rather than
reinterpreted. A native handle never resurrects, and a path or digest grants no
authority to recover anything. Ordinary serialization and ordinary durable
state are inadmissible carriers; only the declared durable reconstruction
record carries these facts.

## Evidence and boundaries

`crates/gantry-conformance/tests/env_value_snapshots.rs` covers malformed and
oversize entries, duplicate names, count and byte bounds at and beyond the
boundary, mutation isolation, protected output redaction, exact child
attenuation, standalone and embedded injection parity, and durable
snapshot-versus-handle admission. That lane performs no host I/O.

The model declares no launcher, adapter, host trait, process-global access,
credential inference, directory authority, native handle, or runtime
availability. Passing these lanes does not qualify a specification revision,
release, target adapter, or environment runtime.
