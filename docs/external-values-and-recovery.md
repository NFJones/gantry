# External values, canonical boundaries, and recovery

This note records the external-value boundaries that version 1 already ships: how a scalar key or a
structural value becomes bytes, which `Option` shapes the admitted type domain excludes, how durable
records reject incompatible versions, and what the encodings and the recovery path do not claim. It
describes the landed surface; it is not a plan for a later boundary revision.

## Canonical scalar keys

`crates/gantry-core/src/canonical_key.rs` defines the versioned frame used for hashable scalar
identities. A frame is the eight-byte magic `GNTYKEY\0`, a big-endian major/minor `u16` pair holding
canonical key format 1.0, a tag byte, and a big-endian `u64` payload length. Decoding rejects a wrong
magic, an unsupported version, an unknown tag, frame-length and trailing-byte violations, a
payload-length mismatch, `Bool` keys, noncanonical or out-of-range `Int` payloads, non-finite and
negative-zero `Float` payloads, invalid UTF-8, and any key above the configured positive byte limit.
Batch decoding checks the declared member count and the aggregate byte budget before it decodes
anything, decodes members in input order, and reports the index of the first duplicate canonical
identity. `crates/gantry-conformance/tests/canonical_key.rs` is the public lane for these frames.

## Strict structural values

`LogicalValue::canonical_json` encodes strict structural values through the canonical encoder: object
members are ordered by UTF-16 code units, duplicate struct fields are refused when the value is
constructed, and a decoded value is rebuilt through `StrictJsonDocument` under `JsonLimits`. The
public lane is `crates/gantry-conformance/tests/value_kernel.rs`.

## The version-1 `Option` domain

`SPEC.md` 3060-3062 declares `Option<Unit>`, `Option<Option<String>>`, and `List<Option<Unit>>`
invalid types. Source that declares them is refused with the `invalid-option-type` diagnostic, which
is emitted from type, body, and generic positions (`crates/gantry-analysis/src/types.rs`,
`crates/gantry-analysis/src/bodies.rs`, `crates/gantry-analysis/src/generics.rs`). The exclusion is
specified rather than incidental: without a variant discriminator the corresponding encoded shapes
are not injective.

## Versioned durable records

Package, registry, identity, and recovery records each reject an unsupported version instead of
reinterpreting it (`crates/gantry-ir/src/package.rs`, `crates/gantry-ir/src/registry.rs`,
`crates/gantry-ir/src/identifier.rs`, `crates/gantry-runtime/src/recovery.rs`).

## What these boundaries do not claim

- Encoding does not change type validity. Providing or reusing a codec neither admits nor forbids a
  source type; admission stays with the analyzer and the `Option` domain above.
- Encoding does not grant durability. A value that can be encoded is not thereby recoverable, and the
  recovery path invokes no source decoder and publishes no partial machine.
- Live handles cannot enter a checkpoint; recovery projections exclude them.
- The next boundary revision is an open versioned protocol and source-edition decision: an
  implementation must not silently change the meaning or bytes of an existing v1 entry, action,
  schema, journal, or durable artifact (`docs/reference/general-purpose-refactor.md`).
