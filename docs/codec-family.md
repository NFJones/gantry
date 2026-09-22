# The `std.codec` family

Section 42 of `SPEC.md` publishes the codec foundation and its declared codec clauses. This note
is the family's reader-facing index. It is pinned by
`crates/gantry-conformance/tests/codec_foundation.rs#codec_family_note_is_current`, which
requires it to name every declared clause anchor, module row, frozen diagnostic, and non-claim,
so it cannot drift from the specification or the model.

## Clauses

- `GNT-42.0-codec-foundation-scope` — the section's declared scope, its pure model, its analyzer
  evidence, and its frozen diagnostics.
- `GNT-42.1-versioned-codec-contract` — the declared family, the versioned codec identity, and
  the decode, encode, and refusal contract every codec obeys.
- `GNT-42.2-hex-codec` — the canonical hex codec and its declared bounds.
- `GNT-42.3-base64-codec` — the canonical base64 codec and its declared bounds.
- `GNT-42.4-binary-endian-readers-and-writers` — the declared widths, byte orders, and
  truncation rule.
- `GNT-42.5-bounded-dynamic-json` — the compact canonical JSON codec and its dynamic value model.
- `GNT-42.6-compression-codec` — the declared stored form of the compression codec's version 1.
- `GNT-42.7-codec-non-claims` — the closed non-claim vocabulary and its guarding refusal.

## Modules

`std.codec::base64`, `std.codec::binary`, `std.codec::compression`, `std.codec::hex`, and
`std.codec::json`, each a stable module item of the family.

## Frozen diagnostics

- `codec-unsupported-version`, owned by `GNT-42.1-versioned-codec-contract`.
- `codec-malformed-input`, owned by `GNT-42.1-versioned-codec-contract`.
- `codec-expansion-limit`, owned by `GNT-42.1-versioned-codec-contract`.
- `codec-non-claim-as-guarantee`, owned by `GNT-42.7-codec-non-claims`.

## Declared non-claims

- `boundary-encoding` — no codec interprets, substitutes for, or extends the sealed canonical
  boundary encoding.
- `durable-eligibility` — codec input and output are never durable state.
- `external-eligibility` — no codec publishes an external capability or protected release.
- `host-library-authority` — no host facility is a semantic authority for the section.
- `implicit-application` — every codec operation is invoked explicitly.
- `recovery-invocation` — recovery never invokes a codec.
- `unbounded-expansion` — every operation is bounded by its codec's declared bounds.
- `version-negotiation` — no version negotiation, upgrade, downgrade, or fallback.
