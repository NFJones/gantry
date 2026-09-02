# Durable generics and traits recovery

This document describes the implemented durable-runtime boundary for closed
generic applications and statically selected trait methods. `SPEC.md` remains
normative. The qualified release advertises this profile with explicit platform
and stable-media limitations in the release record.

## Retained artifacts

Sequence-one evidence retains the analyzer-produced executable program and the
exact canonical analysis IR, generated-schema object, package-source manifest,
and source map. Each analysis artifact is stored with its SHA-256 identity and
is authenticated before recovered execution is admitted.

The executable program codec preserves the canonical callable identity paired
with every workflow. Closed free functions, inherent methods, and selected
trait methods therefore retain their complete applied identities, direct call
targets, result descriptors, effects, operation metadata, and static sites.
Method workflow paths are reconstructed through their canonical method form,
not treated as ordinary `crate::` paths.

Declared value shapes used at entry and operation boundaries are indexed by
complete `TypeDescriptor` values. Different applications such as
`crate::Envelope<Int>` and `crate::Envelope<String>` retain independently
substituted field and variant shapes even though they share one declaration.

## Recovery boundary

Source-free resume uses only the authoritative journal prefix. It does not
parse source, infer type arguments, prove bounds, run coherence, select trait
implementations, or discover instantiations. A version-two compacted recovery
snapshot embeds the same sequence-one record, so full and compacted prefixes
reconstruct the identical closed executable program and machine state.

When candidate source is supplied, Gantry analyzes it only for compatibility.
The retained canonical-IR identity remains the resume key. An identical source
manifest is reported as an exact match; a cosmetic manifest difference may be
accepted only when the canonical IR remains identical.

`DurableResumeExecutionAccepted::retained_artifacts` exposes authenticated
bytes and identities for the canonical IR, generated schemas, package
manifest, and source map. Embedders can audit those bytes without making them
runtime inference inputs.

## Rejection and compatibility

Malformed or noncanonical retained executable bytes, open callable identities,
tampered artifact bytes, identity mismatches, stale protocol/configuration
selection, mixed execution state, and incompatible candidate canonical IR are
rejected before recovered interpretation or an authoritative journal commit.
Retained generic artifact failures use the
`source-or-configuration-incompatibility` category and the stable
`invalid-retained-artifact` code where no narrower compatibility code applies.

This is the adopted amended v1 contract. Gantry does not migrate or
compatibility-resume older draft execution-start metadata or program bytes.

## Executable evidence

`crates/gantry-conformance/tests/durable_start.rs` covers:

- two concrete applications of one generic template and their exact selected
  trait-call targets, pure effects, and generated schema entries;
- sequence-one program and checkpoint round trips;
- equivalent full-prefix and version-two compacted-prefix recovery;
- recovery in a fresh process from retained bytes without analyzer setup;
- public source-free resume and exact candidate-source comparison;
- execution of the recovered closed program to the expected applied value;
- authenticated canonical IR, schema, manifest, and source-map access; and
- tampered metadata and malformed retained-program rejection without an extra
  journal commit.

`protocol/conformance/generics-traits-durable-v1.json` maps every applicable
durable-runtime generics-and-traits clause to this regression or to its
frontend, analyzer, and IR prerequisite evidence. The qualified release record
states the remaining macOS and stable-media limitations.
