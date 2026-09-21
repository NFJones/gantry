# The executable authority closure and its preflight resolution

This note describes the authority model in `crates/gantry-ir/src/authority.rs`
and its machine-checked evidence in
`crates/gantry-conformance/tests/authority_closure.rs`. The specification is
normative; the crate models the two clauses this issue owns,
`GNT-3-T-AUTHORITY-CLOSURE` and `GNT-7.2-authority-rebinding`. The other
authority clauses of Section 3 (instances, lineage, revocation, admission) and
`GNT-11.6-authority-instance-compatibility` are modelled in the same crate but
are out of scope for this note.

## `GNT-3-T-AUTHORITY-CLOSURE`

Each analyzed artifact has one conservative executable authority closure: the
least set of capability requirement instances — a public capability requirement
together with the selected implementation binding that satisfies it — plus the
agent, model-exposed tool, handler, and operation requirement slots that
contains the declared requirement of every exact operation site reachable from
every retained root.

The model publishes exactly that set and nothing else:

- instances are deduplicated by binding identity and ordered canonically by
  that identity, so two closures over the same supplied entries are equal
  whatever the declaration or traversal order;
- a site-qualified requirement slot composes the exact operation site, the
  declared tool slot, and its slot kind, so one slot name at two sites, and two
  kinds of one slot at one site, are three distinct requirements;
- least-ness is the caller's obligation: the value never adds an instance or a
  slot the caller did not supply, so a declaration the caller did not prove
  reachable cannot enter the closure;
- construction is bounded: the supplied instance and slot counts are measured
  before deduplication against the declared ceilings
  `CapabilityAuthorityClosure::MAXIMUM_INSTANCES` and
  `CapabilityAuthorityClosure::MAXIMUM_SLOTS` (each 4096), and a larger input is
  refused with the registered code `authority-closure-exceeds-maximum` rather
  than truncated;
- the closure is byte-identical for the same inputs: its canonical identity
  spellings are domain-separated and length-prefixed, and no `Debug` or
  `Display` rendering of any type is a protocol identity.

The model does not compute the closure's reachability, the instantiation
closure, or the effect fixed point, and it fails closed in the clause's sense:
nothing here publishes a canonical analysis artifact, an executable projection,
or any authority state derived from an incomplete closure.

## `GNT-7.2-authority-rebinding`

The preflight resolution establishes the authorization scope of a run and
nothing more. `RequirementResolution::resolve` resolves every declared
requirement against one closure: each declared requirement must be satisfied by
exactly one binding, an unsatisfied requirement is refused with
`authority-unresolved-requirement`, and two distinct bindings for one
requirement are refused with `authority-ambiguous-requirement`, so a
conflicting or ambiguous registration is rejected during preflight. The
supplied requirement count is measured before deduplication against
`RequirementResolution::MAXIMUM_REQUIREMENTS` (4096) and a larger input is
refused with `authority-resolution-exceeds-maximum`. A requirement the caller
did not declare never yields a resolution entry.

`RequirementResolution::rebind` re-establishes that same scope through
replacement bindings: every resolved requirement must be rebound
(`authority-unresolved-requirement`), duplicates collapse, and a replacement
naming a requirement outside the resolved scope is refused with
`authority-rebinding-widens-closure` before its own registrations are
inspected, so rebinding can neither widen nor narrow the closure.

Two obligations the clause also names are not this model's, and a caller must
not read this surface as satisfying them: the canonical action-signature
resolution and the single opaque action-mapping revision ID of `GNT-7.2` item
2, which belong to the agent and action-mapping boundary, and the committed
execution-state evidence for a replacement binding and its mapping revision,
which belongs to the durable-record owners.

## Non-claims

The model establishes scope, not authority. It is not a runtime authority
store, it holds no live instance, host handle, or protected payload, and it
confers no dispatch right: resolving a requirement is not a per-call
authorization under `GNT-3-T-AUTHORITY-ADMISSION`. It grants nothing, invents
no identity another owner is chartered to define, and reads no host path,
registry, or source program.
