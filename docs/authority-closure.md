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

The clause's closure is the least set of capability requirement instances — a
public capability requirement together with the selected implementation binding
that satisfies it — plus the agent, tool, handler, and operation requirement
slots — including the agent, model-exposed tool, handler, and operation slots
attached to those sites — that contains the declared requirement of every exact
operation site reachable from every retained root, and it also contains every
retained concrete public or durable schema root, every retained instantiation
key, and every callable row bound invocable from those roots. Inside the
retained roots it is the maximum static authority of the artifact: it is never
narrowed by an unreachable-path argument or by runtime observation.

The model implements part of that set, and the note states the boundary
exactly:

- `CapabilityAuthorityClosure` holds capability-binding instances and
  site-qualified requirement slots, and nothing else. It computes no
  reachability, no instantiation closure, and no effect fixed point, and it
  holds no schema root, instantiation key, or callable row: the caller supplies
  the closure members it proved reachable.
- a site-qualified requirement slot composes the exact operation site, the
  declared tool slot, and its slot kind, so one slot name at two sites, and two
  kinds of one slot at one site, are three distinct requirements. Its slot kind
  is the closed tool-slot vocabulary (`composite`, `provider-tool`,
  `source-handler`); the agent, model-exposed tool, and operation slot flavours
  the clause also names are **not representable** here, so a caller holding one
  cannot supply it.
- instances are deduplicated by binding identity and ordered canonically by
  that identity's spelling, so two closures over the same supplied entries are
  equal whatever the declaration or traversal order. The clause orders closure
  contents canonically by requirement identity. The model's key is the
  length-prefixed binding-identity spelling, whose parts place the requirement
  identity's length before its text, so the model groups one requirement's
  bindings together without reproducing the clause's requirement-identity
  order; the model has no canonical byte encoding of its own beyond its
  members' spellings.
- least-ness is the caller's obligation: the value never adds an instance or a
  slot the caller did not supply, so a declaration the caller did not prove
  reachable cannot enter the closure.
- construction is bounded: the supplied instance and slot counts are measured
  before deduplication against the declared ceilings
  `CapabilityAuthorityClosure::MAXIMUM_INSTANCES` (4096) and
  `CapabilityAuthorityClosure::MAXIMUM_SLOTS` (4096), and a larger input is
  refused with the registered code `authority-closure-exceeds-maximum` rather
  than truncated.

The clause's fail-closed publication rule — analysis fails source-invalid with
a registered diagnostic identifying an unresolved item, and no closure-derived
authority state is published — has no v1 surface and no path in this model; the
reviewed requirement ledger records that rule as `not-applicable` under v1,
because no v1 artifact publishes an authority closure. This note claims no
fail-closed behaviour for the model.

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

The clause also requires rebinding not to resurrect a revoked or expired
generation and not to confer rights the prior binding lacked. This type carries
no rights set, no generation, and no lineage, so it decides neither duty: those
are the instance-level rebinding and comparison rules the same crate models for
the revocation and compatibility clauses, and a caller must not read the
requirement resolution as satisfying them.

Two further obligations the clause names are not this model's, and a caller
must not read this surface as satisfying them: the canonical action-signature
resolution and the single opaque action-mapping revision ID of Section 7 item 2
(the anchor `GNT-7.2`, a different anchor from
`GNT-7.2-authority-rebinding`), which belong to the agent and action-mapping
boundary, and the committed execution-state evidence for a replacement binding
and its mapping revision, which belongs to the durable-record owners.

## Non-claims

The model establishes scope, not authority. It is not a runtime authority
store, it holds no live instance, host handle, or protected payload, and it
confers no dispatch right: resolving a requirement is not a per-call
authorization under `GNT-3-T-AUTHORITY-ADMISSION`. It grants nothing, invents
no identity another owner is chartered to define, and reads no host path,
registry, or source program.
