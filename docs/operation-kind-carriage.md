# Section 20 operation-kind carriage

`GNT-20.0-value-actions-and-live-resource-operations` closes the Section 20 kind over exactly
`value-action`, `protected-operation`, and `live-resource`, and the model publishes it as
`OperationKind`. Until this work the kind existed only as a model vocabulary: no analyzed fact
carried it and no machine-retained metadata recorded it. This note records what now carries it.

## What is carried

- **Executable metadata.** `ExecutableOperation.section20_kind: Option<OperationKind>`
  (`crates/gantry-ir/src/executable.rs`) records the kind an analysis authenticated. `None` means no
  layer authenticated one, and a consumer that needs the kind must fail closed rather than assume
  one: the hook-site `OperationSiteKind` is a different fact and never stands in for it.
- **Analysis rule.** Lowering first authenticates the live-resource arm, from the result type's
  resource class through `OperationKind::for_value_resource_class`: a `LiveResource` class yields
  `Some(LiveResource)`, while a non-live class yields `None`, because the resource class cannot
  distinguish a value action from a protected operation. The class comes from
  `prove_resource_class`, the same uncounted stored-member fold the public type-property surface
  publishes, so an operation whose analyzed result type carries the declaration below - a declared
  `live_resource struct` or a closed generic application of one - authenticates its arm, while a
  fold that refuses the descriptor leaves the kind unauthenticated rather than guessed, and a
  unsealed non-live result stays `None`. A sealed analyzed result authenticates the protected
  arm through `prove_source_protection_class`; sealed operands and effects do not participate.
- **Declaration surface.** `GNT-6.2j` declares the `live_resource` struct modifier: it seeds the
  `LiveResource` resource class of `GNT-5.20-parametric-types` for its declared type, an empty
  declaration remains `LiveResource`, a stored member that is itself `LiveResource` makes every
  enclosing stored aggregate `LiveResource`, no ownership class or transfer contract is admitted,
  and a declaration stacking it with `affine` or `must_consume` is rejected at syntax time.
  An analyzed `live_resource struct` therefore reports `ValueResourceClass::LiveResource` through
  `type_capabilities`; the declaration creates no resource, value, handle, or operation and decides
  no operation kind.
- **Retained-program wire.** The `GNTPRG05` form carries the kind as an optional wire name
  (`write_operation` writes it, `read_operation` decodes it strictly and refuses an unknown
  spelling). `GNTPRG02`, `GNTPRG03`, and `GNTPRG04` keep their byte layout and decode the field as
  unauthenticated, so committed durable programs still decode.

## Known gap

Lowering now also authenticates `ProtectedOperation` from the analyzed result's sealed protection
class, after checking the live-resource class. An unsealed non-live result remains unauthenticated;
sealed operands or effects do not authenticate the result kind.

`Machine::complete_operation` refuses ordinary logical-value transport for authenticated
live-resource results with `OperationCompletionError::LiveResourceValueRefused`. Pending identity
and cancellation checks take precedence; refusal changes no checkpoint fact or settlement lease.
An attempted operation's handle-free `Err(OperationError)` remains eligible for the existing
value-limit and expected-result-type checks and one settlement, including durable replay. Neither
an ordinary `Ok` nor an unsealed error payload bypasses the refusal; task cancellation still wins.
The analyzer/retained-wire regression
`executable_bridge.rs#authenticated_live_resource_refuses_ordinary_completion_without_mutation`
checks this boundary with a structurally matching ordinary value. A separate source live-handle
completion path remains unimplemented; this refusal does not grant one or roll back accepted work.

Product start uses only raw-byte hooks, so its workflow and spawned-body operation inventory
rejects authenticated live-resource results, including attempted operations, with
`unsupported-live-resource-transport` before mapping calls, root-session/execution identities,
or execution acceptance. Source analysis remains valid; an unsupported transport cannot cause
an external dispatch and then fail only when its successful result reaches the machine.
The low-level attempted-error and replay contract remains available to its existing owners.
Reachable aggregate constructors are also classified using the configured frontend limits and refused
with the same transport code when their analyzed type is live-resource, including empty structs,
absent options, empty lists, and payload-free enum variants. Ordinary data cannot fabricate
live-handle ownership or bypass static transport eligibility. Unused declarations do not trigger
this instruction-level refusal, and ordinary non-live aggregate construction remains eligible.

Ordinary JSON entry normalization separately refuses an analyzed live-resource parameter,
including enclosing aggregates, with `live-resource-entry-value-refused` in the
entry-input-validation category. Classification is checked after required-input presence and
before parsing or normalization, mapping calls and execution acceptance. Even an absent optional
payload cannot make a statically live-resource entry type eligible for ordinary data transport.
This check supplies no host authority or live-handle entry path.

## Evidence

Codec tests in `crates/gantry-runtime/src/machine/program_codec.rs` (compiled under
`--all-features`): `v5_carries_the_authenticated_section20_kind_and_predecessors_do_not`,
`v5_is_selected_when_only_a_task_body_operation_is_authenticated`, and
`v5_keeps_a_non_copyable_caller_place_admission`. These exercise the carrier and the wire with
hand-built operations; none of them demonstrates an analyzer-produced `Some(LiveResource)` from
source, and none demonstrates a runtime decision taken from the field, so they are carrier evidence
rather than authentication or consumption evidence. The analyzer-produced kind is evidenced
separately by
`crates/gantry-conformance/tests/analyzer_lowering.rs#analyzed_operation_result_authenticates_live_and_protected_kinds_only`,
which lowers a source operation returning a `live_resource struct` and asserts the authenticated arm
beside an unauthenticated non-live result, and by
`crates/gantry-conformance/tests/executable_bridge.rs#analyzer_authenticated_operation_kinds_survive_the_retained_program_wire`,
which encodes that analyzer-produced program with the published
`gantry::runtime::{encode_machine_program, decode_machine_program}` pair, observes the `GNTPRG05`
form, and decodes it back with the kind intact and a byte-identical re-encode. No runtime decision
reads the field everywhere yet: the runtime resource-admission boundary does read it, so a subject
whose operation carries no authenticated live-resource kind is refused with
`ResourceRegistryRefusal::UnauthenticatedOperationKind` rather than admitted, and the wider
integration arms stay with `b87d011f` `GNT-GP-RESOURCE-RUNTIME-001`.

## Handoff

What is in place: `ExecutableOperation` can express the kind and publishes no unauthenticated
default; analysis has one declared rule for producing it; the `GNTPRG05` wire round-trips whatever
is authenticated while `GNTPRG02`-`GNTPRG04` keep decoding; and `GNT-6.2j` gives one source
declaration that reports the analyzed class the rule consumes, lowering emits the authenticated kind
for it, and the retained-program encode/decode pair is published
(`gantry::runtime::{encode_machine_program, decode_machine_program}`) so the analyzer-produced kind
is provably carried by the wire; and the runtime resource-admission boundary consumes it, since
`AdmittedResource::admit`, the single account-construction path, refuses a subject whose operation
carries no authenticated live-resource kind with
`ResourceRegistryRefusal::UnauthenticatedOperationKind`, and `ResourceRegistry::admit` propagates
that refusal. What is **not** in place: the wider integration arms the retry condition on `b87d011f`
`GNT-GP-RESOURCE-RUNTIME-001` owns - quota enforcement in live paths, cleanup across cancellation,
shutdown, and hard cancellation, adapter fault containment, and durable resource reconstruction -
while source live-handle completion remains unavailable. The protected arm is authenticated from
sealed analyzed results. Ordinary completion now consumes the authenticated live-resource kind
by refusing cloneable logical-value substitution without changing pending ownership. These
carriage and refusal boundaries are not complete runtime integration or qualification evidence.
