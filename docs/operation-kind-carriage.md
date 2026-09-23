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
- **Analysis rule.** Lowering authenticates only the live-resource arm, from the result type's
  resource class through `OperationKind::for_value_resource_class`: a `LiveResource` class yields
  `Some(LiveResource)`, while a non-live class yields `None`, because the resource class cannot
  distinguish a value action from a protected operation. The rule reads
  `result_type.primitive_properties()`, which publishes properties for the compiler-owned primitive
  kinds only; a declared result type exposes none, so the class the declaration below makes
  reachable still does not reach this expression, and lowering publishes `None` for an operation
  whose result type is a declared `live_resource struct`. Emitting the authenticated kind for those
  operations is owned by `a0257d36` `GNT-GP-LIVERES-001`, not by this carriage.
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

`ProtectedOperation` is never authenticated today: no declaration-level fact separates a protected
operation from a value action. That fact belongs to the protection/declaration owner rather than to
this carriage, and the carriage is designed to stay unauthenticated until it lands.

## Evidence

Codec tests in `crates/gantry-runtime/src/machine/program_codec.rs` (compiled under
`--all-features`): `v5_carries_the_authenticated_section20_kind_and_predecessors_do_not`,
`v5_is_selected_when_only_a_task_body_operation_is_authenticated`, and
`v5_keeps_a_non_copyable_caller_place_admission`. These exercise the carrier and the wire with
hand-built operations; none of them demonstrates an analyzer-produced `Some(LiveResource)` from
source, and none demonstrates a runtime decision taken from the field, so they are carrier evidence
rather than authentication or consumption evidence.

## Handoff

What is in place: `ExecutableOperation` can express the kind and publishes no unauthenticated
default; analysis has one declared rule for producing it; the `GNTPRG05` wire round-trips whatever
is authenticated while `GNTPRG02`-`GNTPRG04` keep decoding; and `GNT-6.2j` gives one source
declaration that reports the analyzed class the rule consumes. What is **not** in place: (a) the
emission itself - lowering reads only primitive properties, so an operation whose declared result
type is a `live_resource struct` still publishes `None`, and `a0257d36` `GNT-GP-LIVERES-001` owns
that emission, and (b) a runtime boundary consumer - `gantry-runtime` selects the wire and
round-trips the field, but no admission path reads it. The retry condition recorded on `b87d011f`
`GNT-GP-RESOURCE-RUNTIME-001`
is therefore only **partially** satisfied: carriage is done, the boundary consumption belongs to
that issue's own integration scope, and the analyzed class now has a declaration while the emission
it feeds stays with `a0257d36`.
