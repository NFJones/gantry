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
- **Analysis.** The analyzer authenticates only the live-resource arm, from the analyzed result
  type's resource class through `OperationKind::for_value_resource_class`: a `LiveResource` class
  yields `Some(LiveResource)`, while a non-live class yields `None`, because the resource class
  cannot distinguish a value action from a protected operation.
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
`v5_keeps_a_non_copyable_caller_place_admission`.

## Handoff

With the kind authenticated for the live-resource arm, carried in machine-retained executable
metadata, and readable at the operation boundary, the retry condition recorded on `b87d011f`
`GNT-GP-RESOURCE-RUNTIME-001` is satisfied for that arm, and its integration slices can proceed.
