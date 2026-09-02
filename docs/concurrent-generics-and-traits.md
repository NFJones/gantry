# Concurrent generics and traits runtime

This document describes the implemented nondurable concurrent-evaluator
boundary for closed generic applications and statically selected trait
methods. `SPEC.md` remains normative. Durable reconstruction, the complete
authoring guide, and the replacement publication remain later adoption work.

## Closed task boundaries

The concurrent scheduler consumes the same analyzer-produced
`MachineProgram` as sequential execution. Captures, child inputs and result
types, successful settlements, and joined values carry complete closed
`TypeDescriptor` values. A declared struct or enum value is tagged with its
complete canonical descriptor, such as `crate::Envelope<Int>`, rather than
only the outer declaration path. A value from another application, such as
`crate::Envelope<String>`, is rejected at capture, machine-input, operation-
completion, and task-settlement boundaries.

Task capture makes a detached logical copy. Immutable backing may be shared,
but child-local mutable-root replacement cannot alter the parent value. Join
and all-settled assembly preserve the resulting logical values and the
analyzer-fixed source order.

## Scheduling and operation identity

Scheduling does not inspect templates or source traits. The immutable
executable program already contains every reachable closed callable identity,
selected implementation, concrete effect set, and direct call target. The
runtime crate has no dependency on `gantry-analysis` and contains no unifier,
trait solver, implementation lookup, dictionary, or monomorphization fallback.

Before a pristine child machine is admitted, the scheduler binds its canonical
dynamic task path. That path prefixes subsequent call, branch, loop, and
operation occurrence frames. Identical operation sites in sibling instances
therefore retain distinct logical operation identities while preserving the
same analyzer-selected concrete target and schema.

## Operations, lifecycle, and executors

An explicit prompt, decision, or action reached from a closed generic body is
the only integration operation. Its occurrence retains the substituted result
descriptor, and the hook boundary uses the schema generated for that exact
descriptor. Scheduling itself creates no operation or selection event.

Joined, detached, cancelled, and shutdown-cohort task records retain the same
closed result and capture descriptors. Parent cancellation excludes already
detached work; execution cancellation and bounded abort still settle it under
the existing concurrent lifecycle rules. Neither cancellation nor detachment
introduces an open descriptor.

Executor transfer remains an executor-neutral `Send + 'static` owned future.
The conformance suite runs the same analyzer-produced closed generic program
through bounded deterministic schedule permutations and caller-owned Tokio
current-thread and multi-thread runtimes. These schedules produce identical
semantic results and do not change direct call targets.

## Executable evidence

`crates/gantry-conformance/tests/concurrent_task_state.rs` covers:

- exact applied capture and result validation, including a negative cross-
  application case;
- child-local mutation and parent/join isolation;
- task-path-scoped operation identities;
- concrete generic operation descriptors and schemas;
- all-settled success/cancellation mixtures; and
- detach, cancellation, shutdown-cohort, abort, and terminal behavior without
  open descriptors.

`crates/gantry-conformance/tests/concurrent_executor.rs` covers deterministic
schedule permutations, both supported Tokio runtime flavors, `Send` task
transfer, fixed closed call targets, and identical concrete results.

`protocol/conformance/generics-traits-concurrent-v1.json` maps the applicable
concurrent-evaluator clauses to these cases and to prerequisite frontend,
analyzer, IR, diagnostic, and resource-limit evidence. Global profile
advertisement remains withheld until the complete generics-and-traits adoption
gate closes.
