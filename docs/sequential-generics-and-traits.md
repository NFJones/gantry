# Sequential generics and traits runtime

This document describes the implemented nondurable evaluator boundary for
parametric values, closed generic applications, and statically selected trait
methods. `SPEC.md` remains normative. The complete authoring guide and amended
publication remain later adoption work.

## Closed executable handoff

Semantic analysis retains one monomorphized callable for each reachable closed
application. The executable program indexes those bodies by
`CanonicalCallableIdentity`; calls contain that exact identity rather than an
open template, source path requiring overload resolution, or dynamic method
slot. The evaluator therefore performs ordinary frame dispatch and contains no
unifier, trait solver, implementation lookup, dictionary, vtable, or
monomorphization fallback.

The runtime crate has no dependency on `gantry-analysis`. Analyzer-owned
lowering supplies all concrete parameter and result descriptors, exact effects,
direct call targets, operation metadata, and declared-enum branch tables before
machine construction. Program validation rejects missing direct targets,
incorrect arity, noncanonical callable order, duplicate enum arms, and invalid
branch targets.

## Values, methods, and operations

- Generic free functions, inherent methods, and selected trait methods use the
  existing explicit workflow frames.
- `self` and `mut self` are copied into a callee-local root. Replacing a field
  publishes only the complete copied receiver, so the caller's original value
  remains unchanged.
- Applied structs and enums retain their closed descriptors in instructions,
  frames, results, and branch metadata. Enum construction and matching use
  analyzer-produced variant names and never consult source declarations at
  runtime.
- A prompt or action reached through a concrete generic body remains the sole
  integration operation. Generic dispatch itself creates no operation, event,
  or journal record.
- Operation occurrences retain the substituted concrete result descriptor.
  The public interpreter obtains the matching generated schema and includes
  both the descriptor and schema in the immutable hook request. A result of a
  different type is rejected before source execution resumes.

## Serialization and scope

The in-memory executable program retains concrete workflow descriptors, direct
call identities, and enum branch tables. Durable retention now preserves those
same closed identities and authenticates the analyzer artifacts without adding
source analysis to the runtime. That boundary is documented in
[`durable-generics-and-traits.md`](durable-generics-and-traits.md).

Concurrent transfer of concrete captures and results is implemented separately
and documented in
[`concurrent-generics-and-traits.md`](concurrent-generics-and-traits.md).
Global evaluator profile advertisement also remains disabled until the complete
generics-and-traits adoption gate closes.

## Executable evidence

`crates/gantry-conformance/tests/executable_bridge.rs` covers:

- closed generic free calls;
- inherent and trait methods, including `mut self` copy isolation;
- closed enum construction and matching;
- concrete generic operation result types and schemas, including rejection of
  a mismatched result; and
- the absence of open callable identities or an analyzer dependency in the
  evaluator crate.

`protocol/conformance/generics-traits-runtime-v1.json` maps the applicable
evaluator clauses to those public cases and to the prerequisite frontend,
analyzer, IR, diagnostic, and resource-limit evidence.
