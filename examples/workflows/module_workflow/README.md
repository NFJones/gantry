# File-module workflow composition

`main.gnt` owns package-wide agent declarations and composes pure preparation
with drafting. `domain.gnt` owns the shared result, `preparation.gnt` trims input,
and `drafting.gnt` imports the domain type and visibly owns the model operation.
Module calls are interpreter calls, not implicit integration dispatch.

Scripts cover nonempty and whitespace-only inputs, asserting the canonical
module workflow site, inherited agent and cleaned named input. The empty path
requires zero dispatches.

From the repository root, build once and reuse:

```sh
timeout 180 cargo build --offline -p gantry-conformance --example corpus
timeout 120 target/debug/examples/corpus examples/workflows/module_workflow
```

Spec: [module resolution](../../../SPEC.md#GNT-13.3),
[package-wide agents](../../../SPEC.md#142-modules-imports-and-package-wide-agents),
[transitive effects](../../../SPEC.md#GNT-6.5).
