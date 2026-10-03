# Parallel tasks, sessions, and agents

`research` inherits the default researcher and reuses its automatically forked
child session via `session(inline)`. A hook-free sibling independently produces
`17`. After joining research, the root creates a reviewer child with an explicit
fresh `session(new)` context. The second prompt interpolates the joined brief.

The hook FIFO is deterministic: the review spawn is reached only after the
research join completes. No unordered sibling prompts are assigned distinct
responses. This demonstrates tasks with inherited/overridden agent and session
contexts, not two simultaneously blocked model providers.

Spec: [agent inheritance](../../../SPEC.md#GNT-7.3),
[sessions](../../../SPEC.md#GNT-7.6),
[spawn sessions](../../../SPEC.md#GNT-10.3),
[parallel work](../../../SPEC.md#148-parallel-homogeneous-work-and-listt-joins).
See [Parallel Execution](../../../docs/parallel-execution.md).

From the repository root (build once; reuse):

```sh
timeout 120 cargo build --offline -p gantry-conformance --example corpus
timeout 120 target/debug/examples/corpus examples/concurrency/parallel-sessions-agents
```

Expected foreground JSON: `["source brief",17,"reviewed"]`. One passing
scenario, two prompt dispatches. Exact request assertions check both selected
agents, rendered prompts, and inline use of already established sessions (even
inside the lexical `session(new)` block). Unique child session IDs are not
asserted; those require relational request checks or dedicated facade tests.
