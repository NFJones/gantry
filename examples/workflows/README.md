# Composed workflows (offline corpus)

Each directory is a complete package with `main.gnt`, required module files,
`case.json` full scenarios, exact request trace assertions and a package README.
No model service, credentials, network, real publication or real research is used.

| Package | Composition and paths |
| --- | --- |
| `readme_research_brief` | Read-only evidence action, brief workflow, empty-evidence fallback |
| `bounded_review_revise` | Scoped reviewer, writer, acceptance and finite exhaustion |
| `classify_enum_route` | Typed classification and all exhaustive enum routes |
| `extract_validate_fallback` | Structural repair, exhaustion, provider failure and domain normalization |
| `parallel_compare_synthesize` | Deterministic child tasks, ordered join, optional synthesis |
| `application_approval_action` | Application review gate, explicit action, host policy denial |
| `module_workflow` | Domain, preparation and drafting file modules |
| `durable_batch` | Idempotent batch with SQLite committed-result restart |

Build once from the repository root and reuse the binary for all packages:

```sh
timeout 180 cargo build --offline -p gantry-conformance --example corpus
timeout 120 target/debug/examples/corpus --all examples/workflows
```

The shared [runner](../../crates/gantry-conformance/examples/support/mod.rs)
checks typed results and exact scripted dispatch consumption. Concurrent
comparison deliberately dispatches no hooks in sibling tasks, avoiding FIFO
assumptions about scheduling. Durable batch needs the dedicated durable adapter
and must not be changed to `host` to bypass missing integration.

See [composition semantics](../../SPEC.md#GNT-6.4),
[explicit boundaries](../../SPEC.md#1412-explicit-harness-actions-and-named-prompt-inputs),
[durability](../../SPEC.md#11-durable-execution-and-resume).
