# Durable batch workflow

Compose a pure finite snapshot preparation loop with one idempotent bulk-action
workflow. Preparation retains the ordered items and computes a summary; the
capability returns a typed `Batch` receipt. Empty input skips the capability.
The offline capability returns receipts; it performs no filesystem or network
effects. `class: durable` requires the corpus SQLite durable adapter: this is
not a nondurable host example disguised by its name.

The full batch and empty batch scenarios assert the ordered batch argument,
canonical workflow ownership, recovery class and exact hook consumption. The
durable adapter commits the execution, opens a fresh interpreter on the journal,
resumes its committed terminal result and checks that no action is redispatched.
This is committed-result logical restart coverage, not injected mid-batch crash
coverage or a proof of external exactly-once effects. Real idempotence must be
provided by the action implementation.

There is one operation boundary for the entire batch, not a durable checkpoint
per item. Multi-operation durable initial execution currently hangs in the
shared harness/runtime path; this fixture intentionally does not claim coverage
of that unsupported path.

From the repository root, build once after the durable adapter is installed and
reuse the runner:

```sh
timeout 180 cargo build --offline -p gantry-conformance --example corpus
timeout 120 target/debug/examples/corpus examples/workflows/durable_batch
```

Spec: [finite loops](../../../SPEC.md#147-finite-general-pre-test-and-post-test-loops),
[action recovery classes](../../../SPEC.md#GNT-6.12),
[durable execution and resume](../../../SPEC.md#11-durable-execution-and-resume).
