# SQLite durability demonstrations

Run from the repository root, offline with no credentials:

```sh
timeout 180 cargo run --offline -p gantry-conformance --example corpus -- --all examples/durability
timeout 180 cargo test --offline -p gantry-conformance --test example_durability
```

The real adapter is `crates/gantry-conformance/examples/support/durable.rs`.
It starts through `Interpreter::start_durable_execution` with `SqliteJournalStore`,
awaits committed terminal state, orderly-shuts down, closes/reopens SQLite, and
resumes into a fresh interpreter with disjoint identities and an empty hook script.
Every unexpected restart dispatch fails. Temporary databases are private to each
scenario and removed afterward. This demonstrates **logical restart**, not a killed
process, mid-operation crash, power-loss durability, or recovery of external effects.

| Package | Executable assertion |
| --- | --- |
| `committed_result` | One non-idempotent action produces `"receipt-7"`; reopened journal returns that result without redispatch. |
| `source_free` | Entry input 41 is retained; resume passes no candidate source and returns 42 with `SourceFree` provenance. |
| `candidate_check` | Exact source gives `ExactManifest`; a changed return type is rejected as `canonical-ir-identity-mismatch` without changing the prefix. |
| `configuration_check` | A changed hook-output byte limit rejects as `immutable-configuration-mismatch` without changing the prefix. |
| `recovery_classes` | Three independent runs execute read-only, idempotent, and non-idempotent actions, then reuse committed results without dispatch. |
| `task_graph` | SQLite-backed spawn/join graph reaches 42 and orderly shutdown; explicitly **start-only**, not a graph resume claim. |

## Metadata

Ordinary corpus `class`, `input`, `expected`, `hooks`, and exact `assert_request`
fields remain unchanged. `class: "durable"` enables SQLite. Optional `durable_mode`
is a closed set: `source-free` (default), `candidate-exact`, `candidate-mismatch`,
`configuration-mismatch`, or `start-only`. The mismatch modes still require the
initial successful `expected` value. The latter skips restart deliberately and
must never be presented as recovered execution. Typos and use on other classes fail.

## Boundaries and known limitations

- Source-free means the resume request provides no source path; the checked-in
  source is not deleted. The retained executable is used by the public API.
- A literal-only candidate change was classified `CosmeticManifestDifference`
  during validation. The example changes the signature instead; do not infer
  full semantic equivalence from candidate acceptance in this implementation.
- The terminal two-child graph resumed as `invalid-authoritative-prefix` during
  validation. Its checked-in mode demonstrates start/join/shutdown only.
  The public API also has `RunnableReplacementUnavailable` for recognized
  unfinished graphs; this adapter does not claim to repair that path.
- A sequential three-action package timed out before initial terminal publication
  during validation. The recovery-class scenarios intentionally use one action
  each. They do not demonstrate interrupted-operation retry or unknown outcomes.
- Existing crash-cut conformance coverage lives in
  `crates/gantry-conformance/tests/automatic_durable_root/recovery.rs`; the
  `async_recovery.rs` test audits its evidence manifest. These examples do not
  substitute an orderly restart for that crash-cut coverage.
- Durable adapter-identity accounting is explicitly unavailable. See the real
  rejection demonstration in `../embedding/resource_policy`.
