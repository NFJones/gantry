# Example navigation and offline validation

Start with the [teaching path](#teaching-path), then use the category tables below.
Each linked package with `case.json` contains executable expected outcomes and a
README explaining its source, commands, and coverage limits. The
[specification](../SPEC.md) is normative; a passing example proves only its
declared assertions, not every semantic property discussed in its README.

## Choose the right runner

Run these commands from the repository root. The default CLI supports sequential,
hook-free execution; `check` tests syntax, `analyze` tests source semantics, and
`run` prints the result as JSON:

```sh
just run check examples/basics/hello-value
just run analyze examples/basics/hello-value
just run run examples/basics/hello-value
```

Host operations, concurrent execution, and SQLite durability need the public Rust
embedding surface and configured adapters, not a promise that default CLI `run`
can execute them. The shared [offline runner](../crates/gantry-conformance/examples/corpus.rs)
uses real analysis/interpreter APIs with scripted hook responses, finite limits,
and bounded shutdown. No credentials, model service, sockets, or network access
are used. Cargo also runs offline, so dependencies must already be cached.

| `case.json` class | What a passing scenario establishes |
| --- | --- |
| `cli` | A hook-free result equals the expected JSON. The corpus runner uses the public interpreter, not a CLI subprocess. |
| `host` | Scripted prompt/decide/action outcomes and typed results; hook kinds, script consumption, and any `assert_request` JSON pointers are checked. This is not a live provider integration. |
| `concurrent` | Task execution and the declared result under the Tokio adapter; hooks, if present, are still offline scripts. Sibling scheduling order is not guaranteed. |
| `durable` | Real SQLite-backed execution through the durable adapter; the selected `durable_mode` controls restart assertions or start-only coverage. See the durability limits below. |
| `negative` | Parsing/analysis returns `SourceInvalid` with the named `expected_diagnostic` among its codes. No execution occurs; a pass means expected rejection. |
| `runtime-failure` | Valid source is accepted for execution, then its foreground outcome fails with exactly `expected_error`. Start rejection or a timeout is not a passing failure demonstration. |

One package may contain multiple scenarios, including success and expected-failure
classes. Category placement alone does not determine the class; read `case.json`.
The runner checks exact JSON values (including explicit `null`) and consumes every
scripted response. Concurrent scripts must not assume FIFO dispatch by siblings.
It also checks terminal categories independently of foreground outcomes. Success
cases require terminal `success` unless `expected_terminal` explicitly overrides
it; concurrent error cases use `expected_error` instead of `expected`.

```sh
# All case.json packages; default total subprocess deadline is 600 seconds.
python3 scripts/validate-examples.py
# One package, or a whole category directory:
python3 scripts/validate-examples.py examples/types/structs-defaults
python3 scripts/validate-examples.py examples/agents
# Equivalent direct Rust runner: PATH is a package directory containing case.json.
cargo run --offline -p gantry-conformance --example corpus -- PATH
# A corpus/category directory needs --all with the direct runner:
timeout 180 cargo run --offline -p gantry-conformance --example corpus -- --all examples/concurrency
# Dedicated SQLite restart and Rust embedding demonstrations:
timeout 180 cargo test --offline -p gantry-conformance --test example_durability
```

The Python wrapper resolves a supplied path relative to the caller, chooses
package versus `--all` mode, and accepts `--timeout SECONDS`. Each corpus scenario
has a 30-second deadline and a one-second runtime shutdown bound. Validation
discovers only `case.json` packages: it does **not** run the Rust embedding demos
or older source-only packages. Use the dedicated test above for embedding.

## Teaching path

1. [Hello value](basics/hello-value/) → [bindings](basics/bindings-assignment/)
   → [checked arithmetic](basics/checked-arithmetic/).
2. [Explicit structs with declared defaults](types/structs-defaults/)
   → [options](types/options/) → [results](types/results/)
   → [matching](control-flow/match_forms/).
3. [Workflow composition](control-flow/workflow_composition/)
   → [file modules](modules/file_modules/) → [trait bounds](generics/trait-bounds/).
4. [Typed prompts](agents/prompt-structured/) → [named inputs](agents/named-inputs/)
   → [read-only actions](actions/read-only/) → [validation retry](actions/validation-retry/)
   → [external JSON boundaries](boundaries/source-default-vs-json/).
5. [Scoped sessions](sessions/scoped-new/) → [named spawn/join](concurrency/spawn-named-join/)
   → [composed workflows](workflows/README.md).
6. Contrast [invalid source](invalid/README.md) with
   [expected runtime failures](runtime-failures/README.md), then study
   [committed-result restart](durability/committed_result/) and
   [Rust embedding lifecycle](embedding/lifecycle/).

## Values, language structure, and pure computation

| Category | Packages | Focus |
| --- | --- | --- |
| [Basics](basics/) | [hello-value](basics/hello-value/), [unit](basics/unit/), [bindings-assignment](basics/bindings-assignment/), [checked-arithmetic](basics/checked-arithmetic/), [conversions](basics/conversions/), [short-circuit-equality](basics/short-circuit-equality/), [nested-struct-copy](basics/nested-struct-copy/) | Entry values, mutation, arithmetic, conversion, equality, copy semantics (`cli`). |
| [Types](types/) | [structs-defaults](types/structs-defaults/), [enums](types/enums/), [options](types/options/), [results](types/results/), [lists-tuples-aggregates](types/lists-tuples-aggregates/), [recursive-structs](types/recursive-structs/) | Typed construction, variants, aggregates, guarded recursion (`cli`). Defaults example uses explicit fields; omission is blocked. |
| [Strings](strings/) | [inspection](strings/inspection/), [parsing](strings/parsing/), [split-join](strings/split-join/), [transforms](strings/transforms/), [unicode](strings/unicode/) | String operations, parsing and Unicode behavior (`cli`). |
| [Control flow](control-flow/) | [early_returns](control-flow/early_returns/), [for_snapshot](control-flow/for_snapshot/), [if_let_match](control-flow/if_let_match/), [loop_limit](control-flow/loop_limit/), [match_forms](control-flow/match_forms/), [recursive_pure](control-flow/recursive_pure/), [until_posttest](control-flow/until_posttest/), [while_pretest](control-flow/while_pretest/), [workflow_composition](control-flow/workflow_composition/) | Branching, loop snapshots/bounds, recursion and composition (`cli`). |
| [Errors as values](errors/) | [checked-assertions](errors/checked-assertions/), [domain-error-conversion](errors/domain-error-conversion/), [propagation-success](errors/propagation-success/) | Assertions on valid paths, domain normalization and result propagation (`cli`). |
| [Generics and traits](generics/) | [declared-fn-alias](generics/declared-fn-alias/), [generic-workflows](generics/generic-workflows/), [receiver-copy](generics/receiver-copy/), [regular-recursion](generics/regular-recursion/), [static-traits](generics/static-traits/), [trait-bounds](generics/trait-bounds/), [type-inference](generics/type-inference/) | Aliases, monomorphization, receiver copying, static dispatch and inference (`cli`). |
| [Modules](modules/) | [file_modules](modules/file_modules/), [inline_nested](modules/inline_nested/), [path_imports](modules/path_imports/) | File/inline modules and imports (`cli`); retain the complete directory when running. |

## Host boundaries and orchestration

| Category | Packages | Focus |
| --- | --- | --- |
| [Agents and prompts](agents/) | [decide-routing](agents/decide-routing/), [interpolation](agents/interpolation/), [literal-forms](agents/literal-forms/), [named-inputs](agents/named-inputs/), [prompt-string](agents/prompt-string/), [prompt-structured](agents/prompt-structured/), [prompt-unit](agents/prompt-unit/), [retained-decision](agents/retained-decision/), [reusable-judgment](agents/reusable-judgment/), [scoped-selection](agents/scoped-selection/) | Typed prompts/decisions, request envelopes and agent selection (`host`). |
| [Actions and attempts](actions/) | [attempt-action](actions/attempt-action/), [attempt-decide](actions/attempt-decide/), [attempt-prompt](actions/attempt-prompt/), [domain-result](actions/domain-result/), [fallback-can-fail](actions/fallback-can-fail/), [idempotent](actions/idempotent/), [non-idempotent](actions/non-idempotent/), [read-only](actions/read-only/), [retry-exhaustion](actions/retry-exhaustion/), [validation-retry](actions/validation-retry/) | Recovery classes, bounded retries, attempts and domain results (`host` and `runtime-failure` scenarios). |
| [Typed boundaries](boundaries/) | [invalid-output](boundaries/invalid-output/), [optional-omission](boundaries/optional-omission/), [source-default-vs-json](boundaries/source-default-vs-json/), [typed-entry](boundaries/typed-entry/), [validation-retry-prompt](boundaries/validation-retry-prompt/) | Entry/hook JSON validation and normalization (`host` and `runtime-failure` scenarios); source defaults do not relax required external fields. |
| [Sessions](sessions/) | [inline](sessions/inline/), [operation-fork](sessions/operation-fork/), [operation-new](sessions/operation-new/), [scope-overrides](sessions/scope-overrides/), [scoped-fork](sessions/scoped-fork/), [scoped-new](sessions/scoped-new/) | Session selection, new/fork identity and scope inheritance (`host`). |
| [Concurrency](concurrency/) | [child-failure-all-settled](concurrency/child-failure-all-settled/), [copied-captures](concurrency/copied-captures/), [detach-foreground-terminal](concurrency/detach-foreground-terminal/), [heterogeneous-join](concurrency/heterogeneous-join/), [homogeneous-join](concurrency/homogeneous-join/), [lexical-joinall](concurrency/lexical-joinall/), [nested-tasks](concurrency/nested-tasks/), [parallel-sessions-agents](concurrency/parallel-sessions-agents/), [spawn-named-join](concurrency/spawn-named-join/), [unit-tasks](concurrency/unit-tasks/) | Task ownership, copied captures, joins, detach and parallel scopes (`concurrent`). |
| [Composed workflows](workflows/README.md) | [application_approval_action](workflows/application_approval_action/), [bounded_review_revise](workflows/bounded_review_revise/), [classify_enum_route](workflows/classify_enum_route/), [durable_batch](workflows/durable_batch/), [extract_validate_fallback](workflows/extract_validate_fallback/), [module_workflow](workflows/module_workflow/), [parallel_compare_synthesize](workflows/parallel_compare_synthesize/), [readme_research_brief](workflows/readme_research_brief/) | Application review, bounded revision, routing, extraction, modules and evidence; Host, Concurrent, and Durable cases. Research/publication are scripted, not real external work. |

## Durability and Rust embedding

| Category | Packages | Scope |
| --- | --- | --- |
| [SQLite durability](durability/README.md) | [candidate_check](durability/candidate_check/), [committed_result](durability/committed_result/), [configuration_check](durability/configuration_check/), [recovery_classes](durability/recovery_classes/), [source_free](durability/source_free/), [task_graph](durability/task_graph/) | Durable adapter: committed-result reuse, candidate/configuration checks, source-free resume; task graph is **start-only**. |
| [Rust embedding](embedding/README.md) | [lifecycle](embedding/lifecycle/), [observation](embedding/observation/), [resource_policy](embedding/resource_policy/); driver [demos.rs](embedding/demos.rs) | Dedicated `example_durability` test, not `case.json` discovery: cancellation/shutdown, required event delivery/privacy, finite resource policy and explicit durable refusal. |

Restart demonstrations await committed terminal state, orderly-shut down, close
and reopen SQLite, then resume with a fresh interpreter and no scripted restart
hooks. They establish **logical orderly SQLite restart**, not killed-process,
mid-operation crash, power-loss durability, interrupted-operation retry, or
recovery of external effects. `durable_mode: "start-only"` deliberately skips
restart; [task_graph](durability/task_graph/) therefore makes no graph-resume claim.
[durable_batch](workflows/durable_batch/) demonstrates committed-result restart,
not interrupted batch recovery. Source-free resume omits the candidate source
path; it does not delete the checked-in source.

See the [durability limitations](durability/README.md#boundaries-and-known-limitations):
terminal graph resume has failed with `invalid-authoritative-prefix`, unfinished
graph replacement may be unavailable, and a sequential multi-action demonstration
timed out. Candidate acceptance must not be interpreted as proof of complete
semantic equivalence. Durable adapter-identity accounting is unavailable;
[resource_policy](embedding/resource_policy/) demonstrates the refusal. The Rust
embedding demos do not prove resource exhaustion or external transport delivery.

## Expected rejections and failures

| Category | Packages | Passing means |
| --- | --- | --- |
| [Negative source](invalid/README.md) | [detach-capture](invalid/detach-capture/), [duplicate-declaration](invalid/duplicate-declaration/), [generic-arity](invalid/generic-arity/), [generic-bound](invalid/generic-bound/), [generic-inference](invalid/generic-inference/), [import-path](invalid/import-path/), [incompatible-pattern](invalid/incompatible-pattern/), [integer-literal-range](invalid/integer-literal-range/), [list-index-type](invalid/list-index-type/), [missing-annotation](invalid/missing-annotation/), [missing-return](invalid/missing-return/), [mixed-list](invalid/mixed-list/), [mixed-numeric](invalid/mixed-numeric/), [never-signature](invalid/never-signature/), [none-without-context](invalid/none-without-context/), [nonexhaustive-pattern](invalid/nonexhaustive-pattern/), [option-unit](invalid/option-unit/), [polymorphic-recursion](invalid/polymorphic-recursion/), [pure-effect](invalid/pure-effect/), [recursive-type](invalid/recursive-type/), [sealed-boundary](invalid/sealed-boundary/), [shadow-binding](invalid/shadow-binding/), [task-double-consumption](invalid/task-double-consumption/), [task-unconsumed](invalid/task-unconsumed/), [unreachable-source](invalid/unreachable-source/), [unsupported-closure](invalid/unsupported-closure/), [unsupported-errors](invalid/unsupported-errors/), [unsupported-syntax](invalid/unsupported-syntax/) | Named diagnostic observed without execution (`negative`); individual READMEs link to valid corrections. |
| [Runtime failures](runtime-failures/README.md) | [assertion](runtime-failures/assertion/), [empty-replace](runtime-failures/empty-replace/), [empty-split](runtime-failures/empty-split/), [float-division-zero](runtime-failures/float-division-zero/), [integer-division-zero](runtime-failures/integer-division-zero/), [integer-overflow](runtime-failures/integer-overflow/), [integer-remainder-zero](runtime-failures/integer-remainder-zero/), [list-index-bounds](runtime-failures/list-index-bounds/), [loop-limit](runtime-failures/loop-limit/), [panic](runtime-failures/panic/) | Accepted execution reaches the exact foreground error, not analysis failure or wall-clock timeout (`runtime-failure`). |

## Older source-only examples and supporting data

These have no `case.json` and are not counted by the offline corpus validator:

| Path | Purpose and route |
| --- | --- |
| [generics-and-traits](generics-and-traits/main.gnt) | Combined positive generics/traits tour; default CLI check/analyze/run as in the [root quick start](../README.md#check-and-run-a-package). |
| [generics-and-traits-invalid](generics-and-traits-invalid/) | Older negative sources: [cyclic-obligation](generics-and-traits-invalid/cyclic-obligation/main.gnt), [duplicate-parameter](generics-and-traits-invalid/duplicate-parameter/main.gnt), [incomplete-inference](generics-and-traits-invalid/incomplete-inference/main.gnt), [polymorphic-recursion](generics-and-traits-invalid/polymorphic-recursion/main.gnt). Check/analyze individually; use `invalid/` for executable diagnostic assertions. |
| [parallel-execution](parallel-execution/main.gnt) | Source-only spawn/join/joinall/detach tour; requires concurrent library support for execution. Use `concurrency/` for offline expected-result packages. |
| [frontend-limits.json](frontend-limits.json) | Supporting frontend-limit configuration, not a runnable source package or an override of the corpus runner's built-in limits. |

## Evidence boundaries

- [structs-defaults](types/structs-defaults/) declares defaults but constructs
  complete values explicitly. Omitted-field materialization remains blocked;
  incomplete struct output must not become a positive normative expectation.
- [source-default-vs-json](boundaries/source-default-vs-json/) does not validate
  missing required entry-field rejection or default-bearing hook output. See its
  documented gaps rather than inferring coverage from the package name.
- The [detach example](concurrency/detach-foreground-terminal/) checks foreground
  success independently of terminal `success` or `detached-task-failure`. It does
  not force foreground completion to occur before child settlement.
- Scripts prove typed dispatch and declared request assertions, not real model
  quality, actual research, publication, tool effects, or exactly-once external
  execution. These examples make **no `std` model source API promises**: the host
  supplies model/tool policy and integration; use only documented, supported
  source syntax and public embedding contracts.
