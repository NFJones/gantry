# Gantry Documentation

`SPEC.md` is the normative Gantry v1 language and runtime contract. It is
organized as separately addressable language-reference, static-semantics,
abstract-machine, durable-execution, embedding-protocol, observability and
security, and executable-authoring-guide artifacts.

The revised v1 contract makes integration behavior source-explicit:

- `Unit` is the sole no-information result; `None` only means option absence.
- `prompt` and `decide` are externally read-only and receive only explicit
  inputs plus the canonical Gantry session transcript.
- actions declare `read_only`, `idempotent`, or `non_idempotent` recovery.
- `attempt` provides narrow typed `OperationError` recovery.
- workflows have inferred effect sets and may assert `pure`.
- attached tasks are structured; `detach` transfers work to durable background
  ownership; joins are all-settled.
- execution budgets, canonical IR identity, explicit migration, Unicode
  identifier security, and versioned conformance schemas are portable parts of
  the contract.

Section 14 of `SPEC.md` contains the canonical authoring examples and common
error corrections. Repository implementation status remains documented in the
top-level `README.md`.

The complete twelve-field package-activity policy, its reset and applicability
rules, stable failures, and reference CLI values are documented in
[`frontend-resource-policy.md`](frontend-resource-policy.md).
That guide also defines bounded blocking-work admission, owned package-source
and analysis jobs, caller-cancellation behavior, interpreter shutdown
ownership, and SQLite worker isolation.

The versioned binary identity, eligibility, limits, total order, deterministic
hash, and compatibility boundary for the sealed scalar-key domain are
documented in [`canonical-scalar-keys.md`](canonical-scalar-keys.md).

The syntax-only boundary for parametric declarations and static traits is
documented in [`frontend-generics-and-traits.md`](frontend-generics-and-traits.md).

The complete source-author guide, executable package, diagnostic examples,
resource-policy summary, and deliberate feature exclusions are documented in
[`generics-and-traits.md`](generics-and-traits.md).

The source-author guide to `spawn`, named `join`, lexical `joinall()`, explicit
`detach`, copied captures, forked child sessions, foreground and terminal
observation, executor ownership and limits, CLI worker policy, and durable
resume is documented in [`parallel-execution.md`](parallel-execution.md). Its
hook-free analyzable package is
[`examples/parallel-execution/main.gnt`](../examples/parallel-execution/main.gnt).

The implemented analyzer boundary for generic binders, exact local inference,
regular recursion, sealed structural capabilities, and generic-analysis limits
is documented in
[`analyzer-generics-and-traits.md`](analyzer-generics-and-traits.md).

The analyzer profile's written static argument, explicit assumptions, bounded
model, and counterexample-replay links are documented in
[`analyzer-package-validity.md`](analyzer-package-validity.md).

The nondurable evaluator's closed generic applications, static trait calls,
logical-copy behavior, concrete operation schemas, and no-runtime-solver
boundary are documented in
[`sequential-generics-and-traits.md`](sequential-generics-and-traits.md).

The nondurable concurrent evaluator's exact generic task captures and results,
task-path operation identities, all-settled and lifecycle behavior, and
deterministic/Tokio schedule equivalence are documented in
[`concurrent-generics-and-traits.md`](concurrent-generics-and-traits.md).

The durable runtime's authenticated generic artifacts, source-free and
candidate-source resume, compacted and fresh-process reconstruction, and
pre-execution tamper rejection are documented in
[`durable-generics-and-traits.md`](durable-generics-and-traits.md).

Executor-backed graph reconstruction, committed operation/session reuse, and
the remaining recovery qualification boundary are documented in
[`executor-backed-recovery.md`](executor-backed-recovery.md).

The composed sequential, concurrent, and durable executor-backed refinement,
including its finite model bounds and physical-submission exclusions, is
documented in [`async-execution-refinement.md`](async-execution-refinement.md).

The `gantry run` multithread Tokio default, positive `--workers` option, runtime
ownership, and shutdown behavior are documented in
[`cli-runtime-policy.md`](cli-runtime-policy.md).

The assembled executor-backed publication baseline, embedding migration from
manual root driving, durable compatibility boundary, and release
qualifications are documented in
[`async-execution-release.md`](async-execution-release.md).

The general-purpose effort's fixed platform, embedding-hook, agent-run,
performance, representative-application, rerun, and claim-blocking boundaries
are documented in
[`general-purpose-preregistration.md`](general-purpose-preregistration.md).

The nondurable sequential evaluator's progress, preservation, cancellation,
operation-consumption, lifecycle, observation, and terminal-uniqueness
argument is documented in
[`sequential-evaluator-refinement.md`](sequential-evaluator-refinement.md).

The reference SQLite journal adapter's ownership, fencing, effective durability
settings, restart evidence, and deliberately unqualified power-loss boundary
are documented in [`sqlite-journal-storage.md`](sqlite-journal-storage.md).
