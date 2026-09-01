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

The syntax-only boundary for parametric declarations and static traits is
documented in [`frontend-generics-and-traits.md`](frontend-generics-and-traits.md).

The implemented analyzer boundary for generic binders, exact local inference,
regular recursion, sealed structural capabilities, and generic-analysis limits
is documented in
[`analyzer-generics-and-traits.md`](analyzer-generics-and-traits.md).

The analyzer profile's written static argument, explicit assumptions, bounded
model, and counterexample-replay links are documented in
[`analyzer-package-validity.md`](analyzer-package-validity.md).

The nondurable sequential evaluator's progress, preservation, cancellation,
operation-consumption, lifecycle, observation, and terminal-uniqueness
argument is documented in
[`sequential-evaluator-refinement.md`](sequential-evaluator-refinement.md).

The reference SQLite journal adapter's ownership, fencing, effective durability
settings, restart evidence, and deliberately unqualified power-loss boundary
are documented in [`sqlite-journal-storage.md`](sqlite-journal-storage.md).
