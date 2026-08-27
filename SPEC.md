# Gantry Specification

## 1. Status and Scope

Gantry is a proposed, Rust-inspired control language for coordinating
model-backed agents. It is named for the elevated structure spanning a factory
floor: a Gantry program directs and observes the work performed below it.

Gantry is harness-neutral. Mezzanine may integrate Gantry, but it is not an
assumed runtime or part of the language contract. An integration supplies the
agents, models, tools, transport, credentials, resource policy, and any
provider-specific behavior.

This document records the settled version 1 (v1) requirements. Sections
marked as open design work identify decisions required before syntax and full
operational semantics can become normative.

## 2. Normative Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119.

## 3. Implementation and Execution Model

1. Gantry MUST provide its own grammar, lexer, parser, and abstract syntax
   tree (AST).
2. Gantry MUST execute source directly. It MUST NOT require compilation to a
   different language or runtime as its execution model.
3. Gantry MUST be available as an embeddable Rust library. It does not
   implement an agent, model provider, or transport itself.
4. The interpreter MUST control program flow, hook invocation, result
   validation, retry handling, and state transitions.
5. An integration MUST implement the hooks needed to perform agent/model
   calls. It is responsible for mapping Gantry agent names to its own agents
   or models.
6. Model selection, tool access, approvals, authentication, persistence
   backend selection, logging backend selection, timeouts, cancellation
   mechanics, and resource limits belong to the integrating agent.
7. Gantry execution MUST be serializable and resumable. Gantry MUST provide a
   journal, or an equivalent durable execution record, sufficient to continue
   an interrupted execution from its recorded state. Section 11 defines the
   required recovery behavior.
8. Gantry does not promise deterministic replay. Re-execution of the same
   source and inputs MAY produce different agent results. Resumption MUST,
   however, reuse operation results already committed to the journal.
9. v1 makes no backward-compatibility promise for source, serialized state,
   or the Rust hook API.

## 4. Source Organization

1. Gantry source files MUST use the `.gnt` extension.
2. A package entry point is `main.gnt`, and its selected entry function is
   `fn main()`.
3. Gantry MUST support comments and SHOULD adopt Rust lexical conventions
   where they fit the v1 feature set. Rust likeness is primarily a syntactic
   and readability goal; Gantry does not inherit Rust semantics by default.
4. Names MUST be declared before use. Gantry uses lexical scope.
5. Gantry MUST support namespaces and whole-module imports through a
   Rust-inspired `mod` form. Included files are parsed as independent modules,
   not textual insertion into the caller's scope.
6. Module paths MUST be local, relative paths and MUST remain inside the same
   package. Remote paths, absolute paths, environment expansion, and package
   resolution are excluded from v1.
7. Duplicate declarations are errors. Visibility constraints are excluded from
   v1.

## 5. Values, Bindings, and Structs

1. Runtime values MUST include `String`, declared struct values,
   `Option<T>`, and lists. User-visible Boolean values are excluded from v1;
   Boolean decisions exist only inside the interpreter.
2. Parameters and returned values MAY be `String`, a declared struct type, or
   `Option<T>` of either. A function or method MAY have no returned value.
3. `Option<T>` MAY appear in parameters, bindings, returned values, and struct
   fields. `Some(value)` and `None` MUST be constructible and inspectable by
   Gantry code using deterministic interpreter operations that do not invoke
   an agent hook.
4. Struct fields MAY be `String`, declared struct values, or `Option<T>` of
   either. Nested and recursive struct definitions are permitted. Every cycle
   in a recursive type definition MUST pass through `Option<T>` so that a
   finite value can terminate the recursion.
5. Gantry MUST support named-field struct construction. Struct values MAY be
   constructed by source execution or produced by an agent hook.
6. Structs MUST support field defaults, optional fields, update syntax, and
   destructuring.
7. Bindings are immutable by default. `mut` enables rebinding and field
   mutation. Assignments MUST preserve type, and v1 permits no implicit type
   coercion.
8. `const` is excluded from v1. Runtime initialization of immutable bindings
   is permitted.
9. Built-in deterministic string operations are excluded from v1.

## 6. Functions and Methods

1. Gantry MUST support free functions and inherent methods declared in
   Rust-inspired `impl` blocks. Traits are excluded from v1.
2. Methods MUST support `self` and `mut self` receivers.
3. A method may mutate its receiver. Such updates MUST be transactional: a
   failed operation MUST NOT leave interpreter-managed receiver state partly
   updated.
4. Functions and methods are interpreter-managed workflows. Calling one MUST
   create an interpreter call frame and execute its body; the call itself MUST
   NOT invoke an agent hook.
5. A workflow body MAY contain one or more explicit agent operation
   expressions. Each such expression, and each conditional or loop decision,
   MUST invoke exactly one agent operation hook. Struct construction, field
   access, assignment, `Option<T>` construction or inspection, module lookup,
   function or method dispatch, and `join` are interpreter operations and MUST
   NOT invoke an agent hook.
6. Each agent operation MUST contain an explicit prompt. Operation variables
   MUST be interpolated into that prompt.
7. The final agent operation in a function or method supplies its return value
   unless an explicit `return` supplies an earlier operation result. A workflow
   whose signature has no return type MAY complete without an agent-produced
   value.

## 7. Agents, Hooks, and Sessions

1. A Gantry program MUST support a declared list of agent names and a default
   agent. Every operation MUST support selecting an agent by name.
2. Agent names are logical identifiers. Their mapping to concrete models or
   agent implementations is exclusively the integration's responsibility.
3. Hooks are synchronous. Gantry parallelism is expressed with `spawn` and
   `join`, not by an asynchronous language-level hook contract.
4. Every operation hook MUST receive structured input containing the
   information needed to perform the operation, including a stable operation
   ID, attempt number, operation kind, source location, prompt, interpolated
   variables, selected agent, expected output schema, logical session ID,
   session directive, prior validation errors, and execution context. The
   operation ID MUST remain stable across validation retries and resume.
5. Hooks MUST receive the expected output schema as a separate
   machine-readable value. Gantry MUST provide guidance that clearly states
   the operation's input and output contract; the exact guidance may evolve.
6. The only v1 operation-selection knob is the agent name. System/user/
   assistant roles, model choice, tools, sampling settings, streaming,
   progress reporting, timeouts, and cancellation mechanics are integration
   concerns.
7. A hook MUST return one of three host-level outcomes: `Completed(value)`,
   `Declined(reason)`, or `Failed(message)`. `Completed` contains the strict
   JSON value to validate. `Declined` produces `None` only when the operation's
   expected type is `Option<T>`; for every other result type, including a
   control decision, it aborts execution. `Failed` aborts execution and is not
   a structured-output validation failure.
8. Gantry MUST assign a logical session ID to each operation. Session IDs MUST
   remain stable across validation retries and resume. An integration MUST
   honor the following session directives:
   - `inline` reuses the enclosing logical session;
   - `fork` creates one child session initialized from the enclosing session;
   - `new` creates one session without inherited conversational context.
   A `fork` or `new` session is created once when its enclosing construct is
   entered and is reused by that construct. Nested constructs inherit the
   active session unless they explicitly select another directive.
9. The integration MUST preserve the conversational continuity denoted by a
   reused logical session ID. Provider-specific session storage and mapping
   remain integration concerns.
10. Agent operations may have side effects. Gantry does not require retries to
    be idempotent or prevent duplicate external effects.

## 8. Structured Output and Validation

1. A successful agent hook outcome MUST contain strict JSON for its operation
   result.
2. A `String` result is represented by a JSON string. A struct result is a
   JSON object whose property names directly match its declared field names.
3. `Some(value)` is represented by the JSON encoding of `value`, and `None` is
   represented by JSON `null`. An `Option<T>` struct property MAY also be
   omitted; omission and explicit `null` both normalize to `None`.
4. Gantry MUST derive JSON Schema Draft 2020-12 from declared output types
   during semantic analysis and MUST independently validate every successful
   hook result against that schema. Recursive types MUST use `$defs` and
   `$ref`.
5. Struct results MUST reject unknown properties. Declared fields are required
   unless represented by `Option<T>`.
6. v1 validation MUST check JSON shape and types. Constraints such as length,
   patterns, enums, and semantic validity are conveyed through prompt guidance
   rather than enforced by Gantry.
7. Malformed JSON and schema-invalid output MUST be returned to the agent as
   validation guidance and retried up to the configured retry limit.
8. The retry limit is configured per interpreter and MAY be overridden per
   operation. It counts retries after the initial attempt; zero permits exactly
   one attempt. Retry backoff MUST be configurable with sensible defaults.
9. When retries are exhausted, the operation and program MUST fail. Gantry has
   no language-level error recovery in v1.
10. Transport failures and their retry policy are integration concerns, not
   Gantry structured-output retries.
11. Source snippets MAY be included in validation diagnostics. Raw agent
    output MUST NOT be included in validation diagnostics.

## 9. Control Flow

1. Gantry MUST support `if`, `else if`, and `else`. Each `if` or `else if`
   condition is exactly one agent decision operation.
2. A conditional decision MUST return a strict JSON object containing a
   Boolean decision and a string rationale. Gantry uses only the Boolean to
   select control flow and retains the rationale for observability.
3. Gantry MUST support `while` as a pre-test loop and `until` as a post-test
   loop. Each condition evaluation invokes its agent decision operation again.
4. Gantry MUST support `loop` with a session directive and a limit directive.
   The session values are `new`, `fork`, and `inline`; `inline` is the default.
   A limit accepts an integer from zero through the maximum supported integer;
   zero means no language-imposed limit.
5. Gantry MUST support `break`, `continue`, and `return` in loops. `break`
   exits its enclosing loop.
6. `for` and `match` are excluded from v1.
7. Control decisions MUST use the same schema-validation and retry policy as
   other structured agent results.
8. Gantry imposes no mandatory loop, cost, or agent-call limit. Integrations
   MAY impose their own limits.

## 10. Parallel Execution

1. Gantry MUST support `spawn <name> { ... }`, `join <name>`, and `joinall`.
2. A spawn creates an arbitrary child program block running in parallel. The
   spawn name declares a new, lexically scoped, unique, interpreter-owned task
   handle. A task handle is not a `String`, is not agent-visible structured
   data, and is not otherwise a first-class runtime value.
3. A spawned block captures outer variables by copy and MUST NOT mutate outer
   variables. It MAY mutate its local captured copies.
4. A spawned block has the type of its yielded value, or no-result type when it
   yields no value. `join <name>` waits for the named child and yields that
   typed block value. Joining a no-result block is a waiting statement and
   yields no value.
5. `joinall` waits for all tasks in its lexical scope and discards their
   outputs.
6. A child failure does not immediately cancel siblings. Its failure is
   deferred until joined.
7. Unjoined tasks detach on scope exit. Detached tasks and nested spawns are
   permitted.
8. Parent timeout and cancellation constraints apply to spawned children and
   their descendants. The integration determines concurrency limits, queueing,
   thread usage, and concrete cancellation mechanics.

## 11. Journal and Resume Semantics

1. Gantry MUST durably journal committed operation results, validation attempt
   counts, interpreter call frames, scopes, instruction positions, loop state,
   task relationships, and values needed to resume execution.
2. A hook dispatch MUST be recorded before the hook is invoked, and its outcome
   MUST be committed atomically before execution consumes it.
3. If execution is interrupted after dispatch but before an outcome is
   committed, the operation is indeterminate. Gantry MUST halt resumption and
   ask the integration to resolve the operation as completed, failed, or safe
   to retry. Gantry MUST NOT automatically repeat an indeterminate operation.
4. An integration that resolves an indeterminate operation as completed MUST
   supply its outcome. An integration that resolves it as safe to retry accepts
   that the operation has at-least-once side-effect semantics.
5. Committed results MUST be reused during resume and MUST NOT consume the
   remaining validation-retry budget again. Invalid attempts and retry counts
   MUST also be journaled.
6. Journals MUST identify the exact source content and journal format version.
   Gantry MUST reject resume when the source identity differs or the journal
   format is unsupported.
7. These resume guarantees do not create a deterministic-replay guarantee for
   a new execution.

## 12. Observability and Validation Modes

1. Gantry MUST expose events for parsing, call start and end, prompts, schema,
   validation failure, retry, branch decision, spawn, join, mutation, and
   failure.
2. Each event MUST include a source location and parent/child operation IDs.
   Prompts and schemas MUST be observable through the event interface.
3. Gantry MUST support a separately configured raw event sink through which
   completed agent outputs are observable. Raw agent output MUST be omitted
   from default human-readable diagnostics and ordinary validation events.
4. A dry-run performs syntax validation only and MUST NOT invoke agent hooks.

## 13. Open Design Work Before Syntax Is Finalized

The following contracts remain intentionally unresolved and must be specified
before the grammar and detailed evaluator semantics are finalized:

- the exact prompt-operation form, interpolation rules, and agent-selection
  syntax;
- the exact `loop`, `while`, `until`, session, retry, and return grammar;
- `Option<T>` inspection syntax, struct update syntax, and destructuring syntax;
- `join` binding forms, `joinall` failure aggregation, and
  detached-task ownership;
- the journal storage API and recovery of in-flight child tasks;
- the exact module-resolution forms, package-root definition, module-cycle
  behavior, and recursive declaration rules.
