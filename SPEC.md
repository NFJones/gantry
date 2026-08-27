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
3. Gantry MUST be available as an embeddable Rust library with an asynchronous
   execution API. It does not implement an agent, model provider, or transport
   itself.
4. The interpreter MUST control program flow, hook invocation, result
   validation, retry handling, and state transitions.
5. An integration MUST implement the hooks needed to perform agent/model
   calls. It is responsible for mapping Gantry agent names to its own agents
   or models.
6. Model selection, tool access, approvals, authentication, persistence
   backend selection, logging backend selection, timeouts, cancellation
   policy, and resource limits belong to the integration. Gantry MUST provide
   the asynchronous task scheduling needed to execute parallel Gantry blocks.
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
   `fn main()`. The directory containing `main.gnt` is the package root.
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
7. A file module declaration `mod foo;` resolves relative to the declaring
   module as either `foo.gnt` or `foo/mod.gnt`. If both candidates exist,
   analysis MUST fail as ambiguous. The package root is a containment boundary,
   not an alternate lookup directory for nested modules.
8. Inline modules of the form `mod foo { ... }` MUST be supported. Module items
   are visible package-wide in v1 and qualified access uses Rust-inspired
   `module::item` paths.
9. `mod` declarations MUST precede references to their namespace. Module cycles,
   duplicate declarations, and duplicate module resolutions are analysis
   errors. Visibility constraints are excluded from v1.
10. A function MAY call itself and a struct MAY refer to its own type even
    though names otherwise must be declared before use. Mutual recursion
    between distinct functions or types is excluded from v1.

## 5. Values, Bindings, and Structs

1. Runtime values MUST include `String`, declared struct values, and
   `Option<T>`. Lists and user-visible Boolean or integer values are excluded
   from v1. Boolean decisions exist only inside the interpreter. Nonnegative
   integer literals MAY occur only in language directives such as loop limits
   and retry counts; they are not values that source code can bind or pass.
2. Parameters and returned values MAY be `String`, a declared struct type, or
   `Option<T>` of either. A function or method MAY have no returned value.
3. `Option<T>` MAY appear in parameters, bindings, returned values, and struct
   fields. `Some(value)` and `None` MUST be constructible by deterministic
   interpreter operations. Gantry code MUST NOT inspect an option through
   deterministic branching, pattern matching, `if let`, or an unwrap
   operation in v1; a program that needs to branch on an option MUST supply it
   to an agent decision operation.
4. Struct fields MAY be `String`, declared struct values, or `Option<T>` of
   either. Nested and recursive struct definitions are permitted. Every cycle
   in a recursive type definition MUST pass through `Option<T>` so that a
   finite strict-JSON value can terminate the recursion. An unguarded recursive
   cycle is an analysis error because it has no finite inhabitant.
5. Gantry MUST support named-field struct construction. Struct values MAY be
   constructed by source execution or produced by an agent hook.
6. Struct fields MAY declare literal defaults. Defaults MUST NOT invoke an
   agent operation. When an optional field with a default is omitted, the
   default is assigned; explicit `null` remains `None`. Struct update syntax
   and destructuring are excluded from v1.
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
3. A method may mutate its receiver only through interpreter-executed field
   assignments in its body. An assignment that consumes an agent operation
   result MUST commit atomically only after that operation completes and its
   output validates. A failed operation MUST leave the assignment target
   unchanged; external hook side effects are not rolled back. This operation-
   level atomicity is the v1 transaction boundary.
4. Functions and methods are interpreter-managed workflows. Calling one MUST
   create an interpreter call frame and execute its body; the call itself MUST
   NOT invoke an agent hook.
5. A workflow body MAY contain one or more `prompt` expressions. Each `prompt`
   expression, and each conditional or loop decision, MUST invoke exactly one
   agent operation hook. Struct construction, field access, assignment,
   `Option<T>` construction, module lookup, function or method dispatch, and
   `join` are interpreter operations and MUST NOT invoke an agent hook.
6. Each `prompt` expression MUST contain an explicit prompt template. Template
   variables MUST be interpolated before hook dispatch. The source template and
   the interpolated prompt MUST both be supplied to the hook.
7. A trailing expression in a function, method, or spawned block implicitly
   yields its value. An explicit `return` MAY yield earlier from a function or
   method. A workflow whose signature has no return type MAY complete without a
   value. Values of standalone `prompt` expressions, assignments, and `spawn`
   statements MAY be discarded.
8. A method MAY return `self`; the returned value is a deep value copy and does
   not consume the receiver. Duplicate inherent methods for the same struct are
   analysis errors.

## 7. Agents, Hooks, and Sessions

1. A Gantry program MUST declare its permitted agent names and a dedicated
   default-agent binding in source. Absence of a default agent, duplicate agent
   names, or selection of an undeclared agent is an analysis error.
2. Agent names are logical identifiers. Their mapping to concrete models or
   agent implementations is exclusively the integration's responsibility.
3. Agent selection is lexical. A `with <name> { ... }` context selects the named
   agent for all nested operations unless a nested `with` context overrides it.
   `with` contexts MAY occur at any block scope. Operations outside such a
   context use the declared default agent.
4. The Rust hook contract MUST be asynchronous so Gantry can schedule parallel
   blocks without blocking its executor. Each individual operation awaits one
   hook outcome before it advances and is therefore logically synchronous.
   Gantry MUST obtain an independently usable hook instance for each concurrent
   task; it MUST NOT invoke one non-concurrent hook instance simultaneously.
5. Every operation hook request MUST contain at least:
   - stable operation, execution, and parent-operation IDs;
   - an operation kind and selected agent name;
   - the original prompt template and interpolated prompt;
   - JSON-serialized typed arguments;
   - the expected JSON Schema;
   - the source location;
   - the logical session ID and session directive;
   - the attempt number; and
   - validation errors from the immediately preceding invalid attempt, when
     applicable.
   The operation ID MUST remain stable across validation retries and resume.
   Each attempt MUST have a distinct attempt identity.
6. Prompt interpolation MUST use `${name}` for a binding reference. `$$` MUST
   produce one literal dollar sign, so `$${name}` renders the literal text
   `${name}` without interpolation. A `String` is interpolated as its string
   contents; a struct or `Option<T>` is interpolated as compact strict JSON.
   Missing names and values that cannot be encoded are analysis or runtime
   errors, respectively.
7. Hooks MUST receive the expected output schema as a separate
   machine-readable value. Gantry MUST provide guidance that clearly states
   the operation's input and output contract; the exact guidance may evolve.
8. The only v1 operation-selection knob is the agent name. System/user/
   assistant roles, model choice, tools, sampling settings, streaming,
   progress reporting, timeouts, and cancellation mechanics are integration
   concerns.
9. A hook MUST return one of three host-level outcomes: `Completed(value)`,
   `Declined(reason)`, or `Failed(message)`. `Completed` contains the strict
   JSON value to validate. `Declined` produces `None` only when the operation's
   expected type is `Option<T>`; for every other result type, including a
   control decision, it aborts execution. `Failed` aborts execution and is not
   a structured-output validation failure.
10. Gantry MUST assign a logical session ID to each operation. Session IDs MUST
   remain stable across validation retries and resume. An integration MUST
   honor the following session directives:
   - `inline` reuses the enclosing logical session;
   - `fork` creates a child session initialized from the enclosing session; and
   - `new` creates a session without inherited conversational context.
   Nested constructs inherit the active directive unless they override it. For
   a loop, `fork` creates a separate child session for each body execution,
   while `new` creates one fresh session on loop entry and reuses it for every
   body execution. Outside a loop, `fork` and `new` each create one session on
   entry to their annotated construct.
11. The integration MUST preserve the conversational continuity denoted by a
   reused logical session ID. Provider-specific session storage and mapping
   remain integration concerns.
12. Agent operations may have side effects. Gantry does not require retries to
    be idempotent or prevent duplicate external effects.

## 8. Structured Output and Validation

1. A successful agent hook outcome MUST contain strict JSON for its operation
   result.
2. A `String` result is represented by a JSON string. A struct result is a
   JSON object whose property names directly match its declared field names.
3. `Some(value)` is represented by the JSON encoding of `value`, and `None` is
   represented by JSON `null`. An `Option<T>` struct property MAY also be
   omitted. Omission assigns the field's declared literal default when one
   exists and otherwise normalizes to `None`; explicit `null` always normalizes
   to `None`.
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
   validation guidance and retried up to the configured retry limit. A retry
   request MUST include the preceding validation errors but MUST NOT require
   Gantry to return the preceding raw output to the hook.
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
   condition MUST ultimately perform exactly one agent decision operation. The
   condition MAY be a direct prompt expression or a call to a workflow whose
   result is a control decision; calling the workflow does not add a second
   hook invocation.
2. A conditional decision MUST return this strict JSON shape, with no
   additional properties:

   ```json
   {
     "decision": true,
     "rationale": "A nonempty explanation"
   }
   ```

   `decision` MUST be a JSON Boolean and `rationale` MUST be a nonempty JSON
   string. Gantry uses only `decision` to select control flow and retains the
   rationale for observability. A decision is interpreter-only and cannot be
   bound as a user-visible Boolean value.
3. Each `else if` performs a separate decision operation. Its hook request MUST
   include the decisions and rationales produced by preceding arms in the same
   conditional chain.
4. Gantry MUST support `while` as a pre-test loop and `until` as a post-test
   loop. `until` MUST execute its body once before its first decision. Each
   condition evaluation invokes its agent decision operation again.
5. The general loop form is `loop(session = inline, limit = 0) { ... }`.
   `while` and `until` MUST also accept `session`, `limit`, and structured-output
   retry modifiers. Agent selection is inherited from a lexical `with` context
   rather than specified as a loop modifier.
6. A loop session is `new`, `fork`, or `inline`, with `inline` as the default.
   A loop limit is a nonnegative directive integer up to the implementation's
   maximum supported integer. It counts body executions. Zero always means
   unlimited and MUST NOT be reinterpreted by interpreter configuration.
   Reaching a positive limit completes the loop normally rather than failing.
7. Gantry MUST support `break`, `continue`, and `return` in loops. Unlabeled
   `break` and `continue` target the nearest enclosing loop. Labeled loop
   control is excluded from v1.
8. `for`, `match`, and deterministic `if let` are excluded from v1.
9. Control decisions MUST use the same schema-validation and retry policy as
   other structured agent results.
10. Gantry imposes no mandatory loop, cost, or agent-call limit. Integrations
    MAY impose their own limits, except that such policy does not alter the
    language meaning of `limit = 0`.

## 10. Parallel Execution

1. Gantry MUST support `spawn <name> { ... }`, `join <name>`, and `joinall`.
2. A spawn creates an arbitrary child program block running in parallel. The
   spawn name declares a new, lexically scoped, unique, interpreter-owned task
   handle. A task handle is not a `String`, is not agent-visible structured
   data, and is not otherwise a first-class runtime value.
3. A spawned block captures outer variables by copy and MUST NOT mutate outer
   variables. The capture is a deep immutable snapshot taken when `spawn`
   executes. A child MAY create mutable local bindings from, or mutate its own
   local copy of, captured values without affecting the parent.
4. A spawned block has the type of its yielded value, or no-result type when it
   yields no value. `join <name>` waits for the named child and yields that
   typed block value. A join result MAY be bound as
   `let result: T = join task;`. Joining a no-result block is a waiting
   statement and yields no value.
5. `joinall` waits until all tasks in its lexical scope have settled and
   discards successful outputs. It MUST NOT stop waiting merely because one
   task fails. After all tasks settle, one or more failures MUST abort the
   current program with one aggregate runtime error.
6. A child failure does not immediately cancel siblings. A named child's
   failure is deferred until `join`; a scoped failure is deferred until
   `joinall`.
7. Unjoined tasks detach on scope exit. Detached tasks and nested spawns are
   permitted. The interpreter instance owns detached tasks, and a top-level
   execution MAY report success while they continue to run.
8. A detached-task failure MUST be journaled and emitted as a failure event. It
   MUST NOT retroactively change an already returned top-level success into a
   failure. If execution is still awaiting that task through `join` or
   `joinall`, the ordinary join failure rules apply.
9. Parent timeout and cancellation constraints apply while a child remains
   attached and propagate through its attached descendants. Detachment releases
   the task from those parent constraints. Integration-specific operation
   timeouts and cancellation policy MAY still apply.
10. Gantry MUST schedule spawned blocks on its asynchronous runtime. The
    integration determines operation-level resource limits and queueing policy.
    Dropping an interpreter instance MUST wait for its detached tasks to settle.

## 11. Journal and Resume Semantics

1. Gantry MUST durably journal committed operation results, validation attempt
   counts, interpreter call frames, scopes, instruction positions, loop state,
   task relationships, and values needed to resume execution.
2. Gantry MUST expose a journal-storage trait through which an integration
   provides durable storage. The trait MUST support atomic append and flush
   operations sufficient to establish the commit points required by this
   section.
3. A hook dispatch MUST be recorded and flushed before the hook is invoked, and
   its outcome MUST be committed atomically before execution consumes it.
4. If execution is interrupted after dispatch but before an outcome is
   committed, the operation is indeterminate. On resume, Gantry MUST
   automatically invoke that operation again with the same operation ID and a
   new attempt ID. Integrations MUST therefore assume at-least-once invocation
   and possible duplicate external side effects.
5. Committed results MUST be reused during resume and MUST NOT consume the
   remaining validation-retry budget again. Invalid attempts and retry counts
   MUST also be journaled.
6. Journals MUST identify the exact source content and journal format version.
   Gantry MUST reject resume when the source identity differs or the journal
   format is unsupported.
7. Recovery MUST restore scopes, instruction positions, call frames, loop
   counters, task relationships, and committed values. An in-flight spawned
   block MUST restart at the top of that block while reusing every committed
   operation result recorded for it. Uncommitted operations are retried under
   item 4.
8. These resume guarantees do not create a deterministic-replay guarantee for
   a new execution.

## 12. Observability and Validation Modes

1. Gantry MUST expose events for parsing, call start and end, prompts, schema,
   validation failure, retry, branch decision, spawn, join, mutation, and
   failure.
2. Each event MUST include a source location and parent/child operation IDs.
   Event order is guaranteed within one task but not across concurrent tasks;
   IDs MUST permit reconstruction of cross-task causality.
3. Raw agent outputs MUST be present in the applicable structured event
   payloads. Prompts and schemas MUST be observable by journal or event IDs
   referenced from events rather than duplicated in every event. Raw output
   MUST remain omitted from default human-readable diagnostics and validation
   error text.
4. Event delivery failures MUST be retried according to a configurable event
   delivery policy. If delivery remains unsuccessful after exhaustion,
   execution MUST fail.
5. A dry-run performs syntax validation only and MUST NOT invoke agent hooks.
   Gantry MUST separately provide an analysis mode that performs name, type,
   module, and schema validation without invoking hooks.
6. Normal execution MUST complete semantic analysis successfully before its
   first hook invocation.

## 13. Open Design Work Before Syntax Is Finalized

The semantic requirements above are sufficient to begin grammar design. The
following narrower contracts remain intentionally open:

- exact declaration syntax for agent names and the default-agent binding;
- exact `prompt` result annotation, retry override, session annotation, and
  prompt literal grammar;
- declaration syntax for workflow functions that produce interpreter-only
  control decisions;
- precedence and attachment rules for `while` and `until` prompt conditions;
- the concrete asynchronous hook-factory, cancellation, journal-storage, and
  event-sink Rust APIs; and
- journal and event payload formats, versioning rules, and event-delivery retry
  defaults.
