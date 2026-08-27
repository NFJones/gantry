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
   execution API. It does not implement an agent, model provider, transport, or
   hidden asynchronous runtime itself. The embedding application MUST supply
   the executor used to poll Gantry futures. Gantry MUST permit its task
   scheduler or executor adapter to be replaced through library configuration,
   not through Gantry source syntax.
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
11. Gantry MUST support Rust-inspired `use` declarations as well as qualified
    `module::item` access. `use` does not change item visibility.
12. Module filenames and identifiers MUST be valid UTF-8 and MAY use
    `snake_case`, `camelCase`, or `PascalCase`. A module declaration's
    identifier and resolved filesystem name MUST match exactly, including case.
13. Top-level package and module contents MUST be declarations. Executable
    statements are permitted only within function, method, decision, spawn, or
    other executable block bodies.

## 5. Values, Bindings, and Structs

1. Runtime values MUST include `String`, declared struct values, `Option<T>`,
   and `List<T>`. User-visible Boolean or integer values are excluded from v1.
   Boolean decisions exist only inside the interpreter. Nonnegative integer
   literals MAY occur only in language directives such as loop limits and retry
   counts; they are not values that source code can bind or pass.
2. Parameters and returned values MAY be `String`, a declared struct type,
   `Option<T>`, or `List<T>` whose element type is otherwise permitted. A
   function, method, prompt, or spawned block MAY have no returned value.
   Omission of a result annotation and the explicit result annotation `-> None`
   both denote this no-result form; they do not denote `Option<T>`.
3. `Option<T>` and `List<T>` MAY appear in parameters, bindings, returned
   values, and struct fields. `Some(value)` and `None` MUST be constructible
   by deterministic interpreter operations. Gantry code MUST NOT inspect an option through
   deterministic branching, pattern matching, `if let`, or an unwrap
   operation in v1; a program that needs to branch on an option MUST supply it
   to an agent decision operation.
4. `List<T>` is an ordered, homogeneous collection. List literals, indexing,
   iteration, and deterministic list operations are excluded from v1; v1 lists
   are produced by agent operations, returned by joins, passed as values, and
   represented in schemas and JSON.
5. Struct fields MAY be `String`, declared struct values, `Option<T>`, or
   `List<T>` of an otherwise permitted type. Nested and recursive struct
   definitions are permitted. Every cycle in a recursive type definition MUST
   pass through `Option<T>` or `List<T>` so that a finite strict-JSON value can
   terminate the recursion. An unguarded recursive cycle is an analysis error
   because it has no finite inhabitant.
6. Gantry MUST support named-field struct construction. Struct values MAY be
   constructed by source execution or produced by an agent hook.
7. Struct fields MAY declare literal defaults. Defaults MUST NOT invoke an
   agent operation. When an optional field with a default is omitted, the
   default is assigned; explicit `null` remains `None`. Struct update syntax
   and destructuring are excluded from v1.
8. Bindings are immutable by default. `mut` enables rebinding and field
   mutation. Assignments MUST preserve type, and v1 permits no implicit type
   coercion.
9. `const` is excluded from v1. Runtime initialization of immutable bindings
   is permitted.
10. Built-in deterministic string and list operations are excluded from v1.

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
6. Each `prompt` expression MUST contain an explicit prompt template and MAY
   contain parenthesized operation modifiers before that template. A typed
   prompt places its result annotation after the template, as in
   `prompt(retry_limit = 2, session = fork) "..." -> Report`. A prompt with no
   result annotation, or with `-> None`, has no result.
7. Template expressions MUST be interpolated before hook dispatch. An
   interpolation MAY contain a binding, field path, constructor, function call,
   or method call. Interpolations are evaluated in source order before the
   containing prompt operation is dispatched; any nested prompt operations
   caused by those calls complete first. The source template and interpolated
   prompt MUST both be supplied to the hook.
8. A trailing expression in a function, method, or spawned block implicitly
   yields its value. An explicit `return` MAY yield earlier from a function or
   method. Every explicit or implicit returned expression MUST exactly match
   the declared result type. A workflow whose signature omits a result type
   implicitly returns no result. Values of standalone `prompt` expressions,
   assignments, and `spawn` statements MAY be discarded.
9. A method MAY return `self`; the returned value is a deep value copy and does
   not consume the receiver. Duplicate inherent methods for the same struct are
   analysis errors.

## 7. Agents, Hooks, and Sessions

1. A Gantry program MUST declare its permitted agent names in one or more
   `agents { ... }` declarations. Declarations from all package modules are
   merged into one package-wide set; repeating the same logical name is
   idempotent rather than an error. Exactly one dedicated
   `default agent = <name>;` binding MUST appear in `main.gnt`, and its name
   MUST belong to the merged set. Conflicting default bindings or selection of
   an undeclared agent are analysis errors. Integrations MUST resolve every
   occurrence of the same logical name to the same integration-side agent
   configuration.
2. Agent names are logical identifiers. Their mapping to concrete models or
   agent implementations is exclusively the integration's responsibility.
3. Agent selection is lexical. A `with <name> { ... }` context selects the named
   agent for all nested operations unless a nested `with` context overrides it.
   `<name>` MUST be a literal name from the merged agent declarations, not a
   runtime binding. `with` contexts MAY occur at any block scope. Operations
   outside such a context use the declared default agent.
4. The Rust hook contract MUST be asynchronous and its futures MUST be `Send`
   so Gantry tasks can execute on a multithreaded executor. Each individual
   operation awaits one hook outcome before it advances and is therefore
   logically synchronous. Gantry MUST obtain an independently usable hook
   instance for each concurrent task from an asynchronous hook factory; it
   MUST NOT invoke one non-concurrent hook instance simultaneously. The
   conceptual factory contract is one `OperationHook` per `TaskContext`.
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
6. A hook request MUST also contain an ordered execution-context vector. Each
   context entry MUST identify its kind, source operation, and associated
   structured data so that an integration can decide whether and how to use it.
   The vector MUST preserve execution order. In particular, an `else if`
   request MUST include the decisions and rationales from preceding arms in
   this vector by default.
7. Prompt interpolation MUST use `${expression}`. `$$` MUST
   produce one literal dollar sign, so `$${name}` renders the literal text
   `${name}` without interpolation. A `String` is interpolated as its string
   contents; a struct, `Option<T>`, or `List<T>` is interpolated as compact
   strict JSON, with `None` rendered as `null`. Invalid references and values
   that cannot be encoded are analysis or runtime errors, respectively.
8. A quoted prompt literal MAY contain literal newline characters, which MUST
   be preserved in both its template and interpolated forms. The complete
   escape grammar remains part of grammar design.
9. Hooks MUST receive the expected output schema as a separate
   machine-readable value. Gantry MUST provide guidance that clearly states
   the operation's input and output contract; the exact guidance may evolve.
10. The only v1 operation-selection knob is the agent name. System/user/
   assistant roles, model choice, tools, sampling settings, streaming,
   progress reporting, timeouts, and cancellation mechanics are integration
   concerns.
11. A hook MUST return one of three host-level outcomes: `Completed(value)`,
   `Declined(reason)`, or `Failed(message)`. `Completed` contains the strict
   JSON value to validate. `Declined` produces `None` only when the operation's
   expected type is `Option<T>`; for every other result type, including a
   control decision, it aborts execution. `Failed` aborts execution and is not
   a structured-output validation failure.
12. Gantry MUST assign a logical session ID to each operation. Session IDs MUST
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
13. The integration MUST preserve the conversational continuity denoted by a
   reused logical session ID. Provider-specific session storage and mapping
   remain integration concerns.
14. Agent operations may have side effects. Gantry does not require retries to
    be idempotent or prevent duplicate external effects.

## 8. Structured Output and Validation

1. A successful agent hook outcome MUST contain strict JSON for its operation
   result.
2. A `String` result is represented by a JSON string. A struct result is a
   JSON object whose property names directly match its declared field names.
3. A `List<T>` result is represented by a JSON array. Every array item MUST
   validate as `T`, and item order MUST be preserved. Gantry MUST derive an
   array schema with the schema for `T` as its `items` schema.
4. `Some(value)` is represented by the JSON encoding of `value`, and `None` is
   represented by JSON `null`. An `Option<T>` struct property MAY also be
   omitted. Omission assigns the field's declared literal default when one
   exists and otherwise normalizes to `None`; explicit `null` always normalizes
   to `None`.
5. Gantry MUST derive JSON Schema Draft 2020-12 from declared output types
   during semantic analysis and MUST independently validate every successful
   hook result against that schema. Recursive types MUST use `$defs` and
   `$ref`.
6. Struct results MUST reject unknown properties. Declared fields are required
   unless represented by `Option<T>`.
7. v1 validation MUST check JSON shape and types. Constraints such as length,
   patterns, enums, and semantic validity are conveyed through prompt guidance
   rather than enforced by Gantry.
8. Malformed JSON and schema-invalid output MUST be returned to the agent as
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
   conditional chain through the ordered execution-context vector.
4. Gantry MUST support `while` as a pre-test loop and `until` as a post-test
   loop. `until` MUST execute its body once before its first decision. Each
   condition evaluation invokes its agent decision operation again.
5. The general loop form is `loop(session = inline, limit = 0) { ... }`.
   `loop { ... }` is equivalent to the form with all defaults. `while` and
   `until` place parenthesized modifiers before their decision expression, as
   in `while(session = fork, limit = 10, retry_limit = 2) prompt "..." { ... }`.
   They MUST accept `session`, `limit`, and `retry_limit` modifiers. Agent
   selection is inherited from a lexical `with` context rather than specified
   as a loop modifier. `retry_limit` counts retries after the initial attempt.
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
11. A direct prompted condition uses `if prompt "..." { ... }`. Gantry MUST
    also support `decision` workflow declarations whose final yielded value is
    an interpreter-only decision. A decision workflow MAY contain multiple
    prompts, nested decisions, and other executable blocks, but each evaluation
    of its final decision MUST ultimately be produced by exactly one prompt
    hook result with the decision schema in item 2.

## 10. Parallel Execution

1. Gantry MUST support annotated spawn declarations of the form
   `spawn <name> -> <type> { ... }`, joins of the form
   `join(<task-name>, ...)`, and `joinall`.
2. A spawn creates an arbitrary child program block running in parallel. The
   spawn name declares a new, lexically scoped, unique, interpreter-owned task
   handle. A task handle is not a `String`, is not agent-visible structured
   data, and is not otherwise a first-class runtime value.
3. A spawned block captures outer variables by copy and MUST NOT mutate outer
   variables. The capture is a deep immutable snapshot taken when `spawn`
   executes. A child MAY create mutable local bindings from, or mutate its own
   local copy of, captured values without affecting the parent.
4. A spawned block MUST declare the type of its yielded value with `-> T`, or
   declare `-> None` when it yields no value. Its trailing expression MUST
   exactly match that annotation. `spawn` declares the named handle but does
   not itself yield the handle as a value.
5. `join(task)` waits for one named child and yields that child's typed block
   value. A join result MAY be bound as `let result: T = join(task);`. Joining
   a no-result block is a waiting statement and yields no value.
   `join(task_a, task_b, ...)` waits for every named child and yields an ordered
   `List<T>` of their successful block values in argument order. Every joined
   task in a multi-task join MUST have the same non-`None` result type; mixing
   result types or joining a no-result task in this form is an analysis error.
6. `joinall` is syntactic sugar for joining every task in the current lexical
   scope. It waits until all such tasks have settled and yields an ordered
   `List<T>` in task declaration order when every joined task has the same
   non-`None` result type. Otherwise it is a waiting statement that discards
   successful outputs. It MUST NOT stop waiting merely because one task fails.
   After all tasks settle, one or more failures MUST abort the current program
   with one aggregate runtime error.
7. A child failure does not immediately cancel siblings. A named child's
   failure is deferred until `join`; a scoped failure is deferred until
   `joinall`.
8. Unjoined tasks detach on scope exit. Detached tasks and nested spawns are
   permitted. The interpreter instance owns detached tasks, and a top-level
   execution MAY report success while they continue to run.
9. A detached-task failure MUST be journaled and emitted as a failure event. It
   MUST NOT retroactively change an already returned top-level success into a
   failure. If execution is still awaiting that task through `join` or
   `joinall`, the ordinary join failure rules apply.
10. Parent timeout and cancellation constraints apply while a child remains
   attached and propagate through its attached descendants. Detachment releases
   the task from those parent constraints. Integration-specific operation
   timeouts and cancellation policy MAY still apply.
11. Gantry MUST schedule spawned blocks through the executor supplied by the
    embedding application. The integration determines operation-level resource
    limits and queueing policy.
12. The embedding API MUST provide `shutdown().await`, which waits for detached
    tasks and performs an orderly interpreter shutdown. Embedders MUST call it
    before dropping the interpreter. Because Rust destruction cannot await,
    dropping an interpreter without shutdown MUST initiate a documented bounded
    fallback that prevents new work and cancels remaining owned tasks; it MUST
    NOT block indefinitely while pretending to provide awaited shutdown.

## 11. Journal and Resume Semantics

1. Gantry MUST durably journal committed operation results, validation attempt
   counts, interpreter call frames, scopes, instruction positions, loop state,
   task relationships, and values needed to resume execution.
2. Gantry MUST expose a journal-storage trait through which an integration
   provides durable storage. The trait MUST expose atomic append and flush
   operations only; Gantry defines the transaction and commit boundaries built
   from those operations.
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

- the full quoted-string escape grammar and interpolation-expression grammar;
- the concrete asynchronous hook-factory, scheduler, cancellation,
  journal-storage, and event-sink Rust APIs;
- the exact bounded fallback performed when an interpreter is dropped without
  `shutdown().await`;
- journal and event payload formats and versioning rules;
- event-delivery retry defaults, backoff, durability, and failure behavior; and
- whether a future aggregate value type should allow multi-task `join` to yield
  results rather than discard them.
