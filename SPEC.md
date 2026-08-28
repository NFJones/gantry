# Gantry Specification

## 1. Status and Scope

Gantry is a proposed, Rust-inspired control language for coordinating
model-backed agents. It is named for the elevated structure spanning a factory
floor: a Gantry program directs and observes the work performed below it.

Gantry is harness-neutral. Mezzanine may integrate Gantry, but it is not an
assumed runtime or part of the language contract. An integration supplies the
agents, models, tools, transport, credentials, resource policy, and any
provider-specific behavior.

This document records the settled version 1 (v1) language and operational
requirements. Concrete Rust type signatures may remain implementation-defined
where the semantic contract is fully specified here.

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
   the root module's `fn main`. The directory containing `main.gnt` is the
   package root. `main` MUST have either no parameters or exactly one typed
   parameter and MAY return any v1 result type or no result. When `main` has a
   parameter, the embedding application MUST supply one strict-JSON entry
   value, which Gantry MUST validate against the parameter's generated schema
   before execution begins. When `main` has no parameter, supplying an entry
   value is an error. Gantry MUST return a successful entry result to the
   embedder as strict JSON together with a host-level indication of whether the
   function returned a value; this indication distinguishes a no-result
   `main` from an `Option<T>` result whose JSON value is `null`.
3. Gantry MUST support comments and SHOULD adopt Rust lexical conventions
   where they fit the v1 feature set. Rust likeness is primarily a syntactic
   and readability goal; Gantry does not inherit Rust semantics by default.
4. Names MUST be declared before use. Gantry uses lexical scope.
5. Gantry MUST support namespaces and whole-module imports through a
   Rust-inspired `mod` form. Included files are parsed as independent modules,
   not textual insertion into the caller's scope.
6. Module paths MUST be local, relative paths and MUST remain inside the same
   package. Remote paths, absolute paths, environment expansion, and package
   resolution are excluded from v1. Module resolution MUST reject `.` and `..`
   path components and symbolic links. Rejecting symbolic links keeps package
   containment and source identity independent of host filesystem aliasing.
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
    item paths. An unprefixed path begins in the current module's lexical
    namespace. `crate::` begins at the package root, `self::` begins at the
    current module, and each leading `super::` moves outward by one module.
    Escaping above the package root is an analysis error. `use` follows the
    same path rules and does not change item visibility.
12. Module filenames and identifiers MUST be valid UTF-8 and MAY use
    `snake_case`, `camelCase`, or `PascalCase`. A module declaration's
    identifier and resolved filesystem name MUST match exactly, including case.
    Module path components MUST be Unicode Normalization Form C (NFC); an
    implementation MUST reject a non-NFC component rather than silently
    normalize it.
13. Top-level package and module contents MUST be declarations. Executable
    statements are permitted only within function, method, decision, spawn, or
    other executable block bodies.
14. Gantry MUST collect all module declarations and package-wide agent names
    before resolving item bodies. This collection pass is the only exception
    to declared-before-use ordering; it does not make functions, types, or
    imports usable before their declarations. Within one module, item names
    MUST be unique across structs, functions, decisions, and modules. An
    imported name MUST NOT collide with another import or local item.
15. Struct field names, parameter names, and method names for one receiver type
    MUST each be unique. A local binding or task handle MUST NOT duplicate or
    shadow any parameter, binding, or task handle visible at its declaration
    point. Fields and methods occupy their receiver's member namespace and MAY
    reuse names that exist in unrelated lexical scopes. These rules deliberately
    exclude source-level shadowing in v1 so references remain unambiguous to
    both readers and static analysis.

## 5. Values, Bindings, and Structs

1. Runtime values MUST include `String`, declared struct values, `Option<T>`,
   `List<T>`, and `Tuple<T1, T2, ..., Tn>`. User-visible Boolean or integer
   values are excluded from v1.
   Boolean decisions exist only inside the interpreter. Nonnegative integer
   tokens MAY occur only in language directives such as loop limits and retry
   counts and in deterministic list or tuple projections; they are not values
   that source code can bind or pass.
2. Parameters and returned values MAY be `String`, a declared struct type,
   `Option<T>`, `List<T>`, or `Tuple<T1, T2, ..., Tn>` whose member types are
   otherwise permitted. A function, method, prompt, or spawned block MAY have
   no returned value.
   Omission of a result annotation and the explicit result annotation `-> None`
   both denote this no-result form; they do not denote `Option<T>`.
3. `Option<T>`, `List<T>`, and `Tuple<T1, T2, ..., Tn>` MAY appear in
   parameters, bindings, returned values, and struct fields. `Some(value)` and
   `None` MUST be constructible by deterministic interpreter operations.
   Gantry code MUST NOT inspect an option through
   deterministic branching, pattern matching, `if let`, or an unwrap
   operation in v1; a program that needs to branch on an option MUST supply it
   to an agent decision operation. `Option<Option<T>>` is excluded from v1
   because the untagged strict-JSON encoding cannot distinguish `None` from
   `Some(None)`.
4. `List<T>` is an ordered, homogeneous collection. v1 supports zero-based
   deterministic projection with `value[index]`, where `index` is a
   nonnegative integer token. Projection yields `T`; an out-of-bounds list
   projection is a fatal runtime error. List literals, iteration, length
   queries, and other deterministic list operations are excluded from v1; v1
   lists are produced by agent operations, returned by joins, passed as values,
   and represented in schemas and JSON.
5. `Tuple<T1, T2, ..., Tn>` is an ordered, fixed-arity heterogeneous
   collection. Its arity MUST be at least two, and each positional member MAY
   have a distinct otherwise permitted type. v1 supports zero-based
   deterministic projection with `value[index]`; the literal index MUST be in
   bounds during analysis and the projection's static type is the type at that
   tuple position. Tuple literals, destructuring, iteration, and other
   deterministic tuple operations are excluded from v1; v1 tuples are produced
   by agent operations or multi-task joins, passed as values, and represented
   in schemas and JSON.
6. Struct fields MAY be `String`, declared struct values, `Option<T>`,
   `List<T>`, or `Tuple<T1, T2, ..., Tn>` of otherwise permitted types. Nested and recursive struct
   definitions are permitted. Every cycle in a recursive type definition MUST
   pass through `Option<T>` or `List<T>` so that a finite strict-JSON value can
   terminate the recursion. An unguarded recursive cycle is an analysis error
   because it has no finite inhabitant.
7. Gantry MUST support named-field struct construction. Struct values MAY be
   constructed by source execution or produced by an agent hook. A source
   constructor MUST reject unknown and duplicate fields during analysis.
   Constructor field expressions are evaluated once in source order. Omitted
   required fields are analysis errors; an omitted field with a default uses
   that default, and an omitted `Option<T>` field without a default becomes
   `None`. A constructed value becomes visible only after every supplied field
   expression completes successfully. Earlier hook side effects are not
   reversible if a later field expression fails.
8. Struct fields MAY declare literal defaults. Defaults MUST NOT invoke an
   agent operation. When an optional field with a default is omitted, the
   default is assigned; explicit `null` remains `None`. Struct update syntax
   and destructuring are excluded from v1.
9. Bindings are immutable by default. `mut` enables rebinding and field
   mutation. Assignments MUST preserve type, and v1 permits no implicit type
   coercion.
10. `const` is excluded from v1. Runtime initialization of immutable bindings
   is permitted.
11. Built-in deterministic string operations and list operations other than
    projection are excluded from v1. Lists and tuples are typed transport
    aggregates: source may pass, return, interpolate, submit, or project them,
    but cannot branch on, iterate over, or otherwise inspect them
    deterministically.

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
   Arguments and receivers use deep-copy value semantics. There are no aliases,
   references, moves, or borrowed values in v1. A `self` or `mut self` receiver
   is therefore a local receiver copy. `mut self` permits mutation of that copy
   but never changes the caller's value implicitly; callers MUST assign a
   returned value explicitly when they intend to retain receiver changes.
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
7. Template expressions MUST be interpolated before hook dispatch. To keep
   agent invocation explicit, an interpolation MAY contain only bindings,
   field paths, literals, and deterministic struct or `Option<T>` constructor
   expressions composed from other permitted interpolation expressions.
   Function calls, method calls, `prompt`, decisions, assignment, `join`, and
   other expressions that can invoke a hook, alter control flow, or mutate
   state are prohibited inside interpolation. Interpolations are evaluated in
   source order. If any interpolation cannot be evaluated or encoded, the
   containing prompt MUST remain undispatched and execution MUST fail. The
   source template and interpolated prompt MUST both be supplied to the hook.
8. A trailing expression in a function, method, or spawned block implicitly
   yields its value. An explicit `return` MAY yield earlier from a function or
   method. Every explicit or implicit returned expression MUST exactly match
   the declared result type. A workflow whose signature omits a result type
   implicitly returns no result. Values of standalone `prompt` expressions,
   assignments, and `spawn` statements MAY be discarded. Semantic analysis
   MUST prove that every reachable normal completion of a value-returning
   function, method, or spawned block yields the declared type. Falling through
   a value-returning body is an analysis error; it MUST NOT be deferred to a
   runtime missing-value failure.
9. A method MAY return `self`; the returned value is a deep value copy and does
   not consume the receiver. Duplicate inherent methods for the same struct are
   analysis errors.
10. `return` exits the nearest enclosing function, method, or decision workflow.
    `break` and `continue` target the nearest enclosing loop even when they
    occur inside a nested `with` block. A `with` block changes agent selection
    only; it does not intercept or retarget control transfer.

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
4. The Rust hook contract MUST be asynchronous and executor-neutral. Its
   futures MUST be `Send + 'static` so Gantry tasks can execute on a
   multithreaded executor, and Gantry's public API MUST NOT expose Tokio- or
   provider-specific types. Each individual operation awaits one hook outcome
   before it advances and is therefore logically synchronous. Gantry MUST
   obtain one independently usable `OperationHook` instance for each Gantry
   task from an asynchronous `HookFactory`. That instance MUST live for the
   task's entire lifetime, including nested workflow calls and validation
   retries, and MUST NOT be invoked concurrently with itself. A spawned child
   receives a distinct hook instance. `HookFactory::create` MUST receive a
   `TaskContext` containing task, execution, parent-task, and inherited logical
   session identity. Agent selection MUST remain part of each operation
   request because a task can enter different lexical `with` contexts. Hook
   creation may fail but cannot decline; failure aborts creation of the task.
   Gantry MUST give every hook a Gantry-owned cancellation token whose signal
   the integration MUST make a best effort to honor.
   Public asynchronous extension traits MUST use executor-neutral boxed
   futures or equivalent stable abstractions. The executor adapter MUST provide
   task spawning, task joining, task abortion, and asynchronous sleeping for
   backoff. Gantry MUST retain its own cancellation semantics rather than
   treating executor abortion as cooperative hook cancellation.
5. Every operation hook request MUST contain at least:
   - a protocol major and minor version;
   - stable operation, execution, and parent-operation IDs;
   - an operation kind and selected agent name;
   - the original prompt template and interpolated prompt;
   - JSON-serialized typed arguments;
   - the expected result kind;
   - the expected JSON Schema;
   - generated operation guidance describing the input contract, output
     contract, and required strict-JSON response;
   - the source location;
   - the logical session ID and session directive;
   - a dispatch ID, validation-attempt number, and recovery-dispatch number;
     and
   - validation errors from the immediately preceding invalid attempt, when
     applicable.
   The v1 operation kinds are `prompt` and `decision`. The result kind is
   `value`, `no-result`, or `decision`. Typed arguments MUST be an ordered
   vector containing one record for each interpolation island in source order;
   each record contains the source expression, its static type, and its strict-
   JSON value. A repeated interpolation appears repeatedly so the request
   preserves the template's operation inputs exactly. Source locations MUST
   identify the package-relative UTF-8 file and half-open byte span. The
   operation ID MUST remain stable across validation retries and resume. Each
   physical hook invocation MUST have a distinct dispatch ID. The zero-based
   validation-attempt number advances only after Gantry receives output that
   fails UTF-8, JSON parsing, or schema validation; it is bounded by the
   operation's structured-output retry limit. The zero-based recovery-dispatch
   number advances when an indeterminate invocation is repeated after resume
   and does not consume that retry budget. Validation errors MUST identify the
   failing JSON instance location with JSON Pointer when one exists, the
   violated schema location when one exists, and a human-readable message;
   they MUST NOT contain raw model output.
6. A hook request MUST also contain a finite ordered execution-context vector.
   It MUST contain the active workflow call chain and the control-chain entries
   needed to interpret the current operation; it MUST NOT contain the entire
   event history or all events since session creation. Each context entry MUST
   identify its kind, source operation when applicable, and associated
   structured data. The canonical v1 context kinds and payloads are:
   - `workflow-frame`: workflow path, call-site location, and frame occurrence;
   - `decision-frame`: decision workflow path and frame occurrence;
   - `conditional-arm`: conditional-chain ID, zero-based arm index, decision,
     and nonempty rationale for an already evaluated arm;
   - `loop-iteration`: loop operation ID, zero-based body-execution index, and
     phase (`condition` or `body`); and
   - `optional-decline`: declined operation ID, selected agent, source location,
     and decline reason when a decline normalized to `None`.
   Entries MUST be ordered from outermost to innermost scope, with repeated
   entries in execution order within one scope. An `else if` request MUST
   include the `conditional-arm` entries from preceding arms in the same
   chain. A decline that becomes `None` MUST remain available to subsequent
   operations in the active workflow/control chain through an
   `optional-decline` entry. The integration MUST make every supplied entry
   available to the selected agent in order, although its provider-specific
   presentation is implementation-defined.
7. Prompt interpolation MUST use `${expression}`. An unescaped `$` followed by
   `{` begins interpolation. `$$` consumes exactly those two dollar signs and
   produces one literal dollar sign, so `$${name}` renders the literal text
   `${name}` without interpolation. A `String` is interpolated as its string
   contents; a struct, `Option<T>`, `List<T>`, or tuple is interpolated as
   compact strict JSON, with `None` rendered as `null`. Invalid references and
   values that cannot be encoded are analysis or runtime errors, respectively.
8. Ordinary quoted strings MUST support `\\`, `\"`, `\n`, `\r`, `\t`, `\0`,
   and Rust-style Unicode scalar escapes of the form `\u{HEX}`. Unknown,
   incomplete, or invalid escapes are syntax errors. A quoted prompt literal
   MAY contain literal newline characters. Literal newlines and all indentation
   MUST be preserved exactly; Gantry performs no implicit indentation
   stripping. Gantry MUST also support Rust-style raw strings `r"..."` and
   hash-delimited forms such as `r#"..."#`. Raw strings disable backslash
   escape processing but do not disable `${...}` interpolation or `$$`
   escaping.
9. Hooks MUST receive the expected output schema as a separate
   machine-readable value. Gantry MUST provide guidance that clearly states
   the operation's input and output contract; the exact guidance may evolve.
10. The only v1 operation-selection knob is the agent name. System/user/
   assistant roles, model choice, tools, sampling settings, streaming,
   progress reporting, timeouts, and cancellation mechanics are integration
   concerns.
11. A hook MUST return one of three host-level outcomes:
   `Completed(raw_output)`, `Declined(reason)`, or `Failed(message)`.
   `Completed` contains the agent's raw output as bytes; Gantry, not the hook,
   owns UTF-8 decoding, strict-JSON parsing, schema validation, and repair
   retries. Non-UTF-8 or malformed-JSON output is therefore a structured-output
   validation failure rather than a transport failure. `Declined` produces
   `None` only when the operation's expected type is `Option<T>`; for every
   other result type, including a control decision, it aborts execution.
   `Failed` aborts execution and is not a structured-output validation failure.
12. Gantry MUST assign a logical session ID to each operation. Session IDs MUST
   remain stable across validation retries and resume. An integration MUST
   honor the following session directives:
   - `inline` reuses the enclosing logical session;
   - `fork` creates a child session initialized from the enclosing session; and
   - `new` creates a session without inherited conversational context.
   At execution start, the embedder MAY supply one root logical session ID and
   its integration-side context. Otherwise Gantry MUST create a fresh root
   logical session with no inherited conversational context. Entry-level
   `inline` operations use this root session. The selected root identity and
   whether it was supplied or generated MUST be journaled and restored on
   resume.
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
15. `prompt` and decision evaluation are the only v1 source constructs that
    directly dispatch an `OperationHook`. Tools, approvals, shell commands,
    network calls, and other harness actions MAY occur while the integration
    fulfills that hook, but they are not separately expressed or interpreted
    by Gantry v1. Gantry observes such work only through the hook outcome and
    integration-supplied events. This boundary keeps the language focused on
    agent control flow without prescribing a harness action vocabulary.
16. Every dynamic operation identity MUST correspond to a logical execution
    path consisting of the execution ID, task path, workflow-call path, source
    operation location, branch arm, and enclosing loop iteration counters.
    Recursive calls and repeated calls from the same call site MUST receive
    distinct call-frame occurrences; distinct loop iterations and spawned
    task occurrences MUST likewise receive distinct identities. Validation
    retries and recovery of one indeterminate dispatch retain that identity.
    Implementations MAY encode or hash the path opaquely, but MUST journal
    enough of it to reconstruct the same identity on resume and MUST NOT reuse
    an identity for another dynamic invocation.
17. Hook outcomes and interpreter failures are separate domains. A hook
    outcome is exactly `Completed(raw_output)`, `Declined(reason)`, or
    `Failed(message)`. Gantry runtime errors MUST at least distinguish entry-
    input validation, syntax, analysis, hook creation, hook failure, decline of
    a required result, structured-output exhaustion, cancellation, journal
    failure, required-event-delivery failure, task/join failure, and internal
    invariant failure. Concrete Rust error types are implementation-defined,
    but embedders MUST be able to distinguish these categories without parsing
    display text.

## 8. Structured Output and Validation

1. A successful agent hook outcome provides raw bytes in
   `Completed(raw_output)`. Gantry MUST decode those bytes as UTF-8 and parse
   exactly one RFC 8259 JSON text, allowing only JSON whitespace after the
   value. Gantry owns this parsing step and MUST reject non-UTF-8, malformed,
   empty, or trailing-data output as structured-output validation failures.
   For a no-result prompt, the expected schema is exactly
   `{ "type": "null" }`, and the parsed value MUST be JSON `null`. This wire
   value confirms successful completion but does not create a Gantry value;
   `Declined` and `Failed` retain their ordinary fatal behavior for no-result
   operations.
2. A `String` result is represented by a JSON string. A struct result is a
   JSON object whose property names directly match its declared field names.
3. A `List<T>` result is represented by a JSON array. Every array item MUST
   validate as `T`, and item order MUST be preserved. Gantry MUST derive an
   array schema with the schema for `T` as its `items` schema.
4. A `Tuple<T1, T2, ..., Tn>` result is represented by a JSON array with
   exactly `n` items. Each item MUST validate against its corresponding
   positional member type, and item order MUST be preserved. Gantry MUST
   derive a fixed-length JSON Schema array using `prefixItems`, with
   `items: false`.
5. `Some(value)` is represented by the JSON encoding of `value`, and `None` is
   represented by JSON `null`. An `Option<T>` struct property MAY also be
   omitted. Omission assigns the field's declared literal default when one
   exists and otherwise normalizes to `None`; explicit `null` always normalizes
   to `None`.
6. Gantry MUST derive JSON Schema Draft 2020-12 from declared output types
   during semantic analysis and MUST independently validate every successful
   hook result against that schema. Recursive types MUST use `$defs` and
   `$ref`.
7. Struct results MUST reject unknown properties. Declared fields are required
   unless represented by `Option<T>`.
8. v1 validation MUST check JSON shape and types. Constraints such as length,
   patterns, enums, and semantic validity are conveyed through prompt guidance
   rather than enforced by Gantry.
9. UTF-8 decoding failures, malformed JSON, and schema-invalid output MUST be
   returned to the agent as validation guidance and retried up to the
   configured retry limit. A retry request MUST include the preceding
   validation errors but MUST NOT return the preceding raw output to the hook.
10. The retry limit is configured per interpreter and MAY be overridden per
   operation. It counts retries after the initial attempt; zero permits exactly
   one attempt. Retry backoff MUST be configurable with sensible defaults.
11. When retries are exhausted, the operation and program MUST fail. Gantry has
   no language-level error recovery in v1.
12. Transport failures and their retry policy are integration concerns, not
   Gantry structured-output retries.
13. Source snippets MAY be included in validation diagnostics. Raw agent
    output MUST NOT be included in validation diagnostics.

## 9. Control Flow

1. Gantry MUST support `if`, `else if`, and `else`. Each `if` or `else if`
   condition MUST ultimately perform exactly one agent decision operation. A
   direct decision operation uses the visually distinct `decide` expression;
   an ordinary unannotated `prompt` always remains a no-result prompt. A
   condition MAY be a direct `decide` expression or a call to a decision
   workflow; calling the workflow does not add a second hook invocation.
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
   loop. The post-test syntax places the body before its condition:
   `until(...) { ... } when decide "...";`. This ordering is normative and
   makes execution order visible in source. `until` MUST execute its body once
   before its first decision. Each condition evaluation invokes its agent
   decision operation again.
5. The general loop form is `loop(session = inline, limit = 0) { ... }`.
   `loop { ... }` is equivalent to the form with all defaults. `while`
   places parenthesized modifiers before its decision expression, as
   in `while(session = fork, limit = 10) decide(retry_limit = 2) "..." { ... }`.
   `until` places the same loop modifiers before its body and operation
   modifiers on the `decide` expression after `when`.
   They MUST accept `session`, `limit`, and `retry_limit` modifiers. Agent
   selection is inherited from a lexical `with` context rather than specified
   as a loop modifier. `retry_limit` counts retries after the initial attempt.
6. A loop session is `new`, `fork`, or `inline`, with `inline` as the default.
   A loop limit is a nonnegative integer no greater than `2^63 - 1`; every v1
   implementation MUST support that full range. It counts body executions.
   Zero always means unlimited and MUST NOT be reinterpreted by interpreter
   configuration.
   Reaching a positive limit completes the loop normally rather than failing.
   `inline` uses the enclosing session for both the condition and body. `fork`
   creates one child session for each prospective iteration; a `while`
   condition and the body it admits share that child, while an `until` body and
   its following condition share it. A final false `while` condition therefore
   has a child session with no body execution. `new` creates one fresh session
   on loop entry and uses it for every condition and body execution. A session
   modifier on the decision's final `decide` overrides the loop session only
   for that decision operation. Validation retries always retain the logical
   session of the operation being retried.
7. Gantry MUST support `break`, `continue`, and `return` in loops. Unlabeled
   `break` and `continue` target the nearest enclosing loop. Labeled loop
   control is excluded from v1. A body execution is counted when control enters
   the body. After a body completes normally or through `continue`, Gantry
   checks the positive `limit` before performing another condition operation.
   Reaching the limit completes the loop without another decision call. If the
   limit is not reached, `continue` in a `while` advances to its next pre-test,
   `continue` in an `until` advances to that iteration's post-test, and
   `continue` in `loop` advances to its next body execution. `break` completes
   any loop immediately without another decision call.
8. `for`, `match`, and deterministic `if let` are excluded from v1.
9. Control decisions MUST use the same schema-validation and retry policy as
   other structured agent results.
10. Gantry imposes no mandatory loop, cost, or agent-call limit. Integrations
    MAY impose their own limits, except that such policy does not alter the
    language meaning of `limit = 0`.
11. A direct prompted condition uses `if decide "..." { ... }`. Gantry MUST
    also support declarations of the form
    `decision is_complete(report: Report) { ... }`. A completed decision
    workflow MUST end in a `decide` expression, whose result schema is the
    interpreter-only decision schema in item 2. A decision workflow MAY contain
    multiple ordinary prompts, nested decisions, and other executable blocks.
    `return` MAY exit it early, but the returned expression MUST be a direct
    `decide` expression, a call to another decision workflow, or a `with` context
    whose trailing expression is one of those forms. Each completed
    evaluation MUST ultimately obtain its decision from exactly one prompt hook
   result with the decision schema in item 2. A decision call is valid only as
   the condition of `if`, `else if`, `while`, or `until`, or as the returned
   expression of another decision workflow. Its result cannot be bound,
   returned by an ordinary workflow, interpolated, or discarded as a
   standalone statement.

## 10. Parallel Execution

1. Gantry MUST support annotated spawn declarations of the form
   `spawn <name> -> <type> { ... }`, joins of the form
   `join(<task-name>, ...)`, `joinall`, and explicit detachment of the form
   `detach(<task-name>);`.
2. A spawn creates an arbitrary child program block running in parallel. The
   spawn name declares a new, lexically scoped, unique, interpreter-owned task
   handle. A task handle is not a `String`, is not agent-visible structured
   data, and is not otherwise a first-class runtime value.
3. A spawned block captures outer variables by copy and MUST NOT mutate outer
   variables. The captured values form a deep, isolated snapshot taken when
   `spawn` executes; “snapshot” describes isolation, not universal read-only
   access. Each captured binding preserves its declared mutability: an
   immutable capture cannot be assigned, while a `mut` capture may be changed
   inside the child without affecting the parent. A child MAY initialize a new
   mutable local binding from any captured value.
4. A spawned block MUST declare the type of its yielded value with `-> T`, or
   declare `-> None` when it yields no value. Its trailing expression MUST
   exactly match that annotation. `spawn` declares the named handle but does
   not itself yield the handle as a value. A spawn boundary is also a control-
   transfer boundary: `return`, `break`, or `continue` inside a spawned block
   MUST NOT target a workflow or loop outside that block. Such a transfer is an
   analysis error. Transfers wholly contained in a workflow or loop entered
   within the child remain valid.
5. `join(task)` waits for one named child and yields that child's typed block
   value. A join result MAY be bound as `let result: T = join(task);`. Joining
   a no-result block is a waiting statement and yields no value. A successful
   join consumes the task handle. Every task handle MAY be joined at most once;
   repeated handles in one join, joins of already consumed handles, and uses of
   handles that may have been consumed on an incoming control-flow path are
   analysis errors. `join()` with no task names is invalid.
   `join(task_a, task_b, ...)` waits for every named child and yields an ordered
   `List<T>` of their successful block values in argument order when every
   joined task has the same non-`None` result type. When the named tasks have
   different non-`None` result types, it yields
   `Tuple<T1, T2, ..., Tn>`, whose positional types and values follow argument
   order. Joining a no-result task in this form is an analysis error. A multi-
   task join waits until every named task settles even after a failure. Entering
   the join consumes every named handle, including handles for successful tasks
   in a join where another task fails. After settlement, failures abort the
   current program as one aggregate task/join error ordered by join argument,
   never by completion time. A failed single-task join consumes its handle and
   aborts with a task/join error.
6. `joinall` is syntactic sugar for joining every unconsumed, attached task
   declared directly in the current lexical scope. It excludes tasks declared
   in nested scopes and tasks explicitly detached before the join. It consumes all
   included handles, waits until all included tasks have settled, and yields an
   ordered `List<T>` in task declaration order when every joined task has the
   same non-`None` result type. When every joined task has a non-`None` result
   but their types differ, it yields a positional tuple in task declaration
   order. Otherwise it is a waiting statement that discards successful
   outputs. With zero included tasks, `joinall` is a no-result no-op. It MUST
   NOT stop waiting merely because one task fails.
   After all tasks settle, one or more failures MUST abort the current program
   with one aggregate runtime error. That error MUST report failed tasks in
   source declaration order, not completion order.
7. A child failure does not immediately cancel siblings. A named child's
   failure is deferred until `join`; a scoped failure is deferred until
   `joinall`.
8. `detach(task)` consumes one attached task handle and transfers ownership of
   that task to the interpreter instance without waiting for it. Detaching an
   already consumed handle is an analysis error. An attached, unconsumed task
   at lexical scope exit is an analysis error; v1 never detaches work
   implicitly. Detached tasks and nested spawns are permitted, and a top-level
   execution MAY report foreground success while detached tasks continue.
   Requiring an explicit `detach` keeps background execution visible to humans,
   agents, analysis, and recovery tooling.
9. A detached-task failure MUST be journaled and emitted as a failure event. It
   MUST NOT retroactively change an already returned top-level success into a
   failure. If execution is still awaiting that task through `join` or
   `joinall`, the ordinary join failure rules apply.
10. Parent timeout and cancellation constraints apply while a child remains
   attached and propagate through its attached descendants. Detachment releases
   the task from those parent constraints. Integration-specific operation
   timeouts and cancellation policy MAY still apply.
    If a parent task aborts for any runtime error, Gantry MUST signal
    cancellation to all of its attached descendants, wait for them during the
    configured post-cancellation drain period, and abort executor tasks that do
    not settle in that period before reporting the parent failure. Detached
    tasks are not cancelled by that parent failure. Secondary attached-task
    failures MUST be recorded in the parent failure details in source task
    order but MUST NOT replace the initiating runtime-error category.
11. Gantry MUST schedule spawned blocks through the executor supplied by the
    embedding application. The integration determines operation-level resource
    limits and queueing policy.
12. The embedding API MUST provide a terminal asynchronous shutdown operation.
    The embedder MUST configure a finite graceful-shutdown timeout; indefinite
    shutdown is not the v1 default. Shutdown MUST reject new executions and
    allow detached tasks to finish naturally until the timeout expires. It
    MUST then signal cancellation, abort tasks that do not finish within a
    bounded drain period, flush journal and required event state, and return a
    shutdown report. An interpreter cannot be reused after shutdown begins.
    Embedders MUST complete shutdown before dropping the interpreter.
13. Because Rust destruction cannot await, dropping an interpreter without
    shutdown MUST reject new work, signal cancellation, abort or detach
    remaining executor handles without blocking, and emit a best-effort
    diagnostic event when a sink is still usable. The drop path MUST NOT retry
    event delivery or claim that detached work completed.

## 11. Journal and Resume Semantics

1. Gantry MUST durably journal committed operation results, validation attempt
   counts, interpreter call frames, scopes, instruction positions, loop state,
   task relationships, and values needed to resume execution.
2. Gantry MUST expose a journal-storage trait through which an integration
   provides durable storage. The trait MUST expose atomic append and flush
   operations only; Gantry defines the transaction and commit boundaries built
   from those operations. Each append MUST return a stable record ID and a
   sequence number that increases monotonically within that journal.
   `flush(sequence)` MUST establish that every successfully appended record
   through that sequence is durable before it returns.
3. A hook dispatch MUST be recorded and flushed before the hook is invoked.
   After a hook returns, Gantry MUST append the outcome and flush through that
   outcome record's sequence number before the interpreter validates, assigns,
   branches on, returns, or otherwise consumes it. A successfully flushed
   outcome is committed. This ordering ensures recovery either reuses the
   committed outcome or treats the dispatch as indeterminate; program state
   MUST NOT advance using an outcome that is not yet durable.
4. If execution is interrupted after dispatch but before an outcome is
   committed, the operation is indeterminate. On resume, Gantry MUST
   automatically invoke that operation again with the same operation ID and a
   new dispatch ID and an incremented recovery-dispatch number. The validation-
   attempt number and remaining structured-output retry budget MUST NOT change
   merely because of recovery redispatch. Integrations MUST therefore assume
   at-least-once invocation and possible duplicate external side effects.
5. Committed results MUST be reused during resume and MUST NOT consume the
   remaining validation-retry budget again. Invalid attempts and retry counts
   MUST also be journaled. Gantry MUST append and flush a validation-attempt
   record before dispatching its repair retry, so recovery preserves both the
   preceding errors and the exact remaining budget.
6. Journals MUST identify the exact package source and journal format version.
   The package source identity is the SHA-256 digest of a canonical manifest
   containing every resolved source module exactly once. Manifest entries are
   sorted by package-relative UTF-8 path, use `/` as their path separator, and
   contain the path, the exact source-file bytes, and the resolved module path.
   Paths use the NFC spelling already required by Section 4; source bytes and
   line endings MUST NOT otherwise be normalized. The manifest byte stream is
   the ASCII domain tag `gantry-source-v1\0`, followed by the entry count and,
   for each entry, the path, source bytes, and resolved module path. Every
   count and byte-string length is encoded as an unsigned 64-bit big-endian
   integer, and every path is encoded as UTF-8. This length-prefix encoding is
   unambiguous even when source contains arbitrary delimiters. Gantry MUST
   reject resume when this identity differs or the journal format is
   unsupported.
7. Recovery MUST restore scopes, instruction positions, call frames, loop
   counters, task relationships, and committed values. An in-flight spawned
   block MUST restart at the top of that block while reusing every committed
   operation result recorded for it. Uncommitted operations are retried under
   item 4.
8. A detached task remains part of its originating execution and journal after
   foreground `main` returns. Foreground completion, detachment, detached-task
   completion, and detached-task failure MUST each be durable states. Resuming
   an execution with unfinished detached tasks MUST recover them under the
   same rules as other in-flight spawned blocks. An execution reaches its
   terminal durable state only after its foreground and every detached task
   have completed, failed, or been cancelled during shutdown.
9. A v1 journal envelope MUST identify its protocol version, journal and
   execution IDs, monotonically increasing sequence number, record ID, record
   kind, causal parent record when one exists, task and operation identities
   when applicable, and a kind-specific payload. The required record kinds are
   execution state, operation dispatch, operation outcome, validation attempt,
   interpreter checkpoint, task state, event, event-delivery state, and
   terminal failure. Concrete serialization and Rust types are implementation-
   defined, but all required information and durability boundaries are
   normative.
10. An execution-start record MUST contain an effective-configuration identity
    and the configuration fields needed to verify it. The identity is the
    SHA-256 digest of the RFC 8785 JSON Canonicalization Scheme encoding of a
    versioned object containing the default structured-output retry limit and
    backoff policy, maximum directive integer, root-session identity and
    provenance, required event-sink stable identities and delivery policies,
    and protocol major versions. Required sinks MUST be ordered by stable sink
    identity before canonicalization.
    Resume MUST reject changes to those fields. Executor implementation,
    worker count, operation timeouts, shutdown timing, best-effort sinks, and
    logical-agent-to-provider mappings MAY change on resume; such changes MUST
    be journaled before further work. Allowing agent mappings to change is
    intentional because Gantry promises resumability, not deterministic model
    replay. Source operation modifiers remain bound through the package source
    identity rather than being duplicated into this configuration identity.
11. These resume guarantees do not create a deterministic-replay guarantee for
    a new execution.

## 12. Observability and Validation Modes

1. Gantry MUST expose events for parsing, call start and end, prompts, schema,
   validation failure, retry, branch decision, spawn, join, mutation, and
   failure. Event and journal envelopes MUST be explicitly versioned from the
   first public release, and consumers MUST reject unsupported major versions.
2. Each event MUST have a stable event ID and execution ID. It MUST include a
   source location when caused by a source-backed construct, a task ID when it
   occurs in a task, an operation ID when it concerns an operation, and causal
   parent/child IDs when such relationships exist. Parse, package-analysis,
   shutdown, and storage failures MAY lack task or operation identity. Event
   order is guaranteed within one task but not across concurrent tasks; IDs
   MUST permit reconstruction of cross-task causality. Delivery retries reuse
   the event ID and use a distinct delivery-attempt ID.
3. Events from a resumable execution MUST be durably journaled before their
   first delivery. Parse and analysis events produced without a resumable
   execution MAY be delivered without a journal. Event delivery MAY use
   bounded asynchronous queues, but queue backpressure MUST prevent silent
   event loss and preserve per-task order.
4. Canonical protected event records for completed agent operations MUST make
   raw agent output available. A sink receives raw output only when it
   explicitly declares that capability and the embedder enables it for that
   sink. Other sinks receive the same event identity with the raw field
   redacted. Prompts and schemas MUST be observable through journal or event
   IDs referenced from events rather than duplicated in every event. Raw output
   MUST remain omitted from default human-readable diagnostics and validation
   error text.
5. Event sinks MUST be configured independently as `required` or
   `best-effort`, with interpreter defaults overridable per sink. Gantry MUST
   retry only errors the sink classifies as retriable. A non-retriable error
   exhausts delivery immediately. The default policy is three retries after
   the initial attempt with exponential backoff beginning at 100 milliseconds,
   capped at two seconds, and randomized jitter.
6. Event delivery is at least once. Sinks MUST deduplicate using the stable
   event ID. Exhaustion for a required sink MUST abort the affected execution;
   exhaustion for a best-effort sink MUST be journaled and execution MUST
   continue. Successful completion and orderly shutdown MUST flush all required
   sink deliveries for the applicable execution before returning.
   An event describing sink-delivery failure MUST NOT be delivered to the same
   failing sink. Required-sink exhaustion MUST append and flush one terminal
   failure record directly to the journal without requiring event delivery;
   failure of that journal write is returned to the embedder as a journal
   failure. These rules prevent recursive failure-event generation.
7. Every event envelope MUST identify its protocol version, event and
   execution IDs, event kind, source location when source-backed, task and
   operation identities when applicable, causal parent IDs, per-task sequence,
   timestamp, payload reference, and redaction state. The canonical v1 event
   kinds are parse, analysis, workflow start, workflow end, operation dispatch,
   operation completion, schema validation failure, retry, branch decision,
   spawn, join, detach, mutation, cancellation, execution completion, and
   failure. Concrete serialization is implementation-defined.
8. A dry-run performs syntax validation only and MUST NOT invoke agent hooks.
   Gantry MUST separately provide an analysis mode that performs name, type,
   module, and schema validation without invoking hooks.
9. Normal execution MUST complete semantic analysis successfully before its
   first hook invocation.

## 13. Formal Lexical and Syntactic Grammar

This section defines the normative v1 source grammar. Semantic restrictions in
the preceding sections still apply when the grammar admits a construct in a
broader syntactic position. In particular, name resolution, exact type
matching, decision-only contexts, task-handle consumption, modifier validity,
and interpolation restrictions are semantic-analysis concerns.

### 13.1 Grammar notation

The grammar uses extended Backus-Naur form (EBNF):

- quoted text is a literal terminal;
- `A | B` selects one alternative;
- `[ A ]` makes `A` optional;
- `{ A }` repeats `A` zero or more times;
- `( A )` groups terms; and
- productions ending in `_token` are emitted by the lexer.

Whitespace and comments separate tokens and are otherwise insignificant,
except inside string and raw-string tokens. A trailing comma is accepted in
every comma-separated declaration, parameter, argument, field, and modifier
list.

### 13.2 Lexical grammar

```ebnf
source              = { item }, end_of_file ;

whitespace          = " " | "\t" | "\r" | "\n" ;
line_comment        = "//", { any_character_except_newline },
                      ( "\n" | end_of_file ) ;
block_comment       = "/*", { block_comment | block_comment_character }, "*/" ;

identifier_token    = xid_start_or_underscore,
                      { xid_continue_or_underscore } ;
integer_token       = "0" | nonzero_decimal_digit, { decimal_digit } ;

string_token        = '"', { string_character | escape_sequence }, '"' ;
escape_sequence     = "\\\\" | "\\\"" | "\\n" | "\\r" | "\\t" | "\\0"
                    | "\\u{", hex_digit, { hex_digit }, "}" ;

block_prompt_token  = '"""', block_prompt_body, '"""' ;

raw_string_token    = "r", raw_hashes, '"', raw_string_body,
                      '"', matching_raw_hashes ;
raw_hashes          = { "#" } ;
```

`xid_start_or_underscore` and `xid_continue_or_underscore` are the Unicode
XID_Start and XID_Continue classes, respectively, with `_` additionally
permitted. Source MUST be valid UTF-8. An identifier MUST NOT equal a reserved
word. Decimal directive integers have no sign, separator, or radix prefix.

Block comments nest. An unterminated block comment, quoted string, raw string,
escape, or Unicode escape is a syntax error. A Unicode escape MUST identify a
Unicode scalar value and contain one through six hexadecimal digits. A normal
string may contain a literal newline. The lexer preserves its bytes after
escape decoding and performs no indentation normalization.

`string_character` is any Unicode scalar value other than `"` or `\`; newline
characters are included. `block_prompt_body` is the shortest sequence ending
before an unescaped `"""` delimiter and uses the same escape sequences as an
ordinary string. A block prompt MUST begin with a newline immediately after
its opening delimiter. Its closing delimiter MUST appear on a line containing
only indentation and the delimiter. Gantry removes that first newline and the
common indentation prefix shared by every nonblank content line; the closing
delimiter's indentation is the maximum prefix that may be removed. Relative
indentation and trailing newlines remain significant. A nonblank line with
less indentation than the closing delimiter is a syntax error. This explicit
dedent form keeps multiline prompts readable while ordinary and raw strings
continue to preserve exact whitespace. `block_comment_character` consumes one
scalar value that does not begin the nested opener `/*` or closing delimiter
`*/`.
`raw_string_body` is the shortest sequence ending immediately before a quote
followed by exactly `matching_raw_hashes`. Lexing uses maximal munch for
identifiers, directive integers, `::`, and `->`. A raw-string token takes
precedence over an identifier only when `r` is immediately followed by zero or
more `#` characters and a quote. Reserved-word classification occurs after an
identifier token is scanned. Comments are recognized only outside string
tokens, and interpolation islands are recognized only by the contextual prompt
scan described in Section 13.7.

For a raw string, `matching_raw_hashes` means exactly the same number of `#`
characters as `raw_hashes`. Backslashes have no special meaning in a raw
string. The variable-hash delimiter rule is lexical and is intentionally
described outside pure EBNF.

The reserved words are:

```text
agent      agents     as          break       continue    crate
decision   decide     default     detach       else        fn
fork       if         impl        inline       join        joinall
let        limit      List        loop         mod         mut
new        None       Option      prompt      return      retry_limit
self       session    Some        spawn       String      struct
super      Tuple      until       use          when        while
with
```

`as` is reserved for future compatible extension even though v1 has no alias
form for `use`. Reserved type and constructor names are case-sensitive.

### 13.3 Package declarations and types

```ebnf
item                    = agents_declaration
                        | default_agent_declaration
                        | file_module_declaration
                        | inline_module_declaration
                        | use_declaration
                        | struct_declaration
                        | function_declaration
                        | decision_declaration
                        | impl_declaration ;

agents_declaration      = "agents", "{", identifier_list, "}" ;
identifier_list         = identifier_token,
                          { ",", identifier_token }, [ "," ] ;
default_agent_declaration
                        = "default", "agent", "=", identifier_token, ";" ;

file_module_declaration = "mod", identifier_token, ";" ;
inline_module_declaration
                        = "mod", identifier_token, "{", { item }, "}" ;
use_declaration         = "use", qualified_path, ";" ;
qualified_path          = relative_path
                        | "crate", "::", relative_path
                        | "self", "::", relative_path
                        | "super", "::", { "super", "::" }, relative_path ;
relative_path           = identifier_token, { "::", identifier_token } ;

struct_declaration      = "struct", identifier_token, "{",
                          { struct_field }, "}" ;
struct_field            = identifier_token, ":", value_type,
                          [ "=", field_default ], "," ;
field_default           = string_token | raw_string_token | "None" ;

value_type              = "String"
                        | qualified_path
                        | "Option", "<", value_type, ">"
                        | "List", "<", value_type, ">"
                        | "Tuple", "<", value_type, ",", value_type,
                          { ",", value_type }, [ "," ], ">" ;
result_type             = value_type | "None" ;
result_annotation       = "->", result_type ;
```

The built-in type alternatives take precedence over `qualified_path`. A
`Tuple` has at least two member types by grammar. `None` in a result annotation
is the no-result type; `None` in an expression is the absent value of an
expected `Option<T>`. Field defaults are deliberately limited to strings and
`None` in v1. Their declared field type MUST accept the default without
coercion.

A `use` declaration imports the item named by the final path segment into the
current module. The path roots have the meanings defined in Section 4. Glob
imports, grouped imports, aliases, importing a module under the name `self`,
and visibility modifiers are not v1 syntax.

### 13.4 Workflows and methods

```ebnf
function_declaration    = "fn", identifier_token, "(",
                          [ parameter_list ], ")",
                          [ result_annotation ], block ;
parameter_list          = parameter, { ",", parameter }, [ "," ] ;
parameter               = identifier_token, ":", value_type ;

decision_declaration    = "decision", identifier_token, "(",
                          [ parameter_list ], ")", decision_block ;

impl_declaration        = "impl", qualified_path, "{",
                          { method_declaration }, "}" ;
method_declaration      = "fn", identifier_token, "(", receiver,
                          [ ",", parameter_list ], ")",
                          [ result_annotation ], block ;
receiver                = "self" | "mut", "self" ;
```

A function signature without a result annotation returns no result, exactly as
if it had `-> None`. A method always has a receiver as its first parameter.
Associated functions without a receiver are excluded from v1. A `decision`
has no source-level result annotation because its interpreter-only decision
schema is implied by the declaration.

### 13.5 Blocks and statements

```ebnf
block                   = "{", { statement }, [ trailing_expression ], "}" ;
decision_block          = "{", { statement }, decision_tail, "}" ;
decision_tail           = decision_expression
                        | "return", decision_expression, ";" ;

statement               = let_statement
                        | assignment_statement
                        | expression_statement
                        | return_statement
                        | break_statement
                        | continue_statement
                        | spawn_statement
                        | detach_statement
                        | if_statement
                        | loop_statement
                        | while_statement
                        | until_statement ;

let_statement           = "let", [ "mut" ], identifier_token, ":",
                          value_type, "=", expression, ";" ;
assignment_statement    = assignment_target, "=", expression, ";" ;
assignment_target       = ( identifier_token | "self" ),
                          { ".", identifier_token } ;
expression_statement    = expression, ";" ;
return_statement        = "return", [ expression ], ";" ;
break_statement         = "break", ";" ;
continue_statement      = "continue", ";" ;
trailing_expression     = expression ;
```

Bindings require explicit types in v1. A trailing expression is distinguished
from an expression statement by the absence of `;` immediately before the
closing brace. `return;` is valid only in a no-result function or method.
`break` and `continue` are valid only in a loop body. A `decision_block` MUST
end in a direct `decide` expression or decision-workflow call, whether trailing
or returned; an earlier `return` in its statement sequence is subject to the
same restriction.

### 13.6 Expressions

```ebnf
expression              = prompt_expression
                        | join_expression
                        | joinall_expression
                        | with_expression
                        | postfix_expression ;

postfix_expression      = primary_expression, { postfix_suffix } ;
postfix_suffix          = ".", identifier_token
                        | "(", [ argument_list ], ")"
                        | "[", integer_token, "]" ;
primary_expression      = string_token
                        | raw_string_token
                        | "None"
                        | "Some", "(", expression, ")"
                        | "self"
                        | struct_expression
                        | qualified_path
                        | "(", expression, ")" ;

struct_expression       = qualified_path, "{", [ field_initializer_list ], "}" ;
field_initializer_list  = field_initializer, { ",", field_initializer },
                          [ "," ] ;
field_initializer       = identifier_token, ":", expression ;
argument_list           = expression, { ",", expression }, [ "," ] ;

with_expression         = "with", identifier_token, block ;
```

Postfix `(...)` dispatches a workflow function or method, postfix `.name`
accesses a field or selects a method, and postfix `[integer]` projects a list
or tuple member. Gantry has no arithmetic, Boolean, comparison, list literal,
or tuple literal syntax in v1. Parentheses group one expression; they do not
construct tuples.

An unqualified primary path used as a value MUST resolve to a visible parameter
or binding. A qualified item path is valid in an expression only as the callee
of a workflow call or as the type path beginning a struct constructor. Because
v1 has no module, type, function, decision, or method values, semantic analysis
MUST reject a bare path that resolves to any such item. Task handles are legal
only in `join`, `joinall`, and `detach`, never as primary expressions.

A `with` expression yields its block's trailing value, if any, which permits a
lexically selected agent to produce the enclosing workflow's result. If its
block has no trailing value, the `with` expression has no result.

Semantic analysis MUST validate every postfix step from left to right. A call
suffix is legal only on a function item or selected inherent method; a field
suffix is legal only on a struct value unless it immediately selects an
inherent method; and an index suffix is legal only on a list or tuple value.
Calling a value, selecting a field from a non-struct, indexing another type, or
continuing a postfix chain after a no-result expression is an analysis error.

### 13.7 Prompts and interpolation

```ebnf
prompt_expression       = "prompt", [ prompt_modifiers ], prompt_template,
                          [ result_annotation ] ;
prompt_modifiers        = "(", prompt_modifier,
                          { ",", prompt_modifier }, [ "," ], ")" ;
prompt_modifier         = "session", "=", session_directive
                        | "retry_limit", "=", integer_token ;
session_directive       = "inline" | "fork" | "new" ;
prompt_template         = string_token | raw_string_token
                        | block_prompt_token ;

interpolation           = "${", interpolation_expression, "}" ;
interpolation_expression
                        = interpolation_primary,
                          { ".", identifier_token } ;
interpolation_primary   = string_token
                        | raw_string_token
                        | "None"
                        | "Some", "(", interpolation_expression, ")"
                        | interpolation_struct
                        | identifier_token
                        | "self" ;
interpolation_struct    = qualified_path, "{",
                          [ interpolation_field_list ], "}" ;
interpolation_field_list
                        = interpolation_field,
                          { ",", interpolation_field }, [ "," ] ;
interpolation_field     = identifier_token, ":",
                          interpolation_expression ;
```

The parser treats the prompt template immediately following `prompt` or
`decide` as a template and scans its decoded and, for block prompts, dedented
contents for interpolation islands. `${` opens an interpolation unless its
`$` was consumed by `$$`. `$$` emits one literal
`$`; therefore `$${name}` emits literal `${name}`. This contextual scan applies
to normal, raw, and block prompt strings. In non-prompt string expressions,
`$` and `${...}` are ordinary string contents and are not interpolated.

The scan proceeds left to right after ordinary-string escape decoding. Thus
`$$${name}` emits one literal `$` followed by the interpolation of `name`, and
an ordinary-string Unicode escape that decodes to `$` immediately before `{`
begins interpolation. Authors SHOULD use `$$` rather than Unicode spelling when
they intend a literal dollar sign. Raw strings skip escape decoding but use the
same left-to-right interpolation and `$$` rules. A closing `}` ends an island
only when all nested constructor braces and parentheses inside it are balanced;
an unclosed or syntactically invalid island is a syntax error.

Interpolation permits only the restricted grammar above. In particular, it
does not admit function or method calls, prompts, decisions, joins, mutation,
or control flow. Nested braces belonging to a struct initializer are balanced
before the interpolation's closing `}` is recognized. Duplicate prompt
modifiers are analysis errors. `retry_limit` counts retries after the initial
attempt.

### 13.8 Decisions and sequential control flow

```ebnf
if_statement            = "if", decision_expression, block,
                          { "else", "if", decision_expression, block },
                          [ "else", block ] ;

decision_expression     = decide_expression
                        | decision_call
                        | decision_with_expression
                        | "(", decision_expression, ")" ;
decide_expression       = "decide", [ prompt_modifiers ], prompt_template ;
decision_call           = qualified_path, "(", [ argument_list ], ")" ;
decision_with_expression
                        = "with", identifier_token, "{",
                          { statement }, decision_tail, "}" ;

loop_statement          = "loop", [ loop_modifiers ], block ;
loop_modifiers          = "(", loop_modifier,
                          { ",", loop_modifier }, [ "," ], ")" ;
loop_modifier           = "session", "=", session_directive
                        | "limit", "=", integer_token ;

while_statement         = "while", [ condition_modifiers ],
                          decision_expression, block ;
until_statement         = "until", [ condition_modifiers ], block,
                          "when", decision_expression, ";" ;
condition_modifiers     = "(", condition_modifier,
                          { ",", condition_modifier }, [ "," ], ")" ;
condition_modifier      = "session", "=", session_directive
                        | "limit", "=", integer_token
                        | "retry_limit", "=", integer_token ;
```

The optional modifier forms require at least one modifier when parentheses are
present; empty `prompt()`, `decide()`, `loop()`, `while()`, and `until()`
modifiers are not v1 syntax. Bare `loop` uses `session = inline` and
`limit = 0`. Duplicate modifiers are analysis errors.

A condition-level `session` or `retry_limit` establishes the inherited value
for the decision evaluation. A modifier written directly on a `decide`
expression is more local and overrides the inherited value. `limit` belongs
only to the enclosing `while` or `until`. The `until` grammar deliberately
places its body before `when` and the post-test decision. A `decision_call`
MUST resolve to a `decision` declaration; an ordinary workflow call is not a
condition.

### 13.9 Parallel control flow

```ebnf
spawn_statement         = "spawn", identifier_token, result_annotation, block ;
detach_statement        = "detach", "(", identifier_token, ")", ";" ;
join_expression         = "join", "(", identifier_token,
                          { ",", identifier_token }, [ "," ], ")" ;
joinall_expression      = "joinall" ;
```

Every spawn has an explicit result annotation, including `-> None`. `join`
requires at least one handle. `joinall` takes no parentheses or arguments.
`detach` consumes exactly one attached task handle and is a statement rather
than a value-producing expression.
Static result typing follows Section 10: one value for one task, `List<T>` for
multiple homogeneous results, and `Tuple<T1, ..., Tn>` for multiple
heterogeneous results.

## 14. Syntax Examples

The examples in this section are illustrative complete programs or focused
fragments. They use only v1 syntax. Comments beginning with `//` explain the
example and are valid Gantry comments.

### 14.1 Minimal package entry point

```gantry
agents { worker }
default agent = worker;

fn main() {
    prompt "Inspect the current assignment and carry it out.";
}
```

The omitted prompt annotation and omitted function result both mean no result.
The explicit equivalent is:

```gantry
fn main() -> None {
    prompt "Inspect the current assignment and carry it out." -> None;
}
```

### 14.2 Modules, imports, and package-wide agents

`main.gnt`:

```gantry
agents { researcher, writer }
default agent = researcher;

mod domain;
mod workflows;

use domain::Report;
use workflows::produce_report;

fn main() -> Report {
    produce_report("Agent control languages")
}
```

`domain.gnt`:

```gantry
agents { reviewer }

struct Citation {
    title: String,
    url: String,
}

struct Report {
    title: String,
    summary: String,
    caveat: Option<String> = None,
    citations: List<Citation>,
}
```

`workflows.gnt`:

```gantry
use domain::Report;

fn produce_report(topic: String) -> Report {
    with researcher {
        prompt(session = new, retry_limit = 2)
            "Research ${topic} and return a sourced report."
            -> Report
    }
}
```

All three agent declarations merge into one package set. Only `main.gnt`
declares the default agent.

### 14.3 Struct construction, options, bindings, and mutation

```gantry
struct Metadata {
    source: String,
    note: Option<String> = None,
}

struct Draft {
    title: String,
    body: String,
    metadata: Metadata,
}

fn revise(seed: Draft) -> Draft {
    let mut draft: Draft = seed;
    draft.body = prompt "Rewrite this body clearly: ${draft.body}" -> String;
    draft.metadata.note = Some(
        prompt "Give one short editorial note for ${draft}." -> String
    );
    draft
}

fn make_seed() -> Draft {
    Draft {
        title: "Initial draft",
        body: "Unedited material",
        metadata: Metadata {
            source: "operator",
            note: None,
        },
    }
}
```

Assignments become visible only after the producing operation validates. The
second assignment does not roll back the first if its prompt later fails.

### 14.4 Inherent methods and lexical agent selection

```gantry
struct Report {
    title: String,
    summary: String,
}

impl Report {
    fn revise(mut self, instruction: String) -> Report {
        self.summary = with writer {
            prompt(retry_limit = 3)
                "Apply ${instruction} to this report: ${self}"
                -> String
        };
        self
    }

    fn review(self) {
        with reviewer {
            prompt "Review ${self} and record any concerns.";
        };
    }
}
```

`with` is an expression and may yield its block's trailing value. A nested
`with` would override `writer` or `reviewer` only inside the nested block.

### 14.5 Prompt strings, interpolation, and escaping

```gantry
fn summarize(topic: String, report: Report) -> String {
    prompt(session = fork, retry_limit = 2)
        "Topic: ${topic}\nReport: ${report}\nLiteral marker: $${topic}"
        -> String
}
```

The hook receives `topic` as plain string content and `report` as compact JSON.
The final marker is the literal text `${topic}`. An ordinary quoted multiline
prompt preserves all indentation shown in the source:

```gantry
fn explain(report: Report) -> String {
    prompt "Explain this report:
        ${report}
    Keep the answer concise." -> String
}
```

Triple-quoted block prompts provide explicit dedentation for clean source
layout. The following sends `Explain this report:`, the compact JSON report,
and `Keep the answer concise.` without the source indentation before those
lines:

```gantry
fn explain_cleanly(report: Report) -> String {
    prompt """
        Explain this report:
        ${report}
        Keep the answer concise.
        """ -> String
}
```

Raw strings avoid quote and backslash escapes but still interpolate:

```gantry
fn emit_json_example(report: Report) -> String {
    prompt r#"Describe ${report} using a JSON object such as {"status":"ok"}.
Write the literal placeholder $${report} once."# -> String
}
```

Operations remain visible outside interpolation. Compute a value first rather
than attempting a call inside `${...}`:

```gantry
fn two_stage(report: Report) -> String {
    let critique: String = prompt "Critique ${report}." -> String;
    prompt "Rewrite ${report} using this critique: ${critique}" -> String
}
```

### 14.6 Decision workflows and conditional chains

```gantry
decision is_complete(report: Report) {
    let checklist: String = prompt
        "Create a completeness checklist for ${report}."
        -> String;

    decide "Using ${checklist}, is ${report} complete?"
}

fn route(report: Report) -> String {
    if is_complete(report) {
        return prompt "Return a publication message for ${report}." -> String;
    } else if decide(retry_limit = 1) "Should ${report} receive human review?" {
        return prompt "Return a review-queue message for ${report}." -> String;
    } else {
        return prompt "Return a revision message for ${report}." -> String;
    }
}
```

The `decide` expression visibly requests the interpreter-only decision schema
and never accepts a `->` annotation. The `else if` hook receives the preceding
decision and rationale in its ordered context vector. Conditional blocks do
not themselves form value expressions in v1, so each selected branch returns
its value explicitly.

An early decision return is also valid:

```gantry
decision should_stop(report: Option<Report>) {
    if decide "Is ${report} absent?" {
        return decide "Given that the report is absent, should work stop?";
    }

    decide "Given ${report}, should work stop now?"
}
```

Option inspection remains agent-mediated; no source-level Boolean is created.

### 14.7 General, pre-test, and post-test loops

```gantry
fn refine(mut report: Report) -> Report {
    loop(session = inline, limit = 5) {
        report = prompt "Improve ${report}." -> Report;

        if decide "Is ${report} ready to leave the refinement loop?" {
            break;
        }
    }

    report
}
```

```gantry
fn monitor(mut state: String) -> String {
    while(session = fork, limit = 10)
        decide(retry_limit = 2) "Should monitoring continue for ${state}?" {
        state = prompt "Perform the next monitoring step for ${state}." -> String;

        if decide "Should this iteration skip remaining work?" {
            continue;
        }

        prompt "Record monitoring observations for ${state}.";
    }

    state
}
```

```gantry
fn converge(mut draft: String) -> String {
    until(session = new, limit = 4) {
        draft = prompt "Revise ${draft}." -> String;
    } when decide(retry_limit = 1) "Is ${draft} acceptable now?";

    draft
}
```

`until` places the body before its `when` decision because it runs that body
before its first decision. A `continue` in this body proceeds to the post-test.
Reaching either positive limit completes normally without another decision;
`limit = 0` would mean unlimited execution.

### 14.8 Parallel homogeneous work and `List<T>` joins

```gantry
fn parallel_research(topic: String) -> List<Report> {
    spawn primary -> Report {
        with researcher {
            prompt(session = fork) "Research primary sources for ${topic}." -> Report
        }
    }

    spawn independent -> Report {
        with reviewer {
            prompt(session = fork) "Independently research ${topic}." -> Report
        }
    }

    let reports: List<Report> = join(primary, independent);
    reports
}
```

The returned list follows join argument order, not task completion order.

### 14.9 Parallel heterogeneous work and `Tuple<...>` joins

```gantry
fn research_pair(topic: String) -> Tuple<String, Report> {
    spawn headline -> String {
        prompt "Write a headline for ${topic}." -> String
    }

    spawn report -> Report {
        prompt "Produce a report about ${topic}." -> Report
    }

    let pair: Tuple<String, Report> = join(headline, report);
    pair
}
```

Tuple positions follow the explicit join argument order. v1 code can pass or
return `pair`, project `pair[0]` or `pair[1]`, but cannot destructure it. For
example, `let headline_text: String = pair[0];` is a deterministic projection
and does not invoke an agent hook.

### 14.10 `joinall`, no-result tasks, and detachment

```gantry
fn collect_all(topic: String) -> List<Report> {
    spawn first -> Report {
        prompt "Investigate the first perspective on ${topic}." -> Report
    }

    spawn second -> Report {
        prompt "Investigate the second perspective on ${topic}." -> Report
    }

    let reports: List<Report> = joinall;
    reports
}
```

```gantry
fn audit_in_parallel(report: Report) {
    spawn security_audit -> None {
        prompt "Perform a security audit of ${report}.";
    }

    spawn style_audit -> None {
        prompt "Perform a style audit of ${report}.";
    }

    joinall;
}
```

Background work is explicit. `detach(background)` consumes the scoped handle
and transfers the task to the interpreter instance:

```gantry
fn launch_background(report: Report) {
    if decide "Should a background audit be launched for ${report}?" {
        spawn background -> None {
            prompt "Audit ${report} in the background.";
        }

        detach(background);
    }
}
```

### 14.11 Nested modules and qualified paths

```gantry
mod quality {
    struct Finding {
        summary: String,
    }

    fn inspect(text: String) -> Finding {
        prompt "Inspect ${text}." -> Finding
    }
}

fn run_check(text: String) -> quality::Finding {
    quality::inspect(text)
}
```

The equivalent imported form is:

```gantry
use quality::Finding;
use quality::inspect;

fn run_imported_check(text: String) -> Finding {
    inspect(text)
}
```

## 15. Required Embedding Interfaces

Concrete Rust names and signatures MAY evolve during implementation, but a v1
embedding API MUST expose the following semantic interfaces without requiring
provider-specific or executor-specific types in Gantry programs:

1. An `Interpreter` accepts a package root, interpreter configuration, a hook
   factory, executor adapter, journal storage, and zero or more event sinks. It
   MUST expose syntax-only validation, semantic analysis, execution, resume,
   and terminal asynchronous shutdown operations. Execution accepts either no
   entry value or one strict-JSON entry value as required by `main`, and returns
   a typed execution outcome that distinguishes a value, no result, and every
   runtime-error category defined in Section 7.
2. A `HookFactory` asynchronously creates one `OperationHook` for a supplied
   task context. `OperationHook` asynchronously accepts the versioned request
   defined in Section 7 and a Gantry-owned cancellation token, and returns
   exactly one `Completed(raw_output)`, `Declined(reason)`, or `Failed(message)`
   outcome. `raw_output` is an uninterpreted byte sequence; Gantry owns UTF-8
   decoding, JSON parsing, schema validation, and repair retries. Hook futures
   MUST be `Send`; one hook instance is used serially for one Gantry task.
3. A cancellation token is cloneable, safe to observe from multiple threads,
   and transitions monotonically from active to cancelled. Cancellation does
   not itself constitute a hook outcome; an integration that stops work after
   observing cancellation returns `Failed` or lets Gantry surface cancellation
   according to the runtime state.
4. An executor adapter provides asynchronous task spawn, join, abort, and sleep
   capabilities. Gantry MUST use those capabilities rather than constructing a
   hidden Tokio or other provider runtime. Executor handles and errors MUST be
   wrapped so no specific executor type appears in the language-facing API.
5. Journal storage asynchronously provides atomic `append(record)` and
   `flush(sequence)` operations with the behavior in Section 11. An append
   returns the stable record ID and monotonically increasing sequence number
   assigned to the record. Storage errors are never retried as model-output
   failures and MUST surface as journal runtime errors.
6. Each event sink declares its required/best-effort class, raw-output
   capability, enabled redaction policy, and retry policy. Its asynchronous
   delivery operation receives a versioned event envelope and returns success,
   a retriable error, or a terminal error. Gantry owns delivery attempt IDs,
   retry timing, journaling, and required-sink failure semantics.
7. Interpreter configuration MUST include the default agent-output retry
   limit and backoff, event-delivery defaults, executor adapter, graceful-
   shutdown timeout, and post-cancellation drain duration. Implementations
   MUST accept directive and projection integers through `2^63 - 1` and MAY
   reject larger tokens during analysis. The v1 defaults are 30 seconds for
   graceful shutdown and 5 seconds for post-cancellation drain. Embedders MAY
   override both with finite nonnegative durations; zero requests immediate
   cancellation or immediate return after cancellation, respectively.
8. All public protocol envelopes MUST carry a major and minor version. A major
   mismatch is incompatible and MUST be rejected. An implementation MAY accept
   a newer minor version only when it ignores unknown optional fields without
   changing the meaning of known fields; unknown required fields or enum
   variants MUST be rejected.

The canonical serialization format and concrete Rust data-type layout are
implementation choices. They MUST preserve every field, category, ordering,
durability boundary, and compatibility rule made normative by this document.
