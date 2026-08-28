# Gantry Specification

- [Gantry Specification](#gantry-specification)
  - [1. Status and Scope](#1-status-and-scope)
    - [1.1 Language at a glance](#11-language-at-a-glance)
    - [1.2 Reading the surface syntax](#12-reading-the-surface-syntax)
    - [1.3 V1 design boundary](#13-v1-design-boundary)
    - [1.4 Authoring conventions](#14-authoring-conventions)
    - [1.5 Core terminology](#15-core-terminology)
  - [2. Normative Language](#2-normative-language)
  - [3. Implementation and Execution Model](#3-implementation-and-execution-model)
  - [4. Source Organization](#4-source-organization)
  - [5. Values, Bindings, Structs, and Tagged Types](#5-values-bindings-structs-and-tagged-types)
  - [6. Functions and Methods](#6-functions-and-methods)
  - [7. Agents, Hooks, and Sessions](#7-agents-hooks-and-sessions)
  - [8. Structured Output and Validation](#8-structured-output-and-validation)
  - [9. Control Flow](#9-control-flow)
  - [10. Parallel Execution](#10-parallel-execution)
  - [11. Journal and Resume Semantics](#11-journal-and-resume-semantics)
  - [12. Observability and Validation Modes](#12-observability-and-validation-modes)
  - [13. Formal Lexical and Syntactic Grammar](#13-formal-lexical-and-syntactic-grammar)
    - [13.1 Grammar notation](#131-grammar-notation)
    - [13.2 Lexical grammar](#132-lexical-grammar)
    - [13.3 Package declarations and types](#133-package-declarations-and-types)
    - [13.4 Workflows and methods](#134-workflows-and-methods)
    - [13.5 Blocks and statements](#135-blocks-and-statements)
    - [13.6 Expressions](#136-expressions)
    - [13.7 Prompts and interpolation](#137-prompts-and-interpolation)
    - [13.8 Decisions and sequential control flow](#138-decisions-and-sequential-control-flow)
    - [13.9 Parallel control flow](#139-parallel-control-flow)
  - [14. Syntax Examples](#14-syntax-examples)
    - [14.1 Minimal package entry point](#141-minimal-package-entry-point)
    - [14.2 Modules, imports, and package-wide agents](#142-modules-imports-and-package-wide-agents)
    - [14.3 Primitive values, structs, tagged values, and structural routing](#143-primitive-values-structs-tagged-values-and-structural-routing)
    - [14.4 Inherent methods and lexical agent selection](#144-inherent-methods-and-lexical-agent-selection)
    - [14.5 Prompt strings, interpolation, and escaping](#145-prompt-strings-interpolation-and-escaping)
    - [14.6 Decision workflows and conditional chains](#146-decision-workflows-and-conditional-chains)
    - [14.7 General, pre-test, and post-test loops](#147-general-pre-test-and-post-test-loops)
    - [14.8 Parallel homogeneous work and `List<T>` joins](#148-parallel-homogeneous-work-and-listt-joins)
    - [14.9 Parallel heterogeneous work and `Tuple<...>` joins](#149-parallel-heterogeneous-work-and-tuple-joins)
    - [14.10 `joinall()`, no-result tasks, and detachment](#1410-joinall-no-result-tasks-and-detachment)
    - [14.11 Nested modules and qualified paths](#1411-nested-modules-and-qualified-paths)
    - [14.12 Explicit harness actions and named prompt inputs](#1412-explicit-harness-actions-and-named-prompt-inputs)
    - [14.13 Common invalid forms and their corrections](#1413-common-invalid-forms-and-their-corrections)
  - [15. Required Embedding Interfaces](#15-required-embedding-interfaces)

## 1. Status and Scope

Gantry is a Rust-inspired control language for coordinating model-backed
agents. It is named for the elevated structure spanning a factory floor: a
Gantry program directs and observes the work performed below it.

Gantry is harness-neutral. Mezzanine may integrate Gantry, but it is not an
assumed runtime or part of the language contract. An integration supplies the
agents, models, tools, transport, credentials, resource policy, and any
provider-specific behavior.

The v1 language deliberately separates deterministic orchestration from
integration-backed work. Bindings, construction, workflow dispatch,
assignment, projection, pattern routing, modules, joins, and task ownership
are interpreter operations. Every source-level request that crosses the
integration boundary is visibly introduced by `prompt`, `decide`, or `action`;
an ordinary function or method call does not itself dispatch a hook, although
the called workflow may contain explicit external operations. `prompt` and
`decide` request model-backed work. `action` requests a named, typed harness
capability without implying that a model must fulfill it. An integration may
perform provider-internal work while fulfilling an operation, as defined in
Section 7, but that work does not create hidden Gantry operations.
Interpolation and named-input evaluation never dispatch a hook. Typed
strict-JSON values are the boundary between integration-backed work and source
execution: raw hook outcomes cross the embedding boundary first, and Gantry
alone admits a value into source execution after decoding, validation,
normalization, and durable acceptance. This explicitness is a core readability
requirement for both human and model authors.

This document records the settled version 1 (v1) language and operational
requirements. Concrete Rust type signatures may remain implementation-defined
where the semantic contract is fully specified here.

### 1.1 Language at a glance

The following non-normative example shows the intended v1 source style in one
place. Model-backed work is explicit at each `prompt` or `decide`; ordinary
calls, assignment, loops, and joins remain deterministic interpreter control.

```gantry
agents { researcher, reviewer }
default agent = researcher;

struct Report {
    topic: String,
    summary: String,
    sources: List<String>,
}

struct SearchRequest {
    topic: String,
}

struct SearchFailure {
    message: String,
}

action search(request: SearchRequest)
    -> Result<List<String>, SearchFailure>;

decision needs_revision(report: Report) {
    decide "Does this report need another revision? ${report}"
}

fn main(topic: String) -> Report {
    let search_result: Result<List<String>, SearchFailure> =
        action search(SearchRequest { topic: topic });

    let sources: List<String> = match search_result {
        Ok(value) => value,
        Err(error) => prompt "Recover source references." using {
            topic,
            error,
        } -> List<String>,
    };

    spawn primary -> Report {
        prompt """
            Research primary sources for this topic:
            ${topic}
            """ -> Report
    }

    spawn independent -> Report {
        with reviewer {
            prompt
                "Independently research ${topic}."
                -> Report
        }
    }

    let reports: List<Report> = join(primary, independent);
    let mut report: Report = prompt
        "Synthesize the supplied research reports."
        using { topic, sources, reports }
        -> Report;

    loop(limit = 3) {
        if needs_revision(report) {
            report = prompt "Revise this report: ${report}" -> Report;
        } else {
            break;
        }
    }

    report
}
```

Section 14 provides focused examples of each language construct. Sections 3
through 13 define the normative language and runtime behavior behind this
surface syntax, and Section 15 defines the required embedding boundary.

### 1.2 Reading the surface syntax

The following non-normative reading rules summarize the distinctions that are
most important when humans or models author Gantry source:

- `prompt` visibly performs model-backed work and optionally returns the type
  written after `->`. An omitted annotation or `-> None` means that the
  operation returns no source value.
- `decide` visibly performs model-backed judgment and returns a sealed
  `Decision` containing a `Bool` decision, nonempty rationale, and interpreter
  provenance. A decision can be retained and passed; its read-only fields can
  be projected, but source cannot construct or mutate one.
- `action <path>(...)` visibly invokes a source-declared, typed harness action.
  It is distinct from an ordinary workflow call and from model selection.
- `using { ... }` supplies ordered typed inputs to `prompt` or `decide`
  without rendering them into the authored prompt text.
- `${...}` computes deterministic prompt input. It can read and construct
  values, but cannot hide another external operation, mutation, join, or
  control-flow transfer.
- `Bool` expressions, `match`, and `if let` route validated structure
  deterministically. Semantic judgment remains explicit through `decide`.
- `with <agent> { ... }` selects an agent lexically, while
  `session(<directive>) { ... }` selects conversational continuity. Neither
  construct hides the `prompt` and `decide` sites inside it.
- `spawn` makes concurrency explicit. Every spawned handle must be consumed
  visibly by `join`, `joinall()`, or `detach` on every normal path that leaves
  its scope.
- Ordinary calls, assignments, construction, projection, pattern routing, and
  joins are deterministic interpreter work. If source does not contain
  `prompt`, `decide`, or `action` at a dynamic call path, that path dispatches
  no integration operation.

### 1.3 V1 design boundary

The following non-normative summary makes deliberate v1 omissions visible.
It is a reading aid rather than a substitute for the normative requirements
in later sections:

- Gantry is an orchestration language, not a general-purpose language. Its
  source values include `Bool`, bounded exact `Int`, finite binary64 `Float`,
  strings, structs, enums, options, results, lists, tuples, and sealed
  decisions. Numeric operations are deliberately small and deterministic.
- Integration-backed work is limited to the explicit `prompt`, `decide`, and
  `action` operations. `prompt` and `decide` are model-facing. `action` invokes
  a typed capability declared by the package and resolved by the integrating
  harness.
- V1 has checked arithmetic, numeric ordering, short-circuit Boolean algebra,
  exact equality, and a small deterministic String library, but no `for`,
  user-defined generics, traits, general exception handling, regular
  expressions, or locale-sensitive text processing. Semantic judgments remain
  agent-mediated.
- Lists and tuples are typed aggregates. Source can construct, pass, return,
  interpolate, project, and pattern-destructure them. Lists additionally
  expose deterministic `len()` and dynamic `Int` indexing, enabling explicit
  bounded traversal with `while`; aggregate mutation remains excluded.
- `Result<T, E>` represents a declared, expected source-level outcome. Hook
  failure, invalid structured output, cancellation, journal failure, and retry
  exhaustion remain runtime failures and are never implicitly converted to
  `Err`.
- `Map<T>` and an opaque artifact-reference type are deferred. They require
  lookup, lifetime, authorization, and resume contracts that v1 does not need
  to express typed model and action control flow.
- A struct field default is a source-construction convenience. Agent output
  must still contain every non-optional field, even when that field has a
  source default; only `Option<T>` properties may be omitted from hook output.
- `None` has two intentionally contextual uses: as an expression it is an
  absent `Option<T>` value whose type must be known from context; after `->`
  it denotes that a workflow or operation returns no source value.
- Concurrency is structured and ownership-visible. A spawned task must be
  joined, joined through `joinall()`, or explicitly detached on every normal
  path before its handle leaves scope.

### 1.4 Authoring conventions

The following non-normative conventions define the clearest portable Gantry
style for both human and model authors. They do not change which programs are
valid:

- Keep each `prompt` or `decide` visually prominent. Bind an intermediate
  model result before passing it to another workflow when nesting would make
  operation order difficult to scan.
- Keep each `action` invocation equally prominent. An ordinary call is always
  an interpreter-managed workflow call; the `action` keyword is the visible
  indication that execution crosses into a harness capability.
- Treat each visible model operation as logically singular but physically
  repeatable. Validation repair and interruption recovery can dispatch the
  same operation more than once, so harness actions with external side effects
  should use the stable operation and dispatch identities for deduplication or
  audit whenever the integration can do so.
- Prefer one model operation per statement or trailing expression. Keep the
  `prompt` or `decide` keyword, its modifiers, template, and result annotation
  as one visibly continuous construct; do not rely on unusual line breaks to
  make an operation resemble ordinary deterministic code.
- Treat interpolation as textual prompt composition, not as an instruction/
  data trust boundary. Delimit or explain untrusted string content in the
  authored prompt when that distinction matters. Gantry also supplies each
  interpolation as a separate typed hook argument, but canonical JSON and the
  typed argument vector do not by themselves prevent prompt injection.
- Prefer `using { ... }` for typed context that the model needs but that need
  not be embedded in prose. Use `${...}` when the placement of a value in the
  rendered prompt is itself meaningful.
- Prefer `match` for exhaustive routing over enums and results, and `if let`
  for one focused structural case. Use `decide` instead when the branch depends
  on interpretation, quality, intent, policy, or another semantic judgment.
- Use `Bool` for known mechanical facts and `Decision` for model judgment.
  Project `.decision` only when composing a judgment with deterministic policy;
  retain `.rationale` when later operations need the model's explanation.
- Use deterministic String operations for exact text composition, inspection,
  and scalar parsing. Use `decide` rather than a String predicate when routing
  depends on meaning, quality, intent, policy, or another semantic judgment.
- Keep numeric expressions short. Bind intermediate values when checked
  arithmetic, conversion, or list indexing would otherwise obscure operation
  inputs or control-flow intent.
- Use triple-quoted block prompts for multiline instructions and ordinary or
  raw quoted prompts for short text. Keep result annotations on the same
  visual operation, even when the template spans several lines.
- Use `with` and `session` blocks when several operations deliberately share
  an agent or session policy; use operation-local modifiers for one-off
  overrides.
- Give decision workflows question-like names and ordinary workflows
  action- or result-oriented names. Prefer a direct `decide` for a condition
  that does not need reusable preparation.
- Place `join`, `joinall()`, or `detach` near the corresponding spawns when
  practical. A distant ownership transfer is valid but makes parallel flow
  harder to audit.
- Prefer imported or `crate::`-rooted item paths when the unqualified lookup
  would not be obvious from the surrounding module.
- Keep agent names visually distinct from workflow, module, binding, and task
  names even though the grammar makes each namespace use unambiguous. This
  makes `with <agent>` blocks easier to scan in model-authored source.

The valid examples in Section 14 follow these conventions and serve as the
canonical source-style reference for v1.

### 1.5 Core terminology

The following terms distinguish source constructs from runtime and integration
activity throughout this specification:

- A **workflow** is a source `fn`, inherent method, or `decision`
  declaration. Calling a workflow creates an interpreter frame; the call is
  not itself model-backed work.
- An **action declaration** is a typed package item that names an external
  harness capability. It has no Gantry body. An **action invocation** is an
  `action <path>(...)` expression resolved against that declaration.
- A **logical operation** is one dynamic execution of a source `prompt`,
  terminal `decide`, or action invocation. It has one stable operation ID and
  produces at most one consumable operation result.
- A **physical dispatch** is one invocation of `OperationHook` for a logical
  operation. Validation repair and recovery may cause several physical
  dispatches for one logical operation, each with a distinct dispatch ID.
- A **hook outcome** is `Completed(raw_output)`, `Declined(reason)`, or
  `Failed(message)`. An **operation result** is the validated and normalized
  value, no-result acceptance, optional decline, or sealed `Decision`
  that Gantry durably derives from an outcome and may consume.
- A **Gantry task** is an interpreter execution lane: the root task or one
  child created by `spawn`. A task is not an agent, model, provider request,
  or executor thread.
- An **agent** is a logical source-declared name selected by `with` or by the
  package default. The integration maps that name to its model or agent
  implementation.
- A **harness action** is a package-declared capability fulfilled through an
  action operation. An integration may also perform provider-internal work
  while fulfilling any operation; such hidden work is not a second Gantry
  operation and cannot mutate Gantry state except through the hook outcome.
- A **tagged value** is an enum or `Result<T, E>` value whose strict-JSON
  representation carries an explicit variant discriminator.
- A **deterministic condition** is a `Bool` expression evaluated over already
  validated values. Pattern tests and exact equality are interpreter work and
  never invoke a hook.
- A **named input** is one ordered, typed `using` entry supplied separately
  from rendered prompt text.
- A **foreground outcome** is the completion of root `main`. A **terminal
  execution outcome** is known only after foreground and detached work have
  settled and required terminal state is durable. Foreground success can
  therefore precede a terminal detached-task failure.

## 2. Normative Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119.

## 3. Implementation and Execution Model

1. A conforming Gantry v1 implementation MUST accept every source program
   admitted by the grammar in Section 13 when it also satisfies the semantic
   requirements in this document, and MUST reject source outside that grammar
   when operating in v1 mode. An implementation MAY provide an explicitly
   selected extension mode, but source accepted only by that mode MUST NOT be
   represented as portable Gantry v1 source. Conformance requires all v1
   `MUST` and `MUST NOT` requirements; implementing only the parser or only a
   subset of runtime constructs is not full v1 conformance.
2. Gantry MUST provide its own grammar, lexer, parser, and abstract syntax
   tree (AST).
3. Gantry MUST execute source directly. It MUST NOT require compilation to a
   different language or runtime as its execution model.
4. Gantry MUST be available as an embeddable Rust library with an asynchronous
   execution API. It does not implement an agent, model provider, transport, or
   hidden asynchronous runtime itself. The embedding application MUST supply
   the executor used to poll Gantry futures. Gantry MUST permit its task
   scheduler or executor adapter to be replaced through library configuration,
   not through Gantry source syntax.
5. The interpreter MUST control program flow, hook invocation, result
   validation, retry handling, and state transitions.
6. An integration MUST implement the hooks needed to perform model operations
   and declared harness actions. It is responsible for mapping Gantry agent
   names to its own agents or models and canonical action signatures to its
   own capabilities.
7. Model selection, tool access, approvals, authentication, persistence
   backend selection, logging backend selection, operation-level timeouts,
   provider-specific cancellation mechanics, and resource limits belong to
   the integration. Gantry owns the language-level execution, task-ownership,
   and cancellation state transitions defined in Sections 10 and 15 and MUST
   provide Gantry-owned cancellation tokens to integrations. The integration
   chooses applicable policy values and makes a best effort to stop provider
   work when those tokens are signalled. Gantry MUST provide the asynchronous
   task scheduling needed to execute parallel Gantry blocks.
   Interpreter-only work MUST remain cooperatively cancellable even when it
   executes no hook or spawned task. Gantry MUST observe cancellation before a
   hook dispatch, child-task submission, workflow or decision frame entry, and
   every loop condition or back edge. It MUST also yield to the embedding
   executor after a finite configured number of consecutive deterministic
   interpreter transitions. That yield quantum MUST be nonzero and finite;
   changing it affects scheduling only and MUST NOT alter language results,
   dynamic identities, journal state, or retry accounting. Recursion MUST use
   interpreter-managed frames rather than rely on unbounded native Rust stack
   growth. Exhaustion of a configured interpreter resource limit MUST surface
   as a structured deterministic-evaluation runtime error, never a panic or
   silent process termination.
8. Gantry execution MUST be serializable and resumable. Gantry MUST provide a
   journal, or an equivalent durable execution record, sufficient to continue
   an interrupted execution from its recorded state. Section 11 defines the
   required recovery behavior.
9. Gantry does not promise deterministic replay. Re-execution of the same
   source and inputs MAY produce different integration results. Resumption MUST,
   however, reuse every committed physical hook outcome and MUST reuse every
   validated operation result already derived from committed journal state.
   A committed raw `Completed` outcome that has not yet passed validation is
   durable input to resumed validation, not yet a successful operation result.
10. The Gantry v1 source-language version is major `1`, minor `0`. The initial
    public protocol version for hook requests, journal envelopes, event
    envelopes, and the configuration identity is likewise major `1`, minor
    `0`, but source-language and protocol versions are distinct fields and
    MUST NOT be inferred from one another. A document reference to “v1”
    identifies source-language major version 1 and does not by itself permit a
    different protocol major version. Every new execution and resume request
    MUST explicitly select a supported source-language version through the
    embedding API; v1 source contains no in-file version pragma.
11. v1 makes no backward-compatibility promise for source syntax or the
    concrete Rust hook API. Public hook, journal, event, and configuration
    envelopes remain subject to the explicit major/minor compatibility rules
    in item 10 and Section 15. That protocol obligation preserves the meaning
    of a supported envelope; it does not require a later implementation to
    accept source written for another language version or preserve concrete
    Rust type signatures.

## 4. Source Organization

1. Gantry source files MUST use the `.gnt` extension.
2. A package entry point is `main.gnt`, and its selected entry function is
   the root module's `fn main`. The root module MUST declare exactly one
   function named `main`; a missing `main`, a `main` declared only in a child
   module, or any non-function root item named `main` is an analysis error.
   The directory containing `main.gnt` is the package root. `main` MUST have
   either no parameters or exactly one typed parameter and MAY return any v1
   result type or no result. Neither the entry parameter nor the result type
   MAY be `Decision` or contain `Decision` at any nesting depth. Entry and
   result JSON encode the visible `decision` and `rationale` fields but cannot
   carry the interpreter-only operation provenance that makes a `Decision`
   sealed. A workflow that needs to export a judgment MUST project those
   fields into an ordinary declared struct before returning it from `main`.
   When `main` has a parameter, the embedding application MUST supply one raw
   byte sequence containing the entry JSON. Gantry MUST own UTF-8 decoding and RFC 8259 JSON
   parsing and MUST apply the same empty-input, trailing-data, duplicate-member,
   and Unicode-scalar rejection rules that Section 8 applies to hook output.
   Gantry MUST then validate the parsed value against the parameter's generated
   schema before execution begins. After validation, Gantry MUST normalize the
   entry value exactly as it normalizes hook output: omitted optional struct
   fields receive their declared defaults when present and otherwise become
   `None`, and every runtime struct contains all declared fields. An embedding
   API MUST NOT require callers to preparse the entry input through a JSON
   representation that can erase those errors. When `main` has no parameter,
   supplying entry bytes is an error.
   Entry decoding, validation, and normalization are pre-execution work. A
   failure in that work MUST be returned as a structured start failure and
   MUST NOT create a resumable Gantry execution or an execution-start journal
   record. Section 15 defines the corresponding embedding result boundary.
   Gantry MUST return a successful entry result to the embedder as the
   canonical strict JSON defined in Section 8
   together with a host-level indication of whether the function returned a
   value; this indication distinguishes a no-result `main` from an `Option<T>`
   result whose JSON value is `null`. A no-result `main` returns JSON `null`
   with the host-level no-result indication; a value-returning `main` uses the
   Section 8 encoding of its declared type. The successful result envelope
   MUST also contain the canonical result-type descriptor from Section 5:
   `None` for a no-result `main`, or the declared return type for a
   value-returning `main`. Embedders therefore never need to infer type or
   no-result semantics from JSON shape.
3. Gantry MUST support comments and SHOULD adopt Rust lexical conventions
   where they fit the v1 feature set. Rust likeness is primarily a syntactic
   and readability goal; Gantry does not inherit Rust semantics by default.
4. Names MUST be declared before use. Gantry uses lexical scope. Declaration
   order is evaluated within each module's source order. A child module becomes
   available when its enclosing `mod` declaration is reached; names inside that
   child are then resolved according to the child's own source order. Analysis
   MUST NOT depend on filesystem enumeration order or the order in which an
   implementation happens to parse module files.
5. Gantry MUST support namespaces and whole-module imports through a
   Rust-inspired `mod` form. Included files are parsed as independent modules,
   not textual insertion into the caller's scope.
6. Module paths MUST be local, relative paths and MUST remain inside the same
   package. Remote paths, absolute paths, environment expansion, and package
   resolution are excluded from v1. Module resolution MUST reject `.` and `..`
   path components and symbolic links. Rejecting symbolic links keeps package
   containment and source identity independent of host filesystem aliasing.
7. A file module declaration `mod foo;` resolves in the declaring module's
   module directory as either `foo.gnt` or `foo/mod.gnt`. The root module's
   module directory is the package root. A module loaded from `foo.gnt` or
   `foo/mod.gnt` has `foo/` as its module directory, and an inline `mod foo {
   ... }` likewise has the conceptual module directory `foo/` below its
   parent's module directory. These rules apply recursively to child module
   declarations. If both file candidates exist, analysis MUST fail as
   ambiguous. The package root is a containment boundary, not an alternate
   lookup directory for nested modules.
8. Inline modules of the form `mod foo { ... }` MUST be supported. Module items
   are addressable package-wide in v1, but an item is not automatically added
   to another module's unqualified lexical namespace. Code in another module
   MUST use a `use` declaration or a Rust-inspired qualified `module::item`
   path.
9. `mod` declarations MUST precede references to their namespace. Module cycles,
   duplicate declarations, and duplicate module resolutions are analysis
   errors. Visibility constraints are excluded from v1.
10. A function, method, or decision workflow MAY call itself, and a struct MAY
    refer to its own declared name subject to the guarded-recursion rule in
    Section 5, even though names otherwise must be declared before use. Mutual
    recursion between distinct workflow declarations or between distinct
    struct declarations is excluded from v1.
11. Gantry MUST support Rust-inspired `use` declarations as well as qualified
    item paths. An unprefixed path begins in the current module's lexical
    namespace. `crate::` begins at the package root, `self::` begins at the
    current module, and each leading `super::` moves outward by one module.
    Escaping above the package root is an analysis error. `use` follows the
    same path rules and does not change item visibility.
12. Module filenames and identifiers MUST be valid UTF-8 and MAY use
    `snake_case`, `camelCase`, or `PascalCase`. All source identifiers MUST be
    in Unicode Normalization Form C (NFC); an implementation MUST reject rather
    than silently normalize a non-NFC identifier. Gantry v1 identifier
    classification and normalization MUST use Unicode Standard version 16.0.0,
    the same pinned release used by the deterministic String operations in
    Section 5.
    A scalar that is not `XID_Start` or `XID_Continue` in that version MUST NOT
    become valid merely because a later Unicode release assigns it different
    properties. Identifier equality and name resolution MUST compare the exact
    NFC Unicode scalar sequence and MUST be case-sensitive; implementations
    MUST NOT apply case folding or locale-dependent comparison. Authors SHOULD
    use `PascalCase` for struct types and `snake_case` for modules, agents,
    workflows, methods, fields, parameters, bindings, and task handles. These
    case forms are readability conventions rather than analysis requirements.
    A `mod foo;` declaration MUST
    match either the `foo` stem in `foo.gnt` or the `foo` directory in
    `foo/mod.gnt` exactly, including case. Module path components MUST be
    NFC under the general identifier rule.
13. Top-level package and module contents MUST be declarations. Executable
    statements are permitted only within function, method, decision, spawn, or
    other executable block bodies.
14. Gantry MUST discover the complete module graph and collect package-wide
    agent names before resolving item bodies. After declarations, type names,
    and `impl` targets have been resolved under the ordinary source-order
    rules, Gantry MUST also collect every valid inherent-method signature
    before resolving executable bodies. Agent-name collection and
    inherent-method collection are the only exceptions to declared-before-use
    ordering. A valid inherent method is consequently available on its target
    type throughout the package even when its `impl` block occurs later or in
    another module. The target type and every type named by the method
    signature MUST still be available at the `impl` declaration itself;
    method collection does not make a later type declaration usable earlier.
    Discovery of a later `mod` declaration MUST NOT make that namespace usable
    earlier in its parent module, and it does not make functions, types,
    actions, or imports usable before their declarations. Within one module,
    item names MUST be unique across structs, enums, functions, decisions,
    actions, and modules. An imported name MUST NOT collide with another
    import or local item.
15. Struct field names, parameter names, and method names for one receiver type
    MUST each be unique. A local binding or task handle MUST NOT duplicate or
    shadow any parameter, binding, or task handle visible at its declaration
    point. A parameter, local binding, or task handle also MUST NOT reuse the
    unqualified name of a module item or import visible at its declaration
    point. Authors MAY use an explicit qualified path when they need an item
    whose final segment is reused in a nested, unrelated scope. Fields and
    methods occupy one shared namespace for their receiver, so a field and an
    inherent method on the same struct MUST NOT have the same name. Members MAY
    reuse names that exist in unrelated lexical scopes. These rules deliberately
    exclude source-level shadowing in v1 so references remain unambiguous to
    both readers and static analysis.
    Agent names occupy a separate package-wide namespace. They are introduced
    only by `agents`, selected only by `default agent` or `with`, and MUST NOT
    participate in ordinary item, local-binding, field, method, or task-handle
    lookup. The same spelling MAY therefore occur in the agent namespace and
    one ordinary namespace without creating a name-resolution conflict,
    although Section 1.4 recommends distinct spellings when coexistence would
    make source harder to read.
16. Every protocol, journal, event, or diagnostic field that requires a
    canonical item or workflow path MUST use a `crate::`-rooted path after
    resolving `use`, `self`, and `super`. The root function `main` is therefore
    `crate::main`; an item `inspect` in nested modules `quality::checks` is
    `crate::quality::checks::inspect`. A free function or decision workflow
    uses its canonical item path as its workflow path. An inherent method uses
    `<T>::method`, where `T` is the receiver's canonical struct type descriptor
    from Section 5, for example
    `<crate::domain::Report>::revise`. Canonical paths MUST use exact NFC item
    spellings and MUST NOT retain a source-level import alias or relative root.

    A canonical workflow or action signature is one UTF-8 string constructed
    from that path and the canonical type descriptors in Section 5. A
    free-function signature is `fn PATH(P1,P2,...)->R`; a decision signature
    is `decision PATH(P1,P2,...)->Decision`; an action signature is
    `action PATH(P1,P2,...)->R`; and a method signature is
    `fn METHOD_PATH(RECEIVER[,P1,P2,...])->R`. `RECEIVER` is exactly `self` or
    `mut self`. Each non-receiver parameter descriptor is its type descriptor,
    prefixed by `mut ` when the source parameter is mutable. `R` is the
    declared result descriptor or `None` for no result. The encoding contains
    no whitespace except the one space in `mut ` or `mut self`, contains no
    parameter names, and preserves declaration order. Examples are
    `fn crate::main(String)->crate::domain::Report`,
    `decision crate::quality::is_complete(crate::domain::Report)->Decision`,
    `action crate::search(crate::SearchRequest)->Result<List<crate::Source>,crate::SearchFailure>`,
    and
    `fn <crate::domain::Report>::revise(mut self,String)->crate::domain::Report`.
    This format is metadata rather than source syntax.
17. Package loading MUST operate on one immutable source snapshot per dry-run,
    analysis, new-execution, or resume activity. For each selected file, module
    resolution, UTF-8 decoding, lexing, parsing, source spans, diagnostics, and
    the package-source manifest in Section 11 MUST all use the same exact byte
    buffer and package-relative path observation. An implementation MUST NOT
    reread a selected path during one activity and combine tokens, spans, or a
    digest from different file contents. A filesystem-backed implementation
    MAY copy files into immutable memory as it discovers the module graph or
    use an equivalent stable source-provider snapshot. A source change after
    a file has entered that snapshot cannot affect the active activity; a
    later activity observes either a complete compatible snapshot or a source
    identity mismatch. This requirement does not promise an atomic snapshot of
    unrelated host files, but it prevents one Gantry activity from having
    internally inconsistent source text and identity.

## 5. Values, Bindings, Structs, and Tagged Types

1. Runtime values MUST include `Bool`, `Int`, `Float`, `String`, declared
   struct and enum values, `Option<T>`, `Result<T, E>`, `List<T>`,
   `Tuple<T1, T2, ..., Tn>`, and `Decision`. `Bool` is ordinary deterministic
   data. `Decision` is a sealed first-class model judgment with provenance;
   retaining it as a distinct type keeps agent judgment distinguishable from
   locally computed facts.
   `Int` is an exact signed integer in the inclusive range
   `-9007199254740991` through `9007199254740991` (`±(2^53 - 1)`). `Float` is a
   finite IEEE 754 binary64 value. Directive integers used for limits and retry
   counts remain a separate nonnegative syntax domain through `2^63 - 1` and
   are not implicitly `Int` values.
2. Parameters and returned values MAY be `Bool`, `Int`, `Float`, `String`, a declared struct or enum
   type, `Option<T>`, `Result<T, E>`, `List<T>`,
   `Tuple<T1, T2, ..., Tn>`, or `Decision` whose member types are otherwise
   permitted. A function, method, prompt, action, or spawned block MAY have no
   returned value. An ordinary function, method, binding, aggregate, or struct
   MAY carry `Decision`, but an expected `prompt` or `action` output type MUST
   NOT contain `Decision` at any nesting depth. Only `decide` or a decision
   workflow can produce that sealed type.
   Omission of a result annotation and the explicit result annotation `-> None`
   both denote this no-result form; they do not denote `Option<T>`. No-result
   is not a first-class value and cannot be bound, passed, interpolated, or
   constructed. In particular, `return;` exits a no-result body, while
   `return None;` is valid only when an expected `Option<T>` return type gives
   that expression a type; it is not another spelling of a no-result return.
3. `Option<T>`, `Result<T, E>`, `List<T>`, and
   `Tuple<T1, T2, ..., Tn>` MAY appear in
   parameters, bindings, returned values, and struct fields. `Some(value)` and
   `None` MUST be constructible by deterministic interpreter operations.
   Gantry code MAY inspect an option through the deterministic `match` and
   `if let` forms in Section 9. An unwrap operation remains excluded.
   `Option<Option<T>>` is excluded from v1
   because the untagged strict-JSON encoding cannot distinguish `None` from
   `Some(None)`.
   Every expression MUST have one statically known type. `Some(value)` has
   type `Option<T>` when `value` has type `T`. A `None` expression acquires its
   `Option<T>` type only from an expected type supplied by a binding annotation,
   assignment target, parameter, struct field, or return position. Bare `None`
   in a position without such an expected type, including a top-level prompt
   interpolation island, is an analysis error; authors can interpolate a typed
   option binding instead. Gantry performs no other implicit option wrapping.
4. `List<T>` is an ordered, homogeneous collection. V1 supports list literals
   and zero-based deterministic projection with `value[index]`, where `index`
   is an `Int` expression. Projection yields `T`; a negative or out-of-bounds
   list projection is a fatal runtime error. Every item in a list literal MUST
   have exactly one static type. An empty literal is valid only where an
   expected `List<T>` type is known. Items are evaluated once from left to
   right and the list becomes visible atomically after all items succeed.
   `List<T>.len()` is defined in item 14, and `List<String>.join(separator)` is
   defined in item 15. Iteration, mutation, and other deterministic list
   operations are excluded from v1.
5. `Tuple<T1, T2, ..., Tn>` is an ordered, fixed-arity heterogeneous
   collection. Its arity MUST be at least two, and each positional member MAY
   have a distinct otherwise permitted type. v1 supports zero-based
   deterministic projection with `value[index]`; the literal index MUST be in
   bounds during analysis and the projection's static type is the type at that
   tuple position. `(a, b, ...)` constructs a tuple of at least two members;
   `(value)` remains grouping. Tuple members are evaluated once from left to
   right and the tuple becomes visible atomically after all members succeed.
   A tuple pattern MAY destructure a tuple in `let`, `if let`, or `match`.
   Iteration and mutation of tuple members are excluded from v1.
6. Struct fields MAY be `Bool`, `Int`, `Float`, `String`, declared struct or enum values, `Option<T>`,
   `Result<T, E>`, `List<T>`, `Tuple<T1, T2, ..., Tn>`, or `Decision` of
   otherwise permitted types. Nested and directly self-recursive struct
   definitions are permitted. In accordance with Section 4, a cycle through
   two or more distinct declared types is excluded from v1. Every permitted
   self-recursive struct cycle MUST pass through `Option<T>` or `List<T>` so
   that a finite strict-JSON value can terminate the recursion. An unguarded
   recursive cycle is an analysis error because it has no finite inhabitant.
7. Gantry MUST support declared enums as closed tagged unions. An enum MUST
   contain at least one variant. Each variant is either unit-like or carries
   exactly one otherwise permitted payload type; authors MUST use a struct
   payload when one variant needs several named values. Variant names MUST be
   unique within the enum. A unit variant is constructed as
   `Type::Variant`; a payload variant is constructed as
   `Type::Variant(value)`. The payload type MUST match exactly. Enum values
   MAY be inspected only by patterns, equality expressions, projection from a
   bound payload, or by supplying the complete value to an operation.
   Directly or transitively recursive enum payloads are excluded from v1.
8. `Result<T, E>` is a built-in tagged union with source constructors
   `Ok(value)` and `Err(error)`. Their types are `Result<T, E>` when the
   expected type and argument type identify the other member. A constructor
   without enough expected-type information is an analysis error. `Result`
   represents an expected outcome intentionally returned by a prompt, action,
   workflow, or source constructor. Gantry MUST NOT convert `HookOutcome::Failed`,
   a required decline, invalid output, retry exhaustion, cancellation,
   journal failure, or another runtime error into `Err`; those failures retain
   their ordinary runtime semantics. V1 has no `?` operator or implicit result
   propagation.
9. `Decision` is a sealed first-class value with read-only fields
   `decision: Bool` and `rationale: String`, where the rationale is nonempty.
   Only `decide` and decision workflows may create one.
   Source MAY bind, pass, return, capture, store, interpolate, and consume a
   `Decision` as an `if`, `while`, or `until` condition. The field projections
   `.decision` and `.rationale` yield `Bool` and `String`, respectively.
   Source MUST NOT construct, compare, pattern-match, destructure, or mutate a
   `Decision`. Reusing a bound decision performs no new hook dispatch and
   preserves the logical operation provenance of the original decision.
10. Gantry MUST support named-field struct construction. Struct values MAY be
   constructed by source execution or produced by an operation hook. A source
   constructor MUST reject unknown and duplicate fields during analysis.
   Constructor field expressions are evaluated once in source order. For
   source construction, a field is required only when it has neither a
   declared default nor an `Option<T>` type. Omitting such a field is an
   analysis error; an omitted field with a default uses that default, and an
   omitted `Option<T>` field without a default becomes `None`. A non-optional
   field with a source default may therefore be omitted from a source
   constructor even though Section 8 still requires that field in operation-hook
   output. A constructed value becomes visible only after every supplied field
   expression completes successfully. Earlier hook side effects are not
   reversible if a later field expression fails.
11. Struct fields MAY declare `Bool`, `Int`, `Float`, `String`, or `None`
   defaults, which are the only field-default forms in v1. A scalar default
   MUST exactly match the field's declared scalar type or the member type of
   an `Option` around that scalar. A scalar default on `Option<T>` normalizes
   to `Some(default)`. A `None` default is valid only for an `Option<T>` field.
   Defaults MUST NOT invoke an agent operation. When an optional field with a
   default is omitted, the default is assigned; explicit `null` remains
   `None`. Struct update syntax and destructuring are excluded from v1.
12. Every first-class Gantry value has deep, nonaliasing value semantics.
   Binding initialization, assignment, argument and return passing, field and
   aggregate projection, construction, task capture, and join-result delivery
   each produce an independent logical value. An implementation MAY share
   immutable backing storage or use copy-on-write internally, but that sharing
   MUST NOT be observable through mutation, failure, cancellation, journaling,
   or resume. Interpreter-only optional-decline provenance is copied with its
   value under Section 7. Bindings, including function, method, and
   decision-workflow parameters other than the receiver, are immutable by
   default. `mut` on a local declaration or parameter enables rebinding and
   field mutation of that local value. Parameter mutability is local to the
   called workflow and never permits mutation of the caller's value.
   Assignments MUST preserve type, and v1 permits no implicit type coercion.
13. `const` is excluded from v1. Runtime initialization of immutable bindings
   is permitted.
14. Gantry MUST provide the deterministic primitive operations in this item.
    There is no truthiness or implicit numeric or String coercion.
    - `!` accepts `Bool`. `&&` and `||` accept `Bool`, evaluate left to right,
      short-circuit, and return `Bool`.
    - Unary `-` accepts `Int` or `Float` and preserves its operand type.
    - `+`, `-`, `*`, and `/` accept two values of the same numeric type and
      return that type. `%` accepts two `Int` values and returns `Int`.
      Additionally, `+` accepts two `String` values and returns their exact
      concatenation without inserting a separator, whitespace, normalization,
      or other text.
    - `<`, `<=`, `>`, and `>=` accept two values of the same numeric type and
      return `Bool`.
    - `==` and `!=` accept two values of one identical equatable type and
      return `Bool`. Equality is exact deep structural equality over normalized
      values. `Decision`, and any aggregate transitively containing one, is
      non-equatable.
    - `Int.to_float()` returns an exact `Float`. `Float.to_int()` returns
      `Some(Int)` only when the value is integral and in range, and otherwise
      returns `None`; it never rounds or truncates.
    - `Bool.to_string()`, `Int.to_string()`, and `Float.to_string()` return the
      same canonical spelling used when that primitive is interpolated:
      exactly `true` or `false`, canonical decimal `Int`, or RFC 8785 JSON
      number serialization, respectively.
    - `List<T>.len()` returns an `Int`. Every runtime list length MUST fit the
      `Int` range.
    Integer arithmetic is checked. Overflow, division by zero, remainder by
    zero, and negation of an unrepresentable result are fatal runtime errors.
    Integer division truncates toward zero and remainder has the dividend's
    sign, preserving `a == (a / b) * b + (a % b)`. Float operations use
    binary64 round-to-nearest, ties-to-even; a non-finite result or division by
    either signed zero is fatal. Underflow to a finite subnormal or zero is
    permitted, and negative zero is normalized to positive zero after every
    operation and input normalization. Implementations MUST NOT use fused
    arithmetic where it changes the specified intermediate rounding.
    Power, floating remainder, rounding and transcendental functions, String
    repetition, list mutation, and other built-ins are excluded.
    Lists and tuples MAY otherwise be constructed, passed, returned,
    interpolated, projected, and pattern-destructured.
15. `String` is an immutable valid-UTF-8 sequence of Unicode scalar values.
    Gantry performs no implicit Unicode normalization. A `mut String` binding
    permits atomic replacement of the complete value, not observable in-place
    mutation of backing storage. String equality is exact scalar-sequence
    equality. Gantry MUST provide the following sealed, deterministic methods;
    source declarations cannot override them:
    - `String.len() -> Int` returns the number of Unicode scalar values, not
      bytes or grapheme clusters. `String.is_empty() -> Bool` is true exactly
      when that count is zero.
    - `String.contains(needle)`, `String.starts_with(prefix)`, and
      `String.ends_with(suffix)` each accept one `String` and return `Bool`
      using exact contiguous scalar-sequence matching. Every String contains,
      starts with, and ends with the empty String.
    - `String.trim()`, `String.trim_start()`, and `String.trim_end()` return a
      new String after removing Unicode `White_Space` scalars from both ends,
      the start, or the end, respectively.
    - `String.to_lowercase()` and `String.to_uppercase()` return a new String
      using full, locale-independent Unicode case mappings. A mapping MAY
      change the scalar count.
    - `String.replace(from, to)` returns a new String after exact,
      nonoverlapping, left-to-right replacement. It MUST NOT rescan replacement
      text. An empty `from` is a fatal `string-empty-pattern` deterministic-
      evaluation error.
    - `String.split(separator) -> List<String>` performs exact,
      nonoverlapping, left-to-right splitting. An empty separator is a fatal
      `string-empty-separator` deterministic-evaluation error. Leading,
      trailing, and adjacent empty segments are preserved; no match returns a
      one-item list containing the original String.
    - `String.parse_bool() -> Option<Bool>` accepts exactly `true` or `false`.
      `String.parse_int() -> Option<Int>` accepts exactly `0` or an optional
      `-` followed by a nonzero decimal digit and zero or more decimal digits;
      it rejects `-0`, leading `+`, separators, radix prefixes, leading zeroes,
      and out-of-range values. `String.parse_float() -> Option<Float>` accepts
      exactly the RFC 8259 JSON number grammar and returns the normalized
      finite binary64 value, or `None` when parsing or normalization fails.
      These parsers do not trim and never fail the task for invalid input.
    `List<String>.join(separator) -> String` joins items in list order with the
    exact separator only between adjacent items. It returns the empty String
    for an empty list and the sole item unchanged for a one-item list. `join`
    is not defined for another `List<T>`.
    Trimming, case mapping, and scalar classification MUST use Unicode Standard
    version 16.0.0, specifically its `White_Space` property and full default
    case mappings. These methods are locale-independent. String indexing,
    slicing, characters, bytes, regexes, normalization, locale-aware behavior,
    case-insensitive comparison, ordering, repetition, and mutable String
    methods are excluded from v1.
16. Every String result and every List result produced by a deterministic
    operation MUST satisfy the effective limits in Section 11 before it is
    published. Concatenation, case mapping, replacement, splitting, and joining
    are atomic: a `string-size-limit` or `list-size-limit` deterministic-
    evaluation error leaves the assignment target unchanged. The same checks
    apply recursively to source construction, entry input, hook output, and
    resumed values. Deterministic String operations dispatch no hook, create no
    model rationale or operation event, and consume no validation-retry budget.
17. Patterns are deterministic structural operations over an already evaluated
    value. V1 patterns are `_`, an identifier binding, `Some(pattern)`,
    `None`, `Ok(pattern)`, `Err(pattern)`, a unit or payload enum variant, and
    a fixed-arity tuple pattern. `_` matches without binding. An identifier
    pattern matches and deep-copies the complete value into a new immutable
    lexical binding. Names introduced by one pattern MUST be unique and obey
    the no-shadowing rules in Section 4. A `let` destructuring pattern MUST be
    irrefutable for its static type; v1 therefore permits only identifier and
    tuple patterns, recursively, in `let`. `if let` and `match` admit refutable
    patterns under Section 9.
18. Every protocol field that identifies a Gantry type MUST use one canonical
    UTF-8 type descriptor. `Bool`, `Int`, `Float`, `String`, and `Decision` are
    encoded exactly as their source names; a declared struct or enum is encoded as its
    `crate::`-rooted qualified path; and constructed types are encoded as
    `Option<T>`, `Result<T,E>`, `List<T>`, or `Tuple<T1,T2,...,Tn>` with no
    whitespace and with each member recursively encoded by this rule. The
    no-result form is encoded as `None`. Source aliases introduced by `use`
    MUST be resolved before a descriptor is produced. Canonical descriptors
    are metadata rather than source values, but they ensure that hooks,
    journals, events, and diagnostics identify the same type independently of
    the spelling visible at a call site.
19. Boolean literals are `true` and `false`. Integer and float literals follow
    Section 13.2. A numeric literal MUST be representable by its inferred
    primitive type; out-of-range literals are analysis errors. Gantry performs
    no implicit conversion between `Int` and `Float`, including in assignment,
    arguments, returns, aggregate members, equality, or arithmetic. Unary `-`
    is an operator rather than part of a numeric token.

## 6. Functions and Methods

1. Gantry MUST support free functions and inherent methods declared in
   Rust-inspired `impl` blocks. An `impl` target MUST resolve to a struct
   declared in the same Gantry package. Because the grammar accepts only a
   qualified path after `impl`, built-in and constructed types such as
   `Bool`, `Int`, `Float`, `String`, `Option<T>`, `List<T>`, `Tuple<...>`, and no-result `None` cannot
   be written as `impl` targets in v1. A qualified path that resolves to a
   function, decision, module, or other non-struct item is an analysis error.
   A package MAY split one struct's methods across multiple `impl` blocks,
   subject to the package-wide duplicate-method rule below. Traits are
   excluded from v1.
2. Methods MUST support `self` and `mut self` receivers.
3. A method may mutate its receiver only through interpreter-executed field
   assignments in its body. For every assignment, Gantry MUST evaluate the
   complete right-hand side before changing the target and MUST commit the new
   root value atomically only after evaluation succeeds. Compound assignments
   `+=`, `-=`, `*=`, `/=`, and `%=` read the target exactly once, apply the
   corresponding checked primitive operator, and atomically commit its result.
   `+=` is valid for mutable `String`, `Int`, or `Float` targets; `-=`, `*=`,
   and `/=` are valid only for mutable numeric targets; and `%=` is valid only
   for mutable `Int` targets. String `+=` performs the exact concatenation
   defined in Section 5 and is subject to its atomic size-limit check. This includes hook
   validation, workflow calls, construction, projection, and every nested
   subexpression. Any failure MUST leave the assignment target unchanged;
   external hook side effects and earlier successful assignments are not
   rolled back. This assignment-level atomicity is the v1 transaction
   boundary. The root binding of any assignment target MUST be declared `mut`,
   except that receiver-field assignment is permitted through `mut self`.
   Assigning a nested field constructs and commits one updated root value; it
   does not create aliases to intermediate structs.
4. Functions and methods are interpreter-managed workflows. Calling one MUST
   create an interpreter call frame and execute its body; the call itself MUST
   NOT invoke an operation hook.
   Arguments and receivers use deep-copy value semantics. There are no aliases,
   references, moves, or borrowed values in v1. A `self` or `mut self` receiver
   is therefore a local receiver copy. `mut self` permits mutation of that copy
   but never changes the caller's value implicitly; callers MUST assign a
   returned value explicitly when they intend to retain receiver changes. A
   workflow call MUST provide exactly one argument for each declared
   non-receiver parameter, in declaration order, and every argument's static
   type MUST exactly equal its parameter type. A method call additionally
   requires a receiver of the `impl` target type. Gantry has no default,
   variadic, named, coerced, or overloaded call arguments in v1.
5. A workflow body MAY contain one or more external-operation expressions.
   Each executed `prompt`, `decide`, or `action` expression MUST create exactly
   one logical operation. That logical operation MAY require multiple physical hook
   dispatches because of structured-output validation retries or recovery of
   an indeterminate dispatch; those dispatches retain the same operation ID
   and do not represent additional source operations. Calling a decision
   workflow invokes no hook merely because of the call; evaluating its body
   MAY execute multiple explicitly written prompt or nested decision
   operations before its terminal decision is obtained.
   The same transitive rule applies to ordinary workflow and method calls: a
   call site is deterministic interpreter dispatch, but executing the called
   body MAY reach any `prompt`, `decide`, or `action` sites written in that
   body or in workflows it calls. Consequently, the absence of those keywords
   on the same source line as a call does not prove that the call tree is free
   of integration operations. External work remains explicit at its source site and
   observable through the workflow-call context, operation source location,
   journal, and events. Analysis tooling SHOULD expose this transitive effect
   to authors without representing the call itself as a model operation.
   The terminal `decide` reached through a decision-workflow call is the
   logical decision operation; the call expression and each intermediate
   decision-workflow frame are not additional operations. Its source location
   and static operation site are those of that executed `decide`, while its
   dynamic identity also records the complete workflow-call path that reached
   it. This rule keeps operation counts, hook requests, journals, and events
   aligned with the model-backed sites visible in source.
   Semantic analysis MUST expose this transitive behavior without changing
   the call syntax. For every function, method, and decision workflow, the
   structured analysis result MUST contain:
   - every direct workflow-call edge, identified by call-site location and
     canonical callee path;
   - the direct `prompt`, `decide`, `action`, `spawn`, and `detach` sites in that
     workflow, identified by kind and source location; and
   - five transitive flags indicating whether execution of the workflow may
     reach a `prompt`, `decide`, `action`, `spawn`, or `detach`, respectively.
   The transitive flags MUST be the least fixed point of the package call
   graph, including permitted self-recursion and method calls. These summaries
   are analysis metadata rather than source-level effects or additional hook
   operations. They let human-facing tools and model repair agents distinguish
   deterministic calls from calls that may eventually perform integration-
   backed or parallel work without adding annotations to the source language.
   Struct, enum, option, result, list, and tuple construction; field access;
   assignment; pattern routing; module lookup; workflow dispatch; and `join`
   are interpreter operations and MUST NOT invoke an operation hook.
6. Each `prompt` expression MUST contain an explicit prompt template and MAY
   contain parenthesized operation modifiers before that template. A typed
   prompt places its result annotation after the template, as in
   `prompt(retry_limit = 2, session = fork) "..." -> Report`. A prompt with no
   result annotation, or with `-> None`, has no result. A prompt or `decide`
   expression MAY contain one `using { ... }` clause after its template and
   before the prompt result annotation. Each entry is either shorthand `name`,
   equivalent to `name: name`, or `name: expression`. Entry names MUST be
   unique. Expressions use the same deterministic, side-effect-free subset as
   interpolation. Gantry MUST evaluate named inputs once from left to right
   after interpolation and before dispatch. Validation retries and recovery
   redispatches MUST reuse the captured values rather than reevaluate them.
7. Template expressions MUST be interpolated before hook dispatch. To keep
   agent invocation explicit, an interpolation MAY contain only bindings,
   field paths, list or tuple projections, primitive literals, deterministic
   primitive operators and conversions, the sealed deterministic String and
   List methods in Section 5, and deterministic aggregate constructor
   expressions composed from other permitted interpolation expressions.
   Workflow calls, source-defined method calls, `prompt`, `decide`, `action`,
   assignment, `join`, and other expressions that can invoke a hook, alter
   control flow, or mutate state are prohibited inside interpolation. A call
   inside interpolation MUST resolve to a sealed deterministic built-in whose
   receiver and arguments are themselves valid interpolation expressions.
   Interpolations are evaluated in
   source order. If any interpolation cannot be evaluated or encoded, the
   containing prompt MUST remain undispatched and execution MUST fail. The
   source template and interpolated prompt MUST both be supplied to the hook.
   Interpolation islands and `$$` escapes MUST be identified from the authored
   template body before ordinary or block-prompt escape decoding, as specified
   in Section 13.7. The supplied source template is the authored template body
   after removal of its outer delimiter and any structural block-prompt lines
   and indentation, but before ordinary or block-prompt escape decoding, `$$`
   processing, or interpolation replacement. It therefore preserves authored
   escape spellings and distinguishes `$${name}` from an actual `${name}`
   island. It is not the complete original source token because delimiters and
   structural block-prompt layout are omitted. An implementation MUST retain
   each interpolation island's exact source text and source span independently
   of the dedented hook-facing template. The hook request MUST carry named
   inputs separately from interpolation arguments as an ordered vector of
   name, source span, canonical type descriptor, and canonical JSON value.
   An integration MUST make every named input available to the selected agent,
   even when it must render that structured vector into provider text.
8. A trailing expression in a function, method, or spawned block implicitly
   yields its value. An explicit `return` MAY yield earlier from a function,
   method, or spawned block. An explicit `return` in a decision workflow is
   governed by Section 9. Every explicit or implicit returned expression MUST
   exactly match the
   declared result type. A workflow whose signature omits a result type
   implicitly returns no result. Because no-result is not a value, a no-result
   prompt, workflow call, method call, or `join` MUST be terminated with `;` as
   an expression statement; it cannot be a block's trailing expression. A
   statement-only agent or session context uses `with <agent> { ... }` or
   `session(<directive>) { ... }` without a semicolon after its closing brace.
   A value-producing prompt MAY be discarded by writing it as an expression
   statement. A value-producing workflow or method call, `with` expression,
   `session` expression, or `join` expression MAY likewise be used as an
   expression statement when its result is intentionally discarded. A
   standalone literal, constructor, field access, projection, `Some`, or
   `None` expression has no execution effect and MUST be rejected as an
   expression statement.
   Assignment and `spawn` statements do not themselves produce values.
   Conditional-arm and loop bodies are statement-only blocks; they MUST NOT
   end in a trailing expression whose value would be silently discarded.
   Semantic analysis MUST prove that every reachable normal completion of a
   value-returning function, method, or spawned block yields the declared type.
   Falling through a value-returning body is an analysis error; it MUST NOT be
   deferred to a runtime missing-value failure.
9. A method MAY return `self`; the returned value is a deep value copy and does
   not consume the receiver. Duplicate inherent methods for the same struct are
   analysis errors.
10. `return` exits the nearest enclosing function, method, decision workflow,
    or spawned block. A spawned block is therefore a return target before any
    workflow that lexically encloses the `spawn`. `break` and `continue` target
    the nearest enclosing loop even when they occur inside a nested `with` or
    `session` block, but they MUST NOT cross a spawned-block boundary. An
    ordinary value-producing or statement-only `with` block changes agent
    selection only, and the corresponding `session` block changes the active
    logical session only; neither intercepts or retargets control transfer.
    A `with` or `session` block that yields `Decision` remains an ordinary
    value-producing block; its result type does not create a special control-
    transfer boundary.
11. Except for explicitly parallel spawned blocks, expression evaluation MUST
    be deterministic and left to right. A workflow call evaluates its callee
    and then its arguments in source order; a method call evaluates its
    receiver before its arguments; and a postfix chain evaluates each suffix
    before the next. Constructor fields follow the source-order rule in
    Section 5, and prompt interpolations follow the source-order rule in item
    7 above. Each subexpression MUST complete before the next begins. Failure,
    decline of a required result, or cancellation in one subexpression MUST
    prevent every later subexpression in that expression from being evaluated
    or dispatched. Entering a `with` expression establishes its selected agent
    before its body begins; entering a `session` expression establishes its
    active logical session before its body begins. These rules make the order
    of external operations visible even when calls or constructors are nested.
12. An action declaration is a package item with a canonical path, typed
    positional parameters, an optional result type, and no Gantry body. An
    action invocation MUST use the `action` keyword and MUST resolve to one
    declared action; writing the same path as an ordinary call is an analysis
    error rather than an implicit action dispatch. Gantry evaluates action
    arguments exactly once from left to right, requires exact parameter-type
    equality, captures their canonical JSON values, and then dispatches one
    logical action operation. Source execution awaits that result unless the
    invocation occurs in a spawned task. A no-result action is an expression
    statement; a value-producing action yields its declared type and MAY be
    bound, returned, matched, or intentionally discarded. Action declarations
    have no agent, session, prompt template, or provider policy in Gantry
    source. The integration resolves their canonical signatures during
    preflight under Section 7.

## 7. Agents, Hooks, and Sessions

1. A Gantry package MAY declare permitted agent names in one or more
   `agents { ... }` declarations. Declarations from all package modules are
   merged into one package-wide set; repeating the same logical name is
   idempotent rather than an error. A package containing any `prompt` or
   `decide` operation site MUST have a nonempty merged agent set. When that set
   is nonempty, exactly one dedicated `default agent = <name>;` binding MUST
   appear in `main.gnt`, and its name MUST belong to the merged set. When the
   set is empty, `default agent` MUST be absent. A `default agent` declaration
   in any child module is an analysis error, even when it repeats the root
   declaration. Conflicting default bindings or selection of an undeclared
   agent are analysis errors. This conditional rule permits deterministic-only
   and action-only packages without fictitious model configuration. Within one
   uninterrupted execution or resume run,
   integrations MUST resolve every occurrence of the same logical name
   consistently across all tasks. Before a new execution or resume begins,
   the integration MUST attest that it can resolve every name in a nonempty
   merged set and MUST supply one opaque, stable agent-mapping revision ID.
   An empty set requires neither agent resolution nor an agent-mapping
   revision. When present, the ID identifies the complete logical-name mapping
   for that run without requiring
   Gantry to inspect provider configuration. For a new execution, Gantry MUST
   record that revision in the durably flushed execution-start record required
   by Section 11. A later resume MAY change the mapping only by supplying and
   durably recording a new revision in an execution-state record before
   recovered interpretation or dispatch continues. The new revision then
   applies consistently to every physical hook dispatch made by that resume
   run, including a validation retry or recovery redispatch of an operation
   whose logical agent name was selected earlier. Such a redispatch MUST retain
   the selected logical agent name but MUST carry the newly recorded mapping
   revision. A previously committed hook outcome or logical operation result
   remains unchanged and MUST NOT be redispatched merely because the mapping
   changed. Failure to resolve the complete set MUST occur before any hook
   dispatch. For a new execution it is an integration-preflight start failure;
   for a resume invocation it is the nonterminal resume-start failure defined
   in item 17. It is not a task-local hook-creation error, because no
   `OperationHook` creation or task execution has begun.
2. Agent names are logical identifiers. Their mapping to concrete models or
   agent implementations is exclusively the integration's responsibility.
   Action declarations likewise identify logical harness capabilities rather
   than concrete provider functions. Before a new execution or resume begins,
   the integration MUST resolve every canonical action signature in the
   analyzed package and, when that set is nonempty, MUST supply one opaque
   stable action-mapping revision ID covering that complete mapping. A package
   with no action declarations requires neither action resolution nor an
   action-mapping revision. An unresolved action is an integration-
   preflight start or resume-start failure, even when no reachable execution
   path is expected to invoke it. When present, the execution-start record MUST
   contain the initial revision. A resume MAY change the mapping only after Gantry appends
   and flushes an execution-state record containing the replacement revision;
   that revision applies to every later action dispatch in the resume run.
   Previously committed outcomes and results remain unchanged. Recovery of an
   indeterminate action retains its canonical action path, signature, typed
   arguments, and logical operation ID while carrying the active recorded
   action-mapping revision. The integration MUST map one canonical signature
   consistently for the complete run and MUST reject conflicting or ambiguous
   capability registrations during preflight.
3. Agent selection is established by lexical `with <name> { ... }` blocks and
   inherited by their dynamic model-backed work. The selected name applies to
   `prompt` and `decide` operations written directly in the block, model
   operations reached through workflow or decision calls made from it, and
   child tasks spawned from it, unless a nested `with` block overrides the
   selection. It does not apply to `action` operations. A workflow call therefore
   inherits the caller's active selection rather than resetting to the default,
   and a spawned child snapshots the selection that is active when `spawn`
   executes. Exiting `with` restores the previous selection for its caller;
   an already spawned child retains its snapshot. `<name>` MUST be a literal
   name from the merged agent declarations, not a runtime binding. `with`
   contexts MAY occur at any block scope. Model operations with no active
   selection use the declared default agent.
   Agent selection and logical-session selection are orthogonal. Reusing one
   logical session across nested or sequential `with` blocks MUST preserve the
   session's conversational continuity even when those blocks select different
   agent names. An integration MAY implement that continuity with a shared
   transcript, provider session transfer, or another semantically equivalent
   mechanism, but it MUST NOT silently reset, fork, or replace the logical
   session merely because the selected agent changed. An integration that
   cannot honor cross-agent reuse for the package's declared mappings MUST
   reject the execution during integration preflight rather than fail after a
   partially executed session.
4. The Rust hook contract MUST be asynchronous and executor-neutral. Its
   futures MUST be `Send` so Gantry tasks can execute on a multithreaded
   executor, and Gantry's public API MUST NOT expose Tokio- or provider-specific
   types. A future returned by an extension method MAY borrow that method's
   receiver or arguments and therefore need not be `'static`; only an owned
   Gantry task future submitted to the executor MUST be `Send + 'static`. Each
   individual operation awaits one hook outcome before it advances and is
   therefore logically synchronous. Gantry MUST lazily obtain at most one
   independently usable `OperationHook` instance for each Gantry task from an
   asynchronous `HookFactory`, immediately before that task's first hook
   dispatch. A task that executes no `prompt`, `decide`, or `action` operation MUST NOT
   require hook creation merely because the task exists. Once created, that
   instance MUST live for the remainder of the task's lifetime, including
   nested workflow calls and validation retries, and MUST NOT be invoked
   concurrently with itself. A spawned child receives a distinct hook instance
   if it reaches an operation. `HookFactory::create` MUST receive a
   `TaskContext` containing task, execution, and parent-task identity; the
   task's base logical session ID; the root logical session ID and provenance;
   the enclosing session ID and fork provenance when the task was spawned;
   the inherited agent selection; and the immutable structural-context
   ancestry captured when the task was created.
   The base session is the root session for the root task and the automatically
   forked child session for a spawned task. It is fixed when the task is
   created and MUST NOT be replaced by a transient `session(...)` context that
   happens to be active when lazy hook creation occurs. Active session and
   agent selection remain properties of each operation request because one
   hook instance may serve operations executed under several nested `session`
   and `with` contexts. Agent selection MUST remain part of each operation
   request because a task can enter different lexical `with` contexts. Hook
   creation may fail but cannot decline. Failure while creating the root task's
   hook aborts the execution as a hook-creation error. Failure while creating a
   spawned task's hook settles that child as failed; it is then observed by
   `join`, `joinall()`, detachment, and terminal execution under the ordinary
   task-failure rules. Hook creation MUST NOT dispatch a model operation.
   Gantry MUST give every hook a Gantry-owned cancellation token whose signal
   the integration MUST make a best effort to honor.
   Public asynchronous extension traits MUST use executor-neutral boxed
   futures or equivalent stable abstractions. The executor adapter MUST provide
   task spawning, task joining, task abortion, and asynchronous sleeping for
   backoff. Gantry MUST retain its own cancellation semantics rather than
   treating executor abortion as cooperative hook cancellation.
   “Task lifetime” in this interface means one in-process execution or resume
   run. Hook instances are integration resources and MUST NOT be serialized in
   the journal. After process restart and the session-resolution preflight in
   item 13, Gantry MUST lazily create a fresh hook instance for each recovered
   task that reaches another hook dispatch, then continue that logical task
   with its restored task and session IDs. A recovered task that completes by
   deterministic interpreter work alone does not require a hook instance.
5. Every operation hook request MUST be a versioned tagged envelope with a
   common header and exactly one operation-specific body. The common header
   MUST contain at least:
   - a protocol major and minor version;
   - stable operation, execution, and task IDs, plus the parent-task ID when
     the task was spawned;
   - an operation kind;
   - the expected result kind;
   - the expected canonical result-type descriptor from Section 5;
   - the expected JSON Schema;
   - generated operation guidance describing the input contract, output
     contract, and required strict-JSON response;
   - the source location;
   - a dispatch ID, validation-attempt number, and recovery-dispatch number;
     and
   - validation errors from the immediately preceding invalid attempt, when
     applicable.
   The v1 operation kinds are `prompt`, `decision`, and `action`. The result
   kind is `value`, `no-result`, or `decision`. The expected result descriptor
   is the declared value type for `value`, `None` for `no-result`, and
   `Decision` for `decision`.

   A `prompt` or `decision` body MUST contain the selected agent name and
   active agent-mapping revision; authored source template and interpolated
   prompt; ordered interpolation-argument vector; ordered named-input vector;
   active, root, and parent logical-session metadata; and request and creation
   directives required by this section. Typed interpolation arguments MUST be
   an ordered
   vector containing one record for each interpolation island in source order;
   each record contains the exact UTF-8 source text between that island's
   `${` and matching `}` delimiters, its package-relative source file and
   half-open byte span, its canonical static-type descriptor from Section 5,
   and its RFC 8785 canonical strict-JSON value. The named-input vector MUST
   preserve `using` source order. Each entry contains its unique name, complete
   entry source span, canonical static-type descriptor, and RFC 8785 canonical
   strict-JSON value. A shorthand entry and its expanded `name: name` form have
   the same protocol value but retain their own authored source span.

   An `action` body MUST instead contain the action's canonical item path and
   canonical signature; the action-mapping revision active for the dispatch;
   and an ordered argument vector containing each parameter name, argument
   source span, canonical static-type descriptor, and RFC 8785 canonical
   strict-JSON value. It MUST NOT contain a selected agent, prompt template,
   interpolated prompt, named model input, or conversational-session directive.
   Lexical `with` and `session` contexts do not change an action request.
   Comments and whitespace inside the island remain part of that source-text
   field even though they do not affect evaluation. A repeated
   interpolation appears repeatedly so the request
   preserves the template's operation inputs exactly. Source locations MUST
   identify the package-relative UTF-8 file and a zero-based, end-exclusive
   byte span into that file's exact source bytes. A permitted UTF-8 byte-order
   mark is part of those bytes and therefore contributes three bytes to later
   offsets even though the lexer ignores it. An operation location spans the
   complete authored `prompt`, `decide`, or action-invocation expression,
   including modifiers, template delimiters, arguments, and a prompt result
   annotation when present. An
   interpolation location spans the complete `${...}` island. Implementations
   MAY additionally report line and scalar-column coordinates, but protocol
   identity and resume MUST use the byte span. The operation ID MUST remain
   stable across validation retries and resume. Each physical hook invocation
   MUST have a distinct dispatch ID. The zero-based
   validation-attempt number advances only after Gantry receives output that
   fails UTF-8, JSON parsing, or schema validation; it is bounded by the
   operation's structured-output retry limit. The zero-based recovery-dispatch
   number advances when an indeterminate invocation is repeated after resume
   and does not consume that retry budget. Validation errors MUST identify the
   failing JSON instance location with JSON Pointer when one exists, the
   violated schema location when one exists, and a human-readable message;
   they MUST NOT contain raw integration output. Each error MUST also carry exactly
   one machine-readable category: `utf8`, `json-syntax`, `json-duplicate-key`,
   `json-unicode`, or `schema`. JSON Pointer and schema-location fields are
   absent rather than fabricated when the applicable parse stage could not
   produce them. Error ordering MUST follow raw-output byte position for
   decoding and parsing errors and depth-first instance traversal, with object
   properties in unsigned UTF-8 name order and array members in index order,
   for schema errors. This canonical shape and order allow independent
   harnesses to render equivalent repair guidance without parsing diagnostic
   prose.
6. A hook request MUST also contain a finite ordered execution-context vector.
   It MUST contain the task's immutable structural ancestry, its active
   workflow call chain, and the control-chain entries needed to interpret the
   current operation; it MUST NOT contain the entire event history or all
   events since session creation. Each context entry MUST identify its kind,
   dynamic source-construct identity when applicable, and associated
   structured data. The canonical v1 context kinds and payloads are:
   - `workflow-frame`: canonical workflow path, call-site location when the
     frame was entered by a source call, and zero-based frame occurrence
     within its immediate dynamic caller;
   - `decision-frame`: canonical decision-workflow path, call-site location,
     and zero-based frame occurrence within its immediate dynamic caller;
   - `spawn-frame`: parent and child task IDs, source spawn location,
     zero-based spawn occurrence within its immediate dynamic parent, and the
     child's canonical declared result-type descriptor;
   - `conditional-arm`: conditional-chain dynamic identity, zero-based arm
     index, condition kind (`decision`, `bool`, or `pattern`), controlling
     outcome, and, for a model-produced decision, its operation ID and
     nonempty rationale;
   - `loop-iteration`: loop dynamic identity, zero-based prospective-iteration
     index, phase (`condition` or `body`), and the most recently settled
     condition's associated index, decision, and nonempty rationale when one
     exists; and
   - `optional-decline`: declined operation ID, operation kind, selected agent
     or canonical action path as applicable, source location, and decline
     reason when a decline normalized to `None`.
   The root `crate::main` frame has no source call site and MUST encode that
   field as absent rather than inventing a location. It has frame occurrence
   zero and is always the first structural context entry. Every non-root
   workflow or decision frame MUST carry the source location of the call that
   entered it. This exception makes the context shape complete for entry-point
   operations without assigning a fictitious caller to `main`.
   A prospective-iteration index identifies the condition/body pair described
   by Section 9: a `while` condition and the body it admits share an index, as
   do an `until` body and its following condition. A final false `while`
   condition may therefore have an index for which no body executes.
   Conditional-chain and loop dynamic identities MUST use the same execution,
   task, workflow-call, branch, loop-counter, and source-span components that
   item 16 requires for dynamic operation identity. They identify the
   controlling source construct rather than any one `decide` operation within
   it and MUST remain stable across retry and resume.
   A context entry's protocol representation MUST preserve one entry boundary,
   its canonical kind, the listed payload fields, and the source-construct
   identity and location when the kind requires them. The structured vector
   MUST remain intact at the Gantry hook boundary: an integration MUST NOT
   discard or reorder entries before presenting them to the selected agent. A
   harness MAY render the entries into provider messages or prompt text when
   its model API has no structured-context channel, but that rendering MUST
   preserve vector order, visibly distinguish entry boundaries and kinds, and
   make every required field available to the selected agent. Such rendering
   and any provider-specific presentation metadata are integration behavior
   and MUST NOT replace or mutate the canonical request vector. An unknown
   context kind is incompatible with protocol major version 1 and MUST be
   rejected. Adding a context kind requires a new protocol major version; a
   newer minor version may add only optional fields to a known kind under the
   compatibility rule in Section 15.
   When a spawn executes, the child MUST capture the parent's current
   structural entries and append one `spawn-frame` before the child becomes
   runnable. Parent workflow, decision, conditional-arm, and loop-iteration
   entries in that snapshot remain immutable origin context for the child even
   after the corresponding parent scopes exit. Structural entries created by
   the child are appended inside that inherited ancestry. Nested spawns repeat
   this rule, so the vector records task provenance without copying event or
   session history.
   Structural entries (`workflow-frame`, `decision-frame`, `spawn-frame`,
   `conditional-arm`, and `loop-iteration`) MUST appear first, ordered from
   outermost to innermost dynamic scope, with repeated entries in execution
   order within one scope.
   Any `optional-decline` entries MUST follow all structural entries and use
   the interpolation-input and value-traversal order defined below. This is a
   total ordering; integrations MUST NOT regroup entries by kind. An `else if`
   request MUST include the `conditional-arm` entries from preceding arms in
   the same chain. While a selected conditional arm executes, its active
   control-chain context MUST include every preceding false arm followed by
   the controlling true arm. Decision entries include their rationale;
   structural entries do not fabricate one. An `else`
   arm MUST include
   every preceding false arm. These entries leave the active context when the
   conditional chain completes; they are not unbounded execution history. A
   `None` produced by `Declined` MUST carry interpreter-only decline
   provenance distinct from a `None` produced by `Completed(null)` or source.
   That provenance MUST survive assignment, argument and return passing,
   struct or aggregate containment, capture, and other deep copies. An
   operation request MUST include one `optional-decline` entry for every
   distinct decline provenance reachable from its captured inputs. Prompt and
   decision requests traverse interpolation arguments followed by named inputs;
   action requests traverse action arguments. Within each vector, entries are
   ordered by source order and then depth-first value traversal;
   repeated references to the same declined value produce one entry. Depth-first
   value traversal is preorder: a struct visits fields in declaration order;
   an enum, result, or present option visits its payload; and a list or tuple
   visits members in ascending index order. A `None` or unit enum variant has
   no child value. When the
   same provenance is reachable by more than one path, its first encounter in
   this total order determines the entry position. The
   metadata is not part of Gantry's JSON value and MUST NOT change schema
   validation or interpolation, which still emits `null`. The integration MUST
   make every supplied entry
   available to the selected agent in order, although its provider-specific
   presentation is implementation-defined.
7. Prompt interpolation MUST use `${expression}`. An unescaped `$` followed by
   `{` begins interpolation. `$$` consumes exactly those two dollar signs and
   produces one literal dollar sign, so `$${name}` renders the literal text
   `${name}` without interpolation. A `String` is interpolated as its string
   contents; `Bool`, `Int`, `Float`, a struct, enum, option, result, list,
   tuple, or `Decision` is interpolated as compact strict JSON, with `None`
   rendered as `null`. This compact encoding
   MUST use the RFC 8785 JSON Canonicalization Scheme so equivalent Gantry
   values produce the same interpolated prompt across implementations.
   Consequently, `Some("text")` held as an `Option<String>` interpolates as
   the JSON text `"text"`, including its quotes, while a plain `String` with
   the same contents interpolates as `text`. This distinction preserves the
   type and absence semantics of optional values.
   Replacement text is inserted verbatim and MUST NOT be scanned again for
   `${...}` or `$$`; interpolation is a single-pass template operation rather
   than recursive template evaluation. Invalid references and values that
   cannot be encoded are analysis or runtime errors, respectively.
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
   the operation's input and output contract. At minimum, the guidance MUST
   state that the raw operation output returned through `Completed` must contain
   exactly one JSON text with no surrounding prose, Markdown fence, or
   additional value; identify the expected result kind; explain that unknown
   struct properties are rejected; identify fields that may be omitted and the
   defaults or `None` values omission supplies; describe every interpolation,
   named input, or action argument; and explain the no-result, tagged-value, or
   decision shape when applicable. The wording and provider-specific
   presentation MAY evolve, but those semantic instructions MUST remain
   present on every initial dispatch and repair retry.
10. The only v1 source-level model-selection knob is the agent name. Action
    selection is instead the canonical path of a declared action. System/user/
    assistant roles, model choice, tool implementation, sampling settings,
    streaming, progress reporting, operation-level timeouts, and provider-
    specific cancellation mechanisms are integration concerns. Those
    mechanisms MUST still observe the Gantry-owned cancellation token and the
    language-level cancellation state transitions required by Sections 10 and
    15.
11. A hook MUST return one of three host-level outcomes:
   `Completed(raw_output)`, `Declined(reason)`, or `Failed(message)`.
   `Completed` contains the integration's raw output as bytes; Gantry, not the hook,
   owns UTF-8 decoding, strict-JSON parsing, schema validation, and repair
   retries. Non-UTF-8 or malformed-JSON output is therefore a structured-output
   validation failure rather than a transport failure. A decline reason or
   failure message MUST be a nonempty sequence of Unicode scalar values; it is
   diagnostic integration data, not model output, and MUST follow the
   redaction rules in Section 12. `Declined` produces `None` only when the
   operation's expected type is `Option<T>`; for every other result type,
   including a control decision, it fails the current Gantry task. `Failed`
   likewise fails the current Gantry task and is not a structured-output
   validation failure. Item 18 defines how task failure propagates through
   foreground, attached, and detached work.
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
   resume. Root provenance is a separate protocol field and MUST NOT be
   represented as a `new` or `fork` creation directive. For an
   `embedder-supplied` root, integration preflight MUST resolve the supplied
   context before execution begins. For a `gantry-created` root, the
   integration MUST lazily establish one fresh empty conversational context
   for that ID before first using the root or a session derived from it, then
   resolve the same context for every later use in that execution. Establishing
   that integration-side context is not a Gantry operation and MUST NOT
   dispatch an `OperationHook` by itself.
   Every session created by `fork` or `new` MUST receive a fresh logical ID
   that is unique within the execution and stable across retry and resume.
   Before a hook dispatch, child-task submission, or other durable state may
   refer to that ID, Gantry MUST append and flush a session-state record that
   contains the ID, creation directive, creating construct's dynamic identity,
   enclosing session ID, and creator task ID. Replaying the same dynamic
   construct MUST recover that record and reuse its ID rather than allocate a
   second session. `inline` creates no session-state record because it reuses an
   existing ID. A `fork` request identifies that enclosing session as
   the context source the integration MUST copy. A `new` request includes the
   enclosing session only for causality and the integration MUST NOT inherit
   its conversational context. An `inline` request uses the enclosing session
   as its active session rather than creating another ID. A root operation has
   no enclosing session. These fields make the `new`, `fork`, and `inline`
   obligations implementable without relying on provider-specific hidden
   state.
   Entering a construct with an explicit session modifier establishes the
   active logical session for that construct's dynamic extent. Nested
   operations or constructs without their own session modifier reuse that
   active session as `inline`; they MUST NOT recursively reapply an enclosing
   `fork` or `new` directive. A nested explicit modifier establishes a new
   override under these same rules. Gantry MUST support a lexical session
   context of the form `session(<directive>) { ... }`. Entering that context
   applies its directive exactly once and makes the resulting logical session
   active for the complete block, including workflow calls and explicit model
   operations reached from it. This form exists so several visible `prompt`
   and `decide` operations can deliberately share one fresh or forked
   conversation without repeating operation-local modifiers. It MAY be used as
   a statement, a value-producing expression, or a decision-valued expression
   under the same block-result rules as `with`. Entering a `session(fork)` or
   `session(new)` block MUST allocate and journal its stable logical session ID
   before its body can dispatch a hook or spawn a child. Every operation in the
   block that does not carry a more local session modifier uses the block's
   active ID with an `inline` request directive. The integration learns the
   allocated session's original `fork` or `new` directive and enclosing ID from
   its journaled creation provenance and the task/session preflight contract;
   it MUST NOT create a second provider session for each inline request.
   For a loop, `fork` creates a separate child session for each prospective
   iteration under the condition/body rules in Section 9, while `new` creates
   one fresh session on loop entry and reuses it for every condition and body
   execution. Outside a loop or lexical session context, an explicit `fork` or
   `new` modifier creates one session on entry to the prompt, decision
   condition, or other construct carrying that modifier.
13. The integration MUST preserve the conversational continuity denoted by a
   reused logical session ID. Provider-specific session storage and mapping
   remain integration concerns. This obligation applies across interpreter
   process restart: before resuming a task, the integration MUST be able to
   resolve every journaled root, `new`, and `fork` session that unfinished work
   may reuse. Gantry MUST enumerate those required logical session IDs and
   their parent/provenance metadata to the embedding API before the first
   resumed hook dispatch. The integration MAY reattach existing provider
   sessions or reconstruct equivalent conversational state, but it MUST report
   an unresolved session before dispatch rather than silently creating an
   empty replacement. For a new execution, failure to resolve an embedder-
   supplied root session is an integration-preflight start failure. For resume,
   failure to resolve any required session is a nonterminal resume-start
   failure under item 17. Sessions used only by committed, completed operations
   need not be reattached unless unfinished work will reuse them.
14. External operations may have side effects. Gantry does not require retries
    to be idempotent or prevent duplicate external effects. Integrations SHOULD
    use the stable operation and dispatch identities to deduplicate action
    effects when the underlying capability permits it.
15. `prompt`, decision evaluation, and `action` invocation are the only v1
    source constructs that directly dispatch an `OperationHook`. Tools,
    approvals, shell commands, network calls, and other provider-internal work
    MAY still occur while an integration fulfills any hook, but such work is
    not a second Gantry operation. A source-visible harness capability MUST be
    declared and invoked as an `action`; Gantry observes its arguments,
    declared result contract, outcome, durability, retry, cancellation, and
    events through the same operation lifecycle as model operations.
    Actions are independent of agent and conversational-session selection.
    Their default structured-output retry limit is zero because redispatch can
    duplicate side effects; an action invocation MAY explicitly override that
    limit. Crash recovery retains the at-least-once redispatch semantics in
    Section 11.
16. Every dynamic operation identity MUST correspond to a logical execution
    path consisting of the execution ID, task path, workflow-call path, source
    operation location, branch arm, and enclosing loop iteration counters.
    Recursive calls and repeated calls from the same call site MUST receive
    distinct call-frame occurrences; distinct loop iterations and spawned
    task occurrences MUST likewise receive distinct identities. Validation
    retries and recovery of one indeterminate dispatch retain that identity.
    Implementations MAY encode or hash the path opaquely, but MUST journal
    enough of it to reconstruct the same identity on resume and MUST NOT reuse
    an identity for another dynamic invocation. The source operation location
    is the complete byte span defined in item 5. Call-frame, recursive-call,
    spawn, and repeated-call occurrences are zero-based counters assigned in
    deterministic encounter order within their immediate dynamic parent.
    Branch identity uses the zero-based arm position in its conditional chain;
    loop identity uses the zero-based body-execution and condition-evaluation
    positions required by Section 9. These counters are logical interpreter
    state and MUST be checkpointed or reconstructible from the durable prefix;
    wall-clock order and executor completion order MUST NOT influence them.
17. Hook outcomes and Gantry failures are separate domains. A hook outcome is
    exactly `Completed(raw_output)`, `Declined(reason)`, or `Failed(message)`.
    Before a new execution is accepted and its execution ID is returned to the
    embedder, structured start failures MUST at least distinguish syntax,
    analysis, entry-input validation, integration preflight, initial journal
    ownership, execution-start persistence, and required-event-delivery
    failure during pre-execution validation or analysis. Gantry MAY allocate a
    candidate execution ID while constructing the execution-start record, but
    that ID is not an accepted execution handle until the record is durable.

    Resume has a distinct pre-execution failure boundary even though the
    execution ID already exists. A resume-start failure MUST at least
    distinguish journal read or format failure, ownership acquisition failure,
    source or effective-configuration incompatibility, unresolved agent
    mapping, unresolved logical session, and unavailable required event sink.
    Such a failure means recovered interpretation never began: Gantry MUST NOT
    append an execution-state or terminal-execution record, consume a retry
    budget, or change the execution's durable terminal status. If journal
    ownership was acquired before the failure, Gantry MUST release it under
    Section 11. The embedder MAY correct the dependency or configuration and
    attempt resume again.

    Once a new execution has a durably flushed execution-start record, or a
    resume invocation has completed compatibility and dependency preflight and
    begins advancing recovered state, failures are runtime errors. Runtime
    errors MUST at least distinguish logical-session setup, hook creation,
    hook failure, decline of a required result, structured-output exhaustion,
    deterministic evaluation failure, executor failure, cancellation, journal
    failure, required-event-delivery failure, task/join failure, and internal
    invariant failure.
    Projection bounds failures are deterministic evaluation failures. Concrete
    Rust error types are implementation-defined, but embedders MUST be able to
    distinguish start, resume-start, and runtime categories without parsing
    display text.
18. Unless a more specific rule states otherwise, a fatal operation or
    interpreter error terminates the current Gantry task rather than silently
    terminating unrelated parallel work. Failure of the root foreground task
    fails the foreground execution and applies the attached-descendant
    cancellation rules in Section 10. Failure of an attached spawned task
    settles that child as failed and is observed through its owning `join` or
    `joinall()`; it does not immediately cancel siblings. Failure of a detached
    task follows the detached-task rules in Section 10 and cannot retroactively
    change an already returned foreground outcome. This propagation rule
    applies to hook failure, decline of a required result, structured-output
    exhaustion, deterministic evaluation failure, and other task-local runtime
    errors.

## 8. Structured Output and Validation

1. A successful operation-hook outcome provides raw bytes in
   `Completed(raw_output)`. Gantry MUST decode those bytes as UTF-8 and parse
   exactly one RFC 8259 JSON text, allowing only JSON whitespace after the
   value. Gantry owns this parsing step and MUST reject non-UTF-8, malformed,
   empty, or trailing-data output as structured-output validation failures.
   Duplicate member names in any JSON object MUST also be rejected as a
   structured-output validation failure rather than normalized by a JSON
   library's first-member or last-member behavior.
   JSON strings and object member names MUST decode to sequences of Unicode
   scalar values; valid escaped surrogate pairs are combined, and unpaired
   surrogates MUST be rejected.
   For any no-result operation, the expected schema is exactly the following schema
   object, and the parsed value MUST be JSON `null`:

   ```json
   {
     "$schema": "https://json-schema.org/draft/2020-12/schema",
     "type": "null"
   }
   ```

   This wire value confirms successful completion but does not create a Gantry
   value; `Declined` and `Failed` retain their ordinary fatal behavior for
   no-result operations. Including `$schema` resolves the no-result case under
   the same root-schema rule as every value-producing operation.
2. A `Bool` result is represented by a JSON Boolean. An `Int` result is a JSON
   integer in Gantry's exact range. A `Float` result is a JSON number that
   parses to a finite IEEE 754 binary64 value. Gantry MUST reject `NaN`,
   infinities, overflow to a non-finite value, and any JSON number outside the
   declared primitive contract. Gantry MUST normalize negative zero to
   positive zero before exposing or serializing a `Float`. A `String` result
   is represented by a JSON string. A struct result is a JSON object whose
   property names directly match its declared field names.
   Every decoded or computed String and every decoded or computed List MUST
   also satisfy the effective scalar-count and item-count resource limits in
   Section 11. This resource check is independent of JSON Schema shape
   validation and applies recursively before a value becomes observable.
   JSON decoding does not normalize String contents. Deterministic String
   methods operate on the decoded Unicode scalar sequence and serialize their
   results through the same ordinary JSON String representation; they add no
   provider-specific wire type or schema keyword.
   After source construction or hook-output normalization, a runtime struct
   contains every declared field. Whenever Gantry serializes that normalized
   struct, it MUST emit every field; an `Option<T>` field whose value is `None`
   is emitted as JSON `null`, and an applied default is emitted as its resolved
   value. Although hook output may omit an optional property, omission is not
   preserved as a distinct runtime state.
   Normalization is recursive and deterministic. Gantry MUST normalize nested
   primitive values, structs, enum payloads, result payloads, list items,
   tuple members, present option values, and decisions from outermost
   to innermost structure, preserving list and tuple order. It MUST apply each
   omitted optional field's declared default, or `None` when no default exists,
   at every nesting depth. A hook result becomes available to source execution
   only after the entire value has validated and normalized successfully; no
   partially normalized value may be observed.
3. A `List<T>` result is represented by a JSON array. Every array item MUST
   validate as `T`, and item order MUST be preserved. Gantry MUST derive an
   array schema with the schema for `T` as its `items` schema.
4. A `Tuple<T1, T2, ..., Tn>` result is represented by a JSON array with
   exactly `n` items. Each item MUST validate against its corresponding
   positional member type, and item order MUST be preserved. Gantry MUST
   derive a fixed-length JSON Schema array using `prefixItems`, `items: false`,
   and `minItems` and `maxItems` both equal to `n`.
5. `Some(value)` is represented by the JSON encoding of `value`, and `None` is
   represented by JSON `null`. An `Option<T>` struct property MAY also be
   omitted. Omission assigns the field's declared literal default when one
   exists and otherwise normalizes to `None`; explicit `null` always normalizes
   to `None`.
   Whenever Gantry serializes a first-class runtime value as JSON for a hook
   argument, prompt interpolation of a non-`String` value, an entry result, or
   another language-defined boundary, it MUST use the RFC 8785 JSON
   Canonicalization Scheme. Raw entry input and raw hook output are accepted in
   any otherwise valid RFC 8259 spelling and are canonicalized only after
   successful parsing, validation, and normalization. Plain `String`
   interpolation remains the deliberate exception because it inserts string
   contents rather than a JSON value.

   A declared enum uses a strict tagged JSON object. A unit variant is
   `{"variant":"NAME"}`. A payload variant is
   `{"variant":"NAME","value":PAYLOAD}`. `variant` and `value` are the
   literal protocol property names; unit variants MUST reject `value`, payload
   variants MUST require it, and every variant object MUST reject additional
   properties. `Result<T, E>` uses the same representation with variant names
   `Ok` and `Err`, each requiring `value` of type `T` or `E`, respectively.
   `Decision` uses the exact `decision` and nonempty `rationale` object shape
   in Section 9. Decision provenance is interpreter metadata and is not part
   of that JSON value.
6. Gantry MUST derive JSON Schema Draft 2020-12 from declared output types
   during semantic analysis and MUST independently validate every successful
   hook result against that schema. Every schema root MUST identify that
   dialect with its `$schema` URI. Recursive types MUST use `$defs` and `$ref`.
   `Option<T>` MUST be represented by a schema accepting exactly `null` or the
   schema for `T`. Declared enums, results, and decisions MUST use the strict
   tagged and decision schemas defined in this section and Section 9.
   Schema generation is part of the portable hook protocol, not an
   implementation formatting choice. Gantry MUST serialize every generated
   schema with RFC 8785 JSON canonicalization before placing it in a hook,
   journal, or protected event payload. A protocol schema reference MUST be
   the lowercase hexadecimal SHA-256 digest of those canonical bytes.
   Implementations MUST derive equivalent types with the same structural
   schema rules: `Bool` uses `{"type":"boolean"}`; `Int` uses an integer
   schema with Gantry's inclusive exact bounds; `Float` uses a number schema
   with finite binary64 bounds; `String` uses `{"type":"string"}`; `List<T>` uses an array
   with the schema for `T` in `items`; tuples use the exact fixed-array form in
   item 4; options use `anyOf` with `{"type":"null"}` first and the schema
   for `T` second; results and enums use strict `oneOf` branches; decisions use
   the exact schema in Section 9; and structs use the object rules in item 7. A struct's
   `properties` object is keyed by exact field name, while its `required` array
   lists required fields in declaration order. RFC 8785 canonicalization, not
   source declaration order, determines serialized JSON object-member order.
   More precisely, schema generation recursively constructs one schema node
   for a type. `Bool` produces exactly `{"type":"boolean"}`. `Int` produces
   exactly
   `{"type":"integer","minimum":-9007199254740991,"maximum":9007199254740991}`.
   `Float` produces exactly
   `{"type":"number","minimum":-1.7976931348623157e308,"maximum":1.7976931348623157e308}`.
   These `Float` schema bounds are necessary but not sufficient: Gantry MUST
   additionally perform the finite-binary64 parsing and normalization checks
   in item 2. `String` produces exactly `{"type":"string"}`.
   `List<T>` produces exactly `{"type":"array","items":NODE(T)}`.
   `Tuple<T1,...,Tn>` produces exactly an object whose `type` is `array`, whose
   `prefixItems` is `[NODE(T1),...,NODE(Tn)]`, whose `items` is `false`, and
   whose `minItems` and `maxItems` are both `n`. `Option<T>` produces exactly
   `{"anyOf":[{"type":"null"},NODE(T)]}`, except for the field-level
   `default` annotation permitted below. Define `TAG(NAME)` as exactly
   `{"type":"string","const":NAME}`. Define `PAYLOAD(NAME,T)` as exactly
   `{"type":"object","properties":{"variant":TAG(NAME),"value":NODE(T)},
   "required":["variant","value"],"additionalProperties":false}` and
   `UNIT(NAME)` as exactly
   `{"type":"object","properties":{"variant":TAG(NAME)},
   "required":["variant"],"additionalProperties":false}`. These are schema
   construction formulas; `NAME` is replaced by its JSON string and line
   breaks shown here are not part of canonical serialization.
   `Result<T,E>` produces exactly
   `{"oneOf":[PAYLOAD("Ok",T),PAYLOAD("Err",E)]}`. A declared enum
   definition produces exactly one `oneOf` array whose branches follow source
   variant order, using `UNIT(NAME)` for a unit variant and `PAYLOAD(NAME,T)`
   for a payload variant.
   `Decision` produces exactly the schema in Section 9 without its root
   `$schema` member when nested as `NODE(Decision)`. A declared struct or enum
   type produces exactly `{"$ref":"#/$defs/KEY"}`, where `KEY` is that
   declared type's definition
   key. `NODE(T)` denotes recursive application of these rules; it is notation
   in this specification, not a protocol member.
   Every reachable declared struct or enum MUST have exactly one `$defs`
   entry. Its
   definition key is the lowercase hexadecimal SHA-256 digest of the UTF-8
   canonical type descriptor from Section 5, and every occurrence of that
   declared type uses a local `$ref` to that entry. RFC 8785 canonicalization
   determines `$defs` object-member order from those definition keys. The root
   adds `$schema`, the complete reachable `$defs` object when nonempty, and
   either its own non-declared-type schema keywords or a `$ref` for a declared
   struct or enum result.
   No implementation-specific title, description, identifier, or annotation
   may be added to the expected protocol schema. The sole annotations are the
   field defaults required by item 7. These rules make the expected schema and
   its identity stable across conforming Gantry implementations.
7. Every struct schema MUST set `additionalProperties` to `false`. Declared
   fields are required unless represented by `Option<T>`. Literal field
   defaults affect source construction; they do not make a non-optional field
   optional in an operation result. A schema for an optional field with a declared
   default MUST include that value through JSON Schema's `default` annotation.
   The `default` member MUST be a direct member of that field's property schema,
   alongside the `anyOf` member that represents `Option<T>`; it MUST NOT be
   placed inside either the `null` or `T` branch. A non-optional field default
   MUST NOT produce a schema annotation because that field remains required in
   operation output. These placement rules are part of canonical schema generation
   and therefore of the schema digest.
   Each struct definition in `$defs` MUST contain exactly `type`, `properties`,
   `required`, and `additionalProperties`. `type` is `object`;
   `additionalProperties` is `false`; `properties` contains every declared
   field mapped to its recursively generated schema node; and `required`
   contains every non-`Option<T>` field name in source declaration order. An
   empty struct therefore has an empty `properties` object and empty
   `required` array. An optional field's property remains present in
   `properties` even though its name is absent from `required`. When that field
   has a source default, Gantry adds the `default` member to the property schema
   object after generating its `anyOf`; no other schema node gains a source
   default annotation. These exact members, together with the root and `$defs`
   assembly in item 6, are the complete portable generated-schema shape.
   Gantry MUST still perform the normalization in item 2 because the annotation
   does not itself insert a value during JSON Schema validation.
8. v1 validation MUST check JSON shape and types, including enum and result
   discriminators, closed variant sets, fixed tuple arity, and the nonempty
   `Decision` rationale. Additional constraints such as arbitrary string
   length, regular-expression patterns, and semantic validity are conveyed
   through operation guidance rather than enforced by Gantry.
9. UTF-8 decoding failures, malformed JSON, and schema-invalid output MUST be
   returned to the integration as validation guidance and retried up to the
   configured retry limit. A retry request MUST include the preceding
   validation errors but MUST NOT return the preceding raw output to the hook.
   A validation retry is another physical dispatch of the same logical
   operation, not a reevaluation of the source expression. Gantry MUST reuse
   the selected agent, logical session, authored template, interpolated
   operation-specific request body, expected type and schema, base guidance,
   source location, and ordered execution context from the initial dispatch.
   For a prompt or decision this includes agent, session, template,
   interpolation arguments, and named inputs; for an action it includes its
   canonical path, signature, mapping revision, and typed arguments. Gantry
   MUST NOT reevaluate any captured input expression or observe intervening
   source state. Only the dispatch identity, validation-attempt
   number, applicable recovery-dispatch number, preceding validation errors,
   and repair-specific rendering of those errors may differ. This rule keeps
   retries understandable as repairs of one visible operation rather than
   hidden additional program evaluations.
10. The retry limit is configured per interpreter and MAY be overridden per
   operation. It counts retries after the initial attempt; zero permits exactly
   one attempt. The v1 interpreter default is two retries after the initial
   attempt for `prompt` and `decide`, and zero retries for `action`. An explicit
   operation-local `retry_limit` overrides the applicable default. Retry
   backoff MUST be configurable. The v1 default uses full-jitter
   exponential backoff: for the one-based retry number `r`, the delay ceiling
   is `min(100 ms * 2^(r - 1), 2 s)`, and the selected delay is sampled
   uniformly from the inclusive range of whole microseconds from zero through
   that ceiling. This formula uses saturating arithmetic: once doubling the
   initial delay would meet or exceed the cap, the ceiling is the cap for that
   and every later retry. An implementation MUST NOT construct an unbounded
   power or overflow an integer when `retry_limit` is large. An implementation
   MUST record the selected delay in the validation-attempt record before
   sleeping. If execution is interrupted before the corresponding retry
   dispatch is durably recorded, resume MUST wait the complete recorded delay
   again; it MUST NOT sample another delay.
   The effective retry limit, initial delay, cap, and jitter mode are bound to
   resumable execution as specified in Section 11. A configured policy MAY
   choose no jitter, but it MUST still identify its initial delay, cap, and
   jitter mode explicitly.
11. When retries are exhausted, the operation and its current Gantry task MUST
    fail under Section 7. Gantry has no language-level error recovery within
    that task in v1; parallel failure observation and propagation follow
    Section 10.
12. Transport failures and their retry policy are integration concerns, not
   Gantry structured-output retries.
13. Source snippets MAY be included in validation diagnostics only when the
    embedder's diagnostic-disclosure policy explicitly permits source text for
    that consumer. The default policy MUST report source spans without copying
    source snippets. Raw agent output MUST NOT be included in validation
    diagnostics under any disclosure policy.

## 9. Control Flow

1. Gantry MUST support `if`, `else if`, and `else`. Each `if` or `else if`
   condition MUST have type `Bool` or `Decision`. A `Decision` condition uses
   its sealed `decision` field. A direct model judgment uses the
   visually distinct `decide` expression; an ordinary unannotated `prompt`
   always remains a no-result prompt. A condition MAY reuse a bound
   `Decision`, call a decision workflow, or evaluate a new `decide`. Reusing a
   decision or calling a workflow does not itself add a hook invocation,
   although evaluating the workflow body may reach explicit operations.
   There is no truthiness: every other value type is invalid as a condition.
2. A conditional decision MUST return this strict JSON shape, with no
   additional properties:

   ```json
   {
     "decision": true,
     "rationale": "A nonempty explanation"
   }
   ```

   `decision` MUST be a JSON Boolean and `rationale` MUST be a nonempty JSON
   string. The generated decision schema MUST be the following JSON Schema
   Draft 2020-12 schema:

   ```json
   {
     "$schema": "https://json-schema.org/draft/2020-12/schema",
     "type": "object",
     "properties": {
       "decision": { "type": "boolean" },
       "rationale": { "type": "string", "minLength": 1 }
     },
     "required": ["decision", "rationale"],
     "additionalProperties": false
   }
   ```

   Gantry uses `decision` to select control flow and retains the rationale and
   operation provenance for observability. The complete object is the sealed
   first-class `Decision` value defined in Section 5. Its read-only
   `.decision` and `.rationale` projections yield `Bool` and `String`.
3. Each `else if` evaluates its own condition. A newly evaluated `decide`
   expression performs a separate decision operation; a reused `Decision` or
   `Bool` expression performs no new dispatch. A later model-operation hook
   request MUST include the outcomes of preceding arms in the same conditional
   chain through the ordered execution-context vector. Decision entries carry
   their rationales, while structural entries identify their condition kind
   and outcome without fabricating a rationale.
4. Gantry MUST support `while` as a pre-test loop and `until` as a post-test
   loop. The post-test syntax places the body before its condition:
   `until(...) { ... } when decide "...";`. This ordering is normative and
   makes execution order visible in source. `until` MUST execute its body once
   before its first condition. Each iteration reevaluates its condition
   expression. A direct `decide` therefore dispatches on every evaluation;
   reusing an already bound `Decision` or evaluating a `Bool` expression
   performs no new dispatch.
5. The general loop form is `loop(session = inline, limit = 0) { ... }`.
   `loop { ... }` is equivalent to the form with all defaults. `while`
   places parenthesized loop modifiers before its condition expression, as
   in `while(session = fork, limit = 10) decide(retry_limit = 2) "..." { ... }`.
   `until` places the same loop modifiers before its body and operation
   modifiers on the explicit `decide` expression after `when`.
   `loop`, `while`, and `until` accept `session` and `limit`. A structured-
   output retry override MUST appear on the explicit `decide` operation it
   configures; a loop whose condition calls a decision workflow uses the
   modifiers written on the `decide` operations in that workflow or the
   interpreter default. Agent selection is inherited from a lexical `with`
   context rather than specified as a loop modifier.
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
   the body. After a `loop` or `while` body completes normally or through
   `continue`, Gantry checks the positive `limit` before starting another body
   execution or `while` pre-test. Reaching the limit completes that loop
   without another decision call. After an `until` body completes normally or
   through `continue`, Gantry MUST always evaluate that body's post-test. A
   true condition completes the loop. After a false condition, Gantry checks the
   positive `limit`; reaching it completes the loop normally, and otherwise
   the next body execution begins. Thus every entered `until` body has exactly
   one following post-test unless it exits through `break`, `return`, failure,
   or cancellation. `break` completes any loop immediately without another
   decision call.
8. Gantry MUST support deterministic routing with `Bool` expressions, `if let`,
   and `match`. These constructs MUST NOT invoke an operation hook unless
   evaluation reaches an explicitly written workflow containing an operation;
   primitive operators themselves never dispatch.
   An `if let PATTERN = EXPRESSION` evaluates its scrutinee exactly once. A
   successful match enters the first arm with fresh immutable bindings; a
   failed match enters `else` when present and otherwise continues normally.
   Pattern bindings exist only in the selected arm. An `if let` MAY omit
   `else`.

   A `match` evaluates its scrutinee exactly once and tests arms in source
   order, selecting the first matching arm. Match patterns use Section 5.
   Analysis MUST reject duplicate or unreachable arms and MUST prove exhaustive
   coverage of `Option<T>`, `Result<T,E>`, and every declared enum unless a
   final `_` or irrefutable identifier arm covers the remainder. Tuple-pattern
   coverage is the product of its member coverage. A value-producing `match`
   requires every reachable arm to yield exactly one identical static type;
   a statement `match` requires statement-only arms. Pattern bindings are deep
   copies scoped to their arm.

   `==` and `!=` are ordinary `Bool`-producing expressions. Both operands MUST
   have exactly the same equatable first-class type and are evaluated once from
   left to right. Equality is exact deep structural equality over normalized
   values: Boolean and integer values compare exactly; floats compare their
   normalized binary64 values; strings compare Unicode scalar sequences;
   structs compare fields in declaration order; tagged values compare variant
   and payload; options compare presence and contained value; and lists and
   tuples compare length or arity and members in order. `Decision`, and every
   aggregate transitively containing `Decision`, is non-equatable. `for`
   remains excluded.
9. Model-produced decisions MUST use the same schema-validation and retry
   policy as other structured operation results. Deterministic `Bool`
   conditions do not have a schema, retry budget, rationale, or hook context
   entry unless their evaluation explicitly performs an operation.
10. Gantry imposes no mandatory loop, cost, or operation-call limit. Integrations
    MAY impose their own limits, except that such policy does not alter the
    language meaning of `limit = 0`. Unlimited language execution does not
    mean uninterruptible execution: every loop transition and deterministic
    transition quantum remains a cancellation and executor-yield safe point
    under Section 3. Cancellation or configured resource exhaustion terminates
    the affected task under the ordinary runtime-error rules; it does not make
    an unlimited loop complete normally.
11. A direct model condition uses `if decide "..." { ... }`. Gantry MUST
    also support declarations of the form
    `decision is_complete(report: Report) { ... }`. Each reachable normal
    completion of a decision workflow MUST yield a trailing `decide`
    expression or another `Decision` expression;
    alternatively, every reachable path MAY exit through an explicit valid
    decision `return`. This permits a fully returning `if`/`else` decision
    workflow without an artificial unreachable tail. The result schema is the
    decision schema in item 2. A decision workflow MAY contain
    multiple ordinary prompts, nested decisions, and other executable blocks.
    `return` MAY exit it early with any `Decision` expression. Each completed
    evaluation MUST ultimately obtain its value from a previously evaluated or
    newly dispatched decision operation; source cannot construct one.
    Decision workflows are free module items in v1; decision methods remain
    excluded. Their results may be bound, passed, returned by ordinary
    workflows, stored in aggregates, interpolated as strict JSON, or consumed
    by `if`, `else if`, `while`, and `until`. Discarding a `Decision` as an
    expression statement is permitted for its observable rationale, although
    authors SHOULD bind or consume it when practical.
    Semantic analysis MUST prove that every reachable
    normal completion of a decision workflow yields `Decision` and
    that every reachable explicit `return` in that workflow returns
    `Decision`. A no-result `return;`, another value type, or fallthrough
    from a decision workflow is an analysis error.
12. Static control-flow analysis MUST treat every model-produced decision as capable of
    producing either `true` or `false`, independently of its prompt text,
    previous outcomes, rationale, selected agent, or session. Analysis MUST
    inspect both outcomes of every model-controlled reachable `if`, `else if`,
    `while`, and `until`; it MUST NOT assume that a model will make one branch
    unreachable. Static analysis MAY use compile-time constant `Bool`
    expressions to establish reachability, but MUST otherwise inspect all
    possible outcomes. A `while` has a possible zero-body normal path unless
    its condition is statically `true`. An `until` has
    at least one body execution before a possible normal exit. A positive loop
    limit contributes the normal limit-exhaustion path defined in item 7,
    whereas `loop(limit = 0)` has no implicit normal exit. A reachable `break`
    still contributes a normal exit path from its target loop. Potential hook
    failure, decline, cancellation, or retry exhaustion is an abnormal runtime
    outcome and MUST NOT be used to satisfy definite-return or task-handle
    consumption analysis. These conservative rules apply uniformly to the
    definite-result requirements in Sections 6 and 10 and to linear task-handle
    analysis in Section 10.

## 10. Parallel Execution

1. Gantry MUST support annotated spawn declarations of the form
   `spawn <name> -> <type> { ... }`, joins of the form
   `join(<task-name>, ...)`, `joinall()`, and explicit detachment of the form
   `detach(<task-name>);`.
2. A spawn creates an arbitrary child program block running in parallel. The
   spawn name declares a new, lexically scoped, unique, interpreter-owned task
   handle. A task handle is not a `String`, is not agent-visible structured
   data, and is not otherwise a first-class runtime value. The Gantry task that
   executes the `spawn` exclusively owns the new handle. A spawned child MUST
   NOT reference, join, detach, or otherwise consume a task handle declared by
   its parent or another task, even when that handle's declaration is lexically
   visible. A child may operate only on handles created by spawns that the child
   itself executes. This ownership rule prevents cross-task races over linear
   handles and keeps every join or detach visibly controlled by the task that
   created the work. Before submitting the child to the executor or invoking
   its `HookFactory`, Gantry MUST append and flush a task-state record containing
   the child's stable task identity, parent identity, source spawn occurrence,
   copied captures, inherited agent selection, and forked-session identity. The
   record MUST also contain the immutable structural-context ancestry captured
   for the child under Section 7, including its appended `spawn-frame`. The
   handle becomes visible to the parent only after that record is durable. This
   ordering prevents a child from performing model-backed work that recovery
   cannot identify. If executor submission then fails, the child MUST settle as
   failed with an executor error; Gantry MUST append and flush that settlement
   before the parent can observe it. The handle remains attached and visible,
   and its owner MUST still consume it through `join`, `joinall()`, or `detach`
   on every normal path. Recovery MUST reuse the durable failed settlement and
   MUST NOT submit a second child for the same spawn occurrence. If Gantry
   cannot durably record the submission failure, the execution instead fails
   with the journal error under Section 11.
3. A spawned block captures outer variables by copy and MUST NOT mutate outer
   variables. The captured values form a deep, isolated snapshot taken when
   `spawn` executes; “snapshot” describes isolation, not universal read-only
   access. Each captured binding preserves its declared mutability: an
   immutable capture cannot be assigned, while a `mut` capture may be changed
   inside the child without affecting the parent. A child MAY initialize a new
   mutable local binding from any captured value. Each spawned task MUST begin
   with a forked child of the spawning task's active logical session. That
   child session is the spawned task's enclosing session, so an `inline`
   operation in the child reuses it. Sibling tasks MUST receive distinct child
   sessions. An explicit session directive inside the child MAY override this
   inherited session under Section 7.
   Semantic analysis MUST derive the capture set from every parameter, method
   receiver, or local binding referenced by the spawned block outside
   declarations local to that block. A captured `self` is the same deep,
   isolated receiver copy visible to the enclosing method and preserves
   whether that receiver was declared `self` or `mut self`; mutations through
   a captured `mut self` remain child-local. Module items and agent names are
   resolved package-wide and are not captures; task handles owned by another
   task are prohibited by item 2.
   Gantry MUST snapshot every captured value and its binding mutability before
   the child becomes runnable, and the durable task-state record in item 2 MUST
   contain that complete snapshot. Evaluation of a `spawn` therefore cannot
   observe a mixture of parent values from before and after child submission.
4. A spawned block MUST declare the type of its yielded value with `-> T`, or
   declare `-> None` when it yields no value. Every reachable normal completion
   of a value-yielding block MUST produce exactly `T` through its trailing
   expression or a task-local `return`. A no-result block MAY fall through or
   use `return;` but MUST NOT return a value. `spawn` declares the named handle
   but does not itself yield the handle as a value. A spawn boundary is also a
   control-transfer boundary: a `return` whose nearest return target is the
   spawned block completes only that child task. `break` or `continue` inside a
   spawned block MUST NOT target a loop outside that block. Transfers wholly
   contained in a workflow or loop entered within the child remain valid.
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
   non-`None` result types that are not all exactly equal, it yields
   `Tuple<T1, T2, ..., Tn>`, whose positional types and values follow argument
   order. When every named task has no result, the join is a waiting statement
   with no source value. Mixing value-producing and no-result tasks in one
   named join is an analysis error; Gantry MUST NOT silently discard selected
   values merely because another named task has no result. Every named join
   waits until every named task settles even after a failure. Before waiting,
   Gantry MUST append and flush one task-state record that identifies
   the join form, source location, named handles in argument order, and their
   transition from attached to consumed-by-join. Only then are the handles
   consumed. This transition includes handles for successful tasks in a join
   where another task fails. After settlement, Gantry MUST append and flush the
   ordered result, successful no-result settlement, or aggregate failure before
   returning it to source execution.
   Consuming a handle for a join changes its source-level ownership state but
   does not detach the child: until it settles, the child remains an attached
   descendant for cancellation and cleanup under items 10 and 14.
   Failures abort the current Gantry task as one aggregate task/join error
   ordered by join argument, never by completion time. A failed single-task
   join likewise consumes its handle durably and fails the current Gantry task
   with a task/join error. Propagation beyond that task follows Section 7 rather
   than implicitly aborting unrelated parallel work.
6. `joinall()` is the scope-oriented form for joining every unconsumed, attached
   task handle that is owned by the current Gantry task, declared directly in
   the current lexical scope, and definitely available at the `joinall()`
   expression's program point. It excludes later declarations, tasks declared
   in nested scopes, tasks owned by another Gantry task, and tasks explicitly
   detached before the join. It consumes all included handles, waits until all
   included tasks have settled, and yields one included task's declared result
   type when exactly one task is included and that task has a non-`None`
   result. With two or more included tasks, every task MUST either have a
   non-`None` result or every task MUST have no result. When all have non-`None`
   results, `joinall()` yields an ordered `List<T>` in task declaration order
   if the result types are exactly equal, and otherwise yields a positional
   tuple in task declaration order. When every included task has no result,
   `joinall()` is a waiting statement with no result. Mixing value-producing
   and no-result tasks in one `joinall()` is an analysis error; Gantry MUST NOT
   silently discard the value-producing results merely because another task
   has no result. With zero included tasks, `joinall()` is a no-result no-op.
   Semantic analysis MUST
   determine the included handle set and resulting type at that program point;
   a no-result `joinall()` cannot be bound or used as a trailing expression.
   `joinall()` MUST NOT stop waiting merely because one task fails.
   After all tasks settle, one or more failures MUST fail the current Gantry
   task with one aggregate task/join error. That error MUST report failed tasks
   in source declaration order, not completion order. Propagation beyond the
   current task follows Section 7. At a `joinall()`, every task
   handle declared directly in that scope MUST have one definite ownership
   state on all incoming control-flow paths. A handle that is consumed or
   detached on only some incoming paths is an analysis error rather than a
   conditionally included `joinall()` member.
   Before waiting, a nonempty `joinall()` MUST append and flush the same
   consumed-by-join task-state transition required for a named join, listing
   included handles in declaration order. Its ordered result or aggregate
   failure MUST likewise be appended and flushed before source execution
   consumes it. A zero-task `joinall()` requires no ownership record.
7. A child failure does not immediately cancel siblings. A named child's
   failure is deferred until `join`; a scoped failure is deferred until
   `joinall()`.
8. `detach(task)` consumes one attached task handle and transfers foreground
   ownership to the interpreter, acting on behalf of the task's originating
   execution and journal, without waiting for it. Detaching an
   already consumed handle is an analysis error. An attached, unconsumed task
   at lexical scope exit is an analysis error; v1 never detaches work
   implicitly. Detached tasks and nested spawns are permitted, and a top-level
   execution MAY report foreground success while detached tasks continue.
   Requiring an explicit `detach` keeps background execution visible to humans,
   agents, analysis, and recovery tooling.
   Before releasing the child from parent cancellation constraints or allowing
   the enclosing scope to continue, Gantry MUST append and flush a task-state
   record that identifies the source `detach`, child task, previous owner, and
   transition to interpreter-owned detached work. Failure to make that transfer
   durable is a journal failure; the task remains attached for cancellation and
   cleanup purposes.
   Detaching a value-producing task intentionally discards its eventual value;
   completion, failure, and observability remain governed by items 9 and 10.
   Semantic analysis MUST model each handle on every reachable path as exactly
   one of attached-and-unconsumed, consumed-by-join, or consumed-by-detach. At
   a control-flow merge, attached-and-unconsumed on every incoming path keeps
   the handle available. Consumed on every incoming path makes the handle
   unavailable after the merge; those paths MAY differ between
   consumed-by-join and consumed-by-detach because both visibly discharge the
   source-level ownership obligation. A merge between an attached path and any
   consumed path is an analysis error. The path-specific durable ownership
   transition remains join or detach and MUST NOT be collapsed in journals or
   events. A `return`, `break`, or `continue` that exits a handle's lexical
   scope is valid only when the handle is consumed on that path. Runtime
   failure, cancellation, shutdown, and unclean interpreter drop are exempt because
   items 9 through 13 define their cleanup and ownership consequences. These
   linear-state rules apply even when the consuming operation appears inside a
   nested `with` or `session` block.
9. A detached-task failure MUST be journaled and emitted as a failure event. It
   MUST NOT abort foreground execution or change a top-level success,
   regardless of whether it settles before or after that success is returned.
   A detached task cannot subsequently be joined because `detach` consumes its
   handle. These rules make explicit detachment a deliberate transfer of both
   lifetime and failure ownership to the interpreter instance.
   A detached-task failure MUST NOT cancel sibling detached tasks. Terminal
   execution state is determined after all detached work settles. An
   execution-wide runtime error, whether it occurs before or after foreground
   completion, is the primary terminal category and includes detached failures
   as secondary details. If more than one execution-wide runtime error races,
   the first one in durable journal-sequence order is primary and later errors
   are secondary. Otherwise, one or more detached failures produce the
   `detached-task failure` terminal category; otherwise, a cancellation
   produces the `cancellation` category; and only then is the terminal category
   `success`. Multiple detached failures MUST be reported in stable task-path
   order, using source spawn location and dynamic spawn occurrence rather than
   completion time.
10. Parent timeout and cancellation constraints apply while a child remains
   attached and propagate through its attached descendants. Detachment releases
   the task from those parent constraints. Integration-specific operation
   timeouts and provider-specific cancellation policy MAY still apply, but
   they MUST NOT override Gantry's durable task-ownership or cancellation state.
   An integration MAY stop provider work earlier than Gantry's outer task
   policy requires; it MUST report that outcome through the hook contract and
   MUST still honor a signalled Gantry cancellation token.
    If a parent task aborts for any runtime error, Gantry MUST signal
    cancellation to all of its attached descendants, wait for them during the
    configured post-cancellation drain period, and abort executor tasks that do
    not settle in that period before reporting the parent failure. Detached
    tasks are not cancelled by that parent failure. Secondary attached-task
    failures MUST be recorded in the parent failure details in source task
    order but MUST NOT replace the initiating runtime-error category.
    Once cancellation is signalled to a task, Gantry MUST dispatch no new
    operation for that task. If an already-dispatched hook returns during the
    cancellation drain, Gantry MUST append and flush the outcome for audit but
    mark it cancelled and non-consumable; it MUST NOT validate-retry, assign,
    branch on, return, or reuse that outcome to continue the cancelled task.
    A durably cancelled task is terminal and MUST NOT later be resumed as an
    interrupted task. If executor abortion prevents a hook outcome from being
    observed, Gantry MUST durably record cancellation of the indeterminate
    dispatch rather than redispatch it on resume. These rules make cancellation
    win deterministically over a racing hook completion.
    The append-and-flush requirements in this paragraph apply only while the
    journal remains usable. When journal failure is the initiating error,
    Gantry MUST NOT attempt additional journal appends through the failed
    storage path. It MUST discard late in-process hook outcomes after making a
    best effort to stop the work, MUST NOT consume them, and MUST NOT claim
    that the affected tasks are durably cancelled. A later owner recovers only
    the authoritative durable prefix and may consequently redispatch an
    invocation that remained indeterminate there, as required by Section 11.
11. Gantry MUST schedule spawned blocks through the executor supplied by the
    embedding application. The integration determines operation-level resource
    limits and queueing policy.
12. The embedding API MUST provide a terminal asynchronous shutdown operation.
    The embedder MUST configure a finite graceful-shutdown timeout; indefinite
    shutdown is not the v1 default. Shutdown MUST reject new executions and
    allow every interpreter-owned foreground execution and detached task to
    finish naturally until the timeout expires. It MUST then signal
    cancellation to all remaining work, abort tasks that do not finish within
    a bounded drain period, flush journal and required event state, and return
    a shutdown report covering every execution and detached task that was
    active when shutdown began. After that report's task and journal content is
    fixed, and while the executor adapter and event sinks remain available,
    Gantry MUST create exactly one final interpreter-wide `shutdown` event and
    satisfy the required-sink barrier in Section 12. Before shutdown returns,
    every finite best-effort delivery obligation already owned by the
    interpreter, including obligations for that final event, MUST also reach
    success or terminal exhaustion under its captured policy. Journaled
    settlements MUST be durable, every execution-journal owner MUST then be
    released, and no delivery worker may remain dependent on the terminal
    interpreter. A delivery-barrier failure or best-effort exhaustion summary
    is reported separately from the task and execution outcomes already fixed
    in the shutdown report. An interpreter cannot be reused after shutdown
    begins. Embedders MUST complete shutdown before dropping the interpreter.
13. Because Rust destruction cannot await, dropping an interpreter without
    shutdown MUST reject new work, signal cancellation, request abortion of
    every remaining owned executor task, and relinquish its executor handles
    without blocking. When configured, it SHOULD invoke the non-durable
    emergency diagnostic callback defined in Section 12; that callback is not
    a Gantry event and MUST NOT use `EventSink` delivery. The drop path cannot
    guarantee that integrations observed cancellation before handles were
    relinquished. It MUST NOT create or retry standard event delivery or claim
    that foreground or detached work completed. Unless a cancellation or
    completion was already durably recorded, this path is an unclean
    interruption rather than a durable cancellation: a later resume MUST
    follow the authoritative journal prefix and MAY recover tasks or redispatch
    indeterminate operations under Section 11.
14. The embedding application MUST be able to request cancellation of one
    execution without shutting down the interpreter. Execution cancellation
    targets the foreground task plus every attached and detached descendant
    owned by that execution. When the journal remains usable, Gantry MUST
    append and flush the cancellation request before signalling task tokens,
    reject new task and hook dispatch for the execution, apply the configured
    post-cancellation drain and abortion behavior from item 10, and durably
    record terminal cancellation before reporting completion. Repeating a
    cancellation request is idempotent; requesting cancellation of an already
    terminal execution returns its existing terminal state without changing
    it. A journal failure while recording cancellation takes precedence and is
    reported under Section 11. Cancellation of one execution MUST NOT cancel
    unrelated executions owned by the same interpreter.

## 11. Journal and Resume Semantics

1. Gantry MUST durably journal committed operation results, validation attempt
   counts, interpreter call frames, scopes, instruction positions, loop state,
   lexical session-context identities and lifetimes, task relationships, and
   values needed to resume execution. Journaled values MUST retain the
   interpreter-only optional-decline provenance required by Section 7 so a
   resumed operation receives the same decline context as uninterrupted
   execution. Gantry MAY
   replay deterministic interpreter steps after the latest durable checkpoint,
   but such replay MUST reuse committed hook outcomes and reconstruct the same
   dynamic operation and task identities.
2. Gantry MUST expose a journal-storage trait through which an integration
   provides durable storage. The trait MUST expose durable record reading,
   exclusive owner acquisition and release, plus atomic append and flush
   operations. Append and flush are the only record-mutation primitives;
   ownership operations change fencing state rather than journal records.
   Gantry defines the transaction and commit boundaries built from these
   primitives, and v1 requires no storage-level update, delete, or general
   transaction operation. Each append MUST return a stable record ID and a
   sequence number from one contiguous sequence within that journal. The first
   record has sequence number 1, and each successful append is linearizable and
   receives exactly the preceding sequence number plus one, including when
   concurrent Gantry tasks append to the same journal. `flush(sequence)` MUST establish
   that every successfully appended record through that sequence is durable
   before it returns.
   A durable read MUST identify a journal and return its authoritative flushed
   prefix in strictly increasing sequence order, optionally beginning after a
   caller-supplied sequence number. It MUST also report the greatest sequence
   known durable. Records physically present beyond that durability watermark
   MUST NOT be returned as committed state or used during resume. A duplicate
   sequence, a gap within the returned durable prefix, a changed record for an
   already observed sequence, or a record whose envelope identifies another
   journal is a journal failure. These read semantics are required for resume;
   they do not add another storage mutation primitive. Before appending after
   recovery, storage MUST discard or otherwise make unreachable every
   physically present record beyond the durability watermark, and the next
   append MUST receive the watermark plus one. This reconciliation is an
   internal storage-recovery obligation completed before a new owner receives
   its fencing token; it is not an additional journal-record mutation exposed
   through `JournalStorage`. A store that cannot reconcile its non-durable tail
   MUST fail owner acquisition rather than expose an ambiguous prefix. A
   journal failure aborts the affected in-process execution or resume run:
   Gantry MUST reject further
   state transitions, signal
   cancellation to all foreground, attached, and detached tasks owned by that
   execution, apply the configured cancellation drain, and return the journal
   failure directly to the embedder because durability can no longer be
   assumed. Gantry MUST NOT claim a new durable terminal state after storage
   has failed. A later owner MAY resume from the last authoritative durable
   prefix after storage recovery and fencing, so operations whose outcomes did
   not reach that prefix remain indeterminate under item 4. Section 12 defines
   the corresponding limit on standard event delivery after journal failure.
   Exactly one interpreter execution owner MAY advance a journal at a time.
   Before execution or resume advances durable state, storage MUST grant
   that owner an opaque fencing token or equivalent monotonically ordered
   ownership generation. Every append and flush MUST be authorized by the
   current token, and storage MUST reject an operation from a superseded owner.
   Concurrent tasks belonging to the current owner MAY append through the
   storage's linearizable ordering, but starting or resuming a second owner for
   the same journal while the first is active MUST be rejected before hook or
   task dispatch. After an unclean process loss, the embedder and storage MAY
   reclaim ownership only after establishing that the preceding owner can no
   longer successfully append or flush; granting the new fencing token MUST
   make that guarantee atomic. Read-only inspection MAY remain concurrent.
   An orderly owner release MUST atomically invalidate that owner's token so
   every later append or flush using it fails. Gantry MUST release ownership
   after an execution reaches terminal durable state and every required and
   best-effort event-delivery obligation created through its terminal event has
   settled durably. Returning a terminal result waits only for the required
   delivery barrier in Section 12; finite best-effort delivery MAY continue
   afterward while the current interpreter retains journal ownership. An
   orderly interpreter shutdown is stricter: Section 10 requires every such
   finite obligation to settle and every journal owner to be released before
   shutdown returns. Gantry MUST also release ownership after a start or
   resume-start failure when
   ownership was acquired but interpretation never began.
   Release failure is a journal failure after execution has begun. A start or
   resume-start invocation that has not advanced durable execution state MUST
   instead include ownership-release failure in its structured pre-execution
   result and leave later acquisition to the storage's fencing rules. These
   ownership operations coordinate access and do not add a mutation primitive
   for journal records themselves.
3. A hook dispatch MUST be recorded and flushed before the hook is invoked.
   Its dispatch record MUST preserve the complete versioned semantic request,
   including the operation-specific body, operation and result kinds, captured
   inputs, schema, guidance, source location, ordered execution context,
   validation state, and logical identities. Prompt and decision records MUST
   preserve their selected agent, mapping revision, templates, interpolation
   arguments, named inputs, and session fields. Action records MUST preserve
   their canonical action path and signature, action-mapping revision, and
   typed arguments.
   Protected or repeated payloads MAY be stored by stable reference, but those
   references MUST resolve from the same durable journal. A recovery
   redispatch MUST reuse those committed semantic fields except for the
   physical-dispatch fields and the applicable agent- or action-mapping
   revision explicitly allowed to change by Section 7. It MUST retain all
   committed operation inputs, schema, guidance, source location, context, and
   validation state. A model operation also retains its logical agent and
   session; an action retains its canonical path and signature. The new
   dispatch ID and incremented recovery-dispatch number MUST differ, and the
   request MUST carry the applicable mapping revision recorded for the resume
   run. No other semantic request field may change.
   A durable dispatch record represents a prepared physical dispatch attempt;
   it does not prove that the hook future began polling or that the integration
   observed the request. There is no portable atomic boundary between durable
   preparation and entry into integration code. Consequently, a prepared
   attempt with no committed outcome is indeterminate under item 4 even when
   interruption may have happened before the hook began.
   After a hook returns, Gantry MUST append the outcome and flush through that
   outcome record's sequence number before the interpreter validates, assigns,
   branches on, returns, or otherwise consumes it. A successfully flushed
   outcome is committed. Commitment at this boundary means that the physical
   hook outcome is durable; it does not mean that `Completed(raw_output)` has
   passed UTF-8 decoding, JSON parsing, schema validation, or normalization.
   On resume, Gantry MUST continue deterministic processing of that committed
   outcome and MUST NOT redispatch it solely because validation or
   normalization had not completed before interruption. This ordering ensures
   recovery either reuses the committed outcome or treats the dispatch as
   indeterminate; program state MUST NOT advance using an outcome that is not
   yet durable.
4. If execution is interrupted after dispatch but before an outcome is
   committed, the operation is indeterminate. On resume, Gantry MUST
   automatically invoke that operation again with the same operation ID and a
   new dispatch ID and an incremented recovery-dispatch number. The validation-
   attempt number and remaining structured-output retry budget MUST NOT change
   merely because of recovery redispatch. Integrations MUST therefore assume
   at-least-once invocation and possible duplicate external side effects.
5. A consumable logical result derived from a committed hook outcome MUST be
   appended and flushed as an operation-result record before source execution
   may assign, branch on, return, or otherwise consume it. This requirement
   applies both to a successfully validated `Completed` outcome and to a
   `Declined` outcome that produces `None` for an expected `Option<T>`. The
   record MUST identify the operation and committed outcome, outcome variant,
   result kind, canonical type descriptor, normalized canonical JSON when the
   operation returns a value, and the sealed decision value, provenance, and
   rationale when the operation returns a decision. An optional decline records JSON
   `null` together with its decline provenance. A no-result operation records
   successful acceptance without creating a source value. A logical result
   recorded this way MUST be reused during resume and MUST NOT consume the
   remaining validation-retry budget again.
   A committed but invalid `Completed` outcome MUST likewise be reused as the
   cause of its validation failure; Gantry MUST NOT invoke the hook again for
   that same validation attempt. Invalid attempts and retry counts MUST also
   be journaled. Gantry MUST append and flush a validation-attempt
   record before dispatching its repair retry, so recovery preserves both the
   preceding errors and the exact remaining budget.
6. Journals MUST identify the exact package source and journal format version.
   The package source identity is the SHA-256 digest of a canonical manifest
   containing every selected package-relative source-file path exactly once.
   `main.gnt` contributes the root entry, and a file selected by a file-module
   declaration contributes one entry for that module. Inline modules
   contribute no separate entry because their bytes are already part of the
   containing file's entry. Manifest entries are
   sorted in ascending lexicographic order by the unsigned UTF-8 bytes of their
   package-relative path, use `/` as their path separator, and contain the
   path, the exact source-file bytes, and the resolved module path.
   Paths use the NFC spelling already required by Section 4; source bytes and
   line endings MUST NOT otherwise be normalized. The manifest byte stream is
   the ASCII domain tag `gantry-source-v1\0`, followed by the entry count and,
   for each entry, the path, source bytes, and resolved module path. Every
   count and byte-string length is encoded as an unsigned 64-bit big-endian
   integer, and every path is encoded as UTF-8. This length-prefix encoding is
   unambiguous even when source contains arbitrary delimiters. Gantry MUST
   reject resume when this identity differs or the journal format is
   unsupported. The package-relative path of the root module is exactly
   `main.gnt`. Every other manifest path is the path of the source file selected
   by module resolution, relative to the package root; inline modules add no
   manifest entry of their own because their bytes are already present in the
   containing source file. Each resolved module path is encoded as its
   `crate::`-rooted sequence of NFC identifier segments joined by `::`, with the
   root module encoded as `crate`. One package-relative path MUST NOT be
   selected as more than one file-backed module; such aliasing is the duplicate
   module resolution error defined in Section 4. Distinct package-relative
   paths remain distinct manifest entries even when the host filesystem stores
   them as hard links to the same bytes. These rules make the digest
   independent of module-discovery order and host path syntax.
7. Recovery MUST restore scopes, instruction positions, call frames, loop
   counters, task relationships, and committed values. An in-flight spawned
   block MUST restart at the top of that block while reusing every committed
   operation result recorded for it. Uncommitted operations are retried under
   item 4. Deterministic replay of `spawn`, `join`, `joinall()`, or `detach` MUST
   consult the durable task-state history before changing task ownership. A
   replayed `spawn` occurrence MUST recover its existing stable child task and
   MUST NOT create a duplicate child. A replayed join or detach whose ownership
   transition is already durable MUST recover that transition and its committed
   result or failure rather than consume the handle again. Task identities and
   lifecycle records MUST therefore be keyed by the same logical task and
   source-occurrence path used by dynamic operation identity.
8. A detached task remains part of its originating execution and journal after
   foreground `main` returns. Foreground completion, detachment, detached-task
   completion, and detached-task failure MUST each be durable states. Resuming
   an execution with unfinished detached tasks MUST recover them under the
   same rules as other in-flight spawned blocks. An execution reaches its
   terminal durable state only after its foreground and every detached task
   have completed, failed, or been cancelled during shutdown. Before returning
   a foreground result, Gantry MUST append and flush an interpreter checkpoint
   that makes the corresponding scopes, instruction positions, task ownership,
   and completed values durable. Once all foreground and detached work has
   settled, Gantry MUST append and flush exactly one terminal-execution record
   containing the final category and references to its foreground result,
   detached-task outcomes, cancellation, and primary and secondary failures
   when applicable. That record, not an earlier checkpoint or event,
   establishes terminal durable state. Gantry MUST then create the terminal-
   execution event that references this record and satisfy the required-event
   barrier in Section 12 before returning an orderly terminal result. Failure
   to deliver that event cannot rewrite the already durable language outcome;
   Section 12 defines the separate delivery-barrier failure returned to the
   embedder. Unsettled best-effort obligations MAY continue after that result
   is returned, but they MUST settle under their captured finite policies
   before journal ownership is released.
   When the authoritative prefix already contains a terminal-execution record,
   `resume` MUST NOT reevaluate source, recreate a Gantry task, or dispatch an
   operation hook. It MUST recover and settle only journaled event-delivery
   obligations that remain unsettled, then return the existing terminal
   language outcome together with any required-delivery barrier status. A
   durable `terminal` delivery settlement MUST NOT be retried merely because a
   caller invokes `resume` again.
   When foreground completion is durable but detached tasks remain unfinished,
   `resume` MUST preserve the existing foreground outcome and recover only the
   unfinished detached task graph and unsettled delivery obligations. It MUST
   NOT call `main` again or emit another foreground-completion event. The
   embedding API MAY expose the preserved foreground outcome immediately while
   the resumed execution continues toward terminal state.
9. A v1 journal envelope MUST identify its protocol version, journal and
   execution IDs, monotonically increasing sequence number, record ID, record
   kind, causal parent record when one exists, task and operation identities
   when applicable, and a kind-specific payload. The required record kinds are
   execution state, session state, operation dispatch, operation outcome,
   validation attempt, operation result, interpreter checkpoint, task state,
   event, event-delivery state, and terminal execution. A session-state record
   MUST contain the logical-session creation fields and obey the durability and
   replay rules in Section 7. An execution-state record MUST
   identify its state-transition subtype, including execution start, agent-
   mapping revision, action-mapping revision, best-effort-sink configuration
   change, or shutdown-policy revision when applicable.
   A terminal-execution record MUST use one of the terminal categories defined
   in Sections 7, 10, and 15 and MUST be the final record that changes language
   execution state. Later event-delivery records and ownership release do not
   alter that state. Concrete serialization and Rust types are implementation-
   defined, but all required information and durability boundaries are
   normative. Before append, Gantry constructs an unfinalized record body that
   omits the record ID and sequence number. The storage append operation MUST
   atomically assign both fields and store the resulting finalized envelope;
   only that finalized envelope is a journal record returned by durable reads.
10. A new-execution request MUST identify a fresh journal target through an
    embedder-supplied stable journal ID. Allocation and naming of that target
    are integration concerns outside the `JournalStorage` mutation interface.
    After exclusive ownership is acquired, the target's authoritative durable
    prefix MUST be empty, its durability watermark MUST be zero, and its next
    append sequence MUST be one. A nonempty target is an initial-
    journal-ownership start failure; Gantry MUST NOT overwrite it, append a
    second execution start, or reinterpret it as the requested new execution.
    The embedder retains the journal target identity even when startup fails so
    it can inspect an uncertain storage outcome or resume by journal identity
    if an execution-start record became durable before an error was observed.

    For each new execution, after entry validation and integration preflight
    succeed but before evaluating `main`, creating a child task, or dispatching
    a hook, Gantry MUST allocate a fresh execution ID and append and flush
    exactly one execution-start record as the journal's first record. That
    record MUST have sequence number one and MUST contain the package source
    identity, the selected source-language major and minor version, the
    effective-configuration identity and fields defined below, the selected
    root-session identity and provenance, each applicable agent- or action-
    mapping revision from Section 7, the canonical signature of `main` defined in
    Section 4, and
    either a no-entry-input marker or the validated and normalized canonical
    entry value with its type descriptor.
    Resume MUST verify and reuse the existing execution-start record, restore
    its entry value, and MUST NOT append a second execution-start record or
    accept replacement entry input. An agent- or action-mapping revision
    changed during resume MUST instead be appended and flushed as an
    execution-state record before recovered interpretation or dispatch
    continues.

    The effective-configuration identity is the SHA-256 digest of the RFC 8785
    JSON Canonicalization Scheme encoding of the following canonical object
    shape. Property names and enum strings shown here are normative. Protocol
    version components are JSON numbers. Every other integer-valued field is a
    canonical unsigned decimal string with no sign or leading zero except the
    value `0`; this avoids loss of precision in RFC 8785 implementations whose
    JSON number domain is IEEE 754 binary64.
    Durations are represented as whole microseconds, identities are JSON
    strings, and no additional properties participate in the v1 identity:

    ```json
    {
      "configuration_protocol": { "major": 1, "minor": 0 },
      "source_language": { "major": 1, "minor": 0 },
      "hook_protocol_major": 1,
      "journal_protocol_major": 1,
      "event_protocol_major": 1,
      "maximum_directive_integer": "9223372036854775807",
      "root_session": {
        "id": "logical-session-id",
        "provenance": "embedder-supplied"
      },
      "structured_output": {
        "model_retry_limit": "2",
        "action_retry_limit": "0",
        "backoff": {
          "initial_us": "100000",
          "cap_us": "2000000",
          "jitter": "full"
        }
      },
      "deterministic_values": {
        "maximum_string_scalars": "1048576",
        "maximum_list_items": "65536"
      },
      "required_event_sinks": [
        {
          "id": "stable-sink-id",
          "raw_output_enabled": false,
          "redaction_policy_id": "policy-id",
          "retry_policy_revision": "revision-id",
          "attempt_timeout_us": "30000000",
          "retry_limit": "3",
          "backoff": {
            "initial_us": "100000",
            "cap_us": "2000000",
            "jitter": "full"
          }
        }
      ]
    }
    ```

    The displayed values illustrate the v1 defaults; the identity MUST encode
    the effective configured values. `maximum_string_scalars` limits each
    normalized or computed String by Unicode-scalar count, and
    `maximum_list_items` limits each normalized or computed List by item count.
    Both limits MUST be positive and no greater than Gantry's maximum `Int`,
    `9007199254740991`, because `String.len()` and `List<T>.len()` return
    `Int`. They are checked recursively at entry, operation, construction,
    parsing, resume, and deterministic-evaluation boundaries. `model_retry_limit`
    applies to `prompt`
    and `decide`, while `action_retry_limit` applies to `action`. Both count
    retries after the initial attempt. `source_language` MUST equal the version
    selected for the execution and MUST match the execution-start record.
    `root_session.provenance` is exactly `embedder-supplied` or
    `gantry-created`. `jitter` is exactly `none` or `full`; a future mode
    requires a protocol change. Required sinks MUST be ordered by the unsigned
    UTF-8 bytes of `id` before canonicalization, and their IDs and redaction-
    policy and retry-policy-revision IDs MUST be valid UTF-8. The root-session
    ID and every required-sink ID MUST use the same stable string
    representation that their embedding interfaces expose. This exact object
    definition makes independently produced identities comparable rather than
    leaving property spelling or nesting to an implementation.

    The execution-start record MUST additionally contain the initial mutable
    runtime policy that is deliberately excluded from the configuration
    identity: the effective graceful-shutdown duration, post-cancellation-drain
    duration, and complete effective best-effort sink set. Each best-effort
    sink descriptor MUST contain the same fields shown above for a required
    sink, plus its `best-effort` class, and the descriptors MUST be ordered by
    unsigned UTF-8 sink ID. These initial values are the baseline for resume;
    Gantry MUST restore them from the execution-start record and then apply
    later compatible execution-state revisions in journal sequence order. A
    resume caller MUST NOT silently replace that baseline through ordinary
    interpreter configuration. A requested compatible change becomes active
    only after the execution-state record described below is appended and
    flushed. This separation keeps mutable operational policy recoverable
    without pretending that it is immutable execution identity.
    Resume MUST reject changes to those fields. Executor implementation,
    worker count, and integration-owned operation-timeout policy MAY change on
    resume without changing this identity; they affect scheduling or
    integration behavior rather than the meaning of already committed Gantry
    state. Shutdown timing, best-effort sinks, and logical-agent-to-provider
    mappings and action mappings MAY change only after Gantry appends and flushes the applicable
    execution-state record before further work. That record MUST contain the
    effective graceful-shutdown and post-cancellation-drain durations when
    shutdown timing changes; a best-effort-sink revision MUST contain the
    complete replacement set in the canonical order and descriptor shape
    above; and agent- and action-mapping changes use the state described in
    Section 7.
    These changes MUST obey the per-event delivery-obligation rules in Section
    12. Allowing agent mappings to change is
    intentional because Gantry promises resumability, not deterministic model
    replay. Source operation modifiers remain bound through the package source
    identity rather than being duplicated into this configuration identity.
11. These resume guarantees do not create a deterministic-replay guarantee for
    a new execution.

## 12. Observability and Validation Modes

1. Gantry MUST expose events for parsing and analysis, workflow start and end,
   operation dispatch, completion, and result acceptance, schema validation
   failure, retry, branch decision, spawn, join, detach, mutation,
   cancellation, foreground completion, task completion, terminal execution,
   shutdown, and failure, except that sink-delivery failures use the
   nonrecursive representation defined in item 6. Foreground
   completion is distinct from terminal execution when detached tasks remain.
   This event requirement applies while the event's required durability
   boundary is available. A journal failure that makes a resumable execution's
   event stream unwritable is reported through the structured embedding error
   required by Sections 11 and 15 rather than by fabricating an undurable
   standard event.
   Operation-dispatch events MUST reference the applicable prompt and schema
   payloads. Event and journal envelopes MUST be explicitly versioned from the
   first public release, and consumers MUST reject unsupported major versions.
   One operation-dispatch event MUST be emitted for each prepared physical
   dispatch attempt, including validation retries and recovery redispatches.
   It records durable intent immediately before hook invocation, not proof that
   the integration observed the request. Process interruption MAY therefore
   leave a dispatch event with no corresponding hook entry or outcome; sinks
   MUST treat the attempt as indeterminate rather than infer that provider work
   occurred. One operation-completion event MUST be emitted for each host-level
   outcome actually returned by a hook, including a `Completed` outcome that
   subsequently fails parsing or schema validation. Those events retain the
   logical operation ID and carry the distinct dispatch ID and applicable
   validation-attempt and recovery-dispatch numbers. A structured-output-
   validation-failure event and, when another attempt is permitted, a retry
   event follow the corresponding completion event. After a `Completed` outcome is successfully decoded,
   parsed, validated, normalized, and durably recorded under Section 11, or an
   optional `Declined` outcome is durably normalized to `None`, Gantry MUST
   emit exactly one operation-result event for that logical operation. The
   event represents acceptance of a value, decision, or no-result completion
   and MUST reference the operation-result record. It is not emitted for a
   required-result `Declined`, `Failed`, or invalid `Completed` outcome.
   Recovery that reuses an existing operation-result record MUST reuse its
   corresponding durable event occurrence rather than emit another logical
   acceptance event. If the operation-result record is durable but its event
   record is absent, recovery MUST create exactly one replacement occurrence
   under item 2 before source execution consumes the result. This event
   cardinality distinguishes physical hook activity from the one source-level
   result that execution may consume.
   For a resumable execution, causal event creation has the following mandatory
   ordering. After the operation-dispatch record is durable and before invoking
   the hook, Gantry MUST append and flush the corresponding operation-dispatch
   event record. After an operation outcome is durable and before decoding,
   validation, decline handling, or failure propagation consumes that outcome,
   Gantry MUST append and flush its operation-completion event record. A
   structured-output-validation-failure event and any retry event MUST be appended and flushed
   before the next dispatch record. After an operation-result record is durable
   and before source execution consumes that result, Gantry MUST append and
   flush the operation-result event record. Delivery MAY remain asynchronous
   under item 3; these requirements order durable event creation, not sink
   acknowledgement. They ensure that a journal can never expose a consumed
   operation transition without its canonical event occurrence.
   On recovery, a durable outcome without its operation-completion event MUST
   receive exactly one replacement event under item 2 before processing of the
   outcome resumes. A durable completion event MUST never be duplicated. For a
   `Declined` or `Failed` outcome that fails the task, this completion event is
   the final operation-specific event; the resulting task failure is observed
   separately and does not manufacture an operation-result event.
2. Each event MUST have a stable event ID and activity ID. An activity is one
   syntax-validation, semantic-analysis, execution/resume, or shutdown
   invocation. An event associated with a program execution MUST also include
   its execution ID; standalone validation, analysis, and interpreter-wide
   shutdown events MAY omit it. An event MUST include a source location when
   caused by a source-backed construct, a task ID when it occurs in a task, an
   operation ID when it concerns an operation, and causal parent/child IDs
   when such relationships exist. Parse, package-analysis, shutdown, and
   storage failures MAY lack task or operation identity. Event order is
   guaranteed within one task but not across concurrent tasks; IDs MUST permit
   reconstruction of cross-task causality. Delivery retries reuse the event ID
   and use a distinct delivery-attempt ID.
   For a resumable execution, an event ID MUST identify one logical event
   occurrence rather than one interpreter replay of that occurrence. A durable
   event record is the point at which that protocol-visible occurrence is
   created. Gantry MUST reuse its event ID, original activity ID, and timestamp
   whenever deterministic replay encounters an event already present in the
   authoritative journal prefix; it MUST NOT append a second event for that
   occurrence. If a causal interpreter transition is durable but interruption
   occurred before its required event record became durable, no event from that
   transition could have been delivered under item 3. Recovery MUST create
   exactly one replacement event before performing work that depends on that
   transition. The replacement uses the resume activity ID and its actual
   creation timestamp, identifies the durable causal record, and thereafter has
   the same stable recovery and deduplication behavior as any other event. An
   unflushed event record is not authoritative and MUST NOT reserve an event ID
   or timestamp across recovery. Events for genuinely new work performed by the
   resume likewise use the resume activity ID. These rules make sink
   deduplication effective without requiring recovery to reproduce metadata that
   was never durable or externally visible.
3. Events from a resumable execution MUST be durably journaled before their
   first delivery. Parse and analysis events produced without a resumable
   execution MAY be delivered without a journal. Event delivery MAY use
   bounded asynchronous queues, but queue backpressure MUST prevent silent
   event loss and preserve per-task order.
   Parsing and semantic analysis performed as preflight for a requested new
   execution remain activity-scoped until the execution-start record in
   Section 11 is durable. Their events MAY therefore omit an execution ID and
   be delivered without that execution's journal; an analysis failure creates
   no resumable execution. Once the execution-start record is durable, every
   event associated with that execution is subject to the journal-first rule.
   Every required-sink obligation created by new-execution preflight MUST
   settle successfully before Gantry appends the execution-start record.
   Exhaustion is a structured start failure, and Gantry MUST NOT create the
   resumable execution merely to report it.

   Compatibility and dependency preflight for resume follows the same
   activity boundary. Because a resume-start failure MUST NOT modify the
   existing journal, events created before recovered interpretation begins are
   unjournaled activity events even when they carry the existing execution ID
   for correlation. Their required-sink obligations MUST settle successfully
   before Gantry advances recovered state. After recovered interpretation or
   delivery recovery begins, newly created events are journal-first execution
   events. These rules prevent asynchronous preflight delivery failure from
   changing category after an execution or resume has already begun.
   If journal storage subsequently fails, the authoritative standard event
   stream ends with its last durably flushed event. Gantry MUST NOT deliver a
   newly created standard event for that journal failure because doing so
   would violate the journal-first rule. An implementation MAY invoke a
   separately configured, non-durable emergency diagnostic callback, but that
   callback is not an `EventSink`, carries no at-least-once guarantee, and MUST
   be identified as out-of-band reporting rather than a Gantry event.
4. Canonical protected event records for completed operations MUST make raw
   integration output available. A sink receives raw output only when it
   explicitly declares that capability and the embedder enables it for that
   sink. Other sinks receive the same event identity with the raw field
   redacted. Prompts and schemas MUST be observable through journal or event
   IDs referenced from events rather than duplicated in every event. Raw output
   MUST remain omitted from default human-readable diagnostics and validation
   error text. A decision rationale is normalized model-derived output and
   MUST likewise be stored as a protected payload referenced by operation-
   result and branch-decision events; it MUST NOT be copied into an ordinary
   event envelope. A sink receives the rationale text only when its enabled
   redaction policy permits model-derived result content. For delivery, Gantry
   MUST resolve an event's protected references into a capability-filtered
   payload bundle supplied alongside, but not inside, the ordinary event
   envelope. The bundle MUST preserve the stable reference keys used by the
   envelope. It MUST omit or explicitly redact raw output for a sink that lacks
   raw-output access and MUST omit or explicitly redact a rationale when the
   sink's redaction policy disallows model-derived result content. A protected
   payload referenced by a durable journal or event record MUST remain
   resolvable for as long as that record is retained. Gantry MUST additionally
   retain it until every required delivery has succeeded or terminally failed
   and every best-effort delivery has either succeeded or exhausted its policy.
   Retention or deletion policy MAY remove a complete journal and its payloads,
   but MUST NOT leave a retained durable record with a dangling protected
   reference. This makes reference-based events usable without placing
   sensitive or repeated payloads directly in each event envelope.
5. Event sinks MUST be configured independently as `required` or
   `best-effort`, with interpreter defaults overridable per sink. Gantry MUST
   retry only errors the sink classifies as retriable. A non-retriable error
   exhausts delivery immediately. The retry limit counts known retriable
   failures after the initial delivery; recovery of an indeterminate delivery
   does not consume that budget. The default policy is three retries and uses
   the same full-jitter exponential formula as Section 8: for one-based retry
   `r`, the ceiling is `min(100 ms * 2^(r - 1), 2 s)`, and the delay is sampled
   uniformly from whole microseconds from zero through that ceiling. Every
   physical delivery attempt MUST also have a finite positive attempt timeout.
   The v1 default is 30 seconds. Gantry MUST race the sink future against that
   timeout through the executor adapter. Expiration is a retriable delivery
   error while retry budget remains and a terminal delivery error otherwise.
   Gantry MUST stop polling the expired future and MAY signal a sink-specific
   cancellation mechanism when the embedding API provides one, but it cannot
   assume that external sink effects stopped. A later retry is therefore an
   at-least-once delivery and retains the same stable event ID.

   For a resumable execution, every physical sink invocation MUST use two
   durable event-delivery state transitions. Before invoking the sink, Gantry
   MUST append and flush a `dispatched` state containing the sink ID, stable
   event ID, distinct delivery-attempt ID, and zero-based retry number. After
   the sink returns, Gantry MUST append and flush a `settled` state containing
   the same identities, an outcome classification of `success`, `retriable`,
   or `terminal`, and the remaining retry budget. A `retriable` settlement is
   valid only when at least one retry remains and MUST also contain the selected
   delay. A non-retriable sink error, or a retriable sink error received after
   the retry budget is exhausted, MUST be recorded as `terminal`. Gantry MUST
   NOT treat the delivery as successful or terminally exhausted until the
   corresponding `settled` state is durable.

   A durable `success` or `terminal` settlement MUST NOT be delivered again to
   that sink. A `dispatched` delivery with no durable settlement is
   indeterminate and MUST be delivered again with the same stable event ID, a
   new delivery-attempt ID, and the same retry number; this recovery redelivery
   does not apply backoff or consume retry budget. A durable `retriable`
   settlement records its selected delay before any sleep begins. If execution
   is interrupted before the following `dispatched` state becomes durable,
   resume MUST wait that complete recorded delay again and then use the next
   retry number. These rules give event delivery at-least-once semantics while
   making retry accounting and crash recovery unambiguous.

   Each journaled event MUST freeze its delivery obligations at creation by
   recording the active sink IDs and, for each sink, its required/best-effort
   class, raw-output permission, retry-policy revision, attempt timeout, retry
   limit, initial delay, cap, and jitter mode. A retry or recovery redelivery
   MUST use that captured class and effective retry policy rather than a later
   interpreter default. Adding a sink after an event was created MUST NOT
   retroactively deliver the older event to that sink. Removing or replacing a
   sink MUST NOT silently abandon an unsettled captured obligation. Before
   recovered interpretation begins, Gantry MUST verify that every required sink named by
   the execution-start configuration and every unsettled required delivery
   obligation has a resolvable adapter. An unavailable required adapter is the
   nonterminal resume-start failure defined in Section 7 rather than permanent
   exhaustion of that obligation. Once resume begins, an adapter that becomes
   unavailable returns a terminal sink error under the captured required
   policy. An absent best-effort adapter is an immediate terminal delivery
   error under its captured policy and does not block resume. Raw-output access
   at delivery time requires both the
   event's captured permission and the sink's current enabled capability, so a
   later configuration may reduce but MUST NOT retroactively broaden access to
   protected output. Configuration changes apply to events created after the
   corresponding execution-state record becomes durable. For an active
   resumable execution, the required-sink identities and their identity-bound
   policy fields MUST remain exactly those in the execution-start
   configuration identity; adding, removing, or changing a required sink is a
   resume-compatibility error. Best-effort sinks MAY be added, removed, or
   reconfigured after Gantry appends and flushes an execution-state record
   describing the new effective set. Such a change affects only later events
   and never alters an already frozen delivery obligation.
6. Delivery of a journaled event is durably at least once across process
   interruption and resume. Sinks MUST deduplicate using the stable event ID.
   For a standalone validation or analysis activity without a journal, Gantry
   MUST apply the configured delivery attempts while that activity remains
   alive, but process interruption MAY lose an unsettled event and v1 provides
   no recovery source from which to redeliver it. An implementation MUST NOT
   describe that weaker standalone guarantee as durable at-least-once
   delivery. Exhaustion for a required sink MUST abort the affected activity
   and its execution when one exists; exhaustion for a best-effort sink MUST
   be journaled when a journal exists, otherwise included in the activity
   result, and the activity MUST continue. Before returning a foreground
   outcome, Gantry MUST flush required-sink delivery through that execution's
   foreground-completion event; events from detached work remain eligible for
   later delivery through the same execution. Before returning a terminal
   execution result, validation or analysis result, or orderly shutdown
   report, Gantry MUST flush all required-sink deliveries produced by that
   completed activity through its final event. These barriers do not require
   waiting for events that the activity has not yet produced. The terminal
   interpreter shutdown rule in Section 10 additionally requires every finite
   best-effort obligation owned by the interpreter to settle before shutdown
   returns; ordinary foreground and terminal execution results retain the
   required-sink-only barrier stated here.
   A sink-delivery failure MUST NOT itself create a standard Gantry event.
   Its durable event-delivery settlement, the affected activity result, and
   the structured barrier or runtime error are its canonical observability
   records. An implementation MAY additionally use the non-durable emergency
   diagnostic callback, but MUST NOT create another event-delivery obligation
   from that callback. This rule prevents one failing sink, or a cycle of
   failing sinks, from recursively generating more failure events.
   Required-sink exhaustion while an execution is nonterminal is
   execution-wide rather than task-local: Gantry MUST reject new work for that
   execution, signal cancellation to its foreground, attached, and detached
   tasks, and apply the configured cancellation drain. It MUST then append and
   flush the execution's terminal-execution record with the `required-event-
   delivery failure` category, without making that record depend on another
   event. That record MUST identify the exhausted sink, failed event, delivery
   attempt, and cancellation outcome. Failure of the terminal-record write is
   returned to the embedder as a journal failure.

   After a sink has exhausted, Gantry MUST exclude that sink from every new
   cancellation, failure, foreground-completion, task-completion, and terminal-
   execution event obligation created while terminating the affected activity.
   This is the sole exception to creating obligations for every sink active at
   event creation. Other active sinks retain their ordinary obligations. The
   exhausted sink's durable terminal delivery settlement and the terminal-
   execution record are its canonical notification; Gantry MUST NOT attempt to
   make it acknowledge consequences of its own failure.

   Exhaustion of any required delivery obligation after the terminal-execution
   record is durable—including an older queued event or the terminal-execution
   event itself—MUST NOT append a second terminal record or replace the
   recorded language outcome. Gantry MUST durably settle the failed delivery
   obligation and return a structured required-event-delivery barrier failure
   that includes the existing terminal outcome. A later query still observes
   that durable terminal outcome, while delivery state identifies every
   required event that was not delivered. A standalone activity without a
   journal MUST return the required-event-delivery failure directly. No event
   produced during cancellation is delivered to the exhausted sink, and an
   implementation MUST NOT recursively require that sink to acknowledge its
   own failure. These rules override the general failure-event requirement for
   that exhausted sink and prevent recursive failure-event generation.
7. Every event envelope MUST identify its protocol version, event and activity
   IDs, optional execution ID, event kind, source location when source-backed,
   task and operation identities when applicable, causal parent IDs, per-task
   sequence when task-backed, timestamp, a kind-specific payload or stable
   payload reference, and redaction state. A timestamp MUST be the event's
   creation time encoded as an RFC 3339 UTC string and MUST remain unchanged
   across delivery retries. Prompt templates, schemas, and raw integration
   output MUST use protected stable references rather than being copied into ordinary
   event payloads; diagnostics and other nonsensitive standalone activity data
   MAY be carried inline. The canonical v1 event kinds are parse, analysis,
   workflow start, workflow end, operation dispatch, operation completion,
   operation result, structured output validation failure, retry, branch
   decision, spawn,
   join, detach, mutation, cancellation, foreground completion, task
   completion, terminal execution, shutdown, and failure. Concrete
   serialization is implementation-defined.
8. Event kind payloads MUST expose enough structured information for a harness
   to interpret an execution without parsing diagnostic text. The canonical
   minimum payloads are:
   - `parse` and `analysis`: phase, status, and structured diagnostics;
   - `workflow start` and `workflow end`: workflow path, frame occurrence, and
     completion status, plus a typed result reference when one exists;
   - `operation dispatch`: operation and dispatch IDs, dispatch state
     (`prepared` in v1), operation and result kinds, validation-attempt number,
     recovery-dispatch number, and schema and operation-body references. A
     prompt or decision additionally identifies its selected agent, active
     agent-mapping revision, logical session, request session directive,
     active-session creation directive and parent session when applicable, and
     prompt reference. An action instead identifies its canonical path and
     signature and active action-mapping revision;
   - `operation completion`: operation and dispatch IDs, outcome variant, and
     a protected raw-output reference for `Completed`, or the decline/failure
     reason under the sink's redaction policy;
   - `operation result`: operation ID, committed outcome and operation-result
     record references, outcome variant, result kind, canonical type
     descriptor, and a protected normalized-value reference for a value result
     or the decision and protected rationale reference for a decision result;
     an optional decline additionally identifies its decline provenance;
   - `structured output validation failure`: operation and dispatch IDs plus
     the structured validation errors defined in Section 7;
   - `retry`: operation ID, preceding and next dispatch IDs when assigned,
     validation-attempt and recovery-dispatch numbers, retry class, and
     selected delay;
   - `branch decision`: conditional, match, or loop identity; condition kind
     (`decision`, `bool`, or `pattern`); outcome; and selected arm or loop
     transition, plus the decision operation and protected rationale references
     when the condition used `Decision`;
   - `spawn`: parent and child task IDs, spawn occurrence, declared result
     type, and attachment state;
   - `join`: joining task ID, joined task IDs in source order, join form,
     settlement status, result type when any, and ordered child failures;
   - `detach`: owner and detached task IDs plus the durable ownership-transfer
     record reference;
   - `mutation`: task ID, assignment source location, target path, static type,
     and committed-value reference, without requiring the value inline;
   - `cancellation`: target activity, execution, or task; cancellation reason;
     and whether cancellation is requested or terminal;
   - `foreground completion` and `task completion`: the applicable identity,
     completion category, and typed result or failure reference when one
     exists;
   - `terminal execution`: the execution identity, completion category,
     terminal-execution record reference, and typed foreground result or
     primary failure reference when one exists; and
   - `shutdown`: the shutdown activity identity, configured graceful and drain
     durations, counts of executions and tasks observed at shutdown start,
     counts completed naturally, cancelled, and aborted, required-state flush
     status, and a shutdown-report reference; and
   - `failure`: the runtime-error category, structured causal identities, and
     redacted diagnostic details.
   An implementation MAY add optional fields under the minor-version rules,
   but it MUST NOT omit these applicable fields or encode their only usable
   representation in human-readable text.
9. A dry-run performs syntax validation only and MUST NOT invoke operation hooks.
   Starting from `main.gnt`, it MUST discover every file module reachable
   through syntactically valid `mod` declarations and lex and parse every
   selected source file. Missing or ambiguous module files, containment
   violations, invalid UTF-8, lexical errors, and syntax errors are therefore
   dry-run failures because they prevent construction of the package syntax
   tree. A dry-run MUST NOT perform name resolution, type checking, schema
   generation, definite-control-flow analysis, or task-ownership analysis.
   Gantry MUST separately provide an analysis mode that first satisfies this
   whole-package syntax contract and then performs name, type, module, control-
   flow, task-ownership, and schema validation without invoking hooks.
   A successful analysis result MUST include the per-workflow call edges,
   direct operation sites, and transitive effect flags required by Section 6.
10. Normal execution MUST complete semantic analysis successfully before its
   first hook invocation.
11. Diagnostics MUST be usable by both human authors and automated repair
    agents without parsing display text. Every syntax or analysis diagnostic
    MUST contain a canonical phase, severity, machine-readable category, a
    documented code stable within the protocol major version, a human-readable
    message, and a primary package-relative source span when the problem is
    source-backed. The canonical v1 categories are `lexical`, `syntax`,
    `package`, `name-resolution`, `type`, `control-flow`, `task-ownership`, and
    `schema`. Diagnostic code namespaces are implementation-defined in v1, but
    each implementation MUST publish its code registry and MUST NOT reuse one
    code for a different meaning while supporting the same protocol major
    version. The canonical category, source spans, and structured fields are
    the portable cross-implementation contract; clients MUST NOT assume that
    two implementations assign the same code to the same condition. A
    diagnostic SHOULD include labeled related spans for conflicting
    declarations or ownership paths. A syntax diagnostic SHOULD identify the
    encountered token or end of input and the expected token classes when that
    information is available without fabricating parser state.
    Runtime diagnostics MUST include the runtime-error category from Section 7
    and the applicable execution, task, operation, source, and causal
    identities. Implementations MAY add notes and implementation-specific
    subcodes, but the only machine-usable representation of an error MUST NOT
    be free-form text. The redaction rules in this section continue to apply to
    every diagnostic field.

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
except inside string, raw-string, and block-prompt tokens. A trailing comma is
accepted only where the productions below include an optional final comma.
All EBNF fences in Sections 13.2 through 13.9 form one grammar; a production
MAY refer forward to a production in a later fence. Names explicitly described
as lexical metavariables in Section 13.2 constrain token characters and are not
missing parser productions.

### 13.2 Lexical grammar

```ebnf
source              = [ utf8_bom ], { item }, end_of_file ;

utf8_bom            = U+FEFF ;

whitespace          = " " | "\t" | "\r" | "\n" ;
line_terminator     = "\r\n" | "\n" | "\r" ;
line_comment        = "//", { line_comment_character },
                      ( line_terminator | end_of_file ) ;
block_comment       = "/*", { block_comment | block_comment_character }, "*/" ;
trivia              = whitespace | line_comment | block_comment ;

identifier_token    = xid_start_or_underscore,
                      { xid_continue_or_underscore } ;
directive_integer_token
                    = "0" | nonzero_decimal_digit, { decimal_digit } ;
integer_literal_token
                    = decimal_digits ;
float_literal_token = decimal_digits, ".", decimal_digits,
                      [ exponent_part ]
                    | decimal_digits, exponent_part ;
decimal_digits      = decimal_digit, { [ "_" ], decimal_digit } ;
exponent_part       = ( "e" | "E" ), [ "+" | "-" ], decimal_digits ;
decimal_digit       = "0" | "1" | "2" | "3" | "4"
                    | "5" | "6" | "7" | "8" | "9" ;
nonzero_decimal_digit
                    = "1" | "2" | "3" | "4" | "5"
                    | "6" | "7" | "8" | "9" ;
hex_digit           = decimal_digit
                    | "a" | "b" | "c" | "d" | "e" | "f"
                    | "A" | "B" | "C" | "D" | "E" | "F" ;

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
permitted. The exact one-character token `_` is reserved and MUST NOT be
emitted as an `identifier_token`; leading `_` remains valid when at least one
`XID_Continue` scalar follows it. Source MUST be valid UTF-8. One UTF-8
byte-order mark MAY appear only as the first decoded scalar of a source file
and is ignored; U+FEFF in any other source position is not whitespace and is a
syntax error. An identifier MUST NOT equal a reserved word. Decimal directive
integers have no sign, separator, or radix prefix.

An integer literal has decimal digits with optional `_` separators only
between digits. A float literal has either a decimal point with at least one
digit on each side or an exponent; its exponent may have a leading `+` or `-`.
The spellings `.5`, `1.`, radix-prefixed values, type suffixes, `NaN`, and
infinities are invalid. A leading `-` is the unary operator, not part of either
numeric token. Maximal munch classifies a digit sequence followed by `.` or an
exponent as one `float_literal_token`; otherwise it is an
`integer_literal_token`. Semantic analysis enforces the ranges in Section 5.

`end_of_file` is the zero-width lexical boundary after the final source scalar.
`line_comment_character` is any Unicode scalar other than U+000A or U+000D.
`string_character`, `block_comment_character`, `block_prompt_body`,
`raw_string_body`, and `matching_raw_hashes` are lexical metavariables whose
constraints are defined in the following paragraphs because nesting,
delimiter matching, and exclusions cannot be expressed faithfully by the
simple EBNF notation used here.

Block comments nest. An unterminated block comment, quoted string, raw string,
escape, or Unicode escape is a syntax error. A Unicode escape MUST identify a
Unicode scalar value and contain one through six hexadecimal digits. A normal
string may contain a literal newline. A string token MUST retain both its
authored body and the decoded semantic text needed by later phases; this is
required because prompt interpolation is recognized before escape decoding.
The lexer performs no indentation normalization. Outside string tokens,
`\r\n` is one line terminator rather than two. Inside ordinary, raw, and block
prompt strings, authored line-ending scalars are content and are preserved
exactly except for the structural block-prompt delimiters described below.

`trivia` is a lexical skip production rather than a syntactic nonterminal.
Outside string and prompt-template tokens, zero or more trivia elements MAY
occur between any two grammar tokens and are discarded by the lexer. Trivia
MUST NOT split one identifier, numeric token, string delimiter, comment
delimiter, or fixed multicharacter terminal such as `::` or `->`. Maximal munch therefore
requires trivia between a reserved word and an immediately following
identifier character when they are intended as separate tokens.

`string_character` is any Unicode scalar value other than `"` or `\`; newline
characters are included. `block_prompt_body` is the shortest sequence ending
before an unescaped `"""` delimiter and uses the same escape sequences as an
ordinary string. One or two consecutive unescaped quote characters are block-
prompt content; only three begin the closing delimiter. Escaping at least one
quote permits a literal three-quote sequence in the decoded content. A block
prompt MUST begin with a `line_terminator` immediately after its opening
delimiter; that required terminator is structural and is not part of the
resulting template. Its closing delimiter MUST be the first non-indentation
sequence on its line. Source text after the delimiter is outside the block-
prompt token and is lexed normally as a continuation of the enclosing
expression. Block-prompt indentation consists only of ASCII space and
horizontal-tab characters. The line terminator immediately before that
closing-delimiter line and the indentation before its delimiter are structural
and are not part of the resulting template. Authors who need a trailing
newline MUST include one additional blank content line.
The closing indentation is the exact dedent prefix: every nonblank content line
MUST begin with that same sequence of spaces and tabs, and Gantry removes it
once from each such line. A whitespace-only content line becomes an empty line
regardless of its authored indentation. Dedentation operates on authored
characters before escape decoding and interpolation replacement; it never
removes whitespace produced by an escape or an interpolated value. Relative
indentation and explicitly authored leading or trailing blank content lines
remain significant. This symmetric
structural-newline rule keeps multiline prompts readable without silently
adding a trailing newline. Ordinary and raw strings continue to preserve exact
whitespace. `block_comment_character` consumes one scalar value that does not
begin the nested opener `/*` or closing delimiter `*/`.
`raw_string_body` is the shortest sequence ending immediately before a quote
followed by exactly `matching_raw_hashes`. Lexing uses maximal munch for
identifiers, directive integers, `::`, and `->`. A raw-string token takes
precedence over an identifier only when `r` is immediately followed by zero or
more `#` characters and a quote. A block-prompt token takes precedence over an
ordinary quoted-string token when the next three characters are `"""`.
Reserved-word classification occurs after an identifier token is scanned.
Comments are recognized only outside string tokens, and interpolation islands
are recognized only by the contextual prompt scan described in Section 13.7.

The shortest-closing-delimiter rules above apply directly to strings used as
ordinary source values. When a string, raw string, or block prompt occurs in
the `prompt_template` position after `prompt` or `decide`, its closing
delimiter is recognized by the contextual template scan in Section 13.7.
That scan suspends recognition of the outer delimiter while it tokenizes a
balanced interpolation island. Consequently, quote characters and even a
delimiter-shaped sequence inside an island's nested string token do not close
the outer template.

For a raw string, `matching_raw_hashes` means exactly the same number of `#`
characters as `raw_hashes`. Backslashes have no special meaning in a raw
string. The variable-hash delimiter rule is lexical and is intentionally
described outside pure EBNF.

A `block_prompt_token` is valid only in the `prompt_template` position of a
`prompt` or `decide` expression. It is not a general `String` literal and
cannot be used as a field default; ordinary or raw strings serve those source
value positions. This restriction keeps triple-quoted indentation processing
specific to model instructions rather than introducing a second multiline
`String` value semantics.

The reserved words are:

```text
action     agent      agents      as           Bool        break       continue
crate      decision   Decision    decide       default     detach
else       enum       Err         false        Float       fn          fork        if
impl       inline     join        joinall      let         limit
Int        List       loop        match         mod         mut         new
None       null       Ok          Option       prompt      Result
return     retry_limit self       session      Some        spawn
String     struct     super       true         Tuple       until
use        using      when        while        with
```

`as` is reserved for future compatible extension even though v1 has no alias
form for `use`. `true` and `false` are `Bool` literals. `null` remains reserved
because absence is written as typed `None` rather than as a source null value.
Reserved type and constructor names are case-sensitive. Lexing uses maximal
munch for the fixed multi-character terminals `::`, `->`, `=>`, `==`, `!=`,
`<=`, `>=`, `&&`, `||`, `+=`, `-=`, `*=`, `/=`, and `%=`; trivia MUST NOT
split one of those terminals.

### 13.3 Package declarations and types

```ebnf
item                    = agents_declaration
                        | default_agent_declaration
                        | file_module_declaration
                        | inline_module_declaration
                        | use_declaration
                        | struct_declaration
                        | enum_declaration
                        | action_declaration
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
                          [ struct_field_list ], "}" ;
struct_field_list       = struct_field, { ",", struct_field }, [ "," ] ;
struct_field            = identifier_token, ":", value_type,
                          [ "=", field_default ] ;
field_default           = boolean_literal
                        | [ "-" ], integer_literal_token
                        | [ "-" ], float_literal_token
                        | string_token
                        | raw_string_token
                        | "None" ;

enum_declaration        = "enum", identifier_token, "{",
                          enum_variant, { ",", enum_variant }, [ "," ], "}" ;
enum_variant            = identifier_token, [ "(", value_type, ")" ] ;

action_declaration      = "action", identifier_token, "(",
                          [ action_parameter_list ], ")",
                          [ result_annotation ], ";" ;
action_parameter_list   = action_parameter, { ",", action_parameter }, [ "," ] ;
action_parameter        = identifier_token, ":", value_type ;

value_type              = "Bool"
                        | "Int"
                        | "Float"
                        | "String"
                        | "Decision"
                        | qualified_path
                        | "Option", "<", value_type, ">"
                        | "Result", "<", value_type, ",", value_type, ">"
                        | "List", "<", value_type, ">"
                        | "Tuple", "<", value_type, ",", value_type,
                          { ",", value_type }, [ "," ], ">" ;
result_type             = value_type | "None" ;
result_annotation       = "->", result_type ;
```

The built-in type alternatives take precedence over `qualified_path`. A
`Tuple` has at least two member types by grammar. An enum has at least one
variant, and an action declaration has no body. `None` in a result annotation
is the no-result type; `None` in an expression is the absent value of an
expected `Option<T>`. Field defaults are deliberately limited to primitive
literals, optionally negated numeric literals, strings, and `None` in v1.
Their declared field type MUST accept the default without coercion.

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
parameter               = [ "mut" ], identifier_token, ":", value_type ;

decision_declaration    = "decision", identifier_token, "(",
                          [ parameter_list ], ")", block ;

impl_declaration        = "impl", qualified_path, "{",
                          { method_declaration }, "}" ;
method_declaration      = "fn", identifier_token, "(", receiver,
                          [ ",", parameter_list ], ")",
                          [ result_annotation ], block ;
receiver                = "self" | "mut", "self" ;
```

A function signature without a result annotation returns no result, exactly as
if it had `-> None`. `mut` on a non-receiver parameter permits mutation of that
workflow's deep-copied local argument; it does not affect the caller. A method
always has a receiver as its first parameter. Associated functions without a
receiver are excluded from v1. A `decision` has no source-level result
annotation because its `Decision` result type and schema are implied by the
declaration. The `self` token is valid only within the lexical body of an
inherent method, including nested blocks and spawned blocks inside that method;
it is an analysis error in a free function, decision workflow, field default,
or module-level declaration. A spawned block captures `self` under the copy
rules in Section 10 rather than introducing a new receiver.

### 13.5 Blocks and statements

```ebnf
block                   = "{", { statement }, [ trailing_expression ], "}" ;
value_block             = "{", { statement }, trailing_expression, "}" ;
statement_block         = "{", { statement }, "}" ;

statement               = let_statement
                        | assignment_statement
                        | expression_statement
                        | return_statement
                        | break_statement
                        | continue_statement
                        | spawn_statement
                        | detach_statement
                        | with_statement
                        | session_statement
                        | if_statement
                        | if_let_statement
                        | loop_statement
                        | while_statement
                        | until_statement ;

let_statement           = "let", let_binding, ":",
                          value_type, "=", expression, ";" ;
let_binding             = [ "mut" ], identifier_token | tuple_pattern ;
assignment_statement    = assignment_target, assignment_operator,
                          expression, ";" ;
assignment_operator     = "=" | "+=" | "-=" | "*=" | "/=" | "%=" ;
assignment_target       = identifier_token, { ".", identifier_token }
                        | "self", ".", identifier_token,
                          { ".", identifier_token } ;
expression_statement    = expression, ";" ;
with_statement          = "with", identifier_token, statement_block ;
session_statement       = "session", "(", session_directive, ")",
                          statement_block ;
return_statement        = "return", [ return_expression ], ";" ;
return_expression       = expression ;
break_statement         = "break", ";" ;
continue_statement      = "continue", ";" ;
trailing_expression     = expression ;
```

Bindings require explicit types in v1. `mut` is valid only on a single-name
binding; tuple destructuring introduces immutable bindings. A trailing expression is distinguished
from an expression statement by the absence of `;` immediately before the
closing brace. A trailing expression MUST produce a first-class value; a
no-result operation must instead be an expression statement ending in `;`.
`return;` is valid only in a no-result function, method, or spawned block.
`break` and `continue` are valid only in a loop body. A decision workflow uses
the ordinary block grammar because `Decision` is a first-class value. Semantic
analysis applies the definite-`Decision` return requirement in Section 9.
Assignment to `self` as a whole is not v1 syntax; a
`mut self` method may assign its receiver fields and may return the resulting
receiver value.

### 13.6 Expressions

```ebnf
expression              = logical_or_expression ;
logical_or_expression   = logical_and_expression,
                          { "||", logical_and_expression } ;
logical_and_expression  = equality_expression,
                          { "&&", equality_expression } ;
equality_expression     = ordering_expression,
                          { ("==" | "!="), ordering_expression } ;
ordering_expression     = additive_expression,
                          { ("<" | "<=" | ">" | ">="),
                            additive_expression } ;
additive_expression     = multiplicative_expression,
                          { ("+" | "-"), multiplicative_expression } ;
multiplicative_expression
                        = unary_expression,
                          { ("*" | "/" | "%"), unary_expression } ;
unary_expression        = ("!" | "-"), unary_expression
                        | complete_expression
                        | postfix_expression ;
complete_expression     = prompt_expression
                        | decide_expression
                        | action_expression
                        | match_expression
                        | join_expression
                        | joinall_expression
                        | with_expression
                        | session_expression ;

postfix_expression      = primary_expression, { postfix_suffix } ;
postfix_suffix          = ".", postfix_member_name
                        | "(", [ argument_list ], ")"
                        | "[", expression, "]" ;
postfix_member_name     = identifier_token | "join" ;
primary_expression      = boolean_literal
                        | integer_literal_token
                        | float_literal_token
                        | string_token
                        | raw_string_token
                        | "None"
                        | "Some", "(", expression, ")"
                        | "Ok", "(", expression, ")"
                        | "Err", "(", expression, ")"
                        | "self"
                        | struct_expression
                        | enum_expression
                        | list_expression
                        | tuple_expression
                        | qualified_path
                        | "(", expression, ")" ;

struct_expression       = qualified_path, "{", [ field_initializer_list ], "}" ;
field_initializer_list  = field_initializer, { ",", field_initializer },
                          [ "," ] ;
field_initializer       = identifier_token, ":", expression ;
argument_list           = expression, { ",", expression }, [ "," ] ;

enum_expression         = qualified_path, "::", identifier_token,
                          [ "(", expression, ")" ] ;
list_expression         = "[", [ argument_list ], "]" ;
tuple_expression        = "(", expression, ",", expression,
                          { ",", expression }, [ "," ], ")" ;

action_expression       = "action", [ action_modifiers ], qualified_path,
                          "(", [ argument_list ], ")" ;
action_modifiers        = "(", "retry_limit", "=",
                          directive_integer_token, ")" ;

match_expression        = "match", expression, "{",
                          match_arm, { match_arm }, "}" ;
match_arm               = pattern, "=>", match_arm_body, "," ;
match_arm_body          = expression | block ;

pattern                 = "_"
                        | identifier_token
                        | "None"
                        | "Some", "(", pattern, ")"
                        | "Ok", "(", pattern, ")"
                        | "Err", "(", pattern, ")"
                        | qualified_path, "::", identifier_token,
                          [ "(", pattern, ")" ]
                        | tuple_pattern ;
tuple_pattern           = "(", pattern, ",", pattern,
                          { ",", pattern }, [ "," ], ")" ;

with_expression         = "with", identifier_token, value_block ;
session_expression      = "session", "(", session_directive, ")",
                          value_block ;
boolean_literal         = "true" | "false" ;
```

The grammar admits `self` as a primary expression so the same expression
productions can parse method bodies and their nested blocks. Semantic analysis
MUST enforce the receiver scope specified in Section 13.4.

Postfix `(...)` dispatches a workflow function or method or invokes one of the
sealed built-ins defined in Section 5. These include numeric conversion,
primitive formatting, String query/transformation/parsing, `List<T>.len()`,
and `List<String>.join(separator)`. Postfix `.name`
accesses a struct field, selects a method, or selects the read-only
`Decision.decision` or `Decision.rationale` field. Postfix `[expression]`
projects a list when the index has type `Int`; tuple projection still requires
a nonnegative compile-time integer literal so its result type is statically
known. Bracketed expressions construct lists; parentheses containing at least
two comma-separated expressions construct tuples, while `(value)` remains
grouping. Operators use the precedence shown by the grammar, all binary
operators associate left to right, and parentheses override precedence.

An unqualified primary path used as a value MUST resolve to a visible parameter
or binding. A qualified item path is valid in an expression only as the callee
of a workflow call, the action path after `action`, or the type path beginning
a struct or enum constructor. Because v1 has no module, type, function,
decision, action, or method values, semantic analysis MUST reject a bare path
that resolves to any such item. Task handles are legal only in `join`,
`joinall()`, and `detach`, never as primary expressions.

A value-producing `with` or `session` expression requires its block's trailing
expression and yields that value. These forms permit a lexical agent or session
context to produce the enclosing workflow's result. Their statement-only forms
in Section 13.5 have no result and take no semicolon after the closing brace. A
value-producing context expression MAY still be followed by `;` when its value
is intentionally discarded.

`prompt`, `decide`, `action`, `match`, `join`, `joinall()`, `with`, and
`session` are complete expression forms rather than direct bases of a postfix
chain. To select a field, invoke a method, or project from one of their results
without first binding it, source MUST parenthesize that expression, as in
`(join(first, second))[0]`. This explicit grouping avoids ambiguity between
operation result annotations and operations on the produced value.

Semantic analysis MUST validate every postfix step from left to right. A call
suffix is legal only on a function or decision item, selected inherent method,
or a sealed deterministic built-in defined in Section 5 with exactly its
declared argument count and types;
a field suffix is legal only on a struct value, selected inherent method, or a
read-only `Decision` field; and an index suffix is legal only on a list or
tuple value. Calling another value, selecting an unsupported field, indexing
another type, or continuing a postfix chain after a no-result expression is an
analysis error.

### 13.7 Prompts and interpolation

```ebnf
prompt_expression       = "prompt", [ prompt_modifiers ], prompt_template,
                          [ using_clause ], [ result_annotation ] ;
prompt_modifiers        = "(", prompt_modifier,
                          { ",", prompt_modifier }, [ "," ], ")" ;
prompt_modifier         = "session", "=", session_directive
                        | "retry_limit", "=", directive_integer_token ;
session_directive       = "inline" | "fork" | "new" ;
prompt_template         = string_token | raw_string_token
                        | block_prompt_token ;

using_clause            = "using", "{", named_input,
                          { ",", named_input }, [ "," ], "}" ;
named_input             = identifier_token,
                          [ ":", interpolation_expression ] ;

interpolation           = "${", interpolation_expression, "}" ;
interpolation_expression
                        = interpolation_logical_or ;
interpolation_logical_or
                        = interpolation_logical_and,
                          { "||", interpolation_logical_and } ;
interpolation_logical_and
                        = interpolation_equality,
                          { "&&", interpolation_equality } ;
interpolation_equality  = interpolation_ordering,
                          { ("==" | "!="), interpolation_ordering } ;
interpolation_ordering  = interpolation_additive,
                          { ("<" | "<=" | ">" | ">="),
                            interpolation_additive } ;
interpolation_additive  = interpolation_multiplicative,
                          { ("+" | "-"), interpolation_multiplicative } ;
interpolation_multiplicative
                        = interpolation_unary,
                          { ("*" | "/" | "%"), interpolation_unary } ;
interpolation_unary     = ("!" | "-"), interpolation_unary
                        | interpolation_postfix ;
interpolation_postfix   = interpolation_primary,
                          { interpolation_suffix } ;
interpolation_suffix    = ".", interpolation_member_name
                        | "(", [ interpolation_argument_list ], ")"
                        | "[", interpolation_expression, "]" ;
interpolation_member_name
                        = identifier_token | "join" ;
interpolation_argument_list
                        = interpolation_expression,
                          { ",", interpolation_expression }, [ "," ] ;
interpolation_primary   = boolean_literal
                        | integer_literal_token
                        | float_literal_token
                        | string_token
                        | raw_string_token
                        | "None"
                        | "Some", "(", interpolation_expression, ")"
                        | "Ok", "(", interpolation_expression, ")"
                        | "Err", "(", interpolation_expression, ")"
                        | interpolation_struct
                        | interpolation_list
                        | interpolation_tuple
                        | interpolation_enum
                        | identifier_token
                        | "self"
                        | "(", interpolation_expression, ")" ;
interpolation_struct    = qualified_path, "{",
                          [ interpolation_field_list ], "}" ;
interpolation_field_list
                        = interpolation_field,
                          { ",", interpolation_field }, [ "," ] ;
interpolation_field     = identifier_token, ":",
                          interpolation_expression ;
interpolation_list      = "[", [ interpolation_expression,
                          { ",", interpolation_expression }, [ "," ] ], "]" ;
interpolation_tuple     = "(", interpolation_expression, ",",
                          interpolation_expression,
                          { ",", interpolation_expression }, [ "," ], ")" ;
interpolation_enum      = qualified_path, "::", identifier_token,
                          [ "(", interpolation_expression, ")" ] ;
```

`interpolation` is a contextual scanner production embedded within a
`prompt_template`; it is intentionally not referenced as an ordinary parser
nonterminal. The contextual scan produces one template syntax value while
retaining its ordered literal segments and interpolation islands. This keeps a
generic non-prompt `string_token` free of interpolation semantics.

When the parser expects the prompt template immediately following `prompt` or
`decide`, the lexer MUST enter contextual template mode. It identifies the
opening delimiter and then scans literal segments, `$$` escapes, and balanced
interpolation islands together; it MUST NOT first terminate a generic string
token and search its completed body afterward. An outer closing delimiter is
recognized only while scanning a literal segment, never while scanning an
interpolation island. Within an island, ordinary Gantry tokens—including
quoted and raw strings—use their normal lexical rules. This makes source such
as `${Some("draft")}` valid inside an ordinary quoted prompt without requiring
the island's quotes to be escaped for the outer template. Structural opening
and closing lines of a block prompt are delimiters rather than body text and
are excluded from this scan. `${` opens an interpolation unless its `$` was
consumed by `$$`. `$$` emits one literal `$`; therefore `$${name}` emits
literal `${name}`. This contextual mode applies to normal, raw, and block
prompt templates. In non-prompt string expressions, `$` and `${...}` are
ordinary string contents and are not interpolated.

The scan proceeds left to right over authored dollar signs. Thus `$$${name}`
emits one literal `$` followed by the interpolation of `name`. An ordinary or
block-prompt escape such as `\u{24}` that later decodes to `$` does not begin
interpolation; `\u{24}{name}` emits the literal text `${name}`. Once islands
have been recognized, escapes are decoded independently in the intervening
literal segments and block-prompt dedentation is applied without changing the
authored source text retained for an island. Raw strings skip escape decoding
but use the same left-to-right interpolation and `$$` rules. A closing `}` ends
an island only when all nested constructor braces and parentheses inside it are
balanced.
The contextual scanner MUST tokenize the island using the ordinary Gantry
lexical rules, so braces or parentheses inside nested quoted or raw string
tokens do not affect that balance and comment delimiters inside those strings
remain literal text. An unclosed or syntactically invalid island is a syntax
error.

Interpolation and named inputs permit only the restricted grammar above. A
postfix call is legal only for the sealed deterministic built-ins in Section
5, with the exact argument count and types defined there; it cannot dispatch a
workflow or source-defined method.
A projection index MUST obey the list and tuple rules in Section 5. Neither
form admits any other function or method call, `prompt`, `decide`, `action`,
joins, mutation, or control flow. Primitive operators use the same typing,
precedence, short-circuiting, checked arithmetic, and deterministic-failure
rules as ordinary expressions. Plain `String` interpolation of a computed
String still inserts its unquoted contents. A deterministic built-in failure,
including an empty split or replacement pattern or a size-limit failure,
prevents the containing operation from being dispatched. Nested braces
belonging to a constructor are
balanced before the interpolation's closing `}` is recognized.
Duplicate prompt modifiers and duplicate named-input names are analysis
errors. `retry_limit` counts retries after the initial attempt.

### 13.8 Decisions and sequential control flow

```ebnf
if_statement            = "if", condition_expression, statement_block,
                          { "else", "if",
                            condition_expression, statement_block },
                          [ "else", statement_block ] ;

if_let_statement        = "if", "let", pattern, "=", expression,
                          statement_block, [ "else", statement_block ] ;

condition_expression    = expression ;
decide_expression       = "decide", [ prompt_modifiers ], prompt_template,
                          [ using_clause ] ;

loop_statement          = "loop", [ loop_modifiers ], statement_block ;
loop_modifiers          = "(", loop_modifier,
                          { ",", loop_modifier }, [ "," ], ")" ;
loop_modifier           = "session", "=", session_directive
                        | "limit", "=", directive_integer_token ;

while_statement         = "while", [ loop_condition_modifiers ],
                          condition_expression, statement_block ;
until_statement         = "until", [ loop_condition_modifiers ],
                          statement_block,
                          "when", condition_expression, ";" ;
loop_condition_modifiers
                        = "(", loop_condition_modifier,
                          { ",", loop_condition_modifier }, [ "," ], ")" ;
loop_condition_modifier = "session", "=", session_directive
                        | "limit", "=", directive_integer_token ;
```

The optional modifier forms require at least one modifier when parentheses are
present; empty `prompt()`, `decide()`, `loop()`, `while()`, and `until()`
modifiers are not v1 syntax. Bare `loop` uses
`session = inline` and `limit = 0`. Duplicate modifiers are analysis errors.

`if` and `else if` have no condition-level modifiers. An author who wants a
condition and its selected arm to share one explicit session wraps the complete
conditional in `session(<directive>) { ... }`; an author who wants to configure
one model judgment places modifiers directly on its visible `decide` expression.
On `while` and `until`, the modifier position declares the loop session and
limit whose condition/body lifetime is defined normatively in Section 9.
`limit` belongs only to the enclosing loop. A modifier written directly on a
`decide` expression affects only that operation. The `until` grammar deliberately
places its body before `when` and the post-test condition.
Semantic analysis MUST require every `condition_expression` to have type
`Bool` or `Decision`. Ordinary and decision workflow calls share one
Rust-inspired call syntax and are distinguished by their resolved result type
rather than by parser guessing.

### 13.9 Parallel control flow

```ebnf
spawn_statement         = "spawn", identifier_token, result_annotation, block ;
detach_statement        = "detach", "(", identifier_token, ")", ";" ;
join_expression         = "join", "(", identifier_token,
                          { ",", identifier_token }, [ "," ], ")" ;
joinall_expression      = "joinall", "(", ")" ;
```

Every spawn has an explicit result annotation, including `-> None`. `join`
requires at least one handle. `joinall()` takes no arguments.
`detach` consumes exactly one attached task handle and is a statement rather
than a value-producing expression.
Static result typing follows Section 10: one value for one task, `List<T>` for
multiple homogeneous results, and `Tuple<T1, ..., Tn>` for multiple
heterogeneous results.

## 14. Syntax Examples

The examples in this section are illustrative complete programs or focused
fragments. Except for snippets explicitly labeled invalid in Section 14.13,
they use only v1 syntax. Comments beginning with `//` explain the example and
are valid Gantry comments.

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
use crate::domain::Report;

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

### 14.3 Primitive values, structs, tagged values, and structural routing

```gantry
struct Metadata {
    source: String,
    note: Option<String> = None,
}

struct Draft {
    title: String,
    body: String,
    revision: Int = 0,
    confidence: Float = 0.0,
    publishable: Bool = false,
    metadata: Metadata,
}

fn revise(seed: Draft) -> Draft {
    let mut draft: Draft = seed;
    draft.body = prompt "Rewrite this body clearly: ${draft.body}" -> String;
    draft.revision += 1;
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

Enums, aggregate literals, patterns, and exact equality provide deterministic
routing over already validated structure:

```gantry
enum ReviewOutcome {
    Approved(Draft),
    NeedsRevision(String),
    Cancelled,
}

fn route_review(draft: Draft) -> Draft {
    let labels: List<String> = ["draft", "review"];
    let pair: Tuple<String, List<String>> = (draft.title, labels);
    let (title, copied_labels): Tuple<String, List<String>> = pair;

    if let Some(note) = draft.metadata.note {
        prompt "Record the existing editorial note."
            using { note, title, copied_labels };
    }

    let outcome: ReviewOutcome = prompt "Classify the supplied draft."
        using { draft }
        -> ReviewOutcome;

    match outcome {
        ReviewOutcome::Approved(approved) => approved,
        ReviewOutcome::NeedsRevision(feedback) => prompt
            "Revise the supplied draft."
            using { draft, feedback }
            -> Draft,
        ReviewOutcome::Cancelled => draft,
    }
}

fn compare_titles(left: Draft, right: Draft) -> String {
    if left.publishable && right.publishable && left.title == right.title {
        return "same";
    } else {
        return "different";
    }
}
```

Primitive operators are deterministic and checked. List elements have one
exact type, tuple positions may differ, and pattern bindings are immutable deep
copies. `if let`, `match`, Boolean algebra, and equality do not dispatch hooks;
the visible `prompt` operations still perform the semantic classification and
revision work.

Numeric conversion, precedence, list length, and dynamic indexing support
bounded deterministic traversal without hiding model work:

```gantry
fn average(scores: List<Float>) -> Float {
    let mut index: Int = 0;
    let mut total: Float = 0.0;

    while index < scores.len() {
        total += scores[index];
        index += 1;
    }

    total / scores.len().to_float()
}

fn exact_count(value: Float) -> Option<Int> {
    value.to_int()
}
```

An empty list would make `average` fail through checked floating-point
division by zero; callers must establish that precondition before calling it.

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
        }
    }
}

fn apply_revision(mut report: Report, instruction: String) -> Report {
    // Receivers are copied. Retaining the revised copy requires assignment.
    report = report.revise(instruction);
    report
}
```

`with` is an expression and may yield its block's trailing value. A nested
`with` would override `writer` or `reviewer` only inside the nested block.
When a `with` block is used only for its effects, as in `review`, it is a
statement and takes no semicolon after its closing brace.
The `apply_revision` assignment makes the by-value receiver rule visible: a
`mut self` method never updates the caller's binding implicitly.

A lexical session context applies one session choice to several explicit
operations. Here both prompts share one logical child session forked from the
caller's active session:

```gantry
fn investigate(report: Report) -> Report {
    with researcher {
        session(fork) {
            let plan: String = prompt
                "Plan a focused investigation of ${report}."
                -> String;

            prompt
                "Follow this plan: ${plan}\nInvestigate: ${report}"
                -> Report
        }
    }
}
```

The `session` block does not hide model work: each hook site remains a visible
`prompt` or `decide`. `session(new)` would instead start one conversation with
no inherited context, while `session(inline)` would explicitly reuse the
enclosing conversation.

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
lines and without adding structural leading or trailing newlines:

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

Basic text preparation remains deterministic and visibly separate from model
judgment:

```gantry
fn prepare_label(mut topic: String, attempt: Int) -> String {
    topic = topic.trim().to_lowercase();
    topic += " #";
    topic += attempt.to_string();
    topic
}

fn route_text(command: String) -> String {
    if command.trim().starts_with("review:") {
        return "review";
    }

    if decide "Does ${command} request a semantic review?" {
        return "review";
    }

    "other"
}

fn assemble_prompt(lines: List<String>) -> String {
    let body: String = lines.join("\n");
    prompt "Summarize these lines:\n${body}" -> String
}

fn parse_settings(enabled_text: String, count_text: String)
    -> Tuple<Option<Bool>, Option<Int>> {
    (enabled_text.trim().parse_bool(), count_text.trim().parse_int())
}
```

`len()` counts Unicode scalar values. `split` preserves empty segments and
`replace` uses nonoverlapping matches:

```gantry
let scalar_count: Int = "é".len();
let parts: List<String> = ",a,,b,".split(",");
let revised: String = "aaaa".replace("aa", "b");
// scalar_count is 1, parts is ["", "a", "", "b", ""], revised is "bb".
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

The `decide` expression visibly requests the `Decision` schema and never
accepts a `->` annotation. The resulting sealed value may be retained and
reused without another hook dispatch:

```gantry
fn retain_decision(report: Report) -> String {
    let readiness: Decision = decide
        "Is this report ready?"
        using { report };
    let allowed: Bool = readiness.decision;

    if allowed {
        return readiness.rationale;
    } else {
        return prompt "Explain the next revision."
            using { report, readiness }
            -> String;
    }
}
```

The `else if` hook receives the preceding
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

This example asks for semantic judgment. Mechanical option presence checks can
instead use `if let` or `match`, while ordinary comparisons and Boolean
operators produce first-class `Bool` values without model dispatch.

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
A positive `loop` or `while` limit completes normally without another
decision after its final body. An `until` body always performs its matching
post-test; if that decision is false at the positive limit, the loop then
completes normally. `limit = 0` means unlimited execution.

### 14.8 Parallel homogeneous work and `List<T>` joins

```gantry
fn parallel_research(topic: String) -> List<Report> {
    spawn primary -> Report {
        with researcher {
            prompt "Research primary sources for ${topic}." -> Report
        }
    }

    spawn independent -> Report {
        with reviewer {
            prompt "Independently research ${topic}." -> Report
        }
    }

    let reports: List<Report> = join(primary, independent);
    reports
}
```

The returned list follows join argument order, not task completion order. Each
spawned task begins in its own forked child session, so its default `inline`
prompt preserves inherited context without sharing one mutable conversation
with its sibling. The result can be projected deterministically when a known
position is needed, for example `let primary_report: Report = reports[0];`.

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

Tuple positions follow the explicit join argument order. V1 code can pass,
return, project, or destructure `pair`:

```gantry
let (headline_text, full_report): Tuple<String, Report> = pair;
```

The destructuring is deterministic and does not invoke an operation hook.

### 14.10 `joinall()`, no-result tasks, and detachment

```gantry
fn collect_all(topic: String) -> List<Report> {
    spawn first -> Report {
        prompt "Investigate the first perspective on ${topic}." -> Report
    }

    spawn second -> Report {
        prompt "Investigate the second perspective on ${topic}." -> Report
    }

    let reports: List<Report> = joinall();
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

    joinall();
}
```

Named joins can wait for a selected set of no-result tasks without manufacturing
an unused aggregate value:

```gantry
fn audit_selected(report: Report) {
    spawn security_audit -> None {
        prompt "Perform a security audit of ${report}.";
    }

    spawn style_audit -> None {
        prompt "Perform a style audit of ${report}.";
    }

    join(security_audit, style_audit);
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

Control flow may deliberately choose whether to wait for work or leave it in
the background. Both branches consume the handle, so it is unavailable after
the conditional even though the durable consumption mode differs by path:

```gantry
fn launch_or_wait(report: Report) {
    spawn audit -> None {
        prompt "Audit ${report}.";
    }

    if decide "Must this audit finish before the workflow continues?" {
        join(audit);
    } else {
        detach(audit);
    }
}
```

### 14.11 Nested modules and qualified paths

```gantry
struct Input {
    text: String,
}

mod quality {
    use crate::Input;

    struct Finding {
        summary: String,
    }

    mod formatting {
        use super::Finding;

        fn normalize(finding: Finding) -> Finding {
            prompt "Normalize ${finding}." -> Finding
        }
    }

    fn inspect(input: Input) -> Finding {
        let finding: self::Finding = prompt "Inspect ${input}." -> Finding;
        formatting::normalize(finding)
    }
}

fn run_check(input: Input) -> quality::Finding {
    quality::inspect(input)
}
```

`crate::` begins at the package root, `self::` begins at the current module,
and `super::` moves to the parent module. Unprefixed paths such as
`formatting::normalize` begin in the current module.

The equivalent imported form is:

```gantry
use quality::Finding;
use quality::inspect;

fn run_imported_check(input: Input) -> Finding {
    inspect(input)
}
```

### 14.12 Explicit harness actions and named prompt inputs

Actions declare typed harness capabilities and remain visually distinct from
ordinary workflow calls:

```gantry
struct SearchRequest {
    query: String,
}

struct SearchFailure {
    message: String,
}

struct Source {
    title: String,
    url: String,
}

action web_search(request: SearchRequest)
    -> Result<List<Source>, SearchFailure>;
action publish(report: Report) -> None;

fn research(topic: String) -> Report {
    let request: SearchRequest = SearchRequest { query: topic };
    let search: Result<List<Source>, SearchFailure> =
        action web_search(request);

    let sources: List<Source> = match search {
        Ok(value) => value,
        Err(error) => prompt "Recover source material after the search failure."
            using { error, topic }
            -> List<Source>,
    };

    let report: Report = prompt "Write a sourced report." using {
        topic,
        sources,
    } -> Report;

    action publish(report);
    report
}
```

`using` carries ordered typed values separately from rendered prompt text.
`${...}` remains available when exact textual placement is meaningful. The
action declaration, action invocation, and result contract are visible in
source; provider-internal tools used while fulfilling another hook do not
create hidden Gantry operations.

### 14.13 Common invalid forms and their corrections

The following non-normative examples collect source shapes that can look
plausible to a human or model author but are intentionally invalid in v1.
Keeping these boundaries visible is part of Gantry's clean-syntax goal.

An interpolation cannot hide another model-backed workflow call:

```gantry
// Invalid: workflow calls are not permitted inside interpolation.
prompt "Rewrite this critique: ${make_critique(report)}" -> Report

// Valid: operation order is explicit in separate source expressions.
let critique: String = make_critique(report);
prompt "Rewrite this critique: ${critique}" -> Report
```

An unannotated prompt has no source value. `Decision` is first-class but is not
a `String` or an ordinary `Bool`:

```gantry
// Invalid: the prompt returns no source value.
let summary: String = prompt "Summarize the report.";

// Valid: the result contract is visible.
let summary: String = prompt "Summarize the report." -> String;

// Invalid: the declared binding type is wrong.
let answer: String = decide "Is the report complete?";

// Valid: retain the sealed Decision and use it as a condition.
let answer: Decision = decide "Is the report complete?";
if answer {
    prompt "Publish the report.";
}

// Valid: project its controlling Bool when deterministic composition is needed.
let approved: Bool = answer.decision;
```

String operations never perform implicit conversion, and empty split or
replacement patterns are deterministic runtime errors:

```gantry
// Invalid: `attempt` is not implicitly converted to String.
let label: String = "attempt " + attempt;

// Valid: conversion is explicit.
let label: String = "attempt " + attempt.to_string();

// Runtime error: empty separators and replacement patterns are prohibited.
let pieces: List<String> = text.split("");
let expanded: String = text.replace("", "-");
```

Task handles are linear ownership markers rather than ordinary values. Every
normal path leaving their scope must visibly join or detach them:

```gantry
// Invalid: `audit` remains attached when the function returns.
fn start_invalid(report: Report) {
    spawn audit -> None {
        prompt "Audit ${report}.";
    }
}

// Valid: background ownership is transferred explicitly.
fn start_background(report: Report) {
    spawn audit -> None {
        prompt "Audit ${report}.";
    }
    detach(audit);
}
```

Mechanical option inspection is deterministic; semantic judgment remains
model-backed:

```gantry
// Valid: structural presence check, with no hook dispatch.
if let Some(report) = maybe_report {
    prompt "Publish ${report}.";
}

// Also valid: semantic publication judgment is model-backed and visible.
if decide "Should this optional report be published? ${maybe_report}" {
    prompt "Handle publication for ${maybe_report}.";
}
```

These invalid examples are explanatory only; the normative grammar and
semantic requirements in Sections 5, 6, 9, 10, and 13 determine rejection.

## 15. Required Embedding Interfaces

Concrete Rust names and signatures MAY evolve during implementation, but a v1
embedding API MUST expose the following semantic interfaces without requiring
provider-specific or executor-specific types in Gantry programs:

1. An `Interpreter` accepts a package root, an explicitly selected supported
   source-language version, interpreter configuration (which includes the
   executor adapter), a hook factory, journal storage, and zero or more event
   sinks. It MUST expose syntax-only validation, semantic analysis, execution,
   resume, execution cancellation, and terminal asynchronous shutdown
   operations. Dry-run, analysis, and new execution MUST use the selected
   source-language version. Resume MUST use the version stored in the
   execution-start record and MUST reject an incompatible caller selection as
   a resume-start compatibility failure. Execution cancellation accepts an
   execution ID and a structured reason, is idempotent, and implements Section
   10 rather than requiring the embedder to manipulate executor handles
   directly. Resume
   MUST identify the execution or journal to load and reconstruct state only
   from the authoritative durable record prefix returned by journal storage,
   and MUST obtain the exclusive execution ownership required by Section 11
   before advancing it.
   A new-execution request MUST identify a fresh journal target through an
   embedder-supplied stable journal ID. Allocation of that ID and its storage
   target is an integration concern completed before calling Gantry. The API
   MUST return that journal identity even when startup fails, while it MUST
   return an accepted execution ID only after the execution-start record is
   durable. This distinction permits inspection or resume after an uncertain
   storage response without presenting an uncommitted candidate execution as
   accepted. Execution accepts either no entry input or one raw byte sequence
   containing strict JSON as required by `main`; Gantry, rather than the
   embedder, performs the decoding, parsing, duplicate-member rejection, and
   schema validation defined in Section 4. It MUST also accept an optional
   root-session
   specification containing an embedder-chosen logical session ID. When that
   specification is present, the embedder MUST arrange for the hook integration
   to resolve the ID to its integration-owned conversational context; Gantry
   treats that context as opaque and does not serialize it. When the
   specification is absent, Gantry creates the fresh root session required by
   Section 7. Resume MUST restore the journaled root-session identity and MUST
   NOT accept a replacement. Failure to resolve an embedder-supplied root
   session is an integration-preflight start failure for a new execution;
   failure to resolve any required journaled session is a nonterminal resume-
   start failure. Before resume creates recovered task hooks, the API MUST
   enumerate every journaled logical session needed by unfinished work,
   including its parent and creation provenance, and require the integration
   to resolve the complete set as specified in Section 7. Resume MUST dispatch no hook when
   this preflight fails. Starting a new execution MUST return either a
   structured start failure with no execution ID, or an execution ID after the
   execution-start record is durably flushed. Syntax, analysis, entry-input,
   integration-preflight, initial journal-ownership, execution-start write,
   and required-event-delivery failures during pre-execution validation or
   analysis are start failures. Returning the execution ID establishes an
   accepted, resumable execution handle; it does not by itself report that
   `main` has completed. The API MUST let the embedder asynchronously await or
   query the foreground outcome through that handle while detached work, when
   any, continues toward terminal execution state.
   Resume MUST likewise return a structured
   resume-start failure when Section 7 preflight fails, without changing the
   execution's durable state, and MUST permit a later corrected resume attempt.
   Once recovered interpretation begins, resume returns the same execution
   handle and foreground-outcome categories as a new execution. If foreground
   completion is already durable, resume MUST expose that preserved outcome
   without invoking `main` again while it recovers unfinished detached work.
   If terminal execution is already durable, resume performs only the unsettled
   event-delivery recovery permitted by Section 11 and exposes the existing
   terminal outcome without creating a task or dispatching a hook.
   A typed foreground outcome distinguishes a value, no result, and every
   runtime-error category defined in Section 7. A foreground outcome MAY be
   returned while explicitly detached tasks remain;
   the execution ID allows the embedder to correlate their later events and
   terminal durable state. Because event sinks are optional, the API MUST also
   permit the embedder to query an execution's latest durable foreground and
   terminal states and to asynchronously wait for terminal state by execution
   ID. Foreground-await and terminal-await results MUST represent the Gantry
   language outcome separately from the required-event-delivery barrier
   status. A delivery-barrier failure MUST NOT masquerade as, replace, or erase
   a durable foreground or terminal language outcome. A terminal language
   result MUST distinguish success, detached-task failure, cancellation, and
   the runtime-error categories defined in Section 7.
2. A `HookFactory` asynchronously creates an `OperationHook` for a supplied
   task context. The factory, or a companion harness-preflight interface owned
   by the same integration, MUST also validate the complete nonempty merged
   agent-name set and every declared canonical action signature, and MUST
   supply each corresponding mapping revision before a new execution begins.
   An empty agent or action declaration set requires no mapping or revision for
   that family. Before resume continues, that preflight MUST resolve every
   applicable active mapping and every unfinished logical session descriptor
   enumerated by Gantry, including root, parent, and creation provenance. For a
   new execution, preflight failure is an
   integration-preflight start failure. For resume, it is the applicable
   nonterminal resume-start failure. It creates no `OperationHook` and MUST
   occur before `main` evaluation or recovered work. Successful preflight does
   not itself dispatch an operation.

   For a `gantry-created` root session, this integration surface MUST also let
   Gantry request establishment of one fresh empty integration-side
   conversational context for the generated logical session ID before that
   root or a session derived from it is first used. That request is session
   setup, not hook creation or model dispatch. Repeating it for the same
   execution and root ID MUST resolve the same context rather than create a
   replacement. The interface MUST return structured success or failure and
   MUST be safe to retry for the same execution and root ID. Gantry invokes it
   only after the execution-start record is durable; failure prevents hook
   creation and is the `logical-session setup` runtime error defined in
   Section 7. An `embedder-supplied` root instead uses the preflight resolution
   required by Section 7.

   Gantry MUST call the factory lazily, at most once per Gantry task in one
   in-process run, immediately before that task's first hook dispatch; a task
   that performs only deterministic interpreter work does not require a hook.
   `OperationHook` asynchronously accepts the versioned request defined in
   Section 7 and a Gantry-owned cancellation token, and returns exactly one
   `Completed(raw_output)`, `Declined(reason)`, or `Failed(message)` outcome.
   `raw_output` is an uninterpreted byte sequence; Gantry owns UTF-8 decoding,
   JSON parsing, schema validation, and repair retries. Hook futures MUST be
   `Send`; one hook instance is used serially for one Gantry task.
   Returning `Completed(raw_output)` means the integration considers the
   operation complete even when the bytes later fail Gantry validation.
   Provider transport failures, timeouts, and integration-internal retry
   exhaustion MUST instead be represented as `Failed(message)`; they MUST NOT
   be encoded as synthetic malformed model output merely to enter Gantry's
   structured-output retry path.
3. A cancellation token is cloneable, safe to observe from multiple threads,
   and transitions monotonically from active to cancelled. Cancellation does
   not itself constitute a hook outcome; an integration that stops work after
   observing cancellation returns `Failed` or lets Gantry surface cancellation
   according to the runtime state.
4. An executor adapter provides asynchronous task spawn, join, abort, and sleep
   capabilities. Gantry MUST use those capabilities rather than constructing a
   hidden Tokio or other provider runtime. Executor handles and errors MUST be
   wrapped so no specific executor type appears in the language-facing API.
5. Journal storage asynchronously provides durable-prefix reads, exclusive
   owner acquisition and release with fencing, plus atomic `append(record)` and
   `flush(sequence)` operations with the behavior in Section 11. Append and
   flush are its only record-mutation primitives. Every mutation call MUST be
   associated with the current opaque ownership token so a superseded process
    cannot advance the journal. The `record` accepted by `append` is an
    unfinalized versioned body without a record ID or sequence number. Append
    atomically assigns both fields, stores the finalized immutable envelope, and
    returns an append receipt containing the assigned stable record ID and the
    assigned contiguous sequence number from the per-journal linearizable
    ordering. A read returns those finalized immutable versioned records in
    sequence order
    together with the durable-through sequence and supports continuation after
    a supplied sequence. Owner release invalidates the supplied fencing token
    atomically and MUST NOT append, update, or delete a journal record.
   Storage errors and malformed or noncontiguous durable histories are never
   retried as model-output failures and MUST surface as journal runtime errors.
6. Each event sink declares a stable identity, its required/best-effort class,
   raw-output capability, enabled redaction policy, and retry policy. Stable
   sink identities MUST be unique within one interpreter configuration. Its
   asynchronous delivery operation receives a versioned event envelope and the
   capability-filtered referenced-payload bundle defined in Section 12, and
   returns success, a retriable error, or a terminal error. Gantry owns delivery
   attempt IDs, finite attempt timeouts, retry timing, payload retention,
   journaling, and required-sink failure semantics. The embedding API MUST
   expose a stable retry-policy revision and finite positive attempt timeout
   for each sink. Gantry journals the effective policy values with each event
   obligation, so recovery does not depend on an embedder retaining historical
   defaults. The embedder MUST resolve every required sink identity
   attached to an unsettled journaled delivery obligation during resume before
   recovered interpretation begins. Failure to resolve one is the nonterminal
   resume-start failure defined in Section 7. An absent best-effort sink is
   handled as the terminal best-effort delivery error defined in Section 12;
   neither case permits the obligation or protected payload references to be
   dropped silently.
   The embedding API MAY additionally accept one non-durable emergency
   diagnostic callback. That callback is not an event sink, receives no
   protected payload by default, and has no delivery, retry, ordering,
   journaling, or at-least-once guarantee. It exists only for best-effort
   reporting when journal-first standard events cannot be created, including
   journal failure and unclean interpreter drop. Failure of this callback MUST
   be ignored after a bounded, nonblocking invocation attempt.
7. Interpreter configuration MUST include the default model-output retry
   limit, the default action-output retry limit, their backoff policy,
   event-delivery retry and attempt-timeout defaults,
   executor adapter, graceful-shutdown timeout, post-cancellation drain
   duration, maximum String scalar count, maximum List item count, and the
   finite nonzero deterministic-transition yield quantum required by Section
   3. The two deterministic-value limits MUST be positive and no greater than
   `9007199254740991`, as required by Sections 5 and 11. Implementations
   MUST accept directive and projection integers through `2^63 - 1` and MAY
   reject larger tokens during analysis. The v1 defaults are 30 seconds for
   each event-delivery attempt, 30 seconds for graceful shutdown, and 5 seconds
   for post-cancellation drain. Event-delivery attempt timeouts MUST remain
   finite and positive. Embedders MAY override shutdown and drain with finite
   nonnegative durations; zero requests immediate cancellation or immediate
   return after cancellation, respectively.
8. All public protocol envelopes MUST carry a major and minor version. A major
   mismatch is incompatible and MUST be rejected. An implementation MAY accept
   a newer minor version only when it ignores unknown optional fields without
   changing the meaning of known fields; unknown required fields or enum
   variants MUST be rejected.
9. Integration-provided hook factories, executor adapters, journal stores, and
   event sinks MUST be `Send + Sync` and safe for Gantry to access from its
   multithreaded tasks. An individual `OperationHook` MUST be `Send` but need
   not be `Sync`, because Gantry owns it within one task and invokes it only
   serially. Futures returned by these interfaces MUST be `Send` for the
   lifetime of their borrows. Gantry MUST package all borrowed state into owned
   task state before submitting a `Send + 'static` future to the executor.
10. Source, entry input, interpolated arguments, prompts, session identifiers,
    raw hook output, normalized values, journals, and protected event payloads
    MUST be treated as potentially sensitive integration data. Gantry MUST NOT
    copy protected payloads into default diagnostics, display strings, or sinks
    that lack the applicable capability. An embedder MUST control access to
    journal storage and payload references and MUST define retention and
    deletion policy for them. It MUST also control whether a diagnostic
    consumer may receive source snippets; absent an explicit source-disclosure
    policy, Gantry diagnostics MUST expose source locations and spans but not
    copied source text. At-rest encryption, credential management, and operator
    authorization remain deployment concerns, but an implementation MUST
    provide enough separation between ordinary diagnostics and protected
    records for an embedder to enforce those policies without parsing free-form
    text.

The canonical serialization format and concrete Rust data-type layout are
implementation choices. They MUST preserve every field, category, ordering,
durability boundary, and compatibility rule made normative by this document.
