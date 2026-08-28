# Gantry Specification

- [Gantry Specification](#gantry-specification)
  - [1. Status and Scope](#1-status-and-scope)
    - [1.1 Language at a glance](#11-language-at-a-glance)
    - [1.2 Reading the surface syntax](#12-reading-the-surface-syntax)
    - [1.3 V1 design boundary](#13-v1-design-boundary)
    - [1.4 Authoring conventions](#14-authoring-conventions)
  - [2. Normative Language](#2-normative-language)
  - [3. Implementation and Execution Model](#3-implementation-and-execution-model)
  - [4. Source Organization](#4-source-organization)
  - [5. Values, Bindings, and Structs](#5-values-bindings-and-structs)
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
    - [14.3 Struct construction, options, bindings, and mutation](#143-struct-construction-options-bindings-and-mutation)
    - [14.4 Inherent methods and lexical agent selection](#144-inherent-methods-and-lexical-agent-selection)
    - [14.5 Prompt strings, interpolation, and escaping](#145-prompt-strings-interpolation-and-escaping)
    - [14.6 Decision workflows and conditional chains](#146-decision-workflows-and-conditional-chains)
    - [14.7 General, pre-test, and post-test loops](#147-general-pre-test-and-post-test-loops)
    - [14.8 Parallel homogeneous work and `List<T>` joins](#148-parallel-homogeneous-work-and-listt-joins)
    - [14.9 Parallel heterogeneous work and `Tuple<...>` joins](#149-parallel-heterogeneous-work-and-tuple-joins)
    - [14.10 `joinall()`, no-result tasks, and detachment](#1410-joinall-no-result-tasks-and-detachment)
    - [14.11 Nested modules and qualified paths](#1411-nested-modules-and-qualified-paths)
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
model-backed work. Bindings, construction, workflow dispatch, assignment,
projection, modules, joins, and task ownership are interpreter operations.
Every source-level request for model-backed work is visibly introduced by
`prompt` or `decide`; an ordinary function or method call does not itself
dispatch a hook, although the called workflow may contain explicit model
operations. An integration may perform provider-internal work while fulfilling
one such request, as defined in Section 7, but that work does not create hidden
Gantry operations. Interpolation never dispatches a hook. Typed strict-JSON
results are the boundary between the interpreter and model-backed work. This
explicitness is a core readability requirement for both human and model
authors.

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

decision needs_revision(report: Report) {
    decide "Does this report need another revision? ${report}"
}

fn main(topic: String) -> Report {
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
        "Synthesize these reports: ${reports}"
        -> Report;

    loop(limit = 3) {
        if(retry_limit = 1) needs_revision(report) {
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
- `decide` visibly performs the model-backed work that controls `if`, `while`,
  and `until`. Its Boolean decision and rationale are interpreter-only and do
  not introduce a source-level Boolean value.
- `${...}` computes deterministic prompt input. It can read and construct
  values, but cannot hide another model call, mutation, join, or control-flow
  transfer.
- `with <agent> { ... }` selects an agent lexically, while
  `session(<directive>) { ... }` selects conversational continuity. Neither
  construct hides the `prompt` and `decide` sites inside it.
- `spawn` makes concurrency explicit. Every spawned handle must be consumed
  visibly by `join`, `joinall()`, or `detach` on every normal path that leaves
  its scope.
- Ordinary calls, assignments, construction, projection, and joins are
  deterministic interpreter work. If source does not contain `prompt` or
  `decide` at a dynamic call path, that path dispatches no model operation.

### 1.3 V1 design boundary

The following non-normative summary makes deliberate v1 omissions visible.
It is a reading aid rather than a substitute for the normative requirements
in later sections:

- Gantry is an orchestration language, not a general-purpose language. Its
  source values are strings, structs, options, lists, and tuples. Boolean
  decisions remain interpreter-only, and integers appear only in directives
  and aggregate projections.
- Model work is limited to the explicit `prompt` and `decide` operations.
  Provider tools and harness actions may be used while fulfilling those
  operations, but v1 has no separate source-level tool or action instruction.
- V1 has no arithmetic, comparison operators, deterministic string
  operations, `for`, `match`, `if let`, user-defined generics, traits, or
  language-level error recovery. Branching on semantic content is deliberately
  agent-mediated.
- Lists and tuples are typed transport aggregates. Source can pass, return,
  interpolate, and project them, but cannot construct literals, iterate over
  them, or query their lengths in v1.
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

Section 14 follows these conventions and serves as the canonical source-style
reference for v1 examples.

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
6. An integration MUST implement the hooks needed to perform agent/model
   calls. It is responsible for mapping Gantry agent names to its own agents
   or models.
7. Model selection, tool access, approvals, authentication, persistence
   backend selection, logging backend selection, operation-level timeouts,
   provider-specific cancellation mechanics, and resource limits belong to
   the integration. Gantry owns the language-level execution, task-ownership,
   and cancellation state transitions defined in Sections 10 and 15 and MUST
   provide Gantry-owned cancellation tokens to integrations. The integration
   chooses applicable policy values and makes a best effort to stop provider
   work when those tokens are signalled. Gantry MUST provide the asynchronous
   task scheduling needed to execute parallel Gantry blocks.
8. Gantry execution MUST be serializable and resumable. Gantry MUST provide a
   journal, or an equivalent durable execution record, sufficient to continue
   an interrupted execution from its recorded state. Section 11 defines the
   required recovery behavior.
9. Gantry does not promise deterministic replay. Re-execution of the same
   source and inputs MAY produce different agent results. Resumption MUST,
   however, reuse every committed physical hook outcome and MUST reuse every
   validated operation result already derived from committed journal state.
   A committed raw `Completed` outcome that has not yet passed validation is
   durable input to resumed validation, not yet a successful operation result.
10. The initial public protocol version for hook requests, journal envelopes,
    event envelopes, and the configuration identity is major `1`, minor `0`.
    A document reference to “v1” identifies source-language version 1 and does
    not by itself permit a different protocol major version.
11. v1 makes no backward-compatibility promise for source, serialized state,
   or the Rust hook API.

## 4. Source Organization

1. Gantry source files MUST use the `.gnt` extension.
2. A package entry point is `main.gnt`, and its selected entry function is
   the root module's `fn main`. The root module MUST declare exactly one
   function named `main`; a missing `main`, a `main` declared only in a child
   module, or any non-function root item named `main` is an analysis error.
   The directory containing `main.gnt` is the package root. `main` MUST have
   either no parameters or exactly one typed parameter and MAY return any v1
   result type or no result. When `main` has a
   parameter, the embedding application MUST supply one raw byte sequence
   containing the entry JSON. Gantry MUST own UTF-8 decoding and RFC 8259 JSON
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
   Section 8 encoding of its declared type.
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
    classification and normalization MUST use Unicode Standard version 15.1.0.
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
    earlier in its parent module, and it does not make functions, types, or
    imports usable before their declarations. Within one module, item names
    MUST be unique across structs, functions, decisions, and modules. An
    imported name MUST NOT collide with another import or local item.
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
   both denote this no-result form; they do not denote `Option<T>`. No-result
   is not a first-class value and cannot be bound, passed, interpolated, or
   constructed. In particular, `return;` exits a no-result body, while
   `return None;` is valid only when an expected `Option<T>` return type gives
   that expression a type; it is not another spelling of a no-result return.
3. `Option<T>`, `List<T>`, and `Tuple<T1, T2, ..., Tn>` MAY appear in
   parameters, bindings, returned values, and struct fields. `Some(value)` and
   `None` MUST be constructible by deterministic interpreter operations.
   Gantry code MUST NOT inspect an option through
   deterministic branching, pattern matching, `if let`, or an unwrap
   operation in v1; a program that needs to branch on an option MUST supply it
   to an agent decision operation. `Option<Option<T>>` is excluded from v1
   because the untagged strict-JSON encoding cannot distinguish `None` from
   `Some(None)`.
   Every expression MUST have one statically known type. `Some(value)` has
   type `Option<T>` when `value` has type `T`. A `None` expression acquires its
   `Option<T>` type only from an expected type supplied by a binding annotation,
   assignment target, parameter, struct field, or return position. Bare `None`
   in a position without such an expected type, including a top-level prompt
   interpolation island, is an analysis error; authors can interpolate a typed
   option binding instead. Gantry performs no other implicit option wrapping.
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
   `List<T>`, or `Tuple<T1, T2, ..., Tn>` of otherwise permitted types. Nested
   and directly self-recursive struct definitions are permitted. In accordance
   with Section 4, a cycle through two or more distinct struct declarations is
   excluded from v1. Every permitted self-recursive cycle MUST pass through
   `Option<T>` or `List<T>` so that a finite strict-JSON value can terminate the
   recursion. An unguarded recursive cycle is an analysis error because it has
   no finite inhabitant.
7. Gantry MUST support named-field struct construction. Struct values MAY be
   constructed by source execution or produced by an agent hook. A source
   constructor MUST reject unknown and duplicate fields during analysis.
   Constructor field expressions are evaluated once in source order. Omitted
   required fields are analysis errors; an omitted field with a default uses
   that default, and an omitted `Option<T>` field without a default becomes
   `None`. A constructed value becomes visible only after every supplied field
   expression completes successfully. Earlier hook side effects are not
   reversible if a later field expression fails.
8. Struct fields MAY declare string-literal or `None` defaults, which are the
   only field-default forms in v1. A string default is valid for `String` and
   `Option<String>` fields; for `Option<String>` it normalizes to
   `Some(default)`. A `None` default is valid only for an `Option<T>` field.
   Defaults MUST NOT invoke an agent operation. When an optional field with a
   default is omitted, the default is assigned; explicit `null` remains
   `None`. Struct update syntax and destructuring are excluded from v1.
9. Bindings, including function, method, and decision-workflow parameters
   other than the receiver, are immutable by default. `mut` on a local
   declaration or parameter enables rebinding and field mutation of that local
   value. Parameter mutability is local to the called workflow because
   arguments use the deep-copy semantics in Section 6; it never permits
   mutation of the caller's value. Assignments MUST preserve type, and v1
   permits no implicit type coercion.
10. `const` is excluded from v1. Runtime initialization of immutable bindings
   is permitted.
11. Built-in deterministic string operations and list operations other than
    projection are excluded from v1. Lists and tuples are typed transport
    aggregates: source may pass, return, interpolate into an operation, or
    project them, but cannot branch on, iterate over, or otherwise inspect
    them deterministically.
12. Every protocol field that identifies a Gantry type MUST use one canonical
    UTF-8 type descriptor. `String` is encoded as `String`; a declared struct
    is encoded as its `crate::`-rooted qualified path; and constructed types
    are encoded as `Option<T>`, `List<T>`, or `Tuple<T1,T2,...,Tn>` with no
    whitespace and with each member recursively encoded by this rule. The
    no-result form is encoded as `None`, and the interpreter-only decision
    result is encoded as `Decision`. Source aliases introduced by `use` MUST
    be resolved before a descriptor is produced. Canonical descriptors are
    metadata rather than source values, but they ensure that hooks, journals,
    events, and diagnostics identify the same type independently of the
    spelling visible at a call site.

## 6. Functions and Methods

1. Gantry MUST support free functions and inherent methods declared in
   Rust-inspired `impl` blocks. An `impl` target MUST resolve to a struct
   declared in the same Gantry package. Implementations for `String`,
   `Option<T>`, `List<T>`, `Tuple<...>`, no-result `None`, or any other
   built-in type are analysis errors. A package MAY split one struct's methods
   across multiple `impl` blocks, subject to the package-wide duplicate-method
   rule below. Traits are excluded from v1.
2. Methods MUST support `self` and `mut self` receivers.
3. A method may mutate its receiver only through interpreter-executed field
   assignments in its body. For every assignment, Gantry MUST evaluate the
   complete right-hand side before changing the target and MUST commit the new
   root value atomically only after evaluation succeeds. This includes hook
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
   NOT invoke an agent hook.
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
5. A workflow body MAY contain one or more `prompt` expressions. Each executed
   `prompt` or `decide` expression MUST create exactly one logical agent
   operation. That logical operation MAY require multiple physical hook
   dispatches because of structured-output validation retries or recovery of
   an indeterminate dispatch; those dispatches retain the same operation ID
   and do not represent additional source operations. Calling a decision
   workflow invokes no hook merely because of the call; evaluating its body
   MAY execute multiple explicitly written prompt or nested decision
   operations before its terminal decision is obtained.
   The terminal `decide` reached through a decision-workflow call is the
   logical decision operation; the call expression and each intermediate
   decision-workflow frame are not additional operations. Its source location
   and static operation site are those of that executed `decide`, while its
   dynamic identity also records the complete workflow-call path that reached
   it. This rule keeps operation counts, hook requests, journals, and events
   aligned with the model-backed sites visible in source.
   Struct construction, field access, assignment, `Option<T>` construction,
   module lookup, function or method dispatch, and `join` are interpreter
   operations and MUST NOT invoke an agent hook.
6. Each `prompt` expression MUST contain an explicit prompt template and MAY
   contain parenthesized operation modifiers before that template. A typed
   prompt places its result annotation after the template, as in
   `prompt(retry_limit = 2, session = fork) "..." -> Report`. A prompt with no
   result annotation, or with `-> None`, has no result.
7. Template expressions MUST be interpolated before hook dispatch. To keep
   agent invocation explicit, an interpolation MAY contain only bindings,
   field paths, zero-based `List<T>` or tuple projections, literals, and
   deterministic struct or `Option<T>` constructor expressions composed from
   other permitted interpolation expressions.
   Function calls, method calls, `prompt`, decisions, assignment, `join`, and
   other expressions that can invoke a hook, alter control flow, or mutate
   state are prohibited inside interpolation. Interpolations are evaluated in
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
   of the dedented hook-facing template.
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
    `session` block, but they MUST NOT cross a spawned-block boundary. A `with` block
    changes agent selection only, and a `session` block changes the active
    logical session only. Neither context intercepts or retargets control
    transfer.
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
    of model operations visible even when calls or constructors are nested.

## 7. Agents, Hooks, and Sessions

1. A Gantry program MUST declare its permitted agent names in one or more
   `agents { ... }` declarations. Declarations from all package modules are
   merged into one package-wide set; repeating the same logical name is
   idempotent rather than an error. Exactly one dedicated
   `default agent = <name>;` binding MUST appear in `main.gnt`, and its name
   MUST belong to the merged set. A `default agent` declaration in any child
   module is an analysis error, even when it repeats the root declaration.
   Conflicting default bindings or selection of an undeclared agent are
   analysis errors. Within one uninterrupted execution or resume run,
   integrations MUST resolve every occurrence of the same logical name
   consistently across all tasks. Before a new execution or resume begins,
   the integration MUST attest that it can resolve every name in the merged
   set and MUST supply one opaque, stable agent-mapping revision ID. The ID
   identifies the complete logical-name mapping for that run without requiring
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
3. Agent selection is established by lexical `with <name> { ... }` blocks and
   inherited by their dynamic work. The selected name applies to operations
   written directly in the block, operations reached through workflow or
   decision calls made from it, and child tasks spawned from it, unless a
   nested `with` block overrides the selection. A workflow call therefore
   inherits the caller's active selection rather than resetting to the default,
   and a spawned child snapshots the selection that is active when `spawn`
   executes. Exiting `with` restores the previous selection for its caller;
   an already spawned child retains its snapshot. `<name>` MUST be a literal
   name from the merged agent declarations, not a runtime binding. `with`
   contexts MAY occur at any block scope. Operations with no active selection
   use the declared default agent.
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
   dispatch. A task that executes no `prompt` or `decide` operation MUST NOT
   require hook creation merely because the task exists. Once created, that
   instance MUST live for the remainder of the task's lifetime, including
   nested workflow calls and validation retries, and MUST NOT be invoked
   concurrently with itself. A spawned child receives a distinct hook instance
   if it reaches an operation. `HookFactory::create` MUST receive a
   `TaskContext` containing task, execution, and parent-task identity; the
   task's active logical session ID; the enclosing session ID and fork
   provenance when the task was spawned; and the inherited agent selection.
   Agent selection MUST remain part of each operation
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
5. Every operation hook request MUST contain at least:
   - a protocol major and minor version;
   - stable operation, execution, and task IDs, plus the parent-task ID when
     the task was spawned;
   - an operation kind, selected agent name, and the agent-mapping revision ID
     active for this dispatch;
   - the authored source prompt template defined in Section 6 and the
     interpolated prompt;
   - JSON-serialized typed arguments;
   - the expected result kind;
   - the expected canonical result-type descriptor from Section 5;
   - the expected JSON Schema;
   - generated operation guidance describing the input contract, output
     contract, and required strict-JSON response;
   - the source location;
   - the active logical session ID and root logical session ID;
   - the request session directive, which describes how this operation selected
     its active session;
   - the active session's creation directive, creator-construct identity, and
     parent logical session ID when that session was created by `fork` or
     `new`;
   - a dispatch ID, validation-attempt number, and recovery-dispatch number;
     and
   - validation errors from the immediately preceding invalid attempt, when
     applicable.
   The v1 operation kinds are `prompt` and `decision`. The result kind is
   `value`, `no-result`, or `decision`. Typed arguments MUST be an ordered
   vector containing one record for each interpolation island in source order;
   each record contains the exact UTF-8 source text between that island's
   `${` and matching `}` delimiters, its package-relative source file and
   half-open byte span, its canonical static-type descriptor from Section 5,
   and its RFC 8785 canonical strict-JSON value. The expected result descriptor
   is the declared value type for `value`, `None` for `no-result`, and
   `Decision` for `decision`.
   Comments and whitespace inside the island remain part of that source-text
   field even though they do not affect evaluation. A repeated
   interpolation appears repeatedly so the request
   preserves the template's operation inputs exactly. Source locations MUST
   identify the package-relative UTF-8 file and a zero-based, end-exclusive
   byte span into that file's exact source bytes. A permitted UTF-8 byte-order
   mark is part of those bytes and therefore contributes three bytes to later
   offsets even though the lexer ignores it. An operation location spans the
   complete authored `prompt` or `decide` expression, including modifiers,
   template delimiters, and a prompt result annotation when present. An
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
   - `loop-iteration`: loop operation ID, zero-based body-execution index,
     phase (`condition` or `body`), and the most recently settled condition's
     associated index, decision, and nonempty rationale when one exists; and
   - `optional-decline`: declined operation ID, selected agent, source location,
     and decline reason when a decline normalized to `None`.
   Structural entries (`workflow-frame`, `decision-frame`, `conditional-arm`,
   and `loop-iteration`) MUST appear first, ordered from outermost to
   innermost scope, with repeated entries in execution order within one scope.
   Any `optional-decline` entries MUST follow all structural entries and use
   the interpolation-input and value-traversal order defined below. This is a
   total ordering; integrations MUST NOT regroup entries by kind. An `else if`
   request MUST include the `conditional-arm` entries from preceding arms in
   the same chain. While a selected conditional arm executes, its active
   control-chain context MUST include every preceding false arm followed by
   the controlling true arm, each with its decision and rationale. An `else`
   arm MUST include
   every preceding false arm. These entries leave the active context when the
   conditional chain completes; they are not unbounded execution history. A
   `None` produced by `Declined` MUST carry interpreter-only decline
   provenance distinct from a `None` produced by `Completed(null)` or source.
   That provenance MUST survive assignment, argument and return passing,
   struct or aggregate containment, capture, and other deep copies. An
   operation request MUST include one `optional-decline` entry for every
   distinct decline provenance reachable from its interpolation inputs,
   ordered by interpolation-input order and then depth-first value traversal;
   repeated references to the same declined value produce one entry. Depth-first
   value traversal is preorder: a struct visits fields in declaration order, a
   `List<T>` or tuple visits members in ascending index order, and a present
   `Option<T>` visits its contained value. A `None` has no child value. When the
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
   contents; a struct, `Option<T>`, `List<T>`, or tuple is interpolated as
   compact strict JSON, with `None` rendered as `null`. This compact encoding
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
   state that `Completed` output is exactly one JSON text with no surrounding
   prose, Markdown fence, or additional value; identify the expected result
   kind; explain that unknown struct properties are rejected; identify fields
   that may be omitted and the defaults or `None` values omission supplies;
   and explain the no-result or decision shape when applicable. The wording and
   provider-specific presentation MAY evolve, but those semantic instructions
   MUST remain present on every initial dispatch and repair retry.
10. The only v1 operation-selection knob is the agent name. System/user/
   assistant roles, model choice, tools, sampling settings, streaming,
   progress reporting, operation-level timeouts, and provider-specific
   cancellation mechanisms are integration concerns. Those mechanisms MUST
   still observe the Gantry-owned cancellation token and the language-level
   cancellation state transitions required by Sections 10 and 15.
11. A hook MUST return one of three host-level outcomes:
   `Completed(raw_output)`, `Declined(reason)`, or `Failed(message)`.
   `Completed` contains the agent's raw output as bytes; Gantry, not the hook,
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
   resume.
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
14. Agent operations may have side effects. Gantry does not require retries to
    be idempotent or prevent duplicate external effects.
15. `prompt` and decision evaluation are the only v1 source constructs that
    directly dispatch an `OperationHook`. Tools, approvals, shell commands,
    network calls, and other harness actions MAY occur while the integration
    fulfills that hook, but they are not separately expressed or interpreted
    by Gantry v1. Gantry observes that internal work only through the hook
    outcome; an integration MAY expose additional telemetry through its own
    harness-specific facilities. This boundary keeps the language focused on
    agent control flow without prescribing a harness action vocabulary or
    implying that harness-internal actions alter Gantry state independently of
    their hook outcome.
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
    Before an execution ID exists, structured start failures MUST at least
    distinguish syntax, analysis, entry-input validation, integration
    preflight, initial journal ownership, execution-start persistence, and
    required-event-delivery failure during pre-execution validation or
    analysis.

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
    errors MUST at least distinguish hook creation, hook failure, decline of a
    required result, structured-output exhaustion, deterministic evaluation
    failure, executor failure, cancellation, journal failure, required-event-
    delivery failure, task/join failure, and internal invariant failure.
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

1. A successful agent hook outcome provides raw bytes in
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
   For a no-result prompt, the expected schema is exactly the following schema
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
2. A `String` result is represented by a JSON string. A struct result is a
   JSON object whose property names directly match its declared field names.
   After source construction or hook-output normalization, a runtime struct
   contains every declared field. Whenever Gantry serializes that normalized
   struct, it MUST emit every field; an `Option<T>` field whose value is `None`
   is emitted as JSON `null`, and an applied default is emitted as its resolved
   value. Although hook output may omit an optional property, omission is not
   preserved as a distinct runtime state.
   Normalization is recursive and deterministic. Gantry MUST normalize nested
   structs, list items, tuple members, and present option values from outermost
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
6. Gantry MUST derive JSON Schema Draft 2020-12 from declared output types
   during semantic analysis and MUST independently validate every successful
   hook result against that schema. Every schema root MUST identify that
   dialect with its `$schema` URI. Recursive types MUST use `$defs` and `$ref`.
   `Option<T>` MUST be represented by a schema accepting exactly `null` or the
   schema for `T`.
7. Every struct schema MUST set `additionalProperties` to `false`. Declared
   fields are required unless represented by `Option<T>`. Literal field
   defaults affect source construction; they do not make a non-optional field
   optional in an agent result. A schema for an optional field with a declared
   default MUST include that value through JSON Schema's `default` annotation.
   Gantry MUST still perform the normalization in item 2 because the annotation
   does not itself insert a value during JSON Schema validation.
8. v1 validation MUST check JSON shape and types. Constraints such as length,
   patterns, enums, and semantic validity are conveyed through prompt guidance
   rather than enforced by Gantry. The fixed nonempty-rationale requirement for
   the interpreter-only decision schema is the sole v1 exception to this rule.
9. UTF-8 decoding failures, malformed JSON, and schema-invalid output MUST be
   returned to the agent as validation guidance and retried up to the
   configured retry limit. A retry request MUST include the preceding
   validation errors but MUST NOT return the preceding raw output to the hook.
   A validation retry is another physical dispatch of the same logical
   operation, not a reevaluation of the source expression. Gantry MUST reuse
   the selected agent, logical session, authored template, interpolated
   prompt, typed interpolation arguments, expected type and schema, base
   guidance, source location, and ordered execution context from the initial
   dispatch. It MUST NOT reevaluate interpolation expressions or observe
   intervening source state. Only the dispatch identity, validation-attempt
   number, applicable recovery-dispatch number, preceding validation errors,
   and repair-specific rendering of those errors may differ. This rule keeps
   retries understandable as repairs of one visible operation rather than
   hidden additional program evaluations.
10. The retry limit is configured per interpreter and MAY be overridden per
   operation. It counts retries after the initial attempt; zero permits exactly
   one attempt. The v1 interpreter default is two retries after the initial
   attempt. Retry backoff MUST be configurable. The v1 default uses full-jitter
   exponential backoff: for the one-based retry number `r`, the delay ceiling
   is `min(100 ms * 2^(r - 1), 2 s)`, and the selected delay is sampled
   uniformly from the inclusive range of whole microseconds from zero through
   that ceiling. An implementation MUST record the selected delay in the
   validation-attempt record before sleeping. If execution is interrupted
   before the corresponding retry dispatch is durably recorded, resume MUST
   wait the complete recorded delay again; it MUST NOT sample another delay.
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
13. Source snippets MAY be included in validation diagnostics. Raw agent
    output MUST NOT be included in validation diagnostics.

## 9. Control Flow

1. Gantry MUST support `if`, `else if`, and `else`. Each `if` or `else if`
   condition MUST obtain its controlling result from exactly one terminal
   agent decision operation. A direct decision operation uses the visually
   distinct `decide` expression; an ordinary unannotated `prompt` always
   remains a no-result prompt. A condition MAY be a direct `decide` expression
   or a call to a decision workflow. Calling the workflow does not itself add
   a hook invocation, although explicit prompts and nested decisions in that
   workflow execute normally before its terminal decision.
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

   Gantry uses only `decision` to select control flow and retains the rationale
   for observability. A decision is interpreter-only and cannot be bound as a
   user-visible Boolean value.
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
   `loop` MUST accept `session` and `limit`; `while` and `until` MUST also
   accept `retry_limit` for their decision operation. Agent selection is
   inherited from a lexical `with` context rather than specified as a loop
   modifier. `retry_limit` counts retries after the initial attempt.
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
   true decision completes the loop. After a false decision, Gantry checks the
   positive `limit`; reaching it completes the loop normally, and otherwise
   the next body execution begins. Thus every entered `until` body has exactly
   one following post-test unless it exits through `break`, `return`, failure,
   or cancellation. `break` completes any loop immediately without another
   decision call.
8. `for`, `match`, and deterministic `if let` are excluded from v1.
9. Control decisions MUST use the same schema-validation and retry policy as
   other structured agent results.
10. Gantry imposes no mandatory loop, cost, or agent-call limit. Integrations
    MAY impose their own limits, except that such policy does not alter the
    language meaning of `limit = 0`.
11. A direct prompted condition uses `if decide "..." { ... }`. Gantry MUST
    also support declarations of the form
    `decision is_complete(report: Report) { ... }`. Each reachable normal
    completion of a decision workflow MUST yield a trailing `decide`
    expression, decision-workflow call, or decision-valued `with` or `session`
    expression;
    alternatively, every reachable path MAY exit through an explicit valid
    decision `return`. This permits a fully returning `if`/`else` decision
    workflow without an artificial unreachable tail. The result schema is the
    interpreter-only decision schema in item 2. A decision workflow MAY contain
    multiple ordinary prompts, nested decisions, and other executable blocks.
    `return` MAY exit it early, but the returned expression MUST be a direct
    `decide` expression, a call to another decision workflow, or a `with` or
    `session` context whose trailing expression is one of those forms. Each
    completed evaluation MUST ultimately obtain its decision from exactly one
    prompt hook result with the decision schema in item 2. A decision call is
    valid only as the condition of `if`, `else if`, `while`, or `until`, or as the returned
   expression of another decision workflow. Its result cannot be bound,
   returned by an ordinary workflow, interpolated, or discarded as a
    standalone statement. Decision workflows are free module items in v1;
    decision methods and decision-valued first-class values are excluded.
    Semantic analysis MUST prove that every reachable
    normal completion of a decision workflow yields a decision expression and
    that every reachable explicit `return` in that workflow returns a decision
    expression. A no-result `return;`, an ordinary value return, or fallthrough
    from a decision workflow is an analysis error.
12. Static control-flow analysis MUST treat every agent decision as capable of
    producing either `true` or `false`, independently of its prompt text,
    previous outcomes, rationale, selected agent, or session. Analysis MUST
    inspect both outcomes of every reachable `if`, `else if`, `while`, and
    `until` decision; it MUST NOT assume that a model will make one branch
    unreachable. A `while` has a possible zero-body normal path. An `until` has
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
   order. Joining a no-result task in this form is an analysis error. A multi-
   task join waits until every named task settles even after a failure. Before
   waiting, Gantry MUST append and flush one task-state record that identifies
   the join form, source location, named handles in argument order, and their
   transition from attached to consumed-by-join. Only then are the handles
   consumed. This transition includes handles for successful tasks in a join
   where another task fails. After settlement, Gantry MUST append and flush the
   ordered result or aggregate failure before returning it to source execution.
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
   included tasks have settled, and yields the task's declared result type
   when exactly one included task has a non-`None` result. With two or more
   included tasks, it yields an ordered `List<T>` in task declaration order
   when every joined task has the same non-`None` result type. When two or more
   joined tasks all have non-`None` result types that are not exactly equal, it
   yields a positional tuple in task declaration order. Otherwise it is a
   waiting statement that discards
   successful outputs and has no result. In particular, if any included task
   has no result, the complete `joinall()` has no result. With zero included
   tasks, `joinall()` is likewise a no-result no-op. Semantic analysis MUST
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
    active when shutdown began. An interpreter cannot be reused after shutdown
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
   after an execution reaches terminal durable state and all required event
   obligations through that state have settled, and after a start or resume-
   start failure when ownership was acquired but interpretation never began.
   Release failure is a journal failure after execution has begun. A start or
   resume-start invocation that has not advanced durable execution state MUST
   instead include ownership-release failure in its structured pre-execution
   result and leave later acquisition to the storage's fencing rules. These
   ownership operations coordinate access and do not add a mutation primitive
   for journal records themselves.
3. A hook dispatch MUST be recorded and flushed before the hook is invoked.
   Its dispatch record MUST preserve the complete versioned semantic request,
   including the selected agent, operation and result kinds, templates,
   interpolated inputs, schema, guidance, source location, session fields,
   ordered execution context, validation state, and logical identities.
   Protected or repeated payloads MAY be stored by stable reference, but those
   references MUST resolve from the same durable journal. A recovery
   redispatch MUST reuse those committed semantic fields except for the
   physical-dispatch fields and the agent-mapping revision explicitly allowed
   to change by Section 7. It MUST retain the committed logical agent name,
   operation inputs, session, schema, guidance, source location, context, and
   validation state. The new dispatch ID and incremented recovery-dispatch
   number MUST differ, and the request MUST carry the mapping revision recorded
   for the resume run. No other semantic request field may change.
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
   operation returns a value, and the interpreter-only decision and rationale
   when the operation returns a decision. An optional decline records JSON
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
   embedder.
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
   mapping revision, or best-effort-sink configuration change when applicable.
   A terminal-execution record MUST use one of the terminal categories defined
   in Sections 7, 10, and 15 and MUST be the final record that changes language
   execution state. Later event-delivery records and ownership release do not
   alter that state. Concrete serialization and Rust types are implementation-
   defined, but all required information and durability boundaries are
   normative. Before append, Gantry constructs an unfinalized record body that
   omits the record ID and sequence number. The storage append operation MUST
   atomically assign both fields and store the resulting finalized envelope;
   only that finalized envelope is a journal record returned by durable reads.
10. For each new execution, after entry validation and integration preflight
    succeed but before evaluating `main`, creating a child task, or dispatching
    a hook, Gantry MUST append and flush exactly one execution-start record.
    That record MUST contain the package source identity, the effective-
    configuration identity and fields defined below, the selected root-session
    identity and provenance, the agent-mapping revision from Section 7, the
    canonical signature of `main`, and either a no-entry-input marker or the
    validated and normalized canonical entry value with its type descriptor.
    Resume MUST verify and reuse the existing execution-start record, restore
    its entry value, and MUST NOT append a second execution-start record or
    accept replacement entry input. A mapping revision changed during resume
    MUST instead be appended and flushed as an execution-state record before
    recovered interpretation or dispatch continues.

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
      "hook_protocol_major": 1,
      "journal_protocol_major": 1,
      "event_protocol_major": 1,
      "maximum_directive_integer": "9223372036854775807",
      "root_session": {
        "id": "logical-session-id",
        "provenance": "embedder-supplied"
      },
      "structured_output": {
        "retry_limit": "2",
        "backoff": {
          "initial_us": "100000",
          "cap_us": "2000000",
          "jitter": "full"
        }
      },
      "required_event_sinks": [
        {
          "id": "stable-sink-id",
          "raw_output_enabled": false,
          "redaction_policy_id": "policy-id",
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
    the effective configured values. `root_session.provenance` is exactly
    `embedder-supplied` or `gantry-created`. `jitter` is exactly `none` or
    `full`; a future mode requires a protocol change. Required sinks MUST be
    ordered by the unsigned UTF-8 bytes of `id` before canonicalization, and
    their IDs and redaction-policy IDs MUST be valid UTF-8. The root-session ID
    and every required-sink ID MUST use the same stable string representation
    that their embedding interfaces expose. This exact object definition makes
    independently produced identities comparable rather than leaving property
    spelling or nesting to an implementation.
    Resume MUST reject changes to those fields. Executor implementation,
    worker count, operation timeouts, shutdown timing, best-effort sinks, and
    logical-agent-to-provider mappings MAY change on resume; such changes MUST
    be journaled before further work and MUST obey the per-event delivery-
    obligation rules in Section 12. Allowing agent mappings to change is
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
   and failure. Foreground
   completion is distinct from terminal execution when detached tasks remain.
   This event requirement applies while the event's required durability
   boundary is available. A journal failure that makes a resumable execution's
   event stream unwritable is reported through the structured embedding error
   required by Sections 11 and 15 rather than by fabricating an undurable
   standard event.
   Operation-dispatch events MUST reference the applicable prompt and schema
   payloads. Event and journal envelopes MUST be explicitly versioned from the
   first public release, and consumers MUST reject unsupported major versions.
   One operation-dispatch event MUST be emitted for each physical hook
   invocation, including validation retries and recovery redispatches. One
   operation-completion event MUST be emitted for each host-level outcome from
   such an invocation, including a `Completed` outcome that subsequently fails
   parsing or schema validation. Those events retain the logical operation ID
   and carry the distinct dispatch ID and applicable validation-attempt and
   recovery-dispatch numbers. A schema-validation-failure event and, when
   another attempt is permitted, a retry event follow the corresponding
   completion event. After a `Completed` outcome is successfully decoded,
   parsed, validated, normalized, and durably recorded under Section 11, or an
   optional `Declined` outcome is durably normalized to `None`, Gantry MUST
   emit exactly one operation-result event for that logical operation. The
   event represents acceptance of a value, decision, or no-result completion
   and MUST reference the operation-result record. It is not emitted for a
   required-result `Declined`, `Failed`, or invalid `Completed` outcome.
   Recovery that reuses an existing operation-result record MUST reuse the
   corresponding durable event occurrence rather than emit another logical
   acceptance event. This event cardinality distinguishes physical hook
   activity from the one source-level result that execution may consume.
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
   If journal storage subsequently fails, the authoritative standard event
   stream ends with its last durably flushed event. Gantry MUST NOT deliver a
   newly created standard event for that journal failure because doing so
   would violate the journal-first rule. An implementation MAY invoke a
   separately configured, non-durable emergency diagnostic callback, but that
   callback is not an `EventSink`, carries no at-least-once guarantee, and MUST
   be identified as out-of-band reporting rather than a Gantry event.
4. Canonical protected event records for completed agent operations MUST make
   raw agent output available. A sink receives raw output only when it
   explicitly declares that capability and the embedder enables it for that
   sink. Other sinks receive the same event identity with the raw field
   redacted. Prompts and schemas MUST be observable through journal or event
   IDs referenced from events rather than duplicated in every event. Raw output
   MUST remain omitted from default human-readable diagnostics and validation
   error text. For delivery, Gantry MUST resolve an event's protected references
   into a capability-filtered payload bundle supplied alongside, but not inside,
   the ordinary event envelope. The bundle MUST preserve the stable reference
   keys used by the envelope. It MUST omit or explicitly redact raw output for
   a sink that lacks raw-output access. Gantry MUST retain referenced payloads
   until every required delivery has succeeded or terminally failed and every
   best-effort delivery has either succeeded or exhausted its policy. This
   makes reference-based events usable without placing sensitive or repeated
   payloads directly in each event envelope.
5. Event sinks MUST be configured independently as `required` or
   `best-effort`, with interpreter defaults overridable per sink. Gantry MUST
   retry only errors the sink classifies as retriable. A non-retriable error
   exhausts delivery immediately. The retry limit counts known retriable
   failures after the initial delivery; recovery of an indeterminate delivery
   does not consume that budget. The default policy is three retries and uses
   the same full-jitter exponential formula as Section 8: for one-based retry
   `r`, the ceiling is `min(100 ms * 2^(r - 1), 2 s)`, and the delay is sampled
   uniformly from whole microseconds from zero through that ceiling.

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
   class, raw-output permission, retry-policy revision, retry limit, initial
   delay, cap, and jitter mode. A retry or recovery redelivery MUST use that
   captured class and effective retry policy rather than a later interpreter
   default. Adding a sink after an event was created MUST NOT retroactively
   deliver the older event to that sink. Removing or replacing a sink MUST NOT
   silently abandon an unsettled captured obligation. Before recovered
   interpretation begins, Gantry MUST verify that every required sink named by
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
   waiting for events that the activity has not yet produced.
   An event describing sink-delivery failure MUST NOT be delivered to the same
   failing sink. Required-sink exhaustion while an execution is nonterminal is
   execution-wide rather than task-local: Gantry MUST reject new work for that
   execution, signal cancellation to its foreground, attached, and detached
   tasks, and apply the configured cancellation drain. It MUST then append and
   flush the execution's terminal-execution record with the `required-event-
   delivery failure` category, without making that record depend on another
   event. That record MUST identify the exhausted sink, failed event, delivery
   attempt, and cancellation outcome. Failure of the terminal-record write is
   returned to the embedder as a journal failure.

   Exhaustion while delivering the terminal-execution event occurs after the
   terminal-execution record is durable and MUST NOT append a second terminal
   record or replace the recorded language outcome. Gantry MUST durably settle
   the failed delivery obligation and return a structured required-event-
   delivery barrier failure that includes the existing terminal outcome. A
   later query still observes that durable terminal outcome, while delivery
   state shows that its required terminal event was not delivered. A
   standalone activity without a journal MUST return the required-event-
   delivery failure directly. No event produced during cancellation is
   delivered to the exhausted sink, and an implementation MUST NOT recursively
   require that sink to acknowledge its own failure. These rules override the
   general failure-event requirement for that exhausted sink and prevent
   recursive failure-event generation.
7. Every event envelope MUST identify its protocol version, event and activity
   IDs, optional execution ID, event kind, source location when source-backed,
   task and operation identities when applicable, causal parent IDs, per-task
   sequence when task-backed, timestamp, a kind-specific payload or stable
   payload reference, and redaction state. A timestamp MUST be the event's
   creation time encoded as an RFC 3339 UTC string and MUST remain unchanged
   across delivery retries. Prompt templates, schemas, and raw model output
   MUST use protected stable references rather than being copied into ordinary
   event payloads; diagnostics and other nonsensitive standalone activity data
   MAY be carried inline. The canonical v1 event kinds are parse, analysis,
   workflow start, workflow end, operation dispatch, operation completion,
   operation result, schema validation failure, retry, branch decision, spawn,
   join, detach, mutation, cancellation, foreground completion, task
   completion, terminal execution, and failure. Concrete serialization is
   implementation-defined.
8. Event kind payloads MUST expose enough structured information for a harness
   to interpret an execution without parsing diagnostic text. The canonical
   minimum payloads are:
   - `parse` and `analysis`: phase, status, and structured diagnostics;
   - `workflow start` and `workflow end`: workflow path, frame occurrence, and
     completion status, plus a typed result reference when one exists;
   - `operation dispatch`: operation and dispatch IDs, operation and result
     kinds, selected agent, active agent-mapping revision ID, logical session
     ID, validation-attempt number, recovery-dispatch number, and prompt and
     schema references;
   - `operation completion`: operation and dispatch IDs, outcome variant, and
     a protected raw-output reference for `Completed`, or the decline/failure
     reason under the sink's redaction policy;
   - `operation result`: operation ID, committed outcome and operation-result
     record references, outcome variant, result kind, canonical type
     descriptor, and a protected normalized-value reference for a value result
     or the decision and rationale for a decision result; an optional decline
     additionally identifies its decline provenance;
   - `schema validation failure`: operation and dispatch IDs plus the
     structured validation errors defined in Section 7;
   - `retry`: operation ID, preceding and next dispatch IDs when assigned,
     validation-attempt and recovery-dispatch numbers, retry class, and
     selected delay;
   - `branch decision`: conditional or loop identity, decision, rationale, and
     selected arm or loop transition;
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
   - `failure`: the runtime-error category, structured causal identities, and
     redacted diagnostic details.
   An implementation MAY add optional fields under the minor-version rules,
   but it MUST NOT omit these applicable fields or encode their only usable
   representation in human-readable text.
9. A dry-run performs syntax validation only and MUST NOT invoke agent hooks.
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
10. Normal execution MUST complete semantic analysis successfully before its
   first hook invocation.
11. Diagnostics MUST be usable by both human authors and automated repair
    agents without parsing display text. Every syntax or analysis diagnostic
    MUST contain a canonical phase, severity, machine-readable category, a
    documented code stable within the protocol major version, a human-readable
    message, and a primary package-relative source span when the problem is
    source-backed. The canonical v1 categories are `lexical`, `syntax`,
    `package`, `name-resolution`, `type`, `control-flow`, `task-ownership`, and
    `schema`. A diagnostic SHOULD include labeled related spans for conflicting
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

### 13.2 Lexical grammar

```ebnf
source              = [ utf8_bom ], { item }, end_of_file ;

utf8_bom            = U+FEFF ;

whitespace          = " " | "\t" | "\r" | "\n" ;
line_terminator     = "\r\n" | "\n" | "\r" ;
line_comment        = "//", { any_character_except_line_terminator },
                      ( line_terminator | end_of_file ) ;
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
permitted. The exact one-character token `_` is reserved and MUST NOT be
emitted as an `identifier_token`; leading `_` remains valid when at least one
`XID_Continue` scalar follows it. Source MUST be valid UTF-8. One UTF-8
byte-order mark MAY appear only as the first decoded scalar of a source file
and is ignored; U+FEFF in any other source position is not whitespace and is a
syntax error. An identifier MUST NOT equal a reserved word. Decimal directive
integers have no sign, separator, or radix prefix.

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

`string_character` is any Unicode scalar value other than `"` or `\`; newline
characters are included. `block_prompt_body` is the shortest sequence ending
before an unescaped `"""` delimiter and uses the same escape sequences as an
ordinary string. One or two consecutive unescaped quote characters are block-
prompt content; only three begin the closing delimiter. Escaping at least one
quote permits a literal three-quote sequence in the decoded content. A block
prompt MUST begin with a `line_terminator` immediately after its opening
delimiter; that required terminator is structural and is not part of the
resulting template. Its closing delimiter MUST appear on a line containing
only indentation followed by the delimiter. Block-prompt indentation consists
only of ASCII space and horizontal-tab characters. The line terminator
immediately before that closing-delimiter line and the delimiter line's
indentation are structural and are not part of the resulting template. Authors
who need a trailing newline MUST include one additional blank content line.
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
                          [ struct_field_list ], "}" ;
struct_field_list       = struct_field, { ",", struct_field }, [ "," ] ;
struct_field            = identifier_token, ":", value_type,
                          [ "=", field_default ] ;
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
parameter               = [ "mut" ], identifier_token, ":", value_type ;

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
if it had `-> None`. `mut` on a non-receiver parameter permits mutation of that
workflow's deep-copied local argument; it does not affect the caller. A method
always has a receiver as its first parameter. Associated functions without a
receiver are excluded from v1. A `decision` has no source-level result
annotation because its interpreter-only decision schema is implied by the
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
decision_block          = "{", { statement }, [ decision_tail ], "}" ;
decision_tail           = decision_expression ;

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
                        | loop_statement
                        | while_statement
                        | until_statement ;

let_statement           = "let", [ "mut" ], identifier_token, ":",
                          value_type, "=", expression, ";" ;
assignment_statement    = assignment_target, "=", expression, ";" ;
assignment_target       = identifier_token, { ".", identifier_token }
                        | "self", ".", identifier_token,
                          { ".", identifier_token } ;
expression_statement    = expression, ";" ;
with_statement          = "with", identifier_token, statement_block ;
session_statement       = "session", "(", session_directive, ")",
                          statement_block ;
return_statement        = "return", [ return_expression ], ";" ;
return_expression       = expression | decision_expression ;
break_statement         = "break", ";" ;
continue_statement      = "continue", ";" ;
trailing_expression     = expression ;
```

Bindings require explicit types in v1. A trailing expression is distinguished
from an expression statement by the absence of `;` immediately before the
closing brace. A trailing expression MUST produce a first-class value; a
no-result operation must instead be an expression statement ending in `;`.
`return;` is valid only in a no-result function, method, or spawned block.
`break` and `continue` are valid only in a loop body. When a `decision_block`
has a reachable normal completion, it MUST end in a direct
`decide` expression, decision-workflow call, or decision-valued `with` or
`session` expression. The optional grammar tail permits a
block whose static control-flow analysis proves that every reachable path has
already exited through a valid decision `return`; it does not permit decision
fallthrough. An earlier `return` in the statement sequence is subject to the
same restriction. The broader `return_expression` production permits a parser
to recognize early decision returns inside nested ordinary blocks; semantic
analysis MUST reject decision expressions returned from ordinary workflows and
ordinary values returned from decision workflows. Assignment to `self` as a
whole is not v1 syntax; a
`mut self` method may assign its receiver fields and may return the resulting
receiver value.

### 13.6 Expressions

```ebnf
expression              = prompt_expression
                        | join_expression
                        | joinall_expression
                        | with_expression
                        | session_expression
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

with_expression         = "with", identifier_token, value_block ;
session_expression      = "session", "(", session_directive, ")",
                          value_block ;
```

The grammar admits `self` as a primary expression so the same expression
productions can parse method bodies and their nested blocks. Semantic analysis
MUST enforce the receiver scope specified in Section 13.4.

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
only in `join`, `joinall()`, and `detach`, never as primary expressions.

A value-producing `with` or `session` expression requires its block's trailing
expression and yields that value. These forms permit a lexical agent or session
context to produce the enclosing workflow's result. Their statement-only forms
in Section 13.5 have no result and take no semicolon after the closing brace. A
value-producing context expression MAY still be followed by `;` when its value
is intentionally discarded.

`prompt`, `join`, `joinall()`, `with`, and `session` are complete expression
forms rather than direct bases of a postfix chain. To select a field, invoke a
method, or project from one of their results without first binding it, source
MUST parenthesize that expression, as in `(join(first, second))[0]`. This explicit
grouping avoids ambiguity between prompt result annotations and operations on
the produced value.

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
                          { interpolation_suffix } ;
interpolation_suffix    = ".", identifier_token
                        | "[", integer_token, "]" ;
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

Interpolation permits only the restricted grammar above. A projection index
MUST obey the list and tuple rules in Section 5. In particular, interpolation
does not admit function or method calls, prompts, decisions, joins, mutation,
or control flow. Nested braces belonging to a struct initializer are balanced
before the interpolation's closing `}` is recognized. Duplicate prompt
modifiers are analysis errors. `retry_limit` counts retries after the initial
attempt.

### 13.8 Decisions and sequential control flow

```ebnf
if_statement            = "if", [ decision_modifiers ],
                          decision_expression, statement_block,
                          { "else", "if", [ decision_modifiers ],
                            decision_expression, statement_block },
                          [ "else", statement_block ] ;

decision_modifiers      = "(", decision_modifier,
                          { ",", decision_modifier }, [ "," ], ")" ;
decision_modifier       = "session", "=", session_directive
                        | "retry_limit", "=", integer_token ;

decision_expression     = decide_expression
                        | decision_call
                        | decision_with_expression
                        | decision_session_expression
                        | "(", decision_expression, ")" ;
decide_expression       = "decide", [ prompt_modifiers ], prompt_template ;
decision_call           = qualified_path, "(", [ argument_list ], ")" ;
decision_with_expression
                        = "with", identifier_token, decision_block ;
decision_session_expression
                        = "session", "(", session_directive, ")",
                          decision_block ;

loop_statement          = "loop", [ loop_modifiers ], statement_block ;
loop_modifiers          = "(", loop_modifier,
                          { ",", loop_modifier }, [ "," ], ")" ;
loop_modifier           = "session", "=", session_directive
                        | "limit", "=", integer_token ;

while_statement         = "while", [ loop_condition_modifiers ],
                          decision_expression, statement_block ;
until_statement         = "until", [ loop_condition_modifiers ],
                          statement_block,
                          "when", decision_expression, ";" ;
loop_condition_modifiers
                        = "(", loop_condition_modifier,
                          { ",", loop_condition_modifier }, [ "," ], ")" ;
loop_condition_modifier = "session", "=", session_directive
                        | "limit", "=", integer_token
                        | "retry_limit", "=", integer_token ;
```

The optional modifier forms require at least one modifier when parentheses are
present; empty `prompt()`, `decide()`, `if()`, `else if()`, `loop()`,
`while()`, and `until()` modifiers are not v1 syntax. Bare `loop` uses
`session = inline` and `limit = 0`. Duplicate modifiers are analysis errors.

A condition-level `session` on `if` or `else if` takes effect before evaluation
of the decision expression. It therefore establishes the inherited session for
prompt operations used to compute decision-call arguments as well as for the
complete decision-workflow evaluation. That session context ends when the
decision expression completes and does not automatically extend into the
selected arm. Authors who want a decision and its arm operations to share one
explicit session should wrap the complete conditional in
`session(<directive>) { ... }`. On `while` and `until`, the same modifier
position instead declares the loop session whose condition/body lifetime is
defined normatively in Section 9; it is not condition-only. A condition-level
`retry_limit` applies only to the ultimate decision operation;
prompts used in arguments or inside a decision workflow use their own modifier
or the interpreter default. A modifier written directly on a `decide`
expression is more local and overrides the corresponding inherited value.
`limit` belongs only to the enclosing `while` or `until`. The `until` grammar
deliberately places its body before `when` and the post-test decision. A
`decision_call` MUST resolve to a `decision` declaration; an ordinary workflow
call is not a condition.
The body of a decision-valued `with` or `session` expression follows the same
definite-decision rules as any other `decision_block`: it either has a terminal
decision tail or, when enclosed by a decision workflow, proves that every
reachable path exits that workflow through a valid decision `return`.

An ordinary workflow call and a decision-workflow call intentionally use the
same Rust-inspired token sequence. The parser MUST represent that shared call
shape without guessing from spelling alone; semantic analysis resolves the
callee and requires a `decision` declaration in every `decision_expression`
position. In particular, `return check(value);` is decision-valued only inside
a decision workflow and only when `check` resolves to a decision declaration.
This contextual resolution MUST NOT permit an ordinary function to masquerade
as a condition or a decision call to escape into a first-class value position.

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
operations. Here both prompts share one child conversation forked from the
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

Tuple positions follow the explicit join argument order. v1 code can pass or
return `pair`, project `pair[0]` or `pair[1]`, but cannot destructure it. For
example, `let headline_text: String = pair[0];` and
`let full_report: Report = pair[1];` are deterministic projections and do not
invoke an agent hook.

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

## 15. Required Embedding Interfaces

Concrete Rust names and signatures MAY evolve during implementation, but a v1
embedding API MUST expose the following semantic interfaces without requiring
provider-specific or executor-specific types in Gantry programs:

1. An `Interpreter` accepts a package root, interpreter configuration (which
   includes the executor adapter), a hook factory, journal storage, and zero or
   more event sinks. It MUST expose syntax-only validation, semantic analysis,
   execution, resume, execution cancellation, and terminal asynchronous
   shutdown operations. Execution cancellation accepts an execution ID and a
   structured reason, is idempotent, and implements Section 10 rather than
   requiring the embedder to manipulate executor handles directly. Resume
   MUST identify the execution or journal to load and reconstruct state only
   from the authoritative durable record prefix returned by journal storage,
   and MUST obtain the exclusive execution ownership required by Section 11
   before advancing it.
   Execution accepts either no entry input or one raw byte sequence containing
   strict JSON as required by `main`; Gantry, rather than the embedder, performs
   the decoding, parsing, duplicate-member rejection, and schema validation
   defined in Section 4. It MUST also accept an optional root-session
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
   analysis are start failures. Resume MUST likewise return a structured
   resume-start failure when Section 7 preflight fails, without changing the
   execution's durable state, and MUST permit a later corrected resume attempt.
   Once recovered interpretation begins, resume returns the same runtime and
   foreground outcome categories as execution. Once the execution ID is
   returned, execution produces a typed foreground outcome that distinguishes
   a value, no result, and every runtime-error category defined in Section 7. A
   foreground outcome MAY be returned while explicitly detached tasks remain;
   the execution ID allows the embedder to correlate their later events and
   terminal durable state. Because event sinks are optional, the API MUST also
   permit the embedder to query an execution's latest durable foreground and
   terminal states and to asynchronously wait for terminal state by execution
   ID. A terminal result MUST distinguish success, detached-task failure,
   cancellation, and the runtime-error categories defined in Section 7.
2. A `HookFactory` asynchronously creates an `OperationHook` for a supplied
   task context. The factory, or a companion harness-preflight interface owned
   by the same integration, MUST also validate the complete merged agent-name
   set and its supplied mapping revision before a new execution begins. Before
   resume continues, that preflight MUST resolve every unfinished logical
   session descriptor enumerated by Gantry, including root, parent, and
   creation provenance. For a new execution, preflight failure is an
   integration-preflight start failure. For resume, it is the applicable
   nonterminal resume-start failure. It creates no `OperationHook` and MUST
   occur before `main` evaluation or recovered work. Successful preflight does
   not itself dispatch an operation.

   Gantry MUST call the factory lazily, at most once per Gantry task in one
   in-process run, immediately before that task's first hook dispatch; a task
   that performs only deterministic interpreter work does not require a hook.
   `OperationHook` asynchronously accepts the versioned request defined in
   Section 7 and a Gantry-owned cancellation token, and returns exactly one
   `Completed(raw_output)`, `Declined(reason)`, or `Failed(message)` outcome.
   `raw_output` is an uninterpreted byte sequence; Gantry owns UTF-8 decoding,
   JSON parsing, schema validation, and repair retries. Hook futures MUST be
   `Send`; one hook instance is used serially for one Gantry task.
   Returning `Completed(raw_output)` means the integration considers the model
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
    returns an append receipt containing the assigned stable record ID and next
    contiguous sequence number through a per-journal linearizable ordering. A
    read returns those finalized immutable versioned records in sequence order
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
   attempt IDs, retry timing, payload retention, journaling, and required-sink
   failure semantics. The embedding API MUST expose a stable retry-policy
   revision for each sink. Gantry journals the effective policy values with
   each event obligation, so recovery does not depend on an embedder retaining
   historical defaults. The embedder MUST resolve every required sink identity
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
    deletion policy for them. At-rest encryption, credential management, and
    operator authorization remain deployment concerns, but an implementation
    MUST provide enough separation between ordinary diagnostics and protected
    records for an embedder to enforce those policies without parsing free-form
    text.

The canonical serialization format and concrete Rust data-type layout are
implementation choices. They MUST preserve every field, category, ordering,
durability boundary, and compatibility rule made normative by this document.
