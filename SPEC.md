# Gantry Language and Runtime Specification

- [Gantry Language and Runtime Specification](#gantry-language-and-runtime-specification)
  - [1. Status and Scope](#1-status-and-scope)
    - [1.1 Language at a glance](#11-language-at-a-glance)
    - [1.2 Reading the surface syntax](#12-reading-the-surface-syntax)
    - [1.3 V1 design boundary](#13-v1-design-boundary)
    - [1.4 Authoring conventions](#14-authoring-conventions)
    - [1.5 Core terminology](#15-core-terminology)
  - [2. Normative Language](#2-normative-language)
    - [2.1 Requirement identifier registry](#21-requirement-identifier-registry)
  - [3. Implementation and Execution Model](#3-implementation-and-execution-model)
    - [3.1 Formal domains and core language](#31-formal-domains-and-core-language)
    - [3.2 Static semantics](#32-static-semantics)
    - [3.3 Control-flow, ownership, and package validity](#33-control-flow-ownership-and-package-validity)
    - [3.4 Dynamic semantics](#34-dynamic-semantics)
    - [3.5 Operations, tasks, cancellation, and failure](#35-operations-tasks-cancellation-and-failure)
    - [3.6 Durability refinement and semantic properties](#36-durability-refinement-and-semantic-properties)
  - [4. Source Organization](#4-source-organization)
  - [5. Values, Bindings, Structs, and Tagged Types](#5-values-bindings-structs-and-tagged-types)
  - [6. Workflows, Methods, and Actions](#6-workflows-methods-and-actions)
  - [7. Integration Operations, Agents, Hooks, and Sessions](#7-integration-operations-agents-hooks-and-sessions)
  - [8. Structured Output and Validation](#8-structured-output-and-validation)
  - [9. Control Flow](#9-control-flow)
  - [10. Parallel Execution](#10-parallel-execution)
  - [11. Durable Execution and Resume](#11-durable-execution-and-resume)
  - [12. Observability and Tooling Modes](#12-observability-and-tooling-modes)
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
  - [14. Authoring Examples and Common Errors](#14-authoring-examples-and-common-errors)
    - [14.1 Minimal package entry point](#141-minimal-package-entry-point)
    - [14.2 Modules, imports, and package-wide agents](#142-modules-imports-and-package-wide-agents)
    - [14.3 Primitive values, structs, tagged values, and structural routing](#143-primitive-values-structs-tagged-values-and-structural-routing)
    - [14.4 Inherent methods and scoped agent selection](#144-inherent-methods-and-scoped-agent-selection)
    - [14.5 Prompt strings, interpolation, and escaping](#145-prompt-strings-interpolation-and-escaping)
    - [14.6 Reusable model judgments and conditional chains](#146-reusable-model-judgments-and-conditional-chains)
    - [14.7 General, pre-test, and post-test loops](#147-general-pre-test-and-post-test-loops)
    - [14.8 Parallel homogeneous work and `List<T>` joins](#148-parallel-homogeneous-work-and-listt-joins)
    - [14.9 Parallel heterogeneous work and `Tuple<...>` joins](#149-parallel-heterogeneous-work-and-tuple-joins)
    - [14.10 `joinall()`, Unit tasks, and detachment](#1410-joinall-unit-tasks-and-detachment)
    - [14.11 Nested modules and qualified paths](#1411-nested-modules-and-qualified-paths)
    - [14.12 Explicit harness actions and named prompt inputs](#1412-explicit-harness-actions-and-named-prompt-inputs)
    - [14.13 Explicit operation failure handling with `attempt`](#1413-explicit-operation-failure-handling-with-attempt)
    - [14.14 Common invalid forms and their corrections](#1414-common-invalid-forms-and-their-corrections)
  - [15. Required Embedding Interfaces](#15-required-embedding-interfaces)
    - [15.1 Interpreter lifecycle](#151-interpreter-lifecycle)
    - [15.2 Hooks and session integration](#152-hooks-and-session-integration)
    - [15.3 Cancellation](#153-cancellation)
    - [15.4 Executor services](#154-executor-services)
    - [15.5 Journal storage](#155-journal-storage)
    - [15.6 Event delivery](#156-event-delivery)
    - [15.7 Configuration](#157-configuration)
    - [15.8 Protocol versioning](#158-protocol-versioning)
    - [15.9 Thread safety](#159-thread-safety)
    - [15.10 Protected data](#1510-protected-data)

## 1. Status and Scope

<a id="GNT-1.0"></a>

Gantry is a Rust-inspired control language for coordinating model-backed
agents. It is named for the elevated structure spanning a factory floor: a
Gantry program directs and observes the work performed below it.

This document is the draft design contract for Gantry v1.0. It combines the
portable source-language contract with the runtime and embedding contract
needed to execute, observe, interrupt, and resume that language consistently.
It is therefore broader than an authoring guide: source authors can follow the
focused reading paths below, while implementers and integrators must account
for the operational sections. Publication does not imply that the current
implementation is complete or conforming; the repository README reports
implementation status. Until v1.0 is declared stable there, the contract may
still change without a source-language version change. A
pre-stable conformance claim MUST therefore identify both source-language
version 1.0 and one immutable revision of this document, expressed as either
the repository commit containing `SPEC.md` or the lowercase hexadecimal
SHA-256 digest of the exact `SPEC.md` bytes. The claim applies to the complete
identified revision, not to a selected subset of its requirements.

Sections 1.1 through 1.4 and Section 14 are non-normative reading and
authoring aids. The remainder of Sections 1 through 13 and all of Section 15
are normative unless a passage is explicitly labeled non-normative. Examples
and tables in a non-normative passage illustrate the contract but do not add
requirements. The capitalized key words defined in Section 2 identify
requirement strength, but lowercase declarative statements in normative
passages remain part of the language and operational contract.

The source language is designed around three priorities, in order:

1. **Visible operation sites.** Model and harness work is marked by `prompt`,
   `decide`, or `action` where that work is defined. An ordinary workflow call
   may reach such a site in the called body, so this guarantee is source-local
   visibility rather than a claim that call sites are effect-free.
2. **Readable control flow.** Familiar blocks, typed values, pattern routing,
   loops, and structured concurrency should make execution order and ownership
   apparent without specialized notation.
3. **One portable meaning.** Validation, retry, cancellation, and resume rules
   are specified precisely enough that integrations do not silently change a
   program's meaning.

These priorities favor a small source surface, not a small implementation
contract. Sections 3 through 12 and 15 are intentionally detailed because
durability and integration behavior must be portable; that protocol detail is
not additional syntax an author must learn. Use these reading paths:

- **Source authors:** begin with Sections 1.1 through 1.5 and Section 14. Use
  Sections 4 through 10 only for the semantics of a construct in question and
  Section 13 when exact grammar is needed.
- **Language tooling authors:** read Sections 4 through 10, requirements
  `GNT-12.9` through `GNT-12.11`, and Section 13. Section 13 contains both the
  formal grammar and a small number of syntax-position and disambiguation rules
  enforced during semantic analysis. Protocol and persistence requirements are
  relevant only when the tool also executes programs or claims full
  conformance.
- **Integrators:** begin with Sections 1 and 3, then read Sections 7, 8, 10
  through 12, and 15 before consulting the remaining normative sections.
- **Conformance implementers:** read the complete normative contract.

This document uses the following related but distinct judgments and
conformance profiles:

- **Syntactically valid** source is admitted by the lexical and syntactic
  grammar in Section 13 and the package-loading rules required to parse it.
- **Source-valid** source is syntactically valid and satisfies every applicable
  static semantic rule in this document. Those rules are concentrated in
  Sections 4 through 10, with syntax-position and disambiguation rules stated
  alongside the grammar in Section 13. Requirements `GNT-12.9` through
  `GNT-12.11` define how an analyzer evaluates and reports that single
  judgment; they do not add a second set of source-acceptance rules. Source
  validity does not imply that a particular integration can resolve the
  package's agents or actions.
- A **frontend-profile implementation** parses complete packages and provides
  syntax diagnostics under Sections 4, 12, and 13.
- An **analyzer-profile implementation** additionally decides source validity,
  generates canonical schemas, reports inferred effects, and enforces control-
  flow and task-ownership rules.
- An **evaluator-profile implementation** additionally executes source-valid
  packages when `main`'s transitive inferred effect set omits `spawn`, `join`,
  and `background`, according to the sequential subset of the abstract machine
  in Section 3. It need not implement spawned tasks, persist, or resume
  executions. A package whose `main` effect set includes any of those three
  effects remains source-valid but is outside this profile's execution
  capability; unused workflows do not restrict execution capability.
- A **concurrent-evaluator-profile implementation** additionally implements
  tasks, cancellation, joins, and background ownership transfer under Section
  10.
- A **durable-runtime-profile implementation** additionally implements the
  crash, resume, evolution, and durable-observation refinements in Sections 11
  and 12.
- An **embedding-profile implementation** exposes the interfaces and versioned
  protocol schemas in Section 15. It MUST identify which evaluator profile it
  embeds. Interfaces for concurrent or durable capabilities apply only when
  the embedding includes the corresponding evaluator profile; in particular,
  a nondurable embedding does not require journal storage or resume.
- A **conforming Gantry v1 implementation** satisfies every requirement of one
  or more named profiles. A claim MUST name all claimed profiles and MUST NOT
  imply support for an unclaimed profile. The unqualified phrase “conforming
  Gantry v1 implementation” means all six profiles above.
- A **conforming Gantry v1 integration** satisfies every requirement assigned
  to the embedder, harness, or integration for the features it configures,
  including hooks, sessions, executor services, journal storage, and event
  sinks. Optional services create no obligation when they are not configured.
- A **conforming Gantry v1 deployment** combines a conforming implementation
  and integration and satisfies the complete normative language, execution,
  durability, observability, and embedding contract for every claimed
  profile. Conformance claims MUST name the claimed role and profiles; an
  implementation cannot guarantee behavior that the contract assigns to
  integration code after control crosses an embedding interface, but it MUST
  detect and report integration failures where this specification requires it
  to do so.

Profile applicability is capability-scoped. A frontend-profile claim covers
package discovery needed for parsing, lexical and syntactic grammar, and syntax
diagnostics. An analyzer-profile claim additionally covers name and type
resolution, source validity, canonical schemas and core IR, effect analysis,
control-flow completion, and task-ownership analysis. An evaluator-profile
claim additionally covers sequential execution, integration operations,
sessions, validation, and root-task cancellation. A concurrent-evaluator-
profile claim additionally covers spawned tasks, joins, detachment, and their
cancellation semantics. A durable-runtime-profile claim additionally covers
journaling, resume, migration, durable events, and delivery recovery. An
embedding-profile claim covers the host interfaces in Section 15 and the
integration-facing obligations used by the evaluator profile it embeds.
Requirements for an earlier capability also apply to profiles defined as
adding to it. Requirements for a later or orthogonal capability do not: for
example, a frontend-only implementation need not execute hooks or provide a
journal, and a nondurable evaluator need not implement resume. When one
requirement block contains clauses for more than one capability or role, each
clause applies only to the profile or integration role whose behavior it
governs. A conformance manifest MUST map every requirement identifier to each
applicable claimed profile, or record a profile-based `not-applicable`
justification.

Every normative requirement has a stable identifier in one of two forms:
`GNT-<section>.<item>[-<label>]` for prose blocks, or
`GNT-3-<family>-<label>` for named formal rules, where `<family>` is `F`, `T`,
`M`, or `D`. Published editions MUST preserve an
identifier's meaning within one source-language
major version and MUST NOT reuse a retired identifier. The machine-readable
conformance manifest required by Section 15 maps each claimed profile and
requirement identifier to one or more executable tests or an explicit
`not-applicable` justification. Prose numbering may change editorially, but
the published manifest preserves the stable identifiers.

Accordingly, “accepting a source-valid package” means recognizing it as a
valid Gantry package. It does not mean that every execution request must start:
entry-input validation, integration preflight, journal ownership, persistence,
and required event delivery can still produce the structured start failures
defined later in this document.

Gantry is harness-neutral. Mezzanine may integrate Gantry, but it is not an
assumed runtime or part of the language contract. An integration supplies the
agents, models, tools, transport, credentials, resource policy, and any
provider-specific behavior.

The v1 language deliberately separates deterministic orchestration from
integration-backed work. Bindings, construction, call dispatch, assignment,
projection, pattern routing, modules, joins, and task ownership are
interpreter operations. Executing a called workflow may still reach explicit
integration operations in that workflow's body. Every source-level request
that crosses the integration boundary is visibly introduced by `prompt`,
`decide`, or `action` at the operation site; an ordinary function or method
call site does not itself dispatch a hook, although executing the called body
may reach explicit external operations. `prompt` and `decide` request
model-backed, externally read-only work. An `action` invocation requests a
named, typed harness capability with a declared recovery class. An integration
may perform provider-internal read-only work while fulfilling a model
operation, as defined in Section 7, but state-changing work requires an
explicit action invocation.
Interpolation and named-input evaluation never dispatch a hook. Typed
strict-JSON values are the boundary between integration-backed work and source
execution: raw hook outcomes cross the embedding boundary first, and Gantry
alone admits a value into source execution after decoding, validation,
normalization, and durable acceptance. This explicitness is a core readability
requirement for both human and model authors.

The contract is organized into layers:

| Layer | What it specifies | Primary sections |
| --- | --- | --- |
| Language surface | Packages, values, workflows, visible operations, and control flow | Sections 4 through 10 and 13 |
| Static source validity | Name and type resolution, syntax-position restrictions, schema generation, control-flow completion, and task ownership | Rules concentrated in Sections 4 through 10, with grammar-adjacent rules in Section 13; analysis interface in requirements `GNT-12.9` through `GNT-12.11` |
| Portable execution | Interpretation, validation, concurrency, durability, and observability | Sections 3 and 7 through 12 |
| Formal syntax | Normative lexical and syntactic grammar | Section 13 |
| Authoring guide | Non-normative focused examples and corrections | Section 14 |
| Host contract | Required embedding interfaces | Section 15 |

The v1 publication MUST expose this contract and its companion protocol
schemas, conformance corpus, and authoring fixtures as separately addressable,
versioned artifacts. A machine-readable index MUST map each requirement and
companion artifact to its applicable profiles so an implementation or
integration can select the contract for its claim without duplicating the
normative prose into several differently maintained documents. The examples in
Section 14 MUST be maintained as executable positive or negative fixtures
rather than copied, unchecked prose.

These layers are complementary rather than an order of precedence. The lexical
and syntactic productions in Section 13 determine whether source can be
parsed. The static requirements concentrated in Sections 4 through 10,
together with the grammar-adjacent semantic rules in Section 13, determine
whether parsed source is source-valid. Sections 3 and 7 through 12 define what
executing it means, and Section 15 defines the host capabilities required to
provide that meaning. A grammatical form is therefore not necessarily a valid
program. Section 14 illustrates the normative contract and cannot extend or
override it. If two normative passages cannot both be satisfied, that is a
defect in this specification rather than permission for an implementation to
choose one silently.

Concrete Rust type signatures may remain implementation-defined only where
the semantic contract is fully specified here.

### 1.1 Language at a glance

A complete model-backed program can be this small:

```gantry
agents { worker }
default agent = worker;

fn main(topic: String) -> String {
    prompt "Summarize ${topic} clearly." -> String
}
```

The declarations identify the available agent and default selection, `main`
defines the typed entry point, `${topic}` performs deterministic textual
interpolation, and `prompt ... -> String` is the one visible model operation
and its output contract. Deterministic-only and action-only packages need no
agent declarations.

The core authoring model is deliberately small:

1. Declare typed data and workflows.
2. Use ordinary expressions and control flow for facts the interpreter can
   compute.
3. Use `prompt` for model-generated values, `decide` for model judgment, and
   `action` for harness capabilities.
4. Wrap one of those explicit operations in `attempt` only when source should
   handle its declared operation failures as data.
5. Use `spawn` only when work should overlap, then visibly consume every task
   with `join`, `joinall()`, or `detach`.

The source surface is organized around these families:

| Need | Canonical forms | Details | Focused examples |
| --- | --- | --- | --- |
| Package structure | `mod`, `use` | Section 4 | Sections 14.2 and 14.11 |
| Typed data | `struct`, `enum`, `Option`, `Result`, `List`, `Tuple` | Section 5 | Section 14.3 |
| Reusable orchestration | `fn`, `impl` | Section 6 | Sections 14.4 and 14.6 |
| Integration-backed work | `prompt`, `decide`, `action` | Sections 6 through 8 | Sections 14.1, 14.6, and 14.12 |
| Explicit operation failure handling | `attempt` | Sections 5, 7, and 8 | Section 14.13 |
| Model context | `with`, `session` | Sections 6 and 7 | Sections 14.4 through 14.7 |
| Sequential routing | `if`, `if let`, `match` | Section 9 | Sections 14.3 and 14.6 |
| Repetition | `loop`, `while`, `until` | Section 9 | Section 14.7 |
| Parallel work | `spawn`, `join`, `joinall`, `detach` | Section 10 | Sections 14.8 through 14.10 |

A representative workflow shows how these forms compose without requiring an
all-features example:

```gantry
struct Report {
    title: String,
    summary: String,
    sources: List<String>,
}

agents { researcher, editor }
default agent = researcher;

action read_only search(topic: String) -> List<String>;

fn main(topic: String) -> Report {
    let sources: List<String> = action search(topic);

    spawn draft -> Report {
        prompt "Draft a report about ${topic}."
            using { sources }
            -> Report
    }

    spawn headline -> String {
        with editor {
            prompt "Write a concise headline for ${topic}." -> String
        }
    }

    let (report, proposed_title): Tuple<Report, String> =
        join(draft, headline);

    if decide "Does this report need revision?" using { report } {
        return with editor {
            prompt "Revise the report and use ${proposed_title} as its title."
                using { report }
                -> Report
        };
    }

    report
}
```

Every integration crossing remains visible: `action` invokes the declared
harness capability, each `prompt` requests model output, and `decide` requests
model judgment. Construction, assignment, routing, workflow calls, and joins
are interpreter operations, although a called workflow can reach explicit
integration operations in its body. Section 14 provides focused examples for
the remaining syntax instead of combining every construct into one program.

### 1.2 Reading the surface syntax

The following non-normative reading rules summarize the distinctions that are
most important when humans or models author Gantry source:

| Author intent | Canonical source shape | What it does |
| --- | --- | --- |
| Define a workflow | `fn name(...) -> T { ... }` | Creates interpreter-managed orchestration; only explicit operations reached in its body cross the integration boundary. |
| Request a model-produced value | `prompt "..." -> T` | Performs one logical model operation and validates its output as `T`. |
| Request model judgment | `decide "..."` | Performs one logical model operation and returns a sealed `Decision`. |
| Invoke a harness capability | `action path(...)` | Performs one logical action operation against a declared action signature. |
| Handle an expected operation failure | `attempt prompt ...`, `attempt decide ...`, `attempt action path(...)` | Performs that one explicit operation and returns `Result<T, OperationError>` instead of propagating the operation failures that `attempt` is defined to convert. |
| Select an agent | `with agent_name { ... }` | Sets the active agent for model operations dynamically reached from the block, including through workflow calls and spawned children, unless overridden. |
| Select conversational continuity | `session(fork) { ... }` | Establishes the active logical session for model operations dynamically reached from the block; nested unmodified operations use it inline. |
| Run work concurrently | `spawn task { ... }`, `spawn task -> T { ... }` | Creates an owned child task; omit `-> T` only for a Unit task. The handle must later be consumed by `join`, `joinall()`, or `detach`. |

These forms are intentionally visually distinct. In particular, an ordinary
workflow call never stands in for `prompt`, `decide`, or `action`, and none of
those three operation forms is implicit in assignment, interpolation, routing,
or concurrency syntax. This distinction does not make an ordinary workflow
call transitively pure: its called body may execute visible operation sites.
Authors and tools that need call-site effect information use the transitive
workflow summaries required by Section 6.

- `prompt` visibly performs model-backed work and optionally returns the type
  written after `->`. An omitted annotation or `-> Unit` means that the
  operation returns the sole `Unit` value `()`.
- `decide` visibly performs model-backed judgment and returns a sealed
  `Decision` containing a `Bool` decision and nonempty rationale. A decision
  can be retained and passed; its read-only fields can
  be projected, but source cannot construct or mutate one. A `decide`
  expression has no result annotation because its result is always
  `Decision`.
- `action <path>(...)` visibly invokes a source-declared, typed harness action.
  Its result type is written on the action declaration, not at the invocation
  site. It is distinct from an ordinary workflow call and from model
  selection.
- `attempt` wraps exactly one syntactic `prompt`, `decide`, or `action`
  expression. It does not catch failures from a workflow call, deterministic
  evaluation, journaling, the executor, or task cancellation.
- `using { ... }` supplies ordered typed inputs to `prompt` or `decide`
  without rendering them into the authored prompt text.
- `${...}` computes deterministic prompt input. It can read and construct
  values, but cannot hide another external operation, mutation, join, or
  control-flow transfer.
- `Bool` expressions, `match`, and `if let` route validated structure
  deterministically. Use them when the answer follows mechanically from
  available values. Use `decide` when the answer requires interpretation,
  quality assessment, intent, or policy judgment.
- `with <agent> { ... }` is lexically delimited and dynamically inherited by
  model operations reached from its block. `session(<directive>) { ... }`
  similarly delimits conversational continuity. Neither construct hides the
  `prompt` and `decide` sites inside it.
- `spawn` makes concurrency explicit. Every spawned handle must be consumed
  visibly by `join`, `joinall()`, or `detach` on every normal path that leaves
  its scope.
- Ordinary call dispatch, assignments, construction, projection, pattern
  routing, and joins are deterministic interpreter work. A called workflow's
  body may reach explicit integration operations. If a dynamic call path
  reaches no `prompt`, `decide`, or `action`, it dispatches no integration
  operation.

The following non-normative table summarizes the visible execution boundary.
It is a reading aid; Sections 6 through 8 define the normative contracts:

| Source form | Work requested | Source result | Agent/session applies | V1 default structured-output retries |
| --- | --- | --- | --- | --- |
| `prompt "..." -> T` | Model-backed generation | Declared `T`, or `Unit` when omitted | Yes | 2 |
| `decide "..."` | Model-backed judgment | Sealed `Decision` | Yes | 2 |
| `action path(...)` | Declared harness capability | Declared type, or `Unit` when omitted | No | 0 |
| `workflow(...)` | Interpreter-managed call dispatch; the body may reach explicit operations | Workflow's declared result | Only to explicit operations reached in the body | Not applicable |

The retry counts are defaults, not fixed operation behavior. Interpreter
configuration may replace them, and an operation-local `retry_limit` replaces
the applicable configured default. A `non_idempotent` action must always have
an effective retry limit of zero; a positive source override is invalid.
Section 8 defines the normative rules.
Wrapping an operation in `attempt` does not change its retry policy or make it
effect-free; it changes only the narrow operation failures listed in Section 5
into an explicit `Result<T, OperationError>`.

### 1.3 V1 design boundary

The following non-normative summary makes deliberate v1 omissions visible.
It is a reading aid rather than a substitute for the normative requirements
in later sections:

- Gantry is an orchestration language, not a general-purpose language. Its
  source values include `Unit`, `Bool`, bounded exact `Int`, finite binary64
  `Float`, strings, structs, enums, options, results, lists, tuples, sealed
  decisions, and sealed operation errors. Numeric operations are deliberately
  small and deterministic.
- Integration-backed work is limited to the explicit `prompt`, `decide`, and
  `action` operations. `prompt` and `decide` are model-facing. `action` invokes
  a typed capability declared by the package and resolved by the integrating
  harness.
- V1 has checked arithmetic, numeric ordering, short-circuit Boolean algebra,
  exact equality, finite list `for` iteration, and a small deterministic String
  library, but no user-defined generics, traits, general exception handling,
  regular expressions, or locale-sensitive text processing. Semantic
  judgments remain agent-mediated.
- Raw entry input and raw hook output are subject to explicit byte limits, and
  every value is subject to explicit nesting-depth and total-node limits,
  before it can consume unbounded parser or interpreter resources. These
  limits are part of resumable execution identity rather than implementation-
  dependent hidden policy.
- Lists and tuples are typed aggregates. Source can construct, pass, return,
  interpolate, and project them. Tuples additionally support pattern
  destructuring. Lists expose deterministic `len()` and dynamic `Int`
  indexing, enabling explicit bounded traversal with `while`; list-pattern
  destructuring and aggregate mutation remain excluded.
- `Result<T, E>` represents a declared, expected source-level outcome. Hook
  failure, invalid structured output, cancellation, journal failure, and retry
  exhaustion are never implicitly converted to `Err`; only an explicit
  `attempt` converts the narrow operation failures in Section 5 to
  `OperationError`.
- `Map<T>` and an opaque artifact-reference type are deferred. They require
  lookup, lifetime, authorization, and resume contracts that v1 does not need
  to express typed model and action control flow.
- A struct field default is a source-construction convenience. Operation
  output must still contain every non-optional field, even when that field has
  a source default; only `Option<T>` properties may be omitted from hook
  output.
- `None` is exclusively the absent `Option<T>` value whose type must be known
  from context. `Unit` and `()` represent no-information results.
- Attached concurrency is structured and ownership-visible. A spawned task
  must be joined, joined through `joinall()`, or explicitly transferred to
  durable background ownership with `detach` on every normal path before its
  handle leaves scope.

V1 also keeps integration protocol controls out of the source language unless
they change portable orchestration semantics. Provider selection, credentials,
transport, executor choice, persistence, event sinks, resource-limit values,
and operation timeouts therefore remain embedding configuration. New source
syntax should be introduced only when an author must express a portable
semantic distinction at the operation or control-flow site; exposing a host
implementation choice is not sufficient reason to enlarge the language.

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
- Treat each visible integration operation as logically singular but physically
  repeatable. Validation repair and interruption recovery can dispatch the
  same operation more than once, so harness actions with external side effects
  should use the stable operation ID as their deduplication key whenever the
  integration can do so. Distinct dispatch IDs identify physical attempts for
  audit; using a dispatch ID as the deduplication key would not suppress a
  repeated attempt of the same logical operation.
- Prefer one model operation per statement or trailing expression. Keep the
  `prompt` or `decide` keyword, its modifiers, template, and result annotation
  as one visibly continuous construct; do not rely on unusual line breaks to
  make an operation resemble ordinary deterministic code. When deterministic
  computation uses an operation's result, bind the result first rather than
  burying the operation inside a larger expression statement.
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
- Treat `Float` equality as exact normalized binary64 equality. Use explicit
  bounds or a model-backed `decide` when the intended comparison is
  approximate or semantic rather than bit-for-bit numeric equality.
- Use triple-quoted block prompts for multiline instructions and ordinary or
  raw quoted prompts for short text. Keep result annotations on the same
  visual operation, even when the template spans several lines.
- Use `with <agent> { ... }` for every nondefault agent selection; it may wrap
  one operation or group several. Use `session(<directive>) { ... }` when
  several operations deliberately share one session choice, and use a
  `session` modifier on one `prompt` or `decide` for a one-off session
  override. Gantry has no operation-local agent modifier.
- Give workflows that return `Decision` question-like names and other
  workflows action- or result-oriented names. Prefer a direct `decide` for a
  condition that does not need reusable preparation.
- Place `join`, `joinall()`, or `detach` near the corresponding spawns when
  practical. A distant ownership transfer is valid but makes parallel flow
  harder to audit.
- Prefer imported or `crate::`-rooted item paths when the unqualified lookup
  would not be obvious from the surrounding module.
- Keep agent names visually distinct from workflow, module, binding, and task
  names even though the grammar makes each namespace use unambiguous. This
  makes `with <agent>` blocks easier to scan in model-authored source.

The valid examples in Section 14 follow these conventions and serve as the
preferred source-style reference for v1. They remain non-normative: Sections
4 through 10 and 13 determine whether source is valid and what it means.

### 1.5 Core terminology

<a id="GNT-1.5"></a>

The following terms distinguish source constructs from runtime and integration
activity throughout this specification:

- A **workflow** is a source `fn` or inherent method. Calling a workflow
  creates an interpreter frame; the call is not itself model-backed work. A
  workflow may return `Decision` through the ordinary `-> Decision` result
  annotation.
- A **decide operation** is the logical model operation created by one dynamic
  evaluation of a `decide` expression. `Decision` (capitalized) is the sealed
  value type produced by a successful decide operation. A workflow call or a
  retained `Decision` value is not another decide operation.
- An **action declaration** is a typed package item that names an external
  harness capability. It has no Gantry body. An **action invocation** is an
  `action <path>(...)` expression resolved against that declaration.
- An **integration operation** is a source-visible `prompt`, `decide`, or
  action invocation. A **model operation** is specifically a `prompt` or
  `decide`; an action is integration-backed but is not model-backed.
- A **static integration-operation site** (shortened to **operation site** when
  the context is unambiguous) is one authored `prompt`, `decide`, or `action`
  invocation expression at a particular source location. A site exists even
  when no execution path reaches it. Executing a site zero, one, or several
  times produces the corresponding number of logical operations. `spawn`,
  `join`, `joinall()`, and `detach` are **task-control sites**, not operation
  sites, because they never dispatch an `OperationHook` by themselves.
- A **logical operation** is one dynamic execution of a source `prompt`,
  `decide`, or action invocation. It has one stable operation ID and
  produces at most one consumable operation result. Failed or invalid
  attempts are outcomes of physical dispatches, not additional logical
  operation results.
- A **physical dispatch** is one invocation of `OperationHook` for a logical
  operation. Validation repair and recovery may cause several physical
  dispatches for one logical operation, each with a distinct dispatch ID.
- A **hook outcome** is `Completed(raw_output)`, `Declined(reason)`, or
  `Failed(category, message)`. An **operation result** is the validated and
  normalized value, including `Unit`, or sealed `Decision` that Gantry durably
  derives from `Completed` and may consume. Decline and failure are operation
  failures; only an explicit `attempt` converts them into source-visible
  `OperationError` values.
- A **Gantry task** is an interpreter execution lane: the root task or one
  child created by `spawn`. A task is not an agent, model, provider request,
  or executor thread.
- An **agent** is a logical source-declared name selected by `with` or by the
  package default. The integration maps that name to its model or agent
  implementation.
- A **harness action** is a package-declared capability fulfilled through an
  action operation. Provider-internal work during a model operation is limited
  to the read-only behavior in Section 7; externally state-changing work must
  use an action with an explicit recovery class.
- A **tagged value** is an enum or `Result<T, E>` value whose strict-JSON
  representation carries an explicit variant discriminator.
- A **deterministic condition** is a `Bool` expression evaluated over already
  validated values. Primitive arithmetic, Boolean and String operations,
  pattern tests, and exact equality are interpreter work and never invoke a
  hook by themselves.
- A **named input** is one ordered, typed `using` entry supplied separately
  from rendered prompt text.
- An **analysis error** rejects a package before execution because its parsed
  source violates a static language rule such as name resolution, typing,
  definite completion, schema generation, or task-handle ownership.
- A **start failure** rejects a requested new execution before Gantry returns
  an accepted execution ID. A **resume-start failure** rejects one resume
  attempt before recovered interpretation begins and without changing the
  execution's durable terminal status. Both are embedding outcomes rather
  than failures of a running Gantry task.
- A **runtime error** occurs after a new execution has a durable execution-
  start record or after a resume begins advancing recovered state. Runtime
  errors are task-local unless a rule explicitly makes one execution-wide.
- A **foreground outcome** is the completion of root `main`. A **terminal
  outcome** is known only after foreground and detached work have
  settled and required terminal state is durable. Foreground success can
  therefore precede a terminal detached-task failure.

## 2. Normative Language

<a id="GNT-2.0"></a>

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in BCP 14
(RFC 2119 and RFC 8174) when, and only when, they appear in all capitals as
shown here.

Normativity is determined first by section scope: passages identified as
normative define the contract, including lowercase declarative statements.
The capitalized BCP 14 terms express requirement strength within that
contract; their absence does not make a normative statement merely
informative. Non-normative examples and authoring guidance do not add or
override requirements. When an example conflicts with normative prose or the
grammar, the normative prose and grammar govern and the example is a defect in
this document.

### 2.1 Requirement identifier registry

<a id="GNT-2.1"></a>

A **requirement block** is the smallest independently anchored normative unit
in this document. Every normative statement belongs to exactly one requirement
block and inherits that block's stable identifier. A numbered normative item
is one block, including its subordinate paragraphs, lists, tables, and code
fences. An unnumbered normative section introduction is its section's `.0`
block. Each unnumbered grammar or embedding subsection is one block. Each
bracketed, anchored formal-rule heading such as `[GNT-3-T-VALUE]` is one named
formal-rule block. Labels inside its inference figure, such as `T-Value`,
`T-Name`, and `T-None`, are subrules of that block and inherit its identifier;
they are not independently registered blocks. Non-normative Sections 1.1
through 1.4 and 14 have no requirement identifiers.

Every block begins with an inline HTML anchor whose `id` is its requirement
identifier. The anchors, rather than mutable line numbers or Markdown heading
slugs, are the authoritative registry. A range below expands inclusively; each
expanded identifier and each named formal-rule identifier MUST occur exactly
once as an `id` attribute in this document. An edition MUST fail its
publication check if an identifier is missing, duplicated, or attached to more
than one block.

| Normative scope | Registered identifiers |
| --- | --- |
| Status, terminology, and normativity | `GNT-1.0`, `GNT-1.5`, `GNT-2.0`, `GNT-2.1` |
| Implementation summary items | `GNT-3.0`, `GNT-3.1` through `GNT-3.15` |
| Formal kernel | Every named `GNT-3-F-*`, `GNT-3-T-*`, `GNT-3-M-*`, and `GNT-3-D-*` rule in Sections 3.1 through 3.6 |
| Source organization | `GNT-4.0`, `GNT-4.1` through `GNT-4.17` |
| Values and types | `GNT-5.0`, `GNT-5.1` through `GNT-5.20` |
| Workflows and actions | `GNT-6.0`, `GNT-6.1` through `GNT-6.12` |
| Integration operations | `GNT-7.0`, `GNT-7.1` through `GNT-7.18` |
| Structured output | `GNT-8.0`, `GNT-8.1` through `GNT-8.13` |
| Control flow | `GNT-9.0`, `GNT-9.1` through `GNT-9.12` |
| Parallel execution | `GNT-10.0`, `GNT-10.1` through `GNT-10.14` |
| Durable execution | `GNT-11.0`, `GNT-11.1` through `GNT-11.11` |
| Observability | `GNT-12.0`, `GNT-12.1` through `GNT-12.11` |
| Grammar | `GNT-13.0`, `GNT-13.1` through `GNT-13.9` |
| Embedding | `GNT-15.0`, `GNT-15.1` through `GNT-15.10` |

Adding an independently testable obligation to an existing block SHOULD add a
descriptive child identifier by appending a suffix such as `-request-header`
to its parent identifier; moving existing text without changing its meaning
preserves its identifier. Splitting a block
retires the parent or retains it as an umbrella while assigning new child
identifiers. Merging blocks retires all but one identifier. Retired identifiers
MUST remain reserved in the publication manifest and MUST NOT acquire a new
meaning within source-language major version 1. Conformance tests and the
machine-readable manifest cite these anchors directly.

## 3. Implementation and Execution Model

<a id="GNT-3.0"></a>

This section defines shared implementation obligations and the normative
semantic kernel used by the source-language, concurrency, and durability
profiles. Requirement applicability follows the capability boundaries in
Section 1: a frontend-only claim does not acquire evaluator or durability
obligations merely because they are collected here. Items 1 through 10 define
implementation boundaries; items 11 through 15 summarize the formal relations
defined in Sections 3.1 through 3.6.

<a id="GNT-3.1"></a>

1. A conforming Gantry v1 implementation claiming the analyzer profile MUST
   recognize as source-valid every
   source program admitted by the grammar in Section 13 that also satisfies
   the semantic requirements in this document, and MUST reject source outside
   that grammar when operating in v1 mode. Recognizing a package as
   source-valid does not guarantee that a particular execution request starts;
   the pre-execution failures defined in Sections 4, 7, 11, 12, and 15 remain
   applicable. An implementation MAY provide an explicitly selected extension
   mode, but source accepted only by that mode MUST NOT be represented as
   portable Gantry v1 source. Profile conformance requires every applicable v1
   `MUST` and `MUST NOT` assigned to that profile; deployment conformance
   additionally requires the integration obligations defined above. A parser,
   analyzer, or nondurable evaluator may therefore make a precise profile
   claim without claiming the complete durable runtime.
<a id="GNT-3.2"></a>

2. An implementation MUST parse Gantry source according to Section 13 and
   preserve every semantic rule in this document. It MAY use handwritten or
   generated parsing, an AST, another private intermediate representation,
   bytecode, or native compilation. No such internal representation is a
   portable Gantry artifact, and an implementation MUST NOT require authors or
   embedders to supply source in another language or expose an additional
   language layer whose behavior changes Gantry semantics.
<a id="GNT-3.3"></a>

3. An implementation claiming the embedding profile MUST make Gantry available
   as an embeddable Rust library with an asynchronous execution API.
   “Portable” in this specification describes Gantry source and runtime
   semantics across conforming integrations, not a requirement to expose a
   language-neutral ABI.
   Gantry does not implement an agent, model provider, transport, or hidden
   asynchronous runtime itself. Gantry schedules logical tasks through an
   embedder-supplied executor adapter; it neither creates nor owns an async
   executor. The adapter MUST be replaceable through library configuration,
   not through Gantry source syntax.
<a id="GNT-3.4"></a>

4. The interpreter MUST control program flow, hook invocation, result
   validation, retry handling, and state transitions.
<a id="GNT-3.5"></a>

5. An integration MUST implement the hooks needed to perform model operations
   and declared harness actions. It is responsible for mapping Gantry agent
   names to its own agents or models and canonical action signatures to its
   own capabilities.
<a id="GNT-3.6"></a>

6. Model selection, tool access, approvals, authentication, persistence backend
   selection, logging backend selection, operation-level timeouts,
   and provider-specific cancellation mechanics belong to the integration.
   The integration also chooses the configurable resource-limit values that
   Section 15 requires, while Gantry MUST enforce those values at the language
   and protocol boundaries defined in this specification. Gantry owns the
   language-level execution, task-ownership, and cancellation state
   transitions defined in Sections 10 and 15 and MUST provide Gantry-owned
   cancellation tokens to integrations. The integration makes a best effort
   to stop provider work when those tokens are signalled. Gantry MUST control
   asynchronous Gantry task scheduling through the embedder-supplied executor
   adapter so parallel blocks retain the semantics in Section 10.
   Interpreter-only work MUST remain cooperatively cancellable even when it
   executes no hook or spawned task. Gantry MUST observe cancellation before a
   hook dispatch, child-task submission, workflow-frame entry, and
   every loop condition or back edge. Each task MUST also yield to the
   embedding executor after a finite configured number of its own consecutive
   deterministic interpreter transitions. One transition is one completed
   interpreter step that advances evaluation state without awaiting a hook,
   executor task, timer, journal operation, event delivery, or another host
   future. Checking cancellation does not itself consume a transition. The
   per-task counter resets after any such await or explicit scheduler yield.
   The yield quantum MUST be nonzero and finite, and Gantry MUST observe
   cancellation immediately before and after the yield. Changing the quantum
   affects scheduling only: it MUST NOT alter deterministic computation within
   one task, dynamic operation or task identities, retry accounting, or the
   semantic content and per-task order of logical evidence and events. It MAY
   alter timestamps and the global sequence order in which records and events
   from different tasks interleave. Recursion MUST use interpreter-managed
   frames rather than rely on unbounded native Rust stack growth. Each task MUST
   enforce the configured
   `maximum_workflow_call_depth`: the root `main` frame counts as depth one,
   and entering a function or method frame increases the
   active task's depth by one. A spawned block is a task body rather than a
   workflow frame; its first workflow call has depth one. Gantry MUST fail with
   a `workflow-call-depth-limit` deterministic-evaluation runtime error before
   entering a frame that would exceed the limit. Exhaustion of this or another
   configured interpreter resource limit MUST surface as a structured
   deterministic-evaluation runtime error, never a panic or silent process
   termination.
<a id="GNT-3.7"></a>

7. An implementation claiming the durable-runtime profile MUST make Gantry
   execution state serializable and resumable. It MUST provide a journal, or
   an equivalent durable execution record, sufficient to continue an
   interrupted execution from its recorded state. Section 11 defines the
   required recovery behavior.
<a id="GNT-3.8"></a>

8. Gantry does not promise deterministic replay. Re-execution of the same
   source and inputs MAY produce different integration results. Resumption
   MUST,
   however, reuse every committed physical hook outcome and MUST reuse every
   validated operation result already derived from committed journal state.
   A committed raw `Completed` outcome that has not yet passed validation is
   durable input to resumed validation, not yet a successful operation result.
<a id="GNT-3.9"></a>

9. The Gantry v1 source-language version is major `1`, minor `0`. The initial
   public protocol version for hook requests, journal envelopes, event
    envelopes, and the configuration identity is likewise major `1`, minor
    `0`, but source-language and protocol versions are distinct fields and
    MUST NOT be inferred from one another. A document reference to “v1”
    identifies source-language major version 1 and does not by itself permit a
    different protocol major version. Every new execution and resume request
    MUST explicitly select a supported source-language version through the
    embedding API; v1 source contains no in-file version pragma.
<a id="GNT-3.10"></a>

10. v1 makes no backward-compatibility promise for source syntax or the
   concrete Rust hook API. Public hook, journal, event, and configuration
    envelopes remain subject to the explicit major/minor compatibility rules
    in item 9 and Section 15. That protocol obligation preserves the meaning
    of a supported envelope; it does not require a later implementation to
    accept source written for another language version or preserve concrete
    Rust type signatures.
<a id="GNT-3.11"></a>

11. The normative semantics are defined over a desugared core language. A
   frontend MUST lower surface source to the following core constructs while
    retaining source spans: typed literals and variables; immutable aggregate
    construction and projection; mutable-root assignment; workflow-frame
    entry and return; ordered sequencing; Boolean and tagged-pattern branch;
    loop back edge; explicit `prompt`, `decide`, and `action` operation;
    `spawn`, all-settled `join`, and background ownership transfer; explicit
    agent and session dynamic scopes; `attempt`; and cancellation checks.
    Surface conveniences, including compound assignment, `if let`, `match`,
    `for`, `joinall()`, implicit trailing return, and operation modifiers,
    MUST desugar to those constructs without reordering evaluation or creating
    an integration operation. The canonical core IR schema, desugaring rules,
    and source-map schema are versioned public artifacts of the source-language
    major version rather than implementation-private bytecode.
<a id="GNT-3.12"></a>

12. Static semantics use judgments of the forms `Σ; Γ; Ω ⊢ e : T ! ε ⇒ Ω'`, `Σ;
   Γ; Ω ⊢ c ! ε ⇒ Φ`, and
    `Σ ⊢ package ok`. `Σ` is the resolved package signature, `Γ` maps source
    names to types and mutability, `Ω` maps task handles to their linear
    ownership states, `T` is a source type, `ε` is the least inferred effect
    set, and `Φ` maps each reachable completion kind to its outgoing ownership
    environment. The output `Ω'` is necessary because `join` and `joinall()`
    are expressions that consume handles. Expression evaluation MUST preserve
    types and produce the stated ownership environment; statement evaluation
    MUST produce the stated ownership environment for every reachable normal
    or transferring completion; and package validity MUST include name
    resolution, schema construction, control-flow completion, and the least
    fixed-point effect analysis in Section 6.
    Implementations MAY use another algorithm only when it accepts and rejects
    exactly the same packages and emits equivalent canonical types and effects.
<a id="GNT-3.13"></a>

13. Dynamic semantics use labelled configurations `⟨P, C, K, H, S, Q, B, R⟩`,
   containing the immutable package IR `P`, task
    configuration `C`, continuation/frame state `K`, linear handle state `H`,
    logical-session state `S`, pending logical operations `Q`, and remaining
    deterministic budgets `B`. `R` contains the active durable runtime
    revisions that later transitions may consult, including agent and action
    mapping revisions and compatible mutable execution-policy revisions. One
    abstract transition is written
    `configuration --label--> configuration'`. The portable labels are
    deterministic, operation-prepared, operation-outcome, operation-accepted,
    task-created, task-settled, ownership-transferred, cancellation, failure,
    and foreground/terminal completion. Integration code may choose an
    operation outcome only after an operation-prepared label; executor
    scheduling may choose among runnable tasks but MUST preserve each task's
    transition order. No telemetry, wall-clock value, provider identity, or
    implementation object may affect a transition unless this specification
    places its semantic value explicitly in `P`, `S`, `Q`, `B`, or `R`.
<a id="GNT-3.14"></a>

14. The durable runtime is a refinement of that labelled transition system, not
   a second language semantics. A durable implementation MAY combine,
    split, batch, snapshot, or compact physical storage records provided that
    every externally observable committed prefix corresponds to a prefix of
    abstract labels; no accepted operation result or ownership transition is
    observed before its causal state is durable; recovery resumes from a
    causally closed prefix; and a committed logical result is consumed at most
    once. Section 11 defines the required crash cuts and evidence, not one
    mandatory database layout.
<a id="GNT-3.15"></a>

15. Conforming implementations MUST test and document the following semantic
   properties for every applicable claimed profile: progress or a specified
    runtime error for a well-typed nonterminal configuration; preservation of
    source types across deterministic and accepted-operation transitions; linear task
    handles are never joined or transferred twice; one logical operation
    produces at most one consumable result; cancellation prevents later source
    consumption in the cancelled task; and every recovered execution is a
    continuation of one causally closed durable prefix. These are conformance
    obligations even though provider outcomes and cross-task schedules remain
    nondeterministic.

### 3.1 Formal domains and core language

<a id="GNT-3-F-META"></a>

**[GNT-3-F-META] Formal scope and metavariables.**

This section is normative. It completes the definitions summarized by items
11 through 15 above. The named rules are the authoritative
construct-by-construct static and dynamic semantics. Later sections define the
primitive signatures, protocol fields, limits, error codes, and predicates
referenced by these rules. A later rule that specializes a named premise is
part of that premise; prose does not otherwise create an additional typing or
transition rule.

The metavariables are:

- `τ` for a canonical value type and `v` for a normalized value of that type;
- `x` for a value binding, `h` for a lexical task-handle name, `η` for a
  stable dynamic handle identity, `t` for a stable dynamic task identity, `o`
  for a stable logical-operation identity, and `q` for a physical dispatch
  identity;
- `Σ` for the resolved package signature, `Γ` for value bindings of the form
  `x : (b, τ)`, `b` for binding mutability (`immutable` or `mutable`), `Ω` for
  task handles, and `ε` for effects;
- `ρ` for a task-local environment from value names to store roots, `χ` for a
  frame-local environment from lexical handle names to dynamic handle
  identities, `μ` for the task-local value store, `a` for active agent
  selection, and `s` for active logical-session identity; and
- `N`, `R`, `Br`, and `Co` for normal, return, break, and continue completion.

<a id="GNT-3-F-DOMAINS"></a>

**[GNT-3-F-DOMAINS] Core domains.** Canonical types are exactly:

```text
τ ::= Unit | Bool | Int | Float | String | D
    | Option<τ> | Result<τ,τ> | List<τ> | Tuple<τ,...,τ>
    | Decision | OperationError
```

`D` is a resolved declared struct or enum path, and every type satisfies
Section 5's well-formedness restrictions. Values are exactly the finite,
normalized inhabitants described by Section 5. A task handle is not a value.
The ownership environment maps each handle visible to the current task to one
of `attached(κ, τ)`, `joined(κ, τ)`, `detached(κ, τ)`, or
`discharged(κ, τ)`, where `κ` is the canonical static spawn site. Only
`attached` is available for a source use. `joined` and `detached` retain a
path's exact disposition; `discharged` is the analysis-only merge of paths
whose handles were consumed in different valid ways. Those states remain until
scope exit so a merge can distinguish a discharged obligation from an
available handle. Dynamic task identities are created only by `M-Spawn` and
are tracked in `H`, not in static `Ω`. Each dynamic handle identity `η` is
unique within its execution even when a loop, recursive call, or repeated call
executes the same static `spawn h` site more than once. The current lexical
handle environment `χ` resolves the source name `h` to that occurrence's `η`;
continuation frames preserve the environments of suspended callers and
enclosing scopes.

In the formal rules, **consumed** means any `joined`, `detached`, or
`discharged` state. The name `discharged` by itself denotes only the
analysis-only merged state; prose about satisfying or discharging an ownership
obligation means that the handle is consumed rather than still `attached`.

The effect domain is the powerset of:

```text
E = { prompt, decide,
      action(read_only), action(idempotent), action(non_idempotent),
      spawn, join, background, session, attempt }
```

It is ordered by subset, with union as join and the empty set as bottom.
Effects describe possible execution, not guaranteed execution. A construct's
inferred effect is the union of its evaluated subterms, its direct effect
specified below, and the least-fixed-point summary of every callable body it
can enter.

<a id="GNT-3-F-CORE"></a>

**[GNT-3-F-CORE] Core terms.** Surface syntax lowers to these typed core
categories. `prim` is one sealed deterministic primitive whose domain and
result are fixed by Section 5, `pat` is a pattern, `m` is an operation
descriptor containing all static modifiers, and `d` is `inline`, `fork`, or
`new`.

```text
e ::= v | x | aggregate(e...) | project(e,k) | prim(e...)
    | call(f,e...) | method(e,f,e...) | prompt(m,e...) | decide(m,e...)
    | action(m,e...) | attempt(e) | match(e,pat=>e...)
    | with-agent(a,e) | with-session(d,e) | join(h...)
    | join-all(h...)

c ::= skip | let b pat:τ=e | assign p=e | discard e | return e
    | break | continue | c;c | if e then c else c
    | match e with pat=>c... | loop[L,d] c
    | while[L,d] e do c | until[L,d] c when e
    | for x in e do c | with-agent(a,c) | with-session(d,c)
    | spawn h:τ c | detach h | yield e
```

`join-all(h...)` contains the handles computed statically in declaration
order; runtime timing cannot change that set. `for` retains its list snapshot
and current index. Compound assignment, short-circuit operators, `if let`,
trailing expressions, operation modifiers, and implicit Unit returns lower to
these terms while preserving Section 6's evaluation order. Lowering MUST
retain a distinct core site for every operation, spawn, join, detachment,
branch, loop, return target, and cancellation point.
For `let b pat:τ=e`, `b` is `mutable` exactly when the surface declaration is
the single-name form `let mut`; every other binding is `immutable`. The
frontend evaluates `e` exactly once and then applies the irrefutable binding
pattern atomically. If evaluation completes, every name in `pat` becomes
visible with its projected value and mutability `b` at the same sequence
boundary; if evaluation fails, none becomes visible. A mutable tuple pattern
has no lowering because Section 13.5 prohibits that surface form.

<a id="GNT-3-F-AUX"></a>

**[GNT-3-F-AUX] Auxiliary functions.** The following partial functions and
predicates are deterministic for one `Σ`: `type(v)`, exact type equality,
`wf(τ)`, canonical `copy(v)`, primitive application `δprim`, static pattern
bindings `bind(Σ,τ,pat)`, runtime pattern matching `match(v,pat)`,
`join_type`, `joinall_type`, canonical schema generation `schema(Σ,τ)`,
canonical effect ordering, and core-site and dynamic-identity construction.
Their domains, successful results, and named analysis or runtime failures are
exactly those in Sections 4 through 10 and 13. No conforming v1 implementation
may extend one of these domains.

### 3.2 Static semantics

<a id="GNT-3-T-JUDGMENTS"></a>

**[GNT-3-T-JUDGMENTS] Expression judgments.**

An expression judgment `Σ; Γ; Ω ⊢ e : τ ! ε ⇒ Ω'` means that normal
completion yields type `τ`, may perform effects `ε`, and changes ownership
from `Ω` to `Ω'`. Expression failure has no normal output. Premises are
evaluated top to bottom and indexed premises from left to right. `expected τ`
is a bidirectional checking premise supplied only by the positions enumerated
in Section 5.

<a id="GNT-3-T-VALUE"></a>

**[GNT-3-T-VALUE] Values and names.**

```text
type(v)=τ
────────────────────────────── T-Value
Σ;Γ;Ω ⊢ v : τ ! ∅ ⇒ Ω

Γ(x)=(b,τ)
────────────────────────────── T-Name
Σ;Γ;Ω ⊢ x : τ ! ∅ ⇒ Ω

expected Option<τ>
────────────────────────────── T-None
Σ;Γ;Ω ⊢ None : Option<τ> ! ∅ ⇒ Ω
```

There is no derivation for an unresolved name, a task handle in value
position, or `None` without an expected option type.

<a id="GNT-3-T-AGGREGATE"></a>

**[GNT-3-T-AGGREGATE] Constructors.** Analyze list, tuple, struct, enum,
`Some`, `Ok`, and `Err` members in source order:

```text
Ω0=Ω    Σ;Γ;Ωi-1 ⊢ ei : τi ! εi ⇒ Ωi
constructor_ok(Σ,K,τ1...τn,expected τ)
────────────────────────────────────────────── T-Aggregate
Σ;Γ;Ω ⊢ K(e1...en) : τ ! ⋃i εi ⇒ Ωn
```

`constructor_ok` applies Section 5's exact member types, arity, source field
order, omission and default rules, homogeneous-list rule, fixed tuple shape,
guarded recursion, and expected-type requirements. Empty lists and `None`,
`Ok`, or `Err` without sufficient expected type have no derivation. Source
constructors for `Decision` and `OperationError` have no derivation.

<a id="GNT-3-T-PRIMITIVE"></a>

**[GNT-3-T-PRIMITIVE] Projection and deterministic primitives.**

```text
Ω0=Ω    Σ;Γ;Ωi-1 ⊢ ei:τi ! εi ⇒ Ωi
primitive_signature(prim,τ1...τn)=τ
────────────────────────────────────────────── T-Primitive
Σ;Γ;Ω ⊢ prim(e1...en):τ ! ⋃i εi ⇒ Ωn
```

Field, list, and tuple projections are instances of this rule. Section 5
defines all signatures. Exact types are required, equality has no signature
for a non-equatable type, and this rule cannot produce a mutable assignment
target.

<a id="GNT-3-T-CALL"></a>

**[GNT-3-T-CALL] Workflow and method calls.** Let `Σ(f)` contain the ordered
parameter types, result type `τ`, receiver requirements when applicable, and
the least-fixed-point effect summary `effects(f)`:

```text
Ω0=Ω    Σ;Γ;Ωi-1 ⊢ ei:τi ! εi ⇒ Ωi
Σ(f)=(τ1...τn)->τ ! εf
────────────────────────────────────────────── T-Call
Σ;Γ;Ω ⊢ call(f,e1...en):τ ! (⋃i εi)∪εf ⇒ Ωn
```

Method calls use the same rule with the receiver as `e1`; its type must be the
declared receiver type, and receiver mutability affects only the callee's deep
copy. Callee and member resolution occurs before operand analysis. The rule
has no direct integration effect: all effects of executing the body are in
`εf`. There is no derivation for an action path used as an ordinary call,
wrong arity, a non-callable value, or a type mismatch.

<a id="GNT-3-T-OPERATION"></a>

**[GNT-3-T-OPERATION] Integration operations and recovery.** Operation inputs
are analyzed left to right in the order specified by Sections 6 and 7. Let
`op_result(prompt,τ)=τ`, `op_result(decide)=Decision`, and
`op_result(action f)=result(Σ(f))`; let `direct(m)` be `prompt`, `decide`, or
the action's declared class:

```text
Ω0=Ω    Σ;Γ;Ωi-1 ⊢ ei:τi ! εi ⇒ Ωi
operation_ok(Σ,m,τ1...τn)    op_result(m)=τ
──────────────────────────────────────────────── T-Operation
Σ;Γ;Ω ⊢ operation(m,e1...en):τ ! (⋃i εi)∪{direct(m)} ⇒ Ωn

Σ;Γ;Ω ⊢ operation(m,e...):τ ! ε ⇒ Ω'
──────────────────────────────────────────────── T-Attempt
Σ;Γ;Ω ⊢ attempt(operation(m,e...))
       :Result<τ,OperationError> ! ε∪{attempt} ⇒ Ω'
```

`operation_ok` enforces agent availability, action resolution and class,
modifier validity, interpolation and `using` restrictions, exact argument
types, output restrictions, and retry constraints. `attempt` has no derivation
for any operand other than one syntactic operation expression. It changes only
the operation-failure result described in Sections 5 and 7; it does not remove
the operation's effects or catch another failure category.

<a id="GNT-3-T-CONTEXT"></a>

**[GNT-3-T-CONTEXT] Agent and session contexts.**

```text
a∈agents(Σ)    Σ;Γ;Ω ⊢ e:τ ! ε ⇒ Ω'
──────────────────────────────────────── T-With-Agent
Σ;Γ;Ω ⊢ with-agent(a,e):τ ! ε ⇒ Ω'

d∈{inline,fork,new}    Σ;Γ;Ω ⊢ e:τ ! ε ⇒ Ω'
──────────────────────────────────────── T-With-Session
Σ;Γ;Ω ⊢ with-session(d,e):τ ! ε∪{session} ⇒ Ω'
```

The command forms use the corresponding rules. Selecting an agent is not
itself an effect; creating or dynamically selecting a session is. The rules
change dynamic context only for evaluation of the body and restore it on every
completion.

<a id="GNT-3-T-MATCH"></a>

**[GNT-3-T-MATCH] Value-producing pattern routing.** Analyze the scrutinee
once, require ordered nonredundant exhaustive patterns, and require every arm
to have one result type and ownership output:

```text
Σ;Γ;Ω ⊢ e:τs ! ε0 ⇒ Ω0
bind(Σ,τs,pati)=Γi    Σ;Γ,Γi;Ω0 ⊢ ei:τ ! εi ⇒ Ωi
exhaustive(τs,pat1...patn)    merge_ownership(Ω1...Ωn)=Ω'
──────────────────────────────────────────────────── T-Match
Σ;Γ;Ω ⊢ match(e,pati=>ei...):τ ! ε0∪⋃i εi ⇒ Ω'
```

`merge_ownership` is partial. It requires the same visible handle names on all
incoming paths. For each handle, `attached` on every path remains `attached`;
the same `joined` state on every path remains `joined`; and the same `detached`
state on every path remains `detached`. Any mixture consisting only of
`joined`, `detached`, and `discharged` becomes `discharged`, while
path-specific evidence remains available to the runtime and diagnostics. A
mixture of `attached` and any consumed state is not defined, so the match has
no derivation and produces a task-ownership analysis error. A redundant,
nonexhaustive, or ill-typed match likewise has no derivation.

<a id="GNT-3-T-JOIN"></a>

**[GNT-3-T-JOIN] Join expressions.** For a nonempty ordered handle vector,
all handles must be distinct and attached in the input environment:

```text
∀i. Ω(hi)=attached(κi,τi)    distinct(h1...hn)
join_type(τ1...τn)=τ    Ω'=Ω[hi↦joined(κi,τi)]i
──────────────────────────────────────────────── T-Join
Σ;Γ;Ω ⊢ join(h1...hn):τ ! {join} ⇒ Ω'
```

`join-all(h1...hn)` uses the same rule and `joinall_type`; its ordered vector
is exactly the statically computed set for that program point. For an empty
vector it has type `Unit`, effect `{join}`, and leaves `Ω` unchanged. The
partial result functions enforce the Unit/value and homogeneous/heterogeneous
rules in Section 10. A discharged, repeated, foreign, or path-dependent
handle has no derivation.

### 3.3 Control-flow, ownership, and package validity

<a id="GNT-3-T-COMMANDS"></a>

**[GNT-3-T-COMMANDS] Command judgments.**

A command judgment `Σ; Γ; Ω ⊢ c ! ε ⇒ Φ` maps each reachable completion to
one ownership environment. `Φ(N)`, when present, is ordinary fallthrough;
`Φ(R(τ))` is return or yield of type `τ`; and `Φ(Br)` and `Φ(Co)` are loop
transfers. Combining the same completion from alternatives requires the
ownership environments to satisfy the merge rule below. A missing map entry
means that completion is unreachable.

<a id="GNT-3-T-BASIC-COMMAND"></a>

**[GNT-3-T-BASIC-COMMAND] Basic commands.**

```text
────────────────────────────── T-Skip
Σ;Γ;Ω ⊢ skip ! ∅ ⇒ {N↦Ω}

Σ;Γ;Ω ⊢ e:τ ! ε ⇒ Ω'
────────────────────────────── T-Let/T-Discard
Σ;Γ;Ω ⊢ let b pat:τ=e ! ε ⇒ {N↦Ω'}
Σ;Γ;Ω ⊢ discard e ! ε ⇒ {N↦Ω'}

Σ;Γ;Ω ⊢ e:τ ! ε ⇒ Ω'
────────────────────────────── T-Return/T-Yield
Σ;Γ;Ω ⊢ return e ! ε ⇒ {R(τ)↦Ω'}
Σ;Γ;Ω ⊢ yield e ! ε ⇒ {R(τ)↦Ω'}

────────────────────────────── T-Break/T-Continue
Σ;Γ;Ω ⊢ break ! ∅ ⇒ {Br↦Ω}
Σ;Γ;Ω ⊢ continue ! ∅ ⇒ {Co↦Ω}
```

`let` additionally requires every name bound by `pat` to be fresh and the
declared exact type to equal the type of `e`; its scope extension applies to
the following command in the enclosing sequence. `bind(Σ,τ,pat)` determines
the names and projected types and requires `pat` to be irrefutable. The scope
extension records mutability `b` for every resulting binding. `b=mutable` is
valid only when `pat` is one identifier. The value is evaluated once before
those bindings become visible. `_` may ignore selected members inside a tuple
pattern, but whole-value discard uses the explicit `discard` command.
Bare expression statements are `discard e` only when
`τ=Unit`; otherwise only the explicit source `discard` lowers to this command.
`return`, `break`, and `continue` must have a valid nearest target, and every
handle whose lexical scope they exit must be consumed in its output
environment.

<a id="GNT-3-T-ASSIGN"></a>

**[GNT-3-T-ASSIGN] Assignment.** If `place(Γ,p)=(mutable,τ)`, then:

```text
Σ;Γ;Ω ⊢ e:τ ! ε ⇒ Ω'    place(Γ,p)=(mutable,τ)
────────────────────────────────────────────── T-Assign
Σ;Γ;Ω ⊢ assign p=e ! ε ⇒ {N↦Ω'}
```

The place predicate implements Section 6's mutable-root and `mut self` rules.
Compound assignment first types its single target read and primitive
application. No rule permits mutation through an immutable root or changes a
target before the right operand has completed.

<a id="GNT-3-T-SEQUENCE"></a>

**[GNT-3-T-SEQUENCE] Sequencing and completion composition.**

```text
Σ;Γ;Ω ⊢ c1 ! ε1 ⇒ Φ1
Φ1(N)=Ω1    Σ;Γ';Ω1 ⊢ c2 ! ε2 ⇒ Φ2
────────────────────────────────────────────── T-Sequence
Σ;Γ;Ω ⊢ c1;c2 ! ε1∪ε2 ⇒ (Φ1\{N}) ⊔ Φ2
```

`Γ'` adds only bindings whose declarations in `c1` scope over `c2`.
Alternative maps are combined by the partial operator `⊔`, using
`merge_ownership` from `GNT-3-T-MATCH` for each completion present on multiple
paths. Thus a handle must be `attached` on every incoming path or consumed on
every incoming path. A mixture of `attached` and consumed states makes `⊔`
undefined, gives this sequence no derivation, and produces a task-ownership
analysis error. Equal `joined` or `detached` states remain exact; differing
consumed states merge to `discharged` while retaining their path-specific
action for runtime evidence. A completion present on only one reachable
alternative is retained. If `Φ1` has no `N`, `c2` is unreachable and is
rejected under Section 9's reachability rule rather than analyzed as executing
code.

<a id="GNT-3-T-BRANCH"></a>

**[GNT-3-T-BRANCH] Conditional and statement-match commands.**

```text
Σ;Γ;Ω ⊢ e:τc ! ε0 ⇒ Ω0    τc∈{Bool,Decision}
Σ;Γ;Ω0 ⊢ c1 ! ε1 ⇒ Φ1    Σ;Γ;Ω0 ⊢ c2 ! ε2 ⇒ Φ2
──────────────────────────────────────────────── T-If
Σ;Γ;Ω ⊢ if e then c1 else c2 ! ε0∪ε1∪ε2 ⇒ Φ1⊔Φ2
```

An omitted `else` is `skip`. `if let` is a two-arm pattern match. Statement
`match` uses the scrutinee and pattern premises of `T-Match`, analyzes each arm
as a command, and merges all completion maps with `⊔`. Only the literal facts
listed in Section 9 remove an arm from the merge.

<a id="GNT-3-T-LOOP"></a>

**[GNT-3-T-LOOP] Loops and finite iteration.** A loop body is analyzed from
one invariant ownership environment `ΩI`. Every reachable `Co` and every
normal back edge must equal `ΩI`; every reachable `Br` becomes normal loop
completion. For `while`, zero iterations contributes `{N↦ΩI}`. For `until`,
the body runs once before its test. An unbroken `loop` has no normal
completion. Conditions have type `Bool` or `Decision`, and their ownership
output must equal `ΩI`. Effects are the union of condition, body, and
`{session}` when a non-inline loop session is selected.

For `for x in e do c`, first derive `e:List<τ> ⇒ ΩI`; analyze `c` under a
fresh immutable `x:τ` from `ΩI`; require normal and continue outputs to equal
`ΩI`; and convert breaks to normal completion. The empty-list path also
contributes `N↦ΩI`. Loop limits and budgets affect dynamic failure only and do
not create a static normal path.

<a id="GNT-3-T-SPAWN"></a>

**[GNT-3-T-SPAWN] Spawn and detachment.**

```text
h∉dom(Ω)    spawn_site(c)=κ    captures(c)=Γc    Σ;Γc;∅ ⊢ c ! ε ⇒ Φ
task_body_result(Φ,τ)    no_escaping_handles(Φ)
──────────────────────────────────────────────── T-Spawn
Σ;Γ;Ω ⊢ spawn h:τ c ! ε∪{spawn} ⇒ {N↦Ω[h↦attached(κ,τ)]}

Ω(h)=attached(κ,τ)
──────────────────────────────────────────────── T-Detach
Σ;Γ;Ω ⊢ detach h ! {background} ⇒ {N↦Ω[h↦detached(κ,τ)]}
```

`captures` contains exactly the copied bindings and receiver permitted by
Section 10 and never a foreign handle. The child is analyzed with an empty
handle environment because it can own only handles it spawns. Its every normal
completion must yield exactly the declared `τ`, and every child-local handle
must be consumed on every completion that exits its scope.
`task_body_result(Φ,τ)` holds when every reachable task-body exit is `R(τ)`;
it does not require an exit when the body has no reachable completion. Unit
fallthrough is first lowered to `R(Unit)` under `T-Completion`. A scope may
complete normally or transfer control outward only when all handles declared
in that scope are consumed.

<a id="GNT-3-T-COMPLETION"></a>

**[GNT-3-T-COMPLETION] Callable completion.** A function or method with
declared result `τ` is valid only if its body has no reachable normal
fallthrough when `τ≠Unit`, every `R` completion is `R(τ)`, and every handle is
consumed at each body-exiting completion. Unit bodies lower normal
fallthrough and `return;` to `R(Unit)`. Spawned blocks use the same check with
their declared result. `Decision` is checked like every other declared result
type. A loop body may expose `Br` or `Co` only to its immediately enclosing
loop; no completion may cross a spawned-block boundary.

<a id="GNT-3-T-EFFECTS"></a>

**[GNT-3-T-EFFECTS] Effects and package validity.** For each callable `f`, let
`direct(f)` be the effects introduced by its typed core body excluding call
summaries and let `calls(f)` be its resolved call edges. Its unique summary is
the least solution of:

```text
effects(f) = direct(f) ∪ ⋃g∈calls(f) effects(g)
```

The finite powerset lattice guarantees termination, including self-recursion.
A `pure` declaration is valid exactly when this set is empty. `Σ ⊢ package ok`
holds exactly when module loading and declarations satisfy Section 4; every
type is well formed; every schema and canonical identity is constructible;
every callable body derives under the rules above with valid completion;
effects equal this least fixed point; every grammar-adjacent rule in Section
13 holds; and every required entry, agent, action, and package-wide condition
holds. Failure of any premise is an analysis error. There is no other route to
the package-valid judgment.

### 3.4 Dynamic semantics

<a id="GNT-3-M-STATE"></a>

**[GNT-3-M-STATE] Machine state.**

The dynamic semantics is a small-step relation over
`M = ⟨P,C,K,H,S,Q,B,R⟩`. `P` is immutable typed core IR. `C(t)` is one task's
control, value environment `ρ`, lexical handle environment `χ`, value store
`μ`, active agent `a`, active session `s`, cancellation state, and status.
`K(t)` is its stack of evaluation, workflow-return, dynamic-context, loop, and
task-result frames, including suspended lexical environments. `H` maps each
stable dynamic handle identity `η` to its child task, owner, result type, and
ownership state. `S` maps
session IDs to parent, root, creation mode, and canonical transcript. `Q`
maps operation IDs to the lifecycle below. `B` contains the remaining
execution and per-task budgets. `R` contains the active durable agent and
action mapping revisions and every compatible mutable execution-policy
revision that a later transition can observe. Values in `ρ` and `μ` are
normalized deep values; no machine component contains a source-visible alias.

<a id="GNT-3-M-LABELS"></a>

**[GNT-3-M-LABELS] Labels and scheduler.** A transition is
`M --ℓ--> M'`, where `ℓ` is exactly one of:

```text
deterministic(t,site,kind)
operation-prepared(t,o,q,attempt,recovery)
operation-outcome(t,o,q,outcome)
operation-accepted(t,o,result-kind)
task-created(t,parent,spawn-site)
task-settled(t,status)
ownership-transferred(owner,t,join|detach)
cancellation(t,reason)
failure(t,category,code?)
foreground-completion(result)
terminal-completion(category)
```

Payloads are the canonical identities and values required by later sections;
the notation above omits those fields only for readability. The scheduler
chooses any runnable task, but only the selected task takes the next rule and
each task's transitions remain ordered. `operation-outcome` is the only
source-operation label whose payload is selected by integration code.
Runnable-task selection, integration outcomes, and sampled retry jitter are
the nondeterministic inputs to source evaluation. Session setup, executor,
storage, clock, timer, and event-sink services can additionally return the
success or failure outcomes defined in Sections 7 and 10 through 15; those
outcomes may trigger the specified failure transition or durability behavior
but never supply a source value. Once one of these inputs is chosen and, where
required, recorded in `Q` or `R`, every other applicable source-evaluation
rule and its resulting state are unique. Wall-clock timestamps remain
nonsemantic observability data.

<a id="GNT-3-M-CONTEXT"></a>

**[GNT-3-M-CONTEXT] Evaluation contexts.** `E[e]` denotes the unique next
expression under these left-to-right contexts:

```text
E ::= [] | aggregate(v*,E,e*) | project(E,k) | prim(v*,E,e*)
    | call(f,v*,E,e*) | method(E,f,e*) | method(v,f,v*,E,e*)
    | operation(m,v*,E,e*) | attempt(E) | match(E,pat=>e*)
    | with-agent(a,E) | with-session(d,E)
```

Short-circuit Boolean operators lower to branches and therefore have no
right-operand context until the left value requires it. Constructor fields,
interpolations, named inputs, call arguments, receivers, and action arguments
occur in their mandated source order. A failure in `E` removes every frame
for later operands, so no later operand executes. Command evaluation similarly
places exactly one expression in an evaluation frame before applying the
command rule that consumes its value.

<a id="GNT-3-M-VALUES"></a>

**[GNT-3-M-VALUES] Values, aggregates, and primitives.** For a runnable task
whose next redex is shown, these are deterministic transitions:

```text
ρ(x)=r   μ(r)=v
──────────────────────────── M-Name
E[x] ↦ E[copy(v)]

v=construct(K,v1...vn)
──────────────────────────── M-Aggregate
E[K(v1...vn)] ↦ E[v]

δprim(prim,v1...vn)=v
──────────────────────────── M-Primitive
E[prim(v1...vn)] ↦ E[v]
```

Each successful rule emits `deterministic` and decrements the deterministic
transition budget before publishing its result. If the applicable size,
bounds, arithmetic, conversion, or other partial primitive condition fails,
`M-Primitive` is replaced by `M-Fail` with the exact Section 5 code and no
value is produced. Construction copies every member and becomes visible only
as one completed result.

<a id="GNT-3-M-CALL"></a>

**[GNT-3-M-CALL] Calls and returns.** `call(f,v1...vn)` allocates fresh local
roots containing copies of the arguments, pushes a return frame containing
the caller control and destination context, and starts the typed core body of
`f`. Method calls additionally copy the receiver into `self`. Frame entry
first checks cancellation and workflow-depth budget. A `return v` or trailing
`yield v` copies `v`, discards the callee's locals, restores the return frame,
and plugs the copy into its destination context. Returning from the root emits
`foreground-completion`; returning from a spawned block invokes
`M-Task-Settle`. These steps emit `deterministic`; a depth-limit failure uses
`M-Fail`. No call or return rule dispatches a hook.

<a id="GNT-3-M-STORE"></a>

**[GNT-3-M-STORE] Bindings, assignment, discard, and sequence.** `let`
allocates a fresh root only after its initializer is a value and stores a
copy; tuple-pattern bindings are allocated together or not at all. `assign`
evaluates its right operand to a value before replacing one complete mutable
root with the copied and path-updated value. `discard v` drops only that copy.
`skip;c` advances to `c`; `return`, `break`, and `continue` unwind to the
nearest statically valid frame. Every successful step emits `deterministic`.
Failure before the binding or root replacement leaves the old environment and
store unchanged.

<a id="GNT-3-M-BRANCH"></a>

**[GNT-3-M-BRANCH] Branches and patterns.** `if true` selects its first arm,
`if false` its second, and a `Decision` selects by its `decision` field.
`match(v,pat=>c...)` chooses the first matching arm, atomically installs copies
of that pattern's bindings, and starts that arm. Exhaustiveness guarantees one
arm. Loop control lowers as follows: `while` tests before each body; `until`
runs the body before each test; `loop` repeats after each normal body; and
`for` evaluates and copies its list once, then installs one copied item at each
ascending index. An `until` post-test whose Boolean value is `true` exits the
loop normally; `false` proceeds toward the next body entry. `continue` reaches
the applicable test or next item and
`break` exits. A source limit is checked before body entry. Cancellation and
the loop-entry budget are checked at every condition, item binding, body
entry, and back edge. Successful selection emits `deterministic`; exhausted
limits use `M-Fail` and never synthesize normal completion.

<a id="GNT-3-M-CONTEXT-SCOPE"></a>

**[GNT-3-M-CONTEXT-SCOPE] Agent and session scopes.** Entering
`with-agent(a,body)` pushes the old agent, evaluates under `a`, and restores
the old agent on value, transfer, or failure. Entering an inline session scope
does the analogous operation with the existing session. Entering `fork` or
`new` deterministically allocates its stable session identity and `S` entry
before body evaluation: `fork` copies the parent's committed transcript and
`new` uses the empty transcript. Exit restores the prior session. Session
creation is part of the transition's semantic state and must satisfy the
commit rule in Section 3.6 before an operation can use it.

### 3.5 Operations, tasks, cancellation, and failure

<a id="GNT-3-M-LIFECYCLES"></a>

**[GNT-3-M-LIFECYCLES] External and concurrent lifecycles.**

<a id="GNT-3-M-OPERATION"></a>

**[GNT-3-M-OPERATION] Operation lifecycle.** The operation state is exactly:

```text
absent
prepared(request,q,validation-attempt,recovery-dispatch,retries-left)
outcome(request,q,host-outcome,retries-left)
accepted(request,v)
failed(request,error)
```

After all explicit inputs are values, `M-Prepare` checks cancellation and the
operation budget, captures and copies the complete semantic request, derives
`o` and fresh `q`, decrements that budget, inserts `prepared`, and emits
`operation-prepared`. For an operation-local `session = fork` or `session =
new` modifier, the same transition first allocates and records one stable
logical-session ID and its transcript basis, then places that ID and the
complete `session-use = create` data in the captured request. The task's
enclosing active session remains unchanged. Validation retries and recovery
redispatches reuse the allocated session ID, transcript basis, and creation
data; they MUST NOT allocate another session. The session record and prepared
request must satisfy the Section 3.6 commit rule before dispatch, and the
integration establishes the session through the idempotent request boundary
in Sections 7 and 15.2. A hook may be invoked only for this state. For exactly
one matching prepared dispatch, `M-Outcome` accepts one well-formed host
outcome from Section 7, changes the state to `outcome`, and emits
`operation-outcome`. No other rule introduces a host outcome.

For `Completed(bytes)`, `M-Validate` applies Section 8's ordered decoding,
resource, schema, and normalization functions. Success changes `Q(o)` to
`accepted`, emits `operation-accepted`, and only then plugs a copy of `v` into
the suspended expression. A prompt or decision acceptance extends its active
session with exactly one canonical transcript turn in the same transition.
Validation failure with retries remaining records the canonical errors and
delay, decrements the retry count, creates a fresh `q`, increments only the
validation-attempt number, returns to `prepared`, and emits another
`operation-prepared`. Exhaustion applies `M-Operation-Fail`.

`Declined` and `Failed` apply `M-Operation-Fail` without validation. In an
`attempt` frame, that rule changes `Q(o)` to `failed`, constructs the exact
`OperationError`, and returns `Err(error)` to source. Without that frame it
uses `M-Fail`. A successful operation in an `attempt` frame returns `Ok(v)`.
No journal, executor, deterministic, event-persistence, or invariant failure
enters this conversion. A completed or failed operation state has no rule that
dispatches it again during uninterrupted execution.

<a id="GNT-3-M-SPAWN"></a>

**[GNT-3-M-SPAWN] Task creation.** After cancellation and task-count checks,
`spawn h:τ c` derives a stable child identity, copies the statically determined
captures and mutability, forks the active session, creates `C(child)` with an
empty lexical handle environment, derives a fresh stable dynamic handle
identity `η` from the owner and spawn occurrence, inserts
`H(η)=attached(child,owner,τ)`, and extends the current lexical environment
with `χ(h)=η`. It then increments the cumulative execution task count and emits
`task-created`. The parent advances only after this transition; the child may
then be scheduled independently. Failure of executor submission settles that
same child as failed and never creates a replacement identity or handle.

<a id="GNT-3-M-TASK-SETTLE"></a>

**[GNT-3-M-TASK-SETTLE] Settlement and all-settled join.** Returning `v` from
a spawned block, uncaught failure, or durable cancellation changes that task
exactly once from running to `succeeded(v)`, `failed(error)`, or `cancelled`
and emits `task-settled`. A named `join` atomically changes every selected
attached dynamic handle resolved through `χ` to joined and emits one
`ownership-transferred(...,join)` per handle in argument order before waiting.
`join-all` does the same for the dynamic handles resolved from its static
lexical-name vector in the current environment. The owner then blocks until
every selected task is settled.
If all succeed, one deterministic step constructs the Section 10 result in
argument or declaration order. Otherwise one `M-Fail` produces the ordered
aggregate `task-join-failure`. Timing never changes either ordering. Joined
handles have no later source transition.

<a id="GNT-3-M-DETACH"></a>

**[GNT-3-M-DETACH] Background ownership.** `detach h` resolves `h` through
`χ`, changes exactly that attached dynamic handle to detached execution-owned
work, emits
`ownership-transferred(...,detach)`, and advances the parent without waiting.
The detached result is never returned to source. Its settlement still uses
`M-Task-Settle` and contributes to terminal outcome according to Section 10.
A joined or detached handle has no join or detach rule.

<a id="GNT-3-M-CANCEL"></a>

**[GNT-3-M-CANCEL] Cancellation.** A cancellation request monotonically marks
its target and the descendants selected by Section 10 and emits one
`cancellation` label per newly marked task. A marked task has no
`M-Prepare`, `M-Spawn`, frame-entry, condition, body-entry, or back-edge
transition. It may only drain an already prepared dispatch, settle attached
descendants, or take `M-Task-Settle(cancelled)`. A later host outcome may be
retained as nonconsumable audit evidence but has no `M-Validate` transition.
No rule clears a cancellation mark.

<a id="GNT-3-M-FAIL"></a>

**[GNT-3-M-FAIL] Failure and propagation.** `M-Fail(t,category,code,details)`
removes the failing redex and its ordinary continuations, stores the pending
failure, emits `failure`, and cancels and drains its attached descendants.
After that drain, `M-Task-Settle` changes the still-running task exactly once
to `failed(error)`. It does not cancel siblings or detached work. A failed
attached task is observed only by its owner's all-settled join; a failed root
fixes the foreground failure; a failed detached task contributes the stable
terminal category. Execution-wide journal and required-delivery failures
follow their explicit Section 10 precedence instead of this task-local rule.
When root and every detached task are settled, exactly one transition computes
the precedence in Section 10 and emits `terminal-completion`. No transition
may change that category afterward.

### 3.6 Durability refinement and semantic properties

<a id="GNT-3-D-REFINEMENT"></a>

**[GNT-3-D-REFINEMENT] Refinement relation.**

Let `A = ℓ1…ℓn` be an abstract trace and let durable state `D` contain an
authoritative committed logical-evidence prefix, its causal graph, and a
recovery projection `recover(D)`. Write `D ≈ M` when replaying that evidence
through the published recovery projection reconstructs `M`, modulo physical
storage layout, integration resources, and telemetry.

<a id="GNT-3-D-SIMULATION"></a>

**[GNT-3-D-SIMULATION] Forward simulation.** If `D ≈ M` and
`M --ℓ--> M'`, the durable runtime must either make no externally observable
semantic progress, or atomically commit a finite nonempty evidence batch to
`D'` such that `D' ≈ M'` and the batch records `ℓ` with all causal
predecessors. One physical batch may represent several adjacent labels only
when no hook, task submission, source consumption, event obligation, or
external observer can occur between them. Splitting one label across records
is permitted only when none of those records alone advances `recover(D)`.

<a id="GNT-3-D-COMMIT-ORDER"></a>

**[GNT-3-D-COMMIT-ORDER] Required semantic commit points.** The state produced
by `M-Prepare` is committed before hook entry; `M-Outcome` before validation or
failure conversion; `M-Validate` before source consumption or transcript use;
`M-Spawn` before executor submission or handle visibility; join and detach
ownership transitions before parent continuation; cancellation before tokens
are signalled; task settlement before a join or terminal computation observes
it; foreground completion before its result is returned; and terminal
completion before a terminal outcome is reported. These are semantic ordering
constraints, not required physical record boundaries.

<a id="GNT-3-D-CRASH"></a>

**[GNT-3-D-CRASH] Crash and recovery.** A crash may occur before or after any
physical write and at every boundary above. Recovery discards or ignores every
uncommitted physical tail, acquires fenced ownership, reconstructs exactly
`recover(D)`, and continues with the next applicable abstract rule. A committed
outcome is never redispatched; a committed accepted result is never validated
or consumed twice. A committed prepared dispatch without outcome is
indeterminate: recovery creates a new dispatch and increments only its
recovery-dispatch number for prompts, decisions, and read-only or idempotent
actions. For a non-idempotent action it instead applies the exact unknown-
outcome operation failure. Task creation, ownership transfer, session creation,
budget decrement, foreground completion, and terminal completion are never
reapplied when their label is already in the recovered prefix.

<a id="GNT-3-D-EQUIVALENCE"></a>

**[GNT-3-D-EQUIVALENCE] Permitted storage implementations.** Append logs,
transactions, atomic batches, group commit, snapshots, compaction, and
snapshot-plus-log designs conform exactly when their authoritative reads
produce the same logical evidence and recovery projection and satisfy
`GNT-3-D-SIMULATION`, `GNT-3-D-COMMIT-ORDER`, and `GNT-3-D-CRASH`. Terms such
as record, envelope, checkpoint, and evidence elsewhere name logical protocol
objects; they do not require one physical row, append, file write, or flush.

<a id="GNT-3-D-PROPERTIES"></a>

**[GNT-3-D-PROPERTIES] Proof and conformance obligations.** For the static and
dynamic relations above, a conforming implementation must document a proof or
machine-checked model argument and map executable conformance cases to each of
these properties: (1) progress to a rule or specified runtime error for a
well-typed nonterminal configuration; (2) preservation of expression types,
store typing, and ownership consistency after every transition; (3) one
attached handle has at most one join or detach transition; (4) one logical
operation has at most one source-consumable accepted result; (5) a cancelled
task consumes no later operation outcome; (6) every recovered state simulates
one causally closed prefix; and (7) terminal completion is unique. Provider
outcomes and cross-task scheduling are quantified nondeterministically; they
are not assumptions of deterministic replay.

## 4. Source Organization

<a id="GNT-4.0"></a>

This section defines package entry, module loading, name resolution,
identifier policy, canonical paths, and immutable source snapshots.

<a id="GNT-4.1"></a>

1. Gantry source files MUST use the `.gnt` extension.
<a id="GNT-4.2"></a>

2. A package entry point is `main.gnt`, and its selected entry function is the
   root module's `fn main`. The root module MUST declare exactly one
   function named `main`; a missing `main`, a `main` declared only in a child
   module, or any non-function root item named `main` is an analysis error.
   The directory containing `main.gnt` is the package root. `main` MUST have
   either no parameters or exactly one typed parameter. It MAY return `Unit`
   or any v1 value type that contains neither `Decision` nor `OperationError`
   at any nesting depth. The entry parameter has the same restriction. Entry
   and result JSON cannot
   originate a sealed judgment or operation failure. A workflow
   that needs to import or export a judgment MUST use an ordinary declared
   struct containing the required data rather than `Decision` itself.
   When `main` has a parameter, the embedding application MUST supply one raw
   byte sequence containing the entry JSON. Gantry MUST reject that sequence
   with an entry-input resource-limit failure before UTF-8 decoding when its
   byte length exceeds `maximum_entry_input_bytes`. Gantry MUST own UTF-8
   decoding and RFC 8259 JSON parsing and MUST apply the same empty-input,
   trailing-data, duplicate-member, Unicode-scalar, and value-nesting-depth
   rejection rules that Section 8 applies to hook output.
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
   canonical strict JSON defined in Section 8 together with its canonical static
   type descriptor. `Unit` is encoded as JSON `null` with descriptor `Unit`;
   `Option<T>::None` is also encoded as JSON `null` but retains descriptor
   `Option<T>`. Embedders therefore determine semantics from the required type
   descriptor rather than guessing from JSON shape.
<a id="GNT-4.3"></a>

3. Gantry MUST support the comments and lexical forms defined in Section 13.
   Gantry resembles Rust only where this specification explicitly says so; it
   does not inherit unstated Rust lexical or semantic rules.
<a id="GNT-4.4"></a>

4. Gantry uses lexical scope for parameters, local bindings, pattern bindings,
   and task handles; those names MUST be declared before use and MUST obey the
   no-shadowing rule in item 15. Package-item and module declarations are
   order-independent within the discovered package graph. A function, type,
   action, module, or inherent method may therefore be referenced before its
   declaration when ordinary path and import resolution finds exactly one
   item. Analysis MUST NOT depend on source-file traversal, filesystem
   enumeration, or parser implementation order.
<a id="GNT-4.5"></a>

5. Gantry MUST support namespaces and module declaration or loading through a
   Rust-inspired `mod` form. A file selected by `mod` is parsed as an
   independent module, not textually inserted into the caller's scope.
   Rust-inspired `use` declarations import item names as defined in item 11;
   `mod` itself is not an import statement.
<a id="GNT-4.6"></a>

6. Module paths MUST be local, relative paths and MUST remain inside the same
   package. Remote paths, absolute paths, environment expansion, and package
   resolution are excluded from v1. Module resolution MUST reject `.` and `..`
   path components and symbolic links. Rejecting symbolic links keeps package
   containment and source identity independent of host filesystem aliasing.
<a id="GNT-4.7"></a>

7. A file module declaration `mod foo;` resolves in the declaring module's
   module directory as either `foo.gnt` or `foo/mod.gnt`. The root module's
   module directory is the package root. A module loaded from `foo.gnt` or
   `foo/mod.gnt` has `foo/` as its module directory, and an inline `mod foo {
   ... }` likewise has the conceptual module directory `foo/` below its
   parent's module directory. These rules apply recursively to child module
   declarations. If both file candidates exist, analysis MUST fail as
   ambiguous. The package root is a containment boundary, not an alternate
   lookup directory for nested modules.
<a id="GNT-4.8"></a>

8. Inline modules of the form `mod foo { ... }` MUST be supported. Module items
   are addressable package-wide in v1, but an item is not automatically added
   to another module's unqualified lexical namespace. Code in another module
   MUST use a `use` declaration or a Rust-inspired qualified `module::item`
   path.
<a id="GNT-4.9"></a>

9. Module cycles, duplicate ordinary item or module declarations, and
   duplicate module resolutions are analysis errors. Repeated logical agent
   names remain the explicit idempotent exception defined in Section 7.
   Visibility constraints are excluded from v1.
<a id="GNT-4.10"></a>

10. Functions and methods MAY be recursive and MAY participate in mutual
    recursion. A struct MAY refer to itself subject to the guarded-recursion
    rule in Section 5. Cycles through two or more declared types and recursive
    enum payloads remain excluded from v1; declaration-order independence does
    not enlarge the recursive data model. Recursive call graphs do not change
    left-to-right evaluation, workflow-depth limits, or least-fixed-point
    effect analysis.
<a id="GNT-4.11"></a>

11. Gantry MUST support Rust-inspired `use` declarations as well as qualified
   item paths. An unprefixed path begins in the current module's lexical
    namespace. `crate::` begins at the package root, `self::` begins at the
    current module, and each leading `super::` moves outward by one module.
    Escaping above the package root is an analysis error. `use` follows the
    same path rules and does not change item visibility.
<a id="GNT-4.12"></a>

12. Module filenames and identifiers MUST be valid UTF-8. Identifiers MAY use
   any NFC spelling admitted by the Unicode XID rule below; `snake_case`,
    `camelCase`, and `PascalCase` are style conventions rather than the
    validity grammar. All source identifiers MUST be in Unicode Normalization
    Form C (NFC); an implementation MUST reject rather than silently normalize
    a non-NFC identifier. Gantry v1 identifier
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
<a id="GNT-4.13"></a>

13. Top-level package and module contents MUST be declarations. Executable
   statements are permitted only within function, method, spawn, or other
   executable block bodies.
<a id="GNT-4.14"></a>

14. Gantry MUST first discover the complete module graph, then collect
    package-wide agent names and every module-item and inherent-method
    signature, and only then resolve type definitions and executable bodies.
    `use` declarations contribute to their module's lexical item namespace
    regardless of textual position. An import target, `impl` target, and every
    type or item named by a signature MUST resolve against that collected
    package graph; collection does not excuse an unresolved or ambiguous path.
    Within one module, item names MUST be unique across structs, enums,
    functions, actions, and modules. An imported name MUST NOT collide with
    another import or local item. These rules make declaration reordering a
    nonsemantic edit while retaining explicit, unambiguous lookup.
<a id="GNT-4.15"></a>

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
<a id="GNT-4.16"></a>

16. Every protocol, journal, event, or diagnostic field that requires a
   canonical item or workflow path MUST use a `crate::`-rooted path after
    resolving `use`, `self`, and `super`. The root function `main` is therefore
    `crate::main`; an item `inspect` in nested modules `quality::checks` is
    `crate::quality::checks::inspect`. A free function uses its canonical item
    path as its workflow path. An inherent method uses
    `<T>::method`, where `T` is the receiver's canonical struct type descriptor
    from Section 5, for example
    `<crate::domain::Report>::revise`. Canonical paths MUST use exact NFC item
    spellings and MUST NOT retain a source-level import alias or relative root.

    A canonical workflow or action signature is one UTF-8 string constructed
    from that path and the canonical type descriptors in Section 5. A
    free-function signature is `fn PATH(P1,P2,...)->R`; an action signature is
    `action[CLASS] PATH(P1,P2,...)->R`; and a method signature is
    `fn METHOD_PATH(RECEIVER[,P1,P2,...])->R`. `RECEIVER` is exactly `self` or
    `mut self`. Each non-receiver parameter descriptor is its type descriptor,
    prefixed by `mut ` when the source parameter is mutable. `R` is the
    declared result descriptor or `Unit` when the annotation is omitted. The encoding contains
    no whitespace except the one space in `mut ` or `mut self`, contains no
    parameter names, and preserves declaration order. Examples are
    `fn crate::main(String)->crate::domain::Report`,
    `fn crate::quality::is_complete(crate::domain::Report)->Decision`,
    `action[read_only] crate::search(crate::SearchRequest)->Result<List<crate::Source>,crate::SearchFailure>`,
    and
    `fn <crate::domain::Report>::revise(mut self,String)->crate::domain::Report`.
    This format is metadata rather than source syntax.
<a id="GNT-4.17"></a>

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

<a id="GNT-5.0"></a>

This section defines the complete v1 value domain, construction and copy
semantics, deterministic primitives, patterns, and canonical type descriptors.
Task handles are governed by Section 10 and are not source values.

<a id="GNT-5.1"></a>

1. Runtime values MUST include `Unit`, `Bool`, `Int`, `Float`, `String`,
   declared struct and enum values, `Option<T>`, `Result<T, E>`, `List<T>`,
   `Tuple<T1, T2, ..., Tn>`, `Decision`, and the sealed `OperationError` type.
   `Unit` has exactly one value, written `()`, and is the result type for work
   that returns no information. `None` is exclusively the absent constructor
   of `Option<T>` and MUST NOT denote Unit work. `Bool` is ordinary
   deterministic data. `Decision` is a sealed first-class model judgment;
   retaining it as a distinct type keeps agent judgment distinguishable from
   locally computed facts without attaching hidden operation identity to the
   value.
   `Int` is an exact signed integer in the inclusive range
   `-9007199254740991` through `9007199254740991` (`±(2^53 - 1)`). `Float` is a
   finite IEEE 754 binary64 value. Directive integers used for limits and retry
   counts remain a separate nonnegative syntax domain through `2^63 - 1` and
   are not implicitly `Int` values.
<a id="GNT-5.2"></a>

2. Parameters and returned values MAY be `Unit`, `Bool`, `Int`, `Float`,
   `String`, a declared struct or enum type, `Option<T>`, `Result<T, E>`,
   `List<T>`,
   `Tuple<T1, T2, ..., Tn>`, `Decision`, or `OperationError`. Every member of a constructed type
   MUST itself be a permitted value type. A function, method, prompt, action,
   or spawned block that returns no information has result type `Unit`. An ordinary function, method,
   binding, aggregate, or struct
   MAY carry `Decision` or `OperationError`, but an expected `prompt` or
   `action` output type MUST NOT contain either sealed type at any nesting depth.
   Entry parameters and results have the same restriction. Only an executed `decide`
   operation can originate a new sealed `Decision`; an ordinary workflow,
   method, or spawned block may return or forward a `Decision` obtained from a
   valid source without creating another one.
   Where the grammar permits omission, an omitted result annotation and the
   explicit result annotation `-> Unit` both denote `Unit`. This applies to
   functions, methods, prompts, action declarations, and spawned blocks. `()`
   may be bound, passed, returned, and discarded like another value, but it
   carries no information and encodes as JSON `null` at an external boundary.
   `return;` is sugar for `return ();`. `return None;`
   is valid only when an expected `Option<T>` return type gives that expression
   a type; it is never a spelling of `Unit`.
<a id="GNT-5.3"></a>

3. `Option<T>`, `Result<T, E>`, `List<T>`, and `Tuple<T1, T2, ..., Tn>` MAY
   appear in
   parameters, bindings, returned values, and struct fields. `Some(value)` and
   `None` MUST be constructible by deterministic interpreter operations.
   Gantry code MAY inspect an option through the deterministic `match` and
   `if let` forms in Section 9. An unwrap operation remains excluded.
   For every `Option<T>` occurrence, its immediate member `T` MUST NOT be
   `Unit` or another `Option<U>`. This rule applies recursively to option
   occurrences inside every constructed type. For example, `Option<Unit>`,
   `Option<Option<String>>`, `List<Option<Unit>>`, and
   `List<Option<Option<String>>>` are invalid. The untagged strict-JSON
   encoding uses `null` for `None`, `Unit`, and an inner `None`, so it cannot
   distinguish those present values from the outer `None`. An option nested
   through a tagged or object-shaped member, such as
   `Option<Result<Option<String>, E>>`, remains valid because its outer
   presence is distinguishable on the wire.
   Every expression MUST have one statically known type. `Some(value)` has
   type `Option<T>` when `value` has type `T`. A `None` expression acquires its
   `Option<T>` type only from an expected type supplied by a binding annotation,
   assignment target, parameter, struct field, return position, or aggregate
   member whose enclosing constructor has a known expected type. Expected
   member types propagate recursively through list, tuple, option, result,
   struct, and enum construction. Bare `None` in a position without such an
   expected type, including a top-level prompt interpolation island, is an
   analysis error; authors can interpolate a typed option binding instead.
   Gantry performs no other implicit option wrapping.
<a id="GNT-5.4"></a>

4. `List<T>` is an ordered, homogeneous collection. V1 supports list literals
   and zero-based deterministic projection with `value[index]`, where `index`
   is an `Int` expression. Projection yields `T`; a negative or out-of-bounds
   list projection is a `deterministic-evaluation-failure` runtime error with
   code `list-index-out-of-bounds`. Every item in a list literal MUST have
   exactly one static type. An empty literal is valid only where an
   expected `List<T>` type is known. Items are evaluated once from left to
   right and the list becomes visible atomically after all items succeed.
   `List<T>.len()` is defined in item 15, and `List<String>.join(separator)` is
   defined in item 16. List mutation, list patterns and destructuring, and
   deterministic list methods beyond those specified here are excluded from
   v1; finite `for` iteration is defined in Section 9.
<a id="GNT-5.5"></a>

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
<a id="GNT-5.6"></a>

6. Struct fields MAY be `Unit`, `Bool`, `Int`, `Float`, `String`, declared
   struct or enum values, `Option<T>`, `Result<T, E>`, `List<T>`,
   `Tuple<T1, T2, ..., Tn>`, `Decision`, or `OperationError`. Every member of a
   constructed field type MUST itself be a permitted value type. Nested and directly
   self-recursive struct definitions are permitted. In accordance with Section
   4, a cycle through
   two or more distinct declared types is excluded from v1. Every permitted
   self-recursive struct cycle MUST pass through `Option<T>` or `List<T>` so
   that a finite strict-JSON value can terminate the recursion. An unguarded
   recursive cycle is an analysis error because it has no finite inhabitant.
<a id="GNT-5.7"></a>

7. Gantry MUST support declared enums as closed tagged unions. An enum MUST
   contain at least one variant. Each variant is either unit-like or carries
   exactly one otherwise permitted payload type; authors MUST use a struct
   payload when one variant needs several named values. Variant names MUST be
   unique within the enum. A unit variant is constructed as
   `Type::Variant`; a payload variant is constructed as
   `Type::Variant(value)`. The payload type MUST match exactly. Enum values MAY
   be copied, stored, passed, returned, serialized, and supplied to operations
   as complete values. Their variant or payload MAY be examined only by an
   enum pattern or equality expression; a payload becomes available through
   the binding introduced by a matching payload pattern. Directly or
   transitively recursive enum payloads are excluded from v1.
<a id="GNT-5.8"></a>

8. `Result<T, E>` is a built-in tagged union with source constructors
   `Ok(value)` and `Err(error)`. Their types are `Result<T, E>` when the
   expected type and argument type identify the other member. A constructor
   without enough expected-type information is an analysis error. `Result`
   represents an expected outcome intentionally returned by a prompt, action,
   workflow, source constructor, or `attempt` expression. Gantry MUST NOT
   convert an operation failure into `Err` except at an explicit `attempt`
   expression under item 9. Journal failure, internal invariant failure, and
   deterministic evaluation failure are never converted. V1 has no `?`
   operator or implicit result propagation.
   When an operation's declared output type is `Result<T,E>`, an accepted,
   validated `Err(E)` hook output is an ordinary successful operation value.
   It does not represent a hook decline or failure, does not consume an
   operation-failure retry, and does not propagate a runtime error. Conversely,
   `Declined`, `Failed`, structured-output exhaustion, and unknown action
   outcomes never synthesize that declared `Err(E)` value. Only an explicit
   `attempt` converts the operation-failure categories listed in item 9 into
   `Err(OperationError)`.
<a id="GNT-5.9"></a>

9. `OperationError` is a sealed built-in tagged type with the variants
   `Declined(String)`, `InvalidOutput(String)`, `ProviderFailure(String)`,
   `Timeout(String)`, `PolicyDenied(String)`, `Cancelled(String)`, and
   `UnknownOutcome(Tuple<String,String>)`. The first six payloads are the
   bounded diagnostic message. The `UnknownOutcome` tuple contains the stable
   operation ID followed by its diagnostic message. Source can inspect these
   variants with `match`, including
   `OperationError::UnknownOutcome((operation_id, message))`, but cannot
   construct an `OperationError`. Read-only `.message` returns the applicable
   message, and `.operation_id` returns `Some(id)` only for `UnknownOutcome`.
   `attempt OPERATION` evaluates exactly one syntactic `prompt`, `decide`, or
   `action` expression. If the operation accepts a value of type `T`, the
   result is `Ok(value): Result<T, OperationError>`. If it encounters a
   decline, structured-output exhaustion, categorized provider failure,
   timeout, policy denial, a hook-reported operation cancellation received
   while the containing Gantry task is still active, or an unknown non-
   idempotent action outcome, the result is the corresponding `Err`. Gantry
   task cancellation is different: it is monotonic, bypasses `attempt`, and
   prevents the cancelled task from consuming an `Err` or any other later
   operation result. `OperationError::Cancelled` therefore represents only an
   operation-level integration outcome, never recovery from task cancellation.
   Journal, event-persistence, executor, deterministic-evaluation, and
   internal-invariant failures bypass `attempt`. An unattempted operation
   failure retains the runtime-error propagation in Section 7.
<a id="GNT-5.10"></a>

10. `Decision` is a sealed first-class value with read-only fields `decision:
   Bool` and `rationale: String`, where the rationale is nonempty.
   Only `decide` creates a new `Decision`; an ordinary workflow may return a
   `Decision` obtained from an executed `decide` or from another valid source.
   Source MAY bind, pass, return, capture, store, interpolate, and consume a
   `Decision` as an `if`, `while`, or `until` condition. The field projections
   `.decision` and `.rationale` yield `Bool` and `String`, respectively.
   Source MUST NOT construct, compare, pattern-match, destructure, or mutate a
   `Decision`. In particular, assignment through `.decision` or `.rationale`
   is invalid. This restriction does not prevent rebinding a mutable
   `Decision` binding, or replacing a mutable struct field that has type
   `Decision`, with another sealed `Decision` obtained from a valid source.
   Reusing or replacing a bound decision performs no new hook dispatch.
   `Decision` equality remains unavailable, but two decisions with equal
   visible fields MUST be indistinguishable to later integration operations
   unless source explicitly supplies different surrounding values.
<a id="GNT-5.11"></a>

11. Gantry MUST support named-field struct construction. Struct values MAY be
   constructed by source execution or produced by an operation hook. A source
   constructor MUST reject unknown and duplicate fields during analysis.
   A source field initializer MAY use the explicit `name: expression` form or
   the shorthand `name` form. Shorthand is exactly equivalent to
   `name: name`; the name MUST resolve to a visible binding of exactly the
   field's declared type. Constructor field expressions are evaluated once in
   source order. For
   source construction, a field is required only when it has neither a
   declared default nor an `Option<T>` type. Omitting such a field is an
   analysis error; an omitted field with a default uses that default, and an
   omitted `Option<T>` field without a default becomes `None`. A non-optional
   field with a source default may therefore be omitted from a source
   constructor even though Section 8 still requires that field in operation-hook
   output. A constructed value becomes visible only after every supplied field
   expression completes successfully. Earlier hook side effects are not
   reversible if a later field expression fails.
<a id="GNT-5.12"></a>

12. Struct fields MAY declare `()`, `Bool`, `Int`, `Float`, `String`, or `None`
   defaults, which are the only field-default forms in v1. The `()` default is
   valid only for a `Unit` field. A scalar default MUST exactly match the
   field's declared scalar type or the member type of an `Option` around that
   scalar. A scalar default on `Option<T>` normalizes to `Some(default)`. A
   `None` default is valid only for an `Option<T>` field.
   Defaults MUST NOT invoke an integration operation. When an optional field
   with a default is omitted, the default is assigned; explicit `null` remains
   `None`. Struct update syntax and destructuring are excluded from v1.
<a id="GNT-5.13"></a>

13. Every first-class Gantry value has deep, nonaliasing value semantics.
   Binding initialization, assignment, argument and return passing, field and
   aggregate projection, construction, task capture, and join-result delivery
   each produce an independent logical value. An implementation MAY share
   immutable backing storage or use copy-on-write internally, but that sharing
   MUST NOT be observable through mutation, failure, cancellation, journaling,
   or resume. Values carry no hidden provenance that can alter a later
   integration request. Operation and control provenance remains in journal
   and observability records only. Function and method parameters other than
   the receiver, and all other bindings, are immutable by default. `mut` on a
   local declaration or parameter enables rebinding and
   field mutation of that local value. Parameter mutability is local to the
   called workflow and never permits mutation of the caller's value.
   Assignments MUST preserve type, and v1 permits no implicit type coercion.
   A local binding is not visible in its own initializer and becomes visible
   only after the complete initializer has evaluated successfully and its
   value has been copied into the binding. Tuple destructuring introduces all
   of its bindings atomically after the initializer has completed and matched;
   no binding from the pattern is visible while another is being introduced.
   The `discard expression;` statement evaluates and type-checks its operand
   and then explicitly discards the resulting first-class value. `_` remains
   available inside tuple patterns to ignore selected members without creating
   bindings. Initializer or discard failure introduces no binding, although
   integration side effects produced before that failure are not rolled back.
<a id="GNT-5.14"></a>

14. `const` is excluded from v1. Runtime initialization of immutable bindings is
   permitted.
<a id="GNT-5.15"></a>

15. Gantry MUST provide the deterministic primitive operations in this item.
   There is no truthiness or implicit numeric or String coercion.
    - `!` accepts `Bool`. `&&` and `||` accept `Bool`, evaluate left to right,
      short-circuit, and return `Bool`. When the left operand determines the
      result, Gantry MUST NOT evaluate the right operand. A skipped operand
      creates no workflow frame, operation or dispatch identity, hook request,
      task, journal transition, or event. If execution later reaches the same
      source expression under a different dynamic path, identities are
      assigned only to the operations actually evaluated on that path.
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
    Partial deterministic primitives fail in the
    `deterministic-evaluation-failure` category with these exact codes:

    | Condition | Code |
    | --- | --- |
    | Negative or out-of-bounds `List` projection | `list-index-out-of-bounds` |
    | `Int` arithmetic overflow, including unary negation | `integer-overflow` |
    | `Int` division by zero | `integer-division-by-zero` |
    | `Int` remainder by zero | `integer-remainder-by-zero` |
    | `Float` division by positive or negative zero | `float-division-by-zero` |
    | Non-finite `Float` arithmetic result | `float-non-finite-result` |
    | Empty `String.replace` source pattern | `string-empty-pattern` |
    | Empty `String.split` separator | `string-empty-separator` |
    | Result exceeding the effective String limit | `string-size-limit` |
    | Result exceeding the effective List limit | `list-size-limit` |

    The owner rules for each condition define when it is checked; this table
    defines the portable code. `Float.to_int()` returning `None` is not a
    failure. Integer arithmetic is checked. Overflow, division by zero,
    remainder by zero, and negation of an unrepresentable result use the codes
    above.
    Integer division truncates toward zero and remainder has the dividend's
    sign, preserving `a == (a / b) * b + (a % b)`. Float operations use
    binary64 round-to-nearest, ties-to-even; a non-finite result or division by
    either signed zero uses the corresponding code above. Underflow to a finite
    subnormal or zero is permitted, and negative zero is normalized to positive
    zero after every operation and input normalization. Implementations MUST
    NOT use fused arithmetic where it changes the specified intermediate
    rounding.
    Power, floating remainder, rounding and transcendental functions, String
    repetition, list mutation, and other built-ins are excluded.
    Lists and tuples MAY otherwise be constructed, passed, returned,
    interpolated, and projected. Tuple patterns provide deterministic tuple
    destructuring; list patterns and list destructuring are excluded from v1.
<a id="GNT-5.16"></a>

16. `String` is an immutable valid-UTF-8 sequence of Unicode scalar values.
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
      text. An empty `from` is a `deterministic-evaluation-failure` runtime
      error with code `string-empty-pattern`.
    - `String.split(separator) -> List<String>` performs exact,
      nonoverlapping, left-to-right splitting. An empty separator is a
      `deterministic-evaluation-failure` runtime error with code
      `string-empty-separator`. Leading, trailing, and adjacent empty segments
      are preserved; no match returns a one-item list containing the original
      String.
    - `String.parse_bool() -> Option<Bool>` accepts exactly `true` or `false`.
      `String.parse_int() -> Option<Int>` accepts exactly `0` or an optional
      `-` followed by a nonzero decimal digit and zero or more decimal digits;
      it rejects `-0`, leading `+`, separators, radix prefixes, leading zeroes,
      and out-of-range values. `String.parse_float() -> Option<Float>` accepts
      exactly the RFC 8259 JSON number grammar, including integer-looking
      spellings such as `1`. It returns the normalized finite binary64 value
      only when the parsed exact mathematical value lies within the inclusive
      decimal bounds defined for `Float` in Section 8, item 6, and rounds to a
      finite binary64 value; it otherwise returns `None`, including when
      parsing, range checking, or normalization fails. These parsers do not
      trim and never fail the task for invalid input.
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
<a id="GNT-5.17"></a>

17. Every String result and every List result produced by a deterministic
   operation MUST satisfy the effective limits in Section 11 before it is
    published. A rendered prompt, including its literal template segments and
    interpolation replacements, MUST satisfy `maximum_string_scalars` before
    hook dispatch; exceeding that limit is a `string-size-limit` deterministic-
    evaluation error and the operation remains undispatched. Concatenation,
    case mapping, replacement, splitting, and joining
    are atomic: a `string-size-limit` or `list-size-limit` deterministic-
    evaluation error leaves the assignment target unchanged. The same checks
    apply recursively to source construction, entry input, hook output, and
    resumed values. Deterministic String operations dispatch no hook, create no
    model rationale or operation event, and consume no validation-retry budget.
<a id="GNT-5.18"></a>

18. Patterns are deterministic structural operations over an already evaluated
   value. V1 patterns are `_`, an identifier binding, `Some(pattern)`,
    `None`, `Ok(pattern)`, `Err(pattern)`, a unit or payload enum variant, and
    a fixed-arity tuple pattern. `_` matches without binding. An identifier
    pattern matches and deep-copies the complete value into a new immutable
    lexical binding. Names introduced by one pattern MUST be unique and obey
    the no-shadowing rules in Section 4. A `let` destructuring pattern MUST be
    irrefutable for its static type; v1 therefore permits only identifier
    bindings, `_`, and tuple patterns recursively composed from those forms in
    `let`. `if let` and `match` admit refutable patterns under Section 9.
<a id="GNT-5.19"></a>

19. Every protocol field that identifies a Gantry type MUST use one canonical
   UTF-8 type descriptor. `Unit`, `Bool`, `Int`, `Float`, `String`,
    `Decision`, and `OperationError` are
    encoded exactly as their source names; a declared struct or enum is encoded as its
    `crate::`-rooted qualified path; and constructed types are encoded as
    `Option<T>`, `Result<T,E>`, `List<T>`, or `Tuple<T1,T2,...,Tn>` with no
    whitespace and with each member recursively encoded by this rule. The
    no-information result form is encoded as `Unit`. Source aliases introduced by `use`
    MUST be resolved before a descriptor is produced. Canonical descriptors
    are metadata rather than source values, but they ensure that hooks,
    journals, events, and diagnostics identify the same type independently of
    the spelling visible at a call site.
<a id="GNT-5.20"></a>

20. Boolean literals are `true` and `false`. Integer and float literals follow
   Section 13.2. An `integer_literal_token` has type `Int`, and a
    `float_literal_token` has type `Float`; surrounding expected type does not
    change that classification. A numeric literal MUST be representable by its
    token's primitive type; out-of-range literals are analysis errors. Gantry
    performs no implicit conversion between `Int` and `Float`, including in
    assignment, arguments, returns, aggregate members, equality, or arithmetic.
    Unary `-` is an operator rather than part of a numeric token.

## 6. Workflows, Methods, and Actions

<a id="GNT-6.0"></a>

This section defines callable source workflows, their evaluation order and
effect summaries, prompt construction, and declared harness actions. Ordinary
workflow dispatch is interpreter work; only the explicit operation forms
defined here and in Section 7 cross the integration boundary.

<a id="GNT-6.1"></a>

1. Gantry MUST support free functions and inherent methods declared in
   Rust-inspired `impl` blocks. An `impl` target MUST resolve to a struct
   declared in the same Gantry package. Because the grammar accepts only a
   qualified path after `impl`, built-in types, constructed types such as
   `Option<T>`, `List<T>`, and `Tuple<...>`, and the `Unit` type cannot be
   written as `impl` targets in v1. A qualified path that resolves to a
   function, module, or other non-struct item is an analysis error.
   A package MAY split one struct's methods across multiple `impl` blocks,
   subject to the package-wide duplicate-method rule below. Traits are
   excluded from v1.
<a id="GNT-6.2"></a>

2. Methods MUST support `self` and `mut self` receivers.
<a id="GNT-6.3"></a>

3. A method may mutate its receiver only through interpreter-executed field
   assignments in its body. For every assignment, Gantry MUST evaluate the
   complete right-hand side before changing the target and MUST commit the new
   root value atomically only after evaluation succeeds. Compound assignments
   `+=`, `-=`, `*=`, `/=`, and `%=` read the target exactly once, apply the
   corresponding checked primitive operator, and atomically commit its result.
   `+=` is valid for mutable `String`, `Int`, or `Float` targets; `-=`, `*=`,
   and `/=` are valid only for mutable numeric targets; and `%=` is valid only
   for mutable `Int` targets. String `+=` performs the exact concatenation
   defined in Section 5 and is subject to its atomic size-limit check. The
   right-hand-side evaluation includes hook validation, workflow calls,
   construction, projection, and every nested subexpression. Any failure MUST
   leave the assignment target unchanged;
   external hook side effects and earlier successful assignments are not
   rolled back. This assignment-level atomicity is the v1 transaction
   boundary. The root binding of any assignment target MUST be declared `mut`,
   except that receiver-field assignment is permitted through `mut self`.
   Assigning a nested field constructs and commits one updated root value; it
   does not create aliases to intermediate structs.
<a id="GNT-6.4"></a>

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
<a id="GNT-6.5"></a>

5. A workflow body MAY contain one or more integration-operation expressions.
   Each executed `prompt`, `decide`, or `action` expression MUST create exactly
   one logical operation. That logical operation MAY require multiple physical hook
   dispatches because of structured-output validation retries or recovery of
   an indeterminate dispatch; those dispatches retain the same operation ID
   and do not represent additional source operations. Calling a workflow that
   returns `Decision` invokes no hook merely because of its result type;
   evaluating its body MAY execute explicitly written model operations.
   The same transitive rule applies to ordinary workflow and method calls: a
   call site is deterministic interpreter dispatch, but executing the called
   body MAY reach any `prompt`, `decide`, or `action` sites written in that
   body or in workflows it calls. Consequently, an ordinary call is not
   necessarily free of integration effects merely because its call site does
   not contain one of those keywords. External work remains explicit at the
   reached operation site and observable through the workflow-call context,
   operation source location, journal, and events. Analysis tooling SHOULD
   expose this transitive effect to authors without representing the call
   itself as an integration operation.
   Each `decide` executed through a workflow call is its own logical decide
   operation; the call expression and intermediate workflow frames are not
   additional operations. Its source location and static operation site are
   those of the executed `decide`, while its dynamic identity also records the
   complete workflow-call path that reached it. A workflow may instead return
   a previously obtained `Decision`;
   returning or forwarding that value creates no new operation. These rules
   keep operation counts, hook requests, journals, and events aligned with the
   model-backed sites visible in source.
   Semantic analysis MUST expose this transitive behavior without changing
   ordinary call syntax. For every function and method,
   the structured analysis result MUST contain the following direct-site
   inventory and transitive effect summary:
   - every direct workflow-call edge, identified by call-site location and
     canonical callee path;
   - every direct integration-operation site (`prompt`, `decide`, or `action`)
     and task-control site (`spawn`, `join`, `joinall()`, or `detach`) in that
     workflow, identified by kind and source location; and
   - a canonical effect set drawn from `prompt`, `decide`,
     `action(read_only)`, `action(idempotent)`, `action(non_idempotent)`,
     `spawn`, `join`, `background`, `session`, and `attempt`; and
   - the source locations and canonical action paths contributing each action
     effect.
   For this inventory, “direct” means lexically contained in the workflow's
   body, including sites and call edges inside its nested control-flow and
   spawned blocks, but excluding sites and edges in another workflow reached
   by a call. A site inside a spawned block is therefore direct syntax of the
   enclosing workflow even though the child task executes it. The transitive
   flags include both those direct sites and sites reachable through direct
   call edges.
   Direct syntax contributes effects as follows: `prompt`, `decide`, and an
   action invocation contribute their correspondingly named effects; `spawn`
   contributes `spawn`; both `join(...)` and `joinall()` contribute `join`;
   `detach(...)` contributes `background`; every explicit lexical, loop, or
   operation-local session modifier contributes `session`; and `attempt`
   contributes `attempt` in addition to the wrapped operation's effect.
   Runtime-created root and spawned-task sessions do not independently add a
   source effect. One source site MAY therefore contribute more than one
   effect. Canonical effect order is the order shown in the effect domain in
   Section 3.1.
   The transitive effect set MUST be the least fixed point of the package call
   graph, including recursion and method calls. Effects are a
   source-level contract reported by analysis, not additional hook operations.
   A function or method MAY be declared `pure fn`; analysis MUST reject that
   assertion unless its inferred effect set is empty. A workflow returning
   `Decision` follows the same rule and may be pure when it only forwards a
   supplied value. Implementations MUST emit the same canonical effect set for
   the same package.
   Struct, enum, option, result, list, and tuple construction; field access;
   assignment; pattern routing; module lookup; the act of dispatching a
   workflow call; and `join` are interpreter operations and MUST NOT directly
   invoke an operation hook. Executing the called workflow body may still
   reach an explicit integration operation, as specified above.
<a id="GNT-6.6"></a>

6. Each `prompt` expression MUST contain an explicit prompt template and MAY
   contain parenthesized operation modifiers before that template. A typed
   prompt places its result annotation after the template and any `using`
   clause, as in
   `prompt(retry_limit = 2, session = fork) "..." -> Report`. A prompt with no
   result annotation, or with `-> Unit`, returns `Unit`. A prompt or `decide`
   expression MAY contain one `using { ... }` clause after its template.
   Each entry is either shorthand `name`, equivalent to `name: name`, or
   `name: expression`. Entry names MUST be
   unique. Expressions use the same deterministic, side-effect-free subset as
   interpolation. Gantry MUST first evaluate and capture interpolations in
   source order, then evaluate and capture named inputs once from left to
   right, and only then dispatch. If either phase fails, Gantry MUST NOT
   evaluate entries in a later phase or dispatch the operation. Validation
   retries and recovery redispatches MUST reuse the captured values rather
   than reevaluate them.
<a id="GNT-6.7"></a>

7. Template expressions MUST be interpolated before hook dispatch. To keep
   agent invocation explicit, an interpolation MAY contain only bindings,
   field paths, list or tuple projections, primitive literals, deterministic
   primitive operators and conversions, the sealed deterministic String and
   List methods in Section 5, and deterministic aggregate constructor
   expressions composed from other permitted interpolation expressions.
   Workflow calls, source-defined method calls, `prompt`, `decide`, `action`,
   assignment, `join`, and other expressions that can invoke a hook, alter
   control flow, or mutate state are prohibited inside interpolation. A
   postfix call inside interpolation MUST resolve either to a declared enum
   payload constructor or to a sealed deterministic built-in. Its payload,
   receiver, and arguments, as applicable, MUST themselves be valid
   interpolation expressions.
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
   structural block-prompt layout are omitted. Exact interpolation source text
   and source spans MUST be retained for diagnostics and protected
   observability, but MUST NOT be supplied to or used by the operation
   fulfiller. The hook request carries interpolation arguments and named inputs
   as the ordered names, canonical type descriptors, and canonical JSON values
   defined in Section 7. An integration MUST make every named input available
   to the selected agent, even when it must render that structured vector into
   provider text.
<a id="GNT-6.8"></a>

8. A trailing expression in a function, method, or spawned block implicitly
   yields its value. An explicit `return` MAY yield earlier from a function,
   method, or spawned block. Every explicit or implicit returned expression MUST
   exactly match the
   declared result type. A workflow whose signature omits a result type
   implicitly returns `Unit`. A Unit-producing prompt, action, workflow call,
   method call, `join`, or `joinall()` MAY be terminated with `;`, which
   evaluates it and discards its sole `()` value. A
   statement-only agent or session context uses `with <agent> { ... }` or
   `session(<directive>) { ... }` without a semicolon after its closing brace.
   Every non-Unit value that is intentionally ignored MUST use the explicit
   statement `discard expression;`. The expression is evaluated once with its
   inferred effects and its value is then discarded. A bare `expression;` is
   valid only when the expression has type `Unit`; syntax shape and inferred
   effect do not create exceptions. In particular, `discard decision;` is
   explicit but performs no new dispatch when `decision` is a previously
   evaluated binding. This type-directed rule replaces the syntax-shaped
   expression-statement whitelist.
   Assignment and `spawn` statements do not themselves produce values.
   Conditional-arm and loop bodies are statement-only blocks; they MUST NOT
   end in a trailing expression whose value would be silently discarded.
   Semantic analysis MUST prove that every reachable normal completion of a
   value-returning function, method, or spawned block yields the declared type.
   Falling through a value-returning body is an analysis error; it MUST NOT be
   deferred to a runtime missing-value failure.
<a id="GNT-6.9"></a>

9. A method MAY return `self`; the returned value is a deep value copy and does
   not consume the receiver. Duplicate inherent methods for the same struct are
   analysis errors.
<a id="GNT-6.10"></a>

10. `return` exits the nearest enclosing function, method, or spawned block. A
   spawned block is therefore a return target before any
    workflow that lexically encloses the `spawn`. `break` and `continue` target
    the nearest enclosing loop even when they occur inside a nested `with` or
    `session` block, but they MUST NOT cross a spawned-block boundary. An
    ordinary value-producing or statement-only `with` block changes agent
    selection only, and the corresponding `session` block changes the active
    logical session only; neither intercepts or retargets control transfer.
    A `with` or `session` block that yields `Decision` remains an ordinary
    value-producing block; its result type does not create a special control-
    transfer boundary.
<a id="GNT-6.11"></a>

11. Except for explicitly parallel spawned blocks, expression evaluation MUST be
   deterministic and left to right. A workflow call resolves its callee
    before evaluating its arguments in source order; resolving the callee does
    not produce a runtime value or execute the workflow. A method call
    evaluates its receiver before its arguments, and a postfix chain applies
    each suffix before the next. Constructor fields follow the source-order
    rule in Section 5, and prompt interpolations follow the source-order rule
    in item 7 above. Each subexpression MUST complete before the next begins.
    Failure, decline of a required result, or cancellation in one subexpression MUST
    prevent every later subexpression in that expression from being evaluated
    or dispatched. Entering a `with` expression establishes its selected agent
    before its body begins; entering a `session` expression establishes its
    active logical session before its body begins. These rules make the order
    of external operations visible even when calls or constructors are nested.
<a id="GNT-6.12"></a>

12. An action declaration introduces one named item in its containing module.
   Its canonical path is the containing module's canonical path followed by
   the declared identifier; a declaration therefore uses an identifier, while
   an invocation may use a qualified path to reach that item. An action has one
   mandatory recovery class, typed positional parameters, an optional result
    type, and no Gantry body. The recovery class is exactly `read_only`,
    `idempotent`, or `non_idempotent`. An
    action invocation MUST use the `action` keyword and MUST resolve to one
    declared action; writing the same path as an ordinary call is an analysis
    error rather than an implicit action dispatch. Gantry evaluates action
    arguments exactly once from left to right, requires exact parameter-type
    equality, captures their canonical JSON values, and then dispatches one
    logical action operation. The current Gantry task awaits that result before
    advancing; concurrency requires placing the action invocation in a
    `spawn` block, whose child task performs the same await independently. A
    Unit action is a Unit expression statement; a value-producing action
    yields its declared type and MAY be bound, returned, matched, or explicitly
    discarded. Every action request carries the declared recovery class and
    stable operation ID. Action declarations
    have no agent, session, prompt template, or provider policy in Gantry
    source. The integration resolves their canonical signatures during
    preflight under Section 7.

## 7. Integration Operations, Agents, Hooks, and Sessions

<a id="GNT-7.0"></a>

This section defines the runtime side of the three visible integration
operations. Items 1 through 3 cover package-level resolution and dynamic agent
selection; items 4 through 11 define hook requests and outcomes; items 12 and
13 define logical sessions; and items 14 through 18 define side effects,
operation identity, failure categories, and propagation.

<a id="GNT-7.1"></a>

1. A Gantry package MAY declare permitted agent names in one or more `agents {
   ... }` declarations. Declarations from all package modules are
   merged into one package-wide set; repeating the same logical name is
   idempotent rather than an error. A package containing any `prompt` or
   `decide` operation site MUST have a nonempty merged agent set. When that set
   is nonempty, exactly one `default agent = <name>;` declaration MUST
   appear in `main.gnt`, and its name MUST belong to the merged set. When the
   set is empty, `default agent` MUST be absent. A `default agent` declaration
   in any child module is an analysis error, even when it repeats the root
   declaration. Conflicting default bindings or selection of an undeclared
   agent are analysis errors. This conditional rule permits packages that
   declare no agents, including deterministic-only and action-only packages,
   to omit fictitious model configuration. The grammar intentionally does not
   admit `agents {}`; a package with no agents omits agent declarations
   entirely. Within one uninterrupted execution or resume run,
   integrations MUST resolve every occurrence of the same logical name
   consistently across all tasks. Before a new execution or resume begins,
   the integration MUST attest that it can resolve every name in a nonempty
   merged set and MUST supply one opaque, stable agent-mapping revision ID.
   An empty set requires neither agent resolution nor an agent-mapping
   revision. When present, the ID identifies the complete logical-name mapping
   for that run without requiring
   Gantry to inspect provider configuration. For a new execution, Gantry MUST
   include that revision in the committed execution-start evidence required by
   Section 11. A later resume MAY change the mapping only by supplying and
   committing a new revision in execution-state evidence before
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
<a id="GNT-7.2"></a>

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
   contain the initial revision. A resume MAY change the mapping only after
   Gantry commits execution-state evidence containing the replacement revision;
   that revision applies to every later action dispatch in the resume run.
   Previously committed outcomes and results remain unchanged. Recovery of an
   indeterminate action retains its canonical action path, signature, recovery
   class, typed arguments, and logical operation ID while carrying the active
   recorded action-mapping revision. The integration MUST map one canonical
   signature and recovery class consistently for the complete run and MUST
   reject conflicting or ambiguous capability registrations during preflight.
<a id="GNT-7.3"></a>

3. Agent selection is established by lexically delimited `with <name> { ... }`
   blocks and dynamically inherited by model-backed work
   reached from them. The selected name applies to
   `prompt` and `decide` operations written directly in the block, model
   operations reached through workflow calls made from it, and
   child tasks spawned from it, unless a nested `with` block overrides the
   selection. It does not apply to `action` operations. A workflow call therefore
   inherits the caller's active selection rather than resetting to the default,
   and a spawned child snapshots the selection that is active when `spawn`
   executes. Exiting `with` restores the previous selection for its caller;
   an already spawned child retains its snapshot. `<name>` MUST be a literal
   name from the merged agent declarations, not a runtime binding. `with`
   contexts MAY occur at any block scope. Model operations with no active
   selection use the declared default agent.
   Agent selection and logical-session selection are orthogonal. Every logical
   session owns one Gantry-defined canonical transcript. The transcript is an
   ordered sequence of the versioned canonical turns defined in item 12.
   Failed physical dispatches, repair diagnostics,
   telemetry, workflow frames, branches, task ancestry, and action operations
   are not transcript turns. `inline` reuses the sequence, `fork` snapshots its
   complete committed prefix at creation, and `new` starts with an empty
   sequence. A prompt or decide request carries that sequence before the
   current request. The integration MUST present its semantic content in order
   and MUST NOT add provider history that is absent from it. Provider session
   handles MAY cache this transcript, but the canonical sequence is the
   portable authority. Reusing a session across `with` blocks therefore gives
   every selected agent the same transcript; an integration unable to do so
   MUST reject the mapping during preflight.
<a id="GNT-7.4"></a>

4. The Rust hook contract MUST be asynchronous and independent of any specific
   executor implementation. Every Rust embedding-profile implementation uses
   the multithread-safe baseline in Section 15.9; this is not a separate
   conformance profile.
   Its futures MUST be `Send`, and Gantry's public API MUST NOT expose Tokio-
   or provider-specific types. A future returned by an extension method MAY
   borrow that method's receiver or arguments and therefore need not be
   `'static`; only an owned Gantry task future submitted to the executor MUST
   be `Send + 'static`. Each
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
   `TaskContext` containing task and execution identity; the
   task's base logical session ID; the root logical session ID and provenance;
   the enclosing session ID and fork provenance when the task was spawned; and
   the inherited agent selection. Workflow frames, branch history, task
   ancestry, and value provenance are observability data and MUST NOT be
   supplied through `TaskContext` or otherwise influence hook fulfillment.
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
   Public asynchronous extension traits MUST use executor-independent boxed
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
<a id="GNT-7.5"></a>

5. Every operation hook request MUST be a versioned tagged envelope with a
   common header and exactly one operation-specific body. Except for fields
   explicitly described as conditional below, every listed v1 field is
   required. The common header MUST contain:
   - a protocol major and minor version;
   - stable operation, execution, and task IDs;
   - an operation kind;
   - the expected result kind;
   - the expected canonical result-type descriptor from Section 5;
   - the expected JSON Schema;
   - the effective `maximum_hook_output_bytes`,
     `maximum_value_nesting_depth`, `maximum_value_nodes`,
     `maximum_string_scalars`, and `maximum_list_items` limits that Gantry
     will enforce outside or in addition to JSON Schema validation;
   - generated operation guidance describing the input contract, output
     contract, and required strict-JSON response;
   - the canonical core operation-site ID;
   - a dispatch ID, validation-attempt number, and recovery-dispatch number;
     and
   - validation errors exactly when the dispatch is a structured-output repair
     attempt, including a recovery redispatch of such an attempt.
   The v1 operation kinds are `prompt`, `decide`, and `action`, matching the
   three source keywords that create operations. The result
   kind is `value`, `unit`, or `decision`. The expected result descriptor is
   the declared value type for `value`, `Unit` for `unit`, and `Decision` for
   `decision`.

   A `prompt` or `decide` body MUST contain the selected agent name and
   active agent-mapping revision; authored source template and interpolated
   prompt; ordered interpolation-argument vector; ordered named-input vector;
   the active canonical logical-session transcript immediately before the
   current operation; required active and root logical-session IDs; a parent
   logical-session ID exactly when the active session has a parent; and one
   session-use value.
   The session-use value is `inline` when the operation reuses the active
   session and contains no creation payload. It is `create` only when this
   request creates a `fork` or `new` session and then contains that directive,
   the new session ID, its parent ID and root ID, and the creation provenance
   required by this section. A session created earlier by a lexical session
   block, loop, or spawned task uses `inline` only after the runtime session-
   establishment interface has established its integration-side context under
   item 12. An `inline` request MUST NOT itself cause creation of a Gantry or
   provider session. Typed interpolation arguments MUST be an ordered
   vector containing one record for each interpolation island in source order;
   each record contains its zero-based source-order position, canonical static-
   type descriptor from Section 5, and RFC 8785 canonical strict-JSON value.
   Exact island text and spans are observability metadata and MUST NOT be
   supplied to or used by the fulfiller. The named-input vector MUST
   preserve `using` source order. Each entry contains its unique name,
   canonical static-type descriptor, and RFC 8785 canonical strict-JSON value.
   A shorthand entry and its expanded `name: name` form have the same protocol
   value. A repeated interpolation appears repeatedly so the request preserves
   the explicit operation inputs exactly.

   An `action` body MUST instead contain the action's canonical item path,
   canonical signature, and declared recovery class; the action-mapping
   revision active for the dispatch; and an ordered argument
   vector containing each parameter name, canonical static-type descriptor,
   and RFC 8785 canonical
   strict-JSON value. It MUST NOT contain a selected agent, prompt template,
   interpolated prompt, named model input, or conversational-session directive.
   Lexical `with` and `session` contexts do not change an action request.
   The action fulfiller receives the stable operation ID from the common
   header; the action body MUST NOT duplicate it. This single authoritative
   field avoids conflicting identities within one request.
   Source locations remain required in diagnostics, journals, and protected
   observability records. They identify package-relative UTF-8 files and zero-
   based, end-exclusive byte spans into the immutable source snapshot, but they
   are not hook input, semantic identity, or a resume compatibility key. The
   operation ID MUST remain
   stable across validation retries and resume. Each physical hook invocation
   MUST have a distinct dispatch ID. The zero-based
   validation-attempt number advances only after Gantry receives output that
   fails UTF-8 decoding, JSON parsing, schema validation, or an effective raw-
   byte, value-depth, value-node, String, or List resource limit; it is bounded
   by the operation's structured-output retry limit. The zero-based recovery-
   dispatch number advances when
   an indeterminate invocation is repeated after resume and does not consume
   that retry budget. Validation errors MUST identify the failing JSON
   instance location with JSON Pointer when one exists, the violated schema
   location when one exists, and a human-readable message; they MUST NOT
   contain raw integration output. Each error MUST also carry exactly one
   machine-readable category: `utf8`, `json-syntax`, `json-duplicate-key`,
   `json-unicode`, `schema`, or `resource-limit`. JSON Pointer and schema-
   location fields are absent rather than fabricated when the applicable
   validation stage cannot produce them. Gantry validates in this order:
   raw-byte limit, UTF-8, JSON syntax and scalar validity (including duplicate
   member rejection), parser-enforced depth and node limits, schema, and then
   recursive String and List limits. Failure at a stage prevents later stages
   from running. Within the failing stage, error ordering MUST follow
   raw-output byte position for decoding and parsing errors and depth-first
   instance traversal, with object properties in unsigned UTF-8 name order and
   array members in index order, for schema and resource-limit errors. This
   canonical shape and order allow independent harnesses to render equivalent
   repair guidance without parsing diagnostic prose.
<a id="GNT-7.6"></a>

6. A hook request MUST NOT contain an implicit logical trace. Workflow and
   decision frames, branch outcomes, loop history, parent-task identity or
   task ancestry, source locations, value or operation provenance, decline
   evidence, and telemetry are nonsemantic observability data. They MAY appear
   in protected journal or event payloads, but MUST NOT appear in
   `TaskContext` or be presented to a selected model or action implementation
   as semantic fulfillment input. Operational metadata required by the hook
   envelope is governed by the following paragraph.

   The versioned hook envelope necessarily contains operational metadata such
   as protocol, execution, task, operation, site, dispatch, attempt, recovery,
   and mapping-revision identifiers. Integration infrastructure MAY use those
   fields only for routing, capability lookup, lifecycle management,
   cancellation, required deduplication, validation, journaling, and
   correlation. Except for the stable operation ID supplied to an action for
   its declared recovery behavior, the integration MUST NOT present that
   metadata to the selected model or action implementation or let it alter the
   fulfilled result.

   The common semantic fulfillment input is exactly the operation and result
   kinds, expected canonical type and schema, effective output limits,
   generated output guidance, and structured validation errors on a repair
   dispatch. Model fulfillment additionally receives exactly the authored and
   rendered prompt, ordered interpolation arguments, ordered `using` inputs,
   selected agent, and explicit canonical logical-session transcript. Action
   fulfillment additionally receives exactly the canonical action path and
   signature, recovery class, stable operation ID, and ordered typed
   arguments. Source modifiers affect fulfillment only through those listed
   fields. A value carries only its source-visible type and content: a
   `Decision` carries its visible Boolean and rationale, and every `None` of
   one `Option<T>` type is semantically identical regardless of how it arose.
   Adding another behavior-affecting fulfiller input requires a source-language
   and hook-protocol major version change.
<a id="GNT-7.7"></a>

7. Prompt interpolation MUST use `${expression}`. An unescaped `$` followed by
   `{` begins interpolation. `$$` consumes exactly those two dollar signs and
   produces one literal dollar sign, so `$${name}` renders the literal text
   `${name}` without interpolation. A `String` is interpolated as its string
   contents; `Unit`, `Bool`, `Int`, `Float`, a struct, enum, option, result,
   list, tuple, `Decision`, or `OperationError` is interpolated as compact
   strict JSON, with both `()` and `None` rendered as `null`. This compact encoding
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
<a id="GNT-7.8"></a>

8. Ordinary quoted strings MUST support `\\`, `\"`, `\n`, `\r`, `\t`, `\0`, and
   Rust-style Unicode scalar escapes of the form `\u{HEX}`. Unknown,
   incomplete, or invalid escapes are syntax errors. A quoted prompt literal
   MAY contain literal newline characters. Literal newlines and all indentation
   MUST be preserved exactly; Gantry performs no implicit indentation
   stripping. Gantry MUST also support Rust-style raw strings `r"..."` and
   hash-delimited forms such as `r#"..."#`. Raw strings disable backslash
   escape processing but do not disable `${...}` interpolation or `$$`
   escaping.
<a id="GNT-7.9"></a>

9. Hooks MUST receive the expected output schema as a separate machine-readable
   value. Gantry MUST provide guidance that clearly states
   the operation's input and output contract. At minimum, the guidance MUST
   state that the raw operation output returned through `Completed` must contain
   exactly one JSON text with no surrounding prose, Markdown fence, or
   additional value; identify the expected result kind; explain that unknown
   struct properties are rejected; identify fields that may be omitted and the
   defaults or `None` values omission supplies; describe every interpolation,
   named input, or action argument; and explain the Unit, tagged-value, or
   decision shape when applicable. The guidance MUST also state the effective
   raw-output byte, value-depth, value-node, String-scalar, and List-item
   limits supplied in the request. These limits are part of the output
   contract even when the generated JSON Schema cannot express them. The
   wording and provider-specific
   presentation MAY evolve, but those semantic instructions MUST remain
   present on every initial dispatch and repair retry.
<a id="GNT-7.10"></a>

10. The only v1 source-level model-selection knob is the agent name. Action
   selection is instead the canonical path of a declared action. System/user/
    assistant roles, model choice, tool implementation, sampling settings,
    streaming, progress reporting, operation-level timeouts, and provider-
    specific cancellation mechanisms are integration concerns. Those
    mechanisms MUST still observe the Gantry-owned cancellation token and the
    language-level cancellation state transitions required by Sections 10 and
    15.
<a id="GNT-7.11"></a>

11. A hook MUST return one of three host-level outcomes:
   `Completed(raw_output)`, `Declined(reason)`, or
   `Failed(category, message)`. `category` is exactly `provider-failure`,
   `timeout`, `policy-denied`, or `cancelled`. `Completed` contains raw bytes;
   Gantry alone owns decoding, validation, normalization, and repair. Reasons
   and messages MUST be nonempty bounded Unicode strings under the effective
   hook-output and String limits. Invalid diagnostic data is a bounded
   `hook-failure` contract violation and MUST NOT be journaled verbatim.
   `Declined` is an operation failure for every expected type, including
   `Option<T>` and `Unit`; it never manufactures `None`. An enclosing `attempt`
   converts it to `OperationError::Declined`. `Failed` maps its category to the
   corresponding `OperationError` under `attempt`, or otherwise fails the task
   in the applicable runtime category. `Failed(cancelled, message)` is
   catchable only when it is a hook-reported operation outcome received while
   the containing Gantry task remains active. Once Gantry task cancellation is
   signalled, the cancellation rules in Sections 3 and 10 win: the task cannot
   consume that outcome and `attempt` cannot convert it. Structured-output
   repair applies only to `Completed` bytes, never to decline or failure.
<a id="GNT-7.12"></a>

12. Every `prompt` and `decide` MUST use exactly one stable logical session ID;
   several operations may intentionally reuse that session. Actions have no
   session. Every session owns a Gantry-defined
   canonical transcript consisting only of accepted model exchanges. Each turn
   is a `TranscriptTurnV1` record containing exactly: `operation_kind`
   (`prompt` or `decide`); `authored_template` and `rendered_prompt` Strings;
   separate ordered `interpolation_inputs` and `using_inputs` arrays in the
   request shapes defined by item 5; `selected_agent`; and `accepted_result`.
   `accepted_result` contains the result kind, canonical type descriptor, and
   normalized strict-JSON value. A canonical transcript value is an object
   containing protocol major `1`, protocol minor `0`, and a `turns` array of
   those records in acceptance order. It is serialized as RFC 8785 canonical
   JSON. The v1 publication MUST provide its JSON Schema and golden encodings;
   implementations MUST reject unknown fields, unknown variants, invalid
   canonical type descriptors, and transcript values that exceed the effective
   value-depth, value-node, String-scalar, or List-item limits. Failed
   dispatches, validation diagnostics, actions,
   workflow frames, branch or loop history, task ancestry, and telemetry are
   excluded. Gantry MUST commit a turn before a later inline operation can
   observe it.

   `inline` reuses the active session. `fork` allocates a stable child ID and
   snapshots the complete committed transcript prefix of its parent at the
   fork point. `new` allocates a stable ID with an empty transcript. The root
   session is initialized from an optional embedder-supplied canonical
   transcript or created empty by Gantry. Gantry validates, normalizes, and
   durably records that transcript; an integration-owned provider handle is
   only a cache of the Gantry-owned sequence. A lexical `session(fork)` or
   `session(new)` creates one session for its dynamic block; an operation-local
   directive creates one for that operation. Spawn creates a fork before the child becomes runnable.
   A loop `fork` creates child sessions at the loop-form-specific points in
   Section 9, item 6, while loop `new` creates one session on loop entry. Every
   allocated ID and its transcript basis MUST be durable before dispatch or
   child submission can depend on it.

<a id="GNT-7.13"></a>

13. Gantry is the transcript authority across retry, agent changes, process
   restart, and resume. A hook request carries the active canonical transcript
   before the current operation. An integration MAY cache provider session
   handles, but it MUST be able to reconstruct or verify their content against
   that transcript and MUST NOT add provider history absent from it. Session
   establishment is idempotent by execution and logical-session ID. Resume
   preflight MUST resolve or reconstruct every transcript required by
   unfinished work; inability to do so is `unresolved-logical-session`, never
   permission to substitute an empty conversation. Cross-agent reuse presents
   the same canonical transcript to each selected agent.
<a id="GNT-7.14"></a>

14. Model operations are externally read-only in v1: their fulfillment MAY read
   provider state and use pure or read-only tools, but MUST NOT mutate an
    external system, obtain approval, publish data, execute a state-changing
    command, or perform another externally visible side effect. Such work MUST
    be declared and invoked as an `action`, so its recovery class and operation
    ID are visible. Provider caching, billing, and append-only audit telemetry
    are not source-visible effects, but they MUST NOT alter Gantry semantics.

<a id="GNT-7.15"></a>

15. An action's declared recovery class governs retries and interruption.
   `read_only` promises no externally visible mutation. `idempotent` promises
    that repeating the same stable operation ID has the effect of one
    successful invocation; the handler MUST deduplicate with that ID.
    `non_idempotent` makes no repetition promise. Structured-output repair and
    recovery MAY automatically redispatch only `read_only` or `idempotent`
    actions. An indeterminate `non_idempotent` action MUST become
    `OperationError::UnknownOutcome` when enclosed by `attempt`, or the
    `unknown-action-outcome` runtime error otherwise; it MUST NOT be
    redispatched automatically. Prompt and decide repair remains safe because
    item 14 prohibits external mutation. A dispatch ID identifies one physical
    attempt for audit and is never the deduplication key.
<a id="GNT-7.16"></a>

16. Every dynamic operation identity MUST correspond to a logical execution path
   consisting of the execution ID, task path, workflow-call path, canonical
    core operation-site ID, branch arm, and enclosing loop iteration counters.
    A core site ID is derived from canonical module and workflow paths plus the
    construct's structural position in canonical IR; comments, whitespace,
    file paths, line endings, and source spans do not affect it.
    Recursive calls and repeated calls from the same call site MUST receive
    distinct call-frame occurrences; distinct loop iterations and spawned
    task occurrences MUST likewise receive distinct identities. Validation
    retries and recovery of one indeterminate dispatch retain that identity.
    Implementations MAY encode or hash the path opaquely, but MUST journal
    enough of it to reconstruct the same identity on resume and MUST NOT reuse
    an identity for another dynamic invocation. Source locations remain
    observability metadata and do not participate in identity. Call-frame,
    recursive-call, spawn, and repeated-call occurrences are zero-based counters assigned in
    deterministic encounter order within their immediate dynamic parent.
    Branch identity uses the branch-construct kind and the zero-based arm
    position in its conditional chain or `match`;
    loop identity uses the zero-based body-execution and condition-evaluation
    positions required by Section 9. These counters are logical interpreter
    state and MUST be checkpointed or reconstructible from the durable prefix;
    wall-clock order and executor completion order MUST NOT influence them.
<a id="GNT-7.17"></a>

17. Hook outcomes and Gantry failures are separate domains. A hook outcome is
   exactly `Completed(raw_output)`, `Declined(reason)`, or
    `Failed(category, message)` with a category from item 11.
    Before a new execution is accepted and its execution ID is returned to the
    embedder, structured start failures MUST use one of the following exact
    category values when applicable: `syntax`, `analysis`,
    `entry-input-validation`, `integration-preflight`,
    `initial-journal-ownership`, `execution-start-persistence`, or
    `required-event-delivery`. The last category applies to required delivery
    failure during pre-execution validation or analysis. Gantry MAY allocate
    a candidate execution ID while constructing the execution-start record,
    but that ID is not an accepted execution handle until the record is
    durable.

    Resume has a distinct pre-execution failure boundary even though the
    execution ID already exists. A resume-start failure MUST use one of the
    following exact category values when applicable: `journal-read-or-format`,
    `ownership-acquisition`, `source-or-configuration-incompatibility`,
    `unresolved-agent-mapping`, `unresolved-action-mapping`,
    `unresolved-logical-session`, or `unavailable-required-event-sink`.
    Such a failure means recovered interpretation never began: Gantry MUST NOT
    commit execution-state or terminal-execution evidence, consume a retry
    budget, or change the execution's durable terminal status. If journal
    ownership was acquired before the failure, Gantry MUST release it under
    Section 11. The embedder MAY correct the dependency or configuration and
    attempt resume again.

    Once a new execution has committed execution-start evidence, or a
    resume invocation has completed compatibility and dependency preflight and
    begins advancing recovered state, failures are runtime errors. Runtime
    errors MUST expose a stable category and MAY expose a more specific stable
    code plus structured details. The exact v1 runtime category values are
    `logical-session-setup`, `hook-creation`, `hook-failure`,
    `required-result-decline`, `structured-output-exhaustion`,
    `unknown-action-outcome`, `deterministic-evaluation-failure`,
    `executor-failure`, `cancellation`, `journal-failure`,
    `required-event-delivery-failure`, `task-join-failure`, and
    `internal-invariant-failure`.
    `success` and `detached-task-failure` are terminal-only outcome categories,
    not runtime-error categories. A terminal-execution record uses
    one of those terminal-only categories or the exact runtime-error category
    that determines the terminal outcome under Section 10. `journal-failure`
    cannot become a durable terminal category because journal failure prevents
    the required terminal record from being committed. After a terminal record
    is durable, `required-event-delivery-failure` is reported separately as a
    delivery-barrier status and MUST NOT replace the recorded terminal
    category.
    Backticked limit names such as `workflow-call-depth-limit`,
    `string-size-limit`, `list-size-limit`, and `task-count-limit` are codes
    within the `deterministic-evaluation-failure` category, not additional
    categories. Task failures, foreground outcomes, terminal records, and
    events MUST preserve the category and any specified code. Projection bounds
    failures use `deterministic-evaluation-failure`. Prose elsewhere in this
    document MAY use spaces or descriptive wording for readability, but every
    protocol, journal, event, diagnostic, and embedding result MUST use these
    exact category values. Concrete Rust error types are implementation-defined,
    but embedders MUST be able to distinguish start, resume-start, and runtime
    categories without parsing display text.
<a id="GNT-7.18"></a>

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

<a id="GNT-8.0"></a>

Items 1 through 8 define strict-JSON decoding, normalization, and generated
schemas. Items 9 through 12 define repair retries and exhaustion. Item 13
limits source disclosure in diagnostics. These rules validate integration
output; they do not add source syntax beyond the result annotations and
operation modifiers defined in Sections 6 and 13.

<a id="GNT-8.1"></a>

1. A successful operation-hook outcome provides raw bytes in
   `Completed(raw_output)`. Gantry MUST reject the outcome in the
   `resource-limit` validation category before UTF-8 decoding when its byte
   length exceeds `maximum_hook_output_bytes`. Gantry MUST decode an admitted
   outcome as UTF-8 and parse exactly one RFC 8259 JSON text. RFC 8259
   whitespace is allowed before and after the single value; every other byte
   before or after it is trailing data and MUST be rejected. Gantry owns this
   parsing step and MUST
   reject non-UTF-8, malformed, empty, trailing-data, or excessively nested
   output as structured-output validation failures.
   Duplicate member names in any JSON object MUST also be rejected as a
   structured-output validation failure rather than normalized by a JSON
   library's first-member or last-member behavior.
   JSON strings and object member names MUST decode to sequences of Unicode
   scalar values; valid escaped surrogate pairs are combined, and unpaired
   surrogates MUST be rejected.
   During parsing, Gantry MUST enforce `maximum_value_nesting_depth` and
   `maximum_value_nodes` without first constructing a deeper or larger in-
   memory value. JSON root depth is one. Each array member or object-property
   value has its containing array or object's depth plus one; an object
   property name does not add depth. Empty arrays and objects therefore have
   depth one. The root is also one value node. Each array member and each
   object-property value contributes one additional node, recursively; object
   property names do not contribute nodes. A scalar root therefore has one
   node, and an empty array or object also has one node. Exceeding either limit
   is a `resource-limit` validation failure. The same depth and node-count
   definitions apply to entry input and to the JSON encoding of every source-
   constructed, deterministic, journal-restored, or normalized Gantry value.
   For a `Unit` operation, the expected schema is exactly the following
   object, and the parsed value MUST be JSON `null`:

   ```json
   {
     "$schema": "https://json-schema.org/draft/2020-12/schema",
     "type": "null"
   }
   ```

   This wire value creates the sole `Unit` value `()`. `Declined` and `Failed`
   retain their operation-failure behavior. Including `$schema` gives `Unit`
   the same explicit output contract as every other result type.
<a id="GNT-8.2"></a>

2. A `Bool` result is represented by a JSON Boolean. An `Int` result is a JSON
   number whose exact mathematical value is integral and in Gantry's exact
   range. RFC 8259 has one number grammar rather than distinct integer and
   floating lexical types, so spellings such as `1`, `1.0`, and `1e0` all
   normalize to the same `Int` value when `Int` is the expected type. Gantry
   MUST determine integrality and range without first rounding through
   binary64. A `Float` result is a JSON number whose exact mathematical value
   is within the inclusive decimal bounds in item 6 and that rounds under
   Section 5 to a finite IEEE 754 binary64 value; integer-looking spellings
   are valid when `Float` is expected. The expected Gantry type, not the source
   lexeme, determines numeric normalization. Gantry MUST reject `NaN`,
   infinities, values outside those decimal bounds, and values whose
   conversion overflows to a non-finite result. Gantry MUST normalize negative
   zero to positive zero
   before exposing or serializing a `Float`. A `String` result is represented
   by a JSON string. A struct result is a JSON object whose property names
   directly match its declared field names.
   Every decoded or computed String and every decoded or computed List MUST
   also satisfy the effective scalar-count and item-count resource limits in
   Section 11. This resource check is independent of JSON Schema shape
   validation and applies recursively before a value becomes observable. A
   hook output that exceeds either limit is a structured-output validation
   failure in the `resource-limit` category and participates in the operation's
   normal validation-retry policy. Entry input that exceeds a limit is an
   entry-input validation failure. Source construction or deterministic
   evaluation that exceeds a limit is a deterministic-evaluation runtime
   error. These contexts MUST NOT be conflated merely because they enforce the
   same effective limits.
   Every decoded, computed, restored, or normalized value MUST likewise
   satisfy `maximum_value_nesting_depth` and `maximum_value_nodes` under the
   JSON-tree definitions in item 1 before it becomes observable. A source
   construction or deterministic evaluation that exceeds either limit is a
   deterministic-evaluation runtime error; entry input fails entry validation;
   hook output enters structured-output repair; and an incompatible or corrupt
   restored value fails resume. Implementations MUST enforce both limits with
   bounded traversal rather than recursive native-stack growth.
   JSON decoding does not normalize String contents. Deterministic String
   methods operate on the decoded Unicode scalar sequence and serialize their
   results through the same ordinary JSON String representation; they add no
   provider-specific wire type or schema keyword.
   After source construction or hook-output normalization, a runtime struct
   contains every declared field. Whenever Gantry serializes that normalized
   struct, it MUST emit every field; an `Option<T>` field whose value is `None`
   is emitted as JSON `null`, and an applied default is emitted as its resolved
   value. Although hook output may omit an optional property, omission is not
   preserved as a distinct runtime state. Every `None` of the same `Option<T>`
   type is semantically identical; observability records may state how an
   operation failed, but values carry no hidden decline evidence.
   Normalization is recursive and deterministic. Gantry MUST normalize nested
   primitive values, structs, enum payloads, result payloads, list items,
   tuple members, present option values, and decisions from outermost
   to innermost structure, preserving list and tuple order. It MUST apply each
   omitted optional field's declared default, or `None` when no default exists,
   at every nesting depth. A hook result becomes available to source execution
   only after the entire value has validated and normalized successfully; no
   partially normalized value may be observed.
<a id="GNT-8.3"></a>

3. A `List<T>` result is represented by a JSON array. Every array item MUST
   validate as `T`, and item order MUST be preserved. Gantry MUST derive an
   array schema with the schema for `T` as its `items` schema.
<a id="GNT-8.4"></a>

4. A `Tuple<T1, T2, ..., Tn>` result is represented by a JSON array with
   exactly `n` items. Each item MUST validate against its corresponding
   positional member type, and item order MUST be preserved. Gantry MUST
   derive a fixed-length JSON Schema array using `prefixItems`, `items: false`,
   and `minItems` and `maxItems` both equal to `n`.
<a id="GNT-8.5"></a>

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
   contents rather than a JSON value. RFC 8785 determines object-member order
   and number spelling at every canonical boundary; source declaration order
   remains semantically relevant only where this specification states it, such
   as struct traversal, schema `required` arrays, and ordered argument vectors.
   “Canonical strict JSON” elsewhere in this document means exactly the
   normalized Gantry value encoded by these RFC 8785 rules, not a second JSON
   format.

   A declared enum uses a strict tagged JSON object. A unit variant is
   `{"variant":"NAME"}`. A payload variant is
   `{"variant":"NAME","value":PAYLOAD}`. `variant` and `value` are the
   literal protocol property names; unit variants MUST reject `value`, payload
   variants MUST require it, and every variant object MUST reject additional
   properties. `Result<T, E>` uses the same representation with variant names
   `Ok` and `Err`, each requiring `value` of type `T` or `E`, respectively.
   `Decision` uses the exact `decision` and nonempty `rationale` object shape
   in Section 9. Operation identity is observability metadata and is not part
   of that JSON value. `OperationError` uses the same strict tagged encoding
   as an enum. Its first six variants carry their message as the JSON String
   `value`; `UnknownOutcome` carries a two-item JSON array containing operation
   ID and message. Because operation and entry result contracts cannot contain
   `OperationError`, this encoding is used only for source values, explicit
   operation inputs, journals, events, and diagnostics.
<a id="GNT-8.6"></a>

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
   schema rules: `Unit` uses `{"type":"null"}`; `Bool` uses
   `{"type":"boolean"}`; `Int` uses an integer
   schema with Gantry's inclusive exact bounds; `Float` uses a number schema
   with the inclusive decimal bounds shown below; `String` uses
   `{"type":"string"}`; `List<T>` uses an array with the schema for `T` in
   `items`; tuples use the exact fixed-array form in item 4; options use
   `anyOf` with `{"type":"null"}` first and the schema for `T` second;
   results, enums, and `OperationError` use strict `oneOf` branches; decisions
   use the exact schema in Section 9; and structs use the object rules in item
   7. A struct's
   `properties` object is keyed by exact field name, while its `required` array
   lists required fields in declaration order. RFC 8785 canonicalization, not
   source declaration order, determines serialized JSON object-member order.
   More precisely, schema generation recursively constructs one schema node
   for a type. `Unit` produces exactly `{"type":"null"}`. `Bool` produces
   exactly `{"type":"boolean"}`. `Int` produces
   exactly
   `{"type":"integer","minimum":-9007199254740991,"maximum":9007199254740991}`.
   `Float` produces exactly
   `{"type":"number","minimum":-1.7976931348623157e+308,"maximum":1.7976931348623157e+308}`.
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
   `{"oneOf":[PAYLOAD("Ok",T),PAYLOAD("Err",E)]}`. `OperationError`
   produces exactly one `oneOf` array containing `PAYLOAD(NAME,String)` for
   `Declined`, `InvalidOutput`, `ProviderFailure`, `Timeout`, `PolicyDenied`,
   and `Cancelled`, in that order, followed by
   `PAYLOAD("UnknownOutcome",Tuple<String,String>)`. This `OperationError`
   node is available for protocol and source-value schemas such as the result
   of `attempt`; Section 5 excludes it from a hook's declared output type, so
   it is never the expected schema sent for the underlying operation. A
   declared enum definition produces exactly one `oneOf` array whose branches
   follow source variant order, using `UNIT(NAME)` for a unit variant and
   `PAYLOAD(NAME,T)` for a payload variant.
   `Decision` produces exactly `DECISION_NODE` from Section 9, item 2, when
   nested as `NODE(Decision)`. A declared struct or enum
   type produces exactly `{"$ref":"#/$defs/KEY"}`, where `KEY` is that
   declared type's definition
   key. `NODE(T)` denotes recursive application of these rules; it is notation
   in this specification, not a protocol member.
   Every declared struct or enum reachable from the root result type by
   recursively following struct fields, enum payloads, and constructed-type
   members MUST have exactly one `$defs` entry. Reachability in this rule is
   type-graph reachability; it does not depend on package item order, runtime
   control flow, or whether a workflow that mentions the type can execute. Its
   definition key is the lowercase hexadecimal SHA-256 digest of the UTF-8
   canonical type descriptor from Section 5, and every occurrence of that
   declared type uses a local `$ref` to that entry. If two distinct canonical
   type descriptors reachable from one schema produce the same definition key,
   schema generation MUST fail with a `schema-identity-collision` analysis
   error rather than merge definitions, choose an implementation-specific key,
   or emit an ambiguous `$ref`. RFC 8785 canonicalization determines `$defs`
   object-member order from those definition keys. The root
   adds `$schema`, the complete reachable `$defs` object when nonempty, and
   either its own non-declared-type schema keywords or a `$ref` for a declared
   struct or enum result.
   No implementation-specific title, description, identifier, or annotation
   may be added to the expected protocol schema. The sole annotations are the
   field defaults required by item 7. These rules make the expected schema and
   its identity stable across conforming Gantry implementations.
<a id="GNT-8.7"></a>

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
<a id="GNT-8.8"></a>

8. v1 validation MUST check JSON shape and types, including enum and result
   discriminators, closed variant sets, fixed tuple arity, and the nonempty
   `Decision` rationale. It MUST also enforce the effective String and List
   resource limits outside the generated shape schema as specified in item 2.
   Additional constraints such as regular-expression patterns and semantic
   validity are conveyed through operation guidance rather than enforced by
   Gantry.
<a id="GNT-8.9"></a>

9. UTF-8 decoding failures, malformed JSON, schema-invalid output, and output
   exceeding the effective raw-byte, value-depth, value-node, String, or List
   resource limits MUST be returned to the integration as validation guidance
   and retried up to the configured retry limit. A retry request MUST include
   the preceding
   validation errors but MUST NOT return the preceding raw output to the hook.
   A validation retry is another physical dispatch of the same logical
   operation, not a reevaluation of the source expression. Gantry MUST reuse
   the selected agent, logical session, authored template, interpolated
   operation-specific request body, expected type and schema, base guidance,
   and canonical transcript from the initial dispatch.
   For a prompt or decide operation this includes the logical agent, session,
   canonical transcript, template, interpolation arguments, and named inputs;
   for an action it includes its canonical path, signature, recovery class,
   operation ID, and typed arguments. A non-idempotent action MUST have an
   effective retry limit of zero; a positive source override is an analysis
   error. Gantry MUST
   NOT reevaluate any captured input expression or observe intervening source
   state. Only the dispatch identity, validation-attempt number, applicable
   recovery-dispatch number, preceding validation errors, repair-specific
   rendering of those errors, and an agent- or action-mapping revision changed
   through the durable resume procedure in Sections 7 and 11 may differ. A
   validation retry made without such a recorded resume change MUST reuse the
   preceding dispatch's mapping revision. This rule keeps retries
   understandable as repairs of one visible operation rather than hidden
   additional program evaluations while preserving the explicit mapping-
   replacement contract for resumed work. Gantry MUST retain the original
   source location separately for diagnostics, journaling, and protected
   observability across every retry, but Section 7 prohibits placing that
   location in the hook request or semantic fulfillment input.
<a id="GNT-8.10"></a>

10. Interpreter configuration supplies separate default retry limits for model
   and action operations, and, subject to the non-idempotent-action restriction
   in item 9, an operation MAY override its applicable default.
   A retry limit counts retries after the initial attempt; zero permits exactly
   one attempt. Unless the embedder configures replacements, the v1 defaults are
   two retries for `prompt` and `decide`, and zero retries for `action`. An
   explicit operation-local `retry_limit` overrides the applicable configured
   default.
   Retry backoff MUST be configurable as an initial delay, a cap, and a jitter
   mode. Both durations are nonnegative whole-microsecond values, and the cap
   MUST be greater than or equal to the initial delay. The jitter mode is
   exactly `full` or `none`. For one-based retry number `r`, the delay ceiling
   is `min(initial_delay * 2^(r - 1), cap)`. Under `full`, the selected delay is
   sampled uniformly from the inclusive range of whole microseconds from zero
   through that ceiling. Under `none`, the selected delay is exactly the
   ceiling. Unless the embedder configures replacements, the v1 defaults are
   `initial_delay = 100 ms`, `cap = 2 s`, and `jitter = full`.
   The ceiling calculation uses saturating arithmetic: once doubling the
   initial delay would meet or exceed the cap, the ceiling is the cap for that
   and every later retry. An implementation MUST NOT construct an unbounded
   power or overflow an integer when `retry_limit` is large. An implementation
   MUST record the selected delay in the validation-attempt record before
   sleeping. If execution is interrupted before the corresponding retry
   dispatch is durably recorded, resume MUST wait the complete recorded delay
   again; it MUST NOT sample another delay.
   The effective retry limit, initial delay, cap, and jitter mode are bound to
   resumable execution as specified in Section 11.
<a id="GNT-8.11"></a>

11. When retries are exhausted, an enclosing `attempt` yields
   `OperationError::InvalidOutput`; without `attempt`, the current task fails
    with `structured-output-exhaustion`. `attempt` does not catch journal,
    executor, deterministic-evaluation, event-persistence, or invariant
    failures. Parallel propagation follows Section 10.
<a id="GNT-8.12"></a>

12. Transport failures and their retry policy are integration concerns, not
   Gantry structured-output retries.
<a id="GNT-8.13"></a>

13. Source snippets MAY be included in validation diagnostics only when the
   embedder's diagnostic-disclosure policy explicitly permits source text for
    that consumer. The default policy MUST report source spans without copying
    source snippets. Raw integration output MUST NOT be included in validation
    diagnostics under any disclosure policy.

## 9. Control Flow

<a id="GNT-9.0"></a>

This section separates deterministic routing from model judgment and defines
finite iteration, explicit source limits, and mandatory execution budgets.

<a id="GNT-9.1"></a>

1. `if` and `else if` conditions MUST have type `Bool` or `Decision`; a
   `Decision` uses its visible `decision` field. `if let` and `match` inspect
   tagged structure deterministically. Conditions and scrutinees are evaluated
   once, left to right, and only explicit operation sites dispatch hooks.

<a id="GNT-9.2"></a>

2. A successful `decide` returns exactly
   `{"decision":BOOL,"rationale":STRING}`, with a nonempty rationale and no
   additional properties. Define `DECISION_NODE` as exactly the following
   schema object without a `$schema` member:

   ```json
   {
     "type": "object",
     "properties": {
       "decision": { "type": "boolean" },
       "rationale": { "type": "string", "minLength": 1 }
     },
     "required": ["decision", "rationale"],
     "additionalProperties": false
   }
   ```

   The root `Decision` schema is exactly that object plus
   `"$schema":"https://json-schema.org/draft/2020-12/schema"`. The schema is
   canonicalized under Section 8 before hashing or transport; the presentation
   whitespace above is not part of its canonical bytes. `Decision` values
   carry only the two visible fields; their originating operation identity
   belongs to logical-trace observability.

<a id="GNT-9.3"></a>

3. Conditional and match arm selection is deterministic after the controlling
   value is available. Analysis MUST reject unreachable or duplicate match arms
   and prove exhaustive coverage of `Option`, `Result`, declared enums, and
   tuple products unless a final irrefutable arm covers the remainder. Branch
   outcomes and rationales MAY be journaled and emitted as protected logical
   trace, but MUST NOT become implicit input to a later hook.

<a id="GNT-9.4"></a>

4. Gantry supports `loop`, pre-test `while`, post-test `until`, and finite `for
   NAME in EXPRESSION`. `until { BODY } when CONDITION;` executes its body
   before the first condition. After its condition evaluates, `true` completes
   the loop normally and `false` proceeds toward another body entry, subject
   to the cancellation, limit, budget, and session-establishment rules in this
   section. A `for` expression is evaluated once, MUST have
   type `List<T>`, and iterates a deep snapshot in ascending index order with a
   fresh immutable `NAME: T` binding per item. Empty lists execute no body.
   `break`, `continue`, and `return` have their ordinary nearest-target rules;
   `continue` in `until` proceeds to its post-test and in `for` proceeds to the
   next snapshot item.

<a id="GNT-9.5"></a>

5. `loop`, `while`, and `until` accept `session` and optional `limit`
   modifiers. Omission means no source-level limit; authors MAY write `limit =
   unbounded`
   explicitly. A numeric limit MUST be positive and no greater than `2^63-1`;
   `limit = 0` is an analysis error. The limit counts body entries. Attempting
   another body after the limit is exhausted fails with deterministic code
   `loop-limit-exhausted`; it is never normal completion. `break` remains
   normal completion. `for` needs no source limit because its snapshotted list
   is finite, but it still consumes the mandatory execution budgets.

<a id="GNT-9.6"></a>

6. Loop session behavior is `inline` by default. For `while(session = fork)`,
   Gantry creates and durably records one child session before each condition
   evaluation; that condition and its body, when admitted, share the child.
   A false condition therefore leaves one recorded session with no body entry.
   For `until(session = fork)`, Gantry creates the child before each body entry,
   and that body and its following condition share the child. For
   `loop(session = fork)`, Gantry creates the child before each body entry.
   For `until` and `loop`, a limit or budget check that rejects a prospective
   body entry occurs before that entry's child session is created. For `while`,
   the child already exists because its condition must use that session; if a
   true condition is followed by a limit or budget failure, no body is entered
   but the recorded child remains. `new` creates and durably records one empty
   session on loop entry and reuses it for every condition and body. `inline`
   allocates no loop session. Operation-local session modifiers override only
   that operation. These creation points determine transcript lineage,
   operation identity context, establishment ordering, and resume behavior.

<a id="GNT-9.7"></a>

7. Every execution MUST enforce identity-bound positive budgets for
   deterministic transitions, logical operations, and loop body entries. A
   deterministic transition, the `M-Prepare` transition defined in Section
   3.5, or body entry
   decrements its corresponding durable counter before the transition becomes
   observable. Exhaustion fails with `deterministic-transition-budget`,
   `operation-budget`, or `loop-iteration-budget`, respectively, in the
   `deterministic-evaluation-failure` category. Budgets apply even to source
   marked `unbounded`, are restored exactly on resume, and MUST NOT be converted
   into normal loop completion or caught by `attempt`. Input evaluation before
   `M-Prepare` does not consume the logical-operation budget. Validation
   retries and recovery redispatches remain transitions of the same prepared
   logical operation and MUST NOT consume that budget again.

<a id="GNT-9.8"></a>

8. Routing operators do not dispatch hooks. `==` and `!=` require identical
   equatable types and perform exact deep equality. `Decision` and aggregates
   containing it are non-equatable. A statement-form `match` has statement
   blocks; discarding a value-producing `match` requires explicit `discard`.

<a id="GNT-9.9"></a>

9. Model decisions use the ordinary structured-output retry and recovery rules.
   Deterministic `Bool` conditions have no schema, rationale, retry budget, or
   model-visible context unless their evaluation explicitly executes an
   operation.

<a id="GNT-9.10"></a>

10. A function or method declared with result type `Decision` MUST yield or
    explicitly return one on every reachable normal path. Only `decide` can
    originate a new value, but a workflow may forward a `Decision` parameter
    or binding without model work. Discarding a newly evaluated decision
    requires `discard decide ...;` or `discard workflow(...);`; discarding a
    retained value performs no operation.

<a id="GNT-9.11"></a>

11. Static control-flow analysis treats every model-produced decision and every
   nonliteral `Bool` as capable of both outcomes. Only `true`, `false`,
    parentheses, and `!`, `&&`, or `||` composed solely from those literals are
    compile-time Boolean facts. Pattern irrefutability and ordered coverage are
    the only compile-time basis for removing structural paths. A `while` may
    execute zero bodies, `until` executes at least one, and `for` may execute
    zero or more because list length is not generally a compile-time fact.
    Budget exhaustion is abnormal and cannot satisfy definite-return or linear
    handle analysis. Every syntactic branch or match arm is still analyzed for
    local name, type, control-flow, ownership, schema, and modifier validity,
    even when a compile-time fact excludes it from the enclosing completion
    merge. Such an arm is not rejected merely because the fact excludes it.
    Within one block, however, a statement or trailing expression that follows
    an unconditional `return`, `break`, `continue`, or another command with no
    reachable normal completion is an unreachable-source analysis error. This
    is the reachability rule used by `GNT-3-T-SEQUENCE`; Gantry performs no
    broader dead-code inference in v1.

<a id="GNT-9.12"></a>

12. Evaluation observes cancellation before every condition, body entry, for
   item binding, and back edge. Deterministic budgets complement cancellation;
    they do not weaken cooperative yield or task-cleanup requirements.

## 10. Parallel Execution

<a id="GNT-10.0"></a>

This section defines attached structured tasks and explicit durable background
work. `spawn` creates one owned attached handle. `join` and `joinall()` are
all-settled operations: they consume their selected attached handles and wait
for every selected child before returning values or an aggregate failure.
`detach` leaves structured concurrency by visibly transferring lifetime and
failure ownership to execution-scoped background work. Detached work may
outlive lexical parents, foreground completion, and an interpreter process and
MUST NOT be described as a structured child after transfer.

<a id="GNT-10.1"></a>

1. Gantry MUST support Unit spawn declarations of the form `spawn <name> {
   ... }`, value-producing spawn declarations of the form `spawn <name> ->
   <type> { ... }`, joins of the form
   `join(<task-name>, ...)`, `joinall()`, and explicit detachment of the form
   `detach(<task-name>);`.
<a id="GNT-10.2"></a>

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
   created the work. One execution MUST create no more than the configured
   `maximum_tasks_per_execution`, counting the root task and every distinct
   child task occurrence durably created during that execution, including
   children that have already settled. This cumulative definition is
   independent of executor timing and is recoverable from the journal. Gantry
   MUST fail the spawning task with a `task-count-limit` deterministic-
   evaluation runtime error before creating a child whose occurrence would
   exceed the limit. No task identity, session, hook, task-state record, or
   executor submission is created for that rejected child. Before submitting
   an admitted child to the executor or invoking its `HookFactory`, Gantry MUST
   commit task-creation evidence containing
   the child's stable task identity, parent identity, source spawn occurrence,
   copied captures, inherited agent selection, and forked-session identity. The
   record MAY also contain structural ancestry for protected observability,
   but that metadata MUST NOT be presented to later operation fulfillers. The
   handle becomes visible to the parent only after that record is durable. This
   ordering prevents a child from performing model-backed work that recovery
   cannot identify. If executor submission then fails, the child MUST settle as
   failed with an executor error; Gantry MUST commit that settlement
   before the parent can observe it. The handle remains attached and visible,
   and its owner MUST still consume it through `join`, `joinall()`, or `detach`
   on every normal path. Recovery MUST reuse the durable failed settlement and
   MUST NOT submit a second child for the same spawn occurrence. If Gantry
   cannot durably record the submission failure, the execution instead fails
   with the journal error under Section 11.
<a id="GNT-10.3"></a>

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
<a id="GNT-10.4"></a>

4. A spawned block that yields information MUST declare its result type with
   `-> T`. Omitting the annotation declares a Unit block; writing `-> Unit` is
   the explicit equivalent. Every reachable normal completion of a value-
   yielding block MUST produce exactly `T` through its trailing expression or
   a task-local `return`. A Unit block MAY fall through, return `()`, or use
   `return;`, but MUST NOT return a non-Unit value. `spawn` declares the named handle
   but does not itself yield the handle as a value. A spawn boundary is also a
   control-transfer boundary: a `return` whose nearest return target is the
   spawned block completes only that child task. `break` or `continue` inside a
   spawned block MUST NOT target a loop outside that block. Transfers wholly
   contained in a workflow or loop entered within the child remain valid.
<a id="GNT-10.5"></a>

5. `join(task)` waits for one named child and yields that child's typed block
   value. A join result MAY be bound as `let result: T = join(task);`. Joining
   a Unit block is a waiting statement and yields `()`. Every admitted join
   consumes each selected task handle durably before waiting; consumption is
   not rolled back when a child or aggregate join fails. Every task handle MAY be joined at most once;
   repeated handles in one join, joins of already consumed handles, and uses of
   handles that may have been consumed on an incoming control-flow path are
   analysis errors. `join()` with no task names is invalid.
   A join of two or more named children waits for every named child and yields
   an ordered `List<T>` of their successful block values in argument order when
   every joined task has the same non-`Unit` result type. When two or more named
   tasks have non-`Unit` result types that are not all exactly equal, it yields
   `Tuple<T1, T2, ..., Tn>`, whose positional types and values follow argument
   order. When every named task returns `Unit`, the join is a waiting statement
   with `()`. Mixing value-producing and Unit tasks in one
   named join is an analysis error; Gantry MUST NOT silently discard selected
   values merely because another named task returns `Unit`. Every named join
   waits until every named task settles even after a failure. Before waiting,
   Gantry MUST commit task-ownership evidence that identifies
   the join form, source location, named handles in argument order, and their
   transition from attached to consumed-by-join. Only then are the handles
   consumed. This transition includes handles for successful tasks in a join
   where another task fails. After settlement, Gantry MUST commit the ordered
   result, successful Unit settlement, or aggregate failure before returning
   it to source execution.
   Consuming a handle for a join changes its source-level ownership state but
   does not detach the child: until it settles, the child remains an attached
   descendant for cancellation and cleanup under items 10 and 14.
   Failures abort the current Gantry task with one aggregate
   `task-join-failure` runtime error
   ordered by join argument, never by completion time. A failed single-task
   join likewise consumes its handle durably and fails the current Gantry task
   with `task-join-failure`. Propagation beyond that task follows Section 7
   rather than implicitly aborting unrelated parallel work.
<a id="GNT-10.6"></a>

6. `joinall()` is the scope-oriented form for joining every unconsumed,
   attached task handle that is owned by the current Gantry task, declared
   directly in
   the current lexical scope, and definitely available at the `joinall()`
   expression's program point. It excludes later declarations, tasks declared
   in nested scopes, tasks owned by another Gantry task, and tasks explicitly
   detached before the join. It consumes all included handles, waits until all
   included tasks have settled, and yields one included task's declared result
   type when exactly one task is included and that task has a non-`Unit`
   result. With two or more included tasks, every task MUST either have a
   non-`Unit` result or every task MUST return `Unit`. When all have non-`Unit`
   results, `joinall()` yields an ordered `List<T>` in task declaration order
   if the result types are exactly equal, and otherwise yields a positional
   tuple in task declaration order. When every included task returns `Unit`,
   `joinall()` waits and yields `()`. Mixing value-producing
   and Unit tasks in one `joinall()` is an analysis error; Gantry MUST NOT
   silently discard the value-producing results merely because another task
   returns `Unit`. With zero included tasks, `joinall()` is a Unit no-op.
   Semantic analysis MUST
   determine the included handle set and resulting type at that program point.
   Analysis computes that set as follows: start with spawn declarations whose
   declarations are direct children of the current lexical block and precede
   the `joinall()`; remove a handle only when every incoming path has already
   consumed it by `join` or `detach`; reject the program when consumption
   differs across incoming paths. Declarations inside an `if`, loop, `match`,
   `with`, `session`, or nested spawn block belong to that nested block and are
   never members of an enclosing block's `joinall()`. Runtime completion order
   never adds, removes, or reorders members.
   Because `Unit` is first-class, a Unit `joinall()` MAY be bound, returned, or
   used as a trailing expression, although a bare `joinall();` is conventional.
   `joinall()` MUST NOT stop waiting merely because one task fails.
   After all tasks settle, one or more failures MUST fail the current Gantry
   task with one aggregate `task-join-failure` runtime error. That error MUST
   report failed tasks in source declaration order, not completion order.
   Propagation beyond the current task follows Section 7. At a `joinall()`, every task
   handle declared directly in that scope MUST have one definite ownership
   state on all incoming control-flow paths. A handle that is consumed or
   detached on only some incoming paths is an analysis error rather than a
   conditionally included `joinall()` member.
   Before waiting, a nonempty `joinall()` MUST commit the same consumed-by-join
   task-state transition required for a named join, listing included handles
   in declaration order. Its ordered result or aggregate failure MUST likewise
   be committed before source execution consumes it. A zero-task `joinall()`
   requires no ownership evidence.
<a id="GNT-10.7"></a>

7. A child failure does not immediately cancel siblings. A named child's
   failure is deferred until `join`; a scoped failure is deferred until
   `joinall()`.
<a id="GNT-10.8"></a>

8. `detach(task)` consumes one attached task handle and transfers foreground
   ownership to Gantry on behalf of the task's originating execution and
   journal, without waiting for it. That ownership is durable execution state,
   not state tied to the lifetime of the current interpreter instance; an
   unfinished detached task is recovered by a later execution owner under
   Section 11. Detaching an
   already consumed handle is an analysis error. An attached, unconsumed task
   at lexical scope exit is an analysis error; v1 never detaches work
   implicitly. Detached tasks and nested spawns are permitted, and a top-level
   execution MAY report foreground success while detached tasks continue.
   Requiring an explicit `detach` keeps background execution visible to humans,
   agents, analysis, and recovery tooling.
   Before releasing the child from parent cancellation constraints or allowing
   the enclosing scope to continue, Gantry MUST commit task-ownership evidence
   that identifies the source `detach`, child task, previous owner, and
   transition to interpreter-owned detached work. Failure to commit that
   transfer is a journal failure; the task remains attached for cancellation
   and cleanup purposes.
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
<a id="GNT-10.9"></a>

9. A detached-task failure MUST be journaled and emitted as a failure event. It
   MUST NOT abort foreground execution or change an already returned foreground
   outcome, regardless of whether it settles before or after that outcome is
   returned. It does, however, make the eventual terminal execution category
   `detached-task-failure` unless a durably recordable execution-wide runtime
   error takes precedence under this item. For this rule, an
   **execution-wide runtime error** is one that another normative requirement
   applies to the complete execution rather than to one Gantry task. In v1,
   `journal-failure` and `required-event-delivery-failure` are execution-wide;
   ordinary hook, structured-output, deterministic-evaluation, executor, and
   `task-join-failure` errors remain task-local unless a more specific rule
   propagates them. Journal failure aborts the current in-process run but is
   not a durable terminal category: after storage fails, Gantry cannot commit
   the terminal evidence that would establish one. It is returned separately to
   the embedder, and a later owner may resume from the authoritative durable
   prefix under Section 11.
   A detached task cannot subsequently be joined because `detach` consumes its
   handle. These rules make explicit detachment a deliberate transfer of both
   lifetime and failure ownership to the originating execution.
   A detached-task failure MUST NOT cancel sibling detached tasks. Terminal
   execution state is determined after all detached work settles. Before the
   terminal-execution record is durable, a durably recordable execution-wide
   runtime error other than an execution-cancellation request is the primary
   terminal category and includes detached failures as secondary details. If
   more than one such execution-wide runtime error races,
   the first one in durable journal-sequence order is primary and later errors
   are secondary. A failure after the terminal-execution record is durable
   MUST NOT replace its category; in particular, Section 12 reports later
   required-delivery exhaustion as a separate barrier failure. Otherwise, a
   failed foreground task produces its runtime-error category as the terminal
   category and includes detached failures as secondary details. Otherwise,
   one or more detached failures produce the
   `detached-task-failure` terminal category; otherwise, a cancellation
   produces the `cancellation` category; and only then is the terminal category
   `success`. Multiple detached failures MUST be reported in stable task-path
   order, using source spawn location and dynamic spawn occurrence rather than
   completion time.
<a id="GNT-10.10"></a>

10. Cancellation constraints inherited from a parent apply while a child
   remains attached and propagate through its attached descendants. Detachment
   releases the task from those parent cancellation constraints. Integration-
   specific operation timeouts and provider-specific cancellation policy MAY
   still apply, but
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
    cancellation drain, Gantry MUST commit the outcome for audit but
    mark it cancelled and non-consumable; it MUST NOT validate-retry, assign,
    branch on, return, or reuse that outcome to continue the cancelled task.
    A durably cancelled task is terminal and MUST NOT later be resumed as an
    interrupted task. If executor abortion prevents a hook outcome from being
    observed, Gantry MUST durably record cancellation of the indeterminate
    dispatch rather than redispatch it on resume. These rules make cancellation
    win deterministically over a racing hook completion.
    The commit requirements in this paragraph apply only while the journal
    remains usable. When journal failure is the initiating error, Gantry MUST
    NOT attempt additional commits through the failed
    storage path. It MUST discard late in-process hook outcomes after making a
    best effort to stop the work, MUST NOT consume them, and MUST NOT claim
    that the affected tasks are durably cancelled. A later owner recovers only
    the authoritative durable prefix and may consequently redispatch an
    invocation that remained indeterminate there, as required by Section 11.
<a id="GNT-10.11"></a>

11. Gantry MUST schedule spawned blocks through the executor supplied by the
   embedding application. The integration determines executor queueing and
    provider-internal limits, including operation timeouts. Gantry's configured
    language and protocol resource limits remain governed by Sections 3, 8,
    10, 11, and 15 and MUST still be enforced at their specified boundaries.
<a id="GNT-10.12"></a>

12. The embedding API MUST provide a terminal asynchronous shutdown operation.
   The embedder MUST configure a finite graceful-shutdown timeout; indefinite
    shutdown is not the v1 default. Shutdown MUST reject new executions and
    allow every interpreter-owned foreground execution and detached task to
    finish naturally until the timeout expires. It MUST then signal
    cancellation to all remaining work, abort tasks that do not finish within
    a bounded drain period, commit pending journal and required event state,
    and return
    a shutdown report covering every execution and detached task that was
    active when shutdown began. After that report's task and journal content is
    fixed, and while the executor adapter and event sinks remain available,
    Gantry MUST create exactly one final interpreter-wide `shutdown` event for
    that completed shutdown invocation and satisfy the required-sink barrier
    in Section 12. This event is interpreter-scoped, non-resumable activity: it
    has no execution journal, and its delivery state is retained in memory
    only for the lifetime of the shutdown invocation. If the process is
    interrupted before shutdown returns, Gantry makes no claim that the event
    or its deliveries completed; a later interpreter does not recover or
    recreate that interrupted interpreter's shutdown event. Before shutdown
    returns, every finite best-effort delivery obligation already owned by the
    interpreter, including obligations for that final event, MUST also reach
    success or terminal exhaustion under its captured policy. Journaled
    settlements MUST be durable, release MUST have been attempted for every
    execution-journal owner, and no delivery worker may remain dependent on the
    terminal interpreter. If every release succeeds, shutdown returns an
    orderly result. If a release fails, shutdown returns a non-orderly
    `release-failed` result with that owner retained as unreleased under
    Section 11. A delivery-barrier failure or best-effort exhaustion summary is
    reported separately from the task and execution outcomes already fixed in
    the shutdown report. An interpreter cannot be reused after shutdown begins.
    Embedders MUST complete shutdown before dropping the interpreter.
<a id="GNT-10.13"></a>

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
<a id="GNT-10.14"></a>

14. The embedding application MUST be able to request cancellation of one
   execution without shutting down the interpreter. Execution cancellation
    targets the foreground task plus every attached and detached descendant
    owned by that execution. When the journal remains usable, Gantry MUST
    commit the cancellation request before signalling task tokens,
    reject new task and hook dispatch for the execution, apply the configured
    post-cancellation drain and abortion behavior from item 10, and durably
    record the resulting terminal state before reporting completion. The
    terminal category MUST follow the precedence in item 9: it is
    `cancellation` unless a foreground failure, detached-task failure, or
    durably recordable execution-wide runtime error already takes precedence.
    Repeating a cancellation request is idempotent; requesting cancellation of
    an already terminal execution returns its existing terminal state without
    changing it. A journal failure while recording cancellation takes
    precedence and is reported under Section 11. Cancellation of one execution
    MUST NOT cancel unrelated executions owned by the same interpreter.

## 11. Durable Execution and Resume

<a id="GNT-11.0"></a>

Items 1 through 5 define durable commit boundaries for interpreter and hook
state. Items 6 through 9 define package identity, migration, recovery, and
logical evidence envelopes. Item 10 defines execution-start state and the
configuration fields that are immutable or durably revisable across resume.
Item 11 clarifies the boundary between resumption and replay.

<a id="GNT-11.1"></a>

1. The durable profile MUST commit a causally closed prefix of the abstract
   transitions in Section 3. Before source execution or an external observer
   can
   depend on a transition, durable state MUST establish its label, identities,
   continuation, values, linear handle state, session transcripts, remaining
   budgets, and causal predecessor. A transition and its canonical event MAY be
   committed atomically. Dedicated operation, task, session, checkpoint, event,
   and terminal schemas are logical evidence types, not a requirement to write
   duplicate physical rows. An implementation MAY batch labels, use atomic
   transactions, snapshot a prefix, group-commit concurrent tasks, or compact
   old evidence when retained identities and protected references remain
   resolvable. Recovery MUST reconstruct exactly one causally closed prefix,
   never consume an uncommitted operation result, and never apply one logical
   ownership or mutation transition twice.
<a id="GNT-11.2"></a>

2. Gantry MUST expose durable-prefix reading, exclusive fenced ownership,
   atomic commit, and owner release. `commit(batch)` atomically assigns a
   contiguous sequence range and stable evidence IDs, stores one or more
   logical evidence envelopes, and establishes durability before returning.
   A storage adapter MAY implement this as an append log with a durability
   barrier, one transaction, a snapshot-plus-log update, or an equivalent
   primitive. Concurrent commits are
   linearizable; the first sequence is one and there are no committed gaps.
   A durable read MUST identify a journal and return its authoritative committed
   prefix in strictly increasing sequence order, optionally beginning after a
   caller-supplied sequence number. It MUST also report the greatest sequence
   known durable. Records physically present beyond that durability watermark
   MUST NOT be returned as committed state or used during resume. A duplicate
   sequence, a gap within the returned durable prefix, a changed record for an
   already observed sequence, or a record whose envelope identifies another
   journal is a journal failure. These read semantics are required for resume;
   they do not add another storage mutation primitive. Before committing after
   recovery, storage MUST discard or otherwise make unreachable every
   physically present record beyond the durability watermark, and the next
   committed sequence MUST be the watermark plus one. This reconciliation is an
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
   ownership generation. Every commit MUST be authorized by the current token,
   and storage MUST reject an operation from a superseded owner. Concurrent
   tasks belonging to the current owner MAY commit through the
   storage's linearizable ordering, but starting or resuming a second owner for
   the same journal while the first is active MUST be rejected before hook or
   task dispatch. After an unclean process loss, the embedder and storage MAY
   reclaim ownership only after establishing that the preceding owner can no
   longer successfully commit; granting the new fencing token MUST
   make that guarantee atomic. Read-only inspection MAY remain concurrent.
   An orderly owner release MUST atomically invalidate that owner's token so
   every later commit using it fails. Gantry MUST release ownership
   after an execution reaches terminal durable state and every required and
   best-effort event-delivery obligation created through its terminal event has
   settled durably. Returning a terminal result waits only for the required
   delivery barrier in Section 12; finite best-effort delivery MAY continue
   afterward while the current interpreter retains journal ownership. An
   orderly interpreter shutdown is stricter: Section 10 requires every such
   finite obligation to settle and every journal-owner release to be attempted
   before shutdown returns. A failed attempt produces the non-orderly
   `release-failed` shutdown result defined there. Gantry MUST also release
   ownership after a start or resume-start failure when ownership was acquired
   but interpretation never began.
   Release failure is a journal failure after execution has begun. A start or
   resume-start invocation that has not advanced durable execution state MUST
   instead include ownership-release failure in its structured pre-execution
   result and leave later acquisition to the storage's fencing rules. These
   ownership operations coordinate access and do not add a mutation primitive
   for journal records themselves.
   If release fails after a terminal result has already been returned, the
   durable language outcome and its delivery-barrier status remain unchanged.
   Gantry MUST retain the owner as unreleased, report the failure through the
   execution's journal-owner status and the shutdown report, and MAY invoke the
   bounded emergency diagnostic callback from Section 15. It MUST NOT emit an
   undurable standard event or claim successful orderly shutdown. A later owner
   can proceed only through the storage fencing and recovery rules above;
   Gantry MUST NOT assume that a failed release invalidated the token.
<a id="GNT-11.3"></a>

3. A hook dispatch MUST be committed before the hook is invoked. Its dispatch
   evidence MUST preserve the complete versioned hook request separately from
   nonsemantic observability metadata. The hook request includes the
   operation-specific body, operation and result kinds, captured inputs,
   schema, guidance, canonical transcript when applicable, validation state,
   and logical identities defined in Section 7. Source location and protected
   trace metadata MAY be retained alongside it for diagnostics and
   observability, but they are not semantic request fields and MUST NOT be
   supplied to the fulfiller. Prompt and decision evidence MUST preserve their
   selected agent, mapping revision, templates, interpolation arguments,
   named inputs, and session fields. Action evidence MUST preserve its
   canonical action path and signature, action-mapping revision, and typed
   arguments.
   Protected or repeated payloads MAY be stored by stable reference, but those
   references MUST resolve from the same durable journal. A recovery
   redispatch MUST reuse the committed hook-request fields except for the
   physical-dispatch fields and the applicable agent- or action-mapping
   revision explicitly allowed to change by Section 7. It MUST retain all
   committed operation inputs, schema, guidance, and validation state. A model
   operation also retains its logical agent and session; an action retains its
   canonical path and signature. Observability metadata MAY be reused but MUST
   remain outside the hook request. The new dispatch ID and incremented
   recovery-dispatch number MUST differ, and the request MUST carry the
   applicable mapping revision recorded for the resume run. No other semantic
   hook-request field may change.
   A durable dispatch record represents a prepared physical dispatch attempt;
   it does not prove that the hook future began polling or that the integration
   observed the request. There is no portable atomic boundary between durable
   preparation and entry into integration code. Consequently, a prepared
   attempt with no committed outcome is indeterminate under item 4 even when
   interruption may have happened before the hook began.
   After a hook returns a valid host-level outcome under Section 7, item 11,
   Gantry MUST commit the outcome before the interpreter validates, assigns,
   branches on,
   returns, or otherwise consumes it. An invalid `Declined` reason or `Failed`
   message is a hook-contract violation rather than an operation outcome and
   follows the bounded hook-failure rule in Section 7, item 11. Commitment at
   this boundary means that the physical hook outcome is durable; it does not
   mean that
   `Completed(raw_output)` has passed UTF-8 decoding, JSON parsing, schema
   validation, or normalization.
   On resume, Gantry MUST continue deterministic processing of that committed
   outcome and MUST NOT redispatch it solely because validation or
   normalization had not completed before interruption. This ordering ensures
   recovery either reuses the committed outcome or treats the dispatch as
   indeterminate; program state MUST NOT advance using an outcome that is not
   yet durable.
<a id="GNT-11.4"></a>

4. A prepared dispatch with no committed outcome is indeterminate. On resume,
   `prompt`, `decide`, and `read_only` or `idempotent` actions are redispatched
   with the same operation ID, captured semantic request, validation-attempt
   number, and remaining retry budget, plus a new dispatch ID and incremented
   recovery-dispatch number. An `idempotent` handler MUST deduplicate by the
   operation ID. An indeterminate `non_idempotent` action is never
   redispatched: it becomes `OperationError::UnknownOutcome` under `attempt` or
   fails with `unknown-action-outcome`. This distinction is durable and cannot
   be changed by a later integration mapping.
<a id="GNT-11.5"></a>

5. A consumable logical result derived from a committed `Completed` outcome
   MUST be committed before source execution may assign, branch on, return, or
   otherwise consume it. The logical evidence identifies the operation,
   outcome, result kind, canonical type descriptor, normalized canonical JSON,
   and accepted decision fields when applicable. `Unit` records canonical JSON
   `null` and produces `()`. Decline and failure produce no operation-result
   value; `attempt` instead commits its explicit `OperationError` result.
   Committed logical results and committed failed validation attempts are
   reused on resume and never consume a retry budget twice.
<a id="GNT-11.6"></a>

6. An execution MUST identify a versioned canonical core IR, its source map,
   and the journal schema version. The execution package identity is the
   SHA-256 digest of canonical core IR bytes under the published IR schema.
   Canonical IR contains resolved item paths, types, effects, desugared control
   flow, static operation and task sites, and modifiers, but excludes comments,
   whitespace, physical file paths, line endings, and diagnostic spans. The
   durable execution record MUST retain the exact canonical IR and source map,
   or a content-addressed reference through which the embedding can retrieve
   their exact bytes and verify the recorded identity. Missing, unavailable, or
   mismatched recovery artifacts are a
   `source-or-configuration-incompatibility` resume-start failure. Gantry SHOULD
   retain the original immutable source snapshot by content address for audit,
   but cosmetic source changes do not prevent resume when they lower to the
   same canonical IR identity.

   If a new package has a different IR identity, resume MUST reject it unless
   the caller supplies an explicit versioned migration accepted by the
   embedding API. A migration maps old core continuation points, static sites,
   value schemas, session transcripts, task ownership, and remaining budgets
   to the new IR. It MUST be deterministic, side-effect-free, schema-validated,
   and durably committed with old and new identities and a migration ID before
   recovered execution advances. It MUST NOT alter committed outcomes,
   resurrect consumed handles, reset budgets, or map an indeterminate
   non-idempotent action to a redispatchable state. Failure leaves the old
   execution prefix unchanged and is `source-or-configuration-incompatibility`.
<a id="GNT-11.7"></a>

7. Recovery MUST restore scopes, instruction positions, call frames, loop
   counters, task relationships, and committed values. Each task, including an
   in-flight spawned block, MUST resume from its latest durable instruction
   position. When Gantry replays deterministic steps after the latest durable
   checkpoint, it starts at that checkpoint's instruction position rather than
   unconditionally restarting the task body. Such replay MUST reuse committed
   operation results, and uncommitted operations are retried under item 4.
   Deterministic replay of `spawn`, `join`, `joinall()`, or `detach` MUST
   consult the durable task-state history before changing task ownership. A
   replayed `spawn` occurrence MUST recover its existing stable child task and
   MUST NOT create a duplicate child. A replayed join or detach whose ownership
   transition is already durable MUST recover that transition and its committed
   result or failure rather than consume the handle again. Task identities and
   lifecycle records MUST therefore be keyed by the same logical task and
   canonical core-occurrence path used by dynamic operation identity.
<a id="GNT-11.8"></a>

8. A detached task remains part of its originating execution and journal after
   foreground `main` returns. Foreground completion, detachment, detached-task
   completion, and detached-task failure MUST each be durable states. Resuming
   an execution with unfinished detached tasks MUST recover them under the
   same rules as other in-flight spawned blocks. An execution reaches its
   terminal durable state only after its foreground and every detached task
   have completed, failed, or reached durable cancellation under Section 10.
   Before returning
   a foreground result, Gantry MUST commit interpreter checkpoint evidence
   that makes the corresponding scopes, instruction positions, task ownership,
   and completed values durable. Once all foreground and detached work has
   settled, Gantry MUST commit exactly one terminal-execution evidence envelope
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
<a id="GNT-11.9"></a>

9. The journal protocol MUST publish stable versioned schemas for the logical
   evidence kinds: execution and migration state, session transcript state,
   operation dispatch/outcome/validation/result, abstract interpreter
   transition or checkpoint, task ownership and settlement, event and delivery
   state, and terminal execution. Each envelope identifies journal, execution,
   contiguous sequence or snapshot frontier, stable evidence ID, kind, causal
   predecessors, applicable task and operation IDs, and a kind-specific payload.
   Unknown required fields, unsupported major versions, dangling causal
   references, or incompatible payloads are journal-format failures. Physical
   storage MAY combine logical envelopes in an atomic batch or materialized
   snapshot; it MUST reproduce the same authoritative logical prefix to a
   durable reader.
<a id="GNT-11.10"></a>

10. A new-execution request MUST identify a fresh journal target through an
   embedder-supplied stable journal ID. Allocation and naming of that target
    are integration concerns outside the `JournalStorage` mutation interface.
    After exclusive ownership is acquired, the target's authoritative durable
    prefix MUST be empty, its durability watermark MUST be zero, and its next
    committed sequence MUST be one. A nonempty target is an initial-
    journal-ownership start failure; Gantry MUST NOT overwrite it, commit a
    second execution start, or reinterpret it as the requested new execution.
    The embedder retains the journal target identity even when startup fails so
    it can inspect an uncertain storage outcome or resume by journal identity
    if an execution-start record became durable before an error was observed.

    For each new execution, after entry validation and integration preflight
    succeed but before evaluating `main`, creating a child task, or dispatching
    a hook, Gantry MUST allocate a fresh execution ID and commit exactly one
    execution-start evidence envelope as the journal's first logical item. That
    record MUST have sequence number one and MUST contain the package source
    identity, the selected source-language major and minor version, the
    effective-configuration identity and fields defined below, the selected
    root-session identity, provenance, and normalized canonical transcript,
    each applicable agent- or action-mapping revision from Section 7, the
    canonical signature of `main` defined in Section 4, and
    either a no-entry-input marker or the validated and normalized canonical
    entry value with its type descriptor.
    Resume MUST verify and reuse the existing execution-start record, restore
    its entry value, and MUST NOT commit a second execution-start record or
    accept replacement entry input. An agent- or action-mapping revision
    changed during resume MUST instead be committed as execution-state
    evidence before recovered interpretation or dispatch
    continues.

    The effective-configuration identity is the SHA-256 digest of the RFC 8785
    JSON Canonicalization Scheme encoding of the following canonical object
    shape. Property names and enum strings shown here are normative. Protocol
    version components are JSON numbers. Every other integer-valued field is a
    canonical unsigned decimal string with no sign or leading zero except the
    value `0`; this avoids loss of precision in RFC 8785 implementations whose
    JSON number domain is IEEE 754 binary64.
    Durations are represented as whole microseconds, identities are JSON
    strings, and no additional properties participate in the v1 identity.
    Unless a narrower bound is stated below, every decimal-string integer in
    this object MUST be no greater than `2^63 - 1`. This bound applies to retry
    limits, retry-backoff durations, and event-delivery attempt timeouts as
    well as to the resource limits described below:

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
        "maximum_entry_input_bytes": "16777216",
        "maximum_hook_output_bytes": "16777216",
        "maximum_value_nesting_depth": "256",
        "maximum_value_nodes": "1048576",
        "maximum_string_scalars": "1048576",
        "maximum_list_items": "65536"
      },
      "interpreter": {
        "maximum_workflow_call_depth": "1024",
        "maximum_tasks_per_execution": "65536",
        "maximum_deterministic_transitions_per_execution": "10000000",
        "maximum_operations_per_execution": "100000",
        "maximum_loop_iterations_per_task": "1000000"
      },
      "required_event_sinks": [
        {
          "id": "stable-sink-id",
          "raw_output_enabled": false,
          "redaction_policy_id": "policy-id",
          "redaction_capabilities": {
            "operation_request_content": false,
            "operation_result_content": false,
            "integration_diagnostics": false,
            "source_snippets": false
          },
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

    The displayed model/action retry, retry-backoff, workflow-depth, task-count,
    and event-delivery values are the normative v1 defaults when the embedder
    does not configure replacements. Their behavior is defined in Sections 3,
    8, 10, and 12. The six values inside
    `deterministic_values` are
    illustrative effective values, not language defaults; the integration MUST
    choose them within the bounds below. `maximum_directive_integer` is the
    fixed v1 language maximum, not an integration setting; including it makes
    that parser capability explicit in the configuration identity. Identity
    strings are placeholders, and `required_event_sinks` illustrates a
    nonempty configured set rather than prescribing a default sink. The
    identity MUST encode the effective configured values. Each required sink's
    `redaction_capabilities` object contains exactly the four Boolean
    properties shown; these resolved values, rather than the policy ID alone,
    govern protected-data delivery and are frozen into event obligations under
    Sections 12 and 15.
    `maximum_entry_input_bytes` limits the
    raw entry-input byte sequence before UTF-8 decoding.
    `maximum_hook_output_bytes` limits each raw `Completed` outcome before
    UTF-8 decoding and the UTF-8 encoding of each `Declined` reason or `Failed`
    message before that diagnostic text is accepted. A reason or message is
    additionally subject to `maximum_string_scalars` under Section 7.
    `maximum_value_nesting_depth` and `maximum_value_nodes`
    limit every strict-JSON tree under Section 8's depth and node-count
    definitions. `maximum_string_scalars` limits each normalized or computed
    String by Unicode-scalar count, and
    `maximum_list_items` limits each normalized or computed List by item count.
    `maximum_workflow_call_depth` is the per-task active-frame limit defined in
    Section 3, and `maximum_tasks_per_execution` is the cumulative task limit
    defined in Section 10. The three remaining interpreter values are the
    mandatory durable budgets defined in Section 9. All eleven limits and
    budgets MUST be positive. The byte,
    nesting, node, workflow-depth, and task-count limits MUST be no greater
    than `2^63 - 1`; the String and List limits MUST be no greater than
    Gantry's maximum `Int`, `9007199254740991`, because `String.len()` and
    `List<T>.len()` return `Int`. The displayed workflow-depth and task-count
    values are the v1 defaults. Every limit is checked at the applicable
    entry, operation, construction, parsing, task-creation, frame-entry,
    resume, or deterministic-evaluation boundary. Budget counters and their
    effective maxima are part of execution identity and MUST NOT change on
    resume or migration. `model_retry_limit`
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
    sink plus a `class` field whose value is exactly `best-effort`. The
    descriptors MUST be ordered by unsigned UTF-8 sink ID. These initial values
    are the baseline for resume;
    Gantry MUST restore them from the execution-start record and then apply
    later compatible execution-state revisions in journal sequence order. A
    resume caller MUST NOT silently replace that baseline through ordinary
    interpreter configuration. A requested compatible change becomes active
    only after the execution-state evidence described below is committed. This
    separation keeps mutable operational policy recoverable
    without pretending that it is immutable execution identity.
    Resume MUST reject a change to any identity-bound field in the canonical
    configuration object above. The mutable baseline fields in the preceding
    paragraph are not identity-bound; they may change only through the durable
    execution-state revisions defined below. Executor implementation,
    worker count, and integration-owned operation-timeout policy MAY change on
    resume without changing this identity; they affect scheduling or
    integration behavior rather than the meaning of already committed Gantry
    state. Shutdown timing, best-effort sinks, and logical-agent-to-provider
    mappings and action mappings MAY change only after Gantry commits the
    applicable execution-state evidence before further work. That evidence MUST contain the
    effective graceful-shutdown and post-cancellation-drain durations when
    shutdown timing changes; a best-effort-sink revision MUST contain the
    complete replacement set in the canonical order and descriptor shape
    above; and agent- and action-mapping changes use the state described in
    Section 7.
    The deterministic-transition yield quantum is also excluded from the
    configuration identity. It MAY change between in-process runs and on
    resume because Section 3 defines it as scheduling-only policy. Changing it
    MUST NOT alter language results, dynamic identities, retry accounting, or
    the semantic content and per-task order of logical evidence and events; it
    MAY alter timestamps and the global sequence order of records and events
    from different tasks.
    These changes MUST obey the per-event delivery-obligation rules in Section
    12. Allowing agent mappings to change is
    intentional because Gantry promises resumability, not deterministic model
    replay. Source operation modifiers remain bound through the package source
    identity rather than being duplicated into this configuration identity.
<a id="GNT-11.11"></a>

11. These resume guarantees do not create a deterministic-replay guarantee for a
   new execution.

## 12. Observability and Tooling Modes

<a id="GNT-12.0"></a>

Items 1 through 8 define event creation, protected payloads, delivery, and
failure behavior. Items 9 through 11 define syntax-only validation, semantic
analysis, and machine-readable diagnostics; those tooling modes never invoke
an operation hook.

Gantry exposes four strictly separated observation layers: (1) source-visible
values and errors, (2) one logical trace over abstract machine labels, (3) a
physical trace of dispatch, retry, recovery, persistence, and delivery
attempts, and (4) nonsemantic telemetry such as timing and provider metrics.
Only layer 1 is readable by Gantry source. Layers 2 and 3 are durable evidence
used to enforce causality, recovery, deduplication, and delivery guarantees;
they MUST refine, rather than add behavior to, the abstract source semantics.
Layer 4 may be sampled or dropped. Layers 2 through 4 MUST NOT be injected
into fulfiller input or otherwise alter fulfillment, and every event schema
MUST identify its layer. Standard v1 event envelopes use layer `logical` for
source and abstract-machine occurrences and layer `physical` for dispatch,
completion, validation-failure, retry, persistence, delivery, and shutdown
occurrences. Optional telemetry uses layer `telemetry`. One causal transition
MAY produce linked logical and physical events, but each occurrence has one
layer and its own stable event ID.

<a id="GNT-12.1"></a>

1. Gantry MUST expose events for parsing and analysis, workflow start and end,
   operation dispatch, completion, and result acceptance, structured output
   validation failure, retry, branch decision, spawn, join, detach, mutation,
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
   occurred. One operation-completion event MUST be emitted for each valid host-
   level outcome accepted under Section 7, item 11, including a `Completed`
   outcome that subsequently fails parsing or schema validation. An invalid
   decline reason or failure message instead produces the bounded hook-failure
   reporting required by that item. Those events retain the
   logical operation ID and carry the distinct dispatch ID and applicable
   validation-attempt and recovery-dispatch numbers. A structured-output-
   validation-failure event and, when another attempt is permitted, a retry
   event follow the corresponding completion event. Gantry MUST emit exactly
   one operation-result event for every committed logical result that source
   may consume. This includes a value, decision, or `Unit` accepted from a
   successfully decoded, parsed, validated, and normalized `Completed`
   outcome, and an explicit `Err(OperationError)` that `attempt` derives from
   a committed decline, failure, exhausted invalid output, or unknown outcome.
   The event MUST reference the applicable operation-result record. It is not
   emitted for a required-result `Declined`, `Failed`, or invalid `Completed`
   outcome that propagates as task failure rather than becoming source data.
   Recovery that reuses an existing operation-result record MUST reuse its
   corresponding durable event occurrence rather than emit another logical
   acceptance event. If the operation-result record is durable but its event
   record is absent, recovery MUST create exactly one replacement occurrence
   under item 2 before source execution consumes the result. This event
   cardinality distinguishes physical hook activity from the one source-level
   result that execution may consume.
   For a resumable execution, causal event creation has the following mandatory
   ordering. After the operation-dispatch record is durable and before invoking
   the hook, Gantry MUST commit the corresponding operation-dispatch event
   evidence. After an operation outcome is durable and before decoding,
   validation, decline handling, or failure propagation consumes that outcome,
   Gantry MUST commit its operation-completion event evidence. A
   structured-output-validation-failure event and any retry event MUST be
   committed before the next dispatch record. After an operation-result record
   is durable and before source execution consumes that result, Gantry MUST
   commit the operation-result event evidence. Delivery MAY remain asynchronous
   under item 3; these requirements order durable event creation, not sink
   acknowledgement. They ensure that a journal can never expose a consumed
   operation transition without its canonical event occurrence.
   On recovery, a durable outcome without its operation-completion event MUST
   receive exactly one replacement event under item 2 before processing of the
   outcome resumes. A durable completion event MUST never be duplicated. For a
   `Declined` or `Failed` outcome that fails the task, this completion event is
   the final operation-specific event; the resulting task failure is observed
   separately and does not manufacture an operation-result event.
   For every other required event kind that represents a durable interpreter
   transition, Gantry MUST commit the event evidence after its causal journal
   evidence is durable and before later source execution, an execution
   waiter, or an event sink observes or depends on that transition. The event
   MUST reference the causal record. This rule applies to workflow, branch,
   spawn, join, detach, mutation, cancellation, task-completion, foreground-
   completion, and terminal-execution events. If recovery finds such a causal
   transition without its event record, Gantry MUST commit exactly one
   replacement event under item 2 before work depends on the transition.
<a id="GNT-12.2"></a>

2. Each event MUST have a stable event ID and activity ID. An event ID MUST be
   globally unique among all event occurrences that can be delivered to the
   same sink, across executions, resumes, validation and analysis activities,
   and shutdown invocations. Sinks therefore deduplicate on the event ID alone
   without applying an execution-, journal-, or activity-local namespace. An
   activity is one
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
   authoritative journal prefix; it MUST NOT commit a second event for that
   occurrence. If a causal interpreter transition is durable but interruption
   occurred before its required event record became durable, no event from that
   transition could have been delivered under item 3. Recovery MUST create
   exactly one replacement event before performing work that depends on that
   transition. The replacement uses the resume activity ID and its actual
   creation timestamp, identifies the durable causal record, and thereafter has
   the same stable recovery and deduplication behavior as any other event. An
   uncommitted event record is not authoritative and MUST NOT reserve an event ID
   or timestamp across recovery. Events for genuinely new work performed by the
   resume likewise use the resume activity ID. These rules make sink
   deduplication effective without requiring recovery to reproduce metadata that
   was never durable or externally visible.
<a id="GNT-12.3"></a>

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
   settle successfully before Gantry commits the execution-start evidence.
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
   stream ends with its last committed event. Gantry MUST NOT deliver a
   newly created standard event for that journal failure because doing so
   would violate the journal-first rule. An implementation MAY invoke a
   separately configured, non-durable emergency diagnostic callback, but that
   callback is not an `EventSink`, carries no at-least-once guarantee, and MUST
   be identified as out-of-band reporting rather than a Gantry event.
<a id="GNT-12.4"></a>

4. Canonical protected event records for completed operations MUST make raw
   integration output available. A sink receives raw output only when it
   explicitly declares that capability and the embedder enables it for that
   sink. Other sinks receive the same event identity with the raw field
   redacted. Operation request content includes authored and rendered prompts,
   expected schemas, interpolation arguments, named inputs, action arguments,
   logical-session identifiers, and the canonical session transcript. A sink receives that content only
   when its frozen `operation_request_content` capability is true. Operation
   result content includes normalized values from every operation kind and
   both visible fields of a sealed `Decision`; a sink receives that content
   only when its frozen `operation_result_content` capability is true.
   Integration diagnostics and source snippets are likewise delivered only
   when the corresponding frozen `integration_diagnostics` or
   `source_snippets` capability is true.

   Prompts, schemas, normalized operation values, decision rationales, and
   other protected content MUST be stored as protected payloads referenced by
   journal or event IDs rather than copied into ordinary event envelopes. Raw
   output MUST remain omitted from default human-readable diagnostics and
   validation error text. For delivery, Gantry MUST resolve an event's
   protected references into a capability-filtered payload bundle supplied
   alongside, but not inside, the ordinary event envelope. The bundle MUST
   preserve the stable reference keys used by the envelope and MUST omit or
   explicitly redact each payload whose applicable frozen capability is
   false. Raw-output access remains independent of the four redaction-policy
   capabilities. A protected payload referenced by a durable journal or event
   record MUST remain resolvable for as long as that record is retained.
   Gantry MUST additionally retain it until every required delivery has
   succeeded or terminally failed and every best-effort delivery has either
   succeeded or exhausted its policy.
   Retention or deletion policy MAY remove a complete journal and its payloads,
   but MUST NOT leave a retained durable record with a dangling protected
   reference. This makes reference-based events usable without placing
   sensitive or repeated payloads directly in each event envelope.
<a id="GNT-12.5"></a>

5. Event sinks MUST be configured independently as `required` or `best-effort`,
   with interpreter defaults overridable per sink. Gantry MUST
   retry only errors the sink classifies as retriable. A non-retriable error
   exhausts delivery immediately. The retry limit counts known retriable
   failures after the initial delivery; recovery of an indeterminate delivery
   does not consume that budget. Event delivery uses the same configurable
   initial-delay, cap, `full`/`none` jitter semantics, and saturating ceiling
   calculation as structured-output retry in Section 8, item 10. The default
   policy is three retries with `initial_delay = 100 ms`, `cap = 2 s`, and
   `jitter = full`. Every physical delivery attempt MUST also have a finite
   positive attempt timeout.
   The v1 default is 30 seconds. Gantry MUST race the sink future against that
   timeout through the executor adapter. Expiration is a retriable delivery
   error while retry budget remains and a terminal delivery error otherwise.
   Gantry MUST stop polling the expired future and MAY signal a sink-specific
   cancellation mechanism when the embedding API provides one, but it cannot
   assume that external sink effects stopped. A later retry is therefore an
   at-least-once delivery and retains the same stable event ID.

   For a resumable execution, every physical sink invocation MUST use two
   durable event-delivery state transitions. Before invoking the sink, Gantry
   MUST commit a `dispatched` state containing the sink ID, stable event ID,
   distinct delivery-attempt ID, and zero-based retry number. After the sink
   returns, Gantry MUST commit a `settled` state containing
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
   class, raw-output permission, redaction-policy ID, resolved Boolean
   capabilities for `operation_request_content`, `operation_result_content`,
   `integration_diagnostics`, and `source_snippets`, retry-policy revision,
   attempt timeout, retry limit, initial delay, cap, and jitter mode. The event
   evidence and this complete immutable initial delivery plan MUST
   be committed atomically in one journal batch. Recovery MUST treat an event
   record missing that plan as malformed journal evidence and MUST NOT infer
   obligations or permissions from current configuration. A retry or recovery
   redelivery
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
   error under its captured policy and does not block resume. Access to each
   protected payload class at delivery time is governed by the permission
   captured in that event's obligation. Later configuration MUST NOT broaden
   or reduce access for an existing obligation; configuration changes apply
   only to events created after the corresponding execution-state record
   becomes durable. For an active
   resumable execution, the required-sink identities and their identity-bound
   policy fields MUST remain exactly those in the execution-start
   configuration identity; adding, removing, or changing a required sink is a
   resume-compatibility error. Best-effort sinks MAY be added, removed, or
   reconfigured after Gantry commits execution-state evidence describing the
   new effective set. Such a change affects only later events
   and never alters an already frozen delivery obligation.
<a id="GNT-12.6"></a>

6. Delivery of a journaled event is durably at least once across process
   interruption and resume. Sinks MUST deduplicate using the globally scoped
   stable event ID defined in item 2.
   For a standalone validation or analysis activity without a journal, Gantry
   MUST apply the configured delivery attempts while that activity remains
   alive, but process interruption MAY lose an unsettled event and v1 provides
   no recovery source from which to redeliver it. An implementation MUST NOT
   describe that weaker standalone guarantee as durable at-least-once
   delivery. A shutdown event uses the same non-durable, non-resumable
   delivery model for the lifetime of its shutdown invocation. Required-sink
   exhaustion is reported in the shutdown result without changing task or
   execution outcomes already fixed there; best-effort exhaustion is included
   in that result under Section 10. Exhaustion for a required sink MUST abort
   the affected standalone activity. It MUST NOT cancel an independent
   validation, analysis, or shutdown activity merely because both use the same
   interpreter or sink configuration.
   For an execution whose terminal-execution record is not yet durable, it
   MUST abort the execution as specified below. For an execution whose
   terminal-execution record is already durable, it MUST produce only the
   required-event-delivery barrier failure specified below and MUST NOT alter
   the durable language outcome. Exhaustion for a best-effort sink MUST be
   journaled when a journal exists, otherwise included in the activity result,
   and the activity MUST continue. Before returning a foreground
   outcome, Gantry MUST await required-sink settlements through that execution's
   foreground-completion event; events from detached work remain eligible for
   later delivery through the same execution. Before returning a terminal
   execution result, validation or analysis result, or orderly shutdown
   report, Gantry MUST await all required-sink deliveries produced by that
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
   tasks, and apply the configured cancellation drain. It MUST then commit the
   execution's terminal-execution evidence with the
   `required-event-delivery-failure` category, without making that record
   depend on another event. That record MUST identify the exhausted sink,
   failed event, delivery attempt, and cancellation outcome. Failure of the
   terminal-record write is returned to the embedder as a journal failure.

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
   event itself—MUST NOT commit a second terminal record or replace the
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
<a id="GNT-12.7"></a>

7. Every event envelope MUST identify its protocol version, event and activity
   IDs, optional execution ID, event kind, event layer (`logical`, `physical`,
   or `telemetry`), source location when source-backed,
   task and operation identities when applicable, causal parent IDs, per-task
   sequence when task-backed, timestamp, a kind-specific payload or stable
   payload reference. Redaction state is represented per protected reference
   as `available`, `redacted`, or `not-applicable`, together with the frozen
   permission class that governs it; there is no ambiguous envelope-wide
   redaction Boolean. A timestamp MUST be the event's
   creation time encoded as an RFC 3339 UTC string and MUST remain unchanged
   across delivery retries. Prompt templates, schemas, and raw integration
   output MUST use protected stable references rather than being copied into ordinary
   event payloads; diagnostics and other nonsensitive standalone activity data
   MAY be carried inline. The canonical v1 event-kind values are `parse`,
   `analysis`, `workflow-start`, `workflow-end`, `operation-dispatch`,
   `operation-completion`, `operation-result`,
   `structured-output-validation-failure`, `retry`, `branch-decision`,
   `spawn`, `join`, `detach`, `mutation`, `cancellation`,
   `foreground-completion`, `task-completion`, `terminal-execution`,
   `shutdown`, and `failure`. These kebab-case spellings are exact protocol
   values; headings and prose MAY use spaces for readability. Event envelopes
   use the canonical UTF-8 JSON representation required by Section 15.8;
   private in-memory and storage layouts remain implementation-defined.
<a id="GNT-12.8"></a>

8. Event kind payloads MUST expose enough structured information for a harness
   to interpret an execution without parsing diagnostic text. The canonical
   minimum payloads are:
   - `parse` and `analysis`: phase, status, and structured diagnostics;
   - `workflow-start` and `workflow-end`: workflow path, frame occurrence, and
     completion status, plus a typed result reference when one exists;
   - `operation-dispatch`: operation and dispatch IDs, dispatch state
     (`prepared` in v1), operation and result kinds, validation-attempt number,
     recovery-dispatch number, and schema and operation-body references. A
     prompt or decide operation additionally identifies its selected agent,
     active agent-mapping revision, logical session, request session directive,
     active-session creation directive and parent session when applicable, and
     prompt reference. An action instead identifies its canonical path and
     signature and active action-mapping revision;
   - `operation-completion`: operation and dispatch IDs, outcome variant, and
     a protected raw-output reference for `Completed`, or a protected
     integration-diagnostic reference for a decline or failure reason. A
     `Completed` raw-output reference is resolved only when the obligation's
     separately frozen raw-output permission is true; a decline or failure
     diagnostic is resolved only when its frozen `integration_diagnostics`
     capability is true;
   - `operation-result`: operation ID, committed outcome and operation-result
     record references, outcome variant, result kind, canonical type
     descriptor, and a protected normalized-value reference for a value result,
     a protected normalized-decision reference for a decision result, or a
     protected normalized-`OperationError` reference for an `Err` produced by
     `attempt`;
   - `structured-output-validation-failure`: operation and dispatch IDs plus
     the structured validation errors defined in Section 8;
   - `retry`: operation ID, preceding and next dispatch IDs when assigned,
     validation-attempt and recovery-dispatch numbers, retry class, and
     selected delay;
   - `branch-decision`: conditional, match, or loop identity; condition kind
     (`decision`, `bool`, or `pattern`); selected arm or loop transition; and
     the inline outcome for a `bool` or `pattern` condition. When the condition
     used `Decision`, the payload instead contains the decide operation ID and
     a protected normalized-decision reference; neither visible `Decision`
     field is copied into the ordinary event envelope;
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
   - `foreground-completion` and `task-completion`: the applicable identity,
     completion category, and typed result or failure reference when one
     exists;
   - `terminal-execution`: the execution identity, completion category,
     terminal-execution record reference, and typed foreground result or
     primary failure reference when one exists;
   - `shutdown`: the shutdown activity identity, configured graceful and drain
     durations, counts of executions and tasks observed at shutdown start,
     counts completed naturally, cancelled, and aborted, required-state commit
     status, and a shutdown-report reference;
   - `failure`: the runtime-error category, structured causal identities, and
     redacted diagnostic details.
   An implementation MAY add optional fields under the minor-version rules,
   but it MUST NOT omit these applicable fields or encode their only usable
   representation in human-readable text.
<a id="GNT-12.9"></a>

9. A dry-run performs syntax validation only and MUST NOT invoke operation
   hooks. Starting from `main.gnt`, it MUST discover every file module
   reachable
   through syntactically valid `mod` declarations and lex and parse every
   selected source file. Missing or ambiguous module files, containment
   violations, invalid UTF-8, lexical errors, and syntax errors are therefore
   dry-run failures because they prevent construction of the package syntax
   tree. A dry-run MUST NOT perform name resolution, type checking, schema
   generation, definite-control-flow analysis, or task-ownership analysis.
   Gantry MUST separately provide an analysis mode that first satisfies this
   whole-package syntax contract and then enforces every applicable static
   semantic requirement in this document without invoking hooks. This includes
   name, type, module, source-form and modifier, control-flow, task-ownership,
   and schema validation; the list is descriptive rather than an independent
   or exhaustive definition of source validity.
   A successful analysis result MUST include the per-workflow call edges,
   direct integration-operation and task-control sites, canonical inferred
   effect sets with contributing action paths, and checked `pure` assertions
   required by Section 6.
<a id="GNT-12.10"></a>

10. Normal execution MUST complete semantic analysis successfully before its
   first hook invocation.
<a id="GNT-12.11"></a>

11. Diagnostics MUST be usable by both human authors and automated repair agents
   without parsing display text. Every syntax or analysis diagnostic
    MUST contain a canonical phase, severity, machine-readable category, a
    documented code stable within the protocol major version, a human-readable
    message, and a primary package-relative source span when the problem is
    source-backed. The canonical v1 categories are `lexical`, `syntax`,
    `package`, `name-resolution`, `type`, `control-flow`, `task-ownership`,
    `schema`, and `identifier-security`. Diagnostic code namespaces are
    implementation-defined in v1, but
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

<a id="GNT-13.0"></a>

This section defines the normative v1 source grammar. Semantic restrictions in
the preceding sections still apply when the grammar admits a construct in a
broader syntactic position. This section also states a small number of
grammar-adjacent semantic rules where they are clearest, including contextual
name restrictions and source-form disambiguation. Those rules are part of the
same source-validity judgment; they are not optional parser guidance. In
particular, name resolution, exact type matching, decision-only contexts,
task-handle consumption, modifier validity, interpolation restrictions, and
the control-boundary constructor rule are semantic-analysis concerns.

### 13.1 Grammar notation

<a id="GNT-13.1"></a>

The grammar uses extended Backus-Naur form (EBNF):

- double-quoted or single-quoted text is a literal terminal; single quotes are
  used only when the terminal itself contains double quotes;
- inside an EBNF terminal, `\\`, `\"`, `\n`, `\r`, and `\t` denote one
  backslash, double quote, line feed (U+000A), carriage return (U+000D), and
  horizontal tab (U+0009), respectively; no other EBNF-terminal escape is
  permitted, and these notation escapes are distinct from Gantry source
  escapes recognized by `escape_sequence`;
- concatenation, written with commas, binds more tightly than alternation;
- `A | B` selects one alternative;
- `[ A ]` makes `A` optional;
- `{ A }` repeats `A` zero or more times;
- `( A )` groups EBNF terms; quoted `"("` and `")"` are source terminals;
- productions ending in `_token` describe lexical token classes; where a
  production is explicitly contextual, the parser MAY reclassify a token with
  the same boundaries after ordinary lexing; and
- `U+NNNN` denotes the single Unicode scalar with that hexadecimal code point,
  not the literal source characters `U`, `+`, and digits.

Whitespace and comments separate tokens and are otherwise insignificant,
except inside string, raw-string, and block-prompt tokens. A trailing comma is
accepted only where the productions below include an optional final comma.
All EBNF fences in Sections 13.2 through 13.9 form one grammar; a production
MAY refer forward to a production in a later fence. Names explicitly described
as lexical metavariables in Section 13.2 constrain token characters and are not
missing parser productions.

The lexical skip productions `whitespace`, `line_comment`, `block_comment`,
and `trivia` describe tokenization and are intentionally not referenced from
the parser entry production `module_source`. A conforming lexer removes that
trivia between tokens under Section 13.2 before the parser applies the
remaining productions. The lexer also consumes the one permitted initial
byte-order mark. The `module_source` production applies independently to
`main.gnt` and every source file selected by a `mod` declaration.

### 13.2 Lexical grammar

<a id="GNT-13.2"></a>

```ebnf
module_source       = { item }, end_of_file ;

whitespace          = " " | "\t" | "\r" | "\n" ;
line_terminator     = "\r\n" | "\n" | "\r" ;
line_comment        = "//", { line_comment_character },
                      ( line_terminator | end_of_file ) ;
block_comment       = "/*", { block_comment | block_comment_character }, "*/" ;
trivia              = whitespace | line_comment | block_comment ;

identifier_token    = xid_start, { xid_continue_or_underscore }
                    | "_", xid_continue,
                      { xid_continue_or_underscore } ;
directive_integer_token
                    = "0" | nonzero_decimal_digit, { decimal_digit } ;
integer_literal_token
                    = unsigned_integer_digits ;
float_literal_token = unsigned_integer_digits, ".", decimal_digits,
                      [ exponent_part ]
                    | unsigned_integer_digits, exponent_part ;
unsigned_integer_digits
                    = "0"
                    | nonzero_decimal_digit,
                      { [ "_" ], decimal_digit } ;
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
                    | "\\u{", hex_digit, [ hex_digit ], [ hex_digit ],
                      [ hex_digit ], [ hex_digit ], [ hex_digit ], "}" ;

block_prompt_token  = '"""', block_prompt_body, '"""' ;

raw_string_token    = "r", raw_hashes, '"', raw_string_body,
                      '"', matching_raw_hashes ;
raw_hashes          = { "#" } ;
```

`xid_start` and `xid_continue` are the Unicode XID_Start and XID_Continue
classes, respectively; `xid_continue_or_underscore` additionally permits `_`.
The exact one-character token `_` is reserved and is not an
`identifier_token`; leading `_` remains valid when at least one
`XID_Continue` scalar follows it. Reserved-word classification takes
precedence over `identifier_token`, so a reserved word is never emitted as an
identifier. Source MUST be valid UTF-8. One UTF-8
byte-order mark MAY appear only as the first decoded scalar of a source file
and is ignored; U+FEFF in any other source position, including inside an
ordinary string, raw string, or block prompt, is a syntax error. An identifier
MUST NOT equal a reserved word.

Identifiers use the UAX #31 default identifier profile for Unicode 16.0.0,
narrowed by NFC and the grammar above. An identifier MUST NOT contain a
Default_Ignorable_Code_Point, join control, variation selector, or bidi
formatting/control scalar, even if a broad library classifies it as XID.
Analysis MUST compute the Unicode 16.0.0 UTS #39 confusable skeleton for every
identifier. Two distinct spellings with the same skeleton in one lookup
namespace are an analysis diagnostic with category `identifier-security` and
the stable portable code `identifier-confusable-collision`. Collisions
across separate namespaces and identifiers containing scripts outside one
Recommended single-script set MUST produce an `identifier-security` diagnostic
that lists the exact scripts, skeleton, and related spans. Diagnostics MUST
render control scalars by code point and MUST NOT allow bidi reordering to hide
the authored token.

`directive_integer_token` is a contextual classification used only where the
grammar expects the value of `retry_limit` or loop `limit`. In those positions,
an unsigned decimal spelling with no sign, separator, or radix prefix is
emitted as `directive_integer_token`; the same spelling in an expression is
emitted as `integer_literal_token`. The contextual classification is necessary
because directive values may exceed the first-class `Int` range. It does not
change token boundaries: the lexer still consumes the complete contiguous
decimal digit sequence before applying the range rule for the applicable
token class.

An integer literal has decimal digits with optional `_` separators only
between digits. Its semantic magnitude is the base-ten value after removing
those separators. Its integral part is exactly `0` or begins with a nonzero
digit; leading-zero spellings such as `00`, `01`, and `0_1` are invalid. A
source expression such as `-0` is valid and evaluates by checked unary
negation to `0`; this differs intentionally from `String.parse_int()`, which
accepts only canonical input spellings and therefore rejects the text `-0`. A
float literal has either a decimal point with at least one digit on each side
or an exponent and follows the same integral-part rule; its exponent may have
a leading `+` or `-`. The spellings `.5`, `1.`, `01.0`, radix-prefixed values,
type suffixes, `NaN`, and infinities are invalid. A leading `-` is the unary
operator, not part of either numeric token. Maximal munch classifies a valid
integral part followed by `.` or an exponent as one `float_literal_token`;
otherwise it is an `integer_literal_token`. Semantic analysis enforces the
ranges in Section 5.

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
Outside string and prompt-template tokens, the lexer discards zero or more
trivia elements before the first parser token, between parser tokens, and
after the last parser token before `end_of_file`. Trivia MUST NOT split one
identifier, numeric token, string delimiter, comment
delimiter, or fixed multicharacter terminal such as `::` or `->`. Maximal munch therefore
requires trivia between a reserved word and an immediately following
identifier character when they are intended as separate tokens.

`string_character` is any Unicode scalar value other than `"`, `\`, or
U+FEFF; newline characters are included. `block_prompt_body` and
`raw_string_body` likewise exclude U+FEFF under the file-wide rule above.
`block_prompt_body` uses the same escape sequences as
an ordinary string. While scanning it, a backslash followed by a valid escape
suffix consumes the complete escape sequence before delimiter recognition.
Otherwise, the first unconsumed run beginning with three consecutive `"`
scalars starts the closing delimiter; a run of one or two quotes is content.
Thus a `\"` escape consumes exactly one quote as content, and the following
unconsumed quotes are considered independently for delimiter recognition. A block
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
followed by `matching_raw_hashes`. The lexer consumes that quote and exactly
the opening delimiter's number of `#` characters as the close; any immediately
following additional `#` characters are outside the raw-string token. Thus
`r#"x"##` tokenizes as the raw string `r#"x"#` followed by `#`, which is an
error unless another surrounding production admits that token. Lexing uses maximal munch for
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
action     agent      agents      as           attempt     Bool        break
continue   crate      Decision      decide      default     detach
discard
else       enum       Err         false        Float       fn          fork        if
for        idempotent in          impl        inline       join        joinall      let
limit
Int        List       loop        match         mod         mut         new
non_idempotent None    null       Ok           OperationError Option
prompt     pure       read_only   Result       return      retry_limit self
session    Some       spawn       String       struct      super       true
Tuple      unbounded  Unit       until       use          using       when        while
with
```

`as` is reserved for future compatible extension even though v1 has no alias
form for `use`. `true` and `false` are `Bool` literals. `null` remains reserved
because absence is written as typed `None` rather than as a source null value.
Reserved type and constructor names are case-sensitive. Lexing uses maximal
munch for the fixed multi-character terminals `::`, `->`, `=>`, `==`, `!=`,
`<=`, `>=`, `&&`, `||`, `+=`, `-=`, `*=`, `/=`, and `%=`; trivia MUST NOT
split one of those terminals.

### 13.3 Package declarations and types

<a id="GNT-13.3"></a>

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
                        | "(", ")"
                        | "None" ;

enum_declaration        = "enum", identifier_token, "{",
                          enum_variant, { ",", enum_variant }, [ "," ], "}" ;
enum_variant            = identifier_token, [ "(", value_type, ")" ] ;

action_declaration      = "action", action_recovery_class,
                          identifier_token, "(",
                          [ action_parameter_list ], ")",
                          [ result_annotation ], ";" ;
action_recovery_class   = "read_only" | "idempotent" | "non_idempotent" ;
action_parameter_list   = action_parameter, { ",", action_parameter }, [ "," ] ;
action_parameter        = identifier_token, ":", value_type ;

value_type              = "Unit"
                        | "Bool"
                        | "Int"
                        | "Float"
                        | "String"
                        | "Decision"
                        | "OperationError"
                        | qualified_path
                        | "Option", "<", value_type, ">"
                        | "Result", "<", value_type, ",", value_type, ">"
                        | "List", "<", value_type, ">"
                        | "Tuple", "<", value_type, ",", value_type,
                          { ",", value_type }, [ "," ], ">" ;
result_type             = value_type ;
result_annotation       = "->", result_type ;
```

The built-in type alternatives take precedence over `qualified_path`. A
`Tuple` has at least two member types by grammar. An enum has at least one
variant, and an action declaration has no body and exactly one recovery class.
`Unit` is the result type for no-information work; `None` is only the absent
value of an expected `Option<T>`. Field defaults are deliberately limited to
`()`, Boolean literals, optionally negated numeric literals, ordinary or raw
strings, and `None` in v1. Their declared field type and normalization MUST
satisfy requirement `GNT-5.12` without coercion.

A `use` declaration imports the item named by the final path segment into the
current module. The path roots have the meanings defined in Section 4. Glob
imports, grouped imports, aliases, importing a module under the name `self`,
and visibility modifiers are not v1 syntax. Only package items admitted by
the `item` production are importable. Enum variants, struct fields, and
inherent methods are members rather than package items and therefore cannot be
imported directly; authors refer to them through their enum type, value, or
receiver.

### 13.4 Workflows and methods

<a id="GNT-13.4"></a>

```ebnf
function_declaration    = [ "pure" ], "fn", identifier_token, "(",
                          [ parameter_list ], ")",
                          [ result_annotation ], block ;
parameter_list          = parameter, { ",", parameter }, [ "," ] ;
parameter               = [ "mut" ], identifier_token, ":", value_type ;

impl_declaration        = "impl", qualified_path, "{",
                          { method_declaration }, "}" ;
method_declaration      = [ "pure" ], "fn", identifier_token, "(", receiver,
                          [ ",", parameter_list ], ")",
                          [ result_annotation ], block ;
receiver                = "self" | "mut", "self" ;
```

A function signature without a result annotation returns `Unit`, exactly as
if it had `-> Unit`. `pure` is a checked assertion that the inferred effect set
is empty; it does not change evaluation. A workflow that returns a model
judgment uses the ordinary `-> Decision` annotation. `mut` on a non-receiver parameter permits mutation of that
workflow's deep-copied local argument; it does not affect the caller. A method
always has a receiver as its first parameter. Associated functions without a
receiver are excluded from v1. The `self` token is valid only within the lexical body of an
inherent method, including nested blocks and spawned blocks inside that method;
it is an analysis error in a free function, field default,
or module-level declaration. A spawned block captures `self` under the copy
rules in Section 10 rather than introducing a new receiver.
The root module's function named `main` is additionally restricted by Section
4 to zero parameters or exactly one typed parameter; this is an entry-point
semantic constraint rather than a separate function grammar.

### 13.5 Blocks and statements

<a id="GNT-13.5"></a>

```ebnf
block                   = "{", { statement }, [ trailing_expression ], "}" ;
value_block             = "{", { statement }, trailing_expression, "}" ;
statement_block         = "{", { statement }, "}" ;

statement               = let_statement
                        | assignment_statement
                        | expression_statement
                        | discard_statement
                        | return_statement
                        | break_statement
                        | continue_statement
                        | spawn_statement
                        | detach_statement
                        | with_statement
                        | session_statement
                        | if_statement
                        | match_statement
                        | loop_statement
                        | while_statement
                        | until_statement
                        | for_statement ;

let_statement           = "let", let_binding, ":",
                          value_type, "=", expression, ";" ;
let_binding             = [ "mut" ], identifier_token
                        | let_tuple_pattern ;
let_pattern             = "_" | identifier_token | let_tuple_pattern ;
let_tuple_pattern       = "(", let_pattern, ",", let_pattern,
                          { ",", let_pattern }, [ "," ], ")" ;
assignment_statement    = assignment_target, assignment_operator,
                          expression, ";" ;
assignment_operator     = "=" | "+=" | "-=" | "*=" | "/=" | "%=" ;
assignment_target       = identifier_token, { ".", identifier_token }
                        | "self", ".", identifier_token,
                          { ".", identifier_token } ;
expression_statement    = expression, ";" ;
discard_statement       = "discard", expression, ";" ;
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
binding, and tuple destructuring introduces immutable bindings. `_` may appear
inside a tuple pattern to ignore selected members; ignoring the complete
initializer uses `discard expression;` rather than a second wildcard-binding
form. A trailing expression is distinguished
from an expression statement by the absence of `;` immediately before the
closing brace. A bare expression statement MUST have type `Unit`; every other
intentionally ignored value uses `discard expression;`. `discard` evaluates
its operand exactly once before discarding it and does not suppress the
operand's effects or failures. `return;` is sugar for `return ();` and is valid
only in a `Unit` function, method, or spawned block.
`break` and `continue` are valid only in a loop body. Semantic analysis applies
the definite-return requirement in Section 9 to every declared result type,
including `Decision`.
Assignment to `self` as a whole is not v1 syntax; a
`mut self` method may assign its receiver fields and may return the resulting
receiver value.

### 13.6 Expressions

<a id="GNT-13.6"></a>

```ebnf
expression              = logical_or_expression ;
logical_or_expression   = logical_and_expression,
                          { "||", logical_and_expression } ;
logical_and_expression  = equality_expression,
                          { "&&", equality_expression } ;
equality_expression     = ordering_expression,
                          [ ("==" | "!="), ordering_expression ] ;
ordering_expression     = additive_expression,
                          [ ("<" | "<=" | ">" | ">="),
                            additive_expression ] ;
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
                        | attempt_expression
                        | match_expression
                        | join_expression
                        | joinall_expression
                        | with_expression
                        | session_expression ;

attempt_expression      = "attempt", operation_expression ;
operation_expression    = prompt_expression
                        | decide_expression
                        | action_expression ;

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
                        | "(", ")"
                        | "None"
                        | "Some", "(", expression, ")"
                        | "Ok", "(", expression, ")"
                        | "Err", "(", expression, ")"
                        | "self"
                        | struct_expression
                        | list_expression
                        | tuple_expression
                        | qualified_path
                        | "(", expression, ")" ;

struct_expression       = qualified_path, "{", [ field_initializer_list ], "}" ;
field_initializer_list  = field_initializer, { ",", field_initializer },
                          [ "," ] ;
field_initializer       = identifier_token, [ ":", expression ] ;
argument_list           = expression, { ",", expression }, [ "," ] ;

list_expression         = "[", [ argument_list ], "]" ;
tuple_expression        = "(", expression, ",", expression,
                          { ",", expression }, [ "," ], ")" ;

action_expression       = "action", [ action_modifiers ], qualified_path,
                          "(", [ argument_list ], ")" ;
action_modifiers        = "(", retry_modifier, ")" ;

match_expression        = "match", expression, "{",
                          match_arm, { ",", match_arm }, [ "," ], "}" ;
match_arm               = pattern, "=>", match_arm_body ;
match_arm_body          = expression | value_block ;
match_statement         = "match", expression, "{",
                          statement_match_arm,
                          { ",", statement_match_arm }, [ "," ], "}" ;
statement_match_arm     = pattern, "=>", statement_block ;

pattern                 = "_"
                        | identifier_token
                        | "None"
                        | "Some", "(", pattern, ")"
                        | "Ok", "(", pattern, ")"
                        | "Err", "(", pattern, ")"
                        | operation_error_pattern
                        | enum_variant_pattern
                        | tuple_pattern ;
operation_error_pattern = "OperationError", "::", identifier_token,
                          "(", pattern, ")" ;
enum_variant_pattern    = path_segment, "::", path_segment,
                          { "::", path_segment },
                          [ "(", pattern, ")" ]
                        | ( "crate" | "self" ), "::", relative_path,
                          [ "(", pattern, ")" ]
                        | "super", "::", { "super", "::" }, relative_path,
                          [ "(", pattern, ")" ] ;
path_segment            = identifier_token ;
tuple_pattern           = "(", pattern, ",", pattern,
                          { ",", pattern }, [ "," ], ")" ;

with_expression         = "with", identifier_token, value_block ;
session_expression      = "session", "(", session_directive, ")",
                          value_block ;
boolean_literal         = "true" | "false" ;
```

An action `retry_limit` counts validation retries after the initial dispatch.
Under Section 8, item 9, a `non_idempotent` action must have an effective limit
of zero, so a positive source override on such an action is an analysis error.

The grammar admits `self` as a primary expression so the same expression
productions can parse method bodies and their nested blocks. Semantic analysis
MUST enforce the receiver scope specified in Section 13.4.

`join` is the sole reserved word admitted as a postfix member name because
`List<String>.join(separator)` is a deterministic built-in while bare
`join(...)` is the parallel task operation. All other postfix member names are
ordinary identifiers. Name and type resolution always distinguish these two
forms; `.join(...)` never consumes task handles.

Postfix `(...)` dispatches a workflow function or method, constructs the
payload of a declared enum variant, or invokes one of the sealed built-ins
defined in Section 5. These include numeric conversion,
primitive formatting, String query/transformation/parsing, `List<T>.len()`,
and `List<String>.join(separator)`. Postfix `.name`
accesses a struct field, selects a method, selects the read-only
`Decision.decision` or `Decision.rationale` field, or selects the read-only
`OperationError.message: String` or
`OperationError.operation_id: Option<String>` field. Postfix `[expression]`
projects a list when the index has type `Int`; tuple projection still requires
a nonnegative compile-time integer literal so its result type is statically
known. Bracketed expressions construct lists; parentheses containing at least
two comma-separated expressions construct tuples, while `(value)` remains
grouping. Operators use the precedence shown by the grammar. Arithmetic and
logical operators associate left to right, while equality and ordering are
non-associative and may occur at most once at their respective unparenthesized
precedence level. Authors MUST write `low < value && value < high` rather than
`low < value < high`; explicit parentheses remain available when comparing
Boolean results is genuinely intended. Parentheses override precedence.

An unqualified primary path used as a value MUST resolve to a visible parameter
or binding. A qualified item path is valid in an expression only as the callee
of a workflow call, the action path after `action`, the type path beginning a
struct constructor, or a declared enum variant. A unit enum variant is a
complete value; a payload variant requires one following call suffix carrying
its payload. Workflow calls and payload-variant construction intentionally
share Rust-like `path(value)` syntax and are distinguished by name and type
resolution rather than by an ambiguous pair of grammar productions. Because
v1 has no module, type, function, action, or method values, semantic
analysis MUST reject a bare path that resolves to any such item other than a
unit enum variant. Task handles are legal only in `join`,
`joinall()`, and `detach`, never as primary expressions.

Path interpretation follows the next source token. A path followed by `{`
MUST resolve to a struct type and begins a struct constructor. A path followed
by `(` MUST resolve to exactly one callable workflow, declared enum payload
variant, or permitted built-in. A path with no such suffix in value position
MUST resolve to a visible binding when it has one unqualified segment, or to a
declared unit enum variant. Enum patterns use the same root and module lookup
rules as `qualified_path` and MUST resolve to an enum variant. An
`operation_error_pattern` is valid only for the seven exact variants in
Section 5; the first six require a `String` payload pattern and
`UnknownOutcome` requires a `Tuple<String,String>` payload pattern. This
special production exists because `OperationError` is a reserved sealed type,
not an ordinary declared enum. Failure to find
the required item kind, or finding more than one valid interpretation, is an
analysis error.

A value-producing `with` or `session` expression requires its block's trailing
expression and yields that value. These forms permit a lexical agent or session
context to produce the enclosing workflow's result. Their statement-only forms
in Section 13.5 execute their blocks for effects, produce no expression value,
and take no semicolon after the closing brace. A
non-`Unit` context value is ignored only through `discard with ...` or
`discard session(...) ...`; a bare trailing semicolon is valid only when the
context expression has type `Unit`.

`prompt`, `decide`, `action`, `match`, `join`, `joinall()`, `with`, and
`session` are complete expression forms rather than direct bases of a postfix
chain. To select a field, invoke a method, or project from one of their results
without first binding it, source MUST parenthesize that expression, as in
`(join(first, second))[0]`. This explicit grouping avoids ambiguity between
operation result annotations and operations on the produced value.

An effect-only `match` is parsed as `match_statement`: every arm body is a
braced `statement_block`, and no semicolon follows the closing match brace. A
value-producing match is `match_expression`; a braced arm in that form is a
`value_block` and therefore has a trailing expression. Ignoring the complete
non-`Unit` match value requires `discard match ...`. The disjoint block forms prevent a
block-shaped control construct from silently discarding a value while keeping
the common effect-only form visually aligned with `if` and loops.

Semantic analysis MUST validate every postfix step from left to right. A call
suffix is legal only on a function item, selected inherent method, declared
enum payload variant, or a sealed deterministic built-in defined in
Section 5 with exactly its declared argument count and types;
a field suffix is legal only on a struct value, selected inherent method, a
read-only `Decision` field, or a read-only `OperationError` field; and an index
suffix is legal only on a list or tuple value. Calling another value, selecting an unsupported field, or
indexing another type is an analysis error. `Unit` has no fields, methods, or
index operation, so an attempted postfix suffix on `()` is rejected by those
ordinary rules.

As a semantic disambiguation rule applied after parsing, a struct constructor
in an `if` (including an `else if`) or `while` condition, an `if let`
scrutinee, or a `match` scrutinee MUST occur inside an already-opened delimiter
pair: parentheses, call arguments, an index, or an aggregate. For example,
`if (Policy { enabled: true }).enabled { ... }` and
`if check(Policy { enabled: true }) { ... }` are valid, while
`if Policy { enabled: true }.enabled { ... }` is rejected. A constructor
nested in one of those delimited expressions needs no additional parentheses.
An `until` condition is not subject to this rule because it follows the body
and ends at `;`. This local rule gives parsers and readers one interpretation
of a path followed immediately by `{` at a control-flow boundary without
imposing recursive punctuation on otherwise unambiguous expressions.

### 13.7 Prompts and interpolation

<a id="GNT-13.7"></a>

```ebnf
prompt_expression       = "prompt", [ prompt_modifiers ], prompt_template,
                          [ using_clause ], [ result_annotation ] ;
prompt_modifiers        = "(", prompt_modifier,
                          { ",", prompt_modifier }, [ "," ], ")" ;
prompt_modifier         = "session", "=", session_directive
                        | retry_modifier ;
retry_modifier          = "retry_limit", "=", directive_integer_token ;
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
                          [ ("==" | "!="), interpolation_ordering ] ;
interpolation_ordering  = interpolation_additive,
                          [ ("<" | "<=" | ">" | ">="),
                            interpolation_additive ] ;
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
                        | "(", ")"
                        | "None"
                        | "Some", "(", interpolation_expression, ")"
                        | "Ok", "(", interpolation_expression, ")"
                        | "Err", "(", interpolation_expression, ")"
                        | interpolation_struct
                        | interpolation_list
                        | interpolation_tuple
                        | qualified_path
                        | "self"
                        | "(", interpolation_expression, ")" ;
interpolation_struct    = qualified_path, "{",
                          [ interpolation_field_list ], "}" ;
interpolation_field_list
                        = interpolation_field,
                          { ",", interpolation_field }, [ "," ] ;
interpolation_field     = identifier_token,
                          [ ":", interpolation_expression ] ;
interpolation_list      = "[", [ interpolation_expression,
                          { ",", interpolation_expression }, [ "," ] ], "]" ;
interpolation_tuple     = "(", interpolation_expression, ",",
                          interpolation_expression,
                          { ",", interpolation_expression }, [ "," ], ")" ;
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
an island only when every nested `()`, `[]`, and `{}` delimiter opened by the
island's token stream has been closed.
The contextual scanner MUST tokenize the island using the ordinary Gantry
lexical rules, so delimiters inside quoted or raw string tokens or comments do
not affect that balance. Comment delimiters inside strings remain literal text.
An unclosed, mismatched, or syntactically invalid island is a syntax error.

Interpolation and named inputs permit only the restricted grammar above. A
postfix call is legal only for a declared enum payload constructor or a sealed
deterministic built-in in Section 5, with the exact argument count and types
defined for that target; it cannot dispatch a workflow or source-defined
method. A qualified path without a call may denote a unit enum variant, while
an unqualified path denotes a visible binding under the ordinary name rules.
A projection index MUST obey the list and tuple rules in Section 5. Neither
form admits any other function or method call, `prompt`, `decide`, `action`,
joins, mutation, or control flow. Primitive operators use the same typing,
precedence, short-circuiting, checked arithmetic, and deterministic-failure
rules as ordinary expressions. Plain `String` interpolation of a computed
String still inserts its unquoted contents. A deterministic built-in failure,
including an empty split or replacement pattern or a size-limit failure,
prevents the containing operation from being dispatched.
Duplicate prompt modifiers and duplicate named-input names are analysis
errors. `retry_limit` counts retries after the initial attempt.

### 13.8 Decisions and sequential control flow

<a id="GNT-13.8"></a>

```ebnf
if_statement            = "if", conditional_head, statement_block,
                          { "else", "if", conditional_head, statement_block },
                          [ "else", statement_block ] ;
conditional_head        = condition_expression
                        | if_let_head ;
if_let_head             = "let", pattern, "=", expression ;
condition_expression    = expression ;
decide_expression       = "decide", [ prompt_modifiers ], prompt_template,
                          [ using_clause ] ;

loop_statement          = "loop", [ loop_modifiers ], statement_block ;
while_statement         = "while", [ loop_modifiers ],
                          condition_expression, statement_block ;
until_statement         = "until", [ loop_modifiers ], statement_block,
                          "when", condition_expression, ";" ;
for_statement           = "for", identifier_token, "in", expression,
                          statement_block ;
loop_modifiers          = "(", loop_modifier,
                          { ",", loop_modifier }, [ "," ], ")" ;
loop_modifier           = "session", "=", session_directive
                        | "limit", "=", loop_limit ;
loop_limit              = directive_integer_token | "unbounded" ;
```

Modifier parentheses cannot be empty, and duplicate modifiers are analysis
errors. Omitted `limit` and `limit = unbounded` both mean no source-level
limit; a numeric limit must be positive. `for` evaluates its list expression
once and has the finite snapshot semantics in Section 9. Conditions must have
type `Bool` or `Decision`. An `if let` scrutinee instead has the type required
by its pattern; a successful structural match makes the pattern bindings
available only in the selected body. For-item bindings are likewise scoped to
their body. The `until` grammar deliberately places its body before its
post-test.

### 13.9 Parallel control flow

<a id="GNT-13.9"></a>

```ebnf
spawn_statement         = "spawn", identifier_token,
                          [ result_annotation ], block ;
detach_statement        = "detach", "(", identifier_token, ")", ";" ;
join_expression         = "join", "(", identifier_token,
                          { ",", identifier_token }, [ "," ], ")" ;
joinall_expression      = "joinall", "(", ")" ;
```

Omitting a spawn result annotation declares a Unit task; a non-Unit task must
write its result annotation explicitly. Named `join` requires at least one
handle. `joinall()` takes no arguments; its
statically determined member set may contain zero, one, or several handles.
`detach` consumes exactly one attached task handle and is a statement rather
than a value-producing expression. Static result typing follows Section 10:
one value for one value-producing task, `List<T>` for multiple homogeneous
results, and `Tuple<T1, ..., Tn>` for multiple heterogeneous results. Zero
tasks, or one or more exclusively Unit tasks, produce `Unit`.

## 14. Authoring Examples and Common Errors

*This section is non-normative. It illustrates the contract but does not add
or override language requirements. Section 2 defines how normative prose,
grammar, and examples relate; Sections 5, 6, 9, 10, and 13 govern when a form
shown here is source-valid.*

The examples in this section are either complete programs when explicitly
introduced with package files, or focused fragments. A focused fragment
assumes that referenced types, agents, defaults, and helper workflows are
declared elsewhere in the package; it is not necessarily pasteable as a
standalone `main.gnt`. Except for snippets explicitly labeled invalid in
Section 14.14, all shown forms use only v1 syntax. Comments beginning with
`//` explain the example and are valid Gantry comments.

The following matrix highlights the result-position rules most likely to be
missed when reading Rust-inspired braces. It is a navigation aid, not a second
grammar:

| Source context | Body form | Trailing value | Semicolon after closing brace |
| --- | --- | --- | --- |
| Function, method, or spawned block | ordinary block | Optional, but required on each reachable normal completion of a value-returning body | No |
| `if`, loop, or effect-only `match` arm | statement-only block | Prohibited | No |
| Value-producing `match` arm | value block | Required | No within an enclosing expression; `discard match ...;` requires `;` after the complete match |
| Statement-only `with` or `session` | statement-only block | Prohibited | No |
| Value-producing `with` or `session` | value block | Required | No within an enclosing expression; `discard with ... { ... };` or `discard session(...) { ... };` requires `;` |

Only `Unit` expressions may be bare expression statements; other values use
explicit `discard`. A Unit operation or workflow call therefore ends in `;`,
whereas a statement-only braced control construct does not. Section 13.6 also
requires a struct constructor at an `if`, `while`, `if let`, or `match`
boundary to be parenthesized where specified. Section 14.14 gives paired
invalid and valid forms for these less-obvious rules.

### 14.1 Minimal package entry point

```gantry
agents { worker }
default agent = worker;

fn main() {
    prompt "Inspect the current assignment and carry it out.";
}
```

The omitted prompt annotation and omitted function result both mean `Unit`.
The complete explicit equivalent is:

```gantry
agents { worker }
default agent = worker;

fn main() -> Unit {
    prompt "Inspect the current assignment and carry it out." -> Unit;
}
```

An entry point may instead accept one typed strict-JSON value and return one
typed value:

```gantry
struct Request {
    topic: String,
    audience: Option<String>,
    dry_run: Bool = false,
}

struct Report {
    text: String,
}

fn main(request: Request) -> Report {
    prompt "Write about ${request.topic} for ${request.audience}."
        using { dry_run: request.dry_run }
        -> Report
}
```

For example, `{"topic":"task ownership"}` supplies `audience = None` and
the declared `dry_run = false` default. Gantry, not the embedder, parses and
normalizes those raw bytes. A `main` parameter or result containing `Decision`
or `OperationError` at any nesting depth is invalid; authors must copy any
data they intend to export into an ordinary declared type. Sections 4.2 and
15.1 define this boundary normatively.

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

The agent declaration in `main.gnt` makes both names available package-wide,
including in `workflows.gnt`; only `main.gnt` declares the default agent.

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
    let note: String =
        prompt "Give one short editorial note for ${draft}." -> String;
    draft.metadata.note = Some(note);
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

fn describe_optional(outcome: Option<ReviewOutcome>) -> String {
    if let Some(ReviewOutcome::Approved(_)) = outcome {
        return "approved";
    } else if let Some(ReviewOutcome::NeedsRevision(feedback)) = outcome {
        return feedback;
    } else {
        return "cancelled or absent";
    }
}
```

Primitive operators are deterministic and checked. List elements have one
exact type, tuple positions may differ, and pattern bindings are immutable deep
copies. Conditional chains may mix `if`, `else if`, and `else if let` without
extra nesting. `if let`, `match`, Boolean algebra, and equality do not dispatch hooks;
the visible `prompt` operations still perform the semantic classification and
revision work.

An effect-only match uses braced statement arms and no trailing semicolon:

```gantry
fn record_review_route(outcome: ReviewOutcome) {
    match outcome {
        ReviewOutcome::Approved(_) => {
            prompt "Record approval.";
        },
        ReviewOutcome::NeedsRevision(feedback) => {
            prompt "Record revision feedback: ${feedback}.";
        },
        ReviewOutcome::Cancelled => {
            prompt "Record cancellation.";
        },
    }
}
```

By contrast, the `match` in `route_review` is a value-producing expression and
its selected arm supplies the function's `Draft` result.

Numeric conversion, precedence, list length, and dynamic indexing support
bounded deterministic traversal without hiding model work:

```gantry
fn average(scores: List<Float>) -> Option<Float> {
    if scores.len() == 0 {
        return None;
    }

    let mut index: Int = 0;
    let mut total: Float = 0.0;

    while index < scores.len() {
        total += scores[index];
        index += 1;
    }

    Some(total / scores.len().to_float())
}

fn exact_count(value: Float) -> Option<Int> {
    value.to_int()
}
```

The explicit empty-list branch keeps a normal absence case in the value domain
rather than turning it into a checked-arithmetic runtime failure.

### 14.4 Inherent methods and scoped agent selection

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
fn prepare_label(mut topic: String, sequence: Int) -> String {
    topic = topic.trim().to_lowercase();
    topic += " #";
    topic += sequence.to_string();
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
`replace` uses nonoverlapping matches. The following deterministic workflow
keeps the example in a valid executable scope:

```gantry
fn inspect_text() -> Tuple<Int, List<String>, String> {
    let scalar_count: Int = "é".len();
    let parts: List<String> = ",a,,b,".split(",");
    let revised: String = "aaaa".replace("aa", "b");
    // scalar_count is 1, parts is ["", "a", "", "b", ""], revised is "bb".
    (scalar_count, parts, revised)
}
```

### 14.6 Reusable model judgments and conditional chains

```gantry
fn is_complete(report: Report) -> Decision {
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

The `decide` operation in the `else if` condition receives only its explicit prompt, inputs, and canonical session transcript. The `else if` syntax
does not create a hook by itself. Conditional blocks do not themselves form
value expressions in v1, so each selected branch returns its value explicitly.

An early decision return is also valid:

```gantry
fn should_stop(report: Option<Report>) -> Decision {
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
A positive source limit fails with `loop-limit-exhausted` before another body entry.
Omitting the limit or writing `limit = unbounded` removes only that source-level
limit; mandatory execution budgets still apply.

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
// Inside an executable block where `pair` is in scope:
let (headline_text, full_report): Tuple<String, Report> = pair;
```

The destructuring is deterministic and does not invoke an operation hook.

### 14.10 `joinall()`, Unit tasks, and detachment

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
    spawn security_audit {
        prompt "Perform a security audit of ${report}.";
    }

    spawn style_audit {
        prompt "Perform a style audit of ${report}.";
    }

    joinall();
}
```

Named joins can wait for a selected set of Unit tasks and return `()`:

```gantry
fn audit_selected(report: Report) {
    spawn security_audit {
        prompt "Perform a security audit of ${report}.";
    }

    spawn style_audit {
        prompt "Perform a style audit of ${report}.";
    }

    join(security_audit, style_audit);
}
```

Background work is explicit. `detach(background)` consumes the scoped handle
and transfers the task to its originating execution. The task may outlive the
current foreground workflow or process and remains recoverable from its
journal until terminal execution:

```gantry
fn launch_background(report: Report) {
    if decide "Should a background audit be launched for ${report}?" {
        spawn background {
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
    spawn audit {
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

struct Report {
    title: String,
    summary: String,
    sources: List<Source>,
}

action read_only web_search(request: SearchRequest)
    -> Result<List<Source>, SearchFailure>;
action non_idempotent publish(report: Report) -> Unit;

fn research(query: String) -> Report {
    let request: SearchRequest = SearchRequest { query };
    let search: Result<List<Source>, SearchFailure> =
        action web_search(request);

    let sources: List<Source> = match search {
        Ok(value) => value,
        Err(error) => prompt "Recover source material after the search failure."
            using { error, query }
            -> List<Source>,
    };

    let report: Report = prompt "Write a sourced report." using {
        query,
        sources,
    } -> Report;

    action publish(report);
    report
}
```

`using` carries ordered typed values separately from rendered prompt text.
`${...}` remains available when exact textual placement is meaningful. The
action declaration, action invocation, and result contract are visible in
source; model hooks are externally read-only; state-changing capabilities require a
declared action recovery class.

### 14.13 Explicit operation failure handling with `attempt`

`attempt` converts the operation failures defined in Section 5 into an
explicit `Result<T, OperationError>`. The wrapped `prompt`, `decide`, or
`action` remains visible and keeps its normal validation and retry policy:

```gantry
fn summarize_with_fallback(report: Report) -> String {
    let outcome: Result<String, OperationError> =
        attempt prompt "Summarize the supplied report."
            using { report }
            -> String;

    match outcome {
        Ok(summary) => summary,
        Err(error) => prompt "Explain why no summary is available."
            using { report, error }
            -> String,
    }
}
```

The `Err` branch handles only failure of the first prompt. A failure from the
fallback prompt still propagates normally. `attempt` cannot wrap a workflow
call, a join, or a larger expression, and it does not catch deterministic,
journal, executor, event-persistence, invariant, or Gantry task-cancellation
failures. To handle an operation reached inside a workflow, place `attempt`
around that operation in the workflow body rather than around the call.

### 14.14 Common invalid forms and their corrections

The following non-normative excerpts collect syntax errors, analysis errors,
and syntactically valid forms that deterministically fail at runtime. Each
failing comment names its phase. Unless a snippet contains a module-level
declaration, each fragment is shown as if it appears inside an executable
block with the referenced bindings and types already in scope. Module-level
declarations are identified by their ordinary declaration syntax. Keeping
these boundaries visible is part of Gantry's clean-syntax goal.

An interpolation cannot contain a workflow or source-defined method call,
whether or not that call can reach a model operation:

```gantry
// Analysis error: workflow calls are not permitted inside interpolation.
prompt "Rewrite this critique: ${make_critique(report)}" -> Report

// Valid: operation order is explicit in separate source expressions.
let critique: String = make_critique(report);
prompt "Rewrite this critique: ${critique}" -> Report
```

An unannotated prompt returns `Unit`. `Decision` is first-class but is not a
`String` or an ordinary `Bool`:

```gantry
// Analysis error: the prompt returns Unit, not String.
let summary: String = prompt "Summarize the report.";

// Valid: the result contract is visible.
let summary: String = prompt "Summarize the report." -> String;

// Analysis error: the declared binding type is wrong.
let answer: String = decide "Is the report complete?";

// Valid: retain the sealed Decision and use it as a condition.
let answer: Decision = decide "Is the report complete?";
if answer {
    prompt "Publish the report.";
}

// Valid: project its controlling Bool when deterministic composition is needed.
let approved: Bool = answer.decision;
```

Only `prompt` writes an output annotation at the operation site. A `decide`
always returns `Decision`, while an action invocation gets its result type
from the declaration:

```gantry
action read_only load_report(id: String) -> Report;

// Syntax error: `decide` has a fixed result type and no result annotation.
let answer: Decision = decide "Is the report complete?" -> Decision;

// Syntax error: the action declaration, not the invocation, carries `-> Report`.
let report: Report = action load_report(report_id) -> Report;

// Valid: both result types are already determined.
let answer: Decision = decide "Is the report complete?";
let report: Report = action load_report(report_id);
```

A previously evaluated non-`Unit` value cannot be “used” by writing it as a
standalone statement. Every ignored non-`Unit` result requires `discard`:

```gantry
// Analysis error: this performs no operation and does not emit the rationale again.
answer;

// Valid: consume the retained judgment in control flow.
if answer {
    prompt "Publish the report.";
}

// Also valid: deliberately execute a new judgment and discard its value.
discard decide "Record a fresh publication judgment.";
```

Any non-`Unit` expression, including an operation, requires explicit `discard`
when its value is intentionally ignored. Larger deterministic expressions obey
the same type-directed rule:

```gantry
// Analysis error: the arithmetic result is discarded by the outer expression.
(prompt "Return the next count." -> Int) + 1;

// Valid: bind the operation result, then make the computation explicit.
let next: Int = prompt "Return the next count." -> Int;
let incremented: Int = next + 1;

// Also valid: intentionally discard the operation result itself.
discard prompt "Return the next count." -> Int;
```

Harness actions cannot be called with ordinary workflow-call syntax, even
when an action and workflow would otherwise have similar signatures:

```gantry
action non_idempotent publish(report: Report) -> Unit;

// Analysis error: an action declaration is not an ordinary callable workflow.
publish(report);

// Valid: the integration boundary remains explicit.
action publish(report);
```

String operations never perform implicit conversion, and empty split or
replacement patterns are deterministic runtime errors:

```gantry
// Analysis error: `retry_count` is not implicitly converted to String.
let label: String = "attempt " + retry_count;

// Valid: conversion is explicit.
let label: String = "attempt " + retry_count.to_string();

// Runtime error: empty separators and replacement patterns are prohibited.
let pieces: List<String> = text.split("");
let expanded: String = text.replace("", "-");
```

Ordering and equality operators are intentionally non-associative so
model-authored source cannot accidentally rely on a surprising chained
comparison:

```gantry
// Syntax error: Gantry does not interpret this as a mathematical range test.
if minimum < value < maximum {
    prompt "Handle the in-range value.";
}

// Valid: each comparison is explicit and the Bool results are combined.
if minimum < value && value < maximum {
    prompt "Handle the in-range value.";
}
```

Struct constructors at control-flow boundaries are parenthesized so the first
unparenthesized `{` always begins the control-flow body or match arms:

```gantry
// Analysis error: the constructor brace conflicts with the `if` body boundary.
if Policy { enabled: true }.enabled {
    prompt "Apply the policy.";
}

// Valid: grouping makes the complete condition explicit.
if (Policy { enabled: true }).enabled {
    prompt "Apply the policy.";
}
```

Task handles are linear ownership markers rather than ordinary values. Every
normal path leaving their scope must visibly join or detach them:

```gantry
// Analysis error: `audit` remains attached when the function returns.
fn start_invalid(report: Report) {
    spawn audit {
        prompt "Audit ${report}.";
    }
}

// Valid: background ownership is transferred explicitly.
fn start_background(report: Report) {
    spawn audit {
        prompt "Audit ${report}.";
    }
    detach(audit);
}
```

Consumption must also agree at control-flow merges. A handle cannot remain
attached on one incoming path after another path has consumed it:

```gantry
// Analysis error: `audit` is consumed only when `publish_now` is true.
spawn audit {
    prompt "Audit ${report}.";
}
if publish_now {
    join(audit);
}
join(audit);

// Valid: route first, then consume the still-attached handle once.
spawn routed_audit {
    prompt "Audit ${report}.";
}
if publish_now {
    prompt "Prepare immediate publication.";
}
join(routed_audit);
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

<a id="GNT-15.0"></a>

*This section is normative.*

This section collects the host capabilities implied by the runtime contract:
interpreter lifecycle, hook and session integration, cancellation, executor
services, journal storage, event delivery, configuration, protocol versioning,
thread safety, and protected-data handling. It does not introduce additional
Gantry source forms.

Interface requirements are capability-scoped as defined in Section 1. A
nondurable embedding omits journal storage, resume, migration, durable
observation, and delivery recovery. A concurrent embedding exposes task and
detachment lifecycle behavior only when it embeds the concurrent evaluator.
Sections 15.1 and 15.5 explicitly distinguish the durable and nondurable
execution paths; other clauses apply only when the embedded profile uses the
capability they govern.

Concrete Rust names and signatures MAY evolve during implementation, but a v1
embedding API MUST expose the following semantic interfaces without requiring
provider-specific or executor-specific types in Gantry programs:

The public operations named in this section are protocol operations, not
prescribed Rust method names. Their request and result envelopes belong to the
`gantry.embedding` protocol artifact defined in Section 15.8. That artifact
MUST define the required and optional fields and stable discriminants for
`ValidatePackage`, `AnalyzePackage`, `StartExecution`, `ResumeExecution`,
`CancelExecution`, `AwaitForeground`, `AwaitTerminal`, `QueryExecution`, and
`Shutdown`; the `IntegrationPreflight` operations `ResolveMappings`,
`ResolveSessions`, and `EstablishSession`; `CreateHook` and
`DispatchOperation`; journal ownership, read, commit, payload-resolution, and
release operations; and `DeliverEvent`. The prose below defines their
behavior. A publication that omits this artifact is a draft design and is not
independently sufficient for an embedding-profile interoperability claim.

### 15.1 Interpreter lifecycle

<a id="GNT-15.1"></a>

**Construction and operations.**

An `Interpreter` accepts a package root, an explicitly selected supported
   source-language version, interpreter configuration (which includes the
   executor adapter), a hook factory, an `IntegrationPreflight` implementation,
   zero or more event sinks, and, for a durable embedding, journal storage. The
   hook factory MAY also
   implement `IntegrationPreflight`, but the interpreter MUST have an
   explicit reference through which it can invoke the mapping, root-session,
   and reusable-session operations in Section 15.2. Every evaluator embedding
   MUST expose syntax-only validation, semantic analysis, execution, execution
   cancellation, and terminal asynchronous shutdown operations. A durable
   embedding MUST additionally expose resume. Dry-run, analysis, and new
   execution MUST use the selected source-language version. Resume MUST use
   the version stored in the execution-start record and MUST reject an
   incompatible caller selection as a resume-start compatibility failure.
   Execution cancellation accepts an execution ID and a `CancellationReason`, is
   idempotent, and implements Section 10 rather than requiring the embedder to
   manipulate executor handles directly. A resume request MUST identify the
   execution or journal to load
   and provide a candidate package identity plus an optional versioned
   migration. Gantry MUST reconstruct state only from the authoritative
   durable record prefix and the exact verified recovery artifacts required by
   Section 11. It MUST obtain exclusive execution ownership before migration
   validation or recovered execution advances. If the candidate identity
   differs, Gantry MUST validate and commit the supplied migration under
   Section 11 before advancing; an absent or rejected migration is
   `source-or-configuration-incompatibility`.

**New execution and entry input.**

   In a durable embedding, a new-execution request MUST identify a fresh
   journal target through an embedder-supplied stable journal ID. Allocation of
   that ID and its storage target is an integration concern completed before
   calling Gantry. The API MUST return that journal identity even when startup
   fails, while it MUST return an accepted execution ID only after the
   execution-start record is durable. This distinction permits inspection or
   resume after an uncertain storage response without presenting an
   uncommitted candidate execution as accepted. In a nondurable embedding, no
   journal target is accepted or required, resume is unavailable, and a
   successful start returns an execution ID after preflight succeeds but before
   `main` is evaluated. That ID is valid only for the lifetime of the
   interpreter and MUST NOT be described as resumable. Execution accepts either
   no entry input or one raw byte sequence containing strict JSON as required
   by `main`; Gantry, rather than the embedder, performs the decoding, parsing,
   duplicate-member rejection, and schema validation defined in Section 4. It
   MUST also accept an optional
   `root_session` specification containing an embedder-chosen logical session
   ID, optional opaque integration lookup material, and an optional canonical
   transcript in the versioned turn format from Section 7. When the
   specification is present but its transcript is omitted,
   the transcript is the empty sequence. Gantry MUST validate and normalize
   that transcript before
   execution, commit it as the authoritative root-session state, and reject
   malformed or resource-limit-exceeding input as an integration-preflight
   start failure. The embedder MUST arrange for the hook integration to resolve
   the ID to an integration-owned conversational context whose semantic content
   matches the canonical transcript. Provider handles and lookup material are
   opaque and are not serialized; the canonical transcript is Gantry state and
   is serialized. Opaque lookup material is an initial-resolution hint only.
   An integration that accepts an embedder-supplied root MUST bind its
   integration-side context to the durable logical session ID and MUST be able
   to resolve that context on resume from the journaled session descriptor
   without the opaque hint. When the specification is absent, Gantry creates
   the fresh empty root session required by Section 7. Resume MUST restore the
   journaled root-session identity and transcript and MUST NOT accept a
   replacement or new opaque lookup material.
   Failure to resolve an embedder-supplied root
   session is an integration-preflight start failure for a new execution;
   failure to resolve any required journaled session is a nonterminal resume-
   start failure. Before resume creates recovered task hooks, the API MUST
   enumerate every journaled logical session that unfinished work will reuse
   through `inline` or as a session parent, including its parent and creation
   provenance, and require the integration to resolve the complete set as
   specified in Section 7. An operation-local session represented by a pending
   `session-use = create` redispatch is resolved by that idempotent request,
   not by this preflight; any enclosing or root session on which it depends
   remains in the preflight set. Resume MUST dispatch no hook when this
   preflight fails. The same `ResolveSessions` operation MUST receive and
   resolve an embedder-supplied root-session descriptor for a new execution.
   That descriptor contains the execution candidate's root logical session ID,
   `embedder-supplied` provenance, normalized canonical transcript, and the
   same optional opaque integration lookup material from `root_session`.
   Omitted lookup material is represented explicitly as absent. This field is
   always absent from a resume descriptor; resume resolution uses only the
   journaled logical session ID, canonical transcript, parent identity, and
   creation provenance. An integration that cannot later resolve an accepted
   root from those durable fields MUST reject it as unresolved during new-
   execution preflight rather than create a non-resumable durable execution.
   Resolution MUST be idempotent, MUST return a structured resolved or
   unresolved result,
   and MUST reattach a context with the same semantic transcript rather than
   create an empty replacement. An unresolved new root is
   an `integration-preflight` start failure; an unresolved reusable session on
   resume is an `unresolved-logical-session` resume-start failure. Neither
   result creates a hook or dispatches an operation.

**Start and resume outcomes.**

   `StartExecution` MUST return a `StartResult`. Its nondurable form is either
   `accepted(execution_id, handle)` or `rejected(start_failure)` and carries no
   journal ID. Its durable form always carries the caller-supplied stable
   journal ID and an acceptance union that is either
   `accepted(execution_id, handle)` or `rejected(start_failure)`; the rejected
   variant carries no execution ID. For a durable execution, the acceptance
   boundary is the committed execution-start evidence; for a nondurable
   execution, it is successful preflight. Syntax, analysis, entry-input,
   integration-preflight, initial journal-ownership, execution-start write,
   and required-event-delivery failures during pre-execution validation or
   analysis are start failures when applicable to the embedded profile.
   Returning the execution ID establishes an accepted execution handle; only
   the durable form is resumable. Acceptance does not by itself report that
   `main` has completed. The API MUST let the embedder asynchronously await or
   query the foreground outcome through that handle while detached work, when
   any, continues toward terminal execution state.
   `ResumeExecution` MUST likewise return either
   `accepted(execution_id, handle)` or `rejected(resume_start_failure)`. It
   returns the existing execution ID rather than allocating another. A
   resume-start failure under Section 7 leaves the execution's durable state
   unchanged and MUST permit a later corrected resume attempt.
   Once recovered interpretation begins, resume returns the same execution
   handle and foreground-outcome categories as a new execution. If foreground
   completion is already durable, resume MUST expose that preserved outcome
   without invoking `main` again while it recovers unfinished detached work.
   If terminal execution is already durable, resume performs only the unsettled
   event-delivery recovery permitted by Section 11 and exposes the existing
   terminal outcome without creating a task or dispatching a hook.

**Execution observation.**

   A typed foreground outcome carries its canonical value type, including
   `Unit`, or one runtime-error category defined in Section 7. A foreground
   outcome MAY be
   returned while explicitly detached tasks remain;
   the execution ID allows the embedder to correlate their later events and
   terminal state. Every evaluator embedding MUST support in-process foreground
   and terminal awaits. A durable embedding MUST additionally permit the
   embedder to query an execution's latest durable foreground and terminal
   states by execution ID. Foreground-await and terminal-await results MUST
   represent the Gantry language outcome separately from the
   `required-event-delivery-failure` barrier status. A delivery-barrier failure
   MUST NOT masquerade as, replace, or erase a durable foreground or terminal
   language outcome. Execution
   observation MUST distinguish `not-terminal`,
   `terminal(outcome, barrier_status)`, and
   `run-failed-nondurably(journal_error)`. The last state is returned by an
   in-process await when journal failure aborts the current run; it is not a
   durable execution state and a later query observes only the authoritative
   durable prefix. Separately from language outcome, the API MUST expose the
   in-process journal-owner status as `held`, `released`, or
   `release-failed(journal_error)`. This status is operational rather than a
   durable execution state: a release failure does not rewrite a terminal
   outcome or delivery-barrier result, and a later process determines ownership
   only through the storage fencing rules in Section 11. A terminal language
   outcome MUST distinguish success,
   detached-task failure, cancellation, and every runtime-error category that
   Sections 7 through 12 permit to be durably recorded as terminal. Journal
   failure is excluded because Sections 10 and 11 prohibit claiming a new
   durable terminal state after storage fails. The terminal-only categories
   are exactly `success` and `detached-task-failure`; all other durable failure
   outcomes use the applicable exact runtime-error category from Section 7.
### 15.2 Hooks and session integration

<a id="GNT-15.2"></a>

A `HookFactory` asynchronously creates an `OperationHook` for a supplied
   task context. The factory, or an `IntegrationPreflight` implementation owned
   by the same integration, MUST also validate the complete nonempty merged
   agent-name set and every declared canonical action signature, and MUST
   supply each corresponding mapping revision before a new execution begins.
   Its `ResolveMappings` operation performs that mapping validation. Its
   `ResolveSessions` operation MUST implement the structured logical-session
   resolution required by Section 15.1. For a new execution it
   resolves the optional embedder-supplied root descriptor, including its
   normalized canonical transcript; for resume it
   resolves the complete reusable-session descriptor set enumerated by Gantry.
   An empty agent or action declaration set requires no mapping or revision for
   that family. Before resume continues, that preflight MUST resolve every
   applicable active mapping and every reusable logical session descriptor
   enumerated by Gantry, including root, parent, and creation provenance.
   Operation-local sessions represented by pending `session-use = create`
   redispatches are excluded because the repeated idempotent operation request
   establishes or resolves them; their required enclosing and root sessions
   are not excluded. For a new execution, preflight failure is an
   integration-preflight start failure. For resume, it is the applicable
   nonterminal resume-start failure. It creates no `OperationHook` and MUST
   occur before `main` evaluation or recovered work. Successful preflight does
   not itself dispatch an operation.

   For a `gantry-created` root session, `EstablishSession` MUST let Gantry
   request establishment of one fresh empty integration-side
   conversational context for the generated logical session ID before that
   root or a session derived from it is first used. That request is session
   setup, not hook creation or model dispatch. Repeating it for the same
   execution and root ID MUST resolve the same context rather than create a
   replacement. The interface MUST return structured success or failure and
   MUST be safe to retry for the same execution and root ID. Gantry invokes it
   only after the execution-start record is durable; failure prevents hook
   creation and is the `logical-session-setup` runtime error defined in
   Section 7. An `embedder-supplied` root instead uses `ResolveSessions` as
   required by Section 15.1.

   `EstablishSession` MUST also establish every non-root
   logical session created outside an operation request, including lexical-
   block, loop, and automatic spawned-task sessions. Gantry supplies the
   durable session descriptor: execution and session IDs, `new` or `fork`,
   enclosing and root session IDs, creator task ID, and creation provenance.
   The integration MUST establish an empty conversation for `new` or a child
   conversation initialized from the identified enclosing session for `fork`.
   The call MUST be safe to repeat for the same execution and session ID and
   MUST resolve the same context across retry or process restart. Gantry makes
   the call only after the session-state record is durable and before the
   session's first model use or use as another session's parent. Operation-
   local `new` and `fork` sessions are instead established by the
   `session-use = create` operation request defined in Section 7; the companion
   call MUST NOT create a second context for them. Session establishment is
   not `OperationHook` creation and dispatches no Gantry operation.

   Gantry MUST call the factory lazily, at most once per Gantry task in one
   in-process run, immediately before that task's first hook dispatch; a task
   that performs only deterministic interpreter work does not require a hook.
   `OperationHook` asynchronously accepts the versioned request defined in
   Section 7 and a Gantry-owned cancellation token, and returns exactly one
   `Completed(raw_output)`, `Declined(reason)`, or
   `Failed(category, message)` outcome.
   `raw_output` is an uninterpreted byte sequence; Gantry owns UTF-8 decoding,
   JSON parsing, schema validation, and repair retries. A failure outcome also
   carries the exact typed category from Section 7 rather than requiring text
   parsing. Hook futures MUST be
   `Send`; one hook instance is used serially for one Gantry task.
   Returning `Completed(raw_output)` means the integration considers the
   operation complete even when the bytes later fail Gantry validation.
   Provider transport failures, timeouts, policy denials, cancellation, and
   integration-internal retry exhaustion MUST instead be represented as
   `Failed(category, message)` with the category defined in Section 7; they MUST NOT
   be encoded as synthetic malformed model output merely to enter Gantry's
   structured-output retry path.
### 15.3 Cancellation

<a id="GNT-15.3"></a>

A cancellation token is cloneable, safe to observe from multiple threads,
   and transitions monotonically from active to cancelled. Cancellation does
   not itself constitute a hook outcome; an integration that stops work after
   observing cancellation returns `Failed` or lets Gantry surface cancellation
   according to the runtime state. `CancellationReason` is a versioned record
   containing a stable category (`caller`, `deadline`, `shutdown`, or
   `runtime`), an optional diagnostic message subject to the configured maximum
   String scalar count, and an optional causal identity discriminated as an
   operation ID or task ID. Gantry MUST use the same canonical record in the
   cancellation request and resulting journal and event evidence. Protected
   content MUST be carried by a protected reference rather than copied into
   the diagnostic message.
### 15.4 Executor services

<a id="GNT-15.4"></a>

Every evaluator embedding's executor adapter provides asynchronous sleep and
   explicit scheduler-yield capabilities. An embedding claiming the
   concurrent-evaluator profile MUST additionally provide task spawn, join,
   and abort. Every evaluator adapter MUST also provide a
   cancellation-aware race against a monotonic deadline. Completion wins when
   the raced future completes no later than the deadline; otherwise timeout
   wins, the adapter stops polling the losing future, and Gantry may invoke an
   available cancellation mechanism. `sleep(0)` is not a substitute for
   `yield_now` unless the adapter explicitly guarantees one scheduler yield.
   Gantry MUST use these capabilities rather than constructing a hidden Tokio
   or other provider runtime. Executor handles and errors MUST be wrapped so no
   specific executor type appears in the language-facing API.

   Executor-neutral runtime services MUST additionally provide the current UTC
   time for RFC 3339 event timestamps and uniform sampling of an integer from
   an inclusive bounded range for `full` jitter. Deadline and elapsed-time
   behavior MUST use a monotonic clock and MUST NOT be affected by wall-clock
   adjustment. A clock, timer, or sampling failure is an executor runtime error;
   implementations MUST NOT silently substitute a fixed delay, reuse a stale
   timestamp, or weaken a timeout. Selected retry delays and created event
   timestamps are persisted where Sections 8, 11, and 12 require and are not
   regenerated during recovery.
### 15.5 Journal storage

<a id="GNT-15.5"></a>

This interface is REQUIRED only for an embedding that includes the
durable-runtime profile. Journal storage asynchronously provides durable-prefix
   reads, exclusive owner acquisition and release with fencing, and atomic
   `commit(batch)` with the behavior in Section 11. An adapter MAY implement
   commit with an append
   log and durability barrier, transactions, snapshots, group commit, or an
   equivalent primitive; the physical mechanism is not part of the embedding
   contract. Every commit MUST be associated with the current opaque ownership
   token so a superseded process cannot advance the journal. A batch contains
   one or more unfinalized versioned logical evidence bodies without evidence
   IDs or sequence numbers and MAY contain protected payload entries. Each
   protected payload entry contains a caller-assigned stable reference key
   unique within the journal, its protected-data class, and its exact bytes.
   A logical evidence body in the same or a later batch refers to that key.
   Commit MUST reject a duplicate key with different class or bytes and MUST
   atomically store every new payload before any reference to it becomes
   visible. Repeating the same key, class, and bytes is idempotent.
   Commit atomically assigns evidence IDs and sequence numbers, stores the
   finalized immutable envelopes and payload entries, and returns a receipt
   containing the assigned stable evidence IDs and contiguous sequence range
   from the per-journal linearizable ordering. A read returns those finalized
   immutable envelopes in sequence order together with the committed-through
   sequence and supports continuation after a supplied sequence. Journal
   storage MUST also resolve a protected payload by journal ID and stable
   reference key for Gantry's capability-filtered event delivery. Resolution
   returns the exact stored class and bytes or a structured missing-payload
   error; a missing payload referenced by retained evidence is malformed
   durable history. Compaction or deletion MUST retain a payload while any
   retained evidence refers to it or Section 12 still requires it for an
   unsettled delivery obligation. Owner release invalidates the supplied
   fencing token atomically and MUST NOT commit, update, or delete logical
   evidence or protected payloads.
   Storage errors and malformed or noncontiguous durable histories are never
   retried as model-output failures and MUST surface as journal failures.
   Sections 11 and 15.1 classify them as start or resume-start failures before
   interpretation begins and as journal runtime errors afterward.

### 15.6 Event delivery

<a id="GNT-15.6"></a>

Each event sink declares a stable identity, its required/best-effort class,
   raw-output capability, enabled redaction policy, and retry policy. The v1
   redaction policy resolves to explicit Boolean capabilities for
   `operation_request_content`, `operation_result_content`,
   `integration_diagnostics`, and `source_snippets`; raw integration output
   remains governed by the separate raw-output capability. Their protected
   payload classes are defined in Section 12, item 4. The sink configuration
   MUST expose both its policy ID and these resolved values. Gantry MUST freeze
   the resolved capability values, together with the policy ID, in every event
   obligation. Recovery and delivery use the frozen values rather than
   reinterpreting the policy ID under current host configuration. The policy
   ID is audit metadata and MUST NOT be the sole semantic representation of
   protected-data access. Stable
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
### 15.7 Configuration

<a id="GNT-15.7"></a>

Interpreter configuration MUST include the default model-output
   retry limit, the default action-output retry limit, their backoff policy,
   event-delivery retry and attempt-timeout defaults,
   executor adapter, graceful-shutdown timeout, post-cancellation drain
   duration, maximum entry-input bytes, maximum hook-output bytes, maximum
   value nesting depth, maximum value nodes, maximum String scalar count,
   maximum List item count, maximum workflow-call depth, maximum tasks per
   execution, maximum deterministic transitions per execution, maximum logical
   operations per execution, maximum loop body entries per task, and the finite
   nonzero deterministic-transition yield quantum
   required by Section 3. These value and interpreter limits MUST satisfy
   Sections 3, 5, 8, 10, and 11. Implementations
   MUST accept directive integers through `2^63 - 1` and MUST reject larger
   directive tokens during analysis. First-class `Int` values used for list
   projection retain the exact range in Section 5; tuple projection requires
   an in-bounds nonnegative `Int` literal. The v1 defaults are 30 seconds for
   each event-delivery attempt, 30 seconds for graceful shutdown, and 5 seconds
   for post-cancellation drain. Event-delivery attempt timeouts MUST remain
   finite and positive. Configured retry limits and whole-microsecond duration
   values MUST be no greater than `2^63 - 1`. Embedders MAY override shutdown
   and drain with finite nonnegative durations; zero requests immediate
   cancellation or immediate return after cancellation, respectively. The
   deterministic-transition yield quantum counts transitions, MUST be no
   greater than `2^63 - 1`, and remains subject to the nonzero requirement in
   Section 3.
### 15.8 Protocol versioning

<a id="GNT-15.8"></a>

All public protocol envelopes MUST carry a major and minor version. A major
   mismatch is incompatible and MUST be rejected. Every protocol definition
   MUST identify which fields are required and which are optional. An
   implementation MAY accept a newer minor version only after selecting the
   published protocol definition for that exact major and minor version and
   determining from that definition that every unknown field is optional and
   ignoring it does not change the meaning of known fields. A receiver without
   that exact definition MUST reject the newer minor version; an instance
   cannot self-attest that its unknown fields are optional. Unknown required
   fields and unknown enum variants MUST be rejected.

The v1 publication MUST provide canonical JSON Schemas and RFC 8785 golden
encodings for hook requests/outcomes, canonical transcripts, events,
diagnostics, configuration, canonical IR/source maps, migrations, journal
logical evidence, and the conformance manifest. It MUST provide a versioned
requirement-ID registry and
an executable conformance corpus covering lexer/parser boundaries, positive
and negative static semantics, schema/hash goldens, RFC 8785 differential
cases, cross-implementation logical traces, crash injection at every commit
cut, idempotency and unknown outcomes, Unicode security, workflow migration,
and property/model tests for linear task ownership and single result
consumption. A profile claim maps every applicable requirement ID to at least
one corpus test and publishes the results.

The publication index MUST expose at least these stable artifact IDs and one
versioned URI for each:

| Artifact ID | Required contents |
| --- | --- |
| `gantry.embedding` | Lifecycle, preflight, hook, cancellation, executor, journal, event-delivery, and observation request/result envelopes from Sections 15.1 through 15.7 |
| `gantry.values` | Canonical value, transcript, diagnostic, event, configuration, and protected-reference schemas |
| `gantry.ir` | Canonical core IR and source-map schemas and desugaring fixtures |
| `gantry.journal` | Logical evidence, migration, ownership, and commit schemas |
| `gantry.conformance` | Requirement-ID registry, manifest schema, corpus index, and published results |

Each artifact MUST identify its protocol major and minor version, applicable
profiles and requirement IDs, canonical JSON Schemas, and golden encodings.
Sections 15.1 through 15.7 refer to these logical IDs; repository paths and
transport URLs may change only through a new publication index that preserves
their versioned identities.
### 15.9 Thread safety

<a id="GNT-15.9"></a>

Integration-provided hook factories, executor adapters, journal stores, and
   event sinks MUST be `Send + Sync` and safe for Gantry to access from its
   multithreaded tasks. This is a baseline requirement of every Rust embedding-
   profile implementation, including one that embeds only the sequential
   evaluator profile; it is not a separate unnamed conformance profile. An
   individual `OperationHook` MUST be `Send` but need not be `Sync`, because
   Gantry owns it within one task and invokes it only serially. Futures returned
   by these interfaces MUST be `Send` for the lifetime of their borrows. Gantry
   MUST package all borrowed state into owned task state before submitting a
   `Send + 'static` future to the executor.
### 15.10 Protected data

<a id="GNT-15.10"></a>

Source, entry input, interpolation arguments, named inputs, action
    arguments, rendered prompts, session identifiers, raw hook output,
    normalized values, decision rationales, decline reasons, hook-failure
    messages, journals, and protected event payloads MUST be treated as
    potentially sensitive integration data. Gantry MUST NOT copy protected
    payloads into default diagnostics, display strings, or sinks that lack the
    applicable capability defined in Section 12, item 4. An embedder MUST
    control access to
    journal storage and payload references and MUST define retention and
    deletion policy for them. It MUST also control whether a diagnostic
    consumer may receive source snippets; absent an explicit source-disclosure
    policy, Gantry diagnostics MUST expose source locations and spans but not
    copied source text. At-rest encryption, credential management, and operator
    authorization remain deployment concerns, but an implementation MUST
    provide enough separation between ordinary diagnostics and protected
    records for an embedder to enforce those policies without parsing free-form
    text.

Public protocol envelopes use UTF-8 JSON validated by the published canonical
schemas and RFC 8785 when an identity or golden byte sequence is required.
Concrete Rust layouts and private storage encodings remain implementation
choices. Independent implementations that support the same protocol major
version MUST interoperate on canonical public envelopes and canonical IR;
private database pages and executor objects are never portable artifacts.
