# Analyzer generics and traits boundary

The analyzer resolves the parametric syntax described in
[`frontend-generics-and-traits.md`](frontend-generics-and-traits.md) into
deterministic binder, type, callable-template, and closed-instantiation facts.
This document describes the implemented static boundary for generic declared
types and callable bodies, coherent user-trait implementations, concrete
static trait calls, reachable monomorphization, and exact concrete effects.
`SPEC.md` remains normative.

## Implemented judgments

- Every generic declaration owns a stable binder. Type parameters use their
  declaration-order ordinal in canonical `TypeExpression` values; source names
  are metadata and cannot escape, duplicate, or shadow an enclosing binder.
- Built-in and package-declared applications require exact arity. An open type
  remains analyzer-only; a runtime `TypeDescriptor` is produced only after one
  complete substitution closes every parameter.
- Generic free calls and struct or enum constructors use exact local
  unification. Constraints may come from explicit `::<...>` arguments, value
  arguments, initialized fields, payloads, and expected results. Inference has
  no coercions, default type arguments, overload guessing, or trait-driven
  guessing. These permitted local and expected constraints are gathered and
  exactly unified before candidate or trait-implementation selection.
- Receiver checks, capture and ownership analysis, effect and suspension
  analysis, and lowering consume the resulting exact value types; none may
  guess a missing value type. Lowering starts only after call and reachable
  package closure. This ordering preserves the fixed v1 literal types without
  adding defaulting and does not admit absent associated types or closure
  types.
- Trait contracts and implementation heads are retained in canonical path and
  implementation-identity order. Every implementation parameter must occur in
  its receiver or trait arguments. A trait implementation may target a
  package-declared type or a closed built-in type; naked parameters and open
  built-in receivers are rejected.
- Coherence freshens and pairwise-unifies receiver and trait-reference heads.
  Unifiable trait implementations are rejected regardless of source order or
  `where` predicates. Generic inherent implementations are rejected when
  unifiable heads provide the same method.
- Trait implementations must provide exactly the declared methods. Receiver
  form, method-generic arity, substituted parameter and result types, method
  predicates, and conservative effect bounds are checked exactly.
- Postfix lookup gives inherent methods precedence and otherwise considers
  only module-local or imported traits. A qualified `Trait::method(...)` call
  restricts lookup explicitly. Trait and method type arguments are inferred
  independently from the receiver, value arguments, and expected result, or
  supplied as complete independent lists.
- Concrete obligations use a canonical trait-and-outer-receiver candidate
  index. Trait and implementation predicates are expanded in canonical order;
  results are memoized, cache hits retain exact charging semantics, and an
  active obligation that re-enters itself is rejected with a bounded
  `cyclic-trait-obligation` chain.
- Declaration and callable bounds using the compiler-owned `Equatable`, `Interpolatable`,
  and `ExternalValue` capabilities are proved only after substitution is
  complete. Capability proof is structural, memoized, native-stack-safe, and
  deterministic across declaration order and cache hits.
  Primitive leaves use `TypeDescriptor::primitive_properties()` from the
  public IR API. It reports copyability, equality, numeric ordering,
  interpolation, external eligibility, and recovery projection separately.
  Structural descriptors return `None`: this API cannot infer declared
  fields, grant execution admission, or introduce affine values and loans.
  For declaration-aware inspection, `TypedPackage::type_capabilities` reports
  the three existing sealed capabilities for primitives and exact retained
  closed types, plus independent ownership, transfer, live-resource,
  source-protection, and value-recovery classifications. One componentwise
  fold over the retained instantiated stored-member graph derives all five;
  it reuses declaration substitution, recursive cache safety, depth checks,
  and the query's trait-resolution budget. Current v1 leaves are copyable,
  transferable only as isolated source-task captures, non-live-resource, and
  reconstructable through sealed value evidence. `Decision` and
  `OperationError` are source-sealed; an aggregate is source-sealed when any
  stored member is. This source type classification does not classify
  transport content as nonsensitive: SPEC section 15.10 still treats source,
  operation, normalized-value, journal, and protected-event data as
  potentially sensitive integration data. Capture eligibility grants no spawn
  authority, shared identity, host-thread safety, loan, release authority, or
  runtime recovery implementation.
  The query rejects invalid packages and unretained descriptors, uses fresh
  constructed-depth and trait-resolution limits on every query, and
  returns no partial report on exhaustion. Query results do not admit new
  types, grant authority, or establish durable execution eligibility.
  Depth checks also cover each expanded stored-member type, so a shallow
  nominal root cannot hide an over-depth field from the query policy.
  Compound successes that may depend on recursive back-edges are published
  only after the root proof succeeds; a failed or exhausted proof cannot
  leave a provisional success available to a later query.
  Both use instantiated stored fields and enum payloads: an unused phantom
  type argument does not by itself disqualify a declared value. Proof work is
  charged to the trait-resolution budget, including callable-bound checks.
  Generic methods on nongeneric receivers use the same substitution and bound
  checks as methods on generic receivers; path-form `impl` declarations do not
  turn their method parameters into monomorphic signatures. Empty receiver
  structs are valid zero-field values.
- Equality uses the same stored-member capability proof. Structs containing
  `Decision` cannot be compared, while unused phantom arguments do not affect
  equality eligibility. A generic body may compare a type parameter only
  when its declaration promises `Equatable`.
- Entry, action-result, and prompt-result boundary checks also prove
  `ExternalValue` over instantiated stored members. Phantom arguments do not
  disqualify an otherwise external value; stored sealed values do. These
  boundary proofs consume the shared trait-resolution budget.
- Generic field defaults are valid only when they hold for every admitted
  substitution. Generic enum constructors, payload bindings, redundancy, and
  exhaustiveness use the substituted closed enum application.
- A direct generic self-reference must preserve the same constructor and type
  parameter ordinals in the same order and remain guarded by `Option` or
  `List`. Type-changing, reordered, enum, and multi-declaration recursion are
  rejected.
- Every generic function and generic inherent or trait implementation method
  is checked parametrically, including unreachable declarations. The check
  uses rigid internal representatives and only the declaration's canonical
  predicates; those predicates supply trait-method slots without selecting a
  concrete implementation or retaining a synthetic instantiation.
  Calls in these bodies must also prove the callee's sealed capability bounds
  from the caller's declared predicates, even when no concrete call reaches
  the body. Later instantiation cannot repair a missing generic bound.
- Calls reached from non-generic roots seed a canonical worklist of closed
  generic free workflows, inherent methods, and selected trait methods.
  Substituted bodies extend the worklist transitively. Equal template and type
  argument keys are interned once, same-substitution recursion is finite, and
  type-changing recursion is rejected with a deterministic
  `instantiation_witness` chain.
- Each retained method receives its canonical closed identity, such as
  `<crate::Envelope<String>>::get` or
  `<crate::Envelope<String> as crate::Label>::label`. Substituted receiver and
  field shapes are used while checking its body, and inherent lookup continues
  to take precedence over trait lookup.
- Conservative template effects and exact concrete effects are retained
  separately. Exact effects are the least fixed point over the reachable
  closed call graph, including generic free workflows, generic inherent
  methods, and the implementation selected for each trait call.
- `TypedPackage` retains the complete analyzer result. The supported `gantry`
  facade exposes borrowed `AnalyzePackageArtifacts` and
  `AnalyzePackageGenericFacts` views, including complete substitutions,
  selected calls, exact effects, concrete schemas, source origins, and the
  distinct closed executable projection. Consumers do not need to parse
  display strings or rerun inference or trait selection.

For example, this declaration and use are valid:

```rust
struct Node<T> {
    value: T,
    next: Option<Node<T>>,
}

struct Envelope<T> where T: Equatable {
    value: T,
}

trait Label {
    pure fn label(self) -> String;
}

impl<T> Label for Envelope<T> where T: Equatable {
    pure fn label(self) -> String {
        "envelope"
    }
}

fn inspect(value: Envelope<Node<String>>) -> String {
    value.label()
}
fn main() {}
```

The application `Envelope<Node<Decision>>` is invalid because `Decision` is
not equatable, and `Option<Node<List<T>>>` inside `Node<T>` is invalid because
the recursive application changes its own substitution.

## Facade and CLI access

`AnalyzePackageResult::diagnostics()` returns syntax or analysis diagnostics
with stable phase, severity, category, code, primary and related spans, and
structured fields. For source-valid packages, `artifacts()` returns the
package-source manifest, canonical IR, source map, and concrete schema object;
`generic_facts()` returns typed generic facts and the closed executable
projection without copying their canonical data.

The CLI keeps its concise text mode and also supports deterministic structured
output:

```sh
gantry analyze --json [PACKAGE_ROOT]
```

The JSON document has format `gantry.analysis/v1`. It contains `status`, the
complete structured `diagnostics` array, and, for source-valid packages, the
four canonical analysis artifacts as JSON values. Source-invalid output uses
`null` for `artifacts`; operational failures remain separate CLI failures.

## Portable limits and diagnostics

Public analysis must call `analyze_package_types_with_limits`. The analyzer
shares one activity-scoped policy across modules and charges:

- inferred and substituted descriptor depth against
  `maximum_constructed_type_depth`;
- each newly retained canonical closed generic type or callable key against
  `maximum_generic_instantiations_per_activity`; and
- each obligation lookup, predicate expansion, and structural capability node
  or edge visit against `maximum_trait_resolution_steps_per_activity`.

Operational exhaustion uses `constructed-type-depth-limit`,
`generic-instantiation-limit`, or `trait-resolution-step-limit`. Source errors
use stable diagnostics such as `duplicate-type-parameter`,
`shadowed-type-parameter`, `escaped-type-parameter`, `type-argument-arity`,
`incomplete-type-inference`, `conflicting-type-inference`,
`unsatisfied-bound`, `invalid-implementation-head`,
`overlapping-implementation`, `overlapping-inherent-method`,
`implementation-method-mismatch`, `missing-implementation`,
`ambiguous-trait-method`, `cyclic-trait-obligation`, and
`polymorphic-recursion`.

## Deliberate stage boundary

The analyzer checks generic bodies, selects user-defined implementations,
retains the reachable closed type and callable instantiation closure, computes
exact concrete effects, emits concrete schemas, and publishes canonical
analysis and closed executable projections with multi-origin source maps. It
does not execute the projection, schedule tasks, invoke hooks, or reconstruct
durable state; those behaviors remain owned by evaluator-derived profiles.

The focused supported-path regression in
`crates/gantry-conformance/tests/validate_package.rs` compares the public
`validate_package_syntax` path with a manually driven
`PackageSyntaxWork::{begin, accept_acquisition, parse_next}` path using
`RootDirectorySourceProvider`. Concurrent independent analyses of multi-file
generic/recursive valid and inference-conflict invalid packages must retain
the same ordered structured diagnostics, closed types and executable
projection, and byte-identical canonical IR, generated-schema, package
manifest, and source-map outputs wherever those outputs are published.

This evidence qualifies resumable source acquisition and isolation between
independent concurrent package analyses only. It is not a cached incremental
analysis implementation, is not separate compilation, and does not establish
the complete `GNT-GP-TYPE-001` acceptance condition. Full-prefix, compacted-
prefix, and fresh-process recovery of generic artifacts remains covered by
`crates/gantry-conformance/tests/durable_start.rs`; this regression does not
duplicate or broaden that durable-recovery evidence.
