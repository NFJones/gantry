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
  guessing.
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
- Declaration bounds using the compiler-owned `Equatable`, `Interpolatable`,
  and `ExternalValue` capabilities are proved only after substitution is
  complete. Capability proof is structural, memoized, native-stack-safe, and
  deterministic across declaration order and cache hits.
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
