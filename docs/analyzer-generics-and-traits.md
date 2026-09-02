# Analyzer generics and traits boundary

The analyzer resolves the parametric syntax described in
[`frontend-generics-and-traits.md`](frontend-generics-and-traits.md) into
deterministic binder and type facts. This document describes the implemented
static boundary for generic declared types, free workflow calls, coherent
user-trait implementations, and concrete static trait calls. `SPEC.md` remains
normative.

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

## Portable limits and diagnostics

Public analysis must call `analyze_package_types_with_limits`. The analyzer
shares one activity-scoped policy across modules and charges:

- inferred and substituted descriptor depth against
  `maximum_constructed_type_depth`;
- each unique closed generic declared application against
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

This analyzer stage selects user-defined implementations for concrete calls,
but it does not yet check every generic callable body parametrically, enumerate
the complete reachable executable-instantiation closure, emit concrete generic
schemas, or monomorphize executable code. Packages with generic templates
therefore retain generic and trait analysis facts but do not publish a closed
generic executable projection from this stage. Those remaining contracts are
owned by the subsequent generic-body and concrete-artifact stages.
