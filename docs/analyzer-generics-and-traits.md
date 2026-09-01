# Analyzer generics and traits boundary

The analyzer resolves the parametric syntax described in
[`frontend-generics-and-traits.md`](frontend-generics-and-traits.md) into
deterministic binder and type facts. This document describes the implemented
static boundary for generic declared types and free workflow calls. `SPEC.md`
remains normative.

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

fn inspect(value: Envelope<Node<String>>) {}
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
`unsatisfied-bound`, and `polymorphic-recursion`.

## Deliberate stage boundary

This analyzer stage does not select user-defined trait implementations, check
generic callable bodies parametrically, enumerate executable instantiations,
emit concrete generic schemas, or monomorphize executable code. Packages with
generic templates therefore retain generic analysis facts but do not publish a
closed executable projection from this stage. Those contracts are owned by the
subsequent trait-resolution, generic-body, and concrete-artifact stages.
