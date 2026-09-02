# Generics and traits

This guide describes Gantry's source-facing generic types, generic workflows,
and statically selected traits. `SPEC.md` is normative; this guide focuses on
how to author packages and interpret diagnostics.

## Complete example

The package in [`examples/generics-and-traits/`](../examples/generics-and-traits/)
is analyzed and executed by the conformance suite. Run it with:

```sh
just run -- analyze --json examples/generics-and-traits
just run -- run examples/generics-and-traits
```

It demonstrates generic structs and enums, inferred and explicit type
arguments, a `where` predicate, static trait dispatch, and matching a concrete
generic enum. Its result is the JSON string `"envelope"`.

## Declared types and applications

A struct or enum may declare one or more type parameters:

```rust
struct Envelope<T> {
    value: T,
}

enum Outcome<T, E> {
    Ready(T),
    Failed(E),
}
```

Every runtime use is complete and concrete, such as `Envelope<Report>` or
`Outcome<Envelope<Report>, String>`. Gantry does not expose partially applied
types, higher-kinded parameters, aliases, or type-level values.

Constructors use an explicit complete argument list when context does not
determine one:

```rust
let wrapped: Envelope<String> = Envelope::<String> { value: "ready" };
let result: Outcome<String, String> = Outcome::<String, String>::Ready("ok");
```

Patterns name the same complete enum application:

```rust
match result {
    Outcome::<String, String>::Ready(value) => value,
    Outcome::<String, String>::Failed(error) => error,
}
```

## Generic workflows and inference

Functions and methods may declare type parameters and trailing `where`
predicates:

```rust
pure fn preserve<T>(value: T) -> T {
    value
}
```

Type arguments may be inferred from receivers, arguments, fields, payloads,
and an expected result type. Use turbofish syntax when you want to make the
complete substitution explicit:

```rust
let inferred: String = preserve("value");
let explicit: String = preserve::<String>("value");
```

Inference is exact: it performs no coercion and never selects a trait
implementation to guess a missing type. `main`, actions, action invocations,
and public entry signatures are not generic and cannot contain free type
parameters.

## Traits, implementations, and lookup

A source trait contains receiver methods. It has no associated types,
associated constants, supertraits, default bodies, trait objects, vtables, or
runtime reflection:

```rust
trait Summarize {
    pure fn summarize(self) -> String;
}
```

Implementations must provide every method exactly once with the same receiver,
generic arity, parameters, result, predicates, and a compatible effect set:

```rust
impl<T> Summarize for Envelope<T>
where
    T: Summarize,
{
    pure fn summarize(self) -> String {
        "envelope"
    }
}
```

Postfix lookup considers inherent methods first. Otherwise it considers only
module-local or imported traits containing the member and requires one unique
selected implementation. A qualified call can state trait and method
arguments independently:

```rust
Summarize::summarize(value)
```

`Self` is contextual. In a trait it denotes the eventual receiver; in an
implementation method it denotes that implementation's receiver. It is valid
only in method signatures, method `where` clauses, and method bodies. It is
not a source-declared parameter and cannot appear in an implementation head or
an unrelated item.

Implementation overlap is conservative and source-order independent. If two
freshened heads unify, `where` predicates do not make them disjoint and Gantry
reports `overlapping-implementation` or `overlapping-inherent-method` rather
than choosing one by declaration order.

## Effects and operation boundaries

Generic bodies have conservative template effects. Each retained concrete
callable receives its exact closed transitive effect set. A `pure` declaration
must remain effect-free for every admitted substitution.

Trait dispatch itself is ordinary direct workflow dispatch. It creates no
model request, action request, event, or journal record. Only explicit
`prompt`, `decide`, and `action` expressions cross the integration boundary.
At entry, operation, capture, return, join, event, journal, and recovery
boundaries, values and generated schemas use complete concrete descriptors.

The sealed capabilities `Equatable`, `Interpolatable`, and `ExternalValue`
are compiler-owned structural judgments. Source cannot declare or implement
them. A closed application satisfies one only when its complete structure
satisfies the corresponding rules.

## Recursion and limits

Direct generic recursion is regular: a recursive call must preserve the
callable's current type arguments. Type-changing recursion is rejected as
`polymorphic-recursion` with an `instantiation_witness` chain. Trait obligation
cycles are rejected as `cyclic-trait-obligation` with an `obligation_chain`;
cycles never prove a bound.

Every public package activity receives all twelve positive frontend-policy
fields. The checked sample [`examples/frontend-limits.json`](../examples/frontend-limits.json)
uses the reference CLI values. The fields are:

1. `maximum_package_files`
2. `maximum_source_file_bytes`
3. `maximum_package_source_bytes`
4. `maximum_source_tokens`
5. `maximum_diagnostics_per_activity`
6. `maximum_package_source_manifest_bytes`
7. `maximum_canonical_ir_bytes`
8. `maximum_source_map_bytes`
9. `maximum_generated_schema_bytes`
10. `maximum_constructed_type_depth`
11. `maximum_generic_instantiations_per_activity`
12. `maximum_trait_resolution_steps_per_activity`

Counters reset to zero for each admitted validate, analyze, start, or
candidate-source resume activity. Source-free durable recovery performs no
analysis and consumes none of them. Reused instantiation keys are not charged
twice; memoized trait queries still charge the lookup but not skipped work.
The three generic failures are `constructed-type-depth-limit`,
`generic-instantiation-limit`, and `trait-resolution-step-limit`.

These are deterministic logical-work limits, not package semantics, durable
execution identity, allocator-byte limits, process RSS limits, or a portable
host-out-of-memory policy. All values are in `1..=2^63-1`; Gantry defines no
portable defaults. See [`frontend-resource-policy.md`](frontend-resource-policy.md)
for charging and applicability details.

## Diagnostics

Use `gantry analyze --json` for stable machine fields. Human messages may
improve, but diagnostic code, phase, category, severity, primary byte span,
related spans, and required fields are the portable interface. Selection and
construction failures are reported before later body or effect failures when
the precedence rules require it.

Checked invalid packages are provided under
[`examples/generics-and-traits-invalid/`](../examples/generics-and-traits-invalid/):

| Package | Primary diagnostic | Required evidence |
| --- | --- | --- |
| `incomplete-inference` | `incomplete-type-inference` | `main.gnt` bytes `62..74` |
| `cyclic-obligation` | `cyclic-trait-obligation` | bytes `476..481`, plus `obligation` and complete `obligation_chain` fields |
| `duplicate-parameter` | `duplicate-type-parameter` | bytes `15..16`, plus the first declaration at bytes `12..13` as a related span |
| `polymorphic-recursion` | `polymorphic-recursion` | bytes `19..23`, plus complete `instantiation_witness` |

Related spans identify declarations, binders, predicates, or competing
implementations when those entities exist. Consumers should not parse display
text to recover this information.

## Runtime and durable behavior

Analysis closes every reachable application and selects direct call targets
before execution. The evaluator contains no type inference, bound solver,
coherence pass, implementation lookup, dictionary dispatch, or fallback
monomorphizer. Concurrent captures and joins retain complete descriptors.
Durable recovery authenticates retained canonical IR, concrete schemas,
package manifest, source map, and executable projection, then reconstructs the
same closed program without parsing source or repeating trait selection.

See [`sequential-generics-and-traits.md`](sequential-generics-and-traits.md),
[`concurrent-generics-and-traits.md`](concurrent-generics-and-traits.md), and
[`durable-generics-and-traits.md`](durable-generics-and-traits.md) for those
runtime boundaries.

## Deliberate exclusions

Gantry v1 does not provide variadics, higher-kinded parameters, specialization,
negative bounds, user-defined sealed capabilities, default trait methods,
associated items, supertraits, trait values or objects, dynamic dispatch,
reflection, downcasts, implicit conversions, open runtime types, polymorphic
recursion, or compatibility migration from pre-adoption durable artifacts.

