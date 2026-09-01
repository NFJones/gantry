# Frontend generics and traits syntax

The frontend profile parses the integrated parametric-generics and
static-traits grammar without performing semantic analysis. It accepts generic
`struct`, `enum`, function, method, trait, and implementation declarations;
trailing `where` clauses; trait method `pure` or `effects { ... }` contracts;
applied value types; explicit `::<...>` arguments; qualified trait calls; and
generic enum constructors and patterns.

Angle-delimited type lists remain ordinary `<` and `>` tokens. The predictive
parser distinguishes them from comparison operators by grammar position, so
nested closers such as `List<Option<T>>` require no special shift token and may
contain comments or newlines. An explicit type-argument suffix is retained
only when followed by a call, constructor, or member selector.

`Self` is contextual type syntax. The frontend admits it only in method
signatures, method `where` clauses, and method bodies; it rejects `Self` in
declared types, actions, free functions, trait-level predicates,
implementation heads, and implementation-level predicates. The analyzer still
owns binder resolution, arity, inference, implementation selection, and bound
proofs. Other grammatical but semantically invalid packages continue to
receive a syntax-valid judgment.

Constructed type depth is enforced before a `ValueType` node is retained. A
leaf has depth one; a built-in or declared application has depth one plus the
maximum argument depth. The configured limit applies independently to
validate, analyze, start, and candidate-source resume activities, with the
stable failure code `constructed-type-depth-limit`. Parser work remains on an
explicit owned task stack, including deeply nested admitted types.

The complete source semantics, diagnostics, and excluded features remain
normative in `SPEC.md`. The later authoring guide will cover analyzer and
runtime behavior after those dependent implementation gates close.
