# Analyzer package-validity argument

This document is the repository-owned static argument required for the Gantry
analyzer profile. It is bound to the exact `SPEC.md` revision recorded in
`protocol/conformance/analyzer-validity-v1.json` and is executable through
`crates/gantry-conformance/tests/analyzer_validity_model.rs`.

## Scope and claim

The argument covers static package validity only. It does not claim evaluator
progress, runtime type preservation, task scheduling, cancellation, accepted
operation results, recovery, or terminal uniqueness. Those properties belong
to later profile-specific arguments. The bounded model strengthens the written
argument but is not an unbounded proof.

For one syntax-valid immutable package snapshot, let the analyzer obligations
be:

1. **module-resolution-security** — the module graph, symbols, imports,
   references, no-shadowing rules, NFC rules, and identifier-security facts are
   deterministic and canonical;
2. **types-patterns-completion-schemas** — annotations, bodies, constructors,
   patterns, completion paths, entry boundaries, and generated schemas satisfy
   the exact closed type contracts;
3. **binder-substitution-well-formedness** — binders have stable lexical
   ownership and ordinals, and substitution is capture-avoiding, complete, and
   preserves canonical argument order;
4. **complete-unique-inference** — every retained generic call or constructor
   has one complete exact substitution derived only from admitted local facts;
5. **structural-capability-proof** — the compiler-owned capabilities are proved
   by their finite structural fixed points after substitution;
6. **trait-coherence-and-termination** — implementation heads are coherent,
   lookup is deterministic, and canonical memoized obligation resolution
   either terminates with one selection or a specified diagnostic;
7. **finite-monomorphization-closure** — canonical closed instantiation keys are
   interned once and recursive callable components preserve their substitution;
8. **linear-task-ownership** — every static handle has one path-consistent
   ownership state and no attached handle escapes its required scope;
9. **concrete-effects-and-purity** — direct concrete sites and call edges reach
   the least fixed point in canonical effect order, with `pure` assertions
   checked against the applicable conservative or exact result;
10. **concrete-schema-closure** — every public boundary root has one finite,
    deduplicated closed schema closure, including regular recursive references;
11. **diagnostic-precedence-and-witnesses** — diagnostics follow the specified
    precedence and canonical order and retain required bounded generic witness
    fields;
12. **closed-lowering-preservation** — lowering preserves concrete types,
    effects, operation and task sites, source origins, and direct call targets
    while publishing no open executable type or dynamic selection site; and
13. **bounded-artifact-admission** — schemas, package-source manifest, canonical
    IR, and source map are accepted only after their complete canonical bytes
    satisfy the configured positive limits.

A source-valid result requires all thirteen obligations. Any retained error
diagnostic makes the result source-invalid. A source-valid result contains the
schema inventory, manifest, canonical analysis IR, multi-origin source map, and
distinct closed executable projection. A source-invalid result never exposes
executable canonical IR or an execution-package identity. An artifact-limit
failure is an operational `frontend-resource-limit`, not a source-invalid
judgment.

## Assumptions and abstraction boundary

- The frontend supplied one syntax-valid, immutable, completely selected
  snapshot under finite source and diagnostic limits.
- The selected protocol versions and specification digest are the reviewed v1
  values checked by the repository protocol suites.
- Host allocation failure and an analyzer invariant panic are outside the
  portable static model. Safely detected portable artifact exhaustion remains
  in scope as an operational result.
- The model abstracts each obligation to pass or fail. It does not enumerate
  all Gantry programs, Unicode strings, type graphs, implementation heads, or
  filesystem states.
- The model has thirteen Boolean obligations, explores exactly 8,192
  combinations, and has maximum trace depth thirteen. The checked-in fixture
  records these bounds.
- Capture-avoiding substitution, inference uniqueness, coherence, obligation
  termination, and lowering preservation are unbounded written arguments
  supported by focused and metamorphic tests. The finite Boolean search is not
  used as their proof.

## Argument

`gantry-analysis` applies the obligations in dependency order: package
structure and references; binder and type-expression construction; declaration
and body typing; complete inference; structural and user-trait proofs;
coherence; parametric body checks; finite instantiation closure; concrete
effects; completion, pattern, and ownership checks; schema closure; then
artifact lowering. Diagnostics are sorted, deduplicated, and charged against
the shared activity counter before status is decided. Thus later ordering
cannot erase an earlier error.

Schema generation and executable lowering are gated by the absence of semantic
errors. Canonical artifact constructors independently reject noncanonical
order, missing direct targets, open descriptors, malformed source-origin sets,
and over-limit complete encodings. Consequently, a returned source-valid
package has passed every modeled obligation, while source-invalid and
operational results cannot fabricate executable canonical IR.

Canonicalization is intentionally narrower than source equivalence. The public
lowering suite proves that comments and layout may change the source manifest
while preserving canonical IR, and that an edit to a prompt literal changes
canonical IR. The bounded model replays both the cosmetic pair and the semantic
negative control. Its metamorphic cases additionally prove that type-parameter
alpha-renaming, independent implementation declaration order, and predicate
source order leave canonical analysis IR unchanged.

The analyzer performs no integration action. Its direct dependency graph is
limited to `gantry-core`, `gantry-frontend`, `gantry-ir`, and `sha2`; it has no
dependency on host hooks, executor adapters, observation delivery, runtime, or
journal services. Its public entry points consume `CompletedSyntaxPhase` and
return analyzer-owned facts and artifacts synchronously. Public activities use
`analyze_package_types_with_limits` so semantic inference and capability proof
share the same complete `FrontendLimits` policy as parsing and artifacts.

## Lemma: Binder and substitution well-formedness

Every parameter belongs to one lexical binder and receives a declaration-order
ordinal. Canonical type expressions use binder depth and ordinal rather than
source spelling, so alpha-renaming does not alter identity. Substitution maps
only parameters owned by the applicable declaration, implementation, trait, or
method binder; it preserves constructor shape and argument order, performs an
occurs check, and yields a runtime descriptor only after every parameter and
`Self` entry is replaced. Duplicate, shadowed, escaped, or unresolved
parameters therefore prevent the package-valid judgment before a concrete key
can be retained.

## Lemma: Complete and unique inference

Inference is an exact unification problem over explicit type arguments,
receiver and argument types, constructor members, and the available expected
result. No trait implementation, coercion, default argument, or global use may
supply a missing fact. Pairwise constraints either agree on one complete
substitution or produce the specified incomplete, ambiguous, or conflicting
diagnostic. Because substitution application is deterministic and trait
resolution starts afterward, each accepted generic site identifies one
canonical closed key.

## Lemma: Structural capability proof

`Equatable`, `Interpolatable`, and `ExternalValue` are not user-selected
implementations. After substitution closes the queried type, capability proof
visits its finite declared and built-in member graph in canonical order and
computes the specified greatest admissible structural component. Memoization
does not change charge units or results. A failed member prevents the enclosing
capability and emits the bounded obligation data required by the diagnostic
contract.

## Lemma: Trait coherence and termination

Coherence freshens and unifies implementation heads independently of source
order; any pair that can overlap is rejected before call-site selection.
Resolution then processes the finite canonical candidate set and substituted
predicate graph. Memoized completed obligations terminate repeated queries,
while re-entry of an active obligation produces `cyclic-trait-obligation`
instead of proving itself. Inherent precedence and qualified lookup narrow the
same deterministic candidate relation, so an accepted call has exactly one
selected implementation identity.

## Lemma: Finite monomorphization closure

The worklist key is the finite canonical tuple of template kind, template
identity, and ordered closed arguments. Equal keys are interned once, and each
retained body contributes a finite set of substituted direct edges. A recursive
callable component is admitted only when it preserves its own ordered
substitution; a type-changing cycle is rejected as `polymorphic-recursion`
with an instantiation witness. Under the configured finite instantiation limit,
the accepted worklist therefore reaches a finite fixed point.

## Lemma: Concrete effects fixed point

Parametric bodies are checked against only their declared predicate slots and
conservative trait method contracts. After static selection, every retained
call edge names a concrete callable. Effect inference is monotone union over a
finite effect lattice and finite closed call graph, so iteration terminates at
the unique least fixed point. Checking `pure` against that summary preserves
the package-valid judgment under recursion and selected implementation changes.

## Lemma: Concrete schema closure

Schema roots are the concrete entry, operation, action, event, journal,
recovery, and embedding boundary types exposed by analysis. Each root and
reachable declared application is keyed by its full closed descriptor; equal
applications share one definition and regular recursion uses canonical
`$defs`/`$ref` edges. Construction rejects an open descriptor or missing
definition before publication, so every accepted schema is finite and
contains no parameter expression.

## Lemma: Diagnostic determinism and witnesses

Analysis phases enforce the precedence relation before sorting diagnostics by
portable source span, code, and related identity fields. Generic failures name
their primary authored span and retain applicable binder, candidate,
instantiation, or obligation evidence. Instantiation and obligation chains end
at the first failure or repetition and are bounded by the same public activity
limits that bound the attempted work; no private truncation count is needed.

## Lemma: Closed lowering preservation

Lowering begins only after coherence, substitution, closure, effects, schemas,
and diagnostics have succeeded. It copies each concrete signature, direct
target, operation result, task site, effect summary, declaration, and canonical
origin set into the analysis IR and closed executable projection. Constructors
validate canonical ordering and direct-target closure. The executable
projection consequently contains neither `^` parameters nor templates,
dictionaries, vtables, candidate sets, or source-level resolution operations.

## Requirement and trace links

- Module graph, resolution, and security: `GNT-3.1`, `GNT-3.2`, and the clause
  keys in `protocol/conformance/analyzer-symbols-v1.json`.
- Types, patterns, completion, schemas, and inventories: the clause keys in
  `protocol/conformance/analyzer-types-v1.json` and
  `protocol/conformance/analyzer-workflows-v1.json`.
- Binder and substitution well-formedness: `GNT-3-F-GENERICS` and
  `GNT-5.20-parametric-types`.
- Complete exact inference: `GNT-3-T-GENERIC-CALL` and
  `GNT-5.20-parametric-types`.
- Structural capability proof: `GNT-5.20-parametric-types`.
- Coherent terminating trait selection: `GNT-3-F-TRAITS` and
  `GNT-6.12-static-traits`.
- Finite monomorphization: `GNT-3-F-INSTANTIATION`,
  `GNT-3-T-PARAMETRIC-PACKAGE`, and
  `GNT-4.17-generic-analysis-limits`.
- Concrete effects and schemas: `GNT-3-T-PARAMETRIC-PACKAGE`,
  `GNT-6.12-static-traits`, and `GNT-8.13-concrete-generic-schemas`.
- Deterministic generic diagnostics: `GNT-12.11-generic-diagnostics`.
- Linear ownership and existing effects: `GNT-10.5`, `GNT-10.6`, `GNT-10.8`,
  `GNT-6.5`, and their executable workflow evidence.
- Closed lowering, profile boundary, and public analysis result:
  `GNT-3.15-generic-profiles`, `GNT-3-T-PARAMETRIC-PACKAGE`, `GNT-12.9`,
  and the IR, lowering, package, and validity evidence manifests.
- Bounded artifacts: `GNT-3.11`, `GNT-4.17-frontend-resource-limits`, and
  `protocol/conformance/analyzer-lowering-v1.json`.
- Profile-scoped proof obligation: `GNT-3-D-PROPERTIES`, exercised by the
  bounded model and replay suite named above.

## Counterexample replay

The model fixture contains deterministic source cases for missing modules,
unresolved names, binder failure, incomplete inference, failed structural
capability proof, overlapping implementations, cyclic obligations,
polymorphic recursion, type/completion failure, leaked task ownership, failed
`pure` assertions, and artifact-limit exhaustion. Witness-bearing cases also
name the required structured field. Each case records the first
machine-readable diagnostic or operational code expected from the public
analyzer boundary. A future model or implementation change that alters one of
those outcomes must update the reviewed fixture and requirement evidence rather
than silently broadening this argument.
