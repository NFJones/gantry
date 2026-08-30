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
3. **linear-task-ownership** — every static handle has one path-consistent
   ownership state and no attached handle escapes its required scope;
4. **effects-and-purity** — direct sites and call edges reach the least fixed
   point in canonical effect order, with contributing action paths retained and
   `pure` assertions checked against that result;
5. **canonical-lowering** — workflow facts lower in canonical path and
   structural-position order without adding, dropping, or reordering semantic
   sites; and
6. **bounded-artifact-admission** — schemas, package-source manifest, canonical
   IR, and source map are accepted only after their complete canonical bytes
   satisfy the configured positive limits.

A source-valid result requires all six obligations. Any retained error
diagnostic makes the result source-invalid. A source-valid result contains the
schema inventory, manifest, canonical IR, and source map; a source-invalid
result never exposes executable canonical IR or an execution-package identity.
An artifact-limit failure is an operational `frontend-resource-limit`, not a
source-invalid judgment.

## Assumptions and abstraction boundary

- The frontend supplied one syntax-valid, immutable, completely selected
  snapshot under finite source and diagnostic limits.
- The selected protocol versions and specification digest are the reviewed v1
  values checked by the repository protocol suites.
- Host allocation failure and an analyzer invariant panic are outside the
  portable static model. Safely detected portable artifact exhaustion remains
  in scope as an operational result.
- The model abstracts each obligation to pass or fail. It does not enumerate
  all Gantry programs, Unicode strings, type graphs, or filesystem states.
- The model has six Boolean obligations, explores exactly 64 combinations, and
  has maximum trace depth six. The checked-in fixture records these bounds.

## Argument

`gantry-analysis` applies the obligations in dependency order: package
structure and references; declaration and body typing; recursive and sealed
type checks; completion and pattern checks; ownership and effect inference;
schema/inventory construction; then artifact lowering. Diagnostics are sorted,
deduplicated, and charged against the shared activity counter before status is
decided. Thus later ordering cannot erase an earlier error.

Schema generation and executable lowering are gated by the absence of semantic
errors. Canonical artifact constructors independently reject noncanonical order
and over-limit complete encodings. Consequently, a returned source-valid
package has passed every modeled obligation, while source-invalid and
operational results cannot fabricate executable canonical IR.

Canonicalization is intentionally narrower than source equivalence. The public
lowering suite proves that comments and layout may change the source manifest
while preserving canonical IR, and that an edit to a prompt literal changes
canonical IR. The bounded model replays both the cosmetic pair and the semantic
negative control.

The analyzer performs no integration action. Its direct dependency graph is
limited to `gantry-core`, `gantry-frontend`, `gantry-ir`, and `sha2`; it has no
dependency on host hooks, executor adapters, observation delivery, runtime, or
journal services. Its public entry point consumes `CompletedSyntaxPhase` and
returns analyzer-owned facts and artifacts synchronously.

## Requirement and trace links

- Module graph, resolution, and security: `GNT-3.1`, `GNT-3.2`, and the clause
  keys in `protocol/conformance/analyzer-symbols-v1.json`.
- Types, patterns, completion, schemas, and inventories: the clause keys in
  `protocol/conformance/analyzer-types-v1.json` and
  `protocol/conformance/analyzer-workflows-v1.json`.
- Linear ownership and effects: `GNT-10.5`, `GNT-10.6`, `GNT-10.8`, `GNT-6.5`,
  and their executable workflow evidence.
- Canonical lowering and bounded artifacts: `GNT-3.11`,
  `GNT-4.17-frontend-resource-limits`, and
  `protocol/conformance/analyzer-lowering-v1.json`.
- Public source judgment and activity boundary: `GNT-12.9` and
  `protocol/conformance/analyzer-package-v1.json`.
- Profile-scoped proof obligation: `GNT-3-D-PROPERTIES`, exercised by the
  bounded model and replay suite named above.

## Counterexample replay

The model fixture contains deterministic source cases for missing modules,
unresolved names, type/completion failure, leaked task ownership, failed
`pure` assertions, and artifact-limit exhaustion. Each case records the first
machine-readable diagnostic or operational code expected from the public
analyzer boundary. A future model or implementation change that alters one of
those outcomes must update the reviewed fixture and requirement evidence rather
than silently broadening this argument.
