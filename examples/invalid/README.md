# Negative source corpus

These 28 packages intentionally fail parsing or analysis. Each package contains
`main.gnt`, a phase-specific `README.md` with an observed diagnostic and valid
correction link, and `case.json` with class `negative` and `expected_diagnostic`.
Existing examples outside this directory are correction references, not edits.

The shared runner in
[`support/mod.rs`](../../crates/gantry-conformance/examples/support/mod.rs)
requires `SourceInvalid` and exact membership of the named diagnostic code.
It does not require that this be the only diagnostic, and never executes an
invalid package. Codes were obtained by running the sources, not by inferring
diagnostic spellings from error descriptions. Parser traps deliberately assert
`unexpected-token`, not a nonexistent annotation/range/errors-specific code.

From the repository root, validate all packages or one package:

```sh
timeout 180 cargo run --offline -p gantry-conformance --example corpus -- --all examples/invalid
timeout 180 cargo run --offline -p gantry-conformance --example corpus -- examples/invalid/missing-annotation
```

A passing validation means the expected rejection occurred, not that the source
is valid. Each scenario has a 30-second deadline and its runtime shutdown is
bounded to one second. Frontend limits include 32 files, 1 MiB per file, 4 MiB
total source, 262,144 tokens, and finite parser/type/trait budgets. See the runner
for the complete constructor argument list; no runner or runtime limit is changed
by this corpus.

Coverage: missing annotation and unsupported range/errors syntax; duplicate
declarations, shadowing and unresolved imports; numeric, literal, list, index,
None and Option type errors; incompatible/nonexhaustive patterns, missing results
and unreachable source; generic bounds, arity, inference and polymorphic recursion;
stored-type cycles; transitive pure/effect violations; sealed entry boundaries;
double/unconsumed task handles and ineligible detached-task captures; recognized
but unadmitted closures and refused Never signatures.
