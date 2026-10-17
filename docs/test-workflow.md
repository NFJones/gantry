# The experimental `gantry test` workflow

`gantry test` is the first tooling workflow of
`GNT-GP-TOOLING-RUNTIME-001` (decision D7): one bounded, zero-authority, local, offline,
single-package unit run. It is experimental and non-shipping. It does not claim Section 16
multi-package target support, and `gantry run` keeps its existing defaults.

## Invocation

```sh
gantry test --max-transitions POSITIVE_INTEGER [--json] [PACKAGE_ROOT]
```

`--max-transitions` is mandatory, positive, and finite. It bounds labelled runtime transitions;
it is not a wall-clock timeout and implies no external interrupt or host cleanup support. `jobs` is
fixed at 1. `PACKAGE_ROOT` defaults to the current directory. `--json` publishes the versioned
report; without it the command prints one human marker and payload-free detail lines.

## Selected target

The workflow explicitly selects the package entry as its single unit test target: the entry must be
a zero-argument `Unit` entry. The program comes from public source analysis
(`AnalyzePackageResult`), never from a test-name scan, an arbitrary retained-program loader, a new
source annotation, or a mutation of the shipping entry interface.

Refusal classes:

- a missing root `main` is refused by the language entry rule as invalid source (exit 1);
- an argument-taking entry is refused at admission (exit 2);
- a valid package whose entry returns a non-`Unit` value has no admissible unit target and reports
  `no-tests` (exit 2).

The declared run plan admits exactly kind `unit` with no substitutions. A conflicting declaration,
a non-Unit kind, an unknown kind, or a declared substitution is refused rather than dropped.

## Preflight and admission

Preflight runs before any frontend stage is dispatched. It checks the declared policy revision,
the job cardinality, the transition bound, the declared run plan, and every declared registry,
authority, and external-artifact input. Unknown or unsupported declarations refuse with a
structured code and dispatch nothing.

Preflight also checks the identity record against the current build: source-language version,
specification revision, profile revision, compiled facade features, the published target
descriptor, the standard-library contract, and the toolchain identity. A stale expectation refuses
as `identity-mismatch` and the report names the disagreeing field.

Admission then requires the analyzed entry-reachable program to have an empty effect inventory, an
empty operation inventory, an empty live-resource inventory, and an empty authority ceiling. A
non-empty inventory refuses; it is never downgraded to a warning. The report publishes the
observed inventories so an empty set is evidence rather than an assumption. The inventory is
measured over the admitted executable program: a package-wide declaration that no executed
workflow reaches is not an effect of the run, is neither refused nor counted, and grants nothing.

## Bounds

Frontend input, frontend stages, and diagnostics are declared policy bounds in the closed
toolchain budget-unit vocabulary, separate from the runtime step bound:

| Bound | Unit | Reference CLI value |
| --- | --- | --- |
| Frontend input | `bytes` | 4 MiB |
| Frontend stages | `count` | 2 (syntax, then analysis) |
| Diagnostics | `count` | 4096 |
| Runtime steps | labelled transitions | `--max-transitions` |

A policy that declares fewer than two frontend stages cannot admit a test run, because the workflow
refuses instead of dropping the analysis stage. One coordinator dispatch performs those two stages
over one package snapshot, so a run neither parses the package twice nor executes a third stage.
The derived `FrontendLimits` are finite in every dimension; there is no unlimited frontend path in
this workflow.

The report encoding ceiling is fixed by the contract at 1 MiB and cannot be raised by a caller. The
reference CLI builds the whole document and checks its exact encoded length before writing the
first byte, so an over-ceiling report is an operational failure with no partial JSON.

## Exit codes

| Exit | Class |
| --- | --- |
| 0 | Clean completion: every admitted target completed |
| 1 | Invalid source, or a fixed test failure |
| 2 | Admission, operational failure, no-tests, step exhaustion, or cancellation |
| 64 | Malformed usage (missing, zero, negative, or non-numeric `--max-transitions`, unknown option, duplicate option, unexpected argument) |

Step exhaustion is a declared step bound with no fixed outcome. It is reported as `exhausted`, not
as a timeout, and the workflow claims no external interrupt or host cleanup support. The workflow
declares no cancellation reason, so a cancellation outcome is mapped to exit 2 but is not produced
by this slice.

## Versioned report

The `--json` document has format `gantry.test-workflow/v1` and report version 1. It carries:

- `identity`: the observed source-language version, specification and profile revisions, semantic
  mode, compiled features, the published target descriptor, the standard-library contract, and the
  toolchain identity, or `null` when observation itself was refused;
- `expected_identity`: the identity record the caller expected, so a refusal names both the
  observed fact and the stale expectation;
- `policy`: the declared revision, jobs, the three declared frontend bounds, the runtime step bound,
  and the output ceiling;
- `selection`: the declared kind (or `null` for an unknown spelling), declared substitutions,
  jobs, and the admitted entry;
- `declared`: the bounded counts of declared registry, authority, and external-artifact inputs;
- `package` and `inventory`: the observed bounded source package and the observed empty inventories;
- `results`: one ordered result per admitted target, in canonical target-name order, with the
  outcome class, labelled steps, and any structured machine failure;
- `refusal`: at most one structured refusal with stage, stable code, requirement anchor, and a
  stable detail spelling;
- `diagnostics`: bounded structured diagnostics for invalid source.

The report carries no source text, diagnostic message, repair field, or captured value, so it
cannot leak a payload. A clean report is the only `status` that exits 0.

## Non-claims

This workflow does not provide compile-fail, property, benchmark, replay, durable-recovery,
snapshot, or substitution support. The runtime harness can execute unit, integration, and example
program targets, but only unit is selected here. Harness support for those program targets is not
support for the other declared test kinds. The workflow starts no Tokio runtime, performs no live
I/O, resolves no dependency, reads no registry, and grants no authority.

## Validation

- Facade module tests: policy bounds, derived frontend limits.
- CLI tests: clean completion, fixed failure, invalid source, admission, no-tests, exhaustion,
  malformed usage, JSON shape and ceiling, and the normalized report golden
  `crates/gantry-cli/tests/goldens/test-unit-v1.json`.
- Conformance lane `crates/gantry-conformance/tests/test_workflow.rs`: report shape and ordering,
  determinism, structured failure, payload-free diagnostics, preflight non-dispatch, stale identity,
  refused-declaration retention, policy revisions, entry selection, non-empty inventories, one
  frontend activity per run, entry-reachable inventory scope, and step exhaustion.
