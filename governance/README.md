# Dependency and toolchain governance

`dependency-ledger-v1.json` binds dependency decisions to the exact root
`Cargo.lock` used by CI and publication checks. Run
`cargo run --locked -p xtask -- check governance` after any manifest,
lockfile, toolchain, CI, or dependency-policy change.

The root workspace is an MSRV product workspace. The separate `fuzz/`
workspace is nightly-only, has its own digest-bound lockfile, and may not
change the root toolchain or publication lockfile.
CI installs the exact `cargo-deny` and `cargo-fuzz` releases recorded in the
ledger. A dependency upgrade that can affect portable behavior must update its
decision, rerun the listed boundary evidence, and update the lockfile digest.

The negative fixture is intentionally invalid input for the validator. It
covers stale lockfile evidence, denied sources and licenses, unresolved
advisories, and unsupported facade features without introducing those values
into the product dependency graph.

## Upstream contract decisions

`upstream-contract-decisions.md` records successor ownership, common-I/O
sequencing, benchmark measurement policy, and the unmodified qualification
boundary. It is a planning addendum, not normative semantics or release evidence.
Run `python3 governance/audit_spec_revision.py` to report SPEC revision mismatches
without changing any input. Its regression tests run with
`timeout 120s python3 -B -m unittest discover -s governance -p 'test_*.py'`.

For a non-gating product-CLI timing observation, build the CLI from the exact
candidate, then run:

```sh
python3 -B governance/measure_application.py --binary target/debug/gantry --package examples/generics-and-traits --expected-json '"envelope"' --repetitions 3
```

The runner prints an identity-bound record only when every bounded run returns
the exact expected canonical JSON with no error output. Its product CLI uses
unlimited semantic budgets by default; the subprocess timeout bounds the
measurement, not Gantry's semantic work. It does not record semantic charges;
pair its observations with separate
production-interface work/storage assertions and representative application
workloads before evaluating BENCH. Timing alone never qualifies a strategy,
regression threshold, publication, or release. Do not use a stale CLI binary as
evidence for newer source bytes.
