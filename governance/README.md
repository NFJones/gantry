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
