# Fuzzing

This is a separate, nightly-only Cargo workspace. Its pinned toolchain and
dependencies do not change Gantry's Rust 1.91 product MSRV or root publication
lockfile.

Run the bounded protocol-identity target with:

```text
cargo fuzz run protocol_identity -- -runs=2000 -max_len=256
```

Minimize any failure with `cargo fuzz tmin`, copy the smallest reproducer into
`regressions/protocol_identity/` with a descriptive name, and add any semantic
assertion needed to `gantry-conformance`. Deterministic regression replay is
part of the ordinary product test suite; fuzz success is only bounded
supplementary evidence.
