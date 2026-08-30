# Fuzzing

This is a separate, nightly-only Cargo workspace. Its pinned toolchain and
dependencies do not change Gantry's Rust 1.91 product MSRV or root publication
lockfile.

Run the bounded protocol-identity, lexer, parser, and strict-JSON targets with:

```text
cargo fuzz run protocol_identity -- -runs=2000 -max_len=256
cargo fuzz run lexer -- -runs=5000 -max_len=65536
cargo fuzz run parser -- -runs=5000 -max_len=65536
cargo fuzz run strict_json -- -runs=5000 -max_len=65536
```

Minimize any failure with `cargo fuzz tmin`, copy the smallest reproducer into
the matching `regressions/` directory with a descriptive name, and add any
semantic assertion needed to `gantry-conformance`. Deterministic regression
replay is part of the ordinary product test suite; fuzz success is only
bounded supplementary evidence.
