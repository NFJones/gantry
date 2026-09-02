# Fuzzing

This is a separate, nightly-only Cargo workspace. Its pinned toolchain and
dependencies do not change Gantry's Rust 1.91 product MSRV or root publication
lockfile.

Run the bounded protocol-identity, lexer, parser, strict-JSON, generic-IR, and
hostile generic-package targets with:

```text
cargo fuzz run protocol_identity -- -runs=2000 -max_len=256
cargo fuzz run lexer -- -runs=5000 -max_len=65536
cargo fuzz run parser -- -runs=5000 -max_len=65536
cargo fuzz run strict_json -- -runs=5000 -max_len=65536
cargo fuzz run generic_ir -- -runs=5000 -max_len=65536
cargo fuzz run generic_package -- -runs=5000 -max_len=65536
```

The checked-in parser corpus includes angle/path disambiguation and qualified
trait calls. The generic-IR corpus covers open template identities, closed
callable identities, and nested descriptors. The generic-package corpus covers
contextual `Self`, recursive obligations, and nested applications under finite
analysis limits.

Minimize any failure with `cargo fuzz tmin`, copy the smallest reproducer into
the matching `regressions/` directory with a descriptive name, and add any
semantic assertion needed to `gantry-conformance`. Deterministic regression
replay is part of the ordinary product test suite; fuzz success is only
bounded supplementary evidence.
