# Diagnostic fixture review

Gantry keeps machine-facing diagnostics independent from terminal wording.
The reviewed fixtures therefore have separate owners:

- `protocol/goldens/diagnostic-machine-v1.json` records stable phase, severity,
  category, code, source span, and structured repair fields.
- `protocol/goldens/diagnostic-presentation-v1.json` records the immutable
  source input plus default-redacted and explicitly disclosed terminal output.

Neither fixture is generated or automatically updated. A fixture change must
be edited directly and reviewed as a protocol change. Review machine-field
changes before presentation changes; a wording-only change must not alter the
machine fixture. Then run:

```text
cargo test --locked -p gantry-conformance --test diagnostic_presentation
cargo test --locked -p gantry-cli --bin gantry
cargo run --locked -p xtask -- check generated
```

Source disclosure is per consumer and defaults to off. The disclosed golden
may copy only source text selected from the immutable snapshot. Raw integration
output is never an input to this renderer and must not be added to either
fixture. Authored text is directionally isolated, and control or bidi-formatting
scalars are rendered as `U+` code-point escapes.
