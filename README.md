# Gantry

Gantry is an agent control language.

The language is intended to make prompts, agent operations, routing, and
control flow explicit, reviewable program constructs.

## Status

The frontend profile is implemented for Gantry source language 1.0 at
`SPEC.md` SHA-256
`78fc02332a01a8a53ca4cbe82b3cdd01125b2aae7039c940274ae97559391e22`.
It provides complete package discovery, lexical and syntactic validation,
structured diagnostics, parse events, `ValidatePackage`, and `gantry check`.
Analyzer, evaluator, concurrent, durable-runtime, and embedding profiles are
not yet advertised.

## Development

Gantry is a Rust 2024 workspace. With Rust 1.91 or newer installed:

```sh
just check
just test
```

See [`AGENTS.md`](AGENTS.md) for contributor workflow and
[`SPEC.md`](SPEC.md) for the evolving language contract.

## License

Gantry is licensed under the [Apache License 2.0](COPYING).
