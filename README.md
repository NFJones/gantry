# Gantry

Gantry is a Rust-inspired, agent-control language for coordinating
model-backed agents in Mezzanine. It makes integration operations, routing,
and control flow explicit, reviewable parts of a program.

The language is specified for portable behavior across validation, execution,
observation, cancellation, and resume. The current implementation is an
early, profile-scoped implementation rather than a complete Gantry runtime.

## Current status

Gantry implements and advertises the **frontend profile** for source language
1.0 at this [`SPEC.md`](SPEC.md) revision:

`78fc02332a01a8a53ca4cbe82b3cdd01125b2aae7039c940274ae97559391e22`

The frontend discovers packages, performs lexical and syntactic validation,
emits structured diagnostics and parse events, and exposes both the Rust
`ValidatePackage` API and the `gantry check` command. It does not yet
advertise the analyzer, evaluator, concurrent-evaluator, durable-runtime, or
embedding profiles.

## Quick start

Gantry is a Rust 2024 workspace and requires Rust 1.91 or newer. Run the
syntax checker against a package directory (the current directory by default):

```sh
just run -- check [PACKAGE_ROOT]
```

The command prints `syntax-valid` for a valid package; invalid source produces
diagnostics, prints `syntax-invalid`, and exits with status 1.

For local development:

```sh
just check
just test
```

Run `just help` for all workspace commands.

## Documentation and contributing

- [`SPEC.md`](SPEC.md) is the normative language and runtime contract. Source
  authors can start with its introduction and Section 14 examples.
- [`docs/`](docs/README.md) indexes language, user, and contributor
  documentation.
- [`AGENTS.md`](AGENTS.md) defines the repository workflow, validation, and
  contribution requirements.
- [`protocol/`](protocol/README.md) contains canonical protocol inputs,
  schemas, generated bindings, and conformance evidence.

## License

Gantry is licensed under the [Apache License 2.0](COPYING).
