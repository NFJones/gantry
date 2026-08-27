# Repository Guidelines

## Project Structure & Module Organization

Gantry is a Rust 2024 workspace for an agent-control language designed to run
within Mezzanine. The `crates/gantry` package builds the `gantry` command-line
tool. Keep language syntax, runtime semantics, and model operations explicit
and documented as the implementation grows.

- `SPEC.md`: normative language and runtime contract.
- `README.md`: project overview and quick-start material.
- `crates/gantry/`: product package and command-line entry point.
- `docs/`: user, language, and contributor documentation.
- `Justfile`: local development command entry points.
- `.github/workflows/ci.yml`: continuous-integration validation.

## Build, Test, and Development Commands

- Always wrap tests in a 120 second `timeout` or greater to check for hangs.
- `just`: build all targets and features in release mode.
- `just build`: build all targets and features in debug mode.
- `just check`: run `cargo check --all-targets --all-features`.
- `just fmt`: apply Rust formatting with `cargo fmt --all`.
- `just clippy`: run clippy with warnings denied.
- `just test`: run the test suite.

## Coding, Documentation, and Testing Requirements

- Rust edition is 2024; follow standard `rustfmt` defaults.
- New modules should have module-level documentation describing purpose,
  boundaries, and important invariants.
- Public Rust items should have rustdoc describing behavior and error cases.
- New behavior should include a happy-path test and an edge or failure case.
- Behavior or language changes must update `SPEC.md` and relevant `docs/`.
- Do not commit secrets; use examples for configuration.

## Commit Requirements

- Commit messages are short, imperative, sentence case, and end with a period.
- Run `just fmt`, `just clippy`, and `just test` before handoff when feasible.
