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
- `target/`: generated Cargo build output; do not edit or commit it.

Keep the binary entry point thin as the language implementation grows. Place
parsing, semantic analysis, runtime behavior, and model-operation integration
in focused subsystem modules behind clear contracts rather than accumulating
application logic in `main.rs`.

## Build, Test, and Development Commands

- Always wrap tests in a 120 second `timeout` or greater to check for hangs.
- `just`: build all targets and features in release mode.
- `just build`: build all targets and features in debug mode.
- `just check`: run `cargo check --all-targets --all-features`.
- `just fmt`: apply Rust formatting with `cargo fmt --all`.
- `just clippy`: run clippy with warnings denied.
- `just test`: run the test suite.
- `just clean`: remove Cargo build artifacts.
- `just help`: list available recipes.

## Coding, Documentation, and Testing Requirements

- Rust edition is 2024; follow standard `rustfmt` defaults.
- Module and file names are `snake_case`.
- New modules should have module-level documentation describing purpose,
  boundaries, and important invariants.
- Major architectural components should document how they relate to the
  language pipeline and runtime.
- Public and private Rust items should have rustdoc describing behavior,
  inputs and outputs, and error cases.
- Prefer small, composable functions. Split parsing, semantic rules, and I/O
  into clear units rather than combining them in one function.
- Pass dependencies explicitly where practical; avoid hidden global coupling.
- Do not use `unwrap` or `expect` in production paths unless the invariant is
  documented and intentional. Add context to propagated errors so failures are
  diagnosable in logs and tests.
- New behavior should include a happy-path test and an edge or failure case.
- Bug fixes should include a regression test that fails before the fix and
  passes afterward.
- Tests should explain what behavior they cover and why it matters.
- Behavior or language changes must update `SPEC.md` and relevant `docs/`.
- When behavior or configuration changes affect user workflows, update the
  relevant examples and configuration samples alongside the implementation.
- Keep exploratory or documentation-only research in `docs/reference/`; do
  not stage or commit material in that local-reference directory. Promote
  conclusions that affect the product to `SPEC.md` or the relevant committed
  documentation.
- For refactors or investigations spanning multiple work sessions, maintain a
  concise progress note in the active issue, pull request, or handoff with
  completed work, remaining work, and material decisions or risks.
- Do not commit secrets; use examples for configuration.

## Architecture, Compatibility, and Security

- Keep Gantry compatible with Linux and macOS; do not introduce
  platform-specific behavior without a supported alternative.
- Preserve explicit language semantics in `SPEC.md`. New behavior must not
  violate the specification.
- Unless instructed otherwise, do not retain deprecated behavior solely for
  backward compatibility; remove superseded code and modules.
- Review network bind addresses and TLS settings before running in shared
  environments.

## Validation and Handoff

- Use `just check` for fast type-checking while developing.
- Run `just fmt`, `just clippy`, and `just test` successfully before handoff.
- Prefer end-to-end coverage for user-visible language and runtime behavior
  when practical.
- Pull requests should summarize the change, list validation results, and note
  relevant language, configuration, or documentation updates.
- Always commit your changes at the end of a turn with a long-form informative message. Never skip this.

## Commit Requirements

- Commit messages are short, imperative, sentence case, and end with a period.
- Commit meaningful completed changes with an informative message.
