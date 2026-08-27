# Gantry

Gantry is an agent-control language for [Mezzanine](../mezzanine): the
terminal harness from which people can observe and direct agents working on
the factory floor.

The language is intended to make prompts, agent operations, routing, and
control flow explicit, reviewable program constructs.

## Status

This repository contains the initial project scaffold. The language contract
will be developed in [`SPEC.md`](SPEC.md) before implementation expands.

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
