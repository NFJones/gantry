# Value matches versus effect-only matches

[main.gnt](main.gnt) exhaustively routes a declared enum in three ways:
a value match initializes `value`, a statement match assigns `effect`, and
`discard match` explicitly ignores a produced string. The statement match
has statement-only braced arms and no trailing semicolon. Value-block arms
have trailing expressions. Here “effect-only” means local mutation, not an
integration effect; neither form dispatches a hook.

From the repository root, build once (reuse it for all packages):

```sh
cargo build -p gantry-cli
```

Commands (exit 0, empty stderr):

```sh
target/debug/gantry check examples/control-flow/match_forms
target/debug/gantry analyze examples/control-flow/match_forms
target/debug/gantry run examples/control-flow/match_forms
```

Expected stdout, respectively:

```text
syntax-valid
source-valid
[{"effect":12,"value":8},{"effect":1,"value":0}]
```

See [case.json](case.json), [SPEC §9](../../../SPEC.md#GNT-9.8),
[blocks and discard](../../../SPEC.md#GNT-13.5), and
[match forms](../../../SPEC.md#GNT-13.6).
