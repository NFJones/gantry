# Inline nested modules

[main.gnt](main.gnt) contains `quality` and its nested `formatting` module.
`quality` imports the root `Input`, while `formatting` imports its parent's
`Finding`. Calls and result types use qualified paths; declaring a module does
not automatically import its items into another module's unqualified scope.
`self::Finding` means the current module's type, not a method receiver.

The normalizer mutates only its local copy and returns it. This is a
deterministic counterpart to the specification's model-backed nested-module
example, with no agent declarations or hook requirements.

From the repository root, build once and reuse the binary:

```sh
cargo build -p gantry-cli
```

Commands (exit 0, empty stderr):

```sh
target/debug/gantry check examples/modules/inline_nested
target/debug/gantry analyze examples/modules/inline_nested
target/debug/gantry run examples/modules/inline_nested
```

Expected stdout, respectively:

```text
syntax-valid
source-valid
{"summary":"Inline modules checked"}
```

See [case.json](case.json), [SPEC inline modules](../../../SPEC.md#GNT-4.8),
[path roots](../../../SPEC.md#GNT-4.11), and
[nested-module authoring](../../../SPEC.md#1411-nested-modules-and-qualified-paths).
