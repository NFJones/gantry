# Path roots and explicit imports

[main.gnt](main.gnt) combines unprefixed paths, `crate::`, `self::`, and
one- and two-level `super::` paths. `routing` imports a root type, a sibling
helper, and a child workflow. The child imports the same root type by moving
outward twice. `main` exercises both imported and fully qualified calls.

`use` imports the final item name, not an alias, glob, or group. It contributes
to the module namespace regardless of declaration order; here the child
workflow is imported before its inline module declaration. Do not reuse an
imported name as a local binding, or escape above the package root with `super`.
These are language item paths, not remote dependencies or filesystem paths.

From the repository root, build once and reuse the binary:

```sh
cargo build -p gantry-cli
```

Commands (exit 0, empty stderr):

```sh
target/debug/gantry check examples/modules/path_imports
target/debug/gantry analyze examples/modules/path_imports
target/debug/gantry run examples/modules/path_imports
```

Expected stdout, respectively:

```text
syntax-valid
source-valid
["imported!","qualified!"]
```

See [case.json](case.json), [SPEC path resolution](../../../SPEC.md#GNT-4.11),
[namespace collection](../../../SPEC.md#GNT-4.14),
[import grammar](../../../SPEC.md#GNT-13.3), and
[nested-module authoring](../../../SPEC.md#1411-nested-modules-and-qualified-paths).
