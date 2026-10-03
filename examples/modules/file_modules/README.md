# File modules and nested loading

[main.gnt](main.gnt) loads [domain.gnt](domain.gnt) via `mod domain;` and
[workflows/mod.gnt](workflows/mod.gnt) via `mod workflows;`. The latter loads
its child from [workflows/render.gnt](workflows/render.gnt). Each file is an
independent module, not textual inclusion. Imports expose the report type and
workflow under their final names.

Nested lookup uses the declaring module's directory. A module loaded from
`workflows.gnt` would also use `workflows/` for its children. Never provide both
`workflows.gnt` and `workflows/mod.gnt`: that is ambiguous. Paths must stay local
to this package and cannot use symlinks or `.` / `..` components.

From the repository root, build once and reuse the binary:

```sh
cargo build -p gantry-cli
```

Commands (exit 0, empty stderr):

```sh
target/debug/gantry check examples/modules/file_modules
target/debug/gantry analyze examples/modules/file_modules
target/debug/gantry run examples/modules/file_modules
```

Expected stdout, respectively:

```text
syntax-valid
source-valid
{"summary":"Loaded sibling and nested file modules","title":"Module guide"}
```

See [case.json](case.json), [SPEC module loading](../../../SPEC.md#GNT-4.7),
[declaration grammar](../../../SPEC.md#GNT-13.3), and
[module authoring examples](../../../SPEC.md#142-modules-imports-and-package-wide-agents).
