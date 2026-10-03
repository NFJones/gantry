# If-let and exhaustive tagged routing

[main.gnt](main.gnt) handles present and absent `Option<Int>` values with
`if let`, then both `Result<Int, String>` variants with an exhaustive value
match. Payload bindings exist only in their selected branch or arm. These
structural checks do not request model judgments.

From the repository root, build the default CLI once for all examples:

```sh
cargo build -p gantry-cli
```

Run these exact commands (each exits 0 with empty stderr):

```sh
target/debug/gantry check examples/control-flow/if_let_match
target/debug/gantry analyze examples/control-flow/if_let_match
target/debug/gantry run examples/control-flow/if_let_match
```

Expected stdout, respectively:

```text
syntax-valid
source-valid
[7,0,9,-1]
```

[case.json](case.json) records the run result. See
[SPEC §9](../../../SPEC.md#GNT-9.1),
[match grammar](../../../SPEC.md#GNT-13.6), and
[conditional grammar](../../../SPEC.md#GNT-13.8).
