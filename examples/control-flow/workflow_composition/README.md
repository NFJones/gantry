# Compose workflows with copied values

[main.gnt](main.gnt) composes draft creation, revision, and publication.
`mut draft` permits mutation of the revision workflow's local argument copy.
The returned copy is retained explicitly as `revised`; `original` is unchanged.
Ordinary workflow dispatch creates interpreter frames, not operation hooks.
These bodies contain no integration operations, although a workflow in general
can transitively reach explicit `prompt`, `decide`, or `action` sites.

From the repository root, build once and reuse the binary:

```sh
cargo build -p gantry-cli
```

Commands (exit 0, empty stderr):

```sh
target/debug/gantry check examples/control-flow/workflow_composition
target/debug/gantry analyze examples/control-flow/workflow_composition
target/debug/gantry run examples/control-flow/workflow_composition
```

Expected stdout, respectively:

```text
syntax-valid
source-valid
{"original":{"revisions":0,"title":"Guide"},"published":"Guide reviewed","revised":{"revisions":1,"title":"Guide reviewed"}}
```

See [case.json](case.json), [SPEC call semantics](../../../SPEC.md#GNT-6.4),
[transitive effects](../../../SPEC.md#GNT-6.5), and
[workflow grammar](../../../SPEC.md#GNT-13.4).
