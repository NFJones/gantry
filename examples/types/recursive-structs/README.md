# Finite recursive structs

Direct self-recursion is guarded by Option or List, with None and the empty list
terminating the finite value. No Box, pointer, or reference syntax is needed.
Mutually recursive types and recursive enum payloads are excluded from this v1
contract. See [recursive struct fields](../../../SPEC.md#GNT-5.6).

From the repository root:

```sh
just run check examples/types/recursive-structs
just run analyze examples/types/recursive-structs
just run run examples/types/recursive-structs
```

CLI stdout: check prints `syntax-valid`, analyze prints `source-valid`,
and run prints:

```json
[{"next":{"next":null,"value":2},"value":1},{"children":[{"children":[],"name":"leaf"}],"name":"root"}]
```
