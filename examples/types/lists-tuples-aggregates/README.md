# Lists, tuples, and nested aggregates

Construct homogeneous lists, a typed empty list, heterogeneous tuples, and
struct/Result/Option nesting. Project a list using an Int index and a tuple
using a literal index; destructure a tuple with an irrefutable pattern.
No list or tuple mutation is used. See [lists](../../../SPEC.md#GNT-5.4),
[tuples](../../../SPEC.md#GNT-5.5), and [patterns](../../../SPEC.md#GNT-5.18).

From the repository root:

```sh
just run check examples/types/lists-tuples-aggregates
just run analyze examples/types/lists-tuples-aggregates
just run run examples/types/lists-tuples-aggregates
```

CLI stdout: check prints `syntax-valid`, analyze prints `source-valid`,
and run prints:

```json
[{"outcome":{"value":[10,20,30],"variant":"Ok"},"rows":[["first",20],["second",null]]},3,"first",20,0,true]
```
