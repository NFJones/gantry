# String inspection

Count scalars and inspect emptiness, substrings, prefixes, and suffixes.
Matching is exact and case-sensitive; every String contains the empty String.
See [deterministic String methods](../../../SPEC.md#GNT-5.16).

From the repository root:

```sh
just run check examples/strings/inspection
just run analyze examples/strings/inspection
just run run examples/strings/inspection
```

CLI stdout: check prints `syntax-valid`, analyze prints `source-valid`,
and run prints:

```json
[10,false,true,true,true,true,true,false]
```
