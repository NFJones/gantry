# Split and join

Split preserves leading, adjacent, and trailing empty segments. No match leaves
one segment, even for empty input. Join inserts a separator only between items;
an empty list joins to an empty String. Empty split separators fail and are not
used here. See [split and List<String>.join](../../../SPEC.md#GNT-5.16).

From the repository root:

```sh
just run check examples/strings/split-join
just run analyze examples/strings/split-join
just run run examples/strings/split-join
```

CLI stdout: check prints `syntax-valid`, analyze prints `source-valid`,
and run prints:

```json
[["","red","","blue",""],"|red||blue|",["whole"],"","solo",[""]]
```
