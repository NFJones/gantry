# Unicode scalar semantics

The second literal is `e` followed by U+0301; the first is U+00E9. They are
visually similar but unequal: Gantry does not normalize. Length counts scalars,
not UTF-8 bytes or grapheme clusters. Full Unicode case mapping expands sharp s,
handles final Greek sigma, and trimming recognizes U+3000 whitespace.
See [Unicode 16.0 String semantics](../../../SPEC.md#GNT-5.16).

From the repository root:

```sh
just run check examples/strings/unicode
just run analyze examples/strings/unicode
just run run examples/strings/unicode
```

CLI stdout: check prints `syntax-valid`, analyze prints `source-valid`,
and run prints:

```json
[1,2,1,false,"STRASSE",7,"hello","ος"]
```
