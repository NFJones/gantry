# Struct declarations with defaults and explicit construction

Declare source defaults, use named fields and shorthand `name`, and explicitly
construct two complete `Settings` values. The first supplies values matching the
declaration defaults; the second overrides `enabled` with `false` and `label`
with `None`, and supplies `Some("provided")` for `note`. **Every field is supplied
in both constructors. This executable example does not demonstrate omitted-field
default materialization.**

See [source](main.gnt), [expected full values](case.json),
[construction](../../../SPEC.md#GNT-5.11),
[defaults](../../../SPEC.md#GNT-5.12), and the [example index](../../README.md).
Source defaults are construction conveniences, not permission to omit
nonoptional fields from external JSON input; compare
[source defaults versus JSON](../../boundaries/source-default-vs-json/).

## Run

From the repository root:

```sh
just run check examples/types/structs-defaults
just run analyze examples/types/structs-defaults
just run run examples/types/structs-defaults
python3 scripts/validate-examples.py examples/types/structs-defaults
```

`check` prints `syntax-valid`, `analyze` prints `source-valid`, and `run` returns
the following valid JSON (object key order is not significant):

```json
[
  {"name":"default","enabled":true,"retries":2,"ratio":1.5,"note":null,"label":"automatic","absent":null,"completed":null},
  {"name":"explicit","enabled":false,"retries":2,"ratio":1.5,"note":"provided","label":null,"absent":null,"completed":null}
]
```

The offline runner compares both complete values against `case.json`; missing
fields are a failure, not an accepted alternative output. `Option` values encode
as their payload or `null`, and `Unit` encodes as `null`.

## Separately blocked: omitted-field defaults

The normative source contract says omitted defaulted fields use their declared
defaults, omitted optional fields without defaults become `None`, and an optional
scalar default becomes `Some`. Explicit `None` must override an optional default.
However, the previous constructors `Settings { name }` and
`Settings { name: "explicit", enabled: false, label: None, note: Some("provided") }`
produced incomplete objects in the current interpreter. Requiring the full values
above rejects that output. It is not a normative success and is no longer recorded
as one in the positive fixture.

A runnable omitted-field demonstration remains blocked until the implementation
materializes all required defaulted/optional fields. This package works around
that defect with explicit fields; it neither fixes nor validates omission support.
