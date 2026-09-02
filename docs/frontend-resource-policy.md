# Frontend resource policy

Every public package activity receives one explicit `FrontendLimits` value.
The policy has no portable implicit defaults: embedders must supply all twelve
positive integers, each no greater than `2^63 - 1`.

[`examples/frontend-limits.json`](../examples/frontend-limits.json) records a
machine-checked complete policy using the reference CLI values. It is a sample
embedding configuration, not a language default.

| Field | Applies to | Unit and charging boundary |
| --- | --- | --- |
| `maximum_package_files` | validate, analyze, start, candidate-source resume | selected source files, before admission |
| `maximum_source_file_bytes` | all package activities | exact bytes in one selected file, before copying or decoding |
| `maximum_package_source_bytes` | all package activities | cumulative selected source bytes, before admission |
| `maximum_source_tokens` | all package activities | nontrivia lexical tokens, while scanning |
| `maximum_diagnostics_per_activity` | all package activities | retained errors and warnings, before retention |
| `maximum_package_source_manifest_bytes` | analysis activities | canonical package-manifest bytes, before publication |
| `maximum_canonical_ir_bytes` | analysis activities | canonical analysis-IR bytes, before publication |
| `maximum_source_map_bytes` | analysis activities | canonical source-map bytes, before publication |
| `maximum_generated_schema_bytes` | analysis activities | one generated schema object, before publication |
| `maximum_constructed_type_depth` | validate, analyze, start, candidate-source resume | authored, inferred, substituted, or decoded type depth, before retaining the deeper type |
| `maximum_generic_instantiations_per_activity` | semantic analysis only | each new canonical template/type-argument key, before interning it |
| `maximum_trait_resolution_steps_per_activity` | semantic analysis only | obligation lookups, candidate unifications, predicate expansions, and sealed-capability node or edge visits, before retaining work or output |

All activity counters start from zero for each admitted public package
activity and are shared across that activity's modules and phases. Reusing a
canonical generic-instantiation key does not charge it again. A memoized trait
lookup still charges the lookup unit but does not charge work skipped by the
cached result. Recovery from retained canonical artifacts performs no source
analysis and therefore does not consume these counters.

Failure uses the stable codes `constructed-type-depth-limit`,
`generic-instantiation-limit`, and `trait-resolution-step-limit` for the three
generic-analysis fields. Checked-arithmetic overflow fails with the same field's
code. Charges are failure-atomic: rejected work does not alter the retained
counter prefix or publish a partial analysis or executable artifact.

The reference CLI currently selects these explicit values:

| Field group | Value |
| --- | ---: |
| package files | 4,096 |
| source file bytes | 16,777,216 |
| package source bytes | 268,435,456 |
| source tokens | 4,194,304 |
| diagnostics | 4,096 |
| package manifest, canonical IR, source map, generated schema | 268,435,456 each |
| constructed type depth | 256 |
| generic instantiations | 65,536 |
| trait-resolution steps | 1,000,000 |

These CLI values are implementation policy, not language defaults and not
part of package or durable execution identity. Changing them may change whether
an activity is admitted, but it cannot change the canonical bytes or meaning of
a package admitted under both policies. They are logical work limits, not host
memory, allocator, CPU-time, or process-RSS limits.
