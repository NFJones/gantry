# The Section 28 resource-accounting model

This note indexes the pure Section 28 resource-accounting model declared by
`crates/gantry-ir/src/resource.rs` and exercised by
`crates/gantry-conformance/tests/resource_accounting.rs`. The model declares facts only: it creates
no runtime resource, performs no host call, and claims no evaluator, journal, checkpoint, or
adapter integration. The note is pinned by
`crates/gantry-conformance/tests/resource_accounting.rs#resource_model_note_is_current`, which
requires every section below to name exactly the live members of the vocabulary it indexes, so the
note cannot drift from the model.

## Clauses

- `GNT-28.0-resource-accounting-and-lifetime-contract`
- `GNT-28.1-resource-identity-and-closed-liveness-roots`
- `GNT-28.2-logical-measures-and-representation-equivalence`
- `GNT-28.3-atomic-copy-move-loan-update-and-release-charging`
- `GNT-28.4-resource-lifetime-finish-poison-and-emergency-release`
- `GNT-28.5-closed-quota-families-and-owners`
- `GNT-28.6-bounded-renewal-and-exhaustion`
- `GNT-28.7-durable-resource-reconstruction`
- `GNT-28.8-retention-and-compaction-fences`
- `GNT-28.9-retirement-deletion-and-stale-owner-fences`
- `GNT-28.10-resource-accounting-non-claims`

## Liveness roots

- `durable-record`
- `loan`
- `owner`
- `resource`

## Logical measures

- `bytes`
- `handles`
- `operations`

## Quota families

- `bytes`
- `handles`
- `operations`

## Quota owners

- `durable-record`
- `owner`
- `resource`

## Resource actions

- `copy`
- `loan`
- `move`
- `release`
- `update`

## Resource carriers

A resource's accounting facts are carried only by the declared reconstruction record of
`GNT-28.7-durable-resource-reconstruction`. The declared carriers are:

- `ordinary-durable-state`
- `ordinary-serialization`
- `reconstruction-record`
