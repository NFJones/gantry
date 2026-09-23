# Runtime resource integration

This note is a reader index of the runtime surfaces that consume the declared resource, operation,
and containment contracts. It states what the runtime publishes, where each decision is decided, and
what the runtime does not claim.

Declared semantics belong to the model: the runtime selects an account, applies a fence, and reports
the model's own reason. Two things are runtime policy over declared facts rather than model
decisions - the registry's live-account ceiling and physical reclamation - and both are named as such
below. Where a clause owns a fence rather than the runtime policy that consumes it, this note says so.

## Registry surfaces

| Surface | Runtime route | Decided by |
| --- | --- | --- |
| Admission | `new`, `admit` | `GNT-28.7-durable-resource-reconstruction`, `GNT-20.1-operation-kinds` |
| Reconstruction | `reconstruct`, `RecoveredResourceRecord` | `GNT-28.7-durable-resource-reconstruction`, `GNT-20.10-retirement-and-stale-owner-fencing` |
| Capture | `declared_records` | `GNT-28.7-durable-resource-reconstruction` |
| Live-account ceiling | `with_live_limit`, `live_limit`, `live_resources` | Runtime policy over the lifetimes `GNT-28.4-resource-lifetime-finish-poison-and-emergency-release` declares; the model owns no ceiling |
| Physical reclamation | `reap_deleted` | Runtime policy that removes only accounts whose lifetime already reached the terminal retention state; the fences are `GNT-28.8-retention-and-compaction-fences` and `GNT-28.9-retirement-deletion-and-stale-owner-fences` |
| Quota charging and renewal | `charge`, `renew` | `GNT-28.3-atomic-copy-move-loan-update-and-release-charging`, `GNT-28.5-closed-quota-families-and-owners`, `GNT-28.6-bounded-renewal-and-exhaustion` |
| Two-phase finish | `begin_finish`, `complete_finalization` | `GNT-28.4-resource-lifetime-finish-poison-and-emergency-release` |
| Root closure, retirement, deletion | `close_liveness_root`, `retire`, `delete` | `GNT-28.1-resource-identity-and-closed-liveness-roots`, `GNT-28.8-retention-and-compaction-fences`, `GNT-28.9-retirement-deletion-and-stale-owner-fences` |
| Failure settlement | `settle_from_post_failure`, `settle_from_emergency_cleanup` | `GNT-20.7-resource-state-after-failure-and-poisoning`, `GNT-28.4-resource-lifetime-finish-poison-and-emergency-release` |
| Containment settlement | `settle_containment` | `GNT-23.4-operation-ownership-and-single-settlement` |
| Adapter binding and poisoning | `bind_adapter_instance`, `adapter_instance`, `poison_adapter_instance` | `GNT-23.5-failed-instance-poisoning-and-isolation`, `GNT-20.11-adapter-obligations-and-diagnostics` |
| Inspection | `account` | `GNT-28.7-durable-resource-reconstruction` |

## Account surfaces

`AdmittedResource` publishes `admit`, `subject`, `ledger`, `quota`, `remaining`, `durable_record`,
`containment`, `settle_containment`, `adapter_instance`, `bind_adapter_instance`,
`begin_finish_for`, `complete_finalization_for`, `charge`, `renew`, `close_liveness_root_for`,
`retire`, `delete_for`, `settle_from_post_failure`, and `settle_from_emergency_cleanup`. The registry
routes above select an account and delegate to these, so both levels publish the same model
decisions, and the account level is the narrower surface: it mutates one account a caller already
holds rather than selecting one by subject.

## Fences

Every route that changes a declared fact is subject-addressed at the registry level: the account is
selected by the subject's own operation and generation rather than by caller text. The ordinary
mutation routes - `charge`, `renew`, `begin_finish`, `complete_finalization`, `close_liveness_root`,
`retire`, `delete`, `bind_adapter_instance`, and `poison_adapter_instance` - are additionally
owner-qualified: the presented owner generation must be the account's current one, as
`GNT-20.10-retirement-and-stale-owner-fencing` requires, and a superseded generation is refused
before any declared fact changes. The two failure routes are fenced differently and are not
owner-qualified: `settle_from_post_failure` is authorized by the settlement's own operation and
resource generation, and `settle_from_emergency_cleanup` only by the sealed cleanup witness, so an
owner generation is not what authorizes either. Physical reclamation is the one registry-wide
mutating route and changes no declared fact.

No public route hands out a mutable registry-held account. The bounded compile-fail witnesses cover
the private subject-binding constructor, the removed mutable registry-held account route, the
unqualified finish and finalization steps, and the removed raw ledger accessor, so those specific
transitions are unnameable outside the crate rather than merely unused.

## Non-claims

- Account uniqueness is per registry: the runtime publishes no global uniqueness claim for one
  subject, and `GNT-28.10-resource-accounting-non-claims` is not widened here.
- The containment settlement is runtime state of one account value under
  `GNT-23.4-operation-ownership-and-single-settlement`, so one contained operation settles once for
  the lifetime of that value. A subject rebuilt from its declared capture, or reclaimed and
  readmitted, holds a fresh unsettled settlement; the runtime publishes no cross-recovery
  single-settlement claim.
- The bound adapter instance and the poison reason ledger are runtime state under
  `GNT-23.5-failed-instance-poisoning-and-isolation`. A registry rebuilt from declared
  reconstruction records holds neither, and the runtime publishes no recovery claim for either.
- A contained fault is not a settlement of the resource's accounting lifetime:
  `GNT-23.7-adapter-containment-obligations` and `GNT-23.8-containment-non-claims` declare
  containment obligations and limits only, so the runtime never derives a resource settlement from a
  containment report.
- Protected-scope containment reports are not published here:
  `GNT-23.6-protected-fault-diagnostics` leaves them to the landed protection rules.
- Physical reclamation is not semantic release: `reap_deleted` frees registry memory only, and under
  `GNT-28.9-retirement-deletion-and-stale-owner-fences` no retention state returns a released live
  place.
