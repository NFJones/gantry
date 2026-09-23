# Runtime resource integration

This note is a reader index of the runtime surfaces that consume the declared resource,
operation, and containment contracts. It states what the runtime publishes, where each claim is
decided, and what the runtime does not claim. It adds no semantics of its own: every decision below
belongs to the model, and the runtime selects an account, applies a fence, and reports the model's
own reason.

## Surfaces

| Surface | Runtime route | Decided by |
| --- | --- | --- |
| Admission | `ResourceRegistry::admit`, `AdmittedResource::admit` | `GNT-28.7-durable-resource-reconstruction`, `GNT-20.1-operation-kinds` |
| Reconstruction | `ResourceRegistry::reconstruct` | `GNT-28.7-durable-resource-reconstruction`, `GNT-20.10-retirement-and-stale-owner-fencing` |
| Capture | `ResourceRegistry::declared_records` | `GNT-28.7-durable-resource-reconstruction` |
| Live-resource limit and reclamation | `with_live_limit`, `live_resources`, `reap_deleted` | `GNT-28.8-retention-and-compaction-fences`, `GNT-28.9-retirement-deletion-and-stale-owner-fences` |
| Quota charging and renewal | `charge`, `renew` | `GNT-28.3-atomic-copy-move-loan-update-and-release-charging`, `GNT-28.5-closed-quota-families-and-owners`, `GNT-28.6-bounded-renewal-and-exhaustion` |
| Two-phase finish | `begin_finish`, `complete_finalization` | `GNT-28.4-resource-lifetime-finish-poison-and-emergency-release` |
| Root closure, retirement, deletion | `close_liveness_root`, `retire`, `delete` | `GNT-28.1-resource-identity-and-closed-liveness-roots`, `GNT-28.8-retention-and-compaction-fences`, `GNT-28.9-retirement-deletion-and-stale-owner-fences` |
| Failure settlement | `settle_from_post_failure`, `settle_from_emergency_cleanup` | `GNT-20.7-resource-state-after-failure-and-poisoning`, `GNT-28.4-resource-lifetime-finish-poison-and-emergency-release` |
| Containment settlement | `settle_containment` | `GNT-23.4-operation-ownership-and-single-settlement` |
| Adapter binding and poisoning | `bind_adapter_instance`, `adapter_instance`, `poison_adapter_instance` | `GNT-23.5-failed-instance-poisoning-and-isolation`, `GNT-20.11-adapter-obligations-and-diagnostics` |

## Fences

Every route that changes a declared fact is subject-addressed and owner-qualified. The account is
selected by the subject's own operation and generation rather than by caller text, and the presented
owner generation must be the account's current one, as
`GNT-20.10-retirement-and-stale-owner-fencing` requires. A superseded generation is refused before
any declared fact changes. Physical reclamation is the one registry-wide mutating route and changes
no declared fact: `reap_deleted` removes only the accounts whose lifetime already reached the
terminal retention state. No public route hands out a mutable registry-held account: each prohibited
route is pinned by its own bounded compile-fail witness, so an unfenced transition is unnameable
outside the crate rather than merely unused.

## Non-claims

- Account uniqueness is per registry. The runtime publishes no global uniqueness claim for one
  subject, and `GNT-28.10-resource-accounting-non-claims` is not widened here.
- The containment settlement is runtime state of one account value, so one contained operation
  settles once for the lifetime of that value. A subject rebuilt from its declared capture, or
  reclaimed and readmitted, holds a fresh unsettled settlement; the runtime publishes no
  cross-recovery single-settlement claim.
- The bound adapter instance and the poison reason ledger are runtime state. A registry rebuilt
  from declared reconstruction records holds neither, and the runtime publishes no recovery claim
  for either.
- A contained fault is not a settlement of the resource's accounting lifetime. Section
  `GNT-23.7-adapter-containment-obligations` and `GNT-23.8-containment-non-claims` declare
  containment obligations and limits only, so the runtime never derives a resource settlement from
  a containment report.
- Protected-scope containment reports are not published here;
  `GNT-23.6-protected-fault-diagnostics` leaves them to the landed protection rules.
- Physical reclamation is not semantic release: `reap_deleted` frees registry memory only, and no
  retention state returns a released live place.
