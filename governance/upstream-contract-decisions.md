# Upstream contract ownership and qualification decisions

This is an accepted project sequencing and ownership decision under the delegated
blocker-resolution task, not a language specification, conformance attestation, or
release adoption. `SPEC.md` remains normative. The original preregistration and
its task/application intent remain unchanged; this addendum assigns successor
work created after that preregistration. Historic resolutions `f9a7d10f` and
`e61f5335` remain resolved.

## Contract ownership before implementation

| Issue | Accepted ownership and next independently reviewable deliverable |
| --- | --- |
| RESOURCE-RUNTIME `b87d011f` | Own the missing source-resource to runtime/host-adapter mapping, not just consumption of an unspecified external contract. Extend Sections 20/28 through reviewed clauses; map creation, authenticated kind, operation/resource/owner generations, admission, progress, settlement, quota release, finish, poison, and emergency cleanup to `gantry-host` contracts and `gantry-runtime/src/resource.rs`. Preserve the distinction between accounting reconstruction and physical host reconstruction. |
| IO-RUNTIME `ecc871f8` | Own the common adapter/settlement substrate over Sections 20/23/24/29/45. Start with bounded memory-buffer transport and deterministic fake completion/cancellation races. Resource integration consumes RESOURCE-RUNTIME. FS, CONSOLE, PROCESS, NET, APP-CORPUS, and PUB are integration/evaluation consumers, not prerequisites for authoring the common contract. Their family mappings remain required before whole-issue closure. |
| CONSOLE `aee7225a` | Own Section 46's missing typed operation signatures and authority mapping. Input, output/flush, terminal observation, and terminal control need distinct declared requirements; text output must not imply control authority. Reuse common I/O settlement, never infer it from descriptors or operation names. |
| OBSERVE `3a8770c4` | Own Section 48's telemetry contract: bounded record/context/labels/cardinality, queue and retention limits, destination-specific release, required versus best-effort delivery, backpressure, cancellation, shutdown, and sink containment. Source telemetry remains distinct from Section 12 semantic evidence. |
| Vocabulary defect `758196e3` | Own normative text/num/random module and item vocabulary authoring with the family owners; choose the clause route, not a PUB freeze prerequisite. Derive each name from a reviewed owning clause before STDLIB-ITEMS authors rows. No names or interface digests are approved by this decision. |
| STDLIB-ITEMS `0a6d2292` | Consume the vocabulary above, then implement exact rows, interface identity changes, and invented-name rejection. RANDOM-BEHAVIOR `cf27072a` remains downstream of those rows and owns draw/settlement/recovery behavior, not deterministic PRNGs. |
| TIME `4cf122ef` | Own its missing normative family section and exact module/item rows, consuming Section 33 rather than redefining civil ambiguity, pinned rule data, or monotonic/wall separation. Then implement timers and family behavior in slices. |
| ARTIFACT `d65e4e69` | Own its missing normative family section and rows, consuming Sections 15/20/25/28/45. Separate immutable identity, grants, affine transport, retention, and durable revalidation; IDs never confer bearer authority. |
| INTEROP `0aaebf65` | Own the declaration/model prerequisite as well as enforcement: distinguish typed host actions, audited deterministic intrinsics, isolated components, and explicitly trusted native escapes. Declare forfeited guarantees and reject unsupported isolation before loading; wrappers alone establish no confinement. |

RESOURCE-RUNTIME also retains the four obligations consolidated from
RUNTIME-RESIDUAL `92d845ac`: text cancellation safe points with atomic publication,
numeric semantic-work/cancellation limits and strategy equivalence, value-storage
recovery-projection equivalence, and linked-artifact durable execution evidence.
The consolidation must not disappear from its successor's scope.

The IO successor's hard prerequisites are RESOURCE-RUNTIME and the landed IO,
FAULT, and HOST-SPEC contracts. The reverse edges to consumers and publication
are removed from that successor only. The original milestone catalog is a
historical preregistration, not a fabricated record of these later successors.
No consumer obligation, acceptance criterion, or original gate fan-in is waived.

## Benchmark mechanism decision

BENCH `f4d5e02c` adopts non-gating timing observations alongside deterministic
semantic-work/storage assertions through production interfaces. No new dependency
or unsafe allocator exemption is authorized. Record workload/input identity,
toolchain, target, strategy, configured budgets, raw observations, and repetitions;
compare semantic outcomes and charges before considering performance. Timing is
never the sole evidence and never a CI pass/fail threshold. This is consistent
with the preregistered functionality-first policy and deferred quantitative
thresholds. Representative whole applications and preregistered quantitative
thresholds still require later work; this mechanism decision does not close BENCH.

## Qualification disposition

Defect `be47045e` retains the governed requalification route. Do not substitute
digests, relabel existing async/generics evidence, or turn adoption into a blocked
state merely to make a generation command green. Existing publication bytes are
not asserted to be a coherent frozen fallback: the snapshot and its index must
also agree. Preserve unrelated working specification and environment edits.

Run `python3 governance/audit_spec_revision.py` for a read-only, aggregate report
of the current specification, reviewed sidecars, adoption records, catalog pins,
and publication index/snapshot. Exit zero means only these revision bindings
agree, never that review, evidence, or release qualification passed.

The qualification owner must first select and review the exact candidate bytes,
review clause coverage/applicability and Section 14 excerpts, then obtain genuine
async and generics qualification for those bytes. Only then run governed
requirements/protocol generation to a no-change fixpoint, the revision audit,
generated/workspace/governance checks, and the repository floor from a clean
checkout. PUB `624db3b4` freezes evaluated inputs; it does not invent upstream
vocabulary. REL-REFRESH `086a419b` remains downstream of REL and PUB; none of this
changes a release record or enables a release claim.

## Decision-record fields and validation

- **Normative owner:** the issue in each row owns authoring its named missing
  contract in `SPEC.md`, with clause-derived generated keys; this document grants
  no runtime semantics before that review.
- **Compatibility owner:** the same family/runtime owner plus PUB for interface,
  authority, wire, and publication identity effects; REL owns adoption separately.
- **Evidence owner:** `gantry-conformance` with the owning subsystem; test happy
  paths, exact refusal/limit boundaries, cancellation/fault/late-completion cuts,
  and recovery/target cells actually implemented. No fabricated evidence rows.
- **Publication blocker:** unreviewed clauses, incomplete implementation or
  required evidence, and `be47045e` prevent currency/qualification claims. Design
  authoring may proceed without final consumer or publication closure.
- **Rerun set:** affected family and common-contract lanes, requirement ledger,
  interface/aggregate identities, publication integrity, generated/workspace/
  governance, `just fmt`, `just check`, `just clippy`, and bounded `just test`.
  Authority, recovery, or public-contract changes also rerun the affected
  preregistered applications and matrix cells before their qualification.

This addendum resolves ownership and ordering choices only. Normative family
sections, runtime adapters, representative applications, and independent
qualification remain concrete work, not implicit completed Phase 2–4 features.
