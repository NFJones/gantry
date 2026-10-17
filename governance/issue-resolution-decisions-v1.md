# Issue-resolution decisions v1

Status: accepted delegated design consensus; implementation and qualification pending.

This record implements the user's delegation to decide the outstanding design
questions using Gantry's declared purpose: typed, explicit, reviewable agent/tool
orchestration, bounded work, explicit authority, and fail-closed recovery. It
extends `upstream-contract-decisions.md`; it does not change `SPEC.md`, the
historical preregistration, implementation support, or any qualification verdict.
The decisions below authorize the owning issues to author and implement their
contracts without another unspecified owner-choice or PUB-freeze prerequisite.
Normative review, implementation, negative evidence, and genuine qualification
remain required. A selected declaration is not a delivered feature.

Four large reviewers independently inspected vocabulary, runtime/I/O, candidate
qualification/family boundaries, and tooling/identity/evaluation. Vocabulary and
qualification were cross-reviewed together; runtime and tooling were
cross-reviewed together, with additional timer/artifact and evaluation review.
The parent reconciled the corrections, including static operation identity,
result-only resource authentication, and the executable test-harness subset.
All four scoped reviewers concurred after the bounded final-review amendments:
explicit authored-candidate freeze, settled-versus-pending task-transfer state,
I/O progress-versus-effect certainty, caller refusal versus host fault, staged
family applicability, and prohibition of all timing-based CI thresholds.
Review participants were agent-%2 (vocabulary), agent-%3 (resource/I/O),
agent-%4 (qualification/family boundaries), and agent-%5 (tooling/evaluation).

## D1. Vocabulary and exact declaration metadata

Owners: vocabulary defect `758196e3`, STDLIB-ITEMS `0a6d2292`, and subsequently
RANDOM-BEHAVIOR `cf27072a`. Adopt exactly these 17 exported **module** rows:

| Defining package | Module | Existing semantic clause |
| --- | --- | --- |
| `std.text` | `builders` | `GNT-41.4` |
| `std.text` | `case_mapping` | `GNT-41.3` |
| `std.text` | `comparison` | `GNT-41.6` |
| `std.text` | `conversions` | `GNT-41.9` |
| `std.text` | `graphemes` | `GNT-41.7` |
| `std.text` | `matching` | `GNT-41.8` |
| `std.text` | `normalization` | `GNT-41.2` |
| `std.text` | `traversal` | `GNT-41.5` |
| `std.text` | `values` | `GNT-41.1` |
| `std.num` | `bits` | `GNT-40.4` |
| `std.num` | `conversions` | `GNT-40.3` |
| `std.num` | `floating` | `GNT-40.5` |
| `std.num` | `integer` | `GNT-40.2` |
| `std.num` | `overflow` | `GNT-40.7` |
| `std.num` | `prng` | `GNT-40.1` |
| `std.num` | `text` | `GNT-40.6` |
| `std.random` | `entropy` | New random family scope and row-owning clauses |

New numeric/text naming clauses own the closed module sets; proposed anchors are
`GNT-40.8` and `GNT-41.12`, subject to collision checks at authoring. Existing
clauses continue to own behavior. Text rows also bind scope `41.0` and value bound
`41.11`; values/conversions additionally bind admission bound `41.10`. Numeric
rows also bind scope `40.0`. Store clause references in specification order.

All rows use `Module` class and `Stable` declaration compatibility. Text/num
retain Portable and Application modes over Library and Binary targets. Random
starts Application-only over Library and Binary. Stable namespace compatibility
is not stable-edition status or runtime availability, as with existing ENV rows.
No Durable/Test/Example/Benchmark expansion, prelude addition, adapter dependency,
pure-DAG change, callable signature, or new numeric/text behavior is implied.

`entropy` needs its own normative naming clauses: `GNT-34.1` and `GNT-29.8` do
not declare that module. Allocate the random section during authoring, not by
assuming that a planning reservation is normative. It names a capability-backed
namespace, not a raw entropy API or authority grant. RANDOM-BEHAVIOR owns bounded
draw signatures, failures, cancellation/concurrency, accepted-work settlement,
and crash cuts. Fresh secure draws are not Durable merely because bytes can be
recorded; replay of an already committed result is distinct from a fresh draw.
No redraw-on-recovery, hidden entropy fallback, or substitution for `std.num`.

Next: review/land naming clauses, derive exact 9/7/1 row constants and
declare/admit surfaces, compose aggregate/interface identities, and add refusal
tests. Register random as a capability family, not in the pure dependency DAG.
Test exact membership/order, real anchors, missing/extra/duplicate/wrong-class/
tier/applicability rows, nonmutation on refusal, invented names, reserved words,
interface changes and unchanged algorithm lanes. Do not inherit the draft's
inconsistent reserved-word count as evidence.

## D2. Bounded qualification candidate, not manufactured attestations

Owner: `be47045e`, with actual async/generics qualification roles and publication.
Select the current committed base plus D1's reviewed vocabulary and derived
rows as the next bounded authored candidate. Do not first qualify the old SPEC
only to invalidate it immediately. Do not add full TIME/ARTIFACT/INTEROP/runtime
or general-purpose corpus completion to this revision-repair prerequisite.

Replace be47045e's hard whole-issue dependency on vocabulary defect 758196e3
with a reviewed-authored-artifact gate: committed naming clauses AND derived
rows/tests, with exact commit/hash and review references, are mandatory before
qualification. Vocabulary and row issues themselves stay unresolved until their
final generated/floor acceptance passes. Their whole-issue closure cannot be a
prerequisite for repairing the currency that closure requires. Keep the
vocabulary-before-rows semantic dependency and RANDOM-BEHAVIOR's row dependency;
do not change original phase gate fan-in. An empty hard-dependency list does not
permit qualification of an incomplete or pre-vocabulary candidate.

1. Finish and review the bounded slice. Record its actual committed SPEC, source,
   tests, lockfile, toolchain and input identities; invent no future digest.
   Freeze these authored inputs before coverage review and qualification;
   concurrent D3-D9 authoring stays outside this candidate. Any inclusion or
   material change requires an explicit recut and affected review/evidence reruns.
2. Review coverage/applicability and Section 14 excerpts across all accumulated
   drift, not merely the 17 new rows. Exclusions need genuine profile rationale.
3. Fresh-build and run affected async/generics behavior, refinement and negative
   evidence. Retain commands, results, reviewer scope, gaps and actual verdicts.
   Delegated decision authority is not a passing qualification verdict.
4. Update reviewed/adoption records only when justified, then run governed
   requirements/protocol generation and derived metadata to a no-change fixpoint.
   Do not substitute hashes under old verified labels or change adoption to
   blocked merely to bootstrap generation. Repair a demonstrated tooling cycle
   through a separately reviewed slice rather than bypassing its guards.
5. Freeze the complete resulting evidence/publication tree; independently check
   membership, embedded identities, and snapshot/index agreement. Material source
   or evidence changes invalidate affected prior verdicts and require reruns.
6. Require two clean deterministic regeneration passes, revision/digest audits,
   generated/workspace/governance checks, format/check/strict clippy, bounded full
   tests and applicable matrices. Audit-zero is necessary, not sufficient.

The inspected baseline had 14 revision-binding mismatches, including disagreement
between publication snapshot and index. No coherent frozen fallback or
qualification is asserted. PUB freezes evaluated inputs; REL and REL-REFRESH
remain separate downstream adoption work. Edition stays v1 (2026). Preserve
Section 16's profile-deferred scope and do not infer new macOS or SQLite
power-loss qualification from existing Linux release prose.

## D3. Source-resource identity, ownership, and restart

Owner: RESOURCE-RUNTIME `b87d011f`. Reuse landed accounting, physical transport,
leases and off-worker cleanup instead of reimplementing them.

- Choose a separate unclonable, process-local machine resource carrier backed by
  a registry-owned physical slot. Authenticate declaration/type, issuing subject,
  current owner generation/task and registry association. Never encode handles
  in ordinary values, JSON, raw hook results, prompts or checkpoints. Preserve
  existing guards; add dedicated carrier admission/completion/storage paths.
- Select the opaque declaration form `affine live_resource struct`, in that
  modifier order, through an explicit reviewed revision of the current stacking
  prohibition. It independently seeds affine ownership, live-resource class and
  unavailable ordinary recovery. Bare `live_resource struct` remains
  classification-only. Refuse source field-literal forging and ordinary copying.
- Authenticate receiver/input/output arrangements and cleanup/recovery contracts
  in the executable ABI. A live receiver makes `read(handle) -> bytes` a resource
  operation even though the result contains no handle. Result-only inference,
  names, and adapter behavior are insufficient; contradictory/missing metadata
  fails preflight and retained decode.
- Authority is the exact abstract requirement/signature/family/recovery bound to
  a selected current capability, lineage, rights, target/mode and revocation
  state. A type, handle, registry key or descriptor grants nothing.
- Move source place, destination, owner generation, cleanup task and charges
  atomically; refusal preserves all. Receiver loans are exclusive, sealed to the
  declaration/site/generation, end at settlement and cannot escape. Aggregates
  and closure captures use carrier-aware affine storage; mutation/consumption
  obeys FnMut/FnOnce rather than copied Fn captures.
- Same-task transport comes first. Later explicit same-execution task moves use
  distinct owned-move eligibility, not `IsolatedTaskCapture`; both tasks must be
  eligible and uncancelled, with no outstanding loan, accepted pending work, or
  unsettled containment. Settled historical containment evidence remains valid.
  Revalidate attenuated recipient authority, keep issuing provenance, and refuse
  bound-adapter handoff until a governed rebind exists.

No v1 physical-handle resurrection. Accounting recovery does not recreate a
physical slot, source cell, adapter or accepted-work lease. Later family-declared
immutable-content/committed-snapshot descriptors may permit fresh, all-or-none
host reacquisition after current identity/authority/retention/target validation.
That is a new operation and physical generation, not recovery of the old handle.
Mutable files/cursors, locks/watchers, sockets/TLS, process pipes, console/native
CWD, mutable buffers and pending I/O remain ineligible. Recover exact eligible
snapshot values instead; paths/digests/receipts are not bearer authority.

Durable cancellation composes existing graph/owner/finish machinery under one
authoritative predecessor and journal receipts: close admissions; retain accepted
leases until one settlement winner; commit outcome and cleanup obligation before
exposure or cleanup dispatch. Normal finish is committed Begin, owned off-worker
finalization, then validated completion. Emergency disposition and physical
cleanup outcome are distinct. Rejection preserves predecessor; indeterminate
submission fences publication/redispatch until authoritative recovery. Drop,
process exit or a missing slot is not cleanup success. Do not promise exactly-once
external destruction across crash without family-specific proof.

Keep text cancellation safe points, numeric work/cancellation limits,
value-recovery projection equivalence and linked-artifact evidence in scope.

## D4. Common I/O and dependency-ready consumers

Owner: IO-RUNTIME `ecc871f8`, consuming RESOURCE-RUNTIME and landed common
contracts. First deliverable: reviewed settlement envelope, executor-neutral host
boundary, bounded in-memory transport and deterministic race tests, without
enabling source handles or waiting for consumers/PUB.

Reuse `IoRequest`/`IoOutcome` and the existing 1,048,576-octet request bound.
Bind request to authenticated operation occurrence, generation, owner, kind and
quantity. Zero/excess read/write requests refuse before effects. Reads expose
exactly initialized returned bytes, including EOF with final bytes; writes report
exact accepted prefix while the caller retains the remainder. Short progress
settles one call, not the whole stream. Blocked means not-started for that call;
the blocked attempt settles once. Section 24 readiness and any subsequent new
call are explicit, never busy polling or hidden retry. This progress observation
does not prove definitely-not-started effect certainty: Section 20 admission and
cancellation facts govern certainty and retry eligibility.
Cancellation/interruption are settlement facts, not progress;
known accepted prefixes remain protected evidence, not fabricated successful
output. Malformed host completion lengths or request-mismatched outcomes cause
contained operational failure with no partial publication, without pretending
external effects are undone. Invalid caller requests refused before dispatch
remain admission refusals, not host faults.
Observer drop retains accepted-work buffers/leases. Late/duplicate/wrong-owner/
generation completions cannot publish or refund twice. Family errors,
operational failures and protected native diagnostics remain distinct.

- FS `ed0e707c`: first integrate rooted read-only immutable-file open/read/close
  after source carriers and common I/O, with grant/identity/symlink-race fencing.
  Writes, receipts, locks and watchers follow; declaration rows are not behavior.
- ENV `c8717957`: bounded immutable argument/env snapshots, explicit lookup and
  enumeration, update-as-new-snapshot, child attenuation, protection and launch
  injection can proceed without live I/O. Native CWD handles cannot.
- APP `3e1d6f75`: explicit entry/snapshots/injected stdio, renewable service fuel
  and fixed yield quanta; admission closure, cooperative stop, bounded final
  flush/drain, witnessed escalation, independent obligation settlement, then exit.
  Huge finite fuel and outstanding obligations are not orderly service semantics.

## D5. Console and observability contracts

CONSOLE owner `aee7225a` authors new Section 46 typed signatures and canonical
requirements before implementation. Select these semantic shapes (new types and
operations require reviewed clauses, not assumptions about existing variants):

| Operation | Selected shape | Recovery class |
| --- | --- | --- |
| `input::read` | Input receiver loan + bounded request -> chunk/error | non-idempotent |
| `output::write` | Output receiver loan + initialized octets -> prefix receipt/error | non-idempotent |
| `output::flush` | Output receiver loan -> Unit/error, no octet quantity | idempotent |
| `terminal::inspect` | Observation receiver -> terminal report/error | read-only |
| `control::set_mode` | Control receiver + typed echo/canonical-input flags -> Unit/error | idempotent |

Input, output/flush, observation and control are four separately granted groups
with exact operation identities. Stdio is launch-injected, never ambient numeric
descriptor authority. First output supports redirected/non-controlling sinks.
Attached-terminal output must refuse control-bearing bytes byte-preservingly or
require explicit control authority; no implicit control grant or sanitization.
Unsupported safe output refuses. Preserve accepted-input ambiguity/no replay;
the grantor owns final flush/shutdown, and flush failure cannot rewrite a fixed
task result.

OBSERVE owner `3a8770c4` selects typed log/metric/trace records, explicit context,
and immutable per-sink finite policy for bytes, fields/labels, context depth,
active-series cardinality, queues, retention, pending emits and shutdown. Missing
or unlimited policy refuses; zero denies that dimension. Admission is atomic,
without truncation, hidden eviction or overflow labels. Protected values are not
labels/identity; destination-specific Section 15 release precedes export queueing.
Required delivery completes at a declared sink acknowledgement, not enqueue;
best-effort returns queued/dropped and a full queue drops the newest whole record
with bounded accounting. Queued is not delivered. Required backpressure uses
bounded Section 24 waits. Accepted cancellation settles once; ambiguous writes
are not silently retried. Contain/poison sink faults, redact diagnostics, prohibit
recursive fault logging, retain delivery failures separately from fixed business
outcomes. APP owns bounded drain/flush. Telemetry is never Section 12 proof.

## D6. Time, content artifacts, and interoperability

Initial Application-only rows are declaration slices, not completion of TIME's
portable surface or either family's durable obligations. Later applicability
changes require owning clauses and interface identity/evidence updates.

TIME `4cf122ef`: dedicated family section consuming Section 33; closed modules
`civil`, `clocks`, `locale`, `rule_data`, `timers`, `values`. Stable namespace,
initially Application over Library/Binary. Pure Section 33 computations remain
deterministic, but do not imply Portable/Durable applicability for the package.
First deliver scope/row clauses, declare/admit surfaces, aggregate rows and
refusal tests/docs. Next implement injected monotonic clock and one-shot timers,
domain/generation-bound deadlines, readiness recheck/stale-wake fencing and one
completion/cancellation winner. This need not wait for I/O byte buffers. Wall
observations/preferences require separate authority; no UTC-derived deadlines,
raw monotonic restart guarantee, periodic scheduler or silent rule-data upgrade.
Preserve typed civil ambiguity, explicit locale and pinned data. Durable timers
need a later explicit reconstruction policy and real crash cuts. The historic
editing workaround/cascade-first deferral is superseded, not endorsed.

ARTIFACT `d65e4e69`: dedicated content/media family, not compiled-artifact
envelopes. Closed modules `grants`, `identity`, `readers`, `retention`, `writers`;
uploads are writer lifecycle. Stable namespace, Application over Library/Binary
initially. Content IDs and bounded metadata are not bearer authority; grants bind
holder/subject/content version/rights/lineage/generation and applicable expiry/
destination, with current authority checked at admission. Only authorized Gantry
operations mint/widen grants; attenuation cannot amplify. Payload-derived
metadata/status/length/readiness stays protected. First deliver declaration and
authority/admission model with exact refusals. First runtime slice consumes
RESOURCE/I/O: bounded in-memory upload/write -> consuming finish -> immutable
artifact/read. Publish normal content identity only after complete content and
metadata validation plus retention/grant admission. Partial/aborted uploads have
no completed artifact; accepted bytes keep a cleanup owner. Affine streams are
not serialized; durable references require explicit eligibility and retained
content/grant revalidation. Revocation fences new admissions, not accepted-work
settlement. Retention/provenance/authority and physical reclamation stay distinct.

INTEROP `0aaebf65`: typed host actions are the default. Declare four classes:
typed host action, curated/versioned deterministic intrinsic, isolated component,
explicit trusted native escape. Do not add a `std.interop` package to the closed
hierarchy. Intrinsics require exact vectors/bounded work/governed dependencies,
not arbitrary plugins. Isolated components start unavailable; admit only an
implemented/evidenced target/backend/ABI/limit contract and reject unsupported
isolation before loading/instantiation, with no native downgrade. Trusted escape
requires explicit package/target opt-in outside portable closure, initially no
durable use without a separate recovery contract, and named forfeited confinement,
memory-corruption isolation and cross-target guarantees. Wrappers/allowlists/
typed bytes/catch_unwind prove no sandbox. First deliver trust declarations,
admission model and audit metadata, with a loader spy proving no load on refusal;
then enforce through package/link/preflight. No pointers/layout/native unwinds in
portable source; `gantry-host` remains executor-neutral.

## D7. First tooling workflow

TOOLING-RUNTIME `000761b0` owns contract and implementation of
`gantry test --max-transitions N [--json] [PACKAGE_ROOT]`. N is mandatory positive
and finite, jobs initially 1. Local/offline/single-package, unit-only, no
substitutions, experimental non-shipping workflow; it does not claim Section 16
multi-package target support. Explicitly select the zero-argument Unit entry as
the test target, without test-name scanning, new annotations or shipping-interface
mutation; reject conflicting declarations and non-Unit/argument entries.

Derive programs from public source analysis, not an arbitrary retained-program
loader. Preflight source/toolchain/SPEC/profile/feature/target/stdlib identities,
empty effects/operation/live-resource inventories and empty authority ceiling.
Unknown/unsupported registry, authority, external artifact, kind or substitution
inputs refuse rather than disappear. Bound frontend inputs/stages/diagnostics
separately from runtime steps using declared policy units. Publish a versioned
identity/policy/ordered-result/structured-refusal report with a 1 MiB output
ceiling and no partial-success JSON or payload leaks. Exit 0 only for clean
completion, 1 for invalid source/fixed test failure, 2 for admission/operational/
no-tests/exhaustion/cancellation, 64 for malformed usage. Step exhaustion is not
wall-clock timeout; do not claim external interrupt/host cleanup support.

First slices: request/policy/report and preflight, facade adapter, thin CLI/docs/
goldens. Harness support for unit/integration/example is not compile-fail,
property, benchmark, replay, durable-recovery or substitution support. Ordinary
`run` defaults remain unchanged. This zero-authority slice needs no live I/O;
remaining workflows and whole-issue obligations remain required.

## D8. Closure-slot identity

AGENT-BIND `a83f2f76` owns the identity-contract sub-slice now with abstract
operation owners; `19929103` consumes the landed vocabulary. Keep whole-issue
ARTIFACT prerequisites without blocking independent identity authoring.

Use a versioned tagged closure-slot sum with exact StaticSiteId: agent uses
AgentRequirementId; tool uses existing ToolSlotId + ToolSlotKind; model-exposed
tool uses that identity with a distinct role; operation preferably reuses
AuthorityRequirementId (path/signature/family/recovery) with the site. The owning
operation clause decides composition with existing static LogicalOperationId,
which is already declaration-plus-site, not a dynamic invocation identity.
Do not invent a redundant untyped operation-ID module or widen the closed
three-member ToolSlotKind; source-handler remains its existing tool kind.

Bind descriptor/schema/effects/recovery to closure/artifact identity; mapping
revision/provider label is separate. Preserve domain-separated unambiguous
framing, canonical order, cross-role distinctness and the 4096 pre-dedup bound.
Preserve legacy tool bytes or explicitly version migration, never reinterpret
them. Refuse unresolved slots atomically. Test same-site/name cross-role cases,
site/package changes, permutations/duplicates, 4096/4097, unknown tags, changed
signature/recovery versus mapping replacement, and slot-is-not-authority cases.

## D9. Applications, strategy, benchmark and prospective evaluation

Owners: APP-CORPUS `c0f77512`, BENCH `f4d5e02c`, STRATEGY `5c56695c`, USABILITY
`276f7dad` and CONF `8aa06f51`. Preserve the canonical v1 seven applications and
seven task intents; Linux and macOS scope, Windows unsupported, one controlled
agent run per task, humans deferred initially, no current quantitative performance
threshold. Do not rewrite historical catalog bytes/intents to fit outcomes.

First product workload: bounded newline `key=value` parser, typed records/errors,
closure/iterator transformations, collection aggregation and canonical sorted
summary via real public source/std interfaces. Select 64/128/256-record fixtures
plus empty/malformed/duplicate/declared-bound cases prospectively; these are input
sizes, not measurements or thresholds. Missing public facilities are product
blockers, never permission for Rust-only substitutes. Next reuse the portable
core in the FS CLI; subprocess build, TLS client, HTTP service, agent service and
durable companion remain required. Linux is first executed cell; macOS remains
required/pending actual native evidence, not unsupported. Use each app's declared
mode and intended embedded/standalone arrangements, not a fabricated Cartesian
matrix. Fakes/mocked hooks/transcripts are semantic oracles; real-provider smoke
is separate interoperability, not a language gate.

Evaluate the existing interpreter first, sequential control and actual concurrent
configurations independently. Do not claim qualification, waive other shipped
strategies or treat physical storage variants as execution backends. Retain
non-gating timing plus deterministic semantic-work/storage assertions through
production interfaces; no unsafe allocator exemption, new dependency or timing
CI gate, including mixed timing-and-semantic thresholds. The existing runner
observes no semantic charges and cannot close BENCH alone; add public bounded
embedding/accounting evidence.

Choose this initial trial allocation in a prospective supplement before runs:

| Task intent | Application |
| --- | --- |
| create | parser/data library |
| modify | filesystem CLI |
| debug | subprocess build tool |
| cancellation | concurrent TLS client |
| sustained-service | HTTP service |
| explain | durable agent companion |
| security-review | agent-enabled service |

This allocation waives no full application/matrix or later protocol coverage.
Inventory candidate/support cells; implement real apps and separately label
exploratory calibration; review/freeze a new prospective protocol with workload
hashes/sizes, budgets, metric/formula definitions, repetitions/order, environment,
abort/missing-data rules, held-out inputs and material-change reruns before
qualification. Calibration is not held-out evidence. Later quantitative targets
require reviewed prospective preregistration, not fitted outcomes; any change to
non-gating timing policy needs explicit governance amendment. Retain all failed/
abandoned attempts and model/system/context/sampling/tools/starting inputs/results.
CONF authenticates shared package/interface/artifact/stdlib/tool-set/strategy
identities, distinguishes unsupported from untested, and returns failures to
owners instead of repairing or waiving them inside the gate.

## D10. Ownership, readiness, validation and issue disposition

- Normative owner: each issue named above authors its clauses/models; decisions
  remove unspecified design-approval deferrals, not actual prerequisite work.
- Compatibility owner: subsystem/family owner with PUB for public interface,
  wire, authority and publication identity effects; REL separately owns adoption.
- Evidence owner: subsystem plus gantry-conformance; qualification roles record
  genuine candidate-specific verdicts, not assertions from this record.
- Publication blocker: unreviewed clauses, incomplete behavior/evidence, and
  `be47045e` currency. Original gate fan-in, acceptance and claim blockers remain.
- Rerun set: affected clause/row/ABI/authority/resource/I/O/family/tooling lanes,
  requirement ledger, aggregate identities and publication integrity; generated/
  workspace/governance, fmt/check/clippy, bounded full tests; affected preregistered
  apps/cells after material public-contract, recovery, authority or strategy change.

Immediate parallel work: D1 clause authoring, D4 memory I/O, D3 carrier/ABI design,
ENV value snapshots, D5/D6 family clauses, D7 test policy and D8 slot vocabulary.
Integrations wait only for the concrete contracts they consume. Design acceptance
does not resolve any implementation issue. Do not close gates, PUB, REL or
REL-REFRESH until their existing evidence-based acceptance is met; LINK-DEFER's
Section 16 not-applicable ledger is not satisfied implementation evidence.

Key negative lanes include bounded request/queue/cardinality edges; initialized
bytes/EOF/short prefixes; cancellation, observer loss, stale/double completion;
forgery/copy/loan escape; owner/task/authority transfer; indeterminate journal and
cleanup cuts; raw-handle durable rejection; grant/terminal/protected-output denial;
clock-domain/stale wake races; artifact finish/retention/grant admission; zero
loader calls on unsupported isolation; tooling no-dispatch refusals and output
bounds. Planned validation is not a claim that these features/tests already exist.
