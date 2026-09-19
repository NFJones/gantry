# Authenticated package acquisition and registry trust

`SPEC.md` Section 27 (`GNT-27.0` .. `GNT-27.14`) fixes the client-side trust decisions every
package acquisition makes. The pure model is `crates/gantry-ir/src/registry.rs`, published as
`gantry::ir::registry`, and its machine-checked evidence is
`crates/gantry-conformance/tests/registry_trust.rs`, one lane per clause. This note is
documentation: it names what the model declares and what it refuses, and it grants nothing.

## Declared clauses

| Clause anchor | What it owns |
| --- | --- |
| `GNT-27.0-authenticated-package-acquisition-and-registry-trust` | the section scope: acquisition authenticates and authorizes before parsing, and the model is a pure decision surface |
| `GNT-27.1-immutable-source-identity-and-source-kind-vocabulary` | immutable source identity and the closed source-kind vocabulary; digest-only trust and namespace fallback are refusals, not conveniences |
| `GNT-27.2-canonical-publication-names-and-external-name-mapping` | canonical publication names with one admitted byte representation and the external-name map |
| `GNT-27.3-authenticated-metadata-snapshot-and-client-verification` | metadata-snapshot verification; a refusal names its causing entry |
| `GNT-27.4-trust-roots-and-delegated-authority` | explicit trust roots, narrowing delegations, and multi-root selection |
| `GNT-27.5-signing-key-rotation-and-compromise-recovery` | rotation and compromise recovery; a retired key cannot rotate, delegate, or extend a chain |
| `GNT-27.6-expiry-freshness-and-offline-mode` | expiry, freshness, offline mode, and declared maximum staleness |
| `GNT-27.7-rollback-and-freeze-resistance` | rollback and freeze resistance against retained state |
| `GNT-27.8-publication-immutability` | publication immutability per release |
| `GNT-27.9-yank-semantics` | yank semantics under explicit lock and update policy; a yank never silently rewrites |
| `GNT-27.10-security-revocation-and-durable-execution-policy` | security revocation and its durable-execution policy input |
| `GNT-27.11-vcs-path-and-vendor-source-verification` | pinned VCS, path, mirror, and vendor verification before parsing |
| `GNT-27.12-lockfile-evidence-binding` | lockfile evidence binding for every acquired source |
| `GNT-27.13-trust-failure-attribution` | trust-failure attribution: one reason and one clause anchor per refusal |
| `GNT-27.14-registry-non-claims` | the frozen non-claims below |

## What the model decides

- A source declaration binds exactly one canonical identity; substituting a different source kind
  is a refusal rather than an implicit fallback, and a moved or rewritten reference never keeps the
  old identity.
- Authority is always explicit: declared roots, narrowing delegations with timing, and an explicit
  multi-root selection policy. Nothing is trusted because a name is well formed.
- Freshness, rollback, immutability, yank, and revocation are declared inputs. Stale or expired
  metadata, a greatest-snapshot rollback, a post-lockfile yank outside policy, and a revoked
  publisher each refuse; none is repaired or reinterpreted.
- VCS checkouts, path trees, mirrors, and vendored directories are verified against authenticated
  evidence before parsing, and the verified facts are bound into the lockfile record.
- Every refusal carries one `TrustFailureReason` and the clause anchor that owns it, so a failure
  identifies the causing dependency declaration instead of a generic acquisition error.

## Trust-failure attribution and diagnostics

The model publishes 41 trust-failure reasons and 33 registry diagnostic codes. Every refusal carries
exactly one `TrustFailureReason` and the clause anchor that owns it, and the reason and clause
matches are exhaustive, so a new refusal cannot be added without naming a reason and an anchor.
Published diagnostic codes are a coarser surface rather than a one-to-one alias: 15 conditions
deliberately report no code (`RegistryError::code` returns `None` for structural, declaration, and
retained-state conditions, including `TrustRootAbsent`, `ObservedInstantMissing`, and
`RetainedContentMissing`), and several conditions share one spelling where the specification groups
them — `PinMismatch` and `VcsPinIdentityMismatch` both report `registry-vcs-pin-mismatch`, and the
name-collision and yank-condition families share their reasons. The lanes
`gnt_27_13_reason_owned_anchors_cover_every_error_surface` and
`gnt_27_clause_owned_structural_failures_have_matching_reasons_and_anchors` exercise representative
conditions of that surface; the exhaustive guarantee is the compiler-checked match, not a test over
every variant.

## Non-claims (`GNT-27.14-registry-non-claims`)

In declared order, the model publishes these non-claims and `check_registry_non_claims` refuses to
present any of them as a guarantee:

1. `verified-provenance-safety` — verified provenance is not a safety, correctness, or behavioral
   compatibility guarantee.
2. `transparency-log-operation` — no transparency-log operation or equivocation detection is claimed;
   such a log may strengthen audit but never substitutes for client verification.
3. `registry-honesty-beyond-verified-entries` — no registry honesty beyond entries authenticated
   under a declared root.
4. `transport-universe-equivalence` — a mirror or vendor copy is compared as one declared
   authenticated snapshot and claims nothing about a nominal universe.
5. `yank-security-statement` — a yank is a resolution-policy change, not a security statement.
6. `revocation-retroactive-execution-prevention` — revocation never rewrites, reinterprets, or
   substitutes an existing artifact and does not prevent an already linked executable from running.
7. `offline-currentness` — an offline result reports declared age and never claims an online check.
8. `resolution-termination-or-availability` — the model fixes checks and refusals, not a schedule or
   availability promise.
9. `automatic-durable-migration` — cancellation, drain, and migration facilities stay profile-gated;
   durable execution is not promised to migrate automatically.

## Boundaries and downstream work

- The section adds no registry protocol operation, no downloader, no package manager policy, and no
  host adapter: adapters remain leaves and no standard package depends on one.
- Publication membership, distribution, and release adoption are not claimed here; they belong to
  the publication and release issues, which freeze these identities rather than restating them.
- Physical repository layout, crate names, and lockfile paths are never source identity.

## Evidence

| Surface | Location |
| --- | --- |
| Pure model and closed vocabularies | `crates/gantry-ir/src/registry.rs` |
| Clause lanes, refusals, and attribution | `crates/gantry-conformance/tests/registry_trust.rs` |
| Declared names pinned against this note | `registry_trust_note_names_every_declared_clause_and_non_claim` |

The model is exercised by the repository floor (`just fmt`, `just clippy`, `just test`) together
with the generated, workspace, and governance checks.
