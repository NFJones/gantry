# Unreadable secret references and protected credential authority

`SPEC.md` Section 21 (`GNT-21.0` .. `GNT-21.9`) fixes what a source-visible secret or
credential reference may be. The pure model is `crates/gantry-ir/src/secret.rs`, published through
`gantry::ir`, and its machine-checked evidence is `crates/gantry-conformance/tests/secret_model.rs`,
one lane per behavior. This note is documentation: it names what the model declares and what it
refuses, and it grants nothing.

## Declared clauses

| Clause anchor | What it owns |
| --- | --- |
| `GNT-21.0-secrets-and-credentials` | the section scope: a secret or credential is an unreadable, authority-bound handle, and this model is a pure decision surface with no material |
| `GNT-21.1-unreadable-secret-references` | unreadability: no accessor, conversion, serializer, or diagnostic returns material, and a reference is not clonable or renderable |
| `GNT-21.2-secret-authority-binding` | binding to a holder instance, a capability requirement, the selected implementation binding, a protected class, and preferably one logical operation |
| `GNT-21.3-secret-lifetime-transfer-and-attenuation` | lifetime, monotone attenuation, delegation, affine transfer, and the strict generation advance a transfer must make |
| `GNT-21.4-secret-generation-fencing` | generation fencing: a fenced generation is refused, and no successor path reinstates it |
| `GNT-21.5-secret-expiry-and-revocation-races` | expiry and revocation racing the admission commit point |
| `GNT-21.6-secret-redaction-and-protected-audit` | redacted renderings and capability-gated audit evidence; the records of this model name it as the owning clause |
| `GNT-21.7-secret-tenant-isolation` | tenant isolation: a foreign tenant and a tenant change are both refused |
| `GNT-21.8-durable-secret-revalidation` | durable cuts revalidate before a use is admitted and rebind fail-closed on resume |
| `GNT-21.9-secret-non-claims` | the frozen non-claims listed below |

## What the model decides

- A reference is an identity, not a value. Its identity is derived under a domain separator, so
  the same holder, requirement, binding, operation, and tenant always derive the same reference and
  a differently split pair cannot be confused with it.
- Authority is explicit: the holder binding names the holder instance, the requirement, and the
  selected implementation binding, and the reference carries the protected class, the logical
  operation it serves, its generation, its rights, and its lease policy.
- Attenuation and delegation are monotone: rights and lease are never amplified, and a successor
  that satisfies another requirement or another binding is refused (`secret-transfer-holder-mismatch`).
- Transfer is affine and strictly advances the generation; a successor that does not succeed the
  current generation is refused (`secret-transfer-not-succeeding`).
- Fencing and staleness are different verdicts. A fenced generation is refused and never
  reinstated (`secret-fenced`, `secret-reinstatement-forbidden`), while a stale input is refused
  without latching a fence, so a later fresh generation can still be admitted
  (`secret-stale-generation`).
- Revalidation immediately before a use returns one of three verdicts: fresh, stale with exactly
  one reason, or fenced by revocation or expiry. Admission records the transition, and the audit
  evidence is capability-gated and names its owning clause.
- A durable cut neither serializes a reference nor restores a handle. A cut revalidates against
  the committed requirement, binding, operation, class, lineage root, and generation, and a rebind
  refusing any of those is fail-closed (`secret-rebind-requirement-mismatch`).
- Diagnostics and redacted renderings carry no material and no digest of material.

## Declared refusal codes

Every refusal of the model reports one registered code, and each refusal names exactly one owning
clause of Section 21. Two codes are deliberately shared: every refusal passed through from the
landed authority model reports `secret-authority` (the code names the condition, not the inner
detail), and both fence categories report `secret-fenced` (the category is carried by the refusal
and its rendering, not by the code).

| Code | Refusal |
| --- | --- |
| `secret-authority` | the landed authority model refused the operation |
| `secret-tenant-mismatch` | the presented tenant is not the tenant the reference is bound to |
| `secret-tenant-change-forbidden` | the presented tenant would change the bound tenant |
| `secret-operation-mismatch` | the presented operation is not the operation the reference serves |
| `secret-class-change-forbidden` | the presented class would change the carried protected class |
| `secret-stale-generation` | the presented generation is not later than the generation already held |
| `secret-fenced` | the generation is fenced by revocation or expiry |
| `secret-transfer-not-succeeding` | the presented successor does not strictly advance the generation |
| `secret-transfer-holder-mismatch` | the successor satisfies another requirement or another binding |
| `secret-rebind-requirement-mismatch` | the durable cut differs in requirement, binding, operation, class, or lineage root, or is not resumable |
| `secret-reinstatement-forbidden` | the generation is fenced, so no successor path may reinstate it |
| `secret-inadmissible-audit-record` | the audit record is inadmissible: a use without the admission that committed it, another generation's admission, or an admission attached to a use that was not admitted |
| `secret-serialization-forbidden` | the model has no serializer, so no durable cut can be produced by one |
| `secret-extraction-forbidden` | the model has no material accessor, so material can never be extracted |

## Staleness vocabulary

One revalidation verdict carries exactly one reason from the closed vocabulary: `holder`,
`tenant`, `operation`, `class`, `generation`, `lifetime`, `policy`, `reference`.

## Non-claims

The section promises none of the following, and the model reports them as excluded claims rather
than as satisfied or partially satisfied rows: `physical-zeroization`, `ordinary-extraction`,
`ambient-discovery`, `bearer-without-lineage`, `checkpoint-serialization`. Physical zeroization,
erasure of copies made outside Gantry's control, memory safety against a hostile host,
side-channel resistance, and protection of material after an authorized protected release are
likewise outside the section.

## Boundaries

- Credential host contracts, leaf adapters, runtime lineage, and resume-time rebinding behaviour
  belong to the capability and runtime issues that own them; this model decides the value layer
  only and depends on no adapter.
- Ordinary byte or string key APIs are not secret references and receive none of these guarantees.
