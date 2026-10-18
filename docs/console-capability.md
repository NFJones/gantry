# The `std.console` capability surface

This note records the `std.console` surface that the model declares: its canonical package
identity, its host-domain family, applicability, and categories, the declared operations and their
recovery classes, the shape a console capability requirement must have, the normative bounds already
in force, its separation from the common I/O contract and the pure families, and what the surface
does not claim. It records declarations; it does not add a right spelling, a terminal-control
capability, an adapter, or a runtime.

## Package identity

`crates/gantry-ir/src/stdlib.rs` declares the capability family `PackageFamily::Console` with the
canonical logical package name `std.console` and the wire spelling `console`. The family is one of
the twenty entries of `PackageFamily::ALL`, it is excluded from `is_pure`, and `GNT-34.1` lists
`std.console` among the capability-backed families of the logical standard-library hierarchy.

## Host-domain family, applicability, and categories

`crates/gantry-ir/src/generated/host_domain.rs` declares the host-domain family
`HostDomainFamily::Console` with the wire spelling `console`. Its closed categories are those of
`GNT-29.4`: closed, interrupted, read, write, and unclassified, and that clause also fixes the
envelope rule that a console declaration carries no terminal handle, terminal capability, terminal
escape sequence, or host-specific error detail. Under `GNT-29.10` the console applies to the
application target only, and `GNT-29.11` fixes that an adapter declaration is evidence only and is
never an implementation, binding, capability grant, or runtime availability claim.

## Declared operations and their recovery classes

`crates/gantry-ir/src/console.rs` publishes the declared operations of `GNT-46.2` — read, write, and
flush, in that canonical order — and the recovery classes of `GNT-46.3`: a read and a write are
`non_idempotent`, a flush is `idempotent` because repeating it delivers no additional octet, and no
console operation is `read_only`. `CONSOLE_OPERATION_FACTS` publishes the same facts per operation,
including that only an adapter that owns a replayable or transactional source and binds the admitted
read identity to its exact result may retry a read.

## Declared signatures, requirement groups, and authority admission

`crates/gantry-ir/src/console.rs` publishes the five typed signatures of `GNT-46.6` in canonical
declaration order — `input::read`, `output::write`, `output::flush`, `terminal::inspect`, and
`control::set_mode` — with the receiver kinds `input-receiver-loan`, `output-receiver-loan`,
`observation-receiver`, and `control-receiver`, the result shapes `chunk-or-error`,
`accepted-prefix-receipt-or-error`, `unit-or-error`, and `terminal-report-or-error`, and the exact
operation identities `std.console::input::read@1`, `std.console::output::write@1`,
`std.console::output::flush@1`, `std.console::terminal::inspect@1`, and
`std.console::control::set_mode@1`. `declare_console_signatures` and `admit_console_signatures`
declare and admit exactly that closed set: a missing, partial, extra, duplicated, reordered, or
retyped surface is refused under `console-signature-undeclared`. The `ConsoleOperation` vocabulary
stays exactly the three spellings `read`, `write`, and `flush`; `terminal::inspect` and
`control::set_mode` are not members of it, so no existing variant is read as implementing them, and
`terminal::inspect` is the only `read_only` shape.

`ConsoleRequirementGroup` publishes the four separately granted groups `input`, `output-flush`,
`observation`, and `control` with the exact identities each governs, and `implies_authority_over`
is `false` for every ordered pair of groups: no group satisfies another group requirement, and no
ordering of the groups is an authority chain.

`GNT-46.8` fixes access admission. `ConsoleAccessInjection::from_launch` is the only constructor,
so access is injected by the launch and never reconstructed from an ambient numeric descriptor. A
call whose group carries no injected grant is refused under `console-authority-missing` before it
consumes an input cursor or delivers an octet; a presented grant that the injection did not issue
is refused under `console-authority-forged`; an access presented as a numeric descriptor is
refused under `console-authority-ambient-descriptor`. The owner that granted the access owns the
final flush and the shutdown, and `ConsoleShutdownSettlement` publishes a flush failure separately
from the fixed task outcome: `task_outcome_rewritten` is `false` for every settlement.

`GNT-46.9` fixes the output boundary. The first declared output target is the redirected or
otherwise non-controlling sink, which publishes its octets unchanged. On an attached terminal,
octets containing the declared control octet `0x1b` are refused under
`console-control-bearing-output-refused` unless the same requester holds an injected grant of the
`control` group, and the refusal publishes the presented octets unchanged: no octet is stripped,
replaced, or sanitized, and a refusal is never a silent control grant. An output presented to a
sink kind the section does not declare is refused under `console-safe-output-unsupported` even when
the octets carry no control octet.

## The shape of a console capability requirement

The operation form of a public capability requirement is one four-part identity: the package-qualified declaration path,
the complete canonical typed signature, the capability family, and the recovery class, which
`crates/gantry-ir/src/authority.rs` composes in `AuthorityRequirementId::new` and the
abstract-requirement contract of `GNT-6.5` owns. The console surface declares three of those parts
today: the capability family spelling `console`, the admissible recovery classes, and the complete
canonical typed signatures of `GNT-46.6-console-operation-signatures`. The declared recovery
classes are the two classes its declared operations state — `idempotent` for a
flush and `non_idempotent` for a read or a write — while the two declared non-I/O signatures state
`read_only` for `terminal::inspect` and `idempotent` for `control::set_mode`. No operation of the
`ConsoleOperation` vocabulary is `read_only`, so a console capability requirement that names one of
those three operations can never carry the excluded `read_only` class. The typed signature part of the
requirement is published as an exact operation identity: `std.console::input::read@1`,
`std.console::output::write@1`, `std.console::output::flush@1`,
`std.console::terminal::inspect@1`, and `std.console::control::set_mode@1`. The package-qualified
declaration path is still declared nowhere in the repository, so this note publishes no right
spelling, mints no requirement identity, and records that single missing part as an obligation
rather than a claim.

## Normative bounds already in force

- `GNT-46.0-console-foundation-scope` publishes the section scope and the frozen diagnostic
  `console-observation-inconsistent` owned by `GNT-46.5-console-terminal-observations`, and
  `GNT-46.1-console-modules-and-item-rows` publishes the four declared modules and their rows.
- `GNT-46.2-console-bounded-operations` fixes the declared operation vocabulary and its consumption
  of one admitted `std.io` request; `GNT-46.3-console-operation-recovery-and-accepted-input` fixes
  the recovery classes, the nontransactional accepted input, and the interruption category that is
  never a progress observation.
- `GNT-46.4-console-encoding-and-shutdown-settlement` fixes the payload, encoding, protected-data,
  flush, and shutdown facts: octets-only payloads, decoding owned by the consuming family, protected
  values not an octet source, and shutdown ownership with the access requester.
- `GNT-46.5-console-terminal-observations` fixes the terminal observation vocabulary and the control
  boundary: the detection facts `terminal-attached` and `terminal-not-attached`, a dimension
  observation inside `CONSOLE_DIMENSION_BOUND`, and terminal control left separately authorized.
- `GNT-46.6-console-operation-signatures` declares the five typed signature shapes, their receivers,
  their result shapes, their exact operation identities, and the closed declare-and-admit surface.
- `GNT-46.7-console-requirement-groups` declares the four separately granted requirement groups
  with exact operation identities and no authority implication between them.
- `GNT-46.8-console-authority-admission` declares launch-injected access, the missing, forged, and
  ambient-descriptor refusals, and grantor-owned final flush and shutdown with the flush failure
  separate from a fixed task outcome.
- `GNT-46.9-console-control-and-output-boundary` declares the redirected and attached-terminal
  output targets, the escape control octet, the byte-preserving control-bearing refusal, and the
  unsupported-safe-output refusal.
- `GNT-29.15` is the host-contract non-claim: this section promises no runtime adapter or host
  operation, so no model fact or test here is a host guarantee.

## Separation from the common I/O contract and the pure families

The one-call request contract, the progress derivation, and the backpressure fact stay with the
common I/O foundation, and the console consumes them: it publishes no second request contract, no
second octet bound, and no second progress vocabulary. Text, scalar, line, and codec decoding of
console octets belongs to the family that owns it, so an encoding error is not a console category.
A protected value, envelope, credential, or key is not an octet source for a console operation, so
no console clause is a release authority, a redaction rule, or an implicit declassification.

## What this surface does not claim

- It declares no right spelling, no console capability requirement identity, and no authority-layer
  family declaration: the package-qualified declaration path is undecided, and this note records
  that single gap instead of claiming the requirement identity.
- It grants no terminal-control capability: no console read, write, flush, detection, or dimension
  observation carries terminal-control authority, and the `std.console::control` row
  carries only the signature, requirement-group, admission, and refusal-boundary contracts of
  `GNT-46.6` through `GNT-46.9`. A declared grant, a typed flag value, and an admitted write are
  never a control capability.
- It provides no adapter, no deterministic or raw adapter, no cross-target mapping, no launcher or
  protected-rendering arrangement, no terminal handle, and no descriptor, and it claims no runtime
  availability, quota, charge, or cancellation facility.
- It claims no behavior: the surface is a declaration surface, and the runtime, adapter, and
  cross-target arms that consume it are not published here.
