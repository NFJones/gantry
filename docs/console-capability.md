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

## The shape of a console capability requirement

`GNT-6.5` item 5a and `crates/gantry-ir/src/authority.rs` compose one public capability requirement
from a canonical signature, a capability family, and a recovery class, and the authority model
validates an owner-supplied family spelling. A console capability requirement therefore names the
declared family spelling `console` together with one of the three recovery classes that the
declared console operations state, so a requirement can never carry a class no console operation
declares. This note publishes no right spelling and declares no console requirement identity,
because the authority layer owns that vocabulary and no typed console signature exists yet.

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
  family declaration; the requirement shape above is a derivation rule, not a minted identity.
- It grants no terminal-control capability: no console read, write, flush, detection, or dimension
  observation carries terminal-control authority, and the `std.console::control` row stays a
  declared name without a published contract.
- It provides no adapter, no deterministic or raw adapter, no cross-target mapping, no launcher or
  protected-rendering arrangement, no terminal handle, and no descriptor, and it claims no runtime
  availability, quota, charge, or cancellation facility.
- It claims no behavior: the surface is a declaration surface, and the runtime, adapter, and
  cross-target arms that consume it are not published here.
