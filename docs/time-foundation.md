# Time package foundation

`SPEC.md` Section 51 owns the `std.time` family contract. The declaration clauses
`GNT-51.0-time-foundation-scope`, `GNT-51.1-time-modules-and-item-rows`, and
`GNT-51.2-time-declaration-non-claims` publish the family identity and the closed
module rows. `GNT-51.3-injected-monotonic-clock` and `GNT-51.4-one-shot-timer`
publish the first clock and timer behavior slice. The family is not a periodic
scheduler, a timezone integration, a host adapter, a durable timer store, or a
wall-clock observation surface.

## Identity and applicability

`GNT-51.0-time-foundation-scope` identifies the capability-backed family and consumes Section 33
without restating it. `GNT-51.1-time-modules-and-item-rows` declares exactly six stable modules,
in canonical name order:

- `std.time::civil`
- `std.time::clocks`
- `std.time::locale`
- `std.time::rule_data`
- `std.time::timers`
- `std.time::values`

Every row applies only in the application semantic mode over the library and binary target
kinds. `TIME_MODULE_ROWS` publishes the rows, and `TIME_MODULE_CLAUSES` publishes the scope and
row-owning clause vocabulary. `declare_time_surface`, `admit_time_surface`, and
`validate_time_module_rows` refuse a missing, extra, duplicate, reordered, wrong-class,
wrong-tier, wrong-applicability, or wrongly-bound clause row instead of repairing it, and a
refusal never mutates the decided graph. `canonical_time_hierarchy` composes the family with the
pure hierarchy, and `canonical_std_hierarchy` includes the same defining package and item
identity. The aggregate catalog records the package interface digest. Repository module paths
and host adapters are not the source-level package identity.

Wrong class, duplicate, missing, extra, reordered, and wrongly-bound clause rows are refused
under `std-invalid-name-classification` of `GNT-34.2-name-classification`; a wrong tier is
refused under `std-invalid-stability-transition` of `GNT-34.6-stability-tiers`; and wrong
applicability is refused under `std-unsupported-applicability` of
`GNT-34.7-applicability-and-feature-granularity`. The declaration clauses own no diagnostic
spelling and add no refusal condition to Section 33.

## Injected monotonic clock

`GNT-51.3-injected-monotonic-clock` declares one explicit sample port rather than an ambient
clock. A caller supplies the `MonotonicClock` implementation and passes it to the model, so the
model reads no thread-local, process, global, environment, or host clock and owns no clock
instance. A `ClockDomainId` names one nonempty bounded ASCII domain, a `MonotonicInstant` carries
that domain and one exact count of elapsed microseconds since its epoch, and `ClockObservation`
refuses a sample that moves backwards within one domain. `TimerDuration` and
`MonotonicInstant::checked_add` use exact checked arithmetic, so an overflowing deadline is
refused under `time-deadline-overflow` rather than saturated or wrapped. A sample, deadline, or
clock of another domain is refused under `time-wrong-clock-domain`, and a deadline that names another waiter-generation fence than its registration is refused under `time-generation-mismatch`.

Monotonic order belongs to one epoch. A new epoch is a new `ClockDomainId`, and the model claims
no raw tick continuity across epochs, restarts, processes, or hosts. A sample is never a wall
time, a civil time, a timestamp, or a UTC instant, and UTC never supplies a monotonic deadline.

## One-shot timer

`GNT-51.4-one-shot-timer` declares one deadline bound to one clock domain and one waiter
generation fence of `GNT-24.2-wait-identity-and-generations`. `TimerDeadline` binds the domain,
the exact deadline instant, and the fence, so a deadline can never be compared with a foreign
sample or woken under a foreign fence. `OneShotTimer::arm_after` and `OneShotTimer::arm_at`
perform the atomic registration and readiness recheck of
`GNT-24.1-atomic-registration-and-readiness-recheck`: a zero, equal, or past deadline publishes
the timeout cause of `GNT-24.3-wake-causes-and-wake-ownership` as readiness and settles without a
later wake, while a future deadline registers one live waiter in a `WaitSet`.

`OneShotTimer::expire` samples the injected clock, refuses a not-due observation under
`time-timer-not-due` without clearing the deadline or recording the refused sample, and wakes
the registered waiter with the timeout cause. `OneShotTimer::cancel` wakes it with the landed cancellation cause. The first
admissible wake fixes exactly one winner, `TimerWinner::Expired` or `TimerWinner::Cancelled`, and
a later expiry or cancellation is refused as a second wake. A wake presented under a fence the
live wait does not hold is refused under the landed `wait-stale-wake-refused` spelling and
mutates no timer or wait state. A timer is never reconstructed from durable state, and it is not
a periodic timer, an interval, or a scheduler.

## Section 33 consumption and non-claims

`GNT-51.2-time-declaration-non-claims` consolidates the explicit non-claims below. Section 33
remains the normative owner of machine formats, explicit locale and collation values,
civil-time values, typed gaps and repetitions, pinned rule-data identity, preference snapshots,
target availability, presentation separation, monotonic and wall separation, rule-data
upgrades, durable replay retention, and the locale and time non-claims. In particular
`GNT-33.9-monotonic-and-wall-separation` remains the owner of the rule that UTC never supplies
a monotonic deadline. Civil rows consume the civil-value and typed-outcome clauses; clocks and
timers consume the monotonic and wall separation clause; locale consumes the explicit locale
clause; rule data consumes the pinned identity and upgrade clauses; values consumes the machine
format clause.

Declaring a module grants no capability and reads or mutates no ambient locale, time zone, or
clock. The clock and timer model delivers no typed civil ambiguity, no pinned rule-data identity,
and no durable timer reconstruction. It provides no host adapter, capability grant, wall-clock
observation, preference snapshot, timer reconstruction, periodic scheduler, timezone upgrade, or
raw monotonic restart guarantee. Those behavior and authority surfaces require their own
reviewed contracts and runtime integration; declaration coverage is not evidence that they work.

## Evidence and qualification

`crates/gantry-conformance/tests/time_foundation.rs` checks the closed rows and their canonical
order, package and item applicability, exact declaration and admission, every published refusal
class (missing, extra, duplicate, reordered, wrong class, wrong tier, wrong mode, wrong target,
and wrongly-bound clause), and the no-mutation rule.
`crates/gantry-conformance/tests/timer_foundation.rs` checks the injected clock domain, checked
deadline arithmetic, zero, past, and future deadlines, immediate readiness, one registered
waiter, not-due refusal, exactly one expiry or cancellation winner, stale-wake fencing, and
wrong-domain refusals. `crates/gantry-conformance/tests/stdlib_architecture.rs` checks aggregate
composition and catalog identity. These tests perform no host time, locale, rule-data, or clock
operation: they read committed repository fixtures, the aggregate catalog, and an explicitly
injected deterministic clock only.

Passing these lanes does not qualify a specification revision, publication, release, target
adapter, or time runtime. Generated and revision-bound checks must still agree with genuinely
reviewed adoption evidence before any such qualification is claimed.
