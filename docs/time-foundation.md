# Time package foundation

`SPEC.md` Section 51 owns the declaration-only `std.time` surface. This foundation is not a
clock, a timer, a scheduler, or a timezone integration, and it is not a runtime availability
claim.

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
wrong-tier, or wrong-applicability row instead of repairing it, and a refusal never mutates the
decided graph. `canonical_time_hierarchy` composes the family with the pure hierarchy, and
`canonical_std_hierarchy` includes the same defining package and item identity. The aggregate
catalog records the package interface digest. Repository module paths and host adapters are not
the source-level package identity.

Wrong class, duplicate, missing, extra, and reordered rows are refused under
`std-invalid-name-classification` of `GNT-34.2-name-classification`; a wrong tier is refused
under `std-invalid-stability-transition` of `GNT-34.6-stability-tiers`; and wrong applicability
is refused under `std-unsupported-applicability` of
`GNT-34.7-applicability-and-feature-granularity`. Section 51 owns no diagnostic spelling and
adds no refusal condition to Section 33.

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
clock. This foundation does not implement a clock, timer, scheduler, or timezone upgrade. It does
not implement typed civil ambiguity, pinned rule-data identities, or durable timer reconstruction.
It provides no host adapter, capability grant, wall-clock observation, preference snapshot,
timer reconstruction, or raw monotonic restart guarantee. Those behavior and authority surfaces
require their own reviewed contracts and runtime integration; declaration coverage is not
evidence that they work.

The next slice owns the injected monotonic clock and one-shot timer under the existing
ownership, wait, cancel, and fault contracts, with domain- and generation-bound deadlines,
readiness recheck, stale-wake fencing, and exactly one completion or cancel winner. Wall
observations and host preferences require separate authority and are not implied here.

## Evidence and qualification

`crates/gantry-conformance/tests/time_foundation.rs` checks the closed rows, applicability,
exact declaration and admission, all six refusal classes, and the no-mutation rule.
`crates/gantry-conformance/tests/stdlib_architecture.rs` checks aggregate composition and
catalog identity. These tests perform no host I/O and observe no clock.

Passing these lanes does not qualify a specification revision, publication, release, target
adapter, or time runtime. Generated and revision-bound checks must still agree with genuinely
reviewed adoption evidence before any such qualification is claimed.
