//! Conformance for the injected monotonic clock and one-shot timer of Section 51.
//!
//! The lane exercises the landed ownership, wait, cancellation, and fencing
//! machinery through the public facade. It reads no host clock, performs no I/O,
//! and derives every identity from declared test values.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use gantry::ir::{
    CanonicalPath, ClockDomainId, ClockObservation, FixedMonotonicClock, LogicalOperationId,
    MonotonicClock, MonotonicInstant, OneShotTimer, ResourceGenerationId, StaticSiteId,
    StructuralPosition, TIMER_CLAUSES, TimerArm, TimerDeadline, TimerDiagnosticCode, TimerDuration,
    TimerError, TimerWinner, WaitGeneration, WaitOwnerId, WaitRegistration, WaitResourceId,
    WaitSet, WakeCause,
};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn canonical(value: &str) -> CanonicalPath {
    match CanonicalPath::new(value) {
        Ok(path) => path,
        Err(error) => panic!("the declared path is canonical: {error:?}"),
    }
}

fn site() -> StaticSiteId {
    match StructuralPosition::new(vec![0, 1]) {
        Ok(position) => StaticSiteId::new(canonical("crate::main"), position),
        Err(error) => panic!("the declared position is nonempty: {error:?}"),
    }
}

fn generation() -> ResourceGenerationId {
    let site = site();
    let operation = LogicalOperationId::derive(&canonical("crate::wait"), &site);
    ResourceGenerationId::derive(&operation, &site, 1)
}

fn owner() -> WaitOwnerId {
    match WaitOwnerId::new("crate::main") {
        Ok(owner) => owner,
        Err(error) => panic!("the declared owner is named: {error}"),
    }
}

fn resource() -> WaitResourceId {
    match WaitResourceId::new("std.time::timers") {
        Ok(resource) => resource,
        Err(error) => panic!("the declared resource is named: {error}"),
    }
}

fn domain(value: &str) -> ClockDomainId {
    match ClockDomainId::new(value) {
        Ok(domain) => domain,
        Err(error) => panic!("the declared clock domain is admitted: {error}"),
    }
}

fn registration(ordinal: u32, fence: WaitGeneration) -> WaitRegistration {
    let owner = owner();
    let resource = resource();
    let generation = generation();
    WaitRegistration::new(
        gantry::ir::WaitId::derive(&owner, &resource, &generation, fence, ordinal),
        owner,
        resource,
        generation,
        fence,
        ordinal,
    )
}

fn next_fence(fence: WaitGeneration) -> WaitGeneration {
    match fence.succeeding() {
        Ok(next) => next,
        Err(error) => panic!("the declared fence advances: {error}"),
    }
}

fn refusal_code<T>(result: Result<T, TimerError>) -> TimerDiagnosticCode {
    match result {
        Ok(_) => panic!("the declared decision must be refused"),
        Err(error) => error.code(),
    }
}

#[test]
fn timer_clauses_publish_injected_clock_and_one_shot_boundaries() {
    assert_eq!(
        TIMER_CLAUSES,
        [
            "GNT-51.3-injected-monotonic-clock",
            "GNT-51.4-one-shot-timer",
        ]
    );
    let specification = fs::read_to_string(workspace_root().join("SPEC.md"))
        .unwrap_or_else(|error| panic!("could not read SPEC.md: {error}"))
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    for clause in TIMER_CLAUSES {
        assert!(specification.contains(clause), "SPEC.md declares {clause}");
    }
    for rule in [
        "explicitly injected sample port",
        "one exact count of elapsed microseconds since the epoch of that domain",
        "refused under `time-monotonic-regression`",
        "refused under `time-deadline-overflow`",
        "refused under `time-wrong-clock-domain`",
        "readiness recheck",
        "exactly one source-visible winner",
        "refused under `wait-second-wake-refused`",
        "refused under `time-timer-not-due`",
        "refused under `wait-stale-wake-refused`",
        "no raw monotonic restart guarantee",
    ] {
        assert!(specification.contains(rule), "SPEC.md pins: {rule}");
    }
    let note = fs::read_to_string(workspace_root().join("docs/time-foundation.md"))
        .unwrap_or_else(|error| panic!("could not read time note: {error}"))
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    for anchor in TIMER_CLAUSES {
        assert!(note.contains(anchor), "reader note names {anchor}");
    }
    let codes = TimerDiagnosticCode::ALL
        .into_iter()
        .map(TimerDiagnosticCode::wire_name)
        .collect::<Vec<_>>();
    assert_eq!(codes.len(), 10);
    assert_eq!(
        codes.iter().collect::<BTreeSet<_>>().len(),
        codes.len(),
        "every refusal spelling is declared exactly once"
    );
    for code in TimerDiagnosticCode::ALL {
        assert!(!code.owner().is_empty(), "every refusal names one owner");
        assert!(!code.wire_name().is_empty());
    }
}

#[test]
fn clock_domains_are_bounded_and_samples_never_regress() {
    for value in ["", "clock/with/slash", "clock with space"] {
        assert_eq!(
            refusal_code(ClockDomainId::new(value)),
            TimerDiagnosticCode::InvalidClockDomain
        );
    }
    let oversized = "a".repeat(65);
    assert_eq!(
        refusal_code(ClockDomainId::new(&oversized)),
        TimerDiagnosticCode::InvalidClockDomain
    );
    let clock = domain("monotonic-session-1");
    let mut observation = ClockObservation::new(clock.clone());
    assert_eq!(
        observation
            .observe(&MonotonicInstant::new(clock.clone(), 10))
            .ok(),
        Some(10)
    );
    assert_eq!(observation.last(), Some(10));
    let regressed = observation.observe(&MonotonicInstant::new(clock.clone(), 9));
    assert_eq!(
        refusal_code(regressed),
        TimerDiagnosticCode::MonotonicRegression
    );
    assert_eq!(
        observation.last(),
        Some(10),
        "a refusal never rewrites the held sample"
    );
    assert_eq!(
        observation.observe(&MonotonicInstant::new(clock, 10)).ok(),
        Some(10)
    );
    let foreign = domain("monotonic-session-2");
    assert_eq!(
        refusal_code(observation.observe(&MonotonicInstant::new(foreign, 11))),
        TimerDiagnosticCode::WrongClockDomain
    );
}

#[test]
fn checked_deadline_arithmetic_refuses_overflow_and_foreign_domains() {
    let clock = domain("clock-a");
    let near_max = MonotonicInstant::new(clock.clone(), u64::MAX - 1);
    assert_eq!(
        refusal_code(near_max.checked_add(TimerDuration::from_micros(2))),
        TimerDiagnosticCode::DeadlineOverflow
    );
    let start = MonotonicInstant::new(clock, 5);
    let deadline = match TimerDeadline::after(
        &start,
        TimerDuration::from_micros(10),
        WaitGeneration::FIRST,
    ) {
        Ok(deadline) => deadline,
        Err(error) => panic!("the declared deadline is in range: {error}"),
    };
    assert_eq!(deadline.micros(), 15);
    assert_eq!(deadline.generation(), WaitGeneration::FIRST);
    assert_eq!(
        deadline
            .has_elapsed(&MonotonicInstant::new(start.domain().clone(), 15))
            .ok(),
        Some(true)
    );
    assert_eq!(
        deadline
            .has_elapsed(&MonotonicInstant::new(start.domain().clone(), 14))
            .ok(),
        Some(false)
    );
    let foreign = domain("clock-b");
    assert_eq!(
        refusal_code(deadline.has_elapsed(&MonotonicInstant::new(foreign, 99))),
        TimerDiagnosticCode::WrongClockDomain
    );
}

#[test]
fn zero_and_past_deadlines_publish_immediate_timeout_without_a_later_wake() {
    let clock_domain = domain("clock-a");
    let mut clock = FixedMonotonicClock::new(clock_domain.clone(), 100);
    let mut waits = WaitSet::new();
    let mut timer = OneShotTimer::new(clock_domain.clone());
    let armed = match timer.arm_after(
        &clock,
        TimerDuration::ZERO,
        registration(1, WaitGeneration::FIRST),
        &mut waits,
    ) {
        Ok(armed) => armed,
        Err(error) => panic!("the zero deadline rechecks readiness: {error}"),
    };
    assert_eq!(armed, TimerArm::AlreadyElapsed(TimerWinner::Expired));
    assert!(!timer.is_armed());
    assert_eq!(timer.winner(), Some(TimerWinner::Expired));
    assert_eq!(timer.deadline().map(TimerDeadline::micros), Some(100));
    assert_eq!(
        refusal_code(timer.expire(&clock, &mut waits)),
        TimerDiagnosticCode::TimerAlreadySettled
    );
    assert_eq!(
        refusal_code(timer.cancel(&mut waits)),
        TimerDiagnosticCode::TimerAlreadySettled
    );

    let past = TimerDeadline::from_instant(
        &MonotonicInstant::new(clock_domain.clone(), 50),
        WaitGeneration::FIRST,
    );
    let mut second = OneShotTimer::new(clock_domain);
    let armed = match second.arm_at(
        &clock,
        past,
        registration(2, next_fence(WaitGeneration::FIRST)),
        &mut waits,
    ) {
        Ok(armed) => armed,
        Err(error) => panic!("the past deadline rechecks readiness: {error}"),
    };
    assert_eq!(armed, TimerArm::AlreadyElapsed(TimerWinner::Expired));
    assert_eq!(second.winner(), Some(TimerWinner::Expired));
    assert_eq!(clock.set_micros(60), ());
    assert_eq!(timer.winner(), Some(TimerWinner::Expired));
}

#[test]
fn future_deadline_registers_and_expires_once() {
    let clock_domain = domain("clock-a");
    let mut clock = FixedMonotonicClock::new(clock_domain.clone(), 100);
    let mut waits = WaitSet::new();
    let mut timer = OneShotTimer::new(clock_domain);
    let registration = registration(1, WaitGeneration::FIRST);
    let wait_id = registration.id().clone();
    let fence = registration.generation();
    let armed = match timer.arm_after(
        &clock,
        TimerDuration::from_micros(50),
        registration,
        &mut waits,
    ) {
        Ok(armed) => armed,
        Err(error) => panic!("the future deadline registers: {error}"),
    };
    assert_eq!(armed, TimerArm::Armed);
    assert!(timer.is_armed());
    assert_eq!(timer.deadline().map(TimerDeadline::micros), Some(150));
    assert_eq!(
        refusal_code(timer.expire(&clock, &mut waits)),
        TimerDiagnosticCode::TimerNotDue
    );
    assert!(
        timer.is_armed(),
        "a not-due observation leaves the deadline live"
    );
    clock.set_micros(150);
    let record = match timer.expire(&clock, &mut waits) {
        Ok(record) => record,
        Err(error) => panic!("the due deadline expires: {error}"),
    };
    assert_eq!(record.cause(), WakeCause::Timeout);
    assert_eq!(record.wait(), &wait_id);
    assert_eq!(record.generation(), fence);
    assert_eq!(timer.winner(), Some(TimerWinner::Expired));
    assert_eq!(
        refusal_code(timer.expire(&clock, &mut waits)),
        TimerDiagnosticCode::TimerAlreadySettled
    );
    match waits.wake(&wait_id, fence, WakeCause::Timeout) {
        Ok(_) => panic!("the landed wait set refuses a second wake"),
        Err(gantry::ir::WaitError::SecondWake { .. }) => {}
        Err(error) => panic!("the second wake is refused as a second wake: {error}"),
    }
}

#[test]
fn cancellation_and_expiry_have_exactly_one_winner() {
    let clock_domain = domain("clock-a");
    let mut clock = FixedMonotonicClock::new(clock_domain.clone(), 100);
    let mut waits = WaitSet::new();
    let mut cancelled = OneShotTimer::new(clock_domain.clone());
    let armed = match cancelled.arm_after(
        &clock,
        TimerDuration::from_micros(50),
        registration(1, WaitGeneration::FIRST),
        &mut waits,
    ) {
        Ok(armed) => armed,
        Err(error) => panic!("the cancellation candidate arms: {error}"),
    };
    assert_eq!(armed, TimerArm::Armed);
    let record = match cancelled.cancel(&mut waits) {
        Ok(record) => record,
        Err(error) => panic!("the cancellation wins: {error}"),
    };
    assert_eq!(record.cause(), WakeCause::Cancellation);
    assert_eq!(cancelled.winner(), Some(TimerWinner::Cancelled));
    assert_eq!(
        refusal_code(cancelled.expire(&clock, &mut waits)),
        TimerDiagnosticCode::TimerAlreadySettled
    );
    assert_eq!(
        refusal_code(cancelled.cancel(&mut waits)),
        TimerDiagnosticCode::TimerAlreadySettled
    );

    let mut expired = OneShotTimer::new(clock_domain);
    let fence = next_fence(WaitGeneration::FIRST);
    let armed = match expired.arm_after(
        &clock,
        TimerDuration::from_micros(10),
        registration(2, fence),
        &mut waits,
    ) {
        Ok(armed) => armed,
        Err(error) => panic!("the expiry candidate arms: {error}"),
    };
    assert_eq!(armed, TimerArm::Armed);
    clock.set_micros(110);
    match expired.expire(&clock, &mut waits) {
        Ok(record) => assert_eq!(record.cause(), WakeCause::Timeout),
        Err(error) => panic!("the expiry wins: {error}"),
    };
    assert_eq!(expired.winner(), Some(TimerWinner::Expired));
    assert_eq!(
        refusal_code(expired.cancel(&mut waits)),
        TimerDiagnosticCode::TimerAlreadySettled
    );
}

#[test]
fn stale_wake_fence_is_refused_without_mutation() {
    let clock_domain = domain("clock-a");
    let clock = FixedMonotonicClock::new(clock_domain.clone(), 100);
    let mut waits = WaitSet::new();
    let mut timer = OneShotTimer::new(clock_domain);
    let armed = match timer.arm_after(
        &clock,
        TimerDuration::from_micros(50),
        registration(1, WaitGeneration::FIRST),
        &mut waits,
    ) {
        Ok(armed) => armed,
        Err(error) => panic!("the stale-fence candidate arms: {error}"),
    };
    assert_eq!(armed, TimerArm::Armed);
    let stale = next_fence(WaitGeneration::FIRST);
    match timer.expire_under(&clock, &mut waits, stale) {
        Err(TimerError::StaleWake {
            held, presented, ..
        }) => {
            assert_eq!(held, WaitGeneration::FIRST);
            assert_eq!(presented, stale);
        }
        other => panic!("the stale expiry is refused, observed {other:?}"),
    }
    assert!(timer.is_armed(), "a stale wake mutates no timer state");
    assert_eq!(timer.winner(), None);
    match timer.cancel_under(&mut waits, stale) {
        Err(TimerError::StaleWake { .. }) => {}
        other => panic!("the stale cancellation is refused, observed {other:?}"),
    }
    assert!(timer.is_armed());
    match timer.cancel(&mut waits) {
        Ok(record) => assert_eq!(record.cause(), WakeCause::Cancellation),
        Err(error) => panic!("the held fence still settles: {error}"),
    }
}

struct DriftingClock {
    domain: ClockDomainId,
    instant: MonotonicInstant,
}

impl MonotonicClock for DriftingClock {
    fn domain(&self) -> &ClockDomainId {
        &self.domain
    }

    fn sample(&self) -> MonotonicInstant {
        self.instant.clone()
    }
}

#[test]
fn wrong_domain_clock_sample_and_deadline_are_refused() {
    let first = domain("clock-a");
    let second = domain("clock-b");
    let mut waits = WaitSet::new();
    let mut clock = FixedMonotonicClock::new(second.clone(), 100);
    let mut timer = OneShotTimer::new(first.clone());
    assert_eq!(
        refusal_code(timer.arm_after(
            &clock,
            TimerDuration::from_micros(1),
            registration(1, WaitGeneration::FIRST),
            &mut waits,
        )),
        TimerDiagnosticCode::WrongClockDomain
    );
    assert!(!timer.is_armed());

    let drifting = DriftingClock {
        domain: first.clone(),
        instant: MonotonicInstant::new(second.clone(), 100),
    };
    assert_eq!(
        refusal_code(timer.arm_after(
            &drifting,
            TimerDuration::from_micros(1),
            registration(2, next_fence(WaitGeneration::FIRST)),
            &mut waits,
        )),
        TimerDiagnosticCode::WrongClockDomain
    );
    assert!(!timer.is_armed());

    clock.set_micros(100);
    let foreign =
        TimerDeadline::from_instant(&MonotonicInstant::new(second, 200), WaitGeneration::FIRST);
    assert_eq!(
        refusal_code(timer.arm_at(
            &clock,
            foreign,
            registration(3, next_fence(next_fence(WaitGeneration::FIRST))),
            &mut waits,
        )),
        TimerDiagnosticCode::WrongClockDomain
    );
}

#[test]
fn unarmed_and_rearmed_timers_are_refused() {
    let clock_domain = domain("clock-a");
    let clock = FixedMonotonicClock::new(clock_domain.clone(), 100);
    let mut waits = WaitSet::new();
    let mut timer = OneShotTimer::new(clock_domain);
    assert_eq!(
        refusal_code(timer.expire(&clock, &mut waits)),
        TimerDiagnosticCode::TimerUnarmed
    );
    assert_eq!(
        refusal_code(timer.cancel(&mut waits)),
        TimerDiagnosticCode::TimerUnarmed
    );
    match timer.arm_after(
        &clock,
        TimerDuration::from_micros(50),
        registration(1, WaitGeneration::FIRST),
        &mut waits,
    ) {
        Ok(armed) => assert_eq!(armed, TimerArm::Armed),
        Err(error) => panic!("the first arm is admitted: {error}"),
    }
    assert_eq!(
        refusal_code(timer.arm_after(
            &clock,
            TimerDuration::from_micros(1),
            registration(2, next_fence(WaitGeneration::FIRST)),
            &mut waits,
        )),
        TimerDiagnosticCode::TimerAlreadyArmed
    );
    assert!(timer.is_armed());
    assert_eq!(timer.winner(), None);
}
