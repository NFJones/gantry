//! Injected monotonic clock and one-shot timer model for `SPEC.md` Section 51.
//!
//! This module publishes `GNT-51.3-injected-monotonic-clock` and
//! `GNT-51.4-one-shot-timer`. A monotonic clock is an explicitly injected sample
//! port: the module reads no ambient clock and owns no clock instance. A one-shot
//! timer binds one checked deadline to one clock domain and one waiter-generation
//! fence, reuses the landed registration, wake, and fencing machinery of
//! [`crate::wait`], and settles exactly once as a timeout completion or a
//! cancellation.
//!
//! Scope is deliberately narrow. No value of this module is a wall clock, a civil
//! time, a timestamp, a UTC instant, a scheduler, a periodic timer, a durable
//! object, or a host adapter. A clock-domain identity names one epoch and nothing
//! across epochs, restarts, processes, or hosts, so this module makes no raw
//! monotonic restart-continuity claim. It performs no I/O and depends on no host
//! crate.

use std::fmt;

use crate::wait::{
    ReadinessObservation, RegistrationOutcome, WaitError, WaitGeneration, WaitId, WaitRegistration,
    WaitSet, WakeCause, WakeOutcome, WakeRecord,
};

/// The Section 51 behavior clauses this module publishes, in specification order.
pub const TIMER_CLAUSES: [&str; 2] = [
    "GNT-51.3-injected-monotonic-clock",
    "GNT-51.4-one-shot-timer",
];

/// The maximum accepted byte length of one declared clock-domain identity.
pub const CLOCK_DOMAIN_MAX_BYTES: usize = 64;

/// One declared clock-domain identity of `GNT-51.3-injected-monotonic-clock`.
///
/// The identity is one nonempty bounded ASCII identifier derived from declared
/// fields only. No process identifier, thread identity, host path, environment
/// fact, locale, socket, or adapter handle participates, so equal declared inputs
/// produce equal identities.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ClockDomainId {
    text: String,
}

impl ClockDomainId {
    /// Constructs one clock-domain identity from its declared spelling.
    ///
    /// # Errors
    ///
    /// Returns [`TimerError::InvalidClockDomain`] when the spelling is empty,
    /// exceeds [`CLOCK_DOMAIN_MAX_BYTES`], or contains a byte outside the admitted
    /// ASCII identifier set, because an unbounded or ambiguous domain could not
    /// fence a sample.
    pub fn new(value: &str) -> Result<Self, TimerError> {
        if value.is_empty() {
            return Err(TimerError::InvalidClockDomain {
                value: value.to_owned(),
                reason: "a clock domain must not be empty".to_owned(),
            });
        }
        if value.len() > CLOCK_DOMAIN_MAX_BYTES {
            return Err(TimerError::InvalidClockDomain {
                value: value.to_owned(),
                reason: "a clock domain exceeds its declared byte bound".to_owned(),
            });
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || [45u8, 46, 58, 95].contains(&byte))
        {
            return Err(TimerError::InvalidClockDomain {
                value: value.to_owned(),
                reason: "a clock domain admits only ASCII identifier bytes".to_owned(),
            });
        }
        Ok(Self {
            text: value.to_owned(),
        })
    }

    /// Returns the exact portable spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }
}

impl fmt::Display for ClockDomainId {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str(&self.text)
    }
}

/// One declared non-negative duration in whole microseconds.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct TimerDuration(u64);

impl TimerDuration {
    /// The zero duration, which makes a relative deadline already elapsed.
    pub const ZERO: Self = Self(0);

    /// Constructs one duration from its exact microsecond count.
    #[must_use]
    pub const fn from_micros(micros: u64) -> Self {
        Self(micros)
    }

    /// Returns the exact microsecond count.
    #[must_use]
    pub const fn micros(self) -> u64 {
        self.0
    }
}

/// One monotonic sample of `GNT-51.3-injected-monotonic-clock`.
///
/// A sample carries one clock-domain identity and one exact count of elapsed
/// microseconds since the epoch of that domain. It is never a wall time, a civil
/// time, a timestamp, or a UTC instant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MonotonicInstant {
    domain: ClockDomainId,
    micros: u64,
}

impl MonotonicInstant {
    /// Constructs one sample of one clock domain.
    #[must_use]
    pub fn new(domain: ClockDomainId, micros: u64) -> Self {
        Self { domain, micros }
    }

    /// Returns the clock domain of this sample.
    #[must_use]
    pub const fn domain(&self) -> &ClockDomainId {
        &self.domain
    }

    /// Returns the exact elapsed microsecond count of this sample.
    #[must_use]
    pub const fn micros(&self) -> u64 {
        self.micros
    }

    /// Adds one duration with exact checked arithmetic.
    ///
    /// # Errors
    ///
    /// Returns [`TimerError::DeadlineOverflow`] when the sum exceeds the declared
    /// count, because a saturated or wrapped deadline would name a different
    /// instant.
    pub fn checked_add(&self, duration: TimerDuration) -> Result<Self, TimerError> {
        match self.micros.checked_add(duration.micros()) {
            Some(micros) => Ok(Self {
                domain: self.domain.clone(),
                micros,
            }),
            None => Err(TimerError::DeadlineOverflow {
                domain: self.domain.clone(),
                base: self.micros,
                duration: duration.micros(),
            }),
        }
    }
}

/// One injected monotonic clock port of `GNT-51.3-injected-monotonic-clock`.
///
/// The embedding supplies the implementation and the caller passes it, so no
/// ambient, thread-local, global, or host-discovered clock is consulted. The port
/// declares exactly one domain and one sample operation.
pub trait MonotonicClock {
    /// Returns the clock domain this port samples.
    fn domain(&self) -> &ClockDomainId;

    /// Returns one monotonic sample of that domain.
    fn sample(&self) -> MonotonicInstant;
}

/// One deterministic injected clock for callers and conformance lanes.
///
/// The clock holds one declared domain and one exact microsecond count. It reads
/// no host clock, and advancing it is an explicit caller operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixedMonotonicClock {
    domain: ClockDomainId,
    micros: u64,
}

impl FixedMonotonicClock {
    /// Constructs one clock at one exact sample.
    #[must_use]
    pub fn new(domain: ClockDomainId, micros: u64) -> Self {
        Self { domain, micros }
    }

    /// Advances the clock by one checked duration.
    ///
    /// # Errors
    ///
    /// Returns [`TimerError::DeadlineOverflow`] when the sum exceeds the declared
    /// count rather than saturating or wrapping.
    pub fn advance(&mut self, duration: TimerDuration) -> Result<(), TimerError> {
        match self.micros.checked_add(duration.micros()) {
            Some(micros) => {
                self.micros = micros;
                Ok(())
            }
            None => Err(TimerError::DeadlineOverflow {
                domain: self.domain.clone(),
                base: self.micros,
                duration: duration.micros(),
            }),
        }
    }

    /// Sets the clock to one exact sample.
    pub fn set_micros(&mut self, micros: u64) {
        self.micros = micros;
    }
}

impl MonotonicClock for FixedMonotonicClock {
    fn domain(&self) -> &ClockDomainId {
        &self.domain
    }

    fn sample(&self) -> MonotonicInstant {
        MonotonicInstant::new(self.domain.clone(), self.micros)
    }
}

/// One non-decreasing observation sequence of one clock domain.
///
/// The observation records the last accepted sample of one domain and refuses a
/// sample that moves backwards. A refusal mutates nothing, so the held sample is
/// never replaced by a regressed one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClockObservation {
    domain: ClockDomainId,
    last: Option<u64>,
}

impl ClockObservation {
    /// Opens one empty observation sequence of one domain.
    #[must_use]
    pub fn new(domain: ClockDomainId) -> Self {
        Self { domain, last: None }
    }

    /// Returns the observed domain.
    #[must_use]
    pub const fn domain(&self) -> &ClockDomainId {
        &self.domain
    }

    /// Returns the last accepted microsecond count, if any.
    #[must_use]
    pub const fn last(&self) -> Option<u64> {
        self.last
    }

    /// Checks one sample, refusing a foreign domain or a regression.
    ///
    /// # Errors
    ///
    /// Returns [`TimerError::WrongClockDomain`] when the sample names another
    /// domain, and [`TimerError::MonotonicRegression`] when the sample is less than
    /// one already observed for this domain. A refused sample mutates nothing.
    pub fn check(&self, instant: &MonotonicInstant) -> Result<u64, TimerError> {
        if instant.domain() != &self.domain {
            return Err(TimerError::WrongClockDomain {
                held: self.domain.clone(),
                presented: instant.domain().clone(),
            });
        }
        if let Some(held) = self.last
            && instant.micros() < held
        {
            return Err(TimerError::MonotonicRegression {
                domain: self.domain.clone(),
                held,
                presented: instant.micros(),
            });
        }
        Ok(instant.micros())
    }

    /// Records one checked sample as the last accepted sample.
    ///
    /// # Errors
    ///
    /// Returns every refusal of [`Self::check`].
    pub fn observe(&mut self, instant: &MonotonicInstant) -> Result<u64, TimerError> {
        let micros = self.check(instant)?;
        self.last = Some(micros);
        Ok(micros)
    }
}

/// One checked one-shot deadline of `GNT-51.4-one-shot-timer`.
///
/// The deadline carries its clock domain, its exact microsecond instant, and the
/// waiter-generation fence it observes, so a deadline can never be compared with a
/// sample of another domain or woken under another fence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimerDeadline {
    domain: ClockDomainId,
    micros: u64,
    generation: WaitGeneration,
}

impl TimerDeadline {
    /// Declares one absolute deadline at one sample.
    #[must_use]
    pub fn from_instant(instant: &MonotonicInstant, generation: WaitGeneration) -> Self {
        Self {
            domain: instant.domain().clone(),
            micros: instant.micros(),
            generation,
        }
    }

    /// Declares one relative deadline from one sample and one checked duration.
    ///
    /// # Errors
    ///
    /// Returns [`TimerError::DeadlineOverflow`] when the addition exceeds the
    /// declared microsecond count.
    pub fn after(
        instant: &MonotonicInstant,
        duration: TimerDuration,
        generation: WaitGeneration,
    ) -> Result<Self, TimerError> {
        let deadline = instant.checked_add(duration)?;
        Ok(Self::from_instant(&deadline, generation))
    }

    /// Returns the clock domain this deadline is bound to.
    #[must_use]
    pub const fn domain(&self) -> &ClockDomainId {
        &self.domain
    }

    /// Returns the exact deadline instant.
    #[must_use]
    pub const fn micros(&self) -> u64 {
        self.micros
    }

    /// Returns the waiter-generation fence this deadline observes.
    #[must_use]
    pub const fn generation(&self) -> WaitGeneration {
        self.generation
    }

    /// Returns whether one sample has reached this deadline.
    ///
    /// # Errors
    ///
    /// Returns [`TimerError::WrongClockDomain`] when the sample names another
    /// clock domain, because two domains are not comparable.
    pub fn has_elapsed(&self, instant: &MonotonicInstant) -> Result<bool, TimerError> {
        if instant.domain() != &self.domain {
            return Err(TimerError::WrongClockDomain {
                held: self.domain.clone(),
                presented: instant.domain().clone(),
            });
        }
        Ok(instant.micros() >= self.micros)
    }
}

/// The single source-visible winner of one one-shot timer.
///
/// The timer settles as exactly one of these members. The first admissible wake
/// fixes it, and a later expiry or cancellation is refused rather than becoming a
/// second winner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimerWinner {
    /// The declared deadline expired and settled the timeout completion.
    Expired,
    /// The landed cancellation of `GNT-15.3` or Section 22 settled first.
    Cancelled,
}

impl TimerWinner {
    /// Returns the closed wake cause of `GNT-24.3` this winner reports.
    #[must_use]
    pub const fn cause(self) -> WakeCause {
        match self {
            Self::Expired => WakeCause::Timeout,
            Self::Cancelled => WakeCause::Cancellation,
        }
    }
}

/// The published outcome of arming one one-shot timer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimerArm {
    /// The future deadline registered exactly one live waiter.
    Armed,
    /// The deadline was already elapsed, so the timer settled without a later wake.
    AlreadyElapsed(TimerWinner),
}

impl TimerArm {
    /// Returns whether the arm registered a live waiter.
    #[must_use]
    pub const fn is_armed(self) -> bool {
        matches!(self, Self::Armed)
    }

    /// Returns the settled winner of an already elapsed deadline.
    #[must_use]
    pub const fn winner(self) -> Option<TimerWinner> {
        match self {
            Self::Armed => None,
            Self::AlreadyElapsed(winner) => Some(winner),
        }
    }
}

/// The declared state of one one-shot timer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TimerState {
    /// No deadline has been armed.
    Unarmed,
    /// One future deadline registered one live waiter.
    Armed,
    /// The timer settled exactly once with one winner.
    Settled(TimerWinner),
}

/// One injected-clock one-shot timer of `GNT-51.4-one-shot-timer`.
///
/// The timer binds one checked deadline to one clock domain and one waiter
/// registration. Arming performs the atomic registration and readiness recheck of
/// `GNT-24.1-atomic-registration-and-readiness-recheck`; an elapsed deadline settles
/// immediately as the timeout completion, and a future deadline registers one live
/// waiter in one [`WaitSet`]. Expiry and cancellation reuse the landed wake and
/// fence machinery, so exactly one of [`TimerWinner::Expired`] and
/// [`TimerWinner::Cancelled`] settles, and a stale fence is refused without
/// mutation.
#[derive(Debug)]
pub struct OneShotTimer {
    domain: ClockDomainId,
    observation: ClockObservation,
    registration: Option<WaitRegistration>,
    deadline: Option<TimerDeadline>,
    outcome: Option<WakeOutcome>,
    state: TimerState,
}

impl OneShotTimer {
    /// Creates one unarmed timer over one clock domain.
    #[must_use]
    pub fn new(domain: ClockDomainId) -> Self {
        Self {
            observation: ClockObservation::new(domain.clone()),
            domain,
            registration: None,
            deadline: None,
            outcome: None,
            state: TimerState::Unarmed,
        }
    }

    /// Returns the clock domain of this timer.
    #[must_use]
    pub const fn domain(&self) -> &ClockDomainId {
        &self.domain
    }

    /// Returns the armed deadline, if one was accepted.
    #[must_use]
    pub const fn deadline(&self) -> Option<&TimerDeadline> {
        self.deadline.as_ref()
    }

    /// Returns the settled winner, if the timer settled.
    #[must_use]
    pub const fn winner(&self) -> Option<TimerWinner> {
        match self.state {
            TimerState::Settled(winner) => Some(winner),
            TimerState::Unarmed | TimerState::Armed => None,
        }
    }

    /// Returns whether one future deadline is armed and unsettled.
    #[must_use]
    pub const fn is_armed(&self) -> bool {
        matches!(self.state, TimerState::Armed)
    }

    /// Returns the clock observation sequence of this timer.
    #[must_use]
    pub const fn observation(&self) -> &ClockObservation {
        &self.observation
    }

    /// Arms one relative deadline and rechecks readiness in one atomic step.
    ///
    /// # Errors
    ///
    /// Returns [`TimerError::TimerAlreadyArmed`] when a deadline is already armed,
    /// [`TimerError::TimerAlreadySettled`] when the timer already settled,
    /// [`TimerError::WrongClockDomain`] when the clock or its sample names another
    /// domain, [`TimerError::MonotonicRegression`] when the sample moves backwards,
    /// [`TimerError::DeadlineOverflow`] when the sum overflows, and the landed
    /// [`WaitError`] refusals of registration or wake when the waiter slot cannot
    /// accept the registration.
    pub fn arm_after(
        &mut self,
        clock: &dyn MonotonicClock,
        duration: TimerDuration,
        registration: WaitRegistration,
        waits: &mut WaitSet,
    ) -> Result<TimerArm, TimerError> {
        let instant = self.sample(clock)?;
        let deadline = TimerDeadline::after(&instant, duration, registration.generation())?;
        self.arm(deadline, instant, registration, waits)
    }

    /// Arms one absolute deadline and rechecks readiness in one atomic step.
    ///
    /// # Errors
    ///
    /// Returns every refusal of [`Self::arm_after`], including
    /// [`TimerError::WrongClockDomain`] for a deadline of another clock domain.
    pub fn arm_at(
        &mut self,
        clock: &dyn MonotonicClock,
        deadline: TimerDeadline,
        registration: WaitRegistration,
        waits: &mut WaitSet,
    ) -> Result<TimerArm, TimerError> {
        let instant = self.sample(clock)?;
        if deadline.domain() != &self.domain {
            return Err(TimerError::WrongClockDomain {
                held: self.domain.clone(),
                presented: deadline.domain().clone(),
            });
        }
        self.arm(deadline, instant, registration, waits)
    }

    /// Delivers one expiry under the held waiter-generation fence.
    ///
    /// # Errors
    ///
    /// Returns [`TimerError::TimerUnarmed`] before arming,
    /// [`TimerError::TimerAlreadySettled`] after any winner,
    /// [`TimerError::WrongClockDomain`] or [`TimerError::MonotonicRegression`] for
    /// the sample, [`TimerError::TimerNotDue`] before the deadline, and the landed
    /// [`WaitError`] refusals of the wait set.
    pub fn expire(
        &mut self,
        clock: &dyn MonotonicClock,
        waits: &mut WaitSet,
    ) -> Result<WakeRecord, TimerError> {
        let generation = self.held_generation()?;
        self.expire_under(clock, waits, generation)
    }

    /// Delivers one expiry under one presented waiter-generation fence.
    ///
    /// # Errors
    ///
    /// Returns [`TimerError::StaleWake`] when the presented fence is not the fence
    /// the live wait holds, without mutating any timer or wait state, and every
    /// refusal of [`Self::expire`].
    pub fn expire_under(
        &mut self,
        clock: &dyn MonotonicClock,
        waits: &mut WaitSet,
        presented: WaitGeneration,
    ) -> Result<WakeRecord, TimerError> {
        let held = self.held_generation()?;
        if !held.observes(presented) {
            return Err(TimerError::StaleWake {
                wait: self.wait_id()?,
                held,
                presented,
            });
        }
        let deadline = self.deadline.clone().ok_or(TimerError::TimerUnarmed)?;
        let instant = self.sample(clock)?;
        if !deadline.has_elapsed(&instant)? {
            return Err(TimerError::TimerNotDue {
                deadline: deadline.micros(),
                observed: instant.micros(),
            });
        }
        let record = waits.wake(&self.wait_id()?, presented, WakeCause::Timeout)?;
        self.observation.observe(&instant)?;
        self.state = TimerState::Settled(TimerWinner::Expired);
        Ok(record)
    }

    /// Delivers one cancellation under the held waiter-generation fence.
    ///
    /// # Errors
    ///
    /// Returns [`TimerError::TimerUnarmed`] before arming and
    /// [`TimerError::TimerAlreadySettled`] after any winner, and the landed
    /// [`WaitError`] refusals of the wait set.
    pub fn cancel(&mut self, waits: &mut WaitSet) -> Result<WakeRecord, TimerError> {
        let generation = self.held_generation()?;
        self.cancel_under(waits, generation)
    }

    /// Delivers one cancellation under one presented waiter-generation fence.
    ///
    /// # Errors
    ///
    /// Returns [`TimerError::StaleWake`] when the presented fence is not the fence
    /// the live wait holds, without mutating any timer or wait state, and every
    /// refusal of [`Self::cancel`].
    pub fn cancel_under(
        &mut self,
        waits: &mut WaitSet,
        presented: WaitGeneration,
    ) -> Result<WakeRecord, TimerError> {
        let held = self.held_generation()?;
        if !held.observes(presented) {
            return Err(TimerError::StaleWake {
                wait: self.wait_id()?,
                held,
                presented,
            });
        }
        let record = waits.wake(&self.wait_id()?, presented, WakeCause::Cancellation)?;
        self.state = TimerState::Settled(TimerWinner::Cancelled);
        Ok(record)
    }

    /// Samples the injected clock and checks it without recording it.
    fn sample(&self, clock: &dyn MonotonicClock) -> Result<MonotonicInstant, TimerError> {
        if clock.domain() != &self.domain {
            return Err(TimerError::WrongClockDomain {
                held: self.domain.clone(),
                presented: clock.domain().clone(),
            });
        }
        let instant = clock.sample();
        self.observation.check(&instant)?;
        Ok(instant)
    }

    /// Arms one deadline after the atomic readiness recheck.
    fn arm(
        &mut self,
        deadline: TimerDeadline,
        instant: MonotonicInstant,
        registration: WaitRegistration,
        waits: &mut WaitSet,
    ) -> Result<TimerArm, TimerError> {
        match self.state {
            TimerState::Unarmed => {}
            TimerState::Armed => return Err(TimerError::TimerAlreadyArmed),
            TimerState::Settled(winner) => {
                return Err(TimerError::TimerAlreadySettled { winner });
            }
        }
        if deadline.domain() != &self.domain {
            return Err(TimerError::WrongClockDomain {
                held: self.domain.clone(),
                presented: deadline.domain().clone(),
            });
        }
        let mut registration = registration;
        if deadline.generation() != registration.generation() {
            return Err(TimerError::GenerationMismatch {
                deadline: deadline.generation(),
                registration: registration.generation(),
            });
        }
        let elapsed = instant.micros() >= deadline.micros();
        let observation = if elapsed {
            ReadinessObservation::Ready(WakeCause::Timeout)
        } else {
            ReadinessObservation::NotReady
        };
        match registration.register_and_recheck(observation)? {
            RegistrationOutcome::Registered => {
                waits.register(&registration)?;
                self.observation.observe(&instant)?;
                self.registration = Some(registration);
                self.deadline = Some(deadline);
                self.state = TimerState::Armed;
                Ok(TimerArm::Armed)
            }
            RegistrationOutcome::AlreadyReady(cause) => {
                if cause != WakeCause::Timeout {
                    return Err(TimerError::UnexpectedReadiness { cause });
                }
                let outcome = WakeOutcome::pending(&registration)?;
                if outcome.require_winner()? != WakeCause::Timeout {
                    return Err(TimerError::UnexpectedReadiness { cause });
                }
                self.observation.observe(&instant)?;
                self.registration = Some(registration);
                self.deadline = Some(deadline);
                self.outcome = Some(outcome);
                self.state = TimerState::Settled(TimerWinner::Expired);
                Ok(TimerArm::AlreadyElapsed(TimerWinner::Expired))
            }
        }
    }

    /// Returns the live waiter-generation fence or the refusal of the timer state.
    fn held_generation(&self) -> Result<WaitGeneration, TimerError> {
        match (&self.state, &self.registration) {
            (TimerState::Unarmed, _) | (TimerState::Armed, None) => Err(TimerError::TimerUnarmed),
            (TimerState::Settled(winner), _) => {
                Err(TimerError::TimerAlreadySettled { winner: *winner })
            }
            (TimerState::Armed, Some(registration)) => Ok(registration.generation()),
        }
    }

    /// Returns the waiter identity of the held registration.
    fn wait_id(&self) -> Result<WaitId, TimerError> {
        self.registration
            .as_ref()
            .map(|registration| registration.id().clone())
            .ok_or(TimerError::TimerUnarmed)
    }
}

/// The closed refusal vocabulary of `GNT-51.3` and `GNT-51.4`.
///
/// Every spelling names exactly one owning clause. The stale-fence refusal is the
/// landed `wait-stale-wake-refused` spelling of
/// `GNT-24.4-stale-wake-fencing-and-waiter-reuse`, so Section 51 adds no second
/// fencing vocabulary.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TimerDiagnosticCode {
    /// The declared clock domain is empty, oversized, or malformed.
    InvalidClockDomain,
    /// A sample, deadline, or clock names another clock domain.
    WrongClockDomain,
    /// A sample is less than one already observed for its domain.
    MonotonicRegression,
    /// Checked deadline arithmetic exceeds the declared microsecond count.
    DeadlineOverflow,
    /// A deadline observes another waiter-generation fence than its registration.
    GenerationMismatch,
    /// An expiry observation is presented before the recorded deadline.
    TimerNotDue,
    /// A second deadline is presented to a timer that is already armed.
    TimerAlreadyArmed,
    /// An expiry or cancellation is presented before any deadline is armed.
    TimerUnarmed,
    /// A wake presents a fence the live wait does not hold.
    StaleWake,
    /// A later expiry or cancellation follows one settled winner.
    SecondWake,
    /// The readiness recheck reports a cause this timer did not declare.
    UnexpectedReadiness,
}

impl TimerDiagnosticCode {
    /// Every frozen code, in sorted code order.
    pub const ALL: [Self; 11] = [
        Self::DeadlineOverflow,
        Self::GenerationMismatch,
        Self::InvalidClockDomain,
        Self::MonotonicRegression,
        Self::SecondWake,
        Self::StaleWake,
        Self::TimerAlreadyArmed,
        Self::TimerNotDue,
        Self::TimerUnarmed,
        Self::UnexpectedReadiness,
        Self::WrongClockDomain,
    ];

    /// Returns the exact frozen spelling.
    #[must_use]
    pub fn wire_name(self) -> String {
        match self {
            Self::InvalidClockDomain => "time-invalid-clock-domain",
            Self::WrongClockDomain => "time-wrong-clock-domain",
            Self::MonotonicRegression => "time-monotonic-regression",
            Self::DeadlineOverflow => "time-deadline-overflow",
            Self::GenerationMismatch => "time-generation-mismatch",
            Self::TimerNotDue => "time-timer-not-due",
            Self::TimerAlreadyArmed => "time-timer-already-armed",
            Self::TimerUnarmed => "time-timer-unarmed",
            Self::StaleWake => "wait-stale-wake-refused",
            Self::SecondWake => "wait-second-wake-refused",
            Self::UnexpectedReadiness => "time-unexpected-readiness",
        }
        .to_owned()
    }

    /// Returns the one clause that owns this refusal.
    #[must_use]
    pub fn owner(self) -> String {
        match self {
            Self::InvalidClockDomain
            | Self::WrongClockDomain
            | Self::MonotonicRegression
            | Self::DeadlineOverflow => "GNT-51.3-injected-monotonic-clock",
            Self::GenerationMismatch
            | Self::TimerNotDue
            | Self::TimerAlreadyArmed
            | Self::TimerUnarmed
            | Self::UnexpectedReadiness => "GNT-51.4-one-shot-timer",
            Self::StaleWake => "GNT-24.4-stale-wake-fencing-and-waiter-reuse",
            Self::SecondWake => "GNT-24.3-wake-causes-and-wake-ownership",
        }
        .to_owned()
    }
}

/// One refusal of the injected monotonic clock or one-shot timer model.
#[derive(Debug)]
pub enum TimerError {
    /// The declared clock-domain spelling is not admitted.
    InvalidClockDomain {
        /// The presented spelling.
        value: String,
        /// The declared reason it was refused.
        reason: String,
    },
    /// A sample, deadline, or clock names another clock domain.
    WrongClockDomain {
        /// The held domain.
        held: ClockDomainId,
        /// The presented domain.
        presented: ClockDomainId,
    },
    /// A sample is less than one already observed for its domain.
    MonotonicRegression {
        /// The observed domain.
        domain: ClockDomainId,
        /// The last accepted microsecond count.
        held: u64,
        /// The presented microsecond count.
        presented: u64,
    },
    /// Checked deadline arithmetic overflows the declared count.
    DeadlineOverflow {
        /// The domain of the sample.
        domain: ClockDomainId,
        /// The base microsecond count.
        base: u64,
        /// The added duration.
        duration: u64,
    },
    /// A deadline observes another waiter-generation fence than its registration.
    GenerationMismatch {
        /// The deadline fence.
        deadline: WaitGeneration,
        /// The registration fence.
        registration: WaitGeneration,
    },
    /// An expiry observation is presented before the recorded deadline.
    TimerNotDue {
        /// The recorded deadline.
        deadline: u64,
        /// The observed microsecond count.
        observed: u64,
    },
    /// A second deadline is presented to an already armed timer.
    TimerAlreadyArmed,
    /// The timer already settled with one winner.
    TimerAlreadySettled {
        /// The committed winner.
        winner: TimerWinner,
    },
    /// No deadline is armed.
    TimerUnarmed,
    /// A wake presents a fence the live wait does not hold.
    StaleWake {
        /// The addressed waiter.
        wait: WaitId,
        /// The held fence.
        held: WaitGeneration,
        /// The presented fence.
        presented: WaitGeneration,
    },
    /// The readiness recheck reports a cause this timer did not declare.
    UnexpectedReadiness {
        /// The observed cause.
        cause: WakeCause,
    },
    /// A landed wait refusal.
    Wait(WaitError),
}

impl TimerError {
    /// Returns the exact frozen refusal spelling.
    #[must_use]
    pub fn wire_name(&self) -> String {
        match self {
            Self::InvalidClockDomain { .. } => "time-invalid-clock-domain",
            Self::WrongClockDomain { .. } => "time-wrong-clock-domain",
            Self::MonotonicRegression { .. } => "time-monotonic-regression",
            Self::DeadlineOverflow { .. } => "time-deadline-overflow",
            Self::GenerationMismatch { .. } => "time-generation-mismatch",
            Self::TimerNotDue { .. } => "time-timer-not-due",
            Self::TimerAlreadyArmed => "time-timer-already-armed",
            Self::TimerUnarmed => "time-timer-unarmed",
            Self::UnexpectedReadiness { .. } => "time-unexpected-readiness",
            Self::StaleWake { .. } => "wait-stale-wake-refused",
            Self::TimerAlreadySettled { .. } => "wait-second-wake-refused",
            Self::Wait(error) => return error.code().wire_name().to_owned(),
        }
        .to_owned()
    }

    /// Returns the one clause that owns this refusal.
    #[must_use]
    pub fn owner(&self) -> String {
        match self {
            Self::InvalidClockDomain { .. }
            | Self::WrongClockDomain { .. }
            | Self::MonotonicRegression { .. }
            | Self::DeadlineOverflow { .. } => "GNT-51.3-injected-monotonic-clock",
            Self::GenerationMismatch { .. }
            | Self::TimerNotDue { .. }
            | Self::TimerAlreadyArmed
            | Self::TimerUnarmed
            | Self::UnexpectedReadiness { .. } => "GNT-51.4-one-shot-timer",
            Self::StaleWake { .. } => "GNT-24.4-stale-wake-fencing-and-waiter-reuse",
            Self::TimerAlreadySettled { .. } => "GNT-24.3-wake-causes-and-wake-ownership",
            Self::Wait(error) => return error.code().requirement().to_owned(),
        }
        .to_owned()
    }
}

impl fmt::Display for TimerError {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::InvalidClockDomain { value, reason } => {
                write!(formatter, "clock domain {value} is refused: {reason}")
            }
            Self::WrongClockDomain { held, presented } => {
                write!(
                    formatter,
                    "clock domain {held} is not the presented domain {presented}"
                )
            }
            Self::MonotonicRegression {
                domain,
                held,
                presented,
            } => write!(
                formatter,
                "clock domain {domain} observed {presented} after the held sample {held}"
            ),
            Self::DeadlineOverflow {
                domain,
                base,
                duration,
            } => write!(
                formatter,
                "deadline arithmetic in domain {domain} overflows from {base} by {duration}"
            ),
            Self::GenerationMismatch {
                deadline,
                registration,
            } => write!(
                formatter,
                "the deadline fence {deadline} differs from the registration fence {registration}"
            ),
            Self::TimerNotDue { deadline, observed } => write!(
                formatter,
                "the timer deadline {deadline} is not reached at {observed}"
            ),
            Self::TimerAlreadyArmed => formatter.write_str("the one-shot timer is already armed"),
            Self::TimerAlreadySettled { winner } => {
                write!(
                    formatter,
                    "the one-shot timer already settled as {winner:?}"
                )
            }
            Self::TimerUnarmed => formatter.write_str("no one-shot deadline is armed"),
            Self::StaleWake {
                wait,
                held,
                presented,
            } => write!(
                formatter,
                "waiter {wait} holds fence {held} and was presented the stale fence {presented}"
            ),
            Self::UnexpectedReadiness { cause } => write!(
                formatter,
                "the readiness recheck reported an unexpected cause {}",
                cause.wire_name()
            ),
            Self::Wait(error) => write!(formatter, "the landed wait contract refused: {error}"),
        }
    }
}

impl std::error::Error for TimerError {}

impl From<WaitError> for TimerError {
    fn from(error: WaitError) -> Self {
        Self::Wait(error)
    }
}
