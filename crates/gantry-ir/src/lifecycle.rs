//! Pure cooperative-stop and hard-cancellation model for application-level stops.
//!
//! This module is the machine-checked model for
//! `GNT-22.0-cooperative-stop-and-hard-cancellation`. It states the stop request
//! and its cause (`GNT-22.1-stop-request-identity-and-cause`), cooperative
//! observation and propagation
//! (`GNT-22.2-cooperative-stop-observation-and-propagation`), admission closure
//! (`GNT-22.3-admission-closure-during-stop`), safe points and suspension
//! (`GNT-22.4-safe-points-and-suspension`), declared grace and drain
//! (`GNT-22.5-grace-and-drain-ownership`), grace expiry and hard cancellation
//! (`GNT-22.6-grace-expiry-and-hard-cancellation`), the single published outcome
//! (`GNT-22.7-outcome-winner-and-single-publication`), durable stop cuts and replay
//! (`GNT-22.8-durable-stop-cuts-and-replay`), late and stale-generation fencing
//! (`GNT-22.9-late-result-and-stale-generation-fencing`), and the explicit
//! non-claims of the section (`GNT-22.10-stop-non-claims`).
//!
//! Scope is deliberately narrow. Every rule here is a pure function of its own
//! arguments: this module reads no process identifier, signal number, clock, host
//! path, environment variable, locale, socket, or adapter handle, and it exposes no
//! constructor that accepts one. Stop instants are explicit logical microseconds
//! supplied by the caller, so every verdict is reproducible from its own arguments.
//! This module is not the interpreter, not a scheduler, not an executor adapter, and
//! not a journal: it decides the stop contract that those landed components observe.
//!
//! Landed contracts are cited and reused rather than redeclared. The lifecycle state
//! machine `I = running | shutting-down(cause, effective-grace, effective-drain,
//! cohort) | terminated(report)` and the exactly-once settlement, foreground, and
//! terminal completion rules remain those of `GNT-3-M-LIFECYCLES`; the shutdown
//! operation, its cohort, its finite graceful timeout, its bounded drain, its report
//! and its unclean-drop path remain those of `GNT-10.12`, `GNT-10.13` and
//! `GNT-10.14`; the monotone one-way cancellation token remains that of `GNT-15.3`
//! and of the landed host contracts `CancellationSignal` and `CancellationToken`;
//! sealed emergency cleanup remains that of `GNT-15.10-emergency-cleanup`; and the
//! operation interruption, settlement-winner and generation-fencing rules remain
//! those of `GNT-20.5-interruption-cancellation-and-late-completion` and
//! `GNT-20.10-retirement-and-stale-owner-fencing`.
//!
//! Four separations stay explicit.
//!
//! * A [`StopRequestId`] is an opaque domain-separated digest over one declared
//!   cause and one declared grace and drain at one logical instant. It has no free
//!   constructor and no deserializer, so no process id, signal number, clock, path,
//!   environment fact, or adapter handle can become a stop identity.
//! * [`StopState`] refines the landed lifecycle without renaming it. Each phase
//!   reports the landed state it belongs to through [`StopState::landed_name`], so
//!   no phase becomes a second lifecycle machine and no phase returns to `running`.
//! * A [`TaskStopState`] publishes exactly one outcome. [`TaskStopState::publish`]
//!   and [`TaskStopState::publish_escalated`] refuse a second outcome, and
//!   [`LateResultFence::check`] refuses a late or stale-generation result without
//!   mutating settled state, so a settled outcome is immutable.
//! * [`DurableStopCut::advance`] moves the durable cut only forward. Escalation is
//!   therefore never re-decided by a replay, and a committed prefix reproduces the
//!   same winner.

use std::fmt;
use std::sync::Arc;

use crate::authority::digest_fields;
use crate::manifest::encode_hex;
use crate::operation::OwnerGeneration;

/// Domain separator for canonical stop-request identity derivation.
const STOP_REQUEST_DOMAIN: &str = "gantry.stop-request/v1";

/// The clause keys this model implements, in clause order.
///
/// Every diagnostic of this module names exactly one of these keys through
/// [`StopDiagnosticCode::requirement`], so every refusal is attributable to the
/// clause that owns it.
pub const LIFECYCLE_STOP_CLAUSES: [&str; 11] = [
    "GNT-22.0-cooperative-stop-and-hard-cancellation",
    "GNT-22.1-stop-request-identity-and-cause",
    "GNT-22.2-cooperative-stop-observation-and-propagation",
    "GNT-22.3-admission-closure-during-stop",
    "GNT-22.4-safe-points-and-suspension",
    "GNT-22.5-grace-and-drain-ownership",
    "GNT-22.6-grace-expiry-and-hard-cancellation",
    "GNT-22.7-outcome-winner-and-single-publication",
    "GNT-22.8-durable-stop-cuts-and-replay",
    "GNT-22.9-late-result-and-stale-generation-fencing",
    "GNT-22.10-stop-non-claims",
];

/// Encodes one number as its big-endian bytes.
fn number(value: u64) -> Vec<u8> {
    value.to_be_bytes().to_vec()
}

/// One landed cause class of the shutdown lifecycle (`GNT-3-M-LIFECYCLES`).
///
/// The landed state machine writes `cause ::= requested | poisoned`. This
/// vocabulary names those two classes so a [`StopCause`] can be assigned to one of
/// them without restating the machine; no third class exists.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum StopCauseClass {
    /// A stop that an operator, a supervisor, or a runtime request asked for.
    Requested,
    /// A stop that an applicable invariant failure forced.
    Poisoned,
}

impl StopCauseClass {
    /// Every member of the closed vocabulary.
    pub const ALL: [Self; 2] = [Self::Requested, Self::Poisoned];

    /// Returns the exact landed spelling of this cause class.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::Poisoned => "poisoned",
        }
    }

    /// Returns the same exact spelling as [`Self::wire_name`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.wire_name()
    }

    /// Strictly decodes one exact landed spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.wire_name() == value)
    }
}

/// One closed cause of a stop request (`GNT-22.1-stop-request-identity-and-cause`).
///
/// The vocabulary is exactly the three members below and admits no other spelling,
/// so a diagnostic, event, or report never carries an improvised cause. Each member
/// belongs to one landed cause class, and an invariant failure is the member that
/// carries the landed `poisoned` class.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum StopCause {
    /// An operator signal asked for the stop.
    OperatorSignal,
    /// A supervising component asked for the stop.
    SupervisorRequest,
    /// An applicable invariant failure forced the stop.
    InvariantFailure,
}

impl StopCause {
    /// Every member of the closed vocabulary, in class order.
    pub const ALL: [Self; 3] = [
        Self::OperatorSignal,
        Self::SupervisorRequest,
        Self::InvariantFailure,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::OperatorSignal => "operator-signal",
            Self::SupervisorRequest => "supervisor-request",
            Self::InvariantFailure => "invariant-failure",
        }
    }

    /// Returns the same exact portable spelling as [`Self::wire_name`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.wire_name()
    }

    /// Returns the landed cause class this member belongs to.
    #[must_use]
    pub const fn class(self) -> StopCauseClass {
        match self {
            Self::OperatorSignal | Self::SupervisorRequest => StopCauseClass::Requested,
            Self::InvariantFailure => StopCauseClass::Poisoned,
        }
    }

    /// Strictly decodes one exact portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.wire_name() == value)
    }

    /// Strictly decodes one spelling and names the clause that refuses an unknown one.
    ///
    /// A cause outside the closed vocabulary is refused rather than mapped onto the
    /// nearest declared cause, because a stop report that carried an improvised
    /// cause could not be attributed to a clause of this section.
    pub fn decode(spelling: &str) -> Result<Self, StopError> {
        Self::from_wire_name(spelling).ok_or_else(|| StopError::UnknownSpelling {
            vocabulary: "stop-cause",
            spelling: Arc::from(spelling),
        })
    }
}

/// One declared grace and drain budget of one stop request
/// (`GNT-22.5-grace-and-drain-ownership`).
///
/// Grace bounds cooperative settlement and drain bounds descendant and cleanup work
/// after escalation. Both are explicit, finite, and positive: unlike the landed
/// `effective-grace` and `effective-drain` of `GNT-3-M-LIFECYCLES`, a zero budget is
/// refused here, because a zero budget would mean the stop declared no budget at all
/// rather than a budget of zero instants. There is no default policy, so no
/// coordinator acquires a grace it never declared.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GracePolicy {
    grace_us: u64,
    drain_us: u64,
}

impl GracePolicy {
    /// Declares one positive, finite grace and drain, in logical microseconds.
    ///
    /// # Errors
    ///
    /// Returns [`StopError::UndeclaredGrace`] when either budget is zero, because
    /// such a policy declares nothing.
    pub fn new(grace_us: u64, drain_us: u64) -> Result<Self, StopError> {
        if grace_us == 0 || drain_us == 0 {
            return Err(StopError::UndeclaredGrace { grace_us, drain_us });
        }
        Ok(Self { grace_us, drain_us })
    }

    /// Returns the declared cooperative-settlement grace.
    #[must_use]
    pub const fn grace_us(self) -> u64 {
        self.grace_us
    }

    /// Returns the declared descendant-and-cleanup drain.
    #[must_use]
    pub const fn drain_us(self) -> u64 {
        self.drain_us
    }

    /// Returns the logical instant at which cooperative settlement expires.
    ///
    /// The deadline saturates rather than wrapping, so a declared budget never
    /// produces a deadline earlier than the instant it was declared at.
    #[must_use]
    pub const fn deadline_us(self, request_at_us: u64) -> u64 {
        request_at_us.saturating_add(self.grace_us)
    }

    /// Returns whether cooperative settlement has expired at one logical instant.
    #[must_use]
    pub const fn has_expired(self, request_at_us: u64, at_us: u64) -> bool {
        at_us >= self.deadline_us(request_at_us)
    }

    /// Returns the logical instant at which the declared drain expires.
    #[must_use]
    pub const fn drain_deadline_us(self, escalation_at_us: u64) -> u64 {
        escalation_at_us.saturating_add(self.drain_us)
    }
}

/// The stable Gantry-owned identity of one stop request
/// (`GNT-22.1-stop-request-identity-and-cause`).
///
/// The identity is a domain-separated SHA-256 digest over the canonical request: one
/// declared cause, one declared grace and drain, and one explicit logical instant. No
/// process identifier, signal number, clock reading, host path, environment fact, or
/// adapter handle participates, so equal requests always produce equal identities and
/// two requests that differ in any declared field are distinct identities. There is
/// no free constructor and no deserializer: a stop identity is obtainable only from
/// [`StopRequest::new`].
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StopRequestId {
    text: Arc<str>,
}

impl StopRequestId {
    /// Derives one identity over one declared cause, grace, drain, and instant.
    fn derive(cause: StopCause, grace: GracePolicy, at_us: u64) -> Self {
        let digest = digest_fields(
            STOP_REQUEST_DOMAIN,
            &[
                cause.wire_name().as_bytes(),
                cause.class().wire_name().as_bytes(),
                &number(grace.grace_us()),
                &number(grace.drain_us()),
                &number(at_us),
            ],
        );
        Self {
            text: Arc::from(format!("stop-request:{}", encode_hex(&digest))),
        }
    }

    /// Returns the exact portable identity spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Returns the lowercase digest text without the identity prefix.
    #[must_use]
    pub fn digest_hex(&self) -> &str {
        self.text
            .strip_prefix("stop-request:")
            .unwrap_or(&self.text)
    }
}

impl fmt::Display for StopRequestId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.text)
    }
}

/// One stop request: its stable identity, cause, declared budgets, and instant
/// (`GNT-22.1-stop-request-identity-and-cause`).
///
/// The identity is computed from the declared fields, never supplied, so a caller
/// cannot present an identity that does not describe the request it belongs to. The
/// request is a declaration only: it carries no process fact, no signal number, and
/// no handle, and creating one changes no lifecycle state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StopRequest {
    id: StopRequestId,
    cause: StopCause,
    grace: GracePolicy,
    at_us: u64,
}

impl StopRequest {
    /// Declares one stop request at one explicit logical instant.
    #[must_use]
    pub fn new(cause: StopCause, grace: GracePolicy, at_us: u64) -> Self {
        Self {
            id: StopRequestId::derive(cause, grace, at_us),
            cause,
            grace,
            at_us,
        }
    }

    /// Returns the stable identity of this request.
    #[must_use]
    pub const fn id(&self) -> &StopRequestId {
        &self.id
    }

    /// Returns the declared cause.
    #[must_use]
    pub const fn cause(&self) -> StopCause {
        self.cause
    }

    /// Returns the declared grace and drain.
    #[must_use]
    pub const fn grace(&self) -> GracePolicy {
        self.grace
    }

    /// Returns the explicit logical instant this request was declared at.
    #[must_use]
    pub const fn at_us(&self) -> u64 {
        self.at_us
    }

    /// Returns the logical instant at which cooperative settlement expires.
    #[must_use]
    pub const fn deadline_us(&self) -> u64 {
        self.grace.deadline_us(self.at_us)
    }

    /// Returns whether cooperative settlement has expired at one logical instant.
    #[must_use]
    pub const fn has_expired(&self, at_us: u64) -> bool {
        self.grace.has_expired(self.at_us, at_us)
    }

    /// Returns one canonical rendering of the declared request fields.
    #[must_use]
    pub fn canonical_text(&self) -> String {
        format!(
            "stop-request id={} cause={} class={} grace-us={} drain-us={} at-us={}",
            self.id.as_str(),
            self.cause.wire_name(),
            self.cause.class().wire_name(),
            self.grace.grace_us(),
            self.grace.drain_us(),
            self.at_us,
        )
    }
}

/// One closed source point at which cooperative stop may be observed
/// (`GNT-22.4-safe-points-and-suspension`).
///
/// The vocabulary is exactly the members below. Cooperative stop is not observable
/// at any other point, so no ad hoc poll, adapter callback, provider notification, or
/// asynchronous handler becomes a safe point.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SafePoint {
    /// The admission boundary of one operation.
    OperationAdmission,
    /// The entry of one workflow frame.
    WorkflowFrameEntry,
    /// The return of one workflow frame.
    WorkflowFrameReturn,
    /// The condition of one loop.
    LoopCondition,
    /// The back edge of one loop.
    LoopBackEdge,
    /// One wait or park of the source.
    WaitOrPark,
    /// One explicit cancellation check of the source.
    ExplicitCheck,
}

impl SafePoint {
    /// Every member of the closed vocabulary, in declaration order.
    pub const ALL: [Self; 7] = [
        Self::OperationAdmission,
        Self::WorkflowFrameEntry,
        Self::WorkflowFrameReturn,
        Self::LoopCondition,
        Self::LoopBackEdge,
        Self::WaitOrPark,
        Self::ExplicitCheck,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::OperationAdmission => "operation-admission",
            Self::WorkflowFrameEntry => "workflow-frame-entry",
            Self::WorkflowFrameReturn => "workflow-frame-return",
            Self::LoopCondition => "loop-condition",
            Self::LoopBackEdge => "loop-back-edge",
            Self::WaitOrPark => "wait-or-park",
            Self::ExplicitCheck => "explicit-check",
        }
    }

    /// Returns the same exact portable spelling as [`Self::wire_name`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.wire_name()
    }

    /// Strictly decodes one exact portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.wire_name() == value)
    }

    /// Observes one coordinator at this safe point.
    ///
    /// Returns `Ok(None)` while no stop request is held, `Ok(Some(observation))`
    /// while cooperative stop is observable, and
    /// [`StopError::CooperativeObservationAfterEscalation`] once hard cancellation has
    /// linearized: hard cancellation is not catchable by source, so no safe point
    /// yields a cooperative observation or a cooperative suspension after escalation.
    /// A terminated lifecycle yields no cooperative observation at all, so `Ok(None)`
    /// is returned for it rather than a stale observation of a stop that already
    /// finished.
    pub fn observe(
        &self,
        coordinator: &StopCoordinator,
    ) -> Result<Option<CooperativeObservation>, StopError> {
        if let Some(at_us) = coordinator.escalated_at_us() {
            return Err(StopError::CooperativeObservationAfterEscalation {
                safe_point: *self,
                escalated_at_us: at_us,
            });
        }
        if coordinator.state().is_terminal() {
            return Ok(None);
        }
        Ok(coordinator.request().map(|request| CooperativeObservation {
            request: request.id().clone(),
            cause: request.cause(),
            safe_point: *self,
        }))
    }
}

/// One cooperative observation of a held stop request
/// (`GNT-22.2-cooperative-stop-observation-and-propagation`).
///
/// The observation names the held request, its cause, and the safe point that
/// produced it. It is evidence only: observing a stop changes no source state, no
/// task outcome, and no durable record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CooperativeObservation {
    request: StopRequestId,
    cause: StopCause,
    safe_point: SafePoint,
}

impl CooperativeObservation {
    /// Returns the held request identity this observation reports.
    #[must_use]
    pub const fn request(&self) -> &StopRequestId {
        &self.request
    }

    /// Returns the held cause.
    #[must_use]
    pub const fn cause(&self) -> StopCause {
        self.cause
    }

    /// Returns the safe point that produced this observation.
    #[must_use]
    pub const fn safe_point(&self) -> SafePoint {
        self.safe_point
    }

    /// Returns one canonical rendering of the observation.
    #[must_use]
    pub fn canonical_text(&self) -> String {
        format!(
            "cooperative-observation request={} cause={} safe-point={}",
            self.request.as_str(),
            self.cause.wire_name(),
            self.safe_point.wire_name(),
        )
    }
}

/// One disposition cooperative stop fixes for one already-admitted task
/// (`GNT-22.2-cooperative-stop-observation-and-propagation`).
///
/// Cooperative stop leaves already-admitted work to settle under its own recovery
/// class and never fabricates, rewinds, or reclassifies a settled outcome.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AdmittedWork {
    /// The task is still nonterminal and settles under its own recovery class.
    SettlesUnderOwnRecoveryClass,
    /// The task already published an outcome, which the stop leaves untouched.
    SettledOutcomeLeftUntouched,
}

impl AdmittedWork {
    /// Every member of the closed vocabulary.
    pub const ALL: [Self; 2] = [
        Self::SettlesUnderOwnRecoveryClass,
        Self::SettledOutcomeLeftUntouched,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::SettlesUnderOwnRecoveryClass => "settles-under-own-recovery-class",
            Self::SettledOutcomeLeftUntouched => "settled-outcome-left-untouched",
        }
    }

    /// Returns the same exact portable spelling as [`Self::wire_name`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.wire_name()
    }
}

/// One coordinator phase of a stop
/// (`GNT-22.2-cooperative-stop-observation-and-propagation`).
///
/// The phases refine the landed `running | shutting-down | terminated` states without
/// renaming them: [`Self::Running`] is landed `running`, [`Self::StopRequested`],
/// [`Self::Draining`] and [`Self::Escalated`] are phases of landed `shutting-down`, and
/// [`Self::Terminated`] carries the landed immutable `terminated(report)`. No
/// transition returns to [`Self::Running`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StopState {
    /// The landed `running` state: admission is open and no request is held.
    Running,
    /// A stop request is held, admission is closed, and cooperative settlement is open.
    StopRequested,
    /// The cohort is closed and only descendant drain and cleanup work remain.
    Draining,
    /// Grace expired; hard cancellation is effective and irreversible.
    Escalated,
    /// The landed terminated state, carrying the immutable stop report.
    Terminated(StopReport),
}

impl StopState {
    /// Returns the exact portable phase spelling of this refinement.
    #[must_use]
    pub fn phase_name(&self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::StopRequested => "stop-requested",
            Self::Draining => "draining",
            Self::Escalated => "escalated",
            Self::Terminated(_) => "terminated",
        }
    }

    /// Returns the landed lifecycle state this phase belongs to.
    #[must_use]
    pub fn landed_name(&self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::StopRequested | Self::Draining | Self::Escalated => "shutting-down",
            Self::Terminated(_) => "terminated",
        }
    }

    /// Returns the position of this phase in the monotone phase order.
    #[must_use]
    pub fn rank(&self) -> u8 {
        match self {
            Self::Running => 0,
            Self::StopRequested => 1,
            Self::Draining => 2,
            Self::Escalated => 3,
            Self::Terminated(_) => 4,
        }
    }

    /// Returns whether this phase is the landed terminated state.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Terminated(_))
    }

    /// Returns the immutable stop report of the landed terminated state.
    #[must_use]
    pub fn report(&self) -> Option<&StopReport> {
        match self {
            Self::Terminated(report) => Some(report),
            Self::Running | Self::StopRequested | Self::Draining | Self::Escalated => None,
        }
    }
}

/// One fixed stop report of one terminated lifecycle
/// (`GNT-22.7-outcome-winner-and-single-publication`).
///
/// The report is computed from declared fields, the monotone cohort, and the single
/// escalation point. It carries no process fact, no signal number, and no clock
/// reading, and it is never rewritten after termination.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StopReport {
    request: StopRequestId,
    cause: StopCause,
    grace: GracePolicy,
    cohort: u64,
    escalated_at_us: Option<u64>,
    escalated_tasks: u64,
    preserved_outcomes: u64,
    terminated_at_us: u64,
}

impl StopReport {
    /// Returns the identity of the request this report belongs to.
    #[must_use]
    pub const fn request(&self) -> &StopRequestId {
        &self.request
    }

    /// Returns the cause that stopped this lifecycle.
    #[must_use]
    pub const fn cause(&self) -> StopCause {
        self.cause
    }

    /// Returns the declared grace and drain.
    #[must_use]
    pub const fn grace(&self) -> GracePolicy {
        self.grace
    }

    /// Returns the monotone cohort size at termination.
    #[must_use]
    pub const fn cohort(&self) -> u64 {
        self.cohort
    }

    /// Returns the single escalation instant, when grace expired.
    #[must_use]
    pub const fn escalated_at_us(&self) -> Option<u64> {
        self.escalated_at_us
    }

    /// Returns the number of tasks hard cancellation settled as escalated.
    #[must_use]
    pub const fn escalated_tasks(&self) -> u64 {
        self.escalated_tasks
    }

    /// Returns the number of already-settled outcomes escalation preserved.
    #[must_use]
    pub const fn preserved_outcomes(&self) -> u64 {
        self.preserved_outcomes
    }

    /// Returns the logical instant of termination.
    #[must_use]
    pub const fn terminated_at_us(&self) -> u64 {
        self.terminated_at_us
    }

    /// Returns whether grace expired before this lifecycle terminated.
    #[must_use]
    pub const fn is_escalated(&self) -> bool {
        self.escalated_at_us.is_some()
    }

    /// Returns one canonical rendering of the report fields.
    #[must_use]
    pub fn canonical_text(&self) -> String {
        let escalation = match self.escalated_at_us {
            Some(at_us) => at_us.to_string(),
            None => "none".to_owned(),
        };
        format!(
            "stop-report request={} cause={} grace-us={} drain-us={} cohort={} escalation-us={} escalated-tasks={} preserved-outcomes={} terminated-us={}",
            self.request.as_str(),
            self.cause.wire_name(),
            self.grace.grace_us(),
            self.grace.drain_us(),
            self.cohort,
            escalation,
            self.escalated_tasks,
            self.preserved_outcomes,
            self.terminated_at_us,
        )
    }
}

/// One result of joining one stop request to an existing stop
/// (`GNT-22.1-stop-request-identity-and-cause`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StopRequestJoin {
    /// The request joined the held request; the held identity and budgets remain in force.
    Joined,
    /// An invariant-failure request superseded a held requested-class cause.
    Replaced {
        /// The cause the coordinator held before the supersession.
        previous: StopCause,
    },
}

/// One cooperative phase transition that requires a held stop request
/// (`GNT-22.2-cooperative-stop-observation-and-propagation`).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum StopTransition {
    /// Propagation to an owned child of one coordinator.
    Propagation,
    /// Registration of one member of the shutdown cohort.
    CohortRegistration,
    /// Closure of the shutdown cohort.
    CohortClosure,
}

impl StopTransition {
    /// Every member of the closed vocabulary.
    pub const ALL: [Self; 3] = [
        Self::Propagation,
        Self::CohortRegistration,
        Self::CohortClosure,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Propagation => "propagation",
            Self::CohortRegistration => "cohort-registration",
            Self::CohortClosure => "cohort-closure",
        }
    }

    /// Returns the same exact portable spelling as [`Self::wire_name`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.wire_name()
    }
}

/// One escalation of one coordinator
/// (`GNT-22.6-grace-expiry-and-hard-cancellation`).
///
/// The escalation reports the single irreversible linearization point, whether the
/// call was a repetition of that point, and how the cohort settled: every
/// still-nonterminal task was settled once as escalated, and every already-settled
/// outcome was preserved.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Escalation {
    request: StopRequestId,
    at_us: u64,
    repeated: bool,
    escalated_tasks: u64,
    preserved_outcomes: u64,
}

impl Escalation {
    /// Returns the request this escalation belongs to.
    #[must_use]
    pub const fn request(&self) -> &StopRequestId {
        &self.request
    }

    /// Returns the single linearization point of this escalation.
    #[must_use]
    pub const fn at_us(&self) -> u64 {
        self.at_us
    }

    /// Returns whether this call repeated an already linearized escalation.
    #[must_use]
    pub const fn is_repeated(&self) -> bool {
        self.repeated
    }

    /// Returns the number of tasks this escalation settled as escalated.
    #[must_use]
    pub const fn escalated_tasks(&self) -> u64 {
        self.escalated_tasks
    }

    /// Returns the number of already-settled outcomes this escalation preserved.
    #[must_use]
    pub const fn preserved_outcomes(&self) -> u64 {
        self.preserved_outcomes
    }
}

/// The single shutdown coordinator of one lifecycle
/// (`GNT-22.2-cooperative-stop-observation-and-propagation`).
///
/// The coordinator holds at most one stop request, closes admission at the first
/// request, grows one monotone cohort, linearizes escalation exactly once, and
/// terminates into exactly one immutable report. Repeated requests join, repeated
/// escalation is stuttering, and repeated termination observes the same report, so no
/// phase transition reopens admission or returns to `running`. One lifecycle has
/// exactly one coordinator, so this value is not cloneable: a clone would be a second
/// coordinator claiming the same lifecycle.
#[derive(Debug)]
pub struct StopCoordinator {
    request: Option<StopRequest>,
    state: StopState,
    cohort: u64,
    cohort_closed: bool,
    escalated_at_us: Option<u64>,
    escalated_tasks: u64,
    preserved_outcomes: u64,
    watermark_us: u64,
}

impl Default for StopCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

impl StopCoordinator {
    /// Returns one fresh coordinator in the landed `running` phase.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            request: None,
            state: StopState::Running,
            cohort: 0,
            cohort_closed: false,
            escalated_at_us: None,
            escalated_tasks: 0,
            preserved_outcomes: 0,
            watermark_us: 0,
        }
    }

    /// Returns the current phase.
    #[must_use]
    pub const fn state(&self) -> &StopState {
        &self.state
    }

    /// Returns the held stop request, when one was declared.
    #[must_use]
    pub const fn request(&self) -> Option<&StopRequest> {
        self.request.as_ref()
    }

    /// Returns whether admission of new application work is still open.
    #[must_use]
    pub const fn is_admission_open(&self) -> bool {
        self.request.is_none()
    }

    /// Returns the monotone shutdown cohort size.
    #[must_use]
    pub const fn cohort(&self) -> u64 {
        self.cohort
    }

    /// Returns whether the cohort is closed to further growth.
    #[must_use]
    pub const fn is_cohort_closed(&self) -> bool {
        self.cohort_closed
    }

    /// Returns the single escalation instant, once escalation linearized.
    #[must_use]
    pub const fn escalated_at_us(&self) -> Option<u64> {
        self.escalated_at_us
    }

    /// Returns the highest logical instant this coordinator has accepted.
    #[must_use]
    pub const fn watermark_us(&self) -> u64 {
        self.watermark_us
    }

    /// Returns the declared descendant-and-cleanup drain deadline of 22.5.
    ///
    /// The declared drain is the descendant-and-cleanup budget of
    /// `GNT-22.5-grace-and-drain-ownership`. The deadline is the declared escalation
    /// instant plus that drain, once escalation linearized; before escalation the
    /// lifecycle declared no drain deadline and the answer is `None`.
    #[must_use]
    pub const fn drain_deadline_us(&self) -> Option<u64> {
        match self.escalated_at_us {
            Some(at_us) => match &self.request {
                Some(request) => Some(request.grace().drain_deadline_us(at_us)),
                None => None,
            },
            None => None,
        }
    }

    /// Returns whether the declared drain of 22.5 has expired at one logical instant.
    ///
    /// The declared drain is the descendant-and-cleanup budget of
    /// `GNT-22.5-grace-and-drain-ownership`, measured from the escalation instant. The
    /// answer is `true` at or after that deadline and `false` before it, and it is
    /// `false` before escalation linearized, because nothing was declared yet.
    #[must_use]
    pub const fn has_drain_expired(&self, at_us: u64) -> bool {
        match self.drain_deadline_us() {
            Some(deadline_us) => at_us >= deadline_us,
            None => false,
        }
    }

    /// Admits one application work item while admission is open.
    ///
    /// # Errors
    ///
    /// Returns [`StopError::AdmissionAfterClosure`] once admission closed, so a
    /// stopped lifecycle never queues, buffers, or admits new application work.
    pub fn admit_application_work(&self, at_us: u64) -> Result<(), StopError> {
        if self.request.is_some() {
            return Err(StopError::AdmissionAfterClosure { at_us });
        }
        Ok(())
    }

    /// Requests one stop, joining a held request of the same cause.
    ///
    /// The first request closes admission, fixes the identity and the declared grace
    /// and drain in force, and moves the lifecycle to the landed `shutting-down`
    /// state. A later request with the same cause joins the held request: the held
    /// identity, cause, and budgets remain in force and no second transition is
    /// created. An invariant-failure request may supersede a held requested-class
    /// cause under the landed rule that `poisoned` may replace `requested`; it must
    /// present the budgets already declared, because a stop declaration is made once.
    /// The declaration instant and the budgets in force remain those the first request
    /// fixed, so a superseding request replaces only the cause; a presented instant is
    /// admitted only when it preserves the monotone instant order. An accepted call
    /// advances the coordinator instant watermark to the presented instant, including a
    /// joining or stuttering call, so a later transition at an earlier instant is
    /// refused.
    ///
    /// # Errors
    ///
    /// Returns [`StopError::NonMonotoneInstant`] when the first request precedes the
    /// coordinator's instant watermark, [`StopError::RedeclaredGrace`] when a
    /// joining or superseding request re-declares the budgets, and
    /// [`StopError::CauseConflict`] when the causes cannot be joined or superseded.
    pub fn request_stop(&mut self, request: StopRequest) -> Result<StopRequestJoin, StopError> {
        let Some(held) = self.request.as_ref() else {
            self.check_instant(request.at_us())?;
            self.watermark_us = request.at_us();
            self.request = Some(request);
            self.state = StopState::StopRequested;
            return Ok(StopRequestJoin::Joined);
        };
        self.check_instant(request.at_us())?;
        if held.cause() == request.cause() {
            if held.grace() != request.grace() {
                return Err(StopError::RedeclaredGrace {
                    held: held.grace(),
                    presented: request.grace(),
                });
            }
            self.watermark_us = self.watermark_us.max(request.at_us());
            return Ok(StopRequestJoin::Joined);
        }
        if held.cause().class() == StopCauseClass::Requested
            && request.cause().class() == StopCauseClass::Poisoned
        {
            if held.grace() != request.grace() {
                return Err(StopError::RedeclaredGrace {
                    held: held.grace(),
                    presented: request.grace(),
                });
            }
            let previous = held.cause();
            let grace = held.grace();
            let at_us = held.at_us();
            self.watermark_us = self.watermark_us.max(request.at_us());
            self.request = Some(StopRequest::new(request.cause(), grace, at_us));
            return Ok(StopRequestJoin::Replaced { previous });
        }
        Err(StopError::CauseConflict {
            requested: request.cause(),
            held: held.cause(),
        })
    }

    /// Propagates this coordinator's held request to one owned child.
    ///
    /// The child joins the same request identity and closes its own admission, so
    /// propagation creates no second identity and no second cause. The coordinator is
    /// not an ownership registry: the caller owns the obligation to propagate to every
    /// child it owns, one call per child, because only the caller knows which children
    /// are its own.
    ///
    /// # Errors
    ///
    /// Returns [`StopError::WithoutStopRequest`] when no request is held,
    /// [`StopError::TerminatedCoordinator`] once the lifecycle terminated, and the join
    /// refusals of [`Self::request_stop`] when the child cannot join.
    pub fn propagate(&self, child: &mut Self) -> Result<StopRequestJoin, StopError> {
        if self.state.is_terminal() {
            return Err(StopError::TerminatedCoordinator);
        }
        let Some(held) = self.request.as_ref() else {
            return Err(StopError::WithoutStopRequest {
                transition: StopTransition::Propagation,
            });
        };
        child.request_stop(held.clone())
    }

    /// Registers one more member of the monotone shutdown cohort.
    ///
    /// # Errors
    ///
    /// Returns [`StopError::WithoutStopRequest`] before any request is held and
    /// [`StopError::CohortGrowthAfterClosure`] once the cohort closed, because after
    /// closure no new cooperative work joins the cohort.
    pub fn register_cohort_member(&mut self) -> Result<u64, StopError> {
        if self.request.is_none() {
            return Err(StopError::WithoutStopRequest {
                transition: StopTransition::CohortRegistration,
            });
        }
        if self.cohort_closed {
            return Err(StopError::CohortGrowthAfterClosure {
                cohort: self.cohort,
            });
        }
        self.cohort = self.cohort.saturating_add(1);
        Ok(self.cohort)
    }

    /// Closes the cohort and enters the cooperative drain phase.
    ///
    /// After closure only descendant drain and cleanup work remain. A repeated call is
    /// stuttering, and a call after escalation changes nothing, because escalation
    /// closed the cohort at its own linearization point; the presented instant must
    /// still preserve the monotone instant order. An accepted call advances the
    /// coordinator instant watermark to the presented instant, including a stuttering
    /// call on an already closed cohort, so a later transition at an earlier instant is
    /// refused.
    ///
    /// # Errors
    ///
    /// Returns [`StopError::TerminatedCoordinator`] once the lifecycle terminated,
    /// [`StopError::WithoutStopRequest`] before any request is held, and
    /// [`StopError::NonMonotoneInstant`] for an instant that precedes the watermark.
    pub fn close_cohort(&mut self, at_us: u64) -> Result<(), StopError> {
        if self.state.is_terminal() {
            return Err(StopError::TerminatedCoordinator);
        }
        if self.request.is_none() {
            return Err(StopError::WithoutStopRequest {
                transition: StopTransition::CohortClosure,
            });
        }
        self.check_instant(at_us)?;
        self.watermark_us = self.watermark_us.max(at_us);
        if self.cohort_closed {
            return Ok(());
        }
        self.cohort_closed = true;
        if matches!(self.state, StopState::StopRequested) {
            self.state = StopState::Draining;
        }
        Ok(())
    }

    /// Escalates to hard cancellation at one irreversible linearization point.
    ///
    /// Every still-nonterminal task of `tasks` is settled once as escalated, and every
    /// already-settled outcome is preserved. Escalation closes the cohort at the same
    /// point, so no further cooperative work is admitted. A repeated call is
    /// stuttering: it reports the recorded point, settles no task, and still advances
    /// the coordinator instant watermark to the presented instant.
    ///
    /// The point is the declared grace deadline of the held request, so an instant
    /// that precedes that deadline is refused rather than treated as grace expiry. Each
    /// settled task is published from this coordinator's own [`Escalation`], so hard
    /// cancellation is never applied from a caller-supplied instant.
    ///
    /// # Errors
    ///
    /// Returns [`StopError::EscalationWithoutStopRequest`] in the landed `running`
    /// state, [`StopError::TerminatedCoordinator`] after termination,
    /// [`StopError::NonMonotoneInstant`] for an instant that precedes the watermark,
    /// and [`StopError::EscalationBeforeGraceExpiry`] for an instant that precedes the
    /// declared deadline.
    pub fn escalate(
        &mut self,
        tasks: &mut [TaskStopState],
        at_us: u64,
    ) -> Result<Escalation, StopError> {
        if matches!(self.state, StopState::Running) {
            return Err(StopError::EscalationWithoutStopRequest);
        }
        if matches!(self.state, StopState::Terminated(_)) {
            return Err(StopError::TerminatedCoordinator);
        }
        let Some(held) = self.request.as_ref() else {
            return Err(StopError::EscalationWithoutStopRequest);
        };
        let request = held.id().clone();
        if let Some(recorded) = self.escalated_at_us {
            if at_us < recorded {
                return Err(StopError::NonMonotoneInstant {
                    presented: at_us,
                    held: recorded,
                });
            }
            self.watermark_us = self.watermark_us.max(at_us);
            return Ok(Escalation {
                request,
                at_us: recorded,
                repeated: true,
                escalated_tasks: self.escalated_tasks,
                preserved_outcomes: self.preserved_outcomes,
            });
        }
        self.check_instant(at_us)?;
        let deadline_us = held.deadline_us();
        if at_us < deadline_us {
            return Err(StopError::EscalationBeforeGraceExpiry {
                deadline_us,
                presented_at_us: at_us,
            });
        }
        self.watermark_us = at_us;
        self.escalated_at_us = Some(at_us);
        self.cohort_closed = true;
        let mut escalation = Escalation {
            request,
            at_us,
            repeated: false,
            escalated_tasks: 0,
            preserved_outcomes: 0,
        };
        let mut escalated_tasks = 0_u64;
        let mut preserved_outcomes = 0_u64;
        for task in tasks.iter_mut() {
            if task.publish_escalated(&escalation).is_ok() {
                escalated_tasks += 1;
            } else {
                preserved_outcomes += 1;
            }
        }
        escalation.escalated_tasks = escalated_tasks;
        escalation.preserved_outcomes = preserved_outcomes;
        self.escalated_tasks = escalated_tasks;
        self.preserved_outcomes = preserved_outcomes;
        self.state = StopState::Escalated;
        Ok(escalation)
    }

    /// Terminates the lifecycle into one immutable stop report.
    ///
    /// A repeated call observes the same report, so the winner is never recomputed, and
    /// it advances the coordinator instant watermark to the presented instant, so a
    /// later transition at an earlier instant is refused. A presented instant that
    /// precedes the coordinator watermark is refused rather than reordered.
    ///
    /// # Errors
    ///
    /// Returns [`StopError::TerminationBeforeDrain`] while the cohort is still open or
    /// no request is held, and [`StopError::NonMonotoneInstant`] for an instant that
    /// precedes the watermark.
    pub fn terminate(&mut self, at_us: u64) -> Result<StopReport, StopError> {
        self.check_instant(at_us)?;
        if let StopState::Terminated(report) = &self.state {
            let observed = report.clone();
            self.watermark_us = self.watermark_us.max(at_us);
            return Ok(observed);
        }
        if !matches!(self.state, StopState::Draining | StopState::Escalated) {
            return Err(StopError::TerminationBeforeDrain {
                phase: self.state.phase_name(),
            });
        }
        let Some(held) = self.request.as_ref() else {
            return Err(StopError::WithoutStopRequest {
                transition: StopTransition::CohortClosure,
            });
        };
        self.check_instant(at_us)?;
        self.watermark_us = at_us;
        let report = StopReport {
            request: held.id().clone(),
            cause: held.cause(),
            grace: held.grace(),
            cohort: self.cohort,
            escalated_at_us: self.escalated_at_us,
            escalated_tasks: self.escalated_tasks,
            preserved_outcomes: self.preserved_outcomes,
            terminated_at_us: at_us,
        };
        self.state = StopState::Terminated(report.clone());
        Ok(report)
    }

    /// Returns the durable stop cut this phase has committed.
    #[must_use]
    pub fn durable_cut(&self) -> Option<DurableStopCut> {
        match &self.state {
            StopState::Running => None,
            StopState::StopRequested | StopState::Draining => Some(DurableStopCut::StopRequested),
            StopState::Escalated => Some(DurableStopCut::GraceExpired),
            StopState::Terminated(_) => Some(DurableStopCut::Terminated),
        }
    }

    /// Returns the disposition cooperative stop fixes for one admitted task.
    #[must_use]
    pub fn admitted_work(&self, task: &TaskStopState) -> AdmittedWork {
        if task.is_settled() {
            AdmittedWork::SettledOutcomeLeftUntouched
        } else {
            AdmittedWork::SettlesUnderOwnRecoveryClass
        }
    }

    /// Returns whether one logical instant preserves the monotone instant order.
    fn check_instant(&self, at_us: u64) -> Result<(), StopError> {
        if at_us < self.watermark_us {
            return Err(StopError::NonMonotoneInstant {
                presented: at_us,
                held: self.watermark_us,
            });
        }
        Ok(())
    }
}

/// One published terminal outcome of one task
/// (`GNT-22.7-outcome-winner-and-single-publication`).
///
/// The four members describe how one task settled and are not a second task-status
/// vocabulary: each member names the landed status it publishes, and the escalation
/// member publishes the landed `cancelled` status rather than a fourth one. The
/// member is fixed by whoever settles the task: only hard cancellation may publish
/// [`Self::Escalated`].
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TaskOutcome {
    /// The task completed under its own recovery class.
    Completed,
    /// The task failed under its own recovery class, including a contained panic.
    Failed,
    /// The task's own monotone cancellation mark settled it.
    Cancelled,
    /// Hard cancellation settled a still-nonterminal task.
    Escalated,
}

impl TaskOutcome {
    /// Every member of the closed vocabulary.
    pub const ALL: [Self; 4] = [
        Self::Completed,
        Self::Failed,
        Self::Cancelled,
        Self::Escalated,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Escalated => "escalated",
        }
    }

    /// Returns the same exact portable spelling as [`Self::wire_name`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.wire_name()
    }

    /// Strictly decodes one exact portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.wire_name() == value)
    }

    /// Returns whether hard cancellation published this outcome.
    #[must_use]
    pub const fn is_escalated(self) -> bool {
        matches!(self, Self::Escalated)
    }

    /// Returns the landed task status this outcome publishes.
    ///
    /// The spellings are the landed ones, so escalation never creates a fourth task
    /// status and a report never claims one.
    #[must_use]
    pub const fn landed_status(self) -> &'static str {
        match self {
            Self::Completed => "succeeded",
            Self::Failed => "failed",
            Self::Cancelled | Self::Escalated => "cancelled",
        }
    }
}

/// One result arriving for one task (`GNT-22.9-late-result-and-stale-generation-fencing`).
///
/// A result names the outcome it carries, the owner generation it belongs to, and the
/// explicit logical instant it arrived at. It is not a domain outcome of hard
/// cancellation: [`TaskResult::new`] refuses the escalation member, because escalation
/// is published by the coordinator rather than reported as an ordinary result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaskResult {
    outcome: TaskOutcome,
    generation: OwnerGeneration,
    at_us: u64,
}

impl TaskResult {
    /// Builds one arriving result for one owner generation and logical instant.
    ///
    /// # Errors
    ///
    /// Returns [`StopError::EscalationAsDomainOutcome`] when the result claims the
    /// escalation member, so hard cancellation is never reported as a domain failure
    /// and never presented as an ordinary completion.
    pub fn new(
        outcome: TaskOutcome,
        generation: OwnerGeneration,
        at_us: u64,
    ) -> Result<Self, StopError> {
        if outcome.is_escalated() {
            return Err(StopError::EscalationAsDomainOutcome);
        }
        Ok(Self {
            outcome,
            generation,
            at_us,
        })
    }

    /// Returns the outcome this result carries.
    #[must_use]
    pub const fn outcome(&self) -> TaskOutcome {
        self.outcome
    }

    /// Returns the owner generation this result belongs to.
    #[must_use]
    pub const fn generation(&self) -> OwnerGeneration {
        self.generation
    }

    /// Returns the explicit logical instant this result arrived at.
    #[must_use]
    pub const fn at_us(&self) -> u64 {
        self.at_us
    }
}

/// The published outcome state of one task
/// (`GNT-22.7-outcome-winner-and-single-publication`).
///
/// The state holds the landed owner generation it was created for, the outcome it
/// published, and the instant of that publication. It publishes at most one outcome,
/// and the generation is the landed [`OwnerGeneration`] of
/// `GNT-20.10-retirement-and-stale-owner-fencing` rather than a second fence
/// vocabulary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskStopState {
    generation: OwnerGeneration,
    outcome: Option<TaskOutcome>,
    published_at_us: Option<u64>,
}

impl TaskStopState {
    /// Returns one nonterminal task state held under one owner generation.
    #[must_use]
    pub const fn new(generation: OwnerGeneration) -> Self {
        Self {
            generation,
            outcome: None,
            published_at_us: None,
        }
    }

    /// Returns the owner generation this task state holds.
    #[must_use]
    pub const fn generation(&self) -> OwnerGeneration {
        self.generation
    }

    /// Returns the published outcome, when one was published.
    #[must_use]
    pub const fn outcome(&self) -> Option<TaskOutcome> {
        self.outcome
    }

    /// Returns the logical instant the outcome was published at.
    #[must_use]
    pub const fn published_at_us(&self) -> Option<u64> {
        self.published_at_us
    }

    /// Returns whether an outcome was published.
    #[must_use]
    pub const fn is_settled(&self) -> bool {
        self.outcome.is_some()
    }

    /// Publishes one arriving result as this task's single terminal outcome.
    ///
    /// # Errors
    ///
    /// Returns the fence refusal of [`LateResultFence::check`]: a result of another
    /// owner generation, a late result, or a second completion is refused without
    /// mutating the state, so an already-published outcome stays the winner.
    pub fn publish(&mut self, result: &TaskResult) -> Result<TaskOutcome, StopError> {
        LateResultFence::check(self, result)?;
        self.outcome = Some(result.outcome());
        self.published_at_us = Some(result.at_us());
        Ok(result.outcome())
    }

    /// Settles one still-nonterminal task once as escalated.
    ///
    /// The escalation member is publishable only from a coordinator-issued
    /// [`Escalation`], whose instant is the single irreversible linearization point of
    /// hard cancellation, so no caller can manufacture hard cancellation by presenting
    /// an instant of its own.
    ///
    /// # Errors
    ///
    /// Returns [`StopError::EscalationOverSettledOutcome`] when the task already
    /// published an outcome, because escalation never overwrites a completed,
    /// failed, or cancelled result.
    pub fn publish_escalated(&mut self, escalation: &Escalation) -> Result<TaskOutcome, StopError> {
        if let Some(published) = self.outcome {
            return Err(StopError::EscalationOverSettledOutcome { published });
        }
        self.outcome = Some(TaskOutcome::Escalated);
        self.published_at_us = Some(escalation.at_us());
        Ok(TaskOutcome::Escalated)
    }
}

/// The fence that refuses a late or stale-generation result
/// (`GNT-22.9-late-result-and-stale-generation-fencing`).
///
/// The fence is checked before any publication mutates state. It refuses a result
/// that names an owner generation the task does not hold, refuses a result that
/// arrived at or before the instant of the published outcome as late, and refuses any
/// other second completion. A refusal latches nothing and rewrites no outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LateResultFence;

impl LateResultFence {
    /// Checks one arriving result against one task's published state.
    ///
    /// # Errors
    ///
    /// Returns [`StopError::StaleOwnerGeneration`] for a foreign generation,
    /// [`StopError::LateResult`] for a result at or before the publication instant, and
    /// [`StopError::SecondPublication`] for any other second completion.
    pub fn check(state: &TaskStopState, result: &TaskResult) -> Result<(), StopError> {
        if result.generation() != state.generation() {
            return Err(StopError::StaleOwnerGeneration {
                presented: result.generation(),
                held: state.generation(),
            });
        }
        let Some(published) = state.outcome() else {
            return Ok(());
        };
        match state.published_at_us() {
            Some(published_at_us) if result.at_us() <= published_at_us => {
                Err(StopError::LateResult {
                    published,
                    published_at_us,
                    presented_at_us: result.at_us(),
                })
            }
            Some(_) | None => Err(StopError::SecondPublication { published }),
        }
    }
}

/// One durable stop cut of one lifecycle
/// (`GNT-22.8-durable-stop-cuts-and-replay`).
///
/// The cuts are exactly the three members below, in cut order. The cut only ever
/// advances, so a replay from a committed prefix reproduces the same winner and never
/// re-decides escalation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DurableStopCut {
    /// The stop request was committed and admission is closed.
    StopRequested,
    /// Grace expiry and hard cancellation were committed at one point.
    GraceExpired,
    /// The terminal stop report was committed.
    Terminated,
}

impl DurableStopCut {
    /// Every member of the closed vocabulary, in cut order.
    pub const ALL: [Self; 3] = [Self::StopRequested, Self::GraceExpired, Self::Terminated];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::StopRequested => "stop-requested",
            Self::GraceExpired => "grace-expired",
            Self::Terminated => "terminated",
        }
    }

    /// Returns the same exact portable spelling as [`Self::wire_name`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.wire_name()
    }

    /// Strictly decodes one exact portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.wire_name() == value)
    }

    /// Returns the position of this cut in the declared cut order.
    #[must_use]
    pub const fn rank(self) -> u8 {
        match self {
            Self::StopRequested => 0,
            Self::GraceExpired => 1,
            Self::Terminated => 2,
        }
    }

    /// Advances one durable cut, refusing a cut that regresses or skips one.
    ///
    /// A repeated advance to the same cut is stuttering, so an idempotent replay
    /// commits nothing twice. A cut only advances to the next committed cut: it never
    /// moves backwards and never jumps over an uncommitted cut, so a replay never
    /// rewrites escalation into a cooperative stop and no intermediate cut is skipped.
    ///
    /// # Errors
    ///
    /// Returns [`StopError::CutRegression`] when `next` precedes the current cut or
    /// skips over an uncommitted cut.
    pub fn advance(&mut self, next: Self) -> Result<(), StopError> {
        if next.rank() < self.rank() || next.rank() > self.rank() + 1 {
            return Err(StopError::CutRegression {
                current: *self,
                next,
            });
        }
        *self = next;
        Ok(())
    }

    /// Classifies what recovery must do from this committed cut.
    #[must_use]
    pub const fn classify_crash_cut(self) -> StopCrashCutClassification {
        match self {
            Self::StopRequested => StopCrashCutClassification::Cooperative,
            Self::GraceExpired => StopCrashCutClassification::Escalated,
            Self::Terminated => StopCrashCutClassification::Terminated,
        }
    }
}

/// One recovery classification of one committed durable stop cut
/// (`GNT-22.8-durable-stop-cuts-and-replay`).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum StopCrashCutClassification {
    /// A stop request is durable: recovery resumes cooperative settlement.
    Cooperative,
    /// Grace expiry is durable: hard cancellation is already effective.
    Escalated,
    /// The terminal report is durable and immutable.
    Terminated,
}

impl StopCrashCutClassification {
    /// Every member of the closed vocabulary.
    pub const ALL: [Self; 3] = [Self::Cooperative, Self::Escalated, Self::Terminated];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Cooperative => "cooperative",
            Self::Escalated => "escalated",
            Self::Terminated => "terminated",
        }
    }

    /// Returns the same exact portable spelling as [`Self::wire_name`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.wire_name()
    }

    /// Returns whether the committed cut already decided escalation.
    #[must_use]
    pub const fn is_escalation_decided(self) -> bool {
        matches!(self, Self::Escalated | Self::Terminated)
    }
}

/// One work item hard cancellation permits or forbids
/// (`GNT-22.6-grace-expiry-and-hard-cancellation`).
///
/// After escalation only descendant drain and sealed emergency release are admitted.
/// Source cleanup is forbidden: hard cancellation is not catchable, so no source
/// scope, handler, or callback runs cleanup for it.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum EscalatedWork {
    /// Draining of descendants and owned cleanup work.
    DescendantDrain,
    /// Sealed emergency release under `GNT-15.10-emergency-cleanup`.
    EmergencyRelease,
    /// Source cleanup, which hard cancellation forbids.
    SourceCleanup,
}

impl EscalatedWork {
    /// Every member of this vocabulary.
    pub const ALL: [Self; 3] = [
        Self::DescendantDrain,
        Self::EmergencyRelease,
        Self::SourceCleanup,
    ];

    /// The members hard cancellation permits.
    pub const PERMITTED: [Self; 2] = [Self::DescendantDrain, Self::EmergencyRelease];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::DescendantDrain => "descendant-drain",
            Self::EmergencyRelease => "emergency-release",
            Self::SourceCleanup => "source-cleanup",
        }
    }

    /// Returns the same exact portable spelling as [`Self::wire_name`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.wire_name()
    }

    /// Returns whether hard cancellation admits this work.
    #[must_use]
    pub const fn is_permitted(self) -> bool {
        matches!(self, Self::DescendantDrain | Self::EmergencyRelease)
    }

    /// Admits one work item after escalation.
    ///
    /// # Errors
    ///
    /// Returns [`StopError::SourceCleanupAfterEscalation`] for the forbidden source
    /// cleanup step, so a stopped lifecycle never runs source cleanup after hard
    /// cancellation.
    pub fn admit(self) -> Result<Self, StopError> {
        if self.is_permitted() {
            return Ok(self);
        }
        Err(StopError::SourceCleanupAfterEscalation {
            step: Arc::from(self.wire_name()),
        })
    }
}

/// One closed name of a stop non-claim (`GNT-22.10-stop-non-claims`).
///
/// Each member names property this section explicitly does not promise. A report,
/// clause, or evidence item MUST NOT be read as promising one, and the vocabulary is
/// closed so no unlisted guarantee can be claimed under this section.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum StopNonClaimName {
    /// Hard cancellation is not catchable by source.
    CatchableHardCancellation,
    /// No ambient asynchronous handler becomes a stop source.
    AmbientSourceHandlers,
    /// No provider cancellation becomes an application stop.
    ProviderCancellationAsStop,
    /// No source cleanup runs after hard cancellation.
    SourceCleanupAfterEscalation,
    /// No forcibly terminated process publishes a stop report.
    ForcedTerminationReport,
}

impl StopNonClaimName {
    /// Every member of the closed vocabulary, in published order.
    pub const ALL: [Self; 5] = [
        Self::CatchableHardCancellation,
        Self::AmbientSourceHandlers,
        Self::ProviderCancellationAsStop,
        Self::SourceCleanupAfterEscalation,
        Self::ForcedTerminationReport,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::CatchableHardCancellation => "catchable-hard-cancellation",
            Self::AmbientSourceHandlers => "ambient-source-handlers",
            Self::ProviderCancellationAsStop => "provider-cancellation-as-stop",
            Self::SourceCleanupAfterEscalation => "source-cleanup-after-escalation",
            Self::ForcedTerminationReport => "forced-termination-report",
        }
    }

    /// Returns the same exact portable spelling as [`Self::wire_name`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.wire_name()
    }

    /// Strictly decodes one exact portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.wire_name() == value)
    }
}

/// One published stop non-claim (`GNT-22.10-stop-non-claims`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StopNonClaim {
    name: StopNonClaimName,
    statement: &'static str,
}

impl StopNonClaim {
    /// Returns the closed name of this non-claim.
    #[must_use]
    pub const fn name(self) -> StopNonClaimName {
        self.name
    }

    /// Returns the published statement of this non-claim.
    #[must_use]
    pub const fn statement(self) -> &'static str {
        self.statement
    }

    /// Refuses a request to read this non-claim as a stop guarantee.
    ///
    /// # Errors
    ///
    /// Always returns [`StopError::NonClaimAsGuarantee`], because this section has no
    /// path that turns one of these limits into a guarantee.
    pub const fn as_guarantee(self) -> Result<(), StopError> {
        Err(StopError::NonClaimAsGuarantee { name: self.name })
    }
}

/// The published order of the closed stop non-claim vocabulary.
pub const STOP_NON_CLAIM_ORDER: [StopNonClaimName; 5] = StopNonClaimName::ALL;

/// The published stop non-claims, in [`STOP_NON_CLAIM_ORDER`] order.
pub const STOP_NON_CLAIMS: [StopNonClaim; 5] = [
    StopNonClaim {
        name: StopNonClaimName::CatchableHardCancellation,
        statement: "hard cancellation is not catchable by source: no handler, scope, callback, or recovery clause observes, defers, or dismisses it",
    },
    StopNonClaim {
        name: StopNonClaimName::AmbientSourceHandlers,
        statement: "no ambient asynchronous handler becomes a stop source; every stop request is the explicit request of GNT-22.1",
    },
    StopNonClaim {
        name: StopNonClaimName::ProviderCancellationAsStop,
        statement: "a provider, adapter, or integration cancellation is not an application stop and never becomes one",
    },
    StopNonClaim {
        name: StopNonClaimName::SourceCleanupAfterEscalation,
        statement: "after hard cancellation no source cleanup runs: only descendant drain and sealed emergency release are admitted",
    },
    StopNonClaim {
        name: StopNonClaimName::ForcedTerminationReport,
        statement: "a forcibly terminated process publishes no stop report, and this section claims nothing about one",
    },
];

/// One frozen published diagnostic identity of the cooperative-stop model.
///
/// `SPEC.md` assigns no exact stop diagnostic code, so this module publishes the
/// registry below, one code per condition it decides, each anchored to the clause that
/// owns that condition. The variant order is the sorted code order, so [`Self::ALL`]
/// is already the order a code registry requires, and no condition is reported under
/// another condition's code.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum StopDiagnosticCode {
    /// `stop-admission-after-closure`
    AdmissionAfterClosure,
    /// `stop-cause-conflict`
    CauseConflict,
    /// `stop-cohort-growth-after-closure`
    CohortGrowthAfterClosure,
    /// `stop-cooperative-observation-after-escalation`
    CooperativeObservationAfterEscalation,
    /// `stop-cut-regression`
    CutRegression,
    /// `stop-escalation-as-domain-outcome`
    EscalationAsDomainOutcome,
    /// `stop-escalation-before-grace-expiry`
    EscalationBeforeGraceExpiry,
    /// `stop-escalation-over-settled-outcome`
    EscalationOverSettledOutcome,
    /// `stop-escalation-without-stop-request`
    EscalationWithoutStopRequest,
    /// `stop-late-result`
    LateResult,
    /// `stop-non-claim-as-guarantee`
    NonClaimAsGuarantee,
    /// `stop-non-monotone-instant`
    NonMonotoneInstant,
    /// `stop-redeclared-grace`
    RedeclaredGrace,
    /// `stop-second-publication`
    SecondPublication,
    /// `stop-source-cleanup-after-escalation`
    SourceCleanupAfterEscalation,
    /// `stop-stale-owner-generation`
    StaleOwnerGeneration,
    /// `stop-terminated-coordinator`
    TerminatedCoordinator,
    /// `stop-termination-before-drain`
    TerminationBeforeDrain,
    /// `stop-undeclared-grace`
    UndeclaredGrace,
    /// `stop-unknown-spelling`
    UnknownSpelling,
    /// `stop-without-stop-request`
    WithoutStopRequest,
}

impl StopDiagnosticCode {
    /// Every frozen code, in sorted code order.
    pub const ALL: [Self; 21] = [
        Self::AdmissionAfterClosure,
        Self::CauseConflict,
        Self::CohortGrowthAfterClosure,
        Self::CooperativeObservationAfterEscalation,
        Self::CutRegression,
        Self::EscalationAsDomainOutcome,
        Self::EscalationBeforeGraceExpiry,
        Self::EscalationOverSettledOutcome,
        Self::EscalationWithoutStopRequest,
        Self::LateResult,
        Self::NonClaimAsGuarantee,
        Self::NonMonotoneInstant,
        Self::RedeclaredGrace,
        Self::SecondPublication,
        Self::SourceCleanupAfterEscalation,
        Self::StaleOwnerGeneration,
        Self::TerminatedCoordinator,
        Self::TerminationBeforeDrain,
        Self::UndeclaredGrace,
        Self::UnknownSpelling,
        Self::WithoutStopRequest,
    ];

    /// Returns the exact portable code spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::AdmissionAfterClosure => "stop-admission-after-closure",
            Self::CauseConflict => "stop-cause-conflict",
            Self::CohortGrowthAfterClosure => "stop-cohort-growth-after-closure",
            Self::CooperativeObservationAfterEscalation => {
                "stop-cooperative-observation-after-escalation"
            }
            Self::CutRegression => "stop-cut-regression",
            Self::EscalationAsDomainOutcome => "stop-escalation-as-domain-outcome",
            Self::EscalationBeforeGraceExpiry => "stop-escalation-before-grace-expiry",
            Self::EscalationOverSettledOutcome => "stop-escalation-over-settled-outcome",
            Self::EscalationWithoutStopRequest => "stop-escalation-without-stop-request",
            Self::LateResult => "stop-late-result",
            Self::NonClaimAsGuarantee => "stop-non-claim-as-guarantee",
            Self::NonMonotoneInstant => "stop-non-monotone-instant",
            Self::RedeclaredGrace => "stop-redeclared-grace",
            Self::SecondPublication => "stop-second-publication",
            Self::SourceCleanupAfterEscalation => "stop-source-cleanup-after-escalation",
            Self::StaleOwnerGeneration => "stop-stale-owner-generation",
            Self::TerminatedCoordinator => "stop-terminated-coordinator",
            Self::TerminationBeforeDrain => "stop-termination-before-drain",
            Self::UndeclaredGrace => "stop-undeclared-grace",
            Self::UnknownSpelling => "stop-unknown-spelling",
            Self::WithoutStopRequest => "stop-without-stop-request",
        }
    }

    /// Returns the same exact portable spelling as [`Self::wire_name`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.wire_name()
    }

    /// Returns the frozen one-line meaning of this code.
    #[must_use]
    pub const fn meaning(self) -> &'static str {
        match self {
            Self::AdmissionAfterClosure => {
                "admission of new application work was attempted after closure"
            }
            Self::CauseConflict => "a stop request cannot be joined to or supersede the held cause",
            Self::CohortGrowthAfterClosure => "the shutdown cohort was asked to grow after closure",
            Self::CooperativeObservationAfterEscalation => {
                "cooperative stop was observed after hard cancellation linearized"
            }
            Self::CutRegression => {
                "a durable stop cut was advanced backwards or over an uncommitted cut"
            }
            Self::EscalationAsDomainOutcome => {
                "hard cancellation was presented as a domain outcome"
            }
            Self::EscalationBeforeGraceExpiry => {
                "escalation was presented before the declared grace deadline"
            }
            Self::EscalationOverSettledOutcome => {
                "escalation was attempted over an already-settled outcome"
            }
            Self::EscalationWithoutStopRequest => {
                "escalation was attempted with no stop request held"
            }
            Self::LateResult => "a result arrived at or before the published outcome instant",
            Self::NonClaimAsGuarantee => "a stop non-claim was presented as a stop guarantee",
            Self::NonMonotoneInstant => {
                "a logical instant preceded the coordinator instant watermark"
            }
            Self::RedeclaredGrace => {
                "a joining or superseding request re-declared the grace and drain already in force"
            }
            Self::SecondPublication => "a task was asked to publish a second terminal outcome",
            Self::SourceCleanupAfterEscalation => {
                "source cleanup was admitted after hard cancellation"
            }
            Self::StaleOwnerGeneration => {
                "a result named an owner generation the task does not hold"
            }
            Self::TerminatedCoordinator => {
                "a stop transition was attempted on a terminated coordinator"
            }
            Self::TerminationBeforeDrain => "termination was attempted before the cohort closed",
            Self::UndeclaredGrace => "a grace or drain budget of zero was declared",
            Self::UnknownSpelling => {
                "a stop vocabulary member was spelled outside the closed vocabulary"
            }
            Self::WithoutStopRequest => {
                "a cooperative phase transition was attempted with no stop request held"
            }
        }
    }

    /// Returns the clause key that owns this condition.
    #[must_use]
    pub const fn requirement(self) -> &'static str {
        match self {
            Self::UnknownSpelling => "GNT-22.1-stop-request-identity-and-cause",
            Self::CauseConflict => "GNT-22.1-stop-request-identity-and-cause",
            Self::NonMonotoneInstant | Self::WithoutStopRequest => {
                "GNT-22.2-cooperative-stop-observation-and-propagation"
            }
            Self::AdmissionAfterClosure => "GNT-22.3-admission-closure-during-stop",
            Self::CooperativeObservationAfterEscalation => "GNT-22.4-safe-points-and-suspension",
            Self::CohortGrowthAfterClosure
            | Self::RedeclaredGrace
            | Self::TerminationBeforeDrain
            | Self::UndeclaredGrace => "GNT-22.5-grace-and-drain-ownership",
            Self::EscalationAsDomainOutcome
            | Self::EscalationBeforeGraceExpiry
            | Self::EscalationWithoutStopRequest
            | Self::SourceCleanupAfterEscalation => "GNT-22.6-grace-expiry-and-hard-cancellation",
            Self::EscalationOverSettledOutcome
            | Self::SecondPublication
            | Self::TerminatedCoordinator => "GNT-22.7-outcome-winner-and-single-publication",
            Self::CutRegression => "GNT-22.8-durable-stop-cuts-and-replay",
            Self::LateResult | Self::StaleOwnerGeneration => {
                "GNT-22.9-late-result-and-stale-generation-fencing"
            }
            Self::NonClaimAsGuarantee => "GNT-22.10-stop-non-claims",
        }
    }
}

/// One refusal of the cooperative-stop model.
///
/// Every refusal carries exactly one frozen [`StopDiagnosticCode`] and renders that
/// code first, so a diagnostic, an event, or a report names the clause that owns the
/// condition and no condition is reported under another condition's code.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StopError {
    /// Admission of new application work was attempted after closure.
    AdmissionAfterClosure {
        /// The logical instant of the attempted admission.
        at_us: u64,
    },
    /// A stop request cannot be joined to or supersede the held cause.
    CauseConflict {
        /// The cause the presented request declared.
        requested: StopCause,
        /// The cause the coordinator holds.
        held: StopCause,
    },
    /// The shutdown cohort was asked to grow after closure.
    CohortGrowthAfterClosure {
        /// The cohort size at closure.
        cohort: u64,
    },
    /// Cooperative stop was observed after hard cancellation linearized.
    CooperativeObservationAfterEscalation {
        /// The safe point that produced the refused observation.
        safe_point: SafePoint,
        /// The single escalation instant.
        escalated_at_us: u64,
    },
    /// A durable stop cut was advanced backwards or over an uncommitted cut.
    CutRegression {
        /// The committed cut.
        current: DurableStopCut,
        /// The refused successor cut.
        next: DurableStopCut,
    },
    /// Hard cancellation was presented as a domain outcome.
    EscalationAsDomainOutcome,
    /// Escalation was presented before the declared grace deadline.
    EscalationBeforeGraceExpiry {
        /// The deadline the held request declared.
        deadline_us: u64,
        /// The refused instant.
        presented_at_us: u64,
    },
    /// Escalation was attempted over an already-settled outcome.
    EscalationOverSettledOutcome {
        /// The outcome escalation would have overwritten.
        published: TaskOutcome,
    },
    /// Escalation was attempted with no stop request held.
    EscalationWithoutStopRequest,
    /// A result arrived at or before the published outcome instant.
    LateResult {
        /// The outcome already published.
        published: TaskOutcome,
        /// The logical instant that outcome was published at.
        published_at_us: u64,
        /// The logical instant the late result presented.
        presented_at_us: u64,
    },
    /// A stop non-claim was presented as a stop guarantee.
    NonClaimAsGuarantee {
        /// The non-claim that was presented as a guarantee.
        name: StopNonClaimName,
    },
    /// A logical instant preceded the coordinator instant watermark.
    NonMonotoneInstant {
        /// The refused instant.
        presented: u64,
        /// The watermark the coordinator holds.
        held: u64,
    },
    /// A joining or superseding request re-declared the grace and drain already in force.
    RedeclaredGrace {
        /// The budgets already declared.
        held: GracePolicy,
        /// The budgets the joining or superseding request presented.
        presented: GracePolicy,
    },
    /// A task was asked to publish a second terminal outcome.
    SecondPublication {
        /// The outcome already published.
        published: TaskOutcome,
    },
    /// Source cleanup was admitted after hard cancellation.
    SourceCleanupAfterEscalation {
        /// The refused cleanup step spelling.
        step: Arc<str>,
    },
    /// A result named an owner generation the task does not hold.
    StaleOwnerGeneration {
        /// The generation the result named.
        presented: OwnerGeneration,
        /// The generation the task holds.
        held: OwnerGeneration,
    },
    /// A stop transition was attempted on a terminated coordinator.
    TerminatedCoordinator,
    /// Termination was attempted before the cohort closed.
    TerminationBeforeDrain {
        /// The phase that refused the termination.
        phase: &'static str,
    },
    /// A grace or drain budget of zero was declared.
    UndeclaredGrace {
        /// The refused grace budget.
        grace_us: u64,
        /// The refused drain budget.
        drain_us: u64,
    },
    /// A stop vocabulary member was spelled outside the closed vocabulary.
    UnknownSpelling {
        /// The vocabulary that refused the spelling.
        vocabulary: &'static str,
        /// The refused spelling.
        spelling: Arc<str>,
    },
    /// A cooperative phase transition was attempted with no stop request held.
    WithoutStopRequest {
        /// The refused transition.
        transition: StopTransition,
    },
}

impl StopError {
    /// Returns the frozen stop code of this condition.
    #[must_use]
    pub const fn code(&self) -> StopDiagnosticCode {
        match self {
            Self::AdmissionAfterClosure { .. } => StopDiagnosticCode::AdmissionAfterClosure,
            Self::CauseConflict { .. } => StopDiagnosticCode::CauseConflict,
            Self::CohortGrowthAfterClosure { .. } => StopDiagnosticCode::CohortGrowthAfterClosure,
            Self::CooperativeObservationAfterEscalation { .. } => {
                StopDiagnosticCode::CooperativeObservationAfterEscalation
            }
            Self::CutRegression { .. } => StopDiagnosticCode::CutRegression,
            Self::EscalationAsDomainOutcome => StopDiagnosticCode::EscalationAsDomainOutcome,
            Self::EscalationBeforeGraceExpiry { .. } => {
                StopDiagnosticCode::EscalationBeforeGraceExpiry
            }
            Self::EscalationOverSettledOutcome { .. } => {
                StopDiagnosticCode::EscalationOverSettledOutcome
            }
            Self::EscalationWithoutStopRequest => StopDiagnosticCode::EscalationWithoutStopRequest,
            Self::LateResult { .. } => StopDiagnosticCode::LateResult,
            Self::NonClaimAsGuarantee { .. } => StopDiagnosticCode::NonClaimAsGuarantee,
            Self::NonMonotoneInstant { .. } => StopDiagnosticCode::NonMonotoneInstant,
            Self::RedeclaredGrace { .. } => StopDiagnosticCode::RedeclaredGrace,
            Self::SecondPublication { .. } => StopDiagnosticCode::SecondPublication,
            Self::SourceCleanupAfterEscalation { .. } => {
                StopDiagnosticCode::SourceCleanupAfterEscalation
            }
            Self::StaleOwnerGeneration { .. } => StopDiagnosticCode::StaleOwnerGeneration,
            Self::TerminatedCoordinator => StopDiagnosticCode::TerminatedCoordinator,
            Self::TerminationBeforeDrain { .. } => StopDiagnosticCode::TerminationBeforeDrain,
            Self::UndeclaredGrace { .. } => StopDiagnosticCode::UndeclaredGrace,
            Self::UnknownSpelling { .. } => StopDiagnosticCode::UnknownSpelling,
            Self::WithoutStopRequest { .. } => StopDiagnosticCode::WithoutStopRequest,
        }
    }

    /// Returns the requirement anchor that owns this condition.
    #[must_use]
    pub const fn requirement(&self) -> &'static str {
        self.code().requirement()
    }
}

impl fmt::Display for StopError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code().as_str())?;
        formatter.write_str(": ")?;
        match self {
            Self::AdmissionAfterClosure { at_us } => write!(
                formatter,
                "admission of new application work was attempted at logical instant {at_us} after closure"
            ),
            Self::CauseConflict { requested, held } => write!(
                formatter,
                "the requested cause `{}` conflicts with the held cause `{}`",
                requested.wire_name(),
                held.wire_name()
            ),
            Self::CohortGrowthAfterClosure { cohort } => write!(
                formatter,
                "the cohort of {cohort} members was asked to grow after closure"
            ),
            Self::CooperativeObservationAfterEscalation {
                safe_point,
                escalated_at_us,
            } => write!(
                formatter,
                "the safe point `{}` observed cooperative stop after escalation at logical instant {escalated_at_us}",
                safe_point.wire_name()
            ),
            Self::CutRegression { current, next } => write!(
                formatter,
                "the committed cut `{}` cannot advance to `{}`",
                current.wire_name(),
                next.wire_name()
            ),
            Self::EscalationAsDomainOutcome => formatter.write_str(
                "hard cancellation is published by the coordinator and never reported as a domain outcome",
            ),
            Self::EscalationBeforeGraceExpiry {
                deadline_us,
                presented_at_us,
            } => write!(
                formatter,
                "escalation at logical instant {presented_at_us} precedes the declared grace deadline {deadline_us}"
            ),
            Self::EscalationOverSettledOutcome { published } => write!(
                formatter,
                "the task already published `{}` and escalation never overwrites it",
                published.wire_name()
            ),
            Self::EscalationWithoutStopRequest => {
                formatter.write_str("escalation requires a held stop request")
            }
            Self::LateResult {
                published,
                published_at_us,
                presented_at_us,
            } => write!(
                formatter,
                "the outcome `{}` published at logical instant {published_at_us} is not replaced by a result presented at {presented_at_us}",
                published.wire_name()
            ),
            Self::NonClaimAsGuarantee { name } => write!(
                formatter,
                "`{}` is a non-claim of this section and never a guarantee",
                name.wire_name()
            ),
            Self::NonMonotoneInstant { presented, held } => write!(
                formatter,
                "logical instant {presented} precedes the held watermark {held}"
            ),
            Self::RedeclaredGrace { held, presented } => write!(
                formatter,
                "grace {} and drain {} are already in force and cannot be re-declared as grace {} and drain {}",
                held.grace_us(),
                held.drain_us(),
                presented.grace_us(),
                presented.drain_us()
            ),
            Self::SecondPublication { published } => write!(
                formatter,
                "the task already published `{}`",
                published.wire_name()
            ),
            Self::SourceCleanupAfterEscalation { step } => write!(
                formatter,
                "`{step}` is not admitted after hard cancellation"
            ),
            Self::StaleOwnerGeneration { presented, held } => write!(
                formatter,
                "owner generation {} is not the held owner generation {}",
                presented.value(),
                held.value()
            ),
            Self::TerminatedCoordinator => formatter.write_str(
                "the lifecycle already terminated and admits no further stop transition",
            ),
            Self::TerminationBeforeDrain { phase } => write!(
                formatter,
                "the `{phase}` phase cannot terminate before the cohort closes"
            ),
            Self::UndeclaredGrace { grace_us, drain_us } => write!(
                formatter,
                "grace {grace_us} and drain {drain_us} declare no budget"
            ),
            Self::UnknownSpelling {
                vocabulary,
                spelling,
            } => write!(
                formatter,
                "`{spelling}` is not a member of the closed {vocabulary} vocabulary"
            ),
            Self::WithoutStopRequest { transition } => write!(
                formatter,
                "`{}` requires a held stop request",
                transition.wire_name()
            ),
        }
    }
}

impl std::error::Error for StopError {}
