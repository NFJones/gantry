//! Pure wait, wakeup, arbitration, and quiescence model.
//!
//! This module is the machine-checked model for
//! `GNT-24.0-waits-wakeups-arbitration-and-quiescence`. It states the atomic
//! registration and readiness recheck of
//! `GNT-24.1-atomic-registration-and-readiness-recheck`, the waiter identity, owning
//! task, generation fence, and closed wake-cause set of
//! `GNT-24.2-wait-identity-and-generations`, wake ownership under
//! `GNT-24.3-wake-causes-and-wake-ownership`, stale-wake fencing and waiter reuse
//! under `GNT-24.4-stale-wake-fencing-and-waiter-reuse`, producer-loss closure under
//! `GNT-24.5-producer-loss-and-closure`, the snapshot and permanent winner of
//! `GNT-24.6-select-and-race-snapshots-and-winner-permanence`, losing-arm ownership
//! and the declared nondeterminism envelope of
//! `GNT-24.7-losing-arm-ownership-and-nondeterminism`, the five quiescence classes of
//! `GNT-24.8-quiescence-classification`, the durable wait cuts and reconstruction of
//! `GNT-24.9-durable-wait-and-winner-reconstruction`, and the explicit non-claims of
//! `GNT-24.10-wait-non-claims`.
//!
//! Scope is deliberately narrow. Every rule here is a pure function of its own
//! arguments: this module reads no clock, host path, environment variable, locale,
//! socket, process identifier, thread identity, or adapter handle, and it exposes no
//! constructor that accepts one. A waiter identity is derived from one declared
//! owning task, one declared waitable resource, the landed resource generation of
//! `GNT-20.2-logical-operation-and-resource-generation-identity`, one declared
//! registration ordinal, and the waiter-generation fence that registration holds, so
//! equal declared inputs produce equal identities and every verdict here is
//! reproducible from its own inputs. This module is not the interpreter, not an
//! executor, and not a scheduler: it decides the wait contract that those landed
//! components observe.
//!
//! Landed contracts are cited and reused rather than redeclared. The operation kinds,
//! receiver arrangement, progress observation, interruption, and late completion
//! remain those of `GNT-20.1` through `GNT-20.5`; the ambiguous-effect and
//! retry-eligibility classification remains that of `GNT-20.6`; the resource state
//! after failure, the half-close rules, and the adapter obligations remain those of
//! `GNT-20.7`, `GNT-20.8` and `GNT-20.11`; the owner generation and its stale-owner
//! fencing remain those of `GNT-20.10-retirement-and-stale-owner-fencing`;
//! cooperative stop and hard cancellation remain those of Section 22; the
//! cancellation rule remains that of `GNT-15.3`; the task lifecycle remains that of
//! `GNT-3-M-LIFECYCLES`; the shutdown operation, its cohort, and its finite graceful
//! timeout remain those of `GNT-10.12`, `GNT-10.13` and `GNT-10.14`; and protected
//! data and its protected diagnostics remain those of `GNT-15.10` and the landed
//! protection store, whose [`AuditAccess`] capability gates the rendering of a
//! protected wait-graph diagnostic.
//!
//! Four separations stay explicit.
//!
//! * Registration and the readiness recheck are one step. [`WaitRegistration`]
//!   publishes exactly one decision through
//!   [`WaitRegistration::register_and_recheck`], and
//!   [`WaitRegistration::admit_suspension`] admits a suspension only for the decision
//!   that step published, so a wake that linearizes at or before the step is consumed
//!   as readiness rather than lost between the check and the suspension.
//! * The waiter-generation fence is a registration fence, not a second generation
//!   vocabulary: [`WaitGeneration`] records which registration of one waiter slot a
//!   wake observes, while the owner generation and the resource generation remain the
//!   landed counters. [`WaitSet::wake`] refuses a wake that does not name the fence the
//!   live wait holds, and [`WaitSet::register`] refuses a registration whose ordinal or
//!   fence would move a slot backwards, so fencing and reuse are one-way.
//! * [`WakeOutcome`] holds at most one winner and [`WaitSet`] records at most one
//!   settlement per wait, so each wake has exactly one owner and a second wake is
//!   refused rather than becoming a second winner.
//! * [`Arbitration`], [`LosingArmSettlement`], and [`WakeOutcome`] are affine: none of
//!   them derives `Clone` or `Copy`, [`Arbitration::decide`] and
//!   [`Arbitration::into_losing_settlement`] consume the arbitration they act on, and
//!   [`LosingArmSettlement::settle`] consumes its dispositions, so one committed
//!   arbitration yields exactly one losing-arm settlement and every losing arm receives
//!   exactly one declared disposition.
//!
//! Three declared rules bound what this model decides and what it does not enforce.
//!
//! * [`classify_quiescence`] decides a class from the declared facts a caller presents:
//!   this model holds no wait graph of its own and observes no host prerequisite. A
//!   pending host prerequisite the type contract permits to remain pending is
//!   classified as externally wakeable idle and never as closed-wait deadlock, so this
//!   model reports no deadlock for genuinely pending external work.
//! * [`WaitGraphDiagnostic::new`] bounds the graph it reports by declared maxima and
//!   refuses a larger graph rather than truncating one, and
//!   [`WaitGraphDiagnostic::protected_text`] names the protected-diagnostic gate of
//!   `GNT-24.8`: enforcement of the audience is the host's, because this pure model
//!   grants no capability and audits no access.
//! * [`DurableWaitRecord::reattach`] reattaches only the external prerequisites the
//!   caller declares permitted, because the type contract that admits a prerequisite
//!   belongs to the caller that owns the wait; a presented prerequisite outside the
//!   permitted set is refused rather than reattached.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

use crate::authority::digest_fields;
use crate::manifest::encode_hex;
use crate::operation::ResourceGenerationId;
use crate::protected::AuditAccess;

/// The clause keys this model implements, in clause order.
///
/// Every diagnostic of this module names exactly one of these keys through
/// [`WaitDiagnosticCode::requirement`], so every refusal and every quiescence report
/// is attributable to the clause that owns it.
pub const WAIT_CLAUSES: [&str; 11] = [
    "GNT-24.0-waits-wakeups-arbitration-and-quiescence",
    "GNT-24.1-atomic-registration-and-readiness-recheck",
    "GNT-24.2-wait-identity-and-generations",
    "GNT-24.3-wake-causes-and-wake-ownership",
    "GNT-24.4-stale-wake-fencing-and-waiter-reuse",
    "GNT-24.5-producer-loss-and-closure",
    "GNT-24.6-select-and-race-snapshots-and-winner-permanence",
    "GNT-24.7-losing-arm-ownership-and-nondeterminism",
    "GNT-24.8-quiescence-classification",
    "GNT-24.9-durable-wait-and-winner-reconstruction",
    "GNT-24.10-wait-non-claims",
];

/// Domain separator for waiter-identity derivation
/// (`GNT-24.2-wait-identity-and-generations`).
///
/// The separator is distinct from every other identity domain of this crate, so a
/// waiter identity is never equal to a stop-request, resource-generation, or symbol
/// identity that happens to share a spelling of its inputs.
const WAIT_IDENTITY_DOMAIN: &str = "gantry.wait-identity/v1";

/// Declared maximum node count of one wait-graph diagnostic
/// (`GNT-24.8-quiescence-classification`).
pub const WAIT_GRAPH_MAX_NODES: usize = 256;

/// Declared maximum edge count of one wait-graph diagnostic
/// (`GNT-24.8-quiescence-classification`).
pub const WAIT_GRAPH_MAX_EDGES: usize = 1024;

/// One declared identity input of this model.
///
/// The vocabulary is closed and each member owns its own diagnostic, so a refusal that
/// names an input names exactly one of these and never an unspecified field.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum IdentityInput {
    /// The owning task identity of one wait.
    Owner,
    /// The waitable-resource identity of one wait.
    Resource,
    /// One arbitration arm key.
    Arm,
    /// One external prerequisite key.
    Prerequisite,
}

impl IdentityInput {
    /// Every member of the closed vocabulary, in declaration order.
    pub const ALL: [Self; 4] = [Self::Owner, Self::Resource, Self::Arm, Self::Prerequisite];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Resource => "resource",
            Self::Arm => "arm",
            Self::Prerequisite => "prerequisite",
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

    /// Returns the clause anchor that owns an empty declared input of this kind.
    #[must_use]
    pub const fn requirement(self) -> &'static str {
        match self {
            Self::Owner | Self::Resource => "GNT-24.2-wait-identity-and-generations",
            Self::Arm => "GNT-24.6-select-and-race-snapshots-and-winner-permanence",
            Self::Prerequisite => "GNT-24.9-durable-wait-and-winner-reconstruction",
        }
    }
}

/// One stable owning-task identity of one wait (`GNT-24.2-wait-identity-and-generations`).
///
/// The identity is the declared task identity text of the landed task lifecycle of
/// `GNT-3-M-LIFECYCLES`: it is not a thread, a process, or an execution context, and
/// no host fact enters it.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct WaitOwnerId {
    text: Arc<str>,
}

impl WaitOwnerId {
    /// Constructs one owning-task identity from its declared task identity.
    ///
    /// # Errors
    ///
    /// Returns [`WaitError::EmptyDeclaredIdentity`] when the declared text is empty or
    /// whitespace only, because an unnamed owner could not attribute a wait to a task.
    pub fn new(task: &str) -> Result<Self, WaitError> {
        Ok(Self {
            text: declared_text(task, IdentityInput::Owner)?,
        })
    }

    /// Returns the exact portable identity spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }
}

impl fmt::Display for WaitOwnerId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.text)
    }
}

/// One declared waitable-resource identity of one wait
/// (`GNT-24.2-wait-identity-and-generations`).
///
/// The identity names the awaited value, operation, or resource of Section 20 and never
/// a host handle, a path, or a socket.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct WaitResourceId {
    text: Arc<str>,
}

impl WaitResourceId {
    /// Constructs one waitable-resource identity from its declared resource identity.
    ///
    /// # Errors
    ///
    /// Returns [`WaitError::EmptyDeclaredIdentity`] when the declared text is empty or
    /// whitespace only.
    pub fn new(resource: &str) -> Result<Self, WaitError> {
        Ok(Self {
            text: declared_text(resource, IdentityInput::Resource)?,
        })
    }

    /// Returns the exact portable identity spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }
}

impl fmt::Display for WaitResourceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.text)
    }
}

/// One declared external prerequisite key
/// (`GNT-24.9-durable-wait-and-winner-reconstruction`).
///
/// The key names one external prerequisite the type contract of the awaited value
/// admits, so recovery can decide from declared values whether a presented prerequisite
/// may be reattached. It carries no host handle and no payload.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PrerequisiteRef {
    text: Arc<str>,
}

impl PrerequisiteRef {
    /// Constructs one external prerequisite key from its declared identity.
    ///
    /// # Errors
    ///
    /// Returns [`WaitError::EmptyDeclaredIdentity`] when the declared text is empty or
    /// whitespace only.
    pub fn new(key: &str) -> Result<Self, WaitError> {
        Ok(Self {
            text: declared_text(key, IdentityInput::Prerequisite)?,
        })
    }

    /// Returns the exact portable key spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }
}

impl fmt::Display for PrerequisiteRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.text)
    }
}

/// The generation fence of one waiter slot (`GNT-24.2-wait-identity-and-generations`).
///
/// The fence is monotone per waiter slot and is not a second generation vocabulary: the
/// owner generation of `GNT-20.10-retirement-and-stale-owner-fencing` and the resource
/// generation of `GNT-20.2-logical-operation-and-resource-generation-identity` remain
/// the landed counters, and the fence only records which registration of one waiter
/// slot a wake observes. Fencing is one-way: a retired fence is never revived and a
/// slot never returns to an earlier fence, so a stale or duplicate wake can never
/// resume a reused waiter, task, or resource generation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct WaitGeneration(u64);

impl WaitGeneration {
    /// The first fence of a fresh waiter slot.
    pub const FIRST: Self = Self(1);

    /// Returns the explicit fence value.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }

    /// Returns the next fence of the same slot.
    ///
    /// # Errors
    ///
    /// Returns [`WaitError::GenerationExhausted`] at the counter maximum rather than
    /// wrapping, because a wrapped fence would let a stale wake observe a live wait.
    pub const fn succeeding(self) -> Result<Self, WaitError> {
        match self.0.checked_add(1) {
            Some(value) => Ok(Self(value)),
            None => Err(WaitError::GenerationExhausted { generation: self }),
        }
    }

    /// Returns whether a slot that holds this fence has already retired `presented`.
    #[must_use]
    pub const fn retires(self, presented: Self) -> bool {
        presented.0 <= self.0
    }

    /// Returns whether this fence observes exactly the held fence.
    #[must_use]
    pub const fn observes(self, held: Self) -> bool {
        self.0 == held.0
    }
}

impl fmt::Display for WaitGeneration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

/// One stable waiter identity (`GNT-24.2-wait-identity-and-generations`).
///
/// The identity is a domain-separated SHA-256 digest over one declared owning task, one
/// declared waitable resource, the landed resource generation, and one declared
/// registration ordinal. No process identifier, thread identity, clock reading, host
/// path, environment fact, locale, socket, or adapter handle participates, so equal
/// declared inputs always produce equal identities and two waits that differ in any
/// declared input are distinct identities. There is no free constructor and no
/// deserializer: a waiter identity is obtainable only from [`WaitId::derive`].
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct WaitId {
    text: Arc<str>,
}

impl WaitId {
    /// Derives one waiter identity under its own domain separator.
    ///
    /// `registration` is the declared ordinal of the waiter slot, so a slot that is
    /// reused after settlement derives a distinct identity even when the owner, the
    /// resource, and the resource generation are unchanged.
    #[must_use]
    pub fn derive(
        owner: &WaitOwnerId,
        resource: &WaitResourceId,
        resource_generation: &ResourceGenerationId,
        generation: WaitGeneration,
        registration: u32,
    ) -> Self {
        let digest = digest_fields(
            WAIT_IDENTITY_DOMAIN,
            &[
                owner.as_str().as_bytes(),
                resource.as_str().as_bytes(),
                resource_generation.as_str().as_bytes(),
                &generation.value().to_be_bytes(),
                &u64::from(registration).to_be_bytes(),
            ],
        );
        Self {
            text: Arc::from(format!("wait:{}", encode_hex(&digest))),
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
        self.text.strip_prefix("wait:").unwrap_or(&self.text)
    }
}

impl fmt::Display for WaitId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.text)
    }
}

/// One wake cause of the closed wake-cause vocabulary
/// (`GNT-24.3-wake-causes-and-wake-ownership`).
///
/// The vocabulary is exactly five causes: delivery, resource closure, cancellation, a
/// stop request, and timeout. Delivery is a send, a task settlement, or an operation
/// completion; a stop request is the cooperative stop request of
/// `GNT-22.1-stop-request-identity-and-cause`, which stays distinct from cancellation.
/// Each has one frozen spelling, one frozen meaning, and one declared rank, and no
/// clause of Section 24 introduces a sixth cause or a cause inferred from a payload.
/// Waiter removal by the owner is a withdrawal rather than a wake cause, so it is not a
/// member of this vocabulary.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum WakeCause {
    /// A send, a task settlement, or an operation completion under Section 20.
    Delivery,
    /// The awaited resource closed under `GNT-20.7` and `GNT-20.8`.
    ResourceClosure,
    /// The landed cancellation of `GNT-15.3` or of Section 22.
    Cancellation,
    /// The cooperative stop request of `GNT-22.1`, distinct from cancellation.
    StopRequest,
    /// A declared wait deadline, in logical microseconds, expired.
    Timeout,
}

impl WakeCause {
    /// Every member of the closed vocabulary, in declared rank order.
    pub const ALL: [Self; 5] = [
        Self::Delivery,
        Self::ResourceClosure,
        Self::Cancellation,
        Self::StopRequest,
        Self::Timeout,
    ];

    /// Returns the exact frozen spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Delivery => "delivery",
            Self::ResourceClosure => "resource-closure",
            Self::Cancellation => "cancellation",
            Self::StopRequest => "stop-request",
            Self::Timeout => "timeout",
        }
    }

    /// Returns the same exact frozen spelling as [`Self::wire_name`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.wire_name()
    }

    /// Strictly decodes one exact frozen spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.wire_name() == value)
    }

    /// Returns the frozen one-line meaning of this cause.
    #[must_use]
    pub const fn meaning(self) -> &'static str {
        match self {
            Self::Delivery => {
                "a send, a task settlement, or an operation completion under Section 20"
            }
            Self::ResourceClosure => "the awaited resource closed under GNT-20.7 and GNT-20.8",
            Self::Cancellation => {
                "the landed cancellation of GNT-15.3 or of Section 22 settled the wait"
            }
            Self::StopRequest => {
                "the cooperative stop request of GNT-22.1 was observed, distinct from cancellation"
            }
            Self::Timeout => "a declared wait deadline in logical microseconds expired",
        }
    }

    /// Returns the declared rank of this cause, used for deterministic settlement order.
    #[must_use]
    pub const fn rank(self) -> u8 {
        match self {
            Self::Delivery => 0,
            Self::ResourceClosure => 1,
            Self::Cancellation => 2,
            Self::StopRequest => 3,
            Self::Timeout => 4,
        }
    }

    /// Returns the clause anchor that owns this cause.
    #[must_use]
    pub const fn requirement(self) -> &'static str {
        "GNT-24.3-wake-causes-and-wake-ownership"
    }
}

impl fmt::Display for WakeCause {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.wire_name())
    }
}

/// Returns one declared identity text, refusing an empty or blank one.
fn declared_text(value: &str, input: IdentityInput) -> Result<Arc<str>, WaitError> {
    if value.trim().is_empty() {
        return Err(WaitError::EmptyDeclaredIdentity { input });
    }
    Ok(Arc::from(value))
}

/// One readiness recheck observation of one waitable resource
/// (`GNT-24.1-atomic-registration-and-readiness-recheck`).
///
/// The recheck reports one member of the closed wake-cause set of
/// `GNT-24.3-wake-causes-and-wake-ownership`, so the wake that linearizes at or before
/// the atomic step is published as readiness rather than lost. A send, a task
/// settlement, and an operation completion are all the delivery cause; a stop request of
/// `GNT-22.1-stop-request-identity-and-cause` is the stop-request cause; a close is the
/// resource-closure cause; a cancellation of `GNT-15.3` is the cancellation cause; and a
/// timer firing is the timeout cause. There is no sixth observation and no observation
/// outside this set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadinessObservation {
    /// The recheck observed no pending wake.
    NotReady,
    /// The recheck observed a pending wake of the given cause.
    Ready(WakeCause),
}

impl ReadinessObservation {
    /// Returns the observed cause, if the recheck observed one.
    #[must_use]
    pub const fn cause(self) -> Option<WakeCause> {
        match self {
            Self::NotReady => None,
            Self::Ready(cause) => Some(cause),
        }
    }

    /// Returns whether the recheck observed a pending wake.
    #[must_use]
    pub const fn is_ready(self) -> bool {
        matches!(self, Self::Ready(_))
    }
}

/// The single decision one atomic registration and readiness recheck publishes
/// (`GNT-24.1-atomic-registration-and-readiness-recheck`).
///
/// One step decides exactly one of the two members, so there is no declared state in
/// which a waiter is registered and the resource has not been rechecked against it, and
/// no declared state in which the resource has been rechecked and the waiter is not yet
/// registered.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistrationOutcome {
    /// The wait is registered, so every later wake is delivered to a live waiter.
    Registered,
    /// The wait is already ready, so the wake consumed at the same step is not lost.
    AlreadyReady(WakeCause),
}

impl RegistrationOutcome {
    /// Returns whether the step registered the wait.
    #[must_use]
    pub const fn is_registered(self) -> bool {
        matches!(self, Self::Registered)
    }

    /// Returns the readiness cause the step observed, if any.
    #[must_use]
    pub const fn ready_cause(self) -> Option<WakeCause> {
        match self {
            Self::Registered => None,
            Self::AlreadyReady(cause) => Some(cause),
        }
    }

    /// Returns the clause anchor that owns this decision.
    #[must_use]
    pub const fn requirement(self) -> &'static str {
        "GNT-24.1-atomic-registration-and-readiness-recheck"
    }
}

/// The published state of one atomic registration decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RegistrationState {
    /// The step has not run, so no decision exists.
    Unregistered,
    /// The step registered the wait.
    Registered,
    /// The step decided that the wait was already ready.
    Ready(WakeCause),
}

/// One wait registration (`GNT-24.1-atomic-registration-and-readiness-recheck`).
///
/// The registration carries the waiter identity, the owning task, the waitable resource,
/// the landed resource generation of `GNT-20.2`, the waiter-generation fence, and the
/// declared registration ordinal of the waiter slot, and it publishes exactly one
/// decision. Registration and the readiness recheck are reachable only through
/// [`Self::register_and_recheck`], so a caller cannot take a readiness observation
/// without registering and cannot register without rechecking, and [`WaitSet::register`]
/// refuses a registration whose ordinal or fence does not move the slot forward, so reuse
/// can only move forward.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WaitRegistration {
    id: WaitId,
    owner: WaitOwnerId,
    resource: WaitResourceId,
    resource_generation: ResourceGenerationId,
    generation: WaitGeneration,
    ordinal: u32,
    state: RegistrationState,
}

impl WaitRegistration {
    /// Constructs one undecided wait registration.
    ///
    /// `ordinal` is the declared registration ordinal of the waiter slot, the same value
    /// the waiter identity is derived from, so
    /// `GNT-24.4-stale-wake-fencing-and-waiter-reuse` can refuse a registration that would
    /// return a reused slot to an earlier ordinal.
    #[must_use]
    pub fn new(
        id: WaitId,
        owner: WaitOwnerId,
        resource: WaitResourceId,
        resource_generation: ResourceGenerationId,
        generation: WaitGeneration,
        ordinal: u32,
    ) -> Self {
        Self {
            id,
            owner,
            resource,
            resource_generation,
            generation,
            ordinal,
            state: RegistrationState::Unregistered,
        }
    }

    /// Returns the stable waiter identity.
    #[must_use]
    pub const fn id(&self) -> &WaitId {
        &self.id
    }

    /// Returns the owning task identity.
    #[must_use]
    pub const fn owner(&self) -> &WaitOwnerId {
        &self.owner
    }

    /// Returns the waitable-resource identity.
    #[must_use]
    pub const fn resource(&self) -> &WaitResourceId {
        &self.resource
    }

    /// Returns the landed resource generation the wait observes.
    #[must_use]
    pub const fn resource_generation(&self) -> &ResourceGenerationId {
        &self.resource_generation
    }

    /// Returns the waiter-generation fence of this registration.
    #[must_use]
    pub const fn generation(&self) -> WaitGeneration {
        self.generation
    }

    /// Returns the declared registration ordinal of the waiter slot.
    #[must_use]
    pub const fn ordinal(&self) -> u32 {
        self.ordinal
    }

    /// Returns whether the atomic step published registration.
    #[must_use]
    pub const fn is_registered(&self) -> bool {
        matches!(self.state, RegistrationState::Registered)
    }

    /// Returns the readiness cause the atomic step observed, if any.
    #[must_use]
    pub const fn ready_cause(&self) -> Option<WakeCause> {
        match self.state {
            RegistrationState::Ready(cause) => Some(cause),
            RegistrationState::Unregistered | RegistrationState::Registered => None,
        }
    }

    /// Registers the waiter and rechecks the resource in one atomic step.
    ///
    /// The step publishes exactly one of the two members of [`RegistrationOutcome`]. A
    /// wake that linearizes at or before the step is observed as readiness and consumed
    /// by the step, so it is not lost between the check and the suspension; a wake that
    /// linearizes after the step is delivered to the registered waiter.
    ///
    /// # Errors
    ///
    /// Returns [`WaitError::RegistrationAlreadyDecided`] when this registration already
    /// published a decision, because one wait has exactly one atomic step and a second
    /// registration would give one waiter two decisions.
    pub fn register_and_recheck(
        &mut self,
        observation: ReadinessObservation,
    ) -> Result<RegistrationOutcome, WaitError> {
        if self.state != RegistrationState::Unregistered {
            return Err(WaitError::RegistrationAlreadyDecided {
                wait: self.id.clone(),
            });
        }
        match observation {
            ReadinessObservation::NotReady => {
                self.state = RegistrationState::Registered;
                Ok(RegistrationOutcome::Registered)
            }
            ReadinessObservation::Ready(cause) => {
                self.state = RegistrationState::Ready(cause);
                Ok(RegistrationOutcome::AlreadyReady(cause))
            }
        }
    }

    /// Admits a suspension of source for this registration.
    ///
    /// # Errors
    ///
    /// Returns [`WaitError::SuspensionWithoutRecheck`] when the atomic step has not run,
    /// because suspending without the step would leave a wake with no waiter, and
    /// [`WaitError::SuspensionAfterReadiness`] when the step decided that the wait was
    /// already ready, because suspending then would lose the wake the step observed.
    pub fn admit_suspension(&self) -> Result<(), WaitError> {
        match self.state {
            RegistrationState::Unregistered => Err(WaitError::SuspensionWithoutRecheck {
                wait: self.id.clone(),
            }),
            RegistrationState::Registered => Ok(()),
            RegistrationState::Ready(cause) => Err(WaitError::SuspensionAfterReadiness {
                wait: self.id.clone(),
                cause,
            }),
        }
    }
}

/// The single source-visible outcome of one wait
/// (`GNT-24.3-wake-causes-and-wake-ownership`).
///
/// The outcome holds at most one winner. The first admissible wake fixes it, a later
/// wake is refused as a second wake rather than becoming a second winner, and no wake is
/// ever owned by two waits. The outcome is affine: it derives no `Clone` and no `Copy`, so
/// one wait yields exactly one settled outcome and that outcome is never duplicated.
#[derive(Debug, Eq, PartialEq)]
pub struct WakeOutcome {
    wait: WaitId,
    owner: WaitOwnerId,
    generation: WaitGeneration,
    winner: Option<WakeCause>,
}

impl WakeOutcome {
    /// Opens the outcome of one decided registration.
    ///
    /// A registration whose atomic step decided that the wait was already ready opens
    /// with that cause as its winner, because the wake was consumed at the step.
    ///
    /// # Errors
    ///
    /// Returns [`WaitError::SuspensionWithoutRecheck`] when the registration has not run
    /// its atomic step, because a wait with no decision has no outcome to open.
    pub fn pending(registration: &WaitRegistration) -> Result<Self, WaitError> {
        if registration.state == RegistrationState::Unregistered {
            return Err(WaitError::SuspensionWithoutRecheck {
                wait: registration.id.clone(),
            });
        }
        Ok(Self {
            wait: registration.id.clone(),
            owner: registration.owner.clone(),
            generation: registration.generation,
            winner: registration.ready_cause(),
        })
    }

    /// Delivers one wake to this outcome and returns the single winner.
    ///
    /// # Errors
    ///
    /// Returns [`WaitError::SecondWake`] when this outcome already holds a winner. The
    /// refusal mutates nothing, so the recorded winner is never replaced, reclassified,
    /// or merged.
    pub fn wake(&mut self, cause: WakeCause) -> Result<WakeCause, WaitError> {
        if let Some(held) = self.winner {
            return Err(WaitError::SecondWake {
                wait: self.wait.clone(),
                held: self.generation,
                presented: self.generation,
                winner: held,
                repeated: cause,
            });
        }
        self.winner = Some(cause);
        Ok(cause)
    }

    /// Returns the single winner, if the outcome is settled.
    #[must_use]
    pub const fn winner(&self) -> Option<WakeCause> {
        self.winner
    }

    /// Returns the single winner, refusing an unsettled outcome.
    ///
    /// # Errors
    ///
    /// Returns [`WaitError::NoWinnerYet`] when no wake has settled this outcome.
    pub fn require_winner(&self) -> Result<WakeCause, WaitError> {
        self.winner.ok_or_else(|| WaitError::NoWinnerYet {
            wait: self.wait.clone(),
        })
    }

    /// Returns whether a wake settled this outcome.
    #[must_use]
    pub const fn is_settled(&self) -> bool {
        self.winner.is_some()
    }

    /// Returns the waiter identity this outcome belongs to.
    #[must_use]
    pub const fn wait(&self) -> &WaitId {
        &self.wait
    }

    /// Returns the owning task identity of this outcome.
    #[must_use]
    pub const fn owner(&self) -> &WaitOwnerId {
        &self.owner
    }

    /// Returns the waiter-generation fence of this outcome.
    #[must_use]
    pub const fn generation(&self) -> WaitGeneration {
        self.generation
    }
}

/// One settled wake of one wait (`GNT-24.3-wake-causes-and-wake-ownership`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WakeRecord {
    wait: WaitId,
    generation: WaitGeneration,
    cause: WakeCause,
}

/// One recorded withdrawal of one wait by its own owner
/// (`GNT-24.5-producer-loss-and-closure`).
///
/// A withdrawal is not a wake: it retires the fence the wait held and removes the wait
/// from the live set without reporting a wake cause, because the closed cause set of
/// `GNT-24.3-wake-causes-and-wake-ownership` holds exactly delivery, resource closure,
/// cancellation, a stop request, and timeout. The record keeps the withdrawal observable,
/// so an owner that removes a wait leaves a classified outcome rather than a dropped one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WithdrawalRecord {
    wait: WaitId,
    generation: WaitGeneration,
}

impl WithdrawalRecord {
    /// Returns the waiter identity this withdrawal retired.
    #[must_use]
    pub const fn wait(&self) -> &WaitId {
        &self.wait
    }

    /// Returns the waiter-generation fence this withdrawal retired.
    #[must_use]
    pub const fn generation(&self) -> WaitGeneration {
        self.generation
    }

    /// Returns the clause anchor that owns this withdrawal.
    #[must_use]
    pub const fn requirement(&self) -> &'static str {
        "GNT-24.5-producer-loss-and-closure"
    }
}

impl WakeRecord {
    /// Returns the waiter identity this wake settled.
    #[must_use]
    pub const fn wait(&self) -> &WaitId {
        &self.wait
    }

    /// Returns the waiter-generation fence the wake observed.
    #[must_use]
    pub const fn generation(&self) -> WaitGeneration {
        self.generation
    }

    /// Returns the cause of this wake.
    #[must_use]
    pub const fn cause(&self) -> WakeCause {
        self.cause
    }
}

/// The report of one resource closure (`GNT-24.5-producer-loss-and-closure`).
///
/// A caller can decide the outcome of every dependent wait from the two sets: the waits
/// this closure settled, and the waits an earlier cause had already settled and this
/// closure preserved without rewrite. Ordering within each set is declared: owning task,
/// then generation fence, then waiter identity. The report names the landed resource
/// generation it closed, because closure is keyed by the waitable-resource identity and
/// that generation together.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClosureReport {
    resource: WaitResourceId,
    generation: ResourceGenerationId,
    closed: Vec<WakeRecord>,
    preserved: Vec<WakeRecord>,
}

impl ClosureReport {
    /// Returns the resource identity this closure closed.
    #[must_use]
    pub const fn resource(&self) -> &WaitResourceId {
        &self.resource
    }

    /// Returns the landed resource generation this closure closed.
    #[must_use]
    pub const fn generation(&self) -> &ResourceGenerationId {
        &self.generation
    }

    /// Returns the waits this closure settled, in declared order.
    #[must_use]
    pub fn closed(&self) -> &[WakeRecord] {
        &self.closed
    }

    /// Returns the waits an earlier cause settled and this closure preserved.
    #[must_use]
    pub fn preserved(&self) -> &[WakeRecord] {
        &self.preserved
    }

    /// Returns whether every wait of the closed resource is classified.
    #[must_use]
    pub fn is_classified(&self) -> bool {
        self.closed
            .iter()
            .all(|record| record.cause == WakeCause::ResourceClosure)
    }
}

/// The waiter-slot key of one registered wait: its owning task and its waitable resource.
type SlotKey = (WaitOwnerId, WaitResourceId);

/// The live wait of one waiter slot.
#[derive(Clone, Debug, Eq, PartialEq)]
struct LiveWait {
    /// The waiter identity of the live wait.
    id: WaitId,
    /// The waiter-generation fence the live wait holds.
    fence: WaitGeneration,
    /// The declared registration ordinal of the live wait.
    ordinal: u32,
    /// The landed resource generation the live wait observes.
    resource_generation: ResourceGenerationId,
}

/// The live state of one waiter slot.
#[derive(Clone, Debug, Default)]
struct Slot {
    /// The live wait of this slot.
    live: Option<LiveWait>,
    /// The highest fence this slot has retired, if any.
    highest_retired: Option<WaitGeneration>,
    /// The highest registration ordinal this slot has retired, if any.
    highest_retired_ordinal: Option<u32>,
}

/// The resolved state of one wake or withdrawal target under
/// `GNT-24.4-stale-wake-fencing-and-waiter-reuse`.
///
/// Resolution is the one place the fencing checks of that clause are applied in their
/// declared order, so a wake and a withdrawal classify an addressed waiter identically and
/// a refusal mutates nothing.
#[derive(Clone, Debug, Eq, PartialEq)]
enum TargetResolution {
    /// The addressed wait was live under the presented fence and is now retired.
    Retired,
    /// The addressed wait already holds the winner of a wake applied to it.
    Duplicate(WakeRecord),
    /// The wait set never held the addressed waiter identity.
    Unknown,
    /// The presented fence is retired, or is not the fence the live wait holds.
    Stale {
        /// The fence the wait set holds for the addressed waiter slot.
        held: WaitGeneration,
    },
}

/// The live waits of one wait domain
/// (`GNT-24.4-stale-wake-fencing-and-waiter-reuse`,
/// `GNT-24.5-producer-loss-and-closure`).
///
/// The set tracks one live wait and its fence per waiter slot, the highest fence and the
/// highest registration ordinal each slot has retired, the recorded settlement or
/// withdrawal of each wait, and the closed waitable-resource generations. A wake is
/// admissible only against a live wait that holds the presented fence, a registration
/// never moves a slot backwards in ordinal or fence, and closure settles every live wait
/// of the resource generation it names, so a wait is never left permanently
/// unclassifiable. The closed set is keyed by the waitable-resource identity **and** the
/// landed resource generation of
/// `GNT-20.2-logical-operation-and-resource-generation-identity` that the registration
/// carries, so a closure of one generation never settles a wait of another.
#[derive(Debug, Default)]
pub struct WaitSet {
    slots: BTreeMap<SlotKey, Slot>,
    index: BTreeMap<WaitId, (SlotKey, ResourceGenerationId)>,
    settlements: BTreeMap<WaitId, WakeRecord>,
    withdrawals: BTreeMap<WaitId, WithdrawalRecord>,
    closed: BTreeSet<(WaitResourceId, ResourceGenerationId)>,
}

impl WaitSet {
    /// Creates one empty wait set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Admits one registered wait whose atomic step published registration.
    ///
    /// # Errors
    ///
    /// Returns [`WaitError::DuplicateWaiter`] when the slot already holds a live wait,
    /// [`WaitError::RegistrationAfterClosure`] when the waited resource generation is
    /// closed, [`WaitError::RegistrationOrdinalRegression`] when the presented ordinal is
    /// not strictly greater than the ordinal the slot already retired,
    /// [`WaitError::StaleRegistration`] when the presented fence is one the slot already
    /// retired, [`WaitError::SuspensionAfterReadiness`] when the atomic step decided that
    /// the wait was already ready and must therefore be consumed rather than registered,
    /// and [`WaitError::SuspensionWithoutRecheck`] when the atomic step has not run. Every
    /// refusal mutates nothing, so a refused registration leaves the retired ordinal and
    /// the retired fence of the slot exactly as they were.
    pub fn register(&mut self, registration: &WaitRegistration) -> Result<(), WaitError> {
        let id = registration.id.clone();
        if !registration.is_registered() {
            return Err(match registration.ready_cause() {
                Some(cause) => WaitError::SuspensionAfterReadiness { wait: id, cause },
                None => WaitError::SuspensionWithoutRecheck { wait: id },
            });
        }
        if self.closed.contains(&(
            registration.resource().clone(),
            registration.resource_generation().clone(),
        )) {
            return Err(WaitError::RegistrationAfterClosure {
                wait: id,
                resource: registration.resource().clone(),
            });
        }
        let key = (
            registration.owner().clone(),
            registration.resource().clone(),
        );
        let generation = registration.generation();
        let ordinal = registration.ordinal();
        let slot = self.slots.entry(key.clone()).or_default();
        if slot.live.is_some() {
            return Err(WaitError::DuplicateWaiter { wait: id });
        }
        if let Some(retired) = slot.highest_retired_ordinal
            && ordinal <= retired
        {
            return Err(WaitError::RegistrationOrdinalRegression {
                wait: id,
                retired,
                presented: ordinal,
            });
        }
        if let Some(retired) = slot.highest_retired
            && retired.retires(generation)
        {
            return Err(WaitError::StaleRegistration {
                wait: id,
                held: retired,
                presented: generation,
            });
        }
        slot.live = Some(LiveWait {
            id: id.clone(),
            fence: generation,
            ordinal,
            resource_generation: registration.resource_generation().clone(),
        });
        self.index
            .insert(id, (key, registration.resource_generation().clone()));
        Ok(())
    }

    /// Delivers one wake naming one waiter identity and one fence.
    ///
    /// # Errors
    ///
    /// Returns [`WaitError::UnknownWaiter`] when the set never held this waiter,
    /// [`WaitError::StaleWake`] when the addressed waiter is not the live waiter of its
    /// slot or the presented fence is not the fence that wait holds, including a fence the
    /// slot already retired and the fence of a reused slot's predecessor, and
    /// [`WaitError::SecondWake`] when the addressed wait already holds the winner of a
    /// wake already applied to it. Every refusal mutates nothing, and every refusal names
    /// the waiter, the held fence, and the presented fence.
    pub fn wake(
        &mut self,
        id: &WaitId,
        generation: WaitGeneration,
        cause: WakeCause,
    ) -> Result<WakeRecord, WaitError> {
        match self.resolve_target(id, generation) {
            TargetResolution::Retired => {
                let record = WakeRecord {
                    wait: id.clone(),
                    generation,
                    cause,
                };
                self.settlements.insert(id.clone(), record.clone());
                Ok(record)
            }
            TargetResolution::Duplicate(record) => Err(WaitError::SecondWake {
                wait: id.clone(),
                held: record.generation,
                presented: generation,
                winner: record.cause,
                repeated: cause,
            }),
            TargetResolution::Unknown => Err(WaitError::UnknownWaiter {
                wait: id.clone(),
                held: None,
                presented: generation,
            }),
            TargetResolution::Stale { held } => Err(WaitError::StaleWake {
                wait: id.clone(),
                held,
                presented: generation,
            }),
        }
    }

    /// Removes one wait at the request of its own owner, as a withdrawal.
    ///
    /// Removal is a withdrawal rather than a wake: the wait is retired, removed from the
    /// live set, and recorded as a [`WithdrawalRecord`] instead of reporting a member of
    /// the closed wake-cause set of `GNT-24.3-wake-causes-and-wake-ownership`, so an owner
    /// that removes a wait leaves a classified outcome and no wake is reported under a
    /// sixth cause.
    ///
    /// # Errors
    ///
    /// Returns [`WaitError::UnknownWaiter`] when the set never held this waiter, and
    /// [`WaitError::StaleWake`] when the addressed wait is not live under the presented
    /// fence, including a wait that already holds a winner, because a retired fence is
    /// never revived.
    pub fn remove_waiter(
        &mut self,
        id: &WaitId,
        generation: WaitGeneration,
    ) -> Result<WithdrawalRecord, WaitError> {
        match self.resolve_target(id, generation) {
            TargetResolution::Retired => {
                let record = WithdrawalRecord {
                    wait: id.clone(),
                    generation,
                };
                self.withdrawals.insert(id.clone(), record.clone());
                Ok(record)
            }
            TargetResolution::Duplicate(record) => Err(WaitError::StaleWake {
                wait: id.clone(),
                held: record.generation,
                presented: generation,
            }),
            TargetResolution::Unknown => Err(WaitError::UnknownWaiter {
                wait: id.clone(),
                held: None,
                presented: generation,
            }),
            TargetResolution::Stale { held } => Err(WaitError::StaleWake {
                wait: id.clone(),
                held,
                presented: generation,
            }),
        }
    }

    /// Returns the recorded withdrawal of one waiter under one fence, if it matches.
    #[must_use]
    pub fn withdrawal(&self, id: &WaitId, generation: WaitGeneration) -> Option<WithdrawalRecord> {
        self.withdrawals
            .get(id)
            .filter(|record| record.generation.observes(generation))
            .cloned()
    }

    /// Resolves the live wait one wake or withdrawal addresses, retiring it when it is
    /// admissible.
    ///
    /// The refusals of `GNT-24.4-stale-wake-fencing-and-waiter-reuse` are applied in their
    /// declared order and a refusal mutates nothing: a waiter identity the set never held
    /// is unknown, a wake that does not name the fence the live wait holds is stale, a wake
    /// that repeats a wake already applied to that wait is a duplicate, and any other fence
    /// of a retired or reused slot is stale rather than a duplicate, because a slot that has
    /// moved on no longer holds the wait the wake addresses. Retiring a wait advances the
    /// retired fence and the retired ordinal of its slot without ever moving either
    /// backwards.
    fn resolve_target(&mut self, id: &WaitId, generation: WaitGeneration) -> TargetResolution {
        let Some((key, _)) = self.index.get(id).cloned() else {
            return TargetResolution::Unknown;
        };
        let Some(slot) = self.slots.get_mut(&key) else {
            return TargetResolution::Unknown;
        };
        if let Some(live) = slot.live.as_ref() {
            if live.id != *id || !generation.observes(live.fence) {
                return TargetResolution::Stale { held: live.fence };
            }
            let ordinal = live.ordinal;
            slot.live = None;
            slot.highest_retired = Some(match slot.highest_retired {
                Some(retired) if retired > generation => retired,
                _ => generation,
            });
            slot.highest_retired_ordinal = Some(match slot.highest_retired_ordinal {
                Some(retired) if retired > ordinal => retired,
                _ => ordinal,
            });
            return TargetResolution::Retired;
        }
        let retired = slot.highest_retired;
        if let Some(record) = self.settlements.get(id)
            && record.generation.observes(generation)
        {
            return TargetResolution::Duplicate(record.clone());
        }
        TargetResolution::Stale {
            held: retired.unwrap_or(generation),
        }
    }

    /// Closes one landed waitable-resource generation after its last producer, requester,
    /// sender, or resource owner is dropped.
    ///
    /// Closure is keyed by the waitable-resource identity and the landed resource
    /// generation of `GNT-20.2-logical-operation-and-resource-generation-identity` that
    /// the waiting registrations carry. It settles exactly the live waits that observe the
    /// closed generation, preserves the waits of every other generation of the same
    /// resource without rewrite, and records the closed generation alongside the resource
    /// identity, so a closure of one generation never settles the wait of another.
    ///
    /// # Errors
    ///
    /// Returns [`WaitError::UnknownResource`] when the set never held a wait of this
    /// resource, [`WaitError::UnknownResourceGeneration`] when the set holds no wait of
    /// this landed resource generation, and [`WaitError::RepeatedClosure`] when the
    /// resource generation is already closed, because a repeated closure would re-settle an
    /// already settled wait.
    pub fn close_resource(
        &mut self,
        resource: &WaitResourceId,
        generation: &ResourceGenerationId,
    ) -> Result<ClosureReport, WaitError> {
        if self
            .closed
            .contains(&(resource.clone(), generation.clone()))
        {
            return Err(WaitError::RepeatedClosure {
                resource: resource.clone(),
            });
        }
        if !self
            .index
            .values()
            .any(|((_, candidate), _)| candidate == resource)
        {
            return Err(WaitError::UnknownResource {
                resource: resource.clone(),
            });
        }
        if !self
            .index
            .values()
            .any(|((_, candidate), known)| candidate == resource && known == generation)
        {
            return Err(WaitError::UnknownResourceGeneration {
                resource: resource.clone(),
                generation: generation.clone(),
            });
        }
        let mut pending = self
            .slots
            .iter()
            .filter(|((_, candidate), _)| candidate == resource)
            .filter_map(|(_, slot)| slot.live.as_ref())
            .filter(|live| &live.resource_generation == generation)
            .map(|live| (live.id.clone(), live.fence))
            .collect::<Vec<_>>();
        pending.sort_by(|(left_id, left_fence), (right_id, right_fence)| {
            left_fence.cmp(right_fence).then(left_id.cmp(right_id))
        });
        let mut preserved = self
            .settlements
            .values()
            .filter(|record| {
                self.index
                    .get(record.wait())
                    .is_some_and(|((_, candidate), known)| {
                        candidate == resource && known == generation
                    })
            })
            .cloned()
            .collect::<Vec<_>>();
        let mut closed = Vec::with_capacity(pending.len());
        for (id, fence) in pending {
            closed.push(self.wake(&id, fence, WakeCause::ResourceClosure)?);
        }
        self.closed.insert((resource.clone(), generation.clone()));
        Self::sort_records(&self.index, &mut closed);
        Self::sort_records(&self.index, &mut preserved);
        Ok(ClosureReport {
            resource: resource.clone(),
            generation: generation.clone(),
            closed,
            preserved,
        })
    }

    /// Returns whether one waiter is live.
    #[must_use]
    pub fn is_live(&self, id: &WaitId) -> bool {
        self.index.get(id).is_some_and(|(key, _)| {
            self.slots
                .get(key)
                .and_then(|slot| slot.live.as_ref())
                .is_some_and(|live| &live.id == id)
        })
    }

    /// Returns every live waiter identity, in identity order.
    #[must_use]
    pub fn live_waiters(&self) -> Vec<WaitId> {
        let mut waiters = self
            .slots
            .values()
            .filter_map(|slot| slot.live.as_ref().map(|live| live.id.clone()))
            .collect::<Vec<_>>();
        waiters.sort();
        waiters
    }

    /// Returns the count of live waits.
    #[must_use]
    pub fn live_count(&self) -> usize {
        self.slots
            .values()
            .filter(|slot| slot.live.is_some())
            .count()
    }

    /// Returns the count of live waits of one waitable resource.
    #[must_use]
    pub fn live_for(&self, resource: &WaitResourceId) -> usize {
        self.slots
            .iter()
            .filter(|((_, candidate), slot)| candidate == resource && slot.live.is_some())
            .count()
    }

    /// Returns the count of live waits that no cause can classify.
    ///
    /// The count is zero by construction: closure settles every live wait of a closed
    /// resource generation and registration for a closed resource generation is refused,
    /// so no permanent unclassifiable wait exists.
    #[must_use]
    pub fn unclassifiable_count(&self) -> usize {
        self.slots
            .iter()
            .filter(|((_, resource), slot)| {
                slot.live.as_ref().is_some_and(|live| {
                    self.closed
                        .contains(&(resource.clone(), live.resource_generation.clone()))
                })
            })
            .count()
    }

    /// Returns the single winner of one waiter, if it is settled.
    #[must_use]
    pub fn winner(&self, id: &WaitId) -> Option<WakeCause> {
        self.settlements.get(id).map(|record| record.cause)
    }

    /// Returns the settlement of one waiter under one fence, if it matches.
    #[must_use]
    pub fn settlement(&self, id: &WaitId, generation: WaitGeneration) -> Option<WakeRecord> {
        self.settlements
            .get(id)
            .filter(|record| record.generation.observes(generation))
            .cloned()
    }

    /// Returns whether one landed waitable-resource generation is closed.
    #[must_use]
    pub fn is_closed(&self, resource: &WaitResourceId, generation: &ResourceGenerationId) -> bool {
        self.closed
            .contains(&(resource.clone(), generation.clone()))
    }

    /// Sorts one record list by owning task, generation fence, and waiter identity.
    fn sort_records(
        index: &BTreeMap<WaitId, (SlotKey, ResourceGenerationId)>,
        records: &mut [WakeRecord],
    ) {
        records.sort_by(|left, right| {
            index
                .get(left.wait())
                .map(|((owner, _), _)| owner.clone())
                .cmp(&index.get(right.wait()).map(|((owner, _), _)| owner.clone()))
                .then(left.generation().cmp(&right.generation()))
                .then(left.wait().cmp(right.wait()))
        });
    }
}

/// One declared arbitration arm key
/// (`GNT-24.6-select-and-race-snapshots-and-winner-permanence`).
///
/// The key names one armed alternative of one declared arm order. It is not a host
/// handle, an arrival order, or a scheduling order, so a tie is decided by the declared
/// order of keys rather than by an observation.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ArmId {
    text: Arc<str>,
}

impl ArmId {
    /// Constructs one declared arm key from its declared identity.
    ///
    /// # Errors
    ///
    /// Returns [`WaitError::EmptyDeclaredIdentity`] when the declared text is empty or
    /// whitespace only.
    pub fn new(key: &str) -> Result<Self, WaitError> {
        Ok(Self {
            text: declared_text(key, IdentityInput::Arm)?,
        })
    }

    /// Returns the exact portable key spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }
}

impl fmt::Display for ArmId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.text)
    }
}

/// One armed alternative of one arbitration
/// (`GNT-24.6-select-and-race-snapshots-and-winner-permanence`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArmedAlternative {
    arm: ArmId,
    wait: WaitId,
}

impl ArmedAlternative {
    /// Arms one wait under one declared arm key.
    #[must_use]
    pub const fn new(arm: ArmId, wait: WaitId) -> Self {
        Self { arm, wait }
    }

    /// Returns the declared arm key.
    #[must_use]
    pub const fn arm(&self) -> &ArmId {
        &self.arm
    }

    /// Returns the armed waiter identity.
    #[must_use]
    pub const fn wait(&self) -> &WaitId {
        &self.wait
    }
}

/// The frozen snapshot of one arbitration
/// (`GNT-24.6-select-and-race-snapshots-and-winner-permanence`).
///
/// The snapshot is the declared arm set, in declared arm order, and it is immutable for
/// the life of the arbitration: no arm presented after the snapshot and no re-read that
/// would widen the arm set is admitted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArbitrationSnapshot {
    arms: Vec<ArmedAlternative>,
}

impl ArbitrationSnapshot {
    /// Returns the count of armed alternatives.
    #[must_use]
    pub fn arm_count(&self) -> usize {
        self.arms.len()
    }

    /// Returns the armed alternatives in declared arm order.
    #[must_use]
    pub fn arms(&self) -> &[ArmedAlternative] {
        &self.arms
    }

    /// Returns whether one declared arm key belongs to the snapshot.
    #[must_use]
    pub fn contains(&self, arm: &ArmId) -> bool {
        self.arms.iter().any(|alternative| alternative.arm() == arm)
    }

    /// Returns the declared position of one arm key, if it belongs to the snapshot.
    #[must_use]
    pub fn position(&self, arm: &ArmId) -> Option<usize> {
        self.arms
            .iter()
            .position(|alternative| alternative.arm() == arm)
    }

    /// Returns the armed waiter identity of one arm key, if it belongs to the snapshot.
    #[must_use]
    pub fn wait(&self, arm: &ArmId) -> Option<&WaitId> {
        self.arms
            .iter()
            .find(|alternative| alternative.arm() == arm)
            .map(ArmedAlternative::wait)
    }
}

/// One wake observed for one arm of one arbitration instant
/// (`GNT-24.6-select-and-race-snapshots-and-winner-permanence`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArmObservation {
    arm: ArmId,
    cause: WakeCause,
}

impl ArmObservation {
    /// Records one wake of one closed cause for one arm.
    #[must_use]
    pub const fn new(arm: ArmId, cause: WakeCause) -> Self {
        Self { arm, cause }
    }

    /// Returns the observed arm key.
    #[must_use]
    pub const fn arm(&self) -> &ArmId {
        &self.arm
    }

    /// Returns the observed cause.
    #[must_use]
    pub const fn cause(&self) -> WakeCause {
        self.cause
    }
}

/// The committed winner of one arbitration
/// (`GNT-24.6-select-and-race-snapshots-and-winner-permanence`).
///
/// The winner records the arm key, the armed waiter identity, the cause, the declared
/// position that decided a tie, and every contending arm, so a tie is decidable from
/// declared values rather than from an observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArmedWinner {
    arm: ArmId,
    wait: WaitId,
    cause: WakeCause,
    position: usize,
    contending: Vec<ArmId>,
}

impl ArmedWinner {
    /// Returns the declared arm key of the winner.
    #[must_use]
    pub const fn arm(&self) -> &ArmId {
        &self.arm
    }

    /// Returns the armed waiter identity of the winner.
    #[must_use]
    pub const fn wait(&self) -> &WaitId {
        &self.wait
    }

    /// Returns the cause that made the winning arm eligible.
    #[must_use]
    pub const fn cause(&self) -> WakeCause {
        self.cause
    }

    /// Returns the declared position of the winning arm.
    #[must_use]
    pub const fn position(&self) -> usize {
        self.position
    }

    /// Returns every arm that was eligible at the arbitration instant.
    #[must_use]
    pub fn contending(&self) -> &[ArmId] {
        &self.contending
    }

    /// Returns whether more than one arm was eligible, so the tie order decided.
    #[must_use]
    pub fn was_tie(&self) -> bool {
        self.contending.len() > 1
    }
}

/// The declared nondeterminism envelope of one arbitration
/// (`GNT-24.7-losing-arm-ownership-and-nondeterminism`).
///
/// The envelope is the set of eligible arms of the frozen snapshot. An
/// application-visible choice may differ between runs only within it, so every permitted
/// outcome is a declared value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NondeterminismEnvelope {
    eligible: Vec<ArmId>,
}

impl NondeterminismEnvelope {
    /// Returns the eligible arms in declared arm order.
    #[must_use]
    pub fn eligible(&self) -> &[ArmId] {
        &self.eligible
    }

    /// Returns whether one arm is a permitted outcome.
    #[must_use]
    pub fn permits(&self, arm: &ArmId) -> bool {
        self.eligible.contains(arm)
    }

    /// Returns whether the envelope admits exactly one outcome.
    #[must_use]
    pub fn is_deterministic(&self) -> bool {
        self.eligible.len() <= 1
    }

    /// Returns the clause anchor that owns this envelope.
    #[must_use]
    pub const fn requirement(&self) -> &'static str {
        "GNT-24.7-losing-arm-ownership-and-nondeterminism"
    }
}

/// One arbitration over one frozen snapshot
/// (`GNT-24.6-select-and-race-snapshots-and-winner-permanence`).
///
/// The arbitration freezes its arm set once, decides at most one permanent winner, and
/// never re-chooses a committed winner. An arbitration with no eligible arm stays
/// unresolved and a later decision observes the same snapshot. The arbitration is affine:
/// it derives no `Clone` and no `Copy`, [`Self::decide`] and
/// [`Self::into_losing_settlement`] consume it, and no second value can be produced from
/// one committed arbitration, so exactly one losing-arm settlement exists per committed
/// arbitration.
#[derive(Debug, Eq, PartialEq)]
pub struct Arbitration {
    snapshot: ArbitrationSnapshot,
    winner: Option<ArmedWinner>,
}

impl Arbitration {
    /// Opens one arbitration over one declared arm set, freezing the snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`WaitError::EmptyArbitration`] when no arm is declared, because an
    /// arbitration without alternatives has no winner to commit;
    /// [`WaitError::DuplicateArm`] when one declared arm key appears twice, because a
    /// duplicated key would make a tie undecidable; and
    /// [`WaitError::RepeatedArmedAlternative`] when one waiter is armed twice, because one
    /// wait has exactly one winner and a repeated armed alternative is a refusal of
    /// `GNT-24.6` rather than the duplicate waiter of
    /// `GNT-24.4-stale-wake-fencing-and-waiter-reuse`.
    pub fn open(arms: Vec<ArmedAlternative>) -> Result<Self, WaitError> {
        if arms.is_empty() {
            return Err(WaitError::EmptyArbitration);
        }
        let mut keys = BTreeSet::new();
        let mut waits = BTreeSet::new();
        for alternative in &arms {
            if !keys.insert(alternative.arm().clone()) {
                return Err(WaitError::DuplicateArm {
                    arm: alternative.arm().clone(),
                });
            }
            if !waits.insert(alternative.wait().clone()) {
                return Err(WaitError::RepeatedArmedAlternative {
                    arm: alternative.arm().clone(),
                    wait: alternative.wait().clone(),
                });
            }
        }
        Ok(Self {
            snapshot: ArbitrationSnapshot { arms },
            winner: None,
        })
    }

    /// Returns the frozen snapshot.
    #[must_use]
    pub const fn snapshot(&self) -> &ArbitrationSnapshot {
        &self.snapshot
    }

    /// Returns the committed winner, if the arbitration is decided.
    #[must_use]
    pub const fn winner(&self) -> Option<&ArmedWinner> {
        self.winner.as_ref()
    }

    /// Consumes this arbitration into its decision from the wakes observed at one instant.
    ///
    /// An empty observation list leaves the arbitration unresolved and hands the same
    /// arbitration value back. Where more than one arm is eligible, the winner is the
    /// eligible arm with the lowest declared position. The arbitration is affine, so this
    /// decision consumes the one arbitration value and returns it, and the single
    /// losing-arm settlement is reachable only from that returned value.
    ///
    /// # Errors
    ///
    /// Returns [`WaitError::WinnerAlreadyCommitted`] when a winner is already committed,
    /// because a committed winner is never re-chosen; [`WaitError::ArmOutsideSnapshot`]
    /// when an observation names an arm the snapshot does not hold, because no later
    /// arrival enters an arbitration it did not freeze; and
    /// [`WaitError::DuplicateObservation`] when one arm is observed twice at one instant,
    /// because one wait has exactly one winner. Every refusal mutates nothing.
    pub fn decide(
        mut self,
        observations: &[ArmObservation],
    ) -> Result<ArbitrationDecision, WaitError> {
        if let Some(winner) = &self.winner {
            return Err(WaitError::WinnerAlreadyCommitted {
                arm: winner.arm.clone(),
            });
        }
        let mut eligible = Vec::with_capacity(observations.len());
        for observation in observations {
            let Some(position) = self.snapshot.position(observation.arm()) else {
                return Err(WaitError::ArmOutsideSnapshot {
                    arm: observation.arm().clone(),
                });
            };
            if eligible
                .iter()
                .any(|(_, arm, _): &(usize, ArmId, WakeCause)| arm == observation.arm())
            {
                return Err(WaitError::DuplicateObservation {
                    arm: observation.arm().clone(),
                });
            }
            eligible.push((position, observation.arm().clone(), observation.cause()));
        }
        eligible.sort_by_key(|(position, _, _)| *position);
        let Some((position, arm, cause)) = eligible.into_iter().next() else {
            return Ok(ArbitrationDecision::Unresolved(self));
        };
        let contending = observations
            .iter()
            .map(|observation| observation.arm().clone())
            .collect::<Vec<_>>();
        let Some(wait) = self.snapshot.wait(&arm).cloned() else {
            return Err(WaitError::ArmOutsideSnapshot { arm });
        };
        let winner = ArmedWinner {
            arm,
            wait,
            cause,
            position,
            contending,
        };
        self.winner = Some(winner.clone());
        Ok(ArbitrationDecision::Committed(self))
    }

    /// Returns the declared nondeterminism envelope of one observation set.
    ///
    /// # Errors
    ///
    /// Returns [`WaitError::ArmOutsideSnapshot`] when an observation names an arm of
    /// another snapshot, because a choice among arms of another snapshot is refused.
    pub fn envelope(
        &self,
        observations: &[ArmObservation],
    ) -> Result<NondeterminismEnvelope, WaitError> {
        let mut observed = BTreeSet::new();
        for observation in observations {
            if !self.snapshot.contains(observation.arm()) {
                return Err(WaitError::ArmOutsideSnapshot {
                    arm: observation.arm().clone(),
                });
            }
            observed.insert(observation.arm().clone());
        }
        let eligible = self
            .snapshot
            .arms()
            .iter()
            .filter(|alternative| observed.contains(alternative.arm()))
            .map(|alternative| alternative.arm().clone())
            .collect();
        Ok(NondeterminismEnvelope { eligible })
    }

    /// Consumes this arbitration into the single settlement of its losing arms.
    ///
    /// The settlement is affine because this arbitration is: consuming the one committed
    /// arbitration yields exactly one settlement, and no second settlement of the same
    /// arbitration exists.
    ///
    /// # Errors
    ///
    /// Returns [`WaitError::WinnerNotCommitted`] before a winner is committed, because
    /// ownership of the losing arms is decided only after the winner is permanent.
    pub fn into_losing_settlement(self) -> Result<LosingArmSettlement, WaitError> {
        let Some(winner) = self.winner else {
            return Err(WaitError::WinnerNotCommitted);
        };
        Ok(LosingArmSettlement {
            arms: self.snapshot.arms,
            winner: winner.arm,
        })
    }
}

/// The decision one affine arbitration reaches at one declared instant
/// (`GNT-24.6-select-and-race-snapshots-and-winner-permanence`).
///
/// The decision hands the one live arbitration value back, so the losing arms are
/// reachable only through the arbitration that produced them. [`Arbitration`] derives no
/// `Clone` and no `Copy`, [`Arbitration::decide`] consumes it, and
/// [`Arbitration::into_losing_settlement`] consumes it, so a committed arbitration yields
/// exactly one losing-arm settlement and no settlement can be produced twice.
#[derive(Debug, Eq, PartialEq)]
pub enum ArbitrationDecision {
    /// One eligible arm was committed as the permanent winner.
    Committed(Arbitration),
    /// No arm was eligible at the declared instant, so the arbitration stays unresolved.
    Unresolved(Arbitration),
}

impl ArbitrationDecision {
    /// Returns the arbitration this decision was reached from.
    #[must_use]
    pub const fn arbitration(&self) -> &Arbitration {
        match self {
            Self::Committed(arbitration) | Self::Unresolved(arbitration) => arbitration,
        }
    }

    /// Consumes this decision into its arbitration.
    #[must_use]
    pub fn into_arbitration(self) -> Arbitration {
        match self {
            Self::Committed(arbitration) | Self::Unresolved(arbitration) => arbitration,
        }
    }

    /// Returns the committed winner, if this decision committed one.
    #[must_use]
    pub fn winner(&self) -> Option<&ArmedWinner> {
        match self {
            Self::Committed(arbitration) => arbitration.winner(),
            Self::Unresolved(_) => None,
        }
    }

    /// Returns whether this decision committed a winner.
    #[must_use]
    pub const fn is_committed(&self) -> bool {
        matches!(self, Self::Committed(_))
    }

    /// Returns the clause anchor that owns this decision.
    #[must_use]
    pub const fn requirement(&self) -> &'static str {
        "GNT-24.6-select-and-race-snapshots-and-winner-permanence"
    }
}

/// One declared disposition of one losing arm
/// (`GNT-24.7-losing-arm-ownership-and-nondeterminism`).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ArmDispositionKind {
    /// The losing wait is cancelled with the cancellation cause.
    Cancel,
    /// The losing wait is retained for its owner unchanged.
    Retain,
}

impl ArmDispositionKind {
    /// Every member of the closed vocabulary, in declaration order.
    pub const ALL: [Self; 2] = [Self::Cancel, Self::Retain];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Cancel => "cancel",
            Self::Retain => "retain",
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

    /// Returns the clause anchor that owns this disposition.
    #[must_use]
    pub const fn requirement(self) -> &'static str {
        "GNT-24.7-losing-arm-ownership-and-nondeterminism"
    }
}

/// One disposition of one losing arm
/// (`GNT-24.7-losing-arm-ownership-and-nondeterminism`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArmDisposition {
    arm: ArmId,
    kind: ArmDispositionKind,
}

impl ArmDisposition {
    /// Declares one disposition of one losing arm.
    #[must_use]
    pub const fn new(arm: ArmId, kind: ArmDispositionKind) -> Self {
        Self { arm, kind }
    }

    /// Returns the arm key this disposition settles.
    #[must_use]
    pub const fn arm(&self) -> &ArmId {
        &self.arm
    }

    /// Returns the declared disposition kind.
    #[must_use]
    pub const fn kind(&self) -> ArmDispositionKind {
        self.kind
    }
}

/// The single affine settlement of the losing arms of one committed arbitration
/// (`GNT-24.7-losing-arm-ownership-and-nondeterminism`).
///
/// The settlement derives no `Clone` and no `Copy`, so exactly one live settlement of
/// one arbitration exists and it is consumed once by [`Self::settle`].
#[derive(Debug)]
pub struct LosingArmSettlement {
    arms: Vec<ArmedAlternative>,
    winner: ArmId,
}

impl LosingArmSettlement {
    /// Returns the committed winner key.
    #[must_use]
    pub const fn winner(&self) -> &ArmId {
        &self.winner
    }

    /// Returns the losing arm keys in declared arm order.
    #[must_use]
    pub fn losing_arms(&self) -> Vec<ArmId> {
        self.arms
            .iter()
            .filter(|alternative| alternative.arm() != &self.winner)
            .map(|alternative| alternative.arm().clone())
            .collect()
    }

    /// Settles every losing arm with exactly one declared disposition.
    ///
    /// # Errors
    ///
    /// Returns [`WaitError::WinnerNotLosable`] when a disposition names the committed
    /// winner, [`WaitError::ArmOutsideSnapshot`] when a disposition names an arm of
    /// another snapshot, [`WaitError::RepeatedDisposition`] when one arm is settled
    /// twice, and [`WaitError::UnsettledLosingArm`] when a losing arm receives no
    /// disposition.
    pub fn settle(
        self,
        dispositions: &[ArmDisposition],
    ) -> Result<LosingArmSettlementReport, WaitError> {
        let losing = self.losing_arms();
        let mut seen = BTreeSet::new();
        for disposition in dispositions {
            if disposition.arm() == &self.winner {
                return Err(WaitError::WinnerNotLosable {
                    arm: disposition.arm().clone(),
                });
            }
            if !self
                .arms
                .iter()
                .any(|alternative| alternative.arm() == disposition.arm())
            {
                return Err(WaitError::ArmOutsideSnapshot {
                    arm: disposition.arm().clone(),
                });
            }
            if !seen.insert(disposition.arm().clone()) {
                return Err(WaitError::RepeatedDisposition {
                    arm: disposition.arm().clone(),
                });
            }
        }
        for arm in &losing {
            if !seen.contains(arm) {
                return Err(WaitError::UnsettledLosingArm { arm: arm.clone() });
            }
        }
        let mut cancelled = Vec::new();
        let mut retained = Vec::new();
        for arm in losing {
            let Some(disposition) = dispositions
                .iter()
                .find(|disposition| disposition.arm() == &arm)
            else {
                return Err(WaitError::UnsettledLosingArm { arm });
            };
            match disposition.kind() {
                ArmDispositionKind::Cancel => cancelled.push(arm),
                ArmDispositionKind::Retain => retained.push(arm),
            }
        }
        Ok(LosingArmSettlementReport {
            winner: self.winner,
            cancelled,
            retained,
        })
    }
}

/// The report of one losing-arm settlement
/// (`GNT-24.7-losing-arm-ownership-and-nondeterminism`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LosingArmSettlementReport {
    winner: ArmId,
    cancelled: Vec<ArmId>,
    retained: Vec<ArmId>,
}

impl LosingArmSettlementReport {
    /// Returns the committed winner key.
    #[must_use]
    pub const fn winner(&self) -> &ArmId {
        &self.winner
    }

    /// Returns the losing arms settled by cancellation, in declared arm order.
    #[must_use]
    pub fn cancelled(&self) -> &[ArmId] {
        &self.cancelled
    }

    /// Returns the losing arms retained for their owners, in declared arm order.
    #[must_use]
    pub fn retained(&self) -> &[ArmId] {
        &self.retained
    }

    /// Returns whether every losing arm received exactly one disposition.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        !self.cancelled.is_empty() || !self.retained.is_empty()
    }
}

/// One quiescence class of the closed five-member vocabulary
/// (`GNT-24.8-quiescence-classification`).
///
/// The five classes are total and mutually exclusive over declared wait and edge facts.
/// A pending host prerequisite that the type contract permits to remain pending is
/// classified as externally wakeable idle and never as closed-wait deadlock.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum QuiescenceClass {
    /// Live waits remain whose only remaining prerequisite is an external prerequisite
    /// permitted to remain pending, and no deadlock is reported for it.
    ExternallyWakeableIdle,
    /// The remaining pending work is work this lifecycle can itself wake or schedule.
    InternallyWakeableIdle,
    /// Every live wait is blocked on an internal edge, no external prerequisite is
    /// pending, and no admitted work can be scheduled.
    ClosedWaitDeadlock,
    /// No live wait and no admitted nonterminal work remain.
    Completion,
    /// Waits of a retired owner, or admitted nonterminal work with no owner able to
    /// advance it, remain.
    OrphanedWork,
}

impl QuiescenceClass {
    /// Every member of the closed vocabulary, in declaration order.
    pub const ALL: [Self; 5] = [
        Self::ExternallyWakeableIdle,
        Self::InternallyWakeableIdle,
        Self::ClosedWaitDeadlock,
        Self::Completion,
        Self::OrphanedWork,
    ];

    /// Returns the exact frozen spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::ExternallyWakeableIdle => "externally-wakeable-idle",
            Self::InternallyWakeableIdle => "internally-wakeable-idle",
            Self::ClosedWaitDeadlock => "closed-wait-deadlock",
            Self::Completion => "completion",
            Self::OrphanedWork => "orphaned-work",
        }
    }

    /// Returns the same exact frozen spelling as [`Self::wire_name`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.wire_name()
    }

    /// Strictly decodes one exact frozen spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.wire_name() == value)
    }

    /// Returns the frozen one-line meaning of this class.
    #[must_use]
    pub const fn meaning(self) -> &'static str {
        match self {
            Self::ExternallyWakeableIdle => {
                "live waits remain whose only remaining prerequisite is an external prerequisite the type contract permits to remain pending"
            }
            Self::InternallyWakeableIdle => {
                "the remaining pending work is work this lifecycle can itself wake or schedule"
            }
            Self::ClosedWaitDeadlock => {
                "every live wait is blocked on an internal edge, no external prerequisite is pending, and no admitted work can be scheduled"
            }
            Self::Completion => "no live wait and no admitted nonterminal work remain",
            Self::OrphanedWork => {
                "waits of a retired owner, or admitted nonterminal work with no owner able to advance it, remain"
            }
        }
    }

    /// Returns whether this class reports a closed-wait deadlock.
    #[must_use]
    pub const fn is_deadlock(self) -> bool {
        matches!(self, Self::ClosedWaitDeadlock)
    }

    /// Returns the clause anchor that owns this class.
    #[must_use]
    pub const fn requirement(self) -> &'static str {
        "GNT-24.8-quiescence-classification"
    }
}

impl fmt::Display for QuiescenceClass {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.wire_name())
    }
}

/// The declared wait and edge facts one quiescence classification reads
/// (`GNT-24.8-quiescence-classification`).
///
/// The facts are declared values: live waits, live waits blocked on internal edges of
/// the same lifecycle, live waits whose only remaining prerequisite is an external
/// prerequisite the type contract permits to remain pending, admitted nonterminal work
/// units, the admitted work units an internal wake can resume, and waits whose owner
/// retired without settling them, together with admitted work units whose owner retired
/// without settling them. No clock, process fact, adapter handle, or host state enters
/// one, so equal facts produce the same class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuiescenceFacts {
    live_waits: usize,
    blocked_on_internal_edges: usize,
    blocked_on_external_prerequisites: usize,
    admitted_unsettled_work: usize,
    resumable_work: usize,
    orphaned_units: usize,
}

impl QuiescenceFacts {
    /// Declares one set of quiescence facts.
    ///
    /// # Errors
    ///
    /// Returns [`WaitError::MalformedQuiescenceFacts`] when the facts cannot describe an
    /// observation: when more live waits are blocked than are live, or when more work
    /// units are resumable than are admitted and nonterminal.
    pub fn new(
        live_waits: usize,
        blocked_on_internal_edges: usize,
        blocked_on_external_prerequisites: usize,
        admitted_unsettled_work: usize,
        resumable_work: usize,
        orphaned_units: usize,
    ) -> Result<Self, WaitError> {
        let blocked = blocked_on_internal_edges.saturating_add(blocked_on_external_prerequisites);
        if blocked > live_waits || resumable_work > admitted_unsettled_work {
            return Err(WaitError::MalformedQuiescenceFacts {
                live_waits,
                blocked,
                resulting: resumable_work,
                admitted: admitted_unsettled_work,
            });
        }
        Ok(Self {
            live_waits,
            blocked_on_internal_edges,
            blocked_on_external_prerequisites,
            admitted_unsettled_work,
            resumable_work,
            orphaned_units,
        })
    }

    /// Returns the count of live waits.
    #[must_use]
    pub const fn live_waits(&self) -> usize {
        self.live_waits
    }

    /// Returns the count of live waits blocked on an internal edge.
    #[must_use]
    pub const fn blocked_on_internal_edges(&self) -> usize {
        self.blocked_on_internal_edges
    }

    /// Returns the count of live waits whose only remaining prerequisite is external.
    #[must_use]
    pub const fn blocked_on_external_prerequisites(&self) -> usize {
        self.blocked_on_external_prerequisites
    }

    /// Returns the count of admitted nonterminal work units.
    #[must_use]
    pub const fn admitted_unsettled_work(&self) -> usize {
        self.admitted_unsettled_work
    }

    /// Returns the count of admitted work units an internal wake can resume.
    #[must_use]
    pub const fn resumable_work(&self) -> usize {
        self.resumable_work
    }

    /// Returns the count of waits and work units whose owner retired without settling
    /// them.
    #[must_use]
    pub const fn orphaned_units(&self) -> usize {
        self.orphaned_units
    }

    /// Returns the clause anchor that owns these facts.
    #[must_use]
    pub const fn requirement(&self) -> &'static str {
        "GNT-24.8-quiescence-classification"
    }
}

/// Classifies one quiescent observation from declared wait and edge facts
/// (`GNT-24.8-quiescence-classification`).
///
/// The class is decided in the declared order of
/// `GNT-24.8-quiescence-classification`, so the five classes are total and mutually
/// exclusive. A pending host prerequisite the type contract permits to remain pending is
/// never reported as a deadlock.
#[must_use]
pub fn classify_quiescence(facts: &QuiescenceFacts) -> QuiescenceClass {
    if facts.orphaned_units > 0 {
        return QuiescenceClass::OrphanedWork;
    }
    if facts.live_waits == 0 {
        return if facts.admitted_unsettled_work == 0 {
            QuiescenceClass::Completion
        } else {
            QuiescenceClass::InternallyWakeableIdle
        };
    }
    if facts.blocked_on_internal_edges == facts.live_waits
        && facts.blocked_on_external_prerequisites == 0
        && facts.resumable_work == 0
    {
        return QuiescenceClass::ClosedWaitDeadlock;
    }
    if facts.blocked_on_external_prerequisites > 0 {
        return QuiescenceClass::ExternallyWakeableIdle;
    }
    QuiescenceClass::InternallyWakeableIdle
}

/// The declared remedy of one quiescence class (`GNT-24.8-quiescence-classification`).
///
/// A closed-wait deadlock is remedied by the ordinary cancellation and cleanup of
/// `GNT-15.3` and Section 22 rather than by a second fault or cancellation taxonomy.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum QuiescenceRemedy {
    /// No remedy is declared for this class.
    None,
    /// The ordinary cancellation and cleanup of `GNT-15.3` and Section 22.
    OrdinaryCancellationAndCleanup,
}

impl QuiescenceRemedy {
    /// Every member of the closed vocabulary, in declaration order.
    pub const ALL: [Self; 2] = [Self::None, Self::OrdinaryCancellationAndCleanup];

    /// Returns the exact frozen spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::OrdinaryCancellationAndCleanup => "ordinary-cancellation-and-cleanup",
        }
    }

    /// Returns the same exact frozen spelling as [`Self::wire_name`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.wire_name()
    }

    /// Strictly decodes one exact frozen spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.wire_name() == value)
    }

    /// Returns the clause anchor that owns this remedy.
    #[must_use]
    pub const fn requirement(self) -> &'static str {
        "GNT-24.8-quiescence-classification"
    }
}

/// One bounded protected wait-graph diagnostic
/// (`GNT-24.8-quiescence-classification`).
///
/// The diagnostic names the waiting identities and the internal edge count of one
/// closed-wait deadlock, and it is bounded by the declared maxima
/// [`WAIT_GRAPH_MAX_NODES`] and [`WAIT_GRAPH_MAX_EDGES`]: a larger graph is refused rather
/// than truncated, so a diagnostic never presents a partial graph as a complete one. It
/// carries declared metadata, identities, and codes only, so no field of it can hold a
/// payload byte, a protected content, or a value derived from one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WaitGraphDiagnostic {
    waits: Vec<WaitId>,
    internal_edges: usize,
}

impl WaitGraphDiagnostic {
    /// Bounds one wait-graph diagnostic over the declared waiting identities.
    ///
    /// # Errors
    ///
    /// Returns [`WaitError::EmptyWaitGraph`] when no waiting identity is declared,
    /// because an empty graph reports no cycle, and
    /// [`WaitError::WaitGraphDiagnosticTooLarge`] when the node or edge count exceeds the
    /// declared maximum.
    pub fn new(waits: Vec<WaitId>, internal_edges: usize) -> Result<Self, WaitError> {
        if waits.is_empty() {
            return Err(WaitError::EmptyWaitGraph);
        }
        if waits.len() > WAIT_GRAPH_MAX_NODES || internal_edges > WAIT_GRAPH_MAX_EDGES {
            return Err(WaitError::WaitGraphDiagnosticTooLarge {
                nodes: waits.len(),
                edges: internal_edges,
            });
        }
        Ok(Self {
            waits,
            internal_edges,
        })
    }

    /// Returns the count of waiting identities in the diagnostic.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.waits.len()
    }

    /// Returns the internal edge count of the diagnostic.
    #[must_use]
    pub const fn edge_count(&self) -> usize {
        self.internal_edges
    }

    /// Returns the waiting identities in declaration order.
    #[must_use]
    pub fn waits(&self) -> &[WaitId] {
        &self.waits
    }

    /// Returns the class this diagnostic reports.
    #[must_use]
    pub const fn class(&self) -> QuiescenceClass {
        QuiescenceClass::ClosedWaitDeadlock
    }

    /// Returns the declared remedy of this diagnostic.
    #[must_use]
    pub const fn remedy(&self) -> QuiescenceRemedy {
        QuiescenceRemedy::OrdinaryCancellationAndCleanup
    }

    /// Returns the frozen diagnostic code of this report.
    #[must_use]
    pub const fn code(&self) -> WaitDiagnosticCode {
        WaitDiagnosticCode::ClosedWaitDeadlockReported
    }

    /// Returns the clause anchor that owns this diagnostic.
    #[must_use]
    pub const fn requirement(&self) -> &'static str {
        "GNT-24.8-quiescence-classification"
    }

    /// Renders the diagnostic under the landed protected-diagnostic capability of
    /// `GNT-15.10`.
    ///
    /// Presenting [`AuditAccess`] is the admission of this rendering; this pure model
    /// grants no capability and audits no access, so enforcement of the audience is the
    /// host's. The text carries the code, the class, the bounds, and the waiting
    /// identities, and it can carry nothing else.
    #[must_use]
    pub fn protected_text(&self, _access: AuditAccess) -> String {
        format!(
            "{}: class={} nodes={} edges={} waits=[{}]",
            self.code().as_str(),
            self.class().wire_name(),
            self.node_count(),
            self.edge_count(),
            self.waits
                .iter()
                .map(WaitId::as_str)
                .collect::<Vec<_>>()
                .join(",")
        )
    }
}

/// The classified quiescence of one observation
/// (`GNT-24.8-quiescence-classification`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuiescenceOutcome {
    class: QuiescenceClass,
    diagnostic: Option<WaitGraphDiagnostic>,
    remedy: QuiescenceRemedy,
}

impl QuiescenceOutcome {
    /// Returns the decided class.
    #[must_use]
    pub const fn class(&self) -> QuiescenceClass {
        self.class
    }

    /// Returns the bounded wait-graph diagnostic of a closed-wait deadlock.
    #[must_use]
    pub const fn diagnostic(&self) -> Option<&WaitGraphDiagnostic> {
        self.diagnostic.as_ref()
    }

    /// Returns the declared remedy of the decided class.
    #[must_use]
    pub const fn remedy(&self) -> QuiescenceRemedy {
        self.remedy
    }

    /// Returns the clause anchor that owns this outcome.
    #[must_use]
    pub const fn requirement(&self) -> &'static str {
        "GNT-24.8-quiescence-classification"
    }
}

/// Classifies one quiescent observation and reports one bounded diagnostic for a
/// closed-wait deadlock (`GNT-24.8-quiescence-classification`).
///
/// Classification is evidence: it settles no task, closes no resource, and rewinds no
/// accepted work. A closed-wait deadlock additionally reports the bounded protected
/// wait-graph diagnostic of the declared waiting identities.
///
/// # Errors
///
/// Returns the refusals of [`WaitGraphDiagnostic::new`] when a deadlock is decided but
/// the declared graph is empty or exceeds the declared maxima.
pub fn observe_quiescence(
    facts: &QuiescenceFacts,
    waits: Vec<WaitId>,
    internal_edges: usize,
) -> Result<QuiescenceOutcome, WaitError> {
    let class = classify_quiescence(facts);
    if class.is_deadlock() {
        let diagnostic = WaitGraphDiagnostic::new(waits, internal_edges)?;
        return Ok(QuiescenceOutcome {
            class,
            diagnostic: Some(diagnostic),
            remedy: QuiescenceRemedy::OrdinaryCancellationAndCleanup,
        });
    }
    Ok(QuiescenceOutcome {
        class,
        diagnostic: None,
        remedy: QuiescenceRemedy::None,
    })
}

/// One committed decision of one durable wait
/// (`GNT-24.9-durable-wait-and-winner-reconstruction`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WaitDecision {
    /// The selected wake of the committed cause.
    Wake(WakeCause),
    /// The deadlock transition of the committed class.
    Deadlock(QuiescenceClass),
}

impl WaitDecision {
    /// Returns the committed wake cause, if this decision is a wake.
    #[must_use]
    pub const fn wake(self) -> Option<WakeCause> {
        match self {
            Self::Wake(cause) => Some(cause),
            Self::Deadlock(_) => None,
        }
    }

    /// Returns the committed deadlock class, if this decision is a deadlock.
    #[must_use]
    pub const fn deadlock(self) -> Option<QuiescenceClass> {
        match self {
            Self::Wake(_) => None,
            Self::Deadlock(class) => Some(class),
        }
    }

    /// Returns the clause anchor that owns this decision.
    #[must_use]
    pub const fn requirement(self) -> &'static str {
        "GNT-24.9-durable-wait-and-winner-reconstruction"
    }
}

impl fmt::Display for WaitDecision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wake(cause) => write!(formatter, "wake:{}", cause.wire_name()),
            Self::Deadlock(class) => write!(formatter, "deadlock:{}", class.wire_name()),
        }
    }
}

/// One durable wait cut (`GNT-24.9-durable-wait-and-winner-reconstruction`).
///
/// The cuts are exactly the four members below, in cut order: registration, ownership,
/// readiness, and the decision. A cut only ever advances, so a replay from a committed
/// prefix reproduces the same winner and never re-decides it.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DurableWaitCut {
    /// The registration of the wait was committed.
    Registration,
    /// The ownership of the armed wait was committed.
    Ownership,
    /// The readiness of the wait was committed.
    Readiness,
    /// The selected wake or the deadlock transition was committed.
    Decision,
}

impl DurableWaitCut {
    /// Every member of the closed vocabulary, in cut order.
    pub const ALL: [Self; 4] = [
        Self::Registration,
        Self::Ownership,
        Self::Readiness,
        Self::Decision,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Registration => "registration",
            Self::Ownership => "ownership",
            Self::Readiness => "readiness",
            Self::Decision => "decision",
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

    /// Returns the next cut in the declared cut order, if one follows.
    #[must_use]
    pub const fn succeeding(self) -> Option<Self> {
        match self {
            Self::Registration => Some(Self::Ownership),
            Self::Ownership => Some(Self::Readiness),
            Self::Readiness => Some(Self::Decision),
            Self::Decision => None,
        }
    }

    /// Returns the position of this cut in the declared cut order.
    #[must_use]
    pub const fn rank(self) -> u8 {
        match self {
            Self::Registration => 0,
            Self::Ownership => 1,
            Self::Readiness => 2,
            Self::Decision => 3,
        }
    }

    /// Returns the frozen one-line meaning of this cut.
    #[must_use]
    pub const fn meaning(self) -> &'static str {
        match self {
            Self::Registration => "the registration of the wait was committed",
            Self::Ownership => "the ownership of the armed wait was committed",
            Self::Readiness => "the readiness of the wait was committed",
            Self::Decision => "the selected wake or the deadlock transition was committed",
        }
    }

    /// Advances one durable cut, refusing a cut that regresses or skips one.
    ///
    /// A repeated advance to the same cut is stuttering, so an idempotent replay commits
    /// nothing twice; a cut that would move backwards or skip an uncommitted cut is
    /// refused rather than applied.
    ///
    /// # Errors
    ///
    /// Returns [`WaitError::CutRegression`] when `next` precedes the current cut or skips
    /// over an uncommitted cut.
    pub fn advance(&mut self, next: Self) -> Result<(), WaitError> {
        if next.rank() < self.rank() || next.rank() > self.rank() + 1 {
            return Err(WaitError::CutRegression {
                current: *self,
                next,
            });
        }
        *self = next;
        Ok(())
    }

    /// Classifies what recovery resumes from this committed cut.
    #[must_use]
    pub const fn recovery_class(self) -> WaitRecoveryClass {
        match self {
            Self::Registration => WaitRecoveryClass::Registering,
            Self::Ownership => WaitRecoveryClass::Armed,
            Self::Readiness => WaitRecoveryClass::Ready,
            Self::Decision => WaitRecoveryClass::Decided,
        }
    }

    /// Returns the clause anchor that owns this cut.
    #[must_use]
    pub const fn requirement(self) -> &'static str {
        "GNT-24.9-durable-wait-and-winner-reconstruction"
    }
}

/// What recovery resumes from one committed durable wait cut
/// (`GNT-24.9-durable-wait-and-winner-reconstruction`).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum WaitRecoveryClass {
    /// The committed cut resumes registration of the same waiter.
    Registering,
    /// The committed cut resumes the armed wait.
    Armed,
    /// The committed cut resumes the ready cause it recorded.
    Ready,
    /// The committed cut resumes the committed winner or deadlock.
    Decided,
}

impl WaitRecoveryClass {
    /// Every member of the closed vocabulary, in cut order.
    pub const ALL: [Self; 4] = [Self::Registering, Self::Armed, Self::Ready, Self::Decided];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Registering => "registering",
            Self::Armed => "armed",
            Self::Ready => "ready",
            Self::Decided => "decided",
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

    /// Returns the frozen one-line meaning of this classification.
    #[must_use]
    pub const fn meaning(self) -> &'static str {
        match self {
            Self::Registering => "the committed cut resumes registration of the same waiter",
            Self::Armed => "the committed cut resumes the armed wait",
            Self::Ready => "the committed cut resumes the ready cause it recorded",
            Self::Decided => "the committed cut resumes the committed winner or deadlock",
        }
    }

    /// Returns the clause anchor that owns this classification.
    #[must_use]
    pub const fn requirement(self) -> &'static str {
        "GNT-24.9-durable-wait-and-winner-reconstruction"
    }
}

/// What one recovery from a committed durable wait cut resumes
/// (`GNT-24.9-durable-wait-and-winner-reconstruction`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WaitRecoveryDecision {
    /// The same waiter identity and generation are re-registered.
    ResumeRegistration,
    /// The armed wait is resumed.
    ResumeArmed,
    /// The ready cause the committed cut recorded is resumed.
    ResumeReady(WakeCause),
    /// The committed winner is resumed and never re-chosen.
    ResumeWinner(WakeCause),
    /// The committed deadlock is resumed and never re-chosen.
    ResumeDeadlock(QuiescenceClass),
}

impl WaitRecoveryDecision {
    /// Returns the exact portable spelling of this resume kind.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::ResumeRegistration => "resume-registration",
            Self::ResumeArmed => "resume-armed",
            Self::ResumeReady(_) => "resume-ready",
            Self::ResumeWinner(_) => "resume-winner",
            Self::ResumeDeadlock(_) => "resume-deadlock",
        }
    }

    /// Returns the same exact portable spelling as [`Self::wire_name`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.wire_name()
    }

    /// Returns the resumed ready cause, if this decision resumes readiness.
    #[must_use]
    pub const fn ready_cause(self) -> Option<WakeCause> {
        match self {
            Self::ResumeReady(cause) => Some(cause),
            Self::ResumeRegistration
            | Self::ResumeArmed
            | Self::ResumeWinner(_)
            | Self::ResumeDeadlock(_) => None,
        }
    }

    /// Returns the resumed winner, if this decision resumes a winner.
    #[must_use]
    pub const fn winner(self) -> Option<WakeCause> {
        match self {
            Self::ResumeWinner(cause) => Some(cause),
            Self::ResumeRegistration
            | Self::ResumeArmed
            | Self::ResumeReady(_)
            | Self::ResumeDeadlock(_) => None,
        }
    }

    /// Returns the resumed deadlock class, if this decision resumes a deadlock.
    #[must_use]
    pub const fn deadlock(self) -> Option<QuiescenceClass> {
        match self {
            Self::ResumeDeadlock(class) => Some(class),
            Self::ResumeRegistration
            | Self::ResumeArmed
            | Self::ResumeReady(_)
            | Self::ResumeWinner(_) => None,
        }
    }

    /// Returns the clause anchor that owns this decision.
    #[must_use]
    pub const fn requirement(self) -> &'static str {
        "GNT-24.9-durable-wait-and-winner-reconstruction"
    }
}

/// One durable wait record (`GNT-24.9-durable-wait-and-winner-reconstruction`).
///
/// Constructing a record commits the registration cut, and every later cut is committed
/// through [`Self::advance_to`], [`Self::commit_readiness`], and
/// [`Self::commit_decision`]. Every one of those commits advances exactly one cut of the
/// declared order registration, ownership, readiness, decision, and every one of them
/// refuses a cut whose predecessor cut is not committed rather than committing the
/// intermediate cuts on the caller's behalf. Recovery from a committed cut classifies what
/// it resumes from that cut alone, reconstructs the same waiter identity, owner, resource,
/// and generation, reattaches only permitted external prerequisites, and never turns a
/// committed wake into a different winner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableWaitRecord {
    wait: WaitId,
    owner: WaitOwnerId,
    resource: WaitResourceId,
    generation: WaitGeneration,
    cut: DurableWaitCut,
    readiness: Option<WakeCause>,
    decision: Option<WaitDecision>,
}

impl DurableWaitRecord {
    /// Commits the registration cut of one durable wait.
    #[must_use]
    pub const fn new(
        wait: WaitId,
        owner: WaitOwnerId,
        resource: WaitResourceId,
        generation: WaitGeneration,
    ) -> Self {
        Self {
            wait,
            owner,
            resource,
            generation,
            cut: DurableWaitCut::Registration,
            readiness: None,
            decision: None,
        }
    }

    /// Commits the registration cut of one wait from its declared registration.
    #[must_use]
    pub fn for_registration(registration: &WaitRegistration) -> Self {
        Self::new(
            registration.id().clone(),
            registration.owner().clone(),
            registration.resource().clone(),
            registration.generation(),
        )
    }

    /// Returns the waiter identity this record reconstructs.
    #[must_use]
    pub const fn wait(&self) -> &WaitId {
        &self.wait
    }

    /// Returns the owning task identity this record reconstructs.
    #[must_use]
    pub const fn owner(&self) -> &WaitOwnerId {
        &self.owner
    }

    /// Returns the waitable-resource identity this record reconstructs.
    #[must_use]
    pub const fn resource(&self) -> &WaitResourceId {
        &self.resource
    }

    /// Returns the waiter-generation fence this record reconstructs.
    #[must_use]
    pub const fn generation(&self) -> WaitGeneration {
        self.generation
    }

    /// Returns the committed cut.
    #[must_use]
    pub const fn cut(&self) -> DurableWaitCut {
        self.cut
    }

    /// Returns the committed readiness cause, if the readiness cut is committed.
    #[must_use]
    pub const fn readiness(&self) -> Option<WakeCause> {
        self.readiness
    }

    /// Returns the committed decision, if the decision cut is committed.
    #[must_use]
    pub const fn decision(&self) -> Option<WaitDecision> {
        self.decision
    }

    /// Advances the committed cut of this record.
    ///
    /// # Errors
    ///
    /// Returns [`WaitError::CutRegression`] for a cut that regresses or skips one.
    pub fn advance_to(&mut self, next: DurableWaitCut) -> Result<(), WaitError> {
        self.cut.advance(next)
    }

    /// Commits exactly the readiness cut with the ready cause the wait observed.
    ///
    /// The commit advances one cut and no more, so the ownership cut of
    /// `GNT-24.6-select-and-race-snapshots-and-winner-permanence` must already be committed
    /// and no intermediate cut is committed on the caller's behalf.
    ///
    /// # Errors
    ///
    /// Returns [`WaitError::ReadinessRegression`] when another readiness cause is already
    /// committed, because a committed readiness is never rewritten, and
    /// [`WaitError::CutRegression`] when the predecessor cut is not the committed ownership
    /// cut, because a commit never skips an uncommitted cut and never commits one for the
    /// caller. A refusal leaves the committed cut and the recorded readiness exactly as
    /// they were.
    pub fn commit_readiness(&mut self, cause: WakeCause) -> Result<(), WaitError> {
        if let Some(held) = self.readiness {
            if held == cause {
                return Ok(());
            }
            return Err(WaitError::ReadinessRegression {
                wait: self.wait.clone(),
                committed: held,
                presented: cause,
            });
        }
        if self.cut != DurableWaitCut::Ownership {
            return Err(WaitError::CutRegression {
                current: self.cut,
                next: DurableWaitCut::Readiness,
            });
        }
        self.cut.advance(DurableWaitCut::Readiness)?;
        self.readiness = Some(cause);
        Ok(())
    }

    /// Commits exactly the decision cut with the selected wake or the deadlock transition.
    ///
    /// The commit advances one cut and no more, so the readiness cut must already be
    /// committed. A wake decision additionally requires a committed readiness that recorded
    /// its cause, because the wake a decision selects is the readiness the wait observed and
    /// a decision without that record could not name the cause it selected.
    ///
    /// # Errors
    ///
    /// Returns [`WaitError::DeadlockClassificationRefused`] when the transition is not
    /// the closed-wait deadlock class, because the decision cut records a deadlock only
    /// for that class; [`WaitError::DecisionRegression`] when another decision is already
    /// committed, because a committed decision is never re-decided;
    /// [`WaitError::CutRegression`] when the cut order would move backwards or skip an
    /// uncommitted cut; and [`WaitError::MissingCommittedReadiness`] when a wake decision
    /// is presented with no committed readiness that recorded a ready cause. Every refusal
    /// leaves the committed cut, the recorded readiness, and the recorded decision exactly
    /// as they were.
    pub fn commit_decision(&mut self, decision: WaitDecision) -> Result<(), WaitError> {
        if let WaitDecision::Deadlock(class) = decision
            && !class.is_deadlock()
        {
            return Err(WaitError::DeadlockClassificationRefused { class });
        }
        if let Some(held) = self.decision {
            if held == decision {
                return Ok(());
            }
            return Err(WaitError::DecisionRegression {
                wait: self.wait.clone(),
                committed: held,
                presented: decision,
            });
        }
        if self.cut != DurableWaitCut::Readiness {
            return Err(WaitError::CutRegression {
                current: self.cut,
                next: DurableWaitCut::Decision,
            });
        }
        if let WaitDecision::Wake(_) = decision
            && self.readiness.is_none()
        {
            return Err(WaitError::MissingCommittedReadiness {
                wait: self.wait.clone(),
            });
        }
        self.cut.advance(DurableWaitCut::Decision)?;
        self.decision = Some(decision);
        Ok(())
    }

    /// Classifies what recovery resumes from the committed cut.
    ///
    /// # Errors
    ///
    /// Returns [`WaitError::DecisionBeforeCommit`] when a decision is presented before
    /// the decision cut is committed, [`WaitError::MissingCommittedReadiness`] when the
    /// readiness cut is committed without a ready cause,
    /// [`WaitError::MissingCommittedDecision`] when the decision cut is committed without
    /// a decision, and [`WaitError::DecisionRegression`] when a presented decision differs
    /// from the committed one, so a committed wake is never turned into a different
    /// winner.
    pub fn resume(
        &self,
        presented: Option<WaitDecision>,
    ) -> Result<WaitRecoveryDecision, WaitError> {
        match self.cut {
            DurableWaitCut::Registration => {
                self.refuse_presented_decision(presented)?;
                Ok(WaitRecoveryDecision::ResumeRegistration)
            }
            DurableWaitCut::Ownership => {
                self.refuse_presented_decision(presented)?;
                Ok(WaitRecoveryDecision::ResumeArmed)
            }
            DurableWaitCut::Readiness => {
                self.refuse_presented_decision(presented)?;
                let cause = self
                    .readiness
                    .ok_or_else(|| WaitError::MissingCommittedReadiness {
                        wait: self.wait.clone(),
                    })?;
                Ok(WaitRecoveryDecision::ResumeReady(cause))
            }
            DurableWaitCut::Decision => {
                let committed =
                    self.decision
                        .ok_or_else(|| WaitError::MissingCommittedDecision {
                            wait: self.wait.clone(),
                        })?;
                if let Some(presented) = presented
                    && presented != committed
                {
                    return Err(WaitError::DecisionRegression {
                        wait: self.wait.clone(),
                        committed,
                        presented,
                    });
                }
                Ok(resume_committed(committed))
            }
        }
    }

    /// Reattaches the external prerequisites recovery is permitted to rebuild.
    ///
    /// The result is a subset of the presented prerequisites that the caller declares
    /// permitted, in declared key order. A presented prerequisite outside the permitted
    /// set is refused rather than reattached, and a prerequisite that was not presented
    /// is never invented.
    ///
    /// # Errors
    ///
    /// Returns [`WaitError::UnpermittedPrerequisite`] when a presented prerequisite is
    /// outside the permitted set.
    pub fn reattach(
        &self,
        presented: &[PrerequisiteRef],
        permitted: &[PrerequisiteRef],
    ) -> Result<Vec<PrerequisiteRef>, WaitError> {
        let mut attached = Vec::with_capacity(presented.len());
        for prerequisite in presented {
            if !permitted.contains(prerequisite) {
                return Err(WaitError::UnpermittedPrerequisite {
                    key: prerequisite.clone(),
                });
            }
            if !attached.contains(prerequisite) {
                attached.push(prerequisite.clone());
            }
        }
        attached.sort();
        Ok(attached)
    }

    /// Refuses a presented decision before the decision cut is committed.
    fn refuse_presented_decision(&self, presented: Option<WaitDecision>) -> Result<(), WaitError> {
        match presented {
            Some(_) => Err(WaitError::DecisionBeforeCommit {
                wait: self.wait.clone(),
            }),
            None => Ok(()),
        }
    }
}

/// Returns the recovery decision of one committed decision.
fn resume_committed(decision: WaitDecision) -> WaitRecoveryDecision {
    match decision {
        WaitDecision::Wake(cause) => WaitRecoveryDecision::ResumeWinner(cause),
        WaitDecision::Deadlock(class) => WaitRecoveryDecision::ResumeDeadlock(class),
    }
}

/// One published wait non-claim of the closed non-claim vocabulary
/// (`GNT-24.10-wait-non-claims`).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum WaitNonClaimName {
    /// No unbounded fairness or latency promise.
    UnboundedFairnessOrLatency,
    /// No deadlock detection for genuinely pending external work.
    ExternalPendingDeadlockDetection,
    /// No shared-memory thread semantics.
    SharedMemoryThreadSemantics,
    /// No disclosure of a protected payload in a diagnostic.
    ProtectedPayloadDisclosure,
}

impl WaitNonClaimName {
    /// Every member of the closed vocabulary, in declared non-claim order.
    pub const ALL: [Self; 4] = [
        Self::UnboundedFairnessOrLatency,
        Self::ExternalPendingDeadlockDetection,
        Self::SharedMemoryThreadSemantics,
        Self::ProtectedPayloadDisclosure,
    ];

    /// Returns the exact frozen spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::UnboundedFairnessOrLatency => "unbounded-fairness-or-latency",
            Self::ExternalPendingDeadlockDetection => "external-pending-deadlock-detection",
            Self::SharedMemoryThreadSemantics => "shared-memory-thread-semantics",
            Self::ProtectedPayloadDisclosure => "protected-payload-disclosure",
        }
    }

    /// Returns the same exact frozen spelling as [`Self::wire_name`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.wire_name()
    }

    /// Strictly decodes one exact frozen spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.wire_name() == value)
    }

    /// Returns the frozen non-claim this member publishes.
    #[must_use]
    pub const fn statement(self) -> &'static str {
        match self {
            Self::UnboundedFairnessOrLatency => WAIT_NON_CLAIMS[0],
            Self::ExternalPendingDeadlockDetection => WAIT_NON_CLAIMS[1],
            Self::SharedMemoryThreadSemantics => WAIT_NON_CLAIMS[2],
            Self::ProtectedPayloadDisclosure => WAIT_NON_CLAIMS[3],
        }
    }

    /// Returns the clause anchor that owns this non-claim.
    #[must_use]
    pub const fn requirement(self) -> &'static str {
        "GNT-24.10-wait-non-claims"
    }
}

/// The frozen wait non-claims of `GNT-24.10-wait-non-claims`, in declared order.
pub const WAIT_NON_CLAIMS: [&str; 4] = [
    "No unbounded fairness or latency promise: Section 24 declares no schedule and no clock, so it promises no bound on the logical instants before a wait is woken.",
    "No deadlock detection for genuinely pending external work: a pending host prerequisite the type contract permits to remain pending is classified as externally wakeable idle, never as closed-wait deadlock.",
    "No shared-memory thread semantics: a waiter identity names one declared wait and never a thread, a process, a memory location, or an execution context.",
    "No disclosure of a protected payload in a diagnostic: a wait diagnostic carries declared metadata, identities, and codes only, and a protected diagnostic is reachable only through the protected-diagnostic rules of GNT-15.10.",
];

/// The declared order of the wait non-claims (`GNT-24.10-wait-non-claims`).
pub const WAIT_NON_CLAIM_ORDER: [WaitNonClaimName; 4] = WaitNonClaimName::ALL;

/// One presented non-claim assertion (`GNT-24.10-wait-non-claims`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WaitNonClaimAssertion {
    claim: WaitNonClaimName,
    presented_as_guarantee: bool,
}

impl WaitNonClaimAssertion {
    /// Records whether one non-claim is presented as a guarantee.
    #[must_use]
    pub const fn new(claim: WaitNonClaimName, presented_as_guarantee: bool) -> Self {
        Self {
            claim,
            presented_as_guarantee,
        }
    }

    /// Returns the non-claim this assertion names.
    #[must_use]
    pub const fn claim(&self) -> WaitNonClaimName {
        self.claim
    }

    /// Returns whether this assertion presents the non-claim as a guarantee.
    #[must_use]
    pub const fn is_presented_as_guarantee(&self) -> bool {
        self.presented_as_guarantee
    }
}

/// Checks that no wait non-claim is presented as a guarantee
/// (`GNT-24.10-wait-non-claims`).
///
/// # Errors
///
/// Returns [`WaitError::NonClaimAsGuarantee`] for the first assertion that presents a
/// non-claim as a guarantee, because a non-claim MUST NOT be presented as a guarantee.
pub fn check_wait_non_claims(assertions: &[WaitNonClaimAssertion]) -> Result<(), WaitError> {
    for assertion in assertions {
        if assertion.presented_as_guarantee {
            return Err(WaitError::NonClaimAsGuarantee {
                claim: assertion.claim,
            });
        }
    }
    Ok(())
}

/// One frozen wait diagnostic code of `GNT-24`, one code per condition.
///
/// The registry is frozen: each condition of Section 24 owns exactly one code, each code
/// is anchored to exactly one clause, and no condition is reported under another
/// condition's code.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum WaitDiagnosticCode {
    /// `wait-arm-outside-snapshot`
    ArmOutsideSnapshot,
    /// `wait-cut-regression`
    CutRegression,
    /// `wait-deadlock-classification-refused`
    DeadlockClassificationRefused,
    /// `wait-decision-before-commit`
    DecisionBeforeCommit,
    /// `wait-decision-regression`
    DecisionRegression,
    /// `wait-duplicate-arm`
    DuplicateArm,
    /// `wait-duplicate-observation`
    DuplicateObservation,
    /// `wait-duplicate-waiter-refused`
    DuplicateWaiter,
    /// `wait-empty-arbitration`
    EmptyArbitration,
    /// `wait-empty-declared-identity`
    EmptyDeclaredIdentity,
    /// `wait-empty-wait-graph`
    EmptyWaitGraph,
    /// `wait-generation-exhausted`
    GenerationExhausted,
    /// `wait-graph-diagnostic-reported`
    ClosedWaitDeadlockReported,
    /// `wait-graph-diagnostic-too-large`
    WaitGraphDiagnosticTooLarge,
    /// `wait-malformed-quiescence-facts`
    MalformedQuiescenceFacts,
    /// `wait-missing-committed-decision`
    MissingCommittedDecision,
    /// `wait-missing-committed-readiness`
    MissingCommittedReadiness,
    /// `wait-no-winner-yet`
    NoWinnerYet,
    /// `wait-non-claim-as-guarantee`
    NonClaimAsGuarantee,
    /// `wait-readiness-regression`
    ReadinessRegression,
    /// `wait-registration-after-closure`
    RegistrationAfterClosure,
    /// `wait-registration-already-decided`
    RegistrationAlreadyDecided,
    /// `wait-registration-ordinal-regression`
    RegistrationOrdinalRegression,
    /// `wait-repeated-closure`
    RepeatedClosure,
    /// `wait-repeated-armed-alternative`
    RepeatedArmedAlternative,
    /// `wait-repeated-disposition`
    RepeatedDisposition,
    /// `wait-second-wake-refused`
    SecondWake,
    /// `wait-stale-registration-refused`
    StaleRegistration,
    /// `wait-stale-wake-refused`
    StaleWake,
    /// `wait-suspension-after-readiness`
    SuspensionAfterReadiness,
    /// `wait-suspension-without-recheck`
    SuspensionWithoutRecheck,
    /// `wait-unknown-resource`
    UnknownResource,
    /// `wait-unknown-resource-generation`
    UnknownResourceGeneration,
    /// `wait-unknown-waiter`
    UnknownWaiter,
    /// `wait-unpermitted-prerequisite`
    UnpermittedPrerequisite,
    /// `wait-unsettled-losing-arm`
    UnsettledLosingArm,
    /// `wait-winner-already-committed`
    WinnerAlreadyCommitted,
    /// `wait-winner-not-committed`
    WinnerNotCommitted,
    /// `wait-winner-not-losable`
    WinnerNotLosable,
}

impl WaitDiagnosticCode {
    /// Every frozen code, in sorted code order.
    pub const ALL: [Self; 39] = [
        Self::ArmOutsideSnapshot,
        Self::CutRegression,
        Self::DeadlockClassificationRefused,
        Self::DecisionBeforeCommit,
        Self::DecisionRegression,
        Self::DuplicateArm,
        Self::DuplicateObservation,
        Self::DuplicateWaiter,
        Self::EmptyArbitration,
        Self::EmptyDeclaredIdentity,
        Self::EmptyWaitGraph,
        Self::GenerationExhausted,
        Self::ClosedWaitDeadlockReported,
        Self::WaitGraphDiagnosticTooLarge,
        Self::MalformedQuiescenceFacts,
        Self::MissingCommittedDecision,
        Self::MissingCommittedReadiness,
        Self::NoWinnerYet,
        Self::NonClaimAsGuarantee,
        Self::ReadinessRegression,
        Self::RegistrationAfterClosure,
        Self::RegistrationAlreadyDecided,
        Self::RegistrationOrdinalRegression,
        Self::RepeatedArmedAlternative,
        Self::RepeatedClosure,
        Self::RepeatedDisposition,
        Self::SecondWake,
        Self::StaleRegistration,
        Self::StaleWake,
        Self::SuspensionAfterReadiness,
        Self::SuspensionWithoutRecheck,
        Self::UnknownResource,
        Self::UnknownResourceGeneration,
        Self::UnknownWaiter,
        Self::UnpermittedPrerequisite,
        Self::UnsettledLosingArm,
        Self::WinnerAlreadyCommitted,
        Self::WinnerNotCommitted,
        Self::WinnerNotLosable,
    ];

    /// Returns the exact frozen code spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ArmOutsideSnapshot => "wait-arm-outside-snapshot",
            Self::CutRegression => "wait-cut-regression",
            Self::DeadlockClassificationRefused => "wait-deadlock-classification-refused",
            Self::DecisionBeforeCommit => "wait-decision-before-commit",
            Self::DecisionRegression => "wait-decision-regression",
            Self::DuplicateArm => "wait-duplicate-arm",
            Self::DuplicateObservation => "wait-duplicate-observation",
            Self::DuplicateWaiter => "wait-duplicate-waiter-refused",
            Self::EmptyArbitration => "wait-empty-arbitration",
            Self::EmptyDeclaredIdentity => "wait-empty-declared-identity",
            Self::EmptyWaitGraph => "wait-empty-wait-graph",
            Self::GenerationExhausted => "wait-generation-exhausted",
            Self::ClosedWaitDeadlockReported => "wait-graph-diagnostic-reported",
            Self::WaitGraphDiagnosticTooLarge => "wait-graph-diagnostic-too-large",
            Self::MalformedQuiescenceFacts => "wait-malformed-quiescence-facts",
            Self::MissingCommittedDecision => "wait-missing-committed-decision",
            Self::MissingCommittedReadiness => "wait-missing-committed-readiness",
            Self::NoWinnerYet => "wait-no-winner-yet",
            Self::NonClaimAsGuarantee => "wait-non-claim-as-guarantee",
            Self::ReadinessRegression => "wait-readiness-regression",
            Self::RegistrationAfterClosure => "wait-registration-after-closure",
            Self::RegistrationAlreadyDecided => "wait-registration-already-decided",
            Self::RegistrationOrdinalRegression => "wait-registration-ordinal-regression",
            Self::RepeatedArmedAlternative => "wait-repeated-armed-alternative",
            Self::RepeatedClosure => "wait-repeated-closure",
            Self::RepeatedDisposition => "wait-repeated-disposition",
            Self::SecondWake => "wait-second-wake-refused",
            Self::StaleRegistration => "wait-stale-registration-refused",
            Self::StaleWake => "wait-stale-wake-refused",
            Self::SuspensionAfterReadiness => "wait-suspension-after-readiness",
            Self::SuspensionWithoutRecheck => "wait-suspension-without-recheck",
            Self::UnknownResource => "wait-unknown-resource",
            Self::UnknownResourceGeneration => "wait-unknown-resource-generation",
            Self::UnknownWaiter => "wait-unknown-waiter",
            Self::UnpermittedPrerequisite => "wait-unpermitted-prerequisite",
            Self::UnsettledLosingArm => "wait-unsettled-losing-arm",
            Self::WinnerAlreadyCommitted => "wait-winner-already-committed",
            Self::WinnerNotCommitted => "wait-winner-not-committed",
            Self::WinnerNotLosable => "wait-winner-not-losable",
        }
    }

    /// Returns the same exact frozen code spelling as [`Self::as_str`].
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        self.as_str()
    }

    /// Returns the frozen one-line meaning of this code.
    #[must_use]
    pub const fn meaning(self) -> &'static str {
        match self {
            Self::ArmOutsideSnapshot => {
                "an observation or disposition named an arm outside the frozen snapshot"
            }
            Self::CutRegression => "a durable cut would move backwards or skip an uncommitted cut",
            Self::DeadlockClassificationRefused => {
                "a deadlock transition was presented for a class that is not closed-wait deadlock"
            }
            Self::DecisionBeforeCommit => {
                "a decision was presented before the decision cut was committed"
            }
            Self::DecisionRegression => "a presented decision differs from the committed decision",
            Self::DuplicateArm => "one declared arm key was presented twice",
            Self::DuplicateObservation => "one arm was observed twice at one arbitration instant",
            Self::DuplicateWaiter => "one waiter slot already holds a live wait",
            Self::EmptyArbitration => "an arbitration was opened with no armed alternative",
            Self::EmptyDeclaredIdentity => "a declared identity was empty or whitespace only",
            Self::EmptyWaitGraph => {
                "a wait-graph diagnostic was requested with no waiting identity"
            }
            Self::GenerationExhausted => "a waiter-generation fence reached the counter maximum",
            Self::ClosedWaitDeadlockReported => {
                "a closed-wait deadlock was classified and reported as a bounded wait graph"
            }
            Self::WaitGraphDiagnosticTooLarge => {
                "a wait graph exceeded the declared node or edge maximum"
            }
            Self::MalformedQuiescenceFacts => {
                "the declared quiescence facts cannot describe an observation"
            }
            Self::MissingCommittedDecision => {
                "the decision cut is committed but records no decision"
            }
            Self::MissingCommittedReadiness => {
                "the readiness cut is committed but records no ready cause"
            }
            Self::NoWinnerYet => "a waiter has no winner yet",
            Self::NonClaimAsGuarantee => "a wait non-claim was presented as a guarantee",
            Self::ReadinessRegression => "another readiness cause is already committed",
            Self::RegistrationAfterClosure => {
                "a registration was presented for a closed waitable resource"
            }
            Self::RegistrationAlreadyDecided => {
                "a wait already published its single atomic registration decision"
            }
            Self::RegistrationOrdinalRegression => {
                "a registration did not move the waiter slot's ordinal strictly forward"
            }
            Self::RepeatedArmedAlternative => {
                "one waiter identity was armed by two alternatives of one snapshot"
            }
            Self::RepeatedClosure => "a waitable resource was closed a second time",
            Self::RepeatedDisposition => "one losing arm received two dispositions",
            Self::SecondWake => "a wait already has a single source-visible winner",
            Self::StaleRegistration => {
                "a registration presented a fence the waiter slot already retired"
            }
            Self::StaleWake => "a wake did not name the fence the live wait holds",
            Self::SuspensionAfterReadiness => {
                "a suspension was attempted after the atomic step decided the wait was already ready"
            }
            Self::SuspensionWithoutRecheck => {
                "a suspension was attempted with no published registration decision"
            }
            Self::UnknownResource => "no wait of the waitable resource is known",
            Self::UnknownResourceGeneration => {
                "no wait of the landed waitable-resource generation is known"
            }
            Self::UnknownWaiter => "the waiter identity is not known",
            Self::UnpermittedPrerequisite => {
                "a presented external prerequisite is outside the permitted set"
            }
            Self::UnsettledLosingArm => "a losing arm received no disposition",
            Self::WinnerAlreadyCommitted => "a winner is already committed",
            Self::WinnerNotCommitted => "no winner is committed yet",
            Self::WinnerNotLosable => "a disposition named the committed winner",
        }
    }

    /// Returns the clause anchor that owns this code.
    #[must_use]
    pub const fn requirement(self) -> &'static str {
        match self {
            Self::RegistrationAlreadyDecided
            | Self::SuspensionWithoutRecheck
            | Self::SuspensionAfterReadiness => {
                "GNT-24.1-atomic-registration-and-readiness-recheck"
            }
            Self::EmptyDeclaredIdentity | Self::GenerationExhausted => {
                "GNT-24.2-wait-identity-and-generations"
            }
            Self::SecondWake | Self::NoWinnerYet => "GNT-24.3-wake-causes-and-wake-ownership",
            Self::DuplicateWaiter
            | Self::StaleRegistration
            | Self::StaleWake
            | Self::RegistrationOrdinalRegression
            | Self::UnknownWaiter => "GNT-24.4-stale-wake-fencing-and-waiter-reuse",
            Self::UnknownResource
            | Self::UnknownResourceGeneration
            | Self::RepeatedClosure
            | Self::RegistrationAfterClosure => "GNT-24.5-producer-loss-and-closure",
            Self::EmptyArbitration
            | Self::DuplicateArm
            | Self::RepeatedArmedAlternative
            | Self::DuplicateObservation
            | Self::ArmOutsideSnapshot
            | Self::WinnerAlreadyCommitted => {
                "GNT-24.6-select-and-race-snapshots-and-winner-permanence"
            }
            Self::WinnerNotCommitted
            | Self::WinnerNotLosable
            | Self::UnsettledLosingArm
            | Self::RepeatedDisposition => "GNT-24.7-losing-arm-ownership-and-nondeterminism",
            Self::EmptyWaitGraph
            | Self::WaitGraphDiagnosticTooLarge
            | Self::MalformedQuiescenceFacts
            | Self::DeadlockClassificationRefused
            | Self::ClosedWaitDeadlockReported => "GNT-24.8-quiescence-classification",
            Self::CutRegression
            | Self::MissingCommittedDecision
            | Self::MissingCommittedReadiness
            | Self::DecisionBeforeCommit
            | Self::DecisionRegression
            | Self::ReadinessRegression
            | Self::UnpermittedPrerequisite => "GNT-24.9-durable-wait-and-winner-reconstruction",
            Self::NonClaimAsGuarantee => "GNT-24.10-wait-non-claims",
        }
    }
}

/// One refusal or report of the wait, wakeup, arbitration, and quiescence model.
///
/// Every condition of Section 24 owns one variant and one frozen
/// [`WaitDiagnosticCode`], so a refusal names the clause that owns its condition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WaitError {
    /// An observation or disposition named an arm outside the frozen snapshot.
    ArmOutsideSnapshot {
        /// The arm outside the snapshot.
        arm: ArmId,
    },
    /// A durable cut would move backwards or skip an uncommitted cut.
    CutRegression {
        /// The committed cut.
        current: DurableWaitCut,
        /// The refused cut.
        next: DurableWaitCut,
    },
    /// A deadlock transition was presented for a class that is not closed-wait deadlock.
    DeadlockClassificationRefused {
        /// The refused class.
        class: QuiescenceClass,
    },
    /// A decision was presented before the decision cut was committed.
    DecisionBeforeCommit {
        /// The waiter that has not committed a decision.
        wait: WaitId,
    },
    /// A presented decision differs from the committed decision.
    DecisionRegression {
        /// The waiter whose decision is committed.
        wait: WaitId,
        /// The committed decision.
        committed: WaitDecision,
        /// The presented decision.
        presented: WaitDecision,
    },
    /// One declared arm key was presented twice.
    DuplicateArm {
        /// The repeated arm key.
        arm: ArmId,
    },
    /// One arm was observed twice at one arbitration instant.
    DuplicateObservation {
        /// The repeated arm key.
        arm: ArmId,
    },
    /// One waiter slot already holds a live wait.
    DuplicateWaiter {
        /// The waiter that is already live or already armed.
        wait: WaitId,
    },
    /// An arbitration was opened with no armed alternative.
    EmptyArbitration,
    /// A declared identity was empty or whitespace only.
    EmptyDeclaredIdentity {
        /// The declared input that was empty.
        input: IdentityInput,
    },
    /// A wait-graph diagnostic was requested with no waiting identity.
    EmptyWaitGraph,
    /// A waiter-generation fence reached the counter maximum.
    GenerationExhausted {
        /// The exhausted fence.
        generation: WaitGeneration,
    },
    /// The declared quiescence facts cannot describe an observation.
    MalformedQuiescenceFacts {
        /// The declared live wait count.
        live_waits: usize,
        /// The declared blocked wait count.
        blocked: usize,
        /// The declared resumable work count.
        resulting: usize,
        /// The declared admitted work count.
        admitted: usize,
    },
    /// The decision cut is committed but records no decision.
    MissingCommittedDecision {
        /// The waiter whose decision is missing.
        wait: WaitId,
    },
    /// The readiness cut is committed but records no ready cause.
    MissingCommittedReadiness {
        /// The waiter whose readiness is missing.
        wait: WaitId,
    },
    /// A waiter has no winner yet.
    NoWinnerYet {
        /// The unsettled waiter.
        wait: WaitId,
    },
    /// A wait non-claim was presented as a guarantee.
    NonClaimAsGuarantee {
        /// The non-claim that was presented as a guarantee.
        claim: WaitNonClaimName,
    },
    /// Another readiness cause is already committed.
    ReadinessRegression {
        /// The waiter whose readiness is committed.
        wait: WaitId,
        /// The committed readiness cause.
        committed: WakeCause,
        /// The presented readiness cause.
        presented: WakeCause,
    },
    /// A registration was presented for a closed waitable resource.
    RegistrationAfterClosure {
        /// The refused waiter.
        wait: WaitId,
        /// The closed waitable resource.
        resource: WaitResourceId,
    },
    /// A wait already published its single atomic registration decision.
    RegistrationAlreadyDecided {
        /// The waiter that already decided.
        wait: WaitId,
    },
    /// A registration did not move the waiter slot's ordinal strictly forward.
    ///
    /// The refusal names the waiter, the ordinal the slot already retired, and the
    /// presented ordinal.
    RegistrationOrdinalRegression {
        /// The refused waiter.
        wait: WaitId,
        /// The ordinal the waiter slot already retired.
        retired: u32,
        /// The presented registration ordinal.
        presented: u32,
    },
    /// One waiter identity was armed by two alternatives of one frozen snapshot.
    ///
    /// The refusal names the repeated arm key and the waiter identity that alternative
    /// armed a second time.
    RepeatedArmedAlternative {
        /// The arm that repeated the waiter identity.
        arm: ArmId,
        /// The waiter identity another alternative already armed.
        wait: WaitId,
    },
    /// A waitable resource was closed a second time.
    RepeatedClosure {
        /// The already closed waitable resource.
        resource: WaitResourceId,
    },
    /// One losing arm received two dispositions.
    RepeatedDisposition {
        /// The repeated arm key.
        arm: ArmId,
    },
    /// A wake already applied to one wait is refused as a second wake.
    ///
    /// The refusal names the waiter, the held fence, and the presented fence, and it also
    /// names the recorded winner cause of the settled wait and the cause of the repeated
    /// wake.
    SecondWake {
        /// The already settled waiter.
        wait: WaitId,
        /// The fence the settled wait held.
        held: WaitGeneration,
        /// The presented fence.
        presented: WaitGeneration,
        /// The recorded winner cause.
        winner: WakeCause,
        /// The cause of the repeated wake.
        repeated: WakeCause,
    },
    /// A registration presented a fence the waiter slot already retired.
    StaleRegistration {
        /// The refused waiter.
        wait: WaitId,
        /// The retired fence the slot holds.
        held: WaitGeneration,
        /// The presented fence.
        presented: WaitGeneration,
    },
    /// A wake did not name the fence the live wait holds.
    StaleWake {
        /// The addressed waiter.
        wait: WaitId,
        /// The fence the live wait holds.
        held: WaitGeneration,
        /// The presented fence.
        presented: WaitGeneration,
    },
    /// A suspension was attempted after the atomic step decided the wait was ready.
    SuspensionAfterReadiness {
        /// The ready waiter.
        wait: WaitId,
        /// The readiness cause the atomic step observed.
        cause: WakeCause,
    },
    /// A suspension was attempted with no published registration decision.
    SuspensionWithoutRecheck {
        /// The waiter with no decision.
        wait: WaitId,
    },
    /// No wait of the waitable resource is known.
    UnknownResource {
        /// The unknown waitable resource.
        resource: WaitResourceId,
    },
    /// No wait of the landed waitable-resource generation is known.
    UnknownResourceGeneration {
        /// The waitable resource.
        resource: WaitResourceId,
        /// The unknown landed resource generation.
        generation: ResourceGenerationId,
    },
    /// The waiter identity is not known.
    ///
    /// The refusal names the waiter, the held fence, and the presented fence: the wait set
    /// holds no fence for a waiter it never held, so the held fence is absent rather than
    /// invented.
    UnknownWaiter {
        /// The unknown waiter.
        wait: WaitId,
        /// The fence the wait set holds for the addressed waiter slot, if it holds one.
        held: Option<WaitGeneration>,
        /// The presented fence.
        presented: WaitGeneration,
    },
    /// A presented external prerequisite is outside the permitted set.
    UnpermittedPrerequisite {
        /// The unpermitted prerequisite key.
        key: PrerequisiteRef,
    },
    /// A losing arm received no disposition.
    UnsettledLosingArm {
        /// The unsettled arm key.
        arm: ArmId,
    },
    /// A winner is already committed.
    WinnerAlreadyCommitted {
        /// The committed winner key.
        arm: ArmId,
    },
    /// No winner is committed yet.
    WinnerNotCommitted,
    /// A disposition named the committed winner.
    WinnerNotLosable {
        /// The committed winner key.
        arm: ArmId,
    },
    /// A wait graph exceeded the declared node or edge maximum.
    WaitGraphDiagnosticTooLarge {
        /// The presented node count.
        nodes: usize,
        /// The presented edge count.
        edges: usize,
    },
}

impl WaitError {
    /// Returns the frozen diagnostic code of this condition.
    #[must_use]
    pub const fn code(&self) -> WaitDiagnosticCode {
        match self {
            Self::ArmOutsideSnapshot { .. } => WaitDiagnosticCode::ArmOutsideSnapshot,
            Self::CutRegression { .. } => WaitDiagnosticCode::CutRegression,
            Self::DeadlockClassificationRefused { .. } => {
                WaitDiagnosticCode::DeadlockClassificationRefused
            }
            Self::DecisionBeforeCommit { .. } => WaitDiagnosticCode::DecisionBeforeCommit,
            Self::DecisionRegression { .. } => WaitDiagnosticCode::DecisionRegression,
            Self::DuplicateArm { .. } => WaitDiagnosticCode::DuplicateArm,
            Self::DuplicateObservation { .. } => WaitDiagnosticCode::DuplicateObservation,
            Self::DuplicateWaiter { .. } => WaitDiagnosticCode::DuplicateWaiter,
            Self::EmptyArbitration => WaitDiagnosticCode::EmptyArbitration,
            Self::EmptyDeclaredIdentity { .. } => WaitDiagnosticCode::EmptyDeclaredIdentity,
            Self::EmptyWaitGraph => WaitDiagnosticCode::EmptyWaitGraph,
            Self::GenerationExhausted { .. } => WaitDiagnosticCode::GenerationExhausted,
            Self::MalformedQuiescenceFacts { .. } => WaitDiagnosticCode::MalformedQuiescenceFacts,
            Self::MissingCommittedDecision { .. } => WaitDiagnosticCode::MissingCommittedDecision,
            Self::MissingCommittedReadiness { .. } => WaitDiagnosticCode::MissingCommittedReadiness,
            Self::NoWinnerYet { .. } => WaitDiagnosticCode::NoWinnerYet,
            Self::NonClaimAsGuarantee { .. } => WaitDiagnosticCode::NonClaimAsGuarantee,
            Self::ReadinessRegression { .. } => WaitDiagnosticCode::ReadinessRegression,
            Self::RegistrationAfterClosure { .. } => WaitDiagnosticCode::RegistrationAfterClosure,
            Self::RegistrationAlreadyDecided { .. } => {
                WaitDiagnosticCode::RegistrationAlreadyDecided
            }
            Self::RegistrationOrdinalRegression { .. } => {
                WaitDiagnosticCode::RegistrationOrdinalRegression
            }
            Self::RepeatedArmedAlternative { .. } => WaitDiagnosticCode::RepeatedArmedAlternative,
            Self::RepeatedClosure { .. } => WaitDiagnosticCode::RepeatedClosure,
            Self::RepeatedDisposition { .. } => WaitDiagnosticCode::RepeatedDisposition,
            Self::SecondWake { .. } => WaitDiagnosticCode::SecondWake,
            Self::StaleRegistration { .. } => WaitDiagnosticCode::StaleRegistration,
            Self::StaleWake { .. } => WaitDiagnosticCode::StaleWake,
            Self::SuspensionAfterReadiness { .. } => WaitDiagnosticCode::SuspensionAfterReadiness,
            Self::SuspensionWithoutRecheck { .. } => WaitDiagnosticCode::SuspensionWithoutRecheck,
            Self::UnknownResource { .. } => WaitDiagnosticCode::UnknownResource,
            Self::UnknownResourceGeneration { .. } => WaitDiagnosticCode::UnknownResourceGeneration,
            Self::UnknownWaiter { .. } => WaitDiagnosticCode::UnknownWaiter,
            Self::UnpermittedPrerequisite { .. } => WaitDiagnosticCode::UnpermittedPrerequisite,
            Self::UnsettledLosingArm { .. } => WaitDiagnosticCode::UnsettledLosingArm,
            Self::WinnerAlreadyCommitted { .. } => WaitDiagnosticCode::WinnerAlreadyCommitted,
            Self::WinnerNotCommitted => WaitDiagnosticCode::WinnerNotCommitted,
            Self::WinnerNotLosable { .. } => WaitDiagnosticCode::WinnerNotLosable,
            Self::WaitGraphDiagnosticTooLarge { .. } => {
                WaitDiagnosticCode::WaitGraphDiagnosticTooLarge
            }
        }
    }

    /// Returns the requirement anchor that owns this condition.
    #[must_use]
    pub const fn requirement(&self) -> &'static str {
        match self {
            Self::EmptyDeclaredIdentity { input } => input.requirement(),
            _ => self.code().requirement(),
        }
    }

    /// Returns the waiter identity this refusal addresses, if it addresses one.
    #[must_use]
    pub const fn wait(&self) -> Option<&WaitId> {
        match self {
            Self::UnknownWaiter { wait, .. }
            | Self::StaleWake { wait, .. }
            | Self::StaleRegistration { wait, .. }
            | Self::SecondWake { wait, .. } => Some(wait),
            _ => None,
        }
    }

    /// Returns the fence this refusal holds, if it names one.
    ///
    /// A refusal that names no held fence returns `None`. The unknown-waiter refusal of
    /// `GNT-24.4-stale-wake-fencing-and-waiter-reuse` names the held fence it knows, which
    /// is none for a waiter the wait set never held, so the absence is reported rather than
    /// an invented fence.
    #[must_use]
    pub const fn held_fence(&self) -> Option<WaitGeneration> {
        match self {
            Self::StaleWake { held, .. }
            | Self::StaleRegistration { held, .. }
            | Self::SecondWake { held, .. } => Some(*held),
            Self::UnknownWaiter { held, .. } => *held,
            _ => None,
        }
    }

    /// Returns the presented fence this refusal names, if it names one.
    #[must_use]
    pub const fn presented_fence(&self) -> Option<WaitGeneration> {
        match self {
            Self::UnknownWaiter { presented, .. }
            | Self::StaleWake { presented, .. }
            | Self::StaleRegistration { presented, .. }
            | Self::SecondWake { presented, .. } => Some(*presented),
            _ => None,
        }
    }
}

impl fmt::Display for WaitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code().as_str())?;
        formatter.write_str(": ")?;
        match self {
            Self::ArmOutsideSnapshot { arm } => write!(
                formatter,
                "the arm `{arm}` does not belong to the frozen snapshot"
            ),
            Self::CutRegression { current, next } => write!(
                formatter,
                "the durable cut `{}` does not follow the committed cut `{}`",
                next.wire_name(),
                current.wire_name()
            ),
            Self::DeadlockClassificationRefused { class } => write!(
                formatter,
                "the class `{}` is not a closed-wait deadlock transition",
                class.wire_name()
            ),
            Self::DecisionBeforeCommit { wait } => write!(
                formatter,
                "the decision of `{wait}` was presented before the decision cut was committed"
            ),
            Self::DecisionRegression {
                wait,
                committed,
                presented,
            } => write!(
                formatter,
                "the presented decision `{presented}` of `{wait}` differs from the committed `{committed}`"
            ),
            Self::DuplicateArm { arm } => {
                write!(formatter, "the arm `{arm}` was declared twice")
            }
            Self::DuplicateObservation { arm } => write!(
                formatter,
                "the arm `{arm}` was observed twice at one arbitration instant"
            ),
            Self::DuplicateWaiter { wait } => {
                write!(formatter, "the waiter `{wait}` is already live")
            }
            Self::EmptyArbitration => formatter.write_str("no armed alternative was declared"),
            Self::EmptyDeclaredIdentity { input } => write!(
                formatter,
                "the declared `{}` identity is empty or whitespace only",
                input.wire_name()
            ),
            Self::EmptyWaitGraph => {
                formatter.write_str("the wait graph declares no waiting identity")
            }
            Self::GenerationExhausted { generation } => write!(
                formatter,
                "the fence {generation} reached the counter maximum"
            ),
            Self::MalformedQuiescenceFacts {
                live_waits,
                blocked,
                resulting,
                admitted,
            } => write!(
                formatter,
                "the facts declare {blocked} blocked waits of {live_waits} and {resulting} resumable units of {admitted}"
            ),
            Self::MissingCommittedDecision { wait } => write!(
                formatter,
                "the decision cut of `{wait}` records no decision"
            ),
            Self::MissingCommittedReadiness { wait } => write!(
                formatter,
                "the readiness cut of `{wait}` records no ready cause"
            ),
            Self::NoWinnerYet { wait } => {
                write!(formatter, "the waiter `{wait}` has no winner yet")
            }
            Self::NonClaimAsGuarantee { claim } => write!(
                formatter,
                "the non-claim `{}` was presented as a guarantee",
                claim.wire_name()
            ),
            Self::ReadinessRegression {
                wait,
                committed,
                presented,
            } => write!(
                formatter,
                "the presented readiness `{presented}` of `{wait}` differs from the committed `{committed}`"
            ),
            Self::RegistrationAfterClosure { wait, resource } => write!(
                formatter,
                "the waiter `{wait}` was registered for the closed resource `{resource}`"
            ),
            Self::RegistrationAlreadyDecided { wait } => write!(
                formatter,
                "the waiter `{wait}` already published its atomic registration decision"
            ),
            Self::RegistrationOrdinalRegression {
                wait,
                retired,
                presented,
            } => write!(
                formatter,
                "the waiter `{wait}` presented ordinal {presented} against the retired {retired}"
            ),
            Self::RepeatedArmedAlternative { arm, wait } => write!(
                formatter,
                "the arm `{arm}` armed the waiter `{wait}` a second time in one snapshot"
            ),
            Self::RepeatedClosure { resource } => {
                write!(formatter, "the resource `{resource}` is already closed")
            }
            Self::RepeatedDisposition { arm } => {
                write!(formatter, "the arm `{arm}` received two dispositions")
            }
            Self::SecondWake {
                wait,
                held,
                presented,
                winner,
                repeated,
            } => write!(
                formatter,
                "the waiter `{wait}` holds the winner `{winner}` under fence {held} and refuses `{repeated}` under fence {presented}"
            ),
            Self::StaleRegistration {
                wait,
                held,
                presented,
            } => write!(
                formatter,
                "the waiter `{wait}` presented fence {presented} against the retired {held}"
            ),
            Self::StaleWake {
                wait,
                held,
                presented,
            } => write!(
                formatter,
                "the wake of `{wait}` presented fence {presented} against the held {held}"
            ),
            Self::SuspensionAfterReadiness { wait, cause } => write!(
                formatter,
                "the waiter `{wait}` is already ready with `{cause}` and cannot suspend"
            ),
            Self::SuspensionWithoutRecheck { wait } => write!(
                formatter,
                "the waiter `{wait}` published no registration decision to suspend under"
            ),
            Self::UnknownResource { resource } => {
                write!(formatter, "the resource `{resource}` holds no known wait")
            }
            Self::UnknownResourceGeneration {
                resource,
                generation,
            } => write!(
                formatter,
                "the resource `{resource}` holds no wait of generation `{generation}`"
            ),
            Self::UnknownWaiter {
                wait,
                held,
                presented,
            } => match held {
                Some(held) => write!(
                    formatter,
                    "the waiter `{wait}` is not known; the held fence is {held} and the presented fence is {presented}"
                ),
                None => write!(
                    formatter,
                    "the waiter `{wait}` is not known, holds no fence, and presented fence {presented}"
                ),
            },
            Self::UnpermittedPrerequisite { key } => write!(
                formatter,
                "the prerequisite `{key}` is outside the permitted set"
            ),
            Self::UnsettledLosingArm { arm } => {
                write!(formatter, "the losing arm `{arm}` received no disposition")
            }
            Self::WinnerAlreadyCommitted { arm } => {
                write!(formatter, "the winner `{arm}` is already committed")
            }
            Self::WinnerNotCommitted => formatter.write_str("no winner is committed yet"),
            Self::WinnerNotLosable { arm } => write!(
                formatter,
                "the committed winner `{arm}` cannot be settled as a losing arm"
            ),
            Self::WaitGraphDiagnosticTooLarge { nodes, edges } => write!(
                formatter,
                "the wait graph of {nodes} nodes and {edges} edges exceeds the declared maximum"
            ),
        }
    }
}

impl std::error::Error for WaitError {}

#[cfg(test)]
mod tests {
    use super::{
        Arbitration, ArbitrationDecision, ArmDisposition, ArmDispositionKind, ArmId,
        ArmObservation, ArmedAlternative, DurableWaitCut, DurableWaitRecord, QuiescenceClass,
        QuiescenceFacts, QuiescenceRemedy, ReadinessObservation, RegistrationOutcome, WAIT_CLAUSES,
        WAIT_NON_CLAIMS, WaitDecision, WaitDiagnosticCode, WaitError, WaitGeneration, WaitId,
        WaitNonClaimAssertion, WaitNonClaimName, WaitOwnerId, WaitRecoveryDecision,
        WaitRegistration, WaitResourceId, WaitSet, WakeCause, WakeOutcome, check_wait_non_claims,
        classify_quiescence, observe_quiescence,
    };
    use crate::CanonicalPath;
    use crate::approval::LogicalOperationId;
    use crate::facts::{StaticSiteId, StructuralPosition};
    use crate::operation::ResourceGenerationId;
    use crate::protected::AuditAccess;

    fn canonical(value: &str) -> CanonicalPath {
        match CanonicalPath::new(value) {
            Ok(path) => path,
            Err(error) => panic!("the declared path {value} is canonical: {error:?}"),
        }
    }

    fn site() -> StaticSiteId {
        match StructuralPosition::new(vec![0, 1]) {
            Ok(position) => StaticSiteId::new(canonical("crate::main"), position),
            Err(error) => panic!("the declared position is nonempty: {error:?}"),
        }
    }

    fn generation(counter: u64) -> ResourceGenerationId {
        let site = site();
        let operation = LogicalOperationId::derive(&canonical("crate::read"), &site);
        ResourceGenerationId::derive(&operation, &site, counter)
    }

    fn owner() -> WaitOwnerId {
        match WaitOwnerId::new("crate::main") {
            Ok(owner) => owner,
            Err(error) => panic!("the declared owner is named: {error}"),
        }
    }

    fn other_owner() -> WaitOwnerId {
        match WaitOwnerId::new("crate::worker") {
            Ok(owner) => owner,
            Err(error) => panic!("the declared owner is named: {error}"),
        }
    }

    fn resource() -> WaitResourceId {
        match WaitResourceId::new("std.io.read") {
            Ok(resource) => resource,
            Err(error) => panic!("the declared resource is named: {error}"),
        }
    }

    fn arm(key: &str) -> ArmId {
        match ArmId::new(key) {
            Ok(arm) => arm,
            Err(error) => panic!("the declared arm {key} is named: {error}"),
        }
    }

    fn fence() -> WaitGeneration {
        WaitGeneration::FIRST
    }

    fn next_fence() -> WaitGeneration {
        match WaitGeneration::FIRST.succeeding() {
            Ok(next) => next,
            Err(error) => panic!("the declared fence advances: {error}"),
        }
    }

    fn waiter(ordinal: u32, fence: WaitGeneration) -> WaitId {
        WaitId::derive(&owner(), &resource(), &generation(1), fence, ordinal)
    }

    fn registration(ordinal: u32, fence: WaitGeneration) -> WaitRegistration {
        WaitRegistration::new(
            waiter(ordinal, fence),
            owner(),
            resource(),
            generation(1),
            fence,
            ordinal,
        )
    }

    fn armed(key: &str, wait: WaitId) -> ArmedAlternative {
        ArmedAlternative::new(arm(key), wait)
    }

    fn decided(arms: Vec<ArmedAlternative>, observations: &[ArmObservation]) -> Arbitration {
        let arbitration = match Arbitration::open(arms) {
            Ok(arbitration) => arbitration,
            Err(error) => panic!("the declared arm set opens: {error}"),
        };
        match arbitration.decide(observations) {
            Ok(ArbitrationDecision::Committed(arbitration)) => arbitration,
            other => panic!("the declared observation set decides a winner: {other:?}"),
        }
    }

    fn refused_decision(arms: Vec<ArmedAlternative>, observations: &[ArmObservation]) -> WaitError {
        let arbitration = match Arbitration::open(arms) {
            Ok(arbitration) => arbitration,
            Err(error) => panic!("the declared arm set opens: {error}"),
        };
        match arbitration.decide(observations) {
            Ok(other) => panic!("the declared observations are refused, not {other:?}"),
            Err(error) => error,
        }
    }

    fn refused_settlement(dispositions: &[ArmDisposition]) -> WaitError {
        let arbitration = decided(
            vec![
                armed("first", waiter(1, fence())),
                armed("second", waiter(2, fence())),
            ],
            &[ArmObservation::new(arm("first"), WakeCause::Delivery)],
        );
        let settlement = match arbitration.into_losing_settlement() {
            Ok(settlement) => settlement,
            Err(error) => panic!("a decided arbitration yields a settlement: {error}"),
        };
        match settlement.settle(dispositions) {
            Ok(report) => panic!("the declared dispositions are refused, not {report:?}"),
            Err(error) => error,
        }
    }

    #[test]
    fn registration_refuses_an_ordinal_that_does_not_move_the_slot_forward() {
        let mut waits = WaitSet::new();
        let mut first = registration(2, fence());
        assert_eq!(
            first.register_and_recheck(ReadinessObservation::NotReady),
            Ok(RegistrationOutcome::Registered)
        );
        assert_eq!(waits.register(&first), Ok(()));
        assert_eq!(
            waits
                .wake(first.id(), fence(), WakeCause::Delivery)
                .map(|record| record.cause()),
            Ok(WakeCause::Delivery)
        );

        // The presented fence is strictly greater than the retired fence, so only the
        // ordinal can refuse this reuse of the slot.
        let mut earlier = registration(1, next_fence());
        assert_eq!(
            earlier.register_and_recheck(ReadinessObservation::NotReady),
            Ok(RegistrationOutcome::Registered)
        );
        assert_eq!(earlier.ordinal(), 1);
        assert_eq!(first.ordinal(), 2);
        match waits.register(&earlier) {
            Err(error) => {
                assert_eq!(
                    error.code(),
                    WaitDiagnosticCode::RegistrationOrdinalRegression
                );
                assert_eq!(
                    error.requirement(),
                    "GNT-24.4-stale-wake-fencing-and-waiter-reuse"
                );
            }
            Ok(()) => panic!("a reused slot never returns to an earlier registration ordinal"),
        }
        assert_eq!(waits.live_count(), 0);

        let mut later = registration(3, next_fence());
        assert_eq!(
            later.register_and_recheck(ReadinessObservation::NotReady),
            Ok(RegistrationOutcome::Registered)
        );
        assert_eq!(waits.register(&later), Ok(()));
        assert_eq!(waits.live_count(), 1);
    }

    #[test]
    fn stop_requests_and_task_settlements_are_causes_and_removal_is_a_withdrawal() {
        assert_eq!(WakeCause::ALL.len(), 5);
        assert_eq!(
            WakeCause::ALL.map(WakeCause::wire_name),
            [
                "delivery",
                "resource-closure",
                "cancellation",
                "stop-request",
                "timeout"
            ]
        );
        assert_eq!(WakeCause::from_wire_name("waiter-removal"), None);
        for cause in WakeCause::ALL {
            assert_eq!(
                cause.requirement(),
                "GNT-24.3-wake-causes-and-wake-ownership"
            );
        }

        let mut waits = WaitSet::new();
        let mut stopped = registration(1, fence());
        assert_eq!(
            stopped.register_and_recheck(ReadinessObservation::NotReady),
            Ok(RegistrationOutcome::Registered)
        );
        assert_eq!(waits.register(&stopped), Ok(()));
        assert_eq!(
            waits
                .wake(stopped.id(), fence(), WakeCause::StopRequest)
                .map(|record| record.cause()),
            Ok(WakeCause::StopRequest)
        );

        // A task settlement is the delivery cause, so it needs no sixth cause either.
        let mut settled = registration(2, next_fence());
        assert_eq!(
            settled.register_and_recheck(ReadinessObservation::Ready(WakeCause::Delivery)),
            Ok(RegistrationOutcome::AlreadyReady(WakeCause::Delivery))
        );

        // The owner's removal is a withdrawal rather than a wake cause, so it settles no
        // winner and reports no cause.
        let mut removed = registration(3, next_fence());
        assert_eq!(
            removed.register_and_recheck(ReadinessObservation::NotReady),
            Ok(RegistrationOutcome::Registered)
        );
        assert_eq!(waits.register(&removed), Ok(()));
        let withdrawal = match waits.remove_waiter(removed.id(), next_fence()) {
            Ok(withdrawal) => withdrawal,
            Err(error) => panic!("the owner withdraws its own live wait: {error}"),
        };
        assert_eq!(withdrawal.wait(), removed.id());
        assert_eq!(waits.winner(removed.id()), None);
        assert!(!waits.is_live(removed.id()));
    }

    #[test]
    fn clause_keys_are_the_eleven_section_anchors_in_order() {
        assert_eq!(WAIT_CLAUSES.len(), 11);
        for (position, key) in WAIT_CLAUSES.iter().enumerate() {
            let expected = format!("GNT-24.{position}");
            assert!(
                key.starts_with(&expected),
                "clause {position} is {key}, which does not start with {expected}"
            );
        }
    }

    #[test]
    fn waiter_identities_are_domain_separated_and_registration_scoped() {
        assert_eq!(waiter(1, fence()), waiter(1, fence()));
        assert_ne!(waiter(1, fence()), waiter(2, fence()));
        assert_ne!(waiter(1, fence()), waiter(1, next_fence()));
        assert!(waiter(1, fence()).as_str().starts_with("wait:"));
        assert_eq!(waiter(1, fence()).digest_hex().len(), 64);

        match WaitOwnerId::new("   ") {
            Err(error) => assert_eq!(error.code(), WaitDiagnosticCode::EmptyDeclaredIdentity),
            Ok(owner) => panic!("a blank owner is refused, not admitted as {owner}"),
        }
        match WaitResourceId::new("") {
            Err(error) => assert_eq!(
                error.requirement(),
                "GNT-24.2-wait-identity-and-generations"
            ),
            Ok(resource) => panic!("a blank resource is refused, not admitted as {resource}"),
        }
        match ArmId::new("   ") {
            Err(error) => assert_eq!(
                error.requirement(),
                "GNT-24.6-select-and-race-snapshots-and-winner-permanence"
            ),
            Ok(value) => panic!("a blank arm is refused, not admitted as {value}"),
        }
    }

    #[test]
    fn atomic_step_publishes_one_decision_and_refuses_a_second_registration() {
        let mut pending = registration(1, fence());
        match pending.admit_suspension() {
            Err(error) => assert_eq!(error.code(), WaitDiagnosticCode::SuspensionWithoutRecheck),
            Ok(()) => panic!("a suspension without the atomic step is refused"),
        }
        assert_eq!(
            pending.register_and_recheck(ReadinessObservation::NotReady),
            Ok(RegistrationOutcome::Registered)
        );
        assert!(pending.admit_suspension().is_ok());
        match pending.register_and_recheck(ReadinessObservation::NotReady) {
            Err(error) => assert_eq!(error.code(), WaitDiagnosticCode::RegistrationAlreadyDecided),
            Ok(outcome) => panic!("a second registration is refused, not {outcome:?}"),
        }

        let mut ready = registration(2, fence());
        assert_eq!(
            ready.register_and_recheck(ReadinessObservation::Ready(WakeCause::Delivery)),
            Ok(RegistrationOutcome::AlreadyReady(WakeCause::Delivery))
        );
        match ready.admit_suspension() {
            Err(error) => assert_eq!(error.code(), WaitDiagnosticCode::SuspensionAfterReadiness),
            Ok(()) => panic!("a suspension after the step observed readiness is refused"),
        }
    }

    #[test]
    fn wake_outcome_holds_one_winner_and_refuses_a_second_wake() {
        let mut pending = registration(1, fence());
        assert_eq!(
            pending.register_and_recheck(ReadinessObservation::NotReady),
            Ok(RegistrationOutcome::Registered)
        );
        let mut outcome = match WakeOutcome::pending(&pending) {
            Ok(outcome) => outcome,
            Err(error) => panic!("a decided registration opens an outcome: {error}"),
        };
        assert!(!outcome.is_settled());
        match outcome.require_winner() {
            Err(error) => assert_eq!(error.code(), WaitDiagnosticCode::NoWinnerYet),
            Ok(cause) => panic!("an unsettled outcome has no winner, not {cause}"),
        }
        assert_eq!(outcome.wake(WakeCause::Delivery), Ok(WakeCause::Delivery));
        match outcome.wake(WakeCause::Cancellation) {
            Err(error) => assert_eq!(error.code(), WaitDiagnosticCode::SecondWake),
            Ok(cause) => panic!("a second wake is refused, not {cause}"),
        }
        assert_eq!(outcome.winner(), Some(WakeCause::Delivery));

        let mut ready = registration(2, fence());
        assert_eq!(
            ready.register_and_recheck(ReadinessObservation::Ready(WakeCause::Timeout)),
            Ok(RegistrationOutcome::AlreadyReady(WakeCause::Timeout))
        );
        let opened = match WakeOutcome::pending(&ready) {
            Ok(outcome) => outcome,
            Err(error) => panic!("a decided registration opens an outcome: {error}"),
        };
        assert_eq!(opened.winner(), Some(WakeCause::Timeout));
    }

    #[test]
    fn wait_set_refuses_stale_duplicate_and_unknown_wakes() {
        let mut waits = WaitSet::new();
        let mut first = registration(1, fence());
        assert_eq!(
            first.register_and_recheck(ReadinessObservation::NotReady),
            Ok(RegistrationOutcome::Registered)
        );
        assert_eq!(waits.register(&first), Ok(()));
        assert_eq!(waits.live_count(), 1);

        let id = first.id().clone();
        match waits.wake(&id, next_fence(), WakeCause::Delivery) {
            Err(error) => assert_eq!(error.code(), WaitDiagnosticCode::StaleWake),
            Ok(record) => panic!("a wake of an unheld fence is refused, not {record:?}"),
        }
        assert_eq!(waits.live_count(), 1);
        assert_eq!(
            waits
                .wake(&id, fence(), WakeCause::Delivery)
                .map(|record| record.cause()),
            Ok(WakeCause::Delivery)
        );
        match waits.wake(&id, fence(), WakeCause::Delivery) {
            Err(error) => {
                assert_eq!(error.code(), WaitDiagnosticCode::SecondWake);
                assert_eq!(error.wait(), Some(&id));
                assert_eq!(error.held_fence(), Some(fence()));
                assert_eq!(error.presented_fence(), Some(fence()));
            }
            Ok(record) => panic!("a repeated wake is refused, not {record:?}"),
        }

        let mut reused = registration(2, fence());
        assert_eq!(
            reused.register_and_recheck(ReadinessObservation::NotReady),
            Ok(RegistrationOutcome::Registered)
        );
        match waits.register(&reused) {
            Err(error) => assert_eq!(error.code(), WaitDiagnosticCode::StaleRegistration),
            Ok(()) => panic!("a registration of a retired fence is refused"),
        }

        let mut fresh = registration(2, next_fence());
        assert_eq!(
            fresh.register_and_recheck(ReadinessObservation::NotReady),
            Ok(RegistrationOutcome::Registered)
        );
        assert_eq!(waits.register(&fresh), Ok(()));
        let fresh_id = fresh.id().clone();
        let withdrawal = match waits.remove_waiter(&fresh_id, next_fence()) {
            Ok(withdrawal) => withdrawal,
            Err(error) => panic!("the owner withdraws its own live wait: {error}"),
        };
        assert_eq!(withdrawal.wait(), &fresh_id);
        assert_eq!(withdrawal.generation(), next_fence());
        assert_eq!(
            withdrawal.requirement(),
            "GNT-24.5-producer-loss-and-closure"
        );
        assert_eq!(waits.withdrawal(&fresh_id, next_fence()), Some(withdrawal));
        assert_eq!(waits.live_count(), 0);

        // A withdrawal is not a wake: it retires the fence, so a later wake is stale
        // rather than a duplicate of a wake that was never applied.
        match waits.wake(&fresh_id, next_fence(), WakeCause::Delivery) {
            Err(error) => {
                assert_eq!(error.code(), WaitDiagnosticCode::StaleWake);
                assert_eq!(error.wait(), Some(&fresh_id));
                assert_eq!(error.held_fence(), Some(next_fence()));
                assert_eq!(error.presented_fence(), Some(next_fence()));
            }
            Ok(record) => panic!("a withdrawn fence is never revived, not {record:?}"),
        }

        let unknown = waiter(9, fence());
        match waits.wake(&unknown, fence(), WakeCause::Delivery) {
            Err(error) => {
                assert_eq!(error.code(), WaitDiagnosticCode::UnknownWaiter);
                assert_eq!(error.wait(), Some(&unknown));
                assert_eq!(error.held_fence(), None);
                assert_eq!(error.presented_fence(), Some(fence()));
            }
            Ok(record) => panic!("an unknown waiter is refused, not {record:?}"),
        }

        let mut ready = registration(3, fence());
        assert_eq!(
            ready.register_and_recheck(ReadinessObservation::Ready(WakeCause::Delivery)),
            Ok(RegistrationOutcome::AlreadyReady(WakeCause::Delivery))
        );
        match waits.register(&ready) {
            Err(error) => assert_eq!(error.code(), WaitDiagnosticCode::SuspensionAfterReadiness),
            Ok(()) => panic!("an already-ready wait is consumed rather than registered"),
        }
    }

    #[test]
    fn wait_set_closes_every_live_wait_of_the_generation_and_refuses_a_repeat() {
        let mut waits = WaitSet::new();
        let mut first = registration(1, fence());
        assert_eq!(
            first.register_and_recheck(ReadinessObservation::NotReady),
            Ok(RegistrationOutcome::Registered)
        );
        assert_eq!(waits.register(&first), Ok(()));
        let settled = waits
            .wake(first.id(), fence(), WakeCause::Delivery)
            .map(|record| record.cause());
        assert_eq!(settled, Ok(WakeCause::Delivery));

        let mut second = WaitRegistration::new(
            WaitId::derive(&other_owner(), &resource(), &generation(1), fence(), 1),
            other_owner(),
            resource(),
            generation(1),
            fence(),
            1,
        );
        assert_eq!(
            second.register_and_recheck(ReadinessObservation::NotReady),
            Ok(RegistrationOutcome::Registered)
        );
        assert_eq!(waits.register(&second), Ok(()));
        assert_eq!(waits.live_for(&resource()), 1);

        let report = match waits.close_resource(&resource(), &generation(1)) {
            Ok(report) => report,
            Err(error) => panic!("the known resource closes: {error}"),
        };
        assert!(report.is_classified());
        assert_eq!(report.resource(), &resource());
        assert_eq!(report.generation(), &generation(1));
        assert_eq!(report.closed().len(), 1);
        assert_eq!(report.closed()[0].cause(), WakeCause::ResourceClosure);
        assert_eq!(report.preserved().len(), 1);
        assert_eq!(report.preserved()[0].cause(), WakeCause::Delivery);
        assert_eq!(waits.live_for(&resource()), 0);
        assert_eq!(waits.unclassifiable_count(), 0);
        assert!(waits.is_closed(&resource(), &generation(1)));
        assert!(!waits.is_closed(&resource(), &generation(2)));

        // Closure is keyed by the landed resource generation, so a closure of a generation
        // the wait set does not know is refused with its own condition.
        match waits.close_resource(&resource(), &generation(9)) {
            Err(error) => assert_eq!(error.code(), WaitDiagnosticCode::UnknownResourceGeneration),
            Ok(report) => panic!("an unknown resource generation is refused, not {report:?}"),
        }
        match waits.close_resource(&resource(), &generation(1)) {
            Err(error) => assert_eq!(error.code(), WaitDiagnosticCode::RepeatedClosure),
            Ok(report) => panic!("a repeated closure is refused, not {report:?}"),
        }
        let mut after_closure = registration(4, next_fence());
        assert_eq!(
            after_closure.register_and_recheck(ReadinessObservation::NotReady),
            Ok(RegistrationOutcome::Registered)
        );
        match waits.register(&after_closure) {
            Err(error) => assert_eq!(error.code(), WaitDiagnosticCode::RegistrationAfterClosure),
            Ok(()) => panic!("a registration for a closed resource is refused"),
        }
        let unknown = match WaitResourceId::new("std.io.write") {
            Ok(resource) => resource,
            Err(error) => panic!("the declared resource is named: {error}"),
        };
        match waits.close_resource(&unknown, &generation(1)) {
            Err(error) => assert_eq!(error.code(), WaitDiagnosticCode::UnknownResource),
            Ok(report) => panic!("an unknown resource is refused, not {report:?}"),
        }
    }

    #[test]
    fn arbitration_commits_the_lowest_position_and_refuses_redecision() {
        let arms = vec![
            armed("first", waiter(1, fence())),
            armed("second", waiter(2, fence())),
        ];
        let arbitration = match Arbitration::open(arms) {
            Ok(arbitration) => arbitration,
            Err(error) => panic!("the declared arm set opens: {error}"),
        };
        assert_eq!(arbitration.snapshot().arm_count(), 2);
        let unresolved = match arbitration.decide(&[]) {
            Ok(ArbitrationDecision::Unresolved(arbitration)) => arbitration,
            other => panic!("no eligible arm leaves the arbitration unresolved: {other:?}"),
        };
        assert_eq!(unresolved.winner(), None);

        let observations = [
            ArmObservation::new(arm("second"), WakeCause::Delivery),
            ArmObservation::new(arm("first"), WakeCause::Delivery),
        ];
        let envelope = match unresolved.envelope(&observations) {
            Ok(envelope) => envelope,
            Err(error) => panic!("the declared observations are inside the snapshot: {error}"),
        };
        assert!(envelope.permits(&arm("first")) && envelope.permits(&arm("second")));
        assert!(!envelope.permits(&arm("third")));
        assert!(!envelope.is_deterministic());

        let decision = match unresolved.decide(&observations) {
            Ok(decision) => decision,
            other => panic!("the declared observations decide a winner: {other:?}"),
        };
        assert!(decision.is_committed());
        assert_eq!(
            decision.requirement(),
            "GNT-24.6-select-and-race-snapshots-and-winner-permanence"
        );
        let winner = match decision.winner() {
            Some(winner) => winner,
            None => panic!("a committed decision records one winner"),
        };
        assert_eq!(winner.arm(), &arm("first"));
        assert_eq!(winner.position(), 0);
        assert_eq!(winner.contending().len(), 2);
        assert!(winner.was_tie());

        let arbitration = decision.into_arbitration();
        let held = match arbitration.winner() {
            Some(winner) => winner.arm().clone(),
            None => panic!("the committed winner is recorded"),
        };
        assert_eq!(held, arm("first"));
        match arbitration.decide(&observations) {
            Err(error) => assert_eq!(error.code(), WaitDiagnosticCode::WinnerAlreadyCommitted),
            Ok(other) => panic!("a second decision is refused, not {other:?}"),
        }

        // A decision consumes the arbitration, so each refused observation set is presented
        // to its own freshly opened arbitration, and no refusal commits a winner.
        assert_eq!(
            refused_decision(
                vec![armed("only", waiter(1, fence()))],
                &[ArmObservation::new(arm("other"), WakeCause::Delivery)]
            )
            .code(),
            WaitDiagnosticCode::ArmOutsideSnapshot
        );
        assert_eq!(
            refused_decision(
                vec![armed("only", waiter(1, fence()))],
                &[
                    ArmObservation::new(arm("only"), WakeCause::Delivery),
                    ArmObservation::new(arm("only"), WakeCause::Timeout),
                ]
            )
            .code(),
            WaitDiagnosticCode::DuplicateObservation
        );
        let fresh = match Arbitration::open(vec![armed("only", waiter(1, fence()))]) {
            Ok(arbitration) => arbitration,
            Err(error) => panic!("the declared arm set opens: {error}"),
        };
        assert_eq!(fresh.winner(), None);
        match fresh.into_losing_settlement() {
            Err(error) => assert_eq!(error.code(), WaitDiagnosticCode::WinnerNotCommitted),
            Ok(other) => panic!("an undecided arbitration has no settlement, {other:?}"),
        }

        match Arbitration::open(Vec::new()) {
            Err(error) => assert_eq!(error.code(), WaitDiagnosticCode::EmptyArbitration),
            Ok(other) => panic!("an empty arm set is refused, not {other:?}"),
        }
        match Arbitration::open(vec![
            armed("same", waiter(1, fence())),
            armed("same", waiter(2, fence())),
        ]) {
            Err(error) => assert_eq!(error.code(), WaitDiagnosticCode::DuplicateArm),
            Ok(other) => panic!("a repeated arm key is refused, not {other:?}"),
        }
        match Arbitration::open(vec![
            armed("first", waiter(1, fence())),
            armed("second", waiter(1, fence())),
        ]) {
            Err(error) => {
                assert_eq!(error.code(), WaitDiagnosticCode::RepeatedArmedAlternative);
                assert_eq!(
                    error.requirement(),
                    "GNT-24.6-select-and-race-snapshots-and-winner-permanence"
                );
            }
            Ok(other) => panic!("a repeated armed alternative is refused, not {other:?}"),
        }
    }

    #[test]
    fn losing_arms_are_settled_once_with_one_disposition_each() {
        let observations = [ArmObservation::new(arm("first"), WakeCause::Delivery)];
        let arbitration = decided(
            vec![
                armed("first", waiter(1, fence())),
                armed("second", waiter(2, fence())),
                armed("third", waiter(3, fence())),
            ],
            &observations,
        );
        let settlement = match arbitration.into_losing_settlement() {
            Ok(settlement) => settlement,
            Err(error) => panic!("a decided arbitration yields a settlement: {error}"),
        };
        assert_eq!(settlement.losing_arms(), vec![arm("second"), arm("third")]);

        match settlement.settle(&[ArmDisposition::new(
            arm("second"),
            ArmDispositionKind::Cancel,
        )]) {
            Err(error) => assert_eq!(error.code(), WaitDiagnosticCode::UnsettledLosingArm),
            Ok(report) => panic!("an unsettled losing arm is refused, not {report:?}"),
        }
    }

    #[test]
    fn losing_arm_settlements_refuse_the_winner_a_repeat_and_a_foreign_arm() {
        let observations = [ArmObservation::new(arm("first"), WakeCause::Delivery)];
        let arbitration = decided(
            vec![
                armed("first", waiter(1, fence())),
                armed("second", waiter(2, fence())),
            ],
            &observations,
        );
        assert_eq!(
            arbitration.winner().map(|winner| winner.arm().clone()),
            Some(arm("first"))
        );
        let committed = arbitration.winner().map(|winner| winner.cause());
        assert_eq!(committed, Some(WakeCause::Delivery));

        // One committed arbitration yields exactly one settlement, and that settlement is
        // consumed once, so the refusing dispositions are each presented to the settlement
        // of their own committed arbitration.
        let settlement = match arbitration.into_losing_settlement() {
            Ok(settlement) => settlement,
            Err(error) => panic!("a decided arbitration yields a settlement: {error}"),
        };
        assert_eq!(settlement.winner(), &arm("first"));
        assert_eq!(settlement.losing_arms(), vec![arm("second")]);
        let report = match settlement.settle(&[ArmDisposition::new(
            arm("second"),
            ArmDispositionKind::Cancel,
        )]) {
            Ok(report) => report,
            Err(error) => panic!("the losing arm is settled once: {error}"),
        };
        assert_eq!(report.winner(), &arm("first"));
        assert_eq!(report.cancelled(), [arm("second")]);
        assert!(report.retained().is_empty());
        assert!(report.is_complete());

        assert_eq!(
            refused_settlement(&[ArmDisposition::new(
                arm("first"),
                ArmDispositionKind::Retain
            )])
            .code(),
            WaitDiagnosticCode::WinnerNotLosable
        );
        assert_eq!(
            refused_settlement(&[
                ArmDisposition::new(arm("second"), ArmDispositionKind::Cancel),
                ArmDisposition::new(arm("second"), ArmDispositionKind::Retain),
            ])
            .code(),
            WaitDiagnosticCode::RepeatedDisposition
        );
        assert_eq!(
            refused_settlement(&[ArmDisposition::new(
                arm("third"),
                ArmDispositionKind::Cancel
            )])
            .code(),
            WaitDiagnosticCode::ArmOutsideSnapshot
        );
        assert_eq!(
            refused_settlement(&[]).code(),
            WaitDiagnosticCode::UnsettledLosingArm
        );
    }

    #[test]
    fn quiescence_classes_are_total_and_exempt_pending_external_prerequisites() {
        let facts =
            |live, internal, external, admitted, resumable, orphaned| match QuiescenceFacts::new(
                live, internal, external, admitted, resumable, orphaned,
            ) {
                Ok(facts) => facts,
                Err(error) => panic!("the declared facts are well formed: {error}"),
            };
        assert_eq!(
            classify_quiescence(&facts(0, 0, 0, 0, 0, 0)),
            QuiescenceClass::Completion
        );
        assert_eq!(
            classify_quiescence(&facts(0, 0, 0, 1, 1, 0)),
            QuiescenceClass::InternallyWakeableIdle
        );
        assert_eq!(
            classify_quiescence(&facts(1, 0, 1, 0, 0, 0)),
            QuiescenceClass::ExternallyWakeableIdle
        );
        assert_eq!(
            classify_quiescence(&facts(2, 2, 0, 2, 0, 0)),
            QuiescenceClass::ClosedWaitDeadlock
        );
        assert_eq!(
            classify_quiescence(&facts(0, 0, 0, 0, 0, 1)),
            QuiescenceClass::OrphanedWork
        );

        match QuiescenceFacts::new(1, 2, 0, 0, 0, 0) {
            Err(error) => assert_eq!(error.code(), WaitDiagnosticCode::MalformedQuiescenceFacts),
            Ok(other) => panic!("more blocked waits than live waits are refused: {other:?}"),
        }
        match QuiescenceFacts::new(0, 0, 0, 1, 2, 0) {
            Err(error) => assert_eq!(error.code(), WaitDiagnosticCode::MalformedQuiescenceFacts),
            Ok(other) => panic!("more resumable work than admitted work is refused: {other:?}"),
        }

        let deadlocked = facts(2, 2, 0, 2, 0, 0);
        let waits = vec![waiter(1, fence()), waiter(2, fence())];
        let outcome = match observe_quiescence(&deadlocked, waits.clone(), 2) {
            Ok(outcome) => outcome,
            Err(error) => panic!("the declared deadlock is classified: {error}"),
        };
        assert_eq!(outcome.class(), QuiescenceClass::ClosedWaitDeadlock);
        assert_eq!(
            outcome.remedy(),
            QuiescenceRemedy::OrdinaryCancellationAndCleanup
        );
        let diagnostic = match outcome.diagnostic() {
            Some(diagnostic) => diagnostic,
            None => panic!("a closed-wait deadlock reports a bounded diagnostic"),
        };
        assert_eq!(diagnostic.node_count(), 2);
        assert_eq!(diagnostic.edge_count(), 2);
        let text = diagnostic.protected_text(AuditAccess::granted());
        assert!(text.contains(WaitDiagnosticCode::ClosedWaitDeadlockReported.as_str()));

        let exempt = facts(1, 0, 1, 0, 0, 0);
        let idle = match observe_quiescence(&exempt, waits, 1) {
            Ok(outcome) => outcome,
            Err(error) => panic!("pending external work is classified: {error}"),
        };
        assert_eq!(idle.class(), QuiescenceClass::ExternallyWakeableIdle);
        assert!(idle.diagnostic().is_none());
        assert_eq!(idle.remedy(), QuiescenceRemedy::None);

        match observe_quiescence(&deadlocked, Vec::new(), 2) {
            Err(error) => assert_eq!(error.code(), WaitDiagnosticCode::EmptyWaitGraph),
            Ok(other) => panic!("an empty wait graph is refused, not {other:?}"),
        }
        match observe_quiescence(&deadlocked, vec![waiter(1, fence())], 4_096) {
            Err(error) => assert_eq!(
                error.code(),
                WaitDiagnosticCode::WaitGraphDiagnosticTooLarge
            ),
            Ok(other) => panic!("an oversized wait graph is refused, not {other:?}"),
        }
    }

    #[test]
    fn durable_cuts_advance_forward_only_and_recovery_keeps_the_winner() {
        let registration = registration(1, fence());
        let mut record = DurableWaitRecord::for_registration(&registration);
        assert_eq!(record.cut(), DurableWaitCut::Registration);
        assert_eq!(record.generation(), fence());
        assert_eq!(record.owner(), &owner());

        match record.advance_to(DurableWaitCut::Decision) {
            Err(error) => assert_eq!(error.code(), WaitDiagnosticCode::CutRegression),
            Ok(()) => panic!("a cut that skips an uncommitted cut is refused"),
        }
        // A commit advances exactly one cut: a readiness commit whose predecessor cut is
        // not committed is refused and commits nothing on the caller's behalf.
        match record.commit_readiness(WakeCause::Delivery) {
            Err(error) => assert_eq!(error.code(), WaitDiagnosticCode::CutRegression),
            Ok(()) => panic!("a readiness commit never commits the ownership cut for the caller"),
        }
        assert_eq!(record.cut(), DurableWaitCut::Registration);
        assert_eq!(record.readiness(), None);

        assert_eq!(record.advance_to(DurableWaitCut::Registration), Ok(()));
        assert_eq!(record.advance_to(DurableWaitCut::Ownership), Ok(()));
        assert_eq!(record.commit_readiness(WakeCause::Delivery), Ok(()));
        assert_eq!(record.cut(), DurableWaitCut::Readiness);
        assert_eq!(
            record.commit_readiness(WakeCause::Delivery),
            Ok(()),
            "a repeated readiness commit is stuttering"
        );
        let resumed = match record.resume(None) {
            Ok(resumed) => resumed,
            Err(error) => panic!("the committed readiness resumes: {error}"),
        };
        assert_eq!(
            resumed,
            WaitRecoveryDecision::ResumeReady(WakeCause::Delivery)
        );
        match record.resume(Some(WaitDecision::Wake(WakeCause::Delivery))) {
            Err(error) => assert_eq!(error.code(), WaitDiagnosticCode::DecisionBeforeCommit),
            Ok(other) => panic!("a decision before the decision cut is refused, {other:?}"),
        }

        assert_eq!(
            record
                .commit_readiness(WakeCause::Timeout)
                .map_err(|e| e.code()),
            Err(WaitDiagnosticCode::ReadinessRegression)
        );
        assert_eq!(
            record.commit_decision(WaitDecision::Wake(WakeCause::Delivery)),
            Ok(())
        );
        assert_eq!(record.cut(), DurableWaitCut::Decision);
        let resumed = match record.resume(Some(WaitDecision::Wake(WakeCause::Delivery))) {
            Ok(resumed) => resumed,
            Err(error) => panic!("the committed winner resumes: {error}"),
        };
        assert_eq!(
            resumed,
            WaitRecoveryDecision::ResumeWinner(WakeCause::Delivery)
        );
        match record.resume(Some(WaitDecision::Wake(WakeCause::Cancellation))) {
            Err(error) => assert_eq!(error.code(), WaitDiagnosticCode::DecisionRegression),
            Ok(other) => panic!("a different winner is refused, not {other:?}"),
        }
        assert_eq!(
            record.commit_decision(WaitDecision::Wake(WakeCause::Delivery)),
            Ok(()),
            "a repeated decision commit is stuttering"
        );
        match record.commit_decision(WaitDecision::Deadlock(QuiescenceClass::ClosedWaitDeadlock)) {
            Err(error) => assert_eq!(error.code(), WaitDiagnosticCode::DecisionRegression),
            Ok(()) => panic!("a deadlock over a committed wake is refused"),
        }

        // A decision commit advances exactly one cut from the committed readiness cut, and a
        // wake decision additionally requires a committed readiness that recorded its cause.
        let mut unreadied =
            DurableWaitRecord::new(waiter(2, fence()), owner(), resource(), fence());
        match unreadied.commit_decision(WaitDecision::Wake(WakeCause::Delivery)) {
            Err(error) => assert_eq!(error.code(), WaitDiagnosticCode::CutRegression),
            Ok(()) => panic!("a decision commit never commits the readiness cut for the caller"),
        }
        assert_eq!(unreadied.cut(), DurableWaitCut::Registration);
        assert_eq!(unreadied.decision(), None);
        assert_eq!(unreadied.advance_to(DurableWaitCut::Ownership), Ok(()));
        assert_eq!(unreadied.advance_to(DurableWaitCut::Readiness), Ok(()));
        match unreadied.commit_decision(WaitDecision::Wake(WakeCause::Delivery)) {
            Err(error) => assert_eq!(error.code(), WaitDiagnosticCode::MissingCommittedReadiness),
            Ok(()) => {
                panic!("a wake decision requires a committed readiness that recorded its cause")
            }
        }
        assert_eq!(unreadied.cut(), DurableWaitCut::Readiness);
        assert_eq!(unreadied.decision(), None);
        match unreadied.resume(None) {
            Err(error) => assert_eq!(error.code(), WaitDiagnosticCode::MissingCommittedReadiness),
            Ok(other) => {
                panic!("a readiness cut with no recorded cause resumes nothing: {other:?}")
            }
        }

        // The deadlock transition requires the committed readiness cut, because every commit
        // advances exactly one cut, but it records no ready cause.
        let mut transition =
            DurableWaitRecord::new(waiter(4, fence()), owner(), resource(), fence());
        assert_eq!(transition.advance_to(DurableWaitCut::Ownership), Ok(()));
        assert_eq!(transition.advance_to(DurableWaitCut::Readiness), Ok(()));
        assert_eq!(
            transition.commit_decision(WaitDecision::Deadlock(QuiescenceClass::ClosedWaitDeadlock)),
            Ok(())
        );
        assert_eq!(
            transition.resume(None),
            Ok(WaitRecoveryDecision::ResumeDeadlock(
                QuiescenceClass::ClosedWaitDeadlock
            ))
        );
        match transition.commit_decision(WaitDecision::Deadlock(
            QuiescenceClass::ExternallyWakeableIdle,
        )) {
            Err(error) => assert_eq!(
                error.code(),
                WaitDiagnosticCode::DeadlockClassificationRefused
            ),
            Ok(()) => panic!("a non-deadlock classification is refused"),
        }

        let permitted = match super::PrerequisiteRef::new("host.read") {
            Ok(key) => key,
            Err(error) => panic!("the declared prerequisite is named: {error}"),
        };
        let unpermitted = match super::PrerequisiteRef::new("host.write") {
            Ok(key) => key,
            Err(error) => panic!("the declared prerequisite is named: {error}"),
        };
        assert_eq!(
            transition.reattach(
                std::slice::from_ref(&permitted),
                std::slice::from_ref(&permitted)
            ),
            Ok(vec![permitted.clone()])
        );
        match transition.reattach(&[unpermitted], &[permitted]) {
            Err(error) => assert_eq!(error.code(), WaitDiagnosticCode::UnpermittedPrerequisite),
            Ok(attached) => panic!("an unpermitted prerequisite is refused, not {attached:?}"),
        }
    }

    #[test]
    fn diagnostic_codes_are_unique_sorted_and_owned_by_one_clause() {
        assert_eq!(WaitDiagnosticCode::ALL.len(), 39);
        let mut codes = WaitDiagnosticCode::ALL.iter().map(|code| code.as_str());
        let mut previous: Option<&str> = None;
        for code in codes.by_ref() {
            assert!(code.starts_with("wait-"));
            if let Some(held) = previous {
                assert!(held < code, "{held} must sort before {code}");
            }
            previous = Some(code);
        }
        let unique = WaitDiagnosticCode::ALL
            .iter()
            .map(|code| code.wire_name())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(unique.len(), WaitDiagnosticCode::ALL.len());
        for code in WaitDiagnosticCode::ALL {
            assert!(WAIT_CLAUSES.contains(&code.requirement()));
        }
        assert!(matches!(
            super::WaitError::WinnerNotCommitted.code(),
            WaitDiagnosticCode::WinnerNotCommitted
        ));
    }

    #[test]
    fn non_claims_are_closed_ordered_and_never_guarantees() {
        assert_eq!(super::WAIT_NON_CLAIM_ORDER, WaitNonClaimName::ALL);
        assert_eq!(WAIT_NON_CLAIMS.len(), WaitNonClaimName::ALL.len());
        for (position, claim) in WaitNonClaimName::ALL.iter().enumerate() {
            assert_eq!(claim.statement(), WAIT_NON_CLAIMS[position]);
            assert_eq!(
                WaitNonClaimName::from_wire_name(claim.as_str()),
                Some(*claim)
            );
        }
        let honest = WaitNonClaimName::ALL
            .iter()
            .map(|claim| WaitNonClaimAssertion::new(*claim, false))
            .collect::<Vec<_>>();
        assert_eq!(check_wait_non_claims(&honest), Ok(()));
        let overstated = [WaitNonClaimAssertion::new(
            WaitNonClaimName::UnboundedFairnessOrLatency,
            true,
        )];
        match check_wait_non_claims(&overstated) {
            Err(error) => assert_eq!(error.code(), WaitDiagnosticCode::NonClaimAsGuarantee),
            Ok(()) => panic!("presenting a non-claim as a guarantee is refused"),
        }
    }
}
