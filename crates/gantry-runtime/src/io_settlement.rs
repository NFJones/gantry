//! Bounded settlement of one admitted Section 45 one-call I/O attempt.
//!
//! This module is the executor-neutral host boundary of
//! `GNT-45.1-bounded-one-call-io-contract` and its settlement step. It supplies one bounded
//! in-memory transport, one synchronous endpoint boundary, and one settlement service that
//! binds a caller's admitted [`IoRequest`] to the authenticated operation occurrence the machine
//! already retained, performs exactly one call, and publishes exactly one settlement through the
//! landed Section 20 receiver-loan, accounting, and cancellation machinery.
//!
//! The service reuses the landed runtime rather than restating it: the caller supplies an
//! [`OwnedHostResource`] over an endpoint and the [`Machine`] whose pending operation occurrence
//! the account was admitted under, and every attempt goes through
//! [`OwnedHostResource::borrow_receiver_from_pending`], [`HostReceiverLoan::observe`], and
//! [`HostReceiverLoan::settle`]. Quota charges are committed by that landed loan admission, the
//! model's own progress rule derives the exposed progress, and the model's own lifetime and
//! projection rules publish the resulting resource state. Nothing here reimplements accounting,
//! leases, progress derivation, containment, or off-worker cleanup.
//!
//! Boundaries and invariants.
//!
//! * One attempt binds one request to one authenticated occurrence: operation identity, resource
//!   generation, owner generation, receiver kind, and quantity. A request whose kind or payload
//!   does not belong to that binding is refused before dispatch and before any effect.
//! * Zero and excess quantities are refused by [`IoRequest`] itself before a service can be
//!   built, so an out-of-bound request never reaches an endpoint.
//! * A read publishes exactly the initialized octets the endpoint returned, including the final
//!   octets at end of stream, and never spare capacity. A write publishes exactly its accepted
//!   prefix; the remainder stays with the caller.
//! * Short progress settles this one call and never a stream, and a blocked attempt settles once
//!   with the Section 24 readiness fact of `GNT-24.1-atomic-registration-and-readiness-recheck`.
//!   No busy polling, hidden retry, or implicit second attempt exists here: a later call needs a
//!   new admitted occurrence, because a settled loan root is never reopened by this module.
//! * Cancellation and interruption are settlement facts, not progress. The admission lease is
//!   rechecked once, after the single call returns and before any observation or settlement, so
//!   the completion and cancellation race has one deterministic linearization point. A
//!   cancellation observed at that point withholds publication while any known accepted prefix
//!   stays retained as protected evidence; it never erases a fault the completion established, and
//!   it is never reported for a lease that is merely closed or unreadable, which are contained
//!   operational failures instead. A cancellation observed after that point does not retract a
//!   settlement that already exists.
//! * A malformed host completion length or a request-mismatched completion is a contained
//!   operational failure: no bytes or prefixes are published, and no claim is made that an
//!   external effect was undone. Family domain refusals, operational faults, and protected native
//!   diagnostics stay distinct kinds of failure and are never relabelled as one another.
//! * A late, duplicate, wrong-owner, or wrong-generation completion can neither publish nor
//!   refund twice: one attempt publishes at most once, and a second attempt is refused before it
//!   can charge, observe, or settle again.
//! * Dropping the settlement service, or any outcome it produced, does not fabricate a settlement.
//!   The accepted in-memory octets stay in the endpoint the caller bound and the machine-issued
//!   admission lease stays shared with the account, so losing every observer of the attempt keeps
//!   both. This slice binds a caller-owned transport: registry-owned slot retention and off-worker
//!   physical cleanup of a discarded binding are consumed by the consumer slice, not claimed here.
//!
//! This module publishes no source handle, live source admission, adapter, host-family
//! integration, durable cleanup cut, or task transfer, and it performs no filesystem, socket,
//! console, or process I/O. A seek is refused: cursor state belongs to a live source carrier that
//! the accepted carrier decision keeps ineligible.

use std::sync::{Arc, Mutex};

use gantry_ir::{
    Charge, ExternalOutcome, FenceCategory, IoBackpressure, IoError, IoOperation, IoOutcome,
    IoRequest, LiveResource, LogicalOperationId, ObservationAllowance, OperationAbiError,
    OperationSettlement, OwnerGeneration, ProgressObservation, ProgressRecord,
    ReadinessObservation, ResourceGenerationId, ResourceState, StaticSiteId,
};

use crate::{HostReceiverLoan, HostResourceError, Machine, OwnedHostResource};

/// One authenticated receiver occurrence a bounded attempt may settle against.
///
/// Identity, generation, site, and owner are read from the loan's own live resource, so no caller
/// can name another occurrence. The receiver kind is the kind the embedding boundary declares for
/// that receiver; it is bound here and checked against the caller's request rather than inferred
/// from it, because a live receiver makes even a handle-free result a live-resource operation
/// (`GNT-20.1-operation-kinds`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IoOccurrence {
    operation: LogicalOperationId,
    generation: ResourceGenerationId,
    site: StaticSiteId,
    owner: OwnerGeneration,
    kind: IoOperation,
}

impl IoOccurrence {
    /// Authenticates the occurrence of one admitted receiver loan.
    ///
    /// The receiver arrangement must be the exclusive, sealed, generation-bound loan of
    /// `GNT-20.3-receiver-loan-and-ownership-transfer`; a transferred-in, retained-by-caller,
    /// fenced, already-settled, or non-open receiver is refused rather than reinterpreted.
    ///
    /// # Errors
    ///
    /// Returns the [`IoRefusal`] that names why this live resource cannot carry a bounded call.
    pub fn authenticate(live: &LiveResource, kind: IoOperation) -> Result<Self, IoRefusal> {
        if !live.ownership().is_borrowed_loan() {
            return Err(IoRefusal::NotAReceiverLoan {
                arrangement: live.ownership().wire_name(),
            });
        }
        if let Some(category) = live.fenced() {
            return Err(IoRefusal::Fenced { category });
        }
        if live.settlement().is_some() || live.failure_settlement().is_some() {
            return Err(IoRefusal::AlreadySettled);
        }
        if !live.state().is_open() {
            return Err(IoRefusal::NotUsable {
                state: live.state(),
            });
        }
        Ok(Self {
            operation: live.operation().clone(),
            generation: live.generation().clone(),
            site: live.site().clone(),
            owner: live.owner(),
            kind,
        })
    }

    /// Returns the authenticated logical operation identity.
    #[must_use]
    pub const fn operation(&self) -> &LogicalOperationId {
        &self.operation
    }

    /// Returns the authenticated resource generation.
    #[must_use]
    pub const fn generation(&self) -> &ResourceGenerationId {
        &self.generation
    }

    /// Returns the exact static site of this occurrence.
    #[must_use]
    pub const fn site(&self) -> &StaticSiteId {
        &self.site
    }

    /// Returns the owner generation that holds this occurrence.
    #[must_use]
    pub const fn owner(&self) -> OwnerGeneration {
        self.owner
    }

    /// Returns the receiver kind the boundary declared for this occurrence.
    #[must_use]
    pub const fn kind(&self) -> IoOperation {
        self.kind
    }
}

/// One admitted request bound to the occurrence it may settle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IoCallBinding {
    occurrence: IoOccurrence,
    request: IoRequest,
}

impl IoCallBinding {
    /// Binds one admitted request to one authenticated occurrence.
    ///
    /// # Errors
    ///
    /// Refuses `io-request-kind` when the request's declared kind differs from the kind the
    /// occurrence declares.
    pub fn bind(occurrence: IoOccurrence, request: IoRequest) -> Result<Self, IoRefusal> {
        if request.operation() != occurrence.kind {
            return Err(IoRefusal::RequestKind {
                declared: occurrence.kind,
                request: request.operation(),
            });
        }
        Ok(Self {
            occurrence,
            request,
        })
    }

    /// Returns the authenticated occurrence this call belongs to.
    #[must_use]
    pub const fn occurrence(&self) -> &IoOccurrence {
        &self.occurrence
    }

    /// Returns the admitted request of this call.
    #[must_use]
    pub const fn request(&self) -> &IoRequest {
        &self.request
    }

    /// Returns the bound quantity of this call.
    #[must_use]
    pub const fn quantity(&self) -> u64 {
        self.request.quantity()
    }
}

/// One family-declared domain refusal presented at the endpoint boundary.
///
/// This slice declares no family code and interprets none: the spelling is presented by the
/// boundary of the family that owns the operation, kept as its own kind, and never relabelled as
/// an operational fault or a native diagnostic.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IoFamilyFault {
    code: Arc<str>,
}

impl IoFamilyFault {
    /// Presents one family-declared code, refusing an empty spelling at the boundary.
    #[must_use]
    pub fn new(code: impl Into<Arc<str>>) -> Option<Self> {
        let code = code.into();
        if code.is_empty() {
            None
        } else {
            Some(Self { code })
        }
    }

    /// Returns the family-declared code exactly as presented.
    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }
}

/// One contained native diagnostic reduced to its endpoint-supplied class label.
///
/// A native diagnostic is protected: only the endpoint's classification label crosses this
/// boundary, no message or payload is retained, and the diagnostic is never published as a
/// portable outcome, a domain refusal, or an operational fault.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IoNativeDiagnostic {
    class: Arc<str>,
}

impl IoNativeDiagnostic {
    /// Presents one classification label, refusing an empty label at the boundary.
    #[must_use]
    pub fn new(class: impl Into<Arc<str>>) -> Option<Self> {
        let class = class.into();
        if class.is_empty() {
            None
        } else {
            Some(Self { class })
        }
    }

    /// Returns the contained classification label.
    #[must_use]
    pub fn class(&self) -> &str {
        &self.class
    }
}

/// One contained operational fault of a dispatched bounded call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IoOperationalFault {
    /// The endpoint claimed an advance its returned initialized octets do not carry.
    ReadLength {
        /// The advance the endpoint claimed.
        advanced: u64,
        /// The initialized octet count it actually returned.
        returned: u64,
    },
    /// The endpoint returned more initialized octets than the call asked for.
    ReadOverlong {
        /// The octet count the call asked for.
        requested: u64,
        /// The initialized octet count the endpoint returned.
        returned: u64,
    },
    /// The endpoint accepted more octets than the call presented.
    WriteOverAccepted {
        /// The octet count the call presented.
        provided: u64,
        /// The octet count the endpoint claimed to accept.
        accepted: u64,
    },
    /// The endpoint reported a backpressure kind this call cannot observe.
    BlockedKind {
        /// The kind of the call.
        request: IoOperation,
        /// The backpressure kind the endpoint reported.
        blocked: IoBackpressure,
    },
    /// The endpoint answered with facts the declared one-call contract refuses.
    Contract(IoError),
    /// The endpoint answered a different call than the one dispatched.
    ForeignCompletion,
    /// The endpoint panicked; its payload is contained and never disclosed.
    Panicked,
    /// The endpoint's retained state was unreadable, so no completion could be formed.
    StateUnreadable,
    /// Other accepted work closed admission after this call was dispatched.
    AdmissionClosed,
    /// The admission lease became unreadable after this call was dispatched.
    AdmissionLeaseUnreadable,
    /// The endpoint declared a capacity or initial length its own bound refuses.
    Capacity {
        /// The declared retention capacity.
        declared: u64,
        /// The greatest capacity the declared Section 45 bound admits.
        maximum: u64,
        /// The initialized octet count presented with that capacity.
        initialized: u64,
    },
    /// The endpoint presented no callable answer for the request it was given.
    UnsupportedRequest {
        /// The request kind the endpoint refused.
        operation: IoOperation,
    },
}

/// One endpoint-reported completion of one bounded call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IoHostCompletion {
    /// The peer observed not ready for this call and transferred no octet.
    Blocked {
        /// The declared kind whose peer was not ready.
        operation: IoBackpressure,
    },
    /// The peer returned this many initialized octets and claims this advance.
    Read {
        /// The advance the peer claims for this call.
        advanced: u64,
        /// The initialized octets the peer returned, and no spare capacity.
        bytes: Vec<u8>,
        /// Whether the peer observed the end of its stream.
        ended: bool,
    },
    /// The peer accepted this many octets of the presented payload.
    Write {
        /// The accepted octet count, which is at most the presented count.
        accepted: u64,
    },
    /// The family refused the call before any effect of this call.
    FamilyRefused(IoFamilyFault),
    /// The endpoint observed a contained operational fault.
    Operational(IoOperationalFault),
    /// The endpoint reported a protected native diagnostic.
    Native(IoNativeDiagnostic),
}

/// One completion presented against the call it claims to answer.
///
/// The claimed binding is compared with the dispatched binding, so a completion of another
/// operation, generation, owner, kind, or quantity is detected instead of being published.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IoHostResponse {
    binding: IoCallBinding,
    completion: IoHostCompletion,
}

impl IoHostResponse {
    /// Presents one completion for the binding it claims to answer.
    #[must_use]
    pub const fn new(binding: IoCallBinding, completion: IoHostCompletion) -> Self {
        Self {
            binding,
            completion,
        }
    }

    /// Returns the binding this completion claims to answer.
    #[must_use]
    pub const fn binding(&self) -> &IoCallBinding {
        &self.binding
    }

    /// Returns the presented completion.
    #[must_use]
    pub const fn completion(&self) -> &IoHostCompletion {
        &self.completion
    }
}

/// Executor-neutral host boundary for one bounded one-call I/O attempt.
///
/// An implementation performs at most one call, returns exactly one completion for the binding it
/// was given, and neither retries nor polls. It supplies no scheduler, executor, async
/// cancellation, authority admission, or source carrier: the caller's service owns the settlement.
pub trait BoundedIoEndpoint {
    /// Performs this one bounded call and reports the facts it observed.
    fn attempt(&mut self, call: &IoCallBinding, provided: &[u8]) -> IoHostResponse;
}

/// The exact evidence one settlement publishes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IoEvidence {
    /// This settlement publishes no octet evidence.
    NoOctets,
    /// Exactly the initialized returned octets, including the final octets at end of stream.
    Read {
        /// The octet count the call asked for.
        requested: u64,
        /// The initialized octets the endpoint returned, and no spare capacity.
        returned: Vec<u8>,
        /// Whether this read observed the end of its stream.
        ended: bool,
    },
    /// Exactly the accepted prefix of the presented payload.
    Write {
        /// The octet count the caller presented.
        provided: u64,
        /// The octet count the endpoint accepted.
        accepted: u64,
        /// Exactly the accepted prefix; the remainder stays with the caller.
        prefix: Vec<u8>,
    },
}

/// One published settlement of one bounded call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IoSettlement {
    binding: IoCallBinding,
    outcome: ExternalOutcome,
    progress: ProgressObservation,
    state: ResourceState,
    evidence: IoEvidence,
    observation: Option<ProgressRecord>,
    settled_at_us: u64,
}

impl IoSettlement {
    /// Returns the exact call this settlement answers.
    #[must_use]
    pub const fn binding(&self) -> &IoCallBinding {
        &self.binding
    }

    /// Returns the observed external outcome, which is never reclassified.
    #[must_use]
    pub const fn outcome(&self) -> ExternalOutcome {
        self.outcome
    }

    /// Returns the declared progress observation of this call.
    #[must_use]
    pub const fn progress(&self) -> ProgressObservation {
        self.progress
    }

    /// Returns the landed resource state the model projected for this settlement.
    #[must_use]
    pub const fn state(&self) -> ResourceState {
        self.state
    }

    /// Returns the exact evidence this settlement publishes.
    ///
    /// A cancelled settlement withholds its octets from publication and keeps them here as
    /// protected evidence, so an accepted prefix stays observable without being reported as
    /// successful output.
    #[must_use]
    pub const fn evidence(&self) -> &IoEvidence {
        &self.evidence
    }

    /// Returns the charged Section 20 progress record of this settlement when one was retained.
    #[must_use]
    pub const fn observation(&self) -> Option<&ProgressRecord> {
        self.observation.as_ref()
    }

    /// Returns the explicit logical instant of settlement.
    #[must_use]
    pub const fn settled_at_us(&self) -> u64 {
        self.settled_at_us
    }
}

/// One settlement of a call whose peer was not ready.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IoBlockedCall {
    settlement: IoSettlement,
    backpressure: IoBackpressure,
    readiness: ReadinessObservation,
}

impl IoBlockedCall {
    /// Returns the one settlement of this blocked attempt.
    #[must_use]
    pub const fn settlement(&self) -> &IoSettlement {
        &self.settlement
    }

    /// Returns the declared backpressure witness this attempt observed.
    #[must_use]
    pub const fn backpressure(&self) -> IoBackpressure {
        self.backpressure
    }

    /// Returns the Section 24 readiness fact of this attempt's own initial recheck.
    ///
    /// The fact is the readiness observed for this attempt alone. A later call is a separately
    /// admitted occurrence the caller must decide to make; this module never polls, retries, or
    /// treats one blocked attempt as progress of a stream.
    #[must_use]
    pub const fn readiness(&self) -> ReadinessObservation {
        self.readiness
    }
}

/// How far one attempt got before it settled.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IoAttemptStage {
    /// The attempt was refused before any call was dispatched and before any effect.
    NotDispatched,
    /// The call was dispatched; its external effects are not claimed to be undone.
    Dispatched,
}

/// One settlement of an interrupted or cancelled attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IoCancelledCall {
    settlement: IoSettlement,
    stage: IoAttemptStage,
    blocked: Option<IoBackpressure>,
}

impl IoCancelledCall {
    /// Returns the one settlement of this cancelled attempt.
    #[must_use]
    pub const fn settlement(&self) -> &IoSettlement {
        &self.settlement
    }

    /// Returns how far the attempt got before cancellation settled it.
    #[must_use]
    pub const fn stage(&self) -> IoAttemptStage {
        self.stage
    }

    /// Returns the not-ready witness this attempt observed before cancellation settled it.
    ///
    /// Cancellation withholds publication but never erases a witness the completion established, so
    /// a blocked call that is cancelled still reports which peer was not ready.
    #[must_use]
    pub const fn blocked(&self) -> Option<IoBackpressure> {
        self.blocked
    }
}

/// The distinct kind of one failed bounded call.
///
/// The kinds are never substituted for one another: a family domain refusal is not an operational
/// fault, a protected native diagnostic is not a domain refusal, and neither is a model refusal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IoCallFault {
    /// A contained operational fault of a dispatched call.
    Operational(IoOperationalFault),
    /// A family-declared domain refusal presented before any effect of the call.
    Family(IoFamilyFault),
    /// A protected native diagnostic, contained and never disclosed as portable output.
    Native(IoNativeDiagnostic),
    /// The landed Section 20 model refused an observation or settlement candidate.
    Model(OperationAbiError),
    /// The landed transport boundary refused or failed.
    Transport(HostResourceError),
}

/// Whether one failed call published a settlement.
// The published value is the settlement itself. Boxing it would move the exact evidence one
// indirection away from the caller that must inspect it, and one settlement exists per attempt, so
// the flat value stays bounded by construction.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IoPublication {
    /// The attempt published exactly this settlement.
    Published(IoSettlement),
    /// The model refused the settlement, so nothing was published and no effect is claimed undone.
    Refused(IoCallFault),
}

impl IoPublication {
    /// Returns the published settlement, when this attempt published one.
    #[must_use]
    pub const fn settlement(&self) -> Option<&IoSettlement> {
        match self {
            Self::Published(settlement) => Some(settlement),
            Self::Refused(_) => None,
        }
    }
}

/// One contained failure of a bounded call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IoFailedCall {
    fault: IoCallFault,
    publication: IoPublication,
    stage: IoAttemptStage,
    cancelled: bool,
}

impl IoFailedCall {
    /// Returns the distinct kind of this failure.
    #[must_use]
    pub const fn fault(&self) -> &IoCallFault {
        &self.fault
    }

    /// Returns the settlement this failure published, when one was published.
    #[must_use]
    pub const fn settlement(&self) -> Option<&IoSettlement> {
        self.publication.settlement()
    }

    /// Returns whether this failure published a settlement.
    #[must_use]
    pub const fn publication(&self) -> &IoPublication {
        &self.publication
    }

    /// Returns how far the attempt got before the failure was contained.
    #[must_use]
    pub const fn stage(&self) -> IoAttemptStage {
        self.stage
    }

    /// Returns whether cancellation was observed at this attempt own recheck instant.
    ///
    /// The fault is always the fault the completion established. Cancellation is recorded here as
    /// an additional settlement fact, so a cancelled attempt never reports a smaller fault set than
    /// the same attempt would report without cancellation.
    #[must_use]
    pub const fn cancelled(&self) -> bool {
        self.cancelled
    }
}

/// One refusal that occurred before any call was dispatched and before any effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IoRefusal {
    /// This attempt already settled; a later completion cannot publish or refund twice.
    DuplicateSettlement,
    /// The request kind differs from the kind this occurrence declares.
    RequestKind {
        /// The kind the occurrence declares.
        declared: IoOperation,
        /// The kind the request declares.
        request: IoOperation,
    },
    /// This slice delivers no seek: cursor state belongs to an ineligible live source carrier.
    UnsupportedOperation {
        /// The request kind this boundary does not deliver.
        operation: IoOperation,
    },
    /// A write presented a payload that does not match its admitted quantity.
    PayloadQuantity {
        /// The octet count the request admitted.
        requested: u64,
        /// The octet count the caller presented.
        provided: u64,
    },
    /// A read presented a payload, which a read cannot carry.
    PayloadNotApplicable {
        /// The kind of the call.
        operation: IoOperation,
    },
    /// The receiver is not the exclusive borrowed loan of its generation.
    NotAReceiverLoan {
        /// The declared receiver arrangement, which is never a borrowed loan here.
        arrangement: &'static str,
    },
    /// The receiver generation was fenced before this attempt.
    Fenced {
        /// The category that fenced the generation.
        category: FenceCategory,
    },
    /// The receiver already carries a settlement.
    AlreadySettled,
    /// The receiver's declared state does not admit a call.
    NotUsable {
        /// The declared state that refused the attempt.
        state: ResourceState,
    },
    /// The declared observation allowance cannot record any progress for this attempt.
    ObservationAllowanceExhausted {
        /// The allowance remaining.
        remaining: u64,
        /// The charge one observation consumes.
        charge: u64,
    },
    /// Machine cancellation closed admission before this attempt dispatched.
    CancelledBeforeAdmission,
    /// The pending occurrence is no longer pending for this attempt.
    NoPendingOccurrence,
    /// The account's admission lease is unreadable, so admission cannot be established.
    AdmissionLeaseUnreadable,
    /// The account is not the pending occurrence's own subject.
    ForeignOccurrence,
    /// The receiver loan root is not live on the account.
    LoanRootNotLive,
    /// The landed transport boundary refused the attempt before dispatch.
    Transport(HostResourceError),
}

/// The single settlement outcome of one bounded attempt.
// The published value is the settlement itself. Boxing it would move the exact evidence one
// indirection away from the caller that must inspect it, and one settlement exists per attempt, so
// the flat value stays bounded by construction.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IoCallOutcome {
    /// The call settled with the observed facts of one completion.
    Settled(IoSettlement),
    /// The peer observed not ready, and this attempt settled once with its readiness fact.
    Blocked(IoBlockedCall),
    /// Cancellation or interruption settled this attempt; it is not progress.
    Cancelled(IoCancelledCall),
    /// The attempt failed with one distinct fault kind, contained without partial publication.
    Failed(IoFailedCall),
    /// The attempt was refused before dispatch, so no effect and no settlement occurred.
    Refused(IoRefusal),
}

/// One bounded in-memory byte endpoint with a declared retention capacity.
///
/// The endpoint models one in-memory stream: exactly the initialized octets are readable, a read
/// exposes no spare capacity, and a write accepts at most the declared capacity and reports exactly
/// the prefix it accepted. It performs no filesystem, socket, console, or process I/O and holds no
/// source handle.
pub struct InMemoryIoTransport {
    shared: Arc<Mutex<InMemoryIoState>>,
}

/// The private state one in-memory endpoint owns, kept behind the registry-held physical slot.
struct InMemoryIoState {
    /// Exactly the initialized octets of this stream.
    contents: Vec<u8>,
    /// The next unread octet of `contents`.
    position: usize,
    /// The greatest retained octet count this endpoint accepts.
    capacity: usize,
    /// The kind whose peer this endpoint declares not ready, when one is declared.
    not_ready: Option<IoOperation>,
    /// The number of calls this endpoint actually performed.
    calls: u64,
}

impl InMemoryIoTransport {
    /// Builds one bounded in-memory endpoint over exactly these initialized octets.
    ///
    /// # Errors
    ///
    /// Refuses a zero capacity, a capacity beyond the declared Section 45 octet bound, and an
    /// initialized length beyond the capacity, because an endpoint may never retain or expose
    /// more than it declared.
    pub fn bounded(contents: Vec<u8>, capacity: u64) -> Result<Self, IoOperationalFault> {
        let declared = usize::try_from(capacity).unwrap_or(usize::MAX);
        if capacity == 0
            || capacity > gantry_ir::IO_REQUEST_OCTET_BOUND
            || contents.len() > declared
        {
            return Err(IoOperationalFault::Capacity {
                declared: capacity,
                maximum: gantry_ir::IO_REQUEST_OCTET_BOUND,
                initialized: u64::try_from(contents.len()).unwrap_or(u64::MAX),
            });
        }
        Ok(Self {
            shared: Arc::new(Mutex::new(InMemoryIoState {
                contents,
                position: 0,
                capacity: declared,
                not_ready: None,
                calls: 0,
            })),
        })
    }

    /// Returns an observation handle over the same registry-held octets.
    ///
    /// The handle observes retention and readiness only; it grants no machine authority, no
    /// admission, and no receipt, and it does not move or copy the physical value.
    #[must_use]
    pub fn handle(&self) -> InMemoryIoHandle {
        InMemoryIoHandle {
            shared: Arc::clone(&self.shared),
        }
    }

    /// Completes this one call against the retained state.
    fn complete(&mut self, call: &IoCallBinding, provided: &[u8]) -> IoHostCompletion {
        let Ok(mut state) = self.shared.lock() else {
            return IoHostCompletion::Operational(IoOperationalFault::StateUnreadable);
        };
        state.calls = state.calls.saturating_add(1);
        let operation = call.request().operation();
        if state.not_ready == Some(operation) {
            return match backpressure_of(operation) {
                Some(backpressure) => IoHostCompletion::Blocked {
                    operation: backpressure,
                },
                None => IoHostCompletion::Operational(IoOperationalFault::UnsupportedRequest {
                    operation,
                }),
            };
        }
        match operation {
            IoOperation::Read => {
                let requested = usize::try_from(call.quantity()).unwrap_or(usize::MAX);
                let available = state.contents.len().saturating_sub(state.position);
                let take = requested.min(available);
                let start = state.position;
                let end = start.saturating_add(take);
                let bytes = state.contents.get(start..end).unwrap_or_default().to_vec();
                state.position = end;
                IoHostCompletion::Read {
                    advanced: u64::try_from(take).unwrap_or(u64::MAX),
                    bytes,
                    ended: state.position >= state.contents.len(),
                }
            }
            IoOperation::Write => {
                let spare = state.capacity.saturating_sub(state.contents.len());
                let presented = provided.len();
                let accept = spare.min(presented);
                let accepted = provided.get(..accept).unwrap_or_default();
                state.contents.extend_from_slice(accepted);
                IoHostCompletion::Write {
                    accepted: u64::try_from(accept).unwrap_or(u64::MAX),
                }
            }
            IoOperation::Seek => {
                IoHostCompletion::Operational(IoOperationalFault::UnsupportedRequest { operation })
            }
        }
    }
}

impl BoundedIoEndpoint for InMemoryIoTransport {
    /// Performs exactly one bounded call and answers the binding it was given.
    fn attempt(&mut self, call: &IoCallBinding, provided: &[u8]) -> IoHostResponse {
        let completion = self.complete(call, provided);
        IoHostResponse::new(call.clone(), completion)
    }
}

/// One observation handle over an [`InMemoryIoTransport`]'s retained octets.
///
/// The handle is the in-memory analogue of observing a registry-owned physical slot: it shows the
/// retained octets and declared readiness after every observer of the attempt has been dropped.
pub struct InMemoryIoHandle {
    shared: Arc<Mutex<InMemoryIoState>>,
}

impl InMemoryIoHandle {
    /// Returns exactly the retained initialized octets.
    #[must_use]
    pub fn retained(&self) -> Vec<u8> {
        self.shared
            .lock()
            .map(|state| state.contents.clone())
            .unwrap_or_default()
    }

    /// Returns the next unread octet index.
    #[must_use]
    pub fn position(&self) -> usize {
        self.shared.lock().map(|state| state.position).unwrap_or(0)
    }

    /// Returns the declared retention capacity.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.shared.lock().map(|state| state.capacity).unwrap_or(0)
    }

    /// Returns how many calls this endpoint actually performed.
    #[must_use]
    pub fn calls(&self) -> u64 {
        self.shared.lock().map(|state| state.calls).unwrap_or(0)
    }

    /// Declares one kind whose peer this endpoint reports not ready, or clears the declaration.
    pub fn declare_not_ready(&self, operation: Option<IoOperation>) {
        if let Ok(mut state) = self.shared.lock() {
            state.not_ready = operation;
        }
    }
}

/// Bounded settlement service for one authenticated Section 45 receiver occurrence.
///
/// The service holds no physical value and no account borrow of its own: the endpoint stays in the
/// registry-held slot the caller bound, and one attempt borrows the account for the length of that
/// single call. One attempt publishes at most one settlement, and the service refuses a second
/// attempt rather than charging, observing, or settling twice.
pub struct IoSettlementService<'a> {
    machine: &'a Machine,
    owner: OwnerGeneration,
    kind: IoOperation,
    allowance: ObservationAllowance,
    charges: Vec<Charge>,
    settled_at_us: u64,
    settled: bool,
}

impl<'a> IoSettlementService<'a> {
    /// Admits one settlement service over the pending occurrence of one bound account.
    ///
    /// * `machine` is the issuing machine; its pending occurrence supplies identity, generation,
    ///   site, and recovery, so no caller names them.
    /// * `owner` is the current owner generation of the account.
    /// * `kind` is the receiver kind the boundary declares for this occurrence.
    /// * `allowance` is the Section 20 observation allowance this attempt may charge.
    /// * `charges` is the exact Section 28 loan-charge vector the landed loan admission commits.
    /// * `settled_at_us` is the explicit logical instant this attempt settles at.
    ///
    /// # Errors
    ///
    /// Refuses before any loan, charge, observation, or effect when the declared observation
    /// allowance cannot charge one observation.
    pub fn new(
        machine: &'a Machine,
        owner: OwnerGeneration,
        kind: IoOperation,
        allowance: ObservationAllowance,
        charges: Vec<Charge>,
        settled_at_us: u64,
    ) -> Result<Self, IoRefusal> {
        if allowance.is_exhausted() {
            return Err(IoRefusal::ObservationAllowanceExhausted {
                remaining: allowance.remaining(),
                charge: allowance.charge().value(),
            });
        }
        Ok(Self {
            machine,
            owner,
            kind,
            allowance,
            charges,
            settled_at_us,
            settled: false,
        })
    }

    /// Returns the receiver kind this service settles.
    #[must_use]
    pub const fn kind(&self) -> IoOperation {
        self.kind
    }

    /// Returns whether this service already settled its attempted call.
    #[must_use]
    pub const fn is_settled(&self) -> bool {
        self.settled
    }

    /// Performs and settles exactly one bounded call of this occurrence.
    ///
    /// `provided` is the caller payload: empty for a read, and exactly the admitted quantity for a
    /// write. The caller keeps the remainder of its payload after a short write; the settlement
    /// publishes only the accepted prefix.
    ///
    /// The order is deliberate and deterministic: the request and payload are checked, the
    /// admission lease is rechecked, the landed exclusive loan is admitted, the endpoint performs
    /// one call under the landed containment boundary, the admission lease is rechecked once more,
    /// and only then are progress and the settlement published. A refusal before dispatch leaves no
    /// effect; a failure after dispatch is contained without publication and without any claim that
    /// an external effect was undone.
    pub fn attempt<T: BoundedIoEndpoint>(
        &mut self,
        resource: &mut OwnedHostResource<T>,
        request: IoRequest,
        provided: &[u8],
    ) -> IoCallOutcome {
        if self.settled {
            return IoCallOutcome::Refused(IoRefusal::DuplicateSettlement);
        }
        if let Some(refusal) = pre_dispatch_refusal(self.kind, &request, provided) {
            return IoCallOutcome::Refused(refusal);
        }
        let lease = resource.account().subject().admission_lease();
        match admission_state(&lease) {
            AdmissionState::Open => {}
            AdmissionState::Cancelled => {
                return IoCallOutcome::Refused(IoRefusal::CancelledBeforeAdmission);
            }
            AdmissionState::Closed => {
                return IoCallOutcome::Refused(IoRefusal::NoPendingOccurrence);
            }
            AdmissionState::Unreadable => {
                return IoCallOutcome::Refused(IoRefusal::AdmissionLeaseUnreadable);
            }
        }
        let loan = match resource.borrow_receiver_from_pending(
            self.machine,
            self.owner,
            self.allowance,
            &self.charges,
        ) {
            Ok(loan) => loan,
            Err(error) => return IoCallOutcome::Refused(transport_refusal(error)),
        };
        self.settled = true;
        settle_attempt(
            loan,
            self.kind,
            request,
            provided,
            self.settled_at_us,
            &lease,
        )
    }
}

/// The machine-issued admission fact one bounded attempt rechecks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AdmissionState {
    /// Admission is pending and no cancellation was requested.
    Open,
    /// Cancellation was requested before this attempt dispatched.
    Cancelled,
    /// Accepted work already closed admission for this occurrence.
    Closed,
    /// The lease is poisoned, so no admission can be established.
    Unreadable,
}

/// Reads the authoritative admission fact without fabricating one from an unreadable lease.
fn admission_state(lease: &Mutex<crate::machine::ResourceOperationLease>) -> AdmissionState {
    match lease.lock() {
        Ok(admission) if admission.cancellation_requested => AdmissionState::Cancelled,
        Ok(admission) if !admission.pending => AdmissionState::Closed,
        Ok(_) => AdmissionState::Open,
        Err(_) => AdmissionState::Unreadable,
    }
}

/// Refuses one request before dispatch when it does not belong to this bounded attempt.
fn pre_dispatch_refusal(
    kind: IoOperation,
    request: &IoRequest,
    provided: &[u8],
) -> Option<IoRefusal> {
    if request.operation() != kind {
        return Some(IoRefusal::RequestKind {
            declared: kind,
            request: request.operation(),
        });
    }
    match kind {
        IoOperation::Read if !provided.is_empty() => Some(IoRefusal::PayloadNotApplicable {
            operation: IoOperation::Read,
        }),
        IoOperation::Write if provided.len() as u64 != request.quantity() => {
            Some(IoRefusal::PayloadQuantity {
                requested: request.quantity(),
                provided: provided.len() as u64,
            })
        }
        IoOperation::Seek => Some(IoRefusal::UnsupportedOperation {
            operation: IoOperation::Seek,
        }),
        IoOperation::Read | IoOperation::Write => None,
    }
}

/// Maps one landed transport refusal onto this boundary's pre-dispatch refusal set.
fn transport_refusal(error: HostResourceError) -> IoRefusal {
    match error {
        HostResourceError::CancellationRequested => IoRefusal::CancelledBeforeAdmission,
        HostResourceError::PendingOperation => IoRefusal::NoPendingOccurrence,
        HostResourceError::ForeignSubject | HostResourceError::ForeignLoan => {
            IoRefusal::ForeignOccurrence
        }
        HostResourceError::MissingLoanRoot => IoRefusal::LoanRootNotLive,
        HostResourceError::UnknownSubject => IoRefusal::ForeignOccurrence,
        other => IoRefusal::Transport(other),
    }
}

/// Maps one landed transport failure onto a settlement fault.
fn transport_fault(error: HostResourceError) -> IoCallFault {
    match error {
        HostResourceError::Operation(error) => IoCallFault::Model(error),
        other => IoCallFault::Transport(other),
    }
}

/// Returns the declared backpressure kind of one operation kind.
fn backpressure_of(operation: IoOperation) -> Option<IoBackpressure> {
    match operation {
        IoOperation::Read => Some(IoBackpressure::Read),
        IoOperation::Write => Some(IoBackpressure::Write),
        IoOperation::Seek => None,
    }
}

/// Dispatches exactly one call through the landed containment boundary.
fn dispatch<T: BoundedIoEndpoint>(
    loan: &mut HostReceiverLoan<'_, T>,
    binding: &IoCallBinding,
    provided: &[u8],
) -> Result<IoHostResponse, HostResourceError> {
    loan.invoke(|endpoint| Ok(endpoint.attempt(binding, provided)))
}

/// Publishes one observation and settlement, refusing rather than fabricating on model refusal.
fn publish<T: BoundedIoEndpoint>(
    loan: &mut HostReceiverLoan<'_, T>,
    binding: &IoCallBinding,
    outcome: ExternalOutcome,
    progress: ProgressObservation,
    evidence: IoEvidence,
    settled_at_us: u64,
) -> Result<IoSettlement, IoCallFault> {
    let occurrence = binding.occurrence();
    let observation = loan.observe(progress).map_err(transport_fault)?;
    let candidate = OperationSettlement::new(
        occurrence.operation(),
        occurrence.generation(),
        occurrence.owner(),
        outcome,
        progress,
        settled_at_us,
    )
    .map_err(IoCallFault::Model)?;
    let state = loan.settle(&candidate).map_err(transport_fault)?;
    Ok(IoSettlement {
        binding: binding.clone(),
        outcome,
        progress,
        state,
        evidence,
        observation: Some(observation),
        settled_at_us,
    })
}

/// The settlement facts one contained failure still records.
///
/// `progress` is the observation such a failure can still support; `None` settles at the progress
/// the receiver already retained, because a malformed, foreign, refused, or cancelled completion
/// never advances it here and is never published as partial output.
struct FailureFacts {
    /// The observed external outcome this failure records.
    outcome: ExternalOutcome,
    /// The observation this failure can still support, when it supports one.
    progress: Option<ProgressObservation>,
    /// The exact evidence this failure publishes.
    evidence: IoEvidence,
}

/// Publishes one failure settlement and returns the contained failure outcome.
///
/// `progress` is the observation such a failure can still support; `None` settles at the progress
/// the receiver already retained, because a malformed, foreign, or refused completion never
/// advances it here and is never published as partial output.
fn failed<T: BoundedIoEndpoint>(
    loan: &mut HostReceiverLoan<'_, T>,
    binding: &IoCallBinding,
    fault: IoCallFault,
    facts: FailureFacts,
    settled_at_us: u64,
    cancelled: bool,
) -> IoCallOutcome {
    let progress = facts.progress.unwrap_or_else(|| loan.live().progress());
    let publication = match publish(
        loan,
        binding,
        facts.outcome,
        progress,
        facts.evidence,
        settled_at_us,
    ) {
        Ok(settlement) => IoPublication::Published(settlement),
        Err(error) => IoPublication::Refused(error),
    };
    IoCallOutcome::Failed(IoFailedCall {
        fault,
        publication,
        stage: IoAttemptStage::Dispatched,
        cancelled,
    })
}

/// Returns the contained failure of an attempt whose settlement the model refused.
///
/// The refusal is reported as the fault of this attempt: nothing was published, and the accepted
/// work keeps its obligation instead of being reported as a completed call.
fn failed_publication(error: IoCallFault, cancelled: bool) -> IoCallOutcome {
    IoCallOutcome::Failed(IoFailedCall {
        fault: error.clone(),
        publication: IoPublication::Refused(error),
        stage: IoAttemptStage::Dispatched,
        cancelled,
    })
}

/// Settles the one dispatched call of one attempt.
///
/// The occurrence is authenticated from the loan itself, so a completion of another operation,
/// generation, owner, kind, or quantity cannot be published for this call. The admission lease is
/// rechecked once, after the call returned and before any observation, so the completion and
/// cancellation race has one deterministic linearization point. That recheck is read without
/// invention: an observed cancellation settles the attempt as cancelled while withholding
/// publication of octets, a lease that is merely closed or unreadable is a contained failure rather
/// than a cancellation, and a fault the completion established is never erased by a cancellation
/// that raced it.
fn settle_attempt<T: BoundedIoEndpoint>(
    mut loan: HostReceiverLoan<'_, T>,
    kind: IoOperation,
    request: IoRequest,
    provided: &[u8],
    settled_at_us: u64,
    lease: &Mutex<crate::machine::ResourceOperationLease>,
) -> IoCallOutcome {
    let occurrence = match IoOccurrence::authenticate(loan.live(), kind) {
        Ok(occurrence) => occurrence,
        Err(refusal) => return IoCallOutcome::Refused(refusal),
    };
    let binding = match IoCallBinding::bind(occurrence, request) {
        Ok(binding) => binding,
        Err(refusal) => return IoCallOutcome::Refused(refusal),
    };
    let response = match dispatch(&mut loan, &binding, provided) {
        Ok(response) => response,
        Err(HostResourceError::Boundary(_)) => {
            let cancelled = matches!(admission_state(lease), AdmissionState::Cancelled);
            return failed(
                &mut loan,
                &binding,
                IoCallFault::Operational(IoOperationalFault::Panicked),
                FailureFacts {
                    outcome: ExternalOutcome::Ambiguous,
                    progress: None,
                    evidence: IoEvidence::NoOctets,
                },
                settled_at_us,
                cancelled,
            );
        }
        Err(error) => return IoCallOutcome::Refused(IoRefusal::Transport(error)),
    };
    let post = admission_state(lease);
    let cancelled = matches!(post, AdmissionState::Cancelled);
    if response.binding() != &binding {
        return failed(
            &mut loan,
            &binding,
            IoCallFault::Operational(IoOperationalFault::ForeignCompletion),
            FailureFacts {
                outcome: ExternalOutcome::Ambiguous,
                progress: None,
                evidence: IoEvidence::NoOctets,
            },
            settled_at_us,
            cancelled,
        );
    }
    let containment = match post {
        AdmissionState::Unreadable => Some(IoOperationalFault::AdmissionLeaseUnreadable),
        AdmissionState::Closed => Some(IoOperationalFault::AdmissionClosed),
        AdmissionState::Open | AdmissionState::Cancelled => None,
    };
    if let Some(fault) = containment {
        return failed(
            &mut loan,
            &binding,
            IoCallFault::Operational(fault),
            FailureFacts {
                outcome: ExternalOutcome::Ambiguous,
                progress: None,
                evidence: IoEvidence::NoOctets,
            },
            settled_at_us,
            cancelled,
        );
    }
    match classify(response.completion(), &binding, provided) {
        Classification::Settled { progress, evidence } => {
            if cancelled {
                return cancelled_call(
                    &mut loan,
                    &binding,
                    progress,
                    evidence,
                    None,
                    settled_at_us,
                );
            }
            match publish(
                &mut loan,
                &binding,
                ExternalOutcome::Accepted,
                progress,
                evidence,
                settled_at_us,
            ) {
                Ok(settlement) => IoCallOutcome::Settled(settlement),
                Err(error) => failed_publication(error, cancelled),
            }
        }
        Classification::Blocked {
            backpressure,
            progress,
        } => {
            if cancelled {
                return cancelled_call(
                    &mut loan,
                    &binding,
                    progress,
                    IoEvidence::NoOctets,
                    Some(backpressure),
                    settled_at_us,
                );
            }
            match publish(
                &mut loan,
                &binding,
                ExternalOutcome::Rejected,
                progress,
                IoEvidence::NoOctets,
                settled_at_us,
            ) {
                Ok(settlement) => IoCallOutcome::Blocked(IoBlockedCall {
                    settlement,
                    backpressure,
                    readiness: ReadinessObservation::NotReady,
                }),
                Err(error) => failed_publication(error, cancelled),
            }
        }
        Classification::Family(fault) => failed(
            &mut loan,
            &binding,
            IoCallFault::Family(fault),
            FailureFacts {
                outcome: ExternalOutcome::Rejected,
                progress: Some(ProgressObservation::NotStarted),
                evidence: IoEvidence::NoOctets,
            },
            settled_at_us,
            cancelled,
        ),
        Classification::Native(diagnostic) => failed(
            &mut loan,
            &binding,
            IoCallFault::Native(diagnostic),
            FailureFacts {
                outcome: ExternalOutcome::Ambiguous,
                progress: None,
                evidence: IoEvidence::NoOctets,
            },
            settled_at_us,
            cancelled,
        ),
        Classification::Contained { fault, progress } => failed(
            &mut loan,
            &binding,
            IoCallFault::Operational(fault),
            FailureFacts {
                outcome: ExternalOutcome::Ambiguous,
                progress,
                evidence: IoEvidence::NoOctets,
            },
            settled_at_us,
            cancelled,
        ),
    }
}

/// Publishes one cancelled settlement, withholding octets and keeping every observed witness.
///
/// The settlement records an ambiguous external outcome, because a cancelled call may or may not
/// have applied an effect, and it retains any known accepted octets as protected evidence rather
/// than publishing them as output.
fn cancelled_call<T: BoundedIoEndpoint>(
    loan: &mut HostReceiverLoan<'_, T>,
    binding: &IoCallBinding,
    progress: ProgressObservation,
    evidence: IoEvidence,
    blocked: Option<IoBackpressure>,
    settled_at_us: u64,
) -> IoCallOutcome {
    match publish(
        loan,
        binding,
        ExternalOutcome::Ambiguous,
        progress,
        evidence,
        settled_at_us,
    ) {
        Ok(settlement) => IoCallOutcome::Cancelled(IoCancelledCall {
            settlement,
            stage: IoAttemptStage::Dispatched,
            blocked,
        }),
        Err(error) => failed_publication(error, true),
    }
}

/// One completion classified against the call it answers.
enum Classification {
    /// The peer was not ready; this attempt settles once with its readiness fact.
    Blocked {
        /// The declared backpressure witness.
        backpressure: IoBackpressure,
        /// The model-derived progress of a blocked call.
        progress: ProgressObservation,
    },
    /// The call settled with an observed completion.
    Settled {
        /// The model-derived progress of the observed facts.
        progress: ProgressObservation,
        /// The exact evidence this completion may publish.
        evidence: IoEvidence,
    },
    /// The family refused the call before any effect.
    Family(IoFamilyFault),
    /// A protected native diagnostic is contained without publication.
    Native(IoNativeDiagnostic),
    /// The completion is malformed, mismatched, or otherwise contained.
    Contained {
        /// The contained operational fault.
        fault: IoOperationalFault,
        /// The progress such a completion can still support, when any.
        progress: Option<ProgressObservation>,
    },
}

/// Classifies one completion against the binding it answers, without publishing anything.
fn classify(
    completion: &IoHostCompletion,
    binding: &IoCallBinding,
    provided: &[u8],
) -> Classification {
    let request = binding.request();
    match completion {
        IoHostCompletion::Blocked { operation } => {
            if Some(*operation) != backpressure_of(request.operation()) {
                return Classification::Contained {
                    fault: IoOperationalFault::BlockedKind {
                        request: request.operation(),
                        blocked: *operation,
                    },
                    progress: None,
                };
            }
            let facts = IoOutcome::Blocked {
                operation: *operation,
                quantity: request.quantity(),
            };
            match request.derive_progress(&facts) {
                Ok(progress) => Classification::Blocked {
                    backpressure: *operation,
                    progress,
                },
                Err(error) => Classification::Contained {
                    fault: IoOperationalFault::Contract(error),
                    progress: None,
                },
            }
        }
        IoHostCompletion::Read { .. } if request.operation() != IoOperation::Read => {
            Classification::Contained {
                fault: IoOperationalFault::Contract(IoError::RequestMismatch {
                    operation: request.operation(),
                    fact: "operation",
                }),
                progress: None,
            }
        }
        IoHostCompletion::Write { .. } if request.operation() != IoOperation::Write => {
            Classification::Contained {
                fault: IoOperationalFault::Contract(IoError::RequestMismatch {
                    operation: request.operation(),
                    fact: "operation",
                }),
                progress: None,
            }
        }
        IoHostCompletion::Read {
            advanced,
            bytes,
            ended,
        } => {
            let returned = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
            if *advanced != returned {
                return Classification::Contained {
                    fault: IoOperationalFault::ReadLength {
                        advanced: *advanced,
                        returned,
                    },
                    progress: None,
                };
            }
            if returned > request.quantity() {
                return Classification::Contained {
                    fault: IoOperationalFault::ReadOverlong {
                        requested: request.quantity(),
                        returned,
                    },
                    progress: None,
                };
            }
            let facts = IoOutcome::Read {
                requested: request.quantity(),
                advanced: returned,
                ended: *ended,
            };
            match request.derive_progress(&facts) {
                Ok(progress) => Classification::Settled {
                    progress,
                    evidence: IoEvidence::Read {
                        requested: request.quantity(),
                        returned: bytes.clone(),
                        ended: *ended,
                    },
                },
                Err(error) => Classification::Contained {
                    fault: IoOperationalFault::Contract(error),
                    progress: None,
                },
            }
        }
        IoHostCompletion::Write { accepted } => {
            let provided_count = request.quantity();
            let presented = u64::try_from(provided.len()).unwrap_or(u64::MAX);
            if *accepted > provided_count || *accepted > presented {
                return Classification::Contained {
                    fault: IoOperationalFault::WriteOverAccepted {
                        provided: provided_count.min(presented),
                        accepted: *accepted,
                    },
                    progress: None,
                };
            }
            let facts = IoOutcome::Write {
                provided: provided_count,
                accepted: *accepted,
            };
            match request.derive_progress(&facts) {
                Ok(progress) => {
                    let accepted_count = usize::try_from(*accepted).unwrap_or(provided.len());
                    Classification::Settled {
                        progress,
                        evidence: IoEvidence::Write {
                            provided: provided_count,
                            accepted: *accepted,
                            prefix: provided.get(..accepted_count).unwrap_or_default().to_vec(),
                        },
                    }
                }
                Err(error) => Classification::Contained {
                    fault: IoOperationalFault::Contract(error),
                    progress: None,
                },
            }
        }
        IoHostCompletion::FamilyRefused(fault) => Classification::Family(fault.clone()),
        IoHostCompletion::Operational(fault) => Classification::Contained {
            fault: fault.clone(),
            progress: None,
        },
        IoHostCompletion::Native(diagnostic) => Classification::Native(diagnostic.clone()),
    }
}

#[cfg(test)]
mod tests {
    //! Unit lanes for the bounded in-memory settlement service.
    //!
    //! Each lane exercises one declared settlement fact of the reviewed call contract: the request
    //! bound gate, exact initialized read octets including the final end-of-stream octets, exact
    //! accepted write prefixes with the remainder retained by the caller, spare-capacity exhaustion,
    //! one-call settlement of short progress, one blocked attempt with Section 24 readiness,
    //! cancellation before admission and cancellation observed during dispatch, malformed and
    //! request-mismatched completions, foreign and duplicate completions, distinct family,
    //! operational and native failure kinds, and the retention of accepted octets and admission
    //! leases after every observer of the attempt is gone.

    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

    use gantry_core::identity::ProtocolIdentity;
    use gantry_core::portable::IdentityKind;
    use gantry_core::value::DEFAULT_VALUE_LIMITS;
    use gantry_ir::generated::{OperationSiteKind, RecoveryClass};
    use gantry_ir::{
        CanonicalSignature, DisclosureCharge, DurableResourceRecord, EffectSet, ExecutableAction,
        ExecutableOperation, Instruction, InstructionKind, LoanId, MachineProgram,
        ObservationAllowance, OperationAbi, OperationKind, OwnerGeneration, ReceiverOwnership,
        ResourceCarrier, ResourceLedger, ResourceState, TypeDescriptor, Workflow,
    };

    use super::*;
    use crate::machine::ResourceOperationLease;
    use crate::{
        AdmittedResource, Machine, MachineLimits, OwnedHostResource, ResourceSubjectBinding,
    };

    /// One canonical fixture path.
    fn path(name: &str) -> gantry_ir::CanonicalPath {
        gantry_ir::CanonicalPath::new(name).unwrap_or_else(|error| panic!("fixture path: {error}"))
    }

    /// One structural fixture site.
    fn site(index: u64) -> gantry_ir::StructuralPosition {
        gantry_ir::StructuralPosition::new(vec![index])
            .unwrap_or_else(|error| panic!("fixture site: {error}"))
    }

    /// One stable fixture execution identity.
    fn execution() -> ProtocolIdentity {
        ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x5a; 32])
            .unwrap_or_else(|error| panic!("fixture identity: {error}"))
    }

    /// One declared observation allowance of `observations` charged observations.
    fn allowance(observations: u64) -> ObservationAllowance {
        OperationAbi::observation_allowance(
            observations,
            DisclosureCharge::new(1).unwrap_or_else(|| panic!("fixture charge")),
        )
    }

    /// One live-resource action declaration the machine authenticates as Section 20 live.
    fn live_operation() -> ExecutableOperation {
        let action = path("crate::stream");
        ExecutableOperation {
            kind: OperationSiteKind::Action,
            section20_kind: Some(OperationKind::LiveResource),
            result_type: TypeDescriptor::UNIT,
            action: Some(ExecutableAction {
                path: action.clone(),
                signature: CanonicalSignature::action(
                    RecoveryClass::Idempotent,
                    &action,
                    &[],
                    &TypeDescriptor::UNIT,
                ),
                recovery: RecoveryClass::Idempotent,
                parameters: Vec::new(),
            }),
            template_segments: Vec::new(),
            interpolation_types: Vec::new(),
            named_input_names: Vec::new(),
            named_input_types: Vec::new(),
            retry_limit: None,
            session_mode: None,
            attempted: false,
        }
    }

    /// One machine prepared at exactly one pending live-resource occurrence.
    fn live_machine() -> Machine {
        let workflow = Workflow {
            path: path("crate::main"),
            parameters: Vec::new(),
            result: TypeDescriptor::UNIT,
            effects: EffectSet::default(),
            instructions: vec![Instruction {
                site: site(0),
                ty: TypeDescriptor::UNIT,
                kind: InstructionKind::OperationCall {
                    operation: live_operation(),
                    operands: 0,
                },
            }],
        };
        let program = MachineProgram::new(vec![workflow])
            .unwrap_or_else(|error| panic!("fixture program: {error:?}"));
        let limits = MachineLimits::new(64, 8, 8, 4, 8, DEFAULT_VALUE_LIMITS)
            .unwrap_or_else(|| panic!("fixture limits"));
        let mut machine = Machine::new(
            Arc::new(program),
            &path("crate::main"),
            Vec::new(),
            execution(),
            limits,
        )
        .unwrap_or_else(|error| panic!("fixture machine: {error:?}"));
        let _ = machine.step();
        if machine.pending_resource_subject().is_none() {
            panic!("the fixture machine must prepare one live-resource occurrence");
        }
        machine
    }

    /// One account fixture over a machine pending at its live-resource occurrence.
    struct Fixture {
        machine: Machine,
        owner: OwnerGeneration,
        subject: ResourceSubjectBinding,
        record: DurableResourceRecord,
    }

    impl Fixture {
        /// Builds one fixture whose ledger retains the resource and loan liveness roots.
        fn new() -> Self {
            let machine = live_machine();
            let subject = machine
                .pending_resource_subject()
                .unwrap_or_else(|| panic!("pending subject"));
            let owner = OwnerGeneration::new(4);
            let record = ResourceLedger::new(
                owner,
                ResourceState::Usable,
                &[
                    gantry_ir::LivenessRoot::Resource,
                    gantry_ir::LivenessRoot::Loan,
                ],
                &[],
            )
            .unwrap_or_else(|error| panic!("fixture ledger: {error:?}"))
            .durable_record();
            Self {
                machine,
                owner,
                subject,
                record,
            }
        }

        /// Returns the machine-issued admission lease of this occurrence.
        fn lease(&self) -> Arc<Mutex<ResourceOperationLease>> {
            self.subject.admission_lease()
        }

        /// Admits one fresh account and binds one physical endpoint to it.
        fn bind<T: BoundedIoEndpoint>(&self, endpoint: T) -> OwnedHostResource<T> {
            let account = AdmittedResource::admit(
                ResourceCarrier::ReconstructionRecord,
                self.record.clone(),
                self.subject.clone(),
            )
            .unwrap_or_else(|error| panic!("fixture account: {error:?}"));
            OwnedHostResource::bind(account, endpoint)
                .unwrap_or_else(|_| panic!("fixture physical binding"))
        }

        /// Admits one settlement service over the bound account for one receiver kind.
        fn service<'a>(&'a self, kind: IoOperation) -> IoSettlementService<'a> {
            IoSettlementService::new(&self.machine, self.owner, kind, allowance(8), Vec::new(), 7)
                .unwrap_or_else(|error| panic!("fixture service: {error:?}"))
        }
    }

    /// One scripted endpoint that answers with exactly one prepared completion.
    struct ScriptedEndpoint {
        completion: IoHostCompletion,
        lease: Option<Arc<Mutex<ResourceOperationLease>>>,
        mid_call: Option<MidCall>,
        owner_override: Option<OwnerGeneration>,
        calls: Arc<AtomicU64>,
    }

    /// One mid-call mutation of the machine-issued admission lease.
    #[derive(Clone, Copy)]
    enum MidCall {
        /// Report cancellation while the call is in flight.
        Cancel,
        /// Close admission as accepted work would.
        Close,
        /// Poison the lease so no admission fact is readable afterwards.
        Poison,
    }

    /// Poisons one admission lease without printing a panic message.
    fn poison_lease(lease: &Arc<Mutex<ResourceOperationLease>>) {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let poisoned = Arc::clone(lease);
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _guard = poisoned.lock().unwrap_or_else(|error| error.into_inner());
            panic!("poison the admission lease");
        }));
        std::panic::set_hook(previous);
    }

    impl ScriptedEndpoint {
        /// Prepares one endpoint that reports this completion for the call it receives.
        fn new(completion: IoHostCompletion) -> Self {
            Self {
                completion,
                lease: None,
                mid_call: None,
                owner_override: None,
                calls: Arc::new(AtomicU64::new(0)),
            }
        }

        /// Reports cancellation on this account lease while the call is in flight.
        fn cancelling(mut self, lease: Arc<Mutex<ResourceOperationLease>>) -> Self {
            self.lease = Some(lease);
            self.mid_call = Some(MidCall::Cancel);
            self
        }

        /// Closes admission on this account lease while the call is in flight.
        fn closing(mut self, lease: Arc<Mutex<ResourceOperationLease>>) -> Self {
            self.lease = Some(lease);
            self.mid_call = Some(MidCall::Close);
            self
        }

        /// Poisons this account lease while the call is in flight.
        fn poisoning(mut self, lease: Arc<Mutex<ResourceOperationLease>>) -> Self {
            self.lease = Some(lease);
            self.mid_call = Some(MidCall::Poison);
            self
        }

        /// Answers as though another owner generation held the occurrence.
        fn foreign(mut self, owner: OwnerGeneration) -> Self {
            self.owner_override = Some(owner);
            self
        }

        /// Returns the shared call counter of this endpoint.
        fn counter(&self) -> Arc<AtomicU64> {
            Arc::clone(&self.calls)
        }
    }

    impl BoundedIoEndpoint for ScriptedEndpoint {
        fn attempt(&mut self, call: &IoCallBinding, _provided: &[u8]) -> IoHostResponse {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if let (Some(mid_call), Some(lease)) = (self.mid_call, self.lease.as_ref()) {
                match mid_call {
                    MidCall::Cancel => {
                        if let Ok(mut admission) = lease.lock() {
                            admission.cancellation_requested = true;
                        }
                    }
                    MidCall::Close => {
                        if let Ok(mut admission) = lease.lock() {
                            admission.pending = false;
                        }
                    }
                    MidCall::Poison => poison_lease(lease),
                }
            }
            let binding = match self.owner_override {
                Some(owner) => IoCallBinding {
                    occurrence: IoOccurrence {
                        owner,
                        ..call.occurrence().clone()
                    },
                    request: call.request().clone(),
                },
                None => call.clone(),
            };
            IoHostResponse::new(binding, self.completion.clone())
        }
    }

    /// One synthetic live resource of one declared receiver arrangement.
    fn synthetic_live(ownership: ReceiverOwnership) -> LiveResource {
        let declaration = path("crate::stream");
        let static_site = StaticSiteId::new(path("crate::main"), site(0));
        let abi = OperationAbi::new(
            OperationKind::LiveResource,
            &declaration,
            &static_site,
            0,
            RecoveryClass::Idempotent,
            ownership,
        )
        .unwrap_or_else(|error| panic!("synthetic abi: {error:?}"));
        abi.open_live(OwnerGeneration::new(1), allowance(4))
            .unwrap_or_else(|error| panic!("synthetic live: {error:?}"))
    }

    /// One synthetic exclusive receiver loan of one sealed generation.
    fn synthetic_loan_live() -> LiveResource {
        let declaration = path("crate::stream");
        let static_site = StaticSiteId::new(path("crate::main"), site(0));
        let operation = LogicalOperationId::derive(&declaration, &static_site);
        let generation = ResourceGenerationId::derive(&operation, &static_site, 0);
        synthetic_live(ReceiverOwnership::BorrowedLoan(LoanId::seal(
            &declaration,
            &static_site,
            &generation,
        )))
    }

    /// A read of an initialized stream publishes exactly its octets and the final end-of-stream octet.
    #[test]
    fn a_read_publishes_exactly_the_initialized_octets_including_final_eof_octets() {
        let fixture = Fixture::new();
        let transport = InMemoryIoTransport::bounded(b"ab".to_vec(), 4)
            .unwrap_or_else(|error| panic!("transport: {error:?}"));
        let handle = transport.handle();
        let mut resource = fixture.bind(transport);
        let mut service = fixture.service(IoOperation::Read);
        let outcome = service.attempt(
            &mut resource,
            IoRequest::read(4).unwrap_or_else(|error| panic!("request: {error:?}")),
            &[],
        );
        let IoCallOutcome::Settled(settlement) = outcome else {
            panic!("a short final read must settle, observed {outcome:?}")
        };
        assert_eq!(settlement.progress(), ProgressObservation::Eof);
        assert_eq!(settlement.outcome(), ExternalOutcome::Accepted);
        assert_eq!(settlement.state(), ResourceState::Closed);
        assert_eq!(
            settlement.evidence(),
            &IoEvidence::Read {
                requested: 4,
                returned: b"ab".to_vec(),
                ended: true,
            }
        );
        assert_eq!(handle.retained(), b"ab".to_vec());
        assert_eq!(handle.capacity(), 4);
        assert_eq!(handle.calls(), 1);
        assert_eq!(
            resource.account().durable_record().operation_state(),
            ResourceState::Closed
        );
    }

    /// Short progress settles this one call, and a later attempt on the same service is refused.
    #[test]
    fn short_progress_settles_one_call_and_a_later_attempt_is_refused() {
        let fixture = Fixture::new();
        let endpoint = ScriptedEndpoint::new(IoHostCompletion::Read {
            advanced: 1,
            bytes: b"a".to_vec(),
            ended: false,
        });
        let counter = endpoint.counter();
        let mut resource = fixture.bind(endpoint);
        let mut service = fixture.service(IoOperation::Read);
        let request = IoRequest::read(3).unwrap_or_else(|error| panic!("request: {error:?}"));
        let outcome = service.attempt(&mut resource, request.clone(), &[]);
        let IoCallOutcome::Settled(settlement) = outcome else {
            panic!("short progress must settle this call, observed {outcome:?}")
        };
        assert_eq!(settlement.progress(), ProgressObservation::ShortRead);
        assert_eq!(settlement.state(), ResourceState::PartiallyAdvanced);
        assert_eq!(
            settlement.evidence(),
            &IoEvidence::Read {
                requested: 3,
                returned: b"a".to_vec(),
                ended: false,
            }
        );
        let settled_record = resource.account().durable_record();
        let second = service.attempt(&mut resource, request, &[]);
        assert_eq!(
            second,
            IoCallOutcome::Refused(IoRefusal::DuplicateSettlement)
        );
        assert_eq!(resource.account().durable_record(), settled_record);
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    /// A full read of one call advances the stream by exactly that call, and no further.
    #[test]
    fn a_committed_read_advances_the_stream_by_exactly_one_call() {
        let fixture = Fixture::new();
        let transport = InMemoryIoTransport::bounded(b"abcdef".to_vec(), 8)
            .unwrap_or_else(|error| panic!("transport: {error:?}"));
        let handle = transport.handle();
        let mut resource = fixture.bind(transport);
        let mut service = fixture.service(IoOperation::Read);
        let outcome = service.attempt(
            &mut resource,
            IoRequest::read(2).unwrap_or_else(|error| panic!("request: {error:?}")),
            &[],
        );
        let IoCallOutcome::Settled(settlement) = outcome else {
            panic!("a committed read must settle, observed {outcome:?}")
        };
        assert_eq!(
            settlement.progress(),
            ProgressObservation::CommittedProgress
        );
        assert_eq!(settlement.state(), ResourceState::Consumed);
        assert_eq!(handle.position(), 2);
        assert_eq!(handle.retained(), b"abcdef".to_vec());
        assert_eq!(handle.calls(), 1);
    }

    /// A write publishes exactly its accepted prefix and the caller keeps the remainder.
    #[test]
    fn a_write_publishes_the_exact_accepted_prefix_and_the_caller_keeps_the_remainder() {
        let fixture = Fixture::new();
        let transport = InMemoryIoTransport::bounded(b"abc".to_vec(), 5)
            .unwrap_or_else(|error| panic!("transport: {error:?}"));
        let handle = transport.handle();
        let mut resource = fixture.bind(transport);
        let mut service = fixture.service(IoOperation::Write);
        let payload = b"WXYZ".to_vec();
        let outcome = service.attempt(
            &mut resource,
            IoRequest::write(4).unwrap_or_else(|error| panic!("request: {error:?}")),
            &payload,
        );
        let IoCallOutcome::Settled(settlement) = outcome else {
            panic!("a short write must settle, observed {outcome:?}")
        };
        assert_eq!(settlement.progress(), ProgressObservation::ShortWrite);
        assert_eq!(settlement.state(), ResourceState::PartiallyAdvanced);
        assert_eq!(
            settlement.evidence(),
            &IoEvidence::Write {
                provided: 4,
                accepted: 2,
                prefix: b"WX".to_vec(),
            }
        );
        assert_eq!(payload, b"WXYZ".to_vec());
        assert_eq!(handle.retained(), b"abcWX".to_vec());
    }

    /// The bounded transport refuses a capacity outside its own declared bound.
    #[test]
    fn the_bounded_transport_refuses_a_capacity_outside_its_declared_bound() {
        assert_eq!(
            InMemoryIoTransport::bounded(Vec::new(), 0).err(),
            Some(IoOperationalFault::Capacity {
                declared: 0,
                maximum: gantry_ir::IO_REQUEST_OCTET_BOUND,
                initialized: 0,
            })
        );
        assert_eq!(
            InMemoryIoTransport::bounded(vec![0_u8; 5], 4).err(),
            Some(IoOperationalFault::Capacity {
                declared: 4,
                maximum: gantry_ir::IO_REQUEST_OCTET_BOUND,
                initialized: 5,
            })
        );
        assert!(InMemoryIoTransport::bounded(Vec::new(), 4).is_ok());
        assert!(
            InMemoryIoTransport::bounded(
                Vec::new(),
                gantry_ir::IO_REQUEST_OCTET_BOUND.saturating_add(1)
            )
            .is_err()
        );
    }

    /// A write at the declared capacity accepts nothing and reports no progress.
    #[test]
    fn a_write_at_declared_capacity_settles_without_accepting_an_octet() {
        let fixture = Fixture::new();
        let transport = InMemoryIoTransport::bounded(b"abc".to_vec(), 3)
            .unwrap_or_else(|error| panic!("transport: {error:?}"));
        let handle = transport.handle();
        let mut resource = fixture.bind(transport);
        let mut service = fixture.service(IoOperation::Write);
        let outcome = service.attempt(
            &mut resource,
            IoRequest::write(2).unwrap_or_else(|error| panic!("request: {error:?}")),
            b"XY",
        );
        let IoCallOutcome::Settled(settlement) = outcome else {
            panic!("a full sink must settle, observed {outcome:?}")
        };
        assert_eq!(settlement.progress(), ProgressObservation::NotStarted);
        assert_eq!(settlement.state(), ResourceState::Usable);
        assert_eq!(
            settlement.evidence(),
            &IoEvidence::Write {
                provided: 2,
                accepted: 0,
                prefix: Vec::new(),
            }
        );
        assert_eq!(handle.retained(), b"abc".to_vec());
        assert_eq!(handle.capacity(), 3);
    }

    /// A blocked attempt settles once with the Section 24 readiness fact and performs one call.
    #[test]
    fn a_blocked_attempt_settles_once_with_section_24_readiness() {
        let fixture = Fixture::new();
        let transport = InMemoryIoTransport::bounded(b"ab".to_vec(), 4)
            .unwrap_or_else(|error| panic!("transport: {error:?}"));
        let handle = transport.handle();
        handle.declare_not_ready(Some(IoOperation::Read));
        let mut resource = fixture.bind(transport);
        let mut service = fixture.service(IoOperation::Read);
        let request = IoRequest::read(2).unwrap_or_else(|error| panic!("request: {error:?}"));
        let outcome = service.attempt(&mut resource, request.clone(), &[]);
        let IoCallOutcome::Blocked(blocked) = outcome else {
            panic!("a not-ready peer must settle as blocked, observed {outcome:?}")
        };
        assert_eq!(blocked.backpressure(), IoBackpressure::Read);
        assert_eq!(blocked.readiness(), ReadinessObservation::NotReady);
        assert_eq!(blocked.settlement().outcome(), ExternalOutcome::Rejected);
        assert_eq!(
            blocked.settlement().progress(),
            ProgressObservation::NotStarted
        );
        assert_eq!(blocked.settlement().state(), ResourceState::Usable);
        assert_eq!(blocked.settlement().evidence(), &IoEvidence::NoOctets);
        assert_eq!(handle.calls(), 1);
        assert_eq!(handle.retained(), b"ab".to_vec());
        assert_eq!(handle.position(), 0);
        assert_eq!(
            service.attempt(&mut resource, request, &[]),
            IoCallOutcome::Refused(IoRefusal::DuplicateSettlement)
        );
    }

    /// A zero, excess, or mismatched request is refused before any call reaches the endpoint.
    #[test]
    fn invalid_requests_refuse_before_any_call_reaches_the_endpoint() {
        assert!(IoRequest::read(0).is_err());
        assert!(IoRequest::write(0).is_err());
        assert!(IoRequest::read(gantry_ir::IO_REQUEST_OCTET_BOUND + 1).is_err());
        assert!(IoRequest::write(gantry_ir::IO_REQUEST_OCTET_BOUND + 1).is_err());
        assert_eq!(
            IoRequest::read(gantry_ir::IO_REQUEST_OCTET_BOUND).map(|request| request.quantity()),
            Ok(gantry_ir::IO_REQUEST_OCTET_BOUND)
        );

        let fixture = Fixture::new();
        let write_transport = InMemoryIoTransport::bounded(Vec::new(), 8)
            .unwrap_or_else(|error| panic!("write transport: {error:?}"));
        let write_handle = write_transport.handle();
        let mut write_resource = fixture.bind(write_transport);
        let mut write_service = fixture.service(IoOperation::Write);
        let outcome = write_service.attempt(
            &mut write_resource,
            IoRequest::write(2).unwrap_or_else(|error| panic!("write request: {error:?}")),
            b"X",
        );
        assert_eq!(
            outcome,
            IoCallOutcome::Refused(IoRefusal::PayloadQuantity {
                requested: 2,
                provided: 1,
            })
        );
        assert_eq!(write_handle.calls(), 0);

        let read_transport = InMemoryIoTransport::bounded(b"ab".to_vec(), 4)
            .unwrap_or_else(|error| panic!("read transport: {error:?}"));
        let read_handle = read_transport.handle();
        let mut read_resource = fixture.bind(read_transport);
        let mut read_service = fixture.service(IoOperation::Read);
        let outcome = read_service.attempt(
            &mut read_resource,
            IoRequest::read(2).unwrap_or_else(|error| panic!("read request: {error:?}")),
            b"X",
        );
        assert_eq!(
            outcome,
            IoCallOutcome::Refused(IoRefusal::PayloadNotApplicable {
                operation: IoOperation::Read,
            })
        );
        assert_eq!(read_handle.calls(), 0);
        assert_eq!(read_handle.retained(), b"ab".to_vec());
    }

    /// This slice delivers no seek, so a seek request is refused before any effect.
    #[test]
    fn a_seek_request_is_refused_before_any_call() {
        let fixture = Fixture::new();
        let transport = InMemoryIoTransport::bounded(b"ab".to_vec(), 4)
            .unwrap_or_else(|error| panic!("transport: {error:?}"));
        let handle = transport.handle();
        let mut resource = fixture.bind(transport);
        let mut service = fixture.service(IoOperation::Seek);
        let outcome = service.attempt(&mut resource, IoRequest::seek(2), &[]);
        assert_eq!(
            outcome,
            IoCallOutcome::Refused(IoRefusal::UnsupportedOperation {
                operation: IoOperation::Seek,
            })
        );
        assert_eq!(handle.calls(), 0);
    }

    /// An exhausted observation allowance is refused before any loan, charge, or effect.
    #[test]
    fn an_exhausted_observation_allowance_is_refused_before_effects() {
        let fixture = Fixture::new();
        let transport = InMemoryIoTransport::bounded(b"ab".to_vec(), 4)
            .unwrap_or_else(|error| panic!("transport: {error:?}"));
        let handle = transport.handle();
        let resource = fixture.bind(transport);
        let record = resource.account().durable_record();
        let refusal = IoSettlementService::new(
            &fixture.machine,
            fixture.owner,
            IoOperation::Read,
            allowance(0),
            Vec::new(),
            7,
        )
        .err()
        .unwrap_or_else(|| panic!("an exhausted allowance must refuse"));
        assert_eq!(
            refusal,
            IoRefusal::ObservationAllowanceExhausted {
                remaining: 0,
                charge: 1,
            }
        );
        assert_eq!(handle.calls(), 0);
        assert_eq!(resource.account().durable_record(), record);
    }

    /// Cancellation before admission refuses the attempt without dispatching anything.
    #[test]
    fn cancellation_before_admission_refuses_without_dispatch() {
        let fixture = Fixture::new();
        let transport = InMemoryIoTransport::bounded(b"ab".to_vec(), 4)
            .unwrap_or_else(|error| panic!("transport: {error:?}"));
        let handle = transport.handle();
        let mut resource = fixture.bind(transport);
        let record = resource.account().durable_record();
        let lease = fixture.lease();
        let mut service = fixture.service(IoOperation::Read);
        lease
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .cancellation_requested = true;
        let outcome = service.attempt(
            &mut resource,
            IoRequest::read(2).unwrap_or_else(|error| panic!("request: {error:?}")),
            &[],
        );
        assert_eq!(
            outcome,
            IoCallOutcome::Refused(IoRefusal::CancelledBeforeAdmission)
        );
        assert_eq!(handle.calls(), 0);
        assert_eq!(handle.retained(), b"ab".to_vec());
        assert_eq!(resource.account().durable_record(), record);
        assert!(!service.is_settled());
    }

    /// Cancellation observed during dispatch withholds publication and keeps the known prefix.
    #[test]
    fn cancellation_after_dispatch_withholds_publication_and_keeps_the_prefix() {
        let fixture = Fixture::new();
        let endpoint = ScriptedEndpoint::new(IoHostCompletion::Write { accepted: 3 })
            .cancelling(fixture.lease());
        let counter = endpoint.counter();
        let mut resource = fixture.bind(endpoint);
        let mut service = fixture.service(IoOperation::Write);
        let payload = b"ABCDE".to_vec();
        let outcome = service.attempt(
            &mut resource,
            IoRequest::write(5).unwrap_or_else(|error| panic!("request: {error:?}")),
            &payload,
        );
        let IoCallOutcome::Cancelled(cancelled) = outcome else {
            panic!("a cancellation during dispatch must settle as cancelled, observed {outcome:?}")
        };
        assert_eq!(cancelled.stage(), IoAttemptStage::Dispatched);
        assert_eq!(cancelled.settlement().outcome(), ExternalOutcome::Ambiguous);
        assert_eq!(cancelled.settlement().state(), ResourceState::Poisoned);
        assert_eq!(
            cancelled.settlement().evidence(),
            &IoEvidence::Write {
                provided: 5,
                accepted: 3,
                prefix: b"ABC".to_vec(),
            }
        );
        assert_eq!(
            resource.account().durable_record().operation_state(),
            ResourceState::Poisoned
        );
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    /// A malformed completion length is contained without publishing any octet.
    #[test]
    fn a_malformed_completion_length_is_contained_without_publication() {
        let fixture = Fixture::new();
        let endpoint = ScriptedEndpoint::new(IoHostCompletion::Read {
            advanced: 5,
            bytes: b"ab".to_vec(),
            ended: false,
        });
        let mut resource = fixture.bind(endpoint);
        let mut service = fixture.service(IoOperation::Read);
        let outcome = service.attempt(
            &mut resource,
            IoRequest::read(5).unwrap_or_else(|error| panic!("request: {error:?}")),
            &[],
        );
        let IoCallOutcome::Failed(failed) = outcome else {
            panic!("a malformed length must be contained, observed {outcome:?}")
        };
        assert_eq!(
            failed.fault(),
            &IoCallFault::Operational(IoOperationalFault::ReadLength {
                advanced: 5,
                returned: 2,
            })
        );
        let settlement = failed
            .settlement()
            .unwrap_or_else(|| panic!("a contained failure still settles this attempt once"));
        assert_eq!(settlement.evidence(), &IoEvidence::NoOctets);
        assert_eq!(settlement.outcome(), ExternalOutcome::Ambiguous);
        assert_eq!(settlement.state(), ResourceState::Poisoned);
        assert_eq!(
            resource.account().durable_record().operation_state(),
            ResourceState::Poisoned
        );
    }

    /// A completion of another kind than the request is a contained request mismatch.
    #[test]
    fn a_request_mismatched_completion_is_contained() {
        let fixture = Fixture::new();
        let endpoint = ScriptedEndpoint::new(IoHostCompletion::Write { accepted: 1 });
        let mut resource = fixture.bind(endpoint);
        let mut service = fixture.service(IoOperation::Read);
        let outcome = service.attempt(
            &mut resource,
            IoRequest::read(2).unwrap_or_else(|error| panic!("request: {error:?}")),
            &[],
        );
        let IoCallOutcome::Failed(failed) = outcome else {
            panic!("a mismatched completion must be contained, observed {outcome:?}")
        };
        assert_eq!(
            failed.fault(),
            &IoCallFault::Operational(IoOperationalFault::Contract(IoError::RequestMismatch {
                operation: IoOperation::Read,
                fact: "operation",
            }))
        );
        let settlement = failed
            .settlement()
            .unwrap_or_else(|| panic!("a mismatched completion still settles this attempt once"));
        assert_eq!(settlement.evidence(), &IoEvidence::NoOctets);
    }

    /// A completion for another owner generation cannot publish anything.
    #[test]
    fn a_completion_for_another_owner_cannot_publish() {
        let fixture = Fixture::new();
        let endpoint = ScriptedEndpoint::new(IoHostCompletion::Read {
            advanced: 0,
            bytes: Vec::new(),
            ended: false,
        })
        .foreign(OwnerGeneration::new(9));
        let counter = endpoint.counter();
        let mut resource = fixture.bind(endpoint);
        let mut service = fixture.service(IoOperation::Read);
        let request = IoRequest::read(2).unwrap_or_else(|error| panic!("request: {error:?}"));
        let outcome = service.attempt(&mut resource, request.clone(), &[]);
        let IoCallOutcome::Failed(failed) = outcome else {
            panic!("a foreign completion must be contained, observed {outcome:?}")
        };
        assert_eq!(
            failed.fault(),
            &IoCallFault::Operational(IoOperationalFault::ForeignCompletion)
        );
        let settlement = failed
            .settlement()
            .unwrap_or_else(|| panic!("a foreign completion settles at most once"));
        assert_eq!(settlement.evidence(), &IoEvidence::NoOctets);
        assert_eq!(settlement.state(), ResourceState::Poisoned);
        let settled_record = resource.account().durable_record();
        assert_eq!(
            service.attempt(&mut resource, request, &[]),
            IoCallOutcome::Refused(IoRefusal::DuplicateSettlement)
        );
        assert_eq!(resource.account().durable_record(), settled_record);
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    /// A duplicate settlement cannot publish or refund twice.
    #[test]
    fn a_duplicate_settlement_cannot_publish_or_refund_twice() {
        let fixture = Fixture::new();
        let transport = InMemoryIoTransport::bounded(b"ab".to_vec(), 4)
            .unwrap_or_else(|error| panic!("transport: {error:?}"));
        let handle = transport.handle();
        let mut resource = fixture.bind(transport);
        let mut service = fixture.service(IoOperation::Read);
        let request = IoRequest::read(2).unwrap_or_else(|error| panic!("request: {error:?}"));
        assert!(matches!(
            service.attempt(&mut resource, request.clone(), &[]),
            IoCallOutcome::Settled(_)
        ));
        let settled_record = resource.account().durable_record();
        assert_eq!(
            service.attempt(&mut resource, request, &[]),
            IoCallOutcome::Refused(IoRefusal::DuplicateSettlement)
        );
        assert_eq!(resource.account().durable_record(), settled_record);
        assert_eq!(handle.calls(), 1);
    }

    /// Family, operational, and native failures stay distinct and keep their own settlement shape.
    #[test]
    fn family_operational_and_native_failures_stay_distinct() {
        let family_code =
            IoFamilyFault::new("family::refused").unwrap_or_else(|| panic!("family code"));
        let family_fixture = Fixture::new();
        let family_endpoint =
            ScriptedEndpoint::new(IoHostCompletion::FamilyRefused(family_code.clone()));
        let mut family_resource = family_fixture.bind(family_endpoint);
        let mut family_service = family_fixture.service(IoOperation::Read);
        let family_outcome = family_service.attempt(
            &mut family_resource,
            IoRequest::read(2).unwrap_or_else(|error| panic!("family request: {error:?}")),
            &[],
        );
        let IoCallOutcome::Failed(family_failure) = family_outcome else {
            panic!("a family refusal must fail, observed {family_outcome:?}")
        };
        assert_eq!(family_failure.fault(), &IoCallFault::Family(family_code));
        assert_eq!(
            family_failure
                .settlement()
                .map(|settlement| settlement.outcome()),
            Some(ExternalOutcome::Rejected)
        );
        assert_eq!(
            family_failure
                .settlement()
                .map(|settlement| settlement.state()),
            Some(ResourceState::Usable)
        );

        let operational_fixture = Fixture::new();
        let operational_endpoint = ScriptedEndpoint::new(IoHostCompletion::Operational(
            IoOperationalFault::StateUnreadable,
        ));
        let mut operational_resource = operational_fixture.bind(operational_endpoint);
        let mut operational_service = operational_fixture.service(IoOperation::Read);
        let operational_outcome = operational_service.attempt(
            &mut operational_resource,
            IoRequest::read(2).unwrap_or_else(|error| panic!("operational request: {error:?}")),
            &[],
        );
        let IoCallOutcome::Failed(operational_failure) = operational_outcome else {
            panic!("an operational fault must fail, observed {operational_outcome:?}")
        };
        assert_eq!(
            operational_failure.fault(),
            &IoCallFault::Operational(IoOperationalFault::StateUnreadable)
        );
        assert_eq!(
            operational_failure
                .settlement()
                .map(|settlement| settlement.outcome()),
            Some(ExternalOutcome::Ambiguous)
        );
        assert_eq!(
            operational_failure
                .settlement()
                .map(|settlement| settlement.state()),
            Some(ResourceState::Poisoned)
        );

        let class =
            IoNativeDiagnostic::new("host-terminal").unwrap_or_else(|| panic!("native class"));
        let native_fixture = Fixture::new();
        let native_endpoint = ScriptedEndpoint::new(IoHostCompletion::Native(class.clone()));
        let mut native_resource = native_fixture.bind(native_endpoint);
        let mut native_service = native_fixture.service(IoOperation::Read);
        let native_outcome = native_service.attempt(
            &mut native_resource,
            IoRequest::read(2).unwrap_or_else(|error| panic!("native request: {error:?}")),
            &[],
        );
        let IoCallOutcome::Failed(native_failure) = native_outcome else {
            panic!("a native diagnostic must fail, observed {native_outcome:?}")
        };
        assert_eq!(native_failure.fault(), &IoCallFault::Native(class));
        assert_eq!(
            native_failure
                .settlement()
                .map(|settlement| settlement.outcome()),
            Some(ExternalOutcome::Ambiguous)
        );
    }

    /// An empty family code or native class is refused at the boundary.
    #[test]
    fn an_empty_family_code_or_native_class_is_refused() {
        assert!(IoFamilyFault::new("").is_none());
        assert!(IoNativeDiagnostic::new("").is_none());
    }

    /// Only an exclusive borrowed receiver loan can carry a bounded call.
    #[test]
    fn only_an_exclusive_borrowed_receiver_loan_carries_a_bounded_call() {
        let retained = synthetic_live(ReceiverOwnership::RetainedByCaller);
        assert_eq!(
            IoOccurrence::authenticate(&retained, IoOperation::Read),
            Err(IoRefusal::NotAReceiverLoan {
                arrangement: "retained-by-caller",
            })
        );

        let mut loan = synthetic_loan_live();
        let occurrence = IoOccurrence::authenticate(&loan, IoOperation::Write)
            .unwrap_or_else(|error| panic!("a loan carries a call: {error:?}"));
        assert_eq!(occurrence.kind(), IoOperation::Write);
        assert_eq!(occurrence.owner(), loan.owner());
        assert_eq!(occurrence.generation(), loan.generation());
        assert_eq!(
            IoCallBinding::bind(
                occurrence.clone(),
                IoRequest::read(1).unwrap_or_else(|error| panic!("request: {error:?}"))
            ),
            Err(IoRefusal::RequestKind {
                declared: IoOperation::Write,
                request: IoOperation::Read,
            })
        );

        loan.fence(FenceCategory::Revocation);
        assert_eq!(
            IoOccurrence::authenticate(&loan, IoOperation::Write),
            Err(IoRefusal::Fenced {
                category: FenceCategory::Revocation,
            })
        );
    }

    /// A cancellation that races a malformed completion cannot erase the contained fault.
    #[test]
    fn a_cancelled_malformed_completion_keeps_the_contained_fault() {
        let fixture = Fixture::new();
        let endpoint = ScriptedEndpoint::new(IoHostCompletion::Read {
            advanced: 5,
            bytes: b"ab".to_vec(),
            ended: false,
        })
        .cancelling(fixture.lease());
        let mut resource = fixture.bind(endpoint);
        let mut service = fixture.service(IoOperation::Read);
        let outcome = service.attempt(
            &mut resource,
            IoRequest::read(5).unwrap_or_else(|error| panic!("request: {error:?}")),
            &[],
        );
        let IoCallOutcome::Failed(failed) = outcome else {
            panic!("a cancelled malformed completion must fail, observed {outcome:?}")
        };
        assert_eq!(
            failed.fault(),
            &IoCallFault::Operational(IoOperationalFault::ReadLength {
                advanced: 5,
                returned: 2,
            })
        );
        assert!(failed.cancelled());
        let settlement = failed
            .settlement()
            .unwrap_or_else(|| panic!("a cancelled failure still settles this attempt once"));
        assert_eq!(settlement.outcome(), ExternalOutcome::Ambiguous);
        assert_eq!(settlement.evidence(), &IoEvidence::NoOctets);
    }

    /// A cancellation that races a family refusal keeps the domain fault distinct.
    #[test]
    fn a_cancelled_family_refusal_keeps_the_domain_fault() {
        let code = IoFamilyFault::new("family::refused").unwrap_or_else(|| panic!("family code"));
        let fixture = Fixture::new();
        let endpoint = ScriptedEndpoint::new(IoHostCompletion::FamilyRefused(code.clone()))
            .cancelling(fixture.lease());
        let mut resource = fixture.bind(endpoint);
        let mut service = fixture.service(IoOperation::Read);
        let outcome = service.attempt(
            &mut resource,
            IoRequest::read(2).unwrap_or_else(|error| panic!("request: {error:?}")),
            &[],
        );
        let IoCallOutcome::Failed(failed) = outcome else {
            panic!("a cancelled family refusal must fail, observed {outcome:?}")
        };
        assert_eq!(failed.fault(), &IoCallFault::Family(code));
        assert!(failed.cancelled());
        let settlement = failed
            .settlement()
            .unwrap_or_else(|| panic!("a cancelled family refusal settles once"));
        assert_eq!(settlement.outcome(), ExternalOutcome::Rejected);
        assert_eq!(settlement.state(), ResourceState::Usable);
    }

    /// A cancelled blocked attempt keeps the not-ready witness it observed.
    #[test]
    fn a_cancelled_blocked_attempt_keeps_the_readiness_witness() {
        let fixture = Fixture::new();
        let endpoint = ScriptedEndpoint::new(IoHostCompletion::Blocked {
            operation: IoBackpressure::Read,
        })
        .cancelling(fixture.lease());
        let mut resource = fixture.bind(endpoint);
        let mut service = fixture.service(IoOperation::Read);
        let outcome = service.attempt(
            &mut resource,
            IoRequest::read(2).unwrap_or_else(|error| panic!("request: {error:?}")),
            &[],
        );
        let IoCallOutcome::Cancelled(blocked) = outcome else {
            panic!("a cancelled blocked attempt settles as cancelled, observed {outcome:?}")
        };
        assert_eq!(blocked.blocked(), Some(IoBackpressure::Read));
        assert_eq!(blocked.stage(), IoAttemptStage::Dispatched);
        assert_eq!(
            blocked.settlement().progress(),
            ProgressObservation::NotStarted
        );
        assert_eq!(blocked.settlement().outcome(), ExternalOutcome::Ambiguous);
        assert_eq!(blocked.settlement().evidence(), &IoEvidence::NoOctets);
    }

    /// A closed admission after dispatch is contained, and is not reported as cancellation.
    #[test]
    fn a_closed_admission_after_dispatch_is_contained_not_cancelled() {
        let fixture = Fixture::new();
        let endpoint = ScriptedEndpoint::new(IoHostCompletion::Read {
            advanced: 2,
            bytes: b"ab".to_vec(),
            ended: true,
        })
        .closing(fixture.lease());
        let mut resource = fixture.bind(endpoint);
        let mut service = fixture.service(IoOperation::Read);
        let outcome = service.attempt(
            &mut resource,
            IoRequest::read(2).unwrap_or_else(|error| panic!("request: {error:?}")),
            &[],
        );
        let IoCallOutcome::Failed(failed) = outcome else {
            panic!("a closed admission must be contained, observed {outcome:?}")
        };
        assert_eq!(
            failed.fault(),
            &IoCallFault::Operational(IoOperationalFault::AdmissionClosed)
        );
        assert!(!failed.cancelled());
        let settlement = failed
            .settlement()
            .unwrap_or_else(|| panic!("a closed admission still settles this attempt once"));
        assert_eq!(settlement.outcome(), ExternalOutcome::Ambiguous);
        assert_eq!(settlement.evidence(), &IoEvidence::NoOctets);
    }

    /// An admission lease poisoned after dispatch is contained, not read as cancellation.
    #[test]
    fn an_unreadable_lease_after_dispatch_is_contained_not_cancelled() {
        let fixture = Fixture::new();
        let endpoint = ScriptedEndpoint::new(IoHostCompletion::Read {
            advanced: 2,
            bytes: b"ab".to_vec(),
            ended: true,
        })
        .poisoning(fixture.lease());
        let mut resource = fixture.bind(endpoint);
        let mut service = fixture.service(IoOperation::Read);
        let outcome = service.attempt(
            &mut resource,
            IoRequest::read(2).unwrap_or_else(|error| panic!("request: {error:?}")),
            &[],
        );
        let IoCallOutcome::Failed(failed) = outcome else {
            panic!("an unreadable lease must be contained, observed {outcome:?}")
        };
        assert_eq!(
            failed.fault(),
            &IoCallFault::Operational(IoOperationalFault::AdmissionLeaseUnreadable)
        );
        assert!(!failed.cancelled());
    }

    /// An admission lease poisoned before dispatch refuses admission without any effect.
    #[test]
    fn an_unreadable_lease_before_dispatch_refuses_admission() {
        let fixture = Fixture::new();
        let transport = InMemoryIoTransport::bounded(b"ab".to_vec(), 4)
            .unwrap_or_else(|error| panic!("transport: {error:?}"));
        let handle = transport.handle();
        let mut resource = fixture.bind(transport);
        let record = resource.account().durable_record();
        poison_lease(&fixture.lease());
        let mut service = fixture.service(IoOperation::Read);
        let outcome = service.attempt(
            &mut resource,
            IoRequest::read(2).unwrap_or_else(|error| panic!("request: {error:?}")),
            &[],
        );
        assert_eq!(
            outcome,
            IoCallOutcome::Refused(IoRefusal::AdmissionLeaseUnreadable)
        );
        assert_eq!(handle.calls(), 0);
        assert_eq!(resource.account().durable_record(), record);
    }

    /// Dropping the attempt retains the accepted octets and the admission lease.
    ///
    /// The accepted octets live in the endpoint the caller bound, and the admission lease is shared
    /// with the machine-issued subject, so losing the settlement service and the attempt outcome
    /// keeps both. Registry-owned retention across loss of the binding itself, and off-worker
    /// physical cleanup of it, are the consumer slice integration and are not claimed here.
    #[test]
    fn dropping_the_attempt_retains_accepted_octets_and_the_admission_lease() {
        let fixture = Fixture::new();
        let lease = fixture.lease();
        let transport = InMemoryIoTransport::bounded(b"abc".to_vec(), 8)
            .unwrap_or_else(|error| panic!("transport: {error:?}"));
        let handle = transport.handle();
        let mut resource = fixture.bind(transport);
        let settled_record = {
            let mut service = fixture.service(IoOperation::Write);
            let outcome = service.attempt(
                &mut resource,
                IoRequest::write(3).unwrap_or_else(|error| panic!("request: {error:?}")),
                b"XYZ",
            );
            assert!(matches!(outcome, IoCallOutcome::Settled(_)));
            resource.account().durable_record()
        };
        assert_eq!(handle.retained(), b"abcXYZ".to_vec());
        assert!(
            lease
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .pending
        );
        assert_eq!(settled_record.operation_state(), ResourceState::Consumed);
        drop(resource);
        assert_eq!(handle.retained(), b"abcXYZ".to_vec());
    }
}
