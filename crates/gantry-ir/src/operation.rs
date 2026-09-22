//! Pure operation-ABI model for value actions, protected operations, and live resources.
//!
//! This module is the machine-checked model for `GNT-20.0` through
//! `GNT-20.11-adapter-obligations-and-diagnostics`. It states value actions and
//! live-resource operations
//! (`GNT-20.0-value-actions-and-live-resource-operations`), operation kinds
//! (`GNT-20.1-operation-kinds`), logical operation and resource-generation identity
//! (`GNT-20.2-logical-operation-and-resource-generation-identity`), receiver loans
//! and ownership transfer (`GNT-20.3-receiver-loan-and-ownership-transfer`), partial
//! progress and EOF (`GNT-20.4-partial-progress-and-eof`), interruption,
//! cancellation, and late completion
//! (`GNT-20.5-interruption-cancellation-and-late-completion`), ambiguous-effect
//! classification and retry eligibility
//! (`GNT-20.6-ambiguous-effect-classification-and-retry-eligibility`), resource state
//! after failure and poisoning
//! (`GNT-20.7-resource-state-after-failure-and-poisoning`), half-close and
//! post-failure ownership (`GNT-20.8-half-close-and-post-failure-ownership`),
//! deduplication retention and compaction
//! (`GNT-20.9-deduplication-retention-and-compaction`), retirement and stale-owner
//! fencing (`GNT-20.10-retirement-and-stale-owner-fencing`), and adapter obligations
//! and diagnostics (`GNT-20.11-adapter-obligations-and-diagnostics`).
//!
//! Scope is deliberately narrow. Every rule here is a pure function of its own
//! arguments: this module reads no host path, environment variable, clock, locale,
//! filesystem, socket, or service, and it exposes no constructor that accepts one.
//! Settlement instants are explicit logical microseconds supplied by the caller
//! under the landed admission model of `GNT-3-T-AUTHORITY-ADMISSION`, and resource
//! and owner generations are explicit counters supplied by the caller, so every
//! verdict is reproducible from its own arguments. This module is not a resource
//! registry, not an adapter, not a deduplication store, and not a scheduler.
//!
//! Landed types are reused rather than redeclared. The stable logical operation
//! identity is the landed [`LogicalOperationId`] of `GNT-19.2-approval-subject`,
//! which is the stable approval-subject identity and never the path-derived dynamic
//! dispatch identity of `GNT-7.16`; the exact source site is the landed
//! [`StaticSiteId`]; the selected downstream implementation is the landed
//! [`CanonicalImplementationIdentity`]; the observed external outcome is the landed
//! [`ExternalOutcome`]; the fencing category of a fenced generation is the landed
//! [`FenceCategory`]; the recovery class is the generated [`RecoveryClass`]; the
//! nonzero charge size of the observation allowance is the landed
//! [`crate::protected::DisclosureCharge`]; and operation, generation, loan, and
//! adapter identities are derived with the landed canonical-encoding helpers. This
//! module adds no second operation-site vocabulary, no second recovery rule, and no
//! second rights lattice, and it adds no release accounting at all: the observation
//! accounting of a live resource is this module's own [`ObservationAllowance`], while
//! a Section 15 [`crate::protected::DisclosureBudget`] is charged per accepted
//! release and is never charged, consumed, or projected by an observation.
//!
//! Five separations stay explicit.
//!
//! * A live-resource operation is never a durable value. [`OperationAbi::open_live`]
//!   refuses a value action or a protected operation, and
//!   [`OperationAbi::durable_value`] refuses a live-resource operation, so no
//!   operation kind can be read as, reported as, or substituted for another one.
//! * A [`ResourceGenerationId`] is an opaque domain-separated digest over one
//!   logical operation identity, one exact site, and one explicit generation
//!   counter. It has no free constructor and no deserializer, so a stale generation
//!   can never settle a later operation.
//! * A [`OperationSettlement`] is the single durable settlement of one resource
//!   generation. [`LiveResource::settle`] accepts at most one per generation, so a
//!   duplicate, late, or wrong-generation completion loses the race rather than
//!   settling twice, and a cancellation race has exactly one settlement winner.
//! * A [`DedupRecord`] carries its own identity and retention bounds and is never a
//!   cache. An ambiguous effect is retried only through the record of that exact
//!   operation and generation, a retired record fences the stale owner instead of
//!   admitting a new invocation, and compaction preserves every identity needed to
//!   redispatch.
//! * An observation consumes the declared [`ObservationAllowance`] of the
//!   live-resource observation channel and nothing else. A claimed settlement
//!   progress must equal the observed progress or be a declared upgrade of it, so
//!   progress never moves backwards and a completion is never reported as an end of
//!   stream or the reverse.

use std::fmt;
use std::sync::Arc;

use crate::approval::LogicalOperationId;
use crate::authority::{AuthorityRight, ExternalOutcome, FenceCategory, RightsSet, digest_fields};
use crate::generated::RecoveryClass;
use crate::manifest::encode_hex;
use crate::protected::DisclosureCharge;
use crate::{CanonicalImplementationIdentity, CanonicalPath, StaticSiteId};

/// Domain separator for the canonical resource-generation encoding.
const RESOURCE_GENERATION_DOMAIN: &str = "gantry.resource-generation/v1";

/// Domain separator for the canonical sealed receiver-loan encoding.
const LOAN_DOMAIN: &str = "gantry.receiver-loan/v1";

/// Domain separator for the canonical adapter-instance encoding.
const ADAPTER_DOMAIN: &str = "gantry.adapter-instance/v1";

/// The clause keys this model implements, in clause order.
///
/// Every diagnostic of this module names exactly one of these keys through
/// [`OperationAbiDiagnosticCode::requirement`], so every refusal is attributable to
/// the clause that owns it.
pub const OPERATION_ABI_CLAUSES: [&str; 12] = [
    "GNT-20.0-value-actions-and-live-resource-operations",
    "GNT-20.1-operation-kinds",
    "GNT-20.2-logical-operation-and-resource-generation-identity",
    "GNT-20.3-receiver-loan-and-ownership-transfer",
    "GNT-20.4-partial-progress-and-eof",
    "GNT-20.5-interruption-cancellation-and-late-completion",
    "GNT-20.6-ambiguous-effect-classification-and-retry-eligibility",
    "GNT-20.7-resource-state-after-failure-and-poisoning",
    "GNT-20.8-half-close-and-post-failure-ownership",
    "GNT-20.9-deduplication-retention-and-compaction",
    "GNT-20.10-retirement-and-stale-owner-fencing",
    "GNT-20.11-adapter-obligations-and-diagnostics",
];

/// Encodes one number as its big-endian bytes.
fn number(value: u64) -> Vec<u8> {
    value.to_be_bytes().to_vec()
}

/// Encodes one structural route as fixed-width big-endian components.
fn components(values: &[u64]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(values.len() * 8);
    for value in values {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    bytes
}

/// Returns the landed authority right one declared recovery class demands.
const fn required_right(recovery: RecoveryClass) -> AuthorityRight {
    match recovery {
        RecoveryClass::ReadOnly => AuthorityRight::InvokeReadOnly,
        RecoveryClass::Idempotent => AuthorityRight::InvokeIdempotent,
        RecoveryClass::NonIdempotent => AuthorityRight::InvokeNonIdempotent,
    }
}

/// One owner generation of the receiver that holds one resource.
///
/// The generation is an explicit caller-supplied counter rather than a clock, a
/// process identifier, or an adapter handle, and it only ever advances: retirement
/// requires a generation that succeeds the settling one, so a stale owner can never
/// claim the resources of a later owner
/// (`GNT-20.10-retirement-and-stale-owner-fencing`).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OwnerGeneration(u64);

impl OwnerGeneration {
    /// Returns the initial owner generation of a fresh receiver.
    #[must_use]
    pub const fn initial() -> Self {
        Self(0)
    }

    /// Returns the owner generation of one explicit counter value.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the explicit counter value.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }

    /// Returns the next owner generation, saturating at the counter maximum.
    #[must_use]
    pub const fn advanced(self) -> Self {
        Self(self.0.saturating_add(1))
    }

    /// Returns whether this generation succeeds one earlier generation.
    #[must_use]
    pub const fn succeeds(self, previous: Self) -> bool {
        self.0 > previous.0
    }
}

impl fmt::Display for OwnerGeneration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

/// One closed operation kind (`GNT-20.1-operation-kinds`).
///
/// The three kinds are distinct and exhaustive. A [`Self::ValueAction`] and a
/// [`Self::ProtectedOperation`] produce a durable value and carry no live handle; a
/// [`Self::LiveResource`] carries a live handle and is never reported as a durable
/// value. Membership of a kind is decided once, at declaration, and no operation
/// changes kind later.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum OperationKind {
    /// A value action: a durable value with no live handle.
    ValueAction,
    /// A protected operation over protected data: a durable value with no live
    /// handle.
    ProtectedOperation,
    /// A live-resource operation: a live handle that is never a durable value.
    LiveResource,
}

impl OperationKind {
    /// Every member of the closed vocabulary, in wire-name order.
    pub const ALL: [Self; 3] = [
        Self::LiveResource,
        Self::ProtectedOperation,
        Self::ValueAction,
    ];

    /// Returns the kind one analyzed value-resource classification authenticates, if any.
    ///
    /// A value that contains a live source resource authenticates a live-resource operation. A
    /// value that contains none authenticates nothing: a non-live result is either a value action
    /// or a protected operation, and the resource class alone never distinguishes them, so the
    /// caller must not assume either one. A declaration-level fact that also separates protection
    /// is needed before the non-live arm can be authenticated by anyone.
    #[must_use]
    pub const fn for_value_resource_class(
        class: crate::type_properties::ValueResourceClass,
    ) -> Option<Self> {
        match class {
            crate::type_properties::ValueResourceClass::LiveResource => Some(Self::LiveResource),
            crate::type_properties::ValueResourceClass::NonLiveResource => None,
        }
    }

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::ValueAction => "value-action",
            Self::ProtectedOperation => "protected-operation",
            Self::LiveResource => "live-resource",
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

    /// Returns whether this kind carries a live resource handle.
    #[must_use]
    pub const fn carries_live_handle(self) -> bool {
        matches!(self, Self::LiveResource)
    }

    /// Returns whether this kind produces a durable value.
    ///
    /// The answer is the exact complement of [`Self::carries_live_handle`]: a
    /// live-resource operation is never a durable value, and a value action or a
    /// protected operation carries no live handle.
    #[must_use]
    pub const fn reports_durable_value(self) -> bool {
        !self.carries_live_handle()
    }
}

/// One closed declared state of a live resource
/// (`GNT-20.7-resource-state-after-failure-and-poisoning`,
/// `GNT-20.8-half-close-and-post-failure-ownership`).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ResourceState {
    /// The resource is usable and nothing has advanced it yet.
    Usable,
    /// Some progress was observed and the resource carries it.
    PartiallyAdvanced,
    /// A failure closed one half of the resource and the still-open half survives.
    HalfClosed,
    /// The resource can no longer be relied on or reused.
    Poisoned,
    /// The resource was consumed by a completed operation.
    Consumed,
    /// The resource reached the end of its stream and was closed.
    Closed,
}

impl ResourceState {
    /// Every member of the closed vocabulary, in wire-name order.
    pub const ALL: [Self; 6] = [
        Self::Closed,
        Self::Consumed,
        Self::HalfClosed,
        Self::PartiallyAdvanced,
        Self::Poisoned,
        Self::Usable,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Usable => "usable",
            Self::PartiallyAdvanced => "partially-advanced",
            Self::HalfClosed => "half-closed",
            Self::Poisoned => "poisoned",
            Self::Consumed => "consumed",
            Self::Closed => "closed",
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

    /// Returns whether this state still has an open half.
    ///
    /// Only [`Self::Usable`] and [`Self::PartiallyAdvanced`] have an open half, so a
    /// half-close is meaningful exactly for them.
    #[must_use]
    pub const fn is_open(self) -> bool {
        matches!(self, Self::Usable | Self::PartiallyAdvanced)
    }
}

/// One closed progress observation of one operation
/// (`GNT-20.4-partial-progress-and-eof`).
///
/// A short read and a short write are progress: they are neither an end of stream
/// nor a completion. An end of stream is a distinct observation from a committed
/// completion, so no partial advance is ever read as completion or as EOF.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ProgressObservation {
    /// No progress was observed.
    NotStarted,
    /// A committed completion was observed.
    CommittedProgress,
    /// Partial progress was observed and more remains.
    PartialAdvance,
    /// The stream reached its end.
    Eof,
    /// A read returned less than requested before any end of stream.
    ShortRead,
    /// A write accepted less than provided before any completion.
    ShortWrite,
}

impl ProgressObservation {
    /// Every member of the closed vocabulary, in wire-name order.
    pub const ALL: [Self; 6] = [
        Self::CommittedProgress,
        Self::Eof,
        Self::NotStarted,
        Self::PartialAdvance,
        Self::ShortRead,
        Self::ShortWrite,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::NotStarted => "not-started",
            Self::CommittedProgress => "committed-progress",
            Self::PartialAdvance => "partial-advance",
            Self::Eof => "eof",
            Self::ShortRead => "short-read",
            Self::ShortWrite => "short-write",
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

    /// Returns whether this observation is progress rather than completion or EOF.
    #[must_use]
    pub const fn is_progress(self) -> bool {
        matches!(
            self,
            Self::PartialAdvance | Self::ShortRead | Self::ShortWrite
        )
    }

    /// Returns whether this observation is an end of stream.
    #[must_use]
    pub const fn is_eof(self) -> bool {
        matches!(self, Self::Eof)
    }

    /// Returns whether this observation is a completion.
    ///
    /// An end of stream is a distinct observation from a committed completion, so
    /// this reports `true` for a committed completion alone.
    #[must_use]
    pub const fn is_completion(self) -> bool {
        matches!(self, Self::CommittedProgress)
    }

    /// Returns the declared disposition of this observation.
    #[must_use]
    pub const fn disposition(self) -> ProgressDisposition {
        match self {
            Self::NotStarted => ProgressDisposition::NotStarted,
            Self::CommittedProgress => ProgressDisposition::Completion,
            Self::PartialAdvance | Self::ShortRead | Self::ShortWrite => {
                ProgressDisposition::Progress
            }
            Self::Eof => ProgressDisposition::EndOfStream,
        }
    }

    /// Returns whether `claimed` is a declared upgrade of this observation.
    ///
    /// A resource that has recorded no observation yet takes the settlement's
    /// observation as its first record, so every observation upgrades
    /// [`Self::NotStarted`]. An observation that recorded progress may be followed by
    /// further progress, and a partial advance may be followed by an end of stream,
    /// while a short read and a short write declare no end of stream, so an end of
    /// stream is not an upgrade of them. An end of stream and a committed completion
    /// are terminal, and partial progress is never a completion, so every other pair is
    /// a mismatch: progress never moves backwards and a settlement never reports an
    /// observation the resource's declared progress does not permit. One observation is
    /// always an upgrade of itself.
    #[must_use]
    pub const fn upgrades_to(self, claimed: Self) -> bool {
        matches!(
            (self, claimed),
            (Self::NotStarted, _)
                | (
                    Self::PartialAdvance,
                    Self::PartialAdvance | Self::ShortRead | Self::ShortWrite | Self::Eof,
                )
                | (
                    Self::ShortRead | Self::ShortWrite,
                    Self::PartialAdvance | Self::ShortRead | Self::ShortWrite,
                )
                | (Self::Eof, Self::Eof)
                | (Self::CommittedProgress, Self::CommittedProgress)
        )
    }
}

/// One closed disposition of a progress observation
/// (`GNT-20.4-partial-progress-and-eof`).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ProgressDisposition {
    /// No progress was observed.
    NotStarted,
    /// Progress was observed and more remains.
    Progress,
    /// The stream reached its end without a committed completion.
    EndOfStream,
    /// A committed completion was observed.
    Completion,
}

impl ProgressDisposition {
    /// Every member of the closed vocabulary, in wire-name order.
    pub const ALL: [Self; 4] = [
        Self::Completion,
        Self::EndOfStream,
        Self::NotStarted,
        Self::Progress,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::NotStarted => "not-started",
            Self::Progress => "progress",
            Self::EndOfStream => "end-of-stream",
            Self::Completion => "completion",
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

/// Whether one host cancellation of one operation was requested
/// (`GNT-20.5-interruption-cancellation-and-late-completion`).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum OperationCancellation {
    /// No cancellation was requested.
    NotRequested,
    /// A cancellation was requested and races with admission and dispatch.
    Requested,
}

impl OperationCancellation {
    /// Every member of the closed vocabulary, in wire-name order.
    pub const ALL: [Self; 2] = [Self::NotRequested, Self::Requested];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::NotRequested => "not-requested",
            Self::Requested => "requested",
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

/// One durable cut one operation passes
/// (`GNT-20.5-interruption-cancellation-and-late-completion`).
///
/// The cuts are ordered. An operation that has not passed
/// [`Self::Admitted`] carries no effect and no ambiguity; dispatch is admitted only
/// at or after [`Self::Admitted`].
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DurableOperationCut {
    /// The operation was declared and nothing was admitted.
    Declared,
    /// The operation passed the admission commit point.
    Admitted,
    /// The operation was dispatched to its adapter.
    Dispatched,
    /// The operation was durably settled.
    Settled,
}

impl DurableOperationCut {
    /// Every member of the closed vocabulary, in cut order.
    pub const ALL: [Self; 4] = [
        Self::Declared,
        Self::Admitted,
        Self::Dispatched,
        Self::Settled,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Declared => "declared",
            Self::Admitted => "admitted",
            Self::Dispatched => "dispatched",
            Self::Settled => "settled",
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
            Self::Declared => 0,
            Self::Admitted => 1,
            Self::Dispatched => 2,
            Self::Settled => 3,
        }
    }

    /// Returns whether this cut is at or after the admission commit point.
    #[must_use]
    pub const fn is_at_or_after_admission(self) -> bool {
        self.rank() >= 1
    }
}

/// One certainty classification of one operation's effect
/// (`GNT-20.6-ambiguous-effect-classification-and-retry-eligibility`).
///
/// The vocabulary is exactly two members. An effect is either definitely not
/// started, so nothing was dispatched and no retry can duplicate anything, or it is
/// ambiguously begun, so work may already have reached the target and any retry is
/// gated on the deduplication record of that exact operation and generation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum EffectCertainty {
    /// The operation's effect definitely did not start.
    DefiniteNotStarted,
    /// The operation's effect may have begun.
    AmbiguouslyBegun,
}

impl EffectCertainty {
    /// Every member of the closed vocabulary, in wire-name order.
    pub const ALL: [Self; 2] = [Self::AmbiguouslyBegun, Self::DefiniteNotStarted];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::DefiniteNotStarted => "definite-not-started",
            Self::AmbiguouslyBegun => "ambiguously-begun",
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

    /// Returns whether this classification is a definite not-started effect.
    #[must_use]
    pub const fn is_definite_not_started(self) -> bool {
        matches!(self, Self::DefiniteNotStarted)
    }
}

/// One retry eligibility verdict
/// (`GNT-20.6-ambiguous-effect-classification-and-retry-eligibility`).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RetryEligibility {
    /// The retry may proceed as a fresh invocation.
    Eligible,
    /// The retry is refused.
    Ineligible,
    /// The retry may proceed only through the deduplication proof of the exact
    /// operation and generation.
    RequiresDeduplicationProof,
}

impl RetryEligibility {
    /// Every member of the closed vocabulary, in wire-name order.
    pub const ALL: [Self; 3] = [
        Self::Eligible,
        Self::Ineligible,
        Self::RequiresDeduplicationProof,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Eligible => "eligible",
            Self::Ineligible => "ineligible",
            Self::RequiresDeduplicationProof => "requires-deduplication-proof",
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

    /// Returns whether the retry may proceed as a fresh invocation.
    #[must_use]
    pub const fn is_eligible(self) -> bool {
        matches!(self, Self::Eligible)
    }
}

/// One declared class of failure of one operation
/// (`GNT-20.7-resource-state-after-failure-and-poisoning`).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum FailureClass {
    /// The adapter instance that carried the operation failed.
    AdapterFailure,
    /// The operation failed on the resource itself.
    ResourceFailure,
}

impl FailureClass {
    /// Every member of the closed vocabulary, in wire-name order.
    pub const ALL: [Self; 2] = [Self::AdapterFailure, Self::ResourceFailure];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::AdapterFailure => "adapter-failure",
            Self::ResourceFailure => "resource-failure",
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

/// One closed state of one deduplication record
/// (`GNT-20.9-deduplication-retention-and-compaction`,
/// `GNT-20.10-retirement-and-stale-owner-fencing`).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DedupRecordState {
    /// The record is the authority for one exact operation and generation.
    Authoritative,
    /// The record was compacted and keeps every identity needed to redispatch.
    Compacted,
    /// The record was durably settled and retired, and it fences the stale owner.
    Retired,
    /// A completion from a stale owner generation was rejected.
    RejectedStaleOwner,
}

impl DedupRecordState {
    /// Every member of the closed vocabulary, in wire-name order.
    pub const ALL: [Self; 4] = [
        Self::Authoritative,
        Self::Compacted,
        Self::RejectedStaleOwner,
        Self::Retired,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Authoritative => "authoritative",
            Self::Compacted => "compacted",
            Self::Retired => "retired",
            Self::RejectedStaleOwner => "rejected-stale-owner",
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

    /// Returns whether this state carries the deduplication proof of its identity.
    #[must_use]
    pub const fn carries_proof(self) -> bool {
        matches!(self, Self::Authoritative | Self::Compacted)
    }

    /// Returns whether this state carries a durable settlement.
    #[must_use]
    pub const fn carries_settlement(self) -> bool {
        matches!(self, Self::Authoritative | Self::Compacted | Self::Retired)
    }
}

/// One opaque resource generation identity
/// (`GNT-20.2-logical-operation-and-resource-generation-identity`).
///
/// The identity is a domain-separated SHA-256 digest over one logical operation
/// identity, one exact source site, and one explicit generation counter. No process
/// identifier, adapter handle, host path, clock reading, or locale participates, so
/// equal inputs always produce equal generations and a later generation is a
/// distinct identity. Two generations of one operation can never settle each
/// other's completions, so a stale generation can never settle a later operation.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ResourceGenerationId {
    operation: LogicalOperationId,
    site: StaticSiteId,
    generation: u64,
    text: Arc<str>,
}

impl ResourceGenerationId {
    /// Derives one resource generation of one operation, site, and counter.
    #[must_use]
    pub fn derive(operation: &LogicalOperationId, site: &StaticSiteId, generation: u64) -> Self {
        let digest = digest_fields(
            RESOURCE_GENERATION_DOMAIN,
            &[
                operation.as_str().as_bytes(),
                site.workflow().as_str().as_bytes(),
                &components(site.position().components()),
                &number(generation),
            ],
        );
        Self {
            operation: operation.clone(),
            site: site.clone(),
            generation,
            text: Arc::from(format!("resource-generation:{}", encode_hex(&digest))),
        }
    }

    /// Returns the logical operation identity this generation belongs to.
    #[must_use]
    pub const fn operation(&self) -> &LogicalOperationId {
        &self.operation
    }

    /// Returns the exact source site this generation belongs to.
    #[must_use]
    pub const fn site(&self) -> &StaticSiteId {
        &self.site
    }

    /// Returns the explicit generation counter.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
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
            .strip_prefix("resource-generation:")
            .unwrap_or(&self.text)
    }
}

impl fmt::Display for ResourceGenerationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.text)
    }
}

/// One sealed receiver loan identity
/// (`GNT-20.3-receiver-loan-and-ownership-transfer`).
///
/// A receiver loan is sealed by the declaring operation's canonical path, the exact
/// source site that borrows it, and the resource generation that is lent, and it is
/// domain-separated from every operation, requirement, and generation identity. The
/// seal is the only path to a [`ReceiverOwnership::BorrowedLoan`], the seal names the
/// site and generation it belongs to, and the loan is released when the operation
/// that holds it settles, so a loan of another site or another generation is refused
/// rather than reinterpreted and a loan is never a transfer of ownership. This is its
/// own rule: `GNT-6.2f` is the general argument-loan rule and explicitly excludes
/// live-resource loans, so it neither admits, seals, nor releases a receiver loan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoanId {
    site: StaticSiteId,
    generation: ResourceGenerationId,
    text: Arc<str>,
}

impl LoanId {
    /// Seals one receiver loan of one declaration, site, and resource generation
    /// under `GNT-20.3-receiver-loan-and-ownership-transfer`.
    #[must_use]
    pub fn seal(
        declaration: &CanonicalPath,
        site: &StaticSiteId,
        generation: &ResourceGenerationId,
    ) -> Self {
        let digest = digest_fields(
            LOAN_DOMAIN,
            &[
                declaration.as_str().as_bytes(),
                site.workflow().as_str().as_bytes(),
                &components(site.position().components()),
                generation.as_str().as_bytes(),
            ],
        );
        Self {
            site: site.clone(),
            generation: generation.clone(),
            text: Arc::from(format!("receiver-loan:{}", encode_hex(&digest))),
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
            .strip_prefix("receiver-loan:")
            .unwrap_or(&self.text)
    }

    /// Returns the exact source site this loan belongs to.
    #[must_use]
    pub const fn site(&self) -> &StaticSiteId {
        &self.site
    }

    /// Returns the resource generation this loan lends.
    #[must_use]
    pub const fn generation(&self) -> &ResourceGenerationId {
        &self.generation
    }

    /// Returns whether this loan belongs to one site and one resource generation.
    #[must_use]
    pub fn matches(&self, site: &StaticSiteId, generation: &ResourceGenerationId) -> bool {
        self.site == *site && self.generation == *generation
    }
}

impl fmt::Display for LoanId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.text)
    }
}

/// One of the three receiver arrangements
/// (`GNT-20.3-receiver-loan-and-ownership-transfer`).
///
/// The arrangements are distinct and exhaustive: the receiver is borrowed as one
/// sealed, generation-bound, non-transferable receiver loan of
/// `GNT-20.3-receiver-loan-and-ownership-transfer`, transferred in under an explicit
/// owner generation, or retained by the caller. A loan cannot be written as free
/// text, an owner generation cannot be written as a transfer, and a retained receiver
/// cannot be read as transferred. The general argument-loan rule of `GNT-6.2f`
/// excludes live-resource loans, so it is not the rule this arrangement follows.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReceiverOwnership {
    /// The receiver is borrowed as one sealed loan.
    BorrowedLoan(LoanId),
    /// The receiver was transferred in under one explicit owner generation.
    TransferredIn(OwnerGeneration),
    /// The receiver is retained by the caller.
    RetainedByCaller,
}

impl ReceiverOwnership {
    /// Every arrangement spelling, in wire-name order.
    pub const WIRE_NAMES: [&'static str; 3] =
        ["borrowed-loan", "retained-by-caller", "transferred-in"];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(&self) -> &'static str {
        match self {
            Self::BorrowedLoan(_) => "borrowed-loan",
            Self::TransferredIn(_) => "transferred-in",
            Self::RetainedByCaller => "retained-by-caller",
        }
    }

    /// Returns the same exact portable spelling as [`Self::wire_name`].
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        self.wire_name()
    }

    /// Returns the sealed loan, when the receiver is borrowed.
    #[must_use]
    pub const fn loan(&self) -> Option<&LoanId> {
        match self {
            Self::BorrowedLoan(loan) => Some(loan),
            Self::TransferredIn(_) | Self::RetainedByCaller => None,
        }
    }

    /// Returns the owner generation, when the receiver was transferred in.
    #[must_use]
    pub const fn owner(&self) -> Option<OwnerGeneration> {
        match self {
            Self::TransferredIn(owner) => Some(*owner),
            Self::BorrowedLoan(_) | Self::RetainedByCaller => None,
        }
    }

    /// Returns whether the receiver is borrowed as a sealed loan.
    #[must_use]
    pub const fn is_borrowed_loan(&self) -> bool {
        matches!(self, Self::BorrowedLoan(_))
    }

    /// Returns whether the receiver was transferred in.
    #[must_use]
    pub const fn is_transferred_in(&self) -> bool {
        matches!(self, Self::TransferredIn(_))
    }

    /// Returns whether the receiver is retained by the caller.
    #[must_use]
    pub const fn is_retained_by_caller(&self) -> bool {
        matches!(self, Self::RetainedByCaller)
    }

    /// Returns the canonical text of this arrangement.
    #[must_use]
    pub fn canonical_text(&self) -> String {
        match self {
            Self::BorrowedLoan(loan) => format!("borrowed-loan:{}", loan.as_str()),
            Self::TransferredIn(owner) => format!("transferred-in:{}", owner.value()),
            Self::RetainedByCaller => Self::RetainedByCaller.wire_name().to_owned(),
        }
    }
}

/// One durable settlement of one operation's resource generation
/// (`GNT-20.5-interruption-cancellation-and-late-completion`).
///
/// A settlement names the logical operation identity, the exact resource generation,
/// the owner generation that settled it, the observed external outcome, the observed
/// progress, and the explicit logical instant of settlement. The observed outcome is
/// never reclassified: an ambiguous outcome stays ambiguous.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationSettlement {
    operation: LogicalOperationId,
    generation: ResourceGenerationId,
    owner: OwnerGeneration,
    outcome: ExternalOutcome,
    progress: ProgressObservation,
    settled_at_us: u64,
}

impl OperationSettlement {
    /// Records one settlement of one operation and one resource generation.
    ///
    /// The generation must belong to the operation it is presented with, so a
    /// settlement never mixes one operation's identity with another's generation.
    pub fn new(
        operation: &LogicalOperationId,
        generation: &ResourceGenerationId,
        owner: OwnerGeneration,
        outcome: ExternalOutcome,
        progress: ProgressObservation,
        settled_at_us: u64,
    ) -> Result<Self, OperationAbiError> {
        if generation.operation() != operation {
            return Err(OperationAbiError::ForeignOperation {
                operation: Arc::from(generation.operation().as_str()),
            });
        }
        Ok(Self {
            operation: operation.clone(),
            generation: generation.clone(),
            owner,
            outcome,
            progress,
            settled_at_us,
        })
    }

    /// Returns the settled logical operation identity.
    #[must_use]
    pub const fn operation(&self) -> &LogicalOperationId {
        &self.operation
    }

    /// Returns the settled resource generation.
    #[must_use]
    pub const fn generation(&self) -> &ResourceGenerationId {
        &self.generation
    }

    /// Returns the owner generation that settled the operation.
    #[must_use]
    pub const fn owner(&self) -> OwnerGeneration {
        self.owner
    }

    /// Returns the observed external outcome, which is never reclassified.
    #[must_use]
    pub const fn outcome(&self) -> ExternalOutcome {
        self.outcome
    }

    /// Returns the observed progress.
    #[must_use]
    pub const fn progress(&self) -> ProgressObservation {
        self.progress
    }

    /// Returns the logical instant of settlement.
    #[must_use]
    pub const fn settled_at_us(&self) -> u64 {
        self.settled_at_us
    }

    /// Returns the declared resource state this settlement leaves behind.
    ///
    /// The state is a declared function of the observed outcome and the observed
    /// progress alone: an ambiguous outcome poisons the resource, a rejection leaves
    /// it usable because nothing took effect, and an accepted outcome is closed at an
    /// end of stream, consumed at a committed completion, partially advanced at
    /// partial progress or a short read or write, and usable when nothing advanced.
    #[must_use]
    pub const fn resource_state(&self) -> ResourceState {
        match self.outcome {
            ExternalOutcome::Ambiguous => ResourceState::Poisoned,
            ExternalOutcome::Rejected => ResourceState::Usable,
            ExternalOutcome::Accepted => match self.progress {
                ProgressObservation::Eof => ResourceState::Closed,
                ProgressObservation::CommittedProgress => ResourceState::Consumed,
                ProgressObservation::PartialAdvance
                | ProgressObservation::ShortRead
                | ProgressObservation::ShortWrite => ResourceState::PartiallyAdvanced,
                ProgressObservation::NotStarted => ResourceState::Usable,
            },
        }
    }

    /// Returns the canonical text of this settlement.
    #[must_use]
    pub fn canonical_text(&self) -> String {
        format!(
            "operation={};generation={};owner={};state={};progress={};settled-at-us={}",
            self.operation.as_str(),
            self.generation.as_str(),
            self.owner.value(),
            self.resource_state().wire_name(),
            self.progress.wire_name(),
            self.settled_at_us,
        )
    }
}

/// One declared progress record retained across an interruption
/// (`GNT-20.5-interruption-cancellation-and-late-completion`).
///
/// The record names the exact operation, resource generation, owner generation, and
/// the progress that was observed before the interruption, so an interrupted
/// operation resumes from the progress it actually declared instead of from an
/// assumption of no progress.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProgressRecord {
    operation: LogicalOperationId,
    generation: ResourceGenerationId,
    owner: OwnerGeneration,
    progress: ProgressObservation,
}

impl ProgressRecord {
    /// Returns the interrupted logical operation identity.
    #[must_use]
    pub const fn operation(&self) -> &LogicalOperationId {
        &self.operation
    }

    /// Returns the resource generation the progress belongs to.
    #[must_use]
    pub const fn generation(&self) -> &ResourceGenerationId {
        &self.generation
    }

    /// Returns the owner generation the progress belongs to.
    #[must_use]
    pub const fn owner(&self) -> OwnerGeneration {
        self.owner
    }

    /// Returns the declared progress observation.
    #[must_use]
    pub const fn progress(&self) -> ProgressObservation {
        self.progress
    }

    /// Returns the canonical text of this record.
    #[must_use]
    pub fn canonical_text(&self) -> String {
        format!(
            "operation={};generation={};owner={};progress={}",
            self.operation.as_str(),
            self.generation.as_str(),
            self.owner.value(),
            self.progress.wire_name(),
        )
    }
}

/// One declared post-failure settlement of one operation
/// (`GNT-20.7-resource-state-after-failure-and-poisoning`,
/// `GNT-20.8-half-close-and-post-failure-ownership`).
///
/// Exactly one declared post-failure state and exactly one declared post-failure
/// ownership arrangement are produced for one failure: the pair is derived from the
/// operation's kind and the failure class rather than chosen by the caller, so a
/// partial failure can never leave the operation in an undeclared or ambiguous
/// state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PostFailureSettlement {
    operation: LogicalOperationId,
    generation: ResourceGenerationId,
    state: ResourceState,
    ownership: ReceiverOwnership,
    adapter_poisoned: bool,
}

impl PostFailureSettlement {
    /// Returns the failed logical operation identity.
    #[must_use]
    pub const fn operation(&self) -> &LogicalOperationId {
        &self.operation
    }

    /// Returns the resource generation the failure settles.
    #[must_use]
    pub const fn generation(&self) -> &ResourceGenerationId {
        &self.generation
    }

    /// Returns the single declared post-failure resource state.
    #[must_use]
    pub const fn state(&self) -> ResourceState {
        self.state
    }

    /// Returns the single declared post-failure receiver arrangement.
    #[must_use]
    pub const fn ownership(&self) -> &ReceiverOwnership {
        &self.ownership
    }

    /// Returns whether this failure poisons the adapter instance that carried it.
    #[must_use]
    pub const fn poisons_adapter(&self) -> bool {
        self.adapter_poisoned
    }

    /// Returns the canonical text of this settlement.
    #[must_use]
    pub fn canonical_text(&self) -> String {
        format!(
            "operation={};generation={};state={};ownership={};adapter-poisoned={}",
            self.operation.as_str(),
            self.generation.as_str(),
            self.state.wire_name(),
            self.ownership.canonical_text(),
            self.adapter_poisoned,
        )
    }
}

/// The declared operation ABI of one value action, protected operation, or live
/// resource (`GNT-20.0-value-actions-and-live-resource-operations`).
///
/// The ABI binds exactly the declared operation kind, the canonical declaration, the
/// exact source site, the derived logical operation identity, the derived resource
/// generation, the declared recovery class, and the declared receiver arrangement.
/// Two ABIs are one ABI if and only if every bound input is equal, so no adapter, no
/// host path, and no mutable configuration participates in it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationAbi {
    kind: OperationKind,
    declaration: CanonicalPath,
    site: StaticSiteId,
    operation: LogicalOperationId,
    generation: ResourceGenerationId,
    recovery: RecoveryClass,
    ownership: ReceiverOwnership,
}

impl OperationAbi {
    /// Declares one operation ABI of one kind, declaration, site, generation
    /// counter, recovery class, and receiver arrangement.
    ///
    /// A borrowed receiver must be a loan sealed for this exact site and resource
    /// generation, so a loan of another site or another generation is refused as
    /// [`OperationAbiError::ForeignLoan`] rather than reinterpreted.
    pub fn new(
        kind: OperationKind,
        declaration: &CanonicalPath,
        site: &StaticSiteId,
        generation: u64,
        recovery: RecoveryClass,
        ownership: ReceiverOwnership,
    ) -> Result<Self, OperationAbiError> {
        let operation = LogicalOperationId::derive(declaration, site);
        let resource = ResourceGenerationId::derive(&operation, site, generation);
        if let Some(loan) = ownership.loan()
            && !loan.matches(site, &resource)
        {
            return Err(OperationAbiError::ForeignLoan {
                loan: Arc::from(loan.as_str()),
            });
        }
        Ok(Self {
            kind,
            declaration: declaration.clone(),
            site: site.clone(),
            operation,
            generation: resource,
            recovery,
            ownership,
        })
    }

    /// Returns the declared operation kind.
    #[must_use]
    pub const fn kind(&self) -> OperationKind {
        self.kind
    }

    /// Returns the canonical operation declaration.
    #[must_use]
    pub const fn declaration(&self) -> &CanonicalPath {
        &self.declaration
    }

    /// Returns the exact operation site.
    #[must_use]
    pub const fn site(&self) -> &StaticSiteId {
        &self.site
    }

    /// Returns the stable logical operation identity.
    #[must_use]
    pub const fn operation(&self) -> &LogicalOperationId {
        &self.operation
    }

    /// Returns the declared resource generation.
    #[must_use]
    pub const fn generation(&self) -> &ResourceGenerationId {
        &self.generation
    }

    /// Returns the declared recovery class.
    #[must_use]
    pub const fn recovery(&self) -> RecoveryClass {
        self.recovery
    }

    /// Returns the declared receiver arrangement.
    #[must_use]
    pub const fn ownership(&self) -> &ReceiverOwnership {
        &self.ownership
    }

    /// Returns whether this operation carries a live resource handle.
    #[must_use]
    pub const fn carries_live_handle(&self) -> bool {
        self.kind.carries_live_handle()
    }

    /// Declares one bounded observation allowance of one live-resource observation
    /// channel (`GNT-20.11-adapter-obligations-and-diagnostics`).
    ///
    /// The allowance is the Section 20 bound on observation alone, so an observation is
    /// charged here and never against a Section 15 disclosure budget, which is charged
    /// per accepted release.
    #[must_use]
    pub const fn observation_allowance(
        remaining: u64,
        charge: DisclosureCharge,
    ) -> ObservationAllowance {
        ObservationAllowance::declared(remaining, charge)
    }

    /// Opens the live handle of one live-resource operation.
    ///
    /// This is the only path to a [`LiveResource`], and it refuses every operation
    /// that is not a live-resource operation as
    /// [`OperationAbiError::LiveHandleOnNonLiveKind`], so a value action or a
    /// protected operation can never be reported as a live resource. The opened
    /// resource carries the declared observation allowance of its observation channel.
    pub fn open_live(
        &self,
        owner: OwnerGeneration,
        allowance: ObservationAllowance,
    ) -> Result<LiveResource, OperationAbiError> {
        if !self.carries_live_handle() {
            return Err(OperationAbiError::LiveHandleOnNonLiveKind { kind: self.kind });
        }
        Ok(LiveResource {
            abi: self.clone(),
            owner,
            state: ResourceState::Usable,
            progress: ProgressObservation::NotStarted,
            allowance,
            fenced: None,
            settlement: None,
        })
    }

    /// Reports this operation as a durable value.
    ///
    /// A live-resource operation is never a durable value, so it is refused as
    /// [`OperationAbiError::DurableValueForLiveResource`] rather than reported.
    pub fn durable_value(&self) -> Result<DurableValueRecord, OperationAbiError> {
        if self.carries_live_handle() {
            return Err(OperationAbiError::DurableValueForLiveResource {
                operation: Arc::from(self.operation.as_str()),
            });
        }
        Ok(DurableValueRecord {
            kind: self.kind,
            operation: self.operation.clone(),
            generation: self.generation.clone(),
        })
    }

    /// Classifies one crash cut of this operation from retained evidence.
    ///
    /// A crash before admission carries no effect and is never ambiguous. A crash
    /// at or after admission without a retained deduplication record that settles
    /// this exact operation and generation is ambiguous, so it is never reported as
    /// a completed effect. With that record, the operation's identity and settlement
    /// are reconstructed from the retained evidence.
    #[must_use]
    pub fn classify_crash_cut(
        &self,
        cut: DurableOperationCut,
        evidence: Option<&DedupRecord>,
    ) -> CrashCutClassification {
        if !cut.is_at_or_after_admission() {
            return CrashCutClassification::NoEffect;
        }
        match evidence {
            Some(record) if record.matches(&self.operation, &self.generation) => {
                match record.settlement() {
                    Some(settlement) => CrashCutClassification::Settled(settlement.clone()),
                    None => CrashCutClassification::Ambiguous,
                }
            }
            Some(_) | None => CrashCutClassification::Ambiguous,
        }
    }

    /// Settles one failed operation into exactly one declared post-failure state.
    ///
    /// A live resource that lost its adapter is half-closed, because the still-open
    /// half survives the failure; a live resource that failed on the resource itself
    /// is poisoned; a value action or a protected operation carries no live half, so
    /// it is consumed when its adapter failed and partially advanced when the
    /// resource failed. An adapter failure poisons the adapter instance that carried
    /// it, and the receiver arrangement is preserved unchanged.
    #[must_use]
    pub fn settle_failure(&self, failure: FailureClass) -> PostFailureSettlement {
        let (state, adapter_poisoned) = match (self.kind, failure) {
            (OperationKind::LiveResource, FailureClass::AdapterFailure) => {
                (ResourceState::HalfClosed, true)
            }
            (OperationKind::LiveResource, FailureClass::ResourceFailure) => {
                (ResourceState::Poisoned, false)
            }
            (
                OperationKind::ValueAction | OperationKind::ProtectedOperation,
                FailureClass::AdapterFailure,
            ) => (ResourceState::Consumed, true),
            (
                OperationKind::ValueAction | OperationKind::ProtectedOperation,
                FailureClass::ResourceFailure,
            ) => (ResourceState::PartiallyAdvanced, false),
        };
        PostFailureSettlement {
            operation: self.operation.clone(),
            generation: self.generation.clone(),
            state,
            ownership: self.ownership.clone(),
            adapter_poisoned,
        }
    }
}

/// One durable value produced by one operation that is not a live resource
/// (`GNT-20.0-value-actions-and-live-resource-operations`).
///
/// The record is obtainable only from an operation ABI that carries no live handle,
/// so a live-resource operation is never reported as a durable value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableValueRecord {
    kind: OperationKind,
    operation: LogicalOperationId,
    generation: ResourceGenerationId,
}

impl DurableValueRecord {
    /// Returns the operation kind, which is never a live-resource kind.
    #[must_use]
    pub const fn kind(&self) -> OperationKind {
        self.kind
    }

    /// Returns the producing logical operation identity.
    #[must_use]
    pub const fn operation(&self) -> &LogicalOperationId {
        &self.operation
    }

    /// Returns the producing resource generation.
    #[must_use]
    pub const fn generation(&self) -> &ResourceGenerationId {
        &self.generation
    }

    /// Returns whether this record reports a live resource, which it never does.
    #[must_use]
    pub const fn is_live_resource(&self) -> bool {
        self.kind.carries_live_handle()
    }
}

/// One bounded allowance of observations for one live-resource observation channel
/// (`GNT-20.11-adapter-obligations-and-diagnostics`).
///
/// The allowance is the Section 20 bound on the observation channel alone: it declares
/// the remaining allowance, the nonzero charge one observation consumes, and the number
/// of observations charged so far. It is monotone, so a charge can only reduce the
/// remaining allowance and exhaustion is deterministic in the declared accounting
/// alone. It is deliberately not the landed release-scoped
/// [`crate::protected::DisclosureBudget`]: a disclosure budget is charged per accepted
/// release and is never charged by an observation, while this allowance is never
/// charged by a release and never participates in a release projection. A zero charge
/// would make exhaustion unreachable, so the charge is the landed nonzero charge size
/// and is not representable as zero.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObservationAllowance {
    remaining: u64,
    charge: DisclosureCharge,
    accepted: u64,
}

impl ObservationAllowance {
    /// Declares one allowance with a declared remaining bound and a nonzero charge.
    #[must_use]
    pub const fn declared(remaining: u64, charge: DisclosureCharge) -> Self {
        Self {
            remaining,
            charge,
            accepted: 0,
        }
    }

    /// Returns the allowance remaining after the last charge.
    #[must_use]
    pub const fn remaining(self) -> u64 {
        self.remaining
    }

    /// Returns the nonzero charge one observation consumes.
    #[must_use]
    pub const fn charge(self) -> DisclosureCharge {
        self.charge
    }

    /// Returns the number of observations charged so far.
    #[must_use]
    pub const fn accepted(self) -> u64 {
        self.accepted
    }

    /// Returns whether the next charge cannot be satisfied.
    #[must_use]
    pub const fn is_exhausted(self) -> bool {
        self.remaining < self.charge.value()
    }

    /// Returns the allowance after one charge, or `None` when it is exhausted.
    #[must_use]
    pub const fn after_charge(self) -> Option<Self> {
        if self.remaining < self.charge.value() {
            return None;
        }
        Some(Self {
            remaining: self.remaining - self.charge.value(),
            charge: self.charge,
            accepted: self.accepted + 1,
        })
    }
}

/// One observable live resource bound to one live-resource operation ABI
/// (`GNT-20.1-operation-kinds` through
/// `GNT-20.10-retirement-and-stale-owner-fencing`).
///
/// The handle carries its derived resource generation, its owner generation, the
/// declared receiver arrangement, the declared resource state, the declared progress
/// record, the declared observation allowance of its observation channel, the fencing
/// category of a fenced generation, and the single settlement of its generation. It
/// is constructed only by [`OperationAbi::open_live`], so it can never exist for an
/// operation kind that carries no live handle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiveResource {
    abi: OperationAbi,
    owner: OwnerGeneration,
    state: ResourceState,
    progress: ProgressObservation,
    allowance: ObservationAllowance,
    fenced: Option<FenceCategory>,
    settlement: Option<OperationSettlement>,
}

impl LiveResource {
    /// Returns the declared operation ABI of this resource.
    #[must_use]
    pub const fn abi(&self) -> &OperationAbi {
        &self.abi
    }

    /// Returns the operation kind, which is always a live-resource kind.
    #[must_use]
    pub const fn kind(&self) -> OperationKind {
        self.abi.kind
    }

    /// Returns the stable logical operation identity.
    #[must_use]
    pub const fn operation(&self) -> &LogicalOperationId {
        self.abi.operation()
    }

    /// Returns the exact operation site.
    #[must_use]
    pub const fn site(&self) -> &StaticSiteId {
        self.abi.site()
    }

    /// Returns the derived resource generation.
    #[must_use]
    pub const fn generation(&self) -> &ResourceGenerationId {
        self.abi.generation()
    }

    /// Returns the owner generation that holds this resource.
    #[must_use]
    pub const fn owner(&self) -> OwnerGeneration {
        self.owner
    }

    /// Returns the declared receiver arrangement.
    #[must_use]
    pub const fn ownership(&self) -> &ReceiverOwnership {
        self.abi.ownership()
    }

    /// Returns the declared resource state.
    #[must_use]
    pub const fn state(&self) -> ResourceState {
        self.state
    }

    /// Returns the declared progress record.
    #[must_use]
    pub const fn progress(&self) -> ProgressObservation {
        self.progress
    }

    /// Returns the declared observation allowance of this resource's observation
    /// channel.
    #[must_use]
    pub const fn observation_allowance(&self) -> ObservationAllowance {
        self.allowance
    }

    /// Returns the fencing category that fenced this generation, when one did.
    #[must_use]
    pub const fn fenced(&self) -> Option<FenceCategory> {
        self.fenced
    }

    /// Returns the single settlement of this resource generation, when it settled.
    #[must_use]
    pub const fn settlement(&self) -> Option<&OperationSettlement> {
        self.settlement.as_ref()
    }

    /// Observes one progress observation, charging the declared observation allowance.
    ///
    /// The observation is refused when the resource has no open half or its
    /// generation was fenced, and it is refused when the declared observation allowance
    /// is exhausted, so an adapter can never observe beyond that allowance. The charge
    /// is consumed from the Section 20 allowance alone and never from a Section 15
    /// disclosure budget, which is charged per accepted release. Progress advances the
    /// resource to [`ResourceState::PartiallyAdvanced`] and an end of stream closes it.
    pub fn observe(
        &mut self,
        progress: ProgressObservation,
    ) -> Result<ProgressRecord, OperationAbiError> {
        if let Some(category) = self.fenced {
            return Err(OperationAbiError::FencedResource { category });
        }
        if !self.state.is_open() {
            return Err(OperationAbiError::ResourceNotUsable { state: self.state });
        }
        self.allowance = match self.allowance.after_charge() {
            Some(charged) => charged,
            None => {
                return Err(OperationAbiError::ObservationBudgetExhausted {
                    accepted: self.allowance.accepted(),
                    remaining: self.allowance.remaining(),
                });
            }
        };
        self.progress = progress;
        self.state = match (self.state, progress) {
            (ResourceState::Usable, ProgressObservation::Eof) => ResourceState::Closed,
            (_, observed) if observed.is_progress() => ResourceState::PartiallyAdvanced,
            (state, _) => state,
        };
        Ok(self.progress_record())
    }

    /// Interrupts this operation and retains its declared progress record.
    ///
    /// The interruption changes no resource state and loses no progress: the record
    /// it returns is the same declared progress the resource keeps, so a resume
    /// continues from the progress that was actually observed.
    #[must_use]
    pub fn interrupt(&self) -> ProgressRecord {
        self.progress_record()
    }

    /// Returns the declared progress record of this resource.
    #[must_use]
    pub fn progress_record(&self) -> ProgressRecord {
        ProgressRecord {
            operation: self.abi.operation().clone(),
            generation: self.abi.generation().clone(),
            owner: self.owner,
            progress: self.progress,
        }
    }

    /// Settles this resource generation at most once.
    ///
    /// The first settlement of one generation wins: a duplicate, late, or
    /// wrong-generation completion is refused as [`OperationAbiError::SecondSettlement`]
    /// or [`OperationAbiError::StaleGeneration`], so no completion settles twice and a
    /// cancellation race has exactly one winner. The claimed progress must be the
    /// declared progress the resource observed or a declared upgrade of it, so a
    /// settlement that claims completion while only partial progress was observed, that
    /// claims an end of stream while only a short read or short write was observed, or
    /// that moves progress backwards is refused and the declared progress record is
    /// retained. A fenced generation stays poisoned even after its settlement is
    /// recorded, because the observed outcome is recorded rather than allowed to reopen
    /// the generation.
    pub fn settle(&mut self, candidate: &OperationSettlement) -> Result<(), OperationAbiError> {
        if self.settlement.is_some() {
            return Err(OperationAbiError::SecondSettlement {
                operation: Arc::from(self.abi.operation().as_str()),
            });
        }
        if candidate.generation() != self.abi.generation() {
            return Err(OperationAbiError::StaleGeneration {
                generation: Arc::from(candidate.generation().as_str()),
                expected: Arc::from(self.abi.generation().as_str()),
            });
        }
        if candidate.operation() != self.abi.operation() {
            return Err(OperationAbiError::ForeignOperation {
                operation: Arc::from(candidate.operation().as_str()),
            });
        }
        if candidate.owner() != self.owner {
            return Err(OperationAbiError::StaleOwnerGeneration {
                owner: candidate.owner(),
                expected: self.owner,
            });
        }
        if !self.progress.upgrades_to(candidate.progress()) {
            return Err(match (self.progress, candidate.progress()) {
                (
                    ProgressObservation::ShortRead | ProgressObservation::ShortWrite,
                    ProgressObservation::Eof,
                ) => OperationAbiError::ShortObservationAsEof {
                    observed: self.progress,
                },
                (
                    ProgressObservation::PartialAdvance
                    | ProgressObservation::ShortRead
                    | ProgressObservation::ShortWrite,
                    ProgressObservation::CommittedProgress,
                ) => OperationAbiError::PartialProgressAsCompletion {
                    observed: self.progress,
                    claimed: ProgressObservation::CommittedProgress,
                },
                (observed, claimed) => {
                    OperationAbiError::ProgressObservationMismatch { observed, claimed }
                }
            });
        }
        self.progress = candidate.progress();
        self.state = if self.fenced.is_some() {
            ResourceState::Poisoned
        } else {
            candidate.resource_state()
        };
        self.settlement = Some(candidate.clone());
        Ok(())
    }

    /// Half-closes this resource, preserving the still-open half and its generation.
    ///
    /// A half-close is meaningful exactly while an open half survives, so it is
    /// refused as [`OperationAbiError::HalfCloseWithoutOpenHalf`] for a resource that
    /// is already closed, consumed, poisoned, or half-closed. The generation and the
    /// owner generation are unchanged by a half-close, so the surviving half stays
    /// the same generation.
    pub fn half_close(&mut self) -> Result<(), OperationAbiError> {
        if !self.state.is_open() {
            return Err(OperationAbiError::HalfCloseWithoutOpenHalf { state: self.state });
        }
        self.state = ResourceState::HalfClosed;
        Ok(())
    }

    /// Fences this resource generation by one landed fencing category.
    ///
    /// A fenced generation is poisoned: it can be neither observed nor reused, and a
    /// later settlement records the observed outcome without reopening it. The
    /// category is preserved so revocation and expiry are never relabelled.
    pub fn fence(&mut self, category: FenceCategory) -> PostFailureSettlement {
        self.fenced = Some(category);
        self.state = ResourceState::Poisoned;
        self.post_failure(ResourceState::Poisoned, false)
    }

    /// Settles one failure of this live resource into exactly one declared state.
    ///
    /// An adapter failure half-closes a resource that still has an open half, which
    /// preserves the still-open half and its generation, and it poisons the adapter
    /// instance that carried the operation. A failure without an open half is refused
    /// rather than reported as a half-close. A resource failure poisons the resource,
    /// and poisoning a poisoned resource is refused rather than repeated.
    pub fn settle_failure(
        &mut self,
        failure: FailureClass,
    ) -> Result<PostFailureSettlement, OperationAbiError> {
        match failure {
            FailureClass::AdapterFailure => {
                if !self.state.is_open() {
                    return Err(OperationAbiError::HalfCloseWithoutOpenHalf { state: self.state });
                }
                self.state = ResourceState::HalfClosed;
                Ok(self.post_failure(ResourceState::HalfClosed, true))
            }
            FailureClass::ResourceFailure => {
                if self.state == ResourceState::Poisoned {
                    return Err(OperationAbiError::PoisonedResourceReuse {
                        operation: Arc::from(self.abi.operation().as_str()),
                    });
                }
                self.state = ResourceState::Poisoned;
                Ok(self.post_failure(ResourceState::Poisoned, false))
            }
        }
    }

    /// Returns one declared post-failure settlement of this resource.
    fn post_failure(&self, state: ResourceState, adapter_poisoned: bool) -> PostFailureSettlement {
        PostFailureSettlement {
            operation: self.abi.operation().clone(),
            generation: self.abi.generation().clone(),
            state,
            ownership: self.abi.ownership().clone(),
            adapter_poisoned,
        }
    }
}

/// One sealed adapter binding of one operation ABI
/// (`GNT-20.11-adapter-obligations-and-diagnostics`).
///
/// The binding names the selected downstream implementation, the rights it may
/// exercise, the owner generation it was bound under, and the binding sequence it was
/// bound at, and it carries its own domain-separated identity. Substitution is the only
/// way one binding replaces another, it may only narrow the rights it presents and only
/// advance the owner generation, and it is refused for a poisoned or retired binding, so
/// adapter substitution can never widen authority or reuse a retired identity. The model
/// derives the identity over the binding sequence but never compares sequences: a
/// deployment that binds one implementation again after a retirement MUST advance the
/// binding sequence, and that deployment obligation is what keeps the reinstated
/// binding's identity distinct from the retired one it replaces.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdapterInstance {
    implementation: CanonicalImplementationIdentity,
    rights: RightsSet,
    generation: OwnerGeneration,
    binding_sequence: u64,
    poisoned: bool,
    retired: bool,
    text: Arc<str>,
}

impl AdapterInstance {
    /// Binds one selected implementation, rights set, owner generation, and explicit
    /// monotonic binding sequence.
    ///
    /// The binding sequence participates in the derived identity, so two bindings of one
    /// implementation, one rights set, and one owner generation are distinct identities
    /// exactly when their binding sequences differ. A deployment that binds an
    /// implementation again after a retirement MUST advance the sequence, because the
    /// model cannot observe a reinstatement and enforces only the derivation itself.
    #[must_use]
    pub fn bind(
        implementation: &CanonicalImplementationIdentity,
        rights: RightsSet,
        generation: OwnerGeneration,
        binding_sequence: u64,
    ) -> Self {
        let digest = digest_fields(
            ADAPTER_DOMAIN,
            &[
                implementation.as_str().as_bytes(),
                &[rights.bits()],
                &number(generation.value()),
                &number(binding_sequence),
            ],
        );
        Self {
            implementation: implementation.clone(),
            rights,
            generation,
            binding_sequence,
            poisoned: false,
            retired: false,
            text: Arc::from(format!("adapter-instance:{}", encode_hex(&digest))),
        }
    }

    /// Returns the exact portable binding spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Returns the lowercase digest text without the binding prefix.
    #[must_use]
    pub fn digest_hex(&self) -> &str {
        self.text
            .strip_prefix("adapter-instance:")
            .unwrap_or(&self.text)
    }

    /// Returns the selected downstream implementation identity.
    #[must_use]
    pub const fn implementation(&self) -> &CanonicalImplementationIdentity {
        &self.implementation
    }

    /// Returns the rights this binding may exercise.
    #[must_use]
    pub const fn rights(&self) -> RightsSet {
        self.rights
    }

    /// Returns the owner generation this binding was bound under.
    #[must_use]
    pub const fn generation(&self) -> OwnerGeneration {
        self.generation
    }

    /// Returns the explicit monotonic binding sequence this binding was bound at.
    #[must_use]
    pub const fn binding_sequence(&self) -> u64 {
        self.binding_sequence
    }

    /// Returns whether a failure poisoned this binding.
    #[must_use]
    pub const fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// Returns whether this binding was retired.
    #[must_use]
    pub const fn is_retired(&self) -> bool {
        self.retired
    }

    /// Poisons this binding after one failure, so it can never be reused.
    pub fn poison(&mut self) {
        self.poisoned = true;
    }

    /// Retires this binding, so it is refused for dispatch and substitution.
    ///
    /// A retired binding is never dispatched and never substituted again, and a
    /// deployment that binds that implementation again MUST advance the binding
    /// sequence, so the reinstated binding's derived identity differs from this one.
    pub fn retire(&mut self) {
        self.retired = true;
    }

    /// Presents this binding for one operation ABI.
    ///
    /// A poisoned binding is refused as [`OperationAbiError::AdapterInstancePoisoned`]
    /// and a retired binding as [`OperationAbiError::AdapterInstanceRetired`], so a
    /// failed or retired instance is never reused. The binding must carry the landed
    /// right its operation's declared recovery class demands.
    pub fn dispatch(&self, abi: &OperationAbi) -> Result<(), OperationAbiError> {
        if self.poisoned {
            return Err(OperationAbiError::AdapterInstancePoisoned {
                instance: Arc::from(self.text.as_ref()),
            });
        }
        if self.retired {
            return Err(OperationAbiError::AdapterInstanceRetired {
                instance: Arc::from(self.text.as_ref()),
            });
        }
        if !self.rights.contains(required_right(abi.recovery())) {
            return Err(OperationAbiError::AdapterRightsInsufficient {
                recovery: abi.recovery(),
                rights: self.rights.bits(),
            });
        }
        Ok(())
    }

    /// Substitutes one binding with another implementation under one rights set and
    /// one owner generation.
    ///
    /// A poison on this binding is refused before anything else, because a failed
    /// instance is never reused. A retired binding is refused, so a retired identity
    /// is never reused. The presented rights must be a subset of the rights this
    /// binding already held, so substitution can only narrow authority, and the
    /// presented owner generation must succeed this binding's generation, so a
    /// substitution never reuses an older owner. The replacement is bound at the
    /// presented binding sequence, which the deployment MUST advance past this
    /// binding's sequence, so the replacement identity differs from the substituted
    /// one even when every other identity input is equal.
    pub fn substitute(
        &self,
        replacement: &CanonicalImplementationIdentity,
        rights: RightsSet,
        generation: OwnerGeneration,
        binding_sequence: u64,
    ) -> Result<Self, OperationAbiError> {
        if self.poisoned {
            return Err(OperationAbiError::AdapterInstancePoisoned {
                instance: Arc::from(self.text.as_ref()),
            });
        }
        if self.retired {
            return Err(OperationAbiError::AdapterInstanceRetired {
                instance: Arc::from(self.text.as_ref()),
            });
        }
        if !rights.is_subset_of(self.rights) {
            return Err(OperationAbiError::AdapterWidensAuthority {
                declared: self.rights.bits(),
                presented: rights.bits(),
            });
        }
        if !generation.succeeds(self.generation) {
            return Err(OperationAbiError::StaleOwnerGeneration {
                owner: generation,
                expected: self.generation,
            });
        }
        Ok(Self::bind(
            replacement,
            rights,
            generation,
            binding_sequence,
        ))
    }
}

impl fmt::Display for AdapterInstance {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.text)
    }
}

/// The declared retention bounds of one deduplication record
/// (`GNT-20.9-deduplication-retention-and-compaction`).
///
/// A record is retained while the presenting owner generation is within the declared
/// number of generations of the settling generation and the presenting logical
/// instant is within the declared interval of the settlement instant. A pair of zero
/// bounds is not a bound at all, so it is refused rather than published as a record
/// that is retained forever.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DedupRetentionBounds {
    generations: u64,
    instants_us: u64,
}

impl DedupRetentionBounds {
    /// Binds one generation bound and one logical interval bound.
    pub fn new(generations: u64, instants_us: u64) -> Result<Self, OperationAbiError> {
        if generations == 0 && instants_us == 0 {
            return Err(OperationAbiError::UnboundedRetention);
        }
        Ok(Self {
            generations,
            instants_us,
        })
    }

    /// Returns the declared generation bound.
    #[must_use]
    pub const fn generations(self) -> u64 {
        self.generations
    }

    /// Returns the declared logical interval bound.
    #[must_use]
    pub const fn instants_us(self) -> u64 {
        self.instants_us
    }

    /// Returns whether one owner generation and logical instant are within these
    /// bounds of one settlement.
    #[must_use]
    pub const fn retains(
        self,
        settled: OwnerGeneration,
        settled_at_us: u64,
        owner: OwnerGeneration,
        now_us: u64,
    ) -> bool {
        owner.value() <= settled.value().saturating_add(self.generations)
            && now_us <= settled_at_us.saturating_add(self.instants_us)
    }

    /// Returns the canonical text of these bounds.
    #[must_use]
    pub fn canonical_text(self) -> String {
        format!(
            "generations={};instants-us={}",
            self.generations, self.instants_us
        )
    }
}

/// One deduplication record for one exact operation and resource generation
/// (`GNT-20.9-deduplication-retention-and-compaction`,
/// `GNT-20.10-retirement-and-stale-owner-fencing`).
///
/// The record is the durable evidence of what one resource generation did. It carries
/// its own identity, its owner generation, its state, the observed settlement it was
/// created from, and its retention bounds, and it is never a cache: an ambiguous
/// effect retries only through the record of that exact operation and generation, a
/// retired record fences the stale owner rather than admitting a new invocation, and
/// compaction removes nothing an identity needs to redispatch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DedupRecord {
    operation: LogicalOperationId,
    generation: ResourceGenerationId,
    owner: OwnerGeneration,
    state: DedupRecordState,
    settlement: Option<OperationSettlement>,
    bounds: DedupRetentionBounds,
}

impl DedupRecord {
    /// Records one durable settlement as the authoritative record of its own
    /// operation and generation.
    #[must_use]
    pub fn authoritative(settlement: OperationSettlement, bounds: DedupRetentionBounds) -> Self {
        Self {
            operation: settlement.operation().clone(),
            generation: settlement.generation().clone(),
            owner: settlement.owner(),
            state: DedupRecordState::Authoritative,
            settlement: Some(settlement),
            bounds,
        }
    }

    /// Records that one completion of one operation and generation was rejected
    /// because it came from a stale owner generation.
    #[must_use]
    pub fn rejected_stale_owner(
        operation: &LogicalOperationId,
        generation: &ResourceGenerationId,
        owner: OwnerGeneration,
        bounds: DedupRetentionBounds,
    ) -> Self {
        Self {
            operation: operation.clone(),
            generation: generation.clone(),
            owner,
            state: DedupRecordState::RejectedStaleOwner,
            settlement: None,
            bounds,
        }
    }

    /// Restores one record from retained evidence after a restart.
    ///
    /// Every state that carries a durable settlement must be restored with one, so a
    /// restart never reconstructs an operation's identity without the settlement that
    /// gives it meaning, and a record that rejected a stale owner must carry no
    /// settlement. A settlement that does not name the restored identity is refused, and
    /// the restored record carries the owner generation the settlement names rather than
    /// the presented one, so retirement and fencing always compare against the settling
    /// generation: a record whose settlement does not name both the restored identity and
    /// the presented owner generation is refused rather than restored against an
    /// unrelated owner.
    pub fn restore(
        operation: &LogicalOperationId,
        generation: &ResourceGenerationId,
        state: DedupRecordState,
        settlement: Option<OperationSettlement>,
        owner: OwnerGeneration,
        bounds: DedupRetentionBounds,
    ) -> Result<Self, OperationAbiError> {
        let owner = match settlement.as_ref() {
            Some(settled) if settled.owner() != owner => {
                return Err(OperationAbiError::StaleOwnerGeneration {
                    owner,
                    expected: settled.owner(),
                });
            }
            Some(settled) => settled.owner(),
            None => owner,
        };
        match (state.carries_settlement(), &settlement) {
            (true, None) => {
                return Err(OperationAbiError::SettlementEvidenceMissing { state });
            }
            (false, Some(_)) => {
                return Err(OperationAbiError::SettlementForStaleOwner {
                    operation: Arc::from(operation.as_str()),
                });
            }
            (_, Some(settled)) => {
                if settled.operation() != operation || settled.generation() != generation {
                    return Err(OperationAbiError::StaleGeneration {
                        generation: Arc::from(settled.generation().as_str()),
                        expected: Arc::from(generation.as_str()),
                    });
                }
            }
            (false, None) => {}
        }
        Ok(Self {
            operation: operation.clone(),
            generation: generation.clone(),
            owner,
            state,
            settlement,
            bounds,
        })
    }

    /// Returns the recorded logical operation identity.
    #[must_use]
    pub const fn operation(&self) -> &LogicalOperationId {
        &self.operation
    }

    /// Returns the recorded resource generation.
    #[must_use]
    pub const fn generation(&self) -> &ResourceGenerationId {
        &self.generation
    }

    /// Returns the record state.
    #[must_use]
    pub const fn state(&self) -> DedupRecordState {
        self.state
    }

    /// Returns the owner generation the record carries.
    #[must_use]
    pub const fn owner(&self) -> OwnerGeneration {
        self.owner
    }

    /// Returns the recorded durable settlement, when the record carries one.
    #[must_use]
    pub const fn settlement(&self) -> Option<&OperationSettlement> {
        self.settlement.as_ref()
    }

    /// Returns the retention bounds of the record.
    #[must_use]
    pub const fn bounds(&self) -> DedupRetentionBounds {
        self.bounds
    }

    /// Returns whether this record covers one exact operation and generation.
    #[must_use]
    pub fn matches(
        &self,
        operation: &LogicalOperationId,
        generation: &ResourceGenerationId,
    ) -> bool {
        self.operation == *operation && self.generation == *generation
    }

    /// Compacts this record under new retention bounds.
    ///
    /// Compaction preserves the logical operation identity, the resource generation,
    /// the owner generation, and the durable settlement, so every identity needed to
    /// redispatch survives it and a compacted record still answers its own operation
    /// and generation.
    #[must_use]
    pub fn compact(&self, bounds: DedupRetentionBounds) -> Self {
        Self {
            state: DedupRecordState::Compacted,
            bounds,
            ..self.clone()
        }
    }

    /// Returns whether this record is still retained for one owner and instant.
    ///
    /// A record that carries no durable settlement carries no retention evidence
    /// either, so it reports `false` here.
    #[must_use]
    pub fn retains(&self, owner: OwnerGeneration, now_us: u64) -> bool {
        match self.settlement.as_ref() {
            Some(settled) => {
                self.bounds
                    .retains(settled.owner(), settled.settled_at_us(), owner, now_us)
            }
            None => false,
        }
    }

    /// Requests the retirement of this record at one advanced owner generation.
    ///
    /// Retirement requires a durable settlement and an owner generation that
    /// succeeds the settling one, so a record is never retired on evidence it does
    /// not have and a stale owner never advances it. The retired record carries the
    /// advanced owner generation, so it fences every owner at or below it.
    pub fn request_retirement(mut self, owner: OwnerGeneration) -> Result<Self, OperationAbiError> {
        if self.settlement.is_none() {
            return Err(OperationAbiError::RetirementWithoutSettlement {
                operation: Arc::from(self.operation.as_str()),
            });
        }
        if !owner.succeeds(self.owner) {
            return Err(OperationAbiError::RetirementWithoutAdvancedOwner {
                settled: self.owner,
                presented: owner,
            });
        }
        self.owner = owner;
        self.state = DedupRecordState::Retired;
        Ok(self)
    }

    /// Returns whether this record fences one owner generation.
    ///
    /// Only a retired record fences, and it fences every owner generation that does
    /// not succeed the retired one: a retired record fences the stale owner rather
    /// than admitting a new invocation through it.
    #[must_use]
    pub fn fences(&self, owner: OwnerGeneration) -> bool {
        self.state == DedupRecordState::Retired && !owner.succeeds(self.owner)
    }
}

/// How one crashed operation is classified from retained evidence
/// (`GNT-20.5-interruption-cancellation-and-late-completion`,
/// `GNT-20.9-deduplication-retention-and-compaction`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CrashCutClassification {
    /// The crash happened before admission, so the operation carries no effect.
    NoEffect,
    /// The crash happened at or after admission without proof of the effect.
    Ambiguous,
    /// The retained evidence settles the operation's exact generation.
    Settled(OperationSettlement),
}

impl CrashCutClassification {
    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(&self) -> &'static str {
        match self {
            Self::NoEffect => "no-effect",
            Self::Ambiguous => "ambiguous",
            Self::Settled(_) => "settled",
        }
    }

    /// Returns the same exact portable spelling as [`Self::wire_name`].
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        self.wire_name()
    }

    /// Returns the reconstructed settlement, when the evidence settles the cut.
    #[must_use]
    pub const fn settlement(&self) -> Option<&OperationSettlement> {
        match self {
            Self::Settled(settlement) => Some(settlement),
            Self::NoEffect | Self::Ambiguous => None,
        }
    }

    /// Returns whether the crash cut carries no effect.
    #[must_use]
    pub const fn is_no_effect(&self) -> bool {
        matches!(self, Self::NoEffect)
    }

    /// Returns whether the crash cut is ambiguous.
    #[must_use]
    pub const fn is_ambiguous(&self) -> bool {
        matches!(self, Self::Ambiguous)
    }
}

/// The verdict of one dispatch admission
/// (`GNT-20.0-value-actions-and-live-resource-operations`,
/// `GNT-20.6-ambiguous-effect-classification-and-retry-eligibility`).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DispatchAdmission {
    /// The dispatch is a fresh invocation of an operation that definitely did not
    /// start.
    Fresh,
    /// The dispatch proceeds only through the deduplication proof of its exact
    /// operation and generation.
    Deduplicated,
}

impl DispatchAdmission {
    /// Every member of the closed vocabulary, in wire-name order.
    pub const ALL: [Self; 2] = [Self::Deduplicated, Self::Fresh];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Fresh => "fresh",
            Self::Deduplicated => "deduplicated",
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

/// Classifies the effect certainty of one operation
/// (`GNT-20.6-ambiguous-effect-classification-and-retry-eligibility`).
///
/// An operation that has not passed the admission commit point and whose
/// cancellation was not requested definitely did not start. Every other combination
/// may have begun: an operation at or after admission may already have reached its
/// target, and a requested cancellation races with admission, so a cancelled
/// operation is never classified as a definite not-started effect.
#[must_use]
pub fn classify_effect(
    cut: DurableOperationCut,
    cancellation: OperationCancellation,
) -> EffectCertainty {
    match (cut.is_at_or_after_admission(), cancellation) {
        (false, OperationCancellation::NotRequested) => EffectCertainty::DefiniteNotStarted,
        (true, _) | (false, OperationCancellation::Requested) => EffectCertainty::AmbiguouslyBegun,
    }
}

/// Returns the declared retry eligibility of one effect classification
/// (`GNT-20.6-ambiguous-effect-classification-and-retry-eligibility`).
///
/// An effect that definitely did not start is retried freely, because no invocation
/// was ever dispatched. An effect that may have begun is never retried as a fresh
/// invocation: without a deduplication record for that exact operation and
/// generation it is ineligible, and with one it either requires the deduplication
/// proof, for a recovery class that must not run twice, or is eligible as a
/// deduplicated retry, for a recovery class whose repeat is harmless. A record that
/// was retired or that rejected a stale owner never authorizes a retry.
#[must_use]
pub fn retry_eligibility(
    certainty: EffectCertainty,
    recovery: RecoveryClass,
    dedup: Option<&DedupRecord>,
    operation: &LogicalOperationId,
    generation: &ResourceGenerationId,
) -> RetryEligibility {
    match certainty {
        EffectCertainty::DefiniteNotStarted => RetryEligibility::Eligible,
        EffectCertainty::AmbiguouslyBegun => {
            let record = match dedup {
                Some(record) if record.matches(operation, generation) => record,
                Some(_) | None => return RetryEligibility::Ineligible,
            };
            match record.state() {
                DedupRecordState::Authoritative | DedupRecordState::Compacted => match recovery {
                    RecoveryClass::NonIdempotent => RetryEligibility::RequiresDeduplicationProof,
                    RecoveryClass::Idempotent | RecoveryClass::ReadOnly => {
                        RetryEligibility::Eligible
                    }
                },
                DedupRecordState::Retired | DedupRecordState::RejectedStaleOwner => {
                    RetryEligibility::Ineligible
                }
            }
        }
    }
}

/// Returns the dispatch admission of one operation
/// (`GNT-20.0-value-actions-and-live-resource-operations`).
///
/// Dispatch is admitted only at or after the admission commit point, so a crash
/// before admission can never carry an effect. The effect certainty is derived here
/// from the presented cut and cancellation through [`classify_effect`] rather than
/// accepted from the caller, so an at-or-after-admission cut is may-have-begun and is
/// never admitted as a fresh invocation: every such cut is admitted only through the
/// deduplication proof of its exact operation and generation. A retained record that
/// covers this operation and generation decides the rest: an authoritative or compacted
/// record admits the dispatch only as a deduplicated redispatch, a record that rejected
/// a stale owner refuses the stale owner, and a retired record fences the stale owner
/// while admitting a genuinely advanced owner as a fresh invocation. Without a covering
/// record, the derived classification decides: a definite not-started effect is a fresh
/// invocation, which the admission guard above refuses for every cut before admission,
/// and a may-have-begun effect is refused, so an ambiguous effect is never redispatched
/// without the deduplication proof of that exact operation and generation.
pub fn admit_dispatch(
    abi: &OperationAbi,
    cut: DurableOperationCut,
    cancellation: OperationCancellation,
    dedup: Option<&DedupRecord>,
    owner: OwnerGeneration,
) -> Result<DispatchAdmission, OperationAbiError> {
    if !cut.is_at_or_after_admission() {
        return Err(OperationAbiError::DispatchBeforeAdmission { cut });
    }
    let certainty = classify_effect(cut, cancellation);
    if let Some(record) = dedup.filter(|record| record.matches(abi.operation(), abi.generation())) {
        match record.state() {
            DedupRecordState::Retired => {
                if record.fences(owner) {
                    return Err(OperationAbiError::RetiredRecordFencesStaleOwner {
                        operation: Arc::from(abi.operation().as_str()),
                        owner,
                    });
                }
                return Ok(DispatchAdmission::Fresh);
            }
            DedupRecordState::RejectedStaleOwner => {
                return Err(OperationAbiError::StaleOwnerGeneration {
                    owner,
                    expected: record.owner(),
                });
            }
            DedupRecordState::Authoritative | DedupRecordState::Compacted => {
                return Ok(DispatchAdmission::Deduplicated);
            }
        }
    }
    match certainty {
        EffectCertainty::DefiniteNotStarted => Ok(DispatchAdmission::Fresh),
        EffectCertainty::AmbiguouslyBegun => {
            Err(OperationAbiError::AmbiguousEffectWithoutDeduplication {
                operation: Arc::from(abi.operation().as_str()),
            })
        }
    }
}

/// One frozen published diagnostic identity of the operation ABI model.
///
/// `SPEC.md` assigns no exact operation-ABI diagnostic code, so this module
/// publishes the registry below, one code per condition it decides, each anchored to
/// the clause that owns that condition. The variant order is the sorted code order,
/// so [`Self::ALL`] is already the order a code registry requires, and no condition
/// is reported under another condition's code.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum OperationAbiDiagnosticCode {
    /// `operation-abi-adapter-instance-poisoned`
    AdapterInstancePoisoned,
    /// `operation-abi-adapter-instance-retired`
    AdapterInstanceRetired,
    /// `operation-abi-adapter-rights-insufficient`
    AdapterRightsInsufficient,
    /// `operation-abi-adapter-widens-authority`
    AdapterWidensAuthority,
    /// `operation-abi-ambiguous-effect-without-deduplication`
    AmbiguousEffectWithoutDeduplication,
    /// `operation-abi-dispatch-before-admission`
    DispatchBeforeAdmission,
    /// `operation-abi-durable-value-for-live-resource`
    DurableValueForLiveResource,
    /// `operation-abi-fenced-resource`
    FencedResource,
    /// `operation-abi-foreign-loan`
    ForeignLoan,
    /// `operation-abi-foreign-operation`
    ForeignOperation,
    /// `operation-abi-half-close-without-open-half`
    HalfCloseWithoutOpenHalf,
    /// `operation-abi-live-handle-on-non-live-kind`
    LiveHandleOnNonLiveKind,
    /// `operation-abi-observation-budget-exhausted`
    ObservationBudgetExhausted,
    /// `operation-abi-partial-progress-reported-as-completion`
    PartialProgressAsCompletion,
    /// `operation-abi-poisoned-resource-reuse`
    PoisonedResourceReuse,
    /// `operation-abi-progress-observation-mismatch`
    ProgressObservationMismatch,
    /// `operation-abi-resource-not-usable`
    ResourceNotUsable,
    /// `operation-abi-retention-bounds-unbounded`
    UnboundedRetention,
    /// `operation-abi-retired-record-fences-stale-owner`
    RetiredRecordFencesStaleOwner,
    /// `operation-abi-retirement-without-advanced-owner-generation`
    RetirementWithoutAdvancedOwner,
    /// `operation-abi-retirement-without-settlement`
    RetirementWithoutSettlement,
    /// `operation-abi-second-settlement`
    SecondSettlement,
    /// `operation-abi-settlement-evidence-missing`
    SettlementEvidenceMissing,
    /// `operation-abi-settlement-recorded-for-stale-owner`
    SettlementForStaleOwner,
    /// `operation-abi-short-observation-reported-as-eof`
    ShortObservationAsEof,
    /// `operation-abi-stale-generation`
    StaleGeneration,
    /// `operation-abi-stale-owner-generation`
    StaleOwnerGeneration,
}

impl OperationAbiDiagnosticCode {
    /// Every published code, in sorted code order.
    pub const ALL: [Self; 27] = [
        Self::AdapterInstancePoisoned,
        Self::AdapterInstanceRetired,
        Self::AdapterRightsInsufficient,
        Self::AdapterWidensAuthority,
        Self::AmbiguousEffectWithoutDeduplication,
        Self::DispatchBeforeAdmission,
        Self::DurableValueForLiveResource,
        Self::FencedResource,
        Self::ForeignLoan,
        Self::ForeignOperation,
        Self::HalfCloseWithoutOpenHalf,
        Self::LiveHandleOnNonLiveKind,
        Self::ObservationBudgetExhausted,
        Self::PartialProgressAsCompletion,
        Self::PoisonedResourceReuse,
        Self::ProgressObservationMismatch,
        Self::ResourceNotUsable,
        Self::UnboundedRetention,
        Self::RetiredRecordFencesStaleOwner,
        Self::RetirementWithoutAdvancedOwner,
        Self::RetirementWithoutSettlement,
        Self::SecondSettlement,
        Self::SettlementEvidenceMissing,
        Self::SettlementForStaleOwner,
        Self::ShortObservationAsEof,
        Self::StaleGeneration,
        Self::StaleOwnerGeneration,
    ];

    /// Returns the exact frozen code spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AdapterInstancePoisoned => "operation-abi-adapter-instance-poisoned",
            Self::AdapterInstanceRetired => "operation-abi-adapter-instance-retired",
            Self::AdapterRightsInsufficient => "operation-abi-adapter-rights-insufficient",
            Self::AdapterWidensAuthority => "operation-abi-adapter-widens-authority",
            Self::AmbiguousEffectWithoutDeduplication => {
                "operation-abi-ambiguous-effect-without-deduplication"
            }
            Self::DispatchBeforeAdmission => "operation-abi-dispatch-before-admission",
            Self::DurableValueForLiveResource => "operation-abi-durable-value-for-live-resource",
            Self::FencedResource => "operation-abi-fenced-resource",
            Self::ForeignLoan => "operation-abi-foreign-loan",
            Self::ForeignOperation => "operation-abi-foreign-operation",
            Self::HalfCloseWithoutOpenHalf => "operation-abi-half-close-without-open-half",
            Self::LiveHandleOnNonLiveKind => "operation-abi-live-handle-on-non-live-kind",
            Self::ObservationBudgetExhausted => "operation-abi-observation-budget-exhausted",
            Self::PartialProgressAsCompletion => {
                "operation-abi-partial-progress-reported-as-completion"
            }
            Self::PoisonedResourceReuse => "operation-abi-poisoned-resource-reuse",
            Self::ProgressObservationMismatch => "operation-abi-progress-observation-mismatch",
            Self::ResourceNotUsable => "operation-abi-resource-not-usable",
            Self::UnboundedRetention => "operation-abi-retention-bounds-unbounded",
            Self::RetiredRecordFencesStaleOwner => {
                "operation-abi-retired-record-fences-stale-owner"
            }
            Self::RetirementWithoutAdvancedOwner => {
                "operation-abi-retirement-without-advanced-owner-generation"
            }
            Self::RetirementWithoutSettlement => "operation-abi-retirement-without-settlement",
            Self::SecondSettlement => "operation-abi-second-settlement",
            Self::SettlementEvidenceMissing => "operation-abi-settlement-evidence-missing",
            Self::SettlementForStaleOwner => "operation-abi-settlement-recorded-for-stale-owner",
            Self::ShortObservationAsEof => "operation-abi-short-observation-reported-as-eof",
            Self::StaleGeneration => "operation-abi-stale-generation",
            Self::StaleOwnerGeneration => "operation-abi-stale-owner-generation",
        }
    }

    /// Returns the same exact frozen code spelling as [`Self::as_str`].
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        self.as_str()
    }

    /// Returns the frozen meaning registered for this code.
    #[must_use]
    pub const fn meaning(self) -> &'static str {
        match self {
            Self::AdapterInstancePoisoned => {
                "A failed adapter instance was presented for dispatch or substitution after a failure poisoned it."
            }
            Self::AdapterInstanceRetired => {
                "A retired adapter instance was presented for dispatch or substitution, so a retired identity would be reused."
            }
            Self::AdapterRightsInsufficient => {
                "The adapter binding does not carry the landed right the operation's declared recovery class demands."
            }
            Self::AdapterWidensAuthority => {
                "An adapter substitution presents rights that are not a subset of the rights the substituted binding already held."
            }
            Self::AmbiguousEffectWithoutDeduplication => {
                "An ambiguous effect was dispatched without a deduplication record for that exact operation and resource generation."
            }
            Self::DispatchBeforeAdmission => {
                "A dispatch was requested before the operation passed the admission commit point."
            }
            Self::DurableValueForLiveResource => {
                "A live-resource operation was reported as a durable value."
            }
            Self::FencedResource => {
                "The resource generation was fenced by revocation or expiry, so it can no longer be observed or reused."
            }
            Self::ForeignLoan => {
                "A borrowed receiver presents a loan sealed for another site or another resource generation."
            }
            Self::ForeignOperation => {
                "A settlement names a logical operation identity other than the generation it is presented with."
            }
            Self::HalfCloseWithoutOpenHalf => {
                "A half-close was requested for a resource whose declared state has no still-open half."
            }
            Self::LiveHandleOnNonLiveKind => {
                "A live resource handle was opened for a value action or a protected operation."
            }
            Self::ObservationBudgetExhausted => {
                "The declared observation allowance of the resource observation channel is exhausted."
            }
            Self::PartialProgressAsCompletion => {
                "A settlement claims a committed completion while only partial progress or a short read or write was observed."
            }
            Self::PoisonedResourceReuse => "A poisoned resource was presented for further work.",
            Self::ProgressObservationMismatch => {
                "A settlement claims a progress observation that is neither the progress the resource observed nor a declared upgrade of it, so progress would move backwards."
            }
            Self::ResourceNotUsable => {
                "The resource's declared state has no open half, so the requested observation is refused."
            }
            Self::UnboundedRetention => {
                "A deduplication retention bound of zero generations and zero instants bounds nothing."
            }
            Self::RetiredRecordFencesStaleOwner => {
                "A retired deduplication record fences this owner generation, so no new invocation is admitted through it."
            }
            Self::RetirementWithoutAdvancedOwner => {
                "A retirement was requested under an owner generation that does not succeed the settling generation."
            }
            Self::RetirementWithoutSettlement => {
                "A retirement was requested for a record that carries no durable settlement."
            }
            Self::SecondSettlement => {
                "A second, duplicate, or late completion was presented for a resource generation that already settled."
            }
            Self::SettlementEvidenceMissing => {
                "A record state that carries a durable settlement was restored without one, so the settlement cannot be reconstructed."
            }
            Self::SettlementForStaleOwner => {
                "A record that rejected a stale owner was restored with a durable settlement, which a rejected completion does not have."
            }
            Self::ShortObservationAsEof => {
                "A settlement claims an end of stream while only a short read or short write was observed."
            }
            Self::StaleGeneration => {
                "A completion names a resource generation other than the generation it is presented against."
            }
            Self::StaleOwnerGeneration => {
                "A completion names an owner generation other than the owner generation the resource is held under."
            }
        }
    }

    /// Returns the requirement anchor this code implements.
    #[must_use]
    pub const fn requirement(self) -> &'static str {
        match self {
            Self::AdapterInstancePoisoned
            | Self::FencedResource
            | Self::PoisonedResourceReuse
            | Self::ResourceNotUsable => "GNT-20.7-resource-state-after-failure-and-poisoning",
            Self::AdapterInstanceRetired
            | Self::RetiredRecordFencesStaleOwner
            | Self::RetirementWithoutAdvancedOwner
            | Self::RetirementWithoutSettlement
            | Self::SettlementForStaleOwner
            | Self::StaleOwnerGeneration => "GNT-20.10-retirement-and-stale-owner-fencing",
            Self::AdapterRightsInsufficient
            | Self::AdapterWidensAuthority
            | Self::ObservationBudgetExhausted => "GNT-20.11-adapter-obligations-and-diagnostics",
            Self::AmbiguousEffectWithoutDeduplication => {
                "GNT-20.6-ambiguous-effect-classification-and-retry-eligibility"
            }
            Self::DispatchBeforeAdmission | Self::DurableValueForLiveResource => {
                "GNT-20.0-value-actions-and-live-resource-operations"
            }
            Self::ForeignLoan => "GNT-20.3-receiver-loan-and-ownership-transfer",
            Self::ForeignOperation | Self::StaleGeneration => {
                "GNT-20.2-logical-operation-and-resource-generation-identity"
            }
            Self::HalfCloseWithoutOpenHalf => "GNT-20.8-half-close-and-post-failure-ownership",
            Self::LiveHandleOnNonLiveKind => "GNT-20.1-operation-kinds",
            Self::PartialProgressAsCompletion
            | Self::ProgressObservationMismatch
            | Self::ShortObservationAsEof => "GNT-20.4-partial-progress-and-eof",
            Self::UnboundedRetention | Self::SettlementEvidenceMissing => {
                "GNT-20.9-deduplication-retention-and-compaction"
            }
            Self::SecondSettlement => "GNT-20.5-interruption-cancellation-and-late-completion",
        }
    }
}

/// Failure of one operation-ABI model operation.
///
/// Every variant names exactly one published code through [`Self::code`], so a
/// refusal is always attributable to one clause, and no variant reuses another
/// condition's code.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OperationAbiError {
    /// A poisoned adapter instance was presented for dispatch or substitution.
    AdapterInstancePoisoned {
        /// The portable spelling of the poisoned binding.
        instance: Arc<str>,
    },
    /// A retired adapter instance was presented for dispatch or substitution.
    AdapterInstanceRetired {
        /// The portable spelling of the retired binding.
        instance: Arc<str>,
    },
    /// The adapter binding lacks the right the declared recovery class demands.
    AdapterRightsInsufficient {
        /// The declared recovery class of the operation.
        recovery: RecoveryClass,
        /// The canonical membership bits the binding carries.
        rights: u8,
    },
    /// An adapter substitution would widen the rights it presents.
    AdapterWidensAuthority {
        /// The canonical membership bits the substituted binding held.
        declared: u8,
        /// The canonical membership bits the substitution presents.
        presented: u8,
    },
    /// An ambiguous effect was dispatched without its deduplication record.
    AmbiguousEffectWithoutDeduplication {
        /// The logical operation identity that was dispatched.
        operation: Arc<str>,
    },
    /// A dispatch was requested before the admission commit point.
    DispatchBeforeAdmission {
        /// The cut the operation was at.
        cut: DurableOperationCut,
    },
    /// A live-resource operation was reported as a durable value.
    DurableValueForLiveResource {
        /// The logical operation identity that was reported.
        operation: Arc<str>,
    },
    /// The resource generation was fenced by revocation or expiry.
    FencedResource {
        /// The landed fencing category that fenced the generation.
        category: FenceCategory,
    },
    /// A borrowed receiver presents a loan of another site or generation.
    ForeignLoan {
        /// The portable spelling of the presented loan.
        loan: Arc<str>,
    },
    /// A settlement names another logical operation identity.
    ForeignOperation {
        /// The logical operation identity that was named.
        operation: Arc<str>,
    },
    /// A half-close was requested for a state with no still-open half.
    HalfCloseWithoutOpenHalf {
        /// The declared state that has no open half.
        state: ResourceState,
    },
    /// A live handle was opened for a kind that carries none.
    LiveHandleOnNonLiveKind {
        /// The declared operation kind.
        kind: OperationKind,
    },
    /// The declared observation budget is exhausted.
    ObservationBudgetExhausted {
        /// The accepted observations charged so far.
        accepted: u64,
        /// The budget remaining after the last charge.
        remaining: u64,
    },
    /// A settlement claims a completion while only partial progress was observed.
    PartialProgressAsCompletion {
        /// The observation the resource declared.
        observed: ProgressObservation,
        /// The observation the settlement claimed.
        claimed: ProgressObservation,
    },
    /// A poisoned resource was presented for further work.
    PoisonedResourceReuse {
        /// The logical operation identity of the poisoned resource.
        operation: Arc<str>,
    },
    /// A settlement claims a progress the resource's declared progress does not permit.
    ProgressObservationMismatch {
        /// The progress the resource observed.
        observed: ProgressObservation,
        /// The progress the settlement claimed.
        claimed: ProgressObservation,
    },
    /// The resource's declared state has no open half.
    ResourceNotUsable {
        /// The declared state that refused the observation.
        state: ResourceState,
    },
    /// A retention bound of zero generations and zero instants bounds nothing.
    UnboundedRetention,
    /// A retired record fences this owner generation.
    RetiredRecordFencesStaleOwner {
        /// The logical operation identity the retired record covers.
        operation: Arc<str>,
        /// The fenced owner generation.
        owner: OwnerGeneration,
    },
    /// A retirement was requested under an owner generation that does not advance.
    RetirementWithoutAdvancedOwner {
        /// The owner generation the record carried.
        settled: OwnerGeneration,
        /// The owner generation the retirement presented.
        presented: OwnerGeneration,
    },
    /// A retirement was requested for a record with no durable settlement.
    RetirementWithoutSettlement {
        /// The logical operation identity the record covers.
        operation: Arc<str>,
    },
    /// A duplicate, late, or second completion was presented for a settled
    /// generation.
    SecondSettlement {
        /// The logical operation identity that already settled.
        operation: Arc<str>,
    },
    /// A record state that carries a settlement was restored without one.
    SettlementEvidenceMissing {
        /// The state the record was restored into.
        state: DedupRecordState,
    },
    /// A record that rejected a stale owner was restored with a settlement.
    SettlementForStaleOwner {
        /// The logical operation identity the record covers.
        operation: Arc<str>,
    },
    /// A settlement claims an end of stream after a short read or write.
    ShortObservationAsEof {
        /// The observation the resource declared.
        observed: ProgressObservation,
    },
    /// A completion names another resource generation.
    StaleGeneration {
        /// The generation the completion named.
        generation: Arc<str>,
        /// The generation the resource holds.
        expected: Arc<str>,
    },
    /// A completion names another owner generation.
    StaleOwnerGeneration {
        /// The owner generation the completion named.
        owner: OwnerGeneration,
        /// The owner generation the resource is held under.
        expected: OwnerGeneration,
    },
}

impl OperationAbiError {
    /// Returns the frozen operation-ABI code of this condition.
    #[must_use]
    pub const fn code(&self) -> OperationAbiDiagnosticCode {
        match self {
            Self::AdapterInstancePoisoned { .. } => {
                OperationAbiDiagnosticCode::AdapterInstancePoisoned
            }
            Self::AdapterInstanceRetired { .. } => {
                OperationAbiDiagnosticCode::AdapterInstanceRetired
            }
            Self::AdapterRightsInsufficient { .. } => {
                OperationAbiDiagnosticCode::AdapterRightsInsufficient
            }
            Self::AdapterWidensAuthority { .. } => {
                OperationAbiDiagnosticCode::AdapterWidensAuthority
            }
            Self::AmbiguousEffectWithoutDeduplication { .. } => {
                OperationAbiDiagnosticCode::AmbiguousEffectWithoutDeduplication
            }
            Self::DispatchBeforeAdmission { .. } => {
                OperationAbiDiagnosticCode::DispatchBeforeAdmission
            }
            Self::DurableValueForLiveResource { .. } => {
                OperationAbiDiagnosticCode::DurableValueForLiveResource
            }
            Self::FencedResource { .. } => OperationAbiDiagnosticCode::FencedResource,
            Self::ForeignLoan { .. } => OperationAbiDiagnosticCode::ForeignLoan,
            Self::ForeignOperation { .. } => OperationAbiDiagnosticCode::ForeignOperation,
            Self::HalfCloseWithoutOpenHalf { .. } => {
                OperationAbiDiagnosticCode::HalfCloseWithoutOpenHalf
            }
            Self::LiveHandleOnNonLiveKind { .. } => {
                OperationAbiDiagnosticCode::LiveHandleOnNonLiveKind
            }
            Self::ObservationBudgetExhausted { .. } => {
                OperationAbiDiagnosticCode::ObservationBudgetExhausted
            }
            Self::PartialProgressAsCompletion { .. } => {
                OperationAbiDiagnosticCode::PartialProgressAsCompletion
            }
            Self::PoisonedResourceReuse { .. } => OperationAbiDiagnosticCode::PoisonedResourceReuse,
            Self::ProgressObservationMismatch { .. } => {
                OperationAbiDiagnosticCode::ProgressObservationMismatch
            }
            Self::ResourceNotUsable { .. } => OperationAbiDiagnosticCode::ResourceNotUsable,
            Self::UnboundedRetention => OperationAbiDiagnosticCode::UnboundedRetention,
            Self::RetiredRecordFencesStaleOwner { .. } => {
                OperationAbiDiagnosticCode::RetiredRecordFencesStaleOwner
            }
            Self::RetirementWithoutAdvancedOwner { .. } => {
                OperationAbiDiagnosticCode::RetirementWithoutAdvancedOwner
            }
            Self::RetirementWithoutSettlement { .. } => {
                OperationAbiDiagnosticCode::RetirementWithoutSettlement
            }
            Self::SecondSettlement { .. } => OperationAbiDiagnosticCode::SecondSettlement,
            Self::SettlementEvidenceMissing { .. } => {
                OperationAbiDiagnosticCode::SettlementEvidenceMissing
            }
            Self::SettlementForStaleOwner { .. } => {
                OperationAbiDiagnosticCode::SettlementForStaleOwner
            }
            Self::ShortObservationAsEof { .. } => OperationAbiDiagnosticCode::ShortObservationAsEof,
            Self::StaleGeneration { .. } => OperationAbiDiagnosticCode::StaleGeneration,
            Self::StaleOwnerGeneration { .. } => OperationAbiDiagnosticCode::StaleOwnerGeneration,
        }
    }

    /// Returns the requirement anchor that owns this condition.
    #[must_use]
    pub const fn requirement(&self) -> &'static str {
        self.code().requirement()
    }
}

impl fmt::Display for OperationAbiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code().as_str())?;
        formatter.write_str(": ")?;
        match self {
            Self::AdapterInstancePoisoned { instance } => {
                write!(formatter, "adapter binding `{instance}` is poisoned")
            }
            Self::AdapterInstanceRetired { instance } => {
                write!(formatter, "adapter binding `{instance}` is retired")
            }
            Self::AdapterRightsInsufficient { recovery, rights } => write!(
                formatter,
                "a `{}` operation demands a right the binding bits `{rights}` do not carry",
                recovery.wire_name()
            ),
            Self::AdapterWidensAuthority {
                declared,
                presented,
            } => write!(
                formatter,
                "the substitution presents bits `{presented}` beyond the declared bits `{declared}`"
            ),
            Self::AmbiguousEffectWithoutDeduplication { operation } => write!(
                formatter,
                "operation `{operation}` may have begun and carries no deduplication record"
            ),
            Self::DispatchBeforeAdmission { cut } => write!(
                formatter,
                "the operation is at cut `{}` and has not passed admission",
                cut.wire_name()
            ),
            Self::DurableValueForLiveResource { operation } => write!(
                formatter,
                "operation `{operation}` is a live resource and not a durable value"
            ),
            Self::FencedResource { category } => write!(
                formatter,
                "the resource generation was fenced by `{}`",
                category.wire_name()
            ),
            Self::ForeignLoan { loan } => write!(
                formatter,
                "loan `{loan}` is sealed for another site or generation"
            ),
            Self::ForeignOperation { operation } => write!(
                formatter,
                "operation `{operation}` is not this resource's logical operation"
            ),
            Self::HalfCloseWithoutOpenHalf { state } => write!(
                formatter,
                "a `{}` resource has no still-open half",
                state.wire_name()
            ),
            Self::LiveHandleOnNonLiveKind { kind } => write!(
                formatter,
                "a `{}` operation carries no live handle",
                kind.wire_name()
            ),
            Self::ObservationBudgetExhausted {
                accepted,
                remaining,
            } => write!(
                formatter,
                "the observation budget was charged {accepted} times and leaves {remaining}"
            ),
            Self::PartialProgressAsCompletion { observed, claimed } => write!(
                formatter,
                "`{}` was observed but `{}` was claimed",
                observed.wire_name(),
                claimed.wire_name()
            ),
            Self::PoisonedResourceReuse { operation } => write!(
                formatter,
                "the resource of operation `{operation}` is already poisoned"
            ),
            Self::ProgressObservationMismatch { observed, claimed } => write!(
                formatter,
                "`{}` was observed but `{}` is not a declared upgrade of it",
                observed.wire_name(),
                claimed.wire_name()
            ),
            Self::ResourceNotUsable { state } => write!(
                formatter,
                "a `{}` resource cannot be observed",
                state.wire_name()
            ),
            Self::UnboundedRetention => {
                formatter.write_str("a retention bound of zero generations and zero instants")
            }
            Self::RetiredRecordFencesStaleOwner { operation, owner } => write!(
                formatter,
                "the retired record of operation `{operation}` fences owner generation {}",
                owner.value()
            ),
            Self::RetirementWithoutAdvancedOwner { settled, presented } => write!(
                formatter,
                "retirement presents owner generation {} over settled owner generation {}",
                presented.value(),
                settled.value()
            ),
            Self::RetirementWithoutSettlement { operation } => write!(
                formatter,
                "the record of operation `{operation}` carries no durable settlement"
            ),
            Self::SecondSettlement { operation } => write!(
                formatter,
                "operation `{operation}` already has a settlement"
            ),
            Self::SettlementEvidenceMissing { state } => write!(
                formatter,
                "a `{}` record was restored without its settlement",
                state.wire_name()
            ),
            Self::SettlementForStaleOwner { operation } => write!(
                formatter,
                "the record of operation `{operation}` rejected a stale owner and carries no settlement"
            ),
            Self::ShortObservationAsEof { observed } => write!(
                formatter,
                "`{}` was observed and an end of stream was claimed",
                observed.wire_name()
            ),
            Self::StaleGeneration {
                generation,
                expected,
            } => write!(
                formatter,
                "generation `{generation}` is not the held generation `{expected}`"
            ),
            Self::StaleOwnerGeneration { owner, expected } => write!(
                formatter,
                "owner generation {} is not the held owner generation {}",
                owner.value(),
                expected.value()
            ),
        }
    }
}

impl std::error::Error for OperationAbiError {}
