//! Pure integration-fault containment model for foreign integration failures.
//!
//! This module is the machine-checked model for
//! `GNT-23.0-integration-fault-containment`. It states the containment boundaries
//! (`GNT-23.1-containment-boundaries`), the closed foreign failure taxonomy
//! (`GNT-23.2-foreign-failure-taxonomy`), effect-ambiguity preservation
//! (`GNT-23.3-effect-ambiguity-preservation`), operation ownership and single
//! settlement (`GNT-23.4-operation-ownership-and-single-settlement`), failed-instance
//! poisoning and isolation (`GNT-23.5-failed-instance-poisoning-and-isolation`),
//! protected fault diagnostics (`GNT-23.6-protected-fault-diagnostics`), the adapter
//! containment obligations (`GNT-23.7-adapter-containment-obligations`), and the
//! explicit non-claims of the section (`GNT-23.8-containment-non-claims`).
//!
//! Scope is deliberately narrow. Every rule here is a pure function of its own
//! arguments: this module reads no clock, host path, environment variable, locale,
//! socket, process identifier, or adapter handle, and it exposes no constructor that
//! accepts one. The identity of a poisoned instance is the landed identity it already
//! carries: the adapter-instance binding identity of
//! `GNT-20.11-adapter-obligations-and-diagnostics`, or the landed resource state of
//! `GNT-20.7-resource-state-after-failure-and-poisoning`. This module derives no
//! identity of its own, so equal landed declarations produce equal identities and every
//! verdict is reproducible from its own arguments. This module is not the interpreter,
//! not an executor adapter, and not a protection store: it decides the containment
//! contract that those landed components observe.
//!
//! Landed contracts are cited and reused rather than redeclared. The operation kinds,
//! receiver arrangement, progress observation, interruption, late completion, and
//! ambiguous-effect and retry-eligibility rules remain those of `GNT-20.1` through
//! `GNT-20.6`; the resource state after failure, the half-close rules, and the adapter
//! obligations remain those of `GNT-20.7`, `GNT-20.8` and `GNT-20.11`; the owner
//! generation and its stale-owner fencing remain those of
//! `GNT-20.10-retirement-and-stale-owner-fencing`; the shutdown operation, its cohort,
//! and its finite graceful timeout remain those of `GNT-10.12`, `GNT-10.13` and
//! `GNT-10.14`; cooperative stop and hard cancellation remain those of Section 22; the
//! unreadable credential contract remains that of Section 21; and protected data and
//! its protected diagnostics remain those of `GNT-15.10` and the landed protection
//! store, whose [`AuditAccess`] capability gates the rendering of a protected
//! containment report.
//!
//! Four separations stay explicit.
//!
//! * Poisoning is landed rather than redeclared. A [`PoisonLedger`] poisons an instance
//!   through the landed one-way [`AdapterInstance::poison`], the reuse refusal is the
//!   landed [`AdapterInstance::dispatch`] refusal of
//!   `OperationAbiError::AdapterInstancePoisoned` and the landed substitution refusal,
//!   and [`poison_resource_state`] reuses the landed [`ResourceState::Poisoned`] state.
//!   The ledger carries the reason fixed by the first poisoning of one landed identity
//!   and can neither clear the landed poisoned flag nor return a poisoned instance to
//!   service.
//! * [`EffectState`] keeps the three effect states distinct.
//!   [`EffectState::preserved`] refuses the refinement that would make an ambiguous
//!   effect definite, and [`EffectState::refuse_ambiguous_retry`] refuses a retry of an
//!   ambiguous mutation, so an effect that may already have begun is never rolled back or
//!   re-run.
//! * [`ContainmentSettlement`] is an affine per-operation value: it derives no `Clone`
//!   and no `Copy`, exactly one live settlement of one operation exists, and a
//!   pre-settlement snapshot cannot be settled later. Its
//!   [`ContainmentSettlement::settle`] decides a malformed completion first, then a second
//!   settlement, then a stale generation, then a definite accepted outcome over an
//!   ambiguous effect, and no refusal mutates the owner generation, the held effect
//!   state, or the settled outcome.
//! * [`ContainmentReport`] carries declared metadata and codes only, because no field
//!   of it can hold a payload byte, a secret, a protected content, or a foreign
//!   backtrace; a report that relates to protected data is withheld from ordinary
//!   observation and rendered only under [`AuditAccess`].
//!
//! Four declared rules bound what this model decides and what it does not enforce.
//!
//! * A [`PoisonLedger`] is the reason record of one adapter domain, and the model assumes
//!   exactly one ledger per domain: [`PoisonLedger::new`] starts a new domain, so two
//!   ledgers over one landed instance are two independent reason records rather than one
//!   shared record. A ledger that recorded no reason still never admits a landed poisoned
//!   instance, because the landed flag is one-way and this model never clears it.
//! * [`check_containment_declaration`] decides a declaration against the boundaries the
//!   adapter carries, which the caller passes: the model holds no adapter inventory and
//!   re-derives no boundary set.
//! * [`ContainmentReport::protected_text`] names the protected-diagnostic gate of
//!   `GNT-23.6`; enforcement of the audience is the host's, because this pure model grants
//!   no capability and audits no access.
//! * [`attribute_foreign_failure`] attributes one observed failure to one of the four
//!   foreign classes or refuses it, so a failure that cannot be attributed to one of them
//!   is never mapped onto the nearest declared class. [`AdapterInstance::as_str`] keys the
//!   reason ledger, so a caller MUST pass the landed instance identity and not a
//!   host-derived fact such as an adapter handle, a path, or a process identifier. There is
//!   no host validation here, because the model is pure.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

use crate::authority::ExternalOutcome;
use crate::operation::{AdapterInstance, OwnerGeneration, ResourceState};
use crate::protected::AuditAccess;

/// The clause keys this model implements, in clause order.
///
/// Every diagnostic of this module names exactly one of these keys through
/// [`ContainmentDiagnosticCode::requirement`], so every refusal and every containment
/// report is attributable to the clause that owns it.
pub const FAULT_CONTAINMENT_CLAUSES: [&str; 9] = [
    "GNT-23.0-integration-fault-containment",
    "GNT-23.1-containment-boundaries",
    "GNT-23.2-foreign-failure-taxonomy",
    "GNT-23.3-effect-ambiguity-preservation",
    "GNT-23.4-operation-ownership-and-single-settlement",
    "GNT-23.5-failed-instance-poisoning-and-isolation",
    "GNT-23.6-protected-fault-diagnostics",
    "GNT-23.7-adapter-containment-obligations",
    "GNT-23.8-containment-non-claims",
];

/// One containment boundary (`GNT-23.1-containment-boundaries`).
///
/// A foreign failure is contained at exactly these six boundaries and at no others,
/// and each of them contains the failure as a value rather than letting an unwind, an
/// abort, or an unspecified propagation cross a task boundary or a public API boundary.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ContainmentBoundary {
    /// The call of one integration operation.
    Call,
    /// The poll of one live-resource operation.
    Poll,
    /// The cancel or abort of one operation.
    CancelAbort,
    /// The completion of one operation.
    Completion,
    /// A callback the integration invokes into Gantry.
    Callback,
    /// The destructor of one adapter or resource instance.
    Destructor,
}

impl ContainmentBoundary {
    /// Every member of the closed vocabulary, in clause order.
    pub const ALL: [Self; 6] = [
        Self::Call,
        Self::Poll,
        Self::CancelAbort,
        Self::Completion,
        Self::Callback,
        Self::Destructor,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Call => "call",
            Self::Poll => "poll",
            Self::CancelAbort => "cancel-abort",
            Self::Completion => "completion",
            Self::Callback => "callback",
            Self::Destructor => "destructor",
        }
    }

    /// Returns the same exact portable spelling as [`Self::wire_name`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.wire_name()
    }

    /// Strictly decodes one exact portable spelling.
    ///
    /// A spelling outside the closed vocabulary decodes to nothing rather than being
    /// mapped onto the nearest declared boundary, because a containment decision at an
    /// improvised boundary could not be attributed to a clause of this section.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.wire_name() == value)
    }

    /// Returns the clause key that owns this boundary.
    #[must_use]
    pub const fn requirement(self) -> &'static str {
        "GNT-23.1-containment-boundaries"
    }
}

/// One class of foreign failure (`GNT-23.2-foreign-failure-taxonomy`).
///
/// The four classes are distinct and exhaustive, each carries its own frozen
/// containment diagnostic, and none of them is a Gantry invariant failure. A class
/// names the origin of a failure only: it carries no payload, no message, and no
/// backtrace.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ForeignFailureKind {
    /// A panic raised by foreign integration code.
    Panic,
    /// An exception raised by foreign integration code.
    Exception,
    /// A trap raised by foreign integration code.
    Trap,
    /// A protocol failure observed while speaking an integration protocol.
    Protocol,
}

impl ForeignFailureKind {
    /// Every member of the closed vocabulary, in clause order.
    pub const ALL: [Self; 4] = [Self::Panic, Self::Exception, Self::Trap, Self::Protocol];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Panic => "panic",
            Self::Exception => "exception",
            Self::Trap => "trap",
            Self::Protocol => "protocol",
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

    /// Returns the frozen containment diagnostic of this class.
    ///
    /// Each class owns exactly one code, so no foreign failure is ever reported under
    /// another class's code.
    #[must_use]
    pub const fn code(self) -> ContainmentDiagnosticCode {
        match self {
            Self::Panic => ContainmentDiagnosticCode::ForeignPanicContained,
            Self::Exception => ContainmentDiagnosticCode::ForeignExceptionContained,
            Self::Trap => ContainmentDiagnosticCode::ForeignTrapContained,
            Self::Protocol => ContainmentDiagnosticCode::ForeignProtocolContained,
        }
    }

    /// Returns the clause key that owns this class.
    #[must_use]
    pub const fn requirement(self) -> &'static str {
        "GNT-23.2-foreign-failure-taxonomy"
    }
}

/// One declared failure class (`GNT-23.2-foreign-failure-taxonomy`).
///
/// The vocabulary holds the four foreign classes and the single invariant class. Only a
/// foreign class is containable: a Gantry invariant failure is reported as itself and
/// containment of it as a foreign class is refused.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ContainmentFailureClass {
    /// A foreign failure of one closed foreign class.
    Foreign(ForeignFailureKind),
    /// A detected failure of a Gantry invariant.
    GantryInvariant,
}

impl ContainmentFailureClass {
    /// Every member of the closed vocabulary, in clause order.
    pub const ALL: [Self; 5] = [
        Self::Foreign(ForeignFailureKind::Panic),
        Self::Foreign(ForeignFailureKind::Exception),
        Self::Foreign(ForeignFailureKind::Trap),
        Self::Foreign(ForeignFailureKind::Protocol),
        Self::GantryInvariant,
    ];

    /// Returns the exact portable spelling.
    ///
    /// A foreign class is spelled with its own prefix so that a containment report can
    /// never be read as reporting the invariant class, and the invariant class is
    /// spelled without that prefix.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Foreign(ForeignFailureKind::Panic) => "foreign-panic",
            Self::Foreign(ForeignFailureKind::Exception) => "foreign-exception",
            Self::Foreign(ForeignFailureKind::Trap) => "foreign-trap",
            Self::Foreign(ForeignFailureKind::Protocol) => "foreign-protocol",
            Self::GantryInvariant => "gantry-invariant",
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

    /// Returns the foreign class of this class, when it is a foreign failure.
    #[must_use]
    pub const fn kind(self) -> Option<ForeignFailureKind> {
        match self {
            Self::Foreign(kind) => Some(kind),
            Self::GantryInvariant => None,
        }
    }

    /// Returns whether this class is a foreign failure.
    #[must_use]
    pub const fn is_foreign(self) -> bool {
        matches!(self, Self::Foreign(_))
    }

    /// Returns whether this class is a Gantry invariant failure.
    #[must_use]
    pub const fn is_invariant(self) -> bool {
        matches!(self, Self::GantryInvariant)
    }

    /// Returns whether this class may be contained as a value at a boundary.
    ///
    /// Only a foreign failure is containable, because an invariant failure is reported
    /// as itself under its own code.
    #[must_use]
    pub const fn is_containable(self) -> bool {
        self.is_foreign()
    }

    /// Returns the frozen containment diagnostic of this class.
    #[must_use]
    pub const fn code(self) -> ContainmentDiagnosticCode {
        match self {
            Self::Foreign(kind) => kind.code(),
            Self::GantryInvariant => ContainmentDiagnosticCode::GantryInvariantFailure,
        }
    }

    /// Returns the clause key that owns this class.
    #[must_use]
    pub const fn requirement(self) -> &'static str {
        "GNT-23.2-foreign-failure-taxonomy"
    }
}

/// One observed foreign failure presented for attribution
/// (`GNT-23.2-foreign-failure-taxonomy`).
///
/// A boundary either attributes the failure it observed to one of the four foreign
/// classes or reports that it cannot attribute it. The vocabulary is closed, and it
/// carries no payload byte, no message, no backtrace, and no protected content, so an
/// attribution is never derived from a payload.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ForeignFailureObservation {
    /// The boundary attributed the failure to one of the four foreign classes.
    Attributed(ForeignFailureKind),
    /// The boundary observed a failure it cannot attribute to one of the four classes.
    Unattributable,
}

impl ForeignFailureObservation {
    /// Every member of the closed vocabulary, in clause order.
    pub const ALL: [Self; 5] = [
        Self::Attributed(ForeignFailureKind::Panic),
        Self::Attributed(ForeignFailureKind::Exception),
        Self::Attributed(ForeignFailureKind::Trap),
        Self::Attributed(ForeignFailureKind::Protocol),
        Self::Unattributable,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Attributed(kind) => kind.wire_name(),
            Self::Unattributable => "unattributable",
        }
    }

    /// Returns the same exact portable spelling as [`Self::wire_name`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.wire_name()
    }

    /// Strictly decodes one exact portable spelling.
    ///
    /// A spelling outside the closed vocabulary decodes to nothing rather than being
    /// mapped onto the nearest observation, because an improvised observation could not be
    /// attributed to `GNT-23.2-foreign-failure-taxonomy`.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.wire_name() == value)
    }

    /// Returns the foreign class this observation was attributed to, when it was.
    #[must_use]
    pub const fn kind(self) -> Option<ForeignFailureKind> {
        match self {
            Self::Attributed(kind) => Some(kind),
            Self::Unattributable => None,
        }
    }

    /// Returns whether this observation is attributable to one of the four classes.
    #[must_use]
    pub const fn is_attributable(self) -> bool {
        matches!(self, Self::Attributed(_))
    }

    /// Returns the clause key that owns this observation.
    #[must_use]
    pub const fn requirement(self) -> &'static str {
        "GNT-23.2-foreign-failure-taxonomy"
    }
}

/// Attributes one observed foreign failure to one class of the closed foreign taxonomy
/// (`GNT-23.2-foreign-failure-taxonomy`).
///
/// This is the decidable check behind the clause's attribution rule: an observation the
/// boundary attributed to one of the four foreign classes is reported as that class, and
/// an unattributable observation is refused rather than mapped onto the nearest declared
/// class.
///
/// # Errors
///
/// Returns [`ContainmentError::UnattributableFailure`] when the observation cannot be
/// attributed to one of the four foreign classes.
pub const fn attribute_foreign_failure(
    observed: ForeignFailureObservation,
) -> Result<ContainmentFailureClass, ContainmentError> {
    match observed {
        ForeignFailureObservation::Attributed(kind) => Ok(ContainmentFailureClass::Foreign(kind)),
        ForeignFailureObservation::Unattributable => {
            Err(ContainmentError::UnattributableFailure { observed })
        }
    }
}

/// One observed effect state of a contained failure
/// (`GNT-23.3-effect-ambiguity-preservation`).
///
/// The three states stay distinct. A definite state reports that nothing was
/// dispatched or that the boundary definitely rejected the operation, and an ambiguous
/// state reports that work may already have reached the target. An ambiguous state is
/// never rolled back, never reclassified as definite, and never retried.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum EffectState {
    /// The effect definitely did not start.
    NotStarted,
    /// The boundary definitely rejected the operation, so nothing took effect.
    DefiniteRejection,
    /// The effect may have begun.
    Ambiguous,
}

impl EffectState {
    /// Every member of the closed vocabulary, in clause order.
    pub const ALL: [Self; 3] = [Self::NotStarted, Self::DefiniteRejection, Self::Ambiguous];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::NotStarted => "definite-not-started",
            Self::DefiniteRejection => "definite-rejection",
            Self::Ambiguous => "ambiguous",
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

    /// Returns whether this state is the ambiguous state.
    #[must_use]
    pub const fn is_ambiguous(self) -> bool {
        matches!(self, Self::Ambiguous)
    }

    /// Returns whether this state is one of the two definite states.
    #[must_use]
    pub const fn is_definite(self) -> bool {
        !self.is_ambiguous()
    }

    /// Returns the frozen diagnostic code that reports this state.
    ///
    /// Each of the three states owns exactly one code, so a definite not-started effect
    /// and a definite rejection are not reported under each other's code and neither is
    /// reported as an ambiguous effect.
    #[must_use]
    pub const fn code(self) -> ContainmentDiagnosticCode {
        match self {
            Self::NotStarted => ContainmentDiagnosticCode::DefiniteNotStarted,
            Self::DefiniteRejection => ContainmentDiagnosticCode::DefiniteRejection,
            Self::Ambiguous => ContainmentDiagnosticCode::AmbiguousEffectPreserved,
        }
    }

    /// Returns the clause key that owns this state.
    #[must_use]
    pub const fn requirement(self) -> &'static str {
        "GNT-23.3-effect-ambiguity-preservation"
    }

    /// Returns the state that survives one later observation at one boundary.
    ///
    /// This state is the state the boundary already holds and `presented` is the later
    /// observation. The class of a held state is one-way, so the two classes are never
    /// exchanged and a held state is never re-derived from a later observation:
    ///
    /// * an ambiguous held state stays ambiguous over an ambiguous presentation, because
    ///   an ambiguous effect is never resolved by being observed again;
    /// * an ambiguous held state refuses a definite presentation as
    ///   [`ContainmentError::AmbiguousEffectMadeDefinite`], because a definite report would
    ///   let a caller retry or roll back an effect that may already have reached the
    ///   target;
    /// * a definite held state refuses an ambiguous presentation as
    ///   [`ContainmentError::DefiniteEffectMadeAmbiguous`], because that would deny the
    ///   boundary the definite observation it made and would present decided work as
    ///   unresolved work;
    /// * a definite held state ignores a later definite presentation and returns the held
    ///   state, so a definite effect stutters instead of being re-derived from a later
    ///   observation of the same target.
    ///
    /// # Errors
    ///
    /// Returns [`ContainmentError::AmbiguousEffectMadeDefinite`] when this state is
    /// ambiguous and the presented state is not, and
    /// [`ContainmentError::DefiniteEffectMadeAmbiguous`] when this state is definite and
    /// the presented state is ambiguous.
    pub fn preserved(
        self,
        presented: Self,
        boundary: ContainmentBoundary,
    ) -> Result<Self, ContainmentError> {
        if self.is_ambiguous() {
            if presented.is_ambiguous() {
                return Ok(Self::Ambiguous);
            }
            return Err(ContainmentError::AmbiguousEffectMadeDefinite {
                boundary,
                presented,
            });
        }
        if presented.is_ambiguous() {
            return Err(ContainmentError::DefiniteEffectMadeAmbiguous {
                boundary,
                held: self,
            });
        }
        Ok(self)
    }

    /// Refuses a retry of a mutation whose effect is ambiguous
    /// (`GNT-23.3-effect-ambiguity-preservation`).
    ///
    /// A definite state is not refused here: retry eligibility for anything the boundary
    /// did not classify as ambiguous remains the landed rule of
    /// `GNT-20.6-ambiguous-effect-classification-and-retry-eligibility`, which this
    /// model cites rather than restates.
    ///
    /// # Errors
    ///
    /// Returns [`ContainmentError::AmbiguousEffectRetryRefused`] when this state is
    /// ambiguous.
    pub fn refuse_ambiguous_retry(
        self,
        boundary: ContainmentBoundary,
    ) -> Result<(), ContainmentError> {
        if self.is_ambiguous() {
            return Err(ContainmentError::AmbiguousEffectRetryRefused { boundary });
        }
        Ok(())
    }
}

/// One declared cause of a malformed completion
/// (`GNT-23.4-operation-ownership-and-single-settlement`).
///
/// A malformed completion is its own distinct condition: it is neither a second
/// settlement of an already-settled operation nor a completion of a stale generation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum MalformedCompletion {
    /// The completion declared no outcome at all.
    NoOutcome,
    /// The completion declared more than one outcome for one settlement.
    MultipleOutcomes,
}

impl MalformedCompletion {
    /// Every member of the closed vocabulary, in clause order.
    pub const ALL: [Self; 2] = [Self::NoOutcome, Self::MultipleOutcomes];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::NoOutcome => "no-outcome",
            Self::MultipleOutcomes => "multiple-outcomes",
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

    /// Returns the clause key that owns this condition.
    #[must_use]
    pub const fn requirement(self) -> &'static str {
        "GNT-23.4-operation-ownership-and-single-settlement"
    }
}

/// One completion presented to an [`ContainmentSettlement`]
/// (`GNT-23.4-operation-ownership-and-single-settlement`).
///
/// A well-formed completion names exactly one observed external outcome, which is the
/// landed vocabulary of `GNT-20.5-interruption-cancellation-and-late-completion`, together
/// with the effect state the boundary observed for that outcome. A malformed completion
/// names a declared malformed cause instead, so a completion that declares nothing or
/// declares too much cannot be read as an outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Completion {
    /// A well-formed completion naming the outcome and the effect state the boundary
    /// observed.
    Observed {
        /// The observed external outcome.
        outcome: ExternalOutcome,
        /// The observed effect state of the settled effect.
        effect: EffectState,
    },
    /// A malformed completion, refused as its own distinct condition.
    Malformed(MalformedCompletion),
}

impl Completion {
    /// Builds one well-formed completion over one observed outcome and effect state.
    #[must_use]
    pub const fn observed(outcome: ExternalOutcome, effect: EffectState) -> Self {
        Self::Observed { outcome, effect }
    }

    /// Builds one malformed completion over one declared cause.
    #[must_use]
    pub const fn malformed(cause: MalformedCompletion) -> Self {
        Self::Malformed(cause)
    }

    /// Returns whether this completion is malformed.
    #[must_use]
    pub const fn is_malformed(self) -> bool {
        matches!(self, Self::Malformed(_))
    }

    /// Returns the observed outcome of a well-formed completion.
    #[must_use]
    pub const fn outcome(self) -> Option<ExternalOutcome> {
        match self {
            Self::Observed { outcome, .. } => Some(outcome),
            Self::Malformed(_) => None,
        }
    }

    /// Returns the observed effect state of a well-formed completion.
    #[must_use]
    pub const fn effect(self) -> Option<EffectState> {
        match self {
            Self::Observed { effect, .. } => Some(effect),
            Self::Malformed(_) => None,
        }
    }
}

/// One settlement of one operation under one owner generation
/// (`GNT-23.4-operation-ownership-and-single-settlement`).
///
/// The settlement holds the owner generation that owns the operation, the refined effect
/// state the boundary observed for it, and at most one settled outcome. It is settled by
/// the first admissible completion only, and every refusal leaves the held owner
/// generation, the held effect state, and the settled outcome exactly as they were, so a
/// settled operation is immutable.
///
/// The value is affine: it derives no `Clone` and no `Copy`, so exactly one live
/// settlement of one operation exists and a pre-settlement snapshot cannot be settled
/// later. That is what "exactly one settlement per operation" means here, which is
/// stronger than "exactly one settlement per settlement value": the only way to hold an
/// unsettled operation is to hold the one value that owns it, and duplicating that value
/// is not expressible.
#[derive(Debug, Eq, PartialEq)]
pub struct ContainmentSettlement {
    owner: OwnerGeneration,
    effect: Option<EffectState>,
    outcome: Option<ExternalOutcome>,
}

impl ContainmentSettlement {
    /// Opens one unsettled operation under one owner generation.
    ///
    /// Nothing has been observed for the operation yet, so the settlement holds no effect
    /// state and no settled outcome.
    #[must_use]
    pub const fn open(owner: OwnerGeneration) -> Self {
        Self {
            owner,
            effect: None,
            outcome: None,
        }
    }

    /// Returns the owner generation that owns the operation.
    #[must_use]
    pub const fn owner(&self) -> OwnerGeneration {
        self.owner
    }

    /// Returns the settled outcome, when the operation has settled.
    #[must_use]
    pub const fn outcome(&self) -> Option<ExternalOutcome> {
        self.outcome
    }

    /// Returns the refined effect state this settlement holds, when it has observed one.
    ///
    /// A settlement that has observed no effect state returns nothing rather than a
    /// definite state, so an unobserved operation is never reported as an operation whose
    /// effect definitely did not start.
    #[must_use]
    pub const fn effect_state(&self) -> Option<EffectState> {
        self.effect
    }

    /// Returns whether the operation has settled.
    #[must_use]
    pub const fn is_settled(&self) -> bool {
        self.outcome.is_some()
    }

    /// Settles the operation from one completion, or refuses without mutating it.
    ///
    /// The checks are decided in one fixed order, so a completion that would be refused
    /// for several reasons is refused for the first of them:
    ///
    /// 1. a completion that declares no outcome or more than one outcome is refused as
    ///    [`ContainmentError::MalformedCompletion`] before anything else is decided,
    ///    because a malformed completion is its own distinct condition and is never read
    ///    as the repeated or stale completion it may also be;
    /// 2. a completion presented to an already-settled operation is refused as
    ///    [`ContainmentError::SecondSettlement`], which follows the landed settlement
    ///    winner order this clause refines: [`crate::operation::LiveResource::settle`]
    ///    refuses a repeated completion before it decides the generation, so a repeated
    ///    completion that also names another generation is a second settlement;
    /// 3. a completion that names an owner generation the operation does not hold is
    ///    refused as [`ContainmentError::StaleGeneration`];
    /// 4. the effect state the completion observed becomes the effect state this
    ///    settlement holds. A settlement that already holds an effect state refines it
    ///    with [`EffectState::preserved`], so a definite held state is never made
    ///    ambiguous and an ambiguous held state is never made definite; a settlement that
    ///    holds none holds the state it just observed, because nothing was observed before
    ///    it;
    /// 5. a definite [`ExternalOutcome::Accepted`] presented while the effect state this
    ///    settlement holds after step 4 is ambiguous is refused as
    ///    [`ContainmentError::AmbiguousOutcomeRefused`], because an ambiguous effect is
    ///    never settled as a definite accepted outcome.
    ///
    /// No refusal writes the owner generation, the held effect state, or the settled
    /// outcome, so no completion settles the operation twice and no refused completion runs
    /// the operation's effect path.
    ///
    /// # Errors
    ///
    /// Returns [`ContainmentError::MalformedCompletion`],
    /// [`ContainmentError::SecondSettlement`], [`ContainmentError::StaleGeneration`],
    /// [`ContainmentError::AmbiguousEffectMadeDefinite`],
    /// [`ContainmentError::DefiniteEffectMadeAmbiguous`], or
    /// [`ContainmentError::AmbiguousOutcomeRefused`] for the refusals of the order above.
    pub fn settle(
        &mut self,
        generation: OwnerGeneration,
        completion: Completion,
    ) -> Result<ExternalOutcome, ContainmentError> {
        let (outcome, presented) = match completion {
            Completion::Malformed(cause) => {
                return Err(ContainmentError::MalformedCompletion { cause });
            }
            Completion::Observed { outcome, effect } => (outcome, effect),
        };
        if let Some(settled) = self.outcome {
            return Err(ContainmentError::SecondSettlement { settled });
        }
        if generation != self.owner {
            return Err(ContainmentError::StaleGeneration {
                presented: generation,
                held: self.owner,
            });
        }
        let refined = match self.effect {
            Some(held) => held.preserved(presented, ContainmentBoundary::Completion)?,
            None => presented,
        };
        if refined.is_ambiguous() && outcome == ExternalOutcome::Accepted {
            return Err(ContainmentError::AmbiguousOutcomeRefused {
                outcome,
                held: refined,
            });
        }
        self.effect = Some(refined);
        self.outcome = Some(outcome);
        Ok(outcome)
    }
}

/// One declared reason an instance was poisoned
/// (`GNT-23.5-failed-instance-poisoning-and-isolation`).
///
/// The reason is fixed by the first poisoning of an instance and is never rewritten, so
/// the record of why an instance left service is one-way evidence.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum PoisonReason {
    /// A contained foreign failure of one closed class poisoned the instance.
    ForeignFailure(ForeignFailureKind),
    /// An ambiguous effect left the instance unusable.
    AmbiguousEffect,
    /// A Gantry invariant failure forced the instance out of service.
    InvariantFailure,
}

impl PoisonReason {
    /// Every member of the closed vocabulary, in clause order.
    pub const ALL: [Self; 6] = [
        Self::ForeignFailure(ForeignFailureKind::Panic),
        Self::ForeignFailure(ForeignFailureKind::Exception),
        Self::ForeignFailure(ForeignFailureKind::Trap),
        Self::ForeignFailure(ForeignFailureKind::Protocol),
        Self::AmbiguousEffect,
        Self::InvariantFailure,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::ForeignFailure(ForeignFailureKind::Panic) => "foreign-panic",
            Self::ForeignFailure(ForeignFailureKind::Exception) => "foreign-exception",
            Self::ForeignFailure(ForeignFailureKind::Trap) => "foreign-trap",
            Self::ForeignFailure(ForeignFailureKind::Protocol) => "foreign-protocol",
            Self::AmbiguousEffect => "ambiguous-effect",
            Self::InvariantFailure => "gantry-invariant-failure",
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

    /// Returns the clause key that owns this reason.
    #[must_use]
    pub const fn requirement(self) -> &'static str {
        "GNT-23.5-failed-instance-poisoning-and-isolation"
    }
}

/// The one-way poison reason ledger of one containment domain
/// (`GNT-23.5-failed-instance-poisoning-and-isolation`).
///
/// The ledger holds the reason fixed by the first poisoning of one landed adapter-instance
/// identity, keyed by the identity string of [`AdapterInstance::as_str`]. Poisoning itself
/// is landed: [`Self::poison`] sets the landed one-way [`AdapterInstance::poison`], and the
/// reuse refusals of this section are the landed [`AdapterInstance::dispatch`] refusal of
/// `OperationAbiError::AdapterInstancePoisoned` and the landed substitution refusal. The
/// ledger adds a reason to that landed fact and carries no poisoned flag of its own, so a
/// fresh ledger cannot clear a landed poison and a poisoned instance stays unusable.
///
/// A ledger is the reason record of one adapter domain, and the model assumes exactly one
/// ledger per domain: [`PoisonLedger::new`] starts a new domain, so two ledgers over one
/// landed identity are two independent reason records rather than one shared record, and
/// the model neither shares nor merges them.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PoisonLedger {
    reasons: BTreeMap<Arc<str>, PoisonReason>,
}

impl PoisonLedger {
    /// Opens an empty poison reason ledger.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            reasons: BTreeMap::new(),
        }
    }

    /// Poisons one landed adapter instance through its landed one-way poison and returns
    /// the reason fixed by the first poisoning of its identity.
    ///
    /// A repeated poisoning is stuttering: it reports the recorded reason instead of
    /// rewriting it, and it never clears the landed poisoned flag. The landed poisoning is
    /// set even when this ledger already recorded a reason, because the landed poison is
    /// one-way and this model does not rewrite landed facts.
    pub fn poison(&mut self, instance: &mut AdapterInstance, reason: PoisonReason) -> PoisonReason {
        instance.poison();
        self.record(instance, reason)
    }

    /// Records one reason for one landed instance identity without touching the instance.
    ///
    /// This is the ledger path for a failure that already poisoned the instance through the
    /// landed one-way poison: the reason recorded first for an identity is fixed, and a
    /// repeated record reports the recorded reason instead of rewriting it.
    pub fn record(&mut self, instance: &AdapterInstance, reason: PoisonReason) -> PoisonReason {
        if let Some(recorded) = self.reasons.get(instance.as_str()) {
            return *recorded;
        }
        self.reasons.insert(Arc::from(instance.as_str()), reason);
        reason
    }

    /// Returns the recorded reason of one landed instance identity, when there is one.
    #[must_use]
    pub fn recorded_reason(&self, instance: &AdapterInstance) -> Option<PoisonReason> {
        self.reasons.get(instance.as_str()).copied()
    }

    /// Refuses the reuse of one landed instance, reporting the reason fixed by its first
    /// poisoning.
    ///
    /// The refusal is decided by the landed poisoned flag rather than by this ledger, so a
    /// landed poisoned instance is refused even when this ledger recorded no reason for it:
    /// poisoning is one-way and this model never returns a poisoned instance to service.
    ///
    /// # Errors
    ///
    /// Returns [`ContainmentError::PoisonedInstanceRefused`] when the landed instance is
    /// poisoned.
    pub fn reuse_refusal(&self, instance: &AdapterInstance) -> Result<(), ContainmentError> {
        if !instance.is_poisoned() {
            return Ok(());
        }
        Err(ContainmentError::PoisonedInstanceRefused {
            id: Arc::from(instance.as_str()),
            reason: self.recorded_reason(instance),
        })
    }

    /// Returns the number of identities this ledger recorded a reason for.
    #[must_use]
    pub fn len(&self) -> usize {
        self.reasons.len()
    }

    /// Returns whether this ledger recorded no reason.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.reasons.is_empty()
    }
}

/// Returns the landed resource state that survives one poisoning of one resource
/// (`GNT-23.5-failed-instance-poisoning-and-isolation`).
///
/// The transition reuses the landed [`ResourceState::Poisoned`] state and declares no
/// resource state of its own. Only a resource that is neither poisoned nor terminal
/// poisons: [`ResourceState::Usable`], [`ResourceState::PartiallyAdvanced`], and
/// [`ResourceState::HalfClosed`] become [`ResourceState::Poisoned`]. A repeated poisoning
/// stutters and returns [`ResourceState::Poisoned`] unchanged, because the fault model
/// reports the state the resource already holds instead of repeating a transition it
/// already made. A resource that already reached a terminal state,
/// [`ResourceState::Consumed`] or [`ResourceState::Closed`], is refused, because poisoning
/// such a resource would invent a state the landed lifecycle never reaches.
///
/// # Errors
///
/// Returns [`ContainmentError::ResourcePoisoningRefused`] for a terminal resource state.
pub const fn poison_resource_state(
    state: ResourceState,
) -> Result<ResourceState, ContainmentError> {
    match state {
        ResourceState::Poisoned => Ok(ResourceState::Poisoned),
        ResourceState::Consumed | ResourceState::Closed => {
            Err(ContainmentError::ResourcePoisoningRefused { state })
        }
        ResourceState::Usable | ResourceState::PartiallyAdvanced | ResourceState::HalfClosed => {
            Ok(ResourceState::Poisoned)
        }
    }
}

/// One declared protection scope of a containment report
/// (`GNT-23.6-protected-fault-diagnostics`).
///
/// A declaration-scope report relates to declared metadata only. A protected-scope
/// report relates to protected data and is itself protected, so it is withheld from
/// ordinary observation and rendered only under the landed protection-store capability.
/// The protected classes themselves remain those of `GNT-15.10` and Section 21.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ReportScope {
    /// The report relates to declared metadata only.
    Declaration,
    /// The report relates to protected data and is itself protected.
    ProtectedData,
}

impl ReportScope {
    /// Every member of the closed vocabulary, in clause order.
    pub const ALL: [Self; 2] = [Self::Declaration, Self::ProtectedData];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Declaration => "declaration",
            Self::ProtectedData => "protected-data",
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

    /// Returns whether a report of this scope is itself protected.
    #[must_use]
    pub const fn is_protected(self) -> bool {
        matches!(self, Self::ProtectedData)
    }

    /// Returns the clause key that owns this scope.
    #[must_use]
    pub const fn requirement(self) -> &'static str {
        "GNT-23.6-protected-fault-diagnostics"
    }
}

/// One containment report of one foreign failure contained at one boundary
/// (`GNT-23.6-protected-fault-diagnostics`).
///
/// A report carries the boundary, the failure class, the effect state, the owner
/// generation, the codes, the clause anchors, and the protection scope, and it carries
/// nothing else. It holds no payload byte, no protected content, no secret, no credential,
/// and no foreign backtrace, and no accessor returns one, so the prohibition holds by
/// construction rather than by redaction. The protected scope is carried because a report
/// that relates to protected data is itself protected under `GNT-23.6`; the codes are
/// computed from the declared class and the declared effect state, so a report can never
/// claim a code that contradicts its own declared fields.
///
/// A report implements no rendering trait and no deserializer: it derives no `Debug` and
/// defines no `Display`, so the declared metadata of a report relating to protected data is
/// reachable only through the protected-diagnostic rules of `GNT-23.6`. The rendering paths
/// of the model are [`ContainmentReport::canonical_text`], which withholds such a report,
/// and [`ContainmentReport::protected_text`], which renders it under the landed audit
/// capability.
#[derive(Clone, Eq, PartialEq)]
pub struct ContainmentReport {
    boundary: ContainmentBoundary,
    class: ContainmentFailureClass,
    effect: EffectState,
    owner: OwnerGeneration,
    scope: ReportScope,
}

impl ContainmentReport {
    /// Records one contained foreign failure at one boundary.
    ///
    /// # Errors
    ///
    /// Returns [`ContainmentError::InvariantFailureNotContainable`] when the presented
    /// class is a Gantry invariant failure, because such a failure is reported as itself
    /// and is never contained as a foreign class.
    pub fn contained(
        boundary: ContainmentBoundary,
        class: ContainmentFailureClass,
        effect: EffectState,
        owner: OwnerGeneration,
        scope: ReportScope,
    ) -> Result<Self, ContainmentError> {
        if class.is_invariant() {
            return Err(ContainmentError::InvariantFailureNotContainable { class });
        }
        Ok(Self {
            boundary,
            class,
            effect,
            owner,
            scope,
        })
    }

    /// Returns the boundary that contained the failure.
    #[must_use]
    pub const fn boundary(&self) -> ContainmentBoundary {
        self.boundary
    }

    /// Returns the declared failure class.
    #[must_use]
    pub const fn failure_class(&self) -> ContainmentFailureClass {
        self.class
    }

    /// Returns the declared effect state.
    #[must_use]
    pub const fn effect_state(&self) -> EffectState {
        self.effect
    }

    /// Returns the owner generation of the operation.
    #[must_use]
    pub const fn owner_generation(&self) -> OwnerGeneration {
        self.owner
    }

    /// Returns the frozen diagnostic code of the declared failure class.
    #[must_use]
    pub const fn diagnostic_code(&self) -> ContainmentDiagnosticCode {
        self.class.code()
    }

    /// Returns the frozen diagnostic code of the declared effect state.
    #[must_use]
    pub const fn effect_code(&self) -> ContainmentDiagnosticCode {
        self.effect.code()
    }

    /// Returns both codes, in the canonical order of this section.
    #[must_use]
    pub const fn codes(&self) -> [ContainmentDiagnosticCode; 2] {
        [self.diagnostic_code(), self.effect_code()]
    }

    /// Returns the clause key that owns the declared failure class.
    #[must_use]
    pub const fn clause(&self) -> &'static str {
        self.class.requirement()
    }

    /// Returns the clause anchors this report carries, in clause order.
    #[must_use]
    pub const fn clauses(&self) -> [&'static str; 3] {
        [
            self.boundary.requirement(),
            self.class.requirement(),
            self.effect.requirement(),
        ]
    }

    /// Returns the declared protection scope of this report.
    #[must_use]
    pub const fn scope(&self) -> ReportScope {
        self.scope
    }

    /// Returns whether this report is itself protected.
    #[must_use]
    pub const fn is_protected(&self) -> bool {
        self.scope.is_protected()
    }

    /// Returns the canonical text of this report for an ordinary observer.
    ///
    /// The text is built from the declared metadata and the two codes only, so it can
    /// contain no payload byte, no protected content, no secret, and no backtrace.
    ///
    /// # Errors
    ///
    /// Returns [`ContainmentError::ProtectedDiagnosticWithheld`] when this report relates
    /// to protected data: such a report is itself protected and is reachable only through
    /// [`ContainmentReport::protected_text`] under the landed protection-store capability.
    pub fn canonical_text(&self) -> Result<String, ContainmentError> {
        if self.is_protected() {
            return Err(ContainmentError::ProtectedDiagnosticWithheld {
                code: self.diagnostic_code(),
            });
        }
        Ok(self.declaration_text())
    }

    /// Returns the canonical text of this report under the protected-diagnostic
    /// capability of the landed protection store.
    ///
    /// This is the only path that renders a report relating to protected data, and it
    /// renders the same declared metadata and codes as
    /// [`ContainmentReport::canonical_text`] renders for a declaration-scope report.
    ///
    /// This method names the protected-diagnostic gate of `GNT-23.6` and grants no
    /// capability of its own: enforcement of the audience is the host's, and this pure
    /// model keeps no audit record and decides no access.
    #[must_use]
    pub fn protected_text(&self, _access: &AuditAccess) -> String {
        self.declaration_text()
    }

    /// Returns the declared metadata and codes of this report as canonical text.
    fn declaration_text(&self) -> String {
        format!(
            "boundary={};class={};effect={};owner={};diagnostic-code={};effect-code={};clauses={},{},{};scope={}",
            self.boundary.wire_name(),
            self.class.wire_name(),
            self.effect.wire_name(),
            self.owner.value(),
            self.diagnostic_code().as_str(),
            self.effect_code().as_str(),
            self.boundary.requirement(),
            self.class.requirement(),
            self.effect.requirement(),
            self.scope.wire_name(),
        )
    }
}

/// One containment verdict of one boundary
/// (`GNT-23.2-foreign-failure-taxonomy`).
///
/// A containable foreign failure produces a contained verdict carrying its report. A
/// Gantry invariant failure produces an invariant-failure verdict that carries no code
/// field at all, because containment of such a failure as a foreign class is refused and
/// its code is the invariant code of the variant itself.
#[derive(Clone, Eq, PartialEq)]
pub enum ContainmentVerdict {
    /// The foreign failure was contained at one boundary.
    Contained(ContainmentReport),
    /// The failure is not containable and is reported as itself.
    InvariantFailure,
}

impl ContainmentVerdict {
    /// Contains one foreign failure at one boundary, or refuses a non-foreign class.
    ///
    /// # Errors
    ///
    /// Returns [`ContainmentError::InvariantFailureNotContainable`] when the presented
    /// class is a Gantry invariant failure.
    pub fn contain(
        boundary: ContainmentBoundary,
        class: ContainmentFailureClass,
        effect: EffectState,
        owner: OwnerGeneration,
        scope: ReportScope,
    ) -> Result<Self, ContainmentError> {
        ContainmentReport::contained(boundary, class, effect, owner, scope).map(Self::Contained)
    }

    /// Reports one Gantry invariant failure as itself.
    ///
    /// There is no constructor that takes a code: this verdict reports
    /// [`ContainmentDiagnosticCode::GantryInvariantFailure`] and no other code, so an
    /// invariant failure is never reported under a foreign containment code.
    #[must_use]
    pub const fn invariant_failure() -> Self {
        Self::InvariantFailure
    }

    /// Returns whether this verdict is a contained foreign failure.
    #[must_use]
    pub const fn is_contained(&self) -> bool {
        matches!(self, Self::Contained(_))
    }

    /// Returns whether this verdict is an invariant-failure report.
    #[must_use]
    pub const fn is_invariant_failure(&self) -> bool {
        matches!(self, Self::InvariantFailure)
    }

    /// Returns the containment report of a contained verdict.
    #[must_use]
    pub const fn report(&self) -> Option<&ContainmentReport> {
        match self {
            Self::Contained(report) => Some(report),
            Self::InvariantFailure => None,
        }
    }

    /// Returns the frozen code this verdict reports.
    ///
    /// A contained verdict reports the diagnostic code of its own declared failure class
    /// and an invariant-failure verdict reports the invariant code, so no verdict reports
    /// an invariant failure under a foreign containment code.
    #[must_use]
    pub const fn code(&self) -> ContainmentDiagnosticCode {
        match self {
            Self::Contained(report) => report.diagnostic_code(),
            Self::InvariantFailure => ContainmentDiagnosticCode::GantryInvariantFailure,
        }
    }
}

/// One adapter containment obligation (`GNT-23.7-adapter-containment-obligations`).
///
/// The vocabulary is closed and covers exactly the five obligations that an adapter
/// carrying integration operations owes. Each obligation is decidable from declared values
/// and is anchored to `GNT-23.7`, and an adapter that cannot meet one refuses it by name
/// through [`ContainmentDeclaration`] instead of propagating the failure it could not
/// contain.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ContainmentObligation {
    /// No foreign unwind crosses a task boundary or a public API boundary.
    NoForeignUnwindCrossesBoundary,
    /// A foreign failure is reported as exactly one class of the closed foreign taxonomy.
    ForeignFailureReportedAsClosedClass,
    /// The adapter declares the effect state it observed.
    EffectStateDeclared,
    /// A poisoned instance is never reused, presented, substituted, or repaired.
    PoisonedInstanceNotReused,
    /// Destructor and cancellation follow the same rules as call, poll, and completion.
    DestructorAndCancellationFollowSameRules,
}

impl ContainmentObligation {
    /// Every member of the closed vocabulary, in clause order.
    pub const ALL: [Self; 5] = [
        Self::NoForeignUnwindCrossesBoundary,
        Self::ForeignFailureReportedAsClosedClass,
        Self::EffectStateDeclared,
        Self::PoisonedInstanceNotReused,
        Self::DestructorAndCancellationFollowSameRules,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::NoForeignUnwindCrossesBoundary => "no-foreign-unwind-crosses-boundary",
            Self::ForeignFailureReportedAsClosedClass => "foreign-failure-reported-as-closed-class",
            Self::EffectStateDeclared => "effect-state-declared",
            Self::PoisonedInstanceNotReused => "poisoned-instance-not-reused",
            Self::DestructorAndCancellationFollowSameRules => {
                "destructor-and-cancellation-follow-same-rules"
            }
        }
    }

    /// Returns the same exact portable spelling as [`Self::wire_name`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.wire_name()
    }

    /// Strictly decodes one exact portable spelling.
    ///
    /// A spelling outside the closed vocabulary decodes to nothing rather than being
    /// mapped onto the nearest obligation, because an improvised obligation could not be
    /// attributed to `GNT-23.7-adapter-containment-obligations`.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.wire_name() == value)
    }

    /// Returns the clause key that owns this obligation.
    #[must_use]
    pub const fn requirement(self) -> &'static str {
        "GNT-23.7-adapter-containment-obligations"
    }
}

/// One declared containment plan of one adapter
/// (`GNT-23.7-adapter-containment-obligations`).
///
/// The plan lists the boundaries one adapter declares it contains, and it is declared
/// evidence rather than an inferred set: [`Self::of`] records exactly the boundaries it is
/// given, [`Self::all`] records every boundary of the closed boundary vocabulary, and
/// [`Self::covers`] decides whether the plan contains every boundary of the set the adapter
/// carries. A plan is built from declared boundaries alone and never from an adapter
/// handle, a host path, a clock reading, or an environment fact, so a declaration is
/// reproducible from its own arguments.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ContainmentPlan {
    boundaries: BTreeSet<ContainmentBoundary>,
}

impl ContainmentPlan {
    /// Declares one plan over the listed boundaries.
    #[must_use]
    pub fn of(boundaries: &[ContainmentBoundary]) -> Self {
        Self {
            boundaries: boundaries.iter().copied().collect(),
        }
    }

    /// Declares one plan over every boundary of the closed boundary vocabulary.
    #[must_use]
    pub fn all() -> Self {
        Self::of(&ContainmentBoundary::ALL)
    }

    /// Returns whether this plan contains one boundary.
    #[must_use]
    pub fn contains(&self, boundary: ContainmentBoundary) -> bool {
        self.boundaries.contains(&boundary)
    }

    /// Returns whether this plan covers every boundary of one carried set.
    #[must_use]
    pub fn covers(&self, carried: &Self) -> bool {
        carried.boundaries.is_subset(&self.boundaries)
    }

    /// Returns the boundaries of one carried set this plan does not contain, in clause
    /// order.
    #[must_use]
    pub fn missing_from(&self, carried: &Self) -> Vec<ContainmentBoundary> {
        ContainmentBoundary::ALL
            .into_iter()
            .filter(|boundary| carried.contains(*boundary) && !self.contains(*boundary))
            .collect()
    }

    /// Returns the number of boundaries this plan declares.
    #[must_use]
    pub fn len(&self) -> usize {
        self.boundaries.len()
    }

    /// Returns whether this plan declares no boundary.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.boundaries.is_empty()
    }
}

/// One adapter containment declaration of one boundary
/// (`GNT-23.7-adapter-containment-obligations`).
///
/// A declaration either declares containment at one boundary, with the plan that lists the
/// boundaries the adapter contains, or refuses one named obligation at that boundary. There
/// is no third shape, so an adapter cannot declare containment while leaving an obligation
/// undecided, and a declaration of containment carries declared evidence for the
/// containment it claims rather than a name only.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ContainmentDeclaration {
    /// The adapter declares containment at this boundary, with the declared plan of the
    /// boundaries it contains.
    Declared {
        /// The boundary at which containment is declared.
        boundary: ContainmentBoundary,
        /// The declared containment plan of this adapter.
        plan: ContainmentPlan,
    },
    /// The adapter refuses one named obligation at this boundary.
    Refused {
        /// The boundary at which the obligation is refused.
        boundary: ContainmentBoundary,
        /// The refused obligation.
        obligation: ContainmentObligation,
    },
}

impl ContainmentDeclaration {
    /// Declares containment at one boundary with one declared plan.
    #[must_use]
    pub fn declared(boundary: ContainmentBoundary, plan: ContainmentPlan) -> Self {
        Self::Declared { boundary, plan }
    }

    /// Declares containment at one boundary with a plan over every boundary.
    #[must_use]
    pub fn declared_for_all(boundary: ContainmentBoundary) -> Self {
        Self::Declared {
            boundary,
            plan: ContainmentPlan::all(),
        }
    }

    /// Refuses one named obligation at one boundary.
    #[must_use]
    pub const fn refused(boundary: ContainmentBoundary, obligation: ContainmentObligation) -> Self {
        Self::Refused {
            boundary,
            obligation,
        }
    }

    /// Returns the boundary of this declaration.
    #[must_use]
    pub const fn boundary(&self) -> ContainmentBoundary {
        match self {
            Self::Declared { boundary, .. } | Self::Refused { boundary, .. } => *boundary,
        }
    }

    /// Returns the declared containment plan, when this declaration declares containment.
    #[must_use]
    pub const fn plan(&self) -> Option<&ContainmentPlan> {
        match self {
            Self::Declared { plan, .. } => Some(plan),
            Self::Refused { .. } => None,
        }
    }

    /// Returns the refused obligation, when this declaration refuses one.
    #[must_use]
    pub const fn obligation(&self) -> Option<ContainmentObligation> {
        match self {
            Self::Declared { .. } => None,
            Self::Refused { obligation, .. } => Some(*obligation),
        }
    }

    /// Returns whether this declaration declares containment.
    #[must_use]
    pub const fn is_declared(&self) -> bool {
        matches!(self, Self::Declared { .. })
    }

    /// Returns the clause key that owns this declaration.
    #[must_use]
    pub const fn requirement(&self) -> &'static str {
        "GNT-23.7-adapter-containment-obligations"
    }
}

/// One refused adapter containment obligation
/// (`GNT-23.7-adapter-containment-obligations`).
///
/// The refusal carries the boundary at which the obligation was refused and the obligation
/// itself, and its clause is the obligation's own clause, so a refusal is attributable to
/// `GNT-23.7` and names which obligation the adapter declined.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObligationRefusal {
    boundary: ContainmentBoundary,
    obligation: ContainmentObligation,
}

impl ObligationRefusal {
    /// Returns the boundary at which the obligation was refused.
    #[must_use]
    pub const fn boundary(self) -> ContainmentBoundary {
        self.boundary
    }

    /// Returns the refused obligation.
    #[must_use]
    pub const fn obligation(self) -> ContainmentObligation {
        self.obligation
    }

    /// Returns the clause key that owns the refused obligation.
    #[must_use]
    pub const fn clause(self) -> &'static str {
        self.obligation.requirement()
    }

    /// Returns the same clause key as [`Self::clause`].
    #[must_use]
    pub const fn requirement(self) -> &'static str {
        self.clause()
    }
}

impl fmt::Display for ObligationRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "the `{}` obligation is refused at the `{}` boundary",
            self.obligation.wire_name(),
            self.boundary.wire_name()
        )
    }
}

impl std::error::Error for ObligationRefusal {}

/// Checks one adapter containment declaration against the boundaries the adapter carries
/// (`GNT-23.7-adapter-containment-obligations`).
///
/// A declaration that declares containment succeeds with the plan it declares, but only
/// when that plan covers every boundary of `carried`, the set of boundaries the adapter
/// actually carries. A plan that does not cover every carried boundary is refused as
/// [`ContainmentError::IncompleteContainmentPlan`], because a boundary the adapter carries
/// and does not contain is exactly the foreign unwind the obligation forbids, so a
/// declaration of containment is decidable rather than a name only.
///
/// A declaration that refuses one named obligation is refused as
/// [`ContainmentError::ObligationRefused`], which names the obligation and its clause,
/// because an adapter that cannot contain refuses the obligation instead of propagating the
/// failure.
///
/// The carried set is a caller argument: this pure model holds no adapter inventory, and
/// the caller that owns the adapter declares which boundaries that adapter carries.
///
/// # Errors
///
/// Returns [`ContainmentError::IncompleteContainmentPlan`] when the declared plan does not
/// cover every carried boundary, and [`ContainmentError::ObligationRefused`] when the
/// declaration refuses one of its obligations.
pub fn check_containment_declaration(
    declaration: ContainmentDeclaration,
    carried: &ContainmentPlan,
) -> Result<ContainmentPlan, ContainmentError> {
    match declaration {
        ContainmentDeclaration::Declared { plan, .. } => {
            if plan.covers(carried) {
                return Ok(plan);
            }
            Err(ContainmentError::IncompleteContainmentPlan {
                missing: plan.missing_from(carried),
            })
        }
        ContainmentDeclaration::Refused {
            boundary,
            obligation,
        } => Err(ContainmentError::ObligationRefused(ObligationRefusal {
            boundary,
            obligation,
        })),
    }
}

/// One frozen containment diagnostic code (`GNT-23.6-protected-fault-diagnostics`).
///
/// The registry holds one code per condition this model decides, and every code is
/// anchored to exactly one clause of Section 23 through
/// [`ContainmentDiagnosticCode::requirement`], so no condition is reported under another
/// condition's code. The variant order is the sorted code order, so [`Self::ALL`] is
/// already the order a code registry requires.
///
/// A refusal of this model never borrows the code of the condition it concerns:
/// [`Self::GantryInvariantFailure`] reports the Gantry invariant failure of
/// [`ContainmentVerdict::InvariantFailure`] as itself and no refusal of this model, the
/// ambiguous effect that is preserved keeps [`Self::AmbiguousEffectPreserved`] while each
/// refusal that constrains it carries its own code, and the two definite states keep their
/// own codes.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ContainmentDiagnosticCode {
    /// `fault-ambiguous-effect-made-definite`
    AmbiguousEffectMadeDefinite,
    /// `fault-ambiguous-effect-preserved`
    AmbiguousEffectPreserved,
    /// `fault-ambiguous-effect-retry-refused`
    AmbiguousEffectRetryRefused,
    /// `fault-ambiguous-outcome-refused`
    AmbiguousOutcomeRefused,
    /// `fault-containment-obligation-refused`
    ContainmentObligationRefused,
    /// `fault-containment-plan-incomplete`
    ContainmentPlanIncomplete,
    /// `fault-definite-effect-made-ambiguous`
    DefiniteEffectMadeAmbiguous,
    /// `fault-definite-not-started`
    DefiniteNotStarted,
    /// `fault-definite-rejection`
    DefiniteRejection,
    /// `fault-foreign-exception-contained`
    ForeignExceptionContained,
    /// `fault-foreign-panic-contained`
    ForeignPanicContained,
    /// `fault-foreign-protocol-contained`
    ForeignProtocolContained,
    /// `fault-foreign-trap-contained`
    ForeignTrapContained,
    /// `fault-gantry-invariant-failure`
    GantryInvariantFailure,
    /// `fault-invariant-failure-not-containable`
    InvariantFailureNotContainable,
    /// `fault-malformed-completion-refused`
    MalformedCompletionRefused,
    /// `fault-poisoned-instance-refused`
    PoisonedInstanceRefused,
    /// `fault-protected-diagnostic-withheld`
    ProtectedDiagnosticWithheld,
    /// `fault-resource-poisoning-refused`
    ResourcePoisoningRefused,
    /// `fault-second-settlement-refused`
    SecondSettlementRefused,
    /// `fault-stale-generation-refused`
    StaleGenerationRefused,
    /// `fault-unattributable-failure-refused`
    UnattributableFailureRefused,
}

impl ContainmentDiagnosticCode {
    /// Every frozen code, in sorted code order.
    pub const ALL: [Self; 22] = [
        Self::AmbiguousEffectMadeDefinite,
        Self::AmbiguousEffectPreserved,
        Self::AmbiguousEffectRetryRefused,
        Self::AmbiguousOutcomeRefused,
        Self::ContainmentObligationRefused,
        Self::ContainmentPlanIncomplete,
        Self::DefiniteEffectMadeAmbiguous,
        Self::DefiniteNotStarted,
        Self::DefiniteRejection,
        Self::ForeignExceptionContained,
        Self::ForeignPanicContained,
        Self::ForeignProtocolContained,
        Self::ForeignTrapContained,
        Self::GantryInvariantFailure,
        Self::InvariantFailureNotContainable,
        Self::MalformedCompletionRefused,
        Self::PoisonedInstanceRefused,
        Self::ProtectedDiagnosticWithheld,
        Self::ResourcePoisoningRefused,
        Self::SecondSettlementRefused,
        Self::StaleGenerationRefused,
        Self::UnattributableFailureRefused,
    ];

    /// Returns the exact frozen code spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AmbiguousEffectMadeDefinite => "fault-ambiguous-effect-made-definite",
            Self::AmbiguousEffectPreserved => "fault-ambiguous-effect-preserved",
            Self::AmbiguousEffectRetryRefused => "fault-ambiguous-effect-retry-refused",
            Self::AmbiguousOutcomeRefused => "fault-ambiguous-outcome-refused",
            Self::ContainmentObligationRefused => "fault-containment-obligation-refused",
            Self::ContainmentPlanIncomplete => "fault-containment-plan-incomplete",
            Self::DefiniteEffectMadeAmbiguous => "fault-definite-effect-made-ambiguous",
            Self::DefiniteNotStarted => "fault-definite-not-started",
            Self::DefiniteRejection => "fault-definite-rejection",
            Self::ForeignExceptionContained => "fault-foreign-exception-contained",
            Self::ForeignPanicContained => "fault-foreign-panic-contained",
            Self::ForeignProtocolContained => "fault-foreign-protocol-contained",
            Self::ForeignTrapContained => "fault-foreign-trap-contained",
            Self::GantryInvariantFailure => "fault-gantry-invariant-failure",
            Self::InvariantFailureNotContainable => "fault-invariant-failure-not-containable",
            Self::MalformedCompletionRefused => "fault-malformed-completion-refused",
            Self::PoisonedInstanceRefused => "fault-poisoned-instance-refused",
            Self::ProtectedDiagnosticWithheld => "fault-protected-diagnostic-withheld",
            Self::ResourcePoisoningRefused => "fault-resource-poisoning-refused",
            Self::SecondSettlementRefused => "fault-second-settlement-refused",
            Self::StaleGenerationRefused => "fault-stale-generation-refused",
            Self::UnattributableFailureRefused => "fault-unattributable-failure-refused",
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
            Self::AmbiguousEffectMadeDefinite => {
                "an ambiguous effect was presented as definite and the presentation was refused"
            }
            Self::AmbiguousEffectPreserved => {
                "an ambiguous effect was preserved rather than reclassified as definite or retried"
            }
            Self::AmbiguousEffectRetryRefused => {
                "a retry of a mutation whose effect is ambiguous was refused"
            }
            Self::AmbiguousOutcomeRefused => {
                "a definite accepted outcome was refused over an ambiguous effect"
            }
            Self::ContainmentObligationRefused => {
                "an adapter refused one named containment obligation at one boundary"
            }
            Self::ContainmentPlanIncomplete => {
                "a declared containment plan does not cover every boundary the adapter carries"
            }
            Self::DefiniteEffectMadeAmbiguous => {
                "a definite effect state was presented as an ambiguous effect and the presentation was refused"
            }
            Self::DefiniteNotStarted => {
                "an effect definitely did not start, so nothing was dispatched and nothing took effect"
            }
            Self::DefiniteRejection => {
                "the boundary definitely rejected the operation, so nothing took effect and the effect stays definite"
            }
            Self::ForeignExceptionContained => {
                "a foreign exception was contained at a boundary as a value"
            }
            Self::ForeignPanicContained => "a foreign panic was contained at a boundary as a value",
            Self::ForeignProtocolContained => {
                "a foreign protocol failure was contained at a boundary as a value"
            }
            Self::ForeignTrapContained => "a foreign trap was contained at a boundary as a value",
            Self::GantryInvariantFailure => {
                "a Gantry invariant failure was reported as itself and not as a foreign failure"
            }
            Self::InvariantFailureNotContainable => {
                "a Gantry invariant failure was presented for containment as a foreign class and was refused"
            }
            Self::MalformedCompletionRefused => {
                "a completion that declared no outcome or more than one outcome was refused"
            }
            Self::PoisonedInstanceRefused => {
                "a poisoned landed adapter or resource instance was presented for reuse"
            }
            Self::ProtectedDiagnosticWithheld => {
                "a containment report relating to protected data was withheld from ordinary observation"
            }
            Self::ResourcePoisoningRefused => {
                "a resource that already reached a terminal state was presented for poisoning"
            }
            Self::SecondSettlementRefused => {
                "an operation that already settled was presented with a second completion"
            }
            Self::StaleGenerationRefused => {
                "a completion named an owner generation the operation does not hold"
            }
            Self::UnattributableFailureRefused => {
                "a failure that cannot be attributed to one of the four foreign classes was refused"
            }
        }
    }

    /// Returns the clause key that owns this code.
    #[must_use]
    pub const fn requirement(self) -> &'static str {
        match self {
            Self::ForeignPanicContained
            | Self::ForeignExceptionContained
            | Self::ForeignTrapContained
            | Self::ForeignProtocolContained
            | Self::GantryInvariantFailure
            | Self::InvariantFailureNotContainable
            | Self::UnattributableFailureRefused => "GNT-23.2-foreign-failure-taxonomy",
            Self::AmbiguousEffectMadeDefinite
            | Self::AmbiguousEffectPreserved
            | Self::AmbiguousEffectRetryRefused
            | Self::AmbiguousOutcomeRefused
            | Self::DefiniteEffectMadeAmbiguous
            | Self::DefiniteNotStarted
            | Self::DefiniteRejection => "GNT-23.3-effect-ambiguity-preservation",
            Self::SecondSettlementRefused
            | Self::StaleGenerationRefused
            | Self::MalformedCompletionRefused => {
                "GNT-23.4-operation-ownership-and-single-settlement"
            }
            Self::PoisonedInstanceRefused => "GNT-23.5-failed-instance-poisoning-and-isolation",
            Self::ProtectedDiagnosticWithheld => "GNT-23.6-protected-fault-diagnostics",
            Self::ContainmentObligationRefused | Self::ContainmentPlanIncomplete => {
                "GNT-23.7-adapter-containment-obligations"
            }
            Self::ResourcePoisoningRefused => "GNT-23.5-failed-instance-poisoning-and-isolation",
        }
    }
}

/// One refusal of the containment model.
///
/// Every refusal carries exactly one frozen [`ContainmentDiagnosticCode`] and renders
/// that code first, so a diagnostic, an event, or a report names the clause that owns the
/// condition and no condition is reported under another condition's code. Each condition
/// of this model owns one code: the refusal that constrains an ambiguous effect, the
/// refusal that constrains a retry of one, the refusal that makes a definite accepted
/// outcome over an ambiguous effect, the refusal of an invariant failure as a foreign
/// class, and the refusal of an unattributable failure are distinct conditions with
/// distinct codes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ContainmentError {
    /// A refinement would have made an ambiguous effect definite.
    AmbiguousEffectMadeDefinite {
        /// The boundary at which the refinement was presented.
        boundary: ContainmentBoundary,
        /// The definite state that was presented over the ambiguous effect.
        presented: EffectState,
    },
    /// A retry of an ambiguous mutation was presented to the containment path.
    AmbiguousEffectRetryRefused {
        /// The boundary at which the retry was presented.
        boundary: ContainmentBoundary,
    },
    /// A definite accepted outcome was presented over an ambiguous effect.
    AmbiguousOutcomeRefused {
        /// The definite outcome that was presented.
        outcome: ExternalOutcome,
        /// The ambiguous effect state the settlement holds.
        held: EffectState,
    },
    /// A definite effect was presented as an ambiguous effect.
    DefiniteEffectMadeAmbiguous {
        /// The boundary at which the presentation was made.
        boundary: ContainmentBoundary,
        /// The definite state the boundary holds.
        held: EffectState,
    },
    /// A declared containment plan does not cover every boundary the adapter carries.
    IncompleteContainmentPlan {
        /// The carried boundaries the declared plan does not contain, in clause order.
        missing: Vec<ContainmentBoundary>,
    },
    /// A Gantry invariant failure was presented for containment as a foreign class.
    InvariantFailureNotContainable {
        /// The presented class.
        class: ContainmentFailureClass,
    },
    /// A malformed completion was presented to a settlement.
    MalformedCompletion {
        /// The declared malformed cause.
        cause: MalformedCompletion,
    },
    /// An adapter refused one named containment obligation at one boundary.
    ObligationRefused(
        /// The refused obligation and the boundary at which it was refused.
        ObligationRefusal,
    ),
    /// A poisoned instance was presented for reuse.
    PoisonedInstanceRefused {
        /// The portable spelling of the landed poisoned identity.
        id: Arc<str>,
        /// The reason fixed by the first poisoning, when this model recorded one.
        reason: Option<PoisonReason>,
    },
    /// A containment report relating to protected data was requested by an ordinary
    /// observer.
    ProtectedDiagnosticWithheld {
        /// The frozen code of the withheld report.
        code: ContainmentDiagnosticCode,
    },
    /// A resource that already reached a terminal state was presented for poisoning.
    ResourcePoisoningRefused {
        /// The terminal landed resource state.
        state: ResourceState,
    },
    /// A completion was presented to an already-settled operation.
    SecondSettlement {
        /// The outcome that settled the operation.
        settled: ExternalOutcome,
    },
    /// A completion named an owner generation the operation does not hold.
    StaleGeneration {
        /// The presented owner generation.
        presented: OwnerGeneration,
        /// The held owner generation.
        held: OwnerGeneration,
    },
    /// A failure could not be attributed to one of the four foreign classes.
    UnattributableFailure {
        /// The observation that could not be attributed.
        observed: ForeignFailureObservation,
    },
}

impl ContainmentError {
    /// Returns the frozen code of this condition.
    #[must_use]
    pub const fn code(&self) -> ContainmentDiagnosticCode {
        match self {
            Self::AmbiguousEffectMadeDefinite { .. } => {
                ContainmentDiagnosticCode::AmbiguousEffectMadeDefinite
            }
            Self::AmbiguousEffectRetryRefused { .. } => {
                ContainmentDiagnosticCode::AmbiguousEffectRetryRefused
            }
            Self::AmbiguousOutcomeRefused { .. } => {
                ContainmentDiagnosticCode::AmbiguousOutcomeRefused
            }
            Self::DefiniteEffectMadeAmbiguous { .. } => {
                ContainmentDiagnosticCode::DefiniteEffectMadeAmbiguous
            }
            Self::IncompleteContainmentPlan { .. } => {
                ContainmentDiagnosticCode::ContainmentPlanIncomplete
            }
            Self::InvariantFailureNotContainable { .. } => {
                ContainmentDiagnosticCode::InvariantFailureNotContainable
            }
            Self::MalformedCompletion { .. } => {
                ContainmentDiagnosticCode::MalformedCompletionRefused
            }
            Self::ObligationRefused(_) => ContainmentDiagnosticCode::ContainmentObligationRefused,
            Self::PoisonedInstanceRefused { .. } => {
                ContainmentDiagnosticCode::PoisonedInstanceRefused
            }
            Self::ProtectedDiagnosticWithheld { .. } => {
                ContainmentDiagnosticCode::ProtectedDiagnosticWithheld
            }
            Self::ResourcePoisoningRefused { .. } => {
                ContainmentDiagnosticCode::ResourcePoisoningRefused
            }
            Self::SecondSettlement { .. } => ContainmentDiagnosticCode::SecondSettlementRefused,
            Self::StaleGeneration { .. } => ContainmentDiagnosticCode::StaleGenerationRefused,
            Self::UnattributableFailure { .. } => {
                ContainmentDiagnosticCode::UnattributableFailureRefused
            }
        }
    }

    /// Returns the clause key that owns this condition.
    #[must_use]
    pub const fn clause(&self) -> &'static str {
        self.code().requirement()
    }

    /// Returns the same clause key as [`Self::clause`].
    #[must_use]
    pub const fn requirement(&self) -> &'static str {
        self.clause()
    }

    /// Returns the outcome that settled an operation, for a second-settlement refusal.
    #[must_use]
    pub const fn settled_outcome(&self) -> Option<ExternalOutcome> {
        match self {
            Self::SecondSettlement { settled } => Some(*settled),
            _ => None,
        }
    }

    /// Returns the carried boundaries a declared plan does not cover, for an
    /// incomplete-plan refusal.
    #[must_use]
    pub fn missing_boundaries(&self) -> &[ContainmentBoundary] {
        match self {
            Self::IncompleteContainmentPlan { missing } => missing,
            _ => &[],
        }
    }

    /// Returns the refused adapter obligation, for an obligation refusal.
    #[must_use]
    pub fn refused_obligation(&self) -> Option<ContainmentObligation> {
        match self {
            Self::ObligationRefused(refusal) => Some(refusal.obligation()),
            _ => None,
        }
    }

    /// Returns the reason fixed by the first poisoning, for a reuse refusal.
    ///
    /// A ledger that recorded no reason for a landed poisoned instance reports nothing
    /// here: the refusal is decided by the landed poisoned flag, and the reason this model
    /// recorded is reported only when it recorded one.
    #[must_use]
    pub const fn poison_reason(&self) -> Option<PoisonReason> {
        match self {
            Self::PoisonedInstanceRefused { reason, .. } => *reason,
            _ => None,
        }
    }
}

impl fmt::Display for ContainmentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code().as_str())?;
        formatter.write_str(": ")?;
        match self {
            Self::AmbiguousEffectMadeDefinite {
                boundary,
                presented,
            } => write!(
                formatter,
                "the ambiguous effect at the `{}` boundary is not reclassified as `{}`",
                boundary.wire_name(),
                presented.wire_name()
            ),
            Self::AmbiguousEffectRetryRefused { boundary } => write!(
                formatter,
                "an ambiguous mutation is not retried at the `{}` boundary",
                boundary.wire_name()
            ),
            Self::AmbiguousOutcomeRefused { outcome, held } => write!(
                formatter,
                "the definite `{}` outcome is not settled over the `{}` effect",
                match outcome {
                    ExternalOutcome::Accepted => "accepted",
                    ExternalOutcome::Ambiguous => "ambiguous",
                    ExternalOutcome::Rejected => "rejected",
                },
                held.wire_name()
            ),
            Self::DefiniteEffectMadeAmbiguous { boundary, held } => write!(
                formatter,
                "the definite `{}` effect at the `{}` boundary is not presented as an ambiguous effect",
                held.wire_name(),
                boundary.wire_name()
            ),
            Self::IncompleteContainmentPlan { missing } => {
                formatter.write_str("the declared containment plan does not cover every boundary the adapter carries")?;
                for boundary in missing {
                    write!(formatter, " `{}`", boundary.wire_name())?;
                }
                Ok(())
            }
            Self::InvariantFailureNotContainable { class } => write!(
                formatter,
                "the `{}` class is a Gantry invariant failure and is never contained as a foreign failure",
                class.wire_name()
            ),
            Self::MalformedCompletion { cause } => write!(
                formatter,
                "the completion is malformed as `{}` and settles nothing",
                cause.wire_name()
            ),
            Self::ObligationRefused(refusal) => write!(formatter, "{refusal}"),
            Self::PoisonedInstanceRefused { id, reason } => write!(
                formatter,
                "the landed instance `{id}` is poisoned by `{}` and is never reused",
                match reason {
                    Some(reason) => reason.wire_name(),
                    None => "an unrecorded-reason",
                }
            ),
            Self::ProtectedDiagnosticWithheld { code } => write!(
                formatter,
                "the report of `{}` relates to protected data and is withheld from ordinary observation",
                code.as_str()
            ),
            Self::ResourcePoisoningRefused { state } => write!(
                formatter,
                "the `{}` resource is terminal and is not poisoned",
                state.wire_name()
            ),
            Self::SecondSettlement { .. } => formatter
                .write_str("the operation already settled and no completion settles it twice"),
            Self::StaleGeneration { presented, held } => write!(
                formatter,
                "owner generation {} is not the held owner generation {}",
                presented.value(),
                held.value()
            ),
            Self::UnattributableFailure { observed } => write!(
                formatter,
                "the `{}` observation is not attributed to a foreign class",
                observed.wire_name()
            ),
        }
    }
}

impl std::error::Error for ContainmentError {}

/// One closed name of a containment non-claim
/// (`GNT-23.8-containment-non-claims`).
///
/// Each member names a property this section explicitly does not promise. A report, a
/// clause, or an evidence item MUST NOT be read as promising one, and the vocabulary is
/// closed so no unlisted guarantee can be claimed under this section.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ContainmentNonClaimName {
    /// Containment is not an arbitrary memory-corruption guarantee.
    ArbitraryMemoryCorruptionGuarantee,
    /// Containment is not a rollback after effects may have begun.
    RollbackAfterEffects,
    /// Containment is not a platform or ABI guarantee.
    PlatformAbiGuarantee,
    /// A poisoned instance is not repairable in place.
    PoisonedInstanceRepair,
    /// Containment is not a protected payload or backtrace disclosure.
    ProtectedPayloadOrBacktraceDisclosure,
}

impl ContainmentNonClaimName {
    /// Every member of the closed vocabulary, in published order.
    pub const ALL: [Self; 5] = [
        Self::ArbitraryMemoryCorruptionGuarantee,
        Self::RollbackAfterEffects,
        Self::PlatformAbiGuarantee,
        Self::PoisonedInstanceRepair,
        Self::ProtectedPayloadOrBacktraceDisclosure,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::ArbitraryMemoryCorruptionGuarantee => "arbitrary-memory-corruption-guarantee",
            Self::RollbackAfterEffects => "rollback-after-effects",
            Self::PlatformAbiGuarantee => "platform-abi-guarantee",
            Self::PoisonedInstanceRepair => "poisoned-instance-repair",
            Self::ProtectedPayloadOrBacktraceDisclosure => {
                "protected-payload-or-backtrace-disclosure"
            }
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

    /// Returns the clause key that owns this non-claim.
    #[must_use]
    pub const fn requirement(self) -> &'static str {
        "GNT-23.8-containment-non-claims"
    }
}

/// One published containment non-claim (`GNT-23.8-containment-non-claims`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContainmentNonClaim {
    name: ContainmentNonClaimName,
    statement: &'static str,
}

impl ContainmentNonClaim {
    /// Returns the closed name of this non-claim.
    #[must_use]
    pub const fn name(self) -> ContainmentNonClaimName {
        self.name
    }

    /// Returns the published statement of this non-claim.
    #[must_use]
    pub const fn statement(self) -> &'static str {
        self.statement
    }
}

/// The published order of the closed containment non-claim vocabulary.
pub const CONTAINMENT_NON_CLAIM_NAMES: [ContainmentNonClaimName; 5] = ContainmentNonClaimName::ALL;

/// The published containment non-claims, in [`CONTAINMENT_NON_CLAIM_NAMES`] order.
pub const CONTAINMENT_NON_CLAIM_ORDER: [ContainmentNonClaim; 5] = [
    ContainmentNonClaim {
        name: ContainmentNonClaimName::ArbitraryMemoryCorruptionGuarantee,
        statement: "containment reports that a foreign failure was observed at a boundary and never claims that the memory state of the process, the task, or the foreign code is sound",
    },
    ContainmentNonClaim {
        name: ContainmentNonClaimName::RollbackAfterEffects,
        statement: "containment never undoes an effect: an ambiguous effect stays ambiguous and no accepted effect is rolled back",
    },
    ContainmentNonClaim {
        name: ContainmentNonClaimName::PlatformAbiGuarantee,
        statement: "this section makes no claim about how a platform implements an unwind, a trap, an abort, or a protocol failure beyond containing what a boundary observed",
    },
    ContainmentNonClaim {
        name: ContainmentNonClaimName::PoisonedInstanceRepair,
        statement: "poisoning is one-way and a poisoned instance is never repaired in place or returned to service",
    },
    ContainmentNonClaim {
        name: ContainmentNonClaimName::ProtectedPayloadOrBacktraceDisclosure,
        statement: "a containment report carries declared metadata and codes only, so no payload byte, protected content, secret, credential, or foreign backtrace is disclosed",
    },
];
