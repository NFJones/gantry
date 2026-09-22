//! Portable declarations for standard host-domain contracts.
//!
//! This is the pure model for `GNT-29.0` through `GNT-29.15`.  It classifies
//! declared host outcomes and adapter mappings without opening a host resource,
//! performing an operation, or defining a runtime adapter or host trait.

use std::fmt;

use crate::generated::{HostDomainCategory, HostDomainFamily, HostTarget};
use crate::{
    EffectCertainty, OwnerGeneration, PostFailureSettlement, ProgressObservation, ReceiverOwnership,
};

/// The Section 29 clauses in publication order.
pub const HOST_DOMAIN_CLAUSES: [&str; 16] = [
    "GNT-29.0-portable-host-domain-and-standard-host-family-contracts",
    "GNT-29.1-channel-separation",
    "GNT-29.2-reader-writer-seek-progress",
    "GNT-29.3-portable-domain-error-envelope",
    "GNT-29.4-console-contract",
    "GNT-29.5-filesystem-and-environment-contracts",
    "GNT-29.6-dns-socket-tls-and-http-contracts",
    "GNT-29.7-process-contract",
    "GNT-29.8-time-randomness-and-secret-contracts",
    "GNT-29.9-codec-contract",
    "GNT-29.10-target-applicability",
    "GNT-29.11-adapter-declaration-obligations",
    "GNT-29.12-adapter-diagnostics",
    "GNT-29.13-process-confinement-and-supervision",
    "GNT-29.14-native-detail-exclusion",
    "GNT-29.15-host-contract-non-claims",
];

/// The bounded byte length of a portable domain-error message.
pub const PORTABLE_MESSAGE_MAX_BYTES: usize = 256;

/// An operational adapter failure is distinct from a source-visible domain error.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum HostOperationFailure {
    /// The adapter could not carry an operation.
    Operational,
    /// The declared host domain rejected or could not complete the operation.
    Domain,
}

impl HostOperationFailure {
    /// Every channel in canonical wire order.
    pub const ALL: [Self; 2] = [Self::Domain, Self::Operational];
    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Operational => "operational",
            Self::Domain => "domain",
        }
    }
}

/// A bounded portable host-domain error envelope with no native detail field.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostDomainError {
    family: HostDomainFamily,
    category: HostDomainCategory,
    message: String,
}

impl HostDomainError {
    /// Constructs a strictly matched, bounded portable envelope.
    pub fn new(
        family: HostDomainFamily,
        category: HostDomainCategory,
        message: impl Into<String>,
    ) -> Result<Self, HostDomainErrorKind> {
        let message = message.into();
        if !family.admits(category) {
            return Err(HostDomainErrorKind::MismatchedFamilyCategory);
        }
        if message.len() > PORTABLE_MESSAGE_MAX_BYTES || !portable_message(&message) {
            return Err(HostDomainErrorKind::InvalidPortableDetail);
        }
        Ok(Self {
            family,
            category,
            message,
        })
    }
    /// Returns the closed error family.
    #[must_use]
    pub const fn family(&self) -> HostDomainFamily {
        self.family
    }
    /// Returns the closed family category.
    #[must_use]
    pub const fn category(&self) -> HostDomainCategory {
        self.category
    }
    /// Returns the bounded portable diagnostic text.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

fn portable_message(message: &str) -> bool {
    !message.is_empty()
        && message
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b' ' || byte == b'-')
        && !message.starts_with([' ', '-'])
        && !message.ends_with([' ', '-'])
        && !message.contains("  ")
        && !message.contains("--")
        && !message.split([' ', '-']).any(|word| word == "provider")
}

/// One operation outcome: exactly one success, domain error, or operational error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HostOperationOutcome {
    /// The operation succeeded with no source-visible domain failure.
    Succeeded,
    /// A source-visible portable domain failure occurred.
    DomainError(HostDomainError),
    /// The adapter's operational channel failed and exposes no domain error.
    OperationalFailure,
}

impl HostOperationOutcome {
    /// Returns the channel selected by this outcome, if it failed.
    #[must_use]
    pub const fn failure_channel(&self) -> Option<HostOperationFailure> {
        match self {
            Self::Succeeded => None,
            Self::DomainError(_) => Some(HostOperationFailure::Domain),
            Self::OperationalFailure => Some(HostOperationFailure::Operational),
        }
    }
}

/// Maps Reader, Writer, and Seek declarations to the landed Section 20 observation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum HostProgress {
    /// No bytes or position change was observed.
    NotStarted,
    /// A read ended normally.
    Eof,
    /// A reader made a nonterminal short advance.
    ShortRead,
    /// A writer made a nonterminal short advance.
    ShortWrite,
    /// A seek or non-streaming operation completed.
    Complete,
}

impl HostProgress {
    /// Every declared member, in the canonical order of the observations it maps to.
    pub const ALL: [Self; 5] = [
        Self::Complete,
        Self::Eof,
        Self::NotStarted,
        Self::ShortRead,
        Self::ShortWrite,
    ];

    /// Maps exactly to Section 20's progress observation vocabulary.
    #[must_use]
    pub const fn observation(self) -> ProgressObservation {
        match self {
            Self::NotStarted => ProgressObservation::NotStarted,
            Self::Eof => ProgressObservation::Eof,
            Self::ShortRead => ProgressObservation::ShortRead,
            Self::ShortWrite => ProgressObservation::ShortWrite,
            Self::Complete => ProgressObservation::CommittedProgress,
        }
    }
}

/// The declared post-operation settlement facts for one host operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostSettlement {
    outcome: HostOperationOutcome,
    progress: HostProgress,
    receiver: ReceiverOwnership,
    post_failure: Option<PostFailureSettlement>,
    effect: EffectCertainty,
    owner: OwnerGeneration,
}

impl HostSettlement {
    /// Creates one complete settlement that satisfies the Section 20 facts.
    pub fn new(
        outcome: HostOperationOutcome,
        progress: HostProgress,
        receiver: ReceiverOwnership,
        post_failure: Option<PostFailureSettlement>,
        effect: EffectCertainty,
        owner: OwnerGeneration,
    ) -> Result<Self, HostSettlementError> {
        if matches!(outcome, HostOperationOutcome::Succeeded)
            && (post_failure.is_some() || effect != EffectCertainty::AmbiguouslyBegun)
        {
            return Err(HostSettlementError::SuccessContradictsFailureFacts);
        }
        if progress != HostProgress::NotStarted && effect == EffectCertainty::DefiniteNotStarted {
            return Err(HostSettlementError::ProgressContradictsEffectCertainty);
        }
        if !matches!(outcome, HostOperationOutcome::Succeeded) && post_failure.is_none() {
            return Err(HostSettlementError::FailureMissingPostFailureSettlement);
        }
        if receiver
            .owner()
            .is_some_and(|receiver_owner| receiver_owner != owner)
            || post_failure.as_ref().is_some_and(|settlement| {
                settlement.ownership() != &receiver
                    || receiver
                        .owner()
                        .is_some_and(|receiver_owner| receiver_owner != owner)
            })
        {
            return Err(HostSettlementError::OwnerMismatch);
        }
        Ok(Self {
            outcome,
            progress,
            receiver,
            post_failure,
            effect,
            owner,
        })
    }
    /// Returns the sole outcome.
    #[must_use]
    pub const fn outcome(&self) -> &HostOperationOutcome {
        &self.outcome
    }
    /// Returns the mapped progress observation.
    #[must_use]
    pub const fn progress(&self) -> HostProgress {
        self.progress
    }
    /// Returns the receiver arrangement.
    #[must_use]
    pub const fn receiver(&self) -> &ReceiverOwnership {
        &self.receiver
    }
    /// Returns the post-failure settlement where one was declared.
    #[must_use]
    pub const fn post_failure(&self) -> Option<&PostFailureSettlement> {
        self.post_failure.as_ref()
    }
    /// Returns effect certainty.
    #[must_use]
    pub const fn effect(&self) -> EffectCertainty {
        self.effect
    }
    /// Returns the owning generation.
    #[must_use]
    pub const fn owner(&self) -> OwnerGeneration {
        self.owner
    }
}

/// A contradiction in declared Section 20 host-settlement facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostSettlementError {
    /// A successful outcome carried failure facts or an indefinite effect.
    SuccessContradictsFailureFacts,
    /// A failed outcome omitted its required post-failure settlement.
    FailureMissingPostFailureSettlement,
    /// Observed progress was paired with a definite not-started effect.
    ProgressContradictsEffectCertainty,
    /// The top-level owner did not match the transferred receiver.
    OwnerMismatch,
}

/// Declared process confinement state; only process mappings may name it.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ProcessConfinement {
    /// The declaration names confined execution without claiming OS isolation.
    Confined,
    /// The declaration records that execution is unconfined and audited.
    AuditedUnconfined,
}
/// Declared standard-I/O arrangement for a process mapping.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ProcessStdio {
    /// The child inherits standard I/O.
    Inherit,
    /// The child uses declared pipes.
    Piped,
    /// The child uses null standard I/O.
    Null,
}
/// Declared lifecycle state of a process mapping.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ProcessSupervision {
    /// The process was declared launched by its owner.
    Launched,
    /// The owner declared that it waited for the process.
    Waited,
    /// The owner declared that it reaped the process.
    Reaped,
}

/// Single-owner declared lifecycle facts for one process mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessLifecycle {
    owner: OwnerGeneration,
    state: ProcessSupervision,
}

impl ProcessLifecycle {
    /// Opens a lifecycle under one explicit owner generation.
    #[must_use]
    pub const fn launched(owner: OwnerGeneration) -> Self {
        Self {
            owner,
            state: ProcessSupervision::Launched,
        }
    }

    /// Returns the sole lifecycle owner.
    #[must_use]
    pub const fn owner(self) -> OwnerGeneration {
        self.owner
    }

    /// Returns the declared lifecycle state.
    #[must_use]
    pub const fn state(self) -> ProcessSupervision {
        self.state
    }

    /// Declares the only admitted next lifecycle state for the current owner.
    pub fn advance(
        &mut self,
        owner: OwnerGeneration,
        next: ProcessSupervision,
    ) -> Result<(), HostDomainErrorKind> {
        if owner != self.owner {
            return Err(HostDomainErrorKind::ProcessOwnerMismatch);
        }
        if !matches!(
            (self.state, next),
            (ProcessSupervision::Launched, ProcessSupervision::Waited)
                | (ProcessSupervision::Waited, ProcessSupervision::Reaped)
        ) {
            return Err(HostDomainErrorKind::InvalidProcessLifecycleTransition);
        }
        self.state = next;
        Ok(())
    }
}

/// One native-to-portable category mapping, with native detail retained outside portable output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeMappingDeclaration {
    family: HostDomainFamily,
    category: HostDomainCategory,
    native_code: String,
}
impl NativeMappingDeclaration {
    /// Validates a mapping against the closed family-category matrix.
    pub fn new(
        family: HostDomainFamily,
        category: HostDomainCategory,
        native_code: impl Into<String>,
    ) -> Result<Self, HostDomainErrorKind> {
        if !family.admits(category) {
            return Err(HostDomainErrorKind::MismatchedFamilyCategory);
        }
        let native_code = native_code.into();
        if native_code.is_empty() {
            return Err(HostDomainErrorKind::IncompleteAdapterDeclaration);
        }
        Ok(Self {
            family,
            category,
            native_code,
        })
    }
    /// Returns the mapped family.
    #[must_use]
    pub const fn family(&self) -> HostDomainFamily {
        self.family
    }
    /// Returns the mapped category.
    #[must_use]
    pub const fn category(&self) -> HostDomainCategory {
        self.category
    }
    /// Returns native-only detail, never part of `HostDomainError`.
    #[must_use]
    pub fn native_code(&self) -> &str {
        &self.native_code
    }
}

/// An adapter's complete pure declaration of mappings and target applicability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdapterContractDeclaration {
    target: HostTarget,
    mappings: Vec<NativeMappingDeclaration>,
    process: Option<(
        ProcessConfinement,
        ProcessStdio,
        OwnerGeneration,
        ProcessLifecycle,
    )>,
}
impl AdapterContractDeclaration {
    /// Validates that each declared family has every category including `Unclassified`.
    pub fn new(
        target: HostTarget,
        mappings: Vec<NativeMappingDeclaration>,
        process: Option<(
            ProcessConfinement,
            ProcessStdio,
            OwnerGeneration,
            ProcessLifecycle,
        )>,
    ) -> Result<Self, HostDomainErrorKind> {
        if mappings.is_empty() {
            return Err(HostDomainErrorKind::IncompleteAdapterDeclaration);
        }
        if process.is_some()
            && !mappings
                .iter()
                .any(|mapping| mapping.family == HostDomainFamily::Process)
        {
            return Err(HostDomainErrorKind::ProcessDeclarationOutsideProcess);
        }
        if let Some((_, _, owner, lifecycle)) = process {
            if lifecycle.owner() != owner {
                return Err(HostDomainErrorKind::ProcessOwnerMismatch);
            }
            if lifecycle.state() != ProcessSupervision::Launched {
                return Err(HostDomainErrorKind::InvalidProcessLifecycleTransition);
            }
        }
        for family in HostDomainFamily::ALL {
            let declared = mappings
                .iter()
                .filter(|mapping| mapping.family == family)
                .collect::<Vec<_>>();
            if !declared.is_empty()
                && (declared.len() != family.categories().len()
                    || family.categories().iter().any(|category| {
                        declared
                            .iter()
                            .filter(|mapping| mapping.category == *category)
                            .count()
                            != 1
                    }))
            {
                return Err(HostDomainErrorKind::IncompleteAdapterDeclaration);
            }
            if !declared.is_empty() && !family.applies_to(target) {
                return Err(HostDomainErrorKind::TargetMappingInapplicable);
            }
        }
        Ok(Self {
            target,
            mappings,
            process,
        })
    }
    /// Returns the declared target.
    #[must_use]
    pub const fn target(&self) -> HostTarget {
        self.target
    }
    /// Returns all native mappings.
    #[must_use]
    pub fn mappings(&self) -> &[NativeMappingDeclaration] {
        &self.mappings
    }
    /// Returns process declarations only when process is mapped.
    #[must_use]
    pub const fn process(
        &self,
    ) -> Option<(
        ProcessConfinement,
        ProcessStdio,
        OwnerGeneration,
        ProcessLifecycle,
    )> {
        self.process
    }
}

/// Frozen diagnostics for Section 29 pure declarations.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum HostDomainDiagnosticCode {
    /// A family does not admit a presented category.
    MismatchedFamilyCategory,
    /// A portable field is malformed, oversized, or carries excluded detail.
    InvalidPortableDetail,
    /// A declaration omits, duplicates, or leaves a mapping incomplete.
    IncompleteAdapterDeclaration,
    /// A mapping appears for a target its family does not admit.
    TargetMappingInapplicable,
    /// Process-only declaration facts were presented without a process mapping.
    ProcessDeclarationOutsideProcess,
    /// A process lifecycle transition names a different owner generation.
    ProcessOwnerMismatch,
    /// A process lifecycle transition is not launched-to-waited or waited-to-reaped.
    InvalidProcessLifecycleTransition,
}
impl HostDomainDiagnosticCode {
    /// Every code in canonical spelling order.
    pub const ALL: [Self; 7] = [
        Self::IncompleteAdapterDeclaration,
        Self::InvalidProcessLifecycleTransition,
        Self::InvalidPortableDetail,
        Self::MismatchedFamilyCategory,
        Self::ProcessOwnerMismatch,
        Self::ProcessDeclarationOutsideProcess,
        Self::TargetMappingInapplicable,
    ];
    /// Returns the frozen diagnostic spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MismatchedFamilyCategory => "host-domain-mismatched-family-category",
            Self::InvalidPortableDetail => "host-domain-invalid-portable-detail",
            Self::IncompleteAdapterDeclaration => "host-domain-incomplete-adapter-declaration",
            Self::TargetMappingInapplicable => "host-domain-target-mapping-inapplicable",
            Self::ProcessDeclarationOutsideProcess => {
                "host-domain-process-declaration-outside-process"
            }
            Self::ProcessOwnerMismatch => "host-domain-process-owner-mismatch",
            Self::InvalidProcessLifecycleTransition => {
                "host-domain-invalid-process-lifecycle-transition"
            }
        }
    }
    /// Returns the sole owning requirement clause.
    #[must_use]
    pub const fn requirement(self) -> &'static str {
        match self {
            Self::MismatchedFamilyCategory => HOST_DOMAIN_CLAUSES[3],
            Self::InvalidPortableDetail => HOST_DOMAIN_CLAUSES[14],
            Self::IncompleteAdapterDeclaration => HOST_DOMAIN_CLAUSES[11],
            Self::TargetMappingInapplicable => HOST_DOMAIN_CLAUSES[10],
            Self::ProcessDeclarationOutsideProcess => HOST_DOMAIN_CLAUSES[13],
            Self::ProcessOwnerMismatch | Self::InvalidProcessLifecycleTransition => {
                HOST_DOMAIN_CLAUSES[13]
            }
        }
    }
}

/// A typed refusal from the pure host-domain declaration model.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostDomainErrorKind {
    /// A family does not admit a presented category.
    MismatchedFamilyCategory,
    /// A portable field is malformed, oversized, or carries excluded detail.
    InvalidPortableDetail,
    /// A declaration omits, duplicates, or leaves a mapping incomplete.
    IncompleteAdapterDeclaration,
    /// A mapping appears for a target its family does not admit.
    TargetMappingInapplicable,
    /// Process-only declaration facts were presented without a process mapping.
    ProcessDeclarationOutsideProcess,
    /// A process lifecycle transition names a different owner generation.
    ProcessOwnerMismatch,
    /// A process lifecycle transition is not launched-to-waited or waited-to-reaped.
    InvalidProcessLifecycleTransition,
}
impl HostDomainErrorKind {
    /// Returns the frozen diagnostic code.
    #[must_use]
    pub const fn code(self) -> HostDomainDiagnosticCode {
        match self {
            Self::MismatchedFamilyCategory => HostDomainDiagnosticCode::MismatchedFamilyCategory,
            Self::InvalidPortableDetail => HostDomainDiagnosticCode::InvalidPortableDetail,
            Self::IncompleteAdapterDeclaration => {
                HostDomainDiagnosticCode::IncompleteAdapterDeclaration
            }
            Self::TargetMappingInapplicable => HostDomainDiagnosticCode::TargetMappingInapplicable,
            Self::ProcessDeclarationOutsideProcess => {
                HostDomainDiagnosticCode::ProcessDeclarationOutsideProcess
            }
            Self::ProcessOwnerMismatch => HostDomainDiagnosticCode::ProcessOwnerMismatch,
            Self::InvalidProcessLifecycleTransition => {
                HostDomainDiagnosticCode::InvalidProcessLifecycleTransition
            }
        }
    }
}
impl fmt::Display for HostDomainErrorKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code().as_str())
    }
}
impl std::error::Error for HostDomainErrorKind {}
