//! Pure declaration model for application entry and launch lifecycle.
//!
//! The Section 30 model is deliberately not a launcher, runtime, evaluator, host
//! trait, CLI, or adapter. It validates bounded declarations and legal lifecycle
//! ordering from explicit values. Section 22 remains the sole stop coordinator and
//! sealed-cleanup witness; Section 20 remains the sole owner-generation identity.

#![allow(missing_docs)]

use std::collections::{BTreeMap, BTreeSet};

use gantry_core::mode::SemanticMode;

use crate::{
    EmergencyCleanupWitness, GracePolicy, OwnerGeneration, StopCause, StopCoordinator, StopRequest,
    TargetKind,
};

/// The Section 30 clauses in declaration order.
pub const APPLICATION_CLAUSES: [&str; 13] = [
    "GNT-30.0-application-entry-and-launch-lifecycle",
    "GNT-30.1-target-selected-entry-abi",
    "GNT-30.2-bounded-launch-snapshot-and-capability-closure",
    "GNT-30.3-arguments-environment-and-logical-cwd",
    "GNT-30.4-standard-io-and-exit-disposition",
    "GNT-30.5-startup-order-and-admission-closure",
    "GNT-30.6-fuel-grants-suspension-and-renewal",
    "GNT-30.7-signal-translation-and-stop-joining",
    "GNT-30.8-bounded-finalization-and-outcome-preservation",
    "GNT-30.9-supervisor-settlement-and-exit-publication",
    "GNT-30.10-standalone-and-embedded-equivalence",
    "GNT-30.11-durable-companion-admission",
    "GNT-30.12-application-non-claims",
];

/// Closed launch arrangement vocabulary.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum LaunchArrangement {
    Standalone,
    Embedded,
}

/// Closed classification of a durable-companion closure member.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ApplicationClass {
    ApplicationOnly,
    Durable,
    LiveClosure,
}

/// Closed phase vocabulary for the application declaration lifecycle.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ApplicationPhase {
    Declared,
    Started,
    AdmissionClosed,
    Finalizing,
    Settled,
    Published,
}

/// One standard-I/O channel.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum StdioChannel {
    Stdin,
    Stdout,
    Stderr,
}

/// Closed arrangement for a standard-I/O channel.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum StdioArrangement {
    Inherit,
    Null,
    Pipe,
}

/// Closed portable signal classes.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum PortableSignalClass {
    Interrupt,
    Terminate,
}

/// Closed semantic exit dispositions.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ExitDisposition {
    Completed,
    Failed,
    Stopped,
}

/// Closed state of a finite Section 3 fuel grant.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum FuelDisposition {
    Available,
    Exhausted,
    Suspended,
}

/// Closed bounded-finalization order.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum FinalizationStep {
    CloseAdmission,
    FinalFlush,
    HardCancellation,
    SupervisorSettlement,
    ExitPublication,
}

macro_rules! closed_vocabulary {
    ($name:ident, [$($value:ident => $text:literal),+ $(,)?]) => {
        impl $name {
            /// Every member in stable wire-name order.
            pub const ALL: [Self; closed_vocabulary!(@count $($value)+)] = [$(Self::$value),+];

            /// Returns the exact portable spelling.
            #[must_use]
            pub const fn wire_name(self) -> &'static str {
                match self { $(Self::$value => $text),+ }
            }

            /// Strictly decodes one exact portable spelling.
            #[must_use]
            pub fn from_wire_name(value: &str) -> Option<Self> {
                Self::ALL.into_iter().find(|candidate| candidate.wire_name() == value)
            }
        }
    };
    (@count $($value:ident)+) => { <[()]>::len(&[$(closed_vocabulary!(@replace $value ())),+]) };
    (@replace $_value:ident $replacement:expr) => { $replacement };
}

closed_vocabulary!(LaunchArrangement, [Embedded => "embedded", Standalone => "standalone"]);
closed_vocabulary!(ApplicationClass, [ApplicationOnly => "application-only", Durable => "durable", LiveClosure => "live-closure"]);
closed_vocabulary!(ApplicationPhase, [AdmissionClosed => "admission-closed", Declared => "declared", Finalizing => "finalizing", Published => "published", Settled => "settled", Started => "started"]);
closed_vocabulary!(StdioChannel, [Stderr => "stderr", Stdin => "stdin", Stdout => "stdout"]);
closed_vocabulary!(StdioArrangement, [Inherit => "inherit", Null => "null", Pipe => "pipe"]);
closed_vocabulary!(PortableSignalClass, [Interrupt => "interrupt", Terminate => "terminate"]);
closed_vocabulary!(ExitDisposition, [Completed => "completed", Failed => "failed", Stopped => "stopped"]);
closed_vocabulary!(FuelDisposition, [Available => "available", Exhausted => "exhausted", Suspended => "suspended"]);
closed_vocabulary!(FinalizationStep, [CloseAdmission => "close-admission", FinalFlush => "final-flush", HardCancellation => "hard-cancellation", SupervisorSettlement => "supervisor-settlement", ExitPublication => "exit-publication"]);

/// Bounds for one immutable launch snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LaunchSnapshotLimits {
    arguments: usize,
    environment: usize,
    capabilities: usize,
    entry_bytes: usize,
}

impl LaunchSnapshotLimits {
    #[must_use]
    pub const fn new(
        arguments: usize,
        environment: usize,
        capabilities: usize,
        entry_bytes: usize,
    ) -> Self {
        Self {
            arguments,
            environment,
            capabilities,
            entry_bytes,
        }
    }
}

/// One declared capability in a launch closure.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CapabilityGrant(String);

impl CapabilityGrant {
    pub fn new(value: impl Into<String>) -> Result<Self, ApplicationError> {
        let value = value.into();
        if value.is_empty() || value.len() > 128 {
            return Err(ApplicationError::InvalidCapability);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Logical CWD data, distinct from directory authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogicalCwd(String);

impl LogicalCwd {
    pub fn new(value: impl Into<String>) -> Result<Self, ApplicationError> {
        let value = value.into();
        if value.is_empty() || value.len() > 1024 {
            return Err(ApplicationError::InvalidCwd);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Immutable bounded arguments, environment, logical CWD, and capability closure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaunchSnapshot {
    arguments: Vec<String>,
    environment: BTreeMap<String, String>,
    cwd: LogicalCwd,
    capabilities: BTreeSet<CapabilityGrant>,
}

impl LaunchSnapshot {
    pub fn new(
        arguments: Vec<String>,
        environment: Vec<(String, String)>,
        cwd: LogicalCwd,
        capabilities: BTreeSet<CapabilityGrant>,
        limits: LaunchSnapshotLimits,
    ) -> Result<Self, ApplicationError> {
        if arguments.len() > limits.arguments
            || environment.len() > limits.environment
            || capabilities.len() > limits.capabilities
            || arguments
                .iter()
                .any(|value| value.len() > limits.entry_bytes)
        {
            return Err(ApplicationError::SnapshotLimitExceeded);
        }
        let mut frozen = BTreeMap::new();
        for (key, value) in environment {
            if key.is_empty() || key.len() > limits.entry_bytes || value.len() > limits.entry_bytes
            {
                return Err(ApplicationError::InvalidEnvironmentEntry);
            }
            if frozen.insert(key, value).is_some() {
                return Err(ApplicationError::DuplicateEnvironment);
            }
        }
        Ok(Self {
            arguments,
            environment: frozen,
            cwd,
            capabilities,
        })
    }

    #[must_use]
    pub fn arguments(&self) -> &[String] {
        &self.arguments
    }

    #[must_use]
    pub fn environment(&self) -> &BTreeMap<String, String> {
        &self.environment
    }

    #[must_use]
    pub fn cwd(&self) -> &LogicalCwd {
        &self.cwd
    }

    #[must_use]
    pub fn capabilities(&self) -> &BTreeSet<CapabilityGrant> {
        &self.capabilities
    }

    pub fn project_child(
        &self,
        child: BTreeSet<CapabilityGrant>,
    ) -> Result<BTreeSet<CapabilityGrant>, ApplicationError> {
        if !child.is_subset(&self.capabilities) {
            return Err(ApplicationError::CapabilityAmplification);
        }
        Ok(child)
    }
}

/// Target-selected application entry and ABI declaration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplicationEntry {
    target: String,
    mode: SemanticMode,
    abi: String,
    snapshot: LaunchSnapshot,
}

impl ApplicationEntry {
    pub fn new(
        target: impl Into<String>,
        mode: SemanticMode,
        abi: impl Into<String>,
        snapshot: LaunchSnapshot,
        limits: LaunchSnapshotLimits,
    ) -> Result<Self, ApplicationError> {
        let target = target.into();
        let abi = abi.into();
        if target.is_empty()
            || abi.is_empty()
            || abi.len() > limits.entry_bytes
            || mode != SemanticMode::Application
        {
            return Err(ApplicationError::InvalidEntry);
        }
        Ok(Self {
            target,
            mode,
            abi,
            snapshot,
        })
    }

    #[must_use]
    pub fn target(&self) -> &str {
        &self.target
    }

    #[must_use]
    pub const fn mode(&self) -> SemanticMode {
        self.mode
    }

    #[must_use]
    pub fn abi(&self) -> &str {
        &self.abi
    }

    #[must_use]
    pub fn snapshot(&self) -> &LaunchSnapshot {
        &self.snapshot
    }
}

/// The unique target-selected entry declaration set.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ApplicationEntries(BTreeMap<String, ApplicationEntry>);

impl ApplicationEntries {
    pub fn insert(&mut self, entry: ApplicationEntry) -> Result<(), ApplicationError> {
        if self.0.contains_key(entry.target()) {
            return Err(ApplicationError::DuplicateTargetEntry);
        }
        self.0.insert(entry.target.clone(), entry);
        Ok(())
    }

    #[must_use]
    pub fn get(&self, target: &str) -> Option<&ApplicationEntry> {
        self.0.get(target)
    }
}

/// Complete declared standard-I/O arrangement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StdioSet(BTreeMap<StdioChannel, StdioArrangement>);

impl StdioSet {
    pub fn new(items: &[(StdioChannel, StdioArrangement)]) -> Result<Self, ApplicationError> {
        let mut set = BTreeMap::new();
        for (channel, arrangement) in items {
            if set.insert(*channel, *arrangement).is_some() {
                return Err(ApplicationError::DuplicateStdioChannel);
            }
        }
        if set.len() != StdioChannel::ALL.len() {
            return Err(ApplicationError::IncompleteStdio);
        }
        Ok(Self(set))
    }

    #[must_use]
    pub fn arrangement(&self, channel: StdioChannel) -> StdioArrangement {
        self.0[&channel]
    }
}

/// Finite renewable Section 3 transition-budget grant, not a Section 28 quota.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FuelGrant {
    remaining: u64,
    yield_quantum: u64,
    generation: OwnerGeneration,
}

impl FuelGrant {
    pub fn new(
        remaining: u64,
        yield_quantum: u64,
        generation: OwnerGeneration,
    ) -> Result<Self, ApplicationError> {
        if remaining == 0 || yield_quantum == 0 {
            return Err(ApplicationError::InvalidFuelGrant);
        }
        Ok(Self {
            remaining,
            yield_quantum,
            generation,
        })
    }

    #[must_use]
    pub const fn remaining(self) -> u64 {
        self.remaining
    }

    #[must_use]
    pub const fn yield_quantum(self) -> u64 {
        self.yield_quantum
    }

    #[must_use]
    pub const fn generation(self) -> OwnerGeneration {
        self.generation
    }
}

/// Mutable declared fuel state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FuelState {
    grant: FuelGrant,
    disposition: FuelDisposition,
}

impl FuelState {
    #[must_use]
    pub const fn new(grant: FuelGrant) -> Self {
        Self {
            grant,
            disposition: FuelDisposition::Available,
        }
    }

    #[must_use]
    pub const fn disposition(self) -> FuelDisposition {
        self.disposition
    }

    #[must_use]
    pub const fn grant(self) -> FuelGrant {
        self.grant
    }

    pub fn consume(&mut self, amount: u64) -> Result<(), ApplicationError> {
        if self.disposition != FuelDisposition::Available || amount > self.grant.remaining {
            self.disposition = FuelDisposition::Exhausted;
            return Err(ApplicationError::FuelExhausted);
        }
        self.grant.remaining -= amount;
        if self.grant.remaining == 0 {
            self.disposition = FuelDisposition::Exhausted;
        }
        Ok(())
    }

    pub fn suspend(&mut self) {
        self.disposition = FuelDisposition::Suspended;
    }

    pub fn renew(&mut self, grant: FuelGrant) -> Result<(), ApplicationError> {
        if grant.generation != self.grant.generation {
            return Err(ApplicationError::StaleFuelGeneration);
        }
        if grant.yield_quantum != self.grant.yield_quantum {
            return Err(ApplicationError::YieldQuantumChanged);
        }
        self.grant = grant;
        self.disposition = FuelDisposition::Available;
        Ok(())
    }
}

/// One declared supervisor-settlement fact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SupervisorSettlement {
    settled: bool,
}

impl SupervisorSettlement {
    #[must_use]
    pub const fn pending() -> Self {
        Self { settled: false }
    }

    #[must_use]
    pub const fn settled() -> Self {
        Self { settled: true }
    }

    #[must_use]
    pub const fn is_settled(self) -> bool {
        self.settled
    }
}

/// One final exit report. A sealed cleanup witness remains affine.
#[derive(Debug)]
pub struct ExitReport {
    disposition: ExitDisposition,
    flush_succeeded: bool,
    supervisor: SupervisorSettlement,
    cleanup: Option<EmergencyCleanupWitness>,
}

impl ExitReport {
    pub fn new(
        disposition: ExitDisposition,
        flush_succeeded: bool,
        supervisor: SupervisorSettlement,
        cleanup: Option<EmergencyCleanupWitness>,
    ) -> Result<Self, ApplicationError> {
        if !supervisor.is_settled() {
            return Err(ApplicationError::ExitBeforeSupervisorSettlement);
        }
        Ok(Self {
            disposition,
            flush_succeeded,
            supervisor,
            cleanup,
        })
    }

    #[must_use]
    pub const fn disposition(&self) -> ExitDisposition {
        self.disposition
    }

    #[must_use]
    pub const fn flush_succeeded(&self) -> bool {
        self.flush_succeeded
    }

    #[must_use]
    pub const fn supervisor(&self) -> SupervisorSettlement {
        self.supervisor
    }

    #[must_use]
    pub fn cleanup(&self) -> Option<&EmergencyCleanupWitness> {
        self.cleanup.as_ref()
    }
}

/// Admits only a binary whose every durable-companion member is durable.
pub fn admit_durable_companion(
    target: TargetKind,
    members: &[ApplicationClass],
) -> Result<(), ApplicationError> {
    if target != TargetKind::Binary {
        return Err(ApplicationError::DurableCompanionNotBinary);
    }
    if members.is_empty()
        || members
            .iter()
            .any(|member| *member != ApplicationClass::Durable)
    {
        return Err(ApplicationError::DurableCompanionClosureRejected);
    }
    Ok(())
}

/// Pure coordinator for startup, stop admission closure, finalization, and exit order.
#[derive(Debug)]
pub struct ApplicationCoordinator {
    arrangement: LaunchArrangement,
    phase: ApplicationPhase,
    stop: StopCoordinator,
    finalization_progress: usize,
    hard_cancellation: Option<EmergencyCleanupWitness>,
}

impl ApplicationCoordinator {
    #[must_use]
    pub fn new(arrangement: LaunchArrangement) -> Self {
        Self {
            arrangement,
            phase: ApplicationPhase::Declared,
            stop: StopCoordinator::new(),
            finalization_progress: 0,
            hard_cancellation: None,
        }
    }

    #[must_use]
    pub const fn arrangement(&self) -> LaunchArrangement {
        self.arrangement
    }

    #[must_use]
    pub const fn phase(&self) -> ApplicationPhase {
        self.phase
    }

    #[must_use]
    pub fn stop(&self) -> &StopCoordinator {
        &self.stop
    }

    pub fn start(&mut self, entry: &ApplicationEntry) -> Result<(), ApplicationError> {
        if self.phase != ApplicationPhase::Declared || entry.mode() != SemanticMode::Application {
            return Err(ApplicationError::InvalidPhase);
        }
        self.phase = ApplicationPhase::Started;
        Ok(())
    }

    /// Maps either portable signal class to the single landed operator-signal path.
    pub fn translate_signal(
        &mut self,
        _signal: PortableSignalClass,
        policy: GracePolicy,
        at_us: u64,
    ) -> Result<(), ApplicationError> {
        if !matches!(
            self.phase,
            ApplicationPhase::Started | ApplicationPhase::AdmissionClosed
        ) {
            return Err(ApplicationError::InvalidPhase);
        }
        let policy = self.stop.request().map_or(policy, |held| held.grace());
        self.stop
            .request_stop(StopRequest::new(StopCause::OperatorSignal, policy, at_us))
            .map_err(|_| ApplicationError::StopRejected)?;
        self.phase = ApplicationPhase::AdmissionClosed;
        Ok(())
    }

    pub fn begin_finalization(&mut self) -> Result<(), ApplicationError> {
        if self.phase != ApplicationPhase::AdmissionClosed {
            return Err(ApplicationError::InvalidPhase);
        }
        self.phase = ApplicationPhase::Finalizing;
        self.finalization_progress = 1;
        Ok(())
    }

    /// Records the required final-flush attempt without changing the language outcome.
    pub fn record_final_flush(&mut self) -> Result<(), ApplicationError> {
        if self.phase != ApplicationPhase::Finalizing || self.finalization_progress != 1 {
            return Err(ApplicationError::InvalidPhase);
        }
        self.finalization_progress = 2;
        Ok(())
    }

    /// Records the applicable hard-cancellation transition before supervisor settlement.
    pub fn record_hard_cancellation(
        &mut self,
        cleanup: Option<EmergencyCleanupWitness>,
    ) -> Result<(), ApplicationError> {
        if self.phase != ApplicationPhase::Finalizing || self.finalization_progress != 2 {
            return Err(ApplicationError::InvalidPhase);
        }
        self.hard_cancellation = cleanup;
        self.finalization_progress = 3;
        Ok(())
    }

    pub fn settle(&mut self) -> Result<(), ApplicationError> {
        if self.phase != ApplicationPhase::Finalizing || self.finalization_progress != 3 {
            return Err(ApplicationError::InvalidPhase);
        }
        self.phase = ApplicationPhase::Settled;
        Ok(())
    }

    pub fn publish(&mut self, report: ExitReport) -> Result<ExitReport, ApplicationError> {
        if self.phase != ApplicationPhase::Settled
            || self.hard_cancellation.is_some() != report.cleanup().is_some()
        {
            return Err(ApplicationError::InvalidPhase);
        }
        let ExitReport {
            disposition,
            flush_succeeded,
            supervisor,
            cleanup: _,
        } = report;
        let report = ExitReport {
            disposition,
            flush_succeeded,
            supervisor,
            cleanup: self.hard_cancellation.take(),
        };
        self.phase = ApplicationPhase::Published;
        Ok(report)
    }
}

/// Frozen diagnostics emitted by this pure model.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ApplicationDiagnosticCode {
    CapabilityAmplification,
    DuplicateTargetEntry,
    DurableCompanionClosureRejected,
    ExitBeforeSupervisorSettlement,
    FuelExhausted,
    InvalidEntry,
    InvalidPhase,
    StaleFuelGeneration,
    YieldQuantumChanged,
}

impl ApplicationDiagnosticCode {
    pub const ALL: [Self; 9] = [
        Self::CapabilityAmplification,
        Self::DuplicateTargetEntry,
        Self::DurableCompanionClosureRejected,
        Self::ExitBeforeSupervisorSettlement,
        Self::FuelExhausted,
        Self::InvalidEntry,
        Self::InvalidPhase,
        Self::StaleFuelGeneration,
        Self::YieldQuantumChanged,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CapabilityAmplification => "application-capability-amplification",
            Self::DuplicateTargetEntry => "application-duplicate-target-entry",
            Self::DurableCompanionClosureRejected => {
                "application-durable-companion-closure-rejected"
            }
            Self::ExitBeforeSupervisorSettlement => "application-exit-before-supervisor-settlement",
            Self::FuelExhausted => "application-fuel-exhausted",
            Self::InvalidEntry => "application-invalid-entry",
            Self::InvalidPhase => "application-invalid-phase",
            Self::StaleFuelGeneration => "application-stale-fuel-generation",
            Self::YieldQuantumChanged => "application-yield-quantum-changed",
        }
    }
}

/// Typed refusal from the application declaration model.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplicationError {
    InvalidEntry,
    SnapshotLimitExceeded,
    DuplicateEnvironment,
    InvalidEnvironmentEntry,
    InvalidCwd,
    InvalidCapability,
    CapabilityAmplification,
    DuplicateTargetEntry,
    DuplicateStdioChannel,
    IncompleteStdio,
    InvalidFuelGrant,
    FuelExhausted,
    StaleFuelGeneration,
    YieldQuantumChanged,
    DurableCompanionNotBinary,
    DurableCompanionClosureRejected,
    ExitBeforeSupervisorSettlement,
    InvalidPhase,
    StopRejected,
}
