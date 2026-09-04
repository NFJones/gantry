//! Versioned logical evidence and authoritative recovery projection.

#[cfg(all(feature = "concurrent", feature = "durable"))]
mod concurrent;
mod execution_start;

#[cfg(all(feature = "concurrent", feature = "durable"))]
pub use concurrent::{
    ConcurrentDurableEvidenceV3, RecoveredConcurrentDurableStateV1,
    recover_concurrent_authoritative_prefix,
};
pub use execution_start::{
    DurableCancellationEvidenceV3, DurableExecutionStartV3, DurableExecutionStateV1,
    DurableRecoverySnapshotV3,
};

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use gantry_core::canonical_json::CanonicalJson;
use gantry_core::identity::ProtocolIdentity;
use gantry_core::portable::{HookFailureCategory, IdentityKind};
use gantry_core::strict_json::{JsonLimits, JsonNode, JsonNodeId, StrictJsonDocument};
use gantry_host::contracts::HookOutcomeV1;
use gantry_host::journal::{
    BatchLocalEvidenceId, JournalBatchV1, JournalContractError, JournalError,
    JournalEvidenceEnvelopeV1, JournalEvidenceReferenceV1, JournalPrefixV1, UnfinalizedEvidenceV1,
    validate_journal_prefix,
};
use gantry_ir::generated::RecoveryClass;
use gantry_ir::{MachineProgram, TypeDescriptor};

#[cfg(all(feature = "concurrent", feature = "durable"))]
use crate::ConcurrentDurableCheckpointError;
use crate::{
    CancellationReason, DURABLE_EVENT_DISPATCHED_KIND_V1, DURABLE_EVENT_OCCURRENCE_KIND_V1,
    DURABLE_EVENT_SETTLED_KIND_V1, DurableEventEvidenceError, DurableEventOccurrenceV1,
    DurableTransitionSink, ExecutionBudget, ExecutionBudgetSnapshot,
    LogicalSessionRegistryCheckpointV1, LogicalSessionRegistryV1, Machine, MachineCheckpointV3,
    MachineRecoveryError, MachineStatus, RecoveredDurableEventsV1, SessionRecoveryError,
    TransitionReceiptV1, TransitionSink, ValidationErrorCategoryV1, ValidationErrorV1,
};

/// Version-three evidence kind for complete concurrent-durable graph checkpoints.
#[cfg(all(feature = "concurrent", feature = "durable"))]
pub const CONCURRENT_DURABLE_EVIDENCE_KIND_V3: &str = "gantry.concurrent-durable-evidence/v3";

/// Exact semantic boundary represented by one durable logical evidence body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurableCommitCutV1 {
    /// A complete replay base for deterministic state.
    Checkpoint,
    /// One child task was durably created before executor submission.
    TaskCreation,
    /// One atomic join or detach ownership transition became durable.
    TaskOwnership,
    /// A physical operation dispatch was prepared before hook entry.
    OperationPrepared,
    /// A host-level operation outcome was retained before validation.
    OperationOutcome,
    /// A normalized logical result became durable before source consumption.
    OperationResult,
    /// A structured-output retry delay was fixed before sleeping.
    RetryWaiting,
    /// The first effective cancellation reason was fixed before signalling.
    Cancellation,
    /// One Gantry task settled before dependent observation.
    TaskSettlement,
    /// Foreground completion was fixed before returning its result.
    ForegroundCompletion,
    /// Terminal execution state was fixed before reporting it.
    TerminalCompletion,
}

impl DurableCommitCutV1 {
    /// Returns the exact version-one evidence spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Checkpoint => "checkpoint",
            Self::TaskCreation => "task-creation",
            Self::TaskOwnership => "task-ownership",
            Self::OperationPrepared => "operation-prepared",
            Self::OperationOutcome => "operation-outcome",
            Self::OperationResult => "operation-result",
            Self::RetryWaiting => "retry-waiting",
            Self::Cancellation => "cancellation",
            Self::TaskSettlement => "task-settlement",
            Self::ForegroundCompletion => "foreground-completion",
            Self::TerminalCompletion => "terminal-completion",
        }
    }

    const fn requires_operation(self) -> bool {
        matches!(
            self,
            Self::OperationPrepared
                | Self::OperationOutcome
                | Self::OperationResult
                | Self::RetryWaiting
        )
    }

    fn from_wire_name(value: &str) -> Option<Self> {
        match value {
            "checkpoint" => Some(Self::Checkpoint),
            "task-creation" => Some(Self::TaskCreation),
            "task-ownership" => Some(Self::TaskOwnership),
            "operation-prepared" => Some(Self::OperationPrepared),
            "operation-outcome" => Some(Self::OperationOutcome),
            "operation-result" => Some(Self::OperationResult),
            "retry-waiting" => Some(Self::RetryWaiting),
            "cancellation" => Some(Self::Cancellation),
            "task-settlement" => Some(Self::TaskSettlement),
            "foreground-completion" => Some(Self::ForegroundCompletion),
            "terminal-completion" => Some(Self::TerminalCompletion),
            _ => None,
        }
    }
}

/// Operation coordinates retained by an operation-related commit cut.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableOperationEvidenceV1 {
    /// Stable logical operation identity.
    pub operation_id: ProtocolIdentity,
    /// Physical dispatch identity, absent only after logical result acceptance.
    pub dispatch_id: Option<ProtocolIdentity>,
    /// Zero-based structured-output validation attempt.
    pub validation_attempt: u64,
    /// Zero-based recovery redispatch number.
    pub recovery_dispatch: u64,
    /// Selected retry delay, present only for retry-waiting evidence.
    pub retry_delay_us: Option<u64>,
    /// Remaining structured-output retries after the represented cut.
    pub retries_left: Option<u64>,
    /// Action recovery class; model operations leave this absent.
    pub action_recovery: Option<RecoveryClass>,
    /// Exact committed dispatch request bytes for prepared, outcome, and retry cuts.
    pub request_bytes: Option<Arc<[u8]>>,
    /// Exact committed host outcome, present only at the outcome cut.
    pub outcome: Option<HookOutcomeV1>,
    /// Validation errors retained by a retry-waiting cut.
    pub retry_errors: Arc<[ValidationErrorV1]>,
    /// Canonical result type, present only at the logical-result cut.
    pub result_type: Option<TypeDescriptor>,
    /// Normalized canonical JSON, present only at the logical-result cut.
    pub result_bytes: Option<Arc<[u8]>>,
}

/// One successfully committed semantic cut and its stable journal coordinates.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableEvidenceCommitV1 {
    /// Stable storage-assigned evidence identity.
    pub evidence_id: ProtocolIdentity,
    /// Contiguous authoritative journal sequence.
    pub sequence: u64,
    /// Exact semantic boundary established by this commit.
    pub cut: DurableCommitCutV1,
}

/// Serial causal commit boundary for one task in one fenced durable execution.
pub struct DurableCommitCoordinatorV1<'a> {
    sink: &'a DurableTransitionSink,
    execution_id: ProtocolIdentity,
    task_id: ProtocolIdentity,
    predecessor: Option<(ProtocolIdentity, u64)>,
    next_local_id: u64,
}

impl<'a> DurableCommitCoordinatorV1<'a> {
    /// Binds one task to a fenced sink and optional recovered predecessor.
    pub fn new(
        sink: &'a DurableTransitionSink,
        execution_id: ProtocolIdentity,
        task_id: ProtocolIdentity,
        predecessor: Option<(ProtocolIdentity, u64)>,
    ) -> Result<Self, DurableCommitError> {
        if execution_id.kind() != IdentityKind::Execution
            || task_id.kind() != IdentityKind::Task
            || predecessor.is_some_and(|(identity, sequence)| {
                identity.kind() != IdentityKind::Evidence || sequence == 0
            })
        {
            return Err(DurableCommitError::InvalidState);
        }
        Ok(Self {
            sink,
            execution_id,
            task_id,
            predecessor,
            next_local_id: 0,
        })
    }

    /// Atomically commits one validated cut before its dependent external boundary.
    pub async fn commit_cut(
        &mut self,
        cut: DurableCommitCutV1,
        operation: Option<DurableOperationEvidenceV1>,
        machine: &Machine,
        sessions: Option<&LogicalSessionRegistryV1>,
    ) -> Result<DurableEvidenceCommitV1, DurableCommitError> {
        let session_checkpoint = sessions.map(LogicalSessionRegistryV1::checkpoint);
        let evidence = DurableLogicalEvidenceV3::new_with_sessions(
            self.execution_id,
            self.task_id,
            cut,
            operation,
            machine,
            session_checkpoint,
        )
        .map_err(DurableCommitError::Evidence)?;
        self.commit_evidence(cut, evidence).await
    }

    /// Commits the first canonical cancellation reason before task signalling.
    pub async fn commit_cancellation(
        &mut self,
        reason: CancellationReason,
        machine: &Machine,
        sessions: Option<&LogicalSessionRegistryV1>,
    ) -> Result<DurableEvidenceCommitV1, DurableCommitError> {
        let evidence = DurableLogicalEvidenceV3::new_with_sessions(
            self.execution_id,
            self.task_id,
            DurableCommitCutV1::Cancellation,
            None,
            machine,
            sessions.map(LogicalSessionRegistryV1::checkpoint),
        )
        .map_err(DurableCommitError::Evidence)?;
        let cancellation = DurableCancellationEvidenceV3::new(reason, evidence)
            .map_err(DurableCommitError::Evidence)?;
        let local_number = self
            .next_local_id
            .checked_add(1)
            .ok_or(DurableCommitError::InvalidState)?;
        let local_id = BatchLocalEvidenceId::new(format!("cut-{local_number}"))
            .map_err(|_| DurableCommitError::InvalidState)?;
        let references = self
            .predecessor
            .map(|(identity, _)| JournalEvidenceReferenceV1::Existing(identity))
            .into_iter()
            .collect::<Vec<_>>();
        let body = cancellation
            .unfinalized(local_id.clone(), references)
            .map_err(DurableCommitError::Evidence)?;
        self.commit_body(
            DurableCommitCutV1::Cancellation,
            local_number,
            local_id,
            body,
        )
        .await
    }

    async fn commit_evidence(
        &mut self,
        cut: DurableCommitCutV1,
        evidence: DurableLogicalEvidenceV3,
    ) -> Result<DurableEvidenceCommitV1, DurableCommitError> {
        let local_number = self
            .next_local_id
            .checked_add(1)
            .ok_or(DurableCommitError::InvalidState)?;
        let local_id = BatchLocalEvidenceId::new(format!("cut-{local_number}"))
            .map_err(|_| DurableCommitError::InvalidState)?;
        let references = self
            .predecessor
            .map(|(identity, _)| JournalEvidenceReferenceV1::Existing(identity))
            .into_iter()
            .collect::<Vec<_>>();
        let body = evidence
            .unfinalized(local_id.clone(), references)
            .map_err(DurableCommitError::Evidence)?;
        self.commit_body(cut, local_number, local_id, body).await
    }

    async fn commit_body(
        &mut self,
        cut: DurableCommitCutV1,
        local_number: u64,
        local_id: BatchLocalEvidenceId,
        body: UnfinalizedEvidenceV1,
    ) -> Result<DurableEvidenceCommitV1, DurableCommitError> {
        let batch = JournalBatchV1::new(vec![body], Vec::new())
            .map_err(|_| DurableCommitError::InvalidState)?;
        let expected_sequence = self
            .predecessor
            .map_or(Some(1), |(_, sequence)| sequence.checked_add(1))
            .ok_or(DurableCommitError::InvalidState)?;
        let receipt = self
            .sink
            .record(batch)
            .await
            .map_err(DurableCommitError::Journal)?;
        let TransitionReceiptV1::Durable(receipt) = receipt else {
            return Err(DurableCommitError::InvalidReceipt);
        };
        let Some(entry) = receipt.entries.first() else {
            return Err(DurableCommitError::InvalidReceipt);
        };
        if receipt.first_sequence != expected_sequence
            || receipt.last_sequence != expected_sequence
            || receipt.entries.len() != 1
            || entry.sequence != expected_sequence
            || entry.batch_local_id != local_id
            || entry.evidence_id.kind() != IdentityKind::Evidence
        {
            return Err(DurableCommitError::InvalidReceipt);
        }
        self.predecessor = Some((entry.evidence_id, entry.sequence));
        self.next_local_id = local_number;
        Ok(DurableEvidenceCommitV1 {
            evidence_id: entry.evidence_id,
            sequence: entry.sequence,
            cut,
        })
    }
}

/// Failure before one semantic cut can become externally observable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DurableCommitError {
    /// Coordinator identities or recovered predecessor coordinates are invalid.
    InvalidState,
    /// Typed evidence and the supplied machine state disagree.
    Evidence(DurableEvidenceError),
    /// The fenced journal commit failed and coordinator state did not advance.
    Journal(JournalError),
    /// Storage returned a receipt that did not establish exactly the expected cut.
    InvalidReceipt,
}

/// Recovery action selected from the latest authoritative operation cut.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DurableOperationRecoveryV1 {
    /// No operation boundary remains to be resumed from this prefix.
    None,
    /// A prepared prompt, decision, read-only action, or idempotent action is indeterminate.
    Redispatch {
        /// Stable logical operation identity retained across redispatch.
        operation_id: ProtocolIdentity,
        /// Indeterminate physical dispatch from the committed prefix.
        previous_dispatch_id: ProtocolIdentity,
        /// Validation attempt retained independently of recovery dispatches.
        validation_attempt: u64,
        /// Recovery-dispatch number for the next physical attempt.
        next_recovery_dispatch: u64,
        /// Action recovery class; model operations leave this absent.
        action_recovery: Option<RecoveryClass>,
        /// Exact committed request reused except for physical redispatch fields.
        request_bytes: Arc<[u8]>,
    },
    /// An indeterminate non-idempotent action becomes the unknown-outcome path.
    UnknownOutcome {
        /// Stable logical operation identity.
        operation_id: ProtocolIdentity,
        /// Indeterminate physical dispatch that must not be repeated.
        dispatch_id: ProtocolIdentity,
        /// Exact committed non-idempotent request retained for diagnostics and result construction.
        request_bytes: Arc<[u8]>,
    },
    /// A committed host outcome is reused without redispatch.
    ReuseOutcome {
        /// Stable logical operation identity.
        operation_id: ProtocolIdentity,
        /// Physical dispatch whose committed outcome is retained.
        dispatch_id: ProtocolIdentity,
        /// Exact committed dispatch request bytes.
        request_bytes: Arc<[u8]>,
        /// Exact committed host-level outcome.
        outcome: HookOutcomeV1,
    },
    /// A committed normalized result is reused without validation or source consumption twice.
    ReuseResult {
        /// Stable logical operation identity.
        operation_id: ProtocolIdentity,
        /// Canonical result type retained by the result cut.
        result_type: TypeDescriptor,
        /// Normalized canonical JSON retained by the result cut.
        result_bytes: Arc<[u8]>,
    },
    /// A recorded retry delay is waited in full without resampling.
    RetryDelay {
        /// Stable logical operation identity.
        operation_id: ProtocolIdentity,
        /// Complete recorded delay in microseconds.
        delay_us: u64,
        /// Validation attempt for the next dispatch.
        validation_attempt: u64,
        /// Recovery-dispatch coordinate retained across the wait.
        recovery_dispatch: u64,
        /// Remaining validation retries after this wait was admitted.
        retries_left: Option<u64>,
        /// Exact committed dispatch request whose output failed validation.
        request_bytes: Arc<[u8]>,
        /// Exact committed host outcome processed into this retry wait.
        outcome: HookOutcomeV1,
        /// Canonical validation errors reused by the next dispatch.
        errors: Arc<[ValidationErrorV1]>,
    },
}

/// Result of projecting one authoritative journal prefix into the existing machine.
#[derive(Clone, Debug)]
pub struct RecoveredDurableStateV1 {
    machine: Machine,
    sessions: Option<LogicalSessionRegistryV1>,
    execution_start: Option<DurableExecutionStartV3>,
    execution_state: Option<DurableExecutionStateV1>,
    cancellation_reason: Option<CancellationReason>,
    events: RecoveredDurableEventsV1,
    latest_sequence: u64,
    latest_evidence_id: ProtocolIdentity,
    latest_cut: DurableCommitCutV1,
    operation_recovery: DurableOperationRecoveryV1,
}

impl RecoveredDurableStateV1 {
    /// Constructs the authoritative in-process projection immediately after sequence one commits.
    pub fn from_committed_start(
        execution_start: DurableExecutionStartV3,
        evidence_id: ProtocolIdentity,
        sequence: u64,
    ) -> Result<Self, DurableEvidenceError> {
        if sequence != 1 || evidence_id.kind() != IdentityKind::Evidence {
            return Err(DurableEvidenceError::InvalidCausalOrder);
        }
        let program = Arc::new(execution_start.program()?);
        let budget = ExecutionBudget::recover_from_checkpoint(execution_start.state().budget)
            .map_err(DurableEvidenceError::Checkpoint)?;
        let machine = Machine::recover_from_checkpoint(
            program,
            execution_start.state().checkpoint().clone(),
            budget,
        )
        .map_err(DurableEvidenceError::Checkpoint)?;
        let sessions = execution_start
            .state()
            .sessions()
            .cloned()
            .map(LogicalSessionRegistryV1::recover_from_checkpoint)
            .transpose()
            .map_err(DurableEvidenceError::Session)?;
        Ok(Self {
            machine,
            sessions,
            execution_start: Some(execution_start),
            execution_state: None,
            cancellation_reason: None,
            events: RecoveredDurableEventsV1::default(),
            latest_sequence: sequence,
            latest_evidence_id: evidence_id,
            latest_cut: DurableCommitCutV1::Checkpoint,
            operation_recovery: DurableOperationRecoveryV1::None,
        })
    }

    /// Returns the latest authoritative logical sequence represented by recovery.
    #[must_use]
    pub const fn latest_sequence(&self) -> u64 {
        self.latest_sequence
    }

    /// Returns the latest stable evidence identity represented by recovery.
    #[must_use]
    pub const fn latest_evidence_id(&self) -> ProtocolIdentity {
        self.latest_evidence_id
    }

    /// Returns the latest semantic commit cut represented by recovery.
    #[must_use]
    pub const fn latest_cut(&self) -> DurableCommitCutV1 {
        self.latest_cut
    }

    /// Returns the exact operation recovery action selected by the latest cut.
    #[must_use]
    pub const fn operation_recovery(&self) -> &DurableOperationRecoveryV1 {
        &self.operation_recovery
    }

    /// Returns recovered logical sessions and transcripts when evidence retained them.
    #[must_use]
    pub const fn sessions(&self) -> Option<&LogicalSessionRegistryV1> {
        self.sessions.as_ref()
    }

    /// Returns immutable sequence-one metadata when the prefix retained an execution start.
    #[must_use]
    pub const fn execution_start(&self) -> Option<&DurableExecutionStartV3> {
        self.execution_start.as_ref()
    }

    /// Returns the latest compatible execution-state revision retained by recovery.
    #[must_use]
    pub const fn execution_state(&self) -> Option<&DurableExecutionStateV1> {
        self.execution_state.as_ref()
    }

    /// Returns the first canonical cancellation reason committed by this execution.
    #[must_use]
    pub const fn cancellation_reason(&self) -> Option<&CancellationReason> {
        self.cancellation_reason.as_ref()
    }

    /// Returns the recovered journal-first event occurrences and sink obligations.
    #[must_use]
    pub const fn events(&self) -> &RecoveredDurableEventsV1 {
        &self.events
    }

    /// Returns the reconstructed existing evaluator for read-only durable observation.
    #[must_use]
    pub const fn machine(&self) -> &Machine {
        &self.machine
    }

    /// Returns the reconstructed evaluator for one journal-first durable transition.
    pub fn machine_mut(&mut self) -> &mut Machine {
        &mut self.machine
    }

    /// Returns reconstructed logical sessions for a journal-first durable transition.
    pub fn sessions_mut(&mut self) -> Option<&mut LogicalSessionRegistryV1> {
        self.sessions.as_mut()
    }

    /// Returns the mutable machine and session registry as one borrow for a durable commit.
    pub fn state_mut(&mut self) -> (&mut Machine, Option<&mut LogicalSessionRegistryV1>) {
        (&mut self.machine, self.sessions.as_mut())
    }

    /// Advances authoritative coordinates after a validated semantic commit.
    pub fn record_semantic_commit(
        &mut self,
        commit: &DurableEvidenceCommitV1,
    ) -> Result<(), DurableEvidenceError> {
        if commit.evidence_id.kind() != IdentityKind::Evidence
            || self.latest_sequence.checked_add(1) != Some(commit.sequence)
        {
            return Err(DurableEvidenceError::InvalidCausalOrder);
        }
        self.latest_sequence = commit.sequence;
        self.latest_evidence_id = commit.evidence_id;
        self.latest_cut = commit.cut;
        Ok(())
    }

    /// Retains the first reason after its cancellation evidence commits.
    pub fn record_cancellation_commit(
        &mut self,
        reason: CancellationReason,
        commit: &DurableEvidenceCommitV1,
    ) -> Result<(), DurableEvidenceError> {
        if commit.cut != DurableCommitCutV1::Cancellation || self.cancellation_reason.is_some() {
            return Err(DurableEvidenceError::RepeatedCancellation);
        }
        self.record_semantic_commit(commit)?;
        self.cancellation_reason = Some(reason);
        Ok(())
    }

    /// Advances recovery coordinates after one validated execution-state commit receipt.
    pub fn record_execution_state_commit(
        &mut self,
        state: DurableExecutionStateV1,
        evidence_id: ProtocolIdentity,
        sequence: u64,
    ) -> Result<(), DurableEvidenceError> {
        if state.execution_id() != self.machine.execution_id()
            || evidence_id.kind() != IdentityKind::Evidence
            || self.latest_sequence.checked_add(1) != Some(sequence)
        {
            return Err(DurableEvidenceError::InvalidExecutionState);
        }
        self.execution_state = Some(state);
        self.latest_evidence_id = evidence_id;
        self.latest_sequence = sequence;
        Ok(())
    }

    /// Consumes the projection and returns the reconstructed existing evaluator.
    #[must_use]
    pub fn into_machine(self) -> Machine {
        self.machine
    }

    /// Consumes the projection into the existing evaluator and recovered session registry.
    #[must_use]
    pub fn into_parts(self) -> (Machine, Option<LogicalSessionRegistryV1>) {
        (self.machine, self.sessions)
    }
}

/// Projects one validated authoritative full or snapshot prefix into the existing machine.
pub fn recover_authoritative_prefix(
    program: Arc<MachineProgram>,
    prefix: &JournalPrefixV1,
) -> Result<RecoveredDurableStateV1, DurableEvidenceError> {
    validate_journal_prefix(prefix).map_err(DurableEvidenceError::Journal)?;
    let mut projection = PrefixProjection::default();
    match prefix {
        JournalPrefixV1::Full(prefix) => {
            for envelope in prefix.evidence.iter() {
                projection.apply_envelope(&program, envelope)?;
            }
        }
        JournalPrefixV1::Snapshot(prefix) => {
            if prefix.frontier == 0 {
                return Err(DurableEvidenceError::MissingRecoveryState);
            }
            let frontier_id = prefix
                .retained_evidence
                .iter()
                .find_map(|(identity, sequence)| {
                    (*sequence == prefix.frontier).then_some(*identity)
                })
                .ok_or(DurableEvidenceError::InvalidCausalOrder)?;
            let evidence = if prefix.snapshot_version == 5 {
                DurableLogicalEvidenceV3::decode(&program, &prefix.canonical_snapshot)?
            } else if prefix.snapshot_version == 6 {
                let snapshot =
                    DurableRecoverySnapshotV3::decode(&program, &prefix.canonical_snapshot)?;
                projection.execution_start = Some(snapshot.execution_start().clone());
                projection.execution_state = snapshot.execution_state().cloned();
                snapshot.state().clone()
            } else {
                return Err(DurableEvidenceError::Encoding);
            };
            projection.apply_snapshot(
                prefix.frontier,
                frontier_id,
                prefix.retained_evidence.keys().copied(),
                evidence,
            )?;
            for envelope in prefix.suffix.iter() {
                projection.apply_envelope(&program, envelope)?;
            }
        }
    }
    projection.finish(program)
}

/// Recovers one authoritative prefix using the executable program retained by sequence one.
pub fn recover_authoritative_prefix_with_retained_program(
    prefix: &JournalPrefixV1,
) -> Result<(Arc<MachineProgram>, RecoveredDurableStateV1), DurableEvidenceError> {
    validate_journal_prefix(prefix).map_err(DurableEvidenceError::Journal)?;
    let program = Arc::new(match prefix {
        JournalPrefixV1::Full(prefix) => {
            let first = prefix
                .evidence
                .first()
                .ok_or(DurableEvidenceError::MissingRecoveryState)?;
            if first.sequence != 1 || first.kind.as_ref() != "gantry.execution-start/v3" {
                return Err(DurableEvidenceError::InvalidExecutionStart);
            }
            DurableExecutionStartV3::retained_program(&first.canonical_body)?
        }
        JournalPrefixV1::Snapshot(prefix) if prefix.snapshot_version == 6 => {
            DurableRecoverySnapshotV3::retained_program(&prefix.canonical_snapshot)?
        }
        JournalPrefixV1::Snapshot(_) => {
            return Err(DurableEvidenceError::MissingRecoveryState);
        }
    });
    let recovered = recover_authoritative_prefix(Arc::clone(&program), prefix)?;
    Ok((program, recovered))
}

#[derive(Default)]
struct PrefixProjection {
    latest: Option<(u64, ProtocolIdentity, DurableLogicalEvidenceV3)>,
    journal_tip: Option<(u64, ProtocolIdentity)>,
    execution_start: Option<DurableExecutionStartV3>,
    execution_state: Option<DurableExecutionStateV1>,
    committed_cancellation: Option<CancellationReason>,
    events: RecoveredDurableEventsV1,
    known: BTreeSet<ProtocolIdentity>,
    prepared_dispatches: BTreeSet<ProtocolIdentity>,
    latest_prepared: BTreeMap<ProtocolIdentity, ProtocolIdentity>,
    committed_outcomes: BTreeSet<ProtocolIdentity>,
    latest_outcomes: BTreeMap<ProtocolIdentity, ProtocolIdentity>,
    committed_results: BTreeSet<ProtocolIdentity>,
}

impl PrefixProjection {
    fn apply_snapshot(
        &mut self,
        sequence: u64,
        evidence_id: ProtocolIdentity,
        retained: impl IntoIterator<Item = ProtocolIdentity>,
        evidence: DurableLogicalEvidenceV3,
    ) -> Result<(), DurableEvidenceError> {
        self.record_operation_cut(&evidence, false)?;
        self.known.extend(retained);
        if !self.known.contains(&evidence_id) {
            return Err(DurableEvidenceError::InvalidCausalOrder);
        }
        self.latest = Some((sequence, evidence_id, evidence));
        self.journal_tip = Some((sequence, evidence_id));
        Ok(())
    }

    fn apply_envelope(
        &mut self,
        program: &MachineProgram,
        envelope: &JournalEvidenceEnvelopeV1,
    ) -> Result<(), DurableEvidenceError> {
        if self.latest.is_none() && envelope.kind.as_ref() == "gantry.execution-start/v3" {
            if self.journal_tip.is_some()
                || envelope.sequence != 1
                || !envelope.references.is_empty()
            {
                return Err(DurableEvidenceError::InvalidExecutionStart);
            }
            let start = DurableExecutionStartV3::decode(program, &envelope.canonical_body)?;
            let evidence = start.state().clone();
            self.record_operation_cut(&evidence, true)?;
            self.record_tip(envelope)?;
            self.execution_start = Some(start);
            self.latest = Some((envelope.sequence, envelope.evidence_id, evidence));
            return Ok(());
        }
        if matches!(
            envelope.kind.as_ref(),
            DURABLE_EVENT_OCCURRENCE_KIND_V1
                | DURABLE_EVENT_DISPATCHED_KIND_V1
                | DURABLE_EVENT_SETTLED_KIND_V1
        ) {
            let Some((_, _, previous)) = &self.latest else {
                return Err(DurableEvidenceError::InvalidCausalOrder);
            };
            self.require_predecessor(envelope)?;
            if envelope.kind.as_ref() == DURABLE_EVENT_OCCURRENCE_KIND_V1 {
                let occurrence = DurableEventOccurrenceV1::decode(&envelope.canonical_body)
                    .map_err(DurableEvidenceError::Event)?;
                if occurrence.event().execution_id() != Some(previous.execution_id()) {
                    return Err(DurableEvidenceError::MixedExecution);
                }
            }
            self.events
                .apply_envelope(envelope)
                .map_err(DurableEvidenceError::Event)?;
            self.record_tip(envelope)?;
            return Ok(());
        }
        if envelope.kind.as_ref() == "gantry.cancellation/v3" {
            let Some((_, _, previous)) = &self.latest else {
                return Err(DurableEvidenceError::InvalidCausalOrder);
            };
            self.require_predecessor(envelope)?;
            if self.committed_cancellation.is_some() {
                return Err(DurableEvidenceError::RepeatedCancellation);
            }
            let cancellation =
                DurableCancellationEvidenceV3::decode(program, &envelope.canonical_body)?;
            let evidence = cancellation.state().clone();
            if evidence.execution_id() != previous.execution_id()
                || evidence.task_id() != previous.task_id()
            {
                return Err(DurableEvidenceError::MixedExecution);
            }
            validate_budget_successor(&previous.budget, &evidence.budget)?;
            self.record_operation_cut(&evidence, true)?;
            self.record_tip(envelope)?;
            self.committed_cancellation = Some(cancellation.reason().clone());
            self.latest = Some((envelope.sequence, envelope.evidence_id, evidence));
            return Ok(());
        }
        if envelope.kind.as_ref() != "gantry.logical-evidence/v3" {
            if envelope.kind.as_ref() != "gantry.execution-state/v1" {
                return Err(DurableEvidenceError::UnsupportedEvidenceKind);
            }
            let Some((_, _, previous)) = &self.latest else {
                return Err(DurableEvidenceError::InvalidCausalOrder);
            };
            let previous = previous.clone();
            self.require_predecessor(envelope)?;
            let state = DurableExecutionStateV1::decode(&envelope.canonical_body)?;
            if state.execution_id() != previous.execution_id() {
                return Err(DurableEvidenceError::MixedExecution);
            }
            self.record_tip(envelope)?;
            self.execution_state = Some(state);
            self.latest = Some((envelope.sequence, envelope.evidence_id, previous));
            return Ok(());
        }
        if let Some((_, _, previous)) = &self.latest {
            self.require_predecessor(envelope)?;
            let evidence = DurableLogicalEvidenceV3::decode(program, &envelope.canonical_body)?;
            if evidence.execution_id != previous.execution_id
                || evidence.task_id != previous.task_id
            {
                return Err(DurableEvidenceError::MixedExecution);
            }
            validate_budget_successor(&previous.budget, &evidence.budget)?;
            self.record_operation_cut(&evidence, true)?;
            self.record_tip(envelope)?;
            self.latest = Some((envelope.sequence, envelope.evidence_id, evidence));
            return Ok(());
        }
        if !envelope.references.is_empty() {
            return Err(DurableEvidenceError::InvalidCausalOrder);
        }
        let evidence = DurableLogicalEvidenceV3::decode(program, &envelope.canonical_body)?;
        self.record_operation_cut(&evidence, true)?;
        self.record_tip(envelope)?;
        self.latest = Some((envelope.sequence, envelope.evidence_id, evidence));
        Ok(())
    }

    fn require_predecessor(
        &self,
        envelope: &JournalEvidenceEnvelopeV1,
    ) -> Result<(), DurableEvidenceError> {
        let Some((sequence, predecessor)) = self.journal_tip else {
            return Err(DurableEvidenceError::InvalidCausalOrder);
        };
        if sequence.checked_add(1) != Some(envelope.sequence)
            || !envelope.references.contains(&predecessor)
            || envelope
                .references
                .iter()
                .any(|reference| !self.known.contains(reference))
        {
            return Err(DurableEvidenceError::InvalidCausalOrder);
        }
        Ok(())
    }

    fn record_tip(
        &mut self,
        envelope: &JournalEvidenceEnvelopeV1,
    ) -> Result<(), DurableEvidenceError> {
        if !self.known.insert(envelope.evidence_id) {
            return Err(DurableEvidenceError::InvalidCausalOrder);
        }
        self.journal_tip = Some((envelope.sequence, envelope.evidence_id));
        Ok(())
    }

    fn record_operation_cut(
        &mut self,
        evidence: &DurableLogicalEvidenceV3,
        enforce_history: bool,
    ) -> Result<(), DurableEvidenceError> {
        let Some(operation) = evidence.operation.as_ref() else {
            return Ok(());
        };
        match evidence.cut {
            DurableCommitCutV1::OperationPrepared => {
                let dispatch = operation
                    .dispatch_id
                    .ok_or(DurableEvidenceError::InvalidOperation)?;
                if enforce_history && !self.prepared_dispatches.insert(dispatch) {
                    return Err(DurableEvidenceError::RepeatedOperationCut);
                }
                self.prepared_dispatches.insert(dispatch);
                self.latest_prepared
                    .insert(operation.operation_id, dispatch);
            }
            DurableCommitCutV1::OperationOutcome => {
                let dispatch = operation
                    .dispatch_id
                    .ok_or(DurableEvidenceError::InvalidOperation)?;
                if enforce_history
                    && self.latest_prepared.get(&operation.operation_id) != Some(&dispatch)
                {
                    return Err(DurableEvidenceError::InvalidOperationTransition);
                }
                if !self.committed_outcomes.insert(dispatch) {
                    return Err(DurableEvidenceError::RepeatedOperationCut);
                }
                self.latest_outcomes
                    .insert(operation.operation_id, dispatch);
            }
            DurableCommitCutV1::RetryWaiting => {
                let dispatch = operation
                    .dispatch_id
                    .ok_or(DurableEvidenceError::InvalidOperation)?;
                if enforce_history
                    && self.latest_outcomes.get(&operation.operation_id) != Some(&dispatch)
                {
                    return Err(DurableEvidenceError::InvalidOperationTransition);
                }
                self.latest_outcomes
                    .insert(operation.operation_id, dispatch);
            }
            DurableCommitCutV1::OperationResult => {
                if enforce_history && !self.latest_outcomes.contains_key(&operation.operation_id) {
                    return Err(DurableEvidenceError::InvalidOperationTransition);
                }
                if !self.committed_results.insert(operation.operation_id) {
                    return Err(DurableEvidenceError::RepeatedOperationCut);
                }
            }
            _ => return Err(DurableEvidenceError::InvalidOperation),
        }
        Ok(())
    }

    fn finish(
        self,
        program: Arc<MachineProgram>,
    ) -> Result<RecoveredDurableStateV1, DurableEvidenceError> {
        let (_, _, evidence) = self
            .latest
            .ok_or(DurableEvidenceError::MissingRecoveryState)?;
        let (latest_sequence, latest_evidence_id) = self
            .journal_tip
            .ok_or(DurableEvidenceError::MissingRecoveryState)?;
        let operation_recovery = operation_recovery(&evidence)?;
        let sessions = evidence
            .sessions
            .map(LogicalSessionRegistryV1::recover_from_checkpoint)
            .transpose()
            .map_err(DurableEvidenceError::Session)?;
        let budget = ExecutionBudget::recover_from_checkpoint(evidence.budget)
            .map_err(DurableEvidenceError::Checkpoint)?;
        let machine = Machine::recover_from_checkpoint(program, evidence.checkpoint, budget)
            .map_err(DurableEvidenceError::Checkpoint)?;
        Ok(RecoveredDurableStateV1 {
            machine,
            sessions,
            execution_start: self.execution_start,
            execution_state: self.execution_state,
            cancellation_reason: self.committed_cancellation,
            events: self.events,
            latest_sequence,
            latest_evidence_id,
            latest_cut: evidence.cut,
            operation_recovery,
        })
    }
}

pub(super) fn validate_budget_successor(
    previous: &ExecutionBudgetSnapshot,
    current: &ExecutionBudgetSnapshot,
) -> Result<(), DurableEvidenceError> {
    let transition_delta = previous
        .remaining_transitions
        .checked_sub(current.remaining_transitions);
    let operation_delta = previous
        .remaining_operations
        .checked_sub(current.remaining_operations);
    let consumed_delta = transition_delta
        .zip(operation_delta)
        .and_then(|(transitions, operations)| transitions.checked_add(operations));
    let revision_delta = current.revision.checked_sub(previous.revision);
    if current.execution != previous.execution
        || current.maximum_transitions != previous.maximum_transitions
        || current.maximum_operations != previous.maximum_operations
        || revision_delta.is_none()
        || revision_delta != consumed_delta
    {
        return Err(DurableEvidenceError::InvalidExecutionBudget);
    }
    Ok(())
}

fn operation_recovery(
    evidence: &DurableLogicalEvidenceV3,
) -> Result<DurableOperationRecoveryV1, DurableEvidenceError> {
    let Some(operation) = evidence.operation.as_ref() else {
        return Ok(DurableOperationRecoveryV1::None);
    };
    match evidence.cut {
        DurableCommitCutV1::OperationPrepared => {
            let dispatch_id = operation
                .dispatch_id
                .ok_or(DurableEvidenceError::InvalidOperation)?;
            if operation.action_recovery == Some(RecoveryClass::NonIdempotent) {
                return Ok(DurableOperationRecoveryV1::UnknownOutcome {
                    operation_id: operation.operation_id,
                    dispatch_id,
                    request_bytes: operation
                        .request_bytes
                        .clone()
                        .ok_or(DurableEvidenceError::InvalidOperation)?,
                });
            }
            let next_recovery_dispatch = operation
                .recovery_dispatch
                .checked_add(1)
                .ok_or(DurableEvidenceError::InvalidOperation)?;
            Ok(DurableOperationRecoveryV1::Redispatch {
                operation_id: operation.operation_id,
                previous_dispatch_id: dispatch_id,
                validation_attempt: operation.validation_attempt,
                next_recovery_dispatch,
                action_recovery: operation.action_recovery,
                request_bytes: operation
                    .request_bytes
                    .clone()
                    .ok_or(DurableEvidenceError::InvalidOperation)?,
            })
        }
        DurableCommitCutV1::OperationOutcome => Ok(DurableOperationRecoveryV1::ReuseOutcome {
            operation_id: operation.operation_id,
            dispatch_id: operation
                .dispatch_id
                .ok_or(DurableEvidenceError::InvalidOperation)?,
            request_bytes: operation
                .request_bytes
                .clone()
                .ok_or(DurableEvidenceError::InvalidOperation)?,
            outcome: operation
                .outcome
                .clone()
                .ok_or(DurableEvidenceError::InvalidOperation)?,
        }),
        DurableCommitCutV1::OperationResult => Ok(DurableOperationRecoveryV1::ReuseResult {
            operation_id: operation.operation_id,
            result_type: operation
                .result_type
                .clone()
                .ok_or(DurableEvidenceError::InvalidOperation)?,
            result_bytes: operation
                .result_bytes
                .clone()
                .ok_or(DurableEvidenceError::InvalidOperation)?,
        }),
        DurableCommitCutV1::RetryWaiting => Ok(DurableOperationRecoveryV1::RetryDelay {
            operation_id: operation.operation_id,
            delay_us: operation
                .retry_delay_us
                .ok_or(DurableEvidenceError::InvalidOperation)?,
            validation_attempt: operation.validation_attempt,
            recovery_dispatch: operation.recovery_dispatch,
            retries_left: operation.retries_left,
            request_bytes: operation
                .request_bytes
                .clone()
                .ok_or(DurableEvidenceError::InvalidOperation)?,
            outcome: operation
                .outcome
                .clone()
                .ok_or(DurableEvidenceError::InvalidOperation)?,
            errors: Arc::clone(&operation.retry_errors),
        }),
        _ => Err(DurableEvidenceError::InvalidOperation),
    }
}

/// One canonical version-three logical evidence body plus its recovery state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableLogicalEvidenceV3 {
    execution_id: ProtocolIdentity,
    task_id: ProtocolIdentity,
    cut: DurableCommitCutV1,
    operation: Option<DurableOperationEvidenceV1>,
    budget: ExecutionBudgetSnapshot,
    checkpoint: MachineCheckpointV3,
    sessions: Option<LogicalSessionRegistryCheckpointV1>,
}

impl DurableLogicalEvidenceV3 {
    /// Captures one validated commit-cut record over complete machine state.
    pub fn new(
        execution_id: ProtocolIdentity,
        task_id: ProtocolIdentity,
        cut: DurableCommitCutV1,
        operation: Option<DurableOperationEvidenceV1>,
        machine: &Machine,
    ) -> Result<Self, DurableEvidenceError> {
        Self::new_with_sessions(execution_id, task_id, cut, operation, machine, None)
    }

    /// Captures one commit-cut record with complete logical-session state.
    pub fn new_with_sessions(
        execution_id: ProtocolIdentity,
        task_id: ProtocolIdentity,
        cut: DurableCommitCutV1,
        operation: Option<DurableOperationEvidenceV1>,
        machine: &Machine,
        sessions: Option<LogicalSessionRegistryCheckpointV1>,
    ) -> Result<Self, DurableEvidenceError> {
        let checkpoint = machine.checkpoint();
        let budget = machine.budget_checkpoint();
        if machine.execution_id() != execution_id || budget.execution != execution_id {
            return Err(DurableEvidenceError::InvalidExecutionBudget);
        }
        Self::from_parts(
            execution_id,
            task_id,
            cut,
            operation,
            budget,
            checkpoint,
            sessions,
        )
    }

    fn from_parts(
        execution_id: ProtocolIdentity,
        task_id: ProtocolIdentity,
        cut: DurableCommitCutV1,
        operation: Option<DurableOperationEvidenceV1>,
        budget: ExecutionBudgetSnapshot,
        checkpoint: MachineCheckpointV3,
        sessions: Option<LogicalSessionRegistryCheckpointV1>,
    ) -> Result<Self, DurableEvidenceError> {
        if execution_id.kind() != IdentityKind::Execution
            || task_id.kind() != IdentityKind::Task
            || checkpoint.execution_id() != execution_id
            || budget.execution != execution_id
            || sessions
                .as_ref()
                .is_some_and(|sessions| sessions.execution_id() != execution_id)
            || cut.requires_operation() != operation.is_some()
        {
            return Err(DurableEvidenceError::InvalidState);
        }
        if let Some(operation) = &operation
            && (operation.operation_id.kind() != IdentityKind::Operation
                || operation
                    .dispatch_id
                    .is_some_and(|dispatch| dispatch.kind() != IdentityKind::Dispatch)
                || (cut == DurableCommitCutV1::OperationResult && operation.dispatch_id.is_some())
                || (cut != DurableCommitCutV1::OperationResult && operation.dispatch_id.is_none())
                || (cut == DurableCommitCutV1::RetryWaiting) != operation.retry_delay_us.is_some())
        {
            return Err(DurableEvidenceError::InvalidOperation);
        }
        if let Some(operation) = &operation {
            let request_expected = !matches!(cut, DurableCommitCutV1::OperationResult);
            let outcome_expected = matches!(
                cut,
                DurableCommitCutV1::OperationOutcome | DurableCommitCutV1::RetryWaiting
            );
            let retry_errors_expected = cut == DurableCommitCutV1::RetryWaiting;
            let result_expected = cut == DurableCommitCutV1::OperationResult;
            if request_expected != operation.request_bytes.is_some()
                || outcome_expected != operation.outcome.is_some()
                || retry_errors_expected == operation.retry_errors.is_empty()
                || result_expected != operation.result_type.is_some()
                || result_expected != operation.result_bytes.is_some()
                || operation
                    .request_bytes
                    .as_deref()
                    .is_some_and(|bytes| !is_canonical_json(bytes))
                || operation
                    .result_bytes
                    .as_deref()
                    .is_some_and(|bytes| !is_canonical_json(bytes))
                || operation
                    .retry_errors
                    .iter()
                    .any(|error| error.message.is_empty())
            {
                return Err(DurableEvidenceError::InvalidOperation);
            }
        }
        if let Some(operation) = &operation {
            let pending = checkpoint.pending_operation();
            if cut == DurableCommitCutV1::OperationResult {
                if pending.is_some_and(|pending| pending.identity == operation.operation_id) {
                    return Err(DurableEvidenceError::InvalidState);
                }
            } else if checkpoint.status() != MachineStatus::WaitingOperation
                || pending.map(|pending| pending.identity) != Some(operation.operation_id)
            {
                return Err(DurableEvidenceError::InvalidState);
            }
        }
        if cut == DurableCommitCutV1::Cancellation
            && checkpoint.cancellation_reason().is_none()
            && !matches!(checkpoint.status(), MachineStatus::Cancelled)
        {
            return Err(DurableEvidenceError::InvalidState);
        }
        if matches!(
            cut,
            DurableCommitCutV1::TaskSettlement
                | DurableCommitCutV1::ForegroundCompletion
                | DurableCommitCutV1::TerminalCompletion
        ) && checkpoint.outcome().is_none()
        {
            return Err(DurableEvidenceError::InvalidState);
        }
        Ok(Self {
            execution_id,
            task_id,
            cut,
            operation,
            budget,
            checkpoint,
            sessions,
        })
    }

    /// Returns the represented commit boundary.
    #[must_use]
    pub const fn cut(&self) -> DurableCommitCutV1 {
        self.cut
    }

    /// Returns the accepted execution represented by this evidence.
    #[must_use]
    pub const fn execution_id(&self) -> ProtocolIdentity {
        self.execution_id
    }

    /// Returns the task whose transition crossed the commit boundary.
    #[must_use]
    pub const fn task_id(&self) -> ProtocolIdentity {
        self.task_id
    }

    /// Returns operation coordinates for an operation-related cut.
    #[must_use]
    pub const fn operation(&self) -> Option<&DurableOperationEvidenceV1> {
        self.operation.as_ref()
    }

    /// Returns the canonical execution-wide budget projection captured with this cut.
    #[must_use]
    pub const fn budget(&self) -> ExecutionBudgetSnapshot {
        self.budget
    }

    /// Returns the complete same-machine recovery checkpoint.
    #[must_use]
    pub const fn checkpoint(&self) -> &MachineCheckpointV3 {
        &self.checkpoint
    }

    /// Returns complete logical-session recovery state when retained by this cut.
    #[must_use]
    pub const fn sessions(&self) -> Option<&LogicalSessionRegistryCheckpointV1> {
        self.sessions.as_ref()
    }

    /// Returns the unique canonical JSON body stored in a journal envelope.
    #[must_use]
    pub fn canonical_body(&self) -> Vec<u8> {
        let mut output = String::from("{\"budget\":");
        push_json_string(&mut output, &encode_hex(&self.budget.canonical_bytes()));
        output.push_str(",\"checkpoint\":");
        push_json_string(&mut output, &encode_hex(&self.checkpoint.canonical_bytes()));
        output.push_str(",\"cut\":");
        push_json_string(&mut output, self.cut.wire_name());
        output.push_str(",\"execution_id\":");
        push_json_string(&mut output, &self.execution_id.to_string());
        output.push_str(",\"format\":\"gantry.logical-evidence/v3\",\"operation\":");
        match &self.operation {
            Some(operation) => push_operation(&mut output, operation),
            None => output.push_str("null"),
        }
        output.push_str(",\"sessions\":");
        match &self.sessions {
            Some(sessions) => {
                push_json_string(&mut output, &encode_hex(&sessions.canonical_bytes()))
            }
            None => output.push_str("null"),
        }
        output.push_str(",\"task_id\":");
        push_json_string(&mut output, &self.task_id.to_string());
        output.push('}');
        output.into_bytes()
    }

    /// Decodes one exact canonical version-three evidence body.
    pub fn decode(program: &MachineProgram, body: &[u8]) -> Result<Self, DurableEvidenceError> {
        let maximum_bytes =
            u64::try_from(body.len()).map_err(|_| DurableEvidenceError::Encoding)?;
        let document = StrictJsonDocument::decode(
            body,
            JsonLimits {
                maximum_bytes,
                maximum_nesting_depth: maximum_bytes.max(1),
                maximum_nodes: maximum_bytes.max(1),
                maximum_string_scalars: maximum_bytes.max(1),
                maximum_list_items: maximum_bytes.max(1),
            },
        )
        .map_err(|_| DurableEvidenceError::Encoding)?;
        let root = object(&document, document.root())?;
        require_exact_fields(
            root,
            &[
                "budget",
                "checkpoint",
                "cut",
                "execution_id",
                "format",
                "operation",
                "sessions",
                "task_id",
            ],
        )?;
        if string(&document, field(root, "format")?)? != "gantry.logical-evidence/v3" {
            return Err(DurableEvidenceError::Encoding);
        }
        let budget = ExecutionBudgetSnapshot::decode(&decode_hex(string(
            &document,
            field(root, "budget")?,
        )?)?)
        .map_err(DurableEvidenceError::Checkpoint)?;
        let checkpoint_bytes = decode_hex(string(&document, field(root, "checkpoint")?)?)?;
        let checkpoint = MachineCheckpointV3::decode(program, &checkpoint_bytes)
            .map_err(DurableEvidenceError::Checkpoint)?;
        let cut = DurableCommitCutV1::from_wire_name(string(&document, field(root, "cut")?)?)
            .ok_or(DurableEvidenceError::Encoding)?;
        let execution_id = ProtocolIdentity::parse_kind(
            string(&document, field(root, "execution_id")?)?,
            IdentityKind::Execution,
        )
        .map_err(|_| DurableEvidenceError::Encoding)?;
        let task_id = ProtocolIdentity::parse_kind(
            string(&document, field(root, "task_id")?)?,
            IdentityKind::Task,
        )
        .map_err(|_| DurableEvidenceError::Encoding)?;
        let operation = optional_operation(&document, field(root, "operation")?)?;
        let sessions = optional_string(&document, field(root, "sessions")?)?
            .map(decode_hex)
            .transpose()?
            .map(|bytes| {
                LogicalSessionRegistryCheckpointV1::decode(&bytes, checkpoint.value_limits())
                    .map_err(DurableEvidenceError::Session)
            })
            .transpose()?;
        let execution_budget = ExecutionBudget::recover_from_checkpoint(budget)
            .map_err(DurableEvidenceError::Checkpoint)?;
        Machine::recover_from_checkpoint(
            Arc::new(program.clone()),
            checkpoint.clone(),
            execution_budget,
        )
        .map_err(DurableEvidenceError::Checkpoint)?;
        let evidence = Self::from_parts(
            execution_id,
            task_id,
            cut,
            operation,
            budget,
            checkpoint,
            sessions,
        )?;
        if evidence.canonical_body() != body {
            return Err(DurableEvidenceError::Encoding);
        }
        Ok(evidence)
    }

    /// Wraps this body for one atomic journal batch with ordered causal references.
    pub fn unfinalized(
        &self,
        batch_local_id: BatchLocalEvidenceId,
        references: impl Into<Arc<[JournalEvidenceReferenceV1]>>,
    ) -> Result<UnfinalizedEvidenceV1, DurableEvidenceError> {
        UnfinalizedEvidenceV1::new(
            batch_local_id,
            "gantry.logical-evidence/v3",
            self.canonical_body(),
            references,
            Arc::from([]),
        )
        .map_err(DurableEvidenceError::Journal)
    }
}

/// Rejection while constructing or projecting versioned logical evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DurableEvidenceError {
    /// The evidence body is malformed, noncanonical, or uses an unsupported version.
    Encoding,
    /// Durable event occurrence or delivery evidence is malformed or inconsistent.
    Event(DurableEventEvidenceError),
    /// Typed identities, cut kind, and checkpoint state disagree.
    InvalidState,
    /// Sequence-one metadata, identity, or embedded checkpoint state is inconsistent.
    InvalidExecutionStart,
    /// A mutable-policy or mapping execution-state revision is inconsistent.
    InvalidExecutionState,
    /// An execution-budget projection is malformed or discontinuous.
    InvalidExecutionBudget,
    /// Operation coordinates do not match the represented operation cut.
    InvalidOperation,
    /// The backend-neutral journal body contract rejected construction.
    Journal(JournalContractError),
    /// The embedded machine checkpoint is malformed or incompatible with the program.
    Checkpoint(MachineRecoveryError),
    /// Embedded logical-session descriptors or transcripts are malformed.
    Session(SessionRecoveryError),
    /// A composed concurrent-durable checkpoint is malformed or inconsistent.
    #[cfg(all(feature = "concurrent", feature = "durable"))]
    ConcurrentCheckpoint(ConcurrentDurableCheckpointError),
    /// The authoritative prefix contains no recoverable checkpoint state.
    MissingRecoveryState,
    /// One envelope uses a logical evidence kind not owned by this projection.
    UnsupportedEvidenceKind,
    /// Evidence references do not form a causally ordered predecessor chain.
    InvalidCausalOrder,
    /// One prefix mixes execution or task identities.
    MixedExecution,
    /// One operation cut lacks its required earlier committed boundary.
    InvalidOperationTransition,
    /// One dispatch outcome or logical result was committed more than once.
    RepeatedOperationCut,
    /// More than one cancellation transition appears in one authoritative prefix.
    RepeatedCancellation,
}

fn optional_operation(
    document: &StrictJsonDocument,
    id: JsonNodeId,
) -> Result<Option<DurableOperationEvidenceV1>, DurableEvidenceError> {
    if matches!(document.node(id), Some(JsonNode::Null)) {
        return Ok(None);
    }
    let value = object(document, id)?;
    require_exact_fields(
        value,
        &[
            "action_recovery",
            "dispatch_id",
            "operation_id",
            "outcome",
            "recovery_dispatch",
            "request_bytes",
            "result_bytes",
            "result_type",
            "retries_left",
            "retry_delay_us",
            "retry_errors",
            "validation_attempt",
        ],
    )?;
    let action_recovery = optional_string(document, field(value, "action_recovery")?)?
        .map(|value| match value {
            "read_only" => Ok(RecoveryClass::ReadOnly),
            "idempotent" => Ok(RecoveryClass::Idempotent),
            "non_idempotent" => Ok(RecoveryClass::NonIdempotent),
            _ => Err(DurableEvidenceError::Encoding),
        })
        .transpose()?;
    let dispatch_id = optional_string(document, field(value, "dispatch_id")?)?
        .map(|value| ProtocolIdentity::parse_kind(value, IdentityKind::Dispatch))
        .transpose()
        .map_err(|_| DurableEvidenceError::Encoding)?;
    let operation_id = ProtocolIdentity::parse_kind(
        string(document, field(value, "operation_id")?)?,
        IdentityKind::Operation,
    )
    .map_err(|_| DurableEvidenceError::Encoding)?;
    let request_bytes = optional_string(document, field(value, "request_bytes")?)?
        .map(decode_hex)
        .transpose()?
        .map(Arc::from);
    let outcome = optional_outcome(document, field(value, "outcome")?)?;
    let retry_errors = retry_errors(document, field(value, "retry_errors")?)?;
    let result_type = optional_string(document, field(value, "result_type")?)?
        .map(TypeDescriptor::from_canonical_string)
        .transpose()
        .map_err(|_| DurableEvidenceError::Encoding)?;
    let result_bytes = optional_string(document, field(value, "result_bytes")?)?
        .map(decode_hex)
        .transpose()?
        .map(Arc::from);
    Ok(Some(DurableOperationEvidenceV1 {
        operation_id,
        dispatch_id,
        validation_attempt: unsigned(document, field(value, "validation_attempt")?)?,
        recovery_dispatch: unsigned(document, field(value, "recovery_dispatch")?)?,
        retry_delay_us: optional_unsigned(document, field(value, "retry_delay_us")?)?,
        retries_left: optional_unsigned(document, field(value, "retries_left")?)?,
        action_recovery,
        request_bytes,
        outcome,
        retry_errors,
        result_type,
        result_bytes,
    }))
}

fn optional_outcome(
    document: &StrictJsonDocument,
    id: JsonNodeId,
) -> Result<Option<HookOutcomeV1>, DurableEvidenceError> {
    if matches!(document.node(id), Some(JsonNode::Null)) {
        return Ok(None);
    }
    let value = object(document, id)?;
    require_exact_fields(value, &["category", "kind", "payload"])?;
    let kind = string(document, field(value, "kind")?)?;
    let category = optional_string(document, field(value, "category")?)?;
    let payload = string(document, field(value, "payload")?)?;
    match kind {
        "completed" if category.is_none() => decode_hex(payload)
            .map(Arc::from)
            .map(HookOutcomeV1::Completed)
            .map(Some),
        "declined" if category.is_none() => Ok(Some(HookOutcomeV1::Declined(Arc::from(payload)))),
        "failed" => {
            let category = category
                .and_then(HookFailureCategory::from_wire_name)
                .ok_or(DurableEvidenceError::Encoding)?;
            Ok(Some(HookOutcomeV1::Failed {
                category,
                message: Arc::from(payload),
            }))
        }
        _ => Err(DurableEvidenceError::Encoding),
    }
}

fn retry_errors(
    document: &StrictJsonDocument,
    id: JsonNodeId,
) -> Result<Arc<[ValidationErrorV1]>, DurableEvidenceError> {
    let Some(JsonNode::Array(items)) = document.node(id) else {
        return Err(DurableEvidenceError::Encoding);
    };
    items
        .iter()
        .map(|item| {
            let value = object(document, *item)?;
            require_exact_fields(
                value,
                &[
                    "category",
                    "instance_location",
                    "message",
                    "schema_location",
                ],
            )?;
            let category = ValidationErrorCategoryV1::from_wire_name(string(
                document,
                field(value, "category")?,
            )?)
            .ok_or(DurableEvidenceError::Encoding)?;
            Ok(ValidationErrorV1 {
                category,
                instance_location: optional_string(document, field(value, "instance_location")?)?
                    .map(Arc::from),
                message: Arc::from(string(document, field(value, "message")?)?),
                schema_location: optional_string(document, field(value, "schema_location")?)?
                    .map(Arc::from),
            })
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Arc::from)
}

fn object(
    document: &StrictJsonDocument,
    id: JsonNodeId,
) -> Result<&[(Arc<str>, JsonNodeId)], DurableEvidenceError> {
    match document.node(id) {
        Some(JsonNode::Object(value)) => Ok(value),
        _ => Err(DurableEvidenceError::Encoding),
    }
}

fn require_exact_fields(
    object: &[(Arc<str>, JsonNodeId)],
    expected: &[&str],
) -> Result<(), DurableEvidenceError> {
    if object.len() == expected.len()
        && expected
            .iter()
            .all(|expected| object.iter().any(|(name, _)| name.as_ref() == *expected))
    {
        Ok(())
    } else {
        Err(DurableEvidenceError::Encoding)
    }
}

fn field(
    object: &[(Arc<str>, JsonNodeId)],
    name: &str,
) -> Result<JsonNodeId, DurableEvidenceError> {
    object
        .iter()
        .find_map(|(candidate, value)| (candidate.as_ref() == name).then_some(*value))
        .ok_or(DurableEvidenceError::Encoding)
}

fn string(document: &StrictJsonDocument, id: JsonNodeId) -> Result<&str, DurableEvidenceError> {
    match document.node(id) {
        Some(JsonNode::String(value)) => Ok(value),
        _ => Err(DurableEvidenceError::Encoding),
    }
}

fn optional_string(
    document: &StrictJsonDocument,
    id: JsonNodeId,
) -> Result<Option<&str>, DurableEvidenceError> {
    match document.node(id) {
        Some(JsonNode::Null) => Ok(None),
        Some(JsonNode::String(value)) => Ok(Some(value)),
        _ => Err(DurableEvidenceError::Encoding),
    }
}

fn unsigned(document: &StrictJsonDocument, id: JsonNodeId) -> Result<u64, DurableEvidenceError> {
    match document.node(id) {
        Some(JsonNode::Number(value)) => value
            .to_gantry_int()
            .ok()
            .and_then(|value| u64::try_from(value).ok())
            .ok_or(DurableEvidenceError::Encoding),
        _ => Err(DurableEvidenceError::Encoding),
    }
}

fn optional_unsigned(
    document: &StrictJsonDocument,
    id: JsonNodeId,
) -> Result<Option<u64>, DurableEvidenceError> {
    if matches!(document.node(id), Some(JsonNode::Null)) {
        Ok(None)
    } else {
        unsigned(document, id).map(Some)
    }
}

fn decode_hex(value: &str) -> Result<Vec<u8>, DurableEvidenceError> {
    if !value.len().is_multiple_of(2) {
        return Err(DurableEvidenceError::Encoding);
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let high = decode_nibble(pair[0])?;
            let low = decode_nibble(pair[1])?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn decode_nibble(value: u8) -> Result<u8, DurableEvidenceError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(DurableEvidenceError::Encoding),
    }
}

fn push_operation(output: &mut String, operation: &DurableOperationEvidenceV1) {
    output.push_str("{\"action_recovery\":");
    push_optional_string(
        output,
        operation.action_recovery.map(RecoveryClass::wire_name),
    );
    output.push_str(",\"dispatch_id\":");
    let dispatch = operation.dispatch_id.map(|identity| identity.to_string());
    push_optional_string(output, dispatch.as_deref());
    output.push_str(",\"operation_id\":");
    push_json_string(output, &operation.operation_id.to_string());
    output.push_str(",\"outcome\":");
    push_optional_outcome(output, operation.outcome.as_ref());
    output.push_str(",\"recovery_dispatch\":");
    output.push_str(&operation.recovery_dispatch.to_string());
    output.push_str(",\"request_bytes\":");
    push_optional_hex(output, operation.request_bytes.as_deref());
    output.push_str(",\"result_bytes\":");
    push_optional_hex(output, operation.result_bytes.as_deref());
    output.push_str(",\"result_type\":");
    let result_type = operation
        .result_type
        .as_ref()
        .map(TypeDescriptor::canonical_string);
    push_optional_string(output, result_type.as_deref());
    output.push_str(",\"retries_left\":");
    push_optional_u64(output, operation.retries_left);
    output.push_str(",\"retry_delay_us\":");
    push_optional_u64(output, operation.retry_delay_us);
    output.push_str(",\"retry_errors\":[");
    push_retry_errors(output, &operation.retry_errors);
    output.push(']');
    output.push_str(",\"validation_attempt\":");
    output.push_str(&operation.validation_attempt.to_string());
    output.push('}');
}

fn push_optional_outcome(output: &mut String, outcome: Option<&HookOutcomeV1>) {
    let Some(outcome) = outcome else {
        output.push_str("null");
        return;
    };
    output.push_str("{\"category\":");
    match outcome {
        HookOutcomeV1::Failed { category, .. } => push_json_string(output, category.wire_name()),
        HookOutcomeV1::Completed(_) | HookOutcomeV1::Declined(_) => output.push_str("null"),
    }
    output.push_str(",\"kind\":");
    let (kind, payload) = match outcome {
        HookOutcomeV1::Completed(bytes) => ("completed", encode_hex(bytes)),
        HookOutcomeV1::Declined(reason) => ("declined", reason.to_string()),
        HookOutcomeV1::Failed { message, .. } => ("failed", message.to_string()),
    };
    push_json_string(output, kind);
    output.push_str(",\"payload\":");
    push_json_string(output, &payload);
    output.push('}');
}

fn push_retry_errors(output: &mut String, errors: &[ValidationErrorV1]) {
    for (index, error) in errors.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        output.push_str("{\"category\":");
        push_json_string(output, error.category.wire_name());
        output.push_str(",\"instance_location\":");
        push_optional_string(output, error.instance_location.as_deref());
        output.push_str(",\"message\":");
        push_json_string(output, &error.message);
        output.push_str(",\"schema_location\":");
        push_optional_string(output, error.schema_location.as_deref());
        output.push('}');
    }
}

fn push_optional_hex(output: &mut String, value: Option<&[u8]>) {
    match value {
        Some(value) => push_json_string(output, &encode_hex(value)),
        None => output.push_str("null"),
    }
}

fn is_canonical_json(bytes: &[u8]) -> bool {
    let Ok(maximum_bytes) = u64::try_from(bytes.len()) else {
        return false;
    };
    StrictJsonDocument::decode(
        bytes,
        JsonLimits {
            maximum_bytes,
            maximum_nesting_depth: maximum_bytes.max(1),
            maximum_nodes: maximum_bytes.max(1),
            maximum_string_scalars: maximum_bytes.max(1),
            maximum_list_items: maximum_bytes.max(1),
        },
    )
    .ok()
    .and_then(|document| CanonicalJson::from_document(&document).ok())
    .is_some_and(|canonical| canonical.bytes() == bytes)
}

fn push_optional_string(output: &mut String, value: Option<&str>) {
    match value {
        Some(value) => push_json_string(output, value),
        None => output.push_str("null"),
    }
}

fn push_optional_u64(output: &mut String, value: Option<u64>) {
    match value {
        Some(value) => output.push_str(&value.to_string()),
        None => output.push_str("null"),
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

fn push_json_string(output: &mut String, value: &str) {
    output.push('"');
    for scalar in value.chars() {
        match scalar {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{08}' => output.push_str("\\b"),
            '\u{09}' => output.push_str("\\t"),
            '\n' => output.push_str("\\n"),
            '\u{0c}' => output.push_str("\\f"),
            '\r' => output.push_str("\\r"),
            value if value <= '\u{1f}' => output.push_str(&format!("\\u{:04x}", value as u32)),
            value => output.push(value),
        }
    }
    output.push('"');
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use gantry_core::identity::ProtocolIdentity;
    use gantry_core::portable::IdentityKind;
    use gantry_core::value::{DEFAULT_VALUE_LIMITS, LogicalValue};
    use gantry_host::contracts::HookOutcomeV1;
    use gantry_host::journal::{
        FullJournalPrefixV1, JournalEvidenceEnvelopeV1, JournalId, JournalPrefixV1,
        SnapshotJournalPrefixV1,
    };
    use gantry_ir::generated::RecoveryClass;
    use gantry_ir::{
        CanonicalPath, EffectSet, Instruction, InstructionKind, MachineProgram, StructuralPosition,
        TypeDescriptor, Workflow,
    };

    use super::{
        DurableCommitCutV1, DurableEvidenceError, DurableExecutionStartV3,
        DurableLogicalEvidenceV3, DurableOperationEvidenceV1, DurableOperationRecoveryV1,
        DurableRecoverySnapshotV3, recover_authoritative_prefix,
        recover_authoritative_prefix_with_retained_program, validate_budget_successor,
    };
    use crate::{
        CanonicalTranscriptV1, LogicalSessionRegistryV1, Machine, MachineLimits, MachineOutcome,
        MachineStep, SessionCreationModeV1, ValidationErrorCategoryV1, ValidationErrorV1,
    };

    #[test]
    fn full_and_snapshot_prefixes_recover_equivalent_machine_state() {
        let program = value_program();
        let mut machine = machine(Arc::clone(&program));
        assert!(matches!(machine.step(), MachineStep::Transition(_)));
        let evidence = evidence(&machine, DurableCommitCutV1::Checkpoint, None);
        let first = envelope(1, 1, &evidence, &[]);
        let full = JournalPrefixV1::Full(FullJournalPrefixV1 {
            journal_id: journal_id(),
            evidence: Arc::from([first.clone()]),
            committed_through: 1,
        });
        let snapshot = JournalPrefixV1::Snapshot(SnapshotJournalPrefixV1 {
            journal_id: journal_id(),
            snapshot_version: 5,
            frontier: 1,
            canonical_snapshot: Arc::from(evidence.canonical_body()),
            retained_evidence: BTreeMap::from([(first.evidence_id, 1)]),
            suffix: Arc::from([]),
            committed_through: 1,
        });

        let full = recover_authoritative_prefix(Arc::clone(&program), &full)
            .unwrap_or_else(|error| panic!("full recovery failed: {error:?}"));
        let compacted = recover_authoritative_prefix(program, &snapshot)
            .unwrap_or_else(|error| panic!("snapshot recovery failed: {error:?}"));
        assert_eq!(full.latest_sequence(), compacted.latest_sequence());
        assert_eq!(full.latest_cut(), DurableCommitCutV1::Checkpoint);
        assert_eq!(full.operation_recovery(), &DurableOperationRecoveryV1::None);
        assert_eq!(
            compacted.operation_recovery(),
            &DurableOperationRecoveryV1::None
        );
        assert_eq!(drive(full.into_machine()), drive(compacted.into_machine()));
    }

    #[test]
    fn retained_start_snapshot_recovers_program_metadata_and_latest_machine() {
        let program = value_program();
        let mut machine = machine(Arc::clone(&program));
        assert!(matches!(machine.step(), MachineStep::Transition(_)));
        let state = evidence(&machine, DurableCommitCutV1::Checkpoint, None);
        let execution_start = DurableExecutionStartV3::new(
            execution(),
            root_task(),
            &program,
            Arc::<[u8]>::from(&b"{}"[..]),
            state.clone(),
        )
        .unwrap_or_else(|error| panic!("execution start failed: {error:?}"));
        let snapshot = DurableRecoverySnapshotV3::new(execution_start, state)
            .unwrap_or_else(|error| panic!("retained snapshot failed: {error:?}"));
        let prefix = JournalPrefixV1::Snapshot(SnapshotJournalPrefixV1 {
            journal_id: journal_id(),
            snapshot_version: 6,
            frontier: 1,
            canonical_snapshot: Arc::from(snapshot.canonical_body()),
            retained_evidence: BTreeMap::from([(evidence_id(1), 1)]),
            suffix: Arc::from([]),
            committed_through: 1,
        });

        let (retained_program, recovered) =
            recover_authoritative_prefix_with_retained_program(&prefix)
                .unwrap_or_else(|error| panic!("retained recovery failed: {error:?}"));
        assert_eq!(retained_program.as_ref(), program.as_ref());
        assert_eq!(
            recovered
                .execution_start()
                .map(DurableExecutionStartV3::metadata),
            Some(&b"{}"[..])
        );
        assert_eq!(recovered.latest_sequence(), 1);
        assert_eq!(drive(recovered.into_machine()), drive(machine));
    }

    #[test]
    fn recovery_restores_logical_sessions_with_the_same_machine_checkpoint() {
        let program = value_program();
        let mut machine = machine(Arc::clone(&program));
        assert!(matches!(machine.step(), MachineStep::Transition(_)));
        let root_session = fresh(IdentityKind::Session, 7);
        let sessions = LogicalSessionRegistryV1::new(
            execution(),
            root_session,
            SessionCreationModeV1::GantryRoot,
            CanonicalTranscriptV1::empty(),
        )
        .unwrap_or_else(|error| panic!("session registry failed: {error:?}"));
        let evidence = DurableLogicalEvidenceV3::new_with_sessions(
            execution(),
            root_task(),
            DurableCommitCutV1::Checkpoint,
            None,
            &machine,
            Some(sessions.checkpoint()),
        )
        .unwrap_or_else(|error| panic!("session evidence failed: {error:?}"));
        let prefix = JournalPrefixV1::Full(FullJournalPrefixV1 {
            journal_id: journal_id(),
            evidence: Arc::from([envelope(1, 1, &evidence, &[])]),
            committed_through: 1,
        });

        let recovered = recover_authoritative_prefix(program, &prefix)
            .unwrap_or_else(|error| panic!("session recovery failed: {error:?}"));
        let recovered_sessions = recovered
            .sessions()
            .unwrap_or_else(|| panic!("session checkpoint was omitted"));
        assert_eq!(
            recovered_sessions
                .get(root_session)
                .map(|session| session.transcript.bytes()),
            Some(CanonicalTranscriptV1::empty().bytes())
        );
        let (_, sessions) = recovered.into_parts();
        assert!(sessions.is_some());
    }

    #[test]
    fn operation_commit_cuts_select_exact_recovery_without_reconsumption() {
        let program = operation_program();
        let mut machine = machine(Arc::clone(&program));
        let occurrence = match machine.step() {
            MachineStep::Transition(crate::MachineLabel::OperationPrepared(occurrence)) => {
                occurrence
            }
            other => panic!("operation was not prepared: {other:?}"),
        };
        let dispatch = fresh(IdentityKind::Dispatch, 9);
        let prepared = operation_evidence(
            &machine,
            occurrence.identity,
            Some(dispatch),
            DurableCommitCutV1::OperationPrepared,
            Some(RecoveryClass::ReadOnly),
            None,
        );
        let prepared_envelope = envelope(1, 1, &prepared, &[]);
        let prepared_prefix = JournalPrefixV1::Full(FullJournalPrefixV1 {
            journal_id: journal_id(),
            evidence: Arc::from([prepared_envelope.clone()]),
            committed_through: 1,
        });
        let recovered = recover_authoritative_prefix(Arc::clone(&program), &prepared_prefix)
            .unwrap_or_else(|error| panic!("prepared recovery failed: {error:?}"));
        assert_eq!(
            recovered.operation_recovery(),
            &DurableOperationRecoveryV1::Redispatch {
                operation_id: occurrence.identity,
                previous_dispatch_id: dispatch,
                validation_attempt: 0,
                next_recovery_dispatch: 1,
                action_recovery: Some(RecoveryClass::ReadOnly),
                request_bytes: Arc::from(&b"{}"[..]),
            }
        );

        let non_idempotent = operation_evidence(
            &machine,
            occurrence.identity,
            Some(dispatch),
            DurableCommitCutV1::OperationPrepared,
            Some(RecoveryClass::NonIdempotent),
            None,
        );
        let unknown_prefix = JournalPrefixV1::Full(FullJournalPrefixV1 {
            journal_id: journal_id(),
            evidence: Arc::from([envelope(1, 1, &non_idempotent, &[])]),
            committed_through: 1,
        });
        let recovered = recover_authoritative_prefix(Arc::clone(&program), &unknown_prefix)
            .unwrap_or_else(|error| panic!("unknown-outcome recovery failed: {error:?}"));
        assert_eq!(
            recovered.operation_recovery(),
            &DurableOperationRecoveryV1::UnknownOutcome {
                operation_id: occurrence.identity,
                dispatch_id: dispatch,
                request_bytes: Arc::from(&b"{}"[..]),
            }
        );

        let outcome = operation_evidence(
            &machine,
            occurrence.identity,
            Some(dispatch),
            DurableCommitCutV1::OperationOutcome,
            Some(RecoveryClass::ReadOnly),
            None,
        );
        let outcome_envelope = envelope(2, 2, &outcome, &[prepared_envelope.evidence_id]);
        let retry = operation_evidence(
            &machine,
            occurrence.identity,
            Some(dispatch),
            DurableCommitCutV1::RetryWaiting,
            Some(RecoveryClass::ReadOnly),
            Some(17),
        );
        let retry_prefix = JournalPrefixV1::Full(FullJournalPrefixV1 {
            journal_id: journal_id(),
            evidence: Arc::from([
                prepared_envelope.clone(),
                outcome_envelope.clone(),
                envelope(3, 3, &retry, &[outcome_envelope.evidence_id]),
            ]),
            committed_through: 3,
        });
        let recovered = recover_authoritative_prefix(Arc::clone(&program), &retry_prefix)
            .unwrap_or_else(|error| panic!("retry recovery failed: {error:?}"));
        assert_eq!(
            recovered.operation_recovery(),
            &DurableOperationRecoveryV1::RetryDelay {
                operation_id: occurrence.identity,
                delay_us: 17,
                validation_attempt: 0,
                recovery_dispatch: 0,
                retries_left: Some(2),
                request_bytes: Arc::from(&b"{}"[..]),
                outcome: HookOutcomeV1::Completed(Arc::from(&b"invalid"[..])),
                errors: Arc::from([ValidationErrorV1 {
                    category: ValidationErrorCategoryV1::Schema,
                    instance_location: Some(Arc::from("/value")),
                    message: Arc::from("invalid value"),
                    schema_location: Some(Arc::from("/type")),
                }]),
            }
        );

        machine
            .complete_operation(occurrence.identity, LogicalValue::unit())
            .unwrap_or_else(|error| panic!("operation completion failed: {error:?}"));
        let result = operation_evidence(
            &machine,
            occurrence.identity,
            None,
            DurableCommitCutV1::OperationResult,
            Some(RecoveryClass::ReadOnly),
            None,
        );
        let result_prefix = JournalPrefixV1::Full(FullJournalPrefixV1 {
            journal_id: journal_id(),
            evidence: Arc::from([
                prepared_envelope,
                outcome_envelope.clone(),
                envelope(3, 4, &result, &[outcome_envelope.evidence_id]),
            ]),
            committed_through: 3,
        });
        let recovered = recover_authoritative_prefix(program, &result_prefix)
            .unwrap_or_else(|error| panic!("result recovery failed: {error:?}"));
        assert_eq!(
            recovered.operation_recovery(),
            &DurableOperationRecoveryV1::ReuseResult {
                operation_id: occurrence.identity,
                result_type: TypeDescriptor::UNIT,
                result_bytes: Arc::from(&b"null"[..]),
            }
        );
        assert_eq!(
            drive(recovered.into_machine()),
            MachineOutcome::Succeeded(LogicalValue::unit())
        );
    }

    #[test]
    fn recovery_rejects_corrupt_bodies_and_invalid_operation_order() {
        let program = operation_program();
        let mut machine = machine(Arc::clone(&program));
        let occurrence = match machine.step() {
            MachineStep::Transition(crate::MachineLabel::OperationPrepared(occurrence)) => {
                occurrence
            }
            other => panic!("operation was not prepared: {other:?}"),
        };
        let dispatch = fresh(IdentityKind::Dispatch, 10);
        let outcome = operation_evidence(
            &machine,
            occurrence.identity,
            Some(dispatch),
            DurableCommitCutV1::OperationOutcome,
            None,
            None,
        );
        let invalid_order = JournalPrefixV1::Full(FullJournalPrefixV1 {
            journal_id: journal_id(),
            evidence: Arc::from([envelope(1, 1, &outcome, &[])]),
            committed_through: 1,
        });
        assert_eq!(
            recover_authoritative_prefix(Arc::clone(&program), &invalid_order).map(|_| ()),
            Err(DurableEvidenceError::InvalidOperationTransition)
        );

        let checkpoint = evidence(&machine, DurableCommitCutV1::Checkpoint, None);
        let mut corrupt = checkpoint.canonical_body();
        let marker = b"\"checkpoint\":\"";
        let index = corrupt
            .windows(marker.len())
            .position(|window| window == marker)
            .map(|index| index + marker.len())
            .unwrap_or_else(|| panic!("checkpoint hex field missing"));
        corrupt[index] = if corrupt[index] == b'0' { b'1' } else { b'0' };
        let envelope = JournalEvidenceEnvelopeV1 {
            journal_id: journal_id(),
            sequence: 1,
            evidence_id: evidence_id(1),
            kind: Arc::from("gantry.logical-evidence/v3"),
            canonical_body: Arc::from(corrupt),
            references: Arc::from([]),
            protected_payloads: Arc::from([]),
        };
        let corrupt_prefix = JournalPrefixV1::Full(FullJournalPrefixV1 {
            journal_id: journal_id(),
            evidence: Arc::from([envelope]),
            committed_through: 1,
        });
        assert!(matches!(
            recover_authoritative_prefix(program, &corrupt_prefix),
            Err(DurableEvidenceError::Encoding | DurableEvidenceError::Checkpoint(_))
        ));
    }

    #[test]
    fn recovery_preserves_latest_budget_after_sequential_charges() {
        let program = value_program();
        let mut machine = machine(Arc::clone(&program));
        let first = evidence(&machine, DurableCommitCutV1::Checkpoint, None);
        let first_envelope = envelope(1, 1, &first, &[]);

        assert!(matches!(machine.step(), MachineStep::Transition(_)));
        let latest = evidence(&machine, DurableCommitCutV1::Checkpoint, None);
        assert!(latest.budget().revision > first.budget().revision);
        let expected_budget = latest.budget();
        let prefix = JournalPrefixV1::Full(FullJournalPrefixV1 {
            journal_id: journal_id(),
            evidence: Arc::from([
                first_envelope.clone(),
                envelope(2, 2, &latest, &[first_envelope.evidence_id]),
            ]),
            committed_through: 2,
        });

        let recovered = recover_authoritative_prefix(program, &prefix)
            .unwrap_or_else(|error| panic!("sequential budget recovery failed: {error:?}"));
        assert_eq!(recovered.machine().budget_checkpoint(), expected_budget);
    }

    #[test]
    fn budget_successor_validation_covers_continuity_and_each_regression_class() {
        let program = value_program();
        let mut machine = machine(program);
        let initial = machine.budget_checkpoint();
        assert!(matches!(machine.step(), MachineStep::Transition(_)));
        let charged = machine.budget_checkpoint();

        assert_eq!(validate_budget_successor(&initial, &charged), Ok(()));

        let mut replenished = charged;
        replenished.remaining_transitions += 1;
        assert_eq!(
            validate_budget_successor(&charged, &replenished),
            Err(DurableEvidenceError::InvalidExecutionBudget)
        );

        let mut regressive_revision = charged;
        regressive_revision.revision -= 1;
        assert_eq!(
            validate_budget_successor(&charged, &regressive_revision),
            Err(DurableEvidenceError::InvalidExecutionBudget)
        );

        let mut changed_transition_maximum = charged;
        changed_transition_maximum.maximum_transitions += 1;
        assert_eq!(
            validate_budget_successor(&charged, &changed_transition_maximum),
            Err(DurableEvidenceError::InvalidExecutionBudget)
        );

        let mut changed_operation_maximum = charged;
        changed_operation_maximum.maximum_operations += 1;
        assert_eq!(
            validate_budget_successor(&charged, &changed_operation_maximum),
            Err(DurableEvidenceError::InvalidExecutionBudget)
        );

        let mut mismatched_delta = charged;
        mismatched_delta.remaining_transitions -= 1;
        assert_eq!(
            validate_budget_successor(&charged, &mismatched_delta),
            Err(DurableEvidenceError::InvalidExecutionBudget)
        );
    }

    #[test]
    fn compacted_snapshot_validates_start_to_frontier_budget_continuity() {
        let program = value_program();
        let mut machine = machine(Arc::clone(&program));
        let start_state = evidence(&machine, DurableCommitCutV1::Checkpoint, None);
        let continuous_start = DurableExecutionStartV3::new(
            execution(),
            root_task(),
            &program,
            Arc::<[u8]>::from(&b"{}"[..]),
            start_state.clone(),
        )
        .unwrap_or_else(|error| panic!("execution start failed: {error:?}"));

        assert!(matches!(machine.step(), MachineStep::Transition(_)));
        let frontier = evidence(&machine, DurableCommitCutV1::Checkpoint, None);
        DurableRecoverySnapshotV3::new(continuous_start, frontier.clone())
            .unwrap_or_else(|error| panic!("continuous snapshot failed: {error:?}"));

        let regressive_start = DurableExecutionStartV3::new(
            execution(),
            root_task(),
            &program,
            Arc::<[u8]>::from(&b"{}"[..]),
            frontier,
        )
        .unwrap_or_else(|error| panic!("execution start failed: {error:?}"));
        assert_eq!(
            DurableRecoverySnapshotV3::new(regressive_start, start_state).map(|_| ()),
            Err(DurableEvidenceError::InvalidExecutionBudget)
        );
    }

    #[test]
    fn recovery_rejects_mismatched_and_regressive_budget_projections() {
        let program = value_program();
        let mut charged_machine = machine(Arc::clone(&program));
        assert!(matches!(charged_machine.step(), MachineStep::Transition(_)));
        let first = evidence(&charged_machine, DurableCommitCutV1::Checkpoint, None);

        let different_limits = MachineLimits::new(32, 4, 4, 4, 16, DEFAULT_VALUE_LIMITS)
            .unwrap_or_else(|| panic!("machine limits failed"));
        let different_machine = Machine::new(
            Arc::clone(&program),
            &path("crate::main"),
            Vec::new(),
            execution(),
            different_limits,
        )
        .unwrap_or_else(|error| panic!("machine construction failed: {error:?}"));
        let mut mismatched = first.clone();
        mismatched.budget = different_machine.budget_checkpoint();
        assert!(matches!(
            DurableLogicalEvidenceV3::decode(&program, &mismatched.canonical_body()),
            Err(DurableEvidenceError::Checkpoint(_))
        ));

        let changed_maxima = evidence(&different_machine, DurableCommitCutV1::Checkpoint, None);
        let first_envelope = envelope(1, 1, &first, &[]);
        let mixed_prefix = JournalPrefixV1::Full(FullJournalPrefixV1 {
            journal_id: journal_id(),
            evidence: Arc::from([
                first_envelope.clone(),
                envelope(2, 2, &changed_maxima, &[first_envelope.evidence_id]),
            ]),
            committed_through: 2,
        });
        assert_eq!(
            recover_authoritative_prefix(Arc::clone(&program), &mixed_prefix).map(|_| ()),
            Err(DurableEvidenceError::InvalidExecutionBudget)
        );

        let pristine = machine(Arc::clone(&program));
        let regressive = evidence(&pristine, DurableCommitCutV1::Checkpoint, None);
        let first_envelope = envelope(1, 1, &first, &[]);
        let prefix = JournalPrefixV1::Full(FullJournalPrefixV1 {
            journal_id: journal_id(),
            evidence: Arc::from([
                first_envelope.clone(),
                envelope(2, 2, &regressive, &[first_envelope.evidence_id]),
            ]),
            committed_through: 2,
        });
        assert_eq!(
            recover_authoritative_prefix(program, &prefix).map(|_| ()),
            Err(DurableEvidenceError::InvalidExecutionBudget)
        );
    }

    fn evidence(
        machine: &Machine,
        cut: DurableCommitCutV1,
        operation: Option<DurableOperationEvidenceV1>,
    ) -> DurableLogicalEvidenceV3 {
        DurableLogicalEvidenceV3::new(execution(), root_task(), cut, operation, machine)
            .unwrap_or_else(|error| panic!("evidence construction failed: {error:?}"))
    }

    fn operation_evidence(
        machine: &Machine,
        operation_id: ProtocolIdentity,
        dispatch_id: Option<ProtocolIdentity>,
        cut: DurableCommitCutV1,
        action_recovery: Option<RecoveryClass>,
        retry_delay_us: Option<u64>,
    ) -> DurableLogicalEvidenceV3 {
        let request_bytes =
            (cut != DurableCommitCutV1::OperationResult).then(|| Arc::from(&b"{}"[..]));
        let outcome = match cut {
            DurableCommitCutV1::OperationOutcome => {
                Some(HookOutcomeV1::Completed(Arc::from(&b"null"[..])))
            }
            DurableCommitCutV1::RetryWaiting => {
                Some(HookOutcomeV1::Completed(Arc::from(&b"invalid"[..])))
            }
            _ => None,
        };
        let retry_errors = if cut == DurableCommitCutV1::RetryWaiting {
            Arc::from([ValidationErrorV1 {
                category: ValidationErrorCategoryV1::Schema,
                instance_location: Some(Arc::from("/value")),
                message: Arc::from("invalid value"),
                schema_location: Some(Arc::from("/type")),
            }])
        } else {
            Arc::from([])
        };
        let result_type =
            (cut == DurableCommitCutV1::OperationResult).then_some(TypeDescriptor::UNIT);
        let result_bytes =
            (cut == DurableCommitCutV1::OperationResult).then(|| Arc::from(&b"null"[..]));
        evidence(
            machine,
            cut,
            Some(DurableOperationEvidenceV1 {
                operation_id,
                dispatch_id,
                validation_attempt: 0,
                recovery_dispatch: 0,
                retry_delay_us,
                retries_left: Some(2),
                action_recovery,
                request_bytes,
                outcome,
                retry_errors,
                result_type,
                result_bytes,
            }),
        )
    }

    fn envelope(
        sequence: u64,
        evidence_material: u8,
        evidence: &DurableLogicalEvidenceV3,
        references: &[ProtocolIdentity],
    ) -> JournalEvidenceEnvelopeV1 {
        JournalEvidenceEnvelopeV1 {
            journal_id: journal_id(),
            sequence,
            evidence_id: evidence_id(evidence_material),
            kind: Arc::from("gantry.logical-evidence/v3"),
            canonical_body: Arc::from(evidence.canonical_body()),
            references: Arc::from(references),
            protected_payloads: Arc::from([]),
        }
    }

    fn value_program() -> Arc<MachineProgram> {
        program(
            vec![
                instruction(
                    0,
                    TypeDescriptor::BOOL,
                    InstructionKind::Push(LogicalValue::boolean(true)),
                ),
                instruction(1, TypeDescriptor::BOOL, InstructionKind::Return),
            ],
            TypeDescriptor::BOOL,
        )
    }

    fn operation_program() -> Arc<MachineProgram> {
        program(
            vec![
                instruction(0, TypeDescriptor::UNIT, InstructionKind::Operation),
                instruction(1, TypeDescriptor::UNIT, InstructionKind::Return),
            ],
            TypeDescriptor::UNIT,
        )
    }

    fn program(instructions: Vec<Instruction>, result: TypeDescriptor) -> Arc<MachineProgram> {
        Arc::new(
            MachineProgram::new(vec![Workflow {
                path: path("crate::main"),
                parameters: Vec::new(),
                result,
                effects: EffectSet::default(),
                instructions,
            }])
            .unwrap_or_else(|error| panic!("program construction failed: {error:?}")),
        )
    }

    fn machine(program: Arc<MachineProgram>) -> Machine {
        Machine::new(
            program,
            &path("crate::main"),
            Vec::new(),
            execution(),
            MachineLimits::new(16, 4, 4, 4, 16, DEFAULT_VALUE_LIMITS)
                .unwrap_or_else(|| panic!("machine limits failed")),
        )
        .unwrap_or_else(|error| panic!("machine construction failed: {error:?}"))
    }

    fn drive(mut machine: Machine) -> MachineOutcome {
        loop {
            match machine.step() {
                MachineStep::Transition(_) => {}
                MachineStep::YieldRequired => assert!(machine.resume_after_yield()),
                MachineStep::Complete(outcome) => return outcome,
                other => panic!("recovered machine remained externally blocked: {other:?}"),
            }
        }
    }

    fn instruction(index: u64, ty: TypeDescriptor, kind: InstructionKind) -> Instruction {
        Instruction {
            site: StructuralPosition::new(vec![index])
                .unwrap_or_else(|error| panic!("site construction failed: {error}")),
            ty,
            kind,
        }
    }

    fn path(value: &str) -> CanonicalPath {
        CanonicalPath::new(value).unwrap_or_else(|error| panic!("path failed: {error}"))
    }

    fn execution() -> ProtocolIdentity {
        fresh(IdentityKind::Execution, 1)
    }

    fn root_task() -> ProtocolIdentity {
        ProtocolIdentity::derive(IdentityKind::Task, b"durable-root-task")
            .unwrap_or_else(|error| panic!("task identity failed: {error}"))
    }

    fn fresh(kind: IdentityKind, byte: u8) -> ProtocolIdentity {
        ProtocolIdentity::from_fresh_material(kind, [byte; 32])
            .unwrap_or_else(|error| panic!("identity failed: {error}"))
    }

    fn evidence_id(byte: u8) -> ProtocolIdentity {
        ProtocolIdentity::from_storage_material([byte; 32])
    }

    fn journal_id() -> JournalId {
        JournalId::new("recovery-journal")
            .unwrap_or_else(|error| panic!("journal id failed: {error:?}"))
    }
}
