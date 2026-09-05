//! Authoritative evidence for the composed concurrent-durable refinement.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use gantry_core::identity::ProtocolIdentity;
use gantry_core::portable::{
    CancellationReasonCategory, IdentityKind, TaskHandleState, TaskStatusKind,
};
use gantry_host::journal::{
    BatchLocalEvidenceId, FullJournalPrefixV1, JournalEvidenceEnvelopeV1,
    JournalEvidenceReferenceV1, JournalId, JournalPayloadKey, JournalPrefixV1,
    UnfinalizedEvidenceV1, validate_journal_prefix,
};
use gantry_ir::MachineProgram;

use super::{
    CONCURRENT_DURABLE_EVIDENCE_KIND_V4, CONCURRENT_DURABLE_EVIDENCE_KIND_V5,
    DurableCommitCoordinatorV1, DurableCommitCutV1, DurableCommitError, DurableEvidenceCommitV1,
    DurableEvidenceError, DurableExecutionStartV3, DurableOperationEvidenceV1, decode_hex, field,
    object, optional_operation, optional_string, push_json_string, push_operation,
    push_optional_string, require_exact_fields, string, validate_budget_successor,
    validate_operation_evidence,
};
use crate::{
    CancellationCausalIdentity, CancellationReason, ConcurrentDurableCheckpointV4,
    ConcurrentSchedulerV1, DURABLE_EVENT_DISPATCHED_KIND_V1, DURABLE_EVENT_OCCURRENCE_KIND_V1,
    DURABLE_EVENT_SETTLED_KIND_V1, DurableEventOccurrenceV1, LogicalSessionRegistryV1, Machine,
    RecoveredConcurrentDurableExecutionV1, RecoveredDurableEventsV1,
};

/// Journal snapshot selector for the version-one concurrent recovery body.
pub const CONCURRENT_DURABLE_SNAPSHOT_VERSION_V1: u64 = 7;

/// Canonical format identifier for version-one concurrent recovery snapshots.
pub const CONCURRENT_DURABLE_RECOVERY_SNAPSHOT_FORMAT_V1: &str =
    "gantry.concurrent-recovery-snapshot/v1";

/// One canonical authoritative evidence body for a complete concurrent task graph.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConcurrentDurableEvidenceV4 {
    cut: DurableCommitCutV1,
    task_id: ProtocolIdentity,
    checkpoint: ConcurrentDurableCheckpointV4,
}

impl ConcurrentDurableEvidenceV4 {
    /// Constructs one validated post-transition graph checkpoint.
    pub fn new(
        cut: DurableCommitCutV1,
        task_id: ProtocolIdentity,
        checkpoint: ConcurrentDurableCheckpointV4,
    ) -> Result<Self, DurableEvidenceError> {
        if task_id.kind() != IdentityKind::Task || !checkpoint.contains_task(task_id) {
            return Err(DurableEvidenceError::InvalidState);
        }
        let valid_cut = match cut {
            DurableCommitCutV1::Checkpoint => task_id == checkpoint.root_task_id(),
            DurableCommitCutV1::TaskCreation => {
                task_id != checkpoint.root_task_id()
                    && checkpoint.task_status(task_id) == Some(TaskStatusKind::Submitting)
            }
            DurableCommitCutV1::TaskOwnership => matches!(
                checkpoint.task_handle_state(task_id),
                Some(TaskHandleState::Joined | TaskHandleState::Detached)
            ),
            DurableCommitCutV1::Cancellation => checkpoint.task_is_cancelled(task_id),
            DurableCommitCutV1::TaskSettlement => matches!(
                checkpoint.task_status(task_id),
                Some(
                    TaskStatusKind::Succeeded | TaskStatusKind::Failed | TaskStatusKind::Cancelled
                )
            ),
            DurableCommitCutV1::ForegroundCompletion => {
                task_id == checkpoint.root_task_id() && checkpoint.foreground_is_fixed()
            }
            DurableCommitCutV1::TerminalCompletion => {
                task_id == checkpoint.root_task_id() && checkpoint.terminal_is_fixed()
            }
            DurableCommitCutV1::OperationPrepared
            | DurableCommitCutV1::OperationOutcome
            | DurableCommitCutV1::OperationResult
            | DurableCommitCutV1::RetryWaiting => false,
        };
        if !valid_cut {
            return Err(DurableEvidenceError::InvalidState);
        }
        Ok(Self {
            cut,
            task_id,
            checkpoint,
        })
    }

    /// Returns the represented semantic commit boundary.
    #[must_use]
    pub const fn cut(&self) -> DurableCommitCutV1 {
        self.cut
    }

    /// Returns the task whose transition crossed this commit boundary.
    #[must_use]
    pub const fn task_id(&self) -> ProtocolIdentity {
        self.task_id
    }

    /// Returns the accepted execution represented by this graph.
    #[must_use]
    pub const fn execution_id(&self) -> ProtocolIdentity {
        self.checkpoint.execution_id()
    }

    /// Returns the complete composed graph checkpoint.
    #[must_use]
    pub const fn checkpoint(&self) -> &ConcurrentDurableCheckpointV4 {
        &self.checkpoint
    }

    /// Encodes the unique version-four canonical JSON evidence body.
    #[must_use]
    pub fn canonical_body(&self) -> Vec<u8> {
        let mut output = String::from("{\"checkpoint\":");
        push_json_string(
            &mut output,
            &super::encode_hex(&self.checkpoint.canonical_bytes()),
        );
        output.push_str(",\"cut\":");
        push_json_string(&mut output, self.cut.wire_name());
        output.push_str(",\"execution_id\":");
        push_json_string(&mut output, &self.execution_id().to_string());
        output.push_str(",\"format\":\"gantry.concurrent-durable-evidence/v4\",\"task_id\":");
        push_json_string(&mut output, &self.task_id.to_string());
        output.push('}');
        output.into_bytes()
    }

    /// Decodes one exact canonical evidence body against the immutable program.
    pub fn decode(program: &MachineProgram, body: &[u8]) -> Result<Self, DurableEvidenceError> {
        let maximum_bytes =
            u64::try_from(body.len()).map_err(|_| DurableEvidenceError::Encoding)?;
        let document = gantry_core::strict_json::StrictJsonDocument::decode(
            body,
            gantry_core::strict_json::JsonLimits {
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
            &["checkpoint", "cut", "execution_id", "format", "task_id"],
        )?;
        if string(&document, field(root, "format")?)? != "gantry.concurrent-durable-evidence/v4" {
            return Err(DurableEvidenceError::Encoding);
        }
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
        let bytes = decode_hex(string(&document, field(root, "checkpoint")?)?)?;
        let checkpoint = ConcurrentDurableCheckpointV4::decode(program, &bytes)
            .map_err(DurableEvidenceError::ConcurrentCheckpoint)?;
        if checkpoint.execution_id() != execution_id {
            return Err(DurableEvidenceError::MixedExecution);
        }
        let evidence = Self::new(cut, task_id, checkpoint)?;
        if evidence.canonical_body() != body {
            return Err(DurableEvidenceError::Encoding);
        }
        Ok(evidence)
    }

    fn unfinalized(
        &self,
        batch_local_id: BatchLocalEvidenceId,
        references: impl Into<Arc<[JournalEvidenceReferenceV1]>>,
    ) -> Result<UnfinalizedEvidenceV1, DurableEvidenceError> {
        UnfinalizedEvidenceV1::new(
            batch_local_id,
            CONCURRENT_DURABLE_EVIDENCE_KIND_V4,
            self.canonical_body(),
            references,
            Arc::from([]),
        )
        .map_err(DurableEvidenceError::Journal)
    }
}

/// Semantic role carried by one version-five concurrent-durable record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConcurrentDurableEvidenceRecordV5 {
    /// Operation lifecycle evidence with stable operation and dispatch coordinates.
    Operation,
    /// Resolution of one named child from submitting-hidden to visible.
    SubmissionResolution,
    /// First typed execution cancellation fixed before task signalling.
    Cancellation,
}

impl ConcurrentDurableEvidenceRecordV5 {
    const fn wire_name(self) -> &'static str {
        match self {
            Self::Operation => "operation",
            Self::SubmissionResolution => "submission-resolution",
            Self::Cancellation => "cancellation",
        }
    }

    fn from_wire_name(value: &str) -> Option<Self> {
        match value {
            "operation" => Some(Self::Operation),
            "submission-resolution" => Some(Self::SubmissionResolution),
            "cancellation" => Some(Self::Cancellation),
            _ => None,
        }
    }
}

/// One discriminated version-five concurrent-durable graph record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConcurrentDurableEvidenceV5 {
    cut: DurableCommitCutV1,
    task_id: ProtocolIdentity,
    record: ConcurrentDurableEvidenceRecordV5,
    operation: Option<DurableOperationEvidenceV1>,
    cancellation: Option<CancellationReason>,
    checkpoint: ConcurrentDurableCheckpointV4,
}

impl ConcurrentDurableEvidenceV5 {
    /// Constructs operation evidence without changing the version-four wire contract.
    pub fn new_operation(
        cut: DurableCommitCutV1,
        task_id: ProtocolIdentity,
        operation: DurableOperationEvidenceV1,
        checkpoint: ConcurrentDurableCheckpointV4,
    ) -> Result<Self, DurableEvidenceError> {
        Self::new(
            cut,
            task_id,
            ConcurrentDurableEvidenceRecordV5::Operation,
            Some(operation),
            None,
            checkpoint,
        )
    }

    /// Constructs a named child-submission resolution checkpoint.
    pub fn new_submission_resolution(
        cut: DurableCommitCutV1,
        task_id: ProtocolIdentity,
        checkpoint: ConcurrentDurableCheckpointV4,
    ) -> Result<Self, DurableEvidenceError> {
        Self::new(
            cut,
            task_id,
            ConcurrentDurableEvidenceRecordV5::SubmissionResolution,
            None,
            None,
            checkpoint,
        )
    }

    /// Constructs a typed execution-cancellation graph checkpoint.
    pub fn new_cancellation(
        task_id: ProtocolIdentity,
        cancellation: CancellationReason,
        checkpoint: ConcurrentDurableCheckpointV4,
    ) -> Result<Self, DurableEvidenceError> {
        Self::new(
            DurableCommitCutV1::Cancellation,
            task_id,
            ConcurrentDurableEvidenceRecordV5::Cancellation,
            None,
            Some(cancellation),
            checkpoint,
        )
    }

    fn new(
        cut: DurableCommitCutV1,
        task_id: ProtocolIdentity,
        record: ConcurrentDurableEvidenceRecordV5,
        operation: Option<DurableOperationEvidenceV1>,
        cancellation: Option<CancellationReason>,
        checkpoint: ConcurrentDurableCheckpointV4,
    ) -> Result<Self, DurableEvidenceError> {
        if task_id.kind() != IdentityKind::Task || !checkpoint.contains_task(task_id) {
            return Err(DurableEvidenceError::InvalidState);
        }
        match record {
            ConcurrentDurableEvidenceRecordV5::Operation => {
                if !cut.requires_operation() || cancellation.is_some() {
                    return Err(DurableEvidenceError::InvalidOperation);
                }
                let task_checkpoint = checkpoint
                    .task_checkpoint(task_id)
                    .ok_or(DurableEvidenceError::InvalidState)?;
                validate_operation_evidence(cut, operation.as_ref(), task_checkpoint)?;
            }
            ConcurrentDurableEvidenceRecordV5::SubmissionResolution => {
                let valid = operation.is_none()
                    && cancellation.is_none()
                    && task_id != checkpoint.root_task_id()
                    && checkpoint.task_handle_is_visible(task_id)
                    && matches!(
                        (cut, checkpoint.task_status(task_id)),
                        (
                            DurableCommitCutV1::Checkpoint,
                            Some(TaskStatusKind::Running)
                        ) | (
                            DurableCommitCutV1::TaskSettlement,
                            Some(TaskStatusKind::Failed)
                        )
                    );
                if !valid {
                    return Err(DurableEvidenceError::InvalidState);
                }
            }
            ConcurrentDurableEvidenceRecordV5::Cancellation => {
                if cut != DurableCommitCutV1::Cancellation
                    || operation.is_some()
                    || cancellation.is_none()
                    || !checkpoint.task_is_cancelled(task_id)
                {
                    return Err(DurableEvidenceError::InvalidState);
                }
            }
        }
        Ok(Self {
            cut,
            task_id,
            record,
            operation,
            cancellation,
            checkpoint,
        })
    }

    /// Returns the represented semantic commit boundary.
    #[must_use]
    pub const fn cut(&self) -> DurableCommitCutV1 {
        self.cut
    }

    /// Returns the task whose transition crossed this commit boundary.
    #[must_use]
    pub const fn task_id(&self) -> ProtocolIdentity {
        self.task_id
    }

    /// Returns this record's explicit version-five role.
    #[must_use]
    pub const fn record(&self) -> ConcurrentDurableEvidenceRecordV5 {
        self.record
    }

    /// Returns operation coordinates when this is an operation record.
    #[must_use]
    pub const fn operation(&self) -> Option<&DurableOperationEvidenceV1> {
        self.operation.as_ref()
    }

    /// Returns the first typed execution cancellation for a cancellation record.
    #[must_use]
    pub const fn cancellation(&self) -> Option<&CancellationReason> {
        self.cancellation.as_ref()
    }

    /// Returns the accepted execution represented by this graph.
    #[must_use]
    pub const fn execution_id(&self) -> ProtocolIdentity {
        self.checkpoint.execution_id()
    }

    /// Returns the complete composed graph checkpoint.
    #[must_use]
    pub const fn checkpoint(&self) -> &ConcurrentDurableCheckpointV4 {
        &self.checkpoint
    }

    /// Encodes the unique discriminated version-five canonical JSON body.
    #[must_use]
    pub fn canonical_body(&self) -> Vec<u8> {
        let mut output = String::from("{\"checkpoint\":");
        push_json_string(
            &mut output,
            &super::encode_hex(&self.checkpoint.canonical_bytes()),
        );
        output.push_str(",\"cancellation\":");
        push_optional_cancellation(&mut output, self.cancellation.as_ref());
        output.push_str(",\"cut\":");
        push_json_string(&mut output, self.cut.wire_name());
        output.push_str(",\"execution_id\":");
        push_json_string(&mut output, &self.execution_id().to_string());
        output.push_str(",\"format\":\"gantry.concurrent-durable-evidence/v5\",\"operation\":");
        match &self.operation {
            Some(operation) => push_operation(&mut output, operation),
            None => output.push_str("null"),
        }
        output.push_str(",\"record\":");
        push_json_string(&mut output, self.record.wire_name());
        output.push_str(",\"task_id\":");
        push_json_string(&mut output, &self.task_id.to_string());
        output.push('}');
        output.into_bytes()
    }

    /// Decodes one exact version-five evidence body against the immutable program.
    pub fn decode(program: &MachineProgram, body: &[u8]) -> Result<Self, DurableEvidenceError> {
        let maximum_bytes =
            u64::try_from(body.len()).map_err(|_| DurableEvidenceError::Encoding)?;
        let document = gantry_core::strict_json::StrictJsonDocument::decode(
            body,
            gantry_core::strict_json::JsonLimits {
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
                "checkpoint",
                "cancellation",
                "cut",
                "execution_id",
                "format",
                "operation",
                "record",
                "task_id",
            ],
        )?;
        if string(&document, field(root, "format")?)? != CONCURRENT_DURABLE_EVIDENCE_KIND_V5 {
            return Err(DurableEvidenceError::Encoding);
        }
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
        let record = ConcurrentDurableEvidenceRecordV5::from_wire_name(string(
            &document,
            field(root, "record")?,
        )?)
        .ok_or(DurableEvidenceError::Encoding)?;
        let operation = optional_operation(&document, field(root, "operation")?)?;
        let cancellation = optional_cancellation(&document, field(root, "cancellation")?)?;
        let bytes = decode_hex(string(&document, field(root, "checkpoint")?)?)?;
        let checkpoint = ConcurrentDurableCheckpointV4::decode(program, &bytes)
            .map_err(DurableEvidenceError::ConcurrentCheckpoint)?;
        if checkpoint.execution_id() != execution_id {
            return Err(DurableEvidenceError::MixedExecution);
        }
        let evidence = Self::new(cut, task_id, record, operation, cancellation, checkpoint)?;
        if evidence.canonical_body() != body {
            return Err(DurableEvidenceError::Encoding);
        }
        Ok(evidence)
    }

    fn unfinalized(
        &self,
        batch_local_id: BatchLocalEvidenceId,
        references: impl Into<Arc<[JournalEvidenceReferenceV1]>>,
    ) -> Result<UnfinalizedEvidenceV1, DurableEvidenceError> {
        UnfinalizedEvidenceV1::new(
            batch_local_id,
            CONCURRENT_DURABLE_EVIDENCE_KIND_V5,
            self.canonical_body(),
            references,
            Arc::from([]),
        )
        .map_err(DurableEvidenceError::Journal)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ConcurrentDurableEvidenceBody {
    V4(Box<ConcurrentDurableEvidenceV4>),
    V5(Box<ConcurrentDurableEvidenceV5>),
}

impl ConcurrentDurableEvidenceBody {
    fn cut(&self) -> DurableCommitCutV1 {
        match self {
            Self::V4(evidence) => evidence.cut(),
            Self::V5(evidence) => evidence.cut(),
        }
    }

    fn task_id(&self) -> ProtocolIdentity {
        match self {
            Self::V4(evidence) => evidence.task_id(),
            Self::V5(evidence) => evidence.task_id(),
        }
    }

    fn execution_id(&self) -> ProtocolIdentity {
        self.checkpoint().execution_id()
    }

    fn checkpoint(&self) -> &ConcurrentDurableCheckpointV4 {
        match self {
            Self::V4(evidence) => evidence.checkpoint(),
            Self::V5(evidence) => evidence.checkpoint(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ConcurrentSnapshotEventV1 {
    sequence: u64,
    evidence_id: ProtocolIdentity,
    kind: Arc<str>,
    canonical_body: Arc<[u8]>,
    references: Arc<[ProtocolIdentity]>,
    protected_payloads: Arc<[JournalPayloadKey]>,
}

impl ConcurrentSnapshotEventV1 {
    fn from_envelope(envelope: &JournalEvidenceEnvelopeV1) -> Result<Self, DurableEvidenceError> {
        if !matches!(
            envelope.kind.as_ref(),
            DURABLE_EVENT_OCCURRENCE_KIND_V1
                | DURABLE_EVENT_DISPATCHED_KIND_V1
                | DURABLE_EVENT_SETTLED_KIND_V1
        ) {
            return Err(DurableEvidenceError::UnsupportedEvidenceKind);
        }
        Ok(Self {
            sequence: envelope.sequence,
            evidence_id: envelope.evidence_id,
            kind: Arc::clone(&envelope.kind),
            canonical_body: Arc::clone(&envelope.canonical_body),
            references: Arc::clone(&envelope.references),
            protected_payloads: Arc::clone(&envelope.protected_payloads),
        })
    }

    fn envelope(&self, journal_id: &JournalId) -> JournalEvidenceEnvelopeV1 {
        JournalEvidenceEnvelopeV1 {
            journal_id: journal_id.clone(),
            sequence: self.sequence,
            evidence_id: self.evidence_id,
            kind: Arc::clone(&self.kind),
            canonical_body: Arc::clone(&self.canonical_body),
            references: Arc::clone(&self.references),
            protected_payloads: Arc::clone(&self.protected_payloads),
        }
    }
}

/// Version-one compacted concurrent recovery state used by journal snapshot version seven.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConcurrentDurableRecoverySnapshotV1 {
    execution_start: DurableExecutionStartV3,
    start_evidence_id: ProtocolIdentity,
    graph: ConcurrentDurableEvidenceBody,
    graph_sequence: u64,
    graph_evidence_id: ProtocolIdentity,
    operations: Arc<[ConcurrentDurableEvidenceV5]>,
    cancellation: Option<ConcurrentDurableEvidenceV5>,
    events: Arc<[ConcurrentSnapshotEventV1]>,
    frontier: u64,
    frontier_evidence_id: ProtocolIdentity,
    retained_evidence: BTreeMap<ProtocolIdentity, u64>,
}

impl ConcurrentDurableRecoverySnapshotV1 {
    /// Compacts one already valid full concurrent prefix into the version-seven snapshot form.
    pub fn from_full_prefix(
        program: &MachineProgram,
        prefix: &FullJournalPrefixV1,
    ) -> Result<Self, DurableEvidenceError> {
        recover_concurrent_authoritative_prefix(
            Arc::new(program.clone()),
            &JournalPrefixV1::Full(prefix.clone()),
        )?;
        let mut execution_start = None;
        let mut start_evidence_id = None;
        let mut graph = None;
        let mut graph_sequence = 0;
        let mut graph_evidence_id = None;
        let mut operations = Vec::new();
        let mut cancellation = None;
        let mut events = Vec::new();
        let mut retained_evidence = BTreeMap::new();
        for envelope in prefix.evidence.iter() {
            retained_evidence.insert(envelope.evidence_id, envelope.sequence);
            match envelope.kind.as_ref() {
                "gantry.execution-start/v3" => {
                    execution_start = Some(DurableExecutionStartV3::decode(
                        program,
                        &envelope.canonical_body,
                    )?);
                    start_evidence_id = Some(envelope.evidence_id);
                }
                CONCURRENT_DURABLE_EVIDENCE_KIND_V4 => {
                    graph = Some(ConcurrentDurableEvidenceBody::V4(Box::new(
                        ConcurrentDurableEvidenceV4::decode(program, &envelope.canonical_body)?,
                    )));
                    graph_sequence = envelope.sequence;
                    graph_evidence_id = Some(envelope.evidence_id);
                }
                CONCURRENT_DURABLE_EVIDENCE_KIND_V5 => {
                    let evidence =
                        ConcurrentDurableEvidenceV5::decode(program, &envelope.canonical_body)?;
                    match evidence.record() {
                        ConcurrentDurableEvidenceRecordV5::Operation => {
                            operations.push(evidence.clone());
                        }
                        ConcurrentDurableEvidenceRecordV5::Cancellation => {
                            cancellation = Some(evidence.clone());
                        }
                        ConcurrentDurableEvidenceRecordV5::SubmissionResolution => {}
                    }
                    graph = Some(ConcurrentDurableEvidenceBody::V5(Box::new(evidence)));
                    graph_sequence = envelope.sequence;
                    graph_evidence_id = Some(envelope.evidence_id);
                }
                DURABLE_EVENT_OCCURRENCE_KIND_V1
                | DURABLE_EVENT_DISPATCHED_KIND_V1
                | DURABLE_EVENT_SETTLED_KIND_V1 => {
                    events.push(ConcurrentSnapshotEventV1::from_envelope(envelope)?);
                }
                _ => return Err(DurableEvidenceError::UnsupportedEvidenceKind),
            }
        }
        let frontier_envelope = prefix
            .evidence
            .last()
            .ok_or(DurableEvidenceError::MissingRecoveryState)?;
        Self::from_parts(
            program,
            execution_start.ok_or(DurableEvidenceError::InvalidExecutionStart)?,
            start_evidence_id.ok_or(DurableEvidenceError::InvalidExecutionStart)?,
            graph.ok_or(DurableEvidenceError::MissingRecoveryState)?,
            graph_sequence,
            graph_evidence_id.ok_or(DurableEvidenceError::MissingRecoveryState)?,
            operations.into(),
            cancellation,
            events.into(),
            frontier_envelope.sequence,
            frontier_envelope.evidence_id,
            retained_evidence,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn from_parts(
        program: &MachineProgram,
        execution_start: DurableExecutionStartV3,
        start_evidence_id: ProtocolIdentity,
        graph: ConcurrentDurableEvidenceBody,
        graph_sequence: u64,
        graph_evidence_id: ProtocolIdentity,
        operations: Arc<[ConcurrentDurableEvidenceV5]>,
        cancellation: Option<ConcurrentDurableEvidenceV5>,
        events: Arc<[ConcurrentSnapshotEventV1]>,
        frontier: u64,
        frontier_evidence_id: ProtocolIdentity,
        retained_evidence: BTreeMap<ProtocolIdentity, u64>,
    ) -> Result<Self, DurableEvidenceError> {
        if start_evidence_id.kind() != IdentityKind::Evidence
            || graph_evidence_id.kind() != IdentityKind::Evidence
            || frontier_evidence_id.kind() != IdentityKind::Evidence
            || graph_sequence == 0
            || graph_sequence > frontier
            || graph.execution_id() != execution_start.execution_id()
            || graph.checkpoint().root_task_id() != execution_start.task_id()
            || retained_evidence.get(&start_evidence_id) != Some(&1)
            || retained_evidence.get(&graph_evidence_id) != Some(&graph_sequence)
            || retained_evidence.get(&frontier_evidence_id) != Some(&frontier)
        {
            return Err(DurableEvidenceError::MixedExecution);
        }
        validate_budget_successor(
            &execution_start.state().budget(),
            &graph.checkpoint().execution_budget(),
        )?;
        let mut prepared_dispatches = BTreeSet::new();
        let mut latest_prepared = BTreeMap::new();
        let mut committed_outcomes = BTreeSet::new();
        let mut latest_outcomes = BTreeMap::new();
        let mut committed_results = BTreeSet::new();
        for operation in operations.iter() {
            if operation.execution_id() != execution_start.execution_id()
                || operation.record() != ConcurrentDurableEvidenceRecordV5::Operation
            {
                return Err(DurableEvidenceError::MixedExecution);
            }
            record_operation_cut(
                operation,
                &mut prepared_dispatches,
                &mut latest_prepared,
                &mut committed_outcomes,
                &mut latest_outcomes,
                &mut committed_results,
            )?;
        }
        if let Some(cancellation) = &cancellation
            && (cancellation.execution_id() != execution_start.execution_id()
                || cancellation.record() != ConcurrentDurableEvidenceRecordV5::Cancellation)
        {
            return Err(DurableEvidenceError::MixedExecution);
        }
        let validation_journal = JournalId::new("concurrent-recovery-snapshot-validation")
            .map_err(|_| DurableEvidenceError::Encoding)?;
        let mut recovered_events = RecoveredDurableEventsV1::default();
        let mut previous_event_sequence = 0;
        for event in events.iter() {
            if event.sequence <= previous_event_sequence
                || event.sequence > frontier
                || retained_evidence.get(&event.evidence_id) != Some(&event.sequence)
                || event.references.iter().any(|reference| {
                    retained_evidence
                        .get(reference)
                        .is_none_or(|sequence| *sequence >= event.sequence)
                })
            {
                return Err(DurableEvidenceError::InvalidCausalOrder);
            }
            if event.kind.as_ref() == DURABLE_EVENT_OCCURRENCE_KIND_V1 {
                let occurrence = DurableEventOccurrenceV1::decode(&event.canonical_body)
                    .map_err(DurableEvidenceError::Event)?;
                if occurrence.event().execution_id() != Some(execution_start.execution_id()) {
                    return Err(DurableEvidenceError::MixedExecution);
                }
            }
            recovered_events
                .apply_envelope(&event.envelope(&validation_journal))
                .map_err(DurableEvidenceError::Event)?;
            previous_event_sequence = event.sequence;
        }
        let represented_frontier = events
            .last()
            .map_or(graph_sequence, |event| event.sequence.max(graph_sequence));
        let represented_frontier_id = if events
            .last()
            .is_some_and(|event| event.sequence > graph_sequence)
        {
            events
                .last()
                .map(|event| event.evidence_id)
                .ok_or(DurableEvidenceError::MissingRecoveryState)?
        } else {
            graph_evidence_id
        };
        if represented_frontier != frontier || represented_frontier_id != frontier_evidence_id {
            return Err(DurableEvidenceError::InvalidCausalOrder);
        }
        let execution = graph
            .checkpoint()
            .clone()
            .recover(Arc::new(program.clone()))
            .map_err(DurableEvidenceError::ConcurrentCheckpoint)?;
        if let Some(cancellation) = &cancellation {
            let reason = cancellation
                .cancellation()
                .ok_or(DurableEvidenceError::InvalidState)?;
            let expected = reason
                .message
                .as_deref()
                .unwrap_or_else(|| reason.category.wire_name());
            if execution
                .scheduler()
                .state()
                .task_cancellation_reason(cancellation.task_id())
                != Some(expected)
            {
                return Err(DurableEvidenceError::InvalidState);
            }
        }
        Ok(Self {
            execution_start,
            start_evidence_id,
            graph,
            graph_sequence,
            graph_evidence_id,
            operations,
            cancellation,
            events,
            frontier,
            frontier_evidence_id,
            retained_evidence,
        })
    }

    /// Returns the immutable execution-start record retained by compaction.
    #[must_use]
    pub const fn execution_start(&self) -> &DurableExecutionStartV3 {
        &self.execution_start
    }

    /// Returns the authoritative sequence represented by this snapshot.
    #[must_use]
    pub const fn frontier(&self) -> u64 {
        self.frontier
    }

    /// Returns the evidence identity at the authoritative snapshot frontier.
    #[must_use]
    pub const fn frontier_evidence_id(&self) -> ProtocolIdentity {
        self.frontier_evidence_id
    }

    /// Returns the evidence identities retained for suffix causal validation.
    #[must_use]
    pub const fn retained_evidence(&self) -> &BTreeMap<ProtocolIdentity, u64> {
        &self.retained_evidence
    }

    /// Encodes the unique version-one concurrent recovery snapshot body.
    #[must_use]
    pub fn canonical_body(&self) -> Vec<u8> {
        let mut output = String::from("{\"cancellation\":");
        match &self.cancellation {
            Some(cancellation) => push_json_string(
                &mut output,
                &super::encode_hex(&cancellation.canonical_body()),
            ),
            None => output.push_str("null"),
        }
        output.push_str(",\"events\":[");
        for (index, event) in self.events.iter().enumerate() {
            if index != 0 {
                output.push(',');
            }
            output.push_str("{\"body\":");
            push_json_string(&mut output, &super::encode_hex(&event.canonical_body));
            output.push_str(",\"evidence_id\":");
            push_json_string(&mut output, &event.evidence_id.to_string());
            output.push_str(",\"kind\":");
            push_json_string(&mut output, &event.kind);
            output.push_str(",\"payloads\":[");
            for (payload_index, payload) in event.protected_payloads.iter().enumerate() {
                if payload_index != 0 {
                    output.push(',');
                }
                push_json_string(&mut output, payload.as_str());
            }
            output.push_str("],\"references\":[");
            for (reference_index, reference) in event.references.iter().enumerate() {
                if reference_index != 0 {
                    output.push(',');
                }
                push_json_string(&mut output, &reference.to_string());
            }
            output.push_str("],\"sequence\":");
            output.push_str(&event.sequence.to_string());
            output.push('}');
        }
        output.push_str("],\"execution_start\":");
        push_json_string(
            &mut output,
            &super::encode_hex(&self.execution_start.canonical_body()),
        );
        output.push_str(",\"format\":");
        push_json_string(&mut output, CONCURRENT_DURABLE_RECOVERY_SNAPSHOT_FORMAT_V1);
        output.push_str(",\"frontier\":");
        output.push_str(&self.frontier.to_string());
        output.push_str(",\"frontier_evidence_id\":");
        push_json_string(&mut output, &self.frontier_evidence_id.to_string());
        output.push_str(",\"graph\":");
        let (graph_kind, graph_body) = match &self.graph {
            ConcurrentDurableEvidenceBody::V4(evidence) => (
                CONCURRENT_DURABLE_EVIDENCE_KIND_V4,
                evidence.canonical_body(),
            ),
            ConcurrentDurableEvidenceBody::V5(evidence) => (
                CONCURRENT_DURABLE_EVIDENCE_KIND_V5,
                evidence.canonical_body(),
            ),
        };
        push_json_string(&mut output, &super::encode_hex(&graph_body));
        output.push_str(",\"graph_evidence_id\":");
        push_json_string(&mut output, &self.graph_evidence_id.to_string());
        output.push_str(",\"graph_kind\":");
        push_json_string(&mut output, graph_kind);
        output.push_str(",\"graph_sequence\":");
        output.push_str(&self.graph_sequence.to_string());
        output.push_str(",\"operations\":[");
        for (index, operation) in self.operations.iter().enumerate() {
            if index != 0 {
                output.push(',');
            }
            push_json_string(&mut output, &super::encode_hex(&operation.canonical_body()));
        }
        output.push_str("],\"retained_evidence\":[");
        for (index, (evidence_id, sequence)) in self.retained_evidence.iter().enumerate() {
            if index != 0 {
                output.push(',');
            }
            output.push_str("{\"evidence_id\":");
            push_json_string(&mut output, &evidence_id.to_string());
            output.push_str(",\"sequence\":");
            output.push_str(&sequence.to_string());
            output.push('}');
        }
        output.push_str("],\"start_evidence_id\":");
        push_json_string(&mut output, &self.start_evidence_id.to_string());
        output.push('}');
        output.into_bytes()
    }

    /// Decodes one exact version-one concurrent recovery snapshot.
    pub fn decode(program: &MachineProgram, body: &[u8]) -> Result<Self, DurableEvidenceError> {
        let document = decode_snapshot_document(body)?;
        let root = object(&document, document.root())?;
        require_exact_fields(
            root,
            &[
                "cancellation",
                "events",
                "execution_start",
                "format",
                "frontier",
                "frontier_evidence_id",
                "graph",
                "graph_evidence_id",
                "graph_kind",
                "graph_sequence",
                "operations",
                "retained_evidence",
                "start_evidence_id",
            ],
        )?;
        if string(&document, field(root, "format")?)?
            != CONCURRENT_DURABLE_RECOVERY_SNAPSHOT_FORMAT_V1
        {
            return Err(DurableEvidenceError::Encoding);
        }
        let execution_start = DurableExecutionStartV3::decode(
            program,
            &decode_hex(string(&document, field(root, "execution_start")?)?)?,
        )?;
        let start_evidence_id = snapshot_identity(
            &document,
            field(root, "start_evidence_id")?,
            IdentityKind::Evidence,
        )?;
        let graph_kind = string(&document, field(root, "graph_kind")?)?;
        let graph_body = decode_hex(string(&document, field(root, "graph")?)?)?;
        let graph = match graph_kind {
            CONCURRENT_DURABLE_EVIDENCE_KIND_V4 => {
                ConcurrentDurableEvidenceV4::decode(program, &graph_body)
                    .map(Box::new)
                    .map(ConcurrentDurableEvidenceBody::V4)?
            }
            CONCURRENT_DURABLE_EVIDENCE_KIND_V5 => {
                ConcurrentDurableEvidenceV5::decode(program, &graph_body)
                    .map(Box::new)
                    .map(ConcurrentDurableEvidenceBody::V5)?
            }
            _ => return Err(DurableEvidenceError::Encoding),
        };
        let graph_sequence = snapshot_unsigned(&document, field(root, "graph_sequence")?)?;
        let graph_evidence_id = snapshot_identity(
            &document,
            field(root, "graph_evidence_id")?,
            IdentityKind::Evidence,
        )?;
        let cancellation = snapshot_optional_body(&document, field(root, "cancellation")?)?
            .map(|body| ConcurrentDurableEvidenceV5::decode(program, &body))
            .transpose()?;
        let operations = snapshot_array(&document, field(root, "operations")?)?
            .iter()
            .map(|item| {
                ConcurrentDurableEvidenceV5::decode(
                    program,
                    &decode_hex(string(&document, *item)?)?,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let events = snapshot_array(&document, field(root, "events")?)?
            .iter()
            .map(|item| decode_snapshot_event(&document, *item))
            .collect::<Result<Vec<_>, _>>()?;
        let frontier = snapshot_unsigned(&document, field(root, "frontier")?)?;
        let frontier_evidence_id = snapshot_identity(
            &document,
            field(root, "frontier_evidence_id")?,
            IdentityKind::Evidence,
        )?;
        let mut retained_evidence = BTreeMap::new();
        let mut retained_sequences = BTreeSet::new();
        for item in snapshot_array(&document, field(root, "retained_evidence")?)? {
            let retained = object(&document, *item)?;
            require_exact_fields(retained, &["evidence_id", "sequence"])?;
            let evidence_id = snapshot_identity(
                &document,
                field(retained, "evidence_id")?,
                IdentityKind::Evidence,
            )?;
            let sequence = snapshot_unsigned(&document, field(retained, "sequence")?)?;
            if retained_evidence.insert(evidence_id, sequence).is_some()
                || !retained_sequences.insert(sequence)
            {
                return Err(DurableEvidenceError::InvalidCausalOrder);
            }
        }
        let decoded = Self::from_parts(
            program,
            execution_start,
            start_evidence_id,
            graph,
            graph_sequence,
            graph_evidence_id,
            operations.into(),
            cancellation,
            events.into(),
            frontier,
            frontier_evidence_id,
            retained_evidence,
        )?;
        if decoded.canonical_body() != body {
            return Err(DurableEvidenceError::Encoding);
        }
        Ok(decoded)
    }

    /// Extracts the retained executable program before graph checkpoint decoding.
    pub fn retained_program(body: &[u8]) -> Result<MachineProgram, DurableEvidenceError> {
        let document = decode_snapshot_document(body)?;
        let root = object(&document, document.root())?;
        require_exact_fields(
            root,
            &[
                "cancellation",
                "events",
                "execution_start",
                "format",
                "frontier",
                "frontier_evidence_id",
                "graph",
                "graph_evidence_id",
                "graph_kind",
                "graph_sequence",
                "operations",
                "retained_evidence",
                "start_evidence_id",
            ],
        )?;
        if string(&document, field(root, "format")?)?
            != CONCURRENT_DURABLE_RECOVERY_SNAPSHOT_FORMAT_V1
        {
            return Err(DurableEvidenceError::Encoding);
        }
        DurableExecutionStartV3::retained_program(&decode_hex(string(
            &document,
            field(root, "execution_start")?,
        )?)?)
    }
}

fn decode_snapshot_document(
    body: &[u8],
) -> Result<gantry_core::strict_json::StrictJsonDocument, DurableEvidenceError> {
    let maximum_bytes = u64::try_from(body.len()).map_err(|_| DurableEvidenceError::Encoding)?;
    gantry_core::strict_json::StrictJsonDocument::decode(
        body,
        gantry_core::strict_json::JsonLimits {
            maximum_bytes,
            maximum_nesting_depth: maximum_bytes.max(1),
            maximum_nodes: maximum_bytes.max(1),
            maximum_string_scalars: maximum_bytes.max(1),
            maximum_list_items: maximum_bytes.max(1),
        },
    )
    .map_err(|_| DurableEvidenceError::Encoding)
}

fn snapshot_array(
    document: &gantry_core::strict_json::StrictJsonDocument,
    id: gantry_core::strict_json::JsonNodeId,
) -> Result<&[gantry_core::strict_json::JsonNodeId], DurableEvidenceError> {
    match document.node(id) {
        Some(gantry_core::strict_json::JsonNode::Array(items)) => Ok(items),
        _ => Err(DurableEvidenceError::Encoding),
    }
}

fn snapshot_unsigned(
    document: &gantry_core::strict_json::StrictJsonDocument,
    id: gantry_core::strict_json::JsonNodeId,
) -> Result<u64, DurableEvidenceError> {
    match document.node(id) {
        Some(gantry_core::strict_json::JsonNode::Number(value)) => value
            .to_gantry_int()
            .ok()
            .and_then(|value| u64::try_from(value).ok())
            .ok_or(DurableEvidenceError::Encoding),
        _ => Err(DurableEvidenceError::Encoding),
    }
}

fn snapshot_identity(
    document: &gantry_core::strict_json::StrictJsonDocument,
    id: gantry_core::strict_json::JsonNodeId,
    kind: IdentityKind,
) -> Result<ProtocolIdentity, DurableEvidenceError> {
    ProtocolIdentity::parse_kind(string(document, id)?, kind)
        .map_err(|_| DurableEvidenceError::Encoding)
}

fn snapshot_optional_body(
    document: &gantry_core::strict_json::StrictJsonDocument,
    id: gantry_core::strict_json::JsonNodeId,
) -> Result<Option<Vec<u8>>, DurableEvidenceError> {
    match document.node(id) {
        Some(gantry_core::strict_json::JsonNode::Null) => Ok(None),
        Some(gantry_core::strict_json::JsonNode::String(value)) => decode_hex(value).map(Some),
        _ => Err(DurableEvidenceError::Encoding),
    }
}

fn decode_snapshot_event(
    document: &gantry_core::strict_json::StrictJsonDocument,
    id: gantry_core::strict_json::JsonNodeId,
) -> Result<ConcurrentSnapshotEventV1, DurableEvidenceError> {
    let event = object(document, id)?;
    require_exact_fields(
        event,
        &[
            "body",
            "evidence_id",
            "kind",
            "payloads",
            "references",
            "sequence",
        ],
    )?;
    let kind: Arc<str> = Arc::from(string(document, field(event, "kind")?)?);
    if !matches!(
        kind.as_ref(),
        DURABLE_EVENT_OCCURRENCE_KIND_V1
            | DURABLE_EVENT_DISPATCHED_KIND_V1
            | DURABLE_EVENT_SETTLED_KIND_V1
    ) {
        return Err(DurableEvidenceError::UnsupportedEvidenceKind);
    }
    let references = snapshot_array(document, field(event, "references")?)?
        .iter()
        .map(|item| snapshot_identity(document, *item, IdentityKind::Evidence))
        .collect::<Result<Vec<_>, _>>()?;
    let protected_payloads = snapshot_array(document, field(event, "payloads")?)?
        .iter()
        .map(|item| {
            JournalPayloadKey::new(string(document, *item)?)
                .map_err(|_| DurableEvidenceError::Encoding)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ConcurrentSnapshotEventV1 {
        sequence: snapshot_unsigned(document, field(event, "sequence")?)?,
        evidence_id: snapshot_identity(
            document,
            field(event, "evidence_id")?,
            IdentityKind::Evidence,
        )?,
        kind,
        canonical_body: Arc::from(decode_hex(string(document, field(event, "body")?)?)?),
        references: references.into(),
        protected_payloads: protected_payloads.into(),
    })
}

fn push_optional_cancellation(output: &mut String, cancellation: Option<&CancellationReason>) {
    let Some(cancellation) = cancellation else {
        output.push_str("null");
        return;
    };
    output.push_str("{\"causal_identity\":");
    match cancellation.causal_identity {
        Some(CancellationCausalIdentity::Operation(identity)) => {
            output.push_str("{\"identity\":");
            push_json_string(output, &identity.to_string());
            output.push_str(",\"kind\":\"operation\"}");
        }
        Some(CancellationCausalIdentity::Task(identity)) => {
            output.push_str("{\"identity\":");
            push_json_string(output, &identity.to_string());
            output.push_str(",\"kind\":\"task\"}");
        }
        None => output.push_str("null"),
    }
    output.push_str(",\"category\":");
    push_json_string(output, cancellation.category.wire_name());
    output.push_str(",\"message\":");
    push_optional_string(output, cancellation.message.as_deref());
    output.push('}');
}

fn optional_cancellation(
    document: &gantry_core::strict_json::StrictJsonDocument,
    id: gantry_core::strict_json::JsonNodeId,
) -> Result<Option<CancellationReason>, DurableEvidenceError> {
    let Some(node) = document.node(id) else {
        return Err(DurableEvidenceError::Encoding);
    };
    let gantry_core::strict_json::JsonNode::Object(value) = node else {
        return match node {
            gantry_core::strict_json::JsonNode::Null => Ok(None),
            _ => Err(DurableEvidenceError::Encoding),
        };
    };
    require_exact_fields(value, &["causal_identity", "category", "message"])?;
    let category =
        CancellationReasonCategory::from_wire_name(string(document, field(value, "category")?)?)
            .ok_or(DurableEvidenceError::Encoding)?;
    let causal_identity = match document.node(field(value, "causal_identity")?) {
        Some(gantry_core::strict_json::JsonNode::Null) => None,
        Some(gantry_core::strict_json::JsonNode::Object(causal)) => {
            require_exact_fields(causal, &["identity", "kind"])?;
            let (kind, wrap): (
                IdentityKind,
                fn(ProtocolIdentity) -> CancellationCausalIdentity,
            ) = match string(document, field(causal, "kind")?)? {
                "operation" => (
                    IdentityKind::Operation,
                    CancellationCausalIdentity::Operation,
                ),
                "task" => (IdentityKind::Task, CancellationCausalIdentity::Task),
                _ => return Err(DurableEvidenceError::Encoding),
            };
            Some(wrap(
                ProtocolIdentity::parse_kind(string(document, field(causal, "identity")?)?, kind)
                    .map_err(|_| DurableEvidenceError::Encoding)?,
            ))
        }
        _ => return Err(DurableEvidenceError::Encoding),
    };
    CancellationReason::new(
        category,
        optional_string(document, field(value, "message")?)?.map(Arc::from),
        causal_identity,
        u64::MAX,
    )
    .map(Some)
    .map_err(|_| DurableEvidenceError::Encoding)
}

impl DurableCommitCoordinatorV1<'_> {
    /// Commits the graph cut's causal event through the existing event owner.
    pub(crate) async fn commit_graph_event(
        &mut self,
        cause: &DurableEvidenceCommitV1,
        event: gantry_core::event::EventEnvelope,
        plan: crate::DurableEventPlanV1,
        payloads: &[gantry_host::event::ProtectedPayload],
    ) -> Result<gantry_host::journal::JournalEvidenceEnvelopeV1, DurableCommitError> {
        if self.predecessor != Some((cause.evidence_id, cause.sequence))
            || event.execution_id() != Some(self.execution_id)
        {
            return Err(DurableCommitError::InvalidState);
        }
        let occurrence = DurableEventOccurrenceV1::new(cause.evidence_id, event, plan)
            .map_err(|error| DurableCommitError::Evidence(DurableEvidenceError::Event(error)))?;
        let mut events = crate::DurableEventCommitCoordinatorV1::new(
            self.sink,
            (cause.evidence_id, cause.sequence),
        )
        .map_err(map_graph_event_error)?;
        let receipt = events
            .commit_occurrence(&occurrence, payloads)
            .await
            .map_err(map_graph_event_error)?;
        self.predecessor = Some((receipt.evidence_id, receipt.sequence));
        Ok(gantry_host::journal::JournalEvidenceEnvelopeV1 {
            journal_id: self.sink.journal_id().clone(),
            sequence: receipt.sequence,
            evidence_id: receipt.evidence_id,
            kind: Arc::from(DURABLE_EVENT_OCCURRENCE_KIND_V1),
            canonical_body: Arc::from(occurrence.canonical_body()),
            references: Arc::from([cause.evidence_id]),
            protected_payloads: payloads
                .iter()
                .map(|payload| {
                    gantry_host::journal::JournalPayloadKey::new(payload.reference.key())
                        .map_err(|_| DurableCommitError::InvalidState)
                })
                .collect::<Result<Vec<_>, _>>()?
                .into(),
        })
    }

    /// Commits one complete task-graph cut before its dependent external boundary.
    pub async fn commit_concurrent_cut(
        &mut self,
        cut: DurableCommitCutV1,
        affected_task: ProtocolIdentity,
        foreground: &Machine,
        scheduler: &ConcurrentSchedulerV1,
        sessions: &LogicalSessionRegistryV1,
    ) -> Result<DurableEvidenceCommitV1, DurableCommitError> {
        let checkpoint = ConcurrentDurableCheckpointV4::capture(foreground, scheduler, sessions)
            .map_err(|error| {
                DurableCommitError::Evidence(DurableEvidenceError::ConcurrentCheckpoint(error))
            })?;
        self.commit_graph_checkpoint(cut, affected_task, checkpoint)
            .await
    }

    /// Commits an owned coherent graph projection without retaining capture locks.
    ///
    /// The execution owner must serialize staged successors and publish their
    /// semantic state only after this operation returns a validated receipt.
    pub async fn commit_graph_checkpoint(
        &mut self,
        cut: DurableCommitCutV1,
        affected_task: ProtocolIdentity,
        checkpoint: ConcurrentDurableCheckpointV4,
    ) -> Result<DurableEvidenceCommitV1, DurableCommitError> {
        self.commit_graph_checkpoint_with_submission(cut, affected_task, checkpoint, || {})
            .await
    }

    /// Reports the storage invocation boundary to the staged publication owner.
    pub(crate) async fn commit_graph_checkpoint_with_submission(
        &mut self,
        cut: DurableCommitCutV1,
        affected_task: ProtocolIdentity,
        checkpoint: ConcurrentDurableCheckpointV4,
        submitted: impl FnOnce(),
    ) -> Result<DurableEvidenceCommitV1, DurableCommitError> {
        self.commit_graph_checkpoint_with_operation_submission(
            cut,
            affected_task,
            None,
            checkpoint,
            submitted,
        )
        .await
    }

    /// Reports graph operation evidence and the storage invocation boundary.
    pub(crate) async fn commit_graph_checkpoint_with_operation_submission(
        &mut self,
        cut: DurableCommitCutV1,
        affected_task: ProtocolIdentity,
        operation: Option<DurableOperationEvidenceV1>,
        checkpoint: ConcurrentDurableCheckpointV4,
        submitted: impl FnOnce(),
    ) -> Result<DurableEvidenceCommitV1, DurableCommitError> {
        self.commit_graph_checkpoint_with_record_submission(
            cut,
            affected_task,
            operation,
            false,
            checkpoint,
            submitted,
        )
        .await
    }

    /// Reports a discriminated graph record and the storage invocation boundary.
    pub(crate) async fn commit_graph_checkpoint_with_record_submission(
        &mut self,
        cut: DurableCommitCutV1,
        affected_task: ProtocolIdentity,
        operation: Option<DurableOperationEvidenceV1>,
        submission_resolution: bool,
        checkpoint: ConcurrentDurableCheckpointV4,
        submitted: impl FnOnce(),
    ) -> Result<DurableEvidenceCommitV1, DurableCommitError> {
        if checkpoint.execution_id() != self.execution_id
            || checkpoint.root_task_id() != self.task_id
            || (operation.is_some() && submission_resolution)
            || (cut == DurableCommitCutV1::Cancellation && self.graph_cancellation.is_none())
        {
            return Err(DurableCommitError::InvalidState);
        }
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
        let cancellation = if cut == DurableCommitCutV1::Cancellation {
            self.graph_cancellation.take()
        } else {
            None
        };
        let body = match (operation, submission_resolution, cancellation) {
            (None, false, Some(cancellation)) => ConcurrentDurableEvidenceV5::new_cancellation(
                affected_task,
                cancellation,
                checkpoint,
            )
            .and_then(|evidence| evidence.unfinalized(local_id.clone(), references)),
            (None, true, None) => ConcurrentDurableEvidenceV5::new_submission_resolution(
                cut,
                affected_task,
                checkpoint,
            )
            .and_then(|evidence| evidence.unfinalized(local_id.clone(), references)),
            (Some(operation), false, None) => ConcurrentDurableEvidenceV5::new_operation(
                cut,
                affected_task,
                operation,
                checkpoint,
            )
            .and_then(|evidence| evidence.unfinalized(local_id.clone(), references)),
            (None, false, None) => ConcurrentDurableEvidenceV4::new(cut, affected_task, checkpoint)
                .and_then(|evidence| evidence.unfinalized(local_id.clone(), references)),
            _ => Err(DurableEvidenceError::InvalidState),
        }
        .map_err(DurableCommitError::Evidence)?;
        self.commit_body_with_submission(cut, local_number, local_id, body, submitted)
            .await
    }
}

/// Recovered composed runtime plus the latest authoritative journal coordinates.
fn map_graph_event_error(error: crate::DurableEventCommitError) -> DurableCommitError {
    match error {
        crate::DurableEventCommitError::Journal(error)
        | crate::DurableEventCommitError::StreamTerminated(error) => {
            DurableCommitError::Journal(error)
        }
        crate::DurableEventCommitError::Evidence(error) => {
            DurableCommitError::Evidence(DurableEvidenceError::Event(error))
        }
        crate::DurableEventCommitError::InvalidReceipt => DurableCommitError::InvalidReceipt,
        _ => DurableCommitError::InvalidState,
    }
}

/// Recovered composed runtime plus the latest authoritative journal coordinates.
#[derive(Debug)]
pub struct RecoveredConcurrentDurableStateV1 {
    execution: RecoveredConcurrentDurableExecutionV1,
    events: RecoveredDurableEventsV1,
    cancellation: Option<CancellationReason>,
    latest_sequence: u64,
    latest_evidence_id: ProtocolIdentity,
    latest_cut: DurableCommitCutV1,
}

impl RecoveredConcurrentDurableStateV1 {
    /// Returns the recovered existing foreground machine, scheduler, and sessions.
    #[must_use]
    pub const fn execution(&self) -> &RecoveredConcurrentDurableExecutionV1 {
        &self.execution
    }

    /// Returns recovered journal-first events and delivery obligations.
    #[must_use]
    pub const fn events(&self) -> &RecoveredDurableEventsV1 {
        &self.events
    }

    /// Returns the first typed execution cancellation retained by graph evidence.
    #[must_use]
    pub const fn cancellation_reason(&self) -> Option<&CancellationReason> {
        self.cancellation.as_ref()
    }

    /// Returns the latest authoritative journal sequence.
    #[must_use]
    pub const fn latest_sequence(&self) -> u64 {
        self.latest_sequence
    }

    /// Returns the latest authoritative evidence identity.
    #[must_use]
    pub const fn latest_evidence_id(&self) -> ProtocolIdentity {
        self.latest_evidence_id
    }

    /// Returns the latest committed semantic cut.
    #[must_use]
    pub const fn latest_cut(&self) -> DurableCommitCutV1 {
        self.latest_cut
    }
}

/// Projects a full or version-seven snapshot authoritative prefix into the existing runtime.
pub fn recover_concurrent_authoritative_prefix(
    program: Arc<MachineProgram>,
    prefix: &JournalPrefixV1,
) -> Result<RecoveredConcurrentDurableStateV1, DurableEvidenceError> {
    validate_journal_prefix(prefix).map_err(DurableEvidenceError::Journal)?;
    let (journal_id, envelopes, snapshot) = match prefix {
        JournalPrefixV1::Full(prefix) => (&prefix.journal_id, prefix.evidence.as_ref(), None),
        JournalPrefixV1::Snapshot(prefix) => {
            if prefix.snapshot_version != CONCURRENT_DURABLE_SNAPSHOT_VERSION_V1 {
                return Err(DurableEvidenceError::Encoding);
            }
            let snapshot =
                ConcurrentDurableRecoverySnapshotV1::decode(&program, &prefix.canonical_snapshot)?;
            if snapshot.frontier() != prefix.frontier
                || snapshot.retained_evidence() != &prefix.retained_evidence
            {
                return Err(DurableEvidenceError::InvalidCausalOrder);
            }
            (&prefix.journal_id, prefix.suffix.as_ref(), Some(snapshot))
        }
    };
    let mut latest_graph: Option<ConcurrentDurableEvidenceBody> = None;
    let mut execution_start: Option<DurableExecutionStartV3> = None;
    let mut cancellation: Option<CancellationReason> = None;
    let mut cancellation_task: Option<ProtocolIdentity> = None;
    let mut journal_tip: Option<(u64, ProtocolIdentity)> = None;
    let mut events = RecoveredDurableEventsV1::default();
    let mut known = BTreeSet::new();
    let mut prepared_dispatches = BTreeSet::new();
    let mut latest_prepared = BTreeMap::new();
    let mut committed_outcomes = BTreeSet::new();
    let mut latest_outcomes = BTreeMap::new();
    let mut committed_results = BTreeSet::new();
    if let Some(snapshot) = snapshot {
        for operation in snapshot.operations.iter() {
            record_operation_cut(
                operation,
                &mut prepared_dispatches,
                &mut latest_prepared,
                &mut committed_outcomes,
                &mut latest_outcomes,
                &mut committed_results,
            )?;
        }
        for event in snapshot.events.iter() {
            events
                .apply_envelope(&event.envelope(journal_id))
                .map_err(DurableEvidenceError::Event)?;
        }
        if let Some(record) = &snapshot.cancellation {
            cancellation = Some(
                record
                    .cancellation()
                    .cloned()
                    .ok_or(DurableEvidenceError::InvalidState)?,
            );
            cancellation_task = Some(record.task_id());
        }
        known.extend(snapshot.retained_evidence.keys().copied());
        journal_tip = Some((snapshot.frontier, snapshot.frontier_evidence_id));
        execution_start = Some(snapshot.execution_start);
        latest_graph = Some(snapshot.graph);
    }
    for envelope in envelopes {
        match journal_tip {
            None if envelope.sequence == 1 && envelope.references.is_empty() => {}
            Some((sequence, evidence_id))
                if sequence.checked_add(1) == Some(envelope.sequence)
                    && envelope.references.contains(&evidence_id)
                    && envelope.references.iter().all(|id| known.contains(id)) => {}
            _ => return Err(DurableEvidenceError::InvalidCausalOrder),
        }

        if envelope.kind.as_ref() == "gantry.execution-start/v3" {
            if execution_start.is_some()
                || latest_graph.is_some()
                || envelope.sequence != 1
                || !envelope.references.is_empty()
            {
                return Err(DurableEvidenceError::InvalidExecutionStart);
            }
            execution_start = Some(DurableExecutionStartV3::decode(
                &program,
                &envelope.canonical_body,
            )?);
        } else if matches!(
            envelope.kind.as_ref(),
            CONCURRENT_DURABLE_EVIDENCE_KIND_V4 | CONCURRENT_DURABLE_EVIDENCE_KIND_V5
        ) {
            let evidence = if envelope.kind.as_ref() == CONCURRENT_DURABLE_EVIDENCE_KIND_V4 {
                let evidence =
                    ConcurrentDurableEvidenceV4::decode(&program, &envelope.canonical_body)?;
                if evidence.cut() == DurableCommitCutV1::Cancellation {
                    return Err(DurableEvidenceError::UnsupportedConcurrentCancellation);
                }
                ConcurrentDurableEvidenceBody::V4(Box::new(evidence))
            } else {
                ConcurrentDurableEvidenceV5::decode(&program, &envelope.canonical_body)
                    .map(Box::new)
                    .map(ConcurrentDurableEvidenceBody::V5)?
            };
            if let Some(prior) = &latest_graph {
                validate_transition(prior, &evidence)?;
                let submission_resolution = evidence
                    .checkpoint()
                    .submission_resolution_task(&prior.checkpoint().hidden_submission_task_ids())
                    .map_err(DurableEvidenceError::ConcurrentCheckpoint)?;
                if let ConcurrentDurableEvidenceBody::V5(current) = &evidence {
                    match current.record() {
                        ConcurrentDurableEvidenceRecordV5::Operation => {
                            if submission_resolution.is_some() {
                                return Err(DurableEvidenceError::InvalidState);
                            }
                            record_operation_cut(
                                current,
                                &mut prepared_dispatches,
                                &mut latest_prepared,
                                &mut committed_outcomes,
                                &mut latest_outcomes,
                                &mut committed_results,
                            )?;
                        }
                        ConcurrentDurableEvidenceRecordV5::SubmissionResolution => {
                            if submission_resolution != Some(current.task_id()) {
                                return Err(DurableEvidenceError::InvalidState);
                            }
                            current
                                .checkpoint()
                                .validate_submission_resolution(
                                    prior.checkpoint(),
                                    current.task_id(),
                                    Arc::clone(&program),
                                )
                                .map_err(DurableEvidenceError::ConcurrentCheckpoint)?;
                        }
                        ConcurrentDurableEvidenceRecordV5::Cancellation => {
                            if submission_resolution.is_some() || cancellation.is_some() {
                                return Err(DurableEvidenceError::RepeatedCancellation);
                            }
                            cancellation = Some(
                                current
                                    .cancellation()
                                    .cloned()
                                    .ok_or(DurableEvidenceError::InvalidState)?,
                            );
                            cancellation_task = Some(current.task_id());
                        }
                    }
                }
            } else {
                if let Some(start) = &execution_start {
                    if evidence.execution_id() != start.execution_id()
                        || evidence.checkpoint().root_task_id() != start.task_id()
                    {
                        return Err(DurableEvidenceError::InvalidState);
                    }
                    let valid_first_cut = match evidence.cut() {
                        DurableCommitCutV1::Checkpoint => {
                            evidence.task_id() == start.task_id()
                                && evidence.checkpoint().created_task_count() == 1
                        }
                        DurableCommitCutV1::TaskCreation => {
                            evidence.task_id() != start.task_id()
                                && evidence.checkpoint().created_task_count() == 2
                        }
                        _ => false,
                    };
                    if !valid_first_cut {
                        return Err(DurableEvidenceError::InvalidState);
                    }
                    validate_budget_successor(
                        &start.state().budget,
                        &evidence.checkpoint().execution_budget(),
                    )?;
                } else if evidence.cut() != DurableCommitCutV1::Checkpoint {
                    return Err(DurableEvidenceError::InvalidState);
                }
            }
            latest_graph = Some(evidence);
        } else if matches!(
            envelope.kind.as_ref(),
            DURABLE_EVENT_OCCURRENCE_KIND_V1
                | DURABLE_EVENT_DISPATCHED_KIND_V1
                | DURABLE_EVENT_SETTLED_KIND_V1
        ) {
            let graph = latest_graph
                .as_ref()
                .ok_or(DurableEvidenceError::InvalidCausalOrder)?;
            if envelope.kind.as_ref() == DURABLE_EVENT_OCCURRENCE_KIND_V1 {
                let occurrence = DurableEventOccurrenceV1::decode(&envelope.canonical_body)
                    .map_err(DurableEvidenceError::Event)?;
                if occurrence.event().execution_id() != Some(graph.execution_id()) {
                    return Err(DurableEvidenceError::MixedExecution);
                }
            }
            events
                .apply_envelope(envelope)
                .map_err(DurableEvidenceError::Event)?;
        } else {
            return Err(DurableEvidenceError::UnsupportedEvidenceKind);
        }
        if !known.insert(envelope.evidence_id) {
            return Err(DurableEvidenceError::InvalidCausalOrder);
        }
        journal_tip = Some((envelope.sequence, envelope.evidence_id));
    }
    let (latest_sequence, latest_evidence_id) =
        journal_tip.ok_or(DurableEvidenceError::MissingRecoveryState)?;
    let evidence = latest_graph.ok_or(DurableEvidenceError::MissingRecoveryState)?;
    let latest_cut = evidence.cut();
    let execution = evidence
        .checkpoint()
        .clone()
        .recover(program)
        .map_err(DurableEvidenceError::ConcurrentCheckpoint)?;
    if let (Some(reason), Some(task_id)) = (&cancellation, cancellation_task) {
        let expected = reason
            .message
            .as_deref()
            .unwrap_or_else(|| reason.category.wire_name());
        if execution
            .scheduler()
            .state()
            .task_cancellation_reason(task_id)
            != Some(expected)
        {
            return Err(DurableEvidenceError::InvalidState);
        }
    }
    Ok(RecoveredConcurrentDurableStateV1 {
        execution,
        events,
        cancellation,
        latest_sequence,
        latest_evidence_id,
        latest_cut,
    })
}

fn validate_transition(
    previous: &ConcurrentDurableEvidenceBody,
    current: &ConcurrentDurableEvidenceBody,
) -> Result<(), DurableEvidenceError> {
    if current.execution_id() != previous.execution_id()
        || current.checkpoint().root_task_id() != previous.checkpoint().root_task_id()
    {
        return Err(DurableEvidenceError::MixedExecution);
    }
    validate_budget_successor(
        &previous.checkpoint().execution_budget(),
        &current.checkpoint().execution_budget(),
    )?;
    let previous_tasks = previous
        .checkpoint()
        .task_ids()
        .into_iter()
        .collect::<BTreeSet<_>>();
    let current_tasks = current
        .checkpoint()
        .task_ids()
        .into_iter()
        .collect::<BTreeSet<_>>();
    if !previous_tasks.is_subset(&current_tasks) {
        return Err(DurableEvidenceError::InvalidState);
    }
    let valid = match current.cut() {
        DurableCommitCutV1::Checkpoint => previous_tasks == current_tasks,
        DurableCommitCutV1::TaskCreation => {
            current.checkpoint().created_task_count()
                == previous.checkpoint().created_task_count().saturating_add(1)
                && current_tasks
                    .difference(&previous_tasks)
                    .copied()
                    .collect::<Vec<_>>()
                    == [current.task_id()]
        }
        DurableCommitCutV1::TaskOwnership => {
            previous_tasks == current_tasks
                && previous.checkpoint().task_handle_state(current.task_id())
                    == Some(TaskHandleState::Attached)
                && matches!(
                    current.checkpoint().task_handle_state(current.task_id()),
                    Some(TaskHandleState::Joined | TaskHandleState::Detached)
                )
        }
        DurableCommitCutV1::Cancellation => {
            previous_tasks == current_tasks
                && !previous.checkpoint().task_is_cancelled(current.task_id())
                && current.checkpoint().task_is_cancelled(current.task_id())
        }
        DurableCommitCutV1::TaskSettlement => {
            previous_tasks == current_tasks
                && (previous.checkpoint().task_status(current.task_id())
                    == Some(TaskStatusKind::Running)
                    || (previous.checkpoint().task_status(current.task_id())
                        == Some(TaskStatusKind::Submitting)
                        && (current.checkpoint().task_status(current.task_id())
                            == Some(TaskStatusKind::Failed)
                            || (previous.checkpoint().task_is_cancelled(current.task_id())
                                && current.checkpoint().task_status(current.task_id())
                                    == Some(TaskStatusKind::Cancelled)))))
                && matches!(
                    current.checkpoint().task_status(current.task_id()),
                    Some(
                        TaskStatusKind::Succeeded
                            | TaskStatusKind::Failed
                            | TaskStatusKind::Cancelled
                    )
                )
        }
        DurableCommitCutV1::ForegroundCompletion => {
            previous_tasks == current_tasks
                && !previous.checkpoint().foreground_is_fixed()
                && current.checkpoint().foreground_is_fixed()
        }
        DurableCommitCutV1::TerminalCompletion => {
            previous_tasks == current_tasks
                && !previous.checkpoint().terminal_is_fixed()
                && current.checkpoint().terminal_is_fixed()
        }
        DurableCommitCutV1::OperationPrepared
        | DurableCommitCutV1::OperationOutcome
        | DurableCommitCutV1::OperationResult
        | DurableCommitCutV1::RetryWaiting => previous_tasks == current_tasks,
    };
    valid
        .then_some(())
        .ok_or(DurableEvidenceError::InvalidState)
}

fn record_operation_cut(
    evidence: &ConcurrentDurableEvidenceV5,
    prepared_dispatches: &mut BTreeSet<ProtocolIdentity>,
    latest_prepared: &mut BTreeMap<ProtocolIdentity, ProtocolIdentity>,
    committed_outcomes: &mut BTreeSet<ProtocolIdentity>,
    latest_outcomes: &mut BTreeMap<ProtocolIdentity, ProtocolIdentity>,
    committed_results: &mut BTreeSet<ProtocolIdentity>,
) -> Result<(), DurableEvidenceError> {
    let Some(operation) = evidence.operation() else {
        return Ok(());
    };
    match evidence.cut() {
        DurableCommitCutV1::OperationPrepared => {
            let dispatch = operation
                .dispatch_id
                .ok_or(DurableEvidenceError::InvalidOperation)?;
            if !prepared_dispatches.insert(dispatch) {
                return Err(DurableEvidenceError::RepeatedOperationCut);
            }
            latest_prepared.insert(operation.operation_id, dispatch);
        }
        DurableCommitCutV1::OperationOutcome => {
            let dispatch = operation
                .dispatch_id
                .ok_or(DurableEvidenceError::InvalidOperation)?;
            if latest_prepared.get(&operation.operation_id) != Some(&dispatch) {
                return Err(DurableEvidenceError::InvalidOperationTransition);
            }
            if !committed_outcomes.insert(dispatch) {
                return Err(DurableEvidenceError::RepeatedOperationCut);
            }
            latest_outcomes.insert(operation.operation_id, dispatch);
        }
        DurableCommitCutV1::RetryWaiting => {
            let dispatch = operation
                .dispatch_id
                .ok_or(DurableEvidenceError::InvalidOperation)?;
            if latest_outcomes.get(&operation.operation_id) != Some(&dispatch) {
                return Err(DurableEvidenceError::InvalidOperationTransition);
            }
        }
        DurableCommitCutV1::OperationResult => {
            let latest_dispatch = latest_prepared
                .get(&operation.operation_id)
                .ok_or(DurableEvidenceError::InvalidOperationTransition)?;
            if latest_outcomes.get(&operation.operation_id) != Some(latest_dispatch) {
                return Err(DurableEvidenceError::InvalidOperationTransition);
            }
            if !committed_results.insert(operation.operation_id) {
                return Err(DurableEvidenceError::RepeatedOperationCut);
            }
        }
        _ => return Err(DurableEvidenceError::InvalidOperation),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::future::Future;
    use std::pin::pin;
    use std::sync::Arc;
    use std::task::{Context, Poll, Waker};

    use gantry_core::identity::ProtocolIdentity;
    use gantry_core::portable::{CancellationReasonCategory, IdentityKind, TaskStatusKind};
    use gantry_core::value::{DEFAULT_VALUE_LIMITS, LogicalValue};
    use gantry_host::journal::{
        AcquireJournalOwnerV1, FullJournalPrefixV1, JournalEvidenceEnvelopeV1, JournalId,
        JournalOwnerOperationV1, JournalPrefixV1, JournalStorage, ReadJournalPrefixV1,
        SnapshotJournalPrefixV1,
    };
    use gantry_ir::{
        CanonicalPath, EffectSet, Instruction, InstructionKind, MachineProgram, Parameter,
        StructuralPosition, TypeDescriptor, Workflow,
    };

    use super::{
        CONCURRENT_DURABLE_EVIDENCE_KIND_V4, CONCURRENT_DURABLE_EVIDENCE_KIND_V5,
        CONCURRENT_DURABLE_SNAPSHOT_VERSION_V1, ConcurrentDurableEvidenceRecordV5,
        ConcurrentDurableEvidenceV4, ConcurrentDurableEvidenceV5,
        ConcurrentDurableRecoverySnapshotV1, DurableCommitCoordinatorV1, DurableCommitCutV1,
        DurableEvidenceError, DurableOperationEvidenceV1, record_operation_cut,
        validate_transition,
    };
    use crate::{
        CancellationReason, CanonicalTranscriptV1, ConcurrentDurableCheckpointV4,
        ConcurrentSchedulerV1, ConcurrentTaskStateV1, DurableExecutionStartV3,
        DurableLogicalEvidenceV3, DurableTransitionSink, InMemoryJournalStore,
        LogicalSessionRegistryV1, Machine, MachineLimits, MachineStep, SessionCreationModeV1,
        TaskCreationRequestV1, recover_concurrent_authoritative_prefix, root_task_identity,
    };

    #[test]
    fn journal_commit_recovers_pre_submission_graph_and_rejects_repeated_creation() {
        let program = program();
        let execution = fresh(IdentityKind::Execution, 1);
        let root_task = root_task_identity(execution);
        let root_session = fresh(IdentityKind::Session, 2);
        let mut sessions = LogicalSessionRegistryV1::new(
            execution,
            root_session,
            SessionCreationModeV1::GantryRoot,
            CanonicalTranscriptV1::empty(),
        )
        .unwrap_or_else(|error| panic!("session registry failed: {error:?}"));
        let mut foreground = Machine::new_with_context(
            Arc::clone(&program),
            &path("crate::main"),
            Vec::new(),
            execution,
            machine_limits(),
            None,
            Some(root_session),
        )
        .unwrap_or_else(|error| panic!("foreground machine failed: {error:?}"));
        let state = ConcurrentTaskStateV1::new(execution, root_task, 8)
            .unwrap_or_else(|error| panic!("task state failed: {error:?}"));
        let mut scheduler = ConcurrentSchedulerV1::new(state, foreground.execution_budget())
            .unwrap_or_else(|error| panic!("scheduler construction failed: {error:?}"));

        let storage: Arc<dyn JournalStorage> = Arc::new(InMemoryJournalStore::new());
        let journal_id = JournalId::new("combined-task-creation")
            .unwrap_or_else(|error| panic!("journal id failed: {error:?}"));
        let owner = block_on(storage.acquire_owner(AcquireJournalOwnerV1 {
            journal_id: journal_id.clone(),
            operation: JournalOwnerOperationV1::Start,
        }))
        .unwrap_or_else(|error| panic!("owner acquisition failed: {error:?}"));
        let sink =
            DurableTransitionSink::new(Arc::clone(&storage), journal_id.clone(), owner.token);
        let mut commits = DurableCommitCoordinatorV1::new(&sink, execution, root_task, None)
            .unwrap_or_else(|error| panic!("commit coordinator failed: {error:?}"));
        let coordinator = crate::ExecutionCoordinator::new_with_budget(
            scheduler.state().clone(),
            sessions.clone(),
            foreground.execution_budget(),
        )
        .unwrap_or_else(|error| panic!("execution coordinator failed: {error:?}"));
        let checkpoint = coordinator
            .capture_checkpoint(&foreground, &std::collections::BTreeMap::new())
            .unwrap_or_else(|error| panic!("coordinator capture failed: {error:?}"));
        let initial = block_on(commits.commit_graph_checkpoint(
            DurableCommitCutV1::Checkpoint,
            root_task,
            checkpoint,
        ))
        .unwrap_or_else(|error| panic!("initial graph commit failed: {error:?}"));
        assert_eq!(initial.sequence, 1);

        assert!(matches!(foreground.step(), MachineStep::Transition(_)));
        let expected_budget = foreground.budget_checkpoint();

        let created = scheduler
            .create_child(
                &mut sessions,
                TaskCreationRequestV1 {
                    parent_task_id: root_task,
                    handle_name: Arc::from("child"),
                    workflow: path("crate::main"),
                    spawn_site: position(0),
                    spawn_occurrence: 0,
                    result_type: TypeDescriptor::UNIT,
                    captures: Vec::new(),
                    inherited_agent: None,
                    parent_session_id: root_session,
                },
                DEFAULT_VALUE_LIMITS,
            )
            .unwrap_or_else(|error| panic!("task creation failed: {error:?}"));
        let creation = block_on(commits.commit_concurrent_cut(
            DurableCommitCutV1::TaskCreation,
            created.task_id,
            &foreground,
            &scheduler,
            &sessions,
        ))
        .unwrap_or_else(|error| panic!("task creation commit failed: {error:?}"));
        assert_eq!(creation.sequence, 2);

        let prefix = block_on(storage.read_prefix(ReadJournalPrefixV1 {
            journal_id: journal_id.clone(),
        }))
        .unwrap_or_else(|error| panic!("prefix read failed: {error:?}"));
        let recovered = recover_concurrent_authoritative_prefix(Arc::clone(&program), &prefix)
            .unwrap_or_else(|error| panic!("combined recovery failed: {error:?}"));
        assert_eq!(recovered.latest_sequence(), 2);
        assert_eq!(recovered.latest_cut(), DurableCommitCutV1::TaskCreation);
        assert_eq!(
            recovered.execution().foreground().budget_checkpoint(),
            expected_budget
        );
        let task = recovered
            .execution()
            .scheduler()
            .state()
            .task(created.task_id)
            .unwrap_or_else(|| panic!("recovered child task missing"));
        assert_eq!(task.status().kind(), TaskStatusKind::Submitting);
        assert!(!task.handle_is_visible());
        assert!(
            recovered
                .execution()
                .scheduler()
                .state()
                .parent_is_suspended(root_task)
        );
        assert!(
            recovered
                .execution()
                .sessions()
                .get(created.base_session_id)
                .is_some()
        );

        let JournalPrefixV1::Full(full) = prefix else {
            panic!("in-memory journal returned a snapshot")
        };
        let mut evidence = full.evidence.to_vec();
        let mut repeated = evidence
            .last()
            .cloned()
            .unwrap_or_else(|| panic!("creation evidence missing"));
        repeated.sequence = 3;
        repeated.evidence_id = ProtocolIdentity::from_storage_material([77; 32]);
        repeated.references = Arc::from([creation.evidence_id]);
        evidence.push(repeated);
        let repeated_prefix = JournalPrefixV1::Full(FullJournalPrefixV1 {
            journal_id,
            evidence: Arc::from(evidence),
            committed_through: 3,
        });
        assert_eq!(
            recover_concurrent_authoritative_prefix(program, &repeated_prefix).map(|_| ()),
            Err(DurableEvidenceError::InvalidState)
        );
    }

    #[test]
    fn consecutive_combined_evidence_rejects_changed_budget_maxima() {
        let program = program();
        let execution = fresh(IdentityKind::Execution, 11);
        let root_task = root_task_identity(execution);
        let root_session = fresh(IdentityKind::Session, 12);
        let previous = checkpoint_evidence(
            Arc::clone(&program),
            execution,
            root_task,
            root_session,
            machine_limits(),
        );
        let changed_limits = MachineLimits::new(64, 8, 4, 8, 16, DEFAULT_VALUE_LIMITS)
            .unwrap_or_else(|| panic!("machine limits failed"));
        let current = checkpoint_evidence(
            Arc::clone(&program),
            execution,
            root_task,
            root_session,
            changed_limits,
        );
        assert_eq!(
            validate_transition(
                &super::ConcurrentDurableEvidenceBody::V4(Box::new(previous.clone())),
                &super::ConcurrentDurableEvidenceBody::V4(Box::new(current.clone())),
            ),
            Err(DurableEvidenceError::InvalidExecutionBudget)
        );

        let first_id = ProtocolIdentity::from_storage_material([21; 32]);
        let second_id = ProtocolIdentity::from_storage_material([22; 32]);
        let journal_id = JournalId::new("combined-budget-continuity")
            .unwrap_or_else(|error| panic!("journal id failed: {error:?}"));
        let prefix = JournalPrefixV1::Full(FullJournalPrefixV1 {
            journal_id: journal_id.clone(),
            evidence: Arc::from([
                JournalEvidenceEnvelopeV1 {
                    journal_id: journal_id.clone(),
                    sequence: 1,
                    evidence_id: first_id,
                    kind: Arc::from(CONCURRENT_DURABLE_EVIDENCE_KIND_V4),
                    canonical_body: Arc::from(previous.canonical_body()),
                    references: Arc::from([]),
                    protected_payloads: Arc::from([]),
                },
                JournalEvidenceEnvelopeV1 {
                    journal_id,
                    sequence: 2,
                    evidence_id: second_id,
                    kind: Arc::from(CONCURRENT_DURABLE_EVIDENCE_KIND_V4),
                    canonical_body: Arc::from(current.canonical_body()),
                    references: Arc::from([first_id]),
                    protected_payloads: Arc::from([]),
                },
            ]),
            committed_through: 2,
        });
        assert_eq!(
            recover_concurrent_authoritative_prefix(program, &prefix).map(|_| ()),
            Err(DurableEvidenceError::InvalidExecutionBudget)
        );
    }

    #[test]
    fn version_four_body_retains_the_published_five_field_shape() {
        let program = program();
        let execution = fresh(IdentityKind::Execution, 21);
        let root_task = root_task_identity(execution);
        let root_session = fresh(IdentityKind::Session, 22);
        let evidence = checkpoint_evidence(
            Arc::clone(&program),
            execution,
            root_task,
            root_session,
            machine_limits(),
        );
        let body = evidence.canonical_body();
        let text = std::str::from_utf8(&body)
            .unwrap_or_else(|error| panic!("v4 body is not UTF-8: {error}"));

        assert!(!text.contains("\"operation\""));
        assert_eq!(
            ConcurrentDurableEvidenceV4::decode(&program, &body),
            Ok(evidence)
        );
    }

    #[test]
    fn typed_cancellation_recovers_exactly_and_legacy_v4_fails_closed() {
        let program = program();
        let execution = fresh(IdentityKind::Execution, 23);
        let root_task = root_task_identity(execution);
        let root_session = fresh(IdentityKind::Session, 24);
        let sessions = LogicalSessionRegistryV1::new(
            execution,
            root_session,
            SessionCreationModeV1::GantryRoot,
            CanonicalTranscriptV1::empty(),
        )
        .unwrap_or_else(|error| panic!("session registry failed: {error:?}"));
        let mut foreground = Machine::new_with_context(
            Arc::clone(&program),
            &path("crate::main"),
            Vec::new(),
            execution,
            machine_limits(),
            None,
            Some(root_session),
        )
        .unwrap_or_else(|error| panic!("foreground machine failed: {error:?}"));
        let state = ConcurrentTaskStateV1::new(execution, root_task, 8)
            .unwrap_or_else(|error| panic!("task state failed: {error:?}"));
        let mut scheduler = ConcurrentSchedulerV1::new(state, foreground.execution_budget())
            .unwrap_or_else(|error| panic!("scheduler construction failed: {error:?}"));
        let initial_checkpoint =
            ConcurrentDurableCheckpointV4::capture(&foreground, &scheduler, &sessions)
                .unwrap_or_else(|error| panic!("initial checkpoint failed: {error:?}"));
        let initial = ConcurrentDurableEvidenceV4::new(
            DurableCommitCutV1::Checkpoint,
            root_task,
            initial_checkpoint,
        )
        .unwrap_or_else(|error| panic!("initial evidence failed: {error:?}"));

        scheduler
            .cancel_execution("caller-stop")
            .unwrap_or_else(|error| panic!("scheduler cancellation failed: {error:?}"));
        assert!(foreground.cancel("caller-stop").is_some());
        let cancelled_checkpoint =
            ConcurrentDurableCheckpointV4::capture(&foreground, &scheduler, &sessions)
                .unwrap_or_else(|error| panic!("cancelled checkpoint failed: {error:?}"));
        let storage: Arc<dyn JournalStorage> = Arc::new(InMemoryJournalStore::new());
        let journal_id = JournalId::new("typed-concurrent-cancellation")
            .unwrap_or_else(|error| panic!("journal id failed: {error:?}"));
        let owner = block_on(storage.acquire_owner(AcquireJournalOwnerV1 {
            journal_id: journal_id.clone(),
            operation: JournalOwnerOperationV1::Start,
        }))
        .unwrap_or_else(|error| panic!("owner acquisition failed: {error:?}"));
        let sink = DurableTransitionSink::new(storage, journal_id.clone(), owner.token);
        let mut untyped_commits =
            DurableCommitCoordinatorV1::new(&sink, execution, root_task, None)
                .unwrap_or_else(|error| panic!("commit coordinator failed: {error:?}"));
        assert_eq!(
            block_on(untyped_commits.commit_graph_checkpoint(
                DurableCommitCutV1::Cancellation,
                root_task,
                cancelled_checkpoint.clone(),
            )),
            Err(crate::DurableCommitError::InvalidState)
        );
        let reason = CancellationReason::new(
            CancellationReasonCategory::Caller,
            Some(Arc::from("caller-stop")),
            None,
            32,
        )
        .unwrap_or_else(|error| panic!("cancellation reason failed: {error:?}"));
        let cancellation = ConcurrentDurableEvidenceV5::new_cancellation(
            root_task,
            reason.clone(),
            cancelled_checkpoint.clone(),
        )
        .unwrap_or_else(|error| panic!("cancellation evidence failed: {error:?}"));
        let recovered_initial = initial
            .checkpoint()
            .clone()
            .recover(Arc::clone(&program))
            .unwrap_or_else(|error| panic!("initial graph recovery failed: {error:?}"));
        let logical = DurableLogicalEvidenceV3::new_with_sessions(
            execution,
            root_task,
            DurableCommitCutV1::Checkpoint,
            None,
            recovered_initial.foreground(),
            Some(recovered_initial.sessions().checkpoint()),
        )
        .unwrap_or_else(|error| panic!("logical start state failed: {error:?}"));
        let start = DurableExecutionStartV3::new(
            execution,
            root_task,
            &program,
            Arc::<[u8]>::from(&b"{}"[..]),
            logical,
        )
        .unwrap_or_else(|error| panic!("execution start failed: {error:?}"));
        let start_id = ProtocolIdentity::from_storage_material([23; 32]);
        let first_id = ProtocolIdentity::from_storage_material([24; 32]);
        let second_id = ProtocolIdentity::from_storage_material([25; 32]);
        let prefix = |body: Vec<u8>, kind: &'static str| {
            JournalPrefixV1::Full(FullJournalPrefixV1 {
                journal_id: journal_id.clone(),
                evidence: Arc::from([
                    JournalEvidenceEnvelopeV1 {
                        journal_id: journal_id.clone(),
                        sequence: 1,
                        evidence_id: start_id,
                        kind: Arc::from("gantry.execution-start/v3"),
                        canonical_body: Arc::from(start.canonical_body()),
                        references: Arc::from([]),
                        protected_payloads: Arc::from([]),
                    },
                    JournalEvidenceEnvelopeV1 {
                        journal_id: journal_id.clone(),
                        sequence: 2,
                        evidence_id: first_id,
                        kind: Arc::from(CONCURRENT_DURABLE_EVIDENCE_KIND_V4),
                        canonical_body: Arc::from(initial.canonical_body()),
                        references: Arc::from([start_id]),
                        protected_payloads: Arc::from([]),
                    },
                    JournalEvidenceEnvelopeV1 {
                        journal_id: journal_id.clone(),
                        sequence: 3,
                        evidence_id: second_id,
                        kind: Arc::from(kind),
                        canonical_body: Arc::from(body),
                        references: Arc::from([first_id]),
                        protected_payloads: Arc::from([]),
                    },
                ]),
                committed_through: 3,
            })
        };

        let cancellation_prefix = prefix(
            cancellation.canonical_body(),
            CONCURRENT_DURABLE_EVIDENCE_KIND_V5,
        );
        let recovered =
            recover_concurrent_authoritative_prefix(Arc::clone(&program), &cancellation_prefix)
                .unwrap_or_else(|error| panic!("typed cancellation recovery failed: {error:?}"));
        assert_eq!(recovered.cancellation_reason(), Some(&reason));
        let JournalPrefixV1::Full(cancellation_full) = &cancellation_prefix else {
            unreachable!("fixture is a full prefix")
        };
        let compacted =
            ConcurrentDurableRecoverySnapshotV1::from_full_prefix(&program, cancellation_full)
                .unwrap_or_else(|error| panic!("cancellation compaction failed: {error:?}"));
        let snapshot_prefix = JournalPrefixV1::Snapshot(SnapshotJournalPrefixV1 {
            journal_id: journal_id.clone(),
            snapshot_version: CONCURRENT_DURABLE_SNAPSHOT_VERSION_V1,
            frontier: compacted.frontier(),
            canonical_snapshot: Arc::from(compacted.canonical_body()),
            retained_evidence: compacted.retained_evidence().clone(),
            suffix: Arc::from([]),
            committed_through: compacted.frontier(),
        });
        let recovered_snapshot =
            recover_concurrent_authoritative_prefix(Arc::clone(&program), &snapshot_prefix)
                .unwrap_or_else(|error| panic!("cancellation snapshot recovery failed: {error:?}"));
        assert_eq!(recovered_snapshot.cancellation_reason(), Some(&reason));

        let mismatched = ConcurrentDurableEvidenceV5::new_cancellation(
            root_task,
            CancellationReason::new(
                CancellationReasonCategory::Caller,
                Some(Arc::from("different")),
                None,
                32,
            )
            .unwrap_or_else(|error| panic!("mismatched reason failed: {error:?}")),
            cancelled_checkpoint.clone(),
        )
        .unwrap_or_else(|error| panic!("mismatched evidence failed: {error:?}"));
        assert_eq!(
            recover_concurrent_authoritative_prefix(
                Arc::clone(&program),
                &prefix(
                    mismatched.canonical_body(),
                    CONCURRENT_DURABLE_EVIDENCE_KIND_V5,
                ),
            )
            .map(|_| ()),
            Err(DurableEvidenceError::InvalidState)
        );

        let legacy = ConcurrentDurableEvidenceV4::new(
            DurableCommitCutV1::Cancellation,
            root_task,
            cancelled_checkpoint,
        )
        .unwrap_or_else(|error| panic!("legacy cancellation evidence failed: {error:?}"));
        assert_eq!(
            recover_concurrent_authoritative_prefix(
                program,
                &prefix(legacy.canonical_body(), CONCURRENT_DURABLE_EVIDENCE_KIND_V4,),
            )
            .map(|_| ()),
            Err(DurableEvidenceError::UnsupportedConcurrentCancellation)
        );
    }

    #[test]
    fn full_and_snapshot_concurrent_prefixes_recover_equivalent_graphs() {
        let program = program();
        let execution = fresh(IdentityKind::Execution, 25);
        let root_task = root_task_identity(execution);
        let root_session = fresh(IdentityKind::Session, 26);
        let graph = checkpoint_evidence(
            Arc::clone(&program),
            execution,
            root_task,
            root_session,
            machine_limits(),
        );
        let recovered_graph = graph
            .checkpoint()
            .clone()
            .recover(Arc::clone(&program))
            .unwrap_or_else(|error| panic!("graph checkpoint recovery failed: {error:?}"));
        let logical = DurableLogicalEvidenceV3::new_with_sessions(
            execution,
            root_task,
            DurableCommitCutV1::Checkpoint,
            None,
            recovered_graph.foreground(),
            Some(recovered_graph.sessions().checkpoint()),
        )
        .unwrap_or_else(|error| panic!("logical start state failed: {error:?}"));
        let start = DurableExecutionStartV3::new(
            execution,
            root_task,
            &program,
            Arc::<[u8]>::from(&b"{}"[..]),
            logical,
        )
        .unwrap_or_else(|error| panic!("execution start failed: {error:?}"));
        let journal_id = JournalId::new("concurrent-snapshot-equivalence")
            .unwrap_or_else(|error| panic!("journal id failed: {error:?}"));
        let start_id = ProtocolIdentity::from_storage_material([25; 32]);
        let graph_id = ProtocolIdentity::from_storage_material([26; 32]);
        let full = FullJournalPrefixV1 {
            journal_id: journal_id.clone(),
            evidence: Arc::from([
                JournalEvidenceEnvelopeV1 {
                    journal_id: journal_id.clone(),
                    sequence: 1,
                    evidence_id: start_id,
                    kind: Arc::from("gantry.execution-start/v3"),
                    canonical_body: Arc::from(start.canonical_body()),
                    references: Arc::from([]),
                    protected_payloads: Arc::from([]),
                },
                JournalEvidenceEnvelopeV1 {
                    journal_id: journal_id.clone(),
                    sequence: 2,
                    evidence_id: graph_id,
                    kind: Arc::from(CONCURRENT_DURABLE_EVIDENCE_KIND_V4),
                    canonical_body: Arc::from(graph.canonical_body()),
                    references: Arc::from([start_id]),
                    protected_payloads: Arc::from([]),
                },
            ]),
            committed_through: 2,
        };
        let full_prefix = JournalPrefixV1::Full(full.clone());
        let snapshot = ConcurrentDurableRecoverySnapshotV1::from_full_prefix(&program, &full)
            .unwrap_or_else(|error| panic!("snapshot compaction failed: {error:?}"));
        let snapshot_prefix = JournalPrefixV1::Snapshot(SnapshotJournalPrefixV1 {
            journal_id,
            snapshot_version: CONCURRENT_DURABLE_SNAPSHOT_VERSION_V1,
            frontier: snapshot.frontier(),
            canonical_snapshot: Arc::from(snapshot.canonical_body()),
            retained_evidence: snapshot.retained_evidence().clone(),
            suffix: Arc::from([]),
            committed_through: 2,
        });

        let uncompacted =
            recover_concurrent_authoritative_prefix(Arc::clone(&program), &full_prefix)
                .unwrap_or_else(|error| panic!("full recovery failed: {error:?}"));
        let compacted =
            recover_concurrent_authoritative_prefix(Arc::clone(&program), &snapshot_prefix)
                .unwrap_or_else(|error| panic!("snapshot recovery failed: {error:?}"));
        assert_eq!(compacted.latest_sequence(), uncompacted.latest_sequence());
        assert_eq!(
            compacted.latest_evidence_id(),
            uncompacted.latest_evidence_id()
        );
        assert_eq!(compacted.latest_cut(), uncompacted.latest_cut());
        assert_eq!(
            compacted.execution().foreground().checkpoint(),
            uncompacted.execution().foreground().checkpoint()
        );

        let mut malformed = snapshot.canonical_body();
        malformed.push(b' ');
        assert_eq!(
            ConcurrentDurableRecoverySnapshotV1::decode(&program, &malformed),
            Err(DurableEvidenceError::Encoding)
        );

        let JournalPrefixV1::Snapshot(mut wrong_version) = snapshot_prefix.clone() else {
            unreachable!("fixture is a snapshot prefix")
        };
        wrong_version.snapshot_version = CONCURRENT_DURABLE_SNAPSHOT_VERSION_V1 - 1;
        assert_eq!(
            recover_concurrent_authoritative_prefix(
                Arc::clone(&program),
                &JournalPrefixV1::Snapshot(wrong_version),
            )
            .map(|_| ()),
            Err(DurableEvidenceError::Encoding)
        );

        let JournalPrefixV1::Snapshot(mut mismatched_retention) = snapshot_prefix.clone() else {
            unreachable!("fixture is a snapshot prefix")
        };
        mismatched_retention.retained_evidence.remove(&start_id);
        assert_eq!(
            recover_concurrent_authoritative_prefix(
                Arc::clone(&program),
                &JournalPrefixV1::Snapshot(mismatched_retention),
            )
            .map(|_| ()),
            Err(DurableEvidenceError::InvalidCausalOrder)
        );

        let other_execution = fresh(IdentityKind::Execution, 27);
        let other_graph = checkpoint_evidence(
            Arc::clone(&program),
            other_execution,
            root_task_identity(other_execution),
            fresh(IdentityKind::Session, 28),
            machine_limits(),
        );
        let graph_hex = super::super::encode_hex(&graph.canonical_body());
        let other_graph_hex = super::super::encode_hex(&other_graph.canonical_body());
        let mixed = String::from_utf8(snapshot.canonical_body())
            .unwrap_or_else(|error| panic!("snapshot body is not UTF-8: {error}"))
            .replacen(&graph_hex, &other_graph_hex, 1)
            .into_bytes();
        assert_eq!(
            ConcurrentDurableRecoverySnapshotV1::decode(&program, &mixed),
            Err(DurableEvidenceError::MixedExecution)
        );
    }

    #[test]
    fn operation_result_rejects_outcome_for_superseded_prepared_dispatch() {
        let program = program();
        let execution = fresh(IdentityKind::Execution, 31);
        let root_task = root_task_identity(execution);
        let root_session = fresh(IdentityKind::Session, 32);
        let checkpoint = checkpoint_evidence(
            program,
            execution,
            root_task,
            root_session,
            machine_limits(),
        )
        .checkpoint()
        .clone();
        let operation_id = ProtocolIdentity::derive(IdentityKind::Operation, b"operation")
            .unwrap_or_else(|error| panic!("operation identity failed: {error}"));
        let first_dispatch = fresh(IdentityKind::Dispatch, 34);
        let retry_dispatch = fresh(IdentityKind::Dispatch, 35);
        let evidence = |cut, dispatch_id| ConcurrentDurableEvidenceV5 {
            cut,
            task_id: root_task,
            record: ConcurrentDurableEvidenceRecordV5::Operation,
            operation: Some(DurableOperationEvidenceV1 {
                operation_id,
                dispatch_id,
                validation_attempt: 0,
                recovery_dispatch: 0,
                retry_delay_us: None,
                retries_left: None,
                action_recovery: None,
                request_bytes: None,
                outcome: None,
                retry_errors: Arc::from([]),
                result_type: None,
                result_bytes: None,
            }),
            cancellation: None,
            checkpoint: checkpoint.clone(),
        };
        let mut prepared_dispatches = BTreeSet::new();
        let mut latest_prepared = BTreeMap::new();
        let mut committed_outcomes = BTreeSet::new();
        let mut latest_outcomes = BTreeMap::new();
        let mut committed_results = BTreeSet::new();
        let mut record = |evidence: &ConcurrentDurableEvidenceV5| {
            record_operation_cut(
                evidence,
                &mut prepared_dispatches,
                &mut latest_prepared,
                &mut committed_outcomes,
                &mut latest_outcomes,
                &mut committed_results,
            )
        };

        assert_eq!(
            record(&evidence(
                DurableCommitCutV1::OperationPrepared,
                Some(first_dispatch),
            )),
            Ok(())
        );
        assert_eq!(
            record(&evidence(
                DurableCommitCutV1::OperationOutcome,
                Some(first_dispatch),
            )),
            Ok(())
        );
        assert_eq!(
            record(&evidence(
                DurableCommitCutV1::RetryWaiting,
                Some(first_dispatch),
            )),
            Ok(())
        );
        assert_eq!(
            record(&evidence(
                DurableCommitCutV1::OperationPrepared,
                Some(retry_dispatch),
            )),
            Ok(())
        );
        assert_eq!(
            record(&evidence(DurableCommitCutV1::OperationResult, None)),
            Err(DurableEvidenceError::InvalidOperationTransition)
        );
    }

    fn checkpoint_evidence(
        program: Arc<MachineProgram>,
        execution: ProtocolIdentity,
        root_task: ProtocolIdentity,
        root_session: ProtocolIdentity,
        limits: MachineLimits,
    ) -> ConcurrentDurableEvidenceV4 {
        let sessions = LogicalSessionRegistryV1::new(
            execution,
            root_session,
            SessionCreationModeV1::GantryRoot,
            CanonicalTranscriptV1::empty(),
        )
        .unwrap_or_else(|error| panic!("session registry failed: {error:?}"));
        let foreground = Machine::new_with_context(
            Arc::clone(&program),
            &path("crate::main"),
            Vec::new(),
            execution,
            limits,
            None,
            Some(root_session),
        )
        .unwrap_or_else(|error| panic!("foreground machine failed: {error:?}"));
        let state = ConcurrentTaskStateV1::new(execution, root_task, 8)
            .unwrap_or_else(|error| panic!("task state failed: {error:?}"));
        let scheduler = ConcurrentSchedulerV1::new(state, foreground.execution_budget())
            .unwrap_or_else(|error| panic!("scheduler construction failed: {error:?}"));
        let checkpoint = ConcurrentDurableCheckpointV4::capture(&foreground, &scheduler, &sessions)
            .unwrap_or_else(|error| panic!("checkpoint capture failed: {error:?}"));
        ConcurrentDurableEvidenceV4::new(DurableCommitCutV1::Checkpoint, root_task, checkpoint)
            .unwrap_or_else(|error| panic!("combined evidence failed: {error:?}"))
    }

    fn program() -> Arc<MachineProgram> {
        Arc::new(
            MachineProgram::new(vec![workflow("crate::child"), workflow("crate::main")])
                .unwrap_or_else(|error| panic!("program failed: {error:?}")),
        )
    }

    fn workflow(name: &str) -> Workflow {
        Workflow {
            path: path(name),
            parameters: Vec::<Parameter>::new(),
            result: TypeDescriptor::UNIT,
            effects: EffectSet::default(),
            instructions: vec![
                Instruction {
                    site: position(0),
                    ty: TypeDescriptor::UNIT,
                    kind: InstructionKind::Push(LogicalValue::unit()),
                },
                Instruction {
                    site: position(1),
                    ty: TypeDescriptor::UNIT,
                    kind: InstructionKind::Return,
                },
            ],
        }
    }

    fn machine_limits() -> MachineLimits {
        MachineLimits::new(32, 4, 4, 8, 16, DEFAULT_VALUE_LIMITS)
            .unwrap_or_else(|| unreachable!("positive machine limits"))
    }

    fn path(value: &str) -> CanonicalPath {
        CanonicalPath::new(value).unwrap_or_else(|error| panic!("path failed: {error}"))
    }

    fn position(value: u64) -> StructuralPosition {
        StructuralPosition::new(vec![value])
            .unwrap_or_else(|error| panic!("position failed: {error}"))
    }

    fn fresh(kind: IdentityKind, byte: u8) -> ProtocolIdentity {
        ProtocolIdentity::from_fresh_material(kind, [byte; 32])
            .unwrap_or_else(|error| panic!("identity failed: {error}"))
    }

    fn block_on<F: Future>(future: F) -> F::Output {
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        let mut future = pin!(future);
        loop {
            match future.as_mut().poll(&mut context) {
                Poll::Ready(value) => return value,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }
}
