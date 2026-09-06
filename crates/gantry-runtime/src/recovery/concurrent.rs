//! Authoritative evidence for the composed concurrent-durable refinement.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use gantry_core::identity::ProtocolIdentity;
use gantry_core::portable::{
    CancellationReasonCategory, DeterministicEvaluationCode, HookFailureCategory, IdentityKind,
    RuntimeErrorCategory, TaskHandleState, TaskStatusKind,
};
use gantry_core::value::{LogicalValue, OperationErrorValue};
use gantry_host::contracts::HookOutcomeV1;
use gantry_host::journal::{
    BatchLocalEvidenceId, FullJournalPrefixV1, JournalEvidenceEnvelopeV1,
    JournalEvidenceReferenceV1, JournalId, JournalPayloadKey, JournalPrefixV1,
    UnfinalizedEvidenceV1, validate_journal_prefix,
};
use gantry_ir::generated::{OperationSiteKind, TaskControlSiteKind};
use gantry_ir::{CanonicalPath, MachineProgram, StructuralPosition};

use super::{
    CONCURRENT_DURABLE_EVIDENCE_KIND_V4, CONCURRENT_DURABLE_EVIDENCE_KIND_V5,
    DurableCommitCoordinatorV1, DurableCommitCutV1, DurableCommitError, DurableEvidenceCommitV1,
    DurableEvidenceError, DurableExecutionStartV3, DurableOperationEvidenceV1, decode_hex, field,
    object, optional_operation, optional_string, push_json_string, push_operation,
    push_optional_string, require_exact_fields, string, validate_budget_successor,
    validate_operation_evidence,
};
use crate::machine::{
    MachineDetachSuspension, MachineJoinSuspension, MachineSpawnSuspension,
    MachineTaskControlSuspension,
};
use crate::{
    CancellationCausalIdentity, CancellationReason, ConcurrentDurableCheckpointV4,
    ConcurrentSchedulerV1, ConcurrentTaskStatusV1, DURABLE_EVENT_DISPATCHED_KIND_V1,
    DURABLE_EVENT_OCCURRENCE_KIND_V1, DURABLE_EVENT_SETTLED_KIND_V1, DurableEventOccurrenceV1,
    JoinResolutionV1, LogicalSessionRegistryV1, Machine, MachineStep, OperationOccurrence,
    RecoveredConcurrentDurableExecutionV1, RecoveredDurableEventsV1, RuntimeCode,
    SessionCreationModeV1, SessionEstablishmentV1, TaskJoinFailureV1, TaskJoinMemberFailureKindV1,
    TaskJoinMemberFailureV1, TaskOwnershipChangedV1,
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
        let checkpoint = ConcurrentDurableCheckpointV4::decode_compatible(program, &bytes)
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
    /// One atomic source join, joinall, or detach ownership transfer.
    Ownership,
    /// Resolution of one named child from submitting-hidden to visible.
    SubmissionResolution,
    /// First typed execution cancellation fixed before task signalling.
    Cancellation,
}

impl ConcurrentDurableEvidenceRecordV5 {
    const fn wire_name(self) -> &'static str {
        match self {
            Self::Operation => "operation",
            Self::Ownership => "ownership",
            Self::SubmissionResolution => "submission-resolution",
            Self::Cancellation => "cancellation",
        }
    }

    fn from_wire_name(value: &str) -> Option<Self> {
        match value {
            "operation" => Some(Self::Operation),
            "ownership" => Some(Self::Ownership),
            "submission-resolution" => Some(Self::SubmissionResolution),
            "cancellation" => Some(Self::Cancellation),
            _ => None,
        }
    }
}

/// One ordered member of a version-five ownership transfer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConcurrentDurableOwnershipMemberV5 {
    handle_name: Arc<str>,
    handle_owner: ProtocolIdentity,
    handle_child: ProtocolIdentity,
    task_id: ProtocolIdentity,
}

/// Complete source-level coordinates for one atomic ownership transfer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConcurrentDurableOwnershipV5 {
    owner_task_id: ProtocolIdentity,
    workflow: CanonicalPath,
    site: StructuralPosition,
    control_kind: TaskControlSiteKind,
    disposition: TaskHandleState,
    members: Vec<ConcurrentDurableOwnershipMemberV5>,
}

impl ConcurrentDurableOwnershipV5 {
    fn from_changed(ownership: &TaskOwnershipChangedV1) -> Result<Self, DurableEvidenceError> {
        let evidence = Self {
            owner_task_id: ownership.owner_task_id(),
            workflow: ownership.control_site().workflow().clone(),
            site: ownership.control_site().position().clone(),
            control_kind: ownership.control_kind(),
            disposition: ownership.disposition(),
            members: ownership
                .members()
                .iter()
                .map(|member| ConcurrentDurableOwnershipMemberV5 {
                    handle_name: Arc::from(member.handle_name()),
                    handle_owner: member.handle_id().owner(),
                    handle_child: member.handle_id().child(),
                    task_id: member.task_id(),
                })
                .collect(),
        };
        evidence.validate()?;
        Ok(evidence)
    }

    fn validate(&self) -> Result<(), DurableEvidenceError> {
        let disposition_matches = matches!(
            (self.control_kind, self.disposition),
            (
                TaskControlSiteKind::Join | TaskControlSiteKind::JoinAll,
                TaskHandleState::Joined
            ) | (TaskControlSiteKind::Detach, TaskHandleState::Detached)
        );
        if self.owner_task_id.kind() != IdentityKind::Task
            || self.members.is_empty()
            || !disposition_matches
            || (self.control_kind == TaskControlSiteKind::Detach && self.members.len() != 1)
        {
            return Err(DurableEvidenceError::InvalidState);
        }
        let mut handles = BTreeSet::new();
        let mut tasks = BTreeSet::new();
        for member in &self.members {
            if member.handle_name.is_empty()
                || member.handle_owner != self.owner_task_id
                || member.handle_child != member.task_id
                || member.task_id.kind() != IdentityKind::Task
                || !handles.insert((member.handle_owner, member.handle_child))
                || !tasks.insert(member.task_id)
            {
                return Err(DurableEvidenceError::InvalidState);
            }
        }
        Ok(())
    }
}

/// One discriminated version-five concurrent-durable graph record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConcurrentDurableEvidenceV5 {
    cut: DurableCommitCutV1,
    task_id: ProtocolIdentity,
    record: ConcurrentDurableEvidenceRecordV5,
    operation: Option<DurableOperationEvidenceV1>,
    ownership: Option<ConcurrentDurableOwnershipV5>,
    cancellation: Option<CancellationReason>,
    checkpoint: ConcurrentDurableCheckpointV4,
}

impl ConcurrentDurableEvidenceV5 {
    /// Constructs operation evidence without changing the version-four wire contract.
    pub fn new_operation(
        cut: DurableCommitCutV1,
        task_id: ProtocolIdentity,
        operation: DurableOperationEvidenceV1,
        checkpoint: impl Into<ConcurrentDurableCheckpointV4>,
    ) -> Result<Self, DurableEvidenceError> {
        Self::new(
            cut,
            task_id,
            ConcurrentDurableEvidenceRecordV5::Operation,
            Some(operation),
            None,
            None,
            checkpoint.into(),
        )
    }

    /// Constructs one complete source join, joinall, or detach ownership record.
    pub fn new_ownership(
        task_id: ProtocolIdentity,
        checkpoint: impl Into<ConcurrentDurableCheckpointV4>,
    ) -> Result<Self, DurableEvidenceError> {
        let checkpoint = checkpoint.into();
        let ownership = ownership_from_checkpoint(&checkpoint, task_id)?
            .ok_or(DurableEvidenceError::InvalidState)?;
        Self::new(
            DurableCommitCutV1::TaskOwnership,
            task_id,
            ConcurrentDurableEvidenceRecordV5::Ownership,
            None,
            Some(ownership),
            None,
            checkpoint,
        )
    }

    /// Constructs a named child-submission resolution checkpoint.
    pub fn new_submission_resolution(
        cut: DurableCommitCutV1,
        task_id: ProtocolIdentity,
        checkpoint: impl Into<ConcurrentDurableCheckpointV4>,
    ) -> Result<Self, DurableEvidenceError> {
        Self::new(
            cut,
            task_id,
            ConcurrentDurableEvidenceRecordV5::SubmissionResolution,
            None,
            None,
            None,
            checkpoint.into(),
        )
    }

    /// Constructs a typed execution-cancellation graph checkpoint.
    pub fn new_cancellation(
        task_id: ProtocolIdentity,
        cancellation: CancellationReason,
        checkpoint: impl Into<ConcurrentDurableCheckpointV4>,
    ) -> Result<Self, DurableEvidenceError> {
        Self::new(
            DurableCommitCutV1::Cancellation,
            task_id,
            ConcurrentDurableEvidenceRecordV5::Cancellation,
            None,
            None,
            Some(cancellation),
            checkpoint.into(),
        )
    }

    fn new(
        cut: DurableCommitCutV1,
        task_id: ProtocolIdentity,
        record: ConcurrentDurableEvidenceRecordV5,
        operation: Option<DurableOperationEvidenceV1>,
        ownership: Option<ConcurrentDurableOwnershipV5>,
        cancellation: Option<CancellationReason>,
        checkpoint: ConcurrentDurableCheckpointV4,
    ) -> Result<Self, DurableEvidenceError> {
        if task_id.kind() != IdentityKind::Task || !checkpoint.contains_task(task_id) {
            return Err(DurableEvidenceError::InvalidState);
        }
        match record {
            ConcurrentDurableEvidenceRecordV5::Operation => {
                if !cut.requires_operation() || ownership.is_some() || cancellation.is_some() {
                    return Err(DurableEvidenceError::InvalidOperation);
                }
                let task_checkpoint = checkpoint
                    .task_checkpoint(task_id)
                    .ok_or(DurableEvidenceError::InvalidState)?;
                validate_operation_evidence(cut, operation.as_ref(), task_checkpoint)?;
            }
            ConcurrentDurableEvidenceRecordV5::Ownership => {
                if cut != DurableCommitCutV1::TaskOwnership
                    || operation.is_some()
                    || cancellation.is_some()
                    || ownership.as_ref().is_none_or(|ownership| {
                        ownership.members.first().map(|member| member.task_id) != Some(task_id)
                            || ownership_from_checkpoint(&checkpoint, task_id).as_ref()
                                != Ok(&Some(ownership.clone()))
                    })
                {
                    return Err(DurableEvidenceError::InvalidState);
                }
            }
            ConcurrentDurableEvidenceRecordV5::SubmissionResolution => {
                let valid = operation.is_none()
                    && ownership.is_none()
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
                    || ownership.is_some()
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
            ownership,
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

    /// Returns complete source ownership coordinates for an ownership record.
    #[must_use]
    pub const fn ownership(&self) -> Option<&ConcurrentDurableOwnershipV5> {
        self.ownership.as_ref()
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
        output.push_str(",\"ownership\":");
        push_optional_ownership(&mut output, self.ownership.as_ref());
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
                "ownership",
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
        let ownership = optional_ownership(&document, field(root, "ownership")?)?;
        let cancellation = optional_cancellation(&document, field(root, "cancellation")?)?;
        let bytes = decode_hex(string(&document, field(root, "checkpoint")?)?)?;
        let checkpoint = ConcurrentDurableCheckpointV4::decode_compatible(program, &bytes)
            .map_err(DurableEvidenceError::ConcurrentCheckpoint)?;
        if checkpoint.execution_id() != execution_id {
            return Err(DurableEvidenceError::MixedExecution);
        }
        let evidence = Self::new(
            cut,
            task_id,
            record,
            operation,
            ownership,
            cancellation,
            checkpoint,
        )?;
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

#[derive(Clone, Debug, Eq, PartialEq)]
struct ConcurrentSnapshotEvidenceV1 {
    sequence: u64,
    evidence_id: ProtocolIdentity,
    evidence: ConcurrentDurableEvidenceV5,
}

impl ConcurrentSnapshotEvidenceV1 {
    fn from_envelope(
        envelope: &JournalEvidenceEnvelopeV1,
        evidence: ConcurrentDurableEvidenceV5,
    ) -> Self {
        Self {
            sequence: envelope.sequence,
            evidence_id: envelope.evidence_id,
            evidence,
        }
    }

    fn push_canonical_json(&self, output: &mut String) {
        output.push_str("{\"body\":");
        push_json_string(output, &super::encode_hex(&self.evidence.canonical_body()));
        output.push_str(",\"evidence_id\":");
        push_json_string(output, &self.evidence_id.to_string());
        output.push_str(",\"sequence\":");
        output.push_str(&self.sequence.to_string());
        output.push('}');
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ConcurrentSnapshotLegacyGraphV1 {
    sequence: u64,
    evidence_id: ProtocolIdentity,
    evidence: ConcurrentDurableEvidenceV4,
}

impl ConcurrentSnapshotLegacyGraphV1 {
    fn from_envelope(
        envelope: &JournalEvidenceEnvelopeV1,
        evidence: ConcurrentDurableEvidenceV4,
    ) -> Self {
        Self {
            sequence: envelope.sequence,
            evidence_id: envelope.evidence_id,
            evidence,
        }
    }

    fn push_canonical_json(&self, output: &mut String) {
        output.push_str("{\"body\":");
        push_json_string(output, &super::encode_hex(&self.evidence.canonical_body()));
        output.push_str(",\"evidence_id\":");
        push_json_string(output, &self.evidence_id.to_string());
        output.push_str(",\"sequence\":");
        output.push_str(&self.sequence.to_string());
        output.push('}');
    }
}

fn bind_snapshot_evidence(
    retained: &mut BTreeMap<ProtocolIdentity, u64>,
    evidence_id: ProtocolIdentity,
    sequence: u64,
) -> Result<(), DurableEvidenceError> {
    if evidence_id.kind() != IdentityKind::Evidence || sequence == 0 {
        return Err(DurableEvidenceError::InvalidCausalOrder);
    }
    if let Some(existing) = retained.get(&evidence_id) {
        return (*existing == sequence)
            .then_some(())
            .ok_or(DurableEvidenceError::InvalidCausalOrder);
    }
    if retained.values().any(|existing| *existing == sequence) {
        return Err(DurableEvidenceError::InvalidCausalOrder);
    }
    retained.insert(evidence_id, sequence);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn represented_snapshot_evidence(
    start_evidence_id: ProtocolIdentity,
    graph_sequence: u64,
    graph_evidence_id: ProtocolIdentity,
    legacy_graphs: &[ConcurrentSnapshotLegacyGraphV1],
    operations: &[ConcurrentSnapshotEvidenceV1],
    ownership_records: &[ConcurrentSnapshotEvidenceV1],
    submission_resolutions: &[ConcurrentSnapshotEvidenceV1],
    cancellation: Option<&ConcurrentSnapshotEvidenceV1>,
    events: &[ConcurrentSnapshotEventV1],
) -> Result<BTreeMap<ProtocolIdentity, u64>, DurableEvidenceError> {
    let mut retained = BTreeMap::new();
    bind_snapshot_evidence(&mut retained, start_evidence_id, 1)?;
    bind_snapshot_evidence(&mut retained, graph_evidence_id, graph_sequence)?;
    for record in legacy_graphs {
        bind_snapshot_evidence(&mut retained, record.evidence_id, record.sequence)?;
    }
    for record in operations
        .iter()
        .chain(ownership_records)
        .chain(submission_resolutions)
    {
        bind_snapshot_evidence(&mut retained, record.evidence_id, record.sequence)?;
    }
    if let Some(record) = cancellation {
        bind_snapshot_evidence(&mut retained, record.evidence_id, record.sequence)?;
    }
    for event in events {
        bind_snapshot_evidence(&mut retained, event.evidence_id, event.sequence)?;
    }
    Ok(retained)
}

#[allow(clippy::too_many_arguments)]
fn validate_snapshot_graph_history(
    program: &MachineProgram,
    execution_start: &DurableExecutionStartV3,
    graph: &ConcurrentDurableEvidenceBody,
    graph_sequence: u64,
    graph_evidence_id: ProtocolIdentity,
    legacy_graphs: &[ConcurrentSnapshotLegacyGraphV1],
    operations: &[ConcurrentSnapshotEvidenceV1],
    ownership_records: &[ConcurrentSnapshotEvidenceV1],
    submission_resolutions: &[ConcurrentSnapshotEvidenceV1],
    cancellation: Option<&ConcurrentSnapshotEvidenceV1>,
) -> Result<(), DurableEvidenceError> {
    let mut history = BTreeMap::new();
    for record in legacy_graphs {
        if history
            .insert(
                record.sequence,
                (
                    record.evidence_id,
                    ConcurrentDurableEvidenceBody::V4(Box::new(record.evidence.clone())),
                ),
            )
            .is_some()
        {
            return Err(DurableEvidenceError::InvalidCausalOrder);
        }
    }
    for record in operations
        .iter()
        .chain(ownership_records)
        .chain(submission_resolutions)
    {
        if history
            .insert(
                record.sequence,
                (
                    record.evidence_id,
                    ConcurrentDurableEvidenceBody::V5(Box::new(record.evidence.clone())),
                ),
            )
            .is_some()
        {
            return Err(DurableEvidenceError::InvalidCausalOrder);
        }
    }
    if let Some(record) = cancellation
        && history
            .insert(
                record.sequence,
                (
                    record.evidence_id,
                    ConcurrentDurableEvidenceBody::V5(Box::new(record.evidence.clone())),
                ),
            )
            .is_some()
    {
        return Err(DurableEvidenceError::InvalidCausalOrder);
    }

    let mut records = history.iter();
    let (&first_sequence, (_, first)) = records
        .next()
        .ok_or(DurableEvidenceError::MissingRecoveryState)?;
    if first_sequence <= 1
        || first_sequence > graph_sequence
        || first.execution_id() != execution_start.execution_id()
        || first.checkpoint().root_task_id() != execution_start.task_id()
    {
        return Err(DurableEvidenceError::InvalidCausalOrder);
    }
    let valid_first_cut = match first.cut() {
        DurableCommitCutV1::Checkpoint => {
            first.task_id() == execution_start.task_id()
                && first.checkpoint().created_task_count() == 1
        }
        DurableCommitCutV1::TaskCreation => {
            first.task_id() != execution_start.task_id()
                && first.checkpoint().created_task_count() == 2
        }
        _ => false,
    };
    if !valid_first_cut {
        return Err(DurableEvidenceError::InvalidState);
    }
    validate_budget_successor(
        &execution_start.state().budget(),
        &first.checkpoint().execution_budget(),
    )?;

    let program = Arc::new(program.clone());
    let mut previous = first;
    for (&sequence, (_, current)) in records {
        if sequence > graph_sequence {
            return Err(DurableEvidenceError::InvalidCausalOrder);
        }
        validate_transition(&program, previous, current)?;
        let submission_resolution = current
            .checkpoint()
            .submission_resolution_task(&previous.checkpoint().hidden_submission_task_ids())
            .map_err(DurableEvidenceError::ConcurrentCheckpoint)?;
        if let Some(task_id) = submission_resolution {
            current
                .checkpoint()
                .validate_submission_resolution(
                    previous.checkpoint(),
                    task_id,
                    Arc::clone(&program),
                )
                .map_err(DurableEvidenceError::ConcurrentCheckpoint)?;
        }
        if let ConcurrentDurableEvidenceBody::V5(current) = current {
            match current.record() {
                ConcurrentDurableEvidenceRecordV5::Operation if submission_resolution.is_some() => {
                    return Err(DurableEvidenceError::InvalidState);
                }
                ConcurrentDurableEvidenceRecordV5::SubmissionResolution
                    if submission_resolution != Some(current.task_id()) =>
                {
                    return Err(DurableEvidenceError::InvalidState);
                }
                ConcurrentDurableEvidenceRecordV5::Cancellation
                    if submission_resolution.is_some() =>
                {
                    return Err(DurableEvidenceError::InvalidState);
                }
                _ => {}
            }
        }
        previous = current;
    }
    let (&latest_sequence, (latest_evidence_id, latest)) = history
        .last_key_value()
        .ok_or(DurableEvidenceError::MissingRecoveryState)?;
    if latest_sequence != graph_sequence
        || *latest_evidence_id != graph_evidence_id
        || latest != graph
    {
        return Err(DurableEvidenceError::InvalidCausalOrder);
    }
    Ok(())
}

/// Version-one compacted concurrent recovery state used by journal snapshot version seven.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConcurrentDurableRecoverySnapshotV1 {
    execution_start: DurableExecutionStartV3,
    start_evidence_id: ProtocolIdentity,
    graph: ConcurrentDurableEvidenceBody,
    graph_sequence: u64,
    graph_evidence_id: ProtocolIdentity,
    legacy_graphs: Arc<[ConcurrentSnapshotLegacyGraphV1]>,
    operations: Arc<[ConcurrentSnapshotEvidenceV1]>,
    ownership_records: Arc<[ConcurrentSnapshotEvidenceV1]>,
    submission_resolutions: Arc<[ConcurrentSnapshotEvidenceV1]>,
    cancellation: Option<ConcurrentSnapshotEvidenceV1>,
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
        let mut legacy_graphs = Vec::new();
        let mut operations = Vec::new();
        let mut ownership_records = Vec::new();
        let mut submission_resolutions = Vec::new();
        let mut cancellation = None;
        let mut events = Vec::new();
        for envelope in prefix.evidence.iter() {
            match envelope.kind.as_ref() {
                "gantry.execution-start/v3" => {
                    execution_start = Some(DurableExecutionStartV3::decode(
                        program,
                        &envelope.canonical_body,
                    )?);
                    start_evidence_id = Some(envelope.evidence_id);
                }
                CONCURRENT_DURABLE_EVIDENCE_KIND_V4 => {
                    let evidence =
                        ConcurrentDurableEvidenceV4::decode(program, &envelope.canonical_body)?;
                    legacy_graphs.push(ConcurrentSnapshotLegacyGraphV1::from_envelope(
                        envelope,
                        evidence.clone(),
                    ));
                    graph = Some(ConcurrentDurableEvidenceBody::V4(Box::new(evidence)));
                    graph_sequence = envelope.sequence;
                    graph_evidence_id = Some(envelope.evidence_id);
                }
                CONCURRENT_DURABLE_EVIDENCE_KIND_V5 => {
                    let evidence =
                        ConcurrentDurableEvidenceV5::decode(program, &envelope.canonical_body)?;
                    let record =
                        ConcurrentSnapshotEvidenceV1::from_envelope(envelope, evidence.clone());
                    match evidence.record() {
                        ConcurrentDurableEvidenceRecordV5::Operation => {
                            operations.push(record);
                        }
                        ConcurrentDurableEvidenceRecordV5::Ownership => {
                            ownership_records.push(record);
                        }
                        ConcurrentDurableEvidenceRecordV5::Cancellation => {
                            cancellation = Some(record);
                        }
                        ConcurrentDurableEvidenceRecordV5::SubmissionResolution => {
                            submission_resolutions.push(record);
                        }
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
        let start_evidence_id =
            start_evidence_id.ok_or(DurableEvidenceError::InvalidExecutionStart)?;
        let graph_evidence_id =
            graph_evidence_id.ok_or(DurableEvidenceError::MissingRecoveryState)?;
        let retained_evidence = represented_snapshot_evidence(
            start_evidence_id,
            graph_sequence,
            graph_evidence_id,
            &legacy_graphs,
            &operations,
            &ownership_records,
            &submission_resolutions,
            cancellation.as_ref(),
            &events,
        )?;
        Self::from_parts(
            program,
            execution_start.ok_or(DurableEvidenceError::InvalidExecutionStart)?,
            start_evidence_id,
            graph.ok_or(DurableEvidenceError::MissingRecoveryState)?,
            graph_sequence,
            graph_evidence_id,
            legacy_graphs.into(),
            operations.into(),
            ownership_records.into(),
            submission_resolutions.into(),
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
        legacy_graphs: Arc<[ConcurrentSnapshotLegacyGraphV1]>,
        operations: Arc<[ConcurrentSnapshotEvidenceV1]>,
        ownership_records: Arc<[ConcurrentSnapshotEvidenceV1]>,
        submission_resolutions: Arc<[ConcurrentSnapshotEvidenceV1]>,
        cancellation: Option<ConcurrentSnapshotEvidenceV1>,
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
        {
            return Err(DurableEvidenceError::MixedExecution);
        }
        let represented_evidence = represented_snapshot_evidence(
            start_evidence_id,
            graph_sequence,
            graph_evidence_id,
            &legacy_graphs,
            &operations,
            &ownership_records,
            &submission_resolutions,
            cancellation.as_ref(),
            &events,
        )?;
        if retained_evidence != represented_evidence
            || retained_evidence.get(&frontier_evidence_id) != Some(&frontier)
        {
            return Err(DurableEvidenceError::InvalidCausalOrder);
        }
        validate_snapshot_graph_history(
            program,
            &execution_start,
            &graph,
            graph_sequence,
            graph_evidence_id,
            &legacy_graphs,
            &operations,
            &ownership_records,
            &submission_resolutions,
            cancellation.as_ref(),
        )?;
        validate_budget_successor(
            &execution_start.state().budget(),
            &graph.checkpoint().execution_budget(),
        )?;
        let mut prepared_dispatches = BTreeSet::new();
        let mut latest_prepared = BTreeMap::new();
        let mut committed_outcomes = BTreeSet::new();
        let mut latest_outcomes = BTreeMap::new();
        let mut committed_results = BTreeSet::new();
        let mut previous_operation_sequence = 0;
        for operation in operations.iter() {
            if operation.sequence <= previous_operation_sequence
                || operation.sequence > graph_sequence
                || operation.evidence.execution_id() != execution_start.execution_id()
                || operation.evidence.record() != ConcurrentDurableEvidenceRecordV5::Operation
            {
                return Err(DurableEvidenceError::InvalidCausalOrder);
            }
            record_operation_cut(
                &operation.evidence,
                &mut prepared_dispatches,
                &mut latest_prepared,
                &mut committed_outcomes,
                &mut latest_outcomes,
                &mut committed_results,
            )?;
            previous_operation_sequence = operation.sequence;
        }
        let mut previous_ownership_sequence = 0;
        for ownership in ownership_records.iter() {
            if ownership.sequence <= previous_ownership_sequence
                || ownership.sequence > graph_sequence
                || ownership.evidence.execution_id() != execution_start.execution_id()
                || ownership.evidence.record() != ConcurrentDurableEvidenceRecordV5::Ownership
            {
                return Err(DurableEvidenceError::InvalidCausalOrder);
            }
            previous_ownership_sequence = ownership.sequence;
        }
        let mut previous_submission_sequence = 0;
        for submission in submission_resolutions.iter() {
            if submission.sequence <= previous_submission_sequence
                || submission.sequence > graph_sequence
                || submission.evidence.execution_id() != execution_start.execution_id()
                || submission.evidence.record()
                    != ConcurrentDurableEvidenceRecordV5::SubmissionResolution
            {
                return Err(DurableEvidenceError::InvalidCausalOrder);
            }
            previous_submission_sequence = submission.sequence;
        }
        if let Some(cancellation) = &cancellation
            && (cancellation.sequence > graph_sequence
                || cancellation.evidence.execution_id() != execution_start.execution_id()
                || cancellation.evidence.record()
                    != ConcurrentDurableEvidenceRecordV5::Cancellation)
        {
            return Err(DurableEvidenceError::InvalidCausalOrder);
        }
        if let ConcurrentDurableEvidenceBody::V5(graph_record) = &graph {
            let bound = match graph_record.record() {
                ConcurrentDurableEvidenceRecordV5::Operation => operations.iter().any(|record| {
                    record.sequence == graph_sequence
                        && record.evidence_id == graph_evidence_id
                        && record.evidence == **graph_record
                }),
                ConcurrentDurableEvidenceRecordV5::Ownership => {
                    ownership_records.iter().any(|record| {
                        record.sequence == graph_sequence
                            && record.evidence_id == graph_evidence_id
                            && record.evidence == **graph_record
                    })
                }
                ConcurrentDurableEvidenceRecordV5::SubmissionResolution => {
                    submission_resolutions.iter().any(|record| {
                        record.sequence == graph_sequence
                            && record.evidence_id == graph_evidence_id
                            && record.evidence == **graph_record
                    })
                }
                ConcurrentDurableEvidenceRecordV5::Cancellation => {
                    cancellation.as_ref().is_some_and(|record| {
                        record.sequence == graph_sequence
                            && record.evidence_id == graph_evidence_id
                            && record.evidence == **graph_record
                    })
                }
            };
            if !bound {
                return Err(DurableEvidenceError::InvalidCausalOrder);
            }
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
                .evidence
                .cancellation()
                .ok_or(DurableEvidenceError::InvalidState)?;
            let expected = reason
                .message
                .as_deref()
                .unwrap_or_else(|| reason.category.wire_name());
            if execution
                .scheduler()
                .state()
                .task_cancellation_reason(cancellation.evidence.task_id())
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
            legacy_graphs,
            operations,
            ownership_records,
            submission_resolutions,
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
            Some(cancellation) => cancellation.push_canonical_json(&mut output),
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
        output.push_str(",\"legacy_graphs\":[");
        for (index, legacy_graph) in self.legacy_graphs.iter().enumerate() {
            if index != 0 {
                output.push(',');
            }
            legacy_graph.push_canonical_json(&mut output);
        }
        output.push_str("],\"operations\":[");
        for (index, operation) in self.operations.iter().enumerate() {
            if index != 0 {
                output.push(',');
            }
            operation.push_canonical_json(&mut output);
        }
        output.push_str("],\"ownership_records\":[");
        for (index, ownership) in self.ownership_records.iter().enumerate() {
            if index != 0 {
                output.push(',');
            }
            ownership.push_canonical_json(&mut output);
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
        output.push_str(",\"submission_resolutions\":[");
        for (index, submission) in self.submission_resolutions.iter().enumerate() {
            if index != 0 {
                output.push(',');
            }
            submission.push_canonical_json(&mut output);
        }
        output.push(']');
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
                "legacy_graphs",
                "operations",
                "ownership_records",
                "retained_evidence",
                "start_evidence_id",
                "submission_resolutions",
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
        let legacy_graphs = snapshot_array(&document, field(root, "legacy_graphs")?)?
            .iter()
            .map(|item| decode_snapshot_legacy_graph(&document, *item, program))
            .collect::<Result<Vec<_>, _>>()?;
        let cancellation =
            match document.node(field(root, "cancellation")?) {
                Some(gantry_core::strict_json::JsonNode::Null) => None,
                Some(gantry_core::strict_json::JsonNode::Object(_)) => Some(
                    decode_snapshot_evidence(&document, field(root, "cancellation")?, program)?,
                ),
                _ => return Err(DurableEvidenceError::Encoding),
            };
        let operations = snapshot_array(&document, field(root, "operations")?)?
            .iter()
            .map(|item| decode_snapshot_evidence(&document, *item, program))
            .collect::<Result<Vec<_>, _>>()?;
        let ownership_records = snapshot_array(&document, field(root, "ownership_records")?)?
            .iter()
            .map(|item| decode_snapshot_evidence(&document, *item, program))
            .collect::<Result<Vec<_>, _>>()?;
        let submission_resolutions =
            snapshot_array(&document, field(root, "submission_resolutions")?)?
                .iter()
                .map(|item| decode_snapshot_evidence(&document, *item, program))
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
            legacy_graphs.into(),
            operations.into(),
            ownership_records.into(),
            submission_resolutions.into(),
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
                "legacy_graphs",
                "operations",
                "ownership_records",
                "retained_evidence",
                "start_evidence_id",
                "submission_resolutions",
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

fn decode_snapshot_legacy_graph(
    document: &gantry_core::strict_json::StrictJsonDocument,
    id: gantry_core::strict_json::JsonNodeId,
    program: &MachineProgram,
) -> Result<ConcurrentSnapshotLegacyGraphV1, DurableEvidenceError> {
    let record = object(document, id)?;
    require_exact_fields(record, &["body", "evidence_id", "sequence"])?;
    Ok(ConcurrentSnapshotLegacyGraphV1 {
        sequence: snapshot_unsigned(document, field(record, "sequence")?)?,
        evidence_id: snapshot_identity(
            document,
            field(record, "evidence_id")?,
            IdentityKind::Evidence,
        )?,
        evidence: ConcurrentDurableEvidenceV4::decode(
            program,
            &decode_hex(string(document, field(record, "body")?)?)?,
        )?,
    })
}

fn decode_snapshot_evidence(
    document: &gantry_core::strict_json::StrictJsonDocument,
    id: gantry_core::strict_json::JsonNodeId,
    program: &MachineProgram,
) -> Result<ConcurrentSnapshotEvidenceV1, DurableEvidenceError> {
    let record = object(document, id)?;
    require_exact_fields(record, &["body", "evidence_id", "sequence"])?;
    Ok(ConcurrentSnapshotEvidenceV1 {
        sequence: snapshot_unsigned(document, field(record, "sequence")?)?,
        evidence_id: snapshot_identity(
            document,
            field(record, "evidence_id")?,
            IdentityKind::Evidence,
        )?,
        evidence: ConcurrentDurableEvidenceV5::decode(
            program,
            &decode_hex(string(document, field(record, "body")?)?)?,
        )?,
    })
}

fn push_optional_ownership(output: &mut String, ownership: Option<&ConcurrentDurableOwnershipV5>) {
    let Some(ownership) = ownership else {
        output.push_str("null");
        return;
    };
    output.push_str("{\"control_kind\":");
    push_json_string(output, ownership.control_kind.wire_name());
    output.push_str(",\"disposition\":");
    push_json_string(output, ownership.disposition.wire_name());
    output.push_str(",\"members\":[");
    for (index, member) in ownership.members.iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        output.push_str("{\"handle_child\":");
        push_json_string(output, &member.handle_child.to_string());
        output.push_str(",\"handle_name\":");
        push_json_string(output, &member.handle_name);
        output.push_str(",\"handle_owner\":");
        push_json_string(output, &member.handle_owner.to_string());
        output.push_str(",\"task_id\":");
        push_json_string(output, &member.task_id.to_string());
        output.push('}');
    }
    output.push_str("],\"owner_task_id\":");
    push_json_string(output, &ownership.owner_task_id.to_string());
    output.push_str(",\"site\":[");
    for (index, component) in ownership.site.components().iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        output.push_str(&component.to_string());
    }
    output.push_str("],\"workflow\":");
    push_json_string(output, ownership.workflow.as_str());
    output.push('}');
}

fn optional_ownership(
    document: &gantry_core::strict_json::StrictJsonDocument,
    id: gantry_core::strict_json::JsonNodeId,
) -> Result<Option<ConcurrentDurableOwnershipV5>, DurableEvidenceError> {
    let Some(node) = document.node(id) else {
        return Err(DurableEvidenceError::Encoding);
    };
    let gantry_core::strict_json::JsonNode::Object(value) = node else {
        return match node {
            gantry_core::strict_json::JsonNode::Null => Ok(None),
            _ => Err(DurableEvidenceError::Encoding),
        };
    };
    require_exact_fields(
        value,
        &[
            "control_kind",
            "disposition",
            "members",
            "owner_task_id",
            "site",
            "workflow",
        ],
    )?;
    let control_kind = match string(document, field(value, "control_kind")?)? {
        "join" => TaskControlSiteKind::Join,
        "joinall" => TaskControlSiteKind::JoinAll,
        "detach" => TaskControlSiteKind::Detach,
        _ => return Err(DurableEvidenceError::Encoding),
    };
    let disposition =
        TaskHandleState::from_wire_name(string(document, field(value, "disposition")?)?)
            .ok_or(DurableEvidenceError::Encoding)?;
    let members = snapshot_array(document, field(value, "members")?)?
        .iter()
        .map(|id| {
            let member = object(document, *id)?;
            require_exact_fields(
                member,
                &["handle_child", "handle_name", "handle_owner", "task_id"],
            )?;
            Ok(ConcurrentDurableOwnershipMemberV5 {
                handle_name: Arc::from(string(document, field(member, "handle_name")?)?),
                handle_owner: snapshot_identity(
                    document,
                    field(member, "handle_owner")?,
                    IdentityKind::Task,
                )?,
                handle_child: snapshot_identity(
                    document,
                    field(member, "handle_child")?,
                    IdentityKind::Task,
                )?,
                task_id: snapshot_identity(
                    document,
                    field(member, "task_id")?,
                    IdentityKind::Task,
                )?,
            })
        })
        .collect::<Result<Vec<_>, DurableEvidenceError>>()?;
    let site = StructuralPosition::new(
        snapshot_array(document, field(value, "site")?)?
            .iter()
            .map(|id| snapshot_unsigned(document, *id))
            .collect::<Result<Vec<_>, _>>()?,
    )
    .map_err(|_| DurableEvidenceError::Encoding)?;
    let ownership = ConcurrentDurableOwnershipV5 {
        owner_task_id: snapshot_identity(
            document,
            field(value, "owner_task_id")?,
            IdentityKind::Task,
        )?,
        workflow: CanonicalPath::new(string(document, field(value, "workflow")?)?)
            .map_err(|_| DurableEvidenceError::Encoding)?,
        site,
        control_kind,
        disposition,
        members,
    };
    ownership.validate()?;
    Ok(Some(ownership))
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
            (None, false, None) if cut == DurableCommitCutV1::TaskOwnership => {
                ConcurrentDurableEvidenceV5::new_ownership(affected_task, checkpoint)
                    .and_then(|evidence| evidence.unfinalized(local_id.clone(), references))
            }
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
                &operation.evidence,
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
                    .evidence
                    .cancellation()
                    .cloned()
                    .ok_or(DurableEvidenceError::InvalidState)?,
            );
            cancellation_task = Some(record.evidence.task_id());
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
                ConcurrentDurableEvidenceBody::V4(Box::new(evidence))
            } else {
                ConcurrentDurableEvidenceV5::decode(&program, &envelope.canonical_body)
                    .map(Box::new)
                    .map(ConcurrentDurableEvidenceBody::V5)?
            };
            if let Some(prior) = &latest_graph {
                validate_transition(&program, prior, &evidence)?;
                let submission_resolution = evidence
                    .checkpoint()
                    .submission_resolution_task(&prior.checkpoint().hidden_submission_task_ids())
                    .map_err(DurableEvidenceError::ConcurrentCheckpoint)?;
                if let Some(task_id) = submission_resolution {
                    evidence
                        .checkpoint()
                        .validate_submission_resolution(
                            prior.checkpoint(),
                            task_id,
                            Arc::clone(&program),
                        )
                        .map_err(DurableEvidenceError::ConcurrentCheckpoint)?;
                }
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
                        ConcurrentDurableEvidenceRecordV5::Ownership => {
                            if submission_resolution.is_some() {
                                return Err(DurableEvidenceError::InvalidState);
                            }
                        }
                        ConcurrentDurableEvidenceRecordV5::SubmissionResolution => {
                            if submission_resolution != Some(current.task_id()) {
                                return Err(DurableEvidenceError::InvalidState);
                            }
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
    program: &MachineProgram,
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
        DurableCommitCutV1::Checkpoint => {
            previous_tasks == current_tasks
                && validate_checkpoint_transition(program, previous, current)?
        }
        DurableCommitCutV1::TaskCreation => {
            current.checkpoint().created_task_count()
                == previous.checkpoint().created_task_count().saturating_add(1)
                && current_tasks
                    .difference(&previous_tasks)
                    .copied()
                    .collect::<Vec<_>>()
                    == [current.task_id()]
        }
        DurableCommitCutV1::TaskOwnership => validate_task_ownership_transition(
            program,
            previous.checkpoint(),
            current,
            current.task_id(),
        )?,
        DurableCommitCutV1::Cancellation => match current {
            ConcurrentDurableEvidenceBody::V4(_) => {
                previous_tasks == current_tasks
                    && !previous.checkpoint().task_is_cancelled(current.task_id())
                    && current.checkpoint().task_is_cancelled(current.task_id())
            }
            ConcurrentDurableEvidenceBody::V5(_) => {
                validate_execution_cancellation_transition(program, previous, current)?
            }
        },
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

fn validate_checkpoint_transition(
    program: &MachineProgram,
    previous: &ConcurrentDurableEvidenceBody,
    current: &ConcurrentDurableEvidenceBody,
) -> Result<bool, DurableEvidenceError> {
    let previous_checkpoint = previous.checkpoint();
    let current_checkpoint = current.checkpoint();
    let submission_resolution = current_checkpoint
        .submission_resolution_task(&previous_checkpoint.hidden_submission_task_ids())
        .map_err(DurableEvidenceError::ConcurrentCheckpoint)?;
    if let Some(task_id) = submission_resolution {
        if matches!(
            current,
            ConcurrentDurableEvidenceBody::V5(evidence)
                if evidence.record()
                    == ConcurrentDurableEvidenceRecordV5::SubmissionResolution
                    && evidence.task_id() == task_id
        ) || matches!(current, ConcurrentDurableEvidenceBody::V4(_))
        {
            return current_checkpoint
                .validate_submission_resolution(
                    previous_checkpoint,
                    task_id,
                    Arc::new(program.clone()),
                )
                .map(|()| true)
                .map_err(DurableEvidenceError::ConcurrentCheckpoint);
        }
        return Ok(false);
    }
    if matches!(current, ConcurrentDurableEvidenceBody::V5(_)) {
        return Ok(false);
    }

    let recovered = previous_checkpoint
        .clone()
        .recover(Arc::new(program.clone()))
        .map_err(DurableEvidenceError::ConcurrentCheckpoint)?;
    if previous_checkpoint == current_checkpoint {
        return if matches!(
            previous.cut(),
            DurableCommitCutV1::TaskOwnership | DurableCommitCutV1::TaskSettlement
        ) {
            checkpoint_causal_settlement_ready(&recovered)
        } else {
            Ok(false)
        };
    }
    if previous.cut() == DurableCommitCutV1::Checkpoint
        && replay_task_control_checkpoint(program, previous_checkpoint, current_checkpoint)?
    {
        return Ok(true);
    }
    replay_machine_checkpoint(program, previous, current_checkpoint)
}

#[derive(Clone)]
enum CheckpointMachineBoundary {
    TaskControl(MachineTaskControlSuspension),
    Operation(OperationOccurrence),
}

fn replay_machine_checkpoint(
    program: &MachineProgram,
    previous: &ConcurrentDurableEvidenceBody,
    current: &ConcurrentDurableCheckpointV4,
) -> Result<bool, DurableEvidenceError> {
    let previous_checkpoint = previous.checkpoint();
    let transition_delta = current
        .execution_budget()
        .revision
        .checked_sub(previous_checkpoint.execution_budget().revision)
        .ok_or(DurableEvidenceError::InvalidExecutionBudget)?;
    for task_id in previous_checkpoint.task_ids() {
        let mut boundary = previous_checkpoint
            .clone()
            .recover(Arc::new(program.clone()))
            .map_err(DurableEvidenceError::ConcurrentCheckpoint)?;
        let Some(boundary_kind) = advance_to_checkpoint_boundary(
            &mut boundary,
            task_id,
            transition_delta.saturating_add(1),
        )?
        else {
            continue;
        };
        let boundary_checkpoint = capture_recovered_checkpoint(&boundary)?;
        match boundary_kind {
            CheckpointMachineBoundary::TaskControl(pending) => {
                if let Some((join, join_all)) = pending.join()
                    && join_all
                    && join.handles.is_empty()
                    && boundary_checkpoint == *current
                {
                    return Ok(true);
                }
                if let Some(spawn) = pending.spawn()
                    && replay_spawn_failure_checkpoint(
                        program,
                        &boundary_checkpoint,
                        current,
                        task_id,
                        spawn,
                    )?
                {
                    return Ok(true);
                }
            }
            CheckpointMachineBoundary::Operation(operation) => {
                if replay_operation_session_checkpoint(
                    program,
                    &boundary_checkpoint,
                    current,
                    task_id,
                    &operation,
                )? || replay_operation_failure_checkpoint(
                    program,
                    previous,
                    &boundary_checkpoint,
                    current,
                    task_id,
                    &operation,
                )? {
                    return Ok(true);
                }
            }
        }
    }
    Ok(false)
}

fn advance_to_checkpoint_boundary(
    execution: &mut RecoveredConcurrentDurableExecutionV1,
    task_id: ProtocolIdentity,
    maximum_steps: u64,
) -> Result<Option<CheckpointMachineBoundary>, DurableEvidenceError> {
    for _ in 0..=maximum_steps {
        let machine =
            recovered_machine_mut(execution, task_id).ok_or(DurableEvidenceError::InvalidState)?;
        if let Some(pending) = machine.pending_task_control().cloned() {
            return Ok(Some(CheckpointMachineBoundary::TaskControl(pending)));
        }
        match machine.step() {
            MachineStep::Transition(crate::MachineLabel::Deterministic { .. }) => {}
            MachineStep::Transition(crate::MachineLabel::TaskControlSuspended(spawn)) => {
                return Ok(Some(CheckpointMachineBoundary::TaskControl(
                    MachineTaskControlSuspension::Spawn(spawn),
                )));
            }
            MachineStep::WaitingOperation(operation) => {
                return Ok(Some(CheckpointMachineBoundary::Operation(operation)));
            }
            MachineStep::YieldRequired => {
                if !machine.resume_after_yield() {
                    return Err(DurableEvidenceError::InvalidState);
                }
            }
            MachineStep::WaitingSessionScope(_)
            | MachineStep::Complete(_)
            | MachineStep::Transition(_) => return Ok(None),
        }
    }
    Ok(None)
}

fn capture_recovered_checkpoint(
    execution: &RecoveredConcurrentDurableExecutionV1,
) -> Result<ConcurrentDurableCheckpointV4, DurableEvidenceError> {
    ConcurrentDurableCheckpointV4::capture(
        execution.foreground(),
        execution.scheduler(),
        execution.sessions(),
    )
    .map_err(DurableEvidenceError::ConcurrentCheckpoint)
}

fn replay_spawn_failure_checkpoint(
    program: &MachineProgram,
    boundary: &ConcurrentDurableCheckpointV4,
    current: &ConcurrentDurableCheckpointV4,
    task_id: ProtocolIdentity,
    spawn: &MachineSpawnSuspension,
) -> Result<bool, DurableEvidenceError> {
    let recovered = boundary
        .clone()
        .recover(Arc::new(program.clone()))
        .map_err(DurableEvidenceError::ConcurrentCheckpoint)?;
    let task_limit_reached = recovered
        .scheduler()
        .state()
        .created_task_count()
        .checked_add(1)
        .is_none_or(|next| next > recovered.scheduler().state().maximum_task_count());
    if task_limit_reached
        && replay_spawn_failure_candidate(
            program,
            boundary,
            current,
            task_id,
            spawn,
            RuntimeCode::Deterministic(DeterministicEvaluationCode::TaskCountLimit),
        )?
    {
        return Ok(true);
    }
    let session_setup_can_fail = spawn
        .parent_session
        .and_then(|session_id| recovered.sessions().get(session_id))
        .is_some_and(|session| session.establishment == SessionEstablishmentV1::Separate);
    session_setup_can_fail
        .then(|| {
            replay_spawn_failure_candidate(
                program,
                boundary,
                current,
                task_id,
                spawn,
                RuntimeCode::Operation(RuntimeErrorCategory::LogicalSessionSetup),
            )
        })
        .transpose()
        .map(Option::unwrap_or_default)
}

fn replay_spawn_failure_candidate(
    program: &MachineProgram,
    boundary: &ConcurrentDurableCheckpointV4,
    current: &ConcurrentDurableCheckpointV4,
    task_id: ProtocolIdentity,
    spawn: &MachineSpawnSuspension,
    code: RuntimeCode,
) -> Result<bool, DurableEvidenceError> {
    let mut expected = boundary
        .clone()
        .recover(Arc::new(program.clone()))
        .map_err(DurableEvidenceError::ConcurrentCheckpoint)?;
    recovered_machine_mut(&mut expected, task_id)
        .ok_or(DurableEvidenceError::InvalidState)?
        .fail_spawn(spawn, code)
        .map_err(|_| DurableEvidenceError::InvalidState)?;
    capture_recovered_checkpoint(&expected).map(|checkpoint| checkpoint == *current)
}

fn replay_operation_session_checkpoint(
    program: &MachineProgram,
    boundary: &ConcurrentDurableCheckpointV4,
    current: &ConcurrentDurableCheckpointV4,
    task_id: ProtocolIdentity,
    operation: &OperationOccurrence,
) -> Result<bool, DurableEvidenceError> {
    let Some(metadata) = operation.metadata.as_ref() else {
        return Ok(false);
    };
    let mode = match metadata.session_mode.as_deref() {
        Some("new") => SessionCreationModeV1::New,
        Some("fork") => SessionCreationModeV1::Fork,
        _ => return Ok(false),
    };
    if metadata.kind == OperationSiteKind::Action {
        return Ok(false);
    }
    let current_execution = current
        .clone()
        .recover(Arc::new(program.clone()))
        .map_err(DurableEvidenceError::ConcurrentCheckpoint)?;
    let boundary_execution = boundary
        .clone()
        .recover(Arc::new(program.clone()))
        .map_err(DurableEvidenceError::ConcurrentCheckpoint)?;
    let added = current_execution
        .sessions()
        .sessions()
        .filter(|session| boundary_execution.sessions().get(session.id).is_none())
        .cloned()
        .collect::<Vec<_>>();
    let [session] = added.as_slice() else {
        return Ok(false);
    };
    if current_execution.sessions().sessions().count()
        != boundary_execution
            .sessions()
            .sessions()
            .count()
            .saturating_add(1)
        || session.parent != operation.active_session
        || session.mode != mode
        || session.establishment != SessionEstablishmentV1::OperationRequest
        || session.creator_task != Some(task_id)
        || session.creation_site.as_ref() != Some(&operation.site)
    {
        return Ok(false);
    }
    let Some(parent) = operation.active_session else {
        return Ok(false);
    };
    let occurrence = session
        .creation_occurrence
        .ok_or(DurableEvidenceError::InvalidState)?;
    let mut expected = boundary_execution;
    expected
        .sessions_mut()
        .create(
            parent,
            task_id,
            operation.site.clone(),
            occurrence,
            mode,
            SessionEstablishmentV1::OperationRequest,
        )
        .map_err(|_| DurableEvidenceError::InvalidState)?;
    capture_recovered_checkpoint(&expected).map(|checkpoint| checkpoint == *current)
}

fn replay_operation_failure_checkpoint(
    program: &MachineProgram,
    previous: &ConcurrentDurableEvidenceBody,
    boundary: &ConcurrentDurableCheckpointV4,
    current: &ConcurrentDurableCheckpointV4,
    task_id: ProtocolIdentity,
    operation: &OperationOccurrence,
) -> Result<bool, DurableEvidenceError> {
    if rendered_operation_exceeds_limit(boundary, task_id, operation)?
        && replay_operation_failure_candidate(
            program,
            boundary,
            current,
            task_id,
            operation.identity,
            RuntimeCode::Deterministic(DeterministicEvaluationCode::StringSizeLimit),
        )?
    {
        return Ok(true);
    }
    let Some(evidence) = (match previous {
        ConcurrentDurableEvidenceBody::V5(evidence)
            if evidence.record() == ConcurrentDurableEvidenceRecordV5::Operation
                && evidence.task_id() == task_id =>
        {
            evidence.operation()
        }
        _ => None,
    }) else {
        return Ok(false);
    };
    if evidence.operation_id != operation.identity {
        return Ok(false);
    }
    match previous.cut() {
        DurableCommitCutV1::OperationPrepared => {
            let categories: &[RuntimeErrorCategory] =
                match operation.metadata.as_ref().map(|metadata| metadata.kind) {
                    Some(OperationSiteKind::Action) => &[
                        RuntimeErrorCategory::HookCreation,
                        RuntimeErrorCategory::HookFailure,
                    ],
                    Some(OperationSiteKind::Prompt | OperationSiteKind::Decide) => &[
                        RuntimeErrorCategory::Cancellation,
                        RuntimeErrorCategory::LogicalSessionSetup,
                        RuntimeErrorCategory::HookCreation,
                        RuntimeErrorCategory::HookFailure,
                    ],
                    None => return Ok(false),
                };
            for category in categories {
                if replay_operation_failure_candidate(
                    program,
                    boundary,
                    current,
                    task_id,
                    operation.identity,
                    RuntimeCode::Operation(*category),
                )? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        DurableCommitCutV1::OperationOutcome => replay_operation_outcome_failure(
            program, boundary, current, task_id, operation, evidence,
        ),
        DurableCommitCutV1::RetryWaiting => replay_operation_failure_candidate(
            program,
            boundary,
            current,
            task_id,
            operation.identity,
            RuntimeCode::Operation(RuntimeErrorCategory::ExecutorFailure),
        ),
        _ => Ok(false),
    }
}

fn rendered_operation_exceeds_limit(
    boundary: &ConcurrentDurableCheckpointV4,
    task_id: ProtocolIdentity,
    operation: &OperationOccurrence,
) -> Result<bool, DurableEvidenceError> {
    let Some(metadata) = operation.metadata.as_ref() else {
        return Ok(false);
    };
    if metadata.kind == OperationSiteKind::Action {
        return Ok(false);
    }
    let interpolation_count = metadata.interpolation_types.len();
    if metadata.template_segments.len() != interpolation_count.saturating_add(1)
        || operation.inputs.len() < interpolation_count
    {
        return Ok(false);
    }
    let maximum = boundary
        .task_checkpoint(task_id)
        .ok_or(DurableEvidenceError::InvalidState)?
        .value_limits()
        .maximum_string_scalars();
    let mut scalars = 0_u64;
    for (index, input) in operation
        .inputs
        .iter()
        .take(interpolation_count)
        .enumerate()
    {
        scalars = scalars.saturating_add(
            u64::try_from(metadata.template_segments[index].chars().count()).unwrap_or(u64::MAX),
        );
        let rendered_scalars = if let Some(value) = input.as_string() {
            value.chars().count()
        } else {
            let canonical = input.canonical_json();
            let Ok(value) = std::str::from_utf8(canonical.bytes()) else {
                return Ok(false);
            };
            value.chars().count()
        };
        scalars = scalars.saturating_add(u64::try_from(rendered_scalars).unwrap_or(u64::MAX));
    }
    scalars = scalars.saturating_add(metadata.template_segments.last().map_or(0, |segment| {
        u64::try_from(segment.chars().count()).unwrap_or(u64::MAX)
    }));
    Ok(scalars > maximum)
}

fn replay_operation_outcome_failure(
    program: &MachineProgram,
    boundary: &ConcurrentDurableCheckpointV4,
    current: &ConcurrentDurableCheckpointV4,
    task_id: ProtocolIdentity,
    operation: &OperationOccurrence,
    evidence: &DurableOperationEvidenceV1,
) -> Result<bool, DurableEvidenceError> {
    let Some(outcome) = evidence.outcome.as_ref() else {
        return Ok(false);
    };
    let action = operation
        .metadata
        .as_ref()
        .is_some_and(|metadata| metadata.kind == OperationSiteKind::Action);
    let (category, error) = match outcome {
        HookOutcomeV1::Completed(_) => return Ok(false),
        HookOutcomeV1::Declined(message) if !message.is_empty() => (
            RuntimeErrorCategory::RequiredResultDecline,
            Some(OperationErrorValue::Declined(message.to_string())),
        ),
        HookOutcomeV1::Declined(_) => (RuntimeErrorCategory::HookFailure, None),
        HookOutcomeV1::Failed { category, message } if !message.is_empty() => match category {
            HookFailureCategory::Cancelled => (
                RuntimeErrorCategory::Cancellation,
                Some(OperationErrorValue::Cancelled(message.to_string())),
            ),
            HookFailureCategory::PolicyDenied => (
                RuntimeErrorCategory::PolicyDenied,
                Some(OperationErrorValue::PolicyDenied(message.to_string())),
            ),
            HookFailureCategory::ProviderFailure => (
                RuntimeErrorCategory::ProviderFailure,
                Some(OperationErrorValue::ProviderFailure(message.to_string())),
            ),
            HookFailureCategory::Timeout => (
                RuntimeErrorCategory::Timeout,
                Some(OperationErrorValue::Timeout(message.to_string())),
            ),
            HookFailureCategory::UnknownOutcome if action => (
                RuntimeErrorCategory::UnknownActionOutcome,
                Some(OperationErrorValue::UnknownOutcome {
                    operation_id: operation.identity.to_string(),
                    message: message.to_string(),
                }),
            ),
            HookFailureCategory::UnknownOutcome => (RuntimeErrorCategory::HookFailure, None),
        },
        HookOutcomeV1::Failed { .. } => (RuntimeErrorCategory::HookFailure, None),
    };
    let attempted = operation
        .metadata
        .as_ref()
        .is_some_and(|metadata| metadata.attempted);
    if attempted && let Some(error) = error {
        return replay_attempt_failure_candidate(
            program,
            boundary,
            current,
            task_id,
            operation.identity,
            error,
        );
    }
    replay_operation_failure_candidate(
        program,
        boundary,
        current,
        task_id,
        operation.identity,
        RuntimeCode::Operation(category),
    )
}

fn replay_attempt_failure_candidate(
    program: &MachineProgram,
    boundary: &ConcurrentDurableCheckpointV4,
    current: &ConcurrentDurableCheckpointV4,
    task_id: ProtocolIdentity,
    operation_id: ProtocolIdentity,
    error: OperationErrorValue,
) -> Result<bool, DurableEvidenceError> {
    let limits = boundary
        .task_checkpoint(task_id)
        .ok_or(DurableEvidenceError::InvalidState)?
        .value_limits();
    let error = LogicalValue::operation_error(error, limits)
        .and_then(|error| LogicalValue::err(error, limits))
        .map_err(|_| DurableEvidenceError::InvalidState)?;
    let mut expected = boundary
        .clone()
        .recover(Arc::new(program.clone()))
        .map_err(DurableEvidenceError::ConcurrentCheckpoint)?;
    recovered_machine_mut(&mut expected, task_id)
        .ok_or(DurableEvidenceError::InvalidState)?
        .complete_operation(operation_id, error)
        .map_err(|_| DurableEvidenceError::InvalidState)?;
    capture_recovered_checkpoint(&expected).map(|checkpoint| checkpoint == *current)
}

fn replay_operation_failure_candidate(
    program: &MachineProgram,
    boundary: &ConcurrentDurableCheckpointV4,
    current: &ConcurrentDurableCheckpointV4,
    task_id: ProtocolIdentity,
    operation_id: ProtocolIdentity,
    code: RuntimeCode,
) -> Result<bool, DurableEvidenceError> {
    let mut expected = boundary
        .clone()
        .recover(Arc::new(program.clone()))
        .map_err(DurableEvidenceError::ConcurrentCheckpoint)?;
    recovered_machine_mut(&mut expected, task_id)
        .ok_or(DurableEvidenceError::InvalidState)?
        .fail_operation_with_code(operation_id, code)
        .map_err(|_| DurableEvidenceError::InvalidState)?;
    capture_recovered_checkpoint(&expected).map(|checkpoint| checkpoint == *current)
}

fn checkpoint_causal_settlement_ready(
    execution: &RecoveredConcurrentDurableExecutionV1,
) -> Result<bool, DurableEvidenceError> {
    let checkpoint = ConcurrentDurableCheckpointV4::capture(
        execution.foreground(),
        execution.scheduler(),
        execution.sessions(),
    )
    .map_err(DurableEvidenceError::ConcurrentCheckpoint)?;
    for task_id in checkpoint.task_ids() {
        let mut candidate = checkpoint
            .clone()
            .recover(execution.foreground().program_arc())
            .map_err(DurableEvidenceError::ConcurrentCheckpoint)?;
        let pending = recovered_machine_mut(&mut candidate, task_id)
            .and_then(|machine| machine.pending_task_control().cloned());
        let Some(pending) = pending else {
            continue;
        };
        if let Some((join, _)) = pending.join() {
            if resolved_join(&candidate, task_id, join)?.is_some() {
                return Ok(true);
            }
        } else if let Some(detach) = pending.detach()
            && detached_handle_matches(&candidate, task_id, detach)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn replay_task_control_checkpoint(
    program: &MachineProgram,
    previous: &ConcurrentDurableCheckpointV4,
    current: &ConcurrentDurableCheckpointV4,
) -> Result<bool, DurableEvidenceError> {
    for task_id in previous.task_ids() {
        let mut expected = previous
            .clone()
            .recover(Arc::new(program.clone()))
            .map_err(DurableEvidenceError::ConcurrentCheckpoint)?;
        let pending = recovered_machine_mut(&mut expected, task_id)
            .and_then(|machine| machine.pending_task_control().cloned());
        let Some(pending) = pending else {
            continue;
        };
        if let Some((join, _)) = pending.join() {
            let Some(resolution) = resolved_join(&expected, task_id, join)? else {
                continue;
            };
            recovered_machine_mut(&mut expected, task_id)
                .ok_or(DurableEvidenceError::InvalidState)?
                .complete_join(join, resolution)
                .map_err(|_| DurableEvidenceError::InvalidState)?;
        } else if let Some(detach) = pending.detach() {
            if !detached_handle_matches(&expected, task_id, detach) {
                continue;
            }
            recovered_machine_mut(&mut expected, task_id)
                .ok_or(DurableEvidenceError::InvalidState)?
                .complete_detach(detach)
                .map_err(|_| DurableEvidenceError::InvalidState)?;
        } else {
            continue;
        }
        let expected = ConcurrentDurableCheckpointV4::capture(
            expected.foreground(),
            expected.scheduler(),
            expected.sessions(),
        )
        .map_err(DurableEvidenceError::ConcurrentCheckpoint)?;
        if expected == *current {
            return Ok(true);
        }
    }
    Ok(false)
}

fn recovered_machine_mut(
    execution: &mut RecoveredConcurrentDurableExecutionV1,
    task_id: ProtocolIdentity,
) -> Option<&mut Machine> {
    if task_id == execution.foreground().task_id() {
        Some(execution.foreground_mut())
    } else {
        execution.scheduler_mut().machine_mut(task_id)
    }
}

fn detached_handle_matches(
    execution: &RecoveredConcurrentDurableExecutionV1,
    owner_task_id: ProtocolIdentity,
    detach: &MachineDetachSuspension,
) -> bool {
    execution
        .scheduler()
        .state()
        .task(detach.handle.identity().child())
        .is_some_and(|task| {
            task.parent_task_id() == owner_task_id
                && task.handle_id() == detach.handle.identity()
                && task.handle_name() == detach.handle.name()
                && task.handle_state() == TaskHandleState::Detached
        })
}

fn resolved_join(
    execution: &RecoveredConcurrentDurableExecutionV1,
    owner_task_id: ProtocolIdentity,
    join: &MachineJoinSuspension,
) -> Result<Option<JoinResolutionV1>, DurableEvidenceError> {
    if join.handles.is_empty() {
        return Ok(Some(JoinResolutionV1::Succeeded(LogicalValue::unit())));
    }
    let mut result_types = Vec::with_capacity(join.handles.len());
    let mut values = Vec::with_capacity(join.handles.len());
    let mut failures = Vec::new();
    for handle in &join.handles {
        let task = execution
            .scheduler()
            .state()
            .task(handle.identity().child())
            .ok_or(DurableEvidenceError::InvalidState)?;
        if task.parent_task_id() != owner_task_id
            || task.handle_id() != handle.identity()
            || task.handle_name() != handle.name()
            || task.handle_state() != TaskHandleState::Joined
        {
            return Err(DurableEvidenceError::InvalidState);
        }
        match task.status() {
            ConcurrentTaskStatusV1::Submitting | ConcurrentTaskStatusV1::Running => {
                return Ok(None);
            }
            ConcurrentTaskStatusV1::Succeeded(value) => {
                result_types.push(task.result_type().clone());
                values.push(value.clone());
            }
            ConcurrentTaskStatusV1::Failed(failure) => {
                failures.push(TaskJoinMemberFailureV1 {
                    task_id: task.task_id(),
                    task_path: Arc::from(task.task_path()),
                    failure: TaskJoinMemberFailureKindV1::Failed(failure.clone()),
                });
            }
            ConcurrentTaskStatusV1::Cancelled(reason) => {
                failures.push(TaskJoinMemberFailureV1 {
                    task_id: task.task_id(),
                    task_path: Arc::from(task.task_path()),
                    failure: TaskJoinMemberFailureKindV1::Cancelled(Arc::clone(reason)),
                });
            }
        }
    }
    if !failures.is_empty() {
        return Ok(Some(JoinResolutionV1::Failed(TaskJoinFailureV1 {
            category: RuntimeErrorCategory::TaskJoinFailure,
            failures,
        })));
    }
    let all_unit = result_types
        .iter()
        .all(|result_type| *result_type == gantry_ir::TypeDescriptor::UNIT);
    let any_unit = result_types.contains(&gantry_ir::TypeDescriptor::UNIT);
    let limits = ConcurrentDurableCheckpointV4::capture(
        execution.foreground(),
        execution.scheduler(),
        execution.sessions(),
    )
    .map_err(DurableEvidenceError::ConcurrentCheckpoint)?
    .task_checkpoint(owner_task_id)
    .ok_or(DurableEvidenceError::InvalidState)?
    .value_limits();
    let value = if all_unit {
        LogicalValue::unit()
    } else if any_unit {
        return Err(DurableEvidenceError::InvalidState);
    } else if values.len() == 1 {
        values.pop().ok_or(DurableEvidenceError::InvalidState)?
    } else if result_types.windows(2).all(|pair| pair[0] == pair[1]) {
        LogicalValue::list(values, limits).map_err(|_| DurableEvidenceError::InvalidState)?
    } else {
        LogicalValue::tuple(values, limits).map_err(|_| DurableEvidenceError::InvalidState)?
    };
    Ok(Some(JoinResolutionV1::Succeeded(value)))
}

fn validate_task_ownership_transition(
    program: &MachineProgram,
    previous: &ConcurrentDurableCheckpointV4,
    current: &ConcurrentDurableEvidenceBody,
    task_id: ProtocolIdentity,
) -> Result<bool, DurableEvidenceError> {
    let current_checkpoint = current.checkpoint();
    if previous.task_ids() != current_checkpoint.task_ids()
        || previous.task_handle_state(task_id) != Some(TaskHandleState::Attached)
    {
        return Ok(false);
    }
    let disposition = current_checkpoint.task_handle_state(task_id);
    if !matches!(
        disposition,
        Some(TaskHandleState::Joined | TaskHandleState::Detached)
    ) {
        return Ok(false);
    }

    let Some((atomic, ownership)) = replay_source_ownership_transition(program, previous, task_id)?
    else {
        return Ok(false);
    };
    if atomic != *current_checkpoint {
        return Ok(false);
    }
    Ok(match current {
        ConcurrentDurableEvidenceBody::V4(_) => true,
        ConcurrentDurableEvidenceBody::V5(evidence) => {
            evidence.record() == ConcurrentDurableEvidenceRecordV5::Ownership
                && evidence.ownership() == Some(&ownership)
        }
    })
}

fn ownership_from_checkpoint(
    checkpoint: &ConcurrentDurableCheckpointV4,
    task_id: ProtocolIdentity,
) -> Result<Option<ConcurrentDurableOwnershipV5>, DurableEvidenceError> {
    let owner_task_id = checkpoint.task_ids().into_iter().find(|owner_task_id| {
        checkpoint
            .task_checkpoint(*owner_task_id)
            .and_then(|machine| machine.pending_task_control_checkpoint())
            .is_some_and(|pending| {
                pending.join().is_some_and(|(join, _)| {
                    join.handles
                        .iter()
                        .any(|handle| handle.identity().child() == task_id)
                }) || pending
                    .detach()
                    .is_some_and(|detach| detach.handle.identity().child() == task_id)
            })
    });
    let Some(owner_task_id) = owner_task_id else {
        return Ok(None);
    };
    let Some(pending) = checkpoint
        .task_checkpoint(owner_task_id)
        .and_then(|machine| machine.pending_task_control_checkpoint())
    else {
        return Ok(None);
    };
    let (workflow, site, control_kind, disposition, handles) =
        if let Some((join, join_all)) = pending.join() {
            (
                join.workflow.clone(),
                join.site.clone(),
                if join_all {
                    TaskControlSiteKind::JoinAll
                } else {
                    TaskControlSiteKind::Join
                },
                TaskHandleState::Joined,
                join.handles.as_slice(),
            )
        } else if let Some(detach) = pending.detach() {
            (
                detach.workflow.clone(),
                detach.site.clone(),
                TaskControlSiteKind::Detach,
                TaskHandleState::Detached,
                std::slice::from_ref(&detach.handle),
            )
        } else {
            return Ok(None);
        };
    let members = handles
        .iter()
        .map(|handle| {
            if handle.identity().owner() != owner_task_id
                || checkpoint.task_handle_state(handle.identity().child()) != Some(disposition)
            {
                return Err(DurableEvidenceError::InvalidState);
            }
            Ok(ConcurrentDurableOwnershipMemberV5 {
                handle_name: Arc::from(handle.name()),
                handle_owner: handle.identity().owner(),
                handle_child: handle.identity().child(),
                task_id: handle.identity().child(),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let ownership = ConcurrentDurableOwnershipV5 {
        owner_task_id,
        workflow,
        site,
        control_kind,
        disposition,
        members,
    };
    ownership.validate()?;
    Ok(Some(ownership))
}

fn replay_source_ownership_transition(
    program: &MachineProgram,
    previous: &ConcurrentDurableCheckpointV4,
    task_id: ProtocolIdentity,
) -> Result<
    Option<(ConcurrentDurableCheckpointV4, ConcurrentDurableOwnershipV5)>,
    DurableEvidenceError,
> {
    let mut expected = previous
        .clone()
        .recover(Arc::new(program.clone()))
        .map_err(DurableEvidenceError::ConcurrentCheckpoint)?;
    let owner_task_id = expected
        .scheduler()
        .state()
        .task(task_id)
        .ok_or(DurableEvidenceError::InvalidState)?
        .parent_task_id();
    let pending = {
        let owner = if expected.foreground().task_id() == owner_task_id {
            expected.foreground_mut()
        } else {
            expected
                .scheduler_mut()
                .machine_mut(owner_task_id)
                .ok_or(DurableEvidenceError::InvalidState)?
        };
        let MachineStep::Transition(crate::MachineLabel::Deterministic { ref kind, .. }) =
            owner.step()
        else {
            return Ok(None);
        };
        let Some(pending) = owner.pending_task_control().cloned() else {
            return Ok(None);
        };
        let exact_kind = pending.join().is_some() && kind.as_ref() == "join-suspended"
            || pending.detach().is_some() && kind.as_ref() == "detach-suspended";
        if !exact_kind {
            return Ok(None);
        }
        pending
    };
    let ownership = if let Some((join, join_all)) = pending.join() {
        if join
            .handles
            .first()
            .is_none_or(|handle| handle.identity().child() != task_id)
        {
            return Ok(None);
        }
        let kind = if join_all {
            TaskControlSiteKind::JoinAll
        } else {
            TaskControlSiteKind::Join
        };
        let handle_names = join
            .handles
            .iter()
            .map(|handle| Arc::from(handle.name()))
            .collect::<Vec<_>>();
        let handles = join
            .handles
            .iter()
            .map(|handle| handle.identity())
            .collect::<Vec<_>>();
        let started = expected
            .scheduler_mut()
            .begin_source_join(
                owner_task_id,
                join.workflow.clone(),
                join.site.clone(),
                kind,
                &handle_names,
                &handles,
            )
            .map_err(|_| DurableEvidenceError::InvalidState)?;
        let crate::JoinStartV1::Started(ownership) = started else {
            return Ok(None);
        };
        ConcurrentDurableOwnershipV5::from_changed(&ownership)?
    } else if let Some(detach) = pending.detach() {
        if detach.handle.identity().child() != task_id {
            return Ok(None);
        }
        let ownership = expected
            .scheduler_mut()
            .detach_source_handle(
                owner_task_id,
                detach.workflow.clone(),
                detach.site.clone(),
                Arc::from(detach.handle.name()),
                detach.handle.identity(),
            )
            .map_err(|_| DurableEvidenceError::InvalidState)?;
        ConcurrentDurableOwnershipV5::from_changed(&ownership)?
    } else {
        return Ok(None);
    };
    let checkpoint = ConcurrentDurableCheckpointV4::capture(
        expected.foreground(),
        expected.scheduler(),
        expected.sessions(),
    )
    .map_err(DurableEvidenceError::ConcurrentCheckpoint)?;
    Ok(Some((checkpoint, ownership)))
}

fn validate_execution_cancellation_transition(
    program: &MachineProgram,
    previous: &ConcurrentDurableEvidenceBody,
    current: &ConcurrentDurableEvidenceBody,
) -> Result<bool, DurableEvidenceError> {
    let ConcurrentDurableEvidenceBody::V5(current_evidence) = current else {
        return Ok(false);
    };
    if current_evidence.record() != ConcurrentDurableEvidenceRecordV5::Cancellation
        || previous.checkpoint().task_is_cancelled(current.task_id())
    {
        return Ok(false);
    }
    let cancellation = current_evidence
        .cancellation()
        .ok_or(DurableEvidenceError::InvalidState)?;
    let reason = cancellation
        .message
        .as_deref()
        .unwrap_or_else(|| cancellation.category.wire_name());
    let mut expected = previous
        .checkpoint()
        .clone()
        .recover(Arc::new(program.clone()))
        .map_err(DurableEvidenceError::ConcurrentCheckpoint)?;
    let affected = expected
        .scheduler_mut()
        .cancel_execution(reason)
        .map_err(|_| DurableEvidenceError::InvalidState)?;
    if affected.first().copied() != Some(current.task_id()) {
        return Ok(false);
    }
    let _ = expected.foreground_mut().cancel(reason);
    let expected = ConcurrentDurableCheckpointV4::capture(
        expected.foreground(),
        expected.scheduler(),
        expected.sessions(),
    )
    .map_err(DurableEvidenceError::ConcurrentCheckpoint)?;
    Ok(expected == *current.checkpoint())
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
    use gantry_core::portable::{
        CancellationReasonCategory, IdentityKind, TaskHandleState, TaskStatusKind,
    };
    use gantry_core::source::SourceSpan;
    use gantry_core::value::{DEFAULT_VALUE_LIMITS, LogicalValue};
    use gantry_host::contracts::HostError;
    use gantry_host::journal::{
        AcquireJournalOwnerV1, FullJournalPrefixV1, JournalEvidenceEnvelopeV1, JournalId,
        JournalOwnerOperationV1, JournalPrefixV1, JournalStorage, ReadJournalPrefixV1,
        SnapshotJournalPrefixV1,
    };
    use gantry_ir::generated::TaskControlSiteKind;
    use gantry_ir::{
        CanonicalCallableIdentity, CanonicalPath, EffectSet, ExecutableTaskBody,
        ExecutableTaskContext, ExecutableTaskHandle, Instruction, InstructionKind, MachineProgram,
        Parameter, StaticSiteId, StructuralPosition, TaskBodyIdentity, TaskControlSite,
        TypeDescriptor, Workflow,
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
        SessionEstablishmentV1, TaskCreationRequestV1, TaskCreationV1,
        recover_concurrent_authoritative_prefix, root_task_identity,
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
                &program,
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
    fn legacy_v4_submission_resolution_rejects_unrelated_checkpoint_mutation() {
        let program = spawn_program(&["child"]);
        let execution = fresh(IdentityKind::Execution, 13);
        let root_task = root_task_identity(execution);
        let root_session = fresh(IdentityKind::Session, 14);
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
        let suspension = match foreground.step() {
            MachineStep::Transition(crate::MachineLabel::TaskControlSuspended(suspension)) => {
                suspension
            }
            other => panic!("foreground did not suspend at spawn: {other:?}"),
        };
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
        let child = scheduler
            .create_child(
                &mut sessions,
                spawn_request(root_task, root_session, &suspension),
                DEFAULT_VALUE_LIMITS,
            )
            .unwrap_or_else(|error| panic!("child creation failed: {error:?}"));
        let hidden_checkpoint =
            ConcurrentDurableCheckpointV4::capture(&foreground, &scheduler, &sessions)
                .unwrap_or_else(|error| panic!("hidden checkpoint failed: {error:?}"));
        let hidden = ConcurrentDurableEvidenceV4::new(
            DurableCommitCutV1::TaskCreation,
            child.task_id,
            hidden_checkpoint.clone(),
        )
        .unwrap_or_else(|error| panic!("hidden evidence failed: {error:?}"));
        let mut resolved = hidden_checkpoint
            .recover(Arc::clone(&program))
            .unwrap_or_else(|error| panic!("hidden checkpoint recovery failed: {error:?}"));
        resolved
            .foreground_mut()
            .complete_spawn(&suspension, child.handle_id)
            .unwrap_or_else(|error| panic!("spawn completion failed: {error:?}"));
        resolved
            .scheduler_mut()
            .resolve_submission(
                child.task_id,
                Err(HostError {
                    code: Arc::from("executor-closed"),
                    protected_diagnostic: None,
                }),
            )
            .unwrap_or_else(|error| panic!("submission failure failed: {error:?}"));
        let resolved_checkpoint = ConcurrentDurableCheckpointV4::capture(
            resolved.foreground(),
            resolved.scheduler(),
            resolved.sessions(),
        )
        .unwrap_or_else(|error| panic!("resolved checkpoint failed: {error:?}"));
        let resolution = ConcurrentDurableEvidenceV5::new_submission_resolution(
            DurableCommitCutV1::TaskSettlement,
            child.task_id,
            resolved_checkpoint.clone(),
        )
        .unwrap_or_else(|error| panic!("resolution evidence failed: {error:?}"));
        assert!(matches!(
            resolved.foreground_mut().step(),
            MachineStep::Transition(_)
        ));
        let mutated_checkpoint = ConcurrentDurableCheckpointV4::capture(
            resolved.foreground(),
            resolved.scheduler(),
            resolved.sessions(),
        )
        .unwrap_or_else(|error| panic!("mutated checkpoint failed: {error:?}"));
        let mutated = ConcurrentDurableEvidenceV4::new(
            DurableCommitCutV1::TaskSettlement,
            child.task_id,
            mutated_checkpoint,
        )
        .unwrap_or_else(|error| panic!("mutated evidence failed: {error:?}"));
        let journal_id = JournalId::new("legacy-v4-submission-resolution")
            .unwrap_or_else(|error| panic!("journal id failed: {error:?}"));
        let start_id = ProtocolIdentity::from_storage_material([13; 32]);
        let initial_id = ProtocolIdentity::from_storage_material([14; 32]);
        let hidden_id = ProtocolIdentity::from_storage_material([15; 32]);
        let resolution_id = ProtocolIdentity::from_storage_material([16; 32]);
        let mutated_id = ProtocolIdentity::from_storage_material([18; 32]);
        let prefix = JournalPrefixV1::Full(FullJournalPrefixV1 {
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
                    evidence_id: initial_id,
                    kind: Arc::from(CONCURRENT_DURABLE_EVIDENCE_KIND_V4),
                    canonical_body: Arc::from(initial.canonical_body()),
                    references: Arc::from([start_id]),
                    protected_payloads: Arc::from([]),
                },
                JournalEvidenceEnvelopeV1 {
                    journal_id: journal_id.clone(),
                    sequence: 3,
                    evidence_id: hidden_id,
                    kind: Arc::from(CONCURRENT_DURABLE_EVIDENCE_KIND_V4),
                    canonical_body: Arc::from(hidden.canonical_body()),
                    references: Arc::from([initial_id]),
                    protected_payloads: Arc::from([]),
                },
                JournalEvidenceEnvelopeV1 {
                    journal_id: journal_id.clone(),
                    sequence: 4,
                    evidence_id: mutated_id,
                    kind: Arc::from(CONCURRENT_DURABLE_EVIDENCE_KIND_V4),
                    canonical_body: Arc::from(mutated.canonical_body()),
                    references: Arc::from([hidden_id]),
                    protected_payloads: Arc::from([]),
                },
            ]),
            committed_through: 4,
        });

        assert!(matches!(
            recover_concurrent_authoritative_prefix(Arc::clone(&program), &prefix),
            Err(DurableEvidenceError::ConcurrentCheckpoint(_))
        ));

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
                    evidence_id: initial_id,
                    kind: Arc::from(CONCURRENT_DURABLE_EVIDENCE_KIND_V4),
                    canonical_body: Arc::from(initial.canonical_body()),
                    references: Arc::from([start_id]),
                    protected_payloads: Arc::from([]),
                },
                JournalEvidenceEnvelopeV1 {
                    journal_id: journal_id.clone(),
                    sequence: 3,
                    evidence_id: hidden_id,
                    kind: Arc::from(CONCURRENT_DURABLE_EVIDENCE_KIND_V4),
                    canonical_body: Arc::from(hidden.canonical_body()),
                    references: Arc::from([initial_id]),
                    protected_payloads: Arc::from([]),
                },
                JournalEvidenceEnvelopeV1 {
                    journal_id,
                    sequence: 4,
                    evidence_id: resolution_id,
                    kind: Arc::from(CONCURRENT_DURABLE_EVIDENCE_KIND_V5),
                    canonical_body: Arc::from(resolution.canonical_body()),
                    references: Arc::from([hidden_id]),
                    protected_payloads: Arc::from([]),
                },
            ]),
            committed_through: 4,
        };
        let snapshot = ConcurrentDurableRecoverySnapshotV1::from_full_prefix(&program, &full)
            .unwrap_or_else(|error| panic!("snapshot compaction failed: {error:?}"));
        let unbound_id = ProtocolIdentity::from_storage_material([19; 32]);
        let retained_resolution = format!("{{\"evidence_id\":\"{resolution_id}\",\"sequence\":4}}");
        let unbound_resolution = format!("{{\"evidence_id\":\"{unbound_id}\",\"sequence\":4}}");
        let tampered = String::from_utf8(snapshot.canonical_body())
            .unwrap_or_else(|error| panic!("snapshot body is not UTF-8: {error}"))
            .replacen(&retained_resolution, &unbound_resolution, 1)
            .into_bytes();
        assert_eq!(
            ConcurrentDurableRecoverySnapshotV1::decode(&program, &tampered),
            Err(DurableEvidenceError::InvalidCausalOrder)
        );

        let snapshot_body = String::from_utf8(snapshot.canonical_body())
            .unwrap_or_else(|error| panic!("snapshot body is not UTF-8: {error}"));
        let initial_hex = super::super::encode_hex(&initial.canonical_body());
        let hidden_hex = super::super::encode_hex(&hidden.canonical_body());
        let initial_record = format!(
            "{{\"body\":\"{initial_hex}\",\"evidence_id\":\"{initial_id}\",\"sequence\":2}}"
        );

        let invented_id = ProtocolIdentity::from_storage_material([20; 32]);
        let invented_record = format!(
            "{{\"body\":\"{initial_hex}\",\"evidence_id\":\"{invented_id}\",\"sequence\":2}}"
        );
        let invented = snapshot_body
            .replacen(&initial_record, &invented_record, 1)
            .into_bytes();
        assert_eq!(
            ConcurrentDurableRecoverySnapshotV1::decode(&program, &invented),
            Err(DurableEvidenceError::InvalidCausalOrder)
        );

        let duplicate_sequence_record = format!(
            "{{\"body\":\"{initial_hex}\",\"evidence_id\":\"{initial_id}\",\"sequence\":3}}"
        );
        let duplicate_sequence = snapshot_body
            .replacen(&initial_record, &duplicate_sequence_record, 1)
            .into_bytes();
        assert_eq!(
            ConcurrentDurableRecoverySnapshotV1::decode(&program, &duplicate_sequence),
            Err(DurableEvidenceError::InvalidCausalOrder)
        );

        let reordered_record = format!(
            "{{\"body\":\"{hidden_hex}\",\"evidence_id\":\"{initial_id}\",\"sequence\":2}}"
        );
        let reordered = snapshot_body
            .replacen(&initial_record, &reordered_record, 1)
            .into_bytes();
        assert!(ConcurrentDurableRecoverySnapshotV1::decode(&program, &reordered).is_err());

        let other_execution = fresh(IdentityKind::Execution, 20);
        let other_graph = checkpoint_evidence(
            Arc::clone(&program),
            other_execution,
            root_task_identity(other_execution),
            fresh(IdentityKind::Session, 21),
            machine_limits(),
        );
        let other_hex = super::super::encode_hex(&other_graph.canonical_body());
        let mixed_record =
            format!("{{\"body\":\"{other_hex}\",\"evidence_id\":\"{initial_id}\",\"sequence\":2}}");
        let mixed = snapshot_body
            .replacen(&initial_record, &mixed_record, 1)
            .into_bytes();
        assert_eq!(
            ConcurrentDurableRecoverySnapshotV1::decode(&program, &mixed),
            Err(DurableEvidenceError::InvalidCausalOrder)
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
    fn typed_cancellation_recovers_exactly_and_legacy_v4_remains_recoverable() {
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
        let legacy_prefix = prefix(legacy.canonical_body(), CONCURRENT_DURABLE_EVIDENCE_KIND_V4);
        let recovered_legacy =
            recover_concurrent_authoritative_prefix(Arc::clone(&program), &legacy_prefix)
                .unwrap_or_else(|error| panic!("legacy cancellation recovery failed: {error:?}"));
        assert_eq!(recovered_legacy.cancellation_reason(), None);
        assert_eq!(
            recovered_legacy
                .execution()
                .scheduler()
                .state()
                .task_cancellation_reason(root_task),
            Some("caller-stop")
        );
        let JournalPrefixV1::Full(legacy_full) = legacy_prefix else {
            unreachable!("fixture is a full prefix")
        };
        let legacy_snapshot =
            ConcurrentDurableRecoverySnapshotV1::from_full_prefix(&program, &legacy_full)
                .unwrap_or_else(|error| panic!("legacy cancellation compaction failed: {error:?}"));
        assert!(legacy_snapshot.cancellation.is_none());
    }

    #[test]
    fn cancellation_transition_rejects_omitted_live_tasks_and_unrelated_mutation() {
        let program = program();
        let execution = fresh(IdentityKind::Execution, 31);
        let root_task = root_task_identity(execution);
        let root_session = fresh(IdentityKind::Session, 32);
        let mut sessions = LogicalSessionRegistryV1::new(
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
            machine_limits(),
            None,
            Some(root_session),
        )
        .unwrap_or_else(|error| panic!("foreground machine failed: {error:?}"));
        let state = ConcurrentTaskStateV1::new(execution, root_task, 8)
            .unwrap_or_else(|error| panic!("task state failed: {error:?}"));
        let mut scheduler = ConcurrentSchedulerV1::new(state, foreground.execution_budget())
            .unwrap_or_else(|error| panic!("scheduler construction failed: {error:?}"));
        let child = scheduler
            .create_child(
                &mut sessions,
                TaskCreationRequestV1 {
                    parent_task_id: root_task,
                    handle_name: Arc::from("child"),
                    workflow: path("crate::child"),
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
        let previous_checkpoint =
            ConcurrentDurableCheckpointV4::capture(&foreground, &scheduler, &sessions)
                .unwrap_or_else(|error| panic!("previous checkpoint failed: {error:?}"));
        let previous = super::ConcurrentDurableEvidenceBody::V4(Box::new(
            ConcurrentDurableEvidenceV4::new(
                DurableCommitCutV1::TaskCreation,
                child.task_id,
                previous_checkpoint.clone(),
            )
            .unwrap_or_else(|error| panic!("previous evidence failed: {error:?}")),
        ));
        let reason = CancellationReason::new(
            CancellationReasonCategory::Caller,
            Some(Arc::from("caller-stop")),
            None,
            32,
        )
        .unwrap_or_else(|error| panic!("cancellation reason failed: {error:?}"));

        let mut exact = previous_checkpoint
            .clone()
            .recover(Arc::clone(&program))
            .unwrap_or_else(|error| panic!("checkpoint recovery failed: {error:?}"));
        exact
            .scheduler_mut()
            .cancel_execution("caller-stop")
            .unwrap_or_else(|error| panic!("execution cancellation failed: {error:?}"));
        assert!(exact.foreground_mut().cancel("caller-stop").is_some());
        let exact_checkpoint = ConcurrentDurableCheckpointV4::capture(
            exact.foreground(),
            exact.scheduler(),
            exact.sessions(),
        )
        .unwrap_or_else(|error| panic!("exact checkpoint failed: {error:?}"));
        assert_eq!(
            exact_checkpoint
                .task_ids()
                .into_iter()
                .filter(|task_id| {
                    exact_checkpoint.task_is_cancelled(*task_id)
                        && exact_checkpoint
                            .clone()
                            .recover(Arc::clone(&program))
                            .is_ok_and(|recovered| {
                                recovered
                                    .scheduler()
                                    .state()
                                    .task_cancellation_reason(*task_id)
                                    == Some("caller-stop")
                            })
                })
                .count(),
            2
        );
        let exact = super::ConcurrentDurableEvidenceBody::V5(Box::new(
            ConcurrentDurableEvidenceV5::new_cancellation(
                root_task,
                reason.clone(),
                exact_checkpoint,
            )
            .unwrap_or_else(|error| panic!("exact evidence failed: {error:?}")),
        ));
        assert_eq!(validate_transition(&program, &previous, &exact), Ok(()));

        let mut omitted = previous_checkpoint
            .clone()
            .recover(Arc::clone(&program))
            .unwrap_or_else(|error| panic!("checkpoint recovery failed: {error:?}"));
        omitted
            .scheduler_mut()
            .cancel_task_tree(child.task_id, "caller-stop")
            .unwrap_or_else(|error| panic!("child-only cancellation failed: {error:?}"));
        let omitted_checkpoint = ConcurrentDurableCheckpointV4::capture(
            omitted.foreground(),
            omitted.scheduler(),
            omitted.sessions(),
        )
        .unwrap_or_else(|error| panic!("omitted checkpoint failed: {error:?}"));
        assert!(!omitted_checkpoint.task_is_cancelled(root_task));
        let omitted = super::ConcurrentDurableEvidenceBody::V5(Box::new(
            ConcurrentDurableEvidenceV5::new_cancellation(
                child.task_id,
                reason.clone(),
                omitted_checkpoint,
            )
            .unwrap_or_else(|error| panic!("omitted evidence failed: {error:?}")),
        ));
        assert_eq!(
            validate_transition(&program, &previous, &omitted),
            Err(DurableEvidenceError::InvalidState)
        );

        let mut mismatched = previous_checkpoint
            .clone()
            .recover(Arc::clone(&program))
            .unwrap_or_else(|error| panic!("checkpoint recovery failed: {error:?}"));
        mismatched
            .scheduler_mut()
            .cancel_task_tree(child.task_id, "different")
            .unwrap_or_else(|error| panic!("child cancellation failed: {error:?}"));
        mismatched
            .scheduler_mut()
            .cancel_execution("caller-stop")
            .unwrap_or_else(|error| panic!("execution cancellation failed: {error:?}"));
        assert!(mismatched.foreground_mut().cancel("caller-stop").is_some());
        let mismatched_checkpoint = ConcurrentDurableCheckpointV4::capture(
            mismatched.foreground(),
            mismatched.scheduler(),
            mismatched.sessions(),
        )
        .unwrap_or_else(|error| panic!("mismatched checkpoint failed: {error:?}"));
        let mismatched = super::ConcurrentDurableEvidenceBody::V5(Box::new(
            ConcurrentDurableEvidenceV5::new_cancellation(
                root_task,
                reason.clone(),
                mismatched_checkpoint,
            )
            .unwrap_or_else(|error| panic!("mismatched evidence failed: {error:?}")),
        ));
        assert_eq!(
            validate_transition(&program, &previous, &mismatched),
            Err(DurableEvidenceError::InvalidState)
        );

        let mut mutated = previous_checkpoint
            .recover(Arc::clone(&program))
            .unwrap_or_else(|error| panic!("checkpoint recovery failed: {error:?}"));
        assert!(matches!(
            mutated.foreground_mut().step(),
            MachineStep::Transition(_)
        ));
        mutated
            .scheduler_mut()
            .cancel_execution("caller-stop")
            .unwrap_or_else(|error| panic!("execution cancellation failed: {error:?}"));
        assert!(mutated.foreground_mut().cancel("caller-stop").is_some());
        let mutated_checkpoint = ConcurrentDurableCheckpointV4::capture(
            mutated.foreground(),
            mutated.scheduler(),
            mutated.sessions(),
        )
        .unwrap_or_else(|error| panic!("mutated checkpoint failed: {error:?}"));
        let mutated = super::ConcurrentDurableEvidenceBody::V5(Box::new(
            ConcurrentDurableEvidenceV5::new_cancellation(root_task, reason, mutated_checkpoint)
                .unwrap_or_else(|error| panic!("mutated evidence failed: {error:?}")),
        ));
        assert_eq!(
            validate_transition(&program, &previous, &mutated),
            Err(DurableEvidenceError::InvalidState)
        );
    }

    #[test]
    fn task_ownership_accepts_atomic_source_detach_suspension() {
        let fixture = source_ownership_fixture(
            InstructionKind::Detach {
                handle: Arc::from("first"),
            },
            TypeDescriptor::UNIT,
        );
        let previous = super::ConcurrentDurableEvidenceBody::V4(Box::new(
            ConcurrentDurableEvidenceV4::new(
                DurableCommitCutV1::Checkpoint,
                fixture.root_task,
                fixture.checkpoint.clone(),
            )
            .unwrap_or_else(|error| panic!("previous evidence failed: {error:?}")),
        ));

        let mut atomic = fixture
            .checkpoint
            .clone()
            .recover(Arc::clone(&fixture.program))
            .unwrap_or_else(|error| panic!("checkpoint recovery failed: {error:?}"));
        assert!(matches!(
            atomic.foreground_mut().step(),
            MachineStep::Transition(crate::MachineLabel::Deterministic { ref kind, .. })
                if kind.as_ref() == "detach-suspended"
        ));
        let detach = atomic
            .foreground()
            .pending_task_control()
            .and_then(|pending| pending.detach())
            .cloned()
            .unwrap_or_else(|| panic!("detach suspension missing"));
        assert_eq!(detach.handle.name(), "first");
        atomic
            .scheduler_mut()
            .detach_source_handle(
                fixture.root_task,
                detach.workflow.clone(),
                detach.site.clone(),
                Arc::from(detach.handle.name()),
                detach.handle.identity(),
            )
            .unwrap_or_else(|error| panic!("source detach failed: {error:?}"));
        let atomic_checkpoint = ConcurrentDurableCheckpointV4::capture(
            atomic.foreground(),
            atomic.scheduler(),
            atomic.sessions(),
        )
        .unwrap_or_else(|error| panic!("atomic detach checkpoint failed: {error:?}"));
        let atomic = super::ConcurrentDurableEvidenceBody::V4(Box::new(
            ConcurrentDurableEvidenceV4::new(
                DurableCommitCutV1::TaskOwnership,
                fixture.first.task_id,
                atomic_checkpoint,
            )
            .unwrap_or_else(|error| panic!("atomic detach evidence failed: {error:?}")),
        ));
        assert_eq!(
            validate_transition(&fixture.program, &previous, &atomic),
            Ok(())
        );

        let mut scheduler_only = fixture
            .checkpoint
            .clone()
            .recover(Arc::clone(&fixture.program))
            .unwrap_or_else(|error| panic!("checkpoint recovery failed: {error:?}"));
        scheduler_only
            .scheduler_mut()
            .detach_source_handle(
                fixture.root_task,
                path("crate::main"),
                position(2),
                Arc::from("first"),
                fixture.first.handle_id,
            )
            .unwrap_or_else(|error| panic!("scheduler-only detach failed: {error:?}"));
        let scheduler_only_checkpoint = ConcurrentDurableCheckpointV4::capture(
            scheduler_only.foreground(),
            scheduler_only.scheduler(),
            scheduler_only.sessions(),
        )
        .unwrap_or_else(|error| panic!("scheduler-only checkpoint failed: {error:?}"));
        let scheduler_only = super::ConcurrentDurableEvidenceBody::V4(Box::new(
            ConcurrentDurableEvidenceV4::new(
                DurableCommitCutV1::TaskOwnership,
                fixture.first.task_id,
                scheduler_only_checkpoint,
            )
            .unwrap_or_else(|error| panic!("scheduler-only evidence failed: {error:?}")),
        ));
        assert_eq!(
            validate_transition(&fixture.program, &previous, &scheduler_only),
            Err(DurableEvidenceError::InvalidState)
        );
    }

    #[test]
    fn v5_ownership_round_trips_ordered_members_and_rejects_tampering() {
        let fixture = source_ownership_fixture(
            InstructionKind::JoinAll {
                handles: vec![Arc::from("second"), Arc::from("first")],
            },
            TypeDescriptor::list(TypeDescriptor::UNIT),
        );
        let previous = super::ConcurrentDurableEvidenceBody::V4(Box::new(
            ConcurrentDurableEvidenceV4::new(
                DurableCommitCutV1::Checkpoint,
                fixture.root_task,
                fixture.checkpoint.clone(),
            )
            .unwrap_or_else(|error| panic!("previous evidence failed: {error:?}")),
        ));
        let (checkpoint, expected_ownership) = super::replay_source_ownership_transition(
            &fixture.program,
            &fixture.checkpoint,
            fixture.second.task_id,
        )
        .unwrap_or_else(|error| panic!("ownership replay failed: {error:?}"))
        .unwrap_or_else(|| panic!("joinall ownership transition missing"));
        let evidence =
            ConcurrentDurableEvidenceV5::new_ownership(fixture.second.task_id, checkpoint)
                .unwrap_or_else(|error| panic!("V5 ownership evidence failed: {error:?}"));
        assert_eq!(
            evidence.record(),
            ConcurrentDurableEvidenceRecordV5::Ownership
        );
        assert_eq!(evidence.ownership(), Some(&expected_ownership));
        assert_eq!(
            evidence
                .ownership()
                .unwrap_or_else(|| panic!("ownership payload missing"))
                .members
                .iter()
                .map(|member| (
                    member.handle_name.as_ref(),
                    member.handle_child,
                    member.task_id
                ))
                .collect::<Vec<_>>(),
            vec![
                ("second", fixture.second.task_id, fixture.second.task_id),
                ("first", fixture.first.task_id, fixture.first.task_id),
            ]
        );
        let body = evidence.canonical_body();
        assert_eq!(
            ConcurrentDurableEvidenceV5::decode(&fixture.program, &body),
            Ok(evidence.clone())
        );
        let current = super::ConcurrentDurableEvidenceBody::V5(Box::new(evidence));
        assert_eq!(
            validate_transition(&fixture.program, &previous, &current),
            Ok(())
        );

        let body = String::from_utf8(body)
            .unwrap_or_else(|error| panic!("ownership body is not UTF-8: {error}"));
        for tampered in [
            body.replacen("\"handle_name\":\"second\"", "\"handle_name\":\"first\"", 1),
            body.replacen(
                "\"control_kind\":\"joinall\"",
                "\"control_kind\":\"join\"",
                1,
            ),
            body.replacen(
                "\"disposition\":\"joined\"",
                "\"disposition\":\"detached\"",
                1,
            ),
            body.replacen(
                &format!("\"task_id\":\"{}\"", fixture.second.task_id),
                &format!("\"task_id\":\"{}\"", fixture.first.task_id),
                1,
            ),
        ] {
            assert_eq!(
                ConcurrentDurableEvidenceV5::decode(&fixture.program, tampered.as_bytes()),
                Err(DurableEvidenceError::InvalidState)
            );
        }
    }

    #[test]
    fn task_ownership_accepts_full_ordered_source_joinall_selection() {
        let fixture = source_ownership_fixture(
            InstructionKind::JoinAll {
                handles: vec![Arc::from("second"), Arc::from("first")],
            },
            TypeDescriptor::list(TypeDescriptor::UNIT),
        );
        let previous = super::ConcurrentDurableEvidenceBody::V4(Box::new(
            ConcurrentDurableEvidenceV4::new(
                DurableCommitCutV1::Checkpoint,
                fixture.root_task,
                fixture.checkpoint.clone(),
            )
            .unwrap_or_else(|error| panic!("previous evidence failed: {error:?}")),
        ));

        let mut atomic = fixture
            .checkpoint
            .clone()
            .recover(Arc::clone(&fixture.program))
            .unwrap_or_else(|error| panic!("checkpoint recovery failed: {error:?}"));
        assert!(matches!(
            atomic.foreground_mut().step(),
            MachineStep::Transition(crate::MachineLabel::Deterministic { ref kind, .. })
                if kind.as_ref() == "join-suspended"
        ));
        let (join, all) = atomic
            .foreground()
            .pending_task_control()
            .and_then(|pending| pending.join())
            .map(|(join, all)| (join.clone(), all))
            .unwrap_or_else(|| panic!("joinall suspension missing"));
        assert!(all);
        assert_eq!(
            join.handles
                .iter()
                .map(|handle| handle.name())
                .collect::<Vec<_>>(),
            vec!["second", "first"]
        );
        let handle_names = join
            .handles
            .iter()
            .map(|handle| Arc::from(handle.name()))
            .collect::<Vec<_>>();
        let handles = join
            .handles
            .iter()
            .map(|handle| handle.identity())
            .collect::<Vec<_>>();
        atomic
            .scheduler_mut()
            .begin_source_join(
                fixture.root_task,
                join.workflow.clone(),
                join.site.clone(),
                TaskControlSiteKind::JoinAll,
                &handle_names,
                &handles,
            )
            .unwrap_or_else(|error| panic!("source joinall failed: {error:?}"));
        let atomic_checkpoint = ConcurrentDurableCheckpointV4::capture(
            atomic.foreground(),
            atomic.scheduler(),
            atomic.sessions(),
        )
        .unwrap_or_else(|error| panic!("atomic joinall checkpoint failed: {error:?}"));
        assert_eq!(
            atomic_checkpoint.task_handle_state(fixture.second.task_id),
            Some(TaskHandleState::Joined)
        );
        assert_eq!(
            atomic_checkpoint.task_handle_state(fixture.first.task_id),
            Some(TaskHandleState::Joined)
        );
        let atomic = super::ConcurrentDurableEvidenceBody::V4(Box::new(
            ConcurrentDurableEvidenceV4::new(
                DurableCommitCutV1::TaskOwnership,
                fixture.second.task_id,
                atomic_checkpoint,
            )
            .unwrap_or_else(|error| panic!("atomic joinall evidence failed: {error:?}")),
        ));
        assert_eq!(
            validate_transition(&fixture.program, &previous, &atomic),
            Ok(())
        );
    }

    #[test]
    fn checkpoint_join_failure_requires_causal_settlement_before_continuation() {
        let fixture = source_ownership_fixture(
            InstructionKind::JoinAll {
                handles: vec![Arc::from("second"), Arc::from("first")],
            },
            TypeDescriptor::list(TypeDescriptor::UNIT),
        );
        let initial = super::ConcurrentDurableEvidenceBody::V4(Box::new(
            ConcurrentDurableEvidenceV4::new(
                DurableCommitCutV1::Checkpoint,
                fixture.root_task,
                fixture.checkpoint.clone(),
            )
            .unwrap_or_else(|error| panic!("initial evidence failed: {error:?}")),
        ));
        let (ownership_checkpoint, _) = super::replay_source_ownership_transition(
            &fixture.program,
            &fixture.checkpoint,
            fixture.second.task_id,
        )
        .unwrap_or_else(|error| panic!("ownership replay failed: {error:?}"))
        .unwrap_or_else(|| panic!("joinall ownership transition missing"));
        let ownership = super::ConcurrentDurableEvidenceBody::V4(Box::new(
            ConcurrentDurableEvidenceV4::new(
                DurableCommitCutV1::TaskOwnership,
                fixture.second.task_id,
                ownership_checkpoint.clone(),
            )
            .unwrap_or_else(|error| panic!("ownership evidence failed: {error:?}")),
        ));
        assert_eq!(
            validate_transition(&fixture.program, &initial, &ownership),
            Ok(())
        );

        let causal = super::ConcurrentDurableEvidenceBody::V4(Box::new(
            ConcurrentDurableEvidenceV4::new(
                DurableCommitCutV1::Checkpoint,
                fixture.root_task,
                ownership_checkpoint.clone(),
            )
            .unwrap_or_else(|error| panic!("causal evidence failed: {error:?}")),
        ));
        assert_eq!(
            validate_transition(&fixture.program, &ownership, &causal),
            Ok(())
        );

        let mut continued = ownership_checkpoint
            .recover(Arc::clone(&fixture.program))
            .unwrap_or_else(|error| panic!("ownership recovery failed: {error:?}"));
        let join = continued
            .foreground()
            .pending_task_control()
            .and_then(|pending| pending.join())
            .map(|(join, _)| join.clone())
            .unwrap_or_else(|| panic!("joinall suspension missing"));
        let resolution = super::resolved_join(&continued, fixture.root_task, &join)
            .unwrap_or_else(|error| panic!("aggregate resolution failed: {error:?}"))
            .unwrap_or_else(|| panic!("settled aggregate remained pending"));
        assert!(matches!(
            &resolution,
            crate::JoinResolutionV1::Failed(failure)
                if failure
                    .failures
                    .iter()
                    .map(|member| member.task_id)
                    .collect::<Vec<_>>()
                    == vec![fixture.second.task_id, fixture.first.task_id]
        ));
        continued
            .foreground_mut()
            .complete_join(&join, resolution)
            .unwrap_or_else(|error| panic!("aggregate failure completion failed: {error:?}"));
        let continued_checkpoint = ConcurrentDurableCheckpointV4::capture(
            continued.foreground(),
            continued.scheduler(),
            continued.sessions(),
        )
        .unwrap_or_else(|error| panic!("continuation checkpoint failed: {error:?}"));
        let continuation = super::ConcurrentDurableEvidenceBody::V4(Box::new(
            ConcurrentDurableEvidenceV4::new(
                DurableCommitCutV1::Checkpoint,
                fixture.root_task,
                continued_checkpoint,
            )
            .unwrap_or_else(|error| panic!("continuation evidence failed: {error:?}")),
        ));
        assert_eq!(
            validate_transition(&fixture.program, &causal, &continuation),
            Ok(())
        );
        assert_eq!(
            validate_transition(&fixture.program, &ownership, &continuation),
            Err(DurableEvidenceError::InvalidState)
        );
        assert_eq!(
            validate_transition(&fixture.program, &causal, &causal),
            Err(DurableEvidenceError::InvalidState)
        );
    }

    #[test]
    fn checkpoint_join_result_requires_causal_settlement_before_continuation() {
        let fixture = source_ownership_fixture_with_child_success(
            InstructionKind::JoinAll {
                handles: vec![Arc::from("second"), Arc::from("first")],
            },
            TypeDescriptor::UNIT,
        );
        let (ownership_checkpoint, _) = super::replay_source_ownership_transition(
            &fixture.program,
            &fixture.checkpoint,
            fixture.second.task_id,
        )
        .unwrap_or_else(|error| panic!("ownership replay failed: {error:?}"))
        .unwrap_or_else(|| panic!("joinall ownership transition missing"));
        let ownership = super::ConcurrentDurableEvidenceBody::V4(Box::new(
            ConcurrentDurableEvidenceV4::new(
                DurableCommitCutV1::TaskOwnership,
                fixture.second.task_id,
                ownership_checkpoint.clone(),
            )
            .unwrap_or_else(|error| panic!("ownership evidence failed: {error:?}")),
        ));
        let causal = super::ConcurrentDurableEvidenceBody::V4(Box::new(
            ConcurrentDurableEvidenceV4::new(
                DurableCommitCutV1::Checkpoint,
                fixture.root_task,
                ownership_checkpoint.clone(),
            )
            .unwrap_or_else(|error| panic!("causal evidence failed: {error:?}")),
        ));
        assert_eq!(
            validate_transition(&fixture.program, &ownership, &causal),
            Ok(())
        );

        let mut continued = ownership_checkpoint
            .recover(Arc::clone(&fixture.program))
            .unwrap_or_else(|error| panic!("ownership recovery failed: {error:?}"));
        let join = continued
            .foreground()
            .pending_task_control()
            .and_then(|pending| pending.join())
            .map(|(join, _)| join.clone())
            .unwrap_or_else(|| panic!("joinall suspension missing"));
        let resolution = super::resolved_join(&continued, fixture.root_task, &join)
            .unwrap_or_else(|error| panic!("aggregate resolution failed: {error:?}"))
            .unwrap_or_else(|| panic!("settled aggregate remained pending"));
        assert_eq!(
            resolution,
            crate::JoinResolutionV1::Succeeded(LogicalValue::unit())
        );
        continued
            .foreground_mut()
            .complete_join(&join, resolution)
            .unwrap_or_else(|error| panic!("aggregate result completion failed: {error:?}"));
        let continued_checkpoint = ConcurrentDurableCheckpointV4::capture(
            continued.foreground(),
            continued.scheduler(),
            continued.sessions(),
        )
        .unwrap_or_else(|error| panic!("continuation checkpoint failed: {error:?}"));
        let continuation = super::ConcurrentDurableEvidenceBody::V4(Box::new(
            ConcurrentDurableEvidenceV4::new(
                DurableCommitCutV1::Checkpoint,
                fixture.root_task,
                continued_checkpoint,
            )
            .unwrap_or_else(|error| panic!("continuation evidence failed: {error:?}")),
        ));
        assert_eq!(
            validate_transition(&fixture.program, &causal, &continuation),
            Ok(())
        );
        assert_eq!(
            validate_transition(&fixture.program, &ownership, &continuation),
            Err(DurableEvidenceError::InvalidState)
        );
    }

    #[test]
    fn task_ownership_transition_rejects_unrelated_handle_and_state_changes() {
        let program = spawn_program(&["first", "second"]);
        let execution = fresh(IdentityKind::Execution, 33);
        let root_task = root_task_identity(execution);
        let root_session = fresh(IdentityKind::Session, 34);
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
        let first_suspension = match foreground.step() {
            MachineStep::Transition(crate::MachineLabel::TaskControlSuspended(suspension)) => {
                suspension
            }
            other => panic!("foreground did not suspend at first spawn: {other:?}"),
        };
        let state = ConcurrentTaskStateV1::new(execution, root_task, 8)
            .unwrap_or_else(|error| panic!("task state failed: {error:?}"));
        let mut scheduler = ConcurrentSchedulerV1::new(state, foreground.execution_budget())
            .unwrap_or_else(|error| panic!("scheduler construction failed: {error:?}"));
        let first = scheduler
            .create_child(
                &mut sessions,
                spawn_request(root_task, root_session, &first_suspension),
                DEFAULT_VALUE_LIMITS,
            )
            .unwrap_or_else(|error| panic!("first task creation failed: {error:?}"));
        foreground
            .complete_spawn(&first_suspension, first.handle_id)
            .unwrap_or_else(|error| panic!("first spawn completion failed: {error:?}"));
        scheduler
            .resolve_submission(
                first.task_id,
                Err(HostError {
                    code: Arc::from("executor-closed"),
                    protected_diagnostic: None,
                }),
            )
            .unwrap_or_else(|error| panic!("first submission resolution failed: {error:?}"));
        let second_suspension = match foreground.step() {
            MachineStep::Transition(crate::MachineLabel::TaskControlSuspended(suspension)) => {
                suspension
            }
            other => panic!("foreground did not suspend at second spawn: {other:?}"),
        };
        let second = scheduler
            .create_child(
                &mut sessions,
                spawn_request(root_task, root_session, &second_suspension),
                DEFAULT_VALUE_LIMITS,
            )
            .unwrap_or_else(|error| panic!("second task creation failed: {error:?}"));
        foreground
            .complete_spawn(&second_suspension, second.handle_id)
            .unwrap_or_else(|error| panic!("second spawn completion failed: {error:?}"));
        scheduler
            .resolve_submission(
                second.task_id,
                Err(HostError {
                    code: Arc::from("executor-closed"),
                    protected_diagnostic: None,
                }),
            )
            .unwrap_or_else(|error| panic!("second submission resolution failed: {error:?}"));
        let previous_checkpoint =
            ConcurrentDurableCheckpointV4::capture(&foreground, &scheduler, &sessions)
                .unwrap_or_else(|error| panic!("previous checkpoint failed: {error:?}"));
        let previous = super::ConcurrentDurableEvidenceBody::V4(Box::new(
            ConcurrentDurableEvidenceV4::new(
                DurableCommitCutV1::Checkpoint,
                root_task,
                previous_checkpoint.clone(),
            )
            .unwrap_or_else(|error| panic!("previous evidence failed: {error:?}")),
        ));

        for disposition in [TaskHandleState::Joined, TaskHandleState::Detached] {
            let mut exact = previous_checkpoint
                .clone()
                .recover(Arc::clone(&program))
                .unwrap_or_else(|error| panic!("checkpoint recovery failed: {error:?}"));
            match disposition {
                TaskHandleState::Joined => {
                    exact
                        .scheduler_mut()
                        .begin_join(
                            root_task,
                            &task_control(TaskControlSiteKind::Join, 1, &["first"]),
                            &[first.handle_id],
                        )
                        .unwrap_or_else(|error| panic!("exact join failed: {error:?}"));
                }
                TaskHandleState::Detached => {
                    exact
                        .scheduler_mut()
                        .detach(
                            root_task,
                            &task_control(TaskControlSiteKind::Detach, 1, &["first"]),
                            first.handle_id,
                        )
                        .unwrap_or_else(|error| panic!("exact detach failed: {error:?}"));
                }
                _ => unreachable!("fixture uses one supported ownership transition"),
            }
            let exact_checkpoint = ConcurrentDurableCheckpointV4::capture(
                exact.foreground(),
                exact.scheduler(),
                exact.sessions(),
            )
            .unwrap_or_else(|error| panic!("exact ownership checkpoint failed: {error:?}"));
            let exact = super::ConcurrentDurableEvidenceBody::V4(Box::new(
                ConcurrentDurableEvidenceV4::new(
                    DurableCommitCutV1::TaskOwnership,
                    first.task_id,
                    exact_checkpoint,
                )
                .unwrap_or_else(|error| panic!("exact ownership evidence failed: {error:?}")),
            ));
            assert_eq!(
                validate_transition(&program, &previous, &exact),
                Err(DurableEvidenceError::InvalidState)
            );
        }

        let mut extra_handle = previous_checkpoint
            .clone()
            .recover(Arc::clone(&program))
            .unwrap_or_else(|error| panic!("checkpoint recovery failed: {error:?}"));
        extra_handle
            .scheduler_mut()
            .begin_join(
                root_task,
                &task_control(TaskControlSiteKind::JoinAll, 2, &["first", "second"]),
                &[first.handle_id, second.handle_id],
            )
            .unwrap_or_else(|error| panic!("joinall failed: {error:?}"));
        let extra_handle_checkpoint = ConcurrentDurableCheckpointV4::capture(
            extra_handle.foreground(),
            extra_handle.scheduler(),
            extra_handle.sessions(),
        )
        .unwrap_or_else(|error| panic!("extra-handle checkpoint failed: {error:?}"));
        let extra_handle = super::ConcurrentDurableEvidenceBody::V4(Box::new(
            ConcurrentDurableEvidenceV4::new(
                DurableCommitCutV1::TaskOwnership,
                first.task_id,
                extra_handle_checkpoint,
            )
            .unwrap_or_else(|error| panic!("extra-handle evidence failed: {error:?}")),
        ));
        assert_eq!(
            validate_transition(&program, &previous, &extra_handle),
            Err(DurableEvidenceError::InvalidState)
        );

        let mut extra_state = previous_checkpoint
            .recover(Arc::clone(&program))
            .unwrap_or_else(|error| panic!("checkpoint recovery failed: {error:?}"));
        extra_state
            .scheduler_mut()
            .begin_join(
                root_task,
                &task_control(TaskControlSiteKind::Join, 3, &["first"]),
                &[first.handle_id],
            )
            .unwrap_or_else(|error| panic!("join failed: {error:?}"));
        assert!(matches!(
            extra_state.foreground_mut().step(),
            MachineStep::Transition(_)
        ));
        let extra_state_checkpoint = ConcurrentDurableCheckpointV4::capture(
            extra_state.foreground(),
            extra_state.scheduler(),
            extra_state.sessions(),
        )
        .unwrap_or_else(|error| panic!("extra-state checkpoint failed: {error:?}"));
        let extra_state = super::ConcurrentDurableEvidenceBody::V4(Box::new(
            ConcurrentDurableEvidenceV4::new(
                DurableCommitCutV1::TaskOwnership,
                first.task_id,
                extra_state_checkpoint,
            )
            .unwrap_or_else(|error| panic!("extra-state evidence failed: {error:?}")),
        ));
        assert_eq!(
            validate_transition(&program, &previous, &extra_state),
            Err(DurableEvidenceError::InvalidState)
        );
    }

    #[test]
    fn mixed_nested_cancellation_rejects_ownership_session_and_budget_mutations() {
        let fixture = mixed_nested_graph_fixture();
        assert_eq!(
            fixture.checkpoint.task_status(fixture.parent.task_id),
            Some(TaskStatusKind::Running)
        );
        assert_eq!(
            fixture.checkpoint.task_status(fixture.nested.task_id),
            Some(TaskStatusKind::Submitting)
        );
        assert_eq!(
            fixture.checkpoint.task_status(fixture.failed.task_id),
            Some(TaskStatusKind::Failed)
        );
        assert_eq!(
            fixture
                .checkpoint
                .task_handle_state(fixture.detached.task_id),
            Some(TaskHandleState::Detached)
        );
        let previous = super::ConcurrentDurableEvidenceBody::V4(Box::new(
            ConcurrentDurableEvidenceV4::new(
                DurableCommitCutV1::Checkpoint,
                fixture.root_task,
                fixture.checkpoint.clone(),
            )
            .unwrap_or_else(|error| panic!("previous evidence failed: {error:?}")),
        ));
        let reason = CancellationReason::new(
            CancellationReasonCategory::Caller,
            Some(Arc::from("mixed-stop")),
            None,
            32,
        )
        .unwrap_or_else(|error| panic!("cancellation reason failed: {error:?}"));

        let mut exact = fixture
            .checkpoint
            .clone()
            .recover(Arc::clone(&fixture.program))
            .unwrap_or_else(|error| panic!("checkpoint recovery failed: {error:?}"));
        let affected = exact
            .scheduler_mut()
            .cancel_execution("mixed-stop")
            .unwrap_or_else(|error| panic!("whole-graph cancellation failed: {error:?}"));
        assert_eq!(affected.first(), Some(&fixture.root_task));
        assert!(exact.foreground_mut().cancel("mixed-stop").is_some());
        let exact_checkpoint = ConcurrentDurableCheckpointV4::capture(
            exact.foreground(),
            exact.scheduler(),
            exact.sessions(),
        )
        .unwrap_or_else(|error| panic!("exact cancellation checkpoint failed: {error:?}"));
        for task_id in [
            fixture.root_task,
            fixture.parent.task_id,
            fixture.nested.task_id,
            fixture.detached.task_id,
        ] {
            assert!(exact_checkpoint.task_is_cancelled(task_id));
        }
        assert!(!exact_checkpoint.task_is_cancelled(fixture.failed.task_id));
        let exact = super::ConcurrentDurableEvidenceBody::V5(Box::new(
            ConcurrentDurableEvidenceV5::new_cancellation(
                fixture.root_task,
                reason.clone(),
                exact_checkpoint.clone(),
            )
            .unwrap_or_else(|error| panic!("exact cancellation evidence failed: {error:?}")),
        ));
        assert_eq!(
            validate_transition(&fixture.program, &previous, &exact),
            Ok(())
        );
        for noncanonical in affected.iter().skip(1) {
            let noncanonical = super::ConcurrentDurableEvidenceBody::V5(Box::new(
                ConcurrentDurableEvidenceV5::new_cancellation(
                    *noncanonical,
                    reason.clone(),
                    exact_checkpoint.clone(),
                )
                .unwrap_or_else(|error| {
                    panic!("noncanonical cancellation evidence failed: {error:?}")
                }),
            ));
            assert_eq!(
                validate_transition(&fixture.program, &previous, &noncanonical),
                Err(DurableEvidenceError::InvalidState)
            );
        }

        let mut omitted = fixture
            .checkpoint
            .clone()
            .recover(Arc::clone(&fixture.program))
            .unwrap_or_else(|error| panic!("checkpoint recovery failed: {error:?}"));
        omitted
            .scheduler_mut()
            .cancel_task_tree(fixture.parent.task_id, "mixed-stop")
            .unwrap_or_else(|error| panic!("nested subtree cancellation failed: {error:?}"));
        let omitted_checkpoint = ConcurrentDurableCheckpointV4::capture(
            omitted.foreground(),
            omitted.scheduler(),
            omitted.sessions(),
        )
        .unwrap_or_else(|error| panic!("omitted cancellation checkpoint failed: {error:?}"));
        assert!(omitted_checkpoint.task_is_cancelled(fixture.nested.task_id));
        assert!(!omitted_checkpoint.task_is_cancelled(fixture.root_task));
        assert!(!omitted_checkpoint.task_is_cancelled(fixture.detached.task_id));
        let omitted = super::ConcurrentDurableEvidenceBody::V5(Box::new(
            ConcurrentDurableEvidenceV5::new_cancellation(
                fixture.parent.task_id,
                reason.clone(),
                omitted_checkpoint,
            )
            .unwrap_or_else(|error| panic!("omitted cancellation evidence failed: {error:?}")),
        ));
        assert_eq!(
            validate_transition(&fixture.program, &previous, &omitted),
            Err(DurableEvidenceError::InvalidState)
        );

        let mut ownership = fixture
            .checkpoint
            .clone()
            .recover(Arc::clone(&fixture.program))
            .unwrap_or_else(|error| panic!("checkpoint recovery failed: {error:?}"));
        ownership
            .scheduler_mut()
            .detach(
                fixture.root_task,
                &task_control(TaskControlSiteKind::Detach, 40, &["parent"]),
                fixture.parent.handle_id,
            )
            .unwrap_or_else(|error| panic!("unrelated ownership mutation failed: {error:?}"));
        ownership
            .scheduler_mut()
            .cancel_execution("mixed-stop")
            .unwrap_or_else(|error| panic!("whole-graph cancellation failed: {error:?}"));
        assert!(ownership.foreground_mut().cancel("mixed-stop").is_some());
        let ownership_checkpoint = ConcurrentDurableCheckpointV4::capture(
            ownership.foreground(),
            ownership.scheduler(),
            ownership.sessions(),
        )
        .unwrap_or_else(|error| panic!("ownership-mutated checkpoint failed: {error:?}"));
        let ownership = super::ConcurrentDurableEvidenceBody::V5(Box::new(
            ConcurrentDurableEvidenceV5::new_cancellation(
                fixture.root_task,
                reason.clone(),
                ownership_checkpoint,
            )
            .unwrap_or_else(|error| panic!("ownership-mutated evidence failed: {error:?}")),
        ));
        assert_eq!(
            validate_transition(&fixture.program, &previous, &ownership),
            Err(DurableEvidenceError::InvalidState)
        );

        let mut session = fixture
            .checkpoint
            .clone()
            .recover(Arc::clone(&fixture.program))
            .unwrap_or_else(|error| panic!("checkpoint recovery failed: {error:?}"));
        session
            .sessions_mut()
            .create(
                fixture.root_session,
                fixture.root_task,
                position(41),
                0,
                SessionCreationModeV1::New,
                SessionEstablishmentV1::Separate,
            )
            .unwrap_or_else(|error| panic!("unrelated session mutation failed: {error:?}"));
        session
            .scheduler_mut()
            .cancel_execution("mixed-stop")
            .unwrap_or_else(|error| panic!("whole-graph cancellation failed: {error:?}"));
        assert!(session.foreground_mut().cancel("mixed-stop").is_some());
        let session_checkpoint = ConcurrentDurableCheckpointV4::capture(
            session.foreground(),
            session.scheduler(),
            session.sessions(),
        )
        .unwrap_or_else(|error| panic!("session-mutated checkpoint failed: {error:?}"));
        let session = super::ConcurrentDurableEvidenceBody::V5(Box::new(
            ConcurrentDurableEvidenceV5::new_cancellation(
                fixture.root_task,
                reason.clone(),
                session_checkpoint,
            )
            .unwrap_or_else(|error| panic!("session-mutated evidence failed: {error:?}")),
        ));
        assert_eq!(
            validate_transition(&fixture.program, &previous, &session),
            Err(DurableEvidenceError::InvalidState)
        );

        let mut budget = fixture
            .checkpoint
            .clone()
            .recover(Arc::clone(&fixture.program))
            .unwrap_or_else(|error| panic!("checkpoint recovery failed: {error:?}"));
        assert!(matches!(
            budget.foreground_mut().step(),
            MachineStep::Transition(crate::MachineLabel::Deterministic { .. })
        ));
        budget
            .scheduler_mut()
            .cancel_execution("mixed-stop")
            .unwrap_or_else(|error| panic!("whole-graph cancellation failed: {error:?}"));
        assert!(budget.foreground_mut().cancel("mixed-stop").is_some());
        let budget_checkpoint = ConcurrentDurableCheckpointV4::capture(
            budget.foreground(),
            budget.scheduler(),
            budget.sessions(),
        )
        .unwrap_or_else(|error| panic!("budget-mutated checkpoint failed: {error:?}"));
        assert_ne!(
            budget_checkpoint.execution_budget(),
            fixture.checkpoint.execution_budget()
        );
        let budget = super::ConcurrentDurableEvidenceBody::V5(Box::new(
            ConcurrentDurableEvidenceV5::new_cancellation(
                fixture.root_task,
                reason,
                budget_checkpoint,
            )
            .unwrap_or_else(|error| panic!("budget-mutated evidence failed: {error:?}")),
        ));
        assert_eq!(
            validate_transition(&fixture.program, &previous, &budget),
            Err(DurableEvidenceError::InvalidState)
        );
    }

    #[test]
    fn mixed_nested_ownership_rejects_bookkeeping_session_and_budget_mutations() {
        let fixture = mixed_nested_graph_fixture();
        let previous = super::ConcurrentDurableEvidenceBody::V4(Box::new(
            ConcurrentDurableEvidenceV4::new(
                DurableCommitCutV1::Checkpoint,
                fixture.root_task,
                fixture.checkpoint.clone(),
            )
            .unwrap_or_else(|error| panic!("previous evidence failed: {error:?}")),
        ));

        for disposition in [TaskHandleState::Joined, TaskHandleState::Detached] {
            let mut exact = fixture
                .checkpoint
                .clone()
                .recover(Arc::clone(&fixture.program))
                .unwrap_or_else(|error| panic!("checkpoint recovery failed: {error:?}"));
            match disposition {
                TaskHandleState::Joined => {
                    exact
                        .scheduler_mut()
                        .begin_join(
                            fixture.root_task,
                            &task_control(TaskControlSiteKind::Join, 50, &["parent"]),
                            &[fixture.parent.handle_id],
                        )
                        .unwrap_or_else(|error| panic!("exact join failed: {error:?}"));
                }
                TaskHandleState::Detached => {
                    exact
                        .scheduler_mut()
                        .detach(
                            fixture.root_task,
                            &task_control(TaskControlSiteKind::Detach, 50, &["parent"]),
                            fixture.parent.handle_id,
                        )
                        .unwrap_or_else(|error| panic!("exact detach failed: {error:?}"));
                }
                _ => unreachable!("fixture uses one supported ownership transition"),
            }
            let exact_checkpoint = ConcurrentDurableCheckpointV4::capture(
                exact.foreground(),
                exact.scheduler(),
                exact.sessions(),
            )
            .unwrap_or_else(|error| panic!("exact ownership checkpoint failed: {error:?}"));
            let exact = super::ConcurrentDurableEvidenceBody::V4(Box::new(
                ConcurrentDurableEvidenceV4::new(
                    DurableCommitCutV1::TaskOwnership,
                    fixture.parent.task_id,
                    exact_checkpoint,
                )
                .unwrap_or_else(|error| panic!("exact ownership evidence failed: {error:?}")),
            ));
            assert_eq!(
                validate_transition(&fixture.program, &previous, &exact),
                Err(DurableEvidenceError::InvalidState)
            );
        }

        let mut bookkeeping = fixture
            .checkpoint
            .clone()
            .recover(Arc::clone(&fixture.program))
            .unwrap_or_else(|error| panic!("checkpoint recovery failed: {error:?}"));
        bookkeeping
            .scheduler_mut()
            .begin_join(
                fixture.root_task,
                &task_control(TaskControlSiteKind::JoinAll, 51, &["parent", "failed"]),
                &[fixture.parent.handle_id, fixture.failed.handle_id],
            )
            .unwrap_or_else(|error| panic!("multi-handle bookkeeping mutation failed: {error:?}"));
        let bookkeeping_checkpoint = ConcurrentDurableCheckpointV4::capture(
            bookkeeping.foreground(),
            bookkeeping.scheduler(),
            bookkeeping.sessions(),
        )
        .unwrap_or_else(|error| panic!("bookkeeping checkpoint failed: {error:?}"));
        let bookkeeping = super::ConcurrentDurableEvidenceBody::V4(Box::new(
            ConcurrentDurableEvidenceV4::new(
                DurableCommitCutV1::TaskOwnership,
                fixture.parent.task_id,
                bookkeeping_checkpoint,
            )
            .unwrap_or_else(|error| panic!("bookkeeping evidence failed: {error:?}")),
        ));
        assert_eq!(
            validate_transition(&fixture.program, &previous, &bookkeeping),
            Err(DurableEvidenceError::InvalidState)
        );

        let mut session = fixture
            .checkpoint
            .clone()
            .recover(Arc::clone(&fixture.program))
            .unwrap_or_else(|error| panic!("checkpoint recovery failed: {error:?}"));
        session
            .scheduler_mut()
            .detach(
                fixture.root_task,
                &task_control(TaskControlSiteKind::Detach, 52, &["parent"]),
                fixture.parent.handle_id,
            )
            .unwrap_or_else(|error| panic!("ownership transition failed: {error:?}"));
        session
            .sessions_mut()
            .create(
                fixture.root_session,
                fixture.root_task,
                position(53),
                0,
                SessionCreationModeV1::New,
                SessionEstablishmentV1::Separate,
            )
            .unwrap_or_else(|error| panic!("unrelated session mutation failed: {error:?}"));
        let session_checkpoint = ConcurrentDurableCheckpointV4::capture(
            session.foreground(),
            session.scheduler(),
            session.sessions(),
        )
        .unwrap_or_else(|error| panic!("session-mutated ownership checkpoint failed: {error:?}"));
        let session = super::ConcurrentDurableEvidenceBody::V4(Box::new(
            ConcurrentDurableEvidenceV4::new(
                DurableCommitCutV1::TaskOwnership,
                fixture.parent.task_id,
                session_checkpoint,
            )
            .unwrap_or_else(|error| panic!("session-mutated ownership evidence failed: {error:?}")),
        ));
        assert_eq!(
            validate_transition(&fixture.program, &previous, &session),
            Err(DurableEvidenceError::InvalidState)
        );

        let mut budget = fixture
            .checkpoint
            .clone()
            .recover(Arc::clone(&fixture.program))
            .unwrap_or_else(|error| panic!("checkpoint recovery failed: {error:?}"));
        budget
            .scheduler_mut()
            .detach(
                fixture.root_task,
                &task_control(TaskControlSiteKind::Detach, 54, &["parent"]),
                fixture.parent.handle_id,
            )
            .unwrap_or_else(|error| panic!("ownership transition failed: {error:?}"));
        assert!(matches!(
            budget.foreground_mut().step(),
            MachineStep::Transition(crate::MachineLabel::Deterministic { .. })
        ));
        let budget_checkpoint = ConcurrentDurableCheckpointV4::capture(
            budget.foreground(),
            budget.scheduler(),
            budget.sessions(),
        )
        .unwrap_or_else(|error| panic!("budget-mutated ownership checkpoint failed: {error:?}"));
        assert_ne!(
            budget_checkpoint.execution_budget(),
            fixture.checkpoint.execution_budget()
        );
        let budget = super::ConcurrentDurableEvidenceBody::V4(Box::new(
            ConcurrentDurableEvidenceV4::new(
                DurableCommitCutV1::TaskOwnership,
                fixture.parent.task_id,
                budget_checkpoint,
            )
            .unwrap_or_else(|error| panic!("budget-mutated ownership evidence failed: {error:?}")),
        ));
        assert_eq!(
            validate_transition(&fixture.program, &previous, &budget),
            Err(DurableEvidenceError::InvalidState)
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
            ownership: None,
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

    struct MixedNestedGraphFixture {
        program: Arc<MachineProgram>,
        checkpoint: ConcurrentDurableCheckpointV4,
        root_task: ProtocolIdentity,
        root_session: ProtocolIdentity,
        parent: TaskCreationV1,
        failed: TaskCreationV1,
        detached: TaskCreationV1,
        nested: TaskCreationV1,
    }

    fn mixed_nested_graph_fixture() -> MixedNestedGraphFixture {
        let program = nested_spawn_program();
        let execution = fresh(IdentityKind::Execution, 61);
        let root_task = root_task_identity(execution);
        let root_session = fresh(IdentityKind::Session, 62);
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
        let state = ConcurrentTaskStateV1::new(execution, root_task, 16)
            .unwrap_or_else(|error| panic!("task state failed: {error:?}"));
        let mut scheduler = ConcurrentSchedulerV1::new(state, foreground.execution_budget())
            .unwrap_or_else(|error| panic!("scheduler construction failed: {error:?}"));

        let parent_suspension = next_spawn(&mut foreground, "parent");
        let parent = create_spawn_child(
            &mut scheduler,
            &mut sessions,
            root_task,
            root_session,
            &parent_suspension,
        );
        foreground
            .complete_spawn(&parent_suspension, parent.handle_id)
            .unwrap_or_else(|error| panic!("parent spawn completion failed: {error:?}"));
        resolve_spawn_child(
            Arc::clone(&program),
            execution,
            foreground.execution_budget(),
            &mut scheduler,
            &parent,
            &parent_suspension,
        );

        let failed_suspension = next_spawn(&mut foreground, "failed");
        let failed = create_spawn_child(
            &mut scheduler,
            &mut sessions,
            root_task,
            root_session,
            &failed_suspension,
        );
        foreground
            .complete_spawn(&failed_suspension, failed.handle_id)
            .unwrap_or_else(|error| panic!("failed-child spawn completion failed: {error:?}"));
        scheduler
            .resolve_submission(
                failed.task_id,
                Err(HostError {
                    code: Arc::from("executor-closed"),
                    protected_diagnostic: None,
                }),
            )
            .unwrap_or_else(|error| panic!("failed-child submission resolution failed: {error:?}"));

        let detached_suspension = next_spawn(&mut foreground, "detached");
        let detached = create_spawn_child(
            &mut scheduler,
            &mut sessions,
            root_task,
            root_session,
            &detached_suspension,
        );
        foreground
            .complete_spawn(&detached_suspension, detached.handle_id)
            .unwrap_or_else(|error| panic!("detached-child spawn completion failed: {error:?}"));
        resolve_spawn_child(
            Arc::clone(&program),
            execution,
            foreground.execution_budget(),
            &mut scheduler,
            &detached,
            &detached_suspension,
        );
        scheduler
            .detach(
                root_task,
                &task_control(TaskControlSiteKind::Detach, 60, &["detached"]),
                detached.handle_id,
            )
            .unwrap_or_else(|error| panic!("detached-child ownership failed: {error:?}"));

        let nested_suspension = {
            let parent_machine = scheduler
                .machine_mut(parent.task_id)
                .unwrap_or_else(|| panic!("parent machine missing"));
            next_spawn(parent_machine, "nested")
        };
        let nested = create_spawn_child(
            &mut scheduler,
            &mut sessions,
            parent.task_id,
            parent.base_session_id,
            &nested_suspension,
        );
        let checkpoint = ConcurrentDurableCheckpointV4::capture(&foreground, &scheduler, &sessions)
            .unwrap_or_else(|error| panic!("mixed nested checkpoint failed: {error:?}"));
        MixedNestedGraphFixture {
            program,
            checkpoint,
            root_task,
            root_session,
            parent,
            failed,
            detached,
            nested,
        }
    }

    fn next_spawn(machine: &mut Machine, handle: &str) -> crate::MachineSpawnSuspension {
        match machine.step() {
            MachineStep::Transition(crate::MachineLabel::TaskControlSuspended(suspension))
                if suspension.handle.name() == handle =>
            {
                suspension
            }
            other => panic!("machine did not suspend at {handle} spawn: {other:?}"),
        }
    }

    fn create_spawn_child(
        scheduler: &mut ConcurrentSchedulerV1,
        sessions: &mut LogicalSessionRegistryV1,
        parent_task_id: ProtocolIdentity,
        parent_session_id: ProtocolIdentity,
        suspension: &crate::MachineSpawnSuspension,
    ) -> TaskCreationV1 {
        scheduler
            .create_child(
                sessions,
                spawn_request(parent_task_id, parent_session_id, suspension),
                DEFAULT_VALUE_LIMITS,
            )
            .unwrap_or_else(|error| panic!("spawn child creation failed: {error:?}"))
    }

    fn resolve_spawn_child(
        program: Arc<MachineProgram>,
        execution: ProtocolIdentity,
        execution_budget: crate::ExecutionBudget,
        scheduler: &mut ConcurrentSchedulerV1,
        child: &TaskCreationV1,
        suspension: &crate::MachineSpawnSuspension,
    ) {
        let task_path = Arc::from(
            scheduler
                .state()
                .task(child.task_id)
                .unwrap_or_else(|| panic!("spawned task missing"))
                .task_path(),
        );
        let captures = suspension
            .captures
            .iter()
            .map(|capture| capture.task_capture().clone())
            .collect::<Vec<_>>();
        let machine = Machine::new_concurrent_task_body_with_context(
            program,
            &suspension.body,
            &captures,
            execution,
            child.task_id,
            task_path,
            machine_limits(),
            execution_budget,
            suspension.inherited_agent.clone(),
            Some(child.base_session_id),
        )
        .unwrap_or_else(|error| panic!("spawned task machine failed: {error:?}"));
        scheduler
            .resolve_submission(child.task_id, Ok(machine))
            .unwrap_or_else(|error| panic!("spawned task submission failed: {error:?}"));
    }

    fn task_control(
        kind: TaskControlSiteKind,
        position_value: u64,
        handles: &[&str],
    ) -> TaskControlSite {
        TaskControlSite {
            id: StaticSiteId::new(path("crate::main"), position(position_value)),
            kind,
            handles: handles.iter().map(|handle| Arc::from(*handle)).collect(),
            source: SourceSpan::from_portable_parts("recovery-test.gnt", 0, 0)
                .unwrap_or_else(|error| panic!("source span failed: {error:?}")),
        }
    }

    fn program() -> Arc<MachineProgram> {
        Arc::new(
            MachineProgram::new(vec![workflow("crate::child"), workflow("crate::main")])
                .unwrap_or_else(|error| panic!("program failed: {error:?}")),
        )
    }

    fn spawn_program(handles: &[&str]) -> Arc<MachineProgram> {
        source_task_control_program(handles, None)
    }

    fn source_task_control_program(
        handles: &[&str],
        control: Option<(InstructionKind, TypeDescriptor)>,
    ) -> Arc<MachineProgram> {
        let root_path = path("crate::main");
        let caller = CanonicalCallableIdentity::free(&root_path, &[]);
        let bodies = handles
            .iter()
            .enumerate()
            .map(|(index, _)| {
                let body_identity = TaskBodyIdentity::new(
                    caller.clone(),
                    position(u64::try_from(index).unwrap_or(u64::MAX)),
                );
                let body = ExecutableTaskBody::new(
                    body_identity.clone(),
                    TypeDescriptor::UNIT,
                    Vec::new(),
                    ExecutableTaskContext::v1(),
                    vec![
                        Instruction {
                            site: position(0),
                            ty: TypeDescriptor::UNIT,
                            kind: InstructionKind::Push(LogicalValue::unit()),
                        },
                        Instruction {
                            site: position(1),
                            ty: TypeDescriptor::UNIT,
                            kind: InstructionKind::TaskComplete,
                        },
                    ],
                )
                .unwrap_or_else(|error| panic!("task body failed: {error:?}"));
                (body_identity, body)
            })
            .collect::<Vec<_>>();
        let result = control
            .as_ref()
            .map_or(TypeDescriptor::UNIT, |(_, ty)| ty.clone());
        let mut instructions = handles
            .iter()
            .zip(&bodies)
            .enumerate()
            .map(|(index, (handle, (body_identity, _)))| Instruction {
                site: position(u64::try_from(index).unwrap_or(u64::MAX)),
                ty: TypeDescriptor::UNIT,
                kind: InstructionKind::Spawn {
                    handle: ExecutableTaskHandle::new(Arc::from(*handle), TypeDescriptor::UNIT)
                        .unwrap_or_else(|error| panic!("task handle failed: {error:?}")),
                    body: body_identity.clone(),
                },
            })
            .collect::<Vec<_>>();
        if let Some((kind, ty)) = control {
            instructions.push(Instruction {
                site: position(u64::try_from(handles.len()).unwrap_or(u64::MAX)),
                ty,
                kind,
            });
        } else {
            instructions.push(Instruction {
                site: position(u64::try_from(handles.len()).unwrap_or(u64::MAX)),
                ty: TypeDescriptor::UNIT,
                kind: InstructionKind::Push(LogicalValue::unit()),
            });
        }
        instructions.push(Instruction {
            site: position(
                u64::try_from(handles.len())
                    .unwrap_or(u64::MAX)
                    .saturating_add(1),
            ),
            ty: result.clone(),
            kind: InstructionKind::Return,
        });
        let root = Workflow {
            path: root_path,
            parameters: Vec::new(),
            result,
            effects: EffectSet::default(),
            instructions,
        };
        Arc::new(
            MachineProgram::with_task_bodies(
                vec![(caller, root)],
                bodies.into_iter().map(|(_, body)| body).collect(),
            )
            .unwrap_or_else(|error| panic!("spawn program failed: {error:?}")),
        )
    }

    struct SourceOwnershipFixture {
        program: Arc<MachineProgram>,
        checkpoint: ConcurrentDurableCheckpointV4,
        root_task: ProtocolIdentity,
        first: TaskCreationV1,
        second: TaskCreationV1,
    }

    fn source_ownership_fixture(
        control: InstructionKind,
        result: TypeDescriptor,
    ) -> SourceOwnershipFixture {
        source_ownership_fixture_with_status(control, result, false)
    }

    fn source_ownership_fixture_with_child_success(
        control: InstructionKind,
        result: TypeDescriptor,
    ) -> SourceOwnershipFixture {
        source_ownership_fixture_with_status(control, result, true)
    }

    fn source_ownership_fixture_with_status(
        control: InstructionKind,
        result: TypeDescriptor,
        children_succeed: bool,
    ) -> SourceOwnershipFixture {
        let program = source_task_control_program(&["first", "second"], Some((control, result)));
        let execution = fresh(IdentityKind::Execution, 71);
        let root_task = root_task_identity(execution);
        let root_session = fresh(IdentityKind::Session, 72);
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
        let mut children = Vec::new();
        for handle in ["first", "second"] {
            let suspension = next_spawn(&mut foreground, handle);
            let child = scheduler
                .create_child(
                    &mut sessions,
                    spawn_request(root_task, root_session, &suspension),
                    DEFAULT_VALUE_LIMITS,
                )
                .unwrap_or_else(|error| panic!("{handle} task creation failed: {error:?}"));
            foreground
                .complete_spawn(&suspension, child.handle_id)
                .unwrap_or_else(|error| panic!("{handle} spawn completion failed: {error:?}"));
            if children_succeed {
                let task_path: Arc<[Arc<str>]> = Arc::from(
                    scheduler
                        .state()
                        .task(child.task_id)
                        .unwrap_or_else(|| panic!("{handle} task record missing"))
                        .task_path(),
                );
                let captures = suspension
                    .captures
                    .iter()
                    .map(|capture| capture.task_capture().clone())
                    .collect::<Vec<_>>();
                let child_machine = Machine::new_concurrent_task_body_with_context(
                    Arc::clone(&program),
                    &suspension.body,
                    &captures,
                    execution,
                    child.task_id,
                    task_path,
                    machine_limits(),
                    foreground.execution_budget(),
                    suspension.inherited_agent.clone(),
                    Some(child.base_session_id),
                )
                .unwrap_or_else(|error| panic!("{handle} machine failed: {error:?}"));
                scheduler
                    .resolve_submission(child.task_id, Ok(child_machine))
                    .unwrap_or_else(|error| {
                        panic!("{handle} submission resolution failed: {error:?}")
                    });
                for _ in 0..2 {
                    scheduler
                        .step_next()
                        .unwrap_or_else(|error| panic!("{handle} step failed: {error:?}"))
                        .unwrap_or_else(|| panic!("{handle} was not runnable"));
                }
                assert_eq!(
                    scheduler
                        .state()
                        .task(child.task_id)
                        .map(|task| task.status()),
                    Some(&crate::ConcurrentTaskStatusV1::Succeeded(
                        LogicalValue::unit()
                    ))
                );
            } else {
                scheduler
                    .resolve_submission(
                        child.task_id,
                        Err(HostError {
                            code: Arc::from("executor-closed"),
                            protected_diagnostic: None,
                        }),
                    )
                    .unwrap_or_else(|error| {
                        panic!("{handle} submission resolution failed: {error:?}")
                    });
            }
            children.push(child);
        }
        let checkpoint = ConcurrentDurableCheckpointV4::capture(&foreground, &scheduler, &sessions)
            .unwrap_or_else(|error| panic!("source ownership checkpoint failed: {error:?}"));
        let first = children.remove(0);
        let second = children.remove(0);
        SourceOwnershipFixture {
            program,
            checkpoint,
            root_task,
            first,
            second,
        }
    }

    fn nested_spawn_program() -> Arc<MachineProgram> {
        let root_path = path("crate::main");
        let caller = CanonicalCallableIdentity::free(&root_path, &[]);
        let parent_identity = TaskBodyIdentity::new(caller.clone(), position(0));
        let failed_identity = TaskBodyIdentity::new(caller.clone(), position(1));
        let detached_identity = TaskBodyIdentity::new(caller.clone(), position(2));
        let nested_spawn_site = StructuralPosition::new(vec![0, 0])
            .unwrap_or_else(|error| panic!("nested spawn site failed: {error:?}"));
        let nested_result_site = StructuralPosition::new(vec![0, 1])
            .unwrap_or_else(|error| panic!("nested result site failed: {error:?}"));
        let nested_completion_site = StructuralPosition::new(vec![0, 2])
            .unwrap_or_else(|error| panic!("nested completion site failed: {error:?}"));
        let nested_identity = TaskBodyIdentity::new(caller.clone(), nested_spawn_site.clone());
        let leaf_body = |identity: TaskBodyIdentity| {
            ExecutableTaskBody::new(
                identity,
                TypeDescriptor::UNIT,
                Vec::new(),
                ExecutableTaskContext::v1(),
                vec![
                    Instruction {
                        site: position(0),
                        ty: TypeDescriptor::UNIT,
                        kind: InstructionKind::Push(LogicalValue::unit()),
                    },
                    Instruction {
                        site: position(1),
                        ty: TypeDescriptor::UNIT,
                        kind: InstructionKind::TaskComplete,
                    },
                ],
            )
            .unwrap_or_else(|error| panic!("leaf task body failed: {error:?}"))
        };
        let parent_body = ExecutableTaskBody::new(
            parent_identity.clone(),
            TypeDescriptor::UNIT,
            Vec::new(),
            ExecutableTaskContext::v1(),
            vec![
                Instruction {
                    site: nested_spawn_site,
                    ty: TypeDescriptor::UNIT,
                    kind: InstructionKind::Spawn {
                        handle: ExecutableTaskHandle::new(
                            Arc::from("nested"),
                            TypeDescriptor::UNIT,
                        )
                        .unwrap_or_else(|error| panic!("nested handle failed: {error:?}")),
                        body: nested_identity.clone(),
                    },
                },
                Instruction {
                    site: nested_result_site,
                    ty: TypeDescriptor::UNIT,
                    kind: InstructionKind::Push(LogicalValue::unit()),
                },
                Instruction {
                    site: nested_completion_site,
                    ty: TypeDescriptor::UNIT,
                    kind: InstructionKind::TaskComplete,
                },
            ],
        )
        .unwrap_or_else(|error| panic!("parent task body failed: {error:?}"));
        let failed_body = leaf_body(failed_identity.clone());
        let detached_body = leaf_body(detached_identity.clone());
        let nested_body = leaf_body(nested_identity.clone());
        let root = Workflow {
            path: root_path,
            parameters: Vec::new(),
            result: TypeDescriptor::UNIT,
            effects: EffectSet::default(),
            instructions: [
                ("parent", parent_identity),
                ("failed", failed_identity),
                ("detached", detached_identity),
            ]
            .into_iter()
            .enumerate()
            .map(|(index, (handle, body))| Instruction {
                site: position(u64::try_from(index).unwrap_or(u64::MAX)),
                ty: TypeDescriptor::UNIT,
                kind: InstructionKind::Spawn {
                    handle: ExecutableTaskHandle::new(Arc::from(handle), TypeDescriptor::UNIT)
                        .unwrap_or_else(|error| panic!("root handle failed: {error:?}")),
                    body,
                },
            })
            .chain([
                Instruction {
                    site: position(3),
                    ty: TypeDescriptor::UNIT,
                    kind: InstructionKind::Push(LogicalValue::unit()),
                },
                Instruction {
                    site: position(4),
                    ty: TypeDescriptor::UNIT,
                    kind: InstructionKind::Return,
                },
            ])
            .collect(),
        };
        Arc::new(
            MachineProgram::with_task_bodies(
                vec![(caller, root)],
                vec![parent_body, nested_body, failed_body, detached_body],
            )
            .unwrap_or_else(|error| panic!("nested spawn program failed: {error:?}")),
        )
    }

    fn spawn_request(
        parent_task_id: ProtocolIdentity,
        parent_session_id: ProtocolIdentity,
        suspension: &crate::MachineSpawnSuspension,
    ) -> TaskCreationRequestV1 {
        TaskCreationRequestV1 {
            parent_task_id,
            handle_name: Arc::from(suspension.handle.name()),
            workflow: suspension.workflow.clone(),
            spawn_site: suspension.site.clone(),
            spawn_occurrence: suspension.occurrence,
            result_type: suspension.handle.result_type().clone(),
            captures: suspension
                .captures
                .iter()
                .map(|capture| capture.task_capture().clone())
                .collect(),
            inherited_agent: suspension.inherited_agent.clone(),
            parent_session_id,
        }
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
