//! Authoritative evidence for the composed concurrent-durable refinement.

use std::collections::BTreeSet;
use std::sync::Arc;

use gantry_core::identity::ProtocolIdentity;
use gantry_core::portable::{IdentityKind, TaskHandleState, TaskStatusKind};
use gantry_host::journal::{
    BatchLocalEvidenceId, JournalEvidenceReferenceV1, JournalPrefixV1, UnfinalizedEvidenceV1,
    validate_journal_prefix,
};
use gantry_ir::MachineProgram;

use super::{
    CONCURRENT_DURABLE_EVIDENCE_KIND_V1, DurableCommitCoordinatorV1, DurableCommitCutV1,
    DurableCommitError, DurableEvidenceCommitV1, DurableEvidenceError, decode_hex, field, object,
    push_json_string, require_exact_fields, string,
};
use crate::{
    ConcurrentDurableCheckpointV1, ConcurrentSchedulerV1, DURABLE_EVENT_DISPATCHED_KIND_V1,
    DURABLE_EVENT_OCCURRENCE_KIND_V1, DURABLE_EVENT_SETTLED_KIND_V1, DurableEventOccurrenceV1,
    LogicalSessionRegistryV1, Machine, RecoveredConcurrentDurableExecutionV1,
    RecoveredDurableEventsV1,
};

/// One canonical authoritative evidence body for a complete concurrent task graph.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConcurrentDurableEvidenceV1 {
    cut: DurableCommitCutV1,
    task_id: ProtocolIdentity,
    checkpoint: ConcurrentDurableCheckpointV1,
}

impl ConcurrentDurableEvidenceV1 {
    /// Constructs one validated post-transition graph checkpoint.
    pub fn new(
        cut: DurableCommitCutV1,
        task_id: ProtocolIdentity,
        checkpoint: ConcurrentDurableCheckpointV1,
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
    pub const fn checkpoint(&self) -> &ConcurrentDurableCheckpointV1 {
        &self.checkpoint
    }

    /// Encodes the unique version-one canonical JSON evidence body.
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
        output.push_str(",\"format\":\"gantry.concurrent-durable-evidence/v1\",\"task_id\":");
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
        if string(&document, field(root, "format")?)? != "gantry.concurrent-durable-evidence/v1" {
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
        let checkpoint = ConcurrentDurableCheckpointV1::decode(program, &bytes)
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
            CONCURRENT_DURABLE_EVIDENCE_KIND_V1,
            self.canonical_body(),
            references,
            Arc::from([]),
        )
        .map_err(DurableEvidenceError::Journal)
    }
}

impl DurableCommitCoordinatorV1<'_> {
    /// Commits one complete task-graph cut before its dependent external boundary.
    pub async fn commit_concurrent_cut(
        &mut self,
        cut: DurableCommitCutV1,
        affected_task: ProtocolIdentity,
        foreground: &Machine,
        scheduler: &ConcurrentSchedulerV1,
        sessions: &LogicalSessionRegistryV1,
    ) -> Result<DurableEvidenceCommitV1, DurableCommitError> {
        let checkpoint = ConcurrentDurableCheckpointV1::capture(foreground, scheduler, sessions)
            .map_err(|error| {
                DurableCommitError::Evidence(DurableEvidenceError::ConcurrentCheckpoint(error))
            })?;
        if checkpoint.execution_id() != self.execution_id
            || checkpoint.root_task_id() != self.task_id
        {
            return Err(DurableCommitError::InvalidState);
        }
        let evidence = ConcurrentDurableEvidenceV1::new(cut, affected_task, checkpoint)
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
        let body = evidence
            .unfinalized(local_id.clone(), references)
            .map_err(DurableCommitError::Evidence)?;
        self.commit_body(cut, local_number, local_id, body).await
    }
}

/// Recovered composed runtime plus the latest authoritative journal coordinates.
#[derive(Debug)]
pub struct RecoveredConcurrentDurableStateV1 {
    execution: RecoveredConcurrentDurableExecutionV1,
    events: RecoveredDurableEventsV1,
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

    /// Returns mutable access to the recovered composed execution.
    pub const fn execution_mut(&mut self) -> &mut RecoveredConcurrentDurableExecutionV1 {
        &mut self.execution
    }

    /// Returns recovered journal-first events and delivery obligations.
    #[must_use]
    pub const fn events(&self) -> &RecoveredDurableEventsV1 {
        &self.events
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

/// Projects a full authoritative combined prefix into the existing runtime components.
pub fn recover_concurrent_authoritative_prefix(
    program: Arc<MachineProgram>,
    prefix: &JournalPrefixV1,
) -> Result<RecoveredConcurrentDurableStateV1, DurableEvidenceError> {
    validate_journal_prefix(prefix).map_err(DurableEvidenceError::Journal)?;
    let JournalPrefixV1::Full(prefix) = prefix else {
        return Err(DurableEvidenceError::UnsupportedEvidenceKind);
    };
    let mut latest_graph: Option<ConcurrentDurableEvidenceV1> = None;
    let mut journal_tip: Option<(u64, ProtocolIdentity)> = None;
    let mut events = RecoveredDurableEventsV1::default();
    let mut known = BTreeSet::new();
    for envelope in prefix.evidence.iter() {
        match journal_tip {
            None if envelope.sequence == 1 && envelope.references.is_empty() => {}
            Some((sequence, evidence_id))
                if sequence.checked_add(1) == Some(envelope.sequence)
                    && envelope.references.contains(&evidence_id)
                    && envelope.references.iter().all(|id| known.contains(id)) => {}
            _ => return Err(DurableEvidenceError::InvalidCausalOrder),
        }

        if envelope.kind.as_ref() == CONCURRENT_DURABLE_EVIDENCE_KIND_V1 {
            let evidence = ConcurrentDurableEvidenceV1::decode(&program, &envelope.canonical_body)?;
            if let Some(prior) = &latest_graph {
                validate_transition(prior, &evidence)?;
            } else if evidence.cut != DurableCommitCutV1::Checkpoint {
                return Err(DurableEvidenceError::InvalidState);
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
    let latest_cut = evidence.cut;
    let execution = evidence
        .checkpoint
        .recover(program)
        .map_err(DurableEvidenceError::ConcurrentCheckpoint)?;
    Ok(RecoveredConcurrentDurableStateV1 {
        execution,
        events,
        latest_sequence,
        latest_evidence_id,
        latest_cut,
    })
}

fn validate_transition(
    previous: &ConcurrentDurableEvidenceV1,
    current: &ConcurrentDurableEvidenceV1,
) -> Result<(), DurableEvidenceError> {
    if current.execution_id() != previous.execution_id()
        || current.checkpoint.root_task_id() != previous.checkpoint.root_task_id()
    {
        return Err(DurableEvidenceError::MixedExecution);
    }
    let previous_tasks = previous
        .checkpoint
        .task_ids()
        .into_iter()
        .collect::<BTreeSet<_>>();
    let current_tasks = current
        .checkpoint
        .task_ids()
        .into_iter()
        .collect::<BTreeSet<_>>();
    if !previous_tasks.is_subset(&current_tasks) {
        return Err(DurableEvidenceError::InvalidState);
    }
    let valid = match current.cut {
        DurableCommitCutV1::Checkpoint => previous_tasks == current_tasks,
        DurableCommitCutV1::TaskCreation => {
            current.checkpoint.created_task_count()
                == previous.checkpoint.created_task_count().saturating_add(1)
                && current_tasks
                    .difference(&previous_tasks)
                    .copied()
                    .collect::<Vec<_>>()
                    == [current.task_id]
        }
        DurableCommitCutV1::TaskOwnership => {
            previous_tasks == current_tasks
                && previous.checkpoint.task_handle_state(current.task_id)
                    == Some(TaskHandleState::Attached)
                && matches!(
                    current.checkpoint.task_handle_state(current.task_id),
                    Some(TaskHandleState::Joined | TaskHandleState::Detached)
                )
        }
        DurableCommitCutV1::Cancellation => {
            previous_tasks == current_tasks
                && !previous.checkpoint.task_is_cancelled(current.task_id)
                && current.checkpoint.task_is_cancelled(current.task_id)
        }
        DurableCommitCutV1::TaskSettlement => {
            previous_tasks == current_tasks
                && previous.checkpoint.task_status(current.task_id) == Some(TaskStatusKind::Running)
                && matches!(
                    current.checkpoint.task_status(current.task_id),
                    Some(
                        TaskStatusKind::Succeeded
                            | TaskStatusKind::Failed
                            | TaskStatusKind::Cancelled
                    )
                )
        }
        DurableCommitCutV1::ForegroundCompletion => {
            previous_tasks == current_tasks
                && !previous.checkpoint.foreground_is_fixed()
                && current.checkpoint.foreground_is_fixed()
        }
        DurableCommitCutV1::TerminalCompletion => {
            previous_tasks == current_tasks
                && !previous.checkpoint.terminal_is_fixed()
                && current.checkpoint.terminal_is_fixed()
        }
        DurableCommitCutV1::OperationPrepared
        | DurableCommitCutV1::OperationOutcome
        | DurableCommitCutV1::OperationResult
        | DurableCommitCutV1::RetryWaiting => false,
    };
    valid
        .then_some(())
        .ok_or(DurableEvidenceError::InvalidState)
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::pin::pin;
    use std::sync::Arc;
    use std::task::{Context, Poll, Waker};

    use gantry_core::identity::ProtocolIdentity;
    use gantry_core::portable::{IdentityKind, TaskStatusKind};
    use gantry_core::value::{DEFAULT_VALUE_LIMITS, LogicalValue};
    use gantry_host::journal::{
        AcquireJournalOwnerV1, FullJournalPrefixV1, JournalId, JournalOwnerOperationV1,
        JournalPrefixV1, JournalStorage, ReadJournalPrefixV1,
    };
    use gantry_ir::{
        CanonicalPath, EffectSet, Instruction, InstructionKind, MachineProgram, Parameter,
        StructuralPosition, TypeDescriptor, Workflow,
    };

    use super::{DurableCommitCoordinatorV1, DurableCommitCutV1, DurableEvidenceError};
    use crate::{
        CanonicalTranscriptV1, ConcurrentSchedulerV1, ConcurrentTaskStateV1, DurableTransitionSink,
        InMemoryJournalStore, LogicalSessionRegistryV1, Machine, MachineLimits,
        SessionCreationModeV1, TaskCreationRequestV1, recover_concurrent_authoritative_prefix,
    };

    #[test]
    fn journal_commit_recovers_pre_submission_graph_and_rejects_repeated_creation() {
        let program = program();
        let execution = fresh(IdentityKind::Execution, 1);
        let root_task = ProtocolIdentity::derive(IdentityKind::Task, b"{\"root\":true}")
            .unwrap_or_else(|error| panic!("root task identity failed: {error}"));
        let root_session = fresh(IdentityKind::Session, 2);
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
        let mut scheduler = ConcurrentSchedulerV1::new(state);

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
        let initial = block_on(commits.commit_concurrent_cut(
            DurableCommitCutV1::Checkpoint,
            root_task,
            &foreground,
            &scheduler,
            &sessions,
        ))
        .unwrap_or_else(|error| panic!("initial graph commit failed: {error:?}"));
        assert_eq!(initial.sequence, 1);

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
