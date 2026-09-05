//! Public conformance coverage for the combined concurrent-durable refinement.

use std::future::Future;
use std::pin::pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use gantry::event::{EventDraft, EventEnvelope, EventPayload, ProtectedReference};
use gantry::host::event::{
    EventRetryPolicy, ProtectedPayload, RedactionCapabilities, SinkDeliveryPolicy, SinkId,
};
use gantry::host::journal::{
    AcquireJournalOwnerV1, FullJournalPrefixV1, JournalId, JournalOwnerOperationV1,
    JournalPayloadKey, JournalPrefixV1, JournalStorage, ReadJournalPrefixV1, ReleaseJournalOwnerV1,
    ResolveJournalPayloadV1,
};
use gantry::identity::ProtocolIdentity;
use gantry::ir::generated::TaskControlSiteKind;
use gantry::ir::{
    CanonicalPath, EffectSet, Instruction, InstructionKind, MachineProgram, Parameter,
    StaticSiteId, StructuralPosition, TaskControlSite, TypeDescriptor, Workflow,
};
use gantry::portable::{
    CancellationReasonCategory, EventKind, IdentityKind, JitterMode, ProtectedReferenceClass,
    SinkClass, TaskHandleState, TaskStatusKind,
};
use gantry::runtime::{
    CanonicalTranscriptV1, ConcurrentSchedulerV1, ConcurrentTaskStateV1, ConcurrentTaskStatusV1,
    ConcurrentTerminalCategoryV1, DurableCommitCoordinatorV1, DurableCommitCutV1,
    DurableEventBarrierV1, DurableEventCommitCoordinatorV1, DurableEventOccurrenceV1,
    DurableEventPlanV1, DurableSinkObligationV1, DurableTransitionSink, ExecutionBudget,
    InMemoryJournalStore, JoinResolutionV1, JoinStartV1, LogicalSessionRegistryV1, Machine,
    MachineLimits, MachineOutcome, SessionCreationModeV1, TaskCreationRequestV1, TaskStateError,
    recover_concurrent_authoritative_prefix, root_task_identity,
};
use gantry::source::{ByteSpan, SourceLimits, SourceSnapshotBuilder, SourceSpan};
use gantry::timestamp::UtcTimestamp;
use gantry::value::{DEFAULT_VALUE_LIMITS, LogicalValue};

#[test]
fn public_combined_crash_cuts_recover_without_repeating_task_transitions() {
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
    let execution_budget = foreground.execution_budget();
    let state = ConcurrentTaskStateV1::new(execution, root_task, 4)
        .unwrap_or_else(|error| panic!("task state failed: {error:?}"));
    let mut scheduler = ConcurrentSchedulerV1::new(state, execution_budget.clone())
        .unwrap_or_else(|error| panic!("scheduler construction failed: {error:?}"));

    let storage: Arc<dyn JournalStorage> = Arc::new(InMemoryJournalStore::new());
    let journal_id = JournalId::new("public-combined-crash-cuts")
        .unwrap_or_else(|error| panic!("journal id failed: {error:?}"));
    let owner = block_on(storage.acquire_owner(AcquireJournalOwnerV1 {
        journal_id: journal_id.clone(),
        operation: JournalOwnerOperationV1::Start,
    }))
    .unwrap_or_else(|error| panic!("owner acquisition failed: {error:?}"));
    let release_token = owner.token.clone();
    let sink = DurableTransitionSink::new(Arc::clone(&storage), journal_id.clone(), owner.token);
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

    let child = scheduler
        .create_child(
            &mut sessions,
            creation_request(root_task, root_session),
            DEFAULT_VALUE_LIMITS,
        )
        .unwrap_or_else(|error| panic!("child creation failed: {error:?}"));
    let creation = block_on(commits.commit_concurrent_cut(
        DurableCommitCutV1::TaskCreation,
        child.task_id,
        &foreground,
        &scheduler,
        &sessions,
    ))
    .unwrap_or_else(|error| panic!("creation commit failed: {error:?}"));
    assert_eq!(creation.sequence, 2);

    let recovered_creation = recover(Arc::clone(&program), storage.as_ref(), &journal_id);
    let recovered_child = recovered_creation
        .execution()
        .scheduler()
        .state()
        .task(child.task_id)
        .unwrap_or_else(|| panic!("created child was not recovered"));
    assert_eq!(recovered_child.status().kind(), TaskStatusKind::Submitting);
    assert!(!recovered_child.handle_is_visible());
    assert!(
        recovered_creation
            .execution()
            .scheduler()
            .state()
            .parent_is_suspended(root_task)
    );
    assert!(
        recovered_creation
            .execution()
            .sessions()
            .get(child.base_session_id)
            .is_some()
    );

    let child_task_path = Arc::from(
        scheduler
            .state()
            .task(child.task_id)
            .unwrap_or_else(|| panic!("created child missing"))
            .task_path(),
    );
    scheduler
        .resolve_submission(
            child.task_id,
            Ok(child_machine(
                Arc::clone(&program),
                execution,
                child.task_id,
                child_task_path,
                child.base_session_id,
                execution_budget.clone(),
            )),
        )
        .unwrap_or_else(|error| panic!("submission failed: {error:?}"));
    let submission = block_on(commits.commit_concurrent_cut(
        DurableCommitCutV1::Checkpoint,
        root_task,
        &foreground,
        &scheduler,
        &sessions,
    ))
    .unwrap_or_else(|error| panic!("submission checkpoint failed: {error:?}"));
    assert_eq!(submission.sequence, 3);

    let ownership = scheduler
        .detach(root_task, &detach_control(), child.handle_id)
        .unwrap_or_else(|error| panic!("detach failed: {error:?}"));
    assert_eq!(ownership.disposition(), TaskHandleState::Detached);
    let ownership_commit = block_on(commits.commit_concurrent_cut(
        DurableCommitCutV1::TaskOwnership,
        child.task_id,
        &foreground,
        &scheduler,
        &sessions,
    ))
    .unwrap_or_else(|error| panic!("ownership commit failed: {error:?}"));
    assert_eq!(ownership_commit.sequence, 4);

    let protected_reference =
        ProtectedReference::new("event:combined-output", ProtectedReferenceClass::RawOutput)
            .unwrap_or_else(|error| panic!("protected reference failed: {error:?}"));
    let event = EventEnvelope::complete(
        fresh(IdentityKind::Event, 3),
        fresh(IdentityKind::Activity, 4),
        UtcTimestamp::from_unix_seconds(0, 1)
            .unwrap_or_else(|error| panic!("timestamp failed: {error:?}")),
        EventDraft::new(EventKind::OperationCompletion, event_payload())
            .with_execution_id(execution)
            .and_then(|draft| draft.with_protected_references(vec![protected_reference.clone()]))
            .unwrap_or_else(|error| panic!("event execution identity failed: {error:?}")),
    )
    .unwrap_or_else(|error| panic!("event completion failed: {error:?}"));
    let required_sink =
        SinkId::new("required-sink").unwrap_or_else(|error| panic!("sink id failed: {error:?}"));
    let occurrence = DurableEventOccurrenceV1::new(
        ownership_commit.evidence_id,
        event,
        DurableEventPlanV1::new(vec![DurableSinkObligationV1::new(
            required_sink.clone(),
            required_policy(),
        )])
        .unwrap_or_else(|error| panic!("event plan failed: {error:?}")),
    )
    .unwrap_or_else(|error| panic!("event occurrence failed: {error:?}"));
    let mut event_commits = DurableEventCommitCoordinatorV1::new(
        &sink,
        (ownership_commit.evidence_id, ownership_commit.sequence),
    )
    .unwrap_or_else(|error| panic!("event coordinator failed: {error:?}"));
    let protected_bytes: Arc<[u8]> = Arc::from(&b"combined-secret-output"[..]);
    let protected_payload = ProtectedPayload {
        reference: protected_reference,
        bytes: Arc::clone(&protected_bytes),
    };
    let occurrence_commit = block_on(
        event_commits.commit_occurrence(&occurrence, std::slice::from_ref(&protected_payload)),
    )
    .unwrap_or_else(|error| panic!("event occurrence commit failed: {error:?}"));
    assert_eq!(occurrence_commit.sequence, 5);
    let resolved_payload = block_on(
        storage.resolve_payload(ResolveJournalPayloadV1 {
            journal_id: journal_id.clone(),
            key: JournalPayloadKey::new("event:combined-output")
                .unwrap_or_else(|error| panic!("payload key failed: {error:?}")),
        }),
    )
    .unwrap_or_else(|error| panic!("protected payload recovery failed: {error:?}"));
    assert_eq!(resolved_payload.bytes, protected_bytes);
    let JournalPrefixV1::Full(prefix_after_occurrence) = read_prefix(storage.as_ref(), &journal_id)
    else {
        panic!("in-memory journal returned a snapshot")
    };
    assert!(
        !String::from_utf8_lossy(&prefix_after_occurrence.evidence[4].canonical_body)
            .contains("combined-secret-output")
    );

    let recovered_gap = recover(Arc::clone(&program), storage.as_ref(), &journal_id);
    assert!(
        recovered_gap
            .events()
            .event_for_cause(ownership_commit.evidence_id)
            .is_some()
    );
    assert!(
        !recovered_gap
            .events()
            .requires_replacement(ownership_commit.evidence_id)
    );
    assert_eq!(
        recovered_gap
            .events()
            .required_barrier_through(occurrence_commit.sequence),
        DurableEventBarrierV1::Pending {
            event_id: occurrence.event().event_id(),
            sink_id: required_sink.clone(),
        }
    );

    let mut commits = DurableCommitCoordinatorV1::new(
        &sink,
        execution,
        root_task,
        Some((occurrence_commit.evidence_id, occurrence_commit.sequence)),
    )
    .unwrap_or_else(|error| panic!("post-event coordinator failed: {error:?}"));
    assert_eq!(
        scheduler
            .cancel_execution("shutdown")
            .unwrap_or_else(|error| panic!("cancellation failed: {error:?}")),
        [root_task, child.task_id]
    );
    assert!(foreground.cancel("shutdown").is_some());
    commits
        .set_graph_cancellation(
            gantry::runtime::CancellationReason::new(
                CancellationReasonCategory::Caller,
                Some(Arc::from("shutdown")),
                None,
                32,
            )
            .unwrap_or_else(|error| panic!("cancellation reason failed: {error:?}")),
        )
        .unwrap_or_else(|error| panic!("graph cancellation setup failed: {error:?}"));
    let cancellation = block_on(commits.commit_concurrent_cut(
        DurableCommitCutV1::Cancellation,
        root_task,
        &foreground,
        &scheduler,
        &sessions,
    ))
    .unwrap_or_else(|error| panic!("cancellation commit failed: {error:?}"));
    assert_eq!(cancellation.sequence, 6);
    assert!(
        scheduler
            .cancel_execution("later-reason")
            .unwrap_or_else(|error| panic!("repeat cancellation failed: {error:?}"))
            .is_empty()
    );
    assert_eq!(
        scheduler.state().task_cancellation_reason(root_task),
        Some("shutdown")
    );

    while matches!(
        scheduler
            .state()
            .task(child.task_id)
            .map(|task| task.status()),
        Some(ConcurrentTaskStatusV1::Running)
    ) {
        scheduler
            .step_next()
            .unwrap_or_else(|error| panic!("scheduler step failed: {error:?}"));
    }
    assert!(matches!(
        scheduler.state().task(child.task_id).map(|task| task.status()),
        Some(ConcurrentTaskStatusV1::Cancelled(reason)) if reason.as_ref() == "shutdown"
    ));
    let settlement = block_on(commits.commit_concurrent_cut(
        DurableCommitCutV1::TaskSettlement,
        child.task_id,
        &foreground,
        &scheduler,
        &sessions,
    ))
    .unwrap_or_else(|error| panic!("settlement commit failed: {error:?}"));
    assert_eq!(settlement.sequence, 7);

    scheduler
        .complete_foreground(MachineOutcome::Cancelled(Arc::from("shutdown")))
        .unwrap_or_else(|error| panic!("foreground completion failed: {error:?}"));
    let foreground_commit = block_on(commits.commit_concurrent_cut(
        DurableCommitCutV1::ForegroundCompletion,
        root_task,
        &foreground,
        &scheduler,
        &sessions,
    ))
    .unwrap_or_else(|error| panic!("foreground commit failed: {error:?}"));
    assert_eq!(foreground_commit.sequence, 8);

    let terminal = scheduler
        .complete_terminal()
        .unwrap_or_else(|error| panic!("terminal completion failed: {error:?}"));
    assert_eq!(
        terminal.category,
        ConcurrentTerminalCategoryV1::Cancellation
    );
    let terminal_commit = block_on(commits.commit_concurrent_cut(
        DurableCommitCutV1::TerminalCompletion,
        root_task,
        &foreground,
        &scheduler,
        &sessions,
    ))
    .unwrap_or_else(|error| panic!("terminal commit failed: {error:?}"));
    assert_eq!(terminal_commit.sequence, 9);

    let recovered_terminal = recover(Arc::clone(&program), storage.as_ref(), &journal_id);
    assert_eq!(recovered_terminal.latest_sequence(), 9);
    assert_eq!(
        recovered_terminal.latest_cut(),
        DurableCommitCutV1::TerminalCompletion
    );
    assert!(matches!(
        recovered_terminal
            .execution()
            .scheduler()
            .state()
            .terminal_outcome(),
        Some(outcome)
            if outcome.category == ConcurrentTerminalCategoryV1::Cancellation
                && outcome.detached_failures.is_empty()
    ));
    assert_eq!(
        recovered_terminal
            .events()
            .required_barrier_through(terminal_commit.sequence),
        DurableEventBarrierV1::Pending {
            event_id: occurrence.event().event_id(),
            sink_id: required_sink,
        }
    );

    block_on(storage.release_owner(ReleaseJournalOwnerV1 {
        journal_id: journal_id.clone(),
        ownership_token: release_token,
    }))
    .unwrap_or_else(|error| panic!("owner release failed: {error:?}"));
    let after_release = recover(Arc::clone(&program), storage.as_ref(), &journal_id);
    assert_eq!(after_release.latest_sequence(), 9);
    assert!(
        after_release
            .execution()
            .scheduler()
            .shutdown_cohort()
            .attached_tasks
            .is_empty()
    );
    assert!(
        after_release
            .execution()
            .scheduler()
            .shutdown_cohort()
            .detached_tasks
            .is_empty()
    );

    let JournalPrefixV1::Full(full) = read_prefix(storage.as_ref(), &journal_id) else {
        panic!("in-memory journal returned a snapshot")
    };
    let mut evidence = full.evidence.to_vec();
    let mut repeated_settlement = evidence[6].clone();
    repeated_settlement.sequence = 10;
    repeated_settlement.evidence_id = ProtocolIdentity::from_storage_material([99; 32]);
    repeated_settlement.references = Arc::from([terminal_commit.evidence_id]);
    evidence.push(repeated_settlement);
    let repeated_prefix = JournalPrefixV1::Full(FullJournalPrefixV1 {
        journal_id,
        evidence: Arc::from(evidence),
        committed_through: 10,
    });
    assert_eq!(
        recover_concurrent_authoritative_prefix(program, &repeated_prefix).map(|_| ()),
        Err(gantry::runtime::DurableEvidenceError::InvalidState)
    );
}

#[test]
fn public_combined_join_ownership_and_settlement_recover_once() {
    let program = program();
    let execution = fresh(IdentityKind::Execution, 21);
    let root_task = root_task_identity(execution);
    let root_session = fresh(IdentityKind::Session, 22);
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
    let execution_budget = foreground.execution_budget();
    let state = ConcurrentTaskStateV1::new(execution, root_task, 2)
        .unwrap_or_else(|error| panic!("task state failed: {error:?}"));
    let mut scheduler = ConcurrentSchedulerV1::new(state, execution_budget.clone())
        .unwrap_or_else(|error| panic!("scheduler construction failed: {error:?}"));

    let storage: Arc<dyn JournalStorage> = Arc::new(InMemoryJournalStore::new());
    let journal_id = JournalId::new("public-combined-join")
        .unwrap_or_else(|error| panic!("journal id failed: {error:?}"));
    let owner = block_on(storage.acquire_owner(AcquireJournalOwnerV1 {
        journal_id: journal_id.clone(),
        operation: JournalOwnerOperationV1::Start,
    }))
    .unwrap_or_else(|error| panic!("owner acquisition failed: {error:?}"));
    let sink = DurableTransitionSink::new(Arc::clone(&storage), journal_id.clone(), owner.token);
    let mut commits = DurableCommitCoordinatorV1::new(&sink, execution, root_task, None)
        .unwrap_or_else(|error| panic!("commit coordinator failed: {error:?}"));
    block_on(commits.commit_concurrent_cut(
        DurableCommitCutV1::Checkpoint,
        root_task,
        &foreground,
        &scheduler,
        &sessions,
    ))
    .unwrap_or_else(|error| panic!("initial graph commit failed: {error:?}"));

    let child = scheduler
        .create_child(
            &mut sessions,
            TaskCreationRequestV1 {
                parent_task_id: root_task,
                handle_name: Arc::from("joined"),
                workflow: path("crate::main"),
                spawn_site: site(0),
                spawn_occurrence: 0,
                result_type: TypeDescriptor::UNIT,
                captures: Vec::new(),
                inherited_agent: None,
                parent_session_id: root_session,
            },
            DEFAULT_VALUE_LIMITS,
        )
        .unwrap_or_else(|error| panic!("child creation failed: {error:?}"));
    block_on(commits.commit_concurrent_cut(
        DurableCommitCutV1::TaskCreation,
        child.task_id,
        &foreground,
        &scheduler,
        &sessions,
    ))
    .unwrap_or_else(|error| panic!("creation commit failed: {error:?}"));
    let child_task_path = Arc::from(
        scheduler
            .state()
            .task(child.task_id)
            .unwrap_or_else(|| panic!("created child missing"))
            .task_path(),
    );
    scheduler
        .resolve_submission(
            child.task_id,
            Ok(child_machine(
                Arc::clone(&program),
                execution,
                child.task_id,
                child_task_path,
                child.base_session_id,
                execution_budget.clone(),
            )),
        )
        .unwrap_or_else(|error| panic!("submission failed: {error:?}"));
    block_on(commits.commit_concurrent_cut(
        DurableCommitCutV1::Checkpoint,
        root_task,
        &foreground,
        &scheduler,
        &sessions,
    ))
    .unwrap_or_else(|error| panic!("submission checkpoint failed: {error:?}"));

    let control = join_control();
    let ownership = match scheduler
        .begin_join(root_task, &control, &[child.handle_id])
        .unwrap_or_else(|error| panic!("join ownership failed: {error:?}"))
    {
        JoinStartV1::Started(ownership) => ownership,
        JoinStartV1::Empty => panic!("nonempty join unexpectedly reduced as empty"),
    };
    assert_eq!(
        scheduler.begin_join(root_task, &control, &[child.handle_id]),
        Err(TaskStateError::ConsumedHandle)
    );
    block_on(commits.commit_concurrent_cut(
        DurableCommitCutV1::TaskOwnership,
        child.task_id,
        &foreground,
        &scheduler,
        &sessions,
    ))
    .unwrap_or_else(|error| panic!("ownership commit failed: {error:?}"));

    while matches!(
        scheduler
            .state()
            .task(child.task_id)
            .map(|task| task.status()),
        Some(ConcurrentTaskStatusV1::Running)
    ) {
        scheduler
            .step_next()
            .unwrap_or_else(|error| panic!("scheduler step failed: {error:?}"));
    }
    let settlement = block_on(commits.commit_concurrent_cut(
        DurableCommitCutV1::TaskSettlement,
        child.task_id,
        &foreground,
        &scheduler,
        &sessions,
    ))
    .unwrap_or_else(|error| panic!("settlement commit failed: {error:?}"));

    let recovered = recover(program, storage.as_ref(), &journal_id);
    assert_eq!(recovered.latest_sequence(), settlement.sequence);
    let recovered_task = recovered
        .execution()
        .scheduler()
        .state()
        .task(child.task_id)
        .unwrap_or_else(|| panic!("joined child was not recovered"));
    assert_eq!(recovered_task.handle_state(), TaskHandleState::Joined);
    assert_eq!(recovered_task.status().kind(), TaskStatusKind::Succeeded);
    assert_eq!(
        recovered
            .execution()
            .scheduler()
            .resolve_join(&ownership, DEFAULT_VALUE_LIMITS),
        Ok(JoinResolutionV1::Succeeded(LogicalValue::unit()))
    );
}

fn recover(
    program: Arc<MachineProgram>,
    storage: &dyn JournalStorage,
    journal_id: &JournalId,
) -> gantry::runtime::RecoveredConcurrentDurableStateV1 {
    let prefix = read_prefix(storage, journal_id);
    recover_concurrent_authoritative_prefix(program, &prefix)
        .unwrap_or_else(|error| panic!("combined recovery failed: {error:?}"))
}

fn read_prefix(storage: &dyn JournalStorage, journal_id: &JournalId) -> JournalPrefixV1 {
    block_on(storage.read_prefix(ReadJournalPrefixV1 {
        journal_id: journal_id.clone(),
    }))
    .unwrap_or_else(|error| panic!("prefix read failed: {error:?}"))
}

fn creation_request(
    parent_task_id: ProtocolIdentity,
    parent_session_id: ProtocolIdentity,
) -> TaskCreationRequestV1 {
    TaskCreationRequestV1 {
        parent_task_id,
        handle_name: Arc::from("background"),
        workflow: path("crate::main"),
        spawn_site: site(0),
        spawn_occurrence: 0,
        result_type: TypeDescriptor::UNIT,
        captures: Vec::new(),
        inherited_agent: Some(Arc::from("writer")),
        parent_session_id,
    }
}

fn detach_control() -> TaskControlSite {
    TaskControlSite {
        id: StaticSiteId::new(path("crate::main"), site(9)),
        kind: TaskControlSiteKind::Detach,
        handles: vec![Arc::from("background")],
        source: source_span(),
    }
}

fn join_control() -> TaskControlSite {
    TaskControlSite {
        id: StaticSiteId::new(path("crate::main"), site(8)),
        kind: TaskControlSiteKind::Join,
        handles: vec![Arc::from("joined")],
        source: source_span(),
    }
}

fn source_span() -> SourceSpan {
    let limits = SourceLimits::new(1, 64, 64, 1, 1)
        .unwrap_or_else(|error| panic!("source limits failed: {error:?}"));
    let mut builder = SourceSnapshotBuilder::new(limits);
    let id = builder
        .add_file("main.gnt", b"detach(background)")
        .unwrap_or_else(|error| panic!("source fixture failed: {error:?}"));
    let snapshot = builder.finish();
    let record = snapshot
        .get(&id)
        .unwrap_or_else(|| panic!("source record missing"));
    SourceSpan::new(
        record,
        ByteSpan::new(0, 1).unwrap_or_else(|error| panic!("span failed: {error:?}")),
    )
    .unwrap_or_else(|error| panic!("source span failed: {error:?}"))
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
                site: site(0),
                ty: TypeDescriptor::UNIT,
                kind: InstructionKind::Push(LogicalValue::unit()),
            },
            Instruction {
                site: site(1),
                ty: TypeDescriptor::UNIT,
                kind: InstructionKind::Return,
            },
        ],
    }
}

fn child_machine(
    program: Arc<MachineProgram>,
    execution: ProtocolIdentity,
    task_id: ProtocolIdentity,
    task_path: Arc<[Arc<str>]>,
    session: ProtocolIdentity,
    execution_budget: ExecutionBudget,
) -> Machine {
    Machine::new_concurrent_task_with_context(
        program,
        &path("crate::child"),
        Vec::new(),
        execution,
        task_id,
        task_path,
        machine_limits(),
        execution_budget,
        None,
        Some(session),
    )
    .unwrap_or_else(|error| panic!("child machine failed: {error:?}"))
}

fn machine_limits() -> MachineLimits {
    MachineLimits::new(32, 4, 4, 8, 16, DEFAULT_VALUE_LIMITS)
        .unwrap_or_else(|| unreachable!("positive machine limits"))
}

fn event_payload() -> EventPayload {
    EventPayload::from_validated_canonical_bytes(Arc::<[u8]>::from(&b"{}"[..]))
        .unwrap_or_else(|error| panic!("event payload failed: {error:?}"))
}

fn required_policy() -> SinkDeliveryPolicy {
    SinkDeliveryPolicy::new(
        SinkClass::Required,
        false,
        "redaction-v1",
        RedactionCapabilities {
            operation_request_content: false,
            operation_result_content: false,
            integration_diagnostics: false,
            source_snippets: false,
        },
        EventRetryPolicy::new("retry-v1", 2, 10, 40, JitterMode::None)
            .unwrap_or_else(|error| panic!("retry policy failed: {error:?}")),
        30,
    )
    .unwrap_or_else(|error| panic!("sink policy failed: {error:?}"))
}

fn path(value: &str) -> CanonicalPath {
    CanonicalPath::new(value).unwrap_or_else(|error| panic!("path failed: {error}"))
}

fn site(value: u64) -> StructuralPosition {
    StructuralPosition::new(vec![value]).unwrap_or_else(|error| panic!("site failed: {error}"))
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
