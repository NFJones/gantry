//! Regression tests for private staging and journal-first publication.

use super::*;
use crate::{
    CanonicalTranscriptV1, DurableTransitionSink, InMemoryJournalStore, MachineLimits, MachineStep,
    ResourceRegistry, ResourceRegistryRefusal,
};
use gantry_core::portable::IdentityKind;
use gantry_core::value::{DEFAULT_VALUE_LIMITS, LogicalValue};
use gantry_host::contracts::HostFuture;
use gantry_host::journal::*;
use gantry_ir::generated::{OperationSiteKind, RecoveryClass};
use gantry_ir::{
    CanonicalCallableIdentity, CanonicalPath, CanonicalSignature, EffectSet, ExecutableAction,
    ExecutableOperation, ExecutableTaskBody, ExecutableTaskContext, ExecutableTaskHandle,
    Instruction, InstructionKind, LivenessRoot, MachineProgram, OperationKind, OwnerGeneration,
    ResourceCarrier, ResourceLedger, ResourceState, TaskBodyIdentity, TypeDescriptor, Workflow,
};

/// Probes publication from inside a wake callback to catch lock-held notification.
struct SettlementWake {
    coordinator: ExecutionCoordinator,
    task: ProtocolIdentity,
    wakes: std::sync::atomic::AtomicUsize,
}

impl std::task::Wake for SettlementWake {
    fn wake(self: Arc<Self>) {
        let snapshot = self
            .coordinator
            .try_snapshot()
            .unwrap_or_else(|| panic!("settlement wake held coordinator lock"));
        assert!(snapshot.state().root_settled_outcome().is_some());
        assert!(snapshot.state().task_record(self.task).is_some());
        self.wakes.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Explores both waiter-registration orders around the publication linearization.
#[test]
fn settlement_registration_races_do_not_lose_notifications() {
    for seed in 0..32 {
        let (coordinator, mut root, mut children) = fixture();
        let execution = root.execution_id();
        let task = root.task_id();
        let storage = Arc::new(InMemoryJournalStore::new());
        let journal = JournalId::new(format!("registration-race-{seed}"))
            .unwrap_or_else(|error| panic!("journal: {error:?}"));
        let owner = ready(storage.acquire_owner(AcquireJournalOwnerV1 {
            journal_id: journal.clone(),
            operation: JournalOwnerOperationV1::Start,
        }))
        .unwrap_or_else(|error| panic!("owner: {error:?}"));
        let sink = DurableTransitionSink::new(storage, journal, owner.token);
        let mut commits = DurableCommitCoordinatorV1::new(&sink, execution, task, None)
            .unwrap_or_else(|error| panic!("commits: {error:?}"));
        let initial = coordinator
            .capture_checkpoint(&root, &children)
            .unwrap_or_else(|error| panic!("capture: {error:?}"));
        ready(commits.commit_graph_checkpoint(DurableCommitCutV1::Checkpoint, task, initial))
            .unwrap_or_else(|error| panic!("initial: {error:?}"));
        let mut stage = coordinator
            .stage_graph(&mut root, &mut children)
            .unwrap_or_else(|error| panic!("stage: {error:?}"));
        stage.update(|root, _, tasks, _| {
            for _ in 0..10 {
                if let MachineStep::Transition(crate::MachineLabel::TaskSettled(outcome)) =
                    root.step()
                {
                    tasks
                        .settle(task, outcome)
                        .unwrap_or_else(|error| panic!("settle: {error:?}"));
                    return;
                }
            }
            panic!("root did not settle");
        });
        let probe = Arc::new(SettlementWake {
            coordinator: coordinator.clone(),
            task,
            wakes: std::sync::atomic::AtomicUsize::new(0),
        });
        let barrier = std::sync::Barrier::new(2);
        std::thread::scope(|scope| {
            let observer = scope.spawn(|| {
                let mut waiter = Box::pin(
                    coordinator
                        .wait_for_task_settlement(task)
                        .unwrap_or_else(|error| panic!("waiter: {error:?}")),
                );
                let waker = Waker::from(probe.clone());
                if seed % 2 == 0 {
                    assert!(
                        waiter
                            .as_mut()
                            .poll(&mut Context::from_waker(&waker))
                            .is_pending()
                    );
                }
                barrier.wait();
                let pending = waiter
                    .as_mut()
                    .poll(&mut Context::from_waker(&waker))
                    .is_pending();
                (waiter, pending)
            });
            barrier.wait();
            ready(stage.commit(&mut commits, DurableCommitCutV1::TaskSettlement, task))
                .unwrap_or_else(|error| panic!("seed {seed}: commit: {error:?}"));
            let (mut waiter, pending) = observer
                .join()
                .unwrap_or_else(|_| panic!("seed {seed}: observer panicked"));
            assert!(
                waiter
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_ready(),
                "seed {seed}"
            );
            if pending || seed % 2 == 0 {
                assert_eq!(
                    probe.wakes.load(std::sync::atomic::Ordering::SeqCst),
                    1,
                    "seed {seed}"
                );
            }
        });
    }
}

/// Creates an empty child graph with one executable root.
fn fixture() -> (
    ExecutionCoordinator,
    Machine,
    BTreeMap<ProtocolIdentity, Machine>,
) {
    let (coordinator, machine, children, _) = fixture_with_program();
    (coordinator, machine, children)
}

/// The current graph wire has no resource-record member and must not silently drop one.
#[test]
fn resource_records_refuse_durable_graph_capture_and_staging_without_mutation() {
    let (coordinator, mut root, mut children) = fixture();
    lock(&coordinator.inner.state).resources =
        Some(ResourceRegistry::with_adapter_identity_limit(0));
    let before_adapter_policy = coordinator.snapshot();
    assert_eq!(
        coordinator.capture_checkpoint(&root, &children).err(),
        Some(crate::ConcurrentDurableCheckpointError::ResourceStateUnsupported)
    );
    assert_eq!(
        coordinator.stage_graph(&mut root, &mut children).err(),
        Some(TaskStateError::ResourceStateUnsupported)
    );
    assert_eq!(coordinator.snapshot(), before_adapter_policy);
    assert!(!lock(&coordinator.inner.state).durable_publication_reserved);
    lock(&coordinator.inner.state).resources =
        Some(ResourceRegistry::with_accounting_limits(1, 1, 1));
    let before_policy = coordinator.snapshot();
    let checkpoint = coordinator
        .capture_checkpoint(&root, &children)
        .unwrap_or_else(|error| panic!("empty retained policy capture: {error:?}"));
    assert_eq!(checkpoint.retained_resource_limit(), Some(1));
    let stage = coordinator
        .stage_graph(&mut root, &mut children)
        .unwrap_or_else(|error| panic!("empty retained policy staging: {error:?}"));
    drop(stage);
    assert_eq!(coordinator.snapshot(), before_policy);
    assert!(!lock(&coordinator.inner.state).durable_publication_reserved);
    lock(&coordinator.inner.state).resources = Some(ResourceRegistry::with_live_limit(1));
    assert!(coordinator.capture_checkpoint(&root, &children).is_ok());
    let path = CanonicalPath::new("crate::checkpoint_resource")
        .unwrap_or_else(|error| panic!("resource path: {error}"));
    let subject = crate::ResourceSubjectBinding::derive(
        &path,
        path.clone(),
        StructuralPosition::new(vec![0]).unwrap_or_else(|error| panic!("site: {error}")),
        0,
        Some(OperationKind::LiveResource),
        Arc::new(Mutex::new(crate::machine::ResourceOperationLease::open())),
        (root.execution_id(), root.task_id()),
    );
    let record = ResourceLedger::new(
        OwnerGeneration::new(4),
        ResourceState::Usable,
        &[LivenessRoot::Resource],
        &[],
    )
    .unwrap_or_else(|error| panic!("record: {error:?}"))
    .durable_record();
    lock(&coordinator.inner.state)
        .resources
        .as_mut()
        .unwrap_or_else(|| panic!("registry enabled"))
        .admit(subject, ResourceCarrier::ReconstructionRecord, record)
        .unwrap_or_else(|error| panic!("admission: {error:?}"));
    let before = coordinator.snapshot();
    let machine_before = root.checkpoint().canonical_bytes();
    assert_eq!(
        coordinator.capture_checkpoint(&root, &children).err(),
        Some(crate::ConcurrentDurableCheckpointError::ResourceStateUnsupported)
    );
    assert_eq!(
        coordinator.stage_graph(&mut root, &mut children).err(),
        Some(TaskStateError::ResourceStateUnsupported)
    );
    assert_eq!(coordinator.snapshot(), before);
    assert_eq!(root.checkpoint().canonical_bytes(), machine_before);
    assert!(!lock(&coordinator.inner.state).durable_publication_reserved);
}

/// Settled issuing work permits exact accounting and containment recovery, never physical recovery.
#[test]
fn resource_records_survive_version_eight_graph_recovery() {
    let (old, root, _) = fixture();
    let execution = root.execution_id();
    let path = CanonicalPath::new("crate::main").unwrap_or_else(|error| panic!("path: {error}"));
    let action =
        CanonicalPath::new("crate::resource").unwrap_or_else(|error| panic!("action: {error}"));
    let program = Arc::new(
        MachineProgram::new(vec![Workflow {
            path: path.clone(),
            parameters: vec![],
            result: TypeDescriptor::UNIT,
            effects: EffectSet::default(),
            instructions: vec![
                Instruction {
                    site: StructuralPosition::new(vec![0])
                        .unwrap_or_else(|error| panic!("site: {error}")),
                    ty: TypeDescriptor::UNIT,
                    kind: InstructionKind::OperationCall {
                        operation: ExecutableOperation {
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
                                parameters: vec![],
                            }),
                            template_segments: vec![],
                            interpolation_types: vec![],
                            named_input_names: vec![],
                            named_input_types: vec![],
                            retry_limit: None,
                            session_mode: None,
                            attempted: false,
                        },
                        operands: 0,
                    },
                },
                Instruction {
                    site: StructuralPosition::new(vec![1])
                        .unwrap_or_else(|error| panic!("site: {error}")),
                    ty: TypeDescriptor::UNIT,
                    kind: InstructionKind::Return,
                },
            ],
        }])
        .unwrap_or_else(|error| panic!("program: {error:?}")),
    );
    let mut root = Machine::new(
        Arc::clone(&program),
        &path,
        vec![],
        execution,
        root.checkpoint().machine_limits(),
    )
    .unwrap_or_else(|error| panic!("machine: {error:?}"));
    let old = lock(&old.inner.state);
    let coordinator = ExecutionCoordinator::new_with_budget_and_accounting_limits(
        old.tasks.clone(),
        old.sessions.clone(),
        root.execution_budget(),
        1,
        2,
        3,
    )
    .unwrap_or_else(|error| panic!("coordinator: {error:?}"));
    assert!(matches!(
        root.step(),
        MachineStep::Transition(crate::MachineLabel::OperationPrepared(_))
    ));
    let subject = root
        .pending_resource_subject()
        .unwrap_or_else(|| panic!("subject"));
    let owner = OwnerGeneration::new(4);
    let record = ResourceLedger::new(owner, ResourceState::Usable, &[LivenessRoot::Resource], &[])
        .unwrap_or_else(|error| panic!("ledger: {error:?}"));
    coordinator
        .admit_resource_with_issuing_evidence(
            &root,
            ResourceCarrier::ReconstructionRecord,
            record.durable_record(),
            65_536,
        )
        .unwrap_or_else(|error| panic!("admission: {error:?}"));
    assert_eq!(
        coordinator
            .capture_checkpoint(&root, &BTreeMap::new())
            .err(),
        Some(crate::ConcurrentDurableCheckpointError::ResourceStateUnsupported)
    );
    coordinator
        .settle_resource_containment(
            &subject,
            owner,
            gantry_ir::Completion::observed(
                gantry_ir::ExternalOutcome::Accepted,
                gantry_ir::EffectState::NotStarted,
            ),
        )
        .unwrap_or_else(|error| panic!("containment: {error:?}"));
    let operation = root
        .checkpoint()
        .pending_operation()
        .unwrap_or_else(|| panic!("operation"))
        .identity;
    root.fail_operation(
        operation,
        gantry_core::portable::RuntimeErrorCategory::ExecutorFailure,
    )
    .unwrap_or_else(|error| panic!("settlement: {error:?}"));
    let before = coordinator.snapshot();
    let unrelated_root = Machine::new_with_budget(
        Arc::clone(&program),
        &path,
        vec![],
        execution,
        root.checkpoint().machine_limits(),
        root.execution_budget(),
    )
    .unwrap_or_else(|error| panic!("otherwise valid root: {error:?}"));
    assert_eq!(
        coordinator
            .capture_checkpoint(&unrelated_root, &BTreeMap::new())
            .err(),
        Some(crate::ConcurrentDurableCheckpointError::InvalidCheckpoint),
        "a shared budget cannot substitute for retained issuing-machine generation history"
    );
    assert_eq!(coordinator.snapshot(), before);
    let checkpoint = coordinator
        .capture_checkpoint(&root, &BTreeMap::new())
        .unwrap_or_else(|error| panic!("resource capture: {error:?}"));
    let bytes = checkpoint.canonical_bytes();
    let mut replaced = checkpoint
        .clone()
        .recover(Arc::clone(&program))
        .unwrap_or_else(|error| panic!("mutable recovered owner: {error:?}"));
    let replacement = Machine::new_with_budget(
        Arc::clone(&program),
        &path,
        vec![],
        execution,
        root.checkpoint().machine_limits(),
        replaced.foreground().execution_budget(),
    )
    .unwrap_or_else(|error| panic!("replacement root: {error:?}"));
    *replaced.foreground_mut() = replacement;
    assert_eq!(
        replaced.into_driver_admission().err(),
        Some(TaskStateError::InvalidTaskMachine),
        "consuming admission must revalidate mutable issuing-machine history"
    );
    assert_eq!(&bytes[..8], b"GNTCDP08");
    assert!(crate::ConcurrentDurableCheckpointV7::decode(&program, &bytes).is_err());
    assert!(crate::ConcurrentDurableCheckpointV8::decode(&program, &bytes).is_ok());
    assert!(
        crate::ConcurrentDurableCheckpointV8::decode(&program, &bytes[..bytes.len() - 1]).is_err()
    );
    // Reframe the one-record section to distinguish raw byte admission from member validation.
    let envelope =
        crate::encode_resource_recovery_envelope(&checkpoint.resource_records()[0], 65_536)
            .unwrap_or_else(|error| panic!("fixture envelope: {error:?}"));
    let cleanup = root.task_id().to_string();
    let section_start = bytes.len() - (32 + cleanup.len() + envelope.len());
    let reframe = |payload: &[u8], count: u64, current_owner: u64, cleanup: &str| {
        let mut framed = bytes[..section_start].to_vec();
        framed.extend_from_slice(&count.to_be_bytes());
        framed.extend_from_slice(&current_owner.to_be_bytes());
        for member in [cleanup.as_bytes(), payload] {
            framed.extend_from_slice(
                &u64::try_from(member.len())
                    .unwrap_or_else(|_| panic!("bounded member"))
                    .to_be_bytes(),
            );
            framed.extend_from_slice(member);
        }
        framed
    };
    assert_eq!(reframe(&envelope, 1, owner.value(), &cleanup), bytes);
    let maximum = 1_048_576_usize; // Normative GNTCDP08 resource-section ceiling.
    let raw_exact = reframe(
        &vec![0; maximum - 32 - cleanup.len()],
        1,
        owner.value(),
        &cleanup,
    );
    assert_eq!(
        crate::ConcurrentDurableCheckpointV8::decode(&program, &raw_exact).err(),
        Some(crate::ConcurrentDurableCheckpointError::InvalidCheckpoint),
        "an admitted exact-size section must reach member validation"
    );
    let raw_excess = reframe(
        &vec![0; maximum - 31 - cleanup.len()],
        1,
        owner.value(),
        &cleanup,
    );
    assert_eq!(
        crate::ConcurrentDurableCheckpointV8::decode(&program, &raw_excess).err(),
        Some(crate::ConcurrentDurableCheckpointError::InvalidEncoding),
        "excess raw section bytes must refuse before member recovery"
    );
    assert_eq!(
        crate::ConcurrentDurableCheckpointV8::decode(
            &program,
            &reframe(&envelope, u64::MAX, owner.value(), &cleanup)
        )
        .err(),
        Some(crate::ConcurrentDurableCheckpointError::InvalidEncoding)
    );
    assert_eq!(
        crate::ConcurrentDurableCheckpointV8::decode(
            &program,
            &reframe(&envelope, 1, u64::MAX, &cleanup)
        )
        .err(),
        Some(crate::ConcurrentDurableCheckpointError::InvalidCheckpoint)
    );
    assert_eq!(
        crate::ConcurrentDurableCheckpointV8::decode(
            &program,
            &reframe(
                &envelope,
                1,
                owner.value(),
                &root.execution_id().to_string()
            )
        )
        .err(),
        Some(crate::ConcurrentDurableCheckpointError::InvalidEncoding)
    );
    let refused = checkpoint
        .clone()
        .recover(Arc::clone(&program))
        .unwrap_or_else(|error| panic!("machine-only recovery: {error:?}"))
        .into_machine_graph()
        .err()
        .unwrap_or_else(|| panic!("resource owner must be retained"));
    assert_eq!(
        refused
            .capture_replayed_checkpoint()
            .unwrap_or_else(|error| panic!("retained recovery: {error:?}"))
            .resource_records(),
        checkpoint.resource_records()
    );
    let recovered = crate::ConcurrentDurableCheckpointV4::decode_compatible(&program, &bytes)
        .unwrap_or_else(|error| panic!("decode: {error:?}"))
        .recover(Arc::clone(&program))
        .unwrap_or_else(|error| panic!("recover: {error:?}"))
        .into_driver_admission()
        .unwrap_or_else(|error| panic!("driver admission: {error:?}"));
    assert_eq!(
        recovered.coordinator().snapshot().resource_records(),
        before.resource_records()
    );
    assert_eq!(recovered.coordinator().retained_resource_limit(), Some(3));
    assert!(!recovered.coordinator().has_pending_resource_operations());
    let state = lock(&recovered.coordinator().inner.state);
    let account = state
        .resources
        .as_ref()
        .unwrap_or_else(|| panic!("resources"))
        .account(&subject)
        .unwrap_or_else(|| panic!("account"));
    assert_eq!(
        account.containment().outcome(),
        Some(gantry_ir::ExternalOutcome::Accepted)
    );
    drop(state);
    assert_eq!(coordinator.snapshot(), before);
    let mut children = BTreeMap::new();
    let (recovered_coordinator, mut recovered_root, mut recovered_children, _) =
        recovered.into_parts();
    recovered_coordinator
        .begin_resource_finish(&subject, owner)
        .unwrap_or_else(|error| panic!("recovered accounting advancement: {error:?}"));
    let recovered_before = recovered_coordinator.snapshot();
    assert_eq!(
        recovered_coordinator
            .stage_graph(&mut recovered_root, &mut recovered_children)
            .err(),
        Some(TaskStateError::ResourceStateUnsupported),
        "recovery must seed the committed resource image"
    );
    assert_eq!(recovered_coordinator.snapshot(), recovered_before);
    let machine_before = root.checkpoint().canonical_bytes();
    let stage = coordinator
        .stage_graph(&mut root, &mut children)
        .unwrap_or_else(|error| panic!("resource staging: {error:?}"));
    drop(stage);
    assert_eq!(coordinator.snapshot(), before);
    assert_eq!(root.checkpoint().canonical_bytes(), machine_before);
    assert!(!lock(&coordinator.inner.state).durable_publication_reserved);
    let storage = Arc::new(InMemoryJournalStore::new());
    let journal = JournalId::new("resource-record-graph")
        .unwrap_or_else(|error| panic!("journal: {error:?}"));
    let journal_owner = ready(storage.acquire_owner(AcquireJournalOwnerV1 {
        journal_id: journal.clone(),
        operation: JournalOwnerOperationV1::Start,
    }))
    .unwrap_or_else(|error| panic!("journal owner: {error:?}"));
    let sink = DurableTransitionSink::new(storage.clone(), journal.clone(), journal_owner.token);
    let task = root.task_id();
    let mut commits = DurableCommitCoordinatorV1::new(&sink, execution, task, None)
        .unwrap_or_else(|error| panic!("commits: {error:?}"));
    ready(commits.commit_graph_checkpoint(
        DurableCommitCutV1::Checkpoint,
        task,
        checkpoint.clone(),
    ))
    .unwrap_or_else(|error| panic!("initial resource commit: {error:?}"));
    let mut stage = coordinator
        .stage_graph(&mut root, &mut children)
        .unwrap_or_else(|error| panic!("resource commit stage: {error:?}"));
    stage
        .update(|root, _, tasks, _| {
            tasks.settle(
                task,
                root.outcome()
                    .cloned()
                    .unwrap_or_else(|| panic!("fixed machine outcome")),
            )
        })
        .unwrap_or_else(|error| panic!("task settlement: {error:?}"));
    ready(stage.commit(&mut commits, DurableCommitCutV1::TaskSettlement, task))
        .unwrap_or_else(|error| panic!("resource commit: {error:?}"));
    let prefix = ready(storage.read_prefix(ReadJournalPrefixV1 {
        journal_id: journal.clone(),
    }))
    .unwrap_or_else(|error| panic!("prefix: {error:?}"));
    let replayed = crate::recover_concurrent_authoritative_prefix(Arc::clone(&program), &prefix)
        .unwrap_or_else(|error| panic!("resource replay: {error:?}"));
    coordinator
        .begin_resource_finish(&subject, owner)
        .unwrap_or_else(|error| panic!("local accounting advancement: {error:?}"));
    let changed_snapshot = coordinator.snapshot();
    assert_eq!(
        coordinator.stage_graph(&mut root, &mut children).err(),
        Some(TaskStateError::ResourceStateUnsupported),
        "unsupported resource mutation must refuse before journal submission"
    );
    assert_eq!(coordinator.snapshot(), changed_snapshot);
    assert!(!lock(&coordinator.inner.state).durable_publication_reserved);
    assert_eq!(
        ready(storage.read_prefix(ReadJournalPrefixV1 {
            journal_id: journal
        }))
        .unwrap_or_else(|error| panic!("unchanged prefix: {error:?}")),
        prefix
    );
    let replayed_checkpoint = replayed
        .execution()
        .capture_replayed_checkpoint()
        .unwrap_or_else(|error| panic!("replay capture: {error:?}"));
    assert_eq!(
        replayed_checkpoint.resource_records(),
        checkpoint.resource_records()
    );
    let without_records = replayed_checkpoint
        .with_resource_records(Arc::clone(&program), vec![])
        .unwrap_or_else(|error| panic!("otherwise valid record-free checkpoint: {error:?}"));
    let frontier_before = commits.frontier();
    assert_eq!(
        ready(commits.commit_graph_checkpoint(
            DurableCommitCutV1::TaskSettlement,
            task,
            without_records.clone(),
        )),
        Err(DurableCommitError::InvalidState),
        "direct commits must refuse resource-image drift before storage"
    );
    assert_eq!(commits.frontier(), frontier_before);
    let mut unseeded = DurableCommitCoordinatorV1::new(&sink, execution, task, frontier_before)
        .unwrap_or_else(|error| panic!("recovered committer: {error:?}"));
    assert_eq!(
        ready(unseeded.commit_graph_checkpoint(
            DurableCommitCutV1::TaskSettlement,
            task,
            without_records.clone(),
        )),
        Err(DurableCommitError::InvalidState),
        "an unknown predecessor image cannot be inferred empty from its successor"
    );
    assert_eq!(unseeded.frontier(), frontier_before);
    assert_eq!(
        ready(storage.read_prefix(ReadJournalPrefixV1 {
            journal_id: sink.journal_id().clone(),
        }))
        .unwrap_or_else(|error| panic!("direct refusal prefix: {error:?}")),
        prefix
    );
    let changed = crate::ConcurrentDurableEvidenceV4::new(
        DurableCommitCutV1::TaskSettlement,
        task,
        without_records,
    )
    .unwrap_or_else(|error| panic!("changed evidence: {error:?}"));
    let JournalPrefixV1::Full(mut full) = prefix else {
        panic!("full prefix")
    };
    let mut evidence = full.evidence.to_vec();
    evidence
        .last_mut()
        .unwrap_or_else(|| panic!("settlement evidence"))
        .canonical_body = Arc::from(changed.canonical_body());
    full.evidence = Arc::from(evidence);
    assert!(
        crate::recover_concurrent_authoritative_prefix(program, &JournalPrefixV1::Full(full))
            .is_err(),
        "replay must refuse removed resource records"
    );
}

/// Reaping accounting must not make retained failed-adapter evidence disappear on recovery.
#[test]
fn adapter_poison_history_refuses_empty_graph_capture_and_staging() {
    let (coordinator, mut root, mut children) = fixture();
    let path =
        CanonicalPath::new("crate::poison_history").unwrap_or_else(|error| panic!("path: {error}"));
    let lease = Arc::new(Mutex::new(crate::machine::ResourceOperationLease::open()));
    let subject = crate::ResourceSubjectBinding::derive(
        &path,
        path.clone(),
        StructuralPosition::new(vec![0]).unwrap_or_else(|error| panic!("site: {error}")),
        0,
        Some(OperationKind::LiveResource),
        Arc::clone(&lease),
        (root.execution_id(), root.task_id()),
    );
    let owner = OwnerGeneration::new(4);
    let record = ResourceLedger::new(owner, ResourceState::Usable, &[LivenessRoot::Resource], &[])
        .unwrap_or_else(|error| panic!("record: {error:?}"));
    let mut registry = ResourceRegistry::with_limits(1, 1);
    registry
        .admit(
            subject.clone(),
            ResourceCarrier::ReconstructionRecord,
            record.durable_record(),
        )
        .unwrap_or_else(|error| panic!("admit: {error:?}"));
    let receiver = gantry_ir::TypeExpression::from_canonical_string("crate::Adapter", 4)
        .unwrap_or_else(|error| panic!("receiver: {error:?}"));
    let instance = gantry_ir::AdapterInstance::bind(
        &gantry_ir::CanonicalImplementationIdentity::inherent(&receiver),
        gantry_ir::RightsSet::empty(),
        owner,
        0,
    );
    registry
        .bind_adapter_instance(&subject, owner, instance.clone())
        .unwrap_or_else(|error| panic!("bind: {error:?}"));
    registry
        .poison_adapter_instance(&subject, owner, gantry_ir::PoisonReason::InvariantFailure)
        .unwrap_or_else(|error| panic!("poison: {error:?}"));
    registry
        .begin_finish(&subject, owner)
        .unwrap_or_else(|error| panic!("finish: {error:?}"));
    registry
        .complete_finalization(&subject, owner, 20)
        .unwrap_or_else(|error| panic!("finalization: {error:?}"));
    registry
        .close_liveness_root(&subject, owner, LivenessRoot::Resource)
        .unwrap_or_else(|error| panic!("root: {error:?}"));
    registry
        .retire(
            &subject,
            gantry_ir::RetentionFence::new(2, 10)
                .unwrap_or_else(|error| panic!("fence: {error:?}")),
            owner,
            OwnerGeneration::new(5),
            35,
        )
        .unwrap_or_else(|error| panic!("retire: {error:?}"));
    registry
        .delete(&subject, owner)
        .unwrap_or_else(|error| panic!("delete: {error:?}"));
    assert_eq!(registry.reap_deleted(), 1);
    lock(&lease).pending = false;
    assert!(registry.declared_records().is_empty());
    assert_eq!(registry.pending_operations(), 0);
    assert!(registry.host_values_are_quiescent());
    lock(&coordinator.inner.state).resources = Some(registry);
    let before = coordinator.snapshot();
    let machine_before = root.checkpoint().canonical_bytes();
    assert_eq!(
        coordinator.capture_checkpoint(&root, &children).err(),
        Some(crate::ConcurrentDurableCheckpointError::ResourceStateUnsupported)
    );
    assert_eq!(
        coordinator.stage_graph(&mut root, &mut children).err(),
        Some(TaskStateError::ResourceStateUnsupported)
    );
    assert_eq!(coordinator.snapshot(), before);
    assert_eq!(root.checkpoint().canonical_bytes(), machine_before);
    assert!(!lock(&coordinator.inner.state).durable_publication_reserved);
    // The failed identity still cannot bind after the refused capture.
    let mut state = lock(&coordinator.inner.state);
    let registry = state
        .resources
        .as_mut()
        .unwrap_or_else(|| panic!("registry"));
    lock(&lease).pending = true;
    registry
        .admit(
            subject.clone(),
            ResourceCarrier::ReconstructionRecord,
            record.durable_record(),
        )
        .unwrap_or_else(|error| panic!("readmit: {error:?}"));
    assert!(matches!(
        registry.bind_adapter_instance(&subject, owner, instance),
        Err(ResourceRegistryRefusal::AdapterBinding(
            crate::AdapterBindingRefusal::Substitution(
                gantry_ir::OperationAbiError::AdapterInstancePoisoned { .. }
            )
        ))
    ));
}

/// Empty accounting remains enabled with exact limits after durable graph recovery.
#[test]
fn empty_resource_policy_survives_graph_recovery() {
    // Legacy two-ceiling policy remains on the version-six wire.
    let (coordinator, root, children, program) = fixture_with_program();
    lock(&coordinator.inner.state).resources = Some(ResourceRegistry::with_limits(0, 3));
    let checkpoint = coordinator
        .capture_checkpoint(&root, &children)
        .unwrap_or_else(|error| panic!("capture: {error:?}"));
    let bytes = checkpoint.canonical_bytes();
    assert_eq!(bytes.get(..8), Some(b"GNTCDP06".as_slice()));
    assert!(crate::ConcurrentDurableCheckpointV4::decode(&program, &bytes).is_err());
    assert!(crate::ConcurrentDurableCheckpointV5::decode(&program, &bytes).is_err());
    assert!(crate::ConcurrentDurableCheckpointV6::decode(&program, &bytes).is_ok());
    assert!(
        crate::ConcurrentDurableCheckpointV6::decode(&program, &bytes[..bytes.len() - 1]).is_err()
    );
    let decoded = crate::ConcurrentDurableCheckpointV4::decode_compatible(&program, &bytes)
        .unwrap_or_else(|error| panic!("decode: {error:?}"));
    let refused = decoded
        .clone()
        .recover(Arc::clone(&program))
        .unwrap_or_else(|error| panic!("recover for machine-only refusal: {error:?}"))
        .into_machine_graph()
        .err()
        .unwrap_or_else(|| panic!("machines alone must not discard accounting policy"));
    assert_eq!(
        refused
            .capture_replayed_checkpoint()
            .unwrap_or_else(|error| panic!("refused owner retains policy: {error:?}"))
            .resource_policy(),
        Some((Some(0), Some(3)))
    );
    let recovered = decoded
        .recover(program)
        .unwrap_or_else(|error| panic!("recover: {error:?}"))
        .into_driver_admission()
        .unwrap_or_else(|error| panic!("admission: {error:?}"));
    let state = lock(&recovered.coordinator().inner.state);
    let registry = state
        .resources
        .as_ref()
        .unwrap_or_else(|| panic!("recovery must not silently disable resource accounting"));
    assert_eq!(registry.live_limit(), Some(0));
    assert_eq!(registry.pending_limit(), Some(3));
    assert!(registry.declared_records().is_empty());
    assert_eq!(registry.pending_operations(), 0);
}

/// Retained ceilings survive empty-registry graph recovery without creating accepted work.
#[test]
fn retained_resource_policy_survives_graph_recovery() {
    for retained in [0, 1, u64::MAX] {
        let (coordinator, root, children, program) = fixture_with_program();
        lock(&coordinator.inner.state).resources =
            Some(ResourceRegistry::with_accounting_limits(2, 3, retained));
        let checkpoint = coordinator
            .capture_checkpoint(&root, &children)
            .unwrap_or_else(|error| panic!("retained policy capture: {error:?}"));
        let bytes = checkpoint.canonical_bytes();
        assert_eq!(bytes.get(..8), Some(b"GNTCDP07".as_slice()));
        assert!(crate::ConcurrentDurableCheckpointV6::decode(&program, &bytes).is_err());
        assert!(crate::ConcurrentDurableCheckpointV7::decode(&program, &bytes).is_ok());
        assert!(
            crate::ConcurrentDurableCheckpointV7::decode(&program, &bytes[..bytes.len() - 1])
                .is_err()
        );
        let decoded = crate::ConcurrentDurableCheckpointV4::decode_compatible(&program, &bytes)
            .unwrap_or_else(|error| panic!("retained policy decode: {error:?}"));
        assert_eq!(decoded.canonical_bytes(), bytes);
        let admission = decoded
            .recover(program)
            .unwrap_or_else(|error| panic!("retained policy recovery: {error:?}"))
            .into_driver_admission()
            .unwrap_or_else(|error| panic!("driver admission: {error:?}"));
        let state = lock(&admission.coordinator().inner.state);
        let registry = state
            .resources
            .as_ref()
            .unwrap_or_else(|| panic!("enabled registry"));
        assert_eq!(registry.retained_limit(), Some(retained));
        assert_eq!(registry.live_limit(), Some(2));
        assert_eq!(registry.pending_limit(), Some(3));
        assert_eq!(registry.retained_resources(), 0);
        assert_eq!(registry.pending_operations(), 0);
        assert!(!state.durable_publication_reserved);
    }
}

/// Optional ceilings retain absence, unlimited accounting, and mixed limits distinctly.
#[test]
fn optional_resource_policy_round_trips_without_silent_disable() {
    for policy in [
        None,
        Some((None, None)),
        Some((Some(0), None)),
        Some((None, Some(u64::MAX))),
    ] {
        let (coordinator, root, children, program) = fixture_with_program();
        lock(&coordinator.inner.state).resources =
            policy.map(|(live, pending)| ResourceRegistry::with_optional_limits(live, pending));
        let checkpoint = coordinator
            .capture_checkpoint(&root, &children)
            .unwrap_or_else(|error| panic!("capture: {error:?}"));
        let bytes = checkpoint.canonical_bytes();
        assert_eq!(checkpoint.resource_policy(), policy);
        assert_eq!(
            bytes.get(..8),
            Some(if policy.is_some() {
                b"GNTCDP06".as_slice()
            } else {
                b"GNTCDP04".as_slice()
            })
        );
        let decoded = crate::ConcurrentDurableCheckpointV4::decode_compatible(&program, &bytes)
            .unwrap_or_else(|error| panic!("decode: {error:?}"));
        assert_eq!(decoded.canonical_bytes(), bytes);
        let recovered = decoded
            .recover(program)
            .unwrap_or_else(|error| panic!("recovery: {error:?}"));
        if policy.is_none() {
            assert!(recovered.into_machine_graph().is_ok());
        } else {
            let retained = recovered
                .into_machine_graph()
                .err()
                .unwrap_or_else(|| panic!("policy-bearing machine extraction refuses"));
            let admission = retained
                .into_driver_admission()
                .unwrap_or_else(|error| panic!("retained admission: {error:?}"));
            let state = lock(&admission.coordinator().inner.state);
            assert_eq!(
                state
                    .resources
                    .as_ref()
                    .map(|registry| { (registry.live_limit(), registry.pending_limit()) }),
                policy
            );
        }
    }
}

/// Retains the exact executable artifact for journal recovery assertions.
fn fixture_with_program() -> (
    ExecutionCoordinator,
    Machine,
    BTreeMap<ProtocolIdentity, Machine>,
    Arc<MachineProgram>,
) {
    let execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [17; 32])
        .unwrap_or_else(|error| panic!("identity: {error}"));
    let session = ProtocolIdentity::from_fresh_material(IdentityKind::Session, [18; 32])
        .unwrap_or_else(|error| panic!("identity: {error}"));
    let path = CanonicalPath::new("crate::main").unwrap_or_else(|error| panic!("path: {error}"));
    let program = MachineProgram::new(vec![Workflow {
        path: path.clone(),
        parameters: Vec::new(),
        result: TypeDescriptor::UNIT,
        effects: EffectSet::default(),
        instructions: vec![
            Instruction {
                site: StructuralPosition::new(vec![0])
                    .unwrap_or_else(|error| panic!("site: {error}")),
                ty: TypeDescriptor::UNIT,
                kind: InstructionKind::Push(LogicalValue::unit()),
            },
            Instruction {
                site: StructuralPosition::new(vec![1])
                    .unwrap_or_else(|error| panic!("site: {error}")),
                ty: TypeDescriptor::UNIT,
                kind: InstructionKind::Return,
            },
        ],
    }])
    .unwrap_or_else(|error| panic!("program: {error:?}"));
    let program = Arc::new(program);
    let limits = MachineLimits::new(100, 10, 10, 10, 100, DEFAULT_VALUE_LIMITS)
        .unwrap_or_else(|| panic!("limits"));
    let machine = Machine::new(program.clone(), &path, Vec::new(), execution, limits)
        .unwrap_or_else(|error| panic!("machine: {error:?}"));
    let tasks = ConcurrentTaskStateV1::new(execution, machine.task_id(), 10)
        .unwrap_or_else(|error| panic!("tasks: {error:?}"));
    let sessions = LogicalSessionRegistryV1::new(
        execution,
        session,
        SessionCreationModeV1::GantryRoot,
        CanonicalTranscriptV1::empty(),
    )
    .unwrap_or_else(|error| panic!("sessions: {error:?}"));
    let coordinator =
        ExecutionCoordinator::new_with_budget(tasks, sessions, machine.execution_budget())
            .unwrap_or_else(|error| panic!("coordinator: {error:?}"));
    (coordinator, machine, BTreeMap::new(), program)
}

/// Creates one root whose child can be published through a real lexical spawn.
fn spawn_fixture_with_program() -> (
    ExecutionCoordinator,
    Machine,
    BTreeMap<ProtocolIdentity, Machine>,
    Arc<MachineProgram>,
) {
    let execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [17; 32])
        .unwrap_or_else(|error| panic!("identity: {error}"));
    let session = ProtocolIdentity::from_fresh_material(IdentityKind::Session, [18; 32])
        .unwrap_or_else(|error| panic!("identity: {error}"));
    let path = CanonicalPath::new("crate::main").unwrap_or_else(|error| panic!("path: {error}"));
    let caller = CanonicalCallableIdentity::free(&path, &[]);
    let spawn_site =
        StructuralPosition::new(vec![0]).unwrap_or_else(|error| panic!("spawn site: {error}"));
    let body_identity = TaskBodyIdentity::new(caller.clone(), spawn_site.clone());
    let body = ExecutableTaskBody::new(
        body_identity.clone(),
        TypeDescriptor::UNIT,
        Vec::new(),
        ExecutableTaskContext::v1(),
        vec![
            Instruction {
                site: StructuralPosition::new(vec![0, 0])
                    .unwrap_or_else(|error| panic!("body site: {error}")),
                ty: TypeDescriptor::UNIT,
                kind: InstructionKind::Push(LogicalValue::unit()),
            },
            Instruction {
                site: StructuralPosition::new(vec![0, 1])
                    .unwrap_or_else(|error| panic!("body site: {error}")),
                ty: TypeDescriptor::UNIT,
                kind: InstructionKind::TaskComplete,
            },
        ],
    )
    .unwrap_or_else(|error| panic!("task body: {error:?}"));
    let root = Workflow {
        path: path.clone(),
        parameters: Vec::new(),
        result: TypeDescriptor::UNIT,
        effects: EffectSet::default(),
        instructions: vec![
            Instruction {
                site: spawn_site,
                ty: TypeDescriptor::UNIT,
                kind: InstructionKind::Spawn {
                    handle: ExecutableTaskHandle::new(Arc::from("child"), TypeDescriptor::UNIT)
                        .unwrap_or_else(|error| panic!("task handle: {error:?}")),
                    body: body_identity,
                },
            },
            Instruction {
                site: StructuralPosition::new(vec![1])
                    .unwrap_or_else(|error| panic!("site: {error}")),
                ty: TypeDescriptor::UNIT,
                kind: InstructionKind::Detach {
                    handle: Arc::from("child"),
                },
            },
            Instruction {
                site: StructuralPosition::new(vec![2])
                    .unwrap_or_else(|error| panic!("site: {error}")),
                ty: TypeDescriptor::UNIT,
                kind: InstructionKind::Push(LogicalValue::unit()),
            },
            Instruction {
                site: StructuralPosition::new(vec![3])
                    .unwrap_or_else(|error| panic!("site: {error}")),
                ty: TypeDescriptor::UNIT,
                kind: InstructionKind::Return,
            },
        ],
    };
    let program = Arc::new(
        MachineProgram::with_task_bodies(vec![(caller, root)], vec![body])
            .unwrap_or_else(|error| panic!("program: {error:?}")),
    );
    let limits = MachineLimits::new(100, 10, 10, 10, 100, DEFAULT_VALUE_LIMITS)
        .unwrap_or_else(|| panic!("limits"));
    let machine = Machine::new_with_context(
        program.clone(),
        &path,
        Vec::new(),
        execution,
        limits,
        None,
        Some(session),
    )
    .unwrap_or_else(|error| panic!("machine: {error:?}"));
    let tasks = ConcurrentTaskStateV1::new(execution, machine.task_id(), 10)
        .unwrap_or_else(|error| panic!("tasks: {error:?}"));
    let sessions = LogicalSessionRegistryV1::new(
        execution,
        session,
        SessionCreationModeV1::GantryRoot,
        CanonicalTranscriptV1::empty(),
    )
    .unwrap_or_else(|error| panic!("sessions: {error:?}"));
    let coordinator =
        ExecutionCoordinator::new_with_budget(tasks, sessions, machine.execution_budget())
            .unwrap_or_else(|error| panic!("coordinator: {error:?}"));
    (coordinator, machine, BTreeMap::new(), program)
}

/// Creates one root whose successful child is consumed by a source join.
fn join_fixture_with_program() -> (
    ExecutionCoordinator,
    Machine,
    BTreeMap<ProtocolIdentity, Machine>,
    Arc<MachineProgram>,
) {
    let execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [27; 32])
        .unwrap_or_else(|error| panic!("identity: {error}"));
    let session = ProtocolIdentity::from_fresh_material(IdentityKind::Session, [28; 32])
        .unwrap_or_else(|error| panic!("identity: {error}"));
    let path = CanonicalPath::new("crate::main").unwrap_or_else(|error| panic!("path: {error}"));
    let caller = CanonicalCallableIdentity::free(&path, &[]);
    let spawn_site =
        StructuralPosition::new(vec![0]).unwrap_or_else(|error| panic!("spawn site: {error}"));
    let body_identity = TaskBodyIdentity::new(caller.clone(), spawn_site.clone());
    let body = ExecutableTaskBody::new(
        body_identity.clone(),
        TypeDescriptor::UNIT,
        Vec::new(),
        ExecutableTaskContext::v1(),
        vec![
            Instruction {
                site: StructuralPosition::new(vec![0, 0])
                    .unwrap_or_else(|error| panic!("body site: {error}")),
                ty: TypeDescriptor::UNIT,
                kind: InstructionKind::Push(LogicalValue::unit()),
            },
            Instruction {
                site: StructuralPosition::new(vec![0, 1])
                    .unwrap_or_else(|error| panic!("body site: {error}")),
                ty: TypeDescriptor::UNIT,
                kind: InstructionKind::TaskComplete,
            },
        ],
    )
    .unwrap_or_else(|error| panic!("task body: {error:?}"));
    let root = Workflow {
        path: path.clone(),
        parameters: Vec::new(),
        result: TypeDescriptor::UNIT,
        effects: EffectSet::default(),
        instructions: vec![
            Instruction {
                site: spawn_site,
                ty: TypeDescriptor::UNIT,
                kind: InstructionKind::Spawn {
                    handle: ExecutableTaskHandle::new(Arc::from("child"), TypeDescriptor::UNIT)
                        .unwrap_or_else(|error| panic!("task handle: {error:?}")),
                    body: body_identity,
                },
            },
            Instruction {
                site: StructuralPosition::new(vec![1])
                    .unwrap_or_else(|error| panic!("join site: {error}")),
                ty: TypeDescriptor::UNIT,
                kind: InstructionKind::Join {
                    handles: vec![Arc::from("child")],
                },
            },
            Instruction {
                site: StructuralPosition::new(vec![2])
                    .unwrap_or_else(|error| panic!("return site: {error}")),
                ty: TypeDescriptor::UNIT,
                kind: InstructionKind::Return,
            },
        ],
    };
    let program = Arc::new(
        MachineProgram::with_task_bodies(vec![(caller, root)], vec![body])
            .unwrap_or_else(|error| panic!("program: {error:?}")),
    );
    let limits = MachineLimits::new(100, 10, 10, 10, 100, DEFAULT_VALUE_LIMITS)
        .unwrap_or_else(|| panic!("limits"));
    let machine = Machine::new_with_context(
        program.clone(),
        &path,
        Vec::new(),
        execution,
        limits,
        None,
        Some(session),
    )
    .unwrap_or_else(|error| panic!("machine: {error:?}"));
    let tasks = ConcurrentTaskStateV1::new(execution, machine.task_id(), 10)
        .unwrap_or_else(|error| panic!("tasks: {error:?}"));
    let sessions = LogicalSessionRegistryV1::new(
        execution,
        session,
        SessionCreationModeV1::GantryRoot,
        CanonicalTranscriptV1::empty(),
    )
    .unwrap_or_else(|error| panic!("sessions: {error:?}"));
    let coordinator =
        ExecutionCoordinator::new_with_budget(tasks, sessions, machine.execution_budget())
            .unwrap_or_else(|error| panic!("coordinator: {error:?}"));
    (coordinator, machine, BTreeMap::new(), program)
}

/// Polls fixtures that must complete synchronously; never spins on pending I/O.
fn ready<F: Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("unexpected pending fixture"),
    }
}

#[test]
fn dropping_unsubmitted_stage_rolls_back_and_releases_publication() {
    let (coordinator, mut root, mut children) = fixture();
    let before = coordinator.snapshot();
    let checkpoint = root.checkpoint();
    let mut stage = coordinator
        .stage_graph(&mut root, &mut children)
        .unwrap_or_else(|error| panic!("stage: {error:?}"));
    stage.update(|root, _, _, _| assert!(matches!(root.step(), MachineStep::Transition(_))));
    assert_eq!(coordinator.snapshot(), before);
    assert_eq!(
        coordinator.cancel_execution("blocked"),
        Err(TaskStateError::DurablePublicationReserved)
    );
    drop(stage);
    assert_eq!(root.checkpoint(), checkpoint);
    assert_eq!(coordinator.snapshot(), before);
    assert!(coordinator.stage_graph(&mut root, &mut children).is_ok());
}

#[test]
fn dropping_failed_operation_stage_preserves_authoritative_resource_admission() {
    let execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [71; 32])
        .unwrap_or_else(|error| panic!("execution identity: {error}"));
    let session = ProtocolIdentity::from_fresh_material(IdentityKind::Session, [72; 32])
        .unwrap_or_else(|error| panic!("session identity: {error}"));
    let workflow_path =
        CanonicalPath::new("crate::main").unwrap_or_else(|error| panic!("workflow path: {error}"));
    let action_path =
        CanonicalPath::new("crate::action").unwrap_or_else(|error| panic!("action path: {error}"));
    let operation = ExecutableOperation {
        kind: OperationSiteKind::Action,
        section20_kind: Some(OperationKind::LiveResource),
        result_type: TypeDescriptor::UNIT,
        action: Some(ExecutableAction {
            path: action_path.clone(),
            signature: CanonicalSignature::action(
                RecoveryClass::Idempotent,
                &action_path,
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
    };
    let program = Arc::new(
        MachineProgram::new(vec![Workflow {
            path: workflow_path.clone(),
            parameters: Vec::new(),
            result: TypeDescriptor::UNIT,
            effects: EffectSet::default(),
            instructions: vec![
                Instruction {
                    site: StructuralPosition::new(vec![0])
                        .unwrap_or_else(|error| panic!("operation site: {error}")),
                    ty: TypeDescriptor::UNIT,
                    kind: InstructionKind::OperationCall {
                        operation,
                        operands: 0,
                    },
                },
                Instruction {
                    site: StructuralPosition::new(vec![1])
                        .unwrap_or_else(|error| panic!("return site: {error}")),
                    ty: TypeDescriptor::UNIT,
                    kind: InstructionKind::Return,
                },
            ],
        }])
        .unwrap_or_else(|error| panic!("operation program: {error:?}")),
    );
    let limits = MachineLimits::new(100, 10, 10, 10, 100, DEFAULT_VALUE_LIMITS)
        .unwrap_or_else(|| panic!("machine limits"));
    let mut root = Machine::new(
        Arc::clone(&program),
        &workflow_path,
        Vec::new(),
        execution,
        limits,
    )
    .unwrap_or_else(|error| panic!("machine: {error:?}"));
    let tasks = ConcurrentTaskStateV1::new(execution, root.task_id(), 10)
        .unwrap_or_else(|error| panic!("tasks: {error:?}"));
    let sessions = LogicalSessionRegistryV1::new(
        execution,
        session,
        SessionCreationModeV1::GantryRoot,
        CanonicalTranscriptV1::empty(),
    )
    .unwrap_or_else(|error| panic!("sessions: {error:?}"));
    let coordinator =
        ExecutionCoordinator::new_with_budget(tasks, sessions, root.execution_budget())
            .unwrap_or_else(|error| panic!("coordinator: {error:?}"));
    let mut children = BTreeMap::new();
    let record = ResourceLedger::new(
        OwnerGeneration::new(4),
        ResourceState::Usable,
        &[LivenessRoot::Resource],
        &[],
    )
    .unwrap_or_else(|error| panic!("resource reconstruction record: {error:?}"))
    .durable_record();

    let mut before_action_stage = coordinator
        .stage_graph(&mut root, &mut children)
        .unwrap_or_else(|error| panic!("stage before action: {error:?}"));
    let before_action_subject = before_action_stage.update(|staged_root, _, _, _| {
        assert!(matches!(
            staged_root.step(),
            MachineStep::Transition(crate::MachineLabel::OperationPrepared(_))
        ));
        staged_root
            .pending_resource_subject()
            .unwrap_or_else(|| panic!("staged action has a resource subject"))
    });
    drop(before_action_stage);
    assert_eq!(
        ResourceRegistry::new().admit(
            before_action_subject,
            ResourceCarrier::ReconstructionRecord,
            record.clone(),
        ),
        Err(ResourceRegistryRefusal::NoPendingResourceSubject),
        "an action prepared only inside a rolled-back stage cannot be admitted"
    );
    assert!(matches!(
        root.step(),
        MachineStep::Transition(crate::MachineLabel::OperationPrepared(_))
    ));
    let subject = root
        .pending_resource_subject()
        .unwrap_or_else(|| panic!("the pending action has a resource subject"));
    let operation = root
        .checkpoint()
        .pending_operation()
        .unwrap_or_else(|| panic!("the pending action retains its occurrence"))
        .identity;

    let mut stage = coordinator
        .stage_graph(&mut root, &mut children)
        .unwrap_or_else(|error| panic!("stage graph: {error:?}"));
    let staged_subject = stage.update(|staged_root, _, _, _| {
        let subject = staged_root
            .pending_resource_subject()
            .unwrap_or_else(|| panic!("staged pending action has a resource subject"));
        staged_root
            .fail_operation_with_code(operation, crate::RuntimeCode::InternalInvariant)
            .unwrap_or_else(|error| panic!("staged failure: {error:?}"));
        subject
    });
    assert_eq!(
        subject.lock_admission().map(|lease| lease.pending),
        Some(true)
    );
    drop(stage);

    assert!(
        root.checkpoint().pending_operation().is_some(),
        "rollback keeps the authoritative operation pending"
    );
    assert_eq!(
        subject.lock_admission().map(|lease| lease.pending),
        Some(true),
        "a dropped terminal stage leaves the authoritative resource admission open"
    );
    assert_eq!(
        ResourceRegistry::new().admit(
            staged_subject,
            ResourceCarrier::ReconstructionRecord,
            record.clone(),
        ),
        Err(ResourceRegistryRefusal::NoPendingResourceSubject),
        "a subject retained from a rolled-back staged failure cannot be admitted"
    );

    let mut unchanged_stage = coordinator
        .stage_graph(&mut root, &mut children)
        .unwrap_or_else(|error| panic!("stage unchanged pending operation: {error:?}"));
    let staged_pending_subject = unchanged_stage.update(|staged_root, _, _, _| {
        staged_root
            .pending_resource_subject()
            .unwrap_or_else(|| panic!("staged operation remains pending"))
    });
    drop(unchanged_stage);
    assert_eq!(
        ResourceRegistry::new().admit(
            staged_pending_subject,
            ResourceCarrier::ReconstructionRecord,
            record.clone(),
        ),
        Err(ResourceRegistryRefusal::NoPendingResourceSubject),
        "a binding retained from an unchanged rolled-back stage is revoked"
    );

    let task = root.task_id();
    let storage = Arc::new(InMemoryJournalStore::new());
    let journal = JournalId::new("staged-resource-admission")
        .unwrap_or_else(|error| panic!("journal: {error:?}"));
    let owner = ready(storage.acquire_owner(AcquireJournalOwnerV1 {
        journal_id: journal.clone(),
        operation: JournalOwnerOperationV1::Start,
    }))
    .unwrap_or_else(|error| panic!("owner: {error:?}"));
    let sink = DurableTransitionSink::new(storage, journal, owner.token);
    let mut commits = DurableCommitCoordinatorV1::new(&sink, execution, task, None)
        .unwrap_or_else(|error| panic!("commits: {error:?}"));
    let mut committed_stage = coordinator
        .stage_graph(&mut root, &mut children)
        .unwrap_or_else(|error| panic!("stage pending operation: {error:?}"));
    let committed_staged_subject = committed_stage.update(|staged_root, _, _, _| {
        staged_root
            .pending_resource_subject()
            .unwrap_or_else(|| panic!("staged operation remains pending"))
    });
    let payload = gantry_core::event::EventPayload::from_validated_canonical_bytes(
        Arc::<[u8]>::from(&b"{}"[..]),
    )
    .unwrap_or_else(|error| panic!("payload: {error:?}"));
    let draft = gantry_core::event::EventDraft::new(
        gantry_core::portable::EventKind::OperationCompletion,
        payload,
    )
    .with_execution_id(execution)
    .unwrap_or_else(|error| panic!("draft: {error:?}"));
    let event = gantry_core::event::EventEnvelope::complete(
        ProtocolIdentity::from_fresh_material(IdentityKind::Event, [81; 32])
            .unwrap_or_else(|error| panic!("event id: {error}")),
        ProtocolIdentity::from_fresh_material(IdentityKind::Activity, [82; 32])
            .unwrap_or_else(|error| panic!("activity id: {error}")),
        gantry_core::timestamp::UtcTimestamp::from_unix_seconds(0, 82)
            .unwrap_or_else(|error| panic!("time: {error:?}")),
        draft,
    )
    .unwrap_or_else(|error| panic!("event: {error:?}"));
    committed_stage
        .set_event(event, crate::DurableEventPlanV1::default(), Vec::new())
        .unwrap_or_else(|error| panic!("event staging: {error:?}"));
    ready(committed_stage.commit(&mut commits, DurableCommitCutV1::Checkpoint, task))
        .unwrap_or_else(|error| panic!("same-operation commit: {error:?}"));
    assert_eq!(
        ResourceRegistry::new().admit(
            committed_staged_subject.clone(),
            ResourceCarrier::ReconstructionRecord,
            record.clone(),
        ),
        Err(ResourceRegistryRefusal::NoPendingResourceSubject),
        "a subject captured from a committed stage is revoked when its lease is promoted"
    );
    let authoritative_subject = root
        .pending_resource_subject()
        .unwrap_or_else(|| panic!("committed authoritative operation remains pending"));
    let mut registry = ResourceRegistry::new();
    registry
        .admit(
            authoritative_subject,
            ResourceCarrier::ReconstructionRecord,
            record.clone(),
        )
        .unwrap_or_else(|error| panic!("authoritative pending subject admits: {error:?}"));
    root.fail_operation_with_code(operation, crate::RuntimeCode::InternalInvariant)
        .unwrap_or_else(|error| panic!("authoritative pending operation settles: {error:?}"));
    assert_eq!(
        ResourceRegistry::new().admit(
            committed_staged_subject,
            ResourceCarrier::ReconstructionRecord,
            record,
        ),
        Err(ResourceRegistryRefusal::NoPendingResourceSubject),
        "the staged subject remains unusable after the authoritative operation completes"
    );
}

#[test]
fn successful_commit_installs_machine_and_budget_together() {
    let (coordinator, mut root, mut children) = fixture();
    let execution = root.execution_id();
    let task = root.task_id();
    let storage = Arc::new(InMemoryJournalStore::new());
    let journal =
        JournalId::new("staged-graph").unwrap_or_else(|error| panic!("journal: {error:?}"));
    let owner = ready(storage.acquire_owner(AcquireJournalOwnerV1 {
        journal_id: journal.clone(),
        operation: JournalOwnerOperationV1::Start,
    }))
    .unwrap_or_else(|error| panic!("owner: {error:?}"));
    let sink = DurableTransitionSink::new(storage.clone(), journal.clone(), owner.token);
    let mut commits = DurableCommitCoordinatorV1::new(&sink, execution, task, None)
        .unwrap_or_else(|error| panic!("commits: {error:?}"));
    let before = root.budget_checkpoint();
    let mut stage = coordinator
        .stage_graph(&mut root, &mut children)
        .unwrap_or_else(|error| panic!("stage: {error:?}"));
    stage.update(|root, _, _, _| assert!(matches!(root.step(), MachineStep::Transition(_))));
    let payload = gantry_core::event::EventPayload::from_validated_canonical_bytes(
        Arc::<[u8]>::from(&b"{}"[..]),
    )
    .unwrap_or_else(|error| panic!("payload: {error:?}"));
    let draft = gantry_core::event::EventDraft::new(
        gantry_core::portable::EventKind::OperationCompletion,
        payload,
    )
    .with_execution_id(execution)
    .unwrap_or_else(|error| panic!("draft: {error:?}"));
    let event = gantry_core::event::EventEnvelope::complete(
        ProtocolIdentity::from_fresh_material(IdentityKind::Event, [41; 32])
            .unwrap_or_else(|error| panic!("event id: {error}")),
        ProtocolIdentity::from_fresh_material(IdentityKind::Activity, [42; 32])
            .unwrap_or_else(|error| panic!("activity id: {error}")),
        gantry_core::timestamp::UtcTimestamp::from_unix_seconds(0, 42)
            .unwrap_or_else(|error| panic!("time: {error:?}")),
        draft,
    )
    .unwrap_or_else(|error| panic!("event: {error:?}"));
    stage
        .set_event(event, crate::DurableEventPlanV1::default(), Vec::new())
        .unwrap_or_else(|error| panic!("event staging: {error:?}"));
    let receipt = ready(stage.commit(&mut commits, DurableCommitCutV1::Checkpoint, task))
        .unwrap_or_else(|error| panic!("commit: {error:?}"));
    assert_eq!(receipt.sequence, 1);
    assert_eq!(coordinator.committed_events().events().len(), 1);
    let prefix = ready(storage.read_prefix(ReadJournalPrefixV1 {
        journal_id: journal,
    }))
    .unwrap_or_else(|error| panic!("prefix: {error:?}"));
    let JournalPrefixV1::Full(prefix) = prefix else {
        panic!("expected full prefix")
    };
    assert_eq!(prefix.committed_through, 2);
    assert_eq!(
        prefix.evidence[1].kind.as_ref(),
        crate::DURABLE_EVENT_OCCURRENCE_KIND_V1
    );
    assert_eq!(root.budget_checkpoint().revision, before.revision + 1);
    assert_eq!(
        coordinator.snapshot().execution_budget(),
        Some(root.budget_checkpoint())
    );
    assert!(coordinator.capture_checkpoint(&root, &children).is_ok());

    let mut waiter = Box::pin(
        coordinator
            .wait_for_task_settlement(task)
            .unwrap_or_else(|error| panic!("waiter: {error:?}")),
    );
    assert!(
        waiter
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    let mut stage = coordinator
        .stage_graph(&mut root, &mut children)
        .unwrap_or_else(|error| panic!("settlement stage: {error:?}"));
    stage.update(|root, _, tasks, _| {
        for _ in 0..10 {
            if let MachineStep::Transition(crate::MachineLabel::TaskSettled(outcome)) = root.step()
            {
                tasks
                    .settle(task, outcome)
                    .unwrap_or_else(|error| panic!("settle: {error:?}"));
                return;
            }
        }
        panic!("root did not settle");
    });
    assert!(
        waiter
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    coordinator
        .mark_driver_physically_settled(task)
        .unwrap_or_else(|error| panic!("physical completion: {error:?}"));
    ready(stage.commit(&mut commits, DurableCommitCutV1::TaskSettlement, task))
        .unwrap_or_else(|error| panic!("settlement commit: {error:?}"));
    assert!(
        waiter
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_ready()
    );
    assert!(coordinator.snapshot().state().drivers_are_quiescent());
}

/// A coordinator rebuilt from validated recovery must seed its first graph transaction.
#[test]
fn recovered_coordinator_bootstraps_durable_graph_baseline() {
    let (coordinator, root, children, program) = fixture_with_program();
    lock(&coordinator.inner.state).resources =
        Some(ResourceRegistry::with_accounting_limits(0, 3, 5));
    let execution = root.execution_id();
    let task = root.task_id();
    let storage = Arc::new(InMemoryJournalStore::new());
    let journal = JournalId::new("recovered-coordinator-bootstrap")
        .unwrap_or_else(|error| panic!("journal: {error:?}"));
    let owner = ready(storage.acquire_owner(AcquireJournalOwnerV1 {
        journal_id: journal.clone(),
        operation: JournalOwnerOperationV1::Start,
    }))
    .unwrap_or_else(|error| panic!("owner: {error:?}"));
    let sink = DurableTransitionSink::new(storage.clone(), journal.clone(), owner.token);
    let mut commits = DurableCommitCoordinatorV1::new(&sink, execution, task, None)
        .unwrap_or_else(|error| panic!("commits: {error:?}"));
    let initial = coordinator
        .capture_checkpoint(&root, &children)
        .unwrap_or_else(|error| panic!("initial capture: {error:?}"));
    ready(commits.commit_graph_checkpoint(DurableCommitCutV1::Checkpoint, task, initial.clone()))
        .unwrap_or_else(|error| panic!("initial commit: {error:?}"));

    let recovered = initial
        .recover(program.clone())
        .unwrap_or_else(|error| panic!("checkpoint recovery: {error:?}"));
    let admission = recovered
        .into_driver_admission()
        .unwrap_or_else(|error| panic!("recovered admission: {error:?}"));
    let (recovered_coordinator, mut recovered_root, mut recovered_children, _) =
        admission.into_parts();
    let mut stage = recovered_coordinator
        .stage_graph(&mut recovered_root, &mut recovered_children)
        .unwrap_or_else(|error| panic!("recovered stage: {error:?}"));
    stage.update(|root, _, tasks, _| {
        loop {
            match root.step() {
                MachineStep::Transition(crate::MachineLabel::TaskSettled(outcome)) => {
                    tasks
                        .settle(task, outcome)
                        .unwrap_or_else(|error| panic!("recovered settlement: {error:?}"));
                    break;
                }
                MachineStep::Transition(_) => {}
                other => panic!("recovered root did not settle: {other:?}"),
            }
        }
    });
    ready(stage.commit(&mut commits, DurableCommitCutV1::TaskSettlement, task))
        .unwrap_or_else(|error| panic!("recovered commit: {error:?}"));
    assert_eq!(
        recovered_coordinator.snapshot().execution_budget(),
        Some(recovered_root.budget_checkpoint())
    );
    recovered_coordinator
        .capture_checkpoint(&recovered_root, &recovered_children)
        .unwrap_or_else(|error| panic!("recovered capture: {error:?}"));
    let prefix = ready(storage.read_prefix(ReadJournalPrefixV1 {
        journal_id: journal,
    }))
    .unwrap_or_else(|error| panic!("prefix: {error:?}"));
    let recovered = crate::recover_concurrent_authoritative_prefix(program, &prefix)
        .unwrap_or_else(|error| panic!("strict recovery: {error:?}"));
    assert_eq!(
        recovered
            .execution()
            .capture_replayed_checkpoint()
            .unwrap_or_else(|error| panic!("replayed checkpoint: {error:?}"))
            .resource_policy(),
        Some((Some(0), Some(3)))
    );
    assert_eq!(
        recovered
            .execution()
            .capture_replayed_checkpoint()
            .unwrap_or_else(|error| panic!("retained replay capture: {error:?}"))
            .retained_resource_limit(),
        Some(5)
    );
}

/// A physical driver race must not enter the next durable semantic predecessor.
#[test]
fn settlement_checkpoint_and_join_continue_from_committed_semantic_baseline() {
    let (coordinator, mut root, mut children, program) = join_fixture_with_program();
    let execution = root.execution_id();
    let root_task = root.task_id();
    let root_session = coordinator.snapshot().sessions()[0].id;
    let storage = Arc::new(InMemoryJournalStore::new());
    let journal = JournalId::new("settlement-checkpoint-join-race")
        .unwrap_or_else(|error| panic!("journal: {error:?}"));
    let owner = ready(storage.acquire_owner(AcquireJournalOwnerV1 {
        journal_id: journal.clone(),
        operation: JournalOwnerOperationV1::Start,
    }))
    .unwrap_or_else(|error| panic!("owner: {error:?}"));
    let sink = DurableTransitionSink::new(storage.clone(), journal.clone(), owner.token);
    let mut commits = DurableCommitCoordinatorV1::new(&sink, execution, root_task, None)
        .unwrap_or_else(|error| panic!("commits: {error:?}"));
    let initial = coordinator
        .capture_checkpoint(&root, &children)
        .unwrap_or_else(|error| panic!("initial capture: {error:?}"));
    ready(commits.commit_graph_checkpoint(DurableCommitCutV1::Checkpoint, root_task, initial))
        .unwrap_or_else(|error| panic!("initial commit: {error:?}"));

    let mut stage = coordinator
        .stage_graph(&mut root, &mut children)
        .unwrap_or_else(|error| panic!("creation stage: {error:?}"));
    let (created, spawn) = stage.update(|root, _, tasks, sessions| {
        let spawn = match root.step() {
            MachineStep::Transition(crate::MachineLabel::TaskControlSuspended(spawn)) => spawn,
            other => panic!("root did not suspend at spawn: {other:?}"),
        };
        let created = tasks.create_child(
            sessions,
            crate::TaskCreationRequestV1 {
                parent_task_id: root_task,
                handle_name: Arc::from(spawn.handle.name()),
                workflow: spawn.workflow.clone(),
                spawn_site: spawn.site.clone(),
                spawn_occurrence: spawn.occurrence,
                result_type: spawn.handle.result_type().clone(),
                captures: spawn
                    .captures
                    .iter()
                    .map(|capture| capture.task_capture().clone())
                    .collect(),
                inherited_agent: spawn.inherited_agent.clone(),
                parent_session_id: root_session,
            },
            DEFAULT_VALUE_LIMITS,
        );
        (created, spawn)
    });
    let created = created.unwrap_or_else(|error| panic!("creation: {error:?}"));
    ready(stage.commit(
        &mut commits,
        DurableCommitCutV1::TaskCreation,
        created.task_id,
    ))
    .unwrap_or_else(|error| panic!("creation commit: {error:?}"));

    let task_path = Arc::from(
        coordinator
            .snapshot()
            .state()
            .task(created.task_id)
            .unwrap_or_else(|| panic!("created child missing"))
            .task_path(),
    );
    let child = Machine::new_concurrent_task_body_with_context(
        program.clone(),
        &spawn.body,
        &[],
        execution,
        created.task_id,
        task_path,
        MachineLimits::new(100, 10, 10, 10, 100, DEFAULT_VALUE_LIMITS)
            .unwrap_or_else(|| panic!("child limits")),
        root.execution_budget(),
        spawn.inherited_agent.clone(),
        Some(created.base_session_id),
    )
    .unwrap_or_else(|error| panic!("child machine: {error:?}"));
    let mut stage = coordinator
        .stage_graph(&mut root, &mut children)
        .unwrap_or_else(|error| panic!("submission stage: {error:?}"));
    stage
        .update(|root, _, tasks, _| {
            root.complete_spawn(&spawn, created.handle_id)
                .unwrap_or_else(|error| panic!("spawn completion: {error:?}"));
            tasks.resolve_submission(created.task_id, Ok(()))
        })
        .unwrap_or_else(|error| panic!("submission: {error:?}"));
    stage
        .install_child_machine(created.task_id, child)
        .unwrap_or_else(|error| panic!("child installation: {error:?}"));
    ready(stage.commit(
        &mut commits,
        DurableCommitCutV1::Checkpoint,
        created.task_id,
    ))
    .unwrap_or_else(|error| panic!("submission commit: {error:?}"));

    let mut stage = coordinator
        .stage_graph(&mut root, &mut children)
        .unwrap_or_else(|error| panic!("join ownership stage: {error:?}"));
    let ownership = stage.update(|root, _, tasks, _| {
        assert!(matches!(
            root.step(),
            MachineStep::Transition(crate::MachineLabel::Deterministic { ref kind, .. })
                if kind.as_ref() == "join-suspended"
        ));
        let (join, join_all) = root
            .pending_task_control()
            .and_then(|pending| pending.join())
            .unwrap_or_else(|| panic!("join suspension missing"));
        assert!(!join_all);
        let names = join
            .handles
            .iter()
            .map(|handle| Arc::from(handle.name()))
            .collect::<Vec<_>>();
        let handles = join
            .handles
            .iter()
            .map(|handle| handle.identity())
            .collect::<Vec<_>>();
        match tasks.begin_source_join(
            root_task,
            join.workflow.clone(),
            join.site.clone(),
            gantry_ir::generated::TaskControlSiteKind::Join,
            &names,
            &handles,
        ) {
            Ok(JoinStartV1::Started(ownership)) => ownership,
            other => panic!("join ownership failed: {other:?}"),
        }
    });
    ready(stage.commit(
        &mut commits,
        DurableCommitCutV1::TaskOwnership,
        created.task_id,
    ))
    .unwrap_or_else(|error| panic!("join ownership commit: {error:?}"));

    let mut stage = coordinator
        .stage_graph(&mut root, &mut children)
        .unwrap_or_else(|error| panic!("settlement stage: {error:?}"));
    stage.update(|_, children, tasks, _| {
        let outcome = loop {
            match children
                .get_mut(&created.task_id)
                .unwrap_or_else(|| panic!("child machine missing"))
                .step()
            {
                MachineStep::Transition(crate::MachineLabel::TaskSettled(outcome)) => {
                    break outcome;
                }
                MachineStep::Transition(_) => {}
                other => panic!("child did not settle: {other:?}"),
            }
        };
        children.remove(&created.task_id);
        tasks
            .settle(created.task_id, outcome)
            .unwrap_or_else(|error| panic!("semantic settlement: {error:?}"));
    });
    coordinator
        .mark_driver_physically_settled(created.task_id)
        .unwrap_or_else(|error| panic!("physical settlement race: {error:?}"));
    ready(stage.commit(
        &mut commits,
        DurableCommitCutV1::TaskSettlement,
        created.task_id,
    ))
    .unwrap_or_else(|error| panic!("settlement commit: {error:?}"));
    assert_eq!(
        coordinator
            .snapshot()
            .state()
            .task_record(created.task_id)
            .map(|record| record.driver_ownership()),
        Some(TaskDriverOwnershipV1::PhysicallySettled)
    );

    let stage = coordinator
        .stage_graph(&mut root, &mut children)
        .unwrap_or_else(|error| panic!("causal checkpoint stage: {error:?}"));
    ready(stage.commit(&mut commits, DurableCommitCutV1::Checkpoint, root_task))
        .unwrap_or_else(|error| panic!("causal checkpoint commit: {error:?}"));

    let mut stage = coordinator
        .stage_graph(&mut root, &mut children)
        .unwrap_or_else(|error| panic!("join continuation stage: {error:?}"));
    stage.update(|root, _, tasks, _| {
        let join = root
            .pending_task_control()
            .and_then(|pending| pending.join())
            .map(|(join, _)| join.clone())
            .unwrap_or_else(|| panic!("join continuation missing"));
        let resolution = tasks
            .resolve_join(&ownership, DEFAULT_VALUE_LIMITS)
            .unwrap_or_else(|error| panic!("join resolution: {error:?}"));
        assert_eq!(
            resolution,
            JoinResolutionV1::Succeeded(LogicalValue::unit())
        );
        root.complete_join(&join, resolution)
            .unwrap_or_else(|error| panic!("join completion: {error:?}"));
    });
    ready(stage.commit(&mut commits, DurableCommitCutV1::Checkpoint, root_task))
        .unwrap_or_else(|error| panic!("join continuation commit: {error:?}"));

    let prefix = ready(storage.read_prefix(ReadJournalPrefixV1 {
        journal_id: journal,
    }))
    .unwrap_or_else(|error| panic!("prefix: {error:?}"));
    assert!(matches!(prefix, JournalPrefixV1::Full(_)));
    let recovered = crate::recover_concurrent_authoritative_prefix(program, &prefix)
        .unwrap_or_else(|error| panic!("strict recovery: {error:?}"));
    assert_eq!(
        recovered.execution().foreground().checkpoint(),
        root.checkpoint()
    );
    assert_eq!(
        recovered
            .execution()
            .scheduler()
            .state()
            .task_record(created.task_id)
            .map(|record| record.driver_ownership()),
        Some(TaskDriverOwnershipV1::Supervised)
    );
}

/// Rejects the event write after accepting the graph's semantic cut.
#[derive(Default)]
struct EventFailureStore(InMemoryJournalStore);

impl JournalStorage for EventFailureStore {
    fn acquire_owner<'a>(
        &'a self,
        request: AcquireJournalOwnerV1,
    ) -> HostFuture<'a, Result<JournalOwnershipV1, JournalError>> {
        self.0.acquire_owner(request)
    }
    fn read_prefix<'a>(
        &'a self,
        request: ReadJournalPrefixV1,
    ) -> HostFuture<'a, Result<JournalPrefixV1, JournalError>> {
        self.0.read_prefix(request)
    }
    fn commit<'a>(
        &'a self,
        request: JournalCommitRequestV1,
    ) -> HostFuture<'a, Result<JournalCommitReceiptV1, JournalError>> {
        if request
            .batch
            .evidence
            .iter()
            .any(|entry| entry.kind.as_ref() == crate::DURABLE_EVENT_OCCURRENCE_KIND_V1)
        {
            Box::pin(async { Err(JournalError::new(JournalErrorCode::Internal)) })
        } else {
            self.0.commit(request)
        }
    }
    fn resolve_payload<'a>(
        &'a self,
        request: ResolveJournalPayloadV1,
    ) -> HostFuture<'a, Result<ResolvedJournalPayloadV1, JournalError>> {
        self.0.resolve_payload(request)
    }
    fn release_owner<'a>(
        &'a self,
        request: ReleaseJournalOwnerV1,
    ) -> HostFuture<'a, Result<(), JournalError>> {
        self.0.release_owner(request)
    }
}

#[test]
fn task_creation_event_failure_recovers_cause_without_reserving_event_identity() {
    let (coordinator, mut root, mut children, program) = spawn_fixture_with_program();
    let execution = root.execution_id();
    let root_task = root.task_id();
    let root_session = coordinator.snapshot().sessions()[0].id;
    let storage = Arc::new(EventFailureStore::default());
    let journal = JournalId::new("task-creation-event-failure")
        .unwrap_or_else(|error| panic!("journal: {error:?}"));
    let owner = ready(storage.acquire_owner(AcquireJournalOwnerV1 {
        journal_id: journal.clone(),
        operation: JournalOwnerOperationV1::Start,
    }))
    .unwrap_or_else(|error| panic!("owner: {error:?}"));
    let sink = DurableTransitionSink::new(storage.clone(), journal.clone(), owner.token);
    let mut commits = DurableCommitCoordinatorV1::new(&sink, execution, root_task, None)
        .unwrap_or_else(|error| panic!("commits: {error:?}"));
    let initial = coordinator
        .capture_checkpoint(&root, &children)
        .unwrap_or_else(|error| panic!("initial capture: {error:?}"));
    ready(commits.commit_graph_checkpoint(DurableCommitCutV1::Checkpoint, root_task, initial))
        .unwrap_or_else(|error| panic!("initial commit: {error:?}"));

    let mut stage = coordinator
        .stage_graph(&mut root, &mut children)
        .unwrap_or_else(|error| panic!("creation stage: {error:?}"));
    let created = stage
        .update(|root, _, tasks, sessions| {
            let spawn = match root.step() {
                MachineStep::Transition(crate::MachineLabel::TaskControlSuspended(spawn)) => spawn,
                other => panic!("root did not suspend at spawn: {other:?}"),
            };
            tasks.create_child(
                sessions,
                crate::TaskCreationRequestV1 {
                    parent_task_id: root_task,
                    handle_name: Arc::from(spawn.handle.name()),
                    workflow: spawn.workflow.clone(),
                    spawn_site: spawn.site.clone(),
                    spawn_occurrence: spawn.occurrence,
                    result_type: spawn.handle.result_type().clone(),
                    captures: spawn
                        .captures
                        .iter()
                        .map(|capture| capture.task_capture().clone())
                        .collect(),
                    inherited_agent: spawn.inherited_agent.clone(),
                    parent_session_id: root_session,
                },
                DEFAULT_VALUE_LIMITS,
            )
        })
        .unwrap_or_else(|error| panic!("creation: {error:?}"));
    let draft = crate::concurrent_spawn_event(execution, &created.transition, 0)
        .unwrap_or_else(|error| panic!("spawn event draft: {error:?}"));
    let event_id = ProtocolIdentity::from_fresh_material(IdentityKind::Event, [61; 32])
        .unwrap_or_else(|error| panic!("event identity: {error}"));
    let event = gantry_core::event::EventEnvelope::complete(
        event_id,
        ProtocolIdentity::from_fresh_material(IdentityKind::Activity, [62; 32])
            .unwrap_or_else(|error| panic!("activity identity: {error}")),
        gantry_core::timestamp::UtcTimestamp::from_unix_seconds(0, 42)
            .unwrap_or_else(|error| panic!("time: {error:?}")),
        draft.draft,
    )
    .unwrap_or_else(|error| panic!("spawn event: {error:?}"));
    stage
        .set_event(
            event,
            crate::DurableEventPlanV1::default(),
            draft.protected_payloads.to_vec(),
        )
        .unwrap_or_else(|error| panic!("event staging: {error:?}"));
    assert!(matches!(
        ready(stage.commit(
            &mut commits,
            DurableCommitCutV1::TaskCreation,
            created.task_id,
        )),
        Err(DurableCommitError::Journal(_))
    ));

    let prefix = ready(storage.read_prefix(ReadJournalPrefixV1 {
        journal_id: journal,
    }))
    .unwrap_or_else(|error| panic!("prefix: {error:?}"));
    let JournalPrefixV1::Full(full) = &prefix else {
        panic!("expected full prefix")
    };
    // GNT-12.2 makes only the causal transition authoritative: the rejected
    // occurrence must not reserve its event ID, activity, or timestamp.
    assert_eq!(full.committed_through, 2);
    let creation_evidence_id = full.evidence[1].evidence_id;
    let recovered = crate::recover_concurrent_authoritative_prefix(program, &prefix)
        .unwrap_or_else(|error| panic!("strict recovery: {error:?}"));
    assert!(
        recovered
            .events()
            .requires_replacement(creation_evidence_id)
    );
    assert!(
        recovered
            .events()
            .event_for_cause(creation_evidence_id)
            .is_none()
    );
    assert!(!recovered.events().events().contains_key(&event_id));
    assert!(recovered.events().events().is_empty());
}

#[test]
fn event_commit_failure_keeps_graph_private_and_fences_publication() {
    let (coordinator, mut root, mut children) = fixture();
    let before = coordinator.snapshot();
    let checkpoint = root.checkpoint();
    let execution = root.execution_id();
    let task = root.task_id();
    let storage = Arc::new(EventFailureStore::default());
    let journal =
        JournalId::new("event-failure").unwrap_or_else(|error| panic!("journal: {error:?}"));
    let owner = ready(storage.acquire_owner(AcquireJournalOwnerV1 {
        journal_id: journal.clone(),
        operation: JournalOwnerOperationV1::Start,
    }))
    .unwrap_or_else(|error| panic!("owner: {error:?}"));
    let sink = DurableTransitionSink::new(storage.clone(), journal.clone(), owner.token);
    let mut commits = DurableCommitCoordinatorV1::new(&sink, execution, task, None)
        .unwrap_or_else(|error| panic!("commits: {error:?}"));
    let mut stage = coordinator
        .stage_graph(&mut root, &mut children)
        .unwrap_or_else(|error| panic!("stage: {error:?}"));
    stage.update(|root, _, _, _| assert!(matches!(root.step(), MachineStep::Transition(_))));
    let payload = gantry_core::event::EventPayload::from_validated_canonical_bytes(
        Arc::<[u8]>::from(&b"{}"[..]),
    )
    .unwrap_or_else(|error| panic!("payload: {error:?}"));
    let draft = gantry_core::event::EventDraft::new(
        gantry_core::portable::EventKind::OperationCompletion,
        payload,
    )
    .with_execution_id(execution)
    .unwrap_or_else(|error| panic!("draft: {error:?}"));
    let event = gantry_core::event::EventEnvelope::complete(
        ProtocolIdentity::from_fresh_material(IdentityKind::Event, [51; 32])
            .unwrap_or_else(|error| panic!("event: {error}")),
        ProtocolIdentity::from_fresh_material(IdentityKind::Activity, [52; 32])
            .unwrap_or_else(|error| panic!("activity: {error}")),
        gantry_core::timestamp::UtcTimestamp::from_unix_seconds(0, 42)
            .unwrap_or_else(|error| panic!("time: {error:?}")),
        draft,
    )
    .unwrap_or_else(|error| panic!("event: {error:?}"));
    stage
        .set_event(event, crate::DurableEventPlanV1::default(), Vec::new())
        .unwrap_or_else(|error| panic!("event staging: {error:?}"));
    assert!(matches!(
        ready(stage.commit(&mut commits, DurableCommitCutV1::Checkpoint, task)),
        Err(DurableCommitError::Journal(_))
    ));
    assert_eq!(root.checkpoint(), checkpoint);
    assert_eq!(coordinator.snapshot(), before);
    assert!(coordinator.committed_events().events().is_empty());
    assert_eq!(
        coordinator.cancel_execution("blocked"),
        Err(TaskStateError::DurablePublicationReserved)
    );
    let JournalPrefixV1::Full(prefix) = ready(storage.read_prefix(ReadJournalPrefixV1 {
        journal_id: journal,
    }))
    .unwrap_or_else(|error| panic!("prefix: {error:?}")) else {
        panic!("expected full prefix")
    };
    assert_eq!(prefix.committed_through, 1);
}

/// Storage that keeps commit indeterminate while allowing lock probes.
struct PendingStore;
/// Child creation and failed submission retain one identity across journal cuts.
#[test]
fn child_creation_and_submission_failure_publish_coherent_cuts() {
    let (coordinator, mut root, mut children, program) = spawn_fixture_with_program();
    let execution = root.execution_id();
    let task = root.task_id();
    let session = coordinator.snapshot().sessions()[0].id;
    let storage = Arc::new(InMemoryJournalStore::new());
    let journal =
        JournalId::new("child-transaction").unwrap_or_else(|error| panic!("journal: {error:?}"));
    let owner = ready(storage.acquire_owner(AcquireJournalOwnerV1 {
        journal_id: journal.clone(),
        operation: JournalOwnerOperationV1::Start,
    }))
    .unwrap_or_else(|error| panic!("owner: {error:?}"));
    let sink = DurableTransitionSink::new(storage.clone(), journal.clone(), owner.token);
    let mut commits = DurableCommitCoordinatorV1::new(&sink, execution, task, None)
        .unwrap_or_else(|error| panic!("commits: {error:?}"));
    let initial = coordinator
        .capture_checkpoint(&root, &children)
        .unwrap_or_else(|error| panic!("capture: {error:?}"));
    ready(commits.commit_graph_checkpoint(DurableCommitCutV1::Checkpoint, task, initial))
        .unwrap_or_else(|error| panic!("initial: {error:?}"));
    let before = coordinator.snapshot();
    let mut stage = coordinator
        .stage_graph(&mut root, &mut children)
        .unwrap_or_else(|error| panic!("stage: {error:?}"));
    let (child, suspension) = stage.update(|root, _, tasks, sessions| {
        let suspension = match root.step() {
            MachineStep::Transition(crate::MachineLabel::TaskControlSuspended(suspension)) => {
                suspension
            }
            other => panic!("root did not suspend at spawn: {other:?}"),
        };
        let child = tasks.create_child(
            sessions,
            crate::TaskCreationRequestV1 {
                parent_task_id: task,
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
                parent_session_id: session,
            },
            DEFAULT_VALUE_LIMITS,
        );
        (child, suspension)
    });
    let child = child.unwrap_or_else(|error| panic!("creation: {error:?}"));
    assert_eq!(coordinator.snapshot(), before);
    ready(stage.commit(
        &mut commits,
        DurableCommitCutV1::TaskCreation,
        child.task_id,
    ))
    .unwrap_or_else(|error| panic!("creation commit: {error:?}"));
    assert_eq!(coordinator.snapshot().state().created_task_count(), 2);
    assert!(coordinator.session(child.base_session_id).is_some());
    let before = coordinator.snapshot();
    let mut stage = coordinator
        .stage_graph(&mut root, &mut children)
        .unwrap_or_else(|error| panic!("stage: {error:?}"));
    stage
        .update(|root, _, tasks, _| {
            root.complete_spawn(&suspension, child.handle_id)
                .unwrap_or_else(|error| panic!("spawn completion: {error:?}"));
            tasks.resolve_submission(
                child.task_id,
                Err(HostError {
                    code: Arc::from("task-submission-failure"),
                    protected_diagnostic: None,
                }),
            )
        })
        .unwrap_or_else(|error| panic!("submission: {error:?}"));
    assert_eq!(coordinator.snapshot(), before);
    ready(stage.commit(
        &mut commits,
        DurableCommitCutV1::TaskSettlement,
        child.task_id,
    ))
    .unwrap_or_else(|error| panic!("settlement commit: {error:?}"));
    let prefix = ready(storage.read_prefix(ReadJournalPrefixV1 {
        journal_id: journal,
    }))
    .unwrap_or_else(|error| panic!("prefix: {error:?}"));
    let recovered = crate::recover_concurrent_authoritative_prefix(program, &prefix)
        .unwrap_or_else(|error| panic!("recovery: {error:?}"));
    assert_eq!(
        recovered.execution().scheduler().state(),
        coordinator.snapshot().state()
    );
}

/// Invalid semantic cuts must be rejected before the pending storage is called.
#[test]
fn rejected_cut_releases_publication_before_submission() {
    let (coordinator, mut root, mut children) = fixture();
    let before = coordinator.snapshot();
    let task = root.task_id();
    let sink = DurableTransitionSink::new(
        Arc::new(PendingStore),
        JournalId::new("rejected").unwrap_or_else(|error| panic!("journal: {error:?}")),
        JournalOwnershipToken::new("owner").unwrap_or_else(|error| panic!("token: {error:?}")),
    );
    let mut commits = DurableCommitCoordinatorV1::new(&sink, root.execution_id(), task, None)
        .unwrap_or_else(|error| panic!("commits: {error:?}"));
    let stage = coordinator
        .stage_graph(&mut root, &mut children)
        .unwrap_or_else(|error| panic!("stage: {error:?}"));
    assert!(ready(stage.commit(&mut commits, DurableCommitCutV1::TaskSettlement, task)).is_err());
    assert_eq!(coordinator.snapshot(), before);
    assert!(coordinator.stage_graph(&mut root, &mut children).is_ok());
}

/// Root and child progress must charge one private budget and publish one cut.
#[test]
fn multiple_machines_publish_one_budget_and_checkpoint_cut() {
    let (coordinator, mut root, mut children, program) = spawn_fixture_with_program();
    let execution = root.execution_id();
    let root_id = root.task_id();
    let session = coordinator.snapshot().sessions()[0].id;
    let storage = Arc::new(InMemoryJournalStore::new());
    let journal =
        JournalId::new("multi-machine-cut").unwrap_or_else(|error| panic!("journal: {error:?}"));
    let owner = ready(storage.acquire_owner(AcquireJournalOwnerV1 {
        journal_id: journal.clone(),
        operation: JournalOwnerOperationV1::Start,
    }))
    .unwrap_or_else(|error| panic!("owner: {error:?}"));
    let sink = DurableTransitionSink::new(storage.clone(), journal.clone(), owner.token);
    let mut commits = DurableCommitCoordinatorV1::new(&sink, execution, root_id, None)
        .unwrap_or_else(|error| panic!("commits: {error:?}"));
    let initial = coordinator
        .capture_checkpoint(&root, &children)
        .unwrap_or_else(|error| panic!("initial capture: {error:?}"));
    ready(commits.commit_graph_checkpoint(DurableCommitCutV1::Checkpoint, root_id, initial))
        .unwrap_or_else(|error| panic!("initial commit: {error:?}"));

    let mut stage = coordinator
        .stage_graph(&mut root, &mut children)
        .unwrap_or_else(|error| panic!("creation stage: {error:?}"));
    let (child, suspension) = stage.update(|root, _, tasks, sessions| {
        let suspension = match root.step() {
            MachineStep::Transition(crate::MachineLabel::TaskControlSuspended(suspension)) => {
                suspension
            }
            other => panic!("root did not suspend at spawn: {other:?}"),
        };
        let child = tasks.create_child(
            sessions,
            crate::TaskCreationRequestV1 {
                parent_task_id: root_id,
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
                parent_session_id: session,
            },
            DEFAULT_VALUE_LIMITS,
        );
        (child, suspension)
    });
    let child = child.unwrap_or_else(|error| panic!("child creation: {error:?}"));
    ready(stage.commit(
        &mut commits,
        DurableCommitCutV1::TaskCreation,
        child.task_id,
    ))
    .unwrap_or_else(|error| panic!("creation commit: {error:?}"));

    let task_path = Arc::from(
        coordinator
            .snapshot()
            .state()
            .task(child.task_id)
            .unwrap_or_else(|| panic!("missing child"))
            .task_path(),
    );
    let machine = Machine::new_concurrent_task_body_with_context(
        program.clone(),
        &suspension.body,
        &suspension
            .captures
            .iter()
            .map(|capture| capture.task_capture().clone())
            .collect::<Vec<_>>(),
        execution,
        child.task_id,
        task_path,
        MachineLimits::new(100, 10, 10, 10, 100, DEFAULT_VALUE_LIMITS)
            .unwrap_or_else(|| panic!("limits")),
        root.execution_budget(),
        suspension.inherited_agent.clone(),
        Some(child.base_session_id),
    )
    .unwrap_or_else(|error| panic!("child machine: {error:?}"));
    let mut stage = coordinator
        .stage_graph(&mut root, &mut children)
        .unwrap_or_else(|error| panic!("submission stage: {error:?}"));
    stage
        .update(|root, _, tasks, _| {
            root.complete_spawn(&suspension, child.handle_id)
                .unwrap_or_else(|error| panic!("spawn completion: {error:?}"));
            tasks.resolve_submission(child.task_id, Ok(()))
        })
        .unwrap_or_else(|error| panic!("submission: {error:?}"));
    stage
        .install_child_machine(child.task_id, machine)
        .unwrap_or_else(|error| panic!("child installation: {error:?}"));
    ready(stage.commit(&mut commits, DurableCommitCutV1::Checkpoint, child.task_id))
        .unwrap_or_else(|error| panic!("submission commit: {error:?}"));

    let before = coordinator.snapshot();
    let root_before = root.checkpoint();
    let child_before = children[&child.task_id].checkpoint();
    let mut stage = coordinator
        .stage_graph(&mut root, &mut children)
        .unwrap_or_else(|error| panic!("progress stage: {error:?}"));
    stage.update(|root, _, tasks, _| {
        assert!(matches!(
            root.step(),
            MachineStep::Transition(crate::MachineLabel::Deterministic { ref kind, .. })
                if kind.as_ref() == "detach-suspended"
        ));
        let detach = root
            .pending_task_control()
            .and_then(|pending| pending.detach())
            .cloned()
            .unwrap_or_else(|| panic!("detach suspension missing"));
        tasks
            .detach_source_handle(
                root_id,
                detach.workflow.clone(),
                detach.site.clone(),
                Arc::from(detach.handle.name()),
                detach.handle.identity(),
            )
            .unwrap_or_else(|error| panic!("source detach: {error:?}"));
    });
    assert_eq!(coordinator.snapshot(), before);
    ready(stage.commit(
        &mut commits,
        DurableCommitCutV1::TaskOwnership,
        child.task_id,
    ))
    .unwrap_or_else(|error| panic!("commit: {error:?}"));
    assert_ne!(root.checkpoint(), root_before);
    assert_eq!(children[&child.task_id].checkpoint(), child_before);
    assert_eq!(
        root.budget_checkpoint().revision,
        before
            .execution_budget()
            .unwrap_or_else(|| panic!("missing budget"))
            .revision
    );
    assert_eq!(
        root.budget_checkpoint(),
        children[&child.task_id].budget_checkpoint()
    );
    let prefix = ready(storage.read_prefix(ReadJournalPrefixV1 {
        journal_id: journal,
    }))
    .unwrap_or_else(|error| panic!("prefix: {error:?}"));
    let recovered = crate::recover_concurrent_authoritative_prefix(program, &prefix)
        .unwrap_or_else(|error| panic!("recovery: {error:?}"));
    assert_eq!(
        recovered.execution().foreground().checkpoint(),
        root.checkpoint()
    );
    assert_eq!(
        recovered.execution().foreground().budget_checkpoint(),
        root.budget_checkpoint()
    );
    assert_eq!(
        recovered.execution().scheduler().state(),
        coordinator.snapshot().state()
    );
}

impl JournalStorage for PendingStore {
    fn acquire_owner<'a>(
        &'a self,
        _: AcquireJournalOwnerV1,
    ) -> HostFuture<'a, Result<JournalOwnershipV1, JournalError>> {
        Box::pin(std::future::pending())
    }
    fn read_prefix<'a>(
        &'a self,
        _: ReadJournalPrefixV1,
    ) -> HostFuture<'a, Result<JournalPrefixV1, JournalError>> {
        Box::pin(std::future::pending())
    }
    fn commit<'a>(
        &'a self,
        _: JournalCommitRequestV1,
    ) -> HostFuture<'a, Result<JournalCommitReceiptV1, JournalError>> {
        Box::pin(std::future::pending())
    }
    fn resolve_payload<'a>(
        &'a self,
        _: ResolveJournalPayloadV1,
    ) -> HostFuture<'a, Result<ResolvedJournalPayloadV1, JournalError>> {
        Box::pin(std::future::pending())
    }
    fn release_owner<'a>(
        &'a self,
        _: ReleaseJournalOwnerV1,
    ) -> HostFuture<'a, Result<(), JournalError>> {
        Box::pin(std::future::pending())
    }
}

#[test]
fn interrupted_commit_keeps_old_state_and_fences_publication() {
    let (coordinator, mut root, mut children) = fixture();
    let before = coordinator.snapshot();
    let task = root.task_id();
    let sink = DurableTransitionSink::new(
        Arc::new(PendingStore),
        JournalId::new("pending").unwrap_or_else(|error| panic!("journal: {error:?}")),
        JournalOwnershipToken::new("owner").unwrap_or_else(|error| panic!("token: {error:?}")),
    );
    let mut commits = DurableCommitCoordinatorV1::new(&sink, root.execution_id(), task, None)
        .unwrap_or_else(|error| panic!("commits: {error:?}"));
    let mut stage = coordinator
        .stage_graph(&mut root, &mut children)
        .unwrap_or_else(|error| panic!("stage: {error:?}"));
    stage.update(|root, _, _, _| assert!(matches!(root.step(), MachineStep::Transition(_))));
    let mut commit = Box::pin(stage.commit(&mut commits, DurableCommitCutV1::Checkpoint, task));
    assert!(
        commit
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    assert_eq!(coordinator.try_snapshot(), Some(before.clone()));
    drop(commit);
    assert_eq!(coordinator.snapshot(), before);
    assert_eq!(
        coordinator.cancel_execution("blocked"),
        Err(TaskStateError::DurablePublicationReserved)
    );
}
