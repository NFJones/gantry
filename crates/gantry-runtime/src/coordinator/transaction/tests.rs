//! Regression tests for private staging and journal-first publication.

use super::*;
use crate::{
    CanonicalTranscriptV1, DurableTransitionSink, InMemoryJournalStore, MachineLimits, MachineStep,
};
use gantry_core::portable::IdentityKind;
use gantry_core::value::{DEFAULT_VALUE_LIMITS, LogicalValue};
use gantry_host::contracts::HostFuture;
use gantry_host::journal::*;
use gantry_ir::{
    CanonicalPath, EffectSet, Instruction, InstructionKind, MachineProgram, TypeDescriptor,
    Workflow,
};

/// Creates an empty child graph with one executable root.
fn fixture() -> (
    ExecutionCoordinator,
    Machine,
    BTreeMap<ProtocolIdentity, Machine>,
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
    let limits = MachineLimits::new(100, 10, 10, 10, 100, DEFAULT_VALUE_LIMITS)
        .unwrap_or_else(|| panic!("limits"));
    let machine = Machine::new(Arc::new(program), &path, Vec::new(), execution, limits)
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
    (coordinator, machine, BTreeMap::new())
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
    let sink = DurableTransitionSink::new(storage, journal, owner.token);
    let mut commits = DurableCommitCoordinatorV1::new(&sink, execution, task, None)
        .unwrap_or_else(|error| panic!("commits: {error:?}"));
    let before = root.budget_checkpoint();
    let mut stage = coordinator
        .stage_graph(&mut root, &mut children)
        .unwrap_or_else(|error| panic!("stage: {error:?}"));
    stage.update(|root, _, _, _| assert!(matches!(root.step(), MachineStep::Transition(_))));
    let receipt = ready(stage.commit(&mut commits, DurableCommitCutV1::Checkpoint, task))
        .unwrap_or_else(|error| panic!("commit: {error:?}"));
    assert_eq!(receipt.sequence, 1);
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

/// Storage that keeps commit indeterminate while allowing lock probes.
struct PendingStore;
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
