//! Focused conformance coverage for source-spawn execution.

use std::fs;
use std::future::Future;
use std::path::PathBuf;
use std::pin::pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};

use gantry::event::EventEnvelope;
use gantry::host::contracts::{
    CancellationSignal, CancellationToken, ExecutorAdapter, HookOutcomeV1, HostError, HostFuture,
    HostRequest, HostResponse, IdentitySource, JournalStorage, RuntimeSessionService,
};
use gantry::host::embedding::EmbeddingOperation;
use gantry::host::event::{
    EventDeliveryRequest, EventDeliveryRuntime, EventRetryPolicy, EventSink, RedactionCapabilities,
    SinkDeliveryPolicy, SinkId,
};
use gantry::host::journal::{
    AcquireJournalOwnerV1, FullJournalPrefixV1, JournalCommitReceiptV1, JournalCommitRequestV1,
    JournalError, JournalErrorCode, JournalId, JournalOwnershipV1, JournalPrefixV1,
    ReadJournalPrefixV1, ReleaseJournalOwnerV1, ResolveJournalPayloadV1, ResolvedJournalPayloadV1,
    SnapshotJournalPrefixV1,
};
use gantry::identity::ProtocolIdentity;
use gantry::observe::{SinkPlan, SinkRegistration};
use gantry::portable::{
    CancellationReasonCategory, DeliveryOutcome, EventKind, IdentityKind, JitterMode,
    PORTABLE_SPECIFICATION_REVISION, PROTOCOL_FAMILY_DEFINITIONS, RuntimeErrorCategory, SinkClass,
    TaskStatusKind,
};
use gantry::protocol::{ProtocolSelection, ProtocolVersion, SelectedProtocol};
use gantry::runtime::{
    AsyncCapacityLimits, CONCURRENT_DURABLE_EVIDENCE_KIND_V4, CONCURRENT_DURABLE_EVIDENCE_KIND_V5,
    CONCURRENT_DURABLE_SNAPSHOT_VERSION_V1, CancellationRecord, ConcurrentDurableCheckpointV4,
    ConcurrentDurableEvidenceV4, ConcurrentDurableEvidenceV5, ConcurrentDurableRecoverySnapshotV1,
    ConcurrentTaskStatusV1, DURABLE_EVENT_DISPATCHED_KIND_V1, DURABLE_EVENT_OCCURRENCE_KIND_V1,
    DURABLE_EVENT_SETTLED_KIND_V1, DurableCommitCutV1, DurableEventOccurrenceV1,
    DurableExecutionStartV3, InMemoryJournalStore, InterpreterConfiguration, MachineOutcome,
    RequiredConfiguration, RuntimeCode, TaskDriverOwnershipV1,
    recover_concurrent_authoritative_prefix,
};
use gantry::source::FrontendLimits;
use gantry::timestamp::UtcTimestamp;
use gantry::value::DEFAULT_VALUE_LIMITS;
use gantry::{
    DurableJournalOwnerState, DurableLifecycleCoordinator, DurableOwnedExecutionOpenError,
    DurableQueryExecutionRequest, DurableQueryExecutionResult, DurableResumeExecutionRequest,
    DurableResumeExecutionResult, DurableStartExecutionAccepted, DurableStartExecutionRequest,
    DurableStartExecutionResult, Interpreter, RootSessionSpecification, StartExecutionRequest,
    StartExecutionResult, caller_cancellation_reason,
};
use gantry_conformance::concurrent_executor::{
    DeterministicConcurrentExecutor, DeterministicTaskPoll,
};
use gantry_conformance::scripted::{ScriptedHook, ScriptedIntegration, ScriptedPreflight};
use gantry_conformance::services::{DeterministicIdentitySource, DeterministicUtcClock};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TempDirectory(PathBuf);

#[derive(Clone)]
struct RecordedEvent {
    event: EventEnvelope,
    executor_task_ids: Vec<u64>,
}

struct RecordingSink {
    executor: Arc<DeterministicConcurrentExecutor>,
    spawn_outcome: DeliveryOutcome,
    events: Mutex<Vec<RecordedEvent>>,
}

impl RecordingSink {
    fn new(executor: Arc<DeterministicConcurrentExecutor>, spawn_outcome: DeliveryOutcome) -> Self {
        Self {
            executor,
            spawn_outcome,
            events: Mutex::new(Vec::new()),
        }
    }

    fn events(&self) -> Vec<RecordedEvent> {
        lock(&self.events).clone()
    }
}

impl EventSink for RecordingSink {
    fn deliver<'a>(
        &'a self,
        request: EventDeliveryRequest,
    ) -> HostFuture<'a, Result<DeliveryOutcome, HostError>> {
        Box::pin(async move {
            let kind = request.event.kind();
            let executor_task_ids = self.executor.task_ids();
            lock(&self.events).push(RecordedEvent {
                event: request.event,
                executor_task_ids,
            });
            if kind == EventKind::Spawn {
                Ok(self.spawn_outcome)
            } else {
                Ok(DeliveryOutcome::Success)
            }
        })
    }
}

struct ImmediateDeliveryRuntime;

impl EventDeliveryRuntime for ImmediateDeliveryRuntime {
    fn deliver_with_timeout<'a>(
        &'a self,
        sink: &'a dyn EventSink,
        request: EventDeliveryRequest,
        _timeout_us: u64,
    ) -> HostFuture<'a, Result<DeliveryOutcome, HostError>> {
        sink.deliver(request)
    }

    fn sleep<'a>(&'a self, _delay_us: u64) -> HostFuture<'a, Result<(), HostError>> {
        Box::pin(async { Ok(()) })
    }

    fn sample_full_jitter(&self, _ceiling_us: u64) -> Result<u64, HostError> {
        Ok(0)
    }
}

struct CancelAfterEstablishment {
    inner: Arc<ScriptedIntegration>,
    cancel_call: u64,
    calls: AtomicU64,
    cancellation: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    cancelled: AtomicBool,
}

impl CancelAfterEstablishment {
    fn new(inner: Arc<ScriptedIntegration>, cancel_call: u64) -> Self {
        Self {
            inner,
            cancel_call,
            calls: AtomicU64::new(0),
            cancellation: Mutex::new(None),
            cancelled: AtomicBool::new(false),
        }
    }

    fn arm(&self, cancellation: Arc<dyn Fn() + Send + Sync>) {
        *lock(&self.cancellation) = Some(cancellation);
    }

    fn cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

impl RuntimeSessionService for CancelAfterEstablishment {
    fn establish<'a>(
        &'a self,
        request: HostRequest,
    ) -> HostFuture<'a, Result<HostResponse, HostError>> {
        let call = self.calls.fetch_add(1, Ordering::AcqRel) + 1;
        Box::pin(async move {
            let result = self.inner.establish(request).await;
            if result.is_ok()
                && call == self.cancel_call
                && let Some(cancellation) = lock(&self.cancellation).clone()
            {
                cancellation();
                self.cancelled.store(true, Ordering::Release);
            }
            result
        })
    }
}

#[derive(Default)]
struct CountingJournalStore {
    inner: InMemoryJournalStore,
    releases: AtomicU64,
}

impl CountingJournalStore {
    fn release_count(&self) -> u64 {
        self.releases.load(Ordering::Acquire)
    }
}

impl JournalStorage for CountingJournalStore {
    fn acquire_owner<'a>(
        &'a self,
        request: AcquireJournalOwnerV1,
    ) -> HostFuture<'a, Result<JournalOwnershipV1, JournalError>> {
        self.inner.acquire_owner(request)
    }

    fn read_prefix<'a>(
        &'a self,
        request: ReadJournalPrefixV1,
    ) -> HostFuture<'a, Result<JournalPrefixV1, JournalError>> {
        self.inner.read_prefix(request)
    }

    fn commit<'a>(
        &'a self,
        request: JournalCommitRequestV1,
    ) -> HostFuture<'a, Result<JournalCommitReceiptV1, JournalError>> {
        self.inner.commit(request)
    }

    fn resolve_payload<'a>(
        &'a self,
        request: ResolveJournalPayloadV1,
    ) -> HostFuture<'a, Result<ResolvedJournalPayloadV1, JournalError>> {
        self.inner.resolve_payload(request)
    }

    fn release_owner<'a>(
        &'a self,
        request: ReleaseJournalOwnerV1,
    ) -> HostFuture<'a, Result<(), JournalError>> {
        self.releases.fetch_add(1, Ordering::AcqRel);
        self.inner.release_owner(request)
    }
}

struct FailingGraphJournalStore {
    inner: InMemoryJournalStore,
    executor: Arc<DeterministicConcurrentExecutor>,
    failed: AtomicBool,
    releases: AtomicU64,
    release_started: AtomicBool,
    release_allowed: AtomicBool,
    release_waker: Mutex<Option<Waker>>,
    release_saw_cancelled: AtomicBool,
    release_saw_graph_tasks_settled: AtomicBool,
    cancellation: Mutex<Option<CancellationSignal>>,
}

impl FailingGraphJournalStore {
    fn new(executor: Arc<DeterministicConcurrentExecutor>) -> Self {
        Self {
            inner: InMemoryJournalStore::new(),
            executor,
            failed: AtomicBool::new(false),
            releases: AtomicU64::new(0),
            release_started: AtomicBool::new(false),
            release_allowed: AtomicBool::new(false),
            release_waker: Mutex::new(None),
            release_saw_cancelled: AtomicBool::new(false),
            release_saw_graph_tasks_settled: AtomicBool::new(false),
            cancellation: Mutex::new(None),
        }
    }

    fn observe_cancellation(&self, cancellation: CancellationSignal) {
        *lock(&self.cancellation) = Some(cancellation);
    }

    fn release_count(&self) -> u64 {
        self.releases.load(Ordering::Acquire)
    }

    fn release_started(&self) -> bool {
        self.release_started.load(Ordering::Acquire)
    }

    fn allow_release(&self) {
        self.release_allowed.store(true, Ordering::Release);
        if let Some(waker) = lock(&self.release_waker).take() {
            waker.wake();
        }
    }

    fn release_saw_cancelled(&self) -> bool {
        self.release_saw_cancelled.load(Ordering::Acquire)
    }

    fn release_saw_graph_tasks_settled(&self) -> bool {
        self.release_saw_graph_tasks_settled.load(Ordering::Acquire)
    }
}

impl JournalStorage for FailingGraphJournalStore {
    fn acquire_owner<'a>(
        &'a self,
        request: AcquireJournalOwnerV1,
    ) -> HostFuture<'a, Result<JournalOwnershipV1, JournalError>> {
        self.inner.acquire_owner(request)
    }

    fn read_prefix<'a>(
        &'a self,
        request: ReadJournalPrefixV1,
    ) -> HostFuture<'a, Result<JournalPrefixV1, JournalError>> {
        self.inner.read_prefix(request)
    }

    fn commit<'a>(
        &'a self,
        request: JournalCommitRequestV1,
    ) -> HostFuture<'a, Result<JournalCommitReceiptV1, JournalError>> {
        let task_settlement = request.batch.evidence.iter().any(|evidence| {
            matches!(
                evidence.kind.as_ref(),
                CONCURRENT_DURABLE_EVIDENCE_KIND_V4 | CONCURRENT_DURABLE_EVIDENCE_KIND_V5
            ) && std::str::from_utf8(&evidence.canonical_body)
                .is_ok_and(|body| body.contains("\"cut\":\"task-settlement\""))
        });
        if task_settlement && !self.failed.swap(true, Ordering::AcqRel) {
            Box::pin(async { Err(JournalError::new(JournalErrorCode::Internal)) })
        } else {
            self.inner.commit(request)
        }
    }

    fn resolve_payload<'a>(
        &'a self,
        request: ResolveJournalPayloadV1,
    ) -> HostFuture<'a, Result<ResolvedJournalPayloadV1, JournalError>> {
        self.inner.resolve_payload(request)
    }

    fn release_owner<'a>(
        &'a self,
        request: ReleaseJournalOwnerV1,
    ) -> HostFuture<'a, Result<(), JournalError>> {
        Box::pin(async move {
            let cancelled = lock(&self.cancellation)
                .as_ref()
                .is_some_and(CancellationToken::is_cancelled);
            self.release_saw_cancelled
                .store(cancelled, Ordering::Release);
            let settled = [0, 1].into_iter().all(|task_id| {
                matches!(
                    self.executor.poll_task(task_id),
                    Ok(DeterministicTaskPoll::Settled(_)
                        | DeterministicTaskPoll::Stopped
                        | DeterministicTaskPoll::Panicked { .. }
                        | DeterministicTaskPoll::Failed(_))
                )
            });
            self.release_saw_graph_tasks_settled
                .store(settled, Ordering::Release);
            self.releases.fetch_add(1, Ordering::AcqRel);
            self.release_started.store(true, Ordering::Release);
            std::future::poll_fn(|context| {
                if self.release_allowed.load(Ordering::Acquire) {
                    Poll::Ready(())
                } else {
                    *lock(&self.release_waker) = Some(context.waker().clone());
                    Poll::Pending
                }
            })
            .await;
            self.inner.release_owner(request).await
        })
    }
}

struct FixedPrefixJournalStore {
    inner: InMemoryJournalStore,
    prefix: JournalPrefixV1,
}

impl FixedPrefixJournalStore {
    fn new(prefix: JournalPrefixV1) -> Self {
        Self {
            inner: InMemoryJournalStore::new(),
            prefix,
        }
    }
}

impl JournalStorage for FixedPrefixJournalStore {
    fn acquire_owner<'a>(
        &'a self,
        request: AcquireJournalOwnerV1,
    ) -> HostFuture<'a, Result<JournalOwnershipV1, JournalError>> {
        self.inner.acquire_owner(request)
    }

    fn read_prefix<'a>(
        &'a self,
        _request: ReadJournalPrefixV1,
    ) -> HostFuture<'a, Result<JournalPrefixV1, JournalError>> {
        Box::pin(async move { Ok(self.prefix.clone()) })
    }

    fn commit<'a>(
        &'a self,
        request: JournalCommitRequestV1,
    ) -> HostFuture<'a, Result<JournalCommitReceiptV1, JournalError>> {
        self.inner.commit(request)
    }

    fn resolve_payload<'a>(
        &'a self,
        request: ResolveJournalPayloadV1,
    ) -> HostFuture<'a, Result<ResolvedJournalPayloadV1, JournalError>> {
        self.inner.resolve_payload(request)
    }

    fn release_owner<'a>(
        &'a self,
        request: ReleaseJournalOwnerV1,
    ) -> HostFuture<'a, Result<(), JournalError>> {
        self.inner.release_owner(request)
    }
}

impl TempDirectory {
    fn new(source: &str) -> Self {
        let suffix = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "gantry-source-spawn-{}-{suffix}",
            std::process::id()
        ));
        fs::create_dir(&path)
            .unwrap_or_else(|error| panic!("could not create {}: {error}", path.display()));
        fs::write(path.join("main.gnt"), source)
            .unwrap_or_else(|error| panic!("could not write spawn fixture: {error}"));
        Self(path)
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn native_child_submission_keeps_the_gate_closed_and_establishes_session_before_hook() {
    let root = TempDirectory::new(
        "action read_only inspect() -> Int;\nfn main() { spawn child -> Int { action inspect() } discard join(child); }",
    );
    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    let integration = Arc::new(ScriptedIntegration::new(
        [
            ScriptedPreflight::success(
                EmbeddingOperation::ResolveMappings,
                &br#"{"action_mapping_revision":"actions-v1","result":"resolved"}"#[..],
            ),
            ScriptedPreflight::success(
                EmbeddingOperation::ResolveSessions,
                &br#"{"result":"resolved"}"#[..],
            ),
            ScriptedPreflight::success(
                EmbeddingOperation::EstablishSession,
                &br#"{"result":"established"}"#[..],
            ),
        ],
        [ScriptedHook::created([Ok(HookOutcomeV1::Completed(
            Arc::from(&b"7"[..]),
        ))])],
    ));
    let sink = Arc::new(RecordingSink::new(
        Arc::clone(&executor),
        DeliveryOutcome::Success,
    ));
    let interpreter = interpreter_with_delivery(
        Arc::clone(&executor),
        integration.clone(),
        8,
        65_536,
        plan(SinkClass::BestEffort, sink.clone()),
    );
    executor.poll_next_spawn_immediately();
    let accepted = accepted(&interpreter, &root);
    let handle = accepted.handle().clone();
    drop(accepted);

    executor.poll_next_spawn_immediately();
    assert!(matches!(
        executor.poll_task(1),
        Ok(DeterministicTaskPoll::Pending)
    ));
    assert_eq!(executor.task_ids(), [0, 1, 2]);
    assert_eq!(executor.poll_count(2), Some(1));
    let task_state = interpreter
        .test_nondurable_task_state(handle.execution_id())
        .unwrap_or_else(|| panic!("nondurable task state is absent"));
    let spawn = spawn_event(&sink);
    assert_eq!(spawn.executor_task_ids, [0, 1]);
    assert_eq!(spawn.event.task_id(), Some(task_state.root_task_id()));
    assert_eq!(spawn.event.causal_ids().len(), 2);
    let child_id = spawn.event.causal_ids()[1];
    let child = task_state
        .task(child_id)
        .unwrap_or_else(|| panic!("spawn event child is absent from task state"));
    assert!(matches!(child.status(), ConcurrentTaskStatusV1::Running));
    assert!(child.handle_is_visible());
    assert!(!task_state.parent_is_suspended(task_state.root_task_id()));
    assert!(integration.calls().iter().all(|call| {
        !matches!(
            call.operation,
            EmbeddingOperation::EstablishSession | EmbeddingOperation::CreateHook
        )
    }));

    let snapshot = drive_to_terminal(&executor, &interpreter, &handle);
    assert!(matches!(
        snapshot.foreground,
        Some(gantry::runtime::MachineOutcome::Failed(ref failure))
            if failure.code == gantry::runtime::RuntimeCode::InternalInvariant
    ));
    assert_eq!(snapshot.terminal, snapshot.foreground);
    let runtime_calls = integration
        .calls()
        .into_iter()
        .filter(|call| {
            matches!(
                call.operation,
                EmbeddingOperation::EstablishSession
                    | EmbeddingOperation::CreateHook
                    | EmbeddingOperation::DispatchOperation
            )
        })
        .map(|call| call.operation)
        .collect::<Vec<_>>();
    assert_eq!(
        runtime_calls,
        [
            EmbeddingOperation::EstablishSession,
            EmbeddingOperation::CreateHook,
            EmbeddingOperation::DispatchOperation,
        ]
    );
}

#[test]
fn nondurable_cancellation_after_child_session_establishment_constructs_no_hook() {
    let root = TempDirectory::new(
        "action read_only inspect() -> Int;\nfn main() { spawn child -> Int { action inspect() } discard join(child); }",
    );
    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    let integration = Arc::new(ScriptedIntegration::new(
        [
            ScriptedPreflight::success(
                EmbeddingOperation::ResolveMappings,
                &br#"{"action_mapping_revision":"actions-v1","result":"resolved"}"#[..],
            ),
            ScriptedPreflight::success(
                EmbeddingOperation::ResolveSessions,
                &br#"{"result":"resolved"}"#[..],
            ),
            ScriptedPreflight::success(
                EmbeddingOperation::EstablishSession,
                &br#"{"result":"established"}"#[..],
            ),
        ],
        [ScriptedHook::created([Ok(HookOutcomeV1::Completed(
            Arc::from(&b"7"[..]),
        ))])],
    ));
    let sessions = Arc::new(CancelAfterEstablishment::new(Arc::clone(&integration), 1));
    let sink = Arc::new(RecordingSink::new(
        Arc::clone(&executor),
        DeliveryOutcome::Success,
    ));
    let interpreter = interpreter_with_session_service(
        Arc::clone(&executor),
        integration.clone(),
        sessions.clone(),
        8,
        65_536,
        plan(SinkClass::BestEffort, sink.clone()),
    );
    executor.poll_next_spawn_immediately();
    let accepted = accepted(&interpreter, &root);
    let handle = accepted.handle().clone();
    drop(accepted);
    let cancellation = handle
        .cancellation_signal()
        .unwrap_or_else(|error| panic!("cancellation signal failed: {error:?}"));
    sessions.arm(Arc::new(move || {
        cancellation.cancel();
    }));
    let snapshot = drive_to_terminal(&executor, &interpreter, &handle);
    assert!(sessions.cancelled());
    assert!(snapshot.terminal.is_some());

    let state = interpreter
        .test_nondurable_task_state(handle.execution_id())
        .unwrap_or_else(|| panic!("nondurable task state is absent"));
    let spawn = spawn_event(&sink);
    let child_id = spawn.event.causal_ids()[1];
    let child = state
        .task(child_id)
        .unwrap_or_else(|| panic!("cancelled child is absent"));
    assert!(child.handle_is_visible());
    assert!(matches!(
        child.status(),
        ConcurrentTaskStatusV1::Cancelled(_)
    ));
    assert_eq!(
        state
            .task_record(child_id)
            .map(|record| record.driver_ownership()),
        Some(TaskDriverOwnershipV1::PhysicallySettled)
    );
    assert!(state.drivers_are_quiescent());
    assert!(integration.calls().iter().all(|call| {
        !matches!(
            call.operation,
            EmbeddingOperation::CreateHook | EmbeddingOperation::DispatchOperation
        )
    }));
}

#[test]
fn durable_cancellation_after_child_session_establishment_constructs_no_hook() {
    let root = TempDirectory::new(
        "action read_only inspect() -> Int;\nfn main() { spawn child -> Int { action inspect() } discard join(child); }",
    );
    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    let integration = Arc::new(ScriptedIntegration::new(
        [
            ScriptedPreflight::success(
                EmbeddingOperation::ResolveMappings,
                &br#"{"action_mapping_revision":"actions-v1","result":"resolved"}"#[..],
            ),
            ScriptedPreflight::success(
                EmbeddingOperation::ResolveSessions,
                &br#"{"result":"resolved"}"#[..],
            ),
            ScriptedPreflight::success(
                EmbeddingOperation::EstablishSession,
                &br#"{"result":"established"}"#[..],
            ),
            ScriptedPreflight::success(
                EmbeddingOperation::EstablishSession,
                &br#"{"result":"established"}"#[..],
            ),
        ],
        [ScriptedHook::created([Ok(HookOutcomeV1::Completed(
            Arc::from(&b"7"[..]),
        ))])],
    ));
    let sessions = Arc::new(CancelAfterEstablishment::new(Arc::clone(&integration), 2));
    let interpreter = interpreter_with_session_service(
        Arc::clone(&executor),
        integration.clone(),
        sessions.clone(),
        8,
        65_536,
        SinkPlan::default(),
    );
    let storage = Arc::new(InMemoryJournalStore::new());
    let journal_id = JournalId::new("durable-source-spawn-cancel-establishment")
        .unwrap_or_else(|error| panic!("journal identity failed: {error:?}"));
    let accepted = durable_accepted(&interpreter, &root, storage.clone(), journal_id.clone());
    let handle = accepted.handle().clone();
    let execution_id = accepted.execution_id();
    let cancelling_interpreter = interpreter.clone();
    let reason = caller_cancellation_reason(Some(Arc::from("cancel-during-establishment")), 64)
        .unwrap_or_else(|error| panic!("cancellation reason failed: {error:?}"));
    sessions.arm(Arc::new(move || {
        let mut cancellation =
            Box::pin(cancelling_interpreter.cancel_execution(execution_id, reason.clone()));
        assert!(
            cancellation
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
    }));

    let snapshot = drive_to_terminal(&executor, &interpreter, &handle);
    assert!(sessions.cancelled());
    assert!(snapshot.terminal.is_some());
    assert!(integration.calls().iter().all(|call| {
        !matches!(
            call.operation,
            EmbeddingOperation::CreateHook | EmbeddingOperation::DispatchOperation
        )
    }));

    let prefix = block_on(storage.read_prefix(ReadJournalPrefixV1 { journal_id }))
        .unwrap_or_else(|error| panic!("journal read failed: {error:?}"));
    let (program, graph_entries) = durable_graph_entries(&prefix);
    let child_id = graph_entries
        .iter()
        .find(|(_, evidence)| evidence.cut() == DurableCommitCutV1::TaskCreation)
        .map(|(_, evidence)| evidence.task_id())
        .unwrap_or_else(|| panic!("durable child creation cut is absent"));
    assert!(graph_entries.iter().any(|(_, evidence)| {
        evidence.cut() == DurableCommitCutV1::TaskSettlement
            && evidence.task_id() == child_id
            && evidence.checkpoint().task_status(child_id) == Some(TaskStatusKind::Cancelled)
    }));
    let recovered = recover_concurrent_authoritative_prefix(program, &prefix)
        .unwrap_or_else(|error| panic!("cancelled durable prefix failed recovery: {error:?}"));
    let state = recovered.execution().scheduler().state();
    let child = state
        .task(child_id)
        .unwrap_or_else(|| panic!("cancelled durable child is absent"));
    assert!(child.handle_is_visible());
    assert!(matches!(
        child.status(),
        ConcurrentTaskStatusV1::Cancelled(_)
    ));
    assert_eq!(
        state
            .task_record(child_id)
            .map(|record| record.driver_ownership()),
        Some(TaskDriverOwnershipV1::PhysicallySettled)
    );
}

#[test]
fn child_executor_rejection_settles_without_submitting_another_driver() {
    let root = TempDirectory::new("fn main() { spawn child -> Int { 7 } discard join(child); }");
    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    let integration = Arc::new(ScriptedIntegration::new(
        [ScriptedPreflight::success(
            EmbeddingOperation::ResolveSessions,
            &br#"{"result":"resolved"}"#[..],
        )],
        [],
    ));
    let sink = Arc::new(RecordingSink::new(
        Arc::clone(&executor),
        DeliveryOutcome::Success,
    ));
    let interpreter = interpreter_with_delivery(
        Arc::clone(&executor),
        integration,
        8,
        65_536,
        plan(SinkClass::BestEffort, sink.clone()),
    );
    executor.poll_next_spawn_immediately();
    let accepted = accepted(&interpreter, &root);
    let handle = accepted.handle().clone();
    drop(accepted);

    executor.fail_next_spawn();
    let snapshot = drive_to_terminal(&executor, &interpreter, &handle);
    assert_eq!(executor.task_ids(), [0, 1]);
    let task_state = interpreter
        .test_nondurable_task_state(handle.execution_id())
        .unwrap_or_else(|| panic!("nondurable task state is absent"));
    let spawn = spawn_event(&sink);
    assert_eq!(spawn.executor_task_ids, [0, 1]);
    let child_id = spawn.event.causal_ids()[1];
    let child = task_state
        .task(child_id)
        .unwrap_or_else(|| panic!("rejected child is absent from task state"));
    assert!(matches!(
        child.status(),
        ConcurrentTaskStatusV1::Failed(failure)
            if failure.code.as_ref() == "task-submission-failure"
    ));
    assert!(child.handle_is_visible());
    assert!(!task_state.parent_is_suspended(task_state.root_task_id()));
    let child_completions = sink
        .events()
        .into_iter()
        .filter(|record| {
            record.event.kind() == EventKind::TaskCompletion
                && record.event.task_id() == Some(child_id)
        })
        .count();
    assert_eq!(child_completions, 1);
    assert!(matches!(
        snapshot.foreground,
        Some(gantry::runtime::MachineOutcome::Failed(ref failure))
            if failure.code == gantry::runtime::RuntimeCode::InternalInvariant
    ));
    assert_eq!(snapshot.terminal, snapshot.foreground);
}

#[test]
fn cumulative_task_limit_fails_the_spawn_before_session_establishment() {
    let root = TempDirectory::new("fn main() { spawn child -> Int { 7 } discard join(child); }");
    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    let integration = Arc::new(ScriptedIntegration::new(
        [ScriptedPreflight::success(
            EmbeddingOperation::ResolveSessions,
            &br#"{"result":"resolved"}"#[..],
        )],
        [],
    ));
    let interpreter = interpreter_with_delivery(
        Arc::clone(&executor),
        integration.clone(),
        8,
        1,
        SinkPlan::default(),
    );
    let accepted = accepted(&interpreter, &root);
    let handle = accepted.handle().clone();
    drop(accepted);

    let snapshot = drive_to_terminal(&executor, &interpreter, &handle);
    assert_eq!(executor.task_ids(), [0]);
    assert!(matches!(
        snapshot.foreground,
        Some(gantry::runtime::MachineOutcome::Failed(ref failure))
            if failure.code == gantry::runtime::RuntimeCode::Deterministic(
                gantry::portable::DeterministicEvaluationCode::TaskCountLimit
            )
    ));
    assert_eq!(snapshot.terminal, snapshot.foreground);
    let task_state = interpreter
        .test_nondurable_task_state(handle.execution_id())
        .unwrap_or_else(|| panic!("nondurable task state is absent"));
    assert_eq!(task_state.created_task_count(), 1);
    assert_eq!(task_state.task_record_count(), 1);
    assert!(
        integration
            .calls()
            .iter()
            .all(|call| { call.operation != EmbeddingOperation::EstablishSession })
    );
}

#[test]
fn required_spawn_delivery_failure_cancels_the_same_created_child_before_submission() {
    let root = TempDirectory::new("fn main() { spawn child -> Int { 7 } discard join(child); }");
    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    let integration = Arc::new(ScriptedIntegration::new(
        [ScriptedPreflight::success(
            EmbeddingOperation::ResolveSessions,
            &br#"{"result":"resolved"}"#[..],
        )],
        [],
    ));
    let sink = Arc::new(RecordingSink::new(
        Arc::clone(&executor),
        DeliveryOutcome::Terminal,
    ));
    let interpreter = interpreter_with_delivery(
        Arc::clone(&executor),
        integration,
        8,
        65_536,
        plan(SinkClass::Required, sink.clone()),
    );
    executor.poll_next_spawn_immediately();
    let accepted = accepted(&interpreter, &root);
    let handle = accepted.handle().clone();
    drop(accepted);

    let snapshot = drive_to_terminal(&executor, &interpreter, &handle);
    assert_eq!(executor.task_ids(), [0, 1]);
    assert_eq!(snapshot.required_delivery_failures.len(), 1);
    assert!(matches!(
        snapshot.foreground,
        Some(gantry::runtime::MachineOutcome::Cancelled(_))
    ));
    let task_state = interpreter
        .test_nondurable_task_state(handle.execution_id())
        .unwrap_or_else(|| panic!("nondurable task state is absent"));
    let spawn = spawn_event(&sink);
    assert_eq!(spawn.executor_task_ids, [0, 1]);
    let child = task_state
        .task(spawn.event.causal_ids()[1])
        .unwrap_or_else(|| panic!("cancelled child is absent from task state"));
    assert!(matches!(
        child.status(),
        ConcurrentTaskStatusV1::Cancelled(reason)
            if reason.as_ref() == "required-event-delivery-failure"
    ));
    assert!(!matches!(child.status(), ConcurrentTaskStatusV1::Failed(_)));
    assert_eq!(
        task_state
            .task_record(child.task_id())
            .map(|record| record.driver_ownership()),
        Some(TaskDriverOwnershipV1::PhysicallySettled)
    );
    assert!(task_state.drivers_are_quiescent());
}

#[test]
fn durable_child_creation_and_success_publish_before_immediate_child_polling() {
    let root = TempDirectory::new("fn main() { spawn child -> Int { 7 } discard join(child); }");
    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    let integration = Arc::new(ScriptedIntegration::new(
        [
            ScriptedPreflight::success(
                EmbeddingOperation::ResolveSessions,
                &br#"{"result":"resolved"}"#[..],
            ),
            ScriptedPreflight::success(
                EmbeddingOperation::EstablishSession,
                &br#"{"result":"established"}"#[..],
            ),
        ],
        [],
    ));
    let interpreter = interpreter_with_delivery(
        Arc::clone(&executor),
        integration.clone(),
        8,
        65_536,
        SinkPlan::default(),
    );
    let storage = Arc::new(InMemoryJournalStore::new());
    let journal_id = JournalId::new("durable-source-spawn-immediate")
        .unwrap_or_else(|error| panic!("journal identity failed: {error:?}"));

    executor.poll_next_spawn_immediately();
    let accepted = durable_accepted(&interpreter, &root, storage.clone(), journal_id.clone());
    let handle = accepted.handle().clone();
    executor.poll_next_spawn_immediately();
    assert!(matches!(
        executor.poll_task(0),
        Ok(DeterministicTaskPoll::Pending)
    ));

    assert_eq!(executor.task_ids(), [0, 1]);
    assert_eq!(executor.poll_count(1), Some(1));
    let calls = integration.calls();
    assert_eq!(
        calls
            .iter()
            .filter(|call| call.operation == EmbeddingOperation::EstablishSession)
            .count(),
        1,
        "only the parent session may be established before the child gate opens"
    );
    assert!(
        calls
            .iter()
            .all(|call| call.operation != EmbeddingOperation::CreateHook)
    );

    let prefix = block_on(storage.read_prefix(ReadJournalPrefixV1 {
        journal_id: journal_id.clone(),
    }))
    .unwrap_or_else(|error| panic!("journal read failed: {error:?}"));
    let (program, graph_entries) = durable_graph_entries(&prefix);
    assert!(graph_entries.len() >= 2, "missing durable graph cuts");
    assert_eq!(graph_entries[0].1.cut(), DurableCommitCutV1::TaskCreation);
    let child_id = graph_entries[0].1.task_id();
    assert_eq!(
        graph_entries[0].1.checkpoint().task_status(child_id),
        Some(TaskStatusKind::Submitting)
    );
    assert_eq!(graph_entries[1].1.cut(), DurableCommitCutV1::Checkpoint);
    assert_eq!(
        graph_entries[1].1.checkpoint().task_status(child_id),
        Some(TaskStatusKind::Running)
    );
    let JournalPrefixV1::Full(full) = &prefix else {
        panic!("in-memory journal returned a compacted prefix")
    };
    assert_eq!(full.evidence[0].kind.as_ref(), "gantry.execution-start/v3");
    assert_eq!(
        full.evidence[1].kind.as_ref(),
        CONCURRENT_DURABLE_EVIDENCE_KIND_V4
    );
    assert_eq!(
        full.evidence[2].kind.as_ref(),
        DURABLE_EVENT_OCCURRENCE_KIND_V1
    );
    assert_eq!(
        full.evidence[3].kind.as_ref(),
        CONCURRENT_DURABLE_EVIDENCE_KIND_V5
    );

    let snapshot = drive_to_terminal(&executor, &interpreter, &handle);
    assert!(snapshot.terminal.is_some());
    let terminal_prefix = block_on(storage.read_prefix(ReadJournalPrefixV1 { journal_id }))
        .unwrap_or_else(|error| panic!("terminal journal read failed: {error:?}"));
    let recovered = recover_concurrent_authoritative_prefix(program, &terminal_prefix)
        .unwrap_or_else(|error| panic!("concurrent durable recovery failed: {error:?}"));
    assert!(
        recovered
            .execution()
            .scheduler()
            .state()
            .terminal_outcome()
            .is_some()
    );
}

#[test]
fn durable_child_action_commits_ordered_operation_cuts() {
    let root = TempDirectory::new(
        "action read_only inspect() -> Int;\nfn main() { spawn child -> Int { action inspect() } discard join(child); }",
    );
    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    let integration = Arc::new(ScriptedIntegration::new(
        [
            ScriptedPreflight::success(
                EmbeddingOperation::ResolveMappings,
                &br#"{"action_mapping_revision":"actions-v1","result":"resolved"}"#[..],
            ),
            ScriptedPreflight::success(
                EmbeddingOperation::ResolveSessions,
                &br#"{"result":"resolved"}"#[..],
            ),
            ScriptedPreflight::success(
                EmbeddingOperation::EstablishSession,
                &br#"{"result":"established"}"#[..],
            ),
            ScriptedPreflight::success(
                EmbeddingOperation::EstablishSession,
                &br#"{"result":"established"}"#[..],
            ),
        ],
        [ScriptedHook::created([Ok(HookOutcomeV1::Completed(
            Arc::from(&b"7"[..]),
        ))])],
    ));
    let interpreter = interpreter_with_delivery(
        Arc::clone(&executor),
        integration.clone(),
        8,
        65_536,
        SinkPlan::default(),
    );
    let storage = Arc::new(InMemoryJournalStore::new());
    let journal_id = JournalId::new("durable-source-spawn-action-order")
        .unwrap_or_else(|error| panic!("journal identity failed: {error:?}"));
    let accepted = durable_accepted(&interpreter, &root, storage.clone(), journal_id.clone());
    let handle = accepted.handle().clone();

    let snapshot = drive_to_terminal(&executor, &interpreter, &handle);
    assert!(
        snapshot.terminal.is_some(),
        "durable child action did not reach a terminal graph cut: {snapshot:?}"
    );
    assert_eq!(
        integration
            .calls()
            .iter()
            .filter(|call| call.operation == EmbeddingOperation::DispatchOperation)
            .count(),
        1
    );

    let prefix = block_on(storage.read_prefix(ReadJournalPrefixV1 { journal_id }))
        .unwrap_or_else(|error| panic!("journal read failed: {error:?}"));
    let (program, graph_entries) = durable_graph_entries(&prefix);
    let child_id = graph_entries
        .iter()
        .find(|(_, evidence)| evidence.cut() == DurableCommitCutV1::TaskCreation)
        .map(|(_, evidence)| evidence.task_id())
        .unwrap_or_else(|| panic!("durable child creation cut is absent"));
    let operation_cuts = graph_entries
        .iter()
        .filter(|(_, evidence)| evidence.task_id() == child_id && evidence.has_operation())
        .map(|(_, evidence)| evidence.cut())
        .collect::<Vec<_>>();
    assert_eq!(
        operation_cuts,
        [
            DurableCommitCutV1::OperationPrepared,
            DurableCommitCutV1::OperationOutcome,
            DurableCommitCutV1::OperationResult,
        ]
    );
    let full_recovered = recover_concurrent_authoritative_prefix(Arc::clone(&program), &prefix)
        .unwrap_or_else(|error| panic!("ordered operation prefix did not recover: {error:?}"));
    let JournalPrefixV1::Full(full) = &prefix else {
        panic!("in-memory journal returned a compacted prefix")
    };
    let outcome_sequence = graph_entries
        .iter()
        .find(|(_, evidence)| {
            evidence.task_id() == child_id && evidence.cut() == DurableCommitCutV1::OperationOutcome
        })
        .map(|(sequence, _)| *sequence)
        .unwrap_or_else(|| panic!("operation outcome cut is absent"));
    let frontier_index = full
        .evidence
        .iter()
        .position(|entry| entry.sequence == outcome_sequence)
        .unwrap_or_else(|| panic!("operation outcome envelope is absent"));
    let compacted_full = FullJournalPrefixV1 {
        journal_id: full.journal_id.clone(),
        evidence: Arc::from(full.evidence[..=frontier_index].to_vec()),
        committed_through: outcome_sequence,
    };
    let compacted =
        ConcurrentDurableRecoverySnapshotV1::from_full_prefix(&program, &compacted_full)
            .unwrap_or_else(|error| panic!("operation frontier compaction failed: {error:?}"));
    let snapshot_prefix = JournalPrefixV1::Snapshot(SnapshotJournalPrefixV1 {
        journal_id: full.journal_id.clone(),
        snapshot_version: CONCURRENT_DURABLE_SNAPSHOT_VERSION_V1,
        frontier: compacted.frontier(),
        canonical_snapshot: Arc::from(compacted.canonical_body()),
        retained_evidence: compacted.retained_evidence().clone(),
        suffix: Arc::from(full.evidence[frontier_index + 1..].to_vec()),
        committed_through: full.committed_through,
    });
    let compacted_recovered = recover_concurrent_authoritative_prefix(program, &snapshot_prefix)
        .unwrap_or_else(|error| panic!("operation snapshot suffix failed: {error:?}"));
    assert_eq!(
        compacted_recovered.latest_sequence(),
        full_recovered.latest_sequence()
    );
    assert_eq!(
        compacted_recovered.latest_evidence_id(),
        full_recovered.latest_evidence_id()
    );
    assert_eq!(
        compacted_recovered.latest_cut(),
        full_recovered.latest_cut()
    );
    assert_eq!(compacted_recovered.events(), full_recovered.events());
    assert_eq!(
        compacted_recovered
            .execution()
            .scheduler()
            .state()
            .terminal_outcome(),
        full_recovered
            .execution()
            .scheduler()
            .state()
            .terminal_outcome()
    );
}

#[test]
fn durable_child_prompt_uses_ordered_graph_operation_lifecycle() {
    let root = TempDirectory::new(
        "agents { worker }\ndefault agent = worker;\nfn main() { spawn child -> String { prompt \"child\" -> String } discard join(child); }",
    );
    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    let integration = Arc::new(ScriptedIntegration::new(
        [
            ScriptedPreflight::success(
                EmbeddingOperation::ResolveMappings,
                &br#"{"agent_mapping_revision":"agents-v1","result":"resolved"}"#[..],
            ),
            ScriptedPreflight::success(
                EmbeddingOperation::ResolveSessions,
                &br#"{"result":"resolved"}"#[..],
            ),
            ScriptedPreflight::success(
                EmbeddingOperation::EstablishSession,
                &br#"{"result":"established"}"#[..],
            ),
            ScriptedPreflight::success(
                EmbeddingOperation::EstablishSession,
                &br#"{"result":"established"}"#[..],
            ),
            ScriptedPreflight::success(
                EmbeddingOperation::EstablishSession,
                &br#"{"result":"established"}"#[..],
            ),
        ],
        [ScriptedHook::created([Ok(HookOutcomeV1::Completed(
            Arc::from(&br#""done""#[..]),
        ))])],
    ));
    let interpreter = interpreter_with_delivery(
        Arc::clone(&executor),
        integration,
        8,
        65_536,
        SinkPlan::default(),
    );
    let storage = Arc::new(InMemoryJournalStore::new());
    let journal_id = JournalId::new("durable-source-spawn-prompt-order")
        .unwrap_or_else(|error| panic!("journal identity failed: {error:?}"));
    let accepted = durable_accepted(&interpreter, &root, storage.clone(), journal_id.clone());
    let handle = accepted.handle().clone();

    let snapshot = drive_to_terminal(&executor, &interpreter, &handle);
    assert!(
        snapshot.terminal.is_some(),
        "durable child prompt did not reach a terminal graph cut: {snapshot:?}"
    );
    let prefix = block_on(storage.read_prefix(ReadJournalPrefixV1 { journal_id }))
        .unwrap_or_else(|error| panic!("journal read failed: {error:?}"));
    let (program, graph_entries) = durable_graph_entries(&prefix);
    let child_id = graph_entries
        .iter()
        .find(|(_, evidence)| evidence.cut() == DurableCommitCutV1::TaskCreation)
        .map(|(_, evidence)| evidence.task_id())
        .unwrap_or_else(|| panic!("durable child creation cut is absent"));
    let operation_cuts = graph_entries
        .iter()
        .filter(|(_, evidence)| evidence.task_id() == child_id && evidence.has_operation())
        .map(|(_, evidence)| evidence.cut())
        .collect::<Vec<_>>();
    assert_eq!(
        operation_cuts,
        [
            DurableCommitCutV1::OperationPrepared,
            DurableCommitCutV1::OperationOutcome,
            DurableCommitCutV1::OperationResult,
        ]
    );
    recover_concurrent_authoritative_prefix(program, &prefix)
        .unwrap_or_else(|error| panic!("prompt operation prefix did not recover: {error:?}"));
}

#[test]
fn durable_task_limit_precheck_skips_parent_session_and_child_creation() {
    let root = TempDirectory::new("fn main() { spawn child -> Int { 7 } discard join(child); }");
    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    let integration = Arc::new(ScriptedIntegration::new(
        [ScriptedPreflight::success(
            EmbeddingOperation::ResolveSessions,
            &br#"{"result":"resolved"}"#[..],
        )],
        [],
    ));
    let interpreter = interpreter_with_delivery(
        Arc::clone(&executor),
        integration.clone(),
        8,
        1,
        SinkPlan::default(),
    );
    let storage = Arc::new(InMemoryJournalStore::new());
    let journal_id = JournalId::new("durable-source-spawn-task-limit")
        .unwrap_or_else(|error| panic!("journal identity failed: {error:?}"));
    let accepted = durable_accepted(&interpreter, &root, storage.clone(), journal_id.clone());
    let handle = accepted.handle().clone();

    let snapshot = drive_to_terminal(&executor, &interpreter, &handle);
    assert!(matches!(
        snapshot.foreground,
        Some(MachineOutcome::Failed(ref failure))
            if failure.code == RuntimeCode::Deterministic(
                gantry::portable::DeterministicEvaluationCode::TaskCountLimit
            )
    ));
    assert!(
        integration
            .calls()
            .iter()
            .all(|call| call.operation != EmbeddingOperation::EstablishSession)
    );

    let prefix = block_on(storage.read_prefix(ReadJournalPrefixV1 { journal_id }))
        .unwrap_or_else(|error| panic!("journal read failed: {error:?}"));
    let (program, graph_entries) = durable_graph_entries(&prefix);
    assert!(
        graph_entries
            .iter()
            .all(|(_, evidence)| evidence.cut() != DurableCommitCutV1::TaskCreation)
    );
    let recovered = recover_concurrent_authoritative_prefix(program, &prefix)
        .unwrap_or_else(|error| panic!("concurrent durable recovery failed: {error:?}"));
    assert_eq!(
        recovered
            .execution()
            .scheduler()
            .state()
            .created_task_count(),
        1
    );
    assert_eq!(
        recovered
            .execution()
            .scheduler()
            .state()
            .task_record_count(),
        1
    );
}

#[test]
fn durable_parent_session_failure_is_task_local_and_creates_no_child() {
    let root = TempDirectory::new("fn main() { spawn child -> Int { 7 } discard join(child); }");
    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    let integration = Arc::new(ScriptedIntegration::new(
        [
            ScriptedPreflight::success(
                EmbeddingOperation::ResolveSessions,
                &br#"{"result":"resolved"}"#[..],
            ),
            ScriptedPreflight::failure(
                EmbeddingOperation::EstablishSession,
                HostError {
                    code: Arc::from("parent-session-failure"),
                    protected_diagnostic: None,
                },
            ),
        ],
        [],
    ));
    let interpreter = interpreter_with_delivery(
        Arc::clone(&executor),
        integration.clone(),
        8,
        65_536,
        SinkPlan::default(),
    );
    let storage = Arc::new(InMemoryJournalStore::new());
    let journal_id = JournalId::new("durable-source-spawn-parent-session-failure")
        .unwrap_or_else(|error| panic!("journal identity failed: {error:?}"));
    let accepted = durable_accepted(&interpreter, &root, storage.clone(), journal_id.clone());
    let handle = accepted.handle().clone();

    let snapshot = drive_to_terminal(&executor, &interpreter, &handle);
    assert!(matches!(
        snapshot.foreground,
        Some(MachineOutcome::Failed(ref failure))
            if failure.code
                == RuntimeCode::Operation(RuntimeErrorCategory::LogicalSessionSetup)
    ));
    assert_eq!(
        integration
            .calls()
            .iter()
            .filter(|call| call.operation == EmbeddingOperation::EstablishSession)
            .count(),
        1
    );

    let prefix = block_on(storage.read_prefix(ReadJournalPrefixV1 { journal_id }))
        .unwrap_or_else(|error| panic!("journal read failed: {error:?}"));
    let (program, graph_entries) = durable_graph_entries(&prefix);
    assert!(
        graph_entries
            .iter()
            .all(|(_, evidence)| evidence.cut() != DurableCommitCutV1::TaskCreation)
    );
    let recovered = recover_concurrent_authoritative_prefix(program, &prefix)
        .unwrap_or_else(|error| panic!("concurrent durable recovery failed: {error:?}"));
    assert_eq!(
        recovered
            .execution()
            .scheduler()
            .state()
            .created_task_count(),
        1
    );
}

#[test]
fn durable_required_spawn_event_settles_before_child_submission() {
    let root = TempDirectory::new("fn main() { spawn child -> Int { 7 } discard join(child); }");
    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    let integration = Arc::new(ScriptedIntegration::new(
        [
            ScriptedPreflight::success(
                EmbeddingOperation::ResolveSessions,
                &br#"{"result":"resolved"}"#[..],
            ),
            ScriptedPreflight::success(
                EmbeddingOperation::EstablishSession,
                &br#"{"result":"established"}"#[..],
            ),
            ScriptedPreflight::success(
                EmbeddingOperation::EstablishSession,
                &br#"{"result":"established"}"#[..],
            ),
        ],
        [],
    ));
    let sink = Arc::new(RecordingSink::new(
        Arc::clone(&executor),
        DeliveryOutcome::Success,
    ));
    let interpreter = interpreter_with_delivery(
        Arc::clone(&executor),
        integration,
        8,
        65_536,
        plan(SinkClass::Required, sink.clone()),
    );
    let storage = Arc::new(InMemoryJournalStore::new());
    let journal_id = JournalId::new("durable-source-spawn-required-barrier")
        .unwrap_or_else(|error| panic!("journal identity failed: {error:?}"));

    executor.poll_next_spawn_immediately();
    let accepted = durable_accepted(&interpreter, &root, storage.clone(), journal_id.clone());
    for _ in 0..8 {
        if sink
            .events()
            .iter()
            .any(|record| record.event.kind() == EventKind::Spawn)
        {
            break;
        }
        for task_id in executor.task_ids() {
            if executor.is_runnable(task_id) {
                let _ = executor
                    .poll_task(task_id)
                    .unwrap_or_else(|error| panic!("task {task_id} poll failed: {error:?}"));
            }
        }
    }
    let spawn = spawn_event(&sink);
    assert_eq!(executor.task_ids().len(), spawn.executor_task_ids.len() + 1);

    let prefix = block_on(storage.read_prefix(ReadJournalPrefixV1 { journal_id }))
        .unwrap_or_else(|error| panic!("journal read failed: {error:?}"));
    let JournalPrefixV1::Full(full) = prefix else {
        panic!("in-memory journal returned a compacted prefix")
    };
    let kinds = full
        .evidence
        .iter()
        .map(|entry| entry.kind.as_ref())
        .collect::<Vec<_>>();
    assert_eq!(kinds[1], CONCURRENT_DURABLE_EVIDENCE_KIND_V4);
    assert_eq!(kinds[2], DURABLE_EVENT_OCCURRENCE_KIND_V1);
    assert_eq!(kinds[3], DURABLE_EVENT_DISPATCHED_KIND_V1);
    assert_eq!(kinds[4], DURABLE_EVENT_SETTLED_KIND_V1);
    assert_eq!(kinds[5], CONCURRENT_DURABLE_EVIDENCE_KIND_V5);
    drop(accepted);
}

#[test]
fn public_durable_query_retains_required_spawn_delivery_failure() {
    let root = TempDirectory::new("fn main() { spawn child -> Int { 7 } discard join(child); }");
    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    let integration = Arc::new(ScriptedIntegration::new(
        [
            ScriptedPreflight::success(
                EmbeddingOperation::ResolveSessions,
                &br#"{"result":"resolved"}"#[..],
            ),
            ScriptedPreflight::success(
                EmbeddingOperation::EstablishSession,
                &br#"{"result":"established"}"#[..],
            ),
            ScriptedPreflight::success(
                EmbeddingOperation::EstablishSession,
                &br#"{"result":"established"}"#[..],
            ),
        ],
        [],
    ));
    let sink = Arc::new(RecordingSink::new(
        Arc::clone(&executor),
        DeliveryOutcome::Terminal,
    ));
    let interpreter = interpreter_with_delivery(
        Arc::clone(&executor),
        integration,
        8,
        65_536,
        plan(SinkClass::Required, sink),
    );
    let storage = Arc::new(InMemoryJournalStore::new());
    let storage_adapter: Arc<dyn JournalStorage> = storage.clone();
    let journal_id = JournalId::new("durable-query-required-spawn-failure")
        .unwrap_or_else(|error| panic!("journal identity failed: {error:?}"));
    executor.poll_next_spawn_immediately();
    let accepted = durable_accepted(&interpreter, &root, storage.clone(), journal_id.clone());
    let execution_id = accepted.execution_id();
    let live = drive_to_terminal(&executor, &interpreter, accepted.handle());
    assert_eq!(live.required_delivery_failures.len(), 1);
    assert_eq!(
        live.cancellation.as_ref().map(|reason| reason.category),
        Some(CancellationReasonCategory::Runtime)
    );
    assert_eq!(
        live.cancellation
            .as_ref()
            .and_then(|reason| reason.message.as_deref()),
        Some("required-event-delivery-failure")
    );

    let prefix = block_on(storage.read_prefix(ReadJournalPrefixV1 {
        journal_id: journal_id.clone(),
    }))
    .unwrap_or_else(|error| panic!("required-delivery journal read failed: {error:?}"));
    let JournalPrefixV1::Full(full) = &prefix else {
        panic!("in-memory journal returned a compacted prefix")
    };
    let program = DurableExecutionStartV3::retained_program(&full.evidence[0].canonical_body)
        .unwrap_or_else(|error| panic!("retained program failed to decode: {error:?}"));
    let compacted = ConcurrentDurableRecoverySnapshotV1::from_full_prefix(&program, full)
        .unwrap_or_else(|error| panic!("required-delivery compaction failed: {error:?}"));
    let snapshot_prefix = JournalPrefixV1::Snapshot(SnapshotJournalPrefixV1 {
        journal_id: journal_id.clone(),
        snapshot_version: CONCURRENT_DURABLE_SNAPSHOT_VERSION_V1,
        frontier: compacted.frontier(),
        canonical_snapshot: Arc::from(compacted.canonical_body()),
        retained_evidence: compacted.retained_evidence().clone(),
        suffix: Arc::from([]),
        committed_through: compacted.frontier(),
    });

    let queried = block_on(
        DurableLifecycleCoordinator::new(Arc::clone(&storage_adapter)).query(
            DurableQueryExecutionRequest {
                journal_id: journal_id.clone(),
                expected_execution_id: Some(execution_id),
            },
        ),
    );
    let DurableQueryExecutionResult::Snapshot(recovered) = queried else {
        panic!("required-delivery query did not recover a snapshot: {queried:?}")
    };
    assert_eq!(recovered.cancellation, live.cancellation);
    assert_eq!(
        recovered.required_delivery_failures,
        live.required_delivery_failures
    );
    assert_eq!(recovered.terminal, live.terminal);

    let snapshot_storage: Arc<dyn JournalStorage> =
        Arc::new(FixedPrefixJournalStore::new(snapshot_prefix));
    let compacted_query = block_on(DurableLifecycleCoordinator::new(snapshot_storage).query(
        DurableQueryExecutionRequest {
            journal_id,
            expected_execution_id: Some(execution_id),
        },
    ));
    let DurableQueryExecutionResult::Snapshot(compacted_recovered) = compacted_query else {
        panic!("compacted required-delivery query failed: {compacted_query:?}")
    };
    assert_eq!(compacted_recovered.cancellation, live.cancellation);
    assert_eq!(
        compacted_recovered.required_delivery_failures,
        live.required_delivery_failures
    );
    assert_eq!(compacted_recovered.terminal, live.terminal);
}

#[test]
fn public_durable_graph_cancellation_commits_before_signalling_and_finishes() {
    let root = TempDirectory::new("fn main() { spawn child -> Int { 7 } discard join(child); }");
    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    let integration = Arc::new(ScriptedIntegration::new(
        [
            ScriptedPreflight::success(
                EmbeddingOperation::ResolveSessions,
                &br#"{"result":"resolved"}"#[..],
            ),
            ScriptedPreflight::success(
                EmbeddingOperation::EstablishSession,
                &br#"{"result":"established"}"#[..],
            ),
            ScriptedPreflight::success(
                EmbeddingOperation::EstablishSession,
                &br#"{"result":"established"}"#[..],
            ),
        ],
        [],
    ));
    let interpreter = interpreter_with_delivery(
        Arc::clone(&executor),
        integration,
        8,
        65_536,
        SinkPlan::default(),
    );
    let storage = Arc::new(CountingJournalStore::default());
    let journal_id = JournalId::new("durable-source-spawn-public-cancellation")
        .unwrap_or_else(|error| panic!("journal identity failed: {error:?}"));
    let accepted = durable_accepted(&interpreter, &root, storage.clone(), journal_id.clone());
    let execution_id = accepted.execution_id();
    let signal = accepted
        .handle()
        .cancellation_signal()
        .unwrap_or_else(|error| panic!("cancellation signal failed: {error:?}"));
    assert!(matches!(
        executor.poll_task(0),
        Ok(DeterministicTaskPoll::Pending)
    ));
    assert_eq!(executor.task_ids(), [0, 1]);

    let reason = caller_cancellation_reason(Some(Arc::from("cancel-graph")), 64)
        .unwrap_or_else(|error| panic!("cancellation reason failed: {error:?}"));
    let mut cancellation = pin!(interpreter.cancel_execution(execution_id, reason.clone()));
    assert!(
        cancellation
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    assert!(!signal.is_cancelled());
    assert!(matches!(
        executor.poll_task(0),
        Ok(DeterministicTaskPoll::Pending | DeterministicTaskPoll::Settled(_))
    ));
    assert!(signal.is_cancelled());

    let record = 'drive: loop {
        if let Poll::Ready(result) = cancellation
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        {
            break 'drive result.unwrap_or_else(|error| panic!("cancellation failed: {error:?}"));
        }
        for task_id in executor.task_ids() {
            if executor.is_runnable(task_id) {
                let _ = executor
                    .poll_task(task_id)
                    .unwrap_or_else(|error| panic!("task {task_id} poll failed: {error:?}"));
            }
        }
    };
    assert!(matches!(
        record,
        CancellationRecord::Accepted { reason: ref effective, .. } if effective == &reason
    ));
    assert_eq!(storage.release_count(), 1);
    let snapshot = interpreter
        .query_execution(execution_id)
        .unwrap_or_else(|error| panic!("execution query failed: {error:?}"))
        .unwrap_or_else(|| panic!("cancelled execution disappeared"));
    assert_eq!(snapshot.cancellation, Some(reason.clone()));
    assert!(snapshot.terminal.is_some());

    let prefix = block_on(storage.read_prefix(ReadJournalPrefixV1 {
        journal_id: journal_id.clone(),
    }))
    .unwrap_or_else(|error| panic!("journal read failed: {error:?}"));
    let storage_adapter: Arc<dyn JournalStorage> = storage.clone();
    let queried = block_on(DurableLifecycleCoordinator::new(storage_adapter).query(
        DurableQueryExecutionRequest {
            journal_id,
            expected_execution_id: Some(execution_id),
        },
    ));
    let DurableQueryExecutionResult::Snapshot(recovered) = queried else {
        panic!("cancelled concurrent query did not recover a snapshot: {queried:?}")
    };
    assert_eq!(recovered.cancellation, Some(reason));
    assert!(recovered.terminal.is_some());
    let (program, graph_entries) = durable_graph_entries(&prefix);
    let cancellation_sequence = graph_entries
        .iter()
        .find(|(_, evidence)| evidence.cut() == DurableCommitCutV1::Cancellation)
        .map(|(sequence, _)| *sequence)
        .unwrap_or_else(|| panic!("graph cancellation cut is absent"));
    let first_settlement = graph_entries
        .iter()
        .find(|(sequence, evidence)| {
            *sequence > cancellation_sequence
                && evidence.cut() == DurableCommitCutV1::TaskSettlement
        })
        .map(|(sequence, _)| *sequence)
        .unwrap_or_else(|| panic!("post-cancellation task settlement is absent"));
    assert!(cancellation_sequence < first_settlement);

    let JournalPrefixV1::Full(full) = &prefix else {
        unreachable!("in-memory journal retains its full prefix")
    };
    let cancellation = graph_entries
        .iter()
        .find(|(sequence, _)| *sequence == cancellation_sequence)
        .unwrap_or_else(|| panic!("cancellation graph evidence is absent"));
    let legacy = ConcurrentDurableEvidenceV4::new(
        DurableCommitCutV1::Cancellation,
        cancellation.1.task_id(),
        cancellation.1.checkpoint().clone(),
    )
    .unwrap_or_else(|error| panic!("legacy cancellation fixture failed: {error:?}"));
    let mut evidence = full.evidence.to_vec();
    let envelope = evidence
        .iter_mut()
        .find(|entry| entry.sequence == cancellation_sequence)
        .unwrap_or_else(|| panic!("cancellation envelope is absent"));
    envelope.kind = Arc::from(CONCURRENT_DURABLE_EVIDENCE_KIND_V4);
    envelope.canonical_body = Arc::from(legacy.canonical_body());
    let untyped = JournalPrefixV1::Full(gantry::host::journal::FullJournalPrefixV1 {
        journal_id: full.journal_id.clone(),
        evidence: Arc::from(evidence),
        committed_through: full.committed_through,
    });
    assert_eq!(
        recover_concurrent_authoritative_prefix(program, &untyped).map(|_| ()),
        Err(gantry::runtime::DurableEvidenceError::UnsupportedConcurrentCancellation)
    );
}

#[test]
fn durable_graph_owner_releases_after_physical_quiescence_and_finite_events() {
    let root = TempDirectory::new("fn main() { spawn child -> Int { 7 } discard join(child); }");
    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    let integration = Arc::new(ScriptedIntegration::new(
        [
            ScriptedPreflight::success(
                EmbeddingOperation::ResolveSessions,
                &br#"{"result":"resolved"}"#[..],
            ),
            ScriptedPreflight::success(
                EmbeddingOperation::EstablishSession,
                &br#"{"result":"established"}"#[..],
            ),
            ScriptedPreflight::success(
                EmbeddingOperation::EstablishSession,
                &br#"{"result":"established"}"#[..],
            ),
        ],
        [],
    ));
    let sink = Arc::new(RecordingSink::new(
        Arc::clone(&executor),
        DeliveryOutcome::Success,
    ));
    let interpreter = interpreter_with_delivery(
        Arc::clone(&executor),
        integration,
        8,
        65_536,
        plan(SinkClass::BestEffort, sink.clone()),
    );
    let storage = Arc::new(CountingJournalStore::default());
    let journal_id = JournalId::new("durable-source-spawn-owner-quiescence")
        .unwrap_or_else(|error| panic!("journal identity failed: {error:?}"));
    executor.poll_next_spawn_immediately();
    let accepted = durable_accepted(&interpreter, &root, storage.clone(), journal_id);
    let handle = accepted.handle().clone();

    let snapshot = drive_to_terminal(&executor, &interpreter, &handle);
    assert!(snapshot.terminal.is_some());
    let finalizer_task = *executor
        .task_ids()
        .last()
        .unwrap_or_else(|| panic!("terminal graph submitted no finalizer"));
    assert_eq!(storage.release_count(), 0);
    assert!(
        sink.events()
            .iter()
            .all(|record| record.event.kind() != EventKind::TerminalExecution)
    );
    assert!(matches!(
        executor.poll_task(finalizer_task),
        Ok(DeterministicTaskPoll::Settled(_))
    ));
    assert_eq!(storage.release_count(), 1);
    assert!(
        sink.events()
            .iter()
            .any(|record| record.event.kind() == EventKind::TerminalExecution)
    );
}

#[test]
fn public_durable_recovery_recognizes_execution_start_followed_by_graph_evidence() {
    let root = TempDirectory::new("fn main() { spawn child -> Int { 7 } discard join(child); }");
    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    let integration = Arc::new(ScriptedIntegration::new(
        [
            ScriptedPreflight::success(
                EmbeddingOperation::ResolveSessions,
                &br#"{"result":"resolved"}"#[..],
            ),
            ScriptedPreflight::success(
                EmbeddingOperation::EstablishSession,
                &br#"{"result":"established"}"#[..],
            ),
        ],
        [],
    ));
    let interpreter = interpreter_with_delivery(
        Arc::clone(&executor),
        integration,
        8,
        65_536,
        SinkPlan::default(),
    );
    let storage = Arc::new(InMemoryJournalStore::new());
    let storage_adapter: Arc<dyn JournalStorage> = storage.clone();
    let journal_id = JournalId::new("durable-source-spawn-public-recovery")
        .unwrap_or_else(|error| panic!("journal identity failed: {error:?}"));

    executor.poll_next_spawn_immediately();
    let accepted = durable_accepted(&interpreter, &root, storage.clone(), journal_id.clone());
    let execution_id = accepted.execution_id();
    executor.poll_next_spawn_immediately();
    assert!(matches!(
        executor.poll_task(0),
        Ok(DeterministicTaskPoll::Pending)
    ));

    let prefix = block_on(storage.read_prefix(ReadJournalPrefixV1 {
        journal_id: journal_id.clone(),
    }))
    .unwrap_or_else(|error| panic!("journal read failed: {error:?}"));
    let JournalPrefixV1::Full(full) = &prefix else {
        panic!("in-memory journal returned a compacted prefix")
    };
    assert_eq!(full.evidence[0].kind.as_ref(), "gantry.execution-start/v3");
    assert!(
        full.evidence
            .iter()
            .skip(1)
            .any(|entry| entry.kind.as_ref() == CONCURRENT_DURABLE_EVIDENCE_KIND_V4)
    );
    let (_, graph_entries) = durable_graph_entries(&prefix);
    let latest_graph_cut = graph_entries
        .last()
        .map(|(_, evidence)| evidence.cut())
        .unwrap_or_else(|| panic!("mixed prefix omitted graph evidence"));

    let lifecycle = DurableLifecycleCoordinator::new(Arc::clone(&storage_adapter));
    let queried = block_on(lifecycle.query(DurableQueryExecutionRequest {
        journal_id: journal_id.clone(),
        expected_execution_id: Some(execution_id),
    }));
    let DurableQueryExecutionResult::Snapshot(observation) = queried else {
        panic!("mixed-prefix public query did not return a snapshot: {queried:?}")
    };
    assert_eq!(observation.execution_id, execution_id);
    assert_eq!(observation.latest_sequence, full.committed_through);
    assert_eq!(
        observation.latest_evidence_id,
        full.evidence
            .last()
            .unwrap_or_else(|| panic!("mixed prefix is empty"))
            .evidence_id
    );
    let opened = block_on(lifecycle.open_owned_execution(
        journal_id.clone(),
        accepted.test_ownership_token().clone(),
        accepted.handle().clone(),
        execution_id,
    ));
    let Err(DurableOwnedExecutionOpenError::RunnableReplacementUnavailable(opened)) = opened else {
        panic!("mixed-prefix public open was not classified")
    };
    assert_eq!(opened.execution_id, execution_id);
    assert_eq!(opened.latest_sequence, observation.latest_sequence);
    assert_eq!(opened.latest_evidence_id, observation.latest_evidence_id);
    assert_eq!(opened.latest_cut, latest_graph_cut);
    assert_eq!(
        block_on(storage.release_owner(ReleaseJournalOwnerV1 {
            journal_id: journal_id.clone(),
            ownership_token: accepted.test_ownership_token().clone(),
        })),
        Ok(())
    );

    let resume_executor = Arc::new(DeterministicConcurrentExecutor::default());
    let resume_integration = Arc::new(ScriptedIntegration::new([], []));
    let resumed = interpreter_with_delivery(
        Arc::clone(&resume_executor),
        resume_integration,
        8,
        65_536,
        SinkPlan::default(),
    );
    let selection = selection();
    let mut resume = pin!(resumed.resume_durable_execution(
        Arc::clone(&storage_adapter),
        DurableResumeExecutionRequest {
            journal_id: journal_id.clone(),
            protocol_selection: &selection,
            candidate_package_root: None,
            expected_execution_id: Some(execution_id),
            event_delivery: None,
        },
    ));
    assert!(
        resume
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    assert_eq!(resume_executor.task_ids(), [0]);
    assert!(matches!(
        resume_executor.poll_task(0),
        Ok(DeterministicTaskPoll::Settled(_))
    ));
    let resumed = match resume
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(result) => result,
        Poll::Pending => panic!("completed mixed-prefix resume was not published"),
    };
    let DurableResumeExecutionResult::RunnableReplacementUnavailable(classification) = resumed
    else {
        panic!("mixed-prefix public resume was not classified: {resumed:?}")
    };
    assert_eq!(classification.journal_id, journal_id);
    assert_eq!(classification.recovery.execution_id, execution_id);
    assert_eq!(
        classification.recovery.latest_sequence,
        observation.latest_sequence
    );
    assert_eq!(
        classification.recovery.latest_evidence_id,
        observation.latest_evidence_id
    );
    assert_eq!(classification.recovery.latest_cut, latest_graph_cut);
    assert!(classification.release_error.is_none());
    assert_eq!(
        block_on(storage.read_prefix(ReadJournalPrefixV1 {
            journal_id: journal_id.clone(),
        }))
        .unwrap_or_else(|error| panic!("journal reread failed: {error:?}")),
        prefix
    );

    let JournalPrefixV1::Full(full) = &prefix else {
        unreachable!("the fixture retains its full prefix")
    };
    let program = DurableExecutionStartV3::retained_program(&full.evidence[0].canonical_body)
        .unwrap_or_else(|error| panic!("retained program failed to decode: {error:?}"));
    let compacted = ConcurrentDurableRecoverySnapshotV1::from_full_prefix(&program, full)
        .unwrap_or_else(|error| panic!("concurrent compaction failed: {error:?}"));
    let snapshot = JournalPrefixV1::Snapshot(SnapshotJournalPrefixV1 {
        journal_id: journal_id.clone(),
        snapshot_version: 7,
        frontier: compacted.frontier(),
        canonical_snapshot: Arc::from(compacted.canonical_body()),
        retained_evidence: compacted.retained_evidence().clone(),
        suffix: Arc::from([]),
        committed_through: compacted.frontier(),
    });

    let snapshot_storage: Arc<dyn JournalStorage> =
        Arc::new(FixedPrefixJournalStore::new(snapshot.clone()));
    let snapshot_lifecycle = DurableLifecycleCoordinator::new(Arc::clone(&snapshot_storage));
    let queried = block_on(snapshot_lifecycle.query(DurableQueryExecutionRequest {
        journal_id: journal_id.clone(),
        expected_execution_id: Some(execution_id),
    }));
    let DurableQueryExecutionResult::Snapshot(snapshot_observation) = queried else {
        panic!("compacted public query did not recover the graph: {queried:?}")
    };
    assert_eq!(snapshot_observation.execution_id, execution_id);
    assert_eq!(
        snapshot_observation.latest_sequence,
        observation.latest_sequence
    );
    assert_eq!(
        snapshot_observation.latest_evidence_id,
        observation.latest_evidence_id
    );
    assert_eq!(
        snapshot_observation.required_delivery_failures,
        observation.required_delivery_failures
    );

    let opened = block_on(snapshot_lifecycle.open_owned_execution(
        journal_id.clone(),
        accepted.test_ownership_token().clone(),
        accepted.handle().clone(),
        execution_id,
    ));
    let Err(DurableOwnedExecutionOpenError::RunnableReplacementUnavailable(opened)) = opened else {
        panic!("compacted public open did not classify graph replacement")
    };
    assert_eq!(opened.execution_id, execution_id);
    assert_eq!(opened.latest_sequence, observation.latest_sequence);
    assert_eq!(opened.latest_evidence_id, observation.latest_evidence_id);
    assert_eq!(opened.latest_cut, latest_graph_cut);

    let resume_executor = Arc::new(DeterministicConcurrentExecutor::default());
    let resumed = interpreter_with_delivery(
        Arc::clone(&resume_executor),
        Arc::new(ScriptedIntegration::new([], [])),
        8,
        65_536,
        SinkPlan::default(),
    );
    let mut resume = pin!(resumed.resume_durable_execution(
        Arc::clone(&snapshot_storage),
        DurableResumeExecutionRequest {
            journal_id: journal_id.clone(),
            protocol_selection: &selection,
            candidate_package_root: None,
            expected_execution_id: Some(execution_id),
            event_delivery: None,
        },
    ));
    assert!(
        resume
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    assert!(matches!(
        resume_executor.poll_task(0),
        Ok(DeterministicTaskPoll::Settled(_))
    ));
    let resumed = match resume
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(result) => result,
        Poll::Pending => panic!("compacted graph resume was not published"),
    };
    let DurableResumeExecutionResult::RunnableReplacementUnavailable(classification) = resumed
    else {
        panic!("compacted public resume was not classified: {resumed:?}")
    };
    assert_eq!(classification.journal_id, journal_id);
    assert_eq!(classification.recovery.execution_id, execution_id);
    assert_eq!(
        classification.recovery.latest_sequence,
        observation.latest_sequence
    );
    assert_eq!(
        classification.recovery.latest_evidence_id,
        observation.latest_evidence_id
    );
    assert_eq!(classification.recovery.latest_cut, latest_graph_cut);
    assert!(classification.release_error.is_none());
    assert_eq!(
        block_on(snapshot_storage.read_prefix(ReadJournalPrefixV1 {
            journal_id: journal_id.clone(),
        }))
        .unwrap_or_else(|error| panic!("snapshot reread failed: {error:?}")),
        snapshot
    );
}

#[test]
fn durable_abnormal_child_completion_commits_exact_executor_failure() {
    let root = TempDirectory::new("fn main() { spawn child -> Int { 7 } discard join(child); }");
    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    let integration = Arc::new(ScriptedIntegration::new(
        [
            ScriptedPreflight::success(
                EmbeddingOperation::ResolveSessions,
                &br#"{"result":"resolved"}"#[..],
            ),
            ScriptedPreflight::success(
                EmbeddingOperation::EstablishSession,
                &br#"{"result":"established"}"#[..],
            ),
        ],
        [],
    ));
    let interpreter = interpreter_with_delivery(
        Arc::clone(&executor),
        integration,
        8,
        65_536,
        SinkPlan::default(),
    );
    let storage = Arc::new(InMemoryJournalStore::new());
    let journal_id = JournalId::new("durable-source-spawn-abnormal-child")
        .unwrap_or_else(|error| panic!("journal identity failed: {error:?}"));

    executor.poll_next_spawn_immediately();
    let accepted = durable_accepted(&interpreter, &root, storage.clone(), journal_id.clone());
    let execution_id = accepted.execution_id();
    assert!(matches!(
        executor.poll_task(0),
        Ok(DeterministicTaskPoll::Pending)
    ));
    assert_eq!(executor.task_ids(), [0, 1]);

    let creation_prefix = block_on(storage.read_prefix(ReadJournalPrefixV1 {
        journal_id: journal_id.clone(),
    }))
    .unwrap_or_else(|error| panic!("creation journal read failed: {error:?}"));
    let (_, creation_entries) = durable_graph_entries(&creation_prefix);
    let child_id = creation_entries
        .iter()
        .find(|(_, evidence)| evidence.cut() == DurableCommitCutV1::TaskCreation)
        .map(|(_, evidence)| evidence.task_id())
        .unwrap_or_else(|| panic!("task-creation graph cut is absent"));

    executor
        .fail_task(1)
        .unwrap_or_else(|error| panic!("child executor failure injection failed: {error:?}"));
    assert_eq!(executor.task_ids(), [0, 1, 2]);
    assert!(matches!(
        executor.poll_task(2),
        Ok(DeterministicTaskPoll::Pending)
    ));

    let observation = block_on(interpreter.test_durable_observation(execution_id))
        .unwrap_or_else(|| panic!("durable execution observation is absent"));
    assert!(observation.run_failure.is_none());
    assert_eq!(observation.owner, Some(DurableJournalOwnerState::Held));

    let prefix = block_on(storage.read_prefix(ReadJournalPrefixV1 {
        journal_id: journal_id.clone(),
    }))
    .unwrap_or_else(|error| panic!("settlement journal read failed: {error:?}"));
    let (program, graph_entries) = durable_graph_entries(&prefix);
    let settlement = graph_entries
        .iter()
        .find(|(_, evidence)| {
            evidence.cut() == DurableCommitCutV1::TaskSettlement && evidence.task_id() == child_id
        })
        .unwrap_or_else(|| panic!("exact abnormal child settlement is absent"));
    assert_eq!(
        settlement.1.checkpoint().task_status(child_id),
        Some(TaskStatusKind::Failed)
    );
    let recovered = recover_concurrent_authoritative_prefix(program, &prefix)
        .unwrap_or_else(|error| panic!("abnormal child prefix failed recovery: {error:?}"));
    let state = recovered.execution().scheduler().state();
    let child = state
        .task(child_id)
        .unwrap_or_else(|| panic!("abnormally completed child is absent"));
    assert!(matches!(
        child.status(),
        ConcurrentTaskStatusV1::Failed(failure)
            if failure.category == RuntimeErrorCategory::ExecutorFailure
                && failure.code.as_ref() == "executor-failure"
    ));
    assert_eq!(
        state
            .task_record(child_id)
            .map(|record| record.driver_ownership()),
        Some(TaskDriverOwnershipV1::PhysicallySettled)
    );
}

#[test]
fn durable_graph_journal_failure_drains_before_release_and_failure_publication() {
    let root = TempDirectory::new("fn main() { spawn child -> Int { 7 } discard join(child); }");
    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    let integration = Arc::new(ScriptedIntegration::new(
        [
            ScriptedPreflight::success(
                EmbeddingOperation::ResolveSessions,
                &br#"{"result":"resolved"}"#[..],
            ),
            ScriptedPreflight::success(
                EmbeddingOperation::EstablishSession,
                &br#"{"result":"established"}"#[..],
            ),
            ScriptedPreflight::success(
                EmbeddingOperation::EstablishSession,
                &br#"{"result":"established"}"#[..],
            ),
        ],
        [],
    ));
    let interpreter = interpreter_with_delivery(
        Arc::clone(&executor),
        integration,
        8,
        65_536,
        SinkPlan::default(),
    );
    let storage = Arc::new(FailingGraphJournalStore::new(Arc::clone(&executor)));
    let journal_id = JournalId::new("durable-source-spawn-graph-journal-failure")
        .unwrap_or_else(|error| panic!("journal identity failed: {error:?}"));

    executor.poll_next_spawn_immediately();
    let accepted = durable_accepted(&interpreter, &root, storage.clone(), journal_id.clone());
    let execution_id = accepted.execution_id();
    storage.observe_cancellation(
        accepted
            .handle()
            .cancellation_signal()
            .unwrap_or_else(|error| panic!("cancellation signal failed: {error:?}")),
    );
    for _ in 0..8 {
        if executor.task_ids().len() >= 2 {
            break;
        }
        if executor.is_runnable(0) {
            assert!(matches!(
                executor.poll_task(0),
                Ok(DeterministicTaskPoll::Pending
                    | DeterministicTaskPoll::NotRunnable
                    | DeterministicTaskPoll::Settled(_))
            ));
        }
    }
    assert!(executor.task_ids().starts_with(&[0, 1]));
    for _ in 0..8 {
        if executor.task_ids().len() >= 3 {
            break;
        }
        if executor.is_runnable(1) {
            assert!(matches!(
                executor.poll_task(1),
                Ok(DeterministicTaskPoll::Pending | DeterministicTaskPoll::Settled(_))
            ));
        }
    }
    assert_eq!(executor.task_ids(), [0, 1, 2]);
    assert!(matches!(
        executor.poll_task(2),
        Ok(DeterministicTaskPoll::Pending)
    ));

    assert!(storage.release_started());
    assert_eq!(storage.release_count(), 1);
    assert!(storage.release_saw_cancelled());
    assert!(storage.release_saw_graph_tasks_settled());
    assert!(matches!(
        executor.poll_task(1),
        Ok(DeterministicTaskPoll::Stopped)
    ));
    let fenced_prefix = block_on(storage.read_prefix(ReadJournalPrefixV1 {
        journal_id: journal_id.clone(),
    }))
    .unwrap_or_else(|error| panic!("fenced journal read failed: {error:?}"));
    let pending = block_on(interpreter.test_durable_observation(execution_id))
        .unwrap_or_else(|| panic!("pending durable observation is absent"));
    assert!(pending.run_failure.is_none());
    assert_eq!(pending.owner, Some(DurableJournalOwnerState::Held));

    storage.allow_release();
    assert!(matches!(
        executor.poll_task(2),
        Ok(DeterministicTaskPoll::Settled(_))
    ));
    let failed = block_on(interpreter.test_durable_observation(execution_id))
        .unwrap_or_else(|| panic!("failed durable observation is absent"));
    assert!(failed.run_failure.is_some());
    assert_eq!(failed.owner, Some(DurableJournalOwnerState::Released));
    assert_eq!(storage.release_count(), 1);
    assert_eq!(
        block_on(storage.read_prefix(ReadJournalPrefixV1 { journal_id }))
            .unwrap_or_else(|error| panic!("released journal read failed: {error:?}")),
        fenced_prefix
    );
}

#[test]
fn durable_child_submission_failure_settles_the_created_identity_before_parent_progress() {
    let root = TempDirectory::new("fn main() { spawn child -> Int { 7 } discard join(child); }");
    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    let integration = Arc::new(ScriptedIntegration::new(
        [
            ScriptedPreflight::success(
                EmbeddingOperation::ResolveSessions,
                &br#"{"result":"resolved"}"#[..],
            ),
            ScriptedPreflight::success(
                EmbeddingOperation::EstablishSession,
                &br#"{"result":"established"}"#[..],
            ),
        ],
        [],
    ));
    let interpreter = interpreter_with_delivery(
        Arc::clone(&executor),
        integration,
        8,
        65_536,
        SinkPlan::default(),
    );
    let storage = Arc::new(InMemoryJournalStore::new());
    let journal_id = JournalId::new("durable-source-spawn-rejected")
        .unwrap_or_else(|error| panic!("journal identity failed: {error:?}"));

    executor.poll_next_spawn_immediately();
    let accepted = durable_accepted(&interpreter, &root, storage.clone(), journal_id.clone());
    let handle = accepted.handle().clone();
    executor.fail_next_spawn();
    let snapshot = drive_to_terminal(&executor, &interpreter, &handle);
    assert!(snapshot.terminal.is_some());
    assert_eq!(executor.task_ids(), [0, 1]);
    assert_eq!(executor.poll_count(1), Some(0));

    let prefix = block_on(storage.read_prefix(ReadJournalPrefixV1 { journal_id }))
        .unwrap_or_else(|error| panic!("journal read failed: {error:?}"));
    let (program, graph_entries) = durable_graph_entries(&prefix);
    let creation = graph_entries
        .iter()
        .find(|(_, evidence)| evidence.cut() == DurableCommitCutV1::TaskCreation)
        .unwrap_or_else(|| panic!("task-creation graph cut is absent"));
    let child_id = creation.1.task_id();
    let child_settlement = graph_entries
        .iter()
        .find(|(_, evidence)| {
            evidence.cut() == DurableCommitCutV1::TaskSettlement && evidence.task_id() == child_id
        })
        .unwrap_or_else(|| panic!("same-child submission settlement is absent"));
    let root_settlement = graph_entries
        .iter()
        .find(|(_, evidence)| {
            evidence.cut() == DurableCommitCutV1::TaskSettlement
                && evidence.task_id() == evidence.checkpoint().root_task_id()
        })
        .unwrap_or_else(|| panic!("root settlement graph cut is absent"));
    assert!(creation.0 < child_settlement.0);
    assert!(child_settlement.0 < root_settlement.0);
    assert_eq!(
        child_settlement.1.checkpoint().task_status(child_id),
        Some(TaskStatusKind::Failed)
    );
    let JournalPrefixV1::Full(full) = &prefix else {
        panic!("in-memory journal returned a compacted prefix")
    };
    let settlement_envelope = full
        .evidence
        .iter()
        .find(|entry| entry.sequence == child_settlement.0)
        .unwrap_or_else(|| panic!("child settlement envelope is absent"));
    let child_completion = full
        .evidence
        .iter()
        .find(|entry| {
            entry.kind.as_ref() == DURABLE_EVENT_OCCURRENCE_KIND_V1
                && DurableEventOccurrenceV1::decode(&entry.canonical_body).is_ok_and(|occurrence| {
                    occurrence.event().kind() == EventKind::TaskCompletion
                        && occurrence.event().task_id() == Some(child_id)
                })
        })
        .unwrap_or_else(|| panic!("durable child submission completion event is absent"));
    assert_eq!(child_completion.sequence, child_settlement.0 + 1);
    assert!(child_completion.sequence < root_settlement.0);
    assert!(
        child_completion
            .references
            .contains(&settlement_envelope.evidence_id)
    );

    let recovered = recover_concurrent_authoritative_prefix(program, &prefix)
        .unwrap_or_else(|error| panic!("concurrent durable recovery failed: {error:?}"));
    let state = recovered.execution().scheduler().state();
    let child = state
        .task(child_id)
        .unwrap_or_else(|| panic!("failed durable child is absent"));
    assert!(matches!(
        child.status(),
        ConcurrentTaskStatusV1::Failed(failure)
            if failure.code.as_ref() == "task-submission-failure"
    ));
    assert!(child.handle_is_visible());
    assert!(!state.parent_is_suspended(state.root_task_id()));
}

fn interpreter_with_delivery(
    executor: Arc<DeterministicConcurrentExecutor>,
    integration: Arc<ScriptedIntegration>,
    source_child_capacity: u64,
    maximum_tasks_per_execution: u64,
    event_delivery: SinkPlan,
) -> Interpreter {
    interpreter_with_session_service(
        executor,
        integration.clone(),
        integration,
        source_child_capacity,
        maximum_tasks_per_execution,
        event_delivery,
    )
}

fn interpreter_with_session_service(
    executor: Arc<DeterministicConcurrentExecutor>,
    integration: Arc<ScriptedIntegration>,
    runtime_sessions: Arc<dyn RuntimeSessionService>,
    source_child_capacity: u64,
    maximum_tasks_per_execution: u64,
    event_delivery: SinkPlan,
) -> Interpreter {
    let executor_adapter: Arc<dyn ExecutorAdapter> = executor;
    let identities: Arc<dyn IdentitySource> = Arc::new(DeterministicIdentitySource::new(
        (1_u8..=192).map(|byte| Ok([byte; 32])),
    ));
    let required = RequiredConfiguration::new(
        FrontendLimits::new(
            32, 1_048_576, 4_194_304, 262_144, 256, 4_194_304, 4_194_304, 4_194_304, 4_194_304,
            256, 65_536, 1_000_000,
        )
        .unwrap_or_else(|error| panic!("frontend limits failed: {error:?}")),
        1_048_576,
        1_048_576,
        DEFAULT_VALUE_LIMITS,
        1_000_000,
        100_000,
        100_000,
        8,
    )
    .unwrap_or_else(|error| panic!("required configuration failed: {error}"));
    let capacities = AsyncCapacityLimits::new(8, source_child_capacity, 8, 8, 8, 8, 8, 8, 8)
        .unwrap_or_else(|error| panic!("capacity configuration failed: {error}"));
    let configuration =
        InterpreterConfiguration::new(executor_adapter, identities, required, capacities)
            .with_maximum_tasks_per_execution(maximum_tasks_per_execution)
            .unwrap_or_else(|error| panic!("task-limit configuration failed: {error}"));
    Interpreter::new_with_event_delivery(
        configuration,
        execution_clock(),
        integration.clone(),
        runtime_sessions,
        integration,
        Arc::new(ImmediateDeliveryRuntime),
        event_delivery,
    )
}

fn spawn_event(sink: &RecordingSink) -> RecordedEvent {
    sink.events()
        .into_iter()
        .find(|record| record.event.kind() == EventKind::Spawn)
        .unwrap_or_else(|| panic!("spawn event was not delivered"))
}

fn plan(class: SinkClass, sink: Arc<dyn EventSink>) -> SinkPlan {
    let retry = EventRetryPolicy::new("source-spawn-retry-v1", 0, 0, 0, JitterMode::None)
        .unwrap_or_else(|error| panic!("retry policy failed: {error:?}"));
    let policy = SinkDeliveryPolicy::new(
        class,
        false,
        "source-spawn-redaction-v1",
        RedactionCapabilities::default(),
        retry,
        30,
    )
    .unwrap_or_else(|error| panic!("sink policy failed: {error:?}"));
    SinkPlan::new(vec![SinkRegistration::new(
        SinkId::new("source-spawn-sink")
            .unwrap_or_else(|error| panic!("sink identity failed: {error:?}")),
        policy,
        sink,
    )])
    .unwrap_or_else(|error| panic!("sink plan failed: {error:?}"))
}

fn accepted(interpreter: &Interpreter, root: &TempDirectory) -> gantry::StartExecutionAccepted {
    let selection = selection();
    let root_session = RootSessionSpecification {
        id: ProtocolIdentity::from_fresh_material(IdentityKind::Session, [0xf0; 32])
            .unwrap_or_else(|error| panic!("session identity failed: {error}")),
        transcript: Some(b"{\"protocol\":{\"major\":1,\"minor\":0},\"turns\":[]}"),
        opaque_lookup_material: Some(b"source-spawn-test"),
    };
    let started = block_on(interpreter.start_execution(StartExecutionRequest {
        package_root: &root.0,
        protocol_selection: &selection,
        required_peers: &[],
        entry_input: None,
        root_session: Some(root_session),
        event_delivery: None,
    }));
    let StartExecutionResult::Accepted(accepted) = started else {
        panic!("valid source-spawn fixture was rejected: {started:?}")
    };
    *accepted
}

fn durable_accepted(
    interpreter: &Interpreter,
    root: &TempDirectory,
    storage: Arc<dyn JournalStorage>,
    journal_id: JournalId,
) -> Box<DurableStartExecutionAccepted> {
    let selection = selection();
    match block_on(interpreter.start_durable_execution(
        storage,
        DurableStartExecutionRequest {
            journal_id,
            start: StartExecutionRequest {
                package_root: &root.0,
                protocol_selection: &selection,
                required_peers: &[],
                entry_input: None,
                root_session: None,
                event_delivery: None,
            },
        },
    )) {
        DurableStartExecutionResult::Accepted(accepted) => accepted,
        DurableStartExecutionResult::Rejected(failure) => {
            panic!("valid durable source-spawn fixture was rejected: {failure:?}")
        }
    }
}

enum ConcurrentDurableEvidence {
    V4(Box<ConcurrentDurableEvidenceV4>),
    V5(Box<ConcurrentDurableEvidenceV5>),
}

impl ConcurrentDurableEvidence {
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

    fn checkpoint(&self) -> &ConcurrentDurableCheckpointV4 {
        match self {
            Self::V4(evidence) => evidence.checkpoint(),
            Self::V5(evidence) => evidence.checkpoint(),
        }
    }

    fn has_operation(&self) -> bool {
        matches!(self, Self::V5(evidence) if evidence.operation().is_some())
    }
}

fn durable_graph_entries(
    prefix: &JournalPrefixV1,
) -> (
    Arc<gantry::runtime::MachineProgram>,
    Vec<(u64, ConcurrentDurableEvidence)>,
) {
    let JournalPrefixV1::Full(full) = prefix else {
        panic!("in-memory journal returned a compacted prefix")
    };
    let first = full
        .evidence
        .first()
        .unwrap_or_else(|| panic!("durable prefix is empty"));
    let program = Arc::new(
        DurableExecutionStartV3::retained_program(&first.canonical_body)
            .unwrap_or_else(|error| panic!("retained program failed to decode: {error:?}")),
    );
    let entries = full
        .evidence
        .iter()
        .filter(|entry| {
            matches!(
                entry.kind.as_ref(),
                CONCURRENT_DURABLE_EVIDENCE_KIND_V4 | CONCURRENT_DURABLE_EVIDENCE_KIND_V5
            )
        })
        .map(|entry| {
            let body = String::from_utf8_lossy(&entry.canonical_body);
            let cut = body
                .split("\"cut\":\"")
                .nth(1)
                .and_then(|suffix| suffix.split('"').next())
                .unwrap_or("unknown");
            (
                entry.sequence,
                if entry.kind.as_ref() == CONCURRENT_DURABLE_EVIDENCE_KIND_V4 {
                    ConcurrentDurableEvidenceV4::decode(&program, &entry.canonical_body)
                        .map(Box::new)
                        .map(ConcurrentDurableEvidence::V4)
                } else {
                    ConcurrentDurableEvidenceV5::decode(&program, &entry.canonical_body)
                        .map(Box::new)
                        .map(ConcurrentDurableEvidence::V5)
                }
                .unwrap_or_else(|error| {
                    panic!(
                        "graph evidence at sequence {} ({cut}) failed to decode: {error:?}",
                        entry.sequence,
                    )
                }),
            )
        })
        .collect();
    (program, entries)
}

fn drive_to_terminal(
    executor: &DeterministicConcurrentExecutor,
    interpreter: &Interpreter,
    handle: &gantry::runtime::ExecutionHandle,
) -> gantry::runtime::ExecutionSnapshot {
    let mut latest = None;
    for _ in 0..1_000 {
        if let Some(snapshot) = interpreter
            .query_execution(handle.execution_id())
            .unwrap_or_else(|error| panic!("execution query failed: {error:?}"))
        {
            if snapshot.terminal.is_some() {
                return snapshot;
            }
            latest = Some(snapshot);
        }
        let task_ids = executor.task_ids();
        let mut progressed = false;
        for task_id in task_ids {
            if !executor.is_runnable(task_id) {
                continue;
            }
            progressed = true;
            match executor
                .poll_task(task_id)
                .unwrap_or_else(|error| panic!("task {task_id} poll failed: {error:?}"))
            {
                DeterministicTaskPoll::Pending
                | DeterministicTaskPoll::NotRunnable
                | DeterministicTaskPoll::Settled(_) => {}
                other => panic!("task {task_id} settled abnormally: {other:?}"),
            }
        }
        if !progressed {
            std::thread::yield_now();
        }
    }
    let tasks = executor
        .task_ids()
        .into_iter()
        .map(|task_id| {
            (
                task_id,
                executor.poll_count(task_id),
                executor.wake_count(task_id),
                executor.is_runnable(task_id),
            )
        })
        .collect::<Vec<_>>();
    panic!(
        "source-spawn execution did not reach terminal state; latest={latest:?}; tasks={tasks:?}"
    )
}

fn selection() -> ProtocolSelection {
    ProtocolSelection::new(
        PORTABLE_SPECIFICATION_REVISION,
        PROTOCOL_FAMILY_DEFINITIONS
            .iter()
            .map(|definition| SelectedProtocol {
                family: definition.family,
                version: ProtocolVersion {
                    major: definition.major,
                    minor: definition.minor,
                },
            })
            .collect(),
    )
    .unwrap_or_else(|error| panic!("selection failed: {error}"))
}

fn execution_clock() -> Arc<DeterministicUtcClock> {
    Arc::new(DeterministicUtcClock::new((1_u32..=128).map(
        |microseconds| {
            UtcTimestamp::from_unix_seconds(0, microseconds).map_err(|_| {
                gantry::host::contracts::HostError {
                    code: Arc::from("clock-invariant"),
                    protected_diagnostic: None,
                }
            })
        },
    )))
}

fn block_on<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    let mut future = pin!(future);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => return output,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
