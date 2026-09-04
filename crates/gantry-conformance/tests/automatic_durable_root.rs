//! Public conformance for automatic sequential-durable root ownership.

use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use gantry::host::contracts::{
    CancellationToken, ExecutorAdapter, HookFactory, HookOutcomeV1, HostError, HostFuture,
    HostRequest, HostResponse, IdentitySource, IntegrationPreflight, JournalStorage, OperationHook,
    RuntimeSessionService,
};
use gantry::host::embedding::EmbeddingOperation;
use gantry::host::event::{
    EventDeliveryRequest, EventDeliveryRuntime, EventRetryPolicy, EventSink, RedactionCapabilities,
    SinkDeliveryPolicy, SinkId,
};
use gantry::host::journal::{
    AcquireJournalOwnerV1, JournalCommitReceiptV1, JournalCommitRequestV1, JournalError,
    JournalErrorCode, JournalId, JournalOwnershipV1, JournalPrefixV1, ReadJournalPrefixV1,
    ReleaseJournalOwnerV1, ResolveJournalPayloadV1, ResolvedJournalPayloadV1,
};
use gantry::observe::{SinkPlan, SinkRegistration};
use gantry::portable::{
    DeliveryOutcome, EventKind, ExecutionObservationState, JitterMode,
    PORTABLE_SPECIFICATION_REVISION, PROTOCOL_FAMILY_DEFINITIONS, RuntimeErrorCategory, SinkClass,
};
use gantry::protocol::{ProtocolSelection, ProtocolVersion, SelectedProtocol};
use gantry::runtime::{
    AsyncCapacityLimits, CancellationRecord, DURABLE_EVENT_DISPATCHED_KIND_V1,
    DURABLE_EVENT_SETTLED_KIND_V1, DurableCommitCutV1, DurableEventDispatchedV1,
    DurableEventOccurrenceV1, DurableEventSettledV1, DurableLogicalEvidenceV1,
    InMemoryJournalStore, InterpreterConfiguration, MachineOutcome, RequiredConfiguration,
    RuntimeCode, recover_authoritative_prefix_with_retained_program,
};
use gantry::source::FrontendLimits;
use gantry::timestamp::UtcTimestamp;
use gantry::value::{DEFAULT_VALUE_LIMITS, LogicalValueView};
use gantry::{
    DurableHandoffTestGate, DurableResumeExecutionRequest, DurableResumeExecutionResult,
    DurableStartExecutionRequest, DurableStartExecutionResult, Interpreter, StartExecutionRequest,
    caller_cancellation_reason,
};
use gantry_conformance::concurrent_executor::{
    DeterministicConcurrentExecutor, DeterministicTaskPoll,
};
use gantry_conformance::scripted::{ScriptedHook, ScriptedIntegration, ScriptedPreflight};
use gantry_conformance::services::{DeterministicIdentitySource, DeterministicUtcClock};
use serde::Deserialize;

const AUTOMATIC_PROGRESS_EVIDENCE: &str = "crates/gantry-conformance/tests/automatic_durable_root.rs#accepted_durable_root_runs_on_the_executor_and_commits_before_observation";
const COMMIT_FAILURE_EVIDENCE: &str = "crates/gantry-conformance/tests/automatic_durable_root.rs#durable_commit_failure_reports_run_failure_and_preserves_sequence_one";
const OPERATION_EVIDENCE: &str = "crates/gantry-conformance/tests/automatic_durable_root.rs#durable_operation_cuts_commit_before_dispatch_and_source_consumption";
const SESSION_EVIDENCE: &str = "crates/gantry-conformance/tests/automatic_durable_root.rs#durable_lexical_session_state_commits_before_source_progress";
const SUBMISSION_FAILURE_EVIDENCE: &str = "crates/gantry-conformance/tests/automatic_durable_root.rs#durable_submission_failure_commits_terminal_root_failure_after_acceptance";

#[derive(Debug, Deserialize)]
struct EvidenceManifest {
    format: String,
    specification_sha256: String,
    issue: String,
    requirements: Vec<RequirementEvidence>,
    capabilities: Vec<CapabilityEvidence>,
    exclusions: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
struct RequirementEvidence {
    requirement: String,
    clause: String,
    profiles: Vec<String>,
}

#[derive(Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
struct CapabilityEvidence {
    id: String,
    evidence: String,
}

#[derive(Debug, Deserialize)]
struct ContractGate {
    requirement_assignments: Vec<RequirementAssignment>,
}

#[derive(Debug, Deserialize)]
struct RequirementAssignment {
    requirement: String,
    clause: String,
    profiles: Vec<String>,
    evidence_owners: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RequirementReview {
    specification_sha256: String,
}

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TempDirectory(PathBuf);

impl TempDirectory {
    fn new(source: &str) -> Self {
        let suffix = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "gantry-automatic-durable-root-{}-{suffix}",
            std::process::id()
        ));
        fs::create_dir(&path)
            .unwrap_or_else(|error| panic!("could not create {}: {error}", path.display()));
        fs::write(path.join("main.gnt"), source)
            .unwrap_or_else(|error| panic!("could not write durable fixture: {error}"));
        Self(path)
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[derive(Default)]
struct FailAfterStartStore {
    inner: InMemoryJournalStore,
    commits: AtomicU64,
    releases: AtomicU64,
}

impl FailAfterStartStore {
    fn release_count(&self) -> u64 {
        self.releases.load(Ordering::Acquire)
    }
}

impl JournalStorage for FailAfterStartStore {
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
        if self.commits.fetch_add(1, Ordering::AcqRel) == 0 {
            self.inner.commit(request)
        } else {
            Box::pin(async { Err(JournalError::new(JournalErrorCode::Internal)) })
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
        self.releases.fetch_add(1, Ordering::AcqRel);
        self.inner.release_owner(request)
    }
}

struct ObservedJournalStore {
    inner: InMemoryJournalStore,
    committed: Mutex<Vec<(String, Vec<u8>)>>,
    settled_commits: AtomicU64,
    settlement_gate_ordinal: u64,
    settlement_commit_started: AtomicBool,
    settlement_commit_released: AtomicBool,
    settlement_commit_waker: Mutex<Option<Waker>>,
    post_commit_settlement_gate: bool,
    post_commit_settlement_started: AtomicBool,
    post_commit_settlement_released: AtomicBool,
    post_commit_settlement_waker: Mutex<Option<Waker>>,
    releases: AtomicU64,
}

impl ObservedJournalStore {
    fn with_settlement_gate(settlement_gate_ordinal: u64) -> Self {
        Self {
            inner: InMemoryJournalStore::new(),
            committed: Mutex::new(Vec::new()),
            settled_commits: AtomicU64::new(0),
            settlement_gate_ordinal,
            settlement_commit_started: AtomicBool::new(false),
            settlement_commit_released: AtomicBool::new(false),
            settlement_commit_waker: Mutex::new(None),
            post_commit_settlement_gate: false,
            post_commit_settlement_started: AtomicBool::new(false),
            post_commit_settlement_released: AtomicBool::new(false),
            post_commit_settlement_waker: Mutex::new(None),
            releases: AtomicU64::new(0),
        }
    }

    fn with_post_commit_settlement_gate(settlement_gate_ordinal: u64) -> Self {
        Self {
            post_commit_settlement_gate: true,
            ..Self::with_settlement_gate(settlement_gate_ordinal)
        }
    }

    fn latest_committed(&self) -> Option<(String, Vec<u8>)> {
        self.committed
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .last()
            .cloned()
    }

    fn settlement_commit_started(&self) -> bool {
        self.settlement_commit_started.load(Ordering::Acquire)
    }

    fn release_settlement_commit(&self) {
        self.settlement_commit_released
            .store(true, Ordering::Release);
        if let Some(waker) = self
            .settlement_commit_waker
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            waker.wake();
        }
    }

    fn post_commit_settlement_started(&self) -> bool {
        self.post_commit_settlement_started.load(Ordering::Acquire)
    }

    fn release_post_commit_settlement(&self) {
        self.post_commit_settlement_released
            .store(true, Ordering::Release);
        if let Some(waker) = self
            .post_commit_settlement_waker
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            waker.wake();
        }
    }

    fn release_count(&self) -> u64 {
        self.releases.load(Ordering::Acquire)
    }
}

impl JournalStorage for ObservedJournalStore {
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
        let committed = request
            .batch
            .evidence
            .iter()
            .map(|evidence| (evidence.kind.to_string(), evidence.canonical_body.to_vec()))
            .collect::<Vec<_>>();
        let is_settlement = committed
            .iter()
            .any(|(kind, _)| kind == DURABLE_EVENT_SETTLED_KIND_V1);
        let gate = is_settlement
            && self.settled_commits.fetch_add(1, Ordering::AcqRel) + 1
                == self.settlement_gate_ordinal;
        Box::pin(async move {
            if gate && !self.post_commit_settlement_gate {
                self.settlement_commit_started
                    .store(true, Ordering::Release);
                std::future::poll_fn(|context| {
                    if self.settlement_commit_released.load(Ordering::Acquire) {
                        return Poll::Ready(());
                    }
                    *self
                        .settlement_commit_waker
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner()) =
                        Some(context.waker().clone());
                    Poll::Pending
                })
                .await;
            }
            let result = self.inner.commit(request).await;
            if result.is_ok() {
                self.committed
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .extend(committed);
            }
            if gate && self.post_commit_settlement_gate && result.is_ok() {
                self.post_commit_settlement_started
                    .store(true, Ordering::Release);
                std::future::poll_fn(|context| {
                    if self.post_commit_settlement_released.load(Ordering::Acquire) {
                        return Poll::Ready(());
                    }
                    *self
                        .post_commit_settlement_waker
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner()) =
                        Some(context.waker().clone());
                    Poll::Pending
                })
                .await;
            }
            result
        })
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

#[derive(Default)]
struct DeliveryGate {
    calls: AtomicU64,
    released: AtomicBool,
    waker: Mutex<Option<Waker>>,
}

impl DeliveryGate {
    fn calls(&self) -> u64 {
        self.calls.load(Ordering::Acquire)
    }

    fn release(&self) {
        self.released.store(true, Ordering::Release);
        if let Some(waker) = self
            .waker
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            waker.wake();
        }
    }

    async fn wait(&self) {
        std::future::poll_fn(|context| {
            if self.released.load(Ordering::Acquire) {
                return Poll::Ready(());
            }
            *self
                .waker
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(context.waker().clone());
            Poll::Pending
        })
        .await;
    }
}

struct DurableEvidenceSink {
    storage: Arc<ObservedJournalStore>,
    terminal_gate: Option<Arc<DeliveryGate>>,
}

impl EventSink for DurableEvidenceSink {
    fn deliver<'a>(
        &'a self,
        request: EventDeliveryRequest,
    ) -> HostFuture<'a, Result<DeliveryOutcome, HostError>> {
        if request.event.execution_id().is_some() {
            let (kind, body) = self
                .storage
                .latest_committed()
                .unwrap_or_else(|| panic!("durable sink callback preceded journal evidence"));
            assert_eq!(kind, DURABLE_EVENT_DISPATCHED_KIND_V1);
            let dispatched = DurableEventDispatchedV1::decode(&body)
                .unwrap_or_else(|error| panic!("dispatch evidence did not decode: {error:?}"));
            assert_eq!(dispatched.event_id(), request.event.event_id());
            assert_eq!(dispatched.attempt_id(), request.attempt_id);
            assert_eq!(dispatched.retry_number(), request.retry_number);
        }
        let terminal_gate = self.terminal_gate.clone();
        Box::pin(async move {
            if request.event.kind() == EventKind::TerminalExecution
                && let Some(gate) = terminal_gate
            {
                gate.calls.fetch_add(1, Ordering::AcqRel);
                gate.wait().await;
            }
            Ok(DeliveryOutcome::Success)
        })
    }
}

#[derive(Default)]
struct ImmediateDurableDeliveryRuntime;

impl EventDeliveryRuntime for ImmediateDurableDeliveryRuntime {
    fn deliver_with_timeout<'a>(
        &'a self,
        sink: &'a dyn EventSink,
        request: EventDeliveryRequest,
        _: u64,
    ) -> HostFuture<'a, Result<DeliveryOutcome, HostError>> {
        sink.deliver(request)
    }

    fn sleep<'a>(&'a self, _: u64) -> HostFuture<'a, Result<(), HostError>> {
        Box::pin(async { Ok(()) })
    }

    fn sample_full_jitter(&self, _: u64) -> Result<u64, HostError> {
        Ok(0)
    }
}

#[derive(Default)]
struct ShutdownPayloadSink {
    payloads: Mutex<Vec<Vec<u8>>>,
}

impl ShutdownPayloadSink {
    fn payloads(&self) -> Vec<Vec<u8>> {
        self.payloads
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}

impl EventSink for ShutdownPayloadSink {
    fn deliver<'a>(
        &'a self,
        request: EventDeliveryRequest,
    ) -> HostFuture<'a, Result<DeliveryOutcome, HostError>> {
        if request.event.kind() == EventKind::Shutdown {
            self.payloads
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(request.event.payload().canonical_bytes().to_vec());
        }
        Box::pin(async { Ok(DeliveryOutcome::Success) })
    }
}

struct SelectiveOutcomeSink {
    failed_kind: EventKind,
    attempts: Mutex<
        Vec<(
            EventKind,
            gantry::identity::ProtocolIdentity,
            gantry::identity::ProtocolIdentity,
        )>,
    >,
}

impl SelectiveOutcomeSink {
    fn attempts(
        &self,
    ) -> Vec<(
        EventKind,
        gantry::identity::ProtocolIdentity,
        gantry::identity::ProtocolIdentity,
    )> {
        self.attempts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}

impl EventSink for SelectiveOutcomeSink {
    fn deliver<'a>(
        &'a self,
        request: EventDeliveryRequest,
    ) -> HostFuture<'a, Result<DeliveryOutcome, HostError>> {
        let kind = request.event.kind();
        self.attempts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push((kind, request.event.event_id(), request.attempt_id));
        let outcome = if kind == self.failed_kind {
            DeliveryOutcome::Terminal
        } else {
            DeliveryOutcome::Success
        };
        Box::pin(async move { Ok(outcome) })
    }
}

#[derive(Default)]
struct GatedCancellationStore {
    inner: InMemoryJournalStore,
    commits: AtomicU64,
    cancellation_commit_released: AtomicBool,
    cancellation_commit_waker: Mutex<Option<Waker>>,
}

impl GatedCancellationStore {
    fn release_cancellation_commit(&self) {
        self.cancellation_commit_released
            .store(true, Ordering::Release);
        if let Some(waker) = self
            .cancellation_commit_waker
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            waker.wake();
        }
    }
}

impl JournalStorage for GatedCancellationStore {
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
        if self.commits.fetch_add(1, Ordering::AcqRel) == 0 {
            return self.inner.commit(request);
        }
        Box::pin(async move {
            std::future::poll_fn(|context| {
                if self.cancellation_commit_released.load(Ordering::Acquire) {
                    return Poll::Ready(());
                }
                *self
                    .cancellation_commit_waker
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()) =
                    Some(context.waker().clone());
                Poll::Pending
            })
            .await;
            self.inner.commit(request).await
        })
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

#[derive(Default)]
struct CancellationCommitGateStore {
    inner: InMemoryJournalStore,
    commit_started: AtomicBool,
    commit_released: AtomicBool,
    commit_waker: Mutex<Option<Waker>>,
}

impl CancellationCommitGateStore {
    fn commit_started(&self) -> bool {
        self.commit_started.load(Ordering::Acquire)
    }

    fn release_commit(&self) {
        self.commit_released.store(true, Ordering::Release);
        if let Some(waker) = self
            .commit_waker
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            waker.wake();
        }
    }
}

impl JournalStorage for CancellationCommitGateStore {
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
        let cancellation = request
            .batch
            .evidence
            .iter()
            .any(|evidence| evidence.kind.as_ref() == "gantry.cancellation/v1");
        if !cancellation {
            return self.inner.commit(request);
        }
        self.commit_started.store(true, Ordering::Release);
        Box::pin(async move {
            std::future::poll_fn(|context| {
                if self.commit_released.load(Ordering::Acquire) {
                    return Poll::Ready(());
                }
                *self
                    .commit_waker
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()) =
                    Some(context.waker().clone());
                Poll::Pending
            })
            .await;
            self.inner.commit(request).await
        })
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

#[derive(Default)]
struct PendingHookState {
    dispatch_started: AtomicBool,
    cancellation_observed: AtomicBool,
    release: AtomicBool,
    settled: AtomicBool,
    polls: AtomicU64,
    waker: Mutex<Option<Waker>>,
}

impl PendingHookState {
    fn release(&self) {
        self.release.store(true, Ordering::Release);
        if let Some(waker) = self
            .waker
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            waker.wake();
        }
    }
}

struct PendingHookIntegration {
    scripted: ScriptedIntegration,
    state: Arc<PendingHookState>,
}

impl PendingHookIntegration {
    fn new(state: Arc<PendingHookState>) -> Self {
        Self {
            scripted: ScriptedIntegration::new(
                [ScriptedPreflight::success(
                    EmbeddingOperation::ResolveMappings,
                    &br#"{"action_mapping_revision":"actions-v1","result":"resolved"}"#[..],
                )],
                [],
            ),
            state,
        }
    }
}

impl IntegrationPreflight for PendingHookIntegration {
    fn call<'a>(&'a self, request: HostRequest) -> HostFuture<'a, Result<HostResponse, HostError>> {
        self.scripted.call(request)
    }
}

impl RuntimeSessionService for PendingHookIntegration {
    fn establish<'a>(
        &'a self,
        request: HostRequest,
    ) -> HostFuture<'a, Result<HostResponse, HostError>> {
        self.scripted.establish(request)
    }
}

impl HookFactory for PendingHookIntegration {
    fn create_hook<'a>(
        &'a self,
        _request: HostRequest,
    ) -> HostFuture<'a, Result<Box<dyn OperationHook>, HostError>> {
        let state = Arc::clone(&self.state);
        Box::pin(async move { Ok(Box::new(PendingHook { state }) as Box<dyn OperationHook>) })
    }
}

struct PendingHook {
    state: Arc<PendingHookState>,
}

impl OperationHook for PendingHook {
    fn dispatch<'a>(
        &'a mut self,
        _request: HostRequest,
        cancellation: &'a dyn CancellationToken,
    ) -> HostFuture<'a, Result<HookOutcomeV1, HostError>> {
        Box::pin(std::future::poll_fn(move |context| {
            self.state.polls.fetch_add(1, Ordering::AcqRel);
            self.state.dispatch_started.store(true, Ordering::Release);
            if cancellation.is_cancelled() {
                self.state
                    .cancellation_observed
                    .store(true, Ordering::Release);
            }
            if self.state.release.load(Ordering::Acquire)
                && self.state.cancellation_observed.load(Ordering::Acquire)
            {
                self.state.settled.store(true, Ordering::Release);
                return Poll::Ready(Ok(HookOutcomeV1::Completed(Arc::from(&br#""late""#[..]))));
            }
            *self
                .state
                .waker
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(context.waker().clone());
            Poll::Pending
        }))
    }
}

#[test]
fn checked_in_automatic_durable_root_evidence_is_narrow_and_current() {
    let root = workspace_root();
    let manifest: EvidenceManifest =
        read_json(&root.join("protocol/conformance/automatic-durable-root-v1.json"));
    let review: RequirementReview = read_json(&root.join("protocol/requirements/reviewed-v1.json"));
    let gate: ContractGate =
        read_json(&root.join("protocol/conformance/async-execution-contract-v1.json"));

    assert_eq!(manifest.format, "gantry.automatic-durable-root-evidence/v1");
    assert_eq!(manifest.specification_sha256, review.specification_sha256);
    assert_eq!(manifest.issue, "GNT-ASYNC-DROOT-001");
    assert!(
        manifest
            .capabilities
            .windows(2)
            .all(|pair| pair[0] < pair[1])
    );
    assert_eq!(
        manifest
            .capabilities
            .iter()
            .map(|entry| entry.evidence.as_str())
            .collect::<Vec<_>>(),
        [
            AUTOMATIC_PROGRESS_EVIDENCE,
            COMMIT_FAILURE_EVIDENCE,
            OPERATION_EVIDENCE,
            SUBMISSION_FAILURE_EVIDENCE,
            SESSION_EVIDENCE,
        ]
    );

    let mut assigned = gate
        .requirement_assignments
        .into_iter()
        .filter(|assignment| {
            assignment
                .evidence_owners
                .iter()
                .any(|owner| owner == "GNT-ASYNC-DROOT-001")
        })
        .map(|assignment| RequirementEvidence {
            requirement: assignment.requirement,
            clause: assignment.clause,
            profiles: assignment.profiles,
        })
        .collect::<Vec<_>>();
    assigned.sort();
    let mut declared = manifest.requirements;
    declared.sort();
    assert_eq!(declared, assigned);
    assert_eq!(declared.len(), 9);
    assert_eq!(manifest.exclusions.len(), 4);
}

#[test]
fn accepted_durable_root_runs_on_the_executor_and_commits_before_observation() {
    let root = TempDirectory::new("fn main() -> Int { 42 }");
    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    let interpreter = interpreter(Arc::clone(&executor));
    let storage = Arc::new(InMemoryJournalStore::new());
    let storage_adapter: Arc<dyn JournalStorage> = storage.clone();
    let journal_id = JournalId::new("automatic-durable-root")
        .unwrap_or_else(|error| panic!("journal identity failed: {error:?}"));
    let selection = selection();

    let accepted = match block_on(interpreter.start_durable_execution(
        Arc::clone(&storage_adapter),
        DurableStartExecutionRequest {
            journal_id: journal_id.clone(),
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
            panic!("automatic durable start was rejected: {failure:?}")
        }
    };

    assert_eq!(executor.task_ids(), [0]);
    loop {
        match executor
            .poll_task(0)
            .unwrap_or_else(|error| panic!("durable root poll failed: {error:?}"))
        {
            DeterministicTaskPoll::Pending | DeterministicTaskPoll::NotRunnable => {
                std::thread::yield_now();
            }
            DeterministicTaskPoll::Settled(_) => break,
            other => panic!("durable root settled abnormally: {other:?}"),
        }
    }

    let observation = block_on(accepted.owned.await_terminal());
    assert!(
        matches!(
            observation.terminal,
            Some(MachineOutcome::Succeeded(ref value))
                if matches!(value.view(), LogicalValueView::Int(value) if value.get() == 42)
        ),
        "unexpected durable observation: {observation:?}"
    );
    assert_eq!(
        observation.latest_cut(),
        DurableCommitCutV1::TerminalCompletion
    );

    let prefix = block_on(storage.read_prefix(ReadJournalPrefixV1 { journal_id }))
        .unwrap_or_else(|error| panic!("journal read failed: {error:?}"));
    let JournalPrefixV1::Full(full) = &prefix else {
        panic!("in-memory journal returned a compacted prefix")
    };
    assert!(full.committed_through >= 4);
    let (_, recovered) = recover_authoritative_prefix_with_retained_program(&prefix)
        .unwrap_or_else(|error| panic!("terminal prefix did not recover: {error:?}"));
    assert_eq!(
        recovered.latest_cut(),
        DurableCommitCutV1::TerminalCompletion
    );
}

#[test]
fn facade_cancellation_of_a_running_durable_root_commits_before_signalling() {
    let root = TempDirectory::new(
        "action read_only lookup() -> String;\nfn main() -> String { action lookup() }",
    );
    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    let integration = Arc::new(ScriptedIntegration::new(
        [ScriptedPreflight::success(
            EmbeddingOperation::ResolveMappings,
            &br#"{"action_mapping_revision":"actions-v1","result":"resolved"}"#[..],
        )],
        [ScriptedHook::created([Ok(HookOutcomeV1::Completed(
            Arc::from(&br#""done""#[..]),
        ))])],
    ));
    let interpreter = interpreter_with_integration(Arc::clone(&executor), integration);
    let storage = Arc::new(GatedCancellationStore::default());
    let storage_adapter: Arc<dyn JournalStorage> = storage.clone();
    let journal_id = JournalId::new("automatic-durable-facade-cancellation")
        .unwrap_or_else(|error| panic!("journal identity failed: {error:?}"));
    let selection = selection();
    let accepted = match block_on(interpreter.start_durable_execution(
        Arc::clone(&storage_adapter),
        DurableStartExecutionRequest {
            journal_id: journal_id.clone(),
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
            panic!("durable cancellation fixture was rejected: {failure:?}")
        }
    };
    let execution_id = accepted.start.execution_id;
    let signal = accepted
        .start
        .handle
        .cancellation_signal()
        .unwrap_or_else(|error| panic!("cancellation signal failed: {error:?}"));
    let expected_reason = caller_cancellation_reason(Some(Arc::from("stop")), 32)
        .unwrap_or_else(|error| panic!("cancellation reason failed: {error:?}"));
    assert_eq!(
        executor.poll_task(0),
        Ok(DeterministicTaskPoll::Pending),
        "root should be running with its operation-prepared commit in flight"
    );
    let mut cancellation =
        Box::pin(interpreter.cancel_execution(execution_id, expected_reason.clone()));
    assert!(
        cancellation
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    assert!(
        !signal.is_cancelled(),
        "durable cancellation signalled before its journal commit"
    );

    storage.release_cancellation_commit();
    settle_task(&executor, 0);
    let record = match cancellation
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(Ok(record)) => record,
        Poll::Ready(Err(error)) => panic!("facade cancellation failed: {error:?}"),
        Poll::Pending => panic!("facade cancellation did not publish terminal state"),
    };
    assert!(matches!(
        record,
        CancellationRecord::Accepted { ref reason, .. } if reason == &expected_reason
    ));
    assert!(signal.is_cancelled());
    let observation = block_on(accepted.owned.await_terminal());
    assert!(matches!(
        observation.terminal,
        Some(MachineOutcome::Cancelled(ref message)) if message.as_ref() == "stop"
    ));
    let prefix = block_on(storage.read_prefix(ReadJournalPrefixV1 { journal_id }))
        .unwrap_or_else(|error| panic!("journal read failed: {error:?}"));
    let JournalPrefixV1::Full(full) = prefix else {
        panic!("in-memory journal returned a compacted prefix")
    };
    assert!(
        full.evidence
            .iter()
            .any(|entry| entry.kind.as_ref() == "gantry.cancellation/v1")
    );
}

#[test]
fn facade_cancellation_drains_finite_events_before_releasing_durable_owner() {
    let root = TempDirectory::new(
        "action read_only lookup() -> String;\nfn main() -> String { action lookup() }",
    );
    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    let hook_state = Arc::new(PendingHookState::default());
    let integration = Arc::new(PendingHookIntegration::new(Arc::clone(&hook_state)));
    let storage = Arc::new(ObservedJournalStore::with_settlement_gate(u64::MAX));
    let required_gate = Arc::new(DeliveryGate::default());
    let best_effort_gate = Arc::new(DeliveryGate::default());
    let required_sink = Arc::new(DurableEvidenceSink {
        storage: Arc::clone(&storage),
        terminal_gate: Some(Arc::clone(&required_gate)),
    });
    let best_effort_sink = Arc::new(DurableEvidenceSink {
        storage: Arc::clone(&storage),
        terminal_gate: Some(Arc::clone(&best_effort_gate)),
    });
    let interpreter = interpreter_with_durable_delivery(
        Arc::clone(&executor),
        integration,
        1,
        Arc::new(ImmediateDurableDeliveryRuntime),
        durable_required_and_best_effort_plan(required_sink, best_effort_sink),
    );
    let storage_adapter: Arc<dyn JournalStorage> = storage.clone();
    let journal_id = JournalId::new("automatic-durable-facade-cancellation-event-drain")
        .unwrap_or_else(|error| panic!("journal identity failed: {error:?}"));
    let selection = selection();
    let accepted = match block_on(interpreter.start_durable_execution(
        storage_adapter,
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
            panic!("durable cancellation event-drain fixture was rejected: {failure:?}")
        }
    };
    let execution_id = accepted.start.execution_id;
    let root_task_id = *executor
        .task_ids()
        .last()
        .unwrap_or_else(|| panic!("accepted durable execution submitted no root task"));
    assert_eq!(
        executor.poll_task(root_task_id),
        Ok(DeterministicTaskPoll::Pending)
    );
    assert!(hook_state.dispatch_started.load(Ordering::Acquire));

    let expected_reason = caller_cancellation_reason(Some(Arc::from("drain-events")), 64)
        .unwrap_or_else(|error| panic!("cancellation reason failed: {error:?}"));
    let mut cancellation =
        Box::pin(interpreter.cancel_execution(execution_id, expected_reason.clone()));
    assert!(
        cancellation
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending(),
        "facade cancellation returned before the pending hook observed cancellation"
    );
    assert_eq!(
        executor.poll_task(root_task_id),
        Ok(DeterministicTaskPoll::Pending)
    );
    assert!(hook_state.cancellation_observed.load(Ordering::Acquire));
    hook_state.release();
    poll_task_until(&executor, root_task_id, || required_gate.calls() == 1);
    assert!(
        cancellation
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending(),
        "facade cancellation returned before required delivery settled"
    );
    assert_eq!(required_gate.calls(), 1);
    assert_eq!(best_effort_gate.calls(), 0);
    assert_eq!(storage.release_count(), 0);

    required_gate.release();
    poll_task_until(&executor, root_task_id, || best_effort_gate.calls() == 1);
    assert!(
        cancellation
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending(),
        "facade cancellation returned before best-effort delivery settled"
    );
    assert_eq!(required_gate.calls(), 1);
    assert_eq!(best_effort_gate.calls(), 1);
    assert_eq!(storage.release_count(), 0);

    best_effort_gate.release();
    settle_task(&executor, root_task_id);
    let record = match cancellation
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(Ok(record)) => record,
        Poll::Ready(Err(error)) => panic!("facade cancellation failed: {error:?}"),
        Poll::Pending => panic!("facade cancellation remained pending after delivery settlement"),
    };
    assert!(matches!(
        record,
        CancellationRecord::Accepted { ref reason, .. } if reason == &expected_reason
    ));
    assert_eq!(required_gate.calls(), 1);
    assert_eq!(best_effort_gate.calls(), 1);
    assert_eq!(storage.release_count(), 1);
    let observation = block_on(accepted.owned.await_terminal());
    assert!(matches!(
        observation.terminal,
        Some(MachineOutcome::Cancelled(ref message)) if message.as_ref() == "drain-events"
    ));

    let repeated = block_on(interpreter.cancel_execution(execution_id, expected_reason))
        .unwrap_or_else(|error| panic!("repeated facade cancellation failed: {error:?}"));
    assert!(matches!(repeated, CancellationRecord::Accepted { .. }));
    assert_eq!(required_gate.calls(), 1);
    assert_eq!(best_effort_gate.calls(), 1);
    assert_eq!(storage.release_count(), 1);

    let mut shutdown = Box::pin(interpreter.shutdown());
    assert!(
        shutdown
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    let shutdown_task_id = *executor
        .task_ids()
        .last()
        .unwrap_or_else(|| panic!("shutdown submitted no owned task"));
    settle_task(&executor, shutdown_task_id);
    match shutdown
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(Ok(report)) => assert!(report.orderly),
        Poll::Ready(Err(error)) => panic!("facade shutdown failed: {error:?}"),
        Poll::Pending => panic!("facade shutdown did not publish its report"),
    }
    assert_eq!(required_gate.calls(), 1);
    assert_eq!(best_effort_gate.calls(), 1);
    assert_eq!(storage.release_count(), 1);
}

#[test]
fn cancellation_progresses_a_pending_dispatch_and_retains_it_to_settlement() {
    let root = TempDirectory::new(
        "action read_only lookup() -> String;\nfn main() -> String { action lookup() }",
    );
    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    let hook_state = Arc::new(PendingHookState::default());
    let integration = Arc::new(PendingHookIntegration::new(Arc::clone(&hook_state)));
    let interpreter = interpreter_with_integration(Arc::clone(&executor), integration);
    let storage = Arc::new(CancellationCommitGateStore::default());
    let storage_adapter: Arc<dyn JournalStorage> = storage.clone();
    let journal_id = JournalId::new("automatic-durable-pending-dispatch-cancellation")
        .unwrap_or_else(|error| panic!("journal identity failed: {error:?}"));
    let selection = selection();
    let accepted = match block_on(interpreter.start_durable_execution(
        Arc::clone(&storage_adapter),
        DurableStartExecutionRequest {
            journal_id: journal_id.clone(),
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
            panic!("pending-dispatch fixture was rejected: {failure:?}")
        }
    };
    let execution_id = accepted.start.execution_id;
    let signal = accepted
        .start
        .handle
        .cancellation_signal()
        .unwrap_or_else(|error| panic!("cancellation signal failed: {error:?}"));
    assert_eq!(executor.poll_task(0), Ok(DeterministicTaskPoll::Pending));
    assert!(hook_state.dispatch_started.load(Ordering::Acquire));
    assert!(!signal.is_cancelled());

    let expected_reason = caller_cancellation_reason(Some(Arc::from("stop-pending")), 64)
        .unwrap_or_else(|error| panic!("cancellation reason failed: {error:?}"));
    let mut cancellation =
        Box::pin(interpreter.cancel_execution(execution_id, expected_reason.clone()));
    assert!(
        cancellation
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    assert!(
        executor.is_runnable(0),
        "queued driver control did not wake the pending dispatch"
    );
    assert_eq!(executor.poll_task(0), Ok(DeterministicTaskPoll::Pending));
    assert!(storage.commit_started());
    assert!(
        !signal.is_cancelled(),
        "semantic cancellation became visible before its journal commit"
    );

    storage.release_commit();
    assert_eq!(executor.poll_task(0), Ok(DeterministicTaskPoll::Pending));
    assert!(signal.is_cancelled());
    assert!(hook_state.cancellation_observed.load(Ordering::Acquire));
    assert!(!hook_state.settled.load(Ordering::Acquire));
    assert!(
        cancellation
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending(),
        "cancellation completed before the dispatched hook settled"
    );

    hook_state.release();
    settle_task(&executor, 0);
    assert!(hook_state.settled.load(Ordering::Acquire));
    assert!(hook_state.polls.load(Ordering::Acquire) >= 3);
    let record = match cancellation
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(Ok(record)) => record,
        Poll::Ready(Err(error)) => panic!("pending-dispatch cancellation failed: {error:?}"),
        Poll::Pending => panic!("pending-dispatch cancellation did not finish"),
    };
    assert!(matches!(
        record,
        CancellationRecord::Accepted { ref reason, .. } if reason == &expected_reason
    ));
    let observation = block_on(accepted.owned.await_terminal());
    assert!(matches!(
        observation.terminal,
        Some(MachineOutcome::Cancelled(ref message)) if message.as_ref() == "stop-pending"
    ));

    let prefix = block_on(storage.read_prefix(ReadJournalPrefixV1 { journal_id }))
        .unwrap_or_else(|error| panic!("journal read failed: {error:?}"));
    let JournalPrefixV1::Full(full) = &prefix else {
        panic!("in-memory journal returned a compacted prefix")
    };
    let program = full
        .evidence
        .first()
        .and_then(|entry| {
            gantry::runtime::DurableExecutionStartV1::retained_program(&entry.canonical_body).ok()
        })
        .unwrap_or_else(|| panic!("pending-dispatch prefix omitted its retained program"));
    let cuts = full
        .evidence
        .iter()
        .filter(|entry| entry.kind.as_ref() == "gantry.logical-evidence/v1")
        .map(|entry| {
            DurableLogicalEvidenceV1::decode(&program, &entry.canonical_body)
                .unwrap_or_else(|error| panic!("logical evidence did not decode: {error:?}"))
                .cut()
        })
        .collect::<Vec<_>>();
    assert!(cuts.contains(&DurableCommitCutV1::OperationPrepared));
    assert!(!cuts.contains(&DurableCommitCutV1::OperationOutcome));
    assert_eq!(cuts.last(), Some(&DurableCommitCutV1::TerminalCompletion));
}

#[test]
fn facade_shutdown_cancels_a_running_durable_root_only_after_commit() {
    let root = TempDirectory::new(
        "action read_only lookup() -> String;\nfn main() -> String { action lookup() }",
    );
    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    let integration = Arc::new(ScriptedIntegration::new(
        [ScriptedPreflight::success(
            EmbeddingOperation::ResolveMappings,
            &br#"{"action_mapping_revision":"actions-v1","result":"resolved"}"#[..],
        )],
        [ScriptedHook::created([Ok(HookOutcomeV1::Completed(
            Arc::from(&br#""done""#[..]),
        ))])],
    ));
    let interpreter = interpreter_with_integration(Arc::clone(&executor), integration);
    let storage = Arc::new(GatedCancellationStore::default());
    let storage_adapter: Arc<dyn JournalStorage> = storage.clone();
    let journal_id = JournalId::new("automatic-durable-facade-shutdown")
        .unwrap_or_else(|error| panic!("journal identity failed: {error:?}"));
    let selection = selection();
    let accepted = match block_on(interpreter.start_durable_execution(
        Arc::clone(&storage_adapter),
        DurableStartExecutionRequest {
            journal_id: journal_id.clone(),
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
            panic!("durable shutdown fixture was rejected: {failure:?}")
        }
    };
    let signal = accepted
        .start
        .handle
        .cancellation_signal()
        .unwrap_or_else(|error| panic!("cancellation signal failed: {error:?}"));
    assert_eq!(
        executor.poll_task(0),
        Ok(DeterministicTaskPoll::Pending),
        "root should be running with its operation-prepared commit in flight"
    );

    let mut shutdown = Box::pin(interpreter.shutdown());
    assert!(
        shutdown
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    assert_eq!(executor.task_ids(), [0, 1]);
    assert_eq!(executor.poll_task(1), Ok(DeterministicTaskPoll::Pending));
    assert!(
        !signal.is_cancelled(),
        "shutdown signalled durable work before its cancellation commit"
    );

    storage.release_cancellation_commit();
    settle_task(&executor, 0);
    assert!(signal.is_cancelled());
    settle_task(&executor, 1);
    let report = match shutdown
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(Ok(report)) => report,
        Poll::Ready(Err(error)) => panic!("facade shutdown failed: {error:?}"),
        Poll::Pending => panic!("facade shutdown did not publish its report"),
    };
    assert!(report.orderly);
    assert_eq!(report.cohort.len(), 1);
    let observation = block_on(accepted.owned.await_terminal());
    assert!(matches!(
        observation.terminal,
        Some(MachineOutcome::Cancelled(ref message)) if message.as_ref() == "shutdown"
    ));
    let prefix = block_on(storage.read_prefix(ReadJournalPrefixV1 { journal_id }))
        .unwrap_or_else(|error| panic!("journal read failed: {error:?}"));
    let JournalPrefixV1::Full(full) = prefix else {
        panic!("in-memory journal returned a compacted prefix")
    };
    assert!(
        full.evidence
            .iter()
            .any(|entry| entry.kind.as_ref() == "gantry.cancellation/v1")
    );
}

#[test]
fn shutdown_waits_for_durable_owner_published_after_lifecycle_acceptance() {
    let root = TempDirectory::new("fn main() -> Int { 42 }");
    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    let shutdown_sink = Arc::new(ShutdownPayloadSink::default());
    let interpreter = interpreter_with_durable_delivery(
        Arc::clone(&executor),
        Arc::new(ScriptedIntegration::new([], [])),
        1,
        Arc::new(ImmediateDurableDeliveryRuntime),
        durable_plan(shutdown_sink.clone()),
    );
    let gate = Arc::new(DurableHandoffTestGate::default());
    interpreter.install_durable_handoff_test_gate(Arc::clone(&gate));
    let storage = Arc::new(GatedCancellationStore::default());
    let storage_adapter: Arc<dyn JournalStorage> = storage.clone();
    let journal_id = JournalId::new("automatic-durable-shutdown-handoff")
        .unwrap_or_else(|error| panic!("journal identity failed: {error:?}"));
    let selection = selection();

    std::thread::scope(|scope| {
        let starting_interpreter = interpreter.clone();
        let start = scope.spawn(move || {
            block_on(starting_interpreter.start_durable_execution(
                storage_adapter,
                DurableStartExecutionRequest {
                    journal_id: journal_id.clone(),
                    start: StartExecutionRequest {
                        package_root: &root.0,
                        protocol_selection: &selection,
                        required_peers: &[],
                        entry_input: None,
                        root_session: None,
                        event_delivery: None,
                    },
                },
            ))
        });
        let handle = gate.wait_until_accepted();
        let signal = handle
            .cancellation_signal()
            .unwrap_or_else(|error| panic!("cancellation signal failed: {error:?}"));
        let mut shutdown = Box::pin(interpreter.shutdown());
        assert!(
            shutdown
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        let shutdown_task_id = *executor
            .task_ids()
            .last()
            .unwrap_or_else(|| panic!("shutdown submitted no owned task"));
        assert_eq!(
            executor.poll_task(shutdown_task_id),
            Ok(DeterministicTaskPoll::Pending)
        );
        assert!(
            !signal.is_cancelled(),
            "shutdown directly signalled a durable token while its owner was unpublished"
        );

        gate.release();
        let accepted = match start
            .join()
            .unwrap_or_else(|_| panic!("durable start thread panicked"))
        {
            DurableStartExecutionResult::Accepted(accepted) => accepted,
            DurableStartExecutionResult::Rejected(failure) => {
                panic!("durable handoff fixture was rejected: {failure:?}")
            }
        };
        let root_task_id = *executor
            .task_ids()
            .last()
            .unwrap_or_else(|| panic!("accepted durable start submitted no root task"));
        assert!(
            executor.is_runnable(shutdown_task_id),
            "owner publication did not wake shutdown"
        );
        assert_eq!(
            executor.poll_task(shutdown_task_id),
            Ok(DeterministicTaskPoll::Pending)
        );
        assert!(
            !signal.is_cancelled(),
            "shutdown signalled durable cancellation before its journal commit"
        );

        storage.release_cancellation_commit();
        assert_eq!(
            executor.poll_task(shutdown_task_id),
            Ok(DeterministicTaskPoll::Pending)
        );
        assert!(signal.is_cancelled());
        settle_task(&executor, root_task_id);
        settle_task(&executor, shutdown_task_id);
        let report = match shutdown
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        {
            Poll::Ready(Ok(report)) => report,
            Poll::Ready(Err(error)) => panic!("facade shutdown failed: {error:?}"),
            Poll::Pending => panic!("facade shutdown did not publish its report"),
        };
        assert!(report.orderly);
        assert_eq!(report.cohort.len(), 1);
        let observation = block_on(accepted.owned.await_terminal());
        assert!(matches!(
            observation.terminal,
            Some(MachineOutcome::Cancelled(ref message)) if message.as_ref() == "shutdown"
        ));
        let payloads = shutdown_sink.payloads();
        assert_eq!(payloads.len(), 1);
        let payload: serde_json::Value = serde_json::from_slice(&payloads[0])
            .unwrap_or_else(|error| panic!("shutdown payload did not decode: {error}"));
        assert_eq!(payload["executions_at_start"], 1);
        assert_eq!(payload["admitted_after_start_count"], 0);
    });
}

#[test]
fn resumed_root_stays_gated_until_atomic_acceptance_then_completes_automatically() {
    let root = TempDirectory::new("fn main() -> Int { 42 }");
    let integration = Arc::new(ScriptedIntegration::new(
        [ScriptedPreflight::success(
            EmbeddingOperation::ResolveSessions,
            &br#"{"result":"resolved"}"#[..],
        )],
        [],
    ));
    let initial_executor = Arc::new(DeterministicConcurrentExecutor::default());
    let initial = interpreter_with_integration(Arc::clone(&initial_executor), integration.clone());
    let storage = Arc::new(InMemoryJournalStore::new());
    let storage_adapter: Arc<dyn JournalStorage> = storage.clone();
    let journal_id = JournalId::new("automatic-durable-resume")
        .unwrap_or_else(|error| panic!("journal identity failed: {error:?}"));
    let selection = selection();
    let started = match block_on(initial.start_durable_execution(
        Arc::clone(&storage_adapter),
        DurableStartExecutionRequest {
            journal_id: journal_id.clone(),
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
            panic!("resume fixture start was rejected: {failure:?}")
        }
    };
    let execution_id = started.start.execution_id;
    let prefix_before_resume = block_on(storage.read_prefix(ReadJournalPrefixV1 {
        journal_id: journal_id.clone(),
    }))
    .unwrap_or_else(|error| panic!("journal read failed: {error:?}"));
    block_on(storage.release_owner(ReleaseJournalOwnerV1 {
        journal_id: journal_id.clone(),
        ownership_token: started.ownership_token.clone(),
    }))
    .unwrap_or_else(|error| panic!("fixture owner release failed: {error:?}"));

    let resume_executor = Arc::new(DeterministicConcurrentExecutor::default());
    let resumed = interpreter_with_integration_and_identity_start(
        Arc::clone(&resume_executor),
        integration,
        97,
    );
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

    resume_executor.poll_next_spawn_immediately();
    assert!(matches!(
        resume_executor.poll_task(0),
        Ok(DeterministicTaskPoll::Settled(_))
    ));
    assert_eq!(resume_executor.task_ids(), [0, 1]);
    assert_eq!(resume_executor.poll_count(1), Some(1));
    assert_eq!(
        block_on(storage.read_prefix(ReadJournalPrefixV1 {
            journal_id: journal_id.clone(),
        }))
        .unwrap_or_else(|error| panic!("journal read failed: {error:?}")),
        prefix_before_resume
    );

    let accepted = match resume
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(DurableResumeExecutionResult::Accepted(accepted)) => accepted,
        Poll::Ready(DurableResumeExecutionResult::Rejected(failure)) => {
            panic!("atomic resume was rejected: {failure:?}")
        }
        Poll::Pending => panic!("completed resume coordinator did not publish acceptance"),
    };
    assert_eq!(accepted.execution_id, execution_id);
    assert_eq!(accepted.recovered.latest_sequence(), 1);
    settle_task(&resume_executor, 1);
    let observation = block_on(accepted.owned.await_terminal());
    assert!(matches!(
        observation.terminal,
        Some(MachineOutcome::Succeeded(ref value))
            if matches!(value.view(), LogicalValueView::Int(value) if value.get() == 42)
    ));
    assert_eq!(
        observation.latest_cut(),
        DurableCommitCutV1::TerminalCompletion
    );
}

#[test]
fn resume_executor_rejection_rolls_back_and_releases_the_owner_once() {
    let root = TempDirectory::new("fn main() -> Int { 7 }");
    let integration = Arc::new(ScriptedIntegration::new(
        [ScriptedPreflight::success(
            EmbeddingOperation::ResolveSessions,
            &br#"{"result":"resolved"}"#[..],
        )],
        [],
    ));
    let initial_executor = Arc::new(DeterministicConcurrentExecutor::default());
    let initial = interpreter_with_integration(Arc::clone(&initial_executor), integration.clone());
    let storage = Arc::new(FailAfterStartStore::default());
    let storage_adapter: Arc<dyn JournalStorage> = storage.clone();
    let journal_id = JournalId::new("automatic-durable-resume-rejection")
        .unwrap_or_else(|error| panic!("journal identity failed: {error:?}"));
    let selection = selection();
    let started = match block_on(initial.start_durable_execution(
        Arc::clone(&storage_adapter),
        DurableStartExecutionRequest {
            journal_id: journal_id.clone(),
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
            panic!("resume rejection fixture start failed: {failure:?}")
        }
    };
    let execution_id = started.start.execution_id;
    let prefix_before_resume = block_on(storage.read_prefix(ReadJournalPrefixV1 {
        journal_id: journal_id.clone(),
    }))
    .unwrap_or_else(|error| panic!("journal read failed: {error:?}"));
    block_on(storage.release_owner(ReleaseJournalOwnerV1 {
        journal_id: journal_id.clone(),
        ownership_token: started.ownership_token.clone(),
    }))
    .unwrap_or_else(|error| panic!("fixture owner release failed: {error:?}"));
    assert_eq!(storage.release_count(), 1);

    let resume_executor = Arc::new(DeterministicConcurrentExecutor::default());
    let resumed = interpreter_with_integration_and_identity_start(
        Arc::clone(&resume_executor),
        integration,
        97,
    );
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
    resume_executor.fail_next_spawn();
    assert!(matches!(
        resume_executor.poll_task(0),
        Ok(DeterministicTaskPoll::Settled(_))
    ));

    let rejected = match resume
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(DurableResumeExecutionResult::Rejected(failure)) => failure,
        Poll::Ready(DurableResumeExecutionResult::Accepted(_)) => {
            panic!("executor-rejected resume was accepted")
        }
        Poll::Pending => panic!("completed rejection was not published"),
    };
    assert_eq!(
        rejected.category,
        gantry::portable::ResumeStartFailureCategory::Internal
    );
    assert_eq!(rejected.code.as_ref(), "resume-task-submission-failure");
    assert!(rejected.release_error.is_none());
    assert_eq!(resume_executor.task_ids(), [0]);
    assert_eq!(storage.release_count(), 2);
    assert_eq!(
        block_on(storage.read_prefix(ReadJournalPrefixV1 { journal_id }))
            .unwrap_or_else(|error| panic!("journal read failed: {error:?}")),
        prefix_before_resume
    );
}

#[test]
fn resume_revision_commit_failure_stops_the_gated_driver_and_preserves_the_prefix() {
    let root = TempDirectory::new(
        "action read_only lookup() -> String;\nfn main() -> String { action lookup() }",
    );
    let initial_integration = Arc::new(ScriptedIntegration::new(
        [ScriptedPreflight::success(
            EmbeddingOperation::ResolveMappings,
            &br#"{"action_mapping_revision":"actions-v1","result":"resolved"}"#[..],
        )],
        [],
    ));
    let initial_executor = Arc::new(DeterministicConcurrentExecutor::default());
    let initial = interpreter_with_integration(Arc::clone(&initial_executor), initial_integration);
    let storage = Arc::new(FailAfterStartStore::default());
    let storage_adapter: Arc<dyn JournalStorage> = storage.clone();
    let journal_id = JournalId::new("automatic-durable-resume-commit-rollback")
        .unwrap_or_else(|error| panic!("journal identity failed: {error:?}"));
    let selection = selection();
    let started = match block_on(initial.start_durable_execution(
        Arc::clone(&storage_adapter),
        DurableStartExecutionRequest {
            journal_id: journal_id.clone(),
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
            panic!("resume rollback fixture start failed: {failure:?}")
        }
    };
    let execution_id = started.start.execution_id;
    let prefix_before_resume = block_on(storage.read_prefix(ReadJournalPrefixV1 {
        journal_id: journal_id.clone(),
    }))
    .unwrap_or_else(|error| panic!("journal read failed: {error:?}"));
    block_on(storage.release_owner(ReleaseJournalOwnerV1 {
        journal_id: journal_id.clone(),
        ownership_token: started.ownership_token.clone(),
    }))
    .unwrap_or_else(|error| panic!("fixture owner release failed: {error:?}"));

    let resume_integration = Arc::new(ScriptedIntegration::new(
        [
            ScriptedPreflight::success(
                EmbeddingOperation::ResolveMappings,
                &br#"{"action_mapping_revision":"actions-v2","result":"resolved"}"#[..],
            ),
            ScriptedPreflight::success(
                EmbeddingOperation::ResolveSessions,
                &br#"{"result":"resolved"}"#[..],
            ),
        ],
        [],
    ));
    let resume_executor = Arc::new(DeterministicConcurrentExecutor::default());
    let resumed = interpreter_with_integration_and_identity_start(
        Arc::clone(&resume_executor),
        resume_integration,
        97,
    );
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
    settle_task(&resume_executor, 0);

    let rejected = match resume
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(DurableResumeExecutionResult::Rejected(failure)) => failure,
        Poll::Ready(DurableResumeExecutionResult::Accepted(_)) => {
            panic!("commit-failed resume was accepted")
        }
        Poll::Pending => panic!("completed rollback was not published"),
    };
    assert_eq!(
        rejected.category,
        gantry::portable::ResumeStartFailureCategory::JournalReadOrFormat
    );
    assert!(rejected.release_error.is_none());
    assert_eq!(resume_executor.task_ids(), [0, 1]);
    assert_eq!(
        resume_executor.poll_task(1),
        Ok(DeterministicTaskPoll::Stopped)
    );
    assert_eq!(storage.release_count(), 2);
    assert_eq!(
        block_on(storage.read_prefix(ReadJournalPrefixV1 { journal_id }))
            .unwrap_or_else(|error| panic!("journal read failed: {error:?}")),
        prefix_before_resume
    );
}

#[test]
fn dropping_the_resume_waiter_does_not_abandon_accepted_work() {
    let root = TempDirectory::new("fn main() -> Int { 51 }");
    let integration = Arc::new(ScriptedIntegration::new(
        [ScriptedPreflight::success(
            EmbeddingOperation::ResolveSessions,
            &br#"{"result":"resolved"}"#[..],
        )],
        [],
    ));
    let initial_executor = Arc::new(DeterministicConcurrentExecutor::default());
    let initial = interpreter_with_integration(Arc::clone(&initial_executor), integration.clone());
    let storage = Arc::new(InMemoryJournalStore::new());
    let storage_adapter: Arc<dyn JournalStorage> = storage.clone();
    let journal_id = JournalId::new("automatic-durable-resume-dropped-waiter")
        .unwrap_or_else(|error| panic!("journal identity failed: {error:?}"));
    let selection = selection();
    let started = match block_on(initial.start_durable_execution(
        Arc::clone(&storage_adapter),
        DurableStartExecutionRequest {
            journal_id: journal_id.clone(),
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
            panic!("dropped-waiter fixture start failed: {failure:?}")
        }
    };
    let execution_id = started.start.execution_id;
    block_on(storage.release_owner(ReleaseJournalOwnerV1 {
        journal_id: journal_id.clone(),
        ownership_token: started.ownership_token.clone(),
    }))
    .unwrap_or_else(|error| panic!("fixture owner release failed: {error:?}"));

    let resume_executor = Arc::new(DeterministicConcurrentExecutor::default());
    let resumed = interpreter_with_integration_and_identity_start(
        Arc::clone(&resume_executor),
        integration,
        97,
    );
    let mut resume = Box::pin(resumed.resume_durable_execution(
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
    drop(resume);
    settle_task(&resume_executor, 0);
    assert_eq!(resume_executor.task_ids(), [0, 1]);
    settle_task(&resume_executor, 1);

    let prefix = block_on(storage.read_prefix(ReadJournalPrefixV1 { journal_id }))
        .unwrap_or_else(|error| panic!("journal read failed: {error:?}"));
    let (_, recovered) = recover_authoritative_prefix_with_retained_program(&prefix)
        .unwrap_or_else(|error| panic!("dropped-waiter prefix did not recover: {error:?}"));
    assert_eq!(
        recovered.latest_cut(),
        DurableCommitCutV1::TerminalCompletion
    );
    assert!(matches!(
        recovered.machine().outcome(),
        Some(MachineOutcome::Succeeded(value))
            if matches!(value.view(), LogicalValueView::Int(value) if value.get() == 51)
    ));
}

#[test]
fn durable_event_dispatch_and_settlement_precede_callback_and_terminal_observation() {
    let root = TempDirectory::new("fn main() -> Int { 67 }");
    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    let storage = Arc::new(ObservedJournalStore::with_settlement_gate(3));
    let sink = Arc::new(DurableEvidenceSink {
        storage: Arc::clone(&storage),
        terminal_gate: None,
    });
    let interpreter = interpreter_with_durable_delivery(
        Arc::clone(&executor),
        Arc::new(ScriptedIntegration::new([], [])),
        1,
        Arc::new(ImmediateDurableDeliveryRuntime),
        durable_plan(sink),
    );
    let storage_adapter: Arc<dyn JournalStorage> = storage.clone();
    let journal_id = JournalId::new("automatic-durable-event-ordering")
        .unwrap_or_else(|error| panic!("journal identity failed: {error:?}"));
    let selection = selection();
    let accepted = match block_on(interpreter.start_durable_execution(
        Arc::clone(&storage_adapter),
        DurableStartExecutionRequest {
            journal_id: journal_id.clone(),
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
            panic!("durable event ordering fixture was rejected: {failure:?}")
        }
    };

    let root_task_id = *executor
        .task_ids()
        .last()
        .unwrap_or_else(|| panic!("accepted durable execution submitted no root task"));
    poll_task_until(&executor, root_task_id, || {
        storage.settlement_commit_started()
    });
    let prefix = block_on(storage.read_prefix(ReadJournalPrefixV1 {
        journal_id: journal_id.clone(),
    }))
    .unwrap_or_else(|error| panic!("journal read failed: {error:?}"));
    let JournalPrefixV1::Full(full) = &prefix else {
        panic!("in-memory journal returned a compacted prefix")
    };
    let terminal_occurrence = full
        .evidence
        .iter()
        .filter(|entry| entry.kind.as_ref() == "gantry.event-occurrence/v1")
        .filter_map(|entry| DurableEventOccurrenceV1::decode(&entry.canonical_body).ok())
        .find(|occurrence| occurrence.event().kind() == EventKind::TerminalExecution)
        .unwrap_or_else(|| panic!("terminal event occurrence was not committed"));
    let terminal_dispatch = full
        .evidence
        .iter()
        .filter(|entry| entry.kind.as_ref() == DURABLE_EVENT_DISPATCHED_KIND_V1)
        .filter_map(|entry| DurableEventDispatchedV1::decode(&entry.canonical_body).ok())
        .find(|dispatched| dispatched.event_id() == terminal_occurrence.event().event_id())
        .unwrap_or_else(|| panic!("terminal event dispatch was not committed"));
    assert!(
        full.evidence
            .iter()
            .filter(|entry| entry.kind.as_ref() == DURABLE_EVENT_SETTLED_KIND_V1)
            .filter_map(|entry| DurableEventSettledV1::decode(&entry.canonical_body).ok())
            .all(|settled| settled.event_id() != terminal_dispatch.event_id()),
        "terminal event settlement became visible before the gated commit"
    );

    let mut terminal = pin!(accepted.owned.await_terminal());
    assert!(
        terminal
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending(),
        "terminal observation preceded durable event settlement"
    );
    assert_eq!(storage.release_count(), 0);

    storage.release_settlement_commit();
    settle_task(&executor, root_task_id);
    let observation = match terminal
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(observation) => observation,
        Poll::Pending => panic!("terminal observation remained pending after settlement"),
    };
    assert!(matches!(
        observation.terminal,
        Some(MachineOutcome::Succeeded(ref value))
            if matches!(value.view(), LogicalValueView::Int(value) if value.get() == 67)
    ));
    let prefix = block_on(storage.read_prefix(ReadJournalPrefixV1 { journal_id }))
        .unwrap_or_else(|error| panic!("journal read failed: {error:?}"));
    let JournalPrefixV1::Full(full) = prefix else {
        panic!("in-memory journal returned a compacted prefix")
    };
    assert!(full.evidence.iter().any(|entry| {
        entry.kind.as_ref() == DURABLE_EVENT_SETTLED_KIND_V1
            && DurableEventSettledV1::decode(&entry.canonical_body).is_ok_and(|settled| {
                settled.event_id() == terminal_dispatch.event_id()
                    && settled.attempt_id() == terminal_dispatch.attempt_id()
                    && settled.outcome() == DeliveryOutcome::Success
            })
    }));
    assert_eq!(storage.release_count(), 1);
}

#[test]
fn terminal_delivery_only_resume_submits_no_root_or_hook_and_releases_owner() {
    let root = TempDirectory::new("fn main() -> Int { 71 }");
    let initial_executor = Arc::new(DeterministicConcurrentExecutor::default());
    let storage = Arc::new(ObservedJournalStore::with_settlement_gate(3));
    let initial_sink = Arc::new(DurableEvidenceSink {
        storage: Arc::clone(&storage),
        terminal_gate: None,
    });
    let initial = interpreter_with_durable_delivery(
        Arc::clone(&initial_executor),
        Arc::new(ScriptedIntegration::new([], [])),
        1,
        Arc::new(ImmediateDurableDeliveryRuntime),
        durable_plan(initial_sink),
    );
    let storage_adapter: Arc<dyn JournalStorage> = storage.clone();
    let journal_id = JournalId::new("automatic-durable-delivery-only-resume")
        .unwrap_or_else(|error| panic!("journal identity failed: {error:?}"));
    let selection = selection();
    let started = match block_on(initial.start_durable_execution(
        Arc::clone(&storage_adapter),
        DurableStartExecutionRequest {
            journal_id: journal_id.clone(),
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
            panic!("delivery-only resume fixture was rejected: {failure:?}")
        }
    };
    let execution_id = started.start.execution_id;

    let initial_root_task_id = *initial_executor
        .task_ids()
        .last()
        .unwrap_or_else(|| panic!("initial durable execution submitted no root task"));
    poll_task_until(&initial_executor, initial_root_task_id, || {
        storage.settlement_commit_started()
    });
    assert_eq!(storage.release_count(), 0);
    initial_executor
        .fail_task(initial_root_task_id)
        .unwrap_or_else(|error| panic!("could not stop simulated crashed driver: {error:?}"));
    storage.release_settlement_commit();
    block_on(storage.release_owner(ReleaseJournalOwnerV1 {
        journal_id: journal_id.clone(),
        ownership_token: started.ownership_token.clone(),
    }))
    .unwrap_or_else(|error| panic!("fixture owner release failed: {error:?}"));
    assert_eq!(storage.release_count(), 1);

    let resume_executor = Arc::new(DeterministicConcurrentExecutor::default());
    let terminal_gate = Arc::new(DeliveryGate::default());
    let resume_sink = Arc::new(DurableEvidenceSink {
        storage: Arc::clone(&storage),
        terminal_gate: Some(Arc::clone(&terminal_gate)),
    });
    let integration = Arc::new(ScriptedIntegration::new(
        [ScriptedPreflight::success(
            EmbeddingOperation::ResolveSessions,
            &br#"{"result":"resolved"}"#[..],
        )],
        [],
    ));
    let resumed = interpreter_with_durable_delivery(
        Arc::clone(&resume_executor),
        Arc::clone(&integration),
        97,
        Arc::new(ImmediateDurableDeliveryRuntime),
        durable_plan(resume_sink),
    );
    let mut resume = pin!(resumed.resume_durable_execution(
        Arc::clone(&storage_adapter),
        DurableResumeExecutionRequest {
            journal_id,
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
    poll_task_until(&resume_executor, 0, || terminal_gate.calls() == 1);
    assert_eq!(resume_executor.task_ids(), [0]);
    assert_eq!(storage.release_count(), 1);
    assert_eq!(
        integration
            .calls()
            .iter()
            .map(|call| call.operation)
            .collect::<Vec<_>>(),
        [EmbeddingOperation::ResolveSessions]
    );

    terminal_gate.release();
    settle_task(&resume_executor, 0);
    let accepted = match resume
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(DurableResumeExecutionResult::Accepted(accepted)) => accepted,
        Poll::Ready(DurableResumeExecutionResult::Rejected(failure)) => {
            panic!("delivery-only terminal resume was rejected: {failure:?}")
        }
        Poll::Pending => panic!("delivery-only terminal resume was not published"),
    };
    assert_eq!(resume_executor.task_ids(), [0]);
    assert_eq!(storage.release_count(), 2);
    let observation = block_on(accepted.owned.await_terminal());
    assert!(matches!(
        observation.terminal,
        Some(MachineOutcome::Succeeded(ref value))
            if matches!(value.view(), LogicalValueView::Int(value) if value.get() == 71)
    ));
}

#[test]
fn terminal_resume_accepts_without_submitting_a_root_driver() {
    let root = TempDirectory::new("fn main() -> Int { 73 }");
    let initial_executor = Arc::new(DeterministicConcurrentExecutor::default());
    let initial = interpreter(Arc::clone(&initial_executor));
    let storage = Arc::new(InMemoryJournalStore::new());
    let storage_adapter: Arc<dyn JournalStorage> = storage.clone();
    let journal_id = JournalId::new("automatic-durable-terminal-resume")
        .unwrap_or_else(|error| panic!("journal identity failed: {error:?}"));
    let selection = selection();
    let started = match block_on(initial.start_durable_execution(
        Arc::clone(&storage_adapter),
        DurableStartExecutionRequest {
            journal_id: journal_id.clone(),
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
            panic!("terminal-resume fixture start failed: {failure:?}")
        }
    };
    let execution_id = started.start.execution_id;
    settle_task(&initial_executor, 0);

    let resume_executor = Arc::new(DeterministicConcurrentExecutor::default());
    let resumed = interpreter_with_integration_and_identity_start(
        Arc::clone(&resume_executor),
        Arc::new(ScriptedIntegration::new(
            [ScriptedPreflight::success(
                EmbeddingOperation::ResolveSessions,
                &br#"{"result":"resolved"}"#[..],
            )],
            [],
        )),
        97,
    );
    let mut resume = pin!(resumed.resume_durable_execution(
        Arc::clone(&storage_adapter),
        DurableResumeExecutionRequest {
            journal_id,
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
    settle_task(&resume_executor, 0);
    let accepted = match resume
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(DurableResumeExecutionResult::Accepted(accepted)) => accepted,
        Poll::Ready(DurableResumeExecutionResult::Rejected(failure)) => {
            panic!("terminal resume was rejected: {failure:?}")
        }
        Poll::Pending => panic!("terminal resume acceptance was not published"),
    };
    assert_eq!(resume_executor.task_ids(), [0]);
    let observation = block_on(accepted.owned.await_terminal());
    assert!(matches!(
        observation.terminal,
        Some(MachineOutcome::Succeeded(ref value))
            if matches!(value.view(), LogicalValueView::Int(value) if value.get() == 73)
    ));
}

#[test]
fn resume_runnable_capacity_refusal_releases_owner_without_mutating_the_prefix() {
    let root = TempDirectory::new("fn main() -> Int { 89 }");
    let integration = Arc::new(ScriptedIntegration::new(
        [ScriptedPreflight::success(
            EmbeddingOperation::ResolveSessions,
            &br#"{"result":"resolved"}"#[..],
        )],
        [],
    ));
    let initial_executor = Arc::new(DeterministicConcurrentExecutor::default());
    let initial = interpreter_with_integration(Arc::clone(&initial_executor), integration.clone());
    let storage = Arc::new(FailAfterStartStore::default());
    let storage_adapter: Arc<dyn JournalStorage> = storage.clone();
    let journal_id = JournalId::new("automatic-durable-resume-capacity")
        .unwrap_or_else(|error| panic!("journal identity failed: {error:?}"));
    let selection = selection();
    let started = match block_on(initial.start_durable_execution(
        Arc::clone(&storage_adapter),
        DurableStartExecutionRequest {
            journal_id: journal_id.clone(),
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
            panic!("resume-capacity fixture start failed: {failure:?}")
        }
    };
    let execution_id = started.start.execution_id;
    let prefix_before_resume = block_on(storage.read_prefix(ReadJournalPrefixV1 {
        journal_id: journal_id.clone(),
    }))
    .unwrap_or_else(|error| panic!("journal read failed: {error:?}"));
    block_on(storage.release_owner(ReleaseJournalOwnerV1 {
        journal_id: journal_id.clone(),
        ownership_token: started.ownership_token.clone(),
    }))
    .unwrap_or_else(|error| panic!("fixture owner release failed: {error:?}"));

    let resume_executor = Arc::new(DeterministicConcurrentExecutor::default());
    let (resumed, _capacity) =
        interpreter_with_reserved_resume_capacity(Arc::clone(&resume_executor), integration, 97);
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
    settle_task(&resume_executor, 0);
    let rejected = match resume
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(DurableResumeExecutionResult::Rejected(failure)) => failure,
        Poll::Ready(DurableResumeExecutionResult::Accepted(_)) => {
            panic!("capacity-refused resume was accepted")
        }
        Poll::Pending => panic!("capacity refusal was not published"),
    };
    assert_eq!(
        rejected.category,
        gantry::portable::ResumeStartFailureCategory::ImplementationResourceExhaustion
    );
    assert_eq!(rejected.code.as_ref(), "resume-runnable-task-capacity");
    assert!(rejected.release_error.is_none());
    assert_eq!(resume_executor.task_ids(), [0]);
    assert_eq!(storage.release_count(), 2);
    assert_eq!(
        block_on(storage.read_prefix(ReadJournalPrefixV1 { journal_id }))
            .unwrap_or_else(|error| panic!("journal read failed: {error:?}")),
        prefix_before_resume
    );
}

#[test]
fn durable_operation_cuts_commit_before_dispatch_and_source_consumption() {
    let root = TempDirectory::new(
        "action read_only lookup(value: Int) -> String;\nfn main() -> String { action lookup(7) }",
    );
    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    let integration = Arc::new(ScriptedIntegration::new(
        [ScriptedPreflight::success(
            EmbeddingOperation::ResolveMappings,
            &br#"{"action_mapping_revision":"actions-v1","result":"resolved"}"#[..],
        )],
        [ScriptedHook::created([Ok(HookOutcomeV1::Completed(
            Arc::from(&br#""done""#[..]),
        ))])],
    ));
    let interpreter = interpreter_with_integration(Arc::clone(&executor), integration.clone());
    let storage = Arc::new(InMemoryJournalStore::new());
    let storage_adapter: Arc<dyn JournalStorage> = storage.clone();
    let journal_id = JournalId::new("automatic-durable-operation")
        .unwrap_or_else(|error| panic!("journal identity failed: {error:?}"));
    let selection = selection();

    let accepted = match block_on(interpreter.start_durable_execution(
        Arc::clone(&storage_adapter),
        DurableStartExecutionRequest {
            journal_id: journal_id.clone(),
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
            panic!("automatic durable operation start was rejected: {failure:?}")
        }
    };
    settle_task(&executor, 0);

    let observation = block_on(accepted.owned.await_terminal());
    assert!(
        matches!(
            observation.terminal,
            Some(MachineOutcome::Succeeded(ref value))
                if matches!(value.view(), LogicalValueView::String("done"))
        ),
        "unexpected durable operation observation: {observation:?}"
    );
    assert_eq!(
        integration
            .calls()
            .iter()
            .map(|call| call.operation)
            .collect::<Vec<_>>(),
        [
            EmbeddingOperation::ResolveMappings,
            EmbeddingOperation::CreateHook,
            EmbeddingOperation::DispatchOperation,
        ]
    );

    let prefix = block_on(storage.read_prefix(ReadJournalPrefixV1 { journal_id }))
        .unwrap_or_else(|error| panic!("journal read failed: {error:?}"));
    let JournalPrefixV1::Full(full) = &prefix else {
        panic!("in-memory journal returned a compacted prefix")
    };
    let (program, recovered) = recover_authoritative_prefix_with_retained_program(&prefix)
        .unwrap_or_else(|error| panic!("operation prefix did not recover: {error:?}"));
    let cuts = full
        .evidence
        .iter()
        .skip(1)
        .filter(|entry| entry.kind.as_ref() == "gantry.logical-evidence/v1")
        .map(|entry| {
            DurableLogicalEvidenceV1::decode(&program, &entry.canonical_body)
                .unwrap_or_else(|error| panic!("operation evidence did not decode: {error:?}"))
                .cut()
        })
        .collect::<Vec<_>>();
    assert!(
        cuts.windows(3).any(|window| {
            window
                == [
                    DurableCommitCutV1::OperationPrepared,
                    DurableCommitCutV1::OperationOutcome,
                    DurableCommitCutV1::OperationResult,
                ]
        }),
        "operation cuts were not contiguous: {cuts:?}"
    );
    let events = full
        .evidence
        .iter()
        .filter(|entry| entry.kind.as_ref() == "gantry.event-occurrence/v1")
        .map(|entry| {
            let occurrence = DurableEventOccurrenceV1::decode(&entry.canonical_body)
                .unwrap_or_else(|error| panic!("event occurrence did not decode: {error:?}"));
            (occurrence.causal_evidence_id(), occurrence.event().kind())
        })
        .collect::<Vec<_>>();
    let causal_cuts = full
        .evidence
        .iter()
        .filter(|entry| entry.kind.as_ref() == "gantry.logical-evidence/v1")
        .filter_map(|entry| {
            let evidence = DurableLogicalEvidenceV1::decode(&program, &entry.canonical_body)
                .unwrap_or_else(|error| panic!("causal evidence did not decode: {error:?}"));
            matches!(
                evidence.cut(),
                DurableCommitCutV1::OperationPrepared
                    | DurableCommitCutV1::OperationOutcome
                    | DurableCommitCutV1::OperationResult
                    | DurableCommitCutV1::TaskSettlement
                    | DurableCommitCutV1::ForegroundCompletion
                    | DurableCommitCutV1::TerminalCompletion
            )
            .then_some(entry.evidence_id)
        })
        .collect::<Vec<_>>();
    assert_eq!(
        events.iter().map(|(cause, _)| *cause).collect::<Vec<_>>(),
        causal_cuts
    );
    assert_eq!(
        events.iter().map(|(_, kind)| *kind).collect::<Vec<_>>(),
        [
            EventKind::OperationDispatch,
            EventKind::OperationCompletion,
            EventKind::OperationResult,
            EventKind::TaskCompletion,
            EventKind::ForegroundCompletion,
            EventKind::TerminalExecution,
        ]
    );
    assert_eq!(
        recovered.latest_cut(),
        DurableCommitCutV1::TerminalCompletion
    );
}

#[test]
fn preterminal_required_delivery_exhaustion_commits_runtime_failure_precedence() {
    let root = TempDirectory::new(
        "action read_only lookup(value: Int) -> String;\nfn main() -> String { action lookup(7) }",
    );
    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    let integration = Arc::new(ScriptedIntegration::new(
        [ScriptedPreflight::success(
            EmbeddingOperation::ResolveMappings,
            &br#"{"action_mapping_revision":"actions-v1","result":"resolved"}"#[..],
        )],
        [ScriptedHook::created([Ok(HookOutcomeV1::Completed(
            Arc::from(&br#""done""#[..]),
        ))])],
    ));
    let sink = Arc::new(SelectiveOutcomeSink {
        failed_kind: EventKind::OperationDispatch,
        attempts: Mutex::new(Vec::new()),
    });
    let interpreter = interpreter_with_durable_delivery(
        Arc::clone(&executor),
        integration.clone(),
        1,
        Arc::new(ImmediateDurableDeliveryRuntime),
        durable_plan(sink.clone()),
    );
    let storage = Arc::new(InMemoryJournalStore::new());
    let storage_adapter: Arc<dyn JournalStorage> = storage.clone();
    let journal_id = JournalId::new("automatic-durable-required-delivery-failure")
        .unwrap_or_else(|error| panic!("journal identity failed: {error:?}"));
    let selection = selection();

    let accepted = match block_on(interpreter.start_durable_execution(
        storage_adapter,
        DurableStartExecutionRequest {
            journal_id: journal_id.clone(),
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
            panic!("required-delivery fixture was rejected: {failure:?}")
        }
    };
    let root_task_id = *executor
        .task_ids()
        .last()
        .unwrap_or_else(|| panic!("accepted durable execution submitted no root task"));
    for _ in 0..256 {
        match executor
            .poll_task(root_task_id)
            .unwrap_or_else(|error| panic!("required-delivery root poll failed: {error:?}"))
        {
            DeterministicTaskPoll::Settled(_) => break,
            DeterministicTaskPoll::Pending | DeterministicTaskPoll::NotRunnable => {}
            other => panic!("required-delivery root settled abnormally: {other:?}"),
        }
    }
    assert!(
        matches!(
            executor.poll_task(root_task_id),
            Ok(DeterministicTaskPoll::Settled(_))
        ),
        "required-delivery root did not settle: {:?}",
        accepted.owned.observation()
    );

    let observation = block_on(accepted.owned.await_terminal());
    assert!(
        matches!(
            observation.terminal,
            Some(MachineOutcome::Failed(ref failure))
                if failure.code
                    == RuntimeCode::Operation(RuntimeErrorCategory::RequiredEventDeliveryFailure)
        ),
        "unexpected required-delivery outcome: {observation:?}"
    );
    assert_eq!(observation.required_delivery_failures.len(), 1);
    let failed = &observation.required_delivery_failures[0];
    let attempts = sink.attempts();
    let (_, event_id, attempt_id) = attempts
        .iter()
        .find(|(kind, _, _)| *kind == EventKind::OperationDispatch)
        .copied()
        .unwrap_or_else(|| panic!("operation-dispatch delivery was not attempted"));
    assert_eq!(failed.event_id, event_id);
    assert_eq!(failed.attempt_id, attempt_id);
    assert_eq!(failed.sink_id.as_str(), "durable-revent-sink");
    assert_eq!(
        integration
            .calls()
            .iter()
            .map(|call| call.operation)
            .collect::<Vec<_>>(),
        [EmbeddingOperation::ResolveMappings]
    );

    let prefix = block_on(storage.read_prefix(ReadJournalPrefixV1 { journal_id }))
        .unwrap_or_else(|error| panic!("journal read failed: {error:?}"));
    let (_, recovered) = recover_authoritative_prefix_with_retained_program(&prefix)
        .unwrap_or_else(|error| panic!("required-delivery prefix did not recover: {error:?}"));
    assert_eq!(
        recovered.latest_cut(),
        DurableCommitCutV1::TerminalCompletion
    );
    assert!(matches!(
        recovered.machine().outcome(),
        Some(MachineOutcome::Failed(failure))
            if failure.code
                == RuntimeCode::Operation(RuntimeErrorCategory::RequiredEventDeliveryFailure)
    ));
}

#[test]
fn resume_reconstructs_committed_required_delivery_failure_before_source_progress() {
    let root = TempDirectory::new(
        "action read_only lookup(value: Int) -> String;\nfn main() -> String { action lookup(11) }",
    );
    let initial_executor = Arc::new(DeterministicConcurrentExecutor::default());
    let initial_integration = Arc::new(ScriptedIntegration::new(
        [ScriptedPreflight::success(
            EmbeddingOperation::ResolveMappings,
            &br#"{"action_mapping_revision":"actions-v1","result":"resolved"}"#[..],
        )],
        [ScriptedHook::created([Ok(HookOutcomeV1::Completed(
            Arc::from(&br#""unexpected""#[..]),
        ))])],
    ));
    let sink = Arc::new(SelectiveOutcomeSink {
        failed_kind: EventKind::OperationDispatch,
        attempts: Mutex::new(Vec::new()),
    });
    let initial = interpreter_with_durable_delivery(
        Arc::clone(&initial_executor),
        Arc::clone(&initial_integration),
        1,
        Arc::new(ImmediateDurableDeliveryRuntime),
        durable_plan(sink.clone()),
    );
    let storage = Arc::new(ObservedJournalStore::with_post_commit_settlement_gate(1));
    let storage_adapter: Arc<dyn JournalStorage> = storage.clone();
    let journal_id = JournalId::new("automatic-durable-revent-post-commit-resume")
        .unwrap_or_else(|error| panic!("journal identity failed: {error:?}"));
    let selection = selection();
    let started = match block_on(initial.start_durable_execution(
        Arc::clone(&storage_adapter),
        DurableStartExecutionRequest {
            journal_id: journal_id.clone(),
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
            panic!("post-commit REVENT fixture was rejected: {failure:?}")
        }
    };
    let execution_id = started.start.execution_id;
    let initial_root_task_id = *initial_executor
        .task_ids()
        .last()
        .unwrap_or_else(|| panic!("accepted durable execution submitted no root task"));
    poll_task_until(&initial_executor, initial_root_task_id, || {
        storage.post_commit_settlement_started()
    });

    let attempts = sink.attempts();
    let operation_attempts = attempts
        .iter()
        .filter(|(kind, _, _)| *kind == EventKind::OperationDispatch)
        .copied()
        .collect::<Vec<_>>();
    assert_eq!(operation_attempts.len(), 1);
    let (_, failed_event_id, failed_attempt_id) = operation_attempts[0];
    assert_eq!(
        initial_integration
            .calls()
            .iter()
            .map(|call| call.operation)
            .collect::<Vec<_>>(),
        [EmbeddingOperation::ResolveMappings]
    );
    let prefix = block_on(storage.read_prefix(ReadJournalPrefixV1 {
        journal_id: journal_id.clone(),
    }))
    .unwrap_or_else(|error| panic!("post-commit journal read failed: {error:?}"));
    let JournalPrefixV1::Full(full) = &prefix else {
        panic!("in-memory journal returned a compacted prefix")
    };
    assert!(full.evidence.iter().any(|entry| {
        entry.kind.as_ref() == DURABLE_EVENT_SETTLED_KIND_V1
            && DurableEventSettledV1::decode(&entry.canonical_body).is_ok_and(|settled| {
                settled.event_id() == failed_event_id
                    && settled.attempt_id() == failed_attempt_id
                    && settled.outcome() == DeliveryOutcome::Terminal
            })
    }));
    let (_, recovered) = recover_authoritative_prefix_with_retained_program(&prefix)
        .unwrap_or_else(|error| panic!("post-commit prefix did not recover: {error:?}"));
    assert_eq!(
        recovered.latest_cut(),
        DurableCommitCutV1::OperationPrepared
    );

    initial_executor
        .fail_task(initial_root_task_id)
        .unwrap_or_else(|error| panic!("could not stop simulated crashed driver: {error:?}"));
    storage.release_post_commit_settlement();
    block_on(storage.release_owner(ReleaseJournalOwnerV1 {
        journal_id: journal_id.clone(),
        ownership_token: started.ownership_token.clone(),
    }))
    .unwrap_or_else(|error| panic!("fixture owner release failed: {error:?}"));
    assert_eq!(storage.release_count(), 1);

    let resume_executor = Arc::new(DeterministicConcurrentExecutor::default());
    let resume_integration = Arc::new(ScriptedIntegration::new(
        [
            ScriptedPreflight::success(
                EmbeddingOperation::ResolveMappings,
                &br#"{"action_mapping_revision":"actions-v1","result":"resolved"}"#[..],
            ),
            ScriptedPreflight::success(
                EmbeddingOperation::ResolveSessions,
                &br#"{"result":"resolved"}"#[..],
            ),
        ],
        [ScriptedHook::created([Ok(HookOutcomeV1::Completed(
            Arc::from(&br#""unexpected""#[..]),
        ))])],
    ));
    let resumed = interpreter_with_durable_delivery(
        Arc::clone(&resume_executor),
        Arc::clone(&resume_integration),
        97,
        Arc::new(ImmediateDurableDeliveryRuntime),
        durable_plan(sink.clone()),
    );
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
    let accepted = match resume
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(DurableResumeExecutionResult::Accepted(accepted)) => accepted,
        Poll::Ready(DurableResumeExecutionResult::Rejected(failure)) => {
            panic!("post-commit REVENT resume was rejected: {failure:?}")
        }
        Poll::Pending => {
            settle_task(&resume_executor, 0);
            match resume
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
            {
                Poll::Ready(DurableResumeExecutionResult::Accepted(accepted)) => accepted,
                Poll::Ready(DurableResumeExecutionResult::Rejected(failure)) => {
                    panic!("post-commit REVENT resume was rejected: {failure:?}")
                }
                Poll::Pending => panic!("post-commit REVENT resume was not published"),
            }
        }
    };
    assert_eq!(storage.release_count(), 1);
    assert_eq!(resume_executor.task_ids(), [0, 1]);

    settle_task(&resume_executor, 1);
    let observation = block_on(accepted.owned.await_terminal());
    assert!(matches!(
        observation.terminal,
        Some(MachineOutcome::Failed(ref failure))
            if failure.code
                == RuntimeCode::Operation(RuntimeErrorCategory::RequiredEventDeliveryFailure)
    ));
    assert_eq!(
        observation.latest_cut(),
        DurableCommitCutV1::TerminalCompletion
    );
    assert_eq!(observation.required_delivery_failures.len(), 1);
    let failed = &observation.required_delivery_failures[0];
    assert_eq!(failed.event_id, failed_event_id);
    assert_eq!(failed.attempt_id, failed_attempt_id);
    assert_eq!(failed.sink_id.as_str(), "durable-revent-sink");
    assert_eq!(
        resume_integration
            .calls()
            .iter()
            .map(|call| call.operation)
            .collect::<Vec<_>>(),
        [
            EmbeddingOperation::ResolveMappings,
            EmbeddingOperation::ResolveSessions,
        ]
    );
    assert_eq!(
        sink.attempts()
            .iter()
            .filter(|(kind, _, _)| *kind == EventKind::OperationDispatch)
            .count(),
        1
    );
    assert_eq!(storage.release_count(), 2);

    let prefix = block_on(storage.read_prefix(ReadJournalPrefixV1 { journal_id }))
        .unwrap_or_else(|error| panic!("resumed journal read failed: {error:?}"));
    let (_, recovered) = recover_authoritative_prefix_with_retained_program(&prefix)
        .unwrap_or_else(|error| panic!("resumed prefix did not recover: {error:?}"));
    assert_eq!(
        recovered.latest_cut(),
        DurableCommitCutV1::TerminalCompletion
    );
    assert!(matches!(
        recovered.machine().outcome(),
        Some(MachineOutcome::Failed(failure))
            if failure.code
                == RuntimeCode::Operation(RuntimeErrorCategory::RequiredEventDeliveryFailure)
    ));
}

#[test]
fn durable_lexical_session_state_commits_before_source_progress() {
    let root = TempDirectory::new(
        "agents { worker }\ndefault agent = worker;\nfn main() { session(fork) { discard prompt \"first\" -> String; discard prompt \"second\" -> String; } }",
    );
    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    let integration = Arc::new(ScriptedIntegration::new(
        [
            ScriptedPreflight::success(
                EmbeddingOperation::ResolveMappings,
                &br#"{"agent_mapping_revision":"agents-v1","result":"resolved"}"#[..],
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
        [ScriptedHook::created([
            Ok(HookOutcomeV1::Completed(Arc::from(&br#""one""#[..]))),
            Ok(HookOutcomeV1::Completed(Arc::from(&br#""two""#[..]))),
        ])],
    ));
    let interpreter = interpreter_with_integration(Arc::clone(&executor), integration.clone());
    let storage = Arc::new(InMemoryJournalStore::new());
    let storage_adapter: Arc<dyn JournalStorage> = storage.clone();
    let journal_id = JournalId::new("automatic-durable-session")
        .unwrap_or_else(|error| panic!("journal identity failed: {error:?}"));
    let selection = selection();

    let accepted = match block_on(interpreter.start_durable_execution(
        Arc::clone(&storage_adapter),
        DurableStartExecutionRequest {
            journal_id: journal_id.clone(),
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
            panic!("automatic durable session start was rejected: {failure:?}")
        }
    };
    settle_task(&executor, 0);

    let observation = block_on(accepted.owned.await_terminal());
    assert!(
        matches!(
            observation.terminal,
            Some(MachineOutcome::Succeeded(ref value))
                if matches!(value.view(), LogicalValueView::Unit)
        ),
        "unexpected durable session observation: {observation:?}"
    );
    let calls = integration
        .calls()
        .into_iter()
        .map(|call| call.operation)
        .collect::<Vec<_>>();
    assert_eq!(
        calls,
        [
            EmbeddingOperation::ResolveMappings,
            EmbeddingOperation::EstablishSession,
            EmbeddingOperation::EstablishSession,
            EmbeddingOperation::CreateHook,
            EmbeddingOperation::DispatchOperation,
            EmbeddingOperation::DispatchOperation,
        ]
    );

    let prefix = block_on(storage.read_prefix(ReadJournalPrefixV1 { journal_id }))
        .unwrap_or_else(|error| panic!("journal read failed: {error:?}"));
    let JournalPrefixV1::Full(full) = &prefix else {
        panic!("in-memory journal returned a compacted prefix")
    };
    let program = full
        .evidence
        .first()
        .and_then(|entry| {
            gantry::runtime::DurableExecutionStartV1::retained_program(&entry.canonical_body).ok()
        })
        .unwrap_or_else(|| panic!("session prefix omitted its retained program"));
    let session_counts = full
        .evidence
        .iter()
        .skip(1)
        .filter(|entry| entry.kind.as_ref() == "gantry.logical-evidence/v1")
        .map(|entry| {
            let evidence = DurableLogicalEvidenceV1::decode(&program, &entry.canonical_body)
                .unwrap_or_else(|error| panic!("session evidence did not decode: {error:?}"));
            (
                entry.sequence,
                evidence.cut(),
                evidence.sessions().map(|sessions| sessions.session_count()),
            )
        })
        .collect::<Vec<_>>();
    let (_, recovered) = recover_authoritative_prefix_with_retained_program(&prefix)
        .unwrap_or_else(|error| panic!("session prefix did not recover: {error:?}"));
    assert_eq!(
        recovered
            .sessions()
            .map(|sessions| sessions.sessions().count()),
        Some(2),
        "unexpected session projections: {session_counts:?}"
    );
    assert_eq!(
        recovered.latest_cut(),
        DurableCommitCutV1::TerminalCompletion
    );
}

#[test]
fn durable_submission_failure_commits_terminal_root_failure_after_acceptance() {
    let root = TempDirectory::new("fn main() -> Int { 7 }");
    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    executor.fail_next_spawn();
    let interpreter = interpreter(Arc::clone(&executor));
    let storage = Arc::new(InMemoryJournalStore::new());
    let storage_adapter: Arc<dyn JournalStorage> = storage.clone();
    let journal_id = JournalId::new("automatic-durable-submission-failure")
        .unwrap_or_else(|error| panic!("journal identity failed: {error:?}"));
    let selection = selection();

    let accepted = match block_on(interpreter.start_durable_execution(
        Arc::clone(&storage_adapter),
        DurableStartExecutionRequest {
            journal_id: journal_id.clone(),
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
            panic!("post-acceptance submission failure was rejected: {failure:?}")
        }
    };
    assert_eq!(executor.task_ids(), [0]);
    settle_task(&executor, 0);

    let observation = block_on(accepted.owned.await_terminal());
    assert!(
        matches!(
            observation.terminal,
            Some(MachineOutcome::Failed(ref failure))
                if failure.code == gantry::runtime::RuntimeCode::RootSubmissionFailure
        ),
        "unexpected durable submission observation: {observation:?}"
    );
    assert_eq!(
        observation.latest_cut(),
        DurableCommitCutV1::TerminalCompletion
    );
    let prefix = block_on(storage.read_prefix(ReadJournalPrefixV1 { journal_id }))
        .unwrap_or_else(|error| panic!("journal read failed: {error:?}"));
    let (_, recovered) = recover_authoritative_prefix_with_retained_program(&prefix)
        .unwrap_or_else(|error| panic!("submission failure prefix did not recover: {error:?}"));
    assert_eq!(
        recovered.latest_cut(),
        DurableCommitCutV1::TerminalCompletion
    );
}

#[test]
fn durable_commit_failure_reports_run_failure_and_preserves_sequence_one() {
    let root = TempDirectory::new("fn main() -> Int { 9 }");
    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    let interpreter = interpreter(Arc::clone(&executor));
    let storage = Arc::new(FailAfterStartStore::default());
    let storage_adapter: Arc<dyn JournalStorage> = storage.clone();
    let journal_id = JournalId::new("automatic-durable-commit-failure")
        .unwrap_or_else(|error| panic!("journal identity failed: {error:?}"));
    let selection = selection();

    let accepted = match block_on(interpreter.start_durable_execution(
        Arc::clone(&storage_adapter),
        DurableStartExecutionRequest {
            journal_id: journal_id.clone(),
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
            panic!("durable commit-failure fixture was rejected: {failure:?}")
        }
    };
    settle_task(&executor, 0);

    let observation = block_on(accepted.owned.await_terminal());
    assert_eq!(
        observation.state,
        ExecutionObservationState::RunFailedNondurably
    );
    assert!(observation.foreground.is_none());
    assert!(observation.terminal.is_none());
    assert!(observation.run_failure.is_some());
    assert_eq!(observation.latest_sequence, 1);

    let prefix = block_on(storage.read_prefix(ReadJournalPrefixV1 { journal_id }))
        .unwrap_or_else(|error| panic!("journal read failed: {error:?}"));
    let JournalPrefixV1::Full(full) = prefix else {
        panic!("in-memory journal returned a compacted prefix")
    };
    assert_eq!(full.committed_through, 1);
    assert_eq!(full.evidence.len(), 1);
}

fn interpreter(executor: Arc<DeterministicConcurrentExecutor>) -> Interpreter {
    let integration = Arc::new(ScriptedIntegration::new([], []));
    interpreter_with_integration(executor, integration)
}

fn interpreter_with_integration<I>(
    executor: Arc<DeterministicConcurrentExecutor>,
    integration: Arc<I>,
) -> Interpreter
where
    I: IntegrationPreflight + RuntimeSessionService + HookFactory + 'static,
{
    interpreter_with_integration_and_identity_start(executor, integration, 1)
}

fn interpreter_with_integration_and_identity_start<I>(
    executor: Arc<DeterministicConcurrentExecutor>,
    integration: Arc<I>,
    identity_start: u8,
) -> Interpreter
where
    I: IntegrationPreflight + RuntimeSessionService + HookFactory + 'static,
{
    interpreter_with_capacities(executor, integration, identity_start, 8, 8)
}

fn interpreter_with_durable_delivery<I>(
    executor: Arc<DeterministicConcurrentExecutor>,
    integration: Arc<I>,
    identity_start: u8,
    runtime: Arc<dyn EventDeliveryRuntime>,
    event_delivery: SinkPlan,
) -> Interpreter
where
    I: IntegrationPreflight + RuntimeSessionService + HookFactory + 'static,
{
    executor.poll_next_spawn_immediately();
    let executor_adapter: Arc<dyn ExecutorAdapter> = executor;
    let identities: Arc<dyn IdentitySource> = Arc::new(DeterministicIdentitySource::new(
        std::iter::successors(Some(identity_start), |byte| byte.checked_add(1))
            .take(96)
            .map(|byte| Ok([byte; 32])),
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
        1,
    )
    .unwrap_or_else(|error| panic!("required configuration failed: {error}"));
    let configuration = InterpreterConfiguration::new(
        executor_adapter,
        identities,
        required,
        AsyncCapacityLimits::new(2, 8, 8, 8, 8, 8, 8, 8, 8)
            .unwrap_or_else(|error| panic!("capacity configuration failed: {error}")),
    );
    Interpreter::new_with_event_delivery(
        configuration,
        Arc::new(DeterministicUtcClock::new((1_u32..=96).map(timestamp))),
        integration.clone(),
        integration.clone(),
        integration,
        runtime,
        event_delivery,
    )
}

fn interpreter_with_capacities<I>(
    executor: Arc<DeterministicConcurrentExecutor>,
    integration: Arc<I>,
    identity_start: u8,
    resume_runnable_tasks: u64,
    public_activities: u64,
) -> Interpreter
where
    I: IntegrationPreflight + RuntimeSessionService + HookFactory + 'static,
{
    let executor_adapter: Arc<dyn ExecutorAdapter> = executor;
    let identities: Arc<dyn IdentitySource> = Arc::new(DeterministicIdentitySource::new(
        std::iter::successors(Some(identity_start), |byte| byte.checked_add(1))
            .take(96)
            .map(|byte| Ok([byte; 32])),
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
        1,
    )
    .unwrap_or_else(|error| panic!("required configuration failed: {error}"));
    let configuration = InterpreterConfiguration::new(
        executor_adapter,
        identities,
        required,
        AsyncCapacityLimits::new(
            2,
            8,
            resume_runnable_tasks,
            public_activities,
            8,
            8,
            8,
            8,
            8,
        )
        .unwrap_or_else(|error| panic!("capacity configuration failed: {error}")),
    );
    Interpreter::new(
        configuration,
        Arc::new(DeterministicUtcClock::new((1_u32..=96).map(timestamp))),
        integration.clone(),
        integration.clone(),
        integration,
    )
}

fn interpreter_with_reserved_resume_capacity(
    executor: Arc<DeterministicConcurrentExecutor>,
    integration: Arc<ScriptedIntegration>,
    identity_start: u8,
) -> (Interpreter, gantry::runtime::AdmissionReservation) {
    let executor_adapter: Arc<dyn ExecutorAdapter> = executor;
    let identities: Arc<dyn IdentitySource> = Arc::new(DeterministicIdentitySource::new(
        std::iter::successors(Some(identity_start), |byte| byte.checked_add(1))
            .take(96)
            .map(|byte| Ok([byte; 32])),
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
        1,
    )
    .unwrap_or_else(|error| panic!("required configuration failed: {error}"));
    let configuration = InterpreterConfiguration::new(
        executor_adapter,
        identities,
        required,
        AsyncCapacityLimits::new(2, 8, 1, 8, 8, 8, 8, 8, 8)
            .unwrap_or_else(|error| panic!("capacity configuration failed: {error}")),
    );
    let reservation = configuration
        .async_admission()
        .try_reserve(gantry::runtime::AdmissionRequest::single(
            gantry::runtime::AdmissionClass::ResumeRunnableTask,
            1,
        ))
        .unwrap_or_else(|error| panic!("resume capacity reservation failed: {error}"));
    let interpreter = Interpreter::new(
        configuration,
        Arc::new(DeterministicUtcClock::new((1_u32..=96).map(timestamp))),
        integration.clone(),
        integration.clone(),
        integration,
    );
    (interpreter, reservation)
}

fn settle_task(executor: &DeterministicConcurrentExecutor, task_id: u64) {
    loop {
        match executor
            .poll_task(task_id)
            .unwrap_or_else(|error| panic!("durable root poll failed: {error:?}"))
        {
            DeterministicTaskPoll::Pending | DeterministicTaskPoll::NotRunnable => {
                std::thread::yield_now();
            }
            DeterministicTaskPoll::Settled(_) => break,
            other => panic!("durable root settled abnormally: {other:?}"),
        }
    }
}

fn poll_task_until(
    executor: &DeterministicConcurrentExecutor,
    task_id: u64,
    predicate: impl Fn() -> bool,
) {
    for _ in 0..64 {
        if predicate() {
            return;
        }
        match executor
            .poll_task(task_id)
            .unwrap_or_else(|error| panic!("durable task poll failed: {error:?}"))
        {
            DeterministicTaskPoll::Pending => {}
            DeterministicTaskPoll::NotRunnable => std::thread::yield_now(),
            other => panic!("durable task settled before the expected gate: {other:?}"),
        }
    }
    panic!("durable task did not reach the expected gate");
}

fn durable_plan(sink: Arc<dyn EventSink>) -> SinkPlan {
    let retry = EventRetryPolicy::new("durable-revent-retry-v1", 0, 0, 0, JitterMode::None)
        .unwrap_or_else(|error| panic!("retry policy failed: {error:?}"));
    let policy = SinkDeliveryPolicy::new(
        SinkClass::Required,
        false,
        "durable-revent-redaction-v1",
        RedactionCapabilities::default(),
        retry,
        30,
    )
    .unwrap_or_else(|error| panic!("sink policy failed: {error:?}"));
    SinkPlan::new(vec![SinkRegistration::new(
        SinkId::new("durable-revent-sink")
            .unwrap_or_else(|error| panic!("sink identity failed: {error:?}")),
        policy,
        sink,
    )])
    .unwrap_or_else(|error| panic!("sink plan failed: {error:?}"))
}

fn durable_required_and_best_effort_plan(
    required_sink: Arc<dyn EventSink>,
    best_effort_sink: Arc<dyn EventSink>,
) -> SinkPlan {
    let registration = |id, class, sink| {
        let retry = EventRetryPolicy::new("durable-revent-retry-v1", 0, 0, 0, JitterMode::None)
            .unwrap_or_else(|error| panic!("retry policy failed: {error:?}"));
        let policy = SinkDeliveryPolicy::new(
            class,
            false,
            "durable-revent-redaction-v1",
            RedactionCapabilities::default(),
            retry,
            30,
        )
        .unwrap_or_else(|error| panic!("sink policy failed: {error:?}"));
        SinkRegistration::new(
            SinkId::new(id).unwrap_or_else(|error| panic!("sink identity failed: {error:?}")),
            policy,
            sink,
        )
    };
    SinkPlan::new(vec![
        registration("a-durable-required", SinkClass::Required, required_sink),
        registration(
            "b-durable-best-effort",
            SinkClass::BestEffort,
            best_effort_sink,
        ),
    ])
    .unwrap_or_else(|error| panic!("sink plan failed: {error:?}"))
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

fn timestamp(microseconds: u32) -> Result<UtcTimestamp, gantry::host::contracts::HostError> {
    UtcTimestamp::from_unix_seconds(0, microseconds).map_err(|_| {
        gantry::host::contracts::HostError {
            code: Arc::from("clock-invariant"),
            protected_diagnostic: None,
        }
    })
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

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| unreachable!("conformance crate has a workspace root"))
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> T {
    let bytes =
        fs::read(path).unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|error| panic!("could not decode {}: {error}", path.display()))
}
