//! Tokio-backed public conformance coverage for overlapping source spawns.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Poll, Waker};
use std::time::Duration;

use gantry::host::contracts::{
    CancellationToken, EmbeddingVersion, ExecutorAdapter, HookFactory, HookOutcomeV1, HostError,
    HostFuture, HostRequest, HostResponse, IdentitySource, InclusiveJitterRange,
    IntegrationPreflight, JitterSource, OperationHook, RuntimeSessionService,
};
use gantry::host::embedding::EmbeddingOperation;
use gantry::host::event::{
    EventDeliveryRequest, EventDeliveryRuntime, EventRetryPolicy, EventSink, RedactionCapabilities,
    SinkDeliveryPolicy, SinkId,
};
use gantry::identity::ProtocolIdentity;
use gantry::observe::{SinkPlan, SinkRegistration};
use gantry::portable::{
    DeliveryOutcome, EventKind, HookFailureCategory, IdentityKind, JitterMode,
    PORTABLE_SPECIFICATION_REVISION, PROTOCOL_FAMILY_DEFINITIONS, RuntimeErrorCategory, SinkClass,
    TerminalOnlyCategory,
};
use gantry::protocol::{ProtocolSelection, ProtocolVersion, SelectedProtocol};
use gantry::runtime::{
    AsyncCapacityLimits, CancellationRecord, InterpreterConfiguration, MachineOutcome,
    RequiredConfiguration, RuntimeCode,
};
use gantry::source::FrontendLimits;
use gantry::timestamp::UtcTimestamp;
use gantry::value::DEFAULT_VALUE_LIMITS;
use gantry::{
    Interpreter, RootSessionSpecification, StartExecutionRequest, StartExecutionResult,
    caller_cancellation_reason, root_task_identity,
};
use gantry_adapter_tokio::TokioExecutor;
use gantry_conformance::services::{DeterministicIdentitySource, DeterministicUtcClock};
use serde_json::Value;
use tokio::runtime::{Builder, Runtime};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TempDirectory(PathBuf);

impl TempDirectory {
    fn new(source: &str) -> Self {
        let suffix = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "gantry-source-spawn-tokio-{}-{suffix}",
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

#[derive(Debug)]
struct FixedJitter;

impl JitterSource for FixedJitter {
    fn sample_inclusive(&self, range: InclusiveJitterRange) -> Result<u64, HostError> {
        Ok(range.minimum())
    }
}

#[derive(Default)]
struct RecordingSink {
    events: Mutex<Vec<gantry::event::EventEnvelope>>,
}

impl RecordingSink {
    fn events(&self) -> Vec<gantry::event::EventEnvelope> {
        lock(&self.events).clone()
    }
}

impl EventSink for RecordingSink {
    fn deliver<'a>(
        &'a self,
        request: EventDeliveryRequest,
    ) -> HostFuture<'a, Result<DeliveryOutcome, HostError>> {
        lock(&self.events).push(request.event);
        Box::pin(async { Ok(DeliveryOutcome::Success) })
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

#[derive(Default)]
struct PendingDispatch {
    started: AtomicBool,
    released: AtomicBool,
    completed: AtomicBool,
    request: Mutex<Option<Vec<u8>>>,
    waker: Mutex<Option<Waker>>,
    observations: Arc<DispatchObservations>,
}

impl PendingDispatch {
    fn release(&self) {
        self.observations.record_release(self.argument());
        self.released.store(true, Ordering::Release);
        if let Some(waker) = lock(&self.waker).take() {
            waker.wake();
        }
    }

    fn request(&self) -> Value {
        let bytes = lock(&self.request)
            .clone()
            .unwrap_or_else(|| panic!("pending dispatch has no recorded request"));
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|error| panic!("dispatch request was not JSON: {error}"))
    }

    fn argument(&self) -> Option<i64> {
        self.request()["operation_request"]["action"]["arguments"][0]["value"].as_i64()
    }
}

#[derive(Default)]
struct DispatchObservations {
    dispatch: Mutex<Vec<Option<i64>>>,
    release: Mutex<Vec<Option<i64>>>,
    completion: Mutex<Vec<Option<i64>>>,
}

impl DispatchObservations {
    fn record_dispatch(&self, argument: Option<i64>) {
        lock(&self.dispatch).push(argument);
    }

    fn record_release(&self, argument: Option<i64>) {
        lock(&self.release).push(argument);
    }

    fn record_completion(&self, argument: Option<i64>) {
        lock(&self.completion).push(argument);
    }

    fn diagnostic(&self) -> String {
        format!(
            "observed_dispatch={:?} observed_release={:?} observed_completion={:?}",
            lock(&self.dispatch),
            lock(&self.release),
            lock(&self.completion)
        )
    }
}

struct PendingIntegration {
    mapping_response: Arc<[u8]>,
    outcome: PendingOutcome,
    hook_requests: Mutex<Vec<Vec<u8>>>,
    dispatches: Mutex<Vec<Arc<PendingDispatch>>>,
    observations: Arc<DispatchObservations>,
}

#[derive(Clone)]
enum PendingOutcome {
    Fixed(Arc<[u8]>),
    EchoArgument,
    Fail,
}

impl PendingOutcome {
    fn resolve(&self, request: &Value) -> HookOutcomeV1 {
        match self {
            Self::Fixed(output) => HookOutcomeV1::Completed(Arc::clone(output)),
            Self::EchoArgument => {
                let value = &request["operation_request"]["action"]["arguments"][0]["value"];
                let output = serde_json::to_vec(value)
                    .unwrap_or_else(|error| panic!("could not encode echoed argument: {error}"));
                HookOutcomeV1::Completed(output.into())
            }
            Self::Fail => HookOutcomeV1::Failed {
                category: HookFailureCategory::ProviderFailure,
                message: Arc::from("selected child failed"),
            },
        }
    }
}

impl PendingIntegration {
    fn actions() -> Self {
        Self {
            mapping_response: Arc::from(
                &br#"{"action_mapping_revision":"actions-v1","result":"resolved"}"#[..],
            ),
            outcome: PendingOutcome::Fixed(Arc::from(&b"null"[..])),
            hook_requests: Mutex::new(Vec::new()),
            dispatches: Mutex::new(Vec::new()),
            observations: Arc::new(DispatchObservations::default()),
        }
    }

    fn models() -> Self {
        Self {
            mapping_response: Arc::from(
                &br#"{"agent_mapping_revision":"agents-v1","result":"resolved"}"#[..],
            ),
            outcome: PendingOutcome::Fixed(Arc::from(&br#""done""#[..])),
            hook_requests: Mutex::new(Vec::new()),
            dispatches: Mutex::new(Vec::new()),
            observations: Arc::new(DispatchObservations::default()),
        }
    }

    fn echoing_actions() -> Self {
        Self {
            mapping_response: Arc::from(
                &br#"{"action_mapping_revision":"actions-v1","result":"resolved"}"#[..],
            ),
            outcome: PendingOutcome::EchoArgument,
            hook_requests: Mutex::new(Vec::new()),
            dispatches: Mutex::new(Vec::new()),
            observations: Arc::new(DispatchObservations::default()),
        }
    }

    fn failing_actions() -> Self {
        Self {
            mapping_response: Arc::from(
                &br#"{"action_mapping_revision":"actions-v1","result":"resolved"}"#[..],
            ),
            outcome: PendingOutcome::Fail,
            hook_requests: Mutex::new(Vec::new()),
            dispatches: Mutex::new(Vec::new()),
            observations: Arc::new(DispatchObservations::default()),
        }
    }

    fn dispatches(&self) -> Vec<Arc<PendingDispatch>> {
        lock(&self.dispatches).clone()
    }

    fn hook_requests(&self) -> Vec<Value> {
        lock(&self.hook_requests)
            .iter()
            .map(|bytes| {
                serde_json::from_slice(bytes)
                    .unwrap_or_else(|error| panic!("hook request was not JSON: {error}"))
            })
            .collect()
    }

    fn order_diagnostic(&self) -> String {
        self.observations.diagnostic()
    }
}

impl IntegrationPreflight for PendingIntegration {
    fn call<'a>(&'a self, request: HostRequest) -> HostFuture<'a, Result<HostResponse, HostError>> {
        let operation = request.operation();
        let body = match operation {
            EmbeddingOperation::ResolveMappings => Arc::clone(&self.mapping_response),
            EmbeddingOperation::ResolveSessions => Arc::from(&br#"{"result":"resolved"}"#[..]),
            _ => return Box::pin(async { Err(host_error("unexpected-preflight-operation")) }),
        };
        Box::pin(async move {
            HostResponse::new(EmbeddingVersion::V1, operation, body)
                .map_err(|_| host_error("response-envelope"))
        })
    }
}

impl RuntimeSessionService for PendingIntegration {
    fn establish<'a>(
        &'a self,
        request: HostRequest,
    ) -> HostFuture<'a, Result<HostResponse, HostError>> {
        let operation = request.operation();
        Box::pin(async move {
            if operation != EmbeddingOperation::EstablishSession {
                return Err(host_error("unexpected-session-operation"));
            }
            HostResponse::new(
                EmbeddingVersion::V1,
                operation,
                Arc::from(&br#"{"result":"established"}"#[..]),
            )
            .map_err(|_| host_error("response-envelope"))
        })
    }
}

impl HookFactory for PendingIntegration {
    fn create_hook<'a>(
        &'a self,
        request: HostRequest,
    ) -> HostFuture<'a, Result<Box<dyn OperationHook>, HostError>> {
        lock(&self.hook_requests).push(request.canonical_bytes().to_vec());
        let state = Arc::new(PendingDispatch {
            observations: Arc::clone(&self.observations),
            ..PendingDispatch::default()
        });
        lock(&self.dispatches).push(Arc::clone(&state));
        let outcome = self.outcome.clone();
        Box::pin(
            async move { Ok(Box::new(PendingHook { state, outcome }) as Box<dyn OperationHook>) },
        )
    }
}

struct PendingHook {
    state: Arc<PendingDispatch>,
    outcome: PendingOutcome,
}

impl OperationHook for PendingHook {
    fn dispatch<'a>(
        &'a mut self,
        request: HostRequest,
        _cancellation: &'a dyn CancellationToken,
    ) -> HostFuture<'a, Result<HookOutcomeV1, HostError>> {
        *lock(&self.state.request) = Some(request.canonical_bytes().to_vec());
        self.state
            .observations
            .record_dispatch(self.state.argument());
        self.state.started.store(true, Ordering::Release);
        Box::pin(std::future::poll_fn(move |context| {
            if self.state.released.load(Ordering::Acquire) {
                self.state
                    .observations
                    .record_completion(self.state.argument());
                self.state.completed.store(true, Ordering::Release);
                Poll::Ready(Ok(self.outcome.resolve(&self.state.request())))
            } else {
                *lock(&self.state.waker) = Some(context.waker().clone());
                if self.state.released.load(Ordering::Acquire) {
                    lock(&self.state.waker).take();
                    self.state
                        .observations
                        .record_completion(self.state.argument());
                    self.state.completed.store(true, Ordering::Release);
                    Poll::Ready(Ok(self.outcome.resolve(&self.state.request())))
                } else {
                    Poll::Pending
                }
            }
        }))
    }
}

#[test]
fn current_thread_tokio_overlaps_sibling_hooks_with_shared_site_capture_isolation() {
    run_sibling_overlap(current_thread_runtime());
}

#[test]
fn multithread_tokio_overlaps_sibling_hooks_with_shared_site_capture_isolation() {
    run_sibling_overlap(multithread_runtime());
}

#[test]
fn current_thread_tokio_nested_spawn_inherits_capture_agent_and_session_context() {
    run_nested_spawn_context(current_thread_runtime());
}

#[test]
fn multithread_tokio_nested_spawn_inherits_capture_agent_and_session_context() {
    run_nested_spawn_context(multithread_runtime());
}

#[test]
fn current_thread_tokio_named_join_preserves_selection_order_after_reverse_completion() {
    run_ordered_join(current_thread_runtime(), false);
}

#[test]
fn multithread_tokio_joinall_preserves_declaration_order_after_reverse_completion() {
    run_ordered_join(multithread_runtime(), true);
}

#[test]
fn current_thread_tokio_empty_joinall_emits_memberless_join_event() {
    run_empty_joinall_event(current_thread_runtime());
}

#[test]
fn multithread_tokio_join_failure_waits_for_all_selected_children() {
    run_aggregate_join_failure(multithread_runtime());
}

#[test]
fn current_thread_tokio_parent_failure_waits_for_attached_descendant_drain() {
    run_parent_failure_drain(current_thread_runtime());
}

#[test]
fn multithread_tokio_parent_failure_waits_for_attached_descendant_drain() {
    run_parent_failure_drain(multithread_runtime());
}

#[test]
fn current_thread_tokio_detach_separates_foreground_success_from_terminal_failure() {
    run_detached_failure(current_thread_runtime());
}

#[test]
fn current_thread_tokio_committed_cancellation_precedes_pending_dispatch_completion() {
    let runtime = current_thread_runtime();
    let root = TempDirectory::new(
        r#"
action read_only echo(value: Int) -> Int;

fn main() -> Int {
    spawn first -> Int { action echo(11) }
    spawn second -> Int { action echo(22) }
    spawn third -> Int { action echo(33) }
    discard join(first, second, third);
    7
}
"#,
    );
    let integration = Arc::new(PendingIntegration::echoing_actions());
    let sink = Arc::new(RecordingSink::default());
    let interpreter =
        interpreter_with_events(&runtime, Arc::clone(&integration), Arc::clone(&sink));

    runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(10), async {
            let accepted = start(&interpreter, &root).await;
            let execution_id = accepted.execution_id();
            let root_task = root_task_identity(execution_id);
            let handle = accepted.handle().clone();
            drop(accepted);

            let dispatches = wait_for_started(&integration, 3).await;
            assert!(
                dispatches
                    .iter()
                    .all(|dispatch| !dispatch.released.load(Ordering::Acquire)
                        && !dispatch.completed.load(Ordering::Acquire)),
                "all child dispatches must remain pending before cancellation"
            );

            let cancelling_interpreter = interpreter.clone();
            let cancellation = tokio::spawn(async move {
                let reason = caller_cancellation_reason(Some(Arc::from("deterministic")), 64)
                    .unwrap_or_else(|error| panic!("cancellation reason failed: {error:?}"));
                cancelling_interpreter
                    .cancel_execution(execution_id, reason)
                    .await
            });
            tokio::time::timeout(Duration::from_secs(1), async {
                while !sink.events().iter().any(|event| {
                    event.kind() == EventKind::Cancellation && event.task_id() == Some(root_task)
                }) {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap_or_else(|_| {
                panic!("root cancellation was not committed while hooks were pending")
            });
            assert!(
                dispatches
                    .iter()
                    .all(|dispatch| !dispatch.released.load(Ordering::Acquire)
                        && !dispatch.completed.load(Ordering::Acquire)),
                "a child dispatch completed before cancellation committed"
            );

            for dispatch in &dispatches {
                dispatch.release();
            }
            let snapshot = interpreter
                .await_terminal(&handle)
                .await
                .unwrap_or_else(|error| panic!("terminal observation failed: {error:?}"))
                .unwrap_or_else(|| panic!("cancelled execution disappeared"));
            assert!(
                matches!(snapshot.foreground, Some(MachineOutcome::Cancelled(_))),
                "committed cancellation did not determine foreground: {snapshot:?}"
            );
            let record = cancellation
                .await
                .unwrap_or_else(|error| panic!("cancellation actor failed: {error}"))
                .unwrap_or_else(|error| panic!("cancellation failed: {error:?}"));
            assert!(matches!(record, CancellationRecord::Accepted { .. }));

            wait_for_stress_lifecycle_events(&sink).await;
            assert_stress_events(
                sink.events(),
                execution_id,
                true,
                true,
                "deterministic committed cancellation",
            );
        })
        .await
        .unwrap_or_else(|_| panic!("deterministic committed-cancellation case timed out"));
    });
}

#[test]
fn current_thread_tokio_seeded_native_source_stress() {
    run_seeded_native_source_stress(current_thread_runtime(), "current-thread");
}

#[test]
fn multithread_tokio_seeded_native_source_stress() {
    run_seeded_native_source_stress(multithread_runtime(), "multithread");
}

fn run_seeded_native_source_stress(runtime: Runtime, runtime_name: &'static str) {
    const ITERATIONS: usize = 32;
    const BASE_SEED: u64 = 0x6a09_e667_f3bc_c909;

    let selected_iteration = match std::env::var("GANTRY_SOURCE_STRESS_ITERATION") {
        Ok(value) => Some({
            let iteration = value.parse::<usize>().unwrap_or_else(|error| {
                panic!(
                    "GANTRY_SOURCE_STRESS_ITERATION must be an integer in 0..{ITERATIONS}: {error}"
                )
            });
            assert!(
                iteration < ITERATIONS,
                "GANTRY_SOURCE_STRESS_ITERATION={iteration} is outside 0..{ITERATIONS}"
            );
            iteration
        }),
        Err(std::env::VarError::NotPresent) => None,
        Err(std::env::VarError::NotUnicode(_)) => {
            panic!("GANTRY_SOURCE_STRESS_ITERATION must be valid Unicode in 0..{ITERATIONS}")
        }
    };
    let iterations = selected_iteration.map_or(0..ITERATIONS, |iteration| iteration..iteration + 1);

    for iteration in iterations {
        let seed = BASE_SEED
            ^ u64::try_from(iteration)
                .unwrap_or_else(|_| panic!("stress iteration does not fit u64"))
                .wrapping_mul(0x9e37_79b9_7f4a_7c15);
        let mut random = seed;
        let mut release_schedule = [11_i64, 22, 33];
        for index in (1..release_schedule.len()).rev() {
            let selected = usize::try_from(stress_random(&mut random)).unwrap_or(0) % (index + 1);
            release_schedule.swap(index, selected);
        }
        let cancellation_rank = usize::try_from(stress_random(&mut random) % 4).unwrap_or(0);
        let cancellation_race = iteration % 2 == 1;
        // The seed reconstructs generated test inputs only. Tokio scheduling remains
        // nondeterministic, so this selector is not a schedule-replay mechanism.
        let diagnostic = format!(
            "input_reconstruction_seed={seed:#018x} runtime={runtime_name} iteration={iteration} \
             release_schedule={release_schedule:?} cancellation_rank={} mode={}",
            if cancellation_race {
                cancellation_rank.to_string()
            } else {
                "none".to_owned()
            },
            if cancellation_race {
                "cancel-release-race"
            } else {
                "foreground-terminal-split"
            }
        );
        let source = if cancellation_race {
            r#"
action read_only echo(value: Int) -> Int;

fn echo_value(value: Int) -> Int {
    action echo(value)
}

fn main() -> Int {
    spawn first -> Int { echo_value(11) }
    spawn second -> Int { echo_value(22) }
    spawn third -> Int { echo_value(33) }
    discard join(first, second, third);
    7
}
"#
        } else {
            r#"
action read_only echo(value: Int) -> Int;

fn echo_value(value: Int) -> Int {
    action echo(value)
}

fn main() -> Int {
    spawn first -> Int { echo_value(11) }
    spawn second -> Int { echo_value(22) }
    spawn background -> Int { echo_value(33) }
    detach(background);
    discard join(first, second);
    7
}
"#
        };
        let root = TempDirectory::new(source);
        let integration = Arc::new(PendingIntegration::echoing_actions());
        let sink = Arc::new(RecordingSink::default());
        let interpreter =
            interpreter_with_events(&runtime, Arc::clone(&integration), Arc::clone(&sink));

        runtime.block_on(async {
            tokio::time::timeout(
                Duration::from_secs(10),
                run_stress_iteration(
                    &interpreter,
                    &root,
                    &integration,
                    &sink,
                    release_schedule,
                    cancellation_rank,
                    cancellation_race,
                    &diagnostic,
                ),
            )
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "native-source stress timed out (input reconstruction, not schedule replay): \
                     {diagnostic}; {}",
                    integration.order_diagnostic()
                )
            });
        });
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_stress_iteration(
    interpreter: &Interpreter,
    root: &TempDirectory,
    integration: &PendingIntegration,
    sink: &RecordingSink,
    release_schedule: [i64; 3],
    cancellation_rank: usize,
    cancellation_race: bool,
    diagnostic: &str,
) {
    let accepted = tokio::time::timeout(Duration::from_secs(1), start(interpreter, root))
        .await
        .unwrap_or_else(|_| panic!("execution start timed out ({diagnostic})"));
    let execution_id = accepted.execution_id();
    let handle = accepted.handle().clone();
    drop(accepted);

    let dispatches = tokio::time::timeout(Duration::from_secs(1), wait_for_started(integration, 3))
        .await
        .unwrap_or_else(|_| {
            let dispatches = integration.dispatches();
            let states = dispatches
                .iter()
                .map(|dispatch| {
                    (
                        dispatch.started.load(Ordering::Acquire),
                        dispatch.released.load(Ordering::Acquire),
                        dispatch.completed.load(Ordering::Acquire),
                    )
                })
                .collect::<Vec<_>>();
            panic!(
                "pending hooks timed out ({diagnostic}); count={} states={states:?}",
                dispatches.len()
            )
        });
    assert_eq!(
        dispatches.len(),
        3,
        "stress created an unexpected dispatch count: {diagnostic}"
    );
    assert!(
        dispatches.iter().all(|dispatch| {
            dispatch.started.load(Ordering::Acquire)
                && !dispatch.released.load(Ordering::Acquire)
                && !dispatch.completed.load(Ordering::Acquire)
        }),
        "source children were not independently pending: {diagnostic}"
    );

    let requests = dispatches
        .iter()
        .map(|dispatch| dispatch.request())
        .collect::<Vec<_>>();
    let task_ids = requests
        .iter()
        .map(|request| request["operation_request"]["task_id"].clone())
        .collect::<Vec<_>>();
    let operation_ids = requests
        .iter()
        .map(|request| request["operation_request"]["operation_id"].clone())
        .collect::<Vec<_>>();
    assert!(
        task_ids.iter().all(|identity| !identity.is_null()),
        "a pending child omitted its task identity: {diagnostic}"
    );
    assert!(
        operation_ids.iter().all(|identity| !identity.is_null()),
        "a pending child omitted its operation identity: {diagnostic}"
    );
    assert!(
        pairwise_distinct(&task_ids),
        "same-site source children reused a task identity: {diagnostic}"
    );
    assert!(
        pairwise_distinct(&operation_ids),
        "same-site source children reused an operation identity: {diagnostic}"
    );
    assert!(
        requests.windows(2).all(|pair| {
            pair[0]["operation_request"]["site"] == pair[1]["operation_request"]["site"]
        }),
        "stress children did not exercise one shared operation site: {diagnostic}"
    );

    let dispatch_for = |argument: i64| {
        dispatches
            .iter()
            .find(|dispatch| {
                dispatch.request()["operation_request"]["action"]["arguments"][0]["value"].as_i64()
                    == Some(argument)
            })
            .cloned()
            .unwrap_or_else(|| panic!("missing argument {argument} dispatch: {diagnostic}"))
    };

    let snapshot = if cancellation_race {
        let cancelling_interpreter = interpreter.clone();
        let cancellation_diagnostic = diagnostic.to_owned();
        let cancellation = tokio::spawn(async move {
            for _ in 0..cancellation_rank {
                tokio::task::yield_now().await;
            }
            let reason = caller_cancellation_reason(
                Some(Arc::from(format!("stress-{cancellation_rank}"))),
                64,
            )
            .unwrap_or_else(|error| {
                panic!("cancellation reason failed ({cancellation_diagnostic}): {error:?}")
            });
            cancelling_interpreter
                .cancel_execution(execution_id, reason)
                .await
        });
        let mut releases = Vec::new();
        for (rank, argument) in release_schedule.into_iter().enumerate() {
            let dispatch = dispatch_for(argument);
            let release_rank = if rank >= cancellation_rank {
                rank + 1
            } else {
                rank
            };
            releases.push(tokio::spawn(async move {
                for _ in 0..release_rank {
                    tokio::task::yield_now().await;
                }
                dispatch.release();
            }));
        }
        for release in releases {
            tokio::time::timeout(Duration::from_millis(500), release)
                .await
                .unwrap_or_else(|_| panic!("release actor timed out ({diagnostic})"))
                .unwrap_or_else(|error| panic!("release actor failed ({diagnostic}): {error}"));
        }
        let snapshot =
            tokio::time::timeout(Duration::from_secs(5), interpreter.await_terminal(&handle))
                .await
                .unwrap_or_else(|_| panic!("terminal observation timed out ({diagnostic})"))
                .unwrap_or_else(|error| {
                    panic!("terminal observation failed ({diagnostic}): {error:?}")
                })
                .unwrap_or_else(|| panic!("cancelled stress execution disappeared: {diagnostic}"));
        let cancellation = tokio::time::timeout(Duration::from_secs(1), cancellation)
            .await
            .unwrap_or_else(|_| panic!("cancellation actor timed out ({diagnostic})"))
            .unwrap_or_else(|error| panic!("cancellation actor failed ({diagnostic}): {error}"))
            .unwrap_or_else(|error| panic!("cancellation failed ({diagnostic}): {error:?}"));
        assert!(
            !matches!(cancellation, CancellationRecord::NotFound),
            "accepted execution disappeared during cancellation: {diagnostic}"
        );
        snapshot
    } else {
        let attached = release_schedule
            .into_iter()
            .filter(|argument| *argument != 33)
            .collect::<Vec<_>>();
        for argument in attached {
            let dispatch = dispatch_for(argument);
            dispatch.release();
            wait_for_completion(&dispatch).await;
            tokio::task::yield_now().await;
        }
        let foreground = interpreter
            .await_foreground(&handle)
            .await
            .unwrap_or_else(|error| {
                panic!("foreground observation failed ({diagnostic}): {error:?}")
            })
            .unwrap_or_else(|| panic!("stress execution disappeared: {diagnostic}"));
        assert!(
            matches!(foreground.foreground, Some(MachineOutcome::Succeeded(ref value)) if value.canonical_json().bytes() == b"7"),
            "attached children did not produce foreground success: {diagnostic}; snapshot={foreground:?}"
        );
        assert!(
            foreground.terminal.is_none(),
            "detached work did not separate foreground and terminal: {diagnostic}"
        );
        assert!(
            tokio::time::timeout(
                Duration::from_millis(5),
                interpreter.await_terminal(&handle)
            )
            .await
            .is_err(),
            "terminal completed while the detached hook was pending: {diagnostic}"
        );
        let detached = dispatch_for(33);
        assert!(
            !detached.completed.load(Ordering::Acquire),
            "detached hook completed without its independent release: {diagnostic}"
        );
        detached.release();
        interpreter
            .await_terminal(&handle)
            .await
            .unwrap_or_else(|error| panic!("terminal observation failed ({diagnostic}): {error:?}"))
            .unwrap_or_else(|| panic!("successful stress execution disappeared: {diagnostic}"))
    };

    assert!(
        snapshot.terminal.is_some(),
        "stress execution did not drain to terminal: {diagnostic}"
    );
    assert_eq!(
        snapshot
            .terminal
            .as_ref()
            .map(|terminal| &terminal.foreground),
        snapshot.foreground.as_ref(),
        "foreground and terminal projections diverged: {diagnostic}"
    );
    assert_eq!(
        integration.dispatches().len(),
        3,
        "shared operation budget admitted duplicate work: {diagnostic}"
    );
    assert_eq!(
        integration.hook_requests().len(),
        3,
        "source children created duplicate hooks: {diagnostic}"
    );

    let cancelled = matches!(snapshot.foreground, Some(MachineOutcome::Cancelled(_)));
    tokio::time::timeout(
        Duration::from_secs(5),
        wait_for_stress_lifecycle_events(sink),
    )
    .await
    .unwrap_or_else(|_| {
        let kinds = sink
            .events()
            .iter()
            .map(|event| event.kind())
            .collect::<Vec<_>>();
        panic!(
            "lifecycle event timed out ({diagnostic}); kinds={kinds:?}; {}",
            integration.order_diagnostic()
        )
    });
    assert_stress_events(
        sink.events(),
        execution_id,
        cancellation_race,
        cancelled,
        diagnostic,
    );
}

fn stress_random(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

fn pairwise_distinct(values: &[Value]) -> bool {
    values
        .iter()
        .enumerate()
        .all(|(index, value)| !values[..index].contains(value))
}

async fn wait_for_stress_lifecycle_events(sink: &RecordingSink) {
    while {
        let events = sink.events();
        events
            .iter()
            .filter(|event| event.kind() == EventKind::TaskCompletion)
            .count()
            != 4
            || events
                .iter()
                .filter(|event| event.kind() == EventKind::ForegroundCompletion)
                .count()
                != 1
            || events
                .iter()
                .filter(|event| event.kind() == EventKind::TerminalExecution)
                .count()
                != 1
    } {
        tokio::task::yield_now().await;
    }
}

fn assert_stress_events(
    events: Vec<gantry::event::EventEnvelope>,
    execution_id: ProtocolIdentity,
    cancellation_race: bool,
    cancelled: bool,
    diagnostic: &str,
) {
    assert_eq!(
        events
            .iter()
            .filter(|event| event.kind() == EventKind::ForegroundCompletion)
            .count(),
        1,
        "foreground completion was not published exactly once: {diagnostic}"
    );
    let cancellations = events
        .iter()
        .enumerate()
        .filter(|(_, event)| event.kind() == EventKind::Cancellation)
        .collect::<Vec<_>>();
    assert_eq!(
        cancellations.is_empty(),
        !cancelled,
        "Cancellation publication did not match the terminal outcome: {diagnostic}"
    );
    assert!(
        cancellations
            .iter()
            .enumerate()
            .all(|(cancellation_index, (event_index, event))| {
                let Some(task_id) = event.task_id() else {
                    return false;
                };
                !cancellations[..cancellation_index]
                    .iter()
                    .any(|(_, previous)| previous.task_id() == Some(task_id))
                    && events[event_index.saturating_add(1)..].iter().any(|later| {
                        later.kind() == EventKind::TaskCompletion
                            && later.task_id() == Some(task_id)
                    })
            }),
        "task cancellation was duplicated, unidentified, or published after settlement: {diagnostic}"
    );
    let terminal_count = events
        .iter()
        .filter(|event| event.kind() == EventKind::TerminalExecution)
        .count();
    assert_eq!(
        terminal_count, 1,
        "TerminalExecution publication was not exactly once: {diagnostic}"
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| event.kind() == EventKind::Detach)
            .count(),
        usize::from(!cancellation_race),
        "Detach publication did not match the lifecycle mode: {diagnostic}"
    );
    let join_count = events
        .iter()
        .filter(|event| event.kind() == EventKind::Join)
        .count();
    assert!(
        if cancelled {
            join_count <= 1
        } else {
            join_count == 1
        },
        "Join publication did not match the cancellation race: {diagnostic}; count={join_count}"
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| event.kind() == EventKind::Spawn)
            .count(),
        3,
        "source creation was not published exactly once per child: {diagnostic}"
    );
    let completions = events
        .iter()
        .filter(|event| event.kind() == EventKind::TaskCompletion)
        .collect::<Vec<_>>();
    assert_eq!(
        completions.len(),
        4,
        "root and children did not each settle exactly once: {diagnostic}"
    );
    assert!(
        completions.iter().enumerate().all(|(index, event)| {
            event.task_id().is_some()
                && !completions[..index]
                    .iter()
                    .any(|previous| previous.task_id() == event.task_id())
        }),
        "task completion identities were missing or duplicated: {diagnostic}"
    );
    let terminal_index = events
        .iter()
        .position(|event| event.kind() == EventKind::TerminalExecution)
        .unwrap_or_else(|| panic!("TerminalExecution event was absent: {diagnostic}"));
    let foreground_index = events
        .iter()
        .position(|event| event.kind() == EventKind::ForegroundCompletion)
        .unwrap_or_else(|| panic!("ForegroundCompletion event was absent: {diagnostic}"));
    assert!(
        foreground_index < terminal_index
            && events[..terminal_index]
                .iter()
                .filter(|event| event.kind() == EventKind::TaskCompletion)
                .count()
                == 4,
        "TerminalExecution preceded foreground or task completion: {diagnostic}; foreground_index={foreground_index} terminal_index={terminal_index}"
    );
    assert!(
        events
            .iter()
            .filter(|event| {
                matches!(
                    event.kind(),
                    EventKind::Spawn
                        | EventKind::Detach
                        | EventKind::Join
                        | EventKind::Cancellation
                        | EventKind::TaskCompletion
                        | EventKind::ForegroundCompletion
                        | EventKind::TerminalExecution
                )
            })
            .all(|event| event.execution_id() == Some(execution_id)),
        "an applicable lifecycle event omitted or escaped its execution identity: {diagnostic}"
    );
    assert!(
        events.iter().enumerate().all(|(index, event)| {
            !events[..index]
                .iter()
                .any(|previous| previous.event_id() == event.event_id())
        }),
        "event identity was reused: {diagnostic}"
    );
    for (index, event) in events.iter().enumerate().filter(|(_, event)| {
        matches!(
            event.kind(),
            EventKind::Spawn
                | EventKind::Detach
                | EventKind::Join
                | EventKind::Cancellation
                | EventKind::TaskCompletion
                | EventKind::ForegroundCompletion
        )
    }) {
        let task_id = event.task_id().unwrap_or_else(|| {
            panic!(
                "applicable lifecycle event omitted task identity: {diagnostic}; kind={:?}",
                event.kind()
            )
        });
        let sequence = event.per_task_sequence().unwrap_or_else(|| {
            panic!(
                "applicable lifecycle event omitted task sequence: {diagnostic}; kind={:?}",
                event.kind()
            )
        });
        let previous_sequence = events[..index]
            .iter()
            .rev()
            .find(|previous| previous.task_id() == Some(task_id))
            .and_then(|previous| previous.per_task_sequence());
        assert!(
            previous_sequence.is_none_or(|previous| previous < sequence),
            "one task's event sequence was not monotonic: {diagnostic}; task={task_id:?} sequence={sequence} previous={previous_sequence:?}"
        );
    }
}

fn run_ordered_join(runtime: Runtime, join_all: bool) {
    let join = if join_all {
        "joinall()"
    } else {
        "join(first, second)"
    };
    let root = TempDirectory::new(&format!(
        r#"
action read_only echo(value: Int) -> Int;

fn main() -> List<Int> {{
    spawn first -> Int {{ action echo(11) }}
    spawn second -> Int {{ action echo(22) }}
    {join}
}}
"#,
    ));
    let integration = Arc::new(PendingIntegration::echoing_actions());
    let interpreter = interpreter(&runtime, Arc::clone(&integration));

    runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(5), async {
            let accepted = start(&interpreter, &root).await;
            let handle = accepted.handle().clone();
            drop(accepted);

            let dispatches = wait_for_started(&integration, 2).await;
            let first = dispatch_for_argument(&dispatches, 11);
            let second = dispatch_for_argument(&dispatches, 22);
            second.release();
            wait_for_completion(second).await;
            assert!(
                tokio::time::timeout(
                    Duration::from_millis(20),
                    interpreter.await_foreground(&handle),
                )
                .await
                .is_err(),
                "join completed before its first selected child settled"
            );
            first.release();

            let snapshot = interpreter
                .await_terminal(&handle)
                .await
                .unwrap_or_else(|error| panic!("terminal observation failed: {error:?}"))
                .unwrap_or_else(|| panic!("ordered join execution disappeared"));
            let Some(MachineOutcome::Succeeded(ref value)) = snapshot.foreground else {
                panic!("ordered join did not succeed: {snapshot:?}")
            };
            assert_eq!(value.canonical_json().bytes(), br#"[11,22]"#);
            assert_eq!(
                snapshot
                    .terminal
                    .as_ref()
                    .map(|terminal| &terminal.foreground),
                snapshot.foreground.as_ref()
            );
        })
        .await
        .unwrap_or_else(|_| panic!("ordered join exceeded the 5s deadline"));
    });
}

fn run_empty_joinall_event(runtime: Runtime) {
    let root = TempDirectory::new("fn main() { discard joinall(); }");
    let integration = Arc::new(PendingIntegration::actions());
    let sink = Arc::new(RecordingSink::default());
    let interpreter = interpreter_with_events(&runtime, integration, Arc::clone(&sink));

    runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(5), async {
            let accepted = start(&interpreter, &root).await;
            let handle = accepted.handle().clone();
            drop(accepted);
            let snapshot = interpreter
                .await_terminal(&handle)
                .await
                .unwrap_or_else(|error| panic!("terminal observation failed: {error:?}"))
                .unwrap_or_else(|| panic!("empty joinall execution disappeared"));
            assert!(matches!(
                snapshot.foreground,
                Some(MachineOutcome::Succeeded(_))
            ));

            let event = single_join_event(&sink);
            let payload: Value = serde_json::from_slice(event.payload().canonical_bytes())
                .unwrap_or_else(|error| panic!("Join payload was not JSON: {error}"));
            assert_eq!(payload["join_form"], "joinall");
            assert_eq!(payload["joined_task_ids"], serde_json::json!([]));
            assert_eq!(payload["child_failures"], serde_json::json!([]));
            assert_eq!(
                event.causal_ids(),
                &[event
                    .task_id()
                    .unwrap_or_else(|| { panic!("empty joinall event omitted its joining task") })]
            );
        })
        .await
        .unwrap_or_else(|_| panic!("empty joinall exceeded the 5s deadline"));
    });
}

fn run_aggregate_join_failure(runtime: Runtime) {
    let root = TempDirectory::new(
        r#"
action read_only fail(value: Int) -> Int;

fn main() {
    spawn first -> Int { action fail(11) }
    spawn second -> Int { action fail(22) }
    discard join(first, second);
}
"#,
    );
    let integration = Arc::new(PendingIntegration::failing_actions());
    let sink = Arc::new(RecordingSink::default());
    let interpreter =
        interpreter_with_events(&runtime, Arc::clone(&integration), Arc::clone(&sink));

    runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(5), async {
            let accepted = start(&interpreter, &root).await;
            let handle = accepted.handle().clone();
            drop(accepted);

            let dispatches = wait_for_started(&integration, 2).await;
            let first = dispatch_for_argument(&dispatches, 11);
            let second = dispatch_for_argument(&dispatches, 22);
            first.release();
            wait_for_completion(first).await;
            assert!(
                tokio::time::timeout(
                    Duration::from_millis(20),
                    interpreter.await_foreground(&handle),
                )
                .await
                .is_err(),
                "join failure was published before every selected child settled"
            );
            assert!(
                sink.events()
                    .into_iter()
                    .all(|event| event.kind() != EventKind::Join),
                "Join event was emitted before every selected child settled"
            );
            second.release();

            let snapshot = interpreter
                .await_terminal(&handle)
                .await
                .unwrap_or_else(|error| panic!("terminal observation failed: {error:?}"))
                .unwrap_or_else(|| panic!("aggregate join failure execution disappeared"));
            assert!(matches!(
                snapshot.foreground,
                Some(MachineOutcome::Failed(ref failure))
                    if failure.code
                        == RuntimeCode::Operation(RuntimeErrorCategory::TaskJoinFailure)
            ));
            assert_eq!(
                snapshot
                    .terminal
                    .as_ref()
                    .map(|terminal| &terminal.foreground),
                snapshot.foreground.as_ref()
            );

            let event = single_join_event(&sink);
            let payload: Value = serde_json::from_slice(event.payload().canonical_bytes())
                .unwrap_or_else(|error| panic!("Join payload was not JSON: {error}"));
            assert_eq!(payload["join_form"], "join");
            assert_eq!(payload["settlement_status"], "failed");
            assert_eq!(payload["joined_task_ids"].as_array().map(Vec::len), Some(2));
            assert_eq!(payload["child_failures"].as_array().map(Vec::len), Some(2));
            assert_eq!(event.causal_ids().len(), 3);
        })
        .await
        .unwrap_or_else(|_| panic!("aggregate join failure exceeded the 5s deadline"));
    });
}

fn run_parent_failure_drain(runtime: Runtime) {
    let root = TempDirectory::new(
        r#"
action read_only fail(value: Int) -> Int;

fn main() {
    spawn child -> Int { action fail(11) }
    discard action fail(22);
    discard join(child);
}
"#,
    );
    let integration = Arc::new(PendingIntegration::failing_actions());
    let sink = Arc::new(RecordingSink::default());
    let interpreter =
        interpreter_with_events(&runtime, Arc::clone(&integration), Arc::clone(&sink));

    runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(5), async {
            let accepted = start(&interpreter, &root).await;
            let handle = accepted.handle().clone();
            let root_task = root_task_identity(handle.execution_id());
            drop(accepted);

            let dispatches = wait_for_started(&integration, 2).await;
            let child = dispatch_for_argument(&dispatches, 11);
            let parent = dispatch_for_argument(&dispatches, 22);
            let child_task = child.request()["operation_request"]["task_id"]
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| panic!("child dispatch omitted a task identity"));
            parent.release();
            wait_for_completion(parent).await;
            tokio::task::yield_now().await;

            assert!(
                sink.events().into_iter().all(|event| {
                    event.kind() != EventKind::TaskCompletion || event.task_id() != Some(root_task)
                }),
                "parent task settlement was published before its attached child drained"
            );
            assert!(
                tokio::time::timeout(
                    Duration::from_millis(20),
                    interpreter.await_foreground(&handle),
                )
                .await
                .is_err(),
                "parent foreground completed before its attached child drained"
            );

            child.release();
            let snapshot = interpreter
                .await_terminal(&handle)
                .await
                .unwrap_or_else(|error| panic!("terminal observation failed: {error:?}"))
                .unwrap_or_else(|| panic!("failed parent execution disappeared"));
            assert!(matches!(
                snapshot.foreground,
                Some(MachineOutcome::Failed(ref failure))
                    if failure.code
                        == RuntimeCode::Operation(RuntimeErrorCategory::ProviderFailure)
            ));
            assert_eq!(
                snapshot
                    .terminal
                    .as_ref()
                    .map(|terminal| &terminal.foreground),
                snapshot.foreground.as_ref()
            );
            // Terminal observation waits for required delivery, not this
            // best-effort sink. The enclosing timeout bounds delivery waiting.
            while !sink.events().iter().any(|event| event.kind() == EventKind::TerminalExecution) {
                tokio::task::yield_now().await;
            }
            let events = sink.events();
            let child_completion = events
                .iter()
                .position(|event| {
                    event.kind() == EventKind::TaskCompletion
                        && event.task_id().map(|identity| identity.to_string()).as_deref()
                            == Some(child_task.as_str())
                })
                .unwrap_or_else(|| panic!("child TaskCompletion was not published"));
            let root_completions = events
                .iter()
                .enumerate()
                .filter(|(_, event)| {
                    event.kind() == EventKind::TaskCompletion
                        && event.task_id() == Some(root_task)
                })
                .map(|(index, _)| index)
                .collect::<Vec<_>>();
            let [root_completion] = root_completions.as_slice() else {
                panic!(
                    "expected one root TaskCompletion, observed {}",
                    root_completions.len()
                )
            };
            let terminal_events = events
                .iter()
                .enumerate()
                .filter(|(_, event)| event.kind() == EventKind::TerminalExecution)
                .map(|(index, _)| index)
                .collect::<Vec<_>>();
            let [terminal] = terminal_events.as_slice() else {
                panic!(
                    "expected one TerminalExecution, observed {}",
                    terminal_events.len()
                )
            };
            assert!(
                child_completion < *root_completion && *root_completion < *terminal,
                "production supervision did not publish child TaskCompletion before root TaskCompletion before TerminalExecution: child={child_completion} root={root_completion} terminal={terminal}"
            );
        })
        .await
        .unwrap_or_else(|_| panic!("parent failure drain exceeded the 5s deadline"));
    });
}

fn run_detached_failure(runtime: Runtime) {
    let root = TempDirectory::new(
        r#"
action read_only fail(value: Int) -> Int;

fn main() -> Int {
    spawn background -> Int { action fail(33) }
    detach(background);
    7
}
"#,
    );
    let integration = Arc::new(PendingIntegration::failing_actions());
    let sink = Arc::new(RecordingSink::default());
    let interpreter =
        interpreter_with_events(&runtime, Arc::clone(&integration), Arc::clone(&sink));

    runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(5), async {
            let accepted = start(&interpreter, &root).await;
            let handle = accepted.handle().clone();
            drop(accepted);

            let dispatch =
                tokio::time::timeout(Duration::from_secs(1), wait_for_started(&integration, 1))
                    .await
                    .unwrap_or_else(|_| panic!("detached child did not start its hook"))
                    .into_iter()
                    .next()
                    .unwrap_or_else(|| panic!("detached child created no dispatch"));
            let foreground = tokio::time::timeout(
                Duration::from_secs(1),
                interpreter.await_foreground(&handle),
            )
            .await
            .unwrap_or_else(|_| panic!("detached child blocked foreground publication"))
            .unwrap_or_else(|error| panic!("foreground observation failed: {error:?}"))
            .unwrap_or_else(|| panic!("detached execution disappeared before foreground"));
            let Some(MachineOutcome::Succeeded(ref value)) = foreground.foreground else {
                panic!("detached execution foreground did not succeed: {foreground:?}")
            };
            assert_eq!(value.canonical_json().bytes(), b"7");
            assert!(foreground.terminal.is_none());
            assert!(
                tokio::time::timeout(
                    Duration::from_millis(20),
                    interpreter.await_terminal(&handle),
                )
                .await
                .is_err(),
                "terminal completed while detached work was still pending"
            );

            dispatch.release();
            let terminal =
                tokio::time::timeout(Duration::from_secs(1), interpreter.await_terminal(&handle))
                    .await
                    .unwrap_or_else(|_| {
                        panic!("failed detached child did not publish terminal state")
                    })
                    .unwrap_or_else(|error| panic!("terminal observation failed: {error:?}"))
                    .unwrap_or_else(|| panic!("detached execution disappeared before terminal"));
            assert_eq!(terminal.foreground, foreground.foreground);
            let published = terminal
                .terminal
                .as_ref()
                .unwrap_or_else(|| panic!("detached terminal projection is absent"));
            assert_eq!(Some(&published.foreground), terminal.foreground.as_ref());
            assert_eq!(
                published.category,
                gantry::runtime::ConcurrentTerminalCategoryV1::TerminalOnly(
                    TerminalOnlyCategory::DetachedTaskFailure
                )
            );
            let [failure] = published.detached_failures.as_slice() else {
                panic!(
                    "expected one retained detached failure, observed {:?}",
                    published.detached_failures
                )
            };
            assert_eq!(
                failure.failure.category,
                RuntimeErrorCategory::ProviderFailure
            );
            assert_eq!(failure.failure.code.as_ref(), "provider-failure");

            let terminal_events = sink
                .events()
                .into_iter()
                .filter(|event| event.kind() == EventKind::TerminalExecution)
                .collect::<Vec<_>>();
            let [event] = terminal_events.as_slice() else {
                panic!(
                    "expected one TerminalExecution event, observed {}",
                    terminal_events.len()
                )
            };
            let payload: Value = serde_json::from_slice(event.payload().canonical_bytes())
                .unwrap_or_else(|error| panic!("terminal payload was not JSON: {error}"));
            assert_eq!(payload["completion_category"], "detached-task-failure");
            assert_eq!(event.causal_ids().len(), 2);
        })
        .await
        .unwrap_or_else(|_| panic!("detached failure exceeded the 5s deadline"));
    });
}

fn run_sibling_overlap(runtime: Runtime) {
    let root = TempDirectory::new(
        r#"
action read_only observe(value: Int);

fn observe_capture(value: Int) {
    action observe(value);
}

fn main() {
    spawn first { observe_capture(11); }
    spawn second { observe_capture(22); }
    discard join(first, second);
}
"#,
    );
    let integration = Arc::new(PendingIntegration::actions());
    let interpreter = interpreter(&runtime, Arc::clone(&integration));

    runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(5), async {
            let accepted = start(&interpreter, &root).await;
            let handle = accepted.handle().clone();
            drop(accepted);

            let dispatches = tokio::time::timeout(
                Duration::from_secs(1),
                wait_for_started(&integration, 2),
            )
            .await
            .unwrap_or_else(|_| {
                let dispatches = integration.dispatches();
                let states = dispatches
                    .iter()
                    .map(|state| {
                        (
                            state.started.load(Ordering::Acquire),
                            state.released.load(Ordering::Acquire),
                            state.completed.load(Ordering::Acquire),
                        )
                    })
                    .collect::<Vec<_>>();
                panic!(
                    "expected two independently pending sibling dispatches; count={}, states={states:?}",
                    dispatches.len()
                )
            });
            assert!(dispatches.iter().all(|state| {
                state.started.load(Ordering::Acquire)
                    && !state.released.load(Ordering::Acquire)
                    && !state.completed.load(Ordering::Acquire)
            }));

            let requests = dispatches
                .iter()
                .map(|state| state.request())
                .collect::<Vec<_>>();
            let mut captures = requests
                .iter()
                .map(|request| {
                    request["operation_request"]["action"]["arguments"][0]["value"]
                        .as_i64()
                        .unwrap_or_else(|| panic!("action request omitted its Int capture"))
                })
                .collect::<Vec<_>>();
            captures.sort_unstable();
            assert_eq!(captures, [11, 22]);
            assert_eq!(
                requests[0]["operation_request"]["site"], requests[1]["operation_request"]["site"],
                "both siblings must execute the same called operation site"
            );
            assert_ne!(
                requests[0]["operation_request"]["task_id"],
                requests[1]["operation_request"]["task_id"],
                "siblings executing one operation site must remain distinct tasks"
            );

            dispatches[0].release();
            wait_for_completion(&dispatches[0]).await;
            assert!(
                !dispatches[1].completed.load(Ordering::Acquire),
                "releasing one child hook must not release its pending sibling"
            );
            dispatches[1].release();

            interpreter
                .await_terminal(&handle)
                .await
                .unwrap_or_else(|error| panic!("terminal observation failed: {error:?}"))
                .unwrap_or_else(|| panic!("spawn execution disappeared"));
        })
        .await
        .unwrap_or_else(|_| panic!("sibling spawn overlap exceeded the 5s deadline"));
    });
}

fn run_nested_spawn_context(runtime: Runtime) {
    let root = TempDirectory::new(
        r#"
agents { worker, reviewer }
default agent = worker;

fn main() {
    let captured: Int = 41;
    with reviewer {
        spawn outer {
            spawn inner -> String {
                prompt "nested ${captured}" -> String
            }
            detach(inner);
        }
        detach(outer);
    }
}
"#,
    );
    let integration = Arc::new(PendingIntegration::models());
    let interpreter = interpreter(&runtime, Arc::clone(&integration));

    runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(5), async {
            let accepted = start(&interpreter, &root).await;
            let handle = accepted.handle().clone();
            drop(accepted);

            let dispatch = wait_for_started(&integration, 1)
                .await
                .into_iter()
                .next()
                .unwrap_or_else(|| panic!("nested child created no dispatch"));
            let hook_requests = integration.hook_requests();
            assert_eq!(hook_requests.len(), 1);
            let context = &hook_requests[0]["task_context"];
            let request = dispatch.request();
            let operation = &request["operation_request"];
            let model = &operation["model"];

            assert_eq!(context["inherited_agent"], "reviewer");
            assert_eq!(model["selected_agent"], "reviewer");
            assert_eq!(model["rendered_prompt"], "nested 41");
            assert_eq!(model["interpolation_inputs"][0]["value"], 41);
            assert_eq!(operation["task_id"], context["task_id"]);
            assert_eq!(model["active_session_id"], context["base_session_id"]);
            assert_eq!(model["parent_session_id"], context["parent_session_id"]);
            assert_eq!(model["root_session_id"], context["root_session_id"]);
            assert_ne!(
                context["parent_session_id"], context["root_session_id"],
                "the nested child must fork the outer child's session rather than the root"
            );

            dispatch.release();
            interpreter
                .await_terminal(&handle)
                .await
                .unwrap_or_else(|error| panic!("terminal observation failed: {error:?}"))
                .unwrap_or_else(|| panic!("nested spawn execution disappeared"));
        })
        .await
        .unwrap_or_else(|_| panic!("nested spawn context exceeded the 5s deadline"));
    });
}

async fn wait_for_started(
    integration: &PendingIntegration,
    expected: usize,
) -> Vec<Arc<PendingDispatch>> {
    loop {
        let dispatches = integration.dispatches();
        if dispatches.len() == expected
            && dispatches
                .iter()
                .all(|state| state.started.load(Ordering::Acquire))
        {
            return dispatches;
        }
        tokio::task::yield_now().await;
    }
}

async fn wait_for_completion(dispatch: &PendingDispatch) {
    while !dispatch.completed.load(Ordering::Acquire) {
        tokio::task::yield_now().await;
    }
}

fn dispatch_for_argument(dispatches: &[Arc<PendingDispatch>], argument: i64) -> &PendingDispatch {
    dispatches
        .iter()
        .find(|dispatch| {
            dispatch.request()["operation_request"]["action"]["arguments"][0]["value"].as_i64()
                == Some(argument)
        })
        .map(Arc::as_ref)
        .unwrap_or_else(|| panic!("no dispatch recorded argument {argument}"))
}

fn single_join_event(sink: &RecordingSink) -> gantry::event::EventEnvelope {
    let events = sink
        .events()
        .into_iter()
        .filter(|event| event.kind() == EventKind::Join)
        .collect::<Vec<_>>();
    let [event] = events.as_slice() else {
        panic!("expected one Join event, observed {}", events.len())
    };
    event.clone()
}

async fn start(interpreter: &Interpreter, root: &TempDirectory) -> gantry::StartExecutionAccepted {
    let selection = selection();
    let root_session = RootSessionSpecification {
        id: ProtocolIdentity::from_fresh_material(IdentityKind::Session, [0xf1; 32])
            .unwrap_or_else(|error| panic!("session identity failed: {error}")),
        transcript: Some(b"{\"protocol\":{\"major\":1,\"minor\":0},\"turns\":[]}"),
        opaque_lookup_material: Some(b"source-spawn-tokio"),
    };
    let result = interpreter
        .start_execution(StartExecutionRequest {
            package_root: &root.0,
            protocol_selection: &selection,
            required_peers: &[],
            entry_input: None,
            root_session: Some(root_session),
            event_delivery: None,
        })
        .await;
    let StartExecutionResult::Accepted(accepted) = result else {
        panic!("valid source-spawn fixture was rejected: {result:?}")
    };
    *accepted
}

fn interpreter(runtime: &Runtime, integration: Arc<PendingIntegration>) -> Interpreter {
    let executor: Arc<dyn ExecutorAdapter> = Arc::new(TokioExecutor::new(
        runtime.handle().clone(),
        Arc::new(FixedJitter),
    ));
    let configuration = configuration(executor);
    let preflight: Arc<dyn IntegrationPreflight> = integration.clone();
    let sessions: Arc<dyn RuntimeSessionService> = integration.clone();
    let hooks: Arc<dyn HookFactory> = integration;
    Interpreter::new(
        configuration,
        Arc::new(DeterministicUtcClock::new((1_u32..=240).map(timestamp))),
        preflight,
        sessions,
        hooks,
    )
}

fn interpreter_with_events(
    runtime: &Runtime,
    integration: Arc<PendingIntegration>,
    sink: Arc<RecordingSink>,
) -> Interpreter {
    let retry = EventRetryPolicy::new("async-join-retry-v1", 0, 0, 0, JitterMode::None)
        .unwrap_or_else(|error| panic!("retry policy failed: {error:?}"));
    let policy = SinkDeliveryPolicy::new(
        SinkClass::BestEffort,
        false,
        "async-join-redaction-v1",
        RedactionCapabilities::default(),
        retry,
        30,
    )
    .unwrap_or_else(|error| panic!("sink policy failed: {error:?}"));
    let plan = SinkPlan::new(vec![SinkRegistration::new(
        SinkId::new("async-join-sink")
            .unwrap_or_else(|error| panic!("sink identity failed: {error:?}")),
        policy,
        sink,
    )])
    .unwrap_or_else(|error| panic!("sink plan failed: {error:?}"));
    interpreter_with_plan(runtime, integration, plan)
}

fn interpreter_with_plan(
    runtime: &Runtime,
    integration: Arc<PendingIntegration>,
    event_delivery: SinkPlan,
) -> Interpreter {
    let executor: Arc<dyn ExecutorAdapter> = Arc::new(TokioExecutor::new(
        runtime.handle().clone(),
        Arc::new(FixedJitter),
    ));
    let configuration = configuration(executor);
    let preflight: Arc<dyn IntegrationPreflight> = integration.clone();
    let sessions: Arc<dyn RuntimeSessionService> = integration.clone();
    let hooks: Arc<dyn HookFactory> = integration;
    Interpreter::new_with_event_delivery(
        configuration,
        Arc::new(DeterministicUtcClock::new((1_u32..=240).map(timestamp))),
        preflight,
        sessions,
        hooks,
        Arc::new(ImmediateDeliveryRuntime),
        event_delivery,
    )
}

fn configuration(executor: Arc<dyn ExecutorAdapter>) -> InterpreterConfiguration {
    let identities: Arc<dyn IdentitySource> = Arc::new(DeterministicIdentitySource::new(
        (1_u8..=240).map(|byte| Ok([byte; 32])),
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
    InterpreterConfiguration::new(
        executor,
        identities,
        required,
        AsyncCapacityLimits::new(8, 8, 8, 8, 8, 8, 8, 8, 8)
            .unwrap_or_else(|error| panic!("capacity configuration failed: {error}")),
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

fn timestamp(microseconds: u32) -> Result<UtcTimestamp, HostError> {
    UtcTimestamp::from_unix_seconds(0, microseconds).map_err(|_| host_error("clock-invariant"))
}

fn current_thread_runtime() -> Runtime {
    Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap_or_else(|error| panic!("current-thread runtime construction failed: {error}"))
}

fn multithread_runtime() -> Runtime {
    Builder::new_multi_thread()
        .worker_threads(2)
        .enable_time()
        .build()
        .unwrap_or_else(|error| panic!("multi-thread runtime construction failed: {error}"))
}

fn host_error(code: &'static str) -> HostError {
    HostError {
        code: Arc::from(code),
        protected_diagnostic: None,
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
