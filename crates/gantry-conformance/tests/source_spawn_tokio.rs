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
    AsyncCapacityLimits, InterpreterConfiguration, MachineOutcome, RequiredConfiguration,
    RuntimeCode,
};
use gantry::source::FrontendLimits;
use gantry::timestamp::UtcTimestamp;
use gantry::value::DEFAULT_VALUE_LIMITS;
use gantry::{Interpreter, RootSessionSpecification, StartExecutionRequest, StartExecutionResult};
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
}

impl PendingDispatch {
    fn release(&self) {
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
}

struct PendingIntegration {
    mapping_response: Arc<[u8]>,
    outcome: PendingOutcome,
    hook_requests: Mutex<Vec<Vec<u8>>>,
    dispatches: Mutex<Vec<Arc<PendingDispatch>>>,
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
        let state = Arc::new(PendingDispatch::default());
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
        self.state.started.store(true, Ordering::Release);
        Box::pin(std::future::poll_fn(move |context| {
            if self.state.released.load(Ordering::Acquire) {
                self.state.completed.store(true, Ordering::Release);
                Poll::Ready(Ok(self.outcome.resolve(&self.state.request())))
            } else {
                *lock(&self.state.waker) = Some(context.waker().clone());
                Poll::Pending
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
fn current_thread_tokio_detach_separates_foreground_success_from_terminal_failure() {
    run_detached_failure(current_thread_runtime());
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
