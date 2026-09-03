//! Public conformance for shared interpreter ownership and shutdown coordination.

use std::fs;
use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, Waker};

use gantry::host::contracts::{
    CancellationToken, ExecutorAdapter, HookFactory, HostError, HostFuture, HostRequest,
    HostResponse, IdentitySource, IntegrationPreflight, OperationHook, RuntimeSessionService,
};
use gantry::host::embedding::EmbeddingOperation;
use gantry::identity::ProtocolIdentity;
use gantry::portable::{
    IdentityKind, PORTABLE_SPECIFICATION_REVISION, PROTOCOL_FAMILY_DEFINITIONS,
};
use gantry::protocol::{ProtocolSelection, ProtocolVersion, SelectedProtocol};
use gantry::runtime::{InterpreterConfiguration, RequiredConfiguration};
use gantry::source::FrontendLimits;
use gantry::timestamp::UtcTimestamp;
use gantry::value::DEFAULT_VALUE_LIMITS;
use gantry::{Interpreter, StartExecutionRequest, StartExecutionResult};
use gantry_conformance::concurrent_executor::{
    DeterministicConcurrentExecutor, DeterministicTaskPoll,
};
use gantry_conformance::scripted::ScriptedIntegration;
use gantry_conformance::services::{DeterministicIdentitySource, DeterministicUtcClock};
use serde::Deserialize;

const SHUTDOWN_EVIDENCE: &str = "crates/gantry-conformance/tests/interpreter_ownership.rs#dropped_shutdown_waiter_does_not_abandon_the_unique_coordinator";
const CONCURRENCY_EVIDENCE: &str = "crates/gantry-conformance/tests/interpreter_ownership.rs#public_facade_is_cloneable_send_sync_and_concurrently_callable";
const DROP_EVIDENCE: &str = "crates/gantry-conformance/tests/interpreter_ownership.rs#last_external_facade_runs_unclean_cleanup_with_internal_activity_references";
const REENTRY_EVIDENCE: &str = "crates/gantry-conformance/tests/interpreter_lifecycle.rs#reentry_is_chain_local_and_pending_adapters_hold_no_lifecycle_lock";
const RETENTION_EVIDENCE: &str = "crates/gantry-conformance/tests/interpreter_ownership.rs#owned_shutdown_retains_services_after_last_external_facade";
const SUPERVISION_EVIDENCE: &str = "crates/gantry-conformance/tests/task_supervision.rs#control_shares_are_bounded_and_unclean_relinquish_is_nonsemantic";

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

struct TempDirectory(PathBuf);

impl TempDirectory {
    fn new(source: &str) -> Self {
        static NEXT_TEMP: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let suffix = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "gantry-interpreter-ownership-{}-{suffix}",
            std::process::id()
        ));
        fs::create_dir(&path)
            .unwrap_or_else(|error| panic!("could not create {}: {error}", path.display()));
        fs::write(path.join("main.gnt"), source)
            .unwrap_or_else(|error| panic!("could not write ownership fixture: {error}"));
        Self(path)
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct PendingResponse {
    dropped: Arc<AtomicBool>,
}

impl Future for PendingResponse {
    type Output = Result<HostResponse, HostError>;

    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Pending
    }
}

impl Drop for PendingResponse {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::Release);
        panic!("protected pending-preflight cleanup panic")
    }
}

struct PendingIntegration {
    response_dropped: Arc<AtomicBool>,
}

impl IntegrationPreflight for PendingIntegration {
    fn call<'a>(&'a self, request: HostRequest) -> HostFuture<'a, Result<HostResponse, HostError>> {
        assert_eq!(request.operation(), EmbeddingOperation::ResolveMappings);
        Box::pin(PendingResponse {
            dropped: Arc::clone(&self.response_dropped),
        })
    }
}

impl RuntimeSessionService for PendingIntegration {
    fn establish<'a>(&'a self, _: HostRequest) -> HostFuture<'a, Result<HostResponse, HostError>> {
        Box::pin(async { Err(host_error("unexpected-session-establishment")) })
    }
}

impl HookFactory for PendingIntegration {
    fn create_hook<'a>(
        &'a self,
        _: HostRequest,
    ) -> HostFuture<'a, Result<Box<dyn OperationHook>, HostError>> {
        Box::pin(async { Err(host_error("unexpected-hook-creation")) })
    }
}

#[test]
fn checked_in_interpreter_ownership_evidence_is_narrow_and_current() {
    let root = workspace_root();
    let manifest: EvidenceManifest =
        read_json(&root.join("protocol/conformance/interpreter-ownership-v1.json"));
    let review: RequirementReview = read_json(&root.join("protocol/requirements/reviewed-v1.json"));
    let gate: ContractGate =
        read_json(&root.join("protocol/conformance/async-execution-contract-v1.json"));

    assert_eq!(manifest.format, "gantry.interpreter-ownership-evidence/v1");
    assert_eq!(manifest.specification_sha256, review.specification_sha256);
    assert_eq!(manifest.issue, "GNT-ASYNC-LIFE-001");
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
            SHUTDOWN_EVIDENCE,
            CONCURRENCY_EVIDENCE,
            DROP_EVIDENCE,
            REENTRY_EVIDENCE,
            SUPERVISION_EVIDENCE,
            RETENTION_EVIDENCE,
        ]
    );

    let mut assigned = gate
        .requirement_assignments
        .into_iter()
        .filter(|assignment| {
            assignment
                .evidence_owners
                .iter()
                .any(|owner| owner == "GNT-ASYNC-LIFE-001")
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
    assert_eq!(declared.len(), 8);
    assert_eq!(manifest.exclusions.len(), 4);
}

#[test]
fn public_facade_is_cloneable_send_sync_and_concurrently_callable() {
    fn assert_clone_send_sync<T: Clone + Send + Sync>() {}
    assert_clone_send_sync::<Interpreter>();

    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    let integration = Arc::new(ScriptedIntegration::new([], []));
    let interpreter = interpreter(
        executor,
        integration.clone(),
        integration.clone(),
        integration,
    );
    let unknown = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0xee; 32])
        .unwrap_or_else(|error| panic!("execution identity failed: {error}"));
    let mut threads = Vec::new();
    for _ in 0..8 {
        let owner = interpreter.clone();
        threads.push(std::thread::spawn(move || {
            for _ in 0..64 {
                assert_eq!(owner.query_execution(unknown), Ok(None));
            }
        }));
    }
    for thread in threads {
        thread
            .join()
            .unwrap_or_else(|_| panic!("concurrent facade caller panicked"));
    }
}

#[test]
fn last_external_facade_runs_unclean_cleanup_with_internal_activity_references() {
    let root = TempDirectory::new(
        "action read_only lookup() -> String;\nfn main() -> String { action lookup() }",
    );
    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    let response_dropped = Arc::new(AtomicBool::new(false));
    let integration = Arc::new(PendingIntegration {
        response_dropped: Arc::clone(&response_dropped),
    });
    let weak = Arc::downgrade(&integration);
    let interpreter = interpreter(
        Arc::clone(&executor),
        integration.clone(),
        integration.clone(),
        integration,
    );
    let final_owner = interpreter.clone();
    let selection = selection();
    let mut start = Box::pin(interpreter.start_execution(StartExecutionRequest {
        package_root: &root.0,
        protocol_selection: &selection,
        required_peers: &[],
        entry_input: None,
        root_session: None,
        event_delivery: None,
    }));
    assert!(poll_once(start.as_mut()).is_pending());
    assert_eq!(executor.task_ids(), [0]);
    drop(start);

    drop(interpreter);
    assert!(weak.upgrade().is_some());
    assert!(!response_dropped.load(Ordering::Acquire));
    assert_eq!(executor.poll_task(0), Ok(DeterministicTaskPoll::Pending));

    assert!(catch_unwind(AssertUnwindSafe(|| drop(final_owner))).is_ok());
    assert!(response_dropped.load(Ordering::Acquire));
    assert!(weak.upgrade().is_none());
    assert_eq!(executor.poll_task(0), Ok(DeterministicTaskPoll::Stopped));
}

#[test]
fn dropped_shutdown_waiter_does_not_abandon_the_unique_coordinator() {
    let root = TempDirectory::new("fn main() -> Int { 7 }");
    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    let integration = Arc::new(ScriptedIntegration::new([], []));
    let interpreter = interpreter(
        Arc::clone(&executor),
        integration.clone(),
        integration.clone(),
        integration,
    );
    let observer = interpreter.clone();
    let selection = selection();
    let StartExecutionResult::Accepted(accepted) =
        block_on(interpreter.start_execution(StartExecutionRequest {
            package_root: &root.0,
            protocol_selection: &selection,
            required_peers: &[],
            entry_input: None,
            root_session: None,
            event_delivery: None,
        }))
    else {
        panic!("valid shutdown fixture was rejected")
    };
    let cancellation = accepted
        .handle
        .cancellation_signal()
        .unwrap_or_else(|error| panic!("cancellation signal failed: {error:?}"));

    let mut first_waiter = Box::pin(interpreter.shutdown());
    assert!(poll_once(first_waiter.as_mut()).is_pending());
    assert_eq!(executor.task_ids(), [0]);
    drop(first_waiter);
    assert!(!cancellation.is_cancelled());

    assert_eq!(executor.poll_task(0), Ok(DeterministicTaskPoll::Pending));
    assert!(cancellation.is_cancelled());
    let execution = block_on(observer.run_execution(*accepted))
        .unwrap_or_else(|error| panic!("cancelled execution did not drain: {error:?}"));
    assert!(execution.foreground.is_some());
    assert_eq!(execution.terminal, execution.foreground);
    assert!(executor.is_runnable(0));
    assert!(matches!(
        executor.poll_task(0),
        Ok(DeterministicTaskPoll::Settled(_))
    ));

    let report = block_on(observer.shutdown())
        .unwrap_or_else(|error| panic!("shared shutdown failed: {error:?}"));
    let repeated = block_on(interpreter.shutdown())
        .unwrap_or_else(|error| panic!("repeated shutdown failed: {error:?}"));
    assert!(Arc::ptr_eq(&report, &repeated));
    assert!(report.orderly);
    assert_eq!(report.cohort.len(), 1);
}

#[test]
fn owned_shutdown_retains_services_after_last_external_facade() {
    let root = TempDirectory::new("fn main() -> Int { 9 }");
    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    let integration = Arc::new(ScriptedIntegration::new([], []));
    let weak = Arc::downgrade(&integration);
    let interpreter = interpreter(
        Arc::clone(&executor),
        integration.clone(),
        integration.clone(),
        integration.clone(),
    );
    let driver = interpreter.clone();
    let selection = selection();
    let StartExecutionResult::Accepted(accepted) =
        block_on(interpreter.start_execution(StartExecutionRequest {
            package_root: &root.0,
            protocol_selection: &selection,
            required_peers: &[],
            entry_input: None,
            root_session: None,
            event_delivery: None,
        }))
    else {
        panic!("valid retention fixture was rejected")
    };

    let mut shutdown = Box::pin(interpreter.shutdown());
    assert!(poll_once(shutdown.as_mut()).is_pending());
    drop(shutdown);
    assert_eq!(executor.poll_task(0), Ok(DeterministicTaskPoll::Pending));
    block_on(driver.run_execution(*accepted))
        .unwrap_or_else(|error| panic!("retention fixture did not drain: {error:?}"));

    drop(integration);
    drop(driver);
    drop(interpreter);
    assert!(weak.upgrade().is_some());
    let shutdown_poll = executor.poll_task(0);
    assert!(
        matches!(shutdown_poll, Ok(DeterministicTaskPoll::Settled(_))),
        "shutdown task did not settle normally: {shutdown_poll:?}"
    );
    assert!(weak.upgrade().is_none());
}

fn interpreter(
    executor: Arc<DeterministicConcurrentExecutor>,
    preflight: Arc<dyn IntegrationPreflight>,
    sessions: Arc<dyn RuntimeSessionService>,
    hooks: Arc<dyn HookFactory>,
) -> Interpreter {
    let executor: Arc<dyn ExecutorAdapter> = executor;
    let identities: Arc<dyn IdentitySource> = Arc::new(DeterministicIdentitySource::new(
        (1_u8..=96).map(|byte| Ok([byte; 32])),
    ));
    let clock = Arc::new(DeterministicUtcClock::new((1_u32..=96).map(timestamp)));
    Interpreter::new(
        configuration(executor, identities),
        clock,
        preflight,
        sessions,
        hooks,
    )
}

fn configuration(
    executor: Arc<dyn ExecutorAdapter>,
    identities: Arc<dyn IdentitySource>,
) -> InterpreterConfiguration {
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
        1_000,
    )
    .unwrap_or_else(|error| panic!("required configuration failed: {error}"));
    InterpreterConfiguration::new(
        executor,
        identities,
        required,
        gantry::runtime::AsyncCapacityLimits::new(8, 8, 8, 8, 8, 8, 8, 8, 8)
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

fn host_error(code: &str) -> HostError {
    HostError {
        code: Arc::from(code),
        protected_diagnostic: None,
    }
}

fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}

fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = Box::pin(future);
    loop {
        match poll_once(future.as_mut()) {
            Poll::Ready(output) => return output,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> T {
    let bytes =
        fs::read(path).unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|error| panic!("could not decode {}: {error}", path.display()))
}
