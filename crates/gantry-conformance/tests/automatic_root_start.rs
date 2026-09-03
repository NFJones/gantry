//! Public conformance for automatic nondurable root admission and submission.

use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll, Waker};

use gantry::host::contracts::{ExecutorAdapter, IdentitySource};
use gantry::portable::{
    PORTABLE_SPECIFICATION_REVISION, PROTOCOL_FAMILY_DEFINITIONS, StartFailureCategory,
};
use gantry::protocol::{ProtocolSelection, ProtocolVersion, SelectedProtocol};
use gantry::runtime::{
    AsyncCapacityLimits, InterpreterConfiguration, MachineOutcome, RequiredConfiguration,
    RuntimeCode,
};
use gantry::source::FrontendLimits;
use gantry::timestamp::UtcTimestamp;
use gantry::value::{DEFAULT_VALUE_LIMITS, LogicalValueView};
use gantry::{Interpreter, RunExecutionError, StartExecutionRequest, StartExecutionResult};
use gantry_conformance::concurrent_executor::{
    DeterministicConcurrentExecutor, DeterministicTaskPoll,
};
use gantry_conformance::scripted::ScriptedIntegration;
use gantry_conformance::services::{DeterministicIdentitySource, DeterministicUtcClock};
use serde::Deserialize;

const AUTOMATIC_PROGRESS_EVIDENCE: &str = "crates/gantry-conformance/tests/automatic_root_start.rs#independently_accepted_roots_make_executor_owned_progress";
const GATE_EVIDENCE: &str = "crates/gantry-conformance/tests/automatic_root_start.rs#immediate_executor_poll_cannot_cross_the_accepted_root_gate";
const PREVALIDATED_EVIDENCE: &str = "crates/gantry-conformance/tests/task_driver.rs#accepted_root_uses_prevalidated_state_after_return_payload_changes";
const ROOT_CAPACITY_EVIDENCE: &str = "crates/gantry-conformance/tests/automatic_root_start.rs#root_capacity_rejects_before_acceptance_and_releases_after_reaping";
const SUBMISSION_FAILURE_EVIDENCE: &str = "crates/gantry-conformance/tests/automatic_root_start.rs#post_acceptance_submission_failure_returns_accepted_and_settles_the_root";

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
            "gantry-automatic-root-start-{}-{suffix}",
            std::process::id()
        ));
        fs::create_dir(&path)
            .unwrap_or_else(|error| panic!("could not create {}: {error}", path.display()));
        fs::write(path.join("main.gnt"), source)
            .unwrap_or_else(|error| panic!("could not write start fixture: {error}"));
        Self(path)
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn checked_in_automatic_root_start_evidence_is_narrow_and_current() {
    let root = workspace_root();
    let manifest: EvidenceManifest =
        read_json(&root.join("protocol/conformance/automatic-root-start-v1.json"));
    let review: RequirementReview = read_json(&root.join("protocol/requirements/reviewed-v1.json"));
    let gate: ContractGate =
        read_json(&root.join("protocol/conformance/async-execution-contract-v1.json"));

    assert_eq!(manifest.format, "gantry.automatic-root-start-evidence/v1");
    assert_eq!(manifest.specification_sha256, review.specification_sha256);
    assert_eq!(manifest.issue, "GNT-ASYNC-START-001");
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
            GATE_EVIDENCE,
            SUBMISSION_FAILURE_EVIDENCE,
            ROOT_CAPACITY_EVIDENCE,
            PREVALIDATED_EVIDENCE,
        ]
    );

    let mut assigned = gate
        .requirement_assignments
        .into_iter()
        .filter(|assignment| {
            assignment
                .evidence_owners
                .iter()
                .any(|owner| owner == "GNT-ASYNC-START-001")
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
    assert_eq!(declared.len(), 13);
    assert_eq!(manifest.exclusions.len(), 4);
}

#[test]
fn immediate_executor_poll_cannot_cross_the_accepted_root_gate() {
    let root = TempDirectory::new("fn main() -> Int { 41 + 1 }");
    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    executor.poll_next_spawn_immediately();
    let interpreter = interpreter(Arc::clone(&executor), 1);

    let accepted = accepted(&interpreter, &root);
    assert_eq!(executor.task_ids(), [0]);
    assert_eq!(executor.poll_count(0), Some(1));
    let before_progress = accepted
        .handle
        .snapshot()
        .unwrap_or_else(|error| panic!("accepted snapshot failed: {error:?}"));
    assert!(before_progress.foreground.is_none());
    assert!(before_progress.terminal.is_none());
    assert!(matches!(
        interpreter.task_driver(accepted.clone()),
        Err(RunExecutionError::ExecutionAlreadyOwned)
    ));

    let completed = settle_root(&executor, &interpreter, accepted);
    assert!(matches!(
        completed.foreground,
        Some(MachineOutcome::Succeeded(ref value))
            if matches!(value.view(), LogicalValueView::Int(value) if value.get() == 42)
    ));
    assert_eq!(completed.terminal, completed.foreground);
}

#[test]
fn post_acceptance_submission_failure_returns_accepted_and_settles_the_root() {
    let root = TempDirectory::new("fn main() -> Int { 7 }");
    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    executor.fail_next_spawn();
    let interpreter = interpreter(Arc::clone(&executor), 1);

    let accepted = accepted(&interpreter, &root);
    assert!(executor.task_ids().is_empty());
    let snapshot = block_on(interpreter.run_execution(accepted))
        .unwrap_or_else(|error| panic!("failed root observation failed: {error:?}"));
    assert!(matches!(
        snapshot.foreground,
        Some(MachineOutcome::Failed(ref failure))
            if failure.code == RuntimeCode::RootSubmissionFailure
    ));
    assert_eq!(snapshot.terminal, snapshot.foreground);
}

#[test]
fn root_capacity_rejects_before_acceptance_and_releases_after_reaping() {
    let first_root = TempDirectory::new("fn main() -> Int { 1 }");
    let second_root = TempDirectory::new("fn main() -> Int { 2 }");
    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    let interpreter = interpreter(Arc::clone(&executor), 1);

    let first = accepted(&interpreter, &first_root);
    let selection = selection();
    let second = block_on(interpreter.start_execution(request(&second_root, &selection)));
    let StartExecutionResult::Rejected(failure) = second else {
        panic!("saturated root capacity accepted a second execution")
    };
    assert_eq!(
        failure.category,
        StartFailureCategory::ImplementationResourceExhaustion
    );
    assert_eq!(&*failure.code, "root-task-capacity");
    assert!(failure.package_activity.is_some());
    assert_eq!(executor.task_ids(), [0]);

    let _ = settle_root(&executor, &interpreter, first);
    let third = accepted(&interpreter, &second_root);
    assert_eq!(executor.task_ids(), [0, 1]);
    let completed = settle_task(&executor, &interpreter, third, 1);
    assert!(matches!(
        completed.foreground,
        Some(MachineOutcome::Succeeded(_))
    ));
}

#[test]
fn independently_accepted_roots_make_executor_owned_progress() {
    let first_root = TempDirectory::new("fn main() -> Int { 6 }");
    let second_root = TempDirectory::new("fn main() -> Int { 15 }");
    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    let interpreter = interpreter(Arc::clone(&executor), 2);

    let first = accepted(&interpreter, &first_root);
    let second = accepted(&interpreter, &second_root);
    assert_eq!(executor.task_ids(), [0, 1]);
    assert!(matches!(
        executor.poll_task(0),
        Ok(DeterministicTaskPoll::Pending | DeterministicTaskPoll::Settled(_))
    ));
    assert!(matches!(
        executor.poll_task(1),
        Ok(DeterministicTaskPoll::Pending | DeterministicTaskPoll::Settled(_))
    ));

    let first = settle_task(&executor, &interpreter, first, 0);
    let second = settle_task(&executor, &interpreter, second, 1);
    assert!(
        matches!(
            first.foreground,
            Some(MachineOutcome::Succeeded(ref value))
                if matches!(value.view(), LogicalValueView::Int(value) if value.get() == 6)
        ),
        "unexpected first execution outcome: {first:?}"
    );
    assert!(
        matches!(
            second.foreground,
            Some(MachineOutcome::Succeeded(ref value))
                if matches!(value.view(), LogicalValueView::Int(value) if value.get() == 15)
        ),
        "unexpected second execution outcome: {second:?}"
    );
}

fn accepted(interpreter: &Interpreter, root: &TempDirectory) -> gantry::StartExecutionAccepted {
    let selection = selection();
    let StartExecutionResult::Accepted(accepted) =
        block_on(interpreter.start_execution(request(root, &selection)))
    else {
        panic!("valid automatic-root fixture was rejected")
    };
    *accepted
}

fn request<'a>(
    root: &'a TempDirectory,
    selection: &'a ProtocolSelection,
) -> StartExecutionRequest<'a> {
    StartExecutionRequest {
        package_root: &root.0,
        protocol_selection: selection,
        required_peers: &[],
        entry_input: None,
        root_session: None,
        event_delivery: None,
    }
}

fn settle_root(
    executor: &DeterministicConcurrentExecutor,
    interpreter: &Interpreter,
    accepted: gantry::StartExecutionAccepted,
) -> gantry::runtime::ExecutionSnapshot {
    settle_task(executor, interpreter, accepted, 0)
}

fn settle_task(
    executor: &DeterministicConcurrentExecutor,
    interpreter: &Interpreter,
    accepted: gantry::StartExecutionAccepted,
    task_id: u64,
) -> gantry::runtime::ExecutionSnapshot {
    loop {
        match executor
            .poll_task(task_id)
            .unwrap_or_else(|error| panic!("automatic root poll failed: {error:?}"))
        {
            DeterministicTaskPoll::Pending | DeterministicTaskPoll::NotRunnable => {
                std::thread::yield_now();
            }
            DeterministicTaskPoll::Settled(_) => break,
            other => panic!("automatic root settled abnormally: {other:?}"),
        }
    }
    block_on(interpreter.run_execution(accepted))
        .unwrap_or_else(|error| panic!("automatic root observation failed: {error:?}"))
}

fn interpreter(executor: Arc<DeterministicConcurrentExecutor>, root_capacity: u64) -> Interpreter {
    let executor: Arc<dyn ExecutorAdapter> = executor;
    let identities: Arc<dyn IdentitySource> = Arc::new(DeterministicIdentitySource::new(
        (1_u8..=96).map(|byte| Ok([byte; 32])),
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
        executor,
        identities,
        required,
        AsyncCapacityLimits::new(root_capacity, 8, 8, 8, 8, 8, 8, 8, 8)
            .unwrap_or_else(|error| panic!("capacity configuration failed: {error}")),
    );
    let integration = Arc::new(ScriptedIntegration::new([], []));
    Interpreter::new(
        configuration,
        Arc::new(DeterministicUtcClock::new((1_u32..=96).map(timestamp))),
        integration.clone(),
        integration.clone(),
        integration,
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
