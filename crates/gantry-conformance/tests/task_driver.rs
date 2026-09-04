//! Public conformance coverage for the executor-owned asynchronous task driver.

use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll, Waker};

use gantry::host::contracts::{ExecutorAdapter, HookOutcomeV1, HostError, IdentitySource};
use gantry::host::embedding::EmbeddingOperation;
use gantry::portable::{
    PORTABLE_SPECIFICATION_REVISION, PROTOCOL_FAMILY_DEFINITIONS, RuntimeErrorCategory,
};
use gantry::protocol::{ProtocolSelection, ProtocolVersion, SelectedProtocol};
use gantry::runtime::{AsyncCapacityLimits, InterpreterConfiguration, RequiredConfiguration};
use gantry::source::FrontendLimits;
use gantry::timestamp::UtcTimestamp;
use gantry::value::{DEFAULT_VALUE_LIMITS, LogicalValueView};
use gantry::{Interpreter, StartExecutionRequest, StartExecutionResult};
use gantry_conformance::concurrent_executor::{
    DeterministicConcurrentExecutor, DeterministicTaskPoll,
};
use gantry_conformance::scripted::{ScriptedHook, ScriptedIntegration, ScriptedPreflight};
use gantry_conformance::services::{DeterministicIdentitySource, DeterministicUtcClock};
use serde::Deserialize;

const ABNORMAL_EVIDENCE: &str = "crates/gantry-conformance/tests/task_driver.rs#abnormal_physical_completion_settles_the_unpolled_driver_once";
const CANCELLATION_EVIDENCE: &str = "crates/gantry-conformance/tests/task_driver.rs#cancellation_published_during_yield_wins_before_more_source_progress";
const ERROR_EVIDENCE: &str = "crates/gantry-conformance/tests/task_driver.rs#accepted_root_uses_prevalidated_state_after_return_payload_changes";
const HOOK_EVIDENCE: &str = "crates/gantry-conformance/tests/task_driver.rs#driver_uses_coordinator_owned_sessions_and_one_serial_hook";
const OWNERSHIP_EVIDENCE: &str = "crates/gantry-conformance/tests/task_driver.rs#owned_driver_is_send_static_and_publishes_semantic_settlement_before_return";
const PANIC_EVIDENCE: &str = "crates/gantry-conformance/tests/task_driver.rs#hook_factory_panic_is_contained_as_hook_creation_failure";
const SUPERVISION_EVIDENCE: &str = "crates/gantry-conformance/tests/task_driver.rs#driver_yields_and_supervision_observes_physical_completion_after_semantic_settlement";
const YIELD_FAILURE_EVIDENCE: &str = "crates/gantry-conformance/tests/task_driver.rs#failed_yield_settles_the_same_task_with_executor_failure";

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
            "gantry-task-driver-{}-{suffix}",
            std::process::id()
        ));
        fs::create_dir(&path)
            .unwrap_or_else(|error| panic!("could not create {}: {error}", path.display()));
        fs::write(path.join("main.gnt"), source)
            .unwrap_or_else(|error| panic!("could not write driver fixture: {error}"));
        Self(path)
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn checked_in_task_driver_evidence_is_narrow_and_current() {
    let root = workspace_root();
    let manifest: EvidenceManifest =
        read_json(&root.join("protocol/conformance/task-driver-v1.json"));
    let review: RequirementReview = read_json(&root.join("protocol/requirements/reviewed-v1.json"));
    let gate: ContractGate =
        read_json(&root.join("protocol/conformance/async-execution-contract-v1.json"));

    assert_eq!(manifest.format, "gantry.task-driver-evidence/v1");
    assert_eq!(manifest.specification_sha256, review.specification_sha256);
    assert_eq!(manifest.issue, "GNT-ASYNC-DRIVER-001");
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
            ABNORMAL_EVIDENCE,
            CANCELLATION_EVIDENCE,
            ERROR_EVIDENCE,
            HOOK_EVIDENCE,
            OWNERSHIP_EVIDENCE,
            PANIC_EVIDENCE,
            SUPERVISION_EVIDENCE,
            YIELD_FAILURE_EVIDENCE,
        ]
    );

    let mut assigned = gate
        .requirement_assignments
        .into_iter()
        .filter(|assignment| {
            assignment
                .evidence_owners
                .iter()
                .any(|owner| owner == "GNT-ASYNC-DRIVER-001")
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
    assert_eq!(declared.len(), 11);
    assert_eq!(manifest.exclusions.len(), 3);
}

#[test]
fn owned_driver_is_send_static_and_publishes_semantic_settlement_before_return() {
    let root = TempDirectory::new("fn main() -> Int { 1 + 2 }");
    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    let integration = Arc::new(ScriptedIntegration::new([], []));
    let interpreter = Interpreter::new(
        configuration(
            Arc::clone(&executor),
            Arc::new(DeterministicIdentitySource::new(
                (1_u8..=16).map(|byte| Ok([byte; 32])),
            )),
            8,
        ),
        execution_clock(1),
        integration.clone(),
        integration.clone(),
        integration,
    );
    let accepted = accepted(&interpreter, &root);
    let snapshot = settle_automatic_root(&executor, &interpreter, accepted);
    assert!(matches!(
        snapshot.foreground,
        Some(gantry::runtime::MachineOutcome::Succeeded(ref value))
            if matches!(value.view(), LogicalValueView::Int(value) if value.get() == 3)
    ));
    assert_eq!(snapshot.terminal, snapshot.foreground);
}

#[test]
fn driver_yields_and_supervision_observes_physical_completion_after_semantic_settlement() {
    let root = TempDirectory::new("fn main() -> Int { 1 + 2 + 3 }");
    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    let integration = Arc::new(ScriptedIntegration::new([], []));
    let interpreter = Interpreter::new(
        configuration(
            Arc::clone(&executor),
            Arc::new(DeterministicIdentitySource::new(
                (17_u8..=40).map(|byte| Ok([byte; 32])),
            )),
            1,
        ),
        execution_clock(3),
        integration.clone(),
        integration.clone(),
        integration,
    );
    let accepted = accepted(&interpreter, &root);
    let snapshot = settle_automatic_root(&executor, &interpreter, accepted);
    assert_eq!(executor.yields(), 4);
    assert!(snapshot.foreground.is_some());
    assert_eq!(snapshot.terminal, snapshot.foreground);
}

#[test]
fn failed_yield_settles_the_same_task_with_executor_failure() {
    let root = TempDirectory::new("fn main() -> Int { 1 + 2 }");
    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    executor.fail_next_yield(HostError {
        code: Arc::from("yield-failed"),
        protected_diagnostic: None,
    });
    let integration = Arc::new(ScriptedIntegration::new([], []));
    let interpreter = Interpreter::new(
        configuration(
            Arc::clone(&executor),
            Arc::new(DeterministicIdentitySource::new(
                (41_u8..=64).map(|byte| Ok([byte; 32])),
            )),
            1,
        ),
        execution_clock(5),
        integration.clone(),
        integration.clone(),
        integration,
    );
    let accepted = accepted(&interpreter, &root);
    let snapshot = settle_automatic_root(&executor, &interpreter, accepted);
    assert!(matches!(
        snapshot.foreground,
        Some(gantry::runtime::MachineOutcome::Failed(ref failure))
            if failure.code
                == gantry::runtime::RuntimeCode::Operation(RuntimeErrorCategory::ExecutorFailure)
    ));
    assert_eq!(snapshot.terminal, snapshot.foreground);
}

#[test]
fn cancellation_published_during_yield_wins_before_more_source_progress() {
    let root = TempDirectory::new("fn main() -> Int { 1 + 2 + 3 }");
    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    let integration = Arc::new(ScriptedIntegration::new([], []));
    let interpreter = Interpreter::new(
        configuration(
            Arc::clone(&executor),
            Arc::new(DeterministicIdentitySource::new(
                (97_u8..=120).map(|byte| Ok([byte; 32])),
            )),
            1,
        ),
        execution_clock(9),
        integration.clone(),
        integration.clone(),
        integration,
    );
    let accepted = accepted(&interpreter, &root);
    let cancellation = accepted
        .handle()
        .cancellation_signal()
        .unwrap_or_else(|error| panic!("cancellation signal failed: {error:?}"));
    executor.cancel_on_next_yield(cancellation);
    let snapshot = settle_automatic_root(&executor, &interpreter, accepted);
    assert!(matches!(
        snapshot.foreground,
        Some(gantry::runtime::MachineOutcome::Cancelled(ref reason))
            if reason.as_ref() == "cancellation"
    ));
    assert_eq!(snapshot.terminal, snapshot.foreground);
    assert_eq!(executor.yields(), 1);
}

#[test]
fn driver_uses_coordinator_owned_sessions_and_one_serial_hook() {
    let root = TempDirectory::new(
        "agents { worker }\ndefault agent = worker;\nfn main() { session(fork) { discard prompt \"First\" -> String; discard prompt \"Second\" -> String; } }",
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
    let interpreter = Interpreter::new(
        configuration(
            Arc::clone(&executor),
            Arc::new(DeterministicIdentitySource::new(
                (65_u8..=96).map(|byte| Ok([byte; 32])),
            )),
            8,
        ),
        execution_clock(7),
        integration.clone(),
        integration.clone(),
        integration.clone(),
    );
    let accepted = accepted(&interpreter, &root);
    let snapshot = settle_automatic_root(&executor, &interpreter, accepted);
    assert!(matches!(
        snapshot.foreground,
        Some(gantry::runtime::MachineOutcome::Succeeded(ref value))
            if matches!(value.view(), LogicalValueView::Unit)
    ));
    assert_eq!(
        integration
            .calls()
            .iter()
            .filter(|call| call.operation == EmbeddingOperation::CreateHook)
            .count(),
        1
    );
    assert_eq!(
        integration
            .calls()
            .iter()
            .filter(|call| call.operation == EmbeddingOperation::DispatchOperation)
            .count(),
        2
    );
}

#[test]
fn hook_factory_failure_preserves_hook_creation_category() {
    let root = TempDirectory::new(
        "action read_only lookup() -> String;\nfn main() -> String { action lookup() }",
    );
    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    let integration = Arc::new(ScriptedIntegration::new(
        [ScriptedPreflight::success(
            EmbeddingOperation::ResolveMappings,
            &br#"{"action_mapping_revision":"actions-v1","result":"resolved"}"#[..],
        )],
        [ScriptedHook::creation_failure(HostError {
            code: Arc::from("hook-create-failed"),
            protected_diagnostic: None,
        })],
    ));
    let interpreter = Interpreter::new(
        configuration(
            Arc::clone(&executor),
            Arc::new(DeterministicIdentitySource::new(
                (121_u8..=144).map(|byte| Ok([byte; 32])),
            )),
            8,
        ),
        execution_clock(11),
        integration.clone(),
        integration.clone(),
        integration,
    );
    let accepted = accepted(&interpreter, &root);
    let snapshot = settle_automatic_root(&executor, &interpreter, accepted);
    assert!(matches!(
        snapshot.foreground,
        Some(gantry::runtime::MachineOutcome::Failed(ref failure))
            if failure.code
                == gantry::runtime::RuntimeCode::Operation(RuntimeErrorCategory::HookCreation)
    ));
}

#[test]
fn hook_factory_panic_is_contained_as_hook_creation_failure() {
    let root = TempDirectory::new(
        "action read_only lookup() -> String;\nfn main() -> String { action lookup() }",
    );
    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    let integration = Arc::new(ScriptedIntegration::new(
        [ScriptedPreflight::success(
            EmbeddingOperation::ResolveMappings,
            &br#"{"action_mapping_revision":"actions-v1","result":"resolved"}"#[..],
        )],
        [ScriptedHook::creation_panic()],
    ));
    let interpreter = Interpreter::new(
        configuration(
            Arc::clone(&executor),
            Arc::new(DeterministicIdentitySource::new(
                (193_u8..=216).map(|byte| Ok([byte; 32])),
            )),
            8,
        ),
        execution_clock(17),
        integration.clone(),
        integration.clone(),
        integration,
    );
    let accepted = accepted(&interpreter, &root);
    let snapshot = settle_automatic_root(&executor, &interpreter, accepted);
    assert!(matches!(
        snapshot.foreground,
        Some(gantry::runtime::MachineOutcome::Failed(ref failure))
            if failure.code
                == gantry::runtime::RuntimeCode::Operation(RuntimeErrorCategory::HookCreation)
    ));
}

#[test]
fn accepted_root_uses_prevalidated_state_after_return_payload_changes() {
    let root = TempDirectory::new("fn main() -> Int { 1 + 2 }");
    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    let integration = Arc::new(ScriptedIntegration::new([], []));
    let interpreter = Interpreter::new(
        configuration(
            Arc::clone(&executor),
            Arc::new(DeterministicIdentitySource::new(
                (145_u8..=168).map(|byte| Ok([byte; 32])),
            )),
            8,
        ),
        execution_clock(13),
        integration.clone(),
        integration.clone(),
        integration,
    );
    let accepted = accepted(&interpreter, &root);
    let snapshot = settle_automatic_root(&executor, &interpreter, accepted);
    assert!(matches!(
        snapshot.foreground,
        Some(gantry::runtime::MachineOutcome::Succeeded(ref value))
            if matches!(value.view(), LogicalValueView::Int(value) if value.get() == 3)
    ));
    assert_eq!(snapshot.terminal, snapshot.foreground);
}

#[test]
fn abnormal_physical_completion_settles_the_unpolled_driver_once() {
    let root = TempDirectory::new("fn main() -> Int { 1 + 2 }");
    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    let integration = Arc::new(ScriptedIntegration::new([], []));
    let interpreter = Interpreter::new(
        configuration(
            Arc::clone(&executor),
            Arc::new(DeterministicIdentitySource::new(
                (169_u8..=192).map(|byte| Ok([byte; 32])),
            )),
            8,
        ),
        execution_clock(15),
        integration.clone(),
        integration.clone(),
        integration,
    );
    let accepted = accepted(&interpreter, &root);
    let execution_id = accepted.execution_id();
    let handle = accepted.handle().clone();
    drop(accepted);
    executor
        .fail_task(0)
        .unwrap_or_else(|error| panic!("executor failure injection failed: {error:?}"));
    assert!(matches!(
        executor.poll_task(0),
        Ok(DeterministicTaskPoll::Failed(_))
    ));
    let snapshot = block_on(interpreter.await_terminal(&handle))
        .unwrap_or_else(|error| panic!("failed root observation failed: {error:?}"))
        .unwrap_or_else(|| panic!("failed root disappeared"));
    assert_eq!(snapshot.execution_id, execution_id);
    assert!(matches!(
        snapshot.foreground,
        Some(gantry::runtime::MachineOutcome::Failed(ref failure))
            if failure.code
                == gantry::runtime::RuntimeCode::Operation(RuntimeErrorCategory::ExecutorFailure)
    ));
    assert_eq!(snapshot.terminal, snapshot.foreground);
}

fn accepted(interpreter: &Interpreter, root: &TempDirectory) -> gantry::StartExecutionAccepted {
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
        panic!("valid driver fixture was rejected")
    };
    *accepted
}

fn settle_automatic_root(
    executor: &DeterministicConcurrentExecutor,
    interpreter: &Interpreter,
    accepted: gantry::StartExecutionAccepted,
) -> gantry::runtime::ExecutionSnapshot {
    let handle = accepted.handle().clone();
    drop(accepted);
    assert_eq!(executor.task_ids(), [0]);
    loop {
        match executor
            .poll_task(0)
            .unwrap_or_else(|error| panic!("automatic root poll failed: {error:?}"))
        {
            DeterministicTaskPoll::Pending | DeterministicTaskPoll::NotRunnable => {
                std::thread::yield_now();
            }
            DeterministicTaskPoll::Settled(_) => break,
            other => panic!("automatic root settled abnormally: {other:?}"),
        }
    }
    block_on(interpreter.await_terminal(&handle))
        .unwrap_or_else(|error| panic!("automatic root observation failed: {error:?}"))
        .unwrap_or_else(|| panic!("automatic root disappeared"))
}

fn configuration(
    executor: Arc<DeterministicConcurrentExecutor>,
    identities: Arc<DeterministicIdentitySource>,
    yield_quantum: u64,
) -> InterpreterConfiguration {
    let executor: Arc<dyn ExecutorAdapter> = executor;
    let identities: Arc<dyn IdentitySource> = identities;
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
        yield_quantum,
    )
    .unwrap_or_else(|error| panic!("required configuration failed: {error}"));
    InterpreterConfiguration::new(executor, identities, required, capacities())
}

fn capacities() -> AsyncCapacityLimits {
    AsyncCapacityLimits::new(8, 8, 8, 8, 8, 8, 8, 8, 8)
        .unwrap_or_else(|error| panic!("capacity configuration failed: {error}"))
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

fn execution_clock(first_microsecond: u32) -> Arc<DeterministicUtcClock> {
    Arc::new(DeterministicUtcClock::new(
        (first_microsecond..first_microsecond + 6).map(timestamp),
    ))
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
