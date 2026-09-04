//! Public conformance for automatic sequential-durable root ownership.

use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll, Waker};

use gantry::host::contracts::{
    ExecutorAdapter, HookOutcomeV1, HostFuture, IdentitySource, JournalStorage,
};
use gantry::host::embedding::EmbeddingOperation;
use gantry::host::journal::{
    AcquireJournalOwnerV1, JournalCommitReceiptV1, JournalCommitRequestV1, JournalError,
    JournalErrorCode, JournalId, JournalOwnershipV1, JournalPrefixV1, ReadJournalPrefixV1,
    ReleaseJournalOwnerV1, ResolveJournalPayloadV1, ResolvedJournalPayloadV1,
};
use gantry::portable::{
    EventKind, ExecutionObservationState, PORTABLE_SPECIFICATION_REVISION,
    PROTOCOL_FAMILY_DEFINITIONS,
};
use gantry::protocol::{ProtocolSelection, ProtocolVersion, SelectedProtocol};
use gantry::runtime::{
    AsyncCapacityLimits, DurableCommitCutV1, DurableEventOccurrenceV1, DurableLogicalEvidenceV1,
    InMemoryJournalStore, InterpreterConfiguration, MachineOutcome, RequiredConfiguration,
    recover_authoritative_prefix_with_retained_program,
};
use gantry::source::FrontendLimits;
use gantry::timestamp::UtcTimestamp;
use gantry::value::{DEFAULT_VALUE_LIMITS, LogicalValueView};
use gantry::{
    DurableResumeExecutionRequest, DurableResumeExecutionResult, DurableStartExecutionRequest,
    DurableStartExecutionResult, Interpreter, StartExecutionRequest,
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
    block_on(storage.release_owner(ReleaseJournalOwnerV1 {
        journal_id: journal_id.clone(),
        ownership_token: started.ownership_token.clone(),
    }))
    .unwrap_or_else(|error| panic!("terminal fixture owner release failed: {error:?}"));

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

fn interpreter_with_integration(
    executor: Arc<DeterministicConcurrentExecutor>,
    integration: Arc<ScriptedIntegration>,
) -> Interpreter {
    interpreter_with_integration_and_identity_start(executor, integration, 1)
}

fn interpreter_with_integration_and_identity_start(
    executor: Arc<DeterministicConcurrentExecutor>,
    integration: Arc<ScriptedIntegration>,
    identity_start: u8,
) -> Interpreter {
    interpreter_with_capacities(executor, integration, identity_start, 8, 8)
}

fn interpreter_with_capacities(
    executor: Arc<DeterministicConcurrentExecutor>,
    integration: Arc<ScriptedIntegration>,
    identity_start: u8,
    resume_runnable_tasks: u64,
    public_activities: u64,
) -> Interpreter {
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
