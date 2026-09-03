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
    DurableStartExecutionRequest, DurableStartExecutionResult, Interpreter, StartExecutionRequest,
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
    let executor_adapter: Arc<dyn ExecutorAdapter> = executor;
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
        executor_adapter,
        identities,
        required,
        AsyncCapacityLimits::new(2, 8, 8, 8, 8, 8, 8, 8, 8)
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
