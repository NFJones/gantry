//! Public-facade regressions for durable start and resume pre-acceptance behavior.

use std::collections::BTreeMap;
use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::{Pin, pin};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use gantry::host::contracts::{
    CancellationToken, EmbeddingVersion, ExecutorAdapter, FreshIdentityAllocator, HostError,
    HostFuture, HostRequest, HostResponse, IdentitySource, InclusiveJitterRange,
    IntegrationPreflight, JournalStorage, UtcClock,
};
use gantry::host::embedding::EmbeddingOperation;
use gantry::host::event::{
    EventDeliveryRequest, EventRetryPolicy, EventSink, RedactionCapabilities, SinkDeliveryPolicy,
    SinkId,
};
use gantry::host::journal::{
    AcquireJournalOwnerV1, FullJournalPrefixV1, JournalCommitReceiptV1, JournalCommitRequestV1,
    JournalError, JournalErrorCode, JournalId, JournalOwnershipV1, JournalPrefixV1,
    ReadJournalPrefixV1, ReleaseJournalOwnerV1, ResolveJournalPayloadV1, ResolvedJournalPayloadV1,
    SnapshotJournalPrefixV1,
};
use gantry::ir::InstructionKind;
use gantry::observe::{SinkPlan, SinkRegistration};
use gantry::portable::{
    CancellationReasonCategory, DeliveryOutcome, ExecutionObservationState, IdentityKind,
    JitterMode, PORTABLE_SPECIFICATION_REVISION, PROTOCOL_FAMILY_DEFINITIONS,
    ResumeStartFailureCategory, SinkClass, StartFailureCategory,
};
use gantry::protocol::{ProtocolSelection, ProtocolVersion, SelectedProtocol};
use gantry::runtime::{
    CancellationReason, DurableExecutionStartV1, DurableRecoverySnapshotV1,
    FinalShutdownEventSettlement, InMemoryJournalStore, InterpreterConfiguration,
    InterpreterLifecycle, MachineOutcome, MachineStep, RequiredConfiguration,
    recover_authoritative_prefix_with_retained_program,
};
use gantry::source::FrontendLimits;
use gantry::timestamp::UtcTimestamp;
use gantry::value::{LogicalValueView, ValueLimits};
use gantry::{
    AnalyzePackageCoordinator, DurableCancelExecutionResult, DurableJournalOwnerState,
    DurableLifecycleCoordinator, DurableQueryExecutionRequest, DurableQueryExecutionResult,
    DurableResumeExecutionRequest, DurableResumeExecutionResult, DurableResumeSourceComparison,
    DurableRunFailure, DurableStartExecutionCoordinator, DurableStartExecutionRequest,
    DurableStartExecutionResult, StartExecutionCoordinator, StartExecutionRequest,
};
use serde::Deserialize;

const DURABLE_START_EVIDENCE: &str = "crates/gantry-conformance/tests/durable_start.rs#durable_start_and_resume_preserve_acceptance_and_nonmutation_boundaries";
const DURABLE_GENERIC_EVIDENCE: &str = "crates/gantry-conformance/tests/durable_start.rs#durable_generic_artifacts_reconstruct_without_runtime_analysis_and_reject_tampering";
const DURABLE_GENERIC_EVIDENCE_PATH: &str = "protocol/conformance/generics-traits-durable-v1.json";

#[derive(Debug, Deserialize)]
struct EvidenceManifest {
    format: String,
    specification_sha256: String,
    issue: String,
    capabilities: Vec<CapabilityEvidence>,
    reviewed_clauses: Vec<ReviewedClauseLink>,
    exclusions: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
struct CapabilityEvidence {
    id: String,
    evidence: String,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
struct ReviewedClauseLink {
    requirement: String,
    clause: String,
    profile: String,
    evidence: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RequirementReview {
    specification_sha256: String,
    requirements: Vec<Requirement>,
}

#[derive(Debug, Deserialize)]
struct Requirement {
    id: String,
    clauses: Vec<ReviewedClause>,
}

#[derive(Debug, Deserialize)]
struct ReviewedClause {
    key: String,
    profile_reviews: Vec<ProfileReview>,
}

#[derive(Debug, Deserialize)]
struct ProfileReview {
    profile: String,
    state: String,
    evidence: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct DurableStartVectors {
    format: String,
    evidence_formats: Vec<String>,
    resume_modes: Vec<String>,
    compatibility_classes: Vec<String>,
    cases: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct DurableGenericEvidenceManifest {
    format: String,
    specification_sha256: String,
    issue: String,
    profile: String,
    entries: Vec<DurableGenericEvidenceEntry>,
    advertises_profiles: Vec<String>,
    exclusions: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
struct DurableGenericEvidenceEntry {
    requirement: String,
    clause: String,
    evidence: String,
}

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TempDirectory(PathBuf);

impl TempDirectory {
    fn new(source: &[u8]) -> Self {
        let suffix = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "gantry-durable-start-conformance-{}-{suffix}",
            std::process::id()
        ));
        assert!(fs::create_dir(&path).is_ok());
        assert!(fs::write(path.join("main.gnt"), source).is_ok());
        Self(path)
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[derive(Debug, Default)]
struct Services {
    next_identity: AtomicU64,
}

impl IdentitySource for Services {
    fn fresh_material(&self, _kind: IdentityKind) -> Result<[u8; 32], HostError> {
        let value = self.next_identity.fetch_add(1, Ordering::Relaxed) + 1;
        let mut material = [0_u8; 32];
        material[..8].copy_from_slice(&value.to_be_bytes());
        Ok(material)
    }
}

impl ExecutorAdapter for Services {
    fn sleep<'a>(
        &'a self,
        _duration: gantry::host::contracts::DurationMicros,
    ) -> HostFuture<'a, Result<(), HostError>> {
        Box::pin(async { Ok(()) })
    }

    fn yield_now<'a>(&'a self) -> HostFuture<'a, Result<(), HostError>> {
        Box::pin(async { Ok(()) })
    }

    fn sample_inclusive(&self, range: InclusiveJitterRange) -> Result<u64, HostError> {
        Ok(range.minimum())
    }
}

struct FixedClock;

impl UtcClock for FixedClock {
    fn utc_now<'a>(&'a self) -> HostFuture<'a, Result<UtcTimestamp, HostError>> {
        Box::pin(async {
            UtcTimestamp::from_unix_seconds(0, 1).map_err(|_| host_failure("clock-invariant"))
        })
    }
}

struct FixedSink;

impl EventSink for FixedSink {
    fn deliver<'a>(
        &'a self,
        _request: EventDeliveryRequest,
    ) -> HostFuture<'a, Result<DeliveryOutcome, HostError>> {
        Box::pin(async { Ok(DeliveryOutcome::Success) })
    }
}

#[derive(Default)]
struct InstrumentedJournalStore {
    inner: InMemoryJournalStore,
    fail_commits: AtomicBool,
    commit_calls: AtomicU64,
    release_calls: AtomicU64,
    prefix_override: Mutex<Option<JournalPrefixV1>>,
}

impl InstrumentedJournalStore {
    fn set_fail_commits(&self, fail: bool) {
        self.fail_commits.store(fail, Ordering::Release);
    }

    fn release_calls(&self) -> u64 {
        self.release_calls.load(Ordering::Acquire)
    }

    fn commit_calls(&self) -> u64 {
        self.commit_calls.load(Ordering::Acquire)
    }

    fn set_prefix_override(&self, prefix: JournalPrefixV1) {
        *self
            .prefix_override
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(prefix);
    }
}

impl JournalStorage for InstrumentedJournalStore {
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
        if let Some(prefix) = self
            .prefix_override
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
        {
            return Box::pin(async move { Ok(prefix) });
        }
        self.inner.read_prefix(request)
    }

    fn commit<'a>(
        &'a self,
        request: JournalCommitRequestV1,
    ) -> HostFuture<'a, Result<JournalCommitReceiptV1, JournalError>> {
        self.commit_calls.fetch_add(1, Ordering::AcqRel);
        if self.fail_commits.load(Ordering::Acquire) {
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
        self.release_calls.fetch_add(1, Ordering::AcqRel);
        self.inner.release_owner(request)
    }
}

struct ResolvedPreflight {
    agent_revision: &'static str,
    action_revision: &'static str,
}

impl ResolvedPreflight {
    const fn new(agent_revision: &'static str, action_revision: &'static str) -> Self {
        Self {
            agent_revision,
            action_revision,
        }
    }
}

impl IntegrationPreflight for ResolvedPreflight {
    fn call<'a>(&'a self, request: HostRequest) -> HostFuture<'a, Result<HostResponse, HostError>> {
        let operation = request.operation();
        let agent_revision = self.agent_revision;
        let action_revision = self.action_revision;
        Box::pin(async move {
            let body = match operation {
                EmbeddingOperation::ResolveMappings => format!(
                    "{{\"action_mapping_revision\":\"{action_revision}\",\"agent_mapping_revision\":\"{agent_revision}\",\"result\":\"resolved\"}}"
                )
                .into_bytes(),
                EmbeddingOperation::ResolveSessions => {
                    b"{\"result\":\"resolved\"}".to_vec()
                }
                _ => return Err(host_failure("unexpected-preflight-operation")),
            };
            HostResponse::new(EmbeddingVersion::V1, operation, Arc::from(body))
                .map_err(|_| host_failure("response-invariant"))
        })
    }
}

#[test]
fn checked_in_durable_start_evidence_is_narrow_and_current() {
    let root = workspace_root();
    let manifest: EvidenceManifest =
        read_json(&root.join("protocol/conformance/durable-start-v1.json"));
    let vectors: DurableStartVectors =
        read_json(&root.join("protocol/goldens/durable-start-v1.json"));
    let schema: serde_json::Value =
        read_json(&root.join("protocol/schemas/durable-start-v1.schema.json"));
    let review: RequirementReview = read_json(&root.join("protocol/requirements/reviewed-v1.json"));

    assert_eq!(manifest.format, "gantry.durable-start-evidence/v1");
    assert_eq!(manifest.issue, "GNT-DUR-003");
    assert!(gantry_conformance::evidence_revision_is_expected(
        &manifest.specification_sha256,
        &review.specification_sha256,
    ));
    let evidence_is_current = manifest.specification_sha256 == review.specification_sha256;
    assert!(evidence_is_current || gantry::advertised_profiles().is_empty());
    assert!(
        manifest
            .capabilities
            .windows(2)
            .all(|pair| pair[0] < pair[1])
    );
    assert!(
        manifest
            .reviewed_clauses
            .windows(2)
            .all(|pair| pair[0] < pair[1])
    );
    assert_eq!(manifest.exclusions.len(), 4);
    assert!(
        manifest
            .capabilities
            .iter()
            .all(|capability| capability.evidence == DURABLE_START_EVIDENCE)
    );

    for link in manifest.reviewed_clauses {
        if !evidence_is_current {
            continue;
        }
        let profile = review
            .requirements
            .iter()
            .find(|requirement| requirement.id == link.requirement)
            .and_then(|requirement| {
                requirement
                    .clauses
                    .iter()
                    .find(|clause| clause.key == link.clause)
            })
            .and_then(|clause| {
                clause
                    .profile_reviews
                    .iter()
                    .find(|profile| profile.profile == link.profile)
            })
            .unwrap_or_else(|| {
                panic!(
                    "missing {}:{} {} review",
                    link.requirement, link.clause, link.profile
                )
            });
        assert_eq!(profile.state, "covered");
        assert_eq!(profile.evidence, link.evidence);
    }

    assert_eq!(vectors.format, "gantry.durable-start-vectors/v1");
    assert_eq!(vectors.evidence_formats.len(), 3);
    assert_eq!(vectors.resume_modes, ["candidate-source", "source-free"]);
    assert_eq!(vectors.compatibility_classes.len(), 3);
    assert_eq!(vectors.cases.len(), 6);
    assert_eq!(schema["properties"]["format"]["const"], vectors.format);
}

#[test]
fn reviewed_durable_generic_evidence_is_closed() {
    let root = workspace_root();
    let manifest: DurableGenericEvidenceManifest =
        read_json(&root.join(DURABLE_GENERIC_EVIDENCE_PATH));
    let review: RequirementReview = read_json(&root.join("protocol/requirements/reviewed-v1.json"));

    assert_eq!(
        manifest.format,
        "gantry.generics-traits-durable-evidence/v1"
    );
    assert_eq!(manifest.issue, "GNT-GEN-DUR-001");
    assert_eq!(manifest.profile, "durable-runtime");
    let evidence_is_current = manifest.specification_sha256 == review.specification_sha256;
    assert!(gantry_conformance::evidence_revision_is_expected(
        &manifest.specification_sha256,
        &review.specification_sha256,
    ));
    assert!(evidence_is_current || gantry::advertised_profiles().is_empty());
    assert_eq!(manifest.entries.len(), 28);
    assert!(manifest.entries.windows(2).all(|pair| pair[0] < pair[1]));
    assert_eq!(manifest.advertises_profiles, ["durable-runtime"]);
    assert_eq!(manifest.exclusions.len(), 3);
    assert_eq!(
        gantry::advertised_profiles().contains(&gantry::ConformanceProfile::DurableRuntime),
        evidence_is_current
    );

    for entry in &manifest.entries {
        assert_anchor_exists(&root, &entry.evidence);
        if !evidence_is_current {
            continue;
        }
        let clause = review
            .requirements
            .iter()
            .find(|requirement| requirement.id == entry.requirement)
            .and_then(|requirement| {
                requirement
                    .clauses
                    .iter()
                    .find(|clause| clause.key == entry.clause)
            })
            .unwrap_or_else(|| panic!("missing {}:{}", entry.requirement, entry.clause));
        let profile = clause
            .profile_reviews
            .iter()
            .find(|profile| profile.profile == "durable-runtime")
            .unwrap_or_else(|| {
                panic!(
                    "missing durable-runtime review for {}:{}",
                    entry.requirement, entry.clause
                )
            });
        assert_eq!(profile.state, "covered");
        assert_eq!(
            profile.evidence.as_slice(),
            std::slice::from_ref(&entry.evidence)
        );
    }
    assert!(
        manifest
            .entries
            .iter()
            .any(|entry| entry.evidence == DURABLE_GENERIC_EVIDENCE)
    );
}

#[test]
fn durable_cancellation_commits_once_before_terminal_observation_and_release() {
    let root = TempDirectory::new(
        b"agents { worker } default agent = worker; action read_only inspect(value: Int) -> Int; fn main() {}",
    );
    let services = Arc::new(Services::default());
    let configuration = test_configuration(Arc::clone(&services));
    let selection = selection();
    let storage = Arc::new(InMemoryJournalStore::new());
    let storage_adapter: Arc<dyn JournalStorage> = storage.clone();
    let journal_id = JournalId::new("durable-lifecycle-cancellation")
        .unwrap_or_else(|error| panic!("journal identity failed: {error:?}"));
    let clock = FixedClock;
    let preflight = ResolvedPreflight::new("agents-v1", "actions-v1");
    let interpreter_lifecycle = InterpreterLifecycle::new(&configuration);
    let allocator = FreshIdentityAllocator::default();
    let package = AnalyzePackageCoordinator::new(&allocator, services.as_ref(), &clock);
    let start = StartExecutionCoordinator::new(
        &package,
        &interpreter_lifecycle,
        &configuration,
        &allocator,
        &preflight,
    );
    let durable =
        DurableStartExecutionCoordinator::new(start, &configuration, Arc::clone(&storage_adapter));
    let accepted = match block_on(durable.start(DurableStartExecutionRequest {
        journal_id: journal_id.clone(),
        start: start_request(&root.0, &selection),
    })) {
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
        .unwrap_or_else(|error| panic!("cancellation signal was unavailable: {error:?}"));
    assert!(!signal.is_cancelled());

    let lifecycle = DurableLifecycleCoordinator::new(Arc::clone(&storage_adapter));
    let owned = block_on(lifecycle.open_owned_execution(
        journal_id.clone(),
        accepted.ownership_token.clone(),
        accepted.start.handle.clone(),
        execution_id,
    ))
    .unwrap_or_else(|error| panic!("durable execution could not be opened: {error:?}"));
    let reason = CancellationReason::new(
        CancellationReasonCategory::Caller,
        Some(Arc::from("stop")),
        None,
        32,
    )
    .unwrap_or_else(|error| panic!("cancellation reason failed: {error:?}"));
    let first = block_on(owned.cancel_execution(execution_id, reason.clone()));
    let DurableCancelExecutionResult::Accepted {
        effective_reason,
        terminal,
    } = &first
    else {
        panic!("first durable cancellation was not accepted: {first:?}")
    };
    assert_eq!(effective_reason, &reason);
    assert!(signal.is_cancelled());
    assert_eq!(terminal.state, ExecutionObservationState::Terminal);
    assert_eq!(terminal.cancellation, Some(reason.clone()));
    assert!(matches!(
        terminal.terminal,
        Some(MachineOutcome::Cancelled(ref message)) if message.as_ref() == "stop"
    ));
    assert_eq!(terminal.foreground, terminal.terminal);
    assert_eq!(terminal.owner, Some(DurableJournalOwnerState::Released));
    assert!(terminal.required_delivery_failures.is_empty());
    assert!(terminal.run_failure.is_none());

    let prefix_after_terminal = read_prefix(storage.as_ref(), &journal_id);
    let JournalPrefixV1::Full(full) = &prefix_after_terminal else {
        panic!("durable cancellation did not retain a full prefix");
    };
    assert_eq!(full.committed_through, 5);
    assert_eq!(
        full.evidence
            .iter()
            .map(|evidence| evidence.kind.as_ref())
            .collect::<Vec<_>>(),
        [
            "gantry.execution-start/v1",
            "gantry.cancellation/v1",
            "gantry.logical-evidence/v1",
            "gantry.logical-evidence/v1",
            "gantry.logical-evidence/v1",
        ]
    );

    let second_reason = CancellationReason::new(
        CancellationReasonCategory::Deadline,
        Some(Arc::from("later")),
        None,
        32,
    )
    .unwrap_or_else(|error| panic!("second cancellation reason failed: {error:?}"));
    let repeated = block_on(owned.cancel_execution(execution_id, second_reason));
    let DurableCancelExecutionResult::Accepted {
        effective_reason,
        terminal: repeated_terminal,
    } = repeated
    else {
        panic!("repeated durable cancellation did not preserve accepted status")
    };
    assert_eq!(effective_reason, reason);
    assert_eq!(&repeated_terminal, terminal);
    assert_eq!(
        read_prefix(storage.as_ref(), &journal_id),
        prefix_after_terminal
    );
    assert_eq!(block_on(owned.await_foreground()), **terminal);
    assert_eq!(block_on(owned.await_terminal()), **terminal);

    let queried = block_on(lifecycle.query(DurableQueryExecutionRequest {
        journal_id: journal_id.clone(),
        expected_execution_id: Some(execution_id),
    }));
    let DurableQueryExecutionResult::Snapshot(queried) = queried else {
        panic!("terminal durable query did not return a snapshot")
    };
    assert_eq!(queried.state, ExecutionObservationState::Terminal);
    assert_eq!(queried.terminal, terminal.terminal);
    assert_eq!(queried.cancellation, Some(reason));
    assert!(queried.owner.is_none());
    assert!(queried.run_failure.is_none());
}

#[test]
fn durable_shutdown_cancels_sequential_work_releases_once_and_is_idempotent() {
    let storage = Arc::new(InstrumentedJournalStore::default());
    let storage_adapter: Arc<dyn JournalStorage> = storage.clone();
    let (interpreter_lifecycle, lifecycle, owned, execution_id, signal, journal_id) =
        start_owned_lifecycle("durable-lifecycle-shutdown", Arc::clone(&storage_adapter));

    let mut dropped_wait = owned.await_terminal();
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    assert!(Pin::new(&mut dropped_wait).poll(&mut context).is_pending());
    drop(dropped_wait);

    let report = block_on(lifecycle.shutdown(
        &interpreter_lifecycle,
        &[Arc::clone(&owned)],
        None,
        None,
        FinalShutdownEventSettlement::Settled,
    ))
    .unwrap_or_else(|error| panic!("durable shutdown failed: {error:?}"));
    assert!(report.lifecycle.orderly);
    assert_eq!(report.lifecycle.cohort.len(), 1);
    assert_eq!(report.executions.len(), 1);
    assert_eq!(report.executions[0].execution_id, execution_id);
    assert_eq!(
        report.executions[0].state,
        ExecutionObservationState::Terminal
    );
    assert_eq!(
        report.executions[0]
            .cancellation
            .as_ref()
            .map(|reason| reason.category),
        Some(CancellationReasonCategory::Shutdown)
    );
    assert!(matches!(
        report.executions[0].terminal,
        Some(MachineOutcome::Cancelled(ref message)) if message.as_ref() == "shutdown"
    ));
    assert_eq!(
        report.executions[0].owner,
        Some(DurableJournalOwnerState::Released)
    );
    assert!(report.executions[0].required_delivery_failures.is_empty());
    assert!(report.executions[0].run_failure.is_none());
    assert!(signal.is_cancelled());
    assert_eq!(storage.release_calls(), 1);

    let repeated = block_on(lifecycle.shutdown(
        &interpreter_lifecycle,
        &[owned],
        None,
        None,
        FinalShutdownEventSettlement::Exhausted,
    ))
    .unwrap_or_else(|error| panic!("repeated durable shutdown failed: {error:?}"));
    assert!(Arc::ptr_eq(&report, &repeated));
    assert_eq!(storage.release_calls(), 1);
    assert_eq!(
        read_prefix(storage.as_ref(), &journal_id),
        read_prefix(storage.as_ref(), &journal_id)
    );
}

#[test]
fn durable_journal_failure_wakes_waiters_without_fabricating_terminal_state() {
    let storage = Arc::new(InstrumentedJournalStore::default());
    let storage_adapter: Arc<dyn JournalStorage> = storage.clone();
    let (interpreter_lifecycle, lifecycle, owned, execution_id, signal, journal_id) =
        start_owned_lifecycle(
            "durable-lifecycle-journal-failure",
            Arc::clone(&storage_adapter),
        );
    storage.set_fail_commits(true);

    let mut dropped_wait = owned.await_foreground();
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    assert!(Pin::new(&mut dropped_wait).poll(&mut context).is_pending());
    drop(dropped_wait);

    let reason = CancellationReason::new(
        CancellationReasonCategory::Caller,
        Some(Arc::from("will-not-commit")),
        None,
        32,
    )
    .unwrap_or_else(|error| panic!("cancellation reason failed: {error:?}"));
    let failed = block_on(owned.cancel_execution(execution_id, reason));
    let DurableCancelExecutionResult::Failed {
        effective_reason,
        failure,
        observation,
    } = failed
    else {
        panic!("journal failure did not produce a separated failed result")
    };
    assert!(effective_reason.is_none());
    assert!(matches!(failure, DurableRunFailure::Commit(_)));
    assert_eq!(
        observation.state,
        ExecutionObservationState::RunFailedNondurably
    );
    assert!(observation.foreground.is_none());
    assert!(observation.terminal.is_none());
    assert!(observation.cancellation.is_none());
    assert_eq!(observation.owner, Some(DurableJournalOwnerState::Held));
    assert!(signal.is_cancelled());
    assert_eq!(block_on(owned.await_terminal()), *observation);

    let queried = block_on(lifecycle.query(DurableQueryExecutionRequest {
        journal_id: journal_id.clone(),
        expected_execution_id: Some(execution_id),
    }));
    let DurableQueryExecutionResult::Snapshot(queried) = queried else {
        panic!("authoritative query did not return the unchanged durable prefix")
    };
    assert_eq!(queried.state, ExecutionObservationState::NotTerminal);
    assert!(queried.foreground.is_none());
    assert!(queried.terminal.is_none());
    assert!(queried.cancellation.is_none());
    assert!(queried.run_failure.is_none());

    let report = block_on(lifecycle.shutdown(
        &interpreter_lifecycle,
        &[owned],
        None,
        None,
        FinalShutdownEventSettlement::Settled,
    ))
    .unwrap_or_else(|error| panic!("failed-run shutdown did not complete: {error:?}"));
    assert!(!report.lifecycle.orderly);
    assert_eq!(report.executions.len(), 1);
    assert_eq!(
        report.executions[0].state,
        ExecutionObservationState::RunFailedNondurably
    );
    assert!(report.executions[0].terminal.is_none());
    assert_eq!(
        report.executions[0].owner,
        Some(DurableJournalOwnerState::Released)
    );
    assert_eq!(storage.release_calls(), 1);
}

#[test]
fn durable_start_and_resume_preserve_acceptance_and_nonmutation_boundaries() {
    let root = TempDirectory::new(
        b"agents { worker } default agent = worker; action read_only inspect(value: Int) -> Int; fn main() {}",
    );
    let services = Arc::new(Services::default());
    let configuration = test_configuration(Arc::clone(&services));
    let selection = selection();
    let storage = Arc::new(InMemoryJournalStore::new());
    let storage_adapter: Arc<dyn JournalStorage> = storage.clone();
    let journal_id = JournalId::new("durable-start-resume")
        .unwrap_or_else(|error| panic!("journal identity failed: {error:?}"));
    let clock = FixedClock;
    let preflight = ResolvedPreflight::new("agents-v1", "actions-v1");

    let query = DurableLifecycleCoordinator::new(Arc::clone(&storage_adapter));
    let empty = block_on(query.query(DurableQueryExecutionRequest {
        journal_id: journal_id.clone(),
        expected_execution_id: None,
    }));
    assert!(matches!(
        empty,
        DurableQueryExecutionResult::NotFound { journal_id: ref observed }
            if observed == &journal_id
    ));

    let lifecycle = InterpreterLifecycle::new(&configuration);
    let allocator = FreshIdentityAllocator::default();
    let package = AnalyzePackageCoordinator::new(&allocator, services.as_ref(), &clock);
    let start = StartExecutionCoordinator::new(
        &package,
        &lifecycle,
        &configuration,
        &allocator,
        &preflight,
    );
    let durable =
        DurableStartExecutionCoordinator::new(start, &configuration, Arc::clone(&storage_adapter));
    let result = block_on(durable.start(DurableStartExecutionRequest {
        journal_id: journal_id.clone(),
        start: start_request(&root.0, &selection),
    }));
    let accepted = match result {
        DurableStartExecutionResult::Accepted(accepted) => accepted,
        DurableStartExecutionResult::Rejected(failure) => panic!(
            "fresh durable start was rejected: {:?} {} release={:?}",
            failure.failure.category, failure.failure.code, failure.release_error
        ),
    };
    let execution_id = accepted.start.execution_id;
    let prefix_after_start = read_prefix(storage.as_ref(), &journal_id);
    let JournalPrefixV1::Full(full) = &prefix_after_start else {
        panic!("in-memory start did not produce a full prefix");
    };
    assert_eq!(full.committed_through, 1);
    assert_eq!(full.evidence.len(), 1);
    assert_eq!(full.evidence[0].sequence, 1);
    assert_eq!(full.evidence[0].kind.as_ref(), "gantry.execution-start/v1");
    assert_eq!(
        accepted.execution_start_evidence_id,
        full.evidence[0].evidence_id
    );
    assert_eq!(accepted.start.handle.execution_id(), execution_id);
    let query_before = read_prefix(storage.as_ref(), &journal_id);
    let queried = block_on(query.query(DurableQueryExecutionRequest {
        journal_id: journal_id.clone(),
        expected_execution_id: Some(execution_id),
    }));
    let DurableQueryExecutionResult::Snapshot(queried) = queried else {
        panic!("sequence-one durable query did not return a snapshot");
    };
    assert_eq!(queried.journal_id, journal_id);
    assert_eq!(queried.execution_id, execution_id);
    assert_eq!(queried.state, ExecutionObservationState::NotTerminal);
    assert!(queried.foreground.is_none());
    assert!(queried.terminal.is_none());
    assert_eq!(queried.latest_sequence, 1);
    assert_eq!(queried.latest_evidence_id, full.evidence[0].evidence_id);
    assert_eq!(read_prefix(storage.as_ref(), &journal_id), query_before);

    let other_execution = gantry::identity::ProtocolIdentity::from_fresh_material(
        IdentityKind::Execution,
        [0xff; 32],
    )
    .unwrap_or_else(|error| panic!("query mismatch identity failed: {error}"));
    let mismatch = block_on(query.query(DurableQueryExecutionRequest {
        journal_id: journal_id.clone(),
        expected_execution_id: Some(other_execution),
    }));
    assert!(matches!(
        mismatch,
        DurableQueryExecutionResult::NotFound { journal_id: ref observed }
            if observed == &journal_id
    ));
    assert_eq!(read_prefix(storage.as_ref(), &journal_id), query_before);
    let (_, recovered_start) =
        recover_authoritative_prefix_with_retained_program(&prefix_after_start)
            .unwrap_or_else(|error| panic!("sequence-one recovery failed: {error:?}"));
    let execution_start = recovered_start
        .execution_start()
        .unwrap_or_else(|| panic!("sequence-one metadata was not retained"));
    assert_eq!(
        execution_start.canonical_body(),
        full.evidence[0].canonical_body.as_ref()
    );
    let metadata: serde_json::Value = serde_json::from_slice(execution_start.metadata())
        .unwrap_or_else(|error| panic!("sequence-one metadata failed to decode: {error}"));
    assert_eq!(metadata["format"], "gantry.execution-start-metadata/v1");
    assert_eq!(metadata["execution_id"], execution_id.to_string());
    assert_eq!(metadata["agent_mapping_revision"], "agents-v1");
    assert_eq!(metadata["action_mapping_revision"], "actions-v1");
    assert_eq!(metadata["entry"]["input"], serde_json::Value::Null);
    assert_eq!(metadata["entry"]["input_type"], serde_json::Value::Null);
    assert_eq!(metadata["entry"]["signature"], "fn crate::main()->Unit");
    assert_eq!(metadata["maximum_directive_integer"], "9223372036854775807");
    assert_eq!(metadata["journal_schema"]["major"], 1);
    assert_eq!(metadata["journal_schema"]["minor"], 0);
    assert_eq!(
        metadata["configuration"]["root_session"]["id"],
        metadata["root_session"]["id"]
    );
    assert_eq!(
        metadata["configuration"]["required_event_sinks"],
        serde_json::json!([])
    );
    assert_eq!(
        metadata["configuration"]["interpreter"]["maximum_workflow_call_depth"],
        "1024"
    );
    assert_eq!(
        metadata["configuration"]["structured_output"]["model_retry_limit"],
        "2"
    );
    assert_eq!(
        metadata["mutable_policy"]["graceful_shutdown_timeout_us"],
        "30000000"
    );
    assert!(
        metadata["canonical_ir"]
            .as_str()
            .is_some_and(|value| !value.is_empty())
    );
    assert!(
        metadata["manifest"]
            .as_str()
            .is_some_and(|value| !value.is_empty())
    );
    assert!(
        metadata["source_map"]
            .as_str()
            .is_some_and(|value| !value.is_empty())
    );

    let racing_lifecycle = InterpreterLifecycle::new(&configuration);
    let racing_allocator = FreshIdentityAllocator::default();
    let racing_package =
        AnalyzePackageCoordinator::new(&racing_allocator, services.as_ref(), &clock);
    let racing_start = StartExecutionCoordinator::new(
        &racing_package,
        &racing_lifecycle,
        &configuration,
        &racing_allocator,
        &preflight,
    );
    let racing = DurableStartExecutionCoordinator::new(
        racing_start,
        &configuration,
        Arc::clone(&storage_adapter),
    );
    let result = block_on(racing.start(DurableStartExecutionRequest {
        journal_id: journal_id.clone(),
        start: start_request(&root.0, &selection),
    }));
    let DurableStartExecutionResult::Rejected(failure) = result else {
        panic!("ownership race accepted a second durable start");
    };
    assert_eq!(
        failure.failure.category,
        StartFailureCategory::InitialJournalOwnership
    );
    assert_eq!(&*failure.failure.code, "ownership-unavailable");
    assert_eq!(
        read_prefix(storage.as_ref(), &journal_id),
        prefix_after_start
    );

    release(
        storage.as_ref(),
        &journal_id,
        accepted.ownership_token.clone(),
    );

    let nonfresh_lifecycle = InterpreterLifecycle::new(&configuration);
    let nonfresh_allocator = FreshIdentityAllocator::default();
    let nonfresh_package =
        AnalyzePackageCoordinator::new(&nonfresh_allocator, services.as_ref(), &clock);
    let nonfresh_start = StartExecutionCoordinator::new(
        &nonfresh_package,
        &nonfresh_lifecycle,
        &configuration,
        &nonfresh_allocator,
        &preflight,
    );
    let nonfresh = DurableStartExecutionCoordinator::new(
        nonfresh_start,
        &configuration,
        Arc::clone(&storage_adapter),
    );
    let result = block_on(nonfresh.start(DurableStartExecutionRequest {
        journal_id: journal_id.clone(),
        start: start_request(&root.0, &selection),
    }));
    let DurableStartExecutionResult::Rejected(failure) = result else {
        panic!("nonfresh journal accepted a new start");
    };
    assert_eq!(
        failure.failure.category,
        StartFailureCategory::InitialJournalOwnership
    );
    assert_eq!(&*failure.failure.code, "journal-not-fresh");
    assert!(failure.release_error.is_none());
    assert_eq!(
        read_prefix(storage.as_ref(), &journal_id),
        prefix_after_start
    );

    let incompatible_configuration = test_configuration(Arc::clone(&services))
        .with_maximum_workflow_call_depth(2_048)
        .unwrap_or_else(|error| panic!("configuration mutation failed: {error:?}"));
    let incompatible_lifecycle = InterpreterLifecycle::new(&incompatible_configuration);
    let incompatible_allocator = FreshIdentityAllocator::default();
    let incompatible_package =
        AnalyzePackageCoordinator::new(&incompatible_allocator, services.as_ref(), &clock);
    let incompatible_start = StartExecutionCoordinator::new(
        &incompatible_package,
        &incompatible_lifecycle,
        &incompatible_configuration,
        &incompatible_allocator,
        &preflight,
    );
    let incompatible = DurableStartExecutionCoordinator::new(
        incompatible_start,
        &incompatible_configuration,
        Arc::clone(&storage_adapter),
    );
    let result = block_on(incompatible.resume(DurableResumeExecutionRequest {
        journal_id: journal_id.clone(),
        protocol_selection: &selection,
        candidate_package_root: None,
        expected_execution_id: Some(execution_id),
        event_delivery: None,
    }));
    let DurableResumeExecutionResult::Rejected(failure) = result else {
        panic!("immutable configuration mismatch was accepted");
    };
    assert_eq!(
        failure.category,
        ResumeStartFailureCategory::SourceOrConfigurationIncompatibility
    );
    assert_eq!(&*failure.code, "immutable-configuration-mismatch");
    assert!(failure.release_error.is_none());
    assert_eq!(
        read_prefix(storage.as_ref(), &journal_id),
        prefix_after_start
    );

    let resume_lifecycle = InterpreterLifecycle::new(&configuration);
    let resume_allocator = FreshIdentityAllocator::default();
    let resume_package =
        AnalyzePackageCoordinator::new(&resume_allocator, services.as_ref(), &clock);
    let resume_start = StartExecutionCoordinator::new(
        &resume_package,
        &resume_lifecycle,
        &configuration,
        &resume_allocator,
        &preflight,
    );
    let resume = DurableStartExecutionCoordinator::new(
        resume_start,
        &configuration,
        Arc::clone(&storage_adapter),
    );
    let result = block_on(resume.resume(DurableResumeExecutionRequest {
        journal_id: journal_id.clone(),
        protocol_selection: &selection,
        candidate_package_root: None,
        expected_execution_id: Some(execution_id),
        event_delivery: None,
    }));
    let DurableResumeExecutionResult::Accepted(source_free) = result else {
        panic!("source-free durable resume was rejected");
    };
    assert_eq!(source_free.execution_id, execution_id);
    assert_eq!(source_free.handle.execution_id(), execution_id);
    assert_eq!(source_free.recovered.latest_sequence(), 1);
    assert!(source_free.recovered.execution_start().is_some());
    assert!(source_free.candidate_package_activity.is_none());
    assert_eq!(
        source_free.source_comparison,
        DurableResumeSourceComparison::SourceFree
    );
    assert_eq!(
        read_prefix(storage.as_ref(), &journal_id),
        prefix_after_start
    );
    release(
        storage.as_ref(),
        &journal_id,
        source_free.ownership_token.clone(),
    );

    let deep_candidate = TempDirectory::new(b"fn main(value: Option<Option<Int>>) {}");
    let limited_configuration = test_configuration_with_type_depth(Arc::clone(&services), 2);
    let limited_lifecycle = InterpreterLifecycle::new(&limited_configuration);
    let limited_allocator = FreshIdentityAllocator::default();
    let limited_package =
        AnalyzePackageCoordinator::new(&limited_allocator, services.as_ref(), &clock);
    let limited_start = StartExecutionCoordinator::new(
        &limited_package,
        &limited_lifecycle,
        &limited_configuration,
        &limited_allocator,
        &preflight,
    );
    let limited_resume = DurableStartExecutionCoordinator::new(
        limited_start,
        &limited_configuration,
        Arc::clone(&storage_adapter),
    );
    let result = block_on(limited_resume.resume(DurableResumeExecutionRequest {
        journal_id: journal_id.clone(),
        protocol_selection: &selection,
        candidate_package_root: Some(&deep_candidate.0),
        expected_execution_id: Some(execution_id),
        event_delivery: None,
    }));
    let DurableResumeExecutionResult::Rejected(failure) = result else {
        panic!("over-depth candidate source was accepted");
    };
    assert_eq!(
        failure.category,
        ResumeStartFailureCategory::FrontendResourceLimit
    );
    assert_eq!(&*failure.code, "frontend-resource-limit");
    assert!(failure.candidate_package_activity.is_none());
    assert!(failure.release_error.is_none());
    assert_eq!(
        read_prefix(storage.as_ref(), &journal_id),
        prefix_after_start
    );

    let candidate_lifecycle = InterpreterLifecycle::new(&configuration);
    let candidate_allocator = FreshIdentityAllocator::default();
    let candidate_package =
        AnalyzePackageCoordinator::new(&candidate_allocator, services.as_ref(), &clock);
    let candidate_start = StartExecutionCoordinator::new(
        &candidate_package,
        &candidate_lifecycle,
        &configuration,
        &candidate_allocator,
        &preflight,
    );
    let candidate_resume = DurableStartExecutionCoordinator::new(
        candidate_start,
        &configuration,
        Arc::clone(&storage_adapter),
    );
    let result = block_on(candidate_resume.resume(DurableResumeExecutionRequest {
        journal_id: journal_id.clone(),
        protocol_selection: &selection,
        candidate_package_root: Some(&root.0),
        expected_execution_id: Some(execution_id),
        event_delivery: None,
    }));
    let DurableResumeExecutionResult::Accepted(candidate) = result else {
        panic!("matching candidate-source durable resume was rejected");
    };
    assert!(candidate.candidate_package_activity.is_some());
    assert_eq!(
        candidate.source_comparison,
        DurableResumeSourceComparison::ExactManifest
    );
    assert_eq!(
        read_prefix(storage.as_ref(), &journal_id),
        prefix_after_start
    );
    release(
        storage.as_ref(),
        &journal_id,
        candidate.ownership_token.clone(),
    );

    let revised_configuration = test_configuration(Arc::clone(&services))
        .with_graceful_shutdown_timeout_us(45_000_000)
        .unwrap_or_else(|error| panic!("mutable configuration failed: {error:?}"));
    let revised_lifecycle = InterpreterLifecycle::new(&revised_configuration);
    let revised_allocator = FreshIdentityAllocator::default();
    let revised_package =
        AnalyzePackageCoordinator::new(&revised_allocator, services.as_ref(), &clock);
    let revised_preflight = ResolvedPreflight::new("agents-v2", "actions-v2");
    let revised_start = StartExecutionCoordinator::new(
        &revised_package,
        &revised_lifecycle,
        &revised_configuration,
        &revised_allocator,
        &revised_preflight,
    );
    let revised_resume = DurableStartExecutionCoordinator::new(
        revised_start,
        &revised_configuration,
        Arc::clone(&storage_adapter),
    );
    let result = block_on(revised_resume.resume(DurableResumeExecutionRequest {
        journal_id: journal_id.clone(),
        protocol_selection: &selection,
        candidate_package_root: None,
        expected_execution_id: Some(execution_id),
        event_delivery: None,
    }));
    let DurableResumeExecutionResult::Accepted(revised) = result else {
        panic!("compatible mutable-policy revision was rejected");
    };
    assert_eq!(revised.recovered.latest_sequence(), 2);
    let state = revised
        .recovered
        .execution_state()
        .unwrap_or_else(|| panic!("execution-state revision was not projected"));
    assert!(
        std::str::from_utf8(state.mutable_policy())
            .is_ok_and(|policy| policy.contains("\"graceful_shutdown_timeout_us\":\"45000000\""))
    );
    assert_eq!(state.agent_mapping_revision(), Some("agents-v2"));
    assert_eq!(state.action_mapping_revision(), Some("actions-v2"));
    let prefix_after_revision = read_prefix(storage.as_ref(), &journal_id);
    let JournalPrefixV1::Full(full) = &prefix_after_revision else {
        panic!("in-memory revision did not produce a full prefix");
    };
    assert_eq!(full.committed_through, 2);
    assert_eq!(full.evidence.len(), 2);
    assert_eq!(full.evidence[1].sequence, 2);
    assert_eq!(full.evidence[1].kind.as_ref(), "gantry.execution-state/v1");
    release(
        storage.as_ref(),
        &journal_id,
        revised.ownership_token.clone(),
    );

    let best_effort_plan = best_effort_plan();
    let best_effort_configuration = test_configuration(Arc::clone(&services))
        .with_graceful_shutdown_timeout_us(45_000_000)
        .unwrap_or_else(|error| panic!("best-effort configuration failed: {error:?}"));
    let best_effort_lifecycle = InterpreterLifecycle::new(&best_effort_configuration);
    let best_effort_allocator = FreshIdentityAllocator::default();
    let best_effort_package =
        AnalyzePackageCoordinator::new(&best_effort_allocator, services.as_ref(), &clock);
    let best_effort_preflight = ResolvedPreflight::new("agents-v2", "actions-v2");
    let best_effort_start = StartExecutionCoordinator::new(
        &best_effort_package,
        &best_effort_lifecycle,
        &best_effort_configuration,
        &best_effort_allocator,
        &best_effort_preflight,
    );
    let best_effort_resume = DurableStartExecutionCoordinator::new(
        best_effort_start,
        &best_effort_configuration,
        Arc::clone(&storage_adapter),
    );
    let result = block_on(best_effort_resume.resume(DurableResumeExecutionRequest {
        journal_id: journal_id.clone(),
        protocol_selection: &selection,
        candidate_package_root: None,
        expected_execution_id: Some(execution_id),
        event_delivery: Some(&best_effort_plan),
    }));
    let DurableResumeExecutionResult::Accepted(best_effort) = result else {
        panic!("best-effort sink revision was rejected");
    };
    assert_eq!(best_effort.recovered.latest_sequence(), 3);
    assert!(
        best_effort
            .recovered
            .execution_state()
            .is_some_and(|state| std::str::from_utf8(state.mutable_policy())
                .is_ok_and(|policy| policy.contains("\"class\":\"best-effort\"")))
    );
    let prefix_after_best_effort = read_prefix(storage.as_ref(), &journal_id);
    let JournalPrefixV1::Full(full) = &prefix_after_best_effort else {
        panic!("best-effort revision did not produce a full prefix");
    };
    assert_eq!(full.committed_through, 3);
    assert_eq!(full.evidence[2].kind.as_ref(), "gantry.execution-state/v1");
    release(
        storage.as_ref(),
        &journal_id,
        best_effort.ownership_token.clone(),
    );

    let yield_configuration = test_configuration_with_quantum(Arc::clone(&services), 7)
        .with_graceful_shutdown_timeout_us(45_000_000)
        .unwrap_or_else(|error| panic!("yield configuration failed: {error:?}"));
    let yield_lifecycle = InterpreterLifecycle::new(&yield_configuration);
    let yield_allocator = FreshIdentityAllocator::default();
    let yield_package = AnalyzePackageCoordinator::new(&yield_allocator, services.as_ref(), &clock);
    let yield_preflight = ResolvedPreflight::new("agents-v2", "actions-v2");
    let yield_start = StartExecutionCoordinator::new(
        &yield_package,
        &yield_lifecycle,
        &yield_configuration,
        &yield_allocator,
        &yield_preflight,
    );
    let yield_resume = DurableStartExecutionCoordinator::new(
        yield_start,
        &yield_configuration,
        Arc::clone(&storage_adapter),
    );
    let result = block_on(yield_resume.resume(DurableResumeExecutionRequest {
        journal_id: journal_id.clone(),
        protocol_selection: &selection,
        candidate_package_root: None,
        expected_execution_id: Some(execution_id),
        event_delivery: Some(&best_effort_plan),
    }));
    let DurableResumeExecutionResult::Accepted(yield_changed) = result else {
        panic!("scheduling-only yield quantum change was rejected");
    };
    assert_eq!(yield_changed.recovered.latest_sequence(), 3);
    assert_eq!(
        read_prefix(storage.as_ref(), &journal_id),
        prefix_after_best_effort
    );
    release(
        storage.as_ref(),
        &journal_id,
        yield_changed.ownership_token.clone(),
    );
}

#[test]
fn durable_generic_artifacts_reconstruct_without_runtime_analysis_and_reject_tampering() {
    if let Some(snapshot) = std::env::var_os("GANTRY_DURABLE_GENERIC_RECOVERY_CHILD") {
        recover_generic_snapshot_in_fresh_process(&snapshot);
        return;
    }
    let root = TempDirectory::new(
        br#"
struct Envelope<T> { value: T }
trait Label { pure fn label(self) -> String; }
impl<T> Label for Envelope<T> {
    pure fn label(self) -> String { "label" }
}
pure fn main(number: Envelope<Int>) -> Envelope<String> {
    discard number.label();
    let text: Envelope<String> = Envelope::<String> { value: "retained" };
    discard text.label();
    text
}
"#,
    );
    let services = Arc::new(Services::default());
    let configuration = test_configuration(Arc::clone(&services));
    let selection = selection();
    let storage = Arc::new(InstrumentedJournalStore::default());
    let storage_adapter: Arc<dyn JournalStorage> = storage.clone();
    let journal_id = JournalId::new("durable-generic-artifacts")
        .unwrap_or_else(|error| panic!("journal identity failed: {error:?}"));
    let clock = FixedClock;
    let preflight = ResolvedPreflight::new("agents-v1", "actions-v1");

    let lifecycle = InterpreterLifecycle::new(&configuration);
    let allocator = FreshIdentityAllocator::default();
    let package = AnalyzePackageCoordinator::new(&allocator, services.as_ref(), &clock);
    let start = StartExecutionCoordinator::new(
        &package,
        &lifecycle,
        &configuration,
        &allocator,
        &preflight,
    );
    let durable =
        DurableStartExecutionCoordinator::new(start, &configuration, Arc::clone(&storage_adapter));
    let accepted = match block_on(durable.start(DurableStartExecutionRequest {
        journal_id: journal_id.clone(),
        start: StartExecutionRequest {
            package_root: &root.0,
            protocol_selection: &selection,
            required_peers: &[],
            entry_input: Some(br#"{"value":7}"#),
            root_session: None,
            event_delivery: None,
        },
    })) {
        DurableStartExecutionResult::Accepted(accepted) => accepted,
        DurableStartExecutionResult::Rejected(failure) => {
            panic!("generic durable start was rejected: {failure:?}")
        }
    };
    let execution_id = accepted.start.execution_id;
    let analysis = accepted
        .start
        .package_activity
        .analysis
        .as_ref()
        .unwrap_or_else(|| panic!("generic durable start omitted analysis"));
    let expected_program = analysis
        .executable_program()
        .cloned()
        .unwrap_or_else(|| panic!("generic durable start omitted its executable program"));
    let expected_ir = analysis
        .canonical_ir()
        .unwrap_or_else(|| panic!("generic durable start omitted canonical IR"))
        .artifact()
        .canonical_bytes()
        .to_vec();
    let expected_ir_identity = analysis
        .canonical_ir()
        .unwrap_or_else(|| panic!("generic durable start omitted canonical IR"))
        .artifact()
        .sha256_hex();
    let expected_schemas = analysis
        .schemas()
        .unwrap_or_else(|| panic!("generic durable start omitted concrete schemas"))
        .artifact()
        .canonical_bytes()
        .to_vec();
    let expected_schemas_identity = analysis
        .schemas()
        .unwrap_or_else(|| panic!("generic durable start omitted concrete schemas"))
        .artifact()
        .sha256_hex();
    let expected_manifest = analysis
        .manifest()
        .unwrap_or_else(|| panic!("generic durable start omitted package manifest"))
        .artifact()
        .canonical_bytes()
        .to_vec();
    let expected_manifest_identity = analysis
        .manifest()
        .unwrap_or_else(|| panic!("generic durable start omitted package manifest"))
        .artifact()
        .sha256_hex();
    let expected_source_map = analysis
        .source_map()
        .unwrap_or_else(|| panic!("generic durable start omitted source map"))
        .artifact()
        .canonical_bytes()
        .to_vec();
    let expected_source_map_identity = analysis
        .source_map()
        .unwrap_or_else(|| panic!("generic durable start omitted source map"))
        .artifact()
        .sha256_hex();
    assert!(
        expected_program
            .callable_identities()
            .iter()
            .map(|identity| identity.as_str())
            .filter(|identity| identity.ends_with(" as crate::Label>::label"))
            .eq([
                "<crate::Envelope<Int> as crate::Label>::label",
                "<crate::Envelope<String> as crate::Label>::label",
            ])
    );
    let main = expected_program
        .callable_identities()
        .iter()
        .zip(expected_program.workflows())
        .find_map(|(identity, workflow)| (identity.as_str() == "crate::main").then_some(workflow))
        .unwrap_or_else(|| panic!("generic durable program omitted its entry workflow"));
    assert_eq!(
        main.instructions
            .iter()
            .filter_map(|instruction| match &instruction.kind {
                InstructionKind::Call { callee, .. } => Some(callee.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>(),
        [
            "<crate::Envelope<Int> as crate::Label>::label",
            "<crate::Envelope<String> as crate::Label>::label",
        ]
    );
    assert!(
        expected_program
            .callable_identities()
            .iter()
            .zip(expected_program.workflows())
            .filter(|(identity, _)| identity.as_str().ends_with(" as crate::Label>::label"))
            .all(|(_, workflow)| workflow.effects.is_empty())
    );
    assert!(
        std::str::from_utf8(&expected_schemas)
            .is_ok_and(|schemas| schemas.contains("crate::Envelope<Int>")
                && schemas.contains("crate::Envelope<String>"))
    );
    let prefix = read_prefix(storage.as_ref(), &journal_id);
    assert_eq!(storage.commit_calls(), 1);
    let JournalPrefixV1::Full(initial_full) = &prefix else {
        panic!("generic start did not produce a full prefix");
    };
    let retained_program =
        DurableExecutionStartV1::retained_program(&initial_full.evidence[0].canonical_body)
            .unwrap_or_else(|error| panic!("retained generic program failed: {error:?}"));
    assert_eq!(retained_program, expected_program);
    let decoded_start = DurableExecutionStartV1::decode(
        &retained_program,
        &initial_full.evidence[0].canonical_body,
    )
    .unwrap_or_else(|error| panic!("generic execution start failed: {error:?}"));
    let (recovered_program, recovered_state) =
        recover_authoritative_prefix_with_retained_program(&prefix)
            .unwrap_or_else(|error| panic!("generic sequence-one recovery failed: {error:?}"));
    assert_eq!(recovered_program.as_ref(), &expected_program);
    assert_eq!(recovered_state.latest_sequence(), 1);
    let compacted_state = decoded_start.state().clone();
    let snapshot = DurableRecoverySnapshotV1::new(decoded_start, compacted_state)
        .unwrap_or_else(|error| panic!("generic recovery snapshot failed: {error:?}"));
    let compacted_prefix = JournalPrefixV1::Snapshot(SnapshotJournalPrefixV1 {
        journal_id: initial_full.journal_id.clone(),
        snapshot_version: 2,
        frontier: 1,
        canonical_snapshot: Arc::from(snapshot.canonical_body()),
        retained_evidence: BTreeMap::from([(initial_full.evidence[0].evidence_id, 1)]),
        suffix: Arc::from([]),
        committed_through: initial_full.committed_through,
    });
    let (compacted_program, compacted_state) =
        recover_authoritative_prefix_with_retained_program(&compacted_prefix)
            .unwrap_or_else(|error| panic!("compacted generic recovery failed: {error:?}"));
    assert_eq!(compacted_program.as_ref(), &expected_program);
    assert_eq!(compacted_state.latest_sequence(), 1);
    let compacted_outcome = drive_recovered_generic_machine(compacted_state.into_machine());
    assert_generic_string_envelope(&compacted_outcome);

    let snapshot_path = root.0.join("generic-recovery.snapshot");
    fs::write(&snapshot_path, snapshot.canonical_body())
        .unwrap_or_else(|error| panic!("generic recovery snapshot write failed: {error}"));
    let executable = std::env::current_exe()
        .unwrap_or_else(|error| panic!("current test executable lookup failed: {error}"));
    let fresh_process = Command::new(executable)
        .arg("--exact")
        .arg("durable_generic_artifacts_reconstruct_without_runtime_analysis_and_reject_tampering")
        .arg("--nocapture")
        .env("GANTRY_DURABLE_GENERIC_RECOVERY_CHILD", &snapshot_path)
        .env(
            "GANTRY_DURABLE_GENERIC_EVIDENCE_ID",
            initial_full.evidence[0].evidence_id.to_string(),
        )
        .output()
        .unwrap_or_else(|error| panic!("fresh generic recovery process failed to start: {error}"));
    assert!(
        fresh_process.status.success(),
        "fresh generic recovery process failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&fresh_process.stdout),
        String::from_utf8_lossy(&fresh_process.stderr)
    );
    release(
        storage.as_ref(),
        &journal_id,
        accepted.ownership_token.clone(),
    );

    let source_free_lifecycle = InterpreterLifecycle::new(&configuration);
    let source_free_allocator = FreshIdentityAllocator::default();
    let source_free_package =
        AnalyzePackageCoordinator::new(&source_free_allocator, services.as_ref(), &clock);
    let source_free_start = StartExecutionCoordinator::new(
        &source_free_package,
        &source_free_lifecycle,
        &configuration,
        &source_free_allocator,
        &preflight,
    );
    let source_free_resume = DurableStartExecutionCoordinator::new(
        source_free_start,
        &configuration,
        Arc::clone(&storage_adapter),
    );
    let source_free = match block_on(source_free_resume.resume(DurableResumeExecutionRequest {
        journal_id: journal_id.clone(),
        protocol_selection: &selection,
        candidate_package_root: None,
        expected_execution_id: Some(execution_id),
        event_delivery: None,
    })) {
        DurableResumeExecutionResult::Accepted(accepted) => accepted,
        DurableResumeExecutionResult::Rejected(failure) => {
            panic!("source-free generic resume was rejected: {failure:?}")
        }
    };
    assert_eq!(
        source_free.source_comparison,
        DurableResumeSourceComparison::SourceFree
    );
    assert!(source_free.candidate_package_activity.is_none());
    assert_eq!(source_free.retained_artifacts.canonical_ir(), expected_ir);
    assert_eq!(
        source_free.retained_artifacts.canonical_ir_identity(),
        expected_ir_identity
    );
    assert_eq!(
        source_free.retained_artifacts.generated_schemas(),
        expected_schemas
    );
    assert_eq!(
        source_free.retained_artifacts.generated_schemas_identity(),
        expected_schemas_identity
    );
    assert_eq!(source_free.retained_artifacts.manifest(), expected_manifest);
    assert_eq!(
        source_free.retained_artifacts.manifest_identity(),
        expected_manifest_identity
    );
    assert_eq!(
        source_free.retained_artifacts.source_map(),
        expected_source_map
    );
    assert_eq!(
        source_free.retained_artifacts.source_map_identity(),
        expected_source_map_identity
    );
    let retained_program = source_free
        .recovered
        .execution_start()
        .unwrap_or_else(|| panic!("source-free resume omitted sequence one"))
        .program()
        .unwrap_or_else(|error| panic!("retained generic program was invalid: {error:?}"));
    assert_eq!(retained_program, expected_program);
    assert!(
        retained_program
            .callable_identities()
            .iter()
            .all(|identity| { !identity.as_str().contains('^') })
    );
    let outcome = drive_recovered_generic_machine(source_free.recovered.into_machine());
    assert_generic_string_envelope(&outcome);
    release(
        storage.as_ref(),
        &journal_id,
        source_free.ownership_token.clone(),
    );

    let candidate_lifecycle = InterpreterLifecycle::new(&configuration);
    let candidate_allocator = FreshIdentityAllocator::default();
    let candidate_package =
        AnalyzePackageCoordinator::new(&candidate_allocator, services.as_ref(), &clock);
    let candidate_start = StartExecutionCoordinator::new(
        &candidate_package,
        &candidate_lifecycle,
        &configuration,
        &candidate_allocator,
        &preflight,
    );
    let candidate_resume = DurableStartExecutionCoordinator::new(
        candidate_start,
        &configuration,
        Arc::clone(&storage_adapter),
    );
    let candidate = match block_on(candidate_resume.resume(DurableResumeExecutionRequest {
        journal_id: journal_id.clone(),
        protocol_selection: &selection,
        candidate_package_root: Some(&root.0),
        expected_execution_id: Some(execution_id),
        event_delivery: None,
    })) {
        DurableResumeExecutionResult::Accepted(accepted) => accepted,
        DurableResumeExecutionResult::Rejected(failure) => {
            panic!("candidate generic resume was rejected: {failure:?}")
        }
    };
    assert_eq!(
        candidate.source_comparison,
        DurableResumeSourceComparison::ExactManifest
    );
    assert!(candidate.candidate_package_activity.is_some());
    assert_eq!(
        candidate.retained_artifacts.generated_schemas(),
        expected_schemas
    );
    release(
        storage.as_ref(),
        &journal_id,
        candidate.ownership_token.clone(),
    );

    let (program, recovered) = recover_authoritative_prefix_with_retained_program(&prefix)
        .unwrap_or_else(|error| panic!("generic prefix recovery failed: {error:?}"));
    let execution_start = recovered
        .execution_start()
        .unwrap_or_else(|| panic!("generic prefix omitted sequence one"));
    let mut metadata: serde_json::Value = serde_json::from_slice(execution_start.metadata())
        .unwrap_or_else(|error| panic!("generic metadata failed to decode: {error}"));
    let encoded_schemas = metadata["generated_schemas"]
        .as_str()
        .unwrap_or_else(|| panic!("generic metadata omitted generated schemas"));
    let mut tampered_schemas = encoded_schemas.as_bytes().to_vec();
    tampered_schemas[0] = if tampered_schemas[0] == b'0' {
        b'1'
    } else {
        b'0'
    };
    metadata["generated_schemas"] = serde_json::Value::String(
        String::from_utf8(tampered_schemas)
            .unwrap_or_else(|error| panic!("tampered hex was not UTF-8: {error}")),
    );
    let tampered_metadata = serde_json::to_vec(&metadata)
        .unwrap_or_else(|error| panic!("tampered metadata failed to encode: {error}"));
    let tampered_start = DurableExecutionStartV1::new(
        execution_start.execution_id(),
        execution_start.task_id(),
        &program,
        Arc::<[u8]>::from(tampered_metadata),
        execution_start.state().clone(),
    )
    .unwrap_or_else(|error| panic!("tampered execution start failed to build: {error:?}"));
    let JournalPrefixV1::Full(full) = prefix else {
        panic!("generic start did not produce a full prefix");
    };
    let original_evidence = full.evidence.to_vec();
    let mut evidence = original_evidence.clone();
    evidence[0].canonical_body = Arc::from(tampered_start.canonical_body());
    storage.set_prefix_override(JournalPrefixV1::Full(FullJournalPrefixV1 {
        journal_id: full.journal_id.clone(),
        evidence: Arc::from(evidence),
        committed_through: full.committed_through,
    }));
    let commits_before_tamper = storage.commit_calls();
    let tamper_lifecycle = InterpreterLifecycle::new(&configuration);
    let tamper_allocator = FreshIdentityAllocator::default();
    let tamper_package =
        AnalyzePackageCoordinator::new(&tamper_allocator, services.as_ref(), &clock);
    let tamper_start = StartExecutionCoordinator::new(
        &tamper_package,
        &tamper_lifecycle,
        &configuration,
        &tamper_allocator,
        &preflight,
    );
    let tamper_resume = DurableStartExecutionCoordinator::new(
        tamper_start,
        &configuration,
        Arc::clone(&storage_adapter),
    );
    let DurableResumeExecutionResult::Rejected(failure) =
        block_on(tamper_resume.resume(DurableResumeExecutionRequest {
            journal_id: journal_id.clone(),
            protocol_selection: &selection,
            candidate_package_root: None,
            expected_execution_id: Some(execution_id),
            event_delivery: None,
        }))
    else {
        panic!("tampered retained generic artifact was accepted");
    };
    assert_eq!(
        failure.category,
        ResumeStartFailureCategory::SourceOrConfigurationIncompatibility
    );
    assert_eq!(&*failure.code, "invalid-retained-artifact");
    assert!(failure.release_error.is_none());
    assert_eq!(storage.commit_calls(), commits_before_tamper);

    let mut malformed_start: serde_json::Value =
        serde_json::from_slice(&original_evidence[0].canonical_body)
            .unwrap_or_else(|error| panic!("generic start body failed to decode: {error}"));
    let encoded_program = malformed_start["program"]
        .as_str()
        .unwrap_or_else(|| panic!("generic start body omitted retained program"));
    let mut malformed_program = encoded_program.as_bytes().to_vec();
    malformed_program[0] = if malformed_program[0] == b'0' {
        b'1'
    } else {
        b'0'
    };
    malformed_start["program"] = serde_json::Value::String(
        String::from_utf8(malformed_program)
            .unwrap_or_else(|error| panic!("malformed program hex was not UTF-8: {error}")),
    );
    let mut malformed_evidence = original_evidence;
    malformed_evidence[0].canonical_body = Arc::from(
        serde_json::to_vec(&malformed_start)
            .unwrap_or_else(|error| panic!("malformed start body failed to encode: {error}")),
    );
    storage.set_prefix_override(JournalPrefixV1::Full(FullJournalPrefixV1 {
        journal_id: full.journal_id,
        evidence: Arc::from(malformed_evidence),
        committed_through: full.committed_through,
    }));
    let malformed_lifecycle = InterpreterLifecycle::new(&configuration);
    let malformed_allocator = FreshIdentityAllocator::default();
    let malformed_package =
        AnalyzePackageCoordinator::new(&malformed_allocator, services.as_ref(), &clock);
    let malformed_start = StartExecutionCoordinator::new(
        &malformed_package,
        &malformed_lifecycle,
        &configuration,
        &malformed_allocator,
        &preflight,
    );
    let malformed_resume = DurableStartExecutionCoordinator::new(
        malformed_start,
        &configuration,
        Arc::clone(&storage_adapter),
    );
    let DurableResumeExecutionResult::Rejected(failure) =
        block_on(malformed_resume.resume(DurableResumeExecutionRequest {
            journal_id: journal_id.clone(),
            protocol_selection: &selection,
            candidate_package_root: None,
            expected_execution_id: Some(execution_id),
            event_delivery: None,
        }))
    else {
        panic!("malformed retained generic program was accepted");
    };
    assert_eq!(
        failure.category,
        ResumeStartFailureCategory::SourceOrConfigurationIncompatibility
    );
    assert_eq!(&*failure.code, "invalid-retained-artifact");
    assert!(failure.release_error.is_none());
    assert_eq!(storage.commit_calls(), commits_before_tamper);
}

fn recover_generic_snapshot_in_fresh_process(snapshot: &std::ffi::OsStr) {
    let evidence_id = std::env::var("GANTRY_DURABLE_GENERIC_EVIDENCE_ID")
        .ok()
        .and_then(|value| {
            gantry::identity::ProtocolIdentity::parse_kind(&value, IdentityKind::Evidence).ok()
        })
        .unwrap_or_else(|| panic!("fresh generic recovery process omitted its evidence identity"));
    let prefix = JournalPrefixV1::Snapshot(SnapshotJournalPrefixV1 {
        journal_id: JournalId::new("durable-generic-artifacts")
            .unwrap_or_else(|error| panic!("fresh recovery journal identity failed: {error:?}")),
        snapshot_version: 2,
        frontier: 1,
        canonical_snapshot: Arc::from(
            fs::read(Path::new(snapshot))
                .unwrap_or_else(|error| panic!("fresh recovery snapshot read failed: {error}")),
        ),
        retained_evidence: BTreeMap::from([(evidence_id, 1)]),
        suffix: Arc::from([]),
        committed_through: 1,
    });
    let (program, recovered) = recover_authoritative_prefix_with_retained_program(&prefix)
        .unwrap_or_else(|error| panic!("fresh-process generic recovery failed: {error:?}"));
    assert_eq!(
        program
            .callable_identities()
            .iter()
            .map(|identity| identity.as_str())
            .filter(|identity| identity.ends_with(" as crate::Label>::label"))
            .collect::<Vec<_>>(),
        [
            "<crate::Envelope<Int> as crate::Label>::label",
            "<crate::Envelope<String> as crate::Label>::label",
        ]
    );
    let outcome = drive_recovered_generic_machine(recovered.into_machine());
    assert_generic_string_envelope(&outcome);
}

fn drive_recovered_generic_machine(mut machine: gantry::runtime::Machine) -> MachineOutcome {
    loop {
        match machine.step() {
            MachineStep::Transition(_) => {}
            MachineStep::YieldRequired => assert!(machine.resume_after_yield()),
            MachineStep::Complete(outcome) => return outcome,
            other => panic!("recovered generic machine waited unexpectedly: {other:?}"),
        }
    }
}

fn assert_generic_string_envelope(outcome: &MachineOutcome) {
    assert!(matches!(
        outcome,
        MachineOutcome::Succeeded(value)
            if matches!(value.view(), LogicalValueView::Struct { type_name, .. }
                if type_name == "crate::Envelope<String>")
                && value.canonical_json().bytes() == br#"{"value":"retained"}"#
    ));
}

fn start_request<'a>(
    package_root: &'a Path,
    protocol_selection: &'a ProtocolSelection,
) -> StartExecutionRequest<'a> {
    StartExecutionRequest {
        package_root,
        protocol_selection,
        required_peers: &[],
        entry_input: None,
        root_session: None,
        event_delivery: None,
    }
}

fn start_owned_lifecycle(
    journal_name: &str,
    storage: Arc<dyn JournalStorage>,
) -> (
    InterpreterLifecycle,
    DurableLifecycleCoordinator,
    Arc<gantry::DurableOwnedExecution>,
    gantry::identity::ProtocolIdentity,
    gantry::host::contracts::CancellationSignal,
    JournalId,
) {
    let root = TempDirectory::new(
        b"agents { worker } default agent = worker; action read_only inspect(value: Int) -> Int; fn main() {}",
    );
    let services = Arc::new(Services::default());
    let configuration = test_configuration(Arc::clone(&services));
    let selection = selection();
    let journal_id = JournalId::new(journal_name)
        .unwrap_or_else(|error| panic!("journal identity failed: {error:?}"));
    let clock = FixedClock;
    let preflight = ResolvedPreflight::new("agents-v1", "actions-v1");
    let interpreter_lifecycle = InterpreterLifecycle::new(&configuration);
    let allocator = FreshIdentityAllocator::default();
    let package = AnalyzePackageCoordinator::new(&allocator, services.as_ref(), &clock);
    let start = StartExecutionCoordinator::new(
        &package,
        &interpreter_lifecycle,
        &configuration,
        &allocator,
        &preflight,
    );
    let durable =
        DurableStartExecutionCoordinator::new(start, &configuration, Arc::clone(&storage));
    let accepted = match block_on(durable.start(DurableStartExecutionRequest {
        journal_id: journal_id.clone(),
        start: start_request(&root.0, &selection),
    })) {
        DurableStartExecutionResult::Accepted(accepted) => accepted,
        DurableStartExecutionResult::Rejected(failure) => {
            panic!("durable lifecycle fixture was rejected: {failure:?}")
        }
    };
    let execution_id = accepted.start.execution_id;
    let signal = accepted
        .start
        .handle
        .cancellation_signal()
        .unwrap_or_else(|error| panic!("cancellation signal was unavailable: {error:?}"));
    let lifecycle = DurableLifecycleCoordinator::new(Arc::clone(&storage));
    let owned = block_on(lifecycle.open_owned_execution(
        journal_id.clone(),
        accepted.ownership_token.clone(),
        accepted.start.handle.clone(),
        execution_id,
    ))
    .unwrap_or_else(|error| panic!("durable execution could not be opened: {error:?}"));
    (
        interpreter_lifecycle,
        lifecycle,
        owned,
        execution_id,
        signal,
        journal_id,
    )
}

fn read_prefix(storage: &dyn JournalStorage, journal_id: &JournalId) -> JournalPrefixV1 {
    block_on(storage.read_prefix(ReadJournalPrefixV1 {
        journal_id: journal_id.clone(),
    }))
    .unwrap_or_else(|error| panic!("journal read failed: {error:?}"))
}

fn release(
    storage: &dyn JournalStorage,
    journal_id: &JournalId,
    ownership_token: gantry::host::journal::JournalOwnershipToken,
) {
    block_on(storage.release_owner(ReleaseJournalOwnerV1 {
        journal_id: journal_id.clone(),
        ownership_token,
    }))
    .unwrap_or_else(|error| panic!("owner release failed: {error:?}"));
}

fn test_configuration(services: Arc<Services>) -> InterpreterConfiguration {
    test_configuration_with_policy(services, 1_000, 256)
}

fn test_configuration_with_quantum(
    services: Arc<Services>,
    yield_quantum: u64,
) -> InterpreterConfiguration {
    test_configuration_with_policy(services, yield_quantum, 256)
}

fn test_configuration_with_type_depth(
    services: Arc<Services>,
    maximum_constructed_type_depth: u64,
) -> InterpreterConfiguration {
    test_configuration_with_policy(services, 1_000, maximum_constructed_type_depth)
}

fn test_configuration_with_policy(
    services: Arc<Services>,
    yield_quantum: u64,
    maximum_constructed_type_depth: u64,
) -> InterpreterConfiguration {
    let required = RequiredConfiguration::new(
        FrontendLimits::new(
            32,
            1_048_576,
            4_194_304,
            262_144,
            256,
            4_194_304,
            4_194_304,
            4_194_304,
            4_194_304,
            maximum_constructed_type_depth,
            65_536,
            1_000_000,
        )
        .unwrap_or_else(|error| panic!("frontend limits failed: {error:?}")),
        1_048_576,
        1_048_576,
        ValueLimits::new(128, 262_144, 262_144, 65_536)
            .unwrap_or_else(|| panic!("value limits failed")),
        1_000_000,
        100_000,
        100_000,
        yield_quantum,
    )
    .unwrap_or_else(|error| panic!("required configuration failed: {error}"));
    InterpreterConfiguration::new(services.clone(), services, required)
}

fn best_effort_plan() -> SinkPlan {
    let retry = EventRetryPolicy::new("retry-v1", 0, 0, 0, JitterMode::None)
        .unwrap_or_else(|error| panic!("event retry policy failed: {error:?}"));
    let policy = SinkDeliveryPolicy::new(
        SinkClass::BestEffort,
        false,
        "redaction-v1",
        RedactionCapabilities::default(),
        retry,
        30_000_000,
    )
    .unwrap_or_else(|error| panic!("sink policy failed: {error:?}"));
    let id = SinkId::new("audit").unwrap_or_else(|error| panic!("sink identity failed: {error:?}"));
    SinkPlan::new(vec![SinkRegistration::new(id, policy, Arc::new(FixedSink))])
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
    .unwrap_or_else(|error| panic!("published selection failed: {error:?}"))
}

fn host_failure(code: &str) -> HostError {
    HostError {
        code: Arc::from(code),
        protected_diagnostic: None,
    }
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

fn assert_anchor_exists(root: &Path, evidence: &str) {
    let (path, test) = evidence
        .split_once('#')
        .unwrap_or_else(|| panic!("evidence anchor is malformed: {evidence}"));
    let source = fs::read_to_string(root.join(path))
        .unwrap_or_else(|error| panic!("could not read evidence source {path}: {error}"));
    assert!(
        source.contains(&format!("fn {test}(")),
        "missing evidence anchor {evidence}"
    );
}
