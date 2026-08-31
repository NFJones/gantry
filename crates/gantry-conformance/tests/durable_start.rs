//! Public-facade regressions for durable start and resume pre-acceptance behavior.

use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll, Waker};

use gantry::host::contracts::{
    EmbeddingVersion, ExecutorAdapter, FreshIdentityAllocator, HostError, HostFuture, HostRequest,
    HostResponse, IdentitySource, InclusiveJitterRange, IntegrationPreflight, JournalStorage,
    UtcClock,
};
use gantry::host::embedding::EmbeddingOperation;
use gantry::host::event::{
    EventDeliveryRequest, EventRetryPolicy, EventSink, RedactionCapabilities, SinkDeliveryPolicy,
    SinkId,
};
use gantry::host::journal::{
    JournalId, JournalPrefixV1, ReadJournalPrefixV1, ReleaseJournalOwnerV1,
};
use gantry::observe::{SinkPlan, SinkRegistration};
use gantry::portable::{
    DeliveryOutcome, IdentityKind, JitterMode, PORTABLE_SPECIFICATION_REVISION,
    PROTOCOL_FAMILY_DEFINITIONS, ResumeStartFailureCategory, SinkClass, StartFailureCategory,
};
use gantry::protocol::{ProtocolSelection, ProtocolVersion, SelectedProtocol};
use gantry::runtime::{
    InMemoryJournalStore, InterpreterConfiguration, InterpreterLifecycle, RequiredConfiguration,
    recover_authoritative_prefix_with_retained_program,
};
use gantry::source::FrontendLimits;
use gantry::timestamp::UtcTimestamp;
use gantry::value::ValueLimits;
use gantry::{
    AnalyzePackageCoordinator, DurableResumeExecutionRequest, DurableResumeExecutionResult,
    DurableResumeSourceComparison, DurableStartExecutionCoordinator, DurableStartExecutionRequest,
    DurableStartExecutionResult, StartExecutionCoordinator, StartExecutionRequest,
};
use serde::Deserialize;

const DURABLE_START_EVIDENCE: &str = "crates/gantry-conformance/tests/durable_start.rs#durable_start_and_resume_preserve_acceptance_and_nonmutation_boundaries";

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
    assert_eq!(manifest.specification_sha256, review.specification_sha256);
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
    test_configuration_with_quantum(services, 1_000)
}

fn test_configuration_with_quantum(
    services: Arc<Services>,
    yield_quantum: u64,
) -> InterpreterConfiguration {
    let required = RequiredConfiguration::new(
        FrontendLimits::new(
            32, 1_048_576, 4_194_304, 262_144, 256, 4_194_304, 4_194_304, 4_194_304, 4_194_304,
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
