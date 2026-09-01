//! External `ValidatePackage` coverage through the public Gantry facade.

use std::collections::{BTreeMap, VecDeque};
use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use gantry::analysis::AnalysisStatus;
use gantry::frontend::PackageSyntaxStatus;
use gantry::host::contracts::{
    FreshIdentityAllocator, HostError, HostFuture, IdentitySource, UtcClock,
};
use gantry::host::event::{
    EventDeliveryRequest, EventDeliveryRuntime, EventRetryPolicy, EventSink, RedactionCapabilities,
    SinkDeliveryPolicy, SinkId,
};
use gantry::observe::{SinkPlan, SinkRegistration};
use gantry::portable::{
    DeliveryOutcome, EventKind, EventLayer, FrontendResourceCode, IdentityKind, JitterMode,
    PORTABLE_SPECIFICATION_REVISION, PROTOCOL_FAMILY_DEFINITIONS, SinkClass,
};
use gantry::protocol::{ProtocolSelection, ProtocolVersion, SelectedProtocol};
use gantry::source::{FrontendLimits, GenericAnalysisCounters};
use gantry::timestamp::UtcTimestamp;
use gantry::{
    AnalyzePackageCoordinator, AnalyzePackageError, AnalyzePackageRequest, AnalyzePackageStatus,
    ValidatePackageCoordinator, ValidatePackageError, ValidatePackageRequest,
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct AnalyzerPackageEvidence {
    format: String,
    specification_sha256: String,
    issue: String,
    entries: Vec<AnalyzerPackageEvidenceEntry>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
struct AnalyzerPackageEvidenceEntry {
    requirement: String,
    clause: String,
    evidence: String,
}

#[derive(Debug, Deserialize)]
struct RequirementReview {
    specification_sha256: String,
    requirements: Vec<ReviewedRequirement>,
}

#[derive(Debug, Deserialize)]
struct ReviewedRequirement {
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

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TempDirectory(PathBuf);

impl TempDirectory {
    fn new(source: &[u8]) -> Self {
        let suffix = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "gantry-validate-conformance-{}-{suffix}",
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

struct ScriptedIdentities {
    responses: Mutex<VecDeque<Result<[u8; 32], HostError>>>,
    calls: Mutex<Vec<IdentityKind>>,
}

impl ScriptedIdentities {
    fn new(responses: impl IntoIterator<Item = Result<[u8; 32], HostError>>) -> Self {
        Self {
            responses: Mutex::new(responses.into_iter().collect()),
            calls: Mutex::new(Vec::new()),
        }
    }

    fn calls(&self) -> Vec<IdentityKind> {
        self.calls
            .lock()
            .map(|calls| calls.clone())
            .unwrap_or_default()
    }
}

impl IdentitySource for ScriptedIdentities {
    fn fresh_material(&self, kind: IdentityKind) -> Result<[u8; 32], HostError> {
        self.calls
            .lock()
            .map_err(|_| failure("identity-state"))?
            .push(kind);
        self.responses
            .lock()
            .map_err(|_| failure("identity-state"))?
            .pop_front()
            .unwrap_or_else(|| Err(failure("identity-exhausted")))
    }
}

struct FixedClock(Result<UtcTimestamp, HostError>);

impl UtcClock for FixedClock {
    fn utc_now<'a>(&'a self) -> HostFuture<'a, Result<UtcTimestamp, HostError>> {
        Box::pin(async move { self.0.clone() })
    }
}

struct FixedSink(DeliveryOutcome);

impl EventSink for FixedSink {
    fn deliver<'a>(
        &'a self,
        _request: EventDeliveryRequest,
    ) -> HostFuture<'a, Result<DeliveryOutcome, HostError>> {
        Box::pin(async move { Ok(self.0) })
    }
}

struct ImmediateRuntime;

impl EventDeliveryRuntime for ImmediateRuntime {
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

    fn sample_full_jitter(&self, ceiling_us: u64) -> Result<u64, HostError> {
        Ok(ceiling_us)
    }
}

#[test]
fn valid_and_invalid_packages_each_expose_one_parse_occurrence() {
    for (source, expected, payload) in [
        (
            &b"fn main() {}"[..],
            PackageSyntaxStatus::Valid,
            "{\"diagnostics\":[],\"phase\":\"parse\",\"status\":\"syntax-valid\"}",
        ),
        (
            &b"fn main( {"[..],
            PackageSyntaxStatus::Invalid,
            "\"status\":\"syntax-invalid\"",
        ),
    ] {
        let root = TempDirectory::new(source);
        let identities = ScriptedIdentities::new([Ok([1; 32]), Ok([2; 32])]);
        let allocator = FreshIdentityAllocator::default();
        let clock = FixedClock(Ok(timestamp()));
        let coordinator = ValidatePackageCoordinator::new(&allocator, &identities, &clock);
        let selection = selection();
        let result = block_on(coordinator.validate(request(&root.0, &selection, None)));
        assert!(result.is_ok());
        let result = result.unwrap_or_else(|_| unreachable!("checked above"));
        assert_eq!(result.phase.status(), expected);
        assert_eq!(result.event.kind(), EventKind::Parse);
        assert_eq!(result.event.layer(), EventLayer::Physical);
        assert_eq!(result.event.activity_id(), result.activity_id);
        assert!(result.event.execution_id().is_none());
        let event_payload = std::str::from_utf8(result.event.payload().canonical_bytes());
        assert!(event_payload.is_ok_and(|actual| {
            if expected == PackageSyntaxStatus::Valid {
                actual == payload
            } else {
                actual.contains(payload) && actual.contains("\"phase\":\"parse\"")
            }
        }));
        assert_eq!(
            identities.calls(),
            vec![IdentityKind::Activity, IdentityKind::Event]
        );
    }
}

#[test]
fn semantic_errors_remain_outside_syntax_only_validation() {
    let root = TempDirectory::new(
        b"mod child;\nmod child;\nmod nested_scope { mod nested; }\nuse child::thing;\nstruct Duplicate { value: Int, value: Int }\nfn recursive() { recursive(); }\nfn main() { missing_name; child::thing(); }",
    );
    assert!(fs::write(root.0.join("child.gnt"), b"fn thing() {}").is_ok());
    assert!(fs::create_dir(root.0.join("nested_scope")).is_ok());
    assert!(fs::write(root.0.join("nested_scope/nested.gnt"), b"fn nested() {}").is_ok());
    let identities = ScriptedIdentities::new([Ok([8; 32]), Ok([9; 32])]);
    let allocator = FreshIdentityAllocator::default();
    let clock = FixedClock(Ok(timestamp()));
    let coordinator = ValidatePackageCoordinator::new(&allocator, &identities, &clock);
    let selection = selection();

    let result = block_on(coordinator.validate(request(&root.0, &selection, None)));
    assert!(result.is_ok());
    let result = result.unwrap_or_else(|_| unreachable!("checked above"));
    assert_eq!(result.phase.status(), PackageSyntaxStatus::Valid);
    assert!(result.phase.diagnostics().is_empty());
    assert_eq!(result.phase.snapshot().records().len(), 3);
    assert!(result.event.execution_id().is_none());
}

#[test]
fn reviewed_analyzer_package_evidence_is_closed() {
    let root = workspace_root();
    let manifest: AnalyzerPackageEvidence =
        read_json(&root.join("protocol/conformance/analyzer-package-v1.json"));
    let review: RequirementReview = read_json(&root.join("protocol/requirements/reviewed-v1.json"));

    assert_eq!(manifest.format, "gantry.analyzer-package-evidence/v1");
    assert_eq!(manifest.issue, "GNT-AN-006");
    assert!(gantry_conformance::evidence_revision_is_expected(
        &manifest.specification_sha256,
        &review.specification_sha256,
    ));
    assert!(manifest.entries.windows(2).all(|pair| pair[0] < pair[1]));

    let mut entries = BTreeMap::<(String, String), Vec<String>>::new();
    for entry in manifest.entries {
        entries
            .entry((entry.requirement, entry.clause))
            .or_default()
            .push(entry.evidence);
    }
    for ((requirement_id, clause_key), evidence) in entries {
        let clause = review
            .requirements
            .iter()
            .find(|requirement| requirement.id == requirement_id)
            .and_then(|requirement| {
                requirement
                    .clauses
                    .iter()
                    .find(|clause| clause.key == clause_key)
            })
            .unwrap_or_else(|| panic!("missing {requirement_id}:{clause_key}"));
        let analyzer = clause
            .profile_reviews
            .iter()
            .find(|profile| profile.profile == "analyzer")
            .unwrap_or_else(|| panic!("missing analyzer review for {requirement_id}:{clause_key}"));
        assert_eq!(analyzer.state, "covered");
        assert_eq!(analyzer.evidence, evidence);
    }
}

#[test]
fn analyze_package_sequences_phases_and_exposes_valid_artifacts() {
    let valid = TempDirectory::new(b"fn main() {}");
    let identities = ScriptedIdentities::new([Ok([1; 32]), Ok([2; 32]), Ok([3; 32])]);
    let allocator = FreshIdentityAllocator::default();
    let clock = FixedClock(Ok(timestamp()));
    let coordinator = AnalyzePackageCoordinator::new(&allocator, &identities, &clock);
    let selection = selection();

    let result = block_on(coordinator.analyze(analyze_request(&valid.0, &selection, None)));
    assert!(result.is_ok());
    let result = result.unwrap_or_else(|_| unreachable!("checked above"));
    assert_eq!(result.status, AnalyzePackageStatus::SourceValid);
    assert_eq!(result.syntax.status(), PackageSyntaxStatus::Valid);
    assert_eq!(
        result
            .events
            .iter()
            .map(|event| event.kind())
            .collect::<Vec<_>>(),
        [EventKind::Parse, EventKind::Analysis]
    );
    assert!(result.events.iter().all(|event| {
        event.layer() == EventLayer::Physical
            && event.activity_id() == result.activity_id
            && event.execution_id().is_none()
    }));
    assert!(
        std::str::from_utf8(result.events[1].payload().canonical_bytes())
            .is_ok_and(|payload| payload
                == "{\"diagnostics\":[],\"phase\":\"analysis\",\"status\":\"source-valid\"}")
    );
    let analysis = result
        .analysis
        .as_ref()
        .unwrap_or_else(|| unreachable!("source-valid analysis is retained"));
    assert_eq!(analysis.status(), AnalysisStatus::Valid);
    assert!(analysis.manifest().is_some());
    assert!(analysis.canonical_ir().is_some());
    assert!(analysis.source_map().is_some());
    assert!(analysis.schemas().is_some());
    assert_eq!(
        identities.calls(),
        vec![
            IdentityKind::Activity,
            IdentityKind::Event,
            IdentityKind::Event,
        ]
    );
}

#[test]
fn analyze_package_stops_after_syntax_failure_and_reports_semantic_failure() {
    let syntax_invalid = TempDirectory::new(b"fn main( {");
    let identities = ScriptedIdentities::new([Ok([4; 32]), Ok([5; 32])]);
    let allocator = FreshIdentityAllocator::default();
    let clock = FixedClock(Ok(timestamp()));
    let coordinator = AnalyzePackageCoordinator::new(&allocator, &identities, &clock);
    let selection = selection();
    let result =
        block_on(coordinator.analyze(analyze_request(&syntax_invalid.0, &selection, None)));
    assert!(result.is_ok());
    let result = result.unwrap_or_else(|_| unreachable!("checked above"));
    assert_eq!(result.status, AnalyzePackageStatus::SourceInvalid);
    assert!(result.analysis.is_none());
    assert_eq!(result.events.len(), 1);
    assert_eq!(result.events[0].kind(), EventKind::Parse);
    assert_eq!(
        identities.calls(),
        vec![IdentityKind::Activity, IdentityKind::Event]
    );

    let semantic_invalid = TempDirectory::new(b"fn main() -> Int { \"wrong\" }");
    let identities = ScriptedIdentities::new([Ok([6; 32]), Ok([7; 32]), Ok([8; 32])]);
    let coordinator = AnalyzePackageCoordinator::new(&allocator, &identities, &clock);
    let result =
        block_on(coordinator.analyze(analyze_request(&semantic_invalid.0, &selection, None)));
    assert!(result.is_ok());
    let result = result.unwrap_or_else(|_| unreachable!("checked above"));
    assert_eq!(result.status, AnalyzePackageStatus::SourceInvalid);
    assert_eq!(result.events.len(), 2);
    assert_eq!(result.events[1].kind(), EventKind::Analysis);
    let analysis = result
        .analysis
        .as_ref()
        .unwrap_or_else(|| unreachable!("semantic analysis completed"));
    assert_eq!(analysis.status(), AnalysisStatus::Invalid);
    assert!(analysis.canonical_ir().is_none());
    assert!(analysis.source_map().is_none());
    assert!(
        std::str::from_utf8(result.events[1].payload().canonical_bytes())
            .is_ok_and(|payload| payload.contains("\"status\":\"source-invalid\"")
                && payload.contains("\"phase\":\"analysis\""))
    );
}

#[test]
fn analyze_package_preserves_event_barrier_and_limit_failure_order() {
    let root = TempDirectory::new(b"fn main() {}");
    let allocator = FreshIdentityAllocator::default();
    let clock = FixedClock(Ok(timestamp()));
    let selection = selection();

    let identities = ScriptedIdentities::new([Ok([9; 32]), Ok([10; 32])]);
    let coordinator = AnalyzePackageCoordinator::new(&allocator, &identities, &clock);
    let result = block_on(coordinator.analyze(analyze_request(&root.0, &selection, None)));
    assert!(matches!(result, Err(AnalyzePackageError::Event(_))));
    assert_eq!(
        identities.calls(),
        vec![
            IdentityKind::Activity,
            IdentityKind::Event,
            IdentityKind::Event,
        ]
    );

    let identities = ScriptedIdentities::new([
        Ok([11; 32]),
        Ok([12; 32]),
        Ok([13; 32]),
        Ok([14; 32]),
        Ok([15; 32]),
    ]);
    let runtime = ImmediateRuntime;
    let coordinator = AnalyzePackageCoordinator::new(&allocator, &identities, &clock)
        .with_delivery_runtime(&runtime);
    let plan = required_plan(DeliveryOutcome::Success);
    let result = block_on(coordinator.analyze(analyze_request(&root.0, &selection, Some(&plan))));
    assert!(result.is_ok());
    let result = result.unwrap_or_else(|_| unreachable!("checked above"));
    assert_eq!(result.deliveries.as_ref().map(Vec::len), Some(2));
    assert_eq!(
        identities.calls(),
        vec![
            IdentityKind::Activity,
            IdentityKind::Event,
            IdentityKind::DeliveryAttempt,
            IdentityKind::Event,
            IdentityKind::DeliveryAttempt,
        ]
    );

    let identities = ScriptedIdentities::new([Ok([16; 32]), Ok([17; 32]), Ok([18; 32])]);
    let coordinator = AnalyzePackageCoordinator::new(&allocator, &identities, &clock)
        .with_delivery_runtime(&runtime);
    let plan = required_plan(DeliveryOutcome::Terminal);
    let result = block_on(coordinator.analyze(analyze_request(&root.0, &selection, Some(&plan))));
    assert_eq!(result, Err(AnalyzePackageError::RequiredEventDelivery));
    assert_eq!(
        identities.calls(),
        vec![
            IdentityKind::Activity,
            IdentityKind::Event,
            IdentityKind::DeliveryAttempt,
        ]
    );

    let identities = ScriptedIdentities::new([Ok([19; 32]), Ok([20; 32])]);
    let coordinator = AnalyzePackageCoordinator::new(&allocator, &identities, &clock);
    let limits = FrontendLimits::new(32, 1_048_576, 4_194_304, 262_144, 256, 1, 1, 1, 1, 1, 1, 1)
        .unwrap_or_else(|_| unreachable!("positive limits"));
    let result = block_on(coordinator.analyze(AnalyzePackageRequest {
        package_root: &root.0,
        protocol_selection: &selection,
        frontend_limits: limits,
        event_delivery: None,
    }));
    assert!(matches!(
        result,
        Err(AnalyzePackageError::Analysis(
            gantry::analysis::AnalysisError::ResourceLimit { .. }
        ))
    ));
    assert_eq!(
        identities.calls(),
        vec![IdentityKind::Activity, IdentityKind::Event]
    );
}

#[test]
fn complete_frontend_limit_policy_is_public_and_finite() {
    const MAXIMUM: u64 = i64::MAX as u64;

    assert!(
        FrontendLimits::new(
            MAXIMUM, MAXIMUM, MAXIMUM, MAXIMUM, MAXIMUM, MAXIMUM, MAXIMUM, MAXIMUM, MAXIMUM,
            MAXIMUM, MAXIMUM, MAXIMUM,
        )
        .is_ok()
    );
    for index in 0..12 {
        let mut zero = [1; 12];
        zero[index] = 0;
        assert!(
            FrontendLimits::new(
                zero[0], zero[1], zero[2], zero[3], zero[4], zero[5], zero[6], zero[7], zero[8],
                zero[9], zero[10], zero[11],
            )
            .is_err()
        );

        let mut oversized = [1; 12];
        oversized[index] = MAXIMUM + 1;
        assert!(
            FrontendLimits::new(
                oversized[0],
                oversized[1],
                oversized[2],
                oversized[3],
                oversized[4],
                oversized[5],
                oversized[6],
                oversized[7],
                oversized[8],
                oversized[9],
                oversized[10],
                oversized[11],
            )
            .is_err()
        );
    }
}

#[test]
fn generic_analysis_policy_charges_are_public_and_failure_atomic() {
    let limits = FrontendLimits::new(1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 1, 3)
        .unwrap_or_else(|_| unreachable!("positive limits"));
    let mut counters = GenericAnalysisCounters::new(limits);

    assert_eq!(counters.check_constructed_type_depth(2), Ok(()));
    assert!(matches!(
        counters.check_constructed_type_depth(3),
        Err(limit)
            if limit.code == FrontendResourceCode::ConstructedTypeDepthLimit
                && limit.limit == 2
                && limit.observed == Some(3)
    ));
    assert_eq!(counters.charge_generic_instantiation(), Ok(()));
    assert!(matches!(
        counters.charge_generic_instantiation(),
        Err(limit)
            if limit.code == FrontendResourceCode::GenericInstantiationLimit
                && limit.limit == 1
                && limit.observed == Some(2)
    ));
    assert_eq!(counters.charge_trait_resolution_steps(3), Ok(()));
    assert!(matches!(
        counters.charge_trait_resolution_steps(u64::MAX),
        Err(limit)
            if limit.code == FrontendResourceCode::TraitResolutionStepLimit
                && limit.limit == 3
                && limit.observed.is_none()
    ));
    assert_eq!(counters.counts(), (1, 3));
    assert_eq!(GenericAnalysisCounters::new(limits).counts(), (0, 0));
}

#[test]
fn validate_and_analyze_enforce_constructed_type_depth_per_activity() {
    let root = TempDirectory::new(b"fn main(value: Option<Option<Int>>) {}");
    let allocator = FreshIdentityAllocator::default();
    let clock = FixedClock(Ok(timestamp()));
    let selection = selection();

    let admitted_limits = FrontendLimits::new(
        1, 4_096, 4_096, 128, 8, 4_096, 4_096, 4_096, 4_096, 3, 128, 128,
    )
    .unwrap_or_else(|_| unreachable!("positive limits"));
    let admitted_identities = ScriptedIdentities::new([Ok([21; 32]), Ok([22; 32])]);
    let validate = ValidatePackageCoordinator::new(&allocator, &admitted_identities, &clock);
    let admitted = block_on(validate.validate(request_with_limits(
        &root.0,
        &selection,
        admitted_limits,
        None,
    )));
    assert!(admitted.is_ok(), "at-limit validation failed: {admitted:?}");

    let rejected_limits = FrontendLimits::new(
        1, 4_096, 4_096, 128, 8, 4_096, 4_096, 4_096, 4_096, 2, 128, 128,
    )
    .unwrap_or_else(|_| unreachable!("positive limits"));
    let validate_identities = ScriptedIdentities::new([Ok([23; 32])]);
    let validate = ValidatePackageCoordinator::new(&allocator, &validate_identities, &clock);
    let rejected = block_on(validate.validate(request_with_limits(
        &root.0,
        &selection,
        rejected_limits,
        None,
    )));
    assert!(matches!(
        rejected,
        Err(ValidatePackageError::Package(error))
            if matches!(
                error.frontend_resource_limit(),
                Some(limit)
                    if limit.code == FrontendResourceCode::ConstructedTypeDepthLimit
                        && limit.limit == 2
                        && limit.observed == Some(3)
            )
    ));
    assert_eq!(validate_identities.calls(), vec![IdentityKind::Activity]);

    let analyze_identities = ScriptedIdentities::new([Ok([24; 32])]);
    let analyze = AnalyzePackageCoordinator::new(&allocator, &analyze_identities, &clock);
    let rejected = block_on(analyze.analyze(AnalyzePackageRequest {
        package_root: &root.0,
        protocol_selection: &selection,
        frontend_limits: rejected_limits,
        event_delivery: None,
    }));
    assert!(matches!(
        rejected,
        Err(AnalyzePackageError::Package(error))
            if matches!(
                error.frontend_resource_limit(),
                Some(limit)
                    if limit.code == FrontendResourceCode::ConstructedTypeDepthLimit
                        && limit.limit == 2
                        && limit.observed == Some(3)
            )
    ));
    assert_eq!(analyze_identities.calls(), vec![IdentityKind::Activity]);
}

#[test]
fn frontend_limit_failure_is_separate_and_retains_diagnostics() {
    let root = TempDirectory::new(
        b"struct Broken { value Int; }\naction read_only missing( -> String;\nfn good() {}",
    );
    let identities = ScriptedIdentities::new([Ok([10; 32])]);
    let allocator = FreshIdentityAllocator::default();
    let clock = FixedClock(Ok(timestamp()));
    let coordinator = ValidatePackageCoordinator::new(&allocator, &identities, &clock);
    let selection = selection();
    let limits = FrontendLimits::new(
        1, 4_096, 4_096, 128, 1, 4_096, 4_096, 4_096, 4_096, 64, 128, 128,
    )
    .unwrap_or_else(|_| unreachable!("positive limits"));

    let result =
        block_on(coordinator.validate(request_with_limits(&root.0, &selection, limits, None)));
    let error = match result {
        Err(ValidatePackageError::Package(error)) => error,
        other => panic!("expected package resource limit, got {other:?}"),
    };
    assert_eq!(error.code(), "frontend-resource-limit");
    assert!(matches!(
        error.frontend_resource_limit(),
        Some(limit)
            if limit.code == FrontendResourceCode::DiagnosticCountLimit
                && limit.limit == 1
                && limit.observed == Some(2)
    ));
    assert_eq!(error.retained_diagnostics().len(), 1);
    assert_eq!(identities.calls(), vec![IdentityKind::Activity]);
}

#[test]
fn identity_source_and_clock_failures_preserve_phase_ordering() {
    let missing = std::env::temp_dir().join("gantry-conformance-missing-package");
    let identities = ScriptedIdentities::new([Err(failure("identity-failed"))]);
    let allocator = FreshIdentityAllocator::default();
    let clock = FixedClock(Ok(timestamp()));
    let coordinator = ValidatePackageCoordinator::new(&allocator, &identities, &clock);
    let selection = selection();
    let result = block_on(coordinator.validate(request(&missing, &selection, None)));
    assert!(matches!(
        result,
        Err(ValidatePackageError::ActivityIdentity(_))
    ));
    assert_eq!(identities.calls(), vec![IdentityKind::Activity]);

    let root = TempDirectory::new(b"fn main() {}");
    let identities = ScriptedIdentities::new([Ok([3; 32]), Ok([4; 32])]);
    let clock = FixedClock(Err(failure("clock-failed")));
    let coordinator = ValidatePackageCoordinator::new(&allocator, &identities, &clock);
    let result = block_on(coordinator.validate(request(&root.0, &selection, None)));
    assert!(matches!(result, Err(ValidatePackageError::Event(_))));
    assert_eq!(
        identities.calls(),
        vec![IdentityKind::Activity, IdentityKind::Event]
    );
}

#[test]
fn required_sink_exhaustion_is_an_operational_failure_after_parse() {
    let root = TempDirectory::new(b"fn main() {}");
    let identities = ScriptedIdentities::new([Ok([5; 32]), Ok([6; 32]), Ok([7; 32])]);
    let allocator = FreshIdentityAllocator::default();
    let clock = FixedClock(Ok(timestamp()));
    let runtime = ImmediateRuntime;
    let coordinator = ValidatePackageCoordinator::new(&allocator, &identities, &clock)
        .with_delivery_runtime(&runtime);
    let selection = selection();
    let plan = required_plan(DeliveryOutcome::Terminal);
    let result = block_on(coordinator.validate(request(&root.0, &selection, Some(&plan))));
    assert_eq!(result, Err(ValidatePackageError::RequiredEventDelivery));
    assert_eq!(
        identities.calls(),
        vec![
            IdentityKind::Activity,
            IdentityKind::Event,
            IdentityKind::DeliveryAttempt,
        ]
    );
}

fn request<'a>(
    root: &'a std::path::Path,
    selection: &'a ProtocolSelection,
    event_delivery: Option<&'a SinkPlan>,
) -> ValidatePackageRequest<'a> {
    let limits = FrontendLimits::new(
        32, 1_048_576, 4_194_304, 262_144, 256, 4_194_304, 4_194_304, 4_194_304, 4_194_304, 256,
        65_536, 1_000_000,
    )
    .unwrap_or_else(|_| unreachable!("positive limits"));
    request_with_limits(root, selection, limits, event_delivery)
}

fn request_with_limits<'a>(
    root: &'a std::path::Path,
    selection: &'a ProtocolSelection,
    frontend_limits: FrontendLimits,
    event_delivery: Option<&'a SinkPlan>,
) -> ValidatePackageRequest<'a> {
    ValidatePackageRequest {
        package_root: root,
        protocol_selection: selection,
        frontend_limits,
        event_delivery,
    }
}

fn analyze_request<'a>(
    root: &'a std::path::Path,
    selection: &'a ProtocolSelection,
    event_delivery: Option<&'a SinkPlan>,
) -> AnalyzePackageRequest<'a> {
    AnalyzePackageRequest {
        package_root: root,
        protocol_selection: selection,
        frontend_limits: FrontendLimits::new(
            32, 1_048_576, 4_194_304, 262_144, 256, 4_194_304, 4_194_304, 4_194_304, 4_194_304,
            256, 65_536, 1_000_000,
        )
        .unwrap_or_else(|_| unreachable!("positive limits")),
        event_delivery,
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
    .unwrap_or_else(|_| unreachable!("published selection"))
}

fn required_plan(outcome: DeliveryOutcome) -> SinkPlan {
    let retry = EventRetryPolicy::new("retry-v1", 0, 0, 0, JitterMode::None)
        .unwrap_or_else(|_| unreachable!("valid retry policy"));
    let policy = SinkDeliveryPolicy::new(
        SinkClass::Required,
        false,
        "redaction-v1",
        RedactionCapabilities::default(),
        retry,
        30,
    )
    .unwrap_or_else(|_| unreachable!("valid sink policy"));
    SinkPlan::new(vec![SinkRegistration::new(
        SinkId::new("required").unwrap_or_else(|_| unreachable!("valid sink ID")),
        policy,
        Arc::new(FixedSink(outcome)),
    )])
    .unwrap_or_else(|_| unreachable!("valid sink plan"))
}

fn timestamp() -> UtcTimestamp {
    UtcTimestamp::from_unix_seconds(0, 42).unwrap_or_else(|_| unreachable!("valid timestamp"))
}

fn failure(code: &str) -> HostError {
    HostError {
        code: code.into(),
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
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> T {
    let bytes =
        fs::read(path).unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|error| panic!("could not decode {}: {error}", path.display()))
}
