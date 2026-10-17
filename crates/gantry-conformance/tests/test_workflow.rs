//! External conformance for the experimental `gantry test` unit workflow.
//!
//! These rows exercise the facade contract of `GNT-GP-TOOLING-RUNTIME-001` decision D7 over the
//! landed `std.test` harness: the versioned identity/policy/ordered-result/refusal report, the
//! zero-authority unit entry selection, preflight refusals that dispatch no frontend stage, the
//! empty-inventory admission, and the four exit classes the reference CLI maps. They present only
//! public facade types and add no declaration of the `std.test` surface.

use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::pin;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll, Waker};

use gantry::host::contracts::{
    FreshIdentityAllocator, HostError, HostFuture, IdentitySource, UtcClock,
};
use gantry::ir::toolchain::BudgetUnit;
use gantry::ir::{TestKind, TestSubstitution};
use gantry::portable::{
    IdentityKind, PORTABLE_SPECIFICATION_REVISION, PROTOCOL_FAMILY_DEFINITIONS,
};
use gantry::protocol::{ProtocolSelection, ProtocolVersion, SelectedProtocol};
use gantry::timestamp::UtcTimestamp;
use gantry::{
    TEST_WORKFLOW_FRONTEND_STAGES, TEST_WORKFLOW_JOBS, TEST_WORKFLOW_OUTPUT_CEILING_BYTES,
    TEST_WORKFLOW_POLICY_REVISION, TEST_WORKFLOW_REPORT_FORMAT, TEST_WORKFLOW_REPORT_VERSION,
    TEST_WORKFLOW_TOOLCHAIN_IDENTITY, TestPolicyBound, TestWorkflowDeclarations,
    TestWorkflowIdentity, TestWorkflowPolicy, TestWorkflowPolicyError, TestWorkflowReport,
    TestWorkflowRequest, TestWorkflowServices, TestWorkflowStage, TestWorkflowStatus,
    TestWorkflowTargetClassification, run_test_workflow,
};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

/// One package directory removed when the row finishes.
struct TempDirectory(PathBuf);

impl TempDirectory {
    /// Creates one package directory holding `main.gnt` with the supplied source.
    fn new(source: &[u8]) -> Self {
        let suffix = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "gantry-test-workflow-conformance-{}-{suffix}",
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

/// One deterministic fresh identity source that records every requested kind.
struct SequentialIdentities {
    next: AtomicU64,
    calls: Mutex<Vec<IdentityKind>>,
}

impl Default for SequentialIdentities {
    fn default() -> Self {
        Self {
            next: AtomicU64::new(1),
            calls: Mutex::new(Vec::new()),
        }
    }
}

impl SequentialIdentities {
    /// Returns the identity kinds requested so far, in request order.
    fn calls(&self) -> Vec<IdentityKind> {
        self.calls
            .lock()
            .map(|calls| calls.clone())
            .unwrap_or_default()
    }
}

impl IdentitySource for SequentialIdentities {
    fn fresh_material(&self, kind: IdentityKind) -> Result<[u8; 32], HostError> {
        if let Ok(mut calls) = self.calls.lock() {
            calls.push(kind);
        }
        let value = self.next.fetch_add(1, Ordering::Relaxed);
        let mut material = [0_u8; 32];
        material[..8].copy_from_slice(&value.to_be_bytes());
        material[31] = 1;
        Ok(material)
    }
}

/// One fixed UTC clock.
struct FixedClock;

impl UtcClock for FixedClock {
    fn utc_now<'a>(&'a self) -> HostFuture<'a, Result<UtcTimestamp, HostError>> {
        Box::pin(async {
            Ok(UtcTimestamp::from_unix_seconds(0, 42)
                .unwrap_or_else(|_| unreachable!("fixed timestamp is valid")))
        })
    }
}

/// Returns the published complete protocol selection.
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

/// Returns the published identity record.
fn published_identity() -> TestWorkflowIdentity {
    TestWorkflowIdentity::observed(&selection(), TEST_WORKFLOW_TOOLCHAIN_IDENTITY)
        .unwrap_or_else(|_| unreachable!("published identity"))
}

/// Returns one declared policy bound.
fn bound(unit: BudgetUnit, limit: u64) -> TestPolicyBound {
    TestPolicyBound::new(unit, limit).unwrap_or_else(|_| unreachable!("valid bound"))
}

/// Returns the published policy with the supplied runtime step bound.
fn policy(maximum_transitions: u64) -> TestWorkflowPolicy {
    TestWorkflowPolicy::published(
        bound(BudgetUnit::Bytes, 1_048_576),
        bound(BudgetUnit::Count, TEST_WORKFLOW_FRONTEND_STAGES),
        bound(BudgetUnit::Count, 16),
        maximum_transitions,
    )
    .unwrap_or_else(|_| unreachable!("valid policy"))
}

/// Runs one workflow request against one package root and returns its identity requests.
fn run_workflow_with_identities(
    package_root: &Path,
    policy: &TestWorkflowPolicy,
    identity: &TestWorkflowIdentity,
    declarations: TestWorkflowDeclarations<'_>,
) -> (TestWorkflowReport, Vec<IdentityKind>) {
    let selection = selection();
    let allocator = FreshIdentityAllocator::default();
    let identities = SequentialIdentities::default();
    let clock = FixedClock;
    let services = TestWorkflowServices {
        allocator: &allocator,
        identity_source: &identities,
        clock: &clock,
        blocking: gantry_conformance::blocking_work(),
    };
    let request = TestWorkflowRequest {
        package_root,
        protocol_selection: &selection,
        expected_identity: identity,
        policy,
        declarations,
    };
    let report = block_on(run_test_workflow(services, request));
    (report, identities.calls())
}

/// Runs one workflow request against one package root.
fn run_workflow(
    package_root: &Path,
    policy: &TestWorkflowPolicy,
    identity: &TestWorkflowIdentity,
    declarations: TestWorkflowDeclarations<'_>,
) -> TestWorkflowReport {
    run_workflow_with_identities(package_root, policy, identity, declarations).0
}

/// Returns one package root that does not exist, proving a refusal dispatched no frontend stage.
fn missing_package_root() -> PathBuf {
    std::env::temp_dir().join("gantry-test-workflow-missing-package-root")
}

/// Drives one workflow future to completion.
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

#[test]
fn clean_unit_completion_publishes_one_ordered_zero_authority_report() {
    let package = TempDirectory::new(b"fn main() {}");
    let policy = policy(100);
    let identity = published_identity();
    let report = run_workflow(
        &package.0,
        &policy,
        &identity,
        TestWorkflowDeclarations::unit(),
    );

    assert_eq!(report.status(), TestWorkflowStatus::Clean);
    assert!(report.is_clean());
    assert_eq!(report.format(), TEST_WORKFLOW_REPORT_FORMAT);
    assert_eq!(report.format(), "gantry.test-workflow/v1");
    assert_eq!(report.report_version(), TEST_WORKFLOW_REPORT_VERSION);
    assert_eq!(report.report_version(), 1);
    assert_eq!(report.selection().kind(), Some(TestKind::Unit));
    assert_eq!(
        report.selection().kind().map(|kind| kind.wire_name()),
        Some("unit")
    );
    assert!(report.selection().substitutions().is_empty());
    assert_eq!(report.selection().jobs(), TEST_WORKFLOW_JOBS);
    assert_eq!(report.selection().entry(), Some("crate::main"));
    assert_eq!(report.arranged_width(), 1);
    assert!(report.refusal().is_none());
    assert!(report.diagnostics().is_empty());

    let results = report.results();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].name(), "crate::main");
    assert_eq!(
        results[0].classification(),
        TestWorkflowTargetClassification::Completed
    );
    assert!(results[0].steps() > 0);
    assert!(results[0].failure().is_none());

    let inventory = report
        .inventory()
        .unwrap_or_else(|| panic!("admitted target publishes its inventory"));
    assert_eq!(inventory.effects(), 0);
    assert_eq!(inventory.operations(), 0);
    assert_eq!(inventory.live_resources(), 0);
    assert!(inventory.authority_ceiling_empty());
    assert_eq!(report.package().map(|package| package.files()), Some(1));
    assert_eq!(report.package().map(|package| package.bytes()), Some(12));
    assert_eq!(
        report.identity().map(TestWorkflowIdentity::toolchain),
        Some(TEST_WORKFLOW_TOOLCHAIN_IDENTITY)
    );
    assert_eq!(
        report.expected_identity().toolchain(),
        TEST_WORKFLOW_TOOLCHAIN_IDENTITY
    );
    assert_eq!(report.policy().maximum_transitions(), 100);
}

#[test]
fn repeated_runs_over_one_package_are_deterministic() {
    let package = TempDirectory::new(b"fn main() { discard 1 + 2; }");
    let first = run_workflow(
        &package.0,
        &policy(100),
        &published_identity(),
        TestWorkflowDeclarations::unit(),
    );
    let second = run_workflow(
        &package.0,
        &policy(100),
        &published_identity(),
        TestWorkflowDeclarations::unit(),
    );
    assert_eq!(first.status(), second.status());
    assert_eq!(first.results(), second.results());
    assert_eq!(first.arranged_width(), second.arranged_width());
}

#[test]
fn fixed_test_failure_publishes_its_structured_machine_failure() {
    let package = TempDirectory::new(b"fn main() { let value: Int = 1 / 0; discard value; }");
    let report = run_workflow(
        &package.0,
        &policy(100),
        &published_identity(),
        TestWorkflowDeclarations::unit(),
    );
    assert_eq!(report.status(), TestWorkflowStatus::TestFailed);
    let result = &report.results()[0];
    assert_eq!(
        result.classification(),
        TestWorkflowTargetClassification::Failed
    );
    let failure = result
        .failure()
        .unwrap_or_else(|| panic!("a failed target publishes its failure"));
    assert!(!failure.code().is_empty());
    assert_eq!(failure.workflow(), "crate::main");
    assert!(report.refusal().is_none());
}

#[test]
fn invalid_source_publishes_bounded_payload_free_diagnostics() {
    let package = TempDirectory::new(b"fn main() { let SENTINEL_TOKEN: Int = ; }");
    let report = run_workflow(
        &package.0,
        &policy(100),
        &published_identity(),
        TestWorkflowDeclarations::unit(),
    );
    assert_eq!(report.status(), TestWorkflowStatus::SourceInvalid);
    assert!(!report.diagnostics().is_empty());
    assert!(
        report.diagnostics().len() <= 16,
        "the declared diagnostics bound is applied"
    );
    for diagnostic in report.diagnostics() {
        assert!(!diagnostic.code().is_empty());
        if let Some(primary) = diagnostic.primary() {
            assert_eq!(primary.path(), "main.gnt");
            assert!(primary.start() <= primary.end());
        }
    }
    let rendered = format!("{report:?}");
    assert!(
        !rendered.contains("SENTINEL_TOKEN"),
        "a report must not carry source payloads"
    );
}

#[test]
fn declared_inputs_refuse_before_any_frontend_dispatch() {
    let missing = missing_package_root();
    let cases: [(&str, TestWorkflowDeclarations<'_>, &str); 9] = [
        (
            "kind",
            TestWorkflowDeclarations {
                kind: "integration",
                ..TestWorkflowDeclarations::unit()
            },
            "unsupported-test-kind",
        ),
        (
            "kind",
            TestWorkflowDeclarations {
                kind: "not-a-kind",
                ..TestWorkflowDeclarations::unit()
            },
            "unknown-test-kind",
        ),
        (
            "substitution",
            TestWorkflowDeclarations {
                substitutions: &["clock"],
                ..TestWorkflowDeclarations::unit()
            },
            "unsupported-test-substitution",
        ),
        (
            "substitution",
            TestWorkflowDeclarations {
                substitutions: &["bogus"],
                ..TestWorkflowDeclarations::unit()
            },
            "unknown-test-substitution",
        ),
        (
            "registry",
            TestWorkflowDeclarations {
                registry_inputs: &["std.test"],
                ..TestWorkflowDeclarations::unit()
            },
            "unsupported-registry-input",
        ),
        (
            "registry",
            TestWorkflowDeclarations {
                registry_inputs: &[""],
                ..TestWorkflowDeclarations::unit()
            },
            "unknown-registry-input",
        ),
        (
            "authority",
            TestWorkflowDeclarations {
                authority_inputs: &["grant"],
                ..TestWorkflowDeclarations::unit()
            },
            "unsupported-authority-input",
        ),
        (
            "artifact",
            TestWorkflowDeclarations {
                external_artifacts: &["artifact"],
                ..TestWorkflowDeclarations::unit()
            },
            "unsupported-external-artifact",
        ),
        (
            "artifact",
            TestWorkflowDeclarations {
                external_artifacts: &[""],
                ..TestWorkflowDeclarations::unit()
            },
            "unknown-external-artifact",
        ),
    ];
    for (label, declarations, code) in cases {
        let report = run_workflow(&missing, &policy(100), &published_identity(), declarations);
        assert_eq!(
            report.status(),
            TestWorkflowStatus::Refused,
            "{label} declaration {code} must refuse"
        );
        let refusal = report
            .refusal()
            .unwrap_or_else(|| panic!("{label} refusal is published"));
        assert_eq!(refusal.stage(), TestWorkflowStage::Preflight, "{label}");
        assert_eq!(refusal.code(), code, "{label}");
        assert!(report.package().is_none(), "{label} dispatched no analysis");
        assert!(report.results().is_empty(), "{label}");
        assert!(report.diagnostics().is_empty(), "{label}");
    }
}

#[test]
fn stale_identity_expectations_refuse_at_preflight() {
    let stale = TestWorkflowIdentity::observed(&selection(), "gantry/stale-toolchain")
        .unwrap_or_else(|_| unreachable!("recorded identity"));
    let report = run_workflow(
        &missing_package_root(),
        &policy(100),
        &stale,
        TestWorkflowDeclarations::unit(),
    );
    assert_eq!(report.status(), TestWorkflowStatus::Refused);
    let refusal = report
        .refusal()
        .unwrap_or_else(|| panic!("identity mismatch refusal is published"));
    assert_eq!(refusal.stage(), TestWorkflowStage::Preflight);
    assert_eq!(refusal.code(), "identity-mismatch");
    assert_eq!(refusal.detail(), Some("toolchain"));
    assert_eq!(
        report.identity().map(TestWorkflowIdentity::toolchain),
        Some(TEST_WORKFLOW_TOOLCHAIN_IDENTITY)
    );
    assert_eq!(
        report.expected_identity().toolchain(),
        "gantry/stale-toolchain"
    );
    assert!(report.package().is_none());
}

#[test]
fn policy_admission_refuses_invalid_bounds_and_revisions() {
    assert_eq!(
        TestWorkflowPolicy::new(
            TEST_WORKFLOW_POLICY_REVISION,
            2,
            bound(BudgetUnit::Bytes, 1),
            bound(BudgetUnit::Count, TEST_WORKFLOW_FRONTEND_STAGES),
            bound(BudgetUnit::Count, 1),
            10,
        ),
        Err(TestWorkflowPolicyError::NonSingleJobs { declared: 2 })
    );
    assert_eq!(
        TestWorkflowPolicy::new(
            TEST_WORKFLOW_POLICY_REVISION,
            TEST_WORKFLOW_JOBS,
            bound(BudgetUnit::Bytes, 1),
            bound(BudgetUnit::Count, TEST_WORKFLOW_FRONTEND_STAGES),
            bound(BudgetUnit::Count, 1),
            0,
        ),
        Err(TestWorkflowPolicyError::ZeroTransitionBound)
    );
    let stale_policy = TestWorkflowPolicy::new(
        9,
        TEST_WORKFLOW_JOBS,
        bound(BudgetUnit::Bytes, 1_048_576),
        bound(BudgetUnit::Count, TEST_WORKFLOW_FRONTEND_STAGES),
        bound(BudgetUnit::Count, 16),
        10,
    )
    .unwrap_or_else(|_| unreachable!("valid revision"));
    let report = run_workflow(
        &missing_package_root(),
        &stale_policy,
        &published_identity(),
        TestWorkflowDeclarations::unit(),
    );
    assert_eq!(report.status(), TestWorkflowStatus::Refused);
    assert_eq!(
        report
            .refusal()
            .map(|refusal| (refusal.stage(), refusal.code())),
        Some((TestWorkflowStage::Preflight, "unsupported-policy-revision"))
    );

    let single_stage = TestWorkflowPolicy::published(
        bound(BudgetUnit::Bytes, 1_048_576),
        bound(BudgetUnit::Count, 1),
        bound(BudgetUnit::Count, 16),
        10,
    )
    .unwrap_or_else(|_| unreachable!("valid bound"));
    let report = run_workflow(
        &missing_package_root(),
        &single_stage,
        &published_identity(),
        TestWorkflowDeclarations::unit(),
    );
    assert_eq!(report.status(), TestWorkflowStatus::Refused);
    assert_eq!(
        report.refusal().map(|refusal| refusal.code()),
        Some("insufficient-frontend-stages")
    );
}

#[test]
fn entry_selection_refuses_argument_taking_and_value_returning_entries() {
    let argument = TempDirectory::new(b"fn main(value: Int) { discard value; }");
    let report = run_workflow(
        &argument.0,
        &policy(100),
        &published_identity(),
        TestWorkflowDeclarations::unit(),
    );
    assert_eq!(report.status(), TestWorkflowStatus::Refused);
    assert_eq!(
        report
            .refusal()
            .map(|refusal| (refusal.stage(), refusal.code())),
        Some((TestWorkflowStage::Admission, "argument-taking-entry"))
    );
    assert!(report.results().is_empty());

    let value = TempDirectory::new(b"fn main() -> Int { 1 }");
    let report = run_workflow(
        &value.0,
        &policy(100),
        &published_identity(),
        TestWorkflowDeclarations::unit(),
    );
    assert_eq!(report.status(), TestWorkflowStatus::NoTests);
    assert_eq!(
        report
            .refusal()
            .map(|refusal| (refusal.stage(), refusal.code())),
        Some((TestWorkflowStage::Admission, "no-unit-entry-result"))
    );
    assert!(report.results().is_empty());
}

#[test]
fn non_empty_effect_inventory_is_an_admission_refusal() {
    let package = TempDirectory::new(b"fn main() { discard prompt \"x\" -> String; }");
    let report = run_workflow(
        &package.0,
        &policy(100),
        &published_identity(),
        TestWorkflowDeclarations::unit(),
    );
    assert_eq!(report.status(), TestWorkflowStatus::Refused);
    assert_eq!(
        report
            .refusal()
            .map(|refusal| (refusal.stage(), refusal.code())),
        Some((TestWorkflowStage::Admission, "non-empty-effect-inventory"))
    );
    assert!(report.results().is_empty());
}

#[test]
fn step_exhaustion_is_reported_as_exhaustion_not_as_a_timeout() {
    let package = TempDirectory::new(
        b"fn main() { let mut counter: Int = 0; while counter < 1000000 { counter += 1; } }",
    );
    let report = run_workflow(
        &package.0,
        &policy(20),
        &published_identity(),
        TestWorkflowDeclarations::unit(),
    );
    assert_eq!(report.status(), TestWorkflowStatus::Exhausted);
    assert_eq!(
        report.refusal().map(|refusal| refusal.code()),
        Some("step-bound-exhausted")
    );
    let result = &report.results()[0];
    assert_eq!(
        result.classification(),
        TestWorkflowTargetClassification::StepBoundExhausted
    );
    assert_eq!(result.bound(), Some(20));
    assert!(result.cancellation_reason().is_none());
}

#[test]
fn published_constants_pin_the_contract() {
    assert_eq!(TEST_WORKFLOW_JOBS, 1);
    assert_eq!(TEST_WORKFLOW_FRONTEND_STAGES, 2);
    assert_eq!(TEST_WORKFLOW_OUTPUT_CEILING_BYTES, 1_048_576);
    assert_eq!(TEST_WORKFLOW_POLICY_REVISION, 1);
    assert_eq!(TEST_WORKFLOW_REPORT_VERSION, 1);
    assert_eq!(TEST_WORKFLOW_REPORT_FORMAT, "gantry.test-workflow/v1");
    assert!(TEST_WORKFLOW_TOOLCHAIN_IDENTITY.starts_with("gantry/"));
    let policy = policy(7);
    assert_eq!(policy.revision(), TEST_WORKFLOW_POLICY_REVISION);
    assert_eq!(policy.jobs(), TEST_WORKFLOW_JOBS);
    assert_eq!(
        policy.frontend_limits().maximum_package_source_bytes(),
        1_048_576
    );
    assert_eq!(
        policy.frontend_limits().maximum_diagnostics_per_activity(),
        16
    );
    assert_eq!(
        policy.output_ceiling_bytes(),
        TEST_WORKFLOW_OUTPUT_CEILING_BYTES
    );
}

#[test]
fn one_clean_run_requests_one_frontend_activity_and_one_execution_identity() {
    let package = TempDirectory::new(b"fn main() {}");
    let (report, calls) = run_workflow_with_identities(
        &package.0,
        &policy(100),
        &published_identity(),
        TestWorkflowDeclarations::unit(),
    );
    assert_eq!(report.status(), TestWorkflowStatus::Clean);
    let activities = calls
        .iter()
        .filter(|kind| **kind == IdentityKind::Activity)
        .count();
    let executions = calls
        .iter()
        .filter(|kind| **kind == IdentityKind::Execution)
        .count();
    assert_eq!(
        activities, 1,
        "one activity dispatch covers the two declared frontend stages"
    );
    assert_eq!(executions, 1, "one execution identity is admitted");
    assert_eq!(
        calls.first(),
        Some(&IdentityKind::Activity),
        "the frontend activity is the first identity the run requests"
    );
}

#[test]
fn unreachable_declarations_do_not_enter_the_admitted_inventory() {
    let package =
        TempDirectory::new(b"fn helper() { discard prompt \"x\" -> String; } fn main() {}");
    let report = run_workflow(
        &package.0,
        &policy(100),
        &published_identity(),
        TestWorkflowDeclarations::unit(),
    );
    assert_eq!(report.status(), TestWorkflowStatus::Clean);
    assert_eq!(
        report.inventory().map(|inventory| inventory.effects()),
        Some(0),
        "the inventory is measured over the entry-reachable program"
    );
}

#[test]
fn refusal_reports_retain_observed_and_declared_facts() {
    let missing = missing_package_root();
    let observed = published_identity();

    let non_unit = run_workflow(
        &missing,
        &policy(100),
        &observed,
        TestWorkflowDeclarations {
            kind: "integration",
            ..TestWorkflowDeclarations::unit()
        },
    );
    assert_eq!(
        non_unit.selection().kind(),
        Some(TestKind::Integration),
        "the refused declaration is retained rather than reported as unit"
    );
    assert_eq!(non_unit.declared().registry_inputs(), 0);
    assert_eq!(non_unit.declared().authority_inputs(), 0);
    assert_eq!(non_unit.declared().external_artifacts(), 0);

    let substituted = run_workflow(
        &missing,
        &policy(100),
        &observed,
        TestWorkflowDeclarations {
            substitutions: &["clock"],
            ..TestWorkflowDeclarations::unit()
        },
    );
    assert_eq!(
        substituted.selection().substitutions().to_vec(),
        vec![TestSubstitution::Clock]
    );

    let registry = run_workflow(
        &missing,
        &policy(100),
        &observed,
        TestWorkflowDeclarations {
            registry_inputs: &["std.test", ""],
            ..TestWorkflowDeclarations::unit()
        },
    );
    assert_eq!(registry.declared().registry_inputs(), 2);
    assert_eq!(registry.declared().authority_inputs(), 0);
    assert_eq!(registry.declared().external_artifacts(), 0);
}
