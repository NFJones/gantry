//! Public conformance coverage for bounded operational admission.

use std::fs;
use std::path::{Path, PathBuf};

use gantry::portable::{
    CONFIGURATION_FIELDS, ConfigurationClass, ConfigurationField, MAXIMUM_DIRECTIVE_INTEGER,
};
use gantry::runtime::{
    AdmissionBoundary, AdmissionClass, AdmissionFailureCategory, AdmissionPermit, AdmissionRequest,
    AdmissionReservation, AdmissionResourceClass, AsyncAdmission, AsyncCapacityLimits,
    ConfigurationError, ConfigurationErrorKind,
};
use serde::Deserialize;

const ATOMIC_EVIDENCE: &str = "crates/gantry-conformance/tests/async_admission.rs#public_admission_batches_are_atomic_nonblocking_and_boundary_typed";
const CONFIGURATION_EVIDENCE: &str = "crates/gantry-conformance/tests/async_admission.rs#public_async_capacities_are_explicit_positive_operational_policy";
const CLEANUP_EVIDENCE: &str = "crates/gantry-conformance/tests/async_admission.rs#public_cleanup_reserve_survives_ordinary_saturation";

#[derive(Debug, Deserialize)]
struct EvidenceManifest {
    format: String,
    specification_sha256: String,
    issue: String,
    capabilities: Vec<CapabilityEvidence>,
    exclusions: Vec<String>,
}

#[derive(Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
struct CapabilityEvidence {
    id: String,
    evidence: String,
}

#[derive(Debug, Deserialize)]
struct RequirementReview {
    specification_sha256: String,
}

#[test]
fn checked_in_async_admission_evidence_is_narrow_and_current() {
    let root = workspace_root();
    let manifest: EvidenceManifest =
        read_json(&root.join("protocol/conformance/async-admission-v1.json"));
    let review: RequirementReview = read_json(&root.join("protocol/requirements/reviewed-v1.json"));

    assert_eq!(manifest.format, "gantry.async-admission-evidence/v1");
    assert_eq!(manifest.specification_sha256, review.specification_sha256);
    assert_eq!(manifest.issue, "GNT-ASYNC-ADMIT-001");
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
        [ATOMIC_EVIDENCE, CONFIGURATION_EVIDENCE, CLEANUP_EVIDENCE]
    );
    assert_eq!(manifest.exclusions.len(), 4);
}

#[test]
fn public_async_capacities_are_explicit_positive_operational_policy() {
    let capacities = capacities([1, 2, 3, 4, 5, 6, 7, 8, 9]);
    assert_eq!(capacities.maximum_active_root_tasks(), 1);
    assert_eq!(capacities.maximum_active_source_child_tasks(), 2);
    assert_eq!(capacities.maximum_resume_runnable_tasks(), 3);
    assert_eq!(capacities.maximum_admitted_public_activities(), 4);
    assert_eq!(capacities.maximum_interpreter_background_tasks(), 5);
    assert_eq!(capacities.maximum_queued_blocking_jobs(), 6);
    assert_eq!(capacities.maximum_active_blocking_jobs(), 7);
    assert_eq!(capacities.maximum_active_event_deliveries(), 8);
    assert_eq!(capacities.reserved_control_plane_tasks(), 9);

    let fields = [
        ConfigurationField::MaximumActiveRootTasks,
        ConfigurationField::MaximumActiveSourceChildTasks,
        ConfigurationField::MaximumResumeRunnableTasks,
        ConfigurationField::MaximumAdmittedPublicActivities,
        ConfigurationField::MaximumInterpreterBackgroundTasks,
        ConfigurationField::MaximumQueuedBlockingJobs,
        ConfigurationField::MaximumActiveBlockingJobs,
        ConfigurationField::MaximumActiveEventDeliveries,
        ConfigurationField::ReservedControlPlaneTasks,
    ];
    for field in fields {
        let definition = CONFIGURATION_FIELDS
            .iter()
            .find(|definition| definition.field == field)
            .unwrap_or_else(|| panic!("missing {}", field.wire_name()));
        assert_eq!(definition.class, ConfigurationClass::OperationalPolicy);
        assert_eq!(definition.default, None);
        assert_eq!(definition.zero_allowed, Some(false));
        assert_eq!(definition.maximum, Some("9223372036854775807"));
    }

    let zero_cases = [
        (
            fields[0],
            AsyncCapacityLimits::new(0, 1, 1, 1, 1, 1, 1, 1, 1),
        ),
        (
            fields[1],
            AsyncCapacityLimits::new(1, 0, 1, 1, 1, 1, 1, 1, 1),
        ),
        (
            fields[2],
            AsyncCapacityLimits::new(1, 1, 0, 1, 1, 1, 1, 1, 1),
        ),
        (
            fields[3],
            AsyncCapacityLimits::new(1, 1, 1, 0, 1, 1, 1, 1, 1),
        ),
        (
            fields[4],
            AsyncCapacityLimits::new(1, 1, 1, 1, 0, 1, 1, 1, 1),
        ),
        (
            fields[5],
            AsyncCapacityLimits::new(1, 1, 1, 1, 1, 0, 1, 1, 1),
        ),
        (
            fields[6],
            AsyncCapacityLimits::new(1, 1, 1, 1, 1, 1, 0, 1, 1),
        ),
        (
            fields[7],
            AsyncCapacityLimits::new(1, 1, 1, 1, 1, 1, 1, 0, 1),
        ),
        (
            fields[8],
            AsyncCapacityLimits::new(1, 1, 1, 1, 1, 1, 1, 1, 0),
        ),
    ];
    for (field, result) in zero_cases {
        assert!(matches!(
            result,
            Err(ConfigurationError {
                field: actual,
                kind: ConfigurationErrorKind::Zero,
            }) if actual == field
        ));
    }
    assert!(matches!(
        AsyncCapacityLimits::new(MAXIMUM_DIRECTIVE_INTEGER + 1, 1, 1, 1, 1, 1, 1, 1, 1,),
        Err(ConfigurationError {
            field: ConfigurationField::MaximumActiveRootTasks,
            kind: ConfigurationErrorKind::TooLarge,
        })
    ));
}

#[test]
fn public_admission_batches_are_atomic_nonblocking_and_boundary_typed() {
    assert_eq!(
        AdmissionClass::ACQUISITION_ORDER.map(AdmissionClass::wire_name),
        [
            "root-task",
            "source-child-task",
            "resume-runnable-task",
            "public-activity",
            "interpreter-background-task",
            "queued-blocking-job",
            "active-blocking-job",
            "event-delivery",
        ]
    );

    let admission = AsyncAdmission::new(capacities([1; 9]));
    let root = admission
        .try_reserve(AdmissionRequest::single(AdmissionClass::RootTask, 1))
        .unwrap_or_else(|error| panic!("root admission failed: {error}"));
    let failed_batch = AdmissionRequest::new()
        .with(AdmissionClass::RootTask, 1)
        .with(AdmissionClass::SourceChildTask, 1);
    let refusal = match admission.try_reserve(failed_batch) {
        Err(error) => error,
        Ok(_) => panic!("saturated root batch was accepted"),
    };
    assert_eq!(
        refusal.resource,
        AdmissionResourceClass::Ordinary(AdmissionClass::RootTask)
    );
    assert_eq!(refusal.requested, 1);
    assert_eq!(refusal.available, 0);
    assert_eq!(
        refusal.category(AdmissionBoundary::PreAcceptance),
        AdmissionFailureCategory::ImplementationResourceExhaustion
    );
    assert_eq!(
        refusal.category(AdmissionBoundary::PostAcceptance),
        AdmissionFailureCategory::ExecutorFailure
    );
    assert_eq!(
        admission
            .snapshot()
            .in_use(AdmissionResourceClass::Ordinary(
                AdmissionClass::SourceChildTask,
            )),
        0,
        "failed batch partially acquired child capacity"
    );

    let child = admission
        .try_reserve(AdmissionRequest::single(AdmissionClass::SourceChildTask, 1))
        .unwrap_or_else(|error| panic!("capacity-one child admission blocked on root: {error}"));
    let root_permit = root.transfer();
    assert!(
        admission
            .try_reserve(AdmissionRequest::single(AdmissionClass::RootTask, 1))
            .is_err(),
        "transfer released capacity before physical owner settlement"
    );
    drop(root_permit);
    drop(child);
    assert!(
        admission
            .try_reserve(AdmissionRequest::single(AdmissionClass::RootTask, 1))
            .is_ok()
    );
    assert!(admission.try_reserve(AdmissionRequest::new()).is_ok());

    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<AsyncAdmission>();
    assert_send_sync::<AdmissionReservation>();
    assert_send_sync::<AdmissionPermit>();
}

#[test]
fn public_cleanup_reserve_survives_ordinary_saturation() {
    let admission = AsyncAdmission::new(capacities([1; 9]));
    let ordinary = AdmissionClass::ACQUISITION_ORDER.map(|class| {
        admission
            .try_reserve(AdmissionRequest::single(class, 1))
            .unwrap_or_else(|error| panic!("{} admission failed: {error}", class.wire_name()))
    });
    for class in AdmissionClass::ACQUISITION_ORDER {
        assert!(
            admission
                .try_reserve(AdmissionRequest::single(class, 1))
                .is_err()
        );
    }

    let cleanup = admission
        .try_reserve_control_plane(1)
        .unwrap_or_else(|error| panic!("ordinary saturation consumed cleanup reserve: {error}"));
    assert!(admission.try_reserve_control_plane(1).is_err());
    assert_eq!(
        admission
            .snapshot()
            .in_use(AdmissionResourceClass::ControlPlaneTask),
        1
    );
    drop(ordinary);
    assert_eq!(
        admission
            .snapshot()
            .in_use(AdmissionResourceClass::ControlPlaneTask),
        1,
        "ordinary release altered the isolated cleanup reserve"
    );
    cleanup.rollback();
    assert_eq!(
        admission
            .snapshot()
            .in_use(AdmissionResourceClass::ControlPlaneTask),
        0
    );
}

fn capacities(values: [u64; 9]) -> AsyncCapacityLimits {
    AsyncCapacityLimits::new(
        values[0], values[1], values[2], values[3], values[4], values[5], values[6], values[7],
        values[8],
    )
    .unwrap_or_else(|error| panic!("capacity fixture failed: {error}"))
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
