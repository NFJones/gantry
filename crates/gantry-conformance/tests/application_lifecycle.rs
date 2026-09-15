//! Machine-checked conformance for the pure Section 30 application declaration model.
//!
//! These tests use explicit declarations only. They do not launch an application,
//! access a host environment, open standard I/O, receive a signal, or claim evaluator,
//! durable-runtime, or embedding coverage.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use gantry::ir::{
    APPLICATION_CLAUSES, ApplicationClass, ApplicationCoordinator, ApplicationDiagnosticCode,
    ApplicationEntries, ApplicationEntry, ApplicationError, ApplicationPhase, CapabilityGrant,
    EmergencyCleanupWitness, ExitDisposition, ExitReport, FinalizationStep, FuelDisposition,
    FuelGrant, FuelState, GracePolicy, LaunchArrangement, LaunchSnapshot, LaunchSnapshotLimits,
    LogicalCwd, OwnerGeneration, PortableSignalClass, SemanticMode, StdioArrangement, StdioChannel,
    StdioSet, StopCause, StopCoordinator, StopRequest, SupervisorSettlement, TargetKind,
    TaskStopState, admit_durable_companion,
};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap_or_else(|| panic!("workspace root"))
        .to_path_buf()
}

fn limits() -> LaunchSnapshotLimits {
    LaunchSnapshotLimits::new(2, 2, 2, 32)
}

fn snapshot() -> LaunchSnapshot {
    let capabilities = ["console", "filesystem"]
        .into_iter()
        .map(|name| {
            CapabilityGrant::new(name).unwrap_or_else(|error| panic!("capability: {error:?}"))
        })
        .collect();
    LaunchSnapshot::new(
        vec!["app".into()],
        vec![("LANG".into(), "C".into())],
        LogicalCwd::new("/logical").unwrap_or_else(|error| panic!("cwd: {error:?}")),
        capabilities,
        limits(),
    )
    .unwrap_or_else(|error| panic!("snapshot: {error:?}"))
}

#[test]
fn launch_snapshot_bounds_the_declared_capability_closure() {
    let capabilities = ["console", "filesystem", "network"]
        .into_iter()
        .map(|name| {
            CapabilityGrant::new(name).unwrap_or_else(|error| panic!("capability: {error:?}"))
        })
        .collect();
    assert_eq!(
        LaunchSnapshot::new(
            vec!["app".into()],
            vec![("LANG".into(), "C".into())],
            LogicalCwd::new("/logical").unwrap_or_else(|error| panic!("cwd: {error:?}")),
            capabilities,
            limits(),
        ),
        Err(ApplicationError::SnapshotLimitExceeded)
    );
}

fn entry(target: &str) -> ApplicationEntry {
    ApplicationEntry::new(
        target,
        SemanticMode::Application,
        "gantry-v1",
        snapshot(),
        limits(),
    )
    .unwrap_or_else(|error| panic!("entry: {error:?}"))
}

#[test]
fn clauses_and_closed_vocabularies_are_published() {
    let spec = fs::read_to_string(root().join("SPEC.md"))
        .unwrap_or_else(|error| panic!("SPEC.md: {error}"));
    assert_eq!(APPLICATION_CLAUSES.len(), 13);
    for clause in APPLICATION_CLAUSES {
        assert!(spec.contains(&format!("<a id=\"{clause}\"></a>")));
    }
    for (members, unknown) in [
        (
            LaunchArrangement::ALL
                .map(LaunchArrangement::wire_name)
                .as_slice(),
            "native",
        ),
        (
            StdioChannel::ALL.map(StdioChannel::wire_name).as_slice(),
            "fd",
        ),
        (
            StdioArrangement::ALL
                .map(StdioArrangement::wire_name)
                .as_slice(),
            "socket",
        ),
        (
            ExitDisposition::ALL
                .map(ExitDisposition::wire_name)
                .as_slice(),
            "exit-code",
        ),
    ] {
        assert!(!members.contains(&unknown));
    }
    assert_eq!(ApplicationDiagnosticCode::ALL.len(), 9);
}

#[test]
fn target_entry_snapshot_and_attenuation_are_strict() {
    let mut entries = ApplicationEntries::default();
    assert!(entries.insert(entry("linux-x64")).is_ok());
    assert_eq!(
        entries.insert(entry("linux-x64")),
        Err(ApplicationError::DuplicateTargetEntry)
    );
    assert_eq!(
        ApplicationEntry::new("x", SemanticMode::Durable, "abi", snapshot(), limits()),
        Err(ApplicationError::InvalidEntry)
    );
    assert_eq!(
        ApplicationEntry::new("x", SemanticMode::Portable, "abi", snapshot(), limits()),
        Err(ApplicationError::InvalidEntry)
    );
    assert_eq!(
        LaunchSnapshot::new(
            vec!["a".into(), "b".into(), "c".into()],
            vec![],
            LogicalCwd::new("cwd").unwrap_or_else(|_| panic!()),
            BTreeSet::new(),
            limits()
        ),
        Err(ApplicationError::SnapshotLimitExceeded)
    );
    assert_eq!(
        LaunchSnapshot::new(
            vec![],
            vec![("A".into(), "1".into()), ("A".into(), "2".into())],
            LogicalCwd::new("cwd").unwrap_or_else(|_| panic!()),
            BTreeSet::new(),
            limits()
        ),
        Err(ApplicationError::DuplicateEnvironment)
    );
    let child = [CapabilityGrant::new("console").unwrap_or_else(|_| panic!())]
        .into_iter()
        .collect();
    assert!(snapshot().project_child(child).is_ok());
    let expanded = [CapabilityGrant::new("network").unwrap_or_else(|_| panic!())]
        .into_iter()
        .collect();
    assert_eq!(
        snapshot().project_child(expanded),
        Err(ApplicationError::CapabilityAmplification)
    );
    assert_eq!(LogicalCwd::new(""), Err(ApplicationError::InvalidCwd));
    assert_eq!(
        CapabilityGrant::new(""),
        Err(ApplicationError::InvalidCapability)
    );
}

#[test]
fn stdio_fuel_and_durable_companion_admission_are_closed() {
    let stdio = StdioSet::new(&[
        (StdioChannel::Stdin, StdioArrangement::Null),
        (StdioChannel::Stdout, StdioArrangement::Pipe),
        (StdioChannel::Stderr, StdioArrangement::Inherit),
    ]);
    assert!(stdio.is_ok());
    assert_eq!(
        StdioSet::new(&[(StdioChannel::Stdin, StdioArrangement::Null)]),
        Err(ApplicationError::IncompleteStdio)
    );
    assert_eq!(
        StdioSet::new(&[
            (StdioChannel::Stdin, StdioArrangement::Null),
            (StdioChannel::Stdin, StdioArrangement::Pipe),
            (StdioChannel::Stderr, StdioArrangement::Inherit)
        ]),
        Err(ApplicationError::DuplicateStdioChannel)
    );
    let generation = OwnerGeneration::new(7);
    let mut fuel = FuelState::new(FuelGrant::new(2, 5, generation).unwrap_or_else(|_| panic!()));
    assert!(fuel.consume(2).is_ok());
    assert_eq!(fuel.disposition(), FuelDisposition::Exhausted);
    assert_eq!(fuel.consume(1), Err(ApplicationError::FuelExhausted));
    fuel.suspend();
    assert_eq!(fuel.disposition(), FuelDisposition::Suspended);
    assert_eq!(
        fuel.renew(FuelGrant::new(2, 6, generation).unwrap_or_else(|_| panic!())),
        Err(ApplicationError::YieldQuantumChanged)
    );
    assert_eq!(
        fuel.renew(FuelGrant::new(2, 5, OwnerGeneration::new(8)).unwrap_or_else(|_| panic!())),
        Err(ApplicationError::StaleFuelGeneration)
    );
    assert!(
        fuel.renew(FuelGrant::new(2, 5, generation).unwrap_or_else(|_| panic!()))
            .is_ok()
    );
    assert!(admit_durable_companion(TargetKind::Binary, &[ApplicationClass::Durable]).is_ok());
    assert_eq!(
        admit_durable_companion(TargetKind::Binary, &[ApplicationClass::ApplicationOnly]),
        Err(ApplicationError::DurableCompanionClosureRejected)
    );
    assert_eq!(
        admit_durable_companion(TargetKind::Binary, &[ApplicationClass::LiveClosure]),
        Err(ApplicationError::DurableCompanionClosureRejected)
    );
    assert_eq!(
        admit_durable_companion(TargetKind::Library, &[ApplicationClass::Durable]),
        Err(ApplicationError::DurableCompanionNotBinary)
    );
}

#[test]
fn signals_close_admission_and_finalization_preserves_language_outcome() {
    let mut coordinator = ApplicationCoordinator::new(LaunchArrangement::Standalone);
    assert!(coordinator.start(&entry("app")).is_ok());
    let policy = GracePolicy::new(10, 10).unwrap_or_else(|_| panic!());
    assert!(
        coordinator
            .translate_signal(PortableSignalClass::Interrupt, policy, 1)
            .is_ok()
    );
    assert!(
        coordinator
            .translate_signal(
                PortableSignalClass::Terminate,
                GracePolicy::new(20, 20).unwrap_or_else(|_| panic!()),
                2,
            )
            .is_ok()
    );
    assert_eq!(coordinator.phase(), ApplicationPhase::AdmissionClosed);
    assert!(!coordinator.stop().is_admission_open());
    assert!(coordinator.begin_finalization().is_ok());
    assert_eq!(coordinator.settle(), Err(ApplicationError::InvalidPhase));
    assert!(coordinator.record_final_flush().is_ok());
    assert!(coordinator.record_hard_cancellation(None).is_ok());
    assert!(matches!(
        ExitReport::new(
            ExitDisposition::Failed,
            false,
            SupervisorSettlement::pending(),
            None
        ),
        Err(ApplicationError::ExitBeforeSupervisorSettlement)
    ));
    assert!(coordinator.settle().is_ok());
    let report = ExitReport::new(
        ExitDisposition::Failed,
        false,
        SupervisorSettlement::settled(),
        None,
    )
    .unwrap_or_else(|_| panic!());
    let published = coordinator.publish(report).unwrap_or_else(|_| panic!());
    assert_eq!(published.disposition(), ExitDisposition::Failed);
    assert!(!published.flush_succeeded());
    assert_eq!(
        FinalizationStep::ALL.map(FinalizationStep::wire_name),
        [
            "close-admission",
            "final-flush",
            "hard-cancellation",
            "supervisor-settlement",
            "exit-publication"
        ]
    );
}

#[test]
fn hard_cancellation_preserves_the_sealed_section_22_cleanup_witness() {
    let policy = GracePolicy::new(1, 1).unwrap_or_else(|_| panic!());
    let mut stop = StopCoordinator::new();
    assert!(
        stop.request_stop(StopRequest::new(StopCause::OperatorSignal, policy, 1))
            .is_ok()
    );
    let mut tasks: [TaskStopState; 0] = [];
    let witness = stop
        .escalate(&mut tasks, 2)
        .unwrap_or_else(|_| panic!("grace deadline permits hard cancellation"))
        .admit_emergency_release();
    let report = ExitReport::new(
        ExitDisposition::Stopped,
        true,
        SupervisorSettlement::settled(),
        Some(witness),
    )
    .unwrap_or_else(|_| panic!("settled report preserves witness"));
    assert_eq!(report.cleanup().map(|cleanup| cleanup.at_us()), Some(2));
}

#[test]
fn publication_transfers_the_recorded_cleanup_witness_over_a_foreign_witness() {
    let policy = GracePolicy::new(1, 1).unwrap_or_else(|_| panic!());
    let witness_at = |at_us| {
        let mut stop = StopCoordinator::new();
        assert!(
            stop.request_stop(StopRequest::new(StopCause::OperatorSignal, policy, 1))
                .is_ok()
        );
        let mut tasks: [TaskStopState; 0] = [];
        stop.escalate(&mut tasks, at_us)
            .unwrap_or_else(|_| panic!("grace deadline permits hard cancellation"))
            .admit_emergency_release()
    };
    let mut coordinator = ApplicationCoordinator::new(LaunchArrangement::Standalone);
    assert!(coordinator.start(&entry("app")).is_ok());
    assert!(
        coordinator
            .translate_signal(PortableSignalClass::Interrupt, policy, 1)
            .is_ok()
    );
    assert!(coordinator.begin_finalization().is_ok());
    assert!(coordinator.record_final_flush().is_ok());
    assert!(
        coordinator
            .record_hard_cancellation(Some(witness_at(2)))
            .is_ok()
    );
    assert!(coordinator.settle().is_ok());
    let report = ExitReport::new(
        ExitDisposition::Stopped,
        true,
        SupervisorSettlement::settled(),
        Some(witness_at(2)),
    )
    .unwrap_or_else(|_| panic!("settled report"));
    let published = coordinator
        .publish(report)
        .unwrap_or_else(|_| panic!("recorded witness must be transferred"));
    assert_eq!(
        published.cleanup().map(EmergencyCleanupWitness::at_us),
        Some(2)
    );
}

#[test]
fn arrangements_normalize_and_non_claims_remain_explicit() {
    assert_eq!(LaunchArrangement::Standalone.wire_name(), "standalone");
    assert_eq!(LaunchArrangement::Embedded.wire_name(), "embedded");
    let spec = fs::read_to_string(root().join("SPEC.md"))
        .unwrap_or_else(|error| panic!("SPEC.md: {error}"));
    let section = spec
        .split("<a id=\"GNT-30.12-application-non-claims\"></a>")
        .nth(1)
        .unwrap_or_else(|| panic!("Section 30 non-claims anchor"));
    for phrase in [
        "process launch",
        "evaluator behavior",
        "host traits",
        "adapters",
        "CLI behavior",
    ] {
        assert!(section.contains(phrase));
    }
}
