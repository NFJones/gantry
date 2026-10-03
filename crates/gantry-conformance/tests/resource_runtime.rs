//! Machine-checked conformance for the runtime admission of Section 28 resource facts.
//!
//! These rows exercise the runtime's admission boundary only: which declared carrier
//! may present a resource's accounting facts, what an admitted account preserves, and
//! how semantic release stays independent of record retirement. They perform no
//! durable I/O and claim no journal, checkpoint, or evaluator behavior. The optional
//! process-local transport rows use bounded synchronous fake host values only.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use gantry::identity::ProtocolIdentity;
use gantry::ir::generated::{OperationSiteKind, RecoveryClass};
use gantry::ir::{
    AdapterInstance, CanonicalImplementationIdentity, DisclosureCharge, ForeignFailureKind,
    OperationAbiError, OperationSettlement, PoisonReason, ProgressObservation, RightsSet,
    TypeExpression,
};
use gantry::ir::{
    ApplicationCoordinator, ApplicationEntry, CanonicalPath, CanonicalSignature, Charge,
    Completion, ContainmentError, DurableResourceRecord, EffectSet, EffectState,
    EmergencyCleanupWitness, ExecutableAction, ExecutableOperation, ExitDisposition, ExitReport,
    ExternalOutcome, FailureClass, GracePolicy, LaunchArrangement, LaunchSnapshot,
    LaunchSnapshotLimits, LivenessRoot, LogicalCwd, MalformedCompletion, OperationAbi,
    OperationKind, OwnerGeneration, PoisonWitness, PortableSignalClass, PostFailureSettlement,
    Quota, QuotaFamily, QuotaOwner, ReceiverOwnership, ResourceAction, ResourceCarrier,
    ResourceError, ResourceLedger, ResourceLifetimeState, ResourceState, RetentionFence,
    SemanticMode, StaticSiteId, StopCause, StopCoordinator, StopRequest, StructuralPosition,
    SupervisorSettlement, TaskStopState, TypeDescriptor,
};
use gantry::portable::IdentityKind;
use gantry::runtime::AdapterBindingRefusal;
use gantry::runtime::CohortEmergencySettlement;
use gantry::runtime::{
    AdmittedResource, ExecutionBudget, Instruction, InstructionKind, LoopPhase, Machine,
    MachineCheckpointV3, MachineLabel, MachineLimits, MachineOutcome, MachineProgram, MachineStep,
    OperationCompletionError, PostFailureSettlementRefusal, RecoveredResourceRecord,
    ResourceRecordCodecError, ResourceRegistry, ResourceRegistryRefusal, ResourceSubjectBinding,
    Workflow, decode_resource_reconstruction_record, encode_resource_reconstruction_record,
};
use gantry::value::{DEFAULT_VALUE_LIMITS, LogicalValue};

/// Fails to compile if the admitted account acquires a duplicating trait: a runtime
/// account is uniquely owned, so copying one would create a second owner over one
/// resource's lifetime without a second admitted reconstruction record.
macro_rules! assert_not_impl_any {
    ($type:ty: $($trait_name:path),+ $(,)?) => {
        const _: fn() = || {
            trait AmbiguousIfImpl<A> {
                fn some_item() {}
            }
            impl<T: ?Sized> AmbiguousIfImpl<()> for T {}
            $({
                #[allow(dead_code)]
                struct Invalid;
                impl<T: ?Sized + $trait_name> AmbiguousIfImpl<Invalid> for T {}
            })+
            let _ = <$type as AmbiguousIfImpl<_>>::some_item;
        };
    };
}

const ROOTS: &[LivenessRoot] = &[
    LivenessRoot::Resource,
    LivenessRoot::Owner,
    LivenessRoot::Loan,
    LivenessRoot::DurableRecord,
];

fn ledger() -> ResourceLedger {
    ledger_owned_by(4)
}

/// Returns the declared fixture ledger under one owner generation.
fn ledger_owned_by(owner: u64) -> ResourceLedger {
    ResourceLedger::new(
        OwnerGeneration::new(owner),
        ResourceState::PartiallyAdvanced,
        ROOTS,
        &[
            (QuotaOwner::Owner, QuotaFamily::Bytes, Quota::new(8, 1)),
            (QuotaOwner::Resource, QuotaFamily::Handles, Quota::new(1, 0)),
            (
                QuotaOwner::Resource,
                QuotaFamily::Operations,
                Quota::new(2, 0),
            ),
        ],
    )
    .unwrap_or_else(|error| panic!("the declared fixture ledger is valid: {error:?}"))
}

fn admitted(
    carrier: ResourceCarrier,
    record: DurableResourceRecord,
    subject: ResourceSubjectBinding,
) -> Result<AdmittedResource, ResourceRegistryRefusal> {
    AdmittedResource::admit(carrier, record, subject)
}

const FIXTURE_WORKFLOW: &str = "crate::main";
const FIXTURE_DECLARATION: &str = "crate::resource_runtime_metadata";
const SECOND_FIXTURE_DECLARATION: &str = "crate::resource_runtime_second_metadata";
const THIRD_FIXTURE_DECLARATION: &str = "crate::resource_runtime_third_metadata";
const UNAUTHENTICATED_FIXTURE_DECLARATION: &str =
    "crate::resource_runtime_unauthenticated_metadata";
const FIXTURE_SITE: u64 = 45;

/// Constructs the optional accounting owner around one known running root.
fn resource_coordinator(
    execution: ProtocolIdentity,
    root: ProtocolIdentity,
    limit: Option<u64>,
) -> gantry::runtime::ExecutionCoordinator {
    let tasks = gantry::runtime::ConcurrentTaskStateV1::new(execution, root, 1)
        .unwrap_or_else(|error| panic!("coordinator task state: {error:?}"));
    let session = ProtocolIdentity::from_fresh_material(IdentityKind::Session, [7; 32])
        .unwrap_or_else(|error| panic!("session identity: {error}"));
    let sessions = gantry::runtime::LogicalSessionRegistryV1::new(
        execution,
        session,
        gantry::runtime::SessionCreationModeV1::GantryRoot,
        gantry::runtime::CanonicalTranscriptV1::empty(),
    )
    .unwrap_or_else(|error| panic!("coordinator sessions: {error:?}"));
    match limit {
        Some(limit) => {
            gantry::runtime::ExecutionCoordinator::new_with_resource_limit(tasks, sessions, limit)
        }
        None => gantry::runtime::ExecutionCoordinator::new(tasks, sessions),
    }
    .unwrap_or_else(|error| panic!("resource coordinator: {error:?}"))
}

/// Cooperative closure is clone-visible and does not cancel or settle accepted work.
#[test]
fn coordinator_resource_admission_closure_preserves_accepted_work() {
    use gantry::runtime::CoordinatorResourceRefusal;
    let (_, machine, subject) = machine_with_declared_subject(Some(FIXTURE_DECLARATION));
    let subject = subject.unwrap_or_else(|| panic!("subject exists"));
    let coordinator = resource_coordinator(machine.execution_id(), machine.task_id(), Some(2));
    coordinator
        .admit_resource(
            &machine,
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
        )
        .unwrap_or_else(|error| panic!("admission: {error:?}"));
    let before = coordinator.snapshot();
    assert!(!coordinator.resource_admission_is_closed());
    assert!(coordinator.clone().close_resource_admission());
    assert!(coordinator.resource_admission_is_closed());
    assert!(!coordinator.close_resource_admission());
    assert_eq!(coordinator.snapshot(), before);
    assert_eq!(
        coordinator.admit_resource(
            &machine,
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record()
        ),
        Err(CoordinatorResourceRefusal::ResourceAdmissionClosed)
    );
    let (error, returned) = *coordinator
        .attach_resource_host_value(&subject, OwnerGeneration::new(4), 17_u64)
        .err()
        .unwrap_or_else(|| panic!("closed attachment refuses"));
    assert_eq!(error, CoordinatorResourceRefusal::ResourceAdmissionClosed);
    assert_eq!(returned, 17);
    assert_eq!(coordinator.snapshot(), before);
    assert!(machine.pending_resource_subject().is_some());
    assert_eq!(
        coordinator.emergency_release_resource(&subject, emergency_cleanup()),
        Ok(ResourceLifetimeState::EmergencyReleased)
    );
    assert!(coordinator.resource_admission_is_closed());
}

/// Task-selected cleanup refuses before cessation and never settles accepted machine work.
#[test]
fn task_resource_cleanup_requires_cancelled_and_physically_settled_owners() {
    use gantry::host::containment::AdapterPoison;
    use gantry::host::contracts::BlockingWorkService;
    use gantry::runtime::{BoundedBlockingWorkService, CoordinatorResourceRefusal};
    let (_, machine, subject) = machine_with_declared_subject(Some(FIXTURE_DECLARATION));
    let subject = subject.unwrap_or_else(|| panic!("subject exists"));
    let (_, second_machine, second) =
        machine_with_declared_subject(Some(SECOND_FIXTURE_DECLARATION));
    let second = second.unwrap_or_else(|| panic!("second subject exists"));
    let coordinator = resource_coordinator(machine.execution_id(), machine.task_id(), Some(2));
    let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    for (machine, subject) in [(&machine, &subject), (&second_machine, &second)] {
        coordinator
            .admit_resource(
                machine,
                ResourceCarrier::ReconstructionRecord,
                ledger().durable_record(),
            )
            .unwrap_or_else(|error| panic!("admission: {error:?}"));
        coordinator
            .attach_resource_host_value(
                subject,
                OwnerGeneration::new(4),
                TransportValue {
                    drops: Arc::clone(&drops),
                    panic_on_drop: false,
                    value: 1,
                },
            )
            .unwrap_or_else(|_| panic!("attachment"));
    }
    coordinator
        .emergency_release_resource(&second, emergency_cleanup())
        .unwrap_or_else(|error| panic!("prior release: {error:?}"));
    let before = coordinator.snapshot();
    let unknown = ProtocolIdentity::derive(IdentityKind::Task, b"unknown-cleanup-task")
        .unwrap_or_else(|error| panic!("task: {error}"));
    assert_eq!(
        coordinator.emergency_release_task_resources(&[unknown], emergency_escalation_at(21)),
        Err(CoordinatorResourceRefusal::UnknownTask)
    );
    assert_eq!(
        coordinator
            .emergency_release_task_resources(&[machine.task_id()], emergency_escalation_at(21)),
        Err(CoordinatorResourceRefusal::TaskNotCancelled)
    );
    assert_eq!(coordinator.snapshot(), before);
    coordinator
        .cancel_execution("task cleanup")
        .unwrap_or_else(|error| panic!("cancellation: {error:?}"));
    coordinator
        .settle_task(
            machine.task_id(),
            MachineOutcome::Cancelled(Arc::from("task cleanup")),
        )
        .unwrap_or_else(|error| panic!("settlement: {error:?}"));
    let before = coordinator.snapshot();
    assert_eq!(
        coordinator
            .emergency_release_task_resources(&[machine.task_id()], emergency_escalation_at(21)),
        Err(CoordinatorResourceRefusal::TaskDriverNotSettled)
    );
    assert_eq!(coordinator.snapshot(), before);
    assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 0);
    coordinator
        .mark_driver_physically_settled(machine.task_id())
        .unwrap_or_else(|error| panic!("physical settlement: {error:?}"));
    let before = coordinator.snapshot();
    let service =
        BoundedBlockingWorkService::new(1, 1).unwrap_or_else(|error| panic!("service: {error:?}"));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap_or_else(|error| panic!("runtime: {error}"));
    let observer = coordinator
        .submit_task_resource_cleanup(
            &service,
            &AdapterPoison::default(),
            vec![machine.task_id(), machine.task_id()],
            emergency_escalation_at(21),
        )
        .unwrap_or_else(|error| panic!("submission: {error:?}"));
    let report = runtime
        .block_on(observer.completion())
        .unwrap_or_else(|error| panic!("cleanup: {error:?}"));
    assert_eq!(runtime.block_on(service.shutdown()), Ok(()));
    assert!(report.semantic().is_complete());
    assert_eq!(report.semantic().settled().len(), 1);
    assert_eq!(report.semantic().settled()[0].subject(), &subject);
    assert_eq!(report.physical(), &[(subject.clone(), Ok(()))]);
    assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(
        coordinator.snapshot().publication(),
        before.publication() + 1
    );
    assert!(coordinator.has_pending_resource_operations());
    let before_repeat = coordinator.snapshot();
    let repeat = coordinator
        .emergency_release_task_resources(&[machine.task_id()], emergency_escalation_at(21))
        .unwrap_or_else(|error| panic!("repeat: {error:?}"));
    assert!(repeat.semantic().settled().is_empty());
    assert!(repeat.physical().is_empty());
    assert_eq!(coordinator.snapshot(), before_repeat);
    coordinator
        .dispose_resource_host_value(&second, OwnerGeneration::new(4))
        .unwrap_or_else(|error| panic!("prior terminal cleanup: {error:?}"));
    assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 2);
}

/// Builds task/session inputs for an accounting-only reconstruction boundary.
fn resource_recovery_inputs(
    execution: ProtocolIdentity,
    root: ProtocolIdentity,
) -> (
    gantry::runtime::ConcurrentTaskStateV1,
    gantry::runtime::LogicalSessionRegistryV1,
) {
    let tasks = gantry::runtime::ConcurrentTaskStateV1::new(execution, root, 1)
        .unwrap_or_else(|error| panic!("recovery tasks: {error:?}"));
    let session = ProtocolIdentity::from_fresh_material(IdentityKind::Session, [7; 32])
        .unwrap_or_else(|error| panic!("recovery session: {error}"));
    let sessions = gantry::runtime::LogicalSessionRegistryV1::new(
        execution,
        session,
        gantry::runtime::SessionCreationModeV1::GantryRoot,
        gantry::runtime::CanonicalTranscriptV1::empty(),
    )
    .unwrap_or_else(|error| panic!("recovery sessions: {error:?}"));
    (tasks, sessions)
}

/// Recovered empty accounting policy still enforces independent admission limits.
#[test]
fn durable_resource_policy_enforces_admission_after_driver_recovery() {
    use gantry::runtime::{
        ConcurrentDurableCheckpointV6, ConcurrentDurableCheckpointV7, CoordinatorResourceRefusal,
        ExecutionCoordinator,
    };
    for (live, pending, retained, expected) in [
        (
            0,
            1,
            None,
            Some(ResourceRegistryRefusal::LiveResourceLimitReached { limit: 0 }),
        ),
        (
            1,
            0,
            None,
            Some(ResourceRegistryRefusal::PendingOperationLimitReached { limit: 0 }),
        ),
        (1, 1, None, None),
        (
            1,
            1,
            Some(0),
            Some(ResourceRegistryRefusal::RetainedResourceLimitReached { limit: 0 }),
        ),
        (1, 1, Some(1), None),
    ] {
        let (program, machine, _) = machine_with_declared_subject(Some(FIXTURE_DECLARATION));
        let (tasks, sessions) = resource_recovery_inputs(machine.execution_id(), machine.task_id());
        let coordinator = if let Some(retained) = retained {
            ExecutionCoordinator::new_with_budget_and_accounting_limits(
                tasks,
                sessions,
                machine.execution_budget(),
                live,
                pending,
                retained,
            )
        } else {
            ExecutionCoordinator::new_with_budget_and_resource_limits(
                tasks,
                sessions,
                machine.execution_budget(),
                live,
                pending,
            )
        }
        .unwrap_or_else(|error| panic!("coordinator: {error:?}"));
        let checkpoint = coordinator
            .capture_checkpoint(&machine, &std::collections::BTreeMap::new())
            .unwrap_or_else(|error| panic!("empty accounting capture: {error:?}"));
        let decoded: gantry::runtime::ConcurrentDurableCheckpointV4 = if retained.is_some() {
            ConcurrentDurableCheckpointV7::decode(&program, &checkpoint.canonical_bytes())
                .unwrap_or_else(|error| panic!("retained policy decode: {error:?}"))
                .into()
        } else {
            ConcurrentDurableCheckpointV6::decode(&program, &checkpoint.canonical_bytes())
                .unwrap_or_else(|error| panic!("policy decode: {error:?}"))
                .into()
        };
        let admission = decoded
            .recover(program)
            .unwrap_or_else(|error| panic!("policy recovery: {error:?}"))
            .into_driver_admission()
            .unwrap_or_else(|error| panic!("driver admission: {error:?}"));
        admission
            .register_submitted_drivers()
            .unwrap_or_else(|error| panic!("driver registration: {error:?}"));
        let (recovered, root, _, _) = admission.into_parts();
        let before = recovered.snapshot();
        let result = recovered.admit_resource(
            &root,
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
        );
        match expected {
            Some(refusal) => {
                assert_eq!(result, Err(CoordinatorResourceRefusal::Registry(refusal)));
                assert_eq!(recovered.snapshot(), before);
                assert!(!recovered.has_pending_resource_operations());
            }
            None => {
                assert_eq!(result, Ok(()));
                assert_eq!(recovered.snapshot().publication(), before.publication() + 1);
                assert!(recovered.has_unsettled_resource_accounts());
                assert!(recovered.has_pending_resource_operations());
            }
        }
    }
}

/// Declared records reconstruct one shared accounting owner, never physical or pending work.
#[test]
fn coordinator_reconstructs_declared_resource_records_for_known_tasks() {
    use gantry::runtime::{CoordinatorResourceRefusal, ExecutionCoordinator, HostResourceError};
    let (_, machine, subject) = machine_with_declared_subject(Some(FIXTURE_DECLARATION));
    let subject = subject.unwrap_or_else(|| panic!("subject exists"));
    let second = declared_subject(SECOND_FIXTURE_DECLARATION);
    let active = decode_resource_reconstruction_record(&encode_resource_reconstruction_record(
        &ledger().durable_record(),
    ))
    .unwrap_or_else(|error| panic!("active reconstruction record: {error:?}"));
    let terminal = decode_resource_reconstruction_record(&encode_resource_reconstruction_record(
        &settled_record(),
    ))
    .unwrap_or_else(|error| panic!("terminal reconstruction record: {error:?}"));
    let records = vec![
        presented(
            subject.clone(),
            ResourceCarrier::ReconstructionRecord,
            active,
        ),
        presented(second, ResourceCarrier::ReconstructionRecord, terminal),
    ];
    let (mut tasks, sessions) = resource_recovery_inputs(machine.execution_id(), machine.task_id());
    tasks
        .settle(
            machine.task_id(),
            MachineOutcome::Succeeded(LogicalValue::unit()),
        )
        .unwrap_or_else(|error| panic!("terminal recovered task: {error:?}"));
    let coordinator =
        ExecutionCoordinator::new_with_recovered_resources(tasks, sessions, 1, records.clone())
            .unwrap_or_else(|error| panic!("accounting reconstruction: {error:?}"));
    let before = coordinator.snapshot();
    assert_eq!(before.publication(), 0);
    assert_eq!(before.resource_records(), Some(records.as_slice()));
    let (error, returned) = *coordinator
        .attach_resource_host_value(&subject, OwnerGeneration::new(4), 17_u64)
        .err()
        .unwrap_or_else(|| panic!("recovered terminal task cannot acquire host ownership"));
    assert_eq!(error, CoordinatorResourceRefusal::TaskNotRunning);
    assert_eq!(returned, 17);
    assert_eq!(coordinator.snapshot(), before);
    assert_eq!(
        coordinator
            .clone()
            .emergency_release_resource(&subject, emergency_cleanup()),
        Ok(ResourceLifetimeState::EmergencyReleased)
    );
    let after = coordinator.snapshot();
    assert_eq!(after.publication(), 1);
    assert_eq!(
        after
            .resource_records()
            .unwrap_or_else(|| panic!("records retained"))[0]
            .record()
            .lifetime(),
        ResourceLifetimeState::EmergencyReleased
    );
    assert_eq!(
        coordinator.dispose_resource_host_value(&subject, OwnerGeneration::new(4)),
        Err(CoordinatorResourceRefusal::Host(
            HostResourceError::NotAttached
        )),
        "accounting recovery does not invent a physical slot"
    );
}

/// Reconstruction rejects the whole set for bad provenance or registry evidence.
#[test]
fn coordinator_resource_reconstruction_refuses_invalid_sets() {
    use gantry::runtime::{CoordinatorResourceRefusal, ExecutionCoordinator};
    let (_, machine, subject) = machine_with_declared_subject(Some(FIXTURE_DECLARATION));
    let subject = subject.unwrap_or_else(|| panic!("subject exists"));
    let valid = presented(
        subject.clone(),
        ResourceCarrier::ReconstructionRecord,
        ledger().durable_record(),
    );
    let second = presented(
        declared_subject(SECOND_FIXTURE_DECLARATION),
        ResourceCarrier::ReconstructionRecord,
        ledger().durable_record(),
    );
    for (records, limit, expected) in [
        (
            vec![valid.clone(), valid.clone()],
            2,
            ResourceRegistryRefusal::SecondAdmission,
        ),
        (
            vec![
                valid.clone(),
                presented(
                    subject.clone(),
                    ResourceCarrier::OrdinarySerialization,
                    ledger().durable_record(),
                ),
            ],
            2,
            ResourceRegistryRefusal::SecondAdmission,
        ),
        (
            vec![presented(
                subject.clone(),
                ResourceCarrier::OrdinarySerialization,
                ledger().durable_record(),
            )],
            1,
            ResourceRegistryRefusal::Admission(ResourceError::OrdinaryCarrierRefused),
        ),
        (
            vec![RecoveredResourceRecord::new(
                subject.clone(),
                ResourceCarrier::ReconstructionRecord,
                OwnerGeneration::new(3),
                ledger().durable_record(),
            )],
            1,
            ResourceRegistryRefusal::Admission(ResourceError::StaleOwner {
                presented: OwnerGeneration::new(3),
                current: OwnerGeneration::new(4),
            }),
        ),
        (
            vec![valid.clone(), second],
            1,
            ResourceRegistryRefusal::LiveResourceLimitReached { limit: 1 },
        ),
        (
            vec![valid.clone()],
            0,
            ResourceRegistryRefusal::LiveResourceLimitReached { limit: 0 },
        ),
    ] {
        let (tasks, sessions) = resource_recovery_inputs(machine.execution_id(), machine.task_id());
        assert_eq!(
            ExecutionCoordinator::new_with_recovered_resources(tasks, sessions, limit, records)
                .err(),
            Some(CoordinatorResourceRefusal::Registry(expected))
        );
    }
    let foreign_execution =
        ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [12; 32])
            .unwrap_or_else(|error| panic!("foreign execution: {error}"));
    let (tasks, sessions) = resource_recovery_inputs(foreign_execution, machine.task_id());
    assert_eq!(
        ExecutionCoordinator::new_with_recovered_resources(tasks, sessions, 1, vec![valid.clone()])
            .err(),
        Some(CoordinatorResourceRefusal::ForeignExecution)
    );
    let unknown_root =
        ProtocolIdentity::derive(IdentityKind::Task, b"unknown-resource-recovery-root")
            .unwrap_or_else(|error| panic!("unknown root: {error}"));
    let (tasks, sessions) = resource_recovery_inputs(machine.execution_id(), unknown_root);
    assert_eq!(
        ExecutionCoordinator::new_with_recovered_resources(tasks, sessions, 1, vec![valid]).err(),
        Some(CoordinatorResourceRefusal::UnknownTask)
    );
}

/// Accounting reconstruction retains a shared budget without inventing pending or physical work.
#[test]
fn coordinator_resource_reconstruction_retains_execution_budget() {
    use gantry::runtime::{CoordinatorResourceRefusal, ExecutionCoordinator, TaskStateError};
    let (_, machine, subject) = machine_with_declared_subject(Some(FIXTURE_DECLARATION));
    let subject = subject.unwrap_or_else(|| panic!("subject exists"));
    let records = vec![presented(
        subject,
        ResourceCarrier::ReconstructionRecord,
        ledger().durable_record(),
    )];
    let budget = machine.execution_budget();
    let (tasks, sessions) = resource_recovery_inputs(machine.execution_id(), machine.task_id());
    let coordinator = ExecutionCoordinator::new_with_budget_and_recovered_resources(
        tasks,
        sessions,
        budget.clone(),
        1,
        records.clone(),
    )
    .unwrap_or_else(|error| panic!("budget-qualified recovery: {error:?}"));
    assert_eq!(
        coordinator.snapshot().execution_budget(),
        Some(budget.snapshot())
    );
    assert_eq!(
        coordinator.snapshot().resource_records(),
        Some(records.as_slice())
    );
    assert!(!coordinator.has_pending_resource_operations());
    assert!(!coordinator.has_resource_host_values());
    let mut successor = budget.snapshot();
    successor.remaining_transitions = successor
        .remaining_transitions
        .map(|remaining| remaining - 1);
    successor.revision += 1;
    budget
        .publish_committed_snapshot(successor)
        .unwrap_or_else(|error| panic!("shared committed budget projection: {error:?}"));
    assert_eq!(
        coordinator.clone().snapshot().execution_budget(),
        Some(budget.snapshot())
    );

    let (tasks, sessions) = resource_recovery_inputs(machine.execution_id(), machine.task_id());
    assert_eq!(
        ExecutionCoordinator::new_with_budget_and_recovered_resources(
            tasks,
            sessions,
            budget.clone(),
            2,
            vec![records[0].clone(), records[0].clone()],
        )
        .err(),
        Some(CoordinatorResourceRefusal::Registry(
            ResourceRegistryRefusal::SecondAdmission
        ))
    );

    let foreign_execution =
        ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [99; 32])
            .unwrap_or_else(|error| panic!("foreign execution: {error}"));
    let (tasks, sessions) = resource_recovery_inputs(foreign_execution, machine.task_id());
    assert_eq!(
        ExecutionCoordinator::new_with_budget_and_recovered_resources(
            tasks, sessions, budget, 1, records,
        )
        .err(),
        Some(CoordinatorResourceRefusal::Task(
            TaskStateError::InvalidTaskMachine
        ))
    );
}

/// Explicit reconstruction policy bounds records and future admission independently.
#[test]
fn coordinator_bounded_reconstruction_preserves_admission_policy() {
    use gantry::runtime::{CoordinatorResourceRefusal, ExecutionCoordinator};
    let (_, machine, subject) = machine_with_declared_subject(Some(FIXTURE_DECLARATION));
    let records = vec![presented(
        subject.unwrap_or_else(|| panic!("subject exists")),
        ResourceCarrier::ReconstructionRecord,
        settled_record(),
    )];
    let (_, sibling, _) = machine_with_declared_subject(Some(SECOND_FIXTURE_DECLARATION));
    for (pending, retained, expected) in [
        (
            1,
            1,
            ResourceRegistryRefusal::RetainedResourceLimitReached { limit: 1 },
        ),
        (
            0,
            2,
            ResourceRegistryRefusal::PendingOperationLimitReached { limit: 0 },
        ),
    ] {
        let (tasks, sessions) = resource_recovery_inputs(machine.execution_id(), machine.task_id());
        let coordinator = ExecutionCoordinator::new_with_budget_and_bounded_recovered_resources(
            tasks,
            sessions,
            machine.execution_budget(),
            1,
            pending,
            retained,
            records.clone(),
        )
        .unwrap_or_else(|error| panic!("bounded reconstruction: {error:?}"));
        let before = coordinator.snapshot();
        assert_eq!(before.resource_records(), Some(records.as_slice()));
        assert_eq!(
            before.execution_budget(),
            Some(machine.execution_budget().snapshot())
        );
        assert!(!coordinator.has_pending_resource_operations());
        assert!(!coordinator.has_resource_host_values());
        assert_eq!(
            coordinator.clone().admit_resource(
                &sibling,
                ResourceCarrier::ReconstructionRecord,
                settled_record()
            ),
            Err(CoordinatorResourceRefusal::Registry(expected))
        );
        assert_eq!(coordinator.snapshot(), before);
    }
    let (tasks, sessions) = resource_recovery_inputs(machine.execution_id(), machine.task_id());
    assert_eq!(
        ExecutionCoordinator::new_with_budget_and_bounded_recovered_resources(
            tasks,
            sessions,
            machine.execution_budget(),
            1,
            1,
            0,
            records.clone(),
        )
        .err(),
        Some(CoordinatorResourceRefusal::Registry(
            ResourceRegistryRefusal::RetainedResourceLimitReached { limit: 0 }
        ))
    );
    let (tasks, sessions) = resource_recovery_inputs(machine.execution_id(), machine.task_id());
    assert_eq!(
        ExecutionCoordinator::new_with_budget_and_bounded_recovered_resources(
            tasks,
            sessions,
            machine.execution_budget(),
            1,
            1,
            1,
            vec![records[0].clone(), records[0].clone()],
        )
        .err(),
        Some(CoordinatorResourceRefusal::Registry(
            ResourceRegistryRefusal::SecondAdmission
        ))
    );
    let foreign = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [98; 32])
        .unwrap_or_else(|error| panic!("foreign execution: {error}"));
    let (tasks, sessions) = resource_recovery_inputs(foreign, machine.task_id());
    assert_eq!(
        ExecutionCoordinator::new_with_budget_and_bounded_recovered_resources(
            tasks,
            sessions,
            machine.execution_budget(),
            1,
            1,
            0,
            records,
        )
        .err(),
        Some(CoordinatorResourceRefusal::Task(
            gantry::runtime::TaskStateError::InvalidTaskMachine
        ))
    );
}

/// Coordinator clones share admission and quota fences, and terminal cleanup retains records.
#[test]
fn coordinator_resource_accounts_share_one_owner_and_release_only_live_places() {
    use gantry::runtime::CoordinatorResourceRefusal;

    let (_, machine, subject) = machine_with_declared_subject(Some(FIXTURE_DECLARATION));
    let subject = subject.unwrap_or_else(|| panic!("pending subject exists"));
    let coordinator = resource_coordinator(machine.execution_id(), machine.task_id(), Some(1));
    let clone = coordinator.clone();
    let initial = coordinator.snapshot();
    assert_eq!(initial.resource_records(), Some([].as_slice()));
    assert_eq!(
        clone.admit_resource(
            &machine,
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record()
        ),
        Ok(())
    );
    let admitted = coordinator.snapshot();
    assert_eq!(admitted.publication(), initial.publication() + 1);
    assert_eq!(admitted.resource_records().map(<[_]>::len), Some(1));
    assert_eq!(
        coordinator.admit_resource(
            &machine,
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record()
        ),
        Err(CoordinatorResourceRefusal::Registry(
            ResourceRegistryRefusal::SecondAdmission
        ))
    );
    assert_eq!(coordinator.snapshot(), admitted);

    let (_, sibling, sibling_subject) =
        machine_with_declared_subject(Some(SECOND_FIXTURE_DECLARATION));
    let sibling_subject = sibling_subject.unwrap_or_else(|| panic!("sibling subject exists"));
    assert_eq!(
        clone.admit_resource(
            &sibling,
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record()
        ),
        Err(CoordinatorResourceRefusal::Registry(
            ResourceRegistryRefusal::LiveResourceLimitReached { limit: 1 }
        ))
    );
    assert_eq!(coordinator.snapshot(), admitted);
    assert!(matches!(
        coordinator.begin_resource_finish(&subject, OwnerGeneration::new(3)),
        Err(CoordinatorResourceRefusal::Registry(
            ResourceRegistryRefusal::Finish(ResourceError::StaleOwner { .. })
        ))
    ));
    assert_eq!(coordinator.snapshot(), admitted);
    assert_eq!(
        clone.begin_resource_finish(&subject, OwnerGeneration::new(4)),
        Ok(ResourceLifetimeState::Finishing)
    );
    assert_eq!(
        coordinator.complete_resource_finalization(&subject, OwnerGeneration::new(4), 20),
        Ok(ResourceLifetimeState::Finished)
    );
    assert_eq!(
        clone.admit_resource(
            &sibling,
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record()
        ),
        Ok(())
    );
    coordinator
        .settle_task(
            machine.task_id(),
            MachineOutcome::Succeeded(LogicalValue::unit()),
        )
        .unwrap_or_else(|error| panic!("task settles: {error:?}"));
    let settled = coordinator.snapshot();
    assert_eq!(
        clone.admit_resource(
            &machine,
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record()
        ),
        Err(CoordinatorResourceRefusal::TaskNotRunning)
    );
    assert_eq!(coordinator.snapshot(), settled);
    assert_eq!(
        clone.emergency_release_resource(&sibling_subject, emergency_cleanup()),
        Ok(ResourceLifetimeState::EmergencyReleased)
    );
    let cleaned = coordinator.snapshot();
    assert_eq!(cleaned.publication(), settled.publication() + 1);
    let records = cleaned
        .resource_records()
        .unwrap_or_else(|| panic!("accounting records retained"));
    assert_eq!(records.len(), 2);
    assert!(records.iter().all(|record| matches!(
        record.record().lifetime(),
        ResourceLifetimeState::Finished | ResourceLifetimeState::EmergencyReleased
    )));
    assert!(matches!(
        coordinator.emergency_release_resource(&sibling_subject, emergency_cleanup()),
        Err(CoordinatorResourceRefusal::Registry(
            ResourceRegistryRefusal::EmergencyRelease(ResourceError::IllegalLifetimeTransition)
        ))
    ));
    assert_eq!(coordinator.snapshot(), cleaned);
}

/// Execution, task, carrier and disabled-registry refusals leave the complete snapshot unchanged.
#[test]
fn coordinator_resource_admission_refuses_foreign_or_ineligible_machines() {
    use gantry::runtime::CoordinatorResourceRefusal;

    let (_, machine, _) = machine_with_declared_subject(Some(FIXTURE_DECLARATION));
    let foreign_execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [8; 32])
        .unwrap_or_else(|error| panic!("foreign execution: {error}"));
    let foreign_task = ProtocolIdentity::derive(IdentityKind::Task, b"resource-unknown-task")
        .unwrap_or_else(|error| panic!("foreign task: {error}"));
    for (coordinator, refusal) in [
        (
            resource_coordinator(foreign_execution, machine.task_id(), Some(1)),
            CoordinatorResourceRefusal::ForeignExecution,
        ),
        (
            resource_coordinator(machine.execution_id(), foreign_task, Some(1)),
            CoordinatorResourceRefusal::UnknownTask,
        ),
        (
            resource_coordinator(machine.execution_id(), machine.task_id(), None),
            CoordinatorResourceRefusal::RegistryDisabled,
        ),
        (
            resource_coordinator(machine.execution_id(), machine.task_id(), Some(0)),
            CoordinatorResourceRefusal::Registry(
                ResourceRegistryRefusal::LiveResourceLimitReached { limit: 0 },
            ),
        ),
    ] {
        let before = coordinator.snapshot();
        assert_eq!(
            coordinator.admit_resource(
                &machine,
                ResourceCarrier::ReconstructionRecord,
                ledger().durable_record()
            ),
            Err(refusal)
        );
        assert_eq!(coordinator.snapshot(), before);
    }
    let coordinator = resource_coordinator(machine.execution_id(), machine.task_id(), Some(1));
    let before = coordinator.snapshot();
    assert_eq!(
        coordinator.admit_resource(
            &machine,
            ResourceCarrier::OrdinarySerialization,
            ledger().durable_record()
        ),
        Err(CoordinatorResourceRefusal::Registry(
            ResourceRegistryRefusal::Admission(ResourceError::OrdinaryCarrierRefused)
        ))
    );
    assert_eq!(coordinator.snapshot(), before);
    let (_, actionless, _) = machine_with_declared_subject(None);
    assert_eq!(
        coordinator.admit_resource(
            &actionless,
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record()
        ),
        Err(CoordinatorResourceRefusal::Registry(
            ResourceRegistryRefusal::NoPendingResourceSubject
        ))
    );
    assert_eq!(coordinator.snapshot(), before);
}

/// Shared charging publishes a complete charge vector or preserves the entire prior cut.
#[test]
fn coordinator_resource_charging_is_atomic_and_owner_fenced() {
    use gantry::runtime::CoordinatorResourceRefusal;

    let (_, machine, subject) = machine_with_declared_subject(Some(FIXTURE_DECLARATION));
    let subject = subject.unwrap_or_else(|| panic!("pending subject exists"));
    let coordinator = resource_coordinator(machine.execution_id(), machine.task_id(), Some(1));
    coordinator
        .admit_resource(
            &machine,
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
        )
        .unwrap_or_else(|error| panic!("account admits: {error:?}"));
    let before = coordinator.snapshot();
    let charges = [
        Charge {
            owner: QuotaOwner::Owner,
            family: QuotaFamily::Bytes,
            amount: 2,
        },
        Charge {
            owner: QuotaOwner::Resource,
            family: QuotaFamily::Operations,
            amount: 3,
        },
    ];
    assert_eq!(
        coordinator.charge_resource(
            &subject,
            OwnerGeneration::new(4),
            ResourceAction::Update,
            &charges
        ),
        Err(CoordinatorResourceRefusal::Registry(
            ResourceRegistryRefusal::Charge(ResourceError::QuotaExhausted)
        ))
    );
    assert_eq!(coordinator.snapshot(), before);
    assert!(matches!(
        coordinator.charge_resource(
            &subject,
            OwnerGeneration::new(3),
            ResourceAction::Update,
            &charges[..1]
        ),
        Err(CoordinatorResourceRefusal::Registry(
            ResourceRegistryRefusal::Charge(ResourceError::StaleOwner { .. })
        ))
    ));
    assert_eq!(coordinator.snapshot(), before);
    assert_eq!(
        coordinator.clone().charge_resource(
            &subject,
            OwnerGeneration::new(4),
            ResourceAction::Update,
            &charges[..1]
        ),
        Ok(())
    );
    let charged = coordinator.snapshot();
    assert_eq!(charged.publication(), before.publication() + 1);
    let records = charged
        .resource_records()
        .unwrap_or_else(|| panic!("records exist"));
    let quota = records[0]
        .record()
        .quotas()
        .get(&(QuotaOwner::Owner, QuotaFamily::Bytes))
        .unwrap_or_else(|| panic!("byte quota exists"));
    assert_eq!(quota.used(), 2);
    assert_eq!(
        records[0].record().lifetime(),
        ResourceLifetimeState::Active
    );
}

/// Coordinator retention keeps pending work separate and publishes only accepted model transitions.
#[test]
fn coordinator_resource_renewal_and_retention_preserve_model_fences() {
    use gantry::runtime::CoordinatorResourceRefusal;
    let (_, machine, subject) = machine_with_declared_subject(Some(FIXTURE_DECLARATION));
    let subject = subject.unwrap_or_else(|| panic!("subject exists"));
    let coordinator = resource_coordinator(machine.execution_id(), machine.task_id(), Some(1));
    let owner = OwnerGeneration::new(4);
    coordinator
        .admit_resource(
            &machine,
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
        )
        .unwrap_or_else(|error| panic!("admit: {error:?}"));
    let before = coordinator.snapshot();
    assert_eq!(
        coordinator.renew_resource_quota(&subject, owner, QuotaOwner::Owner, QuotaFamily::Bytes, 4),
        Ok(())
    );
    let renewed = coordinator.snapshot();
    assert_eq!(renewed.publication(), before.publication() + 1);
    assert_eq!(
        renewed
            .resource_records()
            .unwrap_or_else(|| panic!("records"))[0]
            .record()
            .quotas()
            .get(&(QuotaOwner::Owner, QuotaFamily::Bytes))
            .map(|quota| quota.limit()),
        Some(12)
    );
    assert_eq!(
        coordinator.renew_resource_quota(&subject, owner, QuotaOwner::Owner, QuotaFamily::Bytes, 4),
        Err(CoordinatorResourceRefusal::Registry(
            ResourceRegistryRefusal::Renewal(ResourceError::RenewalExhausted)
        ))
    );
    assert_eq!(coordinator.snapshot(), renewed);
    assert!(matches!(
        coordinator.close_resource_liveness_root(
            &subject,
            OwnerGeneration::new(3),
            LivenessRoot::Resource
        ),
        Err(CoordinatorResourceRefusal::Registry(
            ResourceRegistryRefusal::RootClosure(ResourceError::StaleOwner { .. })
        ))
    ));
    assert_eq!(coordinator.snapshot(), renewed);
    coordinator
        .begin_resource_finish(&subject, owner)
        .unwrap_or_else(|error| panic!("finish: {error:?}"));
    coordinator
        .complete_resource_finalization(&subject, owner, 31)
        .unwrap_or_else(|error| panic!("finalize: {error:?}"));
    let fence = RetentionFence::new(1, 10).unwrap_or_else(|error| panic!("fence: {error:?}"));
    let settled = coordinator.snapshot();
    assert_eq!(
        coordinator.retire_resource_record(&subject, fence, owner, OwnerGeneration::new(5), 41),
        Err(CoordinatorResourceRefusal::Registry(
            ResourceRegistryRefusal::Retirement(ResourceError::LivenessRootsRemain)
        ))
    );
    assert_eq!(coordinator.snapshot(), settled);
    for root in ROOTS {
        let before = coordinator.snapshot();
        assert_eq!(
            coordinator
                .clone()
                .close_resource_liveness_root(&subject, owner, *root),
            Ok(())
        );
        assert_eq!(
            coordinator.snapshot().publication(),
            before.publication() + 1
        );
    }
    let closed = coordinator.snapshot();
    assert_eq!(
        coordinator.retire_resource_record(&subject, fence, owner, OwnerGeneration::new(5), 41),
        Err(CoordinatorResourceRefusal::Registry(
            ResourceRegistryRefusal::Retirement(ResourceError::RetentionNotExpired)
        ))
    );
    assert_eq!(coordinator.snapshot(), closed);
    assert_eq!(
        coordinator.retire_resource_record(&subject, fence, owner, OwnerGeneration::new(5), 42),
        Ok(())
    );
    let retired = coordinator.snapshot();
    assert_eq!(retired.publication(), closed.publication() + 1);
    assert_eq!(
        coordinator.delete_resource_record(&subject, owner),
        Ok(ResourceLifetimeState::Deleted)
    );
    let deleted = coordinator.snapshot();
    assert_eq!(deleted.publication(), retired.publication() + 1);
    assert_eq!(
        deleted
            .resource_records()
            .unwrap_or_else(|| panic!("records"))[0]
            .record()
            .lifetime(),
        ResourceLifetimeState::Deleted
    );
    assert!(coordinator.has_pending_resource_operations());
    assert!(machine.checkpoint().pending_operation().is_some());
    assert_eq!(
        coordinator.delete_resource_record(&subject, owner),
        Err(CoordinatorResourceRefusal::Registry(
            ResourceRegistryRefusal::Deletion(ResourceError::IllegalLifetimeTransition)
        ))
    );
    assert_eq!(coordinator.snapshot(), deleted);
}

/// Adapter poisoning retains accounting and pending work while preserving publication fences.
#[test]
fn coordinator_resource_adapter_binding_and_failure_preserve_accounting() {
    use gantry::runtime::CoordinatorResourceRefusal;
    let (_, machine, subject) = machine_with_declared_subject(Some(FIXTURE_DECLARATION));
    let subject = subject.unwrap_or_else(|| panic!("subject exists"));
    let coordinator = resource_coordinator(machine.execution_id(), machine.task_id(), Some(1));
    let owner = OwnerGeneration::new(4);
    coordinator
        .admit_resource(
            &machine,
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
        )
        .unwrap_or_else(|error| panic!("admit: {error:?}"));
    let before = coordinator.snapshot();
    assert!(matches!(
        coordinator.bind_resource_adapter(
            &subject,
            OwnerGeneration::new(3),
            adapter_instance("coordinator", 4, 0)
        ),
        Err(CoordinatorResourceRefusal::Registry(
            ResourceRegistryRefusal::AdapterBinding(AdapterBindingRefusal::StaleOwner(_))
        ))
    ));
    assert_eq!(coordinator.snapshot(), before);
    assert_eq!(
        coordinator.bind_resource_adapter(&subject, owner, adapter_instance("coordinator", 4, 0)),
        Ok(())
    );
    let bound = coordinator.snapshot();
    assert_eq!(bound.publication(), before.publication() + 1);
    let resource_failure = failure_settlement_in(
        FIXTURE_WORKFLOW,
        FIXTURE_DECLARATION,
        vec![FIXTURE_SITE],
        0,
        FailureClass::ResourceFailure,
    );
    assert_eq!(
        coordinator.poison_resource_adapter_from_post_failure(
            &resource_failure,
            owner,
            PoisonReason::InvariantFailure,
            &subject
        ),
        Err(CoordinatorResourceRefusal::Registry(
            ResourceRegistryRefusal::Settlement(
                PostFailureSettlementRefusal::AdapterPoisoningNotRequired
            )
        ))
    );
    assert_eq!(coordinator.snapshot(), bound);
    let failure = failure_settlement_in(
        FIXTURE_WORKFLOW,
        FIXTURE_DECLARATION,
        vec![FIXTURE_SITE],
        0,
        FailureClass::AdapterFailure,
    );
    let reason = PoisonReason::ForeignFailure(ForeignFailureKind::Protocol);
    assert_eq!(
        coordinator.poison_resource_adapter_from_post_failure(&failure, owner, reason, &subject),
        Ok(reason)
    );
    let poisoned = coordinator.snapshot();
    assert_eq!(poisoned.publication(), bound.publication() + 1);
    assert_eq!(poisoned.resource_records(), before.resource_records());
    assert!(coordinator.has_pending_resource_operations());
    assert_eq!(
        coordinator.poison_resource_adapter_from_post_failure(
            &failure,
            owner,
            PoisonReason::InvariantFailure,
            &subject
        ),
        Ok(reason)
    );
    let repeated = coordinator.snapshot();
    assert_eq!(repeated.resource_records(), before.resource_records());
    assert!(matches!(
        coordinator.bind_resource_adapter(&subject, owner, adapter_instance("replacement", 5, 1)),
        Err(CoordinatorResourceRefusal::Registry(
            ResourceRegistryRefusal::AdapterBinding(AdapterBindingRefusal::Substitution(
                OperationAbiError::AdapterInstancePoisoned { .. }
            ))
        ))
    ));
    assert_eq!(coordinator.snapshot(), repeated);
}

/// Resource poisoning releases the shared live place; adapter-only evidence and retries do not.
#[test]
fn coordinator_resource_failure_settlement_releases_the_live_place_once() {
    use gantry::runtime::CoordinatorResourceRefusal;

    let (_, machine, subject) = machine_with_declared_subject(Some(FIXTURE_DECLARATION));
    let subject = subject.unwrap_or_else(|| panic!("pending subject exists"));
    let coordinator = resource_coordinator(machine.execution_id(), machine.task_id(), Some(1));
    coordinator
        .admit_resource(
            &machine,
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
        )
        .unwrap_or_else(|error| panic!("account admits: {error:?}"));
    let before = coordinator.snapshot();
    let adapter_failure = failure_settlement_in(
        FIXTURE_WORKFLOW,
        FIXTURE_DECLARATION,
        vec![FIXTURE_SITE],
        0,
        FailureClass::AdapterFailure,
    );
    assert_eq!(
        coordinator.settle_resource_from_post_failure(&adapter_failure, 21, &subject),
        Err(CoordinatorResourceRefusal::Registry(
            ResourceRegistryRefusal::Settlement(PostFailureSettlementRefusal::Model(
                ResourceError::FailureDoesNotPoisonResource
            ))
        ))
    );
    assert_eq!(coordinator.snapshot(), before);
    let resource_failure = failure_settlement_in(
        FIXTURE_WORKFLOW,
        FIXTURE_DECLARATION,
        vec![FIXTURE_SITE],
        0,
        FailureClass::ResourceFailure,
    );
    assert_eq!(
        coordinator
            .clone()
            .settle_resource_from_post_failure(&resource_failure, 22, &subject),
        Ok(ResourceLifetimeState::Poisoned)
    );
    let poisoned = coordinator.snapshot();
    assert_eq!(poisoned.publication(), before.publication() + 1);
    let records = poisoned
        .resource_records()
        .unwrap_or_else(|| panic!("poisoned record retained"));
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0].record().lifetime(),
        ResourceLifetimeState::Poisoned
    );
    assert_eq!(
        records[0].record().quotas(),
        before
            .resource_records()
            .unwrap_or_else(|| panic!("initial record exists"))[0]
            .record()
            .quotas()
    );
    let baseline = records[0]
        .record()
        .settlement()
        .unwrap_or_else(|| panic!("poison baseline exists"));
    assert_eq!(baseline.owner(), OwnerGeneration::new(4));
    assert_eq!(baseline.settled_at(), 22);
    assert_eq!(
        coordinator.settle_resource_from_post_failure(&resource_failure, 23, &subject),
        Err(CoordinatorResourceRefusal::Registry(
            ResourceRegistryRefusal::Settlement(PostFailureSettlementRefusal::Model(
                ResourceError::IllegalLifetimeTransition
            ))
        ))
    );
    assert_eq!(coordinator.snapshot(), poisoned);
    let (_, sibling, _) = machine_with_declared_subject(Some(SECOND_FIXTURE_DECLARATION));
    assert_eq!(
        coordinator.admit_resource(
            &sibling,
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record()
        ),
        Ok(())
    );
    let reused = coordinator.snapshot();
    assert_eq!(reused.resource_records().map(<[_]>::len), Some(2));
    assert_eq!(reused.publication(), poisoned.publication() + 1);
}

/// Pending capacity follows machine settlement rather than accounting lifetime or reclamation.
#[test]
fn pending_resource_operation_limit_releases_only_after_machine_settlement() {
    for disposition in ["failure", "cancellation"] {
        let (_, mut machine, subject) = machine_with_declared_subject(Some(FIXTURE_DECLARATION));
        let subject = subject.unwrap_or_else(|| panic!("pending subject exists"));
        let operation = machine
            .checkpoint()
            .pending_operation()
            .unwrap_or_else(|| panic!("pending operation exists"))
            .identity;
        let (_, sibling, _) = machine_with_declared_subject(Some(SECOND_FIXTURE_DECLARATION));
        let mut registry = ResourceRegistry::with_limits(2, 1);
        assert_eq!(registry.pending_limit(), Some(1));
        registry
            .admit_pending_operation(
                &machine,
                ResourceCarrier::ReconstructionRecord,
                ledger().durable_record(),
            )
            .unwrap_or_else(|error| panic!("first admission: {error:?}"));
        assert_eq!(registry.pending_operations(), 1);
        let before = registry.declared_records();
        assert_eq!(
            registry
                .admit_pending_operation(
                    &machine,
                    ResourceCarrier::ReconstructionRecord,
                    ledger().durable_record()
                )
                .err(),
            Some(ResourceRegistryRefusal::SecondAdmission)
        );
        assert_eq!(
            registry
                .admit_pending_operation(
                    &sibling,
                    ResourceCarrier::ReconstructionRecord,
                    ledger().durable_record()
                )
                .err(),
            Some(ResourceRegistryRefusal::PendingOperationLimitReached { limit: 1 })
        );
        assert_eq!(registry.declared_records(), before);
        assert_eq!(
            machine.complete_operation(operation, LogicalValue::boolean(true)),
            Err(OperationCompletionError::LiveResourceValueRefused)
        );
        assert_eq!(
            registry.pending_operations(),
            1,
            "refused completion retains capacity"
        );
        assert_eq!(
            registry.begin_finish(&subject, OwnerGeneration::new(4)),
            Ok(ResourceLifetimeState::Finishing)
        );
        assert_eq!(
            registry.complete_finalization(&subject, OwnerGeneration::new(4), 20),
            Ok(ResourceLifetimeState::Finished)
        );
        assert_eq!(registry.live_resources(), 0);
        assert_eq!(
            registry.pending_operations(),
            1,
            "accounting settlement cannot settle machine work"
        );
        assert_eq!(
            registry
                .admit_pending_operation(
                    &sibling,
                    ResourceCarrier::ReconstructionRecord,
                    ledger().durable_record()
                )
                .err(),
            Some(ResourceRegistryRefusal::PendingOperationLimitReached { limit: 1 })
        );
        match disposition {
            "failure" => {
                assert!(
                    machine
                        .fail_operation(
                            operation,
                            gantry::portable::RuntimeErrorCategory::ExecutorFailure
                        )
                        .is_ok()
                );
            }
            "cancellation" => {
                assert!(machine.cancel("pending quota regression").is_some());
                assert_eq!(
                    registry.pending_operations(),
                    1,
                    "request alone is not settlement"
                );
                assert_eq!(
                    machine.complete_operation(operation, LogicalValue::unit()),
                    Err(OperationCompletionError::Cancelled)
                );
                assert_eq!(registry.pending_operations(), 1);
                assert!(matches!(
                    machine.step(),
                    MachineStep::Transition(MachineLabel::TaskSettled(MachineOutcome::Cancelled(
                        _
                    )))
                ));
            }
            _ => unreachable!("the declared settlement cases are exhaustive"),
        }
        assert_eq!(
            registry.pending_operations(),
            0,
            "{disposition} releases pending capacity"
        );
        registry
            .admit_pending_operation(
                &sibling,
                ResourceCarrier::ReconstructionRecord,
                ledger().durable_record(),
            )
            .unwrap_or_else(|error| panic!("released pending place admits sibling: {error:?}"));
        assert_eq!(registry.pending_operations(), 1);
        assert_eq!(
            registry.declared_records().len(),
            2,
            "release does not reclaim accounting records"
        );
    }
}

/// Reclaiming terminal accounting records cannot release unsettled machine work.
#[test]
fn pending_capacity_survives_poison_emergency_release_and_record_reclamation() {
    for emergency in [false, true] {
        let (_, mut machine, subject) = machine_with_declared_subject(Some(FIXTURE_DECLARATION));
        let subject = subject.unwrap_or_else(|| panic!("pending subject exists"));
        let operation = machine
            .checkpoint()
            .pending_operation()
            .unwrap_or_else(|| panic!("pending operation exists"))
            .identity;
        let (_, sibling, _) = machine_with_declared_subject(Some(SECOND_FIXTURE_DECLARATION));
        let mut registry = ResourceRegistry::with_limits(1, 1);
        registry
            .admit_pending_operation(
                &machine,
                ResourceCarrier::ReconstructionRecord,
                ledger().durable_record(),
            )
            .unwrap_or_else(|error| panic!("first admission: {error:?}"));
        if emergency {
            assert_eq!(
                registry.settle_from_emergency_cleanup(&subject, emergency_cleanup()),
                Ok(ResourceLifetimeState::EmergencyReleased)
            );
        } else {
            let failure = failure_settlement_in(
                FIXTURE_WORKFLOW,
                FIXTURE_DECLARATION,
                vec![FIXTURE_SITE],
                0,
                FailureClass::ResourceFailure,
            );
            assert_eq!(
                registry.settle_from_post_failure(&failure, 21, &subject),
                Ok(ResourceLifetimeState::Poisoned)
            );
        }
        assert_eq!(registry.live_resources(), 0);
        assert_eq!(registry.pending_operations(), 1);
        for root in ROOTS {
            registry
                .close_liveness_root(&subject, OwnerGeneration::new(4), *root)
                .unwrap_or_else(|error| panic!("root closure: {error:?}"));
        }
        let fence =
            RetentionFence::new(2, 10).unwrap_or_else(|error| panic!("retention fence: {error:?}"));
        registry
            .retire(
                &subject,
                fence,
                OwnerGeneration::new(4),
                OwnerGeneration::new(5),
                35,
            )
            .unwrap_or_else(|error| panic!("record retirement: {error:?}"));
        assert_eq!(
            registry.delete(&subject, OwnerGeneration::new(4)),
            Ok(ResourceLifetimeState::Deleted)
        );
        assert_eq!(registry.reap_deleted(), 1);
        assert!(registry.declared_records().is_empty());
        assert_eq!(
            registry.pending_operations(),
            1,
            "reclamation is not machine settlement"
        );
        assert_eq!(
            registry
                .admit_pending_operation(
                    &sibling,
                    ResourceCarrier::ReconstructionRecord,
                    ledger().durable_record()
                )
                .err(),
            Some(ResourceRegistryRefusal::PendingOperationLimitReached { limit: 1 })
        );
        assert!(
            machine
                .fail_operation(
                    operation,
                    gantry::portable::RuntimeErrorCategory::ExecutorFailure
                )
                .is_ok()
        );
        assert_eq!(registry.pending_operations(), 0);
        registry
            .admit_pending_operation(
                &sibling,
                ResourceCarrier::ReconstructionRecord,
                ledger().durable_record(),
            )
            .unwrap_or_else(|error| panic!("settled lease releases capacity: {error:?}"));
        assert_eq!(registry.pending_operations(), 1);
    }
}

/// Unlimited pending admission still tracks accepted work independently of accounting release.
#[test]
fn unlimited_pending_policy_retains_accepted_resource_work() {
    let (_, mut machine, subject) = machine_with_declared_subject(Some(FIXTURE_DECLARATION));
    let subject = subject.unwrap_or_else(|| panic!("subject exists"));
    let (_, sibling, _) = machine_with_declared_subject(Some(SECOND_FIXTURE_DECLARATION));
    let mut registry = ResourceRegistry::with_live_limit(1);
    assert_eq!(registry.pending_limit(), None);
    registry
        .admit_pending_operation(
            &machine,
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
        )
        .unwrap_or_else(|error| panic!("admission: {error:?}"));
    assert_eq!(
        registry.pending_operations(),
        1,
        "no ceiling does not mean no accepted work"
    );
    registry
        .settle_from_emergency_cleanup(&subject, emergency_cleanup())
        .unwrap_or_else(|error| panic!("release: {error:?}"));
    registry
        .admit_pending_operation(
            &sibling,
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
        )
        .unwrap_or_else(|error| panic!("unlimited pending admission: {error:?}"));
    assert_eq!(registry.pending_operations(), 2);
    assert!(machine.cancel("settle accepted work").is_some());
    assert_eq!(
        registry.pending_operations(),
        2,
        "cancellation alone does not release work"
    );
    let _ = machine.step();
    assert_eq!(registry.pending_operations(), 1);
}

/// Zero pending capacity and stronger admission errors refuse without retaining a lease.
#[test]
fn pending_resource_operation_limit_preserves_admission_refusal_precedence() {
    let (_, machine, _) = machine_with_declared_subject(Some(FIXTURE_DECLARATION));
    let (_, unauthenticated, _) = machine_with_unauthenticated_subject(Some(FIXTURE_DECLARATION));
    let mut registry = ResourceRegistry::with_limits(1, 0);
    assert_eq!(
        registry
            .admit_pending_operation(
                &unauthenticated,
                ResourceCarrier::ReconstructionRecord,
                ledger().durable_record()
            )
            .err(),
        Some(ResourceRegistryRefusal::UnauthenticatedOperationKind)
    );
    assert_eq!(
        registry
            .admit_pending_operation(
                &machine,
                ResourceCarrier::OrdinarySerialization,
                ledger().durable_record()
            )
            .err(),
        Some(ResourceRegistryRefusal::Admission(
            ResourceError::OrdinaryCarrierRefused
        ))
    );
    assert_eq!(
        registry
            .admit_pending_operation(
                &machine,
                ResourceCarrier::ReconstructionRecord,
                ledger().durable_record()
            )
            .err(),
        Some(ResourceRegistryRefusal::PendingOperationLimitReached { limit: 0 })
    );
    assert!(registry.declared_records().is_empty());
    assert_eq!(registry.pending_operations(), 0);
    let mut no_live_capacity = ResourceRegistry::with_limits(0, 0);
    assert_eq!(
        no_live_capacity
            .admit_pending_operation(
                &machine,
                ResourceCarrier::ReconstructionRecord,
                ledger().durable_record()
            )
            .err(),
        Some(ResourceRegistryRefusal::LiveResourceLimitReached { limit: 0 })
    );
}

/// Shared pending capacity is released by machine settlement without reclaiming accounting facts.
#[test]
fn coordinator_pending_resource_limit_is_shared_and_settlement_fenced() {
    use gantry::runtime::{
        CanonicalTranscriptV1, ConcurrentTaskStateV1, CoordinatorResourceRefusal,
        ExecutionCoordinator, LogicalSessionRegistryV1, SessionCreationModeV1,
    };

    let (_, mut machine, _) = machine_with_declared_subject(Some(FIXTURE_DECLARATION));
    let execution = machine.execution_id();
    let tasks = ConcurrentTaskStateV1::new(execution, machine.task_id(), 1)
        .unwrap_or_else(|error| panic!("task state: {error:?}"));
    let session = ProtocolIdentity::from_fresh_material(IdentityKind::Session, [7; 32])
        .unwrap_or_else(|error| panic!("session identity: {error}"));
    let sessions = LogicalSessionRegistryV1::new(
        execution,
        session,
        SessionCreationModeV1::GantryRoot,
        CanonicalTranscriptV1::empty(),
    )
    .unwrap_or_else(|error| panic!("session registry: {error:?}"));
    let coordinator = ExecutionCoordinator::new_with_resource_limits(tasks, sessions, 2, 1)
        .unwrap_or_else(|error| panic!("coordinator: {error:?}"));
    let clone = coordinator.clone();
    coordinator
        .admit_resource(
            &machine,
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
        )
        .unwrap_or_else(|error| panic!("first admission: {error:?}"));
    let before = coordinator.snapshot();
    let (_, sibling, _) = machine_with_declared_subject(Some(SECOND_FIXTURE_DECLARATION));
    assert_eq!(
        clone.admit_resource(
            &sibling,
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record()
        ),
        Err(CoordinatorResourceRefusal::Registry(
            ResourceRegistryRefusal::PendingOperationLimitReached { limit: 1 }
        ))
    );
    assert_eq!(coordinator.snapshot(), before);
    let operation = machine
        .checkpoint()
        .pending_operation()
        .unwrap_or_else(|| panic!("pending operation exists"))
        .identity;
    assert!(
        machine
            .fail_operation(
                operation,
                gantry::portable::RuntimeErrorCategory::ExecutorFailure
            )
            .is_ok()
    );
    assert_eq!(
        coordinator.snapshot(),
        before,
        "lease closure is not accounting publication"
    );
    assert_eq!(
        clone.admit_resource(
            &sibling,
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record()
        ),
        Ok(())
    );
    let after = coordinator.snapshot();
    assert_eq!(after.publication(), before.publication() + 1);
    assert_eq!(after.resource_records().map(<[_]>::len), Some(2));
}

/// Accounting reconstruction does not fabricate process-local pending work or recover its policy.
#[test]
fn reconstruction_does_not_recover_pending_resource_operation_capacity() {
    let (_, machine, _) = machine_with_declared_subject(Some(FIXTURE_DECLARATION));
    let mut registry = ResourceRegistry::with_limits(1, 1);
    registry
        .admit_pending_operation(
            &machine,
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
        )
        .unwrap_or_else(|error| panic!("admission: {error:?}"));
    assert_eq!(registry.pending_operations(), 1);
    let records = registry.declared_records();
    let recovered = ResourceRegistry::reconstruct(Some(1), records.clone())
        .unwrap_or_else(|error| panic!("accounting reconstruction: {error:?}"));
    assert_eq!(recovered.declared_records(), records);
    assert_eq!(recovered.live_resources(), 1);
    assert_eq!(recovered.pending_limit(), None);
    assert_eq!(recovered.pending_operations(), 0);
}

/// Concurrent clone handles cannot publish two accounts for the same pending subject.
#[test]
fn coordinator_resource_admission_race_has_one_publication() {
    use gantry::runtime::CoordinatorResourceRefusal;

    let (_, machine, _) = machine_with_declared_subject(Some(FIXTURE_DECLARATION));
    let coordinator = resource_coordinator(machine.execution_id(), machine.task_id(), Some(2));
    let before = coordinator.snapshot();
    let barrier = std::sync::Barrier::new(2);
    let clone = coordinator.clone();
    let results = std::thread::scope(|scope| {
        let first = scope.spawn(|| {
            barrier.wait();
            coordinator.admit_resource(
                &machine,
                ResourceCarrier::ReconstructionRecord,
                ledger().durable_record(),
            )
        });
        let second = scope.spawn(|| {
            barrier.wait();
            clone.admit_resource(
                &machine,
                ResourceCarrier::ReconstructionRecord,
                ledger().durable_record(),
            )
        });
        [
            first
                .join()
                .unwrap_or_else(|_| panic!("first admission panicked")),
            second
                .join()
                .unwrap_or_else(|_| panic!("second admission panicked")),
        ]
    });
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| **result
                == Err(CoordinatorResourceRefusal::Registry(
                    ResourceRegistryRefusal::SecondAdmission
                )))
            .count(),
        1
    );
    let after = coordinator.snapshot();
    assert_eq!(after.publication(), before.publication() + 1);
    assert_eq!(after.resource_records().map(<[_]>::len), Some(1));
}

/// An operation whose Section 20 kind is not authenticated cannot be admitted as a live resource:
/// the admission boundary reads the authenticated fact rather than defaulting one, on every
/// account-construction path.
#[test]
fn an_unauthenticated_operation_kind_is_refused_at_resource_admission() {
    let (_program, _machine, subject) =
        machine_with_unauthenticated_subject(Some(FIXTURE_DECLARATION));
    let subject = subject.unwrap_or_else(|| panic!("the fixture operation declares an action"));
    assert_eq!(
        subject.operation_kind(),
        None,
        "the fixture leaves the Section 20 kind unauthenticated"
    );
    assert_eq!(
        AdmittedResource::admit(
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
            subject.clone(),
        ),
        Err(ResourceRegistryRefusal::UnauthenticatedOperationKind),
        "the account constructor refuses an unauthenticated subject"
    );
    let mut registry = ResourceRegistry::new();
    assert_eq!(
        registry.admit(
            subject.clone(),
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
        ),
        Err(ResourceRegistryRefusal::UnauthenticatedOperationKind),
        "no account may stand in for an unauthenticated Section 20 operation kind"
    );
    assert!(
        registry.account(&subject).is_none(),
        "a refused admission creates no account"
    );
}

#[test]
fn registry_admission_uses_the_machines_pending_resource_subject() {
    let (_program, machine, expected_subject) =
        machine_with_declared_subject(Some(FIXTURE_DECLARATION));
    let expected_subject =
        expected_subject.unwrap_or_else(|| panic!("the pending action has a resource subject"));
    let mut registry = ResourceRegistry::new();

    registry
        .admit_pending_operation(
            &machine,
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
        )
        .unwrap_or_else(|error| panic!("the pending action subject is admitted: {error:?}"));
    assert!(
        registry.account(&expected_subject).is_some(),
        "admission is bound to the machine-issued subject"
    );

    let (_program, machine_without_action, _) = machine_with_declared_subject(None);
    let registry_before_actionless_refusal = registry.declared_records();
    assert_eq!(
        registry.admit_pending_operation(
            &machine_without_action,
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
        ),
        Err(ResourceRegistryRefusal::NoPendingResourceSubject),
        "an operation without an action cannot present a resource subject"
    );
    assert_eq!(
        registry.declared_records(),
        registry_before_actionless_refusal,
        "an operation without an action leaves registry records unchanged"
    );

    let (_program, mut completed_machine, _) =
        machine_with_declared_subject(Some(FIXTURE_DECLARATION));
    let saved_subject = completed_machine
        .pending_resource_subject()
        .unwrap_or_else(|| panic!("pending action exposes its machine-issued subject"));
    let operation = completed_machine
        .checkpoint()
        .pending_operation()
        .unwrap_or_else(|| panic!("fixture operation is pending"))
        .identity;
    completed_machine
        .fail_operation(
            operation,
            gantry::portable::RuntimeErrorCategory::ExecutorFailure,
        )
        .unwrap_or_else(|error| panic!("fixture operation settles: {error:?}"));
    let registry_before_completed_refusal = registry.declared_records();
    assert_eq!(
        registry.admit_pending_operation(
            &completed_machine,
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
        ),
        Err(ResourceRegistryRefusal::NoPendingResourceSubject),
        "a machine without pending work cannot present a resource subject"
    );
    assert_eq!(
        registry.declared_records(),
        registry_before_completed_refusal,
        "completed work leaves registry records unchanged"
    );
    assert_eq!(
        registry.admit(
            saved_subject,
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
        ),
        Err(ResourceRegistryRefusal::NoPendingResourceSubject),
        "a cloned pending subject cannot bypass the machine's completed-operation refusal"
    );
    assert_eq!(
        registry.declared_records(),
        registry_before_completed_refusal,
        "a stale saved subject cannot publish a resource account"
    );

    let (cancellation_program, mut cancelled_machine, cancellation_subject) =
        machine_with_declared_subject(Some(FIXTURE_DECLARATION));
    let cancellation_subject = cancellation_subject
        .unwrap_or_else(|| panic!("the pending action exposes its cancellation subject"));
    let mut accepted_registry = ResourceRegistry::with_limits(1, 1);
    accepted_registry
        .admit_pending_operation(
            &cancelled_machine,
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
        )
        .unwrap_or_else(|error| panic!("accepted pending account: {error:?}"));
    assert!(
        cancelled_machine
            .cancel("resource admission test")
            .is_some()
    );
    let mut refused_registry = ResourceRegistry::new();
    assert_eq!(
        refused_registry
            .admit(
                cancellation_subject.clone(),
                ResourceCarrier::ReconstructionRecord,
                ledger().durable_record(),
            )
            .err(),
        Some(ResourceRegistryRefusal::CancellationRequested),
        "saved bindings cannot admit new accounts after cancellation request"
    );
    assert_eq!(
        AdmittedResource::admit(
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
            cancellation_subject.clone(),
        )
        .err(),
        Some(ResourceRegistryRefusal::CancellationRequested)
    );
    assert_eq!(
        refused_registry
            .admit_pending_operation(
                &cancelled_machine,
                ResourceCarrier::ReconstructionRecord,
                ledger().durable_record(),
            )
            .err(),
        Some(ResourceRegistryRefusal::CancellationRequested)
    );
    let checkpoint = MachineCheckpointV3::decode(
        &cancellation_program,
        &cancelled_machine.checkpoint().canonical_bytes(),
    )
    .unwrap_or_else(|error| panic!("cancelled checkpoint: {error:?}"));
    let budget = ExecutionBudget::recover_from_checkpoint(cancelled_machine.budget_checkpoint())
        .unwrap_or_else(|error| panic!("cancelled budget: {error:?}"));
    let recovered = Machine::recover_from_checkpoint(cancellation_program, checkpoint, budget)
        .unwrap_or_else(|error| panic!("cancelled recovery: {error:?}"));
    assert_eq!(
        refused_registry
            .admit_pending_operation(
                &recovered,
                ResourceCarrier::ReconstructionRecord,
                ledger().durable_record(),
            )
            .err(),
        Some(ResourceRegistryRefusal::CancellationRequested)
    );
    assert!(refused_registry.declared_records().is_empty());
    assert_eq!(
        accepted_registry.pending_operations(),
        1,
        "cancellation request does not settle already accepted work"
    );
    let before_attachment = accepted_registry.declared_records();
    let refusal =
        accepted_registry.attach_host_value(&cancellation_subject, OwnerGeneration::new(4), 17_u64);
    assert!(
        refusal.is_err(),
        "machine cancellation closes physical acquisition too"
    );
    let (error, returned) = *refusal
        .err()
        .unwrap_or_else(|| panic!("attachment must refuse"));
    assert_eq!(
        error,
        gantry::runtime::HostResourceError::CancellationRequested
    );
    assert_eq!(returned, 17);
    assert_eq!(accepted_registry.declared_records(), before_attachment);
    assert_eq!(accepted_registry.pending_operations(), 1);
    let cancelled_operation = cancelled_machine
        .checkpoint()
        .pending_operation()
        .unwrap_or_else(|| panic!("the cancelled operation remains pending until settlement"))
        .identity;
    assert_eq!(
        cancelled_machine.complete_operation(cancelled_operation, LogicalValue::unit()),
        Err(OperationCompletionError::Cancelled)
    );
    assert_eq!(
        cancelled_machine.pending_resource_subject(),
        Some(cancellation_subject.clone()),
        "a refused late completion leaves the cancellation settlement pending"
    );
    assert!(matches!(
        cancelled_machine.step(),
        MachineStep::Transition(MachineLabel::TaskSettled(MachineOutcome::Cancelled(_)))
    ));
    assert!(cancelled_machine.pending_resource_subject().is_none());
    let mut cancellation_registry = ResourceRegistry::new();
    assert_eq!(accepted_registry.pending_operations(), 0);
    assert_eq!(
        cancellation_registry.admit(
            cancellation_subject.clone(),
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
        ),
        Err(ResourceRegistryRefusal::NoPendingResourceSubject),
        "a saved subject cannot admit after cancellation consumes the pending operation"
    );
    assert!(
        cancellation_registry
            .account(&cancellation_subject)
            .is_none()
    );

    let (_program, mut rejected_machine, rejected_subject) =
        machine_with_declared_subject(Some(FIXTURE_DECLARATION));
    let rejected_subject = rejected_subject
        .unwrap_or_else(|| panic!("the pending action exposes its rejected-result subject"));
    let rejected_operation = rejected_machine
        .checkpoint()
        .pending_operation()
        .unwrap_or_else(|| panic!("the action operation is pending"))
        .identity;
    assert_eq!(
        rejected_machine.complete_operation(rejected_operation, LogicalValue::boolean(true)),
        Err(OperationCompletionError::LiveResourceValueRefused)
    );
    assert_eq!(
        rejected_machine.pending_resource_subject(),
        Some(rejected_subject.clone()),
        "a rejected completion leaves the pending resource subject live"
    );
    let mut rejected_registry = ResourceRegistry::new();
    rejected_registry
        .admit(
            rejected_subject.clone(),
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
        )
        .unwrap_or_else(|error| panic!("rejected completion preserves admission: {error:?}"));
    assert!(rejected_registry.account(&rejected_subject).is_some());

    let (_program, mut failed_machine, failure_subject) =
        machine_with_declared_subject(Some(FIXTURE_DECLARATION));
    let failure_subject =
        failure_subject.unwrap_or_else(|| panic!("the pending action exposes its failure subject"));
    let failure_operation = failed_machine
        .checkpoint()
        .pending_operation()
        .unwrap_or_else(|| panic!("the action operation is pending"))
        .identity;
    assert!(matches!(
        failed_machine.fail_operation(
            failure_operation,
            gantry::portable::RuntimeErrorCategory::ExecutorFailure,
        ),
        Ok(MachineLabel::Failure(_))
    ));
    assert!(failed_machine.pending_resource_subject().is_none());
    let mut failure_registry = ResourceRegistry::new();
    assert_eq!(
        failure_registry.admit(
            failure_subject.clone(),
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
        ),
        Err(ResourceRegistryRefusal::NoPendingResourceSubject),
        "a saved subject cannot admit after failure consumes the pending operation"
    );
    assert!(failure_registry.account(&failure_subject).is_none());

    let (_program, unauthenticated_machine, _) =
        machine_with_unauthenticated_subject(Some(FIXTURE_DECLARATION));
    let mut unauthenticated_registry = ResourceRegistry::new();
    let registry_before_unauthenticated_refusal = unauthenticated_registry.declared_records();
    assert_eq!(
        unauthenticated_registry.admit_pending_operation(
            &unauthenticated_machine,
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
        ),
        Err(ResourceRegistryRefusal::UnauthenticatedOperationKind),
        "the wrapper preserves the existing unauthenticated-kind refusal"
    );
    assert_eq!(
        unauthenticated_registry.declared_records(),
        registry_before_unauthenticated_refusal,
        "an unauthenticated operation leaves registry records unchanged"
    );
}

/// Terminal accounting consumes pending-work capacity, but never a live-account place.
#[test]
fn terminal_account_admission_does_not_consume_live_capacity() {
    let (_, machine, subject) = machine_with_declared_subject(Some(FIXTURE_DECLARATION));
    let subject = subject.unwrap_or_else(|| panic!("subject exists"));
    let mut registry = ResourceRegistry::with_limits(0, 1);
    assert!(
        registry
            .admit_pending_operation(
                &machine,
                ResourceCarrier::ReconstructionRecord,
                settled_record(),
            )
            .is_ok()
    );
    assert_eq!(registry.live_resources(), 0);
    assert_eq!(registry.pending_operations(), 1);
    assert_eq!(
        registry
            .account(&subject)
            .map(AdmittedResource::durable_record),
        Some(settled_record())
    );
    let before = registry.declared_records();
    assert_eq!(
        registry.admit(
            subject,
            ResourceCarrier::ReconstructionRecord,
            settled_record()
        ),
        Err(ResourceRegistryRefusal::SecondAdmission)
    );
    let (_, sibling, _) = machine_with_declared_subject(Some(SECOND_FIXTURE_DECLARATION));
    assert_eq!(
        registry.admit_pending_operation(
            &sibling,
            ResourceCarrier::ReconstructionRecord,
            settled_record(),
        ),
        Err(ResourceRegistryRefusal::PendingOperationLimitReached { limit: 1 })
    );
    assert_eq!(registry.declared_records(), before);
    let mut physical = ResourceRegistry::with_limits(0, 1);
    let sibling_subject = sibling
        .pending_resource_subject()
        .unwrap_or_else(|| panic!("sibling subject exists"));
    let (error, value) = *physical
        .admit_host_value(
            sibling_subject,
            ResourceCarrier::ReconstructionRecord,
            settled_record(),
            17_u64,
        )
        .err()
        .unwrap_or_else(|| panic!("terminal accounting cannot acquire a host value"));
    assert_eq!(
        error,
        ResourceRegistryRefusal::PhysicalAdmission(gantry::runtime::HostResourceError::Model(
            ResourceError::LifetimeDoesNotAdmitCharge {
                state: ResourceLifetimeState::Poisoned,
            }
        ))
    );
    assert_eq!(value, 17);
    assert!(physical.declared_records().is_empty());
    assert_eq!(physical.pending_operations(), 0);
}

/// Settled records remain bounded independently of live and pending accounting.
#[test]
fn retained_resource_limit_refuses_terminal_growth_without_mutation() {
    let first = active_subject();
    let second = declared_subject(SECOND_FIXTURE_DECLARATION);
    let mut registry = ResourceRegistry::with_accounting_limits(0, 2, 1);
    assert_eq!(registry.retained_limit(), Some(1));
    assert!(
        registry
            .admit(
                first.clone(),
                ResourceCarrier::ReconstructionRecord,
                settled_record()
            )
            .is_ok()
    );
    let before = registry.declared_records();
    assert_eq!(registry.retained_resources(), 1);
    assert_eq!(registry.live_resources(), 0);
    assert_eq!(
        registry.admit(
            second.clone(),
            ResourceCarrier::ReconstructionRecord,
            settled_record()
        ),
        Err(ResourceRegistryRefusal::RetainedResourceLimitReached { limit: 1 })
    );
    assert_eq!(registry.declared_records(), before);
    assert_eq!(registry.pending_operations(), 1);
    assert_eq!(
        registry.admit(
            first,
            ResourceCarrier::ReconstructionRecord,
            settled_record()
        ),
        Err(ResourceRegistryRefusal::SecondAdmission)
    );
    let (error, value) = *registry
        .admit_host_value(
            second,
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
            17_u64,
        )
        .err()
        .unwrap_or_else(|| panic!("full retained quota refuses"));
    assert_eq!(
        error,
        ResourceRegistryRefusal::LiveResourceLimitReached { limit: 0 }
    );
    assert_eq!(value, 17);
    assert_eq!(registry.declared_records(), before);
    let mut denied = ResourceRegistry::with_accounting_limits(1, 1, 0);
    assert_eq!(
        denied.admit(
            active_subject(),
            ResourceCarrier::ReconstructionRecord,
            settled_record()
        ),
        Err(ResourceRegistryRefusal::RetainedResourceLimitReached { limit: 0 })
    );
    assert!(denied.declared_records().is_empty());
    assert_eq!(denied.pending_operations(), 0);
    let (error, value) = *denied
        .admit_host_value(
            active_subject(),
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
            19_u64,
        )
        .err()
        .unwrap_or_else(|| panic!("retained quota must refuse physical acquisition"));
    assert_eq!(
        error,
        ResourceRegistryRefusal::RetainedResourceLimitReached { limit: 0 }
    );
    assert_eq!(value, 19);
    assert!(denied.declared_records().is_empty());
    assert_eq!(denied.pending_operations(), 0);
}

/// Coordinator clones share the retained ceiling without publishing a refused admission.
#[test]
fn coordinator_retained_resource_limit_preserves_refusal_publication() {
    use gantry::runtime::{CoordinatorResourceRefusal, ExecutionCoordinator};
    let (_, machine, _) = machine_with_declared_subject(Some(FIXTURE_DECLARATION));
    let (tasks, sessions) = resource_recovery_inputs(machine.execution_id(), machine.task_id());
    let coordinator = ExecutionCoordinator::new_with_budget_and_accounting_limits(
        tasks,
        sessions,
        machine.execution_budget(),
        1,
        2,
        1,
    )
    .unwrap_or_else(|error| panic!("bounded coordinator: {error:?}"));
    assert!(
        coordinator
            .admit_resource(
                &machine,
                ResourceCarrier::ReconstructionRecord,
                settled_record()
            )
            .is_ok()
    );
    let before = coordinator.snapshot();
    let (_, sibling, _) = machine_with_declared_subject(Some(SECOND_FIXTURE_DECLARATION));
    assert_eq!(
        coordinator.clone().admit_resource(
            &sibling,
            ResourceCarrier::ReconstructionRecord,
            settled_record()
        ),
        Err(CoordinatorResourceRefusal::Registry(
            ResourceRegistryRefusal::RetainedResourceLimitReached { limit: 1 }
        ))
    );
    assert_eq!(coordinator.snapshot(), before);
    assert!(coordinator.has_pending_resource_operations());
    assert!(!coordinator.has_unsettled_resource_accounts());
    assert_eq!(
        coordinator
            .capture_checkpoint(&machine, &std::collections::BTreeMap::new())
            .err(),
        Some(gantry::runtime::ConcurrentDurableCheckpointError::ResourceStateUnsupported)
    );
}

/// A declared live-resource limit is enforced at admission and released semantically: settling an
/// account frees its place while the retained account stays queryable, so no retirement, deletion,
/// or physical reclamation is needed to reuse the quota.
#[test]
fn live_resource_quota_is_enforced_at_admission_and_released_by_settlement() {
    let (_program, _machine, first) = machine_with_declared_subject(Some(FIXTURE_DECLARATION));
    let first = first.unwrap_or_else(|| panic!("the fixture operation declares an action"));
    let (_program, _machine, second) =
        machine_with_declared_subject(Some(SECOND_FIXTURE_DECLARATION));
    let second =
        second.unwrap_or_else(|| panic!("the second fixture operation declares an action"));
    assert_ne!(
        first.operation(),
        second.operation(),
        "the two fixtures declare distinct operations"
    );

    let mut registry = ResourceRegistry::with_live_limit(1);
    assert_eq!(registry.live_limit(), Some(1));
    registry
        .admit(
            first.clone(),
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
        )
        .unwrap_or_else(|error| panic!("the first live resource is admitted: {error:?}"));
    assert_eq!(registry.live_resources(), 1);
    assert_eq!(
        registry.admit(
            second.clone(),
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
        ),
        Err(ResourceRegistryRefusal::LiveResourceLimitReached { limit: 1 }),
        "the declared live-resource limit refuses the next admission"
    );
    assert_eq!(
        registry.admit(
            first.clone(),
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
        ),
        Err(ResourceRegistryRefusal::SecondAdmission),
        "a full registry still refuses a duplicate subject with its own refusal"
    );
    let (_program, _machine, unauthenticated) =
        machine_with_unauthenticated_subject(Some(SECOND_FIXTURE_DECLARATION));
    let unauthenticated = unauthenticated
        .unwrap_or_else(|| panic!("the second fixture operation declares an action"));
    assert_eq!(
        registry.admit(
            unauthenticated,
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
        ),
        Err(ResourceRegistryRefusal::UnauthenticatedOperationKind),
        "a full registry still refuses an unauthenticated operation with its own refusal"
    );

    let matching = failure_settlement_in(
        FIXTURE_WORKFLOW,
        FIXTURE_DECLARATION,
        vec![FIXTURE_SITE],
        0,
        FailureClass::ResourceFailure,
    );
    assert_eq!(
        registry.settle_from_post_failure(&matching, 21, &first),
        Ok(ResourceLifetimeState::Poisoned),
        "the account settles into a terminal lifetime"
    );
    assert_eq!(
        registry.live_resources(),
        0,
        "settlement releases the live place before any retirement"
    );
    assert!(
        registry.account(&first).is_some(),
        "the retained account stays queryable after settlement"
    );
    registry
        .admit(
            second,
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
        )
        .unwrap_or_else(|error| {
            panic!("the released place admits the next live resource: {error:?}")
        });
    assert_eq!(registry.live_resources(), 1);
}

/// A settled account keeps its place released through retirement and deletion: no retention state
/// returns it to the live count, so a record the registry already released never blocks a later
/// admission.
#[test]
fn retirement_and_deletion_never_reclaim_a_released_live_place() {
    let subject = active_subject();
    let mut registry = ResourceRegistry::with_accounting_limits(1, 2, 1);
    registry
        .admit(
            subject.clone(),
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
        )
        .unwrap_or_else(|error| {
            panic!("the declared reconstruction record is admitted: {error:?}")
        });
    assert_eq!(registry.live_resources(), 1);
    assert_eq!(
        registry.begin_finish(&subject, OwnerGeneration::new(4)),
        Ok(ResourceLifetimeState::Finishing)
    );
    assert_eq!(
        registry.live_resources(),
        1,
        "a finishing lifetime is still live"
    );
    assert_eq!(
        registry.complete_finalization(&subject, OwnerGeneration::new(4), 20),
        Ok(ResourceLifetimeState::Finished)
    );
    assert_eq!(
        registry.live_resources(),
        0,
        "finishing the lifetime releases the place"
    );
    assert_eq!(
        registry.reap_deleted(),
        0,
        "a settled account that is still retained is not reaped"
    );
    assert!(registry.account(&subject).is_some());

    let fence = RetentionFence::new(2, 10).unwrap_or_else(|_| unreachable!("bounded fence"));
    for root in ROOTS {
        assert!(
            registry
                .close_liveness_root(&subject, OwnerGeneration::new(4), *root)
                .is_ok(),
            "the current owner closes one declared liveness root"
        );
    }
    assert!(
        registry
            .retire(
                &subject,
                fence,
                OwnerGeneration::new(4),
                OwnerGeneration::new(5),
                35
            )
            .is_ok()
    );
    assert_eq!(
        registry
            .account(&subject)
            .map(|account| account.ledger().lifetime()),
        Some(ResourceLifetimeState::Retired)
    );
    assert_eq!(
        registry.live_resources(),
        0,
        "retirement never reclaims the released place"
    );
    assert_eq!(
        registry.delete(&subject, OwnerGeneration::new(4)),
        Ok(ResourceLifetimeState::Deleted)
    );
    assert_eq!(
        registry
            .account(&subject)
            .map(|account| account.ledger().lifetime()),
        Some(ResourceLifetimeState::Deleted)
    );
    assert_eq!(
        registry.live_resources(),
        0,
        "deletion never reclaims the released place"
    );
    assert!(
        registry.account(&subject).is_some(),
        "a deleted account stays registry-held until it is reaped"
    );
    let next = declared_subject(SECOND_FIXTURE_DECLARATION);
    assert_eq!(registry.retained_resources(), 1);
    assert_eq!(
        registry.admit(
            next.clone(),
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record()
        ),
        Err(ResourceRegistryRefusal::RetainedResourceLimitReached { limit: 1 })
    );
    assert_eq!(
        registry.reap_deleted(),
        1,
        "reaping reclaims the deleted account's record"
    );
    assert!(registry.account(&subject).is_none());
    assert_eq!(registry.live_resources(), 0);
    assert_eq!(
        registry.reap_deleted(),
        0,
        "reaping is idempotent once the deleted account is gone"
    );
    assert_eq!(registry.retained_resources(), 0);
    assert!(
        registry
            .admit(
                next,
                ResourceCarrier::ReconstructionRecord,
                ledger().durable_record()
            )
            .is_ok()
    );
    assert_eq!(registry.retained_resources(), 1);
}

fn machine_with_declared_subject(
    action_path: Option<&str>,
) -> (Arc<MachineProgram>, Machine, Option<ResourceSubjectBinding>) {
    machine_with_subject(action_path, Some(OperationKind::LiveResource))
}

/// Builds the same fixture with the operation's Section 20 kind left unauthenticated, so its
/// subject is one no resource account may be admitted for.
fn machine_with_unauthenticated_subject(
    action_path: Option<&str>,
) -> (Arc<MachineProgram>, Machine, Option<ResourceSubjectBinding>) {
    machine_with_subject(action_path, None)
}

/// Builds the fixture machine, drives it to the prepared operation, and takes the subject the
/// machine itself issues for that operation.
fn machine_with_subject(
    action_path: Option<&str>,
    section20_kind: Option<OperationKind>,
) -> (Arc<MachineProgram>, Machine, Option<ResourceSubjectBinding>) {
    let workflow = CanonicalPath::new(FIXTURE_WORKFLOW)
        .unwrap_or_else(|_| unreachable!("fixture workflow is canonical"));
    let site = StructuralPosition::new(vec![FIXTURE_SITE])
        .unwrap_or_else(|_| unreachable!("fixture site is canonical"));
    let program = MachineProgram::new(vec![Workflow {
        path: workflow.clone(),
        parameters: Vec::new(),
        result: TypeDescriptor::UNIT,
        effects: EffectSet::default(),
        instructions: vec![
            Instruction {
                site,
                ty: TypeDescriptor::UNIT,
                kind: InstructionKind::OperationCall {
                    operation: operation_metadata(action_path, section20_kind),
                    operands: 0,
                },
            },
            Instruction {
                site: StructuralPosition::new(vec![FIXTURE_SITE + 1])
                    .unwrap_or_else(|_| unreachable!("fixture return site is canonical")),
                ty: TypeDescriptor::UNIT,
                kind: InstructionKind::Return,
            },
        ],
    }])
    .unwrap_or_else(|error| panic!("fixture machine program is valid: {error:?}"));
    let execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [9; 32])
        .unwrap_or_else(|error| panic!("fixture execution identity is valid: {error}"));
    let limits = MachineLimits::new(8, 1, 1, 1, 8, DEFAULT_VALUE_LIMITS)
        .unwrap_or_else(|| panic!("fixture machine limits are positive"));
    let program = Arc::new(program);
    let mut machine = Machine::new(
        Arc::clone(&program),
        &workflow,
        Vec::new(),
        execution,
        limits,
    )
    .unwrap_or_else(|error| panic!("fixture machine construction succeeds: {error:?}"));
    match machine.step() {
        MachineStep::Transition(MachineLabel::OperationPrepared(_)) => {}
        other => panic!("unexpected machine step: {other:?}"),
    }
    let subject = machine.pending_resource_subject();
    (program, machine, subject)
}

/// Returns the machine-issued subject of the fixture declared operation.
fn active_subject() -> ResourceSubjectBinding {
    declared_subject(FIXTURE_DECLARATION)
}

/// Portable operation identity does not authorize physical access across executions.
#[test]
fn registry_physical_routes_refuse_a_foreign_execution_with_matching_static_identity() {
    use gantry::runtime::HostResourceError;
    let (program, machine, subject) = machine_with_declared_subject(Some(FIXTURE_DECLARATION));
    let subject = subject.unwrap_or_else(|| panic!("local subject exists"));
    let execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [10; 32])
        .unwrap_or_else(|error| panic!("foreign execution: {error}"));
    let mut foreign = Machine::new(
        Arc::clone(&program),
        &CanonicalPath::new(FIXTURE_WORKFLOW).unwrap_or_else(|error| panic!("workflow: {error}")),
        Vec::new(),
        execution,
        MachineLimits::new(8, 1, 1, 1, 8, DEFAULT_VALUE_LIMITS)
            .unwrap_or_else(|| panic!("positive limits")),
    )
    .unwrap_or_else(|error| panic!("foreign machine: {error:?}"));
    assert!(matches!(
        foreign.step(),
        MachineStep::Transition(MachineLabel::OperationPrepared(_))
    ));
    let foreign = foreign
        .pending_resource_subject()
        .unwrap_or_else(|| panic!("foreign subject"));
    assert_eq!(foreign.operation(), subject.operation());
    assert_eq!(foreign.generation(), subject.generation());
    assert_eq!(subject.execution_id(), machine.execution_id());
    assert_eq!(subject.task_id(), machine.task_id());
    assert_ne!(foreign.execution_id(), subject.execution_id());
    let task_key = format!(
        "{{\"execution\":\"{}\",\"path\":[\"foreign-task\"]}}",
        machine.execution_id()
    );
    let task = ProtocolIdentity::derive(IdentityKind::Task, task_key.as_bytes())
        .unwrap_or_else(|error| panic!("foreign task: {error}"));
    let mut other_task = Machine::new_concurrent_task_with_context(
        Arc::clone(&program),
        &CanonicalPath::new(FIXTURE_WORKFLOW).unwrap_or_else(|error| panic!("workflow: {error}")),
        Vec::new(),
        machine.execution_id(),
        task,
        Arc::from([Arc::from("foreign-task")]),
        MachineLimits::new(8, 1, 1, 1, 8, DEFAULT_VALUE_LIMITS)
            .unwrap_or_else(|| panic!("positive limits")),
        ExecutionBudget::new(
            machine.execution_id(),
            MachineLimits::new(8, 1, 1, 1, 8, DEFAULT_VALUE_LIMITS)
                .unwrap_or_else(|| panic!("positive fixture limits")),
        ),
        None,
        None,
    )
    .unwrap_or_else(|error| panic!("other task: {error:?}"));
    assert!(matches!(
        other_task.step(),
        MachineStep::Transition(MachineLabel::OperationPrepared(_))
    ));
    let other_task = other_task
        .pending_resource_subject()
        .unwrap_or_else(|| panic!("task subject"));
    assert_eq!(other_task.operation(), subject.operation());
    assert_eq!(other_task.generation(), subject.generation());
    assert_eq!(other_task.execution_id(), subject.execution_id());
    assert_ne!(other_task.task_id(), subject.task_id());
    let checkpoint = MachineCheckpointV3::decode(&program, &machine.checkpoint().canonical_bytes())
        .unwrap_or_else(|error| panic!("checkpoint: {error:?}"));
    let budget = ExecutionBudget::recover_from_checkpoint(machine.budget_checkpoint())
        .unwrap_or_else(|error| panic!("budget: {error:?}"));
    let recovered = Machine::recover_from_checkpoint(program, checkpoint, budget)
        .unwrap_or_else(|error| panic!("recovery: {error:?}"));
    assert_eq!(recovered.pending_resource_subject(), Some(subject.clone()));
    let mut registry = ResourceRegistry::new();
    registry
        .admit_pending_operation(
            &machine,
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
        )
        .unwrap_or_else(|error| panic!("local admission: {error:?}"));
    let before = registry.declared_records();
    let failure = failure_settlement_in(
        FIXTURE_WORKFLOW,
        FIXTURE_DECLARATION,
        vec![FIXTURE_SITE],
        0,
        FailureClass::ResourceFailure,
    );
    let adapter_failure = failure_settlement_in(
        FIXTURE_WORKFLOW,
        FIXTURE_DECLARATION,
        vec![FIXTURE_SITE],
        0,
        FailureClass::AdapterFailure,
    );
    let mut live = transport_live(FIXTURE_DECLARATION, 0, 4, false);
    let settlement = OperationSettlement::new(
        live.operation(),
        live.generation(),
        live.owner(),
        ExternalOutcome::Accepted,
        ProgressObservation::CommittedProgress,
        30,
    )
    .unwrap_or_else(|error| panic!("settlement: {error:?}"));
    live.settle(&settlement)
        .unwrap_or_else(|error| panic!("accepted settlement: {error:?}"));
    let mut failed_live = transport_live(FIXTURE_DECLARATION, 0, 4, false);
    assert!(
        failed_live
            .settle_failure(FailureClass::AdapterFailure)
            .is_ok()
    );
    let mismatched = declared_subject(SECOND_FIXTURE_DECLARATION);
    for (requested, expected) in [
        (&foreign, ResourceRegistryRefusal::ForeignSubject),
        (&other_task, ResourceRegistryRefusal::ForeignSubject),
        (
            &mismatched,
            ResourceRegistryRefusal::EvidenceSubjectMismatch,
        ),
    ] {
        assert_eq!(
            registry.settle_from_post_failure(&failure, 31, requested),
            Err(expected.clone())
        );
        assert_eq!(
            registry.project_operation_state(&live, requested),
            Err(expected.clone())
        );
        assert_eq!(
            registry.project_failure_state(&failed_live, requested),
            Err(expected.clone())
        );
        assert_eq!(
            registry.poison_adapter_from_post_failure(
                &adapter_failure,
                OwnerGeneration::new(4),
                PoisonReason::InvariantFailure,
                requested
            ),
            Err(expected)
        );
        assert_eq!(registry.declared_records(), before);
        assert_eq!(registry.adapter_instance(&subject), None);
    }
    let refusal = registry.attach_host_value(&foreign, OwnerGeneration::new(4), 17_u64);
    for requested in [&foreign, &other_task] {
        assert_eq!(
            registry.advance_owner(requested, OwnerGeneration::new(4), OwnerGeneration::new(5)),
            Err(ResourceRegistryRefusal::ForeignSubject)
        );
        assert_eq!(registry.declared_records(), before);
    }
    assert_eq!(
        registry.begin_finish(&foreign, OwnerGeneration::new(4)),
        Err(ResourceRegistryRefusal::ForeignSubject)
    );
    assert_eq!(registry.declared_records(), before);
    assert_eq!(
        registry.settle_from_emergency_cleanup(&foreign, emergency_cleanup()),
        Err(ResourceRegistryRefusal::ForeignSubject)
    );
    assert_eq!(registry.declared_records(), before);
    let cohort =
        registry.settle_cohort_from_emergency_cleanup(vec![(foreign.clone(), emergency_cleanup())]);
    assert!(cohort.settled().is_empty());
    assert_eq!(
        cohort.refusal(),
        Some((&foreign, &ResourceRegistryRefusal::ForeignSubject))
    );
    for requested in [&foreign, &other_task] {
        let owner = OwnerGeneration::new(4);
        let fence =
            RetentionFence::new(2, 10).unwrap_or_else(|error| panic!("retention fence: {error:?}"));
        for result in [
            registry.charge(requested, owner, ResourceAction::Update, &[]),
            registry.renew(requested, owner, QuotaOwner::Owner, QuotaFamily::Bytes, 1),
            registry
                .complete_finalization(requested, owner, 31)
                .map(|_| ()),
            registry.close_liveness_root(requested, owner, LivenessRoot::Owner),
            registry.retire(requested, fence, owner, OwnerGeneration::new(5), 35),
            registry.delete(requested, owner).map(|_| ()),
            registry
                .settle_containment(
                    requested,
                    owner,
                    Completion::observed(ExternalOutcome::Accepted, EffectState::NotStarted),
                )
                .map(|_| ()),
            registry.bind_adapter_instance(
                requested,
                owner,
                adapter_instance("foreign_binding", 4, 0),
            ),
            registry
                .poison_adapter_instance(requested, owner, PoisonReason::InvariantFailure)
                .map(|_| ()),
        ] {
            assert_eq!(result, Err(ResourceRegistryRefusal::ForeignSubject));
        }
    }
    assert_eq!(registry.declared_records(), before);
    assert!(
        refusal.is_err(),
        "portable identity cannot substitute for execution ownership"
    );
    let (error, returned) = *refusal
        .err()
        .unwrap_or_else(|| panic!("foreign attachment refuses"));
    assert_eq!(error, HostResourceError::ForeignSubject);
    assert_eq!(returned, 17);
    assert_eq!(registry.declared_records(), before);
    let (error, returned) = *registry
        .attach_host_value(&other_task, OwnerGeneration::new(4), 18_u64)
        .err()
        .unwrap_or_else(|| panic!("foreign task refuses"));
    assert_eq!(error, HostResourceError::ForeignSubject);
    assert_eq!(returned, 18);
    assert_eq!(registry.declared_records(), before);
    registry
        .attach_host_value(&subject, OwnerGeneration::new(4), 7_u64)
        .unwrap_or_else(|_| panic!("local attachment"));
    let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let captured = TransportValue {
        drops: Arc::clone(&drops),
        panic_on_drop: true,
        value: 1,
    };
    let called = std::cell::Cell::new(false);
    assert!(matches!(
        registry.invoke_host_value::<u64, ()>(&foreign, OwnerGeneration::new(4), |_| {
            called.set(true);
            drop(captured);
            Ok(())
        }),
        Err(HostResourceError::Boundary(_))
    ));
    assert!(!called.get());
    assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(registry.declared_records(), before);
    assert_eq!(
        registry
            .invoke_host_value::<u64, u64>(&subject, OwnerGeneration::new(4), |value| Ok(*value)),
        Ok(7),
        "foreign callback destruction cannot poison local transport"
    );
    assert_eq!(
        registry.invoke_host_value::<u64, ()>(&foreign, OwnerGeneration::new(4), |_| panic!(
            "foreign callback must not run"
        )),
        Err(HostResourceError::ForeignSubject)
    );
    registry
        .begin_finish(&subject, OwnerGeneration::new(4))
        .unwrap_or_else(|error| panic!("finish: {error:?}"));
    assert_eq!(
        registry.dispose_host_value(&foreign, OwnerGeneration::new(4)),
        Err(HostResourceError::ForeignSubject)
    );
    assert!(!registry.has_host_value(&foreign));
    assert!(registry.has_host_value(&subject));
    assert_eq!(
        registry.dispose_host_value(&subject, OwnerGeneration::new(4)),
        Ok(())
    );
    assert!(
        registry
            .admit(
                other_task.clone(),
                ResourceCarrier::ReconstructionRecord,
                ledger().durable_record()
            )
            .is_ok(),
        "sibling runtime ownership must not collide on equal portable identities"
    );
    assert_eq!(registry.live_resources(), 2);
    registry
        .attach_host_value(&other_task, OwnerGeneration::new(4), 19_u64)
        .unwrap_or_else(|_| panic!("sibling physical ownership"));
    assert_eq!(
        registry.invoke_host_value::<u64, u64>(&other_task, OwnerGeneration::new(4), |value| Ok(
            *value
        )),
        Ok(19)
    );
    assert!(!registry.has_host_value(&subject));
    let reconstructed = ResourceRegistry::reconstruct(None, registry.declared_records())
        .unwrap_or_else(|error| panic!("sibling accounting recovery: {error:?}"));
    assert_eq!(reconstructed.live_resources(), 2);
    assert_eq!(
        reconstructed.declared_records(),
        registry.declared_records()
    );
    let local_before = registry
        .account(&subject)
        .unwrap_or_else(|| panic!("local account retained"))
        .durable_record();
    assert_eq!(
        registry.charge(
            &other_task,
            OwnerGeneration::new(4),
            ResourceAction::Update,
            &[Charge {
                owner: QuotaOwner::Owner,
                family: QuotaFamily::Bytes,
                amount: 1
            }]
        ),
        Ok(())
    );
    assert_eq!(
        registry.project_operation_state(&live, &other_task),
        Ok(ResourceState::Consumed)
    );
    assert_eq!(
        registry
            .account(&subject)
            .unwrap_or_else(|| panic!("local account retained"))
            .durable_record(),
        local_before,
        "sibling charging and evidence projection leave local accounting unchanged"
    );
    let mut limited = ResourceRegistry::with_live_limit(1);
    limited
        .admit(
            subject.clone(),
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
        )
        .unwrap_or_else(|error| panic!("first limited admission: {error:?}"));
    assert_eq!(
        limited
            .admit(
                other_task.clone(),
                ResourceCarrier::ReconstructionRecord,
                ledger().durable_record()
            )
            .err(),
        Some(ResourceRegistryRefusal::LiveResourceLimitReached { limit: 1 })
    );
    let sweep = registry.settle_cohort_from_emergency_cleanup(vec![
        (other_task.clone(), emergency_cleanup()),
        (subject.clone(), emergency_cleanup()),
        (other_task.clone(), emergency_cleanup()),
    ]);
    assert!(sweep.is_complete());
    assert_eq!(
        sweep.settled().len(),
        2,
        "portable aliases are separate cohort members"
    );
    assert_eq!(registry.live_resources(), 0);
    assert_eq!(
        registry.dispose_host_value(&other_task, OwnerGeneration::new(4)),
        Ok(())
    );
}

/// Returns the machine-issued subject of one declared fixture operation.
fn declared_subject(declaration: &str) -> ResourceSubjectBinding {
    let (_program, _machine, subject) = machine_with_declared_subject(Some(declaration));
    subject.unwrap_or_else(|| panic!("the fixture operation declares an action"))
}

/// Returns the machine-issued subject of one fixture operation whose Section 20 kind is left
/// unauthenticated, so no account and no reconstruction may be created for it.
fn unauthenticated_fixture_subject(declaration: &str) -> ResourceSubjectBinding {
    let (_program, _machine, subject) = machine_with_unauthenticated_subject(Some(declaration));
    subject.unwrap_or_else(|| panic!("the fixture operation declares an action"))
}

/// Presents one declared reconstruction record under the fixture owner generation the record itself
/// names, which is the generation a matching recovery pass holds.
fn presented(
    subject: ResourceSubjectBinding,
    carrier: ResourceCarrier,
    record: DurableResourceRecord,
) -> RecoveredResourceRecord {
    RecoveredResourceRecord::new(subject, carrier, OwnerGeneration::new(4), record)
}

/// Returns one declared reconstruction record whose lifetime has already settled, so it holds no
/// live place while every declared fact remains.
fn settled_record() -> DurableResourceRecord {
    let mut ledger = ResourceLedger::reconstruct(ledger().durable_record());
    let settlement = failure_settlement_in(
        FIXTURE_WORKFLOW,
        FIXTURE_DECLARATION,
        vec![FIXTURE_SITE],
        0,
        FailureClass::ResourceFailure,
    );
    let witness = PoisonWitness::from_post_failure(&settlement, 21)
        .unwrap_or_else(|error| panic!("the fixture settlement poisons the record: {error:?}"));
    ledger
        .poison(witness)
        .unwrap_or_else(|error| panic!("the fixture record is poisoned: {error:?}"));
    ledger.durable_record()
}

/// Issues one model settlement for one containing workflow, declaration, site, and generation.
fn failure_settlement_in(
    workflow: &str,
    declaration: &str,
    position: Vec<u64>,
    generation: u64,
    failure: FailureClass,
) -> PostFailureSettlement {
    let workflow = CanonicalPath::new(workflow)
        .unwrap_or_else(|_| unreachable!("fixture workflow is canonical"));
    let path = CanonicalPath::new(declaration)
        .unwrap_or_else(|_| unreachable!("fixture declaration is canonical"));
    let position = StructuralPosition::new(position)
        .unwrap_or_else(|_| unreachable!("fixture position is canonical"));
    let site = StaticSiteId::new(workflow, position);
    let operation = OperationAbi::new(
        OperationKind::LiveResource,
        &path,
        &site,
        generation,
        RecoveryClass::Idempotent,
        ReceiverOwnership::RetainedByCaller,
    )
    .unwrap_or_else(|_| unreachable!("fixture operation is admissible"));
    let mut live = operation
        .open_live(
            OwnerGeneration::new(4),
            OperationAbi::observation_allowance(
                1,
                DisclosureCharge::new(1).unwrap_or_else(|| unreachable!("nonzero charge")),
            ),
        )
        .unwrap_or_else(|error| panic!("fixture live resource: {error:?}"));
    live.settle_failure(failure)
        .unwrap_or_else(|error| panic!("fixture failure evidence: {error:?}"))
}

fn admitted_active() -> AdmittedResource {
    admitted(
        ResourceCarrier::ReconstructionRecord,
        ledger().durable_record(),
        active_subject(),
    )
    .unwrap_or_else(|error| panic!("the declared reconstruction record is admitted: {error:?}"))
}

/// Builds one decoded operation metadata value with an optional declared action and Section 20 kind.
fn operation_metadata(
    action_path: Option<&str>,
    section20_kind: Option<OperationKind>,
) -> ExecutableOperation {
    let action = action_path.map(|declaration| {
        let path = CanonicalPath::new(declaration)
            .unwrap_or_else(|_| unreachable!("fixture action path is canonical"));
        ExecutableAction {
            path: path.clone(),
            signature: CanonicalSignature::action(
                RecoveryClass::Idempotent,
                &path,
                &[],
                &TypeDescriptor::UNIT,
            ),
            recovery: RecoveryClass::Idempotent,
            parameters: Vec::new(),
        }
    });
    ExecutableOperation {
        kind: OperationSiteKind::Action,
        section20_kind,
        result_type: TypeDescriptor::UNIT,
        action,
        template_segments: Vec::new(),
        interpolation_types: Vec::new(),
        named_input_names: Vec::new(),
        named_input_types: Vec::new(),
        retry_limit: None,
        session_mode: None,
        attempted: false,
    }
}

#[test]
fn an_operation_without_an_authenticated_section20_kind_is_explicit() {
    let metadata = operation_metadata(None, None);
    assert_eq!(metadata.kind, OperationSiteKind::Action);
    assert_eq!(
        metadata.section20_kind, None,
        "an action site does not authenticate a Section 20 kind by itself"
    );
    assert_eq!(
        OperationKind::ALL.len(),
        3,
        "the Section 20 kind vocabulary is closed over three members"
    );
    // A live source resource authenticates the live-resource arm; a non-live result is either a
    // value action or a protected operation, so the class alone authenticates nothing.
    assert_eq!(
        OperationKind::for_value_resource_class(gantry::ir::ValueResourceClass::LiveResource),
        Some(OperationKind::LiveResource)
    );
    assert_eq!(
        OperationKind::for_value_resource_class(gantry::ir::ValueResourceClass::NonLiveResource),
        None
    );
}

#[test]
fn the_admitted_account_is_not_copyable() {
    assert_not_impl_any!(AdmittedResource: Clone, Copy);
}

/// A fake integration value records disposal and can fail during destruction.
struct TransportValue {
    drops: Arc<std::sync::atomic::AtomicUsize>,
    panic_on_drop: bool,
    value: u64,
}

impl Drop for TransportValue {
    fn drop(&mut self) {
        self.drops.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        assert!(!self.panic_on_drop, "fake integration destructor failed");
    }
}

/// A physical sweep leaves Active/Finishing accounts untouched and continues after destruction failure.
#[test]
fn coordinator_settled_physical_sweep_preserves_accounting_and_reports_failures() {
    use gantry::runtime::HostResourceError;
    let fixtures = [
        FIXTURE_DECLARATION,
        SECOND_FIXTURE_DECLARATION,
        THIRD_FIXTURE_DECLARATION,
        "crate::sweep_finishing",
    ]
    .map(|declaration| machine_with_declared_subject(Some(declaration)));
    let coordinator = resource_coordinator(
        fixtures[0].1.execution_id(),
        fixtures[0].1.task_id(),
        Some(4),
    );
    let drops: Vec<_> = (0..4)
        .map(|_| Arc::new(std::sync::atomic::AtomicUsize::new(0)))
        .collect();
    for (index, (_, machine, subject)) in fixtures.iter().enumerate() {
        let subject = subject.as_ref().unwrap_or_else(|| panic!("subject exists"));
        coordinator
            .admit_resource(
                machine,
                ResourceCarrier::ReconstructionRecord,
                ledger().durable_record(),
            )
            .unwrap_or_else(|error| panic!("admission: {error:?}"));
        coordinator
            .attach_resource_host_value(
                subject,
                OwnerGeneration::new(4),
                TransportValue {
                    drops: Arc::clone(&drops[index]),
                    panic_on_drop: index == 0,
                    value: 1,
                },
            )
            .unwrap_or_else(|_| panic!("attachment"));
    }
    let subjects: Vec<_> = fixtures
        .iter()
        .map(|(_, _, subject)| {
            subject
                .as_ref()
                .unwrap_or_else(|| panic!("subject exists"))
                .clone()
        })
        .collect();
    for subject in &subjects[..2] {
        coordinator
            .emergency_release_resource(subject, emergency_cleanup())
            .unwrap_or_else(|error| panic!("release: {error:?}"));
    }
    coordinator
        .begin_resource_finish(&subjects[3], OwnerGeneration::new(4))
        .unwrap_or_else(|error| panic!("finishing: {error:?}"));
    let before = coordinator.snapshot();
    let results = coordinator
        .dispose_settled_resource_host_values()
        .unwrap_or_else(|error| panic!("physical sweep: {error:?}"));
    let mut expected = subjects[..2].to_vec();
    expected.sort_by(|left, right| {
        (
            left.operation(),
            left.generation(),
            left.execution_id(),
            left.task_id(),
        )
            .cmp(&(
                right.operation(),
                right.generation(),
                right.execution_id(),
                right.task_id(),
            ))
    });
    assert_eq!(
        results
            .iter()
            .map(|(subject, _)| subject.clone())
            .collect::<Vec<_>>(),
        expected
    );
    for (subject, result) in &results {
        if subject == &subjects[0] {
            assert!(matches!(result, Err(HostResourceError::Boundary(_))));
        } else {
            assert_eq!(result, &Ok(()));
        }
    }
    assert_eq!(coordinator.snapshot(), before);
    for (index, count) in drops.iter().enumerate() {
        assert_eq!(
            count.load(std::sync::atomic::Ordering::SeqCst),
            usize::from(index < 2)
        );
    }
    let repeated = coordinator
        .dispose_settled_resource_host_values()
        .unwrap_or_else(|error| panic!("repeat sweep: {error:?}"));
    assert_eq!(repeated.len(), 1);
    assert_eq!(repeated[0].0, subjects[0]);
    assert!(matches!(repeated[0].1, Err(HostResourceError::Boundary(_))));
    assert_eq!(coordinator.snapshot(), before);
    for subject in &subjects[2..] {
        coordinator
            .emergency_release_resource(subject, emergency_cleanup())
            .unwrap_or_else(|error| panic!("remaining release: {error:?}"));
    }
    let released = coordinator.snapshot();
    let remaining = coordinator
        .dispose_settled_resource_host_values()
        .unwrap_or_else(|error| panic!("remaining sweep: {error:?}"));
    assert_eq!(
        remaining.len(),
        3,
        "retained failure and two newly released slots are reported"
    );
    assert_eq!(coordinator.snapshot(), released);
    assert!(
        drops
            .iter()
            .all(|count| count.load(std::sync::atomic::Ordering::SeqCst) == 1)
    );
}

/// Cohort disposal continues after one destructor fails, without rolling back semantic release.
#[test]
fn coordinator_resource_cohort_cleanup_reports_semantic_and_physical_outcomes() {
    use gantry::host::containment::AdapterPoison;
    use gantry::host::contracts::BlockingWorkService;
    use gantry::runtime::HostResourceError;
    use gantry::runtime::{BoundedBlockingWorkService, ResourceCleanupError};
    let (_, first_machine, first) = machine_with_declared_subject(Some(FIXTURE_DECLARATION));
    let (_, second_machine, second) =
        machine_with_declared_subject(Some(SECOND_FIXTURE_DECLARATION));
    let first = first.unwrap_or_else(|| panic!("first subject"));
    let second = second.unwrap_or_else(|| panic!("second subject"));
    let coordinator = resource_coordinator(
        first_machine.execution_id(),
        first_machine.task_id(),
        Some(2),
    );
    let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    for (machine, subject, fails) in [
        (&first_machine, &first, true),
        (&second_machine, &second, false),
    ] {
        coordinator
            .admit_resource(
                machine,
                ResourceCarrier::ReconstructionRecord,
                ledger().durable_record(),
            )
            .unwrap_or_else(|error| panic!("admission: {error:?}"));
        coordinator
            .attach_resource_host_value(
                subject,
                OwnerGeneration::new(4),
                TransportValue {
                    drops: Arc::clone(&drops),
                    panic_on_drop: fails,
                    value: 1,
                },
            )
            .unwrap_or_else(|_| panic!("attachment"));
    }
    let before = coordinator.snapshot();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap_or_else(|error| panic!("observer runtime: {error}"));
    let refused =
        BoundedBlockingWorkService::new(1, 1).unwrap_or_else(|error| panic!("service: {error:?}"));
    assert_eq!(runtime.block_on(refused.shutdown()), Ok(()));
    assert!(matches!(
        coordinator.submit_emergency_resource_cleanup(
            &refused,
            &AdapterPoison::default(),
            vec![(first.clone(), emergency_cleanup())]
        ),
        Err(ResourceCleanupError::Submission(_))
    ));
    assert_eq!(coordinator.snapshot(), before);
    assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 0);
    let service =
        BoundedBlockingWorkService::new(1, 1).unwrap_or_else(|error| panic!("service: {error:?}"));
    let observer = coordinator
        .submit_emergency_resource_cleanup(
            &service,
            &AdapterPoison::default(),
            vec![
                (second.clone(), emergency_cleanup()),
                (first.clone(), emergency_cleanup()),
                (first.clone(), emergency_cleanup()),
            ],
        )
        .unwrap_or_else(|error| panic!("submission: {error:?}"));
    let report = runtime
        .block_on(observer.completion())
        .unwrap_or_else(|error| panic!("sweep: {error:?}"));
    assert_eq!(runtime.block_on(observer.completion()), Ok(report.clone()));
    assert_eq!(runtime.block_on(service.shutdown()), Ok(()));
    assert!(report.semantic().is_complete());
    assert_eq!(report.semantic().settled().len(), 2);
    assert_eq!(report.physical().len(), 2);
    let mut expected = vec![first.clone(), second.clone()];
    expected.sort_by(|left, right| {
        (left.operation(), left.generation()).cmp(&(right.operation(), right.generation()))
    });
    assert_eq!(
        report
            .physical()
            .iter()
            .map(|(subject, _)| subject.clone())
            .collect::<Vec<_>>(),
        expected
    );
    for (subject, result) in report.physical() {
        if subject == &first {
            assert!(matches!(result, Err(HostResourceError::Boundary(_))));
        } else {
            assert_eq!(result, &Ok(()));
        }
    }
    assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 2);
    let after = coordinator.snapshot();
    assert_eq!(after.publication(), before.publication() + 1);
    assert!(
        after
            .resource_records()
            .unwrap_or_else(|| panic!("records"))
            .iter()
            .all(|record| record.record().lifetime() == ResourceLifetimeState::EmergencyReleased)
    );
    let repeated = coordinator
        .emergency_release_resource_cohort(vec![(first, emergency_cleanup())])
        .unwrap_or_else(|error| panic!("repeat report: {error:?}"));
    assert!(repeated.semantic().settled().is_empty());
    assert!(repeated.semantic().refusal().is_some());
    assert!(repeated.physical().is_empty());
    assert_eq!(coordinator.snapshot(), after);
}

/// Semantic refusal disposes only the exact settled prefix and preserves later members.
#[test]
fn coordinator_resource_cohort_cleanup_disposes_only_its_settled_prefix() {
    use gantry::host::containment::AdapterPoison;
    use gantry::host::contracts::BlockingWorkService;
    use gantry::runtime::BoundedBlockingWorkService;
    let declarations = [
        FIXTURE_DECLARATION,
        SECOND_FIXTURE_DECLARATION,
        THIRD_FIXTURE_DECLARATION,
    ];
    let fixtures = declarations.map(|declaration| machine_with_declared_subject(Some(declaration)));
    let coordinator = resource_coordinator(
        fixtures[0].1.execution_id(),
        fixtures[0].1.task_id(),
        Some(3),
    );
    let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut subjects = Vec::new();
    for (_, machine, subject) in &fixtures {
        let subject = subject.as_ref().unwrap_or_else(|| panic!("subject"));
        coordinator
            .admit_resource(
                machine,
                ResourceCarrier::ReconstructionRecord,
                ledger().durable_record(),
            )
            .unwrap_or_else(|error| panic!("admission: {error:?}"));
        coordinator
            .attach_resource_host_value(
                subject,
                OwnerGeneration::new(4),
                TransportValue {
                    drops: Arc::clone(&drops),
                    panic_on_drop: false,
                    value: 1,
                },
            )
            .unwrap_or_else(|_| panic!("attachment"));
        subjects.push(subject.clone());
    }
    subjects.sort_by(|left, right| {
        (left.operation(), left.generation()).cmp(&(right.operation(), right.generation()))
    });
    coordinator
        .emergency_release_resource(&subjects[1], emergency_cleanup())
        .unwrap_or_else(|error| panic!("prior release: {error:?}"));
    let before = coordinator.snapshot();
    let service =
        BoundedBlockingWorkService::new(1, 1).unwrap_or_else(|error| panic!("service: {error:?}"));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap_or_else(|error| panic!("observer runtime: {error}"));
    let observer = coordinator
        .submit_emergency_resource_cleanup(
            &service,
            &AdapterPoison::default(),
            subjects
                .iter()
                .rev()
                .map(|subject| (subject.clone(), emergency_cleanup()))
                .collect(),
        )
        .unwrap_or_else(|error| panic!("submission: {error:?}"));
    let report = runtime
        .block_on(observer.completion())
        .unwrap_or_else(|error| panic!("partial sweep: {error:?}"));
    assert_eq!(runtime.block_on(service.shutdown()), Ok(()));
    assert_eq!(report.semantic().settled().len(), 1);
    assert_eq!(report.semantic().settled()[0].subject(), &subjects[0]);
    assert!(matches!(report.semantic().refusal(), Some((subject,
        ResourceRegistryRefusal::EmergencyRelease(ResourceError::IllegalLifetimeTransition))) if subject == &subjects[1]));
    assert_eq!(report.physical(), &[(subjects[0].clone(), Ok(()))]);
    assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 1);
    let after = coordinator.snapshot();
    assert_eq!(after.publication(), before.publication() + 1);
    let before_records = before
        .resource_records()
        .unwrap_or_else(|| panic!("before records"));
    let after_records = after
        .resource_records()
        .unwrap_or_else(|| panic!("after records"));
    for subject in &subjects[1..] {
        assert_eq!(
            after_records
                .iter()
                .find(|record| record.subject() == subject),
            before_records
                .iter()
                .find(|record| record.subject() == subject)
        );
        assert_eq!(
            coordinator
                .dispose_resource_host_value(subject, OwnerGeneration::new(4))
                .is_ok(),
            subject == &subjects[1]
        );
    }
    coordinator
        .emergency_release_resource(&subjects[2], emergency_cleanup())
        .unwrap_or_else(|error| panic!("remaining release: {error:?}"));
    coordinator
        .dispose_resource_host_value(&subjects[2], OwnerGeneration::new(4))
        .unwrap_or_else(|error| panic!("remaining disposal: {error:?}"));
    assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 3);
}

/// A destructor reenters coordinator inspection and pauses so finalization can race with cleanup.
struct CoordinatorDropProbe {
    coordinator: gantry::runtime::ExecutionCoordinator,
    entered: Arc<std::sync::Barrier>,
    release: Arc<std::sync::Barrier>,
    unlocked: Arc<std::sync::atomic::AtomicBool>,
    drops: Arc<std::sync::atomic::AtomicUsize>,
}

impl Drop for CoordinatorDropProbe {
    fn drop(&mut self) {
        self.unlocked.store(
            self.coordinator.try_snapshot().is_some(),
            std::sync::atomic::Ordering::SeqCst,
        );
        self.drops.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.entered.wait();
        self.release.wait();
    }
}

/// Started blocking cleanup retains destruction even after its observer is dropped.
#[test]
fn submitted_resource_cleanup_survives_observer_drop_and_runs_unlocked() {
    use gantry::host::containment::AdapterPoison;
    use gantry::host::contracts::BlockingWorkService;
    use gantry::runtime::BoundedBlockingWorkService;
    let (_, machine, subject) = machine_with_declared_subject(Some(FIXTURE_DECLARATION));
    let subject = subject.unwrap_or_else(|| panic!("subject exists"));
    let coordinator = resource_coordinator(machine.execution_id(), machine.task_id(), Some(1));
    coordinator
        .admit_resource(
            &machine,
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
        )
        .unwrap_or_else(|error| panic!("admission: {error:?}"));
    let entered = Arc::new(std::sync::Barrier::new(2));
    let release = Arc::new(std::sync::Barrier::new(2));
    let unlocked = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    coordinator
        .attach_resource_host_value(
            &subject,
            OwnerGeneration::new(4),
            CoordinatorDropProbe {
                coordinator: coordinator.clone(),
                entered: Arc::clone(&entered),
                release: Arc::clone(&release),
                unlocked: Arc::clone(&unlocked),
                drops: Arc::clone(&drops),
            },
        )
        .unwrap_or_else(|_| panic!("attachment"));
    coordinator
        .emergency_release_resource(&subject, emergency_cleanup())
        .unwrap_or_else(|error| panic!("release: {error:?}"));
    let before = coordinator.snapshot();
    let service =
        BoundedBlockingWorkService::new(1, 1).unwrap_or_else(|error| panic!("service: {error:?}"));
    let observer = coordinator
        .submit_settled_resource_cleanup(&service, &AdapterPoison::default())
        .unwrap_or_else(|error| panic!("submission: {error:?}"));
    entered.wait();
    let mut completion = Box::pin(observer.completion());
    let pending = std::future::Future::poll(
        completion.as_mut(),
        &mut std::task::Context::from_waker(std::task::Waker::noop()),
    )
    .is_pending();
    drop(completion);
    drop(observer);
    let during = coordinator.snapshot();
    release.wait();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap_or_else(|error| panic!("observer runtime: {error}"));
    assert_eq!(runtime.block_on(service.shutdown()), Ok(()));
    assert!(
        pending,
        "observer remains pending while destruction is executing"
    );
    assert!(unlocked.load(std::sync::atomic::Ordering::SeqCst));
    assert_eq!(during, before);
    assert_eq!(coordinator.snapshot(), before);
    assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(
        coordinator.dispose_settled_resource_host_values(),
        Ok(Vec::new())
    );
}

/// Sealed emergency settlement publishes before unlocked destruction and survives observer drop.
#[test]
fn submitted_emergency_cleanup_survives_observer_drop() {
    use gantry::host::containment::AdapterPoison;
    use gantry::host::contracts::BlockingWorkService;
    use gantry::runtime::BoundedBlockingWorkService;
    let (_, machine, subject) = machine_with_declared_subject(Some(FIXTURE_DECLARATION));
    let subject = subject.unwrap_or_else(|| panic!("subject exists"));
    let coordinator = resource_coordinator(machine.execution_id(), machine.task_id(), Some(1));
    coordinator
        .admit_resource(
            &machine,
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
        )
        .unwrap_or_else(|error| panic!("admission: {error:?}"));
    let entered = Arc::new(std::sync::Barrier::new(2));
    let release = Arc::new(std::sync::Barrier::new(2));
    let unlocked = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    coordinator
        .attach_resource_host_value(
            &subject,
            OwnerGeneration::new(4),
            CoordinatorDropProbe {
                coordinator: coordinator.clone(),
                entered: Arc::clone(&entered),
                release: Arc::clone(&release),
                unlocked: Arc::clone(&unlocked),
                drops: Arc::clone(&drops),
            },
        )
        .unwrap_or_else(|_| panic!("attachment"));
    let before = coordinator.snapshot();
    let service =
        BoundedBlockingWorkService::new(1, 1).unwrap_or_else(|error| panic!("service: {error:?}"));
    let observer = coordinator
        .submit_emergency_resource_cleanup(
            &service,
            &AdapterPoison::default(),
            vec![(subject.clone(), emergency_cleanup())],
        )
        .unwrap_or_else(|error| panic!("submission: {error:?}"));
    entered.wait();
    let mut completion = Box::pin(observer.completion());
    let pending = std::future::Future::poll(
        completion.as_mut(),
        &mut std::task::Context::from_waker(std::task::Waker::noop()),
    )
    .is_pending();
    drop(completion);
    drop(observer);
    let during = coordinator.snapshot();
    release.wait();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap_or_else(|error| panic!("observer runtime: {error}"));
    assert_eq!(runtime.block_on(service.shutdown()), Ok(()));
    assert!(pending);
    assert!(unlocked.load(std::sync::atomic::Ordering::SeqCst));
    assert_eq!(during.publication(), before.publication() + 1);
    assert_eq!(
        during
            .resource_records()
            .unwrap_or_else(|| panic!("records"))[0]
            .record()
            .lifetime(),
        ResourceLifetimeState::EmergencyReleased
    );
    assert_eq!(coordinator.snapshot(), during);
    assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert!(
        coordinator.has_pending_resource_operations(),
        "emergency release is not machine settlement"
    );
    assert_eq!(
        coordinator.dispose_settled_resource_host_values(),
        Ok(Vec::new())
    );
}

/// Submission refusal leaves slots held; successful service completion retains member failures.
#[test]
fn submitted_resource_cleanup_refusal_and_failure_preserve_accounting() {
    use gantry::host::containment::AdapterPoison;
    use gantry::host::contracts::BlockingWorkService;
    use gantry::runtime::{BoundedBlockingWorkService, HostResourceError, ResourceCleanupError};
    let (_, machine, subject) = machine_with_declared_subject(Some(FIXTURE_DECLARATION));
    let subject = subject.unwrap_or_else(|| panic!("subject exists"));
    let coordinator = resource_coordinator(machine.execution_id(), machine.task_id(), Some(1));
    coordinator
        .admit_resource(
            &machine,
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
        )
        .unwrap_or_else(|error| panic!("admission: {error:?}"));
    let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    coordinator
        .attach_resource_host_value(
            &subject,
            OwnerGeneration::new(4),
            TransportValue {
                drops: Arc::clone(&drops),
                panic_on_drop: true,
                value: 1,
            },
        )
        .unwrap_or_else(|_| panic!("attachment"));
    coordinator
        .emergency_release_resource(&subject, emergency_cleanup())
        .unwrap_or_else(|error| panic!("release: {error:?}"));
    let before = coordinator.snapshot();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap_or_else(|error| panic!("observer runtime: {error}"));
    let refused =
        BoundedBlockingWorkService::new(1, 1).unwrap_or_else(|error| panic!("service: {error:?}"));
    assert_eq!(runtime.block_on(refused.shutdown()), Ok(()));
    assert!(matches!(
        coordinator.submit_settled_resource_cleanup(&refused, &AdapterPoison::default()),
        Err(ResourceCleanupError::Submission(_))
    ));
    assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(coordinator.snapshot(), before);
    let poison = AdapterPoison::default();
    poison.poison();
    assert!(matches!(
        coordinator.submit_settled_resource_cleanup(&refused, &poison),
        Err(ResourceCleanupError::Boundary(_))
    ));
    assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 0);
    let service =
        BoundedBlockingWorkService::new(1, 1).unwrap_or_else(|error| panic!("service: {error:?}"));
    let observer = coordinator
        .submit_settled_resource_cleanup(&service, &AdapterPoison::default())
        .unwrap_or_else(|error| panic!("submission: {error:?}"));
    let result = runtime
        .block_on(observer.completion())
        .unwrap_or_else(|error| panic!("completion: {error:?}"));
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].0, subject);
    assert!(matches!(result[0].1, Err(HostResourceError::Boundary(_))));
    assert_eq!(runtime.block_on(observer.completion()), Ok(result));
    assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(coordinator.snapshot(), before);
    assert_eq!(runtime.block_on(service.shutdown()), Ok(()));
}

/// Cancelling queued cleanup leaves physical slots available for a later cleanup owner.
#[test]
fn submitted_resource_cleanup_cancelled_before_start_retains_physical_ownership() {
    use gantry::host::containment::AdapterPoison;
    use gantry::host::contracts::{BlockingJobCompletion, BlockingWorkService};
    use gantry::runtime::{BoundedBlockingWorkService, ResourceCleanupError};
    let (_, machine, subject) = machine_with_declared_subject(Some(FIXTURE_DECLARATION));
    let subject = subject.unwrap_or_else(|| panic!("subject exists"));
    let coordinator = resource_coordinator(machine.execution_id(), machine.task_id(), Some(1));
    coordinator
        .admit_resource(
            &machine,
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
        )
        .unwrap_or_else(|error| panic!("admission: {error:?}"));
    let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    coordinator
        .attach_resource_host_value(
            &subject,
            OwnerGeneration::new(4),
            TransportValue {
                drops: Arc::clone(&drops),
                panic_on_drop: false,
                value: 1,
            },
        )
        .unwrap_or_else(|_| panic!("attachment"));
    coordinator
        .emergency_release_resource(&subject, emergency_cleanup())
        .unwrap_or_else(|error| panic!("release: {error:?}"));
    let before = coordinator.snapshot();
    let service =
        BoundedBlockingWorkService::new(1, 1).unwrap_or_else(|error| panic!("service: {error:?}"));
    let (started_tx, started_rx) = std::sync::mpsc::sync_channel(1);
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
    let blocker = service
        .submit(Box::new(move || {
            let _ = started_tx.send(());
            let _ = release_rx.recv();
        }))
        .unwrap_or_else(|error| panic!("blocker: {error:?}"));
    started_rx
        .recv_timeout(std::time::Duration::from_secs(2))
        .unwrap_or_else(|error| panic!("blocker did not start: {error}"));
    let submission =
        coordinator.submit_settled_resource_cleanup(&service, &AdapterPoison::default());
    // Shutdown synchronously cancels queued work, but waits for the running blocker.
    let shutdown = service.shutdown();
    let _ = release_tx.send(());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap_or_else(|error| panic!("observer runtime: {error}"));
    assert_eq!(runtime.block_on(shutdown), Ok(()));
    assert_eq!(
        runtime.block_on(blocker.completion()),
        BlockingJobCompletion::Completed
    );
    let observer = submission.unwrap_or_else(|error| panic!("queued submission: {error:?}"));
    assert_eq!(
        runtime.block_on(observer.completion()),
        Err(ResourceCleanupError::Completion(
            BlockingJobCompletion::CancelledBeforeStart
        ))
    );
    assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(coordinator.snapshot(), before);
    assert_eq!(
        coordinator.dispose_settled_resource_host_values(),
        Ok(vec![(subject, Ok(()))])
    );
    assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(coordinator.snapshot(), before);
}

/// Cancelling a queued sealed cohort does not publish semantic release or destroy physical values.
#[test]
fn submitted_emergency_cleanup_cancelled_before_start_preserves_accounting() {
    use gantry::host::containment::AdapterPoison;
    use gantry::host::contracts::{BlockingJobCompletion, BlockingWorkService};
    use gantry::runtime::{BoundedBlockingWorkService, ResourceCleanupError};
    let (_, machine, subject) = machine_with_declared_subject(Some(FIXTURE_DECLARATION));
    let subject = subject.unwrap_or_else(|| panic!("subject exists"));
    let coordinator = resource_coordinator(machine.execution_id(), machine.task_id(), Some(1));
    coordinator
        .admit_resource(
            &machine,
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
        )
        .unwrap_or_else(|error| panic!("admission: {error:?}"));
    let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    coordinator
        .attach_resource_host_value(
            &subject,
            OwnerGeneration::new(4),
            TransportValue {
                drops: Arc::clone(&drops),
                panic_on_drop: false,
                value: 1,
            },
        )
        .unwrap_or_else(|_| panic!("attachment"));
    let before = coordinator.snapshot();
    let service =
        BoundedBlockingWorkService::new(1, 1).unwrap_or_else(|error| panic!("service: {error:?}"));
    let (started_tx, started_rx) = std::sync::mpsc::sync_channel(1);
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
    let blocker = service
        .submit(Box::new(move || {
            let _ = started_tx.send(());
            let _ = release_rx.recv();
        }))
        .unwrap_or_else(|error| panic!("blocker: {error:?}"));
    started_rx
        .recv_timeout(std::time::Duration::from_secs(2))
        .unwrap_or_else(|error| panic!("blocker did not start: {error}"));
    let submission = coordinator.submit_emergency_resource_cleanup(
        &service,
        &AdapterPoison::default(),
        vec![(subject.clone(), emergency_cleanup())],
    );
    let shutdown = service.shutdown();
    let _ = release_tx.send(());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap_or_else(|error| panic!("observer runtime: {error}"));
    assert_eq!(runtime.block_on(shutdown), Ok(()));
    assert_eq!(
        runtime.block_on(blocker.completion()),
        BlockingJobCompletion::Completed
    );
    let observer = submission.unwrap_or_else(|error| panic!("queued submission: {error:?}"));
    assert_eq!(
        runtime.block_on(observer.completion()),
        Err(ResourceCleanupError::Completion(
            BlockingJobCompletion::CancelledBeforeStart
        ))
    );
    assert_eq!(coordinator.snapshot(), before);
    assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert!(coordinator.has_pending_resource_operations());
    let report = coordinator
        .emergency_release_resource_cohort(vec![(subject.clone(), emergency_cleanup())])
        .unwrap_or_else(|error| panic!("explicit late cleanup: {error:?}"));
    assert!(report.semantic().is_complete());
    assert_eq!(report.physical(), &[(subject, Ok(()))]);
    assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(
        coordinator.snapshot().publication(),
        before.publication() + 1
    );
    assert!(
        coordinator.has_pending_resource_operations(),
        "cleanup does not settle machine work"
    );
}

/// Faults injected independently at each cleanup service boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CleanupServiceFault {
    Submission,
    CompletionConstruction,
    CompletionPoll,
    CompletionDrop,
    HandleDrop,
    MissingResult,
}

/// Inline service double isolates containment; it is not blocking-worker qualification.
struct FaultingCleanupService {
    fault: CleanupServiceFault,
    handle_drops: Arc<std::sync::atomic::AtomicUsize>,
}

impl gantry::host::contracts::BlockingWorkService for FaultingCleanupService {
    fn capacities(&self) -> gantry::host::contracts::BlockingWorkCapacities {
        gantry::host::contracts::BlockingWorkCapacities::new(1, 1)
            .unwrap_or_else(|| panic!("positive fixture capacities"))
    }

    fn submit(
        &self,
        job: gantry::host::contracts::OwnedBlockingJob,
    ) -> Result<
        Arc<dyn gantry::host::contracts::SubmittedBlockingJob>,
        gantry::host::contracts::BlockingWorkSubmitError,
    > {
        assert_ne!(
            self.fault,
            CleanupServiceFault::Submission,
            "protected submission failure"
        );
        if self.fault != CleanupServiceFault::MissingResult {
            job();
        }
        Ok(Arc::new(FaultingCleanupHandle {
            fault: self.fault,
            drops: Arc::clone(&self.handle_drops),
        }))
    }

    fn shutdown(
        &self,
    ) -> gantry::host::contracts::HostFuture<'_, Result<(), gantry::host::contracts::HostError>>
    {
        Box::pin(async { Ok(()) })
    }
}

/// The handle may fail while creating an observer or being physically destroyed.
struct FaultingCleanupHandle {
    fault: CleanupServiceFault,
    drops: Arc<std::sync::atomic::AtomicUsize>,
}

impl gantry::host::contracts::SubmittedBlockingJob for FaultingCleanupHandle {
    fn cancel_before_start(&self) -> gantry::host::contracts::BlockingJobCancellation {
        panic!("cleanup observers must never cancel accepted work")
    }

    fn completion(
        &self,
    ) -> gantry::host::contracts::HostFuture<'_, gantry::host::contracts::BlockingJobCompletion>
    {
        assert_ne!(
            self.fault,
            CleanupServiceFault::CompletionConstruction,
            "protected observer construction failure"
        );
        Box::pin(FaultingCleanupFuture(self.fault))
    }
}

impl Drop for FaultingCleanupHandle {
    fn drop(&mut self) {
        self.drops.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        assert_ne!(
            self.fault,
            CleanupServiceFault::HandleDrop,
            "protected handle disposal failure"
        );
    }
}

/// Completed observer futures can still fail during their contained destruction.
struct FaultingCleanupFuture(CleanupServiceFault);

impl std::future::Future for FaultingCleanupFuture {
    type Output = gantry::host::contracts::BlockingJobCompletion;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        assert_ne!(
            self.0,
            CleanupServiceFault::CompletionPoll,
            "protected completion poll failure"
        );
        std::task::Poll::Ready(gantry::host::contracts::BlockingJobCompletion::Completed)
    }
}

impl Drop for FaultingCleanupFuture {
    fn drop(&mut self) {
        assert_ne!(
            self.0,
            CleanupServiceFault::CompletionDrop,
            "protected completion disposal failure"
        );
    }
}

/// Service faults cannot escape containment, fabricate cleanup results or rewrite accounting.
#[test]
fn submitted_resource_cleanup_contains_hostile_service_boundaries() {
    use gantry::host::containment::AdapterPoison;
    use gantry::runtime::ResourceCleanupError;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap_or_else(|error| panic!("observer runtime: {error}"));
    for fault in [
        CleanupServiceFault::Submission,
        CleanupServiceFault::CompletionConstruction,
        CleanupServiceFault::CompletionPoll,
        CleanupServiceFault::CompletionDrop,
        CleanupServiceFault::HandleDrop,
        CleanupServiceFault::MissingResult,
    ] {
        let (_, machine, subject) = machine_with_declared_subject(Some(FIXTURE_DECLARATION));
        let subject = subject.unwrap_or_else(|| panic!("subject exists"));
        let coordinator = resource_coordinator(machine.execution_id(), machine.task_id(), Some(1));
        coordinator
            .admit_resource(
                &machine,
                ResourceCarrier::ReconstructionRecord,
                ledger().durable_record(),
            )
            .unwrap_or_else(|error| panic!("admission: {error:?}"));
        let value_drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        coordinator
            .attach_resource_host_value(
                &subject,
                OwnerGeneration::new(4),
                TransportValue {
                    drops: Arc::clone(&value_drops),
                    panic_on_drop: false,
                    value: 1,
                },
            )
            .unwrap_or_else(|_| panic!("attachment"));
        coordinator
            .emergency_release_resource(&subject, emergency_cleanup())
            .unwrap_or_else(|error| panic!("release: {error:?}"));
        let before = coordinator.snapshot();
        let handle_drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let service = FaultingCleanupService {
            fault,
            handle_drops: Arc::clone(&handle_drops),
        };
        let poison = AdapterPoison::default();
        let submitted = coordinator.submit_settled_resource_cleanup(&service, &poison);
        if fault == CleanupServiceFault::Submission {
            assert!(matches!(submitted, Err(ResourceCleanupError::Boundary(_))));
            assert!(poison.is_poisoned());
            assert_eq!(value_drops.load(std::sync::atomic::Ordering::SeqCst), 0);
        } else {
            let observer = submitted.unwrap_or_else(|error| panic!("submission: {error:?}"));
            let result = runtime.block_on(observer.completion());
            match fault {
                CleanupServiceFault::MissingResult => {
                    assert_eq!(result, Err(ResourceCleanupError::MissingResult))
                }
                CleanupServiceFault::HandleDrop => {
                    assert_eq!(result, Ok(vec![(subject.clone(), Ok(()))]))
                }
                _ => assert!(matches!(result, Err(ResourceCleanupError::Boundary(_)))),
            }
            assert!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(observer))).is_ok()
            );
            assert_eq!(handle_drops.load(std::sync::atomic::Ordering::SeqCst), 1);
            assert_eq!(
                value_drops.load(std::sync::atomic::Ordering::SeqCst),
                usize::from(fault != CleanupServiceFault::MissingResult)
            );
        }
        assert_eq!(coordinator.snapshot(), before);
        coordinator
            .dispose_settled_resource_host_values()
            .unwrap_or_else(|error| panic!("remaining cleanup: {error:?}"));
        assert_eq!(value_drops.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(coordinator.snapshot(), before);
    }
}

/// Counts physical-quiescence notifications without polling or scheduling cleanup itself.
#[derive(Default)]
struct ResourceShutdownWake(std::sync::atomic::AtomicUsize);

impl std::task::Wake for ResourceShutdownWake {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Shared disposal executes unlocked, and in-flight destruction cannot authorize finalization.
#[test]
fn coordinator_host_disposal_is_unlocked_and_fences_inflight_finalization() {
    use gantry::runtime::{CoordinatorResourceRefusal, HostResourceError};
    let (_, machine, subject) = machine_with_declared_subject(Some(FIXTURE_DECLARATION));
    let subject = subject.unwrap_or_else(|| panic!("subject exists"));
    let owner = OwnerGeneration::new(4);
    let coordinator = resource_coordinator(machine.execution_id(), machine.task_id(), Some(1));
    coordinator
        .admit_resource(
            &machine,
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
        )
        .unwrap_or_else(|error| panic!("admission: {error:?}"));
    let before = coordinator.snapshot();
    let entered = Arc::new(std::sync::Barrier::new(2));
    let release = Arc::new(std::sync::Barrier::new(2));
    let unlocked = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    coordinator
        .attach_resource_host_value(
            &subject,
            owner,
            CoordinatorDropProbe {
                coordinator: coordinator.clone(),
                entered: Arc::clone(&entered),
                release: Arc::clone(&release),
                unlocked: Arc::clone(&unlocked),
                drops: Arc::clone(&drops),
            },
        )
        .unwrap_or_else(|_| panic!("attachment"));
    assert_eq!(
        coordinator.snapshot(),
        before,
        "attachment is not accounting publication"
    );
    assert_eq!(
        coordinator.dispose_resource_host_value(&subject, owner),
        Err(CoordinatorResourceRefusal::Host(HostResourceError::Model(
            ResourceError::IllegalLifetimeTransition
        )))
    );
    assert_eq!(
        coordinator.begin_resource_finish(&subject, owner),
        Ok(ResourceLifetimeState::Finishing)
    );
    coordinator
        .settle_task(
            machine.task_id(),
            MachineOutcome::Succeeded(LogicalValue::unit()),
        )
        .unwrap_or_else(|error| panic!("task settlement: {error:?}"));
    coordinator
        .mark_driver_physically_settled(machine.task_id())
        .unwrap_or_else(|error| panic!("driver settlement: {error:?}"));
    let mut shutdown = Box::pin(coordinator.wait_for_shutdown_quiescence());
    let wakes = Arc::new(ResourceShutdownWake::default());
    let waker = std::task::Waker::from(Arc::clone(&wakes));
    let finishing = coordinator.snapshot();
    std::thread::scope(|scope| {
        let cleanup = scope.spawn(|| {
            coordinator
                .clone()
                .dispose_resource_host_value(&subject, owner)
        });
        entered.wait();
        // Release destruction even if a following assertion fails, avoiding a test-induced hang.
        let observed_unlocked = unlocked.load(std::sync::atomic::Ordering::SeqCst);
        let finalization = coordinator.complete_resource_finalization(&subject, owner, 31);
        let repeated = coordinator.dispose_resource_host_value(&subject, owner);
        let during = coordinator.snapshot();
        let shutdown_during = std::future::Future::poll(
            shutdown.as_mut(),
            &mut std::task::Context::from_waker(&waker),
        );
        release.wait();
        assert_eq!(
            cleanup.join().unwrap_or_else(|_| panic!("cleanup thread")),
            Ok(())
        );
        assert!(
            observed_unlocked,
            "destructor can inspect coordinator without its mutex held"
        );
        assert_eq!(
            finalization,
            Err(CoordinatorResourceRefusal::Registry(
                ResourceRegistryRefusal::PhysicalValuePresent
            ))
        );
        assert_eq!(
            repeated,
            Err(CoordinatorResourceRefusal::Host(
                HostResourceError::DisposalPending
            ))
        );
        assert_eq!(during, finishing);
        assert!(
            shutdown_during.is_pending(),
            "physical cleanup is not quiescent while destruction runs"
        );
    });
    assert_eq!(wakes.0.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert!(
        std::future::Future::poll(
            shutdown.as_mut(),
            &mut std::task::Context::from_waker(&waker)
        )
        .is_ready()
    );
    assert_eq!(
        coordinator.snapshot(),
        finishing,
        "disposal is not accounting publication"
    );
    assert_eq!(
        coordinator.complete_resource_finalization(&subject, owner, 31),
        Ok(ResourceLifetimeState::Finished)
    );
    assert_eq!(
        coordinator.dispose_resource_host_value(&subject, owner),
        Ok(())
    );
    assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 1);
}

/// Shared attachment returns refused inputs and retains disposal failure without normal finish.
#[test]
fn coordinator_host_attachment_refusal_and_failed_disposal_preserve_accounting() {
    use gantry::runtime::{CoordinatorResourceRefusal, HostResourceError};
    let (_, machine, subject) = machine_with_declared_subject(Some(FIXTURE_DECLARATION));
    let subject = subject.unwrap_or_else(|| panic!("subject exists"));
    let owner = OwnerGeneration::new(4);
    let disabled = resource_coordinator(machine.execution_id(), machine.task_id(), None);
    let (error, value) = *disabled
        .attach_resource_host_value(&subject, owner, 17_u64)
        .err()
        .unwrap_or_else(|| panic!("disabled refuses"));
    assert_eq!(error, CoordinatorResourceRefusal::RegistryDisabled);
    assert_eq!(value, 17);
    let coordinator = resource_coordinator(machine.execution_id(), machine.task_id(), Some(1));
    coordinator
        .admit_resource(
            &machine,
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
        )
        .unwrap_or_else(|error| panic!("admission: {error:?}"));
    let before = coordinator.snapshot();
    let (error, value) = *coordinator
        .attach_resource_host_value(&subject, OwnerGeneration::new(3), 17_u64)
        .err()
        .unwrap_or_else(|| panic!("stale owner refuses"));
    assert!(matches!(
        error,
        CoordinatorResourceRefusal::Host(HostResourceError::Model(
            ResourceError::StaleOwner { .. }
        ))
    ));
    assert_eq!(value, 17);
    assert_eq!(coordinator.snapshot(), before);
    let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    coordinator
        .attach_resource_host_value(
            &subject,
            owner,
            TransportValue {
                drops: Arc::clone(&drops),
                panic_on_drop: true,
                value: 7,
            },
        )
        .unwrap_or_else(|_| panic!("attachment"));
    assert_eq!(
        coordinator.begin_resource_finish(&subject, owner),
        Ok(ResourceLifetimeState::Finishing)
    );
    coordinator
        .settle_task(
            machine.task_id(),
            MachineOutcome::Succeeded(LogicalValue::unit()),
        )
        .unwrap_or_else(|error| panic!("task settlement: {error:?}"));
    coordinator
        .mark_driver_physically_settled(machine.task_id())
        .unwrap_or_else(|error| panic!("driver settlement: {error:?}"));
    let mut shutdown = Box::pin(coordinator.wait_for_shutdown_quiescence());
    let wakes = Arc::new(ResourceShutdownWake::default());
    let waker = std::task::Waker::from(Arc::clone(&wakes));
    assert!(
        std::future::Future::poll(
            shutdown.as_mut(),
            &mut std::task::Context::from_waker(&waker)
        )
        .is_pending()
    );
    let finishing = coordinator.snapshot();
    for _ in 0..2 {
        assert!(matches!(
            coordinator.dispose_resource_host_value(&subject, owner),
            Err(CoordinatorResourceRefusal::Host(
                HostResourceError::Boundary(_)
            ))
        ));
        assert_eq!(
            coordinator.complete_resource_finalization(&subject, owner, 31),
            Err(CoordinatorResourceRefusal::Registry(
                ResourceRegistryRefusal::PhysicalDisposalFailed
            ))
        );
        assert_eq!(coordinator.snapshot(), finishing);
    }
    assert_eq!(wakes.0.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert!(
        std::future::Future::poll(
            shutdown.as_mut(),
            &mut std::task::Context::from_waker(&waker)
        )
        .is_ready()
    );
    assert_eq!(
        coordinator.emergency_release_resource(&subject, emergency_cleanup()),
        Ok(ResourceLifetimeState::EmergencyReleased)
    );
    assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 1);
}

/// Task settlement closes physical admission but leaves accounting cleanup available.
#[test]
fn coordinator_host_attachment_refuses_after_task_settlement() {
    let (_, machine, subject) = machine_with_declared_subject(Some(FIXTURE_DECLARATION));
    let subject = subject.unwrap_or_else(|| panic!("subject exists"));
    let owner = OwnerGeneration::new(4);
    let coordinator = resource_coordinator(machine.execution_id(), machine.task_id(), Some(1));
    coordinator
        .admit_resource(
            &machine,
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
        )
        .unwrap_or_else(|error| panic!("admission: {error:?}"));
    coordinator
        .settle_task(
            machine.task_id(),
            MachineOutcome::Succeeded(LogicalValue::unit()),
        )
        .unwrap_or_else(|error| panic!("task settlement: {error:?}"));
    let before = coordinator.snapshot();
    let refusal = coordinator.attach_resource_host_value(&subject, owner, 17_u64);
    assert!(
        refusal.is_err(),
        "settled task must not gain new physical ownership"
    );
    let (error, returned) = *refusal
        .err()
        .unwrap_or_else(|| panic!("attachment refuses"));
    assert_eq!(
        error,
        gantry::runtime::CoordinatorResourceRefusal::TaskNotRunning
    );
    assert_eq!(returned, 17);
    assert_eq!(coordinator.snapshot(), before);
    assert_eq!(
        coordinator.emergency_release_resource(&subject, emergency_cleanup()),
        Ok(ResourceLifetimeState::EmergencyReleased)
    );
}

/// Cancellation requests close admission immediately without settling accepted accounting.
#[test]
fn coordinator_resource_admission_refuses_during_requested_cancellation() {
    for execution_wide in [false, true] {
        let (_, machine, subject) = machine_with_declared_subject(Some(FIXTURE_DECLARATION));
        let subject = subject.unwrap_or_else(|| panic!("subject exists"));
        let (_, sibling, _) = machine_with_declared_subject(Some(SECOND_FIXTURE_DECLARATION));
        let coordinator = resource_coordinator(machine.execution_id(), machine.task_id(), Some(2));
        coordinator
            .admit_resource(
                &machine,
                ResourceCarrier::ReconstructionRecord,
                ledger().durable_record(),
            )
            .unwrap_or_else(|error| panic!("admission: {error:?}"));
        if execution_wide {
            coordinator
                .cancel_execution("resource admission regression")
                .unwrap_or_else(|error| panic!("execution cancellation: {error:?}"));
        } else {
            coordinator
                .cancel_task_tree(machine.task_id(), "resource admission regression")
                .unwrap_or_else(|error| panic!("task cancellation: {error:?}"));
        }
        let before = coordinator.snapshot();
        assert_eq!(
            coordinator.admit_resource(
                &sibling,
                ResourceCarrier::ReconstructionRecord,
                ledger().durable_record()
            ),
            Err(gantry::runtime::CoordinatorResourceRefusal::TaskCancellationRequested)
        );
        assert_eq!(coordinator.snapshot(), before);
        let refusal =
            coordinator.attach_resource_host_value(&subject, OwnerGeneration::new(4), 17_u64);
        let (error, returned) = *refusal
            .err()
            .unwrap_or_else(|| panic!("requested cancellation closes physical admission"));
        assert_eq!(
            error,
            gantry::runtime::CoordinatorResourceRefusal::TaskCancellationRequested
        );
        assert_eq!(returned, 17);
        assert_eq!(coordinator.snapshot(), before);
        assert_eq!(
            coordinator.emergency_release_resource(&subject, emergency_cleanup()),
            Ok(ResourceLifetimeState::EmergencyReleased)
        );
    }
}

/// Physical attachment leaves registry quota and accounting ownership in place until settlement.
#[test]
fn registry_host_attachment_preserves_accounting_and_finalization_fences() {
    // Accounting ownership is independent of cancellation-time admission fences.
    use gantry::runtime::HostResourceError;
    let subject = active_subject();
    let owner = OwnerGeneration::new(4);
    let mut registry = ResourceRegistry::with_live_limit(1);
    registry
        .admit(
            subject.clone(),
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
        )
        .unwrap_or_else(|error| panic!("admission: {error:?}"));
    let before = registry.declared_records();
    let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    registry
        .attach_host_value(
            &subject,
            owner,
            TransportValue {
                drops: Arc::clone(&drops),
                panic_on_drop: false,
                value: 7,
            },
        )
        .unwrap_or_else(|_| panic!("physical attachment"));
    assert_eq!(registry.declared_records(), before);
    assert_eq!(registry.live_resources(), 1);
    assert!(registry.has_host_value(&subject));
    let (error, returned) = *registry
        .attach_host_value(&subject, owner, 9_u64)
        .err()
        .unwrap_or_else(|| panic!("second attachment refuses"));
    assert_eq!(error, HostResourceError::AlreadyAttached);
    assert_eq!(returned, 9);
    assert_eq!(
        registry.invoke_host_value::<u64, ()>(&subject, owner, |_| panic!("wrong type cannot run")),
        Err(HostResourceError::TypeMismatch)
    );
    assert!(matches!(
        registry.invoke_host_value::<TransportValue, ()>(
            &subject,
            OwnerGeneration::new(3),
            |_| panic!("old owner cannot run")
        ),
        Err(HostResourceError::Model(ResourceError::StaleOwner { .. }))
    ));
    assert_eq!(
        registry.invoke_host_value::<TransportValue, u64>(&subject, owner, |value| Ok(value.value)),
        Ok(7)
    );
    assert_eq!(
        registry.dispose_host_value(&subject, owner),
        Err(HostResourceError::Model(
            ResourceError::IllegalLifetimeTransition
        ))
    );
    assert_eq!(registry.declared_records(), before);
    assert_eq!(
        registry.begin_finish(&subject, owner),
        Ok(ResourceLifetimeState::Finishing)
    );
    let finishing = registry.declared_records();
    assert_eq!(
        registry.complete_finalization(&subject, owner, 31),
        Err(ResourceRegistryRefusal::PhysicalValuePresent)
    );
    assert_eq!(registry.declared_records(), finishing);
    assert_eq!(registry.dispose_host_value(&subject, owner), Ok(()));
    assert_eq!(
        registry.live_resources(),
        1,
        "physical disposal alone releases no semantic quota"
    );
    assert_eq!(registry.dispose_host_value(&subject, owner), Ok(()));
    assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(
        registry.complete_finalization(&subject, owner, 31),
        Ok(ResourceLifetimeState::Finished)
    );
    assert_eq!(registry.live_resources(), 0);
    assert!(!registry.has_host_value(&subject));
    let sibling = declared_subject(SECOND_FIXTURE_DECLARATION);
    registry
        .admit(
            sibling,
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
        )
        .unwrap_or_else(|error| panic!("released live place: {error:?}"));
    assert_eq!(registry.live_resources(), 1);
    drop(registry);
    assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 1);
}

/// Failed physical destruction must not be relabeled as successful finalization.
#[test]
fn registry_host_failed_disposal_cannot_complete_finalization() {
    use gantry::runtime::HostResourceError;
    let subject = active_subject();
    let owner = OwnerGeneration::new(4);
    let mut registry = ResourceRegistry::with_live_limit(1);
    registry
        .admit(
            subject.clone(),
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
        )
        .unwrap_or_else(|error| panic!("admission: {error:?}"));
    let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    registry
        .attach_host_value(
            &subject,
            owner,
            TransportValue {
                drops: Arc::clone(&drops),
                panic_on_drop: true,
                value: 7,
            },
        )
        .unwrap_or_else(|_| panic!("attachment"));
    assert_eq!(
        registry.begin_finish(&subject, owner),
        Ok(ResourceLifetimeState::Finishing)
    );
    let before = registry.declared_records();
    assert!(matches!(
        registry.dispose_host_value(&subject, owner),
        Err(HostResourceError::Boundary(_))
    ));
    assert!(!registry.has_host_value(&subject));
    assert_eq!(
        registry.complete_finalization(&subject, owner, 31),
        Err(ResourceRegistryRefusal::PhysicalDisposalFailed),
        "absence after failed disposal is not successful finalization"
    );
    assert!(matches!(
        registry.dispose_host_value(&subject, owner),
        Err(HostResourceError::Boundary(_))
    ));
    assert_eq!(registry.declared_records(), before);
    assert_eq!(registry.live_resources(), 1);
    assert_eq!(
        registry.settle_from_emergency_cleanup(&subject, emergency_cleanup()),
        Ok(ResourceLifetimeState::EmergencyReleased)
    );
    assert_eq!(registry.live_resources(), 0);
    drop(registry);
    assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 1);
}

/// Emergency semantic release survives destruction failure; recovery never invents host values.
#[test]
fn registry_host_emergency_release_is_independent_of_disposal_and_recovery() {
    use gantry::runtime::HostResourceError;
    let subject = active_subject();
    let owner = OwnerGeneration::new(4);
    let mut registry = ResourceRegistry::with_live_limit(1);
    registry
        .admit(
            subject.clone(),
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
        )
        .unwrap_or_else(|error| panic!("admission: {error:?}"));
    let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    registry
        .attach_host_value(
            &subject,
            owner,
            TransportValue {
                drops: Arc::clone(&drops),
                panic_on_drop: true,
                value: 7,
            },
        )
        .unwrap_or_else(|_| panic!("attachment"));
    assert_eq!(
        registry.settle_from_emergency_cleanup(&subject, emergency_cleanup()),
        Ok(ResourceLifetimeState::EmergencyReleased)
    );
    assert_eq!(registry.live_resources(), 0);
    assert!(registry.has_host_value(&subject));
    assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 0);
    let records = registry.declared_records();
    let recovered = ResourceRegistry::reconstruct(Some(1), records.clone())
        .unwrap_or_else(|error| panic!("accounting recovery: {error:?}"));
    assert_eq!(recovered.declared_records(), records);
    assert!(!recovered.has_host_value(&subject));
    assert!(matches!(
        registry.dispose_host_value(&subject, owner),
        Err(HostResourceError::Boundary(_))
    ));
    assert!(!registry.has_host_value(&subject));
    assert_eq!(registry.declared_records(), records);
    assert_eq!(registry.live_resources(), 0);
    assert!(matches!(
        registry.dispose_host_value(&subject, owner),
        Err(HostResourceError::Boundary(_))
    ));
    drop(registry);
    assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 1);
}

/// Attachment refusals preserve inputs, and invocation panics poison only the selected slot.
#[test]
fn registry_host_refusals_preserve_inputs_and_contain_callback_destruction() {
    use gantry::runtime::HostResourceError;
    let subject = active_subject();
    let sibling = declared_subject(SECOND_FIXTURE_DECLARATION);
    let owner = OwnerGeneration::new(4);
    let mut registry = ResourceRegistry::with_live_limit(2);
    registry
        .admit(
            subject.clone(),
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
        )
        .unwrap_or_else(|error| panic!("admission: {error:?}"));
    let before = registry.declared_records();
    for (requested, presented, expected) in [
        (&sibling, owner, HostResourceError::UnknownSubject),
        (
            &subject,
            OwnerGeneration::new(3),
            HostResourceError::Model(ResourceError::StaleOwner {
                presented: OwnerGeneration::new(3),
                current: owner,
            }),
        ),
    ] {
        let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (error, returned) = *registry
            .attach_host_value(
                requested,
                presented,
                TransportValue {
                    drops: Arc::clone(&drops),
                    panic_on_drop: false,
                    value: 17,
                },
            )
            .err()
            .unwrap_or_else(|| panic!("attachment refuses"));
        assert_eq!(error, expected);
        assert_eq!(returned.value, 17);
        assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(registry.declared_records(), before);
        drop(returned);
        assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
    registry
        .attach_host_value(&subject, owner, 7_u64)
        .unwrap_or_else(|_| panic!("attach"));
    assert!(matches!(
        registry.invoke_host_value::<u64, ()>(&subject, owner, |_| panic!("integration panic")),
        Err(HostResourceError::Boundary(_))
    ));
    let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let captured = TransportValue {
        drops: Arc::clone(&drops),
        panic_on_drop: true,
        value: 1,
    };
    let called = std::cell::Cell::new(false);
    assert!(matches!(
        registry.invoke_host_value::<u64, ()>(&subject, owner, |_| {
            called.set(true);
            drop(captured);
            Ok(())
        }),
        Err(HostResourceError::Boundary(_))
    ));
    assert!(!called.get());
    assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(registry.declared_records(), before);
    registry
        .admit(
            sibling.clone(),
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
        )
        .unwrap_or_else(|error| panic!("sibling admission: {error:?}"));
    registry
        .attach_host_value(&sibling, owner, 9_u64)
        .unwrap_or_else(|_| panic!("sibling attach"));
    assert_eq!(
        registry.invoke_host_value::<u64, u64>(&sibling, owner, |value| Ok(*value)),
        Ok(9)
    );
    registry
        .settle_from_emergency_cleanup(&subject, emergency_cleanup())
        .unwrap_or_else(|error| panic!("release: {error:?}"));
    assert_eq!(registry.dispose_host_value(&subject, owner), Ok(()));
}

/// Deleted accounting cannot be reaped while its physical value still needs contained disposal.
#[test]
fn registry_host_record_reclamation_waits_for_physical_disposal() {
    let subject = active_subject();
    let owner = OwnerGeneration::new(4);
    let mut registry = ResourceRegistry::with_live_limit(1);
    registry
        .admit(
            subject.clone(),
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
        )
        .unwrap_or_else(|error| panic!("admission: {error:?}"));
    let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    registry
        .attach_host_value(
            &subject,
            owner,
            TransportValue {
                drops: Arc::clone(&drops),
                panic_on_drop: false,
                value: 1,
            },
        )
        .unwrap_or_else(|_| panic!("attachment"));
    registry
        .settle_from_emergency_cleanup(&subject, emergency_cleanup())
        .unwrap_or_else(|error| panic!("release: {error:?}"));
    for root in ROOTS {
        registry
            .close_liveness_root(&subject, owner, *root)
            .unwrap_or_else(|error| panic!("root closure: {error:?}"));
    }
    let fence = RetentionFence::new(2, 10).unwrap_or_else(|error| panic!("fence: {error:?}"));
    registry
        .retire(&subject, fence, owner, OwnerGeneration::new(5), 35)
        .unwrap_or_else(|error| panic!("retirement: {error:?}"));
    assert_eq!(
        registry.delete(&subject, owner),
        Ok(ResourceLifetimeState::Deleted)
    );
    assert_eq!(registry.reap_deleted(), 0);
    assert_eq!(registry.live_resources(), 0);
    assert!(registry.account(&subject).is_some());
    assert_eq!(registry.dispose_host_value(&subject, owner), Ok(()));
    assert_eq!(registry.reap_deleted(), 1);
    assert!(registry.account(&subject).is_none());
    assert!(!registry.has_host_value(&subject));
    assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 1);
}

/// Atomic acquisition retains one account and physical slot, with one pending settlement lease.
#[test]
fn atomic_host_admission_preserves_refused_inputs_and_complete_acquisition() {
    use gantry::runtime::HostResourceError;
    let (_, machine, subject) = machine_with_declared_subject(Some(FIXTURE_DECLARATION));
    let subject = subject.unwrap_or_else(|| panic!("subject exists"));
    let record = ledger().durable_record();
    let mut registry = ResourceRegistry::with_limits(1, 1);
    assert_eq!(
        registry.admit_host_value(
            subject.clone(),
            ResourceCarrier::ReconstructionRecord,
            record.clone(),
            17_u64
        ),
        Ok(())
    );
    assert_eq!(registry.live_resources(), 1);
    assert_eq!(registry.pending_operations(), 1);
    assert!(registry.has_host_value(&subject));
    assert_eq!(
        registry.invoke_host_value::<u64, u64>(&subject, record.owner(), |value| Ok(*value)),
        Ok(17)
    );
    assert!(machine.checkpoint().pending_operation().is_some());
    let before = registry.declared_records();
    let (error, value) = *registry
        .admit_host_value(
            subject.clone(),
            ResourceCarrier::ReconstructionRecord,
            record,
            19_u64,
        )
        .err()
        .unwrap_or_else(|| panic!("duplicate refuses"));
    assert_eq!(error, ResourceRegistryRefusal::SecondAdmission);
    assert_eq!(value, 19);
    assert_eq!(registry.declared_records(), before);
    assert_eq!(registry.pending_operations(), 1);
    assert_eq!(
        registry
            .invoke_host_value::<u64, u64>(&subject, OwnerGeneration::new(4), |value| Ok(*value)),
        Ok(17)
    );
    assert_eq!(
        registry.dispose_host_value(&subject, OwnerGeneration::new(4)),
        Err(HostResourceError::Model(
            ResourceError::IllegalLifetimeTransition
        ))
    );
}

/// Explicit acquisition charges cannot survive a refused physical ownership admission.
#[test]
fn charged_host_acquisition_preserves_inputs_and_commits_complete_accounting() {
    let (_, mut machine, subject) = machine_with_declared_subject(Some(FIXTURE_DECLARATION));
    let subject = subject.unwrap_or_else(|| panic!("subject"));
    let record = ledger().durable_record();
    let charge = Charge {
        owner: QuotaOwner::Owner,
        family: QuotaFamily::Bytes,
        amount: 2,
    };
    let mut registry = ResourceRegistry::with_limits(1, 1);
    for (vector, expected) in [
        (
            vec![
                charge,
                Charge {
                    family: QuotaFamily::Operations,
                    ..charge
                },
            ],
            ResourceError::UndeclaredQuota,
        ),
        (
            vec![Charge {
                amount: 9,
                ..charge
            }],
            ResourceError::QuotaExhausted,
        ),
    ] {
        let (error, returned) = *registry
            .admit_host_value_with_charges(
                subject.clone(),
                ResourceCarrier::ReconstructionRecord,
                record.clone(),
                17_u64,
                (ResourceAction::Move, &vector),
            )
            .err()
            .unwrap_or_else(|| panic!("quota vector must refuse"));
        assert_eq!(error, ResourceRegistryRefusal::Admission(expected));
        assert_eq!(returned, 17);
        assert!(registry.declared_records().is_empty());
        assert!(!registry.has_host_value(&subject));
        assert_eq!(registry.pending_operations(), 0);
    }
    assert_eq!(
        registry.admit_host_value_with_charges(
            subject.clone(),
            ResourceCarrier::ReconstructionRecord,
            record.clone(),
            17_u64,
            (ResourceAction::Move, &[charge]),
        ),
        Ok(())
    );
    let account = registry
        .account(&subject)
        .unwrap_or_else(|| panic!("account"));
    assert_eq!(
        account.remaining(QuotaOwner::Owner, QuotaFamily::Bytes),
        Some(6)
    );
    assert_eq!(registry.pending_operations(), 1);
    assert_eq!(
        registry.invoke_host_value::<u64, u64>(&subject, record.owner(), |value| Ok(*value)),
        Ok(17)
    );
    let before = registry.declared_records();
    let (error, returned) = *registry
        .admit_host_value_with_charges(
            subject.clone(),
            ResourceCarrier::ReconstructionRecord,
            record.clone(),
            19_u64,
            (
                ResourceAction::Copy,
                &[Charge {
                    amount: 9,
                    ..charge
                }],
            ),
        )
        .err()
        .unwrap_or_else(|| panic!("duplicate must refuse"));
    assert_eq!(error, ResourceRegistryRefusal::SecondAdmission);
    assert_eq!(returned, 19);
    assert_eq!(registry.declared_records(), before);
    assert!(machine.cancel("acquisition cancellation").is_some());
    let mut cancelled_registry = ResourceRegistry::with_limits(1, 1);
    let (error, returned) = *cancelled_registry
        .admit_host_value_with_charges(
            subject.clone(),
            ResourceCarrier::ReconstructionRecord,
            record,
            23_u64,
            (
                ResourceAction::Move,
                &[Charge {
                    amount: 9,
                    ..charge
                }],
            ),
        )
        .err()
        .unwrap_or_else(|| panic!("cancellation must refuse"));
    assert_eq!(error, ResourceRegistryRefusal::CancellationRequested);
    assert_eq!(returned, 23);
    assert!(cancelled_registry.declared_records().is_empty());
    assert_eq!(cancelled_registry.pending_operations(), 0);
}

/// Quota, cancellation and physical eligibility failures cannot leave a half-published account.
#[test]
fn atomic_host_admission_refusals_publish_no_account_slot_or_pending_capacity() {
    use gantry::runtime::HostResourceError;
    for (live_limit, pending_limit, cancel, closed, finishing, expected) in [
        (
            0,
            1,
            false,
            false,
            false,
            ResourceRegistryRefusal::LiveResourceLimitReached { limit: 0 },
        ),
        (
            1,
            0,
            false,
            false,
            false,
            ResourceRegistryRefusal::PendingOperationLimitReached { limit: 0 },
        ),
        (
            1,
            1,
            true,
            false,
            false,
            ResourceRegistryRefusal::CancellationRequested,
        ),
        (
            1,
            1,
            false,
            true,
            false,
            ResourceRegistryRefusal::PhysicalAdmission(HostResourceError::Model(
                ResourceError::IllegalLifetimeTransition,
            )),
        ),
        (
            1,
            1,
            false,
            false,
            true,
            ResourceRegistryRefusal::PhysicalAdmission(HostResourceError::Model(
                ResourceError::LifetimeDoesNotAdmitCharge {
                    state: ResourceLifetimeState::Finishing,
                },
            )),
        ),
    ] {
        let (_, mut machine, subject) = machine_with_declared_subject(Some(FIXTURE_DECLARATION));
        let subject = subject.unwrap_or_else(|| panic!("subject exists"));
        let mut source = ledger();
        if finishing {
            source
                .begin_finish()
                .unwrap_or_else(|error| panic!("finish: {error:?}"));
        }
        let source = source.durable_record();
        let record = DurableResourceRecord::from_durable_facts(
            source.owner(),
            source.lifetime(),
            if closed {
                ResourceState::Closed
            } else {
                source.operation_state()
            },
            source.quotas().clone(),
            source.liveness_roots().clone(),
            source.settlement(),
            source.successor_fence(),
        )
        .unwrap_or_else(|error| panic!("record: {error:?}"));
        if cancel {
            assert!(machine.cancel("atomic acquisition cancelled").is_some());
        }
        let mut registry = ResourceRegistry::with_limits(live_limit, pending_limit);
        let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (error, value) = *registry
            .admit_host_value(
                subject.clone(),
                ResourceCarrier::ReconstructionRecord,
                record,
                TransportValue {
                    drops: Arc::clone(&drops),
                    panic_on_drop: false,
                    value: 17,
                },
            )
            .err()
            .unwrap_or_else(|| panic!("ineligible acquisition refuses"));
        assert_eq!(error, expected);
        assert_eq!(value.value, 17);
        assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert!(registry.declared_records().is_empty());
        assert!(!registry.has_host_value(&subject));
        assert_eq!(registry.pending_operations(), 0);
        assert_eq!(registry.live_resources(), 0);
        assert!(machine.checkpoint().pending_operation().is_some());
        drop(value);
        assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
}

/// Atomic coordinator acquisition publishes once and returns refused values without new state.
#[test]
fn coordinator_atomic_host_admission_publishes_once_and_preserves_refusal() {
    use gantry::runtime::CoordinatorResourceRefusal;
    let (_, machine, subject) = machine_with_declared_subject(Some(FIXTURE_DECLARATION));
    let subject = subject.unwrap_or_else(|| panic!("subject exists"));
    let coordinator = resource_coordinator(machine.execution_id(), machine.task_id(), Some(1));
    let before = coordinator.snapshot();
    assert_eq!(
        coordinator.admit_resource_host_value(
            &machine,
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
            17_u64
        ),
        Ok(())
    );
    let acquired = coordinator.snapshot();
    assert_eq!(acquired.publication(), before.publication() + 1);
    assert_eq!(
        acquired
            .resource_records()
            .unwrap_or_else(|| panic!("records"))
            .len(),
        1
    );
    assert!(coordinator.has_resource_host_values());
    assert!(coordinator.has_pending_resource_operations());
    let (error, value) = *coordinator
        .clone()
        .admit_resource_host_value(
            &machine,
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
            19_u64,
        )
        .err()
        .unwrap_or_else(|| panic!("duplicate refuses"));
    assert_eq!(
        error,
        CoordinatorResourceRefusal::Registry(ResourceRegistryRefusal::SecondAdmission)
    );
    assert_eq!(value, 19);
    assert_eq!(coordinator.snapshot(), acquired);
    assert!(coordinator.close_resource_admission());
    let (error, value) = *coordinator
        .admit_resource_host_value(
            &machine,
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
            21_u64,
        )
        .err()
        .unwrap_or_else(|| panic!("closure refuses"));
    assert_eq!(error, CoordinatorResourceRefusal::ResourceAdmissionClosed);
    assert_eq!(value, 21);
    assert_eq!(coordinator.snapshot(), acquired);
    assert_eq!(
        coordinator.begin_resource_finish(&subject, OwnerGeneration::new(4)),
        Ok(ResourceLifetimeState::Finishing)
    );
    assert_eq!(
        coordinator.dispose_resource_host_value(&subject, OwnerGeneration::new(4)),
        Ok(())
    );
}

/// Coordinator cancellation refuses complete acquisition without consuming the physical input.
#[test]
fn coordinator_atomic_host_admission_refuses_requested_cancellation() {
    use gantry::runtime::CoordinatorResourceRefusal;
    let (_, machine, _) = machine_with_declared_subject(Some(FIXTURE_DECLARATION));
    let coordinator = resource_coordinator(machine.execution_id(), machine.task_id(), Some(1));
    coordinator
        .cancel_execution(Arc::from("atomic acquisition cancelled"))
        .unwrap_or_else(|error| panic!("cancel: {error:?}"));
    let before = coordinator.snapshot();
    let (error, value) = *coordinator
        .admit_resource_host_value(
            &machine,
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
            17_u64,
        )
        .err()
        .unwrap_or_else(|| panic!("cancelled acquisition refuses"));
    assert_eq!(error, CoordinatorResourceRefusal::TaskCancellationRequested);
    assert_eq!(value, 17);
    assert_eq!(coordinator.snapshot(), before);
    assert!(!coordinator.has_resource_host_values());
    assert!(!coordinator.has_pending_resource_operations());
}

/// Cancellation and acquisition linearize to either a complete acquisition or no acquisition.
#[test]
fn coordinator_atomic_host_admission_cancellation_race_never_splits_acquisition() {
    use gantry::runtime::CoordinatorResourceRefusal;
    for _ in 0..32 {
        let (_, machine, _) = machine_with_declared_subject(Some(FIXTURE_DECLARATION));
        let coordinator = resource_coordinator(machine.execution_id(), machine.task_id(), Some(1));
        let before = coordinator.snapshot();
        let barrier = std::sync::Barrier::new(2);
        let result = std::thread::scope(|scope| {
            let acquisition = scope.spawn(|| {
                barrier.wait();
                coordinator.admit_resource_host_value(
                    &machine,
                    ResourceCarrier::ReconstructionRecord,
                    ledger().durable_record(),
                    17_u64,
                )
            });
            barrier.wait();
            coordinator
                .cancel_execution(Arc::from("atomic race cancellation"))
                .unwrap_or_else(|error| panic!("cancel: {error:?}"));
            acquisition
                .join()
                .unwrap_or_else(|_| panic!("acquisition thread"))
        });
        let after = coordinator.snapshot();
        match result {
            Ok(()) => {
                assert_eq!(after.resource_records().map(<[_]>::len), Some(1));
                assert!(coordinator.has_resource_host_values());
                assert!(coordinator.has_pending_resource_operations());
                assert_eq!(after.publication(), before.publication() + 2);
            }
            Err(refusal) => {
                let (error, value) = *refusal;
                assert_eq!(error, CoordinatorResourceRefusal::TaskCancellationRequested);
                assert_eq!(value, 17);
                assert_eq!(after.resource_records().map(<[_]>::len), Some(0));
                assert!(!coordinator.has_resource_host_values());
                assert!(!coordinator.has_pending_resource_operations());
                assert_eq!(after.publication(), before.publication() + 1);
            }
        }
        assert!(machine.checkpoint().pending_operation().is_some());
    }
}

/// Machine-local cancellation shares the acquisition lease even without coordinator cancellation.
#[test]
fn atomic_host_admission_machine_cancellation_race_never_splits_acquisition() {
    for _ in 0..32 {
        let (_, mut machine, subject) = machine_with_declared_subject(Some(FIXTURE_DECLARATION));
        let subject = subject.unwrap_or_else(|| panic!("subject exists"));
        let mut registry = ResourceRegistry::with_limits(1, 1);
        let barrier = std::sync::Barrier::new(2);
        let result = std::thread::scope(|scope| {
            let acquisition = scope.spawn(|| {
                barrier.wait();
                registry.admit_host_value(
                    subject.clone(),
                    ResourceCarrier::ReconstructionRecord,
                    ledger().durable_record(),
                    17_u64,
                )
            });
            barrier.wait();
            assert!(machine.cancel("machine acquisition race").is_some());
            acquisition
                .join()
                .unwrap_or_else(|_| panic!("acquisition thread"))
        });
        match result {
            Ok(()) => {
                assert_eq!(registry.declared_records().len(), 1);
                assert!(registry.has_host_value(&subject));
                assert_eq!(registry.pending_operations(), 1);
            }
            Err(refusal) => {
                let (error, value) = *refusal;
                assert_eq!(error, ResourceRegistryRefusal::CancellationRequested);
                assert_eq!(value, 17);
                assert!(registry.declared_records().is_empty());
                assert!(!registry.has_host_value(&subject));
                assert_eq!(registry.pending_operations(), 0);
            }
        }
        assert!(machine.checkpoint().pending_operation().is_some());
    }
}

/// Refused physical inputs remain caller-owned and can reenter coordinator inspection on drop.
#[test]
fn coordinator_atomic_host_admission_returns_refused_destructor_outside_lock() {
    let (_, machine, _) = machine_with_declared_subject(Some(FIXTURE_DECLARATION));
    let coordinator = resource_coordinator(machine.execution_id(), machine.task_id(), Some(0));
    let entered = Arc::new(std::sync::Barrier::new(2));
    let release = Arc::new(std::sync::Barrier::new(2));
    let unlocked = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let before = coordinator.snapshot();
    let (error, value) = *coordinator
        .admit_resource_host_value(
            &machine,
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
            CoordinatorDropProbe {
                coordinator: coordinator.clone(),
                entered: Arc::clone(&entered),
                release: Arc::clone(&release),
                unlocked: Arc::clone(&unlocked),
                drops: Arc::clone(&drops),
            },
        )
        .err()
        .unwrap_or_else(|| panic!("zero live quota refuses"));
    assert_eq!(
        error,
        gantry::runtime::CoordinatorResourceRefusal::Registry(
            ResourceRegistryRefusal::LiveResourceLimitReached { limit: 0 }
        )
    );
    assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 0);
    std::thread::scope(|scope| {
        let destructor = scope.spawn(|| drop(value));
        entered.wait();
        let observed = unlocked.load(std::sync::atomic::Ordering::SeqCst);
        release.wait();
        destructor
            .join()
            .unwrap_or_else(|_| panic!("destructor thread"));
        assert!(observed);
    });
    assert_eq!(coordinator.snapshot(), before);
    assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 1);
}

/// Same-task owner advancement retains physical identity and rejects outstanding obligations.
#[test]
fn registry_owner_advancement_preserves_physical_ownership_and_fences_old_owners() {
    use gantry::runtime::HostResourceError;
    let (_, mut machine, subject) = machine_with_declared_subject(Some(FIXTURE_DECLARATION));
    let subject = subject.unwrap_or_else(|| panic!("subject exists"));
    let owner = OwnerGeneration::new(4);
    let successor = OwnerGeneration::new(5);
    let record = ResourceLedger::new(owner, ResourceState::Usable, &[LivenessRoot::Resource], &[])
        .unwrap_or_else(|error| panic!("record: {error:?}"))
        .durable_record();
    let mut registry = ResourceRegistry::with_limits(1, 1);
    registry
        .admit(
            subject.clone(),
            ResourceCarrier::ReconstructionRecord,
            record.clone(),
        )
        .unwrap_or_else(|error| panic!("admit: {error:?}"));
    registry
        .attach_host_value(&subject, owner, 17_u64)
        .unwrap_or_else(|_| panic!("attach"));
    let before = registry.declared_records();
    assert_eq!(
        registry.advance_owner(&subject, owner, successor),
        Err(ResourceRegistryRefusal::OwnershipTransfer(
            HostResourceError::PendingOperation
        ))
    );
    assert_eq!(registry.declared_records(), before);
    let operation = machine
        .checkpoint()
        .pending_operation()
        .unwrap_or_else(|| panic!("pending"))
        .identity;
    machine
        .fail_operation(
            operation,
            gantry::portable::RuntimeErrorCategory::ExecutorFailure,
        )
        .unwrap_or_else(|error| panic!("settle: {error:?}"));
    assert_eq!(
        registry.advance_owner(&subject, owner, successor),
        Err(ResourceRegistryRefusal::OwnershipTransfer(
            HostResourceError::ContainmentPending
        ))
    );
    assert_eq!(registry.declared_records(), before);
    registry
        .settle_containment(
            &subject,
            owner,
            Completion::observed(ExternalOutcome::Accepted, EffectState::NotStarted),
        )
        .unwrap_or_else(|error| panic!("containment: {error:?}"));
    assert_eq!(
        registry.advance_owner(&subject, owner, owner),
        Err(ResourceRegistryRefusal::OwnershipTransfer(
            HostResourceError::Model(ResourceError::InvalidSuccessorGeneration)
        ))
    );
    assert_eq!(registry.advance_owner(&subject, owner, successor), Ok(()));
    let account = registry
        .account(&subject)
        .unwrap_or_else(|| panic!("account"));
    let after = account.durable_record();
    assert_eq!(after.owner(), successor);
    assert_eq!(after.quotas(), record.quotas());
    assert_eq!(after.liveness_roots(), record.liveness_roots());
    assert_eq!(after.lifetime(), record.lifetime());
    assert_eq!(after.operation_state(), record.operation_state());
    assert_eq!(account.subject(), &subject);
    assert_eq!(account.containment().owner(), owner);
    assert_eq!(
        account.containment().outcome(),
        Some(ExternalOutcome::Accepted)
    );
    assert_eq!(registry.live_resources(), 1);
    assert_eq!(registry.pending_operations(), 0);
    assert!(registry.has_host_value(&subject));
    assert!(matches!(
        registry.invoke_host_value::<u64, ()>(&subject, owner, |_| panic!("stale")),
        Err(HostResourceError::Model(ResourceError::StaleOwner { .. }))
    ));
    assert_eq!(
        registry.invoke_host_value::<u64, u64>(&subject, successor, |value| Ok(*value)),
        Ok(17)
    );
    let before_poison = registry.declared_records();
    assert!(matches!(
        registry.invoke_host_value::<u64, ()>(&subject, successor, |_| panic!("poison")),
        Err(HostResourceError::Boundary(_))
    ));
    assert_eq!(
        registry.advance_owner(&subject, successor, OwnerGeneration::new(6)),
        Err(ResourceRegistryRefusal::OwnershipTransfer(
            HostResourceError::TransportPoisoned
        ))
    );
    assert_eq!(registry.declared_records(), before_poison);
}

/// Coordinator-held advancement publishes once and stale or unfinished attempts publish nothing.
#[test]
fn coordinator_owner_advancement_and_containment_preserve_publication_boundaries() {
    use gantry::runtime::{CoordinatorResourceRefusal, HostResourceError};
    let (_, mut machine, subject) = machine_with_declared_subject(Some(FIXTURE_DECLARATION));
    let subject = subject.unwrap_or_else(|| panic!("subject exists"));
    let coordinator = resource_coordinator(machine.execution_id(), machine.task_id(), Some(1));
    let owner = OwnerGeneration::new(4);
    let successor = OwnerGeneration::new(5);
    let record = ResourceLedger::new(owner, ResourceState::Usable, &[LivenessRoot::Resource], &[])
        .unwrap_or_else(|error| panic!("record: {error:?}"))
        .durable_record();
    coordinator
        .admit_resource(&machine, ResourceCarrier::ReconstructionRecord, record)
        .unwrap_or_else(|error| panic!("admit: {error:?}"));
    let before = coordinator.snapshot();
    assert_eq!(
        coordinator.advance_resource_owner(&subject, owner, successor),
        Err(CoordinatorResourceRefusal::Registry(
            ResourceRegistryRefusal::OwnershipTransfer(HostResourceError::PendingOperation)
        ))
    );
    assert_eq!(coordinator.snapshot(), before);
    let operation = machine
        .checkpoint()
        .pending_operation()
        .unwrap_or_else(|| panic!("pending"))
        .identity;
    machine
        .fail_operation(
            operation,
            gantry::portable::RuntimeErrorCategory::ExecutorFailure,
        )
        .unwrap_or_else(|error| panic!("settle: {error:?}"));
    assert_eq!(
        coordinator.settle_resource_containment(
            &subject,
            owner,
            Completion::observed(ExternalOutcome::Accepted, EffectState::NotStarted)
        ),
        Ok(ExternalOutcome::Accepted)
    );
    let contained = coordinator.snapshot();
    assert_eq!(contained.publication(), before.publication() + 1);
    assert_eq!(
        coordinator
            .clone()
            .advance_resource_owner(&subject, owner, successor),
        Ok(())
    );
    let advanced = coordinator.snapshot();
    assert_eq!(advanced.publication(), contained.publication() + 1);
    assert_eq!(
        advanced
            .resource_records()
            .unwrap_or_else(|| panic!("records"))[0]
            .owner(),
        successor
    );
    assert!(matches!(
        coordinator.advance_resource_owner(&subject, owner, OwnerGeneration::new(6)),
        Err(CoordinatorResourceRefusal::Registry(
            ResourceRegistryRefusal::OwnershipTransfer(HostResourceError::Model(
                ResourceError::StaleOwner { .. }
            ))
        ))
    ));
    assert_eq!(coordinator.snapshot(), advanced);
}

/// Builds one running child alongside the issuing root for runtime resource handoff tests.
fn resource_handoff_fixture(
    machine: &Machine,
) -> (
    gantry::runtime::ExecutionCoordinator,
    ProtocolIdentity,
    gantry::runtime::ConcurrentTaskStateV1,
    gantry::runtime::LogicalSessionRegistryV1,
) {
    let (_, mut sessions) = resource_recovery_inputs(machine.execution_id(), machine.task_id());
    let mut tasks =
        gantry::runtime::ConcurrentTaskStateV1::new(machine.execution_id(), machine.task_id(), 2)
            .unwrap_or_else(|error| panic!("tasks: {error:?}"));
    let session = sessions
        .sessions()
        .next()
        .unwrap_or_else(|| panic!("root session"))
        .id;
    let child = tasks
        .create_child(
            &mut sessions,
            gantry::runtime::TaskCreationRequestV1 {
                parent_task_id: machine.task_id(),
                handle_name: Arc::from("resource_owner"),
                workflow: CanonicalPath::new(FIXTURE_WORKFLOW)
                    .unwrap_or_else(|error| panic!("path: {error}")),
                spawn_site: StructuralPosition::new(vec![0])
                    .unwrap_or_else(|error| panic!("site: {error}")),
                spawn_occurrence: 0,
                result_type: TypeDescriptor::UNIT,
                captures: Vec::new(),
                inherited_agent: None,
                parent_session_id: session,
            },
            DEFAULT_VALUE_LIMITS,
        )
        .unwrap_or_else(|error| panic!("child: {error:?}"));
    tasks
        .resolve_submission(child.task_id, Ok(()))
        .unwrap_or_else(|error| panic!("submit: {error:?}"));
    let coordinator = gantry::runtime::ExecutionCoordinator::new_with_resource_limit(
        tasks.clone(),
        sessions.clone(),
        1,
    )
    .unwrap_or_else(|error| panic!("coordinator: {error:?}"));
    (coordinator, child.task_id, tasks, sessions)
}

/// Handoff changes cleanup ownership, never issuing provenance or physical ownership.
#[test]
fn resource_task_handoff_preserves_provenance_recovery_and_cleanup_selection() {
    use gantry::runtime::{CoordinatorResourceRefusal, ExecutionCoordinator};
    let (_, mut machine, subject) = machine_with_declared_subject(Some(FIXTURE_DECLARATION));
    let subject = subject.unwrap_or_else(|| panic!("subject"));
    let (coordinator, child, tasks, sessions) = resource_handoff_fixture(&machine);
    let owner = OwnerGeneration::new(4);
    let record = ResourceLedger::new(owner, ResourceState::Usable, &[LivenessRoot::Resource], &[])
        .unwrap_or_else(|error| panic!("ledger: {error:?}"))
        .durable_record();
    let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    coordinator
        .admit_resource_host_value(
            &machine,
            ResourceCarrier::ReconstructionRecord,
            record.clone(),
            TransportValue {
                drops: Arc::clone(&drops),
                panic_on_drop: false,
                value: 17,
            },
        )
        .unwrap_or_else(|_| panic!("acquisition"));
    let operation = machine
        .checkpoint()
        .pending_operation()
        .unwrap_or_else(|| panic!("pending"))
        .identity;
    machine
        .fail_operation(
            operation,
            gantry::portable::RuntimeErrorCategory::ExecutorFailure,
        )
        .unwrap_or_else(|error| panic!("settle: {error:?}"));
    coordinator
        .settle_resource_containment(
            &subject,
            owner,
            Completion::observed(ExternalOutcome::Accepted, EffectState::NotStarted),
        )
        .unwrap_or_else(|error| panic!("containment: {error:?}"));
    let before = coordinator.snapshot();
    assert_eq!(
        coordinator.transfer_resource_task_owner(
            &subject,
            machine.task_id(),
            child,
            owner,
            OwnerGeneration::new(5)
        ),
        Ok(())
    );
    let after = coordinator.snapshot();
    assert_eq!(after.publication(), before.publication() + 1);
    let records = after
        .resource_records()
        .unwrap_or_else(|| panic!("records"));
    assert_eq!(records[0].subject(), &subject);
    assert_eq!(records[0].task_owner(), child);
    assert_eq!(records[0].owner(), OwnerGeneration::new(5));
    assert_eq!(records[0].record().quotas(), record.quotas());
    assert_eq!(
        records[0].record().liveness_roots(),
        record.liveness_roots()
    );
    assert!(coordinator.has_resource_host_values());
    assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert!(matches!(
        coordinator.transfer_resource_task_owner(
            &subject,
            machine.task_id(),
            child,
            OwnerGeneration::new(5),
            OwnerGeneration::new(6)
        ),
        Err(CoordinatorResourceRefusal::Registry(
            ResourceRegistryRefusal::TaskOwnerMismatch
        ))
    ));
    assert_eq!(coordinator.snapshot(), after);
    let recovered =
        ExecutionCoordinator::new_with_recovered_resources(tasks, sessions, 1, records.to_vec())
            .unwrap_or_else(|error| panic!("reconstruction: {error:?}"));
    assert_eq!(recovered.snapshot().resource_records(), Some(records));
    assert!(!recovered.has_resource_host_values());
    assert!(!recovered.has_pending_resource_operations());
    coordinator
        .cancel_execution("handoff cleanup")
        .unwrap_or_else(|error| panic!("cancel: {error:?}"));
    for task in [machine.task_id(), child] {
        coordinator
            .settle_task(
                task,
                MachineOutcome::Cancelled(Arc::from("handoff cleanup")),
            )
            .unwrap_or_else(|error| panic!("task settlement: {error:?}"));
        coordinator
            .mark_driver_physically_settled(task)
            .unwrap_or_else(|error| panic!("driver: {error:?}"));
    }
    let issuing_cleanup = coordinator
        .emergency_release_task_resources(&[machine.task_id()], emergency_escalation_at(21))
        .unwrap_or_else(|error| panic!("issuing cleanup: {error:?}"));
    assert!(issuing_cleanup.semantic().settled().is_empty());
    assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 0);
    let current_cleanup = coordinator
        .emergency_release_task_resources(&[child], emergency_escalation_at(21))
        .unwrap_or_else(|error| panic!("owner cleanup: {error:?}"));
    assert_eq!(current_cleanup.semantic().settled().len(), 1);
    assert_eq!(current_cleanup.semantic().settled()[0].subject(), &subject);
    assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 1);
}

/// Move charges commit together with cleanup ownership and one coordinator publication.
#[test]
fn charged_task_handoff_preserves_refusal_and_recovered_quota_use() {
    use gantry::runtime::{CoordinatorResourceRefusal, ExecutionCoordinator, HostResourceError};
    let (_, mut machine, subject) = machine_with_declared_subject(Some(FIXTURE_DECLARATION));
    let subject = subject.unwrap_or_else(|| panic!("subject"));
    let (coordinator, child, tasks, sessions) = resource_handoff_fixture(&machine);
    let owner = OwnerGeneration::new(4);
    let successor = OwnerGeneration::new(5);
    let record = ResourceLedger::new(
        owner,
        ResourceState::Usable,
        &[LivenessRoot::Resource],
        &[(QuotaOwner::Owner, QuotaFamily::Bytes, Quota::new(8, 0))],
    )
    .unwrap_or_else(|error| panic!("ledger: {error:?}"));
    coordinator
        .admit_resource_host_value(
            &machine,
            ResourceCarrier::ReconstructionRecord,
            record.durable_record(),
            17_u64,
        )
        .unwrap_or_else(|_| panic!("admission"));
    let operation = machine
        .checkpoint()
        .pending_operation()
        .unwrap_or_else(|| panic!("pending"))
        .identity;
    machine
        .fail_operation(
            operation,
            gantry::portable::RuntimeErrorCategory::ExecutorFailure,
        )
        .unwrap_or_else(|error| panic!("settle: {error:?}"));
    coordinator
        .settle_resource_containment(
            &subject,
            owner,
            Completion::observed(ExternalOutcome::Accepted, EffectState::NotStarted),
        )
        .unwrap_or_else(|error| panic!("containment: {error:?}"));
    let charges = [Charge {
        owner: QuotaOwner::Owner,
        family: QuotaFamily::Bytes,
        amount: 2,
    }];
    let before = coordinator.snapshot();
    for (destination, vector, expected) in [
        (
            machine.task_id(),
            vec![Charge {
                amount: 9,
                ..charges[0]
            }],
            CoordinatorResourceRefusal::SameTaskTransfer,
        ),
        (
            child,
            vec![
                charges[0],
                Charge {
                    family: QuotaFamily::Operations,
                    ..charges[0]
                },
            ],
            CoordinatorResourceRefusal::Registry(ResourceRegistryRefusal::OwnershipTransfer(
                HostResourceError::Model(ResourceError::UndeclaredQuota),
            )),
        ),
        (
            child,
            vec![Charge {
                amount: 9,
                ..charges[0]
            }],
            CoordinatorResourceRefusal::Registry(ResourceRegistryRefusal::OwnershipTransfer(
                HostResourceError::Model(ResourceError::QuotaExhausted),
            )),
        ),
    ] {
        assert_eq!(
            coordinator.transfer_resource_task_owner_with_charges(
                &subject,
                machine.task_id(),
                destination,
                (owner, successor),
                &vector
            ),
            Err(expected)
        );
        assert_eq!(coordinator.snapshot(), before);
        assert!(coordinator.has_resource_host_values());
    }
    assert_eq!(
        coordinator.transfer_resource_task_owner_with_charges(
            &subject,
            machine.task_id(),
            child,
            (owner, successor),
            &charges
        ),
        Ok(())
    );
    let after = coordinator.snapshot();
    assert_eq!(after.publication(), before.publication() + 1);
    let records = after
        .resource_records()
        .unwrap_or_else(|| panic!("records"));
    assert_eq!(records[0].subject(), &subject);
    assert_eq!(records[0].owner(), successor);
    assert_eq!(records[0].task_owner(), child);
    assert_eq!(
        records[0].record().quotas()[&(QuotaOwner::Owner, QuotaFamily::Bytes)].used(),
        2
    );
    assert_eq!(
        records[0].record().liveness_roots(),
        record.liveness_roots()
    );
    let recovered =
        ExecutionCoordinator::new_with_recovered_resources(tasks, sessions, 1, records.to_vec())
            .unwrap_or_else(|error| panic!("reconstruction: {error:?}"));
    assert_eq!(recovered.snapshot().resource_records(), Some(records));
    assert!(!recovered.has_resource_host_values());
    assert!(!recovered.has_pending_resource_operations());
}

/// Handoff refusals never publish a partial owner change or consume pending work.
#[test]
fn resource_task_handoff_refuses_ineligible_tasks_and_outstanding_work() {
    use gantry::runtime::{CoordinatorResourceRefusal, HostResourceError};
    let (_, mut machine, subject) = machine_with_declared_subject(Some(FIXTURE_DECLARATION));
    let subject = subject.unwrap_or_else(|| panic!("subject"));
    let (coordinator, child, _, _) = resource_handoff_fixture(&machine);
    let owner = OwnerGeneration::new(4);
    let successor = OwnerGeneration::new(5);
    let record = ResourceLedger::new(owner, ResourceState::Usable, &[LivenessRoot::Resource], &[])
        .unwrap_or_else(|error| panic!("ledger: {error:?}"))
        .durable_record();
    coordinator
        .admit_resource(&machine, ResourceCarrier::ReconstructionRecord, record)
        .unwrap_or_else(|error| panic!("admit: {error:?}"));
    let before = coordinator.snapshot();
    let unknown = ProtocolIdentity::derive(IdentityKind::Task, b"unknown-handoff-task")
        .unwrap_or_else(|error| panic!("identity: {error}"));
    for (source, destination, expected) in [
        (
            machine.task_id(),
            machine.task_id(),
            CoordinatorResourceRefusal::SameTaskTransfer,
        ),
        (
            machine.task_id(),
            unknown,
            CoordinatorResourceRefusal::UnknownTask,
        ),
        (
            machine.task_id(),
            child,
            CoordinatorResourceRefusal::Registry(ResourceRegistryRefusal::OwnershipTransfer(
                HostResourceError::PendingOperation,
            )),
        ),
    ] {
        assert_eq!(
            coordinator.transfer_resource_task_owner(
                &subject,
                source,
                destination,
                owner,
                successor
            ),
            Err(expected)
        );
        assert_eq!(coordinator.snapshot(), before);
    }
    let operation = machine
        .checkpoint()
        .pending_operation()
        .unwrap_or_else(|| panic!("pending"))
        .identity;
    machine
        .fail_operation(
            operation,
            gantry::portable::RuntimeErrorCategory::ExecutorFailure,
        )
        .unwrap_or_else(|error| panic!("settle: {error:?}"));
    assert_eq!(
        coordinator.transfer_resource_task_owner(
            &subject,
            machine.task_id(),
            child,
            owner,
            successor
        ),
        Err(CoordinatorResourceRefusal::Registry(
            ResourceRegistryRefusal::OwnershipTransfer(HostResourceError::ContainmentPending)
        ))
    );
    assert_eq!(coordinator.snapshot(), before);
    coordinator
        .settle_resource_containment(
            &subject,
            owner,
            Completion::observed(ExternalOutcome::Accepted, EffectState::NotStarted),
        )
        .unwrap_or_else(|error| panic!("containment: {error:?}"));
    let contained = coordinator.snapshot();
    assert!(matches!(
        coordinator.transfer_resource_task_owner(
            &subject,
            machine.task_id(),
            child,
            OwnerGeneration::new(3),
            successor
        ),
        Err(CoordinatorResourceRefusal::Registry(
            ResourceRegistryRefusal::OwnershipTransfer(HostResourceError::Model(
                ResourceError::StaleOwner { .. }
            ))
        ))
    ));
    assert_eq!(coordinator.snapshot(), contained);
    assert!(coordinator.close_resource_admission());
    assert_eq!(
        coordinator.transfer_resource_task_owner(
            &subject,
            machine.task_id(),
            child,
            owner,
            successor
        ),
        Err(CoordinatorResourceRefusal::ResourceAdmissionClosed)
    );
    assert_eq!(coordinator.snapshot(), contained);
}

/// Attachment after handoff follows the current task even after the issuing task settles.
#[test]
fn resource_task_handoff_attachment_uses_current_cleanup_task() {
    use gantry::runtime::CoordinatorResourceRefusal;
    let (program, mut machine, subject) = machine_with_declared_subject(Some(FIXTURE_DECLARATION));
    let subject = subject.unwrap_or_else(|| panic!("subject"));
    let (coordinator, child, tasks, sessions) = resource_handoff_fixture(&machine);
    let owner = OwnerGeneration::new(4);
    let issuing_bytes = machine.checkpoint().canonical_bytes();
    let issuing_budget = machine.budget_checkpoint();
    coordinator
        .admit_resource_with_issuing_evidence(
            &machine,
            ResourceCarrier::ReconstructionRecord,
            ResourceLedger::new(owner, ResourceState::Usable, &[LivenessRoot::Resource], &[])
                .unwrap_or_else(|error| panic!("ledger: {error:?}"))
                .durable_record(),
            65_536,
        )
        .unwrap_or_else(|error| panic!("admit: {error:?}"));
    let operation = machine
        .checkpoint()
        .pending_operation()
        .unwrap_or_else(|| panic!("pending"))
        .identity;
    machine
        .fail_operation(
            operation,
            gantry::portable::RuntimeErrorCategory::ExecutorFailure,
        )
        .unwrap_or_else(|error| panic!("settle: {error:?}"));
    coordinator
        .settle_resource_containment(
            &subject,
            owner,
            Completion::observed(ExternalOutcome::Accepted, EffectState::NotStarted),
        )
        .unwrap_or_else(|error| panic!("containment: {error:?}"));
    coordinator
        .transfer_resource_task_owner(
            &subject,
            machine.task_id(),
            child,
            owner,
            OwnerGeneration::new(5),
        )
        .unwrap_or_else(|error| panic!("handoff: {error:?}"));
    let records = coordinator
        .snapshot()
        .resource_records()
        .unwrap_or_else(|| panic!("records"))
        .to_vec();
    let (root_only, root_sessions) =
        resource_recovery_inputs(machine.execution_id(), machine.task_id());
    assert_eq!(
        records[0].issuing_evidence(),
        Some((issuing_bytes.as_slice(), issuing_budget))
    );
    let envelope = gantry::runtime::encode_resource_recovery_envelope(&records[0], 65_536)
        .unwrap_or_else(|error| panic!("transferred envelope: {error:?}"));
    let decoded = gantry::runtime::decode_resource_recovery_envelope(
        program,
        &envelope,
        65_536,
        OwnerGeneration::new(5),
        child,
    )
    .unwrap_or_else(|error| panic!("transferred reconstruction: {error:?}"));
    assert_eq!(decoded, records[0]);
    assert_eq!(decoded.subject().task_id(), machine.task_id());
    assert_eq!(decoded.task_owner(), child);
    assert_eq!(
        gantry::runtime::ExecutionCoordinator::new_with_recovered_resources(
            root_only,
            root_sessions,
            1,
            records.clone()
        )
        .err(),
        Some(CoordinatorResourceRefusal::UnknownTask),
        "reconstruction validates the cleanup task too"
    );
    let reconstructed = gantry::runtime::ExecutionCoordinator::new_with_recovered_resources(
        tasks,
        sessions,
        1,
        vec![decoded],
    )
    .unwrap_or_else(|error| panic!("reconstruct: {error:?}"));
    reconstructed
        .settle_task(
            machine.task_id(),
            MachineOutcome::Succeeded(LogicalValue::unit()),
        )
        .unwrap_or_else(|error| panic!("root settlement: {error:?}"));
    assert_eq!(
        reconstructed.attach_resource_host_value(&subject, OwnerGeneration::new(5), 17_u64),
        Ok(())
    );
    reconstructed
        .begin_resource_finish(&subject, OwnerGeneration::new(5))
        .unwrap_or_else(|error| panic!("finish: {error:?}"));
    assert_eq!(
        reconstructed.dispose_resource_host_value(&subject, OwnerGeneration::new(5)),
        Ok(())
    );
    coordinator
        .cancel_task_tree(child, Arc::from("destination cancelled"))
        .unwrap_or_else(|error| panic!("cancel: {error:?}"));
    let before = coordinator.snapshot();
    let (error, value) = *coordinator
        .attach_resource_host_value(&subject, OwnerGeneration::new(5), 19_u64)
        .err()
        .unwrap_or_else(|| panic!("cancelled cleanup task refuses attachment"));
    assert_eq!(error, CoordinatorResourceRefusal::TaskCancellationRequested);
    assert_eq!(value, 19);
    assert_eq!(coordinator.snapshot(), before);
    assert_eq!(
        coordinator.transfer_resource_task_owner(
            &subject,
            child,
            machine.task_id(),
            OwnerGeneration::new(5),
            OwnerGeneration::new(6)
        ),
        Err(CoordinatorResourceRefusal::TaskCancellationRequested)
    );
    assert_eq!(coordinator.snapshot(), before);
}

/// The registry route retains every accounting obligation before advancing an owner.
#[test]
fn registry_owner_advancement_refuses_loan_adapter_and_ineligible_accounting() {
    use gantry::runtime::HostResourceError;
    for (state, loan, adapter, finishing, expected) in [
        (
            ResourceState::Usable,
            true,
            false,
            false,
            HostResourceError::LoanOutstanding,
        ),
        (
            ResourceState::Usable,
            false,
            true,
            false,
            HostResourceError::AdapterBound,
        ),
        (
            ResourceState::Closed,
            false,
            false,
            false,
            HostResourceError::Model(ResourceError::IllegalLifetimeTransition),
        ),
        (
            ResourceState::Usable,
            false,
            false,
            true,
            HostResourceError::Model(ResourceError::IllegalLifetimeTransition),
        ),
    ] {
        let (_, mut machine, subject) = machine_with_declared_subject(Some(FIXTURE_DECLARATION));
        let subject = subject.unwrap_or_else(|| panic!("subject exists"));
        let owner = OwnerGeneration::new(4);
        let roots = if loan {
            vec![LivenessRoot::Resource, LivenessRoot::Loan]
        } else {
            vec![LivenessRoot::Resource]
        };
        let record = ResourceLedger::new(owner, state, &roots, &[])
            .unwrap_or_else(|error| panic!("record: {error:?}"))
            .durable_record();
        let mut registry = ResourceRegistry::new();
        registry
            .admit(
                subject.clone(),
                ResourceCarrier::ReconstructionRecord,
                record,
            )
            .unwrap_or_else(|error| panic!("admit: {error:?}"));
        let operation = machine
            .checkpoint()
            .pending_operation()
            .unwrap_or_else(|| panic!("pending"))
            .identity;
        machine
            .fail_operation(
                operation,
                gantry::portable::RuntimeErrorCategory::ExecutorFailure,
            )
            .unwrap_or_else(|error| panic!("settle: {error:?}"));
        registry
            .settle_containment(
                &subject,
                owner,
                Completion::observed(ExternalOutcome::Accepted, EffectState::NotStarted),
            )
            .unwrap_or_else(|error| panic!("containment: {error:?}"));
        if adapter {
            registry
                .bind_adapter_instance(&subject, owner, adapter_instance("advance", 4, 0))
                .unwrap_or_else(|error| panic!("adapter: {error:?}"));
        }
        if finishing {
            registry
                .begin_finish(&subject, owner)
                .unwrap_or_else(|error| panic!("finish: {error:?}"));
        }
        let before = registry.declared_records();
        let binding = registry.adapter_instance(&subject).cloned();
        assert_eq!(
            registry.advance_owner(&subject, owner, OwnerGeneration::new(5)),
            Err(ResourceRegistryRefusal::OwnershipTransfer(expected))
        );
        assert_eq!(registry.declared_records(), before);
        assert_eq!(registry.adapter_instance(&subject).cloned(), binding);
    }
}

/// Cancellation closes standalone physical acquisition without consuming either input.
#[test]
fn owned_host_resource_binding_refuses_machine_cancellation_without_mutation() {
    use gantry::runtime::{HostResourceError, OwnedHostResource};
    let (_, mut machine, subject) = machine_with_declared_subject(Some(FIXTURE_DECLARATION));
    let subject = subject.unwrap_or_else(|| panic!("pending subject exists"));
    let account = admitted(
        ResourceCarrier::ReconstructionRecord,
        ledger().durable_record(),
        subject.clone(),
    )
    .unwrap_or_else(|error| panic!("account admits before cancellation: {error:?}"));
    let before = account.durable_record();
    assert!(machine.cancel("standalone acquisition cancelled").is_some());
    let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let refusal = OwnedHostResource::bind(
        account,
        TransportValue {
            drops: Arc::clone(&drops),
            panic_on_drop: false,
            value: 17,
        },
    );
    let (error, returned_account, returned_value) = *refusal
        .err()
        .unwrap_or_else(|| panic!("cancelled account cannot acquire physical ownership"));
    assert_eq!(error, HostResourceError::CancellationRequested);
    assert_eq!(returned_account.durable_record(), before);
    assert_eq!(returned_account.subject(), &subject);
    assert_eq!(returned_value.value, 17);
    assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert!(machine.checkpoint().pending_operation().is_some());
    drop(returned_value);
    assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 1);
}

/// Charged registry callbacks spend nothing on refusal and retain charges after admitted work.
#[test]
fn charged_registry_invocation_preserves_physical_and_quota_admission() {
    use gantry::runtime::HostResourceError;
    let subject = active_subject();
    let owner = OwnerGeneration::new(4);
    let mut registry = ResourceRegistry::new();
    registry
        .admit_host_value(
            subject.clone(),
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
            17_u64,
        )
        .unwrap_or_else(|_| panic!("admit"));
    let charge = |family, amount| Charge {
        owner: QuotaOwner::Owner,
        family,
        amount,
    };
    let before = registry.declared_records();
    assert_eq!(
        registry.invoke_host_value_with_charges::<String, ()>(
            &subject,
            owner,
            &[charge(QuotaFamily::Bytes, 3)],
            |_| panic!("wrong type cannot dispatch")
        ),
        Err(HostResourceError::TypeMismatch)
    );
    assert_eq!(registry.declared_records(), before);
    assert_eq!(
        registry.invoke_host_value_with_charges::<u64, ()>(
            &subject,
            owner,
            &[
                charge(QuotaFamily::Bytes, 3),
                charge(QuotaFamily::Handles, 1)
            ],
            |_| panic!("refused vector cannot dispatch")
        ),
        Err(HostResourceError::Model(ResourceError::UndeclaredQuota))
    );
    assert_eq!(registry.declared_records(), before);
    assert_eq!(
        registry.invoke_host_value_with_charges::<u64, u64>(
            &subject,
            owner,
            &[charge(QuotaFamily::Bytes, 3)],
            |value| {
                *value += 1;
                Ok(*value)
            }
        ),
        Ok(18)
    );
    assert_eq!(
        registry
            .account(&subject)
            .and_then(|account| account.remaining(QuotaOwner::Owner, QuotaFamily::Bytes)),
        Some(5)
    );
    let failure = gantry::host::contracts::HostError {
        code: Arc::from("fixture-failure"),
        protected_diagnostic: None,
    };
    assert_eq!(
        registry.invoke_host_value_with_charges::<u64, ()>(
            &subject,
            owner,
            &[charge(QuotaFamily::Bytes, 2)],
            |_| Err(failure.clone())
        ),
        Err(HostResourceError::Host(failure))
    );
    assert_eq!(
        registry
            .account(&subject)
            .and_then(|account| account.remaining(QuotaOwner::Owner, QuotaFamily::Bytes)),
        Some(3)
    );
    assert!(registry.has_host_value(&subject));
    assert_eq!(registry.pending_operations(), 1);
}

/// Charged transport failures preserve admitted charges but refuse subsequent poisoned work.
#[test]
fn charged_registry_panic_retains_charges_and_fences_reuse() {
    use gantry::runtime::HostResourceError;
    let subject = active_subject();
    let owner = OwnerGeneration::new(4);
    let mut registry = ResourceRegistry::new();
    registry
        .admit_host_value(
            subject.clone(),
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
            17_u64,
        )
        .unwrap_or_else(|_| panic!("admit"));
    let charges = [Charge {
        owner: QuotaOwner::Owner,
        family: QuotaFamily::Bytes,
        amount: 1,
    }];
    assert!(matches!(
        registry.invoke_host_value_with_charges::<u64, ()>(&subject, owner, &charges, |_| panic!(
            "accepted integration panic"
        )),
        Err(HostResourceError::Boundary(_))
    ));
    assert_eq!(
        registry
            .account(&subject)
            .and_then(|account| account.remaining(QuotaOwner::Owner, QuotaFamily::Bytes)),
        Some(7)
    );
    let before = registry.declared_records();
    assert!(matches!(
        registry.invoke_host_value_with_charges::<u64, ()>(&subject, owner, &charges, |_| panic!(
            "poisoned work cannot dispatch"
        )),
        Err(HostResourceError::Boundary(_))
    ));
    assert_eq!(registry.declared_records(), before);
    assert!(registry.has_host_value(&subject));
    assert_eq!(registry.pending_operations(), 1);
}

/// Direct registry invocation admits before cancellation, never through a recovered caller lease.
#[test]
fn registry_host_invocation_refuses_account_cancellation_and_releases_the_lease() {
    use gantry::runtime::HostResourceError;
    let (program, mut machine, subject) = machine_with_declared_subject(Some(FIXTURE_DECLARATION));
    let subject = subject.unwrap_or_else(|| panic!("subject"));
    let recovered = Machine::recover_from_checkpoint(
        program,
        machine.checkpoint(),
        ExecutionBudget::recover_from_checkpoint(machine.budget_checkpoint())
            .unwrap_or_else(|error| panic!("budget: {error:?}")),
    )
    .unwrap_or_else(|error| panic!("recovery: {error:?}"));
    let recovered_subject = recovered
        .pending_resource_subject()
        .unwrap_or_else(|| panic!("recovered subject"));
    let owner = OwnerGeneration::new(4);
    let mut registry = ResourceRegistry::with_limits(1, 1);
    registry
        .admit_host_value(
            subject.clone(),
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
            17_u64,
        )
        .unwrap_or_else(|_| panic!("admit"));
    let before = registry.declared_records();
    assert_eq!(
        registry.invoke_host_value::<u64, u64>(&subject, owner, |value| {
            assert!(machine.cancel("cancel inside accepted callback").is_some());
            *value += 1;
            Ok(*value)
        }),
        Ok(18),
        "accepted integration must run outside the lease lock"
    );
    for binding in [&subject, &recovered_subject] {
        assert_eq!(
            registry.invoke_host_value::<u64, ()>(binding, owner, |_| panic!(
                "cancelled callback must not execute"
            )),
            Err(HostResourceError::CancellationRequested)
        );
        assert_eq!(
            registry.invoke_host_value_with_charges::<String, ()>(
                binding,
                owner,
                &[Charge {
                    owner: QuotaOwner::Owner,
                    family: QuotaFamily::Bytes,
                    amount: 9,
                }],
                |_| panic!("cancelled charged callback must not execute"),
            ),
            Err(HostResourceError::CancellationRequested),
            "account cancellation precedes type mismatch and quota exhaustion",
        );
        assert_eq!(registry.declared_records(), before);
        assert!(registry.has_host_value(&subject));
        assert_eq!(registry.pending_operations(), 1);
    }
    assert!(matches!(
        registry.invoke_host_value::<u64, ()>(&subject, OwnerGeneration::new(3), |_| panic!(
            "stale callback must not execute"
        )),
        Err(HostResourceError::Model(ResourceError::StaleOwner { .. }))
    ));
    registry
        .begin_finish(&subject, owner)
        .unwrap_or_else(|error| panic!("cleanup: {error:?}"));
    assert_eq!(registry.dispose_host_value(&subject, owner), Ok(()));
    assert!(machine.checkpoint().pending_operation().is_some());
}

/// Cancellation after physical binding must refuse a fresh loan without disposing its receiver.
#[test]
fn host_receiver_loan_admission_refuses_machine_cancellation() {
    use gantry::runtime::{HostResourceError, OwnedHostResource};
    let (_, mut machine, subject) = machine_with_declared_subject(Some(FIXTURE_DECLARATION));
    let subject = subject.unwrap_or_else(|| panic!("subject exists"));
    let account = admitted(
        ResourceCarrier::ReconstructionRecord,
        ledger().durable_record(),
        subject,
    )
    .unwrap_or_else(|error| panic!("account: {error:?}"));
    let mut resource = OwnedHostResource::bind(account, 17_u64)
        .unwrap_or_else(|_| panic!("physical binding admits"));
    let before = resource.account().durable_record();
    assert!(machine.cancel("loan acquisition cancelled").is_some());
    assert_eq!(
        resource.invoke(OwnerGeneration::new(4), |value| {
            *value += 1;
            Ok(*value)
        }),
        Err(HostResourceError::CancellationRequested),
        "fresh direct invocation must not bypass cancelled loan admission"
    );
    assert_eq!(resource.account().durable_record(), before);
    let live = transport_live(FIXTURE_DECLARATION, 0, 4, true);
    let preserved = live.clone();
    let (error, returned) = *resource
        .borrow_receiver(live)
        .err()
        .unwrap_or_else(|| panic!("cancelled work cannot acquire a loan"));
    assert_eq!(error, HostResourceError::CancellationRequested);
    assert_eq!(returned, preserved);
    assert_eq!(resource.account().durable_record(), before);
    assert!(!resource.is_poisoned());
    assert!(machine.checkpoint().pending_operation().is_some());
    let (error, returned) = *resource
        .borrow_receiver_with_charges(
            returned,
            &[Charge {
                owner: QuotaOwner::Owner,
                family: QuotaFamily::Bytes,
                amount: 9,
            }],
        )
        .err()
        .unwrap_or_else(|| panic!("cancellation precedes quota exhaustion"));
    assert_eq!(error, HostResourceError::CancellationRequested);
    assert_eq!(returned, preserved);
    assert_eq!(resource.account().durable_record(), before);
    let stale = transport_live(FIXTURE_DECLARATION, 0, 3, true);
    let (error, _) = *resource
        .borrow_receiver(stale)
        .err()
        .unwrap_or_else(|| panic!("stale owner refuses before cancellation"));
    assert!(matches!(
        error,
        HostResourceError::Model(ResourceError::StaleOwner { .. })
    ));
    assert_eq!(
        resource.emergency_release(emergency_cleanup()),
        Ok(ResourceLifetimeState::EmergencyReleased)
    );
}

/// Cancellation does not settle accepted loan work or prevent its explicit failure settlement.
#[test]
fn host_receiver_loan_settlement_survives_machine_cancellation() {
    use gantry::runtime::OwnedHostResource;
    let (_, mut machine, subject) = machine_with_declared_subject(Some(FIXTURE_DECLARATION));
    let subject = subject.unwrap_or_else(|| panic!("subject exists"));
    let account = admitted(
        ResourceCarrier::ReconstructionRecord,
        ledger().durable_record(),
        subject,
    )
    .unwrap_or_else(|error| panic!("account: {error:?}"));
    let mut resource = OwnedHostResource::bind(account, 17_u64)
        .unwrap_or_else(|_| panic!("physical binding admits"));
    {
        let mut loan = resource
            .borrow_receiver(transport_live(FIXTURE_DECLARATION, 0, 4, true))
            .unwrap_or_else(|_| panic!("loan admits before cancellation"));
        assert!(machine.cancel("accepted loan cancelled").is_some());
        let charges = [Charge {
            owner: QuotaOwner::Owner,
            family: QuotaFamily::Bytes,
            amount: 1,
        }];
        assert_eq!(
            loan.invoke_with_charges(&charges, |value| Ok(*value)),
            Ok(17)
        );
        let progress = loan.live().clone();
        assert_eq!(
            loan.invoke_with_charges::<()>(
                &[Charge {
                    amount: 9,
                    ..charges[0]
                }],
                |_| { panic!("exhausted quota cannot invoke acquired work") }
            ),
            Err(gantry::runtime::HostResourceError::Model(
                ResourceError::QuotaExhausted
            )),
        );
        assert_eq!(loan.live(), &progress);
        let failure = gantry::host::contracts::HostError {
            code: Arc::from("acquired-loan-failure"),
            protected_diagnostic: None,
        };
        assert_eq!(
            loan.invoke_with_charges::<()>(&charges, |_| Err(failure.clone())),
            Err(gantry::runtime::HostResourceError::Host(failure)),
        );
        assert!(matches!(
            loan.invoke_with_charges::<()>(&charges, |_| panic!("accepted loan callback panic")),
            Err(gantry::runtime::HostResourceError::Boundary(_)),
        ));
        assert!(matches!(
            loan.invoke_with_charges::<()>(&charges, |_| panic!("poisoned loan cannot invoke")),
            Err(gantry::runtime::HostResourceError::Boundary(_)),
        ));
        assert!(loan.settle_failure(FailureClass::ResourceFailure).is_ok());
        assert_eq!(
            loan.invoke_with_charges::<()>(&charges, |_| panic!("settled loan cannot invoke")),
            Err(gantry::runtime::HostResourceError::LoanSettled),
        );
    }
    assert!(
        !resource
            .account()
            .ledger()
            .liveness_roots()
            .contains(&LivenessRoot::Loan)
    );
    assert_eq!(
        resource.account().ledger().lifetime(),
        ResourceLifetimeState::Active
    );
    assert_eq!(
        resource
            .account()
            .remaining(QuotaOwner::Owner, QuotaFamily::Bytes),
        Some(5)
    );
    assert!(machine.checkpoint().pending_operation().is_some());
    assert_eq!(
        resource.emergency_release(emergency_cleanup()),
        Ok(ResourceLifetimeState::EmergencyReleased)
    );
}

/// A cancellation race either refuses acquisition or leaves one explicitly settled loan.
#[test]
fn host_receiver_loan_cancellation_race_preserves_ownership() {
    use gantry::runtime::{HostResourceError, OwnedHostResource};
    for _ in 0..32 {
        let (_, mut machine, subject) = machine_with_declared_subject(Some(FIXTURE_DECLARATION));
        let account = admitted(
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
            subject.unwrap_or_else(|| panic!("subject exists")),
        )
        .unwrap_or_else(|error| panic!("account: {error:?}"));
        let mut resource =
            OwnedHostResource::bind(account, 17_u64).unwrap_or_else(|_| panic!("bind"));
        let before = resource.account().durable_record();
        let barrier = std::sync::Barrier::new(2);
        let acquired = std::thread::scope(|scope| {
            let acquisition = scope.spawn(|| {
                let live = transport_live(FIXTURE_DECLARATION, 0, 4, true);
                let preserved = live.clone();
                barrier.wait();
                match resource.borrow_receiver(live) {
                    Ok(mut loan) => {
                        assert!(loan.settle_failure(FailureClass::ResourceFailure).is_ok());
                        true
                    }
                    Err(refusal) => {
                        let (error, returned) = *refusal;
                        assert_eq!(error, HostResourceError::CancellationRequested);
                        assert_eq!(returned, preserved);
                        false
                    }
                }
            });
            barrier.wait();
            assert!(machine.cancel("receiver acquisition race").is_some());
            acquisition
                .join()
                .unwrap_or_else(|_| panic!("acquisition thread"))
        });
        if acquired {
            assert_eq!(
                resource.account().ledger().operation_state(),
                ResourceState::Poisoned
            );
            assert!(
                !resource
                    .account()
                    .ledger()
                    .liveness_roots()
                    .contains(&LivenessRoot::Loan)
            );
            assert_eq!(resource.account().ledger().lifetime(), before.lifetime());
            assert_eq!(
                resource.account().durable_record().quotas(),
                before.quotas()
            );
        } else {
            assert_eq!(resource.account().durable_record(), before);
        }
        assert!(!resource.is_poisoned());
        assert!(machine.checkpoint().pending_operation().is_some());
        assert_eq!(
            resource.emergency_release(emergency_cleanup()),
            Ok(ResourceLifetimeState::EmergencyReleased)
        );
    }
}

/// Physical acquisition is eligible only for the two open operation states.
#[test]
fn owned_host_resource_binding_requires_open_operation_state() {
    use gantry::runtime::{HostResourceError, OwnedHostResource};
    for state in [
        ResourceState::Usable,
        ResourceState::PartiallyAdvanced,
        ResourceState::HalfClosed,
        ResourceState::Poisoned,
        ResourceState::Consumed,
        ResourceState::Closed,
    ] {
        let source = ledger().durable_record();
        let record = DurableResourceRecord::from_durable_facts(
            source.owner(),
            ResourceLifetimeState::Active,
            state,
            source.quotas().clone(),
            source.liveness_roots().clone(),
            None,
            None,
        )
        .unwrap_or_else(|error| panic!("active accounting record: {error:?}"));
        let account = admitted(
            ResourceCarrier::ReconstructionRecord,
            record.clone(),
            active_subject(),
        )
        .unwrap_or_else(|error| panic!("account admission: {error:?}"));
        match OwnedHostResource::bind(account, 17_u64) {
            Ok(resource) => {
                assert!(
                    state.is_open(),
                    "closed operation state cannot acquire a host value"
                );
                assert_eq!(resource.account().durable_record(), record);
            }
            Err(refusal) => {
                let (error, account, value) = *refusal;
                assert!(!state.is_open(), "open operation state remains eligible");
                assert_eq!(
                    error,
                    HostResourceError::Model(ResourceError::IllegalLifetimeTransition)
                );
                assert_eq!(account.durable_record(), record);
                assert_eq!(value, 17);
            }
        }
    }
}

/// Prepares a standalone active account with optional outstanding transport obligations.
fn transfer_account(pending: bool, loan: bool, containment_pending: bool) -> AdmittedResource {
    let (_, mut machine, subject) = machine_with_declared_subject(Some(FIXTURE_DECLARATION));
    let subject = subject.unwrap_or_else(|| panic!("pending subject exists"));
    let mut account = admitted(
        ResourceCarrier::ReconstructionRecord,
        ledger().durable_record(),
        subject,
    )
    .unwrap_or_else(|error| panic!("account admits: {error:?}"));
    if !loan {
        account
            .close_liveness_root_for(OwnerGeneration::new(4), LivenessRoot::Loan)
            .unwrap_or_else(|error| panic!("loan root closes: {error:?}"));
    }
    if !containment_pending {
        account
            .settle_containment(
                OwnerGeneration::new(4),
                Completion::observed(ExternalOutcome::Accepted, EffectState::NotStarted),
            )
            .unwrap_or_else(|error| panic!("containment settles: {error:?}"));
    }
    if !pending {
        let operation = machine
            .checkpoint()
            .pending_operation()
            .unwrap_or_else(|| panic!("pending operation exists"))
            .identity;
        machine
            .fail_operation(
                operation,
                gantry::portable::RuntimeErrorCategory::ExecutorFailure,
            )
            .unwrap_or_else(|error| panic!("machine work settles: {error:?}"));
    }
    account
}

/// Builds a generation-bound borrowed or retained Section 20 handle for transport tests.
fn transport_live(
    declaration: &str,
    generation: u64,
    owner: u64,
    borrowed: bool,
) -> gantry::ir::LiveResource {
    use gantry::ir::LoanId;
    let path =
        CanonicalPath::new(declaration).unwrap_or_else(|error| panic!("declaration: {error}"));
    let site = active_subject().site().clone();
    let retained = OperationAbi::new(
        OperationKind::LiveResource,
        &path,
        &site,
        generation,
        RecoveryClass::Idempotent,
        ReceiverOwnership::RetainedByCaller,
    )
    .unwrap_or_else(|error| panic!("retained ABI: {error:?}"));
    let ownership = if borrowed {
        ReceiverOwnership::BorrowedLoan(LoanId::seal(&path, &site, retained.generation()))
    } else {
        ReceiverOwnership::RetainedByCaller
    };
    let abi = OperationAbi::new(
        OperationKind::LiveResource,
        &path,
        &site,
        generation,
        RecoveryClass::Idempotent,
        ownership,
    )
    .unwrap_or_else(|error| panic!("loan ABI: {error:?}"));
    abi.open_live(
        OwnerGeneration::new(owner),
        OperationAbi::observation_allowance(
            1,
            DisclosureCharge::new(1).unwrap_or_else(|| unreachable!("positive charge")),
        ),
    )
    .unwrap_or_else(|error| panic!("live handle: {error:?}"))
}

/// Charged acquisition refuses whole vectors without acquiring a loan or consuming its handle.
#[test]
fn charged_receiver_loan_acquisition_preserves_refusal_and_commits_once() {
    use gantry::runtime::{HostResourceError, OwnedHostResource};
    let mut resource =
        OwnedHostResource::bind(admitted_active(), 11_u64).unwrap_or_else(|_| panic!("bind"));
    let before = resource.account().durable_record();
    let live = transport_live(FIXTURE_DECLARATION, 0, 4, true);
    let preserved = live.clone();
    let charge = |family, amount| Charge {
        owner: QuotaOwner::Owner,
        family,
        amount,
    };
    let vector = [
        charge(QuotaFamily::Bytes, 3),
        charge(QuotaFamily::Handles, 1),
    ];
    let (error, returned) = *resource
        .borrow_receiver_with_charges(live, &vector)
        .err()
        .unwrap_or_else(|| panic!("undeclared quota refuses"));
    assert!(matches!(error, HostResourceError::Model(_)));
    assert_eq!(returned, preserved);
    assert_eq!(resource.account().durable_record(), before);
    assert_eq!(
        resource.invoke(OwnerGeneration::new(4), |value| Ok(*value)),
        Ok(11)
    );
    let vector = [charge(QuotaFamily::Bytes, 9)];
    let (error, returned) = *resource
        .borrow_receiver_with_charges(returned, &vector)
        .err()
        .unwrap_or_else(|| panic!("exhausted quota refuses"));
    assert!(matches!(
        error,
        HostResourceError::Model(ResourceError::QuotaExhausted)
    ));
    assert_eq!(returned, preserved);
    assert_eq!(resource.account().durable_record(), before);
    {
        let mut loan = resource
            .borrow_receiver_with_charges(returned, &[charge(QuotaFamily::Bytes, 3)])
            .unwrap_or_else(|_| panic!("valid vector admits"));
        assert_eq!(loan.invoke(|value| Ok(*value)), Ok(11));
        loan.settle_failure(FailureClass::ResourceFailure)
            .unwrap_or_else(|error| panic!("settle: {error:?}"));
    }
    assert_eq!(
        resource
            .account()
            .remaining(QuotaOwner::Owner, QuotaFamily::Bytes),
        Some(5)
    );
    assert_eq!(
        resource.account().ledger().lifetime(),
        ResourceLifetimeState::Active
    );
    assert!(
        !resource
            .account()
            .ledger()
            .liveness_roots()
            .contains(&LivenessRoot::Loan)
    );
}

/// Direct update charges commit only for admitted callbacks and are not rolled back after failure.
#[test]
fn charged_host_invocation_preserves_refusals_and_accepted_charges() {
    use gantry::runtime::{HostResourceError, OwnedHostResource};
    let owner = OwnerGeneration::new(4);
    let mut resource =
        OwnedHostResource::bind(admitted_active(), 11_u64).unwrap_or_else(|_| panic!("bind"));
    let charge = |family, amount| Charge {
        owner: QuotaOwner::Owner,
        family,
        amount,
    };
    let before = resource.account().durable_record();
    assert_eq!(
        resource.invoke_with_charges::<()>(
            owner,
            &[
                charge(QuotaFamily::Bytes, 3),
                charge(QuotaFamily::Handles, 1)
            ],
            |_| panic!("refused vector cannot execute")
        ),
        Err(HostResourceError::Model(ResourceError::UndeclaredQuota))
    );
    assert_eq!(resource.account().durable_record(), before);
    assert_eq!(
        resource.invoke_with_charges(owner, &[charge(QuotaFamily::Bytes, 3)], |value| {
            *value += 1;
            Ok(*value)
        }),
        Ok(12)
    );
    assert_eq!(
        resource
            .account()
            .remaining(QuotaOwner::Owner, QuotaFamily::Bytes),
        Some(5)
    );
    let failure = gantry::host::contracts::HostError {
        code: Arc::from("fixture-failure"),
        protected_diagnostic: None,
    };
    assert_eq!(
        resource.invoke_with_charges::<()>(owner, &[charge(QuotaFamily::Bytes, 2)], |_| Err(
            failure.clone()
        )),
        Err(HostResourceError::Host(failure))
    );
    assert_eq!(
        resource
            .account()
            .remaining(QuotaOwner::Owner, QuotaFamily::Bytes),
        Some(3)
    );
    let before = resource.account().durable_record();
    assert_eq!(
        resource.invoke_with_charges::<()>(owner, &[charge(QuotaFamily::Bytes, 4)], |_| panic!(
            "exhausted quota cannot execute"
        )),
        Err(HostResourceError::Model(ResourceError::QuotaExhausted))
    );
    assert_eq!(resource.account().durable_record(), before);
    assert_eq!(resource.invoke(owner, |value| Ok(*value)), Ok(12));
    assert!(matches!(
        resource.invoke_with_charges::<()>(owner, &[charge(QuotaFamily::Bytes, 1)], |_| {
            panic!("accepted integration panic");
        }),
        Err(HostResourceError::Boundary(_))
    ));
    assert_eq!(
        resource
            .account()
            .remaining(QuotaOwner::Owner, QuotaFamily::Bytes),
        Some(2)
    );
    let before = resource.account().durable_record();
    assert!(matches!(
        resource.invoke_with_charges::<()>(owner, &[charge(QuotaFamily::Bytes, 1)], |_| {
            panic!("poisoned transport cannot dispatch again");
        }),
        Err(HostResourceError::Boundary(_))
    ));
    assert_eq!(resource.account().durable_record(), before);

    let (_, mut machine, subject) = machine_with_declared_subject(Some(FIXTURE_DECLARATION));
    let account = admitted(
        ResourceCarrier::ReconstructionRecord,
        ledger().durable_record(),
        subject.unwrap_or_else(|| panic!("machine subject")),
    )
    .unwrap_or_else(|error| panic!("account: {error:?}"));
    let mut resource = OwnedHostResource::bind(account, 17_u64)
        .unwrap_or_else(|_| panic!("bind cancellation fixture"));
    assert_eq!(
        resource.invoke_with_charges(owner, &[charge(QuotaFamily::Bytes, 1)], |value| {
            assert!(machine.cancel("cancel inside charged callback").is_some());
            Ok(*value)
        }),
        Ok(17)
    );
    assert_eq!(
        resource
            .account()
            .remaining(QuotaOwner::Owner, QuotaFamily::Bytes),
        Some(7)
    );
    let before = resource.account().durable_record();
    assert_eq!(
        resource.invoke_with_charges::<()>(owner, &[charge(QuotaFamily::Bytes, 9)], |_| panic!(
            "cancelled callback cannot execute"
        )),
        Err(HostResourceError::CancellationRequested)
    );
    assert_eq!(resource.account().durable_record(), before);
    assert!(machine.checkpoint().pending_operation().is_some());
}

/// Accepted settlement releases only the receiver loan, while refused progress claims retain it.
#[test]
fn host_receiver_loan_retains_progress_until_exact_settlement() {
    use gantry::runtime::{HostReceiverLoan, HostResourceError, OwnedHostResource};
    assert_not_impl_any!(HostReceiverLoan<'static, u64>: Clone, Copy);
    let mut resource =
        OwnedHostResource::bind(admitted_active(), 11_u64).unwrap_or_else(|_| panic!("bind"));
    let before = resource.account().durable_record();
    let live = transport_live(FIXTURE_DECLARATION, 0, 4, true);
    {
        let mut loan = resource
            .borrow_receiver(live)
            .unwrap_or_else(|_| panic!("exact loan admits"));
        assert_eq!(
            loan.invoke(|value| {
                *value += 1;
                Ok(*value)
            }),
            Ok(12)
        );
        assert!(loan.observe(ProgressObservation::ShortRead).is_ok());
        assert!(matches!(
            loan.observe(ProgressObservation::ShortRead),
            Err(HostResourceError::Operation(
                OperationAbiError::ObservationBudgetExhausted { .. }
            ))
        ));
        let invalid = OperationSettlement::new(
            loan.live().operation(),
            loan.live().generation(),
            loan.live().owner(),
            ExternalOutcome::Accepted,
            ProgressObservation::CommittedProgress,
            31,
        )
        .unwrap_or_else(|error| panic!("candidate: {error:?}"));
        assert!(matches!(
            loan.settle(&invalid),
            Err(HostResourceError::Operation(
                OperationAbiError::PartialProgressAsCompletion { .. }
            ))
        ));
        assert_eq!(loan.live().settlement(), None);
        assert_eq!(loan.live().progress(), ProgressObservation::ShortRead);
        let accepted = OperationSettlement::new(
            loan.live().operation(),
            loan.live().generation(),
            loan.live().owner(),
            ExternalOutcome::Accepted,
            ProgressObservation::ShortRead,
            32,
        )
        .unwrap_or_else(|error| panic!("settlement: {error:?}"));
        assert_eq!(loan.settle(&accepted), Ok(ResourceState::PartiallyAdvanced));
        assert_eq!(loan.settle(&accepted), Err(HostResourceError::LoanSettled));
        assert_eq!(
            loan.settle_failure(FailureClass::ResourceFailure),
            Err(HostResourceError::LoanSettled)
        );
        assert_eq!(
            loan.invoke::<()>(|_| panic!("settled loan cannot invoke")),
            Err(HostResourceError::LoanSettled)
        );
    }
    let after = resource.account().durable_record();
    assert!(!after.liveness_roots().contains(&LivenessRoot::Loan));
    assert_eq!(after.operation_state(), ResourceState::PartiallyAdvanced);
    assert_eq!(after.owner(), before.owner());
    assert_eq!(after.quotas(), before.quotas());
    assert_eq!(after.lifetime(), ResourceLifetimeState::Active);
    assert_eq!(after.settlement(), before.settlement());
    assert_eq!(
        resource.invoke(OwnerGeneration::new(4), |value| Ok(*value)),
        Ok(12)
    );
}

/// Failure winners close only the loan and fence later transport use without releasing accounting.
#[test]
fn host_receiver_loan_failure_closes_the_loan_once() {
    use gantry::runtime::{HostResourceError, OwnedHostResource};
    for failure in FailureClass::ALL {
        let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut resource = OwnedHostResource::bind(
            admitted_active(),
            TransportValue {
                drops: Arc::clone(&drops),
                panic_on_drop: false,
                value: 11,
            },
        )
        .unwrap_or_else(|_| panic!("bind"));
        let before = resource.account().durable_record();
        let state = match failure {
            FailureClass::AdapterFailure => ResourceState::HalfClosed,
            FailureClass::ResourceFailure => ResourceState::Poisoned,
        };
        {
            let mut loan = resource
                .borrow_receiver(transport_live(FIXTURE_DECLARATION, 0, 4, true))
                .unwrap_or_else(|_| panic!("exact loan admits"));
            assert!(loan.observe(ProgressObservation::ShortRead).is_ok());
            let evidence = loan
                .settle_failure(failure)
                .unwrap_or_else(|error| panic!("loan failure: {error:?}"));
            assert_eq!(evidence.state(), state);
            assert_eq!(loan.live().failure_settlement(), Some(&evidence));
            assert!(loan.live().settlement().is_none());
            assert_eq!(loan.live().progress(), ProgressObservation::ShortRead);
            let late = OperationSettlement::new(
                loan.live().operation(),
                loan.live().generation(),
                loan.live().owner(),
                ExternalOutcome::Accepted,
                ProgressObservation::ShortRead,
                32,
            )
            .unwrap_or_else(|error| panic!("late settlement: {error:?}"));
            assert_eq!(loan.settle(&late), Err(HostResourceError::LoanSettled));
            assert_eq!(
                loan.settle_failure(failure),
                Err(HostResourceError::LoanSettled)
            );
            assert_eq!(
                loan.invoke::<()>(|_| panic!("settled loan cannot invoke")),
                Err(HostResourceError::LoanSettled)
            );
        }
        let after = resource.account().durable_record();
        assert!(!after.liveness_roots().contains(&LivenessRoot::Loan));
        assert_eq!(after.operation_state(), state);
        assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(after.owner(), before.owner());
        assert_eq!(after.quotas(), before.quotas());
        assert_eq!(after.lifetime(), before.lifetime());
        assert_eq!(after.settlement(), before.settlement());
        let mut expected_roots = before.liveness_roots().clone();
        expected_roots.remove(&LivenessRoot::Loan);
        assert_eq!(after.liveness_roots(), &expected_roots);
        let projection = {
            let mut live = transport_live(FIXTURE_DECLARATION, 0, 4, true);
            assert!(live.settle_failure(failure).is_ok());
            live.failure_state_projection()
                .unwrap_or_else(|| panic!("accepted failure projects state"))
        };
        let mut stale = ledger_owned_by(5);
        let stale_before = stale.durable_record();
        assert_eq!(
            stale.project_operation_state(&projection),
            Err(ResourceError::StaleOwner {
                presented: OwnerGeneration::new(4),
                current: OwnerGeneration::new(5),
            })
        );
        assert_eq!(stale.durable_record(), stale_before);
        assert_eq!(
            resource.is_poisoned(),
            failure == FailureClass::AdapterFailure
        );
        assert!(
            resource
                .invoke::<()>(OwnerGeneration::new(4), |_| {
                    panic!("failed resource cannot invoke")
                })
                .is_err()
        );
        if failure == FailureClass::ResourceFailure {
            let before_finish = resource.account().durable_record();
            assert_eq!(
                resource.finish(OwnerGeneration::new(4), 33, |_| {
                    panic!("poisoned generation cannot invoke its finalizer")
                }),
                Err(HostResourceError::Model(
                    ResourceError::IllegalLifetimeTransition
                ))
            );
            assert_eq!(resource.account().durable_record(), before_finish);
        }
        assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(
            resource.emergency_release(emergency_cleanup()),
            Ok(ResourceLifetimeState::EmergencyReleased)
        );
        assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 1);
        drop(resource);
        assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
}

/// A refused adapter classification retains the loan until an admissible terminal winner.
#[test]
fn host_receiver_loan_refused_failure_retains_progress_until_settlement() {
    use gantry::runtime::{HostResourceError, OwnedHostResource};
    let mut resource =
        OwnedHostResource::bind(admitted_active(), 11_u64).unwrap_or_else(|_| panic!("bind"));
    {
        let mut loan = resource
            .borrow_receiver(transport_live(FIXTURE_DECLARATION, 0, 4, true))
            .unwrap_or_else(|_| panic!("exact loan admits"));
        assert!(loan.observe(ProgressObservation::Eof).is_ok());
        let before = loan.live().clone();
        assert_eq!(
            loan.settle_failure(FailureClass::AdapterFailure),
            Err(HostResourceError::Operation(
                OperationAbiError::HalfCloseWithoutOpenHalf {
                    state: ResourceState::Closed
                }
            ))
        );
        assert_eq!(loan.live(), &before);
        assert!(loan.settle_failure(FailureClass::ResourceFailure).is_ok());
    }
    assert!(
        !resource
            .account()
            .ledger()
            .liveness_roots()
            .contains(&LivenessRoot::Loan)
    );
    assert_eq!(
        resource.account().ledger().operation_state(),
        ResourceState::Poisoned
    );
    assert_eq!(
        resource.account().ledger().lifetime(),
        ResourceLifetimeState::Active
    );
}

/// Foreign generations, owners and receiver arrangements refuse without changing either input.
#[test]
fn host_receiver_loan_refuses_foreign_identity_and_missing_roots() {
    use gantry::runtime::{HostResourceError, OwnedHostResource};
    let mut resource =
        OwnedHostResource::bind(admitted_active(), 1_u64).unwrap_or_else(|_| panic!("bind"));
    let before = resource.account().durable_record();
    for recovery in [RecoveryClass::ReadOnly, RecoveryClass::NonIdempotent] {
        let declaration = CanonicalPath::new(FIXTURE_DECLARATION)
            .unwrap_or_else(|error| panic!("declaration: {error}"));
        let subject = active_subject();
        let abi = OperationAbi::new(
            OperationKind::LiveResource,
            &declaration,
            subject.site(),
            0,
            recovery,
            ReceiverOwnership::BorrowedLoan(gantry::ir::LoanId::seal(
                &declaration,
                subject.site(),
                subject.generation(),
            )),
        )
        .unwrap_or_else(|error| panic!("loan ABI: {error:?}"));
        let live = abi
            .open_live(
                OwnerGeneration::new(4),
                OperationAbi::observation_allowance(
                    1,
                    DisclosureCharge::new(1).unwrap_or_else(|| panic!("charge")),
                ),
            )
            .unwrap_or_else(|error| panic!("loan: {error:?}"));
        let preserved = live.clone();
        let (error, returned) = *resource
            .borrow_receiver(live)
            .err()
            .unwrap_or_else(|| panic!("mismatched recovery must refuse"));
        assert_eq!(error, HostResourceError::ForeignLoan);
        assert_eq!(returned, preserved);
        assert_eq!(resource.account().durable_record(), before);
        assert!(!resource.is_poisoned());
    }
    for (live, expected) in [
        (
            transport_live(SECOND_FIXTURE_DECLARATION, 0, 4, true),
            HostResourceError::ForeignLoan,
        ),
        (
            transport_live(FIXTURE_DECLARATION, 1, 4, true),
            HostResourceError::ForeignLoan,
        ),
        (
            transport_live(FIXTURE_DECLARATION, 0, 3, true),
            HostResourceError::Model(ResourceError::StaleOwner {
                presented: OwnerGeneration::new(3),
                current: OwnerGeneration::new(4),
            }),
        ),
        (
            transport_live(FIXTURE_DECLARATION, 0, 4, false),
            HostResourceError::ForeignLoan,
        ),
    ] {
        let preserved = live.clone();
        let (error, returned) = *resource
            .borrow_receiver(live)
            .err()
            .unwrap_or_else(|| panic!("must refuse"));
        assert_eq!(error, expected);
        assert_eq!(returned, preserved);
        assert_eq!(resource.account().durable_record(), before);
    }
    let mut no_root = OwnedHostResource::bind(transfer_account(false, false, false), 1_u64)
        .unwrap_or_else(|_| panic!("bind"));
    let (error, _) = *no_root
        .borrow_receiver(transport_live(FIXTURE_DECLARATION, 0, 4, true))
        .err()
        .unwrap_or_else(|| panic!("missing loan root refuses"));
    assert_eq!(error, HostResourceError::MissingLoanRoot);
}

/// Abandoned and forgotten loans retain a reuse fence until sealed emergency cleanup.
#[test]
fn host_receiver_loan_abandonment_and_forgetting_fence_reuse() {
    use gantry::runtime::{HostResourceError, OwnedHostResource};
    for forgotten in [false, true] {
        let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut resource = OwnedHostResource::bind(
            admitted_active(),
            TransportValue {
                drops: Arc::clone(&drops),
                panic_on_drop: false,
                value: 1,
            },
        )
        .unwrap_or_else(|_| panic!("bind"));
        let before = resource.account().durable_record();
        let loan = resource
            .borrow_receiver(transport_live(FIXTURE_DECLARATION, 0, 4, true))
            .unwrap_or_else(|_| panic!("borrow"));
        if forgotten {
            std::mem::forget(loan);
        } else {
            drop(loan);
        }
        assert_eq!(resource.account().durable_record(), before);
        assert_eq!(resource.is_poisoned(), !forgotten);
        assert_eq!(
            resource.invoke::<()>(OwnerGeneration::new(4), |_| panic!(
                "loan blocks invocation"
            )),
            Err(HostResourceError::LoanOutstanding)
        );
        assert_eq!(
            resource.finish(OwnerGeneration::new(4), 31, |_| panic!(
                "loan blocks finish"
            )),
            Err(HostResourceError::LoanOutstanding)
        );
        let (error, mut resource) = *resource
            .transfer(OwnerGeneration::new(4), OwnerGeneration::new(5))
            .err()
            .unwrap_or_else(|| panic!("loan blocks transfer"));
        assert_eq!(error, HostResourceError::LoanOutstanding);
        let failure = failure_settlement_in(
            FIXTURE_WORKFLOW,
            FIXTURE_DECLARATION,
            vec![FIXTURE_SITE],
            0,
            FailureClass::ResourceFailure,
        );
        assert_eq!(
            resource.poison_from_failure(&failure, 31),
            Err(HostResourceError::LoanOutstanding)
        );
        assert_eq!(resource.account().durable_record(), before);
        assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(
            resource.emergency_release(emergency_cleanup()),
            Ok(ResourceLifetimeState::EmergencyReleased)
        );
        assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 1);
        drop(resource);
        assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
}

/// Explicit move charges commit with ownership, never with a refused transfer.
#[test]
fn charged_host_transfer_preserves_refusals_and_commits_once() {
    use gantry::runtime::{HostResourceError, OwnedHostResource};
    let owner = OwnerGeneration::new(4);
    let successor = OwnerGeneration::new(5);
    let charges = [Charge {
        owner: QuotaOwner::Owner,
        family: QuotaFamily::Bytes,
        amount: 2,
    }];
    let mut resource = OwnedHostResource::bind(transfer_account(false, false, false), 17_u64)
        .unwrap_or_else(|_| panic!("bind"));
    let before = resource.account().durable_record();
    for (next, vector, expected) in [
        (
            owner,
            vec![Charge {
                amount: 9,
                ..charges[0]
            }],
            ResourceError::InvalidSuccessorGeneration,
        ),
        (
            successor,
            vec![
                charges[0],
                Charge {
                    family: QuotaFamily::Operations,
                    ..charges[0]
                },
            ],
            ResourceError::UndeclaredQuota,
        ),
        (
            successor,
            vec![Charge {
                amount: 9,
                ..charges[0]
            }],
            ResourceError::QuotaExhausted,
        ),
    ] {
        let (error, returned) = *resource
            .transfer_with_charges(owner, next, &vector)
            .err()
            .unwrap_or_else(|| panic!("transfer must refuse"));
        assert_eq!(error, HostResourceError::Model(expected));
        assert_eq!(returned.account().durable_record(), before);
        resource = returned;
    }
    let mut moved = resource
        .transfer_with_charges(owner, successor, &charges)
        .unwrap_or_else(|_| panic!("valid charged transfer"));
    assert_eq!(moved.account().ledger().owner(), successor);
    assert_eq!(
        moved
            .account()
            .remaining(QuotaOwner::Owner, QuotaFamily::Bytes),
        Some(6)
    );
    assert_eq!(moved.account().containment().owner(), owner);
    assert_eq!(
        moved.account().containment().outcome(),
        Some(ExternalOutcome::Accepted)
    );
    assert_eq!(
        moved.account().durable_record().liveness_roots(),
        before.liveness_roots()
    );
    assert_eq!(moved.invoke(successor, |value| Ok(*value)), Ok(17));
    assert_eq!(
        moved.finish(successor, 40, |_| Ok(())),
        Ok(ResourceLifetimeState::Finished)
    );
    assert_eq!(
        moved
            .account()
            .remaining(QuotaOwner::Owner, QuotaFamily::Bytes),
        Some(6)
    );
}

/// A consuming move advances only the owner and retains one physical value and historical evidence.
#[test]
fn owned_host_resource_transfer_preserves_facts_and_fences_the_previous_owner() {
    use gantry::runtime::{HostResourceError, OwnedHostResource};
    let account = transfer_account(false, false, false);
    let before = account.durable_record();
    let subject = account.subject().clone();
    let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let resource = OwnedHostResource::bind(
        account,
        TransportValue {
            drops: Arc::clone(&drops),
            panic_on_drop: false,
            value: 17,
        },
    )
    .unwrap_or_else(|_| panic!("active account binds"));
    let mut transferred = resource
        .transfer(OwnerGeneration::new(4), OwnerGeneration::new(5))
        .unwrap_or_else(|_| panic!("settled unbound owner transfers"));
    assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 0);
    let after = transferred.account().durable_record();
    assert_eq!(after.owner(), OwnerGeneration::new(5));
    assert_eq!(after.lifetime(), before.lifetime());
    assert_eq!(after.operation_state(), before.operation_state());
    assert_eq!(after.quotas(), before.quotas());
    assert_eq!(after.liveness_roots(), before.liveness_roots());
    assert_eq!(after.settlement(), before.settlement());
    assert_eq!(after.successor_fence(), before.successor_fence());
    assert_eq!(transferred.account().subject(), &subject);
    assert_eq!(
        transferred.account().containment().owner(),
        OwnerGeneration::new(4)
    );
    assert_eq!(
        transferred.account().containment().outcome(),
        Some(ExternalOutcome::Accepted)
    );
    assert!(matches!(
        transferred.invoke::<()>(OwnerGeneration::new(4), |_| panic!(
            "old owner cannot invoke"
        )),
        Err(HostResourceError::Model(ResourceError::StaleOwner { .. }))
    ));
    assert_eq!(
        transferred.invoke(OwnerGeneration::new(5), |value| Ok(value.value)),
        Ok(17)
    );
    let decoded =
        decode_resource_reconstruction_record(&encode_resource_reconstruction_record(&after))
            .unwrap_or_else(|error| panic!("transferred record decodes: {error:?}"));
    assert_eq!(decoded, after);
    assert_eq!(
        transferred.finish(OwnerGeneration::new(5), 40, |_| Ok(())),
        Ok(ResourceLifetimeState::Finished)
    );
    assert_eq!(
        transferred
            .account()
            .durable_record()
            .settlement()
            .map(|baseline| baseline.owner()),
        Some(OwnerGeneration::new(5))
    );
    drop(transferred);
    assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 1);
}

/// Every refusal returns the complete affine owner without modifying its facts or disposing its value.
#[test]
fn owned_host_resource_transfer_refuses_outstanding_obligations_without_mutation() {
    use gantry::runtime::{HostResourceError, OwnedHostResource};
    for (account, owner, successor, expected) in [
        (
            transfer_account(false, false, false),
            3,
            5,
            HostResourceError::Model(ResourceError::StaleOwner {
                presented: OwnerGeneration::new(3),
                current: OwnerGeneration::new(4),
            }),
        ),
        (
            transfer_account(false, false, false),
            4,
            4,
            HostResourceError::Model(ResourceError::InvalidSuccessorGeneration),
        ),
        (
            transfer_account(false, false, false),
            4,
            3,
            HostResourceError::Model(ResourceError::InvalidSuccessorGeneration),
        ),
        (
            transfer_account(false, true, false),
            4,
            5,
            HostResourceError::LoanOutstanding,
        ),
        (
            transfer_account(true, false, false),
            4,
            5,
            HostResourceError::PendingOperation,
        ),
        (
            transfer_account(false, false, true),
            4,
            5,
            HostResourceError::ContainmentPending,
        ),
    ] {
        let before = account.durable_record();
        let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let resource = OwnedHostResource::bind(
            account,
            TransportValue {
                drops: Arc::clone(&drops),
                panic_on_drop: false,
                value: 17,
            },
        )
        .unwrap_or_else(|_| panic!("active account binds"));
        let (error, mut returned) = *resource
            .transfer(OwnerGeneration::new(owner), OwnerGeneration::new(successor))
            .err()
            .unwrap_or_else(|| panic!("outstanding obligation refuses"));
        assert_eq!(error, expected);
        assert_eq!(returned.account().durable_record(), before);
        assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(
            returned.invoke(OwnerGeneration::new(4), |value| Ok(value.value)),
            Ok(17)
        );
        drop(returned);
        assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
    let mut bound = transfer_account(false, false, false);
    bound
        .bind_adapter_instance(
            OwnerGeneration::new(4),
            adapter_instance("transfer_bound", 4, 0),
        )
        .unwrap_or_else(|error| panic!("adapter binds: {error:?}"));
    let resource = OwnedHostResource::bind(bound, 1_u64).unwrap_or_else(|_| panic!("bind"));
    let before = resource.account().durable_record();
    let (error, returned) = *resource
        .transfer(OwnerGeneration::new(4), OwnerGeneration::new(5))
        .err()
        .unwrap_or_else(|| panic!("bound adapter refuses"));
    assert_eq!(error, HostResourceError::AdapterBound);
    assert_eq!(returned.account().durable_record(), before);
    assert!(returned.account().adapter_instance().is_some());
    let mut resource = OwnedHostResource::bind(transfer_account(false, false, false), 1_u64)
        .unwrap_or_else(|_| panic!("bind"));
    assert!(
        resource
            .invoke::<()>(OwnerGeneration::new(4), |_| panic!("poison"))
            .is_err()
    );
    let before = resource.account().durable_record();
    let (error, returned) = *resource
        .transfer(OwnerGeneration::new(4), OwnerGeneration::new(5))
        .err()
        .unwrap_or_else(|| panic!("poison refuses"));
    assert_eq!(error, HostResourceError::TransportPoisoned);
    assert_eq!(returned.account().durable_record(), before);
}

/// Transport ownership is affine even when the underlying value is copyable.
#[test]
fn owned_host_resource_fences_invocation_and_finishes_exactly_once() {
    use gantry::runtime::{HostResourceError, OwnedHostResource};
    assert_not_impl_any!(OwnedHostResource<u64>: Clone, Copy);
    let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut resource = OwnedHostResource::bind(
        admitted_active(),
        TransportValue {
            drops: Arc::clone(&drops),
            panic_on_drop: false,
            value: 0,
        },
    )
    .unwrap_or_else(|_| panic!("active account binds"));
    let before = resource.account().durable_record();
    assert!(matches!(
        resource.invoke::<()>(OwnerGeneration::new(3), |_| {
            panic!("stale owner cannot invoke integration")
        }),
        Err(HostResourceError::Model(ResourceError::StaleOwner { .. }))
    ));
    assert_eq!(resource.account().durable_record(), before);
    assert_eq!(
        resource.invoke(OwnerGeneration::new(4), |value| {
            value.value += 1;
            Ok(value.value)
        }),
        Ok(1)
    );
    assert_eq!(
        resource.finish(OwnerGeneration::new(4), 31, |value| {
            assert_eq!(value.value, 1);
            Ok(())
        }),
        Ok(ResourceLifetimeState::Finished)
    );
    assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 1);
    let finished = resource.account().durable_record();
    assert_eq!(
        finished.settlement().map(|baseline| baseline.settled_at()),
        Some(31)
    );
    assert_eq!(finished.quotas(), before.quotas());
    assert_eq!(
        resource.finish(OwnerGeneration::new(4), 32, |_| {
            panic!("second finish must not invoke integration")
        }),
        Err(HostResourceError::Model(
            ResourceError::IllegalLifetimeTransition
        ))
    );
    assert!(matches!(
        resource.invoke(OwnerGeneration::new(4), |_| Ok(())),
        Err(HostResourceError::Model(
            ResourceError::LifetimeDoesNotAdmitCharge { .. }
        ))
    ));
    assert_eq!(resource.account().durable_record(), finished);
    drop(resource);
    assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 1);
}

/// Refused binding returns both inputs; callback failures remain finishing without retries.
#[test]
fn owned_host_resource_preserves_refused_inputs_and_failed_finalization() {
    use gantry::host::contracts::HostError;
    use gantry::runtime::{HostResourceError, OwnedHostResource};
    let mut account = admitted_active();
    assert!(account.begin_finish_for(OwnerGeneration::new(4)).is_ok());
    let before = account.durable_record();
    let (error, returned, value) = match OwnedHostResource::bind(account, 7_u64) {
        Err(refusal) => *refusal,
        Ok(_) => panic!("finishing account cannot bind"),
    };
    assert!(matches!(
        error,
        HostResourceError::Model(ResourceError::LifetimeDoesNotAdmitCharge { .. })
    ));
    assert_eq!(returned.durable_record(), before);
    assert_eq!(value, 7);

    for panic_in_callback in [false, true] {
        let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut resource = OwnedHostResource::bind(
            admitted_active(),
            TransportValue {
                drops: Arc::clone(&drops),
                panic_on_drop: false,
                value: 0,
            },
        )
        .unwrap_or_else(|_| panic!("active account binds"));
        let failure = resource.finish(OwnerGeneration::new(4), 31, |_| {
            assert!(!panic_in_callback, "fake finalizer panic");
            Err(HostError {
                code: Arc::from("fake-finalization-failure"),
                protected_diagnostic: None,
            })
        });
        if panic_in_callback {
            assert!(matches!(failure, Err(HostResourceError::Boundary(_))));
            assert!(resource.is_poisoned());
        } else {
            assert!(matches!(failure, Err(HostResourceError::Host(_))));
        }
        assert_eq!(
            resource.account().ledger().lifetime(),
            ResourceLifetimeState::Finishing
        );
        assert_eq!(resource.account().durable_record().settlement(), None);
        assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(
            resource.finish(OwnerGeneration::new(4), 32, |_| {
                panic!("failed finish cannot be retried")
            }),
            Err(HostResourceError::Model(
                ResourceError::IllegalLifetimeTransition
            ))
        );
        assert_eq!(
            resource.emergency_release(emergency_cleanup()),
            Ok(ResourceLifetimeState::EmergencyReleased)
        );
        assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 1);
        drop(resource);
        assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
}

/// Refused callbacks are disposed under containment without executing their bodies.
#[test]
fn owned_host_resource_contains_unused_callback_destruction() {
    use gantry::runtime::{HostResourceError, OwnedHostResource};
    for case in [
        "stale-invoke",
        "stale-finish",
        "inactive-invoke",
        "inactive-finish",
        "poisoned-invoke",
        "poisoned-finish",
    ] {
        let mut resource = OwnedHostResource::bind(admitted_active(), 0_u64)
            .unwrap_or_else(|_| panic!("active account binds"));
        if case.starts_with("inactive") {
            assert!(
                resource
                    .finish(OwnerGeneration::new(4), 31, |_| Ok(()))
                    .is_ok()
            );
        }
        if case.starts_with("poisoned") {
            assert!(matches!(
                resource.invoke::<()>(OwnerGeneration::new(4), |_| {
                    panic!("initial integration failure")
                }),
                Err(HostResourceError::Boundary(_))
            ));
        }
        let before = resource.account().durable_record();
        let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let captured = TransportValue {
            drops: Arc::clone(&drops),
            panic_on_drop: true,
            value: 0,
        };
        let called = std::cell::Cell::new(false);
        let callback = |_: &mut u64| {
            called.set(true);
            drop(captured);
            Ok(())
        };
        let owner = OwnerGeneration::new(if case.starts_with("stale") { 3 } else { 4 });
        let result = if case.ends_with("finish") {
            resource.finish(owner, 32, callback)
        } else {
            resource
                .invoke(owner, callback)
                .map(|()| ResourceLifetimeState::Active)
        };
        assert!(
            matches!(result, Err(HostResourceError::Boundary(_))),
            "{case}"
        );
        assert!(!called.get(), "{case} must not execute the callback");
        assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(resource.is_poisoned());
        if case != "poisoned-finish" {
            assert_eq!(resource.account().durable_record(), before);
        } else {
            assert_eq!(
                resource.account().ledger().lifetime(),
                ResourceLifetimeState::Finishing
            );
        }
    }
}

/// Destruction panic cannot undo sealed semantic release or cause a second physical disposal.
#[test]
fn owned_host_resource_contains_disposal_panics_without_fabricating_finish() {
    use gantry::runtime::{HostResourceError, OwnedHostResource};
    for emergency in [false, true] {
        let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut resource = OwnedHostResource::bind(
            admitted_active(),
            TransportValue {
                drops: Arc::clone(&drops),
                panic_on_drop: true,
                value: 0,
            },
        )
        .unwrap_or_else(|_| panic!("active account binds"));
        let result = if emergency {
            resource.emergency_release(emergency_cleanup())
        } else {
            resource.finish(OwnerGeneration::new(4), 31, |_| Ok(()))
        };
        assert!(matches!(result, Err(HostResourceError::Boundary(_))));
        assert!(resource.is_poisoned());
        assert_eq!(
            resource.account().ledger().lifetime(),
            if emergency {
                ResourceLifetimeState::EmergencyReleased
            } else {
                ResourceLifetimeState::Finishing
            }
        );
        if !emergency {
            assert_eq!(
                resource.emergency_release(emergency_cleanup()),
                Ok(ResourceLifetimeState::EmergencyReleased)
            );
        }
        drop(resource);
        assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
    let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let resource = OwnedHostResource::bind(
        admitted_active(),
        TransportValue {
            drops: Arc::clone(&drops),
            panic_on_drop: true,
            value: 0,
        },
    )
    .unwrap_or_else(|_| panic!("active account binds"));
    assert_eq!(
        resource.account().ledger().lifetime(),
        ResourceLifetimeState::Active
    );
    drop(resource);
    assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 1);
}

/// Resource-failure cleanup releases accounting before disposal and never destroys twice.
#[test]
fn owned_host_resource_poison_cleanup_preserves_release_and_refusals() {
    use gantry::runtime::{HostResourceError, OwnedHostResource};
    for panic_on_drop in [false, true] {
        let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut resource = OwnedHostResource::bind(
            admitted_active(),
            TransportValue {
                drops: Arc::clone(&drops),
                panic_on_drop,
                value: 11,
            },
        )
        .unwrap_or_else(|_| panic!("bind"));
        let before = resource.account().durable_record();
        let adapter_failure = failure_settlement_in(
            FIXTURE_WORKFLOW,
            FIXTURE_DECLARATION,
            vec![FIXTURE_SITE],
            0,
            FailureClass::AdapterFailure,
        );
        assert_eq!(
            resource.poison_from_failure(&adapter_failure, 31),
            Err(HostResourceError::Settlement(
                PostFailureSettlementRefusal::Model(ResourceError::FailureDoesNotPoisonResource)
            ))
        );
        assert_eq!(resource.account().durable_record(), before);
        assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 0);
        let failure = failure_settlement_in(
            FIXTURE_WORKFLOW,
            FIXTURE_DECLARATION,
            vec![FIXTURE_SITE],
            0,
            FailureClass::ResourceFailure,
        );
        let foreign = failure_settlement_in(
            FIXTURE_WORKFLOW,
            SECOND_FIXTURE_DECLARATION,
            vec![FIXTURE_SITE],
            0,
            FailureClass::ResourceFailure,
        );
        assert_eq!(
            resource.poison_from_failure(&foreign, 31),
            Err(HostResourceError::Settlement(
                PostFailureSettlementRefusal::ForeignOperation
            ))
        );
        let mut stale = transport_live(FIXTURE_DECLARATION, 0, 3, false);
        let stale = stale
            .settle_failure(FailureClass::ResourceFailure)
            .unwrap_or_else(|error| panic!("stale failure fixture: {error:?}"));
        assert_eq!(
            resource.poison_from_failure(&stale, 31),
            Err(HostResourceError::Settlement(
                PostFailureSettlementRefusal::Model(ResourceError::StaleOwner {
                    presented: OwnerGeneration::new(3),
                    current: OwnerGeneration::new(4),
                })
            ))
        );
        assert_eq!(resource.account().durable_record(), before);
        assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 0);
        let result = resource.poison_from_failure(&failure, 32);
        if panic_on_drop {
            assert!(matches!(result, Err(HostResourceError::Boundary(_))));
        } else {
            assert_eq!(result, Ok(ResourceLifetimeState::Poisoned));
        }
        let after = resource.account().durable_record();
        assert_eq!(after.lifetime(), ResourceLifetimeState::Poisoned);
        assert_eq!(
            after.settlement().map(|baseline| baseline.settled_at()),
            Some(32)
        );
        assert_eq!(after.quotas(), before.quotas());
        assert_eq!(after.liveness_roots(), before.liveness_roots());
        assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(
            resource.poison_from_failure(&failure, 33),
            Err(HostResourceError::Settlement(
                PostFailureSettlementRefusal::Model(ResourceError::IllegalLifetimeTransition)
            ))
        );
        assert_eq!(resource.account().durable_record(), after);
        drop(resource);
        assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
}

#[test]
fn the_runtime_admits_only_the_declared_reconstruction_record() {
    let record = ledger().durable_record();
    let declared = [
        ("ordinary-durable-state", false),
        ("ordinary-serialization", false),
        ("reconstruction-record", true),
    ];
    let mut observed = Vec::new();
    for carrier in ResourceCarrier::ALL {
        let admitted_ok = match AdmittedResource::admit(carrier, record.clone(), active_subject()) {
            Ok(admitted_resource) => {
                assert_eq!(admitted_resource.durable_record(), record);
                true
            }
            Err(error) => {
                assert_eq!(
                    error,
                    ResourceRegistryRefusal::Admission(ResourceError::OrdinaryCarrierRefused),
                    "carrier {}",
                    carrier.wire_name()
                );
                false
            }
        };
        observed.push((carrier.wire_name(), admitted_ok));
    }
    assert_eq!(observed.as_slice(), declared.as_slice());
}

#[test]
fn an_admitted_account_preserves_every_declared_recorded_fact() {
    let mut source = ledger();
    assert!(
        source
            .charge(
                OwnerGeneration::new(4),
                ResourceAction::Move,
                &[
                    Charge {
                        owner: QuotaOwner::Owner,
                        family: QuotaFamily::Bytes,
                        amount: 3,
                    },
                    Charge {
                        owner: QuotaOwner::Resource,
                        family: QuotaFamily::Operations,
                        amount: 2,
                    },
                ],
            )
            .is_ok()
    );
    assert!(source.close_liveness_root(LivenessRoot::Loan).is_ok());
    let record = source.durable_record();

    let admitted_resource = admitted(
        ResourceCarrier::ReconstructionRecord,
        record.clone(),
        active_subject(),
    )
    .unwrap_or_else(|error| panic!("the declared reconstruction record is admitted: {error:?}"));

    assert_eq!(admitted_resource.durable_record(), record);
    assert_eq!(admitted_resource.durable_record(), source.durable_record());
    assert_eq!(admitted_resource.ledger().owner(), OwnerGeneration::new(4));
    assert_eq!(
        admitted_resource.ledger().lifetime(),
        ResourceLifetimeState::Active
    );
    assert_eq!(
        admitted_resource.ledger().operation_state(),
        ResourceState::PartiallyAdvanced
    );
    assert_eq!(admitted_resource.ledger().liveness_roots().len(), 3);
    assert!(
        !admitted_resource
            .ledger()
            .liveness_roots()
            .contains(&LivenessRoot::Loan)
    );

    let bytes = match admitted_resource.quota(QuotaOwner::Owner, QuotaFamily::Bytes) {
        Some(quota) => quota,
        None => panic!("the declared owner/bytes quota is admitted"),
    };
    assert_eq!(bytes.limit(), 8);
    assert_eq!(bytes.used(), 3);
    assert_eq!(bytes.remaining_renewals(), 1);
    assert_eq!(
        admitted_resource.remaining(QuotaOwner::Owner, QuotaFamily::Bytes),
        Some(5)
    );
    assert_eq!(
        admitted_resource.remaining(QuotaOwner::Resource, QuotaFamily::Handles),
        Some(1)
    );
    assert_eq!(
        admitted_resource.quota(QuotaOwner::DurableRecord, QuotaFamily::Bytes),
        None
    );
    assert_eq!(
        admitted_resource.remaining(QuotaOwner::DurableRecord, QuotaFamily::Bytes),
        None
    );
}

#[test]
fn semantic_release_is_independent_of_record_retirement() {
    let mut admitted_resource = admitted_active();

    assert!(
        admitted_resource
            .begin_finish_for(OwnerGeneration::new(4))
            .is_ok()
    );
    assert!(
        admitted_resource
            .complete_finalization_for(OwnerGeneration::new(4), 20)
            .is_ok()
    );
    assert_eq!(
        admitted_resource.ledger().lifetime(),
        ResourceLifetimeState::Finished
    );
    let settlement = match admitted_resource.ledger().settlement() {
        Some(settlement) => settlement,
        None => panic!("the finished lifetime retains its settlement baseline"),
    };
    assert_eq!(settlement.owner(), OwnerGeneration::new(4));
    assert_eq!(settlement.settled_at(), 20);
    assert_eq!(
        admitted_resource.remaining(QuotaOwner::Owner, QuotaFamily::Bytes),
        Some(8)
    );

    let fence = RetentionFence::new(2, 10).unwrap_or_else(|_| unreachable!("bounded fence"));
    let released = admitted_resource.ledger().clone();
    assert_eq!(
        admitted_resource.retire(fence, OwnerGeneration::new(4), OwnerGeneration::new(5), 35,),
        Err(ResourceError::LivenessRootsRemain)
    );
    assert_eq!(admitted_resource.ledger(), &released);

    for root in ROOTS {
        assert!(
            admitted_resource
                .close_liveness_root_for(OwnerGeneration::new(4), *root)
                .is_ok()
        );
    }
    let roots_closed = admitted_resource.ledger().clone();
    assert_eq!(
        admitted_resource.retire(fence, OwnerGeneration::new(4), OwnerGeneration::new(5), 25,),
        Err(ResourceError::RetentionNotExpired)
    );
    assert_eq!(admitted_resource.ledger(), &roots_closed);

    assert!(
        admitted_resource
            .retire(fence, OwnerGeneration::new(4), OwnerGeneration::new(5), 35,)
            .is_ok()
    );
    assert_eq!(
        admitted_resource.ledger().lifetime(),
        ResourceLifetimeState::Retired
    );
    assert_eq!(
        admitted_resource.ledger().successor_fence(),
        Some(OwnerGeneration::new(5))
    );
    assert_eq!(
        admitted_resource.remaining(QuotaOwner::Owner, QuotaFamily::Bytes),
        Some(8)
    );
    assert_eq!(
        admitted_resource.delete_for(OwnerGeneration::new(4)),
        Ok(ResourceLifetimeState::Deleted)
    );
    assert_eq!(
        admitted_resource.ledger().lifetime(),
        ResourceLifetimeState::Deleted
    );
}

#[test]
fn owner_authorized_changes_refuse_a_stale_generation_without_mutating() {
    let mut admitted_resource = admitted_active();
    let before = admitted_resource.ledger().clone();
    let charges = [Charge {
        owner: QuotaOwner::Owner,
        family: QuotaFamily::Bytes,
        amount: 1,
    }];
    assert_eq!(
        admitted_resource.charge(OwnerGeneration::new(5), ResourceAction::Move, &charges,),
        Err(ResourceError::StaleOwner {
            presented: OwnerGeneration::new(5),
            current: OwnerGeneration::new(4),
        })
    );
    assert_eq!(admitted_resource.ledger(), &before);
    assert!(
        admitted_resource
            .charge(OwnerGeneration::new(4), ResourceAction::Move, &charges,)
            .is_ok()
    );
    assert_eq!(
        admitted_resource.remaining(QuotaOwner::Owner, QuotaFamily::Bytes),
        Some(7)
    );
}

#[test]
fn a_charge_vector_commits_every_declared_member_or_none() {
    let mut admitted_resource = admitted_active();
    let before = admitted_resource.ledger().clone();
    assert_eq!(
        admitted_resource.charge(
            OwnerGeneration::new(4),
            ResourceAction::Copy,
            &[
                Charge {
                    owner: QuotaOwner::Owner,
                    family: QuotaFamily::Bytes,
                    amount: 2,
                },
                Charge {
                    owner: QuotaOwner::Resource,
                    family: QuotaFamily::Operations,
                    amount: 3,
                },
            ],
        ),
        Err(ResourceError::QuotaExhausted)
    );
    assert_eq!(admitted_resource.ledger(), &before);
    assert_eq!(
        admitted_resource.charge(
            OwnerGeneration::new(4),
            ResourceAction::Loan,
            &[
                Charge {
                    owner: QuotaOwner::Owner,
                    family: QuotaFamily::Bytes,
                    amount: 2,
                },
                Charge {
                    owner: QuotaOwner::DurableRecord,
                    family: QuotaFamily::Handles,
                    amount: 1,
                },
            ],
        ),
        Err(ResourceError::UndeclaredQuota)
    );
    assert_eq!(admitted_resource.ledger(), &before);
    assert_eq!(
        admitted_resource.remaining(QuotaOwner::Owner, QuotaFamily::Bytes),
        Some(8)
    );
}

/// Emergency cleanup settles through the registry: the sealed witness plus the account's own
/// subject reaches that account's ledger, an unknown subject changes nothing, the emergency release
/// frees the live place, and the retained account stays queryable.
#[test]
fn registry_routes_emergency_cleanup_and_releases_the_live_place() {
    let subject = active_subject();
    let mut registry = ResourceRegistry::with_live_limit(1);
    registry
        .admit(
            subject.clone(),
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
        )
        .unwrap_or_else(|error| {
            panic!("the declared reconstruction record is admitted: {error:?}")
        });
    assert_eq!(registry.live_resources(), 1);

    let (_program, _machine, other) =
        machine_with_declared_subject(Some(SECOND_FIXTURE_DECLARATION));
    let other = other.unwrap_or_else(|| panic!("the second fixture operation declares an action"));
    assert_eq!(
        registry.settle_from_emergency_cleanup(&other, emergency_cleanup()),
        Err(ResourceRegistryRefusal::UnknownSubject),
        "a subject this registry holds no account for changes nothing"
    );
    assert_eq!(registry.live_resources(), 1);

    assert_eq!(
        registry.settle_from_emergency_cleanup(&subject, emergency_cleanup()),
        Ok(ResourceLifetimeState::EmergencyReleased)
    );
    assert_eq!(
        registry.live_resources(),
        0,
        "emergency release frees the live place"
    );
    assert!(
        registry.account(&subject).is_some(),
        "the retained account stays queryable"
    );
    assert_eq!(
        registry.settle_from_emergency_cleanup(&subject, emergency_cleanup()),
        Err(ResourceRegistryRefusal::EmergencyRelease(
            ResourceError::IllegalLifetimeTransition
        )),
        "a second emergency release is refused by the model's transition rule"
    );
}

/// The published lifecycle report transfers its affine cleanup authority to the resource registry.
#[test]
fn published_hard_cancellation_cleanup_settles_resource_account() {
    let limits = LaunchSnapshotLimits::new(1, 0, 0, 32);
    let snapshot = LaunchSnapshot::new(
        vec!["app".into()],
        vec![],
        LogicalCwd::new("/").unwrap_or_else(|error| panic!("logical cwd: {error:?}")),
        Default::default(),
        limits,
    )
    .unwrap_or_else(|error| panic!("launch snapshot: {error:?}"));
    let entry = ApplicationEntry::new(
        "test",
        SemanticMode::Application,
        "gantry-v1",
        snapshot,
        limits,
    )
    .unwrap_or_else(|error| panic!("application entry: {error:?}"));
    let policy = GracePolicy::new(1, 1).unwrap_or_else(|error| panic!("grace policy: {error:?}"));
    let mut lifecycle = ApplicationCoordinator::new(LaunchArrangement::Standalone);
    lifecycle
        .start(&entry)
        .unwrap_or_else(|error| panic!("application starts: {error:?}"));
    lifecycle
        .translate_signal(PortableSignalClass::Interrupt, policy, 20)
        .unwrap_or_else(|error| panic!("stop closes admission: {error:?}"));
    lifecycle
        .begin_finalization()
        .unwrap_or_else(|error| panic!("finalization begins: {error:?}"));
    lifecycle
        .record_final_flush()
        .unwrap_or_else(|error| panic!("flush is recorded: {error:?}"));
    lifecycle
        .record_hard_cancellation(Some(emergency_cleanup_at(21)))
        .unwrap_or_else(|error| panic!("hard cancellation is recorded: {error:?}"));
    lifecycle
        .settle()
        .unwrap_or_else(|error| panic!("supervisor settles: {error:?}"));
    let report = ExitReport::new(
        ExitDisposition::Stopped,
        true,
        SupervisorSettlement::settled(),
        Some(emergency_cleanup_at(22)),
    )
    .unwrap_or_else(|error| panic!("exit report: {error:?}"));
    let published = lifecycle
        .publish(report)
        .unwrap_or_else(|error| panic!("exit report publishes: {error:?}"));
    let cleanup = published
        .into_cleanup()
        .unwrap_or_else(|| panic!("published hard cancellation retains cleanup"));
    assert_eq!(
        cleanup.at_us(),
        21,
        "publication transfers the coordinator witness"
    );

    let subject = active_subject();
    let mut registry = ResourceRegistry::with_live_limit(1);
    registry
        .admit(
            subject.clone(),
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
        )
        .unwrap_or_else(|error| panic!("resource admission: {error:?}"));
    assert_eq!(registry.live_resources(), 1);
    assert_eq!(
        registry.settle_from_emergency_cleanup(&subject, cleanup,),
        Ok(ResourceLifetimeState::EmergencyReleased)
    );
    assert_eq!(registry.live_resources(), 0);
    assert!(registry.account(&subject).is_some());

    let report_without_cleanup = ExitReport::new(
        ExitDisposition::Stopped,
        true,
        SupervisorSettlement::settled(),
        None,
    )
    .unwrap_or_else(|error| panic!("exit report without cleanup: {error:?}"));
    assert!(report_without_cleanup.into_cleanup().is_none());
}

/// Declared quota families are enforced on the registry's live path: an admitted charge consumes
/// declared headroom, a charge beyond the ceiling is refused with the model's own reason, an
/// undeclared family and a stale owner generation are refused, an unknown subject is refused, and a
/// refused charge leaves the account's headroom unchanged.
#[test]
fn registry_charges_declared_quotas_on_the_live_path() {
    let subject = active_subject();
    let mut registry = ResourceRegistry::new();
    registry
        .admit(
            subject.clone(),
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
        )
        .unwrap_or_else(|error| {
            panic!("the declared reconstruction record is admitted: {error:?}")
        });
    let owner = OwnerGeneration::new(4);
    let bytes = |amount: u64| Charge {
        owner: QuotaOwner::Owner,
        family: QuotaFamily::Bytes,
        amount,
    };
    let headroom = |registry: &ResourceRegistry| {
        registry
            .account(&subject)
            .and_then(|account| account.remaining(QuotaOwner::Owner, QuotaFamily::Bytes))
    };
    assert_eq!(headroom(&registry), Some(8));
    assert!(
        registry
            .charge(&subject, owner, ResourceAction::Move, &[bytes(3)])
            .is_ok()
    );
    assert_eq!(
        headroom(&registry),
        Some(5),
        "the admitted charge consumes declared headroom"
    );
    assert_eq!(
        registry.charge(&subject, owner, ResourceAction::Move, &[bytes(6)]),
        Err(ResourceRegistryRefusal::Charge(
            ResourceError::QuotaExhausted
        )),
        "a charge beyond the declared ceiling is refused"
    );
    assert_eq!(
        headroom(&registry),
        Some(5),
        "a refused charge changes nothing"
    );
    assert_eq!(
        registry.charge(
            &subject,
            owner,
            ResourceAction::Move,
            &[Charge {
                owner: QuotaOwner::DurableRecord,
                family: QuotaFamily::Bytes,
                amount: 1,
            }],
        ),
        Err(ResourceRegistryRefusal::Charge(
            ResourceError::UndeclaredQuota
        )),
        "an undeclared owner and family key is refused"
    );
    assert!(matches!(
        registry.charge(
            &subject,
            OwnerGeneration::new(5),
            ResourceAction::Move,
            &[bytes(1)],
        ),
        Err(ResourceRegistryRefusal::Charge(
            ResourceError::StaleOwner { .. }
        ))
    ));
    let (_program, _machine, other) =
        machine_with_declared_subject(Some(SECOND_FIXTURE_DECLARATION));
    let other = other.unwrap_or_else(|| panic!("the second fixture operation declares an action"));
    assert_eq!(
        registry.charge(&other, owner, ResourceAction::Move, &[bytes(1)]),
        Err(ResourceRegistryRefusal::UnknownSubject),
        "a subject this registry holds no account for changes nothing"
    );
    assert_eq!(headroom(&registry), Some(5));
}

/// Bounded renewal is enforced on the registry's live path: one declared renewal raises exactly one
/// ceiling and consumes one allowance, an exhausted allowance, an undeclared key, and a stale owner
/// are refused with the model's own reasons, an unknown subject is refused, and a refused renewal
/// changes nothing.
#[test]
fn registry_renews_one_declared_quota_and_refuses_exhaustion() {
    let subject = active_subject();
    let mut registry = ResourceRegistry::new();
    registry
        .admit(
            subject.clone(),
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
        )
        .unwrap_or_else(|error| {
            panic!("the declared reconstruction record is admitted: {error:?}")
        });
    let owner = OwnerGeneration::new(4);
    let headroom = |registry: &ResourceRegistry| {
        registry
            .account(&subject)
            .and_then(|account| account.remaining(QuotaOwner::Owner, QuotaFamily::Bytes))
    };
    assert_eq!(headroom(&registry), Some(8));
    assert!(
        registry
            .renew(&subject, owner, QuotaOwner::Owner, QuotaFamily::Bytes, 4)
            .is_ok()
    );
    assert_eq!(
        headroom(&registry),
        Some(12),
        "the renewal raises exactly that ceiling"
    );
    assert_eq!(
        registry.renew(&subject, owner, QuotaOwner::Owner, QuotaFamily::Bytes, 4),
        Err(ResourceRegistryRefusal::Renewal(
            ResourceError::RenewalExhausted
        )),
        "the declared allowance admits exactly one renewal"
    );
    assert_eq!(
        headroom(&registry),
        Some(12),
        "a refused renewal changes nothing"
    );
    assert_eq!(
        registry.renew(
            &subject,
            owner,
            QuotaOwner::DurableRecord,
            QuotaFamily::Bytes,
            1,
        ),
        Err(ResourceRegistryRefusal::Renewal(
            ResourceError::UndeclaredQuota
        )),
        "an undeclared owner and family key is refused"
    );
    assert!(matches!(
        registry.renew(
            &subject,
            OwnerGeneration::new(5),
            QuotaOwner::Owner,
            QuotaFamily::Bytes,
            1,
        ),
        Err(ResourceRegistryRefusal::Renewal(
            ResourceError::StaleOwner { .. }
        ))
    ));
    let (_program, _machine, other) =
        machine_with_declared_subject(Some(SECOND_FIXTURE_DECLARATION));
    let other = other.unwrap_or_else(|| panic!("the second fixture operation declares an action"));
    assert_eq!(
        registry.renew(&other, owner, QuotaOwner::Owner, QuotaFamily::Bytes, 1),
        Err(ResourceRegistryRefusal::UnknownSubject),
        "a subject this registry holds no account for changes nothing"
    );
    assert_eq!(headroom(&registry), Some(12));
}

fn emergency_cleanup() -> EmergencyCleanupWitness {
    emergency_cleanup_at(21)
}

fn emergency_cleanup_at(at_us: u64) -> EmergencyCleanupWitness {
    emergency_escalation_at(at_us).admit_emergency_release()
}

/// Issues sealed fixture evidence only through the stop coordinator's declared deadline.
fn emergency_escalation_at(at_us: u64) -> gantry::ir::Escalation {
    let policy =
        GracePolicy::new(1, 1).unwrap_or_else(|_| unreachable!("fixture stop policy is bounded"));
    let mut coordinator = StopCoordinator::new();
    assert!(
        coordinator
            .request_stop(StopRequest::new(StopCause::OperatorSignal, policy, 20))
            .is_ok()
    );
    let mut tasks: [TaskStopState; 0] = [];
    coordinator
        .escalate(&mut tasks, at_us)
        .unwrap_or_else(|_| unreachable!("held stop request escalates at its deadline"))
}

#[test]
fn runtime_emergency_settlement_requires_the_sealed_cleanup_witness() {
    let mut admitted_resource = admitted_active();
    assert_eq!(
        admitted_resource.settle_from_emergency_cleanup(emergency_cleanup()),
        Ok(ResourceLifetimeState::EmergencyReleased)
    );
    assert_eq!(
        admitted_resource.settle_from_emergency_cleanup(emergency_cleanup()),
        Err(ResourceError::IllegalLifetimeTransition)
    );
    let charges = [Charge {
        owner: QuotaOwner::Owner,
        family: QuotaFamily::Bytes,
        amount: 1,
    }];
    assert!(matches!(
        admitted_resource.charge(OwnerGeneration::new(4), ResourceAction::Update, &charges,),
        Err(ResourceError::LifetimeDoesNotAdmitCharge { .. })
    ));
}

#[test]
fn runtime_finalization_completion_requires_the_finishing_phase() {
    let mut admitted_resource = admitted_active();
    let owner = OwnerGeneration::new(4);
    assert_eq!(
        admitted_resource.complete_finalization_for(owner, 20),
        Err(ResourceError::IllegalLifetimeTransition)
    );
    assert!(admitted_resource.begin_finish_for(owner).is_ok());
    assert_eq!(
        admitted_resource.complete_finalization_for(owner, 20),
        Ok(ResourceLifetimeState::Finished)
    );
    assert_eq!(
        admitted_resource.complete_finalization_for(owner, 21),
        Err(ResourceError::IllegalLifetimeTransition)
    );
}

#[test]
fn emergency_release_survives_declared_registry_reconstruction() {
    let subject = active_subject();
    let mut registry = ResourceRegistry::new();
    registry
        .admit(
            subject.clone(),
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
        )
        .unwrap_or_else(|error| {
            panic!("the declared reconstruction record is admitted: {error:?}")
        });
    assert_eq!(
        registry.settle_from_emergency_cleanup(&subject, emergency_cleanup()),
        Ok(ResourceLifetimeState::EmergencyReleased)
    );

    let captured = registry.declared_records();
    assert_eq!(captured.len(), 1);
    let captured = &captured[0];
    let settlement = captured
        .record()
        .settlement()
        .unwrap_or_else(|| panic!("emergency release retains its settlement baseline"));
    assert_eq!(settlement.owner(), OwnerGeneration::new(4));
    assert_eq!(settlement.settled_at(), 21);

    let encoded = encode_resource_reconstruction_record(captured.record());
    let decoded = decode_resource_reconstruction_record(&encoded)
        .unwrap_or_else(|error| panic!("emergency-release record decodes: {error:?}"));
    let recovered = ResourceRegistry::reconstruct(
        None,
        vec![RecoveredResourceRecord::new(
            captured.subject().clone(),
            captured.carrier(),
            captured.owner(),
            decoded,
        )],
    )
    .unwrap_or_else(|error| panic!("emergency-release record reconstructs: {error:?}"));

    assert_eq!(recovered.live_resources(), 0);
    let account = recovered
        .account(&subject)
        .unwrap_or_else(|| panic!("the reconstructed registry retains the subject"));
    assert_eq!(
        account.ledger().lifetime(),
        ResourceLifetimeState::EmergencyReleased
    );
    assert_eq!(account.durable_record(), captured.record().clone());
    let settlement = account
        .ledger()
        .settlement()
        .unwrap_or_else(|| panic!("reconstructed emergency release retains its baseline"));
    assert_eq!(settlement.owner(), OwnerGeneration::new(4));
    assert_eq!(settlement.settled_at(), 21);
}

/// Failure-state projection changes no lifetime, roots, quota, or accepted-work lease.
#[test]
fn runtime_projects_retained_failure_state_without_releasing_accounting() {
    for failure in FailureClass::ALL {
        let (_, machine, subject) = machine_with_declared_subject(Some(FIXTURE_DECLARATION));
        let subject = subject.unwrap_or_else(|| panic!("subject exists"));
        let mut registry = ResourceRegistry::with_limits(1, 1);
        registry
            .admit_pending_operation(
                &machine,
                ResourceCarrier::ReconstructionRecord,
                ledger().durable_record(),
            )
            .unwrap_or_else(|error| panic!("admission: {error:?}"));
        let before = registry.declared_records();
        let mut live = transport_live(FIXTURE_DECLARATION, 0, 4, false);
        assert_eq!(
            registry.project_failure_state(&live, &subject),
            Err(ResourceRegistryRefusal::OperationStateProjectionNotSettled)
        );
        assert_eq!(registry.declared_records(), before);
        assert!(live.settle_failure(failure).is_ok());
        let projection = live
            .failure_state_projection()
            .unwrap_or_else(|| panic!("failure projects state"));
        let mut expected = ResourceLedger::reconstruct(before[0].record().clone());
        assert!(expected.project_operation_state(&projection).is_ok());
        assert_eq!(
            registry.project_failure_state(&live, &subject),
            Ok(projection.state())
        );
        assert_eq!(
            registry
                .account(&subject)
                .map(AdmittedResource::durable_record),
            Some(expected.durable_record())
        );
        assert_eq!(registry.live_resources(), 1);
        assert_eq!(registry.pending_operations(), 1);
        assert_eq!(
            registry.project_operation_state(&live, &subject),
            Err(ResourceRegistryRefusal::OperationStateProjectionNotSettled)
        );
        if failure == FailureClass::AdapterFailure {
            let half_closed = registry.declared_records();
            let mut older_success = transport_live(FIXTURE_DECLARATION, 0, 4, false);
            let completion = OperationSettlement::new(
                older_success.operation(),
                older_success.generation(),
                older_success.owner(),
                ExternalOutcome::Accepted,
                ProgressObservation::ShortRead,
                29,
            )
            .unwrap_or_else(|error| panic!("older completion: {error:?}"));
            assert!(older_success.settle(&completion).is_ok());
            assert_eq!(
                registry.project_operation_state(&older_success, &subject),
                Err(ResourceRegistryRefusal::OperationStateProjection(
                    ResourceError::TerminalOperationStateRevival
                ))
            );
            assert_eq!(registry.declared_records(), half_closed);
            assert_eq!(
                registry.project_failure_state(&live, &subject),
                Ok(ResourceState::HalfClosed)
            );
        }
        let records = registry.declared_records();
        let stale = transport_live(FIXTURE_DECLARATION, 0, 3, false);
        let mut stale = stale;
        assert!(stale.settle_failure(failure).is_ok());
        assert_eq!(
            registry.project_failure_state(&stale, &subject),
            Err(ResourceRegistryRefusal::OperationStateProjection(
                ResourceError::StaleOwner {
                    presented: OwnerGeneration::new(3),
                    current: OwnerGeneration::new(4),
                }
            ))
        );
        assert_eq!(registry.declared_records(), records);
        let older = live.clone();
        live.fence(gantry::ir::FenceCategory::Revocation);
        assert_eq!(
            registry.project_failure_state(&live, &subject),
            Ok(ResourceState::Poisoned)
        );
        if failure == FailureClass::AdapterFailure {
            let poisoned = registry.declared_records();
            assert_eq!(
                registry.project_failure_state(&older, &subject),
                Err(ResourceRegistryRefusal::OperationStateProjection(
                    ResourceError::PoisonedOperationStateRevival
                ))
            );
            assert_eq!(registry.declared_records(), poisoned);
        }

        let coordinator = resource_coordinator(machine.execution_id(), machine.task_id(), Some(1));
        assert!(
            coordinator
                .admit_resource(
                    &machine,
                    ResourceCarrier::ReconstructionRecord,
                    ledger().durable_record()
                )
                .is_ok()
        );
        let prior = coordinator.snapshot();
        assert_eq!(
            coordinator.project_resource_failure_state(&older, &subject),
            Ok(projection.state())
        );
        let after = coordinator.snapshot();
        assert_eq!(after.publication(), prior.publication() + 1);
        assert_eq!(
            after.resource_records().map(|records| records[0].record()),
            Some(&expected.durable_record())
        );
        assert!(coordinator.has_unsettled_resource_accounts());
        assert!(coordinator.has_pending_resource_operations());
        assert_eq!(
            coordinator.project_resource_failure_state(&stale, &subject),
            Err(gantry::runtime::CoordinatorResourceRefusal::Registry(
                ResourceRegistryRefusal::OperationStateProjection(ResourceError::StaleOwner {
                    presented: OwnerGeneration::new(3),
                    current: OwnerGeneration::new(4),
                })
            ))
        );
        assert_eq!(coordinator.snapshot(), after);
    }
}

#[test]
fn runtime_projects_only_accepted_live_settlement_state_into_matching_account() {
    let subject = active_subject();
    let operation_path = CanonicalPath::new(FIXTURE_DECLARATION)
        .unwrap_or_else(|_| unreachable!("fixture declaration is canonical"));
    let operation_site = StaticSiteId::new(
        CanonicalPath::new(FIXTURE_WORKFLOW)
            .unwrap_or_else(|_| unreachable!("fixture workflow is canonical")),
        StructuralPosition::new(vec![FIXTURE_SITE])
            .unwrap_or_else(|_| unreachable!("fixture site is canonical")),
    );
    let operation = OperationAbi::new(
        OperationKind::LiveResource,
        &operation_path,
        &operation_site,
        0,
        RecoveryClass::Idempotent,
        ReceiverOwnership::RetainedByCaller,
    )
    .unwrap_or_else(|_| unreachable!("fixture operation is admissible"));
    let mut live = operation
        .open_live(
            OwnerGeneration::new(4),
            OperationAbi::observation_allowance(
                1,
                DisclosureCharge::new(1)
                    .unwrap_or_else(|| unreachable!("fixture charge is nonzero")),
            ),
        )
        .unwrap_or_else(|error| panic!("live resource opens: {error:?}"));
    assert_eq!(live.operation(), subject.operation());
    assert_eq!(live.generation(), subject.generation());

    let (_, machine, _) = machine_with_declared_subject(Some(FIXTURE_DECLARATION));
    let coordinator = resource_coordinator(machine.execution_id(), machine.task_id(), Some(1));
    coordinator
        .admit_resource(
            &machine,
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
        )
        .unwrap_or_else(|error| panic!("coordinator account admits: {error:?}"));
    let coordinator_before = coordinator.snapshot();
    assert_eq!(
        coordinator.project_resource_operation_state(&live, &subject),
        Err(gantry::runtime::CoordinatorResourceRefusal::Registry(
            ResourceRegistryRefusal::OperationStateProjectionNotSettled
        ))
    );
    assert_eq!(coordinator.snapshot(), coordinator_before);

    let mut registry = ResourceRegistry::new();
    registry
        .admit(
            subject.clone(),
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
        )
        .unwrap_or_else(|error| panic!("subject is admitted: {error:?}"));
    let before = registry
        .account(&subject)
        .unwrap_or_else(|| panic!("account remains admitted"))
        .durable_record();
    assert!(matches!(
        registry.project_operation_state(&live, &subject),
        Err(ResourceRegistryRefusal::OperationStateProjectionNotSettled)
    ));
    assert_eq!(
        registry
            .account(&subject)
            .unwrap_or_else(|| panic!("account remains admitted"))
            .durable_record(),
        before,
        "an unsettled live resource cannot project state"
    );

    let settlement = OperationSettlement::new(
        live.operation(),
        live.generation(),
        live.owner(),
        ExternalOutcome::Accepted,
        ProgressObservation::CommittedProgress,
        25,
    )
    .unwrap_or_else(|error| panic!("settlement identities agree: {error:?}"));
    assert!(live.settle(&settlement).is_ok());
    let accepted_settlement = live.settlement().cloned();
    let accepted_progress = live.progress();
    let accepted_generation = live.generation().clone();
    assert_eq!(
        coordinator
            .clone()
            .project_resource_operation_state(&live, &subject),
        Ok(ResourceState::Consumed)
    );
    let coordinator_projected = coordinator.snapshot();
    assert_eq!(
        coordinator_projected.publication(),
        coordinator_before.publication() + 1
    );
    let coordinator_records = coordinator_projected
        .resource_records()
        .unwrap_or_else(|| panic!("projected coordinator records exist"));
    assert_eq!(
        coordinator_records[0].record().operation_state(),
        ResourceState::Consumed
    );
    assert_eq!(
        coordinator_records[0].record().lifetime(),
        ResourceLifetimeState::Active
    );
    assert_eq!(coordinator_records[0].record().quotas(), before.quotas());
    assert_eq!(
        registry.project_operation_state(&live, &subject),
        Ok(ResourceState::Consumed)
    );
    let account = registry
        .account(&subject)
        .unwrap_or_else(|| panic!("account remains admitted"));
    assert_eq!(account.ledger().operation_state(), ResourceState::Consumed);
    assert_eq!(account.ledger().lifetime(), ResourceLifetimeState::Active);
    assert_eq!(account.durable_record().quotas(), before.quotas());
    assert_eq!(
        account.durable_record().liveness_roots(),
        before.liveness_roots()
    );
    assert_eq!(account.durable_record().settlement(), before.settlement());
    assert_eq!(accepted_settlement, live.settlement().cloned());
    assert_eq!(accepted_progress, live.progress());
    assert_eq!(accepted_generation, *live.generation());

    let captured = registry.declared_records();
    assert_eq!(captured.len(), 1);
    let captured = &captured[0];
    let encoded = encode_resource_reconstruction_record(captured.record());
    let decoded = decode_resource_reconstruction_record(&encoded)
        .unwrap_or_else(|error| panic!("projected operation-state record decodes: {error:?}"));
    let recovered = ResourceRegistry::reconstruct(
        None,
        vec![RecoveredResourceRecord::new(
            captured.subject().clone(),
            captured.carrier(),
            captured.owner(),
            decoded,
        )],
    )
    .unwrap_or_else(|error| panic!("projected operation-state record reconstructs: {error:?}"));
    let recovered_account = recovered
        .account(&subject)
        .unwrap_or_else(|| panic!("reconstructed registry retains the projected subject"));
    assert_eq!(
        recovered_account.ledger().operation_state(),
        ResourceState::Consumed,
        "the accepted projection remains distinct durable accounting state"
    );
    assert_eq!(
        recovered_account.ledger().lifetime(),
        ResourceLifetimeState::Active,
        "operation-state reconstruction does not settle whole-resource lifetime"
    );
    assert_eq!(
        recovered_account.durable_record(),
        captured.record().clone(),
        "projection recovery preserves every other captured accounting fact"
    );

    let mut rejected_live = operation
        .open_live(
            OwnerGeneration::new(4),
            OperationAbi::observation_allowance(
                1,
                DisclosureCharge::new(1)
                    .unwrap_or_else(|| unreachable!("fixture charge is nonzero")),
            ),
        )
        .unwrap_or_else(|error| panic!("rejection fixture opens: {error:?}"));
    assert!(
        rejected_live
            .observe(ProgressObservation::PartialAdvance)
            .is_ok()
    );
    let progress_before_refusal = rejected_live.progress();
    let candidate = OperationSettlement::new(
        rejected_live.operation(),
        rejected_live.generation(),
        rejected_live.owner(),
        ExternalOutcome::Accepted,
        ProgressObservation::CommittedProgress,
        27,
    )
    .unwrap_or_else(|error| panic!("candidate identities agree: {error:?}"));
    assert_eq!(
        rejected_live.settle(&candidate),
        Err(OperationAbiError::PartialProgressAsCompletion {
            observed: ProgressObservation::PartialAdvance,
            claimed: ProgressObservation::CommittedProgress,
        })
    );
    assert_eq!(rejected_live.settlement(), None);
    assert_eq!(rejected_live.progress(), progress_before_refusal);
    assert_eq!(
        rejected_live.operation_state_projection(),
        None,
        "a rejected Section 20 settlement cannot produce a projection"
    );

    let foreign_path = CanonicalPath::new("crate::resource_runtime_projection_foreign")
        .unwrap_or_else(|_| unreachable!("foreign fixture declaration is canonical"));
    let foreign_operation = OperationAbi::new(
        OperationKind::LiveResource,
        &foreign_path,
        &operation_site,
        0,
        RecoveryClass::Idempotent,
        ReceiverOwnership::RetainedByCaller,
    )
    .unwrap_or_else(|_| unreachable!("foreign fixture operation is admissible"));
    let mut foreign_live = foreign_operation
        .open_live(
            OwnerGeneration::new(4),
            OperationAbi::observation_allowance(
                1,
                DisclosureCharge::new(1)
                    .unwrap_or_else(|| unreachable!("fixture charge is nonzero")),
            ),
        )
        .unwrap_or_else(|error| panic!("foreign live resource opens: {error:?}"));
    let foreign_settlement = OperationSettlement::new(
        foreign_live.operation(),
        foreign_live.generation(),
        foreign_live.owner(),
        ExternalOutcome::Accepted,
        ProgressObservation::Eof,
        28,
    )
    .unwrap_or_else(|error| panic!("foreign settlement identities agree: {error:?}"));
    assert!(foreign_live.settle(&foreign_settlement).is_ok());
    let record_before_foreign_projection = registry
        .account(&subject)
        .unwrap_or_else(|| panic!("the admitted account remains available"))
        .durable_record()
        .clone();
    assert_eq!(
        registry.project_operation_state(&foreign_live, &subject),
        Err(ResourceRegistryRefusal::UnknownSubject)
    );
    assert_eq!(
        registry
            .account(&subject)
            .unwrap_or_else(|| panic!("the admitted account remains available"))
            .durable_record(),
        record_before_foreign_projection,
        "foreign settlement evidence cannot change another account"
    );

    let next_generation_operation = OperationAbi::new(
        OperationKind::LiveResource,
        &operation_path,
        &operation_site,
        1,
        RecoveryClass::Idempotent,
        ReceiverOwnership::RetainedByCaller,
    )
    .unwrap_or_else(|_| unreachable!("next-generation fixture operation is admissible"));
    let mut next_generation_live = next_generation_operation
        .open_live(
            OwnerGeneration::new(4),
            OperationAbi::observation_allowance(
                1,
                DisclosureCharge::new(1)
                    .unwrap_or_else(|| unreachable!("fixture charge is nonzero")),
            ),
        )
        .unwrap_or_else(|error| panic!("next-generation live resource opens: {error:?}"));
    let next_generation_settlement = OperationSettlement::new(
        next_generation_live.operation(),
        next_generation_live.generation(),
        next_generation_live.owner(),
        ExternalOutcome::Accepted,
        ProgressObservation::Eof,
        29,
    )
    .unwrap_or_else(|error| panic!("next-generation settlement identities agree: {error:?}"));
    assert!(
        next_generation_live
            .settle(&next_generation_settlement)
            .is_ok()
    );
    let record_before_stale_generation_projection = registry
        .account(&subject)
        .unwrap_or_else(|| panic!("the admitted account remains available"))
        .durable_record()
        .clone();
    assert_eq!(
        registry.project_operation_state(&next_generation_live, &subject),
        Err(ResourceRegistryRefusal::UnknownSubject)
    );
    assert_eq!(
        registry
            .account(&subject)
            .unwrap_or_else(|| panic!("the admitted account remains available"))
            .durable_record(),
        record_before_stale_generation_projection,
        "a settlement for an unadmitted generation cannot change another account"
    );

    let mut stale_owner_live = operation
        .open_live(
            OwnerGeneration::new(5),
            OperationAbi::observation_allowance(
                1,
                DisclosureCharge::new(1)
                    .unwrap_or_else(|| unreachable!("fixture charge is nonzero")),
            ),
        )
        .unwrap_or_else(|error| panic!("second live resource opens: {error:?}"));
    let stale_settlement = OperationSettlement::new(
        stale_owner_live.operation(),
        stale_owner_live.generation(),
        stale_owner_live.owner(),
        ExternalOutcome::Accepted,
        ProgressObservation::Eof,
        26,
    )
    .unwrap_or_else(|error| panic!("stale settlement identities agree: {error:?}"));
    assert!(stale_owner_live.settle(&stale_settlement).is_ok());
    let projected = registry
        .account(&subject)
        .unwrap_or_else(|| panic!("account remains admitted"))
        .durable_record();
    assert!(matches!(
        registry.project_operation_state(&stale_owner_live, &subject),
        Err(ResourceRegistryRefusal::OperationStateProjection(_))
    ));
    assert_eq!(
        registry
            .account(&subject)
            .unwrap_or_else(|| panic!("account remains admitted"))
            .durable_record(),
        projected,
        "stale owner evidence cannot rewrite the projected state"
    );
}

/// Both cancellation/completion race orders retain one winner through accounting reconstruction.
#[test]
fn runtime_projects_only_the_cancellation_race_winner() {
    let subject = active_subject();
    let operation_path = CanonicalPath::new(FIXTURE_DECLARATION)
        .unwrap_or_else(|_| unreachable!("fixture declaration is canonical"));
    let operation_site = StaticSiteId::new(
        CanonicalPath::new(FIXTURE_WORKFLOW)
            .unwrap_or_else(|_| unreachable!("fixture workflow is canonical")),
        StructuralPosition::new(vec![FIXTURE_SITE])
            .unwrap_or_else(|_| unreachable!("fixture site is canonical")),
    );
    let operation = OperationAbi::new(
        OperationKind::LiveResource,
        &operation_path,
        &operation_site,
        0,
        RecoveryClass::NonIdempotent,
        ReceiverOwnership::RetainedByCaller,
    )
    .unwrap_or_else(|error| panic!("race operation is admissible: {error:?}"));
    let owner = OwnerGeneration::new(4);
    let completed = OperationSettlement::new(
        operation.operation(),
        operation.generation(),
        owner,
        ExternalOutcome::Accepted,
        ProgressObservation::CommittedProgress,
        30,
    )
    .unwrap_or_else(|error| panic!("completion identities agree: {error:?}"));
    let cancelled = OperationSettlement::new(
        operation.operation(),
        operation.generation(),
        owner,
        ExternalOutcome::Ambiguous,
        ProgressObservation::PartialAdvance,
        30,
    )
    .unwrap_or_else(|error| panic!("cancellation identities agree: {error:?}"));

    for (winner, loser, state) in [
        (&completed, &cancelled, ResourceState::Consumed),
        (&cancelled, &completed, ResourceState::Poisoned),
    ] {
        let mut live = operation
            .open_live(
                owner,
                OperationAbi::observation_allowance(
                    1,
                    DisclosureCharge::new(1)
                        .unwrap_or_else(|| unreachable!("fixture charge is nonzero")),
                ),
            )
            .unwrap_or_else(|error| panic!("race resource opens: {error:?}"));
        let mut registry = ResourceRegistry::with_live_limit(1);
        registry
            .admit(
                subject.clone(),
                ResourceCarrier::ReconstructionRecord,
                ledger().durable_record(),
            )
            .unwrap_or_else(|error| panic!("race account admits: {error:?}"));
        live.settle(winner)
            .unwrap_or_else(|error| panic!("first settlement wins: {error:?}"));
        assert_eq!(registry.project_operation_state(&live, &subject), Ok(state));
        let projected = registry
            .account(&subject)
            .unwrap_or_else(|| panic!("race account remains admitted"))
            .durable_record();
        assert!(matches!(
            live.settle(loser),
            Err(OperationAbiError::SecondSettlement { .. })
        ));
        assert_eq!(live.settlement(), Some(winner));
        assert_eq!(live.progress(), winner.progress());
        assert_eq!(registry.project_operation_state(&live, &subject), Ok(state));
        assert_eq!(
            registry
                .account(&subject)
                .unwrap_or_else(|| panic!("race account remains admitted"))
                .durable_record(),
            projected,
            "a losing settlement cannot rewrite any projected accounting fact"
        );
        assert_eq!(registry.live_resources(), 1);
        assert_eq!(projected.lifetime(), ResourceLifetimeState::Active);
        let decoded = decode_resource_reconstruction_record(
            &encode_resource_reconstruction_record(&projected),
        )
        .unwrap_or_else(|error| panic!("race record decodes: {error:?}"));
        let recovered = ResourceRegistry::reconstruct(
            Some(1),
            vec![RecoveredResourceRecord::new(
                subject.clone(),
                ResourceCarrier::ReconstructionRecord,
                owner,
                decoded,
            )],
        )
        .unwrap_or_else(|error| panic!("race accounting reconstructs: {error:?}"));
        assert_eq!(recovered.live_resources(), 1);
        assert_eq!(
            recovered
                .account(&subject)
                .unwrap_or_else(|| panic!("recovered race account exists"))
                .durable_record(),
            projected,
            "reconstruction retains the winner without claiming operation replay"
        );
    }
}

/// Projection preserves a generation fence regardless of when its completion was accepted.
#[test]
fn runtime_projection_preserves_fences_before_and_after_settlement() {
    use gantry::ir::FenceCategory;
    for fence_first in [false, true] {
        let subject = active_subject();
        let mut live = transport_live(FIXTURE_DECLARATION, 0, 4, false);
        let completion = OperationSettlement::new(
            live.operation(),
            live.generation(),
            live.owner(),
            ExternalOutcome::Accepted,
            ProgressObservation::CommittedProgress,
            30,
        )
        .unwrap_or_else(|error| panic!("completion: {error:?}"));
        if fence_first {
            live.fence(FenceCategory::Revocation);
        }
        live.settle(&completion)
            .unwrap_or_else(|error| panic!("settlement: {error:?}"));
        let mut registry = ResourceRegistry::with_live_limit(1);
        registry
            .admit(
                subject.clone(),
                ResourceCarrier::ReconstructionRecord,
                ledger().durable_record(),
            )
            .unwrap_or_else(|error| panic!("admission: {error:?}"));
        if !fence_first {
            assert_eq!(
                registry.project_operation_state(&live, &subject),
                Ok(ResourceState::Consumed)
            );
            live.fence(FenceCategory::Revocation);
        }
        let before = registry
            .account(&subject)
            .unwrap_or_else(|| panic!("account retained"))
            .durable_record();
        assert_eq!(
            registry.project_operation_state(&live, &subject),
            Ok(ResourceState::Poisoned)
        );
        let after = registry
            .account(&subject)
            .unwrap_or_else(|| panic!("account retained"))
            .durable_record();
        let mut unfenced = transport_live(FIXTURE_DECLARATION, 0, 4, false);
        unfenced
            .settle(&completion)
            .unwrap_or_else(|error| panic!("old completion: {error:?}"));
        assert_eq!(
            registry.project_operation_state(&unfenced, &subject),
            Err(ResourceRegistryRefusal::OperationStateProjection(
                ResourceError::PoisonedOperationStateRevival
            )),
            "older unfenced evidence cannot clear retained poison"
        );
        assert_eq!(
            registry
                .account(&subject)
                .unwrap_or_else(|| panic!("account retained"))
                .durable_record(),
            after
        );
        assert_eq!(live.settlement(), Some(&completion));
        assert_eq!(live.progress(), completion.progress());
        assert_eq!(live.fenced(), Some(FenceCategory::Revocation));
        assert_eq!(after.lifetime(), before.lifetime());
        assert_eq!(after.quotas(), before.quotas());
        assert_eq!(after.liveness_roots(), before.liveness_roots());
        assert_eq!(after.owner(), before.owner());
        assert_eq!(after.settlement(), before.settlement());
        assert_eq!(registry.live_resources(), 1);
        assert_eq!(
            registry.project_operation_state(&live, &subject),
            Ok(ResourceState::Poisoned)
        );
        assert_eq!(
            registry
                .account(&subject)
                .unwrap_or_else(|| panic!("account retained"))
                .durable_record(),
            after
        );
        assert_eq!(
            decode_resource_reconstruction_record(&encode_resource_reconstruction_record(&after)),
            Ok(after)
        );
    }
}

/// A settled consumed or closed generation cannot regain an open operation state.
#[test]
fn runtime_terminal_projection_cannot_reopen_the_same_generation() {
    for progress in [
        ProgressObservation::CommittedProgress,
        ProgressObservation::Eof,
    ] {
        let subject = active_subject();
        let mut terminal = transport_live(FIXTURE_DECLARATION, 0, 4, false);
        let completion = OperationSettlement::new(
            terminal.operation(),
            terminal.generation(),
            terminal.owner(),
            ExternalOutcome::Accepted,
            progress,
            30,
        )
        .unwrap_or_else(|error| panic!("terminal completion: {error:?}"));
        terminal
            .settle(&completion)
            .unwrap_or_else(|error| panic!("settlement: {error:?}"));
        let mut registry = ResourceRegistry::new();
        registry
            .admit(
                subject.clone(),
                ResourceCarrier::ReconstructionRecord,
                ledger().durable_record(),
            )
            .unwrap_or_else(|error| panic!("admission: {error:?}"));
        assert_eq!(
            registry.project_operation_state(&terminal, &subject),
            Ok(completion.resource_state())
        );
        let before = registry.declared_records();
        let mut older = transport_live(FIXTURE_DECLARATION, 0, 4, false);
        let partial = OperationSettlement::new(
            older.operation(),
            older.generation(),
            older.owner(),
            ExternalOutcome::Accepted,
            ProgressObservation::ShortRead,
            29,
        )
        .unwrap_or_else(|error| panic!("partial completion: {error:?}"));
        older
            .settle(&partial)
            .unwrap_or_else(|error| panic!("older settlement: {error:?}"));
        assert_eq!(
            registry.project_operation_state(&older, &subject),
            Err(ResourceRegistryRefusal::OperationStateProjection(
                ResourceError::TerminalOperationStateRevival
            )),
            "terminal accounting cannot regain an open half from older evidence"
        );
        assert_eq!(registry.declared_records(), before);
        assert_eq!(
            registry.project_operation_state(&terminal, &subject),
            Ok(completion.resource_state())
        );
        assert_eq!(registry.declared_records(), before);
    }
}

#[test]
fn runtime_post_failure_settlement_is_bound_to_the_admitted_subject() {
    let mut admitted_resource = admitted_active();
    let before = admitted_resource.ledger().clone();

    let subject = admitted_resource.subject();
    let operation = OperationAbi::new(
        OperationKind::LiveResource,
        &CanonicalPath::new(FIXTURE_DECLARATION)
            .unwrap_or_else(|error| panic!("declaration: {error}")),
        subject.site(),
        0,
        RecoveryClass::Idempotent,
        ReceiverOwnership::RetainedByCaller,
    )
    .unwrap_or_else(|error| panic!("operation: {error:?}"));
    let mut stale_owner_resource = operation
        .open_live(
            OwnerGeneration::new(3),
            OperationAbi::observation_allowance(
                1,
                DisclosureCharge::new(1).unwrap_or_else(|| unreachable!("nonzero charge")),
            ),
        )
        .unwrap_or_else(|error| panic!("stale-owner fixture: {error:?}"));
    let stale_owner_failure = stale_owner_resource
        .settle_failure(FailureClass::ResourceFailure)
        .unwrap_or_else(|error| panic!("failure evidence: {error:?}"));
    assert_eq!(
        admitted_resource.settle_from_post_failure(&stale_owner_failure, 21),
        Err(PostFailureSettlementRefusal::Model(
            ResourceError::StaleOwner {
                presented: OwnerGeneration::new(3),
                current: OwnerGeneration::new(4),
            }
        ))
    );
    assert_eq!(admitted_resource.ledger(), &before);
    let declaration_only = operation.settle_failure(FailureClass::ResourceFailure);
    assert_eq!(declaration_only.owner(), None);
    assert_eq!(stale_owner_failure.owner(), Some(OwnerGeneration::new(3)));
    assert_eq!(
        admitted_resource.settle_from_post_failure(&declaration_only, 21),
        Err(PostFailureSettlementRefusal::MissingOwner)
    );
    assert_eq!(admitted_resource.ledger(), &before);

    let foreign = failure_settlement_in(
        FIXTURE_WORKFLOW,
        "crate::resource_runtime_foreign",
        vec![FIXTURE_SITE],
        0,
        FailureClass::ResourceFailure,
    );
    assert_eq!(
        admitted_resource.settle_from_post_failure(&foreign, 21),
        Err(PostFailureSettlementRefusal::ForeignOperation)
    );
    assert_eq!(admitted_resource.ledger(), &before);

    let stale = failure_settlement_in(
        FIXTURE_WORKFLOW,
        FIXTURE_DECLARATION,
        vec![FIXTURE_SITE],
        1,
        FailureClass::ResourceFailure,
    );
    assert_eq!(
        admitted_resource.settle_from_post_failure(&stale, 21),
        Err(PostFailureSettlementRefusal::StaleGeneration)
    );
    assert_eq!(admitted_resource.ledger(), &before);

    let non_poisoning = failure_settlement_in(
        FIXTURE_WORKFLOW,
        FIXTURE_DECLARATION,
        vec![FIXTURE_SITE],
        0,
        FailureClass::AdapterFailure,
    );
    assert_eq!(
        admitted_resource.settle_from_post_failure(&non_poisoning, 21),
        Err(PostFailureSettlementRefusal::Model(
            ResourceError::FailureDoesNotPoisonResource
        ))
    );
    assert_eq!(admitted_resource.ledger(), &before);

    let settlement = failure_settlement_in(
        FIXTURE_WORKFLOW,
        FIXTURE_DECLARATION,
        vec![FIXTURE_SITE],
        0,
        FailureClass::ResourceFailure,
    );
    assert_eq!(
        admitted_resource.subject().operation(),
        settlement.operation()
    );
    assert_eq!(
        admitted_resource.subject().generation(),
        settlement.generation()
    );
    assert_eq!(
        admitted_resource.settle_from_post_failure(&settlement, 21),
        Ok(ResourceLifetimeState::Poisoned)
    );
    let baseline = admitted_resource
        .ledger()
        .settlement()
        .unwrap_or_else(|| panic!("the poisoned lifetime retains its settlement baseline"));
    assert_eq!(baseline.owner(), OwnerGeneration::new(4));
    assert_eq!(baseline.settled_at(), 21);
    assert_eq!(
        admitted_resource.remaining(QuotaOwner::Owner, QuotaFamily::Bytes),
        Some(8)
    );
}

/// Bound adapter dispatch must require the issuing operation's recovery-class right.
#[test]
fn registry_adapter_invocation_requires_authenticated_dispatch_rights() {
    let subject = active_subject();
    let owner = OwnerGeneration::new(4);
    let mut registry = ResourceRegistry::new();
    registry
        .admit_host_value(
            subject.clone(),
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
            17_u64,
        )
        .unwrap_or_else(|_| panic!("admit"));
    registry
        .bind_adapter_instance(&subject, owner, adapter_instance("no_dispatch", 4, 0))
        .unwrap_or_else(|error| panic!("bind: {error:?}"));
    let before = registry.declared_records();
    assert_eq!(
        registry.invoke_host_value::<u64, ()>(&subject, owner, |_| panic!(
            "insufficient adapter rights must not dispatch"
        )),
        Err(gantry::runtime::HostResourceError::Operation(
            OperationAbiError::AdapterRightsInsufficient {
                recovery: RecoveryClass::Idempotent,
                rights: 0,
            }
        ))
    );
    assert_eq!(registry.declared_records(), before);
    assert!(registry.has_host_value(&subject));
    assert_eq!(registry.pending_operations(), 1);
}

/// Affine-owner and admitted-loan callbacks use the same account-qualified dispatch rights.
#[test]
fn owned_adapter_invocation_requires_authenticated_dispatch_rights() {
    use gantry::runtime::{HostResourceError, OwnedHostResource};
    let owner = OwnerGeneration::new(4);
    for authorized in [false, true] {
        let mut account = admitted_active();
        let rights = if authorized {
            RightsSet::from_rights(&[gantry::ir::AuthorityRight::InvokeIdempotent])
        } else {
            RightsSet::empty()
        };
        account
            .bind_adapter_instance(owner, adapter_instance_with("owned_dispatch", rights, 4, 0))
            .unwrap_or_else(|error| panic!("bind: {error:?}"));
        let mut resource =
            OwnedHostResource::bind(account, 17_u64).unwrap_or_else(|_| panic!("physical binding"));
        let before = resource.account().durable_record();
        let expected = if authorized {
            Ok(17)
        } else {
            Err(HostResourceError::Operation(
                OperationAbiError::AdapterRightsInsufficient {
                    recovery: RecoveryClass::Idempotent,
                    rights: 0,
                },
            ))
        };
        assert_eq!(resource.invoke(owner, |value| Ok(*value)), expected);
        {
            let mut loan = resource
                .borrow_receiver(transport_live(FIXTURE_DECLARATION, 0, 4, true))
                .unwrap_or_else(|_| panic!("loan admission"));
            assert_eq!(loan.invoke(|value| Ok(*value)), expected);
            loan.settle_failure(FailureClass::ResourceFailure)
                .unwrap_or_else(|error| panic!("loan settlement: {error:?}"));
        }
        assert_eq!(
            resource.account().durable_record().quotas(),
            before.quotas()
        );
        assert!(!resource.is_poisoned());
        assert_eq!(
            resource.emergency_release(emergency_cleanup()),
            Ok(ResourceLifetimeState::EmergencyReleased)
        );
    }
}

/// Finalizer dispatch cannot bypass adapter rights or consume accounting on admission refusal.
#[test]
fn owned_adapter_finalization_requires_dispatch_rights_before_accounting_mutation() {
    use gantry::runtime::{HostResourceError, OwnedHostResource};
    let owner = OwnerGeneration::new(4);
    for authorized in [false, true] {
        let mut account = admitted_active();
        let rights = if authorized {
            RightsSet::from_rights(&[gantry::ir::AuthorityRight::InvokeIdempotent])
        } else {
            RightsSet::empty()
        };
        account
            .bind_adapter_instance(
                owner,
                adapter_instance_with("finalizer_dispatch", rights, 4, 0),
            )
            .unwrap_or_else(|error| panic!("bind: {error:?}"));
        let mut resource =
            OwnedHostResource::bind(account, 17_u64).unwrap_or_else(|_| panic!("physical binding"));
        let before = resource.account().durable_record();
        let called = std::sync::atomic::AtomicBool::new(false);
        let result = resource.finish(owner, 20, |_| {
            called.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        });
        if authorized {
            assert_eq!(result, Ok(ResourceLifetimeState::Finished));
        } else {
            assert_eq!(
                result,
                Err(HostResourceError::Operation(
                    OperationAbiError::AdapterRightsInsufficient {
                        recovery: RecoveryClass::Idempotent,
                        rights: 0,
                    }
                ))
            );
            assert_eq!(resource.account().durable_record(), before);
            assert_eq!(
                resource.emergency_release(emergency_cleanup()),
                Ok(ResourceLifetimeState::EmergencyReleased)
            );
        }
        assert_eq!(called.load(std::sync::atomic::Ordering::SeqCst), authorized);
    }
}

/// Release charges and finishing commit together only for admitted physical finalizers.
#[test]
fn charged_finalization_preserves_refusal_and_accepted_release_charges() {
    use gantry::runtime::{HostResourceError, OwnedHostResource};
    let owner = OwnerGeneration::new(4);
    let charge = |family, amount| Charge {
        owner: QuotaOwner::Owner,
        family,
        amount,
    };
    for failure_kind in 0..3 {
        let mut resource = OwnedHostResource::bind(admitted_active(), 17_u64)
            .unwrap_or_else(|_| panic!("physical binding"));
        let before = resource.account().durable_record();
        assert_eq!(
            resource.finish_with_charges(
                owner,
                20,
                &[
                    charge(QuotaFamily::Bytes, 1),
                    charge(QuotaFamily::Operations, 1)
                ],
                |_| panic!("undeclared vector tail cannot finalize")
            ),
            Err(HostResourceError::Model(ResourceError::UndeclaredQuota))
        );
        assert_eq!(resource.account().durable_record(), before);
        assert_eq!(
            resource.finish_with_charges(owner, 20, &[charge(QuotaFamily::Bytes, 9)], |_| panic!(
                "exhausted quota cannot finalize"
            )),
            Err(HostResourceError::Model(ResourceError::QuotaExhausted))
        );
        assert_eq!(resource.account().durable_record(), before);
        let failure = gantry::host::contracts::HostError {
            code: Arc::from("finalizer-failed"),
            protected_diagnostic: None,
        };
        let result =
            resource.finish_with_charges(owner, 20, &[charge(QuotaFamily::Bytes, 2)], |value| {
                assert_eq!(*value, 17);
                match failure_kind {
                    0 => Ok(()),
                    1 => Err(failure.clone()),
                    _ => panic!("accepted finalizer panic"),
                }
            });
        assert_eq!(
            resource
                .account()
                .remaining(QuotaOwner::Owner, QuotaFamily::Bytes),
            Some(6)
        );
        if failure_kind != 0 {
            if failure_kind == 1 {
                assert_eq!(result, Err(HostResourceError::Host(failure)));
            } else {
                assert!(matches!(result, Err(HostResourceError::Boundary(_))));
                assert!(resource.is_poisoned());
            }
            assert_eq!(
                resource.account().ledger().lifetime(),
                ResourceLifetimeState::Finishing
            );
            let retained = resource.account().durable_record();
            assert_eq!(
                resource.finish_with_charges(
                    owner,
                    21,
                    &[charge(QuotaFamily::Bytes, 1)],
                    |_| panic!("accepted finalization cannot be retried")
                ),
                Err(HostResourceError::Model(
                    ResourceError::IllegalLifetimeTransition
                ))
            );
            assert_eq!(resource.account().durable_record(), retained);
            assert_eq!(
                resource.emergency_release(emergency_cleanup()),
                Ok(ResourceLifetimeState::EmergencyReleased)
            );
        } else {
            assert_eq!(result, Ok(ResourceLifetimeState::Finished));
        }
    }
}

/// A poisoned adapter cannot carry another physical callback, while siblings remain usable.
#[test]
fn registry_physical_invocation_refuses_a_poisoned_bound_adapter() {
    let subject = active_subject();
    let sibling = declared_subject(SECOND_FIXTURE_DECLARATION);
    let owner = OwnerGeneration::new(4);
    let mut registry = ResourceRegistry::new();
    for (binding, name) in [(&subject, "physical"), (&sibling, "sibling")] {
        registry
            .admit_host_value(
                binding.clone(),
                ResourceCarrier::ReconstructionRecord,
                ledger().durable_record(),
                17_u64,
            )
            .unwrap_or_else(|_| panic!("admit"));
        registry
            .bind_adapter_instance(
                binding,
                owner,
                adapter_instance_with(
                    name,
                    RightsSet::from_rights(&[gantry::ir::AuthorityRight::InvokeIdempotent]),
                    4,
                    0,
                ),
            )
            .unwrap_or_else(|error| panic!("bind: {error:?}"));
        assert_eq!(
            registry.invoke_host_value::<u64, u64>(binding, owner, |value| Ok(*value)),
            Ok(17)
        );
    }
    registry
        .poison_adapter_instance(&subject, owner, PoisonReason::InvariantFailure)
        .unwrap_or_else(|error| panic!("poison: {error:?}"));
    let before = registry.declared_records();
    let called = std::sync::atomic::AtomicBool::new(false);
    let result = registry.invoke_host_value::<u64, ()>(&subject, owner, |_| {
        called.store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    });
    assert!(
        matches!(
            result,
            Err(gantry::runtime::HostResourceError::Operation(
                OperationAbiError::AdapterInstancePoisoned { .. }
            ))
        ),
        "poisoned adapter cannot carry physical invocation"
    );
    assert!(!called.load(std::sync::atomic::Ordering::SeqCst));
    assert_eq!(registry.declared_records(), before);
    assert_eq!(
        registry.invoke_host_value::<u64, u64>(&sibling, owner, |value| Ok(*value)),
        Ok(17)
    );
    assert!(registry.has_host_value(&subject));
    let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let unused = TransportValue {
        drops: Arc::clone(&drops),
        panic_on_drop: true,
        value: 0,
    };
    let result = registry.invoke_host_value::<u64, ()>(&subject, owner, move |_| {
        drop(unused);
        panic!("poisoned adapter cannot execute this callback")
    });
    assert!(matches!(
        result,
        Err(gantry::runtime::HostResourceError::Boundary(_))
    ));
    assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(registry.declared_records(), before);
    assert!(registry.has_host_value(&subject));
    assert_eq!(
        registry.invoke_host_value::<u64, u64>(&sibling, owner, |value| Ok(*value)),
        Ok(17)
    );
    registry
        .begin_finish(&subject, owner)
        .unwrap_or_else(|error| panic!("finish: {error:?}"));
    assert_eq!(registry.dispose_host_value(&subject, owner), Ok(()));
}

/// Aliases of one adapter identity are the same failed instance, not unaffected siblings.
#[test]
fn registry_adapter_poison_fences_aliases_and_rebinding() {
    for evidence_qualified in [false, true] {
        let subject = active_subject();
        let alias = declared_subject(SECOND_FIXTURE_DECLARATION);
        let later = declared_subject(THIRD_FIXTURE_DECLARATION);
        let owner = OwnerGeneration::new(4);
        let instance = adapter_instance("shared_physical", 4, 0);
        let mut registry = ResourceRegistry::new();
        for binding in [&subject, &alias, &later] {
            registry
                .admit_host_value(
                    binding.clone(),
                    ResourceCarrier::ReconstructionRecord,
                    ledger().durable_record(),
                    17_u64,
                )
                .unwrap_or_else(|_| panic!("admit"));
        }
        for binding in [&subject, &alias] {
            registry
                .bind_adapter_instance(binding, owner, instance.clone())
                .unwrap_or_else(|error| panic!("bind: {error:?}"));
        }
        let before = registry.declared_records();
        if evidence_qualified {
            let failure = failure_settlement_in(
                FIXTURE_WORKFLOW,
                FIXTURE_DECLARATION,
                vec![FIXTURE_SITE],
                0,
                FailureClass::AdapterFailure,
            );
            registry
                .poison_adapter_from_post_failure(
                    &failure,
                    owner,
                    PoisonReason::InvariantFailure,
                    &subject,
                )
                .unwrap_or_else(|error| panic!("evidence poison: {error:?}"));
        } else {
            registry
                .poison_adapter_instance(&subject, owner, PoisonReason::InvariantFailure)
                .unwrap_or_else(|error| panic!("poison: {error:?}"));
        }
        assert_eq!(
            registry
                .adapter_instance(&alias)
                .map(AdapterInstance::is_poisoned),
            Some(true)
        );
        assert!(matches!(
            registry.invoke_host_value::<u64, ()>(&alias, owner, |_| Ok(())),
            Err(gantry::runtime::HostResourceError::Operation(
                OperationAbiError::AdapterInstancePoisoned { .. }
            ))
        ));
        assert!(matches!(
            registry.bind_adapter_instance(&later, owner, instance),
            Err(ResourceRegistryRefusal::AdapterBinding(
                AdapterBindingRefusal::Substitution(
                    OperationAbiError::AdapterInstancePoisoned { .. }
                )
            ))
        ));
        assert_eq!(registry.adapter_instance(&later), None);
        assert_eq!(registry.declared_records(), before);
    }
}

#[test]
fn post_failure_adapter_poisoning_requires_matching_model_evidence() {
    let subject = active_subject();
    let sibling = declared_subject(SECOND_FIXTURE_DECLARATION);
    let owner = OwnerGeneration::new(4);
    let mut registry = ResourceRegistry::new();
    for admitted_subject in [&subject, &sibling] {
        registry
            .admit(
                admitted_subject.clone(),
                ResourceCarrier::ReconstructionRecord,
                ledger().durable_record(),
            )
            .unwrap_or_else(|error| {
                panic!("the declared reconstruction record is admitted: {error:?}")
            });
    }

    let adapter_failure = failure_settlement_in(
        FIXTURE_WORKFLOW,
        FIXTURE_DECLARATION,
        vec![FIXTURE_SITE],
        0,
        FailureClass::AdapterFailure,
    );
    assert_eq!(
        registry.poison_adapter_from_post_failure(
            &adapter_failure,
            owner,
            PoisonReason::ForeignFailure(ForeignFailureKind::Protocol),
            &subject,
        ),
        Err(ResourceRegistryRefusal::Settlement(
            PostFailureSettlementRefusal::AdapterBinding(AdapterBindingRefusal::Unbound)
        )),
        "a matching settlement cannot poison an unbound adapter"
    );
    assert_eq!(registry.adapter_instance(&subject), None);
    assert_eq!(registry.adapter_instance(&sibling), None);

    registry
        .bind_adapter_instance(&subject, owner, adapter_instance("post_failure", 4, 0))
        .unwrap_or_else(|error| panic!("the current owner binds its adapter: {error:?}"));
    registry
        .bind_adapter_instance(
            &sibling,
            owner,
            adapter_instance("post_failure_sibling", 4, 0),
        )
        .unwrap_or_else(|error| panic!("the current owner binds its sibling adapter: {error:?}"));

    let operation = OperationAbi::new(
        OperationKind::LiveResource,
        &CanonicalPath::new(FIXTURE_DECLARATION)
            .unwrap_or_else(|error| panic!("declaration: {error}")),
        subject.site(),
        0,
        RecoveryClass::Idempotent,
        ReceiverOwnership::RetainedByCaller,
    )
    .unwrap_or_else(|error| panic!("operation: {error:?}"));
    let unqualified = operation.settle_failure(FailureClass::AdapterFailure);
    let mut stale_live = operation
        .open_live(
            OwnerGeneration::new(3),
            OperationAbi::observation_allowance(
                1,
                DisclosureCharge::new(1).unwrap_or_else(|| unreachable!("nonzero charge")),
            ),
        )
        .unwrap_or_else(|error| panic!("stale resource: {error:?}"));
    let stale_evidence = stale_live
        .settle_failure(FailureClass::AdapterFailure)
        .unwrap_or_else(|error| panic!("stale evidence: {error:?}"));
    let before = registry.declared_records();
    for (evidence, refusal) in [
        (&unqualified, PostFailureSettlementRefusal::MissingOwner),
        (
            &stale_evidence,
            PostFailureSettlementRefusal::Model(ResourceError::StaleOwner {
                presented: OwnerGeneration::new(3),
                current: owner,
            }),
        ),
    ] {
        assert_eq!(
            registry.poison_adapter_from_post_failure(
                evidence,
                owner,
                PoisonReason::InvariantFailure,
                &subject,
            ),
            Err(ResourceRegistryRefusal::Settlement(refusal))
        );
        assert_eq!(registry.declared_records(), before);
        for subject in [&subject, &sibling] {
            assert_eq!(
                registry
                    .adapter_instance(subject)
                    .map(AdapterInstance::is_poisoned),
                Some(false)
            );
        }
    }

    let resource_failure = failure_settlement_in(
        FIXTURE_WORKFLOW,
        FIXTURE_DECLARATION,
        vec![FIXTURE_SITE],
        0,
        FailureClass::ResourceFailure,
    );
    assert_eq!(
        registry.poison_adapter_from_post_failure(
            &resource_failure,
            owner,
            PoisonReason::InvariantFailure,
            &subject,
        ),
        Err(ResourceRegistryRefusal::Settlement(
            PostFailureSettlementRefusal::AdapterPoisoningNotRequired
        )),
        "resource failure does not authorize adapter poisoning"
    );
    assert_eq!(
        registry
            .adapter_instance(&subject)
            .map(AdapterInstance::is_poisoned),
        Some(false),
        "refused evidence leaves the adapter usable"
    );

    assert_eq!(
        registry.poison_adapter_from_post_failure(
            &adapter_failure,
            OwnerGeneration::new(3),
            PoisonReason::ForeignFailure(ForeignFailureKind::Protocol),
            &subject,
        ),
        Err(ResourceRegistryRefusal::Settlement(
            PostFailureSettlementRefusal::AdapterBinding(AdapterBindingRefusal::StaleOwner(
                ResourceError::StaleOwner {
                    presented: OwnerGeneration::new(3),
                    current: owner,
                }
            ))
        )),
        "stale owners cannot poison a model-authorized failed adapter"
    );
    assert_eq!(
        registry
            .adapter_instance(&subject)
            .map(AdapterInstance::is_poisoned),
        Some(false)
    );
    assert_eq!(
        registry.poison_adapter_from_post_failure(
            &adapter_failure,
            owner,
            PoisonReason::ForeignFailure(ForeignFailureKind::Protocol),
            &subject,
        ),
        Ok(PoisonReason::ForeignFailure(ForeignFailureKind::Protocol))
    );
    assert_eq!(
        registry.poison_adapter_from_post_failure(
            &adapter_failure,
            owner,
            PoisonReason::AmbiguousEffect,
            &subject,
        ),
        Ok(PoisonReason::ForeignFailure(ForeignFailureKind::Protocol)),
        "a repeated poison preserves the first recorded reason"
    );
    assert_eq!(
        registry
            .adapter_instance(&subject)
            .map(AdapterInstance::is_poisoned),
        Some(true)
    );
    assert_eq!(
        registry
            .adapter_instance(&sibling)
            .map(AdapterInstance::is_poisoned),
        Some(false),
        "poisoning is isolated to the adapter named by the settlement"
    );
    assert_eq!(
        registry
            .account(&subject)
            .map(|account| account.ledger().lifetime()),
        Some(ResourceLifetimeState::Active),
        "adapter failure poisoning does not settle the resource lifetime"
    );

    let stale = failure_settlement_in(
        FIXTURE_WORKFLOW,
        FIXTURE_DECLARATION,
        vec![FIXTURE_SITE],
        1,
        FailureClass::AdapterFailure,
    );
    assert_eq!(
        registry.poison_adapter_from_post_failure(
            &stale,
            owner,
            PoisonReason::AmbiguousEffect,
            &subject
        ),
        Err(ResourceRegistryRefusal::UnknownSubject),
        "a different resource generation selects no admitted account"
    );
}

#[test]
fn runtime_subject_requires_the_declared_operation_action() {
    let (_program, _machine, subject) = machine_with_declared_subject(Some(FIXTURE_DECLARATION));
    let subject =
        subject.unwrap_or_else(|| panic!("metadata with a declared action carries a subject"));
    let model_issued = failure_settlement_in(
        FIXTURE_WORKFLOW,
        FIXTURE_DECLARATION,
        vec![FIXTURE_SITE],
        0,
        FailureClass::ResourceFailure,
    );
    assert_eq!(subject.operation(), model_issued.operation());
    assert_eq!(subject.generation(), model_issued.generation());
    assert_eq!(subject.site().workflow().as_str(), FIXTURE_WORKFLOW);
    assert_eq!(subject.site().position().components(), &[FIXTURE_SITE]);

    let (_program, _machine, none) = machine_with_declared_subject(None);
    assert!(
        none.is_none(),
        "an operation without a declared action has no Section 20 subject"
    );
}

#[test]
fn repeated_loop_site_gets_a_distinct_checkpointed_resource_generation() {
    let workflow = CanonicalPath::new(FIXTURE_WORKFLOW)
        .unwrap_or_else(|_| unreachable!("fixture workflow is canonical"));
    let program = Arc::new(
        MachineProgram::new(vec![Workflow {
            path: workflow.clone(),
            parameters: Vec::new(),
            result: TypeDescriptor::UNIT,
            effects: EffectSet::default(),
            instructions: vec![
                Instruction {
                    site: StructuralPosition::new(vec![FIXTURE_SITE - 1])
                        .unwrap_or_else(|_| unreachable!("loop site is canonical")),
                    ty: TypeDescriptor::UNIT,
                    kind: InstructionKind::EnterLoop {
                        phase: LoopPhase::Condition,
                        source_limit: None,
                    },
                },
                Instruction {
                    site: StructuralPosition::new(vec![FIXTURE_SITE])
                        .unwrap_or_else(|_| unreachable!("operation site is canonical")),
                    ty: TypeDescriptor::UNIT,
                    kind: InstructionKind::OperationCall {
                        operation: operation_metadata(Some(FIXTURE_DECLARATION), None),
                        operands: 0,
                    },
                },
                Instruction {
                    site: StructuralPosition::new(vec![FIXTURE_SITE + 1])
                        .unwrap_or_else(|_| unreachable!("pop site is canonical")),
                    ty: TypeDescriptor::UNIT,
                    kind: InstructionKind::Pop,
                },
                Instruction {
                    site: StructuralPosition::new(vec![FIXTURE_SITE + 2])
                        .unwrap_or_else(|_| unreachable!("leave site is canonical")),
                    ty: TypeDescriptor::UNIT,
                    kind: InstructionKind::LeaveOccurrence,
                },
                Instruction {
                    site: StructuralPosition::new(vec![FIXTURE_SITE + 3])
                        .unwrap_or_else(|_| unreachable!("jump site is canonical")),
                    ty: TypeDescriptor::UNIT,
                    kind: InstructionKind::Jump(0),
                },
            ],
        }])
        .unwrap_or_else(|error| panic!("loop resource fixture is valid: {error:?}")),
    );
    let execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [9; 32])
        .unwrap_or_else(|error| panic!("fixture execution identity is valid: {error}"));
    let limits = MachineLimits::new(32, 2, 2, 1, 32, DEFAULT_VALUE_LIMITS)
        .unwrap_or_else(|| panic!("fixture machine limits are positive"));
    let mut machine = Machine::new(
        Arc::clone(&program),
        &workflow,
        Vec::new(),
        execution,
        limits,
    )
    .unwrap_or_else(|error| panic!("loop resource machine constructs: {error:?}"));
    let first_occurrence = loop {
        match machine.step() {
            MachineStep::Transition(MachineLabel::OperationPrepared(occurrence)) => {
                break occurrence;
            }
            MachineStep::Transition(_) => {}
            MachineStep::YieldRequired => assert!(machine.resume_after_yield()),
            other => panic!("first loop operation was not prepared: {other:?}"),
        }
    };
    let first_subject = machine
        .pending_resource_subject()
        .unwrap_or_else(|| panic!("first operation has a resource subject"));
    let bytes = machine.checkpoint().canonical_bytes();
    let checkpoint = MachineCheckpointV3::decode(&program, &bytes)
        .unwrap_or_else(|error| panic!("pending-operation checkpoint decodes: {error:?}"));
    let budget = ExecutionBudget::recover_from_checkpoint(machine.budget_checkpoint())
        .unwrap_or_else(|error| panic!("operation budget recovers: {error:?}"));
    let mut machine = Machine::recover_from_checkpoint(program, checkpoint, budget)
        .unwrap_or_else(|error| panic!("pending-operation machine recovers: {error:?}"));
    assert_eq!(
        machine.pending_resource_subject(),
        Some(first_subject.clone()),
        "the checkpoint retains the allocated resource generation"
    );
    machine
        .complete_operation(first_occurrence.identity, LogicalValue::unit())
        .unwrap_or_else(|error| panic!("first operation completes: {error:?}"));
    let second_subject = loop {
        match machine.step() {
            MachineStep::Transition(MachineLabel::OperationPrepared(_)) => {
                break machine
                    .pending_resource_subject()
                    .unwrap_or_else(|| panic!("second operation has a resource subject"));
            }
            MachineStep::Transition(_) => {}
            MachineStep::YieldRequired => assert!(machine.resume_after_yield()),
            other => panic!("second loop operation was not prepared: {other:?}"),
        }
    };

    assert_ne!(
        first_subject.generation(),
        second_subject.generation(),
        "one declared operation site must not reuse a resource generation across loop invocations"
    );
    let mut registry = ResourceRegistry::new();
    assert_eq!(
        registry
            .admit(
                first_subject,
                ResourceCarrier::ReconstructionRecord,
                ledger().durable_record(),
            )
            .err(),
        Some(ResourceRegistryRefusal::UnauthenticatedOperationKind),
        "the saved unauthenticated ordinary subject cannot admit an account"
    );
    assert_eq!(
        registry
            .admit(
                second_subject,
                ResourceCarrier::ReconstructionRecord,
                ledger().durable_record(),
            )
            .err(),
        Some(ResourceRegistryRefusal::UnauthenticatedOperationKind),
        "counter allocation does not authenticate a live-resource kind"
    );
    assert!(registry.declared_records().is_empty());
}

#[test]
fn runtime_subject_survives_checkpoint_recovery() {
    let (program, machine, subject) = machine_with_declared_subject(Some(FIXTURE_DECLARATION));
    let subject = subject.unwrap_or_else(|| panic!("the fixture operation declares an action"));

    let bytes = machine.checkpoint().canonical_bytes();
    let decoded = MachineCheckpointV3::decode(&program, &bytes)
        .unwrap_or_else(|error| panic!("the fixture checkpoint decodes: {error:?}"));
    let budget = ExecutionBudget::recover_from_checkpoint(machine.budget_checkpoint())
        .unwrap_or_else(|error| panic!("the fixture budget snapshot recovers: {error:?}"));
    let recovered = Machine::recover_from_checkpoint(program, decoded, budget)
        .unwrap_or_else(|error| panic!("the fixture machine recovers: {error:?}"));

    assert_eq!(recovered.pending_resource_subject(), Some(subject.clone()));

    let mut admitted_resource = admitted(
        ResourceCarrier::ReconstructionRecord,
        ledger().durable_record(),
        recovered
            .pending_resource_subject()
            .unwrap_or_else(|| panic!("the recovered machine still declares its subject")),
    )
    .unwrap_or_else(|error| panic!("the declared reconstruction record is admitted: {error:?}"));

    let stale = failure_settlement_in(
        FIXTURE_WORKFLOW,
        FIXTURE_DECLARATION,
        vec![FIXTURE_SITE],
        1,
        FailureClass::ResourceFailure,
    );
    assert_eq!(
        admitted_resource.settle_from_post_failure(&stale, 21),
        Err(PostFailureSettlementRefusal::StaleGeneration)
    );
    let matching = failure_settlement_in(
        FIXTURE_WORKFLOW,
        FIXTURE_DECLARATION,
        vec![FIXTURE_SITE],
        0,
        FailureClass::ResourceFailure,
    );
    assert_eq!(
        admitted_resource.settle_from_post_failure(&matching, 21),
        Ok(ResourceLifetimeState::Poisoned)
    );
}

/// An issuing checkpoint derives accounting provenance without reopening its pending work.
#[test]
fn reconstruction_from_issuing_checkpoint_validates_origin_and_closes_admission() {
    use gantry::runtime::ResourceOriginRecoveryError;
    for (program, machine, expected) in [
        {
            let (program, machine, _) =
                machine_with_unauthenticated_subject(Some(FIXTURE_DECLARATION));
            (
                program,
                machine,
                ResourceRegistryRefusal::UnauthenticatedOperationKind,
            )
        },
        {
            let (program, machine, _) = machine_with_declared_subject(None);
            (
                program,
                machine,
                ResourceRegistryRefusal::NoPendingResourceSubject,
            )
        },
    ] {
        let before = machine.checkpoint().canonical_bytes();
        assert_eq!(
            RecoveredResourceRecord::from_issuing_checkpoint(
                program,
                machine.checkpoint(),
                machine.budget_checkpoint(),
                ResourceCarrier::ReconstructionRecord,
                OwnerGeneration::new(4),
                ledger().durable_record(),
            )
            .err(),
            Some(ResourceOriginRecoveryError::Registry(expected))
        );
        assert_eq!(machine.checkpoint().canonical_bytes(), before);
    }
    let (program, machine, subject) = machine_with_declared_subject(Some(FIXTURE_DECLARATION));
    let subject = subject.unwrap_or_else(|| panic!("subject exists"));
    let origin = RecoveredResourceRecord::from_issuing_checkpoint(
        Arc::clone(&program),
        machine.checkpoint(),
        machine.budget_checkpoint(),
        ResourceCarrier::ReconstructionRecord,
        OwnerGeneration::new(4),
        ledger().durable_record(),
    )
    .unwrap_or_else(|error| panic!("validated origin: {error:?}"));
    assert_eq!(origin.subject(), &subject);
    let issuing_bytes = machine.checkpoint().canonical_bytes();
    assert_eq!(
        origin.issuing_evidence(),
        Some((issuing_bytes.as_slice(), machine.budget_checkpoint()))
    );
    let legacy = RecoveredResourceRecord::new(
        subject.clone(),
        ResourceCarrier::ReconstructionRecord,
        OwnerGeneration::new(4),
        ledger().durable_record(),
    );
    assert_eq!(legacy.issuing_evidence(), None);
    let registry = ResourceRegistry::reconstruct(Some(1), vec![origin.clone()])
        .unwrap_or_else(|error| panic!("accounting recovery: {error:?}"));
    assert_eq!(registry.pending_operations(), 0);
    assert_eq!(registry.declared_records(), vec![origin.clone()]);
    let captured = registry.declared_records();
    assert_eq!(captured[0].issuing_evidence(), origin.issuing_evidence());
    let recaptured = ResourceRegistry::reconstruct(Some(1), captured)
        .unwrap_or_else(|error| panic!("recaptured provenance: {error:?}"));
    assert_eq!(recaptured.declared_records(), vec![origin.clone()]);
    let mut advanced = recaptured;
    advanced
        .begin_finish(&subject, OwnerGeneration::new(4))
        .unwrap_or_else(|error| panic!("accounting advancement: {error:?}"));
    let advanced_records = advanced.declared_records();
    assert_eq!(
        advanced_records[0].issuing_evidence(),
        origin.issuing_evidence()
    );
    assert_eq!(
        advanced_records[0].record().lifetime(),
        ResourceLifetimeState::Finishing
    );
    let mut fresh = ResourceRegistry::new();
    assert_eq!(
        fresh.admit(
            origin.subject().clone(),
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record()
        ),
        Err(ResourceRegistryRefusal::NoPendingResourceSubject)
    );
    assert!(registry.account(&subject).is_some());
    assert!(!registry.has_host_value(&subject));
    assert!(
        ResourceRegistry::new()
            .admit(
                subject.clone(),
                ResourceCarrier::ReconstructionRecord,
                ledger().durable_record()
            )
            .is_ok(),
        "origin validation must not close the source machine lease"
    );
    let mut foreign_budget = machine.budget_checkpoint();
    foreign_budget.execution =
        ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [88; 32])
            .unwrap_or_else(|error| panic!("foreign execution: {error}"));
    assert!(matches!(
        RecoveredResourceRecord::from_issuing_checkpoint(
            Arc::clone(&program),
            machine.checkpoint(),
            foreign_budget,
            ResourceCarrier::ReconstructionRecord,
            OwnerGeneration::new(4),
            ledger().durable_record(),
        ),
        Err(ResourceOriginRecoveryError::Machine(
            gantry::runtime::MachineRecoveryError::ExecutionBudgetMismatch
        ))
    ));
    for (carrier, owner, expected) in [
        (
            ResourceCarrier::OrdinarySerialization,
            OwnerGeneration::new(4),
            ResourceError::OrdinaryCarrierRefused,
        ),
        (
            ResourceCarrier::ReconstructionRecord,
            OwnerGeneration::new(3),
            ResourceError::StaleOwner {
                presented: OwnerGeneration::new(3),
                current: OwnerGeneration::new(4),
            },
        ),
    ] {
        assert_eq!(
            RecoveredResourceRecord::from_issuing_checkpoint(
                Arc::clone(&program),
                machine.checkpoint(),
                machine.budget_checkpoint(),
                carrier,
                owner,
                ledger().durable_record(),
            )
            .err(),
            Some(ResourceOriginRecoveryError::Registry(
                ResourceRegistryRefusal::Admission(expected)
            ))
        );
    }
}

/// Complete-set envelope capture refuses omitted obligations and shares one framed byte ceiling.
#[test]
fn complete_resource_envelope_capture_is_bounded_and_failure_atomic() {
    use gantry::runtime::{ResourceRecoveryEnvelopeError, encode_resource_recovery_envelope};
    let empty = ResourceRegistry::new();
    assert_eq!(empty.capture_recovery_envelopes(8), Ok(vec![]));
    assert_eq!(
        empty.capture_recovery_envelopes(7),
        Err(ResourceRecoveryEnvelopeError::ByteLimit)
    );
    let mut registry = ResourceRegistry::with_limits(2, 2);
    let mut subjects = Vec::new();
    for declaration in [FIXTURE_DECLARATION, SECOND_FIXTURE_DECLARATION] {
        let (_, mut machine, subject) = machine_with_declared_subject(Some(declaration));
        let subject = subject.unwrap_or_else(|| panic!("subject"));
        let record = ResourceLedger::new(
            OwnerGeneration::new(4),
            ResourceState::Usable,
            &[LivenessRoot::Resource],
            &[],
        )
        .unwrap_or_else(|error| panic!("ledger: {error:?}"));
        registry
            .admit_pending_operation_with_issuing_evidence(
                &machine,
                ResourceCarrier::ReconstructionRecord,
                record.durable_record(),
                65_536,
            )
            .unwrap_or_else(|error| panic!("admission: {error:?}"));
        let before = registry.declared_records_with_containment();
        assert_eq!(
            registry.capture_recovery_envelopes(131_072),
            Err(ResourceRecoveryEnvelopeError::UnsupportedRuntimeState)
        );
        assert_eq!(registry.declared_records_with_containment(), before);
        let operation = machine
            .checkpoint()
            .pending_operation()
            .unwrap_or_else(|| panic!("pending"))
            .identity;
        machine
            .fail_operation(
                operation,
                gantry::portable::RuntimeErrorCategory::ExecutorFailure,
            )
            .unwrap_or_else(|error| panic!("settlement: {error:?}"));
        subjects.push(subject);
    }
    let before = registry.declared_records_with_containment();
    let expected = before
        .iter()
        .map(|record| {
            encode_resource_recovery_envelope(record, 65_536)
                .unwrap_or_else(|error| panic!("envelope: {error:?}"))
        })
        .collect::<Vec<_>>();
    let exact = expected
        .iter()
        .fold(8_u64, |total, bytes| total + 8 + bytes.len() as u64);
    assert_eq!(registry.capture_recovery_envelopes(exact), Ok(expected));
    assert_eq!(
        registry.capture_recovery_envelopes(exact - 1),
        Err(ResourceRecoveryEnvelopeError::ByteLimit)
    );
    assert_eq!(registry.declared_records_with_containment(), before);
    registry
        .bind_adapter_instance(
            &subjects[0],
            OwnerGeneration::new(4),
            adapter_instance("capture_adapter", 4, 0),
        )
        .unwrap_or_else(|error| panic!("bind: {error:?}"));
    let before_adapter = registry.declared_records_with_containment();
    assert_eq!(
        registry.capture_recovery_envelopes(exact),
        Err(ResourceRecoveryEnvelopeError::UnsupportedRuntimeState)
    );
    assert_eq!(registry.declared_records_with_containment(), before_adapter);
}

/// Complete-set envelope restore preserves policy without manufacturing accepted work.
#[test]
fn resource_envelope_set_restore_preserves_policy_and_refuses_partial_sets() {
    use gantry::runtime::{ResourceOriginRecoveryError, ResourceRecoveryEnvelopeError};
    let (program, mut machine, subject) = machine_with_declared_subject(Some(FIXTURE_DECLARATION));
    let subject = subject.unwrap_or_else(|| panic!("subject"));
    let owner = OwnerGeneration::new(4);
    let record = ResourceLedger::new(
        owner,
        ResourceState::Usable,
        &[LivenessRoot::Resource],
        &[(QuotaOwner::Owner, QuotaFamily::Bytes, Quota::new(8, 0))],
    )
    .unwrap_or_else(|error| panic!("ledger: {error:?}"));
    let mut registry = ResourceRegistry::with_accounting_limits(1, 2, 3);
    registry
        .admit_pending_operation_with_issuing_evidence(
            &machine,
            ResourceCarrier::ReconstructionRecord,
            record.durable_record(),
            65_536,
        )
        .unwrap_or_else(|error| panic!("admit: {error:?}"));
    let operation = machine
        .checkpoint()
        .pending_operation()
        .unwrap_or_else(|| panic!("pending"))
        .identity;
    machine
        .fail_operation(
            operation,
            gantry::portable::RuntimeErrorCategory::ExecutorFailure,
        )
        .unwrap_or_else(|error| panic!("settlement: {error:?}"));
    let envelopes = registry
        .capture_recovery_envelopes(65_536)
        .unwrap_or_else(|error| panic!("capture: {error:?}"));
    let inputs = [(envelopes[0].as_slice(), owner, machine.task_id())];
    let exact = 16 + envelopes[0].len() as u64;
    let captured = registry.declared_records_with_containment();
    let original = &captured[0];
    use gantry::runtime::ResourceFinishTransition;
    let charge = Charge {
        owner: QuotaOwner::Owner,
        family: QuotaFamily::Bytes,
        amount: 2,
    };
    assert_eq!(
        original.stage_finish_with_charges(
            owner,
            ResourceFinishTransition::Begin,
            &[
                charge,
                Charge {
                    family: QuotaFamily::Operations,
                    ..charge
                }
            ]
        ),
        Err(ResourceError::UndeclaredQuota)
    );
    assert_eq!(
        original.stage_finish_with_charges(
            owner,
            ResourceFinishTransition::Begin,
            &[Charge {
                amount: 9,
                ..charge
            }]
        ),
        Err(ResourceError::QuotaExhausted)
    );
    let charged = original
        .stage_finish_with_charges(owner, ResourceFinishTransition::Begin, &[charge])
        .unwrap_or_else(|error| panic!("charged candidate: {error:?}"));
    assert_eq!(
        charged.record().lifetime(),
        ResourceLifetimeState::Finishing
    );
    assert_eq!(
        charged.record().quotas()[&(QuotaOwner::Owner, QuotaFamily::Bytes)].used(),
        2
    );
    assert_eq!(charged.subject(), original.subject());
    assert_eq!(charged.task_owner(), original.task_owner());
    assert_eq!(charged.issuing_evidence(), original.issuing_evidence());
    assert_eq!(
        charged.containment_evidence(),
        original.containment_evidence()
    );
    assert_eq!(
        charged.record().liveness_roots(),
        original.record().liveness_roots()
    );
    assert_eq!(
        charged.stage_finish_with_charges(
            owner,
            ResourceFinishTransition::Complete { settled_at: 20 },
            &[charge]
        ),
        Err(ResourceError::IllegalLifetimeTransition)
    );
    let charged_finished = charged
        .stage_finish(owner, ResourceFinishTransition::Complete { settled_at: 20 })
        .unwrap_or_else(|error| panic!("charged completion: {error:?}"));
    assert_eq!(
        charged_finished.record().quotas(),
        charged.record().quotas()
    );
    for candidate in [&charged, &charged_finished] {
        assert_eq!(
            candidate.stage_finish_with_charges(
                OwnerGeneration::new(3),
                ResourceFinishTransition::Begin,
                &[Charge {
                    amount: 9,
                    ..charge
                }]
            ),
            Err(ResourceError::StaleOwner {
                presented: OwnerGeneration::new(3),
                current: owner
            })
        );
        let bytes = gantry::runtime::encode_resource_recovery_envelope(candidate, 65_536)
            .unwrap_or_else(|error| panic!("charged envelope: {error:?}"));
        assert_eq!(
            gantry::runtime::decode_resource_recovery_envelope(
                Arc::clone(&program),
                &bytes,
                65_536,
                owner,
                machine.task_id()
            ),
            Ok(candidate.clone())
        );
    }
    assert_eq!(registry.declared_records_with_containment(), captured);
    assert_eq!(
        original.stage_finish(OwnerGeneration::new(3), ResourceFinishTransition::Begin),
        Err(ResourceError::StaleOwner {
            presented: OwnerGeneration::new(3),
            current: owner,
        }),
    );
    assert_eq!(
        original.stage_finish(owner, ResourceFinishTransition::Complete { settled_at: 20 }),
        Err(ResourceError::IllegalLifetimeTransition),
    );
    let finishing = original
        .stage_finish(owner, ResourceFinishTransition::Begin)
        .unwrap_or_else(|error| panic!("finish candidate: {error:?}"));
    assert_eq!(
        finishing.record().lifetime(),
        ResourceLifetimeState::Finishing
    );
    assert_eq!(finishing.issuing_evidence(), original.issuing_evidence());
    assert_eq!(
        finishing.containment_evidence(),
        original.containment_evidence()
    );
    assert_eq!(finishing.subject(), original.subject());
    assert_eq!(finishing.task_owner(), original.task_owner());
    assert_eq!(finishing.record().quotas(), original.record().quotas());
    assert_eq!(
        finishing.record().liveness_roots(),
        original.record().liveness_roots()
    );
    assert_eq!(
        finishing.stage_finish(owner, ResourceFinishTransition::Begin),
        Err(ResourceError::IllegalLifetimeTransition)
    );
    let finished = finishing
        .stage_finish(owner, ResourceFinishTransition::Complete { settled_at: 20 })
        .unwrap_or_else(|error| panic!("finished candidate: {error:?}"));
    assert_eq!(
        finished.record().lifetime(),
        ResourceLifetimeState::Finished
    );
    assert_eq!(
        finished
            .record()
            .settlement()
            .map(|value| value.settled_at()),
        Some(20)
    );
    assert_eq!(finished.issuing_evidence(), original.issuing_evidence());
    assert_eq!(
        finished.containment_evidence(),
        original.containment_evidence()
    );
    for candidate in [&finishing, &finished] {
        let bytes = gantry::runtime::encode_resource_recovery_envelope(candidate, 65_536)
            .unwrap_or_else(|error| panic!("candidate envelope: {error:?}"));
        let decoded = gantry::runtime::decode_resource_recovery_envelope(
            Arc::clone(&program),
            &bytes,
            65_536,
            owner,
            machine.task_id(),
        )
        .unwrap_or_else(|error| panic!("candidate recovery: {error:?}"));
        assert_eq!(&decoded, candidate);
        assert_eq!(
            candidate.stage_finish(OwnerGeneration::new(3), ResourceFinishTransition::Begin),
            Err(ResourceError::StaleOwner {
                presented: OwnerGeneration::new(3),
                current: owner,
            }),
            "stale ownership precedes an otherwise illegal lifetime transition",
        );
    }
    assert_eq!(
        finished.stage_finish(owner, ResourceFinishTransition::Complete { settled_at: 21 }),
        Err(ResourceError::IllegalLifetimeTransition)
    );
    assert_eq!(registry.declared_records_with_containment(), captured);
    for policy in [
        (Some(1), Some(2), Some(3)),
        (None, None, None),
        (Some(1), Some(0), None),
    ] {
        let empty =
            ResourceRegistry::reconstruct_recovery_envelopes(Arc::clone(&program), &[], 8, policy)
                .unwrap_or_else(|error| panic!("empty restore: {error:?}"));
        assert_eq!(
            (
                empty.live_limit(),
                empty.pending_limit(),
                empty.retained_limit()
            ),
            policy
        );
        assert!(empty.declared_records().is_empty());
        let recovered = ResourceRegistry::reconstruct_recovery_envelopes(
            Arc::clone(&program),
            &inputs,
            exact,
            policy,
        )
        .unwrap_or_else(|error| panic!("restore: {error:?}"));
        assert_eq!(
            (
                recovered.live_limit(),
                recovered.pending_limit(),
                recovered.retained_limit()
            ),
            policy
        );
        assert_eq!(
            recovered.declared_records_with_containment(),
            registry.declared_records_with_containment()
        );
        assert_eq!(recovered.pending_operations(), 0);
        assert!(!recovered.has_host_value(&subject));
    }
    assert_eq!(
        ResourceRegistry::reconstruct_recovery_envelopes(
            Arc::clone(&program),
            &inputs,
            exact - 1,
            (Some(1), Some(2), Some(3)),
        )
        .err(),
        Some(ResourceRecoveryEnvelopeError::ByteLimit)
    );
    assert_eq!(
        ResourceRegistry::reconstruct_recovery_envelopes(
            Arc::clone(&program),
            &inputs,
            exact,
            (Some(1), Some(2), Some(0)),
        )
        .err(),
        Some(ResourceRecoveryEnvelopeError::Origin(
            ResourceOriginRecoveryError::Registry(
                ResourceRegistryRefusal::RetainedResourceLimitReached { limit: 0 }
            )
        ))
    );
    let duplicate = [inputs[0], inputs[0]];
    assert_eq!(
        ResourceRegistry::reconstruct_recovery_envelopes(
            Arc::clone(&program),
            &inputs,
            exact,
            (Some(0), Some(2), Some(3)),
        )
        .err(),
        Some(ResourceRecoveryEnvelopeError::Origin(
            ResourceOriginRecoveryError::Registry(
                ResourceRegistryRefusal::LiveResourceLimitReached { limit: 0 }
            )
        ))
    );
    assert_eq!(
        ResourceRegistry::reconstruct_recovery_envelopes(
            Arc::clone(&program),
            &duplicate,
            131_072,
            (Some(2), Some(2), Some(3)),
        )
        .err(),
        Some(ResourceRecoveryEnvelopeError::Origin(
            ResourceOriginRecoveryError::Registry(ResourceRegistryRefusal::SecondAdmission)
        ))
    );
    let mut corrupt = envelopes[0].clone();
    corrupt[0] = 0;
    let invalid_tail = [inputs[0], (corrupt.as_slice(), owner, machine.task_id())];
    assert_eq!(
        ResourceRegistry::reconstruct_recovery_envelopes(
            program,
            &invalid_tail,
            131_072,
            (Some(2), Some(2), Some(3)),
        )
        .err(),
        Some(ResourceRecoveryEnvelopeError::Encoding)
    );
    assert_eq!(registry.capture_recovery_envelopes(65_536), Ok(envelopes));
}

/// Distinct subjects restore in canonical registry order, never in caller-selected order.
#[test]
fn resource_envelope_set_restore_preserves_distinct_canonical_members() {
    use gantry::runtime::ResourceRecoveryEnvelopeError;
    let owner = OwnerGeneration::new(4);
    let workflows = ["crate::first", "crate::second"]
        .into_iter()
        .map(|name| Workflow {
            path: CanonicalPath::new(name).unwrap_or_else(|error| panic!("workflow: {error}")),
            parameters: Vec::new(),
            result: TypeDescriptor::UNIT,
            effects: EffectSet::default(),
            instructions: vec![
                Instruction {
                    site: StructuralPosition::new(vec![FIXTURE_SITE])
                        .unwrap_or_else(|error| panic!("site: {error}")),
                    ty: TypeDescriptor::UNIT,
                    kind: InstructionKind::OperationCall {
                        operation: operation_metadata(
                            Some(FIXTURE_DECLARATION),
                            Some(OperationKind::LiveResource),
                        ),
                        operands: 0,
                    },
                },
                Instruction {
                    site: StructuralPosition::new(vec![FIXTURE_SITE + 1])
                        .unwrap_or_else(|error| panic!("site: {error}")),
                    ty: TypeDescriptor::UNIT,
                    kind: InstructionKind::Return,
                },
            ],
        })
        .collect();
    let program = Arc::new(
        MachineProgram::new(workflows).unwrap_or_else(|error| panic!("program: {error:?}")),
    );
    let execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [90; 32])
        .unwrap_or_else(|error| panic!("execution: {error}"));
    let limits = MachineLimits::new(8, 1, 1, 1, 8, DEFAULT_VALUE_LIMITS)
        .unwrap_or_else(|| panic!("positive limits"));
    let mut registry = ResourceRegistry::with_accounting_limits(2, 2, 2);
    for workflow in program.workflows() {
        let mut machine = Machine::new(
            Arc::clone(&program),
            &workflow.path,
            vec![],
            execution,
            limits,
        )
        .unwrap_or_else(|error| panic!("machine: {error:?}"));
        assert!(matches!(
            machine.step(),
            MachineStep::Transition(MachineLabel::OperationPrepared(_))
        ));
        let record =
            ResourceLedger::new(owner, ResourceState::Usable, &[LivenessRoot::Resource], &[])
                .unwrap_or_else(|error| panic!("ledger: {error:?}"));
        registry
            .admit_pending_operation_with_issuing_evidence(
                &machine,
                ResourceCarrier::ReconstructionRecord,
                record.durable_record(),
                65_536,
            )
            .unwrap_or_else(|error| panic!("admit: {error:?}"));
        let operation = machine
            .checkpoint()
            .pending_operation()
            .unwrap_or_else(|| panic!("pending"))
            .identity;
        machine
            .fail_operation(
                operation,
                gantry::portable::RuntimeErrorCategory::ExecutorFailure,
            )
            .unwrap_or_else(|error| panic!("settle: {error:?}"));
    }
    let envelopes = registry
        .capture_recovery_envelopes(131_072)
        .unwrap_or_else(|error| panic!("capture: {error:?}"));
    assert_eq!(envelopes.len(), 2);
    let records = registry.declared_records_with_containment();
    let inputs = envelopes
        .iter()
        .zip(&records)
        .map(|(bytes, record)| (bytes.as_slice(), record.owner(), record.task_owner()))
        .collect::<Vec<_>>();
    let recovered = ResourceRegistry::reconstruct_recovery_envelopes(
        Arc::clone(&program),
        &inputs,
        131_072,
        (Some(2), Some(2), Some(2)),
    )
    .unwrap_or_else(|error| panic!("restore: {error:?}"));
    assert_eq!(recovered.declared_records_with_containment(), records);
    assert_eq!(
        recovered.capture_recovery_envelopes(131_072),
        Ok(envelopes.clone())
    );
    let reversed = inputs.into_iter().rev().collect::<Vec<_>>();
    assert_eq!(
        ResourceRegistry::reconstruct_recovery_envelopes(
            program,
            &reversed,
            131_072,
            (Some(2), Some(2), Some(2)),
        )
        .err(),
        Some(ResourceRecoveryEnvelopeError::Encoding)
    );
}

/// Coordinator restore binds issuing budgets to the current execution frontier.
#[test]
fn coordinator_envelope_restore_validates_issuing_budget_frontier() {
    use gantry::runtime::{CoordinatorResourceRefusal, ExecutionCoordinator};
    let (program, mut machine, subject) = machine_with_declared_subject(Some(FIXTURE_DECLARATION));
    let subject = subject.unwrap_or_else(|| panic!("subject"));
    let owner = OwnerGeneration::new(4);
    let issuing_budget = machine.budget_checkpoint();
    let record = ResourceLedger::new(owner, ResourceState::Usable, &[LivenessRoot::Resource], &[])
        .unwrap_or_else(|error| panic!("ledger: {error:?}"));
    let mut registry = ResourceRegistry::with_accounting_limits(1, 2, 3);
    registry
        .admit_pending_operation_with_issuing_evidence(
            &machine,
            ResourceCarrier::ReconstructionRecord,
            record.durable_record(),
            65_536,
        )
        .unwrap_or_else(|error| panic!("admit: {error:?}"));
    let operation = machine
        .checkpoint()
        .pending_operation()
        .unwrap_or_else(|| panic!("pending"))
        .identity;
    machine
        .fail_operation(
            operation,
            gantry::portable::RuntimeErrorCategory::ExecutorFailure,
        )
        .unwrap_or_else(|error| panic!("settle: {error:?}"));
    let envelopes = registry
        .capture_recovery_envelopes(65_536)
        .unwrap_or_else(|error| panic!("capture: {error:?}"));
    let inputs = [(envelopes[0].as_slice(), owner, machine.task_id())];
    let (tasks, sessions) = resource_recovery_inputs(machine.execution_id(), machine.task_id());
    let budget = ExecutionBudget::recover_from_checkpoint(machine.budget_checkpoint())
        .unwrap_or_else(|error| panic!("budget: {error:?}"));
    let restored = ExecutionCoordinator::new_with_budget_and_recovered_resource_envelopes(
        tasks.clone(),
        sessions.clone(),
        budget.clone(),
        Arc::clone(&program),
        &inputs,
        65_536,
        (Some(1), Some(2), Some(3)),
    )
    .unwrap_or_else(|error| panic!("restore: {error:?}"));
    let snapshot = restored.snapshot();
    assert_eq!(
        snapshot.resource_records(),
        Some(registry.declared_records().as_slice())
    );
    assert_eq!(
        snapshot.execution_budget(),
        Some(machine.budget_checkpoint())
    );
    assert_eq!(restored.retained_resource_limit(), Some(3));
    assert!(!restored.has_pending_resource_operations());
    assert!(!restored.has_resource_host_values());
    assert_eq!(
        snapshot
            .resource_records()
            .unwrap_or_else(|| panic!("records"))[0]
            .subject(),
        &subject
    );
    let mut earlier = issuing_budget;
    earlier.revision -= 1;
    earlier.remaining_operations = earlier.remaining_operations.map(|remaining| remaining + 1);
    let earlier = ExecutionBudget::recover_from_checkpoint(earlier)
        .unwrap_or_else(|error| panic!("earlier budget: {error:?}"));
    assert_eq!(
        ExecutionCoordinator::new_with_budget_and_recovered_resource_envelopes(
            tasks.clone(),
            sessions.clone(),
            earlier,
            Arc::clone(&program),
            &inputs,
            65_536,
            (Some(1), Some(2), Some(3)),
        )
        .err(),
        Some(CoordinatorResourceRefusal::Task(
            gantry::runtime::TaskStateError::InvalidTaskMachine
        ))
    );
    let mut foreign = machine.budget_checkpoint();
    foreign.execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [91; 32])
        .unwrap_or_else(|error| panic!("foreign execution: {error}"));
    let foreign = ExecutionBudget::recover_from_checkpoint(foreign)
        .unwrap_or_else(|error| panic!("foreign budget: {error:?}"));
    assert_eq!(
        ExecutionCoordinator::new_with_budget_and_recovered_resource_envelopes(
            tasks,
            sessions,
            foreign,
            program,
            &inputs,
            0,
            (Some(1), Some(2), Some(3)),
        )
        .err(),
        Some(CoordinatorResourceRefusal::Task(
            gantry::runtime::TaskStateError::InvalidTaskMachine
        ))
    );
}

/// Bounded live admission retains issuing facts after machine work settles.
#[test]
fn bounded_live_admission_retains_issuing_evidence_after_settlement() {
    use gantry::runtime::{ResourceRecoveryEnvelopeError, encode_resource_recovery_envelope};
    let (_, mut machine, subject) = machine_with_declared_subject(Some(FIXTURE_DECLARATION));
    let subject = subject.unwrap_or_else(|| panic!("subject"));
    let issuing_bytes = machine.checkpoint().canonical_bytes();
    let issuing_budget = machine.budget_checkpoint();
    let mut refused = ResourceRegistry::with_limits(1, 1);
    assert_eq!(
        refused
            .admit_pending_operation_with_issuing_evidence(
                &machine,
                ResourceCarrier::ReconstructionRecord,
                ledger().durable_record(),
                0,
            )
            .err(),
        Some(ResourceRecoveryEnvelopeError::ByteLimit)
    );
    assert!(refused.declared_records().is_empty());
    assert_eq!(refused.pending_operations(), 0);
    let mut registry = ResourceRegistry::with_limits(1, 1);
    registry
        .admit_pending_operation_with_issuing_evidence(
            &machine,
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
            65_536,
        )
        .unwrap_or_else(|error| panic!("bounded admission: {error:?}"));
    assert_eq!(registry.pending_operations(), 1);
    let operation = machine
        .checkpoint()
        .pending_operation()
        .unwrap_or_else(|| panic!("pending operation"))
        .identity;
    let before_duplicate = registry.declared_records();
    assert_eq!(
        registry
            .admit_pending_operation_with_issuing_evidence(
                &machine,
                ResourceCarrier::ReconstructionRecord,
                ledger().durable_record(),
                65_536,
            )
            .err(),
        Some(ResourceRecoveryEnvelopeError::Origin(
            gantry::runtime::ResourceOriginRecoveryError::Registry(
                ResourceRegistryRefusal::SecondAdmission
            )
        ))
    );
    assert_eq!(registry.declared_records(), before_duplicate);
    let mut no_live_capacity = ResourceRegistry::with_limits(0, 1);
    assert_eq!(
        no_live_capacity
            .admit_pending_operation_with_issuing_evidence(
                &machine,
                ResourceCarrier::ReconstructionRecord,
                ledger().durable_record(),
                65_536,
            )
            .err(),
        Some(ResourceRecoveryEnvelopeError::Origin(
            gantry::runtime::ResourceOriginRecoveryError::Registry(
                ResourceRegistryRefusal::LiveResourceLimitReached { limit: 0 }
            )
        ))
    );
    assert!(no_live_capacity.declared_records().is_empty());
    assert_eq!(no_live_capacity.pending_operations(), 0);
    machine
        .fail_operation(
            operation,
            gantry::portable::RuntimeErrorCategory::ExecutorFailure,
        )
        .unwrap_or_else(|error| panic!("settlement: {error:?}"));
    assert_eq!(registry.pending_operations(), 0);
    let captured = registry.declared_records();
    assert_eq!(captured[0].subject(), &subject);
    assert_eq!(
        captured[0].issuing_evidence(),
        Some((issuing_bytes.as_slice(), issuing_budget))
    );
    assert!(encode_resource_recovery_envelope(&captured[0], 65_536).is_ok());
}

/// Coordinator provenance admission publishes once and retains historical evidence after settlement.
#[test]
fn coordinator_issuing_evidence_admission_preserves_publication_fences() {
    use gantry::runtime::{CoordinatorResourceRefusal, ResourceRecoveryEnvelopeError};
    let (_, mut machine, _) = machine_with_declared_subject(Some(FIXTURE_DECLARATION));
    let coordinator = resource_coordinator(machine.execution_id(), machine.task_id(), Some(1));
    let before = coordinator.snapshot();
    assert_eq!(
        coordinator.admit_resource_with_issuing_evidence(
            &machine,
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
            0,
        ),
        Err(CoordinatorResourceRefusal::RecoveryEnvelope(
            ResourceRecoveryEnvelopeError::ByteLimit
        ))
    );
    assert_eq!(coordinator.snapshot(), before);
    assert!(!coordinator.has_pending_resource_operations());
    coordinator
        .admit_resource_with_issuing_evidence(
            &machine,
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
            65_536,
        )
        .unwrap_or_else(|error| panic!("provenance admission: {error:?}"));
    let admitted = coordinator.snapshot();
    assert_eq!(admitted.publication(), before.publication() + 1);
    let records = admitted
        .resource_records()
        .unwrap_or_else(|| panic!("records"));
    assert!(records[0].issuing_evidence().is_some());
    assert!(coordinator.has_pending_resource_operations());
    assert_eq!(
        coordinator.admit_resource_with_issuing_evidence(
            &machine,
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
            65_536,
        ),
        Err(CoordinatorResourceRefusal::RecoveryEnvelope(
            ResourceRecoveryEnvelopeError::Origin(
                gantry::runtime::ResourceOriginRecoveryError::Registry(
                    ResourceRegistryRefusal::SecondAdmission
                )
            )
        ))
    );
    assert_eq!(coordinator.snapshot(), admitted);
    assert!(coordinator.close_resource_admission());
    assert_eq!(
        coordinator.admit_resource_with_issuing_evidence(
            &machine,
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
            0,
        ),
        Err(CoordinatorResourceRefusal::ResourceAdmissionClosed)
    );
    assert_eq!(coordinator.snapshot(), admitted);
    let operation = machine
        .checkpoint()
        .pending_operation()
        .unwrap_or_else(|| panic!("operation"))
        .identity;
    machine
        .fail_operation(
            operation,
            gantry::portable::RuntimeErrorCategory::ExecutorFailure,
        )
        .unwrap_or_else(|error| panic!("settlement: {error:?}"));
    assert!(!coordinator.has_pending_resource_operations());
    assert_eq!(
        coordinator.snapshot().resource_records(),
        admitted.resource_records()
    );
}

/// Issuing evidence travels canonically under independent byte and ownership admission bounds.
#[test]
fn resource_recovery_envelope_round_trips_and_refuses_invalid_admission() {
    use gantry::runtime::{
        ResourceRecoveryEnvelopeError, decode_resource_recovery_envelope,
        encode_resource_recovery_envelope,
    };
    let (program, machine, subject) = machine_with_declared_subject(Some(FIXTURE_DECLARATION));
    let owner = OwnerGeneration::new(4);
    let origin = RecoveredResourceRecord::from_issuing_checkpoint(
        Arc::clone(&program),
        machine.checkpoint(),
        machine.budget_checkpoint(),
        ResourceCarrier::ReconstructionRecord,
        owner,
        ledger().durable_record(),
    )
    .unwrap_or_else(|error| panic!("origin: {error:?}"));
    let bytes = encode_resource_recovery_envelope(&origin, 65_536)
        .unwrap_or_else(|error| panic!("envelope: {error:?}"));
    let limit = u64::try_from(bytes.len()).unwrap_or_else(|_| panic!("bounded length"));
    let decoded = decode_resource_recovery_envelope(
        Arc::clone(&program),
        &bytes,
        limit,
        owner,
        machine.task_id(),
    )
    .unwrap_or_else(|error| panic!("decode: {error:?}"));
    assert_eq!(decoded, origin);
    assert_eq!(
        encode_resource_recovery_envelope(&decoded, limit),
        Ok(bytes.clone())
    );
    let mut fresh = ResourceRegistry::new();
    assert_eq!(
        fresh.admit(
            decoded.subject().clone(),
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record()
        ),
        Err(ResourceRegistryRefusal::NoPendingResourceSubject),
        "decoding must not reopen issuing work"
    );
    let mut forged_length = bytes.clone();
    forged_length[8..16].copy_from_slice(&u64::MAX.to_be_bytes());
    assert_eq!(
        decode_resource_recovery_envelope(
            Arc::clone(&program),
            &forged_length,
            limit,
            owner,
            machine.task_id()
        )
        .err(),
        Some(ResourceRecoveryEnvelopeError::Encoding)
    );
    // Reframe valid members so failures come from evidence validation, not truncation.
    let reframe = |budget: &[u8], facts: &[u8]| {
        let checkpoint = origin
            .issuing_evidence()
            .unwrap_or_else(|| panic!("origin evidence"))
            .0;
        let cleanup = machine.task_id().to_string();
        let mut framed = b"GNTRRE01".to_vec();
        for member in [checkpoint, budget, cleanup.as_bytes(), facts] {
            framed.extend_from_slice(
                &u64::try_from(member.len())
                    .unwrap_or_else(|_| panic!("bounded member"))
                    .to_be_bytes(),
            );
            framed.extend_from_slice(member);
        }
        framed
    };
    let facts = encode_resource_reconstruction_record(origin.record());
    let mut foreign_budget = machine.budget_checkpoint();
    foreign_budget.execution =
        ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [89; 32])
            .unwrap_or_else(|error| panic!("foreign execution: {error}"));
    let forged_budget = reframe(&foreign_budget.canonical_bytes(), &facts);
    assert_eq!(
        decode_resource_recovery_envelope(
            Arc::clone(&program),
            &forged_budget,
            65_536,
            owner,
            machine.task_id()
        )
        .err(),
        Some(ResourceRecoveryEnvelopeError::Origin(
            gantry::runtime::ResourceOriginRecoveryError::Machine(
                gantry::runtime::MachineRecoveryError::ExecutionBudgetMismatch
            )
        ))
    );
    let mut alternate_facts = facts;
    alternate_facts.push(b' ');
    let noncanonical = reframe(
        &machine.budget_checkpoint().canonical_bytes(),
        &alternate_facts,
    );
    assert_eq!(
        decode_resource_recovery_envelope(
            Arc::clone(&program),
            &noncanonical,
            65_536,
            owner,
            machine.task_id()
        )
        .err(),
        Some(ResourceRecoveryEnvelopeError::Record(
            ResourceRecordCodecError::Encoding
        ))
    );
    assert_eq!(
        encode_resource_recovery_envelope(&origin, limit - 1),
        Err(ResourceRecoveryEnvelopeError::ByteLimit)
    );
    assert_eq!(
        decode_resource_recovery_envelope(
            Arc::clone(&program),
            &bytes,
            limit - 1,
            owner,
            machine.task_id()
        )
        .err(),
        Some(ResourceRecoveryEnvelopeError::ByteLimit)
    );
    for invalid in [&bytes[..bytes.len() - 1], &bytes[1..]] {
        assert!(
            decode_resource_recovery_envelope(
                Arc::clone(&program),
                invalid,
                limit,
                owner,
                machine.task_id()
            )
            .is_err()
        );
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(
        decode_resource_recovery_envelope(
            Arc::clone(&program),
            &trailing,
            limit + 1,
            owner,
            machine.task_id()
        )
        .err(),
        Some(ResourceRecoveryEnvelopeError::Encoding)
    );
    assert!(
        decode_resource_recovery_envelope(
            Arc::clone(&program),
            &bytes,
            limit,
            OwnerGeneration::new(3),
            machine.task_id()
        )
        .is_err()
    );
    let foreign_task = ProtocolIdentity::derive(IdentityKind::Task, b"foreign-envelope-cleanup")
        .unwrap_or_else(|error| panic!("task: {error}"));
    assert_eq!(
        decode_resource_recovery_envelope(program, &bytes, limit, owner, foreign_task).err(),
        Some(ResourceRecoveryEnvelopeError::CleanupTaskMismatch)
    );
    let legacy = RecoveredResourceRecord::new(
        subject.unwrap_or_else(|| panic!("subject")),
        ResourceCarrier::ReconstructionRecord,
        owner,
        ledger().durable_record(),
    );
    assert_eq!(
        encode_resource_recovery_envelope(&legacy, limit),
        Err(ResourceRecoveryEnvelopeError::MissingIssuingEvidence)
    );
}

#[test]
fn resource_registry_gives_one_subject_exactly_one_account() {
    let (_program, _machine, subject) = machine_with_declared_subject(Some(FIXTURE_DECLARATION));
    let subject = subject.unwrap_or_else(|| panic!("the fixture operation declares an action"));

    let mut registry = ResourceRegistry::new();
    registry
        .admit(
            subject.clone(),
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
        )
        .unwrap_or_else(|error| {
            panic!("the declared reconstruction record is admitted: {error:?}")
        });
    assert!(registry.account(&subject).is_some());

    assert_eq!(
        registry.admit(
            subject.clone(),
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
        ),
        Err(ResourceRegistryRefusal::SecondAdmission)
    );

    let foreign = failure_settlement_in(
        FIXTURE_WORKFLOW,
        "crate::resource_runtime_foreign",
        vec![FIXTURE_SITE],
        0,
        FailureClass::ResourceFailure,
    );
    assert_eq!(
        registry.settle_from_post_failure(&foreign, 21, &subject),
        Err(ResourceRegistryRefusal::UnknownSubject)
    );
    assert_eq!(
        registry
            .account(&subject)
            .map(|account| account.ledger().lifetime()),
        Some(ResourceLifetimeState::Active)
    );

    let matching = failure_settlement_in(
        FIXTURE_WORKFLOW,
        FIXTURE_DECLARATION,
        vec![FIXTURE_SITE],
        0,
        FailureClass::ResourceFailure,
    );
    assert_eq!(
        registry.settle_from_post_failure(&matching, 21, &subject),
        Ok(ResourceLifetimeState::Poisoned)
    );
    let account = registry
        .account(&subject)
        .unwrap_or_else(|| panic!("the subject still owns its account"));
    assert_eq!(account.ledger().lifetime(), ResourceLifetimeState::Poisoned);
    assert_eq!(
        account.remaining(QuotaOwner::Owner, QuotaFamily::Bytes),
        Some(8)
    );

    let record_before_retry = registry
        .account(&subject)
        .unwrap_or_else(|| panic!("the subject still owns its account"))
        .durable_record()
        .clone();
    assert_eq!(
        registry.settle_from_post_failure(&matching, 22, &subject),
        Err(ResourceRegistryRefusal::Settlement(
            PostFailureSettlementRefusal::Model(ResourceError::IllegalLifetimeTransition)
        ))
    );
    assert_eq!(
        registry
            .account(&subject)
            .unwrap_or_else(|| panic!("the subject still owns its account"))
            .durable_record(),
        record_before_retry,
        "a refused repeated settlement leaves every declared fact unchanged"
    );
}

#[test]
fn resource_registry_uniqueness_is_per_registry_until_one_owner_is_wired() {
    let (_program, _machine, subject) = machine_with_declared_subject(Some(FIXTURE_DECLARATION));
    let subject = subject.unwrap_or_else(|| panic!("the fixture operation declares an action"));

    let mut first = ResourceRegistry::new();
    first
        .admit(
            subject.clone(),
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
        )
        .unwrap_or_else(|error| {
            panic!("the declared reconstruction record is admitted: {error:?}")
        });
    assert_eq!(
        first.admit(
            subject.clone(),
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
        ),
        Err(ResourceRegistryRefusal::SecondAdmission)
    );

    // Negative evidence for the deferred rule: this type publishes no global uniqueness claim, so
    // the same subject in a second registry is admitted until one execution-layer owner is wired.
    let mut second = ResourceRegistry::new();
    second
        .admit(
            subject.clone(),
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
        )
        .unwrap_or_else(|error| {
            panic!(
                "a second registry admission is not refused before the owner is wired: {error:?}"
            )
        });
    assert!(second.account(&subject).is_some());
}

/// Recovery publishes one registry from every declared record it presents: each account keeps its
/// own subject and declared facts, and a repeated subject or an unauthenticated operation refuses
/// the whole set instead of producing a partial registry.
#[test]
fn recovery_reconstructs_every_presented_record_or_refuses_the_whole_set() {
    let first = declared_subject(FIXTURE_DECLARATION);
    let second = declared_subject(SECOND_FIXTURE_DECLARATION);
    assert_ne!(first.operation(), second.operation());

    let recovered = ResourceRegistry::reconstruct(
        None,
        vec![
            presented(
                first.clone(),
                ResourceCarrier::ReconstructionRecord,
                ledger().durable_record(),
            ),
            presented(
                second.clone(),
                ResourceCarrier::ReconstructionRecord,
                ledger().durable_record(),
            ),
        ],
    )
    .unwrap_or_else(|error| panic!("both declared records reconstruct: {error:?}"));

    assert_eq!(recovered.live_limit(), None);
    assert_eq!(
        recovered.live_resources(),
        2,
        "both reconstructed accounts live"
    );
    for subject in [&first, &second] {
        let account = recovered
            .account(subject)
            .unwrap_or_else(|| panic!("the reconstructed registry holds every presented subject"));
        assert_eq!(account.ledger().owner(), OwnerGeneration::new(4));
        assert_eq!(account.ledger().lifetime(), ResourceLifetimeState::Active);
        assert_eq!(
            account.remaining(QuotaOwner::Owner, QuotaFamily::Bytes),
            Some(8)
        );
    }

    assert_eq!(
        ResourceRegistry::reconstruct(
            None,
            vec![
                presented(
                    first.clone(),
                    ResourceCarrier::ReconstructionRecord,
                    ledger().durable_record(),
                ),
                presented(
                    first.clone(),
                    ResourceCarrier::ReconstructionRecord,
                    ledger().durable_record(),
                ),
            ],
        )
        .err(),
        Some(ResourceRegistryRefusal::SecondAdmission),
        "one subject is presented at most once in one reconstruction"
    );

    assert_eq!(
        ResourceRegistry::reconstruct(
            None,
            vec![
                presented(
                    second.clone(),
                    ResourceCarrier::ReconstructionRecord,
                    ledger().durable_record(),
                ),
                presented(
                    unauthenticated_fixture_subject(UNAUTHENTICATED_FIXTURE_DECLARATION),
                    ResourceCarrier::ReconstructionRecord,
                    ledger().durable_record(),
                ),
            ],
        )
        .err(),
        Some(ResourceRegistryRefusal::UnauthenticatedOperationKind),
        "a record for an unauthenticated operation refuses the whole set"
    );
}

#[test]
fn reconstruction_record_codec_round_trips_full_range_facts_and_rejects_noncanonical_bytes() {
    let source = ledger().durable_record();
    let mut quotas = source.quotas().clone();
    for owner in QuotaOwner::ALL {
        for family in QuotaFamily::ALL {
            quotas.insert(
                (owner, family),
                Quota::from_durable_facts(u64::MAX, u64::MAX, u64::MAX)
                    .unwrap_or_else(|error| panic!("maximum quota facts are reachable: {error:?}")),
            );
        }
    }
    let record = DurableResourceRecord::from_durable_facts(
        OwnerGeneration::new(u64::MAX),
        ResourceLifetimeState::Active,
        source.operation_state(),
        quotas,
        source.liveness_roots().clone(),
        None,
        None,
    )
    .unwrap_or_else(|error| panic!("maximum owner facts are reachable: {error:?}"));

    let encoded = encode_resource_reconstruction_record(&record);
    assert_eq!(
        decode_resource_reconstruction_record(&encoded),
        Ok(record),
        "the declared record codec preserves all u64 model facts"
    );
    let mut small_quotas = source.quotas().clone();
    small_quotas.insert(
        (QuotaOwner::Owner, QuotaFamily::Bytes),
        Quota::from_durable_facts(u64::MAX, u64::MAX, u64::MAX)
            .unwrap_or_else(|error| panic!("maximum quota facts are reachable: {error:?}")),
    );
    let small_record = DurableResourceRecord::from_durable_facts(
        OwnerGeneration::new(u64::MAX),
        ResourceLifetimeState::Active,
        source.operation_state(),
        small_quotas,
        source.liveness_roots().clone(),
        None,
        None,
    )
    .unwrap_or_else(|error| panic!("small record facts are reachable: {error:?}"));
    let encoded = encode_resource_reconstruction_record(&small_record);
    for hostile in [
        vec![b' '; 4097],
        format!("{}0{}", "[".repeat(100), "]".repeat(100)).into_bytes(),
        format!("\"{}\"", "x".repeat(65)).into_bytes(),
    ] {
        assert_eq!(
            decode_resource_reconstruction_record(&hostile),
            Err(ResourceRecordCodecError::Encoding),
            "oversized, deeply nested, and excess string inputs refuse"
        );
    }
    let settled = settled_record();
    let settled_bytes = encode_resource_reconstruction_record(&settled);
    assert_eq!(
        decode_resource_reconstruction_record(&settled_bytes),
        Ok(settled),
        "terminal settlement facts survive reconstruction-record encoding"
    );
    assert_eq!(
        decode_resource_reconstruction_record(&[encoded.as_slice(), b" "].concat()),
        Err(ResourceRecordCodecError::Encoding),
        "trailing whitespace is not a second canonical spelling"
    );
    assert_eq!(
        decode_resource_reconstruction_record(
            br#"{"format":"gantry.resource-reconstruction/v1","record":{}}"#
        ),
        Err(ResourceRecordCodecError::Encoding),
        "an incomplete record is rejected"
    );
    let mut injected_subject = encoded.clone();
    injected_subject.pop();
    injected_subject.extend_from_slice(br#","subject":"caller-selected"}"#);
    assert_eq!(
        decode_resource_reconstruction_record(&injected_subject),
        Err(ResourceRecordCodecError::Encoding),
        "journal-carried subjects are not accepted by the subject-free record codec"
    );
    let malformed_decimal = String::from_utf8(encoded.clone())
        .unwrap_or_else(|error| panic!("codec output is UTF-8: {error}"))
        .replace("18446744073709551615", "01");
    assert_eq!(
        decode_resource_reconstruction_record(malformed_decimal.as_bytes()),
        Err(ResourceRecordCodecError::Encoding),
        "decimal counters reject leading zeroes"
    );
    let overflowing_decimal = String::from_utf8(encoded.clone())
        .unwrap_or_else(|error| panic!("codec output is UTF-8: {error}"))
        .replace("18446744073709551615", "18446744073709551616");
    assert_eq!(
        decode_resource_reconstruction_record(overflowing_decimal.as_bytes()),
        Err(ResourceRecordCodecError::Encoding),
        "decimal counters reject values outside u64"
    );

    let encoded_text = String::from_utf8(encoded.clone())
        .unwrap_or_else(|error| panic!("codec output is UTF-8: {error}"));
    let duplicate_array_entry = |field: &str, object_entry: bool| {
        let marker = format!("\"{field}\":[");
        let start = encoded_text
            .find(&marker)
            .unwrap_or_else(|| panic!("encoded record has {field} array"))
            + marker.len();
        let end = encoded_text[start..]
            .find(']')
            .map(|offset| start + offset)
            .unwrap_or_else(|| panic!("encoded {field} array closes"));
        let entries = &encoded_text[start..end];
        let first_end = if object_entry {
            entries
                .find('}')
                .map(|offset| offset + 1)
                .unwrap_or_else(|| panic!("encoded {field} array has an object"))
        } else {
            entries.find(',').unwrap_or(entries.len())
        };
        format!(
            "{}{},{}{}",
            &encoded_text[..start],
            entries,
            &entries[..first_end],
            &encoded_text[end..]
        )
    };
    assert_eq!(
        decode_resource_reconstruction_record(
            duplicate_array_entry("liveness_roots", false).as_bytes()
        ),
        Err(ResourceRecordCodecError::Encoding),
        "duplicate liveness roots are not canonical reconstruction facts"
    );
    assert_eq!(
        decode_resource_reconstruction_record(duplicate_array_entry("quotas", true).as_bytes()),
        Err(ResourceRecordCodecError::Model(
            ResourceError::DuplicateQuota
        )),
        "duplicate quota identities are refused"
    );

    // The closed schema has only nine owner/family pairs. Reject a larger array at
    // parser admission, before interpreting even its first duplicate quota identity.
    let quota_start = encoded_text
        .find("\"quotas\":[")
        .map(|offset| offset + "\"quotas\":[".len())
        .unwrap_or_else(|| panic!("encoded quota array exists"));
    let quota_end = encoded_text[quota_start..]
        .find(']')
        .map(|offset| quota_start + offset)
        .unwrap_or_else(|| panic!("encoded quota array closes"));
    let first_quota_end = encoded_text[quota_start..]
        .find('}')
        .map(|offset| quota_start + offset + 1)
        .unwrap_or_else(|| panic!("encoded quota array has an entry"));
    let excess_quotas = format!(
        "{}{}{}",
        &encoded_text[..quota_start],
        [&encoded_text[quota_start..first_quota_end]; 10].join(","),
        &encoded_text[quota_end..]
    );
    assert_eq!(
        decode_resource_reconstruction_record(excess_quotas.as_bytes()),
        Err(ResourceRecordCodecError::Encoding),
        "excess quota arrays refuse at the schema-sized parser budget"
    );

    let first_field_start = encoded_text
        .find("\"record\":{")
        .map(|offset| offset + "\"record\":{".len())
        .unwrap_or_else(|| panic!("encoded record object exists"));
    let second_field_start = encoded_text
        .find(",\"liveness_roots\":")
        .map(|offset| offset + 1)
        .unwrap_or_else(|| panic!("encoded liveness-roots field exists"));
    let second_field_end = encoded_text
        .find(",\"operation_state\":")
        .unwrap_or_else(|| panic!("encoded operation-state field follows roots"));
    let reordered_fields = format!(
        "{}{},{}{}",
        &encoded_text[..first_field_start],
        &encoded_text[second_field_start..second_field_end],
        &encoded_text[first_field_start..second_field_start - 1],
        &encoded_text[second_field_end..]
    );
    assert_eq!(
        decode_resource_reconstruction_record(reordered_fields.as_bytes()),
        Err(ResourceRecordCodecError::Encoding),
        "reordered fields are not a second canonical record spelling"
    );

    let record_start = encoded_text
        .find(",\"record\":")
        .map(|offset| offset + ",\"record\":".len())
        .unwrap_or_else(|| panic!("encoded top-level record field exists"));
    let top_level_reordered = format!(
        r#"{{"record":{},"format":"gantry.resource-reconstruction/v1"}}"#,
        &encoded_text[record_start..encoded_text.len() - 1]
    );
    assert_eq!(
        decode_resource_reconstruction_record(top_level_reordered.as_bytes()),
        Err(ResourceRecordCodecError::Encoding),
        "reordered top-level fields are not a second canonical record spelling"
    );

    let invalid_model_facts = encoded_text.replacen(
        "\"family\":\"bytes\",\"limit\":\"18446744073709551615\"",
        "\"family\":\"bytes\",\"limit\":\"0\"",
        1,
    );
    assert_ne!(
        invalid_model_facts, encoded_text,
        "the selected quota exists"
    );
    assert_eq!(
        decode_resource_reconstruction_record(invalid_model_facts.as_bytes()),
        Err(ResourceRecordCodecError::Model(
            ResourceError::InvalidDurableQuota
        )),
        "durable quota facts above their declared limit are refused"
    );
}

/// A presented record is reconstructed only under the owner generation the pass holds: a record
/// naming another generation is refused with the model's own stale-owner reason, in either
/// presentation order, and the matching presentation reconstructs the very same records.
#[test]
fn reconstruction_refuses_a_stale_owner_generation_without_publishing_an_account() {
    let first = declared_subject(FIXTURE_DECLARATION);
    let second = declared_subject(SECOND_FIXTURE_DECLARATION);
    let stale = || {
        RecoveredResourceRecord::new(
            first.clone(),
            ResourceCarrier::ReconstructionRecord,
            OwnerGeneration::new(3),
            ledger().durable_record(),
        )
    };
    let fresh = || {
        presented(
            second.clone(),
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
        )
    };
    let expected = Some(ResourceRegistryRefusal::Admission(
        ResourceError::StaleOwner {
            presented: OwnerGeneration::new(3),
            current: OwnerGeneration::new(4),
        },
    ));

    assert_eq!(
        ResourceRegistry::reconstruct(None, vec![stale(), fresh()]).err(),
        expected.clone(),
        "a stale record presented first refuses the reconstruction"
    );
    assert_eq!(
        ResourceRegistry::reconstruct(None, vec![fresh(), stale()]).err(),
        expected,
        "a stale record presented last refuses the reconstruction"
    );

    let recovered = ResourceRegistry::reconstruct(
        None,
        vec![
            presented(
                first.clone(),
                ResourceCarrier::ReconstructionRecord,
                ledger().durable_record(),
            ),
            fresh(),
        ],
    )
    .unwrap_or_else(|error| panic!("the matching owner generation reconstructs both: {error:?}"));
    assert_eq!(
        recovered.live_resources(),
        2,
        "the same records reconstruct once the pass holds their own owner generation"
    );
}

/// The verified carrier is the declared reconstruction record alone: an ordinary serialization or
/// ordinary durable-state carrier refuses the whole reconstruction instead of contributing a
/// resource.
#[test]
fn reconstruction_refuses_an_ordinary_carrier_for_the_whole_set() {
    let first = declared_subject(FIXTURE_DECLARATION);
    let second = declared_subject(SECOND_FIXTURE_DECLARATION);

    for carrier in [
        ResourceCarrier::OrdinarySerialization,
        ResourceCarrier::OrdinaryDurableState,
    ] {
        assert_eq!(
            ResourceRegistry::reconstruct(
                None,
                vec![
                    presented(
                        first.clone(),
                        ResourceCarrier::ReconstructionRecord,
                        ledger().durable_record(),
                    ),
                    presented(second.clone(), carrier, ledger().durable_record()),
                ],
            )
            .err(),
            Some(ResourceRegistryRefusal::Admission(
                ResourceError::OrdinaryCarrierRefused
            )),
            "an ordinary carrier refuses the reconstruction rather than contributing an account"
        );
    }

    let recovered = ResourceRegistry::reconstruct(
        None,
        vec![
            presented(
                first.clone(),
                ResourceCarrier::ReconstructionRecord,
                ledger().durable_record(),
            ),
            presented(
                second.clone(),
                ResourceCarrier::ReconstructionRecord,
                ledger().durable_record(),
            ),
        ],
    )
    .unwrap_or_else(|error| panic!("the declared carrier reconstructs both records: {error:?}"));
    assert_eq!(recovered.live_resources(), 2);
}

/// Bounded reconstruction counts terminal records and retains stronger evidence refusals.
#[test]
fn reconstruction_enforces_retained_capacity_before_publication() {
    let first = presented(
        active_subject(),
        ResourceCarrier::ReconstructionRecord,
        settled_record(),
    );
    let second = presented(
        declared_subject(SECOND_FIXTURE_DECLARATION),
        ResourceCarrier::ReconstructionRecord,
        settled_record(),
    );
    let recovered = ResourceRegistry::reconstruct_with_retained_limit(
        Some(0),
        2,
        vec![first.clone(), second.clone()],
    )
    .unwrap_or_else(|error| panic!("bounded terminal recovery: {error:?}"));
    assert_eq!(recovered.retained_limit(), Some(2));
    assert_eq!(recovered.retained_resources(), 2);
    assert_eq!(recovered.live_resources(), 0);
    assert_eq!(recovered.pending_operations(), 0);
    assert_eq!(
        ResourceRegistry::reconstruct_with_retained_limit(Some(0), 1, vec![first.clone(), second])
            .err(),
        Some(ResourceRegistryRefusal::RetainedResourceLimitReached { limit: 1 })
    );
    assert_eq!(
        ResourceRegistry::reconstruct_with_retained_limit(Some(0), 0, vec![first.clone()]).err(),
        Some(ResourceRegistryRefusal::RetainedResourceLimitReached { limit: 0 })
    );
    assert_eq!(
        ResourceRegistry::reconstruct_with_retained_limit(Some(0), 1, vec![first.clone(), first])
            .err(),
        Some(ResourceRegistryRefusal::SecondAdmission)
    );
}

/// Reconstruction honors the declared live-resource limit over the accounts that are still live: a
/// settled record keeps every declared fact without holding a place, so a settled and a live record
/// coexist under a limit of one, while two live records refuse the whole set.
#[test]
fn reconstruction_honors_the_declared_live_limit_over_live_records_only() {
    let first = declared_subject(FIXTURE_DECLARATION);
    let second = declared_subject(SECOND_FIXTURE_DECLARATION);

    let recovered = ResourceRegistry::reconstruct(
        Some(1),
        vec![
            presented(
                first.clone(),
                ResourceCarrier::ReconstructionRecord,
                settled_record(),
            ),
            presented(
                second.clone(),
                ResourceCarrier::ReconstructionRecord,
                ledger().durable_record(),
            ),
        ],
    )
    .unwrap_or_else(|error| panic!("a settled record frees the live place: {error:?}"));

    assert_eq!(recovered.live_limit(), Some(1));
    assert_eq!(recovered.live_resources(), 1);
    assert_eq!(
        recovered
            .account(&first)
            .map(|account| account.ledger().lifetime()),
        Some(ResourceLifetimeState::Poisoned),
        "the settled record is reconstructed with its own terminal lifetime"
    );

    assert_eq!(
        ResourceRegistry::reconstruct(
            Some(1),
            vec![
                presented(
                    first.clone(),
                    ResourceCarrier::ReconstructionRecord,
                    ledger().durable_record(),
                ),
                presented(
                    second.clone(),
                    ResourceCarrier::ReconstructionRecord,
                    ledger().durable_record(),
                ),
            ],
        )
        .err(),
        Some(ResourceRegistryRefusal::LiveResourceLimitReached { limit: 1 }),
        "two live records refuse a reconstruction that declares one place"
    );
}

/// The declared records of a registry are exactly the presentation recovery reconstructs from: a
/// captured set carries every account under the declared reconstruction-record carrier and its own
/// owner generation, and reconstructing from the capture rebuilds the same lifetimes, live count,
/// and declared quota facts.
#[test]
fn a_registry_captures_the_reconstruction_set_that_rebuilds_it() {
    let first = declared_subject(FIXTURE_DECLARATION);
    let second = declared_subject(SECOND_FIXTURE_DECLARATION);

    let mut registry = ResourceRegistry::new();
    for subject in [&first, &second] {
        registry
            .admit(
                subject.clone(),
                ResourceCarrier::ReconstructionRecord,
                ledger().durable_record(),
            )
            .unwrap_or_else(|error| panic!("the declared record is admitted: {error:?}"));
    }
    let settlement = failure_settlement_in(
        FIXTURE_WORKFLOW,
        FIXTURE_DECLARATION,
        vec![FIXTURE_SITE],
        0,
        FailureClass::ResourceFailure,
    );
    assert_eq!(
        registry.settle_from_post_failure(&settlement, 21, &first),
        Ok(ResourceLifetimeState::Poisoned)
    );
    assert_eq!(registry.live_resources(), 1);

    let captured = registry.declared_records();
    assert_eq!(captured.len(), 2, "every admitted account is captured");
    assert!(
        captured
            .iter()
            .all(|record| record.carrier() == ResourceCarrier::ReconstructionRecord),
        "a capture never presents an ordinary carrier"
    );
    assert!(
        captured
            .iter()
            .all(|record| record.owner() == OwnerGeneration::new(4)),
        "every captured record names the account's own owner generation"
    );
    assert!(
        captured.iter().any(|record| record.subject() == &first),
        "the settled account is captured too"
    );

    let rebuilt = ResourceRegistry::reconstruct(None, captured)
        .unwrap_or_else(|error| panic!("the captured set reconstructs: {error:?}"));
    assert_eq!(
        rebuilt.live_resources(),
        1,
        "the captured lifetimes rebuild the same live count"
    );
    assert_eq!(
        rebuilt
            .account(&first)
            .map(|account| account.ledger().lifetime()),
        Some(ResourceLifetimeState::Poisoned)
    );
    assert_eq!(
        rebuilt
            .account(&second)
            .map(|account| account.ledger().lifetime()),
        Some(ResourceLifetimeState::Active)
    );
    assert_eq!(
        rebuilt
            .account(&first)
            .map(|account| account.remaining(QuotaOwner::Owner, QuotaFamily::Bytes)),
        Some(Some(8)),
        "the captured record keeps the declared quota facts of the settled account"
    );
}

/// A capture carries each account's own owner generation rather than one generation for the whole
/// set, so a heterogeneous capture reconstructs every account under its own owner and the capture
/// round-trips through reconstruction as the identical set of complete declared records.
#[test]
fn a_capture_carries_each_accounts_own_owner_generation() {
    let first = declared_subject(FIXTURE_DECLARATION);
    let second = declared_subject(SECOND_FIXTURE_DECLARATION);

    let mut registry = ResourceRegistry::new();
    registry
        .admit(
            first.clone(),
            ResourceCarrier::ReconstructionRecord,
            ledger_owned_by(5).durable_record(),
        )
        .unwrap_or_else(|error| panic!("the declared record is admitted: {error:?}"));
    registry
        .admit(
            second.clone(),
            ResourceCarrier::ReconstructionRecord,
            ledger_owned_by(4).durable_record(),
        )
        .unwrap_or_else(|error| panic!("the declared record is admitted: {error:?}"));

    let captured = registry.declared_records();
    assert_eq!(
        captured
            .iter()
            .find(|record| record.subject() == &first)
            .map(RecoveredResourceRecord::owner),
        Some(OwnerGeneration::new(5)),
        "the capture carries the first account's own owner generation"
    );
    assert_eq!(
        captured
            .iter()
            .find(|record| record.subject() == &second)
            .map(RecoveredResourceRecord::owner),
        Some(OwnerGeneration::new(4)),
        "the capture carries the second account's own owner generation"
    );

    let rebuilt = ResourceRegistry::reconstruct(None, captured.clone())
        .unwrap_or_else(|error| panic!("the heterogeneous capture reconstructs: {error:?}"));
    assert_eq!(rebuilt.live_resources(), 2, "both accounts rebuild");
    assert_eq!(
        rebuilt
            .account(&first)
            .map(|account| account.ledger().owner()),
        Some(OwnerGeneration::new(5))
    );
    assert_eq!(
        rebuilt.declared_records(),
        captured,
        "a capture round-trips through reconstruction as the identical declared records"
    );
}

/// The registry owns the whole two-phase finish path: a finishing account keeps its live place, its
/// completion records the settlement baseline and releases the place while every declared quota fact
/// stays observable, and no second completion is admitted.
#[test]
fn registry_advances_and_completes_the_two_phase_finish() {
    let subject = declared_subject(FIXTURE_DECLARATION);
    let other = declared_subject(SECOND_FIXTURE_DECLARATION);
    let mut registry = ResourceRegistry::new();
    registry
        .admit(
            subject.clone(),
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
        )
        .unwrap_or_else(|error| panic!("the declared record is admitted: {error:?}"));

    assert_eq!(
        registry.begin_finish(&other, OwnerGeneration::new(4)),
        Err(ResourceRegistryRefusal::UnknownSubject),
        "a subject this registry holds no account for changes nothing"
    );
    assert_eq!(
        registry.begin_finish(&subject, OwnerGeneration::new(4)),
        Ok(ResourceLifetimeState::Finishing)
    );
    assert_eq!(
        registry.live_resources(),
        1,
        "a finishing lifetime still holds its live place"
    );
    assert_eq!(
        registry.complete_finalization(&subject, OwnerGeneration::new(4), 20),
        Ok(ResourceLifetimeState::Finished)
    );
    assert_eq!(
        registry.live_resources(),
        0,
        "the completed lifetime releases its place"
    );

    let account = registry
        .account(&subject)
        .unwrap_or_else(|| panic!("the subject still owns its retained account"));
    assert_eq!(account.ledger().lifetime(), ResourceLifetimeState::Finished);
    let settlement = match account.ledger().settlement() {
        Some(settlement) => settlement,
        None => panic!("the finished lifetime retains its settlement baseline"),
    };
    assert_eq!(settlement.owner(), OwnerGeneration::new(4));
    assert_eq!(settlement.settled_at(), 20);
    assert_eq!(
        account.remaining(QuotaOwner::Owner, QuotaFamily::Bytes),
        Some(8),
        "semantic release keeps every declared quota fact observable"
    );
    assert_eq!(
        registry.complete_finalization(&subject, OwnerGeneration::new(4), 21),
        Err(ResourceRegistryRefusal::Finish(
            ResourceError::IllegalLifetimeTransition
        )),
        "a settled resource is never settled a second time"
    );
}

/// Both finish steps are owner-qualified: a superseded owner generation is refused before any
/// lifetime fact changes, and the account's current generation then advances and completes it.
#[test]
fn finish_refuses_a_stale_owner_generation_without_mutating() {
    let subject = declared_subject(FIXTURE_DECLARATION);
    let mut registry = ResourceRegistry::new();
    registry
        .admit(
            subject.clone(),
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
        )
        .unwrap_or_else(|error| panic!("the declared record is admitted: {error:?}"));

    assert_eq!(
        registry.begin_finish(&subject, OwnerGeneration::new(3)),
        Err(ResourceRegistryRefusal::Finish(ResourceError::StaleOwner {
            presented: OwnerGeneration::new(3),
            current: OwnerGeneration::new(4),
        }))
    );
    assert_eq!(
        registry
            .account(&subject)
            .map(|account| account.ledger().lifetime()),
        Some(ResourceLifetimeState::Active),
        "the refused presentation changes no lifetime fact"
    );

    assert_eq!(
        registry.begin_finish(&subject, OwnerGeneration::new(4)),
        Ok(ResourceLifetimeState::Finishing),
        "the current owner generation enters the finish path"
    );
    assert_eq!(
        registry.complete_finalization(&subject, OwnerGeneration::new(3), 20),
        Err(ResourceRegistryRefusal::Finish(ResourceError::StaleOwner {
            presented: OwnerGeneration::new(3),
            current: OwnerGeneration::new(4),
        }))
    );
    assert_eq!(
        registry
            .account(&subject)
            .map(|account| account.ledger().lifetime()),
        Some(ResourceLifetimeState::Finishing),
        "the refused presentation leaves the finishing lifetime unfinished"
    );
    assert_eq!(
        registry.complete_finalization(&subject, OwnerGeneration::new(4), 20),
        Ok(ResourceLifetimeState::Finished),
        "the current owner generation completes the same account"
    );
}

/// A poisoned resource has one terminal disposition: neither finish step can be entered or completed
/// after the model's poisoning witness fixed it.
#[test]
fn a_poisoned_account_cannot_enter_or_complete_the_finish_path() {
    let subject = declared_subject(FIXTURE_DECLARATION);
    let mut registry = ResourceRegistry::new();
    registry
        .admit(
            subject.clone(),
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
        )
        .unwrap_or_else(|error| panic!("the declared record is admitted: {error:?}"));
    let settlement = failure_settlement_in(
        FIXTURE_WORKFLOW,
        FIXTURE_DECLARATION,
        vec![FIXTURE_SITE],
        0,
        FailureClass::ResourceFailure,
    );
    assert_eq!(
        registry.settle_from_post_failure(&settlement, 21, &subject),
        Ok(ResourceLifetimeState::Poisoned)
    );

    assert_eq!(
        registry.begin_finish(&subject, OwnerGeneration::new(4)),
        Err(ResourceRegistryRefusal::Finish(
            ResourceError::IllegalLifetimeTransition
        )),
        "a poisoned lifetime never enters finishing"
    );
    assert_eq!(
        registry.complete_finalization(&subject, OwnerGeneration::new(4), 22),
        Err(ResourceRegistryRefusal::Finish(
            ResourceError::IllegalLifetimeTransition
        )),
        "a poisoned lifetime never finishes"
    );
    assert_eq!(
        registry
            .account(&subject)
            .map(|account| account.ledger().lifetime()),
        Some(ResourceLifetimeState::Poisoned)
    );
}

/// A superseded owner generation is refused on every runtime-added fence - root closure, deletion,
/// and the model's own retirement rule - before any declared fact changes, and the account's current
/// generation still closes its roots, retires, and deletes the same record.
#[test]
fn the_account_mutation_surface_refuses_a_superseded_owner_generation() {
    let mut admitted_resource = admitted_active();
    let owner = OwnerGeneration::new(4);
    let stale = OwnerGeneration::new(3);
    let before = admitted_resource.ledger().clone();

    assert_eq!(
        admitted_resource.close_liveness_root_for(stale, LivenessRoot::Resource),
        Err(ResourceError::StaleOwner {
            presented: stale,
            current: owner,
        })
    );
    assert_eq!(
        admitted_resource.delete_for(stale),
        Err(ResourceError::StaleOwner {
            presented: stale,
            current: owner,
        })
    );
    assert_eq!(
        admitted_resource.ledger(),
        &before,
        "a superseded owner generation changes no declared fact"
    );

    assert!(admitted_resource.begin_finish_for(owner).is_ok());
    assert!(
        admitted_resource
            .complete_finalization_for(owner, 20)
            .is_ok()
    );
    for root in ROOTS {
        assert!(
            admitted_resource
                .close_liveness_root_for(owner, *root)
                .is_ok()
        );
    }

    let fence = RetentionFence::new(2, 10).unwrap_or_else(|_| unreachable!("bounded fence"));
    assert_eq!(
        admitted_resource.retire(fence, stale, OwnerGeneration::new(5), 35),
        Err(ResourceError::StaleOwner {
            presented: stale,
            current: owner,
        }),
        "retirement keeps the model's own stale-owner refusal"
    );
    assert!(
        admitted_resource
            .retire(fence, owner, OwnerGeneration::new(5), 35)
            .is_ok()
    );
    assert_eq!(
        admitted_resource.delete_for(stale),
        Err(ResourceError::StaleOwner {
            presented: stale,
            current: owner,
        })
    );
    assert_eq!(
        admitted_resource.delete_for(owner),
        Ok(ResourceLifetimeState::Deleted)
    );
}

/// A superseded owner generation is refused on the registry's owner-qualified root closure,
/// retirement, and deletion routes before any declared fact changes, and the account's current
/// generation still closes the same roots, retires, and deletes the same record through them.
#[test]
fn the_registry_mutation_surface_refuses_a_superseded_owner_generation() {
    let subject = active_subject();
    let mut registry = ResourceRegistry::new();
    registry
        .admit(
            subject.clone(),
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
        )
        .unwrap_or_else(|error| {
            panic!("the declared reconstruction record is admitted: {error:?}")
        });

    let owner = OwnerGeneration::new(4);
    let stale = OwnerGeneration::new(3);
    let fence = RetentionFence::new(2, 10).unwrap_or_else(|_| unreachable!("bounded fence"));
    let before = registry
        .account(&subject)
        .map(|account| account.ledger().clone());

    assert_eq!(
        registry.close_liveness_root(&subject, stale, LivenessRoot::Resource),
        Err(ResourceRegistryRefusal::RootClosure(
            ResourceError::StaleOwner {
                presented: stale,
                current: owner,
            }
        ))
    );
    assert_eq!(
        registry.delete(&subject, stale),
        Err(ResourceRegistryRefusal::Deletion(
            ResourceError::StaleOwner {
                presented: stale,
                current: owner,
            }
        ))
    );
    assert_eq!(
        registry
            .account(&subject)
            .map(|account| account.ledger().clone()),
        before,
        "a superseded owner generation changes no declared fact"
    );

    assert!(registry.begin_finish(&subject, owner).is_ok());
    assert!(registry.complete_finalization(&subject, owner, 20).is_ok());
    for root in ROOTS {
        assert!(registry.close_liveness_root(&subject, owner, *root).is_ok());
    }
    assert_eq!(
        registry.retire(&subject, fence, stale, OwnerGeneration::new(5), 35),
        Err(ResourceRegistryRefusal::Retirement(
            ResourceError::StaleOwner {
                presented: stale,
                current: owner,
            }
        )),
        "retirement keeps the model's own stale-owner refusal"
    );
    assert!(
        registry
            .retire(&subject, fence, owner, OwnerGeneration::new(5), 35)
            .is_ok()
    );
    assert_eq!(
        registry.delete(&subject, stale),
        Err(ResourceRegistryRefusal::Deletion(
            ResourceError::StaleOwner {
                presented: stale,
                current: owner,
            }
        ))
    );
    assert_eq!(
        registry.delete(&subject, owner),
        Ok(ResourceLifetimeState::Deleted)
    );
}

/// One admitted operation owns exactly one Section 23 containment settlement, and the model's own
/// order decides every refusal: a malformed completion first, then a repeated completion, then a
/// generation the operation does not hold, with a definite accepted outcome never presented over an
/// ambiguous effect, and no refusal changing the settled outcome or the held effect state.
#[test]
fn runtime_containment_settlement_settles_one_operation_once() {
    let subject = active_subject();
    let owner = OwnerGeneration::new(4);
    let stale = OwnerGeneration::new(3);
    let mut registry = ResourceRegistry::new();
    registry
        .admit(
            subject.clone(),
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
        )
        .unwrap_or_else(|error| {
            panic!("the declared reconstruction record is admitted: {error:?}")
        });

    assert_eq!(
        registry.settle_containment(
            &subject,
            stale,
            Completion::malformed(MalformedCompletion::NoOutcome),
        ),
        Err(ResourceRegistryRefusal::Containment(
            ContainmentError::MalformedCompletion {
                cause: MalformedCompletion::NoOutcome,
            }
        )),
        "a malformed completion is refused before the stale generation it also names"
    );
    assert_eq!(
        registry.settle_containment(
            &subject,
            stale,
            Completion::observed(ExternalOutcome::Rejected, EffectState::DefiniteRejection),
        ),
        Err(ResourceRegistryRefusal::Containment(
            ContainmentError::StaleGeneration {
                presented: stale,
                held: owner,
            }
        )),
        "a generation the operation does not hold is refused while the operation is unsettled"
    );
    assert_eq!(
        registry
            .account(&subject)
            .map(|account| account.containment().is_settled()),
        Some(false),
        "no refusal settles the operation"
    );

    assert_eq!(
        registry.settle_containment(
            &subject,
            owner,
            Completion::observed(ExternalOutcome::Accepted, EffectState::NotStarted),
        ),
        Ok(ExternalOutcome::Accepted)
    );
    assert_eq!(
        registry.settle_containment(
            &subject,
            stale,
            Completion::observed(ExternalOutcome::Rejected, EffectState::DefiniteRejection),
        ),
        Err(ResourceRegistryRefusal::Containment(
            ContainmentError::SecondSettlement {
                settled: ExternalOutcome::Accepted,
            }
        )),
        "a repeated completion is refused as a second settlement before its stale generation"
    );
    assert_eq!(
        ResourceRegistry::new().settle_containment(
            &subject,
            owner,
            Completion::observed(ExternalOutcome::Accepted, EffectState::NotStarted),
        ),
        Err(ResourceRegistryRefusal::UnknownSubject),
        "a registry holding no account for the subject refuses the settlement"
    );

    let mut ambiguous = ResourceRegistry::new();
    ambiguous
        .admit(
            subject.clone(),
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
        )
        .unwrap_or_else(|error| {
            panic!("the declared reconstruction record is admitted: {error:?}")
        });
    assert_eq!(
        ambiguous.settle_containment(
            &subject,
            owner,
            Completion::observed(ExternalOutcome::Accepted, EffectState::Ambiguous),
        ),
        Err(ResourceRegistryRefusal::Containment(
            ContainmentError::AmbiguousOutcomeRefused {
                outcome: ExternalOutcome::Accepted,
                held: EffectState::Ambiguous,
            }
        )),
        "a definite accepted outcome is never presented over an ambiguous effect"
    );
    assert_eq!(
        ambiguous.settle_containment(
            &subject,
            owner,
            Completion::observed(ExternalOutcome::Rejected, EffectState::Ambiguous),
        ),
        Ok(ExternalOutcome::Rejected),
        "the ambiguous effect settles once as an outcome that claims no acceptance"
    );
    assert_eq!(
        ambiguous
            .account(&subject)
            .map(|account| account.containment().effect_state()),
        Some(Some(EffectState::Ambiguous)),
        "the settled operation keeps the ambiguous effect state the boundary observed"
    );
}

/// Explicit containment capture preserves historical winners; ordinary capture remains accounting-only.
#[test]
fn explicit_resource_capture_preserves_containment_winners() {
    use gantry::runtime::{decode_resource_recovery_envelope, encode_resource_recovery_envelope};
    for (outcome, effect) in [
        (ExternalOutcome::Accepted, EffectState::NotStarted),
        (ExternalOutcome::Rejected, EffectState::DefiniteRejection),
        (ExternalOutcome::Ambiguous, EffectState::Ambiguous),
    ] {
        let (program, mut machine, subject) =
            machine_with_declared_subject(Some(FIXTURE_DECLARATION));
        let subject = subject.unwrap_or_else(|| panic!("subject"));
        let owner = OwnerGeneration::new(4);
        let record =
            ResourceLedger::new(owner, ResourceState::Usable, &[LivenessRoot::Resource], &[])
                .unwrap_or_else(|error| panic!("ledger: {error:?}"));
        let mut registry = ResourceRegistry::with_limits(1, 1);
        registry
            .admit_pending_operation_with_issuing_evidence(
                &machine,
                ResourceCarrier::ReconstructionRecord,
                record.durable_record(),
                65_536,
            )
            .unwrap_or_else(|error| panic!("admit: {error:?}"));
        registry
            .settle_containment(&subject, owner, Completion::observed(outcome, effect))
            .unwrap_or_else(|error| panic!("containment: {error:?}"));
        let operation = machine
            .checkpoint()
            .pending_operation()
            .unwrap_or_else(|| panic!("pending"))
            .identity;
        machine
            .fail_operation(
                operation,
                gantry::portable::RuntimeErrorCategory::ExecutorFailure,
            )
            .unwrap_or_else(|error| panic!("machine settlement: {error:?}"));
        registry
            .advance_owner(&subject, owner, OwnerGeneration::new(5))
            .unwrap_or_else(|error| panic!("owner advancement: {error:?}"));
        let captured = registry.declared_records_with_containment();
        assert_eq!(
            captured[0].containment_evidence(),
            Some((owner, Some((effect, outcome))))
        );
        let bytes = encode_resource_recovery_envelope(&captured[0], 65_536)
            .unwrap_or_else(|error| panic!("encode: {error:?}"));
        assert_eq!(&bytes[..8], b"GNTRRE02");
        let decoded = decode_resource_recovery_envelope(
            Arc::clone(&program),
            &bytes,
            65_536,
            OwnerGeneration::new(5),
            machine.task_id(),
        )
        .unwrap_or_else(|error| panic!("decode: {error:?}"));
        assert_eq!(decoded, captured[0]);
        let exact_limit = u64::try_from(bytes.len()).unwrap_or_else(|_| panic!("bounded length"));
        assert_eq!(
            encode_resource_recovery_envelope(&captured[0], exact_limit),
            Ok(bytes.clone())
        );
        assert_eq!(
            encode_resource_recovery_envelope(&captured[0], exact_limit - 1),
            Err(gantry::runtime::ResourceRecoveryEnvelopeError::ByteLimit)
        );
        assert_eq!(
            decode_resource_recovery_envelope(
                Arc::clone(&program),
                &bytes,
                exact_limit - 1,
                OwnerGeneration::new(5),
                machine.task_id()
            )
            .err(),
            Some(gantry::runtime::ResourceRecoveryEnvelopeError::ByteLimit)
        );
        // The closed containment member is owner (8), winner flag (1), effect (1), outcome (1).
        let mut future_owner = bytes.clone();
        let start = future_owner.len() - 11;
        future_owner[start..start + 8].copy_from_slice(&6_u64.to_be_bytes());
        let mut impossible_winner = bytes.clone();
        let end = impossible_winner.len();
        impossible_winner[end - 2] = 2; // Ambiguous effect cannot settle Accepted.
        impossible_winner[end - 1] = 0;
        let mut unknown_outcome = bytes.clone();
        unknown_outcome[end - 1] = 255;
        let mut wrong_version = bytes.clone();
        wrong_version[..8].copy_from_slice(b"GNTRRE01");
        for invalid in [
            future_owner,
            impossible_winner,
            unknown_outcome,
            wrong_version,
        ] {
            assert_eq!(
                decode_resource_recovery_envelope(
                    Arc::clone(&program),
                    &invalid,
                    65_536,
                    OwnerGeneration::new(5),
                    machine.task_id(),
                )
                .err(),
                Some(gantry::runtime::ResourceRecoveryEnvelopeError::Encoding),
            );
        }
        let mut rebuilt = ResourceRegistry::reconstruct(Some(1), vec![decoded])
            .unwrap_or_else(|error| panic!("reconstruct: {error:?}"));
        let containment = rebuilt
            .account(&subject)
            .unwrap_or_else(|| panic!("account"))
            .containment();
        assert_eq!(containment.owner(), owner);
        assert_eq!(containment.effect_state(), Some(effect));
        assert_eq!(containment.outcome(), Some(outcome));
        let before = rebuilt.declared_records_with_containment();
        assert_eq!(
            rebuilt.settle_containment(
                &subject,
                OwnerGeneration::new(5),
                Completion::observed(ExternalOutcome::Rejected, EffectState::DefiniteRejection)
            ),
            Err(ResourceRegistryRefusal::Containment(
                ContainmentError::SecondSettlement { settled: outcome }
            ))
        );
        assert_eq!(rebuilt.declared_records_with_containment(), before);
        let legacy = ResourceRegistry::reconstruct(Some(1), registry.declared_records())
            .unwrap_or_else(|error| panic!("legacy reconstruction: {error:?}"));
        assert!(
            !legacy
                .account(&subject)
                .unwrap_or_else(|| panic!("legacy account"))
                .containment()
                .is_settled()
        );
        assert_eq!(
            legacy
                .account(&subject)
                .unwrap_or_else(|| panic!("legacy account"))
                .containment()
                .owner(),
            OwnerGeneration::new(5)
        );
    }
}

/// Explicit capture preserves an unsettled containment owner without inventing an observation.
#[test]
fn explicit_resource_capture_preserves_unsettled_containment() {
    use gantry::runtime::{decode_resource_recovery_envelope, encode_resource_recovery_envelope};
    let (program, machine, subject) = machine_with_declared_subject(Some(FIXTURE_DECLARATION));
    let subject = subject.unwrap_or_else(|| panic!("subject"));
    let owner = OwnerGeneration::new(4);
    let mut registry = ResourceRegistry::with_limits(1, 1);
    registry
        .admit_pending_operation_with_issuing_evidence(
            &machine,
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
            65_536,
        )
        .unwrap_or_else(|error| panic!("admission: {error:?}"));
    let captured = registry.declared_records_with_containment();
    assert_eq!(captured[0].containment_evidence(), Some((owner, None)));
    let bytes = encode_resource_recovery_envelope(&captured[0], 65_536)
        .unwrap_or_else(|error| panic!("envelope: {error:?}"));
    assert_eq!(&bytes[..8], b"GNTRRE02");
    let decoded =
        decode_resource_recovery_envelope(program, &bytes, 65_536, owner, machine.task_id())
            .unwrap_or_else(|error| panic!("decode: {error:?}"));
    assert_eq!(decoded, captured[0]);
    let mut rebuilt = ResourceRegistry::reconstruct(Some(1), vec![decoded])
        .unwrap_or_else(|error| panic!("reconstruction: {error:?}"));
    let containment = rebuilt
        .account(&subject)
        .unwrap_or_else(|| panic!("account"))
        .containment();
    assert_eq!(containment.owner(), owner);
    assert_eq!(containment.effect_state(), None);
    assert_eq!(containment.outcome(), None);
    assert_eq!(
        rebuilt.settle_containment(
            &subject,
            owner,
            Completion::observed(ExternalOutcome::Rejected, EffectState::DefiniteRejection)
        ),
        Ok(ExternalOutcome::Rejected)
    );
}

/// Ordinary capture intentionally reconstructs fresh containment rather than retaining a winner.
#[test]
fn runtime_containment_settlement_restarts_with_the_account_value() {
    let subject = active_subject();
    let owner = OwnerGeneration::new(4);
    let mut registry = ResourceRegistry::new();
    registry
        .admit(
            subject.clone(),
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
        )
        .unwrap_or_else(|error| {
            panic!("the declared reconstruction record is admitted: {error:?}")
        });
    assert_eq!(
        registry.settle_containment(
            &subject,
            owner,
            Completion::observed(ExternalOutcome::Accepted, EffectState::NotStarted),
        ),
        Ok(ExternalOutcome::Accepted)
    );

    let captured = registry.declared_records();
    let mut rebuilt = ResourceRegistry::reconstruct(None, captured)
        .unwrap_or_else(|error| panic!("the declared capture reconstructs: {error:?}"));
    assert_eq!(
        rebuilt
            .account(&subject)
            .map(|account| account.containment().is_settled()),
        Some(false),
        "a rebuilt account value holds a fresh unsettled settlement"
    );
    assert_eq!(
        rebuilt.settle_containment(
            &subject,
            owner,
            Completion::observed(ExternalOutcome::Rejected, EffectState::DefiniteRejection),
        ),
        Ok(ExternalOutcome::Rejected),
        "the rebuilt account value settles its own operation once"
    );

    let mut reclaimed = ResourceRegistry::with_limits(1, 1);
    reclaimed
        .admit(
            subject.clone(),
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
        )
        .unwrap_or_else(|error| {
            panic!("the declared reconstruction record is admitted: {error:?}")
        });
    assert_eq!(
        reclaimed.settle_containment(
            &subject,
            owner,
            Completion::observed(ExternalOutcome::Accepted, EffectState::NotStarted),
        ),
        Ok(ExternalOutcome::Accepted),
        "the account settles its containment before it is reclaimed"
    );
    assert!(reclaimed.begin_finish(&subject, owner).is_ok());
    assert!(reclaimed.complete_finalization(&subject, owner, 20).is_ok());
    for root in ROOTS {
        assert!(
            reclaimed
                .close_liveness_root(&subject, owner, *root)
                .is_ok()
        );
    }
    let fence = RetentionFence::new(2, 10).unwrap_or_else(|_| unreachable!("bounded fence"));
    assert!(
        reclaimed
            .retire(&subject, fence, owner, OwnerGeneration::new(5), 35)
            .is_ok()
    );
    assert_eq!(
        reclaimed.delete(&subject, owner),
        Ok(ResourceLifetimeState::Deleted)
    );
    assert_eq!(
        reclaimed.reap_deleted(),
        1,
        "reaping frees the deleted account's key"
    );
    assert_eq!(reclaimed.pending_operations(), 1);
    reclaimed
        .admit(
            subject.clone(),
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
        )
        .unwrap_or_else(|error| panic!("the reclaimed subject is readmitted: {error:?}"));
    assert_eq!(
        reclaimed.pending_operations(),
        1,
        "readmitting accounting cannot duplicate the same pending machine lease"
    );
    assert_eq!(
        reclaimed
            .account(&subject)
            .map(|account| account.containment().is_settled()),
        Some(false),
        "a readmitted account value holds a fresh unsettled settlement"
    );
}

/// Returns one fixture adapter instance of one implementation name, rights set, owner generation,
/// and binding sequence.
fn adapter_instance_with(
    name: &str,
    rights: RightsSet,
    generation: u64,
    binding_sequence: u64,
) -> AdapterInstance {
    let receiver = TypeExpression::from_canonical_string(&format!("crate::{name}"), 4)
        .unwrap_or_else(|_| unreachable!("fixture receiver is a canonical type"));
    AdapterInstance::bind(
        &CanonicalImplementationIdentity::inherent(&receiver),
        rights,
        OwnerGeneration::new(generation),
        binding_sequence,
    )
}

/// Returns one fixture adapter instance carrying no right.
fn adapter_instance(name: &str, generation: u64, binding_sequence: u64) -> AdapterInstance {
    adapter_instance_with(name, RightsSet::empty(), generation, binding_sequence)
}

/// One admitted account's adapter instance is bound under the account's current owner generation,
/// replaced only through the model's own substitution rule, poisoned once through the model's own
/// one-way poison and reason ledger, and refused as unbound when no instance is bound.
#[test]
fn adapter_identity_capacity_retains_failed_fences_after_reclamation() {
    let subject = active_subject();
    let sibling = declared_subject(SECOND_FIXTURE_DECLARATION);
    let owner = OwnerGeneration::new(4);
    let first = adapter_instance("bounded_adapter", 4, 0);
    let mut registry = ResourceRegistry::with_adapter_identity_limit(1);
    assert_eq!(registry.adapter_identity_limit(), Some(1));
    for binding in [&subject, &sibling] {
        registry
            .admit(
                binding.clone(),
                ResourceCarrier::ReconstructionRecord,
                ledger().durable_record(),
            )
            .unwrap_or_else(|error| panic!("admit: {error:?}"));
        registry
            .bind_adapter_instance(binding, owner, first.clone())
            .unwrap_or_else(|error| panic!("alias binding: {error:?}"));
    }
    assert_eq!(registry.retained_adapter_identities(), 1);
    let before = registry.declared_records();
    let before_binding = registry.adapter_instance(&subject).cloned();
    assert!(matches!(
        registry.bind_adapter_instance(
            &subject,
            OwnerGeneration::new(3),
            adapter_instance("other", 5, 1)
        ),
        Err(ResourceRegistryRefusal::AdapterBinding(
            AdapterBindingRefusal::StaleOwner(_)
        ))
    ));
    assert_eq!(
        registry.bind_adapter_instance(&subject, owner, adapter_instance("other", 5, 1)),
        Err(ResourceRegistryRefusal::AdapterIdentityLimitReached { limit: 1 })
    );
    assert_eq!(registry.adapter_instance(&subject).cloned(), before_binding);
    assert_eq!(registry.declared_records(), before);
    assert_eq!(
        registry.poison_adapter_instance(&subject, owner, PoisonReason::AmbiguousEffect),
        Ok(PoisonReason::AmbiguousEffect)
    );
    assert_eq!(
        registry.poison_adapter_instance(&subject, owner, PoisonReason::InvariantFailure),
        Ok(PoisonReason::AmbiguousEffect)
    );
    assert!(
        registry
            .adapter_instance(&sibling)
            .unwrap_or_else(|| panic!("alias"))
            .is_poisoned()
    );
    registry
        .begin_finish(&subject, owner)
        .unwrap_or_else(|error| panic!("finish: {error:?}"));
    registry
        .complete_finalization(&subject, owner, 20)
        .unwrap_or_else(|error| panic!("finalize: {error:?}"));
    for root in ROOTS {
        registry
            .close_liveness_root(&subject, owner, *root)
            .unwrap_or_else(|error| panic!("close: {error:?}"));
    }
    registry
        .retire(
            &subject,
            RetentionFence::new(2, 10).unwrap_or_else(|error| panic!("fence: {error:?}")),
            owner,
            OwnerGeneration::new(5),
            35,
        )
        .unwrap_or_else(|error| panic!("retire: {error:?}"));
    registry
        .delete(&subject, owner)
        .unwrap_or_else(|error| panic!("delete: {error:?}"));
    assert_eq!(registry.reap_deleted(), 1);
    assert_eq!(registry.retained_adapter_identities(), 1);
    registry
        .admit(
            subject.clone(),
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
        )
        .unwrap_or_else(|error| panic!("readmit: {error:?}"));
    assert!(matches!(
        registry.bind_adapter_instance(&subject, owner, first),
        Err(ResourceRegistryRefusal::AdapterBinding(
            AdapterBindingRefusal::Substitution(OperationAbiError::AdapterInstancePoisoned { .. })
        ))
    ));
    assert_eq!(
        registry.bind_adapter_instance(&subject, owner, adapter_instance("new", 4, 0)),
        Err(ResourceRegistryRefusal::AdapterIdentityLimitReached { limit: 1 })
    );
    let mut zero = ResourceRegistry::with_adapter_identity_limit(0);
    zero.admit(
        subject.clone(),
        ResourceCarrier::ReconstructionRecord,
        ledger().durable_record(),
    )
    .unwrap_or_else(|error| panic!("zero accounting: {error:?}"));
    assert_eq!(
        zero.bind_adapter_instance(&subject, owner, adapter_instance("zero", 4, 0)),
        Err(ResourceRegistryRefusal::AdapterIdentityLimitReached { limit: 0 })
    );
    assert_eq!(zero.retained_adapter_identities(), 0);
    assert_eq!(ResourceRegistry::new().adapter_identity_limit(), None);
    let mut replacement = ResourceRegistry::with_adapter_identity_limit(2);
    replacement
        .admit(
            subject.clone(),
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
        )
        .unwrap_or_else(|error| panic!("replacement accounting: {error:?}"));
    replacement
        .bind_adapter_instance(&subject, owner, adapter_instance("replacement", 4, 0))
        .unwrap_or_else(|error| panic!("first binding: {error:?}"));
    replacement
        .bind_adapter_instance(&subject, owner, adapter_instance("replacement", 5, 1))
        .unwrap_or_else(|error| panic!("replacement binding: {error:?}"));
    assert_eq!(replacement.retained_adapter_identities(), 2);
    let held = replacement.adapter_instance(&subject).cloned();
    for sequence in [0, 1] {
        assert_eq!(
            replacement.bind_adapter_instance(
                &subject,
                owner,
                adapter_instance("replacement", 6, sequence)
            ),
            Err(ResourceRegistryRefusal::AdapterBinding(
                AdapterBindingRefusal::BindingSequenceNotAdvanced {
                    presented: sequence,
                    held: 1,
                }
            ))
        );
        assert_eq!(replacement.adapter_instance(&subject).cloned(), held);
        assert_eq!(replacement.retained_adapter_identities(), 2);
    }
    assert_eq!(
        replacement.bind_adapter_instance(&subject, owner, adapter_instance("replacement", 6, 2)),
        Err(ResourceRegistryRefusal::AdapterIdentityLimitReached { limit: 2 })
    );
    assert_eq!(replacement.adapter_instance(&subject).cloned(), held);
}

/// Existing adapter binding remains owner-qualified without an opt-in identity ceiling.
#[test]
fn runtime_adapter_binding_is_owner_fenced_and_poisons_once() {
    let subject = active_subject();
    let owner = OwnerGeneration::new(4);
    let stale = OwnerGeneration::new(3);
    let mut registry = ResourceRegistry::new();
    registry
        .admit(
            subject.clone(),
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
        )
        .unwrap_or_else(|error| {
            panic!("the declared reconstruction record is admitted: {error:?}")
        });

    assert_eq!(registry.adapter_instance(&subject), None);
    assert_eq!(
        registry.poison_adapter_instance(&subject, owner, PoisonReason::AmbiguousEffect),
        Err(ResourceRegistryRefusal::AdapterBinding(
            AdapterBindingRefusal::Unbound
        )),
        "an account with no bound adapter instance is refused"
    );
    assert_eq!(
        registry.bind_adapter_instance(&subject, stale, adapter_instance("first", 4, 0)),
        Err(ResourceRegistryRefusal::AdapterBinding(
            AdapterBindingRefusal::StaleOwner(ResourceError::StaleOwner {
                presented: stale,
                current: owner,
            })
        )),
        "a superseded owner never binds the adapter of an operation it does not hold"
    );
    assert!(
        registry
            .bind_adapter_instance(&subject, owner, adapter_instance("first", 4, 0))
            .is_ok()
    );
    let held = registry
        .adapter_instance(&subject)
        .map(AdapterInstance::rights)
        .unwrap_or_else(|| panic!("the account holds its bound adapter instance"));

    assert_eq!(
        registry.bind_adapter_instance(
            &subject,
            owner,
            adapter_instance_with("second", held, 4, 1),
        ),
        Err(ResourceRegistryRefusal::AdapterBinding(
            AdapterBindingRefusal::Substitution(OperationAbiError::StaleOwnerGeneration {
                owner,
                expected: owner,
            })
        )),
        "a replacement whose owner generation does not succeed the held one is refused"
    );

    let held_binding = registry.adapter_instance(&subject).cloned();
    assert!(
        held_binding.is_some(),
        "the account holds its bound adapter instance"
    );

    let mut poisoned_candidate = adapter_instance_with("fourth", held, 5, 3);
    poisoned_candidate.poison();
    assert!(
        matches!(
            registry.bind_adapter_instance(&subject, owner, poisoned_candidate),
            Err(ResourceRegistryRefusal::AdapterBinding(
                AdapterBindingRefusal::Substitution(
                    OperationAbiError::AdapterInstancePoisoned { .. }
                )
            ))
        ),
        "a presented binding that is already poisoned is never returned to service"
    );
    let mut retired_candidate = adapter_instance_with("fifth", held, 5, 4);
    retired_candidate.retire();
    assert!(
        matches!(
            registry.bind_adapter_instance(&subject, owner, retired_candidate),
            Err(ResourceRegistryRefusal::AdapterBinding(
                AdapterBindingRefusal::Substitution(
                    OperationAbiError::AdapterInstanceRetired { .. }
                )
            ))
        ),
        "a presented binding that is already retired is never returned to service"
    );
    assert_eq!(
        registry.adapter_instance(&subject),
        held_binding.as_ref(),
        "a refused replacement leaves the held binding exactly as it was"
    );

    let reason = PoisonReason::ForeignFailure(ForeignFailureKind::Panic);
    assert_eq!(
        registry.poison_adapter_instance(&subject, owner, reason),
        Ok(reason),
        "the first poisoning fixes the reason"
    );
    assert_eq!(
        registry.poison_adapter_instance(&subject, owner, PoisonReason::AmbiguousEffect),
        Ok(reason),
        "a repeated poisoning reports the reason recorded first"
    );
    assert_eq!(
        registry
            .adapter_instance(&subject)
            .map(AdapterInstance::is_poisoned),
        Some(true),
        "the bound instance carries the landed one-way poison"
    );
    assert!(
        matches!(
            registry.bind_adapter_instance(
                &subject,
                owner,
                adapter_instance_with("third", held, 5, 2),
            ),
            Err(ResourceRegistryRefusal::AdapterBinding(
                AdapterBindingRefusal::Substitution(
                    OperationAbiError::AdapterInstancePoisoned { .. }
                )
            ))
        ),
        "a poisoned binding is never substituted"
    );
    assert_eq!(
        ResourceRegistry::new().poison_adapter_instance(&subject, owner, reason),
        Err(ResourceRegistryRefusal::UnknownSubject),
        "a registry holding no account for the subject refuses the poisoning"
    );

    let captured = registry.declared_records();
    let mut rebuilt = ResourceRegistry::reconstruct(None, captured)
        .unwrap_or_else(|error| panic!("the declared capture reconstructs: {error:?}"));
    assert_eq!(
        rebuilt.adapter_instance(&subject),
        None,
        "a registry rebuilt from declared records holds no adapter binding"
    );
    assert_eq!(
        rebuilt.poison_adapter_instance(&subject, owner, reason),
        Err(ResourceRegistryRefusal::AdapterBinding(
            AdapterBindingRefusal::Unbound
        )),
        "a rebuilt registry holds no recorded reason, so its account is unbound"
    );
}

/// A cohort emergency-cleanup sweep settles every presented account through its own sealed witness in
/// canonical subject order, settles a repeated subject once, stops at the first refusal, and reports
/// exactly the settled prefix without rolling anything back.
#[test]
fn runtime_cohort_emergency_cleanup_reports_its_settled_prefix() {
    let first = declared_subject(FIXTURE_DECLARATION);
    let second = declared_subject(SECOND_FIXTURE_DECLARATION);
    let mut registry = ResourceRegistry::new();
    for subject in [&first, &second] {
        registry
            .admit(
                subject.clone(),
                ResourceCarrier::ReconstructionRecord,
                ledger().durable_record(),
            )
            .unwrap_or_else(|error| {
                panic!("the declared reconstruction record is admitted: {error:?}")
            });
    }

    let complete = registry.settle_cohort_from_emergency_cleanup(vec![
        (second.clone(), emergency_cleanup()),
        (first.clone(), emergency_cleanup()),
        (first.clone(), emergency_cleanup()),
    ]);
    assert!(complete.is_complete());
    assert!(complete.refusal().is_none());
    assert_eq!(
        complete.settled().len(),
        2,
        "one subject settles once however often it is presented"
    );
    assert!(
        complete
            .settled()
            .iter()
            .all(|settlement| settlement.lifetime() == ResourceLifetimeState::EmergencyReleased)
    );
    let settled_subjects: Vec<&ResourceSubjectBinding> = complete
        .settled()
        .iter()
        .map(CohortEmergencySettlement::subject)
        .collect();
    let mut expected = vec![&first, &second];
    expected.sort_by(|left, right| {
        (left.operation(), left.generation()).cmp(&(right.operation(), right.generation()))
    });
    assert_eq!(
        settled_subjects, expected,
        "the sweep settles in canonical subject order, not the presented order"
    );

    let repeated =
        registry.settle_cohort_from_emergency_cleanup(vec![(first.clone(), emergency_cleanup())]);
    assert!(!repeated.is_complete());
    assert!(repeated.settled().is_empty());
    assert!(matches!(
        repeated.refusal(),
        Some((
            _,
            ResourceRegistryRefusal::EmergencyRelease(ResourceError::IllegalLifetimeTransition)
        ))
    ));

    let third = declared_subject(THIRD_FIXTURE_DECLARATION);
    let mut partial = ResourceRegistry::new();
    for subject in [&first, &second, &third] {
        partial
            .admit(
                subject.clone(),
                ResourceCarrier::ReconstructionRecord,
                ledger().durable_record(),
            )
            .unwrap_or_else(|error| {
                panic!("the declared reconstruction record is admitted: {error:?}")
            });
    }
    // A refusal that follows a successful settlement preserves exactly the settled prefix, stops the
    // sweep before every account that sorts after the refusal, and leaves each lifetime reachable only
    // through the routes that already ran.
    let mut ordered = [&first, &second, &third];
    ordered.sort_by(|left, right| {
        (left.operation(), left.generation()).cmp(&(right.operation(), right.generation()))
    });
    let earlier = (*ordered[0]).clone();
    let refusing = (*ordered[1]).clone();
    let untouched = (*ordered[2]).clone();
    assert_eq!(
        partial.settle_from_emergency_cleanup(&refusing, emergency_cleanup()),
        Ok(ResourceLifetimeState::EmergencyReleased),
        "the refusing account settles before the sweep, so the sweep meets it after a settlement"
    );
    let swept = partial.settle_cohort_from_emergency_cleanup(vec![
        (untouched.clone(), emergency_cleanup()),
        (refusing.clone(), emergency_cleanup()),
        (earlier.clone(), emergency_cleanup()),
    ]);
    assert!(!swept.is_complete());
    assert_eq!(
        swept
            .settled()
            .iter()
            .map(|settlement| settlement.subject().operation().clone())
            .collect::<Vec<_>>(),
        vec![earlier.operation().clone()],
        "the sweep settles exactly the account that sorts before the refusal"
    );
    assert_eq!(
        swept.settled()[0].lifetime(),
        ResourceLifetimeState::EmergencyReleased
    );
    assert!(matches!(
        swept.refusal(),
        Some((
            subject,
            ResourceRegistryRefusal::EmergencyRelease(ResourceError::IllegalLifetimeTransition)
        )) if subject.operation() == refusing.operation()
    ));
    assert_eq!(
        partial
            .account(&earlier)
            .map(|account| account.ledger().lifetime()),
        Some(ResourceLifetimeState::EmergencyReleased),
        "the account the sweep settled keeps its released lifetime"
    );
    assert_eq!(
        partial
            .account(&refusing)
            .map(|account| account.ledger().lifetime()),
        Some(ResourceLifetimeState::EmergencyReleased),
        "the refused account keeps the lifetime it already reached"
    );
    assert_eq!(
        partial
            .account(&untouched)
            .map(|account| account.ledger().lifetime()),
        Some(ResourceLifetimeState::Active),
        "an account sorting after the refusal is untouched, so the sweep really stopped"
    );

    // A cohort whose only subject this registry does not hold settles nothing and reports it.
    let unknown = unauthenticated_fixture_subject(UNAUTHENTICATED_FIXTURE_DECLARATION);
    let missing = ResourceRegistry::new()
        .settle_cohort_from_emergency_cleanup(vec![(unknown.clone(), emergency_cleanup())]);
    assert!(!missing.is_complete());
    assert!(missing.settled().is_empty());
    assert!(matches!(
        missing.refusal(),
        Some((subject, ResourceRegistryRefusal::UnknownSubject))
            if subject.operation() == unknown.operation()
    ));
}

/// One machine-issued subject drives admission, quota charging, the two-phase finish, and the
/// containment settlement, and the hard-cancellation cohort sweep does not reopen the terminal
/// lifetime that path produced.
#[test]
fn runtime_lifecycle_accepts_one_machine_subject_and_keeps_its_terminal_disposition() {
    let (_program, _machine, subject) = machine_with_declared_subject(Some(FIXTURE_DECLARATION));
    let subject = subject.unwrap_or_else(|| panic!("the fixture operation declares an action"));
    let owner = OwnerGeneration::new(4);
    let mut registry = ResourceRegistry::new();
    registry
        .admit(
            subject.clone(),
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
        )
        .unwrap_or_else(|error| panic!("the machine-issued subject is admitted: {error:?}"));

    let headroom = |registry: &ResourceRegistry| {
        registry
            .account(&subject)
            .and_then(|account| account.remaining(QuotaOwner::Owner, QuotaFamily::Bytes))
    };
    assert_eq!(headroom(&registry), Some(8));
    assert!(
        registry
            .charge(
                &subject,
                owner,
                ResourceAction::Update,
                &[Charge {
                    owner: QuotaOwner::Owner,
                    family: QuotaFamily::Bytes,
                    amount: 1,
                }],
            )
            .is_ok()
    );
    assert_eq!(
        headroom(&registry),
        Some(7),
        "the admitted charge consumes declared headroom on this subject"
    );
    assert!(registry.begin_finish(&subject, owner).is_ok());
    assert_eq!(
        registry.complete_finalization(&subject, owner, 20),
        Ok(ResourceLifetimeState::Finished)
    );
    assert_eq!(
        registry.settle_containment(
            &subject,
            owner,
            Completion::observed(ExternalOutcome::Accepted, EffectState::NotStarted),
        ),
        Ok(ExternalOutcome::Accepted)
    );
    assert_eq!(
        registry
            .account(&subject)
            .map(|account| account.containment().outcome()),
        Some(Some(ExternalOutcome::Accepted)),
        "the settled containment outcome is observable on this subject"
    );
    assert_eq!(
        registry
            .account(&subject)
            .map(|account| account.containment().effect_state()),
        Some(Some(EffectState::NotStarted)),
        "the settled containment keeps the effect state its completion observed"
    );
    assert_eq!(
        registry.live_resources(),
        0,
        "the finished lifetime released its live place"
    );

    let swept =
        registry.settle_cohort_from_emergency_cleanup(vec![(subject.clone(), emergency_cleanup())]);
    assert!(!swept.is_complete());
    assert!(
        swept.settled().is_empty(),
        "a settled lifetime is not reopened by hard-cancellation cleanup"
    );
    assert!(matches!(
        swept.refusal(),
        Some((
            _,
            ResourceRegistryRefusal::EmergencyRelease(ResourceError::IllegalLifetimeTransition)
        ))
    ));
    assert_eq!(
        registry
            .account(&subject)
            .map(|account| account.ledger().lifetime()),
        Some(ResourceLifetimeState::Finished),
        "the refused cleanup leaves the terminal lifetime exactly as it was"
    );
    assert_eq!(
        headroom(&registry),
        Some(7),
        "the refused cleanup consumes no quota"
    );
    assert_eq!(
        registry
            .account(&subject)
            .map(|account| account.containment().outcome()),
        Some(Some(ExternalOutcome::Accepted)),
        "the refused cleanup leaves the settled containment outcome as it was"
    );
}

/// Returns the workspace root of this repository.
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Returns the text of one workspace file.
fn read_text(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()))
}

/// Returns the text with every whitespace run collapsed to one space.
fn flatten(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Every clause anchor the runtime resource reader note cites.
const RUNTIME_NOTE_CLAUSES: &[&str] = &[
    "GNT-28.7-durable-resource-reconstruction",
    "GNT-28.11-runtime-admission-mapping",
    "GNT-20.1-operation-kinds",
    "GNT-20.10-retirement-and-stale-owner-fencing",
    "GNT-28.8-retention-and-compaction-fences",
    "GNT-28.9-retirement-deletion-and-stale-owner-fences",
    "GNT-28.3-atomic-copy-move-loan-update-and-release-charging",
    "GNT-28.5-closed-quota-families-and-owners",
    "GNT-28.6-bounded-renewal-and-exhaustion",
    "GNT-28.4-resource-lifetime-finish-poison-and-emergency-release",
    "GNT-28.1-resource-identity-and-closed-liveness-roots",
    "GNT-20.7-resource-state-after-failure-and-poisoning",
    "GNT-23.4-operation-ownership-and-single-settlement",
    "GNT-23.5-failed-instance-poisoning-and-isolation",
    "GNT-20.11-adapter-obligations-and-diagnostics",
    "GNT-28.12-operation-state-projection",
    "GNT-28.10-resource-accounting-non-claims",
    "GNT-23.7-adapter-containment-obligations",
    "GNT-23.8-containment-non-claims",
    "GNT-23.6-protected-fault-diagnostics",
    "GNT-22.6-grace-expiry-and-hard-cancellation",
];

/// Every runtime route or accessor the runtime resource reader note publishes.
const RUNTIME_NOTE_ROUTES: &[&str] = &[
    "admit",
    "reconstruct",
    "RecoveredResourceRecord",
    "declared_records",
    "account",
    "with_live_limit",
    "live_limit",
    "live_resources",
    "reap_deleted",
    "charge",
    "renew",
    "begin_finish",
    "complete_finalization",
    "close_liveness_root",
    "retire",
    "delete",
    "settle_from_post_failure",
    "project_operation_state",
    "settle_from_emergency_cleanup",
    "poison_adapter_from_post_failure",
    "settle_containment",
    "bind_adapter_instance",
    "adapter_instance",
    "poison_adapter_instance",
    "subject",
    "ledger",
    "quota",
    "remaining",
    "durable_record",
    "containment",
    "begin_finish_for",
    "complete_finalization_for",
    "close_liveness_root_for",
    "delete_for",
    "settle_cohort_from_emergency_cleanup",
    "CohortEmergencyCleanup",
    "CohortEmergencySettlement",
];

/// Section 28's scope and exclusions must acknowledge both separately scoped runtime mappings.
#[test]
fn resource_spec_scope_includes_both_runtime_mappings_without_analyzer_claims() {
    let spec = read_text(&workspace_root().join("SPEC.md"));
    let scope = spec
        .split("**[GNT-28.0-resource-accounting-and-lifetime-contract]")
        .nth(1)
        .and_then(|section| section.split("<a id=\"GNT-28.1-").next())
        .unwrap_or_else(|| panic!("the Section 28 scope exists"));
    let non_claims = spec
        .split("**[GNT-28.10-resource-accounting-non-claims]")
        .nth(1)
        .and_then(|section| section.split("<a id=\"GNT-28.11-").next())
        .unwrap_or_else(|| panic!("the Section 28 non-claims exist"));
    let applicability = scope
        .split("**Applicability.**")
        .nth(1)
        .and_then(|section| section.split("**Boundary.**").next())
        .unwrap_or_else(|| panic!("the Section 28 applicability exists"));
    for clause in [
        "GNT-28.11-runtime-admission-mapping",
        "GNT-28.12-operation-state-projection",
    ] {
        assert!(scope.contains(clause), "scope must identify {clause}");
        assert!(
            non_claims.contains(clause),
            "exceptions must identify {clause}"
        );
    }
    let applicability = flatten(applicability);
    assert!(
        applicability
            .contains("Clauses `GNT-28.11` and `GNT-28.12` apply only to a runtime profile")
    );
    assert!(applicability.contains("does not claim coverage of `GNT-28.11` or `GNT-28.12`"));
    for limit in [
        "evaluator behavior",
        "a checkpoint",
        "a journal schema",
        "a host trait",
    ] {
        assert!(
            applicability.contains(limit),
            "retain the {limit} exclusion"
        );
    }
    assert!(non_claims.contains("model fact or test MUST NOT be presented as a runtime guarantee"));
}

/// The runtime resource reader note names every clause it relies on, every route it publishes, and
/// every limit it publishes, so a summary cannot quietly drop a surface or overstate a claim.
#[test]
fn runtime_resource_note_pins_every_declared_surface_and_non_claim() {
    let note = read_text(&workspace_root().join("docs/resource-runtime-integration.md"));
    for anchor in RUNTIME_NOTE_CLAUSES {
        assert!(note.contains(anchor), "the reader note must name {anchor}");
    }
    for route in RUNTIME_NOTE_ROUTES {
        assert!(note.contains(route), "the reader note must name {route}");
    }
    // The material per-claim sentences, so a substantive statement cannot change or disappear while
    // the anchor-only check stays green.
    let claims: &[(&str, &[&str])] = &[
        (
            "GNT-28.7-durable-resource-reconstruction",
            &["Admission", "Reconstruction", "Capture"],
        ),
        (
            "GNT-20.10-retirement-and-stale-owner-fencing",
            &[
                "owner-qualified",
                "a superseded generation is refused before any declared fact changes",
            ],
        ),
        (
            "GNT-28.10-resource-accounting-non-claims",
            &[
                "Account uniqueness is per registry",
                "no global uniqueness claim",
            ],
        ),
        (
            "GNT-23.4-operation-ownership-and-single-settlement",
            &[
                "runtime state of one account value",
                "publishes no cross-recovery single-settlement claim",
            ],
        ),
        (
            "GNT-23.5-failed-instance-poisoning-and-isolation",
            &[
                "poison reason ledger are runtime state",
                "publishes no recovery claim for either",
            ],
        ),
        (
            "GNT-23.7-adapter-containment-obligations",
            &[
                "declare containment obligations and limits only",
                "never derives a resource settlement from a containment report",
            ],
        ),
        (
            "GNT-23.6-protected-fault-diagnostics",
            &["Protected-scope containment reports are not published here"],
        ),
        (
            "GNT-28.9-retirement-deletion-and-stale-owner-fences",
            &[
                "Physical reclamation is not semantic release",
                "no retention state returns a released live place",
            ],
        ),
    ];
    let flattened = flatten(&note);
    for (anchor, fragments) in claims {
        for fragment in *fragments {
            let needle = flatten(fragment);
            assert!(
                flattened.contains(&needle),
                "the reader note must state, under {anchor}: {needle}"
            );
        }
    }
}

/// Returns the units one claim may be stated in: every single line, and every bullet together with
/// its continuation lines. A table row is therefore matched only within its own row and a non-claim
/// only within its own bullet, so an anchor in a neighbouring row cannot satisfy a claim.
fn claim_units(text: &str) -> Vec<String> {
    let mut units: Vec<String> = text.lines().map(flatten).collect();
    let mut bullet: Vec<&str> = Vec::new();
    for line in text.lines() {
        if line.trim_start().starts_with("- ") {
            if !bullet.is_empty() {
                units.push(flatten(&bullet.join(" ")));
            }
            bullet = vec![line];
        } else if line.trim().is_empty() {
            if !bullet.is_empty() {
                units.push(flatten(&bullet.join(" ")));
                bullet.clear();
            }
        } else if !bullet.is_empty() {
            bullet.push(line);
        }
    }
    if !bullet.is_empty() {
        units.push(flatten(&bullet.join(" ")));
    }
    units
}

/// Returns whether one note states one clause anchor together with every fragment of one claim in a
/// single unit.
fn claim_is_stated(text: &str, anchor: &str, fragments: &[&str]) -> bool {
    let needles: Vec<String> = fragments.iter().map(|fragment| flatten(fragment)).collect();
    claim_units(text)
        .iter()
        .any(|unit| unit.contains(anchor) && needles.iter().all(|needle| unit.contains(needle)))
}

/// The reader note states each material claim together with the clause that owns it, in one line or
/// one bullet, so a claim cannot pass by appearing anywhere in the note while the row or bullet that
/// owns it says something else, and so a moved or removed anchor fails rather than passing on a
/// stray word elsewhere in the note.
#[test]
fn runtime_resource_note_pins_claims_to_their_sections() {
    let note = read_text(&workspace_root().join("docs/resource-runtime-integration.md"));
    let units = claim_units(&note);
    let claims: &[(&str, &[&str])] = &[
        ("GNT-20.1-operation-kinds", &["Admission"]),
        ("GNT-28.7-durable-resource-reconstruction", &["Capture"]),
        (
            "GNT-28.11-runtime-admission-mapping",
            &["maps only accounting admission", "physical host resource"],
        ),
        (
            "GNT-28.4-resource-lifetime-finish-poison-and-emergency-release",
            &["Live-account ceiling", "the model owns no ceiling"],
        ),
        (
            "GNT-28.9-retirement-deletion-and-stale-owner-fences",
            &["Physical reclamation", "Runtime policy"],
        ),
        (
            "GNT-20.7-resource-state-after-failure-and-poisoning",
            &["Failure settlement"],
        ),
        (
            "GNT-20.7-resource-state-after-failure-and-poisoning",
            &[
                "poison_adapter_from_post_failure",
                "caller supplies the classified poison reason",
            ],
        ),
        (
            "GNT-22.6-grace-expiry-and-hard-cancellation",
            &["Cohort emergency cleanup"],
        ),
        (
            "GNT-23.4-operation-ownership-and-single-settlement",
            &["Containment settlement"],
        ),
        (
            "GNT-23.4-operation-ownership-and-single-settlement",
            &[
                "runtime state of one account value",
                "publishes no cross-recovery single-settlement claim",
            ],
        ),
        (
            "GNT-23.5-failed-instance-poisoning-and-isolation",
            &["Adapter binding and poisoning"],
        ),
        (
            "GNT-23.5-failed-instance-poisoning-and-isolation",
            &[
                "poison reason ledger are runtime state",
                "publishes no recovery claim for either",
            ],
        ),
        (
            "GNT-20.10-retirement-and-stale-owner-fencing",
            &["Reconstruction"],
        ),
        (
            "GNT-23.7-adapter-containment-obligations",
            &[
                "declare containment obligations and limits only",
                "never derives a resource settlement from a containment report",
            ],
        ),
        (
            "GNT-28.9-retirement-deletion-and-stale-owner-fences",
            &[
                "Physical reclamation is not semantic release",
                "no retention state returns a released live place",
            ],
        ),
        (
            "GNT-23.6-protected-fault-diagnostics",
            &["Protected-scope containment reports are not published here"],
        ),
        (
            "GNT-28.10-resource-accounting-non-claims",
            &[
                "Account uniqueness is per registry",
                "no global uniqueness claim",
            ],
        ),
    ];
    for (anchor, fragments) in claims {
        let needles: Vec<String> = fragments.iter().map(|fragment| flatten(fragment)).collect();
        assert!(
            units.iter().any(|unit| {
                unit.contains(anchor) && needles.iter().all(|needle| unit.contains(needle))
            }),
            "the reader note must state {anchor} together with {needles:?} in one line or bullet"
        );
    }
    // Negative coverage: the predicate must fail when the owning row stops naming its own clause,
    // even though the same anchor still appears in another row of the same table.
    let weakened = note.replace(
        "| Live-account ceiling | `with_live_limit`, `live_limit`, `live_resources` | Runtime policy over the lifetimes `GNT-28.4-resource-lifetime-finish-poison-and-emergency-release` declares; the model owns no ceiling |",
        "| Live-account ceiling | `with_live_limit`, `live_limit`, `live_resources` | Runtime policy over the lifetimes `GNT-28.4` declares; the model owns no ceiling |",
    );
    assert_ne!(weakened, note, "the negative case must change the note");
    assert!(
        !claim_is_stated(
            &weakened,
            "GNT-28.4-resource-lifetime-finish-poison-and-emergency-release",
            &["Live-account ceiling", "the model owns no ceiling"],
        ),
        "a ceiling row that no longer names its own clause must fail the association check"
    );
    // Negative coverage for the non-claims: a bullet that loses its own anchor must fail even though
    // the anchor still appears in the table above it.
    let weakened_bullet = note.replace(
        "runtime state of one account value under\n  `GNT-23.4-operation-ownership-and-single-settlement`, so one contained operation",
        "runtime state of one account value under no named clause, so one contained operation",
    );
    assert_ne!(
        weakened_bullet, note,
        "the negative case must change the note"
    );
    assert!(
        !claim_is_stated(
            &weakened_bullet,
            "GNT-23.4-operation-ownership-and-single-settlement",
            &[
                "runtime state of one account value",
                "publishes no cross-recovery single-settlement claim",
            ],
        ),
        "a containment non-claim that no longer names its own clause must fail"
    );
    let weakened_adapter_bullet = note.replace(
        "runtime state under\n  `GNT-23.5-failed-instance-poisoning-and-isolation`. A registry rebuilt",
        "runtime state under no named clause. A registry rebuilt",
    );
    assert_ne!(
        weakened_adapter_bullet, note,
        "the adapter negative case must change the note"
    );
    assert!(
        !claim_is_stated(
            &weakened_adapter_bullet,
            "GNT-23.5-failed-instance-poisoning-and-isolation",
            &[
                "poison reason ledger are runtime state",
                "publishes no recovery claim for either",
            ],
        ),
        "an adapter non-claim that no longer names its own clause must fail"
    );
    // Statements that no single clause owns must still be published, and the witness paragraph must
    // name the boundaries the witnesses actually cover rather than claiming all of them.
    let flattened = flatten(&note);
    for statement in [
        "`poison_adapter_from_post_failure` is a distinct adapter-failure route",
        "the presented current owner generation fences the bound adapter poison",
        "this route changes neither the resource lifetime nor sibling adapters",
        "are additionally owner-qualified",
        "a superseded generation is refused before any declared fact changes",
        "Physical reclamation is the one registry-wide mutating route and changes no declared fact",
        "No public route hands out a mutable registry-held account",
        "the private subject-binding constructor",
        "the removed raw ledger accessor",
        "each witness authorizes at most one settlement attempt",
        "a witness that reaches no ledger is dropped rather than returned",
    ] {
        assert!(
            flattened.contains(&flatten(statement)),
            "the reader note must state: {statement}"
        );
    }
}
