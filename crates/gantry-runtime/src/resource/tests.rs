//! Storage reclamation and account-qualified adapter dispatch regressions.

use super::*;

/// Projection must use admitted recovery facts, never a caller alias's substituted metadata.
#[test]
fn projection_requires_account_recovery_metadata_even_with_a_matching_alias() {
    use gantry_ir::generated::RecoveryClass;
    use gantry_ir::{DisclosureCharge, OperationAbi, OperationSettlement, ReceiverOwnership};

    let path =
        CanonicalPath::new("crate::resource").unwrap_or_else(|error| panic!("path: {error}"));
    let execution = gantry_core::identity::ProtocolIdentity::from_fresh_material(
        gantry_core::portable::IdentityKind::Execution,
        [72; 32],
    )
    .unwrap_or_else(|error| panic!("execution: {error}"));
    let subject = ResourceSubjectBinding::derive(
        &path,
        path.clone(),
        StructuralPosition::new(vec![0]).unwrap_or_else(|error| panic!("site: {error}")),
        0,
        Some(OperationKind::LiveResource),
        Arc::new(Mutex::new(crate::machine::ResourceOperationLease::open())),
        (execution, crate::root_task_identity(execution)),
    );
    let owner = OwnerGeneration::new(4);
    for failed in [false, true] {
        let mut registry = ResourceRegistry::new();
        registry
            .admit(
                subject.clone(),
                ResourceCarrier::ReconstructionRecord,
                ResourceLedger::new(owner, ResourceState::Usable, &[LivenessRoot::Resource], &[])
                    .unwrap_or_else(|error| panic!("ledger: {error:?}"))
                    .durable_record(),
            )
            .unwrap_or_else(|error| panic!("admit: {error:?}"));
        let mut alias = subject.clone();
        alias.recovery = Some(RecoveryClass::Idempotent);
        let mut live = OperationAbi::new(
            OperationKind::LiveResource,
            &path,
            subject.site(),
            0,
            RecoveryClass::Idempotent,
            ReceiverOwnership::RetainedByCaller,
        )
        .unwrap_or_else(|error| panic!("ABI: {error:?}"))
        .open_live(
            owner,
            OperationAbi::observation_allowance(
                1,
                DisclosureCharge::new(1).unwrap_or_else(|| panic!("charge")),
            ),
        )
        .unwrap_or_else(|error| panic!("live: {error:?}"));
        if failed {
            live.settle_failure(gantry_ir::FailureClass::AdapterFailure)
                .unwrap_or_else(|error| panic!("failure: {error:?}"));
        } else {
            let settlement = OperationSettlement::new(
                live.operation(),
                live.generation(),
                owner,
                ExternalOutcome::Accepted,
                gantry_ir::ProgressObservation::CommittedProgress,
                25,
            )
            .unwrap_or_else(|error| panic!("settlement: {error:?}"));
            live.settle(&settlement)
                .unwrap_or_else(|error| panic!("winner: {error:?}"));
        }
        let before = registry.declared_records();
        let project = |registry: &mut ResourceRegistry| {
            if failed {
                registry.project_failure_state(&live, &alias)
            } else {
                registry.project_operation_state(&live, &alias)
            }
        };
        assert_eq!(
            project(&mut registry),
            Err(ResourceRegistryRefusal::RecoveryContractMismatch {
                presented: RecoveryClass::Idempotent,
                expected: None,
            })
        );
        assert_eq!(registry.declared_records(), before);
        assert_eq!(registry.pending_operations(), 1);
        registry
            .accounts
            .get_mut(&subject.registry_key())
            .unwrap_or_else(|| panic!("account"))
            .subject
            .recovery = Some(RecoveryClass::Idempotent);
        alias.recovery = Some(RecoveryClass::ReadOnly);
        let result = if failed {
            registry.project_failure_state(&live, &alias)
        } else {
            registry.project_operation_state(&live, &alias)
        };
        assert_eq!(
            result,
            Ok(if failed {
                ResourceState::HalfClosed
            } else {
                ResourceState::Consumed
            })
        );
        assert_eq!(registry.pending_operations(), 1);
    }
}

/// Direct reconstruction must retain the same historical-owner fence as envelope decoding.
#[cfg(feature = "durable")]
#[test]
fn reconstruction_refuses_future_containment_owners() {
    let path =
        CanonicalPath::new("crate::resource").unwrap_or_else(|error| panic!("path: {error}"));
    let execution = gantry_core::identity::ProtocolIdentity::from_fresh_material(
        gantry_core::portable::IdentityKind::Execution,
        [71; 32],
    )
    .unwrap_or_else(|error| panic!("execution: {error}"));
    let subject = ResourceSubjectBinding::derive(
        &path,
        path.clone(),
        StructuralPosition::new(vec![0]).unwrap_or_else(|error| panic!("site: {error}")),
        0,
        Some(OperationKind::LiveResource),
        Arc::new(Mutex::new(crate::machine::ResourceOperationLease::open())),
        (execution, crate::root_task_identity(execution)),
    );
    let owner = OwnerGeneration::new(4);
    let ledger = ResourceLedger::new(owner, ResourceState::Usable, &[LivenessRoot::Resource], &[])
        .unwrap_or_else(|error| panic!("ledger: {error:?}"));
    for winner in [
        None,
        Some((
            gantry_ir::EffectState::NotStarted,
            ExternalOutcome::Accepted,
        )),
    ] {
        let mut record = RecoveredResourceRecord::new(
            subject.clone(),
            ResourceCarrier::ReconstructionRecord,
            owner,
            ledger.durable_record(),
        );
        record.containment_evidence = Some((OwnerGeneration::new(5), winner));
        assert_eq!(
            ResourceRegistry::reconstruct(Some(1), [record.clone()]).err(),
            Some(ResourceRegistryRefusal::Containment(
                ContainmentError::StaleGeneration {
                    presented: OwnerGeneration::new(5),
                    held: owner,
                }
            )),
            "future historical ownership must refuse before registry publication"
        );
        for historical in [OwnerGeneration::new(3), owner] {
            record.containment_evidence = Some((historical, winner));
            let rebuilt = ResourceRegistry::reconstruct(Some(1), [record.clone()])
                .unwrap_or_else(|error| panic!("historical reconstruction: {error:?}"));
            assert_eq!(
                rebuilt.declared_records_with_containment(),
                vec![record.clone()]
            );
        }
    }
}

/// Reaping may discard settled storage, never accepted pending or unreadable lease ownership.
#[test]
fn reaping_prunes_closed_leases_and_retains_pending_or_unreadable_work() {
    let closed = Arc::new(Mutex::new(crate::machine::ResourceOperationLease::open()));
    closed
        .lock()
        .unwrap_or_else(|_| panic!("closed lease"))
        .pending = false;
    let closed_weak = Arc::downgrade(&closed);
    let pending = Arc::new(Mutex::new(crate::machine::ResourceOperationLease::open()));
    let unreadable = Arc::new(Mutex::new(crate::machine::ResourceOperationLease::open()));
    assert!(
        std::panic::catch_unwind(|| {
            let _guard = unreadable.lock().unwrap_or_else(|_| panic!("lease"));
            panic!("poison fixture lease");
        })
        .is_err()
    );
    let mut registry = ResourceRegistry::new();
    registry.pending_admissions = vec![closed, Arc::clone(&pending), Arc::clone(&unreadable)];
    assert_eq!(registry.pending_operations(), 2);
    assert_eq!(registry.reap_deleted(), 0);
    assert_eq!(registry.pending_admissions.len(), 2);
    assert!(
        closed_weak.upgrade().is_none(),
        "settled reference must be reclaimed without another admission"
    );
    assert!(
        registry
            .pending_admissions
            .iter()
            .any(|lease| Arc::ptr_eq(lease, &pending))
    );
    assert!(
        registry
            .pending_admissions
            .iter()
            .any(|lease| Arc::ptr_eq(lease, &unreadable))
    );
    assert_eq!(registry.pending_operations(), 2);
    assert_eq!(registry.reap_deleted(), 0);
    assert_eq!(registry.pending_admissions.len(), 2);
}

/// A caller alias cannot weaken the recovery class held by the admitted account.
#[test]
fn adapter_dispatch_uses_account_recovery_across_the_rights_matrix() {
    use gantry_ir::generated::RecoveryClass;
    use gantry_ir::{AuthorityRight, CanonicalImplementationIdentity, RightsSet, TypeExpression};
    for recovery in [
        RecoveryClass::ReadOnly,
        RecoveryClass::Idempotent,
        RecoveryClass::NonIdempotent,
    ] {
        for authorized in [false, true] {
            let path = CanonicalPath::new("crate::resource")
                .unwrap_or_else(|error| panic!("path: {error}"));
            let execution = gantry_core::identity::ProtocolIdentity::from_fresh_material(
                gantry_core::portable::IdentityKind::Execution,
                [41; 32],
            )
            .unwrap_or_else(|error| panic!("execution: {error}"));
            let mut subject = ResourceSubjectBinding::derive(
                &path,
                path.clone(),
                StructuralPosition::new(vec![0]).unwrap_or_else(|error| panic!("site: {error}")),
                0,
                Some(OperationKind::LiveResource),
                Arc::new(Mutex::new(crate::machine::ResourceOperationLease::open())),
                (execution, crate::root_task_identity(execution)),
            );
            subject.recovery = Some(recovery);
            let mut alias = subject.clone();
            alias.recovery = Some(RecoveryClass::ReadOnly);
            let owner = OwnerGeneration::new(4);
            let record =
                ResourceLedger::new(owner, ResourceState::Usable, &[LivenessRoot::Resource], &[])
                    .unwrap_or_else(|error| panic!("record: {error:?}"));
            let mut registry = ResourceRegistry::new();
            registry
                .admit_host_value(
                    subject.clone(),
                    ResourceCarrier::ReconstructionRecord,
                    record.durable_record(),
                    17_u64,
                )
                .unwrap_or_else(|_| panic!("admit"));
            let receiver = TypeExpression::from_canonical_string("crate::Adapter", 4)
                .unwrap_or_else(|error| panic!("receiver: {error:?}"));
            let rights = if authorized {
                RightsSet::from_rights(&[AuthorityRight::for_recovery_class(recovery)])
            } else {
                RightsSet::from_rights(&[AuthorityRight::Observe])
            };
            let adapter = AdapterInstance::bind(
                &CanonicalImplementationIdentity::inherent(&receiver),
                rights,
                owner,
                0,
            );
            registry
                .bind_adapter_instance(&subject, owner, adapter)
                .unwrap_or_else(|error| panic!("bind: {error:?}"));
            let before = registry.declared_records();
            let expected = if authorized {
                Ok(17)
            } else {
                Err(crate::HostResourceError::Operation(
                    OperationAbiError::AdapterRightsInsufficient {
                        recovery,
                        rights: rights.bits(),
                    },
                ))
            };
            assert_eq!(
                registry.invoke_host_value::<u64, u64>(&alias, owner, |value| Ok(*value)),
                expected
            );
            assert_eq!(registry.declared_records(), before);
            assert!(registry.has_host_value(&subject));
            assert_eq!(registry.pending_operations(), 1);
            registry
                .accounts
                .get_mut(&subject.registry_key())
                .unwrap_or_else(|| panic!("account"))
                .subject
                .recovery = None;
            assert_eq!(
                registry.invoke_host_value::<u64, ()>(&alias, owner, |_| panic!(
                    "missing metadata cannot dispatch"
                )),
                Err(crate::HostResourceError::UnauthenticatedRecoveryClass)
            );
            registry
                .accounts
                .get_mut(&subject.registry_key())
                .unwrap_or_else(|| panic!("account"))
                .subject
                .recovery = Some(recovery);
            registry
                .accounts
                .get_mut(&subject.registry_key())
                .and_then(|account| account.adapter.as_mut())
                .unwrap_or_else(|| panic!("adapter"))
                .retire();
            assert!(matches!(
                registry.invoke_host_value::<u64, ()>(&alias, owner, |_| panic!(
                    "retired adapter cannot dispatch"
                )),
                Err(crate::HostResourceError::Operation(
                    OperationAbiError::AdapterInstanceRetired { .. }
                ))
            ));
        }
    }
}

/// The declared physical kind these lanes open their `u64` handle slots under.
const HANDLE_KIND: &str = "native-handle";
/// A second declared physical kind over the same Rust representation as `HANDLE_KIND`.
const DIRECTORY_KIND: &str = "native-directory";

/// One canonical carrier site shared by every provenance variant of these lanes.
fn carrier_site() -> CanonicalPath {
    CanonicalPath::new("crate::carrier").unwrap_or_else(|error| panic!("path: {error}"))
}

/// One execution identity derived from fixed seed material.
fn carrier_execution(seed: u8) -> gantry_core::identity::ProtocolIdentity {
    gantry_core::identity::ProtocolIdentity::from_fresh_material(
        gantry_core::portable::IdentityKind::Execution,
        [seed; 32],
    )
    .unwrap_or_else(|error| panic!("execution: {error}"))
}

/// One non-root task identity of one execution derived from the machine task path key.
fn carrier_task(
    execution: gantry_core::identity::ProtocolIdentity,
    seed: u8,
) -> gantry_core::identity::ProtocolIdentity {
    let name = format!("sibling-{seed}");
    gantry_core::identity::ProtocolIdentity::derive(
        gantry_core::portable::IdentityKind::Task,
        &crate::machine::task_identity_key(execution, &[Arc::from(name.as_str())]),
    )
    .unwrap_or_else(|error| panic!("task: {error}"))
}

/// One subject at the shared static site and first generation for one exact runtime provenance.
fn carrier_subject(
    execution: gantry_core::identity::ProtocolIdentity,
    task: gantry_core::identity::ProtocolIdentity,
) -> ResourceSubjectBinding {
    let path = carrier_site();
    ResourceSubjectBinding::derive(
        &path,
        path.clone(),
        StructuralPosition::new(vec![0]).unwrap_or_else(|error| panic!("site: {error}")),
        0,
        Some(gantry_ir::OperationKind::LiveResource),
        Arc::new(Mutex::new(crate::machine::ResourceOperationLease::open())),
        (execution, task),
    )
}

/// Admits one subject under one owner generation without attaching a physical value.
fn admit_without_slot(
    registry: &mut ResourceRegistry,
    subject: &ResourceSubjectBinding,
    owner: OwnerGeneration,
) {
    registry
        .admit(
            subject.clone(),
            gantry_ir::ResourceCarrier::ReconstructionRecord,
            ResourceLedger::new(
                owner,
                ResourceState::Usable,
                &[LivenessRoot::Resource, LivenessRoot::Owner],
                &[],
            )
            .unwrap_or_else(|error| panic!("ledger: {error:?}"))
            .durable_record(),
        )
        .unwrap_or_else(|error| panic!("admit: {error:?}"));
}

/// Admits one subject under one owner generation and attaches one present physical value.
fn admit_with_slot<T: std::any::Any + Send>(
    registry: &mut ResourceRegistry,
    subject: &ResourceSubjectBinding,
    owner: OwnerGeneration,
    value: T,
) {
    admit_without_slot(registry, subject, owner);
    registry
        .attach_host_value(subject, owner, value)
        .unwrap_or_else(|_| panic!("attach"));
}

/// One admitted account, plus the subject and owner generation its lanes attach a slot under.
fn carrier_fixture(seed: u8) -> (ResourceRegistry, ResourceSubjectBinding, OwnerGeneration) {
    let path = CanonicalPath::new("crate::carrier").unwrap_or_else(|error| panic!("path: {error}"));
    let execution = gantry_core::identity::ProtocolIdentity::from_fresh_material(
        gantry_core::portable::IdentityKind::Execution,
        [seed; 32],
    )
    .unwrap_or_else(|error| panic!("execution: {error}"));
    let subject = ResourceSubjectBinding::derive(
        &path,
        path.clone(),
        StructuralPosition::new(vec![0]).unwrap_or_else(|error| panic!("site: {error}")),
        0,
        Some(gantry_ir::OperationKind::LiveResource),
        Arc::new(Mutex::new(crate::machine::ResourceOperationLease::open())),
        (execution, crate::root_task_identity(execution)),
    );
    let owner = OwnerGeneration::new(4);
    let mut registry = ResourceRegistry::new();
    registry
        .admit(
            subject.clone(),
            gantry_ir::ResourceCarrier::ReconstructionRecord,
            ResourceLedger::new(
                owner,
                ResourceState::Usable,
                &[LivenessRoot::Resource, LivenessRoot::Owner],
                &[],
            )
            .unwrap_or_else(|error| panic!("ledger: {error:?}"))
            .durable_record(),
        )
        .unwrap_or_else(|error| panic!("admit: {error:?}"));
    (registry, subject, owner)
}

/// A carrier exists only for a present registry-owned slot and the current owner generation.
#[test]
fn machine_carrier_requires_an_attached_slot_and_the_current_owner() {
    let (mut registry, subject, owner) = carrier_fixture(21);
    assert_eq!(
        registry
            .issue_carrier::<u64>(&subject, owner, HANDLE_KIND)
            .err(),
        Some(crate::HostResourceError::NotAttached)
    );
    registry
        .attach_host_value(&subject, owner, 7_u64)
        .unwrap_or_else(|_| panic!("attach"));
    assert!(
        registry
            .issue_carrier::<u64>(&subject, OwnerGeneration::new(9), HANDLE_KIND)
            .is_err()
    );
    let carrier = registry
        .issue_carrier::<u64>(&subject, owner, HANDLE_KIND)
        .unwrap_or_else(|error| panic!("issue: {error:?}"));
    assert_eq!(carrier.subject(), &subject);
    assert_eq!(carrier.owner(), owner);
    assert_eq!(registry.authenticate_carrier(&carrier, HANDLE_KIND), Ok(()));
}

/// A carrier is bound to the registry whose account and lease issued it.
#[test]
fn machine_carrier_is_bound_to_one_registry() {
    let (mut registry, subject, owner) = carrier_fixture(22);
    registry
        .attach_host_value(&subject, owner, 7_u64)
        .unwrap_or_else(|_| panic!("attach"));
    let carrier = registry
        .issue_carrier::<u64>(&subject, owner, HANDLE_KIND)
        .unwrap_or_else(|error| panic!("issue: {error:?}"));
    let other = ResourceRegistry::new();
    assert_eq!(
        other.authenticate_carrier(&carrier, HANDLE_KIND).err(),
        Some(crate::HostResourceError::UnknownSubject)
    );
    let mut sibling = ResourceRegistry::new();
    // The subject is cloneable, so a sibling registry may be handed the very same machine-issued
    // admission lease. Only the physical slot identity may authenticate a carrier.
    let sibling_subject = subject.clone();
    sibling
        .admit(
            sibling_subject.clone(),
            gantry_ir::ResourceCarrier::ReconstructionRecord,
            ResourceLedger::new(owner, ResourceState::Usable, &[LivenessRoot::Resource], &[])
                .unwrap_or_else(|error| panic!("ledger: {error:?}"))
                .durable_record(),
        )
        .unwrap_or_else(|error| panic!("admit: {error:?}"));
    sibling
        .attach_host_value(&sibling_subject, owner, 8_u64)
        .unwrap_or_else(|_| panic!("attach"));
    assert_eq!(
        sibling.authenticate_carrier(&carrier, HANDLE_KIND).err(),
        Some(crate::HostResourceError::ForeignSubject)
    );
    sibling
        .begin_finish(&sibling_subject, owner)
        .unwrap_or_else(|error| panic!("begin finish: {error:?}"));
    assert_eq!(
        sibling.complete_carrier::<u64>(carrier, HANDLE_KIND),
        Err(crate::HostResourceError::ForeignSubject)
    );
    assert!(registry.has_host_value(&subject));
    assert!(sibling.has_host_value(&sibling_subject));
}

/// Completion waits for semantic settlement and happens exactly once.
#[test]
fn machine_carrier_completes_only_after_semantic_settlement() {
    let (mut registry, subject, owner) = carrier_fixture(23);
    registry
        .attach_host_value(&subject, owner, 7_u64)
        .unwrap_or_else(|_| panic!("attach"));
    let carrier = registry
        .issue_carrier::<u64>(&subject, owner, HANDLE_KIND)
        .unwrap_or_else(|error| panic!("issue: {error:?}"));
    assert!(matches!(
        registry.complete_carrier::<u64>(carrier, HANDLE_KIND),
        Err(crate::HostResourceError::Model(
            gantry_ir::ResourceError::IllegalLifetimeTransition
        ))
    ));
    let carrier = registry
        .issue_carrier::<u64>(&subject, owner, HANDLE_KIND)
        .unwrap_or_else(|error| panic!("issue: {error:?}"));
    registry
        .begin_finish(&subject, owner)
        .unwrap_or_else(|error| panic!("begin finish: {error:?}"));
    assert_eq!(
        registry.complete_carrier::<u64>(carrier, HANDLE_KIND),
        Ok(())
    );
    registry
        .complete_finalization(&subject, owner, 11)
        .unwrap_or_else(|error| panic!("finalize: {error:?}"));
    assert!(!registry.has_host_value(&subject));
    assert!(
        registry
            .issue_carrier::<u64>(&subject, owner, HANDLE_KIND)
            .is_err()
    );
}

/// Cancelled admission issues no carrier, and completion refuses a different Rust type.
#[test]
fn machine_carrier_refuses_cancelled_admission_and_a_different_type() {
    let (mut registry, subject, owner) = carrier_fixture(24);
    registry
        .attach_host_value(&subject, owner, 7_u64)
        .unwrap_or_else(|_| panic!("attach"));
    let carrier = registry
        .issue_carrier::<u64>(&subject, owner, HANDLE_KIND)
        .unwrap_or_else(|error| panic!("issue: {error:?}"));
    assert_eq!(
        registry.complete_carrier::<u32>(carrier, HANDLE_KIND),
        Err(crate::HostResourceError::TypeMismatch)
    );
    let lease = Arc::clone(&subject.admission_open);
    lease
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .cancellation_requested = true;
    assert_eq!(
        registry
            .issue_carrier::<u64>(&subject, owner, HANDLE_KIND)
            .err(),
        Some(crate::HostResourceError::CancellationRequested)
    );
}

/// Issuance refuses a Rust type the attached slot does not hold, and retains the slot.
#[test]
fn machine_carrier_issuance_refuses_a_type_the_slot_does_not_hold() {
    let (mut registry, subject, owner) = carrier_fixture(25);
    registry
        .attach_host_value(&subject, owner, 7_u64)
        .unwrap_or_else(|_| panic!("attach"));
    assert_eq!(
        registry
            .issue_carrier::<String>(&subject, owner, HANDLE_KIND)
            .err(),
        Some(crate::HostResourceError::TypeMismatch)
    );
    assert!(registry.has_host_value(&subject));
    let carrier = registry
        .issue_carrier::<u64>(&subject, owner, HANDLE_KIND)
        .unwrap_or_else(|error| panic!("issue: {error:?}"));
    assert_eq!(carrier.value_type(), std::any::TypeId::of::<u64>());
}

/// A slot opened as one physical kind refuses authentication and settlement as another.
#[test]
fn machine_carrier_refuses_a_foreign_physical_kind() {
    let (mut registry, subject, owner) = carrier_fixture(26);
    registry
        .attach_host_value(&subject, owner, 7_u64)
        .unwrap_or_else(|_| panic!("attach"));
    let carrier = registry
        .issue_carrier::<u64>(&subject, owner, HANDLE_KIND)
        .unwrap_or_else(|error| panic!("issue: {error:?}"));
    assert_eq!(carrier.kind(), HANDLE_KIND);
    assert_eq!(
        registry.authenticate_carrier(&carrier, DIRECTORY_KIND),
        Err(crate::HostResourceError::CarrierKindMismatch {
            expected: HANDLE_KIND,
            presented: DIRECTORY_KIND,
        })
    );
    // The kind fence precedes every lifetime and accounting decision, so a settlement presented as
    // another physical kind is refused while the account is still active and changes nothing.
    let settled = registry.declared_records();
    assert_eq!(
        registry.complete_carrier::<u64>(carrier, DIRECTORY_KIND),
        Err(crate::HostResourceError::CarrierKindMismatch {
            expected: HANDLE_KIND,
            presented: DIRECTORY_KIND,
        })
    );
    assert_eq!(settled, registry.declared_records());
    assert!(registry.has_host_value(&subject));
    let carrier = registry
        .issue_carrier::<u64>(&subject, owner, HANDLE_KIND)
        .unwrap_or_else(|error| panic!("issue: {error:?}"));
    registry
        .begin_finish(&subject, owner)
        .unwrap_or_else(|error| panic!("begin finish: {error:?}"));
    assert_eq!(
        registry.complete_carrier::<u64>(carrier, HANDLE_KIND),
        Ok(())
    );
    assert!(!registry.has_host_value(&subject));
    registry
        .complete_finalization(&subject, owner, 11)
        .unwrap_or_else(|error| panic!("finalize: {error:?}"));
    // A settled account issues nothing at all, whether or not the disposed slot is queried.
    assert!(
        registry
            .issue_carrier::<u64>(&subject, owner, HANDLE_KIND)
            .is_err()
    );
}

/// One slot issues exactly one live carrier, and the refused duplicate retains the slot.
#[test]
fn machine_carrier_issuance_is_exclusive_and_retains_the_slot() {
    let (mut registry, subject, owner) = carrier_fixture(27);
    registry
        .attach_host_value(&subject, owner, 7_u64)
        .unwrap_or_else(|_| panic!("attach"));
    let carrier = registry
        .issue_carrier::<u64>(&subject, owner, HANDLE_KIND)
        .unwrap_or_else(|error| panic!("issue: {error:?}"));
    assert_eq!(
        registry
            .issue_carrier::<u64>(&subject, owner, HANDLE_KIND)
            .err(),
        Some(crate::HostResourceError::CarrierAlreadyIssued)
    );
    // The refused duplicate spends nothing: the sole carrier still authenticates, the slot is
    // still present, and settling through that carrier does not dispose the slot under a duplicate.
    assert_eq!(registry.authenticate_carrier(&carrier, HANDLE_KIND), Ok(()));
    assert!(registry.has_host_value(&subject));
    registry
        .begin_finish(&subject, owner)
        .unwrap_or_else(|error| panic!("begin finish: {error:?}"));
    assert_eq!(
        registry.complete_carrier::<u64>(carrier, HANDLE_KIND),
        Ok(())
    );
    assert!(!registry.has_host_value(&subject));
    assert!(
        registry
            .issue_carrier::<u64>(&subject, owner, HANDLE_KIND)
            .is_err()
    );
}

/// Equal static site, generation and owner facts across executions and tasks confer no authority.
#[test]
fn machine_carrier_refuses_cross_execution_and_cross_task_authority() {
    let owner = OwnerGeneration::new(4);
    let first_execution = carrier_execution(31);
    let second_execution = carrier_execution(32);
    let root_task = crate::root_task_identity(first_execution);
    let sibling_task = carrier_task(first_execution, 33);
    let first = carrier_subject(first_execution, root_task);
    let same_execution_other_task = carrier_subject(first_execution, sibling_task);
    let other_execution = carrier_subject(
        second_execution,
        crate::root_task_identity(second_execution),
    );
    // Portable identity coincides across all three bindings; only the runtime provenance differs.
    assert_eq!(first.operation(), other_execution.operation());
    assert_eq!(first.generation(), other_execution.generation());
    assert_eq!(first.generation(), same_execution_other_task.generation());
    assert_eq!(first.site(), same_execution_other_task.site());
    assert_ne!(first, same_execution_other_task);
    assert_ne!(first, other_execution);

    let mut registry = ResourceRegistry::new();
    admit_with_slot(&mut registry, &first, owner, 7_u64);
    admit_with_slot(&mut registry, &same_execution_other_task, owner, 8_u64);
    admit_with_slot(&mut registry, &other_execution, owner, 9_u64);
    let carrier = registry
        .issue_carrier::<u64>(&first, owner, HANDLE_KIND)
        .unwrap_or_else(|error| panic!("issue: {error:?}"));
    assert_eq!(carrier.execution_id(), first_execution);
    assert_eq!(carrier.task_id(), root_task);

    // A receipt naming another execution or another task of this execution is refused on
    // provenance alone: kind, slot presence, owner currency, admission and dispatch all hold.
    for foreign in [&same_execution_other_task, &other_execution] {
        let receipt = CarrierAssociationReceipt::new(foreign.clone(), owner, HANDLE_KIND);
        let facts = registry.confirm_association(&carrier, &receipt);
        assert!(!facts.provenance());
        assert!(!facts.is_associated());
        assert!(facts.kind());
        assert!(facts.slot_present());
        assert!(facts.owner_current());
        assert!(facts.lease_admitted());
        assert!(!facts.cancellation_requested());
        assert!(facts.dispatch_eligible());
    }
    // The carrier declaration built from the carrier itself is the only one that holds together.
    let own = CarrierAssociationReceipt::from_carrier(&carrier);
    assert_eq!(own.subject(), &first);
    assert!(registry.confirm_association(&carrier, &own).is_associated());
    assert_eq!(registry.authenticate_carrier(&carrier, HANDLE_KIND), Ok(()));

    // Settling the first provenance disposes only its own slot and leaves the coincident
    // portable identities of the other two accounts untouched.
    let sibling_carrier = registry
        .issue_carrier::<u64>(&other_execution, owner, HANDLE_KIND)
        .unwrap_or_else(|error| panic!("issue: {error:?}"));
    registry
        .begin_finish(&first, owner)
        .unwrap_or_else(|error| panic!("begin finish: {error:?}"));
    assert_eq!(
        registry.complete_carrier::<u64>(carrier, HANDLE_KIND),
        Ok(())
    );
    assert!(!registry.has_host_value(&first));
    assert!(registry.has_host_value(&same_execution_other_task));
    assert!(registry.has_host_value(&other_execution));
    assert_eq!(
        registry.authenticate_carrier(&sibling_carrier, HANDLE_KIND),
        Ok(())
    );
}

/// Association is answerable before accounting and changes no declared ledger fact.
#[test]
fn association_before_accounting_refuses_without_changing_the_ledger() {
    let (mut registry, subject, owner) = carrier_fixture(28);
    let before = registry.declared_records();
    // Without a present slot no carrier exists, so no association is writable either.
    assert_eq!(
        registry
            .issue_carrier::<u64>(&subject, owner, HANDLE_KIND)
            .err(),
        Some(crate::HostResourceError::NotAttached)
    );
    assert_eq!(before, registry.declared_records());
    registry
        .attach_host_value(&subject, owner, 7_u64)
        .unwrap_or_else(|_| panic!("attach"));
    let carrier = registry
        .issue_carrier::<u64>(&subject, owner, HANDLE_KIND)
        .unwrap_or_else(|error| panic!("issue: {error:?}"));
    let settled = registry.declared_records();

    let own = CarrierAssociationReceipt::from_carrier(&carrier);
    assert!(registry.confirm_association(&carrier, &own).is_associated());
    // A kind the carrier was not issued for is reported as a failed fact, not adopted.
    let foreign_kind = CarrierAssociationReceipt::new(subject.clone(), owner, DIRECTORY_KIND);
    let refused = registry.confirm_association(&carrier, &foreign_kind);
    assert!(!refused.kind());
    assert!(!refused.is_associated());
    assert!(refused.provenance());
    // A superseded owner generation and a requested cancellation are facts too.
    let stale =
        CarrierAssociationReceipt::new(subject.clone(), OwnerGeneration::new(9), HANDLE_KIND);
    assert!(
        !registry
            .confirm_association(&carrier, &stale)
            .owner_current()
    );
    Arc::clone(&subject.admission_open)
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .cancellation_requested = true;
    let cancelled = registry.confirm_association(&carrier, &own);
    assert!(cancelled.cancellation_requested());
    assert!(!cancelled.is_associated());
    Arc::clone(&subject.admission_open)
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .cancellation_requested = false;

    // Every answered fact above left the declared ledger byte identical and the slot present.
    assert_eq!(settled, registry.declared_records());
    assert!(registry.has_host_value(&subject));
    registry
        .begin_finish(&subject, owner)
        .unwrap_or_else(|error| panic!("begin finish: {error:?}"));
    assert_eq!(
        registry.complete_carrier::<u64>(carrier, HANDLE_KIND),
        Ok(())
    );
}

/// A foreign completion attempt consumes nothing and cannot release the local issuance fence.
#[test]
fn machine_carrier_fence_survives_a_foreign_completion_attempt() {
    let (mut registry, subject, owner) = carrier_fixture(34);
    registry
        .attach_host_value(&subject, owner, 7_u64)
        .unwrap_or_else(|_| panic!("attach"));
    let mut sibling = ResourceRegistry::new();
    admit_with_slot(&mut sibling, &subject, owner, 8_u64);
    let own = registry
        .issue_carrier::<u64>(&subject, owner, HANDLE_KIND)
        .unwrap_or_else(|error| panic!("issue: {error:?}"));
    let foreign = sibling
        .issue_carrier::<u64>(&subject, owner, HANDLE_KIND)
        .unwrap_or_else(|error| panic!("sibling issue: {error:?}"));

    // Completing another registry carrier for the same cloned subject is refused on the slot
    // identity fence, so the local fence and the local slot both survive the attempt.
    assert_eq!(
        registry.complete_carrier::<u64>(foreign, HANDLE_KIND),
        Err(crate::HostResourceError::ForeignSubject)
    );
    assert_eq!(
        registry
            .issue_carrier::<u64>(&subject, owner, HANDLE_KIND)
            .err(),
        Some(crate::HostResourceError::CarrierAlreadyIssued)
    );
    assert!(registry.has_host_value(&subject));
    assert_eq!(registry.authenticate_carrier(&own, HANDLE_KIND), Ok(()));
    assert!(sibling.has_host_value(&subject));
}

/// A declaration naming another operation of the same execution is refused on provenance.
#[test]
fn association_refuses_a_receipt_naming_another_operation() {
    let (mut registry, subject, owner) = carrier_fixture(35);
    registry
        .attach_host_value(&subject, owner, 7_u64)
        .unwrap_or_else(|_| panic!("attach"));
    let carrier = registry
        .issue_carrier::<u64>(&subject, owner, HANDLE_KIND)
        .unwrap_or_else(|error| panic!("issue: {error:?}"));
    let other_path =
        CanonicalPath::new("crate::carrier::other").unwrap_or_else(|error| panic!("path: {error}"));
    let other = ResourceSubjectBinding::derive(
        &other_path,
        other_path.clone(),
        StructuralPosition::new(vec![0]).unwrap_or_else(|error| panic!("site: {error}")),
        0,
        Some(gantry_ir::OperationKind::LiveResource),
        Arc::new(Mutex::new(crate::machine::ResourceOperationLease::open())),
        (subject.execution_id(), subject.task_id()),
    );
    // The declaration shares the issuing execution and task and still names another operation.
    assert_ne!(other.operation(), subject.operation());
    assert_eq!(other.execution_id(), subject.execution_id());
    assert_eq!(other.task_id(), subject.task_id());

    let receipt = CarrierAssociationReceipt::new(other, owner, HANDLE_KIND);
    let facts = registry.confirm_association(&carrier, &receipt);
    assert!(!facts.provenance());
    assert!(!facts.is_associated());
    assert!(facts.kind());
    assert!(facts.slot_present());
    assert!(facts.owner_current());
}

/// Association reports an absent slot, a closed lease and ineligible dispatch as failed facts.
#[test]
fn association_reports_absent_slot_closed_lease_and_ineligible_dispatch() {
    use gantry_ir::{AuthorityRight, CanonicalImplementationIdentity, RightsSet, TypeExpression};

    let (mut registry, subject, owner) = carrier_fixture(36);
    registry
        .attach_host_value(&subject, owner, 7_u64)
        .unwrap_or_else(|_| panic!("attach"));
    let carrier = registry
        .issue_carrier::<u64>(&subject, owner, HANDLE_KIND)
        .unwrap_or_else(|error| panic!("issue: {error:?}"));
    let own = CarrierAssociationReceipt::from_carrier(&carrier);

    // A registry holding the same cloned account but no slot reports no present slot.
    let mut slotless = ResourceRegistry::new();
    admit_without_slot(&mut slotless, &subject, owner);
    let absent = slotless.confirm_association(&carrier, &own);
    assert!(!absent.slot_present());
    assert!(!absent.is_associated());
    assert!(absent.provenance());
    assert!(absent.kind());
    assert!(absent.owner_current());
    assert!(absent.lease_admitted());
    assert!(!absent.cancellation_requested());
    assert!(absent.dispatch_eligible());

    // A machine admission lease that stopped admitting work is reported as not admitted.
    Arc::clone(&subject.admission_open)
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .pending = false;
    let closed = registry.confirm_association(&carrier, &own);
    assert!(!closed.lease_admitted());
    assert!(!closed.cancellation_requested());
    assert!(!closed.is_associated());
    Arc::clone(&subject.admission_open)
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .pending = true;

    // A bound adapter without authenticated recovery metadata is not dispatch eligible.
    let receiver = TypeExpression::from_canonical_string("crate::AssociationAdapter", 4)
        .unwrap_or_else(|error| panic!("receiver: {error:?}"));
    let adapter = AdapterInstance::bind(
        &CanonicalImplementationIdentity::inherent(&receiver),
        RightsSet::from_rights(&[AuthorityRight::Observe]),
        owner,
        0,
    );
    registry
        .bind_adapter_instance(&subject, owner, adapter)
        .unwrap_or_else(|error| panic!("bind adapter: {error:?}"));
    let ineligible = registry.confirm_association(&carrier, &own);
    assert!(!ineligible.dispatch_eligible());
    assert!(!ineligible.is_associated());
    assert!(ineligible.slot_present());
    assert!(ineligible.provenance());
    assert!(ineligible.lease_admitted());
}
