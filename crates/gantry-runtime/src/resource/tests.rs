//! Storage reclamation and account-qualified adapter dispatch regressions.

use super::*;

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
