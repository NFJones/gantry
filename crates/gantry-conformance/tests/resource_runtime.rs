//! Machine-checked conformance for the runtime admission of Section 28 resource facts.
//!
//! These rows exercise the runtime's admission boundary only: which declared carrier
//! may present a resource's accounting facts, what an admitted account preserves, and
//! how semantic release stays independent of record retirement. They perform no
//! durable I/O and claim no journal, checkpoint, evaluator, or host behavior.

use gantry::ir::generated::RecoveryClass;
use gantry::ir::{
    CanonicalPath, Charge, DurableResourceRecord, EmergencyCleanupWitness, FailureClass,
    GracePolicy, LivenessRoot, OperationAbi, OperationKind, OwnerGeneration, PostFailureSettlement,
    Quota, QuotaFamily, QuotaOwner, ReceiverOwnership, ResourceAction, ResourceCarrier,
    ResourceError, ResourceLedger, ResourceLifetimeState, ResourceState, RetentionFence,
    StaticSiteId, StopCause, StopCoordinator, StopRequest, StructuralPosition, TaskStopState,
};
use gantry::runtime::{AdmittedResource, PostFailureSettlementRefusal, ResourceSubjectBinding};

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
    ResourceLedger::new(
        OwnerGeneration::new(4),
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
) -> Result<AdmittedResource, ResourceError> {
    AdmittedResource::admit(carrier, record, subject)
}

/// Derives the runtime subject of one fixture declaration and runtime generation.
fn active_subject_at(declaration: &str, generation: u64) -> ResourceSubjectBinding {
    let path = CanonicalPath::new(declaration)
        .unwrap_or_else(|_| unreachable!("fixture path is canonical"));
    let position = StructuralPosition::new(vec![45, 1])
        .unwrap_or_else(|_| unreachable!("fixture position is canonical"));
    ResourceSubjectBinding::derive(&path, path.clone(), position, generation)
}

fn active_subject() -> ResourceSubjectBinding {
    active_subject_at("crate::resource_runtime", 1)
}

/// Issues one model settlement for one fixture declaration, site, generation, and failure class.
fn failure_settlement_at(
    declaration: &str,
    position: Vec<u64>,
    generation: u64,
    failure: FailureClass,
) -> PostFailureSettlement {
    let path = CanonicalPath::new(declaration)
        .unwrap_or_else(|_| unreachable!("fixture path is canonical"));
    let position = StructuralPosition::new(position)
        .unwrap_or_else(|_| unreachable!("fixture position is canonical"));
    let site = StaticSiteId::new(path.clone(), position);
    let operation = OperationAbi::new(
        OperationKind::LiveResource,
        &path,
        &site,
        generation,
        RecoveryClass::Idempotent,
        ReceiverOwnership::RetainedByCaller,
    )
    .unwrap_or_else(|_| unreachable!("fixture operation is admissible"));
    operation.settle_failure(failure)
}

fn admitted_active() -> AdmittedResource {
    admitted(
        ResourceCarrier::ReconstructionRecord,
        ledger().durable_record(),
        active_subject(),
    )
    .unwrap_or_else(|error| panic!("the declared reconstruction record is admitted: {error:?}"))
}

#[test]
fn the_admitted_account_is_not_copyable() {
    assert_not_impl_any!(AdmittedResource: Clone, Copy);
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
                    ResourceError::OrdinaryCarrierRefused,
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

    assert!(admitted_resource.ledger_mut().begin_finish().is_ok());
    assert!(admitted_resource.ledger_mut().finish(20).is_ok());
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
        admitted_resource.ledger_mut().retire(
            fence,
            OwnerGeneration::new(4),
            OwnerGeneration::new(5),
            35,
        ),
        Err(ResourceError::LivenessRootsRemain)
    );
    assert_eq!(admitted_resource.ledger(), &released);

    for root in ROOTS {
        assert!(
            admitted_resource
                .ledger_mut()
                .close_liveness_root(*root)
                .is_ok()
        );
    }
    let roots_closed = admitted_resource.ledger().clone();
    assert_eq!(
        admitted_resource.ledger_mut().retire(
            fence,
            OwnerGeneration::new(4),
            OwnerGeneration::new(5),
            25,
        ),
        Err(ResourceError::RetentionNotExpired)
    );
    assert_eq!(admitted_resource.ledger(), &roots_closed);

    assert!(
        admitted_resource
            .ledger_mut()
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
    assert!(admitted_resource.ledger_mut().delete().is_ok());
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
        admitted_resource.ledger_mut().charge(
            OwnerGeneration::new(5),
            ResourceAction::Move,
            &charges,
        ),
        Err(ResourceError::StaleOwner {
            presented: OwnerGeneration::new(5),
            current: OwnerGeneration::new(4),
        })
    );
    assert_eq!(admitted_resource.ledger(), &before);
    assert!(
        admitted_resource
            .ledger_mut()
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
        admitted_resource.ledger_mut().charge(
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
        admitted_resource.ledger_mut().charge(
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

fn emergency_cleanup() -> EmergencyCleanupWitness {
    let policy =
        GracePolicy::new(1, 1).unwrap_or_else(|_| unreachable!("fixture stop policy is bounded"));
    let mut coordinator = StopCoordinator::new();
    assert!(
        coordinator
            .request_stop(StopRequest::new(StopCause::OperatorSignal, policy, 20))
            .is_ok()
    );
    let mut tasks: [TaskStopState; 0] = [];
    let escalation = coordinator
        .escalate(&mut tasks, 21)
        .unwrap_or_else(|_| unreachable!("held stop request escalates at its deadline"));
    escalation.admit_emergency_release()
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
        admitted_resource.ledger_mut().charge(
            OwnerGeneration::new(4),
            ResourceAction::Update,
            &charges,
        ),
        Err(ResourceError::LifetimeDoesNotAdmitCharge { .. })
    ));
}

#[test]
fn runtime_finalization_completion_requires_the_finishing_phase() {
    let mut admitted_resource = admitted_active();
    assert_eq!(
        admitted_resource.complete_finalization(20),
        Err(ResourceError::IllegalLifetimeTransition)
    );
    assert!(admitted_resource.ledger_mut().begin_finish().is_ok());
    assert_eq!(
        admitted_resource.complete_finalization(20),
        Ok(ResourceLifetimeState::Finished)
    );
    assert_eq!(
        admitted_resource.complete_finalization(21),
        Err(ResourceError::IllegalLifetimeTransition)
    );
}

#[test]
fn runtime_post_failure_settlement_is_bound_to_the_admitted_subject() {
    let mut admitted_resource = admitted_active();
    let before = admitted_resource.ledger().clone();

    let foreign = failure_settlement_at(
        "crate::resource_runtime_foreign",
        vec![45, 1],
        1,
        FailureClass::ResourceFailure,
    );
    assert_eq!(
        admitted_resource.settle_from_post_failure(&foreign, 21),
        Err(PostFailureSettlementRefusal::ForeignOperation)
    );
    assert_eq!(admitted_resource.ledger(), &before);

    let stale = failure_settlement_at(
        "crate::resource_runtime",
        vec![45, 1],
        2,
        FailureClass::ResourceFailure,
    );
    assert_eq!(
        admitted_resource.settle_from_post_failure(&stale, 21),
        Err(PostFailureSettlementRefusal::StaleGeneration)
    );
    assert_eq!(admitted_resource.ledger(), &before);

    let non_poisoning = failure_settlement_at(
        "crate::resource_runtime",
        vec![45, 1],
        1,
        FailureClass::AdapterFailure,
    );
    assert_eq!(
        admitted_resource.settle_from_post_failure(&non_poisoning, 21),
        Err(PostFailureSettlementRefusal::Model(
            ResourceError::FailureDoesNotPoisonResource
        ))
    );
    assert_eq!(admitted_resource.ledger(), &before);

    let settlement = failure_settlement_at(
        "crate::resource_runtime",
        vec![45, 1],
        1,
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
