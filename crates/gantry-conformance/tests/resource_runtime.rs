//! Machine-checked conformance for the runtime admission of Section 28 resource facts.
//!
//! These rows exercise the runtime's admission boundary only: which declared carrier
//! may present a resource's accounting facts, what an admitted account preserves, and
//! how semantic release stays independent of record retirement. They perform no
//! durable I/O and claim no journal, checkpoint, evaluator, or host behavior.

use std::sync::Arc;

use gantry::identity::ProtocolIdentity;
use gantry::ir::generated::{OperationSiteKind, RecoveryClass};
use gantry::ir::{
    CanonicalPath, CanonicalSignature, Charge, DurableResourceRecord, EffectSet,
    EmergencyCleanupWitness, ExecutableAction, ExecutableOperation, FailureClass, GracePolicy,
    LivenessRoot, OperationAbi, OperationKind, OwnerGeneration, PostFailureSettlement, Quota,
    QuotaFamily, QuotaOwner, ReceiverOwnership, ResourceAction, ResourceCarrier, ResourceError,
    ResourceLedger, ResourceLifetimeState, ResourceState, RetentionFence, StaticSiteId, StopCause,
    StopCoordinator, StopRequest, StructuralPosition, TaskStopState, TypeDescriptor,
};
use gantry::portable::IdentityKind;
use gantry::runtime::{
    AdmittedResource, ExecutionBudget, Instruction, InstructionKind, Machine, MachineCheckpointV3,
    MachineLabel, MachineLimits, MachineProgram, MachineStep, PostFailureSettlementRefusal,
    ResourceRegistry, ResourceRegistryRefusal, ResourceSubjectBinding, Workflow,
};
use gantry::value::DEFAULT_VALUE_LIMITS;

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
) -> Result<AdmittedResource, ResourceRegistryRefusal> {
    AdmittedResource::admit(carrier, record, subject)
}

const FIXTURE_WORKFLOW: &str = "crate::main";
const FIXTURE_DECLARATION: &str = "crate::resource_runtime_metadata";
const SECOND_FIXTURE_DECLARATION: &str = "crate::resource_runtime_second_metadata";
const FIXTURE_SITE: u64 = 45;

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
        registry.settle_from_post_failure(&matching, 21),
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
    {
        let account = registry
            .account_mut(&subject)
            .unwrap_or_else(|| panic!("the registry holds the admitted account"));
        assert!(account.ledger_mut().begin_finish().is_ok());
    }
    assert_eq!(
        registry.live_resources(),
        1,
        "a finishing lifetime is still live"
    );
    {
        let account = registry
            .account_mut(&subject)
            .unwrap_or_else(|| panic!("the registry holds the admitted account"));
        assert!(account.ledger_mut().finish(20).is_ok());
    }
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
    {
        let account = registry
            .account_mut(&subject)
            .unwrap_or_else(|| panic!("the registry holds the admitted account"));
        for root in ROOTS {
            assert!(account.ledger_mut().close_liveness_root(*root).is_ok());
        }
        assert!(
            account
                .ledger_mut()
                .retire(fence, OwnerGeneration::new(4), OwnerGeneration::new(5), 35)
                .is_ok()
        );
        assert_eq!(account.ledger().lifetime(), ResourceLifetimeState::Retired);
    }
    assert_eq!(
        registry.live_resources(),
        0,
        "retirement never reclaims the released place"
    );
    {
        let account = registry
            .account_mut(&subject)
            .unwrap_or_else(|| panic!("the registry holds the admitted account"));
        assert!(account.ledger_mut().delete().is_ok());
        assert_eq!(account.ledger().lifetime(), ResourceLifetimeState::Deleted);
    }
    assert_eq!(
        registry.live_resources(),
        0,
        "deletion never reclaims the released place"
    );
    assert!(
        registry.account(&subject).is_some(),
        "a deleted account stays registry-held until it is reaped"
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
    let (_program, _machine, subject) = machine_with_declared_subject(Some(FIXTURE_DECLARATION));
    subject.unwrap_or_else(|| panic!("the fixture operation declares an action"))
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
        registry.settle_from_post_failure(&foreign, 21),
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
        registry.settle_from_post_failure(&matching, 21),
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

    assert_eq!(
        registry.settle_from_post_failure(&matching, 22),
        Err(ResourceRegistryRefusal::Settlement(
            PostFailureSettlementRefusal::Model(ResourceError::IllegalLifetimeTransition)
        ))
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
