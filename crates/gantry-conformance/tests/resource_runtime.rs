//! Machine-checked conformance for the runtime admission of Section 28 resource facts.
//!
//! These rows exercise the runtime's admission boundary only: which declared carrier
//! may present a resource's accounting facts, what an admitted account preserves, and
//! how semantic release stays independent of record retirement. They perform no
//! durable I/O and claim no journal, checkpoint, evaluator, or host behavior.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use gantry::identity::ProtocolIdentity;
use gantry::ir::generated::{OperationSiteKind, RecoveryClass};
use gantry::ir::{
    AdapterInstance, CanonicalImplementationIdentity, ForeignFailureKind, OperationAbiError,
    PoisonReason, RightsSet, TypeExpression,
};
use gantry::ir::{
    CanonicalPath, CanonicalSignature, Charge, Completion, ContainmentError, DurableResourceRecord,
    EffectSet, EffectState, EmergencyCleanupWitness, ExecutableAction, ExecutableOperation,
    ExternalOutcome, FailureClass, GracePolicy, LivenessRoot, MalformedCompletion, OperationAbi,
    OperationKind, OwnerGeneration, PoisonWitness, PostFailureSettlement, Quota, QuotaFamily,
    QuotaOwner, ReceiverOwnership, ResourceAction, ResourceCarrier, ResourceError, ResourceLedger,
    ResourceLifetimeState, ResourceState, RetentionFence, StaticSiteId, StopCause, StopCoordinator,
    StopRequest, StructuralPosition, TaskStopState, TypeDescriptor,
};
use gantry::portable::IdentityKind;
use gantry::runtime::AdapterBindingRefusal;
use gantry::runtime::CohortEmergencySettlement;
use gantry::runtime::{
    AdmittedResource, ExecutionBudget, Instruction, InstructionKind, Machine, MachineCheckpointV3,
    MachineLabel, MachineLimits, MachineProgram, MachineStep, PostFailureSettlementRefusal,
    RecoveredResourceRecord, ResourceRegistry, ResourceRegistryRefusal, ResourceSubjectBinding,
    Workflow,
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
const UNAUTHENTICATED_FIXTURE_DECLARATION: &str =
    "crate::resource_runtime_unauthenticated_metadata";
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
    declared_subject(FIXTURE_DECLARATION)
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
        registry.settle_from_post_failure(&settlement, 21),
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
        registry.settle_from_post_failure(&settlement, 21),
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

/// The containment settlement is runtime state of one admitted account value, not a declared durable
/// fact: a subject rebuilt from its declared capture, and the same subject readmitted after physical
/// reclamation, each hold a fresh unsettled settlement, so the runtime publishes no cross-recovery
/// single-settlement claim.
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

    let mut reclaimed = ResourceRegistry::new();
    reclaimed
        .admit(
            subject.clone(),
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
        )
        .unwrap_or_else(|error| {
            panic!("the declared reconstruction record is admitted: {error:?}")
        });
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
    reclaimed
        .admit(
            subject.clone(),
            ResourceCarrier::ReconstructionRecord,
            ledger().durable_record(),
        )
        .unwrap_or_else(|error| panic!("the reclaimed subject is readmitted: {error:?}"));
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

    let held_spelling = registry
        .adapter_instance(&subject)
        .map(AdapterInstance::as_str)
        .map(str::to_owned);

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
        registry
            .adapter_instance(&subject)
            .map(AdapterInstance::as_str)
            .map(str::to_owned),
        held_spelling,
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

    let mut partial = ResourceRegistry::new();
    for subject in [&first, &second] {
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
    let unknown = unauthenticated_fixture_subject(UNAUTHENTICATED_FIXTURE_DECLARATION);
    let swept = partial.settle_cohort_from_emergency_cleanup(vec![
        (second.clone(), emergency_cleanup()),
        (unknown.clone(), emergency_cleanup()),
        (first.clone(), emergency_cleanup()),
    ]);
    assert!(!swept.is_complete());
    assert!(matches!(
        swept.refusal(),
        Some((subject, ResourceRegistryRefusal::UnknownSubject))
            if subject.operation() == unknown.operation()
    ));
    let unknown_key = (unknown.operation().clone(), unknown.generation().clone());
    let prefix = [&first, &second]
        .into_iter()
        .filter(|subject| {
            (subject.operation(), subject.generation()) < (&unknown_key.0, &unknown_key.1)
        })
        .count();
    assert_eq!(
        swept.settled().len(),
        prefix,
        "exactly the accounts sorting before the unknown subject settle"
    );
    assert!(
        swept
            .settled()
            .iter()
            .all(|settlement| settlement.lifetime() == ResourceLifetimeState::EmergencyReleased)
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
    "settle_from_emergency_cleanup",
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
        "The two failure routes are fenced differently and are not owner-qualified",
        "are additionally owner-qualified",
        "a superseded generation is refused before any declared fact changes",
        "Physical reclamation is the one registry-wide mutating route and changes no declared fact",
        "No public route hands out a mutable registry-held account",
        "the private subject-binding constructor",
        "the removed raw ledger accessor",
        "one witness settles exactly one account",
    ] {
        assert!(
            flattened.contains(&flatten(statement)),
            "the reader note must state: {statement}"
        );
    }
}
