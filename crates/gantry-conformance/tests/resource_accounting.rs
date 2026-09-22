//! Machine-checked conformance for the pure Section 28 resource-accounting model.
//!
//! The tests use declared measures, owner generations, quotas, roots, and logical
//! instants only. They neither create runtime resources nor claim evaluator, journal,
//! checkpoint, or host integration.

use std::fs;
use std::path::Path;

use gantry::ir::generated::RecoveryClass;
use gantry::ir::{
    CanonicalPath, Charge, EmergencyReleaseWitness, FailureClass, GracePolicy, LivenessRoot,
    LogicalMeasure, OperationAbi, OperationKind, OwnerGeneration, PoisonWitness, Quota,
    QuotaFamily, QuotaOwner, RESOURCE_CLAUSES, ReceiverOwnership, ResourceAction, ResourceError,
    ResourceLedger, ResourceLifetimeState, ResourceState, RetentionFence, StaticSiteId, StopCause,
    StopCoordinator, StopError, StopRequest, StructuralPosition, TaskStopState,
};

#[test]
fn application_fuel_is_not_a_resource_quota_family() {
    let grant = gantry::ir::FuelGrant::new(2, 1, OwnerGeneration::new(4))
        .unwrap_or_else(|_| panic!("finite fuel grant"));
    assert_eq!(grant.remaining(), 2);
    assert!(
        !QuotaFamily::ALL
            .into_iter()
            .map(QuotaFamily::wire_name)
            .any(|family| family == "fuel")
    );
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

fn refusal<T>(result: Result<T, ResourceError>) -> ResourceError {
    result.unwrap_err_or_else()
}

trait Refusal<T> {
    fn unwrap_err_or_else(self) -> ResourceError;
}

impl<T> Refusal<T> for Result<T, ResourceError> {
    fn unwrap_err_or_else(self) -> ResourceError {
        match self {
            Ok(_) => panic!("the declared operation must be refused"),
            Err(error) => error,
        }
    }
}

fn close_all_roots(ledger: &mut ResourceLedger) {
    for root in ROOTS {
        assert!(ledger.close_liveness_root(*root).is_ok());
    }
}

fn finished_ledger() -> ResourceLedger {
    let mut ledger = ledger();
    assert!(ledger.begin_finish().is_ok());
    assert!(ledger.finish(20).is_ok());
    ledger
}

fn failure_settlement(failure: FailureClass) -> gantry::ir::PostFailureSettlement {
    let path = CanonicalPath::new("crate::resource_accounting")
        .unwrap_or_else(|_| unreachable!("fixture path is canonical"));
    let position = StructuralPosition::new(vec![28, 4])
        .unwrap_or_else(|_| unreachable!("fixture position is canonical"));
    let site = StaticSiteId::new(path.clone(), position);
    let operation = OperationAbi::new(
        OperationKind::LiveResource,
        &path,
        &site,
        1,
        RecoveryClass::Idempotent,
        ReceiverOwnership::RetainedByCaller,
    )
    .unwrap_or_else(|_| unreachable!("fixture operation is admissible"));
    operation.settle_failure(failure)
}

fn poison_witness() -> PoisonWitness {
    PoisonWitness::from_post_failure(&failure_settlement(FailureClass::ResourceFailure), 21)
        .unwrap_or_else(|_| unreachable!("resource failure derives a poison witness"))
}

fn emergency_release_witness() -> EmergencyReleaseWitness {
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
    EmergencyReleaseWitness::from_cleanup(escalation.admit_emergency_release())
}

#[test]
fn terminal_witnesses_are_derived_from_closed_failure_and_cancellation_facts() {
    assert!(matches!(
        PoisonWitness::from_post_failure(&failure_settlement(FailureClass::AdapterFailure), 21),
        Err(ResourceError::FailureDoesNotPoisonResource)
    ));

    let mut poisoned = ledger();
    assert!(poisoned.poison(poison_witness()).is_ok());
    assert_eq!(poisoned.lifetime(), ResourceLifetimeState::Poisoned);

    let mut coordinator = StopCoordinator::new();
    let mut tasks: [TaskStopState; 0] = [];
    assert_eq!(
        coordinator.escalate(&mut tasks, 21),
        Err(StopError::EscalationWithoutStopRequest),
        "a caller cannot obtain an emergency-release witness before hard cancellation"
    );
    let mut emergency_released = ledger();
    assert!(
        emergency_released
            .emergency_release(emergency_release_witness())
            .is_ok()
    );
    assert_eq!(
        emergency_released.lifetime(),
        ResourceLifetimeState::EmergencyReleased
    );
}

#[test]
fn section_scope_has_closed_roots_measures_actions_and_quota_families() {
    assert_eq!(RESOURCE_CLAUSES.len(), 11);
    assert_eq!(
        LivenessRoot::ALL.map(LivenessRoot::wire_name),
        ["durable-record", "loan", "owner", "resource"]
    );
    assert_eq!(
        LogicalMeasure::ALL.map(LogicalMeasure::wire_name),
        ["bytes", "handles", "operations"]
    );
    assert_eq!(
        ResourceAction::ALL.map(ResourceAction::wire_name),
        ["copy", "loan", "move", "release", "update"]
    );
    for root in LivenessRoot::ALL {
        assert_eq!(LivenessRoot::from_wire_name(root.wire_name()), Some(root));
    }
    assert_eq!(LivenessRoot::from_wire_name("ambient"), None);
    assert_eq!(LogicalMeasure::from_wire_name("allocation"), None);
    assert_eq!(QuotaFamily::Bytes.measure(), LogicalMeasure::Bytes);
}

#[test]
fn charges_are_atomic_and_require_the_current_owner_witness() {
    let mut ledger = ledger();
    let charge = Charge {
        owner: QuotaOwner::Owner,
        family: QuotaFamily::Bytes,
        amount: 8,
    };
    assert_eq!(
        refusal(ledger.charge(OwnerGeneration::new(3), ResourceAction::Copy, &[charge])),
        ResourceError::StaleOwner {
            presented: OwnerGeneration::new(3),
            current: OwnerGeneration::new(4),
        }
    );
    assert!(
        ledger
            .charge(OwnerGeneration::new(4), ResourceAction::Copy, &[charge])
            .is_ok()
    );
    assert_eq!(
        ledger
            .quota(QuotaOwner::Owner, QuotaFamily::Bytes)
            .map(Quota::used),
        Some(8)
    );
    assert_eq!(
        refusal(ledger.charge(
            OwnerGeneration::new(4),
            ResourceAction::Update,
            &[
                Charge {
                    owner: QuotaOwner::Owner,
                    family: QuotaFamily::Bytes,
                    amount: 1
                },
                Charge {
                    owner: QuotaOwner::Resource,
                    family: QuotaFamily::Handles,
                    amount: 1
                },
            ],
        )),
        ResourceError::QuotaExhausted
    );
    assert_eq!(
        ledger
            .quota(QuotaOwner::Resource, QuotaFamily::Handles)
            .map(Quota::used),
        Some(0)
    );
}

#[test]
fn renewal_requires_the_current_owner_and_an_active_lifetime() {
    let mut ledger = ledger();
    assert_eq!(
        refusal(ledger.renew(
            OwnerGeneration::new(3),
            QuotaOwner::Owner,
            QuotaFamily::Bytes,
            4,
        )),
        ResourceError::StaleOwner {
            presented: OwnerGeneration::new(3),
            current: OwnerGeneration::new(4),
        }
    );
    assert!(
        ledger
            .renew(
                OwnerGeneration::new(4),
                QuotaOwner::Owner,
                QuotaFamily::Bytes,
                4,
            )
            .is_ok()
    );
    assert_eq!(
        ledger
            .quota(QuotaOwner::Owner, QuotaFamily::Bytes)
            .map(Quota::limit),
        Some(12)
    );
    assert!(ledger.begin_finish().is_ok());
    assert!(matches!(
        refusal(ledger.renew(
            OwnerGeneration::new(4),
            QuotaOwner::Owner,
            QuotaFamily::Bytes,
            1,
        )),
        ResourceError::LifetimeDoesNotAdmitCharge {
            state: ResourceLifetimeState::Finishing,
        }
    ));
}

#[test]
fn retirement_requires_settlement_current_owner_closed_roots_and_stores_fence() {
    let fence = RetentionFence::new(1, 10).unwrap_or_else(|_| unreachable!("bounded"));
    let mut active = ledger();
    assert_eq!(
        refusal(active.retire(fence, OwnerGeneration::new(4), OwnerGeneration::new(6), 100)),
        ResourceError::IllegalLifetimeTransition
    );
    assert!(active.begin_finish().is_ok());
    assert_eq!(
        refusal(active.retire(fence, OwnerGeneration::new(4), OwnerGeneration::new(6), 100)),
        ResourceError::IllegalLifetimeTransition,
        "retirement refuses an unsettled finishing lifetime"
    );

    let mut settled = finished_ledger();
    assert_eq!(
        refusal(settled.retire(fence, OwnerGeneration::new(3), OwnerGeneration::new(6), 100)),
        ResourceError::StaleOwner {
            presented: OwnerGeneration::new(3),
            current: OwnerGeneration::new(4)
        },
        "elapsed logical time cannot admit a stale lower owner"
    );
    assert_eq!(
        refusal(settled.retire(fence, OwnerGeneration::new(4), OwnerGeneration::new(6), 100)),
        ResourceError::LivenessRootsRemain
    );
    close_all_roots(&mut settled);
    assert!(
        settled
            .retire(fence, OwnerGeneration::new(4), OwnerGeneration::new(6), 100)
            .is_ok()
    );
    assert_eq!(settled.lifetime(), ResourceLifetimeState::Retired);
    assert_eq!(settled.successor_fence(), Some(OwnerGeneration::new(6)));
    assert_eq!(
        settled.settlement().map(|baseline| baseline.settled_at()),
        Some(20)
    );
    assert_eq!(
        ResourceLedger::reconstruct(settled.durable_record()),
        settled
    );
    assert!(settled.delete().is_ok());
}

#[test]
fn roots_and_quota_facts_survive_or_refuse_pure_compaction() {
    let mut ledger = ledger();
    assert!(
        ledger
            .charge(
                OwnerGeneration::new(4),
                ResourceAction::Loan,
                &[Charge {
                    owner: QuotaOwner::Resource,
                    family: QuotaFamily::Operations,
                    amount: 1
                }],
            )
            .is_ok()
    );
    let durable = ledger.durable_record();
    assert!(ledger.validate_compaction(&durable).is_ok());
    assert_eq!(
        ResourceLedger::reconstruct(durable.clone())
            .quota(QuotaOwner::Resource, QuotaFamily::Operations)
            .map(Quota::used),
        Some(1),
        "compaction retains committed logical quota facts"
    );
    assert_eq!(
        refusal(ledger.validate_compaction(&durable.with_liveness_roots(&[LivenessRoot::Owner]))),
        ResourceError::CompactionDoesNotPreserve
    );
}

#[test]
fn terminal_lifetime_transitions_are_refused_and_cannot_reopen() {
    for mut terminal in [
        finished_ledger(),
        {
            let mut ledger = ledger();
            assert!(ledger.poison(poison_witness()).is_ok());
            ledger
        },
        {
            let mut ledger = ledger();
            assert!(
                ledger
                    .emergency_release(emergency_release_witness())
                    .is_ok()
            );
            ledger
        },
    ] {
        for error in [
            refusal(terminal.begin_finish()),
            refusal(terminal.finish(30)),
            refusal(terminal.poison(poison_witness())),
            refusal(terminal.emergency_release(emergency_release_witness())),
        ] {
            assert_eq!(error, ResourceError::IllegalLifetimeTransition);
        }
        assert!(matches!(
            refusal(terminal.renew(
                OwnerGeneration::new(4),
                QuotaOwner::Owner,
                QuotaFamily::Bytes,
                1
            )),
            ResourceError::LifetimeDoesNotAdmitCharge { .. }
        ));
    }

    let mut retired = finished_ledger();
    close_all_roots(&mut retired);
    assert!(
        retired
            .retire(
                RetentionFence::new(1, 1).unwrap_or_else(|_| unreachable!("bounded")),
                OwnerGeneration::new(4),
                OwnerGeneration::new(6),
                30,
            )
            .is_ok()
    );
    assert_eq!(
        refusal(retired.begin_finish()),
        ResourceError::IllegalLifetimeTransition
    );
    assert_eq!(
        refusal(retired.finish(31)),
        ResourceError::IllegalLifetimeTransition
    );
    assert_eq!(
        refusal(retired.poison(poison_witness())),
        ResourceError::IllegalLifetimeTransition
    );
    assert_eq!(
        refusal(retired.emergency_release(emergency_release_witness())),
        ResourceError::IllegalLifetimeTransition
    );
    assert!(retired.delete().is_ok());
    for error in [
        refusal(retired.begin_finish()),
        refusal(retired.finish(32)),
        refusal(retired.poison(poison_witness())),
        refusal(retired.emergency_release(emergency_release_witness())),
        refusal(retired.delete()),
    ] {
        assert_eq!(error, ResourceError::IllegalLifetimeTransition);
    }
    assert_eq!(
        RetentionFence::new(0, 0),
        Err(ResourceError::UnboundedRetention)
    );
}

#[test]
fn terminal_transition_matrix_refuses_delete_retire_and_charge() {
    let charge = [Charge {
        owner: QuotaOwner::Owner,
        family: QuotaFamily::Bytes,
        amount: 1,
    }];
    for mut terminal in [
        finished_ledger(),
        {
            let mut ledger = ledger();
            assert!(ledger.poison(poison_witness()).is_ok());
            ledger
        },
        {
            let mut ledger = ledger();
            assert!(
                ledger
                    .emergency_release(emergency_release_witness())
                    .is_ok()
            );
            ledger
        },
    ] {
        assert_eq!(
            refusal(terminal.delete()),
            ResourceError::IllegalLifetimeTransition
        );
        assert_eq!(
            refusal(terminal.charge(OwnerGeneration::new(4), ResourceAction::Copy, &charge)),
            ResourceError::LifetimeDoesNotAdmitCharge {
                state: terminal.lifetime(),
            }
        );
    }

    let mut retired = finished_ledger();
    close_all_roots(&mut retired);
    assert!(
        retired
            .retire(
                RetentionFence::new(1, 1).unwrap_or_else(|_| unreachable!("bounded")),
                OwnerGeneration::new(4),
                OwnerGeneration::new(6),
                30,
            )
            .is_ok()
    );
    assert_eq!(
        refusal(retired.retire(
            RetentionFence::new(1, 1).unwrap_or_else(|_| unreachable!("bounded")),
            OwnerGeneration::new(4),
            OwnerGeneration::new(7),
            31,
        )),
        ResourceError::IllegalLifetimeTransition
    );
    assert_eq!(
        refusal(retired.charge(OwnerGeneration::new(4), ResourceAction::Copy, &charge)),
        ResourceError::LifetimeDoesNotAdmitCharge {
            state: ResourceLifetimeState::Retired,
        }
    );
    assert!(retired.delete().is_ok());
    assert_eq!(
        refusal(retired.retire(
            RetentionFence::new(1, 1).unwrap_or_else(|_| unreachable!("bounded")),
            OwnerGeneration::new(4),
            OwnerGeneration::new(7),
            32,
        )),
        ResourceError::IllegalLifetimeTransition
    );
    assert_eq!(
        refusal(retired.charge(OwnerGeneration::new(4), ResourceAction::Copy, &charge)),
        ResourceError::LifetimeDoesNotAdmitCharge {
            state: ResourceLifetimeState::Deleted,
        }
    );
}

#[test]
fn resource_model_note_is_current() {
    let note = read_note();
    assert_eq!(
        sorted_members(section_members(&note, "## Clauses")),
        sorted_members(
            RESOURCE_CLAUSES
                .iter()
                .map(|clause| (*clause).to_owned())
                .collect()
        )
    );
    for (heading, expected) in [
        (
            "## Liveness roots",
            LivenessRoot::ALL
                .map(|root| root.wire_name().to_owned())
                .to_vec(),
        ),
        (
            "## Logical measures",
            LogicalMeasure::ALL
                .map(|measure| measure.wire_name().to_owned())
                .to_vec(),
        ),
        (
            "## Quota families",
            QuotaFamily::ALL
                .map(|family| family.wire_name().to_owned())
                .to_vec(),
        ),
        (
            "## Quota owners",
            QuotaOwner::ALL
                .map(|owner| owner.wire_name().to_owned())
                .to_vec(),
        ),
        (
            "## Resource actions",
            ResourceAction::ALL
                .map(|action| action.wire_name().to_owned())
                .to_vec(),
        ),
    ] {
        assert_eq!(
            sorted_members(section_members(&note, heading)),
            sorted_members(expected),
            "{heading} names exactly the live members"
        );
    }
}

/// Returns the backticked members one note section declares as its bullets, with multiplicity.
fn section_members(note: &str, heading: &str) -> Vec<String> {
    let mut members = Vec::new();
    let mut in_section = false;
    for line in note.lines() {
        if line.starts_with("## ") {
            in_section = line.trim_end() == heading;
            continue;
        }
        if !in_section || !line.starts_with("- ") {
            continue;
        }
        for (index, part) in line.split('`').enumerate() {
            if index % 2 == 1 && !part.is_empty() {
                members.push(part.to_owned());
            }
        }
    }
    members
}

/// Returns the collected members in canonical order, preserving any duplication.
fn sorted_members(mut members: Vec<String>) -> Vec<String> {
    members.sort_unstable();
    members
}

/// Returns the committed Section 28 resource-model note.
fn read_note() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/resource-model.md");
    fs::read_to_string(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}
