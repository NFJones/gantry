//! Machine-checked conformance for the cooperative-stop and hard-cancellation
//! model of `SPEC.md` Section 22, clauses `GNT-22.0` .. `GNT-22.10`.
//!
//! These tests exercise the public `gantry::ir` surface of the landed stop model:
//! `GNT-22.0-cooperative-stop-and-hard-cancellation`,
//! `GNT-22.1-stop-request-identity-and-cause`,
//! `GNT-22.2-cooperative-stop-observation-and-propagation`,
//! `GNT-22.3-admission-closure-during-stop`,
//! `GNT-22.4-safe-points-and-suspension`,
//! `GNT-22.5-grace-and-drain-ownership`,
//! `GNT-22.6-grace-expiry-and-hard-cancellation`,
//! `GNT-22.7-outcome-winner-and-single-publication`,
//! `GNT-22.8-durable-stop-cuts-and-replay`,
//! `GNT-22.9-late-result-and-stale-generation-fencing`, and
//! `GNT-22.10-stop-non-claims`.
//!
//! Every test is a pure function of its own arguments: no test reads a clock, a
//! process identifier, a signal number, a host path, or an environment fact, and no
//! test spawns a thread or waits on a handle. Stop instants are explicit logical
//! microseconds, so every verdict here is reproducible from its own inputs.

use std::collections::BTreeSet;
use std::sync::Arc;

use gantry::ir::{
    AdmittedWork, DurableStopCut, EscalatedWork, GracePolicy, LIFECYCLE_STOP_CLAUSES,
    LateResultFence, OwnerGeneration, STOP_NON_CLAIM_ORDER, STOP_NON_CLAIMS, SafePoint, StopCause,
    StopCauseClass, StopCoordinator, StopCrashCutClassification, StopDiagnosticCode, StopError,
    StopNonClaimName, StopRequest, StopRequestJoin, StopState, StopTransition, TaskOutcome,
    TaskResult, TaskStopState,
};

/// Declares one positive grace and drain budget.
///
/// Every call below declares nonzero budgets, so a refusal would mean the model no
/// longer accepts a declared policy; the refusal is reported rather than folded away.
fn policy(grace_us: u64, drain_us: u64) -> GracePolicy {
    match GracePolicy::new(grace_us, drain_us) {
        Ok(policy) => policy,
        Err(error) => unreachable!("nonzero grace and drain declare a policy, not {error}"),
    }
}

/// Builds one arriving result that carries a domain outcome.
///
/// Escalation is refused by [`TaskResult::new`], so it is never built here.
fn result(outcome: TaskOutcome, generation: OwnerGeneration, at_us: u64) -> TaskResult {
    match TaskResult::new(outcome, generation, at_us) {
        Ok(result) => result,
        Err(error) => unreachable!("a domain outcome is an admissible result, not {error}"),
    }
}

/// Returns every frozen diagnostic code owned by one clause key, in registry order.
fn members_of_clause(clause: &str) -> Vec<StopDiagnosticCode> {
    StopDiagnosticCode::ALL
        .into_iter()
        .filter(|code| code.requirement() == clause)
        .collect()
}

/// `GNT-22.1`: a request identity is derived from the declared cause, grace, drain,
/// and instant over a closed cause-class vocabulary.
#[test]
fn stop_request_identity_is_derived_from_declared_fields_and_closed_cause_vocabulary() {
    let declared = policy(1_000, 500);
    let request = StopRequest::new(StopCause::OperatorSignal, declared, 10);
    let same = StopRequest::new(StopCause::OperatorSignal, declared, 10);

    assert_eq!(request.id(), same.id());
    assert_eq!(request.id().as_str(), same.id().as_str());
    assert!(request.id().as_str().starts_with("stop-request:"));
    assert_eq!(request.id().digest_hex().len(), 64);
    assert!(
        request
            .id()
            .digest_hex()
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    );
    assert_eq!(request.cause(), StopCause::OperatorSignal);
    assert_eq!(request.grace(), declared);
    assert_eq!(request.at_us(), 10);
    assert_eq!(request.deadline_us(), 1_010);
    assert!(!request.has_expired(1_009));
    assert!(request.has_expired(1_010));
    assert!(request.canonical_text().contains(request.id().as_str()));

    // Every declared field participates: a difference in any one is a distinct identity.
    let other_cause = StopRequest::new(StopCause::SupervisorRequest, declared, 10);
    let other_grace = StopRequest::new(StopCause::OperatorSignal, policy(1_001, 500), 10);
    let other_drain = StopRequest::new(StopCause::OperatorSignal, policy(1_000, 501), 10);
    let other_instant = StopRequest::new(StopCause::OperatorSignal, declared, 11);
    for other in [&other_cause, &other_grace, &other_drain, &other_instant] {
        assert_ne!(request.id(), other.id());
    }

    // The cause vocabulary is closed and each member belongs to exactly one landed class.
    assert_eq!(StopCause::ALL.len(), 3);
    assert_eq!(StopCauseClass::ALL.len(), 2);
    assert_eq!(
        StopCauseClass::ALL,
        [StopCauseClass::Requested, StopCauseClass::Poisoned]
    );
    assert_eq!(
        StopCauseClass::from_wire_name("requested"),
        Some(StopCauseClass::Requested)
    );
    assert_eq!(
        StopCauseClass::from_wire_name("poisoned"),
        Some(StopCauseClass::Poisoned)
    );
    let mut requested = 0_u64;
    let mut poisoned = 0_u64;
    let mut spellings = BTreeSet::new();
    for cause in StopCause::ALL {
        assert!(spellings.insert(cause.wire_name()));
        assert_eq!(cause.as_str(), cause.wire_name());
        assert_eq!(StopCause::from_wire_name(cause.wire_name()), Some(cause));
        match cause.class() {
            StopCauseClass::Requested => requested += 1,
            StopCauseClass::Poisoned => poisoned += 1,
        }
    }
    assert_eq!(spellings.len(), 3);
    assert_eq!(requested, 2);
    assert_eq!(poisoned, 1);
    assert_eq!(StopCause::OperatorSignal.class(), StopCauseClass::Requested);
    assert_eq!(
        StopCause::SupervisorRequest.class(),
        StopCauseClass::Requested
    );
    assert_eq!(
        StopCause::InvariantFailure.class(),
        StopCauseClass::Poisoned
    );
}

/// `GNT-22.1`: an unknown cause or cause-class spelling is refused rather than mapped
/// onto a declared neighbor.
#[test]
fn cause_outside_the_closed_vocabulary_is_refused_rather_than_mapped() {
    let outside = [
        "",
        "operator_signal",
        "OperatorSignal",
        "operator signal",
        "operator-signal ",
        "requested",
        "poisoned",
        "supervisor",
        "invariant_failure",
        "cancelled",
        "sigterm",
    ];
    for spelling in outside {
        assert_eq!(StopCause::from_wire_name(spelling), None);
        assert_eq!(
            StopCause::decode(spelling),
            Err(StopError::UnknownSpelling {
                vocabulary: "stop-cause",
                spelling: Arc::from(spelling),
            })
        );
    }
    // The declared spellings are the only ones accepted, so nothing was mapped away.
    for cause in StopCause::ALL {
        assert_eq!(StopCause::decode(cause.wire_name()), Ok(cause));
    }
    // A class spelling is not a cause spelling, and a cause spelling is not a class one.
    assert_eq!(StopCauseClass::from_wire_name("invariant-failure"), None);
    assert_eq!(StopCauseClass::from_wire_name("operator-signal"), None);
    assert_eq!(StopCauseClass::from_wire_name("Requested"), None);
    assert_eq!(
        StopCauseClass::from_wire_name("poisoned"),
        Some(StopCauseClass::Poisoned)
    );

    let refused = StopCause::decode("sigterm");
    match refused {
        Err(StopError::UnknownSpelling {
            vocabulary,
            spelling,
        }) => {
            assert_eq!(vocabulary, "stop-cause");
            assert_eq!(spelling.as_ref(), "sigterm");
        }
        Err(other) => unreachable!(
            "an unknown cause spelling is refused as stop-unknown-spelling, not {other}"
        ),
        Ok(cause) => unreachable!("`sigterm` is not a declared cause, but decoded to {cause:?}"),
    }
    assert_eq!(
        StopCause::decode("sigterm").err().map(|error| error.code()),
        Some(StopDiagnosticCode::UnknownSpelling)
    );
    assert_eq!(
        StopCause::decode("sigterm")
            .err()
            .map(|error| error.requirement()),
        Some(LIFECYCLE_STOP_CLAUSES[1])
    );
}

/// `GNT-22.1`: the first request closes admission and fixes the held identity; a later
/// request joins, supersedes, or is refused by the held cause.
#[test]
fn request_stop_closes_admission_and_joins_or_supersedes_the_held_cause() {
    let declared = policy(1_000, 500);
    let mut coordinator = StopCoordinator::new();
    assert!(coordinator.is_admission_open());
    assert_eq!(coordinator.state(), &StopState::Running);
    assert_eq!(coordinator.request(), None);

    let requested = StopRequest::new(StopCause::OperatorSignal, declared, 10);
    assert_eq!(
        coordinator.request_stop(requested.clone()),
        Ok(StopRequestJoin::Joined)
    );
    assert!(!coordinator.is_admission_open());
    assert_eq!(coordinator.state(), &StopState::StopRequested);
    assert_eq!(coordinator.state().landed_name(), "shutting-down");
    assert_eq!(coordinator.request(), Some(&requested));
    assert_eq!(coordinator.watermark_us(), 10);

    // A later request of the held cause joins it: the held identity stays in force, no
    // second transition is created, and the accepted instant advances the watermark.
    let repeated = StopRequest::new(StopCause::OperatorSignal, declared, 99);
    assert_eq!(
        coordinator.request_stop(repeated),
        Ok(StopRequestJoin::Joined)
    );
    assert_eq!(coordinator.request(), Some(&requested));
    assert_eq!(coordinator.watermark_us(), 99);
    assert_eq!(coordinator.state(), &StopState::StopRequested);

    // A joining request may not re-declare the grace and drain in force: the refusal
    // leaves the held request and the watermark untouched.
    let rejoined = StopRequest::new(StopCause::OperatorSignal, policy(2_000, 500), 120);
    assert_eq!(
        coordinator.request_stop(rejoined),
        Err(StopError::RedeclaredGrace {
            held: declared,
            presented: policy(2_000, 500),
        })
    );
    let redrained = StopRequest::new(StopCause::OperatorSignal, policy(1_000, 501), 120);
    assert_eq!(
        coordinator.request_stop(redrained),
        Err(StopError::RedeclaredGrace {
            held: declared,
            presented: policy(1_000, 501),
        })
    );
    assert_eq!(coordinator.request(), Some(&requested));
    assert_eq!(
        coordinator.request().map(StopRequest::grace),
        Some(declared)
    );
    assert_eq!(coordinator.watermark_us(), 99);

    // A different cause of the same requested class cannot be joined.
    let conflicting = StopRequest::new(StopCause::SupervisorRequest, declared, 120);
    assert_eq!(
        coordinator.request_stop(conflicting),
        Err(StopError::CauseConflict {
            requested: StopCause::SupervisorRequest,
            held: StopCause::OperatorSignal,
        })
    );
    assert_eq!(coordinator.request(), Some(&requested));
    assert_eq!(coordinator.watermark_us(), 99);

    // A poisoned request may supersede a requested-class cause, but only with the
    // budgets already declared.
    let redeclared = StopRequest::new(StopCause::InvariantFailure, policy(2_000, 500), 130);
    assert_eq!(
        coordinator.request_stop(redeclared),
        Err(StopError::RedeclaredGrace {
            held: declared,
            presented: policy(2_000, 500),
        })
    );
    assert_eq!(coordinator.request(), Some(&requested));
    assert_eq!(coordinator.watermark_us(), 99);

    let poisoned = StopRequest::new(StopCause::InvariantFailure, declared, 130);
    assert_eq!(
        coordinator.request_stop(poisoned.clone()),
        Ok(StopRequestJoin::Replaced {
            previous: StopCause::OperatorSignal,
        })
    );
    assert_eq!(
        coordinator.request().map(StopRequest::cause),
        Some(StopCause::InvariantFailure)
    );
    assert_eq!(coordinator.state(), &StopState::StopRequested);
    assert_eq!(coordinator.watermark_us(), 130);
    assert!(!coordinator.is_admission_open());
    // The superseding declaration is made at the held instant, not the presented one.
    let superseding = StopRequest::new(StopCause::InvariantFailure, declared, 10);
    assert_eq!(coordinator.request(), Some(&superseding));
    assert_ne!(
        coordinator.request().map(StopRequest::id),
        Some(poisoned.id())
    );

    // A requested-class cause never supersedes the held poisoned one, and a repeated
    // poisoned request joins the held request.
    let requested_again = StopRequest::new(StopCause::SupervisorRequest, declared, 140);
    assert_eq!(
        coordinator.request_stop(requested_again),
        Err(StopError::CauseConflict {
            requested: StopCause::SupervisorRequest,
            held: StopCause::InvariantFailure,
        })
    );
    assert_eq!(coordinator.request(), Some(&superseding));
    assert_eq!(coordinator.watermark_us(), 130);
    assert_eq!(
        coordinator.request_stop(poisoned),
        Ok(StopRequestJoin::Joined)
    );
    assert_eq!(coordinator.request(), Some(&superseding));
    assert_eq!(coordinator.watermark_us(), 130);
}

/// `GNT-22.2`: observation is evidence only, and propagation reuses the held identity.
#[test]
fn cooperative_observation_is_evidence_only_and_propagation_reuses_the_held_identity() {
    let declared = policy(1_000, 500);
    let mut coordinator = StopCoordinator::new();
    for point in SafePoint::ALL {
        assert!(matches!(point.observe(&coordinator), Ok(None)));
    }

    let request = StopRequest::new(StopCause::SupervisorRequest, declared, 10);
    assert_eq!(
        coordinator.request_stop(request.clone()),
        Ok(StopRequestJoin::Joined)
    );

    let state_before = coordinator.state().clone();
    for point in SafePoint::ALL {
        let observation = match point.observe(&coordinator) {
            Ok(Some(observation)) => observation,
            Ok(None) => unreachable!("a held request is observable at every safe point"),
            Err(error) => unreachable!("cooperative stop is observable before escalation: {error}"),
        };
        assert_eq!(observation.request(), request.id());
        assert_eq!(observation.cause(), StopCause::SupervisorRequest);
        assert_eq!(observation.safe_point(), point);
        assert!(
            observation
                .canonical_text()
                .contains(observation.request().as_str())
        );
    }

    // Observing mutates nothing: no phase, cohort, escalation point, or durable cut moved.
    assert_eq!(coordinator.state(), &state_before);
    assert_eq!(coordinator.state().phase_name(), "stop-requested");
    assert_eq!(coordinator.state().rank(), 1);
    assert_eq!(coordinator.cohort(), 0);
    assert!(!coordinator.is_cohort_closed());
    assert_eq!(coordinator.escalated_at_us(), None);
    assert_eq!(
        coordinator.durable_cut(),
        Some(DurableStopCut::StopRequested)
    );

    // Cooperative stop fixes the disposition of already-admitted work without settling it.
    let mut admitted = TaskStopState::new(OwnerGeneration::initial());
    assert_eq!(
        coordinator.admitted_work(&admitted),
        AdmittedWork::SettlesUnderOwnRecoveryClass
    );
    let completed = result(TaskOutcome::Completed, OwnerGeneration::initial(), 5);
    assert_eq!(admitted.publish(&completed), Ok(TaskOutcome::Completed));
    assert_eq!(
        coordinator.admitted_work(&admitted),
        AdmittedWork::SettledOutcomeLeftUntouched
    );
    assert_eq!(admitted.published_at_us(), Some(5));

    let mut child = StopCoordinator::new();
    assert!(child.is_admission_open());
    assert_eq!(
        coordinator.propagate(&mut child),
        Ok(StopRequestJoin::Joined)
    );
    assert_eq!(child.request().map(StopRequest::id), Some(request.id()));
    assert_eq!(
        child.request().map(StopRequest::cause),
        Some(StopCause::SupervisorRequest)
    );
    assert_eq!(child.request().map(StopRequest::grace), Some(declared));
    assert_eq!(child.request().map(StopRequest::at_us), Some(10));
    assert!(!child.is_admission_open());
    assert_eq!(child.state(), &StopState::StopRequested);
    assert_eq!(child.watermark_us(), 10);
    assert!(matches!(
        SafePoint::OperationAdmission.observe(&child),
        Ok(Some(_))
    ));
}

/// `GNT-22.2`: cooperative transitions require a held request, and instants never move
/// backwards.
#[test]
fn cooperative_transitions_require_a_held_request_and_monotone_instants() {
    let transitions = [
        StopTransition::Propagation,
        StopTransition::CohortRegistration,
        StopTransition::CohortClosure,
    ];
    assert_eq!(StopTransition::ALL, transitions);
    assert_eq!(
        StopTransition::ALL.map(StopTransition::wire_name),
        ["propagation", "cohort-registration", "cohort-closure"]
    );

    let declared = policy(1_000, 500);
    let mut coordinator = StopCoordinator::new();
    let mut child = StopCoordinator::new();
    assert_eq!(
        coordinator.propagate(&mut child),
        Err(StopError::WithoutStopRequest {
            transition: StopTransition::Propagation,
        })
    );
    assert_eq!(
        coordinator.register_cohort_member(),
        Err(StopError::WithoutStopRequest {
            transition: StopTransition::CohortRegistration,
        })
    );
    assert_eq!(
        coordinator.close_cohort(5),
        Err(StopError::WithoutStopRequest {
            transition: StopTransition::CohortClosure,
        })
    );
    assert_eq!(coordinator.state(), &StopState::Running);
    assert_eq!(coordinator.cohort(), 0);
    assert!(coordinator.is_admission_open());
    assert!(child.is_admission_open());
    assert_eq!(child.state(), &StopState::Running);
    assert_eq!(child.request(), None);

    let request = StopRequest::new(StopCause::OperatorSignal, declared, 100);
    assert_eq!(
        coordinator.request_stop(request),
        Ok(StopRequestJoin::Joined)
    );
    assert_eq!(coordinator.watermark_us(), 100);

    // An instant earlier than the watermark is refused rather than reordered.
    assert_eq!(
        coordinator.close_cohort(99),
        Err(StopError::NonMonotoneInstant {
            presented: 99,
            held: 100,
        })
    );
    assert_eq!(coordinator.watermark_us(), 100);
    assert!(!coordinator.is_cohort_closed());
    assert_eq!(coordinator.state(), &StopState::StopRequested);
    assert_eq!(coordinator.close_cohort(100), Ok(()));
    assert!(coordinator.is_cohort_closed());
    assert_eq!(coordinator.state(), &StopState::Draining);
    assert_eq!(coordinator.watermark_us(), 100);

    // A non-monotone presented instant is refused even on a stuttering path, so no
    // repeated transition silently reorders an earlier instant.
    let earlier_repeat = StopRequest::new(StopCause::OperatorSignal, declared, 50);
    assert_eq!(
        coordinator.request_stop(earlier_repeat),
        Err(StopError::NonMonotoneInstant {
            presented: 50,
            held: 100,
        })
    );
    assert_eq!(
        coordinator.close_cohort(99),
        Err(StopError::NonMonotoneInstant {
            presented: 99,
            held: 100,
        })
    );
    assert_eq!(
        coordinator.terminate(99),
        Err(StopError::NonMonotoneInstant {
            presented: 99,
            held: 100,
        })
    );
    assert_eq!(coordinator.watermark_us(), 100);
    assert_eq!(coordinator.state(), &StopState::Draining);

    // An accepted join at a later instant advances the watermark, so a later transition
    // at an earlier instant is refused.
    let later_join = StopRequest::new(StopCause::OperatorSignal, declared, 150);
    assert_eq!(
        coordinator.request_stop(later_join),
        Ok(StopRequestJoin::Joined)
    );
    assert_eq!(coordinator.request().map(StopRequest::at_us), Some(100));
    assert_eq!(coordinator.watermark_us(), 150);
    assert_eq!(coordinator.state(), &StopState::Draining);
    assert_eq!(
        coordinator.close_cohort(149),
        Err(StopError::NonMonotoneInstant {
            presented: 149,
            held: 150,
        })
    );
    assert_eq!(coordinator.watermark_us(), 150);
    assert!(coordinator.is_cohort_closed());
    assert_eq!(coordinator.state(), &StopState::Draining);
    assert_eq!(coordinator.close_cohort(150), Ok(()));
    assert_eq!(coordinator.watermark_us(), 150);
}

/// `GNT-22.3`: admission closes at the first request and is never reopened.
#[test]
fn admission_closure_refuses_new_work_and_is_never_reopened() {
    let declared = policy(1_000, 500);
    let mut coordinator = StopCoordinator::new();
    assert!(coordinator.is_admission_open());
    assert_eq!(coordinator.admit_application_work(0), Ok(()));
    assert_eq!(coordinator.admit_application_work(u64::MAX), Ok(()));

    let requested = StopRequest::new(StopCause::OperatorSignal, declared, 100);
    assert_eq!(
        coordinator.request_stop(requested),
        Ok(StopRequestJoin::Joined)
    );
    assert!(!coordinator.is_admission_open());
    assert_eq!(
        coordinator.admit_application_work(100),
        Err(StopError::AdmissionAfterClosure { at_us: 100 })
    );

    // A superseding request does not reopen admission.
    let poisoned = StopRequest::new(StopCause::InvariantFailure, declared, 100);
    assert_eq!(
        coordinator.request_stop(poisoned),
        Ok(StopRequestJoin::Replaced {
            previous: StopCause::OperatorSignal,
        })
    );
    assert!(!coordinator.is_admission_open());
    assert_eq!(
        coordinator.admit_application_work(101),
        Err(StopError::AdmissionAfterClosure { at_us: 101 })
    );

    // Cohort closure and escalation leave admission closed.
    assert_eq!(coordinator.close_cohort(110), Ok(()));
    assert_eq!(
        coordinator.admit_application_work(110),
        Err(StopError::AdmissionAfterClosure { at_us: 110 })
    );
    let mut tasks = [TaskStopState::new(OwnerGeneration::initial())];
    assert!(coordinator.escalate(&mut tasks, 1_100).is_ok());
    assert!(!coordinator.is_admission_open());
    assert_eq!(
        coordinator.admit_application_work(130),
        Err(StopError::AdmissionAfterClosure { at_us: 130 })
    );

    // Termination leaves admission closed as well.
    assert!(coordinator.terminate(1_200).is_ok());
    assert_eq!(coordinator.state().landed_name(), "terminated");
    assert!(!coordinator.is_admission_open());
    assert_eq!(
        coordinator.admit_application_work(150),
        Err(StopError::AdmissionAfterClosure { at_us: 150 })
    );
    assert_eq!(
        coordinator
            .admit_application_work(u64::MAX)
            .err()
            .map(|error| error.code()),
        Some(StopDiagnosticCode::AdmissionAfterClosure)
    );
}

/// `GNT-22.4`: the safe-point vocabulary is closed, and no safe point observes
/// cooperative stop after escalation.
#[test]
fn safe_point_vocabulary_is_closed_and_observation_stops_after_escalation() {
    let spellings = [
        "operation-admission",
        "workflow-frame-entry",
        "workflow-frame-return",
        "loop-condition",
        "loop-back-edge",
        "wait-or-park",
        "explicit-check",
    ];
    assert_eq!(SafePoint::ALL.len(), 7);
    assert_eq!(SafePoint::ALL.map(SafePoint::wire_name), spellings);
    let mut unique = BTreeSet::new();
    for point in SafePoint::ALL {
        assert!(unique.insert(point.wire_name()));
        assert_eq!(point.as_str(), point.wire_name());
        assert_eq!(SafePoint::from_wire_name(point.wire_name()), Some(point));
    }
    assert_eq!(unique.len(), 7);
    assert_eq!(SafePoint::from_wire_name("explicit-check "), None);
    assert_eq!(SafePoint::from_wire_name("ExplicitCheck"), None);
    assert_eq!(SafePoint::from_wire_name("safe-point"), None);

    let declared = policy(1_000, 500);
    let mut coordinator = StopCoordinator::new();
    let request = StopRequest::new(StopCause::OperatorSignal, declared, 10);
    assert_eq!(
        coordinator.request_stop(request),
        Ok(StopRequestJoin::Joined)
    );
    let mut tasks = [TaskStopState::new(OwnerGeneration::initial())];
    let escalation = match coordinator.escalate(&mut tasks, 1_010) {
        Ok(escalation) => escalation,
        Err(error) => unreachable!("a held request escalates at its grace expiry: {error}"),
    };
    assert!(!escalation.is_repeated());
    assert_eq!(escalation.at_us(), 1_010);

    for point in SafePoint::ALL {
        assert_eq!(
            point.observe(&coordinator),
            Err(StopError::CooperativeObservationAfterEscalation {
                safe_point: point,
                escalated_at_us: 1_010,
            })
        );
    }

    // A cooperative termination never escalated, and a terminated lifecycle yields no
    // cooperative observation at any safe point.
    let mut cooperative = StopCoordinator::new();
    let cooperative_request = StopRequest::new(StopCause::OperatorSignal, declared, 10);
    assert_eq!(
        cooperative.request_stop(cooperative_request),
        Ok(StopRequestJoin::Joined)
    );
    assert_eq!(cooperative.close_cohort(20), Ok(()));
    assert!(cooperative.terminate(30).is_ok());
    assert!(cooperative.state().is_terminal());
    assert_eq!(cooperative.escalated_at_us(), None);
    for point in SafePoint::ALL {
        assert_eq!(point.observe(&cooperative), Ok(None));
    }
}

/// `GNT-22.5`: zero budgets declare nothing, and deadlines saturate.
#[test]
fn grace_policy_refuses_zero_budgets_and_saturating_deadlines() {
    assert_eq!(
        GracePolicy::new(0, 1),
        Err(StopError::UndeclaredGrace {
            grace_us: 0,
            drain_us: 1,
        })
    );
    assert_eq!(
        GracePolicy::new(1, 0),
        Err(StopError::UndeclaredGrace {
            grace_us: 1,
            drain_us: 0,
        })
    );
    assert_eq!(
        GracePolicy::new(0, 0),
        Err(StopError::UndeclaredGrace {
            grace_us: 0,
            drain_us: 0,
        })
    );
    assert_eq!(
        GracePolicy::new(u64::MAX, 0),
        Err(StopError::UndeclaredGrace {
            grace_us: u64::MAX,
            drain_us: 0,
        })
    );
    assert_eq!(
        GracePolicy::new(0, 1)
            .err()
            .map(|error| error.requirement()),
        Some(LIFECYCLE_STOP_CLAUSES[5])
    );

    let declared = policy(1_000, 500);
    assert_eq!(declared.grace_us(), 1_000);
    assert_eq!(declared.drain_us(), 500);
    assert_eq!(declared.deadline_us(10), 1_010);
    assert_eq!(declared.drain_deadline_us(10), 510);
    assert!(!declared.has_expired(10, 1_009));
    assert!(declared.has_expired(10, 1_010));
    assert!(declared.has_expired(10, u64::MAX));
    assert_eq!(declared.deadline_us(u64::MAX), u64::MAX);
    assert_eq!(declared.drain_deadline_us(u64::MAX), u64::MAX);

    // A declared budget saturates: it never wraps into an earlier deadline.
    let maxed = policy(u64::MAX, u64::MAX);
    assert_eq!(maxed.deadline_us(1), u64::MAX);
    assert_eq!(maxed.deadline_us(u64::MAX), u64::MAX);
    assert_eq!(maxed.drain_deadline_us(1), u64::MAX);
    assert_eq!(maxed.drain_deadline_us(u64::MAX), u64::MAX);
    assert!(maxed.deadline_us(1) >= 1);
    assert!(!maxed.has_expired(u64::MAX - 1, u64::MAX - 1));
    assert!(maxed.has_expired(u64::MAX - 1, u64::MAX));
}

/// `GNT-22.5`, `GNT-22.7`: the cohort grows monotonically and closure is idempotent.
#[test]
fn cohort_grows_monotonically_and_closure_is_idempotent() {
    let declared = policy(1_000, 500);
    let mut coordinator = StopCoordinator::new();
    assert_eq!(
        coordinator.terminate(0),
        Err(StopError::TerminationBeforeDrain { phase: "running" })
    );
    assert_eq!(
        coordinator.register_cohort_member(),
        Err(StopError::WithoutStopRequest {
            transition: StopTransition::CohortRegistration,
        })
    );

    let request = StopRequest::new(StopCause::OperatorSignal, declared, 10);
    assert_eq!(
        coordinator.request_stop(request),
        Ok(StopRequestJoin::Joined)
    );
    assert_eq!(coordinator.register_cohort_member(), Ok(1));
    assert_eq!(coordinator.register_cohort_member(), Ok(2));
    assert_eq!(coordinator.cohort(), 2);
    assert!(!coordinator.is_cohort_closed());
    assert_eq!(coordinator.state(), &StopState::StopRequested);
    assert_eq!(coordinator.state().rank(), 1);
    assert_eq!(
        coordinator.durable_cut(),
        Some(DurableStopCut::StopRequested)
    );

    // Termination before the cohort closes is refused and reports the phase.
    assert_eq!(
        coordinator.terminate(20),
        Err(StopError::TerminationBeforeDrain {
            phase: "stop-requested",
        })
    );
    assert_eq!(coordinator.state(), &StopState::StopRequested);
    assert_eq!(coordinator.state().report(), None);

    assert_eq!(coordinator.close_cohort(20), Ok(()));
    assert!(coordinator.is_cohort_closed());
    assert_eq!(coordinator.state(), &StopState::Draining);
    assert_eq!(coordinator.state().rank(), 2);
    assert_eq!(coordinator.cohort(), 2);
    assert_eq!(coordinator.watermark_us(), 20);
    assert_eq!(coordinator.close_cohort(21), Ok(()));
    assert_eq!(coordinator.watermark_us(), 21);
    assert!(coordinator.is_cohort_closed());
    assert_eq!(coordinator.state(), &StopState::Draining);
    assert_eq!(coordinator.cohort(), 2);

    assert_eq!(
        coordinator.register_cohort_member(),
        Err(StopError::CohortGrowthAfterClosure { cohort: 2 })
    );
    assert_eq!(coordinator.cohort(), 2);
    assert_eq!(
        coordinator.durable_cut(),
        Some(DurableStopCut::StopRequested)
    );

    let report = match coordinator.terminate(30) {
        Ok(report) => report,
        Err(error) => unreachable!("a closed cohort terminates: {error}"),
    };
    assert_eq!(report.cohort(), 2);
    assert_eq!(report.terminated_at_us(), 30);
    assert_eq!(coordinator.cohort(), 2);
    assert_eq!(
        coordinator.register_cohort_member(),
        Err(StopError::CohortGrowthAfterClosure { cohort: 2 })
    );
}

/// `GNT-22.6`: escalation linearizes once, settles nonterminal tasks, and preserves
/// settled outcomes.
#[test]
fn escalation_linearizes_once_and_preserves_settled_outcomes() {
    let declared = policy(1_000, 500);
    let generation = OwnerGeneration::initial();
    let mut coordinator = StopCoordinator::new();
    let request = StopRequest::new(StopCause::OperatorSignal, declared, 10);
    assert_eq!(
        coordinator.request_stop(request.clone()),
        Ok(StopRequestJoin::Joined)
    );

    // Before escalation linearized, the lifecycle declared no drain deadline yet.
    assert_eq!(coordinator.drain_deadline_us(), None);
    assert!(!coordinator.has_drain_expired(u64::MAX));

    let mut tasks = [
        TaskStopState::new(generation),
        TaskStopState::new(generation),
        TaskStopState::new(generation),
        TaskStopState::new(generation),
    ];
    let completed = result(TaskOutcome::Completed, generation, 5);
    assert_eq!(tasks[1].publish(&completed), Ok(TaskOutcome::Completed));
    let cancelled = result(TaskOutcome::Cancelled, generation, 7);
    assert_eq!(tasks[3].publish(&cancelled), Ok(TaskOutcome::Cancelled));

    let escalation = match coordinator.escalate(&mut tasks, 1_010) {
        Ok(escalation) => escalation,
        Err(error) => unreachable!("a held request escalates exactly once: {error}"),
    };
    assert!(!escalation.is_repeated());
    assert_eq!(escalation.at_us(), 1_010);
    assert_eq!(escalation.request(), request.id());
    assert_eq!(escalation.escalated_tasks(), 2);
    assert_eq!(escalation.preserved_outcomes(), 2);
    // The declared drain runs from the escalation instant, so it flips exactly at that
    // deadline and nowhere earlier.
    assert_eq!(coordinator.drain_deadline_us(), Some(1_510));
    assert_eq!(
        coordinator.drain_deadline_us(),
        Some(escalation.at_us() + declared.drain_us())
    );
    assert!(!coordinator.has_drain_expired(1_010));
    assert!(!coordinator.has_drain_expired(1_509));
    assert!(coordinator.has_drain_expired(1_510));
    assert!(coordinator.has_drain_expired(1_511));
    assert!(coordinator.has_drain_expired(u64::MAX));
    assert_eq!(coordinator.state(), &StopState::Escalated);
    assert_eq!(coordinator.state().rank(), 3);
    assert_eq!(coordinator.escalated_at_us(), Some(1_010));
    assert!(coordinator.is_cohort_closed());
    assert_eq!(
        coordinator.durable_cut(),
        Some(DurableStopCut::GraceExpired)
    );

    assert_eq!(tasks[0].outcome(), Some(TaskOutcome::Escalated));
    assert_eq!(tasks[0].published_at_us(), Some(1_010));
    assert_eq!(tasks[2].outcome(), Some(TaskOutcome::Escalated));
    assert_eq!(tasks[2].published_at_us(), Some(1_010));
    assert_eq!(tasks[1].outcome(), Some(TaskOutcome::Completed));
    assert_eq!(tasks[1].published_at_us(), Some(5));
    assert_eq!(tasks[3].outcome(), Some(TaskOutcome::Cancelled));
    assert_eq!(tasks[3].published_at_us(), Some(7));

    // A repeated escalation is stuttering: the recorded point stands and nothing moves.
    let mut later = [TaskStopState::new(generation)];
    let repeated = match coordinator.escalate(&mut later, 5_000) {
        Ok(escalation) => escalation,
        Err(error) => unreachable!("a repeated escalation reports the recorded point: {error}"),
    };
    assert!(repeated.is_repeated());
    assert_eq!(repeated.at_us(), 1_010);
    assert_eq!(repeated.request(), escalation.request());
    assert_eq!(repeated.escalated_tasks(), 2);
    assert_eq!(repeated.preserved_outcomes(), 2);
    assert_eq!(later[0].outcome(), None);
    assert_eq!(coordinator.watermark_us(), 5_000);
    assert_eq!(coordinator.escalated_at_us(), Some(1_010));
    // A repeated escalation reports the recorded point, so the drain deadline stands.
    assert_eq!(coordinator.drain_deadline_us(), Some(1_510));
    assert_eq!(coordinator.state(), &StopState::Escalated);
}

/// `GNT-22.6`, `GNT-22.7`: escalation needs a held request, never runs after
/// termination, and never moves its point backwards.
#[test]
fn escalation_refuses_without_request_after_termination_and_non_monotone_instants() {
    let declared = policy(1_000, 500);
    let mut coordinator = StopCoordinator::new();
    let mut tasks = [TaskStopState::new(OwnerGeneration::initial())];

    assert_eq!(
        coordinator.escalate(&mut tasks, 0),
        Err(StopError::EscalationWithoutStopRequest)
    );
    assert_eq!(
        coordinator.escalate(&mut tasks, u64::MAX),
        Err(StopError::EscalationWithoutStopRequest)
    );
    assert_eq!(coordinator.state(), &StopState::Running);
    assert_eq!(coordinator.escalated_at_us(), None);
    assert_eq!(tasks[0].outcome(), None);
    assert_eq!(
        coordinator
            .escalate(&mut tasks, 0)
            .err()
            .map(|error| error.requirement()),
        Some(LIFECYCLE_STOP_CLAUSES[6])
    );

    let request = StopRequest::new(StopCause::OperatorSignal, declared, 100);
    assert_eq!(
        coordinator.request_stop(request),
        Ok(StopRequestJoin::Joined)
    );
    assert_eq!(
        coordinator.escalate(&mut tasks, 99),
        Err(StopError::NonMonotoneInstant {
            presented: 99,
            held: 100,
        })
    );
    assert_eq!(coordinator.escalated_at_us(), None);
    assert_eq!(coordinator.state(), &StopState::StopRequested);
    assert_eq!(coordinator.watermark_us(), 100);
    assert_eq!(tasks[0].outcome(), None);

    // An instant that precedes the declared grace deadline is not grace expiry.
    assert_eq!(
        coordinator.escalate(&mut tasks, 200),
        Err(StopError::EscalationBeforeGraceExpiry {
            deadline_us: 1_100,
            presented_at_us: 200,
        })
    );
    assert_eq!(coordinator.escalated_at_us(), None);
    assert_eq!(coordinator.state(), &StopState::StopRequested);
    assert_eq!(tasks[0].outcome(), None);

    // After termination the coordinator never escalates again.
    assert_eq!(coordinator.close_cohort(150), Ok(()));
    assert!(coordinator.terminate(200).is_ok());
    assert_eq!(coordinator.state().landed_name(), "terminated");
    assert_eq!(
        coordinator.escalate(&mut tasks, 300),
        Err(StopError::TerminatedCoordinator)
    );
    assert_eq!(coordinator.escalated_at_us(), None);
    assert_eq!(tasks[0].outcome(), None);
    assert_eq!(
        coordinator
            .escalate(&mut tasks, 300)
            .err()
            .map(|error| error.requirement()),
        Some(LIFECYCLE_STOP_CLAUSES[7])
    );

    // Termination gates every further stop transition, not only escalation, and a
    // refused transition leaves the coordinator and the child untouched.
    let mut child = StopCoordinator::new();
    assert_eq!(
        coordinator.close_cohort(300),
        Err(StopError::TerminatedCoordinator)
    );
    assert_eq!(
        coordinator.propagate(&mut child),
        Err(StopError::TerminatedCoordinator)
    );
    assert_eq!(
        coordinator
            .close_cohort(300)
            .err()
            .map(|error| error.code()),
        Some(StopDiagnosticCode::TerminatedCoordinator)
    );
    assert_eq!(
        coordinator
            .propagate(&mut child)
            .err()
            .map(|error| error.requirement()),
        Some(LIFECYCLE_STOP_CLAUSES[7])
    );
    assert_eq!(coordinator.watermark_us(), 200);
    assert_eq!(coordinator.state().landed_name(), "terminated");
    assert!(child.is_admission_open());
    assert_eq!(child.request(), None);
    assert_eq!(child.state(), &StopState::Running);
}

/// `GNT-22.6`: after escalation only descendant drain and emergency release are
/// admitted.
#[test]
fn only_descendant_drain_and_emergency_release_are_admitted_after_escalation() {
    let permitted = [
        EscalatedWork::DescendantDrain,
        EscalatedWork::EmergencyRelease,
    ];
    assert_eq!(EscalatedWork::PERMITTED, permitted);
    assert_eq!(
        EscalatedWork::ALL,
        [
            EscalatedWork::DescendantDrain,
            EscalatedWork::EmergencyRelease,
            EscalatedWork::SourceCleanup,
        ]
    );
    let mut spellings = BTreeSet::new();
    for work in EscalatedWork::ALL {
        assert!(spellings.insert(work.wire_name()));
    }
    assert_eq!(spellings.len(), 3);

    for work in EscalatedWork::PERMITTED {
        assert!(work.is_permitted());
        assert_eq!(work.admit(), Ok(work));
    }
    assert!(!EscalatedWork::SourceCleanup.is_permitted());
    let refused = EscalatedWork::SourceCleanup.admit();
    assert_eq!(
        refused,
        Err(StopError::SourceCleanupAfterEscalation {
            step: Arc::from("source-cleanup"),
        })
    );
    match refused {
        Err(StopError::SourceCleanupAfterEscalation { step }) => {
            assert_eq!(step.as_ref(), EscalatedWork::SourceCleanup.wire_name());
        }
        Err(other) => unreachable!("source cleanup is refused under its own code, not {other}"),
        Ok(work) => unreachable!("source cleanup is never admitted, but admitted {work:?}"),
    }
}

/// `GNT-22.7`, `GNT-22.6`: the outcome vocabulary maps onto the landed task statuses,
/// and escalation is never a domain outcome.
#[test]
fn task_outcome_vocabulary_maps_to_landed_statuses_and_escalation_is_not_a_domain_outcome() {
    assert_eq!(
        TaskOutcome::ALL,
        [
            TaskOutcome::Completed,
            TaskOutcome::Failed,
            TaskOutcome::Cancelled,
            TaskOutcome::Escalated,
        ]
    );
    assert_eq!(TaskOutcome::Completed.landed_status(), "succeeded");
    assert_eq!(TaskOutcome::Failed.landed_status(), "failed");
    assert_eq!(TaskOutcome::Cancelled.landed_status(), "cancelled");
    assert_eq!(TaskOutcome::Escalated.landed_status(), "cancelled");
    assert!(TaskOutcome::Escalated.is_escalated());
    assert!(!TaskOutcome::Cancelled.is_escalated());
    assert!(!TaskOutcome::Completed.is_escalated());
    assert!(!TaskOutcome::Failed.is_escalated());

    // Four members publish exactly three landed statuses: no fourth status exists.
    let statuses: BTreeSet<&str> = TaskOutcome::ALL
        .iter()
        .map(|outcome| outcome.landed_status())
        .collect();
    assert_eq!(statuses.len(), 3);
    assert_eq!(
        statuses,
        BTreeSet::from(["cancelled", "failed", "succeeded"])
    );
    let mut spellings = BTreeSet::new();
    for outcome in TaskOutcome::ALL {
        assert!(spellings.insert(outcome.wire_name()));
        assert_eq!(outcome.as_str(), outcome.wire_name());
        assert_eq!(
            TaskOutcome::from_wire_name(outcome.wire_name()),
            Some(outcome)
        );
    }
    assert_eq!(spellings.len(), 4);
    assert_eq!(TaskOutcome::from_wire_name("escalated-as-outcome"), None);
    assert_eq!(TaskOutcome::from_wire_name("succeeded"), None);

    // Escalation is published by the coordinator, never reported as an ordinary result.
    let generation = OwnerGeneration::initial();
    assert_eq!(
        TaskResult::new(TaskOutcome::Escalated, generation, 1),
        Err(StopError::EscalationAsDomainOutcome)
    );
    assert_eq!(
        TaskResult::new(TaskOutcome::Escalated, generation, 1)
            .err()
            .map(|error| error.requirement()),
        Some(LIFECYCLE_STOP_CLAUSES[6])
    );
    let accepted = result(TaskOutcome::Cancelled, generation, 1);
    assert_eq!(accepted.outcome(), TaskOutcome::Cancelled);
    assert_eq!(accepted.generation(), generation);
    assert_eq!(accepted.at_us(), 1);
}

/// `GNT-22.7`: each task publishes exactly one outcome, and escalation never overwrites
/// a settled one.
#[test]
fn each_task_publishes_exactly_one_outcome_and_escalation_never_overwrites_a_settled_one() {
    let generation = OwnerGeneration::initial();
    let mut task = TaskStopState::new(generation);
    assert_eq!(task.generation(), generation);
    assert_eq!(task.outcome(), None);
    assert_eq!(task.published_at_us(), None);
    assert!(!task.is_settled());

    let completed = result(TaskOutcome::Completed, generation, 40);
    assert_eq!(task.publish(&completed), Ok(TaskOutcome::Completed));
    assert_eq!(task.outcome(), Some(TaskOutcome::Completed));
    assert_eq!(task.published_at_us(), Some(40));
    assert!(task.is_settled());

    // The fence refuses a second completion after the published instant ...
    let failed = result(TaskOutcome::Failed, generation, 50);
    assert_eq!(
        task.publish(&failed),
        Err(StopError::SecondPublication {
            published: TaskOutcome::Completed,
        })
    );
    // ... and refuses a result at or before it as late.
    assert_eq!(
        task.publish(&result(TaskOutcome::Failed, generation, 40)),
        Err(StopError::LateResult {
            published: TaskOutcome::Completed,
            published_at_us: 40,
            presented_at_us: 40,
        })
    );
    assert_eq!(
        task.publish(&result(TaskOutcome::Cancelled, generation, 39)),
        Err(StopError::LateResult {
            published: TaskOutcome::Completed,
            published_at_us: 40,
            presented_at_us: 39,
        })
    );
    assert_eq!(task.outcome(), Some(TaskOutcome::Completed));
    assert_eq!(task.published_at_us(), Some(40));

    // Hard cancellation is publishable only from a coordinator-issued escalation, so the
    // witness below is a real escalation of one still-nonterminal task.
    let declared = policy(1_000, 500);
    let mut coordinator = StopCoordinator::new();
    let request = StopRequest::new(StopCause::OperatorSignal, declared, 10);
    assert_eq!(
        coordinator.request_stop(request),
        Ok(StopRequestJoin::Joined)
    );
    let mut members = [TaskStopState::new(generation)];
    let escalation = match coordinator.escalate(&mut members, 1_010) {
        Ok(escalation) => escalation,
        Err(error) => unreachable!("a held request escalates at its grace expiry: {error}"),
    };
    assert!(!escalation.is_repeated());
    assert_eq!(escalation.at_us(), 1_010);
    assert_eq!(escalation.escalated_tasks(), 1);
    assert_eq!(escalation.preserved_outcomes(), 0);
    assert_eq!(members[0].outcome(), Some(TaskOutcome::Escalated));
    assert_eq!(members[0].published_at_us(), Some(escalation.at_us()));

    // Escalation never overwrites a settled outcome and mutates nothing.
    assert_eq!(
        task.publish_escalated(&escalation),
        Err(StopError::EscalationOverSettledOutcome {
            published: TaskOutcome::Completed,
        })
    );
    assert_eq!(task.outcome(), Some(TaskOutcome::Completed));
    assert_eq!(task.published_at_us(), Some(40));
    assert_eq!(
        task.publish_escalated(&escalation)
            .err()
            .map(|error| error.code()),
        Some(StopDiagnosticCode::EscalationOverSettledOutcome)
    );

    // A still-nonterminal task settles once from that witness, and a second escalation
    // is refused.
    let mut open = TaskStopState::new(generation);
    assert_eq!(
        open.publish_escalated(&escalation),
        Ok(TaskOutcome::Escalated)
    );
    assert_eq!(open.outcome(), Some(TaskOutcome::Escalated));
    assert_eq!(open.published_at_us(), Some(escalation.at_us()));
    assert_eq!(open.published_at_us(), Some(1_010));
    assert_eq!(
        open.publish_escalated(&escalation),
        Err(StopError::EscalationOverSettledOutcome {
            published: TaskOutcome::Escalated,
        })
    );
    assert_eq!(open.outcome(), Some(TaskOutcome::Escalated));
    assert_eq!(open.published_at_us(), Some(1_010));
}

/// `GNT-22.2`, `GNT-22.5`, `GNT-22.8`: termination yields one immutable report, and a
/// repeat observes the same one.
#[test]
fn termination_produces_one_immutable_report_and_repeats_observe_it() {
    let declared = policy(1_000, 500);
    let generation = OwnerGeneration::initial();
    let mut coordinator = StopCoordinator::new();
    let request = StopRequest::new(StopCause::SupervisorRequest, declared, 10);
    assert_eq!(
        coordinator.request_stop(request.clone()),
        Ok(StopRequestJoin::Joined)
    );
    assert_eq!(coordinator.register_cohort_member(), Ok(1));
    assert_eq!(coordinator.register_cohort_member(), Ok(2));
    let mut tasks = [
        TaskStopState::new(generation),
        TaskStopState::new(generation),
    ];
    assert_eq!(coordinator.close_cohort(100), Ok(()));
    let escalation = match coordinator.escalate(&mut tasks, 1_010) {
        Ok(escalation) => escalation,
        Err(error) => unreachable!("a draining lifecycle escalates at its point: {error}"),
    };

    let report = match coordinator.terminate(1_200) {
        Ok(report) => report,
        Err(error) => unreachable!("an escalated lifecycle terminates: {error}"),
    };
    assert_eq!(report.request(), request.id());
    assert_eq!(report.cause(), StopCause::SupervisorRequest);
    assert_eq!(report.grace(), declared);
    assert_eq!(report.grace().grace_us(), 1_000);
    assert_eq!(report.grace().drain_us(), 500);
    assert_eq!(report.cohort(), 2);
    assert_eq!(report.escalated_at_us(), Some(1_010));
    assert_eq!(report.escalated_tasks(), escalation.escalated_tasks());
    assert_eq!(report.preserved_outcomes(), escalation.preserved_outcomes());
    assert_eq!(report.escalated_tasks(), 2);
    assert_eq!(report.preserved_outcomes(), 0);
    assert_eq!(report.terminated_at_us(), 1_200);
    assert!(report.is_escalated());
    assert!(report.canonical_text().contains(report.request().as_str()));

    assert_eq!(coordinator.state(), &StopState::Terminated(report.clone()));
    assert_eq!(coordinator.state().report(), Some(&report));
    assert!(coordinator.state().is_terminal());
    assert_eq!(coordinator.state().phase_name(), "terminated");
    assert_eq!(coordinator.state().landed_name(), "terminated");
    assert_eq!(coordinator.state().rank(), 4);
    assert_eq!(coordinator.durable_cut(), Some(DurableStopCut::Terminated));

    // A repeated termination observes the identical report instead of recomputing it.
    let repeated = match coordinator.terminate(1_900) {
        Ok(report) => report,
        Err(error) => unreachable!("a terminated lifecycle reports its report: {error}"),
    };
    assert_eq!(repeated, report);
    assert_eq!(repeated.terminated_at_us(), 1_200);
    // The accepted repeat advances the watermark, so an earlier instant is now refused
    // while the immutable report itself never moves.
    assert_eq!(coordinator.watermark_us(), 1_900);
    assert_eq!(
        coordinator.terminate(1_100),
        Err(StopError::NonMonotoneInstant {
            presented: 1_100,
            held: 1_900,
        })
    );
    assert_eq!(coordinator.watermark_us(), 1_900);
    assert_eq!(coordinator.state(), &StopState::Terminated(report.clone()));

    // Phases map onto exactly the three landed states, never back onto `running`.
    let states = [
        StopState::Running,
        StopState::StopRequested,
        StopState::Draining,
        StopState::Escalated,
        StopState::Terminated(report),
    ];
    let phases = [
        "running",
        "stop-requested",
        "draining",
        "escalated",
        "terminated",
    ];
    let landed = [
        "running",
        "shutting-down",
        "shutting-down",
        "shutting-down",
        "terminated",
    ];
    let mut previous_rank = None;
    let mut landed_names = BTreeSet::new();
    for (index, state) in states.iter().enumerate() {
        assert_eq!(state.phase_name(), phases[index]);
        assert_eq!(state.landed_name(), landed[index]);
        assert_eq!(state.rank(), index as u8);
        if let Some(previous) = previous_rank {
            assert!(state.rank() > previous);
        }
        previous_rank = Some(state.rank());
        assert_eq!(
            state.is_terminal(),
            matches!(state, StopState::Terminated(_))
        );
        landed_names.insert(state.landed_name());
    }
    assert_eq!(
        landed_names,
        BTreeSet::from(["running", "shutting-down", "terminated"])
    );
    assert_eq!(
        states
            .iter()
            .filter(|state| state.landed_name() == "running")
            .count(),
        1
    );
    assert_eq!(
        states
            .iter()
            .filter(|state| state.landed_name() == "shutting-down")
            .count(),
        3
    );
}

/// `GNT-22.8`: durable cuts advance monotonically and classify recovery.
#[test]
fn durable_cuts_advance_monotonically_and_classify_recovery() {
    assert_eq!(
        DurableStopCut::ALL,
        [
            DurableStopCut::StopRequested,
            DurableStopCut::GraceExpired,
            DurableStopCut::Terminated,
        ]
    );
    assert_eq!(
        DurableStopCut::ALL.map(DurableStopCut::wire_name),
        ["stop-requested", "grace-expired", "terminated"]
    );
    assert_eq!(DurableStopCut::ALL.map(DurableStopCut::rank), [0, 1, 2]);
    for cut in DurableStopCut::ALL {
        assert_eq!(cut.as_str(), cut.wire_name());
        assert_eq!(DurableStopCut::from_wire_name(cut.wire_name()), Some(cut));
    }
    assert_eq!(DurableStopCut::from_wire_name("grace"), None);

    let mut cut = DurableStopCut::StopRequested;
    assert_eq!(cut.advance(DurableStopCut::StopRequested), Ok(()));
    assert_eq!(cut.advance(DurableStopCut::GraceExpired), Ok(()));
    assert_eq!(cut, DurableStopCut::GraceExpired);
    assert_eq!(cut.advance(DurableStopCut::GraceExpired), Ok(()));
    assert_eq!(cut.advance(DurableStopCut::Terminated), Ok(()));
    assert_eq!(
        cut.advance(DurableStopCut::StopRequested),
        Err(StopError::CutRegression {
            current: DurableStopCut::Terminated,
            next: DurableStopCut::StopRequested,
        })
    );
    assert_eq!(cut, DurableStopCut::Terminated);
    assert_eq!(
        cut.advance(DurableStopCut::GraceExpired),
        Err(StopError::CutRegression {
            current: DurableStopCut::Terminated,
            next: DurableStopCut::GraceExpired,
        })
    );
    assert_eq!(cut, DurableStopCut::Terminated);

    // A cut only advances to the next committed cut: a skip over an uncommitted cut is
    // refused exactly like a backwards move, and neither mutates the committed cut.
    let mut skipping = DurableStopCut::StopRequested;
    assert_eq!(
        skipping.advance(DurableStopCut::Terminated),
        Err(StopError::CutRegression {
            current: DurableStopCut::StopRequested,
            next: DurableStopCut::Terminated,
        })
    );
    assert_eq!(skipping, DurableStopCut::StopRequested);
    let mut regressing = DurableStopCut::GraceExpired;
    assert_eq!(
        regressing.advance(DurableStopCut::StopRequested),
        Err(StopError::CutRegression {
            current: DurableStopCut::GraceExpired,
            next: DurableStopCut::StopRequested,
        })
    );
    assert_eq!(regressing, DurableStopCut::GraceExpired);
    assert_eq!(
        skipping
            .advance(DurableStopCut::Terminated)
            .err()
            .map(|error| error.code()),
        Some(StopDiagnosticCode::CutRegression)
    );
    assert_eq!(skipping, DurableStopCut::StopRequested);
    assert_eq!(skipping.advance(DurableStopCut::GraceExpired), Ok(()));
    assert_eq!(skipping, DurableStopCut::GraceExpired);

    assert_eq!(StopCrashCutClassification::ALL.len(), 3);
    assert_eq!(
        DurableStopCut::StopRequested.classify_crash_cut(),
        StopCrashCutClassification::Cooperative
    );
    assert_eq!(
        DurableStopCut::GraceExpired.classify_crash_cut(),
        StopCrashCutClassification::Escalated
    );
    assert_eq!(
        DurableStopCut::Terminated.classify_crash_cut(),
        StopCrashCutClassification::Terminated
    );
    assert!(!StopCrashCutClassification::Cooperative.is_escalation_decided());
    assert!(StopCrashCutClassification::Escalated.is_escalation_decided());
    assert!(StopCrashCutClassification::Terminated.is_escalation_decided());
    for classification in StopCrashCutClassification::ALL {
        assert_eq!(
            classification.is_escalation_decided(),
            matches!(
                classification,
                StopCrashCutClassification::Escalated | StopCrashCutClassification::Terminated
            )
        );
    }

    // The coordinator commits exactly these cuts, in order, and never backwards.
    let declared = policy(1_000, 500);
    let mut coordinator = StopCoordinator::new();
    assert_eq!(coordinator.durable_cut(), None);
    let request = StopRequest::new(StopCause::OperatorSignal, declared, 10);
    assert_eq!(
        coordinator.request_stop(request),
        Ok(StopRequestJoin::Joined)
    );
    assert_eq!(
        coordinator.durable_cut(),
        Some(DurableStopCut::StopRequested)
    );
    assert_eq!(coordinator.close_cohort(20), Ok(()));
    assert_eq!(
        coordinator.durable_cut(),
        Some(DurableStopCut::StopRequested)
    );
    let mut tasks = [TaskStopState::new(OwnerGeneration::initial())];
    assert!(coordinator.escalate(&mut tasks, 1_010).is_ok());
    assert_eq!(
        coordinator.durable_cut(),
        Some(DurableStopCut::GraceExpired)
    );
    assert!(coordinator.terminate(1_200).is_ok());
    assert_eq!(coordinator.durable_cut(), Some(DurableStopCut::Terminated));
    assert_eq!(
        coordinator
            .durable_cut()
            .map(DurableStopCut::classify_crash_cut),
        Some(StopCrashCutClassification::Terminated)
    );
}

/// `GNT-22.9`: late and stale results are fenced without mutating the published outcome.
#[test]
fn late_and_stale_results_are_fenced_without_mutating_the_published_outcome() {
    let generation = OwnerGeneration::initial();
    let foreign = generation.advanced();
    let mut task = TaskStopState::new(generation);
    assert_eq!(task.generation(), generation);
    assert_eq!(task.outcome(), None);
    assert_eq!(task.published_at_us(), None);
    assert!(!task.is_settled());

    // An unsettled task admits only a result of its own owner generation.
    let stale = result(TaskOutcome::Completed, foreign, 5);
    assert_eq!(
        task.publish(&stale),
        Err(StopError::StaleOwnerGeneration {
            presented: foreign,
            held: generation,
        })
    );
    assert_eq!(task.outcome(), None);
    assert_eq!(task.published_at_us(), None);
    assert_eq!(task.generation(), generation);
    assert!(!task.is_settled());

    let accepted = result(TaskOutcome::Completed, generation, 5);
    assert_eq!(task.publish(&accepted), Ok(TaskOutcome::Completed));
    assert_eq!(task.outcome(), Some(TaskOutcome::Completed));
    assert_eq!(task.published_at_us(), Some(5));
    assert_eq!(task.generation(), generation);
    assert!(task.is_settled());

    // The fence classifies: foreign generation first, then lateness, then any other
    // second completion.
    let late = result(TaskOutcome::Failed, generation, 5);
    let late_refusal = StopError::LateResult {
        published: TaskOutcome::Completed,
        published_at_us: 5,
        presented_at_us: 5,
    };
    assert_eq!(
        LateResultFence::check(&task, &late),
        Err(late_refusal.clone())
    );
    assert_eq!(
        LateResultFence::check(&task, &late),
        Err(late_refusal.clone())
    );
    assert_eq!(task.publish(&late), Err(late_refusal.clone()));
    assert_eq!(
        task.publish(&result(TaskOutcome::Cancelled, generation, 4)),
        Err(StopError::LateResult {
            published: TaskOutcome::Completed,
            published_at_us: 5,
            presented_at_us: 4,
        })
    );
    assert_eq!(
        task.publish(&result(TaskOutcome::Failed, generation, 6)),
        Err(StopError::SecondPublication {
            published: TaskOutcome::Completed,
        })
    );
    assert_eq!(
        task.publish(&result(TaskOutcome::Failed, foreign, 100)),
        Err(StopError::StaleOwnerGeneration {
            presented: foreign,
            held: generation,
        })
    );

    // A refusal latches nothing: the same valid-but-late result refuses the same way.
    assert_eq!(task.outcome(), Some(TaskOutcome::Completed));
    assert_eq!(task.published_at_us(), Some(5));
    assert_eq!(task.generation(), generation);
    assert_eq!(
        LateResultFence::check(&task, &late),
        Err(late_refusal.clone())
    );
    assert_eq!(late_refusal.code(), StopDiagnosticCode::LateResult);
    assert_eq!(
        task.publish(&late).err().map(|error| error.requirement()),
        Some(LIFECYCLE_STOP_CLAUSES[9])
    );
    assert_eq!(
        task.publish(&stale).err().map(|error| error.code()),
        Some(StopDiagnosticCode::StaleOwnerGeneration)
    );
}

/// `GNT-22.10`: the non-claim vocabulary is closed and ordered, and no non-claim is a
/// guarantee.
#[test]
fn stop_non_claims_are_closed_ordered_and_refused_as_guarantees() {
    assert_eq!(StopNonClaimName::ALL.len(), 5);
    assert_eq!(STOP_NON_CLAIM_ORDER, StopNonClaimName::ALL);
    assert_eq!(STOP_NON_CLAIM_ORDER.len(), 5);
    assert_eq!(STOP_NON_CLAIMS.len(), 5);

    let mut statements = BTreeSet::new();
    for (index, claim) in STOP_NON_CLAIMS.iter().enumerate() {
        assert_eq!(claim.name(), STOP_NON_CLAIM_ORDER[index]);
        assert!(!claim.statement().is_empty());
        assert!(!claim.statement().trim().is_empty());
        assert!(statements.insert(claim.statement()));
        assert_eq!(
            claim.as_guarantee(),
            Err(StopError::NonClaimAsGuarantee { name: claim.name() })
        );
        assert_eq!(
            claim.as_guarantee().err().map(|error| error.requirement()),
            Some(LIFECYCLE_STOP_CLAUSES[10])
        );
    }
    assert_eq!(statements.len(), 5);

    let mut names = BTreeSet::new();
    for name in StopNonClaimName::ALL {
        assert!(names.insert(name.wire_name()));
        assert_eq!(name.as_str(), name.wire_name());
        assert_eq!(
            StopNonClaimName::from_wire_name(name.wire_name()),
            Some(name)
        );
    }
    assert_eq!(names.len(), 5);
    assert_eq!(StopNonClaimName::from_wire_name("forced-termination"), None);
    assert_eq!(
        StopNonClaimName::from_wire_name("CatchableHardCancellation"),
        None
    );
}

/// `GNT-22.0` .. `GNT-22.10`: the diagnostics are frozen, unique, and each is owned by
/// exactly one clause.
#[test]
fn diagnostic_codes_are_frozen_unique_and_owned_by_exactly_one_clause() {
    assert_eq!(StopDiagnosticCode::ALL.len(), 21);
    assert_eq!(LIFECYCLE_STOP_CLAUSES.len(), 11);

    let clause_keys = BTreeSet::from(LIFECYCLE_STOP_CLAUSES);
    let mut codes = BTreeSet::new();
    let mut owners = BTreeSet::new();
    for code in StopDiagnosticCode::ALL {
        assert!(code.wire_name().starts_with("stop-"));
        assert_eq!(code.as_str(), code.wire_name());
        assert!(!code.meaning().is_empty());
        assert!(codes.insert(code.wire_name()));
        assert!(clause_keys.contains(code.requirement()));
        owners.insert(code.requirement());
    }
    assert_eq!(codes.len(), 21);
    // Every code names exactly one declared clause and every owner key is distinct. The
    // umbrella clause `GNT-22.0` owns no condition of its own, so it owns no code.
    assert_eq!(owners.len(), LIFECYCLE_STOP_CLAUSES.len() - 1);
    assert!(!owners.contains(LIFECYCLE_STOP_CLAUSES[0]));

    // Each code is counted by exactly one clause and every member names the clause that
    // counts it, so the owners partition the frozen registry.
    let mut owned_total = 0;
    for clause in LIFECYCLE_STOP_CLAUSES {
        let members = members_of_clause(clause);
        for member in &members {
            assert_eq!(member.requirement(), clause);
        }
        owned_total += members.len();
    }
    assert_eq!(owned_total, StopDiagnosticCode::ALL.len());

    // The registry is already in sorted code order, so no code needs re-ordering.
    let frozen: Vec<&str> = StopDiagnosticCode::ALL
        .iter()
        .map(|code| code.wire_name())
        .collect();
    let mut sorted = frozen.clone();
    sorted.sort_unstable();
    assert_eq!(frozen, sorted);
    assert_eq!(sorted, codes.iter().copied().collect::<Vec<&str>>());

    // One refusal per frozen code, each naming the clause that owns its condition.
    let declared = policy(1_000, 500);
    let generation = OwnerGeneration::initial();
    let errors = [
        StopError::AdmissionAfterClosure { at_us: 3 },
        StopError::CauseConflict {
            requested: StopCause::SupervisorRequest,
            held: StopCause::OperatorSignal,
        },
        StopError::CohortGrowthAfterClosure { cohort: 6 },
        StopError::CooperativeObservationAfterEscalation {
            safe_point: SafePoint::LoopCondition,
            escalated_at_us: 4,
        },
        StopError::CutRegression {
            current: DurableStopCut::Terminated,
            next: DurableStopCut::StopRequested,
        },
        StopError::EscalationAsDomainOutcome,
        StopError::EscalationBeforeGraceExpiry {
            deadline_us: 1_010,
            presented_at_us: 200,
        },
        StopError::EscalationOverSettledOutcome {
            published: TaskOutcome::Completed,
        },
        StopError::EscalationWithoutStopRequest,
        StopError::LateResult {
            published: TaskOutcome::Failed,
            published_at_us: 7,
            presented_at_us: 7,
        },
        StopError::NonClaimAsGuarantee {
            name: StopNonClaimName::ForcedTerminationReport,
        },
        StopError::NonMonotoneInstant {
            presented: 1,
            held: 2,
        },
        StopError::RedeclaredGrace {
            held: declared,
            presented: policy(2_000, 600),
        },
        StopError::SecondPublication {
            published: TaskOutcome::Cancelled,
        },
        StopError::SourceCleanupAfterEscalation {
            step: Arc::from("source-cleanup"),
        },
        StopError::StaleOwnerGeneration {
            presented: generation.advanced(),
            held: generation,
        },
        StopError::TerminatedCoordinator,
        StopError::TerminationBeforeDrain {
            phase: "stop-requested",
        },
        StopError::UndeclaredGrace {
            grace_us: 0,
            drain_us: 5,
        },
        StopError::UnknownSpelling {
            vocabulary: "stop-cause",
            spelling: Arc::from("sigterm"),
        },
        StopError::WithoutStopRequest {
            transition: StopTransition::CohortClosure,
        },
    ];
    assert_eq!(errors.len(), StopDiagnosticCode::ALL.len());
    assert_eq!(
        errors
            .iter()
            .map(|error| error.code())
            .collect::<BTreeSet<StopDiagnosticCode>>(),
        BTreeSet::from(StopDiagnosticCode::ALL)
    );
    let mut covered = BTreeSet::new();
    for error in &errors {
        assert_eq!(error.code().requirement(), error.requirement());
        assert!(LIFECYCLE_STOP_CLAUSES.contains(&error.requirement()));
        assert!(error.to_string().starts_with(error.code().wire_name()));
        covered.insert(error.requirement());
    }
    // The sample refusals cover exactly the clauses that own a frozen code.
    assert_eq!(covered, owners);
    assert_eq!(
        StopError::EscalationAsDomainOutcome.code(),
        StopDiagnosticCode::EscalationAsDomainOutcome
    );
    assert_eq!(
        StopError::TerminatedCoordinator.requirement(),
        LIFECYCLE_STOP_CLAUSES[7]
    );
    // The unknown-spelling condition is owned by the request identity and cause clause.
    assert_eq!(
        StopError::UnknownSpelling {
            vocabulary: "stop-cause",
            spelling: Arc::from("sigterm"),
        }
        .requirement(),
        LIFECYCLE_STOP_CLAUSES[1]
    );
    assert_eq!(
        members_of_clause(LIFECYCLE_STOP_CLAUSES[1]),
        [
            StopDiagnosticCode::CauseConflict,
            StopDiagnosticCode::UnknownSpelling,
        ]
    );
    // The umbrella clause owns no condition, so no code names it.
    assert!(members_of_clause(LIFECYCLE_STOP_CLAUSES[0]).is_empty());
}
