//! Machine-checked conformance for the wait, wakeup, arbitration, and quiescence model of
//! `SPEC.md` Section 24, clauses `GNT-24.0` .. `GNT-24.10`.
//!
//! These tests exercise the public `gantry::ir` surface of the landed wait model together
//! with the landed `GNT-20` contracts it cites:
//! `GNT-24.0-waits-wakeups-arbitration-and-quiescence`,
//! `GNT-24.1-atomic-registration-and-readiness-recheck`,
//! `GNT-24.2-wait-identity-and-generations`,
//! `GNT-24.3-wake-causes-and-wake-ownership`,
//! `GNT-24.4-stale-wake-fencing-and-waiter-reuse`,
//! `GNT-24.5-producer-loss-and-closure`,
//! `GNT-24.6-select-and-race-snapshots-and-winner-permanence`,
//! `GNT-24.7-losing-arm-ownership-and-nondeterminism`,
//! `GNT-24.8-quiescence-classification`,
//! `GNT-24.9-durable-wait-and-winner-reconstruction`, and
//! `GNT-24.10-wait-non-claims`.
//!
//! Every test is a pure function of its own arguments: no test reads a clock, a process
//! identifier, a thread identity, a host path, an environment fact, or a live host
//! handle, and no test spawns a thread or waits on a handle. Waiter identities, generation
//! fences, arm sets, quiescence facts, and durable cuts are explicit declarations, so
//! every verdict here is reproducible from its own inputs.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use gantry::ir::{
    Arbitration, ArbitrationDecision, ArmDisposition, ArmDispositionKind, ArmId, ArmObservation,
    ArmedAlternative, AuditAccess, CanonicalPath, DurableWaitCut, DurableWaitRecord,
    LogicalOperationId, LosingArmSettlement, PrerequisiteRef, QuiescenceClass, QuiescenceFacts,
    QuiescenceRemedy, ReadinessObservation, RegistrationOutcome, ResourceGenerationId,
    StaticSiteId, StructuralPosition, WAIT_CLAUSES, WAIT_GRAPH_MAX_EDGES, WAIT_GRAPH_MAX_NODES,
    WAIT_NON_CLAIMS, WaitDecision, WaitDiagnosticCode, WaitError, WaitGeneration, WaitId,
    WaitNonClaimAssertion, WaitNonClaimName, WaitOwnerId, WaitRecoveryDecision, WaitRegistration,
    WaitResourceId, WaitSet, WakeCause, WakeOutcome, check_wait_non_claims, classify_quiescence,
    observe_quiescence,
};

/// Compile-time proof that one type implements none of the listed traits.
///
/// A blanket implementation and a trait-bounded implementation both apply, so naming the
/// associated item requires an inference that cannot be resolved and compilation fails. A
/// `Clone` implementation for any affine wait value would stop this crate compiling, which
/// is exactly what `GNT-24.6` and `GNT-24.7` forbid: [`Arbitration`], [`ArbitrationDecision`],
/// [`WakeOutcome`], and [`LosingArmSettlement`] are affine, so one committed arbitration
/// yields exactly one live settlement, that settlement is consumed once, and no second
/// settlement or second decision can be produced from a copy.
macro_rules! assert_not_impl_any {
    ($type:ty: $($trait_name:path),+ $(,)?) => {
        const _: fn() = || {
            trait AmbiguousIfImpl<A> {
                fn some_item() {}
            }
            impl<T: ?Sized> AmbiguousIfImpl<()> for T {}
            $(
                impl<T: ?Sized + $trait_name> AmbiguousIfImpl<Invalid> for T {}
            )+
            struct Invalid;
            let _ = <$type as AmbiguousIfImpl<_>>::some_item;
        };
    };
}

assert_not_impl_any!(LosingArmSettlement: Clone);
assert_not_impl_any!(Arbitration: Clone);
assert_not_impl_any!(ArbitrationDecision: Clone);
assert_not_impl_any!(WakeOutcome: Clone);

/// One canonical workflow path declared by a test fixture.
fn canonical(value: &str) -> CanonicalPath {
    match CanonicalPath::new(value) {
        Ok(path) => path,
        Err(error) => panic!("the declared path {value} is canonical: {error:?}"),
    }
}

/// One declared static site of a test fixture.
fn site() -> StaticSiteId {
    match StructuralPosition::new(vec![0, 1]) {
        Ok(position) => StaticSiteId::new(canonical("crate::main"), position),
        Err(error) => panic!("the declared position is nonempty: {error:?}"),
    }
}

/// One landed resource generation of one operation, site, and counter
/// (`GNT-20.2-logical-operation-and-resource-generation-identity`).
fn generation(counter: u64) -> ResourceGenerationId {
    let site = site();
    let operation = LogicalOperationId::derive(&canonical("crate::read"), &site);
    ResourceGenerationId::derive(&operation, &site, counter)
}

/// One declared owning-task identity (`GNT-3-M-LIFECYCLES`).
fn owner(task: &str) -> WaitOwnerId {
    match WaitOwnerId::new(task) {
        Ok(owner) => owner,
        Err(error) => panic!("the declared owner {task} is named: {error}"),
    }
}

/// One declared waitable-resource identity.
fn resource(name: &str) -> WaitResourceId {
    match WaitResourceId::new(name) {
        Ok(resource) => resource,
        Err(error) => panic!("the declared resource {name} is named: {error}"),
    }
}

/// One declared arbitration arm key.
fn arm(key: &str) -> ArmId {
    match ArmId::new(key) {
        Ok(arm) => arm,
        Err(error) => panic!("the declared arm {key} is named: {error}"),
    }
}

/// One declared external prerequisite key.
fn prerequisite(key: &str) -> PrerequisiteRef {
    match PrerequisiteRef::new(key) {
        Ok(key) => key,
        Err(error) => panic!("the declared prerequisite {key} is named: {error}"),
    }
}

/// The first fence of a waiter slot.
fn fence() -> WaitGeneration {
    WaitGeneration::FIRST
}

/// The next fence of the same waiter slot.
fn next_fence() -> WaitGeneration {
    match WaitGeneration::FIRST.succeeding() {
        Ok(next) => next,
        Err(error) => panic!("the declared fence advances: {error}"),
    }
}

/// Derives one waiter identity from declared fields only.
fn waiter(task: &str, name: &str, ordinal: u32, fence: WaitGeneration) -> WaitId {
    waiter_of(task, name, ordinal, fence, generation(1))
}

/// Derives one waiter identity for one declared landed resource generation.
fn waiter_of(
    task: &str,
    name: &str,
    ordinal: u32,
    fence: WaitGeneration,
    resource_generation: ResourceGenerationId,
) -> WaitId {
    WaitId::derive(
        &owner(task),
        &resource(name),
        &resource_generation,
        fence,
        ordinal,
    )
}

/// Declares one registration of one waiter slot.
fn registration(task: &str, name: &str, ordinal: u32, fence: WaitGeneration) -> WaitRegistration {
    registration_of(task, name, ordinal, fence, generation(1))
}

/// Declares one registration of one waiter slot that observes one landed resource generation.
fn registration_of(
    task: &str,
    name: &str,
    ordinal: u32,
    fence: WaitGeneration,
    resource_generation: ResourceGenerationId,
) -> WaitRegistration {
    WaitRegistration::new(
        waiter_of(task, name, ordinal, fence, resource_generation.clone()),
        owner(task),
        resource(name),
        resource_generation,
        fence,
        ordinal,
    )
}

/// Registers one declared wait in one wait set after its atomic step published registration.
fn registered(waits: &mut WaitSet, registration: &mut WaitRegistration) -> WaitId {
    match registration.register_and_recheck(ReadinessObservation::NotReady) {
        Ok(RegistrationOutcome::Registered) => {}
        other => panic!("a not-ready recheck registers: {other:?}"),
    }
    match waits.register(registration) {
        Ok(()) => registration.id().clone(),
        Err(error) => panic!("a registered wait is admitted: {error}"),
    }
}

/// Opens and decides one declared arm set, returning the committed arbitration.
fn committed_arbitration(
    arms: Vec<ArmedAlternative>,
    observations: &[ArmObservation],
) -> Arbitration {
    let arbitration = match Arbitration::open(arms) {
        Ok(arbitration) => arbitration,
        Err(error) => panic!("the declared arm set opens: {error}"),
    };
    match arbitration.decide(observations) {
        Ok(ArbitrationDecision::Committed(arbitration)) => arbitration,
        other => panic!("the declared observation set decides a winner: {other:?}"),
    }
}

/// Opens and decides one declared arm set, returning the refusal of its decision.
fn refused_decision(arms: Vec<ArmedAlternative>, observations: &[ArmObservation]) -> WaitError {
    let arbitration = match Arbitration::open(arms) {
        Ok(arbitration) => arbitration,
        Err(error) => panic!("the declared arm set opens: {error}"),
    };
    match arbitration.decide(observations) {
        Ok(other) => panic!("the declared observations are refused, not {other:?}"),
        Err(error) => error,
    }
}

/// Opens, decides, and settles one declared arm set, returning the refusal of its settlement.
fn refused_settlement(dispositions: &[ArmDisposition]) -> WaitError {
    let arbitration = committed_arbitration(
        vec![
            ArmedAlternative::new(
                arm("first"),
                waiter("crate::main", "std.net.read", 7, fence()),
            ),
            ArmedAlternative::new(
                arm("second"),
                waiter("crate::worker", "std.net.read", 7, fence()),
            ),
        ],
        &[ArmObservation::new(arm("second"), WakeCause::Timeout)],
    );
    let settlement = match arbitration.into_losing_settlement() {
        Ok(settlement) => settlement,
        Err(error) => panic!("a decided arbitration yields a settlement: {error}"),
    };
    match settlement.settle(dispositions) {
        Ok(report) => panic!("the declared dispositions are refused, not {report:?}"),
        Err(error) => error,
    }
}

/// Returns one quiescence-fact set, or fails with the declared refusal.
#[allow(clippy::too_many_arguments)]
fn facts(
    live: usize,
    internal: usize,
    external: usize,
    admitted: usize,
    resumable: usize,
    orphaned: usize,
) -> QuiescenceFacts {
    match QuiescenceFacts::new(live, internal, external, admitted, resumable, orphaned) {
        Ok(facts) => facts,
        Err(error) => panic!("the declared quiescence facts are well formed: {error}"),
    }
}

/// Returns the workspace root of the conformance crate.
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Reads one file of the workspace, or fails with its path.
fn read(path: &Path) -> String {
    match fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) => panic!("could not read {}: {error}", path.display()),
    }
}

/// Returns the declared text of one clause, from its own anchor to the next anchor, with runs
/// of layout whitespace collapsed so an assertion does not depend on where a line wraps.
fn clause_text(specification: &str, anchor: &str, next: &str) -> String {
    let declared = format!("<a id=\"{anchor}\"></a>");
    let start = match specification.find(&declared) {
        Some(start) => start,
        None => panic!("SPEC.md does not declare the anchor {anchor}"),
    };
    let rest = &specification[start..];
    let following = format!("<a id=\"{next}\"></a>");
    let end = rest.find(&following).unwrap_or(rest.len());
    rest[..end].split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The eleven clauses of `GNT-24.0-waits-wakeups-arbitration-and-quiescence`, in order.
const WAIT_ANCHORS: [&str; 11] = [
    "GNT-24.0-waits-wakeups-arbitration-and-quiescence",
    "GNT-24.1-atomic-registration-and-readiness-recheck",
    "GNT-24.2-wait-identity-and-generations",
    "GNT-24.3-wake-causes-and-wake-ownership",
    "GNT-24.4-stale-wake-fencing-and-waiter-reuse",
    "GNT-24.5-producer-loss-and-closure",
    "GNT-24.6-select-and-race-snapshots-and-winner-permanence",
    "GNT-24.7-losing-arm-ownership-and-nondeterminism",
    "GNT-24.8-quiescence-classification",
    "GNT-24.9-durable-wait-and-winner-reconstruction",
    "GNT-24.10-wait-non-claims",
];

/// `GNT-24.0`: the section publishes exactly its eleven clause anchors, in clause order.
#[test]
fn section_publishes_the_eleven_wait_clause_anchors_in_order() {
    assert_eq!(WAIT_CLAUSES, WAIT_ANCHORS);
    let specification = read(&workspace_root().join("SPEC.md"));
    let mut offset = 0_usize;
    for anchor in WAIT_ANCHORS {
        let declared = format!("<a id=\"{anchor}\"></a>");
        let found = specification
            .find(&declared)
            .unwrap_or_else(|| panic!("SPEC.md does not declare the anchor {anchor}"));
        assert!(
            found >= offset,
            "the anchor {anchor} is declared out of clause order"
        );
        offset = found;
    }
    assert_eq!(WaitDiagnosticCode::ALL.len(), 39);
}

/// `GNT-24.1`: registration and the readiness recheck are one atomic step, so a wake that
/// linearizes at or before the step is consumed as readiness rather than lost, and a
/// suspension is admitted only by the decision that step published.
#[test]
fn registration_and_readiness_recheck_linearize_before_suspension() {
    let mut pending = registration("crate::main", "std.io.read", 1, fence());
    match pending.admit_suspension() {
        Err(error) => assert_eq!(error.code(), WaitDiagnosticCode::SuspensionWithoutRecheck),
        Ok(()) => panic!("a suspension before the atomic step is refused"),
    }
    assert_eq!(
        pending.register_and_recheck(ReadinessObservation::NotReady),
        Ok(RegistrationOutcome::Registered)
    );
    assert!(pending.is_registered());
    assert_eq!(pending.admit_suspension(), Ok(()));
    match pending.register_and_recheck(ReadinessObservation::NotReady) {
        Err(error) => assert_eq!(error.code(), WaitDiagnosticCode::RegistrationAlreadyDecided),
        Ok(outcome) => panic!("one wait has one atomic step, not {outcome:?}"),
    }

    // A wake that linearizes at the step is the readiness the step publishes.
    let mut ready = registration("crate::main", "std.io.read", 2, fence());
    assert_eq!(
        ready.register_and_recheck(ReadinessObservation::Ready(WakeCause::Delivery)),
        Ok(RegistrationOutcome::AlreadyReady(WakeCause::Delivery))
    );
    match ready.admit_suspension() {
        Err(error) => assert_eq!(error.code(), WaitDiagnosticCode::SuspensionAfterReadiness),
        Ok(()) => panic!("a suspension after readiness would lose the observed wake"),
    }
    let mut waits = WaitSet::new();
    match waits.register(&ready) {
        Err(error) => assert_eq!(error.code(), WaitDiagnosticCode::SuspensionAfterReadiness),
        Ok(()) => panic!("an already-ready wait is consumed rather than registered"),
    }

    // The step publishes whichever member of the closed cause set the recheck observed: a
    // task settlement of the awaited value is the delivery cause, and a stop request of
    // `GNT-22.1` is the stop-request cause, which stays distinct from cancellation.
    let mut settled = registration("crate::main", "std.io.read", 4, fence());
    assert_eq!(
        settled.register_and_recheck(ReadinessObservation::Ready(WakeCause::Delivery)),
        Ok(RegistrationOutcome::AlreadyReady(WakeCause::Delivery))
    );
    assert_eq!(settled.ready_cause(), Some(WakeCause::Delivery));
    let mut stopped = registration("crate::main", "std.io.read", 5, fence());
    assert_eq!(
        stopped.register_and_recheck(ReadinessObservation::Ready(WakeCause::StopRequest)),
        Ok(RegistrationOutcome::AlreadyReady(WakeCause::StopRequest))
    );
    assert_eq!(stopped.ready_cause(), Some(WakeCause::StopRequest));
    assert_eq!(
        ReadinessObservation::Ready(WakeCause::StopRequest).cause(),
        Some(WakeCause::StopRequest)
    );
    assert!(!ReadinessObservation::NotReady.is_ready());

    // A wake that linearizes after the step is delivered to the registered waiter.
    let mut suspended = registration("crate::main", "std.io.read", 3, fence());
    let id = registered(&mut waits, &mut suspended);
    assert!(waits.is_live(&id));
    assert_eq!(
        waits
            .wake(&id, fence(), WakeCause::Delivery)
            .map(|r| r.cause()),
        Ok(WakeCause::Delivery)
    );
    assert_eq!(waits.winner(&id), Some(WakeCause::Delivery));
}

/// `GNT-24.2`: a waiter identity is derived from declared fields only, it carries the
/// owning task, the waitable-resource generation, and one monotone fence, and the
/// wake-cause vocabulary is closed.
#[test]
fn wait_identity_fences_a_reused_slot_by_declared_registration() {
    assert_eq!(
        waiter("crate::main", "std.io.read", 1, fence()),
        waiter("crate::main", "std.io.read", 1, fence())
    );
    assert_ne!(
        waiter("crate::main", "std.io.read", 1, fence()),
        waiter("crate::main", "std.io.read", 2, fence())
    );
    assert_ne!(
        waiter("crate::main", "std.io.read", 1, fence()),
        waiter("crate::main", "std.io.read", 1, next_fence())
    );
    assert_ne!(
        waiter("crate::main", "std.io.read", 1, fence()),
        waiter("crate::worker", "std.io.read", 1, fence())
    );
    assert_ne!(
        waiter("crate::main", "std.io.read", 1, fence()),
        waiter("crate::main", "std.io.write", 1, fence())
    );
    let declared = waiter("crate::main", "std.io.read", 1, fence());
    assert!(declared.as_str().starts_with("wait:"));
    assert_eq!(declared.digest_hex().len(), 64);

    let earlier = fence();
    let later = next_fence();
    assert!(later.observes(later) && !later.observes(earlier));
    assert!(later.retires(earlier) && earlier.retires(earlier) && !earlier.retires(later));
    assert_eq!(later.value(), earlier.value() + 1);

    assert_eq!(WakeCause::ALL.len(), 5);
    let causes = WakeCause::ALL
        .iter()
        .map(|cause| cause.wire_name())
        .collect::<BTreeSet<_>>();
    assert_eq!(causes.len(), 5);
    for cause in WakeCause::ALL {
        assert_eq!(WakeCause::from_wire_name(cause.as_str()), Some(cause));
        assert!(!cause.meaning().is_empty());
        assert_eq!(
            cause.requirement(),
            "GNT-24.3-wake-causes-and-wake-ownership"
        );
    }

    // `GNT-24.2` enumerates exactly the inputs this model hashes: the owning task, the
    // waitable resource, the landed resource generation, the declared registration ordinal,
    // and the declared waiter-generation fence, and it says nothing else enters. The fence
    // is named in the clause because the model hashes it, so the text and the digest agree.
    let specification = read(&workspace_root().join("SPEC.md"));
    let identity = clause_text(&specification, WAIT_ANCHORS[2], WAIT_ANCHORS[3]);
    assert!(
        identity.contains("one declared registration ordinal of the waiter slot"),
        "GNT-24.2 names the registration ordinal as a derivation input"
    );
    assert!(
        identity.contains("one declared waiter-generation fence"),
        "GNT-24.2 names the waiter-generation fence as a derivation input"
    );
    assert!(
        identity.contains("and from nothing else"),
        "GNT-24.2 closes the derivation input set"
    );
    assert_eq!(
        registration("crate::main", "std.io.read", 7, fence()).ordinal(),
        7
    );
}

/// `GNT-24.3`: the wake-cause vocabulary is closed, and one wake has exactly one owner and
/// one wait has exactly one source-visible winner.
#[test]
fn wake_causes_are_closed_and_each_wake_has_exactly_one_owner() {
    assert_eq!(
        WakeCause::ALL.map(WakeCause::wire_name),
        [
            "delivery",
            "resource-closure",
            "cancellation",
            "stop-request",
            "timeout"
        ]
    );
    assert_eq!(WakeCause::from_wire_name("unspecified"), None);
    assert_eq!(WakeCause::from_wire_name("waiter-removal"), None);
    assert_eq!(
        WakeCause::from_wire_name("delivery"),
        Some(WakeCause::Delivery)
    );
    assert_eq!(
        WakeCause::from_wire_name("stop-request"),
        Some(WakeCause::StopRequest)
    );
    assert_eq!(WakeCause::ALL.map(WakeCause::rank), [0, 1, 2, 3, 4]);

    let mut waits = WaitSet::new();
    let mut first = registration("crate::main", "std.io.read", 1, fence());
    let first_id = registered(&mut waits, &mut first);
    let mut second = registration("crate::worker", "std.io.read", 1, fence());
    let second_id = registered(&mut waits, &mut second);
    assert_ne!(first_id, second_id);

    assert_eq!(
        waits
            .wake(&first_id, fence(), WakeCause::Delivery)
            .map(|r| r.cause()),
        Ok(WakeCause::Delivery)
    );
    assert_eq!(waits.winner(&first_id), Some(WakeCause::Delivery));
    assert_eq!(waits.winner(&second_id), None);
    assert!(waits.is_live(&second_id));
    match waits.wake(&first_id, fence(), WakeCause::Cancellation) {
        Err(error) => assert_eq!(error.code(), WaitDiagnosticCode::SecondWake),
        Ok(record) => panic!("a second wake is refused, not {record:?}"),
    }
    assert_eq!(waits.winner(&first_id), Some(WakeCause::Delivery));

    let mut outcome = match WakeOutcome::pending(&second) {
        Ok(outcome) => outcome,
        Err(error) => panic!("a decided registration opens an outcome: {error}"),
    };
    match outcome.require_winner() {
        Err(error) => assert_eq!(error.code(), WaitDiagnosticCode::NoWinnerYet),
        Ok(cause) => panic!("an unsettled outcome has no winner, not {cause}"),
    }
    assert_eq!(outcome.wake(WakeCause::Timeout), Ok(WakeCause::Timeout));
    match outcome.wake(WakeCause::Delivery) {
        Err(error) => assert_eq!(error.code(), WaitDiagnosticCode::SecondWake),
        Ok(cause) => panic!("a later wake never becomes a second winner, not {cause}"),
    }
    assert_eq!(outcome.winner(), Some(WakeCause::Timeout));
    assert_eq!(outcome.wait(), &second_id);
    assert_eq!(outcome.generation(), fence());

    // A stop request of `GNT-22.1` is one of the five causes and never a cancellation, and
    // a task settlement of the awaited value is the delivery cause, so neither needs a
    // sixth cause and neither is reclassified.
    assert_ne!(WakeCause::StopRequest, WakeCause::Cancellation);
    assert_eq!(
        waits
            .wake(&second_id, fence(), WakeCause::StopRequest)
            .map(|record| record.cause()),
        Ok(WakeCause::StopRequest)
    );
    assert_eq!(waits.winner(&second_id), Some(WakeCause::StopRequest));
    assert!(
        waits
            .settlement(&second_id, fence())
            .is_some_and(|record| record.cause() == WakeCause::StopRequest),
        "the recorded settlement names the stop request it was woken by"
    );
    assert!(!waits.is_live(&second_id));
}

/// `GNT-24.4`: a stale or duplicate wake cannot resume a reused waiter, fencing and reuse
/// are one-way, a registration never moves a slot backwards in ordinal or fence, and every
/// refusal names the waiter, the held fence, and the presented fence.
#[test]
fn stale_and_duplicate_wakes_cannot_resume_a_reused_waiter() {
    let mut waits = WaitSet::new();
    let name = "std.io.read";
    let mut first = registration("crate::main", name, 1, fence());
    let id = registered(&mut waits, &mut first);

    match waits.wake(&id, next_fence(), WakeCause::Delivery) {
        Err(error) => {
            assert_eq!(error.code(), WaitDiagnosticCode::StaleWake);
            assert_eq!(error.wait(), Some(&id));
            assert_eq!(error.held_fence(), Some(fence()));
            assert_eq!(error.presented_fence(), Some(next_fence()));
            assert_eq!(
                error.requirement(),
                "GNT-24.4-stale-wake-fencing-and-waiter-reuse"
            );
        }
        Ok(record) => panic!("a wake of an unheld fence is refused, not {record:?}"),
    }
    assert_eq!(waits.live_count(), 1);

    // Waiter removal by its own owner is a withdrawal rather than a wake: it settles no
    // cause, reports no winner, and retires the fence.
    let withdrawal = match waits.remove_waiter(&id, fence()) {
        Ok(withdrawal) => withdrawal,
        Err(error) => panic!("the owner withdraws its own live wait: {error}"),
    };
    assert_eq!(withdrawal.wait(), &id);
    assert_eq!(withdrawal.generation(), fence());
    assert_eq!(
        withdrawal.requirement(),
        "GNT-24.5-producer-loss-and-closure"
    );
    assert_eq!(waits.winner(&id), None);
    assert_eq!(waits.live_count(), 0);

    // A wake of a fence the slot already retired is stale, and never a wake of a sixth
    // cause and never a duplicate of a wake that was never applied.
    match waits.wake(&id, fence(), WakeCause::Delivery) {
        Err(error) => {
            assert_eq!(error.code(), WaitDiagnosticCode::StaleWake);
            assert_eq!(error.wait(), Some(&id));
            assert_eq!(error.held_fence(), Some(fence()));
            assert_eq!(error.presented_fence(), Some(fence()));
        }
        Ok(record) => panic!("a withdrawn fence is never revived, not {record:?}"),
    }

    let mut reused = registration("crate::main", name, 2, fence());
    match reused.register_and_recheck(ReadinessObservation::NotReady) {
        Ok(RegistrationOutcome::Registered) => {}
        other => panic!("a not-ready recheck registers: {other:?}"),
    }
    match waits.register(&reused) {
        Err(error) => {
            assert_eq!(error.code(), WaitDiagnosticCode::StaleRegistration);
            assert_eq!(error.wait(), Some(reused.id()));
            assert_eq!(error.held_fence(), Some(fence()));
            assert_eq!(error.presented_fence(), Some(fence()));
        }
        Ok(()) => panic!("a registration of a retired fence is refused"),
    }

    // A reused slot may not return to an earlier registration ordinal, even when the
    // presented fence moves strictly forward, so the ordinal is tracked and refused.
    let mut earlier = registration("crate::main", name, 1, next_fence());
    match earlier.register_and_recheck(ReadinessObservation::NotReady) {
        Ok(RegistrationOutcome::Registered) => {}
        other => panic!("a not-ready recheck registers: {other:?}"),
    }
    match waits.register(&earlier) {
        Err(error) => {
            assert_eq!(
                error.code(),
                WaitDiagnosticCode::RegistrationOrdinalRegression
            );
            assert_eq!(
                error.requirement(),
                "GNT-24.4-stale-wake-fencing-and-waiter-reuse"
            );
        }
        Ok(()) => panic!("a reused slot never returns to an earlier registration ordinal"),
    }
    assert_eq!(waits.live_count(), 0);

    let mut fresh = registration("crate::main", name, 2, next_fence());
    let fresh_id = registered(&mut waits, &mut fresh);
    assert_ne!(fresh_id, id);
    match waits.wake(&id, next_fence(), WakeCause::Delivery) {
        Err(error) => {
            assert_eq!(error.code(), WaitDiagnosticCode::StaleWake);
            assert_eq!(error.wait(), Some(&id));
            assert_eq!(error.held_fence(), Some(next_fence()));
            assert_eq!(error.presented_fence(), Some(next_fence()));
        }
        Ok(record) => panic!("the predecessor fence never resumes the reused waiter, {record:?}"),
    }
    assert_eq!(
        waits
            .wake(&fresh_id, next_fence(), WakeCause::Delivery)
            .map(|r| r.cause()),
        Ok(WakeCause::Delivery)
    );
    assert_eq!(waits.live_count(), 0);

    // A duplicate of the wake already applied to that wait is a second wake, and the
    // refusal names the waiter, the held fence, and the presented fence.
    match waits.wake(&fresh_id, next_fence(), WakeCause::Timeout) {
        Err(error) => {
            assert_eq!(error.code(), WaitDiagnosticCode::SecondWake);
            assert_eq!(error.wait(), Some(&fresh_id));
            assert_eq!(error.held_fence(), Some(next_fence()));
            assert_eq!(error.presented_fence(), Some(next_fence()));
        }
        Ok(record) => panic!("a duplicate wake is refused, not {record:?}"),
    }
    assert_eq!(waits.winner(&fresh_id), Some(WakeCause::Delivery));

    // The reused slot has moved past the predecessor fence, so presenting it is the stale
    // wake of a reused waiter rather than a duplicate wake of the live wait.
    match waits.wake(&id, fence(), WakeCause::Delivery) {
        Err(error) => {
            assert_eq!(error.code(), WaitDiagnosticCode::StaleWake);
            assert_eq!(error.wait(), Some(&id));
            assert_eq!(error.held_fence(), Some(next_fence()));
            assert_eq!(error.presented_fence(), Some(fence()));
        }
        Ok(record) => {
            panic!("a reused slot never accepts the fence of its predecessor, {record:?}")
        }
    }

    let unknown = waiter("crate::other", name, 1, fence());
    match waits.wake(&unknown, fence(), WakeCause::Delivery) {
        Err(error) => {
            assert_eq!(error.code(), WaitDiagnosticCode::UnknownWaiter);
            assert_eq!(error.wait(), Some(&unknown));
            assert_eq!(error.held_fence(), None);
            assert_eq!(error.presented_fence(), Some(fence()));
        }
        Ok(record) => panic!("an unknown waiter is refused, not {record:?}"),
    }
}

/// `GNT-24.5`: dropping the last producer closes the resource generation, closure settles
/// every dependent wait instead of leaving an unclassifiable one, and a repeated closure is
/// refused.
#[test]
fn producer_loss_closes_dependent_waiters_without_unclassifiable_waits() {
    let mut waits = WaitSet::new();
    let name = "std.io.read";
    let mut settled = registration("crate::main", name, 1, fence());
    let settled_id = registered(&mut waits, &mut settled);
    assert_eq!(
        waits
            .wake(&settled_id, fence(), WakeCause::Delivery)
            .map(|r| r.cause()),
        Ok(WakeCause::Delivery)
    );
    let mut dependent = registration("crate::worker", name, 1, fence());
    let dependent_id = registered(&mut waits, &mut dependent);
    assert_eq!(waits.live_for(&resource(name)), 1);

    // Closure is keyed by the landed resource generation of `GNT-20.2` that the waiting
    // registrations carry, so a second live wait of the same resource that observes another
    // generation is not settled by this closure.
    let mut later = registration_of("crate::reader", name, 1, fence(), generation(2));
    let later_id = registered(&mut waits, &mut later);
    assert_eq!(waits.live_for(&resource(name)), 2);

    let report = match waits.close_resource(&resource(name), &generation(1)) {
        Ok(report) => report,
        Err(error) => panic!("the known resource closes: {error}"),
    };
    assert!(report.is_classified());
    assert_eq!(report.resource(), &resource(name));
    assert_eq!(report.generation(), &generation(1));
    assert_eq!(report.closed().len(), 1);
    assert_eq!(report.closed()[0].wait(), &dependent_id);
    assert_eq!(report.closed()[0].cause(), WakeCause::ResourceClosure);
    assert_eq!(report.preserved().len(), 1);
    assert_eq!(report.preserved()[0].wait(), &settled_id);
    assert_eq!(report.preserved()[0].cause(), WakeCause::Delivery);
    assert_eq!(waits.live_for(&resource(name)), 1);
    assert!(waits.is_live(&later_id));
    assert_eq!(waits.winner(&later_id), None);
    assert!(waits.is_closed(&resource(name), &generation(1)));
    assert!(!waits.is_closed(&resource(name), &generation(2)));
    assert_eq!(waits.unclassifiable_count(), 0);
    assert_eq!(
        waits.winner(&dependent_id),
        Some(WakeCause::ResourceClosure)
    );

    // A closure of a generation the wait set does not know is refused with its own
    // condition rather than treated as a new or repeated closure.
    match waits.close_resource(&resource(name), &generation(9)) {
        Err(error) => assert_eq!(error.code(), WaitDiagnosticCode::UnknownResourceGeneration),
        Ok(report) => panic!("an unknown resource generation is refused, not {report:?}"),
    }
    match waits.close_resource(&resource(name), &generation(1)) {
        Err(error) => assert_eq!(error.code(), WaitDiagnosticCode::RepeatedClosure),
        Ok(report) => panic!("a repeated closure is refused, not {report:?}"),
    }
    let mut after_closure = registration("crate::main", name, 3, next_fence());
    match after_closure.register_and_recheck(ReadinessObservation::NotReady) {
        Ok(RegistrationOutcome::Registered) => {}
        other => panic!("a not-ready recheck registers: {other:?}"),
    }
    match waits.register(&after_closure) {
        Err(error) => assert_eq!(error.code(), WaitDiagnosticCode::RegistrationAfterClosure),
        Ok(()) => panic!("a registration for a closed resource is refused"),
    }
    match waits.close_resource(&resource("std.io.write"), &generation(1)) {
        Err(error) => assert_eq!(error.code(), WaitDiagnosticCode::UnknownResource),
        Ok(report) => panic!("an unknown resource is refused, not {report:?}"),
    }

    let mut removed = registration("crate::other", "std.io.write", 1, fence());
    let removed_id = registered(&mut waits, &mut removed);
    let withdrawal = match waits.remove_waiter(&removed_id, fence()) {
        Ok(withdrawal) => withdrawal,
        Err(error) => panic!("the owner withdraws its own live wait: {error}"),
    };
    assert_eq!(withdrawal.wait(), &removed_id);
    assert_eq!(waits.winner(&removed_id), None);
    assert!(!waits.is_live(&removed_id));
}

/// `GNT-24.6`: one `select` or `race` freezes one snapshot, a tie is decided by the
/// declared arm order, and a committed winner is never re-chosen.
#[test]
fn arbitration_freezes_a_snapshot_and_keeps_one_permanent_winner() {
    let arbitration = match Arbitration::open(vec![
        ArmedAlternative::new(
            arm("first"),
            waiter("crate::main", "std.net.read", 1, fence()),
        ),
        ArmedAlternative::new(
            arm("second"),
            waiter("crate::worker", "std.net.read", 1, fence()),
        ),
    ]) {
        Ok(arbitration) => arbitration,
        Err(error) => panic!("the declared arm set opens: {error}"),
    };
    assert_eq!(arbitration.snapshot().arm_count(), 2);
    let arbitration = match arbitration.decide(&[]) {
        Ok(ArbitrationDecision::Unresolved(arbitration)) => arbitration,
        other => panic!("no eligible arm leaves the arbitration unresolved: {other:?}"),
    };
    assert!(arbitration.winner().is_none());

    let observations = [
        ArmObservation::new(arm("second"), WakeCause::Delivery),
        ArmObservation::new(arm("first"), WakeCause::Delivery),
    ];
    let decision = match arbitration.decide(&observations) {
        Ok(decision) => decision,
        other => panic!("the declared observations decide a winner: {other:?}"),
    };
    assert!(decision.is_committed());
    let winner = match decision.winner() {
        Some(winner) => winner,
        None => panic!("a committed decision records one winner"),
    };
    assert_eq!(winner.arm(), &arm("first"));
    assert_eq!(winner.position(), 0);
    assert_eq!(winner.contending().len(), 2);
    assert!(winner.was_tie());

    let arbitration = decision.into_arbitration();
    assert_eq!(
        arbitration.winner().map(|winner| winner.arm().clone()),
        Some(arm("first"))
    );
    match arbitration.decide(&observations) {
        Err(error) => assert_eq!(error.code(), WaitDiagnosticCode::WinnerAlreadyCommitted),
        Ok(other) => panic!("a second decision is refused, not {other:?}"),
    }

    // A decision consumes the arbitration, so each refused observation set is presented to
    // its own freshly opened arbitration, and no refusal commits a winner.
    let only = || {
        vec![ArmedAlternative::new(
            arm("only"),
            waiter("crate::main", "std.net.read", 2, fence()),
        )]
    };
    assert_eq!(
        refused_decision(
            only(),
            &[ArmObservation::new(arm("other"), WakeCause::Delivery)]
        )
        .code(),
        WaitDiagnosticCode::ArmOutsideSnapshot
    );
    assert_eq!(
        refused_decision(
            only(),
            &[
                ArmObservation::new(arm("only"), WakeCause::Delivery),
                ArmObservation::new(arm("only"), WakeCause::Timeout),
            ]
        )
        .code(),
        WaitDiagnosticCode::DuplicateObservation
    );
    let fresh = match Arbitration::open(only()) {
        Ok(arbitration) => arbitration,
        Err(error) => panic!("the declared arm set opens: {error}"),
    };
    assert!(fresh.winner().is_none());

    match Arbitration::open(Vec::new()) {
        Err(error) => assert_eq!(error.code(), WaitDiagnosticCode::EmptyArbitration),
        Ok(other) => panic!("an empty arm set is refused, not {other:?}"),
    }
    match Arbitration::open(vec![
        ArmedAlternative::new(
            arm("same"),
            waiter("crate::main", "std.net.read", 3, fence()),
        ),
        ArmedAlternative::new(
            arm("same"),
            waiter("crate::worker", "std.net.read", 3, fence()),
        ),
    ]) {
        Err(error) => assert_eq!(error.code(), WaitDiagnosticCode::DuplicateArm),
        Ok(other) => panic!("a repeated arm key is refused, not {other:?}"),
    }
    match Arbitration::open(vec![
        ArmedAlternative::new(
            arm("first"),
            waiter("crate::main", "std.net.read", 4, fence()),
        ),
        ArmedAlternative::new(
            arm("second"),
            waiter("crate::main", "std.net.read", 4, fence()),
        ),
    ]) {
        Err(error) => {
            assert_eq!(error.code(), WaitDiagnosticCode::RepeatedArmedAlternative);
            assert_ne!(error.code(), WaitDiagnosticCode::DuplicateWaiter);
            assert_eq!(
                error.requirement(),
                "GNT-24.6-select-and-race-snapshots-and-winner-permanence"
            );
        }
        Ok(other) => panic!("a repeated armed alternative is refused, not {other:?}"),
    }
}

/// `GNT-24.7`: every losing arm receives exactly one declared disposition, the settlement
/// is affine, and application nondeterminism is permitted only inside the declared
/// envelope.
#[test]
fn losing_arms_settle_ownership_inside_the_nondeterminism_envelope() {
    assert_not_impl_any!(LosingArmSettlement: Clone);

    let arms = vec![
        ArmedAlternative::new(
            arm("first"),
            waiter("crate::main", "std.net.read", 1, fence()),
        ),
        ArmedAlternative::new(
            arm("second"),
            waiter("crate::worker", "std.net.read", 1, fence()),
        ),
        ArmedAlternative::new(
            arm("third"),
            waiter("crate::reader", "std.net.read", 1, fence()),
        ),
    ];
    let arbitration = match Arbitration::open(arms) {
        Ok(arbitration) => arbitration,
        Err(error) => panic!("the declared arm set opens: {error}"),
    };
    let eligible = [
        ArmObservation::new(arm("third"), WakeCause::Delivery),
        ArmObservation::new(arm("first"), WakeCause::Delivery),
    ];
    let envelope = match arbitration.envelope(&eligible) {
        Ok(envelope) => envelope,
        Err(error) => panic!("the declared observations are inside the snapshot: {error}"),
    };
    assert!(envelope.permits(&arm("first")) && envelope.permits(&arm("third")));
    assert!(!envelope.permits(&arm("second")));
    assert!(!envelope.is_deterministic());
    match arbitration.envelope(&[ArmObservation::new(arm("absent"), WakeCause::Delivery)]) {
        Err(error) => assert_eq!(error.code(), WaitDiagnosticCode::ArmOutsideSnapshot),
        Ok(envelope) => panic!("an arm of another snapshot is refused, not {envelope:?}"),
    }

    // A decision consumes the arbitration and hands the one live value back, so exactly one
    // losing-arm settlement exists for this committed arbitration and it is consumed once.
    let decision = match arbitration.decide(&eligible) {
        Ok(decision) => decision,
        other => panic!("the declared observations decide a winner: {other:?}"),
    };
    assert!(decision.is_committed());
    assert_eq!(
        decision.requirement(),
        "GNT-24.6-select-and-race-snapshots-and-winner-permanence"
    );
    let arbitration = decision.into_arbitration();
    let settlement = match arbitration.into_losing_settlement() {
        Ok(settlement) => settlement,
        Err(error) => panic!("a decided arbitration yields a settlement: {error}"),
    };
    assert_eq!(settlement.winner(), &arm("first"));
    assert_eq!(settlement.losing_arms(), vec![arm("second"), arm("third")]);
    match settlement.settle(&[ArmDisposition::new(
        arm("second"),
        ArmDispositionKind::Cancel,
    )]) {
        Err(error) => assert_eq!(error.code(), WaitDiagnosticCode::UnsettledLosingArm),
        Ok(report) => panic!("an unsettled losing arm is refused, not {report:?}"),
    }

    let undecided = match Arbitration::open(vec![ArmedAlternative::new(
        arm("only"),
        waiter("crate::main", "std.net.read", 5, fence()),
    )]) {
        Ok(arbitration) => arbitration,
        Err(error) => panic!("the declared arm set opens: {error}"),
    };
    match undecided.into_losing_settlement() {
        Err(error) => assert_eq!(error.code(), WaitDiagnosticCode::WinnerNotCommitted),
        Ok(settlement) => panic!("ownership is decided after the winner, not {settlement:?}"),
    }

    // The committed winner of the second arbitration is the eligible arm, so the losing arm
    // is refused as a winner disposition and settled once.
    let decided = committed_arbitration(
        vec![
            ArmedAlternative::new(
                arm("first"),
                waiter("crate::main", "std.net.read", 6, fence()),
            ),
            ArmedAlternative::new(
                arm("second"),
                waiter("crate::worker", "std.net.read", 6, fence()),
            ),
        ],
        &[ArmObservation::new(arm("second"), WakeCause::Timeout)],
    );
    assert_eq!(
        decided.winner().map(|winner| winner.arm().clone()),
        Some(arm("second"))
    );
    let settlement = match decided.into_losing_settlement() {
        Ok(settlement) => settlement,
        Err(error) => panic!("a decided arbitration yields a settlement: {error}"),
    };
    assert_eq!(settlement.winner(), &arm("second"));
    assert_eq!(settlement.losing_arms(), vec![arm("first")]);
    let report = match settlement.settle(&[ArmDisposition::new(
        arm("first"),
        ArmDispositionKind::Cancel,
    )]) {
        Ok(report) => report,
        Err(error) => panic!("the losing arm settles once: {error}"),
    };
    assert_eq!(report.winner(), &arm("second"));
    assert_eq!(report.cancelled(), [arm("first")]);
    assert!(report.retained().is_empty());
    assert!(report.is_complete());

    // A disposition of the committed winner, a repeated disposition, a disposition of an arm
    // outside the frozen snapshot, and a missing disposition are each refused. Each refusal is
    // presented to the single settlement of its own committed arbitration, because the
    // settlement is affine and consumed once.
    assert_eq!(
        refused_settlement(&[ArmDisposition::new(
            arm("second"),
            ArmDispositionKind::Retain
        )])
        .code(),
        WaitDiagnosticCode::WinnerNotLosable
    );
    assert_eq!(
        refused_settlement(&[
            ArmDisposition::new(arm("first"), ArmDispositionKind::Cancel),
            ArmDisposition::new(arm("first"), ArmDispositionKind::Retain),
        ])
        .code(),
        WaitDiagnosticCode::RepeatedDisposition
    );
    assert_eq!(
        refused_settlement(&[ArmDisposition::new(
            arm("absent"),
            ArmDispositionKind::Cancel
        )])
        .code(),
        WaitDiagnosticCode::ArmOutsideSnapshot
    );
    assert_eq!(
        refused_settlement(&[]).code(),
        WaitDiagnosticCode::UnsettledLosingArm
    );
}

/// `GNT-24.8`: the five quiescence classes are total and mutually exclusive over declared
/// facts, a pending host prerequisite permitted to remain pending is not a deadlock, and a
/// deadlock reports one bounded protected wait-graph diagnostic.
#[test]
fn quiescence_classes_are_closed_and_exempt_pending_external_prerequisites() {
    assert_eq!(QuiescenceClass::ALL.len(), 5);
    let classes = QuiescenceClass::ALL
        .iter()
        .map(|class| class.wire_name())
        .collect::<BTreeSet<_>>();
    assert_eq!(classes.len(), 5);
    for class in QuiescenceClass::ALL {
        assert_eq!(QuiescenceClass::from_wire_name(class.as_str()), Some(class));
        assert!(!class.meaning().is_empty());
        assert_eq!(class.requirement(), "GNT-24.8-quiescence-classification");
    }

    assert_eq!(
        classify_quiescence(&facts(0, 0, 0, 0, 0, 0)),
        QuiescenceClass::Completion
    );
    assert_eq!(
        classify_quiescence(&facts(0, 0, 0, 2, 1, 0)),
        QuiescenceClass::InternallyWakeableIdle
    );
    assert_eq!(
        classify_quiescence(&facts(2, 2, 0, 2, 0, 0)),
        QuiescenceClass::ClosedWaitDeadlock
    );
    assert_eq!(
        classify_quiescence(&facts(1, 0, 1, 0, 0, 0)),
        QuiescenceClass::ExternallyWakeableIdle
    );
    assert_eq!(
        classify_quiescence(&facts(0, 0, 0, 0, 0, 1)),
        QuiescenceClass::OrphanedWork
    );

    // The external-prerequisite exemption: genuinely pending host work is not a deadlock.
    let external = facts(1, 0, 1, 1, 1, 0);
    let idle = match observe_quiescence(&external, Vec::new(), 0) {
        Ok(outcome) => outcome,
        Err(error) => panic!("pending external work is classified: {error}"),
    };
    assert_eq!(idle.class(), QuiescenceClass::ExternallyWakeableIdle);
    assert!(idle.diagnostic().is_none());
    assert_eq!(idle.remedy(), QuiescenceRemedy::None);

    let deadlocked = facts(2, 2, 0, 2, 0, 0);
    let waits = vec![
        waiter("crate::main", "std.net.read", 1, fence()),
        waiter("crate::worker", "std.net.read", 1, fence()),
    ];
    let outcome = match observe_quiescence(&deadlocked, waits.clone(), 2) {
        Ok(outcome) => outcome,
        Err(error) => panic!("the declared deadlock is classified: {error}"),
    };
    assert_eq!(outcome.class(), QuiescenceClass::ClosedWaitDeadlock);
    assert_eq!(
        outcome.remedy(),
        QuiescenceRemedy::OrdinaryCancellationAndCleanup
    );
    let diagnostic = match outcome.diagnostic() {
        Some(diagnostic) => diagnostic,
        None => panic!("a closed-wait deadlock reports one bounded diagnostic"),
    };
    assert_eq!(diagnostic.node_count(), waits.len());
    assert_eq!(diagnostic.edge_count(), 2);
    assert_eq!(diagnostic.class(), QuiescenceClass::ClosedWaitDeadlock);
    assert_eq!(
        diagnostic.code(),
        WaitDiagnosticCode::ClosedWaitDeadlockReported
    );
    assert!(diagnostic.node_count() <= WAIT_GRAPH_MAX_NODES);
    let text = diagnostic.protected_text(AuditAccess::granted());
    assert!(text.contains(WaitDiagnosticCode::ClosedWaitDeadlockReported.as_str()));
    assert!(text.contains(QuiescenceClass::ClosedWaitDeadlock.wire_name()));

    match QuiescenceFacts::new(1, 2, 0, 0, 0, 0) {
        Err(error) => assert_eq!(error.code(), WaitDiagnosticCode::MalformedQuiescenceFacts),
        Ok(other) => panic!("more blocked waits than live waits are refused: {other:?}"),
    }
    match observe_quiescence(&deadlocked, Vec::new(), 2) {
        Err(error) => assert_eq!(error.code(), WaitDiagnosticCode::EmptyWaitGraph),
        Ok(other) => panic!("an empty wait graph is refused, not {other:?}"),
    }
    match observe_quiescence(&deadlocked, waits, WAIT_GRAPH_MAX_EDGES + 1) {
        Err(error) => assert_eq!(
            error.code(),
            WaitDiagnosticCode::WaitGraphDiagnosticTooLarge
        ),
        Ok(other) => panic!("an oversized wait graph is refused, not {other:?}"),
    }
}

/// `GNT-24.9`: a durable wait commits registration, ownership, readiness, and the decision
/// in order, and recovery reconstructs the same wait set without turning a committed wake
/// into a different winner.
#[test]
fn durable_wait_cuts_reconstruct_without_re_choosing_a_winner() {
    assert_eq!(
        DurableWaitCut::ALL.map(DurableWaitCut::wire_name),
        ["registration", "ownership", "readiness", "decision"]
    );
    let mut registration = registration("crate::main", "std.net.read", 1, fence());
    let id = registered(&mut WaitSet::new(), &mut registration);
    let mut record = DurableWaitRecord::for_registration(&registration);
    assert_eq!(record.cut(), DurableWaitCut::Registration);
    assert_eq!(record.wait(), &id);
    assert_eq!(record.owner(), &owner("crate::main"));
    assert_eq!(record.resource(), &resource("std.net.read"));
    assert_eq!(record.generation(), fence());
    assert_eq!(
        record.resume(None),
        Ok(WaitRecoveryDecision::ResumeRegistration)
    );

    match record.advance_to(DurableWaitCut::Decision) {
        Err(error) => assert_eq!(error.code(), WaitDiagnosticCode::CutRegression),
        Ok(()) => panic!("a cut that skips an uncommitted cut is refused"),
    }
    // A commit advances exactly one cut: a readiness commit whose predecessor cut is not
    // committed is refused and commits no intermediate cut for the caller.
    match record.commit_readiness(WakeCause::Delivery) {
        Err(error) => assert_eq!(error.code(), WaitDiagnosticCode::CutRegression),
        Ok(()) => panic!("a readiness commit never commits the ownership cut for the caller"),
    }
    assert_eq!(record.cut(), DurableWaitCut::Registration);
    assert_eq!(record.readiness(), None);

    // The ordered happy path is registration, ownership, readiness, decision.
    assert_eq!(record.advance_to(DurableWaitCut::Registration), Ok(()));
    assert_eq!(record.advance_to(DurableWaitCut::Ownership), Ok(()));
    assert_eq!(record.resume(None), Ok(WaitRecoveryDecision::ResumeArmed));
    assert_eq!(record.commit_readiness(WakeCause::Delivery), Ok(()));
    assert_eq!(record.cut(), DurableWaitCut::Readiness);
    assert_eq!(record.readiness(), Some(WakeCause::Delivery));
    assert_eq!(
        record.resume(None),
        Ok(WaitRecoveryDecision::ResumeReady(WakeCause::Delivery))
    );
    match record.commit_readiness(WakeCause::Timeout) {
        Err(error) => assert_eq!(error.code(), WaitDiagnosticCode::ReadinessRegression),
        Ok(()) => panic!("a committed readiness is never rewritten"),
    }
    match record.resume(Some(WaitDecision::Wake(WakeCause::Delivery))) {
        Err(error) => assert_eq!(error.code(), WaitDiagnosticCode::DecisionBeforeCommit),
        Ok(other) => panic!("a decision before the decision cut is refused, not {other:?}"),
    }

    assert_eq!(
        record.commit_decision(WaitDecision::Wake(WakeCause::Delivery)),
        Ok(())
    );
    assert_eq!(record.cut(), DurableWaitCut::Decision);
    assert_eq!(
        record.resume(Some(WaitDecision::Wake(WakeCause::Delivery))),
        Ok(WaitRecoveryDecision::ResumeWinner(WakeCause::Delivery))
    );
    assert_eq!(
        record.resume(None),
        Ok(WaitRecoveryDecision::ResumeWinner(WakeCause::Delivery))
    );
    match record.resume(Some(WaitDecision::Wake(WakeCause::Cancellation))) {
        Err(error) => assert_eq!(error.code(), WaitDiagnosticCode::DecisionRegression),
        Ok(other) => panic!("a committed wake never becomes another winner, not {other:?}"),
    }
    match record.resume(Some(WaitDecision::Deadlock(
        QuiescenceClass::ClosedWaitDeadlock,
    ))) {
        Err(error) => assert_eq!(error.code(), WaitDiagnosticCode::DecisionRegression),
        Ok(other) => panic!("a wake is never turned into a deadlock, not {other:?}"),
    }
    assert_eq!(
        record.commit_decision(WaitDecision::Wake(WakeCause::Delivery)),
        Ok(())
    );
    assert_eq!(
        record.resume(None),
        Ok(WaitRecoveryDecision::ResumeWinner(WakeCause::Delivery))
    );

    let mut deadlocked = DurableWaitRecord::new(
        waiter("crate::worker", "std.net.read", 2, fence()),
        owner("crate::worker"),
        resource("std.net.read"),
        fence(),
    );
    // A decision commit advances exactly one cut from the committed readiness cut, and a
    // wake decision additionally requires a committed readiness that recorded its cause, so
    // a record whose readiness cut holds no cause refuses the wake decision and mutates
    // nothing.
    match deadlocked.commit_decision(WaitDecision::Wake(WakeCause::Delivery)) {
        Err(error) => assert_eq!(error.code(), WaitDiagnosticCode::CutRegression),
        Ok(()) => panic!("a decision commit never commits the readiness cut for the caller"),
    }
    assert_eq!(deadlocked.cut(), DurableWaitCut::Registration);
    assert_eq!(deadlocked.decision(), None);
    assert_eq!(deadlocked.advance_to(DurableWaitCut::Ownership), Ok(()));
    assert_eq!(deadlocked.advance_to(DurableWaitCut::Readiness), Ok(()));
    match deadlocked.commit_decision(WaitDecision::Wake(WakeCause::Delivery)) {
        Err(error) => assert_eq!(error.code(), WaitDiagnosticCode::MissingCommittedReadiness),
        Ok(()) => panic!("a wake decision requires a committed readiness that recorded its cause"),
    }
    assert_eq!(deadlocked.cut(), DurableWaitCut::Readiness);
    assert_eq!(deadlocked.decision(), None);
    match deadlocked.resume(None) {
        Err(error) => assert_eq!(error.code(), WaitDiagnosticCode::MissingCommittedReadiness),
        Ok(other) => {
            panic!("a readiness cut with no recorded cause resumes nothing, not {other:?}")
        }
    }

    // The deadlock transition needs the committed readiness cut but records no ready cause.
    assert_eq!(
        deadlocked.commit_decision(WaitDecision::Deadlock(QuiescenceClass::ClosedWaitDeadlock)),
        Ok(())
    );
    assert_eq!(
        deadlocked.resume(None),
        Ok(WaitRecoveryDecision::ResumeDeadlock(
            QuiescenceClass::ClosedWaitDeadlock
        ))
    );
    match deadlocked.commit_decision(WaitDecision::Deadlock(QuiescenceClass::OrphanedWork)) {
        Err(error) => assert_eq!(
            error.code(),
            WaitDiagnosticCode::DeadlockClassificationRefused
        ),
        Ok(()) => panic!("a class that is not a deadlock transition is refused"),
    }

    // Recovery reattaches only permitted external prerequisites and invents none.
    let permitted = prerequisite("host.read");
    let unpermitted = prerequisite("host.write");
    assert_eq!(
        deadlocked.reattach(
            std::slice::from_ref(&permitted),
            std::slice::from_ref(&permitted)
        ),
        Ok(vec![permitted.clone()])
    );
    assert_eq!(
        deadlocked.reattach(&[], std::slice::from_ref(&permitted)),
        Ok(Vec::new())
    );
    match deadlocked.reattach(&[unpermitted], &[permitted]) {
        Err(error) => assert_eq!(error.code(), WaitDiagnosticCode::UnpermittedPrerequisite),
        Ok(attached) => panic!("an unpermitted prerequisite is refused, not {attached:?}"),
    }
}

/// `GNT-24.10`: the non-claims are a closed vocabulary, and a non-claim is never presented
/// as a guarantee.
#[test]
fn wait_non_claims_are_closed_and_never_presented_as_guarantees() {
    assert_eq!(WAIT_NON_CLAIMS.len(), 4);
    let names = WaitNonClaimName::ALL
        .iter()
        .map(|claim| claim.wire_name())
        .collect::<BTreeSet<_>>();
    assert_eq!(names.len(), 4);
    for (position, claim) in WaitNonClaimName::ALL.iter().enumerate() {
        assert_eq!(claim.statement(), WAIT_NON_CLAIMS[position]);
        assert_eq!(
            WaitNonClaimName::from_wire_name(claim.as_str()),
            Some(*claim)
        );
        assert_eq!(claim.requirement(), "GNT-24.10-wait-non-claims");
        assert!(WAIT_NON_CLAIMS[position].contains("No "));
    }

    let honest = WaitNonClaimName::ALL
        .iter()
        .map(|claim| WaitNonClaimAssertion::new(*claim, false))
        .collect::<Vec<_>>();
    assert_eq!(check_wait_non_claims(&honest), Ok(()));
    for claim in WaitNonClaimName::ALL {
        let overstated = [WaitNonClaimAssertion::new(claim, true)];
        match check_wait_non_claims(&overstated) {
            Err(error) => {
                assert_eq!(error.code(), WaitDiagnosticCode::NonClaimAsGuarantee);
                assert_eq!(error.requirement(), "GNT-24.10-wait-non-claims");
            }
            Ok(()) => panic!("a non-claim presented as a guarantee is refused"),
        }
    }

    let mut previous: Option<&str> = None;
    for code in WaitDiagnosticCode::ALL {
        let spelling = code.as_str();
        if let Some(held) = previous {
            assert!(held < spelling, "{held} must sort before {spelling}");
        }
        previous = Some(spelling);
        assert!(WAIT_CLAUSES.contains(&code.requirement()));
    }
}
