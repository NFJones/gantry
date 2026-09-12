//! Machine-checked conformance for the integration fault containment model of
//! `SPEC.md` Section 23, clauses `GNT-23.0` .. `GNT-23.8`.
//!
//! These tests exercise the public `gantry::ir` surface of the landed containment model
//! together with the landed `GNT-20` contracts it cites:
//! `GNT-23.0-integration-fault-containment`,
//! `GNT-23.1-containment-boundaries`,
//! `GNT-23.2-foreign-failure-taxonomy`,
//! `GNT-23.3-effect-ambiguity-preservation`,
//! `GNT-23.4-operation-ownership-and-single-settlement`,
//! `GNT-23.5-failed-instance-poisoning-and-isolation`,
//! `GNT-23.6-protected-fault-diagnostics`,
//! `GNT-23.7-adapter-containment-obligations`, and
//! `GNT-23.8-containment-non-claims`.
//!
//! Every test is a pure function of its own arguments: no test reads a clock, a process
//! identifier, a host path, an environment fact, or a live host handle, and no test
//! spawns a thread or waits on a handle. Owner generations, adapter bindings, containment
//! plans, and carried boundary sets are explicit declarations, so every verdict here is
//! reproducible from its own inputs.
//!
//! The tests also pin the properties the hardened model decides: a settlement is an
//! affine per-operation value, so exactly one live settlement of one operation exists and
//! a pre-settlement snapshot cannot be settled later; poisoning is landed through the
//! one-way `AdapterInstance::poison` and the landed `ResourceState::Poisoned`, and the
//! reason ledger only records the reason the first poisoning of one landed identity
//! fixed; the refusal order is malformed, then settled, then stale; an ambiguous effect is
//! never settled as a definite accepted outcome; every condition owns its own frozen code
//! and its own clause anchor; the containment declaration is decided against the
//! boundaries the adapter carries rather than named; the failure attribution is decided
//! rather than assumed; and the canonical report text carries the declared fields and
//! nothing else.

use std::collections::BTreeSet;

use gantry::ir::generated::RecoveryClass;
use gantry::ir::{
    AdapterInstance, AuditAccess, AuthorityRight, CONTAINMENT_NON_CLAIM_NAMES,
    CONTAINMENT_NON_CLAIM_ORDER, CanonicalImplementationIdentity, CanonicalPath, Completion,
    ContainmentBoundary, ContainmentDeclaration, ContainmentDiagnosticCode, ContainmentError,
    ContainmentFailureClass, ContainmentNonClaimName, ContainmentObligation, ContainmentPlan,
    ContainmentReport, ContainmentSettlement, ContainmentVerdict, EffectState, ExternalOutcome,
    FAULT_CONTAINMENT_CLAUSES, ForeignFailureKind, ForeignFailureObservation, MalformedCompletion,
    OperationAbi, OperationAbiDiagnosticCode, OperationAbiError, OperationKind, OwnerGeneration,
    PoisonLedger, PoisonReason, ReceiverOwnership, ReportScope, ResourceState, RightsSet,
    StaticSiteId, StructuralPosition, TypeExpression, attribute_foreign_failure,
    check_containment_declaration, poison_resource_state,
};

/// Compile-time proof that one type implements none of the listed traits.
///
/// A blanket implementation and a trait-bounded implementation both apply, so naming the
/// associated item requires an inference that cannot be resolved and compilation fails. A
/// `Clone` or a `Copy` implementation for [`ContainmentSettlement`] would stop this crate
/// compiling, which is exactly what `GNT-23.4` forbids: the settlement is affine, so
/// exactly one live settlement of one operation exists and a pre-settlement snapshot
/// cannot be duplicated and settled later.
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

/// The canonical operation declaration of every fixture.
const DECLARATION: &str = "crate::fault_containment";

/// Contains one foreign failure at one boundary in a declaration-scope report.
///
/// The model refuses a non-foreign class, so a call here is a class the clause permits;
/// the refusal is reported through the error accessors rather than folded away or
/// formatted, because the containment verdict and its report implement no rendering trait.
fn contain(
    boundary: ContainmentBoundary,
    kind: ForeignFailureKind,
    effect: EffectState,
) -> ContainmentReport {
    match ContainmentVerdict::contain(
        boundary,
        ContainmentFailureClass::Foreign(kind),
        effect,
        OwnerGeneration::new(7),
        ReportScope::Declaration,
    ) {
        Ok(ContainmentVerdict::Contained(report)) => report,
        Ok(ContainmentVerdict::InvariantFailure) => unreachable!(
            "a foreign failure is contained at a boundary, not reported as an invariant failure"
        ),
        Err(error) => unreachable!(
            "a foreign failure is contained at a boundary, not refused as `{}`",
            error.code().as_str()
        ),
    }
}

/// Returns the refusal of one containment verdict the caller expects to be refused.
///
/// The unexpected verdict is reported through its accessors, because
/// [`ContainmentVerdict`] deliberately implements no `Debug`.
fn expect_refusal(verdict: Result<ContainmentVerdict, ContainmentError>) -> ContainmentError {
    match verdict {
        Ok(contained) => match contained.report() {
            Some(report) => unreachable!(
                "the containment at the `{}` boundary is not a refusal",
                report.boundary().wire_name()
            ),
            None => unreachable!("the invariant-failure verdict is not a refusal"),
        },
        Err(error) => error,
    }
}

/// Returns the refusal of one model call the fixture expects to be refused.
///
/// This is the generic form of [`expect_refusal`] for every model call whose success
/// value implements `Debug`, and it is written without unwrapping so the refusal is
/// reported as a value rather than formatted away.
fn refused<T>(result: Result<T, ContainmentError>) -> ContainmentError {
    match result {
        Ok(_) => unreachable!("the model refuses this fixture"),
        Err(error) => error,
    }
}

/// Returns the frozen operation-ABI code of one refusal of the landed adapter contract.
fn abi_refusal<T>(result: Result<T, OperationAbiError>) -> OperationAbiDiagnosticCode {
    match result {
        Ok(_) => unreachable!("the landed adapter contract refuses this fixture"),
        Err(error) => error.code(),
    }
}

/// Builds the full expected canonical text of one containment report of an ambiguous
/// effect, in the canonical field order of `GNT-23.6`.
///
/// The text is written out in full, so an undeclared field, an extra field, or a reordered
/// field in a rendering fails the equality assertion that consumes it, where a
/// forbidden-substring scan can only fail for a name it already lists.
fn expected_canonical_text(
    boundary: &str,
    class: &str,
    diagnostic_code: &str,
    owner: u64,
    scope: &str,
) -> String {
    format!(
        "boundary={boundary};class={class};effect=ambiguous;owner={owner};diagnostic-code={diagnostic_code};effect-code=fault-ambiguous-effect-preserved;clauses=GNT-23.1-containment-boundaries,GNT-23.2-foreign-failure-taxonomy,GNT-23.3-effect-ambiguity-preservation;scope={scope}"
    )
}

/// Returns one canonical fixture path.
fn path(value: &str) -> CanonicalPath {
    CanonicalPath::new(value).unwrap_or_else(|_| unreachable!("fixture path is canonical"))
}

/// Returns one canonical fixture static site at one structural route.
fn site(components: &[u64]) -> StaticSiteId {
    let position = StructuralPosition::new(components.to_vec())
        .unwrap_or_else(|_| unreachable!("fixture structural position is canonical"));
    StaticSiteId::new(path(DECLARATION), position)
}

/// Returns one fixture authority rights set.
fn rights(list: &[AuthorityRight]) -> RightsSet {
    RightsSet::from_rights(list)
}

/// Returns one fixture downstream implementation identity.
fn implementation(name: &str) -> CanonicalImplementationIdentity {
    let receiver = TypeExpression::from_canonical_string(&format!("crate::{name}"), 4)
        .unwrap_or_else(|_| unreachable!("fixture receiver is a canonical type"));
    CanonicalImplementationIdentity::inherent(&receiver)
}

/// Returns one fixture adapter binding of one implementation, rights set, owner
/// generation, and binding sequence.
fn adapter(
    name: &str,
    list: &[AuthorityRight],
    generation: u64,
    binding_sequence: u64,
) -> AdapterInstance {
    AdapterInstance::bind(
        &implementation(name),
        rights(list),
        OwnerGeneration::new(generation),
        binding_sequence,
    )
}

/// Returns the fixture operation ABI of one declared recovery class.
///
/// The ABI is one value action over one canonical declaration and one canonical
/// structural route, so it carries no live handle: a fixture binding either dispatches it
/// with the right its recovery class demands or is refused for a declared reason.
fn abi(recovery: RecoveryClass) -> OperationAbi {
    OperationAbi::new(
        OperationKind::ValueAction,
        &path(DECLARATION),
        &site(&[1, 2]),
        1,
        recovery,
        ReceiverOwnership::RetainedByCaller,
    )
    .unwrap_or_else(|error| unreachable!("the fixture operation ABI is admissible, not `{error}`"))
}

/// Returns one refusal of every condition the containment model can decide.
///
/// The list is the exhaustive set of refusals the model can produce, one per condition.
/// Each entry is decided from explicit fixture declarations rather than hand-written as an
/// error value, so a condition that stops being reachable, or a new condition that borrows
/// another condition's code, fails the count and distinctness assertions that consume this
/// list.
fn every_condition() -> Vec<ContainmentError> {
    let owner = OwnerGeneration::new(64);
    let stale = OwnerGeneration::new(63);
    let mut poisoned = adapter(
        "ConditionAdapter",
        &[AuthorityRight::InvokeReadOnly],
        owner.value(),
        1,
    );
    let mut ledger = PoisonLedger::new();
    let _ = ledger.poison(
        &mut poisoned,
        PoisonReason::ForeignFailure(ForeignFailureKind::Panic),
    );
    let protected = match ContainmentReport::contained(
        ContainmentBoundary::Completion,
        ContainmentFailureClass::Foreign(ForeignFailureKind::Trap),
        EffectState::Ambiguous,
        owner,
        ReportScope::ProtectedData,
    ) {
        Ok(report) => report,
        Err(error) => {
            unreachable!("a foreign failure is contained at a boundary, not refused as `{error}`")
        }
    };
    let mut ambiguous = ContainmentSettlement::open(owner);
    let mut settled = ContainmentSettlement::open(owner);
    if settled
        .settle(
            owner,
            Completion::observed(ExternalOutcome::Rejected, EffectState::NotStarted),
        )
        .is_err()
    {
        unreachable!("the fixture operation settles over a definite not-started effect");
    }
    vec![
        refused(
            EffectState::Ambiguous.preserved(EffectState::NotStarted, ContainmentBoundary::Call),
        ),
        refused(EffectState::Ambiguous.refuse_ambiguous_retry(ContainmentBoundary::Call)),
        refused(ambiguous.settle(
            owner,
            Completion::observed(ExternalOutcome::Accepted, EffectState::Ambiguous),
        )),
        refused(
            EffectState::NotStarted
                .preserved(EffectState::Ambiguous, ContainmentBoundary::Completion),
        ),
        refused(check_containment_declaration(
            ContainmentDeclaration::declared(
                ContainmentBoundary::Call,
                ContainmentPlan::of(&[ContainmentBoundary::Call]),
            ),
            &ContainmentPlan::all(),
        )),
        expect_refusal(ContainmentVerdict::contain(
            ContainmentBoundary::Call,
            ContainmentFailureClass::GantryInvariant,
            EffectState::NotStarted,
            owner,
            ReportScope::Declaration,
        )),
        refused(
            ContainmentSettlement::open(owner)
                .settle(owner, Completion::malformed(MalformedCompletion::NoOutcome)),
        ),
        refused(check_containment_declaration(
            ContainmentDeclaration::refused(
                ContainmentBoundary::Call,
                ContainmentObligation::EffectStateDeclared,
            ),
            &ContainmentPlan::all(),
        )),
        refused(ledger.reuse_refusal(&poisoned)),
        refused(protected.canonical_text()),
        refused(poison_resource_state(ResourceState::Consumed)),
        refused(settled.settle(
            owner,
            Completion::observed(ExternalOutcome::Accepted, EffectState::NotStarted),
        )),
        refused(ContainmentSettlement::open(owner).settle(
            stale,
            Completion::observed(ExternalOutcome::Accepted, EffectState::NotStarted),
        )),
        refused(attribute_foreign_failure(
            ForeignFailureObservation::Unattributable,
        )),
    ]
}

/// `GNT-23.4`: the settlement of one operation is affine, so its value implements neither
/// `Clone` nor `Copy` and exactly one live settlement of one operation exists.
#[test]
fn settlement_is_affine_and_implements_neither_clone_nor_copy() {
    // The whole property is a compile-time fact about the type: a `Clone` or a `Copy`
    // implementation would let a caller duplicate the unsettled settlement and settle one
    // operation twice.
    assert_not_impl_any!(ContainmentSettlement: Clone, Copy);

    // The same value is still an ordinary comparable model value: equal declarations open
    // equal settlements, and a settlement that observed and settled is not an open one.
    let owner = OwnerGeneration::new(12);
    let mut settlement = ContainmentSettlement::open(owner);
    assert_eq!(settlement, ContainmentSettlement::open(owner));
    assert_ne!(settlement, ContainmentSettlement::open(owner.advanced()));
    assert_eq!(settlement.owner(), owner);
    assert_eq!(settlement.effect_state(), None);
    assert!(!settlement.is_settled());

    let settled = settlement.settle(
        owner,
        Completion::observed(ExternalOutcome::Rejected, EffectState::NotStarted),
    );
    assert_eq!(settled, Ok(ExternalOutcome::Rejected));
    assert_ne!(settlement, ContainmentSettlement::open(owner));
    assert_eq!(settlement.effect_state(), Some(EffectState::NotStarted));
}

/// `GNT-23.0`: the section publishes exactly nine clause anchors, and every diagnostic of
/// the model is attributable to one of them.
#[test]
fn section_publishes_the_nine_clause_anchors_in_order() {
    let expected = [
        "GNT-23.0-integration-fault-containment",
        "GNT-23.1-containment-boundaries",
        "GNT-23.2-foreign-failure-taxonomy",
        "GNT-23.3-effect-ambiguity-preservation",
        "GNT-23.4-operation-ownership-and-single-settlement",
        "GNT-23.5-failed-instance-poisoning-and-isolation",
        "GNT-23.6-protected-fault-diagnostics",
        "GNT-23.7-adapter-containment-obligations",
        "GNT-23.8-containment-non-claims",
    ];
    assert_eq!(FAULT_CONTAINMENT_CLAUSES, expected);

    let owned: BTreeSet<&str> = ContainmentDiagnosticCode::ALL
        .into_iter()
        .map(|code| code.requirement())
        .collect();
    for clause in owned {
        assert!(
            FAULT_CONTAINMENT_CLAUSES.contains(&clause),
            "`{clause}` is not a published anchor of Section 23"
        );
    }
}

/// `GNT-23.1`: containment happens at six boundaries and at no others.
#[test]
fn containment_boundary_vocabulary_is_closed_and_owns_clause_23_1() {
    let spellings: Vec<&str> = ContainmentBoundary::ALL
        .iter()
        .map(|boundary| boundary.wire_name())
        .collect();
    assert_eq!(
        spellings,
        [
            "call",
            "poll",
            "cancel-abort",
            "completion",
            "callback",
            "destructor"
        ]
    );

    for boundary in ContainmentBoundary::ALL {
        assert_eq!(
            Some(boundary),
            ContainmentBoundary::from_wire_name(boundary.wire_name())
        );
        assert_eq!(boundary.requirement(), "GNT-23.1-containment-boundaries");
        assert_eq!(boundary.as_str(), boundary.wire_name());
    }

    // No other point is a containment boundary, so no unwind, process abort, or drop hook
    // becomes one by spelling.
    for unknown in ["unwind", "abort", "drop", "task-boundary", "public-api"] {
        assert_eq!(None, ContainmentBoundary::from_wire_name(unknown));
    }
}

/// `GNT-23.2`: four distinct foreign classes, each with its own diagnostic.
#[test]
fn foreign_failure_vocabulary_is_closed_and_each_class_owns_its_own_code() {
    assert_eq!(
        ForeignFailureKind::ALL.map(ForeignFailureKind::wire_name),
        ["panic", "exception", "trap", "protocol"]
    );

    let codes: BTreeSet<ContainmentDiagnosticCode> = ForeignFailureKind::ALL
        .into_iter()
        .map(ForeignFailureKind::code)
        .collect();
    assert_eq!(codes.len(), 4, "each foreign class has its own diagnostic");

    for kind in ForeignFailureKind::ALL {
        assert_eq!(
            Some(kind),
            ForeignFailureKind::from_wire_name(kind.wire_name())
        );
        assert_eq!(kind.as_str(), kind.wire_name());
        assert_eq!(kind.requirement(), "GNT-23.2-foreign-failure-taxonomy");
        assert_ne!(
            kind.code(),
            ContainmentDiagnosticCode::GantryInvariantFailure
        );
    }

    // No foreign failure is reported as another class or as a generic failure.
    for unknown in ["generic", "failure", "unknown", "signal"] {
        assert_eq!(None, ForeignFailureKind::from_wire_name(unknown));
    }
}

/// `GNT-23.2`: an invariant failure is refused as a foreign class and reported as itself.
#[test]
fn gantry_invariant_failure_is_refused_as_foreign_and_reported_separately() {
    assert!(ContainmentFailureClass::GantryInvariant.is_invariant());
    assert!(!ContainmentFailureClass::GantryInvariant.is_foreign());
    assert!(!ContainmentFailureClass::GantryInvariant.is_containable());
    assert_eq!(ContainmentFailureClass::GantryInvariant.kind(), None);

    let refused = expect_refusal(ContainmentVerdict::contain(
        ContainmentBoundary::Call,
        ContainmentFailureClass::GantryInvariant,
        EffectState::NotStarted,
        OwnerGeneration::new(1),
        ReportScope::Declaration,
    ));
    assert_eq!(
        refused.code(),
        ContainmentDiagnosticCode::InvariantFailureNotContainable
    );
    assert_eq!(refused.clause(), "GNT-23.2-foreign-failure-taxonomy");
    assert_eq!(refused.requirement(), "GNT-23.2-foreign-failure-taxonomy");

    let reported = ContainmentVerdict::invariant_failure();
    assert!(reported.is_invariant_failure());
    assert!(!reported.is_contained());
    assert!(reported.report().is_none());
    assert_eq!(
        reported.code(),
        ContainmentDiagnosticCode::GantryInvariantFailure
    );

    // The invariant verdict carries the invariant code and no foreign containment code:
    // the variant owns no field that could hold one.
    for kind in ForeignFailureKind::ALL {
        assert_ne!(
            reported.code(),
            kind.code(),
            "an invariant verdict is never reported under the `{}` code",
            kind.wire_name()
        );
    }

    // `GNT-23.2`: the declared failure vocabulary is closed, ordered, and mapped to the
    // four foreign classes and the invariant class only.
    assert_eq!(
        ContainmentFailureClass::ALL.map(ContainmentFailureClass::wire_name),
        [
            "foreign-panic",
            "foreign-exception",
            "foreign-trap",
            "foreign-protocol",
            "gantry-invariant"
        ]
    );
    for class in ContainmentFailureClass::ALL {
        assert_eq!(
            Some(class),
            ContainmentFailureClass::from_wire_name(class.wire_name())
        );
        assert_eq!(class.is_foreign(), class.is_containable());
        assert_eq!(class.as_str(), class.wire_name());
        assert_eq!(class.requirement(), "GNT-23.2-foreign-failure-taxonomy");
        assert_eq!(
            class.code(),
            class.kind().map_or(
                ContainmentDiagnosticCode::GantryInvariantFailure,
                ForeignFailureKind::code
            )
        );
    }
    for unknown in ["invariant", "panic", "foreign-generic"] {
        assert_eq!(None, ContainmentFailureClass::from_wire_name(unknown));
    }
}

/// `GNT-23.1` and `GNT-23.2`: every class is contained at every boundary as a value with
/// its own code, rather than crossing a task or public API boundary.
#[test]
fn each_foreign_class_is_contained_at_each_boundary_with_its_own_code() {
    let mut observed: BTreeSet<(ContainmentBoundary, ContainmentDiagnosticCode)> = BTreeSet::new();
    for boundary in ContainmentBoundary::ALL {
        for kind in ForeignFailureKind::ALL {
            let report = contain(boundary, kind, EffectState::DefiniteRejection);
            assert_eq!(report.boundary(), boundary);
            assert_eq!(
                report.failure_class(),
                ContainmentFailureClass::Foreign(kind)
            );
            assert_eq!(report.diagnostic_code(), kind.code());
            assert_eq!(report.clause(), "GNT-23.2-foreign-failure-taxonomy");
            assert_eq!(
                report.clauses()[0],
                "GNT-23.1-containment-boundaries",
                "a report names the boundary clause that contained the failure"
            );
            observed.insert((boundary, report.diagnostic_code()));
        }
    }
    assert_eq!(
        observed.len(),
        24,
        "every pair of boundary and foreign class is one distinct containment"
    );
}

/// `GNT-23.7`: destructor and cancellation paths use the same classes, effect states,
/// and codes as the call, poll, and completion paths, and the declaration of containment
/// is decided rather than named.
#[test]
fn destructor_and_cancellation_boundaries_use_the_same_classes_and_codes() {
    assert_eq!(
        ContainmentBoundary::Destructor.requirement(),
        ContainmentBoundary::Call.requirement()
    );

    for kind in ForeignFailureKind::ALL {
        let call = contain(ContainmentBoundary::Call, kind, EffectState::Ambiguous);
        let destructor = contain(
            ContainmentBoundary::Destructor,
            kind,
            EffectState::Ambiguous,
        );
        let cancel = contain(
            ContainmentBoundary::CancelAbort,
            kind,
            EffectState::Ambiguous,
        );

        assert_eq!(destructor.diagnostic_code(), call.diagnostic_code());
        assert_eq!(cancel.diagnostic_code(), call.diagnostic_code());
        assert_eq!(destructor.failure_class(), call.failure_class());
        assert_eq!(destructor.effect_code(), call.effect_code());
        assert_eq!(destructor.boundary(), ContainmentBoundary::Destructor);
        assert_eq!(cancel.boundary(), ContainmentBoundary::CancelAbort);
        assert_eq!(destructor.clauses(), cancel.clauses());
    }

    // `GNT-23.7`: the adapter obligation vocabulary is closed, ordered, and distinct, and
    // every obligation is anchored to the clause that owns it.
    let obligations: Vec<&str> = ContainmentObligation::ALL
        .iter()
        .map(|obligation| obligation.wire_name())
        .collect();
    assert_eq!(
        obligations,
        [
            "no-foreign-unwind-crosses-boundary",
            "foreign-failure-reported-as-closed-class",
            "effect-state-declared",
            "poisoned-instance-not-reused",
            "destructor-and-cancellation-follow-same-rules"
        ]
    );
    let distinct: BTreeSet<&str> = obligations.iter().copied().collect();
    assert_eq!(
        distinct.len(),
        ContainmentObligation::ALL.len(),
        "the obligations are distinct members of one closed vocabulary"
    );
    for (index, obligation) in ContainmentObligation::ALL.iter().enumerate() {
        assert_eq!(
            Some(*obligation),
            ContainmentObligation::from_wire_name(obligation.wire_name())
        );
        assert_eq!(obligation.as_str(), obligation.wire_name());
        assert_eq!(
            obligation.requirement(),
            "GNT-23.7-adapter-containment-obligations"
        );
        assert_eq!(
            obligations[index],
            obligation.wire_name(),
            "the obligations are published in clause order"
        );
    }
    for unknown in [
        "containment",
        "no-unwind",
        "generic-failure",
        "repair-poisoned-instance",
    ] {
        assert_eq!(None, ContainmentObligation::from_wire_name(unknown));
    }

    // A refusal of each obligation is a typed refusal naming that obligation, its boundary,
    // and its own clause; only a declaration of containment succeeds.
    let carried = ContainmentPlan::all();
    for obligation in ContainmentObligation::ALL {
        let error = refused(check_containment_declaration(
            ContainmentDeclaration::refused(ContainmentBoundary::Destructor, obligation),
            &carried,
        ));
        assert_eq!(
            error.refused_obligation(),
            Some(obligation),
            "the refusal names the refused obligation"
        );
        assert_eq!(
            error.code(),
            ContainmentDiagnosticCode::ContainmentObligationRefused
        );
        assert_eq!(error.clause(), "GNT-23.7-adapter-containment-obligations");
        assert_eq!(error.requirement(), error.clause());
        assert!(error.to_string().contains(obligation.wire_name()));
        match &error {
            ContainmentError::ObligationRefused(refusal) => {
                assert_eq!(refusal.boundary(), ContainmentBoundary::Destructor);
                assert_eq!(refusal.obligation(), obligation);
                assert_eq!(refusal.clause(), obligation.requirement());
                assert_eq!(refusal.requirement(), refusal.clause());
                assert!(refusal.to_string().contains(obligation.wire_name()));
            }
            _ => unreachable!("a refused obligation is refused as an obligation refusal"),
        }
    }
    assert_eq!(
        check_containment_declaration(
            ContainmentDeclaration::declared_for_all(ContainmentBoundary::Destructor),
            &carried,
        ),
        Ok(carried.clone())
    );

    let declared = ContainmentDeclaration::declared_for_all(ContainmentBoundary::CancelAbort);
    assert!(declared.is_declared());
    assert_eq!(declared.obligation(), None);
    assert_eq!(declared.boundary(), ContainmentBoundary::CancelAbort);
    assert_eq!(
        declared.plan().map(ContainmentPlan::len),
        Some(ContainmentBoundary::ALL.len())
    );
    assert_eq!(
        declared.requirement(),
        "GNT-23.7-adapter-containment-obligations"
    );
    let refused_declaration = ContainmentDeclaration::refused(
        ContainmentBoundary::CancelAbort,
        ContainmentObligation::EffectStateDeclared,
    );
    assert!(!refused_declaration.is_declared());
    assert_eq!(
        refused_declaration.obligation(),
        Some(ContainmentObligation::EffectStateDeclared)
    );
    assert_eq!(refused_declaration.plan(), None);
}

/// `GNT-23.3`: an ambiguous effect is preserved and never made definite.
#[test]
fn ambiguous_effect_is_preserved_and_never_made_definite() {
    assert!(EffectState::Ambiguous.is_ambiguous());
    assert!(!EffectState::Ambiguous.is_definite());
    assert_eq!(
        EffectState::Ambiguous.preserved(EffectState::Ambiguous, ContainmentBoundary::Poll),
        Ok(EffectState::Ambiguous)
    );

    for definite in [EffectState::NotStarted, EffectState::DefiniteRejection] {
        let error =
            refused(EffectState::Ambiguous.preserved(definite, ContainmentBoundary::Completion));
        assert_eq!(
            error.code(),
            ContainmentDiagnosticCode::AmbiguousEffectMadeDefinite
        );
        assert_eq!(error.clause(), "GNT-23.3-effect-ambiguity-preservation");
        assert!(matches!(
            error,
            ContainmentError::AmbiguousEffectMadeDefinite { boundary, presented }
                if boundary == ContainmentBoundary::Completion && presented == definite
        ));
    }

    let report = contain(
        ContainmentBoundary::Completion,
        ForeignFailureKind::Trap,
        EffectState::Ambiguous,
    );
    assert_eq!(report.effect_state(), EffectState::Ambiguous);
    assert_eq!(
        report.effect_code(),
        ContainmentDiagnosticCode::AmbiguousEffectPreserved
    );
}

/// `GNT-23.3`: the containment path never retries an ambiguous mutation.
#[test]
fn ambiguous_mutation_is_never_retried_by_the_containment_path() {
    let error =
        refused(EffectState::Ambiguous.refuse_ambiguous_retry(ContainmentBoundary::CancelAbort));
    assert_eq!(
        error.code(),
        ContainmentDiagnosticCode::AmbiguousEffectRetryRefused
    );
    assert_eq!(error.clause(), "GNT-23.3-effect-ambiguity-preservation");
    assert!(matches!(
        error,
        ContainmentError::AmbiguousEffectRetryRefused { boundary }
            if boundary == ContainmentBoundary::CancelAbort
    ));

    // A definite state is not refused here: retry eligibility for it remains the landed
    // `GNT-20.6` rule, which this section cites rather than replaces.
    assert_eq!(
        EffectState::NotStarted.refuse_ambiguous_retry(ContainmentBoundary::Call),
        Ok(())
    );
    assert_eq!(
        EffectState::DefiniteRejection.refuse_ambiguous_retry(ContainmentBoundary::Poll),
        Ok(())
    );
}

/// `GNT-23.3`: the three effect states stay distinct and a definite effect stays definite.
#[test]
fn definite_effect_states_stay_distinct_and_definite_not_started_stays_definite() {
    let spellings: BTreeSet<&str> = EffectState::ALL
        .into_iter()
        .map(EffectState::wire_name)
        .collect();
    assert_eq!(
        spellings,
        BTreeSet::from(["ambiguous", "definite-not-started", "definite-rejection"]),
        "the three effect states are distinct members of one closed vocabulary"
    );
    for state in EffectState::ALL {
        assert_eq!(Some(state), EffectState::from_wire_name(state.wire_name()));
        assert_eq!(state.as_str(), state.wire_name());
        assert_eq!(
            state.requirement(),
            "GNT-23.3-effect-ambiguity-preservation"
        );
    }

    // `GNT-23.3`: a definite held state ignores a later definite presentation instead of
    // re-deriving the held state from it.
    let mut settlement = ContainmentSettlement::open(OwnerGeneration::new(4));
    let owner = settlement.owner();
    assert_eq!(
        settlement.settle(
            owner,
            Completion::observed(ExternalOutcome::Rejected, EffectState::NotStarted)
        ),
        Ok(ExternalOutcome::Rejected)
    );
    assert_eq!(settlement.effect_state(), Some(EffectState::NotStarted));
    assert_eq!(
        EffectState::NotStarted.preserved(EffectState::NotStarted, ContainmentBoundary::Poll),
        Ok(EffectState::NotStarted)
    );
    assert_eq!(
        EffectState::NotStarted
            .preserved(EffectState::DefiniteRejection, ContainmentBoundary::Poll),
        Ok(EffectState::NotStarted),
        "a definite held state ignores a later definite presentation"
    );
    assert_eq!(
        EffectState::DefiniteRejection
            .preserved(EffectState::DefiniteRejection, ContainmentBoundary::Poll),
        Ok(EffectState::DefiniteRejection)
    );
    assert_eq!(
        EffectState::NotStarted.code(),
        ContainmentDiagnosticCode::DefiniteNotStarted
    );
    assert_eq!(
        EffectState::DefiniteRejection.code(),
        ContainmentDiagnosticCode::DefiniteRejection
    );
    assert_ne!(
        EffectState::NotStarted.code(),
        EffectState::DefiniteRejection.code(),
        "a definite not-started effect and a definite rejection own one code each"
    );
    assert_ne!(
        EffectState::NotStarted.code(),
        EffectState::Ambiguous.code()
    );

    // `GNT-23.3`: a definite effect is never reported as ambiguous, so both definite states
    // refuse the ambiguous presentation and no such refusal borrows a definite code.
    for definite in [EffectState::NotStarted, EffectState::DefiniteRejection] {
        let error =
            refused(definite.preserved(EffectState::Ambiguous, ContainmentBoundary::Completion));
        assert_eq!(
            error.code(),
            ContainmentDiagnosticCode::DefiniteEffectMadeAmbiguous
        );
        assert_ne!(error.code(), ContainmentDiagnosticCode::DefiniteNotStarted);
        assert_ne!(error.code(), ContainmentDiagnosticCode::DefiniteRejection);
        assert_eq!(error.clause(), "GNT-23.3-effect-ambiguity-preservation");
        assert!(matches!(
            error,
            ContainmentError::DefiniteEffectMadeAmbiguous { held, .. } if held == definite
        ));
    }

    let not_started = contain(
        ContainmentBoundary::Poll,
        ForeignFailureKind::Protocol,
        EffectState::NotStarted,
    );
    assert_eq!(not_started.effect_state(), EffectState::NotStarted);
    assert_eq!(
        not_started.effect_code(),
        ContainmentDiagnosticCode::DefiniteNotStarted
    );

    let rejected = contain(
        ContainmentBoundary::Completion,
        ForeignFailureKind::Trap,
        EffectState::DefiniteRejection,
    );
    assert_eq!(rejected.effect_state(), EffectState::DefiniteRejection);
    assert_eq!(
        rejected.effect_code(),
        ContainmentDiagnosticCode::DefiniteRejection
    );
    assert_ne!(
        rejected.effect_code(),
        not_started.effect_code(),
        "the two definite effect states report their own codes"
    );
}

/// `GNT-23.4`: one settlement per operation, and a second settlement mutates nothing.
#[test]
fn second_settlement_is_refused_without_mutating_settled_state() {
    let owner = OwnerGeneration::new(4);
    let mut settlement = ContainmentSettlement::open(owner);
    assert!(!settlement.is_settled());
    assert_eq!(settlement.outcome(), None);

    let settled = settlement.settle(
        owner,
        Completion::observed(ExternalOutcome::Accepted, EffectState::NotStarted),
    );
    assert_eq!(settled, Ok(ExternalOutcome::Accepted));
    assert!(settlement.is_settled());

    let error = refused(settlement.settle(
        owner,
        Completion::observed(ExternalOutcome::Rejected, EffectState::NotStarted),
    ));
    assert_eq!(
        error.code(),
        ContainmentDiagnosticCode::SecondSettlementRefused
    );
    assert_eq!(
        error.clause(),
        "GNT-23.4-operation-ownership-and-single-settlement"
    );
    assert_eq!(error.settled_outcome(), Some(ExternalOutcome::Accepted));

    // The refusal is not a settlement: the settled outcome and the owner are unchanged.
    assert_eq!(settlement.outcome(), Some(ExternalOutcome::Accepted));
    assert_eq!(settlement.owner(), owner);
    assert_eq!(settlement.effect_state(), Some(EffectState::NotStarted));
}

/// `GNT-23.4`: a completion of another owner generation settles nothing.
#[test]
fn stale_generation_completion_is_refused_without_mutating_settled_state() {
    let owner = OwnerGeneration::new(9);
    let stale = OwnerGeneration::new(8);
    let mut settlement = ContainmentSettlement::open(owner);

    let error = refused(settlement.settle(
        stale,
        Completion::observed(ExternalOutcome::Accepted, EffectState::NotStarted),
    ));
    assert_eq!(
        error.code(),
        ContainmentDiagnosticCode::StaleGenerationRefused
    );
    assert_eq!(
        error.clause(),
        "GNT-23.4-operation-ownership-and-single-settlement"
    );
    assert!(matches!(
        error,
        ContainmentError::StaleGeneration { presented, held } if presented == stale && held == owner
    ));
    assert!(!settlement.is_settled());
    assert_eq!(settlement.outcome(), None);
    assert_eq!(settlement.effect_state(), None);

    // The generation that holds the operation still settles it exactly once.
    assert_eq!(
        settlement.settle(
            owner,
            Completion::observed(ExternalOutcome::Ambiguous, EffectState::Ambiguous)
        ),
        Ok(ExternalOutcome::Ambiguous)
    );

    // A well-formed completion of a stale generation presented to the settled operation is
    // refused as a repeated completion rather than as stale, which is the landed winner
    // order this clause refines: the repeated completion is decided before the generation.
    let after = refused(settlement.settle(
        stale,
        Completion::observed(ExternalOutcome::Rejected, EffectState::NotStarted),
    ));
    assert_eq!(
        after.code(),
        ContainmentDiagnosticCode::SecondSettlementRefused
    );
    assert_eq!(after.settled_outcome(), Some(ExternalOutcome::Ambiguous));
    assert_eq!(settlement.outcome(), Some(ExternalOutcome::Ambiguous));
}

/// `GNT-23.4`: a malformed completion is a distinct condition, neither a second
/// settlement nor a stale generation, and it settles nothing.
#[test]
fn malformed_completion_is_refused_distinctly_from_a_second_settlement() {
    let owner = OwnerGeneration::new(2);
    let mut settlement = ContainmentSettlement::open(owner);

    let error =
        refused(settlement.settle(owner, Completion::malformed(MalformedCompletion::NoOutcome)));
    assert_eq!(
        error.code(),
        ContainmentDiagnosticCode::MalformedCompletionRefused
    );
    assert_ne!(
        error.code(),
        ContainmentDiagnosticCode::SecondSettlementRefused
    );
    assert_ne!(
        error.code(),
        ContainmentDiagnosticCode::StaleGenerationRefused
    );
    assert_eq!(
        error.clause(),
        "GNT-23.4-operation-ownership-and-single-settlement"
    );
    assert!(matches!(
        error,
        ContainmentError::MalformedCompletion { cause } if cause == MalformedCompletion::NoOutcome
    ));
    assert_eq!(settlement.outcome(), None);

    assert!(
        settlement
            .settle(
                owner,
                Completion::malformed(MalformedCompletion::MultipleOutcomes)
            )
            .is_err()
    );
    assert_eq!(settlement.outcome(), None);
    assert_eq!(settlement.effect_state(), None);

    assert_eq!(
        MalformedCompletion::ALL.map(MalformedCompletion::wire_name),
        ["no-outcome", "multiple-outcomes"]
    );
    for cause in MalformedCompletion::ALL {
        assert_eq!(
            Some(cause),
            MalformedCompletion::from_wire_name(cause.wire_name())
        );
        assert_eq!(cause.as_str(), cause.wire_name());
        assert_eq!(
            cause.requirement(),
            "GNT-23.4-operation-ownership-and-single-settlement"
        );
    }
    for unknown in ["empty", "unknown"] {
        assert_eq!(None, MalformedCompletion::from_wire_name(unknown));
    }

    // A well-formed completion is the only shape that carries an outcome and an effect
    // state, so a malformed completion can never be read as either.
    let observed = Completion::observed(ExternalOutcome::Accepted, EffectState::NotStarted);
    assert_eq!(observed.outcome(), Some(ExternalOutcome::Accepted));
    assert_eq!(observed.effect(), Some(EffectState::NotStarted));
    assert!(!observed.is_malformed());
    let malformed = Completion::malformed(MalformedCompletion::NoOutcome);
    assert!(malformed.is_malformed());
    assert_eq!(malformed.outcome(), None);
    assert_eq!(malformed.effect(), None);
}

/// `GNT-23.4`: the refusals of one completion are decided in a fixed order, so a
/// completion refused for several reasons is refused for the first of them.
#[test]
fn refusal_precedence_puts_malformed_before_settled_before_stale() {
    let owner = OwnerGeneration::new(31);
    let stale = OwnerGeneration::new(30);

    // A malformed completion is refused as malformed even when it also names a stale
    // generation, because a malformed completion is its own distinct condition and is
    // never read as the stale completion it may also be.
    let mut settlement = ContainmentSettlement::open(owner);
    let malformed = refused(settlement.settle(
        stale,
        Completion::malformed(MalformedCompletion::MultipleOutcomes),
    ));
    assert_eq!(
        malformed.code(),
        ContainmentDiagnosticCode::MalformedCompletionRefused
    );
    assert_ne!(
        malformed.code(),
        ContainmentDiagnosticCode::StaleGenerationRefused
    );
    assert_ne!(
        malformed.code(),
        ContainmentDiagnosticCode::SecondSettlementRefused
    );
    assert!(!settlement.is_settled());

    // A stale generation is refused as stale while the operation is still open.
    let stale_refusal = refused(settlement.settle(
        stale,
        Completion::observed(ExternalOutcome::Accepted, EffectState::NotStarted),
    ));
    assert_eq!(
        stale_refusal.code(),
        ContainmentDiagnosticCode::StaleGenerationRefused
    );

    // The held generation settles the operation exactly once.
    assert_eq!(
        settlement.settle(
            owner,
            Completion::observed(ExternalOutcome::Accepted, EffectState::NotStarted)
        ),
        Ok(ExternalOutcome::Accepted)
    );

    // A well-formed completion presented to a settled operation is refused as a second
    // settlement, not as stale, following the landed settlement winner order.
    let repeated = refused(settlement.settle(
        stale,
        Completion::observed(ExternalOutcome::Rejected, EffectState::NotStarted),
    ));
    assert_eq!(
        repeated.code(),
        ContainmentDiagnosticCode::SecondSettlementRefused
    );
    assert_eq!(repeated.settled_outcome(), Some(ExternalOutcome::Accepted));
    assert_eq!(settlement.outcome(), Some(ExternalOutcome::Accepted));

    // A malformed completion is still malformed first on a settled operation.
    let after =
        refused(settlement.settle(owner, Completion::malformed(MalformedCompletion::NoOutcome)));
    assert_eq!(
        after.code(),
        ContainmentDiagnosticCode::MalformedCompletionRefused
    );
}

/// `GNT-23.3` and `GNT-23.4`: a definite accepted outcome presented over an ambiguous
/// effect is refused, and the refusal leaves the settlement exactly as it was.
#[test]
fn accepted_outcome_over_an_ambiguous_effect_is_refused_and_settles_nothing() {
    let owner = OwnerGeneration::new(21);
    let mut settlement = ContainmentSettlement::open(owner);

    let error = refused(settlement.settle(
        owner,
        Completion::observed(ExternalOutcome::Accepted, EffectState::Ambiguous),
    ));
    assert_eq!(
        error.code(),
        ContainmentDiagnosticCode::AmbiguousOutcomeRefused
    );
    assert_eq!(error.clause(), "GNT-23.3-effect-ambiguity-preservation");
    assert!(matches!(
        error,
        ContainmentError::AmbiguousOutcomeRefused { outcome, held }
            if outcome == ExternalOutcome::Accepted && held == EffectState::Ambiguous
    ));

    // The refusal is not a settlement and not an effect refinement: the operation still
    // holds no effect state and no outcome, so it can still be settled correctly.
    assert!(!settlement.is_settled());
    assert_eq!(settlement.outcome(), None);
    assert_eq!(settlement.effect_state(), None);
    assert_eq!(settlement.owner(), owner);

    // The bound is exactly the definite accepted outcome over an ambiguous effect: the same
    // ambiguous effect still settles an outcome that does not claim accepted work.
    assert_eq!(
        settlement.settle(
            owner,
            Completion::observed(ExternalOutcome::Rejected, EffectState::Ambiguous)
        ),
        Ok(ExternalOutcome::Rejected)
    );
    assert_eq!(settlement.effect_state(), Some(EffectState::Ambiguous));
    assert_eq!(settlement.outcome(), Some(ExternalOutcome::Rejected));
}

/// `GNT-23.6`: a containment report carries the declared metadata, the codes, and the
/// clause anchors, and nothing else.
#[test]
fn containment_report_carries_declared_metadata_and_codes_only() {
    let owner = OwnerGeneration::new(11);
    let report = match ContainmentVerdict::contain(
        ContainmentBoundary::Callback,
        ContainmentFailureClass::Foreign(ForeignFailureKind::Exception),
        EffectState::Ambiguous,
        owner,
        ReportScope::Declaration,
    ) {
        Ok(ContainmentVerdict::Contained(report)) => report,
        Ok(ContainmentVerdict::InvariantFailure) => unreachable!(
            "a foreign failure is contained at a boundary, not reported as an invariant failure"
        ),
        Err(error) => unreachable!(
            "a foreign failure is contained at a boundary, not refused as `{}`",
            error.code().as_str()
        ),
    };

    assert_eq!(report.boundary(), ContainmentBoundary::Callback);
    assert_eq!(
        report.failure_class(),
        ContainmentFailureClass::Foreign(ForeignFailureKind::Exception)
    );
    assert_eq!(report.effect_state(), EffectState::Ambiguous);
    assert_eq!(report.owner_generation(), owner);
    assert_eq!(
        report.diagnostic_code(),
        ContainmentDiagnosticCode::ForeignExceptionContained
    );
    assert_eq!(
        report.codes(),
        [
            ContainmentDiagnosticCode::ForeignExceptionContained,
            ContainmentDiagnosticCode::AmbiguousEffectPreserved
        ]
    );
    assert_eq!(
        report.clauses(),
        [
            "GNT-23.1-containment-boundaries",
            "GNT-23.2-foreign-failure-taxonomy",
            "GNT-23.3-effect-ambiguity-preservation"
        ]
    );
    assert_eq!(report.clause(), report.failure_class().requirement());
    assert_eq!(report.scope(), ReportScope::Declaration);
    assert!(!report.is_protected());

    // A report is declared metadata only: equal declarations produce the same report, and a
    // different declaration produces a different one, so no field beyond the declared ones
    // participates in the value.
    let same = match ContainmentReport::contained(
        ContainmentBoundary::Callback,
        ContainmentFailureClass::Foreign(ForeignFailureKind::Exception),
        EffectState::Ambiguous,
        owner,
        ReportScope::Declaration,
    ) {
        Ok(report) => report,
        Err(error) => unreachable!("a foreign failure is contained at a boundary, not `{error}`"),
    };
    // The report deliberately implements no `Debug`, so equality is asserted directly rather
    // than through a formatting assertion that would demand a rendering trait the report
    // omits.
    assert!(report == same);
    let protected = match ContainmentReport::contained(
        ContainmentBoundary::Callback,
        ContainmentFailureClass::Foreign(ForeignFailureKind::Exception),
        EffectState::Ambiguous,
        owner,
        ReportScope::ProtectedData,
    ) {
        Ok(report) => report,
        Err(error) => unreachable!("a foreign failure is contained at a boundary, not `{error}`"),
    };
    assert!(report != protected);
    assert!(protected.is_protected());
}

/// `GNT-23.6`: the canonical text of a report is exactly the declared fields, so it can
/// carry no poisoned-instance identity and no poison reason.
#[test]
fn canonical_report_text_carries_exactly_the_declared_fields_and_no_poison_record() {
    let owner = OwnerGeneration::new(11);
    for scope in ReportScope::ALL {
        let report = match ContainmentReport::contained(
            ContainmentBoundary::Callback,
            ContainmentFailureClass::Foreign(ForeignFailureKind::Exception),
            EffectState::Ambiguous,
            owner,
            scope,
        ) {
            Ok(report) => report,
            Err(error) => {
                unreachable!("a foreign failure is contained at a boundary, not `{error}`")
            }
        };
        assert_eq!(report.is_protected(), scope.is_protected());
        assert_eq!(
            report.canonical_text().is_ok(),
            !scope.is_protected(),
            "only a declaration-scope report renders for an ordinary observer"
        );

        let rendered = match scope {
            ReportScope::Declaration => match report.canonical_text() {
                Ok(text) => text,
                Err(error) => unreachable!("a declaration-scope report renders, not `{error}`"),
            },
            ReportScope::ProtectedData => report.protected_text(&AuditAccess::granted()),
        };
        assert_eq!(
            rendered,
            expected_canonical_text(
                "callback",
                "foreign-exception",
                "fault-foreign-exception-contained",
                owner.value(),
                scope.wire_name(),
            ),
            "the canonical text of the `{}` scope is exactly the declared fields",
            scope.wire_name()
        );

        // The full-string equality above already fails for an extra field; these assertions
        // fail with a message that names the field that reappeared, and they are the exact
        // fields the hardened model removed from the canonical text.
        assert!(
            !rendered.contains("instance="),
            "the `{}` report text carries no poisoned-instance field: {rendered}",
            scope.wire_name()
        );
        assert!(
            !rendered.contains("poison-reason="),
            "the `{}` report text carries no poison-reason field: {rendered}",
            scope.wire_name()
        );
        assert!(rendered.contains("effect-code=fault-ambiguous-effect-preserved"));
        assert!(rendered.contains(&format!("owner={}", owner.value())));
        assert!(rendered.contains(&format!("class={}", report.failure_class().wire_name())));
        assert_eq!(
            report.codes().map(ContainmentDiagnosticCode::as_str),
            [
                "fault-foreign-exception-contained",
                "fault-ambiguous-effect-preserved"
            ]
        );
    }
}

/// `GNT-23.6`: a report relating to protected data is itself protected and is reachable
/// only through the landed protected-diagnostic capability.
#[test]
fn protected_containment_report_is_withheld_from_ordinary_observation() {
    let owner = OwnerGeneration::new(3);
    assert_eq!(
        ReportScope::ALL.map(ReportScope::wire_name),
        ["declaration", "protected-data"]
    );
    assert!(ReportScope::ProtectedData.is_protected());
    assert!(!ReportScope::Declaration.is_protected());
    assert_eq!(
        ReportScope::ProtectedData.requirement(),
        "GNT-23.6-protected-fault-diagnostics"
    );
    for scope in ReportScope::ALL {
        assert_eq!(Some(scope), ReportScope::from_wire_name(scope.wire_name()));
        assert_eq!(scope.as_str(), scope.wire_name());
        assert_eq!(scope.requirement(), "GNT-23.6-protected-fault-diagnostics");
    }
    for unknown in ["protected", "declared"] {
        assert_eq!(None, ReportScope::from_wire_name(unknown));
    }

    let protected = match ContainmentReport::contained(
        ContainmentBoundary::Completion,
        ContainmentFailureClass::Foreign(ForeignFailureKind::Trap),
        EffectState::Ambiguous,
        owner,
        ReportScope::ProtectedData,
    ) {
        Ok(report) => report,
        Err(error) => unreachable!("a foreign failure is contained at a boundary, not `{error}`"),
    };
    assert!(protected.is_protected());

    let withheld = refused(protected.canonical_text());
    assert_eq!(
        withheld.code(),
        ContainmentDiagnosticCode::ProtectedDiagnosticWithheld
    );
    assert_eq!(withheld.clause(), "GNT-23.6-protected-fault-diagnostics");
    assert!(matches!(
        withheld,
        ContainmentError::ProtectedDiagnosticWithheld { code }
            if code == ContainmentDiagnosticCode::ForeignTrapContained
    ));

    let rendered = protected.protected_text(&AuditAccess::granted());
    assert_eq!(
        rendered,
        expected_canonical_text(
            "completion",
            "foreign-trap",
            "fault-foreign-trap-contained",
            owner.value(),
            "protected-data",
        ),
        "the protected rendering carries exactly the declared metadata and codes"
    );
}

/// `GNT-23.5`: poisoning is one-way, recorded once, and refuses reuse.
#[test]
fn poisoning_is_one_way_and_refuses_reuse() {
    let mut ledger = PoisonLedger::new();
    assert!(ledger.is_empty());
    assert_eq!(ledger.len(), 0);

    let abi = abi(RecoveryClass::ReadOnly);
    let mut instance = adapter("ReuseAdapter", &[AuthorityRight::InvokeReadOnly], 5, 1);
    assert!(!instance.is_poisoned());
    assert_eq!(instance.dispatch(&abi), Ok(()));
    assert_eq!(ledger.recorded_reason(&instance), None);
    assert_eq!(ledger.reuse_refusal(&instance), Ok(()));

    let reason = ledger.poison(
        &mut instance,
        PoisonReason::ForeignFailure(ForeignFailureKind::Panic),
    );
    assert_eq!(
        reason,
        PoisonReason::ForeignFailure(ForeignFailureKind::Panic)
    );
    assert!(instance.is_poisoned());
    assert_eq!(instance.digest_hex().len(), 64);
    assert_eq!(
        instance.as_str(),
        format!("adapter-instance:{}", instance.digest_hex())
    );
    assert_eq!(ledger.len(), 1);
    assert_eq!(
        ledger.recorded_reason(&instance),
        Some(PoisonReason::ForeignFailure(ForeignFailureKind::Panic))
    );

    // Reuse of the poisoned instance is refused through the landed flag, and the refusal
    // reports the identity of the landed instance and the reason this ledger recorded.
    let error = refused(ledger.reuse_refusal(&instance));
    assert_eq!(
        error.code(),
        ContainmentDiagnosticCode::PoisonedInstanceRefused
    );
    assert_eq!(
        error.clause(),
        "GNT-23.5-failed-instance-poisoning-and-isolation"
    );
    assert_eq!(
        error.poison_reason(),
        Some(PoisonReason::ForeignFailure(ForeignFailureKind::Panic))
    );
    assert!(error.to_string().contains(instance.as_str()));

    // The landed dispatch of the poisoned instance is refused with the landed code.
    assert_eq!(
        abi_refusal(instance.dispatch(&abi)),
        OperationAbiDiagnosticCode::AdapterInstancePoisoned
    );

    // The reason vocabulary is closed, ordered, and anchored to `GNT-23.5`.
    assert_eq!(
        PoisonReason::ALL.map(PoisonReason::wire_name),
        [
            "foreign-panic",
            "foreign-exception",
            "foreign-trap",
            "foreign-protocol",
            "ambiguous-effect",
            "gantry-invariant-failure"
        ]
    );
    let spellings: BTreeSet<&str> = PoisonReason::ALL
        .into_iter()
        .map(PoisonReason::wire_name)
        .collect();
    assert_eq!(spellings.len(), PoisonReason::ALL.len());
    for reason in PoisonReason::ALL {
        assert_eq!(
            Some(reason),
            PoisonReason::from_wire_name(reason.wire_name())
        );
        assert_eq!(reason.as_str(), reason.wire_name());
        assert_eq!(
            reason.requirement(),
            "GNT-23.5-failed-instance-poisoning-and-isolation"
        );
    }
    for unknown in ["panic", "unrecorded", "none"] {
        assert_eq!(None, PoisonReason::from_wire_name(unknown));
    }
}

/// `GNT-23.5`: poisoning lands on the adapter instance, the first reason is fixed, and the
/// landed dispatch refuses a poisoned instance.
#[test]
fn poisoning_through_the_landed_instance_fixes_the_first_reason_and_refuses_dispatch() {
    let abi = abi(RecoveryClass::ReadOnly);
    let mut poisoned = adapter("ReasonAdapter", &[AuthorityRight::InvokeReadOnly], 5, 1);
    let unaffected = adapter("UnaffectedAdapter", &[AuthorityRight::InvokeReadOnly], 5, 2);
    let mut ledger = PoisonLedger::new();
    assert_eq!(unaffected.dispatch(&abi), Ok(()));

    let fixed = ledger.poison(
        &mut poisoned,
        PoisonReason::ForeignFailure(ForeignFailureKind::Trap),
    );
    assert_eq!(
        fixed,
        PoisonReason::ForeignFailure(ForeignFailureKind::Trap)
    );
    assert!(poisoned.is_poisoned());
    assert_eq!(ledger.len(), 1);

    // A repeated poisoning stutters: it reports the recorded reason instead of rewriting
    // it, and it adds no second identity to the ledger.
    let repeated = ledger.poison(&mut poisoned, PoisonReason::AmbiguousEffect);
    assert_eq!(
        repeated,
        PoisonReason::ForeignFailure(ForeignFailureKind::Trap)
    );
    assert_eq!(
        ledger.recorded_reason(&poisoned),
        Some(PoisonReason::ForeignFailure(ForeignFailureKind::Trap))
    );
    assert_eq!(ledger.len(), 1);

    // A poisoning that arrives with a different reason does not rewrite the recorded one,
    // whether it arrives through the landing path or through the record-only path.
    let recorded = ledger.record(&poisoned, PoisonReason::InvariantFailure);
    assert_eq!(
        recorded,
        PoisonReason::ForeignFailure(ForeignFailureKind::Trap)
    );
    assert_eq!(
        ledger.recorded_reason(&poisoned),
        Some(PoisonReason::ForeignFailure(ForeignFailureKind::Trap))
    );
    assert_eq!(ledger.len(), 1);
    assert!(poisoned.is_poisoned());

    // The landed dispatch refuses the poisoned instance, so reuse is refused by the landed
    // adapter contract rather than by a flag of this model.
    assert_eq!(
        abi_refusal(poisoned.dispatch(&abi)),
        OperationAbiDiagnosticCode::AdapterInstancePoisoned
    );

    // A fresh ledger over the same landed identity still cannot admit the poisoned
    // instance, because the refusal is decided by the landed one-way flag and not by the
    // reason this model recorded.
    let fresh = PoisonLedger::new();
    assert!(fresh.is_empty());
    let refusal = refused(fresh.reuse_refusal(&poisoned));
    assert_eq!(
        refusal.code(),
        ContainmentDiagnosticCode::PoisonedInstanceRefused
    );
    assert_eq!(refusal.poison_reason(), None);
    assert_eq!(fresh.recorded_reason(&poisoned), None);
    assert!(poisoned.is_poisoned());

    // An unaffected instance is still dispatchable and still admits reuse.
    assert!(!unaffected.is_poisoned());
    assert_eq!(unaffected.dispatch(&abi), Ok(()));
    assert_eq!(ledger.reuse_refusal(&unaffected), Ok(()));
    assert_eq!(fresh.reuse_refusal(&unaffected), Ok(()));
    assert_eq!(ledger.recorded_reason(&unaffected), None);
    assert_ne!(unaffected.as_str(), poisoned.as_str());
}

/// `GNT-23.5`: poisoning never widens to unaffected instances or sibling work.
#[test]
fn poisoning_does_not_widen_to_unaffected_instances() {
    let abi = abi(RecoveryClass::ReadOnly);
    let mut ledger = PoisonLedger::new();
    let mut poisoned = adapter("IsolationAdapterA", &[AuthorityRight::InvokeReadOnly], 5, 1);
    let mut sibling = adapter("IsolationAdapterB", &[AuthorityRight::InvokeReadOnly], 5, 1);
    let later = adapter("IsolationAdapterA", &[AuthorityRight::InvokeReadOnly], 6, 1);

    let _ = ledger.poison(
        &mut poisoned,
        PoisonReason::ForeignFailure(ForeignFailureKind::Panic),
    );
    assert_eq!(ledger.len(), 1);

    // Distinct landed declarations are distinct identities, so a neighbouring decision
    // never poisons an instance that was not itself poisoned.
    assert_ne!(sibling.as_str(), poisoned.as_str());
    assert_ne!(later.as_str(), poisoned.as_str());
    assert!(!sibling.is_poisoned());
    assert!(!later.is_poisoned());
    assert_eq!(ledger.recorded_reason(&sibling), None);
    assert_eq!(ledger.recorded_reason(&later), None);
    assert_eq!(ledger.reuse_refusal(&sibling), Ok(()));
    assert_eq!(ledger.reuse_refusal(&later), Ok(()));
    assert_eq!(sibling.dispatch(&abi), Ok(()));
    assert_eq!(later.dispatch(&abi), Ok(()));

    // A sibling that is itself poisoned records its own reason and nothing else.
    let reason = ledger.poison(&mut sibling, PoisonReason::AmbiguousEffect);
    assert_eq!(reason, PoisonReason::AmbiguousEffect);
    assert_eq!(ledger.len(), 2);
    assert_eq!(
        ledger.recorded_reason(&poisoned),
        Some(PoisonReason::ForeignFailure(ForeignFailureKind::Panic))
    );
    assert_eq!(
        ledger.recorded_reason(&sibling),
        Some(PoisonReason::AmbiguousEffect)
    );
    assert_eq!(
        refused(ledger.reuse_refusal(&sibling)).code(),
        ContainmentDiagnosticCode::PoisonedInstanceRefused
    );
    assert_eq!(
        abi_refusal(sibling.dispatch(&abi)),
        OperationAbiDiagnosticCode::AdapterInstancePoisoned
    );

    // The third declaration keeps dispatching, so poisoning one instance never widens to
    // the sibling work of another declaration or another owner generation.
    assert!(!later.is_poisoned());
    assert_eq!(later.dispatch(&abi), Ok(()));
    assert_eq!(ledger.reuse_refusal(&later), Ok(()));
}

/// `GNT-23.5`: resource poisoning reuses the landed poisoned state and refuses a resource
/// that already reached a terminal state.
#[test]
fn poison_resource_state_reuses_the_landed_poisoned_state_and_refuses_terminal_states() {
    for state in [
        ResourceState::Usable,
        ResourceState::PartiallyAdvanced,
        ResourceState::HalfClosed,
    ] {
        assert_eq!(
            poison_resource_state(state),
            Ok(ResourceState::Poisoned),
            "a `{}` resource poisons into the landed poisoned state",
            state.wire_name()
        );
    }

    // A repeated poisoning stutters: the state the resource already holds is reported
    // instead of a second transition being invented.
    assert_eq!(
        poison_resource_state(ResourceState::Poisoned),
        Ok(ResourceState::Poisoned)
    );

    for state in [ResourceState::Consumed, ResourceState::Closed] {
        let error = refused(poison_resource_state(state));
        assert_eq!(
            error.code(),
            ContainmentDiagnosticCode::ResourcePoisoningRefused
        );
        assert_eq!(
            error.clause(),
            "GNT-23.5-failed-instance-poisoning-and-isolation"
        );
        assert!(matches!(
            error,
            ContainmentError::ResourcePoisoningRefused { state: terminal } if terminal == state
        ));
    }

    // Every landed resource state is decided, and the two sets are exactly the vocabulary.
    let poisonable: BTreeSet<ResourceState> = ResourceState::ALL
        .into_iter()
        .filter(|state| poison_resource_state(*state) == Ok(ResourceState::Poisoned))
        .collect();
    assert_eq!(
        poisonable,
        BTreeSet::from([
            ResourceState::Usable,
            ResourceState::PartiallyAdvanced,
            ResourceState::HalfClosed,
            ResourceState::Poisoned
        ])
    );
    let terminal: BTreeSet<ResourceState> = ResourceState::ALL
        .into_iter()
        .filter(|state| poison_resource_state(*state).is_err())
        .collect();
    assert_eq!(
        terminal,
        BTreeSet::from([ResourceState::Consumed, ResourceState::Closed])
    );
    assert_eq!(poisonable.len() + terminal.len(), ResourceState::ALL.len());
}

/// `GNT-23.7`: a declaration of containment is decided against the boundaries the adapter
/// carries rather than accepted as a name.
#[test]
fn containment_declaration_is_decided_against_the_boundaries_the_adapter_carries() {
    let carried = ContainmentPlan::of(&[
        ContainmentBoundary::Call,
        ContainmentBoundary::Poll,
        ContainmentBoundary::Destructor,
    ]);
    assert_eq!(carried.len(), 3);
    assert!(!carried.is_empty());
    assert!(carried.contains(ContainmentBoundary::Poll));
    assert!(!carried.contains(ContainmentBoundary::Callback));
    assert!(carried.covers(&carried));
    assert!(ContainmentPlan::all().covers(&carried));
    assert!(!carried.covers(&ContainmentPlan::all()));
    assert!(ContainmentPlan::of(&[]).is_empty());

    let partial = ContainmentPlan::of(&[ContainmentBoundary::Call, ContainmentBoundary::Poll]);
    assert!(!partial.covers(&carried));
    assert_eq!(
        partial.missing_from(&carried),
        [ContainmentBoundary::Destructor]
    );
    assert!(partial.missing_from(&partial).is_empty());

    // A declaration whose plan does not cover a carried boundary is refused, and the
    // refusal names the missing boundaries in clause order.
    let error = refused(check_containment_declaration(
        ContainmentDeclaration::declared(ContainmentBoundary::Callback, partial.clone()),
        &carried,
    ));
    assert_eq!(
        error.code(),
        ContainmentDiagnosticCode::ContainmentPlanIncomplete
    );
    assert_eq!(error.clause(), "GNT-23.7-adapter-containment-obligations");
    assert_eq!(error.requirement(), error.clause());
    assert_eq!(
        error.missing_boundaries(),
        [ContainmentBoundary::Destructor].as_slice()
    );
    assert!(error.to_string().contains("destructor"));

    let empty_error = refused(check_containment_declaration(
        ContainmentDeclaration::declared(ContainmentBoundary::Call, ContainmentPlan::of(&[])),
        &carried,
    ));
    assert_eq!(
        empty_error.missing_boundaries(),
        [
            ContainmentBoundary::Call,
            ContainmentBoundary::Poll,
            ContainmentBoundary::Destructor
        ]
        .as_slice()
    );

    // A plan that covers every carried boundary is accepted and returned as declared, so
    // the check decides coverage rather than pattern-matching one spelling.
    let complete = ContainmentPlan::all();
    assert_eq!(
        check_containment_declaration(
            ContainmentDeclaration::declared(ContainmentBoundary::Call, complete.clone()),
            &carried,
        ),
        Ok(complete.clone())
    );
    let exact = ContainmentPlan::of(&ContainmentBoundary::ALL);
    assert_eq!(
        check_containment_declaration(
            ContainmentDeclaration::declared(ContainmentBoundary::Poll, exact.clone()),
            &carried,
        ),
        Ok(exact.clone())
    );
    let superset = ContainmentPlan::of(&[
        ContainmentBoundary::Call,
        ContainmentBoundary::Poll,
        ContainmentBoundary::Completion,
        ContainmentBoundary::Destructor,
    ]);
    assert_eq!(
        check_containment_declaration(
            ContainmentDeclaration::declared(ContainmentBoundary::Callback, superset.clone()),
            &carried,
        ),
        Ok(superset)
    );
    assert_eq!(
        check_containment_declaration(
            ContainmentDeclaration::declared_for_all(ContainmentBoundary::Destructor),
            &carried,
        ),
        Ok(ContainmentPlan::all())
    );

    // The carried set is a caller argument, so the same declared plan is accepted for a
    // narrower adapter and refused for a wider one.
    assert_eq!(
        check_containment_declaration(
            ContainmentDeclaration::declared(ContainmentBoundary::Call, partial.clone()),
            &ContainmentPlan::of(&[ContainmentBoundary::Call]),
        ),
        Ok(partial.clone())
    );
    assert!(
        check_containment_declaration(
            ContainmentDeclaration::declared(ContainmentBoundary::Call, partial),
            &ContainmentPlan::of(&ContainmentBoundary::ALL),
        )
        .is_err()
    );
}

/// `GNT-23.2`: a failure the boundary cannot attribute is refused under its own code and
/// is never mapped onto one of the four foreign classes.
#[test]
fn unattributable_foreign_failure_is_refused_with_its_own_code() {
    assert_eq!(
        ForeignFailureObservation::ALL.map(ForeignFailureObservation::wire_name),
        ["panic", "exception", "trap", "protocol", "unattributable"]
    );

    for kind in ForeignFailureKind::ALL {
        let attributed = ForeignFailureObservation::Attributed(kind);
        assert_eq!(attributed.kind(), Some(kind));
        assert!(attributed.is_attributable());
        assert_eq!(attributed.as_str(), attributed.wire_name());
        assert_eq!(
            attributed.requirement(),
            "GNT-23.2-foreign-failure-taxonomy"
        );
        assert_eq!(
            Some(attributed),
            ForeignFailureObservation::from_wire_name(attributed.wire_name())
        );
        assert_eq!(
            attribute_foreign_failure(attributed),
            Ok(ContainmentFailureClass::Foreign(kind))
        );
        assert_eq!(
            match attribute_foreign_failure(attributed) {
                Ok(class) => class.code(),
                Err(error) => unreachable!(
                    "an attributed observation is attributed, not refused as `{error}`"
                ),
            },
            kind.code()
        );
    }

    let unattributable = ForeignFailureObservation::Unattributable;
    assert_eq!(unattributable.kind(), None);
    assert!(!unattributable.is_attributable());
    assert_eq!(unattributable.wire_name(), "unattributable");
    assert_eq!(
        Some(unattributable),
        ForeignFailureObservation::from_wire_name("unattributable")
    );
    for unknown in ["generic", "unknown", "foreign", "class"] {
        assert_eq!(None, ForeignFailureObservation::from_wire_name(unknown));
    }

    let error = refused(attribute_foreign_failure(unattributable));
    assert_eq!(
        error.code(),
        ContainmentDiagnosticCode::UnattributableFailureRefused
    );
    assert_eq!(error.clause(), "GNT-23.2-foreign-failure-taxonomy");
    assert!(matches!(
        error,
        ContainmentError::UnattributableFailure { observed } if observed == unattributable
    ));
    // The refusal is never mapped onto a class, so it borrows no foreign class code, no
    // invariant code, and no other condition's payload.
    for kind in ForeignFailureKind::ALL {
        assert_ne!(error.code(), kind.code());
    }
    assert_ne!(
        error.code(),
        ContainmentDiagnosticCode::GantryInvariantFailure
    );
    assert_ne!(
        error.code(),
        ContainmentDiagnosticCode::InvariantFailureNotContainable
    );
    assert_eq!(error.poison_reason(), None);
    assert!(error.missing_boundaries().is_empty());
    assert_eq!(error.refused_obligation(), None);
    assert_eq!(error.settled_outcome(), None);
}

/// `GNT-23.8`: the non-claim vocabulary is closed, ordered, and distinct.
#[test]
fn containment_non_claim_vocabulary_is_closed_ordered_and_distinct() {
    assert_eq!(
        CONTAINMENT_NON_CLAIM_NAMES.map(ContainmentNonClaimName::wire_name),
        [
            "arbitrary-memory-corruption-guarantee",
            "rollback-after-effects",
            "platform-abi-guarantee",
            "poisoned-instance-repair",
            "protected-payload-or-backtrace-disclosure"
        ]
    );
    assert_eq!(
        CONTAINMENT_NON_CLAIM_ORDER.len(),
        CONTAINMENT_NON_CLAIM_NAMES.len()
    );

    let mut statements: BTreeSet<&str> = BTreeSet::new();
    for (index, non_claim) in CONTAINMENT_NON_CLAIM_ORDER.iter().enumerate() {
        assert_eq!(
            non_claim.name(),
            CONTAINMENT_NON_CLAIM_NAMES[index],
            "the published non-claims follow the published name order"
        );
        assert_eq!(
            non_claim.name().requirement(),
            "GNT-23.8-containment-non-claims"
        );
        assert!(
            statements.insert(non_claim.statement()),
            "each non-claim states a distinct limit"
        );
    }
    assert_eq!(statements.len(), 5);

    for name in ContainmentNonClaimName::ALL {
        assert_eq!(
            Some(name),
            ContainmentNonClaimName::from_wire_name(name.wire_name())
        );
        assert_eq!(name.as_str(), name.wire_name());
    }
    for unknown in ["rollback-after-completion", "memory-safety-guarantee"] {
        assert_eq!(None, ContainmentNonClaimName::from_wire_name(unknown));
    }
}

/// `GNT-23.6`: the code registry holds one code per condition, in sorted code order, and
/// every code maps to exactly one of the nine clause keys.
#[test]
fn every_diagnostic_code_maps_to_exactly_one_clause_key() {
    let mut spellings: BTreeSet<&str> = BTreeSet::new();
    for (index, code) in ContainmentDiagnosticCode::ALL.iter().enumerate() {
        assert!(
            spellings.insert(code.as_str()),
            "`{}` is registered once",
            code.as_str()
        );
        assert_eq!(code.wire_name(), code.as_str());
        assert!(
            FAULT_CONTAINMENT_CLAUSES.contains(&code.requirement()),
            "`{}` maps outside the nine anchors",
            code.as_str()
        );
        assert!(!code.meaning().is_empty());
        if index > 0 {
            let previous = ContainmentDiagnosticCode::ALL[index - 1];
            assert!(
                previous.as_str() < code.as_str(),
                "the registry is in sorted code order"
            );
        }
    }
    assert_eq!(spellings.len(), ContainmentDiagnosticCode::ALL.len());

    let owned: BTreeSet<&str> = ContainmentDiagnosticCode::ALL
        .into_iter()
        .map(|code| code.requirement())
        .collect();
    assert_eq!(
        owned,
        BTreeSet::from([
            "GNT-23.2-foreign-failure-taxonomy",
            "GNT-23.3-effect-ambiguity-preservation",
            "GNT-23.4-operation-ownership-and-single-settlement",
            "GNT-23.5-failed-instance-poisoning-and-isolation",
            "GNT-23.6-protected-fault-diagnostics",
            "GNT-23.7-adapter-containment-obligations"
        ])
    );

    // The two definite effect conditions and the three `GNT-23.3` refusals that constrain
    // an ambiguous effect are registered under codes of their own, so no condition shares a
    // code with another and the preserved code is not borrowed by a refusal.
    for code in [
        ContainmentDiagnosticCode::DefiniteNotStarted,
        ContainmentDiagnosticCode::DefiniteRejection,
        ContainmentDiagnosticCode::DefiniteEffectMadeAmbiguous,
        ContainmentDiagnosticCode::AmbiguousEffectMadeDefinite,
        ContainmentDiagnosticCode::AmbiguousOutcomeRefused,
    ] {
        assert!(ContainmentDiagnosticCode::ALL.contains(&code));
        assert_eq!(code.requirement(), "GNT-23.3-effect-ambiguity-preservation");
    }
    assert_eq!(
        ContainmentDiagnosticCode::AmbiguousEffectMadeDefinite.requirement(),
        ContainmentDiagnosticCode::AmbiguousEffectPreserved.requirement()
    );
    assert_ne!(
        ContainmentDiagnosticCode::AmbiguousEffectMadeDefinite,
        ContainmentDiagnosticCode::AmbiguousEffectPreserved
    );
}

/// `GNT-23.0`: every condition the model can decide owns one code, one clause anchor, and
/// one code spelling, and the codes of the conditions are exactly the registry entries the
/// reports and the states do not own.
#[test]
fn every_condition_owns_its_code_its_clause_and_a_distinct_spelling() {
    let conditions = every_condition();
    assert_eq!(
        conditions.len(),
        14,
        "the model decides fourteen refusal conditions"
    );

    let mut condition_codes: BTreeSet<ContainmentDiagnosticCode> = BTreeSet::new();
    let mut condition_spellings: BTreeSet<&str> = BTreeSet::new();
    for error in &conditions {
        let code = error.code();
        assert!(
            ContainmentDiagnosticCode::ALL.contains(&code),
            "`{}` is a registered code",
            code.as_str()
        );
        assert!(!code.meaning().is_empty());
        assert!(
            FAULT_CONTAINMENT_CLAUSES.contains(&error.clause()),
            "`{}` is not anchored to a published clause",
            code.as_str()
        );
        assert_eq!(error.requirement(), error.clause());
        assert_eq!(error.clause(), code.requirement());
        assert!(error.to_string().starts_with(code.as_str()));
        assert!(
            condition_spellings.insert(code.as_str()),
            "`{}` is the code of more than one condition",
            code.as_str()
        );
        assert!(condition_codes.insert(code));
    }
    assert_eq!(
        condition_spellings.len(),
        conditions.len(),
        "no two conditions share a code spelling"
    );
    assert_eq!(condition_codes.len(), conditions.len());

    // The codes the model publishes for a contained report or an effect state are disjoint
    // from the codes of the conditions, and the two sets together are the whole registry, so
    // every registered code is owned by exactly one condition or exactly one report field.
    let mut report_codes: BTreeSet<ContainmentDiagnosticCode> = ForeignFailureKind::ALL
        .into_iter()
        .map(ForeignFailureKind::code)
        .collect();
    report_codes.insert(ContainmentVerdict::invariant_failure().code());
    for state in EffectState::ALL {
        report_codes.insert(state.code());
    }
    for code in &report_codes {
        assert!(
            !condition_codes.contains(code),
            "`{}` is both a condition code and a reported code",
            code.as_str()
        );
    }
    let union: BTreeSet<ContainmentDiagnosticCode> =
        condition_codes.union(&report_codes).copied().collect();
    let registry: BTreeSet<ContainmentDiagnosticCode> =
        ContainmentDiagnosticCode::ALL.into_iter().collect();
    assert_eq!(union, registry);
    assert_eq!(
        condition_codes.len() + report_codes.len(),
        ContainmentDiagnosticCode::ALL.len()
    );
}
