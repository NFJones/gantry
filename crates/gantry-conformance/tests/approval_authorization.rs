//! Machine-checked conformance for `GNT-19.9-execution-and-release-separation`:
//! authorization to execute an operation and authorization to release its data
//! are independent.
//!
//! These tests exercise the public `gantry::ir` surface of the landed
//! `GNT-15.10-release-operation` and `GNT-15.10-protection-invariants` rules
//! together with the admission model of `GNT-3-T-AUTHORITY-ADMISSION` and the
//! protected-value model of `GNT-15.10-protected-values`. They check the model
//! the specification makes normative, not a runtime approval store: no test here
//! observes an approver, a live sink, a provider, a host service, or a protected
//! payload.
//!
//! Both directions of the separation are carried by negative evidence. An
//! operation that passed the ordinary admission commit point reaches no release
//! path, and a holder-derived release grant admits no operation that the
//! authority model refuses. Where the public types make a positive compile-time
//! statement impossible, the test asserts the observable behaviour of the
//! surface instead: an authority right and an admission request are not values
//! the release vocabulary consumes, and a release decision is not an execution
//! decision.

use gantry::ir::generated::RecoveryClass;
use gantry::ir::{
    AUTHORITY_RIGHT_ORDER, Admission, AdmissionRequest, AncestorFences, AuditAccess, AuditOutcome,
    AuthorityBindingId, AuthorityError, AuthorityGeneration, AuthorityInstance,
    AuthorityInstanceId, AuthorityLeasePolicy, AuthorityRequirementId, AuthorityRight,
    CanonicalImplementationIdentity, CanonicalPath, CanonicalSignature, DeclaredName,
    DisclosureBudget, DisclosureCharge, FenceState, ProjectionKind, ProtectedDataClass,
    ProtectedValue, ProvenanceOrigin, ProvenanceOriginKind, ReleaseAuthorityError, ReleaseDecision,
    ReleaseDestination, ReleaseGrant, ReleaseHolderAuthority, ReleaseHolderBindingId,
    ReleaseHolderId, ReleaseOutcome, ReleaseProjection, ReleaseRejection, ReleaseSite,
    ReleasedValue, RightsSet, TypeDescriptor, TypeExpression,
};
use sha2::{Digest, Sha256};

/// Compile-time proof that one type implements none of the listed traits.
///
/// A blanket implementation and a trait-bounded implementation both apply, so
/// naming the associated item requires an inference that cannot be resolved and
/// compilation fails. A release grant or a release-holder authority that
/// acquired `Default`, a conversion from an authority right, a rights set, an
/// admission request, an admitted operation, an authority instance or its
/// identity, or a deserializer would stop this crate compiling. Those are
/// exactly the ordinary values `GNT-19.9` forbids as substitutes for release
/// authority: no authority right and no admission request may be turned into
/// release permission, and no ordinary representation may be deserialized into
/// one.
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

/// The capability family used by every authority fixture.
const FAMILY: &str = "action";

/// The declared release site of every release fixture.
const SITE: &str = "crate::release";

/// Returns one deterministic lowercase hexadecimal digest of one seed.
fn digest_hex(seed: &str) -> String {
    format!("{:x}", Sha256::digest(seed.as_bytes()))
}

/// Builds the canonical path of the fixture requirement.
fn fixture_path() -> CanonicalPath {
    CanonicalPath::new("crate::read_only")
        .unwrap_or_else(|_| unreachable!("fixture path is canonical"))
}

/// Builds the public capability requirement of the authority fixture.
fn fixture_requirement() -> AuthorityRequirementId {
    AuthorityRequirementId::new(
        &fixture_path(),
        &CanonicalSignature::action(
            RecoveryClass::ReadOnly,
            &fixture_path(),
            &[],
            &TypeDescriptor::STRING,
        ),
        FAMILY,
        RecoveryClass::ReadOnly,
    )
    .unwrap_or_else(|_| unreachable!("fixture family is portable"))
}

/// Builds the downstream integration identity of the fixture holder.
fn fixture_integration() -> CanonicalImplementationIdentity {
    let receiver = TypeExpression::from_canonical_string("crate::ApprovalFixture", 4)
        .unwrap_or_else(|_| unreachable!("fixture receiver is a canonical type"));
    CanonicalImplementationIdentity::inherent(&receiver)
}

/// Builds one selected implementation binding for a requirement.
fn fixture_binding(requirement: &AuthorityRequirementId) -> AuthorityBindingId {
    AuthorityBindingId::new(requirement, &fixture_integration())
}

/// Validates one canonical fixture declared name.
fn fixture_name(value: &str) -> DeclaredName {
    DeclaredName::new(value).unwrap_or_else(|_| unreachable!("fixture name is canonical"))
}

/// Declares one fixture provenance origin.
fn fixture_origin(value: &str) -> ProvenanceOrigin {
    ProvenanceOrigin::new(ProvenanceOriginKind::IntegrationBoundary, value)
        .unwrap_or_else(|_| unreachable!("fixture origin is canonical"))
}

/// Seals one fixture protected value of one class and one declared origin name.
fn sealed(class: ProtectedDataClass, origin_name: &str) -> ProtectedValue {
    ProtectedValue::seal(class, fixture_origin(origin_name))
}

/// Returns one nonzero fixture disclosure charge.
fn charge(value: u64) -> DisclosureCharge {
    DisclosureCharge::new(value).unwrap_or_else(|| unreachable!("fixture charge is nonzero"))
}

/// Creates one fixture disclosure budget.
fn disclosure_budget(remaining: u64, charge_value: u64) -> DisclosureBudget {
    DisclosureBudget::new(remaining, charge(charge_value))
}

/// Binds one holder authority over the fixture release site.
fn authority(
    classes: &[ProtectedDataClass],
    destinations: &[ReleaseDestination],
) -> ReleaseHolderAuthority {
    let site = fixture_name(SITE);
    let binding = ReleaseHolderBindingId::new(&site, &fixture_integration());
    ReleaseHolderAuthority::bind(&site, binding, classes, destinations)
        .unwrap_or_else(|_| unreachable!("the fixture binding names its own site"))
}

/// Binds one holder authority that may release nothing.
fn withholding_authority() -> ReleaseHolderAuthority {
    authority(&[], &[])
}

/// Builds one release site declaring exactly one class and destination pair.
fn site(class: ProtectedDataClass, destination: ReleaseDestination) -> ReleaseSite {
    ReleaseSite::new(SITE).declare(class, destination, ProjectionKind::Redacted)
}

/// Binds one capability instance carrying exactly the named rights.
fn instance(rights: &[AuthorityRight]) -> AuthorityInstance {
    let requirement = fixture_requirement();
    let binding = fixture_binding(&requirement);
    AuthorityInstance::bind(
        requirement,
        binding,
        RightsSet::from_rights(rights),
        AuthorityLeasePolicy::Unleased,
        false,
    )
    .unwrap_or_else(|_| unreachable!("the fixture binding satisfies its requirement"))
}

/// Authorization to execute an operation and authorization to release its data
/// are independent: nothing derived from an authority right or an admission
/// request is a release authorization, a grant is obtainable only from a
/// release-holder authority for the declared class and destination, and an
/// operation admitted through the ordinary path leaves the protected value
/// unreleased and still subject to holder authority.
#[test]
fn operation_authority_and_release_authority_remain_independent() {
    assert_not_impl_any!(
        ReleaseGrant: Default,
        From<AuthorityRight>,
        From<RightsSet>,
        From<AdmissionRequest>,
        From<Admission>,
        From<AuthorityInstance>,
        From<AuthorityInstanceId>,
        From<ProtectedValue>,
        serde::Deserialize<'static>
    );
    assert_not_impl_any!(
        ReleaseHolderAuthority: Default,
        From<AuthorityRight>,
        From<RightsSet>,
        From<AdmissionRequest>,
        From<AuthorityInstance>,
        serde::Deserialize<'static>
    );

    // A grant is obtainable only from a release-holder authority, and only for
    // the class and destination sets that authority declares.
    let holder = authority(
        &[ProtectedDataClass::ActionArgument],
        &[ReleaseDestination::OrdinarySource],
    );
    let grant = holder.grant();
    let holder_identity: &ReleaseHolderId = grant.holder();
    assert_eq!(holder_identity.as_str(), holder.id().as_str());
    assert!(holder_identity.as_str().starts_with("release-holder:"));
    assert_eq!(
        grant.classes().collect::<Vec<_>>(),
        vec![ProtectedDataClass::ActionArgument]
    );
    assert_eq!(
        grant.destinations().collect::<Vec<_>>(),
        vec![ReleaseDestination::OrdinarySource]
    );
    assert_eq!(grant.class_count(), 1);
    assert_eq!(grant.destination_count(), 1);
    assert!(!grant.is_empty());
    assert!(grant.covers(
        ProtectedDataClass::ActionArgument,
        ReleaseDestination::OrdinarySource
    ));
    assert!(!grant.covers(
        ProtectedDataClass::ActionArgument,
        ReleaseDestination::DiagnosticSink
    ));
    assert!(!grant.covers(
        ProtectedDataClass::EntryInput,
        ReleaseDestination::OrdinarySource
    ));
    assert!(
        withholding_authority().grant().is_empty(),
        "a holder that declares nothing grants nothing"
    );
    // The holder identity is domain separated from the binding text it derives
    // from, so it is neither the binding spelling nor a naive digest of it.
    assert_ne!(
        holder_identity.digest_hex(),
        digest_hex(holder.binding().as_str())
    );
    assert_ne!(holder_identity.as_str(), holder.binding().as_str());
    let other_site = fixture_name("crate::other-release");
    let foreign_binding = ReleaseHolderBindingId::new(&other_site, &fixture_integration());
    assert_eq!(
        ReleaseHolderAuthority::bind(&fixture_name(SITE), foreign_binding, &[], &[]).err(),
        Some(ReleaseAuthorityError::SiteMismatch),
        "only the integration bound to the declared site mints holder authority"
    );

    // The admission request declares operation-side fields only: no protected
    // class, no release destination, and no grant.
    let mut operator = instance(&AUTHORITY_RIGHT_ORDER);
    let generation = operator.generation();
    let request = AdmissionRequest {
        right: AuthorityRight::InvokeNonIdempotent,
        recovery: RecoveryClass::NonIdempotent,
        generation,
        now_us: 0,
    };
    let declared_right: AuthorityRight = request.right;
    let declared_recovery: RecoveryClass = request.recovery;
    let believed_generation: AuthorityGeneration = request.generation;
    let at_us: u64 = request.now_us;
    assert_eq!(
        declared_right,
        AuthorityRight::for_recovery_class(declared_recovery)
    );
    assert_eq!(believed_generation, generation);
    assert_eq!(at_us, 0);
    for right in AUTHORITY_RIGHT_ORDER {
        assert!(
            !right.wire_name().contains("release"),
            "no authority right is a release right"
        );
        assert_eq!(ProtectedDataClass::from_wire_name(right.wire_name()), None);
        assert_eq!(ReleaseDestination::from_wire_name(right.wire_name()), None);
    }
    let admission = operator
        .admit(&request, &AncestorFences::none())
        .unwrap_or_else(|_| unreachable!("the widest fixture instance admits dispatch"));
    let recorded_sequence: u64 = admission.sequence();
    let recorded_generation: AuthorityGeneration = admission.generation();
    let settlement: RecoveryClass = admission.settlement_rule();
    assert_eq!(recorded_sequence, 0);
    assert_eq!(recorded_generation, generation);
    assert_eq!(settlement, RecoveryClass::NonIdempotent);
    assert_eq!(operator.accepted().len(), 1);
    let operator_identity: &AuthorityInstanceId = operator.id();
    assert!(operator_identity.as_str().starts_with("instance:"));
    assert!(!operator_identity.as_str().starts_with("release-holder:"));
    assert!(!holder_identity.as_str().starts_with("instance:"));
    assert_ne!(operator_identity.as_str(), holder_identity.as_str());

    // The admitted operation exposes no release path: the protected value of
    // the admitted class is still protected, and the release site still
    // requires a grant derived from holder authority.
    let protected = sealed(ProtectedDataClass::ActionArgument, "crate::argument");
    let mut budget = disclosure_budget(2, 1);
    let operation_site = site(
        ProtectedDataClass::ActionArgument,
        ReleaseDestination::OrdinarySource,
    );
    let refused = operation_site.release(
        &withholding_authority().grant(),
        &protected,
        ReleaseDestination::OrdinarySource,
        &mut budget,
    );
    assert_eq!(
        refused.decision(),
        ReleaseDecision::Rejected(ReleaseRejection::ClassMismatch)
    );
    assert_eq!(refused.projection(), None);
    assert_eq!(refused.released_value(), None);
    assert!(refused.audit_view(&AuditAccess::granted()).is_none());
    assert!(protected.is_protected());
    assert_eq!(budget.accepted(), 0);
    assert_eq!(budget.remaining(), 2);

    // Even a grant covering the pair releases nothing without the disclosure
    // budget, which the grant does not carry: authority to execute, holder
    // authority, and the budget are three independent inputs of one release.
    let exhausted = disclosure_budget(0, 1);
    let mut exhausted_budget = exhausted;
    let unaffordable = operation_site.release(
        &grant,
        &protected,
        ReleaseDestination::OrdinarySource,
        &mut exhausted_budget,
    );
    assert_eq!(
        unaffordable.decision(),
        ReleaseDecision::Rejected(ReleaseRejection::BudgetExhausted)
    );
    assert_eq!(unaffordable.released_value(), None);
    assert_eq!(exhausted_budget.accounting(), exhausted.accounting());
    assert_eq!(operator.accepted().len(), 1);
}

/// Positive control and narrowing: a grant derived from the holder authority
/// releases the declared class and destination pair, and releasing through a
/// pair the grant does not cover is refused rather than repaired or widened.
#[test]
fn a_holder_derived_grant_releases_only_its_declared_destination() {
    let class = ProtectedDataClass::SourceText;
    let declared = ReleaseDestination::OrdinarySource;
    let uncovered = ReleaseDestination::DiagnosticSink;
    let declared_projection = ProjectionKind::Verbatim;
    let uncovered_projection = ProjectionKind::Redacted;
    let release_site = ReleaseSite::new(SITE)
        .declare(class, declared, declared_projection)
        .declare(class, uncovered, uncovered_projection);
    assert!(release_site.declares(class, declared));
    assert!(release_site.declares(class, uncovered));
    assert_eq!(
        release_site.projection(class, declared),
        Some(declared_projection)
    );
    assert_eq!(
        release_site.projection(class, uncovered),
        Some(uncovered_projection)
    );

    let holder = authority(&[class], &[declared]);
    let grant = holder.grant();
    let mut budget = disclosure_budget(3, 1);
    let protected = sealed(class, "crate::release-source");
    let accepted = release_site.release(&grant, &protected, declared, &mut budget);
    assert_eq!(
        accepted.decision(),
        ReleaseDecision::Accepted(ReleaseProjection::new(declared_projection, class, declared))
    );
    let released = accepted
        .released_value()
        .unwrap_or_else(|| unreachable!("an accepted release produces an ordinary value"));
    assert!(released.is_ordinary());
    assert!(!released.is_protected());
    assert_eq!(released.class(), class);
    assert_eq!(released.destination(), declared);
    assert_eq!(released.kind(), declared_projection);
    assert_eq!(ReleasedValue::class(released), class);
    assert_eq!(budget.accepted(), 1);
    assert_eq!(budget.remaining(), 2);
    let view = accepted
        .audit_view(&AuditAccess::granted())
        .unwrap_or_else(|| unreachable!("an accepted release has a declared view"));
    assert_eq!(view.site(), SITE);
    assert_eq!(view.class(), class);
    assert_eq!(view.destination(), declared);
    assert_eq!(view.projection(), declared_projection);
    assert_eq!(view.outcome(), AuditOutcome::Accepted);
    assert_eq!(view.budget_consumed(), 1);

    // The destination the grant does not cover is refused, not repaired to the
    // covered destination and not widened into it.
    assert_ne!(declared_projection, uncovered_projection);
    assert!(!grant.contains_destination(uncovered));
    assert!(!grant.covers(class, uncovered));
    let refused = release_site.release(&grant, &protected, uncovered, &mut budget);
    assert_eq!(
        refused.decision(),
        ReleaseDecision::Rejected(ReleaseRejection::DestinationMismatch)
    );
    assert_eq!(refused.projection(), None);
    assert_eq!(refused.released_value(), None);
    assert!(refused.audit_view(&AuditAccess::granted()).is_none());
    assert_eq!(refused.budget(), budget);
    assert_eq!(budget.accepted(), 1);
    assert_eq!(budget.remaining(), 2);

    // A class the grant does not cover is refused against the same site and
    // destination, so a release never widens to another class either.
    let other_class = ProtectedDataClass::JournalRecord;
    let cross_site = ReleaseSite::new(SITE)
        .declare(class, declared, declared_projection)
        .declare(other_class, declared, declared_projection);
    let refused_class = cross_site.release(
        &grant,
        &sealed(other_class, "crate::journal"),
        declared,
        &mut budget,
    );
    assert_eq!(
        refused_class.decision(),
        ReleaseDecision::Rejected(ReleaseRejection::ClassMismatch)
    );
    assert_eq!(refused_class.released_value(), None);
    assert_eq!(budget.accepted(), 1);
    assert_eq!(budget.remaining(), 2);

    // Attenuation only narrows: a narrowed holder keeps the declared site and
    // loses the destination it no longer declares, and its grant releases
    // nothing that the wider grant covered.
    let narrowed = holder.attenuate(&[class], &[]);
    assert_eq!(narrowed.site(), SITE);
    assert_ne!(narrowed.id(), holder.id());
    assert!(narrowed.grant().is_strict_subset_of(&grant));
    assert_eq!(narrowed.grant().destination_count(), 0);
    assert!(narrowed.grant().is_empty());
    assert!(!narrowed.grant().covers(class, declared));
    let mut narrowed_budget = disclosure_budget(1, 1);
    let narrowed_outcome = release_site.release(
        &narrowed.grant(),
        &protected,
        declared,
        &mut narrowed_budget,
    );
    assert_eq!(
        narrowed_outcome.decision(),
        ReleaseDecision::Rejected(ReleaseRejection::DestinationMismatch)
    );
    assert_eq!(narrowed_outcome.released_value(), None);
    assert_eq!(narrowed_budget.accepted(), 0);
    assert_eq!(narrowed_budget.remaining(), 1);
}

/// The converse direction: holding a release grant does not admit an operation
/// that the authority model refuses, and a release decision is not recorded as
/// an execution decision.
#[test]
fn release_authority_does_not_grant_execution_authority() {
    assert_not_impl_any!(Admission: From<ReleaseOutcome>);
    assert_not_impl_any!(ReleaseOutcome: From<Admission>);

    let class = ProtectedDataClass::ActionArgument;
    let destination = ReleaseDestination::OrdinarySource;
    let holder = authority(&[class], &[destination]);
    let grant = holder.grant();
    let release_site = site(class, destination);
    let mut budget = disclosure_budget(2, 1);
    let accepted = release_site.release(
        &grant,
        &sealed(class, "crate::argument"),
        destination,
        &mut budget,
    );
    assert_eq!(
        accepted.decision(),
        ReleaseDecision::Accepted(ReleaseProjection::new(
            ProjectionKind::Redacted,
            class,
            destination
        ))
    );
    let released = accepted
        .released_value()
        .unwrap_or_else(|| unreachable!("a holder-derived grant releases the declared pair"));
    assert!(released.is_ordinary());
    assert_eq!(released.class(), class);
    assert_eq!(released.destination(), destination);

    // The execution side refuses an operation the release side just authorized:
    // the grant carries no execution right.
    let mut observer = instance(&[AuthorityRight::InvokeReadOnly]);
    let generation = observer.generation();
    let refusal = observer
        .admit(
            &AdmissionRequest {
                right: AuthorityRight::InvokeIdempotent,
                recovery: RecoveryClass::Idempotent,
                generation,
                now_us: 0,
            },
            &AncestorFences::none(),
        )
        .err();
    assert_eq!(
        refusal,
        Some(AuthorityError::MissingRight(
            AuthorityRight::InvokeIdempotent
        ))
    );
    assert_eq!(
        AuthorityError::MissingRight(AuthorityRight::InvokeIdempotent).code(),
        "authority-missing-right"
    );
    assert!(
        observer.accepted().is_empty(),
        "a release grant admitted no work"
    );
    assert_eq!(observer.generation(), generation);
    assert_eq!(observer.fence_state(), FenceState::Open);
    assert_eq!(
        observer.rights(),
        RightsSet::from_rights(&[AuthorityRight::InvokeReadOnly])
    );
    assert!(!observer.rights().contains(AuthorityRight::InvokeIdempotent));

    // A dispatch right that is present still admits nothing when the request
    // declares another right, so admission is decided by the authority model
    // alone and never by a release decision.
    let mut idempotent = instance(&[AuthorityRight::InvokeIdempotent]);
    let generation = idempotent.generation();
    let mismatched = idempotent
        .admit(
            &AdmissionRequest {
                right: AuthorityRight::Observe,
                recovery: RecoveryClass::Idempotent,
                generation,
                now_us: 0,
            },
            &AncestorFences::none(),
        )
        .err();
    assert_eq!(
        mismatched,
        Some(AuthorityError::RightRecoveryMismatch {
            declared: AuthorityRight::Observe,
            required: AuthorityRight::InvokeIdempotent,
        })
    );
    assert!(idempotent.accepted().is_empty());
    assert_eq!(
        AuthorityRight::for_recovery_class(RecoveryClass::Idempotent),
        AuthorityRight::InvokeIdempotent
    );
    for right in AUTHORITY_RIGHT_ORDER {
        assert!(!right.wire_name().contains("release"));
        assert!(ProtectedDataClass::from_wire_name(right.wire_name()).is_none());
        assert!(ReleaseDestination::from_wire_name(right.wire_name()).is_none());
    }

    // The grant still releases after both execution refusals, and an admitted
    // operation still records no release: the two authorizations stay separate
    // in both directions.
    let mut widest = instance(&AUTHORITY_RIGHT_ORDER);
    let generation = widest.generation();
    let admitted = widest
        .admit(
            &AdmissionRequest {
                right: AuthorityRight::InvokeIdempotent,
                recovery: RecoveryClass::Idempotent,
                generation,
                now_us: 0,
            },
            &AncestorFences::none(),
        )
        .unwrap_or_else(|_| unreachable!("the widest fixture instance admits dispatch"));
    assert_eq!(admitted.settlement_rule(), RecoveryClass::Idempotent);
    assert_eq!(admitted.generation(), generation);
    let mut second_budget = disclosure_budget(1, 1);
    let released_after_admission = release_site.release(
        &grant,
        &sealed(class, "crate::argument"),
        destination,
        &mut second_budget,
    );
    assert!(matches!(
        released_after_admission.decision(),
        ReleaseDecision::Accepted(_)
    ));
    assert_eq!(
        widest.accepted().len(),
        1,
        "the release recorded no execution decision"
    );
    assert_eq!(second_budget.accepted(), 1);
}
