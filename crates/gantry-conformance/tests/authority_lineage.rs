//! Machine-checked conformance for capability-instance authority.
//!
//! These tests exercise the public identity and lattice model of
//! [`gantry::ir::authority`] for `GNT-3-T-AUTHORITY-INSTANCES`,
//! `GNT-3-T-AUTHORITY-LINEAGE`, `GNT-3-T-AUTHORITY-REVOCATION`,
//! `GNT-3-T-AUTHORITY-ADMISSION`, `GNT-7.2-authority-rebinding`, and
//! `GNT-11.6-authority-instance-compatibility`. They check the model that the
//! specification makes normative, not a runtime authority store: no test here
//! observes a live instance, a host service, or a protected payload.

use std::collections::BTreeSet;

use gantry::ir::generated::RecoveryClass;
use gantry::ir::{
    AdmissionRequest, AncestorFences, AuthorityBindingId, AuthorityChangeClass, AuthorityError,
    AuthorityGeneration, AuthorityInstance, AuthorityLeasePolicy, AuthorityRequirementId,
    AuthorityRight, CanonicalCallableIdentity, CanonicalImplementationIdentity, CanonicalPath,
    CanonicalSignature, ExternalOutcome, FenceCategory, FenceLatches, FenceState,
    GenerationRelation, LeaseRelation, LineageRelation, RightsRelation, RightsSet, TypeDescriptor,
    TypeExpression,
};
use sha2::{Digest, Sha256};

/// The capability family used by every fixture requirement.
const FAMILY: &str = "action";

#[test]
fn instance_identity_is_canonical_and_distinct_from_requirement() {
    let requirement = fixture_requirement();
    let binding = fixture_binding(&requirement, "crate::Fixture");
    let instance = AuthorityInstance::bind(
        requirement.clone(),
        binding.clone(),
        read_only_rights(),
        AuthorityLeasePolicy::Unleased,
        false,
    )
    .unwrap_or_else(|_| unreachable!("fixture binding satisfies its requirement"));

    assert!(instance.id().as_str().starts_with("instance:"));
    assert_eq!(instance.id().digest_hex().len(), 64);
    assert!(
        instance
            .id()
            .digest_hex()
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (byte.is_ascii_lowercase()))
    );

    // The instance identity is not the requirement identity, the binding
    // identity, or a callable-site identity, and it is not a naive re-hash of
    // the requirement text, because derivation is domain-separated.
    assert_ne!(instance.id().as_str(), requirement.as_str());
    assert_ne!(instance.id().as_str(), binding.as_str());
    let callable = CanonicalCallableIdentity::free(&fixture_path(), &[TypeDescriptor::STRING]);
    assert_ne!(instance.id().as_str(), callable.as_str());
    let naive = format!("{:x}", Sha256::digest(requirement.as_str().as_bytes()));
    assert_ne!(instance.id().digest_hex(), naive);
    assert!(!instance.id().as_str().starts_with("capability-"));

    // Identity is canonical: equal inputs derive one identity, and a different
    // binding, generation, or lineage root derives another.
    let repeated = AuthorityInstance::bind(
        requirement.clone(),
        binding.clone(),
        read_only_rights(),
        AuthorityLeasePolicy::Unleased,
        false,
    )
    .unwrap_or_else(|_| unreachable!("fixture binding satisfies its requirement"));
    assert_eq!(instance.id(), repeated.id());
    let descendant = instance
        .attenuate(read_only_rights(), AuthorityLeasePolicy::Unleased)
        .unwrap_or_else(|_| unreachable!("equal rights neither amplify nor empty a set"));
    assert_ne!(descendant.id(), instance.id());
    let previous_id = instance.id().clone();
    let rebound = instance
        .rebind(fixture_binding(&requirement, "crate::Replacement"))
        .unwrap_or_else(|_| unreachable!("a live instance rebinds"));
    assert_ne!(rebound.id(), &previous_id);
}

#[test]
fn capability_instances_arise_only_from_binding_or_derivation() {
    let requirement = fixture_requirement();
    let other = AuthorityRequirementId::new(
        &fixture_path(),
        &CanonicalSignature::action(
            RecoveryClass::Idempotent,
            &fixture_path(),
            &[],
            &TypeDescriptor::STRING,
        ),
        FAMILY,
        RecoveryClass::Idempotent,
    )
    .unwrap_or_else(|_| unreachable!("fixture family is portable"));

    // A binding that satisfies another requirement cannot be bound to this one.
    let mismatched = AuthorityInstance::bind(
        requirement.clone(),
        fixture_binding(&other, "crate::Fixture"),
        read_only_rights(),
        AuthorityLeasePolicy::Unleased,
        false,
    );
    assert_eq!(mismatched, Err(AuthorityError::RequirementMismatch));

    // An instance must carry at least one right, and a capability family is a
    // portable lowercase name.
    assert_eq!(
        AuthorityInstance::bind(
            requirement.clone(),
            fixture_binding(&requirement, "crate::Fixture"),
            RightsSet::empty(),
            AuthorityLeasePolicy::Unleased,
            false,
        ),
        Err(AuthorityError::EmptyRights)
    );
    assert_eq!(
        AuthorityRequirementId::new(
            &fixture_path(),
            &CanonicalSignature::action(
                RecoveryClass::ReadOnly,
                &fixture_path(),
                &[],
                &TypeDescriptor::STRING
            ),
            "Action",
            RecoveryClass::ReadOnly,
        ),
        Err(AuthorityError::InvalidCapabilityFamily)
    );

    // Derivation is the only other origin, and only an owned instance derives.
    let instance = fixture_instance(
        read_only_rights(),
        AuthorityLeasePolicy::Unleased,
        false,
        "crate::Fixture",
    );
    let descendant = instance
        .attenuate(read_only_rights(), AuthorityLeasePolicy::Unleased)
        .unwrap_or_else(|_| unreachable!("equal rights neither amplify nor empty a set"));
    assert_eq!(descendant.parent(), Some(instance.id()));
    assert!(!descendant.is_sharable());
}

#[test]
fn admission_requires_the_declared_right_in_the_bound_instance() {
    let mut instance = fixture_instance(
        read_only_rights(),
        AuthorityLeasePolicy::Unleased,
        false,
        "crate::Fixture",
    );
    let admitted = instance.admit(
        &admission(
            AuthorityRight::InvokeReadOnly,
            RecoveryClass::ReadOnly,
            instance.generation(),
            0,
        ),
        &AncestorFences::none(),
    );
    assert!(admitted.is_ok());
    assert_eq!(instance.accepted().len(), 1);

    let denied = instance.admit(
        &admission(
            AuthorityRight::InvokeNonIdempotent,
            RecoveryClass::NonIdempotent,
            instance.generation(),
            0,
        ),
        &AncestorFences::none(),
    );
    match denied {
        Err(error) => assert_eq!(error.code(), "authority-missing-right"),
        Ok(_) => panic!("an instance admitted a right its rights set omits"),
    }
    assert_eq!(
        instance.accepted().len(),
        1,
        "a denied admission admits nothing"
    );
}

#[test]
fn attenuation_cannot_amplify_rights() {
    let instance = fixture_instance(
        read_only_rights(),
        AuthorityLeasePolicy::Unleased,
        false,
        "crate::Fixture",
    );
    let amplified = RightsSet::from_rights(&[
        AuthorityRight::InvokeReadOnly,
        AuthorityRight::InvokeNonIdempotent,
    ]);
    assert_eq!(
        instance.attenuate(amplified, AuthorityLeasePolicy::Unleased),
        Err(AuthorityError::AmplifiedRights)
    );
    assert!(
        instance
            .attenuate(read_only_rights(), AuthorityLeasePolicy::Unleased)
            .is_ok()
    );

    // Delegation is attenuation gated by the delegate right, so it can never
    // add a right either.
    assert_eq!(
        instance.delegate(read_only_rights(), AuthorityLeasePolicy::Unleased),
        Err(AuthorityError::MissingRight(AuthorityRight::Delegate))
    );
    let delegator = fixture_instance(
        delegate_rights(),
        AuthorityLeasePolicy::Unleased,
        false,
        "crate::Fixture",
    );
    let delegated = delegator.delegate(read_only_rights(), AuthorityLeasePolicy::Unleased);
    assert!(delegated.is_ok());
    assert_eq!(
        delegator.delegate(
            RightsSet::from_rights(&[AuthorityRight::Observe]),
            AuthorityLeasePolicy::Unleased
        ),
        Err(AuthorityError::AmplifiedRights)
    );
}

#[test]
fn narrowing_is_monotone_along_lineage() {
    let root = fixture_instance(
        wide_rights(),
        AuthorityLeasePolicy::Unleased,
        false,
        "crate::Fixture",
    );
    let first = root
        .attenuate(
            RightsSet::from_rights(&[AuthorityRight::InvokeReadOnly, AuthorityRight::Delegate]),
            AuthorityLeasePolicy::Unleased,
        )
        .unwrap_or_else(|_| unreachable!("a subset neither amplifies nor empties"));
    let second = first
        .attenuate(read_only_rights(), AuthorityLeasePolicy::Unleased)
        .unwrap_or_else(|_| unreachable!("a subset neither amplifies nor empties"));

    assert!(first.rights().is_strict_subset_of(root.rights()));
    assert!(second.rights().is_strict_subset_of(first.rights()));
    assert!(second.rights().is_subset_of(root.rights()));
    assert!(root.generation() < first.generation());
    assert!(first.generation() < second.generation());
    assert_ne!(root.id(), first.id());
    assert_ne!(first.id(), second.id());

    // A right an ancestor removed is never restored by a descendant: the root
    // may delegate, the narrowed descendant may not.
    assert!(root.rights().contains(AuthorityRight::Delegate));
    assert_eq!(
        second.delegate(read_only_rights(), AuthorityLeasePolicy::Unleased),
        Err(AuthorityError::MissingRight(AuthorityRight::Delegate))
    );
}

#[test]
fn lineage_is_single_parent_and_acyclic() {
    let root = fixture_instance(
        wide_rights(),
        AuthorityLeasePolicy::Unleased,
        false,
        "crate::Fixture",
    );
    let first = root
        .attenuate(
            RightsSet::from_rights(&[AuthorityRight::InvokeReadOnly, AuthorityRight::Delegate]),
            AuthorityLeasePolicy::Unleased,
        )
        .unwrap_or_else(|_| unreachable!("a subset neither amplifies nor empties"));
    let second = first
        .attenuate(read_only_rights(), AuthorityLeasePolicy::Unleased)
        .unwrap_or_else(|_| unreachable!("a subset neither amplifies nor empties"));

    assert_eq!(root.parent(), None);
    assert!(root.lineage().is_empty());
    assert_eq!(root.root(), root.id());

    assert_eq!(first.parent(), Some(root.id()));
    assert_eq!(first.lineage(), [root.id().clone()]);
    assert_eq!(first.root(), root.id());

    assert_eq!(second.parent(), Some(first.id()));
    assert_eq!(second.lineage().len(), 2);
    assert_eq!(second.lineage().first(), Some(root.id()));
    assert_eq!(second.root(), root.id());

    // The chain is finite and acyclic: no instance is its own ancestor and the
    // ancestors of one chain are distinct.
    assert!(!second.lineage().contains(second.id()));
    let distinct = second
        .lineage()
        .iter()
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(distinct.len(), second.lineage().len());
}

#[test]
fn derived_instance_cannot_outright_or_outlive_its_root() {
    let mut root = fixture_instance(
        wide_rights(),
        AuthorityLeasePolicy::Expiring { expires_at_us: 100 },
        false,
        "crate::Fixture",
    );
    assert_eq!(
        root.attenuate(
            read_only_rights(),
            AuthorityLeasePolicy::Expiring { expires_at_us: 101 }
        ),
        Err(AuthorityError::LeaseExceedsRoot)
    );
    assert_eq!(
        root.attenuate(read_only_rights(), AuthorityLeasePolicy::Unleased),
        Err(AuthorityError::LeaseExceedsRoot)
    );

    let mut within = root
        .attenuate(
            read_only_rights(),
            AuthorityLeasePolicy::Expiring { expires_at_us: 50 },
        )
        .unwrap_or_else(|_| unreachable!("a shorter lease within the root is admitted"));
    let expired = within.admit(
        &admission(
            AuthorityRight::InvokeReadOnly,
            RecoveryClass::ReadOnly,
            within.generation(),
            50,
        ),
        &AncestorFences::none(),
    );
    match expired {
        Err(error) => assert_eq!(error, AuthorityError::Fenced(FenceCategory::Expiry)),
        Ok(_) => panic!("a descendant admitted past its lease expiry"),
    }
    match root.admit(
        &admission(
            AuthorityRight::InvokeReadOnly,
            RecoveryClass::ReadOnly,
            root.generation(),
            100,
        ),
        &AncestorFences::none(),
    ) {
        Err(error) => assert_eq!(error, AuthorityError::Fenced(FenceCategory::Expiry)),
        Ok(_) => panic!("the root admitted past its own lease expiry"),
    }
}

#[test]
fn revocation_fences_new_admission_and_preserves_accepted_work() {
    let mut instance = fixture_instance(
        read_only_rights(),
        AuthorityLeasePolicy::Unleased,
        false,
        "crate::Fixture",
    );
    let request = admission(
        AuthorityRight::InvokeReadOnly,
        RecoveryClass::ReadOnly,
        instance.generation(),
        0,
    );
    let accepted = instance
        .admit(&request, &AncestorFences::none())
        .unwrap_or_else(|_| unreachable!("the bound instance carries the declared right"));
    assert_eq!(accepted.settlement_rule(), RecoveryClass::ReadOnly);
    let accepted_before = instance.accepted().to_vec();

    let point = instance.revoke();
    assert_eq!(point.category(), FenceCategory::Revocation);
    assert_eq!(point.linearization_point(), 1, "one point per instance");
    assert_eq!(instance.revoke(), point, "the point is never re-derived");
    assert_eq!(
        instance.accepted(),
        accepted_before.as_slice(),
        "already accepted work is never rolled back or redelivered"
    );
    assert_eq!(
        accepted.settles(ExternalOutcome::Ambiguous),
        ExternalOutcome::Ambiguous,
        "an ambiguous external outcome stays ambiguous"
    );

    match instance.admit(&request, &AncestorFences::none()) {
        Err(error) => {
            assert_eq!(error, AuthorityError::Fenced(FenceCategory::Revocation));
            assert_eq!(error.code(), "authority-fenced");
        }
        Ok(_) => panic!("a revoked instance admitted new work"),
    }
    assert_eq!(
        instance.accepted().len(),
        1,
        "the fenced admission recorded nothing"
    );
    assert!(matches!(instance.fence_state(), FenceState::Fenced(actual) if actual == point));
}

#[test]
fn revocation_propagates_to_descendants() {
    let mut root = fixture_instance(
        wide_rights(),
        AuthorityLeasePolicy::Unleased,
        false,
        "crate::Fixture",
    );
    let mut child = root
        .attenuate(
            RightsSet::from_rights(&[AuthorityRight::InvokeReadOnly, AuthorityRight::Delegate]),
            AuthorityLeasePolicy::Unleased,
        )
        .unwrap_or_else(|_| unreachable!("a subset neither amplifies nor empties"));
    let request = admission(
        AuthorityRight::InvokeReadOnly,
        RecoveryClass::ReadOnly,
        child.generation(),
        0,
    );
    assert!(child.admit(&request, &AncestorFences::none()).is_ok());

    let point = root.revoke();
    let fenced = AncestorFences::none().with_fenced(root.id(), point.category());
    match child.admit(&request, &fenced) {
        Err(error) => assert_eq!(
            error,
            AuthorityError::AncestorFenced(FenceCategory::Revocation)
        ),
        Ok(_) => panic!("a descendant admitted after its ancestor was revoked"),
    }
    assert_eq!(
        child.fence_state(),
        FenceState::Open,
        "the descendant's own fence is untouched"
    );
    assert_eq!(
        child.accepted().len(),
        1,
        "the fenced admission recorded nothing"
    );
}

#[test]
fn lease_expiry_fences_like_revocation_but_is_distinct() {
    assert_ne!(
        FenceCategory::Revocation.wire_name(),
        FenceCategory::Expiry.wire_name()
    );
    let mut expired = fixture_instance(
        read_only_rights(),
        AuthorityLeasePolicy::Expiring { expires_at_us: 10 },
        false,
        "crate::Fixture",
    );
    let point = expired.expire();
    assert_eq!(point.category(), FenceCategory::Expiry);
    assert_eq!(
        expired.expire(),
        point,
        "expiry has one linearization point"
    );
    let revoked = expired.revoke();
    assert_eq!(
        revoked.category(),
        FenceCategory::Revocation,
        "a revocation after an expiry is observable as a revocation"
    );
    assert_eq!(
        expired.fence_latches().expiry(),
        Some(point),
        "the earlier expiry keeps its own linearization point"
    );
    assert_eq!(expired.fence_latches().revocation(), Some(revoked));
    assert_eq!(
        expired.fence_latches().categories(),
        [FenceCategory::Revocation, FenceCategory::Expiry]
    );
    assert!(
        matches!(expired.fence_state(), FenceState::Fenced(actual) if actual == revoked),
        "the state accessor reports the revocation the later latch recorded"
    );
    assert!(expired.accepted().is_empty());

    let mut leased = fixture_instance(
        read_only_rights(),
        AuthorityLeasePolicy::Expiring { expires_at_us: 10 },
        false,
        "crate::Fixture",
    );
    let request = admission(
        AuthorityRight::InvokeReadOnly,
        RecoveryClass::ReadOnly,
        leased.generation(),
        10,
    );
    match leased.admit(&request, &AncestorFences::none()) {
        Err(error) => assert_eq!(error, AuthorityError::Fenced(FenceCategory::Expiry)),
        Ok(_) => panic!("an expired lease admitted new work"),
    }
    let expired_point = leased.fence_state().point();
    assert_eq!(
        expired_point.map(|actual| actual.category()),
        Some(FenceCategory::Expiry)
    );
    let before_expiry = admission(
        AuthorityRight::InvokeReadOnly,
        RecoveryClass::ReadOnly,
        leased.generation(),
        9,
    );
    assert!(
        leased
            .admit(&before_expiry, &AncestorFences::none())
            .is_err(),
        "a fenced generation stays fenced"
    );
}

#[test]
fn stale_generation_cannot_admit() {
    let mut instance = fixture_instance(
        wide_rights(),
        AuthorityLeasePolicy::Unleased,
        false,
        "crate::Fixture",
    );
    let mut descendant = instance
        .attenuate(
            RightsSet::from_rights(&[AuthorityRight::InvokeReadOnly, AuthorityRight::Delegate]),
            AuthorityLeasePolicy::Unleased,
        )
        .unwrap_or_else(|_| unreachable!("a subset neither amplifies nor empties"));
    let descendant_generation = descendant.generation();
    let stale = admission(
        AuthorityRight::InvokeReadOnly,
        RecoveryClass::ReadOnly,
        descendant_generation,
        0,
    );
    match instance.admit(&stale, &AncestorFences::none()) {
        Err(error) => assert_eq!(error, AuthorityError::StaleGeneration),
        Ok(_) => panic!("the root admitted a descendant generation"),
    }
    assert!(instance.accepted().is_empty());

    let current = admission(
        AuthorityRight::InvokeReadOnly,
        RecoveryClass::ReadOnly,
        descendant_generation,
        0,
    );
    assert!(descendant.admit(&current, &AncestorFences::none()).is_ok());
    assert_eq!(descendant.accepted().len(), 1);
}

#[test]
fn rebinding_cannot_revive_a_revoked_or_expired_generation() {
    let mut revoked = fixture_instance(
        read_only_rights(),
        AuthorityLeasePolicy::Unleased,
        false,
        "crate::Fixture",
    );
    let requirement = revoked.requirement().clone();
    let replacement = fixture_binding(&requirement, "crate::Replacement");
    let generation = revoked.generation();
    revoked.revoke();
    match revoked.rebind(replacement.clone()) {
        Err(error) => assert_eq!(error, AuthorityError::Fenced(FenceCategory::Revocation)),
        Ok(_) => panic!("a revoked generation was revived by re-binding"),
    }

    let mut expired = fixture_instance(
        read_only_rights(),
        AuthorityLeasePolicy::Unleased,
        false,
        "crate::Fixture",
    );
    expired.expire();
    match expired.rebind(replacement.clone()) {
        Err(error) => assert_eq!(error, AuthorityError::Fenced(FenceCategory::Expiry)),
        Ok(_) => panic!("an expired generation was revived by re-binding"),
    }

    // A live instance rebinds into a fresh generation of the same lineage: the
    // replacement keeps the root, uses the replacement binding, never resets the
    // generation counter, and leaves the prior generation stale for itself.
    let live = fixture_instance(
        read_only_rights(),
        AuthorityLeasePolicy::Unleased,
        false,
        "crate::Fixture",
    );
    let previous_id = live.id().clone();
    let previous_root = live.root().clone();
    let mut rebound = live
        .rebind(replacement)
        .unwrap_or_else(|_| unreachable!("a live instance rebinds"));
    assert_ne!(
        rebound.id(),
        &previous_id,
        "a replacement binding gets a new identity"
    );
    assert_eq!(
        rebound.binding(),
        &fixture_binding(&requirement, "crate::Replacement"),
        "the replacement carries the replacement binding"
    );
    assert_eq!(
        rebound.generation(),
        generation
            .successor()
            .unwrap_or_else(|_| unreachable!("the initial generation has a successor")),
        "rebinding starts a fresh generation"
    );
    assert_eq!(rebound.root(), &previous_root);
    match rebound.admit(
        &admission(
            AuthorityRight::InvokeReadOnly,
            RecoveryClass::ReadOnly,
            generation,
            0,
        ),
        &AncestorFences::none(),
    ) {
        Err(error) => assert_eq!(
            error,
            AuthorityError::StaleGeneration,
            "the prior generation is stale for the replacement"
        ),
        Ok(_) => panic!("the prior generation admitted through the rebinding"),
    }
    assert!(rebound.accepted().is_empty());
}

#[test]
fn rebinding_of_unchanged_binding_is_not_an_authority_change() {
    // Two equal fixtures derive one identity, so the twin stands in for the
    // instance that the by-value rebinding consumes.
    let previous = fixture_instance(
        wide_rights(),
        AuthorityLeasePolicy::Expiring { expires_at_us: 40 },
        false,
        "crate::Fixture",
    );
    let twin = fixture_instance(
        wide_rights(),
        AuthorityLeasePolicy::Expiring { expires_at_us: 40 },
        false,
        "crate::Fixture",
    );
    assert_eq!(previous.id(), twin.id(), "equal inputs derive one identity");
    let candidate = twin
        .rebind(fixture_binding(
            previous.requirement(),
            "crate::Replacement",
        ))
        .unwrap_or_else(|_| unreachable!("a live instance rebinds"));
    let comparison = previous
        .compare(&candidate)
        .unwrap_or_else(|_| unreachable!("both fixtures satisfy one requirement"));

    assert_eq!(comparison.rights, RightsRelation::Equal);
    assert_eq!(comparison.lineage, LineageRelation::SameRoot);
    assert_eq!(
        comparison.generation,
        GenerationRelation::Advanced,
        "a rebinding starts a fresh generation instead of resetting one"
    );
    assert_eq!(comparison.lease, LeaseRelation::Equal);
    assert!(!comparison.is_unchanged(), "the generation advanced");
    assert!(
        comparison.is_rebinding_only(),
        "an advanced generation is not an authority-compatibility change"
    );
    assert!(comparison.authority_compatibility_changes().is_empty());
}

#[test]
fn rights_widening_generation_reset_and_lineage_replanting_are_distinct_changes() {
    let previous = fixture_instance(
        read_only_rights(),
        AuthorityLeasePolicy::Unleased,
        false,
        "crate::Fixture",
    );

    // A widening inside one lineage: two attenuations of one parent share a
    // generation and a lineage root, so only the rights relation changes.
    let parent = fixture_instance(
        wide_rights(),
        AuthorityLeasePolicy::Unleased,
        false,
        "crate::Fixture",
    );
    let narrowed = parent
        .attenuate(read_only_rights(), AuthorityLeasePolicy::Unleased)
        .unwrap_or_else(|_| unreachable!("a subset neither amplifies nor empties"));
    let wider_sibling = parent
        .attenuate(delegate_rights(), AuthorityLeasePolicy::Unleased)
        .unwrap_or_else(|_| unreachable!("a subset neither amplifies nor empties"));
    let widened = narrowed
        .compare(&wider_sibling)
        .unwrap_or_else(|_| unreachable!("both fixtures satisfy one requirement"));
    assert_eq!(widened.rights, RightsRelation::Widened);
    assert_eq!(widened.lineage, LineageRelation::SameRoot);
    assert_eq!(widened.generation, GenerationRelation::SameGeneration);
    assert_eq!(
        widened.authority_compatibility_changes(),
        BTreeSet::from([AuthorityChangeClass::RightsWidening])
    );

    // Two roots of one requirement that carry different rights sets are distinct
    // instances, so a cross-root widening also replants the lineage. Both classes
    // stay reported separately instead of collapsing into one verdict.
    let cross_root = previous
        .compare(&parent)
        .unwrap_or_else(|_| unreachable!("both fixtures satisfy one requirement"));
    assert_eq!(cross_root.rights, RightsRelation::Widened);
    assert_eq!(cross_root.lineage, LineageRelation::Replanted);
    assert_eq!(
        cross_root.authority_compatibility_changes(),
        BTreeSet::from([
            AuthorityChangeClass::RightsWidening,
            AuthorityChangeClass::LineageReplanting
        ])
    );

    let advanced = previous
        .attenuate(read_only_rights(), AuthorityLeasePolicy::Unleased)
        .unwrap_or_else(|_| unreachable!("equal rights neither amplify nor empty a set"));
    let reset = advanced
        .compare(&previous)
        .unwrap_or_else(|_| unreachable!("both fixtures satisfy one requirement"));
    assert_eq!(reset.generation, GenerationRelation::Reset);
    assert_eq!(
        reset.authority_compatibility_changes(),
        BTreeSet::from([AuthorityChangeClass::GenerationReset])
    );

    let replanted = fixture_instance(
        read_only_rights(),
        AuthorityLeasePolicy::Unleased,
        false,
        "crate::Replacement",
    );
    let replanted = previous
        .compare(&replanted)
        .unwrap_or_else(|_| unreachable!("both fixtures satisfy one requirement"));
    assert_eq!(replanted.lineage, LineageRelation::Replanted);
    assert_eq!(
        replanted.authority_compatibility_changes(),
        BTreeSet::from([AuthorityChangeClass::LineageReplanting])
    );

    // Each class is reported separately, and two simultaneous changes are never
    // collapsed into one verdict.
    let combined = advanced
        .compare(&fixture_instance(
            read_only_rights(),
            AuthorityLeasePolicy::Unleased,
            false,
            "crate::Replacement",
        ))
        .unwrap_or_else(|_| unreachable!("both fixtures satisfy one requirement"));
    assert_eq!(
        combined.authority_compatibility_changes(),
        BTreeSet::from([
            AuthorityChangeClass::GenerationReset,
            AuthorityChangeClass::LineageReplanting
        ])
    );
    assert_eq!(
        combined
            .authority_compatibility_changes()
            .iter()
            .map(|class| class.wire_name())
            .collect::<Vec<_>>(),
        ["generation-reset", "lineage-replanting"]
    );
}

#[test]
fn instance_comparison_reports_rights_lineage_generation_and_lease_distinctly() {
    let previous = fixture_instance(
        wide_rights(),
        AuthorityLeasePolicy::Expiring { expires_at_us: 100 },
        false,
        "crate::Fixture",
    );
    let candidate = previous
        .attenuate(
            RightsSet::from_rights(&[AuthorityRight::InvokeReadOnly, AuthorityRight::Delegate]),
            AuthorityLeasePolicy::Expiring { expires_at_us: 50 },
        )
        .unwrap_or_else(|_| unreachable!("a subset neither amplifies nor empties"));
    let comparison = previous
        .compare(&candidate)
        .unwrap_or_else(|_| unreachable!("both fixtures satisfy one requirement"));

    assert_eq!(comparison.rights, RightsRelation::Narrowed);
    assert_eq!(comparison.lineage, LineageRelation::SameRoot);
    assert_eq!(comparison.generation, GenerationRelation::Advanced);
    assert_eq!(comparison.lease, LeaseRelation::Shortened);
    assert!(
        !comparison.is_unchanged(),
        "four properties, not one verdict"
    );
    assert!(
        !comparison.is_rebinding_only(),
        "a shortened lease is an authority-compatibility change"
    );
    assert_eq!(
        comparison.authority_compatibility_changes(),
        BTreeSet::from([AuthorityChangeClass::LeasePolicyChange])
    );

    let unleased = previous
        .compare(&fixture_instance(
            wide_rights(),
            AuthorityLeasePolicy::Unleased,
            false,
            "crate::Fixture",
        ))
        .unwrap_or_else(|_| unreachable!("both fixtures satisfy one requirement"));
    assert_eq!(unleased.lease, LeaseRelation::NewlyUnleased);
    assert_eq!(
        unleased.authority_compatibility_changes(),
        BTreeSet::from([AuthorityChangeClass::LeasePolicyChange])
    );
    assert_eq!(
        LeaseRelation::of(
            AuthorityLeasePolicy::Unleased,
            AuthorityLeasePolicy::Unleased
        ),
        LeaseRelation::Equal
    );
}

#[test]
fn admission_is_the_single_commit_point_and_a_failure_never_dispatches() {
    let mut instance = fixture_instance(
        read_only_rights(),
        AuthorityLeasePolicy::Unleased,
        false,
        "crate::Fixture",
    );
    let denied = instance.admit(
        &admission(
            AuthorityRight::Observe,
            RecoveryClass::ReadOnly,
            instance.generation(),
            0,
        ),
        &AncestorFences::none(),
    );
    match denied {
        Err(error) => {
            assert_eq!(error.code(), "authority-right-recovery-mismatch");
            assert!(
                error
                    .to_string()
                    .starts_with("authority-right-recovery-mismatch")
            );
            assert!(error.to_string().contains("observe"));
        }
        Ok(_) => panic!("a preflight-only right admitted an operation"),
    }
    assert!(
        instance.accepted().is_empty(),
        "a failed admission dispatches nothing and records no effect"
    );
    assert!(!instance.rights().contains(AuthorityRight::Observe));

    // A right the request may declare but the instance does not carry fails
    // closed with the missing-right diagnostic instead.
    let unavailable = instance.admit(
        &admission(
            AuthorityRight::InvokeIdempotent,
            RecoveryClass::Idempotent,
            instance.generation(),
            0,
        ),
        &AncestorFences::none(),
    );
    match unavailable {
        Err(error) => {
            assert_eq!(error.code(), "authority-missing-right");
            assert_eq!(
                error,
                AuthorityError::MissingRight(AuthorityRight::InvokeIdempotent)
            );
        }
        Ok(_) => panic!("an instance admitted a right its rights set omits"),
    }
    assert!(
        instance.accepted().is_empty(),
        "neither failure dispatched or recorded an effect"
    );
}

#[test]
fn sharing_requires_a_declared_sharable_instance() {
    let sharable = fixture_instance(
        read_only_rights(),
        AuthorityLeasePolicy::Unleased,
        true,
        "crate::Fixture",
    );
    let holder = sharable
        .share()
        .unwrap_or_else(|_| unreachable!("a declared sharable instance is shared"));
    assert_eq!(holder.id(), sharable.id());

    let exclusive = fixture_instance(
        read_only_rights(),
        AuthorityLeasePolicy::Unleased,
        false,
        "crate::Fixture",
    );
    let exclusive_id = exclusive.id().clone();
    match exclusive.share() {
        Err(error) => assert_eq!(error, AuthorityError::NotSharable),
        Ok(_) => panic!("a non-sharable instance was shared"),
    }
    assert_eq!(
        exclusive.affine_move().id(),
        &exclusive_id,
        "a non-sharable instance moves by value"
    );
    assert!(
        !sharable
            .attenuate(read_only_rights(), AuthorityLeasePolicy::Unleased)
            .unwrap_or_else(|_| unreachable!("equal rights neither amplify nor empty a set"))
            .is_sharable()
    );
}

#[test]
fn lineage_audit_renders_canonical_identities_without_payloads() {
    let root = fixture_instance(
        wide_rights(),
        AuthorityLeasePolicy::Expiring { expires_at_us: 30 },
        false,
        "crate::Fixture",
    );
    let child = root
        .attenuate(
            RightsSet::from_rights(&[AuthorityRight::InvokeReadOnly, AuthorityRight::Delegate]),
            AuthorityLeasePolicy::Expiring { expires_at_us: 20 },
        )
        .unwrap_or_else(|_| unreachable!("a subset neither amplifies nor empties"));
    let record = child.lineage_record();

    assert_eq!(record.instance(), child.id());
    assert_eq!(record.parent(), Some(root.id()));
    assert_eq!(record.root(), root.id());
    assert_eq!(record.generation(), child.generation());
    assert_eq!(record.rights(), child.rights());
    assert_eq!(record.lease(), child.lease());

    let rendered = record.render();
    assert_eq!(rendered.lines().count(), 1);
    assert!(rendered.contains(child.id().as_str()));
    assert!(rendered.contains(root.id().as_str()));
    assert!(rendered.contains("lease=expiring"));
    assert!(rendered.contains("rights=invoke-read-only,delegate"));
    assert!(
        !rendered.contains("payload"),
        "lineage audit reveals no payload"
    );
}

/// A declared right is never the caller's choice: it must be exactly the right
/// the declared recovery class requires, so no request can talk a
/// preflight-only or delegation-only right into dispatch.
#[test]
fn declared_right_must_match_the_recovery_class_requirement() {
    let mut instance = fixture_instance(
        wide_rights(),
        AuthorityLeasePolicy::Unleased,
        false,
        "crate::Fixture",
    );
    for (declared, recovery) in [
        (AuthorityRight::Observe, RecoveryClass::ReadOnly),
        (AuthorityRight::Observe, RecoveryClass::NonIdempotent),
        (AuthorityRight::Delegate, RecoveryClass::ReadOnly),
        (AuthorityRight::Delegate, RecoveryClass::Idempotent),
        (AuthorityRight::Delegate, RecoveryClass::NonIdempotent),
        (AuthorityRight::InvokeNonIdempotent, RecoveryClass::ReadOnly),
    ] {
        let required = AuthorityRight::for_recovery_class(recovery);
        match instance.admit(
            &admission(declared, recovery, instance.generation(), 0),
            &AncestorFences::none(),
        ) {
            Err(error) => {
                assert_eq!(error.code(), "authority-right-recovery-mismatch");
                assert_eq!(
                    error,
                    AuthorityError::RightRecoveryMismatch { declared, required }
                );
            }
            Ok(_) => panic!("{declared:?} admitted {recovery:?} work"),
        }
    }
    assert!(
        instance.accepted().is_empty(),
        "no mismatched request dispatched anything"
    );

    // The right each recovery class requires still admits, so this rule bounds
    // the mismatch instead of blocking dispatch altogether.
    for recovery in [
        RecoveryClass::ReadOnly,
        RecoveryClass::Idempotent,
        RecoveryClass::NonIdempotent,
    ] {
        let required = AuthorityRight::for_recovery_class(recovery);
        assert!(
            instance
                .admit(
                    &admission(required, recovery, instance.generation(), 0),
                    &AncestorFences::none(),
                )
                .is_ok(),
            "{required:?} must admit {recovery:?} work"
        );
    }
    assert_eq!(instance.accepted().len(), 3);

    // Observe and Delegate are never required, so neither admits dispatch.
    for recovery in [
        RecoveryClass::ReadOnly,
        RecoveryClass::Idempotent,
        RecoveryClass::NonIdempotent,
    ] {
        let required = AuthorityRight::for_recovery_class(recovery);
        assert_ne!(required, AuthorityRight::Observe);
        assert_ne!(required, AuthorityRight::Delegate);
        assert!(required.wire_name().starts_with("invoke-"));
    }
}

/// Two attenuations of one parent to different rights sets are distinct
/// instances, so an ancestor-fence view can fence one without the other.
#[test]
fn sibling_attenuations_of_one_parent_are_distinct_and_independently_fenceable() {
    let mut root = fixture_instance(
        wide_rights(),
        AuthorityLeasePolicy::Unleased,
        false,
        "crate::Fixture",
    );
    let reads = root
        .attenuate(read_only_rights(), AuthorityLeasePolicy::Unleased)
        .unwrap_or_else(|_| unreachable!("a subset neither amplifies nor empties"));
    let delegates = root
        .attenuate(delegate_rights(), AuthorityLeasePolicy::Unleased)
        .unwrap_or_else(|_| unreachable!("a subset neither amplifies nor empties"));
    let repeated = root
        .attenuate(read_only_rights(), AuthorityLeasePolicy::Unleased)
        .unwrap_or_else(|_| unreachable!("a subset neither amplifies nor empties"));

    assert_eq!(
        reads.generation(),
        delegates.generation(),
        "siblings share one generation"
    );
    assert_eq!(reads.parent(), Some(root.id()));
    assert_eq!(delegates.parent(), Some(root.id()));
    assert_eq!(reads.lineage(), delegates.lineage());
    assert_ne!(reads.rights(), delegates.rights());
    assert_ne!(
        reads.id(),
        delegates.id(),
        "siblings that carry different rights must not collide on one identity"
    );
    assert_eq!(
        repeated.id(),
        reads.id(),
        "derivation stays deterministic for equal inputs"
    );

    // Each sibling can be named by an ancestor fence independently: a descendant
    // of the fenced sibling is fenced, a descendant of the other sibling is not.
    // The conflation this guards against would fence both descendants.
    let mut reads_child = reads
        .attenuate(read_only_rights(), AuthorityLeasePolicy::Unleased)
        .unwrap_or_else(|_| unreachable!("a subset neither amplifies nor empties"));
    let mut delegates_child = delegates
        .attenuate(read_only_rights(), AuthorityLeasePolicy::Unleased)
        .unwrap_or_else(|_| unreachable!("a subset neither amplifies nor empties"));
    let point = root.revoke();
    let fenced = AncestorFences::none().with_fenced(reads.id(), point.category());
    match reads_child.admit(
        &admission(
            AuthorityRight::InvokeReadOnly,
            RecoveryClass::ReadOnly,
            reads_child.generation(),
            0,
        ),
        &fenced,
    ) {
        Err(error) => assert_eq!(
            error,
            AuthorityError::AncestorFenced(FenceCategory::Revocation)
        ),
        Ok(_) => panic!("a descendant of a fenced sibling admitted work"),
    }
    assert!(
        delegates_child
            .admit(
                &admission(
                    AuthorityRight::InvokeReadOnly,
                    RecoveryClass::ReadOnly,
                    delegates_child.generation(),
                    0,
                ),
                &fenced,
            )
            .is_ok(),
        "a descendant of an unrelated sibling is not fenced by name"
    );
}

/// Rebinding consumes the instance and starts a fresh generation, so exactly one
/// live instance remains and the prior generation can never admit again.
#[test]
fn rebinding_consumes_the_instance_and_starts_a_fresh_generation() {
    let requirement = fixture_requirement();
    let original = fixture_instance(
        read_only_rights(),
        AuthorityLeasePolicy::Unleased,
        false,
        "crate::Fixture",
    );
    let previous_id = original.id().clone();
    let previous_root = original.root().clone();
    let mut rebound = original
        .rebind(fixture_binding(&requirement, "crate::Replacement"))
        .unwrap_or_else(|_| unreachable!("a live instance rebinds"));

    assert_ne!(rebound.id(), &previous_id);
    assert_eq!(rebound.root(), &previous_root, "the lineage root is kept");
    assert_eq!(
        rebound.parent(),
        None,
        "a rebinding is not a derivation, so it adds no parent edge"
    );
    assert_eq!(
        rebound.binding(),
        &fixture_binding(&requirement, "crate::Replacement")
    );
    assert_eq!(
        rebound.generation(),
        AuthorityGeneration::INITIAL
            .successor()
            .unwrap_or_else(|_| unreachable!("the initial generation has a successor"))
    );
    match rebound.admit(
        &admission(
            AuthorityRight::InvokeReadOnly,
            RecoveryClass::ReadOnly,
            AuthorityGeneration::INITIAL,
            0,
        ),
        &AncestorFences::none(),
    ) {
        Err(error) => assert_eq!(
            error,
            AuthorityError::StaleGeneration,
            "the consumed instance's generation is stale for its replacement"
        ),
        Ok(_) => panic!("the consumed instance's generation admitted work"),
    }
    assert!(rebound.accepted().is_empty());
    assert!(
        rebound
            .admit(
                &admission(
                    AuthorityRight::InvokeReadOnly,
                    RecoveryClass::ReadOnly,
                    rebound.generation(),
                    0,
                ),
                &AncestorFences::none(),
            )
            .is_ok(),
        "the fresh generation admits"
    );

    // A derived instance keeps its parent edge, and the edge participates in the
    // replacement's identity.
    let parent = fixture_instance(
        wide_rights(),
        AuthorityLeasePolicy::Unleased,
        false,
        "crate::Fixture",
    );
    let child = parent
        .attenuate(read_only_rights(), AuthorityLeasePolicy::Unleased)
        .unwrap_or_else(|_| unreachable!("a subset neither amplifies nor empties"));
    let child_parent = child.parent().cloned();
    let rebound_child = child
        .rebind(fixture_binding(&requirement, "crate::Replacement"))
        .unwrap_or_else(|_| unreachable!("a live instance rebinds"));
    assert_eq!(
        rebound_child.parent(),
        child_parent.as_ref(),
        "the replacement keeps the parent edge of the instance it replaces"
    );
    assert_eq!(rebound_child.root(), parent.root());
    assert_ne!(
        rebound_child.id(),
        rebound.id(),
        "the parent edge participates in the identity"
    );
}

/// Expiry and revocation are independent one-way latches, so revoking an already
/// expired instance is observable as a revocation.
#[test]
fn revocation_after_expiry_is_observable_as_a_revocation() {
    let mut expired = fixture_instance(
        read_only_rights(),
        AuthorityLeasePolicy::Unleased,
        false,
        "crate::Fixture",
    );
    let expiry = expired.expire();
    assert_eq!(expiry.category(), FenceCategory::Expiry);
    assert_eq!(expired.fence_latches().expiry(), Some(expiry));
    assert_eq!(expired.fence_latches().revocation(), None);

    let revocation = expired.revoke();
    assert_eq!(revocation.category(), FenceCategory::Revocation);
    assert_eq!(
        expired.fence_latches().expiry(),
        Some(expiry),
        "the expiry latch keeps its own linearization point"
    );
    assert_eq!(expired.fence_latches().revocation(), Some(revocation));
    assert_eq!(
        expired.fence_latches().categories(),
        [FenceCategory::Revocation, FenceCategory::Expiry],
        "both categories are reported distinctly"
    );
    assert!(matches!(
        expired.fence_state(),
        FenceState::Fenced(point) if point == revocation
    ));
    assert_eq!(
        expired.revoke(),
        revocation,
        "the revocation point is stable"
    );

    // The reverse order stays distinct as well.
    let mut revoked_first = fixture_instance(
        read_only_rights(),
        AuthorityLeasePolicy::Unleased,
        false,
        "crate::Replacement",
    );
    let first = revoked_first.revoke();
    let second = revoked_first.expire();
    assert_eq!(
        revoked_first.fence_latches().categories(),
        [FenceCategory::Revocation, FenceCategory::Expiry]
    );
    assert_eq!(revoked_first.fence_latches().revocation(), Some(first));
    assert_eq!(revoked_first.fence_latches().expiry(), Some(second));
    assert!(matches!(
        revoked_first.fence_state(),
        FenceState::Fenced(point) if point == first
    ));

    // A lease-driven expiry latches the same expiry latch, and a later
    // revocation is still reported as a revocation.
    let mut leased = fixture_instance(
        read_only_rights(),
        AuthorityLeasePolicy::Expiring { expires_at_us: 5 },
        false,
        "crate::Fixture",
    );
    match leased.admit(
        &admission(
            AuthorityRight::InvokeReadOnly,
            RecoveryClass::ReadOnly,
            leased.generation(),
            5,
        ),
        &AncestorFences::none(),
    ) {
        Err(error) => assert_eq!(error, AuthorityError::Fenced(FenceCategory::Expiry)),
        Ok(_) => panic!("an expired lease admitted work"),
    }
    assert_eq!(
        leased
            .fence_latches()
            .expiry()
            .map(|point| point.category()),
        Some(FenceCategory::Expiry)
    );
    assert_eq!(
        leased.revoke().category(),
        FenceCategory::Revocation,
        "a revocation after a lease expiry is observable as a revocation"
    );
    assert_eq!(
        leased.fence_latches().categories(),
        [FenceCategory::Revocation, FenceCategory::Expiry]
    );
}

/// Admission checks run in one documented order: the stale generation first and
/// without mutating state, then the fences, then the lease expiry, then the
/// declared right.
#[test]
fn admission_checks_run_stale_generation_then_fences_then_lease_then_rights() {
    // A stale generation on an expired lease reports staleness and latches
    // nothing, so no expiry is charged to a request that never held authority.
    let mut expired = fixture_instance(
        read_only_rights(),
        AuthorityLeasePolicy::Expiring { expires_at_us: 10 },
        false,
        "crate::Fixture",
    );
    match expired.admit(
        &admission(
            AuthorityRight::InvokeReadOnly,
            RecoveryClass::ReadOnly,
            AuthorityGeneration::new(7),
            99,
        ),
        &AncestorFences::none(),
    ) {
        Err(error) => assert_eq!(error, AuthorityError::StaleGeneration),
        Ok(_) => panic!("a stale generation admitted work"),
    }
    assert_eq!(
        expired.fence_latches(),
        FenceLatches::open(),
        "a stale request mutates no fence state"
    );
    match expired.admit(
        &admission(
            AuthorityRight::InvokeReadOnly,
            RecoveryClass::ReadOnly,
            expired.generation(),
            10,
        ),
        &AncestorFences::none(),
    ) {
        Err(error) => assert_eq!(error, AuthorityError::Fenced(FenceCategory::Expiry)),
        Ok(_) => panic!("an expired lease admitted work"),
    }
    assert!(expired.fence_latches().expiry().is_some());

    // A stale generation that is also revoked still reports staleness, and a
    // stale generation behind a fenced ancestor is never attributed to the
    // ancestor. The ancestor fence outranks the lease and the rights check.
    let mut revoked = fixture_instance(
        read_only_rights(),
        AuthorityLeasePolicy::Unleased,
        false,
        "crate::Fixture",
    );
    revoked.revoke();
    match revoked.admit(
        &admission(
            AuthorityRight::InvokeReadOnly,
            RecoveryClass::ReadOnly,
            AuthorityGeneration::new(9),
            0,
        ),
        &AncestorFences::none(),
    ) {
        Err(error) => assert_eq!(error, AuthorityError::StaleGeneration),
        Ok(_) => panic!("a stale generation was reported as a fence"),
    }
    let root = fixture_instance(
        wide_rights(),
        AuthorityLeasePolicy::Unleased,
        false,
        "crate::Fixture",
    );
    let mut child = root
        .attenuate(read_only_rights(), AuthorityLeasePolicy::Unleased)
        .unwrap_or_else(|_| unreachable!("a subset neither amplifies nor empties"));
    let ancestors = AncestorFences::none().with_fenced(root.id(), FenceCategory::Revocation);
    match child.admit(
        &admission(
            AuthorityRight::InvokeReadOnly,
            RecoveryClass::ReadOnly,
            AuthorityGeneration::new(9),
            0,
        ),
        &ancestors,
    ) {
        Err(error) => assert_eq!(
            error,
            AuthorityError::StaleGeneration,
            "staleness outranks an ancestor fence"
        ),
        Ok(_) => panic!("a stale generation admitted work"),
    }
    match child.admit(
        &admission(
            AuthorityRight::Observe,
            RecoveryClass::ReadOnly,
            child.generation(),
            0,
        ),
        &ancestors,
    ) {
        Err(error) => assert_eq!(
            error,
            AuthorityError::AncestorFenced(FenceCategory::Revocation),
            "an ancestor fence outranks the declared right"
        ),
        Ok(_) => panic!("a descendant of a revoked ancestor admitted work"),
    }

    // An existing fence outranks lease expiry and the declared right.
    let mut fenced = fixture_instance(
        read_only_rights(),
        AuthorityLeasePolicy::Expiring { expires_at_us: 10 },
        false,
        "crate::Fixture",
    );
    fenced.revoke();
    match fenced.admit(
        &admission(
            AuthorityRight::InvokeNonIdempotent,
            RecoveryClass::NonIdempotent,
            fenced.generation(),
            99,
        ),
        &AncestorFences::none(),
    ) {
        Err(error) => assert_eq!(error, AuthorityError::Fenced(FenceCategory::Revocation)),
        Ok(_) => panic!("a revoked instance admitted work"),
    }

    // Lease expiry outranks the declared right and latches expiry.
    let mut leased = fixture_instance(
        read_only_rights(),
        AuthorityLeasePolicy::Expiring { expires_at_us: 10 },
        false,
        "crate::Fixture",
    );
    match leased.admit(
        &admission(
            AuthorityRight::Observe,
            RecoveryClass::ReadOnly,
            leased.generation(),
            10,
        ),
        &AncestorFences::none(),
    ) {
        Err(error) => assert_eq!(error, AuthorityError::Fenced(FenceCategory::Expiry)),
        Ok(_) => panic!("an expired lease admitted work"),
    }
    assert_eq!(
        leased
            .fence_latches()
            .expiry()
            .map(|point| point.category()),
        Some(FenceCategory::Expiry)
    );

    // With a live lease the declared right decides, and the two right failures
    // are reported distinctly. Only a matching, carried right commits.
    let mut live = fixture_instance(
        read_only_rights(),
        AuthorityLeasePolicy::Unleased,
        false,
        "crate::Fixture",
    );
    match live.admit(
        &admission(
            AuthorityRight::InvokeIdempotent,
            RecoveryClass::Idempotent,
            live.generation(),
            0,
        ),
        &AncestorFences::none(),
    ) {
        Err(error) => assert_eq!(error.code(), "authority-missing-right"),
        Ok(_) => panic!("an instance admitted a right it does not carry"),
    }
    match live.admit(
        &admission(
            AuthorityRight::Observe,
            RecoveryClass::ReadOnly,
            live.generation(),
            0,
        ),
        &AncestorFences::none(),
    ) {
        Err(error) => assert_eq!(error.code(), "authority-right-recovery-mismatch"),
        Ok(_) => panic!("a preflight-only right admitted work"),
    }
    assert!(live.accepted().is_empty());
    assert!(
        live.admit(
            &admission(
                AuthorityRight::InvokeReadOnly,
                RecoveryClass::ReadOnly,
                live.generation(),
                0,
            ),
            &AncestorFences::none(),
        )
        .is_ok()
    );
    assert_eq!(live.accepted().len(), 1);
}

/// A lease-policy difference is its own authority-compatibility change, so the
/// candidate that lengthens or drops a lease is not a plain rebinding.
#[test]
fn lease_policy_changes_are_classified_as_authority_changes() {
    let previous = fixture_instance(
        read_only_rights(),
        AuthorityLeasePolicy::Expiring { expires_at_us: 40 },
        false,
        "crate::Fixture",
    );
    let longer = fixture_instance(
        read_only_rights(),
        AuthorityLeasePolicy::Expiring { expires_at_us: 80 },
        false,
        "crate::Fixture",
    );
    let comparison = previous
        .compare(&longer)
        .unwrap_or_else(|_| unreachable!("both fixtures satisfy one requirement"));
    assert_eq!(comparison.lease, LeaseRelation::Lengthened);
    assert_eq!(
        comparison.authority_compatibility_changes(),
        BTreeSet::from([AuthorityChangeClass::LeasePolicyChange])
    );
    assert!(
        !comparison.is_rebinding_only(),
        "a lengthened lease is not a plain rebinding"
    );

    let unleased = fixture_instance(
        read_only_rights(),
        AuthorityLeasePolicy::Unleased,
        false,
        "crate::Fixture",
    );
    let dropped = previous
        .compare(&unleased)
        .unwrap_or_else(|_| unreachable!("both fixtures satisfy one requirement"));
    assert_eq!(dropped.lease, LeaseRelation::NewlyUnleased);
    assert_eq!(
        dropped.authority_compatibility_changes(),
        BTreeSet::from([AuthorityChangeClass::LeasePolicyChange])
    );
    assert!(
        !dropped.is_rebinding_only(),
        "a dropped lease is not a plain rebinding"
    );
    assert_eq!(
        AuthorityChangeClass::LeasePolicyChange.wire_name(),
        "lease-policy-change"
    );

    // A lease change that also widens rights reports both classes separately.
    // The wider candidate is a second root of one requirement, so it replants the
    // lineage as well; three classes are still reported distinctly.
    let widened = fixture_instance(
        wide_rights(),
        AuthorityLeasePolicy::Unleased,
        false,
        "crate::Fixture",
    );
    let combined = previous
        .compare(&widened)
        .unwrap_or_else(|_| unreachable!("both fixtures satisfy one requirement"));
    assert_eq!(
        combined.authority_compatibility_changes(),
        BTreeSet::from([
            AuthorityChangeClass::LeasePolicyChange,
            AuthorityChangeClass::RightsWidening,
            AuthorityChangeClass::LineageReplanting,
        ])
    );
}

/// Comparison is defined only between instances of one capability requirement.
#[test]
fn comparison_rejects_instances_of_different_requirements() {
    let instance = fixture_instance(
        read_only_rights(),
        AuthorityLeasePolicy::Unleased,
        false,
        "crate::Fixture",
    );
    let idempotent = AuthorityRequirementId::new(
        &fixture_path(),
        &CanonicalSignature::action(
            RecoveryClass::Idempotent,
            &fixture_path(),
            &[],
            &TypeDescriptor::STRING,
        ),
        FAMILY,
        RecoveryClass::Idempotent,
    )
    .unwrap_or_else(|_| unreachable!("fixture family is portable"));
    let other = AuthorityInstance::bind(
        idempotent.clone(),
        fixture_binding(&idempotent, "crate::Fixture"),
        read_only_rights(),
        AuthorityLeasePolicy::Unleased,
        false,
    )
    .unwrap_or_else(|_| unreachable!("fixture binding satisfies its requirement"));

    match instance.compare(&other) {
        Err(error) => {
            assert_eq!(error, AuthorityError::IncomparableRequirements);
            assert_eq!(error.code(), "authority-incomparable-requirements");
        }
        Ok(_) => panic!("compared instances of two different capability requirements"),
    }

    // Instances of one requirement still compare.
    let twin = fixture_instance(
        read_only_rights(),
        AuthorityLeasePolicy::Unleased,
        false,
        "crate::Fixture",
    );
    assert!(instance.compare(&twin).is_ok());
}

/// A generation at the numeric maximum cannot produce a descendant generation,
/// so no descendant can silently reuse its parent's generation and identity.
#[test]
fn generation_exhaustion_is_reported_instead_of_saturating() {
    assert_eq!(
        AuthorityGeneration::new(u64::MAX - 1).successor(),
        Ok(AuthorityGeneration::new(u64::MAX))
    );
    assert_eq!(
        AuthorityGeneration::new(u64::MAX).successor(),
        Err(AuthorityError::GenerationExhausted)
    );
    assert_eq!(
        AuthorityError::GenerationExhausted.code(),
        "authority-generation-exhausted"
    );
}

/// Builds the canonical declaration path used by every fixture.
fn fixture_path() -> CanonicalPath {
    CanonicalPath::new("crate::read_only")
        .unwrap_or_else(|_| unreachable!("fixture path is canonical"))
}

/// Builds the public capability requirement every fixture instance satisfies.
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

/// Builds one selected implementation binding for a requirement.
fn fixture_binding(
    requirement: &AuthorityRequirementId,
    implementation: &str,
) -> AuthorityBindingId {
    let receiver = TypeExpression::from_canonical_string(implementation, 4)
        .unwrap_or_else(|_| unreachable!("fixture receiver is a canonical type"));
    AuthorityBindingId::new(
        requirement,
        &CanonicalImplementationIdentity::inherent(&receiver),
    )
}

/// Builds one bound instance for the fixture requirement.
fn fixture_instance(
    rights: RightsSet,
    lease: AuthorityLeasePolicy,
    sharable: bool,
    implementation: &str,
) -> AuthorityInstance {
    let requirement = fixture_requirement();
    let binding = fixture_binding(&requirement, implementation);
    AuthorityInstance::bind(requirement, binding, rights, lease, sharable)
        .unwrap_or_else(|_| unreachable!("fixture binding satisfies its requirement"))
}

/// Builds one admission request against a known generation.
fn admission(
    right: AuthorityRight,
    recovery: RecoveryClass,
    generation: AuthorityGeneration,
    now_us: u64,
) -> AdmissionRequest {
    AdmissionRequest {
        right,
        recovery,
        generation,
        now_us,
    }
}

/// The rights of the narrowest fixture instance.
fn read_only_rights() -> RightsSet {
    RightsSet::from_rights(&[AuthorityRight::InvokeReadOnly])
}

/// The rights of a fixture instance that may also delegate.
fn delegate_rights() -> RightsSet {
    RightsSet::from_rights(&[AuthorityRight::InvokeReadOnly, AuthorityRight::Delegate])
}

/// The rights of the widest fixture instance.
fn wide_rights() -> RightsSet {
    RightsSet::from_rights(&[
        AuthorityRight::InvokeReadOnly,
        AuthorityRight::InvokeIdempotent,
        AuthorityRight::InvokeNonIdempotent,
        AuthorityRight::Delegate,
    ])
}
