//! Machine-checked conformance for protected values, the protected semantic
//! envelope, destination-specific release, sealed emergency cleanup, and the
//! protection invariants.
//!
//! These tests exercise the public protected-data model of `gantry::ir` for
//! `GNT-15.10-protected-values`, `GNT-15.10-semantic-envelope`,
//! `GNT-15.10-release-operation`, `GNT-15.10-emergency-cleanup`, and
//! `GNT-15.10-protection-invariants`. They check the model the specification
//! makes normative, not a runtime protection store: no test here observes a
//! protected payload, a live sink, a provider, or a host service.
//!
//! Several checks are negative evidence. A compile-time proof shows that an
//! erasing observation of a protected value cannot be expressed at all, and the
//! remaining checks fail when a rule is violated: a component with no evidence
//! reported as safe, a release without holder authority, a frozen delivery
//! permission that widens a declared destination class, or a cleanup report
//! that distinguishes the values it consumed.

use std::collections::BTreeSet;

use gantry::ir::generated::RecoveryClass;
use gantry::ir::{
    AUTHORITY_RIGHT_ORDER, AdmissionRequest, AncestorFences, AuditAccess, AuditOutcome,
    AuthorityBindingId, AuthorityInstance, AuthorityLeasePolicy, AuthorityRequirementId,
    AuthorityRight, CanonicalImplementationIdentity, CanonicalPath, CanonicalSignature,
    CleanupOutcome, CrossingDeclaration, CrossingRejection, DeclaredName, DeclaredNameRejection,
    DeliveryDecision, DeliveryDenial, DisclosureBudget, DisclosureCharge,
    ENVELOPE_OBSERVATION_ORDER, EXCLUDED_PROTECTION_CLAIMS, EmergencyCleanup, EnvelopeClause,
    EnvelopeObservation, ExcludedClaimKind, ExcludedProtectionClaimName, FrozenDeliveryPermission,
    NON_ERASURE_COMPONENT_ORDER, NonErasureComponentKind, NonErasureObligation, NonErasureStatus,
    PROTECTED_DATA_CLASS_ORDER, ProjectionKind, ProtectedDataClass, ProtectedValue,
    ProtectionPreservingTransform, ProvenanceOrigin, ProvenanceOriginKind,
    RELEASE_DESTINATION_ORDER, RecoveryProjectionClass, ReleaseAuditEvidence,
    ReleaseAuthorityError, ReleaseDecision, ReleaseDestination, ReleaseGrant,
    ReleaseHolderAuthority, ReleaseHolderBindingId, ReleaseOutcome, ReleaseProjection,
    ReleaseRejection, ReleaseSite, ReleasedValue, RightsSet, SemanticEnvelope,
    SourceProtectionClass, TypeDescriptor, TypeExpression, ValueActionBoundary, admit_crossing,
    combined_protection_class,
};
use gantry::portable::ProtectedReferenceClass;
use sha2::{Digest, Sha256};

/// Compile-time proof that one type implements none of the listed traits.
///
/// A blanket implementation and a trait-bounded implementation both apply, so
/// naming the associated item requires an inference that cannot be resolved and
/// compilation fails. A protected value or a protected evidence record that
/// acquired `Debug`, `Display`, `Serialize`, `Deserialize`, `PartialEq`, `Eq`,
/// `Hash`, `PartialOrd`, or `Ord` would stop this crate compiling, which is the
/// negative-evidence check the specification requires of codecs, diagnostics,
/// events, dependency edges, tools, provider adapters, and generated schemas.
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
    let receiver = TypeExpression::from_canonical_string("crate::ProtectedFixture", 4)
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

/// Seals one fixture protected value of one class.
fn value(class: ProtectedDataClass) -> ProtectedValue {
    ProtectedValue::seal(class, fixture_origin("crate::integration"))
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

/// Binds one holder authority over one named fixture release site.
///
/// A binding names exactly one site, so an authority built here authorizes
/// releases only at `site_name`, and the grants it derives carry that site.
fn authority_for(
    site_name: &str,
    classes: &[ProtectedDataClass],
    destinations: &[ReleaseDestination],
) -> ReleaseHolderAuthority {
    let site = fixture_name(site_name);
    let binding = ReleaseHolderBindingId::new(&site, &fixture_integration());
    ReleaseHolderAuthority::bind(&site, binding, classes, destinations)
        .unwrap_or_else(|_| unreachable!("the fixture binding names its own site"))
}

/// Binds one holder authority over the fixture release site.
fn authority(
    classes: &[ProtectedDataClass],
    destinations: &[ReleaseDestination],
) -> ReleaseHolderAuthority {
    authority_for("crate::release", classes, destinations)
}

/// Binds one holder authority that may release nothing.
fn withholding_authority() -> ReleaseHolderAuthority {
    authority(&[], &[])
}

/// Builds one release site declaring exactly one pair.
fn site(class: ProtectedDataClass, destination: ReleaseDestination) -> ReleaseSite {
    ReleaseSite::new("crate::release").declare(class, destination, ProjectionKind::Redacted)
}

/// Builds one complete semantic envelope that classifies every consequence.
fn complete_envelope() -> SemanticEnvelope {
    ENVELOPE_OBSERVATION_ORDER
        .into_iter()
        .fold(SemanticEnvelope::new(), |envelope, observation| {
            envelope.classify(observation, EnvelopeClause::Protected)
        })
}

#[test]
fn protected_values_are_sealed_opaque_and_never_ordinary() {
    assert_not_impl_any!(
        ProtectedValue: std::fmt::Debug,
        std::fmt::Display,
        serde::Serialize,
        serde::Deserialize<'static>
    );
    let sealed_value = value(ProtectedDataClass::SourceText);
    assert!(sealed_value.is_protected());
    assert!(!sealed_value.is_external_value());
    assert_eq!(sealed_value.class(), ProtectedDataClass::SourceText);
    assert_eq!(
        sealed_value.protection_class(),
        SourceProtectionClass::Sealed
    );
    assert_eq!(
        sealed_value.recovery_projection(),
        RecoveryProjectionClass::SealedValue
    );
}

#[test]
fn ordinary_observations_of_a_protected_value_are_unreachable() {
    assert_not_impl_any!(
        ProtectedValue: std::fmt::Debug,
        std::fmt::Display,
        serde::Serialize,
        serde::Deserialize<'static>,
        PartialEq,
        Eq,
        std::hash::Hash,
        PartialOrd,
        Ord
    );
    let first = sealed(ProtectedDataClass::SourceText, "crate::first-boundary");
    let second = sealed(ProtectedDataClass::SourceText, "crate::second-boundary");
    assert_ne!(first.id(), second.id());
    assert!(!first.id().as_str().contains("crate::first-boundary"));
    assert!(first.id().as_str().starts_with("protected:"));
    assert_eq!(
        first.id(),
        sealed(ProtectedDataClass::SourceText, "crate::first-boundary").id()
    );
    assert_eq!(first.class(), ProtectedDataClass::SourceText);
    assert!(first.is_protected());
    assert!(!first.id().digest_hex().is_empty());
}

#[test]
fn protected_class_vocabulary_is_closed_and_not_inferred_from_journal_references() {
    let mut spellings = BTreeSet::new();
    for class in PROTECTED_DATA_CLASS_ORDER {
        assert_eq!(
            ProtectedDataClass::from_wire_name(class.wire_name()),
            Some(class)
        );
        assert!(
            spellings.insert(class.wire_name()),
            "each protected data class has one exact spelling"
        );
    }
    assert_eq!(
        ProtectedDataClass::from_wire_name("journal-record-payload"),
        None,
        "the protected-class vocabulary is closed"
    );
    for journal_reference in [
        ProtectedReferenceClass::RawOutput,
        ProtectedReferenceClass::SourceSnippet,
        ProtectedReferenceClass::OperationRequest,
        ProtectedReferenceClass::IntegrationDiagnostic,
        ProtectedReferenceClass::NormalizedDecision,
        ProtectedReferenceClass::NormalizedOperationError,
    ] {
        assert_eq!(
            ProtectedDataClass::from_wire_name(journal_reference.wire_name()),
            None,
            "a journal protected-reference class of Section 12 is not a protected data class"
        );
    }
    assert_eq!(
        ProtectedReferenceClass::NormalizedValue.wire_name(),
        ProtectedDataClass::NormalizedValue.wire_name(),
        "one shared spelling does not make the two vocabularies one definition"
    );
}

#[test]
fn provenance_is_a_validated_declaration_and_identity_is_payload_independent() {
    assert_eq!(
        ProvenanceOrigin::new(
            ProvenanceOriginKind::IntegrationBoundary,
            "{\"payload\":\"secret\"}"
        )
        .err(),
        Some(DeclaredNameRejection::NonCanonicalCharacter),
        "arbitrary payload bytes can never be supplied as provenance"
    );
    assert!(ProvenanceOrigin::new(ProvenanceOriginKind::IntegrationBoundary, "session 7").is_err());
    assert!(
        ProvenanceOrigin::new(
            ProvenanceOriginKind::IntegrationBoundary,
            "non-ascii-\u{e9}"
        )
        .is_err()
    );
    assert_eq!(
        ProvenanceOriginKind::from_wire_name("integration-boundary"),
        Some(ProvenanceOriginKind::IntegrationBoundary)
    );
    assert_eq!(
        ProvenanceOriginKind::from_wire_name("caller-supplied-bytes"),
        None
    );
    let first = sealed(ProtectedDataClass::SourceText, "crate::boundary");
    let second = sealed(ProtectedDataClass::SourceText, "crate::boundary");
    assert_eq!(
        first.id(),
        second.id(),
        "identity is stable across payload differences"
    );
    assert_ne!(
        first.id(),
        sealed(ProtectedDataClass::SourceText, "crate::other-boundary").id()
    );
    assert!(!first.id().as_str().contains("crate::boundary"));
}

#[test]
fn protected_values_have_no_byte_constructor_or_public_storage() {
    let first = sealed(ProtectedDataClass::JournalRecord, "crate::journal");
    let second = sealed(ProtectedDataClass::JournalRecord, "crate::journal");
    assert_eq!(first.id(), second.id());
    assert_eq!(first.id().digest_hex().len(), 64);
    assert!(
        first
            .id()
            .digest_hex()
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte.is_ascii_lowercase())
    );
    let naive = format!("{:x}", Sha256::digest(b"crate::journal"));
    assert_ne!(
        first.id().digest_hex(),
        naive,
        "identity derivation is domain separated, not a naive hash"
    );
    assert_eq!(first.class(), ProtectedDataClass::JournalRecord);
}

#[test]
fn layer_one_readability_does_not_imply_inspectability() {
    for class in PROTECTED_DATA_CLASS_ORDER {
        let inspection = value(class).layer_one_inspection();
        assert_eq!(inspection.layer(), 1);
        assert!(inspection.readable_by_source());
        assert!(
            !inspection.inspectable_by_source(),
            "a layer-1 value may be readable by source without being inspectable by it"
        );
    }
}

#[test]
fn protection_preserving_transformations_keep_dependent_outputs_protected() {
    let transform = ProtectionPreservingTransform::declare(
        ProtectedDataClass::SourceText,
        ProtectedDataClass::RenderedPrompt,
        ProjectionKind::Verbatim,
        complete_envelope(),
    )
    .unwrap_or_else(|_| unreachable!("a complete envelope declares the transformation"));
    let output = transform
        .apply(&value(ProtectedDataClass::SourceText))
        .unwrap_or_else(|| unreachable!("the declared input class is consumed"));
    assert!(output.is_protected());
    assert_eq!(output.class(), ProtectedDataClass::RenderedPrompt);
    assert_eq!(output.protection_class(), SourceProtectionClass::Sealed);
    assert!(
        transform
            .apply(&value(ProtectedDataClass::EntryInput))
            .is_none()
    );
}

#[test]
fn every_semantic_envelope_item_is_classified() {
    let declared = complete_envelope();
    assert!(declared.is_complete());
    for observation in ENVELOPE_OBSERVATION_ORDER {
        assert!(declared.effective(observation).is_protected());
        assert!(declared.declared(observation).is_some());
    }
    let mut missing_one = SemanticEnvelope::new();
    for observation in ENVELOPE_OBSERVATION_ORDER {
        if observation != EnvelopeObservation::DiagnosticText {
            missing_one = missing_one.classify(observation, EnvelopeClause::Protected);
        }
    }
    let refused = ProtectionPreservingTransform::declare(
        ProtectedDataClass::SourceText,
        ProtectedDataClass::NormalizedValue,
        ProjectionKind::Verbatim,
        missing_one,
    );
    let Err(rejection) = refused else {
        unreachable!("a transformation that leaves a consequence unclassified is refused")
    };
    assert_eq!(rejection.unclassified().len(), 1);
    assert_eq!(
        rejection.unclassified()[0],
        EnvelopeObservation::DiagnosticText
    );
}

#[test]
fn semantic_envelope_covers_every_language_visible_consequence() {
    let mut spellings = BTreeSet::new();
    for observation in ENVELOPE_OBSERVATION_ORDER {
        assert_eq!(
            EnvelopeObservation::from_wire_name(observation.wire_name()),
            Some(observation)
        );
        assert!(spellings.insert(observation.wire_name()));
    }
    assert_eq!(
        EnvelopeObservation::from_wire_name("output-content"),
        None,
        "the envelope enumerates declared consequences only"
    );
    assert!(complete_envelope().is_complete());
    assert!(
        ProtectionPreservingTransform::declare(
            ProtectedDataClass::EntryInput,
            ProtectedDataClass::RenderedPrompt,
            ProjectionKind::Redacted,
            SemanticEnvelope::new(),
        )
        .is_err(),
        "an operation over protected inputs must classify every consequence"
    );
    let declaring = SemanticEnvelope::new().classify(
        EnvelopeObservation::OutputSize,
        EnvelopeClause::OrdinaryPayloadIndependent,
    );
    assert_eq!(
        declaring.effective(EnvelopeObservation::OutputSize),
        EnvelopeClause::OrdinaryPayloadIndependent
    );
}

#[test]
fn unclassified_observations_default_to_protected() {
    let envelope = SemanticEnvelope::new().classify(
        EnvelopeObservation::OutputSize,
        EnvelopeClause::OrdinaryPayloadIndependent,
    );
    assert_eq!(
        envelope.effective(EnvelopeObservation::OutputSize),
        EnvelopeClause::OrdinaryPayloadIndependent
    );
    assert_eq!(
        envelope.effective(EnvelopeObservation::DiagnosticText),
        EnvelopeClause::Protected
    );
    assert_eq!(envelope.declared(EnvelopeObservation::DiagnosticText), None);
    assert!(!envelope.is_complete());
    assert_eq!(envelope.unclassified().len(), 9);
    for observation in envelope.unclassified() {
        assert!(
            envelope.effective(observation).is_protected(),
            "a missing item defaults to protected, never to ordinary"
        );
    }
}

#[test]
fn release_requires_authority_class_and_destination_independently() {
    assert_not_impl_any!(ReleaseGrant: Default);
    assert_not_impl_any!(ReleaseHolderAuthority: Default);
    let mut budget = disclosure_budget(4, 1);
    let protected = value(ProtectedDataClass::ActionArgument);
    let site = site(
        ProtectedDataClass::ActionArgument,
        ReleaseDestination::DiagnosticSink,
    );
    let destinations_only = authority(&[], &[ReleaseDestination::DiagnosticSink]);
    assert_eq!(
        site.release(
            &destinations_only.grant(),
            &protected,
            ReleaseDestination::DiagnosticSink,
            &mut budget,
        )
        .decision(),
        ReleaseDecision::Rejected(ReleaseRejection::ClassMismatch)
    );
    let classes_only = authority(&[ProtectedDataClass::ActionArgument], &[]);
    assert_eq!(
        site.release(
            &classes_only.grant(),
            &protected,
            ReleaseDestination::DiagnosticSink,
            &mut budget,
        )
        .decision(),
        ReleaseDecision::Rejected(ReleaseRejection::DestinationMismatch)
    );
    let other_site = ReleaseSite::new("crate::other");
    let granting = authority(
        &[ProtectedDataClass::ActionArgument],
        &[ReleaseDestination::DiagnosticSink],
    );
    assert_eq!(
        other_site
            .release(
                &granting.grant(),
                &protected,
                ReleaseDestination::DiagnosticSink,
                &mut budget,
            )
            .decision(),
        ReleaseDecision::Rejected(ReleaseRejection::ClassMismatch)
    );
    assert_eq!(
        budget.remaining(),
        4,
        "no rejected release charged the budget"
    );
    let wide = authority(
        &[
            ProtectedDataClass::SourceText,
            ProtectedDataClass::ActionArgument,
        ],
        &[
            ReleaseDestination::OrdinarySource,
            ReleaseDestination::DiagnosticSink,
        ],
    );
    let narrow = wide.attenuate(
        &[ProtectedDataClass::SourceText],
        &[ReleaseDestination::OrdinarySource],
    );
    assert!(narrow.grant().is_strict_subset_of(&wide.grant()));
    assert_ne!(narrow.id(), wide.id());
    assert_eq!(narrow.site(), wide.site());
    assert!(narrow.grant().covers(
        ProtectedDataClass::SourceText,
        ReleaseDestination::OrdinarySource
    ));
    assert!(!narrow.grant().covers(
        ProtectedDataClass::ActionArgument,
        ReleaseDestination::OrdinarySource
    ));
    assert!(withholding_authority().grant().is_empty());
    assert_eq!(withholding_authority().grant().class_count(), 0);
    assert_eq!(withholding_authority().grant().destination_count(), 0);
    let other_site_name = fixture_name("crate::other");
    let foreign_binding = ReleaseHolderBindingId::new(&other_site_name, &fixture_integration());
    assert!(
        ReleaseHolderAuthority::bind(&fixture_name("crate::release"), foreign_binding, &[], &[])
            .is_err(),
        "an integration binding that names another site mints no authority"
    );
    assert_eq!(
        ReleaseAuthorityError::SiteMismatch.wire_name(),
        "site-mismatch"
    );
}

#[test]
fn release_grant_is_refused_at_another_site_declaring_the_same_pair() {
    let holder = authority(
        &[ProtectedDataClass::SourceText],
        &[ReleaseDestination::OrdinarySource],
    );
    let grant = holder.grant();
    assert_eq!(grant.holder(), holder.id());
    assert_eq!(grant.site(), "crate::release");
    assert_eq!(grant.binding().site(), "crate::release");
    let protected = value(ProtectedDataClass::SourceText);
    let mut budget = disclosure_budget(2, 1);
    let elsewhere = ReleaseSite::new("crate::other").declare(
        ProtectedDataClass::SourceText,
        ReleaseDestination::OrdinarySource,
        ProjectionKind::Verbatim,
    );
    let refused = elsewhere.release(
        &grant,
        &protected,
        ReleaseDestination::OrdinarySource,
        &mut budget,
    );
    assert_eq!(
        refused.decision(),
        ReleaseDecision::Rejected(ReleaseRejection::DestinationMismatch),
        "a grant carries the site of the authority that derived it, so another site declaring the same class and destination pair authorizes nothing"
    );
    assert_eq!(refused.projection(), None);
    assert_eq!(refused.released_value(), None);
    assert!(refused.audit_view(&AuditAccess::granted()).is_none());
    assert_eq!(budget.accepted(), 0);
    assert_eq!(budget.remaining(), 2, "the refusal charged nothing");
    let own_site = site(
        ProtectedDataClass::SourceText,
        ReleaseDestination::OrdinarySource,
    );
    let accepted = own_site.release(
        &grant,
        &protected,
        ReleaseDestination::OrdinarySource,
        &mut budget,
    );
    assert!(
        matches!(accepted.decision(), ReleaseDecision::Accepted(_)),
        "the same grant still authorizes the site it was derived for"
    );
    assert_eq!(budget.accepted(), 1);
    let foreign = authority_for(
        "crate::other",
        &[ProtectedDataClass::SourceText],
        &[ReleaseDestination::OrdinarySource],
    )
    .grant();
    let narrowed = grant.attenuate(&foreign);
    assert_eq!(
        narrowed.site(),
        "crate::release",
        "attenuation narrows permission but never moves a grant to another site"
    );
}

#[test]
fn release_never_authorizes_execution_and_admission_never_implies_release() {
    let requirement = fixture_requirement();
    let binding = fixture_binding(&requirement);
    let mut instance = AuthorityInstance::bind(
        requirement,
        binding,
        RightsSet::from_rights(&AUTHORITY_RIGHT_ORDER),
        AuthorityLeasePolicy::Unleased,
        false,
    )
    .unwrap_or_else(|_| unreachable!("fixture binding satisfies its requirement"));
    let generation = instance.generation();
    let admission = instance
        .admit(
            &AdmissionRequest {
                right: AuthorityRight::InvokeNonIdempotent,
                recovery: RecoveryClass::NonIdempotent,
                generation,
                now_us: 0,
            },
            &AncestorFences::default(),
        )
        .unwrap_or_else(|_| unreachable!("the widest fixture instance admits dispatch"));
    assert_eq!(admission.settlement_rule(), RecoveryClass::NonIdempotent);
    assert!(
        instance
            .rights()
            .contains(AuthorityRight::InvokeNonIdempotent)
    );
    for right in AUTHORITY_RIGHT_ORDER {
        assert!(
            !right.wire_name().contains("release"),
            "no authority right is a release right"
        );
    }
    assert_eq!(
        AuthorityRight::for_recovery_class(RecoveryClass::NonIdempotent),
        AuthorityRight::InvokeNonIdempotent
    );
    let mut budget = disclosure_budget(2, 1);
    let release_site = ReleaseSite::new("crate::release").declare(
        ProtectedDataClass::ActionArgument,
        ReleaseDestination::OrdinarySource,
        ProjectionKind::Verbatim,
    );
    let outcome = release_site.release(
        &withholding_authority().grant(),
        &sealed(ProtectedDataClass::ActionArgument, "crate::argument"),
        ReleaseDestination::OrdinarySource,
        &mut budget,
    );
    assert_eq!(
        outcome.decision(),
        ReleaseDecision::Rejected(ReleaseRejection::ClassMismatch)
    );
    assert_eq!(outcome.released_value(), None);
    assert_eq!(budget.accepted(), 0);
}

#[test]
fn release_destination_class_is_closed_and_declared_before_evaluation() {
    for destination in RELEASE_DESTINATION_ORDER {
        assert_eq!(
            ReleaseDestination::from_wire_name(destination.wire_name()),
            Some(destination)
        );
    }
    assert!(ReleaseDestination::NullTelemetry.is_null());
    assert!(!ReleaseDestination::OrdinarySource.is_null());
    assert_eq!(
        ReleaseDestination::from_wire_name("arbitrary-sink"),
        None,
        "the destination class is closed"
    );
    let declaring = ReleaseSite::new("crate::release").declare(
        ProtectedDataClass::SourceText,
        ReleaseDestination::OrdinarySource,
        ProjectionKind::Verbatim,
    );
    assert!(declaring.declares(
        ProtectedDataClass::SourceText,
        ReleaseDestination::OrdinarySource
    ));
    assert!(!declaring.declares(
        ProtectedDataClass::SourceText,
        ReleaseDestination::DiagnosticSink
    ));
    assert!(declaring.declares_class(ProtectedDataClass::SourceText));
    let mut budget = disclosure_budget(2, 1);
    let outcome = declaring.release(
        &authority(
            &[ProtectedDataClass::SourceText],
            &[ReleaseDestination::DiagnosticSink],
        )
        .grant(),
        &value(ProtectedDataClass::SourceText),
        ReleaseDestination::DiagnosticSink,
        &mut budget,
    );
    assert_eq!(
        outcome.decision(),
        ReleaseDecision::Rejected(ReleaseRejection::DestinationMismatch)
    );
    assert_eq!(budget.remaining(), 2);
}

#[test]
fn rejection_categories_are_payload_independent() {
    let site = site(
        ProtectedDataClass::SourceText,
        ReleaseDestination::OrdinarySource,
    );
    let mut budget = disclosure_budget(2, 1);
    let withholding = withholding_authority().grant();
    let first = site.release(
        &withholding,
        &sealed(ProtectedDataClass::SourceText, "crate::first"),
        ReleaseDestination::OrdinarySource,
        &mut budget,
    );
    let second = site.release(
        &withholding,
        &sealed(ProtectedDataClass::SourceText, "crate::second"),
        ReleaseDestination::OrdinarySource,
        &mut budget,
    );
    assert_eq!(first.decision(), second.decision());
    assert_eq!(first.released_value(), second.released_value());
    assert_eq!(
        ReleaseRejection::ClassMismatch.wire_name(),
        "class-mismatch"
    );
    assert_eq!(
        ReleaseRejection::DestinationMismatch.wire_name(),
        "destination-mismatch"
    );
    assert_eq!(
        ReleaseRejection::BudgetExhausted.wire_name(),
        "budget-exhausted"
    );
    for rejection in [
        ReleaseRejection::ClassMismatch,
        ReleaseRejection::DestinationMismatch,
        ReleaseRejection::BudgetExhausted,
    ] {
        assert!(!rejection.wire_name().contains("payload"));
        assert!(!rejection.wire_name().contains("delivery"));
    }
}

#[test]
fn disclosure_budget_is_monotone_and_exhausts_deterministically() {
    assert_eq!(
        DisclosureCharge::new(0),
        None,
        "a zero charge would make exhaustion unreachable"
    );
    let site = site(
        ProtectedDataClass::SourceText,
        ReleaseDestination::OrdinarySource,
    );
    let permissions = authority(
        &[ProtectedDataClass::SourceText],
        &[ReleaseDestination::OrdinarySource],
    )
    .grant();
    let mut budget = disclosure_budget(2, 1);
    let mut trail = Vec::new();
    let mut decisions = Vec::new();
    for origin_name in ["crate::first", "crate::second", "crate::third"] {
        let outcome = site.release(
            &permissions,
            &sealed(ProtectedDataClass::SourceText, origin_name),
            ReleaseDestination::OrdinarySource,
            &mut budget,
        );
        trail.push(budget.remaining());
        decisions.push(outcome.decision());
    }
    assert_eq!(trail, vec![1, 0, 0], "the budget only ever decreases");
    assert_eq!(
        decisions,
        vec![
            ReleaseDecision::Accepted(ReleaseProjection::new(
                ProjectionKind::Redacted,
                ProtectedDataClass::SourceText,
                ReleaseDestination::OrdinarySource,
            )),
            ReleaseDecision::Accepted(ReleaseProjection::new(
                ProjectionKind::Redacted,
                ProtectedDataClass::SourceText,
                ReleaseDestination::OrdinarySource,
            )),
            ReleaseDecision::Rejected(ReleaseRejection::BudgetExhausted),
        ]
    );
    assert_eq!(budget.accepted(), 2);
    assert!(budget.is_exhausted());
    assert_eq!(budget.accounting().charge, 1);
    assert_eq!(disclosure_budget(0, 1).after_charge(), None);
}

#[test]
fn release_audit_evidence_names_the_site_without_payload() {
    assert_not_impl_any!(
        ReleaseAuditEvidence: std::fmt::Debug,
        std::fmt::Display,
        serde::Serialize,
        serde::Deserialize<'static>,
        std::hash::Hash
    );
    assert_not_impl_any!(
        ReleaseOutcome: std::fmt::Debug,
        std::fmt::Display,
        serde::Serialize,
        serde::Deserialize<'static>
    );
    let mut budget = disclosure_budget(3, 1);
    let audited_site = ReleaseSite::new("crate::release").declare(
        ProtectedDataClass::SessionIdentifier,
        ReleaseDestination::ProtectedJournal,
        ProjectionKind::Redacted,
    );
    let outcome = audited_site.release(
        &authority(
            &[ProtectedDataClass::SessionIdentifier],
            &[ReleaseDestination::ProtectedJournal],
        )
        .grant(),
        &sealed(
            ProtectedDataClass::SessionIdentifier,
            "crate::session-holder",
        ),
        ReleaseDestination::ProtectedJournal,
        &mut budget,
    );
    let access = AuditAccess::granted();
    let view = outcome
        .audit_view(&access)
        .unwrap_or_else(|| unreachable!("an accepted release has a declared view"));
    assert_eq!(view.site(), "crate::release");
    assert_eq!(view.class(), ProtectedDataClass::SessionIdentifier);
    assert_eq!(view.destination(), ReleaseDestination::ProtectedJournal);
    assert_eq!(view.projection(), ProjectionKind::Redacted);
    assert_eq!(view.budget_consumed(), 1);
    assert_eq!(view.budget_remaining(), 2);
    assert_eq!(view.outcome(), AuditOutcome::Accepted);
    let text = view.canonical_text();
    assert!(text.contains("site=crate::release"));
    assert!(text.contains("class=session-identifier"));
    assert!(text.contains("destination=protected-journal"));
    assert!(text.contains("projection=redacted"));
    assert!(text.contains("consumed=1"));
    assert!(text.contains("outcome=accepted"));
    assert!(!text.contains("crate::session-holder"));
    assert_eq!(AuditOutcome::Accepted.wire_name(), "accepted");
    assert_eq!(AuditOutcome::Rejected.wire_name(), "rejected");
    let refused = site(
        ProtectedDataClass::SourceText,
        ReleaseDestination::OrdinarySource,
    )
    .release(
        &withholding_authority().grant(),
        &value(ProtectedDataClass::SourceText),
        ReleaseDestination::OrdinarySource,
        &mut disclosure_budget(2, 1),
    );
    assert!(refused.audit_view(&access).is_none());
}

#[test]
fn frozen_delivery_permissions_own_the_transport_side_decision() {
    let sink = ReleaseDestination::DiagnosticSink;
    let protected = value(ProtectedDataClass::SourceText);
    let site = site(ProtectedDataClass::SourceText, sink);
    let granting = authority(&[ProtectedDataClass::SourceText], &[sink]);
    let mut budget = disclosure_budget(4, 1);
    let accepted = site.release(&granting.grant(), &protected, sink, &mut budget);
    assert!(accepted.released_value().is_some());
    let denying = FrozenDeliveryPermission::frozen(sink, &[ProtectedDataClass::JournalRecord]);
    assert_eq!(denying.sink(), sink);
    assert!(denying.admits(ProtectedDataClass::JournalRecord));
    assert!(!denying.admits(ProtectedDataClass::SourceText));
    assert_eq!(
        denying.deliver(&accepted, &protected, sink),
        DeliveryDecision::Denied(DeliveryDenial::FrozenPermissionDenies),
        "an accepted release never overrides a frozen permission that denies access"
    );
    let admitting = FrozenDeliveryPermission::frozen(sink, &[ProtectedDataClass::SourceText]);
    let refused = site.release(
        &withholding_authority().grant(),
        &protected,
        sink,
        &mut budget,
    );
    assert_eq!(
        refused.decision(),
        ReleaseDecision::Rejected(ReleaseRejection::ClassMismatch)
    );
    assert_eq!(
        admitting.deliver(&refused, &protected, sink),
        DeliveryDecision::Denied(DeliveryDenial::NoAcceptedRelease),
        "an admitting frozen permission without an accepted release delivers nothing"
    );
    assert_eq!(
        admitting.deliver(&accepted, &protected, ReleaseDestination::OrdinarySource),
        DeliveryDecision::Denied(DeliveryDenial::DestinationWidened)
    );
    let wider = FrozenDeliveryPermission::frozen(
        ReleaseDestination::OrdinarySource,
        &[ProtectedDataClass::SourceText],
    );
    assert_eq!(
        wider.deliver(&accepted, &protected, ReleaseDestination::OrdinarySource),
        DeliveryDecision::Denied(DeliveryDenial::DestinationWidened),
        "a transport admission never widens the declared destination class"
    );
    assert_eq!(
        admitting.deliver(&accepted, &protected, sink),
        DeliveryDecision::Delivered
    );
    assert!(
        admitting
            .deliver(&accepted, &protected, sink)
            .is_delivered()
    );
    assert_eq!(
        admitting.deliver(&refused, &protected, sink).denial(),
        Some(DeliveryDenial::NoAcceptedRelease)
    );
    assert_eq!(
        DeliveryDenial::NoAcceptedRelease.wire_name(),
        "no-accepted-release"
    );
    assert_eq!(
        DeliveryDenial::FrozenPermissionDenies.wire_name(),
        "frozen-permission-denies"
    );
    assert_eq!(
        DeliveryDenial::DestinationWidened.wire_name(),
        "destination-widened"
    );
}

#[test]
fn release_outcomes_depend_on_the_declared_destination_class() {
    let journal_site = ReleaseSite::new("crate::release").declare(
        ProtectedDataClass::SourceText,
        ReleaseDestination::ProtectedJournal,
        ProjectionKind::Verbatim,
    );
    let protected = value(ProtectedDataClass::SourceText);
    let permissions = authority(
        &[ProtectedDataClass::SourceText],
        &[ReleaseDestination::ProtectedJournal],
    )
    .grant();
    let mut budget = disclosure_budget(4, 1);
    let to_journal = journal_site.release(
        &permissions,
        &protected,
        ReleaseDestination::ProtectedJournal,
        &mut budget,
    );
    assert_eq!(
        to_journal.projection().map(ReleaseProjection::kind),
        Some(ProjectionKind::Verbatim)
    );
    assert_eq!(
        to_journal.projection().map(ReleaseProjection::destination),
        Some(ReleaseDestination::ProtectedJournal)
    );
    let released = to_journal
        .released_value()
        .unwrap_or_else(|| unreachable!("an accepted release produces an ordinary value"));
    assert!(released.is_ordinary());
    assert!(!released.is_protected());
    assert_eq!(released.class(), ProtectedDataClass::SourceText);
    assert_eq!(released.destination(), ReleaseDestination::ProtectedJournal);
    let to_source = journal_site.release(
        &permissions,
        &protected,
        ReleaseDestination::OrdinarySource,
        &mut budget,
    );
    assert_eq!(
        to_source.decision(),
        ReleaseDecision::Rejected(ReleaseRejection::DestinationMismatch)
    );
    assert_eq!(
        to_source.released_value(),
        None,
        "no ordinary value exists before acceptance"
    );
    assert_eq!(
        budget.accepted(),
        1,
        "a further release to another destination is a new release with its own charge"
    );
    let ordinary_source_site = site(
        ProtectedDataClass::SourceText,
        ReleaseDestination::OrdinarySource,
    );
    let to_ordinary_source = ordinary_source_site.release(
        &authority(
            &[ProtectedDataClass::SourceText],
            &[ReleaseDestination::OrdinarySource],
        )
        .grant(),
        &protected,
        ReleaseDestination::OrdinarySource,
        &mut budget,
    );
    let declassified = to_ordinary_source
        .released_value()
        .unwrap_or_else(|| unreachable!("release to ordinary source produces an ordinary value"));
    assert!(declassified.is_ordinary());
    assert_eq!(
        declassified.destination(),
        ReleaseDestination::OrdinarySource
    );
    assert_eq!(declassified.kind(), ProjectionKind::Redacted);
    assert_eq!(
        declassified.projection().class(),
        ProtectedDataClass::SourceText
    );
    assert_eq!(
        ReleasedValue::class(declassified),
        ProtectedDataClass::SourceText
    );
}

#[test]
fn payload_independent_public_settlement_stays_ordinary() {
    for observation in [
        EnvelopeObservation::SuccessOrFailure,
        EnvelopeObservation::TaskOrChannelOutcome,
        EnvelopeObservation::Termination,
    ] {
        assert_eq!(
            SemanticEnvelope::new()
                .classify(observation, EnvelopeClause::OrdinaryPayloadIndependent)
                .effective(observation),
            EnvelopeClause::OrdinaryPayloadIndependent
        );
    }
    let permissions = authority(
        &[ProtectedDataClass::SourceText],
        &[ReleaseDestination::OrdinarySource],
    )
    .grant();
    let mut budget = disclosure_budget(1, 1);
    let site = site(
        ProtectedDataClass::SourceText,
        ReleaseDestination::OrdinarySource,
    );
    let accepted = site.release(
        &permissions,
        &value(ProtectedDataClass::SourceText),
        ReleaseDestination::OrdinarySource,
        &mut budget,
    );
    assert!(matches!(accepted.decision(), ReleaseDecision::Accepted(_)));
    let refused = site.release(
        &permissions,
        &value(ProtectedDataClass::SourceText),
        ReleaseDestination::OrdinarySource,
        &mut budget,
    );
    assert_eq!(
        refused.decision(),
        ReleaseDecision::Rejected(ReleaseRejection::BudgetExhausted)
    );
    assert_eq!(
        refused.budget(),
        accepted.budget(),
        "exhaustion refusal is ordinary settlement and changes no accounting"
    );
    assert_eq!(refused.released_value(), None);
    assert!(refused.audit_view(&AuditAccess::granted()).is_none());
}

#[test]
fn denial_transport_failure_and_exhaustion_require_an_independent_contract() {
    let exhausted = disclosure_budget(0, 1);
    assert!(exhausted.is_exhausted());
    assert_eq!(exhausted.after_charge(), None);
    assert_eq!(exhausted.accounting().accepted, 0);
    assert_eq!(exhausted.accounting().remaining, 0);
    assert_eq!(exhausted.accounting().charge, 1);
    let mut budget = exhausted;
    let site = site(
        ProtectedDataClass::SourceText,
        ReleaseDestination::NullTelemetry,
    );
    let refused = site.release(
        &authority(
            &[ProtectedDataClass::SourceText],
            &[ReleaseDestination::NullTelemetry],
        )
        .grant(),
        &value(ProtectedDataClass::SourceText),
        ReleaseDestination::NullTelemetry,
        &mut budget,
    );
    assert_eq!(
        refused.decision(),
        ReleaseDecision::Rejected(ReleaseRejection::BudgetExhausted)
    );
    assert_eq!(refused.released_value(), None);
    assert!(refused.audit_view(&AuditAccess::granted()).is_none());
    assert_eq!(
        budget.accounting(),
        exhausted.accounting(),
        "exhaustion is deterministic in ordinary accounting alone"
    );
    let frozen = FrozenDeliveryPermission::frozen(
        ReleaseDestination::DiagnosticSink,
        &[ProtectedDataClass::SourceText],
    );
    assert_eq!(
        frozen.deliver(
            &refused,
            &value(ProtectedDataClass::SourceText),
            ReleaseDestination::DiagnosticSink
        ),
        DeliveryDecision::Denied(DeliveryDenial::NoAcceptedRelease)
    );
}

#[test]
fn language_visible_completion_and_arbitration_are_semantic() {
    let envelope = SemanticEnvelope::new()
        .classify(
            EnvelopeObservation::ReadinessOrder,
            EnvelopeClause::Protected,
        )
        .classify(
            EnvelopeObservation::RetryDecision,
            EnvelopeClause::Protected,
        );
    for observation in [
        EnvelopeObservation::ReadinessOrder,
        EnvelopeObservation::RetryDecision,
    ] {
        assert!(envelope.effective(observation).is_protected());
        assert!(envelope.declared(observation).is_some());
    }
    assert!(
        !envelope.is_complete(),
        "observed completion and arbitration stay inside the semantic envelope"
    );
    assert!(
        ProtectionPreservingTransform::declare(
            ProtectedDataClass::SourceText,
            ProtectedDataClass::NormalizedValue,
            ProjectionKind::Verbatim,
            envelope,
        )
        .is_err()
    );
}

#[test]
fn logical_charges_are_settlement_or_protected_values() {
    let logical_charge = value(ProtectedDataClass::NormalizedValue);
    assert!(logical_charge.is_protected());
    let mut budget = disclosure_budget(2, 2);
    let site = site(
        ProtectedDataClass::NormalizedValue,
        ReleaseDestination::ProtectedJournal,
    );
    let outcome = site.release(
        &authority(
            &[ProtectedDataClass::NormalizedValue],
            &[ReleaseDestination::ProtectedJournal],
        )
        .grant(),
        &logical_charge,
        ReleaseDestination::ProtectedJournal,
        &mut budget,
    );
    assert!(matches!(outcome.decision(), ReleaseDecision::Accepted(_)));
    assert_eq!(outcome.budget().accepted(), 1);
    assert_eq!(outcome.budget().remaining(), 0);
    assert!(outcome.budget().is_exhausted());
    assert_eq!(
        outcome.released_value().map(ReleasedValue::class),
        Some(ProtectedDataClass::NormalizedValue)
    );
    let ordinary = disclosure_budget(2, 2).accounting();
    assert_eq!(ordinary.accepted, 0);
    assert_eq!(ordinary.remaining, 2);
    assert_eq!(ordinary.charge, 2);
}

#[test]
fn sealed_classification_is_reused_and_unsealed_is_not_nonsensitive() {
    assert_eq!(
        combined_protection_class(
            SourceProtectionClass::Sealed,
            SourceProtectionClass::Unsealed
        ),
        SourceProtectionClass::Sealed
    );
    assert_eq!(
        combined_protection_class(
            SourceProtectionClass::Unsealed,
            SourceProtectionClass::Unsealed
        ),
        SourceProtectionClass::Unsealed
    );
    let integration_data = sealed(
        ProtectedDataClass::NormalizedValue,
        "crate::unsealed-integration-data",
    );
    assert!(integration_data.is_protected());
    assert_eq!(
        combined_protection_class(
            SourceProtectionClass::Unsealed,
            integration_data.protection_class()
        ),
        SourceProtectionClass::Sealed,
        "unsealed never means nonsensitive"
    );
    assert_eq!(
        combined_protection_class(
            integration_data.protection_class(),
            SourceProtectionClass::Unsealed
        ),
        SourceProtectionClass::Sealed
    );
    let mut budget = disclosure_budget(2, 1);
    assert_eq!(
        site(
            ProtectedDataClass::NormalizedValue,
            ReleaseDestination::OrdinarySource
        )
        .release(
            &withholding_authority().grant(),
            &integration_data,
            ReleaseDestination::OrdinarySource,
            &mut budget,
        )
        .decision(),
        ReleaseDecision::Rejected(ReleaseRejection::ClassMismatch)
    );
    assert_eq!(budget.accepted(), 0);
}

#[test]
fn protected_values_do_not_cross_a_value_action_boundary_undeclared() {
    let protected = value(ProtectedDataClass::ActionArgument);
    for boundary in [
        ValueActionBoundary::ActionArgument,
        ValueActionBoundary::EntryInput,
        ValueActionBoundary::WorkflowResult,
        ValueActionBoundary::TaskResult,
        ValueActionBoundary::OperationResult,
        ValueActionBoundary::ProtocolEnvelope,
    ] {
        assert_eq!(
            admit_crossing(&protected, boundary, None),
            Err(CrossingRejection::UndeclaredProtocol)
        );
    }
    let declaration = CrossingDeclaration::new(
        ValueActionBoundary::ProtocolEnvelope,
        ProtectedDataClass::ActionArgument,
    );
    assert_eq!(
        admit_crossing(
            &protected,
            ValueActionBoundary::ProtocolEnvelope,
            Some(&declaration)
        ),
        Ok(())
    );
    assert_eq!(
        admit_crossing(
            &protected,
            ValueActionBoundary::EntryInput,
            Some(&declaration)
        ),
        Err(CrossingRejection::BoundaryMismatch)
    );
    let wrong_class = CrossingDeclaration::new(
        ValueActionBoundary::ProtocolEnvelope,
        ProtectedDataClass::NamedInput,
    );
    assert_eq!(
        admit_crossing(
            &protected,
            ValueActionBoundary::ProtocolEnvelope,
            Some(&wrong_class)
        ),
        Err(CrossingRejection::ClassMismatch)
    );
    assert_eq!(
        CrossingRejection::ClassMismatch.wire_name(),
        "class-mismatch"
    );
}

#[test]
fn emergency_cleanup_is_sealed_and_callback_free() {
    let cleanup = EmergencyCleanup::sealed(disclosure_budget(4, 1), 4);
    assert_eq!(cleanup.destination(), ReleaseDestination::NullTelemetry);
    assert!(cleanup.destination().is_null());
    assert!(!cleanup.accepts_source_callback());
    assert!(!cleanup.declassifies());
    assert!(!cleanup.extends_authority());
    assert_eq!(cleanup.work_limit(), 4);
    let report = cleanup.run(&[&value(ProtectedDataClass::SourceText)]);
    assert_eq!(report.outcome(), CleanupOutcome::Completed);
    assert!(!report.callbacks_invoked());
    assert!(!report.source_semantics_changed());
    assert!(report.durable_prefix_only());
}

#[test]
fn cleanup_reaches_only_a_predeclared_null_destination() {
    let cleanup = EmergencyCleanup::sealed(disclosure_budget(2, 1), 8);
    assert_ne!(cleanup.destination(), ReleaseDestination::OrdinarySource);
    assert_ne!(cleanup.destination(), ReleaseDestination::DiagnosticSink);
    assert_ne!(cleanup.destination(), ReleaseDestination::ProviderModel);
    assert_ne!(cleanup.destination(), ReleaseDestination::ProtectedJournal);
    let empty = cleanup.run(&[]);
    assert_eq!(empty.outcome(), CleanupOutcome::Completed);
    assert!(!empty.callbacks_invoked());
    let unbudgeted = EmergencyCleanup::sealed(disclosure_budget(0, 1), 8);
    let refused = unbudgeted.run(&[&value(ProtectedDataClass::SourceText)]);
    assert_eq!(
        refused.outcome(),
        CleanupOutcome::Refused,
        "cleanup uses only authority that already exists"
    );
    assert!(refused.durable_prefix_only());
}

#[test]
fn no_hidden_finalization_changes_source_semantics() {
    let cleanup = EmergencyCleanup::sealed(disclosure_budget(16, 1), 16);
    let report = cleanup.run(&[
        &value(ProtectedDataClass::JournalRecord),
        &value(ProtectedDataClass::ProtectedEventPayload),
    ]);
    assert_eq!(report.outcome(), CleanupOutcome::Completed);
    assert!(!report.source_semantics_changed());
    assert!(!report.callbacks_invoked());
    assert!(report.durable_prefix_only());
    let interrupted = EmergencyCleanup::interrupted();
    assert_eq!(interrupted.outcome(), CleanupOutcome::Interrupted);
    assert!(!interrupted.source_semantics_changed());
    assert!(!interrupted.callbacks_invoked());
    assert!(interrupted.durable_prefix_only());
}

#[test]
fn cleanup_outcomes_are_payload_independent_and_bounded() {
    let bounded = EmergencyCleanup::sealed(disclosure_budget(8, 1), 2);
    let first = [
        value(ProtectedDataClass::SourceText),
        value(ProtectedDataClass::JournalRecord),
        value(ProtectedDataClass::NamedInput),
    ];
    let second = [
        value(ProtectedDataClass::DecisionRationale),
        value(ProtectedDataClass::DeclineReason),
        value(ProtectedDataClass::HookFailureMessage),
    ];
    let first_report = bounded.run(&first.iter().collect::<Vec<_>>());
    let second_report = bounded.run(&second.iter().collect::<Vec<_>>());
    assert_eq!(
        first_report, second_report,
        "two cleanups over different classes and different values produce identical reports"
    );
    assert_eq!(first_report.outcome(), CleanupOutcome::Bounded);
    assert!(!first_report.callbacks_invoked());
    assert!(!first_report.source_semantics_changed());
    assert!(first_report.durable_prefix_only());
    let completed = EmergencyCleanup::sealed(disclosure_budget(8, 1), 8);
    let one = [value(ProtectedDataClass::SourceText)];
    let five = [
        value(ProtectedDataClass::SourceText),
        value(ProtectedDataClass::JournalRecord),
        value(ProtectedDataClass::NamedInput),
        value(ProtectedDataClass::DecisionRationale),
        value(ProtectedDataClass::DeclineReason),
    ];
    let single_report = completed.run(&one.iter().collect::<Vec<_>>());
    assert_eq!(
        single_report,
        completed.run(&five.iter().collect::<Vec<_>>()),
        "the report publishes neither the number nor the distribution of consumed values"
    );
    assert_eq!(single_report.outcome(), CleanupOutcome::Completed);
}

#[test]
fn interrupted_cleanup_promises_only_the_durable_prefix() {
    let interrupted = EmergencyCleanup::interrupted();
    assert_eq!(interrupted.outcome(), CleanupOutcome::Interrupted);
    assert!(interrupted.durable_prefix_only());
    assert!(!interrupted.source_semantics_changed());
    assert!(!interrupted.callbacks_invoked());
    assert_eq!(
        interrupted,
        EmergencyCleanup::interrupted(),
        "an interrupted cleanup publishes no consumed count to describe"
    );
    assert_eq!(CleanupOutcome::Interrupted.wire_name(), "interrupted");
    assert_eq!(CleanupOutcome::Completed.wire_name(), "completed");
    assert_eq!(CleanupOutcome::Bounded.wire_name(), "bounded");
}

#[test]
fn codecs_diagnostics_events_tools_and_adapters_preserve_protection() {
    let protected = value(ProtectedDataClass::SourceText);
    let mut budget = disclosure_budget(4, 1);
    let refusing = site(
        ProtectedDataClass::SourceText,
        ReleaseDestination::OrdinarySource,
    );
    let refused = refusing.release(
        &withholding_authority().grant(),
        &protected,
        ReleaseDestination::OrdinarySource,
        &mut budget,
    );
    assert!(refused.projection().is_none());
    assert!(refused.released_value().is_none());
    assert!(refused.audit_view(&AuditAccess::granted()).is_none());
    let diagnostic = ReleaseSite::new("crate::diagnostic").declare(
        ProtectedDataClass::SourceText,
        ReleaseDestination::DiagnosticSink,
        ProjectionKind::Redacted,
    );
    let accepted = diagnostic.release(
        &authority_for(
            "crate::diagnostic",
            &[ProtectedDataClass::SourceText],
            &[ReleaseDestination::DiagnosticSink],
        )
        .grant(),
        &protected,
        ReleaseDestination::DiagnosticSink,
        &mut budget,
    );
    assert!(matches!(accepted.decision(), ReleaseDecision::Accepted(_)));
    assert!(protected.is_protected());
    assert_eq!(protected.class(), ProtectedDataClass::SourceText);
    assert_eq!(
        accepted.projection().map(ReleaseProjection::kind),
        Some(ProjectionKind::Redacted)
    );
    for kind in NON_ERASURE_COMPONENT_ORDER {
        let obligation = NonErasureObligation::open(kind, kind.wire_name());
        assert_eq!(
            obligation.status(),
            NonErasureStatus::Unproven,
            "a component with no cited evidence is unproven"
        );
        assert!(
            !obligation.is_reported_safe(),
            "an absence of observed leakage is not evidence of non-erasure"
        );
    }
}

#[test]
fn non_erasure_is_a_negative_evidence_obligation() {
    assert_not_impl_any!(ProtectedValue: std::fmt::Debug, std::fmt::Display, PartialEq);
    let opening =
        NonErasureObligation::open(NonErasureComponentKind::DependencyEdge, "crate::edge");
    assert!(opening.evidence().is_empty());
    assert_eq!(opening.status(), NonErasureStatus::Unproven);
    assert!(!opening.is_reported_safe());
    let empty_evidence = opening.clone().with_evidence("");
    assert_eq!(
        empty_evidence.status(),
        NonErasureStatus::Unproven,
        "empty evidence counts as no proof"
    );
    assert!(empty_evidence.evidence().is_empty());
    let claiming = NonErasureObligation::unreachable(NonErasureComponentKind::Tool, "crate::tool");
    assert_eq!(
        claiming.status(),
        NonErasureStatus::Unproven,
        "a claim without citable evidence stays unproven"
    );
    let proven = claiming.with_evidence(
        "crates/gantry-conformance/tests/protected_release.rs#non_erasure_is_a_negative_evidence_obligation",
    );
    assert_eq!(
        proven.status(),
        NonErasureStatus::UnreachableWithProtectedValue
    );
    assert!(proven.is_reported_safe());
    assert_eq!(proven.evidence().len(), 1);
    assert!(
        NonErasureObligation::not_applicable(NonErasureComponentKind::Codec, "crate::codec", "")
            .is_none()
    );
    let ordinary = NonErasureObligation::not_applicable(
        NonErasureComponentKind::Codec,
        "crate::codec",
        "encodes ordinary scalar bytes only",
    )
    .unwrap_or_else(|| unreachable!("the ordinary-data case declares its own justification"));
    assert_eq!(
        ordinary.justification(),
        Some("encodes ordinary scalar bytes only")
    );
    assert_eq!(
        ordinary.status(),
        NonErasureStatus::Unproven,
        "a justification without evidence stays unproven"
    );
    assert_eq!(
        ordinary
            .with_evidence(
                "crates/gantry-conformance/tests/protected_release.rs#non_erasure_is_a_negative_evidence_obligation",
            )
            .status(),
        NonErasureStatus::NotApplicable
    );
    assert_eq!(NonErasureStatus::Unproven.wire_name(), "unproven");
    assert_eq!(
        NonErasureComponentKind::GeneratedSchema.wire_name(),
        "generated-schema"
    );
    let first = sealed(ProtectedDataClass::SourceText, "crate::provenance");
    let second = sealed(ProtectedDataClass::SourceText, "crate::provenance");
    assert_eq!(first.id(), second.id(), "identity comparison is ordinary");
    assert!(!first.id().as_str().contains("crate::provenance"));
    let projection = ReleaseProjection::new(
        ProjectionKind::Verbatim,
        ProtectedDataClass::SourceText,
        ReleaseDestination::OrdinarySource,
    );
    assert_eq!(projection.kind(), ProjectionKind::Verbatim);
    assert_eq!(projection.class(), ProtectedDataClass::SourceText);
    assert_eq!(projection.destination(), ReleaseDestination::OrdinarySource);
}

#[test]
fn bounded_claim_excludes_noninterference_and_physical_channels() {
    assert_eq!(EXCLUDED_PROTECTION_CLAIMS.len(), 4);
    let not_promised = EXCLUDED_PROTECTION_CLAIMS
        .iter()
        .filter(|claim| claim.is_not_promised())
        .collect::<Vec<_>>();
    assert_eq!(not_promised.len(), 2);
    assert_eq!(
        not_promised[0].name(),
        ExcludedProtectionClaimName::FullNoninterferenceAfterRelease
    );
    assert_eq!(
        not_promised[1].name(),
        ExcludedProtectionClaimName::PhysicalSideChannels
    );
    assert_eq!(
        not_promised[0].wire_name(),
        "full-noninterference-after-release"
    );
    assert_eq!(not_promised[1].wire_name(), "physical-side-channels");
    let mut budget = disclosure_budget(2, 1);
    let site = site(
        ProtectedDataClass::SourceText,
        ReleaseDestination::OrdinarySource,
    );
    let outcome = site.release(
        &authority(
            &[ProtectedDataClass::SourceText],
            &[ReleaseDestination::OrdinarySource],
        )
        .grant(),
        &sealed(ProtectedDataClass::SourceText, "crate::session"),
        ReleaseDestination::OrdinarySource,
        &mut budget,
    );
    assert!(matches!(outcome.decision(), ReleaseDecision::Accepted(_)));
    let released = outcome
        .released_value()
        .unwrap_or_else(|| unreachable!("the release was accepted"));
    assert!(
        released.is_ordinary(),
        "once released the value is ordinary, and the bounded claim says nothing about the destination"
    );
}

#[test]
fn declassification_is_never_implicit_and_authority_is_not_release() {
    let mut budget = disclosure_budget(2, 1);
    let site = site(
        ProtectedDataClass::SourceText,
        ReleaseDestination::OrdinarySource,
    );
    let implied = site.release(
        &withholding_authority().grant(),
        &value(ProtectedDataClass::SourceText),
        ReleaseDestination::OrdinarySource,
        &mut budget,
    );
    assert_eq!(
        implied.decision(),
        ReleaseDecision::Rejected(ReleaseRejection::ClassMismatch)
    );
    assert_eq!(
        implied.released_value(),
        None,
        "no operation declassifies a protected value without a declared release"
    );
    assert_eq!(budget.accepted(), 0);
    let narrow = authority(
        &[ProtectedDataClass::SourceText],
        &[ReleaseDestination::OrdinarySource],
    );
    let wide = authority(
        &[
            ProtectedDataClass::SourceText,
            ProtectedDataClass::ActionArgument,
        ],
        &[
            ReleaseDestination::OrdinarySource,
            ReleaseDestination::DiagnosticSink,
        ],
    );
    assert!(narrow.grant().is_subset_of(&wide.grant()));
    assert!(!wide.grant().is_subset_of(&narrow.grant()));
    let prohibited = EXCLUDED_PROTECTION_CLAIMS
        .iter()
        .filter(|claim| claim.is_prohibited())
        .collect::<Vec<_>>();
    assert_eq!(prohibited.len(), 2);
    assert_eq!(
        prohibited[0].name(),
        ExcludedProtectionClaimName::ImplicitDeclassification
    );
    assert_eq!(
        prohibited[1].name(),
        ExcludedProtectionClaimName::AuthorityIsReleaseAuthority
    );
    assert_eq!(prohibited[0].kind(), ExcludedClaimKind::Prohibited);
    assert_eq!(prohibited[1].kind(), ExcludedClaimKind::Prohibited);
    assert!(!prohibited[0].is_not_promised());
    assert!(!prohibited[1].is_not_promised());
    for right in AUTHORITY_RIGHT_ORDER {
        assert!(
            !right.wire_name().contains("release"),
            "operation authority is not release authority"
        );
    }
}

#[test]
fn ordinary_data_positive_controls_stay_ordinary() {
    let ordinary_budget = disclosure_budget(2, 2);
    assert_eq!(ordinary_budget.remaining(), 2);
    assert_eq!(ordinary_budget.charge().value(), 2);
    assert_eq!(ordinary_budget.accepted(), 0);
    assert!(!ordinary_budget.is_exhausted());
    assert!(ordinary_budget.after_charge().is_some());
    assert_eq!(ordinary_budget.accounting().remaining, 2);
    let envelope = SemanticEnvelope::new().classify(
        EnvelopeObservation::OutputPresence,
        EnvelopeClause::OrdinaryPayloadIndependent,
    );
    assert_eq!(
        envelope.effective(EnvelopeObservation::OutputPresence),
        EnvelopeClause::OrdinaryPayloadIndependent
    );
    let grant = authority(
        &[ProtectedDataClass::SourceText],
        &[ReleaseDestination::OrdinarySource],
    )
    .grant();
    assert_eq!(grant.class_count(), 1);
    assert_eq!(grant.destination_count(), 1);
    assert!(grant.covers(
        ProtectedDataClass::SourceText,
        ReleaseDestination::OrdinarySource
    ));
    assert!(!grant.covers(
        ProtectedDataClass::SourceText,
        ReleaseDestination::ProviderModel
    ));
    assert_eq!(
        grant.classes().collect::<Vec<_>>(),
        vec![ProtectedDataClass::SourceText]
    );
    assert_eq!(
        grant.destinations().collect::<Vec<_>>(),
        vec![ReleaseDestination::OrdinarySource]
    );
}

#[test]
fn no_generic_reveal_or_declassification_is_reachable_by_any_holder() {
    let holder = sealed(ProtectedDataClass::SourceText, "crate::holder");
    let mut budget = disclosure_budget(1, 1);
    let declared_site = site(
        ProtectedDataClass::SourceText,
        ReleaseDestination::OrdinarySource,
    );
    let refused = declared_site.release(
        &withholding_authority().grant(),
        &holder,
        ReleaseDestination::OrdinarySource,
        &mut budget,
    );
    assert_eq!(
        refused.decision(),
        ReleaseDecision::Rejected(ReleaseRejection::ClassMismatch)
    );
    assert!(refused.projection().is_none());
    assert!(refused.released_value().is_none());
    assert!(refused.audit_view(&AuditAccess::granted()).is_none());
    assert_eq!(budget.accepted(), 0);
    assert!(holder.is_protected());
    assert_eq!(holder.class(), ProtectedDataClass::SourceText);
    assert!(!holder.id().as_str().contains("crate::holder"));
    let operation_site = site(
        ProtectedDataClass::ActionArgument,
        ReleaseDestination::OrdinarySource,
    );
    assert_eq!(
        operation_site
            .release(
                &withholding_authority().grant(),
                &value(ProtectedDataClass::ActionArgument),
                ReleaseDestination::OrdinarySource,
                &mut budget,
            )
            .decision(),
        ReleaseDecision::Rejected(ReleaseRejection::ClassMismatch)
    );
    assert_eq!(budget.accepted(), 0);
    assert_eq!(
        budget.remaining(),
        1,
        "no holder revealed or declassified a value without a declared release"
    );
}
