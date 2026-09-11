//! Unit-level checks of the protected-value, release, cleanup, and non-erasure
//! model.
//!
//! These tests check the pure model of the parent module directly. The
//! conformance evidence for `GNT-15.10-protected-values`, `GNT-15.10-semantic-envelope`,
//! `GNT-15.10-release-operation`, `GNT-15.10-emergency-cleanup`, and
//! `GNT-15.10-protection-invariants` lives in
//! `crates/gantry-conformance/tests/protected_release.rs`.

use super::*;

use crate::TypeExpression;
use crate::generic::CanonicalImplementationIdentity;
use crate::type_properties::{RecoveryProjectionClass, SourceProtectionClass};

/// Compile-time proof that one type implements none of the listed traits.
///
/// A blanket implementation and a trait-bounded implementation both apply, so
/// naming the associated item requires an inference that cannot be resolved and
/// compilation fails. A protected channel that acquired `Debug`, `Display`,
/// `PartialEq`, `Eq`, `Hash`, `PartialOrd`, or `Ord` would stop this crate
/// compiling.
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
fn protected_value(class: ProtectedDataClass) -> ProtectedValue {
    ProtectedValue::seal(class, fixture_origin("crate::integration"))
}

/// Returns one nonzero fixture disclosure charge.
fn fixture_charge(value: u64) -> DisclosureCharge {
    DisclosureCharge::new(value).unwrap_or_else(|| unreachable!("fixture charge is nonzero"))
}

/// Creates one fixture disclosure budget.
fn fixture_budget(remaining: u64, charge_value: u64) -> DisclosureBudget {
    DisclosureBudget::new(remaining, fixture_charge(charge_value))
}

/// Builds one release site declaring exactly one pair.
fn release_site(class: ProtectedDataClass, destination: ReleaseDestination) -> ReleaseSite {
    ReleaseSite::new("crate::release").declare(class, destination, ProjectionKind::Redacted)
}

/// Builds the downstream integration identity of the fixture holder.
fn fixture_integration() -> CanonicalImplementationIdentity {
    let receiver = TypeExpression::from_canonical_string("crate::ProtectedFixture", 4)
        .unwrap_or_else(|_| unreachable!("fixture receiver is a canonical type"));
    CanonicalImplementationIdentity::inherent(&receiver)
}

/// Binds one holder authority over the fixture site with the named permission.
fn holder_authority(
    classes: &[ProtectedDataClass],
    destinations: &[ReleaseDestination],
) -> ReleaseHolderAuthority {
    let site = fixture_name("crate::release");
    let binding = ReleaseHolderBindingId::new(&site, &fixture_integration());
    ReleaseHolderAuthority::bind(&site, binding, classes, destinations)
        .unwrap_or_else(|_| unreachable!("the fixture binding names its own site"))
}

/// Binds one holder authority that may release nothing.
fn withholding_authority() -> ReleaseHolderAuthority {
    holder_authority(&[], &[])
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
    assert_not_impl_any!(ProtectedValue: std::fmt::Debug, std::fmt::Display, PartialEq);
    let sealed = protected_value(ProtectedDataClass::SourceText);
    assert!(sealed.is_protected());
    assert!(!sealed.is_external_value());
    assert_eq!(sealed.class(), ProtectedDataClass::SourceText);
    assert_eq!(sealed.protection_class(), SourceProtectionClass::Sealed);
    assert_eq!(
        sealed.recovery_projection(),
        RecoveryProjectionClass::SealedValue
    );
}

#[test]
fn ordinary_observations_of_a_protected_value_are_unreachable() {
    assert_not_impl_any!(
        ProtectedValue: std::fmt::Debug,
        std::fmt::Display,
        PartialEq,
        Eq,
        std::hash::Hash,
        PartialOrd,
        Ord
    );
    let first = ProtectedValue::seal(
        ProtectedDataClass::SourceText,
        fixture_origin("crate::boundary-one"),
    );
    let second = ProtectedValue::seal(
        ProtectedDataClass::SourceText,
        fixture_origin("crate::boundary-two"),
    );
    assert_ne!(first.id(), second.id());
    assert!(!first.id().as_str().contains("crate::boundary-one"));
    assert!(first.id().as_str().starts_with("protected:"));
    assert_eq!(first.id().digest_hex().len(), 64);
}

#[test]
fn payload_like_provenance_is_rejected_and_identity_is_payload_independent() {
    let rejected = [
        (
            "{\"payload\":\"secret\"}",
            DeclaredNameRejection::NonCanonicalCharacter,
        ),
        ("session 7", DeclaredNameRejection::ControlOrWhitespace),
        ("line\nbreak", DeclaredNameRejection::ControlOrWhitespace),
        ("non-ascii-\u{e9}", DeclaredNameRejection::NonAscii),
        ("", DeclaredNameRejection::Empty),
    ];
    for (payload_like, rejection) in rejected {
        assert_eq!(
            ProvenanceOrigin::new(ProvenanceOriginKind::IntegrationBoundary, payload_like).err(),
            Some(rejection),
            "a payload-like or non-canonical name is rejected as provenance"
        );
    }
    assert_eq!(
        DeclaredNameRejection::NonCanonicalCharacter.wire_name(),
        "non-canonical-character"
    );
    let over_long = "a".repeat(DECLARED_NAME_LIMIT + 1);
    assert_eq!(
        ProvenanceOrigin::new(ProvenanceOriginKind::IntegrationBoundary, &over_long).err(),
        Some(DeclaredNameRejection::TooLong)
    );
    let first = ProtectedValue::seal(
        ProtectedDataClass::NormalizedValue,
        fixture_origin("crate::integration"),
    );
    let second = ProtectedValue::seal(
        ProtectedDataClass::NormalizedValue,
        fixture_origin("crate::integration"),
    );
    assert_eq!(
        first.id(),
        second.id(),
        "identity is stable across payload differences"
    );
    assert_ne!(
        first.id(),
        ProtectedValue::seal(
            ProtectedDataClass::NormalizedValue,
            fixture_origin("crate::other")
        )
        .id()
    );
    assert_ne!(
        first.id(),
        ProtectedValue::seal(
            ProtectedDataClass::JournalRecord,
            fixture_origin("crate::integration")
        )
        .id()
    );
    assert!(!first.id().as_str().contains("crate::integration"));
}

#[test]
fn protection_preserving_transformations_keep_dependent_outputs_protected() {
    let transform = ProtectionPreservingTransform::declare(
        ProtectedDataClass::SourceText,
        ProtectedDataClass::NormalizedValue,
        ProjectionKind::Verbatim,
        complete_envelope(),
    )
    .unwrap_or_else(|_| unreachable!("a complete envelope declares a transformation"));
    assert_eq!(transform.input(), ProtectedDataClass::SourceText);
    assert_eq!(transform.output(), ProtectedDataClass::NormalizedValue);
    assert_eq!(transform.projection(), ProjectionKind::Verbatim);
    assert!(transform.envelope().is_complete());
    let consumed = protected_value(ProtectedDataClass::SourceText);
    let output = transform
        .apply(&consumed)
        .unwrap_or_else(|| unreachable!("the declared input class is consumed"));
    assert!(output.is_protected());
    assert_eq!(output.class(), ProtectedDataClass::NormalizedValue);
    assert_eq!(output.protection_class(), SourceProtectionClass::Sealed);
    assert_ne!(output.id(), consumed.id());
    assert!(
        transform
            .apply(&protected_value(ProtectedDataClass::EntryInput))
            .is_none()
    );
}

#[test]
fn protection_preserving_declarations_refuse_an_incomplete_envelope() {
    let mut incomplete = SemanticEnvelope::new();
    for observation in ENVELOPE_OBSERVATION_ORDER {
        if observation != EnvelopeObservation::OutputSize {
            incomplete = incomplete.classify(observation, EnvelopeClause::Protected);
        }
    }
    let refused = ProtectionPreservingTransform::declare(
        ProtectedDataClass::SourceText,
        ProtectedDataClass::NormalizedValue,
        ProjectionKind::Verbatim,
        incomplete,
    );
    let Err(rejection) = refused else {
        unreachable!("a declaration that omits a consequence is refused")
    };
    assert_eq!(rejection.unclassified().len(), 1);
    assert_eq!(rejection.unclassified()[0], EnvelopeObservation::OutputSize);
    let empty_envelope = SemanticEnvelope::new();
    assert_eq!(
        empty_envelope.effective(EnvelopeObservation::OutputSize),
        EnvelopeClause::Protected,
        "an unclassified consequence is treated as protected, never as ordinary"
    );
    assert!(
        ProtectionPreservingTransform::declare(
            ProtectedDataClass::SourceText,
            ProtectedDataClass::NormalizedValue,
            ProjectionKind::Verbatim,
            empty_envelope,
        )
        .is_err()
    );
}

#[test]
fn layer_one_readability_does_not_imply_inspectability() {
    let inspection = protected_value(ProtectedDataClass::SessionIdentifier).layer_one_inspection();
    assert_eq!(inspection.layer(), 1);
    assert!(inspection.readable_by_source());
    assert!(!inspection.inspectable_by_source());
}

#[test]
fn grants_are_derived_only_from_holder_authority() {
    assert_not_impl_any!(ReleaseGrant: Default);
    assert_not_impl_any!(ReleaseHolderAuthority: Default);
    let authority = holder_authority(
        &[ProtectedDataClass::SourceText],
        &[ReleaseDestination::OrdinarySource],
    );
    let grant = authority.grant();
    assert_eq!(grant.holder(), authority.id());
    assert!(grant.covers(
        ProtectedDataClass::SourceText,
        ReleaseDestination::OrdinarySource
    ));
    assert_eq!(grant.class_count(), 1);
    assert_eq!(grant.destination_count(), 1);
    assert!(!grant.is_empty());
    let withholding = withholding_authority();
    assert!(withholding.is_empty());
    assert!(withholding.grant().is_empty());
    assert_eq!(withholding.grant().class_count(), 0);
    assert_eq!(withholding.grant().destination_count(), 0);
    assert_ne!(withholding.id(), authority.id());
    assert!(withholding.id().as_str().starts_with("release-holder:"));
    assert_eq!(withholding.id().digest_hex().len(), 64);
    assert_eq!(withholding.site(), "crate::release");
    let other_site = fixture_name("crate::other");
    let foreign_binding = ReleaseHolderBindingId::new(&other_site, &fixture_integration());
    assert_eq!(
        ReleaseHolderAuthority::bind(&fixture_name("crate::release"), foreign_binding, &[], &[])
            .err(),
        Some(ReleaseAuthorityError::SiteMismatch)
    );
    assert_eq!(
        ReleaseAuthorityError::SiteMismatch.wire_name(),
        "site-mismatch"
    );
}

#[test]
fn attenuation_of_authority_only_removes_permission() {
    let wide = holder_authority(
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
    assert!(narrow.grant().covers(
        ProtectedDataClass::SourceText,
        ReleaseDestination::OrdinarySource
    ));
    assert!(!narrow.grant().covers(
        ProtectedDataClass::ActionArgument,
        ReleaseDestination::OrdinarySource
    ));
    assert_ne!(narrow.id(), wide.id());
    assert_eq!(narrow.site(), wide.site());
    let widening = narrow.attenuate(
        &[ProtectedDataClass::ActionArgument],
        &[ReleaseDestination::ProviderModel],
    );
    assert!(widening.grant().is_subset_of(&narrow.grant()));
    assert!(widening.is_empty());
    assert!(
        narrow
            .grant()
            .attenuate(&wide.grant())
            .is_subset_of(&narrow.grant())
    );
    assert!(
        wide.grant()
            .attenuate(&narrow.grant())
            .is_subset_of(&wide.grant())
    );
}

#[test]
fn release_requires_authority_class_and_destination_independently() {
    let mut budget = fixture_budget(4, 1);
    let protected = protected_value(ProtectedDataClass::ActionArgument);
    let site = release_site(
        ProtectedDataClass::ActionArgument,
        ReleaseDestination::DiagnosticSink,
    );
    let destinations_only = holder_authority(&[], &[ReleaseDestination::DiagnosticSink]);
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
    let classes_only = holder_authority(&[ProtectedDataClass::ActionArgument], &[]);
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
    let undeclaring_site = ReleaseSite::new("crate::other");
    let granting = holder_authority(
        &[ProtectedDataClass::ActionArgument],
        &[ReleaseDestination::DiagnosticSink],
    );
    assert_eq!(
        undeclaring_site
            .release(
                &granting.grant(),
                &protected,
                ReleaseDestination::DiagnosticSink,
                &mut budget,
            )
            .decision(),
        ReleaseDecision::Rejected(ReleaseRejection::ClassMismatch)
    );
    assert!(!withholding_authority().grant().covers(
        ProtectedDataClass::ActionArgument,
        ReleaseDestination::DiagnosticSink
    ));
    assert_eq!(
        budget.remaining(),
        4,
        "no rejected release charged the budget"
    );
    assert_eq!(budget.accepted(), 0);
}

#[test]
fn disclosure_budget_is_monotone_and_exhausts_deterministically() {
    assert_eq!(
        DisclosureCharge::new(0),
        None,
        "a zero charge is not constructible"
    );
    assert_eq!(fixture_charge(3).value(), 3);
    let site = release_site(
        ProtectedDataClass::SourceText,
        ReleaseDestination::OrdinarySource,
    );
    let grant = holder_authority(
        &[ProtectedDataClass::SourceText],
        &[ReleaseDestination::OrdinarySource],
    )
    .grant();
    let mut budget = fixture_budget(2, 1);
    let mut trail = Vec::new();
    let mut decisions = Vec::new();
    for origin_name in ["crate::first", "crate::second", "crate::third"] {
        let outcome = site.release(
            &grant,
            &ProtectedValue::seal(ProtectedDataClass::SourceText, fixture_origin(origin_name)),
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
    assert_eq!(fixture_budget(0, 1).after_charge(), None);
    assert!(fixture_budget(0, 1).is_exhausted());
}

#[test]
fn audit_evidence_is_capability_gated_and_unrenderable() {
    assert_not_impl_any!(
        ReleaseAuditEvidence: std::fmt::Debug,
        std::fmt::Display,
        std::hash::Hash
    );
    assert_not_impl_any!(ReleaseOutcome: std::fmt::Debug, std::fmt::Display);
    let mut budget = fixture_budget(3, 1);
    let site = ReleaseSite::new("crate::release").declare(
        ProtectedDataClass::SessionIdentifier,
        ReleaseDestination::ProtectedJournal,
        ProjectionKind::Redacted,
    );
    let granting = holder_authority(
        &[ProtectedDataClass::SessionIdentifier],
        &[ReleaseDestination::ProtectedJournal],
    );
    let outcome = site.release(
        &granting.grant(),
        &ProtectedValue::seal(
            ProtectedDataClass::SessionIdentifier,
            fixture_origin("crate::session-holder"),
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
    assert!(text.contains("outcome=accepted"));
    assert!(!text.contains("crate::session-holder"));
    assert_eq!(AuditOutcome::Accepted.wire_name(), "accepted");
    let refused = release_site(
        ProtectedDataClass::SourceText,
        ReleaseDestination::OrdinarySource,
    )
    .release(
        &withholding_authority().grant(),
        &protected_value(ProtectedDataClass::SourceText),
        ReleaseDestination::OrdinarySource,
        &mut fixture_budget(2, 1),
    );
    assert!(refused.audit_view(&access).is_none());
}

#[test]
fn accepted_release_produces_an_ordinary_value() {
    let site = release_site(
        ProtectedDataClass::SourceText,
        ReleaseDestination::OrdinarySource,
    );
    let grant = holder_authority(
        &[ProtectedDataClass::SourceText],
        &[ReleaseDestination::OrdinarySource],
    )
    .grant();
    let mut budget = fixture_budget(2, 1);
    let refused = site.release(
        &withholding_authority().grant(),
        &protected_value(ProtectedDataClass::SourceText),
        ReleaseDestination::OrdinarySource,
        &mut budget,
    );
    assert!(
        refused.released_value().is_none(),
        "no ordinary value exists before acceptance"
    );
    assert!(refused.projection().is_none());
    let accepted = site.release(
        &grant,
        &protected_value(ProtectedDataClass::SourceText),
        ReleaseDestination::OrdinarySource,
        &mut budget,
    );
    let released = accepted
        .released_value()
        .unwrap_or_else(|| unreachable!("an accepted release produces an ordinary value"));
    assert!(released.is_ordinary());
    assert!(!released.is_protected());
    assert_eq!(released.class(), ProtectedDataClass::SourceText);
    assert_eq!(released.destination(), ReleaseDestination::OrdinarySource);
    assert_eq!(released.kind(), ProjectionKind::Redacted);
    assert_eq!(
        released.projection().destination(),
        ReleaseDestination::OrdinarySource
    );
}

#[test]
fn transport_delivery_denials_are_separate_from_release_rejections() {
    let sink = ReleaseDestination::DiagnosticSink;
    let value = protected_value(ProtectedDataClass::SourceText);
    let site = release_site(ProtectedDataClass::SourceText, sink);
    let granting = holder_authority(&[ProtectedDataClass::SourceText], &[sink]);
    let mut budget = fixture_budget(4, 1);
    let accepted = site.release(&granting.grant(), &value, sink, &mut budget);
    let denying = FrozenDeliveryPermission::frozen(sink, &[ProtectedDataClass::JournalRecord]);
    assert_eq!(
        denying.deliver(&accepted, &value, sink),
        DeliveryDecision::Denied(DeliveryDenial::FrozenPermissionDenies)
    );
    let admitting = FrozenDeliveryPermission::frozen(sink, &[ProtectedDataClass::SourceText]);
    let refused = site.release(&withholding_authority().grant(), &value, sink, &mut budget);
    assert_eq!(
        refused.decision(),
        ReleaseDecision::Rejected(ReleaseRejection::ClassMismatch)
    );
    assert_eq!(
        admitting.deliver(&refused, &value, sink),
        DeliveryDecision::Denied(DeliveryDenial::NoAcceptedRelease)
    );
    assert_eq!(
        admitting.deliver(&accepted, &value, ReleaseDestination::OrdinarySource),
        DeliveryDecision::Denied(DeliveryDenial::DestinationWidened)
    );
    let wider = FrozenDeliveryPermission::frozen(
        ReleaseDestination::OrdinarySource,
        &[ProtectedDataClass::SourceText],
    );
    assert_eq!(
        wider.deliver(&accepted, &value, ReleaseDestination::OrdinarySource),
        DeliveryDecision::Denied(DeliveryDenial::DestinationWidened)
    );
    assert_eq!(
        admitting.deliver(&accepted, &value, sink),
        DeliveryDecision::Delivered
    );
    assert!(admitting.deliver(&accepted, &value, sink).is_delivered());
    assert!(admitting.deliver(&refused, &value, sink).denial().is_some());
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

/// Runs one cleanup over one freshly sealed value per named class.
fn cleanup_report(cleanup: EmergencyCleanup, classes: &[ProtectedDataClass]) -> CleanupReport {
    let values = classes
        .iter()
        .copied()
        .map(protected_value)
        .collect::<Vec<_>>();
    cleanup.run(&values.iter().collect::<Vec<_>>())
}

#[test]
fn cleanup_reports_publish_no_consumed_count() {
    let cleanup = EmergencyCleanup::sealed(fixture_budget(8, 1), 8);
    let first = cleanup_report(
        cleanup,
        &[
            ProtectedDataClass::SourceText,
            ProtectedDataClass::JournalRecord,
            ProtectedDataClass::NamedInput,
        ],
    );
    let second = cleanup_report(
        cleanup,
        &[
            ProtectedDataClass::DecisionRationale,
            ProtectedDataClass::DeclineReason,
            ProtectedDataClass::HookFailureMessage,
        ],
    );
    assert_eq!(
        first, second,
        "two cleanups over different classes and different values produce identical reports"
    );
    assert_eq!(first.outcome(), CleanupOutcome::Completed);
    assert!(!first.callbacks_invoked());
    assert!(!first.source_semantics_changed());
    assert!(first.durable_prefix_only());
    let longer = cleanup_report(
        cleanup,
        &[
            ProtectedDataClass::SourceText,
            ProtectedDataClass::JournalRecord,
            ProtectedDataClass::NamedInput,
            ProtectedDataClass::DecisionRationale,
            ProtectedDataClass::DeclineReason,
        ],
    );
    assert_eq!(
        first, longer,
        "the report publishes neither the number nor the distribution of consumed values"
    );
    let bounded = EmergencyCleanup::sealed(fixture_budget(8, 1), 2);
    assert_eq!(
        cleanup_report(
            bounded,
            &[
                ProtectedDataClass::SourceText,
                ProtectedDataClass::JournalRecord,
                ProtectedDataClass::NamedInput,
            ],
        ),
        cleanup_report(
            bounded,
            &[
                ProtectedDataClass::JournalRecord,
                ProtectedDataClass::NamedInput,
                ProtectedDataClass::EntryInput,
                ProtectedDataClass::ActionArgument,
            ],
        )
    );
    assert_eq!(
        cleanup_report(bounded, &[ProtectedDataClass::SourceText]).outcome(),
        CleanupOutcome::Completed
    );
    let interrupted = EmergencyCleanup::interrupted();
    assert_eq!(interrupted.outcome(), CleanupOutcome::Interrupted);
    assert!(interrupted.durable_prefix_only());
    assert_eq!(CleanupOutcome::Refused.wire_name(), "refused");
    assert_eq!(cleanup.destination(), ReleaseDestination::NullTelemetry);
    assert!(cleanup.destination().is_null());
    assert!(!cleanup.accepts_source_callback());
    assert!(!cleanup.declassifies());
    assert!(!cleanup.extends_authority());
    assert_eq!(cleanup.work_limit(), 8);
    assert_eq!(cleanup.run(&[]).outcome(), CleanupOutcome::Completed);
}

#[test]
fn cleanup_is_refused_deterministically_without_a_zero_charge() {
    let exhausted = EmergencyCleanup::sealed(fixture_budget(0, 1), 8);
    assert!(fixture_budget(0, 1).is_exhausted());
    assert_eq!(
        cleanup_report(exhausted, &[ProtectedDataClass::SourceText]),
        CleanupReport::settled(CleanupOutcome::Refused)
    );
    assert_eq!(
        cleanup_report(
            exhausted,
            &[
                ProtectedDataClass::DeclineReason,
                ProtectedDataClass::JournalRecord,
            ],
        ),
        CleanupReport::settled(CleanupOutcome::Refused),
        "exhaustion is deterministic in the ordinary accounting alone"
    );
}

#[test]
fn unproven_obligations_are_never_reported_safe() {
    let open = NonErasureObligation::open(NonErasureComponentKind::Codec, "crate::codec");
    assert_eq!(open.status(), NonErasureStatus::Unproven);
    assert!(!open.is_reported_safe());
    assert!(!open.status().is_proven());
    assert!(open.evidence().is_empty());
    assert_eq!(open.kind(), NonErasureComponentKind::Codec);
    assert_eq!(open.subject(), "crate::codec");
    let claiming = NonErasureObligation::protection_preserving(
        NonErasureComponentKind::Diagnostic,
        "crate::diagnostic",
    );
    assert!(
        !claiming.is_reported_safe(),
        "an unproven component is never reported safe"
    );
    assert!(
        !claiming.with_evidence("").is_reported_safe(),
        "an empty anchor is not evidence"
    );
    assert!(
        NonErasureObligation::not_applicable(NonErasureComponentKind::Event, "crate::event", "")
            .is_none()
    );
    let justified = NonErasureObligation::not_applicable(
        NonErasureComponentKind::Event,
        "crate::event",
        "carries ordinary event metadata only",
    )
    .unwrap_or_else(|| unreachable!("the ordinary-data case declares its justification"));
    assert_eq!(
        justified.justification(),
        Some("carries ordinary event metadata only")
    );
    assert!(
        !justified.is_reported_safe(),
        "a justification without evidence stays unproven"
    );
    let proven = justified.with_evidence(
        "crates/gantry-conformance/tests/protected_release.rs#non_erasure_is_a_negative_evidence_obligation",
    );
    assert_eq!(proven.status(), NonErasureStatus::NotApplicable);
    assert!(proven.is_reported_safe());
    assert_eq!(proven.evidence().len(), 1);
    let unreachable_with_a_value = NonErasureObligation::unreachable(
        NonErasureComponentKind::GeneratedSchema,
        "protocol/schemas",
    )
    .with_evidence("crate::schema::tests#no_protected_wire_field");
    assert_eq!(
        unreachable_with_a_value.status(),
        NonErasureStatus::UnreachableWithProtectedValue
    );
    for kind in NON_ERASURE_COMPONENT_ORDER {
        assert_eq!(
            NonErasureComponentKind::from_wire_name(kind.wire_name()),
            Some(kind)
        );
    }
    assert_eq!(NonErasureComponentKind::from_wire_name("unspecified"), None);
    assert_eq!(NonErasureStatus::Unproven.wire_name(), "unproven");
}

#[test]
fn excluded_claims_mirror_two_unpromised_properties_and_two_prohibitions() {
    assert_eq!(EXCLUDED_PROTECTION_CLAIMS.len(), 4);
    let not_promised = EXCLUDED_PROTECTION_CLAIMS
        .iter()
        .filter(|claim| claim.is_not_promised())
        .collect::<Vec<_>>();
    let prohibited = EXCLUDED_PROTECTION_CLAIMS
        .iter()
        .filter(|claim| claim.is_prohibited())
        .collect::<Vec<_>>();
    assert_eq!(not_promised.len(), 2);
    assert_eq!(prohibited.len(), 2);
    assert_eq!(
        not_promised[0].wire_name(),
        "full-noninterference-after-release"
    );
    assert_eq!(not_promised[1].wire_name(), "physical-side-channels");
    assert_eq!(prohibited[0].wire_name(), "implicit-declassification");
    assert_eq!(prohibited[1].wire_name(), "authority-is-release-authority");
    assert_eq!(
        prohibited[0].name(),
        ExcludedProtectionClaimName::ImplicitDeclassification
    );
    assert_eq!(
        prohibited[1].name(),
        ExcludedProtectionClaimName::AuthorityIsReleaseAuthority
    );
    assert_eq!(prohibited[0].kind(), ExcludedClaimKind::Prohibited);
    assert_eq!(not_promised[0].kind(), ExcludedClaimKind::NotPromised);
    for claim in prohibited {
        assert!(!claim.is_not_promised());
    }
    assert_eq!(ExcludedClaimKind::Prohibited.wire_name(), "prohibited");
    assert_eq!(ExcludedClaimKind::NotPromised.wire_name(), "not-promised");
}
