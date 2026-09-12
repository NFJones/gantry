//! Machine-checked conformance for the pure approval model of `GNT-19.0` through
//! `GNT-19.10-approval-audit-evidence`.
//!
//! These tests exercise the public `gantry::ir` surface of the approval model
//! together with the landed authority model of `GNT-3-T-AUTHORITY-LINEAGE`,
//! `GNT-3-T-AUTHORITY-REVOCATION` and `GNT-3-T-AUTHORITY-ADMISSION` and the landed
//! protected-value model of `GNT-15.10-protected-values` and
//! `GNT-15.10-release-operation`. They check the model the specification makes
//! normative, not a runtime approval store: no test here observes an approver, a
//! live sink, a provider, a host service, a clock, a locale, a filesystem, or a
//! protected payload.
//!
//! Where a negative property is a compile-time statement about the surface, the
//! test asserts it with the trait-ambiguity proof below rather than with a runtime
//! probe: a constructor from a host path, an environment value, a clock, or a
//! locale, a deserializer for a request identity, a cache of decisions, or a
//! conversion from an authority right into release authority would all stop this
//! crate compiling.

use std::fmt::{Debug, Display};

use gantry::ir::generated::{Effect, RecoveryClass};
use gantry::ir::{
    AUTHORITY_RIGHT_ORDER, Admission, AdmissionRequest, AncestorFences, ApprovalAuditAccess,
    ApprovalAuditEvidence, ApprovalDecision, ApprovalDiagnosticCode, ApprovalError,
    ApprovalOutcome, ApprovalOutcomeRecord, ApprovalRequestId, ApprovalSubject,
    ApprovalSubjectInputs, ApproverPresentation, AttemptApplicability, AuditTransition,
    AuditTransitionKind, AuthenticatedActor, AuthorityBindingId, AuthorityError,
    AuthorityGeneration, AuthorityInstance, AuthorityLeasePolicy, AuthorityRequirementId,
    AuthorityRight, CanonicalCallableIdentity, CanonicalImplementationIdentity, CanonicalPath,
    CanonicalSignature, CommitPointResult, DecisionConstraints, DecisionScope, DeclaredName,
    DisclosureBudget, DisclosureCharge, DurableApprovalCut, DurableApprovalRecord, EffectSet,
    ExternalOutcome, ExternalTargetRef, FenceCategory, FenceReason, HostAttestationBindingId,
    HostAttestationKind, HostAuthorityDigest, LeaseScope, LogicalExecutionId, LogicalOperationId,
    MappingRevision, PolicyRevision, ProjectionKind, ProtectedDataClass, ProtectedReviewChannel,
    ProtectedScope, ProtectedValue, ProvenanceOrigin, ProvenanceOriginKind, RefusalReason,
    ReleaseDecision, ReleaseDestination, ReleaseGrant, ReleaseHolderAuthority,
    ReleaseHolderBindingId, ReleaseRejection, ReleaseSite, ResumeClass, Revalidation,
    RevocationContract, RightsSet, SealedPredicate, SemanticArgumentDigest, StalenessReason,
    StandingLease, StaticSiteId, StructuralPosition, TargetFactsDigest, TypeDescriptor,
    TypeExpression, revalidate,
};
use sha2::{Digest, Sha256};

/// Compile-time proof that one type implements none of the listed traits.
///
/// A blanket implementation and a trait-bounded implementation both apply, so
/// naming the associated item requires an inference that cannot be resolved and
/// compilation fails. A constructor from a host path, an environment value, a
/// clock, or a locale, a deserializer for a request identity or a decision, a
/// second request identity for one operation, and a conversion from authority
/// rights or an admission request into release authority would each stop this
/// crate compiling, which is exactly what `GNT-19.2-approval-subject`,
/// `GNT-19.3-authenticated-approver-identity`, `GNT-19.5-decision-scope-and-standing-authority`,
/// `GNT-19.7-durable-request-and-decision-cuts` and
/// `GNT-19.9-execution-and-release-separation` forbid.
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

/// The declared release site of every approval fixture.
const SITE: &str = "crate::approval-release";

/// The capability family used by every authority fixture.
const FAMILY: &str = "action";

/// Returns one deterministic lowercase hexadecimal digest of one seed.
fn hex(seed: &str) -> String {
    format!("{:x}", Sha256::digest(seed.as_bytes()))
}

/// Builds one canonical fixture path.
fn path(value: &str) -> CanonicalPath {
    CanonicalPath::new(value).unwrap_or_else(|_| unreachable!("fixture path is canonical"))
}

/// Validates one canonical fixture declared name.
fn name(value: &str) -> DeclaredName {
    DeclaredName::new(value).unwrap_or_else(|_| unreachable!("fixture name is a declared name"))
}

/// Decodes one exact fixture digest.
fn digest<T>(value: &str, decode: impl Fn(&str) -> Result<T, ApprovalError>) -> T {
    decode(value).unwrap_or_else(|_| unreachable!("fixture digest is lowercase hexadecimal"))
}

/// Builds one fixture semantic-argument digest.
fn arguments(seed: &str) -> SemanticArgumentDigest {
    digest(&hex(seed), SemanticArgumentDigest::from_hex)
}

/// Builds one fixture mapping revision.
fn mapping(seed: &str) -> MappingRevision {
    digest(&hex(seed), MappingRevision::from_hex)
}

/// Builds one fixture effective policy revision.
fn policy(seed: &str) -> PolicyRevision {
    digest(&hex(seed), PolicyRevision::from_hex)
}

/// Builds the downstream integration identity of every fixture.
fn integration() -> CanonicalImplementationIdentity {
    let receiver = TypeExpression::from_canonical_string("crate::ApprovalFixture", 4)
        .unwrap_or_else(|_| unreachable!("fixture receiver is a canonical type"));
    CanonicalImplementationIdentity::inherent(&receiver)
}

/// Builds the canonical action signature of the fixture requirement.
fn signature() -> CanonicalSignature {
    CanonicalSignature::action(
        RecoveryClass::ReadOnly,
        &path("crate::read_only"),
        &[],
        &TypeDescriptor::STRING,
    )
}

/// Builds the public capability requirement of one fixture family.
fn requirement(family: &str) -> AuthorityRequirementId {
    AuthorityRequirementId::new(
        &path("crate::read_only"),
        &signature(),
        family,
        RecoveryClass::ReadOnly,
    )
    .unwrap_or_else(|_| unreachable!("fixture family is portable"))
}

/// Binds one capability instance carrying exactly the named rights.
fn instance_with(rights: &[AuthorityRight], lease: AuthorityLeasePolicy) -> AuthorityInstance {
    let requirement = requirement(FAMILY);
    let binding = AuthorityBindingId::new(&requirement, &integration());
    AuthorityInstance::bind(
        requirement,
        binding,
        RightsSet::from_rights(rights),
        lease,
        false,
    )
    .unwrap_or_else(|_| unreachable!("the fixture binding satisfies its requirement"))
}

/// Binds one unleased capability instance carrying exactly the named rights.
fn instance(rights: &[AuthorityRight]) -> AuthorityInstance {
    instance_with(rights, AuthorityLeasePolicy::Unleased)
}

/// Builds one exact operation site of the fixture workflow.
fn site(components: &[u64]) -> StaticSiteId {
    let position = StructuralPosition::new(components.to_vec())
        .unwrap_or_else(|_| unreachable!("fixture structural position is nonempty"));
    StaticSiteId::new(path("crate::workflow"), position)
}

/// Derives one stable logical operation identity.
fn operation_id(declaration: &str, components: &[u64]) -> LogicalOperationId {
    LogicalOperationId::derive(&path(declaration), &site(components))
}

/// Derives one logical-execution identity.
fn execution(label: &str) -> LogicalExecutionId {
    let entry = CanonicalCallableIdentity::free(&path("crate::entry"), &[]);
    LogicalExecutionId::derive(&entry, &name(label))
}

/// Builds the fixture task identity.
fn task() -> CanonicalCallableIdentity {
    CanonicalCallableIdentity::free(&path("crate::task"), &[])
}

/// Builds one fixture external target reference.
fn target() -> ExternalTargetRef {
    ExternalTargetRef::new(
        integration(),
        TargetFactsDigest::from_hex(&hex("target-facts"))
            .unwrap_or_else(|_| unreachable!("fixture target digest is lowercase hexadecimal")),
    )
}

/// Builds one fixture effect summary.
fn effects() -> EffectSet {
    let mut effects = EffectSet::default();
    effects.insert(Effect::ActionReadOnly);
    effects
}

/// Returns one nonzero fixture disclosure charge.
fn charge(value: u64) -> DisclosureCharge {
    DisclosureCharge::new(value).unwrap_or_else(|| unreachable!("fixture charge is nonzero"))
}

/// Builds the protected scope of every fixture operation.
fn scope() -> ProtectedScope {
    ProtectedScope::new(
        ProjectionKind::Redacted,
        ProtectedDataClass::ActionArgument,
        ReleaseDestination::OrdinarySource,
        charge(1),
    )
}

/// Binds one one-shot decision scope naming one logical operation identity.
fn constraints(operation: &LogicalOperationId, expires_at_us: u64) -> DecisionConstraints {
    DecisionConstraints::new(
        DecisionScope::OneShot {
            operation: operation.clone(),
        },
        expires_at_us,
        AttemptApplicability::RecoveryPolicy,
    )
    .unwrap_or_else(|_| unreachable!("a one-shot decision has no lease to outlive"))
}

/// Establishes the host-attested actor of every fixture decision.
fn actor() -> AuthenticatedActor {
    let authority = digest(&hex("host-authority"), HostAuthorityDigest::from_hex);
    let binding = HostAttestationBindingId::new(HostAttestationKind::HostSession, authority);
    AuthenticatedActor::attest(
        &binding,
        &name("requester-bob"),
        &name("approver-alice"),
        &name("tenant-acme"),
        &name("policy-release"),
    )
}

/// Builds the complete canonical input record of one fixture subject.
fn base_inputs(operation: &LogicalOperationId) -> ApprovalSubjectInputs {
    let holder = instance(&AUTHORITY_RIGHT_ORDER);
    ApprovalSubjectInputs::default()
        .with_execution(execution("primary"))
        .with_task(task())
        .with_declaration(path("crate::read_only"))
        .with_site(site(&[0, 1]))
        .with_operation(operation.clone())
        .with_arguments(arguments("arguments"))
        .with_presentation(ApproverPresentation::Faithful)
        .with_requirement(requirement(FAMILY))
        .with_instance(holder.id().clone())
        .with_generation(holder.generation())
        .with_lineage(holder.lineage_record())
        .with_mapping(mapping("mapping"))
        .with_policy(policy("policy"))
        .with_recovery(RecoveryClass::ReadOnly)
        .with_target(target())
        .with_effects(effects())
        .with_scope(scope())
        .with_constraints(constraints(operation, 100))
}

/// Builds one complete fixture subject.
fn subject_of(operation: &LogicalOperationId) -> ApprovalSubject {
    base_inputs(operation)
        .build()
        .unwrap_or_else(|_| unreachable!("the fixture subject is complete"))
}

/// Builds one fixture subject from one mutated input record.
fn build(inputs: ApprovalSubjectInputs) -> ApprovalSubject {
    inputs
        .build()
        .unwrap_or_else(|_| unreachable!("the mutated fixture subject is complete"))
}

/// Builds one positive one-shot decision over one fixture subject.
fn decision(subject: &ApprovalSubject) -> ApprovalDecision {
    ApprovalDecision::new(
        subject.clone(),
        ApprovalOutcome::PositiveDecision,
        &actor(),
        0,
        None,
    )
    .unwrap_or_else(|_| unreachable!("a one-shot decision needs no lease"))
}

/// Builds one admission request against one fixture generation.
fn request(generation: AuthorityGeneration, now_us: u64) -> AdmissionRequest {
    AdmissionRequest {
        right: AuthorityRight::InvokeReadOnly,
        recovery: RecoveryClass::ReadOnly,
        generation,
        now_us,
    }
}

/// Admits one fixture dispatch through one authority generation, recovery class,
/// and declared right, returning the landed admission the instance committed.
///
/// A commit point of this model carries that admission, so a fixture that commits
/// an admission asserts the generation and the settlement rule that actually
/// admitted the work instead of a bare verdict that something was admitted.
fn admission_of(
    generation: AuthorityGeneration,
    recovery: RecoveryClass,
    right: AuthorityRight,
) -> Admission {
    let mut operator = instance(&AUTHORITY_RIGHT_ORDER);
    operator
        .admit(
            &AdmissionRequest {
                right,
                recovery,
                generation,
                now_us: 0,
            },
            &AncestorFences::none(),
        )
        .unwrap_or_else(|_| unreachable!("the widest fixture instance admits this dispatch"))
}

/// Binds the fixture lease of one attenuated capability instance.
fn lease_of(
    parent: &AuthorityInstance,
    rights: &[AuthorityRight],
    expires_at_us: u64,
    revocation: RevocationContract,
) -> StandingLease {
    StandingLease::attenuate(
        parent,
        RightsSet::from_rights(rights),
        AuthorityLeasePolicy::Expiring { expires_at_us },
        revocation,
    )
    .unwrap_or_else(|_| unreachable!("the fixture attenuation narrows its parent"))
}

/// Builds one positive decision over one operation, standing on one lease.
///
/// The subject carries the lease's own instance, generation, lineage, and a
/// validity bound inside the lease, so the decision stands on exactly the lease it
/// presents and the model's scope check accepts it.
fn leased_decision(operation: &LogicalOperationId, lease: StandingLease) -> ApprovalDecision {
    let expires_at_us = lease
        .expires_at_us()
        .unwrap_or_else(|| unreachable!("the fixture lease is bounded"));
    let constraints = DecisionConstraints::new(
        lease.scope(),
        expires_at_us,
        AttemptApplicability::RecoveryPolicy,
    )
    .unwrap_or_else(|_| unreachable!("the decision bound stays within the lease"));
    let subject = build(
        base_inputs(operation)
            .with_constraints(constraints)
            .with_instance(lease.id().clone())
            .with_generation(lease.instance().generation())
            .with_lineage(lease.instance().lineage_record()),
    );
    ApprovalDecision::new(
        subject,
        ApprovalOutcome::PositiveDecision,
        &actor(),
        0,
        Some(lease),
    )
    .unwrap_or_else(|_| unreachable!("the decision stands on the lease it declares"))
}

/// Binds one release-holder authority over the fixture release site.
fn holder(
    classes: &[ProtectedDataClass],
    destinations: &[ReleaseDestination],
) -> ReleaseHolderAuthority {
    let site = name(SITE);
    let binding = ReleaseHolderBindingId::new(&site, &integration());
    ReleaseHolderAuthority::bind(&site, binding, classes, destinations)
        .unwrap_or_else(|_| unreachable!("the fixture binding names its own site"))
}

/// Returns the audit capability the approval evidence store issues for the landed
/// observe right, which every fixture holder of the widest rights set carries.
fn audit_access() -> ApprovalAuditAccess {
    ApprovalAuditAccess::grant(RightsSet::from_rights(&[AuthorityRight::Observe]))
        .unwrap_or_else(|| unreachable!("the observe right issues the audit capability"))
}

/// Seals one fixture protected value of one class.
fn protected(class: ProtectedDataClass) -> ProtectedValue {
    let origin =
        ProvenanceOrigin::new(ProvenanceOriginKind::IntegrationBoundary, "crate::argument")
            .unwrap_or_else(|_| unreachable!("fixture origin is canonical"));
    ProtectedValue::seal(class, origin)
}

/// The request identity is subject-derived: it changes when any subject input
/// changes, it stays stable under any construction order and under permuted
/// declared sets, and it is distinct from the subject digest.
#[test]
fn approval_request_identity_is_subject_derived_and_order_independent() {
    let operation = operation_id("crate::read_only", &[0, 1]);
    let base = base_inputs(&operation);
    let subject = build(base.clone());
    let request_id = ApprovalRequestId::of(&subject);

    assert!(request_id.as_str().starts_with("approval-request:"));
    assert_eq!(request_id.digest_hex().len(), 64);
    assert_eq!(subject.digest().as_str().len(), 64);
    assert_ne!(request_id.as_str(), subject.digest().as_str());
    assert_ne!(request_id.digest_hex(), subject.digest().as_str());
    assert_ne!(subject.digest().as_str(), subject.operation().digest_hex());
    assert_eq!(
        request_id.as_str(),
        ApprovalRequestId::of(&build(base.clone())).as_str(),
        "one input record has one request identity"
    );

    // A provider handle is not a request identity: the only request identity of
    // this subject is the subject-derived one.
    assert_ne!(request_id.as_str(), subject.instance().as_str());
    assert_ne!(request_id.as_str(), subject.requirement().as_str());
    assert_ne!(request_id.as_str(), subject.arguments().as_str());

    // Permutation: the same inputs supplied in another construction order, and a
    // permuted declared rights list, produce the same bytes and the same identity.
    let permuted = ApprovalSubjectInputs::default()
        .with_constraints(constraints(&operation, 100))
        .with_scope(scope())
        .with_effects(effects())
        .with_target(target())
        .with_recovery(RecoveryClass::ReadOnly)
        .with_policy(policy("policy"))
        .with_mapping(mapping("mapping"))
        .with_lineage(instance(&AUTHORITY_RIGHT_ORDER).lineage_record())
        .with_generation(instance(&AUTHORITY_RIGHT_ORDER).generation())
        .with_instance(instance(&AUTHORITY_RIGHT_ORDER).id().clone())
        .with_requirement(requirement(FAMILY))
        .with_presentation(ApproverPresentation::Faithful)
        .with_arguments(arguments("arguments"))
        .with_operation(operation.clone())
        .with_site(site(&[0, 1]))
        .with_declaration(path("crate::read_only"))
        .with_task(task())
        .with_execution(execution("primary"));
    let permuted = build(permuted);
    assert_eq!(permuted.canonical_bytes(), subject.canonical_bytes());
    assert_eq!(permuted.digest(), subject.digest());
    assert_eq!(ApprovalRequestId::of(&permuted), request_id);

    let parent = instance_with(
        &AUTHORITY_RIGHT_ORDER,
        AuthorityLeasePolicy::Expiring { expires_at_us: 100 },
    );
    let forward = lease_of(
        &parent,
        &[AuthorityRight::Observe, AuthorityRight::InvokeReadOnly],
        50,
        RevocationContract::IssuerOrHolder,
    );
    let reversed = lease_of(
        &parent,
        &[AuthorityRight::InvokeReadOnly, AuthorityRight::Observe],
        50,
        RevocationContract::IssuerOrHolder,
    );
    assert_eq!(forward.lease_scope(), reversed.lease_scope());
    assert_eq!(forward.id(), reversed.id());

    // Changing any input changes the canonical bytes, the digest, and the
    // identity of the request.
    let base_digest = subject.digest();
    let mutations = [
        (
            "execution",
            base.clone().with_execution(execution("secondary")),
        ),
        (
            "task",
            base.clone().with_task(CanonicalCallableIdentity::free(
                &path("crate::other_task"),
                &[],
            )),
        ),
        (
            "declaration",
            base.clone().with_declaration(path("crate::other_action")),
        ),
        ("site", base.clone().with_site(site(&[0, 2]))),
        (
            "operation",
            base.clone()
                .with_operation(operation_id("crate::other_action", &[0, 1]))
                .with_constraints(constraints(
                    &operation_id("crate::other_action", &[0, 1]),
                    100,
                )),
        ),
        (
            "arguments",
            base.clone().with_arguments(arguments("other-arguments")),
        ),
        (
            "presentation",
            base.clone()
                .with_presentation(ApproverPresentation::RedactedWithinDeclaredScope(
                    ProtectedReviewChannel::sealed(SealedPredicate::new(
                        name("predicate-cannot-show"),
                        1,
                        arguments("predicate-meaning"),
                    )),
                )),
        ),
        (
            "requirement",
            base.clone().with_requirement(requirement("tool")),
        ),
        (
            "instance",
            base.clone()
                .with_instance(instance(&[AuthorityRight::Observe]).id().clone()),
        ),
        (
            "generation",
            base.clone().with_generation(AuthorityGeneration::new(7)),
        ),
        (
            "lineage",
            base.clone()
                .with_lineage(instance(&[AuthorityRight::Observe]).lineage_record()),
        ),
        (
            "mapping",
            base.clone().with_mapping(mapping("other-mapping")),
        ),
        ("policy", base.clone().with_policy(policy("other-policy"))),
        (
            "recovery",
            base.clone().with_recovery(RecoveryClass::NonIdempotent),
        ),
        (
            "target",
            base.clone().with_target(ExternalTargetRef::new(
                integration(),
                TargetFactsDigest::from_hex(&hex("other-target-facts"))
                    .unwrap_or_else(|_| unreachable!("fixture target digest is hexadecimal")),
            )),
        ),
        ("effects", base.clone().with_effects(EffectSet::default())),
        (
            "scope",
            base.clone().with_scope(ProtectedScope::new(
                ProjectionKind::Verbatim,
                ProtectedDataClass::SourceText,
                ReleaseDestination::DiagnosticSink,
                charge(2),
            )),
        ),
        (
            "constraints",
            base.clone().with_constraints(constraints(&operation, 200)),
        ),
    ];
    for (input, mutated) in mutations {
        let mutated = build(mutated);
        assert_ne!(
            mutated.digest(),
            base_digest,
            "input `{input}` changes the subject"
        );
        assert_ne!(
            mutated.canonical_bytes(),
            subject.canonical_bytes(),
            "input `{input}` changes the canonical bytes"
        );
        assert_ne!(
            ApprovalRequestId::of(&mutated),
            request_id,
            "input `{input}` changes the request identity"
        );
    }

    // An incomplete record fails closed and names the absent input rather than
    // building a partial subject.
    let incomplete = ApprovalSubjectInputs::default()
        .with_operation(operation.clone())
        .build();
    assert_eq!(
        incomplete.err(),
        Some(ApprovalError::IncompleteSubject { input: "execution" })
    );

    // A one-shot scope must name the subject's own operation identity.
    let foreign_scope = constraints(&operation_id("crate::other_action", &[0, 1]), 100);
    assert_eq!(
        base.with_constraints(foreign_scope).build().err(),
        Some(ApprovalError::ScopeMismatch)
    );
}

/// The outcome vocabulary is exactly the closed one of
/// `GNT-19.8-approval-outcome-taxonomy`: each outcome is distinct, carries its own
/// diagnostic, has no unknown member, and no approval wait can make an operation
/// that was never admitted ambiguous or erase an ambiguous external outcome.
#[test]
fn approval_outcome_vocabulary_is_closed_and_has_no_unknown_variant() {
    assert_eq!(ApprovalOutcome::ALL.len(), 7);
    let mut codes = Vec::new();
    for outcome in ApprovalOutcome::ALL {
        assert_eq!(
            ApprovalOutcome::from_wire_name(outcome.wire_name()),
            Some(outcome)
        );
        assert_eq!(outcome.as_str(), outcome.wire_name());
        codes.push(outcome.code().as_str());
        assert_eq!(
            outcome.code().requirement(),
            "GNT-19.8-approval-outcome-taxonomy"
        );
        assert!(!outcome.code().meaning().is_empty());
        assert!(outcome.is_positive() == (outcome == ApprovalOutcome::PositiveDecision));
    }
    codes.sort_unstable();
    codes.dedup();
    assert_eq!(
        codes.len(),
        7,
        "each bounded outcome carries its own diagnostic"
    );

    // There is no unknown outcome to fabricate or to decode.
    for unknown in [
        "unknown",
        "ambiguous",
        "failed",
        "denied",
        "expired",
        "",
        "unknown-outcome",
    ] {
        assert_eq!(ApprovalOutcome::from_wire_name(unknown), None);
    }
    for code in ApprovalDiagnosticCode::ALL {
        assert!(!code.as_str().is_empty());
        assert!(code.as_str().starts_with("approval-"));
        assert!(!code.meaning().is_empty());
        assert!(code.requirement().starts_with("GNT-19"));
    }

    // An operation that never passed the admission commit point has no effect and
    // no external outcome, so no approval-wait outcome is ambiguous.
    for outcome in ApprovalOutcome::ALL {
        let record = ApprovalOutcomeRecord::not_admitted(outcome);
        assert!(!record.is_ambiguous());
        assert_eq!(record.external_outcome(), None);
        assert_eq!(record.approval_outcome(), Some(outcome));
        assert_eq!(record.admission_sequence(), None);
    }

    // An ambiguous external outcome of work that may already have begun stays
    // ambiguous and carries no approval-wait outcome to reclassify it with.
    let mut operator = instance(&AUTHORITY_RIGHT_ORDER);
    let admission = operator
        .admit(&request(operator.generation(), 0), &AncestorFences::none())
        .unwrap_or_else(|_| unreachable!("the widest fixture instance admits dispatch"));
    let admitted = ApprovalOutcomeRecord::admitted(admission, ExternalOutcome::Ambiguous);
    assert!(admitted.is_ambiguous());
    assert_eq!(
        admitted.external_outcome(),
        Some(ExternalOutcome::Ambiguous)
    );
    assert_eq!(admitted.approval_outcome(), None);
    assert_eq!(admitted.admission_sequence(), Some(0));
    let settled = ApprovalOutcomeRecord::admitted(admission, ExternalOutcome::Accepted);
    assert!(!settled.is_ambiguous());
}

/// The default is one decision for one logical operation identity: a one-shot
/// decision does not authorize another logical operation, another argument set, or
/// another destination, and no revalidation repairs it.
#[test]
fn a_one_shot_decision_does_not_authorize_another_logical_operation() {
    let operation = operation_id("crate::read_only", &[0, 1]);
    let subject = subject_of(&operation);
    let decision = decision(&subject);
    let generation = subject.generation();
    let request = request(generation, 1);

    assert!(decision.scope().is_one_shot());
    assert_eq!(decision.scope().wire_name(), "one-shot");
    assert_eq!(decision.scope().one_shot_operation(), Some(&operation));
    assert_eq!(decision.scope().lease_scope(), None);
    assert_eq!(decision.lease(), None);
    assert!(decision.is_positive());
    assert_eq!(
        revalidate(&subject, &decision, &request),
        Revalidation::Fresh
    );

    // Another logical operation identity is not covered.
    let foreign = subject_of(&operation_id("crate::other_action", &[0, 1]));
    assert_ne!(foreign.operation(), decision.subject().operation());
    assert_eq!(
        revalidate(&foreign, &decision, &request),
        Revalidation::Stale(StalenessReason::Scope)
    );

    // The same operation identity with other arguments is not covered either.
    let changed = build(base_inputs(&operation).with_arguments(arguments("other-arguments")));
    assert_eq!(
        revalidate(&changed, &decision, &request),
        Revalidation::Stale(StalenessReason::Argument)
    );

    // A different destination in the protected scope is a widened release scope.
    let widened = build(base_inputs(&operation).with_scope(ProtectedScope::new(
        ProjectionKind::Verbatim,
        ProtectedDataClass::ActionArgument,
        ReleaseDestination::DiagnosticSink,
        charge(1),
    )));
    assert_eq!(
        revalidate(&widened, &decision, &request),
        Revalidation::Stale(StalenessReason::Scope)
    );

    // The decision is never repaired: its subject, scope, and identity stand.
    assert_eq!(decision.subject().digest(), subject.digest());
    assert_eq!(decision.subject().operation(), &operation);
    assert_eq!(decision.scope().one_shot_operation(), Some(&operation));
    assert_eq!(
        decision.subject().canonical_bytes(),
        subject.canonical_bytes()
    );
    assert_ne!(
        decision.id().as_str(),
        ApprovalRequestId::of(&subject).as_str()
    );
    assert_eq!(decision.id().as_str().len(), 64);
}

/// Reusable authority is never the default and never an approval cache: a standing
/// lease is obtainable only by attenuating an existing capability instance, it is
/// bounded, it expires, and it can be revoked.
#[test]
fn a_standing_lease_is_obtainable_only_by_attenuation_expires_and_is_revocable() {
    assert_not_impl_any!(
        StandingLease: Default,
        From<RightsSet>,
        From<ApprovalRequestId>,
        From<ApprovalSubject>,
        From<AdmissionRequest>,
        From<AuthorityRight>,
        serde::Deserialize<'static>
    );
    assert_not_impl_any!(
        LeaseScope: Default,
        From<RightsSet>,
        From<ApprovalRequestId>,
        From<ApprovalSubject>,
        From<StandingLease>
    );
    assert_not_impl_any!(
        DecisionScope: Default,
        From<RightsSet>,
        From<ApprovalRequestId>,
        From<AuthorityRight>
    );

    let operation = operation_id("crate::read_only", &[0, 1]);
    let parent = instance_with(
        &AUTHORITY_RIGHT_ORDER,
        AuthorityLeasePolicy::Expiring { expires_at_us: 100 },
    );
    let parent_generation = parent.generation();

    // A lease must be bounded: an unleased attenuation is not a lease.
    assert_eq!(
        StandingLease::attenuate(
            &parent,
            RightsSet::from_rights(&[AuthorityRight::Observe]),
            AuthorityLeasePolicy::Unleased,
            RevocationContract::IssuerOrHolder,
        )
        .err(),
        Some(ApprovalError::UnboundedLease)
    );

    // Attenuation can only narrow: amplification is refused, and the refusal
    // reports the landed condition under the landed code it already has.
    let narrow = instance(&[AuthorityRight::Observe, AuthorityRight::InvokeReadOnly]);
    let refused = StandingLease::attenuate(
        &narrow,
        RightsSet::from_rights(&[AuthorityRight::InvokeNonIdempotent]),
        AuthorityLeasePolicy::Expiring { expires_at_us: 50 },
        RevocationContract::IssuerOrHolder,
    )
    .err();
    assert_eq!(
        refused,
        Some(ApprovalError::AttenuationRefused {
            landed: AuthorityError::AmplifiedRights,
        })
    );
    let refusal = refused.unwrap_or_else(|| unreachable!("the amplification is refused"));
    assert_eq!(refusal.code(), None);
    assert_eq!(refusal.landed_code(), Some("authority-amplified-rights"));
    assert_eq!(
        refusal.requirement(),
        "GNT-19.5-decision-scope-and-standing-authority"
    );
    assert!(
        refusal
            .to_string()
            .starts_with("authority-amplified-rights")
    );
    let amplification = StandingLease::attenuate(
        &narrow,
        RightsSet::from_rights(&[AuthorityRight::Observe, AuthorityRight::InvokeNonIdempotent]),
        AuthorityLeasePolicy::Expiring { expires_at_us: 50 },
        RevocationContract::IssuerOrHolder,
    )
    .err()
    .unwrap_or_else(|| unreachable!("the partial amplification is refused"));
    assert_eq!(
        amplification.landed_code(),
        Some("authority-amplified-rights")
    );

    // A derived lease narrows the parent in rights, generation, and lineage.
    let mut lease = lease_of(
        &parent,
        &[AuthorityRight::Observe, AuthorityRight::InvokeReadOnly],
        50,
        RevocationContract::IssuerOrHolder,
    );
    let mut issuer_only = lease_of(
        &parent,
        &[AuthorityRight::Observe],
        50,
        RevocationContract::IssuerOnly,
    );
    assert!(lease.rights().is_subset_of(parent.rights()));
    assert_eq!(lease.instance().parent(), Some(parent.id()));
    assert!(lease.instance().generation() > parent_generation);
    assert_eq!(lease.root(), parent.root());
    assert_eq!(lease.instance().lineage().len(), 1);
    assert_eq!(lease.expires_at_us(), Some(50));
    assert_eq!(lease.revocation(), RevocationContract::IssuerOrHolder);
    assert!(!lease.is_delegable());
    assert_eq!(lease.scope().wire_name(), "standing-lease");
    assert_eq!(lease.scope().one_shot_operation(), None);

    // A standing lease never covers one operation identity by itself: the subject
    // names the operation, the lease supplies reusable bounded authority.
    let lease_scope = lease.scope();
    assert_eq!(lease_scope.lease_scope(), Some(&lease.lease_scope()));
    assert_eq!(
        lease_scope.canonical_text(),
        lease.lease_scope().canonical_text()
    );
    assert!(lease.lease_scope().permits(49));
    assert!(!lease.lease_scope().permits(50));

    // A decision must not outlive the lease it stands on.
    assert_eq!(
        DecisionConstraints::new(
            lease_scope.clone(),
            51,
            AttemptApplicability::RecoveryPolicy,
        )
        .err(),
        Some(ApprovalError::DecisionOutlivesLease)
    );
    let lease_constraints = DecisionConstraints::new(
        lease_scope.clone(),
        50,
        AttemptApplicability::RecoveryPolicy,
    )
    .unwrap_or_else(|_| unreachable!("the decision bound stays within the lease"));
    let lease_subject = build(
        base_inputs(&operation)
            .with_constraints(lease_constraints)
            .with_instance(lease.id().clone())
            .with_generation(lease.instance().generation())
            .with_lineage(lease.instance().lineage_record()),
    );
    assert!(
        ApprovalDecision::new(
            lease_subject.clone(),
            ApprovalOutcome::PositiveDecision,
            &actor(),
            0,
            Some(lease_of(
                &parent,
                &[AuthorityRight::Observe],
                40,
                RevocationContract::IssuerOrHolder,
            )),
        )
        .is_err()
    );

    // Presentation is never approval for what it hides: a presentation that
    // conceals an element cannot carry reusable standing authority.
    let redacted = ApproverPresentation::RedactedWithinDeclaredScope(
        ProtectedReviewChannel::sealed(SealedPredicate::new(
            name("predicate-cannot-show"),
            3,
            arguments("predicate-meaning"),
        )),
    );
    assert!(!redacted.is_faithful());
    assert_eq!(
        redacted
            .channel()
            .map(|channel| channel.predicate().version()),
        Some(3)
    );
    assert!(redacted.canonical_text().contains("predicate-cannot-show"));
    let concealed = base_inputs(&operation)
        .with_presentation(redacted)
        .with_constraints(
            DecisionConstraints::new(
                lease_scope.clone(),
                50,
                AttemptApplicability::RecoveryPolicy,
            )
            .unwrap_or_else(|_| unreachable!("the decision bound stays within the lease")),
        )
        .build();
    assert_eq!(
        concealed.err(),
        Some(ApprovalError::PresentationConcealsScope)
    );

    // A lease expires.
    assert!(lease.permits(49));
    assert!(!lease.permits(50));
    assert!(!lease.permits(51));
    assert!(!lease.is_revoked());
    assert_eq!(lease.fenced(), None);

    // A lease can be revoked by a contractual revoker, and a repeated permitted
    // revocation keeps its own point.
    let point = lease
        .revoke(parent.id())
        .unwrap_or_else(|_| unreachable!("the issuer may revoke under this contract"));
    assert_eq!(point.category(), FenceCategory::Revocation);
    assert!(lease.is_revoked());
    assert_eq!(lease.fenced(), Some(FenceCategory::Revocation));
    assert!(!lease.permits(0));
    let repeated = lease
        .revoke(parent.id())
        .unwrap_or_else(|_| unreachable!("a repeated revocation returns its point"));
    assert_eq!(repeated.linearization_point(), point.linearization_point());

    // The revocation contract is decisive and is checked before anything is fenced:
    // a revoker the contract does not admit is refused without fencing the lease.
    let issuer_only_holder = issuer_only.id().clone();
    assert_eq!(
        issuer_only.revoke(&issuer_only_holder).err(),
        Some(ApprovalError::RevocationNotContractual)
    );
    assert!(
        !issuer_only.is_revoked(),
        "a refused revocation fences nothing"
    );
    assert_eq!(issuer_only.fenced(), None);
}

/// Revalidation is fail-closed and reports exactly what it revalidated: staleness
/// on an argument, generation, mapping, policy, scope, or lifetime change, fencing
/// on revocation or expiry before admission, and never a repair of a stale
/// decision.
#[test]
fn revalidation_reports_staleness_and_fencing_without_repair() {
    let operation = operation_id("crate::read_only", &[0, 1]);
    let subject = subject_of(&operation);
    let decision = decision(&subject);
    let generation = subject.generation();
    assert_eq!(
        revalidate(&subject, &decision, &request(generation, 99)),
        Revalidation::Fresh
    );

    let verdicts = [
        (
            "argument",
            revalidate(
                &build(base_inputs(&operation).with_arguments(arguments("other-arguments"))),
                &decision,
                &request(generation, 1),
            ),
            Revalidation::Stale(StalenessReason::Argument),
        ),
        (
            "mapping",
            revalidate(
                &build(base_inputs(&operation).with_mapping(mapping("other-mapping"))),
                &decision,
                &request(generation, 1),
            ),
            Revalidation::Stale(StalenessReason::Mapping),
        ),
        (
            "policy",
            revalidate(
                &build(base_inputs(&operation).with_policy(policy("other-policy"))),
                &decision,
                &request(generation, 1),
            ),
            Revalidation::Stale(StalenessReason::Policy),
        ),
        (
            "generation",
            revalidate(
                &build(base_inputs(&operation).with_generation(AuthorityGeneration::new(9))),
                &decision,
                &request(generation, 1),
            ),
            Revalidation::Stale(StalenessReason::Generation),
        ),
        (
            "instance",
            revalidate(
                &build(
                    base_inputs(&operation)
                        .with_instance(instance(&[AuthorityRight::Observe]).id().clone()),
                ),
                &decision,
                &request(generation, 1),
            ),
            Revalidation::Stale(StalenessReason::Generation),
        ),
        (
            "presented generation",
            revalidate(
                &subject,
                &decision,
                &request(AuthorityGeneration::new(9), 1),
            ),
            Revalidation::Stale(StalenessReason::Generation),
        ),
        (
            "scope",
            revalidate(
                &build(base_inputs(&operation).with_scope(ProtectedScope::new(
                    ProjectionKind::Verbatim,
                    ProtectedDataClass::ActionArgument,
                    ReleaseDestination::DiagnosticSink,
                    charge(1),
                ))),
                &decision,
                &request(generation, 1),
            ),
            Revalidation::Stale(StalenessReason::Scope),
        ),
        (
            "lifetime",
            revalidate(
                &build(base_inputs(&operation).with_constraints(constraints(&operation, 200))),
                &decision,
                &request(generation, 1),
            ),
            Revalidation::Stale(StalenessReason::Lifetime),
        ),
        (
            "presentation",
            revalidate(
                &build(base_inputs(&operation).with_presentation(
                    ApproverPresentation::RedactedWithinDeclaredScope(
                        ProtectedReviewChannel::sealed(SealedPredicate::new(
                            name("predicate-cannot-show"),
                            1,
                            arguments("predicate-meaning"),
                        )),
                    ),
                )),
                &decision,
                &request(generation, 1),
            ),
            Revalidation::Stale(StalenessReason::Presentation),
        ),
        (
            "task",
            revalidate(
                &build(
                    base_inputs(&operation).with_task(CanonicalCallableIdentity::free(
                        &path("crate::other_task"),
                        &[],
                    )),
                ),
                &decision,
                &request(generation, 1),
            ),
            Revalidation::Stale(StalenessReason::Subject),
        ),
        (
            "expiry",
            revalidate(&subject, &decision, &request(generation, 100)),
            Revalidation::Fenced(FenceReason::Expiry),
        ),
    ];
    for (input, observed, expected) in &verdicts {
        assert_eq!(observed, expected, "`{input}` revalidation verdict");
        assert!(!observed.is_fresh(), "`{input}` is not fresh");
        assert!(
            observed.refusal().is_some(),
            "`{input}` records a refusal at the commit point"
        );
    }

    // The subject about to be dispatched also carries the recovery class of the
    // operation, which is revalidated with the arguments.
    let other_recovery = AdmissionRequest {
        right: AuthorityRight::InvokeNonIdempotent,
        recovery: RecoveryClass::NonIdempotent,
        generation,
        now_us: 1,
    };
    assert_eq!(
        revalidate(&subject, &decision, &other_recovery),
        Revalidation::Stale(StalenessReason::Subject)
    );

    // A refusal is recorded at the commit point, and a fresh verdict refuses
    // nothing.
    assert_eq!(CommitPointResult::refused(Revalidation::Fresh), None);
    assert_eq!(
        CommitPointResult::refused(Revalidation::Stale(StalenessReason::Mapping))
            .and_then(|commit_point| commit_point.refusal().and_then(RefusalReason::staleness)),
        Some(StalenessReason::Mapping)
    );

    // No revalidation repaired, widened, or reinterpreted the decision.
    assert_eq!(decision.subject().digest(), subject.digest());
    assert_eq!(
        decision.subject().canonical_bytes(),
        subject.canonical_bytes()
    );
    assert_eq!(decision.scope().one_shot_operation(), Some(&operation));

    // Revocation and the expiry of the lease the decision stands on fence the
    // admission before it is committed.
    let parent = instance_with(
        &AUTHORITY_RIGHT_ORDER,
        AuthorityLeasePolicy::Expiring { expires_at_us: 100 },
    );
    let lease = lease_of(
        &parent,
        &[AuthorityRight::Observe, AuthorityRight::InvokeReadOnly],
        50,
        RevocationContract::IssuerOrHolder,
    );
    let lease_scope = lease.scope();
    let lease_constraints = DecisionConstraints::new(
        lease_scope.clone(),
        50,
        AttemptApplicability::RecoveryPolicy,
    )
    .unwrap_or_else(|_| unreachable!("the decision bound stays within the lease"));
    let lease_subject = build(
        base_inputs(&operation)
            .with_constraints(lease_constraints)
            .with_instance(lease.id().clone())
            .with_generation(lease.instance().generation())
            .with_lineage(lease.instance().lineage_record()),
    );
    let lease_generation = lease_subject.generation();
    let lease_decision = ApprovalDecision::new(
        lease_subject.clone(),
        ApprovalOutcome::PositiveDecision,
        &actor(),
        0,
        Some(lease),
    )
    .unwrap_or_else(|_| unreachable!("the decision stands on the lease it declares"));
    assert_eq!(
        revalidate(
            &lease_subject,
            &lease_decision,
            &request(lease_generation, 49)
        ),
        Revalidation::Fresh
    );
    assert_eq!(
        revalidate(
            &lease_subject,
            &lease_decision,
            &request(lease_generation, 50)
        ),
        Revalidation::Fenced(FenceReason::Expiry)
    );
    assert_eq!(
        lease_decision.lease().map(|stand| stand.permits(49)),
        Some(true)
    );

    let mut revoked = lease_of(
        &parent,
        &[AuthorityRight::Observe, AuthorityRight::InvokeReadOnly],
        50,
        RevocationContract::IssuerOrHolder,
    );
    let point = revoked
        .revoke(parent.id())
        .unwrap_or_else(|_| unreachable!("the contractual holder may revoke"));
    assert_eq!(point.category(), FenceCategory::Revocation);
    let revoked_decision = ApprovalDecision::new(
        lease_subject.clone(),
        ApprovalOutcome::PositiveDecision,
        &actor(),
        0,
        Some(revoked),
    )
    .unwrap_or_else(|_| unreachable!("the decision stands on the lease it declares"));
    assert_eq!(
        revalidate(
            &lease_subject,
            &revoked_decision,
            &request(lease_generation, 10)
        ),
        Revalidation::Fenced(FenceReason::Revocation)
    );
    assert_eq!(
        revalidate(
            &lease_subject,
            &revoked_decision,
            &request(lease_generation, 10)
        )
        .fence(),
        Some(FenceReason::Revocation)
    );
}

/// The durable cuts are ordered: a decision is refused before a committed request,
/// a dispatch is refused before a committed decision, and one logical operation
/// identity never gets a second request.
#[test]
fn durable_cuts_commit_in_order_and_classify_resume() {
    assert_not_impl_any!(
        DurableApprovalRecord: From<DurableApprovalCut>,
        From<ApprovalDecision>,
        From<AdmissionRequest>,
        From<ApprovalOutcome>
    );
    assert_eq!(DurableApprovalCut::ALL.len(), 4);
    for cut in DurableApprovalCut::ALL {
        assert_eq!(
            DurableApprovalCut::from_wire_name(cut.wire_name()),
            Some(cut)
        );
        assert_eq!(cut.as_str(), cut.wire_name());
    }

    let request_cut = DurableApprovalCut::RequestCommitted;
    let decision_cut = DurableApprovalCut::DecisionCommitted;
    let admitted_cut = DurableApprovalCut::Admitted;
    let dispatched_cut = DurableApprovalCut::Dispatched;
    assert_eq!(request_cut.advance(decision_cut), Ok(decision_cut));
    assert_eq!(decision_cut.advance(admitted_cut), Ok(admitted_cut));
    assert_eq!(admitted_cut.advance(dispatched_cut), Ok(dispatched_cut));
    assert_eq!(
        request_cut.advance(admitted_cut),
        Err(ApprovalError::CutOutOfOrder {
            from: request_cut,
            to: admitted_cut,
        })
    );
    assert_eq!(
        request_cut.advance(dispatched_cut),
        Err(ApprovalError::CutOutOfOrder {
            from: request_cut,
            to: dispatched_cut,
        }),
        "a dispatch before a committed decision is refused"
    );
    assert_eq!(
        decision_cut.advance(dispatched_cut),
        Err(ApprovalError::CutOutOfOrder {
            from: decision_cut,
            to: dispatched_cut,
        })
    );
    assert_eq!(
        request_cut.advance(request_cut),
        Err(ApprovalError::CutOutOfOrder {
            from: request_cut,
            to: request_cut,
        }),
        "the request cut is committed before any decision can be reached"
    );
    assert_eq!(request_cut.rank(), 0);
    assert_eq!(dispatched_cut.rank(), 3);

    let operation = operation_id("crate::read_only", &[0, 1]);
    let subject = subject_of(&operation);
    let record = DurableApprovalRecord::commit_request(&subject);
    assert_eq!(record.cut(), request_cut);
    assert_eq!(record.request(), &ApprovalRequestId::of(&subject));
    assert_eq!(record.operation(), &operation);
    assert_eq!(record.decision(), None);
    assert_eq!(record.outcome(), None);
    assert_eq!(record.classify_resume(), ResumeClass::PendingDecision);

    // The decision cut is reachable only through commit_decision: the happy path
    // commits the request, the decision, admission, and dispatch in that order.
    let decision = decision(&subject);
    let committed = record
        .clone()
        .commit_decision(&decision)
        .unwrap_or_else(|_| unreachable!("the decision is of the committed request"));
    assert_eq!(committed.cut(), decision_cut);
    assert_eq!(committed.decision(), Some(&decision.id()));
    assert_eq!(committed.outcome(), Some(ApprovalOutcome::PositiveDecision));
    assert_eq!(committed.resume(&subject), Ok(decision_cut));
    assert_eq!(committed.classify_resume(), ResumeClass::SameDecision);
    assert_eq!(
        committed.clone().commit_decision(&decision).err(),
        Some(ApprovalError::CutOutOfOrder {
            from: decision_cut,
            to: decision_cut,
        }),
        "the decision cut is committed once"
    );
    let admitted = committed
        .clone()
        .advance(admitted_cut)
        .unwrap_or_else(|_| unreachable!("admission follows the decision commit"));
    assert_eq!(admitted.resume(&subject), Ok(admitted_cut));
    assert_eq!(admitted.classify_resume(), ResumeClass::SameDecision);
    let dispatched = admitted
        .clone()
        .advance(dispatched_cut)
        .unwrap_or_else(|_| unreachable!("dispatch follows admission"));
    assert_eq!(dispatched.classify_resume(), ResumeClass::OperationRecovery);
    assert_eq!(
        dispatched.resume(&subject),
        Ok(dispatched_cut),
        "a dispatch is not re-approved"
    );

    // The spec-derived mapping is exhaustive: the committed request resumes the
    // pending wait, a committed decision resumes under the same decision, and only a
    // dispatch hands off to the target operation's recovery state.
    for cut in DurableApprovalCut::ALL {
        let expected = match cut {
            DurableApprovalCut::RequestCommitted => ResumeClass::PendingDecision,
            DurableApprovalCut::DecisionCommitted | DurableApprovalCut::Admitted => {
                ResumeClass::SameDecision
            }
            DurableApprovalCut::Dispatched => ResumeClass::OperationRecovery,
        };
        assert_eq!(cut.classify_resume(), expected);
    }
    assert_eq!(ResumeClass::PendingDecision.wire_name(), "pending-decision");
    assert_eq!(
        DurableApprovalCut::ALL
            .into_iter()
            .filter(|cut| cut.classify_resume() == ResumeClass::OperationRecovery)
            .collect::<Vec<_>>(),
        vec![dispatched_cut],
        "only a dispatch can have begun external work"
    );

    // One logical operation identity never gets a second request.
    let second = build(base_inputs(&operation).with_arguments(arguments("other-arguments")));
    assert_ne!(
        ApprovalRequestId::of(&second),
        ApprovalRequestId::of(&subject)
    );
    assert_eq!(second.operation(), &operation);
    let refusal = dispatched.resume(&second).err();
    assert_eq!(
        refusal.as_ref().and_then(|error| error.code()),
        Some(ApprovalDiagnosticCode::SecondRequestForOperation)
    );
    assert_eq!(
        refusal.as_ref().map(ApprovalError::requirement),
        Some("GNT-19.7-durable-request-and-decision-cuts")
    );

    // A request identity that belongs to another logical operation identity is
    // not the committed request of this interaction.
    let foreign = subject_of(&operation_id("crate::other_action", &[0, 1]));
    let unknown = dispatched.resume(&foreign).err();
    assert_eq!(
        unknown.as_ref().and_then(|error| error.code()),
        Some(ApprovalDiagnosticCode::UnknownRequest)
    );
    assert_eq!(
        unknown
            .as_ref()
            .and_then(|error| error.code())
            .map(|code| code.requirement()),
        Some("GNT-19.1-approval-request-identity")
    );
}

/// Approval to execute and approval to release stay independent: approval alone
/// releases nothing, and the only release path is a grant derived from a
/// release-holder authority that declares exactly the subject's class and
/// destination.
#[test]
fn approval_alone_releases_nothing_and_holder_authority_is_the_only_release_path() {
    assert_not_impl_any!(
        ReleaseGrant: From<ApprovalDecision>,
        From<ApprovalSubject>,
        From<ApprovalOutcome>,
        From<ApprovalRequestId>,
        From<DecisionScope>,
        From<AdmissionRequest>,
        From<AuthorityRight>,
        From<RightsSet>,
        From<AuthorityInstance>,
        From<LeaseScope>,
        serde::Deserialize<'static>
    );
    assert_not_impl_any!(
        ApprovalDecision: From<ReleaseHolderAuthority>,
        From<ReleaseGrant>,
        From<AuthorityRight>,
        From<RightsSet>,
        From<AuthorityInstance>,
        From<ProtectedValue>,
        serde::Deserialize<'static>
    );

    let operation = operation_id("crate::read_only", &[0, 1]);
    let class = ProtectedDataClass::ActionArgument;
    let destination = ReleaseDestination::OrdinarySource;
    let subject = subject_of(&operation);
    assert_eq!(subject.scope().class(), class);
    assert_eq!(subject.scope().destination(), destination);
    assert_eq!(subject.scope().charge().value(), 1);
    assert_eq!(
        subject.scope().projection().kind(),
        ProjectionKind::Redacted
    );
    let decision = decision(&subject);

    // The declared release site, the disclosure budget, and the logical instant
    // that match this decision's subject exactly.
    let release_site = ReleaseSite::new(SITE).declare(class, destination, ProjectionKind::Redacted);
    let matching_budget = DisclosureBudget::new(1, charge(1));
    let authority = holder(
        &[class, ProtectedDataClass::SourceText],
        &[destination, ReleaseDestination::DiagnosticSink],
    );

    // Approval alone releases nothing.
    let withholding = holder(&[], &[]);
    assert_eq!(
        decision.release_grant(&withholding, &release_site, &matching_budget, 0),
        None
    );
    assert!(
        !holder(&[class], &[ReleaseDestination::DiagnosticSink])
            .grant()
            .is_empty()
    );
    assert_eq!(
        decision.release_grant(
            &holder(&[ProtectedDataClass::SourceText], &[destination]),
            &release_site,
            &matching_budget,
            0
        ),
        None
    );
    assert_eq!(
        decision.release_grant(
            &holder(&[class], &[ReleaseDestination::DiagnosticSink]),
            &release_site,
            &matching_budget,
            0
        ),
        None
    );

    // The holder authority that declares exactly the subject's pair is the only
    // source of a grant for a site, budget, and instant that agree with it.
    let grant = decision
        .release_grant(&authority, &release_site, &matching_budget, 0)
        .unwrap_or_else(|| unreachable!("the holder declares the subject's pair"));
    assert!(grant.covers(class, destination));
    assert_eq!(grant.class_count(), 1);
    assert_eq!(grant.destination_count(), 1);
    assert!(grant.holder().as_str().starts_with("release-holder:"));
    assert_ne!(
        grant.holder(),
        authority.id(),
        "the grant narrows the holder authority to the subject's exact pair"
    );
    assert!(grant.is_subset_of(&authority.grant()));
    assert!(grant.is_strict_subset_of(&authority.grant()));

    // A negative decision releases nothing, however the holder declares.
    let denial = ApprovalDecision::new(subject.clone(), ApprovalOutcome::Denial, &actor(), 0, None)
        .unwrap_or_else(|_| unreachable!("a one-shot decision needs no lease"));
    assert_eq!(
        denial.release_grant(&authority, &release_site, &matching_budget, 0),
        None
    );
    assert!(!denial.is_positive());

    // Approval is still not a release: the release site's own declaration, the
    // grant, and the disclosure budget each remain independently required.
    let protected = protected(class);
    let mut budget = DisclosureBudget::new(1, charge(1));
    let refused = release_site.release(&withholding.grant(), &protected, destination, &mut budget);
    assert_eq!(
        refused.decision(),
        ReleaseDecision::Rejected(ReleaseRejection::ClassMismatch)
    );
    assert_eq!(refused.released_value(), None);
    assert_eq!(budget.accepted(), 0);
    let accepted = release_site.release(&grant, &protected, destination, &mut budget);
    assert!(accepted.released_value().is_some());
    assert_eq!(budget.accepted(), 1);
}

/// Audit evidence is declared metadata only and is reachable only through the
/// capability-gated view; it exposes no credential, no protected argument, no
/// protected content, and no protected comment, and it records an admission only
/// for the positive decision and the subject that admission actually belongs to.
#[test]
fn approval_audit_evidence_requires_the_capability_gated_view() {
    assert_not_impl_any!(
        ApprovalAuditEvidence: Debug,
        Display,
        Default,
        serde::Deserialize<'static>,
        serde::Serialize
    );
    assert_not_impl_any!(ApprovalAuditAccess: Default, serde::Deserialize<'static>);

    // The view is reachable only under the audit capability, which the evidence
    // store issues for a bound instance carrying the observe right.
    let access = audit_access();

    let operation = operation_id("crate::read_only", &[0, 1]);
    let protected_arguments = arguments("protected-argument");
    let subject = build(base_inputs(&operation).with_arguments(protected_arguments.clone()));
    let decision = decision(&subject);
    let generation = subject.generation();
    let admission = admission_of(
        generation,
        RecoveryClass::ReadOnly,
        AuthorityRight::InvokeReadOnly,
    );

    // An admission recorded under the positive decision that admitted it succeeds,
    // and the recorded commit point carries that admission itself.
    let admitted = ApprovalAuditEvidence::record(&decision, CommitPointResult::admitted(admission))
        .unwrap_or_else(|_| unreachable!("the admission names the subject's generation and rule"))
        .with_transition(AuditTransition::new(AuditTransitionKind::Revocation, 120));
    let view = admitted.view(&access);
    assert_eq!(view.request(), &ApprovalRequestId::of(&subject));
    assert_eq!(view.decision(), &decision.id());
    assert_eq!(view.requester().as_str(), "requester-bob");
    assert_eq!(view.approver().as_str(), "approver-alice");
    assert_eq!(view.tenant().as_str(), "tenant-acme");
    assert_eq!(view.policy().as_str(), "policy-release");
    assert_eq!(view.policy_revision(), decision.subject().policy());
    assert_eq!(view.scope(), decision.scope().canonical_text());
    assert_eq!(view.issued_at_us(), 0);
    assert_eq!(view.expires_at_us(), decision.expires_at_us());
    assert_eq!(view.outcome(), ApprovalOutcome::PositiveDecision);
    assert_eq!(
        view.commit_point(),
        CommitPointResult::admitted(admission),
        "the commit point carries the admission the authority instance committed"
    );
    assert!(view.commit_point().is_admitted());
    assert_eq!(view.commit_point().admission(), Some(&admission));
    assert_eq!(
        view.commit_point()
            .admission()
            .map(|admission| admission.generation()),
        Some(generation)
    );
    assert_eq!(
        view.commit_point()
            .admission()
            .map(|admission| admission.settlement_rule()),
        Some(subject.recovery())
    );
    assert_eq!(view.commit_point().refusal(), None);
    assert_eq!(view.transitions().len(), 1);
    assert_eq!(
        view.transitions()[0].kind(),
        AuditTransitionKind::Revocation
    );
    assert_eq!(view.transitions()[0].at_us(), 120);

    // The view carries declared metadata only: no protected argument, and no
    // digest of one, is present in it.
    let text = view.canonical_text();
    assert!(!text.contains(protected_arguments.as_str()));
    assert!(text.contains("approver-alice"));
    assert!(!text.contains("GNT"));
    assert!(text.contains("policy-release"));

    // A refusal at the commit point is accepted under any decision outcome, because
    // a positive decision can be refused at the commit point, and a fresh verdict
    // refuses nothing at all.
    let stale = build(
        base_inputs(&operation)
            .with_arguments(arguments("protected-argument"))
            .with_mapping(mapping("other-mapping")),
    );
    let verdict = revalidate(&stale, &decision, &request(generation, 1));
    let refused = CommitPointResult::refused(verdict)
        .unwrap_or_else(|| unreachable!("a stale verdict refuses the admission"));
    let evidence = ApprovalAuditEvidence::record(&decision, refused)
        .unwrap_or_else(|_| unreachable!("a refusal is recorded under a positive decision"))
        .with_transition(AuditTransition::new(AuditTransitionKind::Expiry, 200))
        .with_transition(AuditTransition::new(AuditTransitionKind::Supersession, 210));
    let view = evidence.view(&access);
    assert_eq!(view.commit_point().wire_name(), "refused");
    assert!(!view.commit_point().is_admitted());
    assert_eq!(view.commit_point().admission(), None);
    assert_eq!(
        view.commit_point()
            .refusal()
            .and_then(RefusalReason::staleness),
        Some(StalenessReason::Mapping)
    );
    assert_eq!(view.transitions().len(), 2);
    assert!(view.canonical_text().contains("expiry@200"));
    assert!(view.canonical_text().contains("supersession@210"));
    assert_eq!(CommitPointResult::refused(Revalidation::Fresh), None);

    // A fenced admission records the fencing that refused it.
    let fenced = CommitPointResult::refused(Revalidation::Fenced(FenceReason::Revocation))
        .unwrap_or_else(|| unreachable!("a fenced verdict refuses the admission"));
    assert_eq!(
        fenced.refusal().and_then(RefusalReason::fence),
        Some(FenceReason::Revocation)
    );
}

/// The model is free of ambient facts: no constructor accepts a host path, an
/// environment value, a clock, or a locale, and every instant it revalidates is an
/// explicit logical instant the caller supplies.
#[test]
fn no_constructor_accepts_a_host_path_environment_value_clock_or_locale() {
    assert_not_impl_any!(
        ApprovalSubject: From<&'static str>,
        From<String>,
        From<std::path::PathBuf>,
        From<&'static std::path::Path>,
        From<std::ffi::OsString>,
        From<std::time::SystemTime>,
        From<std::time::Duration>,
        From<std::collections::HashMap<String, String>>,
        serde::Deserialize<'static>
    );
    assert_not_impl_any!(
        ApprovalSubjectInputs: From<std::path::PathBuf>,
        From<std::time::SystemTime>,
        From<std::ffi::OsString>
    );
    assert_not_impl_any!(
        ApprovalRequestId: From<&'static str>,
        From<String>,
        From<std::path::PathBuf>,
        From<std::time::SystemTime>,
        serde::Deserialize<'static>
    );
    assert_not_impl_any!(
        AuthenticatedActor: From<&'static str>,
        From<String>,
        From<std::path::PathBuf>,
        From<std::time::SystemTime>,
        serde::Deserialize<'static>
    );
    assert_not_impl_any!(
        ApprovalDecision: From<std::path::PathBuf>,
        From<std::time::SystemTime>,
        From<std::ffi::OsString>
    );
    assert_not_impl_any!(
        StandingLease: From<std::path::PathBuf>,
        From<std::time::SystemTime>,
        From<std::ffi::OsString>
    );

    // Host spellings are refused where a validated digest or a declared name is
    // required, and the rejection is a typed condition rather than a silent
    // reinterpretation.
    let rejected = MappingRevision::from_hex("/etc/gantry/mapping.json").err();
    assert_eq!(
        rejected.as_ref().and_then(|error| error.code()),
        Some(ApprovalDiagnosticCode::InvalidDigest)
    );
    assert!(PolicyRevision::from_hex("de_DE.UTF-8").is_err());
    assert!(SemanticArgumentDigest::from_hex("2026-02-11T12:00:00Z").is_err());
    assert!(HostAuthorityDigest::from_hex("./relative/host.sock").is_err());
    assert!(DeclaredName::new("GANTRY_APPROVER=alice").is_err());
    assert!(DeclaredName::new("").is_err());
    assert!(
        HostAuthorityDigest::from_hex("/tmp/approver").is_err(),
        "a host path is never a declared identity and never a digest"
    );

    // Expiry is an explicit logical instant: revalidation reads it from the
    // admission request alone and never from a clock.
    let operation = operation_id("crate::read_only", &[0, 1]);
    let subject = subject_of(&operation);
    let decision = decision(&subject);
    let generation = subject.generation();
    let bound = decision.expires_at_us();
    assert_eq!(bound, 100);
    assert_eq!(
        revalidate(&subject, &decision, &request(generation, bound - 1)),
        Revalidation::Fresh
    );
    assert_eq!(
        revalidate(&subject, &decision, &request(generation, bound)),
        Revalidation::Fenced(FenceReason::Expiry)
    );
    assert_eq!(
        revalidate(&subject, &decision, &request(generation, 0)),
        Revalidation::Fresh,
        "the logical instant of admission is the caller's, not the wall clock's"
    );

    // The one ambient fact the model does take is a host-attested binding, and
    // the attestation kind is part of the value it produces.
    let authority = digest(&hex("host-authority"), HostAuthorityDigest::from_hex);
    let session =
        HostAttestationBindingId::new(HostAttestationKind::HostSession, authority.clone());
    let service = HostAttestationBindingId::new(HostAttestationKind::HostService, authority);
    assert_ne!(session.as_str(), service.as_str());
    assert_eq!(session.kind(), HostAttestationKind::HostSession);
    assert_eq!(service.kind(), HostAttestationKind::HostService);
    assert_eq!(
        HostAttestationKind::from_wire_name("host-session"),
        Some(HostAttestationKind::HostSession)
    );
    assert_eq!(HostAttestationKind::from_wire_name("session"), None);
    assert_eq!(actor().binding().as_str(), session.as_str());
    assert_ne!(actor().binding().as_str(), service.as_str());
    assert_eq!(actor().attestation(), HostAttestationKind::HostSession);
    assert!(
        actor()
            .canonical_text()
            .contains("attestation=host-session")
    );
}

/// Audit evidence records an admission only for the positive decision of the subject
/// that admission belongs to: a denial admits nothing, and an admission of another
/// authority generation or another settlement rule is not the subject's admission.
/// Without those checks the audit record could attribute admitted work to an
/// approval that never covered it.
#[test]
fn approval_audit_admission_must_match_the_decision_subject() {
    let operation = operation_id("crate::read_only", &[0, 1]);
    let subject = subject_of(&operation);
    let decision = decision(&subject);
    let generation = subject.generation();
    let admission = admission_of(
        generation,
        RecoveryClass::ReadOnly,
        AuthorityRight::InvokeReadOnly,
    );

    // The positive decision of the admitted subject is recorded with the admission
    // the authority instance committed, and the view reports that admission.
    let admitted = ApprovalAuditEvidence::record(&decision, CommitPointResult::admitted(admission))
        .unwrap_or_else(|_| unreachable!("the admission is of this subject"));
    let view = admitted.view(&audit_access());
    assert!(view.commit_point().is_admitted());
    assert_eq!(view.commit_point().admission(), Some(&admission));
    assert_eq!(
        view.commit_point()
            .admission()
            .map(|admission| admission.generation()),
        Some(generation)
    );
    assert_eq!(
        view.commit_point()
            .admission()
            .map(|admission| admission.settlement_rule()),
        Some(subject.recovery())
    );

    // A denial admits nothing, so an admission recorded under it is refused under
    // its own code and its own anchored clause.
    let denial = ApprovalDecision::new(subject.clone(), ApprovalOutcome::Denial, &actor(), 0, None)
        .unwrap_or_else(|_| unreachable!("a one-shot decision needs no lease"));
    let admitted_under_denial =
        ApprovalAuditEvidence::record(&denial, CommitPointResult::admitted(admission)).err();
    assert_eq!(
        admitted_under_denial,
        Some(ApprovalError::AdmissionWithoutPositiveDecision)
    );
    assert_eq!(
        admitted_under_denial
            .as_ref()
            .and_then(|error| error.code()),
        Some(ApprovalDiagnosticCode::AdmissionWithoutPositiveDecision)
    );
    assert_eq!(
        admitted_under_denial
            .as_ref()
            .map(ApprovalError::requirement),
        Some("GNT-19.6-decision-linearization-and-revalidation")
    );

    // An admission of another authority generation is not this subject's admission.
    let mut descended = instance(&AUTHORITY_RIGHT_ORDER)
        .attenuate(
            RightsSet::from_rights(&[AuthorityRight::InvokeReadOnly]),
            AuthorityLeasePolicy::Unleased,
        )
        .unwrap_or_else(|_| unreachable!("the attenuation narrows the widest fixture instance"));
    let descended_generation = descended.generation();
    assert_ne!(descended_generation, generation);
    let other_generation = descended
        .admit(&request(descended_generation, 0), &AncestorFences::none())
        .unwrap_or_else(|_| unreachable!("the descendant admits read-only dispatch"));
    let foreign_generation =
        ApprovalAuditEvidence::record(&decision, CommitPointResult::admitted(other_generation))
            .err();
    assert_eq!(
        foreign_generation,
        Some(ApprovalError::AdmissionNotOfSubject)
    );
    assert_eq!(
        foreign_generation.as_ref().and_then(|error| error.code()),
        Some(ApprovalDiagnosticCode::AdmissionNotOfSubject)
    );
    assert_eq!(
        ApprovalError::AdmissionNotOfSubject.requirement(),
        "GNT-19.10-approval-audit-evidence"
    );

    // An admission that settles under another recovery class is not one either.
    let other_rule = admission_of(
        generation,
        RecoveryClass::NonIdempotent,
        AuthorityRight::InvokeNonIdempotent,
    );
    assert_eq!(
        ApprovalAuditEvidence::record(&decision, CommitPointResult::admitted(other_rule)).err(),
        Some(ApprovalError::AdmissionNotOfSubject),
        "another settlement rule is not this subject's admission"
    );

    // A refusal commit point is accepted under a positive decision and under a
    // denial alike, because a positive decision can be refused at the commit point.
    let stale = build(
        base_inputs(&operation)
            .with_arguments(arguments("other-arguments"))
            .with_mapping(mapping("other-mapping")),
    );
    let refused =
        CommitPointResult::refused(revalidate(&stale, &decision, &request(generation, 1)))
            .unwrap_or_else(|| unreachable!("a stale verdict refuses the admission"));
    assert!(
        ApprovalAuditEvidence::record(&decision, refused).is_ok(),
        "a positive decision refused at the commit point is still recorded"
    );
    assert!(
        ApprovalAuditEvidence::record(&denial, refused).is_ok(),
        "a denial refused at the commit point is still recorded"
    );
}

/// The audit capability is the declared-rights gate of the evidence store, not
/// cryptographic enforcement: it is issued for a rights set that contains the landed
/// observe right, which is the right of reading the audit record of an admitted
/// operation, and refused for every rights set without it.
#[test]
fn the_audit_capability_is_issued_only_for_the_observe_right() {
    assert_eq!(
        ApprovalAuditAccess::grant(RightsSet::from_rights(&[AuthorityRight::Observe])),
        Some(audit_access())
    );
    assert_eq!(
        ApprovalAuditAccess::grant(instance(&AUTHORITY_RIGHT_ORDER).rights()),
        Some(audit_access()),
        "the widest fixture instance carries observe"
    );

    for rights in [
        RightsSet::empty(),
        RightsSet::from_rights(&[AuthorityRight::InvokeReadOnly]),
        RightsSet::from_rights(&[
            AuthorityRight::InvokeIdempotent,
            AuthorityRight::InvokeNonIdempotent,
            AuthorityRight::Delegate,
        ]),
    ] {
        assert!(
            !rights.contains(AuthorityRight::Observe),
            "the refused fixture rights set carries no observe right"
        );
        assert_eq!(ApprovalAuditAccess::grant(rights), None);
    }
}

/// commit_decision is the only path to the decision cut, and the decision cut is the
/// only cut that may be committed without one: the admitted cut additionally requires
/// a committed decision whose outcome granted the request. Without those gates an
/// admission or a dispatch could be committed for a decision the interaction never
/// held, and the request identity rule could be bypassed.
#[test]
fn durable_cuts_require_a_committed_positive_decision() {
    let operation = operation_id("crate::read_only", &[0, 1]);
    let subject = subject_of(&operation);
    let request_cut = DurableApprovalCut::RequestCommitted;
    let decision_cut = DurableApprovalCut::DecisionCommitted;
    let admitted_cut = DurableApprovalCut::Admitted;
    let record = DurableApprovalRecord::commit_request(&subject);
    assert_eq!(record.decision(), None);
    assert_eq!(record.outcome(), None);

    // Advancing to the decision cut without committing a decision is refused, and the
    // admitted cut is not the immediate successor of the request cut, so no committed
    // state is ever skipped.
    assert_eq!(
        record.clone().advance(decision_cut).err(),
        Some(ApprovalError::DecisionNotCommitted { to: decision_cut })
    );
    assert_eq!(
        record.clone().advance(admitted_cut).err(),
        Some(ApprovalError::CutOutOfOrder {
            from: request_cut,
            to: admitted_cut,
        })
    );

    // A decision of another subject is not the decision of the committed request, and
    // the refusal names the request identity the decision presented.
    let foreign_subject = subject_of(&operation_id("crate::other_action", &[0, 1]));
    let not_of_request = record
        .clone()
        .commit_decision(&decision(&foreign_subject))
        .err();
    assert_eq!(
        not_of_request.as_ref().and_then(|error| error.code()),
        Some(ApprovalDiagnosticCode::DecisionNotOfRequest)
    );
    assert_eq!(
        not_of_request.as_ref().map(ApprovalError::requirement),
        Some("GNT-19.7-durable-request-and-decision-cuts")
    );
    assert!(not_of_request.as_ref().is_some_and(|error| {
        error
            .to_string()
            .contains(ApprovalRequestId::of(&foreign_subject).as_str())
    }));
    assert_eq!(
        record.cut(),
        request_cut,
        "a refused decision commit records nothing"
    );

    // commit_decision records the decision identity and the outcome it committed, and
    // the decision cut is committed exactly once.
    let positive = decision(&subject);
    let committed = record
        .clone()
        .commit_decision(&positive)
        .unwrap_or_else(|_| unreachable!("the decision is of the committed request"));
    assert_eq!(committed.cut(), decision_cut);
    assert_eq!(committed.decision(), Some(&positive.id()));
    assert_eq!(committed.outcome(), Some(ApprovalOutcome::PositiveDecision));
    assert_eq!(
        committed.clone().commit_decision(&positive).err(),
        Some(ApprovalError::CutOutOfOrder {
            from: decision_cut,
            to: decision_cut,
        }),
        "the decision cut is committed once"
    );
    assert!(
        committed.clone().advance(admitted_cut).is_ok(),
        "a committed positive decision admits"
    );

    // A committed decision that denied the request cannot reach the admitted cut, and
    // the refused advance leaves the interaction at the decision cut.
    let denial = ApprovalDecision::new(subject.clone(), ApprovalOutcome::Denial, &actor(), 0, None)
        .unwrap_or_else(|_| unreachable!("a one-shot decision needs no lease"));
    let denied = record
        .clone()
        .commit_decision(&denial)
        .unwrap_or_else(|_| unreachable!("the denial is of the committed request"));
    assert_eq!(denied.outcome(), Some(ApprovalOutcome::Denial));
    assert_eq!(
        denied.clone().advance(admitted_cut).err(),
        Some(ApprovalError::AdmissionWithoutPositiveDecision)
    );
    assert_eq!(
        denied
            .clone()
            .advance(admitted_cut)
            .err()
            .and_then(|error| error.code()),
        Some(ApprovalDiagnosticCode::AdmissionWithoutPositiveDecision)
    );
    assert_eq!(
        denied.cut(),
        decision_cut,
        "a refused advance records nothing"
    );
}

/// `release_grant` is the only path from a decision to a release permission, so it
/// enforces the whole correspondence between them: the holder authority, the
/// decision's validity bound, a standing lease that still permits the instant, the
/// release site's declared projection for the subject's class and destination, and the
/// disclosure budget's charge all have to agree with the subject before a grant is
/// derived. A weaker projection, another charge, or a revoked lease would otherwise
/// release data the decision never covered.
#[test]
fn release_grant_requires_a_matching_site_budget_instant_and_lease() {
    let operation = operation_id("crate::read_only", &[0, 1]);
    let class = ProtectedDataClass::ActionArgument;
    let destination = ReleaseDestination::OrdinarySource;
    let subject = subject_of(&operation);
    assert_eq!(subject.scope().class(), class);
    assert_eq!(subject.scope().destination(), destination);
    assert_eq!(
        subject.scope().projection().kind(),
        ProjectionKind::Redacted
    );
    assert_eq!(subject.scope().charge().value(), 1);
    let decision = decision(&subject);
    let authority = holder(&[class], &[destination]);
    let release_site = ReleaseSite::new(SITE).declare(class, destination, ProjectionKind::Redacted);
    let budget = DisclosureBudget::new(1, charge(1));

    // The matching site, budget, and instant still derive the narrowed grant.
    let grant = decision
        .release_grant(&authority, &release_site, &budget, 0)
        .unwrap_or_else(|| unreachable!("the site, budget, and instant match the subject"));
    assert!(grant.covers(class, destination));

    // A site that declares a weaker projection than the decision, a site that
    // declares nothing for the subject's class, a budget charging another amount, and
    // an instant at the decision's own validity bound all refuse the release.
    let weaker = ReleaseSite::new(SITE).declare(class, destination, ProjectionKind::Structural);
    assert_eq!(
        decision.release_grant(&authority, &weaker, &budget, 0),
        None,
        "a weaker projection than the decision declares releases nothing"
    );
    assert_eq!(
        decision.release_grant(&authority, &ReleaseSite::new(SITE), &budget, 0),
        None,
        "a site that declares no class of the subject releases nothing"
    );
    assert_eq!(
        decision.release_grant(
            &authority,
            &release_site,
            &DisclosureBudget::new(10, charge(2)),
            0
        ),
        None,
        "a budget charging another amount than the decision declares releases nothing"
    );
    assert_eq!(
        decision.release_grant(&authority, &release_site, &budget, decision.expires_at_us()),
        None,
        "the decision's own validity bound fences the release"
    );

    // A decision standing on a revoked lease releases nothing although the same
    // decision on a live lease does and although both still grant the request:
    // revocation removes a release permission that approval never restores.
    let parent = instance_with(
        &AUTHORITY_RIGHT_ORDER,
        AuthorityLeasePolicy::Expiring { expires_at_us: 100 },
    );
    let live = lease_of(
        &parent,
        &[AuthorityRight::Observe, AuthorityRight::InvokeReadOnly],
        50,
        RevocationContract::IssuerOrHolder,
    );
    let mut revoked = lease_of(
        &parent,
        &[AuthorityRight::Observe, AuthorityRight::InvokeReadOnly],
        50,
        RevocationContract::IssuerOrHolder,
    );
    revoked
        .revoke(parent.id())
        .unwrap_or_else(|_| unreachable!("the issuer may revoke under this contract"));
    assert!(revoked.is_revoked());
    let live_decision = leased_decision(&operation, live);
    let revoked_decision = leased_decision(&operation, revoked);
    assert!(live_decision.is_positive());
    assert!(revoked_decision.is_positive());
    assert!(
        live_decision
            .release_grant(&authority, &release_site, &budget, 10)
            .is_some(),
        "a live lease still releases"
    );
    assert_eq!(
        revoked_decision.release_grant(&authority, &release_site, &budget, 10),
        None,
        "a revoked lease releases nothing"
    );
}

/// The declared revocation contract is the holder mapping. An issuer-only lease admits
/// only the issuer, which is the immediate ancestor of the lease instance in its
/// lineage, and an issuer-or-holder lease admits the lease holder as well. A revoker the
/// contract does not admit is refused without fencing, so a party the contract does not
/// name can never fence a live lease, while a repeated permitted revocation keeps the
/// point the lease already held.
#[test]
fn revocation_contract_names_its_permitted_revokers() {
    let parent = instance_with(
        &AUTHORITY_RIGHT_ORDER,
        AuthorityLeasePolicy::Expiring { expires_at_us: 100 },
    );
    let mut issuer_only = lease_of(
        &parent,
        &[AuthorityRight::Observe],
        50,
        RevocationContract::IssuerOnly,
    );
    assert_eq!(issuer_only.instance().parent(), Some(parent.id()));
    assert_eq!(issuer_only.root(), parent.root());

    // Under IssuerOnly the holder is refused and nothing is fenced.
    let holder_id = issuer_only.id().clone();
    assert_eq!(
        issuer_only.revoke(&holder_id).err(),
        Some(ApprovalError::RevocationNotContractual)
    );
    assert!(!issuer_only.is_revoked());
    assert_eq!(issuer_only.fenced(), None);

    // Under IssuerOnly the issuer may revoke, and a repeated revocation returns the
    // point the lease already held.
    let point = issuer_only
        .revoke(parent.id())
        .unwrap_or_else(|_| unreachable!("the issuer may revoke under an issuer-only contract"));
    assert_eq!(point.category(), FenceCategory::Revocation);
    assert!(issuer_only.is_revoked());
    assert_eq!(
        issuer_only
            .revoke(parent.id())
            .unwrap_or_else(|_| unreachable!("a repeated revocation returns its point"))
            .linearization_point(),
        point.linearization_point()
    );

    // Under IssuerOrHolder the lease holder may revoke.
    let mut by_holder = lease_of(
        &parent,
        &[AuthorityRight::Observe],
        50,
        RevocationContract::IssuerOrHolder,
    );
    let holder_id = by_holder.id().clone();
    assert_eq!(
        by_holder
            .revoke(&holder_id)
            .unwrap_or_else(|_| unreachable!("the holder may revoke under this contract"))
            .category(),
        FenceCategory::Revocation
    );

    // Under IssuerOrHolder the issuer may revoke as well, and for a lease taken
    // directly from a root instance the issuer is that root.
    let mut from_root = lease_of(
        &parent,
        &[AuthorityRight::Observe],
        50,
        RevocationContract::IssuerOrHolder,
    );
    assert_eq!(from_root.instance().lineage().last(), Some(parent.id()));
    let root_id = from_root.root().clone();
    assert_eq!(
        from_root
            .revoke(&root_id)
            .unwrap_or_else(|_| unreachable!("the root is the issuer of its first descendant"))
            .category(),
        FenceCategory::Revocation
    );
}
