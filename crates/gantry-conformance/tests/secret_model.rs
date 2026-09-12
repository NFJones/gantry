//! Machine-checked conformance for the opaque secret and credential model of
//! `GNT-GP-SECRET-001`.
//!
//! These tests exercise the public `gantry::ir` surface of the landed authority
//! model (`GNT-3-T-AUTHORITY-INSTANCES`, `GNT-3-T-AUTHORITY-LINEAGE`,
//! `GNT-3-T-AUTHORITY-REVOCATION`, `GNT-3-T-AUTHORITY-ADMISSION`), the protected
//! class vocabulary of `GNT-15.10-protected-values`, and the cancellation rule of
//! `GNT-20.6-ambiguous-effect-classification-and-retry-eligibility`. They check
//! the model the specification makes normative, not a credential store: no test
//! here observes a live credential, a host adapter, a sink, or a secret value.
//!
//! The model holds no material at all, so the redaction and serialization
//! negatives are stated against a declared sentinel value: a rendering that
//! carried material, or a digest of material, would have to contain it.

use std::collections::BTreeSet;

use gantry::ir::generated::RecoveryClass;
use gantry::ir::{
    AdmissionRequest, AncestorFences, AuditTransition, AuditTransitionKind, AuthorityBindingId,
    AuthorityError, AuthorityGeneration, AuthorityInstance, AuthorityLeasePolicy,
    AuthorityRequirementId, AuthorityRight, CanonicalImplementationIdentity, CanonicalPath,
    CanonicalSignature, DeclaredName, DurableOperationCut, DurableSecretReference, EffectCertainty,
    ExternalOutcome, FenceCategory, FencePoint, FenceReason, FenceState, LogicalOperationId,
    OperationCancellation, ProtectedDataClass, RightsSet, SECRET_NON_CLAIM_ORDER,
    SECRET_NON_CLAIMS, SECRET_OWNING_CLAUSE, SecretAuditAccess, SecretAuditEvidence,
    SecretAuditOutcome, SecretDurableCut, SecretError, SecretHolderBindingId, SecretNonClaimName,
    SecretReference, SecretReferenceId, SecretResumeClass, SecretRevalidation,
    SecretStalenessReason, StaticSiteId, StructuralPosition, TypeDescriptor, TypeExpression,
    classify_effect, revalidate_secret,
};
use sha2::{Digest, Sha256};

/// Compile-time proof that one type implements none of the listed traits.
///
/// A blanket implementation and a trait-bounded implementation both apply, so
/// naming the associated item requires an inference that cannot be resolved and
/// compilation fails. A secret reference that acquired `Clone`, a serializer, a
/// deserializer, a rendering trait, or an ordinary conversion out of one, and an
/// audit capability that acquired `Default`, would each stop this crate
/// compiling, which is exactly what `GNT-GP-SECRET-001` forbids.
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

/// The capability family of every fixture requirement.
const FAMILY: &str = "action";

/// The capability family of the unrelated requirement fixture.
const OTHER_FAMILY: &str = "resource";

/// The declared tenant of the primary fixture reference.
const TENANT: &str = "tenant-acme";

/// The declared tenant of the foreign fixture reference.
const OTHER_TENANT: &str = "tenant-globex";

/// A value that stands for secret material no rendering may carry.
const MATERIAL_SENTINEL: &str = "SECRET-MATERIAL-MUST-NEVER-RENDER";

/// Returns one deterministic lowercase hexadecimal digest of one seed.
fn digest_hex(seed: &str) -> String {
    format!("{:x}", Sha256::digest(seed.as_bytes()))
}

/// Builds one canonical fixture path.
fn path(value: &str) -> CanonicalPath {
    CanonicalPath::new(value).unwrap_or_else(|_| unreachable!("fixture path is canonical"))
}

/// Validates one fixture declared name.
fn name(value: &str) -> DeclaredName {
    DeclaredName::new(value).unwrap_or_else(|_| unreachable!("fixture name is canonical"))
}

/// Builds the downstream integration identity of every fixture binding.
fn integration() -> CanonicalImplementationIdentity {
    let receiver = TypeExpression::from_canonical_string("crate::SecretFixture", 4)
        .unwrap_or_else(|_| unreachable!("fixture receiver is a canonical type"));
    CanonicalImplementationIdentity::inherent(&receiver)
}

/// Builds the canonical action signature of every fixture requirement.
fn signature() -> CanonicalSignature {
    CanonicalSignature::action(
        RecoveryClass::ReadOnly,
        &path("crate::read_only"),
        &[],
        &TypeDescriptor::STRING,
    )
}

/// Builds the public capability requirement of one fixture family.
fn requirement_of(family: &str) -> AuthorityRequirementId {
    AuthorityRequirementId::new(
        &path("crate::read_only"),
        &signature(),
        family,
        RecoveryClass::ReadOnly,
    )
    .unwrap_or_else(|_| unreachable!("fixture family is portable"))
}

/// Builds the public capability requirement every fixture reference satisfies.
fn requirement() -> AuthorityRequirementId {
    requirement_of(FAMILY)
}

/// Builds one selected implementation binding for a requirement.
fn binding_of(requirement: &AuthorityRequirementId) -> AuthorityBindingId {
    AuthorityBindingId::new(requirement, &integration())
}

/// Builds one fixture capability instance of the named rights and lease.
fn instance_with(rights: &[AuthorityRight], lease: AuthorityLeasePolicy) -> AuthorityInstance {
    let requirement = requirement();
    let binding = binding_of(&requirement);
    AuthorityInstance::bind(
        requirement,
        binding,
        RightsSet::from_rights(rights),
        lease,
        false,
    )
    .unwrap_or_else(|_| unreachable!("the fixture binding satisfies its requirement"))
}

/// Builds one capability instance of a named requirement, binding, and lease.
fn instance_for(
    requirement: &AuthorityRequirementId,
    binding: &AuthorityBindingId,
    rights: RightsSet,
    lease: AuthorityLeasePolicy,
) -> AuthorityInstance {
    AuthorityInstance::bind(requirement.clone(), binding.clone(), rights, lease, false)
        .unwrap_or_else(|_| unreachable!("the fixture binding satisfies its requirement"))
}

/// Builds one strict successor instance of a fixture instance.
fn attenuation(instance: &AuthorityInstance) -> AuthorityInstance {
    instance
        .attenuate(instance.rights(), instance.lease())
        .unwrap_or_else(|_| unreachable!("equal rights and an equal lease attenuate"))
}

/// The rights of the narrowest fixture instance.
fn read_only_rights() -> RightsSet {
    RightsSet::from_rights(&[AuthorityRight::InvokeReadOnly])
}

/// The rights of a fixture instance that may also delegate.
fn delegating_rights() -> RightsSet {
    RightsSet::from_rights(&[AuthorityRight::InvokeReadOnly, AuthorityRight::Delegate])
}

/// The rights of a fixture holder that may observe an audit record.
fn observing_rights() -> RightsSet {
    RightsSet::from_rights(&[AuthorityRight::Observe])
}

/// Builds one exact operation site of the fixture workflow.
fn site(components: &[u64]) -> StaticSiteId {
    let position = StructuralPosition::new(components.to_vec())
        .unwrap_or_else(|_| unreachable!("fixture structural position is nonempty"));
    StaticSiteId::new(path("crate::workflow"), position)
}

/// Derives one stable logical operation identity.
fn operation(declaration: &str, components: &[u64]) -> LogicalOperationId {
    LogicalOperationId::derive(&path(declaration), &site(components))
}

/// Builds one admission request against a known generation.
fn request(
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

/// Binds one fixture secret reference over one existing instance.
fn secret_of(
    instance: AuthorityInstance,
    class: ProtectedDataClass,
    tenant: &str,
    operation: Option<LogicalOperationId>,
) -> SecretReference {
    SecretReference::bind(instance, class, name(tenant), operation)
        .unwrap_or_else(|_| unreachable!("the fixture instance carries rights and a live lease"))
}

/// Binds one fixture secret reference of the named rights and lease.
fn reference_with(
    rights: &[AuthorityRight],
    lease: AuthorityLeasePolicy,
    class: ProtectedDataClass,
    tenant: &str,
    operation: Option<LogicalOperationId>,
) -> SecretReference {
    secret_of(instance_with(rights, lease), class, tenant, operation)
}

/// Binds one fixture reference together with one strict successor instance.
fn reference_with_successor(
    rights: &[AuthorityRight],
    class: ProtectedDataClass,
    tenant: &str,
    operation: Option<LogicalOperationId>,
) -> (SecretReference, AuthorityInstance) {
    let holder = instance_with(rights, AuthorityLeasePolicy::Unleased);
    let successor = attenuation(&holder);
    (secret_of(holder, class, tenant, operation), successor)
}

/// Mints the secret-audit capability of the primary fixture tenant.
fn audit_access() -> SecretAuditAccess {
    SecretAuditAccess::grant(observing_rights(), &name(TENANT))
        .unwrap_or_else(|| unreachable!("the observe right mints the secret-audit capability"))
}

#[test]
fn secret_references_are_opaque_and_never_serializable_or_material_readable() {
    assert_not_impl_any!(
        SecretReference: Clone,
        serde::Serialize,
        serde::Deserialize<'static>,
        std::fmt::Display,
        PartialEq
    );
    assert_not_impl_any!(
        SecretReferenceId: serde::Serialize,
        serde::Deserialize<'static>,
        std::fmt::Display
    );
    assert_not_impl_any!(
        DurableSecretReference: serde::Serialize,
        serde::Deserialize<'static>,
        std::fmt::Display
    );
    assert_not_impl_any!(
        SecretAuditEvidence: serde::Serialize,
        serde::Deserialize<'static>,
        std::fmt::Display
    );
    assert_not_impl_any!(
        SecretHolderBindingId: serde::Serialize,
        serde::Deserialize<'static>,
        std::fmt::Display
    );
    assert_not_impl_any!(SecretAuditAccess: Default, serde::Deserialize<'static>);
    assert_not_impl_any!(String: From<SecretReference>, From<DurableSecretReference>);

    // The model holds no material, so no rendering can carry it: the sentinel is
    // the exact text a leak would have to contain.
    let reference = reference_with(
        &[AuthorityRight::InvokeReadOnly, AuthorityRight::Delegate],
        AuthorityLeasePolicy::Unleased,
        ProtectedDataClass::ActionArgument,
        TENANT,
        Some(operation("crate::secret_use", &[0, 1])),
    );
    let material_digest = digest_hex(MATERIAL_SENTINEL);
    for rendering in [reference.redacted_text(), format!("{reference:?}")] {
        assert!(!rendering.contains(MATERIAL_SENTINEL));
        assert!(!rendering.contains(&material_digest));
    }
    let redacted = reference.redacted_text();
    assert!(redacted.contains("class=action-argument"));
    assert!(redacted.contains(&format!("tenant={TENANT}")));

    // The exclusions the bounded claim relies on are declared, not implied.
    assert_eq!(
        SecretError::ExtractionForbidden.code(),
        "secret-extraction-forbidden"
    );
    assert_eq!(
        SecretError::SerializationForbidden.code(),
        "secret-serialization-forbidden"
    );
    assert_eq!(SECRET_NON_CLAIMS.len(), 5);
    assert_eq!(
        SECRET_NON_CLAIMS
            .iter()
            .filter(|claim| claim.is_not_promised())
            .count(),
        3
    );
    assert_eq!(
        SECRET_NON_CLAIMS
            .iter()
            .filter(|claim| claim.is_prohibited())
            .count(),
        2
    );
    assert_eq!(
        SECRET_NON_CLAIMS
            .iter()
            .map(|claim| claim.name())
            .collect::<Vec<_>>(),
        SECRET_NON_CLAIM_ORDER.to_vec()
    );
    assert!(SECRET_NON_CLAIMS.iter().any(|claim| {
        claim.name() == SecretNonClaimName::OrdinaryExtraction && claim.is_prohibited()
    }));
    assert!(SECRET_NON_CLAIMS.iter().any(|claim| {
        claim.name() == SecretNonClaimName::CheckpointSerialization && claim.is_prohibited()
    }));
    assert!(SECRET_NON_CLAIMS.iter().any(|claim| {
        claim.name() == SecretNonClaimName::PhysicalZeroization && claim.is_not_promised()
    }));
    assert_eq!(
        SecretNonClaimName::from_wire_name("bearer-without-lineage"),
        Some(SecretNonClaimName::BearerWithoutLineage)
    );
    assert_eq!(
        SecretNonClaimName::from_wire_name("material-accessor"),
        None
    );

    // The exclusions are behavior-level: what the model prohibits is declared as
    // a prohibition and the remaining three are declared as properties it does
    // not promise, so the negative above rests on no sentinel value.
    let prohibited = SECRET_NON_CLAIMS
        .iter()
        .filter(|claim| claim.is_prohibited())
        .map(|claim| claim.name())
        .collect::<Vec<_>>();
    assert_eq!(
        prohibited,
        vec![
            SecretNonClaimName::OrdinaryExtraction,
            SecretNonClaimName::CheckpointSerialization
        ]
    );
    let not_promised = SECRET_NON_CLAIMS
        .iter()
        .filter(|claim| claim.is_not_promised())
        .map(|claim| claim.name())
        .collect::<Vec<_>>();
    assert_eq!(
        not_promised,
        vec![
            SecretNonClaimName::PhysicalZeroization,
            SecretNonClaimName::AmbientDiscovery,
            SecretNonClaimName::BearerWithoutLineage
        ]
    );

    // Every refusal of the vocabulary is one distinct code, and every code names
    // a clause of Section 21, including the refusals of the landed authority model
    // that this module passes through unchanged.
    let vocabulary = [
        SecretError::Authority(AuthorityError::EmptyRights),
        SecretError::TenantMismatch,
        SecretError::TenantChangeForbidden,
        SecretError::OperationMismatch,
        SecretError::ClassChangeForbidden,
        SecretError::StaleGeneration,
        SecretError::Fenced(FenceCategory::Revocation),
        SecretError::TransferNotSucceeding,
        SecretError::TransferHolderMismatch,
        SecretError::RebindRequirementMismatch,
        SecretError::ReinstatementForbidden,
        SecretError::InadmissibleAuditRecord,
        SecretError::SerializationForbidden,
        SecretError::ExtractionForbidden,
    ];
    let codes = vocabulary
        .iter()
        .map(SecretError::code)
        .collect::<BTreeSet<_>>();
    assert_eq!(codes.len(), vocabulary.len());
    // Two refusals of the landed authority model share one code, because the code
    // names the condition the module reports rather than the inner detail.
    assert_eq!(
        SecretError::Authority(AuthorityError::EmptyRights).code(),
        SecretError::Authority(AuthorityError::AmplifiedRights).code()
    );
    // The fence category is carried by the refusal and its rendering rather than
    // by the code, so both categories still share one code.
    assert_eq!(
        SecretError::Fenced(FenceCategory::Revocation).code(),
        SecretError::Fenced(FenceCategory::Expiry).code()
    );
    for refusal in vocabulary {
        assert!(
            refusal.clause().starts_with("GNT-21."),
            "{} names no clause of Section 21",
            refusal.code()
        );
    }
}

#[test]
fn secret_reference_identity_is_domain_separated_and_carries_no_material() {
    let class = ProtectedDataClass::ActionArgument;
    let use_operation = operation("crate::secret_use", &[0, 1]);
    let other_operation = operation("crate::secret_use", &[0, 2]);
    let baseline = reference_with(
        &[AuthorityRight::InvokeReadOnly],
        AuthorityLeasePolicy::Unleased,
        class,
        TENANT,
        Some(use_operation.clone()),
    );
    let id = baseline.id();
    assert!(id.as_str().starts_with("secret-reference:"));
    assert_eq!(id.digest_hex().len(), 64);
    assert!(
        id.digest_hex()
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte.is_ascii_lowercase())
    );

    // Equality and hashing use the derived identity only, so equal inputs are one
    // identity rather than two.
    let repeated = reference_with(
        &[AuthorityRight::InvokeReadOnly],
        AuthorityLeasePolicy::Unleased,
        class,
        TENANT,
        Some(use_operation.clone()),
    );
    let mut identities = BTreeSet::new();
    identities.insert(baseline.id().clone());
    identities.insert(repeated.id().clone());
    assert_eq!(identities.len(), 1);
    assert_eq!(baseline.id(), repeated.id());

    // Derivation is domain separated: the identity is not a naive re-hash of one
    // identity input, and it never carries input text or material.
    let requirement_text = requirement();
    assert_ne!(id.digest_hex(), digest_hex(requirement_text.as_str()));
    assert_ne!(id.digest_hex(), digest_hex(TENANT));
    assert_ne!(id.digest_hex(), digest_hex(MATERIAL_SENTINEL));
    assert!(!id.as_str().contains(TENANT));
    assert!(!id.as_str().contains(MATERIAL_SENTINEL));

    // A distinct tenant, operation, class, or generation derives a distinct id.
    for changed in [
        reference_with(
            &[AuthorityRight::InvokeReadOnly],
            AuthorityLeasePolicy::Unleased,
            class,
            OTHER_TENANT,
            Some(use_operation.clone()),
        ),
        reference_with(
            &[AuthorityRight::InvokeReadOnly],
            AuthorityLeasePolicy::Unleased,
            class,
            TENANT,
            Some(other_operation),
        ),
        reference_with(
            &[AuthorityRight::InvokeReadOnly],
            AuthorityLeasePolicy::Unleased,
            class,
            TENANT,
            None,
        ),
        reference_with(
            &[AuthorityRight::InvokeReadOnly],
            AuthorityLeasePolicy::Unleased,
            ProtectedDataClass::SessionIdentifier,
            TENANT,
            Some(use_operation.clone()),
        ),
    ] {
        assert_ne!(baseline.id(), changed.id());
    }
    let holder = instance_with(
        &[AuthorityRight::InvokeReadOnly],
        AuthorityLeasePolicy::Unleased,
    );
    let successor = attenuation(&holder);
    let first = secret_of(holder, class, TENANT, Some(use_operation.clone()));
    let second = secret_of(successor, class, TENANT, Some(use_operation));
    assert_eq!(second.generation().value(), first.generation().value() + 1);
    assert_ne!(first.id(), second.id());
}

#[test]
fn a_secret_reference_binds_holder_requirement_binding_operation_and_tenant() {
    let requirement = requirement();
    let binding = binding_of(&requirement);
    let class = ProtectedDataClass::ActionArgument;
    let use_operation = operation("crate::secret_use", &[0, 1]);
    let other_operation = operation("crate::secret_use", &[0, 2]);
    let holder = instance_for(
        &requirement,
        &binding,
        read_only_rights(),
        AuthorityLeasePolicy::Unleased,
    );
    let holder_id = holder.id().clone();
    let reference = secret_of(holder, class, TENANT, Some(use_operation.clone()));

    // The holder binding names the requirement, the selected binding, and the
    // concrete instance, so it is derived rather than written by hand.
    assert_eq!(reference.holder().requirement(), &requirement);
    assert_eq!(reference.holder().binding(), &binding);
    assert_eq!(reference.holder().holder(), &holder_id);
    assert!(reference.holder().as_str().starts_with("secret-holder:"));
    assert!(reference.holder().as_str().contains(binding.as_str()));
    let identical = instance_for(
        &requirement,
        &binding,
        read_only_rights(),
        AuthorityLeasePolicy::Unleased,
    );
    assert_eq!(
        reference.holder().as_str(),
        SecretHolderBindingId::bind(&identical, &name(TENANT)).as_str()
    );
    // The tenant is part of the derived holder binding, so one instance presented
    // by another tenant never shares a holder with this reference.
    assert_ne!(
        reference.holder().as_str(),
        SecretHolderBindingId::bind(&identical, &name(OTHER_TENANT)).as_str()
    );

    // The reference names its class, tenant, operation, generation, and rights.
    assert_eq!(reference.class(), class);
    assert_eq!(reference.tenant().as_str(), TENANT);
    assert_eq!(
        reference.operation().map(LogicalOperationId::as_str),
        Some(use_operation.as_str())
    );
    assert_eq!(reference.generation(), AuthorityGeneration::INITIAL);
    assert_eq!(reference.rights(), read_only_rights());
    assert_eq!(reference.lease(), AuthorityLeasePolicy::Unleased);
    assert_eq!(reference.fence_state(), FenceState::Open);
    assert!(reference.accepted().is_empty());

    // One use of the bound operation and tenant is committed, and only one.
    let mut reference = reference;
    let current = request(
        AuthorityRight::InvokeReadOnly,
        RecoveryClass::ReadOnly,
        reference.generation(),
        0,
    );
    assert!(
        reference
            .admit_use(
                &current,
                &AncestorFences::none(),
                &use_operation,
                &name(TENANT)
            )
            .is_ok()
    );
    assert_eq!(reference.accepted().len(), 1);

    // Another operation or another tenant is refused before the commit point.
    assert_eq!(
        reference
            .admit_use(
                &current,
                &AncestorFences::none(),
                &other_operation,
                &name(TENANT)
            )
            .err(),
        Some(SecretError::OperationMismatch)
    );
    assert_eq!(
        reference
            .admit_use(
                &current,
                &AncestorFences::none(),
                &use_operation,
                &name(OTHER_TENANT)
            )
            .err(),
        Some(SecretError::TenantMismatch)
    );
    assert_eq!(reference.accepted().len(), 1);

    // Revalidation agrees with the same cross-checks and mutates nothing.
    let verdict: SecretRevalidation =
        revalidate_secret(&reference, &current, &use_operation, &name(TENANT));
    assert!(verdict.is_fresh());
    assert_eq!(
        reference
            .revalidate(&current, &other_operation, &name(TENANT))
            .staleness(),
        Some(SecretStalenessReason::Operation)
    );
    assert_eq!(
        reference
            .revalidate(&current, &use_operation, &name(OTHER_TENANT))
            .staleness(),
        Some(SecretStalenessReason::Tenant)
    );
    assert_eq!(reference.accepted().len(), 1);
}

#[test]
fn secret_attenuation_is_monotone_and_never_amplifies_rights_or_lease() {
    let class = ProtectedDataClass::ActionArgument;
    let use_operation = operation("crate::secret_use", &[0, 1]);
    let wide = reference_with(
        &[
            AuthorityRight::InvokeReadOnly,
            AuthorityRight::InvokeIdempotent,
            AuthorityRight::Delegate,
        ],
        AuthorityLeasePolicy::Expiring { expires_at_us: 500 },
        class,
        TENANT,
        Some(use_operation.clone()),
    );
    let narrowed = wide
        .attenuate(
            read_only_rights(),
            AuthorityLeasePolicy::Expiring { expires_at_us: 100 },
        )
        .unwrap_or_else(|_| unreachable!("a subset of the rights and a shorter lease attenuate"));
    assert!(narrowed.rights().is_strict_subset_of(wide.rights()));
    assert_eq!(narrowed.rights(), read_only_rights());
    assert_eq!(
        narrowed.lease(),
        AuthorityLeasePolicy::Expiring { expires_at_us: 100 }
    );
    assert_eq!(narrowed.class(), wide.class());
    assert_eq!(narrowed.tenant().as_str(), wide.tenant().as_str());
    assert_eq!(
        narrowed.operation().map(LogicalOperationId::as_str),
        wide.operation().map(LogicalOperationId::as_str)
    );
    assert_eq!(narrowed.generation().value(), wide.generation().value() + 1);
    assert_ne!(narrowed.id(), wide.id());
    assert_ne!(narrowed.holder().holder(), wide.holder().holder());

    // Amplification, a new right, and a longer or newly unleased lease are refused.
    assert_eq!(
        wide.attenuate(
            RightsSet::from_rights(&[
                AuthorityRight::InvokeReadOnly,
                AuthorityRight::InvokeIdempotent,
                AuthorityRight::InvokeNonIdempotent,
                AuthorityRight::Delegate,
            ]),
            AuthorityLeasePolicy::Expiring { expires_at_us: 500 },
        )
        .err(),
        Some(SecretError::Authority(AuthorityError::AmplifiedRights))
    );
    assert_eq!(
        wide.attenuate(
            read_only_rights(),
            AuthorityLeasePolicy::Expiring { expires_at_us: 600 }
        )
        .err(),
        Some(SecretError::Authority(AuthorityError::LeaseExceedsRoot))
    );
    assert_eq!(
        wide.attenuate(read_only_rights(), AuthorityLeasePolicy::Unleased)
            .err(),
        Some(SecretError::Authority(AuthorityError::LeaseExceedsRoot))
    );

    // Delegation is attenuation gated by the delegate right.
    let delegable = reference_with(
        &[AuthorityRight::InvokeReadOnly, AuthorityRight::Delegate],
        AuthorityLeasePolicy::Unleased,
        class,
        TENANT,
        Some(use_operation.clone()),
    );
    let delegated = delegable
        .delegate(read_only_rights(), AuthorityLeasePolicy::Unleased)
        .unwrap_or_else(|_| unreachable!("the delegate right permits delegation"));
    assert!(delegated.rights().is_strict_subset_of(delegable.rights()));
    assert_eq!(
        delegated.generation().value(),
        delegable.generation().value() + 1
    );
    assert_eq!(delegated.tenant().as_str(), delegable.tenant().as_str());
    let plain = reference_with(
        &[AuthorityRight::InvokeReadOnly],
        AuthorityLeasePolicy::Unleased,
        class,
        TENANT,
        Some(use_operation.clone()),
    );
    assert_eq!(
        plain
            .delegate(delegating_rights(), AuthorityLeasePolicy::Unleased)
            .err(),
        Some(SecretError::Authority(AuthorityError::MissingRight(
            AuthorityRight::Delegate
        )))
    );

    // A narrowed reference cannot admit a right it no longer holds.
    let mut idempotent_only = wide
        .attenuate(
            RightsSet::from_rights(&[AuthorityRight::InvokeIdempotent]),
            AuthorityLeasePolicy::Expiring { expires_at_us: 100 },
        )
        .unwrap_or_else(|_| unreachable!("a subset of the rights attenuates"));
    let denied = request(
        AuthorityRight::InvokeReadOnly,
        RecoveryClass::ReadOnly,
        idempotent_only.generation(),
        0,
    );
    assert_eq!(
        idempotent_only
            .admit_use(
                &denied,
                &AncestorFences::none(),
                &use_operation,
                &name(TENANT)
            )
            .err(),
        Some(SecretError::Authority(AuthorityError::MissingRight(
            AuthorityRight::InvokeReadOnly
        )))
    );
    assert!(idempotent_only.accepted().is_empty());
    assert_eq!(
        idempotent_only
            .revalidate(&denied, &use_operation, &name(TENANT))
            .staleness(),
        Some(SecretStalenessReason::Policy)
    );
}

#[test]
fn secret_transfer_is_affine_and_strictly_advances_the_generation() {
    let requirement = requirement();
    let binding = binding_of(&requirement);
    let class = ProtectedDataClass::ActionArgument;
    let use_operation = operation("crate::secret_use", &[0, 1]);
    let (reference, successor) = reference_with_successor(
        &[AuthorityRight::InvokeReadOnly],
        class,
        TENANT,
        Some(use_operation.clone()),
    );
    let id = reference.id().clone();
    let generation = reference.generation();
    let holder_id = reference.holder().holder().clone();

    // The affine move preserves identity, generation, rights, and holder.
    let moved = reference.transfer_affine();
    assert_eq!(moved.id(), &id);
    assert_eq!(moved.generation(), generation);
    assert_eq!(moved.holder().holder(), &holder_id);
    assert_eq!(moved.rights(), read_only_rights());

    // A strict successor advances the generation and re-derives the identity.
    let transferred = moved
        .transfer(successor)
        .unwrap_or_else(|_| unreachable!("the fixture successor strictly advances the holder"));
    assert_eq!(transferred.generation().value(), generation.value() + 1);
    assert_ne!(transferred.id(), &id);
    assert_ne!(transferred.holder().holder(), &holder_id);
    assert_eq!(transferred.class(), class);
    assert_eq!(transferred.tenant().as_str(), TENANT);
    assert_eq!(
        transferred.operation().map(LogicalOperationId::as_str),
        Some(use_operation.as_str())
    );
    assert_eq!(transferred.rights(), read_only_rights());

    // The superseded generation is stale, and the successor generation is fresh.
    let stale = request(
        AuthorityRight::InvokeReadOnly,
        RecoveryClass::ReadOnly,
        generation,
        0,
    );
    assert_eq!(
        transferred
            .revalidate(&stale, &use_operation, &name(TENANT))
            .staleness(),
        Some(SecretStalenessReason::Generation)
    );
    let current = request(
        AuthorityRight::InvokeReadOnly,
        RecoveryClass::ReadOnly,
        transferred.generation(),
        0,
    );
    assert!(
        transferred
            .revalidate(&current, &use_operation, &name(TENANT))
            .is_fresh()
    );

    // A sibling at the same generation, and another requirement's successor, are
    // both refused.
    let sibling = instance_for(
        &requirement,
        &binding,
        read_only_rights(),
        AuthorityLeasePolicy::Unleased,
    );
    let sibling_reference = reference_with(
        &[AuthorityRight::InvokeReadOnly],
        AuthorityLeasePolicy::Unleased,
        class,
        TENANT,
        Some(use_operation.clone()),
    );
    assert_eq!(
        sibling_reference.transfer(sibling).err(),
        Some(SecretError::TransferNotSucceeding)
    );
    let other_requirement = requirement_of(OTHER_FAMILY);
    let other_binding = binding_of(&other_requirement);
    let other_instance = instance_for(
        &other_requirement,
        &other_binding,
        read_only_rights(),
        AuthorityLeasePolicy::Unleased,
    );
    let other_reference = reference_with(
        &[AuthorityRight::InvokeReadOnly],
        AuthorityLeasePolicy::Unleased,
        class,
        TENANT,
        Some(use_operation.clone()),
    );
    assert_eq!(
        other_reference.transfer(other_instance).err(),
        Some(SecretError::TransferHolderMismatch)
    );
}

#[test]
fn a_fenced_secret_generation_is_refused_and_never_reinstated() {
    let requirement = requirement();
    let class = ProtectedDataClass::ActionArgument;
    let use_operation = operation("crate::secret_use", &[0, 1]);
    let mut reference = reference_with(
        &[AuthorityRight::InvokeReadOnly],
        AuthorityLeasePolicy::Unleased,
        class,
        TENANT,
        Some(use_operation.clone()),
    );
    let generation = reference.generation();
    assert_eq!(reference.fence_state(), FenceState::Open);

    let revoke = reference.revoke();
    assert_eq!(revoke.category(), FenceCategory::Revocation);
    assert_eq!(revoke.generation(), generation);
    // One revocation linearization point per generation: revoking again cannot
    // reinstate anything.
    assert_eq!(reference.revoke(), revoke);
    assert_eq!(
        reference.fence_state().point().map(FencePoint::category),
        Some(FenceCategory::Revocation)
    );
    // Expiry is latched independently and never relabels the revocation.
    let expire = reference.expire();
    assert_eq!(expire.category(), FenceCategory::Expiry);
    assert_eq!(
        reference.fence_state().point().map(FencePoint::category),
        Some(FenceCategory::Revocation)
    );

    // A fenced generation admits nothing and records no admission.
    let current = request(
        AuthorityRight::InvokeReadOnly,
        RecoveryClass::ReadOnly,
        generation,
        0,
    );
    assert_eq!(
        reference
            .admit_use(
                &current,
                &AncestorFences::none(),
                &use_operation,
                &name(TENANT)
            )
            .err(),
        Some(SecretError::Fenced(FenceCategory::Revocation))
    );
    assert!(reference.accepted().is_empty());
    assert_eq!(
        revalidate_secret(&reference, &current, &use_operation, &name(TENANT)).fence(),
        Some(FenceReason::Revocation)
    );
    assert_eq!(
        reference
            .revalidate(&current, &use_operation, &name(TENANT))
            .staleness(),
        None
    );

    // No successor path reinstates a fenced generation.
    let (mut fenced, successor) = reference_with_successor(
        &[AuthorityRight::InvokeReadOnly],
        class,
        TENANT,
        Some(use_operation.clone()),
    );
    fenced.revoke();
    assert_eq!(
        fenced.transfer(successor).err(),
        Some(SecretError::ReinstatementForbidden)
    );
    let mut rebound = reference_with(
        &[AuthorityRight::InvokeReadOnly],
        AuthorityLeasePolicy::Unleased,
        class,
        TENANT,
        Some(use_operation.clone()),
    );
    rebound.revoke();
    assert_eq!(
        rebound.rebind(binding_of(&requirement)).err(),
        Some(SecretError::ReinstatementForbidden)
    );
    // A fenced instance binds no fresh reference either.
    let mut expired = instance_with(
        &[AuthorityRight::InvokeReadOnly],
        AuthorityLeasePolicy::Unleased,
    );
    expired.expire();
    assert_eq!(
        SecretReference::bind(expired, class, name(TENANT), None).err(),
        Some(SecretError::Fenced(FenceCategory::Expiry))
    );
}

#[test]
fn a_stale_secret_generation_is_refused_without_latching_a_fence() {
    let class = ProtectedDataClass::ActionArgument;
    let use_operation = operation("crate::secret_use", &[0, 1]);
    let mut reference = reference_with(
        &[AuthorityRight::InvokeReadOnly],
        AuthorityLeasePolicy::Expiring { expires_at_us: 100 },
        class,
        TENANT,
        Some(use_operation.clone()),
    );
    let generation = reference.generation();
    let stale = request(
        AuthorityRight::InvokeReadOnly,
        RecoveryClass::ReadOnly,
        AuthorityGeneration::new(generation.value() + 1),
        0,
    );
    assert_eq!(
        reference
            .admit_use(
                &stale,
                &AncestorFences::none(),
                &use_operation,
                &name(TENANT)
            )
            .err(),
        Some(SecretError::StaleGeneration)
    );
    // A stale presentation latches no fence, records no admission, and asserts no
    // other staleness.
    assert_eq!(reference.fence_state(), FenceState::Open);
    assert!(reference.accepted().is_empty());
    let verdict: SecretRevalidation = reference.revalidate(&stale, &use_operation, &name(TENANT));
    assert_eq!(verdict.staleness(), Some(SecretStalenessReason::Generation));
    assert_eq!(verdict.fence(), None);
    assert_eq!(reference.fence_state(), FenceState::Open);

    // The current generation stays admissible until the lease reaches its expiry.
    let current = request(
        AuthorityRight::InvokeReadOnly,
        RecoveryClass::ReadOnly,
        generation,
        99,
    );
    assert!(
        reference
            .admit_use(
                &current,
                &AncestorFences::none(),
                &use_operation,
                &name(TENANT)
            )
            .is_ok()
    );
    let late = request(
        AuthorityRight::InvokeReadOnly,
        RecoveryClass::ReadOnly,
        generation,
        100,
    );
    assert_eq!(
        reference
            .admit_use(
                &late,
                &AncestorFences::none(),
                &use_operation,
                &name(TENANT)
            )
            .err(),
        Some(SecretError::Fenced(FenceCategory::Expiry))
    );
    assert_eq!(
        reference.fence_state().point().map(FencePoint::category),
        Some(FenceCategory::Expiry)
    );
    assert_eq!(reference.accepted().len(), 1);
    assert_eq!(
        reference
            .revalidate(&current, &use_operation, &name(TENANT))
            .fence(),
        Some(FenceReason::Expiry)
    );
    assert_eq!(
        reference
            .revalidate(&current, &use_operation, &name(TENANT))
            .staleness(),
        None
    );

    // The staleness vocabulary is closed and self-describing.
    assert_eq!(SecretStalenessReason::ALL.len(), 8);
    for reason in SecretStalenessReason::ALL {
        assert_eq!(reason.as_str(), reason.wire_name());
        assert_eq!(
            SecretStalenessReason::from_wire_name(reason.wire_name()),
            Some(reason)
        );
    }
    assert_eq!(SecretStalenessReason::from_wire_name("material"), None);
}

#[test]
fn secret_expiry_and_revocation_race_the_admission_commit_point() {
    let class = ProtectedDataClass::ActionArgument;
    let use_operation = operation("crate::secret_use", &[0, 1]);
    let mut reference = reference_with(
        &[
            AuthorityRight::InvokeReadOnly,
            AuthorityRight::InvokeIdempotent,
        ],
        AuthorityLeasePolicy::Expiring { expires_at_us: 100 },
        class,
        TENANT,
        Some(use_operation.clone()),
    );
    let generation = reference.generation();
    let first = request(
        AuthorityRight::InvokeReadOnly,
        RecoveryClass::ReadOnly,
        generation,
        99,
    );
    let admission = reference
        .admit_use(
            &first,
            &AncestorFences::none(),
            &use_operation,
            &name(TENANT),
        )
        .unwrap_or_else(|_| unreachable!("the lease permits the admission at 99"));
    assert_eq!(admission.sequence(), 0);
    assert_eq!(admission.generation(), generation);
    assert_eq!(admission.settlement_rule(), RecoveryClass::ReadOnly);

    let second = request(
        AuthorityRight::InvokeIdempotent,
        RecoveryClass::Idempotent,
        generation,
        99,
    );
    let second_admission = reference
        .admit_use(
            &second,
            &AncestorFences::none(),
            &use_operation,
            &name(TENANT),
        )
        .unwrap_or_else(|_| unreachable!("the lease still permits the second admission at 99"));
    assert_eq!(second_admission.sequence(), 1);
    assert_eq!(
        second_admission.settlement_rule(),
        RecoveryClass::Idempotent
    );
    assert_eq!(reference.accepted().len(), 2);

    // Reaching the expiry fences new work at the commit point, which records
    // nothing and leaves both accepted uses untouched.
    let late = request(
        AuthorityRight::InvokeReadOnly,
        RecoveryClass::ReadOnly,
        generation,
        100,
    );
    assert_eq!(
        reference
            .admit_use(
                &late,
                &AncestorFences::none(),
                &use_operation,
                &name(TENANT)
            )
            .err(),
        Some(SecretError::Fenced(FenceCategory::Expiry))
    );
    assert_eq!(reference.accepted().len(), 2);

    // A later revocation latches its own point, and the earliest latch is what
    // new admission observes.
    let revoke = reference.revoke();
    assert_eq!(revoke.category(), FenceCategory::Revocation);
    assert_eq!(revoke.linearization_point(), 2);
    assert_eq!(
        reference.fence_state().point().map(FencePoint::category),
        Some(FenceCategory::Revocation)
    );
    assert_eq!(
        reference
            .admit_use(
                &first,
                &AncestorFences::none(),
                &use_operation,
                &name(TENANT)
            )
            .err(),
        Some(SecretError::Fenced(FenceCategory::Revocation))
    );
    assert_eq!(reference.accepted().len(), 2);

    // Fencing never reclassifies work that was already admitted.
    assert_eq!(
        admission.settles(ExternalOutcome::Ambiguous),
        ExternalOutcome::Ambiguous
    );
    assert_eq!(
        admission.settles(ExternalOutcome::Accepted),
        ExternalOutcome::Accepted
    );

    // A lease that already reached its expiry binds no reference at all.
    let expired_instance = instance_with(
        &[AuthorityRight::InvokeReadOnly],
        AuthorityLeasePolicy::Expiring { expires_at_us: 0 },
    );
    assert_eq!(
        SecretReference::bind(expired_instance, class, name(TENANT), Some(use_operation)).err(),
        Some(SecretError::Fenced(FenceCategory::Expiry))
    );
}

#[test]
fn secret_cancellation_never_reports_a_definite_not_started_effect() {
    let class = ProtectedDataClass::ActionArgument;
    let use_operation = operation("crate::secret_use", &[0, 1]);
    let mut reference = reference_with(
        &[AuthorityRight::InvokeReadOnly],
        AuthorityLeasePolicy::Unleased,
        class,
        TENANT,
        Some(use_operation.clone()),
    );
    let generation = reference.generation();
    let current = request(
        AuthorityRight::InvokeReadOnly,
        RecoveryClass::ReadOnly,
        generation,
        0,
    );
    let admission = reference
        .admit_use(
            &current,
            &AncestorFences::none(),
            &use_operation,
            &name(TENANT),
        )
        .unwrap_or_else(|_| unreachable!("the fixture use passes the commit point"));

    // The use crossed the admission commit point, so a cancellation that races it
    // is ambiguous rather than a definite not-started effect.
    assert_eq!(
        classify_effect(
            DurableOperationCut::Admitted,
            OperationCancellation::Requested
        ),
        EffectCertainty::AmbiguouslyBegun
    );
    assert!(
        !classify_effect(
            DurableOperationCut::Admitted,
            OperationCancellation::Requested
        )
        .is_definite_not_started()
    );
    for cut in [
        DurableOperationCut::Admitted,
        DurableOperationCut::Dispatched,
        DurableOperationCut::Settled,
    ] {
        for cancellation in OperationCancellation::ALL {
            assert_eq!(
                classify_effect(cut, cancellation),
                EffectCertainty::AmbiguouslyBegun
            );
        }
    }
    // Only a declared, uncancelled use is ever a definite not-started effect, so
    // the negative above is not vacuous.
    assert_eq!(
        classify_effect(
            DurableOperationCut::Declared,
            OperationCancellation::NotRequested
        ),
        EffectCertainty::DefiniteNotStarted
    );

    // The audit record names the committed admission; a use refused at the commit
    // point records no admission at all.
    let access = audit_access();
    let admitted =
        SecretAuditEvidence::record(&reference, SecretAuditOutcome::Admitted, Some(admission), 0)
            .unwrap_or_else(|_| unreachable!("the committed admission is admissible evidence"))
            .with_transition(AuditTransition::new(AuditTransitionKind::Revocation, 5));
    assert_eq!(
        admitted
            .view(&access)
            .unwrap_or_else(|| unreachable!("the capability is bound to the fixture tenant"))
            .admission(),
        Some(admission)
    );
    reference.revoke();
    assert_eq!(
        reference
            .admit_use(
                &current,
                &AncestorFences::none(),
                &use_operation,
                &name(TENANT)
            )
            .err(),
        Some(SecretError::Fenced(FenceCategory::Revocation))
    );
    let refused = SecretAuditEvidence::record(&reference, SecretAuditOutcome::Fenced, None, 6)
        .unwrap_or_else(|_| unreachable!("a fenced use carries no admission"));
    let refused_view = refused
        .view(&access)
        .unwrap_or_else(|| unreachable!("the capability is bound to the fixture tenant"));
    assert_eq!(refused_view.admission(), None);
    assert_eq!(refused_view.outcome(), SecretAuditOutcome::Fenced);
    assert_eq!(reference.accepted().len(), 1);
    assert_eq!(SecretAuditOutcome::Admitted.wire_name(), "admitted");
    assert_eq!(SecretAuditOutcome::Refused.wire_name(), "refused");
}

#[test]
fn secret_diagnostics_and_redacted_text_never_carry_material_or_its_digest() {
    let class = ProtectedDataClass::ActionArgument;
    let use_operation = operation("crate::secret_use", &[0, 1]);
    let material_digest = digest_hex(MATERIAL_SENTINEL);
    let reference = reference_with(
        &[AuthorityRight::InvokeReadOnly, AuthorityRight::Delegate],
        AuthorityLeasePolicy::Expiring { expires_at_us: 250 },
        class,
        TENANT,
        Some(use_operation),
    );
    let durable = DurableSecretReference::commit(&reference);
    let evidence = SecretAuditEvidence::record(&reference, SecretAuditOutcome::Refused, None, 3)
        .unwrap_or_else(|_| unreachable!("a refused use carries no admission"));
    let access = audit_access();
    let canonical = evidence
        .view(&access)
        .unwrap_or_else(|| unreachable!("the capability is bound to the fixture tenant"))
        .canonical_text();
    let renderings = [
        reference.redacted_text(),
        format!("{reference:?}"),
        durable.redacted_text(),
        format!("{durable:?}"),
        evidence.redacted_text(),
        canonical,
    ];
    for rendering in renderings {
        assert!(!rendering.contains(MATERIAL_SENTINEL));
        assert!(!rendering.contains(&material_digest));
    }

    // Every refusal names one stable kebab-case code and carries no material.
    let errors = [
        SecretError::Authority(AuthorityError::EmptyRights),
        SecretError::TenantMismatch,
        SecretError::TenantChangeForbidden,
        SecretError::OperationMismatch,
        SecretError::ClassChangeForbidden,
        SecretError::StaleGeneration,
        SecretError::Fenced(FenceCategory::Revocation),
        SecretError::TransferNotSucceeding,
        SecretError::TransferHolderMismatch,
        SecretError::RebindRequirementMismatch,
        SecretError::ReinstatementForbidden,
        SecretError::InadmissibleAuditRecord,
        SecretError::SerializationForbidden,
        SecretError::ExtractionForbidden,
    ];
    let mut codes = BTreeSet::new();
    for error in errors {
        let text = format!("{error}");
        assert!(!text.contains(MATERIAL_SENTINEL));
        assert!(!text.contains(&material_digest));
        assert!(error.code().starts_with("secret-"));
        assert!(
            error
                .code()
                .bytes()
                .all(|byte| { byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' })
        );
        assert!(codes.insert(error.code()));
    }
    assert_eq!(codes.len(), 14);

    // The redacted renderings name identity metadata and never a digest of the
    // reference the durable cut commits.
    let redacted = durable.redacted_text();
    assert!(redacted.contains("cut=issued"));
    assert!(redacted.contains(&format!("class={}", class.wire_name())));
    assert!(!redacted.contains(durable.reference().digest_hex()));
    assert!(
        !evidence
            .redacted_text()
            .contains(reference.id().digest_hex())
    );
}

#[test]
fn secret_audit_evidence_is_capability_gated_and_names_the_owning_clause() {
    let class = ProtectedDataClass::ActionArgument;
    let use_operation = operation("crate::secret_use", &[0, 1]);
    // The capability is a declared-rights gate: only the observe right mints it.
    assert_eq!(
        SecretAuditAccess::grant(read_only_rights(), &name(TENANT)),
        None
    );
    assert_eq!(
        SecretAuditAccess::grant(observing_rights(), &name(TENANT)),
        Some(audit_access())
    );
    let access = audit_access();
    assert_eq!(access.tenant().as_str(), TENANT);

    let mut reference = reference_with(
        &[AuthorityRight::InvokeReadOnly],
        AuthorityLeasePolicy::Expiring { expires_at_us: 400 },
        class,
        TENANT,
        Some(use_operation.clone()),
    );
    let current = request(
        AuthorityRight::InvokeReadOnly,
        RecoveryClass::ReadOnly,
        reference.generation(),
        7,
    );
    let admission = reference
        .admit_use(
            &current,
            &AncestorFences::none(),
            &use_operation,
            &name(TENANT),
        )
        .unwrap_or_else(|_| unreachable!("the fixture use passes the commit point"));
    let evidence =
        SecretAuditEvidence::record(&reference, SecretAuditOutcome::Admitted, Some(admission), 7)
            .unwrap_or_else(|_| unreachable!("the committed admission is admissible evidence"))
            .with_transition(AuditTransition::new(AuditTransitionKind::Revocation, 9));
    let view = evidence
        .view(&access)
        .unwrap_or_else(|| unreachable!("the capability is bound to the fixture tenant"));
    assert_eq!(view.outcome(), SecretAuditOutcome::Admitted);
    assert_eq!(view.admission(), Some(admission));
    assert_eq!(view.class(), class);
    assert_eq!(view.generation(), reference.generation());
    assert_eq!(view.issued_at_us(), 7);
    assert_eq!(view.expires_at_us(), Some(400));
    assert_eq!(view.tenant().as_str(), TENANT);
    assert_eq!(view.reference(), reference.id());
    assert_eq!(view.holder().as_str(), reference.holder().as_str());
    assert_eq!(view.transitions().len(), 1);

    // The canonical rendering names the clause that owns the record and every
    // identity input of the decision.
    let canonical = view.canonical_text();
    assert_eq!(
        SECRET_OWNING_CLAUSE,
        "GNT-21.6-secret-redaction-and-protected-audit"
    );
    assert!(canonical.contains(&format!("clause={SECRET_OWNING_CLAUSE}")));

    // Every refusal names exactly one owning clause of this section, and the
    // clause vocabulary is closed: the material boundaries belong to the
    // unreadable-reference clause and no condition is reported under another
    // condition's code.
    let owning = [
        (
            SecretError::Authority(AuthorityError::EmptyRights),
            "GNT-21.5-secret-expiry-and-revocation-races",
        ),
        (
            SecretError::TenantMismatch,
            "GNT-21.7-secret-tenant-isolation",
        ),
        (
            SecretError::TenantChangeForbidden,
            "GNT-21.7-secret-tenant-isolation",
        ),
        (
            SecretError::OperationMismatch,
            "GNT-21.2-secret-authority-binding",
        ),
        (
            SecretError::ClassChangeForbidden,
            "GNT-21.8-durable-secret-revalidation",
        ),
        (
            SecretError::StaleGeneration,
            "GNT-21.4-secret-generation-fencing",
        ),
        (
            SecretError::Fenced(FenceCategory::Revocation),
            "GNT-21.4-secret-generation-fencing",
        ),
        (
            SecretError::TransferNotSucceeding,
            "GNT-21.3-secret-lifetime-transfer-and-attenuation",
        ),
        (
            SecretError::TransferHolderMismatch,
            "GNT-21.3-secret-lifetime-transfer-and-attenuation",
        ),
        (
            SecretError::RebindRequirementMismatch,
            "GNT-21.8-durable-secret-revalidation",
        ),
        (
            SecretError::ReinstatementForbidden,
            "GNT-21.4-secret-generation-fencing",
        ),
        (
            SecretError::InadmissibleAuditRecord,
            "GNT-21.6-secret-redaction-and-protected-audit",
        ),
        (
            SecretError::SerializationForbidden,
            "GNT-21.1-unreadable-secret-references",
        ),
        (
            SecretError::ExtractionForbidden,
            "GNT-21.1-unreadable-secret-references",
        ),
    ];
    for (refusal, clause) in owning {
        assert_eq!(refusal.clause(), clause);
        assert!(refusal.code().starts_with("secret-"));
    }

    // An audit record is admissible only when it agrees with its reference: an
    // admitted use needs the admission of its own generation, and a use that was
    // not admitted carries no admission at all.
    assert_eq!(
        SecretAuditEvidence::record(&reference, SecretAuditOutcome::Admitted, None, 7).err(),
        Some(SecretError::InadmissibleAuditRecord)
    );
    assert_eq!(
        SecretAuditEvidence::record(&reference, SecretAuditOutcome::Refused, Some(admission), 7)
            .err(),
        Some(SecretError::InadmissibleAuditRecord)
    );
    let mut advanced_reference = reference
        .attenuate(
            read_only_rights(),
            AuthorityLeasePolicy::Expiring { expires_at_us: 400 },
        )
        .unwrap_or_else(|_| unreachable!("an equal rights set and an equal lease attenuate"));
    let advanced_request = request(
        AuthorityRight::InvokeReadOnly,
        RecoveryClass::ReadOnly,
        advanced_reference.generation(),
        7,
    );
    let advanced_admission = advanced_reference
        .admit_use(
            &advanced_request,
            &AncestorFences::none(),
            &use_operation,
            &name(TENANT),
        )
        .unwrap_or_else(|_| unreachable!("the fixture use passes the commit point"));
    assert_eq!(
        advanced_admission.generation().value(),
        reference.generation().value() + 1
    );
    assert_eq!(
        SecretAuditEvidence::record(
            &reference,
            SecretAuditOutcome::Admitted,
            Some(advanced_admission),
            7
        )
        .err(),
        Some(SecretError::InadmissibleAuditRecord)
    );

    // The capability is bound to one tenant, so another tenant's evidence is not
    // viewable under it while its own capability still reaches it.
    let foreign_reference = reference_with(
        &[AuthorityRight::InvokeReadOnly],
        AuthorityLeasePolicy::Unleased,
        class,
        OTHER_TENANT,
        Some(use_operation.clone()),
    );
    let foreign_evidence =
        SecretAuditEvidence::record(&foreign_reference, SecretAuditOutcome::Refused, None, 7)
            .unwrap_or_else(|_| unreachable!("a refused use carries no admission"));
    assert!(foreign_evidence.view(&access).is_none());
    let foreign_access = SecretAuditAccess::grant(observing_rights(), &name(OTHER_TENANT))
        .unwrap_or_else(|| unreachable!("the observe right mints the capability for one tenant"));
    assert_eq!(
        foreign_evidence
            .view(&foreign_access)
            .map(|view| view.tenant().as_str()),
        Some(OTHER_TENANT)
    );
    assert!(canonical.contains(reference.id().as_str()));
    assert!(canonical.contains(&format!(
        "holder-requirement={}",
        reference.holder().requirement().as_str()
    )));
    assert!(canonical.contains("outcome=admitted"));
    assert!(canonical.contains("revocation@9"));
    assert!(canonical.contains("expires-at-us=400"));

    // The ordinary rendering of the same record names no reference digest at all.
    let redacted = evidence.redacted_text();
    assert!(redacted.contains("outcome=admitted"));
    assert!(redacted.contains("transitions=1"));
    assert!(!redacted.contains(reference.id().digest_hex()));
}

#[test]
fn secret_references_are_isolated_per_tenant() {
    let class = ProtectedDataClass::ActionArgument;
    let use_operation = operation("crate::secret_use", &[0, 1]);
    let mut acme = reference_with(
        &[AuthorityRight::InvokeReadOnly],
        AuthorityLeasePolicy::Unleased,
        class,
        TENANT,
        Some(use_operation.clone()),
    );
    let mut globex = reference_with(
        &[AuthorityRight::InvokeReadOnly],
        AuthorityLeasePolicy::Unleased,
        class,
        OTHER_TENANT,
        Some(use_operation.clone()),
    );

    // The two holders present equivalent instances, so only the tenant separates
    // them: the derived holder binding text and every identity derived from it
    // differ, so two tenants never share a holder binding or a deduplication key.
    assert_eq!(acme.holder().requirement(), globex.holder().requirement());
    assert_eq!(acme.holder().binding(), globex.holder().binding());
    assert_eq!(acme.holder().holder(), globex.holder().holder());
    assert_ne!(acme.holder().as_str(), globex.holder().as_str());
    assert_ne!(acme.id(), globex.id());
    // One equivalent instance, two tenants: the instance identity is shared while
    // the holder binding derived from it is not.
    let shared = instance_for(
        &requirement(),
        &binding_of(&requirement()),
        read_only_rights(),
        AuthorityLeasePolicy::Unleased,
    );
    assert_eq!(shared.root(), acme.holder().holder());
    assert_ne!(
        SecretHolderBindingId::bind(&shared, &name(TENANT)).as_str(),
        SecretHolderBindingId::bind(&shared, &name(OTHER_TENANT)).as_str()
    );

    // Each reference admits only its own tenant's use.
    let acme_use = request(
        AuthorityRight::InvokeReadOnly,
        RecoveryClass::ReadOnly,
        acme.generation(),
        0,
    );
    let globex_use = request(
        AuthorityRight::InvokeReadOnly,
        RecoveryClass::ReadOnly,
        globex.generation(),
        0,
    );
    assert!(
        acme.admit_use(
            &acme_use,
            &AncestorFences::none(),
            &use_operation,
            &name(TENANT)
        )
        .is_ok()
    );
    assert!(
        globex
            .admit_use(
                &globex_use,
                &AncestorFences::none(),
                &use_operation,
                &name(OTHER_TENANT)
            )
            .is_ok()
    );
    assert_eq!(
        acme.admit_use(
            &acme_use,
            &AncestorFences::none(),
            &use_operation,
            &name(OTHER_TENANT)
        )
        .err(),
        Some(SecretError::TenantMismatch)
    );
    assert_eq!(
        globex
            .admit_use(
                &globex_use,
                &AncestorFences::none(),
                &use_operation,
                &name(TENANT)
            )
            .err(),
        Some(SecretError::TenantMismatch)
    );
    assert_eq!(acme.accepted().len(), 1);
    assert_eq!(globex.accepted().len(), 1);
    assert_eq!(
        acme.revalidate(&acme_use, &use_operation, &name(OTHER_TENANT))
            .staleness(),
        Some(SecretStalenessReason::Tenant)
    );

    // A narrowed descendant never adopts another tenant either.
    let narrowed = acme
        .attenuate(read_only_rights(), AuthorityLeasePolicy::Unleased)
        .unwrap_or_else(|_| unreachable!("an equal rights set and an equal lease attenuate"));
    assert_eq!(narrowed.tenant().as_str(), TENANT);
    assert_ne!(narrowed.id(), acme.id());
    let mut narrowed = narrowed;
    let narrowed_use = request(
        AuthorityRight::InvokeReadOnly,
        RecoveryClass::ReadOnly,
        narrowed.generation(),
        0,
    );
    assert_eq!(
        narrowed
            .admit_use(
                &narrowed_use,
                &AncestorFences::none(),
                &use_operation,
                &name(OTHER_TENANT)
            )
            .err(),
        Some(SecretError::TenantMismatch)
    );
    assert!(narrowed.accepted().is_empty());
}

#[test]
fn durable_secret_cuts_revalidate_and_rebind_fail_closed_on_resume() {
    let requirement = requirement();
    let binding = binding_of(&requirement);
    let class = ProtectedDataClass::ActionArgument;
    let use_operation = operation("crate::secret_use", &[0, 1]);
    let holder = instance_for(
        &requirement,
        &binding,
        read_only_rights(),
        AuthorityLeasePolicy::Unleased,
    );
    let successor = attenuation(&holder);
    let reference = secret_of(holder, class, TENANT, Some(use_operation.clone()));
    let durable = DurableSecretReference::commit(&reference);

    // The cut commits identities, class, generation, operation, and cut only.
    assert_eq!(durable.reference(), reference.id());
    assert_eq!(durable.cut(), SecretDurableCut::Issued);
    assert_eq!(durable.generation(), reference.generation());
    assert_eq!(durable.generation(), AuthorityGeneration::INITIAL);
    assert_eq!(durable.classify_resume(), SecretResumeClass::Continue);
    assert_eq!(
        durable
            .clone()
            .with_cut(SecretDurableCut::Revalidated)
            .classify_resume(),
        SecretResumeClass::Revalidate
    );
    assert_eq!(
        durable
            .clone()
            .with_cut(SecretDurableCut::Fenced)
            .classify_resume(),
        SecretResumeClass::Fenced
    );
    assert_eq!(
        durable
            .clone()
            .with_cut(SecretDurableCut::Expired)
            .classify_resume(),
        SecretResumeClass::Fenced
    );
    assert_eq!(
        durable
            .clone()
            .with_cut(SecretDurableCut::Revoked)
            .classify_resume(),
        SecretResumeClass::ReApproval
    );
    assert_eq!(
        durable
            .clone()
            .with_cut(SecretDurableCut::Expired)
            .generation(),
        durable.generation()
    );

    // A live successor instance is presented at resume: the record holds no handle.
    assert!(durable.revalidate(&successor, 0).is_fresh());
    let same_generation = instance_for(
        &requirement,
        &binding,
        read_only_rights(),
        AuthorityLeasePolicy::Unleased,
    );
    // A durable revalidation requires a STRICTLY advancing generation, so an
    // instance still at the cut's own generation is stale rather than fresh.
    assert_eq!(
        durable.revalidate(&same_generation, 0).staleness(),
        Some(SecretStalenessReason::Generation)
    );

    // A rewound generation is stale rather than fresh.
    let advanced_holder = instance_for(
        &requirement,
        &binding,
        read_only_rights(),
        AuthorityLeasePolicy::Unleased,
    );
    let advanced_successor = attenuation(&advanced_holder);
    let advanced = secret_of(
        advanced_successor,
        class,
        TENANT,
        Some(use_operation.clone()),
    );
    let advanced_cut = DurableSecretReference::commit(&advanced);
    assert_eq!(advanced_cut.generation().value(), 2);
    let rewind = instance_for(
        &requirement,
        &binding,
        read_only_rights(),
        AuthorityLeasePolicy::Unleased,
    );
    assert_eq!(
        advanced_cut.revalidate(&rewind, 0).staleness(),
        Some(SecretStalenessReason::Generation)
    );

    // A replanted lineage root is a stale reference, not a fresh resume.
    let replanted = instance_for(
        &requirement,
        &binding,
        RightsSet::from_rights(&[AuthorityRight::Observe, AuthorityRight::InvokeReadOnly]),
        AuthorityLeasePolicy::Unleased,
    );
    assert_ne!(replanted.root(), reference.holder().holder());
    assert_eq!(
        durable.revalidate(&replanted, 0).staleness(),
        Some(SecretStalenessReason::Reference)
    );

    // An expired lease is a stale lifetime once the generation strictly advances,
    // and a foreign binding is a stale holder.
    let leased_holder = instance_for(
        &requirement,
        &binding,
        read_only_rights(),
        AuthorityLeasePolicy::Expiring { expires_at_us: 50 },
    );
    let leased = attenuation(&leased_holder);
    assert!(durable.revalidate(&leased, 49).is_fresh());
    assert_eq!(
        durable.revalidate(&leased, 50).staleness(),
        Some(SecretStalenessReason::Lifetime)
    );
    let other_requirement = requirement_of(OTHER_FAMILY);
    let other_binding = binding_of(&other_requirement);
    let foreign = instance_for(
        &other_requirement,
        &other_binding,
        read_only_rights(),
        AuthorityLeasePolicy::Unleased,
    );
    assert_eq!(
        durable.revalidate(&foreign, 0).staleness(),
        Some(SecretStalenessReason::Holder)
    );

    // Rebinding fails closed on a foreign or rewound holder and otherwise strictly
    // advances the generation.
    assert_eq!(
        durable.rebind(foreign).err(),
        Some(SecretError::RebindRequirementMismatch)
    );
    let non_advancing = instance_for(
        &requirement,
        &binding,
        read_only_rights(),
        AuthorityLeasePolicy::Unleased,
    );
    assert_eq!(
        durable.rebind(non_advancing).err(),
        Some(SecretError::StaleGeneration)
    );
    let resume_holder = instance_for(
        &requirement,
        &binding,
        read_only_rights(),
        AuthorityLeasePolicy::Unleased,
    );
    let resume_successor = attenuation(&resume_holder);
    let resumed = durable
        .rebind(resume_successor)
        .unwrap_or_else(|_| unreachable!("the fixture successor strictly advances the cut"));
    assert_eq!(
        resumed.generation().value(),
        durable.generation().value() + 1
    );
    assert_ne!(resumed.id(), durable.reference());
    assert_eq!(resumed.class(), reference.class());
    assert_eq!(resumed.tenant().as_str(), TENANT);
    assert_eq!(
        resumed.operation().map(LogicalOperationId::as_str),
        Some(use_operation.as_str())
    );
    assert_eq!(durable.cut(), SecretDurableCut::Issued);
    let mut resumed = resumed;
    let resumed_use = request(
        AuthorityRight::InvokeReadOnly,
        RecoveryClass::ReadOnly,
        resumed.generation(),
        0,
    );
    assert!(
        resumed
            .admit_use(
                &resumed_use,
                &AncestorFences::none(),
                &use_operation,
                &name(TENANT)
            )
            .is_ok()
    );

    // The recorded cut is enforced before any instance is inspected: a fenced,
    // expired, or revoked cut records authority that already ended, so it is never
    // a standing authorization after resume.
    let cut_holder = instance_for(
        &requirement,
        &binding,
        read_only_rights(),
        AuthorityLeasePolicy::Unleased,
    );
    let cut_successor = attenuation(&cut_holder);
    assert_eq!(cut_successor.requirement(), &requirement);
    assert_eq!(cut_successor.binding(), &binding);
    assert_eq!(cut_successor.fence_state(), FenceState::Open);
    assert_eq!(
        cut_successor.generation().value(),
        durable.generation().value() + 1
    );
    for cut in [
        SecretDurableCut::Fenced,
        SecretDurableCut::Expired,
        SecretDurableCut::Revoked,
    ] {
        assert_eq!(
            durable
                .clone()
                .with_cut(cut)
                .rebind(attenuation(&cut_holder))
                .err(),
            Some(SecretError::ReinstatementForbidden)
        );
    }
    // Only an issued or revalidated cut resumes, and only onto a proper successor.
    for cut in [SecretDurableCut::Issued, SecretDurableCut::Revalidated] {
        let resumed = durable
            .clone()
            .with_cut(cut)
            .rebind(attenuation(&cut_holder))
            .unwrap_or_else(|_| unreachable!("an issued or revalidated cut resumes"));
        assert_eq!(
            resumed.generation().value(),
            durable.generation().value() + 1
        );
        assert_eq!(resumed.class(), class);
        assert_eq!(resumed.tenant().as_str(), TENANT);
    }

    // A fenced successor is refused and never reinstated.
    let fenced_holder = instance_for(
        &requirement,
        &binding,
        read_only_rights(),
        AuthorityLeasePolicy::Unleased,
    );
    let mut fenced_successor = attenuation(&fenced_holder);
    fenced_successor.revoke();
    assert_eq!(
        durable.rebind(fenced_successor).err(),
        Some(SecretError::Fenced(FenceCategory::Revocation))
    );
}

#[test]
fn durable_secret_rebinding_refuses_a_changed_operation_class_tenant_or_fenced_instance() {
    let requirement = requirement();
    let binding = binding_of(&requirement);
    let class = ProtectedDataClass::ActionArgument;
    let use_operation = operation("crate::secret_use", &[0, 1]);
    let other_operation = operation("crate::secret_use", &[0, 2]);
    let holder = instance_for(
        &requirement,
        &binding,
        read_only_rights(),
        AuthorityLeasePolicy::Unleased,
    );
    let successor = attenuation(&holder);
    let reference = secret_of(holder, class, TENANT, Some(use_operation.clone()));
    let durable = DurableSecretReference::commit(&reference);

    // A changed operation, class, or tenant is refused rather than adopted.
    let changed_operation = instance_for(
        &requirement,
        &binding,
        read_only_rights(),
        AuthorityLeasePolicy::Unleased,
    );
    assert_eq!(
        durable
            .resume(
                changed_operation,
                class,
                &name(TENANT),
                Some(&other_operation)
            )
            .err(),
        Some(SecretError::RebindRequirementMismatch)
    );
    let changed_class = instance_for(
        &requirement,
        &binding,
        read_only_rights(),
        AuthorityLeasePolicy::Unleased,
    );
    assert_eq!(
        durable
            .resume(
                changed_class,
                ProtectedDataClass::SessionIdentifier,
                &name(TENANT),
                Some(&use_operation)
            )
            .err(),
        Some(SecretError::ClassChangeForbidden)
    );
    let changed_tenant = instance_for(
        &requirement,
        &binding,
        read_only_rights(),
        AuthorityLeasePolicy::Unleased,
    );
    assert_eq!(
        durable
            .resume(
                changed_tenant,
                class,
                &name(OTHER_TENANT),
                Some(&use_operation)
            )
            .err(),
        Some(SecretError::TenantChangeForbidden)
    );

    // A fenced successor is refused and never reinstated.
    let fenced_holder = instance_for(
        &requirement,
        &binding,
        read_only_rights(),
        AuthorityLeasePolicy::Unleased,
    );
    let mut fenced_successor = attenuation(&fenced_holder);
    fenced_successor.revoke();
    assert_eq!(
        durable.rebind(fenced_successor).err(),
        Some(SecretError::Fenced(FenceCategory::Revocation))
    );
    let expired_holder = instance_for(
        &requirement,
        &binding,
        read_only_rights(),
        AuthorityLeasePolicy::Unleased,
    );
    let mut expired_successor = attenuation(&expired_holder);
    expired_successor.expire();
    assert_eq!(
        durable.rebind(expired_successor).err(),
        Some(SecretError::Fenced(FenceCategory::Expiry))
    );

    // A successor of another binding is refused, and the matching resume preserves
    // every identity input of the cut while strictly advancing the generation.
    let other_requirement = requirement_of(OTHER_FAMILY);
    let other_binding = binding_of(&other_requirement);
    let foreign = instance_for(
        &other_requirement,
        &other_binding,
        read_only_rights(),
        AuthorityLeasePolicy::Unleased,
    );
    assert_eq!(
        durable.rebind(foreign).err(),
        Some(SecretError::RebindRequirementMismatch)
    );
    let resumed = durable
        .rebind(successor)
        .unwrap_or_else(|_| unreachable!("the fixture successor strictly advances the cut"));
    assert_eq!(resumed.class(), class);
    assert_eq!(resumed.tenant().as_str(), TENANT);
    assert_eq!(
        resumed.operation().map(LogicalOperationId::as_str),
        Some(use_operation.as_str())
    );
    assert_eq!(resumed.rights(), read_only_rights());
    assert_eq!(
        resumed.generation().value(),
        durable.generation().value() + 1
    );
    assert_ne!(resumed.id(), durable.reference());
    // The committed cut is unchanged by a resume.
    assert_eq!(durable.cut(), SecretDurableCut::Issued);
    assert_eq!(durable.generation(), reference.generation());
    assert_eq!(durable.reference(), reference.id());

    // A successor that satisfies the committed requirement and binding, strictly
    // advances the generation, and is unfenced is still refused when it descends
    // from another lineage root: it is not this cut's holder, and a resume never
    // adopts a replanted lineage.
    let replanted_holder = instance_for(
        &requirement,
        &binding,
        RightsSet::from_rights(&[AuthorityRight::Observe, AuthorityRight::InvokeReadOnly]),
        AuthorityLeasePolicy::Unleased,
    );
    let replanted_successor = attenuation(&replanted_holder);
    assert_eq!(replanted_successor.requirement(), &requirement);
    assert_eq!(replanted_successor.binding(), &binding);
    assert_eq!(replanted_successor.fence_state(), FenceState::Open);
    assert_eq!(
        replanted_successor.generation().value(),
        durable.generation().value() + 1
    );
    assert_eq!(
        durable.revalidate(&replanted_successor, 0).staleness(),
        Some(SecretStalenessReason::Reference)
    );
    assert_eq!(
        durable.rebind(replanted_successor).err(),
        Some(SecretError::RebindRequirementMismatch)
    );
}
