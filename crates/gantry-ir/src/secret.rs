//! Opaque secret and credential references bound to capability authority.
//!
//! This module is the machine-checked model for `GNT-GP-SECRET-001`, the
//! `std.secret` and credential-capability requirement. It reuses the landed
//! identity, rights, lineage, fencing, and admission rules of
//! `GNT-3-T-AUTHORITY-INSTANCES`, `GNT-3-T-AUTHORITY-LINEAGE`,
//! `GNT-3-T-AUTHORITY-REVOCATION`, and `GNT-3-T-AUTHORITY-ADMISSION`, the
//! protected-class vocabulary of `GNT-15.10-protected-values`, and the
//! audit-transition vocabulary of the approval model.
//!
//! # Boundaries
//!
//! A [`SecretReference`] is a handle, never a value. It names the capability
//! instance that holds it, the protected class it stands for, the tenant that
//! owns it, the one logical operation it may influence, and the generation,
//! rights, lease, and fencing state of that instance. The module has no material
//! accessor, no byte or text accessor, no [`std::fmt::Display`], no
//! `Serialize`/`Deserialize`, no conversion from or into a protected value, and
//! no release path, so the material a reference stands for is unreachable from
//! this crate. What is deliberately absent is recorded as a non-claim by
//! [`SECRET_NON_CLAIMS`].
//!
//! # Invariants
//!
//! * Monotone attenuation: [`SecretReference::attenuate`] and
//!   [`SecretReference::delegate`] narrow rights and lease through the landed
//!   instance lattice, so no descendant reference can amplify, add, or restore a
//!   right.
//! * Fail-closed revalidation: [`SecretReference::revalidate`],
//!   [`DurableSecretReference::revalidate`], and [`revalidate_secret`] are pure,
//!   never repair a stale reference, and check fencing before anything else.
//! * Affine transfer and strict succession: [`SecretReference::transfer_affine`]
//!   moves a reference without duplicating it, and
//!   [`SecretReference::transfer`] accepts only a successor of the same
//!   requirement and binding at a strictly later generation.
//! * No reinstatement: a revoked or expired generation is refused by every
//!   successor path, including [`SecretReference::rebind`] and
//!   [`DurableSecretReference::rebind`], because no rebinding may revive one.
//! * Durable cuts are never standing authorization:
//!   [`DurableSecretReference::resume`] and [`DurableSecretReference::rebind`]
//!   refuse a fenced, expired, or revoked cut before they inspect any instance.
//! * Tenant isolation: the tenant is part of the derived identity and is
//!   cross-checked at the admission commit point, so a reference never admits
//!   work for another tenant.
//! * Redaction: every rendering this module publishes is identity metadata
//!   only. Identities are domain-separated digests over identity inputs, so no
//!   clock reading, process identifier, host path, locale, or material
//!   participates in any identity or rendering here.

use std::fmt;
use std::sync::Arc;

use crate::approval::{AuditTransition, FenceReason, LogicalOperationId};
use crate::authority::{
    Admission, AdmissionRequest, AncestorFences, AuthorityBindingId, AuthorityError,
    AuthorityGeneration, AuthorityInstance, AuthorityInstanceId, AuthorityLeasePolicy,
    AuthorityRequirementId, AuthorityRight, FenceCategory, FencePoint, FenceState, RightsSet,
    digest_fields,
};
use crate::manifest::encode_hex;
use crate::protected::{DeclaredName, ExcludedClaimKind, ProtectedDataClass};

/// Domain separator for canonical secret-reference identity derivation.
const REFERENCE_DOMAIN: &str = "gantry.secret-reference/v1";

/// The clause that owns the audit record of a secret reference.
///
/// Audit evidence produced by this module is protected integration data in the
/// sense of `GNT-15.10-protected-values`, and every canonical rendering of it
/// names `GNT-21.6-secret-redaction-and-protected-audit` so a reader can locate
/// the rule that owns the record.
pub const SECRET_OWNING_CLAUSE: &str = "GNT-21.6-secret-redaction-and-protected-audit";

/// Returns one length-prefixed encoding of a declared identity field.
///
/// Length prefixes keep distinct field sequences distinct, so a tenant and an
/// operation cannot be confused with a differently split pair of the same
/// concatenated text. The helper mirrors the private encoder of the protected
/// model, which is not visible outside its own module.
fn encode_text(value: &str) -> String {
    format!("{}:{value}", value.len())
}

/// Maps one fencing category onto the shared fence reason vocabulary.
const fn fence_reason(category: FenceCategory) -> FenceReason {
    match category {
        FenceCategory::Revocation => FenceReason::Revocation,
        FenceCategory::Expiry => FenceReason::Expiry,
    }
}

/// One holder of a secret reference: the bound authority instance itself.
///
/// The binding is derived from the requirement, the selected implementation
/// binding, the tenant, and the concrete instance identity, so two instances of
/// one requirement never share a holder binding, two tenants presenting
/// equivalent instances never share one, and a holder binding cannot be written
/// down by hand. Only [`SecretHolderBindingId::bind`] constructs one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretHolderBindingId {
    requirement: AuthorityRequirementId,
    binding: AuthorityBindingId,
    holder: AuthorityInstanceId,
    text: Arc<str>,
}

impl SecretHolderBindingId {
    /// Derives the holder binding of one bound capability instance of one tenant.
    ///
    /// The tenant participates in the derived text, so one instance presented
    /// under two tenants has two holder bindings and never shares a holder or a
    /// deduplication key across tenants.
    #[must_use]
    pub fn bind(instance: &AuthorityInstance, tenant: &DeclaredName) -> Self {
        let requirement = instance.requirement().clone();
        let binding = instance.binding().clone();
        let holder = instance.id().clone();
        let text = Arc::from(format!(
            "secret-holder:{}:{}:{}:{}",
            encode_text(requirement.as_str()),
            encode_text(binding.as_str()),
            encode_text(holder.as_str()),
            encode_text(tenant.as_str())
        ));
        Self {
            requirement,
            binding,
            holder,
            text,
        }
    }

    /// Returns the capability requirement the holder satisfies.
    #[must_use]
    pub const fn requirement(&self) -> &AuthorityRequirementId {
        &self.requirement
    }

    /// Returns the selected implementation binding of the holder.
    #[must_use]
    pub const fn binding(&self) -> &AuthorityBindingId {
        &self.binding
    }

    /// Returns the concrete instance identity of the holder.
    #[must_use]
    pub const fn holder(&self) -> &AuthorityInstanceId {
        &self.holder
    }

    /// Returns the exact portable spelling of the holder binding.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }
}

/// One canonical, domain-separated secret-reference identity.
///
/// The identity is derived from the holder requirement and binding, the
/// protected class, the tenant, the authority generation, and the optional
/// logical operation. No clock reading, process identifier, host path, or
/// material participates, so identity is reproducible and never leaks the value
/// a reference stands for. Equality and hashing use the derived identity only.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SecretReferenceId(Arc<str>);

impl SecretReferenceId {
    /// Derives one reference identity under its own domain separator.
    fn derive(
        holder: &SecretHolderBindingId,
        class: ProtectedDataClass,
        tenant: &DeclaredName,
        generation: AuthorityGeneration,
        operation: Option<&LogicalOperationId>,
    ) -> Self {
        let operation_text = operation.map_or("", LogicalOperationId::as_str);
        let digest = digest_fields(
            REFERENCE_DOMAIN,
            &[
                holder.requirement().as_str().as_bytes(),
                holder.binding().as_str().as_bytes(),
                class.wire_name().as_bytes(),
                tenant.as_str().as_bytes(),
                &generation.value().to_be_bytes(),
                operation_text.as_bytes(),
            ],
        );
        Self(Arc::from(format!(
            "secret-reference:{}",
            encode_hex(&digest)
        )))
    }

    /// Returns the exact portable identity spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the lowercase digest text without the identity prefix.
    #[must_use]
    pub fn digest_hex(&self) -> &str {
        self.0.strip_prefix("secret-reference:").unwrap_or(&self.0)
    }
}

/// Why one secret-reference operation was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretError {
    /// The landed authority model refused the operation.
    Authority(AuthorityError),
    /// The presented tenant is not the tenant the reference is bound to.
    TenantMismatch,
    /// The presented tenant would change the tenant the reference is bound to.
    TenantChangeForbidden,
    /// The presented logical operation is not the operation the reference serves.
    OperationMismatch,
    /// The presented protected class would change the class the reference carries.
    ClassChangeForbidden,
    /// The presented generation is not later than the generation already held.
    StaleGeneration,
    /// The generation is fenced by revocation or expiry.
    Fenced(FenceCategory),
    /// The presented successor does not strictly advance the generation.
    TransferNotSucceeding,
    /// The transfer successor does not satisfy the reference's holder: it
    /// satisfies another requirement or another implementation binding.
    TransferHolderMismatch,
    /// The presented successor does not satisfy the durable cut: the committed
    /// requirement, binding, operation, class, or lineage root differs, or the
    /// cut is not resumable by this record.
    RebindRequirementMismatch,
    /// The generation is fenced, so no successor path may reinstate it.
    ReinstatementForbidden,
    /// The proposed audit record is inadmissible: an admitted use without the
    /// admission that committed it, an admission of another generation, or an
    /// admission attached to a use that was not admitted.
    InadmissibleAuditRecord,
    /// The model has no serializer, so a durable cut can never be produced by one.
    SerializationForbidden,
    /// The model has no material accessor, so material can never be extracted.
    ExtractionForbidden,
}

impl SecretError {
    /// Returns the registered diagnostic code of this refusal.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Authority(_) => "secret-authority",
            Self::TenantMismatch => "secret-tenant-mismatch",
            Self::TenantChangeForbidden => "secret-tenant-change-forbidden",
            Self::OperationMismatch => "secret-operation-mismatch",
            Self::ClassChangeForbidden => "secret-class-change-forbidden",
            Self::StaleGeneration => "secret-stale-generation",
            Self::Fenced(_) => "secret-fenced",
            Self::TransferNotSucceeding => "secret-transfer-not-succeeding",
            Self::TransferHolderMismatch => "secret-transfer-holder-mismatch",
            Self::RebindRequirementMismatch => "secret-rebind-requirement-mismatch",
            Self::ReinstatementForbidden => "secret-reinstatement-forbidden",
            Self::InadmissibleAuditRecord => "secret-inadmissible-audit-record",
            Self::SerializationForbidden => "secret-serialization-forbidden",
            Self::ExtractionForbidden => "secret-extraction-forbidden",
        }
    }

    /// Returns the clause of Section 21 that owns this refusal.
    ///
    /// Every refusal names exactly one owning clause, so a reader can locate
    /// the rule that decides the condition, and no condition is reported under
    /// another condition's code.
    #[must_use]
    pub const fn clause(&self) -> &'static str {
        match self {
            Self::Authority(_) => "GNT-21.5-secret-expiry-and-revocation-races",
            Self::OperationMismatch => "GNT-21.2-secret-authority-binding",
            Self::TenantMismatch | Self::TenantChangeForbidden => {
                "GNT-21.7-secret-tenant-isolation"
            }
            Self::TransferNotSucceeding | Self::TransferHolderMismatch => {
                "GNT-21.3-secret-lifetime-transfer-and-attenuation"
            }
            Self::StaleGeneration | Self::Fenced(_) | Self::ReinstatementForbidden => {
                "GNT-21.4-secret-generation-fencing"
            }
            Self::ClassChangeForbidden | Self::RebindRequirementMismatch => {
                "GNT-21.8-durable-secret-revalidation"
            }
            Self::InadmissibleAuditRecord => "GNT-21.6-secret-redaction-and-protected-audit",
            Self::SerializationForbidden | Self::ExtractionForbidden => {
                "GNT-21.1-unreadable-secret-references"
            }
        }
    }
}

impl fmt::Display for SecretError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authority(error) => write!(formatter, "{}: {error}", self.code()),
            Self::Fenced(category) => {
                write!(formatter, "{}: {}", self.code(), category.wire_name())
            }
            _ => formatter.write_str(self.code()),
        }
    }
}

impl std::error::Error for SecretError {}

/// Maps one landed authority refusal onto this module's refusal vocabulary.
const fn classify(error: AuthorityError) -> SecretError {
    match error {
        AuthorityError::StaleGeneration => SecretError::StaleGeneration,
        AuthorityError::Fenced(category) | AuthorityError::AncestorFenced(category) => {
            SecretError::Fenced(category)
        }
        other => SecretError::Authority(other),
    }
}

/// One reason a secret reference is stale for an attempted use.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SecretStalenessReason {
    /// The holder binding, or the instance the reference is bound to, changed.
    Holder,
    /// The tenant changed.
    Tenant,
    /// The logical operation changed, or the reference serves another one.
    Operation,
    /// The declared right and recovery class no longer agree.
    Class,
    /// The presented generation does not strictly advance the generation
    /// already held, or the generation recorded by a durable cut.
    Generation,
    /// The lease no longer permits the admission, or it expired.
    Lifetime,
    /// The rights carried by the holder no longer cover the declared right.
    Policy,
    /// The reference identity itself no longer matches the durable cut: the
    /// presented holder descends from another lineage root.
    Reference,
}

impl SecretStalenessReason {
    /// Every member of the closed vocabulary, in reporting order.
    pub const ALL: [Self; 8] = [
        Self::Holder,
        Self::Tenant,
        Self::Operation,
        Self::Class,
        Self::Generation,
        Self::Lifetime,
        Self::Policy,
        Self::Reference,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Holder => "holder",
            Self::Tenant => "tenant",
            Self::Operation => "operation",
            Self::Class => "class",
            Self::Generation => "generation",
            Self::Lifetime => "lifetime",
            Self::Policy => "policy",
            Self::Reference => "reference",
        }
    }

    /// Returns the same exact portable spelling as [`Self::wire_name`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.wire_name()
    }

    /// Strictly decodes one exact portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.wire_name() == value)
    }
}

/// The verdict of one revalidation immediately before a secret use is admitted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretRevalidation {
    /// Every revalidated input still matches, so the use may be admitted.
    Fresh,
    /// A semantic input changed, so the reference is stale and must not dispatch.
    Stale(SecretStalenessReason),
    /// Revocation or expiry fenced the use before it was committed.
    Fenced(FenceReason),
}

impl SecretRevalidation {
    /// Returns whether the reference may still be used.
    #[must_use]
    pub const fn is_fresh(self) -> bool {
        matches!(self, Self::Fresh)
    }

    /// Returns the staleness that refused this use, when it is stale.
    #[must_use]
    pub const fn staleness(self) -> Option<SecretStalenessReason> {
        match self {
            Self::Stale(reason) => Some(reason),
            Self::Fresh | Self::Fenced(_) => None,
        }
    }

    /// Returns the fencing that refused this use, when it is fenced.
    #[must_use]
    pub const fn fence(self) -> Option<FenceReason> {
        match self {
            Self::Fenced(reason) => Some(reason),
            Self::Fresh | Self::Stale(_) => None,
        }
    }
}

/// One opaque secret or credential reference, bound to capability authority.
///
/// The type owns the live authority instance that carries the reference, so it
/// is not `Clone`: a reference reaches another holder only by an explicit affine
/// move, transfer, or rebinding, each of which is recorded in its derived
/// identity. The type implements a redacted [`fmt::Debug`] and no `Display`, no
/// serializer, and no material accessor.
pub struct SecretReference {
    id: SecretReferenceId,
    holder: SecretHolderBindingId,
    class: ProtectedDataClass,
    tenant: DeclaredName,
    operation: Option<LogicalOperationId>,
    authority: AuthorityInstance,
}

impl fmt::Debug for SecretReference {
    /// Renders the identity metadata of a reference and never its material.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("id", &self.id.as_str())
            .field("holder", &self.holder.as_str())
            .field("class", &self.class.wire_name())
            .field("tenant", &self.tenant.as_str())
            .field(
                "operation",
                &self.operation.as_ref().map(LogicalOperationId::as_str),
            )
            .field("generation", &self.authority.generation().value())
            .field("rights", &self.authority.rights().wire_names())
            .field("lease", &self.authority.lease().wire_name())
            .finish_non_exhaustive()
    }
}

impl SecretReference {
    /// Binds one secret reference to an existing capability instance.
    ///
    /// This is the only constructor of an authority-bearing secret reference,
    /// and it fails closed: a fenced instance, an instance carrying no right at
    /// all, and an instance whose lease already reached its expiry admit
    /// nothing, so no reference is derived from them.
    pub fn bind(
        instance: AuthorityInstance,
        class: ProtectedDataClass,
        tenant: DeclaredName,
        operation: Option<LogicalOperationId>,
    ) -> Result<Self, SecretError> {
        if let FenceState::Fenced(point) = instance.fence_state() {
            return Err(SecretError::Fenced(point.category()));
        }
        if instance.rights().is_empty() {
            return Err(SecretError::Authority(AuthorityError::EmptyRights));
        }
        if matches!(
            instance.lease(),
            AuthorityLeasePolicy::Expiring { expires_at_us: 0 }
        ) {
            return Err(SecretError::Fenced(FenceCategory::Expiry));
        }
        Ok(Self::assemble(instance, class, tenant, operation))
    }

    /// Assembles one reference and derives its identity from its own inputs.
    fn assemble(
        authority: AuthorityInstance,
        class: ProtectedDataClass,
        tenant: DeclaredName,
        operation: Option<LogicalOperationId>,
    ) -> Self {
        let holder = SecretHolderBindingId::bind(&authority, &tenant);
        let id = SecretReferenceId::derive(
            &holder,
            class,
            &tenant,
            authority.generation(),
            operation.as_ref(),
        );
        Self {
            id,
            holder,
            class,
            tenant,
            operation,
            authority,
        }
    }

    /// Returns the canonical reference identity.
    #[must_use]
    pub const fn id(&self) -> &SecretReferenceId {
        &self.id
    }

    /// Returns the holder binding of this reference.
    #[must_use]
    pub const fn holder(&self) -> &SecretHolderBindingId {
        &self.holder
    }

    /// Returns the protected class this reference stands for.
    #[must_use]
    pub const fn class(&self) -> ProtectedDataClass {
        self.class
    }

    /// Returns the tenant that owns this reference.
    #[must_use]
    pub const fn tenant(&self) -> &DeclaredName {
        &self.tenant
    }

    /// Returns the one logical operation this reference may influence.
    #[must_use]
    pub const fn operation(&self) -> Option<&LogicalOperationId> {
        self.operation.as_ref()
    }

    /// Returns the authority generation of the holder.
    #[must_use]
    pub const fn generation(&self) -> AuthorityGeneration {
        self.authority.generation()
    }

    /// Returns the rights the holder currently carries.
    #[must_use]
    pub const fn rights(&self) -> RightsSet {
        self.authority.rights()
    }

    /// Returns the lease policy the holder currently carries.
    #[must_use]
    pub const fn lease(&self) -> AuthorityLeasePolicy {
        self.authority.lease()
    }

    /// Returns the fencing state of the holder's current generation.
    #[must_use]
    pub const fn fence_state(&self) -> FenceState {
        self.authority.fence_state()
    }

    /// Returns the secret uses already admitted through this reference.
    #[must_use]
    pub fn accepted(&self) -> &[Admission] {
        self.authority.accepted()
    }

    /// Attenuates this reference into a descendant that carries less authority.
    ///
    /// Attenuation narrows rights and lease through the landed instance lattice
    /// and re-derives the reference identity for the new generation, while the
    /// class, tenant, and operation are preserved: an attenuated reference can
    /// never amplify a right, extend a lease, adopt another tenant, or serve
    /// another operation. There is no parameter for the class, the tenant, or
    /// the operation binding, so a request that would change one of them cannot
    /// be expressed at all. A refusal of the landed lattice is reported as a
    /// [`SecretError`], so it carries a diagnostic code and an owning clause.
    pub fn attenuate(
        &self,
        requested_rights: RightsSet,
        lease: AuthorityLeasePolicy,
    ) -> Result<Self, SecretError> {
        let narrowed = self
            .authority
            .attenuate(requested_rights, lease)
            .map_err(classify)?;
        Ok(Self::assemble(
            narrowed,
            self.class,
            self.tenant.clone(),
            self.operation.clone(),
        ))
    }

    /// Delegates this reference into a descendant under the delegate right.
    ///
    /// Delegation is attenuation gated by [`AuthorityRight::Delegate`], so a
    /// delegated reference still cannot amplify, add, or restore a right, and
    /// the class, tenant, and operation are preserved. As for attenuation, the
    /// class, the tenant, and the operation binding are not parameters, so a
    /// request that would change one of them cannot be expressed, and a refusal
    /// of the landed lattice is reported as a [`SecretError`].
    pub fn delegate(
        &self,
        requested_rights: RightsSet,
        lease: AuthorityLeasePolicy,
    ) -> Result<Self, SecretError> {
        let narrowed = self
            .authority
            .delegate(requested_rights, lease)
            .map_err(classify)?;
        Ok(Self::assemble(
            narrowed,
            self.class,
            self.tenant.clone(),
            self.operation.clone(),
        ))
    }

    /// Moves this reference to one new holder under the affine move rule.
    ///
    /// The move neither duplicates the reference nor changes its identity,
    /// generation, rights, lease, or fencing state.
    #[must_use]
    pub fn transfer_affine(self) -> Self {
        Self {
            id: self.id,
            holder: self.holder,
            class: self.class,
            tenant: self.tenant,
            operation: self.operation,
            authority: self.authority.affine_move(),
        }
    }

    /// Transfers this reference onto a successor instance of the same binding.
    ///
    /// The transfer is affine: the prior reference is consumed, so exactly one
    /// reference remains for the holder. The successor must satisfy the same
    /// requirement and binding and must carry a strictly later generation, so a
    /// transfer can never rewind authority. A fenced current or successor
    /// generation is refused rather than reinstated.
    pub fn transfer(self, successor: AuthorityInstance) -> Result<Self, SecretError> {
        if let FenceState::Fenced(point) = self.authority.fence_state() {
            let _ = point;
            return Err(SecretError::ReinstatementForbidden);
        }
        if successor.requirement() != self.authority.requirement()
            || successor.binding() != self.authority.binding()
        {
            return Err(SecretError::TransferHolderMismatch);
        }
        if let FenceState::Fenced(point) = successor.fence_state() {
            return Err(SecretError::Fenced(point.category()));
        }
        if successor.generation().value() <= self.authority.generation().value() {
            return Err(SecretError::TransferNotSucceeding);
        }
        Ok(Self::assemble(
            successor,
            self.class,
            self.tenant,
            self.operation,
        ))
    }

    /// Rebinds this reference to a replacement binding of the same requirement.
    ///
    /// Rebinding consumes the reference and returns its replacement, so exactly
    /// one live reference remains for the requirement. The replacement keeps the
    /// class, tenant, and operation, uses the replacement binding, and starts a
    /// fresh generation, so a presentation of the prior generation is stale. A
    /// revoked or expired generation fails closed, because no rebinding may
    /// revive one.
    pub fn rebind(self, binding: AuthorityBindingId) -> Result<Self, SecretError> {
        if binding.requirement() != self.authority.requirement() {
            return Err(SecretError::RebindRequirementMismatch);
        }
        if let FenceState::Fenced(_) = self.authority.fence_state() {
            return Err(SecretError::ReinstatementForbidden);
        }
        let rebound = self.authority.rebind(binding).map_err(classify)?;
        Ok(Self::assemble(
            rebound,
            self.class,
            self.tenant,
            self.operation,
        ))
    }

    /// Admits one secret use after cross-checking the operation and tenant.
    ///
    /// The operation and tenant are cross-checked first, because they identify
    /// which secret is being used at all; only then is the request revalidated
    /// and admitted by the landed authority admission order, whose last step is
    /// the single commit point. A refusal records nothing and leaves every
    /// previously accepted use untouched.
    pub fn admit_use(
        &mut self,
        request: &AdmissionRequest,
        ancestors: &AncestorFences,
        operation: &LogicalOperationId,
        tenant: &DeclaredName,
    ) -> Result<Admission, SecretError> {
        if tenant != &self.tenant {
            return Err(SecretError::TenantMismatch);
        }
        if let Some(bound) = &self.operation
            && bound != operation
        {
            return Err(SecretError::OperationMismatch);
        }
        self.authority.admit(request, ancestors).map_err(classify)
    }

    /// Revokes the holder at its single linearization point.
    ///
    /// A repeated revocation returns the point it already held, so a generation
    /// is never reinstated by revoking it again.
    pub fn revoke(&mut self) -> FencePoint {
        self.authority.revoke()
    }

    /// Fences the holder by expiry, a distinct category from revocation.
    pub fn expire(&mut self) -> FencePoint {
        self.authority.expire()
    }

    /// Revalidates one attempted use without mutating any state.
    ///
    /// The verdict is pure: fencing is reported before any staleness, a stale
    /// reference is never repaired, and no check latches a fence. Fencing is
    /// checked first, because a fenced generation admits nothing regardless of
    /// which other input changed.
    #[must_use]
    pub fn revalidate(
        &self,
        request: &AdmissionRequest,
        operation: &LogicalOperationId,
        tenant: &DeclaredName,
    ) -> SecretRevalidation {
        if let FenceState::Fenced(point) = self.authority.fence_state() {
            return SecretRevalidation::Fenced(fence_reason(point.category()));
        }
        if tenant != &self.tenant {
            return SecretRevalidation::Stale(SecretStalenessReason::Tenant);
        }
        if let Some(bound) = &self.operation
            && bound != operation
        {
            return SecretRevalidation::Stale(SecretStalenessReason::Operation);
        }
        if request.generation != self.authority.generation() {
            return SecretRevalidation::Stale(SecretStalenessReason::Generation);
        }
        if !self.authority.lease().permits(request.now_us) {
            return SecretRevalidation::Stale(SecretStalenessReason::Lifetime);
        }
        let required = AuthorityRight::for_recovery_class(request.recovery);
        if request.right != required {
            return SecretRevalidation::Stale(SecretStalenessReason::Class);
        }
        if !self.authority.rights().contains(required) {
            return SecretRevalidation::Stale(SecretStalenessReason::Policy);
        }
        SecretRevalidation::Fresh
    }

    /// Renders the identity metadata of this reference and no material.
    #[must_use]
    pub fn redacted_text(&self) -> String {
        format!(
            "secret-reference:class={};tenant={};generation={};operation={};rights={};lease={};fence={}",
            self.class.wire_name(),
            self.tenant.as_str(),
            self.authority.generation().value(),
            self.operation
                .as_ref()
                .map_or("none", LogicalOperationId::as_str),
            self.authority.rights().wire_names().join(","),
            self.authority.lease().wire_name(),
            if self.authority.fence_state().is_fenced() {
                "fenced"
            } else {
                "open"
            }
        )
    }
}

/// Revalidates one secret use against one reference without mutating it.
///
/// This is the free-function form of [`SecretReference::revalidate`], so a
/// commit-point caller can hold a revalidation as a pure function of the
/// reference, the request, the logical operation, and the tenant.
#[must_use]
pub fn revalidate_secret(
    reference: &SecretReference,
    request: &AdmissionRequest,
    operation: &LogicalOperationId,
    tenant: &DeclaredName,
) -> SecretRevalidation {
    reference.revalidate(request, operation, tenant)
}

/// One capability that admits the declared view of one tenant's secret audit
/// evidence.
///
/// Secret audit evidence names the holder, tenant, and identity of a secret use,
/// so observing it is an explicit, typed act rather than an ordinary field read
/// or rendering. The evidence store issues this capability to a holder whose
/// declared rights contain [`AuthorityRight::Observe`], the landed right of
/// reading the audit record of an admitted operation; a rights set without it is
/// refused rather than narrowed. The capability is bound to the tenant that
/// holds it, so it admits the evidence of that tenant and of no other. This
/// constructor is the declared-rights gate, not cryptographic enforcement: it
/// checks the rights the holder declares, and this pure model cannot verify that
/// a host bound them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretAuditAccess {
    tenant: DeclaredName,
}

impl SecretAuditAccess {
    /// Returns the secret-audit capability of one holder carrying the observe
    /// right under one tenant.
    #[must_use]
    pub fn grant(rights: RightsSet, tenant: &DeclaredName) -> Option<Self> {
        if rights.contains(AuthorityRight::Observe) {
            Some(Self {
                tenant: tenant.clone(),
            })
        } else {
            None
        }
    }

    /// Returns the tenant whose evidence this capability admits.
    #[must_use]
    pub const fn tenant(&self) -> &DeclaredName {
        &self.tenant
    }
}

/// The outcome recorded for one attempted secret use.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SecretAuditOutcome {
    /// The use passed the admission commit point.
    Admitted,
    /// The use was fenced before it was committed.
    Fenced,
    /// The use was refused because a revalidated input changed.
    Stale,
    /// The use was refused before revalidation, for example across tenants.
    Refused,
}

impl SecretAuditOutcome {
    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Admitted => "admitted",
            Self::Fenced => "fenced",
            Self::Stale => "stale",
            Self::Refused => "refused",
        }
    }
}

/// One secret audit record: declared identity metadata only.
///
/// The evidence identifies the reference, its holder binding, the tenant, the
/// protected class, the authority generation, the logical instants of issue and
/// expiry, the recorded outcome, the admission when one was committed, and every
/// later transition. It carries no credential, no material, no digest of
/// material, and no protected payload, and it is itself protected: it implements
/// no rendering trait and no deserializer, and its fields are reachable only
/// through [`SecretAuditEvidence::view`] under a [`SecretAuditAccess`]
/// capability of the same tenant. [`SecretAuditEvidence::redacted_text`] is a
/// separate redacted aggregate of the same record rather than another path to
/// those fields.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretAuditEvidence {
    reference: SecretReferenceId,
    holder: SecretHolderBindingId,
    tenant: DeclaredName,
    class: ProtectedDataClass,
    generation: AuthorityGeneration,
    issued_at_us: u64,
    expires_at_us: Option<u64>,
    outcome: SecretAuditOutcome,
    admission: Option<Admission>,
    transitions: Vec<AuditTransition>,
}

impl SecretAuditEvidence {
    /// Records one attempted secret use at one logical instant.
    ///
    /// An admitted use is accepted only together with the admission that
    /// committed it at the reference's own generation, so evidence never claims
    /// an admission that was not committed through this reference; a use that
    /// was not admitted carries no admission at all, so evidence never claims
    /// one either.
    pub fn record(
        reference: &SecretReference,
        outcome: SecretAuditOutcome,
        admission: Option<Admission>,
        at_us: u64,
    ) -> Result<Self, SecretError> {
        match (outcome, admission) {
            (SecretAuditOutcome::Admitted, Some(admission)) => {
                if admission.generation() != reference.generation() {
                    return Err(SecretError::InadmissibleAuditRecord);
                }
            }
            (SecretAuditOutcome::Admitted, None) | (_, Some(_)) => {
                return Err(SecretError::InadmissibleAuditRecord);
            }
            (_, None) => {}
        }
        Ok(Self {
            reference: reference.id.clone(),
            holder: reference.holder.clone(),
            tenant: reference.tenant.clone(),
            class: reference.class,
            generation: reference.generation(),
            issued_at_us: at_us,
            expires_at_us: reference.lease().expires_at_us(),
            outcome,
            admission,
            transitions: Vec::new(),
        })
    }

    /// Records one later transition of this known use.
    pub fn record_transition(&mut self, transition: AuditTransition) {
        self.transitions.push(transition);
    }

    /// Returns this evidence with one later transition appended.
    #[must_use]
    pub fn with_transition(mut self, transition: AuditTransition) -> Self {
        self.record_transition(transition);
        self
    }

    /// Returns the declared view of this evidence under one access capability.
    ///
    /// This is the only path to the typed fields of the evidence, so no field
    /// read reaches them without a capability bound to this evidence's own
    /// tenant; a capability of another tenant returns `None` rather than a view.
    /// [`SecretAuditEvidence::redacted_text`] is a separate redacted aggregate
    /// of the same record, not another path to these fields.
    pub fn view(&self, access: &SecretAuditAccess) -> Option<SecretAuditView<'_>> {
        if access.tenant() != &self.tenant {
            return None;
        }
        Some(SecretAuditView {
            reference: &self.reference,
            holder: &self.holder,
            tenant: &self.tenant,
            class: self.class,
            generation: self.generation,
            issued_at_us: self.issued_at_us,
            expires_at_us: self.expires_at_us,
            outcome: self.outcome,
            admission: self.admission,
            transitions: &self.transitions,
        })
    }

    /// Renders the identity metadata of this evidence and no material.
    #[must_use]
    pub fn redacted_text(&self) -> String {
        format!(
            "secret-audit:class={};tenant={};generation={};issued-at-us={};expires-at-us={};outcome={};admission={};transitions={}",
            self.class.wire_name(),
            self.tenant.as_str(),
            self.generation.value(),
            self.issued_at_us,
            self.expires_at_us
                .map_or_else(|| "none".to_owned(), |value| value.to_string()),
            self.outcome.wire_name(),
            self.admission.map_or_else(
                || "none".to_owned(),
                |admission| format!(
                    "{}@{}",
                    admission.sequence(),
                    admission.generation().value()
                )
            ),
            self.transitions.len()
        )
    }
}

/// The declared view of one secret audit record: identity metadata, no material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecretAuditView<'a> {
    reference: &'a SecretReferenceId,
    holder: &'a SecretHolderBindingId,
    tenant: &'a DeclaredName,
    class: ProtectedDataClass,
    generation: AuthorityGeneration,
    issued_at_us: u64,
    expires_at_us: Option<u64>,
    outcome: SecretAuditOutcome,
    admission: Option<Admission>,
    transitions: &'a [AuditTransition],
}

impl<'a> SecretAuditView<'a> {
    /// Returns the audited reference identity.
    #[must_use]
    pub const fn reference(self) -> &'a SecretReferenceId {
        self.reference
    }

    /// Returns the audited holder binding.
    #[must_use]
    pub const fn holder(self) -> &'a SecretHolderBindingId {
        self.holder
    }

    /// Returns the audited tenant.
    #[must_use]
    pub const fn tenant(self) -> &'a DeclaredName {
        self.tenant
    }

    /// Returns the audited protected class.
    #[must_use]
    pub const fn class(self) -> ProtectedDataClass {
        self.class
    }

    /// Returns the audited authority generation.
    #[must_use]
    pub const fn generation(self) -> AuthorityGeneration {
        self.generation
    }

    /// Returns the logical instant this evidence was issued at.
    #[must_use]
    pub const fn issued_at_us(self) -> u64 {
        self.issued_at_us
    }

    /// Returns the logical expiry of the audited lease, when it carries one.
    #[must_use]
    pub const fn expires_at_us(self) -> Option<u64> {
        self.expires_at_us
    }

    /// Returns the recorded outcome of the audited use.
    #[must_use]
    pub const fn outcome(self) -> SecretAuditOutcome {
        self.outcome
    }

    /// Returns the admission committed for the audited use, when one was.
    #[must_use]
    pub const fn admission(self) -> Option<Admission> {
        self.admission
    }

    /// Returns the recorded later transitions of the audited use.
    #[must_use]
    pub const fn transitions(self) -> &'a [AuditTransition] {
        self.transitions
    }

    /// Renders the canonical text of this audited record.
    ///
    /// The rendering names the clause that owns the record and every identity
    /// input of the decision. It carries no material and no digest of material.
    #[must_use]
    pub fn canonical_text(self) -> String {
        let transitions = self
            .transitions
            .iter()
            .map(|transition| transition.canonical_text())
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "clause={};reference={};holder-requirement={};holder-binding={};holder={};tenant={};class={};generation={};issued-at-us={};expires-at-us={};outcome={};admission={};transitions={}",
            SECRET_OWNING_CLAUSE,
            self.reference.as_str(),
            self.holder.requirement().as_str(),
            self.holder.binding().as_str(),
            self.holder.holder().as_str(),
            self.tenant.as_str(),
            self.class.wire_name(),
            self.generation.value(),
            self.issued_at_us,
            self.expires_at_us
                .map_or_else(|| "none".to_owned(), |value| value.to_string()),
            self.outcome.wire_name(),
            self.admission.map_or_else(
                || "none".to_owned(),
                |admission| format!(
                    "{}@{}",
                    admission.sequence(),
                    admission.generation().value()
                )
            ),
            transitions
        )
    }
}

/// The cut one durable secret record observed.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SecretDurableCut {
    /// The reference was issued.
    Issued,
    /// The reference was revalidated after a resume.
    Revalidated,
    /// The reference was fenced before it was committed.
    Fenced,
    /// The reference's holder was revoked.
    Revoked,
    /// The reference's lease reached its expiry.
    Expired,
}

impl SecretDurableCut {
    /// Every member of the closed vocabulary, in reporting order.
    pub const ALL: [Self; 5] = [
        Self::Issued,
        Self::Revalidated,
        Self::Fenced,
        Self::Revoked,
        Self::Expired,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Issued => "issued",
            Self::Revalidated => "revalidated",
            Self::Fenced => "fenced",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }
}

/// How a durable secret record may be resumed.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SecretResumeClass {
    /// The cut is issued and unfenced, so the record may continue.
    Continue,
    /// The cut was revalidated before, so a fresh revalidation is required.
    Revalidate,
    /// Authority was revoked, so no resume may proceed without fresh approval.
    ReApproval,
    /// The cut is fenced, so no resume may proceed at all.
    Fenced,
}

impl SecretResumeClass {
    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Continue => "continue",
            Self::Revalidate => "revalidate",
            Self::ReApproval => "re-approval",
            Self::Fenced => "fenced",
        }
    }
}

/// One durable secret cut: identities, class, generation, operation, and cut.
///
/// The record is ordinary durable evidence, not a handle: it carries no live
/// authority instance, no rights, no lease, and no material, so a checkpoint
/// never restores a process-local handle. Resuming therefore presents a live
/// successor instance to [`DurableSecretReference::rebind`], which revalidates
/// the cut and fails closed on any change.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableSecretReference {
    id: SecretReferenceId,
    holder: SecretHolderBindingId,
    root: AuthorityInstanceId,
    tenant: DeclaredName,
    class: ProtectedDataClass,
    generation: AuthorityGeneration,
    operation: Option<LogicalOperationId>,
    cut: SecretDurableCut,
}

impl DurableSecretReference {
    /// Commits one durable cut of an existing reference.
    ///
    /// This is the only constructor, so a durable cut can never be written by
    /// hand, deserialized, or assembled from material.
    #[must_use]
    pub fn commit(reference: &SecretReference) -> Self {
        Self {
            id: reference.id.clone(),
            holder: reference.holder.clone(),
            root: reference.authority.root().clone(),
            tenant: reference.tenant.clone(),
            class: reference.class,
            generation: reference.generation(),
            operation: reference.operation.clone(),
            cut: SecretDurableCut::Issued,
        }
    }

    /// Returns the committed reference identity.
    #[must_use]
    pub const fn reference(&self) -> &SecretReferenceId {
        &self.id
    }

    /// Returns the durability cut this record observed.
    #[must_use]
    pub const fn cut(&self) -> SecretDurableCut {
        self.cut
    }

    /// Returns the generation the reference held at the cut.
    #[must_use]
    pub const fn generation(&self) -> AuthorityGeneration {
        self.generation
    }

    /// Returns this record with the cut the durable store observed.
    #[must_use]
    pub fn with_cut(mut self, cut: SecretDurableCut) -> Self {
        self.cut = cut;
        self
    }

    /// Revalidates the cut against the successor instance presented at resume.
    ///
    /// The verdict is pure. Fencing is reported first, then the holder binding,
    /// then the lineage root, then the generation, then the lease, so a resume
    /// never proceeds on a replanted, rewound, or expired holder. A durable
    /// successor must strictly advance the recorded generation, so an instance
    /// still at the cut's own generation is stale rather than fresh.
    #[must_use]
    pub fn revalidate(&self, instance: &AuthorityInstance, now_us: u64) -> SecretRevalidation {
        if let FenceState::Fenced(point) = instance.fence_state() {
            return SecretRevalidation::Fenced(fence_reason(point.category()));
        }
        if instance.requirement() != self.holder.requirement()
            || instance.binding() != self.holder.binding()
        {
            return SecretRevalidation::Stale(SecretStalenessReason::Holder);
        }
        if instance.root() != &self.root {
            return SecretRevalidation::Stale(SecretStalenessReason::Reference);
        }
        if instance.generation().value() <= self.generation.value() {
            return SecretRevalidation::Stale(SecretStalenessReason::Generation);
        }
        if !instance.lease().permits(now_us) {
            return SecretRevalidation::Stale(SecretStalenessReason::Lifetime);
        }
        SecretRevalidation::Fresh
    }

    /// Resumes the cut onto one live successor instance with explicit inputs.
    ///
    /// The recorded cut is checked before anything else: a fenced, expired, or
    /// revoked cut records authority that already ended, so it is never a
    /// standing authorization after resume and is refused rather than
    /// reinstated. Otherwise every identity input of the resumed reference is
    /// presented explicitly, so a changed operation, class, or tenant is refused
    /// rather than silently adopted, and a successor that does not satisfy the
    /// committed requirement, binding, and lineage root, does not strictly
    /// advance the generation, or is fenced is refused as well.
    pub fn resume(
        &self,
        instance: AuthorityInstance,
        class: ProtectedDataClass,
        tenant: &DeclaredName,
        operation: Option<&LogicalOperationId>,
    ) -> Result<SecretReference, SecretError> {
        match self.cut {
            SecretDurableCut::Fenced | SecretDurableCut::Expired | SecretDurableCut::Revoked => {
                return Err(SecretError::ReinstatementForbidden);
            }
            SecretDurableCut::Issued | SecretDurableCut::Revalidated => {}
        }
        if tenant != &self.tenant {
            return Err(SecretError::TenantChangeForbidden);
        }
        if operation != self.operation.as_ref() {
            return Err(SecretError::RebindRequirementMismatch);
        }
        if class != self.class {
            return Err(SecretError::ClassChangeForbidden);
        }
        if instance.requirement() != self.holder.requirement()
            || instance.binding() != self.holder.binding()
        {
            return Err(SecretError::RebindRequirementMismatch);
        }
        if instance.root() != &self.root {
            return Err(SecretError::RebindRequirementMismatch);
        }
        if let FenceState::Fenced(point) = instance.fence_state() {
            return Err(SecretError::Fenced(point.category()));
        }
        if instance.generation().value() <= self.generation.value() {
            return Err(SecretError::StaleGeneration);
        }
        SecretReference::bind(instance, class, tenant.clone(), operation.cloned())
    }

    /// Rebinds the cut onto one live successor instance.
    ///
    /// The requirement, binding, class, tenant, operation, and lineage root must
    /// match the committed cut, the cut itself must be issued or revalidated, and
    /// the generation must strictly advance. The successor is consumed, because a
    /// durable cut never restores a process-local handle: the caller must present
    /// the live instance it already holds.
    pub fn rebind(&self, instance: AuthorityInstance) -> Result<SecretReference, SecretError> {
        self.resume(instance, self.class, &self.tenant, self.operation.as_ref())
    }

    /// Classifies how the durable store may resume this record.
    ///
    /// The classification is a hint for the resuming runtime, never an
    /// authority grant of its own: a fenced, expired, or revoked cut is refused
    /// by [`Self::resume`] and [`Self::rebind`] before they inspect any instance.
    #[must_use]
    pub const fn classify_resume(&self) -> SecretResumeClass {
        match self.cut {
            SecretDurableCut::Issued => SecretResumeClass::Continue,
            SecretDurableCut::Revalidated => SecretResumeClass::Revalidate,
            SecretDurableCut::Fenced | SecretDurableCut::Expired => SecretResumeClass::Fenced,
            SecretDurableCut::Revoked => SecretResumeClass::ReApproval,
        }
    }

    /// Renders the identity metadata of this cut and no material.
    #[must_use]
    pub fn redacted_text(&self) -> String {
        format!(
            "durable-secret-cut:cut={};class={};tenant={};generation={};operation={}",
            self.cut.wire_name(),
            self.class.wire_name(),
            self.tenant.as_str(),
            self.generation.value(),
            self.operation
                .as_ref()
                .map_or("none", LogicalOperationId::as_str)
        )
    }
}

/// One exact property of the secret model that is excluded from its claim.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SecretNonClaimName {
    /// The model does not promise physical zeroization of material.
    PhysicalZeroization,
    /// The model prohibits ordinary extraction of material.
    OrdinaryExtraction,
    /// The model does not promise to prevent ambient discovery of credentials.
    AmbientDiscovery,
    /// The model does not promise that a bearer without lineage is unusable.
    BearerWithoutLineage,
    /// The model prohibits serializing a reference or restoring a handle from a
    /// checkpoint.
    CheckpointSerialization,
}

impl SecretNonClaimName {
    /// Every member of the closed vocabulary, in reporting order.
    pub const ALL: [Self; 5] = [
        Self::PhysicalZeroization,
        Self::OrdinaryExtraction,
        Self::AmbientDiscovery,
        Self::BearerWithoutLineage,
        Self::CheckpointSerialization,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::PhysicalZeroization => "physical-zeroization",
            Self::OrdinaryExtraction => "ordinary-extraction",
            Self::AmbientDiscovery => "ambient-discovery",
            Self::BearerWithoutLineage => "bearer-without-lineage",
            Self::CheckpointSerialization => "checkpoint-serialization",
        }
    }

    /// Returns the same exact portable spelling as [`Self::wire_name`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.wire_name()
    }

    /// Strictly decodes one exact portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.wire_name() == value)
    }
}

/// One excluded secret claim, of one exact kind and one exact name.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SecretNonClaim {
    kind: ExcludedClaimKind,
    name: SecretNonClaimName,
}

impl SecretNonClaim {
    /// Returns whether this claim is a property the model does not promise.
    #[must_use]
    pub const fn is_not_promised(self) -> bool {
        matches!(self.kind, ExcludedClaimKind::NotPromised)
    }

    /// Returns whether this claim is a practice the model prohibits.
    #[must_use]
    pub const fn is_prohibited(self) -> bool {
        matches!(self.kind, ExcludedClaimKind::Prohibited)
    }

    /// Returns the kind of exclusion.
    #[must_use]
    pub const fn kind(self) -> ExcludedClaimKind {
        self.kind
    }

    /// Returns the exact claim name.
    #[must_use]
    pub const fn name(self) -> SecretNonClaimName {
        self.name
    }

    /// Returns the exact portable spelling of the excluded claim.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        self.name.wire_name()
    }
}

/// Every excluded secret claim in the fixed reporting order of this module.
pub const SECRET_NON_CLAIM_ORDER: [SecretNonClaimName; 5] = [
    SecretNonClaimName::PhysicalZeroization,
    SecretNonClaimName::OrdinaryExtraction,
    SecretNonClaimName::AmbientDiscovery,
    SecretNonClaimName::BearerWithoutLineage,
    SecretNonClaimName::CheckpointSerialization,
];

/// The claims the secret model excludes: three un-promised properties and two
/// prohibitions.
///
/// What the model prohibits is what it refuses to provide at all: ordinary
/// extraction of material and serialization of a reference or restoration of a
/// process-local handle from a checkpoint. What it does not promise is what a
/// bounded claim cannot establish here: physical zeroization, prevention of
/// ambient credential discovery, and unusability of a bearer without lineage.
/// The order matches [`SECRET_NON_CLAIM_ORDER`].
pub const SECRET_NON_CLAIMS: [SecretNonClaim; 5] = [
    SecretNonClaim {
        kind: ExcludedClaimKind::NotPromised,
        name: SecretNonClaimName::PhysicalZeroization,
    },
    SecretNonClaim {
        kind: ExcludedClaimKind::Prohibited,
        name: SecretNonClaimName::OrdinaryExtraction,
    },
    SecretNonClaim {
        kind: ExcludedClaimKind::NotPromised,
        name: SecretNonClaimName::AmbientDiscovery,
    },
    SecretNonClaim {
        kind: ExcludedClaimKind::NotPromised,
        name: SecretNonClaimName::BearerWithoutLineage,
    },
    SecretNonClaim {
        kind: ExcludedClaimKind::Prohibited,
        name: SecretNonClaimName::CheckpointSerialization,
    },
];
