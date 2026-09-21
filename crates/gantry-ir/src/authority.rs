//! Pure capability-instance identity, rights, lineage, fencing, and admission
//! model.
//!
//! This module is the machine-checked identity and lattice model for
//! `GNT-3-T-AUTHORITY-INSTANCES`, `GNT-3-T-AUTHORITY-LINEAGE`,
//! `GNT-3-T-AUTHORITY-REVOCATION`, `GNT-3-T-AUTHORITY-ADMISSION`,
//! `GNT-3-T-AUTHORITY-CLOSURE`, `GNT-7.2-authority-rebinding`, and
//! `GNT-11.6-authority-instance-compatibility`.
//!
//! Scope is deliberately narrow: this module models identity, the rights
//! lattice, lineage linearization, and the admission and fencing decision order.
//! It is not the runtime authority store. No live instance, host handle,
//! integration binding, or protected payload appears here, so every rule it
//! states is reproducible from its own arguments. What the specification
//! forbids for source code (constructing, casting, copying, or serializing an
//! instance) is carried here by the absence of any deserialization, any
//! byte-level constructor, and any public identity derivation, together with the
//! integration binding that alone confers authority; that binding is owned
//! downstream of this model and is not represented here. Canonical identity
//! text is explicit and stable; Rust `Debug` and `Display` renderings of other
//! crates are never protocol identities.
//!
//! The identity layers of the specification stay distinct here:
//!
//! * the public capability requirement of `GNT-6.5-abstract-requirements` item
//!   5a is [`AuthorityRequirementId`];
//! * the selected implementation binding of `GNT-3-T-AUTHORITY-CLOSURE` is
//!   [`AuthorityBindingId`];
//! * the conservative executable closure of `GNT-3-T-AUTHORITY-CLOSURE` over
//!   those bindings and their site-qualified requirement slots is
//!   [`CapabilityAuthorityClosure`];
//! * one site-qualified requirement slot of that closure is
//!   [`SiteRequirementSlotId`];
//! * the concrete runtime instance is [`AuthorityInstanceId`] and
//!   [`AuthorityInstance`].
//!
//! An instance identity is a domain-separated SHA-256 digest over the
//! canonical encoding of its requirement, binding, generation, rights set,
//! parent edge, and lineage root, so it cannot equal a requirement identity, an
//! operation-site identity, or a callable identity, and two distinct
//! descendants of one parent never share one identity.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

use sha2::{Digest, Sha256};

use crate::agent::{ToolSlotId, ToolSlotKind};
use crate::facts::StaticSiteId;
use crate::generated::RecoveryClass;
use crate::manifest::encode_hex;
use crate::{CanonicalImplementationIdentity, CanonicalPath, CanonicalSignature};

/// Domain separator for canonical instance-identity derivation.
const INSTANCE_DOMAIN: &str = "gantry.authority-instance/v1";

/// All authority rights in the fixed reporting order of this module.
///
/// SPEC.md defines no normative order over rights, so this order is a
/// deterministic presentation order only: it fixes how [`RightsSet`] listings
/// and portable spellings are emitted, and carries no authority of its own.
pub const AUTHORITY_RIGHT_ORDER: [AuthorityRight; 5] = [
    AuthorityRight::Observe,
    AuthorityRight::InvokeReadOnly,
    AuthorityRight::InvokeIdempotent,
    AuthorityRight::InvokeNonIdempotent,
    AuthorityRight::Delegate,
];

/// One right a capability instance can carry.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AuthorityRight {
    /// Read the outcome or the audit record of an admitted operation.
    Observe,
    /// Dispatch an operation whose recovery class is `read_only`.
    InvokeReadOnly,
    /// Dispatch an operation whose recovery class is `idempotent`.
    InvokeIdempotent,
    /// Dispatch an operation whose recovery class is `non_idempotent`.
    InvokeNonIdempotent,
    /// Produce a descendant instance by delegation.
    ///
    /// This is a delegation-only right: it gates [`AuthorityInstance::delegate`]
    /// and never admits dispatch work, because no recovery class requires it and
    /// [`AuthorityRight::for_recovery_class`] therefore never returns it.
    Delegate,
}

impl AuthorityRight {
    /// Returns the right one action recovery class requires.
    ///
    /// Only the three dispatch rights are ever required, so a request declaring
    /// [`AuthorityRight::Observe`] or [`AuthorityRight::Delegate`] never matches
    /// the required right and can never admit dispatch.
    #[must_use]
    pub const fn for_recovery_class(recovery: RecoveryClass) -> Self {
        match recovery {
            RecoveryClass::ReadOnly => Self::InvokeReadOnly,
            RecoveryClass::Idempotent => Self::InvokeIdempotent,
            RecoveryClass::NonIdempotent => Self::InvokeNonIdempotent,
        }
    }

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Observe => "observe",
            Self::InvokeReadOnly => "invoke-read-only",
            Self::InvokeIdempotent => "invoke-idempotent",
            Self::InvokeNonIdempotent => "invoke-non-idempotent",
            Self::Delegate => "delegate",
        }
    }

    /// Strictly decodes one exact portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        AUTHORITY_RIGHT_ORDER
            .into_iter()
            .find(|right| right.wire_name() == value)
    }
}

/// One finite set of authority rights.
///
/// Membership is the admission test of `GNT-3-T-AUTHORITY-INSTANCES`: an
/// operation admits only when its declared right is a member of the rights set
/// of the instance currently bound for its requirement.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct RightsSet(u8);

impl RightsSet {
    /// Returns the empty rights set, which admits no operation at all.
    #[must_use]
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Builds a rights set from rights in any order.
    #[must_use]
    pub fn from_rights(rights: &[AuthorityRight]) -> Self {
        let mut set = Self::empty();
        for right in rights {
            set.insert(*right);
        }
        set
    }

    /// Inserts one right and returns whether the set changed.
    pub fn insert(&mut self, right: AuthorityRight) -> bool {
        let bit = right_bit(right);
        let changed = self.0 & bit == 0;
        self.0 |= bit;
        changed
    }

    /// Returns whether one right is a member.
    #[must_use]
    pub const fn contains(self, right: AuthorityRight) -> bool {
        self.0 & right_bit(right) != 0
    }

    /// Returns whether this set is a subset of `other`.
    #[must_use]
    pub const fn is_subset_of(self, other: Self) -> bool {
        self.0 & !other.0 == 0
    }

    /// Returns whether this set is a strict subset of `other`.
    #[must_use]
    pub const fn is_strict_subset_of(self, other: Self) -> bool {
        self.is_subset_of(other) && self.0 != other.0
    }

    /// Returns whether the set contains no right.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Returns the canonical membership bits of this set.
    ///
    /// The byte is the canonical encoding of membership used by instance
    /// identity derivation: it depends only on which rights are members and
    /// never on insertion order, so equal sets always share one encoding.
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Returns the members in the reporting order of this module.
    pub fn iter(self) -> impl Iterator<Item = AuthorityRight> {
        AUTHORITY_RIGHT_ORDER
            .into_iter()
            .filter(move |right| self.contains(*right))
    }

    /// Returns the portable spellings in the reporting order of this module.
    #[must_use]
    pub fn wire_names(self) -> Vec<&'static str> {
        self.iter().map(AuthorityRight::wire_name).collect()
    }
}

const fn right_bit(right: AuthorityRight) -> u8 {
    match right {
        AuthorityRight::Observe => 1,
        AuthorityRight::InvokeReadOnly => 2,
        AuthorityRight::InvokeIdempotent => 4,
        AuthorityRight::InvokeNonIdempotent => 8,
        AuthorityRight::Delegate => 16,
    }
}

/// One canonical public capability requirement identity.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AuthorityRequirementId(Arc<str>);

impl AuthorityRequirementId {
    /// Constructs the canonical identity of one public capability requirement.
    ///
    /// The identity is the package-qualified declaration path, the complete
    /// canonical typed signature, the capability family, and the recovery
    /// class. Every variable-length part is length-prefixed, so two different
    /// requirements cannot share one identity.
    pub fn new(
        path: &CanonicalPath,
        signature: &CanonicalSignature,
        capability_family: &str,
        recovery: RecoveryClass,
    ) -> Result<Self, AuthorityError> {
        validate_capability_family(capability_family)?;
        Ok(Self(Arc::from(format!(
            "capability-requirement:{}:{}:{}:{}",
            encode_text(path.as_str()),
            encode_text(signature.as_str()),
            encode_text(capability_family),
            recovery.wire_name()
        ))))
    }

    /// Returns the exact portable identity spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One canonical selected-implementation binding for a requirement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityBindingId {
    requirement: AuthorityRequirementId,
    text: Arc<str>,
}

impl AuthorityBindingId {
    /// Constructs the binding identity of one requirement and its selected
    /// implementation.
    #[must_use]
    pub fn new(
        requirement: &AuthorityRequirementId,
        implementation: &CanonicalImplementationIdentity,
    ) -> Self {
        Self {
            requirement: requirement.clone(),
            text: Arc::from(format!(
                "capability-binding:{}:{}",
                encode_text(requirement.as_str()),
                encode_text(implementation.as_str())
            )),
        }
    }

    /// Returns the requirement this binding satisfies.
    #[must_use]
    pub const fn requirement(&self) -> &AuthorityRequirementId {
        &self.requirement
    }

    /// Returns the exact portable identity spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }
}

/// One conservative executable authority closure of one analyzed artifact.
///
/// `GNT-3-T-AUTHORITY-CLOSURE` requires the least set of capability-binding
/// instances over the exact operation sites reachable from retained roots. This
/// value holds exactly the bindings its caller proved reachable: instances are
/// deduplicated by binding identity and ordered canonically by that same
/// identity, so two closures over the same reachable sites are equal whatever
/// the declaration or traversal order. Least-ness is the caller's obligation;
/// this type never adds an instance the caller did not supply, so a declaration
/// the caller did not prove reachable cannot enter the closure. The same
/// discipline governs requirement slots: the value holds exactly the
/// site-qualified slots its caller supplied, deduplicated and canonically
/// ordered by slot identity, and it never derives or adds one. [`Self::len`] and
/// [`Self::is_empty`] report the binding count only.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityAuthorityClosure {
    instances: Vec<AuthorityBindingId>,
    slots: Vec<SiteRequirementSlotId>,
}

impl CapabilityAuthorityClosure {
    /// The largest number of supplied instances one construction admits.
    ///
    /// The bound is this module's declared resource limit, not a normative
    /// language constant: a larger input is refused with
    /// [`AuthorityError::ClosureExceedsMaximum`] instead of being truncated, so
    /// one closure construction is bounded in time and memory by this constant.
    /// The bound is measured over the supplied instances before deduplication,
    /// so duplicates count toward it.
    pub const MAXIMUM_INSTANCES: usize = 4096;

    /// The largest number of supplied requirement slots one construction admits.
    ///
    /// The bound is measured over the supplied slots before deduplication, so
    /// duplicates count toward it, and a larger input is refused with
    /// [`AuthorityError::ClosureExceedsMaximum`] instead of being truncated.
    pub const MAXIMUM_SLOTS: usize = 4096;

    /// Builds the closure over the supplied reachable capability bindings.
    ///
    /// Instances are deduplicated by binding identity and ordered canonically by
    /// that identity. A closure built this way declares no requirement slot,
    /// which is exact for a reachable set whose operation sites expose no slot.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityError::ClosureExceedsMaximum`] when the supplied
    /// instances exceed [`Self::MAXIMUM_INSTANCES`].
    pub fn new(
        instances: impl IntoIterator<Item = AuthorityBindingId>,
    ) -> Result<Self, AuthorityError> {
        Self::with_slots(instances, [])
    }

    /// Builds the closure over the supplied bindings and requirement slots.
    ///
    /// `GNT-3-T-AUTHORITY-CLOSURE` requires the closure to contain the declared
    /// requirement of every exact operation site, including the slots attached
    /// to those sites. Each supplied [`SiteRequirementSlotId`] is one such
    /// site-qualified slot. This identity spells the closed tool-slot kinds of
    /// `GNT-25.6-tool-slots-and-tool-set-revisions`; the agent-, model-exposed-,
    /// and operation-slot flavors the clause also names are not representable
    /// here, so a caller holding one of those cannot supply it yet.
    ///
    /// Instances are deduplicated by binding identity and ordered canonically by
    /// that identity; slots are deduplicated by slot identity and ordered
    /// canonically by that identity, so two closures over the same supplied
    /// entries are equal whatever the traversal order. Least-ness stays the
    /// caller's obligation in both directions: this construction never adds a
    /// binding or a slot the caller did not supply.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityError::ClosureExceedsMaximum`] when the supplied
    /// instances exceed [`Self::MAXIMUM_INSTANCES`] or the supplied slots exceed
    /// [`Self::MAXIMUM_SLOTS`].
    pub fn with_slots(
        instances: impl IntoIterator<Item = AuthorityBindingId>,
        slots: impl IntoIterator<Item = SiteRequirementSlotId>,
    ) -> Result<Self, AuthorityError> {
        let mut collected = Vec::new();
        for instance in instances {
            collected.push(instance);
            if collected.len() > Self::MAXIMUM_INSTANCES {
                return Err(AuthorityError::ClosureExceedsMaximum {
                    observed: collected.len(),
                    maximum: Self::MAXIMUM_INSTANCES,
                });
            }
        }
        collected.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        collected.dedup_by(|left, right| left.as_str() == right.as_str());
        let mut collected_slots = Vec::new();
        for slot in slots {
            collected_slots.push(slot);
            if collected_slots.len() > Self::MAXIMUM_SLOTS {
                return Err(AuthorityError::ClosureExceedsMaximum {
                    observed: collected_slots.len(),
                    maximum: Self::MAXIMUM_SLOTS,
                });
            }
        }
        collected_slots.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        collected_slots.dedup_by(|left, right| left.as_str() == right.as_str());
        Ok(Self {
            instances: collected,
            slots: collected_slots,
        })
    }

    /// Returns the closure's bindings in canonical identity order.
    #[must_use]
    pub fn instances(&self) -> &[AuthorityBindingId] {
        &self.instances
    }

    /// Returns the closure's requirement slots in canonical identity order.
    #[must_use]
    pub fn slots(&self) -> &[SiteRequirementSlotId] {
        &self.slots
    }

    /// Returns whether the closure contains one exact requirement slot identity.
    #[must_use]
    pub fn contains_slot(&self, slot: &SiteRequirementSlotId) -> bool {
        self.slots.iter().any(|declared| declared == slot)
    }

    /// Returns whether the closure contains one exact binding identity.
    #[must_use]
    pub fn contains(&self, binding: &AuthorityBindingId) -> bool {
        self.instances.iter().any(|instance| instance == binding)
    }

    /// Returns the number of distinct bindings in the closure.
    #[must_use]
    pub fn len(&self) -> usize {
        self.instances.len()
    }

    /// Returns whether the closure holds no binding.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.instances.is_empty()
    }
}

/// One declared requirement slot of a [`CapabilityAuthorityClosure`]
/// (`GNT-3-T-AUTHORITY-CLOSURE`).
///
/// The identity composes the exact operation site with the kind-qualified tool
/// slot attached to that site, so one slot name at two sites, and two kinds of
/// one slot at one site, are three distinct requirements. Every variable-length
/// part is length-prefixed, so two different slots cannot share one identity, and
/// the structural position is spelled by its ordered numeric components rather
/// than by any source span or physical path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SiteRequirementSlotId {
    site: StaticSiteId,
    slot: ToolSlotId,
    kind: ToolSlotKind,
    text: Arc<str>,
}

impl SiteRequirementSlotId {
    /// Derives one requirement-slot identity from its exact site and slot.
    #[must_use]
    pub fn new(site: StaticSiteId, slot: ToolSlotId, kind: ToolSlotKind) -> Self {
        let position = site
            .position()
            .components()
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join(".");
        let text = format!(
            "site-slot:{}:{}:{}:{}",
            encode_text(site.workflow().as_str()),
            encode_text(&position),
            encode_text(slot.as_str()),
            encode_text(kind.wire_name())
        );
        Self {
            site,
            slot,
            kind,
            text: Arc::from(text),
        }
    }

    /// Returns the exact portable identity spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Returns the exact operation site this slot is attached to.
    #[must_use]
    pub const fn site(&self) -> &StaticSiteId {
        &self.site
    }

    /// Returns the declared tool slot.
    #[must_use]
    pub const fn slot(&self) -> &ToolSlotId {
        &self.slot
    }

    /// Returns the declared slot kind.
    #[must_use]
    pub const fn kind(&self) -> ToolSlotKind {
        self.kind
    }
}

/// One requirement of a [`RequirementResolution`] and the single binding that
/// satisfies it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedRequirement {
    requirement: AuthorityRequirementId,
    binding: AuthorityBindingId,
}

impl ResolvedRequirement {
    /// Returns the declared public capability requirement.
    #[must_use]
    pub const fn requirement(&self) -> &AuthorityRequirementId {
        &self.requirement
    }

    /// Returns the single selected implementation binding of that requirement.
    #[must_use]
    pub const fn binding(&self) -> &AuthorityBindingId {
        &self.binding
    }
}

/// The preflight resolution of one executable authority closure
/// (`GNT-7.2-authority-rebinding`).
///
/// `GNT-7.2-authority-rebinding` requires resume to re-establish every
/// requirement of the executable closure of `GNT-3-T-AUTHORITY-CLOSURE`, to fail
/// resume-start when any requirement cannot be rebound, and not to widen the
/// closure. Resolving the same requirements is what a new execution performs
/// before interpretation begins, so an unsatisfied or ambiguously registered
/// requirement is refused here rather than at first dispatch, whether or not a
/// reachable path is expected to use it.
///
/// Two obligations that clause text also names are not this type's, and a caller
/// must not read this surface as satisfying them: the canonical
/// action-signature resolution and the single opaque action-mapping revision ID
/// of Section 7 item 2 under the anchor `GNT-7.2`, which belong to the agent
/// and action-mapping boundary;
/// and the requirement slots of the closure, whose identities are not
/// requirement identities and are therefore neither resolved nor refused here.
///
/// This type establishes exactly that scope and nothing more. It is not a
/// per-call authorization and confers no dispatch right, which is the explicit
/// rule of `GNT-3-T-AUTHORITY-ADMISSION`. It carries no instance, no rights set,
/// and no lease: a right widening, a generation reset, or a lineage change is an
/// authority-compatibility change under `GNT-11.6-authority-instance-compatibility`
/// and is compared by [`InstanceComparison`] over instances, which resume must
/// not restore. Entries are exactly the caller's declared requirements that the
/// supplied closure satisfies, deduplicated and ordered canonically by
/// requirement identity; a requirement the caller did not declare, and a
/// declaration the closure does not satisfy, never yields an entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequirementResolution {
    entries: Vec<ResolvedRequirement>,
}

impl RequirementResolution {
    /// The largest number of supplied requirements one construction admits.
    ///
    /// The bound is measured over the supplied declarations before
    /// deduplication, so duplicates count toward it, and a larger input is
    /// refused with [`PreflightResolutionError::ExceedsMaximumRequirements`]
    /// instead of being truncated.
    pub const MAXIMUM_REQUIREMENTS: usize = 4096;

    /// Resolves every declared requirement against one executable closure.
    ///
    /// Each declared requirement must be satisfied by exactly one binding in the
    /// closure. A declared requirement the closure does not satisfy is refused
    /// with [`PreflightResolutionError::UnresolvedRequirement`], and two distinct
    /// bindings for one declared requirement are refused with
    /// [`PreflightResolutionError::AmbiguousRequirement`].
    ///
    /// # Errors
    ///
    /// Returns [`PreflightResolutionError::ExceedsMaximumRequirements`] when the
    /// supplied declarations exceed [`Self::MAXIMUM_REQUIREMENTS`], and the two
    /// resolution refusals above for an unsatisfied or ambiguous requirement.
    pub fn resolve(
        closure: &CapabilityAuthorityClosure,
        declared: impl IntoIterator<Item = AuthorityRequirementId>,
    ) -> Result<Self, PreflightResolutionError> {
        let mut candidates = Vec::new();
        for requirement in declared {
            candidates.push(requirement);
            if candidates.len() > Self::MAXIMUM_REQUIREMENTS {
                return Err(PreflightResolutionError::ExceedsMaximumRequirements {
                    observed: candidates.len(),
                    maximum: Self::MAXIMUM_REQUIREMENTS,
                });
            }
        }
        candidates.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        candidates.dedup_by(|left, right| left.as_str() == right.as_str());
        let mut entries = Vec::with_capacity(candidates.len());
        for requirement in candidates {
            let binding = Self::single_binding(closure, &requirement)?;
            entries.push(ResolvedRequirement {
                requirement,
                binding,
            });
        }
        Ok(Self { entries })
    }

    /// Returns the closure's single binding for one requirement, or the refusal.
    fn single_binding(
        closure: &CapabilityAuthorityClosure,
        requirement: &AuthorityRequirementId,
    ) -> Result<AuthorityBindingId, PreflightResolutionError> {
        let mut found: Option<AuthorityBindingId> = None;
        for instance in closure.instances() {
            if instance.requirement() != requirement {
                continue;
            }
            match &found {
                None => found = Some(instance.clone()),
                Some(binding) if binding == instance => {}
                Some(_) => {
                    return Err(PreflightResolutionError::AmbiguousRequirement {
                        requirement: requirement.clone(),
                    });
                }
            }
        }
        found.ok_or_else(|| PreflightResolutionError::UnresolvedRequirement {
            requirement: requirement.clone(),
        })
    }

    /// Re-establishes the same requirement scope through replacement bindings.
    ///
    /// Every resolved requirement must be rebound, so a requirement with no
    /// replacement is refused with
    /// [`PreflightResolutionError::UnresolvedRequirement`]; two distinct
    /// replacement bindings for one requirement are refused with
    /// [`PreflightResolutionError::AmbiguousRequirement`]; and a replacement for
    /// a requirement this resolution does not carry is refused with
    /// [`PreflightResolutionError::RebindingWidensClosure`], so rebinding can
    /// neither widen nor narrow the resolved scope. A replacement outside that
    /// scope is refused as widening before its own registrations are inspected,
    /// so the widening refusal takes precedence over the ambiguity refusal.
    ///
    /// # Errors
    ///
    /// Returns the three refusals above, plus
    /// [`PreflightResolutionError::ExceedsMaximumRequirements`] when the supplied
    /// replacements exceed [`Self::MAXIMUM_REQUIREMENTS`].
    pub fn rebind(
        &self,
        replacements: impl IntoIterator<Item = (AuthorityRequirementId, AuthorityBindingId)>,
    ) -> Result<Self, PreflightResolutionError> {
        let mut supplied: Vec<(AuthorityRequirementId, AuthorityBindingId)> = Vec::new();
        for pair in replacements {
            supplied.push(pair);
            if supplied.len() > Self::MAXIMUM_REQUIREMENTS {
                return Err(PreflightResolutionError::ExceedsMaximumRequirements {
                    observed: supplied.len(),
                    maximum: Self::MAXIMUM_REQUIREMENTS,
                });
            }
        }
        supplied.sort_by(|left, right| left.0.as_str().cmp(right.0.as_str()));
        let mut entries = Vec::new();
        let mut index = 0;
        while index < supplied.len() {
            let requirement = supplied[index].0.clone();
            let Some(resolved) = self.entry_for(&requirement) else {
                return Err(PreflightResolutionError::RebindingWidensClosure { requirement });
            };
            let mut chosen: Option<AuthorityBindingId> = None;
            while index < supplied.len() && supplied[index].0 == requirement {
                let candidate = &supplied[index].1;
                match &chosen {
                    None => chosen = Some(candidate.clone()),
                    Some(binding) if binding == candidate => {}
                    Some(_) => {
                        return Err(PreflightResolutionError::AmbiguousRequirement { requirement });
                    }
                }
                index += 1;
            }
            let Some(binding) = chosen else {
                return Err(PreflightResolutionError::UnresolvedRequirement { requirement });
            };
            entries.push(ResolvedRequirement {
                requirement: resolved.requirement.clone(),
                binding,
            });
        }
        for entry in &self.entries {
            if !entries
                .iter()
                .any(|candidate| candidate.requirement == entry.requirement)
            {
                return Err(PreflightResolutionError::UnresolvedRequirement {
                    requirement: entry.requirement.clone(),
                });
            }
        }
        entries.sort_by(|left, right| left.requirement.as_str().cmp(right.requirement.as_str()));
        Ok(Self { entries })
    }

    /// Returns the resolved requirements in canonical requirement order.
    #[must_use]
    pub fn entries(&self) -> &[ResolvedRequirement] {
        &self.entries
    }

    /// Returns the number of resolved requirements.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether the resolution carries no requirement.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns whether one requirement is resolved in this scope.
    #[must_use]
    pub fn contains(&self, requirement: &AuthorityRequirementId) -> bool {
        self.entry_for(requirement).is_some()
    }

    /// Returns the binding that satisfies one requirement, when it is resolved.
    #[must_use]
    pub fn binding_for(&self, requirement: &AuthorityRequirementId) -> Option<&AuthorityBindingId> {
        self.entry_for(requirement).map(|entry| &entry.binding)
    }

    /// Returns the entry of one requirement, when it is resolved.
    fn entry_for(&self, requirement: &AuthorityRequirementId) -> Option<&ResolvedRequirement> {
        self.entries
            .iter()
            .find(|entry| &entry.requirement == requirement)
    }
}

/// Failure of one preflight requirement resolution (`GNT-7.2-authority-rebinding`).
///
/// This vocabulary is separate from [`AuthorityError`] because a resolution
/// refusal names the requirement it concerns, which that value-typed refusal
/// cannot carry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PreflightResolutionError {
    /// A declared requirement is not satisfied by the closure, or a resolved
    /// requirement has no replacement binding during rebinding.
    UnresolvedRequirement {
        /// The unsatisfied requirement.
        requirement: AuthorityRequirementId,
    },
    /// One requirement carries two distinct binding registrations.
    AmbiguousRequirement {
        /// The ambiguously registered requirement.
        requirement: AuthorityRequirementId,
    },
    /// A replacement names a requirement the resolved scope does not carry.
    RebindingWidensClosure {
        /// The requirement outside the resolved scope.
        requirement: AuthorityRequirementId,
    },
    /// The supplied declarations exceed the resolution's declared bound.
    ExceedsMaximumRequirements {
        /// The number of supplied requirements when the bound was crossed.
        observed: usize,
        /// The declared bound.
        maximum: usize,
    },
}

impl PreflightResolutionError {
    /// Returns the registered diagnostic code of this failure.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::UnresolvedRequirement { .. } => "authority-unresolved-requirement",
            Self::AmbiguousRequirement { .. } => "authority-ambiguous-requirement",
            Self::RebindingWidensClosure { .. } => "authority-rebinding-widens-closure",
            Self::ExceedsMaximumRequirements { .. } => "authority-resolution-exceeds-maximum",
        }
    }
}

impl fmt::Display for PreflightResolutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnresolvedRequirement { requirement }
            | Self::AmbiguousRequirement { requirement }
            | Self::RebindingWidensClosure { requirement } => {
                write!(formatter, "{}: {}", self.code(), requirement.as_str())
            }
            Self::ExceedsMaximumRequirements { observed, maximum } => write!(
                formatter,
                "{}: {observed} supplied requirements exceed the declared maximum of {maximum}",
                self.code()
            ),
        }
    }
}

impl std::error::Error for PreflightResolutionError {}

/// One canonical concrete capability-instance identity.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AuthorityInstanceId(Arc<str>);

impl AuthorityInstanceId {
    /// Derives one instance identity from requirement, binding, generation,
    /// rights, parent edge, and lineage-root material.
    ///
    /// Every part is length-prefixed inside one domain-separated digest, so two
    /// siblings that attenuate one parent to different rights sets, two
    /// descendants of different parents, and two bindings of one requirement all
    /// derive distinct identities while equal inputs stay deterministic.
    fn derive(
        requirement: &AuthorityRequirementId,
        binding: &AuthorityBindingId,
        generation: AuthorityGeneration,
        rights: RightsSet,
        parent: Option<&AuthorityInstanceId>,
        root_material: &str,
    ) -> Self {
        let parent_text = parent.map_or("", |instance| instance.as_str());
        let digest = digest_fields(
            INSTANCE_DOMAIN,
            &[
                requirement.as_str().as_bytes(),
                binding.as_str().as_bytes(),
                &generation.value().to_be_bytes(),
                &[rights.bits()],
                parent_text.as_bytes(),
                root_material.as_bytes(),
            ],
        );
        Self(Arc::from(format!("instance:{}", encode_hex(&digest))))
    }

    /// Returns the exact portable identity spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the lowercase digest text without the instance prefix.
    #[must_use]
    pub fn digest_hex(&self) -> &str {
        self.0.strip_prefix("instance:").unwrap_or(&self.0)
    }
}

/// One monotonically advancing authority generation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AuthorityGeneration(u64);

impl AuthorityGeneration {
    /// The generation of an instance created directly from a binding.
    pub const INITIAL: Self = Self(1);

    /// Constructs one exact generation.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the exact numeric generation.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }

    /// Returns the next generation, or fails closed at the numeric maximum.
    ///
    /// Saturation would let a descendant keep its parent's generation and, with
    /// it, its parent's instance identity, so exhaustion is reported instead.
    pub const fn successor(self) -> Result<Self, AuthorityError> {
        match self.0.checked_add(1) {
            Some(next) => Ok(Self(next)),
            None => Err(AuthorityError::GenerationExhausted),
        }
    }
}

impl fmt::Display for AuthorityGeneration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

/// One lease policy carried by a capability instance.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AuthorityLeasePolicy {
    /// The instance carries no lease and never expires.
    Unleased,
    /// The instance expires at one absolute logical instant.
    Expiring {
        /// Absolute expiry instant in logical microseconds.
        expires_at_us: u64,
    },
}

impl AuthorityLeasePolicy {
    /// Returns whether the policy still permits admission at `now_us`.
    #[must_use]
    pub const fn permits(self, now_us: u64) -> bool {
        match self {
            Self::Unleased => true,
            Self::Expiring { expires_at_us } => now_us < expires_at_us,
        }
    }

    /// Returns the absolute expiry instant when the instance carries a lease.
    #[must_use]
    pub const fn expires_at_us(self) -> Option<u64> {
        match self {
            Self::Unleased => None,
            Self::Expiring { expires_at_us } => Some(expires_at_us),
        }
    }

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Unleased => "unleased",
            Self::Expiring { .. } => "expiring",
        }
    }
}

/// The distinct category of one fencing event.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum FenceCategory {
    /// Authority was revoked.
    Revocation,
    /// Authority reached its lease expiry.
    Expiry,
}

impl FenceCategory {
    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Revocation => "revocation",
            Self::Expiry => "expiry",
        }
    }
}

/// One fenced generation and its single linearization point.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FencePoint {
    category: FenceCategory,
    generation: AuthorityGeneration,
    linearization_point: u64,
}

impl FencePoint {
    /// Returns the distinct fencing category.
    #[must_use]
    pub const fn category(self) -> FenceCategory {
        self.category
    }

    /// Returns the fenced generation.
    #[must_use]
    pub const fn generation(self) -> AuthorityGeneration {
        self.generation
    }

    /// Returns the admission sequence number at which new admission is fenced.
    #[must_use]
    pub const fn linearization_point(self) -> u64 {
        self.linearization_point
    }
}

/// The fencing decision that new admission through one generation observes.
///
/// This is the earliest latch of the generation: revocation and expiry are
/// latched independently and are reported distinctly by [`FenceLatches`], while
/// admission is fenced once, by the first of them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FenceState {
    /// New admission through the generation is still permitted.
    Open,
    /// New admission through the generation is fenced.
    Fenced(FencePoint),
}

impl FenceState {
    /// Returns the fencing point when the generation is fenced.
    #[must_use]
    pub const fn point(self) -> Option<FencePoint> {
        match self {
            Self::Open => None,
            Self::Fenced(point) => Some(point),
        }
    }

    /// Returns whether new admission through the generation is fenced.
    #[must_use]
    pub const fn is_fenced(self) -> bool {
        matches!(self, Self::Fenced(_))
    }
}

/// The independent one-way fencing latches of one instance generation.
///
/// Revocation and expiry are latched separately. Each latch keeps its own
/// linearization point, a repeated latch returns the point it already held, and
/// neither relabels the other, so `revoke()` after `expire()` is still
/// observable as a revocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FenceLatches {
    revocation: Option<FencePoint>,
    expiry: Option<FencePoint>,
}

impl FenceLatches {
    /// Returns the empty latch pair of a generation that is not yet fenced.
    #[must_use]
    pub const fn open() -> Self {
        Self {
            revocation: None,
            expiry: None,
        }
    }

    /// Returns the revocation latch, when authority was revoked.
    #[must_use]
    pub const fn revocation(self) -> Option<FencePoint> {
        self.revocation
    }

    /// Returns the expiry latch, when the lease reached its expiry.
    #[must_use]
    pub const fn expiry(self) -> Option<FencePoint> {
        self.expiry
    }

    /// Returns whether any latch is set.
    #[must_use]
    pub const fn is_fenced(self) -> bool {
        self.revocation.is_some() || self.expiry.is_some()
    }

    /// Returns the latched categories, revocation before expiry.
    #[must_use]
    pub fn categories(self) -> Vec<FenceCategory> {
        let mut categories = Vec::new();
        if self.revocation.is_some() {
            categories.push(FenceCategory::Revocation);
        }
        if self.expiry.is_some() {
            categories.push(FenceCategory::Expiry);
        }
        categories
    }

    /// Returns the fencing decision new admission observes.
    ///
    /// The earliest latch fences admission. When both latches share one
    /// linearization point, revocation is reported, because revocation is the
    /// stronger authority action while the shared point admits nothing either
    /// way.
    #[must_use]
    pub const fn admission_fence(self) -> FenceState {
        match (self.revocation, self.expiry) {
            (None, None) => FenceState::Open,
            (Some(point), None) | (None, Some(point)) => FenceState::Fenced(point),
            (Some(revocation), Some(expiry)) => {
                if expiry.linearization_point() < revocation.linearization_point() {
                    FenceState::Fenced(expiry)
                } else {
                    FenceState::Fenced(revocation)
                }
            }
        }
    }
}

/// One operation admission request against a bound instance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmissionRequest {
    /// The right the declared requirement demands.
    pub right: AuthorityRight,
    /// The recovery class whose settlement rule applies to admitted work.
    pub recovery: RecoveryClass,
    /// The generation the caller believes it holds.
    pub generation: AuthorityGeneration,
    /// The logical instant of the admission.
    pub now_us: u64,
}

/// One admitted operation whose settlement rule is fixed at admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Admission {
    sequence: u64,
    generation: AuthorityGeneration,
    recovery: RecoveryClass,
}

impl Admission {
    /// Returns the logical admission sequence number.
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    /// Returns the generation that admitted the work.
    #[must_use]
    pub const fn generation(self) -> AuthorityGeneration {
        self.generation
    }

    /// Returns the recovery class under which accepted work settles.
    #[must_use]
    pub const fn settlement_rule(self) -> RecoveryClass {
        self.recovery
    }
}

/// One observed outcome of external work that was already admitted.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ExternalOutcome {
    /// The external work completed and its result is committed.
    Accepted,
    /// The external work may or may not have been applied.
    Ambiguous,
    /// The external work was rejected before any effect.
    Rejected,
}

impl Admission {
    /// Returns the settlement of one observed outcome.
    ///
    /// Revocation and expiry never reclassify work that was already admitted:
    /// an ambiguous external outcome stays ambiguous, and an accepted outcome
    /// stays accepted.
    #[must_use]
    pub const fn settles(self, outcome: ExternalOutcome) -> ExternalOutcome {
        outcome
    }
}

/// Pure fencing state machine for one instance generation.
///
/// Revocation and expiry are independent one-way latches: each keeps its own
/// linearization point, neither relabels the other, and both stay observable
/// through [`AuthorityFence::latches`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityFence {
    generation: AuthorityGeneration,
    latches: FenceLatches,
    next_sequence: u64,
    accepted: Vec<Admission>,
}

impl AuthorityFence {
    /// Creates an open fence over one generation.
    #[must_use]
    pub const fn new(generation: AuthorityGeneration) -> Self {
        Self {
            generation,
            latches: FenceLatches::open(),
            next_sequence: 0,
            accepted: Vec::new(),
        }
    }

    /// Returns the fenced generation.
    #[must_use]
    pub const fn generation(&self) -> AuthorityGeneration {
        self.generation
    }

    /// Returns the fencing decision new admission observes.
    ///
    /// This is the earliest latch, so a generation that expired before it was
    /// revoked reports expiry here while [`AuthorityFence::latches`] still
    /// reports both categories distinctly.
    #[must_use]
    pub const fn state(&self) -> FenceState {
        self.latches.admission_fence()
    }

    /// Returns both independent one-way latches of the generation.
    #[must_use]
    pub const fn latches(&self) -> FenceLatches {
        self.latches
    }

    /// Returns the work already admitted, which fencing never alters.
    #[must_use]
    pub fn accepted(&self) -> &[Admission] {
        &self.accepted
    }

    /// Revokes the generation at its own linearization point.
    ///
    /// A repeated revocation returns the original revocation point, and a
    /// revocation after an earlier expiry latches a revocation point of its own,
    /// so the two categories are never relabelled.
    pub fn revoke(&mut self) -> FencePoint {
        self.latch(FenceCategory::Revocation)
    }

    /// Fences the generation by expiry, which is a distinct category.
    pub fn expire(&mut self) -> FencePoint {
        self.latch(FenceCategory::Expiry)
    }

    /// Admits one operation, or fails closed without recording anything.
    ///
    /// A stale generation fails before the fencing check, and a fenced
    /// generation reports the category that fenced it. This primitive checks the
    /// generation and the latches only; the complete admission order of
    /// `GNT-3-T-AUTHORITY-ADMISSION` is applied by [`AuthorityInstance::admit`],
    /// which reaches this method last.
    pub fn admit(&mut self, request: &AdmissionRequest) -> Result<Admission, AuthorityError> {
        if request.generation != self.generation {
            return Err(AuthorityError::StaleGeneration);
        }
        if let FenceState::Fenced(point) = self.state() {
            return Err(AuthorityError::Fenced(point.category));
        }
        let admission = Admission {
            sequence: self.next_sequence,
            generation: self.generation,
            recovery: request.recovery,
        };
        self.next_sequence = self.next_sequence.saturating_add(1);
        self.accepted.push(admission);
        Ok(admission)
    }

    /// Latches one category once and returns the point it holds afterwards.
    fn latch(&mut self, category: FenceCategory) -> FencePoint {
        let latched = match category {
            FenceCategory::Revocation => self.latches.revocation,
            FenceCategory::Expiry => self.latches.expiry,
        };
        if let Some(point) = latched {
            return point;
        }
        let point = FencePoint {
            category,
            generation: self.generation,
            linearization_point: self.next_sequence,
        };
        match category {
            FenceCategory::Revocation => self.latches.revocation = Some(point),
            FenceCategory::Expiry => self.latches.expiry = Some(point),
        }
        point
    }
}

/// The fencing observed for the ancestors of one instance.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AncestorFences {
    fenced: BTreeMap<AuthorityInstanceId, FenceCategory>,
}

impl AncestorFences {
    /// Returns the empty ancestor-fencing view.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    /// Records one fenced ancestor.
    #[must_use]
    pub fn with_fenced(mut self, ancestor: &AuthorityInstanceId, category: FenceCategory) -> Self {
        self.fenced.insert(ancestor.clone(), category);
        self
    }

    /// Returns the category that fences this instance through an ancestor.
    #[must_use]
    pub fn fencing_category(&self, instance: &AuthorityInstance) -> Option<FenceCategory> {
        instance
            .lineage()
            .iter()
            .find_map(|ancestor| self.fenced.get(ancestor).copied())
    }
}

/// One concrete capability instance bound to a requirement.
///
/// The type is intentionally not `Clone`: an instance that is not declared
/// sharable may only be moved under the affine move rule of SPEC.md ownership
/// items 2a-2i, which [`AuthorityInstance::affine_move`] records.
#[derive(Debug, Eq, PartialEq)]
pub struct AuthorityInstance {
    id: AuthorityInstanceId,
    requirement: AuthorityRequirementId,
    binding: AuthorityBindingId,
    rights: RightsSet,
    generation: AuthorityGeneration,
    root: AuthorityInstanceId,
    lineage: Vec<AuthorityInstanceId>,
    lease: AuthorityLeasePolicy,
    sharable: bool,
    fence: AuthorityFence,
}

impl AuthorityInstance {
    /// Binds one requirement to one selected implementation at start or resume.
    ///
    /// This is the only root authority operation, matching
    /// `GNT-3-T-AUTHORITY-INSTANCES`. A binding that does not satisfy the
    /// requirement, or an empty rights set, fails closed.
    pub fn bind(
        requirement: AuthorityRequirementId,
        binding: AuthorityBindingId,
        rights: RightsSet,
        lease: AuthorityLeasePolicy,
        sharable: bool,
    ) -> Result<Self, AuthorityError> {
        if binding.requirement() != &requirement {
            return Err(AuthorityError::RequirementMismatch);
        }
        if rights.is_empty() {
            return Err(AuthorityError::EmptyRights);
        }
        let generation = AuthorityGeneration::INITIAL;
        let id = AuthorityInstanceId::derive(
            &requirement,
            &binding,
            generation,
            rights,
            None,
            binding.as_str(),
        );
        Ok(Self {
            root: id.clone(),
            id,
            requirement,
            binding,
            rights,
            generation,
            lineage: Vec::new(),
            lease,
            sharable,
            fence: AuthorityFence::new(generation),
        })
    }

    /// Returns the canonical instance identity.
    #[must_use]
    pub const fn id(&self) -> &AuthorityInstanceId {
        &self.id
    }

    /// Returns the public capability requirement this instance satisfies.
    #[must_use]
    pub const fn requirement(&self) -> &AuthorityRequirementId {
        &self.requirement
    }

    /// Returns the selected implementation binding of this instance.
    #[must_use]
    pub const fn binding(&self) -> &AuthorityBindingId {
        &self.binding
    }

    /// Returns the rights this instance carries.
    #[must_use]
    pub const fn rights(&self) -> RightsSet {
        self.rights
    }

    /// Returns the instance generation.
    #[must_use]
    pub const fn generation(&self) -> AuthorityGeneration {
        self.generation
    }

    /// Returns the lineage root identity.
    #[must_use]
    pub const fn root(&self) -> &AuthorityInstanceId {
        &self.root
    }

    /// Returns the ancestor identities from the root to the parent.
    #[must_use]
    pub fn lineage(&self) -> &[AuthorityInstanceId] {
        &self.lineage
    }

    /// Returns the single parent identity of a derived instance.
    #[must_use]
    pub fn parent(&self) -> Option<&AuthorityInstanceId> {
        self.lineage.last()
    }

    /// Returns the lease policy this instance carries.
    #[must_use]
    pub const fn lease(&self) -> AuthorityLeasePolicy {
        self.lease
    }

    /// Returns whether this instance is declared sharable.
    #[must_use]
    pub const fn is_sharable(&self) -> bool {
        self.sharable
    }

    /// Returns the fencing state of this instance.
    #[must_use]
    pub const fn fence_state(&self) -> FenceState {
        self.fence.state()
    }

    /// Returns both independent one-way fencing latches of this instance.
    ///
    /// The latches report a revocation and an expiry distinctly, including an
    /// expiry that an earlier admission fence already covers.
    #[must_use]
    pub const fn fence_latches(&self) -> FenceLatches {
        self.fence.latches()
    }

    /// Returns the work already admitted through this instance.
    #[must_use]
    pub fn accepted(&self) -> &[Admission] {
        self.fence.accepted()
    }

    /// Attenuates this instance into a descendant whose rights stay within it.
    pub fn attenuate(
        &self,
        requested: RightsSet,
        lease: AuthorityLeasePolicy,
    ) -> Result<Self, AuthorityError> {
        self.derive_descendant(requested, lease)
    }

    /// Delegates this instance into a descendant under the delegate right.
    ///
    /// Delegation is attenuation gated by [`AuthorityRight::Delegate`], so a
    /// descendant still cannot amplify, add, or restore a right.
    pub fn delegate(
        &self,
        requested: RightsSet,
        lease: AuthorityLeasePolicy,
    ) -> Result<Self, AuthorityError> {
        if !self.rights.contains(AuthorityRight::Delegate) {
            return Err(AuthorityError::MissingRight(AuthorityRight::Delegate));
        }
        self.derive_descendant(requested, lease)
    }

    fn derive_descendant(
        &self,
        requested: RightsSet,
        lease: AuthorityLeasePolicy,
    ) -> Result<Self, AuthorityError> {
        if let FenceState::Fenced(point) = self.fence.state() {
            return Err(AuthorityError::Fenced(point.category()));
        }
        if requested.is_empty() {
            return Err(AuthorityError::EmptyRights);
        }
        if !requested.is_subset_of(self.rights) {
            return Err(AuthorityError::AmplifiedRights);
        }
        if !lease_within(lease, self.lease) {
            return Err(AuthorityError::LeaseExceedsRoot);
        }
        let generation = self.generation.successor()?;
        let id = AuthorityInstanceId::derive(
            &self.requirement,
            &self.binding,
            generation,
            requested,
            Some(&self.id),
            self.root.as_str(),
        );
        let mut lineage = self.lineage.clone();
        lineage.push(self.id.clone());
        Ok(Self {
            id,
            requirement: self.requirement.clone(),
            binding: self.binding.clone(),
            rights: requested,
            generation,
            root: self.root.clone(),
            lineage,
            lease,
            sharable: false,
            fence: AuthorityFence::new(generation),
        })
    }

    /// Rebinds this instance to a replacement binding of the same requirement.
    ///
    /// Rebinding consumes the instance and returns its replacement, so exactly
    /// one live instance remains for the requirement and the rebound instance can
    /// never admit again. The replacement keeps the rights, lineage, and lease of
    /// the instance it replaces, uses the replacement binding, and starts a fresh
    /// generation with a fresh fence, so a presentation of the prior generation is
    /// stale. A revoked or expired generation still fails closed, because no
    /// rebinding may revive one.
    pub fn rebind(self, binding: AuthorityBindingId) -> Result<Self, AuthorityError> {
        if binding.requirement() != &self.requirement {
            return Err(AuthorityError::RequirementMismatch);
        }
        if let FenceState::Fenced(point) = self.fence.state() {
            return Err(AuthorityError::Fenced(point.category()));
        }
        let generation = self.generation.successor()?;
        let parent = self.parent().cloned();
        let id = AuthorityInstanceId::derive(
            &self.requirement,
            &binding,
            generation,
            self.rights,
            parent.as_ref(),
            self.root.as_str(),
        );
        Ok(Self {
            id,
            requirement: self.requirement.clone(),
            binding,
            rights: self.rights,
            generation,
            root: self.root.clone(),
            lineage: self.lineage.clone(),
            lease: self.lease,
            sharable: self.sharable,
            fence: AuthorityFence::new(generation),
        })
    }

    /// Shares this instance with one additional holder.
    ///
    /// Sharing fails closed unless the instance is declared sharable, so a
    /// non-sharable instance reaches a new holder only by affine move.
    pub fn share(&self) -> Result<SharedAuthorityInstance, AuthorityError> {
        if !self.sharable {
            return Err(AuthorityError::NotSharable);
        }
        if let FenceState::Fenced(point) = self.fence.state() {
            return Err(AuthorityError::Fenced(point.category()));
        }
        Ok(SharedAuthorityInstance(self.id.clone()))
    }

    /// Moves this instance to one new owner under the affine move rule.
    #[must_use]
    pub fn affine_move(self) -> Self {
        self
    }

    /// Admits one operation after revalidating authority in one fixed order.
    ///
    /// The checks run in this order, and only the last one commits anything:
    ///
    /// 1. the presented generation, which fails closed without mutating any
    ///    state, so a stale request never latches an expiry;
    /// 2. the existing fences, this generation's own latches before any ancestor
    ///    fence;
    /// 3. the lease expiry, which latches expiry when the lease no longer permits
    ///    the admission;
    /// 4. the declared right, which must be exactly the right the declared
    ///    recovery class requires and a member of this instance's rights set;
    /// 5. the admission itself, the single commit point before dispatch: a
    ///    failure records nothing, returns a registered diagnostic code, and
    ///    leaves every previously accepted admission untouched.
    pub fn admit(
        &mut self,
        request: &AdmissionRequest,
        ancestors: &AncestorFences,
    ) -> Result<Admission, AuthorityError> {
        if request.generation != self.generation {
            return Err(AuthorityError::StaleGeneration);
        }
        if let FenceState::Fenced(point) = self.fence.state() {
            return Err(AuthorityError::Fenced(point.category()));
        }
        if let Some(category) = ancestors.fencing_category(self) {
            return Err(AuthorityError::AncestorFenced(category));
        }
        if !self.lease.permits(request.now_us) {
            self.fence.expire();
            return Err(AuthorityError::Fenced(FenceCategory::Expiry));
        }
        let required = AuthorityRight::for_recovery_class(request.recovery);
        if request.right != required {
            return Err(AuthorityError::RightRecoveryMismatch {
                declared: request.right,
                required,
            });
        }
        if !self.rights.contains(required) {
            return Err(AuthorityError::MissingRight(required));
        }
        self.fence.admit(request)
    }

    /// Revokes this instance at its single linearization point.
    pub fn revoke(&mut self) -> FencePoint {
        self.fence.revoke()
    }

    /// Fences this instance by expiry, a distinct category from revocation.
    pub fn expire(&mut self) -> FencePoint {
        self.fence.expire()
    }

    /// Returns one renderable lineage record built only from canonical ids.
    ///
    /// The record carries no protected payload, no authorization decision, and
    /// no admitted content, so lineage audit can render it directly.
    #[must_use]
    pub fn lineage_record(&self) -> LineageRecord {
        LineageRecord {
            instance: self.id.clone(),
            parent: self.parent().cloned(),
            root: self.root.clone(),
            generation: self.generation,
            rights: self.rights,
            lease: self.lease,
        }
    }

    /// Compares this instance with a candidate instance of the same requirement.
    ///
    /// A comparison is defined only between instances of one capability
    /// requirement, so instances of different requirements are rejected instead
    /// of being reported as an incomparable pair.
    pub fn compare(&self, candidate: &Self) -> Result<InstanceComparison, AuthorityError> {
        if self.requirement != candidate.requirement {
            return Err(AuthorityError::IncomparableRequirements);
        }
        Ok(InstanceComparison {
            rights: RightsRelation::of(self.rights, candidate.rights),
            lineage: if self.root == candidate.root {
                LineageRelation::SameRoot
            } else {
                LineageRelation::Replanted
            },
            generation: match candidate.generation.value().cmp(&self.generation.value()) {
                std::cmp::Ordering::Equal => GenerationRelation::SameGeneration,
                std::cmp::Ordering::Greater => GenerationRelation::Advanced,
                std::cmp::Ordering::Less => GenerationRelation::Reset,
            },
            lease: LeaseRelation::of(self.lease, candidate.lease),
        })
    }
}

/// One additional holder of a sharable capability instance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SharedAuthorityInstance(AuthorityInstanceId);

impl SharedAuthorityInstance {
    /// Returns the shared instance identity.
    #[must_use]
    pub const fn id(&self) -> &AuthorityInstanceId {
        &self.0
    }
}

/// One renderable lineage record of a capability instance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LineageRecord {
    instance: AuthorityInstanceId,
    parent: Option<AuthorityInstanceId>,
    root: AuthorityInstanceId,
    generation: AuthorityGeneration,
    rights: RightsSet,
    lease: AuthorityLeasePolicy,
}

impl LineageRecord {
    /// Returns the instance identity.
    #[must_use]
    pub const fn instance(&self) -> &AuthorityInstanceId {
        &self.instance
    }

    /// Returns the single parent identity, when the instance is derived.
    #[must_use]
    pub fn parent(&self) -> Option<&AuthorityInstanceId> {
        self.parent.as_ref()
    }

    /// Returns the lineage root identity.
    #[must_use]
    pub const fn root(&self) -> &AuthorityInstanceId {
        &self.root
    }

    /// Returns the instance generation.
    #[must_use]
    pub const fn generation(&self) -> AuthorityGeneration {
        self.generation
    }

    /// Returns the rights the instance carries.
    #[must_use]
    pub const fn rights(&self) -> RightsSet {
        self.rights
    }

    /// Returns the lease policy the instance carries.
    #[must_use]
    pub const fn lease(&self) -> AuthorityLeasePolicy {
        self.lease
    }

    /// Renders the record from canonical identities and rights spellings.
    #[must_use]
    pub fn render(&self) -> String {
        format!(
            "instance={};parent={};root={};generation={};rights={};lease={}",
            self.instance.as_str(),
            self.parent
                .as_ref()
                .map_or("none", AuthorityInstanceId::as_str),
            self.root.as_str(),
            self.generation.value(),
            self.rights.wire_names().join(","),
            self.lease.wire_name()
        )
    }
}

/// How the rights of two instances relate.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RightsRelation {
    /// Both instances carry the same rights set.
    Equal,
    /// The candidate carries strictly fewer rights.
    Narrowed,
    /// The candidate carries strictly more rights.
    Widened,
    /// Neither rights set contains the other.
    Incomparable,
}

impl RightsRelation {
    /// Compares a previous rights set with a candidate rights set.
    #[must_use]
    pub const fn of(previous: RightsSet, candidate: RightsSet) -> Self {
        if previous.is_subset_of(candidate) && candidate.is_subset_of(previous) {
            Self::Equal
        } else if candidate.is_subset_of(previous) {
            Self::Narrowed
        } else if previous.is_subset_of(candidate) {
            Self::Widened
        } else {
            Self::Incomparable
        }
    }
}

/// How the lineage roots of two instances relate.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum LineageRelation {
    /// Both instances descend from the same lineage root.
    SameRoot,
    /// The candidate descends from a different lineage root.
    Replanted,
}

/// How the generations of two instances relate.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum GenerationRelation {
    /// The candidate carries the same generation.
    SameGeneration,
    /// The candidate carries a later generation.
    Advanced,
    /// The candidate carries an earlier generation, which is a reset.
    Reset,
}

/// How the lease policies of two instances relate.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum LeaseRelation {
    /// Both instances carry the same lease policy.
    Equal,
    /// The candidate expires earlier.
    Shortened,
    /// The candidate expires later.
    Lengthened,
    /// The previous instance carried no lease and the candidate does.
    NewlyLeased,
    /// The previous instance carried a lease and the candidate does not.
    NewlyUnleased,
}

impl LeaseRelation {
    /// Compares a previous lease policy with a candidate lease policy.
    #[must_use]
    pub const fn of(previous: AuthorityLeasePolicy, candidate: AuthorityLeasePolicy) -> Self {
        match (previous.expires_at_us(), candidate.expires_at_us()) {
            (None, None) => Self::Equal,
            (None, Some(_)) => Self::NewlyLeased,
            (Some(_), None) => Self::NewlyUnleased,
            (Some(previous), Some(candidate)) if candidate == previous => Self::Equal,
            (Some(previous), Some(candidate)) if candidate < previous => Self::Shortened,
            (Some(_), Some(_)) => Self::Lengthened,
        }
    }
}

/// One distinct authority change that a comparison proves.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AuthorityChangeClass {
    /// The candidate can reach rights the previous instance could not.
    RightsWidening,
    /// The candidate restarts the generation counter.
    GenerationReset,
    /// The candidate descends from another lineage root.
    LineageReplanting,
    /// The candidate carries a different lease policy: a longer, shorter, newly
    /// leased, or newly unleased policy.
    LeasePolicyChange,
}

impl AuthorityChangeClass {
    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::RightsWidening => "rights-widening",
            Self::GenerationReset => "generation-reset",
            Self::LineageReplanting => "lineage-replanting",
            Self::LeasePolicyChange => "lease-policy-change",
        }
    }
}

/// Four independently reported relations between two authority instances.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InstanceComparison {
    /// How the compared rights sets relate.
    pub rights: RightsRelation,
    /// How the compared lineage roots relate.
    pub lineage: LineageRelation,
    /// How the compared generation states relate.
    pub generation: GenerationRelation,
    /// How the compared lease policies relate.
    pub lease: LeaseRelation,
}

impl InstanceComparison {
    /// Reports the authority-compatibility changes this comparison proves.
    #[must_use]
    pub fn authority_compatibility_changes(&self) -> BTreeSet<AuthorityChangeClass> {
        let mut changes = BTreeSet::new();
        if self.rights == RightsRelation::Widened {
            changes.insert(AuthorityChangeClass::RightsWidening);
        }
        if self.generation == GenerationRelation::Reset {
            changes.insert(AuthorityChangeClass::GenerationReset);
        }
        if self.lineage == LineageRelation::Replanted {
            changes.insert(AuthorityChangeClass::LineageReplanting);
        }
        if self.lease != LeaseRelation::Equal {
            changes.insert(AuthorityChangeClass::LeasePolicyChange);
        }
        changes
    }

    /// Returns whether the comparison is a plain rebinding without any
    /// authority-compatibility change, including a lease-policy change.
    #[must_use]
    pub fn is_rebinding_only(&self) -> bool {
        self.authority_compatibility_changes().is_empty()
    }

    /// Returns whether every reported property is unchanged.
    #[must_use]
    pub fn is_unchanged(&self) -> bool {
        self.rights == RightsRelation::Equal
            && self.lineage == LineageRelation::SameRoot
            && self.generation == GenerationRelation::SameGeneration
            && self.lease == LeaseRelation::Equal
    }
}

/// Failure of one authority-model operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityError {
    /// The capability family is empty or is not a portable lowercase name.
    InvalidCapabilityFamily,
    /// The requested rights set is empty, which admits no operation.
    EmptyRights,
    /// The binding does not satisfy the requirement it was paired with.
    RequirementMismatch,
    /// The requested rights would amplify the parent's rights.
    AmplifiedRights,
    /// The instance does not carry the right the operation requires.
    MissingRight(AuthorityRight),
    /// The declared right is not the right the declared recovery class requires.
    RightRecoveryMismatch {
        /// The right the request declared.
        declared: AuthorityRight,
        /// The right the declared recovery class requires.
        required: AuthorityRight,
    },
    /// The instance is not declared sharable.
    NotSharable,
    /// The requested lease would extend beyond the root's lease.
    LeaseExceedsRoot,
    /// The presented generation is not the instance's current generation.
    StaleGeneration,
    /// The generation counter is exhausted, so no descendant can be derived.
    GenerationExhausted,
    /// The generation is fenced by revocation or expiry.
    Fenced(FenceCategory),
    /// An ancestor of the instance is fenced.
    AncestorFenced(FenceCategory),
    /// The compared instances do not satisfy the same capability requirement.
    IncomparableRequirements,
    /// The supplied closure input exceeds [`CapabilityAuthorityClosure::MAXIMUM_INSTANCES`].
    ClosureExceedsMaximum {
        /// The number of supplied instances when the bound was crossed.
        observed: usize,
        /// The declared bound.
        maximum: usize,
    },
}

impl AuthorityError {
    /// Returns the registered diagnostic code of this failure.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidCapabilityFamily => "authority-invalid-capability-family",
            Self::EmptyRights => "authority-empty-rights",
            Self::RequirementMismatch => "authority-requirement-mismatch",
            Self::AmplifiedRights => "authority-amplified-rights",
            Self::MissingRight(_) => "authority-missing-right",
            Self::RightRecoveryMismatch { .. } => "authority-right-recovery-mismatch",
            Self::NotSharable => "authority-not-sharable",
            Self::LeaseExceedsRoot => "authority-lease-exceeds-root",
            Self::StaleGeneration => "authority-stale-generation",
            Self::GenerationExhausted => "authority-generation-exhausted",
            Self::Fenced(_) => "authority-fenced",
            Self::AncestorFenced(_) => "authority-ancestor-fenced",
            Self::IncomparableRequirements => "authority-incomparable-requirements",
            Self::ClosureExceedsMaximum { .. } => "authority-closure-exceeds-maximum",
        }
    }
}

impl fmt::Display for AuthorityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingRight(right) => {
                write!(formatter, "{}: {}", self.code(), right.wire_name())
            }
            Self::RightRecoveryMismatch { declared, required } => write!(
                formatter,
                "{}: declared {} requires {}",
                self.code(),
                declared.wire_name(),
                required.wire_name()
            ),
            Self::Fenced(category) | Self::AncestorFenced(category) => {
                write!(formatter, "{}: {}", self.code(), category.wire_name())
            }
            Self::ClosureExceedsMaximum { observed, maximum } => write!(
                formatter,
                "{}: {observed} supplied instances exceed the declared maximum of {maximum}",
                self.code()
            ),
            _ => formatter.write_str(self.code()),
        }
    }
}

impl std::error::Error for AuthorityError {}

/// Validates one portable capability-family name.
fn validate_capability_family(value: &str) -> Result<(), AuthorityError> {
    if value.is_empty()
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_'
        })
    {
        return Err(AuthorityError::InvalidCapabilityFamily);
    }
    Ok(())
}

/// Encodes one length-prefixed canonical text field.
fn encode_text(value: &str) -> String {
    format!("{}:{value}", value.len())
}

/// Returns whether one child lease stays within one parent lease.
fn lease_within(child: AuthorityLeasePolicy, parent: AuthorityLeasePolicy) -> bool {
    match (parent.expires_at_us(), child.expires_at_us()) {
        (None, None) => true,
        (None, Some(_)) | (Some(_), None) => false,
        (Some(parent), Some(child)) => child <= parent,
    }
}

/// Returns the domain-separated digest of length-prefixed canonical fields.
///
/// The helper is crate-visible so that every canonical identity layer of this
/// crate derives its digest under the same length-prefixed, domain-separated
/// encoding.
pub(crate) fn digest_fields(domain: &str, fields: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update([0_u8]);
    for field in fields {
        let length = u64::try_from(field.len()).unwrap_or(u64::MAX);
        hasher.update(length.to_be_bytes());
        hasher.update(field);
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::{
        AUTHORITY_RIGHT_ORDER, AdmissionRequest, AuthorityBindingId, AuthorityError,
        AuthorityFence, AuthorityGeneration, AuthorityRequirementId, AuthorityRight,
        CapabilityAuthorityClosure, FenceCategory, FenceState, PreflightResolutionError,
        RequirementResolution, RightsSet, SiteRequirementSlotId,
    };
    use crate::generated::RecoveryClass;
    use crate::{
        CanonicalImplementationIdentity, CanonicalPath, CanonicalSignature, TypeDescriptor,
        TypeExpression,
    };

    #[test]
    fn rights_sets_iterate_in_reporting_order_encode_membership_and_compare_by_subset() {
        let mut set = RightsSet::empty();
        assert!(set.insert(AuthorityRight::Delegate));
        assert!(set.insert(AuthorityRight::Observe));
        assert!(!set.insert(AuthorityRight::Observe));
        assert_eq!(
            set.wire_names(),
            ["observe", "delegate"],
            "canonical order, not insertion order"
        );
        let narrowed = RightsSet::from_rights(&[AuthorityRight::Observe]);
        assert!(narrowed.is_strict_subset_of(set));
        assert!(!set.is_subset_of(narrowed));
        assert_eq!(AUTHORITY_RIGHT_ORDER.len(), 5);
        assert_eq!(
            AuthorityRight::from_wire_name("invoke-non-idempotent"),
            Some(AuthorityRight::InvokeNonIdempotent)
        );
        assert_eq!(AuthorityRight::from_wire_name("invoke-unknown"), None);
        assert_eq!(
            RightsSet::from_rights(&[AuthorityRight::Observe, AuthorityRight::Delegate]),
            RightsSet::from_rights(&[AuthorityRight::Delegate, AuthorityRight::Observe]),
            "membership is a set, not an insertion history"
        );
        assert_eq!(
            RightsSet::from_rights(&[AuthorityRight::Observe, AuthorityRight::Delegate]).bits(),
            RightsSet::from_rights(&[AuthorityRight::Observe]).bits()
                | RightsSet::from_rights(&[AuthorityRight::Delegate]).bits(),
            "membership bits compose by right, so identity derivation is order-free"
        );
    }

    /// Revocation and expiry are latched separately, so neither relabels the
    /// other and both stay observable at the same time.
    #[test]
    fn fence_latches_revocation_and_expiry_independently() {
        let generation = AuthorityGeneration::INITIAL;
        let mut fence = AuthorityFence::new(generation);
        let request = AdmissionRequest {
            right: AuthorityRight::InvokeReadOnly,
            recovery: RecoveryClass::ReadOnly,
            generation,
            now_us: 0,
        };
        assert!(fence.admit(&request).is_ok());
        let accepted = fence.accepted().to_vec();
        let revoke = fence.revoke();
        assert_eq!(revoke.category(), FenceCategory::Revocation);
        assert_eq!(revoke.linearization_point(), 1);
        assert_eq!(
            fence.revoke(),
            revoke,
            "one revocation linearization point per instance"
        );
        let expire = fence.expire();
        assert_eq!(expire.category(), FenceCategory::Expiry);
        assert_eq!(
            fence.latches().categories(),
            [FenceCategory::Revocation, FenceCategory::Expiry],
            "both latches stay observable"
        );
        assert_eq!(fence.latches().revocation(), Some(revoke));
        assert_eq!(fence.latches().expiry(), Some(expire));
        assert!(matches!(fence.state(), FenceState::Fenced(point) if point == revoke));
        assert_eq!(fence.accepted(), accepted, "accepted work is unaffected");
        assert!(matches!(
            fence.admit(&request),
            Err(AuthorityError::Fenced(FenceCategory::Revocation))
        ));
        let mut stale = AuthorityFence::new(AuthorityGeneration::new(2));
        assert!(matches!(
            stale.admit(&request),
            Err(AuthorityError::StaleGeneration)
        ));
    }

    /// A generation never saturates into the identity of its own predecessor.
    #[test]
    fn generation_successor_fails_closed_at_the_numeric_maximum() {
        assert_eq!(
            AuthorityGeneration::new(41).successor(),
            Ok(AuthorityGeneration::new(42))
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

    /// Returns the canonical workflow path of one declared fixture item.
    fn fixture_path(name: &str) -> CanonicalPath {
        match CanonicalPath::new(&format!("crate::authority::{name}")) {
            Ok(path) => path,
            Err(error) => panic!("the fixture path {name} is canonical: {error:?}"),
        }
    }

    #[test]
    fn requirement_resolution_resolves_each_declared_requirement_and_never_widens_it() {
        let declared = fixture_requirement("resolution_declared");
        let resolved_binding = fixture_binding(&declared, &TypeDescriptor::INT);
        let undeclared = fixture_requirement("resolution_undeclared");
        let undeclared_binding = fixture_binding(&undeclared, &TypeDescriptor::STRING);
        let closure =
            CapabilityAuthorityClosure::new([resolved_binding.clone(), undeclared_binding])
                .unwrap_or_else(|error| {
                    panic!("the declared closure is within the bound: {error}")
                });
        let resolution = RequirementResolution::resolve(&closure, [declared.clone()])
            .unwrap_or_else(|error| panic!("the declared requirement is satisfied: {error}"));
        assert_eq!(resolution.len(), 1);
        assert!(!resolution.is_empty());
        assert!(resolution.contains(&declared));
        assert_eq!(resolution.binding_for(&declared), Some(&resolved_binding));
        assert!(
            !resolution.contains(&undeclared),
            "a requirement the caller did not declare never enters the resolution"
        );
        let unsatisfied = fixture_requirement("resolution_unsatisfied");
        let error = RequirementResolution::resolve(&closure, [unsatisfied.clone()])
            .err()
            .unwrap_or_else(|| panic!("an unsatisfied declaration is refused"));
        assert!(matches!(
            &error,
            PreflightResolutionError::UnresolvedRequirement { requirement }
                if requirement == &unsatisfied
        ));
        assert_eq!(error.code(), "authority-unresolved-requirement");
        assert!(error.to_string().contains(unsatisfied.as_str()));
    }

    #[test]
    fn requirement_resolution_refuses_conflicting_registrations() {
        let declared = fixture_requirement("resolution_conflict");
        let closure = CapabilityAuthorityClosure::new([
            fixture_binding(&declared, &TypeDescriptor::INT),
            fixture_binding(&declared, &TypeDescriptor::STRING),
        ])
        .unwrap_or_else(|error| panic!("the declared closure is within the bound: {error}"));
        let error = RequirementResolution::resolve(&closure, [declared.clone()])
            .err()
            .unwrap_or_else(|| panic!("two distinct bindings are refused"));
        assert!(matches!(
            &error,
            PreflightResolutionError::AmbiguousRequirement { requirement }
                if requirement == &declared
        ));
        assert_eq!(error.code(), "authority-ambiguous-requirement");
        let single = fixture_binding(&declared, &TypeDescriptor::INT);
        let repeated = CapabilityAuthorityClosure::new([single.clone(), single])
            .unwrap_or_else(|error| panic!("the declared closure is within the bound: {error}"));
        let resolution = RequirementResolution::resolve(&repeated, [declared.clone(), declared])
            .unwrap_or_else(|error| panic!("one distinct binding is not a conflict: {error}"));
        assert_eq!(resolution.len(), 1);
    }

    #[test]
    fn requirement_resolution_rebinds_without_widening_or_narrowing() {
        let first_requirement = fixture_requirement("rebind_first");
        let second_requirement = fixture_requirement("rebind_second");
        let closure = CapabilityAuthorityClosure::new([
            fixture_binding(&first_requirement, &TypeDescriptor::INT),
            fixture_binding(&second_requirement, &TypeDescriptor::STRING),
        ])
        .unwrap_or_else(|error| panic!("the declared closure is within the bound: {error}"));
        let resolution = RequirementResolution::resolve(
            &closure,
            [first_requirement.clone(), second_requirement.clone()],
        )
        .unwrap_or_else(|error| panic!("both requirements are satisfied: {error}"));
        let replacement_first = fixture_binding(&first_requirement, &TypeDescriptor::STRING);
        let replacement_second = fixture_binding(&second_requirement, &TypeDescriptor::INT);
        let rebound = resolution
            .rebind([
                (second_requirement.clone(), replacement_second.clone()),
                (first_requirement.clone(), replacement_first.clone()),
                (first_requirement.clone(), replacement_first.clone()),
            ])
            .unwrap_or_else(|error| panic!("every requirement is rebound: {error}"));
        assert_eq!(rebound.len(), 2, "duplicate replacements collapse");
        assert_eq!(
            rebound.binding_for(&first_requirement),
            Some(&replacement_first)
        );
        assert_eq!(
            rebound.binding_for(&second_requirement),
            Some(&replacement_second)
        );
        let error = resolution
            .rebind([(first_requirement.clone(), replacement_first.clone())])
            .err()
            .unwrap_or_else(|| panic!("a missing replacement fails resume-start"));
        assert!(matches!(
            &error,
            PreflightResolutionError::UnresolvedRequirement { requirement }
                if requirement == &second_requirement
        ));
        let outside = fixture_requirement("rebind_outside");
        let error = resolution
            .rebind([
                (first_requirement.clone(), replacement_first.clone()),
                (second_requirement.clone(), replacement_second),
                (
                    outside.clone(),
                    fixture_binding(&outside, &TypeDescriptor::INT),
                ),
            ])
            .err()
            .unwrap_or_else(|| panic!("a replacement outside the scope is refused"));
        assert!(matches!(
            &error,
            PreflightResolutionError::RebindingWidensClosure { requirement }
                if requirement == &outside
        ));
        assert_eq!(error.code(), "authority-rebinding-widens-closure");
        assert_eq!(
            error.to_string(),
            format!("authority-rebinding-widens-closure: {}", outside.as_str())
        );
        let error = resolution
            .rebind([
                (first_requirement.clone(), replacement_first.clone()),
                (
                    second_requirement.clone(),
                    fixture_binding(&second_requirement, &TypeDescriptor::INT),
                ),
                (
                    outside.clone(),
                    fixture_binding(&outside, &TypeDescriptor::INT),
                ),
                (
                    outside.clone(),
                    fixture_binding(&outside, &TypeDescriptor::STRING),
                ),
            ])
            .err()
            .unwrap_or_else(|| panic!("an out-of-scope requirement is refused as widening"));
        assert!(
            matches!(
                &error,
                PreflightResolutionError::RebindingWidensClosure { requirement }
                    if requirement == &outside
            ),
            "the widening refusal precedes the ambiguity refusal for a requirement outside the scope"
        );
    }

    #[test]
    fn requirement_resolution_bound_is_pre_dedup_and_refuses_one_more() {
        let declared = fixture_requirement("resolution_bound");
        let closure =
            CapabilityAuthorityClosure::new([fixture_binding(&declared, &TypeDescriptor::INT)])
                .unwrap_or_else(|error| {
                    panic!("the declared closure is within the bound: {error}")
                });
        let at_bound = RequirementResolution::resolve(
            &closure,
            vec![declared.clone(); RequirementResolution::MAXIMUM_REQUIREMENTS],
        )
        .unwrap_or_else(|error| panic!("the declared bound is inclusive: {error}"));
        assert_eq!(
            at_bound.len(),
            1,
            "duplicate declarations collapse after the bound check"
        );
        let oversized = vec![declared; RequirementResolution::MAXIMUM_REQUIREMENTS + 1];
        let error = RequirementResolution::resolve(&closure, oversized)
            .err()
            .unwrap_or_else(|| panic!("one declaration past the bound is refused"));
        assert!(matches!(
            &error,
            PreflightResolutionError::ExceedsMaximumRequirements { observed, maximum }
                if *maximum == RequirementResolution::MAXIMUM_REQUIREMENTS
                    && *observed == RequirementResolution::MAXIMUM_REQUIREMENTS + 1
        ));
        assert_eq!(error.code(), "authority-resolution-exceeds-maximum");
        assert_eq!(
            error.to_string(),
            format!(
                "authority-resolution-exceeds-maximum: {} supplied requirements exceed the declared maximum of {}",
                RequirementResolution::MAXIMUM_REQUIREMENTS + 1,
                RequirementResolution::MAXIMUM_REQUIREMENTS
            )
        );
    }

    /// Returns one public capability requirement of one declared fixture path.
    fn fixture_requirement(name: &str) -> AuthorityRequirementId {
        let path = fixture_path(name);
        let signature = CanonicalSignature::function(&path, &[], &TypeDescriptor::INT);
        match AuthorityRequirementId::new(&path, &signature, "fixture", RecoveryClass::Idempotent) {
            Ok(requirement) => requirement,
            Err(error) => panic!("the fixture requirement {name} is valid: {error:?}"),
        }
    }

    /// Returns one inherent implementation identity over the declared receiver.
    fn fixture_implementation(descriptor: &TypeDescriptor) -> CanonicalImplementationIdentity {
        match TypeExpression::closed(descriptor, 8) {
            Ok(receiver) => CanonicalImplementationIdentity::inherent(&receiver),
            Err(error) => panic!("the fixture receiver is within depth 8: {error:?}"),
        }
    }

    /// Returns one binding of the declared requirement and receiver.
    fn fixture_binding(
        requirement: &AuthorityRequirementId,
        descriptor: &TypeDescriptor,
    ) -> AuthorityBindingId {
        AuthorityBindingId::new(requirement, &fixture_implementation(descriptor))
    }

    /// The closure is equal under any supplied order and orders by identity.
    #[test]
    fn capability_authority_closure_orders_bindings_canonically() {
        let first = fixture_requirement("order_first");
        let second = fixture_requirement("order_second");
        let alpha = fixture_binding(&first, &TypeDescriptor::INT);
        let beta = fixture_binding(&first, &TypeDescriptor::STRING);
        let gamma = fixture_binding(&second, &TypeDescriptor::INT);
        let forward = CapabilityAuthorityClosure::new([alpha.clone(), beta.clone(), gamma.clone()])
            .unwrap_or_else(|error| panic!("the declared closure is within the bound: {error}"));
        let reversed =
            CapabilityAuthorityClosure::new([gamma.clone(), beta.clone(), alpha.clone()])
                .unwrap_or_else(|error| {
                    panic!("the declared closure is within the bound: {error}")
                });
        assert_eq!(
            forward, reversed,
            "the closure is a set keyed by binding identity, not an input order"
        );
        assert_eq!(forward.len(), 3);
        assert!(!forward.is_empty());
        assert!(
            forward
                .instances()
                .windows(2)
                .all(|pair| pair[0].as_str() < pair[1].as_str()),
            "instances are ordered by their canonical identity spelling"
        );
        let mut expected: Vec<&str> = vec![alpha.as_str(), beta.as_str(), gamma.as_str()];
        expected.sort_unstable();
        assert_eq!(
            forward
                .instances()
                .iter()
                .map(AuthorityBindingId::as_str)
                .collect::<Vec<&str>>(),
            expected
        );
    }

    /// Binding identity covers requirement and implementation; duplicates collapse.
    #[test]
    fn capability_authority_closure_deduplicates_by_binding_identity() {
        let first = fixture_requirement("dedup_first");
        let second = fixture_requirement("dedup_second");
        let int = fixture_binding(&first, &TypeDescriptor::INT);
        let duplicate = fixture_binding(&first, &TypeDescriptor::INT);
        let other_implementation = fixture_binding(&first, &TypeDescriptor::STRING);
        let other_requirement = fixture_binding(&second, &TypeDescriptor::INT);
        assert_eq!(
            int, duplicate,
            "one requirement and one implementation derive one identity"
        );
        assert_ne!(
            int, other_implementation,
            "the selected implementation is part of the binding identity"
        );
        assert_ne!(
            int, other_requirement,
            "the capability requirement is part of the binding identity"
        );
        let closure = CapabilityAuthorityClosure::new([
            int.clone(),
            duplicate,
            other_implementation.clone(),
            other_requirement.clone(),
            int.clone(),
        ])
        .unwrap_or_else(|error| panic!("the declared closure is within the bound: {error}"));
        assert_eq!(closure.len(), 3, "duplicates collapse to one instance each");
        assert_eq!(
            closure
                .instances()
                .iter()
                .filter(|instance| *instance == &int)
                .count(),
            1
        );
        assert!(closure.contains(&int));
        assert!(closure.contains(&other_implementation));
        assert!(closure.contains(&other_requirement));
        assert!(!closure.contains(&fixture_binding(&second, &TypeDescriptor::STRING)));
    }

    /// The declared bound is positive, inclusive, and refuses one more instance.
    #[test]
    fn capability_authority_closure_bound_is_inclusive_and_refuses_one_more() {
        const {
            assert!(
                CapabilityAuthorityClosure::MAXIMUM_INSTANCES > 0,
                "the declared bound is positive"
            );
        }
        let at_bound = (0..CapabilityAuthorityClosure::MAXIMUM_INSTANCES)
            .map(|index| {
                fixture_binding(
                    &fixture_requirement(&format!("bound_{index}")),
                    &TypeDescriptor::INT,
                )
            })
            .collect::<Vec<AuthorityBindingId>>();
        let closure = CapabilityAuthorityClosure::new(at_bound)
            .unwrap_or_else(|error| panic!("exactly the declared maximum is admitted: {error}"));
        assert_eq!(closure.len(), CapabilityAuthorityClosure::MAXIMUM_INSTANCES);
        let over = (0..=CapabilityAuthorityClosure::MAXIMUM_INSTANCES)
            .map(|index| {
                fixture_binding(
                    &fixture_requirement(&format!("bound_{index}")),
                    &TypeDescriptor::INT,
                )
            })
            .collect::<Vec<AuthorityBindingId>>();
        assert_eq!(
            CapabilityAuthorityClosure::new(over),
            Err(AuthorityError::ClosureExceedsMaximum {
                observed: CapabilityAuthorityClosure::MAXIMUM_INSTANCES + 1,
                maximum: CapabilityAuthorityClosure::MAXIMUM_INSTANCES,
            })
        );
        assert_eq!(
            AuthorityError::ClosureExceedsMaximum {
                observed: 2,
                maximum: 1,
            }
            .code(),
            "authority-closure-exceeds-maximum"
        );
    }

    /// Only supplied reachable bindings enter the closure.
    #[test]
    fn capability_authority_closure_holds_only_supplied_reachable_bindings() {
        let reachable = fixture_binding(&fixture_requirement("reachable"), &TypeDescriptor::INT);
        let unreachable =
            fixture_binding(&fixture_requirement("unreachable"), &TypeDescriptor::INT);
        let closure = CapabilityAuthorityClosure::new([reachable.clone()])
            .unwrap_or_else(|error| panic!("the declared closure is within the bound: {error}"));
        assert_eq!(closure.instances(), std::slice::from_ref(&reachable));
        assert_eq!(closure.len(), 1);
        assert!(closure.contains(&reachable));
        assert!(
            !closure.contains(&unreachable),
            "a declaration the caller did not prove reachable never enters the closure"
        );
        let empty = CapabilityAuthorityClosure::new(Vec::new())
            .unwrap_or_else(|error| panic!("the empty closure is within the bound: {error}"));
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);
        assert!(empty.instances().is_empty());
        assert!(!empty.contains(&reachable));
    }

    fn fixture_site(name: &str, component: u64) -> crate::facts::StaticSiteId {
        crate::facts::StaticSiteId::new(
            CanonicalPath::new(&format!("crate::{name}"))
                .unwrap_or_else(|error| panic!("the fixture path is canonical: {error}")),
            crate::facts::StructuralPosition::new(vec![component])
                .unwrap_or_else(|error| panic!("the fixture position is nonempty: {error}")),
        )
    }

    fn fixture_slot(package: &str, name: &str) -> crate::agent::ToolSlotId {
        crate::agent::ToolSlotId::derive(package, name)
            .unwrap_or_else(|error| panic!("the fixture slot is declared: {error}"))
    }

    fn fixture_requirement_slot(
        site: &str,
        component: u64,
        name: &str,
        kind: crate::agent::ToolSlotKind,
    ) -> SiteRequirementSlotId {
        SiteRequirementSlotId::new(
            fixture_site(site, component),
            fixture_slot("fixture", name),
            kind,
        )
    }

    #[test]
    fn capability_authority_closure_orders_and_dedups_requirement_slots() {
        let first = fixture_requirement_slot(
            "alpha",
            0,
            "search",
            crate::agent::ToolSlotKind::ProviderTool,
        );
        let second = fixture_requirement_slot(
            "beta",
            1,
            "fetch",
            crate::agent::ToolSlotKind::SourceHandler,
        );
        let forward = CapabilityAuthorityClosure::with_slots([], [first.clone(), second.clone()])
            .unwrap_or_else(|error| panic!("the declared slots are within the bound: {error}"));
        let reversed = CapabilityAuthorityClosure::with_slots([], [second.clone(), first.clone()])
            .unwrap_or_else(|error| panic!("the declared slots are within the bound: {error}"));
        assert_eq!(forward, reversed, "canonical order is traversal-order free");
        assert_eq!(forward.slots().len(), 2);
        assert!(forward.contains_slot(&first));
        assert!(forward.contains_slot(&second));
        let duplicated =
            CapabilityAuthorityClosure::with_slots([], [first.clone(), first.clone(), second])
                .unwrap_or_else(|error| panic!("duplicates stay within the bound: {error}"));
        assert_eq!(
            duplicated, forward,
            "one slot identity enters the closure once"
        );
    }

    #[test]
    fn capability_authority_closure_qualifies_requirement_slots_by_site() {
        let here = fixture_requirement_slot(
            "alpha",
            0,
            "search",
            crate::agent::ToolSlotKind::ProviderTool,
        );
        let there = fixture_requirement_slot(
            "alpha",
            1,
            "search",
            crate::agent::ToolSlotKind::ProviderTool,
        );
        let elsewhere = fixture_requirement_slot(
            "beta",
            0,
            "search",
            crate::agent::ToolSlotKind::ProviderTool,
        );
        assert_ne!(here, there, "one slot at two positions is two requirements");
        assert_ne!(
            here, elsewhere,
            "one slot in two workflows is two requirements"
        );
        let closure =
            CapabilityAuthorityClosure::with_slots([], [here.clone(), there.clone(), elsewhere])
                .unwrap_or_else(|error| panic!("the declared slots are within the bound: {error}"));
        assert_eq!(closure.slots().len(), 3);
        assert!(closure.contains_slot(&here));
        assert!(closure.contains_slot(&there));
    }

    #[test]
    fn capability_authority_closure_qualifies_requirement_slots_by_kind() {
        let provider = fixture_requirement_slot(
            "alpha",
            0,
            "search",
            crate::agent::ToolSlotKind::ProviderTool,
        );
        let handler = fixture_requirement_slot(
            "alpha",
            0,
            "search",
            crate::agent::ToolSlotKind::SourceHandler,
        );
        assert_ne!(
            provider, handler,
            "one slot name under two kinds is two requirements"
        );
        assert_eq!(provider.kind().wire_name(), "provider-tool");
        assert_eq!(handler.kind().wire_name(), "source-handler");
    }

    #[test]
    fn capability_authority_closure_refuses_oversized_requirement_slot_input() {
        let slot = fixture_requirement_slot(
            "alpha",
            0,
            "search",
            crate::agent::ToolSlotKind::ProviderTool,
        );
        let oversized = vec![slot; CapabilityAuthorityClosure::MAXIMUM_SLOTS + 1];
        let error = CapabilityAuthorityClosure::with_slots([], oversized)
            .err()
            .unwrap_or_else(|| panic!("one slot past the bound is refused"));
        assert!(
            matches!(
                error,
                AuthorityError::ClosureExceedsMaximum { maximum, .. }
                    if maximum == CapabilityAuthorityClosure::MAXIMUM_SLOTS
            ),
            "the refusal names the declared slot bound"
        );
    }

    #[test]
    fn capability_authority_closure_without_slots_declares_none() {
        let reachable = fixture_binding(&fixture_requirement("reachable"), &TypeDescriptor::INT);
        let closure = CapabilityAuthorityClosure::new([reachable.clone()])
            .unwrap_or_else(|error| panic!("the declared closure is within the bound: {error}"));
        assert_eq!(closure.instances(), std::slice::from_ref(&reachable));
        assert!(
            closure.slots().is_empty(),
            "a closure that supplies no slot declares none"
        );
        assert!(!closure.contains_slot(&fixture_requirement_slot(
            "alpha",
            0,
            "search",
            crate::agent::ToolSlotKind::ProviderTool,
        )));
    }

    fn fixture_site_route(components: &[u64]) -> crate::facts::StaticSiteId {
        crate::facts::StaticSiteId::new(
            CanonicalPath::new("crate::alpha")
                .unwrap_or_else(|error| panic!("the fixture path is canonical: {error}")),
            crate::facts::StructuralPosition::new(components.to_vec())
                .unwrap_or_else(|error| panic!("the fixture position is nonempty: {error}")),
        )
    }

    fn fixture_route_slot(components: &[u64]) -> SiteRequirementSlotId {
        SiteRequirementSlotId::new(
            fixture_site_route(components),
            fixture_slot("fixture", "search"),
            crate::agent::ToolSlotKind::Composite,
        )
    }

    #[test]
    fn capability_authority_closure_holds_instances_and_slots_together() {
        let reachable = fixture_binding(&fixture_requirement("reachable"), &TypeDescriptor::INT);
        let slot = fixture_requirement_slot(
            "alpha",
            0,
            "search",
            crate::agent::ToolSlotKind::ProviderTool,
        );
        let closure = CapabilityAuthorityClosure::with_slots([reachable.clone()], [slot.clone()])
            .unwrap_or_else(|error| panic!("the mixed closure is within the bound: {error}"));
        assert_eq!(closure.len(), 1, "len counts bindings only");
        assert!(!closure.is_empty());
        assert_eq!(closure.slots().len(), 1);
        assert!(closure.contains(&reachable));
        assert!(closure.contains_slot(&slot));
    }

    #[test]
    fn capability_authority_closure_spells_multi_component_positions_unambiguously() {
        let first = fixture_route_slot(&[1, 23]);
        let second = fixture_route_slot(&[12, 3]);
        let third = fixture_route_slot(&[1, 2, 3]);
        assert_ne!(
            first, second,
            "one component boundary cannot be confused with another"
        );
        assert_ne!(first, third, "two components cannot be confused with three");
        assert_ne!(second, third);
        assert_ne!(
            first.as_str(),
            second.as_str(),
            "the component separator keeps the routes distinct"
        );
        assert_eq!(
            first.site().position().components(),
            &[1, 23],
            "the full route is retained"
        );
    }

    #[test]
    fn site_requirement_slot_identity_pins_the_exact_spelling() {
        let slot =
            fixture_requirement_slot("alpha", 2, "search", crate::agent::ToolSlotKind::Composite);
        let expected = format!(
            "site-slot:12:crate::alpha:1:2:74:{}:9:composite",
            slot.slot().as_str()
        );
        assert_eq!(
            slot.as_str(),
            expected,
            "the portable spelling is stable, length-prefixed, and kind-qualified"
        );
    }

    #[test]
    fn site_requirement_slot_identity_is_prefixed_and_stable() {
        let slot =
            fixture_requirement_slot("alpha", 2, "search", crate::agent::ToolSlotKind::Composite);
        assert!(slot.as_str().starts_with("site-slot:"));
        assert_eq!(slot.kind(), crate::agent::ToolSlotKind::Composite);
        assert_eq!(slot.site().position().components(), &[2]);
        assert_eq!(
            slot.slot().as_str(),
            fixture_slot("fixture", "search").as_str()
        );
        assert_eq!(
            slot,
            fixture_requirement_slot("alpha", 2, "search", crate::agent::ToolSlotKind::Composite)
        );
        assert_ne!(
            slot.as_str(),
            fixture_requirement_slot("alpha", 20, "search", crate::agent::ToolSlotKind::Composite)
                .as_str(),
            "length-prefixed parts keep neighbouring numbers distinct"
        );
    }
}
