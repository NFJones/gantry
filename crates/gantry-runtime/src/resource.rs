//! Runtime admission of the Section 28 resource-accounting facts.
//!
//! The runtime consumes a resource's owner generation, lifetime, operation state,
//! quotas, liveness roots, and settlement only from the declared durable
//! reconstruction record of `GNT-28.7-durable-resource-reconstruction`. Every
//! admission routes its declared carrier through the model's `admit_resource_carrier`,
//! so an ordinary serialization or ordinary durable-state carrier is refused with
//! `ResourceError::OrdinaryCarrierRefused` before any recorded fact is reconstructed:
//! a resource can never enter the runtime unowned or without a terminal disposition.
//!
//! Semantic release and record retirement stay distinct here. Finishing, poisoning,
//! or emergency release settles the resource's lifetime while every declared quota
//! fact remains observable, and retirement of the retained reconstruction record is
//! refused until every declared liveness root has closed and the retention fence of
//! `GNT-28.8-retention-and-compaction-fences` has expired; host allocation behavior,
//! runtime compaction, and host-resource reconstruction stay outside this model under
//! `GNT-28.10-resource-accounting-non-claims`.
//!
//! This module owns the admission boundary and the runtime's settlement step: an admitted
//! resource settles through the model's own lifetime transitions, so the runtime never chooses a
//! terminal disposition the model did not derive. An admitted account carries the Section 20
//! subject it was admitted under — the logical operation identity and resource generation derived
//! from the operation's declared facts and the runtime's own per-site generation counter — so a
//! model-issued post-failure settlement is applied only after its own operation and generation
//! compare equal to that subject, and a foreign or stale settlement mutates nothing. It performs
//! no durable or host I/O, decodes no record bytes, and publishes no journal, checkpoint,
//! evaluator, or host behavior; those remain with the durable, recovery, and machine modules.
//!
//! Live-resource admission at an operation boundary reads the authenticated Section 20 kind.
//! `ExecutableOperation` carries an optional kind and the retained-program `GNTPRG05` wire
//! round-trips it (see `docs/operation-kind-carriage.md`); the machine derives the subject from the
//! decoded metadata, so the subject carries the kind the program authenticated, and
//! every account-construction path refuses a subject whose operation carries no live-resource kind
//! with [`ResourceRegistryRefusal::UnauthenticatedOperationKind`], so no account can exist for it:
//! the registry checks its own keys first and the constructor enforces the kind. The kind is
//! authenticated by analysis - `GNT-6.2j` declares the `live_resource` struct modifier - and is
//! never inferred from a caller-presented declaration, an effect row, or the hook-site kind.

use std::collections::BTreeMap;

use gantry_ir::{
    CanonicalPath, Charge, DurableResourceRecord, EmergencyCleanupWitness, EmergencyReleaseWitness,
    ExecutableOperation, LogicalOperationId, OperationKind, OwnerGeneration, PoisonWitness,
    PostFailureSettlement, Quota, QuotaFamily, QuotaOwner, ResourceAction, ResourceCarrier,
    ResourceError, ResourceGenerationId, ResourceLedger, ResourceLifetimeState, StaticSiteId,
    StructuralPosition, admit_resource_carrier,
};

/// One runtime-owned binding of an admitted account to its Section 20 subject.
///
/// The binding is derived, never chosen: one declared operation declaration path, the canonical
/// workflow and structural position of the operation's site, and the runtime's own per-site
/// generation counter decide the logical operation identity and the resource generation the
/// account is admitted under. The derivation is exactly the one the Section 20 operation ABI
/// publishes, so a settlement the ABI issues for the same facts compares equal to this binding.
///
/// Construction is crate-private: the only public source of a binding is the machine's own
/// pending-operation accessor, so a caller outside this crate cannot supply or forge a subject.
///
/// ```compile_fail
/// // The derivation constructor is crate-private and unnameable from outside the crate.
/// let _ = gantry_runtime::ResourceSubjectBinding::derive;
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceSubjectBinding {
    site: StaticSiteId,
    operation: LogicalOperationId,
    generation: ResourceGenerationId,
    kind: Option<OperationKind>,
}

impl ResourceSubjectBinding {
    /// Derives the binding of one declared operation site and one runtime generation.
    #[must_use]
    pub(crate) fn derive(
        declaration: &CanonicalPath,
        workflow: CanonicalPath,
        position: StructuralPosition,
        generation: u64,
        kind: Option<OperationKind>,
    ) -> Self {
        let site = StaticSiteId::new(workflow, position);
        let operation = LogicalOperationId::derive(declaration, &site);
        let generation = ResourceGenerationId::derive(&operation, &site, generation);
        Self {
            site,
            operation,
            generation,
            kind,
        }
    }

    /// Returns the Section 20 operation kind the decoded metadata authenticated, when any.
    ///
    /// A subject whose operation carries no authenticated live-resource kind is never admissible:
    /// [`ResourceRegistry::admit`] refuses it rather than defaulting a kind.
    #[must_use]
    pub const fn operation_kind(&self) -> Option<OperationKind> {
        self.kind
    }

    /// Derives the binding one decoded operation metadata declares at one site.
    ///
    /// The declaration is the metadata's canonical action path, so an operation whose decoded
    /// metadata declares no action has no Section 20 resource subject and yields `None` rather
    /// than a substituted identity.
    #[must_use]
    pub(crate) fn from_declared_operation(
        workflow: &CanonicalPath,
        position: &StructuralPosition,
        metadata: &ExecutableOperation,
        generation: u64,
    ) -> Option<Self> {
        let action = metadata.action.as_ref()?;
        Some(Self::derive(
            &action.path,
            workflow.clone(),
            position.clone(),
            generation,
            metadata.section20_kind,
        ))
    }

    /// Returns the canonical operation site of this binding.
    #[must_use]
    pub const fn site(&self) -> &StaticSiteId {
        &self.site
    }

    /// Returns the derived logical operation identity of this binding.
    #[must_use]
    pub const fn operation(&self) -> &LogicalOperationId {
        &self.operation
    }

    /// Returns the derived resource generation of this binding.
    #[must_use]
    pub const fn generation(&self) -> &ResourceGenerationId {
        &self.generation
    }
}

/// Why the runtime refused to apply one model-issued post-failure settlement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PostFailureSettlementRefusal {
    /// The settlement names another logical operation than this account's.
    ForeignOperation,
    /// The settlement names another resource generation of this account's site.
    StaleGeneration,
    /// The model refused the settlement under its own witness or lifetime rules.
    Model(ResourceError),
}

/// One registry of admitted resources, keyed by their Section 20 subject.
///
/// A registry owns at most one account per subject: every account enters through a subject only the
/// machine can issue, and a second admission for the same subject in the same registry is refused
/// rather than replaced. A settlement selects its account by the settlement's own operation and
/// generation rather than by caller text, so a settlement naming an operation or generation this
/// registry holds no account for changes nothing.
///
/// Uniqueness here is per registry: this type publishes no global uniqueness claim, and making one
/// execution-layer registry the runtime's sole live-resource owner remains the next increment's
/// obligation.
///
/// A registry may declare a live-resource limit: admission is refused with
/// [`ResourceRegistryRefusal::LiveResourceLimitReached`] once that many live accounts exist - a
/// lifetime is live exactly while it is `Active` or `Finishing` - and a settlement releases the
/// place immediately, so the later retention states never take it back.
#[derive(Debug, Default)]
pub struct ResourceRegistry {
    accounts: BTreeMap<(LogicalOperationId, ResourceGenerationId), AdmittedResource>,
    live_limit: Option<u64>,
}

impl ResourceRegistry {
    /// Creates an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            accounts: BTreeMap::new(),
            live_limit: None,
        }
    }

    /// Creates an empty registry that admits at most `limit` live resources at once.
    ///
    /// A live resource is one whose lifetime is still live - `Active` or `Finishing`: settling an
    /// account releases its place immediately, while the retained account stays queryable through
    /// retirement, so quota release stays independent of physical reclamation.
    #[must_use]
    pub fn with_live_limit(limit: u64) -> Self {
        Self {
            accounts: BTreeMap::new(),
            live_limit: Some(limit),
        }
    }

    /// Returns the declared live-resource admission limit, when any.
    #[must_use]
    pub const fn live_limit(&self) -> Option<u64> {
        self.live_limit
    }

    /// Counts the admitted resources that still hold a live lifetime.
    ///
    /// A lifetime is live exactly while it is `Active` or `Finishing`, so a settlement releases the
    /// place and the later retention states (`Retired`, `Deleted`) never take it back.
    #[must_use]
    pub fn live_resources(&self) -> u64 {
        self.accounts
            .values()
            .filter(|account| {
                matches!(
                    account.ledger().lifetime(),
                    ResourceLifetimeState::Active | ResourceLifetimeState::Finishing
                )
            })
            .fold(0_u64, |count, _| count.saturating_add(1))
    }

    /// Removes the accounts whose lifetime has reached the terminal retention state.
    ///
    /// Deletion is the only state in which the retained record is gone, so reaping is physical
    /// reclamation alone: it frees registry memory without changing any semantic release, and the
    /// registry holds no account for a reaped subject afterwards. A settled lifetime that is still
    /// retained keeps its account and stays queryable.
    pub fn reap_deleted(&mut self) -> usize {
        let before = self.accounts.len();
        self.accounts
            .retain(|_, account| account.ledger().lifetime() != ResourceLifetimeState::Deleted);
        before.saturating_sub(self.accounts.len())
    }

    /// Admits one resource for one machine-issued subject.
    ///
    /// A subject that already owns an account in this registry is refused rather than replaced, so
    /// one registry never holds two lifetimes for one subject. Refusals keep their own precedence:
    /// a duplicate subject is refused as [`ResourceRegistryRefusal::SecondAdmission`], a subject
    /// whose operation carries no authenticated live-resource kind as
    /// [`ResourceRegistryRefusal::UnauthenticatedOperationKind`], and only then is the declared
    /// live-resource limit consulted, so a full registry never masks a stronger refusal.
    pub fn admit(
        &mut self,
        subject: ResourceSubjectBinding,
        carrier: ResourceCarrier,
        record: DurableResourceRecord,
    ) -> Result<&AdmittedResource, ResourceRegistryRefusal> {
        let live = self.live_resources();
        let limit = self.live_limit;
        let key = (subject.operation().clone(), subject.generation().clone());
        match self.accounts.entry(key) {
            std::collections::btree_map::Entry::Occupied(_) => {
                Err(ResourceRegistryRefusal::SecondAdmission)
            }
            std::collections::btree_map::Entry::Vacant(slot) => {
                let account = AdmittedResource::admit(carrier, record, subject)?;
                if let Some(limit) = limit
                    && live >= limit
                {
                    return Err(ResourceRegistryRefusal::LiveResourceLimitReached { limit });
                }
                Ok(slot.insert(account))
            }
        }
    }

    /// Returns the account one subject owns, when any.
    #[must_use]
    pub fn account(&self, subject: &ResourceSubjectBinding) -> Option<&AdmittedResource> {
        self.accounts
            .get(&(subject.operation().clone(), subject.generation().clone()))
    }

    /// Returns the account one subject owns for owner-authorized changes, when any.
    #[must_use]
    pub fn account_mut(
        &mut self,
        subject: &ResourceSubjectBinding,
    ) -> Option<&mut AdmittedResource> {
        self.accounts
            .get_mut(&(subject.operation().clone(), subject.generation().clone()))
    }

    /// Settles the account its own subject names from one model-issued post-failure settlement.
    ///
    /// The account is selected by the settlement's own operation and generation, so a settlement
    /// naming a subject this registry holds no account for is refused without changing any account.
    pub fn settle_from_post_failure(
        &mut self,
        settlement: &PostFailureSettlement,
        settled_at: u64,
    ) -> Result<ResourceLifetimeState, ResourceRegistryRefusal> {
        let key = (
            settlement.operation().clone(),
            settlement.generation().clone(),
        );
        let account = self
            .accounts
            .get_mut(&key)
            .ok_or(ResourceRegistryRefusal::UnknownSubject)?;
        account
            .settle_from_post_failure(settlement, settled_at)
            .map_err(ResourceRegistryRefusal::Settlement)
    }

    /// Settles one account from the sealed emergency-cleanup witness its caller holds.
    ///
    /// The witness is a sealed stop artifact that names no account, so the caller names the
    /// subject: the registry selects exactly that account and the account's own ledger derives the
    /// emergency-released lifetime. A subject this registry holds no account for is refused with
    /// [`ResourceRegistryRefusal::UnknownSubject`], and a lifetime that does not admit an emergency
    /// release is refused by the model's own transition rule through
    /// [`ResourceRegistryRefusal::EmergencyRelease`].
    pub fn settle_from_emergency_cleanup(
        &mut self,
        subject: &ResourceSubjectBinding,
        cleanup: EmergencyCleanupWitness,
    ) -> Result<ResourceLifetimeState, ResourceRegistryRefusal> {
        let key = (subject.operation().clone(), subject.generation().clone());
        let account = self
            .accounts
            .get_mut(&key)
            .ok_or(ResourceRegistryRefusal::UnknownSubject)?;
        account
            .settle_from_emergency_cleanup(cleanup)
            .map_err(ResourceRegistryRefusal::EmergencyRelease)
    }

    /// Charges one admitted account's declared quotas for one presented action.
    ///
    /// The caller names the subject, so the account is selected by the subject's own operation and
    /// generation and a subject this registry holds no account for is refused with
    /// [`ResourceRegistryRefusal::UnknownSubject`]. The presented owner generation and the charge
    /// vector are then decided by the account's own ledger, so a stale owner, an undeclared quota
    /// key, an exhausted ceiling, an overflowing member, and a lifetime that admits no charge are
    /// each refused with the model's own reason through [`ResourceRegistryRefusal::Charge`], and a
    /// refused vector commits nothing.
    pub fn charge(
        &mut self,
        subject: &ResourceSubjectBinding,
        presented_owner: OwnerGeneration,
        action: ResourceAction,
        charges: &[Charge],
    ) -> Result<(), ResourceRegistryRefusal> {
        let key = (subject.operation().clone(), subject.generation().clone());
        let account = self
            .accounts
            .get_mut(&key)
            .ok_or(ResourceRegistryRefusal::UnknownSubject)?;
        account
            .ledger_mut()
            .charge(presented_owner, action, charges)
            .map_err(ResourceRegistryRefusal::Charge)
    }
}

/// Why the runtime resource registry refused an admission or a settlement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResourceRegistryRefusal {
    /// The subject already owns an admitted account.
    SecondAdmission,
    /// The subject's operation carries no authenticated live-resource Section 20 kind.
    UnauthenticatedOperationKind,
    /// The account's own emergency release refused the sealed cleanup witness.
    EmergencyRelease(ResourceError),
    /// The account's own ledger refused the presented charge.
    Charge(ResourceError),
    /// The registry's declared live-resource limit is already reached.
    LiveResourceLimitReached {
        /// The declared limit.
        limit: u64,
    },
    /// The registry holds no account for the settlement's own operation and generation.
    UnknownSubject,
    /// The model refused the carrier or the reconstruction record at admission.
    Admission(ResourceError),
    /// The account's own settlement step refused the settlement.
    Settlement(PostFailureSettlementRefusal),
}

/// One resource whose declared accounting facts the runtime has admitted.
///
/// The account is reconstructible only from the declared durable reconstruction
/// record: the ledger is private and [`AdmittedResource::admit`] is the only
/// constructor, so no ordinary carrier can produce a runtime account. That constructor admits
/// only a subject whose operation carries an authenticated live-resource Section 20 kind, so no
/// construction path can open an account for an unauthenticated operation.
///
/// The account is uniquely owned and deliberately not copyable: it implements no
/// `Clone`, so a second account over one resource's lifetime requires a second admitted
/// reconstruction record of `GNT-28.7-durable-resource-reconstruction`, and
/// `GNT-28.9-retirement-deletion-and-stale-owner-fences` admits a genuinely later
/// owner only through a distinct declared resource record.
#[derive(Debug, Eq, PartialEq)]
pub struct AdmittedResource {
    ledger: ResourceLedger,
    subject: ResourceSubjectBinding,
}

impl AdmittedResource {
    /// Admits one durable reconstruction record presented under its declared carrier.
    ///
    /// The subject's authenticated live-resource Section 20 kind is checked first, so an
    /// unauthenticated operation is refused before any carrier or record is inspected. The carrier
    /// is then admitted through the model's `admit_resource_carrier`: an ordinary serialization or
    /// ordinary durable-state carrier is refused with `ResourceError::OrdinaryCarrierRefused`, and
    /// the record is dropped unread. Only the declared reconstruction record reconstructs the
    /// account's ledger.
    pub fn admit(
        carrier: ResourceCarrier,
        record: DurableResourceRecord,
        subject: ResourceSubjectBinding,
    ) -> Result<Self, ResourceRegistryRefusal> {
        if subject.operation_kind() != Some(OperationKind::LiveResource) {
            return Err(ResourceRegistryRefusal::UnauthenticatedOperationKind);
        }
        admit_resource_carrier(carrier).map_err(ResourceRegistryRefusal::Admission)?;
        Ok(Self {
            ledger: ResourceLedger::reconstruct(record),
            subject,
        })
    }

    /// Returns the Section 20 subject this account was admitted under.
    #[must_use]
    pub const fn subject(&self) -> &ResourceSubjectBinding {
        &self.subject
    }

    /// Returns the reconstructed accounting ledger of this resource.
    #[must_use]
    pub fn ledger(&self) -> &ResourceLedger {
        &self.ledger
    }

    /// Returns the reconstructed accounting ledger for owner-authorized changes.
    #[must_use]
    pub fn ledger_mut(&mut self) -> &mut ResourceLedger {
        &mut self.ledger
    }

    /// Returns one declared quota of this resource by its closed owner and family.
    #[must_use]
    pub fn quota(&self, owner: QuotaOwner, family: QuotaFamily) -> Option<Quota> {
        self.ledger.quota(owner, family)
    }

    /// Returns the declared ceiling minus the committed logical use of one quota.
    ///
    /// This is exactly the logical headroom of that quota: a charge against the key
    /// is admitted by the quota while the committed use stays within the ceiling, and
    /// refused with `ResourceError::QuotaExhausted` once it would exceed it. A charge
    /// still requires a lifetime that admits charging. `None` means the closed
    /// owner/family key is undeclared for this resource.
    #[must_use]
    pub fn remaining(&self, owner: QuotaOwner, family: QuotaFamily) -> Option<u64> {
        self.ledger
            .quota(owner, family)
            .map(|quota| quota.limit().saturating_sub(quota.used()))
    }

    /// Captures the current declared facts as a durable reconstruction record.
    ///
    /// The captured record is exactly the model's `durable_record` output, so a
    /// runtime checkpoint can only publish facts the admitted account actually holds.
    #[must_use]
    pub fn durable_record(&self) -> DurableResourceRecord {
        self.ledger.durable_record()
    }

    /// Records that finalization of one admitted resource completed.
    ///
    /// The resource must already be finishing: the model's two-phase lifetime of
    /// `GNT-28.4-resource-lifetime-finish-poison-and-emergency-release` is entered through the
    /// ledger and this step records the completion at one declared logical instant. Any other
    /// lifetime is refused by the model's own transition rule, no quota fact changes, and the
    /// retained settlement baseline names the current owner.
    pub fn complete_finalization(
        &mut self,
        settled_at: u64,
    ) -> Result<ResourceLifetimeState, ResourceError> {
        self.ledger.finish(settled_at)?;
        Ok(self.ledger.lifetime())
    }

    /// Settles one admitted resource from a model-issued post-failure settlement.
    ///
    /// The settlement must name exactly the logical operation and resource generation this
    /// account was admitted under: a settlement naming another operation is refused with
    /// [`PostFailureSettlementRefusal::ForeignOperation`] and one naming another generation of the
    /// same site with [`PostFailureSettlementRefusal::StaleGeneration`], each before any lifetime
    /// fact changes. Only then is the model's poisoning witness derived, so a settlement whose
    /// derived state is not the poisoned state is refused with the model's own
    /// `ResourceError::FailureDoesNotPoisonResource`.
    pub fn settle_from_post_failure(
        &mut self,
        settlement: &PostFailureSettlement,
        settled_at: u64,
    ) -> Result<ResourceLifetimeState, PostFailureSettlementRefusal> {
        if settlement.operation() != self.subject.operation() {
            return Err(PostFailureSettlementRefusal::ForeignOperation);
        }
        if settlement.generation() != self.subject.generation() {
            return Err(PostFailureSettlementRefusal::StaleGeneration);
        }
        let witness = PoisonWitness::from_post_failure(settlement, settled_at)
            .map_err(PostFailureSettlementRefusal::Model)?;
        self.ledger
            .poison(witness)
            .map_err(PostFailureSettlementRefusal::Model)?;
        Ok(self.ledger.lifetime())
    }

    /// Settles one admitted resource from admitted hard-cancellation cleanup.
    ///
    /// The cleanup witness is obtainable only from the stop model's linearized escalation, so
    /// this step can never manufacture emergency release from an arbitrary logical instant.
    pub fn settle_from_emergency_cleanup(
        &mut self,
        cleanup: EmergencyCleanupWitness,
    ) -> Result<ResourceLifetimeState, ResourceError> {
        self.ledger
            .emergency_release(EmergencyReleaseWitness::from_cleanup(cleanup))?;
        Ok(self.ledger.lifetime())
    }
}
