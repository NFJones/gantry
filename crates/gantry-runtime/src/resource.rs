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
//!
//! Recovery reconstructs through one declared entry as well. [`ResourceRegistry::reconstruct`] takes
//! the records one recovery pass presents - each a subject's declared reconstruction record, under
//! its declared carrier and with the owner generation that pass holds for it - and publishes a
//! registry only when every presented record was admitted under exactly that owner generation. An
//! ordinary carrier, a subject whose operation carries no authenticated live-resource kind, a
//! repeated subject, a record naming a generation the pass does not hold, and an exceeded
//! live-resource limit each refuse the whole set, so recovery never publishes a partially
//! reconstructed registry. Carrying those records through journal, checkpoint, and durable-state
//! formats remains with the durable, recovery, and machine modules.

use std::collections::BTreeMap;

use gantry_ir::{
    AdapterInstance, CanonicalPath, Charge, Completion, ContainmentError, ContainmentSettlement,
    DurableResourceRecord, EmergencyCleanupWitness, EmergencyReleaseWitness, ExecutableOperation,
    ExternalOutcome, LivenessRoot, LogicalOperationId, OperationAbiError, OperationKind,
    OwnerGeneration, PoisonLedger, PoisonReason, PoisonWitness, PostFailureSettlement, Quota,
    QuotaFamily, QuotaOwner, ResourceAction, ResourceCarrier, ResourceError, ResourceGenerationId,
    ResourceLedger, ResourceLifetimeState, RetentionFence, StaticSiteId, StructuralPosition,
    admit_resource_carrier,
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
///
/// Every mutating route of this type is owner-qualified: charging, renewal, and both finish steps
/// require the owner generation their caller presents to equal the account's current one, so a
/// superseded owner can neither spend, renew, enter, nor complete the finish path.
///
/// Root closure, retirement, and deletion are owner-qualified on those same terms, and no route
/// hands out a mutable registry-held account, so an admitted account cannot be replaced wholesale
/// to reach a transition its own fence refused:
///
/// ```compile_fail
/// use gantry_runtime::{AdmittedResource, ResourceRegistry, ResourceSubjectBinding};
///
/// fn replace_admitted(
///     registry: &mut ResourceRegistry,
///     subject: &ResourceSubjectBinding,
///     account: AdmittedResource,
/// ) {
///     // No route hands out a mutable registry-held account, so this write is unnameable.
///     *registry.account_mut(subject).unwrap() = account;
/// }
/// ```
#[derive(Debug, Default)]
pub struct ResourceRegistry {
    accounts: BTreeMap<(LogicalOperationId, ResourceGenerationId), AdmittedResource>,
    live_limit: Option<u64>,
    adapter_faults: PoisonLedger,
}

/// One declared reconstruction record as a recovery pass presents it.
///
/// A recovery pass holds two independent facts per resource: the declared durable reconstruction
/// record of `GNT-28.7-durable-resource-reconstruction` and the owner generation that pass holds
/// for the resource. Presenting them together is what lets [`ResourceRegistry::reconstruct`] refuse
/// a record whose own owner generation is any other generation, so no superseded record is silently
/// re-adopted and no record naming a generation the pass has not reached is adopted either.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveredResourceRecord {
    subject: ResourceSubjectBinding,
    carrier: ResourceCarrier,
    owner: OwnerGeneration,
    record: DurableResourceRecord,
}

impl RecoveredResourceRecord {
    /// Pairs one declared reconstruction record with the recovered owner generation of its subject.
    #[must_use]
    pub fn new(
        subject: ResourceSubjectBinding,
        carrier: ResourceCarrier,
        owner: OwnerGeneration,
        record: DurableResourceRecord,
    ) -> Self {
        Self {
            subject,
            carrier,
            owner,
            record,
        }
    }

    /// Returns the subject this record is presented for.
    #[must_use]
    pub const fn subject(&self) -> &ResourceSubjectBinding {
        &self.subject
    }

    /// Returns the declared carrier this record is presented under.
    #[must_use]
    pub const fn carrier(&self) -> ResourceCarrier {
        self.carrier
    }

    /// Returns the owner generation the recovery pass holds for this subject.
    #[must_use]
    pub const fn owner(&self) -> OwnerGeneration {
        self.owner
    }

    /// Returns the declared durable reconstruction record.
    #[must_use]
    pub const fn record(&self) -> &DurableResourceRecord {
        &self.record
    }
}

impl ResourceRegistry {
    /// Creates an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            accounts: BTreeMap::new(),
            live_limit: None,
            adapter_faults: PoisonLedger::new(),
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
            adapter_faults: PoisonLedger::new(),
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

    /// Reconstructs a whole registry from the records one recovery pass presents.
    ///
    /// Every presented record enters through the same admission path a live admission uses: the
    /// subject's authenticated live-resource Section 20 kind is checked first, the declared carrier
    /// is admitted through the model's `admit_resource_carrier`, and the record's own owner
    /// generation is then compared with the generation the pass holds for that subject. A record
    /// naming any other generation is refused with the model's own `ResourceError::StaleOwner`
    /// through [`ResourceRegistryRefusal::Admission`], because the pass does not hold that resource
    /// under the generation the record describes.
    ///
    /// The reconstruction is one unit: a registry is published only when every presented record was
    /// admitted, so a refused record publishes no account at all and recovery never continues from a
    /// partially reconstructed registry. Refusals keep their own precedence within each record: a
    /// repeated subject first, then the account's own construction, then the owner generation, and
    /// the declared `live_limit` last over the accounts that are still live.
    pub fn reconstruct(
        live_limit: Option<u64>,
        recovered: impl IntoIterator<Item = RecoveredResourceRecord>,
    ) -> Result<Self, ResourceRegistryRefusal> {
        let mut accounts: BTreeMap<(LogicalOperationId, ResourceGenerationId), AdmittedResource> =
            BTreeMap::new();
        let mut live = 0_u64;
        for presented in recovered {
            let key = (
                presented.subject.operation().clone(),
                presented.subject.generation().clone(),
            );
            if accounts.contains_key(&key) {
                return Err(ResourceRegistryRefusal::SecondAdmission);
            }
            let account =
                AdmittedResource::admit(presented.carrier, presented.record, presented.subject)?;
            let current = account.ledger().owner();
            if current != presented.owner {
                return Err(ResourceRegistryRefusal::Admission(
                    ResourceError::StaleOwner {
                        presented: presented.owner,
                        current,
                    },
                ));
            }
            if matches!(
                account.ledger().lifetime(),
                ResourceLifetimeState::Active | ResourceLifetimeState::Finishing
            ) {
                if let Some(limit) = live_limit
                    && live >= limit
                {
                    return Err(ResourceRegistryRefusal::LiveResourceLimitReached { limit });
                }
                live = live.saturating_add(1);
            }
            accounts.insert(key, account);
        }
        Ok(Self {
            accounts,
            live_limit,
            adapter_faults: PoisonLedger::new(),
        })
    }

    /// Captures the declared reconstruction records of every admitted account.
    ///
    /// The capture is exactly the presentation [`ResourceRegistry::reconstruct`] accepts: every
    /// account publishes the model's own `durable_record` under the declared reconstruction-record
    /// carrier, paired with its own subject and the owner generation its ledger currently holds, so a
    /// checkpoint built from this projection republishes only facts the accounts actually hold and
    /// reconstructs the same accounts under the same generations. No ordinary carrier ever appears in
    /// the output, and the capture is a projection rather than a duplicate: it borrows each account's
    /// declared facts, so it can neither add an account nor change one.
    #[must_use]
    pub fn declared_records(&self) -> Vec<RecoveredResourceRecord> {
        self.accounts
            .values()
            .map(|account| {
                RecoveredResourceRecord::new(
                    account.subject().clone(),
                    ResourceCarrier::ReconstructionRecord,
                    account.ledger().owner(),
                    account.durable_record(),
                )
            })
            .collect()
    }

    /// Returns the account one subject owns, when any.
    #[must_use]
    pub fn account(&self, subject: &ResourceSubjectBinding) -> Option<&AdmittedResource> {
        self.accounts
            .get(&(subject.operation().clone(), subject.generation().clone()))
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
            .charge(presented_owner, action, charges)
            .map_err(ResourceRegistryRefusal::Charge)
    }

    /// Renews exactly one declared quota of one admitted account through the current owner.
    ///
    /// The caller names the subject, so the account is selected by the subject's own operation and
    /// generation and a subject this registry holds no account for is refused with
    /// [`ResourceRegistryRefusal::UnknownSubject`]. The account's own ledger then decides: a stale
    /// presented owner, an undeclared owner-and-family key, an exhausted renewal allowance, an
    /// overflowing ceiling, and a lifetime that admits no charge are each refused with the model's
    /// own reason through [`ResourceRegistryRefusal::Renewal`], and a refused renewal changes
    /// nothing.
    pub fn renew(
        &mut self,
        subject: &ResourceSubjectBinding,
        presented_owner: OwnerGeneration,
        owner: QuotaOwner,
        family: QuotaFamily,
        increase: u64,
    ) -> Result<(), ResourceRegistryRefusal> {
        let key = (subject.operation().clone(), subject.generation().clone());
        let account = self
            .accounts
            .get_mut(&key)
            .ok_or(ResourceRegistryRefusal::UnknownSubject)?;
        account
            .renew(presented_owner, owner, family, increase)
            .map_err(ResourceRegistryRefusal::Renewal)
    }

    /// Advances one admitted account to finishing for the owner generation its caller presents.
    ///
    /// The account is selected by the subject's own operation and generation, so a subject this
    /// registry holds no account for is refused with [`ResourceRegistryRefusal::UnknownSubject`]. The
    /// presented owner generation must then be the account's current one: any other presentation is
    /// refused with the model's own `ResourceError::StaleOwner` through
    /// [`ResourceRegistryRefusal::Finish`] before any lifetime fact changes, so a superseded owner can
    /// neither enter nor complete the finish path. Only then does the model's own transition rule
    /// decide the advance, and a finishing account keeps its live place.
    pub fn begin_finish(
        &mut self,
        subject: &ResourceSubjectBinding,
        presented_owner: OwnerGeneration,
    ) -> Result<ResourceLifetimeState, ResourceRegistryRefusal> {
        let key = (subject.operation().clone(), subject.generation().clone());
        let account = self
            .accounts
            .get_mut(&key)
            .ok_or(ResourceRegistryRefusal::UnknownSubject)?;
        account
            .begin_finish_for(presented_owner)
            .map_err(ResourceRegistryRefusal::Finish)
    }

    /// Completes finalization of one admitted account for the owner generation its caller presents.
    ///
    /// The account is selected and its presented owner generation checked exactly as
    /// [`Self::begin_finish`] does, so a subject this registry holds no account for is refused with
    /// [`ResourceRegistryRefusal::UnknownSubject`] and any other presentation with the model's own
    /// `ResourceError::StaleOwner` through [`ResourceRegistryRefusal::Finish`]. The model's own
    /// transition rule then refuses a lifetime that is not finishing, so one resource settles once and
    /// no second completion is admitted.
    pub fn complete_finalization(
        &mut self,
        subject: &ResourceSubjectBinding,
        presented_owner: OwnerGeneration,
        settled_at: u64,
    ) -> Result<ResourceLifetimeState, ResourceRegistryRefusal> {
        let key = (subject.operation().clone(), subject.generation().clone());
        let account = self
            .accounts
            .get_mut(&key)
            .ok_or(ResourceRegistryRefusal::UnknownSubject)?;
        account
            .complete_finalization_for(presented_owner, settled_at)
            .map_err(ResourceRegistryRefusal::Finish)
    }

    /// Closes one declared liveness root of one admitted account through the current owner.
    ///
    /// The account is selected by the subject's own operation and generation, so a subject this
    /// registry holds no account for is refused with [`ResourceRegistryRefusal::UnknownSubject`]. The
    /// presented owner generation must then be the account's current one: any other presentation is
    /// refused with the model's own `ResourceError::StaleOwner` through
    /// [`ResourceRegistryRefusal::RootClosure`] before any root fact changes. Only then does the
    /// model's own root-closure rule decide, so a root the account does not declare is refused with
    /// the model's own reason.
    pub fn close_liveness_root(
        &mut self,
        subject: &ResourceSubjectBinding,
        presented_owner: OwnerGeneration,
        root: LivenessRoot,
    ) -> Result<(), ResourceRegistryRefusal> {
        let key = (subject.operation().clone(), subject.generation().clone());
        let account = self
            .accounts
            .get_mut(&key)
            .ok_or(ResourceRegistryRefusal::UnknownSubject)?;
        account
            .close_liveness_root_for(presented_owner, root)
            .map_err(ResourceRegistryRefusal::RootClosure)
    }

    /// Retires one admitted account under its declared retention fence through a presented owner.
    ///
    /// The account is selected by the subject's own operation and generation, so a subject this
    /// registry holds no account for is refused with [`ResourceRegistryRefusal::UnknownSubject`]. The
    /// model's own retirement rule then decides the presented owner generation, a still-live root, an
    /// unexpired fence, and an invalid successor, each refused with the model's own reason through
    /// [`ResourceRegistryRefusal::Retirement`], so this route delegates rather than restating them.
    pub fn retire(
        &mut self,
        subject: &ResourceSubjectBinding,
        fence: RetentionFence,
        presented_owner: OwnerGeneration,
        succeeding_owner: OwnerGeneration,
        at: u64,
    ) -> Result<(), ResourceRegistryRefusal> {
        let key = (subject.operation().clone(), subject.generation().clone());
        let account = self
            .accounts
            .get_mut(&key)
            .ok_or(ResourceRegistryRefusal::UnknownSubject)?;
        account
            .retire(fence, presented_owner, succeeding_owner, at)
            .map_err(ResourceRegistryRefusal::Retirement)
    }

    /// Deletes one retired admitted record through the owner generation its caller presents.
    ///
    /// The account is selected by the subject's own operation and generation, so a subject this
    /// registry holds no account for is refused with [`ResourceRegistryRefusal::UnknownSubject`]. The
    /// model's deletion takes no owner generation, so the account's own route requires this
    /// account's current one: any other is refused with the model's own `ResourceError::StaleOwner`
    /// through [`ResourceRegistryRefusal::Deletion`] before the record changes, and only then does
    /// the model's own rule decide whether the lifetime admits deletion.
    pub fn delete(
        &mut self,
        subject: &ResourceSubjectBinding,
        presented_owner: OwnerGeneration,
    ) -> Result<ResourceLifetimeState, ResourceRegistryRefusal> {
        let key = (subject.operation().clone(), subject.generation().clone());
        let account = self
            .accounts
            .get_mut(&key)
            .ok_or(ResourceRegistryRefusal::UnknownSubject)?;
        account
            .delete_for(presented_owner)
            .map_err(ResourceRegistryRefusal::Deletion)
    }

    /// Settles one admitted operation's Section 23 containment path from one completion.
    ///
    /// The account is selected by the subject's own operation and generation, so a subject this
    /// registry holds no account for is refused with [`ResourceRegistryRefusal::UnknownSubject`]. The
    /// account's own containment settlement then decides in the model's declared order - a malformed
    /// completion, then a completion presented to an already-settled operation, then a completion
    /// naming a generation the operation does not hold, then the refinement of the held effect state,
    /// and only then a definite accepted outcome over an ambiguous effect - and every refusal is
    /// reported with the model's own reason through [`ResourceRegistryRefusal::Containment`] without
    /// changing the account's settled facts. The settlement belongs to the account value this registry
    /// holds at that moment, so a subject reconstructed, or reclaimed and readmitted, is a fresh account
    /// value with a fresh unsettled settlement.
    pub fn settle_containment(
        &mut self,
        subject: &ResourceSubjectBinding,
        presented_owner: OwnerGeneration,
        completion: Completion,
    ) -> Result<ExternalOutcome, ResourceRegistryRefusal> {
        let key = (subject.operation().clone(), subject.generation().clone());
        let account = self
            .accounts
            .get_mut(&key)
            .ok_or(ResourceRegistryRefusal::UnknownSubject)?;
        account
            .settle_containment(presented_owner, completion)
            .map_err(ResourceRegistryRefusal::Containment)
    }

    /// Binds or replaces the adapter instance of one admitted account.
    ///
    /// The account is selected by the subject's own operation and generation, so a subject this
    /// registry holds no account for is refused with [`ResourceRegistryRefusal::UnknownSubject`]. The
    /// presented owner generation must be the account's current one, and a replacement is decided by
    /// the model's own substitution rule of the binding the account already holds, so a poisoned
    /// binding, a retired binding, a replacement that widens the rights held, and a replacement whose
    /// owner generation does not succeed the held generation are each refused with the model's own
    /// reason through [`ResourceRegistryRefusal::AdapterBinding`] and nothing is replaced.
    pub fn bind_adapter_instance(
        &mut self,
        subject: &ResourceSubjectBinding,
        presented_owner: OwnerGeneration,
        instance: AdapterInstance,
    ) -> Result<(), ResourceRegistryRefusal> {
        let key = (subject.operation().clone(), subject.generation().clone());
        let account = self
            .accounts
            .get_mut(&key)
            .ok_or(ResourceRegistryRefusal::UnknownSubject)?;
        account
            .bind_adapter_instance(presented_owner, instance)
            .map_err(ResourceRegistryRefusal::AdapterBinding)
    }

    /// Returns the adapter instance bound to one admitted account, when one is bound.
    #[must_use]
    pub fn adapter_instance(&self, subject: &ResourceSubjectBinding) -> Option<&AdapterInstance> {
        self.accounts
            .get(&(subject.operation().clone(), subject.generation().clone()))
            .and_then(AdmittedResource::adapter_instance)
    }

    /// Poisons the adapter instance of one admitted account through the model's own one-way poison.
    ///
    /// The account is selected by the subject's own operation and generation, so a subject this
    /// registry holds no account for is refused with [`ResourceRegistryRefusal::UnknownSubject`]. The
    /// presented owner generation must be the account's current one, and an account that holds no
    /// bound instance is refused as [`AdapterBindingRefusal::Unbound`]. The reason is fixed by the
    /// first poisoning of that instance identity in this registry's reason ledger, so a repeated
    /// poisoning stutters and reports the reason recorded first instead of rewriting it, and no path
    /// clears the landed one-way poison.
    pub fn poison_adapter_instance(
        &mut self,
        subject: &ResourceSubjectBinding,
        presented_owner: OwnerGeneration,
        reason: PoisonReason,
    ) -> Result<PoisonReason, ResourceRegistryRefusal> {
        let ledger = &mut self.adapter_faults;
        let key = (subject.operation().clone(), subject.generation().clone());
        let account = self
            .accounts
            .get_mut(&key)
            .ok_or(ResourceRegistryRefusal::UnknownSubject)?;
        account
            .poison_adapter_instance(presented_owner, reason, ledger)
            .map_err(ResourceRegistryRefusal::AdapterBinding)
    }
}

/// Why the runtime resource registry refused an admission or a settlement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResourceRegistryRefusal {
    /// The subject already owns an admitted account, or was presented twice in one reconstruction.
    SecondAdmission,
    /// The subject's operation carries no authenticated live-resource Section 20 kind.
    UnauthenticatedOperationKind,
    /// The account's own emergency release refused the sealed cleanup witness.
    EmergencyRelease(ResourceError),
    /// The account's own ledger refused the presented charge.
    Charge(ResourceError),
    /// The account's own ledger refused the presented renewal.
    Renewal(ResourceError),
    /// The account's own finish step refused the presented owner or the lifetime transition.
    Finish(ResourceError),
    /// The account's own owner-qualified root closure refused the presented owner or the root.
    RootClosure(ResourceError),
    /// The account's own retirement rule refused the presented owner, a live root, or the fence.
    Retirement(ResourceError),
    /// The account's own deletion rule refused the presented owner generation.
    Deletion(ResourceError),
    /// The account's own Section 23 containment settlement refused the presented completion.
    Containment(ContainmentError),
    /// The account's own adapter binding, replacement, or poisoning refused the request.
    AdapterBinding(AdapterBindingRefusal),
    /// The registry's declared live-resource limit is already reached.
    LiveResourceLimitReached {
        /// The declared limit.
        limit: u64,
    },
    /// The registry holds no account for the settlement's own operation and generation.
    UnknownSubject,
    /// The model refused the carrier, the reconstruction record, or its presented owner generation.
    Admission(ResourceError),
    /// The account's own settlement step refused the settlement.
    Settlement(PostFailureSettlementRefusal),
}

/// Why the runtime refused to bind, replace, or poison one resource-bearing adapter instance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdapterBindingRefusal {
    /// The presented owner generation is not the account's current one.
    StaleOwner(ResourceError),
    /// This account holds no bound adapter instance.
    Unbound,
    /// The model's own substitution rule refused the replacement binding.
    Substitution(OperationAbiError),
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
///
/// The account also owns exactly one Section 23 containment settlement, opened under the owner
/// generation its declared reconstruction record names, so one contained operation settles once for
/// the lifetime of this account value and a malformed, repeated, or stale completion is refused
/// without changing the settled facts. The settlement is runtime state rather than a declared
/// durable fact, so a reconstructed or reclaimed-and-readmitted subject is a fresh account value with
/// a fresh unsettled settlement: the runtime publishes no cross-recovery single-settlement claim.
///
/// The account's whole mutation surface is owner-qualified and its ledger is crate-private, so no
/// caller outside this crate can reach an unfenced transition:
///
/// ```compile_fail
/// use gantry_runtime::AdmittedResource;
///
/// fn unfenced_finish(account: &mut AdmittedResource) {
///     account.begin_finish().ok();
/// }
/// ```
///
/// ```compile_fail
/// use gantry_runtime::AdmittedResource;
///
/// fn unfenced_finalization(account: &mut AdmittedResource) {
///     account.complete_finalization(0).ok();
/// }
/// ```
///
/// The raw ledger accessor does not exist outside this crate at all:
///
/// ```compile_fail
/// use gantry_runtime::AdmittedResource;
///
/// fn raw_ledger(account: &mut AdmittedResource) {
///     let _ = account.ledger_mut();
/// }
/// ```
#[derive(Debug, Eq, PartialEq)]
pub struct AdmittedResource {
    ledger: ResourceLedger,
    subject: ResourceSubjectBinding,
    containment: ContainmentSettlement,
    adapter: Option<AdapterInstance>,
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
        let ledger = ResourceLedger::reconstruct(record);
        let containment = ContainmentSettlement::open(ledger.owner());
        Ok(Self {
            ledger,
            subject,
            containment,
            adapter: None,
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

    /// Returns the Section 23 containment settlement of this operation.
    ///
    /// The settlement is opened under the owner generation the reconstruction record names, so the
    /// operation it owns is the same operation this account value was admitted under, and it holds
    /// that value's single settled outcome and refined effect state.
    #[must_use]
    pub const fn containment(&self) -> &ContainmentSettlement {
        &self.containment
    }

    /// Settles this operation's containment path from one completion a boundary observed.
    ///
    /// The model's own settlement decides in its declared order: a completion that declares no
    /// outcome or more than one outcome is refused first as `MalformedCompletion`, then a completion
    /// presented to an already-settled operation as `SecondSettlement`, then a completion naming a
    /// generation the operation does not hold as `StaleGeneration`, then the held effect state is
    /// refined, and only then is a definite accepted outcome over an ambiguous effect refused as
    /// `AmbiguousOutcomeRefused`. This route delegates rather than restating those decisions, so it
    /// adds no fence that could reorder them, and no refusal writes the owner generation, the held
    /// effect state, or the settled outcome.
    pub fn settle_containment(
        &mut self,
        presented_owner: OwnerGeneration,
        completion: Completion,
    ) -> Result<ExternalOutcome, ContainmentError> {
        self.containment.settle(presented_owner, completion)
    }

    /// Returns the adapter instance bound to this account, when one is bound.
    #[must_use]
    pub const fn adapter_instance(&self) -> Option<&AdapterInstance> {
        self.adapter.as_ref()
    }

    /// Binds or replaces this account's adapter instance under one presented owner generation.
    ///
    /// A first binding is stored as it is presented. A replacement is decided by the model's own
    /// substitution rule of the binding this account already holds, so the model refuses a poisoned
    /// binding, a retired binding, a replacement that widens the rights held, and a replacement whose
    /// owner generation does not succeed the held one, each with its own reason and without replacing
    /// anything. The presented owner generation must be this account's current one, so a superseded
    /// owner can neither bind nor replace the adapter of an operation it does not hold.
    pub fn bind_adapter_instance(
        &mut self,
        presented_owner: OwnerGeneration,
        instance: AdapterInstance,
    ) -> Result<(), AdapterBindingRefusal> {
        self.require_current_owner(presented_owner)
            .map_err(AdapterBindingRefusal::StaleOwner)?;
        match &self.adapter {
            Some(held) => {
                let replacement = held
                    .substitute(
                        instance.implementation(),
                        instance.rights(),
                        instance.generation(),
                        instance.binding_sequence(),
                    )
                    .map_err(AdapterBindingRefusal::Substitution)?;
                self.adapter = Some(replacement);
            }
            None => self.adapter = Some(instance),
        }
        Ok(())
    }

    /// Poisons this account's bound adapter instance through one model reason ledger.
    fn poison_adapter_instance(
        &mut self,
        presented_owner: OwnerGeneration,
        reason: PoisonReason,
        ledger: &mut PoisonLedger,
    ) -> Result<PoisonReason, AdapterBindingRefusal> {
        self.require_current_owner(presented_owner)
            .map_err(AdapterBindingRefusal::StaleOwner)?;
        let instance = self
            .adapter
            .as_mut()
            .ok_or(AdapterBindingRefusal::Unbound)?;
        Ok(ledger.poison(instance, reason))
    }

    /// Advances to finishing from the only ordinary active state.
    ///
    /// The model's two-phase lifetime of
    /// `GNT-28.4-resource-lifetime-finish-poison-and-emergency-release` is entered here rather than by a
    /// caller reaching into the ledger: any other lifetime is refused by the model's own transition
    /// rule, no quota fact changes, and a finishing account keeps its live place because `Finishing` is
    /// live.
    pub(crate) fn begin_finish(&mut self) -> Result<ResourceLifetimeState, ResourceError> {
        self.ledger.begin_finish()?;
        Ok(self.ledger.lifetime())
    }

    /// Records that finalization of one admitted resource completed.
    ///
    /// The resource must already be finishing: the model's two-phase lifetime of
    /// `GNT-28.4-resource-lifetime-finish-poison-and-emergency-release` is entered through the
    /// ledger and this step records the completion at one declared logical instant. Any other
    /// lifetime is refused by the model's own transition rule, no quota fact changes, and the
    /// retained settlement baseline names the current owner.
    pub(crate) fn complete_finalization(
        &mut self,
        settled_at: u64,
    ) -> Result<ResourceLifetimeState, ResourceError> {
        self.ledger.finish(settled_at)?;
        Ok(self.ledger.lifetime())
    }

    /// Advances to finishing for one presented owner generation.
    ///
    /// The presented generation must be this account's current one: any other is refused with the
    /// model's own `ResourceError::StaleOwner` before any lifetime fact changes, so a superseded owner
    /// generation can never enter the finish path.
    pub fn begin_finish_for(
        &mut self,
        presented_owner: OwnerGeneration,
    ) -> Result<ResourceLifetimeState, ResourceError> {
        self.require_current_owner(presented_owner)?;
        self.begin_finish()
    }

    /// Completes finalization for one presented owner generation.
    ///
    /// The presented generation must be this account's current one, exactly as
    /// [`Self::begin_finish_for`] requires: any other is refused with the model's own
    /// `ResourceError::StaleOwner` before any lifetime fact changes.
    pub fn complete_finalization_for(
        &mut self,
        presented_owner: OwnerGeneration,
        settled_at: u64,
    ) -> Result<ResourceLifetimeState, ResourceError> {
        self.require_current_owner(presented_owner)?;
        self.complete_finalization(settled_at)
    }

    /// Refuses a presented owner generation that is not this account's current one.
    fn require_current_owner(&self, presented_owner: OwnerGeneration) -> Result<(), ResourceError> {
        let current = self.ledger.owner();
        if presented_owner != current {
            return Err(ResourceError::StaleOwner {
                presented: presented_owner,
                current,
            });
        }
        Ok(())
    }

    /// Charges this account's declared quotas for one presented action.
    ///
    /// Every decision is the model's own: a stale presented owner, an undeclared owner-and-family
    /// key, an exhausted ceiling, an overflowing member, and a lifetime that admits no charge are each
    /// refused with the model's reason, and a refused vector commits nothing.
    pub fn charge(
        &mut self,
        presented_owner: OwnerGeneration,
        action: ResourceAction,
        charges: &[Charge],
    ) -> Result<(), ResourceError> {
        self.ledger.charge(presented_owner, action, charges)
    }

    /// Renews exactly one declared quota of this account for one presented owner generation.
    ///
    /// The model's own renewal rule decides the presented owner, the declared key, the remaining
    /// allowance, the ceiling overflow, and the charging lifetime, and a refused renewal changes
    /// nothing.
    pub fn renew(
        &mut self,
        presented_owner: OwnerGeneration,
        owner: QuotaOwner,
        family: QuotaFamily,
        increase: u64,
    ) -> Result<(), ResourceError> {
        self.ledger.renew(presented_owner, owner, family, increase)
    }

    /// Closes one declared liveness root for one presented owner generation.
    ///
    /// The model's root closure takes no owner generation, so the runtime requires one here: any
    /// other generation than this account's current one is refused with the model's own
    /// `ResourceError::StaleOwner` before any root fact changes.
    pub fn close_liveness_root_for(
        &mut self,
        presented_owner: OwnerGeneration,
        root: LivenessRoot,
    ) -> Result<(), ResourceError> {
        self.require_current_owner(presented_owner)?;
        self.ledger.close_liveness_root(root)
    }

    /// Retires this account under its declared retention fence.
    ///
    /// The model's own retirement rule already requires the presented owner generation to be the
    /// current one and refuses a still-live root, an unexpired fence, and an invalid successor with
    /// its own reasons, so this route delegates rather than restating them.
    pub fn retire(
        &mut self,
        fence: RetentionFence,
        presented_owner: OwnerGeneration,
        succeeding_owner: OwnerGeneration,
        at: u64,
    ) -> Result<(), ResourceError> {
        self.ledger
            .retire(fence, presented_owner, succeeding_owner, at)
    }

    /// Deletes an already-retired record for one presented owner generation.
    ///
    /// The model's deletion takes no owner generation, so the runtime requires this account's current
    /// one: any other is refused with the model's own `ResourceError::StaleOwner` before the record
    /// changes.
    pub fn delete_for(
        &mut self,
        presented_owner: OwnerGeneration,
    ) -> Result<ResourceLifetimeState, ResourceError> {
        self.require_current_owner(presented_owner)?;
        self.ledger.delete()?;
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
