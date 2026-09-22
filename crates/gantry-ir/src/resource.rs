//! Pure resource-accounting model for `SPEC.md` Section 28.
//!
//! This module records declared logical charges and resource-lifetime facts only. It
//! is not a runtime resource registry, an evaluator, a journal schema, or a host
//! interface. Every transition is a deterministic function of explicit inputs. The
//! landed [`OwnerGeneration`] fences stale owners, [`ResourceState`] remains the
//! state of a Section 20 *operation*, and [`ResourceLifetimeState`] below is the
//! distinct whole-resource lifetime state required by this section.

use std::collections::{BTreeMap, BTreeSet};

use crate::lifecycle::EmergencyCleanupWitness;
use crate::operation::{OwnerGeneration, PostFailureSettlement, ResourceState};

/// The Section 28 clauses implemented by this pure model, in declaration order.
pub const RESOURCE_CLAUSES: [&str; 11] = [
    "GNT-28.0-resource-accounting-and-lifetime-contract",
    "GNT-28.1-resource-identity-and-closed-liveness-roots",
    "GNT-28.2-logical-measures-and-representation-equivalence",
    "GNT-28.3-atomic-copy-move-loan-update-and-release-charging",
    "GNT-28.4-resource-lifetime-finish-poison-and-emergency-release",
    "GNT-28.5-closed-quota-families-and-owners",
    "GNT-28.6-bounded-renewal-and-exhaustion",
    "GNT-28.7-durable-resource-reconstruction",
    "GNT-28.8-retention-and-compaction-fences",
    "GNT-28.9-retirement-deletion-and-stale-owner-fences",
    "GNT-28.10-resource-accounting-non-claims",
];

/// A closed root that keeps one resource live.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum LivenessRoot {
    /// The resource's own retained lifetime record.
    Resource,
    /// The current owner generation.
    Owner,
    /// One sealed Section 20 receiver loan.
    Loan,
    /// A durable reconstruction record.
    DurableRecord,
}

impl LivenessRoot {
    /// Every root in exact wire-name order.
    pub const ALL: [Self; 4] = [Self::DurableRecord, Self::Loan, Self::Owner, Self::Resource];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Resource => "resource",
            Self::Owner => "owner",
            Self::Loan => "loan",
            Self::DurableRecord => "durable-record",
        }
    }

    /// Strictly decodes one portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|root| root.wire_name() == value)
    }
}

/// One closed logical measure. Physical representation is never a measure.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum LogicalMeasure {
    /// Canonical logical bytes.
    Bytes,
    /// Independently accountable live handles.
    Handles,
    /// Accountable operations.
    Operations,
}

impl LogicalMeasure {
    /// Every measure in exact wire-name order.
    pub const ALL: [Self; 3] = [Self::Bytes, Self::Handles, Self::Operations];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Bytes => "bytes",
            Self::Handles => "handles",
            Self::Operations => "operations",
        }
    }

    /// Strictly decodes one portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|measure| measure.wire_name() == value)
    }
}

/// A closed family of quota, deliberately one-to-one with its logical measure.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum QuotaFamily {
    /// Byte accounting.
    Bytes,
    /// Handle accounting.
    Handles,
    /// Operation accounting.
    Operations,
}

impl QuotaFamily {
    /// Every family in exact wire-name order.
    pub const ALL: [Self; 3] = [Self::Bytes, Self::Handles, Self::Operations];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Bytes => "bytes",
            Self::Handles => "handles",
            Self::Operations => "operations",
        }
    }

    /// Returns the measure this family accounts for.
    #[must_use]
    pub const fn measure(self) -> LogicalMeasure {
        match self {
            Self::Bytes => LogicalMeasure::Bytes,
            Self::Handles => LogicalMeasure::Handles,
            Self::Operations => LogicalMeasure::Operations,
        }
    }
}

/// A closed owner family for quota accounting.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum QuotaOwner {
    /// The resource itself owns the quota.
    Resource,
    /// The current resource owner owns the quota.
    Owner,
    /// The durable record owns the retained quota witness.
    DurableRecord,
}

impl QuotaOwner {
    /// Every owner family in exact wire-name order.
    pub const ALL: [Self; 3] = [Self::DurableRecord, Self::Owner, Self::Resource];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Resource => "resource",
            Self::Owner => "owner",
            Self::DurableRecord => "durable-record",
        }
    }
}

/// An action whose accounting must commit atomically.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ResourceAction {
    /// Account an independent logical copy.
    Copy,
    /// Account a logical move.
    Move,
    /// Account a receiver loan.
    Loan,
    /// Account a resource update.
    Update,
    /// Account an explicit release.
    Release,
}

impl ResourceAction {
    /// Every action in exact wire-name order.
    pub const ALL: [Self; 5] = [
        Self::Copy,
        Self::Loan,
        Self::Move,
        Self::Release,
        Self::Update,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Copy => "copy",
            Self::Move => "move",
            Self::Loan => "loan",
            Self::Update => "update",
            Self::Release => "release",
        }
    }
}

/// The state of a whole resource, not [`ResourceState`] of one operation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ResourceLifetimeState {
    /// The resource admits declared charges.
    Active,
    /// Finishing has started; only finalization remains.
    Finishing,
    /// The resource finished normally.
    Finished,
    /// An invariant failure poisoned the resource.
    Poisoned,
    /// Sealed emergency cleanup released the resource.
    EmergencyReleased,
    /// Retention has ended and stale owners are fenced.
    Retired,
    /// The retired record was deleted after its fence.
    Deleted,
}

impl ResourceLifetimeState {
    /// Returns whether ordinary accounting is still admitted.
    #[must_use]
    pub const fn admits_charge(self) -> bool {
        matches!(self, Self::Active)
    }

    /// Returns whether the lifetime has reached one settled terminal result.
    #[must_use]
    pub const fn is_settled(self) -> bool {
        matches!(
            self,
            Self::Finished | Self::Poisoned | Self::EmergencyReleased
        )
    }
}

/// One bounded quota declaration and its current declared use.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Quota {
    limit: u64,
    used: u64,
    remaining_renewals: u64,
}

impl Quota {
    /// Declares one finite quota and its finite number of renewals.
    #[must_use]
    pub const fn new(limit: u64, remaining_renewals: u64) -> Self {
        Self {
            limit,
            used: 0,
            remaining_renewals,
        }
    }

    /// Returns the declared ceiling.
    #[must_use]
    pub const fn limit(self) -> u64 {
        self.limit
    }

    /// Returns the committed logical use.
    #[must_use]
    pub const fn used(self) -> u64 {
        self.used
    }

    /// Returns the number of bounded renewals still admitted.
    #[must_use]
    pub const fn remaining_renewals(self) -> u64 {
        self.remaining_renewals
    }
}

/// A declared charge against one owner-family and quota-family pair.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Charge {
    /// The quota owner.
    pub owner: QuotaOwner,
    /// The quota family.
    pub family: QuotaFamily,
    /// The logical quantity, never a physical representation size.
    pub amount: u64,
}

/// A sealed proof that a Section 20 failure settled the resource as poisoned.
///
/// The private field prevents callers from manufacturing a terminal resource result:
/// this witness is obtainable only by validating a model-issued post-failure
/// settlement whose derived state is [`ResourceState::Poisoned`].
#[derive(Debug)]
pub struct PoisonWitness {
    settled_at: u64,
}

impl PoisonWitness {
    /// Derives a poisoning witness from one model-issued post-failure settlement.
    pub fn from_post_failure(
        settlement: &PostFailureSettlement,
        settled_at: u64,
    ) -> Result<Self, ResourceError> {
        if settlement.state() != ResourceState::Poisoned {
            return Err(ResourceError::FailureDoesNotPoisonResource);
        }
        Ok(Self { settled_at })
    }

    /// Returns the declared logical instant at which the resource lifetime settles.
    #[must_use]
    pub const fn settled_at(&self) -> u64 {
        self.settled_at
    }
}

/// A sealed proof that Section 22 admitted emergency-release cleanup after hard cancellation.
///
/// The wrapped cancellation-model witness has no public constructor, so consuming this
/// proof cannot manufacture emergency release from an arbitrary logical instant.
#[derive(Debug)]
pub struct EmergencyReleaseWitness {
    settled_at: u64,
}

impl EmergencyReleaseWitness {
    /// Derives sealed emergency-release authority from admitted hard-cancellation cleanup.
    #[must_use]
    pub const fn from_cleanup(cleanup: EmergencyCleanupWitness) -> Self {
        Self {
            settled_at: cleanup.at_us(),
        }
    }

    /// Returns the hard-cancellation linearization instant.
    #[must_use]
    pub const fn settled_at(&self) -> u64 {
        self.settled_at
    }
}

/// A durable reconstruction witness of resource accounting facts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableResourceRecord {
    owner: OwnerGeneration,
    lifetime: ResourceLifetimeState,
    operation_state: ResourceState,
    quotas: BTreeMap<(QuotaOwner, QuotaFamily), Quota>,
    liveness_roots: BTreeSet<LivenessRoot>,
    settlement: Option<SettlementBaseline>,
    successor_fence: Option<OwnerGeneration>,
}

impl DurableResourceRecord {
    /// Replaces the retained roots for a candidate compaction record.
    ///
    /// The record is only a candidate until [`ResourceLedger::validate_compaction`]
    /// establishes that it retains every required root and every other model fact.
    #[must_use]
    pub fn with_liveness_roots(mut self, roots: &[LivenessRoot]) -> Self {
        self.liveness_roots = roots.iter().copied().collect();
        self
    }
}

/// One declared carrier that may hold a resource's accounting facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceCarrier {
    /// Ordinary serialization of source or application values.
    OrdinarySerialization,
    /// Ordinary durable state, which carries no reconstruction contract.
    OrdinaryDurableState,
    /// The declared durable reconstruction record of `GNT-28.7-durable-resource-reconstruction`.
    ReconstructionRecord,
}

impl ResourceCarrier {
    /// The closed declared set, in canonical wire-name order.
    pub const ALL: [ResourceCarrier; 3] = [
        Self::OrdinaryDurableState,
        Self::OrdinarySerialization,
        Self::ReconstructionRecord,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::OrdinarySerialization => "ordinary-serialization",
            Self::OrdinaryDurableState => "ordinary-durable-state",
            Self::ReconstructionRecord => "reconstruction-record",
        }
    }

    /// Returns whether this carrier may hold a resource's facts.
    #[must_use]
    pub const fn carries_resources(self) -> bool {
        matches!(self, Self::ReconstructionRecord)
    }
}

/// Admits one declared carrier for a resource's accounting facts, or refuses it.
///
/// A resource's facts are carried only by the declared reconstruction record of
/// `GNT-28.7-durable-resource-reconstruction`: ordinary serialization and ordinary durable state
/// carry no owner generation, lifetime, quota, or root witness, so a resource admitted through
/// them would have no owner and no terminal disposition. The refusal grants nothing and admits no
/// second carrier.
pub fn admit_resource_carrier(carrier: ResourceCarrier) -> Result<(), ResourceError> {
    if carrier.carries_resources() {
        return Ok(());
    }
    Err(ResourceError::OrdinaryCarrierRefused)
}

/// The explicit retained baseline from which a terminal lifetime may retire.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SettlementBaseline {
    owner: OwnerGeneration,
    settled_at: u64,
}

impl SettlementBaseline {
    /// Returns the current owner that settled the resource.
    #[must_use]
    pub const fn owner(self) -> OwnerGeneration {
        self.owner
    }

    /// Returns the declared logical instant at which settlement occurred.
    #[must_use]
    pub const fn settled_at(self) -> u64 {
        self.settled_at
    }
}

/// Retention bounds, expressed only in owner generations and logical instants.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetentionFence {
    owner_generations: u64,
    logical_instants: u64,
}

impl RetentionFence {
    /// Declares finite retention bounds; both zero is refused as unbounded retention.
    pub fn new(owner_generations: u64, logical_instants: u64) -> Result<Self, ResourceError> {
        if owner_generations == 0 && logical_instants == 0 {
            return Err(ResourceError::UnboundedRetention);
        }
        Ok(Self {
            owner_generations,
            logical_instants,
        })
    }

    /// Returns whether the owner and logical-instant fence has expired.
    #[must_use]
    pub const fn expired(
        self,
        settled_owner: OwnerGeneration,
        presented_owner: OwnerGeneration,
        settled_at: u64,
        at: u64,
    ) -> bool {
        presented_owner
            .value()
            .saturating_sub(settled_owner.value())
            > self.owner_generations
            || at.saturating_sub(settled_at) > self.logical_instants
    }
}

/// A pure whole-resource accounting ledger.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceLedger {
    owner: OwnerGeneration,
    lifetime: ResourceLifetimeState,
    operation_state: ResourceState,
    quotas: BTreeMap<(QuotaOwner, QuotaFamily), Quota>,
    liveness_roots: BTreeSet<LivenessRoot>,
    settlement: Option<SettlementBaseline>,
    successor_fence: Option<OwnerGeneration>,
}

impl ResourceLedger {
    /// Constructs a ledger from explicit quota declarations.
    ///
    /// Duplicate owner/family pairs are refused rather than selected by input order.
    pub fn new(
        owner: OwnerGeneration,
        operation_state: ResourceState,
        liveness_roots: &[LivenessRoot],
        quotas: &[(QuotaOwner, QuotaFamily, Quota)],
    ) -> Result<Self, ResourceError> {
        let mut declared = BTreeMap::new();
        for (quota_owner, family, quota) in quotas {
            if declared.insert((*quota_owner, *family), *quota).is_some() {
                return Err(ResourceError::DuplicateQuota);
            }
        }
        let roots = liveness_roots.iter().copied().collect::<BTreeSet<_>>();
        if roots.is_empty() {
            return Err(ResourceError::MissingLivenessRoot);
        }
        Ok(Self {
            owner,
            lifetime: ResourceLifetimeState::Active,
            operation_state,
            quotas: declared,
            liveness_roots: roots,
            settlement: None,
            successor_fence: None,
        })
    }

    /// Returns the current owner generation.
    #[must_use]
    pub const fn owner(&self) -> OwnerGeneration {
        self.owner
    }

    /// Returns the whole-resource lifetime state.
    #[must_use]
    pub const fn lifetime(&self) -> ResourceLifetimeState {
        self.lifetime
    }

    /// Returns the distinct landed operation resource state.
    #[must_use]
    pub const fn operation_state(&self) -> ResourceState {
        self.operation_state
    }

    /// Returns the exact closed roots currently retained for this resource.
    #[must_use]
    pub fn liveness_roots(&self) -> &BTreeSet<LivenessRoot> {
        &self.liveness_roots
    }

    /// Closes one retained liveness root before retention may end.
    ///
    /// The root vocabulary is closed by [`LivenessRoot`]. Closing a root does not
    /// transfer ownership or discover runtime reachability; it records only that
    /// this pure ledger no longer retains that declared root.
    pub fn close_liveness_root(&mut self, root: LivenessRoot) -> Result<(), ResourceError> {
        if !self.liveness_roots.remove(&root) {
            return Err(ResourceError::LivenessRootNotLive);
        }
        Ok(())
    }

    /// Returns the retained terminal settlement baseline, if the lifetime settled.
    #[must_use]
    pub const fn settlement(&self) -> Option<SettlementBaseline> {
        self.settlement
    }

    /// Returns the successor generation stored by retirement, if any.
    #[must_use]
    pub const fn successor_fence(&self) -> Option<OwnerGeneration> {
        self.successor_fence
    }

    /// Returns a declared quota by its closed owner/family key.
    #[must_use]
    pub fn quota(&self, owner: QuotaOwner, family: QuotaFamily) -> Option<Quota> {
        self.quotas.get(&(owner, family)).copied()
    }

    /// Charges every declared member atomically for one action.
    ///
    /// The action name is retained as an explicit input because copy, move, loan,
    /// update, and release are distinct source obligations even when their logical
    /// charge vector is equal. No partial vector is committed after overflow or
    /// exhaustion.
    pub fn charge(
        &mut self,
        presented_owner: OwnerGeneration,
        _action: ResourceAction,
        charges: &[Charge],
    ) -> Result<(), ResourceError> {
        if !self.lifetime.admits_charge() {
            return Err(ResourceError::LifetimeDoesNotAdmitCharge {
                state: self.lifetime,
            });
        }
        self.require_current_owner(presented_owner)?;
        let mut next = self.quotas.clone();
        for charge in charges {
            let quota = next
                .get_mut(&(charge.owner, charge.family))
                .ok_or(ResourceError::UndeclaredQuota)?;
            let used = quota
                .used
                .checked_add(charge.amount)
                .ok_or(ResourceError::ChargeOverflow)?;
            if used > quota.limit {
                return Err(ResourceError::QuotaExhausted);
            }
            quota.used = used;
        }
        self.quotas = next;
        Ok(())
    }

    /// Renews exactly one quota through the current owner generation.
    pub fn renew(
        &mut self,
        presented_owner: OwnerGeneration,
        owner: QuotaOwner,
        family: QuotaFamily,
        increase: u64,
    ) -> Result<(), ResourceError> {
        if !self.lifetime.admits_charge() {
            return Err(ResourceError::LifetimeDoesNotAdmitCharge {
                state: self.lifetime,
            });
        }
        self.require_current_owner(presented_owner)?;
        let quota = self
            .quotas
            .get_mut(&(owner, family))
            .ok_or(ResourceError::UndeclaredQuota)?;
        if quota.remaining_renewals == 0 {
            return Err(ResourceError::RenewalExhausted);
        }
        quota.limit = quota
            .limit
            .checked_add(increase)
            .ok_or(ResourceError::RenewalOverflow)?;
        quota.remaining_renewals -= 1;
        Ok(())
    }

    /// Advances to finishing from the only ordinary active state.
    pub fn begin_finish(&mut self) -> Result<(), ResourceError> {
        if self.lifetime != ResourceLifetimeState::Active {
            return Err(ResourceError::IllegalLifetimeTransition);
        }
        self.lifetime = ResourceLifetimeState::Finishing;
        Ok(())
    }

    /// Completes finishing at one declared logical instant without changing Section 20 state.
    pub fn finish(&mut self, settled_at: u64) -> Result<(), ResourceError> {
        if self.lifetime != ResourceLifetimeState::Finishing {
            return Err(ResourceError::IllegalLifetimeTransition);
        }
        self.lifetime = ResourceLifetimeState::Finished;
        self.settlement = Some(SettlementBaseline {
            owner: self.owner,
            settled_at,
        });
        Ok(())
    }

    /// Poisons an eligible lifetime from a model-derived failure witness.
    pub fn poison(&mut self, witness: PoisonWitness) -> Result<(), ResourceError> {
        if !matches!(
            self.lifetime,
            ResourceLifetimeState::Active | ResourceLifetimeState::Finishing
        ) {
            return Err(ResourceError::IllegalLifetimeTransition);
        }
        self.lifetime = ResourceLifetimeState::Poisoned;
        self.settlement = Some(SettlementBaseline {
            owner: self.owner,
            settled_at: witness.settled_at(),
        });
        Ok(())
    }

    /// Applies sealed emergency cleanup proved by hard-cancellation evidence.
    pub fn emergency_release(
        &mut self,
        witness: EmergencyReleaseWitness,
    ) -> Result<(), ResourceError> {
        if !matches!(
            self.lifetime,
            ResourceLifetimeState::Active | ResourceLifetimeState::Finishing
        ) {
            return Err(ResourceError::IllegalLifetimeTransition);
        }
        self.lifetime = ResourceLifetimeState::EmergencyReleased;
        self.settlement = Some(SettlementBaseline {
            owner: self.owner,
            settled_at: witness.settled_at(),
        });
        Ok(())
    }

    /// Captures only declared facts needed for deterministic durable reconstruction.
    #[must_use]
    pub fn durable_record(&self) -> DurableResourceRecord {
        DurableResourceRecord {
            owner: self.owner,
            lifetime: self.lifetime,
            operation_state: self.operation_state,
            quotas: self.quotas.clone(),
            liveness_roots: self.liveness_roots.clone(),
            settlement: self.settlement,
            successor_fence: self.successor_fence,
        }
    }

    /// Reconstructs the exact ledger from its declared durable record.
    #[must_use]
    pub fn reconstruct(record: DurableResourceRecord) -> Self {
        Self {
            owner: record.owner,
            lifetime: record.lifetime,
            operation_state: record.operation_state,
            quotas: record.quotas,
            liveness_roots: record.liveness_roots,
            settlement: record.settlement,
            successor_fence: record.successor_fence,
        }
    }

    /// Validates that a compacted record preserves every retained pure-model fact.
    pub fn validate_compaction(
        &self,
        compacted: &DurableResourceRecord,
    ) -> Result<(), ResourceError> {
        if compacted != &self.durable_record() {
            return Err(ResourceError::CompactionDoesNotPreserve);
        }
        Ok(())
    }

    /// Retires after its explicit retention fence has expired.
    pub fn retire(
        &mut self,
        fence: RetentionFence,
        presented_owner: OwnerGeneration,
        succeeding_owner: OwnerGeneration,
        at: u64,
    ) -> Result<(), ResourceError> {
        if !self.lifetime.is_settled() {
            return Err(ResourceError::IllegalLifetimeTransition);
        }
        self.require_current_owner(presented_owner)?;
        if !self.liveness_roots.is_empty() {
            return Err(ResourceError::LivenessRootsRemain);
        }
        if !succeeding_owner.succeeds(self.owner) {
            return Err(ResourceError::InvalidSuccessorGeneration);
        }
        let settlement = self
            .settlement
            .ok_or(ResourceError::IllegalLifetimeTransition)?;
        if !fence.expired(
            settlement.owner,
            succeeding_owner,
            settlement.settled_at,
            at,
        ) {
            return Err(ResourceError::RetentionNotExpired);
        }
        self.lifetime = ResourceLifetimeState::Retired;
        self.successor_fence = Some(succeeding_owner);
        Ok(())
    }

    /// Deletes only an already-retired resource record.
    pub fn delete(&mut self) -> Result<(), ResourceError> {
        if self.lifetime != ResourceLifetimeState::Retired {
            return Err(ResourceError::IllegalLifetimeTransition);
        }
        if !self.liveness_roots.is_empty() {
            return Err(ResourceError::LivenessRootsRemain);
        }
        self.lifetime = ResourceLifetimeState::Deleted;
        Ok(())
    }

    /// Refuses a stale owner before an owner-authorized model change commits.
    fn require_current_owner(&self, presented_owner: OwnerGeneration) -> Result<(), ResourceError> {
        if presented_owner != self.owner {
            return Err(ResourceError::StaleOwner {
                presented: presented_owner,
                current: self.owner,
            });
        }
        Ok(())
    }
}

/// The closed refusal set of the resource-accounting model.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceError {
    /// A resource declared no liveness root from the closed vocabulary.
    MissingLivenessRoot,
    /// A requested root closure named no currently live declared root.
    LivenessRootNotLive,
    /// Retirement or deletion would discard one or more still-live declared roots.
    LivenessRootsRemain,
    /// A quota key was declared twice.
    DuplicateQuota,
    /// A charge refers to no declared quota.
    UndeclaredQuota,
    /// A charge would exceed a declared finite quota.
    QuotaExhausted,
    /// A charge counter would wrap.
    ChargeOverflow,
    /// A renewal counter has no remaining admission.
    RenewalExhausted,
    /// A renewal ceiling would wrap.
    RenewalOverflow,
    /// The caller's owner generation is stale.
    StaleOwner {
        /// The owner generation the caller presented.
        presented: OwnerGeneration,
        /// The ledger's current owner generation.
        current: OwnerGeneration,
    },
    /// The current lifetime state admits no ordinary charge.
    LifetimeDoesNotAdmitCharge {
        /// The whole-resource lifetime state that refused the charge.
        state: ResourceLifetimeState,
    },
    /// The requested whole-resource state change is not permitted.
    IllegalLifetimeTransition,
    /// A retention declaration would be unbounded.
    UnboundedRetention,
    /// The retirement fence has not expired.
    RetentionNotExpired,
    /// Retirement did not name a generation later than the settling owner.
    InvalidSuccessorGeneration,
    /// A compaction candidate changed a retained pure-model fact.
    CompactionDoesNotPreserve,
    /// A presented failure settlement does not derive a poisoned resource state.
    FailureDoesNotPoisonResource,
    /// An ordinary serialization or ordinary durable-state carrier was asked to carry a resource.
    OrdinaryCarrierRefused,
}
