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
use std::sync::{Arc, Mutex, MutexGuard};

use gantry_core::strict_json::{JsonLimits, JsonNode, JsonNodeId, StrictJsonDocument};
use gantry_ir::{
    AdapterInstance, CanonicalPath, Charge, Completion, ContainmentError, ContainmentSettlement,
    DurableResourceRecord, EmergencyCleanupWitness, EmergencyReleaseWitness, ExecutableOperation,
    ExternalOutcome, LivenessRoot, LogicalOperationId, OperationAbiError, OperationKind,
    OwnerGeneration, PoisonLedger, PoisonReason, PoisonWitness, PostFailureSettlement, Quota,
    QuotaFamily, QuotaOwner, ResourceAction, ResourceCarrier, ResourceError, ResourceGenerationId,
    ResourceLedger, ResourceLifetimeState, ResourceState, RetentionFence, SettlementBaseline,
    StaticSiteId, StructuralPosition, admit_resource_carrier,
};

/// Decodes one exact canonical declared resource reconstruction record.
///
/// The returned facts are still subject-free: callers must derive the subject from retained
/// executable/checkpoint metadata and present this record only through
/// [`ResourceCarrier::ReconstructionRecord`].
/// The closed v1 schema admits at most nine quota pairs and four roots. Fixed parser
/// budgets cover every canonical record and refuse oversized input before copying it.
pub fn decode_resource_reconstruction_record(
    bytes: &[u8],
) -> Result<DurableResourceRecord, ResourceRecordCodecError> {
    // Nine quota objects with five fields each, four roots, u64 decimal strings,
    // and optional settlement/fence facts fit comfortably within these v1 bounds.
    const MAXIMUM_BYTES: usize = 4096;
    if bytes.len() > MAXIMUM_BYTES {
        return Err(ResourceRecordCodecError::Encoding);
    }
    let document = StrictJsonDocument::decode(
        bytes,
        JsonLimits {
            maximum_bytes: MAXIMUM_BYTES as u64,
            maximum_nesting_depth: 5,
            maximum_nodes: 128,
            maximum_string_scalars: 64,
            maximum_list_items: 9,
        },
    )
    .map_err(|_| ResourceRecordCodecError::Encoding)?;
    let root = codec_object(&document, document.root())?;
    codec_require_fields(root, &["format", "record"])?;
    if codec_string(&document, codec_field(root, "format")?)? != "gantry.resource-reconstruction/v1"
    {
        return Err(ResourceRecordCodecError::Encoding);
    }
    let value = codec_object(&document, codec_field(root, "record")?)?;
    codec_require_fields(
        value,
        &[
            "lifetime",
            "liveness_roots",
            "operation_state",
            "owner",
            "quotas",
            "settlement",
            "successor_fence",
        ],
    )?;
    let owner = OwnerGeneration::new(codec_unsigned(&document, codec_field(value, "owner")?)?);
    let lifetime = ResourceLifetimeState::from_wire_name(codec_string(
        &document,
        codec_field(value, "lifetime")?,
    )?)
    .ok_or(ResourceRecordCodecError::Encoding)?;
    let operation_state = ResourceState::from_wire_name(codec_string(
        &document,
        codec_field(value, "operation_state")?,
    )?)
    .ok_or(ResourceRecordCodecError::Encoding)?;
    let quotas = codec_quotas(&document, codec_field(value, "quotas")?)?;
    let liveness_roots = codec_roots(&document, codec_field(value, "liveness_roots")?)?;
    let settlement = codec_settlement(&document, codec_field(value, "settlement")?)?;
    let successor_fence = codec_optional_owner(&document, codec_field(value, "successor_fence")?)?;
    let record = DurableResourceRecord::from_durable_facts(
        owner,
        lifetime,
        operation_state,
        quotas,
        liveness_roots,
        settlement,
        successor_fence,
    )
    .map_err(ResourceRecordCodecError::Model)?;
    if encode_resource_reconstruction_record(&record) != bytes {
        return Err(ResourceRecordCodecError::Encoding);
    }
    Ok(record)
}

/// Encodes the model's declared resource facts in their canonical reconstruction-record form.
#[must_use]
pub fn encode_resource_reconstruction_record(record: &DurableResourceRecord) -> Vec<u8> {
    let mut output = String::from("{\"format\":\"gantry.resource-reconstruction/v1\",\"record\":{");
    codec_push_string_field(&mut output, "lifetime", record.lifetime().wire_name());
    output.push_str(",\"liveness_roots\":[");
    for (index, root) in record.liveness_roots().iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        codec_push_string(&mut output, root.wire_name());
    }
    output.push_str("],\"operation_state\":");
    codec_push_string(&mut output, record.operation_state().wire_name());
    output.push_str(",\"owner\":");
    codec_push_u64(&mut output, record.owner().value());
    output.push_str(",\"quotas\":[");
    for (index, ((owner, family), quota)) in record.quotas().iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        output.push_str("{\"family\":");
        codec_push_string(&mut output, family.wire_name());
        output.push_str(",\"limit\":");
        codec_push_u64(&mut output, quota.limit());
        output.push_str(",\"owner\":");
        codec_push_string(&mut output, owner.wire_name());
        output.push_str(",\"remaining_renewals\":");
        codec_push_u64(&mut output, quota.remaining_renewals());
        output.push_str(",\"used\":");
        codec_push_u64(&mut output, quota.used());
        output.push('}');
    }
    output.push_str("],\"settlement\":");
    match record.settlement() {
        Some(settlement) => {
            output.push_str("{\"owner\":");
            codec_push_u64(&mut output, settlement.owner().value());
            output.push_str(",\"settled_at\":");
            codec_push_u64(&mut output, settlement.settled_at());
            output.push('}');
        }
        None => output.push_str("null"),
    }
    output.push_str(",\"successor_fence\":");
    match record.successor_fence() {
        Some(successor) => codec_push_u64(&mut output, successor.value()),
        None => output.push_str("null"),
    }
    output.push_str("}}");
    output.into_bytes()
}

/// Failure to decode a canonical resource reconstruction record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceRecordCodecError {
    /// The bytes are malformed, noncanonical, or contain an unknown field or wire name.
    Encoding,
    /// The decoded facts do not describe a reachable resource record.
    Model(ResourceError),
}

fn codec_quotas(
    document: &StrictJsonDocument,
    id: JsonNodeId,
) -> Result<BTreeMap<(QuotaOwner, QuotaFamily), Quota>, ResourceRecordCodecError> {
    let Some(JsonNode::Array(items)) = document.node(id) else {
        return Err(ResourceRecordCodecError::Encoding);
    };
    let mut quotas = BTreeMap::new();
    for item in items {
        let value = codec_object(document, *item)?;
        codec_require_fields(
            value,
            &["family", "limit", "owner", "remaining_renewals", "used"],
        )?;
        let family =
            QuotaFamily::from_wire_name(codec_string(document, codec_field(value, "family")?)?)
                .ok_or(ResourceRecordCodecError::Encoding)?;
        let owner =
            QuotaOwner::from_wire_name(codec_string(document, codec_field(value, "owner")?)?)
                .ok_or(ResourceRecordCodecError::Encoding)?;
        let quota = Quota::from_durable_facts(
            codec_unsigned(document, codec_field(value, "limit")?)?,
            codec_unsigned(document, codec_field(value, "used")?)?,
            codec_unsigned(document, codec_field(value, "remaining_renewals")?)?,
        )
        .map_err(ResourceRecordCodecError::Model)?;
        if quotas.insert((owner, family), quota).is_some() {
            return Err(ResourceRecordCodecError::Model(
                ResourceError::DuplicateQuota,
            ));
        }
    }
    Ok(quotas)
}

fn codec_roots(
    document: &StrictJsonDocument,
    id: JsonNodeId,
) -> Result<std::collections::BTreeSet<LivenessRoot>, ResourceRecordCodecError> {
    let Some(JsonNode::Array(items)) = document.node(id) else {
        return Err(ResourceRecordCodecError::Encoding);
    };
    let mut roots = std::collections::BTreeSet::new();
    for item in items {
        let root = LivenessRoot::from_wire_name(codec_string(document, *item)?)
            .ok_or(ResourceRecordCodecError::Encoding)?;
        if !roots.insert(root) {
            return Err(ResourceRecordCodecError::Encoding);
        }
    }
    Ok(roots)
}

fn codec_settlement(
    document: &StrictJsonDocument,
    id: JsonNodeId,
) -> Result<Option<SettlementBaseline>, ResourceRecordCodecError> {
    if matches!(document.node(id), Some(JsonNode::Null)) {
        return Ok(None);
    }
    let value = codec_object(document, id)?;
    codec_require_fields(value, &["owner", "settled_at"])?;
    Ok(Some(SettlementBaseline::from_durable_facts(
        OwnerGeneration::new(codec_unsigned(document, codec_field(value, "owner")?)?),
        codec_unsigned(document, codec_field(value, "settled_at")?)?,
    )))
}

fn codec_optional_owner(
    document: &StrictJsonDocument,
    id: JsonNodeId,
) -> Result<Option<OwnerGeneration>, ResourceRecordCodecError> {
    if matches!(document.node(id), Some(JsonNode::Null)) {
        return Ok(None);
    }
    codec_unsigned(document, id)
        .map(OwnerGeneration::new)
        .map(Some)
}

fn codec_object(
    document: &StrictJsonDocument,
    id: JsonNodeId,
) -> Result<&[(Arc<str>, JsonNodeId)], ResourceRecordCodecError> {
    match document.node(id) {
        Some(JsonNode::Object(value)) => Ok(value),
        _ => Err(ResourceRecordCodecError::Encoding),
    }
}

fn codec_require_fields(
    object: &[(Arc<str>, JsonNodeId)],
    expected: &[&str],
) -> Result<(), ResourceRecordCodecError> {
    if object.len() == expected.len()
        && expected.iter().all(|name| {
            object
                .iter()
                .any(|(candidate, _)| candidate.as_ref() == *name)
        })
    {
        Ok(())
    } else {
        Err(ResourceRecordCodecError::Encoding)
    }
}

fn codec_field(
    object: &[(Arc<str>, JsonNodeId)],
    name: &str,
) -> Result<JsonNodeId, ResourceRecordCodecError> {
    object
        .iter()
        .find_map(|(candidate, value)| (candidate.as_ref() == name).then_some(*value))
        .ok_or(ResourceRecordCodecError::Encoding)
}

fn codec_string(
    document: &StrictJsonDocument,
    id: JsonNodeId,
) -> Result<&str, ResourceRecordCodecError> {
    match document.node(id) {
        Some(JsonNode::String(value)) => Ok(value),
        _ => Err(ResourceRecordCodecError::Encoding),
    }
}

fn codec_unsigned(
    document: &StrictJsonDocument,
    id: JsonNodeId,
) -> Result<u64, ResourceRecordCodecError> {
    match document.node(id) {
        Some(JsonNode::String(value))
            if !value.is_empty()
                && (value.as_ref() == "0"
                    || (!value.starts_with('0')
                        && value.bytes().all(|byte| byte.is_ascii_digit()))) =>
        {
            value
                .parse()
                .map_err(|_| ResourceRecordCodecError::Encoding)
        }
        _ => Err(ResourceRecordCodecError::Encoding),
    }
}

fn codec_push_u64(output: &mut String, value: u64) {
    codec_push_string(output, &value.to_string());
}

fn codec_push_string_field(output: &mut String, name: &str, value: &str) {
    output.push('"');
    output.push_str(name);
    output.push_str("\":");
    codec_push_string(output, value);
}

fn codec_push_string(output: &mut String, value: &str) {
    output.push('"');
    for scalar in value.chars() {
        match scalar {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{08}' => output.push_str("\\b"),
            '\u{09}' => output.push_str("\\t"),
            '\u{0a}' => output.push_str("\\n"),
            '\u{0c}' => output.push_str("\\f"),
            '\u{0d}' => output.push_str("\\r"),
            value if value <= '\u{1f}' => {
                output.push_str(&format!("\\u{:04x}", value as u32));
            }
            value => output.push(value),
        }
    }
    output.push('"');
}

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
#[derive(Clone, Debug)]
pub struct ResourceSubjectBinding {
    site: StaticSiteId,
    operation: LogicalOperationId,
    generation: ResourceGenerationId,
    kind: Option<OperationKind>,
    runtime_owner: (
        gantry_core::identity::ProtocolIdentity,
        gantry_core::identity::ProtocolIdentity,
    ),
    admission_open: Arc<Mutex<crate::machine::ResourceOperationLease>>,
}

impl PartialEq for ResourceSubjectBinding {
    fn eq(&self, other: &Self) -> bool {
        self.site == other.site
            && self.operation == other.operation
            && self.generation == other.generation
            && self.kind == other.kind
            && self.runtime_owner == other.runtime_owner
    }
}

impl Eq for ResourceSubjectBinding {}

impl ResourceSubjectBinding {
    /// Derives the binding of one declared operation site and one runtime generation.
    #[must_use]
    pub(crate) fn derive(
        declaration: &CanonicalPath,
        workflow: CanonicalPath,
        position: StructuralPosition,
        generation: u64,
        kind: Option<OperationKind>,
        admission_open: Arc<Mutex<crate::machine::ResourceOperationLease>>,
        runtime_owner: (
            gantry_core::identity::ProtocolIdentity,
            gantry_core::identity::ProtocolIdentity,
        ),
    ) -> Self {
        let site = StaticSiteId::new(workflow, position);
        let operation = LogicalOperationId::derive(declaration, &site);
        let generation = ResourceGenerationId::derive(&operation, &site, generation);
        Self {
            site,
            operation,
            generation,
            kind,
            runtime_owner,
            admission_open,
        }
    }

    /// Locks the machine-issued pending-operation admission window.
    #[must_use]
    pub(crate) fn lock_admission(
        &self,
    ) -> Option<MutexGuard<'_, crate::machine::ResourceOperationLease>> {
        self.admission_open.lock().ok()
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
        admission_open: Arc<Mutex<crate::machine::ResourceOperationLease>>,
        runtime_owner: (
            gantry_core::identity::ProtocolIdentity,
            gantry_core::identity::ProtocolIdentity,
        ),
    ) -> Option<Self> {
        let action = metadata.action.as_ref()?;
        Some(Self::derive(
            &action.path,
            workflow.clone(),
            position.clone(),
            generation,
            metadata.section20_kind,
            admission_open,
            runtime_owner,
        ))
    }

    /// Returns the issuing execution, independently of portable operation identity.
    #[must_use]
    pub const fn execution_id(&self) -> gantry_core::identity::ProtocolIdentity {
        self.runtime_owner.0
    }

    /// Returns the issuing task, independently of portable resource generation.
    #[must_use]
    pub const fn task_id(&self) -> gantry_core::identity::ProtocolIdentity {
        self.runtime_owner.1
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

    /// Qualifies portable identity with the issuing runtime owner for registry storage.
    fn registry_key(&self) -> ResourceRegistryKey {
        (
            self.operation.clone(),
            self.generation.clone(),
            self.runtime_owner,
        )
    }
}

/// Why the runtime refused to apply one model-issued post-failure settlement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PostFailureSettlementRefusal {
    /// The settlement names another logical operation than this account's.
    ForeignOperation,
    /// The settlement names another resource generation of this account's site.
    StaleGeneration,
    /// Declaration-only failure classification carries no accepting owner provenance.
    MissingOwner,
    /// The settlement does not declare that the failed adapter instance is poisoned.
    AdapterPoisoningNotRequired,
    /// The account's adapter binding refused the model-issued poison evidence.
    AdapterBinding(AdapterBindingRefusal),
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
/// Storage qualifies that portable identity by issuing execution and task, so independent task
/// counters cannot collapse sibling accounts. Cohort order and duplicate detection retain this
/// runtime qualification without changing the Section 20 identity derivation.
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
    accounts: BTreeMap<ResourceRegistryKey, AdmittedResource>,
    physical: BTreeMap<ResourceRegistryKey, crate::resource_transport::HostValueSlot>,
    live_limit: Option<u64>,
    pending_limit: Option<u64>,
    retained_limit: Option<u64>,
    pending_admissions: Vec<Arc<Mutex<crate::machine::ResourceOperationLease>>>,
    adapter_faults: PoisonLedger,
}

/// Runtime storage identity, ordered by portable subject then issuing execution and task.
type ResourceRegistryKey = (
    LogicalOperationId,
    ResourceGenerationId,
    (
        gantry_core::identity::ProtocolIdentity,
        gantry_core::identity::ProtocolIdentity,
    ),
);

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
    task_owner: gantry_core::identity::ProtocolIdentity,
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
            task_owner: subject.task_id(),
            subject,
            carrier,
            owner,
            record,
        }
    }

    /// Returns current cleanup ownership, independently of immutable issuing provenance.
    #[must_use]
    pub const fn task_owner(&self) -> gantry_core::identity::ProtocolIdentity {
        self.task_owner
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
            physical: BTreeMap::new(),
            live_limit: None,
            pending_limit: None,
            retained_limit: None,
            pending_admissions: Vec::new(),
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
            physical: BTreeMap::new(),
            live_limit: Some(limit),
            pending_limit: None,
            retained_limit: None,
            pending_admissions: Vec::new(),
            adapter_faults: PoisonLedger::new(),
        }
    }

    /// Creates independent finite ceilings for live accounts and admitted pending operations.
    ///
    /// Pending capacity follows the machine's admission lease, not accounting lifetime.
    /// Reconstruction through [`Self::reconstruct`] does not recover this process-local policy.
    #[must_use]
    pub fn with_limits(live_limit: u64, pending_limit: u64) -> Self {
        Self {
            pending_limit: Some(pending_limit),
            ..Self::with_live_limit(live_limit)
        }
    }

    /// Declares independent live, pending-work, and retained-account ceilings.
    ///
    /// Every registry-held account consumes retained capacity until eligible reaping,
    /// even after lifetime settlement. Existing constructors leave this ceiling absent.
    #[must_use]
    pub fn with_accounting_limits(live: u64, pending: u64, retained: u64) -> Self {
        Self {
            retained_limit: Some(retained),
            ..Self::with_limits(live, pending)
        }
    }

    /// Returns the separately declared retained-account ceiling, when any.
    #[must_use]
    pub const fn retained_limit(&self) -> Option<u64> {
        self.retained_limit
    }

    /// Counts all accounts still held by the registry, independently of semantic lifetime.
    #[must_use]
    pub fn retained_resources(&self) -> u64 {
        u64::try_from(self.accounts.len()).unwrap_or(u64::MAX)
    }

    /// Returns the separately declared pending resource-operation ceiling, when any.
    #[must_use]
    pub const fn pending_limit(&self) -> Option<u64> {
        self.pending_limit
    }

    /// Rebuilds empty accounting with exact durable admission policy, never accepted work.
    #[cfg(all(feature = "concurrent", feature = "durable"))]
    pub(crate) fn with_optional_limits(live: Option<u64>, pending: Option<u64>) -> Self {
        Self {
            live_limit: live,
            pending_limit: pending,
            ..Self::new()
        }
    }

    /// Rebuilds empty accounting with all independently optional policy ceilings.
    #[cfg(all(feature = "concurrent", feature = "durable"))]
    pub(crate) fn with_optional_accounting_limits(
        live: Option<u64>,
        pending: Option<u64>,
        retained: Option<u64>,
    ) -> Self {
        Self {
            retained_limit: retained,
            ..Self::with_optional_limits(live, pending)
        }
    }

    /// Counts admitted operations whose machine settlement lease remains open.
    ///
    /// A poisoned lease conservatively retains capacity. Accounting finalization, record
    /// deletion and physical reclamation do not close this lease. This is not a durable fact.
    #[must_use]
    pub fn pending_operations(&self) -> u64 {
        self.pending_admissions
            .iter()
            .filter(|lease| lease.lock().map_or(true, |lease| lease.pending))
            .fold(0_u64, |count, _| count.saturating_add(1))
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

    /// Reports whether every attached physical value has completed destruction.
    ///
    /// In-flight disposal retains physical ownership even after its value leaves the slot.
    /// A completed destruction failure is physically settled, not successful finalization.
    #[must_use]
    pub fn host_values_are_quiescent(&self) -> bool {
        self.physical.values().all(|slot| !slot.is_present())
    }

    /// Removes the accounts whose lifetime has reached the terminal retention state.
    ///
    /// Deletion is the only state in which the retained record is gone, so reaping is physical
    /// reclamation alone: it frees registry memory without changing any semantic release, and the
    /// registry holds no account for a reaped subject afterwards. A settled lifetime that is still
    /// retained keeps its account and stays queryable.
    pub fn reap_deleted(&mut self) -> usize {
        let before = self.accounts.len();
        self.accounts.retain(|key, account| {
            account.ledger().lifetime() != ResourceLifetimeState::Deleted
                || self
                    .physical
                    .get(key)
                    .is_some_and(crate::resource_transport::HostValueSlot::is_present)
        });
        self.physical
            .retain(|key, _| self.accounts.contains_key(key));
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
        self.admit_with_optional_host_value(subject, carrier, record, &mut None::<()>)
    }

    /// Atomically admits accounting and one caller-authenticated physical value.
    ///
    /// The machine lease fences cancellation through both insertions. Refusal returns the host
    /// value untouched and publishes no account, slot or pending capacity. This grants no authority
    /// and does not complete the machine operation or enable source live-handle transport.
    pub fn admit_host_value<T: std::any::Any + Send>(
        &mut self,
        subject: ResourceSubjectBinding,
        carrier: ResourceCarrier,
        record: DurableResourceRecord,
        value: T,
    ) -> Result<(), Box<(ResourceRegistryRefusal, T)>> {
        let mut value = Some(value);
        self.admit_with_optional_host_value(subject, carrier, record, &mut value)
            .map(|_| ())
            .map_err(|error| {
                Box::new((
                    error,
                    value
                        .take()
                        .unwrap_or_else(|| unreachable!("refused input remains owned")),
                ))
            })
    }

    /// Shares admission validation and commits optional physical ownership only after all checks.
    fn admit_with_optional_host_value<'a, T: std::any::Any + Send>(
        &'a mut self,
        subject: ResourceSubjectBinding,
        carrier: ResourceCarrier,
        record: DurableResourceRecord,
        value: &mut Option<T>,
    ) -> Result<&'a AdmittedResource, ResourceRegistryRefusal> {
        // Inspect before locking the presented lease: a duplicate may share that mutex.
        // Stage pruning so refused admissions do not change even process-local bookkeeping.
        // Settlement only closes leases, so concurrent closure can conservatively refuse.
        let mut pending_admissions = self
            .pending_admissions
            .iter()
            .filter(|lease| lease.lock().map_or(true, |lease| lease.pending))
            .cloned()
            .collect::<Vec<_>>();
        let pending = u64::try_from(pending_admissions.len()).unwrap_or(u64::MAX);
        let admission_open = Arc::clone(&subject.admission_open);
        let retained = pending_admissions
            .iter()
            .any(|lease| Arc::ptr_eq(lease, &admission_open));
        let admission_guard = admission_open
            .lock()
            .map_err(|_| ResourceRegistryRefusal::NoPendingResourceSubject)?;
        if !admission_guard.pending {
            return Err(ResourceRegistryRefusal::NoPendingResourceSubject);
        }
        if admission_guard.cancellation_requested {
            return Err(ResourceRegistryRefusal::CancellationRequested);
        }
        let live = self.live_resources();
        let limit = self.live_limit;
        let retained_accounts = self.retained_resources();
        let key = subject.registry_key();
        match self.accounts.entry(key.clone()) {
            std::collections::btree_map::Entry::Occupied(_) => {
                Err(ResourceRegistryRefusal::SecondAdmission)
            }
            std::collections::btree_map::Entry::Vacant(slot) => {
                let account = AdmittedResource::admit_reconstructed(carrier, record, subject)?;
                if let Some(limit) = limit
                    && live >= limit
                    && matches!(
                        account.ledger().lifetime(),
                        ResourceLifetimeState::Active | ResourceLifetimeState::Finishing
                    )
                {
                    return Err(ResourceRegistryRefusal::LiveResourceLimitReached { limit });
                }
                if let Some(limit) = self.pending_limit
                    && !retained
                    && pending >= limit
                {
                    return Err(ResourceRegistryRefusal::PendingOperationLimitReached { limit });
                }
                if let Some(limit) = self.retained_limit
                    && retained_accounts >= limit
                {
                    return Err(ResourceRegistryRefusal::RetainedResourceLimitReached { limit });
                }
                if value.is_some() {
                    let lifetime = account.ledger().lifetime();
                    if lifetime != ResourceLifetimeState::Active {
                        return Err(ResourceRegistryRefusal::PhysicalAdmission(
                            crate::HostResourceError::Model(
                                ResourceError::LifetimeDoesNotAdmitCharge { state: lifetime },
                            ),
                        ));
                    }
                    if !account.ledger().operation_state().is_open() {
                        return Err(ResourceRegistryRefusal::PhysicalAdmission(
                            crate::HostResourceError::Model(
                                ResourceError::IllegalLifetimeTransition,
                            ),
                        ));
                    }
                }
                if !retained {
                    pending_admissions.push(Arc::clone(&admission_open));
                }
                if let Some(value) = value.take() {
                    self.physical
                        .insert(key, crate::resource_transport::HostValueSlot::new(value));
                }
                self.pending_admissions = pending_admissions;
                Ok(slot.insert(account))
            }
        }
    }

    /// Admits the resource subject of a machine's current pending action operation.
    ///
    /// The subject is derived from the machine's retained operation metadata and generation
    /// counter. A machine without a pending action-backed resource subject cannot admit a record.
    pub fn admit_pending_operation(
        &mut self,
        machine: &crate::Machine,
        carrier: ResourceCarrier,
        record: DurableResourceRecord,
    ) -> Result<&AdmittedResource, ResourceRegistryRefusal> {
        let subject = machine
            .pending_resource_subject()
            .ok_or(ResourceRegistryRefusal::NoPendingResourceSubject)?;
        self.admit(subject, carrier, record)
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
        Self::reconstruct_bounded(live_limit, None, recovered)
    }

    /// Reconstructs accounting under an independent retained-record ceiling.
    ///
    /// Every record counts, including terminal lifetimes. Existing evidence and live
    /// capacity refusals retain precedence; no partial registry or pending work is published.
    pub fn reconstruct_with_retained_limit(
        live_limit: Option<u64>,
        retained_limit: u64,
        recovered: impl IntoIterator<Item = RecoveredResourceRecord>,
    ) -> Result<Self, ResourceRegistryRefusal> {
        Self::reconstruct_bounded(live_limit, Some(retained_limit), recovered)
    }

    /// Validates the complete reconstruction set with optional independent capacity bounds.
    fn reconstruct_bounded(
        live_limit: Option<u64>,
        retained_limit: Option<u64>,
        recovered: impl IntoIterator<Item = RecoveredResourceRecord>,
    ) -> Result<Self, ResourceRegistryRefusal> {
        let mut accounts: BTreeMap<ResourceRegistryKey, AdmittedResource> = BTreeMap::new();
        let mut live = 0_u64;
        for presented in recovered {
            let key = presented.subject.registry_key();
            if accounts.contains_key(&key) {
                return Err(ResourceRegistryRefusal::SecondAdmission);
            }
            let mut account = AdmittedResource::admit_reconstructed(
                presented.carrier,
                presented.record,
                presented.subject,
            )?;
            account.task_owner = presented.task_owner;
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
            if let Some(limit) = retained_limit
                && u64::try_from(accounts.len()).map_or(true, |count| count >= limit)
            {
                return Err(ResourceRegistryRefusal::RetainedResourceLimitReached { limit });
            }
            accounts.insert(key, account);
        }
        Ok(Self {
            accounts,
            physical: BTreeMap::new(),
            live_limit,
            pending_limit: None,
            retained_limit,
            pending_admissions: Vec::new(),
            adapter_faults: PoisonLedger::new(),
        })
    }

    /// Reports process-local resource state that the current durable graph wire cannot retain.
    ///
    /// Accounts, physical slots and still-pending admitted work require explicit
    /// reconstruction integration; empty-registry policy is carried by the graph wire.
    #[must_use]
    pub(crate) fn has_uncheckpointed_state(&self) -> bool {
        !self.accounts.is_empty() || !self.physical.is_empty() || self.pending_operations() != 0
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
                let mut record = RecoveredResourceRecord::new(
                    account.subject().clone(),
                    ResourceCarrier::ReconstructionRecord,
                    account.ledger().owner(),
                    account.durable_record(),
                );
                record.task_owner = account.task_owner;
                record
            })
            .collect()
    }

    /// Returns the account one subject owns, when any.
    #[must_use]
    pub fn account(&self, subject: &ResourceSubjectBinding) -> Option<&AdmittedResource> {
        self.accounts.get(&subject.registry_key())
    }

    /// Selects exact ownership first, retaining foreign-provenance refusal for a portable alias.
    fn selection_key(&self, subject: &ResourceSubjectBinding) -> ResourceRegistryKey {
        self.evidence_key(subject.operation(), subject.generation(), subject)
    }

    /// Selects portable evidence within its supplied runtime owner, never an arbitrary sibling.
    ///
    /// A fallback only identifies a foreign account so existing guards can report ForeignSubject;
    /// no mutation may use it without checking the presented binding's provenance.
    fn evidence_key(
        &self,
        operation: &LogicalOperationId,
        generation: &ResourceGenerationId,
        subject: &ResourceSubjectBinding,
    ) -> ResourceRegistryKey {
        let exact = (operation.clone(), generation.clone(), subject.runtime_owner);
        if self.accounts.contains_key(&exact) {
            return exact;
        }
        self.accounts
            .keys()
            .find(|key| &key.0 == operation && &key.1 == generation)
            .cloned()
            .unwrap_or(exact)
    }

    /// Attaches one physical value without moving its account or changing quota facts.
    ///
    /// The embedding caller authenticates the value/subject association and supplies authority.
    /// Refusal returns the value untouched. Disposed slots cannot be attached again.
    pub fn attach_host_value<T: std::any::Any + Send>(
        &mut self,
        subject: &ResourceSubjectBinding,
        owner: OwnerGeneration,
        value: T,
    ) -> Result<(), Box<(crate::HostResourceError, T)>> {
        use crate::HostResourceError;
        let key = self.selection_key(subject);
        let refusal = match self.accounts.get(&key) {
            None => Some(HostResourceError::UnknownSubject),
            Some(account) => {
                if account.subject().runtime_owner != subject.runtime_owner {
                    Some(HostResourceError::ForeignSubject)
                } else if let Err(error) = account.require_current_owner(owner) {
                    Some(HostResourceError::Model(error))
                } else if account.ledger().lifetime() != ResourceLifetimeState::Active
                    || !account.ledger().operation_state().is_open()
                {
                    Some(HostResourceError::Model(
                        ResourceError::IllegalLifetimeTransition,
                    ))
                } else if self.physical.contains_key(&key) {
                    Some(HostResourceError::AlreadyAttached)
                } else {
                    None
                }
            }
        };
        if let Some(error) = refusal {
            return Err(Box::new((error, value)));
        }
        // Use the admitted account's lease, not a caller's recovered or speculative binding.
        // Hold it through insertion so cancellation and physical acquisition linearize once.
        let lease = Arc::clone(
            &self
                .accounts
                .get(&key)
                .unwrap_or_else(|| unreachable!("validated account remains present"))
                .subject
                .admission_open,
        );
        let Ok(admission) = lease.lock() else {
            return Err(Box::new((HostResourceError::PendingOperation, value)));
        };
        if admission.cancellation_requested {
            return Err(Box::new((HostResourceError::CancellationRequested, value)));
        }
        self.physical
            .insert(key, crate::resource_transport::HostValueSlot::new(value));
        Ok(())
    }

    /// Inspects physical presence only; accounting captures never include a physical value.
    #[must_use]
    pub fn has_host_value(&self, subject: &ResourceSubjectBinding) -> bool {
        if self
            .account(subject)
            .is_none_or(|account| account.subject().runtime_owner != subject.runtime_owner)
        {
            return false;
        }
        self.physical
            .get(&subject.registry_key())
            .is_some_and(crate::resource_transport::HostValueSlot::is_present)
    }

    /// Invokes bounded synchronous integration with exact Rust type and accounting owner fences.
    ///
    /// No coordinator route exposes this callback API: integration code must not run under a
    /// coordinator lock. Callback destruction on refusal is contained, with panic precedence.
    pub fn invoke_host_value<T: std::any::Any + Send, R>(
        &mut self,
        subject: &ResourceSubjectBinding,
        owner: OwnerGeneration,
        callback: impl FnOnce(&mut T) -> Result<R, gantry_host::contracts::HostError>,
    ) -> Result<R, crate::HostResourceError> {
        use crate::HostResourceError;
        let key = self.selection_key(subject);
        let refusal = match self.accounts.get(&key) {
            None => Some(HostResourceError::UnknownSubject),
            Some(account) => {
                if account.subject().runtime_owner != subject.runtime_owner {
                    Some(HostResourceError::ForeignSubject)
                } else if let Err(error) = account.require_current_owner(owner) {
                    Some(HostResourceError::Model(error))
                } else if account.ledger().lifetime() != ResourceLifetimeState::Active
                    || !account.ledger().operation_state().is_open()
                {
                    Some(HostResourceError::Model(
                        ResourceError::IllegalLifetimeTransition,
                    ))
                } else if let Some(adapter) = account.adapter_instance()
                    && adapter.is_poisoned()
                {
                    Some(HostResourceError::Operation(
                        OperationAbiError::AdapterInstancePoisoned {
                            instance: Arc::from(adapter.as_str()),
                        },
                    ))
                } else {
                    None
                }
            }
        };
        if matches!(refusal, Some(HostResourceError::ForeignSubject)) {
            return crate::resource_transport::refuse_unbound_callback(
                callback,
                HostResourceError::ForeignSubject,
            );
        }
        let Some(slot) = self.physical.get_mut(&key) else {
            return crate::resource_transport::refuse_unbound_callback(
                callback,
                refusal.unwrap_or(HostResourceError::NotAttached),
            );
        };
        if let Some(error) = refusal {
            return slot.refuse(callback, error);
        }
        slot.invoke(callback)
    }

    /// Disposes physical ownership only after accounting leaves Active.
    ///
    /// Finishing permits disposal before finalization completion. Terminal lifetime release has
    /// already freed live quota even if disposal panics. The slot remains as a no-reattach fence.
    pub fn dispose_host_value(
        &mut self,
        subject: &ResourceSubjectBinding,
        owner: OwnerGeneration,
    ) -> Result<(), crate::HostResourceError> {
        self.extract_host_disposal(subject, owner)?
            .map_or(Ok(()), crate::resource_transport::HostDisposalJob::run)
    }

    /// Selects live accounting for current cleanup owners in canonical runtime-subject order.
    ///
    /// Task validation and escalation authority belong to the coordinator. This inspection
    /// excludes terminal accounts and neither settles accounting nor releases pending work.
    pub(crate) fn live_subjects_for_tasks(
        &self,
        task_ids: &[gantry_core::identity::ProtocolIdentity],
    ) -> Vec<ResourceSubjectBinding> {
        self.accounts
            .values()
            .filter(|account| {
                task_ids.contains(&account.task_owner())
                    && matches!(
                        account.ledger().lifetime(),
                        ResourceLifetimeState::Active | ResourceLifetimeState::Finishing
                    )
            })
            .map(|account| account.subject().clone())
            .collect()
    }

    /// Selects already-settled physical obligations in canonical runtime-subject order.
    ///
    /// Active and finishing accounts require semantic settlement first. Failed disposal remains
    /// reportable, while successfully disposed slots require no further cleanup.
    pub(crate) fn settled_host_subjects(&self) -> Vec<(ResourceSubjectBinding, OwnerGeneration)> {
        self.accounts
            .iter()
            .filter_map(|(key, account)| {
                let slot = self.physical.get(key)?;
                (account.ledger().lifetime().is_settled()
                    || matches!(
                        account.ledger().lifetime(),
                        ResourceLifetimeState::Retired | ResourceLifetimeState::Deleted
                    ))
                .then_some(())?;
                (slot.is_present() || slot.disposal_failed())
                    .then(|| (account.subject().clone(), account.ledger().owner()))
            })
            .collect()
    }

    /// Extracts exclusive physical cleanup while retaining a shared process-local pending fence.
    pub(crate) fn extract_host_disposal(
        &mut self,
        subject: &ResourceSubjectBinding,
        owner: OwnerGeneration,
    ) -> Result<Option<crate::resource_transport::HostDisposalJob>, crate::HostResourceError> {
        use crate::HostResourceError;
        let key = self.selection_key(subject);
        let account = self
            .accounts
            .get(&key)
            .ok_or(HostResourceError::UnknownSubject)?;
        if account.subject().runtime_owner != subject.runtime_owner {
            return Err(HostResourceError::ForeignSubject);
        }
        account
            .require_current_owner(owner)
            .map_err(HostResourceError::Model)?;
        if account.ledger().lifetime() == ResourceLifetimeState::Active {
            return Err(HostResourceError::Model(
                ResourceError::IllegalLifetimeTransition,
            ));
        }
        self.physical
            .get_mut(&key)
            .ok_or(HostResourceError::NotAttached)?
            .extract_disposal()
    }

    /// Settles the account its own subject names from one model-issued post-failure settlement.
    ///
    /// The account is selected by the settlement's own operation and generation, so a settlement
    /// naming a subject this registry holds no account for is refused without changing any account.
    /// The accompanying machine binding must agree with that account and its runtime provenance.
    pub fn settle_from_post_failure(
        &mut self,
        settlement: &PostFailureSettlement,
        settled_at: u64,
        subject: &ResourceSubjectBinding,
    ) -> Result<ResourceLifetimeState, ResourceRegistryRefusal> {
        let key = self.evidence_key(settlement.operation(), settlement.generation(), subject);
        let account = self
            .accounts
            .get_mut(&key)
            .ok_or(ResourceRegistryRefusal::UnknownSubject)?;
        require_evidence_subject(account, subject)?;
        account
            .settle_from_post_failure(settlement, settled_at)
            .map_err(ResourceRegistryRefusal::Settlement)
    }

    /// Projects the state of one accepted live-resource settlement into its admitted record.
    ///
    /// The operation-state projection is available only after the supplied `LiveResource` accepted
    /// its own Section 20 settlement. Its operation and generation select the account; the ledger
    /// then enforces the current owner generation before changing only the distinct operation-state
    /// fact. An unsettled or unknown subject, or stale owner, is refused without changing any
    /// declared account fact.
    /// The accompanying machine binding must name the same account and issuing execution/task.
    pub fn project_operation_state(
        &mut self,
        live: &gantry_ir::LiveResource,
        subject: &ResourceSubjectBinding,
    ) -> Result<ResourceState, ResourceRegistryRefusal> {
        let projection = live
            .operation_state_projection()
            .ok_or(ResourceRegistryRefusal::OperationStateProjectionNotSettled)?;
        self.project_retained_state(&projection, subject)
    }

    /// Projects only a retained failure winner's state, without settling lifetime or work.
    ///
    /// Failure evidence retains exact subject, runtime provenance, current-owner and terminal
    /// state fences. Ordinary successful projection remains unavailable for failure winners.
    pub fn project_failure_state(
        &mut self,
        live: &gantry_ir::LiveResource,
        subject: &ResourceSubjectBinding,
    ) -> Result<ResourceState, ResourceRegistryRefusal> {
        let projection = live
            .failure_state_projection()
            .ok_or(ResourceRegistryRefusal::OperationStateProjectionNotSettled)?;
        self.project_retained_state(&projection, subject)
    }

    /// Selects exact evidence-qualified accounting and applies its model-owned state fence.
    fn project_retained_state(
        &mut self,
        projection: &gantry_ir::OperationStateProjection,
        subject: &ResourceSubjectBinding,
    ) -> Result<ResourceState, ResourceRegistryRefusal> {
        let key = self.evidence_key(projection.operation(), projection.generation(), subject);
        let account = self
            .accounts
            .get_mut(&key)
            .ok_or(ResourceRegistryRefusal::UnknownSubject)?;
        require_evidence_subject(account, subject)?;
        account
            .ledger
            .project_operation_state(projection)
            .map_err(ResourceRegistryRefusal::OperationStateProjection)
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
        let key = self.selection_key(subject);
        let account = self
            .accounts
            .get_mut(&key)
            .ok_or(ResourceRegistryRefusal::UnknownSubject)?;
        require_subject_provenance(account, subject)?;
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
        let key = self.selection_key(subject);
        let account = self
            .accounts
            .get_mut(&key)
            .ok_or(ResourceRegistryRefusal::UnknownSubject)?;
        require_subject_provenance(account, subject)?;
        account
            .charge(presented_owner, action, charges)
            .map_err(ResourceRegistryRefusal::Charge)
    }

    /// Advances only the current owner generation of one registry-held account.
    ///
    /// Exact runtime provenance and current ownership are checked before physical eligibility.
    /// Existing transfer obligations then require active/open accounting, a strict successor,
    /// no loan, settled machine work and containment, and no adapter binding. The account and
    /// physical slot stay in this registry; refusal changes neither. This is not task transfer.
    pub fn advance_owner(
        &mut self,
        subject: &ResourceSubjectBinding,
        owner: OwnerGeneration,
        successor: OwnerGeneration,
    ) -> Result<(), ResourceRegistryRefusal> {
        let key = self.selection_key(subject);
        let account = self
            .accounts
            .get_mut(&key)
            .ok_or(ResourceRegistryRefusal::UnknownSubject)?;
        require_subject_provenance(account, subject)?;
        account.require_current_owner(owner).map_err(|error| {
            ResourceRegistryRefusal::OwnershipTransfer(crate::HostResourceError::Model(error))
        })?;
        if let Some(slot) = self.physical.get(&key) {
            slot.require_transfer_eligible()
                .map_err(ResourceRegistryRefusal::OwnershipTransfer)?;
        }
        account
            .transfer_owner(owner, successor)
            .map_err(ResourceRegistryRefusal::OwnershipTransfer)
    }

    /// Moves cleanup responsibility after validating the current task and transfer obligations.
    ///
    /// Only the coordinator may call this route after validating both tasks in its execution.
    /// The issuing subject, storage key, physical slot and historical containment stay fixed.
    pub(crate) fn transfer_task_owner(
        &mut self,
        subject: &ResourceSubjectBinding,
        source: gantry_core::identity::ProtocolIdentity,
        destination: gantry_core::identity::ProtocolIdentity,
        owner: OwnerGeneration,
        successor: OwnerGeneration,
    ) -> Result<(), ResourceRegistryRefusal> {
        let key = self.selection_key(subject);
        let account = self
            .accounts
            .get(&key)
            .ok_or(ResourceRegistryRefusal::UnknownSubject)?;
        require_subject_provenance(account, subject)?;
        if account.task_owner() != source {
            return Err(ResourceRegistryRefusal::TaskOwnerMismatch);
        }
        self.advance_owner(subject, owner, successor)?;
        self.accounts
            .get_mut(&key)
            .unwrap_or_else(|| unreachable!("validated account remains registered"))
            .task_owner = destination;
        Ok(())
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
        let key = self.selection_key(subject);
        let account = self
            .accounts
            .get_mut(&key)
            .ok_or(ResourceRegistryRefusal::UnknownSubject)?;
        require_subject_provenance(account, subject)?;
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
        let key = self.selection_key(subject);
        let account = self
            .accounts
            .get_mut(&key)
            .ok_or(ResourceRegistryRefusal::UnknownSubject)?;
        require_subject_provenance(account, subject)?;
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
        let key = self.selection_key(subject);
        let account = self
            .accounts
            .get_mut(&key)
            .ok_or(ResourceRegistryRefusal::UnknownSubject)?;
        require_subject_provenance(account, subject)?;
        account
            .require_current_owner(presented_owner)
            .map_err(ResourceRegistryRefusal::Finish)?;
        if self
            .physical
            .get(&key)
            .is_some_and(crate::resource_transport::HostValueSlot::is_present)
        {
            return Err(ResourceRegistryRefusal::PhysicalValuePresent);
        }
        if self
            .physical
            .get(&key)
            .is_some_and(crate::resource_transport::HostValueSlot::disposal_failed)
        {
            return Err(ResourceRegistryRefusal::PhysicalDisposalFailed);
        }
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
        let key = self.selection_key(subject);
        let account = self
            .accounts
            .get_mut(&key)
            .ok_or(ResourceRegistryRefusal::UnknownSubject)?;
        require_subject_provenance(account, subject)?;
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
        let key = self.selection_key(subject);
        let account = self
            .accounts
            .get_mut(&key)
            .ok_or(ResourceRegistryRefusal::UnknownSubject)?;
        require_subject_provenance(account, subject)?;
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
        let key = self.selection_key(subject);
        let account = self
            .accounts
            .get_mut(&key)
            .ok_or(ResourceRegistryRefusal::UnknownSubject)?;
        require_subject_provenance(account, subject)?;
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
        let key = self.selection_key(subject);
        let account = self
            .accounts
            .get_mut(&key)
            .ok_or(ResourceRegistryRefusal::UnknownSubject)?;
        require_subject_provenance(account, subject)?;
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
    /// reason through [`ResourceRegistryRefusal::AdapterBinding`] and nothing is replaced. A presented
    /// binding that is itself already poisoned or already retired is refused for the same reason, so no
    /// replacement returns a failed or retired instance to service. The binding is runtime state rather
    /// than a declared durable fact, so a registry rebuilt from declared reconstruction records holds
    /// no adapter binding.
    pub fn bind_adapter_instance(
        &mut self,
        subject: &ResourceSubjectBinding,
        presented_owner: OwnerGeneration,
        mut instance: AdapterInstance,
    ) -> Result<(), ResourceRegistryRefusal> {
        let key = self.selection_key(subject);
        if self.adapter_faults.recorded_reason(&instance).is_some() {
            instance.poison();
        }
        let account = self
            .accounts
            .get_mut(&key)
            .ok_or(ResourceRegistryRefusal::UnknownSubject)?;
        require_subject_provenance(account, subject)?;
        account
            .bind_adapter_instance(presented_owner, instance)
            .map_err(ResourceRegistryRefusal::AdapterBinding)
    }

    /// Returns the adapter instance bound to one admitted account, when one is bound.
    #[must_use]
    pub fn adapter_instance(&self, subject: &ResourceSubjectBinding) -> Option<&AdapterInstance> {
        self.accounts
            .get(&subject.registry_key())
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
    /// clears the landed one-way poison. The reason record is runtime state of this registry's ledger
    /// rather than a declared durable fact, so a rebuilt registry holds no recorded reason.
    pub fn poison_adapter_instance(
        &mut self,
        subject: &ResourceSubjectBinding,
        presented_owner: OwnerGeneration,
        reason: PoisonReason,
    ) -> Result<PoisonReason, ResourceRegistryRefusal> {
        let key = self.selection_key(subject);
        let ledger = &mut self.adapter_faults;
        let account = self
            .accounts
            .get_mut(&key)
            .ok_or(ResourceRegistryRefusal::UnknownSubject)?;
        require_subject_provenance(account, subject)?;
        let reason = account
            .poison_adapter_instance(presented_owner, reason, ledger)
            .map_err(ResourceRegistryRefusal::AdapterBinding)?;
        let identity = account
            .adapter_instance()
            .unwrap_or_else(|| unreachable!("successful poisoning retains its adapter"))
            .as_str()
            .to_owned();
        self.poison_adapter_aliases(&identity);
        Ok(reason)
    }

    /// Poisons only the bound adapter named by a model-issued adapter-failure settlement.
    ///
    /// The settlement selects its own admitted operation and resource generation; a missing
    /// account is refused without changing any binding. The Section 20 poison flag is required,
    /// while the Section 23 reason remains explicit input from the fault-classification caller.
    /// The account's owner fence and the registry's one-way poison ledger decide whether that
    /// binding can be poisoned; the resource lifetime and sibling accounts are unchanged.
    /// The accompanying machine binding must agree with the evidence-selected runtime account.
    pub fn poison_adapter_from_post_failure(
        &mut self,
        settlement: &PostFailureSettlement,
        presented_owner: OwnerGeneration,
        reason: PoisonReason,
        subject: &ResourceSubjectBinding,
    ) -> Result<PoisonReason, ResourceRegistryRefusal> {
        let key = self.evidence_key(settlement.operation(), settlement.generation(), subject);
        let ledger = &mut self.adapter_faults;
        let account = self
            .accounts
            .get_mut(&key)
            .ok_or(ResourceRegistryRefusal::UnknownSubject)?;
        require_evidence_subject(account, subject)?;
        let reason = account
            .poison_adapter_from_post_failure(settlement, presented_owner, reason, ledger)
            .map_err(ResourceRegistryRefusal::Settlement)?;
        let identity = account
            .adapter_instance()
            .unwrap_or_else(|| unreachable!("successful poisoning retains its adapter"))
            .as_str()
            .to_owned();
        self.poison_adapter_aliases(&identity);
        Ok(reason)
    }

    /// Marks aliases of one failed identity unusable without changing unrelated bindings or facts.
    fn poison_adapter_aliases(&mut self, identity: &str) {
        for account in self.accounts.values_mut() {
            if let Some(adapter) = account.adapter.as_mut()
                && adapter.as_str() == identity
            {
                adapter.poison();
            }
        }
    }

    /// Settles every account of one hard-cancelled cohort from that cohort's sealed cleanup witnesses.
    ///
    /// The model's emergency-release witness is sealed and single-use, so the sweep takes one witness
    /// per account, which is the shape a halted cohort has after each of its escalations admitted
    /// cleanup. Each presented witness authorizes at most one settlement attempt: it is consumed by
    /// that attempt whether the attempt succeeds or is refused, and a witness that reaches no ledger -
    /// because the sweep stopped earlier, because its subject was presented more than once, or because
    /// this registry holds no account for its subject - is dropped. The progress reports no unprocessed
    /// witnesses, so retrying an unsettled account needs a fresh witness for it.
    ///
    /// Accounts settle in canonical subject order rather than the order the caller presents, and each
    /// account's own ledger decides whether it admits an emergency release, exactly as
    /// [`Self::settle_from_emergency_cleanup`] documents. A subject presented more than once settles
    /// once, under the witness the stable sort retains for it, and an account this registry does not
    /// hold is refused with [`ResourceRegistryRefusal::UnknownSubject`]. Two things are runtime policy:
    /// that order, and the progress contract that stops at the first refusal without rolling back an
    /// account that already settled, because an emergency release is one-way.
    pub fn settle_cohort_from_emergency_cleanup(
        &mut self,
        cleanups: Vec<(ResourceSubjectBinding, EmergencyCleanupWitness)>,
    ) -> CohortEmergencyCleanup {
        let mut ordered = cleanups;
        ordered.sort_by_key(|entry| entry.0.registry_key());
        ordered.dedup_by(|left, right| left.0.registry_key() == right.0.registry_key());
        let mut settled = Vec::new();
        for (subject, cleanup) in ordered {
            let key = self.selection_key(&subject);
            let Some(account) = self.accounts.get_mut(&key) else {
                return CohortEmergencyCleanup {
                    settled,
                    refusal: Some((subject, ResourceRegistryRefusal::UnknownSubject)),
                };
            };
            if let Err(refusal) = require_subject_provenance(account, &subject) {
                return CohortEmergencyCleanup {
                    settled,
                    refusal: Some((subject, refusal)),
                };
            }
            match account
                .settle_from_emergency_cleanup(cleanup)
                .map_err(ResourceRegistryRefusal::EmergencyRelease)
            {
                Ok(lifetime) => settled.push(CohortEmergencySettlement { subject, lifetime }),
                Err(refusal) => {
                    return CohortEmergencyCleanup {
                        settled,
                        refusal: Some((subject, refusal)),
                    };
                }
            }
        }
        CohortEmergencyCleanup {
            settled,
            refusal: None,
        }
    }
}

/// Checks runtime ownership independently of portable operation and generation identity.
fn require_subject_provenance(
    account: &AdmittedResource,
    subject: &ResourceSubjectBinding,
) -> Result<(), ResourceRegistryRefusal> {
    if account.subject().runtime_owner != subject.runtime_owner {
        return Err(ResourceRegistryRefusal::ForeignSubject);
    }
    Ok(())
}

/// Checks that a binding names the evidence-selected account before checking runtime ownership.
fn require_evidence_subject(
    account: &AdmittedResource,
    subject: &ResourceSubjectBinding,
) -> Result<(), ResourceRegistryRefusal> {
    if account.subject().operation() != subject.operation()
        || account.subject().generation() != subject.generation()
    {
        return Err(ResourceRegistryRefusal::EvidenceSubjectMismatch);
    }
    require_subject_provenance(account, subject)
}

/// Why the runtime resource registry refused an admission or a settlement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResourceRegistryRefusal {
    /// The subject already owns an admitted account, or was presented twice in one reconstruction.
    SecondAdmission,
    /// Matching portable identity was presented by another execution or task.
    ForeignSubject,
    /// The supplied runtime binding differs from the evidence-selected operation or generation.
    EvidenceSubjectMismatch,
    /// Physical ownership must be disposed before accounting finalization completes.
    PhysicalValuePresent,
    /// Contained physical destruction failed and cannot authorize normal finalization.
    PhysicalDisposalFailed,
    /// Atomic acquisition requires accounting eligible for physical attachment.
    PhysicalAdmission(crate::HostResourceError),
    /// The subject's operation carries no authenticated live-resource Section 20 kind.
    UnauthenticatedOperationKind,
    /// The machine has no pending action-backed operation with a resource subject.
    NoPendingResourceSubject,
    /// Machine cancellation has closed new admission while accepted work remains pending.
    CancellationRequested,
    /// The account's own emergency release refused the sealed cleanup witness.
    EmergencyRelease(ResourceError),
    /// The account's own ledger refused the presented charge.
    Charge(ResourceError),
    /// The account's own ledger refused the presented renewal.
    Renewal(ResourceError),
    /// Existing ownership or physical transport obligations prevent owner advancement.
    OwnershipTransfer(crate::HostResourceError),
    /// A handoff names a source task that no longer owns cleanup for this account.
    TaskOwnerMismatch,
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
    /// The separately declared admitted pending-operation ceiling is already reached.
    PendingOperationLimitReached {
        /// The declared limit.
        limit: u64,
    },
    /// The separately declared retained-account ceiling is already reached.
    RetainedResourceLimitReached {
        /// The declared limit.
        limit: u64,
    },
    /// The registry holds no account for the settlement's own operation and generation.
    UnknownSubject,
    /// The model refused the carrier, the reconstruction record, or its presented owner generation.
    Admission(ResourceError),
    /// The account's own settlement step refused the settlement.
    Settlement(PostFailureSettlementRefusal),
    /// The account's current-owner fence refused an accepted operation-state projection.
    OperationStateProjection(ResourceError),
    /// The presented live resource has not accepted an operation settlement.
    OperationStateProjectionNotSettled,
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

/// One account settled by one cohort emergency-cleanup sweep.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CohortEmergencySettlement {
    subject: ResourceSubjectBinding,
    lifetime: ResourceLifetimeState,
}

impl CohortEmergencySettlement {
    /// Returns the subject of the settled account.
    #[must_use]
    pub const fn subject(&self) -> &ResourceSubjectBinding {
        &self.subject
    }

    /// Returns the lifetime the account settled into.
    #[must_use]
    pub const fn lifetime(&self) -> ResourceLifetimeState {
        self.lifetime
    }
}

/// The progress of one cohort emergency-cleanup sweep.
///
/// A sweep settles the accounts it was given in canonical subject order and stops at the first
/// refusal, so [`Self::settled`] is exactly the prefix that reached its terminal disposition and
/// [`Self::refusal`] names the account the sweep stopped at, when it stopped.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CohortEmergencyCleanup {
    settled: Vec<CohortEmergencySettlement>,
    refusal: Option<(ResourceSubjectBinding, ResourceRegistryRefusal)>,
}

impl CohortEmergencyCleanup {
    /// Returns the accounts that settled, in canonical subject order.
    #[must_use]
    pub fn settled(&self) -> &[CohortEmergencySettlement] {
        &self.settled
    }

    /// Returns the account the sweep stopped at and the refusal it reported, when it stopped.
    #[must_use]
    pub fn refusal(&self) -> Option<(&ResourceSubjectBinding, &ResourceRegistryRefusal)> {
        self.refusal
            .as_ref()
            .map(|(subject, refusal)| (subject, refusal))
    }

    /// Returns whether the sweep settled every account it was given.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.refusal.is_none()
    }
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
    task_owner: gantry_core::identity::ProtocolIdentity,
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
        let admission_open = subject
            .lock_admission()
            .ok_or(ResourceRegistryRefusal::NoPendingResourceSubject)?;
        if !admission_open.pending {
            return Err(ResourceRegistryRefusal::NoPendingResourceSubject);
        }
        if admission_open.cancellation_requested {
            return Err(ResourceRegistryRefusal::CancellationRequested);
        }
        let admitted = Self::admit_reconstructed(carrier, record, subject.clone());
        drop(admission_open);
        admitted
    }

    fn admit_reconstructed(
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
            task_owner: subject.task_id(),
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

    /// Returns the task currently responsible for cleanup, not the immutable issuing task.
    #[must_use]
    pub const fn task_owner(&self) -> gantry_core::identity::ProtocolIdentity {
        self.task_owner
    }

    /// Returns the reconstructed accounting ledger of this resource.
    #[must_use]
    pub fn ledger(&self) -> &ResourceLedger {
        &self.ledger
    }

    /// Applies an exclusively admitted receiver loan's accepted operation-state projection.
    pub(crate) fn settle_receiver_loan(
        &mut self,
        live: &gantry_ir::LiveResource,
    ) -> Result<ResourceState, ResourceError> {
        self.require_current_owner(live.owner())?;
        if !self.ledger.liveness_roots().contains(&LivenessRoot::Loan) {
            return Err(ResourceError::LivenessRootNotLive);
        }
        let projection = live
            .operation_state_projection()
            .or_else(|| live.failure_state_projection())
            .unwrap_or_else(|| unreachable!("loan handle has accepted its settlement"));
        let state = self.ledger.project_operation_state(&projection)?;
        self.ledger.close_liveness_root(LivenessRoot::Loan)?;
        Ok(state)
    }

    /// Advances an exclusively held host account after every prior operation obligation settles.
    ///
    /// This private transport route retains the historical containment value and all facts other
    /// than current ownership. It does not rebind an adapter or reopen the machine admission lease.
    pub(crate) fn transfer_owner(
        &mut self,
        owner: OwnerGeneration,
        successor: OwnerGeneration,
    ) -> Result<(), crate::HostResourceError> {
        use crate::HostResourceError;

        self.require_current_owner(owner)
            .map_err(HostResourceError::Model)?;
        if self.ledger.lifetime() != ResourceLifetimeState::Active
            || !self.ledger.operation_state().is_open()
        {
            return Err(HostResourceError::Model(
                ResourceError::IllegalLifetimeTransition,
            ));
        }
        if !successor.succeeds(owner) {
            return Err(HostResourceError::Model(
                ResourceError::InvalidSuccessorGeneration,
            ));
        }
        if self.ledger.liveness_roots().contains(&LivenessRoot::Loan) {
            return Err(HostResourceError::LoanOutstanding);
        }
        {
            let lease = self
                .subject
                .lock_admission()
                .ok_or(HostResourceError::PendingOperation)?;
            if lease.pending {
                return Err(HostResourceError::PendingOperation);
            }
        }
        if !self.containment.is_settled() {
            return Err(HostResourceError::ContainmentPending);
        }
        if self.adapter.is_some() {
            return Err(HostResourceError::AdapterBound);
        }
        let record = self.ledger.durable_record();
        let transferred = DurableResourceRecord::from_durable_facts(
            successor,
            record.lifetime(),
            record.operation_state(),
            record.quotas().clone(),
            record.liveness_roots().clone(),
            record.settlement(),
            record.successor_fence(),
        )
        .map_err(HostResourceError::Model)?;
        self.ledger = ResourceLedger::reconstruct(transferred);
        Ok(())
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
    /// A first binding is stored as it is presented, and a presented binding that is already poisoned
    /// or already retired is refused with the model's own reason once the presented owner generation is
    /// accepted, so binding can never return a failed or retired instance to service. A replacement is
    /// then decided by the
    /// model's own substitution rule of the binding this account already holds, so a poisoned held
    /// binding, a retired held binding, a replacement that widens the rights held, and a replacement
    /// whose owner generation does not succeed the held one are each refused with the model's own
    /// reason and without replacing anything. The presented owner generation must be this account's
    /// current one, so a superseded owner can neither bind nor replace the adapter of an operation it
    /// does not hold.
    pub fn bind_adapter_instance(
        &mut self,
        presented_owner: OwnerGeneration,
        instance: AdapterInstance,
    ) -> Result<(), AdapterBindingRefusal> {
        self.require_current_owner(presented_owner)
            .map_err(AdapterBindingRefusal::StaleOwner)?;
        if instance.is_poisoned() {
            return Err(AdapterBindingRefusal::Substitution(
                OperationAbiError::AdapterInstancePoisoned {
                    instance: Arc::from(instance.as_str()),
                },
            ));
        }
        if instance.is_retired() {
            return Err(AdapterBindingRefusal::Substitution(
                OperationAbiError::AdapterInstanceRetired {
                    instance: Arc::from(instance.as_str()),
                },
            ));
        }
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

    /// Applies one model-issued adapter-failure settlement to this account's bound adapter.
    fn poison_adapter_from_post_failure(
        &mut self,
        settlement: &PostFailureSettlement,
        presented_owner: OwnerGeneration,
        reason: PoisonReason,
        ledger: &mut PoisonLedger,
    ) -> Result<PoisonReason, PostFailureSettlementRefusal> {
        if settlement.operation() != self.subject.operation() {
            return Err(PostFailureSettlementRefusal::ForeignOperation);
        }
        if settlement.generation() != self.subject.generation() {
            return Err(PostFailureSettlementRefusal::StaleGeneration);
        }
        if !settlement.poisons_adapter() {
            return Err(PostFailureSettlementRefusal::AdapterPoisoningNotRequired);
        }
        self.require_current_owner(
            settlement
                .owner()
                .ok_or(PostFailureSettlementRefusal::MissingOwner)?,
        )
        .map_err(PostFailureSettlementRefusal::Model)?;
        self.poison_adapter_instance(presented_owner, reason, ledger)
            .map_err(PostFailureSettlementRefusal::AdapterBinding)
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
        self.require_current_owner(
            settlement
                .owner()
                .ok_or(PostFailureSettlementRefusal::MissingOwner)?,
        )
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
