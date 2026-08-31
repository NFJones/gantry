//! Journal-first event occurrences and immutable delivery obligations.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

use gantry_core::canonical_json::CanonicalJson;
use gantry_core::event::{EventDraft, EventEnvelope, EventPayload, ProtectedReference};
use gantry_core::identity::ProtocolIdentity;
use gantry_core::portable::{
    DeliveryOutcome, EventKind, IdentityKind, JitterMode, ProtectedReferenceClass, SinkClass,
};
use gantry_core::source::SourceSpan;
use gantry_core::strict_json::{JsonLimits, JsonNode, JsonNodeId, StrictJsonDocument};
use gantry_core::timestamp::UtcTimestamp;
use gantry_host::event::{
    EventRetryPolicy, ProtectedPayload, RedactionCapabilities, SinkDeliveryPolicy, SinkId,
};
use gantry_host::journal::{
    BatchLocalEvidenceId, JournalBatchV1, JournalContractError, JournalError, JournalErrorCode,
    JournalEvidenceEnvelopeV1, JournalEvidenceReferenceV1, JournalPayloadKey,
    JournalProtectedPayloadV1, UnfinalizedEvidenceV1,
};
use gantry_observe::SinkPlan;

use crate::{
    DurableTransitionSink, RequiredEventDeliveryFailureV1, TransitionReceiptV1, TransitionSink,
};

/// Version-one journal evidence kind for one standard event and its frozen plan.
pub const DURABLE_EVENT_OCCURRENCE_KIND_V1: &str = "gantry.event-occurrence/v1";

/// Version-one journal evidence kind committed before one physical sink invocation.
pub const DURABLE_EVENT_DISPATCHED_KIND_V1: &str = "gantry.event-delivery-dispatched/v1";

/// Version-one journal evidence kind committed after one physical sink invocation.
pub const DURABLE_EVENT_SETTLED_KIND_V1: &str = "gantry.event-delivery-settled/v1";

/// Storage coordinates established by one journal-first event evidence commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableEventCommitV1 {
    /// Storage-assigned stable evidence identity.
    pub evidence_id: ProtocolIdentity,
    /// Contiguous authoritative journal sequence.
    pub sequence: u64,
}

/// Serial event-evidence commit boundary for one fenced durable execution.
pub struct DurableEventCommitCoordinatorV1<'a> {
    sink: &'a DurableTransitionSink,
    predecessor: (ProtocolIdentity, u64),
    next_local_id: u64,
    committed_causes: BTreeSet<ProtocolIdentity>,
    terminated: Option<JournalError>,
}

impl<'a> DurableEventCommitCoordinatorV1<'a> {
    /// Resumes journal-first event commits from one authoritative journal tip.
    pub fn new(
        sink: &'a DurableTransitionSink,
        predecessor: (ProtocolIdentity, u64),
    ) -> Result<Self, DurableEventCommitError> {
        if predecessor.0.kind() != IdentityKind::Evidence || predecessor.1 == 0 {
            return Err(DurableEventCommitError::InvalidState);
        }
        Ok(Self {
            sink,
            predecessor,
            next_local_id: 0,
            committed_causes: BTreeSet::new(),
            terminated: None,
        })
    }

    /// Resumes event commits while retaining every already represented cause.
    pub fn from_recovered(
        sink: &'a DurableTransitionSink,
        predecessor: (ProtocolIdentity, u64),
        recovered: &RecoveredDurableEventsV1,
    ) -> Result<Self, DurableEventCommitError> {
        let mut coordinator = Self::new(sink, predecessor)?;
        coordinator.committed_causes = recovered.causal_occurrences.keys().copied().collect();
        Ok(coordinator)
    }

    /// Returns the current authoritative journal tip.
    #[must_use]
    pub const fn predecessor(&self) -> (ProtocolIdentity, u64) {
        self.predecessor
    }

    /// Atomically commits an occurrence, its frozen plan, and all protected payloads.
    pub async fn commit_occurrence(
        &mut self,
        occurrence: &DurableEventOccurrenceV1,
        payloads: &[ProtectedPayload],
    ) -> Result<DurableEventCommitV1, DurableEventCommitError> {
        self.require_writable()?;
        if self
            .committed_causes
            .contains(&occurrence.causal_evidence_id())
        {
            return Err(DurableEventCommitError::DuplicateOccurrence);
        }
        let local_id = self.next_local_id("event-occurrence")?;
        let references = event_references(self.predecessor.0, [occurrence.causal_evidence_id()]);
        let (body, payloads) = occurrence
            .unfinalized(local_id.clone(), references, payloads)
            .map_err(DurableEventCommitError::Evidence)?;
        let commit = self.commit(local_id, body, payloads).await?;
        self.committed_causes
            .insert(occurrence.causal_evidence_id());
        Ok(commit)
    }

    /// Commits a dispatched state before the corresponding sink invocation.
    pub async fn commit_dispatched(
        &mut self,
        occurrence_evidence_id: ProtocolIdentity,
        dispatched: &DurableEventDispatchedV1,
    ) -> Result<DurableEventCommitV1, DurableEventCommitError> {
        self.require_writable()?;
        if occurrence_evidence_id.kind() != IdentityKind::Evidence {
            return Err(DurableEventCommitError::InvalidState);
        }
        let local_id = self.next_local_id("event-dispatched")?;
        let body = dispatched
            .unfinalized(
                local_id.clone(),
                event_references(self.predecessor.0, [occurrence_evidence_id]),
            )
            .map_err(DurableEventCommitError::Evidence)?;
        self.commit(local_id, body, Vec::new()).await
    }

    /// Commits a settlement before success, exhaustion, or retry becomes observable.
    pub async fn commit_settled(
        &mut self,
        occurrence_evidence_id: ProtocolIdentity,
        dispatch_evidence_id: ProtocolIdentity,
        settled: &DurableEventSettledV1,
    ) -> Result<DurableEventCommitV1, DurableEventCommitError> {
        self.require_writable()?;
        if occurrence_evidence_id.kind() != IdentityKind::Evidence
            || dispatch_evidence_id.kind() != IdentityKind::Evidence
        {
            return Err(DurableEventCommitError::InvalidState);
        }
        let local_id = self.next_local_id("event-settled")?;
        let body = settled
            .unfinalized(
                local_id.clone(),
                event_references(
                    self.predecessor.0,
                    [occurrence_evidence_id, dispatch_evidence_id],
                ),
            )
            .map_err(DurableEventCommitError::Evidence)?;
        self.commit(local_id, body, Vec::new()).await
    }

    fn require_writable(&self) -> Result<(), DurableEventCommitError> {
        self.terminated.clone().map_or(Ok(()), |error| {
            Err(DurableEventCommitError::StreamTerminated(error))
        })
    }

    fn next_local_id(
        &mut self,
        prefix: &str,
    ) -> Result<BatchLocalEvidenceId, DurableEventCommitError> {
        self.next_local_id = self
            .next_local_id
            .checked_add(1)
            .ok_or(DurableEventCommitError::InvalidState)?;
        BatchLocalEvidenceId::new(format!("{prefix}-{}", self.next_local_id))
            .map_err(|_| DurableEventCommitError::InvalidState)
    }

    async fn commit(
        &mut self,
        local_id: BatchLocalEvidenceId,
        body: UnfinalizedEvidenceV1,
        payloads: Vec<JournalProtectedPayloadV1>,
    ) -> Result<DurableEventCommitV1, DurableEventCommitError> {
        let batch = JournalBatchV1::new(vec![body], payloads)
            .map_err(|_| DurableEventCommitError::InvalidState)?;
        let expected_sequence = self
            .predecessor
            .1
            .checked_add(1)
            .ok_or(DurableEventCommitError::InvalidState)?;
        let receipt = match self.sink.record(batch).await {
            Ok(TransitionReceiptV1::Durable(receipt)) => receipt,
            Ok(TransitionReceiptV1::Volatile) => {
                return Err(DurableEventCommitError::InvalidReceipt);
            }
            Err(error) => {
                self.terminated = Some(error.clone());
                return Err(DurableEventCommitError::Journal(error));
            }
        };
        let valid = receipt.first_sequence == expected_sequence
            && receipt.last_sequence == expected_sequence
            && receipt.entries.len() == 1
            && receipt.entries[0].batch_local_id == local_id
            && receipt.entries[0].sequence == expected_sequence
            && receipt.entries[0].evidence_id.kind() == IdentityKind::Evidence;
        if !valid {
            self.terminated = Some(JournalError::new(JournalErrorCode::Internal));
            return Err(DurableEventCommitError::InvalidReceipt);
        }
        let commit = DurableEventCommitV1 {
            evidence_id: receipt.entries[0].evidence_id,
            sequence: expected_sequence,
        };
        self.predecessor = (commit.evidence_id, commit.sequence);
        Ok(commit)
    }
}

/// Failure before a durable event boundary can become externally observable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DurableEventCommitError {
    /// Recovered coordinates or supplied evidence identities are invalid.
    InvalidState,
    /// The durable causal transition already has its sole event occurrence.
    DuplicateOccurrence,
    /// Typed occurrence or delivery evidence is inconsistent.
    Evidence(DurableEventEvidenceError),
    /// The journal commit failed and permanently ended this event stream.
    Journal(JournalError),
    /// A previous journal failure already ended this event stream.
    StreamTerminated(JournalError),
    /// Storage returned a receipt that did not establish exactly one expected commit.
    InvalidReceipt,
}

fn event_references(
    predecessor: ProtocolIdentity,
    additional: impl IntoIterator<Item = ProtocolIdentity>,
) -> Vec<JournalEvidenceReferenceV1> {
    let mut identities = vec![predecessor];
    for identity in additional {
        if !identities.contains(&identity) {
            identities.push(identity);
        }
    }
    identities
        .into_iter()
        .map(JournalEvidenceReferenceV1::Existing)
        .collect()
}

/// One sink obligation captured when an event occurrence becomes durable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableSinkObligationV1 {
    sink_id: SinkId,
    policy: SinkDeliveryPolicy,
}

impl DurableSinkObligationV1 {
    /// Captures one stable sink identity and its complete effective policy.
    #[must_use]
    pub fn new(sink_id: SinkId, policy: SinkDeliveryPolicy) -> Self {
        Self { sink_id, policy }
    }

    /// Returns the captured sink identity.
    #[must_use]
    pub const fn sink_id(&self) -> &SinkId {
        &self.sink_id
    }

    /// Returns the complete captured policy.
    #[must_use]
    pub const fn policy(&self) -> &SinkDeliveryPolicy {
        &self.policy
    }
}

/// Canonically ordered immutable delivery obligations for one durable event.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DurableEventPlanV1(Arc<[DurableSinkObligationV1]>);

impl DurableEventPlanV1 {
    /// Sorts obligations by unsigned UTF-8 sink identity and rejects duplicates.
    pub fn new(
        mut obligations: Vec<DurableSinkObligationV1>,
    ) -> Result<Self, DurableEventEvidenceError> {
        obligations.sort_by(|left, right| left.sink_id.as_str().cmp(right.sink_id.as_str()));
        if obligations
            .windows(2)
            .any(|pair| pair[0].sink_id == pair[1].sink_id)
        {
            return Err(DurableEventEvidenceError::DuplicateSink);
        }
        Ok(Self(Arc::from(obligations)))
    }

    /// Freezes the policies in one already canonical runtime sink plan.
    pub fn from_sink_plan(plan: &SinkPlan) -> Result<Self, DurableEventEvidenceError> {
        Self::new(
            plan.registrations()
                .iter()
                .map(|registration| {
                    DurableSinkObligationV1::new(
                        registration.id().clone(),
                        registration.policy().clone(),
                    )
                })
                .collect(),
        )
    }

    /// Returns obligations in canonical sink-ID order.
    #[must_use]
    pub fn obligations(&self) -> &[DurableSinkObligationV1] {
        &self.0
    }

    /// Finds one captured obligation by stable sink identity.
    #[must_use]
    pub fn obligation(&self, sink_id: &SinkId) -> Option<&DurableSinkObligationV1> {
        self.0
            .binary_search_by(|candidate| candidate.sink_id.as_str().cmp(sink_id.as_str()))
            .ok()
            .and_then(|index| self.0.get(index))
    }

    /// Excludes one exhausted sink only from later termination-consequence events.
    #[must_use]
    pub fn without_sink(&self, sink_id: &SinkId) -> Self {
        Self(
            self.0
                .iter()
                .filter(|obligation| obligation.sink_id() != sink_id)
                .cloned()
                .collect(),
        )
    }
}

/// One completed execution event and the obligations frozen at its creation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableEventOccurrenceV1 {
    causal_evidence_id: ProtocolIdentity,
    event: EventEnvelope,
    plan: DurableEventPlanV1,
}

impl DurableEventOccurrenceV1 {
    /// Constructs one journal-first execution event occurrence.
    pub fn new(
        causal_evidence_id: ProtocolIdentity,
        event: EventEnvelope,
        plan: DurableEventPlanV1,
    ) -> Result<Self, DurableEventEvidenceError> {
        if causal_evidence_id.kind() != IdentityKind::Evidence {
            return Err(DurableEventEvidenceError::InvalidCausalEvidence);
        }
        if event.execution_id().is_none() {
            return Err(DurableEventEvidenceError::MissingExecutionIdentity);
        }
        Ok(Self {
            causal_evidence_id,
            event,
            plan,
        })
    }

    /// Returns the durable interpreter transition represented by this event.
    #[must_use]
    pub const fn causal_evidence_id(&self) -> ProtocolIdentity {
        self.causal_evidence_id
    }

    /// Returns the immutable standard event envelope.
    #[must_use]
    pub const fn event(&self) -> &EventEnvelope {
        &self.event
    }

    /// Returns the immutable initial delivery plan.
    #[must_use]
    pub const fn plan(&self) -> &DurableEventPlanV1 {
        &self.plan
    }

    /// Encodes the unique canonical version-one journal body.
    #[must_use]
    pub fn canonical_body(&self) -> Vec<u8> {
        let mut output = String::from("{\"causal_evidence_id\":");
        push_json_string(&mut output, &self.causal_evidence_id.to_string());
        output.push_str(",\"event\":");
        push_event(&mut output, &self.event);
        output.push_str(",\"format\":\"gantry.event-occurrence/v1\",\"plan\":[");
        for (index, obligation) in self.plan.obligations().iter().enumerate() {
            if index > 0 {
                output.push(',');
            }
            push_obligation(&mut output, obligation);
        }
        output.push_str("]}");
        output.into_bytes()
    }

    /// Decodes one exact canonical version-one journal body.
    pub fn decode(body: &[u8]) -> Result<Self, DurableEventEvidenceError> {
        let document = decode_document(body)?;
        let root = object(&document, document.root())?;
        require_exact_fields(root, &["causal_evidence_id", "event", "format", "plan"])?;
        if string(&document, field(root, "format")?)? != DURABLE_EVENT_OCCURRENCE_KIND_V1 {
            return Err(DurableEventEvidenceError::Encoding);
        }
        let causal_evidence_id = identity(
            &document,
            field(root, "causal_evidence_id")?,
            Some(IdentityKind::Evidence),
        )?;
        let event = decode_event(&document, field(root, "event")?)?;
        let plan = decode_plan(&document, field(root, "plan")?)?;
        let occurrence = Self::new(causal_evidence_id, event, plan)?;
        if occurrence.canonical_body() != body {
            return Err(DurableEventEvidenceError::Encoding);
        }
        Ok(occurrence)
    }

    /// Builds one occurrence evidence body and its atomically stored payload entries.
    pub fn unfinalized(
        &self,
        batch_local_id: BatchLocalEvidenceId,
        causal_evidence: impl Into<Arc<[JournalEvidenceReferenceV1]>>,
        payloads: &[ProtectedPayload],
    ) -> Result<(UnfinalizedEvidenceV1, Vec<JournalProtectedPayloadV1>), DurableEventEvidenceError>
    {
        let causal_evidence = causal_evidence.into();
        if causal_evidence.is_empty()
            || causal_evidence.iter().any(|reference| {
                matches!(reference, JournalEvidenceReferenceV1::Existing(identity) if identity.kind() != IdentityKind::Evidence)
            })
            || !causal_evidence.iter().any(|reference| {
                matches!(reference, JournalEvidenceReferenceV1::Existing(identity) if *identity == self.causal_evidence_id)
            })
        {
            return Err(DurableEventEvidenceError::InvalidCausalEvidence);
        }
        let payloads = validate_payloads(self.event.protected_references(), payloads)?;
        let payload_keys = self
            .event
            .protected_references()
            .iter()
            .map(|reference| {
                JournalPayloadKey::new(reference.key()).map_err(DurableEventEvidenceError::Journal)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let evidence = UnfinalizedEvidenceV1::new(
            batch_local_id,
            DURABLE_EVENT_OCCURRENCE_KIND_V1,
            self.canonical_body(),
            causal_evidence,
            payload_keys,
        )
        .map_err(DurableEventEvidenceError::Journal)?;
        Ok((evidence, payloads))
    }
}

/// Durable state committed immediately before one physical event delivery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableEventDispatchedV1 {
    event_id: ProtocolIdentity,
    sink_id: SinkId,
    attempt_id: ProtocolIdentity,
    retry_number: u64,
}

impl DurableEventDispatchedV1 {
    /// Constructs one validated pre-invocation delivery state.
    pub fn new(
        event_id: ProtocolIdentity,
        sink_id: SinkId,
        attempt_id: ProtocolIdentity,
        retry_number: u64,
    ) -> Result<Self, DurableEventEvidenceError> {
        if event_id.kind() != IdentityKind::Event
            || attempt_id.kind() != IdentityKind::DeliveryAttempt
        {
            return Err(DurableEventEvidenceError::InvalidDelivery);
        }
        Ok(Self {
            event_id,
            sink_id,
            attempt_id,
            retry_number,
        })
    }

    /// Returns the stable event identity reused by every retry.
    #[must_use]
    pub const fn event_id(&self) -> ProtocolIdentity {
        self.event_id
    }

    /// Returns the captured sink identity.
    #[must_use]
    pub const fn sink_id(&self) -> &SinkId {
        &self.sink_id
    }

    /// Returns this physical attempt's distinct identity.
    #[must_use]
    pub const fn attempt_id(&self) -> ProtocolIdentity {
        self.attempt_id
    }

    /// Returns the zero-based retry number.
    #[must_use]
    pub const fn retry_number(&self) -> u64 {
        self.retry_number
    }

    /// Encodes the unique canonical version-one journal body.
    #[must_use]
    pub fn canonical_body(&self) -> Vec<u8> {
        let mut output = String::from("{\"attempt_id\":");
        push_json_string(&mut output, &self.attempt_id.to_string());
        output.push_str(",\"event_id\":");
        push_json_string(&mut output, &self.event_id.to_string());
        output.push_str(",\"format\":\"gantry.event-delivery-dispatched/v1\",\"retry_number\":");
        output.push_str(&self.retry_number.to_string());
        output.push_str(",\"sink_id\":");
        push_json_string(&mut output, self.sink_id.as_str());
        output.push('}');
        output.into_bytes()
    }

    /// Decodes one exact canonical version-one dispatched body.
    pub fn decode(body: &[u8]) -> Result<Self, DurableEventEvidenceError> {
        let document = decode_document(body)?;
        let root = object(&document, document.root())?;
        require_exact_fields(
            root,
            &[
                "attempt_id",
                "event_id",
                "format",
                "retry_number",
                "sink_id",
            ],
        )?;
        if string(&document, field(root, "format")?)? != DURABLE_EVENT_DISPATCHED_KIND_V1 {
            return Err(DurableEventEvidenceError::Encoding);
        }
        let value = Self::new(
            identity(
                &document,
                field(root, "event_id")?,
                Some(IdentityKind::Event),
            )?,
            SinkId::new(string(&document, field(root, "sink_id")?)?)
                .map_err(|_| DurableEventEvidenceError::Encoding)?,
            identity(
                &document,
                field(root, "attempt_id")?,
                Some(IdentityKind::DeliveryAttempt),
            )?,
            unsigned(&document, field(root, "retry_number")?)?,
        )?;
        if value.canonical_body() != body {
            return Err(DurableEventEvidenceError::Encoding);
        }
        Ok(value)
    }

    /// Builds one journal body referencing its occurrence and causal predecessor.
    pub fn unfinalized(
        &self,
        batch_local_id: BatchLocalEvidenceId,
        references: impl Into<Arc<[JournalEvidenceReferenceV1]>>,
    ) -> Result<UnfinalizedEvidenceV1, DurableEventEvidenceError> {
        delivery_body(
            batch_local_id,
            DURABLE_EVENT_DISPATCHED_KIND_V1,
            self.canonical_body(),
            references,
        )
    }
}

/// Durable outcome committed after one physical event delivery returns.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableEventSettledV1 {
    event_id: ProtocolIdentity,
    sink_id: SinkId,
    attempt_id: ProtocolIdentity,
    retry_number: u64,
    outcome: DeliveryOutcome,
    remaining_retries: u64,
    selected_delay_us: Option<u64>,
}

impl DurableEventSettledV1 {
    /// Constructs one validated post-invocation delivery state.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        event_id: ProtocolIdentity,
        sink_id: SinkId,
        attempt_id: ProtocolIdentity,
        retry_number: u64,
        outcome: DeliveryOutcome,
        remaining_retries: u64,
        selected_delay_us: Option<u64>,
    ) -> Result<Self, DurableEventEvidenceError> {
        if event_id.kind() != IdentityKind::Event
            || attempt_id.kind() != IdentityKind::DeliveryAttempt
            || (outcome == DeliveryOutcome::Retriable)
                != (remaining_retries > 0 && selected_delay_us.is_some())
            || (outcome != DeliveryOutcome::Retriable && selected_delay_us.is_some())
        {
            return Err(DurableEventEvidenceError::InvalidDelivery);
        }
        Ok(Self {
            event_id,
            sink_id,
            attempt_id,
            retry_number,
            outcome,
            remaining_retries,
            selected_delay_us,
        })
    }

    /// Returns the stable event identity reused by every retry.
    #[must_use]
    pub const fn event_id(&self) -> ProtocolIdentity {
        self.event_id
    }

    /// Returns the captured sink identity.
    #[must_use]
    pub const fn sink_id(&self) -> &SinkId {
        &self.sink_id
    }

    /// Returns this physical attempt's distinct identity.
    #[must_use]
    pub const fn attempt_id(&self) -> ProtocolIdentity {
        self.attempt_id
    }

    /// Returns the zero-based retry number.
    #[must_use]
    pub const fn retry_number(&self) -> u64 {
        self.retry_number
    }

    /// Returns the durable sink outcome classification.
    #[must_use]
    pub const fn outcome(&self) -> DeliveryOutcome {
        self.outcome
    }

    /// Returns the remaining known-retriable failure budget.
    #[must_use]
    pub const fn remaining_retries(&self) -> u64 {
        self.remaining_retries
    }

    /// Returns the selected retry delay committed before sleeping.
    #[must_use]
    pub const fn selected_delay_us(&self) -> Option<u64> {
        self.selected_delay_us
    }

    /// Encodes the unique canonical version-one journal body.
    #[must_use]
    pub fn canonical_body(&self) -> Vec<u8> {
        let mut output = String::from("{\"attempt_id\":");
        push_json_string(&mut output, &self.attempt_id.to_string());
        output.push_str(",\"event_id\":");
        push_json_string(&mut output, &self.event_id.to_string());
        output.push_str(",\"format\":\"gantry.event-delivery-settled/v1\",\"outcome\":");
        push_json_string(&mut output, self.outcome.wire_name());
        output.push_str(",\"remaining_retries\":");
        output.push_str(&self.remaining_retries.to_string());
        output.push_str(",\"retry_number\":");
        output.push_str(&self.retry_number.to_string());
        output.push_str(",\"selected_delay_us\":");
        push_optional_u64(&mut output, self.selected_delay_us);
        output.push_str(",\"sink_id\":");
        push_json_string(&mut output, self.sink_id.as_str());
        output.push('}');
        output.into_bytes()
    }

    /// Decodes one exact canonical version-one settled body.
    pub fn decode(body: &[u8]) -> Result<Self, DurableEventEvidenceError> {
        let document = decode_document(body)?;
        let root = object(&document, document.root())?;
        require_exact_fields(
            root,
            &[
                "attempt_id",
                "event_id",
                "format",
                "outcome",
                "remaining_retries",
                "retry_number",
                "selected_delay_us",
                "sink_id",
            ],
        )?;
        if string(&document, field(root, "format")?)? != DURABLE_EVENT_SETTLED_KIND_V1 {
            return Err(DurableEventEvidenceError::Encoding);
        }
        let value = Self::new(
            identity(
                &document,
                field(root, "event_id")?,
                Some(IdentityKind::Event),
            )?,
            SinkId::new(string(&document, field(root, "sink_id")?)?)
                .map_err(|_| DurableEventEvidenceError::Encoding)?,
            identity(
                &document,
                field(root, "attempt_id")?,
                Some(IdentityKind::DeliveryAttempt),
            )?,
            unsigned(&document, field(root, "retry_number")?)?,
            DeliveryOutcome::from_wire_name(string(&document, field(root, "outcome")?)?)
                .ok_or(DurableEventEvidenceError::Encoding)?,
            unsigned(&document, field(root, "remaining_retries")?)?,
            optional_unsigned(&document, field(root, "selected_delay_us")?)?,
        )?;
        if value.canonical_body() != body {
            return Err(DurableEventEvidenceError::Encoding);
        }
        Ok(value)
    }

    /// Builds one journal body referencing its occurrence, dispatch, and predecessor.
    pub fn unfinalized(
        &self,
        batch_local_id: BatchLocalEvidenceId,
        references: impl Into<Arc<[JournalEvidenceReferenceV1]>>,
    ) -> Result<UnfinalizedEvidenceV1, DurableEventEvidenceError> {
        delivery_body(
            batch_local_id,
            DURABLE_EVENT_SETTLED_KIND_V1,
            self.canonical_body(),
            references,
        )
    }
}

/// Recovery action for one captured sink obligation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DurableDeliveryRecoveryV1 {
    /// The initial or next known retry has not been dispatched durably.
    Pending {
        /// Retry number to dispatch after any already recorded delay.
        retry_number: u64,
    },
    /// A committed dispatch lacks settlement and must be redelivered at the same retry number.
    Indeterminate {
        /// Last indeterminate physical attempt identity.
        previous_attempt_id: ProtocolIdentity,
        /// Retry number that must not consume budget during redelivery.
        retry_number: u64,
    },
    /// A known retriable failure fixed its delay before a later dispatch.
    RetryDelay {
        /// Next retry number after the known failure consumed one attempt.
        retry_number: u64,
        /// Complete selected delay that recovery waits again without resampling.
        delay_us: u64,
        /// Remaining known-retriable failures, including this next retry.
        remaining_retries: u64,
    },
    /// Delivery succeeded durably and must not be repeated.
    Success {
        /// Final successful physical attempt.
        attempt_id: ProtocolIdentity,
    },
    /// Delivery exhausted durably and must not be repeated.
    Terminal {
        /// Final terminal physical attempt.
        attempt_id: ProtocolIdentity,
    },
}

/// One recovered event occurrence and all of its captured sink obligations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveredDurableEventV1 {
    occurrence_evidence_id: ProtocolIdentity,
    occurrence_sequence: u64,
    occurrence: DurableEventOccurrenceV1,
    deliveries: BTreeMap<SinkId, DurableDeliveryRecoveryV1>,
}

impl RecoveredDurableEventV1 {
    /// Returns the storage-assigned occurrence evidence identity.
    #[must_use]
    pub const fn occurrence_evidence_id(&self) -> ProtocolIdentity {
        self.occurrence_evidence_id
    }

    /// Returns the journal sequence at which the occurrence became authoritative.
    #[must_use]
    pub const fn occurrence_sequence(&self) -> u64 {
        self.occurrence_sequence
    }

    /// Returns the exact committed occurrence and frozen plan.
    #[must_use]
    pub const fn occurrence(&self) -> &DurableEventOccurrenceV1 {
        &self.occurrence
    }

    /// Returns recovery state for each sink in canonical identity order.
    #[must_use]
    pub const fn deliveries(&self) -> &BTreeMap<SinkId, DurableDeliveryRecoveryV1> {
        &self.deliveries
    }
}

/// Required-delivery status projected independently of the language outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DurableEventBarrierV1 {
    /// Every required obligation through the selected frontier succeeded.
    Delivered,
    /// At least one required obligation remains eligible for delivery or retry.
    Pending {
        /// Earliest event with an unsettled required obligation.
        event_id: ProtocolIdentity,
        /// Canonically first unsettled required sink for that event.
        sink_id: SinkId,
    },
    /// A required obligation terminally exhausted.
    RequiredExhausted(RequiredEventDeliveryFailureV1),
}

/// Evidence and payload keys that a safe event compaction must retain.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DurableEventRetentionV1 {
    evidence_ids: BTreeSet<ProtocolIdentity>,
    payload_keys: BTreeSet<JournalPayloadKey>,
}

impl DurableEventRetentionV1 {
    /// Returns every event evidence identity needed to reproduce recovery state.
    #[must_use]
    pub const fn evidence_ids(&self) -> &BTreeSet<ProtocolIdentity> {
        &self.evidence_ids
    }

    /// Returns every protected payload key referenced by retained occurrences.
    #[must_use]
    pub const fn payload_keys(&self) -> &BTreeSet<JournalPayloadKey> {
        &self.payload_keys
    }

    /// Rejects a proposed compaction that would leave event recovery dangling.
    pub fn validate_retained(
        &self,
        retained_evidence: &BTreeSet<ProtocolIdentity>,
        retained_payloads: &BTreeSet<JournalPayloadKey>,
    ) -> Result<(), DurableEventEvidenceError> {
        if self.evidence_ids.is_subset(retained_evidence)
            && self.payload_keys.is_subset(retained_payloads)
        {
            Ok(())
        } else {
            Err(DurableEventEvidenceError::CompactionWouldDangle)
        }
    }
}

/// Recovered durable event stream independent of current sink configuration.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RecoveredDurableEventsV1 {
    events: BTreeMap<ProtocolIdentity, RecoveredDurableEventV1>,
    occurrence_evidence: BTreeMap<ProtocolIdentity, ProtocolIdentity>,
    causal_occurrences: BTreeMap<ProtocolIdentity, ProtocolIdentity>,
    dispatch_evidence: BTreeMap<ProtocolIdentity, (ProtocolIdentity, SinkId, ProtocolIdentity)>,
    attempt_ids: BTreeMap<ProtocolIdentity, ProtocolIdentity>,
    event_evidence: BTreeSet<ProtocolIdentity>,
    payload_keys: BTreeSet<JournalPayloadKey>,
}

impl RecoveredDurableEventsV1 {
    /// Returns occurrences in stable event-ID order.
    #[must_use]
    pub const fn events(&self) -> &BTreeMap<ProtocolIdentity, RecoveredDurableEventV1> {
        &self.events
    }

    /// Returns the committed occurrence for one durable causal transition.
    #[must_use]
    pub fn event_for_cause(
        &self,
        causal_evidence_id: ProtocolIdentity,
    ) -> Option<&RecoveredDurableEventV1> {
        self.causal_occurrences
            .get(&causal_evidence_id)
            .and_then(|event_id| self.events.get(event_id))
    }

    /// Reports whether recovery must create the sole replacement for a causal gap.
    #[must_use]
    pub fn requires_replacement(&self, causal_evidence_id: ProtocolIdentity) -> bool {
        causal_evidence_id.kind() == IdentityKind::Evidence
            && !self.causal_occurrences.contains_key(&causal_evidence_id)
    }

    /// Projects the required-sink barrier through an inclusive occurrence sequence.
    #[must_use]
    pub fn required_barrier_through(&self, sequence: u64) -> DurableEventBarrierV1 {
        let mut obligations = self
            .events
            .values()
            .filter(|event| event.occurrence_sequence <= sequence)
            .flat_map(|event| {
                event
                    .deliveries
                    .iter()
                    .filter_map(move |(sink_id, delivery)| {
                        event
                            .occurrence
                            .plan()
                            .obligation(sink_id)
                            .filter(|obligation| obligation.policy().class == SinkClass::Required)
                            .map(|_| {
                                (
                                    event.occurrence_sequence,
                                    event.occurrence.event().event_id(),
                                    sink_id,
                                    delivery,
                                )
                            })
                    })
            })
            .collect::<Vec<_>>();
        obligations
            .sort_by(|left, right| (left.0, left.2.as_str()).cmp(&(right.0, right.2.as_str())));
        for (_, event_id, sink_id, delivery) in obligations {
            match delivery {
                DurableDeliveryRecoveryV1::Success { .. } => {}
                DurableDeliveryRecoveryV1::Terminal { attempt_id } => {
                    return DurableEventBarrierV1::RequiredExhausted(
                        RequiredEventDeliveryFailureV1 {
                            sink_id: sink_id.clone(),
                            event_id,
                            attempt_id: *attempt_id,
                        },
                    );
                }
                DurableDeliveryRecoveryV1::Pending { .. }
                | DurableDeliveryRecoveryV1::Indeterminate { .. }
                | DurableDeliveryRecoveryV1::RetryDelay { .. } => {
                    return DurableEventBarrierV1::Pending {
                        event_id,
                        sink_id: sink_id.clone(),
                    };
                }
            }
        }
        DurableEventBarrierV1::Delivered
    }

    /// Returns the conservative retention set for an equivalent event projection.
    #[must_use]
    pub fn retention(&self) -> DurableEventRetentionV1 {
        DurableEventRetentionV1 {
            evidence_ids: self.event_evidence.clone(),
            payload_keys: self.payload_keys.clone(),
        }
    }

    pub(crate) fn apply_envelope(
        &mut self,
        envelope: &JournalEvidenceEnvelopeV1,
    ) -> Result<(), DurableEventEvidenceError> {
        let result = match envelope.kind.as_ref() {
            DURABLE_EVENT_OCCURRENCE_KIND_V1 => self.apply_occurrence(envelope),
            DURABLE_EVENT_DISPATCHED_KIND_V1 => self.apply_dispatched(envelope),
            DURABLE_EVENT_SETTLED_KIND_V1 => self.apply_settled(envelope),
            _ => Err(DurableEventEvidenceError::Encoding),
        };
        if result.is_ok() && !self.event_evidence.insert(envelope.evidence_id) {
            return Err(DurableEventEvidenceError::InvalidDeliveryHistory);
        }
        result
    }

    fn apply_occurrence(
        &mut self,
        envelope: &JournalEvidenceEnvelopeV1,
    ) -> Result<(), DurableEventEvidenceError> {
        let occurrence = DurableEventOccurrenceV1::decode(&envelope.canonical_body)?;
        let event_id = occurrence.event().event_id();
        let expected_payloads = occurrence
            .event()
            .protected_references()
            .iter()
            .map(|reference| reference.key())
            .collect::<Vec<_>>();
        let actual_payloads = envelope
            .protected_payloads
            .iter()
            .map(JournalPayloadKey::as_str)
            .collect::<Vec<_>>();
        if expected_payloads != actual_payloads
            || self.events.contains_key(&event_id)
            || self.occurrence_evidence.contains_key(&envelope.evidence_id)
            || self
                .causal_occurrences
                .contains_key(&occurrence.causal_evidence_id())
        {
            return Err(DurableEventEvidenceError::InvalidDeliveryHistory);
        }
        let deliveries = occurrence
            .plan()
            .obligations()
            .iter()
            .map(|obligation| {
                (
                    obligation.sink_id().clone(),
                    DurableDeliveryRecoveryV1::Pending { retry_number: 0 },
                )
            })
            .collect();
        self.occurrence_evidence
            .insert(envelope.evidence_id, event_id);
        self.causal_occurrences
            .insert(occurrence.causal_evidence_id(), event_id);
        self.payload_keys
            .extend(envelope.protected_payloads.iter().cloned());
        self.events.insert(
            event_id,
            RecoveredDurableEventV1 {
                occurrence_evidence_id: envelope.evidence_id,
                occurrence_sequence: envelope.sequence,
                occurrence,
                deliveries,
            },
        );
        Ok(())
    }

    fn apply_dispatched(
        &mut self,
        envelope: &JournalEvidenceEnvelopeV1,
    ) -> Result<(), DurableEventEvidenceError> {
        if !envelope.protected_payloads.is_empty() {
            return Err(DurableEventEvidenceError::InvalidDeliveryHistory);
        }
        let dispatched = DurableEventDispatchedV1::decode(&envelope.canonical_body)?;
        let event = self
            .events
            .get_mut(&dispatched.event_id)
            .ok_or(DurableEventEvidenceError::InvalidDeliveryHistory)?;
        if !envelope.references.contains(&event.occurrence_evidence_id)
            || self.attempt_ids.contains_key(&dispatched.attempt_id)
        {
            return Err(DurableEventEvidenceError::InvalidDeliveryHistory);
        }
        let delivery = event
            .deliveries
            .get_mut(&dispatched.sink_id)
            .ok_or(DurableEventEvidenceError::InvalidDeliveryHistory)?;
        let allowed = match delivery {
            DurableDeliveryRecoveryV1::Pending { retry_number }
            | DurableDeliveryRecoveryV1::Indeterminate { retry_number, .. } => {
                *retry_number == dispatched.retry_number
            }
            DurableDeliveryRecoveryV1::RetryDelay { retry_number, .. } => {
                *retry_number == dispatched.retry_number
            }
            DurableDeliveryRecoveryV1::Success { .. }
            | DurableDeliveryRecoveryV1::Terminal { .. } => false,
        };
        if !allowed {
            return Err(DurableEventEvidenceError::InvalidDeliveryHistory);
        }
        *delivery = DurableDeliveryRecoveryV1::Indeterminate {
            previous_attempt_id: dispatched.attempt_id,
            retry_number: dispatched.retry_number,
        };
        self.attempt_ids
            .insert(dispatched.attempt_id, dispatched.event_id);
        self.dispatch_evidence.insert(
            envelope.evidence_id,
            (
                dispatched.event_id,
                dispatched.sink_id,
                dispatched.attempt_id,
            ),
        );
        Ok(())
    }

    fn apply_settled(
        &mut self,
        envelope: &JournalEvidenceEnvelopeV1,
    ) -> Result<(), DurableEventEvidenceError> {
        if !envelope.protected_payloads.is_empty() {
            return Err(DurableEventEvidenceError::InvalidDeliveryHistory);
        }
        let settled = DurableEventSettledV1::decode(&envelope.canonical_body)?;
        let event = self
            .events
            .get_mut(&settled.event_id)
            .ok_or(DurableEventEvidenceError::InvalidDeliveryHistory)?;
        let dispatch_reference = envelope.references.iter().find_map(|reference| {
            self.dispatch_evidence
                .get(reference)
                .filter(|(event_id, sink_id, attempt_id)| {
                    *event_id == settled.event_id
                        && sink_id == &settled.sink_id
                        && *attempt_id == settled.attempt_id
                })
        });
        if !envelope.references.contains(&event.occurrence_evidence_id)
            || dispatch_reference.is_none()
        {
            return Err(DurableEventEvidenceError::InvalidDeliveryHistory);
        }
        let obligation = event
            .occurrence
            .plan()
            .obligation(&settled.sink_id)
            .ok_or(DurableEventEvidenceError::InvalidDeliveryHistory)?;
        let expected_remaining = obligation
            .policy()
            .retry
            .retry_limit
            .saturating_sub(settled.retry_number);
        let delivery = event
            .deliveries
            .get_mut(&settled.sink_id)
            .ok_or(DurableEventEvidenceError::InvalidDeliveryHistory)?;
        if !matches!(
            delivery,
            DurableDeliveryRecoveryV1::Indeterminate {
                previous_attempt_id,
                retry_number,
            } if *previous_attempt_id == settled.attempt_id && *retry_number == settled.retry_number
        ) || settled.remaining_retries != expected_remaining
        {
            return Err(DurableEventEvidenceError::InvalidDeliveryHistory);
        }
        *delivery = match settled.outcome {
            DeliveryOutcome::Success => DurableDeliveryRecoveryV1::Success {
                attempt_id: settled.attempt_id,
            },
            DeliveryOutcome::Terminal => DurableDeliveryRecoveryV1::Terminal {
                attempt_id: settled.attempt_id,
            },
            DeliveryOutcome::Retriable => DurableDeliveryRecoveryV1::RetryDelay {
                retry_number: settled
                    .retry_number
                    .checked_add(1)
                    .ok_or(DurableEventEvidenceError::InvalidDeliveryHistory)?,
                delay_us: settled
                    .selected_delay_us
                    .ok_or(DurableEventEvidenceError::InvalidDeliveryHistory)?,
                remaining_retries: settled.remaining_retries,
            },
        };
        Ok(())
    }
}

fn delivery_body(
    batch_local_id: BatchLocalEvidenceId,
    kind: &'static str,
    canonical_body: Vec<u8>,
    references: impl Into<Arc<[JournalEvidenceReferenceV1]>>,
) -> Result<UnfinalizedEvidenceV1, DurableEventEvidenceError> {
    let references = references.into();
    if references.is_empty()
        || references.iter().any(|reference| {
            matches!(reference, JournalEvidenceReferenceV1::Existing(identity) if identity.kind() != IdentityKind::Evidence)
        })
    {
        return Err(DurableEventEvidenceError::InvalidCausalEvidence);
    }
    UnfinalizedEvidenceV1::new(
        batch_local_id,
        kind,
        canonical_body,
        references,
        Arc::from([]),
    )
    .map_err(DurableEventEvidenceError::Journal)
}

/// Invalid durable event occurrence, plan, or protected payload input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DurableEventEvidenceError {
    /// The evidence body is malformed, noncanonical, or uses an unsupported version.
    Encoding,
    /// Two obligations used the same stable sink identity.
    DuplicateSink,
    /// A journaled execution event omitted its execution identity.
    MissingExecutionIdentity,
    /// The event occurrence has no valid causal evidence reference.
    InvalidCausalEvidence,
    /// Two supplied protected payloads used the same stable key.
    DuplicatePayload,
    /// A protected event reference had no supplied bytes.
    MissingPayload,
    /// Supplied bytes did not correspond to an event reference.
    UnreferencedPayload,
    /// Supplied bytes and the event envelope disagreed on permission class.
    PayloadClassMismatch,
    /// Delivery identities, outcome fields, or retry state are inconsistent.
    InvalidDelivery,
    /// Delivery evidence does not refine a committed occurrence and frozen plan.
    InvalidDeliveryHistory,
    /// A proposed compaction would remove required event evidence or payloads.
    CompactionWouldDangle,
    /// The backend-neutral journal body contract rejected construction.
    Journal(JournalContractError),
}

impl fmt::Display for DurableEventEvidenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Encoding => "durable event evidence is not canonical version-one data",
            Self::DuplicateSink => "durable event plan contains a duplicate sink identity",
            Self::MissingExecutionIdentity => {
                "durable event occurrence is missing its execution identity"
            }
            Self::InvalidCausalEvidence => "durable event occurrence has invalid causal evidence",
            Self::DuplicatePayload => "durable event payload key is duplicated",
            Self::MissingPayload => "durable event reference has no protected payload",
            Self::UnreferencedPayload => "durable event payload is not referenced by the event",
            Self::PayloadClassMismatch => {
                "durable event payload class differs from its protected reference"
            }
            Self::InvalidDelivery => "durable event delivery state is inconsistent",
            Self::InvalidDeliveryHistory => {
                "durable event delivery history violates its frozen obligation"
            }
            Self::CompactionWouldDangle => {
                "durable event compaction would leave dangling recovery state"
            }
            Self::Journal(_) => "durable event evidence violates the journal contract",
        })
    }
}

impl std::error::Error for DurableEventEvidenceError {}

fn decode_event(
    document: &StrictJsonDocument,
    id: JsonNodeId,
) -> Result<EventEnvelope, DurableEventEvidenceError> {
    let value = object(document, id)?;
    require_exact_fields(
        value,
        &[
            "activity_id",
            "causal_ids",
            "event_id",
            "execution_id",
            "kind",
            "layer",
            "operation_id",
            "payload",
            "per_task_sequence",
            "protected_references",
            "source",
            "task_id",
            "timestamp",
            "version",
        ],
    )?;
    let version = object(document, field(value, "version")?)?;
    require_exact_fields(version, &["major", "minor"])?;
    if unsigned(document, field(version, "major")?)? != 1
        || unsigned(document, field(version, "minor")?)? != 0
    {
        return Err(DurableEventEvidenceError::Encoding);
    }
    let kind = EventKind::from_wire_name(string(document, field(value, "kind")?)?)
        .ok_or(DurableEventEvidenceError::Encoding)?;
    if string(document, field(value, "layer")?)? != kind.layer().wire_name() {
        return Err(DurableEventEvidenceError::Encoding);
    }
    let payload = EventPayload::from_validated_canonical_bytes(Arc::<[u8]>::from(decode_hex(
        string(document, field(value, "payload")?)?,
    )?))
    .map_err(|_| DurableEventEvidenceError::Encoding)?;
    let mut draft = EventDraft::new(kind, payload);
    if let Some(execution_id) = optional_identity(
        document,
        field(value, "execution_id")?,
        Some(IdentityKind::Execution),
    )? {
        draft = draft
            .with_execution_id(execution_id)
            .map_err(|_| DurableEventEvidenceError::Encoding)?;
    }
    if let Some(source) = optional_source(document, field(value, "source")?)? {
        draft = draft.with_source(source);
    }
    let task_id = optional_identity(document, field(value, "task_id")?, Some(IdentityKind::Task))?;
    let task_sequence = optional_unsigned(document, field(value, "per_task_sequence")?)?;
    match (task_id, task_sequence) {
        (Some(task_id), Some(sequence)) => {
            draft = draft
                .with_task(task_id, sequence)
                .map_err(|_| DurableEventEvidenceError::Encoding)?;
        }
        (None, None) => {}
        _ => return Err(DurableEventEvidenceError::Encoding),
    }
    if let Some(operation_id) = optional_identity(
        document,
        field(value, "operation_id")?,
        Some(IdentityKind::Operation),
    )? {
        draft = draft
            .with_operation_id(operation_id)
            .map_err(|_| DurableEventEvidenceError::Encoding)?;
    }
    draft = draft.with_causal_ids(identity_array(document, field(value, "causal_ids")?)?);
    draft = draft
        .with_protected_references(protected_references(
            document,
            field(value, "protected_references")?,
        )?)
        .map_err(|_| DurableEventEvidenceError::Encoding)?;
    let event_id = identity(
        document,
        field(value, "event_id")?,
        Some(IdentityKind::Event),
    )?;
    let activity_id = identity(
        document,
        field(value, "activity_id")?,
        Some(IdentityKind::Activity),
    )?;
    let timestamp = UtcTimestamp::parse(string(document, field(value, "timestamp")?)?)
        .map_err(|_| DurableEventEvidenceError::Encoding)?;
    EventEnvelope::complete(event_id, activity_id, timestamp, draft)
        .map_err(|_| DurableEventEvidenceError::Encoding)
}

fn decode_plan(
    document: &StrictJsonDocument,
    id: JsonNodeId,
) -> Result<DurableEventPlanV1, DurableEventEvidenceError> {
    let Some(JsonNode::Array(items)) = document.node(id) else {
        return Err(DurableEventEvidenceError::Encoding);
    };
    let obligations = items
        .iter()
        .map(|item| {
            let value = object(document, *item)?;
            require_exact_fields(
                value,
                &[
                    "attempt_timeout_us",
                    "capabilities",
                    "class",
                    "jitter",
                    "raw_output",
                    "redaction_policy_id",
                    "retry_cap_us",
                    "retry_initial_delay_us",
                    "retry_limit",
                    "retry_revision",
                    "sink_id",
                ],
            )?;
            let capabilities = object(document, field(value, "capabilities")?)?;
            require_exact_fields(
                capabilities,
                &[
                    "integration_diagnostics",
                    "operation_request_content",
                    "operation_result_content",
                    "source_snippets",
                ],
            )?;
            let retry = EventRetryPolicy::new(
                string(document, field(value, "retry_revision")?)?,
                unsigned(document, field(value, "retry_limit")?)?,
                unsigned(document, field(value, "retry_initial_delay_us")?)?,
                unsigned(document, field(value, "retry_cap_us")?)?,
                JitterMode::from_wire_name(string(document, field(value, "jitter")?)?)
                    .ok_or(DurableEventEvidenceError::Encoding)?,
            )
            .map_err(|_| DurableEventEvidenceError::Encoding)?;
            let policy = SinkDeliveryPolicy::new(
                SinkClass::from_wire_name(string(document, field(value, "class")?)?)
                    .ok_or(DurableEventEvidenceError::Encoding)?,
                boolean(document, field(value, "raw_output")?)?,
                string(document, field(value, "redaction_policy_id")?)?,
                RedactionCapabilities {
                    operation_request_content: boolean(
                        document,
                        field(capabilities, "operation_request_content")?,
                    )?,
                    operation_result_content: boolean(
                        document,
                        field(capabilities, "operation_result_content")?,
                    )?,
                    integration_diagnostics: boolean(
                        document,
                        field(capabilities, "integration_diagnostics")?,
                    )?,
                    source_snippets: boolean(document, field(capabilities, "source_snippets")?)?,
                },
                retry,
                unsigned(document, field(value, "attempt_timeout_us")?)?,
            )
            .map_err(|_| DurableEventEvidenceError::Encoding)?;
            Ok(DurableSinkObligationV1::new(
                SinkId::new(string(document, field(value, "sink_id")?)?)
                    .map_err(|_| DurableEventEvidenceError::Encoding)?,
                policy,
            ))
        })
        .collect::<Result<Vec<_>, _>>()?;
    DurableEventPlanV1::new(obligations)
}

fn optional_source(
    document: &StrictJsonDocument,
    id: JsonNodeId,
) -> Result<Option<SourceSpan>, DurableEventEvidenceError> {
    if matches!(document.node(id), Some(JsonNode::Null)) {
        return Ok(None);
    }
    let value = object(document, id)?;
    require_exact_fields(value, &["end", "path", "start"])?;
    SourceSpan::from_portable_parts(
        string(document, field(value, "path")?)?,
        unsigned(document, field(value, "start")?)?,
        unsigned(document, field(value, "end")?)?,
    )
    .map(Some)
    .map_err(|_| DurableEventEvidenceError::Encoding)
}

fn protected_references(
    document: &StrictJsonDocument,
    id: JsonNodeId,
) -> Result<Vec<ProtectedReference>, DurableEventEvidenceError> {
    let Some(JsonNode::Array(items)) = document.node(id) else {
        return Err(DurableEventEvidenceError::Encoding);
    };
    items
        .iter()
        .map(|item| {
            let value = object(document, *item)?;
            require_exact_fields(value, &["class", "key"])?;
            ProtectedReference::new(
                string(document, field(value, "key")?)?,
                ProtectedReferenceClass::from_wire_name(string(document, field(value, "class")?)?)
                    .ok_or(DurableEventEvidenceError::Encoding)?,
            )
            .map_err(|_| DurableEventEvidenceError::Encoding)
        })
        .collect()
}

fn identity_array(
    document: &StrictJsonDocument,
    id: JsonNodeId,
) -> Result<Vec<ProtocolIdentity>, DurableEventEvidenceError> {
    let Some(JsonNode::Array(items)) = document.node(id) else {
        return Err(DurableEventEvidenceError::Encoding);
    };
    items
        .iter()
        .map(|item| identity(document, *item, None))
        .collect()
}

fn optional_identity(
    document: &StrictJsonDocument,
    id: JsonNodeId,
    expected: Option<IdentityKind>,
) -> Result<Option<ProtocolIdentity>, DurableEventEvidenceError> {
    if matches!(document.node(id), Some(JsonNode::Null)) {
        Ok(None)
    } else {
        identity(document, id, expected).map(Some)
    }
}

fn identity(
    document: &StrictJsonDocument,
    id: JsonNodeId,
    expected: Option<IdentityKind>,
) -> Result<ProtocolIdentity, DurableEventEvidenceError> {
    let value = ProtocolIdentity::parse(string(document, id)?)
        .map_err(|_| DurableEventEvidenceError::Encoding)?;
    if expected.is_some_and(|expected| value.kind() != expected) {
        return Err(DurableEventEvidenceError::Encoding);
    }
    Ok(value)
}

fn decode_document(body: &[u8]) -> Result<StrictJsonDocument, DurableEventEvidenceError> {
    let maximum_bytes =
        u64::try_from(body.len()).map_err(|_| DurableEventEvidenceError::Encoding)?;
    let document = StrictJsonDocument::decode(
        Arc::<[u8]>::from(body),
        JsonLimits {
            maximum_bytes,
            maximum_nesting_depth: maximum_bytes.max(1),
            maximum_nodes: maximum_bytes.max(1),
            maximum_string_scalars: maximum_bytes.max(1),
            maximum_list_items: maximum_bytes.max(1),
        },
    )
    .map_err(|_| DurableEventEvidenceError::Encoding)?;
    if CanonicalJson::from_document(&document)
        .map_err(|_| DurableEventEvidenceError::Encoding)?
        .bytes()
        != body
    {
        return Err(DurableEventEvidenceError::Encoding);
    }
    Ok(document)
}

fn object(
    document: &StrictJsonDocument,
    id: JsonNodeId,
) -> Result<&[(Arc<str>, JsonNodeId)], DurableEventEvidenceError> {
    match document.node(id) {
        Some(JsonNode::Object(value)) => Ok(value),
        _ => Err(DurableEventEvidenceError::Encoding),
    }
}

fn require_exact_fields(
    object: &[(Arc<str>, JsonNodeId)],
    expected: &[&str],
) -> Result<(), DurableEventEvidenceError> {
    if object.len() == expected.len()
        && expected
            .iter()
            .all(|expected| object.iter().any(|(name, _)| name.as_ref() == *expected))
    {
        Ok(())
    } else {
        Err(DurableEventEvidenceError::Encoding)
    }
}

fn field(
    object: &[(Arc<str>, JsonNodeId)],
    name: &str,
) -> Result<JsonNodeId, DurableEventEvidenceError> {
    object
        .iter()
        .find_map(|(candidate, value)| (candidate.as_ref() == name).then_some(*value))
        .ok_or(DurableEventEvidenceError::Encoding)
}

fn string(
    document: &StrictJsonDocument,
    id: JsonNodeId,
) -> Result<&str, DurableEventEvidenceError> {
    match document.node(id) {
        Some(JsonNode::String(value)) => Ok(value),
        _ => Err(DurableEventEvidenceError::Encoding),
    }
}

fn boolean(
    document: &StrictJsonDocument,
    id: JsonNodeId,
) -> Result<bool, DurableEventEvidenceError> {
    match document.node(id) {
        Some(JsonNode::Bool(value)) => Ok(*value),
        _ => Err(DurableEventEvidenceError::Encoding),
    }
}

fn unsigned(
    document: &StrictJsonDocument,
    id: JsonNodeId,
) -> Result<u64, DurableEventEvidenceError> {
    match document.node(id) {
        Some(JsonNode::Number(value)) => value
            .to_gantry_int()
            .ok()
            .and_then(|value| u64::try_from(value).ok())
            .ok_or(DurableEventEvidenceError::Encoding),
        _ => Err(DurableEventEvidenceError::Encoding),
    }
}

fn optional_unsigned(
    document: &StrictJsonDocument,
    id: JsonNodeId,
) -> Result<Option<u64>, DurableEventEvidenceError> {
    if matches!(document.node(id), Some(JsonNode::Null)) {
        Ok(None)
    } else {
        unsigned(document, id).map(Some)
    }
}

fn decode_hex(value: &str) -> Result<Vec<u8>, DurableEventEvidenceError> {
    if !value.len().is_multiple_of(2) {
        return Err(DurableEventEvidenceError::Encoding);
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = decode_nibble(pair[0])?;
            let low = decode_nibble(pair[1])?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn decode_nibble(value: u8) -> Result<u8, DurableEventEvidenceError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(DurableEventEvidenceError::Encoding),
    }
}

fn validate_payloads(
    references: &[ProtectedReference],
    payloads: &[ProtectedPayload],
) -> Result<Vec<JournalProtectedPayloadV1>, DurableEventEvidenceError> {
    let mut supplied = BTreeMap::new();
    for payload in payloads {
        if supplied.insert(payload.reference.key(), payload).is_some() {
            return Err(DurableEventEvidenceError::DuplicatePayload);
        }
    }
    if supplied
        .keys()
        .any(|key| !references.iter().any(|reference| reference.key() == *key))
    {
        return Err(DurableEventEvidenceError::UnreferencedPayload);
    }
    references
        .iter()
        .map(|reference| {
            let payload = supplied
                .get(reference.key())
                .ok_or(DurableEventEvidenceError::MissingPayload)?;
            if payload.reference.class() != reference.class() {
                return Err(DurableEventEvidenceError::PayloadClassMismatch);
            }
            Ok(JournalProtectedPayloadV1 {
                key: JournalPayloadKey::new(reference.key())
                    .map_err(DurableEventEvidenceError::Journal)?,
                class: reference.class(),
                bytes: Arc::clone(&payload.bytes),
            })
        })
        .collect()
}

fn push_event(output: &mut String, event: &EventEnvelope) {
    output.push_str("{\"activity_id\":");
    push_json_string(output, &event.activity_id().to_string());
    output.push_str(",\"causal_ids\":[");
    for (index, identity) in event.causal_ids().iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        push_json_string(output, &identity.to_string());
    }
    output.push_str("],\"event_id\":");
    push_json_string(output, &event.event_id().to_string());
    output.push_str(",\"execution_id\":");
    push_optional_identity(output, event.execution_id());
    output.push_str(",\"kind\":");
    push_json_string(output, event.kind().wire_name());
    output.push_str(",\"layer\":");
    push_json_string(output, event.layer().wire_name());
    output.push_str(",\"operation_id\":");
    push_optional_identity(output, event.operation_id());
    output.push_str(",\"payload\":");
    push_json_string(output, &encode_hex(event.payload().canonical_bytes()));
    output.push_str(",\"per_task_sequence\":");
    push_optional_u64(output, event.per_task_sequence());
    output.push_str(",\"protected_references\":[");
    for (index, reference) in event.protected_references().iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        output.push_str("{\"class\":");
        push_json_string(output, reference.class().wire_name());
        output.push_str(",\"key\":");
        push_json_string(output, reference.key());
        output.push('}');
    }
    output.push_str("],\"source\":");
    if let Some(source) = event.source() {
        output.push_str("{\"end\":");
        output.push_str(&source.bytes().end().to_string());
        output.push_str(",\"path\":");
        push_json_string(output, source.source().package_path().as_str());
        output.push_str(",\"start\":");
        output.push_str(&source.bytes().start().to_string());
        output.push('}');
    } else {
        output.push_str("null");
    }
    output.push_str(",\"task_id\":");
    push_optional_identity(output, event.task_id());
    output.push_str(",\"timestamp\":");
    push_json_string(output, event.timestamp().as_str());
    output.push_str(",\"version\":{\"major\":");
    output.push_str(&event.version().major.to_string());
    output.push_str(",\"minor\":");
    output.push_str(&event.version().minor.to_string());
    output.push_str("}}");
}

fn push_obligation(output: &mut String, obligation: &DurableSinkObligationV1) {
    let policy = obligation.policy();
    output.push_str("{\"attempt_timeout_us\":");
    output.push_str(&policy.attempt_timeout_us.to_string());
    output.push_str(",\"capabilities\":{\"integration_diagnostics\":");
    output.push_str(if policy.capabilities.integration_diagnostics {
        "true"
    } else {
        "false"
    });
    output.push_str(",\"operation_request_content\":");
    output.push_str(if policy.capabilities.operation_request_content {
        "true"
    } else {
        "false"
    });
    output.push_str(",\"operation_result_content\":");
    output.push_str(if policy.capabilities.operation_result_content {
        "true"
    } else {
        "false"
    });
    output.push_str(",\"source_snippets\":");
    output.push_str(if policy.capabilities.source_snippets {
        "true"
    } else {
        "false"
    });
    output.push_str("},\"class\":");
    push_json_string(output, policy.class.wire_name());
    output.push_str(",\"jitter\":");
    push_json_string(output, policy.retry.jitter.wire_name());
    output.push_str(",\"raw_output\":");
    output.push_str(if policy.raw_output { "true" } else { "false" });
    output.push_str(",\"redaction_policy_id\":");
    push_json_string(output, &policy.redaction_policy_id);
    output.push_str(",\"retry_cap_us\":");
    output.push_str(&policy.retry.cap_us.to_string());
    output.push_str(",\"retry_initial_delay_us\":");
    output.push_str(&policy.retry.initial_delay_us.to_string());
    output.push_str(",\"retry_limit\":");
    output.push_str(&policy.retry.retry_limit.to_string());
    output.push_str(",\"retry_revision\":");
    push_json_string(output, &policy.retry.revision);
    output.push_str(",\"sink_id\":");
    push_json_string(output, obligation.sink_id().as_str());
    output.push('}');
}

fn push_optional_identity(output: &mut String, value: Option<ProtocolIdentity>) {
    match value {
        Some(value) => push_json_string(output, &value.to_string()),
        None => output.push_str("null"),
    }
}

fn push_optional_u64(output: &mut String, value: Option<u64>) {
    match value {
        Some(value) => output.push_str(&value.to_string()),
        None => output.push_str("null"),
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

fn push_json_string(output: &mut String, value: &str) {
    output.push('"');
    for scalar in value.chars() {
        match scalar {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{08}' => output.push_str("\\b"),
            '\u{09}' => output.push_str("\\t"),
            '\n' => output.push_str("\\n"),
            '\u{0c}' => output.push_str("\\f"),
            '\r' => output.push_str("\\r"),
            value if value <= '\u{1f}' => output.push_str(&format!("\\u{:04x}", value as u32)),
            value => output.push(value),
        }
    }
    output.push('"');
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::future::Future;
    use std::pin::pin;
    use std::sync::Arc;
    use std::task::{Context, Poll, Waker};

    use gantry_core::event::{EventDraft, EventEnvelope, EventPayload, ProtectedReference};
    use gantry_core::identity::ProtocolIdentity;
    use gantry_core::portable::{
        DeliveryOutcome, EventKind, IdentityKind, JitterMode, ProtectedReferenceClass, SinkClass,
    };
    use gantry_core::timestamp::UtcTimestamp;
    use gantry_host::event::{
        EventRetryPolicy, ProtectedPayload, RedactionCapabilities, SinkDeliveryPolicy, SinkId,
    };
    use gantry_host::journal::{
        AcquireJournalOwnerV1, BatchLocalEvidenceId, JournalBatchV1, JournalCommitRequestV1,
        JournalEvidenceEnvelopeV1, JournalEvidenceReferenceV1, JournalId, JournalOwnerOperationV1,
        JournalPayloadKey, JournalPrefixV1, JournalStorage, ReadJournalPrefixV1,
        ReleaseJournalOwnerV1, ResolveJournalPayloadV1, UnfinalizedEvidenceV1,
    };

    use crate::{DurableTransitionSink, InMemoryJournalStore};

    use super::{
        DURABLE_EVENT_DISPATCHED_KIND_V1, DURABLE_EVENT_OCCURRENCE_KIND_V1,
        DURABLE_EVENT_SETTLED_KIND_V1, DurableDeliveryRecoveryV1, DurableEventBarrierV1,
        DurableEventCommitCoordinatorV1, DurableEventCommitError, DurableEventDispatchedV1,
        DurableEventEvidenceError, DurableEventOccurrenceV1, DurableEventPlanV1,
        DurableEventSettledV1, DurableSinkObligationV1, RecoveredDurableEventsV1,
    };

    #[test]
    fn occurrence_freezes_canonical_plan_and_atomic_payload_references() {
        let reference =
            ProtectedReference::new("event:raw-output", ProtectedReferenceClass::RawOutput)
                .unwrap_or_else(|error| panic!("protected reference failed: {error:?}"));
        let event = event(reference.clone());
        let plan = DurableEventPlanV1::new(vec![
            DurableSinkObligationV1::new(sink_id("z-sink"), policy(SinkClass::BestEffort, false)),
            DurableSinkObligationV1::new(sink_id("a-sink"), policy(SinkClass::Required, true)),
        ])
        .unwrap_or_else(|error| panic!("durable plan failed: {error:?}"));
        let occurrence = DurableEventOccurrenceV1::new(evidence_id(1), event, plan)
            .unwrap_or_else(|error| panic!("durable occurrence failed: {error:?}"));

        assert_eq!(
            occurrence.plan().obligations()[0].sink_id().as_str(),
            "a-sink"
        );
        assert_eq!(
            occurrence.plan().obligations()[1].sink_id().as_str(),
            "z-sink"
        );
        let payload = ProtectedPayload {
            reference,
            bytes: Arc::from(&b"sensitive-secret-bytes"[..]),
        };
        let (body, payloads) = occurrence
            .unfinalized(
                BatchLocalEvidenceId::new("event")
                    .unwrap_or_else(|error| panic!("local id failed: {error:?}")),
                vec![JournalEvidenceReferenceV1::Existing(evidence_id(1))],
                &[payload],
            )
            .unwrap_or_else(|error| panic!("event evidence failed: {error:?}"));

        assert_eq!(body.kind.as_ref(), DURABLE_EVENT_OCCURRENCE_KIND_V1);
        assert_eq!(body.protected_payloads.len(), 1);
        assert_eq!(body.protected_payloads[0].as_str(), "event:raw-output");
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0].bytes.as_ref(), b"sensitive-secret-bytes");
        let canonical = std::str::from_utf8(&body.canonical_body)
            .unwrap_or_else(|error| panic!("canonical body is not UTF-8: {error}"));
        assert!(canonical.contains("\"sink_id\":\"a-sink\""));
        assert!(canonical.contains("\"sink_id\":\"z-sink\""));
        assert!(canonical.find("a-sink") < canonical.find("z-sink"));
        assert!(!canonical.contains("sensitive-secret-bytes"));
        assert_eq!(
            DurableEventOccurrenceV1::decode(&body.canonical_body),
            Ok(occurrence)
        );
    }

    #[test]
    fn occurrence_rejects_missing_payload_duplicate_sink_and_nonexecution_event() {
        let reference =
            ProtectedReference::new("event:raw-output", ProtectedReferenceClass::RawOutput)
                .unwrap_or_else(|error| panic!("protected reference failed: {error:?}"));
        let plan = DurableEventPlanV1::new(vec![
            DurableSinkObligationV1::new(sink_id("sink"), policy(SinkClass::Required, true)),
            DurableSinkObligationV1::new(sink_id("sink"), policy(SinkClass::Required, true)),
        ]);
        assert_eq!(plan, Err(DurableEventEvidenceError::DuplicateSink));

        let plan = DurableEventPlanV1::new(vec![DurableSinkObligationV1::new(
            sink_id("sink"),
            policy(SinkClass::Required, true),
        )])
        .unwrap_or_else(|error| panic!("durable plan failed: {error:?}"));
        let occurrence = DurableEventOccurrenceV1::new(evidence_id(1), event(reference), plan)
            .unwrap_or_else(|error| panic!("durable occurrence failed: {error:?}"));
        let result = occurrence.unfinalized(
            BatchLocalEvidenceId::new("event")
                .unwrap_or_else(|error| panic!("local id failed: {error:?}")),
            vec![JournalEvidenceReferenceV1::Existing(evidence_id(1))],
            &[],
        );
        assert_eq!(result, Err(DurableEventEvidenceError::MissingPayload));

        let standalone = EventEnvelope::complete(
            fresh(IdentityKind::Event, 3),
            fresh(IdentityKind::Activity, 4),
            timestamp(),
            EventDraft::new(EventKind::Parse, payload()),
        )
        .unwrap_or_else(|error| panic!("standalone event failed: {error:?}"));
        assert_eq!(
            DurableEventOccurrenceV1::new(
                evidence_id(1),
                standalone,
                DurableEventPlanV1::default(),
            ),
            Err(DurableEventEvidenceError::MissingExecutionIdentity)
        );

        let mut noncanonical = occurrence.canonical_body();
        noncanonical.push(b' ');
        assert_eq!(
            DurableEventOccurrenceV1::decode(&noncanonical),
            Err(DurableEventEvidenceError::Encoding)
        );
    }

    #[test]
    fn delivery_recovery_preserves_indeterminate_retry_and_settlement_state() {
        let reference =
            ProtectedReference::new("event:raw-output", ProtectedReferenceClass::RawOutput)
                .unwrap_or_else(|error| panic!("protected reference failed: {error:?}"));
        let event = event(reference);
        let event_id = event.event_id();
        let sink = sink_id("required-sink");
        let occurrence = DurableEventOccurrenceV1::new(
            evidence_id(1),
            event,
            DurableEventPlanV1::new(vec![DurableSinkObligationV1::new(
                sink.clone(),
                policy(SinkClass::Required, true),
            )])
            .unwrap_or_else(|error| panic!("durable plan failed: {error:?}")),
        )
        .unwrap_or_else(|error| panic!("durable occurrence failed: {error:?}"));
        let occurrence_id = evidence_id(10);
        let mut recovered = RecoveredDurableEventsV1::default();
        recovered
            .apply_envelope(&envelope(
                1,
                occurrence_id,
                DURABLE_EVENT_OCCURRENCE_KIND_V1,
                occurrence.canonical_body(),
                &[evidence_id(1)],
                &["event:raw-output"],
            ))
            .unwrap_or_else(|error| panic!("occurrence projection failed: {error:?}"));

        let first_attempt = fresh(IdentityKind::DeliveryAttempt, 11);
        let first_dispatch_id = evidence_id(11);
        let first_dispatch =
            DurableEventDispatchedV1::new(event_id, sink.clone(), first_attempt, 0)
                .unwrap_or_else(|error| panic!("first dispatch failed: {error:?}"));
        recovered
            .apply_envelope(&envelope(
                2,
                first_dispatch_id,
                DURABLE_EVENT_DISPATCHED_KIND_V1,
                first_dispatch.canonical_body(),
                &[occurrence_id],
                &[],
            ))
            .unwrap_or_else(|error| panic!("first dispatch projection failed: {error:?}"));
        assert_eq!(
            delivery(&recovered, event_id, &sink),
            &DurableDeliveryRecoveryV1::Indeterminate {
                previous_attempt_id: first_attempt,
                retry_number: 0,
            }
        );

        let redelivery_attempt = fresh(IdentityKind::DeliveryAttempt, 12);
        let redelivery_dispatch_id = evidence_id(12);
        let redelivery =
            DurableEventDispatchedV1::new(event_id, sink.clone(), redelivery_attempt, 0)
                .unwrap_or_else(|error| panic!("redelivery dispatch failed: {error:?}"));
        recovered
            .apply_envelope(&envelope(
                3,
                redelivery_dispatch_id,
                DURABLE_EVENT_DISPATCHED_KIND_V1,
                redelivery.canonical_body(),
                &[occurrence_id, first_dispatch_id],
                &[],
            ))
            .unwrap_or_else(|error| panic!("redelivery projection failed: {error:?}"));
        let retry = DurableEventSettledV1::new(
            event_id,
            sink.clone(),
            redelivery_attempt,
            0,
            DeliveryOutcome::Retriable,
            2,
            Some(17),
        )
        .unwrap_or_else(|error| panic!("retry settlement failed: {error:?}"));
        recovered
            .apply_envelope(&envelope(
                4,
                evidence_id(13),
                DURABLE_EVENT_SETTLED_KIND_V1,
                retry.canonical_body(),
                &[occurrence_id, redelivery_dispatch_id],
                &[],
            ))
            .unwrap_or_else(|error| panic!("retry settlement projection failed: {error:?}"));
        assert_eq!(
            delivery(&recovered, event_id, &sink),
            &DurableDeliveryRecoveryV1::RetryDelay {
                retry_number: 1,
                delay_us: 17,
                remaining_retries: 2,
            }
        );

        let final_attempt = fresh(IdentityKind::DeliveryAttempt, 14);
        let final_dispatch_id = evidence_id(14);
        let final_dispatch =
            DurableEventDispatchedV1::new(event_id, sink.clone(), final_attempt, 1)
                .unwrap_or_else(|error| panic!("final dispatch failed: {error:?}"));
        recovered
            .apply_envelope(&envelope(
                5,
                final_dispatch_id,
                DURABLE_EVENT_DISPATCHED_KIND_V1,
                final_dispatch.canonical_body(),
                &[occurrence_id, evidence_id(13)],
                &[],
            ))
            .unwrap_or_else(|error| panic!("final dispatch projection failed: {error:?}"));
        let terminal = DurableEventSettledV1::new(
            event_id,
            sink.clone(),
            final_attempt,
            1,
            DeliveryOutcome::Terminal,
            1,
            None,
        )
        .unwrap_or_else(|error| panic!("terminal settlement failed: {error:?}"));
        recovered
            .apply_envelope(&envelope(
                6,
                evidence_id(15),
                DURABLE_EVENT_SETTLED_KIND_V1,
                terminal.canonical_body(),
                &[occurrence_id, final_dispatch_id],
                &[],
            ))
            .unwrap_or_else(|error| panic!("terminal settlement projection failed: {error:?}"));
        assert_eq!(
            delivery(&recovered, event_id, &sink),
            &DurableDeliveryRecoveryV1::Terminal {
                attempt_id: final_attempt,
            }
        );

        let repeated = DurableEventDispatchedV1::new(
            event_id,
            sink,
            fresh(IdentityKind::DeliveryAttempt, 16),
            1,
        )
        .unwrap_or_else(|error| panic!("repeated dispatch failed: {error:?}"));
        assert_eq!(
            recovered.apply_envelope(&envelope(
                7,
                evidence_id(16),
                DURABLE_EVENT_DISPATCHED_KIND_V1,
                repeated.canonical_body(),
                &[occurrence_id, evidence_id(15)],
                &[],
            )),
            Err(DurableEventEvidenceError::InvalidDeliveryHistory)
        );
    }

    #[test]
    fn delivery_recovery_rejects_unfrozen_sink_and_wrong_retry_budget() {
        let event = event(
            ProtectedReference::new("event:raw-output", ProtectedReferenceClass::RawOutput)
                .unwrap_or_else(|error| panic!("protected reference failed: {error:?}")),
        );
        let event_id = event.event_id();
        let sink = sink_id("required-sink");
        let occurrence = DurableEventOccurrenceV1::new(
            evidence_id(1),
            event,
            DurableEventPlanV1::new(vec![DurableSinkObligationV1::new(
                sink.clone(),
                policy(SinkClass::Required, true),
            )])
            .unwrap_or_else(|error| panic!("durable plan failed: {error:?}")),
        )
        .unwrap_or_else(|error| panic!("durable occurrence failed: {error:?}"));
        let occurrence_id = evidence_id(20);
        let mut recovered = RecoveredDurableEventsV1::default();
        recovered
            .apply_envelope(&envelope(
                1,
                occurrence_id,
                DURABLE_EVENT_OCCURRENCE_KIND_V1,
                occurrence.canonical_body(),
                &[evidence_id(1)],
                &["event:raw-output"],
            ))
            .unwrap_or_else(|error| panic!("occurrence projection failed: {error:?}"));

        let unknown = DurableEventDispatchedV1::new(
            event_id,
            sink_id("later-sink"),
            fresh(IdentityKind::DeliveryAttempt, 21),
            0,
        )
        .unwrap_or_else(|error| panic!("unknown dispatch failed: {error:?}"));
        assert_eq!(
            recovered.apply_envelope(&envelope(
                2,
                evidence_id(21),
                DURABLE_EVENT_DISPATCHED_KIND_V1,
                unknown.canonical_body(),
                &[occurrence_id],
                &[],
            )),
            Err(DurableEventEvidenceError::InvalidDeliveryHistory)
        );

        let attempt = fresh(IdentityKind::DeliveryAttempt, 22);
        let dispatch_id = evidence_id(22);
        let dispatch = DurableEventDispatchedV1::new(event_id, sink.clone(), attempt, 0)
            .unwrap_or_else(|error| panic!("dispatch failed: {error:?}"));
        recovered
            .apply_envelope(&envelope(
                2,
                dispatch_id,
                DURABLE_EVENT_DISPATCHED_KIND_V1,
                dispatch.canonical_body(),
                &[occurrence_id],
                &[],
            ))
            .unwrap_or_else(|error| panic!("dispatch projection failed: {error:?}"));
        let wrong_budget = DurableEventSettledV1::new(
            event_id,
            sink,
            attempt,
            0,
            DeliveryOutcome::Retriable,
            1,
            Some(17),
        )
        .unwrap_or_else(|error| panic!("settlement construction failed: {error:?}"));
        assert_eq!(
            recovered.apply_envelope(&envelope(
                3,
                evidence_id(23),
                DURABLE_EVENT_SETTLED_KIND_V1,
                wrong_budget.canonical_body(),
                &[occurrence_id, dispatch_id],
                &[],
            )),
            Err(DurableEventEvidenceError::InvalidDeliveryHistory)
        );
    }

    #[test]
    fn coordinator_commits_occurrence_payload_dispatch_and_settlement_in_order() {
        let storage: Arc<dyn JournalStorage> = Arc::new(InMemoryJournalStore::new());
        let journal_id = JournalId::new("durable-event-coordinator")
            .unwrap_or_else(|error| panic!("journal id failed: {error:?}"));
        let owner = block_on(storage.acquire_owner(AcquireJournalOwnerV1 {
            journal_id: journal_id.clone(),
            operation: JournalOwnerOperationV1::Start,
        }))
        .unwrap_or_else(|error| panic!("owner acquisition failed: {error:?}"));
        let cause_local = BatchLocalEvidenceId::new("cause")
            .unwrap_or_else(|error| panic!("cause local id failed: {error:?}"));
        let cause = UnfinalizedEvidenceV1::new(
            cause_local.clone(),
            "gantry.test-cause/v1",
            Arc::<[u8]>::from(&b"{}"[..]),
            Arc::from([]),
            Arc::from([]),
        )
        .unwrap_or_else(|error| panic!("cause evidence failed: {error:?}"));
        let cause_receipt = block_on(
            storage.commit(JournalCommitRequestV1 {
                journal_id: journal_id.clone(),
                ownership_token: owner.token.clone(),
                batch: JournalBatchV1::new(vec![cause], Vec::new())
                    .unwrap_or_else(|error| panic!("cause batch failed: {error:?}")),
            }),
        )
        .unwrap_or_else(|error| panic!("cause commit failed: {error:?}"));
        let cause_id = cause_receipt.entries[0].evidence_id;
        let reference =
            ProtectedReference::new("event:raw-output", ProtectedReferenceClass::RawOutput)
                .unwrap_or_else(|error| panic!("protected reference failed: {error:?}"));
        let event = event(reference.clone());
        let event_id = event.event_id();
        let sink_id = sink_id("required-sink");
        let occurrence = DurableEventOccurrenceV1::new(
            cause_id,
            event,
            DurableEventPlanV1::new(vec![DurableSinkObligationV1::new(
                sink_id.clone(),
                policy(SinkClass::Required, true),
            )])
            .unwrap_or_else(|error| panic!("durable plan failed: {error:?}")),
        )
        .unwrap_or_else(|error| panic!("durable occurrence failed: {error:?}"));
        let durable_sink =
            DurableTransitionSink::new(Arc::clone(&storage), journal_id.clone(), owner.token);
        let mut coordinator = DurableEventCommitCoordinatorV1::new(&durable_sink, (cause_id, 1))
            .unwrap_or_else(|error| panic!("coordinator failed: {error:?}"));
        let payload = ProtectedPayload {
            reference,
            bytes: Arc::from(&b"sensitive-secret-bytes"[..]),
        };
        let occurrence_commit = block_on(coordinator.commit_occurrence(&occurrence, &[payload]))
            .unwrap_or_else(|error| panic!("occurrence commit failed: {error:?}"));
        let attempt_id = fresh(IdentityKind::DeliveryAttempt, 30);
        let dispatched = DurableEventDispatchedV1::new(event_id, sink_id.clone(), attempt_id, 0)
            .unwrap_or_else(|error| panic!("dispatch construction failed: {error:?}"));
        let dispatch_commit =
            block_on(coordinator.commit_dispatched(occurrence_commit.evidence_id, &dispatched))
                .unwrap_or_else(|error| panic!("dispatch commit failed: {error:?}"));
        let settled = DurableEventSettledV1::new(
            event_id,
            sink_id,
            attempt_id,
            0,
            DeliveryOutcome::Success,
            2,
            None,
        )
        .unwrap_or_else(|error| panic!("settlement construction failed: {error:?}"));
        let settlement_commit = block_on(coordinator.commit_settled(
            occurrence_commit.evidence_id,
            dispatch_commit.evidence_id,
            &settled,
        ))
        .unwrap_or_else(|error| panic!("settlement commit failed: {error:?}"));
        assert_eq!(
            (
                occurrence_commit.sequence,
                dispatch_commit.sequence,
                settlement_commit.sequence,
            ),
            (2, 3, 4)
        );

        let prefix = block_on(storage.read_prefix(ReadJournalPrefixV1 {
            journal_id: journal_id.clone(),
        }))
        .unwrap_or_else(|error| panic!("prefix read failed: {error:?}"));
        let JournalPrefixV1::Full(prefix) = prefix else {
            panic!("in-memory event journal returned a snapshot")
        };
        assert_eq!(
            prefix
                .evidence
                .iter()
                .map(|envelope| envelope.kind.as_ref())
                .collect::<Vec<_>>(),
            [
                "gantry.test-cause/v1",
                DURABLE_EVENT_OCCURRENCE_KIND_V1,
                DURABLE_EVENT_DISPATCHED_KIND_V1,
                DURABLE_EVENT_SETTLED_KIND_V1,
            ]
        );
        assert!(prefix.evidence[1].references.contains(&cause_id));
        assert!(
            prefix.evidence[2]
                .references
                .contains(&occurrence_commit.evidence_id)
        );
        assert!(
            prefix.evidence[3]
                .references
                .contains(&dispatch_commit.evidence_id)
        );
        let resolved = block_on(
            storage.resolve_payload(ResolveJournalPayloadV1 {
                journal_id,
                key: JournalPayloadKey::new("event:raw-output")
                    .unwrap_or_else(|error| panic!("payload key failed: {error:?}")),
            }),
        )
        .unwrap_or_else(|error| panic!("payload resolution failed: {error:?}"));
        assert_eq!(resolved.bytes.as_ref(), b"sensitive-secret-bytes");
    }

    #[test]
    fn journal_failure_terminates_the_event_stream() {
        let storage: Arc<dyn JournalStorage> = Arc::new(InMemoryJournalStore::new());
        let journal_id = JournalId::new("durable-event-failure")
            .unwrap_or_else(|error| panic!("journal id failed: {error:?}"));
        let owner = block_on(storage.acquire_owner(AcquireJournalOwnerV1 {
            journal_id: journal_id.clone(),
            operation: JournalOwnerOperationV1::Start,
        }))
        .unwrap_or_else(|error| panic!("owner acquisition failed: {error:?}"));
        block_on(storage.release_owner(ReleaseJournalOwnerV1 {
            journal_id: journal_id.clone(),
            ownership_token: owner.token.clone(),
        }))
        .unwrap_or_else(|error| panic!("owner release failed: {error:?}"));
        let sink = DurableTransitionSink::new(storage, journal_id, owner.token);
        let mut coordinator = DurableEventCommitCoordinatorV1::new(&sink, (evidence_id(1), 1))
            .unwrap_or_else(|error| panic!("coordinator failed: {error:?}"));
        let dispatched = DurableEventDispatchedV1::new(
            fresh(IdentityKind::Event, 31),
            sink_id("sink"),
            fresh(IdentityKind::DeliveryAttempt, 32),
            0,
        )
        .unwrap_or_else(|error| panic!("dispatch construction failed: {error:?}"));
        let first = block_on(coordinator.commit_dispatched(evidence_id(2), &dispatched));
        let Err(DurableEventCommitError::Journal(error)) = first else {
            panic!("first failed commit did not return the journal error")
        };
        let second = block_on(coordinator.commit_dispatched(evidence_id(2), &dispatched));
        assert_eq!(
            second,
            Err(DurableEventCommitError::StreamTerminated(error))
        );
    }

    #[test]
    fn replacement_barrier_and_retention_are_projected_without_language_outcomes() {
        let cause_id = evidence_id(40);
        let reference =
            ProtectedReference::new("event:raw-output", ProtectedReferenceClass::RawOutput)
                .unwrap_or_else(|error| panic!("protected reference failed: {error:?}"));
        let event = event(reference);
        let event_id = event.event_id();
        let sink = sink_id("required-sink");
        let occurrence = DurableEventOccurrenceV1::new(
            cause_id,
            event,
            DurableEventPlanV1::new(vec![DurableSinkObligationV1::new(
                sink.clone(),
                policy(SinkClass::Required, true),
            )])
            .unwrap_or_else(|error| panic!("durable plan failed: {error:?}")),
        )
        .unwrap_or_else(|error| panic!("durable occurrence failed: {error:?}"));
        let occurrence_id = evidence_id(41);
        let mut recovered = RecoveredDurableEventsV1::default();
        recovered
            .apply_envelope(&envelope(
                2,
                occurrence_id,
                DURABLE_EVENT_OCCURRENCE_KIND_V1,
                occurrence.canonical_body(),
                &[cause_id],
                &["event:raw-output"],
            ))
            .unwrap_or_else(|error| panic!("occurrence projection failed: {error:?}"));
        assert!(!recovered.requires_replacement(cause_id));
        assert!(recovered.requires_replacement(evidence_id(42)));
        assert_eq!(
            recovered.required_barrier_through(2),
            DurableEventBarrierV1::Pending {
                event_id,
                sink_id: sink.clone(),
            }
        );

        let retention = recovered.retention();
        assert_eq!(retention.evidence_ids(), &BTreeSet::from([occurrence_id]));
        let payload_key = JournalPayloadKey::new("event:raw-output")
            .unwrap_or_else(|error| panic!("payload key failed: {error:?}"));
        assert_eq!(
            retention.payload_keys(),
            &BTreeSet::from([payload_key.clone()])
        );
        assert_eq!(
            retention.validate_retained(&BTreeSet::new(), &BTreeSet::new()),
            Err(DurableEventEvidenceError::CompactionWouldDangle)
        );
        assert_eq!(
            retention.validate_retained(
                &BTreeSet::from([occurrence_id]),
                &BTreeSet::from([payload_key]),
            ),
            Ok(())
        );

        let attempt_id = fresh(IdentityKind::DeliveryAttempt, 43);
        let dispatch_id = evidence_id(43);
        let dispatched = DurableEventDispatchedV1::new(event_id, sink.clone(), attempt_id, 0)
            .unwrap_or_else(|error| panic!("dispatch construction failed: {error:?}"));
        recovered
            .apply_envelope(&envelope(
                3,
                dispatch_id,
                DURABLE_EVENT_DISPATCHED_KIND_V1,
                dispatched.canonical_body(),
                &[occurrence_id],
                &[],
            ))
            .unwrap_or_else(|error| panic!("dispatch projection failed: {error:?}"));
        let settled = DurableEventSettledV1::new(
            event_id,
            sink.clone(),
            attempt_id,
            0,
            DeliveryOutcome::Terminal,
            2,
            None,
        )
        .unwrap_or_else(|error| panic!("settlement construction failed: {error:?}"));
        recovered
            .apply_envelope(&envelope(
                4,
                evidence_id(44),
                DURABLE_EVENT_SETTLED_KIND_V1,
                settled.canonical_body(),
                &[occurrence_id, dispatch_id],
                &[],
            ))
            .unwrap_or_else(|error| panic!("settlement projection failed: {error:?}"));
        assert!(matches!(
            recovered.required_barrier_through(4),
            DurableEventBarrierV1::RequiredExhausted(failure)
                if failure.sink_id == sink
                    && failure.event_id == event_id
                    && failure.attempt_id == attempt_id
        ));
    }

    fn event(reference: ProtectedReference) -> EventEnvelope {
        let draft = EventDraft::new(EventKind::OperationCompletion, payload())
            .with_execution_id(fresh(IdentityKind::Execution, 5))
            .and_then(|draft| draft.with_protected_references(vec![reference]))
            .unwrap_or_else(|error| panic!("event draft failed: {error:?}"));
        EventEnvelope::complete(
            fresh(IdentityKind::Event, 6),
            fresh(IdentityKind::Activity, 7),
            timestamp(),
            draft,
        )
        .unwrap_or_else(|error| panic!("event completion failed: {error:?}"))
    }

    fn delivery<'a>(
        recovered: &'a RecoveredDurableEventsV1,
        event_id: ProtocolIdentity,
        sink_id: &SinkId,
    ) -> &'a DurableDeliveryRecoveryV1 {
        recovered
            .events()
            .get(&event_id)
            .and_then(|event| event.deliveries().get(sink_id))
            .unwrap_or_else(|| panic!("recovered delivery is absent"))
    }

    fn envelope(
        sequence: u64,
        evidence_id: ProtocolIdentity,
        kind: &'static str,
        canonical_body: Vec<u8>,
        references: &[ProtocolIdentity],
        protected_payloads: &[&str],
    ) -> JournalEvidenceEnvelopeV1 {
        JournalEvidenceEnvelopeV1 {
            journal_id: JournalId::new("durable-event-test")
                .unwrap_or_else(|error| panic!("journal id failed: {error:?}")),
            sequence,
            evidence_id,
            kind: Arc::from(kind),
            canonical_body: Arc::from(canonical_body),
            references: Arc::from(references),
            protected_payloads: protected_payloads
                .iter()
                .map(|key| {
                    gantry_host::journal::JournalPayloadKey::new(*key)
                        .unwrap_or_else(|error| panic!("payload key failed: {error:?}"))
                })
                .collect::<Vec<_>>()
                .into(),
        }
    }

    fn policy(class: SinkClass, raw_output: bool) -> SinkDeliveryPolicy {
        let retry = EventRetryPolicy::new("retry-v1", 2, 10, 40, JitterMode::None)
            .unwrap_or_else(|error| panic!("retry policy failed: {error:?}"));
        SinkDeliveryPolicy::new(
            class,
            raw_output,
            "redaction-v1",
            RedactionCapabilities {
                operation_request_content: true,
                operation_result_content: false,
                integration_diagnostics: true,
                source_snippets: false,
            },
            retry,
            30,
        )
        .unwrap_or_else(|error| panic!("sink policy failed: {error:?}"))
    }

    fn payload() -> EventPayload {
        EventPayload::from_validated_canonical_bytes(Arc::<[u8]>::from(&b"{}"[..]))
            .unwrap_or_else(|error| panic!("event payload failed: {error:?}"))
    }

    fn sink_id(value: &str) -> SinkId {
        SinkId::new(value).unwrap_or_else(|error| panic!("sink id failed: {error:?}"))
    }

    fn timestamp() -> UtcTimestamp {
        UtcTimestamp::from_unix_seconds(0, 42)
            .unwrap_or_else(|error| panic!("timestamp failed: {error:?}"))
    }

    fn fresh(kind: IdentityKind, byte: u8) -> ProtocolIdentity {
        ProtocolIdentity::from_fresh_material(kind, [byte; 32])
            .unwrap_or_else(|error| panic!("identity failed: {error:?}"))
    }

    fn evidence_id(byte: u8) -> ProtocolIdentity {
        ProtocolIdentity::from_storage_material([byte; 32])
    }

    fn block_on<F: Future>(future: F) -> F::Output {
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        let mut future = pin!(future);
        loop {
            match future.as_mut().poll(&mut context) {
                Poll::Ready(value) => return value,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }
}
