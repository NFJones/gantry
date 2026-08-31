//! Durable transition sinks and the backend-neutral in-memory journal model.
//!
//! The in-memory store is a contract model. It exercises the same fenced,
//! atomic [`JournalStorage`] boundary as persistent adapters, but its contents
//! do not survive process loss and therefore prove no durable-profile claim.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{Arc, Mutex};

use gantry_core::identity::ProtocolIdentity;
use gantry_core::portable::IdentityKind;
use gantry_host::contracts::HostFuture;
use gantry_host::journal::{
    AcquireJournalOwnerV1, BatchLocalEvidenceId, FullJournalPrefixV1, JournalBatchV1,
    JournalCommitReceiptV1, JournalCommitRequestV1, JournalError, JournalErrorCode,
    JournalEvidenceEnvelopeV1, JournalEvidenceReferenceV1, JournalId, JournalOwnershipToken,
    JournalOwnershipV1, JournalPrefixV1, JournalReceiptEntryV1, JournalStorage,
    ReadJournalPrefixV1, ReleaseJournalOwnerV1, ResolveJournalPayloadV1, ResolvedJournalPayloadV1,
};

/// Result of recording one transition batch through a selected sink.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransitionReceiptV1 {
    /// Ordinary evaluation retained the logical batch only in process memory.
    Volatile,
    /// Durable evaluation crossed the configured journal commit boundary.
    Durable(JournalCommitReceiptV1),
}

/// Runtime-owned transition boundary shared by ordinary and durable execution.
pub trait TransitionSink: Send + Sync {
    /// Records one nonempty logical transition batch atomically for this sink.
    fn record<'a>(
        &'a self,
        batch: JournalBatchV1,
    ) -> HostFuture<'a, Result<TransitionReceiptV1, JournalError>>;
}

/// Process-local transition sink for ordinary nondurable evaluation.
#[derive(Debug, Default)]
pub struct VolatileTransitionSink {
    batches: Mutex<Vec<JournalBatchV1>>,
}

impl VolatileTransitionSink {
    /// Returns the immutable logical batches retained by this process.
    #[must_use]
    pub fn batches(&self) -> Vec<JournalBatchV1> {
        self.batches
            .lock()
            .map(|batches| batches.clone())
            .unwrap_or_default()
    }
}

impl TransitionSink for VolatileTransitionSink {
    fn record<'a>(
        &'a self,
        batch: JournalBatchV1,
    ) -> HostFuture<'a, Result<TransitionReceiptV1, JournalError>> {
        Box::pin(async move {
            self.batches
                .lock()
                .map_err(|_| JournalError::new(JournalErrorCode::Internal))?
                .push(batch);
            Ok(TransitionReceiptV1::Volatile)
        })
    }
}

/// Evidence-committing transition sink bound to one fenced journal owner.
pub struct DurableTransitionSink {
    storage: Arc<dyn JournalStorage>,
    journal_id: JournalId,
    ownership_token: JournalOwnershipToken,
}

impl std::fmt::Debug for DurableTransitionSink {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DurableTransitionSink")
            .field("journal_id", &self.journal_id)
            .finish_non_exhaustive()
    }
}

impl DurableTransitionSink {
    /// Binds a transition sink to one current journal ownership token.
    #[must_use]
    pub fn new(
        storage: Arc<dyn JournalStorage>,
        journal_id: JournalId,
        ownership_token: JournalOwnershipToken,
    ) -> Self {
        Self {
            storage,
            journal_id,
            ownership_token,
        }
    }
}

impl TransitionSink for DurableTransitionSink {
    fn record<'a>(
        &'a self,
        batch: JournalBatchV1,
    ) -> HostFuture<'a, Result<TransitionReceiptV1, JournalError>> {
        Box::pin(async move {
            self.storage
                .commit(JournalCommitRequestV1 {
                    journal_id: self.journal_id.clone(),
                    ownership_token: self.ownership_token.clone(),
                    batch,
                })
                .await
                .map(TransitionReceiptV1::Durable)
        })
    }
}

/// Thread-safe in-memory model of the complete typed [`JournalStorage`] contract.
#[derive(Debug, Default)]
pub struct InMemoryJournalStore {
    state: Mutex<StoreState>,
}

#[derive(Debug, Default)]
struct StoreState {
    journals: BTreeMap<JournalId, JournalState>,
    evidence_ids: BTreeSet<ProtocolIdentity>,
    next_evidence_material: u64,
}

#[derive(Debug, Default)]
struct JournalState {
    generation: u64,
    owner: Option<JournalOwnershipToken>,
    evidence: Vec<JournalEvidenceEnvelopeV1>,
    payloads: BTreeMap<gantry_host::journal::JournalPayloadKey, ResolvedJournalPayloadV1>,
    committed_through: u64,
}

impl InMemoryJournalStore {
    /// Constructs one empty process-local journal contract model.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn acquire_owner_now(
        &self,
        request: AcquireJournalOwnerV1,
    ) -> Result<JournalOwnershipV1, JournalError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| JournalError::new(JournalErrorCode::Internal))?;
        let journal = state
            .journals
            .entry(request.journal_id.clone())
            .or_default();
        if journal.owner.is_some() {
            return Err(JournalError::new(JournalErrorCode::OwnershipUnavailable));
        }
        let generation = journal
            .generation
            .checked_add(1)
            .ok_or_else(|| JournalError::new(JournalErrorCode::SequenceExhausted))?;
        let token = JournalOwnershipToken::new(format!(
            "memory:{}:{generation}",
            request.journal_id.as_str()
        ))
        .map_err(|_| JournalError::new(JournalErrorCode::Internal))?;
        journal.generation = generation;
        journal.owner = Some(token.clone());
        Ok(JournalOwnershipV1 {
            journal_id: request.journal_id,
            token,
        })
    }

    fn read_prefix_now(
        &self,
        request: ReadJournalPrefixV1,
    ) -> Result<JournalPrefixV1, JournalError> {
        let state = self
            .state
            .lock()
            .map_err(|_| JournalError::new(JournalErrorCode::Internal))?;
        let (evidence, committed_through) = state.journals.get(&request.journal_id).map_or_else(
            || (Arc::from([]), 0),
            |journal| {
                (
                    Arc::from(journal.evidence.clone()),
                    journal.committed_through,
                )
            },
        );
        Ok(JournalPrefixV1::Full(FullJournalPrefixV1 {
            journal_id: request.journal_id,
            evidence,
            committed_through,
        }))
    }

    fn commit_now(
        &self,
        request: JournalCommitRequestV1,
    ) -> Result<JournalCommitReceiptV1, JournalError> {
        validate_local_reference_graph(&request.batch)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| JournalError::new(JournalErrorCode::Internal))?;

        let journal = state
            .journals
            .get(&request.journal_id)
            .ok_or_else(|| JournalError::new(JournalErrorCode::StaleOwnership))?;
        require_owner(journal, &request.ownership_token)?;
        let candidate_payloads = validate_payloads(journal, &request.batch)?;
        validate_existing_references(journal, &request.batch)?;

        let count = u64::try_from(request.batch.evidence.len())
            .map_err(|_| JournalError::new(JournalErrorCode::SequenceExhausted))?;
        let first_sequence = journal
            .committed_through
            .checked_add(1)
            .ok_or_else(|| JournalError::new(JournalErrorCode::SequenceExhausted))?;
        let last_sequence = first_sequence
            .checked_add(count.saturating_sub(1))
            .ok_or_else(|| JournalError::new(JournalErrorCode::SequenceExhausted))?;

        let mut next_material = state.next_evidence_material;
        let mut local_ids = BTreeMap::<BatchLocalEvidenceId, ProtocolIdentity>::new();
        for body in request.batch.evidence.iter() {
            next_material = next_material
                .checked_add(1)
                .ok_or_else(|| JournalError::new(JournalErrorCode::IdentityFailure))?;
            let mut material = [0_u8; 32];
            material[24..].copy_from_slice(&next_material.to_be_bytes());
            let identity = ProtocolIdentity::from_storage_material(material);
            if state.evidence_ids.contains(&identity)
                || local_ids
                    .insert(body.batch_local_id.clone(), identity)
                    .is_some()
            {
                return Err(JournalError::new(JournalErrorCode::IdentityFailure));
            }
        }

        let mut envelopes = Vec::with_capacity(request.batch.evidence.len());
        let mut receipt = Vec::with_capacity(request.batch.evidence.len());
        for (index, body) in request.batch.evidence.iter().enumerate() {
            let offset = u64::try_from(index)
                .map_err(|_| JournalError::new(JournalErrorCode::SequenceExhausted))?;
            let sequence = first_sequence
                .checked_add(offset)
                .ok_or_else(|| JournalError::new(JournalErrorCode::SequenceExhausted))?;
            let evidence_id = local_ids
                .get(&body.batch_local_id)
                .copied()
                .ok_or_else(|| JournalError::new(JournalErrorCode::Internal))?;
            let references = body
                .references
                .iter()
                .map(|reference| match reference {
                    JournalEvidenceReferenceV1::Existing(identity) => Ok(*identity),
                    JournalEvidenceReferenceV1::BatchLocal(local) => local_ids
                        .get(local)
                        .copied()
                        .ok_or_else(|| JournalError::new(JournalErrorCode::InvalidBatch)),
                })
                .collect::<Result<Vec<_>, _>>()?;
            envelopes.push(JournalEvidenceEnvelopeV1 {
                journal_id: request.journal_id.clone(),
                sequence,
                evidence_id,
                kind: Arc::clone(&body.kind),
                canonical_body: Arc::clone(&body.canonical_body),
                references: Arc::from(references),
                protected_payloads: Arc::clone(&body.protected_payloads),
            });
            receipt.push(JournalReceiptEntryV1 {
                batch_local_id: body.batch_local_id.clone(),
                evidence_id,
                sequence,
            });
        }

        let journal = state
            .journals
            .get_mut(&request.journal_id)
            .ok_or_else(|| JournalError::new(JournalErrorCode::Internal))?;
        require_owner(journal, &request.ownership_token)?;
        for (key, payload) in candidate_payloads {
            journal.payloads.entry(key).or_insert(payload);
        }
        journal.evidence.extend(envelopes.iter().cloned());
        journal.committed_through = last_sequence;
        for envelope in &envelopes {
            state.evidence_ids.insert(envelope.evidence_id);
        }
        state.next_evidence_material = next_material;

        Ok(JournalCommitReceiptV1 {
            first_sequence,
            last_sequence,
            entries: Arc::from(receipt),
        })
    }

    fn resolve_payload_now(
        &self,
        request: ResolveJournalPayloadV1,
    ) -> Result<ResolvedJournalPayloadV1, JournalError> {
        self.state
            .lock()
            .map_err(|_| JournalError::new(JournalErrorCode::Internal))?
            .journals
            .get(&request.journal_id)
            .and_then(|journal| journal.payloads.get(&request.key))
            .cloned()
            .ok_or_else(|| JournalError::new(JournalErrorCode::MissingPayload))
    }

    fn release_owner_now(&self, request: ReleaseJournalOwnerV1) -> Result<(), JournalError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| JournalError::new(JournalErrorCode::Internal))?;
        let journal = state
            .journals
            .get_mut(&request.journal_id)
            .ok_or_else(|| JournalError::new(JournalErrorCode::StaleOwnership))?;
        require_owner(journal, &request.ownership_token)?;
        journal.owner = None;
        Ok(())
    }
}

impl JournalStorage for InMemoryJournalStore {
    fn acquire_owner<'a>(
        &'a self,
        request: AcquireJournalOwnerV1,
    ) -> HostFuture<'a, Result<JournalOwnershipV1, JournalError>> {
        Box::pin(async move { self.acquire_owner_now(request) })
    }

    fn read_prefix<'a>(
        &'a self,
        request: ReadJournalPrefixV1,
    ) -> HostFuture<'a, Result<JournalPrefixV1, JournalError>> {
        Box::pin(async move { self.read_prefix_now(request) })
    }

    fn commit<'a>(
        &'a self,
        request: JournalCommitRequestV1,
    ) -> HostFuture<'a, Result<JournalCommitReceiptV1, JournalError>> {
        Box::pin(async move { self.commit_now(request) })
    }

    fn resolve_payload<'a>(
        &'a self,
        request: ResolveJournalPayloadV1,
    ) -> HostFuture<'a, Result<ResolvedJournalPayloadV1, JournalError>> {
        Box::pin(async move { self.resolve_payload_now(request) })
    }

    fn release_owner<'a>(
        &'a self,
        request: ReleaseJournalOwnerV1,
    ) -> HostFuture<'a, Result<(), JournalError>> {
        Box::pin(async move { self.release_owner_now(request) })
    }
}

fn require_owner(
    journal: &JournalState,
    token: &JournalOwnershipToken,
) -> Result<(), JournalError> {
    if journal.owner.as_ref() == Some(token) {
        Ok(())
    } else {
        Err(JournalError::new(JournalErrorCode::StaleOwnership))
    }
}

fn validate_local_reference_graph(batch: &JournalBatchV1) -> Result<(), JournalError> {
    let ids = batch
        .evidence
        .iter()
        .map(|body| body.batch_local_id.clone())
        .collect::<BTreeSet<_>>();
    if ids.len() != batch.evidence.len() {
        return Err(JournalError::new(JournalErrorCode::InvalidBatch));
    }

    let mut outgoing = ids
        .iter()
        .cloned()
        .map(|id| (id, BTreeSet::new()))
        .collect::<BTreeMap<_, _>>();
    let mut incoming = ids
        .iter()
        .cloned()
        .map(|id| (id, 0_usize))
        .collect::<BTreeMap<_, _>>();
    for body in batch.evidence.iter() {
        for local in body
            .references
            .iter()
            .filter_map(|reference| match reference {
                JournalEvidenceReferenceV1::BatchLocal(local) => Some(local),
                JournalEvidenceReferenceV1::Existing(_) => None,
            })
        {
            if !ids.contains(local) {
                return Err(JournalError::new(JournalErrorCode::InvalidBatch));
            }
            let inserted = outgoing
                .get_mut(&body.batch_local_id)
                .ok_or_else(|| JournalError::new(JournalErrorCode::Internal))?
                .insert(local.clone());
            if inserted {
                let count = incoming
                    .get_mut(local)
                    .ok_or_else(|| JournalError::new(JournalErrorCode::Internal))?;
                *count = count.saturating_add(1);
            }
        }
    }

    let mut ready = incoming
        .iter()
        .filter_map(|(id, count)| (*count == 0).then_some(id.clone()))
        .collect::<VecDeque<_>>();
    let mut visited = 0_usize;
    while let Some(id) = ready.pop_front() {
        visited = visited.saturating_add(1);
        for target in outgoing.get(&id).into_iter().flatten() {
            let count = incoming
                .get_mut(target)
                .ok_or_else(|| JournalError::new(JournalErrorCode::Internal))?;
            *count = count.saturating_sub(1);
            if *count == 0 {
                ready.push_back(target.clone());
            }
        }
    }
    if visited == ids.len() {
        Ok(())
    } else {
        Err(JournalError::new(JournalErrorCode::InvalidBatch))
    }
}

fn validate_existing_references(
    journal: &JournalState,
    batch: &JournalBatchV1,
) -> Result<(), JournalError> {
    let known = journal
        .evidence
        .iter()
        .map(|envelope| envelope.evidence_id)
        .collect::<BTreeSet<_>>();
    for identity in batch
        .evidence
        .iter()
        .flat_map(|body| body.references.iter())
        .filter_map(|reference| match reference {
            JournalEvidenceReferenceV1::Existing(identity) => Some(identity),
            JournalEvidenceReferenceV1::BatchLocal(_) => None,
        })
    {
        if identity.kind() != IdentityKind::Evidence || !known.contains(identity) {
            return Err(JournalError::new(JournalErrorCode::MissingEvidence));
        }
    }
    Ok(())
}

fn validate_payloads(
    journal: &JournalState,
    batch: &JournalBatchV1,
) -> Result<BTreeMap<gantry_host::journal::JournalPayloadKey, ResolvedJournalPayloadV1>, JournalError>
{
    let mut candidates = BTreeMap::new();
    for payload in batch.protected_payloads.iter() {
        let resolved = ResolvedJournalPayloadV1 {
            class: payload.class,
            bytes: Arc::clone(&payload.bytes),
        };
        if journal
            .payloads
            .get(&payload.key)
            .is_some_and(|existing| existing != &resolved)
            || candidates
                .insert(payload.key.clone(), resolved.clone())
                .is_some_and(|existing| existing != resolved)
        {
            return Err(JournalError::new(JournalErrorCode::PayloadConflict));
        }
    }
    for key in batch
        .evidence
        .iter()
        .flat_map(|body| body.protected_payloads.iter())
    {
        if !journal.payloads.contains_key(key) && !candidates.contains_key(key) {
            return Err(JournalError::new(JournalErrorCode::MissingPayload));
        }
    }
    Ok(candidates)
}
