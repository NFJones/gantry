//! Backend-neutral durable journal contracts.
//!
//! These types describe logical ownership, prefix, evidence, payload, and
//! receipt semantics. Concrete adapters remain free to use transactions,
//! append logs, snapshots, or another physical representation.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use gantry_core::identity::ProtocolIdentity;
use gantry_core::portable::{IdentityKind, JournalPrefixForm, ProtectedReferenceClass};

use crate::contracts::HostFuture;

/// Stable integration-owned journal target identity.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct JournalId(Arc<str>);

impl JournalId {
    /// Constructs one nonempty journal target identity.
    pub fn new(value: impl Into<Arc<str>>) -> Result<Self, JournalContractError> {
        let value = value.into();
        if value.is_empty() {
            return Err(JournalContractError::EmptyIdentifier);
        }
        Ok(Self(value))
    }

    /// Returns the exact integration-owned spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Opaque fencing token granted to one active journal owner.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct JournalOwnershipToken(Arc<str>);

impl JournalOwnershipToken {
    /// Constructs one nonempty opaque token returned by storage.
    pub fn new(value: impl Into<Arc<str>>) -> Result<Self, JournalContractError> {
        let value = value.into();
        if value.is_empty() {
            return Err(JournalContractError::EmptyIdentifier);
        }
        Ok(Self(value))
    }

    /// Returns the exact opaque token spelling for adapter round trips.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Caller operation competing for exclusive journal ownership.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JournalOwnerOperationV1 {
    /// A new execution candidate.
    Start,
    /// A resume candidate for existing history.
    Resume,
}

/// Exclusive ownership request for one journal target.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcquireJournalOwnerV1 {
    /// Stable journal target.
    pub journal_id: JournalId,
    /// Start or resume acquisition class.
    pub operation: JournalOwnerOperationV1,
}

/// Exclusive fenced journal ownership returned by storage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalOwnershipV1 {
    /// Stable journal target.
    pub journal_id: JournalId,
    /// Token required by every mutating operation.
    pub token: JournalOwnershipToken,
}

/// Caller-assigned identifier local to one atomic commit batch.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct BatchLocalEvidenceId(Arc<str>);

impl BatchLocalEvidenceId {
    /// Constructs one nonempty batch-local identifier.
    pub fn new(value: impl Into<Arc<str>>) -> Result<Self, JournalContractError> {
        let value = value.into();
        if value.is_empty() {
            return Err(JournalContractError::EmptyIdentifier);
        }
        Ok(Self(value))
    }

    /// Returns the exact caller-assigned spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Stable protected-payload key within one journal.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct JournalPayloadKey(Arc<str>);

impl JournalPayloadKey {
    /// Constructs one nonempty stable payload key.
    pub fn new(value: impl Into<Arc<str>>) -> Result<Self, JournalContractError> {
        let value = value.into();
        if value.is_empty() {
            return Err(JournalContractError::EmptyIdentifier);
        }
        Ok(Self(value))
    }

    /// Returns the exact caller-assigned spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Causal or semantic reference from an unfinalized evidence body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JournalEvidenceReferenceV1 {
    /// A stable evidence identity already retained by the journal.
    Existing(ProtocolIdentity),
    /// Another body in the same atomic batch.
    BatchLocal(BatchLocalEvidenceId),
}

/// One unfinalized logical evidence body in an atomic batch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnfinalizedEvidenceV1 {
    /// Caller-assigned identifier unique within this batch.
    pub batch_local_id: BatchLocalEvidenceId,
    /// Versioned logical evidence kind.
    pub kind: Arc<str>,
    /// Exact validated canonical kind-specific body bytes.
    pub canonical_body: Arc<[u8]>,
    /// Ordered causal or semantic evidence references.
    pub references: Arc<[JournalEvidenceReferenceV1]>,
    /// Stable protected-payload keys required by this body.
    pub protected_payloads: Arc<[JournalPayloadKey]>,
}

impl UnfinalizedEvidenceV1 {
    /// Validates nonempty kind and body fields before batching.
    pub fn new(
        batch_local_id: BatchLocalEvidenceId,
        kind: impl Into<Arc<str>>,
        canonical_body: impl Into<Arc<[u8]>>,
        references: impl Into<Arc<[JournalEvidenceReferenceV1]>>,
        protected_payloads: impl Into<Arc<[JournalPayloadKey]>>,
    ) -> Result<Self, JournalContractError> {
        let kind = kind.into();
        let canonical_body = canonical_body.into();
        if kind.is_empty() || canonical_body.is_empty() {
            return Err(JournalContractError::EmptyEvidenceBody);
        }
        Ok(Self {
            batch_local_id,
            kind,
            canonical_body,
            references: references.into(),
            protected_payloads: protected_payloads.into(),
        })
    }
}

/// One exact protected payload admitted with an atomic evidence batch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalProtectedPayloadV1 {
    /// Stable key unique within the journal.
    pub key: JournalPayloadKey,
    /// Protected-data class governing later resolution and delivery.
    pub class: ProtectedReferenceClass,
    /// Exact protected bytes stored outside ordinary envelopes.
    pub bytes: Arc<[u8]>,
}

/// One nonempty atomic logical evidence batch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalBatchV1 {
    /// Unfinalized evidence bodies in caller order.
    pub evidence: Arc<[UnfinalizedEvidenceV1]>,
    /// Protected payload entries admitted atomically with those bodies.
    pub protected_payloads: Arc<[JournalProtectedPayloadV1]>,
}

impl JournalBatchV1 {
    /// Constructs a batch containing at least one logical evidence body.
    pub fn new(
        evidence: impl Into<Arc<[UnfinalizedEvidenceV1]>>,
        protected_payloads: impl Into<Arc<[JournalProtectedPayloadV1]>>,
    ) -> Result<Self, JournalContractError> {
        let evidence = evidence.into();
        if evidence.is_empty() {
            return Err(JournalContractError::EmptyBatch);
        }
        Ok(Self {
            evidence,
            protected_payloads: protected_payloads.into(),
        })
    }
}

/// Fenced atomic commit request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalCommitRequestV1 {
    /// Stable journal target.
    pub journal_id: JournalId,
    /// Current ownership token.
    pub ownership_token: JournalOwnershipToken,
    /// Nonempty atomic batch.
    pub batch: JournalBatchV1,
}

/// One finalized immutable logical evidence envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalEvidenceEnvelopeV1 {
    /// Stable owning journal.
    pub journal_id: JournalId,
    /// Contiguous logical sequence beginning at one.
    pub sequence: u64,
    /// Storage-assigned stable evidence identity.
    pub evidence_id: ProtocolIdentity,
    /// Versioned logical evidence kind.
    pub kind: Arc<str>,
    /// Exact validated canonical kind-specific body bytes.
    pub canonical_body: Arc<[u8]>,
    /// Resolved stable evidence references in caller order.
    pub references: Arc<[ProtocolIdentity]>,
    /// Stable protected-payload keys required by this evidence.
    pub protected_payloads: Arc<[JournalPayloadKey]>,
}

/// One finalized mapping entry returned by an atomic commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalReceiptEntryV1 {
    /// Caller-assigned batch-local identifier.
    pub batch_local_id: BatchLocalEvidenceId,
    /// Storage-assigned stable evidence identity.
    pub evidence_id: ProtocolIdentity,
    /// Assigned contiguous sequence.
    pub sequence: u64,
}

/// Receipt for one successful atomic commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalCommitReceiptV1 {
    /// First assigned sequence.
    pub first_sequence: u64,
    /// Last assigned sequence.
    pub last_sequence: u64,
    /// One mapping entry per body in caller order.
    pub entries: Arc<[JournalReceiptEntryV1]>,
}

/// Authoritative complete uncompacted journal prefix.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FullJournalPrefixV1 {
    /// Stable journal target.
    pub journal_id: JournalId,
    /// Envelopes beginning at sequence one without gaps.
    pub evidence: Arc<[JournalEvidenceEnvelopeV1]>,
    /// Authoritative durability watermark.
    pub committed_through: u64,
}

/// Authoritative versioned snapshot plus contiguous retained suffix.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotJournalPrefixV1 {
    /// Stable journal target.
    pub journal_id: JournalId,
    /// Positive snapshot format version.
    pub snapshot_version: u64,
    /// Sequence represented by the snapshot.
    pub frontier: u64,
    /// Exact validated canonical snapshot bytes.
    pub canonical_snapshot: Arc<[u8]>,
    /// Retained evidence identity to original sequence mapping.
    pub retained_evidence: BTreeMap<ProtocolIdentity, u64>,
    /// Evidence contiguous from `frontier + 1`.
    pub suffix: Arc<[JournalEvidenceEnvelopeV1]>,
    /// Authoritative durability watermark.
    pub committed_through: u64,
}

/// One of the two authoritative durable-prefix forms.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JournalPrefixV1 {
    /// Complete uncompacted prefix.
    Full(FullJournalPrefixV1),
    /// Versioned snapshot plus suffix.
    Snapshot(SnapshotJournalPrefixV1),
}

impl JournalPrefixV1 {
    /// Returns the exact closed prefix-form vocabulary value.
    #[must_use]
    pub const fn form(&self) -> JournalPrefixForm {
        match self {
            Self::Full(_) => JournalPrefixForm::FullPrefix,
            Self::Snapshot(_) => JournalPrefixForm::SnapshotPrefix,
        }
    }
}

/// Read request for one authoritative journal prefix.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadJournalPrefixV1 {
    /// Stable journal target.
    pub journal_id: JournalId,
}

/// Protected payload resolution request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolveJournalPayloadV1 {
    /// Stable journal target.
    pub journal_id: JournalId,
    /// Stable protected-payload key.
    pub key: JournalPayloadKey,
}

/// Exact protected payload returned by storage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedJournalPayloadV1 {
    /// Protected-data class fixed at first commit.
    pub class: ProtectedReferenceClass,
    /// Exact stored bytes.
    pub bytes: Arc<[u8]>,
}

/// Atomic owner-release request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseJournalOwnerV1 {
    /// Stable journal target.
    pub journal_id: JournalId,
    /// Current ownership token to invalidate.
    pub ownership_token: JournalOwnershipToken,
}

/// Stable journal-storage failure category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JournalErrorCode {
    /// Another live owner holds the journal.
    OwnershipUnavailable,
    /// The supplied token is absent, released, or superseded.
    StaleOwnership,
    /// Batch identifiers or references are malformed.
    InvalidBatch,
    /// A referenced stable evidence identity is absent.
    MissingEvidence,
    /// A payload key conflicts with immutable stored content.
    PayloadConflict,
    /// A requested protected payload is absent.
    MissingPayload,
    /// Evidence identity allocation failed or collided repeatedly.
    IdentityFailure,
    /// A contiguous sequence or generation cannot advance.
    SequenceExhausted,
    /// Internal adapter state is unavailable.
    Internal,
}

impl JournalErrorCode {
    /// Returns the stable machine-facing spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::OwnershipUnavailable => "ownership-unavailable",
            Self::StaleOwnership => "stale-ownership",
            Self::InvalidBatch => "invalid-batch",
            Self::MissingEvidence => "missing-evidence",
            Self::PayloadConflict => "payload-conflict",
            Self::MissingPayload => "missing-payload",
            Self::IdentityFailure => "identity-failure",
            Self::SequenceExhausted => "sequence-exhausted",
            Self::Internal => "internal",
        }
    }
}

/// Structured journal-storage failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalError {
    /// Stable failure category.
    pub code: JournalErrorCode,
    /// Optional protected diagnostic reference.
    pub protected_diagnostic: Option<Arc<str>>,
}

impl JournalError {
    /// Constructs one failure without a protected diagnostic reference.
    #[must_use]
    pub const fn new(code: JournalErrorCode) -> Self {
        Self {
            code,
            protected_diagnostic: None,
        }
    }
}

/// Invalid typed journal contract construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JournalContractError {
    /// A stable or batch-local identifier is empty.
    EmptyIdentifier,
    /// An evidence body has no kind or no canonical body bytes.
    EmptyEvidenceBody,
    /// An atomic batch contains no evidence body.
    EmptyBatch,
    /// A finalized evidence identity has the wrong kind.
    InvalidEvidenceIdentity,
    /// A full or snapshot prefix violates its form, sequence, or watermark invariants.
    InvalidPrefix,
    /// A retained evidence reference does not resolve within the authoritative prefix.
    DanglingEvidenceReference,
}

/// Backend-neutral asynchronous journal storage boundary.
pub trait JournalStorage: Send + Sync {
    /// Acquires exclusive fenced authority to advance one journal.
    fn acquire_owner<'a>(
        &'a self,
        request: AcquireJournalOwnerV1,
    ) -> HostFuture<'a, Result<JournalOwnershipV1, JournalError>>;

    /// Reads one authoritative full or snapshot prefix.
    fn read_prefix<'a>(
        &'a self,
        request: ReadJournalPrefixV1,
    ) -> HostFuture<'a, Result<JournalPrefixV1, JournalError>>;

    /// Atomically commits one nonempty fenced evidence batch.
    fn commit<'a>(
        &'a self,
        request: JournalCommitRequestV1,
    ) -> HostFuture<'a, Result<JournalCommitReceiptV1, JournalError>>;

    /// Resolves one exact protected payload by stable journal-local key.
    fn resolve_payload<'a>(
        &'a self,
        request: ResolveJournalPayloadV1,
    ) -> HostFuture<'a, Result<ResolvedJournalPayloadV1, JournalError>>;

    /// Atomically invalidates one current ownership token.
    fn release_owner<'a>(
        &'a self,
        request: ReleaseJournalOwnerV1,
    ) -> HostFuture<'a, Result<(), JournalError>>;
}

/// Validates the typed invariants of one finalized evidence envelope.
pub fn validate_evidence_envelope(
    envelope: &JournalEvidenceEnvelopeV1,
) -> Result<(), JournalContractError> {
    if envelope.evidence_id.kind() != IdentityKind::Evidence {
        return Err(JournalContractError::InvalidEvidenceIdentity);
    }
    if envelope.sequence == 0 || envelope.kind.is_empty() || envelope.canonical_body.is_empty() {
        return Err(JournalContractError::EmptyEvidenceBody);
    }
    Ok(())
}

/// Validates one authoritative full or snapshot prefix independently of storage.
pub fn validate_journal_prefix(prefix: &JournalPrefixV1) -> Result<(), JournalContractError> {
    match prefix {
        JournalPrefixV1::Full(prefix) => validate_prefix_segment(
            &prefix.journal_id,
            0,
            prefix.committed_through,
            &prefix.evidence,
            BTreeSet::new(),
        ),
        JournalPrefixV1::Snapshot(prefix) => {
            if prefix.snapshot_version == 0
                || prefix.canonical_snapshot.is_empty()
                || prefix.frontier > prefix.committed_through
            {
                return Err(JournalContractError::InvalidPrefix);
            }
            let retained_sequences = prefix
                .retained_evidence
                .values()
                .copied()
                .collect::<BTreeSet<_>>();
            if retained_sequences.len() != prefix.retained_evidence.len()
                || retained_sequences
                    .iter()
                    .any(|sequence| *sequence == 0 || *sequence > prefix.frontier)
                || prefix
                    .retained_evidence
                    .keys()
                    .any(|identity| identity.kind() != IdentityKind::Evidence)
            {
                return Err(JournalContractError::InvalidPrefix);
            }
            validate_prefix_segment(
                &prefix.journal_id,
                prefix.frontier,
                prefix.committed_through,
                &prefix.suffix,
                prefix.retained_evidence.keys().copied().collect(),
            )
        }
    }
}

fn validate_prefix_segment(
    journal_id: &JournalId,
    frontier: u64,
    committed_through: u64,
    evidence: &[JournalEvidenceEnvelopeV1],
    mut known: BTreeSet<ProtocolIdentity>,
) -> Result<(), JournalContractError> {
    let mut expected = frontier
        .checked_add(1)
        .ok_or(JournalContractError::InvalidPrefix)?;
    for envelope in evidence {
        validate_evidence_envelope(envelope)?;
        if &envelope.journal_id != journal_id
            || envelope.sequence != expected
            || !known.insert(envelope.evidence_id)
        {
            return Err(JournalContractError::InvalidPrefix);
        }
        expected = expected
            .checked_add(1)
            .ok_or(JournalContractError::InvalidPrefix)?;
    }
    if expected.saturating_sub(1) != committed_through {
        return Err(JournalContractError::InvalidPrefix);
    }
    if evidence
        .iter()
        .flat_map(|envelope| envelope.references.iter())
        .any(|reference| !known.contains(reference))
    {
        return Err(JournalContractError::DanglingEvidenceReference);
    }
    Ok(())
}
