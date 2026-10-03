//! Lossless bounded snapshots for histories containing logical resource finish cuts.
//!
//! Every authoritative envelope is retained. This carrier enables snapshot/suffix recovery,
//! not history reduction, payload embedding, storage authentication or physical reconstruction.

use std::collections::BTreeMap;
use std::sync::Arc;

use gantry_core::identity::ProtocolIdentity;
use gantry_core::portable::IdentityKind;
use gantry_host::journal::{
    FullJournalPrefixV1, JournalEvidenceEnvelopeV1, JournalId, JournalPayloadKey, JournalPrefixV1,
    SnapshotJournalPrefixV1, validate_journal_prefix,
};
use gantry_ir::MachineProgram;

use super::{
    DurableEvidenceError, DurableExecutionStartV3, recover_concurrent_authoritative_prefix,
};
use crate::machine::checkpoint_codec::{Reader, Writer};

const MAGIC: &[u8; 8] = b"GNTCSF01";
/// Independent admission ceiling for the complete lossless snapshot carrier.
pub const MAXIMUM_FINISH_SNAPSHOT_BYTES: u64 = 16_777_216;
/// Snapshot selector distinct from the legacy version-seven projection.
pub const CONCURRENT_FINISH_SNAPSHOT_VERSION_V1: u64 = 8;

/// Validated complete history retained independently of a journal's later suffix.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConcurrentFinishSnapshotV1 {
    full: FullJournalPrefixV1,
    bytes: Arc<[u8]>,
}

impl ConcurrentFinishSnapshotV1 {
    /// Validates authoritative replay before retaining a bounded full history.
    ///
    /// Storage authenticity and payload availability remain caller responsibilities. The
    /// ceiling bounds encoded bytes, not allocations already owned by the supplied history.
    pub fn from_full_prefix(
        program: Arc<MachineProgram>,
        full: &FullJournalPrefixV1,
        maximum_bytes: u64,
    ) -> Result<Self, DurableEvidenceError> {
        let bytes = encode(full, maximum_bytes)?;
        recover_concurrent_authoritative_prefix(program, &JournalPrefixV1::Full(full.clone()))?;
        if full
            .evidence
            .first()
            .is_none_or(|entry| entry.kind.as_ref() != "gantry.execution-start/v3")
        {
            return Err(DurableEvidenceError::InvalidExecutionStart);
        }
        Ok(Self {
            full: full.clone(),
            bytes: bytes.into(),
        })
    }

    /// Decodes framing before validating the complete causal history against the executable.
    pub fn decode(
        program: Arc<MachineProgram>,
        bytes: &[u8],
        maximum_bytes: u64,
    ) -> Result<Self, DurableEvidenceError> {
        let full = read_full(bytes, maximum_bytes)?;
        let snapshot = Self::from_full_prefix(program, &full, maximum_bytes)?;
        if snapshot.canonical_bytes() != bytes {
            return Err(DurableEvidenceError::Encoding);
        }
        Ok(snapshot)
    }

    /// Returns immutable canonical carrier bytes, with all original envelopes retained.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Decodes the execution-start envelope retained by this validated history.
    /// The supplied executable must match the original immutable start contract.
    pub fn execution_start(
        &self,
        program: &MachineProgram,
    ) -> Result<DurableExecutionStartV3, DurableEvidenceError> {
        let start = self
            .full
            .evidence
            .first()
            .ok_or(DurableEvidenceError::InvalidExecutionStart)?;
        DurableExecutionStartV3::decode(program, &start.canonical_body)
    }

    /// Projects an empty-suffix authoritative snapshot with exact identity/sequence bindings.
    #[must_use]
    pub fn prefix(&self) -> SnapshotJournalPrefixV1 {
        SnapshotJournalPrefixV1 {
            journal_id: self.full.journal_id.clone(),
            snapshot_version: CONCURRENT_FINISH_SNAPSHOT_VERSION_V1,
            frontier: self.full.committed_through,
            canonical_snapshot: Arc::clone(&self.bytes),
            retained_evidence: bindings(&self.full),
            suffix: Arc::from([]),
            committed_through: self.full.committed_through,
        }
    }

    /// Extracts the retained executable from bounded framing before executable-dependent replay.
    /// This does not by itself validate causal history or authenticate storage.
    pub fn retained_program(bytes: &[u8]) -> Result<MachineProgram, DurableEvidenceError> {
        let full = read_full(bytes, MAXIMUM_FINISH_SNAPSHOT_BYTES)?;
        let start = full
            .evidence
            .first()
            .filter(|entry| {
                entry.sequence == 1 && entry.kind.as_ref() == "gantry.execution-start/v3"
            })
            .ok_or(DurableEvidenceError::InvalidExecutionStart)?;
        DurableExecutionStartV3::retained_program(&start.canonical_body)
    }

    /// Checks external snapshot coordinates and expands the retained history plus suffix.
    /// The caller must replay the returned full prefix before exposing recovered state.
    pub(super) fn expand(
        program: Arc<MachineProgram>,
        prefix: &SnapshotJournalPrefixV1,
    ) -> Result<FullJournalPrefixV1, DurableEvidenceError> {
        let snapshot = Self::decode(
            program,
            &prefix.canonical_snapshot,
            MAXIMUM_FINISH_SNAPSHOT_BYTES,
        )?;
        if prefix.snapshot_version != CONCURRENT_FINISH_SNAPSHOT_VERSION_V1
            || snapshot.full.journal_id != prefix.journal_id
            || snapshot.full.committed_through != prefix.frontier
            || bindings(&snapshot.full) != prefix.retained_evidence
        {
            return Err(DurableEvidenceError::InvalidCausalOrder);
        }
        let mut evidence = snapshot.full.evidence.to_vec();
        evidence.extend(prefix.suffix.iter().cloned());
        let full = FullJournalPrefixV1 {
            journal_id: prefix.journal_id.clone(),
            evidence: evidence.into(),
            committed_through: prefix.committed_through,
        };
        validate_journal_prefix(&JournalPrefixV1::Full(full.clone()))
            .map_err(DurableEvidenceError::Journal)?;
        Ok(full)
    }
}

/// Derives bindings from replay-validated complete history, never caller-selected identities.
fn bindings(full: &FullJournalPrefixV1) -> BTreeMap<ProtocolIdentity, u64> {
    full.evidence
        .iter()
        .map(|entry| (entry.evidence_id, entry.sequence))
        .collect()
}

/// Computes complete framing size before copying any envelope body into the output.
fn encode(full: &FullJournalPrefixV1, maximum_bytes: u64) -> Result<Vec<u8>, DurableEvidenceError> {
    let mut length = 8_u64 + 8 + 8;
    let mut add = |size: usize| -> Result<(), DurableEvidenceError> {
        length = length
            .checked_add(8)
            .and_then(|n| n.checked_add(u64::try_from(size).ok()?))
            .ok_or(DurableEvidenceError::Encoding)?;
        Ok(())
    };
    add(full.journal_id.as_str().len())?;
    for entry in full.evidence.iter() {
        add(8)?; // sequence is encoded as a framed eight-byte member
        add(entry.evidence_id.to_string().len())?;
        add(entry.kind.len())?;
        add(entry.canonical_body.len())?;
        add(8)?; // framed reference count
        for reference in entry.references.iter() {
            add(reference.to_string().len())?;
        }
        add(8)?; // framed payload count
        for key in entry.protected_payloads.iter() {
            add(key.as_str().len())?;
        }
    }
    if length > maximum_bytes.min(MAXIMUM_FINISH_SNAPSHOT_BYTES) {
        return Err(DurableEvidenceError::Encoding);
    }
    let mut writer = Writer::default();
    writer.raw(MAGIC);
    writer.string(full.journal_id.as_str());
    writer.u64(full.committed_through);
    writer.count(full.evidence.len());
    for entry in full.evidence.iter() {
        writer.bytes(&entry.sequence.to_be_bytes());
        writer.string(&entry.evidence_id.to_string());
        writer.string(&entry.kind);
        writer.bytes(&entry.canonical_body);
        writer.bytes(&(entry.references.len() as u64).to_be_bytes());
        for reference in entry.references.iter() {
            writer.string(&reference.to_string());
        }
        writer.bytes(&(entry.protected_payloads.len() as u64).to_be_bytes());
        for key in entry.protected_payloads.iter() {
            writer.string(key.as_str());
        }
    }
    Ok(writer.finish())
}

/// Parses independently bounded framing; no capacity is allocated from an unchecked count.
fn read_full(
    bytes: &[u8],
    maximum_bytes: u64,
) -> Result<FullJournalPrefixV1, DurableEvidenceError> {
    if u64::try_from(bytes.len()).map_or(true, |n| {
        n > maximum_bytes.min(MAXIMUM_FINISH_SNAPSHOT_BYTES)
    }) {
        return Err(DurableEvidenceError::Encoding);
    }
    let parse = || -> Result<FullJournalPrefixV1, crate::MachineRecoveryError> {
        let mut reader = Reader::new(bytes);
        if reader.raw(8)? != MAGIC {
            return Err(crate::MachineRecoveryError::InvalidEncoding);
        }
        let journal = JournalId::new(reader.string()?)
            .map_err(|_| crate::MachineRecoveryError::InvalidEncoding)?;
        let committed_through = reader.u64()?;
        let count = reader.count()?;
        let mut evidence = Vec::new();
        for _ in 0..count {
            let sequence = framed_u64(&mut reader)?;
            let identity = ProtocolIdentity::parse_kind(&reader.string()?, IdentityKind::Evidence)
                .map_err(|_| crate::MachineRecoveryError::InvalidEncoding)?;
            let kind = reader.string()?;
            let body = Arc::from(reader.bytes()?);
            let references_count = framed_u64(&mut reader)?;
            if references_count > bytes.len() as u64 {
                return Err(crate::MachineRecoveryError::InvalidEncoding);
            }
            let mut references = Vec::new();
            for _ in 0..references_count {
                references.push(
                    ProtocolIdentity::parse_kind(&reader.string()?, IdentityKind::Evidence)
                        .map_err(|_| crate::MachineRecoveryError::InvalidEncoding)?,
                );
            }
            let payload_count = framed_u64(&mut reader)?;
            if payload_count > bytes.len() as u64 {
                return Err(crate::MachineRecoveryError::InvalidEncoding);
            }
            let mut payloads = Vec::new();
            for _ in 0..payload_count {
                payloads.push(
                    JournalPayloadKey::new(reader.string()?)
                        .map_err(|_| crate::MachineRecoveryError::InvalidEncoding)?,
                );
            }
            evidence.push(JournalEvidenceEnvelopeV1 {
                journal_id: journal.clone(),
                sequence,
                evidence_id: identity,
                kind: kind.into(),
                canonical_body: body,
                references: references.into(),
                protected_payloads: payloads.into(),
            });
        }
        if !reader.is_empty() {
            return Err(crate::MachineRecoveryError::InvalidEncoding);
        }
        Ok(FullJournalPrefixV1 {
            journal_id: journal,
            evidence: evidence.into(),
            committed_through,
        })
    };
    parse().map_err(|_| DurableEvidenceError::Encoding)
}

/// Reads one exactly framed u64, rejecting alternate member widths.
fn framed_u64(reader: &mut Reader<'_>) -> Result<u64, crate::MachineRecoveryError> {
    let value: [u8; 8] = reader
        .bytes()?
        .try_into()
        .map_err(|_| crate::MachineRecoveryError::InvalidEncoding)?;
    Ok(u64::from_be_bytes(value))
}
