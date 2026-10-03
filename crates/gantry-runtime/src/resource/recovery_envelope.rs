//! Canonical carriage of issuing evidence and declared resource reconstruction facts.
//!
//! This envelope is not ordinary value serialization or a journal authentication mechanism.
//! Its caller supplies independent byte, current-owner and cleanup-task admission facts. Subjects
//! are rederived from validated issuing checkpoints; no physical ownership or pending work resumes.

use std::sync::Arc;

use gantry_core::identity::ProtocolIdentity;
use gantry_core::portable::IdentityKind;
use gantry_ir::{MachineProgram, OwnerGeneration, ResourceCarrier};

use super::{
    RecoveredResourceRecord, ResourceOriginRecoveryError, ResourceRecordCodecError,
    decode_resource_reconstruction_record, encode_resource_reconstruction_record,
};
use crate::machine::checkpoint_codec::{Reader, Writer};

const MAGIC: &[u8; 8] = b"GNTRRE01";

/// Refusal while admitting an independently bounded resource reconstruction envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResourceRecoveryEnvelopeError {
    /// The independent byte ceiling is exceeded, including length arithmetic overflow.
    ByteLimit,
    /// Framing, version, identity, or canonical spelling is invalid.
    Encoding,
    /// Legacy accounting facts have no validated issuing evidence to carry.
    MissingIssuingEvidence,
    /// Serialized cleanup ownership disagrees with the recovery pass's expected task.
    CleanupTaskMismatch,
    /// Declared subject-free reconstruction bytes fail their closed schema or model checks.
    Record(ResourceRecordCodecError),
    /// Issuing provenance or the separately supplied current owner fails validation.
    Origin(ResourceOriginRecoveryError),
}

/// Encodes declared accounting with issuing evidence under an independent total byte ceiling.
///
/// Checks the complete encoded length before copying the retained checkpoint into the envelope.
/// No subject identity is serialized; decoding derives it from the issuing checkpoint instead.
pub fn encode_resource_recovery_envelope(
    record: &RecoveredResourceRecord,
    maximum_bytes: u64,
) -> Result<Vec<u8>, ResourceRecoveryEnvelopeError> {
    let (checkpoint, budget) = record
        .issuing_evidence()
        .ok_or(ResourceRecoveryEnvelopeError::MissingIssuingEvidence)?;
    let budget = budget.canonical_bytes();
    let cleanup = record.task_owner().to_string();
    let facts = encode_resource_reconstruction_record(record.record());
    let length = [checkpoint.len(), budget.len(), cleanup.len(), facts.len()]
        .into_iter()
        .try_fold(MAGIC.len(), |length, member| {
            length.checked_add(8)?.checked_add(member)
        })
        .and_then(|length| u64::try_from(length).ok())
        .ok_or(ResourceRecoveryEnvelopeError::ByteLimit)?;
    if length > maximum_bytes {
        return Err(ResourceRecoveryEnvelopeError::ByteLimit);
    }
    let mut writer = Writer::default();
    writer.raw(MAGIC);
    writer.bytes(checkpoint);
    writer.bytes(&budget);
    writer.bytes(cleanup.as_bytes());
    writer.bytes(&facts);
    Ok(writer.finish())
}

/// Decodes declared reconstruction evidence without trusting serialized subject or owner identity.
///
/// Refuses excess input before parsing or copying. Framing and expected cleanup ownership are
/// checked before issuing machine recovery; the current owner is separately supplied, never
/// inferred from the record. Success returns accounting evidence with a closed private lease.
pub fn decode_resource_recovery_envelope(
    program: Arc<MachineProgram>,
    bytes: &[u8],
    maximum_bytes: u64,
    owner: OwnerGeneration,
    cleanup_task: ProtocolIdentity,
) -> Result<RecoveredResourceRecord, ResourceRecoveryEnvelopeError> {
    if u64::try_from(bytes.len()).map_or(true, |length| length > maximum_bytes) {
        return Err(ResourceRecoveryEnvelopeError::ByteLimit);
    }
    let mut reader = Reader::new(bytes);
    if reader
        .raw(MAGIC.len())
        .map_err(|_| ResourceRecoveryEnvelopeError::Encoding)?
        != MAGIC
    {
        return Err(ResourceRecoveryEnvelopeError::Encoding);
    }
    let checkpoint = reader
        .bytes()
        .map_err(|_| ResourceRecoveryEnvelopeError::Encoding)?;
    let budget = reader
        .bytes()
        .map_err(|_| ResourceRecoveryEnvelopeError::Encoding)?;
    let cleanup = reader
        .bytes()
        .map_err(|_| ResourceRecoveryEnvelopeError::Encoding)?;
    let facts = reader
        .bytes()
        .map_err(|_| ResourceRecoveryEnvelopeError::Encoding)?;
    if !reader.is_empty() {
        return Err(ResourceRecoveryEnvelopeError::Encoding);
    }
    let cleanup = std::str::from_utf8(cleanup)
        .ok()
        .and_then(|value| ProtocolIdentity::parse_kind(value, IdentityKind::Task).ok())
        .ok_or(ResourceRecoveryEnvelopeError::Encoding)?;
    if cleanup != cleanup_task {
        return Err(ResourceRecoveryEnvelopeError::CleanupTaskMismatch);
    }
    let checkpoint = crate::MachineCheckpointV3::decode(&program, checkpoint).map_err(|error| {
        ResourceRecoveryEnvelopeError::Origin(ResourceOriginRecoveryError::Machine(error))
    })?;
    let budget = crate::ExecutionBudgetSnapshot::decode(budget).map_err(|error| {
        ResourceRecoveryEnvelopeError::Origin(ResourceOriginRecoveryError::Machine(error))
    })?;
    let facts = decode_resource_reconstruction_record(facts)
        .map_err(ResourceRecoveryEnvelopeError::Record)?;
    let mut record = RecoveredResourceRecord::from_issuing_checkpoint(
        program,
        checkpoint,
        budget,
        ResourceCarrier::ReconstructionRecord,
        owner,
        facts,
    )
    .map_err(ResourceRecoveryEnvelopeError::Origin)?;
    record.task_owner = cleanup;
    if encode_resource_recovery_envelope(&record, maximum_bytes)? != bytes {
        return Err(ResourceRecoveryEnvelopeError::Encoding);
    }
    Ok(record)
}
