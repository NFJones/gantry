//! Canonical carriage of issuing evidence and declared resource reconstruction facts.
//!
//! This envelope is not ordinary value serialization or a journal authentication mechanism.
//! Its caller supplies independent byte, current-owner and cleanup-task admission facts. Subjects
//! are rederived from validated issuing checkpoints; no physical ownership or pending work resumes.

use std::sync::Arc;

use gantry_core::identity::ProtocolIdentity;
use gantry_core::portable::IdentityKind;
use gantry_ir::{
    Completion, ContainmentSettlement, EffectState, ExternalOutcome, MachineProgram,
    OwnerGeneration, ResourceCarrier,
};

use super::{
    RecoveredResourceRecord, ResourceOriginRecoveryError, ResourceRecordCodecError,
    decode_resource_reconstruction_record, encode_resource_reconstruction_record,
};
use crate::machine::checkpoint_codec::{Reader, Writer};

const MAGIC: &[u8; 8] = b"GNTRRE01";
const MAGIC_V2: &[u8; 8] = b"GNTRRE02";

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
    let containment = record.containment_evidence().map(|(owner, winner)| {
        let mut writer = Writer::default();
        writer.u64(owner.value());
        writer.boolean(winner.is_some());
        if let Some((effect, outcome)) = winner {
            writer.u8(match effect {
                EffectState::NotStarted => 0,
                EffectState::DefiniteRejection => 1,
                EffectState::Ambiguous => 2,
            });
            writer.u8(match outcome {
                ExternalOutcome::Accepted => 0,
                ExternalOutcome::Rejected => 1,
                ExternalOutcome::Ambiguous => 2,
            });
        }
        writer.finish()
    });
    let length = [checkpoint.len(), budget.len(), cleanup.len(), facts.len()]
        .into_iter()
        .try_fold(MAGIC.len(), |length, member| {
            length.checked_add(8)?.checked_add(member)
        })
        .and_then(|length| {
            containment.as_ref().map_or(Some(length), |facts| {
                length.checked_add(8)?.checked_add(facts.len())
            })
        })
        .and_then(|length| u64::try_from(length).ok())
        .ok_or(ResourceRecoveryEnvelopeError::ByteLimit)?;
    if length > maximum_bytes {
        return Err(ResourceRecoveryEnvelopeError::ByteLimit);
    }
    let mut writer = Writer::default();
    writer.raw(if containment.is_some() {
        MAGIC_V2
    } else {
        MAGIC
    });
    writer.bytes(checkpoint);
    writer.bytes(&budget);
    writer.bytes(cleanup.as_bytes());
    writer.bytes(&facts);
    if let Some(containment) = containment {
        writer.bytes(&containment);
    }
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
    let magic = reader
        .raw(MAGIC.len())
        .map_err(|_| ResourceRecoveryEnvelopeError::Encoding)?;
    if magic != MAGIC && magic != MAGIC_V2 {
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
    let containment = if magic == MAGIC_V2 {
        Some(
            reader
                .bytes()
                .map_err(|_| ResourceRecoveryEnvelopeError::Encoding)?,
        )
    } else {
        None
    };
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
    if let Some(bytes) = containment {
        let mut reader = Reader::new(bytes);
        let historical_owner = OwnerGeneration::new(
            reader
                .u64()
                .map_err(|_| ResourceRecoveryEnvelopeError::Encoding)?,
        );
        if historical_owner != owner && !owner.succeeds(historical_owner) {
            return Err(ResourceRecoveryEnvelopeError::Encoding);
        }
        let winner = if reader
            .boolean()
            .map_err(|_| ResourceRecoveryEnvelopeError::Encoding)?
        {
            let effect = match reader
                .u8()
                .map_err(|_| ResourceRecoveryEnvelopeError::Encoding)?
            {
                0 => EffectState::NotStarted,
                1 => EffectState::DefiniteRejection,
                2 => EffectState::Ambiguous,
                _ => return Err(ResourceRecoveryEnvelopeError::Encoding),
            };
            let outcome = match reader
                .u8()
                .map_err(|_| ResourceRecoveryEnvelopeError::Encoding)?
            {
                0 => ExternalOutcome::Accepted,
                1 => ExternalOutcome::Rejected,
                2 => ExternalOutcome::Ambiguous,
                _ => return Err(ResourceRecoveryEnvelopeError::Encoding),
            };
            ContainmentSettlement::open(historical_owner)
                .settle(historical_owner, Completion::observed(outcome, effect))
                .map_err(|_| ResourceRecoveryEnvelopeError::Encoding)?;
            Some((effect, outcome))
        } else {
            None
        };
        if !reader.is_empty() {
            return Err(ResourceRecoveryEnvelopeError::Encoding);
        }
        record.containment_evidence = Some((historical_owner, winner));
    }
    if encode_resource_recovery_envelope(&record, maximum_bytes)? != bytes {
        return Err(ResourceRecoveryEnvelopeError::Encoding);
    }
    Ok(record)
}
