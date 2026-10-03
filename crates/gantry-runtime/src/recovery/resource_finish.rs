//! Bounded exact resource-finish evidence, independent of journal publication authority.
//!
//! A transition names one canonical record index and changes only the ledger facts produced
//! by its owner-qualified finish operation. All other graph, policy and historical facts stay
//! identical. This validator does not relax existing journal resource-image fences.

use std::sync::Arc;

use gantry_ir::{MachineProgram, OwnerGeneration};

use crate::machine::checkpoint_codec::{Reader, Writer};
use crate::{ConcurrentDurableCheckpointV4, ResourceFinishTransition};

use super::DurableEvidenceError;

const MAGIC: &[u8; 8] = b"GNTRFT01";
/// Journal kind for exact logical resource finishing; older graph evidence is unchanged.
pub const RESOURCE_FINISH_EVIDENCE_KIND_V1: &str = "gantry.resource-finish-evidence/v1";
/// Independent ceiling for the complete journal finish carrier, including both graphs.
pub const MAXIMUM_RESOURCE_FINISH_EVIDENCE_BYTES: u64 = 4_194_304;

/// One exact logical finish transition between two validated graph checkpoints.
///
/// Artifact authentication, cleanup authority and journal publication remain caller-owned.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceFinishEvidenceV1 {
    previous: ConcurrentDurableCheckpointV4,
    current: ConcurrentDurableCheckpointV4,
    record_index: usize,
    owner: OwnerGeneration,
    transition: ResourceFinishTransition,
}

impl ResourceFinishEvidenceV1 {
    /// Validates one owner-qualified finish and exact equality of every other graph fact.
    ///
    /// Both checkpoints are revalidated against the supplied executable before comparison.
    /// Missing records, stale owners, illegal lifetimes or unrelated changes refuse without
    /// mutation. Successful validation creates no accepted work or physical resources.
    pub fn new(
        program: Arc<MachineProgram>,
        previous: ConcurrentDurableCheckpointV4,
        current: ConcurrentDurableCheckpointV4,
        record_index: usize,
        owner: OwnerGeneration,
        transition: ResourceFinishTransition,
    ) -> Result<Self, DurableEvidenceError> {
        previous
            .clone()
            .recover(Arc::clone(&program))
            .map_err(DurableEvidenceError::ConcurrentCheckpoint)?;
        current
            .clone()
            .recover(Arc::clone(&program))
            .map_err(DurableEvidenceError::ConcurrentCheckpoint)?;
        let mut records = previous.resource_records().to_vec();
        let record = records
            .get_mut(record_index)
            .ok_or(DurableEvidenceError::InvalidState)?;
        *record = record
            .stage_finish(owner, transition)
            .map_err(|_| DurableEvidenceError::InvalidState)?;
        let expected = previous
            .clone()
            .with_resource_records(program, records)
            .map_err(DurableEvidenceError::ConcurrentCheckpoint)?;
        if expected != current {
            return Err(DurableEvidenceError::InvalidState);
        }
        Ok(Self {
            previous,
            current,
            record_index,
            owner,
            transition,
        })
    }

    /// Returns the exact predecessor graph, not a caller-selected replacement baseline.
    #[must_use]
    pub const fn previous(&self) -> &ConcurrentDurableCheckpointV4 {
        &self.previous
    }

    /// Returns the exact logical successor; this is not proof of a journal commit.
    #[must_use]
    pub const fn current(&self) -> &ConcurrentDurableCheckpointV4 {
        &self.current
    }

    /// Returns the current cleanup task qualified by the validated target record.
    pub fn task_id(&self) -> gantry_core::identity::ProtocolIdentity {
        self.current.resource_records()[self.record_index].task_owner()
    }

    /// Encodes canonical evidence under an independent total byte ceiling.
    ///
    /// The ceiling includes all framing and is checked before copying checkpoint bytes into
    /// the output. Checkpoint construction and temporary encodings are not a peak-heap bound.
    pub fn encode(&self, maximum_bytes: u64) -> Result<Vec<u8>, DurableEvidenceError> {
        let previous = self.previous.canonical_bytes();
        let current = self.current.canonical_bytes();
        let header = 8_u64 + 8 + 8 + 1 + 8 + 8;
        let length = header
            .checked_add(u64::try_from(previous.len()).map_err(|_| DurableEvidenceError::Encoding)?)
            .and_then(|length| length.checked_add(u64::try_from(current.len()).ok()?))
            .and_then(|length| {
                length.checked_add(
                    if matches!(self.transition, ResourceFinishTransition::Complete { .. }) {
                        8
                    } else {
                        0
                    },
                )
            })
            .ok_or(DurableEvidenceError::Encoding)?;
        if length > maximum_bytes {
            return Err(DurableEvidenceError::Encoding);
        }
        let mut writer = Writer::default();
        writer.raw(MAGIC);
        writer.count(self.record_index);
        writer.u64(self.owner.value());
        match self.transition {
            ResourceFinishTransition::Begin => writer.u8(0),
            ResourceFinishTransition::Complete { settled_at } => {
                writer.u8(1);
                writer.u64(settled_at);
            }
        }
        writer.bytes(&previous);
        writer.bytes(&current);
        Ok(writer.finish())
    }

    /// Decodes bounded framing and validates the exact transition against the executable.
    ///
    /// Input admission precedes parsing or checkpoint copying. Unknown versions/tags, trailing
    /// bytes, noncanonical forms and unrelated successor changes refuse without publication.
    pub fn decode(
        program: Arc<MachineProgram>,
        bytes: &[u8],
        maximum_bytes: u64,
    ) -> Result<Self, DurableEvidenceError> {
        if u64::try_from(bytes.len()).map_or(true, |length| length > maximum_bytes) {
            return Err(DurableEvidenceError::Encoding);
        }
        let mut reader = Reader::new(bytes);
        if reader.raw(8).map_err(|_| DurableEvidenceError::Encoding)? != MAGIC {
            return Err(DurableEvidenceError::Encoding);
        }
        let record_index = reader.usize().map_err(|_| DurableEvidenceError::Encoding)?;
        let owner = OwnerGeneration::new(reader.u64().map_err(|_| DurableEvidenceError::Encoding)?);
        let transition = match reader.u8().map_err(|_| DurableEvidenceError::Encoding)? {
            0 => ResourceFinishTransition::Begin,
            1 => ResourceFinishTransition::Complete {
                settled_at: reader.u64().map_err(|_| DurableEvidenceError::Encoding)?,
            },
            _ => return Err(DurableEvidenceError::Encoding),
        };
        let previous = reader.bytes().map_err(|_| DurableEvidenceError::Encoding)?;
        let current = reader.bytes().map_err(|_| DurableEvidenceError::Encoding)?;
        if !reader.is_empty() {
            return Err(DurableEvidenceError::Encoding);
        }
        let previous = ConcurrentDurableCheckpointV4::decode_compatible(&program, previous)
            .map_err(DurableEvidenceError::ConcurrentCheckpoint)?;
        let current = ConcurrentDurableCheckpointV4::decode_compatible(&program, current)
            .map_err(DurableEvidenceError::ConcurrentCheckpoint)?;
        let evidence = Self::new(program, previous, current, record_index, owner, transition)?;
        if evidence.encode(maximum_bytes)? != bytes {
            return Err(DurableEvidenceError::Encoding);
        }
        Ok(evidence)
    }
}

impl super::DurableCommitCoordinatorV1<'_> {
    /// Commits exact logical finish evidence against the held complete predecessor graph.
    ///
    /// Unseeded or stale predecessors refuse before storage. Receipt validation advances
    /// baselines; this method does not install coordinator state or invoke physical cleanup.
    pub async fn commit_resource_finish(
        &mut self,
        evidence: ResourceFinishEvidenceV1,
    ) -> Result<super::DurableEvidenceCommitV1, super::DurableCommitError> {
        self.commit_resource_finish_with_submission(evidence, || {})
            .await
    }

    /// Marks the existing journal submission boundary for the private staging owner.
    pub(crate) async fn commit_resource_finish_with_submission(
        &mut self,
        evidence: ResourceFinishEvidenceV1,
        submitted: impl FnOnce(),
    ) -> Result<super::DurableEvidenceCommitV1, super::DurableCommitError> {
        use super::{DurableCommitCutV1, DurableCommitError};
        use gantry_host::journal::{
            BatchLocalEvidenceId, JournalEvidenceReferenceV1, UnfinalizedEvidenceV1,
        };
        if self.graph_checkpoint_baseline.as_deref() != Some(evidence.previous())
            || self.predecessor.is_none()
            || self.graph_cancellation.is_some()
            || self.graph_task_cancellation
            || self.execution_id != evidence.current().execution_id()
            || self.task_id != evidence.current().root_task_id()
        {
            return Err(DurableCommitError::InvalidState);
        }
        let number = self
            .next_local_id
            .checked_add(1)
            .ok_or(DurableCommitError::InvalidState)?;
        let local = BatchLocalEvidenceId::new(format!("cut-{number}"))
            .map_err(|_| DurableCommitError::InvalidState)?;
        let references = self
            .predecessor
            .map(|(id, _)| JournalEvidenceReferenceV1::Existing(id))
            .into_iter()
            .collect::<Vec<_>>();
        let body = UnfinalizedEvidenceV1::new(
            local.clone(),
            RESOURCE_FINISH_EVIDENCE_KIND_V1,
            evidence
                .encode(MAXIMUM_RESOURCE_FINISH_EVIDENCE_BYTES)
                .map_err(DurableCommitError::Evidence)?,
            references,
            Arc::from([]),
        )
        .map_err(|_| DurableCommitError::InvalidState)?;
        let receipt = self
            .commit_body_with_submission(
                DurableCommitCutV1::ResourceFinish,
                number,
                local,
                body,
                submitted,
            )
            .await?;
        self.graph_resource_baseline = Some(evidence.current().resource_records().to_vec());
        self.graph_resource_policy = Some(super::GraphResourcePolicy {
            policy: evidence.current().resource_policy(),
            retained: evidence.current().retained_resource_limit(),
        });
        self.graph_checkpoint_baseline = Some(Box::new(evidence.current().clone()));
        Ok(receipt)
    }
}
