//! Exact resource owner-advance evidence and journal-first admission over complete durable graphs.
//!
//! One same-cleanup-task candidate may change its current generation and explicit Move use.
//! Every other graph and historical fact remains identical. This carrier grants no journal
//! publication, physical transfer, storage authenticity or accepted-work recovery authority.

use std::sync::Arc;

use gantry_ir::{Charge, MachineProgram, OwnerGeneration, QuotaFamily, QuotaOwner};

use crate::ConcurrentDurableCheckpointV4;
use crate::machine::checkpoint_codec::{Reader, Writer};

use super::DurableEvidenceError;

const MAGIC: &[u8; 8] = b"GNTRWA01";
/// Exact journal kind for same-cleanup-task logical ownership advancement.
pub const RESOURCE_OWNER_EVIDENCE_KIND_V1: &str = "gantry.resource-owner-evidence/v1";
/// Independent complete journal-body ceiling, including both checkpoint graphs.
pub const MAXIMUM_RESOURCE_OWNER_EVIDENCE_BYTES: u64 = 4_194_304;

/// One exact owner advancement; construction alone supplies no journal publication authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceOwnerEvidenceV1 {
    previous: ConcurrentDurableCheckpointV4,
    current: ConcurrentDurableCheckpointV4,
    record_index: usize,
    generations: (OwnerGeneration, OwnerGeneration),
    charges: Arc<[Charge]>,
}

impl ResourceOwnerEvidenceV1 {
    /// Independent authored-member bound, counting duplicates and zero amounts.
    pub const MAXIMUM_CHARGES: usize = 128;

    /// Validates both graphs and reproduces exactly one owner-qualified candidate.
    /// Refuses missing records, outstanding obligations, invalid generations, quota failures
    /// and any unrelated graph change. Successful construction performs no publication.
    pub fn new(
        program: Arc<MachineProgram>,
        previous: ConcurrentDurableCheckpointV4,
        current: ConcurrentDurableCheckpointV4,
        record_index: usize,
        generations: (OwnerGeneration, OwnerGeneration),
        charges: &[Charge],
    ) -> Result<Self, DurableEvidenceError> {
        if charges.len() > Self::MAXIMUM_CHARGES {
            return Err(DurableEvidenceError::Encoding);
        }
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
            .stage_owner_advance(generations.0, generations.1, charges)
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
            generations,
            charges: charges.into(),
        })
    }

    /// Returns the validated complete predecessor, not proof of journal authenticity.
    #[must_use]
    pub const fn previous(&self) -> &ConcurrentDurableCheckpointV4 {
        &self.previous
    }

    /// Returns the exact private logical successor; it carries no publication authority.
    #[must_use]
    pub const fn current(&self) -> &ConcurrentDurableCheckpointV4 {
        &self.current
    }

    /// Returns the unchanged cleanup task selected by the validated resource record.
    #[must_use]
    pub fn task_id(&self) -> gantry_core::identity::ProtocolIdentity {
        self.current.resource_records()[self.record_index].task_owner()
    }

    /// Returns the authored vector without reordering or deduplicating members.
    #[must_use]
    pub fn charges(&self) -> &[Charge] {
        &self.charges
    }

    /// Encodes canonical framing under a caller-supplied complete byte ceiling.
    /// Checks size before copying checkpoint bytes into output. Temporary graph encodings
    /// and validator work are not covered by a total heap or CPU bound.
    pub fn encode(&self, maximum_bytes: u64) -> Result<Vec<u8>, DurableEvidenceError> {
        let previous = self.previous.canonical_bytes();
        let current = self.current.canonical_bytes();
        let members =
            u64::try_from(self.charges.len()).map_err(|_| DurableEvidenceError::Encoding)?;
        let length = members
            .checked_mul(10)
            .and_then(|n| n.checked_add(56))
            .and_then(|n| n.checked_add(u64::try_from(previous.len()).ok()?))
            .and_then(|n| n.checked_add(u64::try_from(current.len()).ok()?))
            .ok_or(DurableEvidenceError::Encoding)?;
        if length > maximum_bytes {
            return Err(DurableEvidenceError::Encoding);
        }
        let mut writer = Writer::default();
        writer.raw(MAGIC);
        writer.count(self.record_index);
        writer.u64(self.generations.0.value());
        writer.u64(self.generations.1.value());
        writer.count(self.charges.len());
        for charge in self.charges.iter() {
            writer.u8(match charge.owner {
                QuotaOwner::DurableRecord => 0,
                QuotaOwner::Owner => 1,
                QuotaOwner::Resource => 2,
            });
            writer.u8(match charge.family {
                QuotaFamily::Bytes => 0,
                QuotaFamily::Handles => 1,
                QuotaFamily::Operations => 2,
            });
            writer.u64(charge.amount);
        }
        writer.bytes(&previous);
        writer.bytes(&current);
        Ok(writer.finish())
    }

    /// Admits bounded bytes before parsing and revalidates exact graph correspondence.
    /// Unknown tags, hostile counts, trailing bytes and noncanonical framing refuse.
    pub fn decode(
        program: Arc<MachineProgram>,
        bytes: &[u8],
        maximum_bytes: u64,
    ) -> Result<Self, DurableEvidenceError> {
        if u64::try_from(bytes.len()).map_or(true, |n| n > maximum_bytes) {
            return Err(DurableEvidenceError::Encoding);
        }
        let mut reader = Reader::new(bytes);
        if reader.raw(8).map_err(|_| DurableEvidenceError::Encoding)? != MAGIC {
            return Err(DurableEvidenceError::Encoding);
        }
        let index = reader.usize().map_err(|_| DurableEvidenceError::Encoding)?;
        let owner = OwnerGeneration::new(reader.u64().map_err(|_| DurableEvidenceError::Encoding)?);
        let successor =
            OwnerGeneration::new(reader.u64().map_err(|_| DurableEvidenceError::Encoding)?);
        let count = reader.count().map_err(|_| DurableEvidenceError::Encoding)?;
        if count > Self::MAXIMUM_CHARGES {
            return Err(DurableEvidenceError::Encoding);
        }
        let mut charges = Vec::new();
        for _ in 0..count {
            let owner = match reader.u8().map_err(|_| DurableEvidenceError::Encoding)? {
                0 => QuotaOwner::DurableRecord,
                1 => QuotaOwner::Owner,
                2 => QuotaOwner::Resource,
                _ => return Err(DurableEvidenceError::Encoding),
            };
            let family = match reader.u8().map_err(|_| DurableEvidenceError::Encoding)? {
                0 => QuotaFamily::Bytes,
                1 => QuotaFamily::Handles,
                2 => QuotaFamily::Operations,
                _ => return Err(DurableEvidenceError::Encoding),
            };
            let amount = reader.u64().map_err(|_| DurableEvidenceError::Encoding)?;
            charges.push(Charge {
                owner,
                family,
                amount,
            });
        }
        let previous = reader.bytes().map_err(|_| DurableEvidenceError::Encoding)?;
        let current = reader.bytes().map_err(|_| DurableEvidenceError::Encoding)?;
        if !reader.is_empty() {
            return Err(DurableEvidenceError::Encoding);
        }
        let previous = ConcurrentDurableCheckpointV4::decode_compatible(&program, previous)
            .map_err(DurableEvidenceError::ConcurrentCheckpoint)?;
        let current = ConcurrentDurableCheckpointV4::decode_compatible(&program, current)
            .map_err(DurableEvidenceError::ConcurrentCheckpoint)?;
        let evidence = Self::new(
            program,
            previous,
            current,
            index,
            (owner, successor),
            &charges,
        )?;
        if evidence.encode(maximum_bytes)? != bytes {
            return Err(DurableEvidenceError::Encoding);
        }
        Ok(evidence)
    }
}

impl super::DurableCommitCoordinatorV1<'_> {
    /// Journals exact owner advancement against the held authoritative complete graph.
    /// Unknown or stale predecessors refuse before storage; only validated receipts advance
    /// baselines. This writer installs no live registry and performs no physical transfer.
    pub async fn commit_resource_owner_advance(
        &mut self,
        evidence: ResourceOwnerEvidenceV1,
    ) -> Result<super::DurableEvidenceCommitV1, super::DurableCommitError> {
        self.commit_resource_owner_advance_with_submission(evidence, || {})
            .await
    }

    /// Exposes the submission coordinate to the journal-first private publication owner.
    pub(crate) async fn commit_resource_owner_advance_with_submission(
        &mut self,
        evidence: ResourceOwnerEvidenceV1,
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
            RESOURCE_OWNER_EVIDENCE_KIND_V1,
            evidence
                .encode(MAXIMUM_RESOURCE_OWNER_EVIDENCE_BYTES)
                .map_err(DurableCommitError::Evidence)?,
            references,
            Arc::from([]),
        )
        .map_err(|_| DurableCommitError::InvalidState)?;
        let receipt = self
            .commit_body_with_submission(
                DurableCommitCutV1::ResourceOwnerAdvance,
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
