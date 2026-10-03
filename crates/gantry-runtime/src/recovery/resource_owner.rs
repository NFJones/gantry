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
const HANDOFF_MAGIC: &[u8; 8] = b"GNTRWA02";
/// Exact journal kind for same-cleanup-task logical ownership advancement.
pub const RESOURCE_OWNER_EVIDENCE_KIND_V1: &str = "gantry.resource-owner-evidence/v1";
/// Exact journal kind for task-qualified logical cleanup ownership handoff.
pub const RESOURCE_OWNER_EVIDENCE_KIND_V2: &str = "gantry.resource-owner-evidence/v2";
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
    handoff: Option<(
        gantry_core::identity::ProtocolIdentity,
        gantry_core::identity::ProtocolIdentity,
    )>,
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
        Self::new_using(
            program,
            previous,
            current,
            record_index,
            (generations, None),
            charges,
        )
    }

    /// Validates exact cleanup-task handoff against tasks recovered from the predecessor.
    /// Both tasks must be distinct, running and uncancelled; no caller-supplied task snapshot
    /// replaces the graph's own facts. All unrelated graph and historical facts remain fixed.
    pub fn new_task_handoff(
        program: Arc<MachineProgram>,
        previous: ConcurrentDurableCheckpointV4,
        current: ConcurrentDurableCheckpointV4,
        record_index: usize,
        generations: (OwnerGeneration, OwnerGeneration),
        tasks: (
            gantry_core::identity::ProtocolIdentity,
            gantry_core::identity::ProtocolIdentity,
        ),
        charges: &[Charge],
    ) -> Result<Self, DurableEvidenceError> {
        Self::new_using(
            program,
            previous,
            current,
            record_index,
            (generations, Some(tasks)),
            charges,
        )
    }

    /// Shares exact graph validation while keeping the selected transition explicit.
    fn new_using(
        program: Arc<MachineProgram>,
        previous: ConcurrentDurableCheckpointV4,
        current: ConcurrentDurableCheckpointV4,
        record_index: usize,
        ownership: (
            (OwnerGeneration, OwnerGeneration),
            Option<(
                gantry_core::identity::ProtocolIdentity,
                gantry_core::identity::ProtocolIdentity,
            )>,
        ),
        charges: &[Charge],
    ) -> Result<Self, DurableEvidenceError> {
        let (generations, handoff) = ownership;
        if charges.len() > Self::MAXIMUM_CHARGES {
            return Err(DurableEvidenceError::Encoding);
        }
        let recovered = previous
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
        *record = if let Some(tasks) = handoff {
            record
                .stage_task_handoff(recovered.scheduler().state(), tasks, generations, charges)
                .map_err(|_| DurableEvidenceError::InvalidState)?
        } else {
            record
                .stage_owner_advance(generations.0, generations.1, charges)
                .map_err(|_| DurableEvidenceError::InvalidState)?
        };
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
            handoff,
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

    /// Selects the exact journal kind associated with the canonical ownership carrier.
    #[must_use]
    pub const fn journal_kind(&self) -> &'static str {
        if self.handoff.is_some() {
            RESOURCE_OWNER_EVIDENCE_KIND_V2
        } else {
            RESOURCE_OWNER_EVIDENCE_KIND_V1
        }
    }

    /// Returns the source/destination cleanup tasks only for explicit handoff evidence.
    #[must_use]
    pub const fn handoff(
        &self,
    ) -> Option<(
        gantry_core::identity::ProtocolIdentity,
        gantry_core::identity::ProtocolIdentity,
    )> {
        self.handoff
    }

    /// Encodes canonical framing under a caller-supplied complete byte ceiling.
    /// Checks size before copying checkpoint bytes into output. Temporary graph encodings
    /// and validator work are not covered by a total heap or CPU bound.
    pub fn encode(&self, maximum_bytes: u64) -> Result<Vec<u8>, DurableEvidenceError> {
        let previous = self.previous.canonical_bytes();
        let current = self.current.canonical_bytes();
        let members =
            u64::try_from(self.charges.len()).map_err(|_| DurableEvidenceError::Encoding)?;
        let handoff = self
            .handoff
            .map(|(source, destination)| (source.to_string(), destination.to_string()));
        let handoff_bytes = handoff
            .as_ref()
            .map_or(Some(0_u64), |(source, destination)| {
                16_u64
                    .checked_add(u64::try_from(source.len()).ok()?)?
                    .checked_add(u64::try_from(destination.len()).ok()?)
            })
            .ok_or(DurableEvidenceError::Encoding)?;
        let length = members
            .checked_mul(10)
            .and_then(|n| n.checked_add(56))
            .and_then(|n| n.checked_add(handoff_bytes))
            .and_then(|n| n.checked_add(u64::try_from(previous.len()).ok()?))
            .and_then(|n| n.checked_add(u64::try_from(current.len()).ok()?))
            .ok_or(DurableEvidenceError::Encoding)?;
        if length > maximum_bytes {
            return Err(DurableEvidenceError::Encoding);
        }
        let mut writer = Writer::default();
        writer.raw(if handoff.is_some() {
            HANDOFF_MAGIC
        } else {
            MAGIC
        });
        writer.count(self.record_index);
        writer.u64(self.generations.0.value());
        writer.u64(self.generations.1.value());
        if let Some((source, destination)) = handoff {
            writer.bytes(source.as_bytes());
            writer.bytes(destination.as_bytes());
        }
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
        let task_handoff = match reader.raw(8).map_err(|_| DurableEvidenceError::Encoding)? {
            magic if magic == MAGIC => false,
            magic if magic == HANDOFF_MAGIC => true,
            _ => return Err(DurableEvidenceError::Encoding),
        };
        let index = reader.usize().map_err(|_| DurableEvidenceError::Encoding)?;
        let owner = OwnerGeneration::new(reader.u64().map_err(|_| DurableEvidenceError::Encoding)?);
        let successor =
            OwnerGeneration::new(reader.u64().map_err(|_| DurableEvidenceError::Encoding)?);
        let handoff = if task_handoff {
            let mut task = || {
                let text = reader
                    .string()
                    .map_err(|_| DurableEvidenceError::Encoding)?;
                gantry_core::identity::ProtocolIdentity::parse_kind(
                    &text,
                    gantry_core::portable::IdentityKind::Task,
                )
                .map_err(|_| DurableEvidenceError::Encoding)
            };
            Some((task()?, task()?))
        } else {
            None
        };
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
        let evidence = Self::new_using(
            program,
            previous,
            current,
            index,
            ((owner, successor), handoff),
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
            evidence.journal_kind(),
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
