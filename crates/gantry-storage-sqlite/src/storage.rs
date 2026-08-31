//! SQLite connection setup and bounded worker-owned journal service.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use gantry_core::identity::ProtocolIdentity;
use gantry_core::portable::{IdentityKind, ProtectedReferenceClass};
use gantry_host::contracts::HostFuture;
use gantry_host::journal::{
    AcquireJournalOwnerV1, BatchLocalEvidenceId, FullJournalPrefixV1, JournalBatchV1,
    JournalCommitReceiptV1, JournalCommitRequestV1, JournalError, JournalErrorCode,
    JournalEvidenceEnvelopeV1, JournalEvidenceReferenceV1, JournalId, JournalOwnershipToken,
    JournalOwnershipV1, JournalPayloadKey, JournalPrefixV1, JournalReceiptEntryV1, JournalStorage,
    ReadJournalPrefixV1, ReleaseJournalOwnerV1, ResolveJournalPayloadV1, ResolvedJournalPayloadV1,
};
use rusqlite::config::DbConfig;
use rusqlite::limits::Limit;
use rusqlite::{Connection, ErrorCode, OpenFlags, OptionalExtension, TransactionBehavior, params};

use crate::worker::{
    CommandCompletion, SqliteWorker, SqliteWorkerSnapshot, WorkerFailure, WorkerStartError,
};

/// SQLite application identifier reserved for Gantry journal databases.
pub const SQLITE_APPLICATION_ID: i32 = 0x474e_5452;

/// Current private SQLite schema version for the reference adapter.
pub const SQLITE_SCHEMA_VERSION: i32 = 1;

/// Stable adapter-specific failure detail carried inside journal failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SqliteAdapterErrorCode {
    /// The finite worker queue could not admit another command.
    QueueSaturated,
    /// The worker thread or its connection is no longer available.
    WorkerUnavailable,
    /// SQLite reported lock contention.
    Busy,
    /// SQLite reported a locked database object.
    Locked,
    /// Existing bytes or schema are not a valid Gantry journal database.
    MalformedDatabase,
    /// A defensive connection setting could not be established and read back.
    DefensiveConfiguration,
    /// An ordinary SQLite operation failed outside the narrower categories.
    Storage,
}

impl SqliteAdapterErrorCode {
    /// Returns the bounded machine-readable adapter spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::QueueSaturated => "sqlite-queue-saturated",
            Self::WorkerUnavailable => "sqlite-worker-unavailable",
            Self::Busy => "sqlite-busy",
            Self::Locked => "sqlite-locked",
            Self::MalformedDatabase => "sqlite-malformed-database",
            Self::DefensiveConfiguration => "sqlite-defensive-configuration",
            Self::Storage => "sqlite-storage",
        }
    }
}

/// Defensive SQLite settings verified before the adapter is exposed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SqliteDefensiveSettings {
    /// Runtime SQLite engine version supplied by the bundled library.
    pub engine_version: Arc<str>,
    /// Whether runtime extension loading remains enabled for the worker connection.
    pub extension_loading_enabled: bool,
    /// SQLite defensive database configuration is enabled.
    pub defensive: bool,
    /// Trusted schema evaluation is disabled.
    pub trusted_schema: bool,
    /// Memory-mapped database I/O is disabled.
    pub mmap_size: i64,
    /// Effective maximum SQLite value, row, or BLOB length in bytes.
    pub maximum_value_bytes: i32,
    /// Effective maximum SQL statement length in bytes.
    pub maximum_sql_bytes: i32,
    /// Auxiliary SQLite statement worker threads are disabled.
    pub worker_threads: i32,
}

/// Finite worker and database limits selected for one adapter instance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SqliteJournalStoreConfig {
    /// Maximum commands waiting behind the connection-owned worker.
    pub queue_capacity: usize,
    /// Maximum SQLite value, row, or BLOB length in bytes.
    pub maximum_value_bytes: i32,
    /// Maximum fixed SQL statement length in bytes.
    pub maximum_sql_bytes: i32,
}

impl Default for SqliteJournalStoreConfig {
    fn default() -> Self {
        Self {
            queue_capacity: 64,
            maximum_value_bytes: 16 * 1024 * 1024,
            maximum_sql_bytes: 64 * 1024,
        }
    }
}

/// Failure before the worker-backed adapter can be exposed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SqliteJournalStoreOpenError {
    /// Stable adapter-specific failure category.
    pub code: SqliteAdapterErrorCode,
}

/// Bounded SQLite journal adapter whose connection is retained by one worker.
pub struct SqliteJournalStore {
    path: PathBuf,
    settings: SqliteDefensiveSettings,
    worker: SqliteWorker,
}

impl SqliteJournalStore {
    /// Opens or creates one journal database through a bounded worker.
    pub fn open(
        path: impl AsRef<Path>,
        config: SqliteJournalStoreConfig,
    ) -> Result<Self, SqliteJournalStoreOpenError> {
        if config.queue_capacity == 0
            || config.maximum_value_bytes <= 0
            || config.maximum_sql_bytes <= 0
        {
            return Err(SqliteJournalStoreOpenError {
                code: SqliteAdapterErrorCode::DefensiveConfiguration,
            });
        }
        let path = path.as_ref().to_path_buf();
        let worker_path = path.clone();
        let (worker, settings) = SqliteWorker::start(config.queue_capacity, move || {
            initialize_connection(&worker_path, config)
        })
        .map_err(|error| SqliteJournalStoreOpenError {
            code: match error {
                WorkerStartError::Initialize(code) => code,
                WorkerStartError::WorkerUnavailable => SqliteAdapterErrorCode::WorkerUnavailable,
            },
        })?;
        Ok(Self {
            path,
            settings,
            worker,
        })
    }

    /// Returns the selected database path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns settings read back from the connection during startup.
    #[must_use]
    pub const fn defensive_settings(&self) -> &SqliteDefensiveSettings {
        &self.settings
    }

    /// Returns point-in-time worker state counters.
    #[must_use]
    pub fn worker_snapshot(&self) -> SqliteWorkerSnapshot {
        self.worker.counters().snapshot()
    }

    /// Stops the worker after every previously admitted command completes.
    pub fn close(&self) -> Result<(), SqliteAdapterErrorCode> {
        self.worker.close().map_err(worker_adapter_code)
    }

    fn submit<T, F>(&self, run: F) -> HostFuture<'_, Result<T, JournalError>>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> Result<T, JournalError> + Send + 'static,
    {
        let response = match self.worker.submit(move |connection| {
            let result = run(connection);
            if result.is_ok() {
                CommandCompletion::Completed(result)
            } else {
                CommandCompletion::Failed(result)
            }
        }) {
            Ok(response) => response,
            Err(error) => return Box::pin(async move { Err(worker_journal_error(error)) }),
        };
        Box::pin(async move { response.await.map_err(worker_journal_error)? })
    }

    fn submit_mutation<T, F>(&self, run: F) -> HostFuture<'_, Result<T, JournalError>>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> Result<T, JournalError> + Send + 'static,
    {
        let response = match self.worker.submit(move |connection| match run(connection) {
            Ok(value) => CommandCompletion::Committed(Ok(value)),
            Err(error) => CommandCompletion::Failed(Err(error)),
        }) {
            Ok(response) => response,
            Err(error) => return Box::pin(async move { Err(worker_journal_error(error)) }),
        };
        Box::pin(async move { response.await.map_err(worker_journal_error)? })
    }
}

impl JournalStorage for SqliteJournalStore {
    fn acquire_owner<'a>(
        &'a self,
        request: AcquireJournalOwnerV1,
    ) -> HostFuture<'a, Result<JournalOwnershipV1, JournalError>> {
        self.submit_mutation(move |connection| acquire_owner(connection, request))
    }

    fn read_prefix<'a>(
        &'a self,
        request: ReadJournalPrefixV1,
    ) -> HostFuture<'a, Result<JournalPrefixV1, JournalError>> {
        self.submit(move |connection| read_prefix(connection, request))
    }

    fn commit<'a>(
        &'a self,
        request: JournalCommitRequestV1,
    ) -> HostFuture<'a, Result<JournalCommitReceiptV1, JournalError>> {
        self.submit_mutation(move |connection| commit_batch(connection, request))
    }

    fn resolve_payload<'a>(
        &'a self,
        request: ResolveJournalPayloadV1,
    ) -> HostFuture<'a, Result<ResolvedJournalPayloadV1, JournalError>> {
        self.submit(move |connection| resolve_payload(connection, request))
    }

    fn release_owner<'a>(
        &'a self,
        request: ReleaseJournalOwnerV1,
    ) -> HostFuture<'a, Result<(), JournalError>> {
        self.submit_mutation(move |connection| release_owner(connection, request))
    }
}

fn acquire_owner(
    connection: &mut Connection,
    request: AcquireJournalOwnerV1,
) -> Result<JournalOwnershipV1, JournalError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(sqlite_journal_error)?;
    let current = transaction
        .query_row(
            "SELECT generation, owner_token FROM journals WHERE journal_id = ?1",
            [request.journal_id.as_str()],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Option<String>>(1)?)),
        )
        .optional()
        .map_err(sqlite_journal_error)?;
    if current
        .as_ref()
        .is_some_and(|(_, owner_token)| owner_token.is_some())
    {
        return Err(JournalError::new(JournalErrorCode::OwnershipUnavailable));
    }
    let generation = current.map_or(Ok(1_i64), |(generation, _)| {
        generation
            .checked_add(1)
            .ok_or_else(|| JournalError::new(JournalErrorCode::SequenceExhausted))
    })?;
    let token = JournalOwnershipToken::new(format!(
        "sqlite:{}:{generation}",
        request.journal_id.as_str()
    ))
    .map_err(|_| JournalError::new(JournalErrorCode::Internal))?;
    transaction
        .execute(
            "INSERT INTO journals (journal_id, generation, owner_token, committed_through) \
             VALUES (?1, ?2, ?3, 0) \
             ON CONFLICT(journal_id) DO UPDATE SET generation = excluded.generation, owner_token = excluded.owner_token",
            params![request.journal_id.as_str(), generation, token.as_str()],
        )
        .map_err(sqlite_journal_error)?;
    transaction.commit().map_err(sqlite_journal_error)?;
    Ok(JournalOwnershipV1 {
        journal_id: request.journal_id,
        token,
    })
}

fn read_prefix(
    connection: &mut Connection,
    request: ReadJournalPrefixV1,
) -> Result<JournalPrefixV1, JournalError> {
    let committed_through = connection
        .query_row(
            "SELECT committed_through FROM journals WHERE journal_id = ?1",
            [request.journal_id.as_str()],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(sqlite_journal_error)?
        .unwrap_or(0);
    let committed_through = u64::try_from(committed_through)
        .map_err(|_| JournalError::new(JournalErrorCode::Internal))?;
    let committed_through_sql = i64::try_from(committed_through)
        .map_err(|_| JournalError::new(JournalErrorCode::SequenceExhausted))?;
    let mut statement = connection
        .prepare(
            "SELECT sequence, evidence_id, kind, canonical_body \
             FROM evidence WHERE journal_id = ?1 AND sequence <= ?2 ORDER BY sequence",
        )
        .map_err(sqlite_journal_error)?;
    let rows = statement
        .query_map(
            params![request.journal_id.as_str(), committed_through_sql],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            },
        )
        .map_err(sqlite_journal_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sqlite_journal_error)?;
    drop(statement);
    let mut evidence = Vec::with_capacity(rows.len());
    for (sequence, evidence_bytes, kind, canonical_body) in rows {
        let sequence =
            u64::try_from(sequence).map_err(|_| JournalError::new(JournalErrorCode::Internal))?;
        let evidence_id = evidence_identity(&evidence_bytes)?;
        let references = query_evidence_references(connection, &request.journal_id, sequence)?;
        let protected_payloads =
            query_evidence_payloads(connection, &request.journal_id, sequence)?;
        evidence.push(JournalEvidenceEnvelopeV1 {
            journal_id: request.journal_id.clone(),
            sequence,
            evidence_id,
            kind: Arc::from(kind),
            canonical_body: Arc::from(canonical_body),
            references: Arc::from(references),
            protected_payloads: Arc::from(protected_payloads),
        });
    }
    Ok(JournalPrefixV1::Full(FullJournalPrefixV1 {
        journal_id: request.journal_id,
        evidence: Arc::from(evidence),
        committed_through,
    }))
}

fn commit_batch(
    connection: &mut Connection,
    request: JournalCommitRequestV1,
) -> Result<JournalCommitReceiptV1, JournalError> {
    validate_local_reference_graph(&request.batch)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(sqlite_journal_error)?;
    require_owner(&transaction, &request.journal_id, &request.ownership_token)?;
    validate_existing_references(&transaction, &request.journal_id, &request.batch)?;
    validate_and_insert_payloads(&transaction, &request.journal_id, &request.batch)?;

    let committed_through = transaction
        .query_row(
            "SELECT committed_through FROM journals WHERE journal_id = ?1",
            [request.journal_id.as_str()],
            |row| row.get::<_, i64>(0),
        )
        .map_err(sqlite_journal_error)?;
    let count = i64::try_from(request.batch.evidence.len())
        .map_err(|_| JournalError::new(JournalErrorCode::SequenceExhausted))?;
    let first_sequence = committed_through
        .checked_add(1)
        .ok_or_else(|| JournalError::new(JournalErrorCode::SequenceExhausted))?;
    let last_sequence = first_sequence
        .checked_add(count.saturating_sub(1))
        .ok_or_else(|| JournalError::new(JournalErrorCode::SequenceExhausted))?;
    let mut local_ids = BTreeMap::<BatchLocalEvidenceId, ProtocolIdentity>::new();
    for (index, body) in request.batch.evidence.iter().enumerate() {
        let offset = u64::try_from(index)
            .map_err(|_| JournalError::new(JournalErrorCode::IdentityFailure))?;
        let identity = allocate_evidence_identity(&transaction, offset)?;
        if local_ids
            .insert(body.batch_local_id.clone(), identity)
            .is_some()
        {
            return Err(JournalError::new(JournalErrorCode::InvalidBatch));
        }
    }

    let mut receipt = Vec::with_capacity(request.batch.evidence.len());
    for (index, body) in request.batch.evidence.iter().enumerate() {
        let offset = i64::try_from(index)
            .map_err(|_| JournalError::new(JournalErrorCode::SequenceExhausted))?;
        let sequence = first_sequence
            .checked_add(offset)
            .ok_or_else(|| JournalError::new(JournalErrorCode::SequenceExhausted))?;
        let evidence_id = local_ids
            .get(&body.batch_local_id)
            .copied()
            .ok_or_else(|| JournalError::new(JournalErrorCode::Internal))?;
        transaction
            .execute(
                "INSERT INTO evidence (journal_id, sequence, evidence_id, kind, canonical_body) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    request.journal_id.as_str(),
                    sequence,
                    evidence_id.material().as_slice(),
                    body.kind.as_ref(),
                    body.canonical_body.as_ref(),
                ],
            )
            .map_err(sqlite_journal_error)?;
        for (ordinal, reference) in body.references.iter().enumerate() {
            let identity = match reference {
                JournalEvidenceReferenceV1::Existing(identity) => *identity,
                JournalEvidenceReferenceV1::BatchLocal(local) => *local_ids
                    .get(local)
                    .ok_or_else(|| JournalError::new(JournalErrorCode::InvalidBatch))?,
            };
            transaction
                .execute(
                    "INSERT INTO evidence_references (journal_id, sequence, ordinal, evidence_id) \
                     VALUES (?1, ?2, ?3, ?4)",
                    params![
                        request.journal_id.as_str(),
                        sequence,
                        i64::try_from(ordinal)
                            .map_err(|_| JournalError::new(JournalErrorCode::SequenceExhausted))?,
                        identity.material().as_slice(),
                    ],
                )
                .map_err(sqlite_journal_error)?;
        }
        for (ordinal, payload_key) in body.protected_payloads.iter().enumerate() {
            transaction
                .execute(
                    "INSERT INTO evidence_payloads (journal_id, sequence, ordinal, payload_key) \
                     VALUES (?1, ?2, ?3, ?4)",
                    params![
                        request.journal_id.as_str(),
                        sequence,
                        i64::try_from(ordinal)
                            .map_err(|_| JournalError::new(JournalErrorCode::SequenceExhausted))?,
                        payload_key.as_str(),
                    ],
                )
                .map_err(sqlite_journal_error)?;
        }
        receipt.push(JournalReceiptEntryV1 {
            batch_local_id: body.batch_local_id.clone(),
            evidence_id,
            sequence: u64::try_from(sequence)
                .map_err(|_| JournalError::new(JournalErrorCode::SequenceExhausted))?,
        });
    }
    transaction
        .execute(
            "UPDATE journals SET committed_through = ?2 WHERE journal_id = ?1 AND owner_token = ?3",
            params![
                request.journal_id.as_str(),
                last_sequence,
                request.ownership_token.as_str()
            ],
        )
        .map_err(sqlite_journal_error)?;
    transaction.commit().map_err(sqlite_journal_error)?;
    Ok(JournalCommitReceiptV1 {
        first_sequence: u64::try_from(first_sequence)
            .map_err(|_| JournalError::new(JournalErrorCode::SequenceExhausted))?,
        last_sequence: u64::try_from(last_sequence)
            .map_err(|_| JournalError::new(JournalErrorCode::SequenceExhausted))?,
        entries: Arc::from(receipt),
    })
}

fn resolve_payload(
    connection: &mut Connection,
    request: ResolveJournalPayloadV1,
) -> Result<ResolvedJournalPayloadV1, JournalError> {
    connection
        .query_row(
            "SELECT class, bytes FROM payloads WHERE journal_id = ?1 AND payload_key = ?2",
            params![request.journal_id.as_str(), request.key.as_str()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .optional()
        .map_err(sqlite_journal_error)?
        .ok_or_else(|| JournalError::new(JournalErrorCode::MissingPayload))
        .and_then(|(class, bytes)| {
            let class = ProtectedReferenceClass::from_wire_name(&class)
                .ok_or_else(|| JournalError::new(JournalErrorCode::Internal))?;
            Ok(ResolvedJournalPayloadV1 {
                class,
                bytes: Arc::from(bytes),
            })
        })
}

fn release_owner(
    connection: &mut Connection,
    request: ReleaseJournalOwnerV1,
) -> Result<(), JournalError> {
    let changed = connection
        .execute(
            "UPDATE journals SET owner_token = NULL WHERE journal_id = ?1 AND owner_token = ?2",
            params![
                request.journal_id.as_str(),
                request.ownership_token.as_str()
            ],
        )
        .map_err(sqlite_journal_error)?;
    if changed == 1 {
        Ok(())
    } else {
        Err(JournalError::new(JournalErrorCode::StaleOwnership))
    }
}

fn evidence_identity(bytes: &[u8]) -> Result<ProtocolIdentity, JournalError> {
    let material: [u8; 32] = bytes
        .try_into()
        .map_err(|_| JournalError::new(JournalErrorCode::Internal))?;
    Ok(ProtocolIdentity::from_storage_material(material))
}

fn query_evidence_references(
    connection: &Connection,
    journal_id: &JournalId,
    sequence: u64,
) -> Result<Vec<ProtocolIdentity>, JournalError> {
    let sequence = i64::try_from(sequence)
        .map_err(|_| JournalError::new(JournalErrorCode::SequenceExhausted))?;
    let mut statement = connection
        .prepare(
            "SELECT evidence_id FROM evidence_references \
             WHERE journal_id = ?1 AND sequence = ?2 ORDER BY ordinal",
        )
        .map_err(sqlite_journal_error)?;
    statement
        .query_map(params![journal_id.as_str(), sequence], |row| {
            row.get::<_, Vec<u8>>(0)
        })
        .map_err(sqlite_journal_error)?
        .map(|row| {
            row.map_err(sqlite_journal_error)
                .and_then(|bytes| evidence_identity(&bytes))
        })
        .collect()
}

fn query_evidence_payloads(
    connection: &Connection,
    journal_id: &JournalId,
    sequence: u64,
) -> Result<Vec<JournalPayloadKey>, JournalError> {
    let sequence = i64::try_from(sequence)
        .map_err(|_| JournalError::new(JournalErrorCode::SequenceExhausted))?;
    let mut statement = connection
        .prepare(
            "SELECT payload_key FROM evidence_payloads \
             WHERE journal_id = ?1 AND sequence = ?2 ORDER BY ordinal",
        )
        .map_err(sqlite_journal_error)?;
    statement
        .query_map(params![journal_id.as_str(), sequence], |row| {
            row.get::<_, String>(0)
        })
        .map_err(sqlite_journal_error)?
        .map(|row| {
            row.map_err(sqlite_journal_error).and_then(|key| {
                JournalPayloadKey::new(key)
                    .map_err(|_| JournalError::new(JournalErrorCode::Internal))
            })
        })
        .collect()
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

fn require_owner(
    transaction: &rusqlite::Transaction<'_>,
    journal_id: &JournalId,
    token: &JournalOwnershipToken,
) -> Result<(), JournalError> {
    let owner = transaction
        .query_row(
            "SELECT owner_token FROM journals WHERE journal_id = ?1",
            [journal_id.as_str()],
            |row| row.get::<_, Option<String>>(0),
        )
        .optional()
        .map_err(sqlite_journal_error)?
        .flatten();
    if owner.as_deref() == Some(token.as_str()) {
        Ok(())
    } else {
        Err(JournalError::new(JournalErrorCode::StaleOwnership))
    }
}

fn validate_existing_references(
    transaction: &rusqlite::Transaction<'_>,
    journal_id: &JournalId,
    batch: &JournalBatchV1,
) -> Result<(), JournalError> {
    for identity in batch
        .evidence
        .iter()
        .flat_map(|body| body.references.iter())
        .filter_map(|reference| match reference {
            JournalEvidenceReferenceV1::Existing(identity) => Some(*identity),
            JournalEvidenceReferenceV1::BatchLocal(_) => None,
        })
    {
        if identity.kind() != IdentityKind::Evidence {
            return Err(JournalError::new(JournalErrorCode::MissingEvidence));
        }
        let exists = transaction
            .query_row(
                "SELECT 1 FROM evidence WHERE journal_id = ?1 AND evidence_id = ?2",
                params![journal_id.as_str(), identity.material().as_slice()],
                |_| Ok(()),
            )
            .optional()
            .map_err(sqlite_journal_error)?
            .is_some();
        if !exists {
            return Err(JournalError::new(JournalErrorCode::MissingEvidence));
        }
    }
    Ok(())
}

fn validate_and_insert_payloads(
    transaction: &rusqlite::Transaction<'_>,
    journal_id: &JournalId,
    batch: &JournalBatchV1,
) -> Result<(), JournalError> {
    let mut candidates = BTreeMap::new();
    for payload in batch.protected_payloads.iter() {
        let candidate = (payload.class, Arc::clone(&payload.bytes));
        if candidates
            .insert(payload.key.clone(), candidate.clone())
            .is_some_and(|existing| existing != candidate)
        {
            return Err(JournalError::new(JournalErrorCode::PayloadConflict));
        }
        let existing = transaction
            .query_row(
                "SELECT class, bytes FROM payloads WHERE journal_id = ?1 AND payload_key = ?2",
                params![journal_id.as_str(), payload.key.as_str()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()
            .map_err(sqlite_journal_error)?;
        if let Some((class, bytes)) = existing {
            if class != payload.class.wire_name() || bytes.as_slice() != payload.bytes.as_ref() {
                return Err(JournalError::new(JournalErrorCode::PayloadConflict));
            }
        } else {
            transaction
                .execute(
                    "INSERT INTO payloads (journal_id, payload_key, class, bytes) VALUES (?1, ?2, ?3, ?4)",
                    params![
                        journal_id.as_str(),
                        payload.key.as_str(),
                        payload.class.wire_name(),
                        payload.bytes.as_ref(),
                    ],
                )
                .map_err(sqlite_journal_error)?;
        }
    }
    for key in batch
        .evidence
        .iter()
        .flat_map(|body| body.protected_payloads.iter())
    {
        let exists = candidates.contains_key(key)
            || transaction
                .query_row(
                    "SELECT 1 FROM payloads WHERE journal_id = ?1 AND payload_key = ?2",
                    params![journal_id.as_str(), key.as_str()],
                    |_| Ok(()),
                )
                .optional()
                .map_err(sqlite_journal_error)?
                .is_some();
        if !exists {
            return Err(JournalError::new(JournalErrorCode::MissingPayload));
        }
    }
    Ok(())
}

fn allocate_evidence_identity(
    transaction: &rusqlite::Transaction<'_>,
    offset: u64,
) -> Result<ProtocolIdentity, JournalError> {
    let previous = transaction
        .query_row(
            "SELECT COALESCE(MAX(rowid), 0) + 1 FROM evidence",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(sqlite_journal_error)?;
    let previous = u64::try_from(previous)
        .map_err(|_| JournalError::new(JournalErrorCode::IdentityFailure))?;
    let next = previous
        .checked_add(offset)
        .ok_or_else(|| JournalError::new(JournalErrorCode::IdentityFailure))?;
    let mut material = [0_u8; 32];
    material[24..].copy_from_slice(&next.to_be_bytes());
    Ok(ProtocolIdentity::from_storage_material(material))
}

const SCHEMA_SQL: &str = "
CREATE TABLE journals (
    journal_id TEXT PRIMARY KEY NOT NULL,
    generation INTEGER NOT NULL,
    owner_token TEXT,
    committed_through INTEGER NOT NULL
) STRICT;
CREATE TABLE payloads (
    journal_id TEXT NOT NULL,
    payload_key TEXT NOT NULL,
    class TEXT NOT NULL,
    bytes BLOB NOT NULL,
    PRIMARY KEY (journal_id, payload_key)
) STRICT;
CREATE TABLE evidence (
    journal_id TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    evidence_id BLOB NOT NULL UNIQUE,
    kind TEXT NOT NULL,
    canonical_body BLOB NOT NULL,
    PRIMARY KEY (journal_id, sequence)
) STRICT;
CREATE TABLE evidence_references (
    journal_id TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    ordinal INTEGER NOT NULL,
    evidence_id BLOB NOT NULL,
    PRIMARY KEY (journal_id, sequence, ordinal)
) STRICT;
CREATE TABLE evidence_payloads (
    journal_id TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    ordinal INTEGER NOT NULL,
    payload_key TEXT NOT NULL,
    PRIMARY KEY (journal_id, sequence, ordinal)
) STRICT;
";

const REQUIRED_TABLES: [&str; 5] = [
    "evidence",
    "evidence_payloads",
    "evidence_references",
    "journals",
    "payloads",
];

const REQUIRED_SCHEMA: [(&str, &str); 5] = [
    (
        "evidence",
        "CREATE TABLE evidence (\n    journal_id TEXT NOT NULL,\n    sequence INTEGER NOT NULL,\n    evidence_id BLOB NOT NULL UNIQUE,\n    kind TEXT NOT NULL,\n    canonical_body BLOB NOT NULL,\n    PRIMARY KEY (journal_id, sequence)\n) STRICT",
    ),
    (
        "evidence_payloads",
        "CREATE TABLE evidence_payloads (\n    journal_id TEXT NOT NULL,\n    sequence INTEGER NOT NULL,\n    ordinal INTEGER NOT NULL,\n    payload_key TEXT NOT NULL,\n    PRIMARY KEY (journal_id, sequence, ordinal)\n) STRICT",
    ),
    (
        "evidence_references",
        "CREATE TABLE evidence_references (\n    journal_id TEXT NOT NULL,\n    sequence INTEGER NOT NULL,\n    ordinal INTEGER NOT NULL,\n    evidence_id BLOB NOT NULL,\n    PRIMARY KEY (journal_id, sequence, ordinal)\n) STRICT",
    ),
    (
        "journals",
        "CREATE TABLE journals (\n    journal_id TEXT PRIMARY KEY NOT NULL,\n    generation INTEGER NOT NULL,\n    owner_token TEXT,\n    committed_through INTEGER NOT NULL\n) STRICT",
    ),
    (
        "payloads",
        "CREATE TABLE payloads (\n    journal_id TEXT NOT NULL,\n    payload_key TEXT NOT NULL,\n    class TEXT NOT NULL,\n    bytes BLOB NOT NULL,\n    PRIMARY KEY (journal_id, payload_key)\n) STRICT",
    ),
];

fn initialize_connection(
    path: &Path,
    config: SqliteJournalStoreConfig,
) -> Result<(Connection, SqliteDefensiveSettings), SqliteAdapterErrorCode> {
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_CREATE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let mut connection = Connection::open_with_flags(path, flags).map_err(sqlite_adapter_code)?;
    connection
        .busy_timeout(Duration::ZERO)
        .map_err(sqlite_adapter_code)?;
    connection
        .load_extension_disable()
        .map_err(|_| SqliteAdapterErrorCode::DefensiveConfiguration)?;

    connection
        .set_limit(Limit::SQLITE_LIMIT_LENGTH, config.maximum_value_bytes)
        .map_err(sqlite_adapter_code)?;
    connection
        .set_limit(Limit::SQLITE_LIMIT_SQL_LENGTH, config.maximum_sql_bytes)
        .map_err(sqlite_adapter_code)?;
    connection
        .set_limit(Limit::SQLITE_LIMIT_ATTACHED, 0)
        .map_err(sqlite_adapter_code)?;
    connection
        .set_limit(Limit::SQLITE_LIMIT_WORKER_THREADS, 0)
        .map_err(sqlite_adapter_code)?;
    connection
        .set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)
        .map_err(|_| SqliteAdapterErrorCode::DefensiveConfiguration)?;
    connection
        .set_db_config(DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false)
        .map_err(|_| SqliteAdapterErrorCode::DefensiveConfiguration)?;
    connection
        .set_db_config(DbConfig::SQLITE_DBCONFIG_DQS_DDL, false)
        .map_err(|_| SqliteAdapterErrorCode::DefensiveConfiguration)?;
    connection
        .set_db_config(DbConfig::SQLITE_DBCONFIG_DQS_DML, false)
        .map_err(|_| SqliteAdapterErrorCode::DefensiveConfiguration)?;
    connection
        .pragma_update(None, "trusted_schema", false)
        .map_err(|_| SqliteAdapterErrorCode::DefensiveConfiguration)?;
    connection
        .pragma_update(None, "mmap_size", 0_i64)
        .map_err(|_| SqliteAdapterErrorCode::DefensiveConfiguration)?;

    let application_id: i32 = connection
        .pragma_query_value(None, "application_id", |row| row.get(0))
        .map_err(sqlite_adapter_code)?;
    let schema_version: i32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(sqlite_adapter_code)?;
    match (application_id, schema_version) {
        (0, 0) => create_schema(&mut connection)?,
        (SQLITE_APPLICATION_ID, SQLITE_SCHEMA_VERSION) => validate_schema(&connection)?,
        _ => return Err(SqliteAdapterErrorCode::MalformedDatabase),
    }

    let defensive = connection
        .db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE)
        .map_err(|_| SqliteAdapterErrorCode::DefensiveConfiguration)?;
    verify_extension_loading_disabled(&connection)?;
    let extension_loading_enabled = false;
    let trusted_schema = connection
        .db_config(DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA)
        .map_err(|_| SqliteAdapterErrorCode::DefensiveConfiguration)?;
    let mmap_size: i64 = connection
        .pragma_query_value(None, "mmap_size", |row| row.get(0))
        .map_err(|_| SqliteAdapterErrorCode::DefensiveConfiguration)?;
    let maximum_value_bytes = connection
        .limit(Limit::SQLITE_LIMIT_LENGTH)
        .map_err(|_| SqliteAdapterErrorCode::DefensiveConfiguration)?;
    let maximum_sql_bytes = connection
        .limit(Limit::SQLITE_LIMIT_SQL_LENGTH)
        .map_err(|_| SqliteAdapterErrorCode::DefensiveConfiguration)?;
    let worker_threads = connection
        .limit(Limit::SQLITE_LIMIT_WORKER_THREADS)
        .map_err(|_| SqliteAdapterErrorCode::DefensiveConfiguration)?;
    if extension_loading_enabled
        || !defensive
        || trusted_schema
        || mmap_size != 0
        || maximum_value_bytes != config.maximum_value_bytes
        || maximum_sql_bytes != config.maximum_sql_bytes
        || worker_threads != 0
    {
        return Err(SqliteAdapterErrorCode::DefensiveConfiguration);
    }
    Ok((
        connection,
        SqliteDefensiveSettings {
            engine_version: Arc::from(rusqlite::version()),
            extension_loading_enabled,
            defensive,
            trusted_schema,
            mmap_size,
            maximum_value_bytes,
            maximum_sql_bytes,
            worker_threads,
        },
    ))
}

fn verify_extension_loading_disabled(
    connection: &Connection,
) -> Result<(), SqliteAdapterErrorCode> {
    let result = connection.query_row(
        "SELECT load_extension('gantry-extension-loading-must-remain-disabled')",
        [],
        |_| Ok(()),
    );
    match result {
        Err(rusqlite::Error::SqliteFailure(error, message))
            if error.code == ErrorCode::Unknown && message.as_deref() == Some("not authorized") =>
        {
            Ok(())
        }
        _ => Err(SqliteAdapterErrorCode::DefensiveConfiguration),
    }
}

fn create_schema(connection: &mut Connection) -> Result<(), SqliteAdapterErrorCode> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(sqlite_adapter_code)?;
    transaction
        .execute_batch(SCHEMA_SQL)
        .map_err(sqlite_adapter_code)?;
    transaction
        .pragma_update(None, "application_id", SQLITE_APPLICATION_ID)
        .map_err(sqlite_adapter_code)?;
    transaction
        .pragma_update(None, "user_version", SQLITE_SCHEMA_VERSION)
        .map_err(sqlite_adapter_code)?;
    transaction.commit().map_err(sqlite_adapter_code)
}

fn validate_schema(connection: &Connection) -> Result<(), SqliteAdapterErrorCode> {
    let quick_check: String = connection
        .query_row("PRAGMA quick_check(1)", [], |row| row.get(0))
        .map_err(sqlite_adapter_code)?;
    if quick_check != "ok" {
        return Err(SqliteAdapterErrorCode::MalformedDatabase);
    }
    let mut statement = connection
        .prepare("SELECT name, sql FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
        .map_err(sqlite_adapter_code)?;
    let tables = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(sqlite_adapter_code)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sqlite_adapter_code)?;
    if tables
        .iter()
        .map(|(name, _)| name.as_str())
        .eq(REQUIRED_TABLES)
        && tables
            .iter()
            .map(|(name, sql)| (name.as_str(), sql.as_str()))
            .eq(REQUIRED_SCHEMA)
    {
        Ok(())
    } else {
        Err(SqliteAdapterErrorCode::MalformedDatabase)
    }
}

fn worker_adapter_code(error: WorkerFailure) -> SqliteAdapterErrorCode {
    match error {
        WorkerFailure::QueueSaturated => SqliteAdapterErrorCode::QueueSaturated,
        WorkerFailure::WorkerUnavailable => SqliteAdapterErrorCode::WorkerUnavailable,
    }
}

fn worker_journal_error(error: WorkerFailure) -> JournalError {
    adapter_journal_error(worker_adapter_code(error))
}

fn sqlite_adapter_code(error: rusqlite::Error) -> SqliteAdapterErrorCode {
    match error.sqlite_error_code() {
        Some(ErrorCode::DatabaseBusy) => SqliteAdapterErrorCode::Busy,
        Some(ErrorCode::DatabaseLocked) => SqliteAdapterErrorCode::Locked,
        Some(ErrorCode::DatabaseCorrupt | ErrorCode::NotADatabase) => {
            SqliteAdapterErrorCode::MalformedDatabase
        }
        _ => SqliteAdapterErrorCode::Storage,
    }
}

fn sqlite_journal_error(error: rusqlite::Error) -> JournalError {
    adapter_journal_error(sqlite_adapter_code(error))
}

fn adapter_journal_error(code: SqliteAdapterErrorCode) -> JournalError {
    JournalError {
        code: JournalErrorCode::Internal,
        protected_diagnostic: Some(Arc::from(code.wire_name())),
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use rusqlite::Connection;

    use super::{
        SQLITE_APPLICATION_ID, SQLITE_SCHEMA_VERSION, SqliteAdapterErrorCode, SqliteJournalStore,
        SqliteJournalStoreConfig,
    };

    static NEXT_DATABASE: AtomicU64 = AtomicU64::new(1);

    #[test]
    fn incompatible_existing_schema_fails_closed() {
        let database = TemporaryDatabase::new("incompatible-schema");
        let connection = Connection::open(database.path())
            .unwrap_or_else(|error| panic!("fixture database open failed: {error}"));
        connection
            .execute_batch("CREATE TABLE wrong_table (id INTEGER) STRICT")
            .unwrap_or_else(|error| panic!("fixture schema failed: {error}"));
        connection
            .pragma_update(None, "application_id", SQLITE_APPLICATION_ID)
            .unwrap_or_else(|error| panic!("fixture application id failed: {error}"));
        connection
            .pragma_update(None, "user_version", SQLITE_SCHEMA_VERSION)
            .unwrap_or_else(|error| panic!("fixture schema version failed: {error}"));
        drop(connection);

        assert_eq!(
            SqliteJournalStore::open(database.path(), SqliteJournalStoreConfig::default())
                .map(|_| ()),
            Err(super::SqliteJournalStoreOpenError {
                code: SqliteAdapterErrorCode::MalformedDatabase,
            })
        );
    }

    #[test]
    fn existing_schema_with_expected_tables_but_wrong_columns_fails_closed() {
        let database = TemporaryDatabase::new("wrong-columns");
        let connection = Connection::open(database.path())
            .unwrap_or_else(|error| panic!("fixture database open failed: {error}"));
        connection
            .execute_batch(
                "CREATE TABLE journals (wrong_column TEXT) STRICT;\
                 CREATE TABLE payloads (wrong_column TEXT) STRICT;\
                 CREATE TABLE evidence (wrong_column TEXT) STRICT;\
                 CREATE TABLE evidence_references (wrong_column TEXT) STRICT;\
                 CREATE TABLE evidence_payloads (wrong_column TEXT) STRICT;",
            )
            .unwrap_or_else(|error| panic!("fixture schema failed: {error}"));
        connection
            .pragma_update(None, "application_id", SQLITE_APPLICATION_ID)
            .unwrap_or_else(|error| panic!("fixture application id failed: {error}"));
        connection
            .pragma_update(None, "user_version", SQLITE_SCHEMA_VERSION)
            .unwrap_or_else(|error| panic!("fixture schema version failed: {error}"));
        drop(connection);

        assert_eq!(
            SqliteJournalStore::open(database.path(), SqliteJournalStoreConfig::default())
                .map(|_| ()),
            Err(super::SqliteJournalStoreOpenError {
                code: SqliteAdapterErrorCode::MalformedDatabase,
            })
        );
    }

    struct TemporaryDatabase {
        path: PathBuf,
    }

    impl TemporaryDatabase {
        fn new(label: &str) -> Self {
            let number = NEXT_DATABASE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "gantry-sqlite-unit-{label}-{}-{number}.db",
                std::process::id()
            ));
            let _ = std::fs::remove_file(&path);
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TemporaryDatabase {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}
