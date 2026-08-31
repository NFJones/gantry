//! Public adapter-contract coverage for the bounded SQLite journal worker.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll, Waker};

use gantry::host::journal::{
    AcquireJournalOwnerV1, BatchLocalEvidenceId, JournalBatchV1, JournalCommitRequestV1,
    JournalErrorCode, JournalEvidenceReferenceV1, JournalId, JournalOwnerOperationV1,
    JournalStorage, ReadJournalPrefixV1, UnfinalizedEvidenceV1,
};
use gantry_conformance::journal::run_journal_storage_contract;
use gantry_storage_sqlite::{SqliteAdapterErrorCode, SqliteJournalStore, SqliteJournalStoreConfig};
use rusqlite::TransactionBehavior;

static NEXT_DATABASE: AtomicU64 = AtomicU64::new(1);

#[test]
fn public_sqlite_worker_passes_common_contract_with_defensive_settings() {
    let database = TemporaryDatabase::new("common-contract");
    let store = SqliteJournalStore::open(database.path(), SqliteJournalStoreConfig::default())
        .unwrap_or_else(|error| panic!("SQLite adapter open failed: {error:?}"));

    let settings = store.defensive_settings();
    assert_eq!(settings.engine_version.as_ref(), "3.53.2");
    assert!(!settings.extension_loading_enabled);
    assert!(settings.defensive);
    assert!(!settings.trusted_schema);
    assert_eq!(settings.mmap_size, 0);
    assert_eq!(settings.maximum_value_bytes, 16 * 1024 * 1024);
    assert_eq!(settings.maximum_sql_bytes, 64 * 1024);
    assert_eq!(settings.worker_threads, 0);
    assert_eq!(block_on(run_journal_storage_contract(&store)), Ok(()));

    let snapshot = store.worker_snapshot();
    assert!(snapshot.queued > 0);
    assert_eq!(snapshot.queued, snapshot.executing);
    assert!(snapshot.committed > 0);
    store
        .close()
        .unwrap_or_else(|error| panic!("SQLite worker close failed: {error:?}"));
}

#[test]
fn public_sqlite_adapter_rejects_malformed_bytes_and_post_close_calls() {
    let malformed = TemporaryDatabase::new("malformed-bytes");
    std::fs::write(malformed.path(), b"not a sqlite database")
        .unwrap_or_else(|error| panic!("malformed fixture write failed: {error}"));
    assert_eq!(
        SqliteJournalStore::open(malformed.path(), SqliteJournalStoreConfig::default()).map(|_| ()),
        Err(gantry_storage_sqlite::SqliteJournalStoreOpenError {
            code: SqliteAdapterErrorCode::MalformedDatabase,
        })
    );

    let closed = TemporaryDatabase::new("closed-worker");
    let store = SqliteJournalStore::open(closed.path(), SqliteJournalStoreConfig::default())
        .unwrap_or_else(|error| panic!("SQLite adapter open failed: {error:?}"));
    store
        .close()
        .unwrap_or_else(|error| panic!("SQLite worker close failed: {error:?}"));
    let error = match block_on(
        store.read_prefix(ReadJournalPrefixV1 {
            journal_id: JournalId::new("closed-journal")
                .unwrap_or_else(|error| panic!("journal id failed: {error:?}")),
        }),
    ) {
        Err(error) => error,
        Ok(_) => panic!("closed worker accepted a read"),
    };
    assert_eq!(
        error.protected_diagnostic.as_deref(),
        Some(SqliteAdapterErrorCode::WorkerUnavailable.wire_name())
    );
}

#[test]
fn public_sqlite_adapter_maps_lock_contention_without_blocking_the_caller() {
    let database = TemporaryDatabase::new("lock-contention");
    let store = SqliteJournalStore::open(database.path(), SqliteJournalStoreConfig::default())
        .unwrap_or_else(|error| panic!("SQLite adapter open failed: {error:?}"));
    let mut blocker = rusqlite::Connection::open(database.path())
        .unwrap_or_else(|error| panic!("blocking connection open failed: {error}"));
    let transaction = blocker
        .transaction_with_behavior(TransactionBehavior::Exclusive)
        .unwrap_or_else(|error| panic!("blocking transaction failed: {error}"));

    let error = match block_on(store.acquire_owner(AcquireJournalOwnerV1 {
        journal_id: journal_id("busy-journal"),
        operation: JournalOwnerOperationV1::Start,
    })) {
        Err(error) => error,
        Ok(_) => panic!("exclusive SQLite transaction did not block owner acquisition"),
    };
    assert_eq!(error.code, JournalErrorCode::Internal);
    assert_eq!(
        error.protected_diagnostic.as_deref(),
        Some(SqliteAdapterErrorCode::Busy.wire_name())
    );

    transaction
        .rollback()
        .unwrap_or_else(|error| panic!("blocking rollback failed: {error}"));
    store
        .close()
        .unwrap_or_else(|error| panic!("SQLite worker close failed: {error:?}"));
}

#[test]
fn public_sqlite_adapter_rejects_cross_journal_evidence_references() {
    let database = TemporaryDatabase::new("cross-journal-reference");
    let store = SqliteJournalStore::open(database.path(), SqliteJournalStoreConfig::default())
        .unwrap_or_else(|error| panic!("SQLite adapter open failed: {error:?}"));
    let first_journal = journal_id("first-journal");
    let first_owner = block_on(store.acquire_owner(AcquireJournalOwnerV1 {
        journal_id: first_journal.clone(),
        operation: JournalOwnerOperationV1::Start,
    }))
    .unwrap_or_else(|error| panic!("first owner acquisition failed: {error:?}"));
    let first_receipt = block_on(
        store.commit(JournalCommitRequestV1 {
            journal_id: first_journal,
            ownership_token: first_owner.token,
            batch: JournalBatchV1::new(vec![body("first", &[])], Vec::new())
                .unwrap_or_else(|error| panic!("first batch failed: {error:?}")),
        }),
    )
    .unwrap_or_else(|error| panic!("first commit failed: {error:?}"));

    let second_journal = journal_id("second-journal");
    let second_owner = block_on(store.acquire_owner(AcquireJournalOwnerV1 {
        journal_id: second_journal.clone(),
        operation: JournalOwnerOperationV1::Start,
    }))
    .unwrap_or_else(|error| panic!("second owner acquisition failed: {error:?}"));
    let cross_reference =
        JournalEvidenceReferenceV1::Existing(first_receipt.entries[0].evidence_id);
    let error = match block_on(
        store.commit(JournalCommitRequestV1 {
            journal_id: second_journal,
            ownership_token: second_owner.token,
            batch: JournalBatchV1::new(vec![body("cross", &[cross_reference])], Vec::new())
                .unwrap_or_else(|error| panic!("cross batch failed: {error:?}")),
        }),
    ) {
        Err(error) => error,
        Ok(_) => panic!("cross-journal evidence reference was accepted"),
    };
    assert_eq!(error.code, JournalErrorCode::MissingEvidence);

    store
        .close()
        .unwrap_or_else(|error| panic!("SQLite worker close failed: {error:?}"));
}

fn journal_id(value: &str) -> JournalId {
    JournalId::new(value).unwrap_or_else(|error| panic!("journal id failed: {error:?}"))
}

fn body(id: &str, references: &[JournalEvidenceReferenceV1]) -> UnfinalizedEvidenceV1 {
    UnfinalizedEvidenceV1::new(
        BatchLocalEvidenceId::new(id)
            .unwrap_or_else(|error| panic!("local evidence id failed: {error:?}")),
        "sqlite-test-evidence/v1",
        Arc::<[u8]>::from(format!("{{\"id\":\"{id}\"}}").into_bytes()),
        Arc::from(references),
        Arc::from([]),
    )
    .unwrap_or_else(|error| panic!("evidence body failed: {error:?}"))
}

struct TemporaryDatabase {
    path: PathBuf,
}

impl TemporaryDatabase {
    fn new(label: &str) -> Self {
        let number = NEXT_DATABASE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "gantry-sqlite-{label}-{}-{number}.db",
            std::process::id()
        ));
        remove_database_files(&path);
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TemporaryDatabase {
    fn drop(&mut self) {
        remove_database_files(&self.path);
    }
}

fn remove_database_files(path: &Path) {
    let _ = std::fs::remove_file(path);
    for suffix in ["-journal", "-shm", "-wal"] {
        let mut sidecar = path.as_os_str().to_os_string();
        sidecar.push(suffix);
        let _ = std::fs::remove_file(sidecar);
    }
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
