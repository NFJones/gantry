//! Public adapter-contract coverage for the bounded SQLite journal worker.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::pin;
use std::process::{Child, Command};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use gantry::host::journal::{
    AcquireJournalOwnerV1, BatchLocalEvidenceId, JournalBatchV1, JournalCommitRequestV1,
    JournalErrorCode, JournalEvidenceReferenceV1, JournalId, JournalOwnerOperationV1,
    JournalStorage, ReadJournalPrefixV1, ReleaseJournalOwnerV1, UnfinalizedEvidenceV1,
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
    let durability = store.durability_settings();
    assert_eq!(durability.vfs.as_ref(), "unix");
    assert_eq!(durability.journal_mode.as_ref(), "delete");
    assert_eq!(durability.synchronous, 3);
    assert_eq!(durability.fullfsync, cfg!(target_os = "macos"));
    assert!(!durability.filesystem.is_empty());
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

#[test]
fn public_sqlite_owner_lease_fences_same_process_and_preserves_sidecar_identity() {
    let database = TemporaryDatabase::new("same-process-owner");
    let first = SqliteJournalStore::open(database.path(), SqliteJournalStoreConfig::default())
        .unwrap_or_else(|error| panic!("first SQLite adapter open failed: {error:?}"));
    let second = SqliteJournalStore::open(database.path(), SqliteJournalStoreConfig::default())
        .unwrap_or_else(|error| panic!("second SQLite adapter open failed: {error:?}"));
    let journal = journal_id("same-process-journal");
    let first_owner = block_on(first.acquire_owner(AcquireJournalOwnerV1 {
        journal_id: journal.clone(),
        operation: JournalOwnerOperationV1::Start,
    }))
    .unwrap_or_else(|error| panic!("first owner acquisition failed: {error:?}"));
    let lock_identity = file_identity(first.owner_lock_path());

    let competing = block_on(second.acquire_owner(AcquireJournalOwnerV1 {
        journal_id: journal.clone(),
        operation: JournalOwnerOperationV1::Resume,
    }));
    assert_eq!(
        competing.map(|_| ()).map_err(|error| error.code),
        Err(JournalErrorCode::OwnershipUnavailable)
    );

    block_on(first.release_owner(ReleaseJournalOwnerV1 {
        journal_id: journal.clone(),
        ownership_token: first_owner.token.clone(),
    }))
    .unwrap_or_else(|error| panic!("first owner release failed: {error:?}"));
    let stale = block_on(
        first.commit(JournalCommitRequestV1 {
            journal_id: journal.clone(),
            ownership_token: first_owner.token.clone(),
            batch: JournalBatchV1::new(vec![body("stale", &[])], Vec::new())
                .unwrap_or_else(|error| panic!("stale batch failed: {error:?}")),
        }),
    );
    assert_eq!(
        stale.map(|_| ()).map_err(|error| error.code),
        Err(JournalErrorCode::StaleOwnership)
    );

    let second_owner = block_on(second.acquire_owner(AcquireJournalOwnerV1 {
        journal_id: journal.clone(),
        operation: JournalOwnerOperationV1::Resume,
    }))
    .unwrap_or_else(|error| panic!("second owner acquisition failed: {error:?}"));
    assert_ne!(second_owner.token, first_owner.token);
    assert_eq!(file_identity(second.owner_lock_path()), lock_identity);
    block_on(second.release_owner(ReleaseJournalOwnerV1 {
        journal_id: journal,
        ownership_token: second_owner.token,
    }))
    .unwrap_or_else(|error| panic!("second owner release failed: {error:?}"));
}

#[test]
fn public_sqlite_cross_process_owner_exclusion_and_crash_reclamation() {
    if let Some(path) = std::env::var_os("GANTRY_SQLITE_OWNER_CHILD") {
        hold_owner_until_killed(PathBuf::from(path));
        return;
    }

    let database = TemporaryDatabase::new("cross-process-owner");
    let bootstrap = SqliteJournalStore::open(database.path(), SqliteJournalStoreConfig::default())
        .unwrap_or_else(|error| panic!("bootstrap SQLite adapter open failed: {error:?}"));
    bootstrap
        .close()
        .unwrap_or_else(|error| panic!("bootstrap SQLite adapter close failed: {error:?}"));
    let ready_path = database.with_suffix(".owner-ready");
    let mut child = spawn_owner_child(database.path());
    wait_for_child_ready(&mut child, &ready_path);

    let contender = SqliteJournalStore::open(database.path(), SqliteJournalStoreConfig::default())
        .unwrap_or_else(|error| panic!("contender SQLite adapter open failed: {error:?}"));
    let journal = journal_id("cross-process-journal");
    let competing = block_on(contender.acquire_owner(AcquireJournalOwnerV1 {
        journal_id: journal.clone(),
        operation: JournalOwnerOperationV1::Resume,
    }));
    assert_eq!(
        competing.map(|_| ()).map_err(|error| error.code),
        Err(JournalErrorCode::OwnershipUnavailable)
    );

    child
        .kill()
        .unwrap_or_else(|error| panic!("owner child kill failed: {error}"));
    child
        .wait()
        .unwrap_or_else(|error| panic!("owner child wait failed: {error}"));
    let recovered = block_on(contender.acquire_owner(AcquireJournalOwnerV1 {
        journal_id: journal.clone(),
        operation: JournalOwnerOperationV1::Resume,
    }))
    .unwrap_or_else(|error| panic!("owner acquisition after crash failed: {error:?}"));
    let prefix = block_on(contender.read_prefix(ReadJournalPrefixV1 {
        journal_id: journal.clone(),
    }))
    .unwrap_or_else(|error| panic!("prefix read after owner crash failed: {error:?}"));
    let gantry::host::journal::JournalPrefixV1::Full(prefix) = prefix else {
        panic!("SQLite recovery returned an unexpected snapshot prefix");
    };
    assert_eq!(prefix.committed_through, 1);
    assert_eq!(prefix.evidence.len(), 1);
    assert_eq!(
        prefix.evidence[0].canonical_body.as_ref(),
        b"{\"id\":\"committed-before-crash\"}"
    );
    block_on(contender.release_owner(ReleaseJournalOwnerV1 {
        journal_id: journal,
        ownership_token: recovered.token,
    }))
    .unwrap_or_else(|error| panic!("recovered owner release failed: {error:?}"));
}

#[test]
fn public_sqlite_strict_power_loss_policy_matches_environment_qualification() {
    let database = TemporaryDatabase::new("strict-environment");
    let ordinary = SqliteJournalStore::open(database.path(), SqliteJournalStoreConfig::default())
        .unwrap_or_else(|error| panic!("ordinary SQLite adapter open failed: {error:?}"));
    let qualified = ordinary.durability_settings().power_loss_qualified;
    ordinary
        .close()
        .unwrap_or_else(|error| panic!("ordinary SQLite adapter close failed: {error:?}"));
    let strict = SqliteJournalStore::open(
        database.path(),
        SqliteJournalStoreConfig {
            require_power_loss_qualified: true,
            ..SqliteJournalStoreConfig::default()
        },
    );
    if qualified {
        strict.unwrap_or_else(|error| panic!("qualified environment was rejected: {error:?}"));
    } else {
        assert_eq!(
            strict.map(|_| ()),
            Err(gantry_storage_sqlite::SqliteJournalStoreOpenError {
                code: SqliteAdapterErrorCode::UnsupportedEnvironment,
            })
        );
    }
}

#[cfg(gantry_sqlite_fault_helper)]
#[test]
fn bundled_sqlite_fault_matrix_preserves_atomic_sequence_and_payload_prefixes() {
    for (case, expected_commit, expected_state) in [
        ("short-write", "success", Some("new")),
        ("torn-write", "crash", Some("old")),
        ("database-sync-failure", "io-error", None),
        ("directory-sync-failure", "io-error", None),
    ] {
        let database = TemporaryDatabase::new(case);
        let output = Command::new(env!("GANTRY_SQLITE_FAULT_HELPER"))
            .arg(case)
            .arg(database.path())
            .output()
            .unwrap_or_else(|error| panic!("fault helper failed to start for {case}: {error}"));
        assert!(
            output.status.success(),
            "fault helper failed for {case}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout)
            .unwrap_or_else(|error| panic!("fault helper output was not UTF-8: {error}"));
        let fields = stdout
            .split_whitespace()
            .filter_map(|field| field.split_once('='))
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(fields.get("case"), Some(&case));
        assert_eq!(fields.get("commit"), Some(&expected_commit));
        assert_eq!(fields.get("injections"), Some(&"1"));
        assert_eq!(fields.get("sqlite"), Some(&"3.53.2"));
        assert!(matches!(fields.get("state"), Some(&"old" | &"new")));
        if let Some(expected_state) = expected_state {
            assert_eq!(fields.get("state"), Some(&expected_state));
        }
    }
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

    fn with_suffix(&self, suffix: &str) -> PathBuf {
        path_with_suffix(&self.path, suffix)
    }
}

impl Drop for TemporaryDatabase {
    fn drop(&mut self) {
        remove_database_files(&self.path);
    }
}

fn remove_database_files(path: &Path) {
    let _ = std::fs::remove_file(path);
    for suffix in [
        "-journal",
        "-shm",
        "-wal",
        ".gantry-owner.lock",
        ".owner-ready",
    ] {
        let _ = std::fs::remove_file(path_with_suffix(path, suffix));
    }
}

fn path_with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut sidecar = path.as_os_str().to_os_string();
    sidecar.push(suffix);
    PathBuf::from(sidecar)
}

#[cfg(unix)]
fn file_identity(path: &Path) -> (u64, u64) {
    use std::os::unix::fs::MetadataExt;

    let metadata = std::fs::metadata(path)
        .unwrap_or_else(|error| panic!("sidecar metadata failed for {}: {error}", path.display()));
    (metadata.dev(), metadata.ino())
}

#[cfg(not(unix))]
fn file_identity(path: &Path) -> PathBuf {
    std::fs::canonicalize(path)
        .unwrap_or_else(|error| panic!("sidecar canonicalization failed: {error}"))
}

fn spawn_owner_child(database_path: &Path) -> Child {
    let executable = std::env::current_exe()
        .unwrap_or_else(|error| panic!("current test executable lookup failed: {error}"));
    Command::new(executable)
        .arg("--exact")
        .arg("public_sqlite_cross_process_owner_exclusion_and_crash_reclamation")
        .arg("--nocapture")
        .env("GANTRY_SQLITE_OWNER_CHILD", database_path)
        .spawn()
        .unwrap_or_else(|error| panic!("owner child spawn failed: {error}"))
}

fn hold_owner_until_killed(database_path: PathBuf) {
    let store = SqliteJournalStore::open(&database_path, SqliteJournalStoreConfig::default())
        .unwrap_or_else(|error| panic!("owner child adapter open failed: {error:?}"));
    let journal = journal_id("cross-process-journal");
    let owner = block_on(store.acquire_owner(AcquireJournalOwnerV1 {
        journal_id: journal.clone(),
        operation: JournalOwnerOperationV1::Resume,
    }))
    .unwrap_or_else(|error| panic!("owner child acquisition failed: {error:?}"));
    block_on(
        store.commit(JournalCommitRequestV1 {
            journal_id: journal,
            ownership_token: owner.token,
            batch: JournalBatchV1::new(vec![body("committed-before-crash", &[])], Vec::new())
                .unwrap_or_else(|error| panic!("owner child batch failed: {error:?}")),
        }),
    )
    .unwrap_or_else(|error| panic!("owner child commit failed: {error:?}"));
    std::fs::write(path_with_suffix(&database_path, ".owner-ready"), b"ready")
        .unwrap_or_else(|error| panic!("owner child ready marker failed: {error}"));
    loop {
        std::thread::sleep(Duration::from_secs(60));
    }
}

fn wait_for_child_ready(child: &mut Child, ready_path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if ready_path.is_file() {
            return;
        }
        if let Some(status) = child
            .try_wait()
            .unwrap_or_else(|error| panic!("owner child status failed: {error}"))
        {
            panic!("owner child exited before acquiring ownership: {status}");
        }
        assert!(Instant::now() < deadline, "owner child readiness timed out");
        std::thread::sleep(Duration::from_millis(10));
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
