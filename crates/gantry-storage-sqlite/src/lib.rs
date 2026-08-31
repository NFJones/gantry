//! Bounded, connection-affine SQLite implementation of Gantry journal storage.
//!
//! One adapter-owned worker opens and retains each SQLite connection. Public
//! calls enqueue typed journal commands through a finite nonblocking queue;
//! no connection, statement, row, or transaction crosses the worker boundary.

mod storage;
mod worker;

pub use storage::{
    SQLITE_APPLICATION_ID, SQLITE_SCHEMA_VERSION, SqliteAdapterErrorCode, SqliteDefensiveSettings,
    SqliteJournalStore, SqliteJournalStoreConfig, SqliteJournalStoreOpenError,
};
pub use worker::SqliteWorkerSnapshot;
