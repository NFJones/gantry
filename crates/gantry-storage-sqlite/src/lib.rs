//! Bounded, connection-affine SQLite implementation of Gantry journal storage.
//!
//! One adapter-owned worker opens and retains each SQLite connection. Public
//! calls enqueue typed journal commands through a finite nonblocking queue;
//! no connection, statement, row, or transaction crosses the worker boundary.

mod ownership;
mod storage;
mod worker;

pub use storage::{
    SQLITE_APPLICATION_ID, SQLITE_ENGINE_VERSION, SQLITE_SCHEMA_VERSION, SqliteAdapterErrorCode,
    SqliteDefensiveSettings, SqliteDurabilitySettings, SqliteJournalStore,
    SqliteJournalStoreConfig, SqliteJournalStoreOpenError,
};
pub use worker::SqliteWorkerSnapshot;
