//! Process-local and cross-process liveness leases for SQLite ownership.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock};

use gantry_host::journal::{JournalId, JournalOwnershipToken};
use rustix::fd::OwnedFd;
use rustix::fs::{self, FileType, FlockOperation, Mode, OFlags};
use rustix::io::Errno;

/// Failure while identifying, qualifying, or locking one database.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OwnerLeaseError {
    /// Another store in this process or another process owns the database.
    Unavailable,
    /// The filesystem cannot support the reference durable claim.
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    UnsupportedEnvironment,
    /// Database identity or sidecar operations failed.
    Io,
}

/// Filesystem qualification recorded for the opened database.
pub(crate) struct FilesystemQualification {
    pub(crate) name: &'static str,
    pub(crate) power_loss_qualified: bool,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct DatabaseIdentity {
    device: u64,
    inode: u64,
}

struct ProcessLease {
    identity: DatabaseIdentity,
    descriptor: OwnedFd,
}

#[derive(Default)]
struct LeaseState {
    process_lease: Option<ProcessLease>,
    active_tokens: BTreeSet<(String, String)>,
}

/// One store's database-wide liveness lease and per-journal active tokens.
pub(crate) struct OwnerLeaseManager {
    identity: DatabaseIdentity,
    lock_path: PathBuf,
    state: Mutex<LeaseState>,
}

impl OwnerLeaseManager {
    pub(crate) fn new(
        database_path: &Path,
    ) -> Result<(Self, FilesystemQualification), OwnerLeaseError> {
        let canonical_path =
            std::fs::canonicalize(database_path).map_err(|_| OwnerLeaseError::Io)?;
        let metadata = std::fs::metadata(&canonical_path).map_err(|_| OwnerLeaseError::Io)?;
        let identity = database_identity(&metadata)?;
        let qualification = qualify_filesystem(&canonical_path)?;
        let mut lock_path = canonical_path.into_os_string();
        lock_path.push(".gantry-owner.lock");
        Ok((
            Self {
                identity,
                lock_path: PathBuf::from(lock_path),
                state: Mutex::new(LeaseState::default()),
            },
            qualification,
        ))
    }

    pub(crate) fn lock_path(&self) -> &Path {
        &self.lock_path
    }

    pub(crate) fn ensure_locked(&self) -> Result<(), OwnerLeaseError> {
        let mut state = lock(&self.state);
        if state.process_lease.is_none() {
            state.process_lease = Some(ProcessLease::acquire(self.identity, &self.lock_path)?);
        }
        Ok(())
    }

    pub(crate) fn is_active(&self, journal_id: &JournalId, token: &JournalOwnershipToken) -> bool {
        lock(&self.state)
            .active_tokens
            .contains(&(journal_id.as_str().to_owned(), token.as_str().to_owned()))
    }

    pub(crate) fn has_owner(&self, journal_id: &JournalId) -> bool {
        lock(&self.state)
            .active_tokens
            .iter()
            .any(|(active_journal, _)| active_journal == journal_id.as_str())
    }

    pub(crate) fn register_owner(&self, journal_id: &JournalId, token: &JournalOwnershipToken) {
        lock(&self.state)
            .active_tokens
            .insert((journal_id.as_str().to_owned(), token.as_str().to_owned()));
    }

    pub(crate) fn finish_release(&self, journal_id: &JournalId, token: &JournalOwnershipToken) {
        let mut state = lock(&self.state);
        state
            .active_tokens
            .remove(&(journal_id.as_str().to_owned(), token.as_str().to_owned()));
        if state.active_tokens.is_empty() {
            state.process_lease.take();
        }
    }

    pub(crate) fn release_if_unused(&self) {
        let mut state = lock(&self.state);
        if state.active_tokens.is_empty() {
            state.process_lease.take();
        }
    }
}

impl ProcessLease {
    fn acquire(identity: DatabaseIdentity, lock_path: &Path) -> Result<Self, OwnerLeaseError> {
        {
            let mut registry = lock(process_registry());
            if !registry.insert(identity) {
                return Err(OwnerLeaseError::Unavailable);
            }
        }
        let descriptor = match fs::open(
            lock_path,
            OFlags::CREATE | OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::RUSR | Mode::WUSR,
        ) {
            Ok(descriptor) => descriptor,
            Err(_) => {
                lock(process_registry()).remove(&identity);
                return Err(OwnerLeaseError::Io);
            }
        };
        let metadata = match fs::fstat(&descriptor) {
            Ok(metadata) => metadata,
            Err(_) => {
                lock(process_registry()).remove(&identity);
                return Err(OwnerLeaseError::Io);
            }
        };
        if !FileType::from_raw_mode(metadata.st_mode).is_file() {
            lock(process_registry()).remove(&identity);
            return Err(OwnerLeaseError::Io);
        }
        if let Err(error) = fs::flock(&descriptor, FlockOperation::NonBlockingLockExclusive) {
            lock(process_registry()).remove(&identity);
            return if error == Errno::AGAIN || error == Errno::WOULDBLOCK {
                Err(OwnerLeaseError::Unavailable)
            } else {
                Err(OwnerLeaseError::Io)
            };
        }
        Ok(Self {
            identity,
            descriptor,
        })
    }
}

impl Drop for ProcessLease {
    fn drop(&mut self) {
        let _ = fs::flock(&self.descriptor, FlockOperation::Unlock);
        lock(process_registry()).remove(&self.identity);
    }
}

fn process_registry() -> &'static Mutex<BTreeSet<DatabaseIdentity>> {
    static REGISTRY: OnceLock<Mutex<BTreeSet<DatabaseIdentity>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(BTreeSet::new()))
}

#[cfg(unix)]
fn database_identity(metadata: &std::fs::Metadata) -> Result<DatabaseIdentity, OwnerLeaseError> {
    use std::os::unix::fs::MetadataExt;

    Ok(DatabaseIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(not(unix))]
fn database_identity(_metadata: &std::fs::Metadata) -> Result<DatabaseIdentity, OwnerLeaseError> {
    Err(OwnerLeaseError::UnsupportedEnvironment)
}

#[cfg(target_os = "linux")]
fn qualify_filesystem(path: &Path) -> Result<FilesystemQualification, OwnerLeaseError> {
    let kind = fs::statfs(path).map_err(|_| OwnerLeaseError::Io)?.f_type as u64;
    let name = match kind {
        0x0000_0000_0000_ef53 => "ext",
        0x0000_0000_0102_1994 => "tmpfs",
        0x0000_0000_5846_5342 => "xfs",
        0x0000_0000_794c_7630 => "overlayfs",
        0x0000_0000_9123_683e => "btrfs",
        _ => "unqualified-linux-filesystem",
    };
    Ok(FilesystemQualification {
        name,
        // Filesystem type and effective PRAGMAs are necessary but not
        // sufficient evidence for the reference power-loss claim. A qualified
        // environment also needs the short/torn-write and sync-fault matrix.
        power_loss_qualified: false,
    })
}

#[cfg(target_os = "macos")]
fn qualify_filesystem(path: &Path) -> Result<FilesystemQualification, OwnerLeaseError> {
    const MNT_LOCAL: u64 = 0x0000_1000;

    let flags = fs::statfs(path).map_err(|_| OwnerLeaseError::Io)?.f_flags as u64;
    if flags & MNT_LOCAL == 0 {
        return Ok(FilesystemQualification {
            name: "nonlocal-macos-filesystem",
            power_loss_qualified: false,
        });
    }
    Ok(FilesystemQualification {
        name: "macos-local",
        // fullfsync readback alone does not prove the required fault matrix.
        power_loss_qualified: false,
    })
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn qualify_filesystem(_path: &Path) -> Result<FilesystemQualification, OwnerLeaseError> {
    Err(OwnerLeaseError::UnsupportedEnvironment)
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}
