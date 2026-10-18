//! Rooted read-only filesystem integration for the declared `std.fs` surface.
//!
//! This module is the first filesystem runtime integration of `SPEC.md` Section 47. It delivers
//! `open`, `read`, and `close` for one regular file reached for read-only access through one
//! declared [`gantry_ir::FsPath`] value, one grant issued by a live mounted root, and the common
//! one-call settlement of `std.io`. It adds no declaration text: every refusal it presents is owned
//! by the declaration model, or is a runtime boundary fact that the declaration clauses leave to the
//! host contract. It claims no content snapshot or immutable-content identity: another writer can
//! modify the same inode, and that limitation is stated rather than papered over.
//!
//! # Delivered boundary
//!
//! One mounted root directory supplies the declared root name and issues every grant, so a grant
//! cannot be forged from a spelling and is refused against another mounted instance. `open`
//! resolves the declared segments one component at a time from the pinned root descriptor with a
//! no-follow walk, probes the final object through an effect-free pinned descriptor, and returns one
//! endpoint with an open-instance receipt. `read` settles exactly one bounded call through
//! [`crate::IoSettlementService`] after the read-only and instance preflight of
//! [`FsReadOnlySettlement`], and publishes exactly the initialized octets that call returned. A
//! positive short read stays short progress; only a zero-octet read observes end of stream. `close`
//! requires the issuing grant and the receipt, inspects the bound endpoint before accounting moves,
//! releases the descriptor once, and after it the account admits no call and cannot be reopened.
//!
//! # Read-only denial
//!
//! A read-only grant refuses the three content-mutating whole-object actions of
//! `GNT-47.3-filesystem-action-values` and the `write` and `truncate` resource operations of
//! `GNT-47.4-filesystem-resource-operations` before any descriptor is opened. The five declared
//! operations this slice does not deliver are refused as undelivered rather than silently
//! accepted, so a missing behavior can never be mistaken for a successful one.
//!
//! # Symlink race resistance
//!
//! Every resolved directory component is opened relative to the previous component descriptor with
//! no-follow, directory-only, and close-on-exec flags. The final object is first probed through an
//! effect-free pinned descriptor on the delivered target, its type is verified from that descriptor,
//! and only then is a readable descriptor obtained from the pinned vnode through the descriptor
//! namespace. A symbolic link, junction, or reparse point at any position is refused at that
//! position and is never followed, so concurrently replacing an already resolved component cannot
//! redirect the walk, and reads never re-resolve the declared path value. The walk resolves exactly
//! once, as `GNT-47.8-filesystem-link-policy` declares.
//!
//! # Durability
//!
//! [`FsReadOnlyEndpoint`] is unclonable, holds one operating-system descriptor, and implements no
//! serialization and no logical-value encoding. [`crate::encode_resource_reconstruction_record`]
//! therefore carries accounting facts only, and recovering those facts never recreates a
//! descriptor. A later acquisition of immutable content would be a fresh authorized `open` in a
//! new physical generation, never the reopening of this descriptor, its position, or an accepted
//! lease.
//!
//! # Targets
//!
//! Linux and macOS are both delivered through the same semantic walk, expressed as one
//! [`FsWalkPolicy`], so neither target has a divergent refusal, progress, or publication rule. A
//! target with no real mapping is refused before any descriptor is opened.
//!
//! Still owed to `GNT-GP-FS-001`: writes, replacement, receipts, locks, watch, short-write
//! prefixes, poisoning, revocation, quotas, adapter fault containment, and durable rejection of a
//! live handle beyond the shapes this module already refuses.

use std::fmt;
use std::os::fd::AsRawFd;
use std::path::Path;
use std::sync::Arc;

use gantry_ir::{
    Charge, FS_RESOLUTION_COUNT, FsAction, FsError, FsPath, FsResourceOperation, IoOperation,
    IoRequest, ObservationAllowance, OwnerGeneration, ResourceLifetimeState,
};
use rustix::fd::OwnedFd;
use rustix::fs::{AtFlags, FileType, Mode, OFlags, fstat, open, openat, statat};
use rustix::io::{Errno, read};

use crate::{
    BoundedIoEndpoint, HostResourceError, IoCallBinding, IoCallOutcome, IoHostCompletion,
    IoHostResponse, IoNativeDiagnostic, IoOperationalFault, IoRefusal, IoSettlementService,
    Machine, OwnedHostResource,
};

#[cfg(test)]
mod tests;

/// The exact flags of one resolved directory component.
const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

/// The exact flags of the readable descriptor of one resolved regular file.
const FILE_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::CLOEXEC)
    .union(OFlags::NONBLOCK)
    .union(OFlags::NOCTTY);

/// The macOS `O_EVTONLY` flag, which opens a vnode for event notification only.
///
/// The published `rustix` flag set does not name this flag, so the delivered macOS mapping carries
/// its documented `<fcntl.h>` value. It is used only to probe a final component without invoking a
/// device or pipe data open; the readable descriptor is then obtained from the pinned vnode.
#[cfg(target_os = "macos")]
const MACOS_EVTONLY: u32 = 0x8000;

/// The effect-free probe flags of one final component on Linux.
#[cfg(target_os = "linux")]
const PROBE_FLAGS: OFlags = OFlags::PATH.union(OFlags::NOFOLLOW).union(OFlags::CLOEXEC);

/// The effect-free probe flags of one final component on macOS.
#[cfg(target_os = "macos")]
const PROBE_FLAGS: OFlags = OFlags::from_bits_retain(MACOS_EVTONLY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

/// The effect-free probe flags of one final component on an unmapped host.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
const PROBE_FLAGS: OFlags = OFlags::empty();

/// The semantic descriptor walk one delivered host target uses.
///
/// The policy is the same value for Linux and macOS: both targets resolve the same way, refuse the
/// same objects, and publish the same settlement facts. It describes delivered behavior; it is not
/// a capability, not a target name, and not a grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FsWalkPolicy {
    no_follow_components: bool,
    directory_components: bool,
    close_on_exec: bool,
    resolution_count: u32,
}

impl FsWalkPolicy {
    /// Returns whether every resolved component refuses a symbolic link instead of following one.
    #[must_use]
    pub const fn no_follow_components(self) -> bool {
        self.no_follow_components
    }

    /// Returns whether every intermediate component is required to be a directory.
    #[must_use]
    pub const fn directory_components(self) -> bool {
        self.directory_components
    }

    /// Returns whether every descriptor is closed across an executed program image.
    #[must_use]
    pub const fn close_on_exec(self) -> bool {
        self.close_on_exec
    }

    /// Returns the declared number of resolutions one operation performs for its path value.
    #[must_use]
    pub const fn resolution_count(self) -> u32 {
        self.resolution_count
    }
}

/// One real host target this runtime maps declared filesystem values onto.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum FsHostTarget {
    /// The Linux mapping.
    Linux,
    /// The macOS mapping.
    MacOs,
    /// A target with no delivered mapping; every operation is refused before execution.
    Unsupported,
}

impl FsHostTarget {
    /// Returns the target this process runs on.
    ///
    /// A process on any other operating system receives [`Self::Unsupported`], so the refusal is
    /// produced before a descriptor, a path resolution, or an effect.
    #[must_use]
    pub const fn current() -> Self {
        if cfg!(target_os = "linux") {
            Self::Linux
        } else if cfg!(target_os = "macos") {
            Self::MacOs
        } else {
            Self::Unsupported
        }
    }

    /// Returns the semantic walk policy of this target, or `None` when it has no mapping.
    #[must_use]
    pub const fn walk_policy(self) -> Option<FsWalkPolicy> {
        match self {
            Self::Linux | Self::MacOs => Some(FsWalkPolicy {
                no_follow_components: true,
                directory_components: true,
                close_on_exec: true,
                resolution_count: FS_RESOLUTION_COUNT,
            }),
            Self::Unsupported => None,
        }
    }
}

impl fmt::Display for FsHostTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Linux => "linux",
            Self::MacOs => "macos",
            Self::Unsupported => "unsupported",
        })
    }
}

/// The admitted real target mapping one grant and one mounted root use.
///
/// A mapping is admitted once and then carried by value, so the target that admitted a grant and
/// the target that mounts a root are the same checked fact rather than two independent guesses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FsTargetMapping {
    target: FsHostTarget,
    policy: FsWalkPolicy,
}

impl FsTargetMapping {
    /// Admits one real target mapping, refusing a target with no delivered mapping.
    ///
    /// # Errors
    ///
    /// Returns [`FsRuntimeRefusal::UnsupportedTarget`] when `target` has no delivered mapping.
    pub fn admit(target: FsHostTarget) -> Result<Self, FsRuntimeRefusal> {
        match target.walk_policy() {
            Some(policy) => Ok(Self { target, policy }),
            None => Err(FsRuntimeRefusal::UnsupportedTarget { target }),
        }
    }

    /// Admits the real target mapping of this process.
    ///
    /// # Errors
    ///
    /// Returns [`FsRuntimeRefusal::UnsupportedTarget`] on a process whose operating system has no
    /// delivered mapping.
    pub fn for_current() -> Result<Self, FsRuntimeRefusal> {
        Self::admit(FsHostTarget::current())
    }

    /// Returns the real target this mapping names.
    #[must_use]
    pub const fn target(self) -> FsHostTarget {
        self.target
    }

    /// Returns the semantic walk policy of this mapping.
    #[must_use]
    pub const fn policy(self) -> FsWalkPolicy {
        self.policy
    }
}

/// One contained native class of a refused descriptor operation.
///
/// The class is a stable label of an operating-system fact, never a message, a path, or a
/// payload. No class is a portable diagnostic spelling of `std.fs`, and none is published as a
/// domain refusal or as a successful outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FsNativeClass {
    /// The operating system reported an interrupted call.
    Interrupted,
    /// The operating system refused access.
    Permission,
    /// The named object was not a regular file.
    NotRegularFile,
    /// The descriptor no longer names a usable object.
    StaleDescriptor,
    /// Another native class this slice does not name.
    Other,
}

impl fmt::Display for FsNativeClass {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Interrupted => "interrupted",
            Self::Permission => "permission",
            Self::NotRegularFile => "not-regular-file",
            Self::StaleDescriptor => "stale-descriptor",
            Self::Other => "other",
        })
    }
}

/// One refusal of this rooted read-only boundary.
///
/// The set is closed for this slice. A read-only grant refusal is distinct from an undelivered
/// operation, a path value refusal is distinct from a target-state refusal, and a contained native
/// class is never relabelled as a portable domain refusal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FsRuntimeRefusal {
    /// A read-only grant refuses a content-mutating whole-object action.
    ReadOnlyActionDenied {
        /// The refused action.
        action: FsAction,
    },
    /// A read-only grant refuses a content-mutating resource operation.
    ReadOnlyGrantDenied {
        /// The refused operation.
        operation: FsResourceOperation,
    },
    /// The declared operation is not delivered by this slice.
    Undelivered {
        /// The undelivered operation.
        operation: FsResourceOperation,
    },
    /// The host target has no real mapping in this runtime.
    UnsupportedTarget {
        /// The unmapped target.
        target: FsHostTarget,
    },
    /// A grant was admitted against another target mapping than the mounted root.
    TargetMappingMismatch {
        /// The target of the grant.
        admitted: FsHostTarget,
        /// The target of the mounted root.
        mounted: FsHostTarget,
    },
    /// The declared path value names a root this directory does not mount.
    ForeignRoot {
        /// The declared root.
        declared: String,
        /// The mounted root.
        mounted: String,
    },
    /// The grant was issued by another mounted root instance of the same declared name.
    ForeignGrant {
        /// The declared root name the grant was issued under.
        root: String,
    },
    /// The grant or receipt does not name the instance being closed.
    ForeignInstance,
    /// The landed settlement service refused admission before dispatch.
    Settlement(IoRefusal),
    /// The declared path value is refused by the declared path-value model.
    Path {
        /// The path-value refusal.
        error: FsError,
    },
    /// The declared target state is absent at this position.
    TargetStateUnadmitted {
        /// The zero-based position of the segment that named no object.
        position: u32,
    },
    /// A symbolic link, junction, or reparse point was refused at this position.
    LinkRefused {
        /// The zero-based position of the refused link.
        position: u32,
    },
    /// The named object is not a directory at this position.
    NotDirectory {
        /// The zero-based position of the offending object.
        position: u32,
    },
    /// The named object is not a regular file at this position.
    NotRegularFile {
        /// The zero-based position of the offending object.
        position: u32,
    },
    /// A contained native class refused the operation.
    Native {
        /// The contained class, which carries no message or payload.
        class: FsNativeClass,
    },
    /// The landed resource transport refused or failed.
    Transport(HostResourceError),
}

impl fmt::Display for FsRuntimeRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReadOnlyActionDenied { action } => write!(
                formatter,
                "the read-only grant refuses the content-mutating action {}",
                action.as_str()
            ),
            Self::ReadOnlyGrantDenied { operation } => write!(
                formatter,
                "the read-only grant refuses the content-mutating operation {}",
                operation.as_str()
            ),
            Self::Undelivered { operation } => write!(
                formatter,
                "this slice does not deliver the declared operation {}",
                operation.as_str()
            ),
            Self::UnsupportedTarget { target } => {
                write!(
                    formatter,
                    "the host target {target} has no delivered mapping"
                )
            }
            Self::TargetMappingMismatch { admitted, mounted } => write!(
                formatter,
                "the grant target {admitted} differs from the mounted target {mounted}"
            ),
            Self::ForeignRoot { declared, mounted } => write!(
                formatter,
                "the declared root {declared} is not the mounted root {mounted}"
            ),
            Self::ForeignGrant { root } => write!(
                formatter,
                "the grant for root {root} was issued by another mounted root instance"
            ),
            Self::ForeignInstance => {
                write!(
                    formatter,
                    "the grant or receipt does not name this open instance"
                )
            }
            Self::Settlement(error) => write!(
                formatter,
                "the landed settlement service refused admission: {error:?}"
            ),
            Self::Path { error } => {
                write!(formatter, "the declared path value is refused: {error}")
            }
            Self::TargetStateUnadmitted { position } => write!(
                formatter,
                "the declared path value names no object at position {position}"
            ),
            Self::LinkRefused { position } => write!(
                formatter,
                "a symbolic link, junction, or reparse point at position {position} is refused"
            ),
            Self::NotDirectory { position } => {
                write!(
                    formatter,
                    "the object at position {position} is not a directory"
                )
            }
            Self::NotRegularFile { position } => {
                write!(
                    formatter,
                    "the object at position {position} is not a regular file"
                )
            }
            Self::Native { class } => {
                write!(
                    formatter,
                    "the contained native class {class} refused the operation"
                )
            }
            Self::Transport(error) => write!(
                formatter,
                "the landed resource transport refused the call: {error:?}"
            ),
        }
    }
}

impl std::error::Error for FsRuntimeRefusal {}

/// One read-only grant issued by one live mounted root over one declared path value.
///
/// A grant cannot be constructed from a spelling: it is issued only by `FsRootDirectory` and
/// carries that root instance's unforgeable identity, its declared root name, the path value, and
/// the admitted target mapping. It answers exactly the declaration-layer grant questions of
/// `GNT-47.7-filesystem-action-grants`. Holding a grant never admits a call by itself: the caller
/// still presents the exact requirement, owner generation, and admission lease that the landed
/// transport and settlement service authenticate, and a grant is not a capability.
#[derive(Clone, Debug)]
pub struct FsReadOnlyGrant {
    root_identity: Arc<()>,
    root_name: String,
    path: FsPath,
    mapping: FsTargetMapping,
}

impl PartialEq for FsReadOnlyGrant {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.root_identity, &other.root_identity)
            && self.root_name == other.root_name
            && self.path == other.path
            && self.mapping == other.mapping
    }
}

impl Eq for FsReadOnlyGrant {}

impl FsReadOnlyGrant {
    /// Returns the declared root name this grant was issued under.
    #[must_use]
    pub fn root_name(&self) -> &str {
        &self.root_name
    }

    /// Checks that this grant is the exact grant one open receipt was issued for.
    fn covers(&self, receipt: &FsOpenReceipt) -> bool {
        Arc::ptr_eq(&self.root_identity, &receipt.root_identity)
            && self.root_name == receipt.root_name
            && self.path == receipt.path
            && self.mapping == receipt.mapping
    }

    /// Returns the declared path value this grant was issued for.
    #[must_use]
    pub const fn path(&self) -> &FsPath {
        &self.path
    }

    /// Returns the admitted target mapping of this grant.
    #[must_use]
    pub const fn mapping(&self) -> FsTargetMapping {
        self.mapping
    }

    /// Returns the real target of this grant.
    #[must_use]
    pub const fn target(&self) -> FsHostTarget {
        self.mapping.target()
    }

    /// Admits one declared whole-object action under this read-only grant.
    ///
    /// # Errors
    ///
    /// Returns [`FsRuntimeRefusal::ReadOnlyActionDenied`] for `create`, `replace`, and `remove`,
    /// which are exactly the declared content-mutating actions. A read is admitted.
    pub fn admit_action(&self, action: FsAction) -> Result<(), FsRuntimeRefusal> {
        if action.declares_content_mutation() {
            Err(FsRuntimeRefusal::ReadOnlyActionDenied { action })
        } else {
            Ok(())
        }
    }

    /// Admits one declared resource operation under this read-only grant.
    ///
    /// # Errors
    ///
    /// Returns [`FsRuntimeRefusal::ReadOnlyGrantDenied`] for `write` and `truncate`, which are
    /// exactly the declared content-mutating resource operations.
    pub fn admit_operation(&self, operation: FsResourceOperation) -> Result<(), FsRuntimeRefusal> {
        if operation.declares_content_mutation() {
            Err(FsRuntimeRefusal::ReadOnlyGrantDenied { operation })
        } else {
            Ok(())
        }
    }

    /// Admits one common I/O request under this read-only grant.
    ///
    /// # Errors
    ///
    /// A write request is refused as [`FsRuntimeRefusal::ReadOnlyGrantDenied`], and a seek request
    /// as [`FsRuntimeRefusal::Undelivered`], both before any dispatch.
    pub fn admit_request(&self, request: &IoRequest) -> Result<(), FsRuntimeRefusal> {
        match request.operation() {
            IoOperation::Read => Ok(()),
            IoOperation::Write => Err(FsRuntimeRefusal::ReadOnlyGrantDenied {
                operation: FsResourceOperation::Write,
            }),
            IoOperation::Seek => Err(FsRuntimeRefusal::Undelivered {
                operation: FsResourceOperation::Seek,
            }),
        }
    }

    /// Authorizes one declared resource operation against this grant and this slice.
    ///
    /// The read-only denial is decided first, so a mutating operation is never reported as merely
    /// undelivered, and the delivery question is decided only for the operations a read-only grant
    /// admits.
    ///
    /// # Errors
    ///
    /// Returns [`FsRuntimeRefusal::ReadOnlyGrantDenied`] for a content-mutating operation, and
    /// [`FsRuntimeRefusal::Undelivered`] for a declared operation this slice does not deliver.
    pub fn authorize(&self, operation: FsResourceOperation) -> Result<(), FsRuntimeRefusal> {
        self.admit_operation(operation)?;
        match operation {
            FsResourceOperation::Open | FsResourceOperation::Read | FsResourceOperation::Close => {
                Ok(())
            }
            FsResourceOperation::Seek
            | FsResourceOperation::Flush
            | FsResourceOperation::Sync
            | FsResourceOperation::Lock
            | FsResourceOperation::Watch => Err(FsRuntimeRefusal::Undelivered { operation }),
            FsResourceOperation::Write | FsResourceOperation::Truncate => {
                Err(FsRuntimeRefusal::ReadOnlyGrantDenied { operation })
            }
        }
    }
}

/// One mounted declared root and the pinned host directory it names.
///
/// The root name is a declared portable root of `GNT-47.2-filesystem-path-values`. The descriptor
/// is opened once and never re-resolved, so the walk of every declared path value under this root
/// starts from the same pinned base. The type is not clonable and carries no serialization.
pub struct FsRootDirectory {
    name: String,
    mapping: FsTargetMapping,
    identity: Arc<()>,
    descriptor: OwnedFd,
}

impl FsRootDirectory {
    /// Mounts one declared portable root name onto one pinned host directory.
    ///
    /// The directory is opened without following a final symbolic link, with directory-only and
    /// close-on-exec flags, and that descriptor becomes the only base the later walk uses. The
    /// declared name is validated by the declared path model, so an invalid root spelling is
    /// refused before the descriptor is acquired.
    ///
    /// # Errors
    ///
    /// Returns [`FsRuntimeRefusal::UnsupportedTarget`] on a host with no delivered mapping,
    /// [`FsRuntimeRefusal::Path`] for a root spelling the declared model refuses, and
    /// [`FsRuntimeRefusal::TargetStateUnadmitted`], [`FsRuntimeRefusal::LinkRefused`],
    /// [`FsRuntimeRefusal::NotDirectory`], or [`FsRuntimeRefusal::Native`] for a directory that
    /// cannot be pinned.
    pub fn mount(name: &str, directory: &Path) -> Result<Self, FsRuntimeRefusal> {
        let mapping = FsTargetMapping::for_current()?;
        FsPath::rooted(name, &["anchor"]).map_err(|error| FsRuntimeRefusal::Path { error })?;
        let descriptor = match open(directory, DIRECTORY_FLAGS, Mode::empty()) {
            Ok(descriptor) => descriptor,
            Err(error) => return Err(map_root_errno(error)),
        };
        let stat = match fstat(&descriptor) {
            Ok(stat) => stat,
            Err(error) => return Err(map_root_errno(error)),
        };
        if !FileType::from_raw_mode(stat.st_mode).is_dir() {
            return Err(FsRuntimeRefusal::NotDirectory { position: 0 });
        }
        Ok(Self {
            name: name.to_owned(),
            mapping,
            identity: Arc::new(()),
            descriptor,
        })
    }

    /// Returns the declared root name this directory is mounted for.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the admitted target mapping of this mount.
    #[must_use]
    pub const fn mapping(&self) -> FsTargetMapping {
        self.mapping
    }

    /// Returns the real target of this mount.
    #[must_use]
    pub const fn target(&self) -> FsHostTarget {
        self.mapping.target()
    }

    /// Issues one read-only grant under this mounted root instance.
    ///
    /// The grant is bound to this exact mount instance, its declared root name, one declared path
    /// value, and the admitted target mapping. A path value naming another root is refused before a
    /// grant exists, and another mounted instance of the same declared name cannot satisfy the
    /// grant later.
    ///
    /// # Errors
    ///
    /// Returns [`FsRuntimeRefusal::ForeignRoot`] when `path` names another declared root.
    pub fn issue_grant(&self, path: &FsPath) -> Result<FsReadOnlyGrant, FsRuntimeRefusal> {
        if path.root() != self.name {
            return Err(FsRuntimeRefusal::ForeignRoot {
                declared: path.root().to_owned(),
                mounted: self.name.clone(),
            });
        }
        Ok(FsReadOnlyGrant {
            root_identity: Arc::clone(&self.identity),
            root_name: self.name.clone(),
            path: path.clone(),
            mapping: self.mapping,
        })
    }

    /// Opens one declared regular file for read-only access under a grant issued by this mount.
    ///
    /// The grant is checked first: it must name this mounted root, it must have been admitted
    /// against the same target mapping, and it must admit both the `open` and the `read` resource
    /// operation. The walk then resolves each declared segment once, from the pinned base, with
    /// no-follow and directory-only flags, and opens the final object the same way. Nothing is
    /// created, truncated, replaced, or removed by this route.
    ///
    /// # Errors
    ///
    /// Returns [`FsRuntimeRefusal::ReadOnlyGrantDenied`] or
    /// [`FsRuntimeRefusal::Undelivered`] before any descriptor is opened,
    /// [`FsRuntimeRefusal::ForeignRoot`] or [`FsRuntimeRefusal::TargetMappingMismatch`] when the
    /// grant does not belong to this mount, and [`FsRuntimeRefusal::Path`],
    /// [`FsRuntimeRefusal::TargetStateUnadmitted`], [`FsRuntimeRefusal::LinkRefused`],
    /// [`FsRuntimeRefusal::NotDirectory`], [`FsRuntimeRefusal::NotRegularFile`], or
    /// [`FsRuntimeRefusal::Native`] for a path value the walk refuses.
    pub fn open_read_only(
        &self,
        grant: &FsReadOnlyGrant,
    ) -> Result<FsReadOnlyEndpoint, FsRuntimeRefusal> {
        if !Arc::ptr_eq(&grant.root_identity, &self.identity) {
            return Err(FsRuntimeRefusal::ForeignGrant {
                root: grant.root_name.clone(),
            });
        }
        if grant.mapping() != self.mapping {
            return Err(FsRuntimeRefusal::TargetMappingMismatch {
                admitted: grant.target(),
                mounted: self.mapping.target(),
            });
        }
        if grant.path().root() != self.name {
            return Err(FsRuntimeRefusal::ForeignRoot {
                declared: grant.path().root().to_owned(),
                mounted: self.name.clone(),
            });
        }
        grant.authorize(FsResourceOperation::Open)?;
        grant.authorize(FsResourceOperation::Read)?;
        let segments = grant.path().segments();
        let Some((last_name, directories)) = segments.split_last() else {
            return Err(FsRuntimeRefusal::Path {
                error: FsError::PathInvalid {
                    detail: "the declared path value carries no segment".to_owned(),
                    position: 0,
                },
            });
        };
        let mut current: Option<OwnedFd> = None;
        for (position, component) in directories.iter().enumerate() {
            // The declared model bounds a path value to 256 segments, so the ordinal always fits.
            let position = position as u32;
            let parent = current.as_ref().unwrap_or(&self.descriptor);
            if let Some(refusal) = component_refusal(parent, component.as_str(), position) {
                return Err(refusal);
            }
            let next = match openat(parent, component.as_str(), DIRECTORY_FLAGS, Mode::empty()) {
                Ok(next) => next,
                Err(error) => return Err(map_component_errno(error, position)),
            };
            let stat = match fstat(&next) {
                Ok(stat) => stat,
                Err(error) => return Err(map_component_errno(error, position)),
            };
            if !FileType::from_raw_mode(stat.st_mode).is_dir() {
                return Err(FsRuntimeRefusal::NotDirectory { position });
            }
            current = Some(next);
        }
        let position = directories.len() as u32;
        let parent = current.as_ref().unwrap_or(&self.descriptor);
        let probe = match openat(parent, last_name.as_str(), probe_flags(), Mode::empty()) {
            Ok(probe) => probe,
            Err(error) => return Err(map_component_errno(error, position)),
        };
        let probe_stat = match fstat(&probe) {
            Ok(stat) => stat,
            Err(error) => return Err(map_component_errno(error, position)),
        };
        let probe_type = FileType::from_raw_mode(probe_stat.st_mode);
        if probe_type == FileType::Symlink {
            return Err(FsRuntimeRefusal::LinkRefused { position });
        }
        if probe_type != FileType::RegularFile {
            return Err(FsRuntimeRefusal::NotRegularFile { position });
        }
        let readable = reopen_path(probe.as_raw_fd());
        let descriptor = match open(readable.as_str(), FILE_FLAGS, Mode::empty()) {
            Ok(descriptor) => descriptor,
            Err(error) => return Err(map_component_errno(error, position)),
        };
        drop(probe);
        let stat = match fstat(&descriptor) {
            Ok(stat) => stat,
            Err(error) => return Err(map_component_errno(error, position)),
        };
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
            || stat.st_dev != probe_stat.st_dev
            || stat.st_ino != probe_stat.st_ino
        {
            return Err(FsRuntimeRefusal::Native {
                class: FsNativeClass::StaleDescriptor,
            });
        }
        Ok(FsReadOnlyEndpoint {
            receipt: FsOpenReceipt {
                root_identity: Arc::clone(&self.identity),
                root_name: self.name.clone(),
                path: grant.path().clone(),
                mapping: self.mapping,
                instance: Arc::new(()),
            },
            descriptor,
            calls: 0,
        })
    }
}

impl fmt::Debug for FsRootDirectory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FsRootDirectory")
            .field("name", &self.name)
            .field("target", &self.mapping.target())
            .finish_non_exhaustive()
    }
}

/// One open instance receipt fixing the issuing grant, root instance, path value, and target.
///
/// A receipt is produced only by [`FsRootDirectory::open_read_only`]. It is a value, not a handle and
/// not authority: it proves which grant and which open instance a close presents, and it carries
/// no descriptor or path authority of its own.
#[derive(Clone, Debug)]
pub struct FsOpenReceipt {
    root_identity: Arc<()>,
    root_name: String,
    path: FsPath,
    mapping: FsTargetMapping,
    instance: Arc<()>,
}

impl PartialEq for FsOpenReceipt {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.root_identity, &other.root_identity)
            && self.root_name == other.root_name
            && self.path == other.path
            && self.mapping == other.mapping
            && Arc::ptr_eq(&self.instance, &other.instance)
    }
}

impl Eq for FsOpenReceipt {}

impl FsOpenReceipt {
    /// Returns the declared path value this open instance was opened for.
    #[must_use]
    pub const fn path(&self) -> &FsPath {
        &self.path
    }

    /// Returns the real target this open instance was opened on.
    #[must_use]
    pub const fn target(&self) -> FsHostTarget {
        self.mapping.target()
    }
}

/// One open regular file and the only live descriptor of its resource instance.
///
/// The endpoint is unclonable, nonserializable, and holds no logical-value encoding, so no
/// descriptor can be placed in an ordinary value, a hook result, a prompt, a checkpoint, or a
/// durable reconstruction record. It pins descriptor identity, not content: another writer can
/// modify the same inode, and this slice claims no snapshot or immutable-content identity. Each
/// [`BoundedIoEndpoint::attempt`] performs exactly one read of at most the admitted request quantity
/// and reports exactly the initialized octets that read returned; no buffer remainder is carried
/// between calls and no call is retried.
pub struct FsReadOnlyEndpoint {
    receipt: FsOpenReceipt,
    descriptor: OwnedFd,
    calls: u64,
}

impl FsReadOnlyEndpoint {
    /// Returns the declared path value this instance was opened for.
    #[must_use]
    pub const fn path(&self) -> &FsPath {
        &self.receipt.path
    }

    /// Returns the real target this instance was opened on.
    #[must_use]
    pub const fn target(&self) -> FsHostTarget {
        self.receipt.mapping.target()
    }

    /// Returns the number of bounded calls this endpoint performed.
    #[must_use]
    pub const fn calls(&self) -> u64 {
        self.calls
    }

    /// Returns one receipt naming this exact open instance.
    #[must_use]
    pub fn receipt(&self) -> FsOpenReceipt {
        self.receipt.clone()
    }

    /// Performs exactly one bounded read and reports the facts it observed.
    ///
    /// Only a read that returned zero octets observes the end of the stream; a positive short read
    /// is short progress and is never relabelled as end of stream, because the operating system can
    /// return a partial count without the stream being exhausted. The caller observes the end of
    /// stream with one further admitted call, which is a new declared read. An interruption is
    /// reported as a contained native class rather than retried, so one attempt always performs at
    /// most one operating-system call.
    fn read_once(&mut self, call: &IoCallBinding, provided: &[u8]) -> IoHostCompletion {
        let request = call.request();
        if request.operation() != IoOperation::Read || !provided.is_empty() {
            return IoHostCompletion::Operational(IoOperationalFault::UnsupportedRequest {
                operation: request.operation(),
            });
        }
        self.calls = self.calls.saturating_add(1);
        let quantity = usize::try_from(request.quantity()).unwrap_or(usize::MAX);
        let mut buffer = vec![0_u8; quantity];
        match read(&self.descriptor, &mut buffer) {
            Ok(advanced) => {
                let advanced = advanced.min(buffer.len());
                let ended = advanced == 0;
                IoHostCompletion::Read {
                    advanced: advanced as u64,
                    bytes: buffer[..advanced].to_vec(),
                    ended,
                }
            }
            Err(Errno::INTR) => native_completion(FsNativeClass::Interrupted),
            Err(Errno::ISDIR) => native_completion(FsNativeClass::NotRegularFile),
            Err(Errno::BADF) => native_completion(FsNativeClass::StaleDescriptor),
            Err(_) => native_completion(FsNativeClass::Other),
        }
    }
}

impl fmt::Debug for FsReadOnlyEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FsReadOnlyEndpoint")
            .field("path", &self.receipt.path)
            .field("target", &self.receipt.mapping.target())
            .field("calls", &self.calls)
            .finish_non_exhaustive()
    }
}

impl BoundedIoEndpoint for FsReadOnlyEndpoint {
    fn attempt(&mut self, call: &IoCallBinding, provided: &[u8]) -> IoHostResponse {
        let completion = self.read_once(call, provided);
        IoHostResponse::new(call.clone(), completion)
    }
}

/// Closes one bound read-only instance through the landed account finalization.
///
/// The declared `close` operation and the exact issuing grant are checked first: the grant must admit
/// `close`, it must cover the presented receipt, and the bound endpoint must carry that same receipt.
/// Every one of those checks is a read-only inspection, so a mismatch is refused as
/// [`FsRuntimeRefusal::ForeignInstance`] before any accounting transition and the account stays active
/// and physically owned. Finalization then releases the descriptor exactly once through the
/// contained physical disposal of the landed transport: the account moves from active to finished, no
/// call is admitted afterwards, and the same account cannot be finalized or rebound again.
///
/// # Errors
///
/// Returns the grant refusal of the declared `close` operation, [`FsRuntimeRefusal::ForeignInstance`]
/// when the grant, receipt, or bound endpoint does not name the same instance, and
/// [`FsRuntimeRefusal::Transport`] when the landed transport refuses the finalization.
pub fn close_read_only(
    resource: &mut OwnedHostResource<FsReadOnlyEndpoint>,
    grant: &FsReadOnlyGrant,
    receipt: &FsOpenReceipt,
    owner: OwnerGeneration,
    settled_at_us: u64,
) -> Result<ResourceLifetimeState, FsRuntimeRefusal> {
    grant.authorize(FsResourceOperation::Close)?;
    if !grant.covers(receipt) {
        return Err(FsRuntimeRefusal::ForeignInstance);
    }
    let bound = resource
        .inspect(|endpoint| endpoint.receipt())
        .map_err(FsRuntimeRefusal::Transport)?;
    if bound != *receipt {
        return Err(FsRuntimeRefusal::ForeignInstance);
    }
    resource
        .finish(owner, settled_at_us, |_endpoint| Ok(()))
        .map_err(FsRuntimeRefusal::Transport)
}

/// One read-only settlement route that enforces the grant before dispatch.
///
/// The route answers the declaration-layer read-only questions first: the grant must admit the
/// declared `read` operation and the presented request kind, and only then is the landed settlement
/// service admitted. A write or seek request is therefore refused as a grant refusal before any
/// endpoint call, settlement, charge, or accounting transition, never as a host fault after
/// dispatch.
pub struct FsReadOnlySettlement<'a> {
    grant: &'a FsReadOnlyGrant,
    machine: &'a Machine,
    owner: OwnerGeneration,
    allowance: ObservationAllowance,
    charges: Vec<Charge>,
    settled_at_us: u64,
}

impl<'a> FsReadOnlySettlement<'a> {
    /// Admits one read-only settlement route for one grant and one issuing machine.
    ///
    /// # Errors
    ///
    /// Returns the grant refusal of the declared `read` operation before any settlement is built.
    pub fn new(
        grant: &'a FsReadOnlyGrant,
        machine: &'a Machine,
        owner: OwnerGeneration,
        allowance: ObservationAllowance,
        charges: Vec<Charge>,
        settled_at_us: u64,
    ) -> Result<Self, FsRuntimeRefusal> {
        grant.authorize(FsResourceOperation::Read)?;
        Ok(Self {
            grant,
            machine,
            owner,
            allowance,
            charges,
            settled_at_us,
        })
    }

    /// Settles exactly one bounded read after the read-only and instance preflight.
    ///
    /// The grant must admit the declared read operation, it must cover the presented receipt, and
    /// the bound endpoint must carry that same receipt. Every check is read-only, so a foreign
    /// grant, receipt, or endpoint is refused before any loan, charge, settlement, or dispatch.
    ///
    /// # Errors
    ///
    /// Returns [`FsRuntimeRefusal::ReadOnlyGrantDenied`] for a content-mutating request,
    /// [`FsRuntimeRefusal::Undelivered`] for an undelivered request kind,
    /// [`FsRuntimeRefusal::ForeignInstance`] when the grant, receipt, or bound endpoint does not name
    /// the same instance, and [`FsRuntimeRefusal::Settlement`] when the landed service refuses
    /// admission. Every refusal precedes any endpoint call, settlement, charge, or accounting
    /// transition.
    pub fn read(
        &self,
        resource: &mut OwnedHostResource<FsReadOnlyEndpoint>,
        receipt: &FsOpenReceipt,
        request: IoRequest,
    ) -> Result<IoCallOutcome, FsRuntimeRefusal> {
        self.grant.admit_request(&request)?;
        self.grant.authorize(FsResourceOperation::Read)?;
        if !self.grant.covers(receipt) {
            return Err(FsRuntimeRefusal::ForeignInstance);
        }
        let bound = resource
            .inspect(|endpoint| endpoint.receipt())
            .map_err(FsRuntimeRefusal::Transport)?;
        if bound != *receipt {
            return Err(FsRuntimeRefusal::ForeignInstance);
        }
        let mut service = IoSettlementService::new(
            self.machine,
            self.owner,
            IoOperation::Read,
            self.allowance,
            self.charges.clone(),
            self.settled_at_us,
        )
        .map_err(FsRuntimeRefusal::Settlement)?;
        Ok(service.attempt(resource, request, &[]))
    }
}

/// Classifies one declared directory component without following a link.
///
/// The classification names the object a declared segment presents so a link is refused at its
/// exact position. It never authorizes the walk: the pinned open that follows is the only step that
/// acquires the descriptor, and it repeats the no-follow requirement.
fn component_refusal(parent: &OwnedFd, name: &str, position: u32) -> Option<FsRuntimeRefusal> {
    match statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => {
            let file_type = FileType::from_raw_mode(stat.st_mode);
            if file_type == FileType::Symlink {
                Some(FsRuntimeRefusal::LinkRefused { position })
            } else if file_type == FileType::Directory {
                None
            } else {
                Some(FsRuntimeRefusal::NotDirectory { position })
            }
        }
        Err(error) => Some(map_component_errno(error, position)),
    }
}

/// Returns the effect-free probe flags of one final component.
const fn probe_flags() -> OFlags {
    PROBE_FLAGS
}

/// Returns the descriptor-namespace path that reopens one pinned probe descriptor.
///
/// The probe descriptor pins the exact vnode without invoking a device or pipe data open. Reopening
/// through the descriptor namespace resolves that same vnode, so no later path resolution can
/// substitute another object before the readable descriptor exists.
fn reopen_path(descriptor: i32) -> String {
    #[cfg(target_os = "linux")]
    {
        format!("/proc/self/fd/{descriptor}")
    }
    #[cfg(target_os = "macos")]
    {
        format!("/dev/fd/{descriptor}")
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = descriptor;
        String::new()
    }
}

/// Maps one native refusal of the mounted root descriptor.
fn map_root_errno(error: Errno) -> FsRuntimeRefusal {
    match error {
        Errno::NOENT => FsRuntimeRefusal::TargetStateUnadmitted { position: 0 },
        Errno::LOOP => FsRuntimeRefusal::LinkRefused { position: 0 },
        Errno::NOTDIR => FsRuntimeRefusal::NotDirectory { position: 0 },
        Errno::ACCESS | Errno::PERM => FsRuntimeRefusal::Native {
            class: FsNativeClass::Permission,
        },
        _ => FsRuntimeRefusal::Native {
            class: FsNativeClass::Other,
        },
    }
}

/// Maps one native refusal of a resolved component at `position`.
fn map_component_errno(error: Errno, position: u32) -> FsRuntimeRefusal {
    match error {
        Errno::NOENT => FsRuntimeRefusal::TargetStateUnadmitted { position },
        Errno::LOOP => FsRuntimeRefusal::LinkRefused { position },
        Errno::NOTDIR => FsRuntimeRefusal::NotDirectory { position },
        Errno::ACCESS | Errno::PERM => FsRuntimeRefusal::Native {
            class: FsNativeClass::Permission,
        },
        _ => FsRuntimeRefusal::Native {
            class: FsNativeClass::Other,
        },
    }
}

/// Presents one contained native class as a completion that withholds every octet.
fn native_completion(class: FsNativeClass) -> IoHostCompletion {
    match IoNativeDiagnostic::new(class.to_string()) {
        Some(diagnostic) => IoHostCompletion::Native(diagnostic),
        None => IoHostCompletion::Operational(IoOperationalFault::StateUnreadable),
    }
}
