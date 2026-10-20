//! Public-surface target policy for the filesystem runtime.
//!
//! These rows need no acquired descriptor, so they compile and run on every host this repository
//! supports: they publish which target the slice delivers and prove that every other named target is
//! refused before a root, a grant, a path resolution, or a descriptor exists. Acquisition itself is
//! covered by `fs_runtime_integration`, which compiles only on the delivered mapping.

use gantry::ir::FS_RESOLUTION_COUNT;
use gantry::runtime::{FsHostTarget, FsRuntimeRefusal, FsTargetMapping};

/// Only the Linux mapping is delivered, and every other target refuses before execution.
///
/// macOS is refused because no effect-free no-follow acquisition method for it is established: the
/// event-only open still reaches a pipe reader wait and a device open entry point, so claiming
/// delivery would claim an equivalence this slice cannot test. The refusal is an initial runtime
/// availability limit of this slice, recorded as a typed preflight outcome before any descriptor
/// exists.
#[test]
fn only_the_linux_mapping_is_delivered_and_other_targets_refuse() {
    let linux = FsHostTarget::Linux
        .walk_policy()
        .unwrap_or_else(|| panic!("the linux mapping must be delivered"));
    assert!(linux.no_follow_components());
    assert!(linux.directory_components());
    assert!(linux.close_on_exec());
    assert_eq!(linux.resolution_count(), FS_RESOLUTION_COUNT);
    assert!(
        FsHostTarget::MacOs.walk_policy().is_none(),
        "macos must not claim a delivered mapping without an effect-free acquisition"
    );
    assert_eq!(
        FsTargetMapping::admit(FsHostTarget::MacOs).err(),
        Some(FsRuntimeRefusal::UnsupportedTarget {
            target: FsHostTarget::MacOs,
        })
    );
    assert!(FsHostTarget::Unsupported.walk_policy().is_none());
    assert_eq!(
        FsTargetMapping::admit(FsHostTarget::Unsupported).err(),
        Some(FsRuntimeRefusal::UnsupportedTarget {
            target: FsHostTarget::Unsupported,
        })
    );
}

/// A Linux process delivers the mapping it runs on.
#[cfg(target_os = "linux")]
#[test]
fn linux_process_delivers_its_mapping() {
    assert_eq!(FsHostTarget::current(), FsHostTarget::Linux);
    assert!(FsTargetMapping::for_current().is_ok());
}

/// A macOS process refuses the mapping and a mount before any acquisition.
#[cfg(target_os = "macos")]
#[test]
fn macos_process_refuses_the_mapping_and_a_mount() {
    use gantry::runtime::FsRootDirectory;

    assert_eq!(FsHostTarget::current(), FsHostTarget::MacOs);
    assert_eq!(
        FsTargetMapping::for_current().err(),
        Some(FsRuntimeRefusal::UnsupportedTarget {
            target: FsHostTarget::MacOs,
        })
    );
    assert_eq!(
        FsRootDirectory::mount("data", std::path::Path::new("/")).err(),
        Some(FsRuntimeRefusal::UnsupportedTarget {
            target: FsHostTarget::MacOs,
        })
    );
}
