//! External provider contract coverage through the public Gantry facade.

use std::fs;
use std::os::unix::fs::symlink;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use gantry::frontend::{
    RootDirectorySourceProvider, SourceProvider, SourceProviderError, SourceReadLimits,
};
use gantry::source::{PackagePath, SourceLimits};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TempDirectory(PathBuf);

impl TempDirectory {
    fn new() -> Self {
        let suffix = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "gantry-provider-contract-{}-{suffix}",
            std::process::id()
        ));
        assert!(fs::create_dir(&path).is_ok());
        Self(path)
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn public_provider_rejects_escape_symlink_and_ambiguity() {
    let root = TempDirectory::new();
    assert!(fs::write(root.0.join("main.gnt"), b"main").is_ok());
    assert!(symlink("main.gnt", root.0.join("link.gnt")).is_ok());
    assert!(fs::write(root.0.join("child.gnt"), b"flat").is_ok());
    assert!(fs::create_dir(root.0.join("child")).is_ok());
    assert!(fs::write(root.0.join("child/mod.gnt"), b"nested").is_ok());
    let provider = RootDirectorySourceProvider::open(&root.0)
        .unwrap_or_else(|_| unreachable!("checked above"));
    let link = PackagePath::new("link.gnt").unwrap_or_else(|_| unreachable!());
    assert_eq!(
        provider.read_source(&link, SourceReadLimits::new(32, 0, 32)),
        Err(SourceProviderError::Symlink)
    );
    let declaring = PackagePath::new("main.gnt").unwrap_or_else(|_| unreachable!());
    assert!(matches!(
        provider.resolve_module(&declaring, "child", 32),
        Err(SourceProviderError::AmbiguousModule { .. })
    ));
    for invalid in ["../child", "/child", "a/b", "A\u{0300}"] {
        assert_eq!(
            provider.resolve_module(&declaring, invalid, 32),
            Err(SourceProviderError::InvalidModuleName)
        );
    }
}

#[test]
fn public_provider_builds_one_immutable_snapshot() {
    let root = TempDirectory::new();
    assert!(fs::write(root.0.join("main.gnt"), b"root").is_ok());
    let provider = RootDirectorySourceProvider::open(&root.0)
        .unwrap_or_else(|_| unreachable!("checked above"));
    let limits =
        SourceLimits::new(1, 4, 4, 1, 1).unwrap_or_else(|_| unreachable!("positive limits"));
    let mut loader = gantry::frontend::PackageSnapshotLoader::new(&provider, limits);
    let id = loader.load("main.gnt");
    assert!(id.is_ok());
    let snapshot = loader.finish();
    let record = snapshot.get(&id.unwrap_or_else(|_| unreachable!()));
    assert!(record.is_some());
    assert_eq!(record.unwrap_or_else(|| unreachable!()).bytes(), b"root");
}
