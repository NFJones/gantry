//! Descriptor-relative package source provider for supported Unix platforms.

use std::collections::BTreeSet;
use std::fmt;
use std::os::fd::OwnedFd;
use std::path::Path;

use gantry_core::portable::FrontendResourceCode;
use gantry_core::source::{
    FrontendResourceLimit, PackagePath, PackagePathError, SourceCounters, SourceError, SourceId,
    SourceLimits, SourceRecord, SourceSnapshot, SourceSnapshotBuilder,
};
use gantry_core::unicode;
use rustix::fs::{FileType, Mode, OFlags, fstat, open, openat};
use rustix::io::{Errno, read};

const READ_CHUNK_BYTES: usize = 8 * 1024;

/// Package-root-relative source access used by snapshot assembly.
pub trait SourceProvider: Send + Sync {
    /// Reads one selected source through exactly one opened file descriptor.
    fn read_source(
        &self,
        path: &PackagePath,
        limits: SourceReadLimits,
    ) -> Result<Vec<u8>, SourceProviderError>;
}

/// Pre-allocation byte limits for one selected source read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceReadLimits {
    maximum_file_bytes: u64,
    package_bytes_before_read: u64,
    maximum_package_bytes: u64,
}

impl SourceReadLimits {
    /// Combines the per-file bound with the package activity's cumulative bytes.
    #[must_use]
    pub const fn new(
        maximum_file_bytes: u64,
        package_bytes_before_read: u64,
        maximum_package_bytes: u64,
    ) -> Self {
        Self {
            maximum_file_bytes,
            package_bytes_before_read,
            maximum_package_bytes,
        }
    }
}

/// One deterministically selected file-module candidate and its exact bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModuleResolution {
    /// Selected package-relative source path.
    pub path: PackagePath,
    /// Exact bytes read from the selected descriptor.
    pub bytes: Vec<u8>,
}

/// Secure filesystem provider rooted at one pinned directory descriptor.
#[derive(Debug)]
pub struct RootDirectorySourceProvider {
    root: OwnedFd,
}

impl RootDirectorySourceProvider {
    /// Opens and pins one package root without following a final symlink.
    pub fn open(root: &Path) -> Result<Self, SourceProviderError> {
        let root = open(
            root,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(map_root_error)?;
        let stat = fstat(&root).map_err(|_| SourceProviderError::Io)?;
        if !FileType::from_raw_mode(stat.st_mode).is_dir() {
            return Err(SourceProviderError::RootNotDirectory);
        }
        Ok(Self { root })
    }

    /// Resolves `mod name;` to exactly one canonical file candidate.
    pub fn resolve_module(
        &self,
        declaring_source: &PackagePath,
        module_name: &str,
        maximum_bytes: u64,
    ) -> Result<ModuleResolution, SourceProviderError> {
        self.resolve_module_bounded(
            declaring_source,
            module_name,
            SourceReadLimits::new(maximum_bytes, 0, maximum_bytes),
        )
    }

    /// Resolves one file module while enforcing both file and cumulative
    /// package byte limits before allocation.
    pub fn resolve_module_bounded(
        &self,
        declaring_source: &PackagePath,
        module_name: &str,
        limits: SourceReadLimits,
    ) -> Result<ModuleResolution, SourceProviderError> {
        validate_module_name(module_name)?;
        let directory = module_directory(declaring_source)?;
        let flat = join_candidate(&directory, &format!("{module_name}.gnt"))?;
        let nested = join_candidate(&directory, &format!("{module_name}/mod.gnt"))?;
        let flat_fd = self.try_open_source(&flat)?;
        let nested_fd = self.try_open_source(&nested)?;
        match (flat_fd, nested_fd) {
            (Some(_), Some(_)) => Err(SourceProviderError::AmbiguousModule { flat, nested }),
            (Some(fd), None) => Ok(ModuleResolution {
                path: flat,
                bytes: read_bounded(&fd, limits)?,
            }),
            (None, Some(fd)) => Ok(ModuleResolution {
                path: nested,
                bytes: read_bounded(&fd, limits)?,
            }),
            (None, None) => Err(SourceProviderError::NotFound),
        }
    }

    fn try_open_source(&self, path: &PackagePath) -> Result<Option<OwnedFd>, SourceProviderError> {
        match self.open_source_with_hook(path, |_, _| {}) {
            Ok(fd) => Ok(Some(fd)),
            Err(SourceProviderError::NotFound) => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn open_source_with_hook(
        &self,
        path: &PackagePath,
        mut after_component: impl FnMut(usize, &str),
    ) -> Result<OwnedFd, SourceProviderError> {
        let components = path.as_str().split('/').collect::<Vec<_>>();
        let (final_name, directories) = components
            .split_last()
            .ok_or(SourceProviderError::InvalidPath(PackagePathError::Empty))?;
        let mut current = None;
        for (index, component) in directories.iter().enumerate() {
            let parent = current.as_ref().unwrap_or(&self.root);
            let next = openat(
                parent,
                *component,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(map_component_error)?;
            let stat = fstat(&next).map_err(|_| SourceProviderError::Io)?;
            if !FileType::from_raw_mode(stat.st_mode).is_dir() {
                return Err(SourceProviderError::NotDirectory);
            }
            current = Some(next);
            after_component(index, component);
        }
        let parent = current.as_ref().unwrap_or(&self.root);
        let file = openat(
            parent,
            *final_name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(map_file_error)?;
        let stat = fstat(&file).map_err(|_| SourceProviderError::Io)?;
        if !FileType::from_raw_mode(stat.st_mode).is_file() {
            return Err(SourceProviderError::NotRegularFile);
        }
        after_component(directories.len(), final_name);
        Ok(file)
    }
}

impl SourceProvider for RootDirectorySourceProvider {
    fn read_source(
        &self,
        path: &PackagePath,
        limits: SourceReadLimits,
    ) -> Result<Vec<u8>, SourceProviderError> {
        let file = self.open_source_with_hook(path, |_, _| {})?;
        read_bounded(&file, limits)
    }
}

/// Incremental package snapshot assembly through one source provider.
pub struct PackageSnapshotLoader<'a> {
    provider: &'a dyn SourceProvider,
    builder: SourceSnapshotBuilder,
    loaded: BTreeSet<PackagePath>,
    maximum_package_files: u64,
    maximum_source_file_bytes: u64,
    maximum_package_source_bytes: u64,
}

impl<'a> PackageSnapshotLoader<'a> {
    /// Starts one immutable package snapshot under the supplied source limits.
    #[must_use]
    pub fn new(provider: &'a dyn SourceProvider, limits: SourceLimits) -> Self {
        Self {
            provider,
            builder: SourceSnapshotBuilder::new(limits),
            loaded: BTreeSet::new(),
            maximum_package_files: limits.maximum_package_files(),
            maximum_source_file_bytes: limits.maximum_source_file_bytes(),
            maximum_package_source_bytes: limits.maximum_package_source_bytes(),
        }
    }

    /// Loads one canonical package path at most once.
    pub fn load(&mut self, path: &str) -> Result<SourceId, SourceProviderError> {
        let path = PackagePath::new(path).map_err(SourceProviderError::InvalidPath)?;
        if self.loaded.contains(&path) {
            return Err(SourceProviderError::DuplicatePath(path));
        }
        let (files, package_bytes, _, _) = self.builder.counters().counts();
        let observed_files = files.checked_add(1);
        if observed_files.is_none_or(|observed| observed > self.maximum_package_files) {
            return Err(SourceProviderError::ResourceLimit(FrontendResourceLimit {
                code: FrontendResourceCode::PackageFileCountLimit,
                limit: self.maximum_package_files,
                observed: observed_files,
            }));
        }
        let bytes = self.provider.read_source(
            &path,
            SourceReadLimits::new(
                self.maximum_source_file_bytes,
                package_bytes,
                self.maximum_package_source_bytes,
            ),
        )?;
        let id = self
            .builder
            .add_file(path.as_str(), &bytes)
            .map_err(SourceProviderError::Source)?;
        self.loaded.insert(path);
        Ok(id)
    }

    /// Admits bytes already selected by deterministic module resolution.
    pub fn add_resolution(
        &mut self,
        resolution: ModuleResolution,
    ) -> Result<SourceId, SourceProviderError> {
        if self.loaded.contains(&resolution.path) {
            return Err(SourceProviderError::DuplicatePath(resolution.path));
        }
        let id = self
            .builder
            .add_file(resolution.path.as_str(), &resolution.bytes)
            .map_err(SourceProviderError::Source)?;
        self.loaded.insert(resolution.path);
        Ok(id)
    }

    /// Borrows one admitted immutable source together with shared activity
    /// counters for incremental lexing and parsing.
    pub fn record_and_counters_mut(
        &mut self,
        id: &SourceId,
    ) -> (Option<&SourceRecord>, &mut SourceCounters) {
        self.builder.record_and_counters_mut(id)
    }

    /// Returns the pre-allocation bounds for the next selected source read,
    /// rejecting the package-file limit before any file bytes are allocated.
    pub fn next_source_read_limits(&self) -> Result<SourceReadLimits, SourceProviderError> {
        let (files, package_bytes, _, _) = self.builder.counters().counts();
        let observed = files.checked_add(1);
        if observed.is_none_or(|value| value > self.maximum_package_files) {
            return Err(SourceProviderError::ResourceLimit(FrontendResourceLimit {
                code: FrontendResourceCode::PackageFileCountLimit,
                limit: self.maximum_package_files,
                observed,
            }));
        }
        Ok(SourceReadLimits::new(
            self.maximum_source_file_bytes,
            package_bytes,
            self.maximum_package_source_bytes,
        ))
    }

    /// Finishes the canonically ordered immutable snapshot.
    #[must_use]
    pub fn finish(self) -> SourceSnapshot {
        self.builder.finish()
    }
}

/// Deterministic package source provider failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SourceProviderError {
    /// Package root could not be pinned as a directory.
    RootNotDirectory,
    /// The package-relative path is invalid.
    InvalidPath(PackagePathError),
    /// A selected component is missing.
    NotFound,
    /// A symlink was encountered at a selected component.
    Symlink,
    /// An intermediate component is not a directory.
    NotDirectory,
    /// A final source is not a regular file.
    NotRegularFile,
    /// Both file-module candidates exist.
    AmbiguousModule {
        /// Flat `name.gnt` candidate.
        flat: PackagePath,
        /// Nested `name/mod.gnt` candidate.
        nested: PackagePath,
    },
    /// A module name cannot form one local candidate component.
    InvalidModuleName,
    /// One source path was requested more than once.
    DuplicatePath(PackagePath),
    /// A source-substrate limit was exceeded before unbounded growth.
    ResourceLimit(FrontendResourceLimit),
    /// Portable snapshot assembly rejected the source.
    Source(SourceError),
    /// Another bounded filesystem failure occurred.
    Io,
}

impl fmt::Display for SourceProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::RootNotDirectory => "package root is not a pinned directory",
            Self::InvalidPath(_) => "package source path is invalid",
            Self::NotFound => "package source does not exist",
            Self::Symlink => "package source path contains a symlink",
            Self::NotDirectory => "package source path component is not a directory",
            Self::NotRegularFile => "package source is not a regular file",
            Self::AmbiguousModule { .. } => "both module file candidates exist",
            Self::InvalidModuleName => "module name is not one canonical local component",
            Self::DuplicatePath(_) => "package source path was loaded more than once",
            Self::ResourceLimit(_) => "package source exceeded its byte limit",
            Self::Source(_) => "portable source snapshot rejected the file",
            Self::Io => "package source filesystem operation failed",
        })
    }
}

impl std::error::Error for SourceProviderError {}

fn read_bounded(file: &OwnedFd, limits: SourceReadLimits) -> Result<Vec<u8>, SourceProviderError> {
    let stat = fstat(file).map_err(|_| SourceProviderError::Io)?;
    let stat_size = u64::try_from(stat.st_size).map_err(|_| SourceProviderError::Io)?;
    check_read_limits(limits, stat_size)?;
    let capacity = usize::try_from(stat_size).map_err(|_| {
        SourceProviderError::ResourceLimit(FrontendResourceLimit {
            code: FrontendResourceCode::SourceFileByteLimit,
            limit: limits.maximum_file_bytes,
            observed: None,
        })
    })?;
    let mut bytes = Vec::with_capacity(capacity);
    let mut chunk = [0_u8; READ_CHUNK_BYTES];
    loop {
        let count = match read(file, &mut chunk[..]) {
            Ok(count) => count,
            Err(Errno::INTR) => continue,
            Err(_) => return Err(SourceProviderError::Io),
        };
        if count == 0 {
            break;
        }
        let observed = u64::try_from(bytes.len())
            .ok()
            .and_then(|current| current.checked_add(count as u64));
        match observed {
            Some(value) => check_read_limits(limits, value)?,
            None => {
                return Err(SourceProviderError::ResourceLimit(FrontendResourceLimit {
                    code: FrontendResourceCode::SourceFileByteLimit,
                    limit: limits.maximum_file_bytes,
                    observed: None,
                }));
            }
        }
        bytes.extend_from_slice(&chunk[..count]);
    }
    Ok(bytes)
}

fn check_read_limits(limits: SourceReadLimits, observed: u64) -> Result<(), SourceProviderError> {
    if observed > limits.maximum_file_bytes {
        return Err(SourceProviderError::ResourceLimit(FrontendResourceLimit {
            code: FrontendResourceCode::SourceFileByteLimit,
            limit: limits.maximum_file_bytes,
            observed: Some(observed),
        }));
    }
    let cumulative = limits.package_bytes_before_read.checked_add(observed);
    if cumulative.is_none_or(|value| value > limits.maximum_package_bytes) {
        return Err(SourceProviderError::ResourceLimit(FrontendResourceLimit {
            code: FrontendResourceCode::PackageSourceByteLimit,
            limit: limits.maximum_package_bytes,
            observed: cumulative,
        }));
    }
    Ok(())
}

fn validate_module_name(module_name: &str) -> Result<(), SourceProviderError> {
    if module_name.is_empty()
        || matches!(module_name, "." | "..")
        || module_name.contains(['/', '\\', '\0'])
        || !unicode::is_nfc(module_name)
    {
        Err(SourceProviderError::InvalidModuleName)
    } else {
        Ok(())
    }
}

fn module_directory(path: &PackagePath) -> Result<String, SourceProviderError> {
    let path = path.as_str();
    if path == "main.gnt" {
        return Ok(String::new());
    }
    if let Some(parent) = path.strip_suffix("/mod.gnt") {
        return Ok(parent.to_owned());
    }
    path.strip_suffix(".gnt")
        .map(str::to_owned)
        .ok_or(SourceProviderError::InvalidPath(
            PackagePathError::NotSourceFile,
        ))
}

fn join_candidate(directory: &str, suffix: &str) -> Result<PackagePath, SourceProviderError> {
    let candidate = if directory.is_empty() {
        suffix.to_owned()
    } else {
        format!("{directory}/{suffix}")
    };
    PackagePath::new(&candidate).map_err(SourceProviderError::InvalidPath)
}

fn map_root_error(error: Errno) -> SourceProviderError {
    match error {
        Errno::LOOP => SourceProviderError::Symlink,
        Errno::NOTDIR => SourceProviderError::RootNotDirectory,
        _ => SourceProviderError::Io,
    }
}

fn map_component_error(error: Errno) -> SourceProviderError {
    match error {
        Errno::NOENT => SourceProviderError::NotFound,
        Errno::LOOP => SourceProviderError::Symlink,
        Errno::NOTDIR => SourceProviderError::NotDirectory,
        _ => SourceProviderError::Io,
    }
}

fn map_file_error(error: Errno) -> SourceProviderError {
    match error {
        Errno::NOENT => SourceProviderError::NotFound,
        Errno::LOOP => SourceProviderError::Symlink,
        Errno::ISDIR => SourceProviderError::NotRegularFile,
        Errno::NOTDIR => SourceProviderError::NotDirectory,
        _ => SourceProviderError::Io,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use gantry_core::portable::FrontendResourceCode;
    use gantry_core::source::{FrontendResourceLimit, PackagePath, SourceLimits};

    use super::{
        PackageSnapshotLoader, RootDirectorySourceProvider, SourceProvider, SourceProviderError,
        SourceReadLimits, read_bounded,
    };

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    struct TempDirectory(PathBuf);

    impl TempDirectory {
        fn new() -> Self {
            let suffix = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("gantry-frontend-{}-{suffix}", std::process::id()));
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
    fn rejects_symlinks_nonregular_files_and_ambiguous_modules() {
        let root = TempDirectory::new();
        assert!(fs::write(root.0.join("main.gnt"), b"root").is_ok());
        assert!(fs::create_dir(root.0.join("dir.gnt")).is_ok());
        assert!(symlink("main.gnt", root.0.join("link.gnt")).is_ok());
        assert!(fs::write(root.0.join("foo.gnt"), b"flat").is_ok());
        assert!(fs::create_dir(root.0.join("foo")).is_ok());
        assert!(fs::write(root.0.join("foo/mod.gnt"), b"nested").is_ok());
        let provider = RootDirectorySourceProvider::open(&root.0);
        assert!(provider.is_ok());
        let provider = provider.unwrap_or_else(|_| unreachable!("checked above"));
        let link = PackagePath::new("link.gnt").unwrap_or_else(|_| unreachable!());
        let directory = PackagePath::new("dir.gnt").unwrap_or_else(|_| unreachable!());
        assert_eq!(
            provider.read_source(&link, SourceReadLimits::new(64, 0, 64)),
            Err(SourceProviderError::Symlink)
        );
        assert_eq!(
            provider.read_source(&directory, SourceReadLimits::new(64, 0, 64)),
            Err(SourceProviderError::NotRegularFile)
        );
        let declaring = PackagePath::new("main.gnt").unwrap_or_else(|_| unreachable!());
        assert!(matches!(
            provider.resolve_module(&declaring, "foo", 64),
            Err(SourceProviderError::AmbiguousModule { .. })
        ));
    }

    #[test]
    fn snapshot_loader_reads_exact_bytes_and_enforces_limits() {
        let root = TempDirectory::new();
        assert!(fs::write(root.0.join("main.gnt"), b"root").is_ok());
        assert!(fs::write(root.0.join("extra.gnt"), b"extra").is_ok());
        let provider = RootDirectorySourceProvider::open(&root.0)
            .unwrap_or_else(|_| unreachable!("checked above"));
        let limits =
            SourceLimits::new(2, 5, 9, 1, 1).unwrap_or_else(|_| unreachable!("positive limits"));
        let mut loader = PackageSnapshotLoader::new(&provider, limits);
        assert!(loader.load("main.gnt").is_ok());
        assert!(loader.load("extra.gnt").is_ok());
        let snapshot = loader.finish();
        assert_eq!(snapshot.records().len(), 2);
        assert_eq!(snapshot.counters().counts().0, 2);

        let count_limits =
            SourceLimits::new(1, 5, 9, 1, 1).unwrap_or_else(|_| unreachable!("positive limits"));
        let mut count_loader = PackageSnapshotLoader::new(&provider, count_limits);
        assert!(count_loader.load("main.gnt").is_ok());
        assert!(matches!(
            count_loader.load("extra.gnt"),
            Err(SourceProviderError::ResourceLimit(FrontendResourceLimit {
                code: FrontendResourceCode::PackageFileCountLimit,
                limit: 1,
                observed: Some(2),
            }))
        ));

        let byte_limits =
            SourceLimits::new(2, 5, 8, 1, 1).unwrap_or_else(|_| unreachable!("positive limits"));
        let mut byte_loader = PackageSnapshotLoader::new(&provider, byte_limits);
        assert!(byte_loader.load("main.gnt").is_ok());
        assert!(matches!(
            byte_loader.load("extra.gnt"),
            Err(SourceProviderError::ResourceLimit(FrontendResourceLimit {
                code: FrontendResourceCode::PackageSourceByteLimit,
                limit: 8,
                observed: Some(9),
            }))
        ));
    }

    #[test]
    fn opened_descriptor_prevents_path_replacement_from_mixing_bytes() {
        let root = TempDirectory::new();
        assert!(fs::create_dir(root.0.join("nested")).is_ok());
        assert!(fs::write(root.0.join("nested/source.gnt"), b"original").is_ok());
        let provider = RootDirectorySourceProvider::open(&root.0)
            .unwrap_or_else(|_| unreachable!("checked above"));
        let path = PackagePath::new("nested/source.gnt").unwrap_or_else(|_| unreachable!());
        let old = root.0.join("old-nested");
        let replacement = root.0.join("nested");
        let descriptor = provider.open_source_with_hook(&path, |index, _| {
            if index == 0 {
                assert!(fs::rename(&replacement, &old).is_ok());
                assert!(fs::create_dir(&replacement).is_ok());
                assert!(fs::write(replacement.join("source.gnt"), b"replacement").is_ok());
            }
        });
        assert!(descriptor.is_ok());
        assert_eq!(
            read_bounded(
                &descriptor.unwrap_or_else(|_| unreachable!()),
                SourceReadLimits::new(64, 0, 64),
            ),
            Ok(b"original".to_vec())
        );
    }

    #[test]
    fn opened_file_descriptor_pins_one_complete_final_file() {
        let root = TempDirectory::new();
        assert!(fs::write(root.0.join("main.gnt"), b"original").is_ok());
        let provider = RootDirectorySourceProvider::open(&root.0)
            .unwrap_or_else(|_| unreachable!("checked above"));
        let path = PackagePath::new("main.gnt").unwrap_or_else(|_| unreachable!());
        let original = root.0.join("original.gnt");
        let selected = root.0.join("main.gnt");
        let descriptor = provider.open_source_with_hook(&path, |index, _| {
            if index == 0 {
                assert!(fs::rename(&selected, &original).is_ok());
                assert!(fs::write(&selected, b"replacement").is_ok());
            }
        });
        assert!(descriptor.is_ok());
        assert_eq!(
            read_bounded(
                &descriptor.unwrap_or_else(|_| unreachable!()),
                SourceReadLimits::new(64, 0, 64),
            ),
            Ok(b"original".to_vec())
        );
    }
}
