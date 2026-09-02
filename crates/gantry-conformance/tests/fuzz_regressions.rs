//! Deterministic replay for minimized byte-oriented fuzz regressions.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use gantry::analysis::{AnalysisStatus, analyze_package_types};
use gantry::frontend::{PackageSyntaxStatus, validate_package_syntax};
use gantry::identity::ProtocolIdentity;
use gantry::ir::{
    CanonicalCallableIdentity, CanonicalTemplateIdentity, TypeDescriptor, TypeExpression,
};
use gantry::source::SourceLimits;

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

#[test]
fn protocol_identity_fuzz_regressions_remain_nonpanicking() {
    let directory = workspace_root().join("fuzz/regressions/protocol_identity");
    let entries = fs::read_dir(&directory);
    assert!(entries.is_ok(), "could not read {}", directory.display());
    let mut paths = entries
        .unwrap_or_else(|_| unreachable!("checked above"))
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<Vec<_>, _>>();
    assert!(paths.is_ok(), "could not enumerate {}", directory.display());
    let paths = paths
        .as_mut()
        .unwrap_or_else(|_| unreachable!("checked above"));
    paths.sort();
    assert!(!paths.is_empty(), "no fuzz regressions are checked in");

    for path in paths {
        let bytes = fs::read(&*path);
        assert!(bytes.is_ok(), "could not read {}", path.display());
        if let Ok(value) = std::str::from_utf8(
            bytes
                .as_deref()
                .unwrap_or_else(|_| unreachable!("checked above")),
        ) {
            let _ = ProtocolIdentity::parse(value.trim_end_matches(['\r', '\n']));
        }
    }
}

#[test]
fn generic_fuzz_corpora_replay_through_public_boundaries() {
    let root = workspace_root();

    for bytes in corpus_files(&root.join("fuzz/corpus/parser")) {
        let temporary = TempDirectory::new(&bytes);
        let outcome = validate_package_syntax(&temporary.0, source_limits(), 256)
            .unwrap_or_else(|error| panic!("parser corpus failed operationally: {error:?}"));
        assert_eq!(
            outcome.status(),
            PackageSyntaxStatus::Valid,
            "{:?}",
            outcome.diagnostics()
        );
    }

    for bytes in corpus_files(&root.join("fuzz/corpus/generic_ir")) {
        let value = std::str::from_utf8(&bytes)
            .unwrap_or_else(|error| panic!("generic IR corpus is not UTF-8: {error}"))
            .trim_end();
        let accepted = TypeExpression::from_canonical_string(value, 256).is_ok()
            || TypeDescriptor::from_canonical_string_with_depth_limit(value, 256).is_ok()
            || CanonicalCallableIdentity::from_canonical_string(value, 256).is_ok()
            || CanonicalTemplateIdentity::from_canonical_string(value, 256).is_ok();
        assert!(
            accepted,
            "generic IR corpus has no accepting codec: {value}"
        );
    }

    for (name, bytes) in named_corpus_files(&root.join("fuzz/corpus/generic_package")) {
        let temporary = TempDirectory::new(&bytes);
        let syntax = validate_package_syntax(&temporary.0, source_limits(), 256)
            .unwrap_or_else(|error| panic!("generic package corpus failed syntax: {error:?}"));
        assert_eq!(
            syntax.status(),
            PackageSyntaxStatus::Valid,
            "{:?}",
            syntax.diagnostics()
        );
        let package = analyze_package_types(&syntax)
            .unwrap_or_else(|error| panic!("generic package corpus failed analysis: {error:?}"));
        match name.as_str() {
            "contextual-self" | "nested-applications" => assert_eq!(
                package.status(),
                AnalysisStatus::Valid,
                "{name}: {:?}",
                package.diagnostics()
            ),
            "recursive-obligation" => assert!(
                package
                    .diagnostics()
                    .iter()
                    .any(|diagnostic| { diagnostic.code.as_str() == "cyclic-trait-obligation" }),
                "{name}: {:?}",
                package.diagnostics()
            ),
            other => panic!("unclassified generic package corpus {other}"),
        }
    }
}

struct TempDirectory(PathBuf);

impl TempDirectory {
    fn new(source: &[u8]) -> Self {
        let suffix = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "gantry-fuzz-regression-{}-{suffix}",
            std::process::id()
        ));
        fs::create_dir(&path)
            .unwrap_or_else(|error| panic!("could not create {}: {error}", path.display()));
        fs::write(path.join("main.gnt"), source)
            .unwrap_or_else(|error| panic!("could not write fuzz corpus: {error}"));
        Self(path)
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn corpus_files(directory: &Path) -> Vec<Vec<u8>> {
    named_corpus_files(directory)
        .into_iter()
        .map(|(_, bytes)| bytes)
        .collect()
}

fn named_corpus_files(directory: &Path) -> Vec<(String, Vec<u8>)> {
    let mut paths = fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("could not read {}: {error}", directory.display()))
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|error| panic!("could not enumerate {}: {error}", directory.display()));
    paths.sort();
    assert!(
        !paths.is_empty(),
        "no corpus files in {}",
        directory.display()
    );
    paths
        .iter()
        .map(|path| {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_else(|| panic!("non-UTF-8 corpus path {}", path.display()))
                .to_owned();
            let bytes = fs::read(path)
                .unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()));
            (name, bytes)
        })
        .collect()
}

fn source_limits() -> SourceLimits {
    SourceLimits::new(1, 65_536, 65_536, 16_384, 64)
        .unwrap_or_else(|_| unreachable!("positive source limits"))
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| unreachable!("conformance crate has a workspace root"))
}
