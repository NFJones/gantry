//! Requirement-indexed executable evidence for package-owned frontend behavior.

use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use gantry::frontend::{
    PackageSnapshotLoader, RootDirectorySourceProvider, SourceProvider, SourceProviderError,
    SourceReadLimits,
};
use gantry::source::{PackagePath, SourceLimits};
use serde::Deserialize;

const EVIDENCE_ID: &str = "crates/gantry-conformance/tests/frontend_package_evidence.rs#package_requirement_vectors_cover_reviewed_clauses";

#[derive(Debug, Deserialize)]
struct EvidenceManifest {
    format: String,
    specification_sha256: String,
    issue: String,
    entries: Vec<EvidenceEntry>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
struct EvidenceEntry {
    requirement: String,
    clause: String,
}

#[derive(Debug, Deserialize)]
struct RequirementReview {
    specification_sha256: String,
    requirements: Vec<Requirement>,
}

#[derive(Debug, Deserialize)]
struct Requirement {
    id: String,
    clauses: Vec<Clause>,
}

#[derive(Debug, Deserialize)]
struct Clause {
    key: String,
    profile_reviews: Vec<ProfileReview>,
}

#[derive(Debug, Deserialize)]
struct ProfileReview {
    profile: String,
    state: String,
    evidence: Vec<String>,
}

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TempDirectory(PathBuf);

impl TempDirectory {
    fn new() -> Self {
        let suffix = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "gantry-package-evidence-{}-{suffix}",
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
fn reviewed_frontend_package_evidence_is_closed() {
    let root = workspace_root();
    let manifest: EvidenceManifest =
        read_json(&root.join("protocol/conformance/frontend-package-v1.json"));
    let review: RequirementReview = read_json(&root.join("protocol/requirements/reviewed-v1.json"));

    assert_eq!(manifest.format, "gantry.frontend-package-evidence/v1");
    assert_eq!(manifest.issue, "GNT-FE-003");
    assert!(gantry_conformance::evidence_revision_is_expected(
        &manifest.specification_sha256,
        &review.specification_sha256,
    ));
    assert!(!manifest.entries.is_empty());
    assert!(manifest.entries.windows(2).all(|pair| pair[0] < pair[1]));

    for entry in manifest.entries {
        let clause = review
            .requirements
            .iter()
            .find(|requirement| requirement.id == entry.requirement)
            .and_then(|requirement| {
                requirement
                    .clauses
                    .iter()
                    .find(|clause| clause.key == entry.clause)
            })
            .unwrap_or_else(|| panic!("missing {}:{}", entry.requirement, entry.clause));
        let review = clause
            .profile_reviews
            .iter()
            .find(|review| review.profile == "frontend")
            .unwrap_or_else(|| {
                panic!(
                    "missing frontend review for {}:{}",
                    entry.requirement, entry.clause
                )
            });
        assert_eq!(
            review.state, "covered",
            "{}:{}",
            entry.requirement, entry.clause
        );
        assert_eq!(
            review.evidence,
            [EVIDENCE_ID],
            "{}:{}",
            entry.requirement,
            entry.clause
        );
    }
}

#[test]
fn package_requirement_vectors_cover_reviewed_clauses() {
    assert!(PackagePath::new("main.gnt").is_ok());
    assert!(PackagePath::new("nested/child.gnt").is_ok());
    for invalid in ["main.rs", "../main.gnt", "/main.gnt", "nested/../main.gnt"] {
        assert!(PackagePath::new(invalid).is_err(), "{invalid}");
    }

    let root = TempDirectory::new();
    assert!(fs::write(root.0.join("main.gnt"), b"original").is_ok());
    assert!(symlink("main.gnt", root.0.join("alias.gnt")).is_ok());
    let provider = RootDirectorySourceProvider::open(&root.0)
        .unwrap_or_else(|_| unreachable!("temporary root is a directory"));
    let alias = PackagePath::new("alias.gnt").unwrap_or_else(|_| unreachable!("valid path"));
    assert_eq!(
        provider.read_source(&alias, SourceReadLimits::new(64, 0, 64)),
        Err(SourceProviderError::Symlink)
    );

    let limits =
        SourceLimits::new(1, 64, 64, 16, 4).unwrap_or_else(|_| unreachable!("positive limits"));
    let mut loader = PackageSnapshotLoader::new(&provider, limits);
    let source = loader
        .load("main.gnt")
        .unwrap_or_else(|_| unreachable!("fixture source is readable"));
    assert!(fs::write(root.0.join("main.gnt"), b"changed").is_ok());
    let snapshot = loader.finish();
    assert_eq!(
        snapshot
            .get(&source)
            .unwrap_or_else(|| unreachable!("loaded source is retained"))
            .bytes(),
        b"original"
    );
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| unreachable!("conformance crate has a workspace root"))
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> T {
    let bytes = fs::read(path);
    assert!(bytes.is_ok(), "could not read {}", path.display());
    let value =
        bytes.and_then(|bytes| serde_json::from_slice(&bytes).map_err(std::io::Error::other));
    assert!(value.is_ok(), "could not decode {}", path.display());
    value.unwrap_or_else(|_| unreachable!("checked above"))
}
