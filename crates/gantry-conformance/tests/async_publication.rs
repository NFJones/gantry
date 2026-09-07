//! Independent validation of the executor-backed async publication baseline.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use sha2::{Digest, Sha256};

const ISSUE: &str = "GNT-ASYNC-PUB-001";
const ADOPTION_PATH: &str = "protocol/conformance/async-execution-adoption-v1.json";
const CONTRACT_PATH: &str = "protocol/conformance/async-execution-contract-v1.json";
const INDEX_PATH: &str = "protocol/publication/index-v1.json";
const REPORT_PATH: &str = "protocol/publication/verification-v1.json";
const RELEASE_GUIDE_PATH: &str = "docs/async-execution-release.md";
const PROFILES: [&str; 6] = [
    "analyzer",
    "concurrent-evaluator",
    "durable-runtime",
    "embedding",
    "evaluator",
    "frontend",
];
const REQUIRED_ARTIFACTS: [&str; 7] = [
    "gantry.authoring",
    "gantry.conformance",
    "gantry.embedding",
    "gantry.ir",
    "gantry.journal",
    "gantry.spec",
    "gantry.values",
];

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdoptionGate {
    format: String,
    gate: String,
    status: String,
    specification_sha256: String,
    amended_profiles: Vec<String>,
    advertises_profiles: Vec<String>,
    blocked_by: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Contract {
    requirement_assignments: Vec<Assignment>,
}

#[derive(Debug, Deserialize)]
struct Assignment {
    requirement: String,
    clause: String,
    profiles: Vec<String>,
    evidence_owners: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicationIndex {
    publication_index: Version,
    source_language: Version,
    publication_revision: String,
    artifacts: Vec<IndexArtifact>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Version {
    major: u64,
    minor: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IndexArtifact {
    id: String,
    uri: String,
    media_type: String,
    byte_length: String,
    sha256: String,
    protocols: Vec<ProtocolVersion>,
    profiles: Vec<String>,
    requirements: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct ProtocolVersion {
    family: String,
    major: u64,
    minor: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicationArtifact {
    format: String,
    id: String,
    specification_sha256: String,
    protocols: Vec<ProtocolVersion>,
    profiles: Vec<String>,
    requirements: Vec<String>,
    files: Vec<ArtifactFile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactFile {
    path: String,
    media_type: String,
    byte_length: String,
    sha256: String,
    content: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VerificationReport {
    format: String,
    publication_set_identity: String,
    index: DigestRecord,
    artifacts: Vec<ReportArtifact>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DigestRecord {
    path: String,
    byte_length: String,
    sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReportArtifact {
    id: String,
    path: String,
    byte_length: String,
    sha256: String,
}

#[test]
fn async_publication_baseline_is_current_complete_and_release_blocked() {
    let root = workspace_root();
    let specification = read(&root.join("SPEC.md"));
    let specification_sha256 = sha256(&specification);
    let adoption: AdoptionGate = read_json(&root.join(ADOPTION_PATH));
    assert_eq!(validate_adoption(&adoption, &specification_sha256), Ok(()));

    let profiles: serde_json::Value = read_json(&root.join("protocol/catalogs/profiles-v1.json"));
    assert_eq!(profiles["claims_enabled"], true);
    assert_eq!(profiles["specification_revision"], specification_sha256);
    assert!(profiles.get("superseded_specification_revision").is_none());
    assert_eq!(
        profiles["claims_enabled"].as_bool(),
        Some(gantry::PROFILE_CLAIMS_ENABLED)
    );
    assert!(gantry::advertises_any_profile());

    let contract: Contract = read_json(&root.join(CONTRACT_PATH));
    let mut owned = contract
        .requirement_assignments
        .into_iter()
        .filter(|assignment| {
            assignment
                .evidence_owners
                .iter()
                .any(|owner| owner == ISSUE)
        })
        .map(|assignment| {
            (
                assignment.requirement,
                assignment.clause,
                assignment.profiles,
            )
        })
        .collect::<Vec<_>>();
    owned.sort();
    assert_eq!(owned, expected_owned_rows());

    let index_bytes = read(&root.join(INDEX_PATH));
    let index: PublicationIndex = decode(&index_bytes, INDEX_PATH);
    let resolved = validate_index(&root, &specification, &specification_sha256, &index)
        .unwrap_or_else(|error| panic!("invalid async publication: {error}"));
    validate_report(&root, &index_bytes, &resolved)
        .unwrap_or_else(|error| panic!("invalid async publication report: {error}"));

    let guide = read_text(&root.join(RELEASE_GUIDE_PATH));
    for required in [
        "manual-driving",
        "ExecutorAdapter",
        "GNT-ASYNC-REL-001",
        "Candidate source",
        "source-free resume",
        "hosted macOS",
        "stable-media power-loss",
    ] {
        assert!(guide.contains(required), "release guide omitted {required}");
    }
    assert!(read_text(&root.join("README.md")).contains(RELEASE_GUIDE_PATH));
    assert!(read_text(&root.join("docs/README.md")).contains("async-execution-release.md"));
    assert!(read_text(&root.join("protocol/README.md")).contains("GNT-ASYNC-REL-001"));
    assert!(read_text(&root.join("crates/gantry/src/lib.rs")).contains("ExecutorAdapter"));
}

#[test]
fn async_publication_validator_rejects_release_and_integrity_overclaims() {
    let root = workspace_root();
    let specification = read(&root.join("SPEC.md"));
    let specification_sha256 = sha256(&specification);
    let adoption: AdoptionGate = read_json(&root.join(ADOPTION_PATH));

    let mut blocked = adoption.clone();
    blocked.status = "blocked".to_owned();
    blocked.blocked_by = vec!["GNT-ASYNC-REL-001".to_owned()];
    blocked.advertises_profiles.clear();
    assert!(validate_adoption(&blocked, &specification_sha256).is_err());

    let index_bytes = read(&root.join(INDEX_PATH));
    let mut index: PublicationIndex = decode(&index_bytes, INDEX_PATH);
    index.artifacts[0].sha256 = "0".repeat(64);
    assert!(validate_index(&root, &specification, &specification_sha256, &index).is_err());
}

fn validate_adoption(adoption: &AdoptionGate, specification_sha256: &str) -> Result<(), String> {
    if adoption.format != "gantry.async-execution-adoption/v1"
        || adoption.gate != "GNT-ASYNC-GATE-000"
        || adoption.status != "verified"
        || adoption.specification_sha256 != specification_sha256
        || adoption
            .amended_profiles
            .iter()
            .map(String::as_str)
            .ne(PROFILES)
        || adoption
            .advertises_profiles
            .iter()
            .map(String::as_str)
            .ne(PROFILES)
        || !adoption.blocked_by.is_empty()
    {
        return Err("publication adoption is incomplete or overclaims profiles".to_owned());
    }
    Ok(())
}

fn validate_index(
    root: &Path,
    specification: &[u8],
    specification_sha256: &str,
    index: &PublicationIndex,
) -> Result<BTreeMap<String, (String, Vec<u8>)>, String> {
    if (index.publication_index.major, index.publication_index.minor) != (1, 0)
        || (index.source_language.major, index.source_language.minor) != (1, 0)
        || index.publication_revision != format!("gantry-v1-{specification_sha256}")
        || index
            .artifacts
            .iter()
            .map(|artifact| artifact.id.as_str())
            .ne(REQUIRED_ARTIFACTS)
    {
        return Err("publication identity or membership differs".to_owned());
    }

    let mut resolved = BTreeMap::new();
    let mut protocols = BTreeSet::new();
    let mut release_guide_seen = false;
    for artifact in &index.artifacts {
        if !artifact
            .uri
            .starts_with("https://github.com/NFJones/gantry/releases/download/v1.0.0/")
            || artifact.profiles.windows(2).any(|pair| pair[0] >= pair[1])
            || artifact
                .requirements
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || artifact
                .protocols
                .windows(2)
                .any(|pair| pair[0].family >= pair[1].family)
        {
            return Err(format!("unordered artifact metadata for {}", artifact.id));
        }
        for protocol in &artifact.protocols {
            if (protocol.major, protocol.minor) != (1, 0)
                || !protocols.insert(protocol.family.as_str())
            {
                return Err("protocol allocation differs".to_owned());
            }
        }

        let path = artifact_path(root, &artifact.id);
        let bytes = read_result(&path)?;
        if artifact.byte_length != bytes.len().to_string() || artifact.sha256 != sha256(&bytes) {
            return Err(format!("artifact integrity differs: {}", artifact.id));
        }
        if artifact.id == "gantry.spec" {
            if artifact.media_type != "text/markdown" || bytes != specification {
                return Err("published specification differs from SPEC.md".to_owned());
            }
        } else {
            if artifact.media_type != "application/json" {
                return Err(format!("artifact media type differs: {}", artifact.id));
            }
            let bundle: PublicationArtifact = decode(&bytes, &path.display().to_string());
            if bundle.format != "gantry.publication-artifact/v1"
                || bundle.id != artifact.id
                || bundle.specification_sha256 != specification_sha256
                || bundle.protocols != artifact.protocols
                || bundle.profiles != artifact.profiles
                || bundle.requirements != artifact.requirements
                || bundle.files.is_empty()
                || bundle
                    .files
                    .windows(2)
                    .any(|pair| pair[0].path >= pair[1].path)
            {
                return Err(format!("artifact envelope differs: {}", artifact.id));
            }
            for file in bundle.files {
                if file.path.starts_with("docs/reference/")
                    || file.byte_length != file.content.len().to_string()
                    || file.sha256 != sha256(file.content.as_bytes())
                    || file.content.as_bytes() != read_result(&root.join(&file.path))?
                    || !matches!(
                        file.media_type.as_str(),
                        "application/json" | "text/markdown" | "text/plain" | "text/x-rust"
                    )
                {
                    return Err(format!("published source differs: {}", file.path));
                }
                release_guide_seen |= file.path == RELEASE_GUIDE_PATH;
            }
        }
        resolved.insert(artifact.id.clone(), (relative_path(root, &path)?, bytes));
    }
    if !release_guide_seen || protocols.len() != 10 {
        return Err("publication omits release guidance or a protocol family".to_owned());
    }
    Ok(resolved)
}

fn validate_report(
    root: &Path,
    index_bytes: &[u8],
    resolved: &BTreeMap<String, (String, Vec<u8>)>,
) -> Result<(), String> {
    let report_bytes = read_result(&root.join(REPORT_PATH))?;
    let report: VerificationReport = decode(&report_bytes, REPORT_PATH);
    if report.format != "gantry.publication-verification/v1"
        || report.publication_set_identity != sha256(index_bytes)
        || report.index.path != INDEX_PATH
        || report.index.byte_length != index_bytes.len().to_string()
        || report.index.sha256 != sha256(index_bytes)
        || report.artifacts.len() != REQUIRED_ARTIFACTS.len()
    {
        return Err("verification report identity differs".to_owned());
    }
    for artifact in report.artifacts {
        let (path, bytes) = resolved
            .get(&artifact.id)
            .ok_or_else(|| format!("unknown report artifact {}", artifact.id))?;
        if &artifact.path != path
            || artifact.byte_length != bytes.len().to_string()
            || artifact.sha256 != sha256(bytes)
        {
            return Err(format!("report artifact differs: {}", artifact.id));
        }
    }
    Ok(())
}

fn expected_owned_rows() -> Vec<(String, String, Vec<String>)> {
    let all_profiles = PROFILES
        .iter()
        .map(|profile| (*profile).to_owned())
        .collect::<Vec<String>>();
    vec![
        (
            "GNT-1.0".to_owned(),
            "clause-001".to_owned(),
            all_profiles.clone(),
        ),
        (
            "GNT-1.5".to_owned(),
            "clause-002".to_owned(),
            all_profiles.clone(),
        ),
        (
            "GNT-15.0".to_owned(),
            "clause-005".to_owned(),
            vec!["embedding".to_owned()],
        ),
        (
            "GNT-15.8".to_owned(),
            "clause-001".to_owned(),
            vec!["embedding".to_owned()],
        ),
        ("GNT-2.1".to_owned(), "clause-001".to_owned(), all_profiles),
    ]
}

fn artifact_path(root: &Path, id: &str) -> PathBuf {
    let name = if id == "gantry.spec" {
        "SPEC.md".to_owned()
    } else {
        format!("{id}.json")
    };
    root.join("protocol/publication/v1").join(name)
}

fn relative_path(root: &Path, path: &Path) -> Result<String, String> {
    path.strip_prefix(root)
        .map_err(|_| format!("{} is outside the workspace", path.display()))
        .map(|path| path.to_string_lossy().replace('\\', "/"))
}

fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8], path: &str) -> T {
    serde_json::from_slice(bytes).unwrap_or_else(|error| panic!("could not decode {path}: {error}"))
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> T {
    decode(&read(path), &path.display().to_string())
}

fn read(path: &Path) -> Vec<u8> {
    read_result(path).unwrap_or_else(|error| panic!("{error}"))
}

fn read_result(path: &Path) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|error| format!("could not read {}: {error}", path.display()))
}

fn read_text(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()))
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}
