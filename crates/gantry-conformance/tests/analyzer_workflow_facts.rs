//! Public-facade conformance for analyzer ownership, effects, schemas, and inventories.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use gantry::analysis::{
    AnalysisError, AnalysisStatus, analyze_package_types,
    analyze_package_types_with_artifact_limits,
};
use gantry::frontend::{CompletedSyntaxPhase, validate_package_syntax};
use gantry::ir::ArtifactLimits;
use gantry::source::SourceLimits;
use serde::Deserialize;

const WORKFLOW_EVIDENCE: &str = "crates/gantry-conformance/tests/analyzer_workflow_facts.rs#public_workflow_effect_schema_and_inventory_contracts";
const OWNERSHIP_EVIDENCE: &str = "crates/gantry-conformance/tests/analyzer_workflow_facts.rs#public_task_ownership_contracts_are_path_sensitive";

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

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
    evidence: String,
}

#[derive(Debug, Deserialize)]
struct RequirementReview {
    specification_sha256: String,
    requirements: Vec<Requirement>,
}

#[derive(Debug, Deserialize)]
struct Requirement {
    id: String,
    clauses: Vec<ReviewedClause>,
}

#[derive(Debug, Deserialize)]
struct ReviewedClause {
    key: String,
    profile_reviews: Vec<ProfileReview>,
}

#[derive(Debug, Deserialize)]
struct ProfileReview {
    profile: String,
    state: String,
    evidence: Vec<String>,
}

struct TempDirectory(PathBuf);

impl TempDirectory {
    fn new() -> Self {
        let suffix = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "gantry-analyzer-workflow-conformance-{}-{suffix}",
            std::process::id()
        ));
        fs::create_dir(&path)
            .unwrap_or_else(|error| panic!("could not create {}: {error}", path.display()));
        Self(path)
    }

    fn write(&self, source: &str) {
        let path = self.0.join("main.gnt");
        fs::write(&path, source)
            .unwrap_or_else(|error| panic!("could not write {}: {error}", path.display()));
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn reviewed_analyzer_workflow_evidence_is_closed() {
    let root = workspace_root();
    let manifest: EvidenceManifest =
        read_json(&root.join("protocol/conformance/analyzer-workflows-v1.json"));
    let review: RequirementReview = read_json(&root.join("protocol/requirements/reviewed-v1.json"));

    assert_eq!(manifest.format, "gantry.analyzer-workflow-evidence/v1");
    assert_eq!(manifest.issue, "GNT-AN-004");
    let evidence_is_current = manifest.specification_sha256 == review.specification_sha256;
    assert!(gantry_conformance::evidence_revision_is_expected(
        &manifest.specification_sha256,
        &review.specification_sha256,
    ));
    assert!(evidence_is_current || gantry::advertised_profiles().is_empty());
    assert!(manifest.entries.windows(2).all(|pair| pair[0] < pair[1]));

    for entry in manifest.entries {
        assert!(matches!(
            entry.evidence.as_str(),
            WORKFLOW_EVIDENCE | OWNERSHIP_EVIDENCE
        ));
        if !evidence_is_current {
            continue;
        }
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
        let analyzer = clause
            .profile_reviews
            .iter()
            .find(|profile| profile.profile == "analyzer")
            .unwrap_or_else(|| {
                panic!(
                    "missing analyzer review for {}:{}",
                    entry.requirement, entry.clause
                )
            });
        assert_eq!(analyzer.state, "covered");
        assert_eq!(analyzer.evidence, [entry.evidence]);
    }
}

#[test]
fn public_workflow_effect_schema_and_inventory_contracts() {
    let source = r#"
action read_only inspect(value: Int) -> String;
struct Worker { value: Int, note: Option<String> = "fallback" }
impl Worker {
    fn leaf(self) -> String { action inspect(self.value) }
    fn wrapper(self) -> String { self.leaf() }
}
fn controls(flag: Bool) -> String {
    spawn consumed -> Int { 1 }
    spawn selected -> String { "selected" }
    if flag { discard join(consumed); } else { detach(consumed); }
    joinall()
}
fn main(worker: Worker) -> Worker {
    discard worker.wrapper();
    discard controls(true);
    worker
}
"#;
    let package = analyze(source);
    assert_eq!(
        package.status(),
        AnalysisStatus::Valid,
        "{:?}",
        package.diagnostics()
    );

    let main = package
        .workflows()
        .iter()
        .find(|workflow| workflow.path.as_str() == "crate::main")
        .unwrap_or_else(|| unreachable!("main workflow is present"));
    assert_eq!(
        main.effects
            .iter()
            .map(|effect| effect.wire_name())
            .collect::<Vec<_>>(),
        ["action(read_only)", "spawn", "join", "background"]
    );
    assert_eq!(
        main.action_contributors
            .iter()
            .map(|contributor| (
                contributor.site.workflow().as_str(),
                contributor.action.as_str(),
                contributor.recovery.wire_name(),
            ))
            .collect::<Vec<_>>(),
        [("<crate::Worker>::leaf", "crate::inspect", "read_only")]
    );

    let controls = package
        .workflows()
        .iter()
        .find(|workflow| workflow.path.as_str() == "crate::controls")
        .unwrap_or_else(|| unreachable!("controls workflow is present"));
    let joinall = controls
        .task_controls
        .iter()
        .find(|site| site.kind.wire_name() == "joinall")
        .unwrap_or_else(|| unreachable!("joinall site is present"));
    assert_eq!(
        joinall
            .handles
            .iter()
            .map(AsRef::as_ref)
            .collect::<Vec<_>>(),
        ["selected"]
    );

    assert_eq!(
        package
            .actions()
            .iter()
            .map(|action| (action.path.as_str(), action.signature.as_str()))
            .collect::<Vec<_>>(),
        [(
            "crate::inspect",
            "action[read_only] crate::inspect(value:Int)->String"
        )]
    );
    let entry = package
        .entry()
        .unwrap_or_else(|| unreachable!("entry inventory is present"));
    assert_eq!(entry.path.as_str(), "crate::main");
    assert_eq!(
        entry.parameter.as_ref().map(|ty| ty.canonical_string()),
        Some("crate::Worker".to_owned())
    );
    assert_eq!(entry.result.canonical_string(), "crate::Worker");

    let schemas = package
        .schemas()
        .unwrap_or_else(|| unreachable!("generated schemas are present"));
    assert_eq!(
        schemas
            .entries()
            .iter()
            .map(|(ty, _)| ty.canonical_string())
            .collect::<Vec<_>>(),
        ["String", "crate::Worker"]
    );
    let worker_schema = schemas
        .entries()
        .iter()
        .find(|(ty, _)| ty.canonical_string() == "crate::Worker")
        .map(|(_, schema)| schema)
        .unwrap_or_else(|| unreachable!("worker schema is present"));
    let worker_schema = std::str::from_utf8(worker_schema)
        .unwrap_or_else(|_| unreachable!("generated schema is UTF-8"));
    assert!(worker_schema.contains("\"default\":\"fallback\""));
    assert!(worker_schema.contains("https://json-schema.org/draft/2020-12/schema"));

    let phase = syntax(source);
    let limited = analyze_package_types_with_artifact_limits(
        &phase,
        ArtifactLimits {
            generated_schema_bytes: 1,
            ..ArtifactLimits::MAXIMUM
        },
    );
    assert!(matches!(limited, Err(AnalysisError::ResourceLimit { .. })));
}

#[test]
fn public_task_ownership_contracts_are_path_sensitive() {
    let invalid = analyze(
        r#"
fn leaked(flag: Bool) {
    spawn task { return; }
    if flag { return; }
    discard join(task);
}
fn repeated() {
    spawn task { return; }
    discard join(task);
    detach(task);
}
fn foreign(flag: Bool) {
    spawn parent { return; }
    if flag {
        spawn child { discard join(parent); }
        discard join(child);
    }
    discard join(parent);
}
fn loop_paths(flags: List<Bool>) {
    for flag in flags {
        spawn loop_task { return; }
        if flag { continue; }
        discard join(loop_task);
    }
}
fn main() {}
"#,
    );
    assert_eq!(invalid.status(), AnalysisStatus::Invalid);
    let codes = invalid
        .diagnostics()
        .iter()
        .map(|diagnostic| diagnostic.code.as_str())
        .collect::<Vec<_>>();
    assert!(codes.contains(&"unconsumed-task-handle"), "{codes:?}");
    assert!(codes.contains(&"consumed-task-handle"), "{codes:?}");
    assert!(codes.contains(&"foreign-task-handle"), "{codes:?}");
}

fn analyze(source: &str) -> gantry::analysis::TypedPackage {
    let phase = syntax(source);
    analyze_package_types(&phase)
        .unwrap_or_else(|error| panic!("analysis failed operationally: {error:?}"))
}

fn syntax(source: &str) -> CompletedSyntaxPhase {
    let root = TempDirectory::new();
    root.write(source);
    validate_package_syntax(&root.0, limits())
        .unwrap_or_else(|error| panic!("syntax phase failed: {error:?}"))
}

fn limits() -> SourceLimits {
    SourceLimits::new(4, 65_536, 65_536, 65_536, 64)
        .unwrap_or_else(|_| unreachable!("positive limits"))
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> T {
    let bytes =
        fs::read(path).unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|error| panic!("could not decode {}: {error}", path.display()))
}
