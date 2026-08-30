//! Public-facade conformance for canonical lowering and analyzer artifacts.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use gantry::analysis::{
    AnalysisError, AnalysisStatus, TypedPackage, analyze_package_types,
    analyze_package_types_with_artifact_limits,
};
use gantry::frontend::{CompletedSyntaxPhase, validate_package_syntax};
use gantry::ir::ArtifactLimits;
use gantry::portable::FrontendResourceCode;
use gantry::source::SourceLimits;
use serde::Deserialize;

const LOWERING_EVIDENCE: &str = "crates/gantry-conformance/tests/analyzer_lowering.rs#public_canonical_lowering_preserves_sites_phases_and_identity";
const LIMIT_EVIDENCE: &str = "crates/gantry-conformance/tests/analyzer_lowering.rs#public_lowering_artifacts_enforce_exact_limits_and_invalid_boundaries";

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
            "gantry-analyzer-lowering-conformance-{}-{suffix}",
            std::process::id()
        ));
        fs::create_dir(&path)
            .unwrap_or_else(|error| panic!("could not create {}: {error}", path.display()));
        Self(path)
    }

    fn write(&self, relative: &str, source: &str) {
        let path = self.0.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .unwrap_or_else(|error| panic!("could not create {}: {error}", parent.display()));
        }
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
fn reviewed_analyzer_lowering_evidence_is_closed() {
    let root = workspace_root();
    let manifest: EvidenceManifest =
        read_json(&root.join("protocol/conformance/analyzer-lowering-v1.json"));
    let review: RequirementReview = read_json(&root.join("protocol/requirements/reviewed-v1.json"));

    assert_eq!(manifest.format, "gantry.analyzer-lowering-evidence/v1");
    assert_eq!(manifest.issue, "GNT-AN-005");
    assert_eq!(manifest.specification_sha256, review.specification_sha256);
    assert!(manifest.entries.windows(2).all(|pair| pair[0] < pair[1]));

    for entry in manifest.entries {
        assert!(matches!(
            entry.evidence.as_str(),
            LOWERING_EVIDENCE | LIMIT_EVIDENCE
        ));
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
fn public_canonical_lowering_preserves_sites_phases_and_identity() {
    let source = r#"
agents { worker }
default agent = worker;
action read_only inspect(value: Int) -> String;
struct Holder { item: Int }
fn helper(value: Int) -> Int { return value; }
fn main(flag: Bool) -> Int {
    let mut value: Int = 1;
    let holder: Holder = Holder { item: value };
    value = holder.item;
    value = helper(value);
    if flag { value = 2; } else { value = 3; }
    loop(limit = 1) { break; }
    with worker { session(inline) { discard attempt action inspect(value); } }
    spawn joined -> Int { value }
    value = join(joined);
    spawn background { return; }
    detach(background);
    discard prompt "${value}" using { chosen: value } -> String;
    value
}
"#;
    let package = analyze(source);
    assert_eq!(
        package.status(),
        AnalysisStatus::Valid,
        "{:?}",
        package.diagnostics()
    );

    let manifest = package
        .manifest()
        .unwrap_or_else(|| unreachable!("valid package has a manifest"));
    let ir = package
        .canonical_ir()
        .unwrap_or_else(|| unreachable!("valid package has canonical IR"));
    let source_map = package
        .source_map()
        .unwrap_or_else(|| unreachable!("valid package has a source map"));
    assert_eq!(manifest.artifact().sha256_hex().len(), 64);
    assert_eq!(ir.artifact().sha256_hex().len(), 64);
    assert_eq!(source_map.artifact().sha256_hex().len(), 64);
    assert_eq!(
        source_map.entries().len(),
        ir.workflows()
            .iter()
            .map(|workflow| workflow.nodes.len())
            .sum::<usize>()
    );

    for facts in package.workflows() {
        let workflow = ir
            .workflows()
            .iter()
            .find(|workflow| workflow.path == facts.path)
            .unwrap_or_else(|| unreachable!("workflow facts have canonical IR"));
        assert!(
            workflow
                .nodes
                .windows(2)
                .all(|pair| pair[0].position < pair[1].position)
        );
        assert_eq!(
            workflow
                .nodes
                .iter()
                .filter_map(|node| node.operation.as_ref().map(|_| node.position.clone()))
                .collect::<Vec<_>>(),
            facts
                .operations
                .iter()
                .map(|operation| operation.id.position().clone())
                .collect::<Vec<_>>()
        );
    }

    let main = ir
        .workflows()
        .iter()
        .find(|workflow| workflow.path.as_str() == "crate::main")
        .unwrap_or_else(|| unreachable!("main is lowered"));
    let operation_kinds = main
        .nodes
        .iter()
        .filter_map(|node| node.operation.as_ref())
        .map(|operation| operation.kind.wire_name())
        .collect::<Vec<_>>();
    assert_eq!(operation_kinds, ["action", "prompt"]);
    let prompt = main
        .nodes
        .iter()
        .filter_map(|node| node.operation.as_ref())
        .find(|operation| operation.kind.wire_name() == "prompt")
        .unwrap_or_else(|| unreachable!("prompt site is retained"));
    assert_eq!(prompt.template_segments.len(), 2);
    assert_eq!(prompt.interpolation_inputs, [0]);
    assert_eq!(
        prompt
            .named_input_names
            .iter()
            .map(AsRef::as_ref)
            .collect::<Vec<_>>(),
        ["chosen"]
    );
    assert_eq!(prompt.named_inputs.len(), 1);
    assert_eq!(
        main.nodes
            .iter()
            .filter_map(|node| node.task_control.as_ref())
            .map(|site| site.kind.wire_name())
            .collect::<Vec<_>>(),
        ["spawn", "join", "spawn", "detach"]
    );

    let compact = artifacts("fn main() { discard prompt \"x\" -> String; }");
    let cosmetic = artifacts(
        r#"
// Cosmetic bytes affect provenance, not execution identity.
fn main() {
    discard prompt "x" -> String;
}
"#,
    );
    let semantic = artifacts("fn main() { discard prompt \"y\" -> String; }");
    assert_eq!(compact.0, cosmetic.0);
    assert_ne!(compact.1, cosmetic.1);
    assert_ne!(compact.0, semantic.0);

    let statement_count = 2_048;
    let mut deep = String::from("fn main() { let mut value: Int = 0;");
    deep.push_str(&"value = value;".repeat(statement_count));
    deep.push('}');
    let deep = analyze(&deep);
    assert_eq!(deep.status(), AnalysisStatus::Valid);
    assert!(
        deep.canonical_ir()
            .unwrap_or_else(|| unreachable!("deep package is lowered"))
            .workflows()[0]
            .nodes
            .len()
            > statement_count
    );
}

#[test]
fn public_lowering_artifacts_enforce_exact_limits_and_invalid_boundaries() {
    let phase = syntax("fn main() { discard prompt \"bounded\" -> String; }");
    let baseline = analyze_package_types(&phase)
        .unwrap_or_else(|error| panic!("baseline analysis failed: {error:?}"));
    let lengths = [
        (
            baseline
                .manifest()
                .unwrap_or_else(|| unreachable!("manifest is present"))
                .artifact()
                .canonical_bytes()
                .len(),
            FrontendResourceCode::PackageSourceManifestByteLimit,
        ),
        (
            baseline
                .canonical_ir()
                .unwrap_or_else(|| unreachable!("IR is present"))
                .artifact()
                .canonical_bytes()
                .len(),
            FrontendResourceCode::CanonicalIrByteLimit,
        ),
        (
            baseline
                .source_map()
                .unwrap_or_else(|| unreachable!("source map is present"))
                .artifact()
                .canonical_bytes()
                .len(),
            FrontendResourceCode::SourceMapByteLimit,
        ),
    ];

    for (index, (length, code)) in lengths.into_iter().enumerate() {
        let length = u64::try_from(length).unwrap_or_else(|_| unreachable!("length fits"));
        let limits = |limit| {
            let mut limits = ArtifactLimits::MAXIMUM;
            match index {
                0 => limits.package_source_manifest_bytes = limit,
                1 => limits.canonical_ir_bytes = limit,
                2 => limits.source_map_bytes = limit,
                _ => unreachable!("three lowering artifacts"),
            }
            limits
        };
        assert!(analyze_package_types_with_artifact_limits(&phase, limits(length)).is_ok());
        assert!(
            analyze_package_types_with_artifact_limits(&phase, limits(length.saturating_add(1)))
                .is_ok()
        );
        let below =
            analyze_package_types_with_artifact_limits(&phase, limits(length.saturating_sub(1)));
        assert!(matches!(
            below,
            Err(AnalysisError::ResourceLimit { error, diagnostics })
                if error.code == code
                    && error.limit == length.saturating_sub(1)
                    && diagnostics.is_empty()
        ));
    }

    let complete_invalid = analyze("fn main() -> Int { \"wrong\" }");
    assert_eq!(complete_invalid.status(), AnalysisStatus::Invalid);
    assert!(complete_invalid.manifest().is_some());
    assert!(complete_invalid.canonical_ir().is_none());
    assert!(complete_invalid.source_map().is_none());

    let incomplete_root = TempDirectory::new();
    incomplete_root.write("main.gnt", "mod absent; fn main() {}");
    let incomplete_phase = validate_package_syntax(&incomplete_root.0, limits())
        .unwrap_or_else(|error| panic!("syntax failed: {error:?}"));
    let incomplete = analyze_package_types(&incomplete_phase)
        .unwrap_or_else(|error| panic!("analysis failed: {error:?}"));
    assert_eq!(incomplete.status(), AnalysisStatus::Invalid);
    assert!(incomplete.manifest().is_none());
    assert!(incomplete.canonical_ir().is_none());
    assert!(incomplete.source_map().is_none());
}

fn artifacts(source: &str) -> (Vec<u8>, Vec<u8>) {
    let package = analyze(source);
    assert_eq!(
        package.status(),
        AnalysisStatus::Valid,
        "{:?}",
        package.diagnostics()
    );
    (
        package
            .canonical_ir()
            .unwrap_or_else(|| unreachable!("IR is present"))
            .artifact()
            .canonical_bytes()
            .to_vec(),
        package
            .manifest()
            .unwrap_or_else(|| unreachable!("manifest is present"))
            .artifact()
            .canonical_bytes()
            .to_vec(),
    )
}

fn analyze(source: &str) -> TypedPackage {
    let phase = syntax(source);
    analyze_package_types(&phase)
        .unwrap_or_else(|error| panic!("analysis failed operationally: {error:?}"))
}

fn syntax(source: &str) -> CompletedSyntaxPhase {
    let root = TempDirectory::new();
    root.write("main.gnt", source);
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
