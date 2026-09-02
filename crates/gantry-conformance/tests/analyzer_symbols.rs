//! Public-facade conformance for module, symbol, and identifier analysis.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use gantry::analysis::{AnalysisStatus, analyze_package_structure};
use gantry::frontend::validate_package_syntax;
use gantry::source::SourceLimits;
use serde::Deserialize;

const MODULE_EVIDENCE: &str = "crates/gantry-conformance/tests/analyzer_symbols.rs#public_module_graph_symbols_and_resolution_are_canonical";
const SECURITY_EVIDENCE: &str = "crates/gantry-conformance/tests/analyzer_symbols.rs#public_no_shadowing_and_identifier_security_are_source_backed";

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
            "gantry-analyzer-conformance-{}-{suffix}",
            std::process::id()
        ));
        fs::create_dir(&path)
            .unwrap_or_else(|error| panic!("could not create {}: {error}", path.display()));
        Self(path)
    }

    fn write(&self, path: &str, source: &str) {
        let path = self.0.join(path);
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
fn reviewed_analyzer_symbol_evidence_is_closed() {
    let root = workspace_root();
    let manifest: EvidenceManifest =
        read_json(&root.join("protocol/conformance/analyzer-symbols-v1.json"));
    let review: RequirementReview = read_json(&root.join("protocol/requirements/reviewed-v1.json"));

    assert_eq!(manifest.format, "gantry.analyzer-symbol-evidence/v1");
    assert_eq!(manifest.issue, "GNT-AN-002");
    assert!(gantry_conformance::evidence_revision_is_expected(
        &manifest.specification_sha256,
        &review.specification_sha256,
    ));
    assert!(manifest.entries.windows(2).all(|pair| pair[0] < pair[1]));

    for entry in manifest.entries {
        assert!(matches!(
            entry.evidence.as_str(),
            MODULE_EVIDENCE | SECURITY_EVIDENCE
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
        assert!(analyzer.evidence.contains(&entry.evidence));
    }
}

#[test]
fn public_module_graph_symbols_and_resolution_are_canonical() {
    fn analyze(root_items: &str) -> (Vec<String>, Vec<String>, Vec<String>) {
        let root = TempDirectory::new();
        root.write(
            "main.gnt",
            &format!(
                "agents {{ researcher }}\ndefault agent = researcher;\n{root_items}\nuse a::Thing;\nfn main(value: Thing) {{ z::consume(value); with researcher {{}} }}"
            ),
        );
        root.write("a.gnt", "struct Thing {}");
        root.write("z.gnt", "use crate::a::Thing; fn consume(value: Thing) {}");
        let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
            .unwrap_or_else(|error| panic!("syntax phase failed: {error:?}"));
        let analysis = analyze_package_structure(&syntax)
            .unwrap_or_else(|error| panic!("analysis failed: {error:?}"));
        assert_eq!(analysis.status(), AnalysisStatus::Valid);
        (
            analysis
                .modules()
                .iter()
                .map(|module| module.path.to_string())
                .collect(),
            analysis
                .symbols()
                .iter()
                .map(|symbol| symbol.path.to_string())
                .collect(),
            analysis
                .references()
                .iter()
                .map(|reference| reference.canonical_path.to_string())
                .collect(),
        )
    }

    let first = analyze("mod z; mod a; mod nested { struct Local {} }");
    let second = analyze("mod nested { struct Local {} } mod a; mod z;");
    assert_eq!(first, second);
    assert_eq!(first.0, ["crate", "crate::a", "crate::nested", "crate::z"]);
    assert!(first.1.windows(2).all(|pair| pair[0] < pair[1]));
    assert!(first.2.contains(&"crate::a::Thing".to_owned()));
    assert!(first.2.contains(&"crate::z::consume".to_owned()));

    let missing = TempDirectory::new();
    missing.write("main.gnt", "mod absent; fn main() {}");
    let syntax = validate_package_syntax(&missing.0, limits(), i64::MAX as u64)
        .unwrap_or_else(|error| panic!("syntax phase failed: {error:?}"));
    let analysis = analyze_package_structure(&syntax)
        .unwrap_or_else(|error| panic!("analysis failed: {error:?}"));
    assert_eq!(analysis.status(), AnalysisStatus::Invalid);
    assert!(
        analysis
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code.as_str() == "missing-module-source")
    );
}

#[test]
fn public_no_shadowing_and_identifier_security_are_source_backed() {
    let root = TempDirectory::new();
    root.write(
        "main.gnt",
        r#"
struct paypal {}
struct раypal {}
struct Report { revise: String }
impl Report { fn revise(self) {} }
fn main(Report: String) {
    let (item, item): Tuple<Int, Int> = (1, 2);
    missing;
}
"#,
    );
    let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
        .unwrap_or_else(|error| panic!("syntax phase failed: {error:?}"));
    let analysis = analyze_package_structure(&syntax)
        .unwrap_or_else(|error| panic!("analysis failed: {error:?}"));
    assert_eq!(analysis.status(), AnalysisStatus::Invalid);

    let codes = analysis
        .diagnostics()
        .iter()
        .map(|diagnostic| diagnostic.code.as_str())
        .collect::<Vec<_>>();
    assert!(codes.contains(&"duplicate-member"));
    assert!(codes.contains(&"shadowed-name"));
    assert!(codes.contains(&"unresolved-reference"));
    assert!(codes.contains(&"identifier-confusable-collision"));
    assert!(codes.contains(&"identifier-script-warning"));
    assert!(analysis.diagnostics().iter().all(|diagnostic| {
        diagnostic.phase.wire_name() == "analysis"
            && diagnostic.primary.is_some()
            && diagnostic.fields.keys().all(|key| !key.is_empty())
    }));
}

fn limits() -> SourceLimits {
    SourceLimits::new(16, 16_384, 65_536, 16_384, 64)
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
