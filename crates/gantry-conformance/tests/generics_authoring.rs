//! Machine-checked source-author documentation for generics and static traits.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use gantry::analysis::{AnalysisStatus, TypedPackage, analyze_package_types};
use gantry::frontend::validate_package_syntax;
use gantry::identity::ProtocolIdentity;
use gantry::portable::IdentityKind;
use gantry::runtime::{Machine, MachineLimits, MachineOutcome, MachineStep};
use gantry::schema::SchemaValidator;
use gantry::source::{FrontendLimits, SourceLimits, SourceSpan};
use gantry::strict_json::{JsonLimits, StrictJsonDocument};
use gantry::value::{DEFAULT_VALUE_LIMITS, LogicalValueView};
use serde::Deserialize;

const EVIDENCE_PATH: &str = "protocol/conformance/generics-traits-authoring-v1.json";
const VECTOR_PATH: &str = "protocol/goldens/generics-traits-authoring-v1.json";
const SCHEMA_PATH: &str = "protocol/schemas/generics-traits-authoring-v1.schema.json";

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TempDirectory(PathBuf);

impl TempDirectory {
    fn new(source: &str) -> Self {
        let suffix = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "gantry-generics-authoring-{}-{suffix}",
            std::process::id()
        ));
        fs::create_dir(&path)
            .unwrap_or_else(|error| panic!("could not create {}: {error}", path.display()));
        fs::write(path.join("main.gnt"), source)
            .unwrap_or_else(|error| panic!("could not write authoring fixture: {error}"));
        Self(path)
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DocumentedFrontendLimits {
    maximum_package_files: u64,
    maximum_source_file_bytes: u64,
    maximum_package_source_bytes: u64,
    maximum_source_tokens: u64,
    maximum_diagnostics_per_activity: u64,
    maximum_package_source_manifest_bytes: u64,
    maximum_canonical_ir_bytes: u64,
    maximum_source_map_bytes: u64,
    maximum_generated_schema_bytes: u64,
    maximum_constructed_type_depth: u64,
    maximum_generic_instantiations_per_activity: u64,
    maximum_trait_resolution_steps_per_activity: u64,
}

#[derive(Debug, Deserialize)]
struct AuthoringEvidenceManifest {
    format: String,
    specification_sha256: String,
    issue: String,
    capabilities: Vec<AuthoringCapability>,
    profiles: Vec<String>,
    advertises_profiles: Vec<String>,
    exclusions: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
struct AuthoringCapability {
    id: String,
    evidence: String,
}

#[derive(Debug, Deserialize)]
struct AuthoringVectors {
    format: String,
    guide: String,
    complete_package: String,
    invalid_packages: Vec<InvalidPackageVector>,
    frontend_policy: FrontendPolicyVector,
    section14_excerpts: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
struct InvalidPackageVector {
    path: String,
    code: String,
    primary_start: u64,
    primary_end: u64,
    required_fields: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct FrontendPolicyVector {
    path: String,
    fields: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Section14Review {
    excerpts: Vec<Section14Excerpt>,
}

#[derive(Debug, Deserialize)]
struct Section14Excerpt {
    key: String,
    classification: String,
    state: String,
    evidence: Vec<String>,
}

#[test]
fn checked_in_generics_authoring_evidence_is_current() {
    let root = workspace_root();
    let manifest: AuthoringEvidenceManifest = read_json(&root.join(EVIDENCE_PATH));
    let vectors: AuthoringVectors = read_json(&root.join(VECTOR_PATH));
    assert_eq!(
        manifest.format,
        "gantry.generics-traits-authoring-evidence/v1"
    );
    assert!(gantry_conformance::evidence_revision_is_expected(
        &manifest.specification_sha256,
        gantry::PROFILE_SPECIFICATION_REVISION,
    ));
    assert_eq!(manifest.issue, "GNT-GEN-DOC-001");
    assert!(
        manifest
            .capabilities
            .windows(2)
            .all(|pair| pair[0] < pair[1])
    );
    assert_eq!(manifest.capabilities.len(), 6);
    assert!(manifest.profiles.is_empty());
    assert!(manifest.advertises_profiles.is_empty());
    assert_eq!(manifest.exclusions.len(), 3);
    assert_eq!(
        gantry::advertises_any_profile(),
        manifest.specification_sha256 == gantry::PROFILE_SPECIFICATION_REVISION
    );
    for capability in &manifest.capabilities {
        assert!(!capability.id.is_empty());
        assert_anchor_exists(&root, &capability.evidence);
    }

    let vector_bytes = fs::read(root.join(VECTOR_PATH))
        .unwrap_or_else(|error| panic!("could not read authoring vectors: {error}"));
    let schema_bytes = fs::read(root.join(SCHEMA_PATH))
        .unwrap_or_else(|error| panic!("could not read authoring schema: {error}"));
    let json_limits = JsonLimits {
        maximum_bytes: 1_048_576,
        maximum_nesting_depth: 32,
        maximum_nodes: 8_192,
        maximum_string_scalars: 1_048_576,
        maximum_list_items: 8_192,
    };
    let document = StrictJsonDocument::decode(vector_bytes.as_slice(), json_limits)
        .unwrap_or_else(|error| panic!("authoring vectors are not strict JSON: {error:?}"));
    let validator = SchemaValidator::compile(Arc::<[u8]>::from(schema_bytes), json_limits)
        .unwrap_or_else(|error| panic!("authoring schema failed to compile: {error:?}"));
    validator
        .normalize(&document, json_limits)
        .unwrap_or_else(|error| panic!("authoring vectors failed their schema: {error:?}"));

    assert_eq!(vectors.format, "gantry.generics-traits-authoring-v1");
    assert_eq!(vectors.guide, "docs/generics-and-traits.md");
    assert_eq!(
        vectors.complete_package,
        "examples/generics-and-traits/main.gnt"
    );
    assert_eq!(vectors.invalid_packages.len(), 4);
    assert!(
        vectors
            .invalid_packages
            .windows(2)
            .all(|pair| pair[0] < pair[1])
    );
    for invalid in &vectors.invalid_packages {
        assert!(root.join(&invalid.path).is_file(), "{}", invalid.path);
        assert!(!invalid.code.is_empty());
        assert!(invalid.primary_start < invalid.primary_end);
        assert!(
            invalid
                .required_fields
                .windows(2)
                .all(|pair| pair[0] < pair[1])
        );
    }
    assert_eq!(
        vectors.frontend_policy.path,
        "examples/frontend-limits.json"
    );
    assert_eq!(vectors.frontend_policy.fields.len(), 12);
    assert!(
        vectors
            .frontend_policy
            .fields
            .windows(2)
            .all(|pair| pair[0] < pair[1])
    );
    assert_eq!(
        vectors.section14_excerpts,
        ["section14-excerpt-050", "section14-excerpt-051"]
    );
}

#[test]
fn complete_generics_authoring_package_executes_with_closed_static_calls() {
    let package = analyze_path(&workspace_root().join("examples/generics-and-traits"));
    assert_eq!(
        package.status(),
        AnalysisStatus::Valid,
        "{:?}",
        package.diagnostics()
    );
    let entry = package
        .entry()
        .unwrap_or_else(|| panic!("authoring package omitted its entry"));
    let program = package
        .executable_program()
        .cloned()
        .unwrap_or_else(|| panic!("authoring package omitted its executable projection"));
    assert!(
        program
            .callable_identities()
            .iter()
            .all(|identity| !identity.as_str().contains('^'))
    );
    assert!(program.callable_identities().iter().any(|identity| {
        identity.as_str() == "<crate::Envelope<crate::Report> as crate::Summarize>::summarize"
    }));

    let execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x75; 32])
        .unwrap_or_else(|error| panic!("execution identity failed: {error}"));
    let mut machine = Machine::new(
        Arc::new(program),
        &entry.path,
        Vec::new(),
        execution,
        machine_limits(),
    )
    .unwrap_or_else(|error| panic!("authoring package machine failed: {error:?}"));
    assert!(matches!(
        drive(&mut machine),
        MachineOutcome::Succeeded(ref value)
            if matches!(value.view(), LogicalValueView::String("envelope"))
    ));
}

#[test]
fn invalid_generics_authoring_packages_expose_exact_structured_diagnostics() {
    let root = workspace_root().join("examples/generics-and-traits-invalid");
    let cases = [
        ("incomplete-inference", "incomplete-type-inference", 62, 74),
        ("cyclic-obligation", "cyclic-trait-obligation", 476, 481),
        ("duplicate-parameter", "duplicate-type-parameter", 15, 16),
        ("polymorphic-recursion", "polymorphic-recursion", 19, 23),
    ];
    for (directory, code, start, end) in cases {
        let package = analyze_path(&root.join(directory));
        assert_eq!(package.status(), AnalysisStatus::Invalid, "{directory}");
        let diagnostic = package
            .diagnostics()
            .iter()
            .find(|diagnostic| diagnostic.code.as_str() == code)
            .unwrap_or_else(|| panic!("{directory} omitted {code}: {:?}", package.diagnostics()));
        assert_span(diagnostic.primary.as_ref(), start, end);
        match directory {
            "cyclic-obligation" => {
                assert_eq!(
                    diagnostic.fields.get("obligation").map(AsRef::as_ref),
                    Some("crate::First<crate::Item> for crate::Envelope<crate::Item>")
                );
                assert_eq!(
                    diagnostic.fields.get("obligation_chain").map(AsRef::as_ref),
                    Some(
                        "crate::First<crate::Item> for crate::Envelope<crate::Item> -> crate::Second<crate::Envelope<crate::Item>> for crate::Item -> crate::First<crate::Item> for crate::Envelope<crate::Item>"
                    )
                );
            }
            "duplicate-parameter" => {
                assert_eq!(
                    diagnostic.fields.get("parameter").map(AsRef::as_ref),
                    Some("T")
                );
                assert_eq!(diagnostic.related.len(), 1);
                assert_eq!(diagnostic.related[0].label.as_ref(), "first declaration");
                assert_span(Some(&diagnostic.related[0].span), 12, 13);
            }
            "polymorphic-recursion" => assert_eq!(
                diagnostic
                    .fields
                    .get("instantiation_witness")
                    .map(AsRef::as_ref),
                Some("crate::grow<^0.0> => [String] -> crate::grow<^0.0> => [List<String>]")
            ),
            _ => assert!(diagnostic.fields.is_empty()),
        }
    }
}

#[test]
fn documented_frontend_policy_round_trips_all_twelve_fields() {
    let root = workspace_root();
    let documented: DocumentedFrontendLimits =
        read_json(&root.join("examples/frontend-limits.json"));
    let limits = FrontendLimits::new(
        documented.maximum_package_files,
        documented.maximum_source_file_bytes,
        documented.maximum_package_source_bytes,
        documented.maximum_source_tokens,
        documented.maximum_diagnostics_per_activity,
        documented.maximum_package_source_manifest_bytes,
        documented.maximum_canonical_ir_bytes,
        documented.maximum_source_map_bytes,
        documented.maximum_generated_schema_bytes,
        documented.maximum_constructed_type_depth,
        documented.maximum_generic_instantiations_per_activity,
        documented.maximum_trait_resolution_steps_per_activity,
    )
    .unwrap_or_else(|error| panic!("documented frontend policy failed: {error:?}"));
    assert_eq!(limits.maximum_package_files(), 4_096);
    assert_eq!(limits.maximum_source_file_bytes(), 16_777_216);
    assert_eq!(limits.maximum_package_source_bytes(), 268_435_456);
    assert_eq!(limits.maximum_source_tokens(), 4_194_304);
    assert_eq!(limits.maximum_diagnostics_per_activity(), 4_096);
    assert_eq!(limits.maximum_package_source_manifest_bytes(), 268_435_456);
    assert_eq!(limits.maximum_canonical_ir_bytes(), 268_435_456);
    assert_eq!(limits.maximum_source_map_bytes(), 268_435_456);
    assert_eq!(limits.maximum_generated_schema_bytes(), 268_435_456);
    assert_eq!(limits.maximum_constructed_type_depth(), 256);
    assert_eq!(limits.maximum_generic_instantiations_per_activity(), 65_536);
    assert_eq!(
        limits.maximum_trait_resolution_steps_per_activity(),
        1_000_000
    );
}

#[test]
fn generics_guide_source_excerpts_are_analyzable_and_indexed() {
    let root = workspace_root();
    let guide = fs::read_to_string(root.join("docs/generics-and-traits.md"))
        .unwrap_or_else(|error| panic!("could not read generics guide: {error}"));
    let blocks = fenced_blocks(&guide, "rust");
    assert_eq!(blocks.len(), 8);
    let fixtures = [
        format!("{}\nfn main() {{}}\n", blocks[0]),
        format!(
            "struct Envelope<T> {{ value: T }}\nenum Outcome<T, E> {{ Ready(T), Failed(E) }}\nfn main() {{\n{}\n}}\n",
            blocks[1]
        ),
        format!(
            "enum Outcome<T, E> {{ Ready(T), Failed(E) }}\nfn main(result: Outcome<String, String>) -> String {{\n{}\n}}\n",
            blocks[2]
        ),
        format!("{}\nfn main() {{ discard preserve(1); }}\n", blocks[3]),
        format!(
            "pure fn preserve<T>(value: T) -> T {{ value }}\nfn main() {{\n{}\n}}\n",
            blocks[4]
        ),
        format!("{}\nfn main() {{}}\n", blocks[5]),
        format!(
            "struct Envelope<T> {{ value: T }}\ntrait Summarize {{ pure fn summarize(self) -> String; }}\n{}\nfn main() {{}}\n",
            blocks[6]
        ),
        format!(
            "struct Report {{ summary: String }}\ntrait Summarize {{ pure fn summarize(self) -> String; }}\nimpl Summarize for Report {{ pure fn summarize(self) -> String {{ self.summary }} }}\npure fn helper(value: Report) -> String {{ {} }}\nfn main() {{ discard helper(Report {{ summary: \"ready\" }}); }}\n",
            blocks[7]
        ),
    ];
    for (index, source) in fixtures.iter().enumerate() {
        let temporary = TempDirectory::new(source);
        let package = analyze_path(&temporary.0);
        assert_eq!(
            package.status(),
            AnalysisStatus::Valid,
            "guide block {}: {:?}\n{source}",
            index + 1,
            package.diagnostics()
        );
    }

    let readme = fs::read_to_string(root.join("README.md"))
        .unwrap_or_else(|error| panic!("could not read README: {error}"));
    let readme_blocks = fenced_blocks(&readme, "rust");
    let generic_example = readme_blocks
        .first()
        .unwrap_or_else(|| panic!("README omitted its generic example"));
    let temporary = TempDirectory::new(generic_example);
    let package = analyze_path(&temporary.0);
    assert_eq!(
        package.status(),
        AnalysisStatus::Valid,
        "README generic example: {:?}",
        package.diagnostics()
    );

    for path in ["README.md", "docs/README.md", "protocol/README.md"] {
        let index = fs::read_to_string(root.join(path))
            .unwrap_or_else(|error| panic!("could not read {path}: {error}"));
        assert!(index.contains("generics-and-traits.md"), "{path}");
    }
    for referenced in [
        "examples/generics-and-traits/main.gnt",
        "examples/generics-and-traits-invalid/cyclic-obligation/main.gnt",
        "examples/generics-and-traits-invalid/duplicate-parameter/main.gnt",
        "examples/generics-and-traits-invalid/incomplete-inference/main.gnt",
        "examples/generics-and-traits-invalid/polymorphic-recursion/main.gnt",
        "examples/frontend-limits.json",
    ] {
        assert!(root.join(referenced).is_file(), "{referenced}");
    }
}

#[test]
fn generic_section14_excerpts_remain_classified_and_executable() {
    let root = workspace_root();
    let review: Section14Review = read_json(&root.join("protocol/requirements/section14-v1.json"));
    for key in ["section14-excerpt-050", "section14-excerpt-051"] {
        let excerpt = review
            .excerpts
            .iter()
            .find(|excerpt| excerpt.key == key)
            .unwrap_or_else(|| panic!("missing {key}"));
        assert!(matches!(
            excerpt.classification.as_str(),
            "complete-positive" | "focused-fragment"
        ));
        assert_eq!(excerpt.state, "covered");
        assert_eq!(
            excerpt.evidence,
            [
                "crates/gantry-conformance/tests/frontend_parser_evidence.rs#section14_excerpts_have_executable_syntax_fixtures"
            ]
        );
    }
}

fn analyze_path(root: &Path) -> TypedPackage {
    let syntax = validate_package_syntax(
        root,
        SourceLimits::new(32, 1_048_576, 4_194_304, 262_144, 256)
            .unwrap_or_else(|_| unreachable!("positive fixture limits")),
        256,
    )
    .unwrap_or_else(|error| panic!("syntax failed for {}: {error}", root.display()));
    analyze_package_types(&syntax)
        .unwrap_or_else(|error| panic!("analysis failed for {}: {error:?}", root.display()))
}

fn assert_span(span: Option<&SourceSpan>, start: u64, end: u64) {
    let span = span.unwrap_or_else(|| panic!("diagnostic omitted its primary span"));
    assert_eq!(span.source().package_path().as_str(), "main.gnt");
    assert_eq!((span.bytes().start(), span.bytes().end()), (start, end));
}

fn machine_limits() -> MachineLimits {
    MachineLimits::new(10_000, 100, 100, 64, 100, DEFAULT_VALUE_LIMITS)
        .unwrap_or_else(|| unreachable!("positive machine limits"))
}

fn drive(machine: &mut Machine) -> MachineOutcome {
    for _ in 0..10_000 {
        match machine.step() {
            MachineStep::Transition(_) => {}
            MachineStep::YieldRequired => assert!(machine.resume_after_yield()),
            MachineStep::Complete(outcome) => return outcome,
            MachineStep::WaitingSessionScope(scope) => {
                panic!("authoring fixture requested a session scope: {scope:?}")
            }
            MachineStep::WaitingOperation(operation) => {
                panic!("authoring fixture requested an operation: {operation:?}")
            }
        }
    }
    panic!("authoring fixture did not settle within the test bound")
}

fn fenced_blocks<'a>(markdown: &'a str, language: &str) -> Vec<&'a str> {
    let opening = format!("```{language}\n");
    markdown
        .split(&opening)
        .skip(1)
        .map(|tail| {
            tail.split_once("\n```")
                .map(|(block, _)| block)
                .unwrap_or_else(|| panic!("unterminated {language} block"))
        })
        .collect()
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| unreachable!("conformance crate has a workspace root"))
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> T {
    let bytes =
        fs::read(path).unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|error| panic!("could not decode {}: {error}", path.display()))
}

fn assert_anchor_exists(root: &Path, evidence: &str) {
    let (path, anchor) = evidence
        .split_once('#')
        .unwrap_or_else(|| panic!("evidence has no anchor: {evidence}"));
    let source = fs::read_to_string(root.join(path))
        .unwrap_or_else(|error| panic!("could not read evidence {path}: {error}"));
    assert!(
        source.contains(&format!("fn {anchor}")),
        "missing evidence anchor {evidence}"
    );
}
