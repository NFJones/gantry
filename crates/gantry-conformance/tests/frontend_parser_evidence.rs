//! Requirement-indexed grammar and Section 14 evidence for the frontend parser.

use std::fs;
use std::path::{Path, PathBuf};

use gantry::frontend::Parser;
use gantry::source::{SourceLimits, SourceSnapshotBuilder};
use serde::Deserialize;

const PARSER_EVIDENCE: &str = "crates/gantry-conformance/tests/frontend_parser_evidence.rs#parser_requirement_vectors_cover_reviewed_grammar";
const AUTHORING_EVIDENCE: &str = "crates/gantry-conformance/tests/frontend_parser_evidence.rs#section14_excerpts_have_executable_syntax_fixtures";

#[derive(Debug, Deserialize)]
struct GenericsFrontendEvidenceManifest {
    format: String,
    specification_sha256: String,
    issue: String,
    capabilities: Vec<CapabilityEvidence>,
    exclusions: Vec<String>,
    profiles: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
struct CapabilityEvidence {
    id: String,
    evidence: String,
}

#[derive(Debug, Deserialize)]
struct ParserEvidenceManifest {
    format: String,
    specification_sha256: String,
    issue: String,
    grammar_entries: Vec<GrammarEntry>,
    section14_excerpt_count: usize,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
struct GrammarEntry {
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
    profiles: Vec<String>,
    profile_reviews: Vec<ProfileReview>,
}

#[derive(Debug, Deserialize)]
struct ProfileReview {
    profile: String,
    state: String,
    evidence: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Section14Review {
    specification_sha256: String,
    excerpts: Vec<Section14Excerpt>,
}

#[derive(Debug, Deserialize)]
struct Section14Excerpt {
    key: String,
    start_line: usize,
    end_line: usize,
    classification: String,
    state: String,
    evidence: Vec<String>,
}

#[test]
fn checked_in_generics_frontend_evidence_is_current_and_withdrawn() {
    let root = workspace_root();
    let manifest: GenericsFrontendEvidenceManifest =
        read_json(&root.join("protocol/conformance/generics-traits-frontend-v1.json"));
    let requirements: RequirementReview =
        read_json(&root.join("protocol/requirements/reviewed-v1.json"));

    assert_eq!(
        manifest.format,
        "gantry.generics-traits-frontend-evidence/v1"
    );
    assert_eq!(
        manifest.specification_sha256,
        requirements.specification_sha256
    );
    assert_eq!(manifest.issue, "GNT-GEN-FE-001");
    assert!(manifest.profiles.is_empty());
    assert!(manifest.exclusions.len() >= 3);
    assert!(
        manifest
            .capabilities
            .windows(2)
            .all(|pair| pair[0] < pair[1])
    );
    assert_eq!(
        manifest
            .capabilities
            .iter()
            .map(|entry| entry.evidence.as_str())
            .collect::<Vec<_>>(),
        [
            "crates/gantry-conformance/tests/durable_start.rs#durable_start_and_resume_preserve_acceptance_and_nonmutation_boundaries",
            "crates/gantry-conformance/tests/validate_package.rs#validate_and_analyze_enforce_constructed_type_depth_per_activity",
            "crates/gantry-conformance/tests/parser_frontend.rs#public_parser_supports_parametric_declarations_static_traits_and_generic_paths",
            "crates/gantry-conformance/tests/frontend_lexical_evidence.rs#lexical_requirement_vectors_cover_reviewed_clauses",
            "crates/gantry-conformance/tests/start_execution.rs#constructed_type_depth_rejects_start_before_preflight_or_execution_identity",
        ]
    );
}

#[test]
fn reviewed_frontend_parser_evidence_is_closed() {
    let root = workspace_root();
    let manifest: ParserEvidenceManifest =
        read_json(&root.join("protocol/conformance/frontend-parser-v1.json"));
    let requirements: RequirementReview =
        read_json(&root.join("protocol/requirements/reviewed-v1.json"));
    let section14: Section14Review =
        read_json(&root.join("protocol/requirements/section14-v1.json"));

    assert_eq!(manifest.format, "gantry.frontend-parser-evidence/v1");
    assert_eq!(manifest.issue, "GNT-FE-002");
    assert!(gantry_conformance::evidence_revision_is_expected(
        &manifest.specification_sha256,
        &requirements.specification_sha256,
    ));
    assert_eq!(
        section14.specification_sha256,
        requirements.specification_sha256
    );
    if !gantry::PROFILE_CLAIMS_ENABLED {
        assert_eq!(manifest.section14_excerpt_count, 49);
        assert_eq!(section14.excerpts.len(), 51);
        assert_eq!(
            section14
                .excerpts
                .iter()
                .filter(|excerpt| excerpt.state == "planned")
                .count(),
            0
        );
        for excerpt in &section14.excerpts[49..] {
            assert_eq!(excerpt.state, "covered", "{}", excerpt.key);
            assert_eq!(excerpt.evidence, [AUTHORING_EVIDENCE], "{}", excerpt.key);
        }
        return;
    }
    assert_eq!(manifest.section14_excerpt_count, section14.excerpts.len());
    assert!(
        manifest
            .grammar_entries
            .windows(2)
            .all(|pair| pair[0] < pair[1])
    );

    for entry in &manifest.grammar_entries {
        let clause = requirements
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
        assert!(clause.profiles.iter().any(|profile| profile == "frontend"));
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
            [PARSER_EVIDENCE],
            "{}:{}",
            entry.requirement,
            entry.clause
        );
    }

    for excerpt in &section14.excerpts {
        assert_eq!(excerpt.state, "covered", "{}", excerpt.key);
        assert_eq!(excerpt.evidence, [AUTHORING_EVIDENCE], "{}", excerpt.key);
    }
}

#[test]
fn parser_requirement_vectors_cover_reviewed_grammar() {
    for source in [
        "agents { worker, reviewer, } default agent = worker; mod child; mod nested { use crate::Thing; } struct Thing { value: Int = -1, pair: Tuple<Int, String,>, } enum Choice { One, Two(String), } action read_only inspect(value: Thing) -> Result<String, Thing>; pure fn main(mut value: Thing) -> String { let pair: Tuple<Int, String> = (1, \"two\"); let (number, text): Tuple<Int, String> = pair; value.value += number; if let Some(item) = Some(value) { discard action(retry_limit = 2) inspect(item); } else { return text; } prompt(session = fork, retry_limit = 2) \"${value.value}\" using { value } -> String } impl Thing { fn update(mut self, value: Int) -> Thing { self.value = value; self } }",
        "fn controls(items: List<Int>) { for item in items { discard item; } loop(session = inline, limit = 2) { break; } while(limit = unbounded) true { continue; } until(session = new, limit = 3) { discard joinall(); } when false; spawn child -> Int { 1 } let value: Int = join(child); spawn background { return; } detach(background); match value { _ => { discard value; }, } }",
        "fn expressions(value: Int) -> Int { let list: List<Int> = [1, 2, 3,]; let pair: Tuple<Int, String> = (list[0], \"x\",); let made: Example = Example { value, }; let result: Result<Int, String> = Ok(made.value + pair.0 * 2); match result { Ok(number) => number, Err(_) => { 0 }, } }",
        "struct Envelope<T> where T: Label { value: T } enum State<T, E> { Ready(T), Failed(E) } trait Label { pure fn label(self) -> String; } impl<T> Label for Envelope<T> where T: Label { pure fn label(self) -> String { self.value.label() } } pure fn preserve<T>(value: T) -> T { value } fn main(value: Envelope<String>) { discard preserve::<Envelope<String>>(value); match State::<String, String>::Ready(\"ok\") { State::<String, String>::Ready(item) => { discard item; }, State::<String, String>::Failed(error) => { discard error; }, } }",
        // Identifier normalization and modifier duplication are analyzer-owned:
        // the syntax-only frontend must preserve these parsed forms.
        "fn A\u{301}(value: Int) -> Int { prompt(retry_limit = 1, retry_limit = 2) \"${value}\" -> Int }",
    ] {
        let outcome = parse(source, 2_048, 32);
        assert!(outcome.is_valid(), "{source}: {:?}", outcome.diagnostics());
    }

    for source in [
        "enum Empty {}",
        "fn bad() { let value = 1; }",
        "fn bad() -> Bool { 1 < 2 < 3 }",
        "fn bad() { discard join(); }",
        "fn bad() { discard attempt joinall(); }",
        "fn bad() { if Policy { enabled: true }.enabled {} }",
        "fn bad() { decide \"question\" -> Decision; }",
        "struct Bad { value: Tuple<Int> }",
        "struct Bad { value: Int = -false }",
        "fn bad() { prompt \"${prompt \\\"nested\\\"}\"; }",
        "struct Bad<T { value: T }",
        "fn bad() { discard value::<String>; }",
        "trait Bad { fn missing(self); }",
        "fn bad(value: Self) -> Self { value }",
        "impl Self { pure fn bad(self) {} }",
    ] {
        let outcome = parse(source, 512, 16);
        assert!(!outcome.is_valid(), "unexpectedly accepted {source}");
        assert!(!outcome.diagnostics().is_empty());
    }
}

#[test]
fn section14_excerpts_have_executable_syntax_fixtures() {
    let root = workspace_root();
    let review: Section14Review = read_json(&root.join("protocol/requirements/section14-v1.json"));
    let specification = fs::read_to_string(root.join("SPEC.md"))
        .unwrap_or_else(|error| panic!("could not read SPEC.md: {error}"));
    let lines = specification.lines().collect::<Vec<_>>();

    assert_eq!(review.excerpts.len(), 51);
    for excerpt in &review.excerpts {
        assert!(matches!(
            excerpt.classification.as_str(),
            "complete-positive" | "complete-negative" | "focused-fragment"
        ));
        if excerpt.state == "planned" {
            assert!(excerpt.evidence.is_empty());
            continue;
        }
        let source = excerpt_source(&lines, excerpt);
        for (fixture, expected_valid) in excerpt_cases(&excerpt.key, &source) {
            let outcome = parse(&fixture, 8_192, 64);
            assert_eq!(
                outcome.is_valid(),
                expected_valid,
                "{} produced diagnostics {:?}\nfixture:\n{}",
                excerpt.key,
                outcome.diagnostics(),
                fixture
            );
        }
    }
}

fn excerpt_source(lines: &[&str], excerpt: &Section14Excerpt) -> String {
    lines
        .get(excerpt.start_line..excerpt.end_line.saturating_sub(1))
        .unwrap_or_else(|| panic!("invalid excerpt range {}", excerpt.key))
        .join("\n")
}

fn excerpt_cases(key: &str, source: &str) -> Vec<(String, bool)> {
    if key == "section14-excerpt-050" {
        return vec![(source.to_owned(), true)];
    }
    if key == "section14-excerpt-051" {
        let declarations = source
            .replace("missing_type();", "")
            .replace("missing_type::<Report>();", "");
        return vec![(
            format!(
                "{declarations}\nfn inference_examples() {{\n    missing_type();\n    missing_type::<Report>();\n}}\n"
            ),
            true,
        )];
    }
    if key >= "section14-excerpt-038" {
        return source
            .split("\n\n")
            .filter(|paragraph| !paragraph.trim().is_empty())
            .map(|paragraph| {
                let valid = !paragraph.contains("// Syntax error:");
                (frame_paragraph(paragraph), valid)
            })
            .collect();
    }
    if body_fragment(key) {
        return vec![(format!("fn fixture() {{\n{source}\n}}\n"), true)];
    }
    vec![(source.to_owned(), true)]
}

fn frame_paragraph(paragraph: &str) -> String {
    let first_code = paragraph
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with("//"))
        .unwrap_or("");
    if [
        "action read_only ",
        "action idempotent ",
        "action non_idempotent ",
        "agents ",
        "default ",
        "enum ",
        "fn ",
        "impl ",
        "mod ",
        "pure fn ",
        "struct ",
        "trait ",
        "use ",
    ]
    .iter()
    .any(|prefix| first_code.starts_with(prefix))
    {
        paragraph.to_owned()
    } else {
        format!("fn fixture() {{\n{paragraph}\n}}\n")
    }
}

fn body_fragment(key: &str) -> bool {
    matches!(
        key,
        "section14-excerpt-028"
            | "section14-excerpt-038"
            | "section14-excerpt-039"
            | "section14-excerpt-041"
            | "section14-excerpt-042"
            | "section14-excerpt-044"
            | "section14-excerpt-045"
            | "section14-excerpt-046"
            | "section14-excerpt-048"
            | "section14-excerpt-049"
    )
}

fn parse(source: &str, token_limit: u64, diagnostic_limit: u64) -> gantry::frontend::ParseOutcome {
    let limits = SourceLimits::new(1, 4_000_000, 4_000_000, token_limit, diagnostic_limit)
        .unwrap_or_else(|_| unreachable!("positive limits"));
    let mut builder = SourceSnapshotBuilder::new(limits);
    assert!(builder.add_file("main.gnt", source.as_bytes()).is_ok());
    let mut snapshot = builder.finish();
    let (records, counters) = snapshot.records_and_counters_mut();
    Parser::new(
        records
            .first()
            .unwrap_or_else(|| unreachable!("one source")),
        counters,
        i64::MAX as u64,
    )
    .parse_module()
    .unwrap_or_else(|error| panic!("syntax phase failed: {error}"))
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
