//! Independent validation of the published conformance manifest and corpus index.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use gantry::canonical_json::CanonicalJson;
use gantry::schema::SchemaValidator;
use gantry::strict_json::{JsonLimits, StrictJsonDocument};
use serde::Deserialize;
use sha2::{Digest, Sha256};

const CORPUS_PATH: &str = "protocol/conformance/corpus-index-v1.json";
const CORPUS_SCHEMA_PATH: &str = "protocol/schemas/conformance-corpus-index-v1.schema.json";
const MANIFEST_PATH: &str = "protocol/conformance/manifest-v1.json";
const MANIFEST_SCHEMA_PATH: &str = "protocol/schemas/conformance-manifest-v1.schema.json";
const NEGATIVE_PATH: &str = "protocol/goldens/conformance-publication-v1.negatives.json";
const REQUIREMENTS_PATH: &str = "protocol/requirements/generated/requirements-v1.json";
const REVIEW_PATH: &str = "protocol/requirements/reviewed-v1.json";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CorpusIndex {
    format: String,
    specification_sha256: String,
    entries: Vec<CorpusEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CorpusEntry {
    evidence: String,
    profiles: Vec<String>,
    roles: Vec<String>,
    mappings: Vec<CorpusMapping>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(deny_unknown_fields)]
struct CorpusMapping {
    requirement: String,
    clause: String,
    profile: String,
    roles: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConformanceManifest {
    format: String,
    specification_sha256: String,
    requirement_registry: RegistrySummary,
    corpus: CorpusSummary,
    schemas: Vec<DigestArtifact>,
    negative_vectors: DigestArtifact,
    manifests: Vec<ManifestSource>,
    gates: Vec<GateSource>,
    profile_results: Vec<ProfileResult>,
    proofs: Vec<ProofSource>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistrySummary {
    path: String,
    sha256: String,
    requirement_count: usize,
    clause_count: usize,
    mapping_count: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CorpusSummary {
    path: String,
    sha256: String,
    evidence_count: usize,
    mapping_count: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DigestArtifact {
    path: String,
    sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestSource {
    path: String,
    format: String,
    sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GateSource {
    gate: String,
    path: String,
    sha256: String,
    status: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileResult {
    profile: String,
    covered_count: usize,
    not_applicable_count: usize,
    planned_count: usize,
    status: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProofSource {
    kind: String,
    path: String,
    sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RequirementReview {
    #[serde(rename = "specification")]
    _specification: String,
    specification_sha256: String,
    #[serde(rename = "regions")]
    _regions: Vec<serde_json::Value>,
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
    roles: Vec<String>,
    profile_reviews: Vec<ProfileReview>,
}

#[derive(Debug, Deserialize)]
struct ProfileReview {
    profile: String,
    state: String,
    evidence: Vec<String>,
    rationale: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GeneratedRequirements {
    requirements: Vec<GeneratedRequirement>,
}

#[derive(Debug, Deserialize)]
struct GeneratedRequirement {
    clauses: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NegativeCatalog {
    format: String,
    cases: Vec<NegativeCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NegativeCase {
    name: String,
    target: String,
    mutation: String,
}

#[test]
fn generated_conformance_manifest_and_corpus_are_exact_and_complete() {
    let root = workspace_root();
    let corpus_bytes = read(&root.join(CORPUS_PATH));
    let manifest_bytes = read(&root.join(MANIFEST_PATH));
    assert_canonical_and_schema_valid(&root, CORPUS_SCHEMA_PATH, &corpus_bytes);
    assert_canonical_and_schema_valid(&root, MANIFEST_SCHEMA_PATH, &manifest_bytes);

    let corpus: CorpusIndex = decode(&corpus_bytes, CORPUS_PATH);
    let manifest: ConformanceManifest = decode(&manifest_bytes, MANIFEST_PATH);
    let review: RequirementReview = read_json(&root.join(REVIEW_PATH));
    let generated: GeneratedRequirements = read_json(&root.join(REQUIREMENTS_PATH));
    let specification_sha256 = sha256(&read(&root.join("SPEC.md")));

    assert_eq!(corpus.format, "gantry.conformance-corpus-index/v1");
    assert_eq!(manifest.format, "gantry.conformance-manifest/v1");
    assert_eq!(corpus.specification_sha256, specification_sha256);
    assert_eq!(manifest.specification_sha256, specification_sha256);
    assert_eq!(review.specification_sha256, specification_sha256);
    assert!(
        corpus
            .entries
            .windows(2)
            .all(|pair| pair[0].evidence < pair[1].evidence)
    );

    let expected = expected_corpus(&review);
    assert_eq!(corpus.entries.len(), expected.len());
    for entry in &corpus.entries {
        let mappings = expected
            .get(&entry.evidence)
            .unwrap_or_else(|| panic!("unknown corpus evidence {}", entry.evidence));
        assert_eq!(&entry.mappings, mappings, "{}", entry.evidence);
        assert!(entry.mappings.windows(2).all(|pair| pair[0] < pair[1]));
        assert_eq!(
            entry.profiles,
            mappings
                .iter()
                .map(|mapping| mapping.profile.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>()
        );
        assert_eq!(
            entry.roles,
            mappings
                .iter()
                .flat_map(|mapping| mapping.roles.iter().cloned())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>()
        );
        assert_anchor_exists(&root, &entry.evidence);
    }
    assert_eq!(corpus.entries.len(), 123);
    assert_eq!(
        corpus
            .entries
            .iter()
            .map(|entry| entry.mappings.len())
            .sum::<usize>(),
        2_057
    );

    assert_eq!(manifest.requirement_registry.path, REQUIREMENTS_PATH);
    assert_digest(
        &root,
        &manifest.requirement_registry.path,
        &manifest.requirement_registry.sha256,
    );
    assert_eq!(
        manifest.requirement_registry.requirement_count,
        generated.requirements.len()
    );
    assert_eq!(
        manifest.requirement_registry.clause_count,
        generated
            .requirements
            .iter()
            .map(|requirement| requirement.clauses.len())
            .sum::<usize>()
    );
    assert_eq!(manifest.requirement_registry.mapping_count, 1_673);
    assert_eq!(manifest.corpus.path, CORPUS_PATH);
    assert_eq!(manifest.corpus.sha256, sha256(&corpus_bytes));
    assert_eq!(manifest.corpus.evidence_count, 123);
    assert_eq!(manifest.corpus.mapping_count, 2_057);

    assert_eq!(manifest.schemas.len(), 2);
    for schema in &manifest.schemas {
        assert_digest(&root, &schema.path, &schema.sha256);
    }
    assert_eq!(manifest.negative_vectors.path, NEGATIVE_PATH);
    assert_digest(
        &root,
        &manifest.negative_vectors.path,
        &manifest.negative_vectors.sha256,
    );

    assert_eq!(manifest.manifests.len(), 41);
    assert!(
        manifest
            .manifests
            .windows(2)
            .all(|pair| pair[0].path < pair[1].path)
    );
    for source in &manifest.manifests {
        assert_digest(&root, &source.path, &source.sha256);
        let value: serde_json::Value = read_json(&root.join(&source.path));
        assert_eq!(
            value.get("format").and_then(serde_json::Value::as_str),
            Some(source.format.as_str())
        );
    }

    assert_eq!(manifest.gates.len(), 10);
    assert!(
        manifest
            .gates
            .windows(2)
            .all(|pair| pair[0].gate < pair[1].gate)
    );
    for gate in &manifest.gates {
        if gate.gate == "GNT-GEN-GATE-000" {
            assert_eq!(gate.status, "blocked");
        } else {
            assert_eq!(gate.status, "verified");
        }
        assert_digest(&root, &gate.path, &gate.sha256);
    }

    let expected_profiles = expected_profile_results(&review);
    assert_eq!(manifest.profile_results.len(), 6);
    for result in &manifest.profile_results {
        assert_eq!(
            result.status,
            if result.planned_count == 0 {
                "verified"
            } else {
                "blocked"
            }
        );
        assert_eq!(
            expected_profiles.get(&result.profile),
            Some(&(
                result.covered_count,
                result.not_applicable_count,
                result.planned_count,
            ))
        );
    }

    assert_eq!(manifest.proofs.len(), 9);
    assert!(
        manifest
            .proofs
            .windows(2)
            .all(|pair| pair[0].path < pair[1].path)
    );
    for proof in &manifest.proofs {
        assert!(matches!(proof.kind.as_str(), "argument" | "model"));
        assert_digest(&root, &proof.path, &proof.sha256);
    }
}

#[test]
fn conformance_publication_negative_goldens_are_rejected() {
    let root = workspace_root();
    let negatives: NegativeCatalog = read_json(&root.join(NEGATIVE_PATH));
    assert_eq!(
        negatives.format,
        "gantry.conformance-publication-negatives/v1"
    );
    assert_eq!(negatives.cases.len(), 6);
    assert!(
        negatives
            .cases
            .windows(2)
            .all(|pair| pair[0].name < pair[1].name)
    );

    for case in negatives.cases {
        let (path, schema_path) = match case.target.as_str() {
            "corpus" => (CORPUS_PATH, CORPUS_SCHEMA_PATH),
            "manifest" => (MANIFEST_PATH, MANIFEST_SCHEMA_PATH),
            other => panic!("unknown negative target {other}"),
        };
        let mut value: serde_json::Value = read_json(&root.join(path));
        mutate(&mut value, &case.mutation);
        let bytes = serde_json::to_vec(&value)
            .unwrap_or_else(|error| panic!("could not encode negative {}: {error}", case.name));
        let document = StrictJsonDocument::decode(bytes, json_limits(4_000_000))
            .unwrap_or_else(|error| panic!("negative {} is not strict JSON: {error:?}", case.name));
        let validator =
            SchemaValidator::compile(read(&root.join(schema_path)), json_limits(4_000_000))
                .unwrap_or_else(|error| panic!("could not compile {schema_path}: {error:?}"));
        let errors = validator
            .validate(&document)
            .unwrap_or_else(|error| panic!("could not validate {}: {error:?}", case.name));
        assert!(!errors.is_empty(), "accepted negative {}", case.name);
    }
}

fn expected_corpus(review: &RequirementReview) -> BTreeMap<String, Vec<CorpusMapping>> {
    let mut expected = BTreeMap::<String, Vec<CorpusMapping>>::new();
    for requirement in &review.requirements {
        for clause in &requirement.clauses {
            for profile_review in &clause.profile_reviews {
                match profile_review.state.as_str() {
                    "covered" => {
                        assert!(!profile_review.evidence.is_empty());
                        assert!(profile_review.rationale.is_none());
                        for evidence in &profile_review.evidence {
                            expected
                                .entry(evidence.clone())
                                .or_default()
                                .push(CorpusMapping {
                                    requirement: requirement.id.clone(),
                                    clause: clause.key.clone(),
                                    profile: profile_review.profile.clone(),
                                    roles: clause.roles.clone(),
                                });
                        }
                    }
                    "not-applicable" => {
                        assert!(profile_review.evidence.is_empty());
                        assert!(
                            profile_review
                                .rationale
                                .as_deref()
                                .is_some_and(|value| !value.is_empty())
                        );
                    }
                    "planned" | "in-progress" | "unresolved" => {
                        assert!(profile_review.evidence.is_empty());
                    }
                    other => panic!("unclosed review state {other}"),
                }
            }
        }
    }
    for mappings in expected.values_mut() {
        mappings.sort();
        mappings.dedup();
    }
    expected
}

fn expected_profile_results(review: &RequirementReview) -> BTreeMap<String, (usize, usize, usize)> {
    let mut results = BTreeMap::<String, (usize, usize, usize)>::new();
    for requirement in &review.requirements {
        for clause in &requirement.clauses {
            for profile_review in &clause.profile_reviews {
                let counts = results.entry(profile_review.profile.clone()).or_default();
                match profile_review.state.as_str() {
                    "covered" => counts.0 += 1,
                    "not-applicable" => counts.1 += 1,
                    "planned" | "in-progress" | "unresolved" => counts.2 += 1,
                    other => panic!("unclosed review state {other}"),
                }
            }
        }
    }
    results
}

fn mutate(value: &mut serde_json::Value, mutation: &str) {
    let root = value
        .as_object_mut()
        .unwrap_or_else(|| panic!("publication fixture root is not an object"));
    match mutation {
        "add-root-field" => {
            root.insert("unexpected".to_owned(), serde_json::Value::Null);
        }
        "missing-entries" => {
            root.remove("entries");
        }
        "missing-gates" => {
            root.remove("gates");
        }
        "wrong-format" => {
            root.insert(
                "format".to_owned(),
                serde_json::Value::String("gantry.unknown/v1".to_owned()),
            );
        }
        other => panic!("unknown conformance-publication mutation {other}"),
    }
}

fn assert_canonical_and_schema_valid(root: &Path, schema_path: &str, bytes: &[u8]) {
    let document = StrictJsonDocument::decode(bytes.to_vec(), json_limits(4_000_000))
        .unwrap_or_else(|error| panic!("could not decode canonical output: {error:?}"));
    let canonical = CanonicalJson::from_document(&document)
        .unwrap_or_else(|error| panic!("canonicalization failed: {error:?}"));
    assert_eq!(
        canonical.bytes(),
        bytes.strip_suffix(b"\n").unwrap_or(bytes)
    );
    let validator = SchemaValidator::compile(read(&root.join(schema_path)), json_limits(4_000_000))
        .unwrap_or_else(|error| panic!("could not compile {schema_path}: {error:?}"));
    assert_eq!(validator.validate(&document), Ok(Vec::new()));
}

fn assert_anchor_exists(root: &Path, anchor: &str) {
    let (path, symbol) = anchor
        .split_once('#')
        .unwrap_or_else(|| panic!("invalid evidence anchor {anchor}"));
    let source = fs::read_to_string(root.join(path))
        .unwrap_or_else(|error| panic!("could not read evidence source {path}: {error}"));
    assert!(
        source.contains(&format!("fn {symbol}(")) || source.contains(&format!("fn {symbol}<")),
        "missing evidence symbol {anchor}"
    );
}

fn assert_digest(root: &Path, path: &str, expected: &str) {
    assert_eq!(sha256(&read(&root.join(path))), expected, "{path}");
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

const fn json_limits(maximum: u64) -> JsonLimits {
    JsonLimits {
        maximum_bytes: maximum,
        maximum_nesting_depth: maximum,
        maximum_nodes: maximum,
        maximum_string_scalars: maximum,
        maximum_list_items: maximum,
    }
}

fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8], path: &str) -> T {
    serde_json::from_slice(bytes).unwrap_or_else(|error| panic!("could not decode {path}: {error}"))
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> T {
    decode(&read(path), &path.display().to_string())
}

fn read(path: &Path) -> Vec<u8> {
    fs::read(path).unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()))
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}
