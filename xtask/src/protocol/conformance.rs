//! Deterministic conformance manifest and executable corpus publication.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::write_atomic_if_changed;

const CORPUS_PATH: &str = "protocol/conformance/corpus-index-v1.json";
const CORPUS_SCHEMA_PATH: &str = "protocol/schemas/conformance-corpus-index-v1.schema.json";
const MANIFEST_PATH: &str = "protocol/conformance/manifest-v1.json";
const MANIFEST_SCHEMA_PATH: &str = "protocol/schemas/conformance-manifest-v1.schema.json";
const NEGATIVE_PATH: &str = "protocol/goldens/conformance-publication-v1.negatives.json";
const REQUIREMENTS_PATH: &str = "protocol/requirements/generated/requirements-v1.json";
const REVIEW_PATH: &str = "protocol/requirements/reviewed-v1.json";

const PROFILES: &[&str] = &[
    "analyzer",
    "concurrent-evaluator",
    "durable-runtime",
    "embedding",
    "evaluator",
    "frontend",
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RequirementReview {
    specification: String,
    specification_sha256: String,
    regions: Vec<Value>,
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
    clauses: Vec<Value>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
struct CorpusMapping {
    requirement: String,
    clause: String,
    profile: String,
    roles: Vec<String>,
}

#[derive(Debug, Serialize)]
struct CorpusEntry {
    evidence: String,
    profiles: Vec<String>,
    roles: Vec<String>,
    mappings: Vec<CorpusMapping>,
}

#[derive(Debug, Serialize)]
struct CorpusIndex {
    format: &'static str,
    specification_sha256: String,
    entries: Vec<CorpusEntry>,
}

#[derive(Debug, Serialize)]
struct DigestArtifact {
    path: String,
    sha256: String,
}

#[derive(Debug, Serialize)]
struct RegistrySummary {
    path: &'static str,
    sha256: String,
    requirement_count: usize,
    clause_count: usize,
    mapping_count: usize,
}

#[derive(Debug, Serialize)]
struct CorpusSummary {
    path: &'static str,
    sha256: String,
    evidence_count: usize,
    mapping_count: usize,
}

#[derive(Debug, Serialize)]
struct ManifestSource {
    path: String,
    format: String,
    sha256: String,
}

#[derive(Debug, Serialize)]
struct GateSource {
    gate: String,
    path: String,
    sha256: String,
    status: String,
}

#[derive(Debug, Serialize)]
struct ProfileResult {
    profile: String,
    covered_count: usize,
    not_applicable_count: usize,
    status: &'static str,
}

#[derive(Debug, Serialize)]
struct ProofSource {
    kind: String,
    path: String,
    sha256: String,
}

#[derive(Debug, Serialize)]
struct ConformanceManifest {
    format: &'static str,
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

pub(super) fn generate(root: &Path) -> Result<bool, String> {
    let corpus = render_corpus(root)?;
    let corpus_changed = write_atomic_if_changed(&root.join(CORPUS_PATH), &corpus)?;
    let manifest = render_manifest(root, &corpus)?;
    let manifest_changed = write_atomic_if_changed(&root.join(MANIFEST_PATH), &manifest)?;
    if corpus_changed {
        println!("generated {CORPUS_PATH}");
    }
    if manifest_changed {
        println!("generated {MANIFEST_PATH}");
    }
    Ok(corpus_changed || manifest_changed)
}

pub(super) fn check_generated(root: &Path) -> Result<(), String> {
    let corpus = render_corpus(root)?;
    check_file(root, CORPUS_PATH, &corpus)?;
    let manifest = render_manifest(root, &corpus)?;
    check_file(root, MANIFEST_PATH, &manifest)?;
    println!("conformance manifest and corpus index are current");
    Ok(())
}

fn render_corpus(root: &Path) -> Result<Vec<u8>, String> {
    let review: RequirementReview = read_json(root, REVIEW_PATH)?;
    if review.specification != "SPEC.md" || review.regions.is_empty() {
        return Err("reviewed requirement inventory has invalid specification metadata".to_owned());
    }
    validate_specification(root, &review.specification_sha256)?;
    let mut mappings = BTreeMap::<String, Vec<CorpusMapping>>::new();
    for requirement in review.requirements {
        for clause in requirement.clauses {
            for profile_review in clause.profile_reviews {
                match profile_review.state.as_str() {
                    "covered" => {
                        if profile_review.evidence.is_empty() || profile_review.rationale.is_some()
                        {
                            return Err(format!(
                                "covered review {}:{}:{} is incomplete",
                                requirement.id, clause.key, profile_review.profile
                            ));
                        }
                        for evidence in profile_review.evidence {
                            validate_anchor(root, &evidence)?;
                            mappings.entry(evidence).or_default().push(CorpusMapping {
                                requirement: requirement.id.clone(),
                                clause: clause.key.clone(),
                                profile: profile_review.profile.clone(),
                                roles: clause.roles.clone(),
                            });
                        }
                    }
                    "not-applicable" => {
                        if !profile_review.evidence.is_empty()
                            || profile_review
                                .rationale
                                .as_deref()
                                .is_none_or(str::is_empty)
                        {
                            return Err(format!(
                                "not-applicable review {}:{}:{} lacks rationale",
                                requirement.id, clause.key, profile_review.profile
                            ));
                        }
                    }
                    other => return Err(format!("unclosed profile review state {other}")),
                }
            }
        }
    }
    let entries = mappings
        .into_iter()
        .map(|(evidence, mut mappings)| {
            mappings.sort();
            mappings.dedup();
            CorpusEntry {
                profiles: mappings
                    .iter()
                    .map(|mapping| mapping.profile.clone())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect(),
                roles: mappings
                    .iter()
                    .flat_map(|mapping| mapping.roles.iter().cloned())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect(),
                evidence,
                mappings,
            }
        })
        .collect();
    canonical_json(&CorpusIndex {
        format: "gantry.conformance-corpus-index/v1",
        specification_sha256: review.specification_sha256,
        entries,
    })
}

fn render_manifest(root: &Path, corpus: &[u8]) -> Result<Vec<u8>, String> {
    let review: RequirementReview = read_json(root, REVIEW_PATH)?;
    validate_specification(root, &review.specification_sha256)?;
    let generated: GeneratedRequirements = read_json(root, REQUIREMENTS_PATH)?;
    let mut profile_counts = PROFILES
        .iter()
        .map(|profile| ((*profile).to_owned(), (0_usize, 0_usize)))
        .collect::<BTreeMap<_, _>>();
    let mut mapping_count = 0;
    for requirement in &review.requirements {
        for clause in &requirement.clauses {
            for profile_review in &clause.profile_reviews {
                mapping_count += 1;
                let counts = profile_counts
                    .get_mut(&profile_review.profile)
                    .ok_or_else(|| {
                        format!("unknown reviewed profile {}", profile_review.profile)
                    })?;
                match profile_review.state.as_str() {
                    "covered" => counts.0 += 1,
                    "not-applicable" => counts.1 += 1,
                    other => return Err(format!("unclosed profile review state {other}")),
                }
            }
        }
    }
    let mut manifests = Vec::new();
    let mut gates = Vec::new();
    let mut proofs = BTreeMap::<String, String>::new();
    let conformance_dir = root.join("protocol/conformance");
    let mut paths = fs::read_dir(&conformance_dir)
        .map_err(|error| format!("could not read {}: {error}", conformance_dir.display()))?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("could not enumerate conformance inputs: {error}"))?;
    paths.sort();
    for path in paths {
        if path.extension().and_then(|value| value.to_str()) != Some("json")
            || path.ends_with(CORPUS_PATH)
            || path.ends_with(MANIFEST_PATH)
        {
            continue;
        }
        let relative = relative_path(root, &path)?;
        let bytes = fs::read(&path)
            .map_err(|error| format!("could not read {}: {error}", path.display()))?;
        let value: Value = serde_json::from_slice(&bytes)
            .map_err(|error| format!("invalid conformance manifest {relative}: {error}"))?;
        let format = value
            .get("format")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("conformance manifest {relative} has no format"))?;
        manifests.push(ManifestSource {
            path: relative.clone(),
            format: format.to_owned(),
            sha256: digest(&bytes),
        });
        if let Some(gate) = value.get("gate").and_then(Value::as_str) {
            let status = value
                .get("status")
                .and_then(Value::as_str)
                .ok_or_else(|| format!("gate {gate} has no status"))?;
            if status != "verified" {
                return Err(format!("gate {gate} is not verified"));
            }
            gates.push(GateSource {
                gate: gate.to_owned(),
                path: relative,
                sha256: digest(&bytes),
                status: status.to_owned(),
            });
        }
        collect_proofs(&value, "", &mut proofs);
    }
    gates.sort_by(|left, right| left.gate.cmp(&right.gate));
    let proofs = proofs
        .into_iter()
        .map(|(path, kind)| {
            let bytes = fs::read(root.join(&path))
                .map_err(|error| format!("could not read proof {path}: {error}"))?;
            Ok(ProofSource {
                kind,
                path,
                sha256: digest(&bytes),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let schemas = [CORPUS_SCHEMA_PATH, MANIFEST_SCHEMA_PATH]
        .into_iter()
        .map(|path| digest_artifact(root, path))
        .collect::<Result<Vec<_>, _>>()?;
    let negative_vectors = digest_artifact(root, NEGATIVE_PATH)?;
    let corpus_value: Value = serde_json::from_slice(corpus)
        .map_err(|error| format!("invalid generated corpus: {error}"))?;
    let entries = corpus_value
        .get("entries")
        .and_then(Value::as_array)
        .ok_or_else(|| "generated corpus has no entries".to_owned())?;
    let corpus_mapping_count = entries
        .iter()
        .map(|entry| {
            entry
                .get("mappings")
                .and_then(Value::as_array)
                .map_or(0, Vec::len)
        })
        .sum();
    canonical_json(&ConformanceManifest {
        format: "gantry.conformance-manifest/v1",
        specification_sha256: review.specification_sha256,
        requirement_registry: RegistrySummary {
            path: REQUIREMENTS_PATH,
            sha256: digest_file(root, REQUIREMENTS_PATH)?,
            requirement_count: generated.requirements.len(),
            clause_count: generated
                .requirements
                .iter()
                .map(|requirement| requirement.clauses.len())
                .sum(),
            mapping_count,
        },
        corpus: CorpusSummary {
            path: CORPUS_PATH,
            sha256: digest(corpus),
            evidence_count: entries.len(),
            mapping_count: corpus_mapping_count,
        },
        schemas,
        negative_vectors,
        manifests,
        gates,
        profile_results: profile_counts
            .into_iter()
            .map(
                |(profile, (covered_count, not_applicable_count))| ProfileResult {
                    profile,
                    covered_count,
                    not_applicable_count,
                    status: "verified",
                },
            )
            .collect(),
        proofs,
    })
}

fn collect_proofs(value: &Value, key: &str, proofs: &mut BTreeMap<String, String>) {
    match value {
        Value::Object(values) => {
            for (child_key, child) in values {
                collect_proofs(child, child_key, proofs);
            }
        }
        Value::Array(values) => {
            for child in values {
                collect_proofs(child, key, proofs);
            }
        }
        Value::String(path)
            if matches!(key, "argument" | "model")
                && (path.starts_with("docs/") || path.starts_with("protocol/goldens/")) =>
        {
            proofs.insert(path.clone(), key.to_owned());
        }
        _ => {}
    }
}

fn validate_specification(root: &Path, expected: &str) -> Result<(), String> {
    let actual = digest_file(root, "SPEC.md")?;
    if actual != expected {
        return Err("conformance publication specification revision is stale".to_owned());
    }
    Ok(())
}

fn validate_anchor(root: &Path, anchor: &str) -> Result<(), String> {
    let (path, symbol) = anchor
        .split_once('#')
        .ok_or_else(|| format!("invalid evidence anchor {anchor}"))?;
    let source = fs::read_to_string(root.join(path))
        .map_err(|error| format!("could not read evidence source {path}: {error}"))?;
    if !source.contains(&format!("fn {symbol}(")) && !source.contains(&format!("fn {symbol}<")) {
        return Err(format!("missing evidence symbol {anchor}"));
    }
    Ok(())
}

fn digest_artifact(root: &Path, path: &str) -> Result<DigestArtifact, String> {
    Ok(DigestArtifact {
        path: path.to_owned(),
        sha256: digest_file(root, path)?,
    })
}

fn digest_file(root: &Path, path: &str) -> Result<String, String> {
    let bytes =
        fs::read(root.join(path)).map_err(|error| format!("could not read {path}: {error}"))?;
    Ok(digest(&bytes))
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn canonical_json(value: &impl Serialize) -> Result<Vec<u8>, String> {
    fn sort(value: Value) -> Value {
        match value {
            Value::Array(values) => Value::Array(values.into_iter().map(sort).collect()),
            Value::Object(values) => Value::Object(
                values
                    .into_iter()
                    .map(|(key, value)| (key, sort(value)))
                    .collect::<BTreeMap<_, _>>()
                    .into_iter()
                    .collect(),
            ),
            other => other,
        }
    }
    let value = serde_json::to_value(value)
        .map_err(|error| format!("could not encode conformance publication: {error}"))?;
    let mut bytes = serde_json::to_vec(&sort(value))
        .map_err(|error| format!("could not canonicalize conformance publication: {error}"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn relative_path(root: &Path, path: &Path) -> Result<String, String> {
    path.strip_prefix(root)
        .map_err(|_| format!("{} is outside workspace", path.display()))
        .map(|path| path.to_string_lossy().replace('\\', "/"))
}

fn read_json<T: serde::de::DeserializeOwned>(root: &Path, path: &str) -> Result<T, String> {
    let bytes =
        fs::read(root.join(path)).map_err(|error| format!("could not read {path}: {error}"))?;
    serde_json::from_slice(&bytes).map_err(|error| format!("invalid {path}: {error}"))
}

fn check_file(root: &Path, path: &str, expected: &[u8]) -> Result<(), String> {
    let actual =
        fs::read(root.join(path)).map_err(|error| format!("could not read {path}: {error}"))?;
    if actual != expected {
        return Err(format!(
            "{path} is stale; run `cargo run --locked -p xtask -- generate protocol`"
        ));
    }
    Ok(())
}
