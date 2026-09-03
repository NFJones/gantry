//! Deterministic assembly of the active immutable Gantry publication set.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::write_atomic_if_changed;

const INDEX_PATH: &str = "protocol/publication/index-v1.json";
const REPORT_PATH: &str = "protocol/publication/verification-v1.json";
const OUTPUT_DIRECTORY: &str = "protocol/publication/v1";
const SPEC_PATH: &str = "SPEC.md";
const ADOPTION_PATH: &str = "protocol/conformance/async-execution-adoption-v1.json";

const PROFILES: &[&str] = &[
    "analyzer",
    "concurrent-evaluator",
    "durable-runtime",
    "embedding",
    "evaluator",
    "frontend",
];

#[derive(Clone, Debug, Deserialize)]
struct RequirementRegistry {
    requirements: Vec<RequirementRecord>,
}

#[derive(Clone, Debug, Deserialize)]
struct RequirementRecord {
    id: String,
}

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
    superseded_publication_revision: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct ProtocolVersion {
    family: String,
    major: u64,
    minor: u64,
}

#[derive(Debug, Serialize)]
struct PublicationArtifact {
    format: &'static str,
    id: String,
    specification_sha256: String,
    protocols: Vec<ProtocolVersion>,
    profiles: Vec<String>,
    requirements: Vec<String>,
    files: Vec<ArtifactFile>,
}

#[derive(Debug, Serialize)]
struct ArtifactFile {
    path: String,
    media_type: String,
    byte_length: String,
    sha256: String,
    content: String,
}

#[derive(Debug, Serialize)]
struct PublicationIndex {
    publication_index: Version,
    source_language: Version,
    publication_revision: String,
    artifacts: Vec<IndexArtifact>,
}

#[derive(Debug, Serialize)]
struct Version {
    major: u64,
    minor: u64,
}

#[derive(Debug, Serialize)]
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

#[derive(Debug, Serialize)]
struct VerificationReport {
    format: &'static str,
    publication_set_identity: String,
    index: DigestRecord,
    artifacts: Vec<ReportArtifact>,
}

#[derive(Debug, Serialize)]
struct DigestRecord {
    path: &'static str,
    byte_length: String,
    sha256: String,
}

#[derive(Debug, Serialize)]
struct ReportArtifact {
    id: String,
    path: String,
    byte_length: String,
    sha256: String,
}

struct ArtifactDefinition {
    id: &'static str,
    protocols: &'static [&'static str],
    profiles: &'static [&'static str],
}

struct BuiltArtifact {
    id: String,
    path: String,
    media_type: String,
    protocols: Vec<ProtocolVersion>,
    profiles: Vec<String>,
    requirements: Vec<String>,
    bytes: Vec<u8>,
}

const DEFINITIONS: &[ArtifactDefinition] = &[
    ArtifactDefinition {
        id: "gantry.authoring",
        protocols: &[],
        profiles: &["frontend"],
    },
    ArtifactDefinition {
        id: "gantry.conformance",
        protocols: &[],
        profiles: PROFILES,
    },
    ArtifactDefinition {
        id: "gantry.embedding",
        protocols: &["embedding", "hook"],
        profiles: &["embedding"],
    },
    ArtifactDefinition {
        id: "gantry.ir",
        protocols: &["canonical-ir", "source-language", "source-map"],
        profiles: &[
            "analyzer",
            "concurrent-evaluator",
            "durable-runtime",
            "evaluator",
        ],
    },
    ArtifactDefinition {
        id: "gantry.journal",
        protocols: &["journal", "recovery-projection"],
        profiles: &["durable-runtime", "embedding"],
    },
    ArtifactDefinition {
        id: "gantry.spec",
        protocols: &[],
        profiles: PROFILES,
    },
    ArtifactDefinition {
        id: "gantry.values",
        protocols: &["configuration", "event", "value"],
        profiles: PROFILES,
    },
];

pub(super) fn generate(root: &Path) -> Result<bool, String> {
    if !publication_ready(root)? {
        println!("replacement publication assembly is blocked by staged language adoption");
        return Ok(false);
    }
    let outputs = build_outputs(root)?;
    let mut changed = false;
    for (path, bytes) in outputs {
        changed |= write_atomic_if_changed(&root.join(&path), &bytes)?;
        if changed {
            println!("generated {path}");
        }
    }
    Ok(changed)
}

pub(super) fn check_generated(root: &Path) -> Result<(), String> {
    if !publication_ready(root)? {
        println!("replacement publication assembly is blocked by staged language adoption");
        return Ok(());
    }
    let outputs = build_outputs(root)?;
    for (path, expected) in &outputs {
        let actual =
            fs::read(root.join(path)).map_err(|error| format!("could not read {path}: {error}"))?;
        if &actual != expected {
            return Err(format!(
                "{path} is stale; run `cargo run --locked -p xtask -- generate protocol`"
            ));
        }
    }
    let expected = outputs.keys().cloned().collect::<BTreeSet<_>>();
    let output_directory = root.join(OUTPUT_DIRECTORY);
    let actual = fs::read_dir(&output_directory)
        .map_err(|error| format!("could not read {}: {error}", output_directory.display()))?
        .map(|entry| {
            entry
                .map_err(|error| format!("could not read publication member: {error}"))
                .and_then(|entry| relative_path(root, &entry.path()))
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let expected_members = expected
        .iter()
        .filter(|path| path.starts_with(OUTPUT_DIRECTORY))
        .cloned()
        .collect::<BTreeSet<_>>();
    if actual != expected_members {
        return Err(
            "active publication member directory contains stale or missing files".to_owned(),
        );
    }
    println!("active seven-artifact publication set is current");
    Ok(())
}

fn publication_ready(root: &Path) -> Result<bool, String> {
    let adoption: AdoptionGate = read_json(root, ADOPTION_PATH)?;
    let specification = read(root, SPEC_PATH)?;
    let current_revision = digest(&specification);
    if adoption.format != "gantry.async-execution-adoption/v1"
        || adoption.gate != "GNT-ASYNC-GATE-000"
        || adoption.specification_sha256 != current_revision
    {
        return Err(
            "language-adoption gate does not identify the current specification".to_owned(),
        );
    }
    if adoption.status == "blocked" {
        if adoption.amended_profiles != PROFILES
            || !adoption.advertises_profiles.is_empty()
            || adoption.blocked_by.is_empty()
            || !adoption.blocked_by.windows(2).all(|pair| pair[0] < pair[1])
            || adoption
                .blocked_by
                .iter()
                .any(|issue| issue == &adoption.gate)
        {
            return Err(
                "blocked language-adoption gate is incomplete or overclaims profiles".to_owned(),
            );
        }
        let index: Value = read_json(root, INDEX_PATH)?;
        let revision = index
            .get("publication_revision")
            .and_then(Value::as_str)
            .ok_or_else(|| "superseded publication index has no revision".to_owned())?;
        if revision != adoption.superseded_publication_revision {
            return Err("blocked adoption found an unexpected publication revision".to_owned());
        }
        if adoption.blocked_by == ["GNT-ASYNC-REL-001"] {
            return Ok(true);
        }
        return Ok(false);
    }
    if adoption.status != "verified"
        || !adoption.blocked_by.is_empty()
        || adoption.advertises_profiles != PROFILES
    {
        return Err("language-adoption gate has an invalid terminal state".to_owned());
    }
    Ok(true)
}

fn build_outputs(root: &Path) -> Result<BTreeMap<String, Vec<u8>>, String> {
    let specification = read(root, SPEC_PATH)?;
    let specification_sha256 = digest(&specification);
    let registry: RequirementRegistry =
        read_json(root, "protocol/requirements/generated/requirements-v1.json")?;
    let registered = registry
        .requirements
        .into_iter()
        .map(|requirement| requirement.id)
        .collect::<BTreeSet<_>>();
    let ownership = source_ownership(root)?;
    validate_source_ownership(root, &ownership)?;

    let mut built = Vec::new();
    for definition in DEFINITIONS {
        let path = artifact_output_path(definition.id);
        let protocols = protocols(definition.protocols);
        let profiles = definition
            .profiles
            .iter()
            .map(|profile| (*profile).to_owned())
            .collect::<Vec<_>>();
        let requirements = requirements_for(
            root,
            definition.id,
            ownership
                .get(definition.id)
                .map(Vec::as_slice)
                .unwrap_or_default(),
            &registered,
        )?;
        let (media_type, bytes) = if definition.id == "gantry.spec" {
            ("text/markdown".to_owned(), specification.clone())
        } else {
            let files = ownership
                .get(definition.id)
                .ok_or_else(|| format!("missing source ownership for {}", definition.id))?
                .iter()
                .map(|path| artifact_file(root, path))
                .collect::<Result<Vec<_>, _>>()?;
            let artifact = PublicationArtifact {
                format: "gantry.publication-artifact/v1",
                id: definition.id.to_owned(),
                specification_sha256: specification_sha256.clone(),
                protocols: protocols.clone(),
                profiles: profiles.clone(),
                requirements: requirements.clone(),
                files,
            };
            ("application/json".to_owned(), canonical_json(&artifact)?)
        };
        built.push(BuiltArtifact {
            id: definition.id.to_owned(),
            path,
            media_type,
            protocols,
            profiles,
            requirements,
            bytes,
        });
    }

    let index = PublicationIndex {
        publication_index: Version { major: 1, minor: 0 },
        source_language: Version { major: 1, minor: 0 },
        publication_revision: format!("gantry-v1-{specification_sha256}"),
        artifacts: built
            .iter()
            .map(|artifact| IndexArtifact {
                id: artifact.id.clone(),
                uri: format!(
                    "https://github.com/NFJones/gantry/releases/download/v1.0.0/{}",
                    Path::new(&artifact.path)
                        .file_name()
                        .and_then(|name| name.to_str())
                        .unwrap_or_default()
                ),
                media_type: artifact.media_type.clone(),
                byte_length: artifact.bytes.len().to_string(),
                sha256: digest(&artifact.bytes),
                protocols: artifact.protocols.clone(),
                profiles: artifact.profiles.clone(),
                requirements: artifact.requirements.clone(),
            })
            .collect(),
    };
    let index_bytes = canonical_json(&index)?;
    let report = VerificationReport {
        format: "gantry.publication-verification/v1",
        publication_set_identity: digest(&index_bytes),
        index: DigestRecord {
            path: INDEX_PATH,
            byte_length: index_bytes.len().to_string(),
            sha256: digest(&index_bytes),
        },
        artifacts: built
            .iter()
            .map(|artifact| ReportArtifact {
                id: artifact.id.clone(),
                path: artifact.path.clone(),
                byte_length: artifact.bytes.len().to_string(),
                sha256: digest(&artifact.bytes),
            })
            .collect(),
    };
    let report_bytes = canonical_json(&report)?;

    let mut outputs = built
        .into_iter()
        .map(|artifact| (artifact.path, artifact.bytes))
        .collect::<BTreeMap<_, _>>();
    outputs.insert(INDEX_PATH.to_owned(), index_bytes);
    outputs.insert(REPORT_PATH.to_owned(), report_bytes);
    Ok(outputs)
}

fn source_ownership(root: &Path) -> Result<BTreeMap<&'static str, Vec<String>>, String> {
    let mut ownership = BTreeMap::<&'static str, BTreeSet<String>>::new();
    let mut add = |id: &'static str, path: &str| {
        ownership.entry(id).or_default().insert(path.to_owned());
    };

    for path in [
        "SPEC.md",
        "crates/gantry-conformance/tests/frontend_parser_evidence.rs",
        "crates/gantry-conformance/tests/generics_authoring.rs",
        "docs/frontend-resource-policy.md",
        "docs/generics-and-traits.md",
        "examples/frontend-limits.json",
        "examples/generics-and-traits/main.gnt",
        "examples/generics-and-traits-invalid/cyclic-obligation/main.gnt",
        "examples/generics-and-traits-invalid/duplicate-parameter/main.gnt",
        "examples/generics-and-traits-invalid/incomplete-inference/main.gnt",
        "examples/generics-and-traits-invalid/polymorphic-recursion/main.gnt",
        "protocol/goldens/generics-traits-authoring-v1.json",
        "protocol/requirements/section14-v1.json",
        "protocol/schemas/generics-traits-authoring-v1.schema.json",
        "protocol/goldens/source-substrate-vectors-v1.json",
        "protocol/goldens/unicode-version-vectors-v1.json",
        "protocol/schemas/source-substrate-v1.schema.json",
    ] {
        add("gantry.authoring", path);
    }

    add(
        "gantry.conformance",
        "protocol/publication/artifacts-v1.json",
    );
    for path in files(root, "protocol/conformance")? {
        add("gantry.conformance", &path);
    }
    for path in files_recursive(root, "protocol/requirements")? {
        if path != "protocol/requirements/section14-v1.json" {
            add("gantry.conformance", &path);
        }
    }
    for path in files(root, "crates/gantry-conformance/tests")? {
        if !matches!(
            path.as_str(),
            "crates/gantry-conformance/tests/frontend_parser_evidence.rs"
                | "crates/gantry-conformance/tests/generics_authoring.rs"
        ) {
            add("gantry.conformance", &path);
        }
    }
    for path in [
        "docs/analyzer-package-validity.md",
        "docs/concurrent-evaluator-refinement.md",
        "docs/durable-runtime-refinement.md",
        "docs/sequential-evaluator-refinement.md",
        "protocol/goldens/analyzer-validity-model-v1.json",
        "protocol/goldens/concurrent-executor-model-v1.json",
        "protocol/goldens/concurrent-refinement-model-v1.json",
        "protocol/goldens/conformance-publication-v1.negatives.json",
        "protocol/goldens/durable-refinement-model-v1.json",
        "protocol/goldens/publication-index-v1.canonical.json",
        "protocol/goldens/publication-index-v1.negatives.json",
        "protocol/goldens/sequential-evaluator-model-v1.json",
        "protocol/schemas/concurrent-executor-model-v1.schema.json",
        "protocol/schemas/concurrent-refinement-model-v1.schema.json",
        "protocol/schemas/conformance-corpus-index-v1.schema.json",
        "protocol/schemas/conformance-manifest-v1.schema.json",
        "protocol/schemas/publication-artifact-v1.schema.json",
        "protocol/schemas/publication-index-v1.schema.json",
    ] {
        add("gantry.conformance", path);
    }

    for path in [
        "protocol/catalogs/embedding-contracts-v1.json",
        "protocol/goldens/activity-observation-vectors-v1.json",
        "protocol/goldens/concurrent-lifecycle-v1.json",
        "protocol/goldens/embedding-contracts-v1.canonical.json",
        "protocol/goldens/embedding-envelope-negatives-v1.json",
        "protocol/goldens/executor-services-v1.json",
        "protocol/goldens/package-service-vectors-v1.json",
        "protocol/schemas/activity-observation-v1.schema.json",
        "protocol/schemas/concurrent-lifecycle-v1.schema.json",
        "protocol/schemas/embedding-contracts-v1.schema.json",
        "protocol/schemas/executor-services-v1.schema.json",
        "protocol/schemas/package-services-v1.schema.json",
    ] {
        add("gantry.embedding", path);
    }

    for path in [
        "protocol/catalogs/ir-contracts-v1.json",
        "protocol/goldens/ir-artifact-vectors-v1.json",
        "protocol/goldens/ir-contracts-v1.canonical.json",
        "protocol/schemas/canonical-ir-v1.schema.json",
        "protocol/schemas/generated-schema-object-v1.schema.json",
        "protocol/schemas/package-source-manifest-v1.schema.json",
        "protocol/schemas/source-map-v1.schema.json",
    ] {
        add("gantry.ir", path);
    }

    for path in [
        "protocol/catalogs/public-formats-v1.json",
        "protocol/goldens/durable-events-v1.json",
        "protocol/goldens/durable-recovery-v1.json",
        "protocol/goldens/durable-start-v1.json",
        "protocol/goldens/journal-storage-v1.json",
        "protocol/goldens/public-formats-v1.json",
        "protocol/goldens/public-formats-v1.negatives.json",
        "protocol/schemas/durable-events-v1.schema.json",
        "protocol/schemas/durable-recovery-v1.schema.json",
        "protocol/schemas/durable-start-v1.schema.json",
        "protocol/schemas/journal-storage-v1.schema.json",
        "protocol/schemas/public-checkpoint-formats-v1.schema.json",
        "protocol/schemas/public-journal-formats-v1.schema.json",
    ] {
        add("gantry.journal", path);
    }

    for path in [
        "protocol/catalogs/portable-contracts-v1.json",
        "protocol/catalogs/profiles-v1.json",
        "protocol/goldens/diagnostic-machine-v1.json",
        "protocol/goldens/diagnostic-presentation-v1.json",
        "protocol/goldens/persistent-values-v1.json",
        "protocol/goldens/portable-contract-vectors-v1.json",
        "protocol/goldens/portable-contracts-v1.canonical.json",
        "protocol/goldens/profiles-v1.canonical.json",
        "protocol/goldens/sequential-machine-v1.json",
        "protocol/goldens/value-kernel-v1.json",
        "protocol/schemas/canonical-transcript-v1.schema.json",
        "protocol/schemas/persistent-values-v1.schema.json",
        "protocol/schemas/portable-contracts-v1.schema.json",
        "protocol/schemas/profile-catalog-v1.schema.json",
        "protocol/schemas/sequential-machine-v1.schema.json",
        "protocol/schemas/value-kernel-v1.schema.json",
    ] {
        add("gantry.values", path);
    }

    ownership
        .into_iter()
        .map(|(id, paths)| Ok((id, paths.into_iter().collect())))
        .collect()
}

fn validate_source_ownership(
    root: &Path,
    ownership: &BTreeMap<&str, Vec<String>>,
) -> Result<(), String> {
    let mut owners = BTreeMap::<String, &str>::new();
    for (id, paths) in ownership {
        for path in paths {
            if !root.join(path).is_file() {
                return Err(format!("publication source {path} is missing"));
            }
            if let Some(prior) = owners.insert(path.clone(), id) {
                return Err(format!(
                    "publication source {path} is owned by {prior} and {id}"
                ));
            }
        }
    }
    let mut expected = BTreeSet::new();
    for directory in [
        "protocol/catalogs",
        "protocol/conformance",
        "protocol/goldens",
        "protocol/requirements",
        "protocol/schemas",
    ] {
        expected.extend(files_recursive(root, directory)?);
    }
    let actual = owners
        .keys()
        .filter(|path| path.starts_with("protocol/") && !path.starts_with("protocol/publication/"))
        .cloned()
        .collect::<BTreeSet<_>>();
    if actual != expected {
        let missing = expected.difference(&actual).cloned().collect::<Vec<_>>();
        let unexpected = actual.difference(&expected).cloned().collect::<Vec<_>>();
        return Err(format!(
            "publication source ownership differs; missing {missing:?}, unexpected {unexpected:?}"
        ));
    }
    Ok(())
}

fn requirements_for(
    root: &Path,
    id: &str,
    members: &[String],
    registered: &BTreeSet<String>,
) -> Result<Vec<String>, String> {
    if matches!(id, "gantry.conformance" | "gantry.spec") {
        return Ok(registered.iter().cloned().collect());
    }
    let mut requirements = BTreeSet::from([
        "GNT-15.8".to_owned(),
        "GNT-15.8-publication-integrity".to_owned(),
    ]);
    if id == "gantry.authoring" {
        requirements.insert("GNT-1.0".to_owned());
    }
    for path in members {
        if !path.ends_with(".json") {
            continue;
        }
        let value: Value = read_json(root, path)?;
        collect_requirements(&value, registered, &mut requirements);
    }
    Ok(requirements.into_iter().collect())
}

fn collect_requirements(
    value: &Value,
    registered: &BTreeSet<String>,
    requirements: &mut BTreeSet<String>,
) {
    match value {
        Value::Array(values) => {
            for value in values {
                collect_requirements(value, registered, requirements);
            }
        }
        Value::Object(values) => {
            for value in values.values() {
                collect_requirements(value, registered, requirements);
            }
        }
        Value::String(value) if registered.contains(value) => {
            requirements.insert(value.clone());
        }
        _ => {}
    }
}

fn artifact_file(root: &Path, path: &str) -> Result<ArtifactFile, String> {
    let bytes = read(root, path)?;
    let content = String::from_utf8(bytes.clone())
        .map_err(|_| format!("publication source {path} is not valid UTF-8"))?;
    if path.ends_with(".json") {
        serde_json::from_slice::<Value>(&bytes)
            .map_err(|error| format!("publication JSON source {path} is invalid: {error}"))?;
    }
    Ok(ArtifactFile {
        path: path.to_owned(),
        media_type: media_type(path)?.to_owned(),
        byte_length: bytes.len().to_string(),
        sha256: digest(&bytes),
        content,
    })
}

fn protocols(families: &[&str]) -> Vec<ProtocolVersion> {
    families
        .iter()
        .map(|family| ProtocolVersion {
            family: (*family).to_owned(),
            major: 1,
            minor: 0,
        })
        .collect()
}

fn artifact_output_path(id: &str) -> String {
    if id == "gantry.spec" {
        format!("{OUTPUT_DIRECTORY}/SPEC.md")
    } else {
        format!("{OUTPUT_DIRECTORY}/{id}.json")
    }
}

fn media_type(path: &str) -> Result<&'static str, String> {
    if path.ends_with(".json") {
        Ok("application/json")
    } else if path.ends_with(".md") {
        Ok("text/markdown")
    } else if path.ends_with(".gnt") {
        Ok("text/plain")
    } else if path.ends_with(".rs") {
        Ok("text/x-rust")
    } else {
        Err(format!("publication source {path} has no media type"))
    }
}

fn files(root: &Path, directory: &str) -> Result<Vec<String>, String> {
    let path = root.join(directory);
    let mut paths = fs::read_dir(&path)
        .map_err(|error| format!("could not read {}: {error}", path.display()))?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.is_file())
        .map(|path| relative_path(root, &path))
        .collect::<Result<Vec<_>, _>>()?;
    paths.sort();
    Ok(paths)
}

fn files_recursive(root: &Path, directory: &str) -> Result<Vec<String>, String> {
    let mut pending = vec![root.join(directory)];
    let mut paths = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory)
            .map_err(|error| format!("could not read {}: {error}", directory.display()))?
        {
            let path = entry
                .map_err(|error| format!("could not read directory entry: {error}"))?
                .path();
            if path.is_dir() {
                pending.push(path);
            } else if path.is_file() {
                paths.push(relative_path(root, &path)?);
            }
        }
    }
    paths.sort();
    Ok(paths)
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
        .map_err(|error| format!("could not encode publication output: {error}"))?;
    let mut bytes = serde_json::to_vec(&sort(value))
        .map_err(|error| format!("could not canonicalize publication output: {error}"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn relative_path(root: &Path, path: &Path) -> Result<String, String> {
    path.strip_prefix(root)
        .map_err(|_| format!("{} is outside workspace", path.display()))
        .map(|path| path.to_string_lossy().replace('\\', "/"))
}

fn read(root: &Path, path: &str) -> Result<Vec<u8>, String> {
    fs::read(root.join(path)).map_err(|error| format!("could not read {path}: {error}"))
}

fn read_json<T: serde::de::DeserializeOwned>(root: &Path, path: &str) -> Result<T, String> {
    let bytes = read(root, path)?;
    serde_json::from_slice(&bytes).map_err(|error| format!("invalid {path}: {error}"))
}
