//! Independent validation of the active immutable Gantry publication set.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use gantry::canonical_json::CanonicalJson;
use gantry::schema::SchemaValidator;
use gantry::strict_json::{JsonLimits, StrictJsonDocument};
use serde::Deserialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

const ARTIFACT_SCHEMA_PATH: &str = "protocol/schemas/publication-artifact-v1.schema.json";
const INDEX_PATH: &str = "protocol/publication/index-v1.json";
const INDEX_SCHEMA_PATH: &str = "protocol/schemas/publication-index-v1.schema.json";
const NEGATIVES_PATH: &str = "protocol/goldens/publication-index-v1.negatives.json";
const REPORT_PATH: &str = "protocol/publication/verification-v1.json";
const REQUIREMENTS_PATH: &str = "protocol/requirements/generated/requirements-v1.json";

const REQUIRED_ARTIFACTS: [&str; 7] = [
    "gantry.authoring",
    "gantry.conformance",
    "gantry.embedding",
    "gantry.ir",
    "gantry.journal",
    "gantry.spec",
    "gantry.values",
];

const PROTOCOL_FAMILIES: [&str; 10] = [
    "canonical-ir",
    "configuration",
    "embedding",
    "event",
    "hook",
    "journal",
    "recovery-projection",
    "source-language",
    "source-map",
    "value",
];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct ProtocolVersion {
    family: String,
    major: u64,
    minor: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicationIndex {
    publication_index: Version,
    source_language: Version,
    publication_revision: String,
    artifacts: Vec<IndexArtifact>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Version {
    major: u64,
    minor: u64,
}

#[derive(Debug, Deserialize)]
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NegativeVectors {
    format: String,
    cases: Vec<NegativeCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NegativeCase {
    name: String,
    mutation: String,
}

#[test]
fn active_publication_set_is_canonical_complete_and_self_contained() {
    let root = workspace_root();
    let index_bytes = read(&root.join(INDEX_PATH));
    assert_canonical_and_schema_valid(&root, INDEX_SCHEMA_PATH, &index_bytes);
    let index: PublicationIndex = decode(&index_bytes, INDEX_PATH);
    assert_eq!(
        (index.publication_index.major, index.publication_index.minor),
        (1, 0)
    );
    assert_eq!(
        (index.source_language.major, index.source_language.minor),
        (1, 0)
    );
    assert_eq!(
        index.publication_revision,
        format!("gantry-v1-{}", sha256(&read(&root.join("SPEC.md"))))
    );
    assert_eq!(
        index
            .artifacts
            .iter()
            .map(|artifact| artifact.id.as_str())
            .collect::<Vec<_>>(),
        REQUIRED_ARTIFACTS
    );

    let registered_requirements = registered_requirements(&root);
    let known_profiles = BTreeSet::from([
        "analyzer",
        "concurrent-evaluator",
        "durable-runtime",
        "embedding",
        "evaluator",
        "frontend",
    ]);
    let mut protocol_owners = BTreeMap::<String, String>::new();
    let mut uris = BTreeSet::new();
    let mut resolved = BTreeMap::<String, (String, Vec<u8>)>::new();
    let specification_sha256 = sha256(&read(&root.join("SPEC.md")));
    let publication_set_identity = sha256(&index_bytes);
    for artifact in &index.artifacts {
        assert!(
            artifact
                .uri
                .starts_with("https://github.com/NFJones/gantry/releases/download/v1.0.0/")
        );
        assert!(uris.insert(artifact.uri.as_str()));
        assert!(decimal_string(&artifact.byte_length));
        assert!(lowercase_sha256(&artifact.sha256));
        assert!(artifact.profiles.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(
            artifact
                .requirements
                .windows(2)
                .all(|pair| pair[0] < pair[1])
        );
        assert!(
            artifact
                .profiles
                .iter()
                .all(|profile| known_profiles.contains(profile.as_str()))
        );
        assert!(
            artifact
                .requirements
                .iter()
                .all(|requirement| registered_requirements.contains(requirement))
        );
        assert!(
            artifact
                .protocols
                .windows(2)
                .all(|pair| pair[0].family < pair[1].family)
        );
        for protocol in &artifact.protocols {
            assert_eq!((protocol.major, protocol.minor), (1, 0));
            assert!(PROTOCOL_FAMILIES.contains(&protocol.family.as_str()));
            assert!(
                protocol_owners
                    .insert(protocol.family.clone(), artifact.id.clone())
                    .is_none()
            );
        }

        let path = artifact_path(&root, &artifact.id);
        let bytes = read(&path);
        assert_eq!(artifact.byte_length, bytes.len().to_string());
        assert_eq!(artifact.sha256, sha256(&bytes));
        if artifact.id == "gantry.spec" {
            assert_eq!(artifact.media_type, "text/markdown");
            assert_eq!(bytes, read(&root.join("SPEC.md")));
        } else {
            assert_eq!(artifact.media_type, "application/json");
            assert_canonical_and_schema_valid(&root, ARTIFACT_SCHEMA_PATH, &bytes);
            let bundle: PublicationArtifact = decode(&bytes, &path.display().to_string());
            assert_eq!(bundle.format, "gantry.publication-artifact/v1");
            assert_eq!(bundle.id, artifact.id);
            assert_eq!(bundle.specification_sha256, specification_sha256);
            assert_eq!(bundle.protocols, artifact.protocols);
            assert_eq!(bundle.profiles, artifact.profiles);
            assert_eq!(bundle.requirements, artifact.requirements);
            assert!(!bundle.files.is_empty());
            assert!(
                bundle
                    .files
                    .windows(2)
                    .all(|pair| pair[0].path < pair[1].path)
            );
            let mut paths = BTreeSet::new();
            for file in &bundle.files {
                assert!(paths.insert(file.path.as_str()));
                assert!(!file.path.starts_with("protocol/publication/v1/"));
                assert_ne!(file.path, INDEX_PATH);
                assert_ne!(file.path, REPORT_PATH);
                assert!(matches!(
                    file.media_type.as_str(),
                    "application/json" | "text/markdown" | "text/x-rust"
                ));
                assert!(decimal_string(&file.byte_length));
                assert!(lowercase_sha256(&file.sha256));
                let content = file.content.as_bytes();
                assert_eq!(file.byte_length, content.len().to_string(), "{}", file.path);
                assert_eq!(file.sha256, sha256(content), "{}", file.path);
                assert_eq!(content, read(&root.join(&file.path)), "{}", file.path);
            }
            assert!(
                !bytes
                    .windows(publication_set_identity.len())
                    .any(|window| window == publication_set_identity.as_bytes())
            );
        }
        resolved.insert(artifact.id.clone(), (relative_path(&root, &path), bytes));
    }
    assert_eq!(
        protocol_owners
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        PROTOCOL_FAMILIES
    );
    assert_required_bundle_members(&root, &resolved);

    let report_bytes = read(&root.join(REPORT_PATH));
    assert_canonical(&report_bytes);
    let report: VerificationReport = decode(&report_bytes, REPORT_PATH);
    assert_eq!(report.format, "gantry.publication-verification/v1");
    assert_eq!(report.publication_set_identity, publication_set_identity);
    assert_eq!(report.index.path, INDEX_PATH);
    assert_eq!(report.index.byte_length, index_bytes.len().to_string());
    assert_eq!(report.index.sha256, sha256(&index_bytes));
    assert_eq!(report.artifacts.len(), REQUIRED_ARTIFACTS.len());
    for artifact in &report.artifacts {
        let (path, bytes) = resolved
            .get(&artifact.id)
            .unwrap_or_else(|| panic!("unknown report artifact {}", artifact.id));
        assert_eq!(&artifact.path, path);
        assert_eq!(artifact.byte_length, bytes.len().to_string());
        assert_eq!(artifact.sha256, sha256(bytes));
    }
}

#[test]
fn active_publication_set_rejects_all_integrity_mutations() {
    let root = workspace_root();
    let source: Value = read_json(&root.join(INDEX_PATH));
    let negatives: NegativeVectors = read_json(&root.join(NEGATIVES_PATH));
    assert_eq!(negatives.format, "gantry.publication-index-negatives/v1");
    assert_eq!(negatives.cases.len(), 20);
    for case in negatives.cases {
        let mutated = mutate(&source, &case.mutation);
        assert!(
            validate_active_index(&root, &mutated).is_err(),
            "accepted active-index mutation {} ({})",
            case.name,
            case.mutation
        );
    }
}

fn validate_active_index(root: &Path, value: &Value) -> Result<(), String> {
    let object = exact_object(
        value,
        &[
            "artifacts",
            "publication_index",
            "publication_revision",
            "source_language",
        ],
    )?;
    validate_version(field(object, "publication_index")?)?;
    validate_version(field(object, "source_language")?)?;
    if string(field(object, "publication_revision")?)?.is_empty() {
        return Err("empty publication revision".to_owned());
    }
    let artifacts = array(field(object, "artifacts")?)?;
    if artifacts.len() != REQUIRED_ARTIFACTS.len() {
        return Err("publication member count differs".to_owned());
    }
    let requirements = registered_requirements(root);
    let profiles = BTreeSet::from([
        "analyzer",
        "concurrent-evaluator",
        "durable-runtime",
        "embedding",
        "evaluator",
        "frontend",
    ]);
    let protocols = PROTOCOL_FAMILIES.into_iter().collect::<BTreeSet<_>>();
    let mut ids = BTreeSet::new();
    let mut uris = BTreeSet::new();
    let mut definitions = BTreeSet::new();
    for (position, artifact) in artifacts.iter().enumerate() {
        let artifact = exact_object(
            artifact,
            &[
                "byte_length",
                "id",
                "media_type",
                "profiles",
                "protocols",
                "requirements",
                "sha256",
                "uri",
            ],
        )?;
        let id = string(field(artifact, "id")?)?;
        if REQUIRED_ARTIFACTS.get(position) != Some(&id) || !ids.insert(id) {
            return Err("artifact identifiers differ".to_owned());
        }
        let uri = string(field(artifact, "uri")?)?;
        if !uri.starts_with("https://") || !uri.contains("/v1.0.0/") || !uris.insert(uri) {
            return Err("artifact URI differs".to_owned());
        }
        let media_type = string(field(artifact, "media_type")?)?;
        if !matches!(media_type, "application/json" | "text/markdown") {
            return Err("artifact media type differs".to_owned());
        }
        let byte_length = string(field(artifact, "byte_length")?)?;
        let digest = string(field(artifact, "sha256")?)?;
        if !decimal_string(byte_length) || !lowercase_sha256(digest) {
            return Err("artifact integrity metadata is malformed".to_owned());
        }
        let path = artifact_path(root, id);
        let bytes =
            fs::read(&path).map_err(|error| format!("missing {}: {error}", path.display()))?;
        if byte_length != bytes.len().to_string() || digest != sha256(&bytes) {
            return Err("artifact integrity metadata differs".to_owned());
        }
        validate_sorted_allowed(field(artifact, "profiles")?, &profiles)?;
        validate_sorted_allowed(field(artifact, "requirements")?, &requirements)?;
        let mut prior = None;
        for protocol in array(field(artifact, "protocols")?)? {
            let protocol = exact_object(protocol, &["family", "major", "minor"])?;
            let family = string(field(protocol, "family")?)?;
            if prior.is_some_and(|prior| prior >= family)
                || !protocols.contains(family)
                || !definitions.insert(family)
            {
                return Err("protocol definitions differ".to_owned());
            }
            prior = Some(family);
            if field(protocol, "major")?.as_u64() != Some(1)
                || field(protocol, "minor")?.as_u64() != Some(0)
            {
                return Err("protocol version differs".to_owned());
            }
        }
    }
    if ids != REQUIRED_ARTIFACTS.into_iter().collect() || definitions != protocols {
        return Err("publication membership differs".to_owned());
    }
    Ok(())
}

fn assert_required_bundle_members(root: &Path, resolved: &BTreeMap<String, (String, Vec<u8>)>) {
    let required = BTreeMap::from([
        (
            "gantry.authoring",
            [
                "SPEC.md",
                "crates/gantry-conformance/tests/frontend_parser_evidence.rs",
                "protocol/requirements/section14-v1.json",
            ]
            .as_slice(),
        ),
        (
            "gantry.conformance",
            [
                "protocol/conformance/corpus-index-v1.json",
                "protocol/conformance/manifest-v1.json",
                "protocol/goldens/publication-index-v1.canonical.json",
                "protocol/goldens/publication-index-v1.negatives.json",
                "protocol/schemas/conformance-corpus-index-v1.schema.json",
                "protocol/schemas/conformance-manifest-v1.schema.json",
                "protocol/schemas/publication-index-v1.schema.json",
            ]
            .as_slice(),
        ),
        (
            "gantry.embedding",
            [
                "protocol/catalogs/embedding-contracts-v1.json",
                "protocol/goldens/embedding-envelope-negatives-v1.json",
                "protocol/schemas/embedding-contracts-v1.schema.json",
            ]
            .as_slice(),
        ),
        (
            "gantry.ir",
            [
                "protocol/catalogs/ir-contracts-v1.json",
                "protocol/goldens/ir-artifact-vectors-v1.json",
                "protocol/schemas/canonical-ir-v1.schema.json",
                "protocol/schemas/package-source-manifest-v1.schema.json",
                "protocol/schemas/source-map-v1.schema.json",
            ]
            .as_slice(),
        ),
        (
            "gantry.journal",
            [
                "protocol/catalogs/public-formats-v1.json",
                "protocol/goldens/public-formats-v1.json",
                "protocol/schemas/public-checkpoint-formats-v1.schema.json",
                "protocol/schemas/public-journal-formats-v1.schema.json",
            ]
            .as_slice(),
        ),
        (
            "gantry.values",
            [
                "protocol/catalogs/portable-contracts-v1.json",
                "protocol/goldens/diagnostic-machine-v1.json",
                "protocol/goldens/value-kernel-v1.json",
                "protocol/schemas/canonical-transcript-v1.schema.json",
                "protocol/schemas/value-kernel-v1.schema.json",
            ]
            .as_slice(),
        ),
    ]);
    for (id, paths) in required {
        let (_, bytes) = resolved
            .get(id)
            .unwrap_or_else(|| panic!("missing required bundle {id}"));
        let bundle: PublicationArtifact = decode(bytes, id);
        let members = bundle
            .files
            .iter()
            .map(|file| file.path.as_str())
            .collect::<BTreeSet<_>>();
        for path in paths {
            assert!(members.contains(path), "{id} omits {path}");
            assert!(root.join(path).is_file());
        }
    }
}

fn mutate(source: &Value, mutation: &str) -> Value {
    let mut value = source.clone();
    let root = value
        .as_object_mut()
        .unwrap_or_else(|| unreachable!("active index is an object"));
    match mutation {
        "add-root-field" => {
            root.insert("unexpected".to_owned(), Value::Bool(true));
        }
        "duplicate-family-definition" => {
            let protocols = artifact_mut(root, 3)["protocols"]
                .as_array_mut()
                .unwrap_or_else(|| unreachable!("protocols are an array"));
            protocols.push(protocols[0].clone());
        }
        "duplicate-artifact-id" => copy_artifact_field(root, 0, 1, "id"),
        "duplicate-artifact-uri" => copy_artifact_field(root, 0, 1, "uri"),
        "leading-zero-byte-length" => set_artifact(root, 0, "byte_length", "00"),
        "invalid-media-type" => set_artifact(root, 0, "media_type", "not-a-media-type"),
        "uppercase-sha256" => set_artifact(root, 0, "sha256", &"A".repeat(64)),
        "remove-required-artifact" => {
            artifacts_mut(root).pop();
        }
        "reverse-artifact-order" => artifacts_mut(root).reverse(),
        "reverse-profile-order" => artifact_mut(root, 1)["profiles"]
            .as_array_mut()
            .unwrap_or_else(|| unreachable!("profiles are an array"))
            .reverse(),
        "reverse-protocol-order" => artifact_mut(root, 2)["protocols"]
            .as_array_mut()
            .unwrap_or_else(|| unreachable!("protocols are an array"))
            .reverse(),
        "reverse-requirement-order" => artifact_mut(root, 0)["requirements"]
            .as_array_mut()
            .unwrap_or_else(|| unreachable!("requirements are an array"))
            .reverse(),
        "embed-active-index-digest" => {
            root.insert(
                "active_index_digest".to_owned(),
                Value::String("0".repeat(64)),
            );
        }
        "unknown-profile" => artifact_mut(root, 0)["profiles"] = serde_json::json!(["unknown"]),
        "unknown-protocol" => {
            artifact_mut(root, 2)["protocols"][0]["family"] = Value::String("unknown".to_owned());
        }
        "unknown-requirement" => {
            artifact_mut(root, 0)["requirements"] = serde_json::json!(["GNT-UNKNOWN"]);
        }
        "unversioned-uri" => set_artifact(
            root,
            0,
            "uri",
            "https://github.com/NFJones/gantry/releases/download/gantry.authoring.json",
        ),
        "wrong-byte-length" => set_artifact(root, 0, "byte_length", "1"),
        "wrong-digest" => set_artifact(root, 0, "sha256", &"0".repeat(64)),
        "wrong-index-version" => root["publication_index"]["major"] = Value::from(2),
        other => panic!("unknown publication mutation {other}"),
    }
    value
}

fn artifact_path(root: &Path, id: &str) -> PathBuf {
    let name = if id == "gantry.spec" {
        "SPEC.md".to_owned()
    } else {
        format!("{id}.json")
    };
    root.join("protocol/publication/v1").join(name)
}

fn assert_canonical_and_schema_valid(root: &Path, schema_path: &str, bytes: &[u8]) {
    let document = StrictJsonDocument::decode(bytes.to_vec(), json_limits(16_000_000))
        .unwrap_or_else(|error| panic!("strict JSON failed: {error:?}"));
    let canonical = CanonicalJson::from_document(&document)
        .unwrap_or_else(|error| panic!("canonicalization failed: {error:?}"));
    assert_eq!(
        canonical.bytes(),
        bytes.strip_suffix(b"\n").unwrap_or(bytes)
    );
    let validator =
        SchemaValidator::compile(read(&root.join(schema_path)), json_limits(16_000_000))
            .unwrap_or_else(|error| panic!("could not compile {schema_path}: {error:?}"));
    assert_eq!(validator.validate(&document), Ok(Vec::new()));
}

fn assert_canonical(bytes: &[u8]) {
    let document = StrictJsonDocument::decode(bytes.to_vec(), json_limits(16_000_000))
        .unwrap_or_else(|error| panic!("strict JSON failed: {error:?}"));
    let canonical = CanonicalJson::from_document(&document)
        .unwrap_or_else(|error| panic!("canonicalization failed: {error:?}"));
    assert_eq!(
        canonical.bytes(),
        bytes.strip_suffix(b"\n").unwrap_or(bytes)
    );
}

fn registered_requirements(root: &Path) -> BTreeSet<String> {
    let registry: Value = read_json(&root.join(REQUIREMENTS_PATH));
    registry["requirements"]
        .as_array()
        .unwrap_or_else(|| panic!("requirement registry has no requirements"))
        .iter()
        .map(|requirement| {
            requirement["id"]
                .as_str()
                .unwrap_or_else(|| panic!("requirement has no id"))
                .to_owned()
        })
        .collect()
}

fn validate_sorted_allowed<T>(value: &Value, allowed: &BTreeSet<T>) -> Result<(), String>
where
    T: std::borrow::Borrow<str> + Ord,
{
    let values = array(value)?;
    let mut prior = None;
    for value in values {
        let value = string(value)?;
        if prior.is_some_and(|prior| prior >= value) || !allowed.contains(value) {
            return Err("member list differs".to_owned());
        }
        prior = Some(value);
    }
    Ok(())
}

fn validate_version(value: &Value) -> Result<(), String> {
    let version = exact_object(value, &["major", "minor"])?;
    if field(version, "major")?.as_u64() != Some(1) || field(version, "minor")?.as_u64() != Some(0)
    {
        return Err("version differs".to_owned());
    }
    Ok(())
}

fn exact_object<'a>(value: &'a Value, fields: &[&str]) -> Result<&'a Map<String, Value>, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "expected object".to_owned())?;
    let actual = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = fields.iter().copied().collect::<BTreeSet<_>>();
    (actual == expected)
        .then_some(object)
        .ok_or_else(|| "object fields differ".to_owned())
}

fn field<'a>(object: &'a Map<String, Value>, name: &str) -> Result<&'a Value, String> {
    object
        .get(name)
        .ok_or_else(|| format!("missing field {name}"))
}

fn array(value: &Value) -> Result<&[Value], String> {
    value
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| "expected array".to_owned())
}

fn string(value: &Value) -> Result<&str, String> {
    value.as_str().ok_or_else(|| "expected string".to_owned())
}

fn decimal_string(value: &str) -> bool {
    value == "0"
        || (!value.starts_with('0')
            && !value.is_empty()
            && value.bytes().all(|byte| byte.is_ascii_digit()))
}

fn lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn artifact_mut(root: &mut Map<String, Value>, index: usize) -> &mut Value {
    artifacts_mut(root)
        .get_mut(index)
        .unwrap_or_else(|| unreachable!("artifact exists"))
}

fn artifacts_mut(root: &mut Map<String, Value>) -> &mut Vec<Value> {
    root.get_mut("artifacts")
        .and_then(Value::as_array_mut)
        .unwrap_or_else(|| unreachable!("artifacts are an array"))
}

fn set_artifact(root: &mut Map<String, Value>, index: usize, field: &str, value: &str) {
    artifact_mut(root, index)[field] = Value::String(value.to_owned());
}

fn copy_artifact_field(root: &mut Map<String, Value>, source: usize, target: usize, field: &str) {
    let value = artifacts_mut(root)[source][field].clone();
    artifacts_mut(root)[target][field] = value;
}

fn relative_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or_else(|_| panic!("{} is outside workspace", path.display()))
        .to_string_lossy()
        .replace('\\', "/")
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
