//! Independent validation of the canonical Gantry publication-index contract.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use gantry::canonical_json::CanonicalJson;
use gantry::schema::SchemaValidator;
use gantry::strict_json::{JsonLimits, StrictJsonDocument};
use serde::Deserialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

const INDEX_PATH: &str = "protocol/goldens/publication-index-v1.canonical.json";
const NEGATIVES_PATH: &str = "protocol/goldens/publication-index-v1.negatives.json";
const SCHEMA_PATH: &str = "protocol/schemas/publication-index-v1.schema.json";

const REQUIRED_ARTIFACTS: [&str; 7] = [
    "gantry.authoring",
    "gantry.conformance",
    "gantry.embedding",
    "gantry.ir",
    "gantry.journal",
    "gantry.spec",
    "gantry.values",
];

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
fn canonical_publication_index_fixture_is_exact_and_complete() {
    let root = workspace_root();
    let bytes = read(&root.join(INDEX_PATH));
    let schema = read(&root.join(SCHEMA_PATH));
    let document = decode(&bytes);
    let canonical = CanonicalJson::from_document(&document)
        .unwrap_or_else(|error| panic!("index canonicalization failed: {error:?}"));
    assert_eq!(
        canonical.bytes(),
        bytes.strip_suffix(b"\n").unwrap_or(&bytes)
    );

    let validator = SchemaValidator::compile(schema, json_limits(2_000_000))
        .unwrap_or_else(|error| panic!("publication schema failed: {error:?}"));
    assert_eq!(validator.validate(&document), Ok(Vec::new()));

    let index: Value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|error| panic!("publication fixture failed: {error}"));
    assert_eq!(validate_index(&root, &index), Ok(()));
}

#[test]
fn publication_index_negative_fixtures_are_all_rejected() {
    let root = workspace_root();
    let source: Value = serde_json::from_slice(&read(&root.join(INDEX_PATH)))
        .unwrap_or_else(|error| panic!("publication fixture failed: {error}"));
    let negatives: NegativeVectors = read_json(&root.join(NEGATIVES_PATH));
    assert_eq!(negatives.format, "gantry.publication-index-negatives/v1");
    assert_eq!(negatives.cases.len(), 20);
    assert!(
        negatives
            .cases
            .windows(2)
            .all(|pair| pair[0].name < pair[1].name)
    );

    for case in negatives.cases {
        let mutated = mutate(&source, &case.mutation);
        assert!(
            validate_index(&root, &mutated).is_err(),
            "accepted negative publication fixture {} ({})",
            case.name,
            case.mutation
        );
    }
}

fn validate_index(root: &Path, index: &Value) -> Result<(), String> {
    let object = exact_object(
        index,
        &[
            "artifacts",
            "publication_index",
            "publication_revision",
            "source_language",
        ],
    )?;
    validate_version(field(object, "publication_index")?)?;
    validate_version(field(object, "source_language")?)?;
    let revision = string(field(object, "publication_revision")?)?;
    if revision.is_empty() {
        return Err("publication revision is empty".to_owned());
    }

    let requirements = registered_requirements(root)?;
    let requirement_names = requirements
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let profiles = BTreeSet::from([
        "analyzer",
        "concurrent-evaluator",
        "durable-runtime",
        "embedding",
        "evaluator",
        "frontend",
    ]);
    let protocols = BTreeSet::from([
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
    ]);
    let artifacts = array(field(object, "artifacts")?)?;
    if artifacts.len() != REQUIRED_ARTIFACTS.len() {
        return Err("publication artifact set is incomplete".to_owned());
    }

    let mut ids = BTreeSet::new();
    let mut uris = BTreeSet::new();
    let mut defined_protocols = BTreeSet::new();
    let mut prior_id: Option<&str> = None;
    for (index, artifact) in artifacts.iter().enumerate() {
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
        if REQUIRED_ARTIFACTS.get(index) != Some(&id)
            || prior_id.is_some_and(|prior| prior >= id)
            || !ids.insert(id)
        {
            return Err("artifact identifiers are missing, duplicated, or unordered".to_owned());
        }
        prior_id = Some(id);

        let uri = string(field(artifact, "uri")?)?;
        if !uri.starts_with("https://") || !uri.contains("/v1/") || !uris.insert(uri) {
            return Err("artifact URI is not absolute, versioned, and unique".to_owned());
        }
        let media_type = string(field(artifact, "media_type")?)?;
        if media_type.split_once('/').is_none()
            || media_type.bytes().any(|byte| byte.is_ascii_uppercase())
        {
            return Err("artifact media type is invalid".to_owned());
        }
        let byte_length = string(field(artifact, "byte_length")?)?;
        if !decimal_string(byte_length) || byte_length != "0" {
            return Err("fixture artifact length differs".to_owned());
        }
        let sha256 = string(field(artifact, "sha256")?)?;
        if !lowercase_sha256(sha256) || sha256 != format!("{:x}", Sha256::digest([])) {
            return Err("fixture artifact digest differs".to_owned());
        }

        validate_sorted_members(field(artifact, "profiles")?, &profiles, "profile")?;
        validate_sorted_members(
            field(artifact, "requirements")?,
            &requirement_names,
            "requirement",
        )?;
        let declared_protocols = array(field(artifact, "protocols")?)?;
        let mut prior_family: Option<&str> = None;
        for protocol in declared_protocols {
            let protocol = exact_object(protocol, &["family", "major", "minor"])?;
            let family = string(field(protocol, "family")?)?;
            if prior_family.is_some_and(|prior| prior >= family)
                || !protocols.contains(family)
                || !defined_protocols.insert(family)
            {
                return Err("protocol definitions are unknown, duplicated, or unordered".to_owned());
            }
            prior_family = Some(family);
            if field(protocol, "major")?.as_u64() != Some(1)
                || field(protocol, "minor")?.as_u64() != Some(0)
            {
                return Err("protocol version is not exactly 1.0".to_owned());
            }
        }
    }
    if ids != REQUIRED_ARTIFACTS.into_iter().collect() || defined_protocols != protocols {
        return Err("publication does not define the exact artifact and protocol sets".to_owned());
    }
    if object.contains_key("active_index_digest") {
        return Err("publication recursively embeds its active index".to_owned());
    }
    Ok(())
}

fn mutate(source: &Value, mutation: &str) -> Value {
    let mut value = source.clone();
    let root = value
        .as_object_mut()
        .unwrap_or_else(|| unreachable!("fixture root is an object"));
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
        "reverse-requirement-order" => {
            artifact_mut(root, 0)["requirements"] =
                serde_json::json!(["GNT-15.8-publication-integrity", "GNT-15.8"]);
        }
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
            "https://gantry.example/publication/gantry.authoring.json",
        ),
        "wrong-byte-length" => set_artifact(root, 0, "byte_length", "1"),
        "wrong-digest" => set_artifact(root, 0, "sha256", &"0".repeat(64)),
        "wrong-index-version" => root["publication_index"]["major"] = Value::from(2),
        other => panic!("unknown publication mutation {other}"),
    }
    value
}

fn registered_requirements(root: &Path) -> Result<BTreeSet<String>, String> {
    let registry: Value =
        read_json(&root.join("protocol/requirements/generated/requirements-v1.json"));
    let requirements = array(
        registry
            .get("requirements")
            .ok_or_else(|| "requirement registry has no requirements".to_owned())?,
    )?;
    requirements
        .iter()
        .map(|requirement| {
            requirement
                .get("id")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| "requirement registry contains an invalid ID".to_owned())
        })
        .collect()
}

fn validate_sorted_members(
    value: &Value,
    allowed: &BTreeSet<&str>,
    kind: &str,
) -> Result<(), String> {
    let values = array(value)?;
    let mut prior: Option<&str> = None;
    for value in values {
        let value = string(value)?;
        if prior.is_some_and(|prior| prior >= value) || !allowed.contains(value) {
            return Err(format!(
                "{kind} values are unknown, duplicated, or unordered"
            ));
        }
        prior = Some(value);
    }
    Ok(())
}

fn validate_version(value: &Value) -> Result<(), String> {
    let version = exact_object(value, &["major", "minor"])?;
    if field(version, "major")?.as_u64() != Some(1) || field(version, "minor")?.as_u64() != Some(0)
    {
        return Err("version is not exactly 1.0".to_owned());
    }
    Ok(())
}

fn exact_object<'a>(value: &'a Value, fields: &[&str]) -> Result<&'a Map<String, Value>, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "expected a JSON object".to_owned())?;
    let actual = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = fields.iter().copied().collect::<BTreeSet<_>>();
    (actual == expected)
        .then_some(object)
        .ok_or_else(|| "object fields differ from the closed contract".to_owned())
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
        .ok_or_else(|| "expected a JSON array".to_owned())
}

fn string(value: &Value) -> Result<&str, String> {
    value
        .as_str()
        .ok_or_else(|| "expected a JSON string".to_owned())
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
        .unwrap_or_else(|| unreachable!("fixture artifact exists"))
}

fn artifacts_mut(root: &mut Map<String, Value>) -> &mut Vec<Value> {
    root.get_mut("artifacts")
        .and_then(Value::as_array_mut)
        .unwrap_or_else(|| unreachable!("fixture artifacts are an array"))
}

fn set_artifact(root: &mut Map<String, Value>, index: usize, field: &str, value: &str) {
    artifact_mut(root, index)[field] = Value::String(value.to_owned());
}

fn copy_artifact_field(root: &mut Map<String, Value>, source: usize, target: usize, field: &str) {
    let value = artifacts_mut(root)[source][field].clone();
    artifacts_mut(root)[target][field] = value;
}

fn decode(bytes: &[u8]) -> StrictJsonDocument {
    StrictJsonDocument::decode(bytes, json_limits(2_000_000))
        .unwrap_or_else(|error| panic!("strict JSON failed: {error:?}"))
}

fn json_limits(maximum: u64) -> JsonLimits {
    JsonLimits {
        maximum_bytes: maximum,
        maximum_nesting_depth: maximum,
        maximum_nodes: maximum,
        maximum_string_scalars: maximum,
        maximum_list_items: maximum,
    }
}

fn read(path: &Path) -> Vec<u8> {
    fs::read(path).unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()))
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> T {
    serde_json::from_slice(&read(path))
        .unwrap_or_else(|error| panic!("could not decode {}: {error}", path.display()))
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}
