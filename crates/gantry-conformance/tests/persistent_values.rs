//! Public-facade conformance for persistent logical values and depth-safe traversal.

use std::collections::BTreeMap;
use std::collections::hash_map::DefaultHasher;
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use gantry::schema::SchemaValidator;
use gantry::strict_json::JsonLimits;
use gantry::value::{
    DEFAULT_VALUE_LIMITS, LogicalValue, ValueError, ValueLimitKind, ValueLimits, ValuePathSegment,
    ValueRoot,
};
use serde::Deserialize;

const STORAGE_EVIDENCE: &str = "crates/gantry-conformance/tests/persistent_values.rs#public_persistent_values_are_representation_independent_and_nonaliasing";
const TRAVERSAL_EVIDENCE: &str = "crates/gantry-conformance/tests/persistent_values.rs#public_value_limits_and_all_traversals_are_depth_safe";

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
    profile: String,
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

#[derive(Debug, Deserialize)]
struct PersistentValueVectors {
    format: String,
    original_canonical: String,
    original_sha256: String,
    updated_canonical: String,
    updated_sha256: String,
    metrics: MetricsVector,
    deep_nesting: u64,
}

#[derive(Debug, Deserialize)]
struct MetricsVector {
    nesting_depth: u64,
    nodes: u64,
    maximum_string_scalars: u64,
    maximum_list_items: u64,
}

#[test]
fn reviewed_persistent_value_evidence_is_closed() {
    let root = workspace_root();
    let manifest: EvidenceManifest =
        read_json(&root.join("protocol/conformance/persistent-values-v1.json"));
    let review: RequirementReview = read_json(&root.join("protocol/requirements/reviewed-v1.json"));

    assert_eq!(manifest.format, "gantry.persistent-values-evidence/v1");
    assert_eq!(manifest.issue, "GNT-VAL-002");
    assert_eq!(manifest.specification_sha256, review.specification_sha256);
    assert!(manifest.entries.windows(2).all(|pair| pair[0] < pair[1]));

    let mut entries = BTreeMap::<(String, String, String), Vec<String>>::new();
    for entry in manifest.entries {
        assert!(matches!(
            entry.evidence.as_str(),
            STORAGE_EVIDENCE | TRAVERSAL_EVIDENCE
        ));
        entries
            .entry((entry.requirement, entry.clause, entry.profile))
            .or_default()
            .push(entry.evidence);
    }

    for ((requirement, clause_key, profile_name), evidence) in entries {
        let clause = review
            .requirements
            .iter()
            .find(|candidate| candidate.id == requirement)
            .and_then(|requirement| {
                requirement
                    .clauses
                    .iter()
                    .find(|clause| clause.key == clause_key)
            })
            .unwrap_or_else(|| panic!("missing {requirement}:{clause_key}"));
        let profile = clause
            .profile_reviews
            .iter()
            .find(|profile| profile.profile == profile_name)
            .unwrap_or_else(|| {
                panic!("missing {profile_name} review for {requirement}:{clause_key}")
            });
        assert_eq!(profile.state, "covered");
        assert_eq!(profile.evidence, evidence);
    }
}

#[test]
fn public_persistent_values_are_representation_independent_and_nonaliasing() {
    let vectors: PersistentValueVectors =
        read_json(&workspace_root().join("protocol/goldens/persistent-values-v1.json"));
    assert_eq!(vectors.format, "gantry.persistent-values-vectors/v1");

    let original = fixture();
    let metrics = original.metrics();
    assert_eq!(metrics.nesting_depth, vectors.metrics.nesting_depth);
    assert_eq!(metrics.nodes, vectors.metrics.nodes);
    assert_eq!(
        metrics.maximum_string_scalars,
        vectors.metrics.maximum_string_scalars
    );
    assert_eq!(
        metrics.maximum_list_items,
        vectors.metrics.maximum_list_items
    );
    assert_canonical(
        &original,
        &vectors.original_canonical,
        &vectors.original_sha256,
    );

    let independent = original.clone();
    let detached = original
        .detached_copy(DEFAULT_VALUE_LIMITS)
        .unwrap_or_else(|error| panic!("detached copy failed: {error:?}"));
    assert_eq!(original, detached);
    assert_eq!(hash(&original), hash(&detached));
    assert_eq!(original.canonical_json(), detached.canonical_json());

    let root = ValueRoot::new(original, DEFAULT_VALUE_LIMITS)
        .unwrap_or_else(|error| panic!("root admission failed: {error:?}"));
    let updated = root
        .replace(
            &[
                ValuePathSegment::StructField("values".to_owned()),
                ValuePathSegment::ListItem(0),
                ValuePathSegment::StructField("flag".to_owned()),
            ],
            &LogicalValue::boolean(true),
            DEFAULT_VALUE_LIMITS,
        )
        .unwrap_or_else(|error| panic!("path replacement failed: {error:?}"));
    assert_canonical(
        &updated,
        &vectors.updated_canonical,
        &vectors.updated_sha256,
    );
    assert_canonical(
        &independent,
        &vectors.original_canonical,
        &vectors.original_sha256,
    );

    let before_failure = root.snapshot();
    let too_small = ValueLimits::new(3, 12, 5, 2)
        .unwrap_or_else(|| unreachable!("fixture limits are positive"));
    assert!(matches!(
        root.replace(
            &[ValuePathSegment::StructField("status".to_owned())],
            &fixture_status(),
            too_small,
        ),
        Err(ValueError::ResourceLimit { .. })
    ));
    assert_eq!(root.snapshot(), before_failure);

    let shared = Arc::new(detached);
    let task_capture = Arc::clone(&shared);
    std::thread::spawn(move || {
        assert_eq!(
            task_capture.canonical_json().sha256_hex(),
            vectors.original_sha256
        );
    })
    .join()
    .unwrap_or_else(|_| panic!("value capture thread panicked"));
}

#[test]
fn public_value_limits_and_all_traversals_are_depth_safe() {
    let vectors: PersistentValueVectors =
        read_json(&workspace_root().join("protocol/goldens/persistent-values-v1.json"));
    let depth = vectors.deep_nesting;
    let limits = ValueLimits::new(depth + 1, depth + 1, 1, 1)
        .unwrap_or_else(|| unreachable!("fixture limits are positive"));
    let mut value = LogicalValue::unit();
    for level in 0..depth {
        value = LogicalValue::list(vec![value], limits)
            .unwrap_or_else(|error| panic!("deep construction failed at {level}: {error:?}"));
    }
    assert_eq!(value.metrics().nesting_depth, depth + 1);
    assert_eq!(value.metrics().nodes, depth + 1);

    let copy = value
        .detached_copy(limits)
        .unwrap_or_else(|error| panic!("deep copy failed: {error:?}"));
    assert_eq!(value, copy);
    assert_eq!(hash(&value), hash(&copy));
    let canonical = value.canonical_json();
    assert_eq!(canonical.bytes().len(), (depth as usize * 2) + 4);
    assert_eq!(canonical, copy.canonical_json());

    let schema = br##"{
        "$defs":{"node":{"anyOf":[{"type":"null"},{"type":"array","items":{"$ref":"#/$defs/node"}}]}},
        "$ref":"#/$defs/node"
    }"##;
    let schema_limits = JsonLimits {
        maximum_bytes: 1_000,
        maximum_nesting_depth: 16,
        maximum_nodes: 32,
        maximum_string_scalars: 128,
        maximum_list_items: 8,
    };
    let validator = SchemaValidator::compile(&schema[..], schema_limits)
        .unwrap_or_else(|error| panic!("schema compilation failed: {error:?}"));
    let instance_limits = JsonLimits {
        maximum_bytes: (depth * 2) + 4,
        maximum_nesting_depth: depth + 1,
        maximum_nodes: depth + 1,
        maximum_string_scalars: 1,
        maximum_list_items: 1,
    };
    assert_eq!(
        value.validate_schema(&validator, instance_limits),
        Ok(Vec::new())
    );

    let depth_limited = ValueLimits::new(depth, depth + 1, 1, 1)
        .unwrap_or_else(|| unreachable!("fixture limits are positive"));
    assert_eq!(
        value.validate(depth_limited),
        Err(ValueError::ResourceLimit {
            kind: ValueLimitKind::NestingDepth,
            limit: depth,
            observed: Some(depth + 1),
        })
    );
    let node_limited = ValueLimits::new(depth + 1, depth, 1, 1)
        .unwrap_or_else(|| unreachable!("fixture limits are positive"));
    assert_eq!(
        value.validate(node_limited),
        Err(ValueError::ResourceLimit {
            kind: ValueLimitKind::Nodes,
            limit: depth,
            observed: Some(depth + 1),
        })
    );

    drop(copy);
    drop(value);
}

fn fixture() -> LogicalValue {
    let shared = LogicalValue::structure(
        "crate::Item",
        vec![
            (
                "label".to_owned(),
                LogicalValue::string("é", DEFAULT_VALUE_LIMITS)
                    .unwrap_or_else(|error| panic!("string failed: {error:?}")),
            ),
            ("flag".to_owned(), LogicalValue::boolean(false)),
        ],
        DEFAULT_VALUE_LIMITS,
    )
    .unwrap_or_else(|error| panic!("item failed: {error:?}"));
    let values = LogicalValue::list(vec![shared.clone(), shared], DEFAULT_VALUE_LIMITS)
        .unwrap_or_else(|error| panic!("list failed: {error:?}"));
    LogicalValue::structure(
        "crate::Envelope",
        vec![
            ("values".to_owned(), values),
            ("status".to_owned(), fixture_status()),
        ],
        DEFAULT_VALUE_LIMITS,
    )
    .unwrap_or_else(|error| panic!("envelope failed: {error:?}"))
}

fn fixture_status() -> LogicalValue {
    let decision = LogicalValue::decision(true, "ready", DEFAULT_VALUE_LIMITS)
        .unwrap_or_else(|error| panic!("decision failed: {error:?}"));
    LogicalValue::ok(decision, DEFAULT_VALUE_LIMITS)
        .unwrap_or_else(|error| panic!("result failed: {error:?}"))
}

fn assert_canonical(value: &LogicalValue, expected: &str, expected_sha256: &str) {
    let canonical = value.canonical_json();
    assert_eq!(canonical.bytes(), expected.as_bytes());
    assert_eq!(canonical.sha256_hex(), expected_sha256);
}

fn hash(value: &LogicalValue) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
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
