//! Public-facade conformance for strict JSON, exact numbers, schemas, and JCS.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use gantry::canonical_json::CanonicalJson;
use gantry::numeric::{GANTRY_INT_MAXIMUM, GantryFloat, GantryInt};
use gantry::portable::DeterministicEvaluationCode;
use gantry::schema::SchemaValidator;
use gantry::strict_json::{JsonError, JsonLimitKind, JsonLimits, JsonNode, StrictJsonDocument};
use serde::Deserialize;

const JSON_EVIDENCE: &str = "crates/gantry-conformance/tests/value_kernel.rs#public_strict_json_numbers_and_canonical_identity_match_goldens";
const SCHEMA_EVIDENCE: &str = "crates/gantry-conformance/tests/value_kernel.rs#public_schema_and_resource_boundaries_are_exact_and_stack_safe";
const NUMERIC_EVIDENCE: &str = "crates/gantry-conformance/tests/value_kernel.rs#public_numeric_primitives_return_exact_portable_failures";

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
struct ValueVectors {
    format: String,
    canonical_input: String,
    canonical_output: String,
    canonical_sha256: String,
    rfc8785_input: String,
    rfc8785_output: String,
    float_cases: Vec<FloatCase>,
    rejected_floats: Vec<String>,
    schema_cases: Vec<SchemaCase>,
    integer_equivalents: Vec<String>,
    invalid_json: Vec<InvalidJsonCase>,
}

#[derive(Debug, Deserialize)]
struct FloatCase {
    input: String,
    canonical: String,
}

#[derive(Debug, Deserialize)]
struct SchemaCase {
    schema: String,
    valid: Vec<String>,
    invalid: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct InvalidJsonCase {
    input: String,
    category: String,
}

#[test]
fn reviewed_value_kernel_evidence_is_closed() {
    let root = workspace_root();
    let manifest: EvidenceManifest =
        read_json(&root.join("protocol/conformance/value-kernel-v1.json"));
    let review: RequirementReview = read_json(&root.join("protocol/requirements/reviewed-v1.json"));

    assert_eq!(manifest.format, "gantry.value-kernel-evidence/v1");
    assert_eq!(manifest.issue, "GNT-VAL-001");
    assert!(gantry_conformance::evidence_revision_is_expected(
        &manifest.specification_sha256,
        &review.specification_sha256,
    ));
    assert!(manifest.entries.windows(2).all(|pair| pair[0] < pair[1]));

    let mut entries = BTreeMap::<(String, String, String), Vec<String>>::new();
    for entry in manifest.entries {
        assert!(matches!(
            entry.evidence.as_str(),
            JSON_EVIDENCE
                | SCHEMA_EVIDENCE
                | NUMERIC_EVIDENCE
                | "crates/gantry-conformance/tests/analyzer_workflow_facts.rs#public_workflow_effect_schema_and_inventory_contracts"
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
fn public_strict_json_numbers_and_canonical_identity_match_goldens() {
    let vectors: ValueVectors =
        read_json(&workspace_root().join("protocol/goldens/value-kernel-v1.json"));
    assert_eq!(vectors.format, "gantry.value-kernel-vectors/v1");

    let document = decode(vectors.canonical_input.as_bytes());
    let canonical = CanonicalJson::from_document(&document)
        .unwrap_or_else(|error| panic!("canonicalization failed: {error:?}"));
    assert_eq!(canonical.bytes(), vectors.canonical_output.as_bytes());
    assert_eq!(canonical.sha256_hex(), vectors.canonical_sha256);

    let rfc8785 = CanonicalJson::from_document(&decode(vectors.rfc8785_input.as_bytes()))
        .unwrap_or_else(|error| panic!("RFC 8785 sample failed: {error:?}"));
    assert_eq!(rfc8785.bytes(), vectors.rfc8785_output.as_bytes());

    for case in vectors.float_cases {
        let canonical = CanonicalJson::from_document(&decode(case.input.as_bytes()))
            .unwrap_or_else(|error| panic!("float vector failed for {}: {error:?}", case.input));
        assert_eq!(
            canonical.bytes(),
            case.canonical.as_bytes(),
            "{}",
            case.input
        );
    }
    for source in vectors.rejected_floats {
        assert!(
            CanonicalJson::from_document(&decode(source.as_bytes())).is_err(),
            "{source}"
        );
    }

    for spelling in vectors.integer_equivalents {
        let document = decode(spelling.as_bytes());
        let Some(JsonNode::Number(number)) = document.node(document.root()) else {
            unreachable!("integer vector is numeric")
        };
        assert_eq!(number.to_gantry_int(), Ok(1), "{spelling}");
    }

    for invalid in vectors.invalid_json {
        let result = StrictJsonDocument::decode(invalid.input.as_bytes(), limits());
        let exact_category = match invalid.category.as_str() {
            "duplicate-member" => matches!(result, Err(JsonError::DuplicateMember { .. })),
            "trailing-data" => matches!(result, Err(JsonError::TrailingData { .. })),
            "unpaired-surrogate" => matches!(result, Err(JsonError::UnpairedSurrogate { .. })),
            _ => unreachable!("closed invalid JSON category"),
        };
        assert!(exact_category, "{}: {result:?}", invalid.input);
    }

    let mut byte_limited = limits();
    byte_limited.maximum_bytes = 0;
    assert!(matches!(
        StrictJsonDocument::decode(&[0xff][..], byte_limited),
        Err(JsonError::ResourceLimit {
            kind: JsonLimitKind::Bytes,
            limit: 0,
            observed: Some(1)
        })
    ));
}

#[test]
fn public_schema_and_resource_boundaries_are_exact_and_stack_safe() {
    let vectors: ValueVectors =
        read_json(&workspace_root().join("protocol/goldens/value-kernel-v1.json"));
    for case in vectors.schema_cases {
        let validator = SchemaValidator::compile(case.schema.as_bytes(), limits())
            .unwrap_or_else(|error| panic!("schema vector failed: {error:?}"));
        for valid in case.valid {
            assert_eq!(
                validator.validate(&decode(valid.as_bytes())),
                Ok(Vec::new())
            );
        }
        for invalid in case.invalid {
            assert!(
                !validator
                    .validate(&decode(invalid.as_bytes()))
                    .unwrap_or_else(|error| panic!("validation failed: {error:?}"))
                    .is_empty(),
                "{invalid}"
            );
        }
    }

    let schema = br##"{
        "$defs":{"node":{"anyOf":[{"type":"null"},{"type":"array","items":{"$ref":"#/$defs/node"}}]}},
        "$ref":"#/$defs/node"
    }"##;
    let validator = SchemaValidator::compile(&schema[..], limits())
        .unwrap_or_else(|error| panic!("schema failed: {error:?}"));
    let depth = 4_096;
    let mut source = "[".repeat(depth);
    source.push_str("null");
    source.push_str(&"]".repeat(depth));
    let instance = decode(source.as_bytes());
    assert_eq!(validator.validate(&instance), Ok(Vec::new()));

    let mut bounded = limits();
    bounded.maximum_string_scalars = 1;
    assert!(matches!(
        StrictJsonDocument::decode("[\"éx\"]".as_bytes(), bounded),
        Err(JsonError::ResourceLimit {
            kind: JsonLimitKind::StringScalars,
            limit: 1,
            observed: Some(2)
        })
    ));
    bounded = limits();
    bounded.maximum_list_items = 1;
    assert!(matches!(
        StrictJsonDocument::decode(&b"[null,true]"[..], bounded),
        Err(JsonError::ResourceLimit {
            kind: JsonLimitKind::ListItems,
            limit: 1,
            observed: Some(2)
        })
    ));

    bounded = limits();
    bounded.maximum_nesting_depth = 1;
    assert!(matches!(
        StrictJsonDocument::decode(&b"[null]"[..], bounded),
        Err(JsonError::ResourceLimit {
            kind: JsonLimitKind::NestingDepth,
            limit: 1,
            observed: Some(2)
        })
    ));

    bounded = limits();
    bounded.maximum_nodes = 1;
    assert!(matches!(
        StrictJsonDocument::decode(&b"[null]"[..], bounded),
        Err(JsonError::ResourceLimit {
            kind: JsonLimitKind::Nodes,
            limit: 1,
            observed: Some(2)
        })
    ));
}

#[test]
fn public_numeric_primitives_return_exact_portable_failures() {
    let maximum =
        GantryInt::new(GANTRY_INT_MAXIMUM).unwrap_or_else(|| unreachable!("maximum is admitted"));
    let one = GantryInt::new(1).unwrap_or_else(|| unreachable!("one is admitted"));
    let zero = GantryInt::new(0).unwrap_or_else(|| unreachable!("zero is admitted"));
    assert_eq!(
        maximum.checked_add(one),
        Err(DeterministicEvaluationCode::IntegerOverflow)
    );
    assert_eq!(
        one.checked_div(zero),
        Err(DeterministicEvaluationCode::IntegerDivisionByZero)
    );
    let seven = GantryInt::new(7).unwrap_or_else(|| unreachable!("seven is admitted"));
    let negative_three =
        GantryInt::new(-3).unwrap_or_else(|| unreachable!("negative three is admitted"));
    assert_eq!(
        seven.checked_div(negative_three).map(GantryInt::get),
        Ok(-2)
    );
    assert_eq!(seven.checked_rem(negative_three).map(GantryInt::get), Ok(1));

    let float_one = GantryFloat::new(1.0).unwrap_or_else(|| unreachable!("one is finite"));
    let float_zero = GantryFloat::new(-0.0).unwrap_or_else(|| unreachable!("zero is finite"));
    assert_eq!(
        float_one.checked_div(float_zero),
        Err(DeterministicEvaluationCode::FloatDivisionByZero)
    );
    assert_eq!(float_zero.canonical_string(), "0");
    let maximum = GantryFloat::new(f64::MAX).unwrap_or_else(|| unreachable!("maximum is finite"));
    assert_eq!(
        maximum.checked_mul(maximum),
        Err(DeterministicEvaluationCode::FloatNonFiniteResult)
    );
    let half = GantryFloat::new(0.5).unwrap_or_else(|| unreachable!("half is finite"));
    assert_eq!(half.to_int(), None);
    assert_eq!(float_one.to_int().map(GantryInt::get), Some(1));
}

fn decode(source: &[u8]) -> StrictJsonDocument {
    StrictJsonDocument::decode(source, limits())
        .unwrap_or_else(|error| panic!("strict JSON failed: {error:?}"))
}

fn limits() -> JsonLimits {
    JsonLimits {
        maximum_bytes: 1_000_000,
        maximum_nesting_depth: 10_000,
        maximum_nodes: 20_000,
        maximum_string_scalars: 1_000_000,
        maximum_list_items: 20_000,
    }
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
