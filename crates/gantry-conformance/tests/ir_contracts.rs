//! Public-facade conformance for canonical analyzer/runtime contracts.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use gantry::ir::generated::{ArtifactKind, CoreForm, Effect, OperationSiteKind};
use gantry::ir::{
    ArtifactEncodingError, ArtifactLimits, CanonicalIr, CanonicalNode, CanonicalOperationSite,
    CanonicalPath, CanonicalSignature, CanonicalSourceMap, CanonicalWorkflow,
    GeneratedSchemaObject, PackageSourceManifest, SourceMapEntry, StructuralPosition,
    TypeDescriptor,
};
use gantry::protocol::ProtocolVersion;
use gantry::source::{ByteSpan, SourceLimits, SourceSnapshotBuilder, SourceSpan};
use serde::Deserialize;

const CONTRACT_EVIDENCE: &str = "crates/gantry-conformance/tests/ir_contracts.rs#canonical_paths_types_signatures_and_effects_match_the_public_contract";

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
struct IrVectors {
    format: String,
    canonical_ir: String,
    source_map: String,
    package_source_manifest: String,
    generated_schema_object: String,
    negative_cases: Vec<NegativeCase>,
}

#[derive(Debug, Deserialize)]
struct NegativeCase {
    name: String,
    expected_error: String,
}

#[test]
fn reviewed_analyzer_ir_contract_evidence_is_closed() {
    let root = workspace_root();
    let manifest: EvidenceManifest =
        read_json(&root.join("protocol/conformance/analyzer-ir-v1.json"));
    let review: RequirementReview = read_json(&root.join("protocol/requirements/reviewed-v1.json"));

    assert_eq!(manifest.format, "gantry.analyzer-ir-evidence/v1");
    assert_eq!(manifest.issue, "GNT-AN-001");
    assert_eq!(manifest.specification_sha256, review.specification_sha256);
    assert!(manifest.entries.windows(2).all(|pair| pair[0] < pair[1]));

    for entry in manifest.entries {
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
        assert_eq!(analyzer.evidence, [CONTRACT_EVIDENCE]);
    }
}

#[test]
fn canonical_paths_types_signatures_and_effects_match_the_public_contract() {
    let report_path = CanonicalPath::new("crate::domain::Report")
        .unwrap_or_else(|_| unreachable!("constant path is canonical"));
    let report = TypeDescriptor::declared(report_path.clone());
    let result = TypeDescriptor::result(
        TypeDescriptor::list(report.clone()),
        TypeDescriptor::option(TypeDescriptor::STRING)
            .unwrap_or_else(|_| unreachable!("String is an option member")),
    );
    assert_eq!(
        result.canonical_string(),
        "Result<List<crate::domain::Report>,Option<String>>"
    );
    assert!(!result.contains_sealed_boundary());

    let signature = CanonicalSignature::function(
        &CanonicalPath::new("crate::main")
            .unwrap_or_else(|_| unreachable!("constant path is canonical")),
        &[gantry::ir::WorkflowParameter {
            mutable: false,
            ty: TypeDescriptor::STRING,
        }],
        &report,
    );
    assert_eq!(
        signature.as_str(),
        "fn crate::main(String)->crate::domain::Report"
    );

    let mut effects = gantry::ir::EffectSet::default();
    assert!(effects.insert(Effect::Attempt));
    assert!(effects.insert(Effect::Prompt));
    assert_eq!(
        effects.iter().map(Effect::wire_name).collect::<Vec<_>>(),
        ["prompt", "attempt"]
    );
}

#[test]
fn ir_schemas_and_catalog_are_versioned_and_closed() {
    let root = protocol_root();
    let catalog: serde_json::Value = read_json(&root.join("catalogs/ir-contracts-v1.json"));
    let golden: serde_json::Value = read_json(&root.join("goldens/ir-contracts-v1.canonical.json"));
    assert_eq!(catalog, golden);
    assert_eq!(catalog["catalog"], "gantry.ir-contracts");
    assert_eq!(
        (catalog["major"].as_u64(), catalog["minor"].as_u64()),
        (Some(1), Some(0))
    );

    for (file, id) in [
        (
            "canonical-ir-v1.schema.json",
            "https://gantry.invalid/protocol/canonical-ir/v1/schema.json",
        ),
        (
            "generated-schema-object-v1.schema.json",
            "https://gantry.invalid/protocol/generated-schema-object/v1/schema.json",
        ),
        (
            "package-source-manifest-v1.schema.json",
            "https://gantry.invalid/protocol/package-source-manifest/v1/schema.json",
        ),
        (
            "source-map-v1.schema.json",
            "https://gantry.invalid/protocol/source-map/v1/schema.json",
        ),
    ] {
        let schema: serde_json::Value = read_json(&root.join("schemas").join(file));
        assert_eq!(
            schema["$schema"],
            "https://json-schema.org/draft/2020-12/schema"
        );
        assert_eq!(schema["$id"], id);
        assert_eq!(schema["type"], "object");
    }
}

#[test]
fn canonical_artifact_vectors_match_the_public_facade() {
    let vectors: IrVectors =
        read_json(&protocol_root().join("goldens/ir-artifact-vectors-v1.json"));
    assert_eq!(vectors.format, "gantry.ir-artifact-vectors/v1");
    let (ir, source_map, manifest, schemas) = artifacts(4_096);
    assert_eq!(
        std::str::from_utf8(ir.artifact().canonical_bytes()),
        Ok(vectors.canonical_ir.as_str())
    );
    assert_eq!(
        std::str::from_utf8(source_map.artifact().canonical_bytes()),
        Ok(vectors.source_map.as_str())
    );
    assert_eq!(
        std::str::from_utf8(manifest.artifact().canonical_bytes()),
        Ok(vectors.package_source_manifest.as_str())
    );
    assert_eq!(
        std::str::from_utf8(schemas.artifact().canonical_bytes()),
        Ok(vectors.generated_schema_object.as_str())
    );
    assert_eq!(ir.artifact().kind(), ArtifactKind::CanonicalIr);
    assert_eq!(source_map.artifact().kind(), ArtifactKind::SourceMap);
    assert_eq!(
        manifest.artifact().kind(),
        ArtifactKind::PackageSourceManifest
    );
    assert_eq!(
        schemas.artifact().kind(),
        ArtifactKind::GeneratedSchemaObject
    );
    assert_eq!(ir.artifact().sha256_hex().len(), 64);
}

#[test]
fn canonical_contract_negatives_and_limits_fail_closed() {
    let vectors: IrVectors =
        read_json(&protocol_root().join("goldens/ir-artifact-vectors-v1.json"));
    let names = vectors
        .negative_cases
        .iter()
        .map(|case| (case.name.as_str(), case.expected_error.as_str()))
        .collect::<BTreeSet<_>>();
    assert_eq!(names.len(), 5);
    assert!(names.contains(&("invalid-canonical-path", "not-crate-rooted")));
    assert!(CanonicalPath::new("self::item").is_err());
    assert!(TypeDescriptor::option(TypeDescriptor::UNIT).is_err());
    assert!(TypeDescriptor::tuple(vec![TypeDescriptor::INT]).is_err());

    let duplicate = vec![
        (
            TypeDescriptor::BOOL,
            Arc::from(&b"{\"type\":\"boolean\"}"[..]),
        ),
        (
            TypeDescriptor::BOOL,
            Arc::from(&b"{\"type\":\"boolean\"}"[..]),
        ),
    ];
    assert!(GeneratedSchemaObject::new(duplicate, limits(4_096)).is_err());

    let (ir, _, _, _) = artifacts(4_096);
    assert!(matches!(
        gantry::ir::BoundedArtifact::from_validated_canonical_bytes(
            ArtifactKind::CanonicalIr,
            ir.artifact().canonical_bytes().to_vec(),
            limits(1),
        ),
        Err(ArtifactEncodingError::ResourceLimit(_))
    ));
}

fn artifacts(
    limit: u64,
) -> (
    CanonicalIr,
    CanonicalSourceMap,
    PackageSourceManifest,
    GeneratedSchemaObject,
) {
    let limits = limits(limit);
    let path = CanonicalPath::new("crate::main")
        .unwrap_or_else(|_| unreachable!("constant path is canonical"));
    let signature = CanonicalSignature::function(&path, &[], &TypeDescriptor::UNIT);
    let mut effects = gantry::ir::EffectSet::default();
    assert!(effects.insert(Effect::Attempt));
    assert!(effects.insert(Effect::Prompt));
    let position =
        StructuralPosition::new(vec![0]).unwrap_or_else(|_| unreachable!("position is nonempty"));
    let node = CanonicalNode {
        position: position.clone(),
        form: CoreForm::Operation,
        ty: TypeDescriptor::UNIT,
        children: Vec::new(),
        operation: Some(CanonicalOperationSite {
            kind: OperationSiteKind::Prompt,
            action: None,
            recovery: None,
            template_segments: Vec::new(),
            interpolation_inputs: Vec::new(),
            named_input_names: Vec::new(),
            named_inputs: Vec::new(),
        }),
        task_control: None,
    };
    let workflow = CanonicalWorkflow::new(path.clone(), signature, effects, vec![node])
        .unwrap_or_else(|_| unreachable!("workflow is canonical"));
    let ir = CanonicalIr::new(vec![workflow], limits).unwrap_or_else(|_| unreachable!("IR fits"));

    let source_limits =
        SourceLimits::new(1, 64, 64, 1, 1).unwrap_or_else(|_| unreachable!("positive limits"));
    let mut builder = SourceSnapshotBuilder::new(source_limits);
    let source = builder.add_file("main.gnt", b"fn main() {}");
    assert!(source.is_ok());
    let snapshot = builder.finish();
    let record = snapshot
        .get(&source.unwrap_or_else(|_| unreachable!("checked above")))
        .unwrap_or_else(|| unreachable!("source is retained"));
    let span = SourceSpan::new(
        record,
        ByteSpan::new(3, 7).unwrap_or_else(|_| unreachable!("ordered span")),
    )
    .unwrap_or_else(|_| unreachable!("span is in bounds"));
    let source_map = CanonicalSourceMap::new(
        vec![SourceMapEntry {
            workflow: path,
            position,
            source: span,
        }],
        limits,
    )
    .unwrap_or_else(|_| unreachable!("source map fits"));
    let manifest = PackageSourceManifest::from_snapshot(
        &snapshot,
        ProtocolVersion { major: 1, minor: 0 },
        limits,
    )
    .unwrap_or_else(|_| unreachable!("manifest fits"));
    let schemas = GeneratedSchemaObject::new(
        vec![
            (
                TypeDescriptor::BOOL,
                Arc::from(&b"{\"type\":\"boolean\"}"[..]),
            ),
            (
                TypeDescriptor::STRING,
                Arc::from(&b"{\"type\":\"string\"}"[..]),
            ),
        ],
        limits,
    )
    .unwrap_or_else(|_| unreachable!("schema object fits"));
    (ir, source_map, manifest, schemas)
}

fn limits(limit: u64) -> ArtifactLimits {
    ArtifactLimits {
        package_source_manifest_bytes: limit,
        canonical_ir_bytes: limit,
        source_map_bytes: limit,
        generated_schema_bytes: limit,
    }
}

fn protocol_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("protocol")
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
