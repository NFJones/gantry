//! Public-facade conformance for canonical analyzer/runtime contracts.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use gantry::canonical_json::CanonicalJson;
use gantry::ir::generated::{ArtifactKind, CoreForm, Effect, OperationSiteKind, TemplateKind};
use gantry::ir::{
    ArtifactEncodingError, ArtifactLimits, CanonicalCallableIdentity, CanonicalIr, CanonicalNode,
    CanonicalOperationSite, CanonicalPath, CanonicalSignature, CanonicalSourceMap,
    CanonicalTemplateIdentity, CanonicalWorkflow, ClosedCallable, ConcreteEffect, ConcreteIdentity,
    ConcreteInstantiation, ConcreteSourceMapEntry, ExecutableProjection, GeneratedSchemaObject,
    GenericAnalysisFacts, GenericContractError, GenericTemplate, PackageSourceManifest,
    SourceMapEntry, SourceOriginSet, StructuralPosition, TypeDescriptor, TypeExpression,
    WorkflowParameter,
};
use gantry::protocol::ProtocolVersion;
use gantry::schema::SchemaValidator;
use gantry::source::{ByteSpan, SourceLimits, SourceSnapshotBuilder, SourceSpan};
use gantry::strict_json::{JsonLimits, StrictJsonDocument};
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
    let evidence_is_current = manifest.specification_sha256 == review.specification_sha256;
    assert!(gantry_conformance::evidence_revision_is_expected(
        &manifest.specification_sha256,
        &review.specification_sha256,
    ));
    assert!(evidence_is_current || gantry::advertised_profiles().is_empty());
    assert!(manifest.entries.windows(2).all(|pair| pair[0] < pair[1]));

    for entry in manifest.entries {
        if !evidence_is_current {
            continue;
        }
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
fn generic_ir_contracts_publish_closed_instantiations_and_multi_origin_maps() {
    let preserve_path = CanonicalPath::new("crate::preserve")
        .unwrap_or_else(|_| unreachable!("constant path is canonical"));
    let parameter = TypeExpression::parameter(0, 0, 8)
        .unwrap_or_else(|_| unreachable!("bounded parameter is canonical"));
    let template_identity =
        CanonicalTemplateIdentity::free(&preserve_path, std::slice::from_ref(&parameter));
    assert_eq!(template_identity.as_str(), "crate::preserve<^0.0>");

    let template = GenericTemplate::new(
        TemplateKind::FreeWorkflow,
        template_identity.clone(),
        1,
        Vec::new(),
        gantry::ir::EffectSet::default(),
    )
    .unwrap_or_else(|_| unreachable!("template facts are canonical"));
    let callable = CanonicalCallableIdentity::free(&preserve_path, &[TypeDescriptor::STRING]);
    let instantiation = ConcreteInstantiation::new(
        TemplateKind::FreeWorkflow,
        template_identity,
        vec![TypeDescriptor::STRING],
        ConcreteIdentity::Callable(callable.clone()),
    )
    .unwrap_or_else(|_| unreachable!("closed instantiation kind matches"));
    let signature = CanonicalSignature::concrete_function(
        &callable,
        &[WorkflowParameter {
            mutable: false,
            ty: TypeDescriptor::STRING,
        }],
        &TypeDescriptor::STRING,
    );
    let closed_callable = ClosedCallable::new(
        callable.clone(),
        signature,
        gantry::ir::EffectSet::default(),
        Vec::new(),
    )
    .unwrap_or_else(|_| unreachable!("call targets are canonical"));
    let executable = ExecutableProjection::new(vec![TypeDescriptor::STRING], vec![closed_callable])
        .unwrap_or_else(|_| unreachable!("projection is closed"));

    let declaration = SourceSpan::from_portable_parts("main.gnt", 0, 18)
        .unwrap_or_else(|_| unreachable!("constant span is portable"));
    let first_origin = SourceSpan::from_portable_parts("main.gnt", 20, 35)
        .unwrap_or_else(|_| unreachable!("constant span is portable"));
    let second_origin = SourceSpan::from_portable_parts("main.gnt", 40, 55)
        .unwrap_or_else(|_| unreachable!("constant span is portable"));
    let generic_source = ConcreteSourceMapEntry::new(
        ConcreteIdentity::Callable(callable.clone()),
        declaration,
        SourceOriginSet::canonicalize(vec![
            second_origin.clone(),
            first_origin.clone(),
            first_origin,
        ]),
    );
    assert_eq!(
        generic_source.origins().origins(),
        [
            SourceSpan::from_portable_parts("main.gnt", 20, 35)
                .unwrap_or_else(|_| unreachable!("constant span is portable")),
            second_origin,
        ]
    );

    let facts = GenericAnalysisFacts::new(
        Vec::new(),
        Vec::new(),
        vec![template],
        vec![instantiation],
        Vec::new(),
        vec![ConcreteEffect {
            callable: callable.clone(),
            effects: gantry::ir::EffectSet::default(),
        }],
        vec![generic_source.clone()],
        executable,
    )
    .unwrap_or_else(|_| unreachable!("generic analysis facts are closed"));
    let ir = CanonicalIr::with_generic_facts(Vec::new(), facts, limits(8_192))
        .unwrap_or_else(|_| unreachable!("generic IR fits"));
    let ir_text = std::str::from_utf8(ir.artifact().canonical_bytes())
        .unwrap_or_else(|_| unreachable!("canonical IR is UTF-8"));
    assert!(ir_text.contains("\"identity\":\"crate::preserve<^0.0>\""));
    assert!(ir_text.contains("\"value\":\"crate::preserve<String>\""));
    assert!(ir_text.contains("\"executable_projection\":{\"callables\":["));
    assert!(!ir_text.contains("^0.0>(String)"));

    let source_map =
        CanonicalSourceMap::with_generic_entries(Vec::new(), vec![generic_source], limits(8_192))
            .unwrap_or_else(|_| unreachable!("generic source map fits"));
    let map_text = std::str::from_utf8(source_map.artifact().canonical_bytes())
        .unwrap_or_else(|_| unreachable!("source map is UTF-8"));
    assert!(map_text.contains("\"generic_entries\":[{"));
    assert_eq!(map_text.matches("\"start\":\"20\"").count(), 1);
}

#[test]
fn generic_ir_contracts_reject_open_runtime_and_noncanonical_inputs() {
    assert!(CanonicalCallableIdentity::from_canonical_string("crate::preserve<^0.0>", 8,).is_err());
    assert!(matches!(
        TypeExpression::from_canonical_string("List<^0.0>", 1),
        Err(gantry::ir::TypeExpressionError::ConstructedTypeDepth {
            limit: 1,
            observed: 2,
        })
    ));

    let repeated = SourceSpan::from_portable_parts("main.gnt", 1, 2)
        .unwrap_or_else(|_| unreachable!("constant span is portable"));
    assert_eq!(
        SourceOriginSet::from_canonical_origins(vec![repeated.clone(), repeated]),
        Err(GenericContractError::NoncanonicalOrigins)
    );

    let main_path = CanonicalPath::new("crate::main")
        .unwrap_or_else(|_| unreachable!("constant path is canonical"));
    let missing_path = CanonicalPath::new("crate::missing")
        .unwrap_or_else(|_| unreachable!("constant path is canonical"));
    let main = CanonicalCallableIdentity::free(&main_path, &[]);
    let missing = CanonicalCallableIdentity::free(&missing_path, &[]);
    let callable = ClosedCallable::new(
        main,
        CanonicalSignature::function(&main_path, &[], &TypeDescriptor::UNIT),
        gantry::ir::EffectSet::default(),
        vec![missing],
    )
    .unwrap_or_else(|_| unreachable!("direct targets are ordered"));
    assert_eq!(
        ExecutableProjection::new(vec![TypeDescriptor::UNIT], vec![callable]),
        Err(GenericContractError::MissingDirectTarget)
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
    assert_canonical_and_schema_valid(
        "canonical-ir-v1.schema.json",
        ir.artifact().canonical_bytes(),
    );
    assert_canonical_and_schema_valid(
        "source-map-v1.schema.json",
        source_map.artifact().canonical_bytes(),
    );
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

fn assert_canonical_and_schema_valid(schema_name: &str, bytes: &[u8]) {
    let document = StrictJsonDocument::decode(bytes, json_limits())
        .unwrap_or_else(|error| panic!("could not strictly decode IR artifact: {error:?}"));
    let canonical = CanonicalJson::from_document(&document)
        .unwrap_or_else(|error| panic!("could not canonicalize IR artifact: {error:?}"));
    assert_eq!(canonical.bytes(), bytes);

    let schema_path = protocol_root().join("schemas").join(schema_name);
    let schema = fs::read(&schema_path)
        .unwrap_or_else(|error| panic!("could not read {}: {error}", schema_path.display()));
    let validator = SchemaValidator::compile(schema, json_limits())
        .unwrap_or_else(|error| panic!("could not compile {schema_name}: {error:?}"));
    assert_eq!(validator.validate(&document), Ok(Vec::new()));
}

fn json_limits() -> JsonLimits {
    JsonLimits {
        maximum_bytes: 4_000_000,
        maximum_nesting_depth: 4_000_000,
        maximum_nodes: 4_000_000,
        maximum_string_scalars: 4_000_000,
        maximum_list_items: 4_000_000,
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
