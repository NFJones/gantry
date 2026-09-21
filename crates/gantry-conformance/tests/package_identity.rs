//! Machine-checked conformance for package identity, resolution, and interfaces.
//!
//! These tests exercise the public model of [`gantry::ir`] for `GNT-16.0`
//! through `GNT-16.9-resolution-order-independence`, refining the landed
//! `GNT-11.6-package-source-manifest` and `GNT-11.6-compatibility-classes`
//! relations. They check the model that the specification makes normative, not
//! a registry client or a package loader: no test here reads a host path,
//! contacts a registry, or runs package source, because resolution MUST NOT
//! depend on those things.

use std::collections::BTreeSet;
use std::sync::Arc;

use gantry::ir::generated::{Effect, RecoveryClass};
use gantry::ir::{
    AliasNamespace, AxisReport, AxisVerdict, BoundarySchemaReport, BoundarySchemaSubReport,
    BoundarySchemaSurface, CanonicalIrDigest, CanonicalPath, CanonicalSignature,
    CollisionCondition, ComparedInput, ComparedInputs, CompatibilityAxis, CompatibilityReport,
    ConstructionPolicy, DeclaredCeiling, DeclaredNamespaces, DeclaredSurface,
    DeclaringPackageScope, DependencyAlias, DependencyInterfacePin, DurableArtifactRelation,
    DurableArtifactReport, DurableArtifactSubReport, EffectSet, ExhaustivenessPolicy, ExportEntry,
    FeatureSolutionDigest, GeneratorInput, GeneratorInputRole, GeneratorInputs, IdentityProof,
    Import, ImportSet, InterfaceDigest, InterfaceItem, InterfaceMetadata, InterfaceProof,
    InterfaceSeal, ItemKind, NominalFacts, PackageDiagnosticCode, PackageError, PackageGraph,
    PackageIdentity, PackageIdentityInputs, PackageIdentityRecord, PackageInstance, PackageName,
    PackageSourceIdentity, PackageVersion, PublicInterfaceManifest, QualifiedPath,
    RequirementDemand, ResolvedName, SelectedFeatureSet, SourceManifestDigest, TargetCondition,
    TargetDescriptor, TargetDescriptorDigest, TargetFactSet, TargetFacts, TargetFactsRecord,
    TargetKind, TargetSet, TraitFacts, TypeDescriptor, UnprovenReason, UnqualifiedResolution,
    Visibility, check_ceiling,
};
use gantry::portable::DiagnosticCategory;
use gantry::protocol::ProtocolVersion;
use gantry::source::{
    DIAGNOSTIC_CODE_REGISTRY, DiagnosticPhase, validate_diagnostic_code_registry,
};
use sha2::{Digest, Sha256};

/// The model source guarded by the resolution-order test.
const MODEL_SOURCE: &str = include_str!("../../gantry-ir/src/package.rs");

/// The published package-model note guarded by this lane.
const PACKAGE_MODEL_NOTE: &str = include_str!("../../../docs/package-model.md");

/// Returns the note with every whitespace run collapsed to one space, so a
/// phrase that a wrap splits in the file can still be asserted as one phrase.
/// The registered-code rows are asserted against the raw note, because a row
/// wrapped across lines would no longer render as one table row.
fn flattened_package_note() -> String {
    PACKAGE_MODEL_NOTE
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// The package model publishes every registered code, its registered meaning,
/// its owning clause, every declared clause anchor, and its non-claims.
#[test]
fn package_model_note_names_every_registered_code_anchor_and_non_claim() {
    let flattened = flattened_package_note();
    for clause in [
        "GNT-16.0",
        "GNT-16.1-package-identity",
        "GNT-16.2-package-instances",
        "GNT-16.3-dependency-aliases",
        "GNT-16.4-visibility",
        "GNT-16.5-reexports",
        "GNT-16.6-target-kinds",
        "GNT-16.7-public-interface-manifest",
        "GNT-16.8-compatibility-axes",
        "GNT-16.9-resolution-order-independence",
    ] {
        assert!(
            flattened.contains(clause),
            "the package-model note names {clause}"
        );
    }
    for code in PackageDiagnosticCode::ALL {
        let row = format!(
            "| `{}` | {} | `{}` |",
            code.as_str(),
            code.meaning(),
            code.clause()
        );
        assert!(
            PACKAGE_MODEL_NOTE.contains(&row),
            "the package-model note carries the registered row of {}",
            code.as_str()
        );
    }
    assert!(
        flattened.contains("MUST NOT be reported under another condition's code"),
        "the note carries the code-less reporting rule"
    );
    assert!(
        flattened.contains("This model grants nothing."),
        "the note carries its non-claim"
    );
    assert!(
        flattened.contains("capability ceiling") && flattened.contains("undefined property"),
        "the note names the remaining code-less condition families"
    );
    assert!(
        flattened.contains("`not-applicable` under a v1 profile"),
        "the note states the v1 not-applicable status of the section"
    );
}

/// Returns one deterministic lowercase hexadecimal fixture digest.
fn hex(seed: &str) -> String {
    format!("{:x}", Sha256::digest(seed.as_bytes()))
}

/// Returns one canonical item path.
fn path(value: &str) -> CanonicalPath {
    CanonicalPath::new(value).unwrap_or_else(|_| unreachable!("fixture path is canonical"))
}

/// Returns one labeled package-source-manifest digest.
fn manifest_digest(seed: &str) -> SourceManifestDigest {
    SourceManifestDigest::from_hex(&hex(seed))
        .unwrap_or_else(|_| unreachable!("fixture digest is lowercase hexadecimal"))
}

/// Returns one labeled canonical-IR digest.
fn ir_digest(seed: &str) -> CanonicalIrDigest {
    CanonicalIrDigest::from_hex(&hex(seed))
        .unwrap_or_else(|_| unreachable!("fixture digest is lowercase hexadecimal"))
}

/// Returns one standalone interface digest.
fn interface_digest(seed: &str) -> InterfaceDigest {
    InterfaceDigest::from_hex(&hex(seed))
        .unwrap_or_else(|_| unreachable!("fixture digest is lowercase hexadecimal"))
}

/// Returns one selected feature set.
fn features(names: &[&str]) -> SelectedFeatureSet {
    SelectedFeatureSet::new(names)
        .unwrap_or_else(|_| unreachable!("fixture features are distinct identifiers"))
}

/// Returns the fixture interface metadata of one sealed manifest.
fn metadata() -> InterfaceMetadata {
    InterfaceMetadata {
        edition: Arc::from("v2"),
        stdlib_contract: ProtocolVersion { major: 1, minor: 0 },
        protocol_versions: vec![(
            Arc::from("boundary"),
            ProtocolVersion { major: 1, minor: 0 },
        )],
        target_predicates: Vec::new(),
        public_features: SelectedFeatureSet::empty(),
    }
}

/// Seals one fixture interface against one declared surface.
#[allow(clippy::result_large_err)]
fn seal(
    items: &[InterfaceItem],
    surface: &[&str],
    exports: &[ExportEntry],
    dependencies: &[DependencyInterfacePin],
) -> Result<PublicInterfaceManifest, PackageError> {
    let metadata = metadata();
    let declared = DeclaredSurface::from_names(surface)
        .unwrap_or_else(|_| unreachable!("fixture surface names are distinct identifiers"));
    PublicInterfaceManifest::seal(InterfaceSeal {
        version: PublicInterfaceManifest::VERSION,
        metadata: &metadata,
        surface: &declared,
        items,
        dependencies,
        exports,
    })
}

/// Returns one exported nominal fixture item.
fn nominal_item(name: &str, visibility: Visibility) -> InterfaceItem {
    let mut item = InterfaceItem::new(name, ItemKind::Nominal, visibility, TargetKind::Library)
        .unwrap_or_else(|_| unreachable!("fixture name is an identifier"));
    item.nominal = Some(NominalFacts {
        fields: vec![Arc::from("value")],
        variants: Vec::new(),
        construction: ConstructionPolicy::Exhaustive,
        exhaustiveness: ExhaustivenessPolicy::Exhaustive,
        schema: None,
    });
    item
}

/// Returns one exported action fixture item with one recovery class.
fn action_item(name: &str, recovery: RecoveryClass, requirements: &[&str]) -> InterfaceItem {
    let mut item = InterfaceItem::new(
        name,
        ItemKind::Action,
        Visibility::Exported,
        TargetKind::Library,
    )
    .unwrap_or_else(|_| unreachable!("fixture name is an identifier"));
    item.signature = Some(CanonicalSignature::action(
        recovery,
        &path(&format!("crate::{name}")),
        &[],
        &TypeDescriptor::UNIT,
    ));
    item.recovery = Some(recovery);
    item.requirements = requirements.iter().map(|name| Arc::from(*name)).collect();
    item
}

/// Returns one exported function fixture item.
fn function_item(name: &str) -> InterfaceItem {
    let mut item = InterfaceItem::new(
        name,
        ItemKind::Function,
        Visibility::Exported,
        TargetKind::Library,
    )
    .unwrap_or_else(|_| unreachable!("fixture name is an identifier"));
    item.signature = Some(CanonicalSignature::function(
        &path(&format!("crate::{name}")),
        &[],
        &TypeDescriptor::UNIT,
    ));
    item
}

/// Returns the declared target facts of one fixture library package.
fn library_facts() -> TargetFactSet {
    let library = TargetFacts::new(TargetKind::Library, None)
        .unwrap_or_else(|_| unreachable!("a library declares no entry point"));
    TargetFactSet::new(&[library])
}

/// Returns the selected target and feature-solution facts of one fixture instance.
fn target_selection(seed: &str) -> TargetFactsRecord {
    TargetFactsRecord::new(
        1,
        TargetDescriptorDigest::from_hex(&hex(&format!("{seed}-descriptor")))
            .unwrap_or_else(|_| unreachable!("fixture digest is lowercase hexadecimal")),
        FeatureSolutionDigest::from_hex(&hex(&format!("{seed}-solution")))
            .unwrap_or_else(|_| unreachable!("fixture digest is lowercase hexadecimal")),
    )
    .unwrap_or_else(|_| unreachable!("fixture selection names its version"))
}

/// Derives one identity over an explicitly supplied interface digest.
fn identity_with_interface(
    name: &str,
    version: &str,
    source_seed: &str,
    ir_seed: &str,
    feature_names: &[&str],
    interface: &InterfaceDigest,
) -> PackageIdentity {
    PackageIdentity::derive(PackageIdentityInputs::new(
        PackageName::new(name).unwrap_or_else(|_| unreachable!("fixture name is valid")),
        PackageVersion::new(version).unwrap_or_else(|_| unreachable!("fixture version is valid")),
        PackageSourceIdentity::new(manifest_digest(source_seed), ir_digest(ir_seed)),
        features(feature_names),
        library_facts(),
        target_selection("selection"),
        interface.clone(),
        GeneratorInputs::empty(),
    ))
}

/// Binds one identity to the interface of one sealed manifest.
fn bound_identity(
    name: &str,
    version: &str,
    feature_names: &[&str],
    manifest: &PublicInterfaceManifest,
) -> PackageIdentity {
    identity_with_interface(
        name,
        version,
        "source",
        "ir",
        feature_names,
        manifest.digest(),
    )
}

/// Derives one identity whose declared target facts are exactly one non-shipping
/// `test` target, over the digest of the supplied manifest.
fn non_shipping_identity(name: &str, manifest: &PublicInterfaceManifest) -> PackageIdentity {
    let facts = TargetFactSet::new(&[TargetFacts::new(TargetKind::Test, None)
        .unwrap_or_else(|_| unreachable!("a test target declares no entry point"))]);
    PackageIdentity::derive(PackageIdentityInputs::new(
        PackageName::new(name).unwrap_or_else(|_| unreachable!("fixture name is valid")),
        PackageVersion::new("1.0.0").unwrap_or_else(|_| unreachable!("fixture version is valid")),
        PackageSourceIdentity::new(manifest_digest("source"), ir_digest("ir")),
        features(&[]),
        facts,
        target_selection("selection"),
        manifest.digest().clone(),
        GeneratorInputs::empty(),
    ))
}

/// Returns one sealed interface whose only surface is one re-export declared by
/// a non-shipping `test` target over one pinned defining instance.
fn non_shipping_facade_interface() -> PublicInterfaceManifest {
    let token_manifest = nominal_interface("Token");
    let defining = bound_identity("token", "1.0.0", &[], &token_manifest);
    seal(
        &[],
        &["Token"],
        &[ExportEntry {
            exported_name: Arc::from("Token"),
            defining_name: Arc::from("Token"),
            kind: ItemKind::Nominal,
            target: TargetKind::Test,
            defining: defining.clone(),
        }],
        &[DependencyInterfacePin {
            package: defining,
            interface: token_manifest.digest().clone(),
        }],
    )
    .unwrap_or_else(|_| unreachable!("fixture interface is closed"))
}

/// Binds one identity to the manifest it was resolved against.
fn instance(identity: PackageIdentity, manifest: PublicInterfaceManifest) -> PackageInstance {
    PackageInstance::new(identity, manifest)
        .unwrap_or_else(|_| unreachable!("fixture identity binds its interface"))
}

/// Returns one sealed single-nominal interface.
fn nominal_interface(name: &str) -> PublicInterfaceManifest {
    seal(
        &[nominal_item(name, Visibility::Exported)],
        &[name],
        &[],
        &[],
    )
    .unwrap_or_else(|_| unreachable!("fixture interface is closed"))
}

// ---------------------------------------------------------------------------
// GNT-16.1-package-identity
// ---------------------------------------------------------------------------

#[test]
fn package_identity_has_one_canonical_encoding_and_a_domain_separated_digest() {
    let manifest = nominal_interface("Token");
    let first = bound_identity("token", "1.0.0", &["std", "fast"], &manifest);
    let reordered = identity_with_interface(
        "token",
        "1.0.0",
        "source",
        "ir",
        &["fast", "std"],
        manifest.digest(),
    );
    assert_eq!(first, reordered);
    assert_eq!(first.canonical_bytes(), reordered.canonical_bytes());
    assert_eq!(first.digest_hex().len(), 64);
    assert!(first.as_str().starts_with("package:"));
    assert_eq!(first.inputs().name().as_str(), "token");
    assert_eq!(first.inputs().version().as_str(), "1.0.0");
    assert_eq!(
        first.inputs().features().names().collect::<Vec<_>>(),
        ["fast", "std"]
    );

    let other_version = bound_identity("token", "1.0.1", &["std", "fast"], &manifest);
    let other_feature = bound_identity("token", "1.0.0", &["std"], &manifest);
    assert_ne!(first, other_version);
    assert_ne!(first, other_feature);
    assert_ne!(first.canonical_bytes(), other_version.canonical_bytes());
    // The identity digest is domain separated rather than a naive re-hash, and it
    // is never a display name, a version string, or a prefix of another identity.
    let naive = format!("{:x}", Sha256::digest(first.canonical_bytes()));
    assert_ne!(first.digest_hex(), naive);
    assert_eq!(first.digest_hex().len(), naive.len());
    assert!(!first.as_str().starts_with(&other_version.as_str()));
}

#[test]
fn package_identity_is_insensitive_to_alias_spelling_and_graph_path() {
    let app_manifest = nominal_interface("App");
    let util_manifest = nominal_interface("Token");
    let app = bound_identity("app", "1.0.0", &[], &app_manifest);
    let util = bound_identity("util", "1.0.0", &[], &util_manifest);

    let mut declared = DeclaringPackageScope::new(app.clone(), DeclaredNamespaces::new());
    declared
        .declare_dependency("util", util.clone())
        .unwrap_or_else(|_| unreachable!("fixture alias collides with nothing"));
    let mut renamed = DeclaringPackageScope::new(app.clone(), DeclaredNamespaces::new());
    renamed
        .declare_dependency("dependency_renamed", util.clone())
        .unwrap_or_else(|_| unreachable!("fixture alias collides with nothing"));

    // An alias is local source spelling and is never an identity, so renaming it
    // binds the same package-instance identity and resolves the same defining item.
    assert_eq!(
        declared.resolve_alias("util"),
        renamed.resolve_alias("dependency_renamed")
    );
    assert_eq!(declared.resolve_alias("util"), Ok(&util));
    assert_ne!(
        declared.alias_map().canonical_bytes(),
        renamed.alias_map().canonical_bytes()
    );

    // A direct path and a diamond path reach one instance, and the identity of the
    // reached package is the same identity under every path.
    let mut graph = PackageGraph::new();
    let left_manifest = nominal_interface("Left");
    let right_manifest = nominal_interface("Right");
    let left = bound_identity("left", "1.0.0", &[], &left_manifest);
    let right = bound_identity("right", "1.0.0", &[], &right_manifest);
    graph
        .register_discovered(
            &[
                instance(app.clone(), app_manifest.clone()),
                instance(left.clone(), left_manifest),
                instance(right.clone(), right_manifest),
                instance(util.clone(), util_manifest),
            ],
            &[
                (app.clone(), util.clone()),
                (app.clone(), left.clone()),
                (left.clone(), util.clone()),
                (app.clone(), right.clone()),
                (right.clone(), util.clone()),
            ],
        )
        .unwrap_or_else(|_| unreachable!("every endpoint is registered"));
    let direct = graph
        .resolve_name(&util, "Token")
        .unwrap_or_else(|_| unreachable!("the fixture item is exported"));
    assert_eq!(direct.defining_instance(), &util);
    assert_eq!(graph.len(), 4);
    assert_eq!(
        graph
            .interface(&util)
            .map(|manifest| manifest.is_exported("Token")),
        Some(true)
    );
}

#[test]
fn package_identity_retains_both_labeled_source_digests() {
    let manifest = nominal_interface("Token");
    let committed = bound_identity("token", "1.0.0", &[], &manifest);
    let cosmetic = identity_with_interface(
        "token",
        "1.0.0",
        "source-with-an-extra-comment",
        "ir",
        &[],
        manifest.digest(),
    );
    // Source bytes that differ only in a comment keep one canonical-IR identity
    // and a different source-manifest identity, and both are retained.
    assert_ne!(committed, cosmetic);
    assert_eq!(
        committed.inputs().source().canonical_ir().as_str(),
        cosmetic.inputs().source().canonical_ir().as_str()
    );
    assert_ne!(
        committed.inputs().source().manifest().as_str(),
        cosmetic.inputs().source().manifest().as_str()
    );
    assert_ne!(
        committed.inputs().source().manifest().as_str(),
        committed.inputs().source().canonical_ir().as_str()
    );
    let semantic = identity_with_interface(
        "token",
        "1.0.0",
        "source",
        "ir-with-a-semantic-change",
        &[],
        manifest.digest(),
    );
    assert_ne!(committed, semantic);
}

#[test]
fn package_identity_reports_missing_inputs_as_unproven_and_rejects_unknown_record_properties() {
    let source_hex = hex("manifest");
    let ir_hex = hex("ir");
    let interface_hex = hex("interface");
    let selection_text = format!("1:{}:{}", hex("descriptor"), hex("solution"));
    let complete = [
        ("name", "token"),
        ("version", "1.0.0"),
        ("source_manifest_sha256", source_hex.as_str()),
        ("canonical_ir_sha256", ir_hex.as_str()),
        ("features", "fast,std"),
        ("target_facts", "library"),
        ("target_selection", selection_text.as_str()),
        ("interface_sha256", interface_hex.as_str()),
        ("generator_inputs", ""),
    ];
    let record = PackageIdentityRecord::new(PackageIdentityRecord::VERSION, &complete)
        .unwrap_or_else(|_| unreachable!("fixture record is closed and well formed"));
    assert_eq!(record.version(), 1);
    let proof = record.prove();
    assert!(matches!(&proof, IdentityProof::Proven(_)));
    assert_eq!(proof.reason(), None);
    let proven = proof
        .proven()
        .unwrap_or_else(|| unreachable!("the fixture record is complete"));
    assert_eq!(proven.inputs().name().as_str(), "token");
    assert_eq!(
        proven.inputs().targets().as_slice(),
        library_facts().as_slice()
    );

    // A missing input is unproven rather than empty.
    let missing = PackageIdentityRecord::new(
        PackageIdentityRecord::VERSION,
        &complete[..complete.len() - 2],
    )
    .unwrap_or_else(|_| unreachable!("fixture record rejects no property"));
    assert_eq!(
        missing.prove().reason(),
        Some(UnprovenReason::MissingInput("interface_sha256"))
    );
    assert!(missing.prove().proven().is_none());

    // An unknown property or an unsupported version is rejected rather than repaired.
    assert_eq!(
        PackageIdentityRecord::new(
            PackageIdentityRecord::VERSION,
            &[("alias", "util"), ("name", "token")],
        ),
        Err(PackageError::UnknownIdentityProperty {
            property: Arc::from("alias")
        })
    );
    assert_eq!(
        PackageIdentityRecord::new(2, &[]),
        Err(PackageError::UnsupportedIdentityVersion { version: 2 })
    );
}

// ---------------------------------------------------------------------------
// GNT-16.2-package-instances
// ---------------------------------------------------------------------------
#[test]
fn target_selection_participates_in_package_identity() {
    let manifest = nominal_interface("Token");
    let build = |descriptor_seed: &str, solution_seed: &str| {
        PackageIdentity::derive(PackageIdentityInputs::new(
            PackageName::new("app").unwrap_or_else(|_| unreachable!("fixture name is valid")),
            PackageVersion::new("1.0.0")
                .unwrap_or_else(|_| unreachable!("fixture version is valid")),
            PackageSourceIdentity::new(manifest_digest("source"), ir_digest("ir")),
            features(&[]),
            library_facts(),
            TargetFactsRecord::new(
                1,
                TargetDescriptorDigest::from_hex(&hex(descriptor_seed))
                    .unwrap_or_else(|_| unreachable!("fixture digest is hexadecimal")),
                FeatureSolutionDigest::from_hex(&hex(solution_seed))
                    .unwrap_or_else(|_| unreachable!("fixture digest is hexadecimal")),
            )
            .unwrap_or_else(|_| unreachable!("fixture selection names its version")),
            manifest.digest().clone(),
            GeneratorInputs::empty(),
        ))
    };
    let linux = build("linux-x86_64-gnu", "solution");
    let macos = build("macos-aarch64-msvc", "solution");
    let fast = build("linux-x86_64-gnu", "fast-solution");
    // The selected target and the selected feature solution are identity inputs,
    // so two builds that differ only in either one are different instances.
    assert_ne!(linux, macos);
    assert_ne!(linux, fast);
    assert_eq!(build("linux-x86_64-gnu", "solution"), linux);
    assert_ne!(linux.inputs().selection(), macos.inputs().selection());
    assert_eq!(linux.inputs().selection().descriptor_version(), 1);
}

#[test]
fn distinct_versions_and_feature_distinct_instances_are_distinct_nominal_universes() {
    let manifest = nominal_interface("Token");
    let old = bound_identity("token", "1.0.0", &[], &manifest);
    let new = bound_identity("token", "2.0.0", &[], &manifest);
    let featured = bound_identity("token", "1.0.0", &["fast"], &manifest);
    assert_ne!(old, new);
    assert_ne!(old, featured);
    assert_ne!(new, featured);

    let mut graph = PackageGraph::new();
    for identity in [&old, &new, &featured] {
        assert_eq!(
            graph.register(instance(identity.clone(), manifest.clone())),
            Ok(true)
        );
    }
    assert_eq!(graph.len(), 3);
    // Structurally identical exports are three distinct nominal universes: each
    // `Token` is defined by its own instance and cannot be substituted.
    for identity in [&old, &new, &featured] {
        let resolved = graph
            .resolve_name(identity, "Token")
            .unwrap_or_else(|_| unreachable!("the fixture item is exported"));
        assert_eq!(resolved.defining_instance(), identity);
        assert_eq!(resolved.kind(), ItemKind::Nominal);
    }
    assert_eq!(graph.interface(&old), graph.interface(&new));
    let old_item = graph
        .defined_item(
            &graph
                .resolve_name(&old, "Token")
                .unwrap_or_else(|_| unreachable!("the fixture item is exported")),
        )
        .unwrap_or_else(|_| unreachable!("the defining item is recorded"));
    let new_item = graph
        .defined_item(
            &graph
                .resolve_name(&new, "Token")
                .unwrap_or_else(|_| unreachable!("the fixture item is exported")),
        )
        .unwrap_or_else(|_| unreachable!("the defining item is recorded"));
    assert_eq!(old_item, new_item);
}

#[test]
fn one_instance_reached_by_several_graph_paths_deduplicates_to_one_identity() {
    let util_manifest = nominal_interface("Token");
    let left_manifest = nominal_interface("Left");
    let right_manifest = nominal_interface("Right");
    let app_manifest = nominal_interface("App");
    let app = bound_identity("app", "1.0.0", &[], &app_manifest);
    let left = bound_identity("left", "1.0.0", &[], &left_manifest);
    let right = bound_identity("right", "1.0.0", &[], &right_manifest);
    let util = bound_identity("util", "1.0.0", &[], &util_manifest);
    let util_instance = instance(util.clone(), util_manifest.clone());

    let mut graph = PackageGraph::new();
    assert_eq!(graph.register(util_instance.clone()), Ok(true));
    // A repeated registration of identical inputs creates no second node, and the
    // node keeps exactly the interface it was first resolved against.
    assert_eq!(graph.register(util_instance.clone()), Ok(false));
    assert_eq!(graph.interface(&util), Some(&util_manifest));
    graph
        .register_discovered(
            &[
                instance(app.clone(), app_manifest),
                instance(left.clone(), left_manifest),
                instance(right.clone(), right_manifest),
                util_instance.clone(),
            ],
            &[
                (app.clone(), left.clone()),
                (left.clone(), util.clone()),
                (app.clone(), right.clone()),
                (right.clone(), util.clone()),
                (app.clone(), util.clone()),
            ],
        )
        .unwrap_or_else(|_| unreachable!("every endpoint is registered"));

    // A direct edge, a transitive edge, a diamond, and a repeated path produce one
    // node and no path-qualified variant of the instance or its declarations.
    assert_eq!(graph.len(), 4);
    assert_eq!(graph.edge_count(), 5);
    assert_eq!(graph.instances().count(), 4);
    assert_eq!(
        graph
            .resolve_name(&util, "Token")
            .unwrap_or_else(|_| unreachable!("the fixture item is exported"))
            .defining_instance(),
        &util
    );
    assert!(
        graph
            .instances()
            .all(|resolved| graph.interface(resolved.identity()).is_some())
    );
}

#[test]
fn package_instance_requires_its_identity_and_interface_digest_to_agree() {
    let token = nominal_interface("Token");
    let other = nominal_interface("Other");
    assert_ne!(token.digest(), other.digest());
    let identity = bound_identity("app", "1.0.0", &[], &token);
    assert_eq!(
        PackageInstance::new(identity.clone(), other.clone()),
        Err(PackageError::InterfaceMismatch {
            expected: token.digest().clone(),
            observed: other.digest().clone(),
        })
    );
    assert!(PackageInstance::new(identity, token).is_ok());
}

// ---------------------------------------------------------------------------
// GNT-16.3-dependency-aliases
// ---------------------------------------------------------------------------
#[test]
fn feature_distinct_siblings_of_one_name_and_version_link_and_resolve_separately() {
    let token_manifest = nominal_interface("Token");
    let grant_manifest = nominal_interface("Grant");
    let plain = bound_identity("util", "1.0.0", &["plain"], &token_manifest);
    let rich = bound_identity("util", "1.0.0", &["rich"], &grant_manifest);
    let app_manifest = seal(
        &[],
        &["Token", "Grant"],
        &[
            ExportEntry {
                exported_name: Arc::from("Token"),
                defining_name: Arc::from("Token"),
                kind: ItemKind::Nominal,
                target: TargetKind::Library,
                defining: plain.clone(),
            },
            ExportEntry {
                exported_name: Arc::from("Grant"),
                defining_name: Arc::from("Grant"),
                kind: ItemKind::Nominal,
                target: TargetKind::Library,
                defining: rich.clone(),
            },
        ],
        &[
            DependencyInterfacePin {
                package: plain.clone(),
                interface: token_manifest.digest().clone(),
            },
            DependencyInterfacePin {
                package: rich.clone(),
                interface: grant_manifest.digest().clone(),
            },
        ],
    )
    .unwrap_or_else(|_| unreachable!("fixture interface is closed"));
    let app = bound_identity("app", "1.0.0", &[], &app_manifest);

    let mut graph = PackageGraph::new();
    graph
        .register_discovered(
            &[
                instance(app.clone(), app_manifest),
                instance(plain.clone(), token_manifest),
                instance(rich.clone(), grant_manifest),
            ],
            &[(app.clone(), plain.clone()), (app.clone(), rich.clone())],
        )
        .unwrap_or_else(|_| unreachable!("a sibling instance is not an interface mismatch"));
    // Two instances of one name and version are two universes: each edge reaches
    // exactly the instance its own pin names, and no pin is compared against the
    // sibling instance that shares the name and version.
    let token = graph
        .resolve_name(&app, "Token")
        .unwrap_or_else(|_| unreachable!("the fixture re-export is pinned"));
    let grant = graph
        .resolve_name(&app, "Grant")
        .unwrap_or_else(|_| unreachable!("the fixture re-export is pinned"));
    assert_eq!(token.defining_instance(), &plain);
    assert_eq!(grant.defining_instance(), &rich);
    assert_eq!(graph.edge_count(), 2);
}

#[test]
fn alias_namespace_collisions_are_static_errors_naming_the_offending_namespace() {
    let app_manifest = nominal_interface("App");
    let dependency_manifest = nominal_interface("Token");
    let app = bound_identity("app", "1.0.0", &[], &app_manifest);
    let dependency = bound_identity("util", "1.0.0", &[], &dependency_manifest);

    for (alias, namespaces, namespace, condition) in [
        (
            "util",
            DeclaredNamespaces::new().with_module("util"),
            AliasNamespace::Module,
            CollisionCondition::Exact,
        ),
        (
            "helper",
            DeclaredNamespaces::new().with_item("helper"),
            AliasNamespace::Item,
            CollisionCondition::Exact,
        ),
        (
            "worker",
            DeclaredNamespaces::new().with_agent("worker"),
            AliasNamespace::Agent,
            CollisionCondition::Exact,
        ),
        (
            "shell",
            DeclaredNamespaces::new().with_capability_slot("shell"),
            AliasNamespace::CapabilitySlot,
            CollisionCondition::Exact,
        ),
        (
            "match",
            DeclaredNamespaces::new().with_reserved_word("match"),
            AliasNamespace::ReservedWord,
            CollisionCondition::ReservedWord,
        ),
    ] {
        let mut scope = DeclaringPackageScope::new(app.clone(), namespaces);
        assert_eq!(
            scope.declare_dependency(alias, dependency.clone()),
            Err(PackageError::AliasCollision {
                namespace,
                alias: Arc::from(alias),
                conflicting: Arc::from(alias),
                condition,
            })
        );
        // A collision is a static error, never a resolution preference: no alias
        // was bound by the rejected declaration.
        assert!(scope.dependencies().is_empty());
    }
    assert_eq!(
        DependencyAlias::new("1util"),
        Err(PackageError::InvalidAlias {
            spelling: Arc::from("1util")
        })
    );
}

#[test]
fn a_direct_dependency_requires_exactly_one_explicit_unique_alias_binding_one_instance() {
    let app_manifest = nominal_interface("App");
    let first_manifest = nominal_interface("Token");
    let second_manifest = nominal_interface("Other");
    let app = bound_identity("app", "1.0.0", &[], &app_manifest);
    let first = bound_identity("util", "1.0.0", &[], &first_manifest);
    let second = bound_identity("util", "2.0.0", &[], &second_manifest);

    let mut scope = DeclaringPackageScope::new(app, DeclaredNamespaces::new());
    assert_eq!(
        scope.declare_dependency("util", first.clone()),
        DependencyAlias::new("util").map_err(|_| PackageError::InvalidAlias {
            spelling: Arc::from("util")
        })
    );
    // One alias binds exactly one instance for the whole declaring package.
    assert_eq!(scope.resolve_alias("util"), Ok(&first));
    assert_eq!(scope.dependencies().len(), 1);
    assert_eq!(
        scope.declare_dependency("util", second.clone()),
        Err(PackageError::DuplicateAlias {
            alias: Arc::from("util")
        })
    );
    assert_eq!(scope.dependencies().len(), 1);
    // An explicit alias is compared exactly and case-sensitively, so a spelling
    // that differs only in case is a second alias of this declaring package rather
    // than a collision.
    assert_eq!(
        scope.declare_dependency("Util", second.clone()),
        DependencyAlias::new("Util").map_err(|_| PackageError::InvalidAlias {
            spelling: Arc::from("Util")
        })
    );
    assert_eq!(scope.resolve_alias("util"), Ok(&first));
    assert_eq!(scope.resolve_alias("Util"), Ok(&second));
    assert_eq!(scope.dependencies().len(), 2);
    assert_eq!(scope.alias_map().entries().len(), 2);
    // A repeated exact spelling stays a static error naming the alias.
    assert_eq!(
        scope.declare_dependency("Util", second),
        Err(PackageError::DuplicateAlias {
            alias: Arc::from("Util")
        })
    );
    assert_eq!(scope.dependencies().len(), 2);
}

#[test]
fn explicit_aliases_are_exact_and_order_independent() {
    let app = bound_identity("app", "1.0.0", &[], &nominal_interface("App"));
    let prefixed = bound_identity("serde-json", "1.0.0", &[], &nominal_interface("First"));
    let prefix = bound_identity("serde", "1.0.0", &[], &nominal_interface("Second"));

    // Two explicit aliases that differ by a prefix are two distinct aliases, and
    // declaring them in either order produces one alias map: no declaration order
    // decides whether an explicit alias collides.
    let mut forward = DeclaringPackageScope::new(app.clone(), DeclaredNamespaces::new());
    forward
        .declare_dependency("serde", prefix.clone())
        .unwrap_or_else(|_| unreachable!("the first explicit alias collides with nothing"));
    forward
        .declare_dependency("serde_json", prefixed.clone())
        .unwrap_or_else(|_| unreachable!("the second explicit alias collides with nothing"));
    let mut backward = DeclaringPackageScope::new(app.clone(), DeclaredNamespaces::new());
    backward
        .declare_dependency("serde_json", prefixed.clone())
        .unwrap_or_else(|_| unreachable!("the first explicit alias collides with nothing"));
    backward
        .declare_dependency("serde", prefix.clone())
        .unwrap_or_else(|_| unreachable!("the second explicit alias collides with nothing"));
    assert_eq!(
        forward.alias_map().canonical_bytes(),
        backward.alias_map().canonical_bytes()
    );
    assert_eq!(
        forward.alias_map().digest_hex(),
        backward.alias_map().digest_hex()
    );
    assert_eq!(forward.resolve_alias("serde"), Ok(&prefix));
    assert_eq!(forward.resolve_alias("serde_json"), Ok(&prefixed));

    // The colliding pair of explicit aliases is the exact duplicate, which is
    // rejected in either declaration order with one diagnostic and no second
    // binding.
    let mut duplicate = DeclaringPackageScope::new(app.clone(), DeclaredNamespaces::new());
    duplicate
        .declare_dependency("serde", prefix.clone())
        .unwrap_or_else(|_| unreachable!("the first explicit alias collides with nothing"));
    let duplicate_rejected = duplicate.declare_dependency("serde", prefixed.clone());
    let mut duplicate_reversed = DeclaringPackageScope::new(app, DeclaredNamespaces::new());
    duplicate_reversed
        .declare_dependency("serde", prefixed.clone())
        .unwrap_or_else(|_| unreachable!("the first explicit alias collides with nothing"));
    let reversed_rejected = duplicate_reversed.declare_dependency("serde", prefix.clone());
    assert_eq!(duplicate_rejected, reversed_rejected);
    assert_eq!(
        reversed_rejected,
        Err(PackageError::DuplicateAlias {
            alias: Arc::from("serde")
        })
    );
    // The rejected declaration bound no alias at all: exactly one alias remains,
    // and it is the instance the accepted declaration bound.
    assert_eq!(duplicate.dependencies().len(), 1);
    assert_eq!(duplicate.alias_map().entries().len(), 1);
    assert_eq!(duplicate.resolve_alias("serde"), Ok(&prefix));
    assert_eq!(duplicate_reversed.dependencies().len(), 1);
    assert_eq!(duplicate_reversed.resolve_alias("serde"), Ok(&prefixed));
}

#[test]
fn unqualified_lookup_stays_lexical_and_package_local() {
    let app_manifest = nominal_interface("App");
    let dependency_manifest = seal(
        &[
            nominal_item("Token", Visibility::Exported),
            nominal_item("hidden", Visibility::PackageLocal),
        ],
        &["Token", "hidden"],
        &[],
        &[],
    )
    .unwrap_or_else(|_| unreachable!("fixture interface is closed"));
    let app = bound_identity("app", "1.0.0", &[], &app_manifest);
    let dependency = bound_identity("util", "1.0.0", &[], &dependency_manifest);
    let mut graph = PackageGraph::new();
    graph
        .register_discovered(
            &[
                instance(app.clone(), app_manifest),
                instance(dependency.clone(), dependency_manifest),
            ],
            &[(app.clone(), dependency.clone())],
        )
        .unwrap_or_else(|_| unreachable!("every endpoint is registered"));
    let mut scope = DeclaringPackageScope::new(
        app,
        DeclaredNamespaces::new()
            .with_item("helper")
            .with_module("nested"),
    );
    scope
        .declare_dependency("util", dependency.clone())
        .unwrap_or_else(|_| unreachable!("fixture alias collides with nothing"));
    // One import set that imports one item under its own name through the alias.
    let imported = |name: &str| {
        ImportSet::new(&[Import::new(
            name,
            QualifiedPath::new(&format!("util::{name}"))
                .unwrap_or_else(|_| unreachable!("fixture path is valid")),
        )
        .unwrap_or_else(|_| unreachable!("fixture import name is the path item"))])
        .unwrap_or_else(|_| unreachable!("fixture imports are distinct"))
    };
    let imports = imported("Token");

    assert_eq!(
        scope.resolve_unqualified(&graph, &imports, "helper"),
        Ok(UnqualifiedResolution::LexicalLocal {
            name: Arc::from("helper")
        })
    );
    assert_eq!(
        scope.resolve_unqualified(&graph, &imports, "nested"),
        Ok(UnqualifiedResolution::LexicalLocal {
            name: Arc::from("nested")
        })
    );
    // The only way an external item becomes nameable through an unqualified name
    // is an explicit import that names the item through the alias, and the import
    // is resolved through the graph to the one instance the alias binds.
    assert_eq!(
        scope.resolve_unqualified(&graph, &imports, "Token"),
        Ok(UnqualifiedResolution::Imported {
            local_name: Arc::from("Token"),
            alias: Arc::from("util"),
            item: Arc::from("Token"),
            defining_instance: Box::new(dependency.clone()),
        })
    );
    assert_eq!(
        scope.resolve_unqualified(&graph, &ImportSet::default(), "Token"),
        Err(PackageError::UnqualifiedNameNotLocal {
            name: Arc::from("Token")
        })
    );
    // An imported name that the bound instance does not export, and an imported
    // name it does not record at all, are rejected from its frozen interface
    // instead of being accepted from the import declaration.
    for name in ["hidden", "absent"] {
        assert_eq!(
            scope.resolve_unqualified(&graph, &imported(name), name),
            Err(PackageError::ItemNotExported {
                package: dependency.clone(),
                name: Arc::from(name),
            })
        );
    }
    assert_eq!(
        scope
            .resolve_unqualified(&graph, &imported("absent"), "absent")
            .err()
            .and_then(|error| error.code()),
        Some(PackageDiagnosticCode::ItemNotExported)
    );
    // A renaming import is invalid: the landed `use` declaration admits no alias
    // for the local name, so the local name is the path item and nothing else.
    assert_eq!(
        Import::new(
            "Renamed",
            QualifiedPath::new("util::Token")
                .unwrap_or_else(|_| unreachable!("fixture path is valid"))
        ),
        Err(PackageError::InvalidDeclaration {
            field: "import name",
            value: Arc::from("Renamed")
        })
    );
    // A local name and an explicit import of the same name are a collision rather
    // than a shadowing preference.
    let mut local = DeclaringPackageScope::new(
        bound_identity("local", "1.0.0", &[], &nominal_interface("Local")),
        DeclaredNamespaces::new().with_item("Token"),
    );
    local
        .declare_dependency("util", dependency)
        .unwrap_or_else(|_| unreachable!("fixture alias collides with nothing"));
    assert_eq!(
        local.resolve_unqualified(&graph, &imports, "Token"),
        Err(PackageError::UnqualifiedNameAmbiguous {
            name: Arc::from("Token")
        })
    );
}

#[test]
fn unresolved_alias_is_reported_without_filesystem_registry_or_discovery_fallback() {
    let app_manifest = nominal_interface("App");
    let util_manifest = nominal_interface("Token");
    let app = bound_identity("app", "1.0.0", &[], &app_manifest);
    let util = bound_identity("util", "1.0.0", &[], &util_manifest);
    let mut graph = PackageGraph::new();
    graph
        .register_discovered(
            &[
                instance(app.clone(), app_manifest),
                instance(util.clone(), util_manifest),
            ],
            &[(app.clone(), util.clone())],
        )
        .unwrap_or_else(|_| unreachable!("every endpoint is registered"));

    // A resolved package named `util` that exports `Token` exists, but an alias is
    // the only way to name it: no filesystem, host-name, registry-display-name,
    // transitive-path, or discovery-order fallback resolves the path.
    let undeclared = DeclaringPackageScope::new(app.clone(), DeclaredNamespaces::new());
    assert_eq!(
        undeclared.resolve_alias("util"),
        Err(PackageError::AliasUnresolved {
            spelling: Arc::from("util")
        })
    );
    assert_eq!(
        undeclared.resolve_qualified(
            &graph,
            &QualifiedPath::new("util::Token")
                .unwrap_or_else(|_| unreachable!("fixture path is valid"))
        ),
        Err(PackageError::AliasUnresolved {
            spelling: Arc::from("util")
        })
    );

    let mut declared = DeclaringPackageScope::new(app, DeclaredNamespaces::new());
    declared
        .declare_dependency("dep", util.clone())
        .unwrap_or_else(|_| unreachable!("fixture alias collides with nothing"));
    let resolved = declared
        .resolve_qualified(
            &graph,
            &QualifiedPath::new("dep::Token")
                .unwrap_or_else(|_| unreachable!("fixture path is valid")),
        )
        .unwrap_or_else(|_| unreachable!("the declared alias resolves to an exported item"));
    assert_eq!(resolved.defining_instance(), &util);
    // An unresolvable name under a declared alias is reported rather than searched.
    assert_eq!(
        declared.resolve_qualified(
            &graph,
            &QualifiedPath::new("dep::Missing")
                .unwrap_or_else(|_| unreachable!("fixture path is valid"))
        ),
        Err(PackageError::ItemNotExported {
            package: util.clone(),
            name: Arc::from("Missing"),
        })
    );
    assert_eq!(
        QualifiedPath::new("Token"),
        Err(PackageError::InvalidDeclaration {
            field: "qualified path",
            value: Arc::from("Token"),
        })
    );
}

#[test]
fn transitive_undeclared_access_is_rejected_and_dependency_items_are_not_implicitly_reexported() {
    let app_manifest = nominal_interface("App");
    let util_manifest = nominal_interface("Token");
    let transitive_manifest = nominal_interface("Thing");
    let app = bound_identity("app", "1.0.0", &[], &app_manifest);
    let util = bound_identity("util", "1.0.0", &[], &util_manifest);
    let transitive = bound_identity("transdep", "1.0.0", &[], &transitive_manifest);
    let mut graph = PackageGraph::new();
    graph
        .register_discovered(
            &[
                instance(app.clone(), app_manifest.clone()),
                instance(util.clone(), util_manifest.clone()),
                instance(transitive.clone(), transitive_manifest),
            ],
            &[
                (app.clone(), util.clone()),
                (util.clone(), transitive.clone()),
            ],
        )
        .unwrap_or_else(|_| unreachable!("every endpoint is registered"));
    let mut declared = DeclaringPackageScope::new(app.clone(), DeclaredNamespaces::new());
    declared
        .declare_dependency("dep", util.clone())
        .unwrap_or_else(|_| unreachable!("fixture alias collides with nothing"));

    // `dep::transdep::Thing` names an item of a dependency of a dependency that
    // the declaring package does not declare, so the path is a static error.
    assert_eq!(
        declared.resolve_qualified(
            &graph,
            &QualifiedPath::new("dep::transdep::Thing")
                .unwrap_or_else(|_| unreachable!("fixture path is valid"))
        ),
        Err(PackageError::TransitiveUndeclared {
            package: Arc::from("transdep"),
            accessed: Arc::from("dep::transdep::Thing"),
        })
    );
    assert_eq!(
        declared
            .resolve_qualified(
                &graph,
                &QualifiedPath::new("dep::transdep::Thing")
                    .unwrap_or_else(|_| unreachable!("fixture path is valid"))
            )
            .err()
            .and_then(|error| error.code()),
        Some(PackageDiagnosticCode::TransitiveUndeclared)
    );

    // Declaring the transitive dependency itself makes its item nameable, and a
    // dependency's items never become part of the declaring package's interface.
    let mut declaring = DeclaringPackageScope::new(app.clone(), DeclaredNamespaces::new());
    declaring
        .declare_dependency("util", util.clone())
        .unwrap_or_else(|_| unreachable!("fixture alias collides with nothing"));
    declaring
        .declare_dependency("transdep", transitive.clone())
        .unwrap_or_else(|_| unreachable!("fixture alias collides with nothing"));
    assert!(
        declaring
            .resolve_qualified(
                &graph,
                &QualifiedPath::new("transdep::Thing")
                    .unwrap_or_else(|_| unreachable!("fixture path is valid"))
            )
            .is_ok()
    );
    assert!(!app_manifest.is_exported("Token"));
    assert!(app_manifest.exports().is_empty());
    assert!(util_manifest.is_exported("Token"));
    assert_eq!(
        graph.resolve_name(&app, "Token"),
        Err(PackageError::ItemNotExported {
            package: app.clone(),
            name: Arc::from("Token"),
        })
    );
}

#[test]
fn a_non_exported_item_sharing_a_dependency_name_is_a_visibility_failure() {
    // `util` records a package-local item named after one of its own dependencies
    // and leaves another dependency unrecorded, so the two paths are distinguished
    // by the bound instance's own interface rather than by the name alone.
    let app_manifest = nominal_interface("App");
    let util_manifest = seal(
        &[nominal_item("shared", Visibility::PackageLocal)],
        &["shared"],
        &[],
        &[],
    )
    .unwrap_or_else(|_| unreachable!("fixture interface is closed"));
    let app = bound_identity("app", "1.0.0", &[], &app_manifest);
    let util = bound_identity("util", "1.0.0", &[], &util_manifest);
    let shared = bound_identity("shared", "1.0.0", &[], &nominal_interface("Thing"));
    let unrecorded = bound_identity("unrecorded", "1.0.0", &[], &nominal_interface("Other"));
    let mut graph = PackageGraph::new();
    graph
        .register_discovered(
            &[
                instance(app.clone(), app_manifest.clone()),
                instance(util.clone(), util_manifest),
                instance(shared.clone(), nominal_interface("Thing")),
                instance(unrecorded.clone(), nominal_interface("Other")),
            ],
            &[
                (app.clone(), util.clone()),
                (util.clone(), shared.clone()),
                (util.clone(), unrecorded.clone()),
            ],
        )
        .unwrap_or_else(|_| unreachable!("every endpoint is registered"));
    let mut declared = DeclaringPackageScope::new(app, DeclaredNamespaces::new());
    declared
        .declare_dependency("dep", util.clone())
        .unwrap_or_else(|_| unreachable!("fixture alias collides with nothing"));

    // A name the bound instance records is a visibility failure of that instance,
    // even though the instance also has a dependency that shares the name.
    let path = |value: &str| {
        QualifiedPath::new(value).unwrap_or_else(|_| unreachable!("fixture path is valid"))
    };
    assert_eq!(
        declared.resolve_qualified(&graph, &path("dep::shared::Thing")),
        Err(PackageError::ItemNotExported {
            package: util.clone(),
            name: Arc::from("shared"),
        })
    );
    assert_eq!(
        declared
            .resolve_qualified(&graph, &path("dep::shared::Thing"))
            .err()
            .and_then(|error| error.code()),
        Some(PackageDiagnosticCode::ItemNotExported)
    );
    // A name the bound instance does not record at all stays a transitive access
    // through a dependency the declaring package does not declare.
    assert_eq!(
        declared.resolve_qualified(&graph, &path("dep::unrecorded::Other")),
        Err(PackageError::TransitiveUndeclared {
            package: Arc::from("unrecorded"),
            accessed: Arc::from("dep::unrecorded::Other"),
        })
    );
    assert_eq!(
        declared.resolve_qualified(&graph, &path("dep::unrecorded")),
        Err(PackageError::TransitiveUndeclared {
            package: Arc::from("unrecorded"),
            accessed: Arc::from("dep::unrecorded"),
        })
    );
}

#[test]
fn synthesized_alias_map_is_deterministic_and_rejects_collisions() {
    let app_manifest = nominal_interface("App");
    let first_manifest = nominal_interface("First");
    let second_manifest = nominal_interface("Second");
    let app = bound_identity("app", "1.0.0", &[], &app_manifest);
    let first = bound_identity("first-package", "1.0.0", &[], &first_manifest);
    let second = bound_identity("second-package", "1.0.0", &[], &second_manifest);

    // The same inputs produce the same alias and the same map independently of
    // discovery or enumeration order.
    let mut forward = DeclaringPackageScope::new(app.clone(), DeclaredNamespaces::new());
    let alias = forward
        .declare_synthesized_dependency("first-package", first.clone())
        .unwrap_or_else(|_| unreachable!("fixture alias collides with nothing"));
    assert_eq!(
        alias,
        DependencyAlias::new("first_package")
            .unwrap_or_else(|_| unreachable!("the synthesized spelling is an identifier"))
    );
    forward
        .declare_synthesized_dependency("second-package", second.clone())
        .unwrap_or_else(|_| unreachable!("fixture alias collides with nothing"));
    let mut reversed = DeclaringPackageScope::new(app.clone(), DeclaredNamespaces::new());
    reversed
        .declare_synthesized_dependency("second-package", second.clone())
        .unwrap_or_else(|_| unreachable!("fixture alias collides with nothing"));
    reversed
        .declare_synthesized_dependency("first-package", first.clone())
        .unwrap_or_else(|_| unreachable!("fixture alias collides with nothing"));
    assert_eq!(
        forward.alias_map().canonical_bytes(),
        reversed.alias_map().canonical_bytes()
    );
    assert_eq!(
        forward.alias_map().digest_hex(),
        reversed.alias_map().digest_hex()
    );
    assert_eq!(forward.alias_map().entries().len(), 2);
    assert_eq!(&forward.alias_map().entries()[0].1, &first);

    // The same permutation holds for a colliding pair: the synthesized aliases of
    // `serde-json` and `serde` collide by truncation, and both declaration orders
    // reject the second alias with one diagnostic while leaving exactly one alias
    // bound.
    let collide = |order: [(&str, &PackageIdentity); 2]| -> (usize, Option<PackageError>) {
        let mut scope = DeclaringPackageScope::new(app.clone(), DeclaredNamespaces::new());
        let mut rejected = None;
        for (package_name, instance) in order {
            match scope.declare_synthesized_dependency(package_name, instance.clone()) {
                Ok(_) => {}
                Err(error) => {
                    rejected = Some(error);
                    break;
                }
            }
        }
        (scope.alias_map().entries().len(), rejected)
    };
    let forward_pair = collide([("serde-json", &first), ("serde", &second)]);
    let reversed_pair = collide([("serde", &second), ("serde-json", &first)]);
    assert_eq!(forward_pair, reversed_pair);
    assert_eq!(forward_pair.0, 1);
    assert_eq!(
        reversed_pair.1,
        Some(PackageError::AliasCollision {
            namespace: AliasNamespace::DependencyAlias,
            alias: Arc::from("serde"),
            conflicting: Arc::from("serde_json"),
            condition: CollisionCondition::Truncation,
        })
    );

    for (package_name, namespaces, namespace, condition) in [
        (
            "serde-json",
            DeclaredNamespaces::new().with_item("serde_json"),
            AliasNamespace::Item,
            CollisionCondition::Exact,
        ),
        (
            "serde",
            DeclaredNamespaces::new().with_item("serde_json"),
            AliasNamespace::Item,
            CollisionCondition::Truncation,
        ),
        (
            "serde",
            DeclaredNamespaces::new().with_item("Serde"),
            AliasNamespace::Item,
            CollisionCondition::Case,
        ),
        // The pinned full case mapping makes `ΑΣ` and `Ας` one spelling, so the
        // synthesized alias of `ας` collides by case; the toolchain's
        // `str::to_lowercase` would report no collision for this pair.
        (
            "ας",
            DeclaredNamespaces::new().with_item("ΑΣ"),
            AliasNamespace::Item,
            CollisionCondition::Case,
        ),
        (
            "match",
            DeclaredNamespaces::new().with_reserved_word("match"),
            AliasNamespace::ReservedWord,
            CollisionCondition::ReservedWord,
        ),
    ] {
        let mut scope = DeclaringPackageScope::new(app.clone(), namespaces);
        assert!(matches!(
            scope.declare_synthesized_dependency(package_name, first.clone()),
            Err(PackageError::AliasCollision {
                namespace: reported,
                condition: reported_condition,
                ..
            }) if reported == namespace && reported_condition == condition
        ));
        assert!(scope.dependencies().is_empty());
    }
}

// ---------------------------------------------------------------------------
// GNT-16.4-visibility
// ---------------------------------------------------------------------------

#[test]
fn only_exported_items_of_a_frozen_interface_are_nameable() {
    let manifest = seal(
        &[
            nominal_item("Token", Visibility::Exported),
            nominal_item("internal_helper", Visibility::PackageLocal),
        ],
        &["Token", "internal_helper"],
        &[],
        &[],
    )
    .unwrap_or_else(|_| unreachable!("fixture interface is closed"));
    let identity = bound_identity("app", "1.0.0", &[], &manifest);
    let mut graph = PackageGraph::new();
    assert_eq!(
        graph.register(instance(identity.clone(), manifest.clone())),
        Ok(true)
    );

    assert!(manifest.is_exported("Token"));
    // An item that is package-wide addressable inside its defining package is not
    // thereby exported, and another package cannot name it.
    assert!(manifest.is_recorded("internal_helper"));
    assert!(!manifest.is_exported("internal_helper"));
    assert_eq!(
        manifest
            .item("internal_helper")
            .map(|item| item.visibility()),
        Some(Visibility::PackageLocal)
    );
    assert_eq!(
        graph.resolve_name(&identity, "internal_helper"),
        Err(PackageError::ItemNotExported {
            package: identity.clone(),
            name: Arc::from("internal_helper"),
        })
    );
    assert_eq!(
        graph
            .resolve_name(&identity, "internal_helper")
            .err()
            .and_then(|error| error.code()),
        Some(PackageDiagnosticCode::ItemNotExported)
    );

    // Visibility is decided against the frozen interface, so a later source edit
    // cannot retroactively widen it: the same lookup on a manifest that exports the
    // item is a different, newly sealed interface with a different digest.
    let widened = seal(
        &[
            nominal_item("Token", Visibility::Exported),
            nominal_item("internal_helper", Visibility::Exported),
        ],
        &["Token", "internal_helper"],
        &[],
        &[],
    )
    .unwrap_or_else(|_| unreachable!("fixture interface is closed"));
    assert_ne!(manifest.digest(), widened.digest());
    assert!(widened.is_exported("internal_helper"));
    assert!(!manifest.is_exported("internal_helper"));
    assert_eq!(
        package_visibility_of(&manifest, "internal_helper"),
        Some(Visibility::PackageLocal)
    );
}

/// Returns one recorded visibility without exposing a mutable interface.
fn package_visibility_of(manifest: &PublicInterfaceManifest, name: &str) -> Option<Visibility> {
    manifest.item(name).map(|item| item.visibility())
}

#[test]
fn non_exported_items_are_unreachable_through_every_reexport_chain() {
    let core_manifest = seal(
        &[
            nominal_item("Token", Visibility::PackageLocal),
            nominal_item("Public", Visibility::Exported),
        ],
        &["Token", "Public"],
        &[],
        &[],
    )
    .unwrap_or_else(|_| unreachable!("fixture interface is closed"));
    let core = bound_identity("core", "1.0.0", &[], &core_manifest);
    let middle_manifest = seal(
        &[],
        &["Token"],
        &[ExportEntry {
            exported_name: Arc::from("Token"),
            defining_name: Arc::from("Token"),
            kind: ItemKind::Nominal,
            target: TargetKind::Library,
            defining: core.clone(),
        }],
        &[DependencyInterfacePin {
            package: core.clone(),
            interface: core_manifest.digest().clone(),
        }],
    )
    .unwrap_or_else(|_| unreachable!("fixture interface is closed"));
    let middle = bound_identity("middle", "1.0.0", &[], &middle_manifest);
    let outer_manifest = seal(
        &[],
        &["Token"],
        &[ExportEntry {
            exported_name: Arc::from("Token"),
            defining_name: Arc::from("Token"),
            kind: ItemKind::Nominal,
            target: TargetKind::Library,
            defining: middle.clone(),
        }],
        &[DependencyInterfacePin {
            package: middle.clone(),
            interface: middle_manifest.digest().clone(),
        }],
    )
    .unwrap_or_else(|_| unreachable!("fixture interface is closed"));
    let outer = bound_identity("outer", "1.0.0", &[], &outer_manifest);

    let mut graph = PackageGraph::new();
    graph
        .register_discovered(
            &[
                instance(core.clone(), core_manifest),
                instance(middle.clone(), middle_manifest),
                instance(outer.clone(), outer_manifest),
            ],
            &[
                (middle.clone(), core.clone()),
                (outer.clone(), middle.clone()),
            ],
        )
        .unwrap_or_else(|_| unreachable!("every endpoint is registered"));

    // Every link of the chain is re-exported, but the chain terminates in a
    // defining package that does not export the item, so the chain is invalid and
    // the final name is not accepted because some other package exports `Public`.
    for start in [&core, &middle, &outer] {
        assert_eq!(
            graph.resolve_name(start, "Token"),
            Err(PackageError::ItemNotExported {
                package: core.clone(),
                name: Arc::from("Token"),
            })
        );
    }
    assert!(
        graph
            .resolve_name(&core, "Public")
            .map(|resolved| resolved.defining_instance().clone())
            .is_ok_and(|defining| defining == core)
    );
    assert_eq!(
        graph.resolve_name(&outer, "Public"),
        Err(PackageError::ItemNotExported {
            package: outer.clone(),
            name: Arc::from("Public"),
        })
    );
}

// ---------------------------------------------------------------------------
// GNT-16.5-reexports
// ---------------------------------------------------------------------------

#[test]
fn reexport_preserves_defining_package_identity_kind_and_requirement_facts() {
    let core_manifest = seal(
        &[action_item(
            "delete",
            RecoveryClass::NonIdempotent,
            &["core::network"],
        )],
        &["delete"],
        &[],
        &[],
    )
    .unwrap_or_else(|_| unreachable!("fixture interface is closed"));
    let core = bound_identity("core", "1.0.0", &[], &core_manifest);
    let facade_manifest = seal(
        &[],
        &["erase"],
        &[ExportEntry {
            exported_name: Arc::from("erase"),
            defining_name: Arc::from("delete"),
            kind: ItemKind::Action,
            target: TargetKind::Library,
            defining: core.clone(),
        }],
        &[DependencyInterfacePin {
            package: core.clone(),
            interface: core_manifest.digest().clone(),
        }],
    )
    .unwrap_or_else(|_| unreachable!("fixture interface is closed"));
    let facade = bound_identity("facade", "1.0.0", &[], &facade_manifest);
    let mut graph = PackageGraph::new();
    graph
        .register_discovered(
            &[
                instance(core.clone(), core_manifest),
                instance(facade.clone(), facade_manifest.clone()),
            ],
            &[(facade.clone(), core.clone())],
        )
        .unwrap_or_else(|_| unreachable!("every endpoint is registered"));

    // A re-export introduces reachability only: the defining package identity, the
    // defining name, and the item kind are preserved, and the facade creates no new
    // nominal, action, capability, agent, trait, or operation identity.
    let resolved = graph
        .resolve_name(&facade, "erase")
        .unwrap_or_else(|_| unreachable!("the re-export reaches an exported item"));
    assert_eq!(resolved.exported_name(), "erase");
    assert_eq!(resolved.defining_name(), "delete");
    assert_eq!(resolved.defining_instance(), &core);
    assert_eq!(resolved.kind(), ItemKind::Action);
    assert!(resolved.is_reexported());
    assert_eq!(resolved.chain().len(), 1);
    assert!(facade_manifest.items().is_empty());
    assert_eq!(facade_manifest.exports().len(), 1);

    // Recovery, requirement, and provenance facts are read from the defining
    // package, so the facade cannot erase them or satisfy a requirement the
    // defining package does not declare.
    let defining_item = graph
        .defined_item(&resolved)
        .unwrap_or_else(|_| unreachable!("the defining item is recorded"));
    assert_eq!(defining_item.name(), "delete");
    assert_eq!(defining_item.recovery, Some(RecoveryClass::NonIdempotent));
    assert_eq!(defining_item.requirements, [Arc::from("core::network")]);
    assert_eq!(facade_manifest.dependency_interfaces().len(), 1);
    assert_eq!(
        facade_manifest.dependency_digest(&core),
        Some(core_manifest_digest(&facade_manifest, &core))
    );
    // A re-export cannot make an unexported or unnamed item nameable.
    assert_eq!(
        graph.resolve_name(&facade, "delete"),
        Err(PackageError::ItemNotExported {
            package: facade.clone(),
            name: Arc::from("delete"),
        })
    );
}

/// Returns the dependency interface digest one facade pins for one package.
fn core_manifest_digest<'a>(
    facade: &'a PublicInterfaceManifest,
    core: &PackageIdentity,
) -> &'a InterfaceDigest {
    facade
        .dependency_digest(core)
        .unwrap_or_else(|| unreachable!("the fixture facade pins the defining interface"))
}

#[test]
fn reexport_chain_must_terminate_in_a_defining_exported_item() {
    // A terminating chain of eight instances re-exports one defining exported item.
    let defining_manifest = seal(
        &[nominal_item("Token", Visibility::Exported)],
        &["Token"],
        &[],
        &[],
    )
    .unwrap_or_else(|_| unreachable!("fixture interface is closed"));
    let defining = bound_identity("chain-0", "1.0.0", &[], &defining_manifest);
    let mut manifests = vec![defining_manifest.clone()];
    let mut identities = vec![defining.clone()];
    for index in 1..8 {
        let previous = identities
            .last()
            .unwrap_or_else(|| unreachable!("the chain starts at a defining instance"))
            .clone();
        let previous_manifest = manifests
            .last()
            .unwrap_or_else(|| unreachable!("the chain starts at a defining interface"));
        let manifest = seal(
            &[],
            &["Token"],
            &[ExportEntry {
                exported_name: Arc::from("Token"),
                defining_name: Arc::from("Token"),
                kind: ItemKind::Nominal,
                target: TargetKind::Library,
                defining: previous.clone(),
            }],
            &[DependencyInterfacePin {
                package: previous.clone(),
                interface: previous_manifest.digest().clone(),
            }],
        )
        .unwrap_or_else(|_| unreachable!("fixture interface is closed"));
        let identity = bound_identity(&format!("chain-{index}"), "1.0.0", &[], &manifest);
        manifests.push(manifest);
        identities.push(identity);
    }
    let mut graph = PackageGraph::new();
    graph
        .register_discovered(
            &identities
                .iter()
                .zip(manifests.iter())
                .map(|(identity, manifest)| instance(identity.clone(), manifest.clone()))
                .collect::<Vec<_>>(),
            &identities
                .windows(2)
                .map(|pair| (pair[1].clone(), pair[0].clone()))
                .collect::<Vec<_>>(),
        )
        .unwrap_or_else(|_| unreachable!("every endpoint is registered"));
    let outermost = identities
        .last()
        .unwrap_or_else(|| unreachable!("the chain has a last instance"))
        .clone();
    let resolved = graph
        .resolve_name(&outermost, "Token")
        .unwrap_or_else(|_| unreachable!("the terminating chain reaches an exported item"));
    assert_eq!(resolved.defining_instance(), &defining);
    assert_eq!(resolved.kind(), ItemKind::Nominal);
    assert_eq!(resolved.chain().len(), 7);
    let hops = resolved
        .chain()
        .iter()
        .map(|(instance, _)| instance.clone())
        .collect::<Vec<_>>();
    let unique = hops.iter().collect::<BTreeSet<_>>();
    assert_eq!(hops.len(), unique.len());
    // Every hop moves to a pinned defining instance whose recorded interface
    // digest the re-exporting manifest pins, so a chain cannot revisit a defining
    // instance and therefore cannot fail to terminate: the interface digest is one
    // of the identity inputs, so a manifest cannot embed its own identity.
    for (index, manifest) in manifests.iter().enumerate().skip(1) {
        assert_eq!(manifest.exports().len(), 1);
        let export = &manifest.exports()[0];
        assert_eq!(&export.defining, &identities[index - 1]);
        assert!(manifest.dependency_digest(&export.defining).is_some());
    }
    assert_eq!(graph.validate_acyclic(), Ok(()));

    // A chain whose final link is not exported, and a chain whose final name is
    // defined by no instance, are static errors rather than unresolved names.
    let hidden_manifest = seal(
        &[nominal_item("Token", Visibility::PackageLocal)],
        &["Token"],
        &[],
        &[],
    )
    .unwrap_or_else(|_| unreachable!("fixture interface is closed"));
    let hidden = bound_identity("hidden", "1.0.0", &[], &hidden_manifest);
    let dangling_manifest = seal(
        &[],
        &["Token"],
        &[ExportEntry {
            exported_name: Arc::from("Token"),
            defining_name: Arc::from("absent"),
            kind: ItemKind::Nominal,
            target: TargetKind::Library,
            defining: hidden.clone(),
        }],
        &[DependencyInterfacePin {
            package: hidden.clone(),
            interface: hidden_manifest.digest().clone(),
        }],
    )
    .unwrap_or_else(|_| unreachable!("fixture interface is closed"));
    let dangling = bound_identity("dangling", "1.0.0", &[], &dangling_manifest);
    graph
        .register_discovered(
            &[
                instance(hidden.clone(), hidden_manifest),
                instance(dangling.clone(), dangling_manifest),
            ],
            &[(dangling.clone(), hidden.clone())],
        )
        .unwrap_or_else(|_| unreachable!("every endpoint is registered"));
    assert_eq!(
        graph
            .resolve_name(&dangling, "Token")
            .err()
            .and_then(|error| error.code()),
        Some(PackageDiagnosticCode::ItemNotExported)
    );
    assert_eq!(
        graph.resolve_name(&dangling, "Token"),
        Err(PackageError::ItemNotExported {
            package: hidden.clone(),
            name: Arc::from("absent"),
        })
    );
    assert_eq!(
        graph
            .resolve_name(&dangling, "absent")
            .err()
            .and_then(|error| error.code()),
        Some(PackageDiagnosticCode::ItemNotExported)
    );
    assert_eq!(
        graph.resolve_name(&dangling, "absent"),
        Err(PackageError::ItemNotExported {
            package: dangling.clone(),
            name: Arc::from("absent"),
        })
    );
}

#[test]
fn package_dependency_cycle_is_a_static_error_and_not_a_traversal_choice() {
    let app_manifest = nominal_interface("App");
    let other_manifest = nominal_interface("Other");
    let app = bound_identity("app", "1.0.0", &[], &app_manifest);
    let other = bound_identity("other", "1.0.0", &[], &other_manifest);
    let discovered = vec![
        instance(app.clone(), app_manifest),
        instance(other.clone(), other_manifest),
    ];
    let edges = vec![(app.clone(), other.clone()), (other.clone(), app.clone())];

    let mut graph = PackageGraph::new();
    graph
        .register_discovered(&discovered, &edges)
        .unwrap_or_else(|_| unreachable!("every endpoint is registered"));
    let error = graph
        .validate_acyclic()
        .err()
        .unwrap_or_else(|| unreachable!("a dependency cycle is a static error"));
    match &error {
        PackageError::DependencyCycle { cycle } => {
            assert_eq!(cycle.len(), 2);
            assert!(cycle.contains(&app) && cycle.contains(&other));
        }
        other => unreachable!("unexpected error: {other:?}"),
    }
    assert_eq!(error.code(), None);
    assert_eq!(error.clause(), "GNT-16.5-reexports");
    // The cycle is not broken by traversal order, by discarding one edge, or by
    // choosing one of the participating instances.
    assert_eq!(graph.edge_count(), 2);
    assert_eq!(graph.len(), 2);

    let mut reversed = PackageGraph::new();
    reversed
        .register_discovered(
            &discovered.iter().rev().cloned().collect::<Vec<_>>(),
            &edges.iter().rev().cloned().collect::<Vec<_>>(),
        )
        .unwrap_or_else(|_| unreachable!("every endpoint is registered"));
    assert_eq!(reversed.validate_acyclic(), Err(error));
    assert_eq!(reversed.canonical_bytes(), graph.canonical_bytes());
    // A graph without the closing edge is acyclic, so the rejection is decided by
    // the resolved graph rather than by the order in which edges were discovered.
    let mut acyclic = PackageGraph::new();
    acyclic
        .register_discovered(&discovered, &edges[..1])
        .unwrap_or_else(|_| unreachable!("every endpoint is registered"));
    assert_eq!(acyclic.validate_acyclic(), Ok(()));
    assert_eq!(acyclic.edge_count(), 1);
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// GNT-16.6-target-kinds
// ---------------------------------------------------------------------------
#[test]
fn a_terminating_reexport_chain_longer_than_any_fixed_bound_resolves() {
    const LINKS: usize = 300;
    let terminal_manifest = nominal_interface("Token");
    let mut identities = vec![bound_identity("link300", "1.0.0", &[], &terminal_manifest)];
    let mut manifests = vec![terminal_manifest];
    for index in (0..LINKS).rev() {
        let target = identities[0].clone();
        let manifest = seal(
            &[],
            &["next"],
            &[ExportEntry {
                exported_name: Arc::from("next"),
                defining_name: if index == LINKS - 1 {
                    Arc::from("Token")
                } else {
                    Arc::from("next")
                },
                kind: ItemKind::Nominal,
                target: TargetKind::Library,
                defining: target.clone(),
            }],
            &[DependencyInterfacePin {
                package: target,
                interface: manifests[0].digest().clone(),
            }],
        )
        .unwrap_or_else(|_| unreachable!("fixture interface is closed"));
        identities.insert(
            0,
            bound_identity(&format!("link{index}"), "1.0.0", &[], &manifest),
        );
        manifests.insert(0, manifest);
    }

    let instances = identities
        .iter()
        .cloned()
        .zip(manifests.iter().cloned())
        .map(|(identity, manifest)| instance(identity, manifest))
        .collect::<Vec<_>>();
    let edges = identities
        .windows(2)
        .map(|pair| (pair[0].clone(), pair[1].clone()))
        .collect::<Vec<_>>();
    let mut graph = PackageGraph::new();
    graph
        .register_discovered(&instances, &edges)
        .unwrap_or_else(|_| unreachable!("every link is pinned by its predecessor"));
    let resolved = graph
        .resolve_name(&identities[0], "next")
        .unwrap_or_else(|_| unreachable!("the chain terminates in an exported item"));
    // A chain that terminates is not a cycle, however long it is.
    assert!(resolved.is_reexported());
    assert_eq!(resolved.chain().len(), LINKS);
    assert_eq!(
        resolved.defining_instance(),
        identities
            .last()
            .unwrap_or_else(|| unreachable!("the chain has a terminal instance"))
    );
    assert_eq!(resolved.defining_name(), "Token");
}

#[test]
fn target_kind_vocabulary_is_closed_and_per_kind_entry_rules_hold() {
    assert_eq!(TargetKind::ALL.len(), 5);
    for kind in TargetKind::ALL {
        assert_eq!(TargetKind::from_wire_name(kind.wire_name()), Some(kind));
    }
    assert_eq!(TargetKind::from_wire_name("dylib"), None);
    assert!(TargetKind::Library.is_shipping());
    assert!(TargetKind::Binary.is_shipping());
    assert!(!TargetKind::Test.is_shipping());
    assert!(!TargetKind::Example.is_shipping());
    assert!(!TargetKind::Benchmark.is_shipping());

    let main = path("crate::main");
    let other = path("crate::other");
    // A library target declares no entry point.
    assert_eq!(
        TargetDescriptor::new(TargetKind::Library, "app", std::slice::from_ref(&main)),
        Err(PackageError::TargetKindInvalid {
            kind: Arc::from("library"),
            condition: TargetCondition::LibraryDeclaresEntryPoint,
        })
    );
    assert!(TargetDescriptor::new(TargetKind::Library, "app", &[]).is_ok());
    // A binary target declares exactly one entry point.
    assert_eq!(
        TargetDescriptor::new(TargetKind::Binary, "app", &[]),
        Err(PackageError::TargetKindInvalid {
            kind: Arc::from("binary"),
            condition: TargetCondition::MissingEntryPoint,
        })
    );
    assert_eq!(
        TargetDescriptor::new(TargetKind::Binary, "app", &[main.clone(), other.clone()]),
        Err(PackageError::TargetKindInvalid {
            kind: Arc::from("binary"),
            condition: TargetCondition::MultipleEntryPoints,
        })
    );
    let binary = TargetDescriptor::new(TargetKind::Binary, "app", std::slice::from_ref(&main))
        .unwrap_or_else(|_| unreachable!("one entry point is exactly right for a binary"));
    assert_eq!(binary.kind(), TargetKind::Binary);
    assert_eq!(binary.entry_points().len(), 1);
    assert_eq!(binary.root(), None);
    assert_eq!(
        TargetFacts::new(TargetKind::Library, Some(main.clone())),
        Err(PackageError::TargetKindInvalid {
            kind: Arc::from("library"),
            condition: TargetCondition::LibraryDeclaresEntryPoint,
        })
    );
    assert_eq!(
        TargetFacts::new(TargetKind::Binary, None),
        Err(PackageError::TargetKindInvalid {
            kind: Arc::from("binary"),
            condition: TargetCondition::MissingEntryPoint,
        })
    );

    let test_target = TargetDescriptor::new(TargetKind::Test, "app_test", &[])
        .unwrap_or_else(|_| unreachable!("a non-shipping target is a closed kind"));
    let targets = TargetSet::new(&[binary.clone(), test_target.clone()])
        .unwrap_or_else(|_| unreachable!("fixture target names are distinct"));
    assert_eq!(targets.targets().len(), 2);
    assert!(targets.has_shipping_target());
    assert_eq!(
        TargetSet::new(&[binary.clone(), binary]),
        Err(PackageError::DuplicateDeclaration {
            field: "target",
            value: Arc::from("app")
        })
    );
    let non_shipping = TargetSet::new(&[test_target])
        .unwrap_or_else(|_| unreachable!("fixture target names are distinct"));
    assert_eq!(non_shipping.targets().len(), 1);
    assert!(!non_shipping.has_shipping_target());
}

#[test]
fn non_shipping_target_items_never_enter_another_target_public_interface() {
    let mut probe = nominal_item("Probe", Visibility::Exported);
    probe.target = TargetKind::Test;
    let manifest = seal(
        &[nominal_item("Token", Visibility::Exported), probe],
        &["Token", "Probe"],
        &[],
        &[],
    )
    .unwrap_or_else(|_| unreachable!("fixture interface is closed"));
    // A non-shipping target's items MUST NOT appear in another target's public
    // interface and MUST NOT be represented as shipping authority.
    for shipping in [TargetKind::Library, TargetKind::Binary] {
        assert_eq!(
            manifest.check_shipping_surface(shipping),
            Err(PackageError::TargetKindInvalid {
                kind: Arc::from("test"),
                condition: TargetCondition::NonShippingItemInPublicInterface,
            })
        );
    }
    // A non-shipping kind short-circuits before any item or export is
    // inspected, so a non-shipping target's own surface is not a shipping
    // interface; this pins that early return.
    for non_shipping in [TargetKind::Test, TargetKind::Example, TargetKind::Benchmark] {
        assert!(manifest.check_shipping_surface(non_shipping).is_ok());
    }
    assert!(
        nominal_interface("Token")
            .check_shipping_surface(TargetKind::Library)
            .is_ok()
    );
    assert!(
        manifest
            .items()
            .iter()
            .any(|item| !item.target().is_shipping())
    );
    // The re-export half of the same rule: an export that a non-shipping target
    // declares is never a shipping target's public interface either, even when
    // every item the manifest records is shipping.
    let facade = non_shipping_facade_interface();
    for shipping in [TargetKind::Library, TargetKind::Binary] {
        assert_eq!(
            facade.check_shipping_surface(shipping),
            Err(PackageError::TargetKindInvalid {
                kind: Arc::from("test"),
                condition: TargetCondition::NonShippingExportInPublicInterface,
            })
        );
    }
}

#[test]
fn a_shipping_instance_never_binds_a_non_shipping_target_item_or_reexport() {
    // Sealing a manifest is not enough: both halves of GNT-16.6-target-kinds are
    // re-checked on the mandatory path that binds an instance to the interface
    // it was resolved against, so no shipping instance can hold a surface that a
    // non-shipping target declares.
    let mut probe = nominal_item("Probe", Visibility::Exported);
    probe.target = TargetKind::Test;
    let item_manifest = seal(
        &[nominal_item("Token", Visibility::Exported), probe],
        &["Token", "Probe"],
        &[],
        &[],
    )
    .unwrap_or_else(|_| unreachable!("fixture interface is closed"));
    let library_identity = bound_identity("app", "1.0.0", &[], &item_manifest);
    assert_eq!(
        PackageInstance::new(library_identity, item_manifest.clone()),
        Err(PackageError::TargetKindInvalid {
            kind: Arc::from("test"),
            condition: TargetCondition::NonShippingItemInPublicInterface,
        })
    );
    // A package that declares no shipping target is unaffected: the same
    // manifest binds successfully under a `test` target fact.
    let test_identity = non_shipping_identity("app", &item_manifest);
    assert!(PackageInstance::new(test_identity, item_manifest).is_ok());

    let export_manifest = non_shipping_facade_interface();
    let library_identity = bound_identity("app", "1.0.0", &[], &export_manifest);
    assert_eq!(
        PackageInstance::new(library_identity, export_manifest.clone()),
        Err(PackageError::TargetKindInvalid {
            kind: Arc::from("test"),
            condition: TargetCondition::NonShippingExportInPublicInterface,
        })
    );
    let test_identity = non_shipping_identity("app", &export_manifest);
    assert!(PackageInstance::new(test_identity, export_manifest).is_ok());
}

#[test]
fn a_shipping_interface_never_resolves_a_non_shipping_targets_item() {
    // A test-only defining instance may hold its own test-declared item, and a
    // facade's own records may be entirely shipping; resolving a name across the
    // re-export edge must still refuse to put that item into the shipping
    // facade's public interface.
    let mut probe = nominal_item("Probe", Visibility::Exported);
    probe.target = TargetKind::Test;
    let defining_manifest = seal(&[probe], &["Probe"], &[], &[])
        .unwrap_or_else(|_| unreachable!("fixture interface is closed"));
    let defining = non_shipping_identity("defining", &defining_manifest);
    let facade_manifest = seal(
        &[],
        &["Probe"],
        &[ExportEntry {
            exported_name: Arc::from("Probe"),
            defining_name: Arc::from("Probe"),
            kind: ItemKind::Nominal,
            target: TargetKind::Library,
            defining: defining.clone(),
        }],
        &[DependencyInterfacePin {
            package: defining.clone(),
            interface: defining_manifest.digest().clone(),
        }],
    )
    .unwrap_or_else(|_| unreachable!("fixture facade interface is closed"));
    let facade = bound_identity("facade", "1.0.0", &[], &facade_manifest);
    let mut graph = PackageGraph::new();
    graph
        .register(instance(defining.clone(), defining_manifest))
        .unwrap_or_else(|_| unreachable!("the defining instance registers"));
    graph
        .register(instance(facade.clone(), facade_manifest.clone()))
        .unwrap_or_else(|_| unreachable!("the facade instance registers"));
    graph
        .link(&facade, &defining)
        .unwrap_or_else(|_| unreachable!("the facade edge is pinned"));
    assert_eq!(
        graph.resolve_name(&facade, "Probe"),
        Err(PackageError::TargetKindInvalid {
            kind: Arc::from("test"),
            condition: TargetCondition::NonShippingItemInPublicInterface,
        })
    );
    // The same name stays reachable from an instance that claims no shipping
    // target, because such an interface is not shipping authority.
    let test_facade = non_shipping_identity("test_facade", &facade_manifest);
    graph
        .register(instance(test_facade.clone(), facade_manifest))
        .unwrap_or_else(|_| unreachable!("the non-shipping facade registers"));
    graph
        .link(&test_facade, &defining)
        .unwrap_or_else(|_| unreachable!("the non-shipping facade edge is pinned"));
    assert!(graph.resolve_name(&test_facade, "Probe").is_ok());
}

#[test]
fn export_declaring_target_kind_participates_in_canonical_interface_identity() {
    let token_manifest = nominal_interface("Token");
    let defining = bound_identity("token", "1.0.0", &[], &token_manifest);
    let pin = DependencyInterfacePin {
        package: defining.clone(),
        interface: token_manifest.digest().clone(),
    };
    let facade = |target: TargetKind| {
        seal(
            &[],
            &["Token"],
            &[ExportEntry {
                exported_name: Arc::from("Token"),
                defining_name: Arc::from("Token"),
                kind: ItemKind::Nominal,
                target,
                defining: defining.clone(),
            }],
            std::slice::from_ref(&pin),
        )
        .unwrap_or_else(|_| unreachable!("fixture facade interface is closed"))
    };
    let shipping = facade(TargetKind::Library);
    let non_shipping = facade(TargetKind::Test);
    // The declaring target kind is a recorded manifest fact, so two interfaces
    // that differ only in it have different canonical bytes and identities; the
    // canonical encoding names it as well.
    assert_ne!(shipping.canonical_bytes(), non_shipping.canonical_bytes());
    assert_ne!(shipping.digest(), non_shipping.digest());
    let shipping_text = std::str::from_utf8(shipping.canonical_bytes())
        .unwrap_or_else(|_| unreachable!("canonical bytes are UTF-8"));
    let non_shipping_text = std::str::from_utf8(non_shipping.canonical_bytes())
        .unwrap_or_else(|_| unreachable!("canonical bytes are UTF-8"));
    assert!(shipping_text.contains("\"target\":\"library\""));
    assert!(non_shipping_text.contains("\"target\":\"test\""));
}

#[test]
fn physical_layout_host_paths_and_target_names_do_not_affect_identity() {
    let manifest = nominal_interface("Token");
    let entry_point = path("crate::main");
    let build = |facts: TargetFactSet, feature_names: &[&str]| {
        PackageIdentity::derive(PackageIdentityInputs::new(
            PackageName::new("app").unwrap_or_else(|_| unreachable!("fixture name is valid")),
            PackageVersion::new("1.0.0")
                .unwrap_or_else(|_| unreachable!("fixture version is valid")),
            PackageSourceIdentity::new(manifest_digest("source"), ir_digest("ir")),
            features(feature_names),
            facts,
            target_selection("selection"),
            manifest.digest().clone(),
            GeneratorInputs::empty(),
        ))
    };
    let binary =
        TargetFactSet::new(&[
            TargetFacts::new(TargetKind::Binary, Some(entry_point.clone()))
                .unwrap_or_else(|_| unreachable!("one entry point is exactly right for a binary")),
        ]);
    let first = build(binary.clone(), &[]);
    // Two hosts with different physical layouts, file names, and manifest or
    // project file layouts, and the same declaration set, derive one identity:
    // the model records no host path, directory, or file name at all.
    let second = build(binary.clone(), &[]);
    assert_eq!(first, second);
    assert_eq!(first.canonical_bytes(), second.canonical_bytes());
    assert_eq!(first.digest_hex(), second.digest_hex());
    let layout_left = TargetDescriptor::new(
        TargetKind::Binary,
        "app-layout-left",
        std::slice::from_ref(&entry_point),
    )
    .unwrap_or_else(|_| unreachable!("one entry point is exactly right for a binary"));
    let layout_right = TargetDescriptor::new(
        TargetKind::Binary,
        "app-layout-right",
        std::slice::from_ref(&entry_point),
    )
    .unwrap_or_else(|_| unreachable!("one entry point is exactly right for a binary"));
    assert_ne!(layout_left.name(), layout_right.name());
    assert_eq!(layout_left.entry_points(), layout_right.entry_points());
    // Two hosts with different physical layouts record different host roots, and
    // the recorded root is not an identity input.
    let left_root = layout_left.with_root("/srv/host-left/src");
    let right_root = layout_right.with_root("/srv/host-right/src");
    assert_ne!(left_root.root(), right_root.root());
    assert_eq!(left_root.kind(), right_root.kind());
    assert!(left_root.root().is_some_and(|root| !root.is_empty()));
    assert_eq!(build(binary, &[]), first);
    // The declared entry point is a declaration rather than a layout fact, so it
    // does participate in identity.
    let other_entry = build(
        TargetFactSet::new(&[
            TargetFacts::new(TargetKind::Binary, Some(path("crate::other")))
                .unwrap_or_else(|_| unreachable!("one entry point is exactly right for a binary")),
        ]),
        &[],
    );
    assert_ne!(first, other_entry);
    assert_ne!(
        build(
            TargetFactSet::new(&[TargetFacts::new(TargetKind::Library, None)
                .unwrap_or_else(|_| unreachable!("a library declares no entry point"))]),
            &[],
        ),
        first
    );
    // The declared fact set is an identity input: adding one example target is a
    // different identity, while a target name, a target root, and a host path are
    // not, and the same declaration set recorded twice is one identity.
    let library = || {
        TargetFactSet::new(&[TargetFacts::new(TargetKind::Library, None)
            .unwrap_or_else(|_| unreachable!("a library declares no entry point"))])
    };
    let with_example = TargetFactSet::new(&[
        TargetFacts::new(TargetKind::Library, None)
            .unwrap_or_else(|_| unreachable!("a library declares no entry point")),
        TargetFacts::new(TargetKind::Example, Some(path("crate::demo")))
            .unwrap_or_else(|_| unreachable!("an example declares at most one entry point")),
    ]);
    assert_ne!(build(library(), &[]), build(with_example.clone(), &[]));
    assert_eq!(build(with_example.clone(), &[]), build(with_example, &[]));
    assert_eq!(build(library(), &[]), build(library(), &[]));
}

#[test]
fn declared_capability_ceiling_bounds_and_never_grants() {
    let ceiling = DeclaredCeiling::new("network", 2)
        .unwrap_or_else(|_| unreachable!("fixture ceiling subject is an identifier"));
    assert_eq!(ceiling.subject(), "network");
    assert_eq!(ceiling.strength(), 2);
    let within = RequirementDemand::new("network", 2)
        .unwrap_or_else(|_| unreachable!("fixture demand subject is an identifier"));
    let above = RequirementDemand::new("network", 3)
        .unwrap_or_else(|_| unreachable!("fixture demand subject is an identifier"));
    let other_subject = RequirementDemand::new("filesystem", 1)
        .unwrap_or_else(|_| unreachable!("fixture demand subject is an identifier"));
    assert_eq!(check_ceiling(&ceiling, &within), Ok(()));
    assert_eq!(
        check_ceiling(&ceiling, &above),
        Err(PackageError::RequirementExceedsCeiling {
            subject: Arc::from("network")
        })
    );
    // A ceiling over one subject never admits a demand for another subject.
    assert_eq!(
        check_ceiling(&ceiling, &other_subject),
        Err(PackageError::RequirementExceedsCeiling {
            subject: Arc::from("filesystem")
        })
    );
    // A satisfied ceiling yields the unit value and nothing else: it carries no
    // admitted operation, requirement, or recovery class, so it cannot grant
    // authority or substitute for a resolved requirement.
    assert_eq!(
        std::mem::size_of_val(
            &check_ceiling(&ceiling, &within)
                .unwrap_or_else(|_| unreachable!("the ceiling covers the demand"))
        ),
        0
    );
    assert!(
        PackageError::RequirementExceedsCeiling {
            subject: Arc::from("network")
        }
        .code()
        .is_none()
    );
}
// GNT-16.7-public-interface-manifest
// ---------------------------------------------------------------------------

#[test]
fn public_interface_manifest_records_every_closed_content_group() {
    let mut nominal = nominal_item("Token", Visibility::Exported);
    nominal.nominal = Some(NominalFacts {
        fields: vec![Arc::from("value"), Arc::from("kind")],
        variants: vec![Arc::from("Ready"), Arc::from("Failed")],
        construction: ConstructionPolicy::Sealed,
        exhaustiveness: ExhaustivenessPolicy::NonExhaustive,
        schema: Some(interface_digest("token-schema")),
    });
    let mut function = function_item("read");
    function.bounds = vec![Arc::from("ExternalValue")];
    function.receiver_mode = Some(Arc::from("owned self"));
    function.mode_restrictions = vec![Arc::from("read-only-caller")];
    function.constants = vec![(Arc::from("LIMIT"), Arc::from("16"))];
    let mut effect_row = EffectSet::default();
    assert!(effect_row.insert(Effect::ActionReadOnly));
    function.effect_row = effect_row;
    let mut trait_item = InterfaceItem::new(
        "Convert",
        ItemKind::Trait,
        Visibility::Exported,
        TargetKind::Library,
    )
    .unwrap_or_else(|_| unreachable!("fixture name is an identifier"));
    trait_item.trait_facts = Some(TraitFacts {
        owner: Some(Arc::from("crate::Convert")),
        methods: vec![Arc::from("convert")],
        coherence_impls: vec![Arc::from("impl Convert for crate::Token")],
    });
    let mut capability = InterfaceItem::new(
        "network",
        ItemKind::Capability,
        Visibility::Exported,
        TargetKind::Library,
    )
    .unwrap_or_else(|_| unreachable!("fixture name is an identifier"));
    capability.requirements = vec![Arc::from("core::network")];
    capability.agents = vec![Arc::from("worker")];
    let mut action = action_item("delete", RecoveryClass::NonIdempotent, &["core::network"]);
    action.fulfilment = Some(Arc::from("confirm-before-effect"));
    action.tool_contract = Some(Arc::from("filesystem.delete@v1"));
    action.data_release = Some(Arc::from("audit-record"));
    action.protected_transition = Some(Arc::from("sealed-to-released"));
    let mut operation = InterfaceItem::new(
        "probe",
        ItemKind::Operation,
        Visibility::Exported,
        TargetKind::Library,
    )
    .unwrap_or_else(|_| unreachable!("fixture name is an identifier"));
    operation.signature = Some(CanonicalSignature::function(
        &path("crate::probe"),
        &[],
        &TypeDescriptor::UNIT,
    ));
    let dependency_manifest = nominal_interface("Dep");
    let dependency = bound_identity("dep", "1.0.0", &[], &dependency_manifest);
    let items = vec![nominal, function, trait_item, capability, action, operation];
    let surface = ["Token", "read", "Convert", "network", "delete", "probe"];
    let manifest = seal(
        &items,
        &surface,
        &[],
        &[DependencyInterfacePin {
            package: dependency.clone(),
            interface: dependency_manifest.digest().clone(),
        }],
    )
    .unwrap_or_else(|_| unreachable!("fixture interface is closed"));
    assert_eq!(manifest.items().len(), 6);
    for name in surface {
        assert!(manifest.is_exported(name), "{name}");
    }
    assert_eq!(manifest.edition(), "v2");
    assert_eq!(
        manifest.stdlib_contract(),
        ProtocolVersion { major: 1, minor: 0 }
    );
    assert_eq!(manifest.protocol_versions().len(), 1);
    assert!(manifest.target_predicates().is_empty());
    assert!(manifest.public_features().is_empty());
    assert_eq!(manifest.dependency_interfaces().len(), 1);
    assert_eq!(
        manifest.dependency_digest(&dependency),
        Some(dependency_manifest.digest())
    );
    assert_eq!(
        manifest.item("delete").map(|item| item.recovery),
        Some(Some(RecoveryClass::NonIdempotent))
    );
    assert_eq!(
        manifest.item("Token").map(|item| item.kind()),
        Some(ItemKind::Nominal)
    );
    assert_eq!(
        manifest.item("Token").map(|item| item.visibility()),
        Some(Visibility::Exported)
    );
    assert!(
        manifest
            .item("Token")
            .and_then(|item| item.nominal.as_ref())
            .is_some_and(|nominal| nominal.construction == ConstructionPolicy::Sealed
                && nominal.exhaustiveness == ExhaustivenessPolicy::NonExhaustive)
    );
    assert!(
        manifest
            .item("read")
            .is_some_and(|item| item.receiver_mode.as_deref() == Some("owned self"))
    );

    // The manifest has one canonical encoding over the closed groups, and it is
    // stable under declaration order.
    let text = std::str::from_utf8(manifest.canonical_bytes())
        .unwrap_or_else(|_| unreachable!("the canonical encoding is UTF-8 text"));
    for key in [
        "\"agents\"",
        "\"bounds\"",
        "\"constants\"",
        "\"coherence_impls\"",
        "\"construction\"",
        "\"data_release\"",
        "\"dependency_interfaces\"",
        "\"edition\"",
        "\"effect_row\"",
        "\"exhaustiveness\"",
        "\"exports\"",
        "\"fields\"",
        "\"fulfilment\"",
        "\"items\"",
        "\"methods\"",
        "\"mode_restrictions\"",
        "\"nominal\"",
        "\"owner\"",
        "\"protected_transition\"",
        "\"protocol_versions\"",
        "\"public_features\"",
        "\"receiver_mode\"",
        "\"recovery\"",
        "\"requirements\"",
        "\"schema\"",
        "\"signature\"",
        "\"stdlib_contract\"",
        "\"target_predicates\"",
        "\"tool_contract\"",
        "\"trait\"",
        "\"variants\"",
        "\"version\"",
    ] {
        assert!(text.contains(key), "missing canonical group {key}");
    }
    let reversed = seal(
        &items.iter().rev().cloned().collect::<Vec<_>>(),
        &surface,
        &[],
        &[DependencyInterfacePin {
            package: dependency,
            interface: dependency_manifest.digest().clone(),
        }],
    )
    .unwrap_or_else(|_| unreachable!("fixture interface is closed"));
    assert_eq!(manifest.digest(), reversed.digest());
    assert_eq!(manifest.canonical_bytes(), reversed.canonical_bytes());

    // Content that the recorded kind does not admit is rejected rather than
    // silently narrowed.
    let without_facts = InterfaceItem::new(
        "Token",
        ItemKind::Nominal,
        Visibility::Exported,
        TargetKind::Library,
    )
    .unwrap_or_else(|_| unreachable!("fixture name is an identifier"));
    assert_eq!(
        seal(&[without_facts], &["Token"], &[], &[]),
        Err(PackageError::ItemContentMismatch {
            name: Arc::from("Token"),
            kind: ItemKind::Nominal,
        })
    );
}

#[test]
fn interface_digest_binds_into_instance_identity_and_stale_pins_are_rejected() {
    let token = nominal_interface("Token");
    let other = nominal_interface("Other");
    let bound = bound_identity("app", "1.0.0", &[], &token);
    assert_eq!(bound.interface_digest(), token.digest());
    // A change to a recorded interface fact changes the instance identity.
    let rebound = bound_identity("app", "1.0.0", &[], &other);
    assert_ne!(bound, rebound);
    assert_ne!(bound.interface_digest(), rebound.interface_digest());

    // An interface whose identity does not match the pinned dependency artifact
    // MUST NOT be used, and the failure names both identities.
    assert!(token.check_pinned(token.digest()).is_ok());
    assert_eq!(
        token.check_pinned(other.digest()),
        Err(PackageError::InterfaceMismatch {
            expected: other.digest().clone(),
            observed: token.digest().clone(),
        })
    );
    assert_eq!(
        token
            .check_pinned(other.digest())
            .err()
            .and_then(|error| error.code()),
        Some(PackageDiagnosticCode::InstanceInterfaceMismatch)
    );
    assert_eq!(
        PackageInstance::new(bound.clone(), other.clone()),
        Err(PackageError::InterfaceMismatch {
            expected: token.digest().clone(),
            observed: other.digest().clone(),
        })
    );

    // The interface entry of the resolution record is keyed by package-instance
    // identity and never by an alias spelling.
    let pinned = seal(
        &[],
        &[],
        &[],
        &[DependencyInterfacePin {
            package: rebound.clone(),
            interface: other.digest().clone(),
        }],
    )
    .unwrap_or_else(|_| unreachable!("fixture interface is closed"));
    assert_eq!(pinned.dependency_digest(&rebound), Some(other.digest()));
    assert_eq!(pinned.dependency_digest(&bound), None);
    assert_eq!(pinned.dependency_interfaces()[0].package, rebound);

    // A re-export whose defining instance the manifest does not pin is an
    // unclosed interface rather than a name to resolve through whatever the graph
    // happens to hold, so it is rejected where the manifest is sealed.
    assert_eq!(
        seal(
            &[],
            &["Token"],
            &[ExportEntry {
                exported_name: Arc::from("Token"),
                defining_name: Arc::from("Token"),
                kind: ItemKind::Nominal,
                target: TargetKind::Library,
                defining: bound.clone(),
            }],
            &[],
        ),
        Err(PackageError::UnpinnedExport {
            exported_name: Arc::from("Token"),
            defining: bound.clone(),
        })
    );
}

#[test]
fn reexport_pins_are_enforced_at_registration_and_resolution() {
    let old_interface = nominal_interface("Token");
    let new_interface = nominal_interface("RenamedToken");
    let core_old = bound_identity("core", "1.0.0", &[], &old_interface);
    let core_new = bound_identity("core", "1.0.0", &[], &new_interface);
    assert_ne!(core_old, core_new);
    let facade_manifest = seal(
        &[],
        &["Token"],
        &[ExportEntry {
            exported_name: Arc::from("Token"),
            defining_name: Arc::from("Token"),
            kind: ItemKind::Nominal,
            target: TargetKind::Library,
            defining: core_old.clone(),
        }],
        &[DependencyInterfacePin {
            package: core_old.clone(),
            interface: old_interface.digest().clone(),
        }],
    )
    .unwrap_or_else(|_| unreachable!("fixture interface is closed"));
    let facade = bound_identity("facade", "1.0.0", &[], &facade_manifest);

    // A facade that pins `core` at the old interface while the graph resolves
    // `core` at the new one MUST NOT be linked, registered, or resolved, and the
    // reported failure names both interface identities under
    // `package-instance-interface-mismatch`.
    let stale = PackageError::InterfaceMismatch {
        expected: old_interface.digest().clone(),
        observed: new_interface.digest().clone(),
    };
    assert_eq!(
        stale.clone().code(),
        Some(PackageDiagnosticCode::InstanceInterfaceMismatch)
    );
    let mut rejected = PackageGraph::new();
    assert_eq!(
        rejected.register_discovered(
            &[
                instance(core_new.clone(), new_interface.clone()),
                instance(facade.clone(), facade_manifest.clone()),
            ],
            &[(facade.clone(), core_new.clone())],
        ),
        Err(stale.clone())
    );
    // Resolution verifies the recorded pins itself, so registering the two nodes
    // one at a time cannot make a stale pin resolvable.
    let mut bypassed = PackageGraph::new();
    assert_eq!(
        bypassed.register(instance(core_new.clone(), new_interface)),
        Ok(true)
    );
    assert_eq!(
        bypassed.register(instance(facade.clone(), facade_manifest.clone())),
        Ok(true)
    );
    assert_eq!(bypassed.check_pins(), Err(stale.clone()));
    assert_eq!(bypassed.resolve_name(&facade, "Token"), Err(stale));

    // The matching pin resolves to the defining instance the facade pinned, and
    // the resolution keeps that instance's defining name and kind.
    let mut matching = PackageGraph::new();
    matching
        .register_discovered(
            &[
                instance(core_old.clone(), old_interface.clone()),
                instance(facade.clone(), facade_manifest),
            ],
            &[(facade.clone(), core_old.clone())],
        )
        .unwrap_or_else(|_| unreachable!("the matching pin is satisfied"));
    let resolved = matching
        .resolve_name(&facade, "Token")
        .unwrap_or_else(|_| unreachable!("the pinned defining instance is registered"));
    assert_eq!(resolved.defining_instance(), &core_old);
    assert_eq!(resolved.defining_name(), "Token");
    assert_eq!(resolved.kind(), ItemKind::Nominal);
    assert!(resolved.is_reexported());
    assert_eq!(
        matching
            .interface(&core_old)
            .map(PublicInterfaceManifest::digest),
        Some(old_interface.digest())
    );
}

#[test]
fn manifest_omitting_a_declared_member_is_invalid_and_an_unsupported_version_is_unproven() {
    let token = nominal_item("Token", Visibility::Exported);
    // A manifest that records a member its package does not declare is invalid.
    assert_eq!(
        seal(
            &[token.clone(), nominal_item("hidden", Visibility::Exported)],
            &["Token"],
            &[],
            &[],
        ),
        Err(PackageError::UndeclaredInterfaceMember {
            name: Arc::from("hidden")
        })
    );
    // A manifest that omits a declared member is invalid and is not a narrower
    // interface, and a consumer MUST NOT read absence as non-export.
    assert_eq!(
        seal(std::slice::from_ref(&token), &["Token", "hidden"], &[], &[]),
        Err(PackageError::OmittedDeclaredMember {
            name: Arc::from("hidden")
        })
    );
    assert_eq!(
        seal(
            &[token.clone(), nominal_item("Token", Visibility::Exported)],
            &["Token"],
            &[],
            &[],
        ),
        Err(PackageError::DuplicateInterfaceMember {
            name: Arc::from("Token")
        })
    );

    let metadata = metadata();
    let surface = DeclaredSurface::from_names(&["Token"])
        .unwrap_or_else(|_| unreachable!("fixture surface name is an identifier"));
    let seal_shape = |version| InterfaceSeal {
        version,
        metadata: &metadata,
        surface: &surface,
        items: std::slice::from_ref(&token),
        dependencies: &[],
        exports: &[],
    };
    // An unsupported version is reported as unproven rather than accepted.
    let proof = PublicInterfaceManifest::seal_versioned(seal_shape(2));
    assert_eq!(
        proof,
        InterfaceProof::Unproven(UnprovenReason::UnsupportedInterfaceVersion(2))
    );
    assert!(proof.proved().is_none());
    assert_eq!(
        PublicInterfaceManifest::seal(seal_shape(2)),
        Err(PackageError::UnsupportedInterfaceVersion { version: 2 })
    );
    assert_eq!(
        PublicInterfaceManifest::seal_versioned(seal_shape(PublicInterfaceManifest::VERSION)),
        InterfaceProof::Proved(Box::new(
            PublicInterfaceManifest::seal(seal_shape(PublicInterfaceManifest::VERSION))
                .unwrap_or_else(|_| unreachable!("the fixture interface is closed"))
        ))
    );
}

// ---------------------------------------------------------------------------
// GNT-16.8-compatibility-axes
// ---------------------------------------------------------------------------
#[test]
fn one_name_recorded_as_both_an_item_and_a_reexport_is_rejected() {
    let defining_manifest = nominal_interface("Token");
    let defining = bound_identity("util", "1.0.0", &[], &defining_manifest);
    let sealed = seal(
        &[nominal_item("Token", Visibility::PackageLocal)],
        &["Token"],
        &[ExportEntry {
            exported_name: Arc::from("Token"),
            defining_name: Arc::from("Token"),
            kind: ItemKind::Nominal,
            target: TargetKind::Library,
            defining,
        }],
        &[],
    );
    // One spelling has one meaning inside one frozen interface, so the model
    // rejects the ambiguity rather than deciding it by lookup order.
    assert!(matches!(
        sealed,
        Err(PackageError::DuplicateInterfaceMember { name }) if name.as_ref() == "Token"
    ));
}

/// Returns the two named compared inputs of one comparison.
fn compared(
    previous: &PackageIdentity,
    candidate: &PackageIdentity,
    previous_manifest: &PublicInterfaceManifest,
    candidate_manifest: &PublicInterfaceManifest,
) -> ComparedInputs {
    ComparedInputs {
        previous: ComparedInput::new(
            "previous-package",
            previous.clone(),
            previous_manifest.digest().clone(),
        )
        .unwrap_or_else(|_| unreachable!("fixture compared input is named")),
        candidate: ComparedInput::new(
            "candidate-package",
            candidate.clone(),
            candidate_manifest.digest().clone(),
        )
        .unwrap_or_else(|_| unreachable!("fixture compared input is named")),
    }
}

/// Returns one complete boundary-schema report, optionally changing one surface.
fn boundary_report(
    verdict: AxisVerdict,
    changed: Option<BoundarySchemaSurface>,
) -> BoundarySchemaReport {
    let reports = BoundarySchemaSurface::ALL
        .into_iter()
        .map(|surface| {
            let surface_verdict = if Some(surface) == changed {
                AxisVerdict::Changed
            } else {
                verdict
            };
            BoundarySchemaSubReport::new(
                surface,
                surface_verdict != AxisVerdict::NotChecked,
                surface_verdict,
            )
            .unwrap_or_else(|_| unreachable!("fixture boundary verdict is self-consistent"))
        })
        .collect::<Vec<_>>();
    BoundarySchemaReport::new(&reports)
        .unwrap_or_else(|_| unreachable!("every boundary surface is reported"))
}

/// Returns one complete durable-artifact report over two sub-verdicts.
fn durable_report(linked: AxisVerdict, resume: AxisVerdict) -> DurableArtifactReport {
    let reports = [
        (DurableArtifactRelation::LinkedReplacement, linked),
        (DurableArtifactRelation::DurableResume, resume),
    ]
    .into_iter()
    .map(|(relation, verdict)| {
        DurableArtifactSubReport::new(relation, verdict != AxisVerdict::NotChecked, verdict)
            .unwrap_or_else(|_| unreachable!("fixture durable verdict is self-consistent"))
    })
    .collect::<Vec<_>>();
    DurableArtifactReport::new(&reports)
        .unwrap_or_else(|_| unreachable!("every durable-artifact relation is reported"))
}

/// Returns one fixture source declaration set to compare on the source axis.
fn source_change_report(
    source_changed: bool,
    changed_surface: Option<BoundarySchemaSurface>,
) -> CompatibilityReport {
    let previous_manifest = nominal_interface("Token");
    let candidate_manifest = if source_changed {
        nominal_interface("RenamedToken")
    } else {
        nominal_interface("Token")
    };
    let previous = bound_identity("app", "1.0.0", &[], &previous_manifest);
    let candidate = bound_identity("app", "2.0.0", &[], &candidate_manifest);
    let source = AxisReport::new(
        CompatibilityAxis::Source,
        true,
        if source_changed {
            AxisVerdict::Changed
        } else {
            AxisVerdict::Unchanged
        },
    )
    .unwrap_or_else(|_| unreachable!("fixture source verdict is self-consistent"));
    CompatibilityReport::new(
        compared(
            &previous,
            &candidate,
            &previous_manifest,
            &candidate_manifest,
        ),
        source,
        boundary_report(AxisVerdict::Unchanged, changed_surface),
        AxisReport::new(CompatibilityAxis::Authority, false, AxisVerdict::NotChecked)
            .unwrap_or_else(|_| unreachable!("an unchecked axis is not marked checked")),
        AxisReport::new(
            CompatibilityAxis::DeclaredBehaviour,
            false,
            AxisVerdict::NotChecked,
        )
        .unwrap_or_else(|_| unreachable!("an unchecked axis is not marked checked")),
        durable_report(AxisVerdict::NotChecked, AxisVerdict::NotChecked),
    )
    .unwrap_or_else(|_| unreachable!("fixture axes are labelled consistently"))
}

#[test]
fn compatibility_report_reports_exactly_five_axes_and_never_aggregates() {
    let report = source_change_report(true, None);
    assert_eq!(report.axes(), CompatibilityAxis::ALL);
    assert_eq!(report.axes().len(), 5);
    assert_eq!(CompatibilityAxis::Source.landed_class(), 1);
    assert_eq!(CompatibilityAxis::BoundarySchema.landed_class(), 1);
    assert_eq!(CompatibilityAxis::Authority.landed_class(), 2);
    assert_eq!(CompatibilityAxis::DeclaredBehaviour.landed_class(), 3);
    assert_eq!(CompatibilityAxis::DurableArtifact.landed_class(), 4);
    for (index, axis) in CompatibilityAxis::ALL.into_iter().enumerate() {
        assert_eq!(axis, report.axes()[index]);
        assert!(!axis.wire_name().is_empty());
    }
    // Each axis is reported on its own, with its own machine-checked flag, and no
    // accessor aggregates them into a single compatibility verdict.
    assert_eq!(report.source().axis(), CompatibilityAxis::Source);
    assert!(report.source().machine_checked());
    assert_eq!(report.source().verdict(), AxisVerdict::Changed);
    assert_eq!(report.authority().axis(), CompatibilityAxis::Authority);
    assert!(!report.authority().machine_checked());
    assert_eq!(report.authority().verdict(), AxisVerdict::NotChecked);
    assert_eq!(
        report.declared_behaviour().axis(),
        CompatibilityAxis::DeclaredBehaviour
    );
    assert_eq!(
        report.boundary_schema().reports().len(),
        BoundarySchemaSurface::ALL.len()
    );
    assert_eq!(
        report.durable_artifact().reports().len(),
        DurableArtifactRelation::ALL.len()
    );
    // The compared inputs are named and their identities are distinct.
    assert_eq!(report.compared().previous.name.as_ref(), "previous-package");
    assert_eq!(
        report.compared().candidate.name.as_ref(),
        "candidate-package"
    );
    assert_ne!(
        report.compared().previous.identity,
        report.compared().candidate.identity
    );
    assert_ne!(
        report.compared().previous.interface,
        report.compared().candidate.interface
    );
}

#[test]
fn boundary_schema_subsurface_changes_are_never_collapsed_into_the_source_axis() {
    // A source-visible declaration change with unchanged boundary acceptance.
    let source_only = source_change_report(true, None);
    assert_eq!(source_only.source().verdict(), AxisVerdict::Changed);
    for surface in BoundarySchemaSurface::ALL {
        assert_eq!(
            source_only.boundary_schema().verdict(surface),
            Some(AxisVerdict::Unchanged)
        );
    }
    assert!(source_only.boundary_schema().is_fully_machine_checked());

    // The reverse: unchanged exported declarations with one changed boundary
    // surface, reported distinctly from the source axis.
    let boundary_only = source_change_report(false, Some(BoundarySchemaSurface::Action));
    assert_eq!(boundary_only.source().verdict(), AxisVerdict::Unchanged);
    assert_eq!(
        boundary_only
            .boundary_schema()
            .verdict(BoundarySchemaSurface::Action),
        Some(AxisVerdict::Changed)
    );
    assert_eq!(
        boundary_only
            .boundary_schema()
            .verdict(BoundarySchemaSurface::Entry),
        Some(AxisVerdict::Unchanged)
    );
    assert_eq!(
        boundary_only
            .boundary_schema()
            .reports()
            .iter()
            .map(|report| report.verdict())
            .collect::<Vec<_>>(),
        [
            AxisVerdict::Unchanged,
            AxisVerdict::Changed,
            AxisVerdict::Unchanged,
            AxisVerdict::Unchanged,
            AxisVerdict::Unchanged,
            AxisVerdict::Unchanged,
        ]
    );
    // The boundary axis has no single collapsed verdict, and every surface is
    // reported.
    assert_eq!(
        boundary_only.boundary_schema().reports().len(),
        BoundarySchemaSurface::ALL.len()
    );
    assert_eq!(
        BoundarySchemaReport::new(&[BoundarySchemaSubReport::new(
            BoundarySchemaSurface::Entry,
            true,
            AxisVerdict::Unchanged,
        )
        .unwrap_or_else(|_| unreachable!("fixture sub-report is self-consistent"))]),
        Err(PackageError::IncompleteCompatibilityReport {
            axis: CompatibilityAxis::BoundarySchema
        })
    );
    // An unchecked surface is reported as not checked rather than as compatible.
    assert_eq!(
        AxisReport::new(CompatibilityAxis::Source, false, AxisVerdict::Unchanged),
        Err(PackageError::UncheckedAxisReportedAsCompatible {
            axis: CompatibilityAxis::Source
        })
    );
    assert_eq!(
        AxisReport::new(CompatibilityAxis::Source, true, AxisVerdict::NotChecked),
        Err(PackageError::NotCheckedAxisMarkedChecked {
            axis: CompatibilityAxis::Source
        })
    );
    assert_eq!(
        BoundarySchemaSubReport::new(BoundarySchemaSurface::Entry, false, AxisVerdict::Unchanged),
        Err(PackageError::UncheckedAxisReportedAsCompatible {
            axis: CompatibilityAxis::BoundarySchema
        })
    );
    assert!(AxisReport::new(CompatibilityAxis::Source, false, AxisVerdict::NotChecked).is_ok());
}

#[test]
fn durable_artifact_linked_replacement_and_durable_resume_are_reported_distinctly() {
    let durable = durable_report(AxisVerdict::Changed, AxisVerdict::Unchanged);
    assert_eq!(
        durable.verdict(DurableArtifactRelation::LinkedReplacement),
        Some(AxisVerdict::Changed)
    );
    assert_eq!(
        durable.verdict(DurableArtifactRelation::DurableResume),
        Some(AxisVerdict::Unchanged)
    );
    assert_ne!(
        durable.verdict(DurableArtifactRelation::LinkedReplacement),
        durable.verdict(DurableArtifactRelation::DurableResume)
    );
    assert_eq!(durable.reports().len(), DurableArtifactRelation::ALL.len());
    assert!(
        durable
            .reports()
            .iter()
            .all(DurableArtifactSubReport::machine_checked)
    );
    // The two relations MUST NOT be merged into one verdict, and an incomplete
    // report is rejected rather than read as a merged verdict.
    assert_eq!(
        DurableArtifactReport::new(&[DurableArtifactSubReport::new(
            DurableArtifactRelation::LinkedReplacement,
            true,
            AxisVerdict::Changed,
        )
        .unwrap_or_else(|_| unreachable!("fixture sub-report is self-consistent"))]),
        Err(PackageError::IncompleteCompatibilityReport {
            axis: CompatibilityAxis::DurableArtifact
        })
    );

    // The durable axis is one of the five reported axes and stays independent of
    // the source and boundary-schema axes.
    let previous_manifest = nominal_interface("Token");
    let candidate_manifest = nominal_interface("RenamedToken");
    let previous = bound_identity("app", "1.0.0", &[], &previous_manifest);
    let candidate = bound_identity("app", "2.0.0", &[], &candidate_manifest);
    let report = CompatibilityReport::new(
        compared(
            &previous,
            &candidate,
            &previous_manifest,
            &candidate_manifest,
        ),
        AxisReport::new(CompatibilityAxis::Source, true, AxisVerdict::Unchanged)
            .unwrap_or_else(|_| unreachable!("fixture source verdict is self-consistent")),
        boundary_report(AxisVerdict::Unchanged, None),
        AxisReport::new(CompatibilityAxis::Authority, false, AxisVerdict::NotChecked)
            .unwrap_or_else(|_| unreachable!("an unchecked axis is not marked checked")),
        AxisReport::new(
            CompatibilityAxis::DeclaredBehaviour,
            false,
            AxisVerdict::NotChecked,
        )
        .unwrap_or_else(|_| unreachable!("an unchecked axis is not marked checked")),
        durable_report(AxisVerdict::Changed, AxisVerdict::Unchanged),
    )
    .unwrap_or_else(|_| unreachable!("fixture axes are labelled consistently"));
    assert_eq!(report.source().verdict(), AxisVerdict::Unchanged);
    assert_eq!(
        report
            .durable_artifact()
            .verdict(DurableArtifactRelation::LinkedReplacement),
        Some(AxisVerdict::Changed)
    );
}

#[test]
fn interface_equality_is_not_behavioural_compatibility_and_unchecked_axes_are_not_compatible() {
    let previous_manifest = nominal_interface("Token");
    let candidate_manifest = nominal_interface("Token");
    assert_eq!(previous_manifest.digest(), candidate_manifest.digest());
    let previous = bound_identity("app", "1.0.0", &[], &previous_manifest);
    let candidate = bound_identity("app", "2.0.0", &[], &candidate_manifest);
    let equal = CompatibilityReport::for_interface_equality(
        compared(
            &previous,
            &candidate,
            &previous_manifest,
            &candidate_manifest,
        ),
        &previous_manifest,
        &candidate_manifest,
    );
    // Equal exported declarations establish the source and boundary-schema axes.
    assert_eq!(equal.source().verdict(), AxisVerdict::Unchanged);
    assert!(equal.source().machine_checked());
    // The encoding records no per-surface boundary-schema fact, so no surface is
    // reported as machine-checked and none is reported as unchanged: the model
    // never compared those surfaces and MUST NOT claim that it did.
    for surface in BoundarySchemaSurface::ALL {
        assert_eq!(
            equal.boundary_schema().verdict(surface),
            Some(AxisVerdict::NotChecked)
        );
    }
    assert!(!equal.boundary_schema().is_fully_machine_checked());
    // They establish nothing further: interface, signature, and schema equality is
    // never behavioural compatibility, never an authority verdict, and never a
    // linked-replacement or durable-resume verdict.
    assert_eq!(
        equal.declared_behaviour().verdict(),
        AxisVerdict::NotChecked
    );
    assert!(!equal.declared_behaviour().machine_checked());
    assert_ne!(equal.declared_behaviour().verdict(), AxisVerdict::Unchanged);
    assert_eq!(equal.authority().verdict(), AxisVerdict::NotChecked);
    assert_eq!(
        equal
            .durable_artifact()
            .verdict(DurableArtifactRelation::LinkedReplacement),
        Some(AxisVerdict::NotChecked)
    );
    assert_eq!(
        equal
            .durable_artifact()
            .verdict(DurableArtifactRelation::DurableResume),
        Some(AxisVerdict::NotChecked)
    );

    // An unequal interface establishes neither of the two axes, and is reported as
    // changed with the two compared interface digests named, rather than as an
    // unchecked axis that would hide the observed difference.
    let other_manifest = nominal_interface("Other");
    assert_ne!(previous_manifest.digest(), other_manifest.digest());
    let unequal = CompatibilityReport::for_interface_equality(
        compared(&previous, &candidate, &previous_manifest, &other_manifest),
        &previous_manifest,
        &other_manifest,
    );
    assert_eq!(unequal.source().verdict(), AxisVerdict::Changed);
    assert!(unequal.source().machine_checked());
    assert_eq!(
        unequal.compared().previous.interface,
        previous_manifest.digest().clone()
    );
    assert_eq!(
        unequal.compared().candidate.interface,
        other_manifest.digest().clone()
    );
    assert_ne!(
        unequal.compared().previous.interface,
        unequal.compared().candidate.interface
    );
    assert!(!unequal.boundary_schema().is_fully_machine_checked());
    assert_eq!(
        unequal
            .boundary_schema()
            .verdict(BoundarySchemaSurface::Entry),
        Some(AxisVerdict::NotChecked)
    );
    assert_ne!(AxisVerdict::NotChecked, AxisVerdict::Unchanged);
    assert_eq!(equal.axes(), unequal.axes());
    assert_eq!(equal.axes().len(), 5);
}

// ---------------------------------------------------------------------------
// GNT-16.9-resolution-order-independence
// ---------------------------------------------------------------------------

#[test]
fn resolution_and_diagnostics_are_identical_under_every_permutation() {
    let app_manifest = nominal_interface("App");
    let left_manifest = nominal_interface("Left");
    let right_manifest = nominal_interface("Right");
    let util_manifest = nominal_interface("Token");
    let app = bound_identity("app", "1.0.0", &[], &app_manifest);
    let left = bound_identity("left", "1.0.0", &[], &left_manifest);
    let right = bound_identity("right", "1.0.0", &[], &right_manifest);
    let util = bound_identity("util", "1.0.0", &[], &util_manifest);
    let discovered = [
        instance(app.clone(), app_manifest),
        instance(left.clone(), left_manifest),
        instance(util.clone(), util_manifest),
        instance(right.clone(), right_manifest),
    ];
    let edges = [
        (app.clone(), left.clone()),
        (left.clone(), util.clone()),
        (app.clone(), right.clone()),
        (right.clone(), util.clone()),
    ];
    let mut scope = DeclaringPackageScope::new(app.clone(), DeclaredNamespaces::new());
    scope
        .declare_dependency("dep", util.clone())
        .unwrap_or_else(|_| unreachable!("fixture alias collides with nothing"));
    let missing = QualifiedPath::new("dep::Missing")
        .unwrap_or_else(|_| unreachable!("fixture path is valid"));
    let exported =
        QualifiedPath::new("dep::Token").unwrap_or_else(|_| unreachable!("fixture path is valid"));

    // Every permutation of discovery, directory enumeration, traversal, and
    // registry response order is one permutation of the same unordered multiset.
    let orders: [(&[usize], &[usize]); 4] = [
        (&[0, 1, 2, 3], &[0, 1, 2, 3]),
        (&[3, 2, 1, 0], &[3, 2, 1, 0]),
        (&[2, 0, 3, 1], &[1, 3, 0, 2]),
        (&[1, 3, 0, 2], &[2, 0, 3, 1]),
    ];
    type Observation = (
        Vec<u8>,
        Vec<String>,
        ResolvedName,
        Result<ResolvedName, PackageError>,
    );
    let mut baseline: Option<Observation> = None;
    for (instance_order, edge_order) in orders {
        let instances = instance_order
            .iter()
            .map(|index| discovered[*index].clone())
            .collect::<Vec<_>>();
        let permuted_edges = edge_order
            .iter()
            .map(|index| edges[*index].clone())
            .collect::<Vec<_>>();
        let mut graph = PackageGraph::new();
        graph
            .register_discovered(&instances, &permuted_edges)
            .unwrap_or_else(|_| unreachable!("every endpoint is registered"));
        assert_eq!(graph.len(), 4);
        assert_eq!(graph.edge_count(), 4);
        assert_eq!(graph.validate_acyclic(), Ok(()));

        // The same resolved graph, the same instance identities, and the same
        // interface digests under every permutation.
        let canonical = graph.canonical_bytes();
        let identities = graph
            .instances()
            .map(|instance| instance.identity().digest_hex())
            .collect::<Vec<_>>();
        let resolved = scope
            .resolve_qualified(&graph, &exported)
            .unwrap_or_else(|_| unreachable!("the declared alias resolves to an exported item"));
        assert_eq!(resolved.defining_instance(), &util);
        // The same diagnostics under every permutation, never an outcome derived
        // from first-wins, last-wins, nearest-wins, or preference ordering.
        let diagnostic = scope.resolve_qualified(&graph, &missing);
        assert_eq!(
            diagnostic,
            Err(PackageError::ItemNotExported {
                package: util.clone(),
                name: Arc::from("Missing"),
            })
        );
        match &baseline {
            None => baseline = Some((canonical, identities, resolved, diagnostic)),
            Some((expected_canonical, expected_identities, expected_resolved, expected)) => {
                assert_eq!(&canonical, expected_canonical);
                assert_eq!(&identities, expected_identities);
                assert_eq!(&identities.len(), &4);
                assert_eq!(&resolved, expected_resolved);
                assert_eq!(&diagnostic, expected);
            }
        }
    }
    assert!(baseline.is_some());
}

#[test]
fn generator_declared_inputs_outputs_and_hashes_participate_in_identity() {
    let manifest = nominal_interface("Token");
    let build = |generators: GeneratorInputs| {
        PackageIdentity::derive(PackageIdentityInputs::new(
            PackageName::new("app").unwrap_or_else(|_| unreachable!("fixture name is valid")),
            PackageVersion::new("1.0.0")
                .unwrap_or_else(|_| unreachable!("fixture version is valid")),
            PackageSourceIdentity::new(manifest_digest("source"), ir_digest("ir")),
            features(&[]),
            library_facts(),
            target_selection("selection"),
            manifest.digest().clone(),
            generators,
        ))
    };
    let schema = GeneratorInput::new("schema", GeneratorInputRole::Input, &hex("schema"))
        .unwrap_or_else(|_| unreachable!("fixture generator declaration is well formed"));
    let lock = GeneratorInput::new("lock", GeneratorInputRole::Output, &hex("lock"))
        .unwrap_or_else(|_| unreachable!("fixture generator declaration is well formed"));
    let declared = build(
        GeneratorInputs::new(&[schema.clone(), lock.clone()])
            .unwrap_or_else(|_| unreachable!("fixture generator declarations are distinct")),
    );
    // Declared inputs, outputs, and hashes enter the artifact identity.
    assert_ne!(declared, build(GeneratorInputs::empty()));
    assert_ne!(
        declared,
        build(
            GeneratorInputs::new(&[
                GeneratorInput::new("schema", GeneratorInputRole::Input, &hex("schema-v2"))
                    .unwrap_or_else(|_| unreachable!(
                        "fixture generator declaration is well formed"
                    )),
                lock.clone(),
            ])
            .unwrap_or_else(|_| unreachable!("fixture generator declarations are distinct"))
        )
    );
    assert_ne!(
        declared,
        build(
            GeneratorInputs::new(&[
                GeneratorInput::new("schema", GeneratorInputRole::Output, &hex("schema"))
                    .unwrap_or_else(|_| unreachable!(
                        "fixture generator declaration is well formed"
                    )),
                lock.clone(),
            ])
            .unwrap_or_else(|_| unreachable!("fixture generator declarations are distinct"))
        )
    );
    assert_ne!(
        declared,
        build(
            GeneratorInputs::new(&[
                schema.clone(),
                GeneratorInput::new("lock", GeneratorInputRole::Output, &hex("lock-v2"))
                    .unwrap_or_else(|_| unreachable!(
                        "fixture generator declaration is well formed"
                    )),
            ])
            .unwrap_or_else(|_| unreachable!("fixture generator declarations are distinct"))
        )
    );
    // Declaration order is not identity, an undeclared input is not admitted, and
    // the declarations are canonically ordered by name.
    let reordered = build(
        GeneratorInputs::new(&[lock, schema.clone()])
            .unwrap_or_else(|_| unreachable!("fixture generator declarations are distinct")),
    );
    assert_eq!(declared, reordered);
    assert_eq!(
        declared.inputs().generator_inputs().as_slice()[0]
            .name
            .as_ref(),
        "lock"
    );
    assert_eq!(declared.inputs().generator_inputs().as_slice().len(), 2);
    assert_eq!(
        GeneratorInputs::new(&[schema.clone(), schema]),
        Err(PackageError::DuplicateDeclaration {
            field: "generator input",
            value: Arc::from("schema")
        })
    );
    // An undeclared or malformed generator declaration is not admitted.
    assert!(GeneratorInput::new("schema", GeneratorInputRole::Input, "not-a-digest").is_err());
    assert!(
        GeneratorInputs::new(&[GeneratorInput {
            name: Arc::from("schema"),
            role: GeneratorInputRole::Input,
            digest: Arc::from("not-a-digest"),
        }])
        .is_err()
    );
}

#[test]
fn package_model_declares_no_mutable_package_global_and_loads_no_source() {
    // Resolving, loading, or linking a package MUST NOT run source code, acquire
    // authority, read host state, or rely on package-level state created when a
    // package is loaded. The model therefore has no mutable global, no
    // interior-mutability cell, and no host filesystem, process, or environment
    // access, so nothing it does can observe or depend on host state.
    let forbidden = [
        "static mut",
        "thread_local!",
        "OnceLock",
        "RefCell",
        "Mutex",
        "std::fs",
        "std::process",
        "std::env",
        "unsafe",
    ];
    for (index, line) in MODEL_SOURCE.lines().enumerate() {
        if line.trim_start().starts_with("//") {
            continue;
        }
        for pattern in forbidden {
            assert!(
                !line.contains(pattern),
                "crates/gantry-ir/src/package.rs:{} contains {pattern}",
                index + 1
            );
        }
    }

    // A fresh graph is empty, equal to the default graph, and stable across
    // construction, so no package state is created by linking this model.
    let fresh = PackageGraph::new();
    assert!(fresh.is_empty());
    assert_eq!(fresh.len(), 0);
    assert_eq!(fresh, PackageGraph::default());
    assert_eq!(
        fresh.canonical_bytes(),
        PackageGraph::new().canonical_bytes()
    );
    // The model exposes no loader: an unregistered instance is reported unresolved
    // rather than loaded from a host path or a registry.
    let identity = bound_identity("app", "1.0.0", &[], &nominal_interface("Token"));
    assert_eq!(fresh.instance(&identity), None);
    assert_eq!(fresh.interface(&identity), None);
    assert_eq!(
        fresh.resolve_name(&identity, "Token"),
        Err(PackageError::UnknownInstance {
            package: identity.clone()
        })
    );
    assert_eq!(
        fresh
            .interface(&identity)
            .and_then(|manifest| manifest.item("Token")),
        None
    );
}

#[test]
fn every_published_package_diagnostic_code_is_registered_sorted_unique_with_a_unique_meaning() {
    assert_eq!(validate_diagnostic_code_registry(), Ok(()));
    let mut meanings = Vec::new();
    for code in PackageDiagnosticCode::ALL {
        let definition = DIAGNOSTIC_CODE_REGISTRY
            .iter()
            .find(|definition| definition.code == code.as_str())
            .unwrap_or_else(|| unreachable!("every published package code is registered"));
        assert_eq!(definition.phase, DiagnosticPhase::Package);
        assert_eq!(definition.category, DiagnosticCategory::Package);
        assert!(!definition.meaning.is_empty());
        assert_eq!(definition.meaning, code.meaning());
        assert!(code.clause().starts_with("GNT-16."));
        assert_eq!(
            PackageDiagnosticCode::ALL
                .iter()
                .filter(|candidate| candidate.as_str() == code.as_str())
                .count(),
            1
        );
        meanings.push(code.meaning());
    }
    meanings.sort_unstable();
    assert!(meanings.windows(2).all(|pair| pair[0] != pair[1]));
    // The registry holds exactly these frozen package codes in sorted order.
    let registered = DIAGNOSTIC_CODE_REGISTRY
        .iter()
        .filter(|definition| definition.code.starts_with("package-"))
        .map(|definition| definition.code)
        .collect::<Vec<_>>();
    assert_eq!(
        registered,
        PackageDiagnosticCode::ALL
            .map(PackageDiagnosticCode::as_str)
            .to_vec()
    );
    assert_eq!(registered.len(), 7);
    assert!(registered.windows(2).all(|pair| pair[0] < pair[1]));
    // A condition that has no published code stays a typed error and never borrows
    // another condition's code.
    assert_eq!(
        PackageError::DependencyCycle { cycle: Vec::new() }.code(),
        None
    );
    assert_eq!(
        PackageError::UnsupportedInterfaceVersion { version: 2 }.code(),
        None
    );
    assert_eq!(
        PackageError::AliasCollision {
            namespace: AliasNamespace::Item,
            alias: Arc::from("util"),
            conflicting: Arc::from("util"),
            condition: CollisionCondition::Exact,
        }
        .code(),
        Some(PackageDiagnosticCode::AliasCollision)
    );
    assert_eq!(
        PackageError::TargetKindInvalid {
            kind: Arc::from("binary"),
            condition: TargetCondition::MissingEntryPoint,
        }
        .code(),
        Some(PackageDiagnosticCode::TargetKindInvalid)
    );
    assert_eq!(
        PackageError::ReexportCycle {
            package: bound_identity("app", "1.0.0", &[], &nominal_interface("Token")),
            name: Arc::from("Token"),
        }
        .code(),
        Some(PackageDiagnosticCode::ReexportCycle)
    );
    assert_eq!(
        PackageError::TransitiveUndeclared {
            package: Arc::from("transdep"),
            accessed: Arc::from("dep::transdep::Thing"),
        }
        .code(),
        Some(PackageDiagnosticCode::TransitiveUndeclared)
    );
}

/// `SPEC.md` 11277-11320 (`GNT-16.8-compatibility-axes`): one comparison reports five axes, marks
/// each axis machine-checked or not, refuses an unchecked axis presented as checked or compatible,
/// keeps the boundary-schema and durable-artifact sub-relations complete and distinct, and exposes
/// each axis separately rather than aggregating them into one verdict.
#[test]
fn compatibility_axes_report_five_separate_relations_and_refuse_unchecked_claims() {
    // The five axes refine the four landed classes in reporting order: source and boundary schema
    // refine class 1, authority is class 2, declared behaviour is class 3, and the durable artifact
    // axis refines class 4.
    assert_eq!(
        CompatibilityAxis::ALL.map(CompatibilityAxis::wire_name),
        [
            "source",
            "boundary-schema",
            "authority",
            "declared-behaviour",
            "durable-artifact"
        ]
    );
    assert_eq!(
        CompatibilityAxis::ALL.map(CompatibilityAxis::landed_class),
        [1, 1, 2, 3, 4]
    );
    assert_eq!(
        BoundarySchemaSurface::ALL.map(BoundarySchemaSurface::wire_name),
        [
            "entry",
            "action",
            "model",
            "tool",
            "artifact",
            "protected-reference"
        ]
    );
    assert_eq!(
        DurableArtifactRelation::ALL.map(DurableArtifactRelation::wire_name),
        ["linked-replacement", "durable-resume"]
    );

    // A machine-checked axis reports changed or unchanged; an unchecked axis reports only
    // `not-checked`, and no unchecked axis is ever reported as compatible.
    for verdict in [AxisVerdict::Changed, AxisVerdict::Unchanged] {
        assert!(
            AxisReport::new(CompatibilityAxis::Source, true, verdict).is_ok(),
            "a checked source axis reports `{verdict:?}`"
        );
    }
    assert!(AxisReport::new(CompatibilityAxis::Source, false, AxisVerdict::NotChecked).is_ok());
    let marked_checked =
        match AxisReport::new(CompatibilityAxis::Source, true, AxisVerdict::NotChecked) {
            Ok(_) => panic!("an unchecked axis cannot be marked checked"),
            Err(error) => error,
        };
    assert!(matches!(
        marked_checked,
        PackageError::NotCheckedAxisMarkedChecked {
            axis: CompatibilityAxis::Source
        }
    ));
    let checked_claim =
        match AxisReport::new(CompatibilityAxis::Authority, false, AxisVerdict::Unchanged) {
            Ok(_) => panic!("an unchecked axis cannot be reported compatible"),
            Err(error) => error,
        };
    assert!(matches!(
        checked_claim,
        PackageError::UncheckedAxisReportedAsCompatible {
            axis: CompatibilityAxis::Authority
        }
    ));
    for refusal in [marked_checked, checked_claim] {
        assert_eq!(refusal.code(), None, "{refusal} has no published code");
        assert_eq!(
            refusal.clause(),
            "GNT-16.8-compatibility-axes",
            "{refusal} is owned by the compatibility-axes clause"
        );
    }

    // Every boundary surface and both durable sub-relations are reported; an incomplete set is
    // refused rather than partially reported.
    let surfaces = BoundarySchemaSurface::ALL
        .into_iter()
        .map(|surface| {
            BoundarySchemaSubReport::new(surface, true, AxisVerdict::Unchanged)
                .unwrap_or_else(|error| panic!("a checked surface reports unchanged: {error}"))
        })
        .collect::<Vec<_>>();
    let schema = BoundarySchemaReport::new(&surfaces)
        .unwrap_or_else(|error| panic!("every boundary surface is reported: {error}"));
    assert!(matches!(
        BoundarySchemaReport::new(&surfaces[..BoundarySchemaSurface::ALL.len() - 1]),
        Err(PackageError::IncompleteCompatibilityReport {
            axis: CompatibilityAxis::BoundarySchema
        })
    ));
    let relations = DurableArtifactRelation::ALL
        .into_iter()
        .map(|relation| {
            DurableArtifactSubReport::new(relation, true, AxisVerdict::Changed)
                .unwrap_or_else(|error| panic!("a checked relation reports changed: {error}"))
        })
        .collect::<Vec<_>>();
    let durable = DurableArtifactReport::new(&relations)
        .unwrap_or_else(|error| panic!("every durable relation is reported: {error}"));
    assert!(matches!(
        DurableArtifactReport::new(&relations[..1]),
        Err(PackageError::IncompleteCompatibilityReport {
            axis: CompatibilityAxis::DurableArtifact
        })
    ));

    // The report exposes the compared inputs and each axis separately, so the two durable
    // sub-relations keep their own verdicts and no aggregate verdict exists.
    let previous = nominal_interface("widget");
    let candidate = nominal_interface("widget");
    let compared = ComparedInputs {
        previous: ComparedInput::new(
            "previous",
            bound_identity("widget", "1.0.0", &[], &previous),
            previous.digest().clone(),
        )
        .unwrap_or_else(|error| panic!("the previous compared input is valid: {error}")),
        candidate: ComparedInput::new(
            "candidate",
            bound_identity("widget", "1.1.0", &[], &candidate),
            candidate.digest().clone(),
        )
        .unwrap_or_else(|error| panic!("the candidate compared input is valid: {error}")),
    };
    let report = CompatibilityReport::new(
        compared,
        AxisReport::new(CompatibilityAxis::Source, true, AxisVerdict::Unchanged)
            .unwrap_or_else(|error| panic!("a checked source axis: {error}")),
        schema,
        AxisReport::new(CompatibilityAxis::Authority, false, AxisVerdict::NotChecked)
            .unwrap_or_else(|error| panic!("an unchecked authority axis: {error}")),
        AxisReport::new(
            CompatibilityAxis::DeclaredBehaviour,
            false,
            AxisVerdict::NotChecked,
        )
        .unwrap_or_else(|error| panic!("an unchecked behaviour axis: {error}")),
        durable,
    )
    .unwrap_or_else(|error| panic!("a complete five-axis report is admitted: {error}"));
    assert_eq!(report.compared().previous.name.as_ref(), "previous");
    assert_eq!(report.source().axis(), CompatibilityAxis::Source);
    assert!(report.source().machine_checked());
    assert_eq!(report.source().verdict(), AxisVerdict::Unchanged);
    assert_eq!(report.authority().verdict(), AxisVerdict::NotChecked);
    assert!(!report.authority().machine_checked());
    assert_eq!(
        report.declared_behaviour().axis(),
        CompatibilityAxis::DeclaredBehaviour
    );
    assert_eq!(
        report
            .boundary_schema()
            .verdict(BoundarySchemaSurface::Model),
        Some(AxisVerdict::Unchanged)
    );
    assert_eq!(
        report
            .durable_artifact()
            .verdict(DurableArtifactRelation::LinkedReplacement),
        Some(AxisVerdict::Changed)
    );
    assert_eq!(
        report
            .durable_artifact()
            .verdict(DurableArtifactRelation::DurableResume),
        Some(AxisVerdict::Changed)
    );
}

/// `SPEC.md` 11277-11320 (`GNT-16.8-compatibility-axes`): each of the five axes lives in its own
/// report slot. `CompatibilityReport::new` refuses a scalar axis report whose embedded axis does not
/// match the slot it is placed in, and that incompleteness refusal is owned by this clause with no
/// published diagnostic code.
#[test]
fn compatibility_report_refuses_an_axis_report_in_another_axis_slot() {
    let compared = || {
        let previous = nominal_interface("widget");
        let candidate = nominal_interface("widget");
        ComparedInputs {
            previous: ComparedInput::new(
                "previous",
                bound_identity("widget", "1.0.0", &[], &previous),
                previous.digest().clone(),
            )
            .unwrap_or_else(|error| panic!("the previous compared input is valid: {error}")),
            candidate: ComparedInput::new(
                "candidate",
                bound_identity("widget", "1.1.0", &[], &candidate),
                candidate.digest().clone(),
            )
            .unwrap_or_else(|error| panic!("the candidate compared input is valid: {error}")),
        }
    };
    let schema = || {
        BoundarySchemaReport::new(
            &BoundarySchemaSurface::ALL
                .into_iter()
                .map(|surface| {
                    BoundarySchemaSubReport::new(surface, true, AxisVerdict::Unchanged)
                        .unwrap_or_else(|error| {
                            panic!("a checked surface reports unchanged: {error}")
                        })
                })
                .collect::<Vec<_>>(),
        )
        .unwrap_or_else(|error| panic!("every boundary surface is reported: {error}"))
    };
    let durable = || {
        DurableArtifactReport::new(
            &DurableArtifactRelation::ALL
                .into_iter()
                .map(|relation| {
                    DurableArtifactSubReport::new(relation, true, AxisVerdict::Changed)
                        .unwrap_or_else(|error| {
                            panic!("a checked relation reports changed: {error}")
                        })
                })
                .collect::<Vec<_>>(),
        )
        .unwrap_or_else(|error| panic!("every durable relation is reported: {error}"))
    };
    let source = || {
        AxisReport::new(CompatibilityAxis::Source, true, AxisVerdict::Unchanged)
            .unwrap_or_else(|error| panic!("a checked source axis: {error}"))
    };
    let authority = || {
        AxisReport::new(CompatibilityAxis::Authority, false, AxisVerdict::NotChecked)
            .unwrap_or_else(|error| panic!("an unchecked authority axis: {error}"))
    };
    let behaviour = || {
        AxisReport::new(
            CompatibilityAxis::DeclaredBehaviour,
            false,
            AxisVerdict::NotChecked,
        )
        .unwrap_or_else(|error| panic!("an unchecked behaviour axis: {error}"))
    };
    // The builder returns the model's own refusal type, whose variants are large because they
    // carry the whole declaration surface; the lane asserts those variants, so the type is kept.
    #[allow(clippy::result_large_err)]
    let build =
        |source_axis: AxisReport, authority_axis: AxisReport, behaviour_axis: AxisReport| {
            CompatibilityReport::new(
                compared(),
                source_axis,
                schema(),
                authority_axis,
                behaviour_axis,
                durable(),
            )
        };

    // The correctly placed axes are admitted, so each refusal below is caused by its slot.
    let report = build(source(), authority(), behaviour())
        .unwrap_or_else(|error| panic!("correct slots are admitted: {error}"));
    assert_eq!(report.source().axis(), CompatibilityAxis::Source);

    let misplaced_source = build(
        AxisReport::new(CompatibilityAxis::Authority, true, AxisVerdict::Changed)
            .unwrap_or_else(|error| panic!("a checked authority axis: {error}")),
        authority(),
        behaviour(),
    );
    assert!(matches!(
        misplaced_source,
        Err(PackageError::IncompleteCompatibilityReport {
            axis: CompatibilityAxis::Source
        })
    ));
    let misplaced_authority = build(
        source(),
        AxisReport::new(
            CompatibilityAxis::DeclaredBehaviour,
            true,
            AxisVerdict::Changed,
        )
        .unwrap_or_else(|error| panic!("a checked behaviour axis: {error}")),
        behaviour(),
    );
    assert!(matches!(
        misplaced_authority,
        Err(PackageError::IncompleteCompatibilityReport {
            axis: CompatibilityAxis::Authority
        })
    ));
    let misplaced_behaviour = build(
        source(),
        authority(),
        AxisReport::new(CompatibilityAxis::Source, true, AxisVerdict::Changed)
            .unwrap_or_else(|error| panic!("a checked source axis: {error}")),
    );
    assert!(matches!(
        misplaced_behaviour,
        Err(PackageError::IncompleteCompatibilityReport {
            axis: CompatibilityAxis::DeclaredBehaviour
        })
    ));

    // The incompleteness refusal carries no published code and is owned by this clause.
    let refusal = match misplaced_authority {
        Ok(_) => panic!("a misplaced authority axis cannot be admitted"),
        Err(error) => error,
    };
    assert_eq!(refusal.code(), None, "{refusal} has no published code");
    assert_eq!(
        refusal.clause(),
        "GNT-16.8-compatibility-axes",
        "{refusal} is owned by the compatibility-axes clause"
    );
}

/// `SPEC.md` `GNT-16.5-reexports` (11142-11144) with the plan's re-export requirement: an alias
/// re-export reaches the defining item without creating a new identity, and that holds for
/// capability, agent, trait, and operation items exactly as it does for actions — the defining
/// package instance, defining name, item kind, and every identity-bearing fact survive the facade,
/// and the defining name stays unreachable through it.
#[test]
fn reexport_preserves_capability_agent_trait_and_operation_identity() {
    fn case(kind: ItemKind, defining_name: &str, alias: &str) {
        let mut item = InterfaceItem::new(
            defining_name,
            kind,
            Visibility::Exported,
            TargetKind::Library,
        )
        .unwrap_or_else(|_| unreachable!("fixture name is an identifier"));
        // Each recorded kind admits exactly its own content: a trait carries trait facts and an
        // operation carries a signature, while capability and agent items carry neither. Every
        // case also carries a distinguishing fact the facade must not be able to replace.
        match kind {
            ItemKind::Trait => {
                item.trait_facts = Some(TraitFacts {
                    owner: Some(Arc::from("provider")),
                    methods: vec![Arc::from("compare")],
                    coherence_impls: vec![Arc::from("provider::impl")],
                });
            }
            ItemKind::Function | ItemKind::Action | ItemKind::Operation => {
                item.signature = Some(CanonicalSignature::function(
                    &path(&format!("crate::{defining_name}")),
                    &[],
                    &TypeDescriptor::INT,
                ));
                item.requirements = vec![Arc::from("provider::net")];
            }
            ItemKind::Capability => item.requirements = vec![Arc::from("provider::net")],
            ItemKind::Agent => item.agents = vec![Arc::from("review-slot")],
            ItemKind::Nominal => {}
        }
        let defining_item = item.clone();
        let defining_manifest = seal(&[item], &[defining_name], &[], &[])
            .unwrap_or_else(|error| panic!("{kind:?} interface: {error}"));
        let defining = bound_identity("provider", "1.0.0", &[], &defining_manifest);
        let facade_manifest = seal(
            &[],
            &[alias],
            &[ExportEntry {
                exported_name: Arc::from(alias),
                defining_name: Arc::from(defining_name),
                kind,
                target: TargetKind::Library,
                defining: defining.clone(),
            }],
            &[DependencyInterfacePin {
                package: defining.clone(),
                interface: defining_manifest.digest().clone(),
            }],
        )
        .unwrap_or_else(|_| unreachable!("fixture interface is closed"));
        let facade = bound_identity("facade", "1.0.0", &[], &facade_manifest);
        let mut graph = PackageGraph::new();
        graph
            .register_discovered(
                &[
                    instance(defining.clone(), defining_manifest),
                    instance(facade.clone(), facade_manifest.clone()),
                ],
                &[(facade.clone(), defining.clone())],
            )
            .unwrap_or_else(|_| unreachable!("every endpoint is registered"));

        let resolved = graph
            .resolve_name(&facade, alias)
            .unwrap_or_else(|_| unreachable!("the re-export reaches an exported item"));
        assert_eq!(resolved.exported_name(), alias, "{kind:?}");
        assert_eq!(resolved.defining_name(), defining_name, "{kind:?}");
        assert_eq!(resolved.defining_instance(), &defining, "{kind:?}");
        assert_eq!(resolved.kind(), kind, "{kind:?}");
        assert!(resolved.is_reexported(), "{kind:?}");
        assert_eq!(resolved.chain().len(), 1, "{kind:?}");
        assert!(facade_manifest.items().is_empty(), "{kind:?}");
        assert_eq!(facade_manifest.exports().len(), 1, "{kind:?}");

        let item = graph
            .defined_item(&resolved)
            .unwrap_or_else(|_| unreachable!("the defining item is recorded"));
        // The retrieved item is the defining item itself: kind, name, and every identity-bearing
        // fact survive the facade rather than being rebuilt from the facade's claim.
        assert_eq!(item.kind, defining_item.kind, "{kind:?}");
        assert_eq!(item.name, defining_item.name, "{kind:?}");
        assert_eq!(item.requirements, defining_item.requirements, "{kind:?}");
        assert_eq!(item.agents, defining_item.agents, "{kind:?}");
        assert_eq!(item.signature, defining_item.signature, "{kind:?}");
        assert_eq!(item.trait_facts, defining_item.trait_facts, "{kind:?}");
        assert_eq!(item.recovery, defining_item.recovery, "{kind:?}");
        // The facade introduces reachability only: the defining name is not nameable through it.
        assert_eq!(
            graph.resolve_name(&facade, defining_name),
            Err(PackageError::ItemNotExported {
                package: facade.clone(),
                name: Arc::from(defining_name),
            }),
            "{kind:?}"
        );
    }

    case(ItemKind::Capability, "net", "connect");
    case(ItemKind::Agent, "reviewer", "ask");
    case(ItemKind::Trait, "comparable", "ordered");
    case(ItemKind::Operation, "load", "fetch");
}

/// `SPEC.md` `GNT-16.5-reexports`: a facade cannot substitute its own claim for the defining
/// item's kind. Either the model refuses the mismatched re-export before resolution, or resolution
/// still reports the defining item's kind; a facade kind silently winning would fail this lane.
#[test]
fn a_facade_cannot_substitute_another_kind_for_a_reexported_operation() {
    let mut operation = InterfaceItem::new(
        "load",
        ItemKind::Operation,
        Visibility::Exported,
        TargetKind::Library,
    )
    .unwrap_or_else(|_| unreachable!("fixture name is an identifier"));
    operation.signature = Some(CanonicalSignature::function(
        &path("crate::load"),
        &[],
        &TypeDescriptor::INT,
    ));
    let defining_manifest = seal(&[operation], &["load"], &[], &[])
        .unwrap_or_else(|error| panic!("operation interface: {error}"));
    let defining = bound_identity("provider", "1.0.0", &[], &defining_manifest);
    let facade_manifest = seal(
        &[],
        &["fetch"],
        &[ExportEntry {
            exported_name: Arc::from("fetch"),
            defining_name: Arc::from("load"),
            kind: ItemKind::Action,
            target: TargetKind::Library,
            defining: defining.clone(),
        }],
        &[DependencyInterfacePin {
            package: defining.clone(),
            interface: defining_manifest.digest().clone(),
        }],
    );
    let facade_manifest = match facade_manifest {
        Ok(manifest) => manifest,
        // Refusing the mismatched claim at seal time is the strict outcome.
        Err(error) => {
            assert!(
                !error.clause().is_empty(),
                "a refused kind mismatch names a clause: {error}"
            );
            return;
        }
    };
    let facade = bound_identity("facade", "1.0.0", &[], &facade_manifest);
    let mut graph = PackageGraph::new();
    if graph
        .register_discovered(
            &[
                instance(defining.clone(), defining_manifest),
                instance(facade.clone(), facade_manifest),
            ],
            &[(facade.clone(), defining.clone())],
        )
        .is_err()
    {
        return;
    }
    match graph.resolve_name(&facade, "fetch") {
        Ok(resolved) => {
            assert_eq!(
                resolved.kind(),
                ItemKind::Operation,
                "the defining kind wins over the facade's action claim"
            );
            assert_eq!(resolved.defining_name(), "load");
            assert_eq!(resolved.defining_instance(), &defining);
        }
        Err(error) => assert!(
            !error.clause().is_empty(),
            "a refused kind mismatch names a clause: {error}"
        ),
    }
}
