//! Machine-checked conformance for the pure Section 34 standard-library architecture model.
//!
//! The tests use declared packages, classifications, edges, preludes, facades, tiers,
//! applicability, relocations, and manifests only. They neither resolve, download, or
//! load a package, nor generate, link, or publish anything, and no physical repository
//! layout fact enters any identity they check.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use gantry::ir::{
    FacadeReexport, FeatureSelection, NameClass, PackageFamily, Prelude, Relocation,
    STDLIB_CLAUSES, STDLIB_NON_CLAIM_ORDER, STDLIB_NON_CLAIMS, SelectedInstance, SemanticMode,
    StabilityTier, StabilityTransition, StdContractVersion, StdDeprecation, StdGraph, StdItem,
    StdName, StdPackage, StdlibDiagnosticCode, StdlibError, StdlibNonClaim,
    StdlibNonClaimAssertion, TargetKind, check_layout_identity, check_stdlib_non_claims,
    require_applicable,
};

const CORE: &str = "std.core";
const COLLECTIONS: &str = "std.collections";
const TEXT: &str = "std.text";
const OPTION_ITEM: &str = "std.core::option";

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap_or_else(|| panic!("conformance crate has a workspace parent"))
        .to_path_buf()
}

/// Returns the refusal produced by one rejected architecture decision.
fn refuse<T>(outcome: Result<T, StdlibError>, context: &str) -> StdlibError {
    match outcome {
        Ok(_) => panic!("{context}: the decision must be refused"),
        Err(error) => error,
    }
}

fn prelude() -> Prelude {
    Prelude::new("2026", &["std.core::option", "std.core::result"])
        .unwrap_or_else(|error| panic!("the fixture prelude is valid: {error}"))
}

fn package(
    family: PackageFamily,
    tier: StabilityTier,
    dependencies: &[&str],
    exports: &[&str],
) -> StdPackage {
    StdPackage::new(
        family,
        NameClass::Package,
        tier,
        &[SemanticMode::Portable, SemanticMode::Application],
        &[TargetKind::Library, TargetKind::Binary],
        dependencies,
        exports,
    )
    .unwrap_or_else(|error| panic!("the fixture package is valid: {error}"))
}

fn graph_with(packages: &[StdPackage]) -> StdGraph {
    let mut graph = StdGraph::new(prelude());
    for package in packages {
        graph
            .declare(package.clone())
            .unwrap_or_else(|error| panic!("the fixture package declares once: {error}"));
    }
    graph
}

#[test]
fn section_34_anchors_and_closed_vocabularies_are_published() {
    assert_eq!(STDLIB_CLAUSES.len(), 13);
    let specification = fs::read_to_string(workspace_root().join("SPEC.md"))
        .unwrap_or_else(|error| panic!("could not read SPEC.md: {error}"));
    for clause in STDLIB_CLAUSES {
        assert!(
            specification.contains(&format!("<a id=\"{clause}\"></a>")),
            "Section 34 must publish {clause}"
        );
    }
    assert_eq!(PackageFamily::ALL.len(), 20);
    for family in PackageFamily::ALL {
        assert_eq!(
            PackageFamily::from_wire_name(family.wire_name()),
            Some(family)
        );
        assert_eq!(family.package_name(), format!("std.{}", family.wire_name()));
    }
    assert_eq!(
        PackageFamily::ALL
            .into_iter()
            .filter(|family| family.is_pure())
            .count(),
        7,
        "seven declared families are pure"
    );
    assert!(PackageFamily::Core.is_pure());
    assert!(!PackageFamily::Io.is_pure());
    for class in NameClass::ALL {
        assert_eq!(NameClass::from_wire_name(class.wire_name()), Some(class));
    }
    for tier in StabilityTier::ALL {
        assert_eq!(StabilityTier::from_wire_name(tier.wire_name()), Some(tier));
    }
    assert!(StabilityTier::Stable.is_stable());
    assert!(StabilityTier::Foundational.is_stable());
    assert!(!StabilityTier::Experimental.is_stable());
    assert!(!StabilityTier::TargetSpecific.is_stable());
    let spellings = StdlibDiagnosticCode::ALL
        .iter()
        .map(|code| code.as_str())
        .collect::<Vec<&str>>();
    let mut sorted = spellings.clone();
    sorted.sort_unstable();
    assert_eq!(
        spellings, sorted,
        "the frozen diagnostic registry is in canonical spelling order"
    );
    for code in StdlibDiagnosticCode::ALL {
        assert_eq!(
            StdlibDiagnosticCode::from_wire_name(code.as_str()),
            Some(code)
        );
        assert!(STDLIB_CLAUSES.contains(&code.requirement()));
        assert!(
            specification.contains(code.as_str()),
            "Section 34 must publish the frozen spelling {}",
            code.as_str()
        );
    }
    assert_eq!(STDLIB_NON_CLAIMS.len(), StdlibNonClaim::ALL.len());
}

#[test]
fn package_names_are_canonical_and_unique() {
    let core = package(
        PackageFamily::Core,
        StabilityTier::Foundational,
        &[],
        &[OPTION_ITEM],
    );
    assert_eq!(core.name(), CORE);
    assert_eq!(core.family(), PackageFamily::Core);
    assert_eq!(core.class(), NameClass::Package);
    assert_eq!(core.tier(), StabilityTier::Foundational);
    assert!(core.exports_item(OPTION_ITEM));
    assert_eq!(core.dependencies().len(), 0);
    assert_eq!(core.modes().len(), 2);
    assert_eq!(core.targets().len(), 2);
    assert_eq!(
        refuse(
            StdPackage::new(
                PackageFamily::Io,
                NameClass::Module,
                StabilityTier::Stable,
                &[SemanticMode::Application],
                &[TargetKind::Library],
                &[],
                &[],
            ),
            "a non-package class"
        )
        .code(),
        StdlibDiagnosticCode::InvalidNameClassification
    );
    assert_eq!(
        refuse(
            StdPackage::new(
                PackageFamily::Io,
                NameClass::Package,
                StabilityTier::Stable,
                &[],
                &[TargetKind::Library],
                &[],
                &[],
            ),
            "no declared mode"
        )
        .code(),
        StdlibDiagnosticCode::UnsupportedApplicability
    );
    assert_eq!(
        refuse(
            StdPackage::new(
                PackageFamily::Io,
                NameClass::Package,
                StabilityTier::Stable,
                &[SemanticMode::Application],
                &[TargetKind::Library],
                &[CORE],
                &["std.collections::map"],
            ),
            "a foreign exported item"
        )
        .code(),
        StdlibDiagnosticCode::FacadeIdentityLoss
    );
    let mut graph = graph_with(std::slice::from_ref(&core));
    assert_eq!(graph.package_names(), vec![CORE]);
    assert_eq!(
        refuse(graph.declare(core), "a duplicate package name").code(),
        StdlibDiagnosticCode::DuplicatePackage
    );
}

#[test]
fn name_classification_is_closed() {
    for class in [
        NameClass::Facade,
        NameClass::GeneratedDeclaration,
        NameClass::ImplementationIntrinsic,
        NameClass::Module,
    ] {
        let name = StdName::new("std.io::console", class, "std.io")
            .unwrap_or_else(|error| panic!("the fixture name is valid: {error}"));
        assert_eq!(name.class(), class);
        assert_eq!(name.path(), "std.io::console");
        assert_eq!(name.owner(), "std.io");
    }
    assert_eq!(
        refuse(
            StdName::new("std.io::console", NameClass::Package, "std.io"),
            "a package classification inside a package"
        )
        .code(),
        StdlibDiagnosticCode::InvalidNameClassification
    );
    assert_eq!(
        refuse(
            StdName::new("std.io::console", NameClass::Module, "   "),
            "an empty owner"
        )
        .code(),
        StdlibDiagnosticCode::InvalidNameClassification
    );
    for path in ["crates::console", "std.", "std::console", "std.IO"] {
        assert_eq!(
            refuse(
                StdName::new(path, NameClass::Module, "std.io"),
                "a malformed logical name"
            )
            .code(),
            StdlibDiagnosticCode::InvalidPackageName
        );
    }
    let mut graph = graph_with(&[package(PackageFamily::Io, StabilityTier::Stable, &[], &[])]);
    let console = StdName::new("std.io::console", NameClass::Module, "std.io")
        .unwrap_or_else(|error| panic!("the fixture name is valid: {error}"));
    assert!(graph.declare_name(console.clone()).is_ok());
    assert_eq!(graph.names().len(), 1);
    assert_eq!(
        refuse(graph.declare_name(console), "a duplicate declared name").code(),
        StdlibDiagnosticCode::DuplicatePackage
    );
    let orphan = StdName::new("std.net::socket", NameClass::Module, "std.net")
        .unwrap_or_else(|error| panic!("the fixture name is valid: {error}"));
    assert_eq!(
        refuse(graph.declare_name(orphan), "an undeclared owning package").code(),
        StdlibDiagnosticCode::UnknownEdge
    );
}

#[test]
fn dependency_dag_refuses_unknown_adapter_and_cyclic_edges() {
    let graph = graph_with(&[
        package(PackageFamily::Core, StabilityTier::Foundational, &[], &[]),
        package(
            PackageFamily::Collections,
            StabilityTier::Stable,
            &[CORE],
            &[],
        ),
        package(PackageFamily::Text, StabilityTier::Stable, &[CORE], &[]),
    ]);
    assert!(graph.validate().is_ok());
    let order = graph
        .topological_order()
        .unwrap_or_else(|error| panic!("the fixture graph is acyclic: {error}"));
    assert_eq!(order, vec![CORE, COLLECTIONS, TEXT]);
    assert_eq!(order[0], CORE, "a dependency precedes its dependent");
    let permuted = graph_with(&[
        package(PackageFamily::Text, StabilityTier::Stable, &[CORE], &[]),
        package(
            PackageFamily::Collections,
            StabilityTier::Stable,
            &[CORE],
            &[],
        ),
        package(PackageFamily::Core, StabilityTier::Foundational, &[], &[]),
    ]);
    assert_eq!(
        permuted
            .topological_order()
            .unwrap_or_else(|error| panic!("the permuted graph is acyclic: {error}")),
        order,
        "declaration order must not change the topological order"
    );
    assert_eq!(
        refuse(
            graph_with(&[package(
                PackageFamily::Text,
                StabilityTier::Stable,
                &["std.absent"],
                &[],
            )])
            .validate(),
            "an undeclared edge"
        )
        .code(),
        StdlibDiagnosticCode::UnknownEdge
    );
    assert_eq!(
        refuse(
            graph_with(&[package(
                PackageFamily::Io,
                StabilityTier::Stable,
                &["adapter.tokio"],
                &[],
            )])
            .validate(),
            "a host adapter edge"
        )
        .code(),
        StdlibDiagnosticCode::PackageToAdapterEdge
    );
    let pure_to_capability = graph_with(&[
        package(PackageFamily::Io, StabilityTier::Stable, &[], &[]),
        package(
            PackageFamily::Collections,
            StabilityTier::Stable,
            &["std.io"],
            &[],
        ),
    ]);
    assert_eq!(
        refuse(pure_to_capability.validate(), "a pure-to-capability edge").code(),
        StdlibDiagnosticCode::PureToCapabilityEdge
    );
    let cycle = graph_with(&[
        package(
            PackageFamily::Text,
            StabilityTier::Stable,
            &["std.collections"],
            &[],
        ),
        package(
            PackageFamily::Collections,
            StabilityTier::Stable,
            &["std.text"],
            &[],
        ),
    ]);
    let refusal = refuse(cycle.validate(), "a dependency cycle");
    assert_eq!(refusal.code(), StdlibDiagnosticCode::DependencyCycle);
    assert!(
        refusal.detail().contains(COLLECTIONS) || refusal.detail().contains(TEXT),
        "the cycle refusal names a declared member: {}",
        refusal.detail()
    );
}

#[test]
fn prelude_is_enumerated_and_wildcards_are_refused() {
    let prelude = prelude();
    assert_eq!(prelude.members().len(), 2);
    assert!(prelude.admit(OPTION_ITEM).is_ok());
    assert_eq!(
        refuse(
            prelude.admit("std.core::map"),
            "an unenumerated prelude member"
        )
        .code(),
        StdlibDiagnosticCode::UnenumeratedPreludeMember
    );
    for member in ["std.core::*", "std.*", "std.collections::*"] {
        assert_eq!(
            refuse(Prelude::new("2026", &[member]), "a wildcard prelude member").code(),
            StdlibDiagnosticCode::WildcardPreludeRefused
        );
    }
    assert_eq!(
        refuse(
            Prelude::new("2026", &["crates::core"]),
            "a malformed prelude member"
        )
        .code(),
        StdlibDiagnosticCode::InvalidPackageName
    );
}

#[test]
fn facade_reexports_preserve_defining_identity() {
    let graph = graph_with(&[package(
        PackageFamily::Core,
        StabilityTier::Foundational,
        &[],
        &[OPTION_ITEM],
    )]);
    let reexport = FacadeReexport::new("std.io::option", CORE, OPTION_ITEM)
        .unwrap_or_else(|error| panic!("the fixture re-export is valid: {error}"));
    assert_eq!(reexport.path(), "std.io::option");
    assert_eq!(reexport.defining_package(), CORE);
    assert_eq!(reexport.item(), OPTION_ITEM);
    assert_eq!(
        reexport.defining_identity(),
        format!("{CORE}#{OPTION_ITEM}")
    );
    assert!(
        reexport
            .admit(&graph, reexport.defining_identity().as_str())
            .is_ok(),
        "a facade preserving the defining identity is admitted"
    );
    assert_eq!(
        refuse(
            reexport.admit(&graph, "std.io#std.core::option"),
            "a substituted identity"
        )
        .code(),
        StdlibDiagnosticCode::FacadeIdentityLoss
    );
    let unexported = FacadeReexport::new("std.io::absent", CORE, "std.core::absent")
        .unwrap_or_else(|error| panic!("the fixture re-export is valid: {error}"));
    assert_eq!(
        refuse(
            unexported.admit(&graph, "std.core#std.core::absent"),
            "an item the defining package does not export"
        )
        .code(),
        StdlibDiagnosticCode::FacadeIdentityLoss
    );
    let unknown = FacadeReexport::new("std.io::socket", "std.net", "std.net::socket")
        .unwrap_or_else(|error| panic!("the fixture re-export is valid: {error}"));
    assert_eq!(
        refuse(
            unknown.admit(&graph, "std.net#std.net::socket"),
            "an undeclared defining package"
        )
        .code(),
        StdlibDiagnosticCode::UnknownEdge
    );
}

#[test]
fn stability_transitions_are_closed() {
    for (from, to) in [
        (StabilityTier::Experimental, StabilityTier::TargetSpecific),
        (StabilityTier::Experimental, StabilityTier::Stable),
        (StabilityTier::TargetSpecific, StabilityTier::Stable),
    ] {
        let transition = StabilityTransition::new(from, to)
            .unwrap_or_else(|error| panic!("a permitted transition is admitted: {error}"));
        assert_eq!(transition.from(), from);
        assert_eq!(transition.to(), to);
    }
    for (from, to) in [
        (StabilityTier::Experimental, StabilityTier::Experimental),
        (StabilityTier::Stable, StabilityTier::Experimental),
        (StabilityTier::Stable, StabilityTier::TargetSpecific),
        (StabilityTier::Foundational, StabilityTier::Stable),
        (StabilityTier::Stable, StabilityTier::Foundational),
    ] {
        assert_eq!(
            refuse(
                StabilityTransition::new(from, to),
                "a no-op, backwards, or foundational transition"
            )
            .code(),
            StdlibDiagnosticCode::InvalidStabilityTransition
        );
    }
}

#[test]
fn applicability_is_declared_and_features_do_not_mutate_instances() {
    let io = StdPackage::new(
        PackageFamily::Io,
        NameClass::Package,
        StabilityTier::Stable,
        &[SemanticMode::Application],
        &[TargetKind::Library],
        &[],
        &[],
    )
    .unwrap_or_else(|error| panic!("the fixture package is valid: {error}"));
    assert!(require_applicable(&io, SemanticMode::Application, TargetKind::Library).is_ok());
    assert_eq!(
        refuse(
            require_applicable(&io, SemanticMode::Portable, TargetKind::Library),
            "an undeclared mode"
        )
        .code(),
        StdlibDiagnosticCode::UnsupportedApplicability
    );
    assert_eq!(
        refuse(
            require_applicable(&io, SemanticMode::Application, TargetKind::Test),
            "an undeclared target"
        )
        .code(),
        StdlibDiagnosticCode::UnsupportedApplicability
    );
    let feature = FeatureSelection::new("net", &["std.net"])
        .unwrap_or_else(|error| panic!("the fixture feature is valid: {error}"));
    assert_eq!(feature.feature(), "net");
    assert_eq!(feature.packages().len(), 1);
    let graph = graph_with(&[
        package(PackageFamily::Core, StabilityTier::Foundational, &[], &[]),
        package(PackageFamily::Io, StabilityTier::Stable, &[], &[]),
        package(PackageFamily::Net, StabilityTier::Stable, &[], &[]),
    ]);
    let net = graph
        .package("std.net")
        .unwrap_or_else(|| panic!("the fixture graph declares std.net"))
        .clone();
    let mut selected = BTreeMap::new();
    selected.insert("std.net".to_owned(), SelectedInstance::from_package(&net));
    let applied = feature
        .apply(&graph, &selected)
        .unwrap_or_else(|error| panic!("applying a feature to a selection is admitted: {error}"));
    assert_eq!(applied.len(), 1);
    assert_eq!(
        applied.get("std.net").map(SelectedInstance::interface),
        Some(&net.identity())
    );
    assert_eq!(
        refuse(
            feature.apply(
                &graph,
                &BTreeMap::from([(
                    "std.net".to_owned(),
                    SelectedInstance::new("std.net", io.identity(), &["std.core"])
                        .unwrap_or_else(|error| panic!("the fixture instance is valid: {error}")),
                )])
            ),
            "a feature that changes a selected instance"
        )
        .code(),
        StdlibDiagnosticCode::FeatureMutatesInstance
    );
    assert_eq!(
        refuse(
            FeatureSelection::new("absent", &["std.absent"])
                .unwrap_or_else(|error| panic!("the fixture feature is valid: {error}"))
                .apply(&graph, &BTreeMap::new()),
            "a feature over an undeclared package"
        )
        .code(),
        StdlibDiagnosticCode::UnknownEdge
    );
    assert_eq!(
        refuse(FeatureSelection::new("   ", &[]), "an empty feature name").code(),
        StdlibDiagnosticCode::InvalidPackageName
    );
}

#[test]
fn interface_identity_covers_every_declared_fact() {
    let base = package(
        PackageFamily::Core,
        StabilityTier::Foundational,
        &[],
        &[OPTION_ITEM],
    );
    assert_eq!(
        base.identity(),
        package(
            PackageFamily::Core,
            StabilityTier::Foundational,
            &[],
            &[OPTION_ITEM],
        )
        .identity()
    );
    assert_ne!(
        base.identity().as_str(),
        package(
            PackageFamily::Core,
            StabilityTier::Stable,
            &[],
            &[OPTION_ITEM]
        )
        .identity()
        .as_str(),
        "the stability tier participates in the interface identity"
    );
    assert_ne!(
        base.identity().as_str(),
        package(
            PackageFamily::Core,
            StabilityTier::Foundational,
            &[COLLECTIONS],
            &[OPTION_ITEM],
        )
        .identity()
        .as_str(),
        "a dependency edge participates in the interface identity"
    );
    assert_ne!(
        base.identity().as_str(),
        package(PackageFamily::Core, StabilityTier::Foundational, &[], &[])
            .identity()
            .as_str(),
        "an exported item participates in the interface identity"
    );
    let narrow = StdPackage::new(
        PackageFamily::Core,
        NameClass::Package,
        StabilityTier::Foundational,
        &[SemanticMode::Portable],
        &[TargetKind::Library],
        &[],
        &[OPTION_ITEM],
    )
    .unwrap_or_else(|error| panic!("the fixture package is valid: {error}"));
    assert_ne!(
        base.identity().as_str(),
        narrow.identity().as_str(),
        "applicability participates in the interface identity"
    );
}

#[test]
fn layout_facts_are_never_identity() {
    assert!(
        check_layout_identity(&[CORE, OPTION_ITEM, "interface:option"]).is_ok(),
        "declared logical facts are admitted"
    );
    for fact in [
        "crates/gantry-ir/src/lib.rs",
        "src/main.rs",
        "lib.rs",
        "Cargo.toml",
    ] {
        assert_eq!(
            refuse(check_layout_identity(&[fact]), "a physical layout fact").code(),
            StdlibDiagnosticCode::LayoutDerivedIdentity
        );
    }
}

#[test]
fn contract_versions_gate_consumers() {
    let published = StdContractVersion::new(1, 2)
        .unwrap_or_else(|error| panic!("the fixture contract version is valid: {error}"));
    assert_eq!(published.major(), 1);
    assert_eq!(published.minor(), 2);
    let presented = StdContractVersion::new(1, 2)
        .unwrap_or_else(|error| panic!("the presented version is valid: {error}"));
    assert!(published.admit_consumer(presented).is_ok());
    for (major, minor) in [(1, 1), (1, 0), (1, 3), (2, 0)] {
        let presented = StdContractVersion::new(major, minor)
            .unwrap_or_else(|error| panic!("the presented version is valid: {error}"));
        assert_eq!(
            refuse(
                published.admit_consumer(presented),
                "a contract version the publication does not admit"
            )
            .code(),
            StdlibDiagnosticCode::ContractVersionMismatch
        );
    }
    assert_eq!(
        refuse(StdContractVersion::new(0, 1), "a zero major version").code(),
        StdlibDiagnosticCode::ContractVersionMismatch
    );
}

#[test]
fn relocations_preserve_identity_or_fail() {
    let relocation = Relocation::new("std.text::format", "std.text::render", "std.text#format")
        .unwrap_or_else(|error| panic!("the fixture relocation is valid: {error}"));
    assert_eq!(relocation.from(), "std.text::format");
    assert_eq!(relocation.to(), "std.text::render");
    assert_eq!(relocation.preserved_identity(), "std.text#format");
    assert!(relocation.admit("std.text#format").is_ok());
    assert_eq!(
        refuse(
            relocation.admit("std.text#render"),
            "a relocation that changes identity"
        )
        .code(),
        StdlibDiagnosticCode::InvalidRelocation
    );
    for (from, to, preserved) in [
        ("std.text::format", "std.text::format", "std.text#format"),
        ("std.text::format", "std.text::render", "   "),
    ] {
        assert_eq!(
            refuse(
                Relocation::new(from, to, preserved),
                "a no-op or undeclared relocation"
            )
            .code(),
            StdlibDiagnosticCode::InvalidRelocation
        );
    }
}

#[test]
fn aggregate_manifest_detects_publication_drift() {
    let contract = StdContractVersion::new(1, 0)
        .unwrap_or_else(|error| panic!("the fixture contract version is valid: {error}"));
    let graph = graph_with(&[
        package(
            PackageFamily::Core,
            StabilityTier::Foundational,
            &[],
            &[OPTION_ITEM],
        ),
        package(
            PackageFamily::Collections,
            StabilityTier::Stable,
            &[CORE],
            &[],
        ),
    ]);
    let manifest = graph
        .manifest(contract)
        .unwrap_or_else(|error| panic!("the fixture manifest is valid: {error}"));
    assert_eq!(manifest.entries().len(), 2);
    assert_eq!(manifest.contract(), contract);
    assert_eq!(manifest.entries()[0].name(), COLLECTIONS);
    assert_eq!(manifest.entries()[0].class(), NameClass::Package);
    assert_eq!(manifest.entries()[0].tier(), StabilityTier::Stable);
    assert!(manifest.verify_against(&graph).is_ok());
    let smaller = graph_with(&[package(
        PackageFamily::Core,
        StabilityTier::Foundational,
        &[],
        &[OPTION_ITEM],
    )]);
    let stale = smaller
        .manifest(contract)
        .unwrap_or_else(|error| panic!("the smaller manifest is valid: {error}"));
    assert_eq!(
        refuse(
            stale.verify_against(&graph),
            "a manifest that omits a declared package"
        )
        .code(),
        StdlibDiagnosticCode::PublicationDrift
    );
    assert_eq!(
        refuse(
            manifest.verify_against(&smaller),
            "a manifest verified against another hierarchy"
        )
        .code(),
        StdlibDiagnosticCode::PublicationDrift
    );
}

#[test]
fn graph_identity_binds_every_package_and_the_prelude() {
    let contract = StdContractVersion::new(1, 0)
        .unwrap_or_else(|error| panic!("the fixture contract version is valid: {error}"));
    let core = || {
        package(
            PackageFamily::Core,
            StabilityTier::Foundational,
            &[],
            &[OPTION_ITEM],
        )
    };
    let first = graph_with(&[core()])
        .manifest(contract)
        .unwrap_or_else(|error| panic!("the fixture manifest is valid: {error}"));
    let second = graph_with(&[core()])
        .manifest(contract)
        .unwrap_or_else(|error| panic!("the fixture manifest is valid: {error}"));
    assert_eq!(first.identity(), second.identity());
    let mut narrow_prelude = StdGraph::new(
        Prelude::new("2026", &[OPTION_ITEM])
            .unwrap_or_else(|error| panic!("the fixture prelude is valid: {error}")),
    );
    narrow_prelude
        .declare(core())
        .unwrap_or_else(|error| panic!("the fixture package declares once: {error}"));
    let narrow = narrow_prelude
        .manifest(contract)
        .unwrap_or_else(|error| panic!("the narrow manifest is valid: {error}"));
    assert_ne!(
        first.identity().as_str(),
        narrow.identity().as_str(),
        "the enumerated prelude participates in the aggregate identity"
    );
}

#[test]
fn non_claims_are_not_presented_as_guarantees() {
    assert_eq!(STDLIB_NON_CLAIM_ORDER, StdlibNonClaim::ALL);
    assert_eq!(STDLIB_NON_CLAIMS.len(), 12);
    assert_eq!(StdlibNonClaim::ALL.len(), 12);
    for claim in StdlibNonClaim::ALL {
        assert_eq!(
            StdlibNonClaim::from_wire_name(claim.wire_name()),
            Some(claim)
        );
        assert!(check_stdlib_non_claims(&[StdlibNonClaimAssertion::new(claim, false)]).is_ok());
        assert_eq!(
            refuse(
                check_stdlib_non_claims(&[StdlibNonClaimAssertion::new(claim, true)]),
                "a non-claim presented as a guarantee"
            )
            .code(),
            StdlibDiagnosticCode::NonClaimAsGuarantee
        );
    }
    assert!(STDLIB_NON_CLAIMS.iter().all(|claim| !claim.is_empty()));
    assert!(
        STDLIB_NON_CLAIMS
            .iter()
            .any(|claim| claim.contains("layout")),
        "layout-as-identity is a declared non-claim"
    );
}

#[test]
fn item_tiers_are_unique_and_fold_into_the_interface_digest() {
    let mut graph = graph_with(&[package(PackageFamily::Io, StabilityTier::Stable, &[], &[])]);
    let read = StdItem::new(
        "std.io::read",
        NameClass::Module,
        StabilityTier::Stable,
        &[SemanticMode::Application],
        &[TargetKind::Library],
    )
    .unwrap_or_else(|error| panic!("the fixture item is valid: {error}"));
    graph
        .declare_item(read)
        .unwrap_or_else(|error| panic!("the fixture item is declared: {error}"));
    // an item declared inside an undeclared package is refused
    assert_eq!(
        refuse(
            graph.declare_item(
                StdItem::new(
                    "std.net::socket",
                    NameClass::Module,
                    StabilityTier::Stable,
                    &[SemanticMode::Application],
                    &[TargetKind::Library],
                )
                .unwrap_or_else(|error| panic!("the fixture item is valid: {error}"))
            ),
            "an item inside an undeclared package"
        )
        .code(),
        StdlibDiagnosticCode::UnknownEdge
    );
    // a second tier for one item is refused
    let mut conflicting = graph.clone();
    assert_eq!(
        refuse(
            conflicting.declare_item(
                StdItem::new(
                    "std.io::read",
                    NameClass::Module,
                    StabilityTier::Experimental,
                    &[SemanticMode::Application],
                    &[TargetKind::Library],
                )
                .unwrap_or_else(|error| panic!("the fixture item is valid: {error}"))
            ),
            "a second tier for one item"
        )
        .code(),
        StdlibDiagnosticCode::InvalidStabilityTransition
    );

    // the package classification and an empty applicability are refused for an item
    assert_eq!(
        refuse(
            StdItem::new(
                "std.io::read",
                NameClass::Package,
                StabilityTier::Stable,
                &[SemanticMode::Application],
                &[TargetKind::Library]
            ),
            "a package classification inside a package"
        )
        .code(),
        StdlibDiagnosticCode::InvalidNameClassification
    );
    assert_eq!(
        refuse(
            StdItem::new(
                "std.io::read",
                NameClass::Module,
                StabilityTier::Stable,
                &[],
                &[]
            ),
            "an item without applicability"
        )
        .code(),
        StdlibDiagnosticCode::UnsupportedApplicability
    );

    // the declared item is readable and a foreign item is refused
    let package = graph
        .package("std.io")
        .unwrap_or_else(|| panic!("the fixture graph declares std.io"))
        .clone();
    let item = package
        .item("std.io::read")
        .unwrap_or_else(|| panic!("the declared item is recorded"));
    assert_eq!(item.owner(), "std.io");
    assert_eq!(item.class(), NameClass::Module);
    assert_eq!(item.tier(), StabilityTier::Stable);
    assert!(package.exports_item("std.io::read"));
    assert_eq!(
        refuse(
            package.clone().declare_item(
                StdItem::new(
                    "std.text::format",
                    NameClass::Module,
                    StabilityTier::Stable,
                    &[SemanticMode::Application],
                    &[TargetKind::Library],
                )
                .unwrap_or_else(|error| panic!("the fixture item is valid: {error}"))
            ),
            "an item owned by another package"
        )
        .code(),
        StdlibDiagnosticCode::FacadeIdentityLoss
    );

    // the interface digest covers every declared item fact
    let retiered = graph.clone();
    let mut retiered_package = retiered
        .package("std.io")
        .unwrap_or_else(|| panic!("the fixture graph declares std.io"))
        .clone();
    retiered_package
        .declare_item(
            StdItem::new(
                "std.io::echo",
                NameClass::Facade,
                StabilityTier::TargetSpecific,
                &[SemanticMode::Application],
                &[TargetKind::Library],
            )
            .unwrap_or_else(|error| panic!("the fixture item is valid: {error}")),
        )
        .unwrap_or_else(|error| panic!("the fixture item is declared: {error}"));
    assert_ne!(
        graph
            .package("std.io")
            .unwrap_or_else(|| panic!("declared"))
            .identity(),
        retiered_package.identity()
    );
}

#[test]
fn deprecations_narrow_a_tier_and_keep_the_item_declared() {
    let package = StdPackage::new(
        PackageFamily::Text,
        NameClass::Package,
        StabilityTier::Stable,
        &[SemanticMode::Portable],
        &[TargetKind::Library],
        &[],
        &["std.text::format", "std.text::render"],
    )
    .unwrap_or_else(|error| panic!("the fixture package is valid: {error}"));
    let deprecation = StdDeprecation::new(
        "std.text::format",
        StabilityTier::Stable,
        StabilityTier::Experimental,
        Some("std.text::render"),
    )
    .unwrap_or_else(|error| panic!("the fixture deprecation is valid: {error}"));
    assert_eq!(deprecation.item(), "std.text::format");
    assert_eq!(deprecation.tier(), StabilityTier::Stable);
    assert_eq!(deprecation.target_tier(), StabilityTier::Experimental);
    assert_eq!(deprecation.replacement(), Some("std.text::render"));
    deprecation
        .admit(&package)
        .unwrap_or_else(|error| panic!("the declared deprecation is admitted: {error}"));

    // a widening or unchanged target tier is refused
    for (tier, target) in [
        (StabilityTier::Stable, StabilityTier::Stable),
        (StabilityTier::Stable, StabilityTier::Foundational),
        (StabilityTier::Experimental, StabilityTier::Stable),
    ] {
        assert_eq!(
            refuse(
                StdDeprecation::new("std.text::format", tier, target, None),
                "a deprecation that does not narrow stability"
            )
            .code(),
            StdlibDiagnosticCode::InvalidRelocation,
            "{} to {}",
            tier.wire_name(),
            target.wire_name()
        );
    }

    // an item the declaring package does not carry, and an undeclared replacement, are refused
    let removed = StdDeprecation::new(
        "std.text::absent",
        StabilityTier::Stable,
        StabilityTier::Experimental,
        None,
    )
    .unwrap_or_else(|error| panic!("the fixture deprecation is valid: {error}"));
    assert_eq!(
        refuse(removed.admit(&package), "a silently removed item").code(),
        StdlibDiagnosticCode::InvalidRelocation
    );
    let absent_replacement = StdDeprecation::new(
        "std.text::format",
        StabilityTier::Stable,
        StabilityTier::Experimental,
        Some("std.text::absent"),
    )
    .unwrap_or_else(|error| panic!("the fixture deprecation is valid: {error}"));
    assert_eq!(
        refuse(
            absent_replacement.admit(&package),
            "an undeclared replacement"
        )
        .code(),
        StdlibDiagnosticCode::InvalidRelocation
    );
}

#[test]
fn references_outside_the_std_hierarchy_are_host_adapters() {
    for adapter in ["adapter.http", "adapters.tokio", "host.tokio", "adapter"] {
        let graph = graph_with(&[package(
            PackageFamily::Fs,
            StabilityTier::Stable,
            &[adapter],
            &[],
        )]);
        assert_eq!(
            refuse(graph.validate(), "a standard package over a host adapter").code(),
            StdlibDiagnosticCode::PackageToAdapterEdge,
            "{adapter}"
        );
    }
    let undeclared = graph_with(&[package(
        PackageFamily::Fs,
        StabilityTier::Stable,
        &["std.absent"],
        &[],
    )]);
    assert_eq!(
        refuse(undeclared.validate(), "an undeclared std package").code(),
        StdlibDiagnosticCode::UnknownEdge
    );
}

#[test]
fn names_are_rooted_under_their_owning_package() {
    let mut graph = graph_with(&[
        package(PackageFamily::Io, StabilityTier::Stable, &[], &[]),
        package(PackageFamily::Net, StabilityTier::Stable, &[], &[]),
    ]);
    let socket = StdName::new("std.net::socket", NameClass::Module, "std.io");
    assert_eq!(
        refuse(socket, "a name contradicting its owning package").code(),
        StdlibDiagnosticCode::InvalidNameClassification
    );
    let owned = StdName::new("std.net::socket", NameClass::Module, "std.net")
        .unwrap_or_else(|error| panic!("the fixture name is valid: {error}"));
    graph
        .declare_name(owned)
        .unwrap_or_else(|error| panic!("the declared name is admitted: {error}"));
    assert_eq!(graph.names().len(), 1);
}

#[test]
fn consumers_must_present_the_published_identity_and_digests() {
    let graph = graph_with(&[
        package(PackageFamily::Core, StabilityTier::Foundational, &[], &[]),
        package(PackageFamily::Text, StabilityTier::Stable, &[], &[]),
    ]);
    let contract = StdContractVersion::new(1, 2)
        .unwrap_or_else(|error| panic!("the fixture contract version is valid: {error}"));
    let manifest = graph
        .manifest(contract)
        .unwrap_or_else(|error| panic!("the fixture manifest is valid: {error}"));
    let interfaces: BTreeMap<String, String> = manifest
        .entries()
        .iter()
        .map(|entry| {
            (
                entry.name().to_owned(),
                entry.identity().as_str().to_owned(),
            )
        })
        .collect();
    manifest
        .admit_consumer(contract, manifest.identity().as_str(), &interfaces)
        .unwrap_or_else(|error| panic!("the published consumer is admitted: {error}"));
    assert!(
        manifest
            .entries()
            .iter()
            .all(|entry| { !entry.modes().is_empty() && !entry.targets().is_empty() })
    );

    let other = StdContractVersion::new(1, 3)
        .unwrap_or_else(|error| panic!("the fixture contract version is valid: {error}"));
    assert_eq!(
        refuse(
            manifest.admit_consumer(other, manifest.identity().as_str(), &interfaces),
            "a differing contract version"
        )
        .code(),
        StdlibDiagnosticCode::ContractVersionMismatch
    );
    assert_eq!(
        refuse(
            manifest.admit_consumer(contract, "std-graph-v1:other", &interfaces),
            "a differing graph identity"
        )
        .code(),
        StdlibDiagnosticCode::ContractVersionMismatch
    );
    let mut altered = interfaces.clone();
    let first = manifest
        .entries()
        .first()
        .unwrap_or_else(|| panic!("the fixture manifest has entries"))
        .name()
        .to_owned();
    altered.insert(first.clone(), "std-package-v1:other".to_owned());
    assert_eq!(
        refuse(
            manifest.admit_consumer(contract, manifest.identity().as_str(), &altered),
            "a differing interface digest"
        )
        .code(),
        StdlibDiagnosticCode::ContractVersionMismatch
    );
    let mut incomplete = interfaces.clone();
    incomplete.remove(&first);
    assert_eq!(
        refuse(
            manifest.admit_consumer(contract, manifest.identity().as_str(), &incomplete),
            "a consumer without every interface digest"
        )
        .code(),
        StdlibDiagnosticCode::ContractVersionMismatch
    );
}

#[test]
fn preludes_are_edition_versioned_and_never_silently_extended() {
    let declared = prelude();
    assert_eq!(declared.edition(), "2026");
    let same = declared
        .for_edition("2026", &["std.core::option", "std.core::result"])
        .unwrap_or_else(|error| panic!("a redeclared edition is admitted: {error}"));
    assert_eq!(same.members(), declared.members());
    assert_eq!(
        refuse(
            declared.for_edition("2026", &["std.core::option"]),
            "a silent extension of a declared edition"
        )
        .code(),
        StdlibDiagnosticCode::UnenumeratedPreludeMember
    );
    let next = declared
        .for_edition("2029", &["std.core::option"])
        .unwrap_or_else(|error| panic!("a new edition is admitted: {error}"));
    assert_eq!(next.edition(), "2029");
    assert_eq!(next.members().len(), 1);
    assert_eq!(
        refuse(Prelude::new("", &[]), "an undeclared edition").code(),
        StdlibDiagnosticCode::UnenumeratedPreludeMember
    );
}
