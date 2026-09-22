//! Machine-checked conformance for the pure Section 34 standard-library architecture model.
//!
//! The tests use declared packages, classifications, edges, preludes, facades, tiers,
//! applicability, relocations, and manifests only. They neither resolve, download, or
//! load a package, nor generate, link, or publish anything, and no physical repository
//! layout fact enters any identity they check.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

use gantry::ir::{
    CANONICAL_PRELUDE_EDITION, CANONICAL_PRELUDE_MEMBERS, FacadeReexport, FeatureSelection,
    NameClass, PRELUDE_BINDINGS, PackageFamily, Prelude, Relocation, STDLIB_CLAUSES,
    STDLIB_NON_CLAIM_ORDER, STDLIB_NON_CLAIMS, SelectedInstance, SemanticMode, StabilityTier,
    StabilityTransition, StdContractVersion, StdDeprecation, StdGraph, StdItem, StdName,
    StdPackage, StdlibDiagnosticCode, StdlibError, StdlibNonClaim, StdlibNonClaimAssertion,
    TargetKind, canonical_codec_hierarchy, canonical_collections_hierarchy,
    canonical_crypto_hierarchy, canonical_data_hierarchy, canonical_pure_hierarchy,
    canonical_std_hierarchy, check_layout_identity, check_stdlib_non_claims, require_applicable,
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

/// Every enumerated prelude member owns a declared, closed set of automatic source spellings
/// (`GNT-34.4`): the declared canonical member set is valid under that closure in both
/// directions, the canonical prelude is the declared one, each binding names a declared item of
/// `std.core`, the published inventory partitions into exactly six prelude-owned and eleven
/// compiler-owned spellings, a member outside the correspondence enumerates no source name and
/// is refused, and dropping a member drops exactly that member's spellings.
#[test]
fn prelude_members_own_their_declared_automatic_spellings() {
    // The declared canonical member set is valid under the same closure the model enforces: a
    // coordinated edit that adds a member without a binding fails here instead of silently
    // enumerating a member that injects no source name.
    let declared_members = Prelude::new("2026", &CANONICAL_PRELUDE_MEMBERS)
        .unwrap_or_else(|error| panic!("the canonical members are declared: {error}"));

    let declared = prelude();
    assert_eq!(
        declared_members, declared,
        "the canonical prelude enumerates exactly the declared canonical members"
    );
    assert_eq!(
        declared,
        Prelude::canonical(),
        "the canonical prelude is the declared prelude"
    );
    let bound = PRELUDE_BINDINGS
        .iter()
        .map(|binding| binding.member())
        .collect::<BTreeSet<&str>>();
    assert_eq!(
        declared
            .members()
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<&str>>(),
        bound,
        "every enumerated member is bound and every bound member is enumerated"
    );
    assert_eq!(
        declared
            .automatic_spellings()
            .into_iter()
            .collect::<Vec<&str>>(),
        ["Err", "None", "Ok", "Option", "Result", "Some"]
    );

    // The note publishes the split as six prelude-owned and eleven compiler-owned spellings.
    let prelude_owned = PRELUDE_BINDINGS
        .iter()
        .flat_map(|binding| binding.spellings().iter().copied())
        .collect::<BTreeSet<&str>>();
    let compiler_owned = COMPILER_OWNED_TYPE_WORDS
        .iter()
        .copied()
        .filter(|word| !prelude_owned.contains(word))
        .collect::<BTreeSet<&str>>();
    assert_eq!(prelude_owned.len(), 6, "six prelude-owned spellings");
    assert_eq!(compiler_owned.len(), 11, "eleven compiler-owned spellings");
    assert_eq!(
        prelude_owned.len() + compiler_owned.len(),
        COMPILER_OWNED_TYPE_WORDS.len(),
        "the published inventory partitions into the prelude-owned and compiler-owned sets"
    );

    let graph = canonical_pure_hierarchy()
        .unwrap_or_else(|error| panic!("the canonical hierarchy is valid: {error}"));
    let core = graph
        .package(CORE)
        .unwrap_or_else(|| panic!("the canonical hierarchy declares `{CORE}`"));
    for binding in PRELUDE_BINDINGS {
        assert!(
            declared.members().contains(binding.member()),
            "`{}` is an enumerated member",
            binding.member()
        );
        assert!(
            core.item(binding.member()).is_some(),
            "`{}` is a declared item of `{CORE}`",
            binding.member()
        );
        assert!(
            !binding.spellings().is_empty(),
            "`{}` owns at least one automatic spelling",
            binding.member()
        );
    }

    assert_eq!(
        refuse(
            Prelude::new("2026", &["std.core::text"]),
            "a member that enumerates no automatic source name"
        )
        .code(),
        StdlibDiagnosticCode::UnenumeratedPreludeMember
    );

    let result_only = Prelude::new("2026", &["std.core::result"])
        .unwrap_or_else(|error| panic!("the reduced prelude is valid: {error}"));
    assert_eq!(
        result_only
            .automatic_spellings()
            .into_iter()
            .collect::<Vec<&str>>(),
        ["Err", "Ok", "Result"]
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
    let mut graph = graph_with(&[package(
        PackageFamily::Text,
        StabilityTier::Stable,
        &[],
        &[],
    )]);
    for item in ["std.text::format", "std.text::render"] {
        graph
            .declare_item(
                StdItem::new(
                    item,
                    NameClass::Module,
                    StabilityTier::Stable,
                    &[SemanticMode::Portable],
                    &[TargetKind::Library],
                )
                .unwrap_or_else(|error| panic!("the fixture item is valid: {error}")),
            )
            .unwrap_or_else(|error| panic!("the fixture item is declared: {error}"));
    }
    let text_package = graph
        .package("std.text")
        .unwrap_or_else(|| panic!("the fixture graph declares std.text"))
        .clone();

    // an exported item without a declared tier cannot be deprecated
    let export_only = StdPackage::new(
        PackageFamily::Codec,
        NameClass::Package,
        StabilityTier::Stable,
        &[SemanticMode::Portable],
        &[TargetKind::Library],
        &[],
        &["std.codec::exported"],
    )
    .unwrap_or_else(|error| panic!("the fixture package is valid: {error}"));
    let tierless = StdDeprecation::new(
        "std.codec::exported",
        StabilityTier::Stable,
        StabilityTier::Experimental,
        None,
    )
    .unwrap_or_else(|error| panic!("the fixture deprecation is valid: {error}"));
    assert_eq!(
        refuse(
            tierless.admit(&export_only),
            "a deprecation over an item without a declared tier"
        )
        .code(),
        StdlibDiagnosticCode::InvalidRelocation
    );
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
        .admit(&text_package)
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
        refuse(removed.admit(&text_package), "a silently removed item").code(),
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
            absent_replacement.admit(&text_package),
            "an undeclared replacement"
        )
        .code(),
        StdlibDiagnosticCode::InvalidRelocation
    );

    // a deprecation leaving the foundational tier is refused
    assert_eq!(
        refuse(
            StdDeprecation::new(
                "std.text::format",
                StabilityTier::Foundational,
                StabilityTier::Stable,
                None
            ),
            "a deprecation leaving the foundational tier"
        )
        .code(),
        StdlibDiagnosticCode::InvalidRelocation
    );

    // a deprecation contradicting the item's declared tier is refused
    let mut graph = graph_with(&[package(
        PackageFamily::Text,
        StabilityTier::Stable,
        &[],
        &[],
    )]);
    graph
        .declare_item(
            StdItem::new(
                "std.text::render",
                NameClass::Module,
                StabilityTier::Stable,
                &[SemanticMode::Portable],
                &[TargetKind::Library],
            )
            .unwrap_or_else(|error| panic!("the fixture item is valid: {error}")),
        )
        .unwrap_or_else(|error| panic!("the fixture item is declared: {error}"));
    let text = graph
        .package("std.text")
        .unwrap_or_else(|| panic!("the fixture graph declares std.text"))
        .clone();
    let untied = StdDeprecation::new(
        "std.text::render",
        StabilityTier::TargetSpecific,
        StabilityTier::Experimental,
        None,
    )
    .unwrap_or_else(|error| panic!("the fixture deprecation is valid: {error}"));
    assert_eq!(
        refuse(
            untied.admit(&text),
            "a deprecation contradicting the declared item tier"
        )
        .code(),
        StdlibDiagnosticCode::InvalidRelocation
    );
}

#[test]
fn prelude_edition_is_folded_into_the_aggregate_identity() {
    let contract = StdContractVersion::new(1, 2)
        .unwrap_or_else(|error| panic!("the fixture contract version is valid: {error}"));
    let mut manifests = Vec::new();
    for edition in ["2024", "2027"] {
        let mut graph = StdGraph::new(
            Prelude::new(edition, &["std.core::option", "std.core::result"])
                .unwrap_or_else(|error| panic!("the fixture prelude is valid: {error}")),
        );
        graph
            .declare(package(
                PackageFamily::Core,
                StabilityTier::Foundational,
                &[],
                &[],
            ))
            .unwrap_or_else(|error| panic!("the fixture package is declared: {error}"));
        manifests.push(
            graph
                .manifest(contract)
                .unwrap_or_else(|error| panic!("the fixture manifest is valid: {error}")),
        );
    }
    let first = &manifests[0];
    let second = &manifests[1];
    assert_eq!(first.prelude_edition(), "2024");
    assert_eq!(second.prelude_edition(), "2027");
    assert_eq!(first.entries(), second.entries());
    assert_ne!(
        first.identity(),
        second.identity(),
        "an edition-only change is visible in the aggregate identity"
    );

    // a manifest built under one edition is refused against a hierarchy declaring another
    let mut other = StdGraph::new(
        Prelude::new("2027", &["std.core::option", "std.core::result"])
            .unwrap_or_else(|error| panic!("the fixture prelude is valid: {error}")),
    );
    other
        .declare(package(
            PackageFamily::Core,
            StabilityTier::Foundational,
            &[],
            &[],
        ))
        .unwrap_or_else(|error| panic!("the fixture package is declared: {error}"));
    assert_eq!(
        refuse(
            first.verify_against(&other),
            "an edition-only publication drift"
        )
        .code(),
        StdlibDiagnosticCode::PublicationDrift
    );
}

#[test]
fn aggregate_hierarchy_composes_every_declared_family_surface() {
    let aggregate = canonical_std_hierarchy()
        .unwrap_or_else(|error| panic!("the aggregate hierarchy is declared: {error}"));
    let families = [
        canonical_collections_hierarchy(),
        canonical_codec_hierarchy(),
        canonical_crypto_hierarchy(),
        canonical_data_hierarchy(),
    ];
    let mut expected: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for family in families {
        let family =
            family.unwrap_or_else(|error| panic!("the family hierarchy declares: {error}"));
        for name in family.package_names() {
            let package = family
                .package(name)
                .unwrap_or_else(|| panic!("`{name}` resolves in its family hierarchy"));
            if !package.items().is_empty() {
                expected
                    .entry(name.to_string())
                    .or_default()
                    .extend(package.items().keys().cloned());
            }
        }
    }
    assert!(
        !expected.is_empty(),
        "the declared families carry item rows"
    );
    let mut declared: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for name in aggregate.package_names() {
        let package = aggregate
            .package(name)
            .unwrap_or_else(|| panic!("`{name}` resolves in the aggregate hierarchy"));
        if !package.items().is_empty() {
            declared.insert(name.to_string(), package.items().keys().cloned().collect());
        }
    }
    assert_eq!(
        declared, expected,
        "the aggregate declares exactly the composed family item surfaces"
    );
    for name in aggregate.package_names() {
        let package = aggregate
            .package(name)
            .unwrap_or_else(|| panic!("`{name}` resolves in the aggregate hierarchy"));
        for item in package.items().values() {
            assert_eq!(
                item.owner(),
                name,
                "every aggregate item is owned by its declaring package"
            );
        }
    }
    assert!(
        aggregate.validate().is_ok(),
        "the composed aggregate hierarchy is valid"
    );
    assert!(
        aggregate.topological_order().is_ok(),
        "the composed pure DAG is acyclic"
    );
    let contract = StdContractVersion::new(1, 0)
        .unwrap_or_else(|error| panic!("the fixture contract version is valid: {error}"));
    let manifest = aggregate
        .manifest(contract)
        .unwrap_or_else(|error| panic!("the aggregate manifest is valid: {error}"));
    assert_eq!(manifest.entries().len(), aggregate.package_names().len());
    assert!(manifest.verify_against(&aggregate).is_ok());
    assert!(
        aggregate
            .package("crates/gantry-ir/src/crypto.rs")
            .is_none(),
        "repository layout is never a standard-package identity"
    );
}

#[test]
fn aggregate_manifest_catalog_matches_the_live_hierarchy() {
    let document =
        fs::read_to_string(workspace_root().join("protocol/catalogs/stdlib-hierarchy-v1.json"))
            .unwrap_or_else(|error| panic!("the aggregate manifest catalog reads: {error}"));
    let catalog: Value = serde_json::from_str(&document)
        .unwrap_or_else(|error| panic!("the aggregate manifest catalog is JSON: {error}"));
    assert_eq!(catalog["format"], Value::from("gantry-stdlib-hierarchy-v1"));
    assert_eq!(
        catalog["prelude_edition"],
        Value::from(CANONICAL_PRELUDE_EDITION)
    );
    assert_eq!(catalog["contract"]["major"], Value::from(1));
    assert_eq!(catalog["contract"]["minor"], Value::from(0));
    let aggregate = canonical_std_hierarchy()
        .unwrap_or_else(|error| panic!("the aggregate hierarchy is declared: {error}"));
    let contract = StdContractVersion::new(1, 0)
        .unwrap_or_else(|error| panic!("the catalog contract version is valid: {error}"));
    let manifest = aggregate
        .manifest(contract)
        .unwrap_or_else(|error| panic!("the aggregate manifest is valid: {error}"));
    assert_eq!(manifest.prelude_edition(), CANONICAL_PRELUDE_EDITION);
    let entries = catalog["packages"]
        .as_array()
        .unwrap_or_else(|| panic!("the catalog publishes its packages as an array"));
    assert_eq!(entries.len(), manifest.entries().len());
    let mut prior: Option<&str> = None;
    for declared in entries {
        let name = declared["name"]
            .as_str()
            .unwrap_or_else(|| panic!("every declared package names itself"));
        if let Some(previous) = prior {
            assert!(
                previous < name,
                "the catalog lists packages in canonical order"
            );
        }
        prior = Some(name);
        let entry = manifest
            .entries()
            .iter()
            .find(|entry| entry.name() == name)
            .unwrap_or_else(|| panic!("`{name}` is declared in the aggregate manifest"));
        assert_eq!(
            declared["class"],
            Value::from(entry.class().wire_name()),
            "`{name}` publishes its class"
        );
        assert_eq!(
            declared["tier"],
            Value::from(entry.tier().wire_name()),
            "`{name}` publishes its tier"
        );
        let modes: Vec<&str> = entry.modes().iter().map(|mode| mode.wire_name()).collect();
        let declared_modes: Vec<&str> = declared["modes"]
            .as_array()
            .unwrap_or_else(|| panic!("`{name}` publishes its modes as an array"))
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert_eq!(
            declared_modes, modes,
            "`{name}` publishes its applicability modes"
        );
        let targets: Vec<&str> = entry
            .targets()
            .iter()
            .map(|target| target.wire_name())
            .collect();
        let declared_targets: Vec<&str> = declared["targets"]
            .as_array()
            .unwrap_or_else(|| panic!("`{name}` publishes its targets as an array"))
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert_eq!(
            declared_targets, targets,
            "`{name}` publishes its applicability targets"
        );
        let dependencies: Vec<&str> = entry.dependencies().iter().map(String::as_str).collect();
        let declared_dependencies: Vec<&str> = declared["dependencies"]
            .as_array()
            .unwrap_or_else(|| panic!("`{name}` publishes its dependencies as an array"))
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert_eq!(
            declared_dependencies, dependencies,
            "`{name}` publishes its dependency edges"
        );
        assert_eq!(
            declared["interface_digest"],
            Value::from(entry.identity().as_str()),
            "`{name}` publishes its interface digest"
        );
    }
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
    for malformed in ["std", "STD.core", "std..core"] {
        let graph = graph_with(&[package(
            PackageFamily::Fs,
            StabilityTier::Stable,
            &[malformed],
            &[],
        )]);
        assert_eq!(
            refuse(graph.validate(), "a malformed std reference").code(),
            StdlibDiagnosticCode::InvalidPackageName,
            "{malformed}"
        );
    }
    check_layout_identity(&["ratio/2", "std.fs", "facet-fs-local"]).unwrap_or_else(|error| {
        panic!("a logical token containing a separator is not a layout fact: {error}")
    });
    let outsides = graph_with(&[package(
        PackageFamily::Fs,
        StabilityTier::Stable,
        &["stdata.x"],
        &[],
    )]);
    assert_eq!(
        refuse(outsides.validate(), "a non-std reference resembling std").code(),
        StdlibDiagnosticCode::PackageToAdapterEdge
    );
    for physical in [
        "gantry-ir/src",
        "target/debug",
        "Src/lib",
        "lib.rs",
        "Cargo.toml",
    ] {
        assert_eq!(
            refuse(check_layout_identity(&[physical]), "a physical layout fact").code(),
            StdlibDiagnosticCode::LayoutDerivedIdentity,
            "{physical}"
        );
    }
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

    // one path cannot carry two classifications in either direction
    let duplicate_item = StdItem::new(
        "std.net::socket",
        NameClass::Facade,
        StabilityTier::Stable,
        &[SemanticMode::Portable],
        &[TargetKind::Library],
    )
    .unwrap_or_else(|error| panic!("the fixture item is valid: {error}"));
    assert_eq!(
        refuse(
            graph.declare_item(duplicate_item),
            "a declared name re-declared as an item"
        )
        .code(),
        StdlibDiagnosticCode::InvalidNameClassification
    );
    graph
        .declare_name(
            StdName::new("std.io::console", NameClass::Module, "std.io")
                .unwrap_or_else(|error| panic!("the fixture name is valid: {error}")),
        )
        .unwrap_or_else(|error| panic!("the declared name is admitted: {error}"));
    let conflicting = StdItem::new(
        "std.io::console",
        NameClass::Facade,
        StabilityTier::Stable,
        &[SemanticMode::Portable],
        &[TargetKind::Library],
    )
    .unwrap_or_else(|error| panic!("the fixture item is valid: {error}"));
    assert_eq!(
        refuse(
            graph.declare_item(conflicting),
            "a declared name re-declared as an item"
        )
        .code(),
        StdlibDiagnosticCode::InvalidNameClassification
    );
    // one logical path has one canonical form
    graph
        .declare_name(
            StdName::new("std.io.alpha", NameClass::Module, "std.io")
                .unwrap_or_else(|error| panic!("the fixture name is valid: {error}")),
        )
        .unwrap_or_else(|error| panic!("the declared name is admitted: {error}"));
    assert_eq!(
        refuse(
            graph.declare_name(
                StdName::new("std.io::alpha", NameClass::Module, "std.io")
                    .unwrap_or_else(|error| panic!("the fixture name is valid: {error}"))
            ),
            "one path declared under two spellings"
        )
        .code(),
        StdlibDiagnosticCode::DuplicatePackage
    );
    assert_eq!(
        refuse(
            graph.declare_item(
                StdItem::new(
                    "std.io::alpha",
                    NameClass::Facade,
                    StabilityTier::Stable,
                    &[SemanticMode::Portable],
                    &[TargetKind::Library],
                )
                .unwrap_or_else(|error| panic!("the fixture item is valid: {error}"))
            ),
            "one path carrying two classifications under two spellings"
        )
        .code(),
        StdlibDiagnosticCode::InvalidNameClassification
    );
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

/// The canonical pure hierarchy declares each pure family exactly once with the roadmap's
/// dependency direction, so `std.collections` has one canonical package identity and no pure
/// package reaches a capability-backed family (`GNT-34.1`, `GNT-34.3`, `GNT-34.8`).
#[test]
fn canonical_pure_hierarchy_declares_each_pure_family_once() {
    let graph = canonical_pure_hierarchy()
        .unwrap_or_else(|error| panic!("the canonical pure hierarchy is valid: {error}"));
    graph
        .validate()
        .unwrap_or_else(|error| panic!("the canonical pure hierarchy validates: {error}"));
    let mut names = graph.package_names();
    names.sort_unstable();
    assert_eq!(
        names,
        vec![
            "std.codec",
            "std.collections",
            "std.core",
            "std.crypto",
            "std.data",
            "std.num",
            "std.text",
        ]
    );
    for name in &names {
        let package = graph
            .package(name)
            .unwrap_or_else(|| panic!("{name} is declared"));
        assert!(
            package
                .dependencies()
                .iter()
                .all(|dependency| names.contains(&dependency.as_str())),
            "{name} depends only on declared pure packages"
        );
        assert!(
            !package.identity().as_str().is_empty(),
            "{name} publishes an interface identity"
        );
        // `std.core` is the foundational root; every other pure family is stable (`GNT-34.6`).
        let tier = if *name == CORE {
            StabilityTier::Foundational
        } else {
            StabilityTier::Stable
        };
        assert_eq!(package.tier(), tier, "{name} declares its canonical tier");
        // Only `std.core` declares items here: the enumerated prelude members of `GNT-34.4`.
        // Every other family's items belong to the issue that owns its API surface
        // (`GNT-GP-COLL-001` and the focused family issues).
        let expected_items = if *name == CORE { 2 } else { 0 };
        assert_eq!(
            package.items().len(),
            expected_items,
            "{name} declares only its reviewed items"
        );
    }
    let collections = graph
        .package(COLLECTIONS)
        .unwrap_or_else(|| panic!("`{COLLECTIONS}` is declared"));
    let core = graph
        .package(CORE)
        .unwrap_or_else(|| panic!("`{CORE}` is declared"));
    let members = core.items().keys().cloned().collect::<Vec<_>>();
    // The model's canonical item identity is the dotted path, exactly as `canonical_std_path`
    // normalizes the `std.core::NAME` prelude spelling; `OPTION_ITEM` is that canonical spelling's
    // prelude-name form.
    assert_eq!(members, vec!["std.core.option", "std.core.result"]);
    for member in &members {
        let item = core
            .items()
            .get(member)
            .unwrap_or_else(|| panic!("{member} is declared"));
        assert_eq!(item.owner(), CORE, "{member} is owned by `std.core`");
        assert_eq!(
            item.tier(),
            StabilityTier::Foundational,
            "{member} is a foundational prelude item"
        );
        // Class and applicability are folded into the interface digest, so they are pinned here
        // exactly as the owning package declares them.
        assert_eq!(
            item.class(),
            NameClass::Module,
            "{member} is a library-owned declaration"
        );
        assert_eq!(
            item.modes(),
            core.modes(),
            "{member} inherits core applicability"
        );
        assert_eq!(
            item.targets(),
            core.targets(),
            "{member} inherits the core target set"
        );
    }
    let manifest = graph
        .manifest(
            StdContractVersion::new(1, 0)
                .unwrap_or_else(|error| panic!("the contract version is valid: {error}")),
        )
        .unwrap_or_else(|error| {
            panic!("the canonical pure hierarchy publishes a manifest: {error}")
        });
    assert_eq!(manifest.entries().len(), 7);
    assert_eq!(
        collections
            .dependencies()
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        vec![CORE],
        "`std.collections` depends only on `std.core`"
    );
    let order = graph
        .topological_order()
        .unwrap_or_else(|error| panic!("the canonical pure hierarchy orders: {error}"));
    let again = graph
        .topological_order()
        .unwrap_or_else(|error| panic!("the canonical pure hierarchy orders again: {error}"));
    assert_eq!(order, again, "the topological order is deterministic");
    let position = |name: &str| {
        order
            .iter()
            .position(|entry| entry.as_str() == name)
            .unwrap_or_else(|| panic!("{name} appears in the topological order"))
    };
    assert!(position(CORE) < position(COLLECTIONS));
    assert_eq!(graph.prelude().edition(), "2026");
    // Edition additions and removals against the canonical prelude (`GNT-34.4`): the declared
    // member set is redeclarable under its own edition, any changed set under that edition is
    // refused, an explicit new edition is admitted, and an automatic name outside the enumeration
    // is refused.
    let declared_prelude = graph.prelude();
    let same = declared_prelude
        .for_edition("2026", &[OPTION_ITEM, "std.core::result"])
        .unwrap_or_else(|error| panic!("the canonical edition is redeclarable: {error}"));
    assert_eq!(same.members(), declared_prelude.members());
    for (members, context) in [
        ([OPTION_ITEM].as_slice(), "a narrower member set"),
        (
            [OPTION_ITEM, "std.core::result", "std.core::map"].as_slice(),
            "a wider member set",
        ),
    ] {
        assert_eq!(
            refuse(
                declared_prelude.for_edition("2026", members),
                "a changed member set under a declared edition"
            )
            .code(),
            StdlibDiagnosticCode::UnenumeratedPreludeMember,
            "{context} under the same edition is refused"
        );
    }
    let next = declared_prelude
        .for_edition("2027", &[OPTION_ITEM])
        .unwrap_or_else(|error| panic!("a new edition is admitted: {error}"));
    assert_eq!(next.edition(), "2027");
    assert_eq!(next.members().len(), 1);
    assert_eq!(
        refuse(
            declared_prelude.admit("std.core::map"),
            "an automatic name outside the enumeration"
        )
        .code(),
        StdlibDiagnosticCode::UnenumeratedPreludeMember
    );
}

/// The committed standard-library architecture note names every family and prelude member the
/// canonical hierarchy declares. The check is deliberately narrow: it pins the declared names so a
/// renamed or added family cannot leave the note stale, and it says nothing about the note's
/// tier, edge, or non-claim wording, which the model tests cover.
#[test]
fn standard_library_architecture_note_names_every_declared_family_and_prelude_member() {
    let note = fs::read_to_string(workspace_root().join("docs/standard-library-architecture.md"))
        .unwrap_or_else(|error| panic!("the architecture note is readable: {error}"));
    let graph = canonical_pure_hierarchy()
        .unwrap_or_else(|error| panic!("the canonical pure hierarchy is valid: {error}"));
    for name in graph.package_names() {
        assert!(note.contains(name), "the note names `{name}`");
    }
    for member in [OPTION_ITEM, "std.core::result"] {
        assert!(note.contains(member), "the note names `{member}`");
    }
}

/// Every declared Section-34 anchor is published in the architecture note.
///
/// The note is descriptive, but the anchors it names are the declared clauses of
/// `STDLIB_CLAUSES`, so this lane requires each of them to appear: a clause added to the model
/// cannot leave the note silent about it.
#[test]
fn standard_library_architecture_note_names_every_declared_clause_anchor() {
    let note = fs::read_to_string(workspace_root().join("docs/standard-library-architecture.md"))
        .unwrap_or_else(|error| panic!("the architecture note is readable: {error}"));
    for clause in STDLIB_CLAUSES {
        assert!(note.contains(clause), "the note names `{clause}`");
    }
}

/// Every declared non-claim is published in the architecture note.
///
/// The non-claim vocabulary is read from `STDLIB_NON_CLAIMS` itself — each entry's label up to its
/// first colon — so a non-claim added to the model fails this lane until the note names it, which
/// is what the previous, incomplete summary lacked.
#[test]
fn standard_library_architecture_note_names_every_declared_non_claim() {
    let note = fs::read_to_string(workspace_root().join("docs/standard-library-architecture.md"))
        .unwrap_or_else(|error| panic!("the architecture note is readable: {error}"));
    for declared in STDLIB_NON_CLAIMS {
        let label = declared
            .split(':')
            .next()
            .unwrap_or_else(|| panic!("the declared non-claim has a label"));
        assert!(
            note.contains(label),
            "the note names the declared non-claim `{label}`"
        );
    }
}

/// The architecture note discloses how the enumerated prelude reaches source resolution.
///
/// The behavior itself is pinned by `analyzer_types.rs`
/// (`edition_prelude_source_boundary_matches_the_enumerated_declaration`,
/// `automatic_source_names_are_derived_from_the_enumerated_prelude`), which requires the
/// prelude-owned spellings to resolve only while their member is enumerated, an unavailable one to
/// refuse with `unresolved-reference`, and a standard-package import to refuse with exactly
/// `unresolved-import`. This lane keeps the note's disclosure of that state present, so a note
/// revision cannot silently drop it; it deliberately does not scan analyzer sources.
#[test]
fn standard_library_architecture_note_discloses_the_prelude_resolution_boundary() {
    let note = fs::read_to_string(workspace_root().join("docs/standard-library-architecture.md"))
        .unwrap_or_else(|error| panic!("the architecture note is readable: {error}"));
    // The note is line-wrapped, so phrases are matched against whitespace-normalized text.
    let normalized = note.split_whitespace().collect::<Vec<_>>().join(" ");
    for phrase in [
        "name resolution consults the enumerated members",
        "is refused with `unresolved-reference`",
        "is refused with `unresolved-import`",
    ] {
        assert!(
            normalized.contains(phrase),
            "the note discloses the prelude resolution boundary: `{phrase}`"
        );
    }
}

/// The capitalized reserved spellings the compiler owns: scalar and foundational type words,
/// composite type words, their constructor spellings, and the contextual `Self`.
const COMPILER_OWNED_TYPE_WORDS: [&str; 17] = [
    "Unit",
    "Bool",
    "Int",
    "Float",
    "String",
    "List",
    "Tuple",
    "Never",
    "Decision",
    "OperationError",
    "Option",
    "Result",
    "Some",
    "None",
    "Ok",
    "Err",
    "Self",
];

/// The capitalized spellings reserved for future compatible extension: the collection vocabulary
/// that no package declares and no source position resolves yet.
const RESERVED_FOR_EXTENSION_SPELLINGS: [&str; 3] = ["Map", "Range", "Set"];

/// The architecture note separates compiler-owned type words from the declared hierarchy, and the
/// front end still reserves every spelling the note publishes.
///
/// The inventory is the capitalized subset of the grammar's reserved words
/// (`crates/gantry-frontend/src/token.rs`); `frontend_lexical_evidence.rs` pins the reserved
/// vocabulary, and `analyzer_types.rs` pins the resolution boundary for the
/// enumerated members. This lane keeps the note's separation present and requires each documented
/// spelling to still classify as a reserved word, so a note revision cannot invent or silently
/// drop one. Drift in the classifier itself is caught by
/// `reserved_spelling_sources_agree_with_the_published_inventory` below.
#[test]
fn standard_library_architecture_note_separates_compiler_owned_type_words() {
    let note = fs::read_to_string(workspace_root().join("docs/standard-library-architecture.md"))
        .unwrap_or_else(|error| panic!("the architecture note is readable: {error}"));
    // The note is line-wrapped, so spellings are matched against whitespace-normalized text.
    let normalized = note.split_whitespace().collect::<Vec<_>>().join(" ");
    for word in COMPILER_OWNED_TYPE_WORDS {
        assert!(
            normalized.contains(&format!("`{word}`")),
            "the note names the compiler-owned spelling `{word}`"
        );
        assert_eq!(
            gantry::frontend::ReservedWord::from_spelling(word)
                .map(gantry::frontend::ReservedWord::spelling),
            Some(word),
            "`{word}` is still a reserved word"
        );
    }
    for word in RESERVED_FOR_EXTENSION_SPELLINGS {
        assert!(
            normalized.contains(&format!("`{word}`")),
            "the note names the reserved-for-extension spelling `{word}`"
        );
        assert_eq!(
            gantry::frontend::ReservedWord::from_spelling(word)
                .map(gantry::frontend::ReservedWord::spelling),
            Some(word),
            "`{word}` is reserved"
        );
    }
}

/// The grammar's reserved-word table, the lexical vector lane, and the published compiler-owned
/// inventory are three hand-maintained lists of one vocabulary; this lane couples them.
///
/// It reads `crates/gantry-frontend/src/token.rs` for the `from_spelling` arms, the lexical lane
/// `frontend_lexical_evidence.rs` for the vector it asserts, and this file's
/// `COMPILER_OWNED_TYPE_WORDS`, and requires the classified spellings, the exercised vector, and
/// the capitalized published subset to agree. The coupling is textual by design — the lists have
/// drifted before — and it fails loudly when the classifier is reformatted, which is when this
/// lane must be revisited.
#[test]
fn reserved_spelling_sources_agree_with_the_published_inventory() {
    let classifier_source =
        fs::read_to_string(workspace_root().join("crates/gantry-frontend/src/token.rs"))
            .unwrap_or_else(|error| panic!("the front-end token source is readable: {error}"));
    let table = classifier_source
        .split_once("pub fn from_spelling")
        .and_then(|(_, rest)| rest.split_once("pub const fn spelling"))
        .map(|(body, _)| body)
        .unwrap_or_else(|| panic!("the reserved-word classifier is locateable"));
    let classified: Vec<&str> = table.lines().filter_map(quoted_arm_spelling).collect();
    let classified_spellings = classified.clone();

    let lexical_source = fs::read_to_string(
        workspace_root().join("crates/gantry-conformance/tests/frontend_lexical_evidence.rs"),
    )
    .unwrap_or_else(|error| panic!("the lexical lane source is readable: {error}"));
    let vector = lexical_source
        .split_once("let reserved = [")
        .and_then(|(_, rest)| rest.split_once("];"))
        .map(|(body, _)| body)
        .unwrap_or_else(|| panic!("the lexical reserved vector is locateable"));
    let exercised: Vec<&str> = vector.lines().filter_map(quoted_entry).collect();

    assert_eq!(
        classified.len(),
        77,
        "the classifier tabulates 77 reserved spellings; update this pin, the lexical vector, and \
         the published inventory together when the table changes"
    );
    assert_eq!(
        sorted_spellings(exercised),
        sorted_spellings(classified.clone()),
        "the lexical vector exercises exactly the classified spellings"
    );
    let capitalized: Vec<&str> = classified
        .into_iter()
        .filter(|spelling| {
            spelling
                .chars()
                .next()
                .is_some_and(|first| first.is_ascii_uppercase())
        })
        .collect();
    let mut published = COMPILER_OWNED_TYPE_WORDS.to_vec();
    published.extend(RESERVED_FOR_EXTENSION_SPELLINGS);
    assert_eq!(
        sorted_spellings(capitalized),
        sorted_spellings(published),
        "the published inventory is exactly the classifier's capitalized spellings"
    );
    assert!(
        COMPILER_OWNED_TYPE_WORDS
            .iter()
            .all(|word| !RESERVED_FOR_EXTENSION_SPELLINGS.contains(word)),
        "the compiler-owned and reserved-for-extension inventories are disjoint"
    );

    // The specification publishes the same vocabulary in its reserved-word block; a classifier
    // edit that leaves the normative list behind fails here rather than drifting silently.
    let specification = fs::read_to_string(workspace_root().join("SPEC.md"))
        .unwrap_or_else(|error| panic!("the specification is readable: {error}"));
    let block = specification
        .split_once("The reserved words are:")
        .and_then(|(_, rest)| rest.split_once("```text"))
        .and_then(|(_, rest)| rest.split_once("```"))
        .map(|(body, _)| body)
        .unwrap_or_else(|| panic!("the reserved-word block is locateable"));
    let published_in_specification: Vec<&str> = block.split_whitespace().collect();
    assert_eq!(
        sorted_spellings(published_in_specification),
        sorted_spellings(classified_spellings.clone()),
        "the specification's reserved-word list is exactly the classified spellings"
    );
}

/// Extracts `<spelling>` from a classifier arm written as `"<spelling>" => "<spelling>",`.
fn quoted_arm_spelling(line: &str) -> Option<&str> {
    let rest = line.trim().strip_prefix('"')?;
    let end = rest.find('"')?;
    let spelling = &rest[..end];
    let tail = rest[end + 1..].trim_start().strip_prefix("=>")?;
    let value = tail.trim_start().strip_prefix('"')?;
    (&value[..value.find('"')?] == spelling).then_some(spelling)
}

/// Extracts `<spelling>` from a lane array entry written as `"<spelling>",`.
fn quoted_entry(line: &str) -> Option<&str> {
    let rest = line.trim().strip_prefix('"')?;
    Some(&rest[..rest.find('"')?])
}

/// Sorts spellings and refuses duplicates, so a repeated arm or entry cannot hide drift.
fn sorted_spellings(mut spellings: Vec<&str>) -> Vec<&str> {
    spellings.sort_unstable();
    let mut deduped = spellings.clone();
    deduped.dedup();
    assert_eq!(spellings, deduped, "each spelling appears once");
    spellings
}
