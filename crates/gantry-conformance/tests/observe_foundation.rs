//! Conformance for the declared `std.observe` surface.
//!
//! This lane pins the closed module rows and their declaration/admission behavior. It performs no
//! telemetry, event delivery, protected-data release, or host I/O.

use std::fs;
use std::path::{Path, PathBuf};

use gantry::ir::{
    NameClass, OBSERVE_CLAUSES, OBSERVE_ITEMS, OBSERVE_SURFACE_MODES, OBSERVE_SURFACE_TARGETS,
    ObserveItemRow, PackageFamily, Prelude, StabilityTier, StdGraph, StdItem, StdPackage,
    StdlibDiagnosticCode, admit_observe_surface, declare_observe_surface,
};
use gantry::ir::{SemanticMode, TargetKind};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn family_package(modes: &[SemanticMode], targets: &[TargetKind]) -> StdPackage {
    StdPackage::new(
        PackageFamily::Observe,
        NameClass::Package,
        StabilityTier::Stable,
        modes,
        targets,
        &[],
        &[],
    )
    .unwrap_or_else(|error| panic!("the std.observe package declaration is valid: {error:?}"))
}

#[test]
fn observe_scope_is_declared_without_runtime_or_release_claims() {
    assert_eq!(
        OBSERVE_CLAUSES,
        [
            "GNT-48.0-observe-foundation-scope",
            "GNT-48.1-observe-modules-and-item-rows",
        ]
    );
    assert_eq!(OBSERVE_SURFACE_MODES, [SemanticMode::Application]);
    assert_eq!(
        OBSERVE_SURFACE_TARGETS,
        [TargetKind::Library, TargetKind::Binary]
    );

    let specification = fs::read_to_string(workspace_root().join("SPEC.md"))
        .unwrap_or_else(|error| panic!("could not read SPEC.md: {error}"))
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    for clause in OBSERVE_CLAUSES {
        assert!(specification.contains(clause), "SPEC.md declares {clause}");
    }
    for rule in [
        "declaration surface of the capability-backed `std.observe` family",
        "logs, metrics, and traces",
        "is distinct from the protected runtime events of Section 12",
        "does not implement telemetry emission, sink delivery, protected-data release, or runtime availability",
    ] {
        assert!(specification.contains(rule), "SPEC.md pins: {rule}");
    }
}

#[test]
fn observe_module_rows_are_closed_and_canonical() {
    assert_eq!(
        OBSERVE_ITEMS.map(|row| row.name),
        [
            "std.observe::log",
            "std.observe::metric",
            "std.observe::trace",
        ]
    );
    assert_eq!(OBSERVE_ITEMS.len(), 3);
    for row in OBSERVE_ITEMS {
        assert_eq!(row.class, NameClass::Module);
        assert_eq!(row.tier, StabilityTier::Stable);
        assert_eq!(
            row.clauses,
            &[
                "GNT-48.0-observe-foundation-scope",
                "GNT-48.1-observe-modules-and-item-rows",
            ]
        );
    }
    let _row_type_witness: Option<ObserveItemRow> = None;
}

#[test]
fn observe_surface_declaration_requires_package_and_is_atomic() {
    let mut empty = StdGraph::new(Prelude::canonical());
    assert_eq!(
        declare_observe_surface(&mut empty)
            .err()
            .map(|error| error.code()),
        Some(StdlibDiagnosticCode::UnknownEdge)
    );

    let mut graph = StdGraph::new(Prelude::canonical());
    assert!(
        graph
            .declare(family_package(
                &OBSERVE_SURFACE_MODES,
                &OBSERVE_SURFACE_TARGETS,
            ))
            .is_ok()
    );
    assert!(declare_observe_surface(&mut graph).is_ok());
    assert!(admit_observe_surface(&graph).is_ok());
    let package = graph
        .package("std.observe")
        .unwrap_or_else(|| panic!("the family package is declared"));
    assert_eq!(package.items().len(), OBSERVE_ITEMS.len());
    let names = package
        .items()
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        ["std.observe.log", "std.observe.metric", "std.observe.trace",]
    );
    for row in OBSERVE_ITEMS {
        let item = package
            .item(row.name)
            .unwrap_or_else(|| panic!("{} is declared", row.name));
        assert_eq!(item.modes(), package.modes());
        assert_eq!(item.targets(), package.targets());
    }
    assert_eq!(
        declare_observe_surface(&mut graph)
            .err()
            .map(|error| error.code()),
        Some(StdlibDiagnosticCode::DuplicatePackage)
    );
}

#[test]
fn observe_surface_rejects_extra_items_and_mismatched_applicability() {
    let mut graph = StdGraph::new(Prelude::canonical());
    assert!(
        graph
            .declare(family_package(
                &OBSERVE_SURFACE_MODES,
                &OBSERVE_SURFACE_TARGETS,
            ))
            .is_ok()
    );
    assert!(declare_observe_surface(&mut graph).is_ok());
    let extra = gantry::ir::StdItem::new(
        "std.observe::extra",
        NameClass::Module,
        StabilityTier::Stable,
        &OBSERVE_SURFACE_MODES,
        &OBSERVE_SURFACE_TARGETS,
    )
    .unwrap_or_else(|error| panic!("the test-only extra item is well-formed: {error:?}"));
    assert!(graph.declare_item(extra).is_ok());
    assert_eq!(
        admit_observe_surface(&graph)
            .err()
            .map(|error| error.code()),
        Some(StdlibDiagnosticCode::InvalidNameClassification)
    );

    let mut mismatched = StdGraph::new(Prelude::canonical());
    assert!(
        mismatched
            .declare(family_package(
                &OBSERVE_SURFACE_MODES,
                &[TargetKind::Binary],
            ))
            .is_ok()
    );
    assert_eq!(
        declare_observe_surface(&mut mismatched)
            .err()
            .map(|error| error.code()),
        Some(StdlibDiagnosticCode::UnsupportedApplicability)
    );
}

#[test]
fn observe_surface_refuses_missing_and_partial_rows_without_mutating_the_graph() {
    let mut missing = StdGraph::new(Prelude::canonical());
    assert!(
        missing
            .declare(family_package(
                &OBSERVE_SURFACE_MODES,
                &OBSERVE_SURFACE_TARGETS,
            ))
            .is_ok()
    );
    let before_missing = missing.clone();
    assert_eq!(
        admit_observe_surface(&missing)
            .err()
            .map(|error| error.code()),
        Some(StdlibDiagnosticCode::InvalidNameClassification)
    );
    assert_eq!(missing, before_missing);

    let mut partial = StdGraph::new(Prelude::canonical());
    assert!(
        partial
            .declare(family_package(
                &OBSERVE_SURFACE_MODES,
                &OBSERVE_SURFACE_TARGETS,
            ))
            .is_ok()
    );
    let log = StdItem::new(
        OBSERVE_ITEMS[0].name,
        OBSERVE_ITEMS[0].class,
        OBSERVE_ITEMS[0].tier,
        &OBSERVE_SURFACE_MODES,
        &OBSERVE_SURFACE_TARGETS,
    )
    .unwrap_or_else(|error| panic!("the test module row is well-formed: {error:?}"));
    assert!(partial.declare_item(log).is_ok());
    let before_partial = partial.clone();
    assert_eq!(
        declare_observe_surface(&mut partial)
            .err()
            .map(|error| error.code()),
        Some(StdlibDiagnosticCode::InvalidNameClassification)
    );
    assert_eq!(partial, before_partial);
    assert_eq!(
        admit_observe_surface(&partial)
            .err()
            .map(|error| error.code()),
        Some(StdlibDiagnosticCode::InvalidNameClassification)
    );
    assert_eq!(partial, before_partial);
}

#[test]
fn observe_surface_refuses_rows_with_wrong_class_tier_or_applicability_atomically() {
    let invalid_rows = [
        (
            NameClass::GeneratedDeclaration,
            StabilityTier::Stable,
            OBSERVE_SURFACE_MODES.to_vec(),
            OBSERVE_SURFACE_TARGETS.to_vec(),
            StdlibDiagnosticCode::InvalidNameClassification,
        ),
        (
            NameClass::Module,
            StabilityTier::Experimental,
            OBSERVE_SURFACE_MODES.to_vec(),
            OBSERVE_SURFACE_TARGETS.to_vec(),
            StdlibDiagnosticCode::InvalidNameClassification,
        ),
        (
            NameClass::Module,
            StabilityTier::Stable,
            OBSERVE_SURFACE_MODES.to_vec(),
            vec![TargetKind::Binary],
            StdlibDiagnosticCode::UnsupportedApplicability,
        ),
    ];

    for (class, tier, modes, targets, expected_code) in invalid_rows {
        let mut graph = StdGraph::new(Prelude::canonical());
        assert!(
            graph
                .declare(family_package(
                    &OBSERVE_SURFACE_MODES,
                    &OBSERVE_SURFACE_TARGETS,
                ))
                .is_ok()
        );
        for (index, row) in OBSERVE_ITEMS.into_iter().enumerate() {
            let (row_class, row_tier, row_modes, row_targets) = if index == 0 {
                (class, tier, modes.as_slice(), targets.as_slice())
            } else {
                (
                    row.class,
                    row.tier,
                    OBSERVE_SURFACE_MODES.as_slice(),
                    OBSERVE_SURFACE_TARGETS.as_slice(),
                )
            };
            let item = StdItem::new(row.name, row_class, row_tier, row_modes, row_targets)
                .unwrap_or_else(|error| panic!("the test row is constructible: {error:?}"));
            assert!(graph.declare_item(item).is_ok());
        }

        let before = graph.clone();
        assert_eq!(
            declare_observe_surface(&mut graph)
                .err()
                .map(|error| error.code()),
            Some(expected_code)
        );
        assert_eq!(graph, before);
        assert_eq!(
            admit_observe_surface(&graph)
                .err()
                .map(|error| error.code()),
            Some(expected_code)
        );
        assert_eq!(graph, before);
    }
}
