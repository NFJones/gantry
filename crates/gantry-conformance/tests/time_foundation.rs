//! Conformance for the declaration-only `std.time` package surface.
//!
//! This lane covers module identity and applicability only; it performs no clock, timer,
//! scheduler, timezone, locale, rule-data, host, or durable operation, and it reads no host time.

use std::fs;
use std::path::{Path, PathBuf};

use gantry::ir::{
    DeclaredModuleRow, NameClass, PackageFamily, Prelude, SemanticMode, StabilityTier, StdGraph,
    StdItem, StdPackage, StdlibDiagnosticCode, TIME_CLAUSES, TIME_ITEMS, TIME_MODULE_CLAUSES,
    TIME_MODULE_MODES, TIME_MODULE_ROWS, TIME_MODULE_TARGETS, TargetKind, admit_time_surface,
    canonical_std_hierarchy, canonical_time_hierarchy, declare_time_surface,
    validate_time_module_rows,
};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn family_package(modes: &[SemanticMode], targets: &[TargetKind]) -> StdPackage {
    family_package_with_exports(modes, targets, &[])
}

fn family_package_with_exports(
    modes: &[SemanticMode],
    targets: &[TargetKind],
    exports: &[&str],
) -> StdPackage {
    match StdPackage::new(
        PackageFamily::Time,
        NameClass::Package,
        StabilityTier::Stable,
        modes,
        targets,
        &[],
        exports,
    ) {
        Ok(package) => package,
        Err(error) => panic!("the std.time package declaration is valid: {error:?}"),
    }
}

fn row_item(
    row: DeclaredModuleRow,
    class: NameClass,
    tier: StabilityTier,
    modes: &[SemanticMode],
    targets: &[TargetKind],
) -> StdItem {
    match StdItem::new(row.name, class, tier, modes, targets) {
        Ok(item) => item,
        Err(error) => panic!("the declared time row is valid: {error:?}"),
    }
}

fn graph_with_rows(
    class: NameClass,
    tier: StabilityTier,
    modes: &[SemanticMode],
    targets: &[TargetKind],
) -> StdGraph {
    let mut graph = StdGraph::new(Prelude::canonical());
    assert!(
        graph
            .declare(family_package(&TIME_MODULE_MODES, &TIME_MODULE_TARGETS))
            .is_ok()
    );
    for row in TIME_MODULE_ROWS {
        assert!(
            graph
                .declare_item(row_item(
                    row,
                    if row.name == TIME_MODULE_ROWS[0].name {
                        class
                    } else {
                        NameClass::Module
                    },
                    tier,
                    modes,
                    targets,
                ))
                .is_ok()
        );
    }
    graph
}

fn refusal<T>(result: Result<T, gantry::ir::StdlibError>) -> StdlibDiagnosticCode {
    match result {
        Ok(_) => panic!("the declared decision must be refused"),
        Err(error) => error.code(),
    }
}

#[test]
fn time_scope_is_declared_without_runtime_or_authority_claims() {
    assert_eq!(
        TIME_CLAUSES,
        [
            "GNT-51.0-time-foundation-scope",
            "GNT-51.1-time-modules-and-item-rows",
            "GNT-51.2-time-declaration-non-claims",
        ]
    );
    assert_eq!(
        TIME_MODULE_CLAUSES,
        [
            "GNT-51.0-time-foundation-scope",
            "GNT-51.1-time-modules-and-item-rows",
        ]
    );
    assert_eq!(TIME_MODULE_MODES, [SemanticMode::Application]);
    assert_eq!(
        TIME_MODULE_TARGETS,
        [TargetKind::Library, TargetKind::Binary]
    );
    let specification = fs::read_to_string(workspace_root().join("SPEC.md"))
        .unwrap_or_else(|error| panic!("could not read SPEC.md: {error}"))
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    for clause in TIME_CLAUSES {
        assert!(specification.contains(clause), "SPEC.md declares {clause}");
    }
    for rule in [
        "declaration surface of the capability-backed `std.time` family",
        "application semantic mode over the library and binary target kinds",
        "not Portable or Durable applicability",
        "not runtime availability",
        "no clock, timer, scheduler, timezone database or upgrade",
        "GNT-33.9-monotonic-and-wall-separation",
        "GNT-33.3-civil-time-timestamp-and-offset-values",
        "GNT-33.5-pinned-rule-data-identity",
    ] {
        assert!(specification.contains(rule), "SPEC.md pins: {rule}");
    }
}

/// The reader note must preserve the boundary between declaration and runtime authority.
#[test]
fn time_reader_note_preserves_declaration_and_qualification_boundaries() {
    let note = fs::read_to_string(workspace_root().join("docs/time-foundation.md"))
        .unwrap_or_else(|error| panic!("could not read time note: {error}"))
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    for anchor in TIME_CLAUSES {
        assert!(note.contains(anchor), "reader note names {anchor}");
    }
    for row in TIME_MODULE_ROWS {
        assert!(note.contains(row.name), "reader note names {}", row.name);
    }
    for boundary in [
        "application semantic mode over the library and binary target kinds",
        "UTC never supplies a monotonic deadline",
        "Declaring a module grants no capability",
        "does not implement typed civil ambiguity, pinned rule-data identities, or durable timer reconstruction",
        "declaration coverage is not evidence that they work",
        "Passing these lanes does not qualify a specification revision",
    ] {
        assert!(note.contains(boundary), "reader note retains {boundary}");
    }
}

#[test]
fn time_module_rows_are_closed_and_canonical() {
    assert_eq!(
        TIME_MODULE_ROWS.map(|row| row.name),
        [
            "std.time::civil",
            "std.time::clocks",
            "std.time::locale",
            "std.time::rule_data",
            "std.time::timers",
            "std.time::values",
        ]
    );
    assert_eq!(
        TIME_ITEMS.map(|row| row.name),
        TIME_MODULE_ROWS.map(|row| row.name)
    );
    for row in TIME_MODULE_ROWS {
        assert_eq!(row.class, NameClass::Module);
        assert_eq!(row.tier, StabilityTier::Stable);
        assert_eq!(row.modes, TIME_MODULE_MODES.as_slice());
        assert_eq!(row.targets, TIME_MODULE_TARGETS.as_slice());
        assert_eq!(row.clauses, TIME_MODULE_CLAUSES.as_slice());
    }
    assert!(validate_time_module_rows(&TIME_MODULE_ROWS).is_ok());
}

#[test]
fn time_surface_declaration_requires_package_and_admits_exact_rows() {
    let mut empty = StdGraph::new(Prelude::canonical());
    assert_eq!(
        refusal(declare_time_surface(&mut empty)),
        StdlibDiagnosticCode::UnknownEdge
    );
    assert_eq!(
        refusal(admit_time_surface(&empty)),
        StdlibDiagnosticCode::UnknownEdge
    );

    let mut graph = StdGraph::new(Prelude::canonical());
    assert!(
        graph
            .declare(family_package(&TIME_MODULE_MODES, &TIME_MODULE_TARGETS))
            .is_ok()
    );
    assert!(declare_time_surface(&mut graph).is_ok());
    assert!(admit_time_surface(&graph).is_ok());
    let package = graph
        .package("std.time")
        .unwrap_or_else(|| panic!("the family package is declared"));
    assert_eq!(package.items().len(), TIME_ITEMS.len());
    assert_eq!(
        package
            .items()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        [
            "std.time.civil",
            "std.time.clocks",
            "std.time.locale",
            "std.time.rule_data",
            "std.time.timers",
            "std.time.values",
        ]
    );

    let family = canonical_time_hierarchy()
        .unwrap_or_else(|error| panic!("the std.time hierarchy declares: {error}"));
    assert_eq!(
        family
            .package("std.time")
            .unwrap_or_else(|| panic!("std.time is declared in its family hierarchy"))
            .items()
            .len(),
        TIME_ITEMS.len()
    );
    let aggregate = canonical_std_hierarchy()
        .unwrap_or_else(|error| panic!("the aggregate hierarchy declares: {error}"));
    let time = aggregate
        .package("std.time")
        .unwrap_or_else(|| panic!("std.time is composed into the aggregate hierarchy"));
    assert_eq!(time.items().len(), TIME_ITEMS.len());
    assert!(time.dependencies().is_empty());
}

#[test]
fn time_surface_rejects_missing_extra_and_duplicate_rows() {
    let mut missing = StdGraph::new(Prelude::canonical());
    assert!(
        missing
            .declare(family_package(&TIME_MODULE_MODES, &TIME_MODULE_TARGETS))
            .is_ok()
    );
    for row in &TIME_MODULE_ROWS[..5] {
        assert!(
            missing
                .declare_item(row_item(
                    *row,
                    NameClass::Module,
                    StabilityTier::Stable,
                    &TIME_MODULE_MODES,
                    &TIME_MODULE_TARGETS,
                ))
                .is_ok()
        );
    }
    let before = missing.clone();
    assert_eq!(
        refusal(declare_time_surface(&mut missing)),
        StdlibDiagnosticCode::InvalidNameClassification
    );
    assert_eq!(missing, before);
    assert_eq!(
        refusal(admit_time_surface(&missing)),
        StdlibDiagnosticCode::InvalidNameClassification
    );
    assert_eq!(missing, before);

    let mut extra_export = StdGraph::new(Prelude::canonical());
    assert!(
        extra_export
            .declare(family_package_with_exports(
                &TIME_MODULE_MODES,
                &TIME_MODULE_TARGETS,
                &["std.time::extra"],
            ))
            .is_ok()
    );
    let before = extra_export.clone();
    assert_eq!(
        refusal(declare_time_surface(&mut extra_export)),
        StdlibDiagnosticCode::InvalidNameClassification
    );
    assert_eq!(extra_export, before);

    let mut extra = graph_with_rows(
        NameClass::Module,
        StabilityTier::Stable,
        &TIME_MODULE_MODES,
        &TIME_MODULE_TARGETS,
    );
    let extra_item = row_item(
        DeclaredModuleRow {
            name: "std.time::extra",
            class: NameClass::Module,
            tier: StabilityTier::Stable,
            modes: &TIME_MODULE_MODES,
            targets: &TIME_MODULE_TARGETS,
            clauses: &TIME_MODULE_CLAUSES,
        },
        NameClass::Module,
        StabilityTier::Stable,
        &TIME_MODULE_MODES,
        &TIME_MODULE_TARGETS,
    );
    assert!(extra.declare_item(extra_item).is_ok());
    let before = extra.clone();
    assert_eq!(
        refusal(admit_time_surface(&extra)),
        StdlibDiagnosticCode::InvalidNameClassification
    );
    assert_eq!(extra, before);

    let duplicate = [
        TIME_MODULE_ROWS[0],
        TIME_MODULE_ROWS[0],
        TIME_MODULE_ROWS[2],
        TIME_MODULE_ROWS[3],
        TIME_MODULE_ROWS[4],
        TIME_MODULE_ROWS[5],
    ];
    assert_eq!(
        refusal(validate_time_module_rows(&duplicate)),
        StdlibDiagnosticCode::InvalidNameClassification
    );

    let reordered = [
        TIME_MODULE_ROWS[1],
        TIME_MODULE_ROWS[0],
        TIME_MODULE_ROWS[2],
        TIME_MODULE_ROWS[3],
        TIME_MODULE_ROWS[4],
        TIME_MODULE_ROWS[5],
    ];
    assert_eq!(
        refusal(validate_time_module_rows(&reordered)),
        StdlibDiagnosticCode::InvalidNameClassification
    );

    let extra_rows = [
        TIME_MODULE_ROWS[0],
        TIME_MODULE_ROWS[1],
        TIME_MODULE_ROWS[2],
        TIME_MODULE_ROWS[3],
        TIME_MODULE_ROWS[4],
        TIME_MODULE_ROWS[5],
        TIME_MODULE_ROWS[5],
    ];
    assert_eq!(
        refusal(validate_time_module_rows(&extra_rows)),
        StdlibDiagnosticCode::InvalidNameClassification
    );

    let mut duplicate_surface = graph_with_rows(
        NameClass::Module,
        StabilityTier::Stable,
        &TIME_MODULE_MODES,
        &TIME_MODULE_TARGETS,
    );
    let before = duplicate_surface.clone();
    assert_eq!(
        refusal(declare_time_surface(&mut duplicate_surface)),
        StdlibDiagnosticCode::DuplicatePackage
    );
    assert_eq!(duplicate_surface, before);
}

#[test]
fn time_surface_rejects_wrong_class_tier_and_applicability() {
    let wrong_class = graph_with_rows(
        NameClass::Facade,
        StabilityTier::Stable,
        &TIME_MODULE_MODES,
        &TIME_MODULE_TARGETS,
    );
    let before = wrong_class.clone();
    assert_eq!(
        refusal(admit_time_surface(&wrong_class)),
        StdlibDiagnosticCode::InvalidNameClassification
    );
    assert_eq!(wrong_class, before);

    let wrong_tier = graph_with_rows(
        NameClass::Module,
        StabilityTier::Experimental,
        &TIME_MODULE_MODES,
        &TIME_MODULE_TARGETS,
    );
    let before = wrong_tier.clone();
    assert_eq!(
        refusal(admit_time_surface(&wrong_tier)),
        StdlibDiagnosticCode::InvalidStabilityTransition
    );
    assert_eq!(wrong_tier, before);

    let mut wrong_mode = StdGraph::new(Prelude::canonical());
    assert!(
        wrong_mode
            .declare(family_package(
                &[SemanticMode::Portable, SemanticMode::Application],
                &TIME_MODULE_TARGETS,
            ))
            .is_ok()
    );
    let before = wrong_mode.clone();
    assert_eq!(
        refusal(declare_time_surface(&mut wrong_mode)),
        StdlibDiagnosticCode::UnsupportedApplicability
    );
    assert_eq!(wrong_mode, before);

    let wrong_item_modes = graph_with_rows(
        NameClass::Module,
        StabilityTier::Stable,
        &[SemanticMode::Portable, SemanticMode::Application],
        &TIME_MODULE_TARGETS,
    );
    let before = wrong_item_modes.clone();
    assert_eq!(
        refusal(admit_time_surface(&wrong_item_modes)),
        StdlibDiagnosticCode::UnsupportedApplicability
    );
    assert_eq!(wrong_item_modes, before);

    let wrong_clauses = [
        DeclaredModuleRow {
            name: TIME_MODULE_ROWS[0].name,
            class: TIME_MODULE_ROWS[0].class,
            tier: TIME_MODULE_ROWS[0].tier,
            modes: TIME_MODULE_ROWS[0].modes,
            targets: TIME_MODULE_ROWS[0].targets,
            clauses: &[TIME_MODULE_CLAUSES[1], TIME_MODULE_CLAUSES[0]],
        },
        TIME_MODULE_ROWS[1],
        TIME_MODULE_ROWS[2],
        TIME_MODULE_ROWS[3],
        TIME_MODULE_ROWS[4],
        TIME_MODULE_ROWS[5],
    ];
    assert_eq!(
        refusal(validate_time_module_rows(&wrong_clauses)),
        StdlibDiagnosticCode::InvalidNameClassification
    );

    let mut wrong_targets = StdGraph::new(Prelude::canonical());
    assert!(
        wrong_targets
            .declare(family_package(&TIME_MODULE_MODES, &[TargetKind::Library]))
            .is_ok()
    );
    let before = wrong_targets.clone();
    assert_eq!(
        refusal(declare_time_surface(&mut wrong_targets)),
        StdlibDiagnosticCode::UnsupportedApplicability
    );
    assert_eq!(wrong_targets, before);

    let wrong_item_targets = graph_with_rows(
        NameClass::Module,
        StabilityTier::Stable,
        &TIME_MODULE_MODES,
        &[TargetKind::Library],
    );
    let before = wrong_item_targets.clone();
    assert_eq!(
        refusal(admit_time_surface(&wrong_item_targets)),
        StdlibDiagnosticCode::UnsupportedApplicability
    );
    assert_eq!(wrong_item_targets, before);
}

#[test]
fn time_non_claims_are_published_without_guarantees() {
    let specification = fs::read_to_string(workspace_root().join("SPEC.md"))
        .unwrap_or_else(|error| panic!("could not read SPEC.md: {error}"))
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    for non_claim in [
        "does not implement a clock, timer, scheduler, or timezone upgrade",
        "does not deliver typed civil ambiguity, pinned rule-data identities, or durable timer reconstruction",
        "UTC never supplies a monotonic deadline",
        "The next slice owns the injected monotonic clock and one-shot timer",
        "domain- and generation-bound deadlines",
        "readiness recheck",
        "stale-wake fencing",
        "exactly one completion or cancel winner",
        "no raw monotonic restart guarantee",
    ] {
        assert!(
            specification.contains(non_claim),
            "SPEC.md pins: {non_claim}"
        );
    }
}
