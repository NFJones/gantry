//! Conformance for the declaration-only `std.env` package surface.
//!
//! This lane covers module identity and applicability only; it performs no process access,
//! environment mutation, directory lookup, credential handling, or host I/O.

use std::fs;
use std::path::{Path, PathBuf};

use gantry::ir::{
    ENV_CLAUSES, ENV_ITEMS, ENV_SURFACE_MODES, ENV_SURFACE_TARGETS, EnvItemRow, NameClass,
    PackageFamily, Prelude, SemanticMode, StabilityTier, StdGraph, StdItem, StdPackage,
    StdlibDiagnosticCode, TargetKind, admit_env_surface, declare_env_surface,
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
    StdPackage::new(
        PackageFamily::Env,
        NameClass::Package,
        StabilityTier::Stable,
        modes,
        targets,
        &[],
        exports,
    )
    .unwrap_or_else(|error| panic!("the std.env package declaration is valid: {error:?}"))
}

#[test]
fn env_scope_is_declared_without_runtime_or_authority_claims() {
    assert_eq!(
        ENV_CLAUSES,
        [
            "GNT-49.0-environment-foundation-scope",
            "GNT-49.1-environment-modules-and-item-rows",
        ]
    );
    assert_eq!(ENV_SURFACE_MODES, [SemanticMode::Application]);
    assert_eq!(
        ENV_SURFACE_TARGETS,
        [TargetKind::Library, TargetKind::Binary]
    );

    let specification = fs::read_to_string(workspace_root().join("SPEC.md"))
        .unwrap_or_else(|error| panic!("could not read SPEC.md: {error}"))
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    for clause in ENV_CLAUSES {
        assert!(specification.contains(clause), "SPEC.md declares {clause}");
    }
    for rule in [
        "declaration surface of the capability-backed `std.env` family",
        "bounded immutable arguments and environment snapshots",
        "Logical working-directory data is not directory authority",
        "does not read or mutate ambient process state",
    ] {
        assert!(specification.contains(rule), "SPEC.md pins: {rule}");
    }
    let _row_type_witness: Option<EnvItemRow> = None;
}

/// The reader note must preserve the distinction between declaration and executable authority.
#[test]
fn env_reader_note_preserves_declaration_and_qualification_boundaries() {
    let note = fs::read_to_string(workspace_root().join("docs/env-foundation.md"))
        .unwrap_or_else(|error| panic!("could not read environment note: {error}"))
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    for anchor in ENV_CLAUSES {
        assert!(note.contains(anchor), "reader note names {anchor}");
    }
    for row in ENV_ITEMS {
        assert!(note.contains(row.name), "reader note names {}", row.name);
    }
    for boundary in [
        "application mode over library and binary targets",
        "Logical working-directory data is not directory authority",
        "Declaring a module grants no capability",
        "It provides no credential access and no durable native handle",
        "declaration coverage is not evidence that they work",
        "Passing these lanes does not qualify a specification revision",
    ] {
        assert!(note.contains(boundary), "reader note retains {boundary}");
    }
}

#[test]
fn env_module_rows_are_closed_and_canonical() {
    assert_eq!(
        ENV_ITEMS.map(|row| row.name),
        [
            "std.env::arguments",
            "std.env::environment",
            "std.env::working_directory",
        ]
    );
    for row in ENV_ITEMS {
        assert_eq!(row.class, NameClass::Module);
        assert_eq!(row.tier, StabilityTier::Stable);
        assert_eq!(
            row.clauses,
            &[
                "GNT-49.0-environment-foundation-scope",
                "GNT-49.1-environment-modules-and-item-rows",
            ]
        );
    }
}

#[test]
fn env_surface_declaration_requires_package_and_admits_exact_rows() {
    let mut empty = StdGraph::new(Prelude::canonical());
    assert_eq!(
        declare_env_surface(&mut empty)
            .err()
            .map(|error| error.code()),
        Some(StdlibDiagnosticCode::UnknownEdge)
    );

    let mut graph = StdGraph::new(Prelude::canonical());
    assert!(
        graph
            .declare(family_package(&ENV_SURFACE_MODES, &ENV_SURFACE_TARGETS))
            .is_ok()
    );
    assert!(declare_env_surface(&mut graph).is_ok());
    assert!(admit_env_surface(&graph).is_ok());
    let package = graph
        .package("std.env")
        .unwrap_or_else(|| panic!("the family package is declared"));
    assert_eq!(package.items().len(), ENV_ITEMS.len());
    assert_eq!(
        package
            .items()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        [
            "std.env.arguments",
            "std.env.environment",
            "std.env.working_directory",
        ]
    );
}

#[test]
fn env_surface_rejects_extra_partial_and_mismatched_declarations() {
    let mut extra_export = StdGraph::new(Prelude::canonical());
    let package = family_package_with_exports(
        &ENV_SURFACE_MODES,
        &ENV_SURFACE_TARGETS,
        &["std.env::extra"],
    );
    assert!(package.exports_item("std.env::extra"));
    assert!(extra_export.declare(package).is_ok());
    assert_eq!(
        declare_env_surface(&mut extra_export)
            .err()
            .map(|error| error.code()),
        Some(StdlibDiagnosticCode::InvalidNameClassification)
    );

    let mut extra_export_with_rows = StdGraph::new(Prelude::canonical());
    let package = family_package_with_exports(
        &ENV_SURFACE_MODES,
        &ENV_SURFACE_TARGETS,
        &["std.env::extra"],
    );
    assert!(extra_export_with_rows.declare(package).is_ok());
    for row in ENV_ITEMS {
        let item = StdItem::new(
            row.name,
            row.class,
            row.tier,
            &ENV_SURFACE_MODES,
            &ENV_SURFACE_TARGETS,
        )
        .unwrap_or_else(|error| panic!("the declared env row is valid: {error:?}"));
        assert!(extra_export_with_rows.declare_item(item).is_ok());
    }
    assert_eq!(
        admit_env_surface(&extra_export_with_rows)
            .err()
            .map(|error| error.code()),
        Some(StdlibDiagnosticCode::InvalidNameClassification)
    );

    let mut extra = StdGraph::new(Prelude::canonical());
    assert!(
        extra
            .declare(family_package(&ENV_SURFACE_MODES, &ENV_SURFACE_TARGETS))
            .is_ok()
    );
    assert!(declare_env_surface(&mut extra).is_ok());
    let extra_item = StdItem::new(
        "std.env::extra",
        NameClass::Module,
        StabilityTier::Stable,
        &ENV_SURFACE_MODES,
        &ENV_SURFACE_TARGETS,
    )
    .unwrap_or_else(|error| panic!("the test-only extra item is valid: {error:?}"));
    assert!(extra.declare_item(extra_item).is_ok());
    assert_eq!(
        admit_env_surface(&extra).err().map(|error| error.code()),
        Some(StdlibDiagnosticCode::InvalidNameClassification)
    );

    let mut partial = StdGraph::new(Prelude::canonical());
    assert!(
        partial
            .declare(family_package(&ENV_SURFACE_MODES, &ENV_SURFACE_TARGETS))
            .is_ok()
    );
    let row = ENV_ITEMS[0];
    assert!(
        partial
            .declare_item(
                StdItem::new(
                    row.name,
                    row.class,
                    row.tier,
                    &ENV_SURFACE_MODES,
                    &ENV_SURFACE_TARGETS,
                )
                .unwrap_or_else(|error| panic!("the test row is valid: {error:?}")),
            )
            .is_ok()
    );
    let before = partial.clone();
    assert_eq!(
        declare_env_surface(&mut partial)
            .err()
            .map(|error| error.code()),
        Some(StdlibDiagnosticCode::InvalidNameClassification)
    );
    assert_eq!(partial, before);
    assert_eq!(
        admit_env_surface(&partial).err().map(|error| error.code()),
        Some(StdlibDiagnosticCode::InvalidNameClassification)
    );

    let mut wrong_mode = StdGraph::new(Prelude::canonical());
    assert!(
        wrong_mode
            .declare(family_package(
                &[SemanticMode::Portable, SemanticMode::Application],
                &ENV_SURFACE_TARGETS,
            ))
            .is_ok()
    );
    assert_eq!(
        declare_env_surface(&mut wrong_mode)
            .err()
            .map(|error| error.code()),
        Some(StdlibDiagnosticCode::UnsupportedApplicability)
    );
}
