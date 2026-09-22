//! Conformance for the declared `std.fs` surface.
//!
//! The lane pins the declared filesystem clauses, the closed module-row set, and the exact
//! declaration and admission behavior of `crates/gantry-ir/src/fs.rs` over one standard-library
//! graph. It performs no host I/O and claims no path, descriptor, resource, adapter, or runtime
//! behavior.

use std::fs;
use std::path::{Path, PathBuf};

use gantry::ir::{
    FS_CLAUSES, FS_ITEMS, FS_SURFACE_MODES, FS_SURFACE_TARGETS, NameClass, PackageFamily, Prelude,
    StabilityTier, StdGraph, StdItem, StdPackage, StdlibDiagnosticCode, admit_fs_surface,
    declare_fs_surface,
};
use gantry::ir::{SemanticMode, TargetKind};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_text(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()))
}

/// Returns the text with every whitespace run collapsed to one space.
fn flatten(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Returns one declared family package of `std.fs` over the library and binary targets.
fn family_package(modes: &[SemanticMode], targets: &[TargetKind]) -> StdPackage {
    StdPackage::new(
        PackageFamily::Fs,
        NameClass::Package,
        StabilityTier::Stable,
        modes,
        targets,
        &[],
        &[],
    )
    .unwrap_or_else(|error| panic!("the family package declaration is admissible: {error:?}"))
}

#[test]
fn fs_contract_clauses_and_scope_are_published() {
    assert_eq!(
        FS_CLAUSES,
        [
            "GNT-47.0-filesystem-foundation-scope",
            "GNT-47.1-filesystem-modules-and-item-rows",
        ]
    );
    assert_eq!(FS_SURFACE_MODES, [SemanticMode::Application]);
    assert_eq!(
        FS_SURFACE_TARGETS,
        [TargetKind::Library, TargetKind::Binary]
    );

    let specification = flatten(&read_text(&workspace_root().join("SPEC.md")));
    for anchor in FS_CLAUSES {
        assert!(
            specification.contains(anchor),
            "the specification must declare {anchor}"
        );
    }
    assert!(specification.contains("the capability-backed family `std.fs`"));
    assert!(specification.contains("consumes and never restates or widens"));
}

#[test]
fn fs_module_rows_are_closed_and_canonical() {
    let names = FS_ITEMS.iter().map(|row| row.name).collect::<Vec<_>>();
    assert_eq!(
        names,
        ["std.fs::action", "std.fs::path", "std.fs::resource"]
    );
    assert_eq!(FS_ITEMS.len(), 3);
    for row in FS_ITEMS {
        assert_eq!(row.class, NameClass::Module);
        assert_eq!(row.tier, StabilityTier::Stable);
        assert_eq!(
            row.clauses,
            [
                "GNT-47.0-filesystem-foundation-scope",
                "GNT-47.1-filesystem-modules-and-item-rows",
            ]
        );
    }
}

#[test]
fn fs_surface_declaration_requires_the_family_package() {
    let mut empty = StdGraph::new(Prelude::canonical());
    assert_eq!(
        declare_fs_surface(&mut empty)
            .err()
            .map(|error| error.code()),
        Some(StdlibDiagnosticCode::UnknownEdge)
    );

    let mut graph = StdGraph::new(Prelude::canonical());
    let declared = family_package(
        &[SemanticMode::Application],
        &[TargetKind::Library, TargetKind::Binary],
    );
    assert!(graph.declare(declared).is_ok());
    assert!(declare_fs_surface(&mut graph).is_ok());

    let owner = PackageFamily::Fs.package_name();
    let package = graph
        .package(&owner)
        .unwrap_or_else(|| panic!("the family package is declared"));
    assert_eq!(package.items().len(), FS_ITEMS.len());
    let declared_order = package.items().keys().cloned().collect::<Vec<_>>();
    let row_order = FS_ITEMS
        .iter()
        .map(|row| row.name.replace("::", "."))
        .collect::<Vec<_>>();
    assert_eq!(
        declared_order, row_order,
        "the rows must follow the package's canonical name order"
    );
    for row in FS_ITEMS {
        let item = package
            .item(row.name)
            .unwrap_or_else(|| panic!("{} is declared", row.name));
        assert_eq!(item.tier(), row.tier);
        assert_eq!(item.modes(), package.modes());
        assert_eq!(item.targets(), package.targets());
    }
    assert_eq!(
        declare_fs_surface(&mut graph)
            .err()
            .map(|error| error.code()),
        Some(StdlibDiagnosticCode::DuplicatePackage),
        "a second declaration of one item is refused by the duplicate rule"
    );
}

#[test]
fn fs_surface_admission_is_closed_and_exact() {
    let mut graph = StdGraph::new(Prelude::canonical());
    assert!(
        graph
            .declare(family_package(
                &[SemanticMode::Application],
                &[TargetKind::Library, TargetKind::Binary],
            ))
            .is_ok()
    );
    assert!(declare_fs_surface(&mut graph).is_ok());
    assert!(admit_fs_surface(&graph).is_ok());

    let extra = StdItem::new(
        "std.fs::extra",
        NameClass::Module,
        StabilityTier::Stable,
        &[SemanticMode::Application],
        &[TargetKind::Library, TargetKind::Binary],
    )
    .unwrap_or_else(|error| panic!("the extra item declaration is admissible: {error:?}"));
    assert!(graph.declare_item(extra).is_ok());
    assert_eq!(
        admit_fs_surface(&graph).err().map(|error| error.code()),
        Some(StdlibDiagnosticCode::InvalidNameClassification),
        "a declared name outside the three modules is refused"
    );

    let mut mismatched = StdGraph::new(Prelude::canonical());
    assert!(
        mismatched
            .declare(family_package(
                &[SemanticMode::Application],
                &[TargetKind::Binary]
            ))
            .is_ok()
    );
    assert_eq!(
        declare_fs_surface(&mut mismatched)
            .err()
            .map(|error| error.code()),
        Some(StdlibDiagnosticCode::UnsupportedApplicability)
    );
}
