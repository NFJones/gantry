//! Conformance for the declared `std.fs` surface.
//!
//! The lane pins the declared filesystem clauses, the closed module-row set, and the exact
//! declaration and admission behavior of `crates/gantry-ir/src/fs.rs` over one standard-library
//! graph. It performs no host I/O and claims no path, descriptor, resource, adapter, or runtime
//! behavior.

use std::fs;
use std::path::{Path, PathBuf};

use gantry::ir::{
    FS_CLAUSES, FS_ITEMS, FS_PATH_SEGMENT_BOUND, FS_SURFACE_MODES, FS_SURFACE_TARGETS,
    FsDiagnosticCode, FsPath, NameClass, PackageFamily, Prelude, StabilityTier, StdGraph, StdItem,
    StdPackage, StdlibDiagnosticCode, admit_fs_surface, declare_fs_surface,
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
            "GNT-47.2-filesystem-path-values",
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
    assert!(
        specification.contains(
            "The frozen diagnostics of this section are `fs-path-invalid` and `fs-path-escape`"
        ),
        "the section must publish its frozen diagnostic registry"
    );
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
        let expected: &[&str] = match row.name {
            "std.fs::path" => &[
                "GNT-47.0-filesystem-foundation-scope",
                "GNT-47.1-filesystem-modules-and-item-rows",
                "GNT-47.2-filesystem-path-values",
            ],
            _ => &[
                "GNT-47.0-filesystem-foundation-scope",
                "GNT-47.1-filesystem-modules-and-item-rows",
            ],
        };
        assert_eq!(row.clauses, expected);
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

    // A partially declared surface is refused rather than completed or repaired.
    let mut partial = StdGraph::new(Prelude::canonical());
    assert!(
        partial
            .declare(family_package(
                &[SemanticMode::Application],
                &[TargetKind::Library, TargetKind::Binary],
            ))
            .is_ok()
    );
    let single = StdItem::new(
        "std.fs::action",
        NameClass::Module,
        StabilityTier::Stable,
        &[SemanticMode::Application],
        &[TargetKind::Library, TargetKind::Binary],
    )
    .unwrap_or_else(|error| panic!("the single-row declaration is admissible: {error:?}"));
    assert!(partial.declare_item(single).is_ok());
    assert_eq!(
        admit_fs_surface(&partial).err().map(|error| error.code()),
        Some(StdlibDiagnosticCode::InvalidNameClassification),
        "a partially declared surface is refused"
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

#[test]
fn fs_path_values_are_bounded_and_escape_free() {
    assert_eq!(
        FsDiagnosticCode::ALL,
        [FsDiagnosticCode::PathEscape, FsDiagnosticCode::PathInvalid]
    );
    assert_eq!(FsDiagnosticCode::PathEscape.as_str(), "fs-path-escape");
    assert_eq!(FsDiagnosticCode::PathInvalid.as_str(), "fs-path-invalid");
    assert_eq!(FS_PATH_SEGMENT_BOUND, 256);

    let path = FsPath::rooted("workspace", &["logs", "today.txt"])
        .unwrap_or_else(|error| panic!("the declared path is admissible: {error}"));
    assert_eq!(path.root(), "workspace");
    let segments = path
        .segments()
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    assert_eq!(segments, ["logs", "today.txt"]);
    assert_eq!(path.canonical_spelling(), "workspace/logs/today.txt");
    let joined = path
        .join(&["extra"])
        .unwrap_or_else(|error| panic!("the declared join is admissible: {error}"));
    assert_eq!(
        joined.canonical_spelling(),
        "workspace/logs/today.txt/extra"
    );
    assert_eq!(
        joined.root(),
        "workspace",
        "a join never changes the declared root"
    );

    // Reserved components are refused rather than normalized, collapsed, or resolved.
    for (declared, component, position) in [
        (vec![".."], "..", 0_u32),
        (vec!["logs", ".."], "..", 1),
        (vec!["."], ".", 0),
    ] {
        let error = FsPath::rooted("workspace", &declared)
            .err()
            .unwrap_or_else(|| panic!("the reserved component {component} must be refused"));
        assert_eq!(error.code(), FsDiagnosticCode::PathEscape);
        assert_eq!(error.component(), Some(component));
        assert_eq!(error.position(), position);
    }
    let error = path
        .join(&[".."])
        .err()
        .unwrap_or_else(|| panic!("a reserved component in a join must be refused"));
    assert_eq!(error.code(), FsDiagnosticCode::PathEscape);
    assert_eq!(error.position(), 2, "a join reports the joined position");

    // Malformed declarations are refused instead of being repaired or defaulted.
    for (root, declared) in [
        ("", vec!["a"]),
        ("/absolute", vec!["a"]),
        ("work/space", vec!["a"]),
        ("~home", vec!["a"]),
        ("$HOME", vec!["a"]),
        ("workspace", Vec::new()),
        ("workspace", vec![""]),
        ("workspace", vec!["a/b"]),
        ("workspace", vec!["a\u{7}b"]),
    ] {
        let error = FsPath::rooted(root, &declared)
            .err()
            .unwrap_or_else(|| panic!("the declared ({root}, {declared:?}) must be refused"));
        assert_eq!(error.code(), FsDiagnosticCode::PathInvalid);
        assert_eq!(error.component(), None);
    }

    // The declared segment bound is enforced rather than truncated.
    let admitted = vec!["segment"; FS_PATH_SEGMENT_BOUND];
    assert!(FsPath::rooted("workspace", &admitted).is_ok());
    let mut beyond = admitted;
    beyond.push("segment");
    let error = FsPath::rooted("workspace", &beyond)
        .err()
        .unwrap_or_else(|| panic!("a segment count beyond the bound must be refused"));
    assert_eq!(error.code(), FsDiagnosticCode::PathInvalid);
    assert!(
        error.detail().contains("257"),
        "the refusal names the declared count: {}",
        error.detail()
    );

    let specification = flatten(&read_text(&workspace_root().join("SPEC.md")));
    for anchor in FS_CLAUSES {
        assert!(
            specification.contains(anchor),
            "the specification must declare {anchor}"
        );
    }
    for rule in [
        "a path spelling is never authority",
        "at most `FS_PATH_SEGMENT_BOUND` segments",
        "refused under `fs-path-escape` naming the reserved component and its position",
        "refused under `fs-path-invalid` naming the segment and its position",
    ] {
        assert!(
            specification.contains(rule),
            "the specification must pin: {rule}"
        );
    }
}
