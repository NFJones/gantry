//! Conformance for the exported item rows of `std.text`, `std.num`, and `std.random`.
//!
//! `GNT-41.12-text-module-names`, `GNT-40.8-numeric-module-names`, and
//! `GNT-50.1-random-modules-and-item-rows` publish the closed module sets these rows derive from,
//! so every exported item of the three families is a derivation rather than an invention. The lane
//! requires the exact 9/7/1 row sets at the declared Module class and Stable declaration
//! compatibility, requires each row to trace to the clause that owns it in specification order,
//! requires the declaration and admission pair of each family to accept exactly that set, and
//! refuses an invented, missing, extra, duplicate, out-of-order, wrong-class, wrong-tier,
//! wrong-applicability, wrong-clause, or partial set without mutating the graph.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

use gantry::ir::{
    DeclaredModuleRow, NUM_ITEMS, NUM_MODULE_MODES, NUM_MODULE_ROWS, NUM_MODULE_TARGETS, NameClass,
    PackageFamily, Prelude, RANDOM_ITEMS, RANDOM_MODULE_MODES, RANDOM_MODULE_ROWS,
    RANDOM_MODULE_TARGETS, SemanticMode, StabilityTier, StdGraph, StdItem, StdPackage,
    StdlibDiagnosticCode, StdlibError, TEXT_ITEMS, TEXT_MODULE_MODES, TEXT_MODULE_ROWS,
    TEXT_MODULE_TARGETS, TargetKind, admit_num_surface, admit_random_surface, admit_text_surface,
    canonical_num_hierarchy, canonical_pure_hierarchy, canonical_random_hierarchy,
    canonical_std_hierarchy, canonical_text_hierarchy, declare_num_surface, declare_random_surface,
    declare_text_surface,
};

const TEXT_SCOPE: &str = "GNT-41.0-text-foundation-scope";
const TEXT_ADMISSION: &str = "GNT-41.10-canonical-text-admission-bound";
const TEXT_VALUE_BOUND: &str = "GNT-41.11-canonical-text-value-bound";
const TEXT_NAMES: &str = "GNT-41.12-text-module-names";
const NUM_SCOPE: &str = "GNT-40.0-deterministic-numeric-scope";
const NUM_NAMES: &str = "GNT-40.8-numeric-module-names";
const RANDOM_SCOPE: &str = "GNT-50.0-random-foundation-scope";
const RANDOM_NAMES: &str = "GNT-50.1-random-modules-and-item-rows";

/// The exact exported item names of `std.text`, in canonical name order.
const TEXT_EXPECTED: [&str; 9] = [
    "std.text::builders",
    "std.text::case_mapping",
    "std.text::comparison",
    "std.text::conversions",
    "std.text::graphemes",
    "std.text::matching",
    "std.text::normalization",
    "std.text::traversal",
    "std.text::values",
];

/// The exact exported item names of `std.num`, in canonical name order.
const NUM_EXPECTED: [&str; 7] = [
    "std.num::bits",
    "std.num::conversions",
    "std.num::floating",
    "std.num::integer",
    "std.num::overflow",
    "std.num::prng",
    "std.num::text",
];

/// The clause that publishes the behavior of each `std.text` item, per `GNT-41.12`.
const TEXT_OWNERS: [(&str, &str); 9] = [
    ("std.text::builders", "GNT-41.4-canonical-text-builders"),
    (
        "std.text::case_mapping",
        "GNT-41.3-canonical-text-case-mapping",
    ),
    ("std.text::comparison", "GNT-41.6-canonical-text-comparison"),
    (
        "std.text::conversions",
        "GNT-41.9-canonical-text-conversions",
    ),
    (
        "std.text::graphemes",
        "GNT-41.7-canonical-grapheme-clusters",
    ),
    ("std.text::matching", "GNT-41.8-bounded-text-matching"),
    (
        "std.text::normalization",
        "GNT-41.2-canonical-text-normalization",
    ),
    ("std.text::traversal", "GNT-41.5-canonical-text-traversal"),
    ("std.text::values", "GNT-41.1-canonical-text-values"),
];

/// The clause that publishes the behavior of each `std.num` item, per `GNT-40.8`.
const NUM_OWNERS: [(&str, &str); 7] = [
    ("std.num::bits", "GNT-40.4-integer-bit-operations"),
    ("std.num::conversions", "GNT-40.3-numeric-conversions"),
    ("std.num::floating", "GNT-40.5-finite-float-algorithms"),
    ("std.num::integer", "GNT-40.2-checked-integer-algorithms"),
    (
        "std.num::overflow",
        "GNT-40.7-canonical-integer-overflow-modes",
    ),
    ("std.num::prng", "GNT-40.1-deterministic-prng-identity"),
    ("std.num::text", "GNT-40.6-canonical-numeric-text"),
];

/// Returns the workspace root of the conformance crate.
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Reads one workspace file or fails the test with its full path.
fn read_text(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()))
}

/// Returns the body of one clause: the text between its anchor and the next anchor.
fn clause_body(specification: &str, anchor: &str) -> String {
    let declaration = format!(r#"<a id={q}{anchor}{q}></a>"#, q = char::from(34_u8));
    let start = specification
        .find(&declaration)
        .unwrap_or_else(|| panic!("the specification anchors `{anchor}`"))
        + declaration.len();
    let rest = &specification[start..];
    match rest.find("<a id=") {
        Some(end) => rest[..end].to_owned(),
        None => rest.to_owned(),
    }
}

/// Maps every declared anchor to its byte position in the specification.
fn anchor_positions(specification: &str) -> BTreeMap<&str, usize> {
    let mut positions = BTreeMap::new();
    let mut rest = specification;
    let mut offset = 0usize;
    while let Some(start) = rest.find("<a id=") {
        let after = &rest[start + "<a id=".len()..];
        let Some(after) = after.strip_prefix(char::from(34_u8)) else {
            break;
        };
        let Some(end) = after.find(char::from(34_u8)) else {
            break;
        };
        let anchor = &after[..end];
        if anchor.starts_with("GNT-") {
            positions.insert(anchor, offset + start);
        }
        let consumed = start + "<a id=".len() + 1 + end + "></a>".len() + 1;
        rest = &rest[consumed..];
        offset += consumed;
    }
    positions
}

#[test]
fn text_exported_items_are_the_nine_clause_derived_rows() {
    let specification = read_text(&workspace_root().join("SPEC.md"));
    let positions = anchor_positions(&specification);
    let naming = clause_body(&specification, TEXT_NAMES);

    assert_eq!(
        TEXT_ITEMS, TEXT_MODULE_ROWS,
        "each exported text row derives from the naming vocabulary"
    );
    assert_eq!(
        TEXT_ITEMS.len(),
        9,
        "the declared text item set is closed at nine rows"
    );
    assert_eq!(TEXT_ITEMS.map(|row| row.name), TEXT_EXPECTED);
    for (index, row) in TEXT_ITEMS.iter().enumerate() {
        assert!(
            TEXT_ITEMS[..index]
                .iter()
                .all(|earlier| earlier.name != row.name),
            "`{}` is declared once",
            row.name
        );
    }
    for row in TEXT_ITEMS {
        let owner_clause = TEXT_OWNERS
            .iter()
            .find(|(item, _)| *item == row.name)
            .map(|(_, clause)| *clause)
            .unwrap_or_else(|| panic!("`{}` is one of the adopted text item names", row.name));
        let mut expected = vec![TEXT_SCOPE, owner_clause];
        if matches!(row.name, "std.text::values" | "std.text::conversions") {
            expected.push(TEXT_ADMISSION);
        }
        expected.push(TEXT_VALUE_BOUND);
        expected.push(TEXT_NAMES);
        assert_eq!(
            row.clauses,
            expected.as_slice(),
            "`{}` binds exactly its declared clauses in specification order",
            row.name
        );
        assert_eq!(row.class, NameClass::Module, "`{}` is a module", row.name);
        assert_eq!(
            row.tier,
            StabilityTier::Stable,
            "`{}` declares stable namespace compatibility",
            row.name
        );
        assert_eq!(
            row.modes, TEXT_MODULE_MODES,
            "`{}` keeps the declared text modes",
            row.name
        );
        assert_eq!(
            row.targets, TEXT_MODULE_TARGETS,
            "`{}` keeps the declared text targets",
            row.name
        );
        assert!(
            naming.contains(&format!("`{}`", row.name)),
            "the owning naming clause declares `{}`",
            row.name
        );
        let mut prior = 0usize;
        for clause in row.clauses {
            let position = positions
                .get(clause)
                .unwrap_or_else(|| panic!("the specification anchors `{clause}`"));
            assert!(
                *position > prior,
                "the clauses of `{}` are stored in specification order",
                row.name
            );
            prior = *position;
        }
    }
}

#[test]
fn numeric_exported_items_are_the_seven_clause_derived_rows() {
    let specification = read_text(&workspace_root().join("SPEC.md"));
    let positions = anchor_positions(&specification);
    let naming = clause_body(&specification, NUM_NAMES);

    assert_eq!(
        NUM_ITEMS, NUM_MODULE_ROWS,
        "each exported numeric row derives from the naming vocabulary"
    );
    assert_eq!(
        NUM_ITEMS.len(),
        7,
        "the declared numeric item set is closed at seven rows"
    );
    assert_eq!(NUM_ITEMS.map(|row| row.name), NUM_EXPECTED);
    for (index, row) in NUM_ITEMS.iter().enumerate() {
        assert!(
            NUM_ITEMS[..index]
                .iter()
                .all(|earlier| earlier.name != row.name),
            "`{}` is declared once",
            row.name
        );
    }
    for row in NUM_ITEMS {
        let owner_clause = NUM_OWNERS
            .iter()
            .find(|(item, _)| *item == row.name)
            .map(|(_, clause)| *clause)
            .unwrap_or_else(|| panic!("`{}` is one of the adopted numeric item names", row.name));
        assert_eq!(
            row.clauses,
            [NUM_SCOPE, owner_clause, NUM_NAMES],
            "`{}` binds the numeric scope, its behavior clause, and the naming clause in order",
            row.name
        );
        assert_eq!(row.class, NameClass::Module, "`{}` is a module", row.name);
        assert_eq!(
            row.tier,
            StabilityTier::Stable,
            "`{}` declares stable namespace compatibility",
            row.name
        );
        assert_eq!(
            row.modes, NUM_MODULE_MODES,
            "`{}` keeps the declared numeric modes",
            row.name
        );
        assert_eq!(
            row.targets, NUM_MODULE_TARGETS,
            "`{}` keeps the declared numeric targets",
            row.name
        );
        assert!(
            naming.contains(&format!("`{}`", row.name)),
            "the owning naming clause declares `{}`",
            row.name
        );
        let mut prior = 0usize;
        for clause in row.clauses {
            let position = positions
                .get(clause)
                .unwrap_or_else(|| panic!("the specification anchors `{clause}`"));
            assert!(
                *position > prior,
                "the clauses of `{}` are stored in specification order",
                row.name
            );
            prior = *position;
        }
    }
}

#[test]
fn random_exported_item_is_the_application_only_capability_row() {
    let specification = read_text(&workspace_root().join("SPEC.md"));
    let positions = anchor_positions(&specification);
    let naming = clause_body(&specification, RANDOM_NAMES);

    assert_eq!(RANDOM_ITEMS, RANDOM_MODULE_ROWS);
    let [row] = RANDOM_ITEMS;
    assert_eq!(row.name, "std.random::entropy");
    assert_eq!(row.clauses, [RANDOM_SCOPE, RANDOM_NAMES]);
    assert_eq!(row.class, NameClass::Module);
    assert_eq!(row.tier, StabilityTier::Stable);
    assert_eq!(row.modes, RANDOM_MODULE_MODES);
    assert_eq!(
        row.modes,
        [SemanticMode::Application],
        "std.random keeps the application mode only"
    );
    assert_eq!(row.targets, RANDOM_MODULE_TARGETS);
    assert!(
        naming.contains(&format!("`{}`", row.name)),
        "the owning naming clause declares `{}`",
        row.name
    );
    let scope = positions
        .get(RANDOM_SCOPE)
        .unwrap_or_else(|| panic!("the specification anchors `{RANDOM_SCOPE}`"));
    let rows = positions
        .get(RANDOM_NAMES)
        .unwrap_or_else(|| panic!("the specification anchors `{RANDOM_NAMES}`"));
    assert!(scope < rows, "the random scope precedes its row clause");
}

/// One canonical family hierarchy constructor of this lane.
type FamilyConstructor = fn() -> Result<StdGraph, StdlibError>;

/// Returns one empty graph over the canonical edition prelude.
fn empty_graph() -> StdGraph {
    StdGraph::new(Prelude::canonical())
}

/// Returns one test-only family package with the given applicability.
fn family_package(
    family: PackageFamily,
    modes: &[SemanticMode],
    targets: &[TargetKind],
) -> StdPackage {
    StdPackage::new(
        family,
        NameClass::Package,
        StabilityTier::Stable,
        modes,
        targets,
        &[],
        &[],
    )
    .unwrap_or_else(|error| panic!("the test-only package is valid: {error:?}"))
}

/// Returns one test-only family package that also exports one canonical path.
fn family_package_with_exports(
    family: PackageFamily,
    modes: &[SemanticMode],
    targets: &[TargetKind],
    exports: &[&str],
) -> StdPackage {
    StdPackage::new(
        family,
        NameClass::Package,
        StabilityTier::Stable,
        modes,
        targets,
        &[],
        exports,
    )
    .unwrap_or_else(|error| panic!("the test-only exporting package is valid: {error:?}"))
}

/// Returns one declared row as a graph item with explicit metadata.
fn item(
    row: DeclaredModuleRow,
    class: NameClass,
    tier: StabilityTier,
    modes: &[SemanticMode],
    targets: &[TargetKind],
) -> StdItem {
    StdItem::new(row.name, class, tier, modes, targets)
        .unwrap_or_else(|error| panic!("the test-only item is valid: {error:?}"))
}

/// Declares one test-only package or fails the test.
fn declare_package(graph: &mut StdGraph, package: StdPackage) {
    graph
        .declare(package)
        .unwrap_or_else(|error| panic!("the test-only package declares: {error:?}"));
}

/// Declares one test-only item or fails the test.
fn declare_row(graph: &mut StdGraph, item: StdItem) {
    graph
        .declare_item(item)
        .unwrap_or_else(|error| panic!("the test-only item declares: {error:?}"));
}

/// Returns the refusal code of one surface decision, or none when it succeeded.
fn code(result: Result<(), StdlibError>) -> Option<StdlibDiagnosticCode> {
    result.err().map(|error| error.code())
}

/// Proves that one family surface accepts exactly its clause rows and refuses every deviation.
fn assert_surface_refusals(
    declare: fn(&mut StdGraph) -> Result<(), StdlibError>,
    admit: fn(&StdGraph) -> Result<(), StdlibError>,
    rows: &[DeclaredModuleRow],
    family: PackageFamily,
    modes: &[SemanticMode],
    targets: &[TargetKind],
) {
    let owner = family.package_name();
    let invented = format!("{owner}::invented");

    let mut undeclared = empty_graph();
    let snapshot = undeclared.clone();
    assert_eq!(
        code(declare(&mut undeclared)),
        Some(StdlibDiagnosticCode::UnknownEdge),
        "an undeclared family package is refused"
    );
    assert_eq!(
        undeclared, snapshot,
        "an undeclared refusal mutates nothing"
    );
    assert_eq!(
        code(admit(&undeclared)),
        Some(StdlibDiagnosticCode::UnknownEdge)
    );

    let mut graph = empty_graph();
    declare_package(&mut graph, family_package(family, modes, targets));
    assert_eq!(code(declare(&mut graph)), None);
    let package = graph
        .package(&owner)
        .unwrap_or_else(|| panic!("`{owner}` is declared"));
    assert_eq!(
        package.items().len(),
        rows.len(),
        "`{owner}` declares exactly its declared item set"
    );
    let names = rows
        .iter()
        .map(|row| row.name.replace("::", "."))
        .collect::<Vec<_>>();
    assert_eq!(package.items().keys().cloned().collect::<Vec<_>>(), names);
    for row in rows {
        let declared = package
            .item(row.name)
            .unwrap_or_else(|| panic!("`{}` is declared", row.name));
        assert_eq!(declared.owner(), owner.as_str());
        assert_eq!(declared.class(), row.class);
        assert_eq!(declared.tier(), row.tier);
        assert_eq!(
            declared.modes().iter().copied().collect::<Vec<_>>(),
            row.modes.to_vec(),
            "`{}` carries its declared modes",
            row.name
        );
        assert_eq!(
            declared.targets().iter().copied().collect::<Vec<_>>(),
            row.targets.to_vec(),
            "`{}` carries its declared targets",
            row.name
        );
    }
    assert_eq!(code(admit(&graph)), None);

    let snapshot = graph.clone();
    assert_eq!(
        code(declare(&mut graph)),
        Some(StdlibDiagnosticCode::DuplicatePackage),
        "a second declaration is refused"
    );
    assert_eq!(graph, snapshot, "a duplicate refusal mutates nothing");

    if rows.len() > 1 {
        let mut partial = empty_graph();
        declare_package(&mut partial, family_package(family, modes, targets));
        let first = rows[0];
        declare_row(
            &mut partial,
            item(first, first.class, first.tier, first.modes, first.targets),
        );
        let snapshot = partial.clone();
        assert_eq!(
            code(declare(&mut partial)),
            Some(StdlibDiagnosticCode::InvalidNameClassification),
            "a partial item set is refused"
        );
        assert_eq!(partial, snapshot, "a partial refusal mutates nothing");
        assert_eq!(
            code(admit(&partial)),
            Some(StdlibDiagnosticCode::InvalidNameClassification)
        );
    }

    let mut extra = graph.clone();
    declare_row(
        &mut extra,
        StdItem::new(
            &invented,
            NameClass::Module,
            StabilityTier::Stable,
            modes,
            targets,
        )
        .unwrap_or_else(|error| panic!("the invented test item is valid: {error:?}")),
    );
    let snapshot = extra.clone();
    assert_eq!(
        code(admit(&extra)),
        Some(StdlibDiagnosticCode::InvalidNameClassification),
        "an invented item is refused"
    );
    assert_eq!(extra, snapshot, "an invented-item refusal mutates nothing");

    let mut exported = empty_graph();
    declare_package(
        &mut exported,
        family_package_with_exports(family, modes, targets, &[&invented]),
    );
    let snapshot = exported.clone();
    assert_eq!(
        code(declare(&mut exported)),
        Some(StdlibDiagnosticCode::InvalidNameClassification),
        "an export outside the declared modules is refused"
    );
    assert_eq!(exported, snapshot, "an export refusal mutates nothing");

    let mut wrong_modes = empty_graph();
    declare_package(
        &mut wrong_modes,
        family_package(family, &[SemanticMode::Durable], targets),
    );
    let snapshot = wrong_modes.clone();
    assert_eq!(
        code(declare(&mut wrong_modes)),
        Some(StdlibDiagnosticCode::UnsupportedApplicability),
        "a package with another mode set is refused"
    );
    assert_eq!(wrong_modes, snapshot, "a mode refusal mutates nothing");

    let mut wrong_targets = empty_graph();
    declare_package(
        &mut wrong_targets,
        family_package(family, modes, &[TargetKind::Test]),
    );
    let snapshot = wrong_targets.clone();
    assert_eq!(
        code(declare(&mut wrong_targets)),
        Some(StdlibDiagnosticCode::UnsupportedApplicability),
        "a package with another target set is refused"
    );
    assert_eq!(wrong_targets, snapshot, "a target refusal mutates nothing");

    let mut wrong_class = empty_graph();
    declare_package(&mut wrong_class, family_package(family, modes, targets));
    for row in rows {
        declare_row(
            &mut wrong_class,
            item(*row, NameClass::Facade, row.tier, row.modes, row.targets),
        );
    }
    let snapshot = wrong_class.clone();
    assert_eq!(
        code(declare(&mut wrong_class)),
        Some(StdlibDiagnosticCode::InvalidNameClassification),
        "a row outside the declared class is refused"
    );
    assert_eq!(wrong_class, snapshot, "a class refusal mutates nothing");

    let mut wrong_tier = empty_graph();
    declare_package(&mut wrong_tier, family_package(family, modes, targets));
    for row in rows {
        declare_row(
            &mut wrong_tier,
            item(
                *row,
                row.class,
                StabilityTier::Experimental,
                row.modes,
                row.targets,
            ),
        );
    }
    let snapshot = wrong_tier.clone();
    assert_eq!(
        code(declare(&mut wrong_tier)),
        Some(StdlibDiagnosticCode::InvalidStabilityTransition),
        "a row outside the declared tier is refused"
    );
    assert_eq!(wrong_tier, snapshot, "a tier refusal mutates nothing");

    let mut wrong_row_modes = empty_graph();
    declare_package(&mut wrong_row_modes, family_package(family, modes, targets));
    for row in rows {
        declare_row(
            &mut wrong_row_modes,
            item(
                *row,
                row.class,
                row.tier,
                &[SemanticMode::Durable],
                row.targets,
            ),
        );
    }
    let snapshot = wrong_row_modes.clone();
    assert_eq!(
        code(declare(&mut wrong_row_modes)),
        Some(StdlibDiagnosticCode::UnsupportedApplicability),
        "a row outside the declared modes is refused"
    );
    assert_eq!(
        wrong_row_modes, snapshot,
        "a row-mode refusal mutates nothing"
    );

    let mut wrong_row_targets = empty_graph();
    declare_package(
        &mut wrong_row_targets,
        family_package(family, modes, targets),
    );
    for row in rows {
        declare_row(
            &mut wrong_row_targets,
            item(*row, row.class, row.tier, row.modes, &[TargetKind::Test]),
        );
    }
    let snapshot = wrong_row_targets.clone();
    assert_eq!(
        code(declare(&mut wrong_row_targets)),
        Some(StdlibDiagnosticCode::UnsupportedApplicability),
        "a row outside the declared targets is refused"
    );
    assert_eq!(
        wrong_row_targets, snapshot,
        "a row-target refusal mutates nothing"
    );
}

#[test]
fn every_family_surface_is_closed_over_its_clause_rows() {
    assert_surface_refusals(
        declare_text_surface,
        admit_text_surface,
        &TEXT_ITEMS,
        PackageFamily::Text,
        &TEXT_MODULE_MODES,
        &TEXT_MODULE_TARGETS,
    );
    assert_surface_refusals(
        declare_num_surface,
        admit_num_surface,
        &NUM_ITEMS,
        PackageFamily::Num,
        &NUM_MODULE_MODES,
        &NUM_MODULE_TARGETS,
    );
    assert_surface_refusals(
        declare_random_surface,
        admit_random_surface,
        &RANDOM_ITEMS,
        PackageFamily::Random,
        &RANDOM_MODULE_MODES,
        &RANDOM_MODULE_TARGETS,
    );
}

#[test]
fn aggregate_hierarchy_composes_the_family_item_rows() {
    let aggregate = canonical_std_hierarchy()
        .unwrap_or_else(|error| panic!("the aggregate hierarchy is declared: {error:?}"));
    assert!(
        aggregate.validate().is_ok(),
        "the composed aggregate hierarchy is valid"
    );
    let order = aggregate
        .topological_order()
        .unwrap_or_else(|error| panic!("the aggregate graph orders: {error:?}"));
    assert!(
        order.iter().any(|name| name == "std.random"),
        "the aggregate graph carries the capability family"
    );

    let text = aggregate
        .package("std.text")
        .unwrap_or_else(|| panic!("`std.text` is declared"));
    assert_eq!(
        text.items().keys().cloned().collect::<Vec<_>>(),
        TEXT_ITEMS
            .iter()
            .map(|row| row.name.replace("::", "."))
            .collect::<Vec<_>>(),
        "the aggregate declares each text item row"
    );
    let numeric = aggregate
        .package("std.num")
        .unwrap_or_else(|| panic!("`std.num` is declared"));
    assert_eq!(
        numeric.items().keys().cloned().collect::<Vec<_>>(),
        NUM_ITEMS
            .iter()
            .map(|row| row.name.replace("::", "."))
            .collect::<Vec<_>>(),
        "the aggregate declares each numeric item row"
    );
    for package in [text, numeric] {
        for item in package.items().values() {
            assert_eq!(
                item.owner(),
                package.name(),
                "`{}` is owned by its declaring package",
                item.name()
            );
        }
    }

    let random = aggregate
        .package("std.random")
        .unwrap_or_else(|| panic!("`std.random` is declared"));
    assert!(
        random.dependencies().is_empty(),
        "`std.random` declares no pure dependency edge"
    );
    assert_eq!(
        random.modes().iter().copied().collect::<Vec<_>>(),
        vec![SemanticMode::Application],
        "`std.random` stays application-only"
    );
    assert_eq!(
        random.targets().iter().copied().collect::<Vec<_>>(),
        RANDOM_MODULE_TARGETS.to_vec()
    );
    assert_eq!(random.items().len(), RANDOM_ITEMS.len());
    assert!(
        random.item("std.random::entropy").is_some(),
        "`std.random::entropy` is declared as an item"
    );
    for name in aggregate.package_names() {
        let package = aggregate
            .package(name)
            .unwrap_or_else(|| panic!("`{name}` is declared"));
        assert!(
            !package
                .dependencies()
                .iter()
                .any(|dependency| dependency == "std.random"),
            "`{name}` declares no edge to the capability family"
        );
    }
}

#[test]
fn family_constructors_republish_item_derived_interface_digests() {
    let pure = canonical_pure_hierarchy()
        .unwrap_or_else(|error| panic!("the canonical pure hierarchy is declared: {error:?}"));
    let builders: [(&str, FamilyConstructor); 2] = [
        ("std.text", canonical_text_hierarchy),
        ("std.num", canonical_num_hierarchy),
    ];
    for (name, build) in builders {
        let family = build().unwrap_or_else(|error| panic!("`{name}` declares: {error:?}"));
        let decorated = family
            .package(name)
            .unwrap_or_else(|| panic!("`{name}` is declared in its family hierarchy"));
        let plain = pure
            .package(name)
            .unwrap_or_else(|| panic!("`{name}` is declared in the pure hierarchy"));
        assert!(!decorated.items().is_empty());
        assert!(
            plain.items().is_empty(),
            "`{name}` carries its item rows in the family constructor only"
        );
        assert_ne!(
            decorated.identity().as_str(),
            plain.identity().as_str(),
            "`{name}` republishes an item-derived interface digest"
        );
    }

    let random = canonical_random_hierarchy()
        .unwrap_or_else(|error| panic!("the random family hierarchy is declared: {error:?}"));
    assert!(
        random.package("std.random").is_some(),
        "the random family constructor declares its package"
    );
    assert!(
        pure.package("std.random").is_none(),
        "the pure hierarchy declares no capability family"
    );
    assert!(
        admit_random_surface(&random).is_ok(),
        "the random family constructor admits its own item surface"
    );
}

#[test]
fn item_rows_add_no_prelude_member_and_no_capability_edge() {
    let pure = canonical_pure_hierarchy()
        .unwrap_or_else(|error| panic!("the canonical pure hierarchy is declared: {error:?}"));
    assert_eq!(
        pure.package_names(),
        vec![
            "std.codec",
            "std.collections",
            "std.core",
            "std.crypto",
            "std.data",
            "std.num",
            "std.text",
        ],
        "the pure dependency DAG keeps its declared packages"
    );
    assert!(
        pure.package("std.random").is_none(),
        "the capability family stays outside the pure dependency DAG"
    );
    let aggregate = canonical_std_hierarchy()
        .unwrap_or_else(|error| panic!("the aggregate hierarchy is declared: {error:?}"));
    let members = aggregate.prelude().members();
    for row in TEXT_ITEMS
        .iter()
        .chain(NUM_ITEMS.iter())
        .chain(RANDOM_ITEMS.iter())
    {
        assert!(
            !members.contains(&row.name.replace("::", ".")),
            "`{}` is not an edition prelude member",
            row.name
        );
    }
}

#[test]
fn hierarchy_catalog_records_each_item_row_and_interface_digest() {
    let document = read_text(&workspace_root().join("protocol/catalogs/stdlib-hierarchy-v1.json"));
    let catalog: Value = serde_json::from_str(&document)
        .unwrap_or_else(|error| panic!("the hierarchy catalog is JSON: {error}"));
    let aggregate = canonical_std_hierarchy()
        .unwrap_or_else(|error| panic!("the aggregate hierarchy is declared: {error:?}"));
    let entries = catalog["packages"]
        .as_array()
        .unwrap_or_else(|| panic!("the catalog publishes its packages as an array"));
    assert_eq!(
        entries.len(),
        aggregate.package_names().len(),
        "the catalog lists every aggregate package"
    );
    for entry in entries {
        let name = entry["name"]
            .as_str()
            .unwrap_or_else(|| panic!("every catalog entry names itself"));
        let package = aggregate
            .package(name)
            .unwrap_or_else(|| panic!("`{name}` is declared in the aggregate"));
        assert_eq!(
            entry["interface_digest"],
            Value::from(package.identity().as_str()),
            "`{name}` publishes its item-derived interface digest"
        );
        let declared = entry["items"]
            .as_array()
            .unwrap_or_else(|| panic!("`{name}` publishes its items as an array"));
        assert_eq!(
            declared.len(),
            package.items().len(),
            "`{name}` records every declared item"
        );
        for item in package.items().values() {
            let record = declared
                .iter()
                .find(|record| record["name"].as_str() == Some(item.name()))
                .unwrap_or_else(|| panic!("`{name}` records the item `{}`", item.name()));
            assert_eq!(
                record["class"],
                Value::from(item.class().wire_name()),
                "`{}` publishes its class",
                item.name()
            );
            assert_eq!(
                record["tier"],
                Value::from(item.tier().wire_name()),
                "`{}` publishes its tier",
                item.name()
            );
            let modes = item
                .modes()
                .iter()
                .map(|mode| mode.wire_name())
                .collect::<Vec<_>>();
            assert_eq!(
                record["modes"]
                    .as_array()
                    .map(|modes| modes.iter().filter_map(Value::as_str).collect::<Vec<_>>()),
                Some(modes),
                "`{}` publishes its modes",
                item.name()
            );
            let targets = item
                .targets()
                .iter()
                .map(|target| target.wire_name())
                .collect::<Vec<_>>();
            assert_eq!(
                record["targets"]
                    .as_array()
                    .map(|targets| targets.iter().filter_map(Value::as_str).collect::<Vec<_>>()),
                Some(targets),
                "`{}` publishes its targets",
                item.name()
            );
        }
    }
    for (name, expected) in [("std.text", 9_usize), ("std.num", 7), ("std.random", 1)] {
        let entry = entries
            .iter()
            .find(|entry| entry["name"].as_str() == Some(name))
            .unwrap_or_else(|| panic!("the catalog records `{name}`"));
        assert_eq!(
            entry["items"].as_array().map(Vec::len),
            Some(expected),
            "`{name}` records exactly its declared item rows"
        );
    }
}
