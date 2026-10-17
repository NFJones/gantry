//! Conformance for the declared `std.text`, `std.num`, and `std.random` module names.
//!
//! `GNT-41.12-text-module-names` and `GNT-40.8-numeric-module-names` own the closed module sets of
//! their pure families, and `GNT-50.0-random-foundation-scope` with
//! `GNT-50.1-random-modules-and-item-rows` owns the capability-backed `std.random` module name. The
//! lane requires every adopted name to trace to its declared owning clause in specification order,
//! requires the declared sets to be closed, and refuses a missing, extra, duplicate, out-of-order,
//! wrong-class, wrong-tier, wrong-applicability, or wrong-clause candidate without mutating it. It
//! also proves that an invented or duplicated name is refused rather than admitted.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use gantry::ir::{
    DeclaredModuleRow, ModuleSetRefusal, NUM_MODULE_CLAUSES, NUM_MODULE_ROWS, NameClass,
    RANDOM_MODULE_CLAUSES, RANDOM_MODULE_ROWS, SemanticMode, StabilityTier, TEXT_MODULE_CLAUSES,
    TEXT_MODULE_ROWS, TargetKind, admit_declared_modules,
};

const TEXT_SCOPE: &str = "GNT-41.0-text-foundation-scope";
const TEXT_ADMISSION: &str = "GNT-41.10-canonical-text-admission-bound";
const TEXT_VALUE_BOUND: &str = "GNT-41.11-canonical-text-value-bound";
const TEXT_NAMES: &str = "GNT-41.12-text-module-names";
const NUM_SCOPE: &str = "GNT-40.0-deterministic-numeric-scope";
const NUM_NAMES: &str = "GNT-40.8-numeric-module-names";
const RANDOM_SCOPE: &str = "GNT-50.0-random-foundation-scope";
const RANDOM_NAMES: &str = "GNT-50.1-random-modules-and-item-rows";

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_text(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()))
}

/// Returns the body of one clause: the text between its anchor and the next anchor.
fn clause_body<'a>(specification: &'a str, anchor: &str) -> &'a str {
    let declaration = format!("<a id=\"{anchor}\"></a>");
    let start = specification
        .find(&declaration)
        .unwrap_or_else(|| panic!("the specification anchors `{anchor}`"))
        + declaration.len();
    let rest = &specification[start..];
    match rest.find("<a id=") {
        Some(end) => &rest[..end],
        None => rest,
    }
}

/// Maps every declared anchor to its byte position in the specification.
fn anchor_positions(specification: &str) -> BTreeMap<&str, usize> {
    let mut positions = BTreeMap::new();
    let mut rest = specification;
    let mut offset = 0usize;
    while let Some(start) = rest.find("<a id=\"") {
        let after = &rest[start + "<a id=\"".len()..];
        let Some(end) = after.find("\"></a>") else {
            break;
        };
        let anchor = &after[..end];
        if anchor.starts_with("GNT-") {
            positions.insert(anchor, offset + start);
        }
        let consumed = start + "<a id=\"".len() + end + "\"></a>".len();
        rest = &rest[consumed..];
        offset += consumed;
    }
    positions
}

/// The clause that publishes the behavior of each `std.text` module, per `GNT-41.12`.
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

/// The clause that publishes the behavior of each `std.num` module, per `GNT-40.8`.
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

fn owner<'a>(owners: &'a [(&'a str, &'a str)], name: &str) -> &'a str {
    owners
        .iter()
        .find(|(module, _)| *module == name)
        .map(|(_, clause)| *clause)
        .unwrap_or_else(|| panic!("`{name}` is one of the adopted module names"))
}

#[test]
fn text_module_names_trace_to_their_owning_clauses_in_specification_order() {
    let specification = read_text(&workspace_root().join("SPEC.md"));
    let positions = anchor_positions(&specification);

    assert_eq!(TEXT_MODULE_CLAUSES, [TEXT_SCOPE, TEXT_NAMES]);
    assert_eq!(
        TEXT_MODULE_ROWS.map(|row| row.name),
        TEXT_OWNERS.map(|(name, _)| name),
        "the rows are exactly the nine adopted names in canonical name order"
    );
    for row in TEXT_MODULE_ROWS {
        let owner = owner(&TEXT_OWNERS, row.name);
        let mut expected = vec![TEXT_SCOPE, owner];
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
            row.modes,
            [SemanticMode::Portable, SemanticMode::Application],
            "`{}` keeps the portable and application modes",
            row.name
        );
        assert_eq!(
            row.targets,
            [TargetKind::Library, TargetKind::Binary],
            "`{}` keeps the library and binary targets",
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
    let clause = clause_body(&specification, TEXT_NAMES);
    for (name, _) in TEXT_OWNERS {
        assert!(
            clause.contains(&format!("`{name}`")),
            "the naming clause declares `{name}`"
        );
    }
}

#[test]
fn numeric_module_names_trace_to_their_owning_clauses_in_specification_order() {
    let specification = read_text(&workspace_root().join("SPEC.md"));
    let positions = anchor_positions(&specification);

    assert_eq!(NUM_MODULE_CLAUSES, [NUM_SCOPE, NUM_NAMES]);
    assert_eq!(
        NUM_MODULE_ROWS.map(|row| row.name),
        NUM_OWNERS.map(|(name, _)| name),
        "the rows are exactly the seven adopted names in canonical name order"
    );
    for row in NUM_MODULE_ROWS {
        let owner = owner(&NUM_OWNERS, row.name);
        assert_eq!(
            row.clauses,
            [NUM_SCOPE, owner, NUM_NAMES],
            "`{}` binds the numeric scope, its behavior clause, and the naming clause in order",
            row.name
        );
        assert_eq!(row.class, NameClass::Module, "`{}` is a module", row.name);
        assert_eq!(row.tier, StabilityTier::Stable, "`{}` is stable", row.name);
        assert_eq!(
            row.modes,
            [SemanticMode::Portable, SemanticMode::Application],
            "`{}` keeps the portable and application modes",
            row.name
        );
        assert_eq!(
            row.targets,
            [TargetKind::Library, TargetKind::Binary],
            "`{}` keeps the library and binary targets",
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
    let clause = clause_body(&specification, NUM_NAMES);
    for (name, _) in NUM_OWNERS {
        assert!(
            clause.contains(&format!("`{name}`")),
            "the naming clause declares `{name}`"
        );
    }
}

#[test]
fn random_module_name_is_owned_by_its_own_scope_and_row_clauses() {
    let specification = read_text(&workspace_root().join("SPEC.md"));
    let positions = anchor_positions(&specification);

    assert_eq!(RANDOM_MODULE_CLAUSES, [RANDOM_SCOPE, RANDOM_NAMES]);
    let [row] = RANDOM_MODULE_ROWS;
    assert_eq!(row.name, "std.random::entropy");
    assert_eq!(row.clauses, [RANDOM_SCOPE, RANDOM_NAMES]);
    assert_eq!(row.class, NameClass::Module);
    assert_eq!(row.tier, StabilityTier::Stable);
    assert_eq!(
        row.modes,
        [SemanticMode::Application],
        "std.random is application-only"
    );
    assert_eq!(row.targets, [TargetKind::Library, TargetKind::Binary]);
    let scope = positions
        .get(RANDOM_SCOPE)
        .unwrap_or_else(|| panic!("the specification anchors `{RANDOM_SCOPE}`"));
    let naming = positions
        .get(RANDOM_NAMES)
        .unwrap_or_else(|| panic!("the specification anchors `{RANDOM_NAMES}`"));
    assert!(scope < naming, "the random scope precedes its row clause");

    assert!(clause_body(&specification, RANDOM_NAMES).contains("`std.random::entropy`"));
    for unrelated in [
        "GNT-34.1-canonical-hierarchy-and-package-names",
        "GNT-29.8-time-randomness-and-secret-contracts",
    ] {
        assert!(
            !clause_body(&specification, unrelated).contains("std.random::entropy"),
            "`{unrelated}` must not own the entropy module name"
        );
    }
}

fn assert_closed_set_refusals(expected: &[DeclaredModuleRow]) {
    assert_eq!(admit_declared_modules(expected, expected), Ok(()));

    let mut missing = expected.to_vec();
    missing.remove(0);
    let snapshot = missing.clone();
    assert_eq!(
        admit_declared_modules(&missing, expected),
        Err(ModuleSetRefusal::Missing)
    );
    assert_eq!(missing, snapshot, "a missing-row refusal mutates nothing");

    let mut extra = expected.to_vec();
    let mut invented = expected[0];
    invented.name = "std.text::invented";
    extra.push(invented);
    let snapshot = extra.clone();
    assert_eq!(
        admit_declared_modules(&extra, expected),
        Err(ModuleSetRefusal::Unexpected)
    );
    assert_eq!(extra, snapshot, "an extra-row refusal mutates nothing");

    let mut duplicate = expected.to_vec();
    duplicate.push(expected[0]);
    let snapshot = duplicate.clone();
    assert_eq!(
        admit_declared_modules(&duplicate, expected),
        Err(ModuleSetRefusal::Duplicate)
    );
    assert_eq!(
        duplicate, snapshot,
        "a duplicate-row refusal mutates nothing"
    );

    if expected.len() > 1 {
        let mut reordered = expected.to_vec();
        reordered.swap(0, 1);
        let snapshot = reordered.clone();
        assert_eq!(
            admit_declared_modules(&reordered, expected),
            Err(ModuleSetRefusal::OutOfOrder)
        );
        assert_eq!(reordered, snapshot, "an order refusal mutates nothing");
    }

    let mut wrong_class = expected.to_vec();
    wrong_class[0].class = NameClass::Package;
    let snapshot = wrong_class.clone();
    assert_eq!(
        admit_declared_modules(&wrong_class, expected),
        Err(ModuleSetRefusal::WrongClass)
    );
    assert_eq!(wrong_class, snapshot, "a class refusal mutates nothing");

    let mut wrong_tier = expected.to_vec();
    wrong_tier[0].tier = StabilityTier::Experimental;
    let snapshot = wrong_tier.clone();
    assert_eq!(
        admit_declared_modules(&wrong_tier, expected),
        Err(ModuleSetRefusal::WrongTier)
    );
    assert_eq!(wrong_tier, snapshot, "a tier refusal mutates nothing");

    let mut wrong_applicability = expected.to_vec();
    wrong_applicability[0].modes = &[SemanticMode::Durable];
    let snapshot = wrong_applicability.clone();
    assert_eq!(
        admit_declared_modules(&wrong_applicability, expected),
        Err(ModuleSetRefusal::WrongApplicability)
    );
    assert_eq!(
        wrong_applicability, snapshot,
        "an applicability refusal mutates nothing"
    );

    let mut wrong_clauses = expected.to_vec();
    wrong_clauses[0].clauses = &["GNT-41.12-text-module-names"];
    let snapshot = wrong_clauses.clone();
    assert_eq!(
        admit_declared_modules(&wrong_clauses, expected),
        Err(ModuleSetRefusal::WrongClauses)
    );
    assert_eq!(wrong_clauses, snapshot, "a clause refusal mutates nothing");
}

#[test]
fn every_declared_family_set_is_closed_and_refuses_without_mutation() {
    assert_closed_set_refusals(&TEXT_MODULE_ROWS);
    assert_closed_set_refusals(&NUM_MODULE_ROWS);
    assert_closed_set_refusals(&RANDOM_MODULE_ROWS);
}

#[test]
fn invented_and_duplicated_names_are_refused() {
    for expected in [TEXT_MODULE_ROWS.as_slice(), NUM_MODULE_ROWS.as_slice()] {
        let mut invented = expected.to_vec();
        let mut row = expected[0];
        row.name = "std.text::invented";
        invented.push(row);
        assert_eq!(
            admit_declared_modules(&invented, expected),
            Err(ModuleSetRefusal::Unexpected),
            "a name no clause declares is refused"
        );
        assert!(expected.iter().all(|declared| declared.name != row.name));

        let mut duplicated = expected.to_vec();
        duplicated.push(expected[0]);
        assert_eq!(
            admit_declared_modules(&duplicated, expected),
            Err(ModuleSetRefusal::Duplicate),
            "a duplicated name is refused"
        );
    }
}
