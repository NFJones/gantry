//! Public conformance for the declared size and work limits of
//! `GNT-41.10-text-work-limits`, whose pure model is `crates/gantry-ir/src/text.rs`.

use std::fs;
use std::path::{Path, PathBuf};

use gantry::ir::{
    CASE_MAPPING_UNITS_PER_SCALAR, COMPARISON_UNITS_PER_SCALAR, CaseMapping, CharValue,
    GRAPHEME_UNITS_PER_SCALAR, NORMALIZATION_UNITS_PER_SCALAR, NormalizationForm, TEXT_CLAUSES,
    TEXT_VALUE_SCALAR_BOUND, TEXT_WORK_UNIT_MAXIMUM, TextDiagnosticCode, TextValue,
};

const LIMITS_CLAUSE: &str = "GNT-41.10-text-work-limits";

fn read_workspace_file(relative: &str) -> String {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative);
    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("`{}` is readable: {error}", path.display()))
}

/// Returns the body of one clause: the paragraph that names its anchor.
fn clause_body(specification: &str, anchor: &str) -> String {
    let heading = format!("**[{anchor}]");
    specification
        .lines()
        .find(|line| line.contains(&heading))
        .unwrap_or_else(|| panic!("the specification declares `{anchor}`"))
        .to_owned()
}

fn admitted(octets: &[u8]) -> TextValue {
    TextValue::from_octets(octets)
        .unwrap_or_else(|error| panic!("the sequence is admitted: {error}"))
}

/// A value of exactly the declared value bound: the largest value this section admits.
fn maximum_value() -> TextValue {
    let octets = vec![b'a'; TEXT_VALUE_SCALAR_BOUND];
    admitted(&octets)
}

#[test]
fn declared_limits_are_published_and_exact() {
    let specification = read_workspace_file("SPEC.md");
    assert!(TEXT_CLAUSES.contains(&LIMITS_CLAUSE));
    assert_eq!(
        TEXT_CLAUSES.len(),
        11,
        "the section declares eleven clauses"
    );
    assert_eq!(
        TextDiagnosticCode::ValueBound.spelling(),
        "text-value-bound"
    );
    assert_eq!(
        TextDiagnosticCode::ValueBound.owning_clause(),
        LIMITS_CLAUSE
    );
    let body = clause_body(&specification, LIMITS_CLAUSE);
    for declaration in [
        "`TEXT_VALUE_SCALAR_BOUND`",
        "`NORMALIZATION_UNITS_PER_SCALAR`",
        "`CASE_MAPPING_UNITS_PER_SCALAR`",
        "`COMPARISON_UNITS_PER_SCALAR`",
        "`GRAPHEME_UNITS_PER_SCALAR`",
        "`TEXT_WORK_UNIT_MAXIMUM`",
        "`text-value-bound`",
    ] {
        assert!(
            body.contains(declaration),
            "the clause states the declared limit {declaration}"
        );
    }
    let largest = [
        NORMALIZATION_UNITS_PER_SCALAR,
        CASE_MAPPING_UNITS_PER_SCALAR,
        COMPARISON_UNITS_PER_SCALAR,
        GRAPHEME_UNITS_PER_SCALAR,
    ]
    .into_iter()
    .max()
    .unwrap_or_else(|| panic!("the section declares per-scalar unit bounds"));
    assert_eq!(
        TEXT_WORK_UNIT_MAXIMUM,
        TEXT_VALUE_SCALAR_BOUND as u64 * largest,
        "the declared maximum work is the value bound times the largest per-scalar bound"
    );
    for bound in [
        NORMALIZATION_UNITS_PER_SCALAR,
        CASE_MAPPING_UNITS_PER_SCALAR,
        COMPARISON_UNITS_PER_SCALAR,
        GRAPHEME_UNITS_PER_SCALAR,
    ] {
        assert!(bound > 0, "every declared per-scalar bound is positive");
    }
}

#[test]
fn admissions_admit_exactly_the_declared_value_bound() {
    let octets = vec![b'a'; TEXT_VALUE_SCALAR_BOUND];
    assert_eq!(admitted(&octets).scalar_count(), TEXT_VALUE_SCALAR_BOUND);
    let mut beyond = octets.clone();
    beyond.push(b'a');
    for (label, error) in [
        (
            "an octet sequence one scalar beyond the bound",
            TextValue::from_octets(&beyond).err(),
        ),
        (
            "a scalar sequence one scalar beyond the bound",
            TextValue::from_scalars(&vec![scalar("a"); TEXT_VALUE_SCALAR_BOUND + 1]).err(),
        ),
        (
            "a code-unit sequence one scalar beyond the bound",
            TextValue::from_utf16_code_units(&vec![0x0061_u16; TEXT_VALUE_SCALAR_BOUND + 1]).err(),
        ),
        (
            "a lossless octet sequence one scalar beyond the bound",
            TextValue::from_lossless_octets(&beyond).err(),
        ),
    ] {
        let error = error.unwrap_or_else(|| panic!("{label} is refused"));
        assert_eq!(error.code(), TextDiagnosticCode::ValueBound, "{label}");
        let detail = error.detail();
        assert!(
            detail.contains(&(TEXT_VALUE_SCALAR_BOUND + 1).to_string())
                && detail.contains(&TEXT_VALUE_SCALAR_BOUND.to_string()),
            "{label} names the observed scalar count and the declared bound: {detail}"
        );
    }
}

#[test]
fn every_kernel_completes_over_a_maximum_size_value() {
    let value = maximum_value();
    assert_eq!(value.scalar_count(), TEXT_VALUE_SCALAR_BOUND);
    let mut scalars = value.scalars();
    let mut published = 0_usize;
    while scalars.next_scalar().is_some() {
        published += 1;
    }
    assert_eq!(published, TEXT_VALUE_SCALAR_BOUND, "traversal is exact");
    assert_eq!(
        value.slice_scalars(0, TEXT_VALUE_SCALAR_BOUND),
        Some(value.clone()),
        "slicing is exact at the declared value bound"
    );
    let mut clusters = value.graphemes();
    let mut segmented = 0_usize;
    while clusters.next_cluster().is_some() {
        segmented += 1;
    }
    assert_eq!(segmented, TEXT_VALUE_SCALAR_BOUND, "segmentation is exact");
    let normalized = value.normalize(NormalizationForm::Nfc);
    assert_eq!(normalized, value, "normalization is idempotent here");
    let mapped = value.map_case(CaseMapping::Lower);
    assert_eq!(mapped, value, "case mapping keeps an unchanged value");
    assert_eq!(
        value.compare(&maximum_value()),
        gantry::ir::TextOrdering::Equal
    );
    assert_eq!(value.utf16_code_units().len(), TEXT_VALUE_SCALAR_BOUND);
    assert_eq!(
        value.lossless_octets().map(|octets| octets.len()),
        Some(TEXT_VALUE_SCALAR_BOUND)
    );
}

fn scalar(text: &str) -> CharValue {
    let value = text
        .chars()
        .next()
        .unwrap_or_else(|| panic!("the fixture names one scalar"));
    CharValue::new(u32::from(value))
        .unwrap_or_else(|error| panic!("the fixture names one admitted scalar: {error}"))
}
