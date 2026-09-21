//! Public conformance for the bounded pattern matching of `GNT-41.8-bounded-text-matching`, whose
//! pure model is `crates/gantry-ir/src/text.rs`.

use std::fs;
use std::path::{Path, PathBuf};

use gantry::ir::{
    PATTERN_INSTRUCTION_BOUND, PATTERN_REPEAT_BOUND, PATTERN_SCALAR_BOUND, PATTERN_STEP_BOUND,
    Pattern, TEXT_CLAUSES, TextDiagnosticCode, TextError, TextValue,
};

/// The declared clauses of Section 41, written out independently of the model.
const EXPECTED_CLAUSES: [&str; 12] = [
    "GNT-41.0-text-foundation-scope",
    "GNT-41.1-canonical-text-values",
    "GNT-41.2-canonical-text-normalization",
    "GNT-41.3-canonical-text-case-mapping",
    "GNT-41.4-canonical-text-builders",
    "GNT-41.5-canonical-text-traversal",
    "GNT-41.6-canonical-text-comparison",
    "GNT-41.7-canonical-grapheme-clusters",
    "GNT-41.8-bounded-text-matching",
    "GNT-41.9-canonical-text-conversions",
    "GNT-41.10-canonical-text-admission-bound",
    "GNT-41.11-canonical-text-value-bound",
];
const MATCHING_CLAUSE: &str = "GNT-41.8-bounded-text-matching";

#[test]
fn matching_clause_publishes_the_bounded_pattern_surface() {
    let specification = read_workspace_file("SPEC.md");
    assert_eq!(TEXT_CLAUSES, EXPECTED_CLAUSES);
    let body = clause_body(&specification, MATCHING_CLAUSE);
    for declaration in [
        "`admit` publishes a pattern from a pattern text value and a declared step budget",
        "`is_match` publishes whether some scalar span of a text value matches",
        "`find_first` publishes the leftmost-longest matching span or nothing when no span matches",
        "`TextRange` publishes a matched span as the inclusive start and exclusive end",
        "`PATTERN_SCALAR_BOUND` bounds the scalars a pattern may hold",
        "`PATTERN_REPEAT_BOUND` bounds the count a bounded repetition may state",
        "`PATTERN_INSTRUCTION_BOUND` bounds the compiled program",
        "`PATTERN_STEP_BOUND` bounds the declared step budget a pattern may be admitted with",
    ] {
        assert!(
            body.contains(declaration),
            "the clause declares `{declaration}`"
        );
    }
    for citation in [
        "`GNT-41.1-canonical-text-values`",
        "`text-pattern-syntax`",
        "`text-pattern-bound`",
        "`text-match-budget`",
    ] {
        assert!(body.contains(citation), "the clause cites {citation}");
    }
    assert_eq!(
        TextDiagnosticCode::ALL.map(|code| code.owning_clause()),
        [
            "GNT-41.1-canonical-text-values",
            "GNT-41.4-canonical-text-builders",
            MATCHING_CLAUSE,
            MATCHING_CLAUSE,
            MATCHING_CLAUSE,
            "GNT-41.11-canonical-text-value-bound",
            "GNT-41.9-canonical-text-conversions",
        ],
    );
    assert_eq!(
        TextDiagnosticCode::ALL
            .iter()
            .filter(|code| code.owning_clause() == MATCHING_CLAUSE)
            .count(),
        3
    );
}

#[test]
fn matching_admits_and_refuses_patterns_exactly() {
    for pattern in [
        "(", "a)", "*a", "[a", "[]", "[z-a]", "a{3,2}", "\\d", "a{,2}", "^", "$", "a$",
    ] {
        let error = refusal(
            Pattern::admit(&admitted(pattern.as_bytes()), 64),
            TextDiagnosticCode::PatternSyntax,
        );
        assert!(
            error.detail().contains("scalar position"),
            "the syntax refusal names the scalar position: {}",
            error.detail()
        );
    }
    let oversized = admitted(vec![b'a'; PATTERN_SCALAR_BOUND + 1].as_slice());
    refusal(
        Pattern::admit(&oversized, 64),
        TextDiagnosticCode::PatternBound,
    );
    refusal(
        Pattern::admit(
            &admitted(format!("a{{{}}}", PATTERN_REPEAT_BOUND + 1).as_bytes()),
            64,
        ),
        TextDiagnosticCode::PatternBound,
    );
    refusal(
        Pattern::admit(&admitted(b"a"), 0),
        TextDiagnosticCode::PatternBound,
    );
    let pattern = Pattern::admit(&admitted(b"a(b|c)*d"), 512)
        .unwrap_or_else(|error| panic!("the hand-written pattern is admitted: {error}"));
    assert_eq!(pattern.steps(), 512);
    assert_eq!(
        (
            PATTERN_SCALAR_BOUND,
            PATTERN_REPEAT_BOUND,
            PATTERN_INSTRUCTION_BOUND,
        ),
        (4096, 255, 16_384),
        "the declared bounds are published exactly"
    );
    assert!(PATTERN_INSTRUCTION_BOUND > PATTERN_REPEAT_BOUND as usize);
    assert!(
        PATTERN_STEP_BOUND > PATTERN_INSTRUCTION_BOUND as u32,
        "the declared maximum step budget exceeds the declared program bound"
    );
    let maximum = Pattern::admit(&admitted(b"a"), PATTERN_STEP_BOUND);
    assert!(
        maximum.is_ok(),
        "the declared maximum step budget is admitted"
    );
    let beyond = Pattern::admit(&admitted(b"a"), PATTERN_STEP_BOUND + 1);
    let error = beyond
        .err()
        .unwrap_or_else(|| panic!("a step budget beyond the declared maximum is refused"));
    assert_eq!(error.code(), TextDiagnosticCode::PatternBound);
    assert_eq!(
        error.detail(),
        format!(
            "the declared step budget {} is beyond the declared maximum budget {PATTERN_STEP_BOUND}",
            PATTERN_STEP_BOUND + 1
        ),
        "the refusal names the observed budget and the declared maximum"
    );
    // A bounded repetition over a bounded repetition stays refused without being expanded.
    let nested = format!(
        "(a{{{}}}){{{}}}",
        PATTERN_REPEAT_BOUND, PATTERN_REPEAT_BOUND
    );
    refusal(
        Pattern::admit(&admitted(nested.as_bytes()), 64),
        TextDiagnosticCode::PatternBound,
    );
    let deeper = format!("((a{{{0}}}){{{0}}}){{{0}}}", PATTERN_REPEAT_BOUND);
    refusal(
        Pattern::admit(&admitted(deeper.as_bytes()), 64),
        TextDiagnosticCode::PatternBound,
    );
    // A program exactly at the declared instruction bound is admitted, and one instruction over
    // it is refused: `(a{255}){64}` holds 16,320 instructions, 60 literals and `a*` hold 63, and
    // the final match instruction holds one.
    let at_bound = format!("(a{{{}}}){{64}}{}a*", PATTERN_REPEAT_BOUND, "a".repeat(60));
    let admitted_at_bound = Pattern::admit(&admitted(at_bound.as_bytes()), 64)
        .unwrap_or_else(|error| panic!("a program exactly at the bound is admitted: {error}"));
    assert_eq!(admitted_at_bound.steps(), 64);
    let over_bound = format!("(a{{{}}}){{64}}{}a*", PATTERN_REPEAT_BOUND, "a".repeat(61));
    refusal(
        Pattern::admit(&admitted(over_bound.as_bytes()), 64),
        TextDiagnosticCode::PatternBound,
    );
}

#[test]
fn matching_decides_literals_classes_and_quantifiers() {
    let cases = [
        ("a", "a", Some((0, 1))),
        ("abc", "xabcx", Some((1, 4))),
        ("a.c", "abc", Some((0, 3))),
        (".", "é", Some((0, 1))),
        ("[abc]+", "zzabcc", Some((2, 6))),
        ("[^abc]+", "abxyz", Some((2, 5))),
        ("[a-c]x", "zzbx", Some((2, 4))),
        ("a|bc", "zbc", Some((1, 3))),
        ("(ab)+", "abab!", Some((0, 4))),
        ("a{2}", "aa", Some((0, 2))),
        ("a{2,3}", "aaaa", Some((0, 3))),
        ("a{2,}", "aaa", Some((0, 3))),
        ("a?", "b", Some((0, 0))),
        ("\\*", "*", Some((0, 1))),
        ("\\^", "^", Some((0, 1))),
        ("é+", "xéé", Some((1, 3))),
        ("z", "aaa", None),
    ];
    for (pattern, text, expected) in cases {
        let compiled = pattern_of(pattern, 4096);
        let value = admitted(text.as_bytes());
        let span = compiled
            .find_first(&value)
            .unwrap_or_else(|error| panic!("`{pattern}` matches `{text}` within budget: {error}"))
            .map(|span| (span.start(), span.end()));
        assert_eq!(span, expected, "`{pattern}` on `{text}`");
        let matched = compiled
            .is_match(&value)
            .unwrap_or_else(|error| panic!("`{pattern}` decides within budget: {error}"));
        assert_eq!(
            matched,
            expected.is_some(),
            "`is_match` agrees with `find_first` for `{pattern}`"
        );
    }
}

#[test]
fn matching_publishes_the_leftmost_longest_span() {
    let value = admitted(b"abab");
    let pattern = pattern_of("a|ab", 4096);
    let span = pattern
        .find_first(&value)
        .unwrap_or_else(|error| panic!("the pattern matches within budget: {error}"))
        .unwrap_or_else(|| panic!("the pattern matches"));
    assert_eq!(
        (span.start(), span.end()),
        (0, 2),
        "the longest match at the leftmost start wins"
    );
    assert_eq!(
        span.slice(&value)
            .unwrap_or_else(|| panic!("the span is a scalar-boundary range"))
            .canonical_octets(),
        b"ab"
    );
    let later = pattern_of("b", 4096);
    let span = later
        .find_first(&value)
        .unwrap_or_else(|error| panic!("the pattern matches within budget: {error}"))
        .unwrap_or_else(|| panic!("the pattern matches"));
    assert_eq!((span.start(), span.end()), (1, 2));
    assert!(!span.is_empty());
}

#[test]
fn matching_refuses_a_budget_exhausting_match() {
    let value = admitted(b"aaaab");
    let tight = pattern_of("a+b", 4);
    let error = refusal(tight.find_first(&value), TextDiagnosticCode::MatchBudget);
    assert!(error.detail().contains("step budget"), "{}", error.detail());
    refusal(tight.is_match(&value), TextDiagnosticCode::MatchBudget);
    let roomy = pattern_of("a+b", 64);
    let span = roomy
        .find_first(&value)
        .unwrap_or_else(|error| panic!("the declared budget suffices: {error}"))
        .unwrap_or_else(|| panic!("the pattern matches"));
    assert_eq!((span.start(), span.end()), (0, 5));
    assert_eq!(
        roomy
            .find_first(&value)
            .unwrap_or_else(|error| panic!("the declared budget suffices: {error}")),
        Some(span),
        "the same call publishes the same span"
    );
}

#[test]
fn matching_is_observation_only_and_deterministic() {
    let value = admitted("aé".as_bytes());
    let recorded = value.canonical_octets().to_vec();
    let pattern = pattern_of("é", 256);
    let span = pattern
        .find_first(&value)
        .unwrap_or_else(|error| panic!("the pattern matches within budget: {error}"))
        .unwrap_or_else(|| panic!("the pattern matches"));
    assert_eq!((span.start(), span.end()), (1, 2));
    assert_eq!(
        span.slice(&value)
            .unwrap_or_else(|| panic!("the span is a scalar-boundary range"))
            .canonical_octets(),
        "é".as_bytes()
    );
    assert_eq!(value.canonical_octets(), recorded.as_slice());
    assert_eq!(
        pattern
            .find_first(&value)
            .unwrap_or_else(|error| panic!("the pattern matches within budget: {error}")),
        Some(span)
    );
    let unmatched = pattern_of("z", 256);
    assert_eq!(
        unmatched
            .find_first(&value)
            .unwrap_or_else(|error| panic!("an unmatched text is decided within budget: {error}")),
        None
    );
    assert!(
        !unmatched
            .is_match(&value)
            .unwrap_or_else(|error| panic!("an unmatched text is decided within budget: {error}"))
    );
}

fn pattern_of(pattern: &str, steps: u32) -> Pattern {
    Pattern::admit(&admitted(pattern.as_bytes()), steps)
        .unwrap_or_else(|error| panic!("`{pattern}` is admitted: {error}"))
}

fn admitted(octets: &[u8]) -> TextValue {
    TextValue::from_octets(octets)
        .unwrap_or_else(|error| panic!("`{octets:?}` is admitted: {error}"))
}

fn refusal<T>(result: Result<T, TextError>, code: TextDiagnosticCode) -> TextError {
    match result {
        Ok(_) => panic!("the call is refused under `{}`", code.spelling()),
        Err(error) => {
            assert_eq!(
                error.code(),
                code,
                "the refusal is reported under `{}`: {}",
                code.spelling(),
                error.detail()
            );
            error
        }
    }
}

/// Returns the body of one clause: the text between its anchor and the next anchor, or to the end
/// of the specification when the clause is the final one.
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

fn read_workspace_file(relative: &str) -> String {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative);
    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("`{}` is readable: {error}", path.display()))
}
