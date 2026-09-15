//! Section 35 scalar and binary foundation evidence.

use std::cmp::Ordering;

use gantry::ir::{
    ByteBufferValue, ByteValue, BytesValue, CharValue, IntegerValue, OverflowMode, SCALAR_CLAUSES,
    ScalarDiagnosticCode, ScalarKind, ScalarNonClaimAssertion, ScalarNonClaimName, ScalarQuota,
    ScalarWidth, StorageStrategy, check_scalar_non_claims,
};

/// Returns the refusal produced by one rejected scalar decision.
trait Refused<E> {
    fn refused(self, context: &str) -> E;
}

impl<T, E> Refused<E> for Result<T, E> {
    fn refused(self, context: &str) -> E {
        match self {
            Ok(_) => panic!("{context}: the decision must be refused"),
            Err(error) => error,
        }
    }
}

const I8: ScalarKind = ScalarKind::Signed(ScalarWidth::W8);
const U8: ScalarKind = ScalarKind::Unsigned(ScalarWidth::W8);
const U64: ScalarKind = ScalarKind::Unsigned(ScalarWidth::W64);

fn value(kind: ScalarKind, text: &str) -> IntegerValue {
    IntegerValue::parse(kind, text).unwrap_or_else(|error| panic!("canonical literal: {error}"))
}

#[test]
fn widths_carry_their_declared_bits_and_octets() {
    assert_eq!(ScalarWidth::ALL.map(ScalarWidth::bits), [8, 16, 32, 64]);
    assert_eq!(ScalarWidth::ALL.map(ScalarWidth::octets), [1, 2, 4, 8]);
    assert_eq!(ScalarKind::ALL.len(), 13);
}

#[test]
fn kinds_are_distinct_and_never_admits_no_value() {
    let names: Vec<&str> = ScalarKind::ALL
        .iter()
        .map(|kind| kind.canonical_name())
        .collect();
    for (index, name) in names.iter().enumerate() {
        assert!(!names[index + 1..].contains(name), "{name} is duplicated");
    }
    assert!(!ScalarKind::Never.is_value());
    assert_eq!(ScalarKind::Never.canonical_encoding(), None);
    let refusal = IntegerValue::parse(ScalarKind::Never, "0").refused("Never admits no value");
    assert_eq!(refusal.code(), ScalarDiagnosticCode::NeverConstructed);
}

#[test]
fn canonical_literals_round_trip_and_deviations_are_refused() {
    for text in ["0", "7", "-1", "-128", "127"] {
        assert_eq!(value(I8, text).to_canonical_string(), text);
    }
    assert_eq!(
        value(U64, "18446744073709551615").to_canonical_string(),
        "18446744073709551615"
    );
    for text in ["", "+1", "007", "-0", " 1", "1 ", "0x1"] {
        let refusal = IntegerValue::parse(I8, text).refused("non-canonical text");
        assert_eq!(
            refusal.code(),
            ScalarDiagnosticCode::InvalidLiteral,
            "{text}"
        );
    }
    assert_eq!(
        IntegerValue::parse(U8, "-1").refused("unsigned").code(),
        ScalarDiagnosticCode::InvalidLiteral
    );
}

#[test]
fn declared_ranges_are_exact_per_width() {
    assert_eq!(IntegerValue::bounds(I8), Some((-128, 127)));
    assert_eq!(IntegerValue::bounds(U8), Some((0, 255)));
    assert_eq!(IntegerValue::bounds(U64), Some((0, i128::from(u64::MAX))));
    assert_eq!(
        IntegerValue::parse(I8, "128").refused("overflow").code(),
        ScalarDiagnosticCode::InvalidLiteral
    );
    assert_eq!(
        IntegerValue::new(I8, 128).refused("overflow").code(),
        ScalarDiagnosticCode::OverflowRefused
    );
}

#[test]
fn overflow_modes_refuse_wrap_and_saturate() {
    let high = value(I8, "100");
    let one = value(I8, "100");
    assert_eq!(
        high.add(one, OverflowMode::Refuse).refused("refuse").code(),
        ScalarDiagnosticCode::OverflowRefused
    );
    assert_eq!(
        high.add(one, OverflowMode::Wrapping)
            .unwrap_or_else(|error| panic!("wrap: {error}"))
            .value(),
        -56
    );
    assert_eq!(
        high.add(one, OverflowMode::Saturating)
            .unwrap_or_else(|error| panic!("clamp: {error}"))
            .value(),
        127
    );
    assert_eq!(
        value(I8, "-100")
            .subtract(value(I8, "100"), OverflowMode::Wrapping)
            .unwrap_or_else(|error| panic!("wrap: {error}"))
            .value(),
        56
    );
}

#[test]
fn division_and_remainder_refuse_zero_and_follow_the_dividend() {
    let zero = value(I8, "0");
    assert_eq!(
        value(I8, "5")
            .divide(zero, OverflowMode::Refuse)
            .refused("zero")
            .code(),
        ScalarDiagnosticCode::DivisionByZero
    );
    assert_eq!(
        value(I8, "5")
            .remainder(zero, OverflowMode::Refuse)
            .refused("zero")
            .code(),
        ScalarDiagnosticCode::DivisionByZero
    );
    assert_eq!(
        value(I8, "-7")
            .remainder(value(I8, "3"), OverflowMode::Refuse)
            .unwrap_or_else(|error| panic!("rem: {error}"))
            .value(),
        -1
    );
    assert_eq!(
        value(I8, "-7")
            .divide(value(I8, "3"), OverflowMode::Refuse)
            .unwrap_or_else(|error| panic!("div: {error}"))
            .value(),
        -2
    );
}

#[test]
fn shifts_refuse_amounts_at_or_beyond_the_width() {
    assert_eq!(
        value(I8, "1").shift_right(8).refused("wide").code(),
        ScalarDiagnosticCode::InvalidShift
    );
    assert_eq!(
        value(I8, "1")
            .shift_left(8, OverflowMode::Refuse)
            .refused("wide")
            .code(),
        ScalarDiagnosticCode::InvalidShift
    );
    assert_eq!(
        value(I8, "-8")
            .shift_right(1)
            .unwrap_or_else(|error| panic!("arithmetic: {error}"))
            .value(),
        -4
    );
    assert_eq!(
        value(U8, "255")
            .shift_right(4)
            .unwrap_or_else(|error| panic!("logical: {error}"))
            .value(),
        15
    );
}

#[test]
fn comparison_is_ordered_within_a_kind_and_refused_across_kinds() {
    assert_eq!(
        value(I8, "-1")
            .compare(value(I8, "2"))
            .unwrap_or_else(|error| panic!("same kind: {error}")),
        Ordering::Less
    );
    assert_eq!(
        value(I8, "1")
            .compare(value(U8, "1"))
            .refused("cross kind")
            .code(),
        ScalarDiagnosticCode::CrossWidthComparison
    );
    assert_eq!(value(I8, "42").stable_hash(), value(I8, "42").stable_hash());
    assert_ne!(value(I8, "42").stable_hash(), value(U8, "42").stable_hash());
}

#[test]
fn characters_admit_only_unicode_scalar_values() {
    assert_eq!(
        CharValue::new(0x41)
            .unwrap_or_else(|error| panic!("ascii: {error}"))
            .code_point(),
        0x41
    );
    assert_eq!(
        CharValue::new(0x1F600)
            .unwrap_or_else(|error| panic!("astral: {error}"))
            .utf8_octets()
            .len(),
        4
    );
    assert_eq!(
        CharValue::new(0xD800).refused("surrogate").code(),
        ScalarDiagnosticCode::InvalidChar
    );
    assert_eq!(
        CharValue::new(0x110000).refused("beyond").code(),
        ScalarDiagnosticCode::InvalidChar
    );
}

#[test]
fn sealed_octets_round_trip_and_refuse_noncanonical_text() {
    let bytes = BytesValue::parse_canonical_text("00ff10")
        .unwrap_or_else(|error| panic!("canonical: {error}"));
    assert_eq!(bytes.to_canonical_text(), "00ff10");
    assert_eq!(
        bytes
            .octet(1)
            .unwrap_or_else(|error| panic!("in range: {error}")),
        0xff
    );
    assert_eq!(
        bytes.octet(3).refused("bounds").code(),
        ScalarDiagnosticCode::BufferBounds
    );
    assert_eq!(
        bytes.decode_utf8().refused("invalid utf8").code(),
        ScalarDiagnosticCode::NoncanonicalEncoding
    );
    for text in ["", "0", "0F", "0g", " 00"] {
        assert_eq!(
            BytesValue::parse_canonical_text(text)
                .refused("non-canonical")
                .code(),
            ScalarDiagnosticCode::NoncanonicalEncoding,
            "{text}"
        );
    }
    assert_eq!(
        BytesValue::parse_canonical_text("c3a9")
            .unwrap_or_else(|error| panic!("utf8: {error}"))
            .decode_utf8()
            .unwrap_or_else(|error| panic!("text: {error}")),
        "\u{e9}"
    );
}

#[test]
fn buffers_mutate_only_while_owned_and_freeze_on_consume() {
    let mut buffer = ByteBufferValue::new(StorageStrategy::Reuse, ScalarQuota::new(8));
    buffer
        .append(1)
        .unwrap_or_else(|error| panic!("append: {error}"));
    buffer
        .extend(&[2, 3])
        .unwrap_or_else(|error| panic!("extend: {error}"));
    let tail = buffer
        .split_off(2)
        .unwrap_or_else(|error| panic!("split: {error}"));
    assert_eq!(buffer.octets(), &[1, 2]);
    assert_eq!(tail.octets(), &[3]);
    assert_eq!(buffer.quota().used_octets() + tail.quota().used_octets(), 3);
    buffer
        .truncate(1)
        .unwrap_or_else(|error| panic!("truncate: {error}"));
    assert_eq!(buffer.quota().used_octets(), 1);
    buffer.truncate(2).refused("beyond prefix");
    let mut alias = buffer.alias();
    assert_eq!(
        alias.append(9).refused("shared").code(),
        ScalarDiagnosticCode::BufferSharedMutation
    );
    assert_eq!(
        buffer.clone().alias().freeze().refused("shared").code(),
        ScalarDiagnosticCode::BufferSharedMutation
    );
    let copy = buffer.independent_copy();
    assert_eq!(
        copy.freeze()
            .unwrap_or_else(|error| panic!("frozen: {error}"))
            .as_octets(),
        &[1]
    );
}

#[test]
fn storage_strategies_agree_on_octets_charges_and_refusals() {
    let mut observed = Vec::new();
    for strategy in StorageStrategy::ALL {
        let mut buffer = ByteBufferValue::with_octets(strategy, ScalarQuota::new(4), vec![1, 2])
            .unwrap_or_else(|error| panic!("seed: {error}"));
        buffer
            .append(3)
            .unwrap_or_else(|error| panic!("append: {error}"));
        let refused = buffer.extend(&[4, 5]).refused("quota").code();
        observed.push((
            buffer.octets().to_vec(),
            buffer.quota().used_octets(),
            refused,
        ));
    }
    assert!(observed.windows(2).all(|pair| pair[0] == pair[1]));
}

#[test]
fn quotas_charge_before_growth_and_release_on_truncate() {
    let mut quota = ScalarQuota::new(2);
    quota
        .reserve(2)
        .unwrap_or_else(|error| panic!("within ceiling: {error}"));
    assert_eq!(
        quota.reserve(1).refused("beyond ceiling").code(),
        ScalarDiagnosticCode::QuotaExceeded
    );
    quota.release(1);
    assert_eq!(quota.used_octets(), 1);
    assert_eq!(
        ByteBufferValue::with_octets(StorageStrategy::EagerCopy, ScalarQuota::new(1), vec![1, 2])
            .refused("quota")
            .code(),
        ScalarDiagnosticCode::QuotaExceeded
    );
}

#[test]
fn bytes_and_chars_share_one_declared_identity_space() {
    assert_eq!(
        ByteValue::parse("255")
            .unwrap_or_else(|error| panic!("octet: {error}"))
            .value(),
        255
    );
    assert_eq!(
        ByteValue::parse("256").refused("octet").code(),
        ScalarDiagnosticCode::InvalidLiteral
    );
    assert_eq!(
        ByteValue::parse("07").refused("non-canonical").code(),
        ScalarDiagnosticCode::InvalidLiteral
    );
    assert_ne!(
        ScalarKind::Byte.canonical_name(),
        ScalarKind::Unsigned(ScalarWidth::W8).canonical_name()
    );
}

#[test]
fn section_35_anchors_and_nonclaims_are_published() {
    let spec = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../SPEC.md"))
        .unwrap_or_else(|error| panic!("SPEC.md is readable: {error}"));
    for clause in SCALAR_CLAUSES {
        assert!(spec.contains(clause), "{clause} is not published");
    }
    for code in ScalarDiagnosticCode::ALL {
        assert!(
            spec.contains(code.as_str()),
            "{} is not published",
            code.as_str()
        );
    }
    let asserted: Vec<ScalarNonClaimAssertion> = ScalarNonClaimName::ALL
        .iter()
        .map(|name| ScalarNonClaimAssertion {
            name: *name,
            claims_as_guarantee: false,
        })
        .collect();
    check_scalar_non_claims(&asserted)
        .unwrap_or_else(|error| panic!("non-claims asserted: {error}"));
    let overclaimed: Vec<ScalarNonClaimAssertion> = asserted
        .iter()
        .map(|entry| ScalarNonClaimAssertion {
            name: entry.name,
            claims_as_guarantee: entry.name == ScalarNonClaimName::RawMemory,
        })
        .collect();
    assert_eq!(
        check_scalar_non_claims(&overclaimed)
            .refused("overclaim")
            .code(),
        ScalarDiagnosticCode::NonClaimAsGuarantee
    );
}
