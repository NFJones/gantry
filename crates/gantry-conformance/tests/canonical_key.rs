//! Public contract tests for versioned canonical scalar keys.

use std::cmp::Ordering;

use gantry::canonical_key::{
    CANONICAL_KEY_FORMAT_MAJOR, CANONICAL_KEY_FORMAT_MINOR, CanonicalKeyError, CanonicalKeyLimits,
    DEFAULT_CANONICAL_KEY_LIMITS,
};
use gantry::numeric::{GantryFloat, GantryInt};
use gantry::value::{DEFAULT_VALUE_LIMITS, LogicalValue, OperationErrorValue, ValueKind};

fn int(value: i64) -> LogicalValue {
    LogicalValue::integer(
        GantryInt::new(value).unwrap_or_else(|| unreachable!("test integer is in range")),
    )
}

fn float(value: f64) -> LogicalValue {
    LogicalValue::float(
        GantryFloat::new(value).unwrap_or_else(|| unreachable!("test float is finite")),
    )
}

#[test]
fn public_scalar_values_produce_versioned_canonical_keys() {
    let values = [
        LogicalValue::unit(),
        LogicalValue::boolean(false),
        int(-7),
        float(1.5),
        LogicalValue::string("key", DEFAULT_VALUE_LIMITS)
            .unwrap_or_else(|error| panic!("test string failed: {error:?}")),
    ];
    for value in values {
        let key = value
            .canonical_key(DEFAULT_CANONICAL_KEY_LIMITS)
            .unwrap_or_else(|error| panic!("eligible scalar failed: {error:?}"));
        assert_eq!(&key.bytes()[..8], b"GNTYKEY\0");
        assert_eq!(
            &key.bytes()[8..10],
            &CANONICAL_KEY_FORMAT_MAJOR.to_be_bytes()
        );
        assert_eq!(
            &key.bytes()[10..12],
            &CANONICAL_KEY_FORMAT_MINOR.to_be_bytes()
        );
        assert_eq!(key.sha256_hex().len(), 64);
    }
}

#[test]
fn public_structural_and_sealed_values_are_not_scalar_keys() {
    let list = LogicalValue::list(vec![int(1)], DEFAULT_VALUE_LIMITS)
        .unwrap_or_else(|error| panic!("test list failed: {error:?}"));
    let tuple = LogicalValue::tuple(vec![int(1), int(2)], DEFAULT_VALUE_LIMITS)
        .unwrap_or_else(|error| panic!("test tuple failed: {error:?}"));
    let structure = LogicalValue::structure(
        "crate::Pair",
        vec![("left".to_owned(), int(1))],
        DEFAULT_VALUE_LIMITS,
    )
    .unwrap_or_else(|error| panic!("test structure failed: {error:?}"));
    let enumeration =
        LogicalValue::enumeration("crate::Choice", "First", Some(int(1)), DEFAULT_VALUE_LIMITS)
            .unwrap_or_else(|error| panic!("test enumeration failed: {error:?}"));
    let option = LogicalValue::none();
    let result = LogicalValue::ok(int(1), DEFAULT_VALUE_LIMITS)
        .unwrap_or_else(|error| panic!("test result failed: {error:?}"));
    let decision = LogicalValue::decision(true, "because", DEFAULT_VALUE_LIMITS)
        .unwrap_or_else(|error| panic!("test decision failed: {error:?}"));
    let operation_error =
        LogicalValue::operation_error(OperationErrorValue::InvalidOutput, DEFAULT_VALUE_LIMITS)
            .unwrap_or_else(|error| panic!("test operation error failed: {error:?}"));
    assert_eq!(
        list.canonical_key(DEFAULT_CANONICAL_KEY_LIMITS),
        Err(CanonicalKeyError::IneligibleKind(ValueKind::List))
    );
    assert_eq!(
        tuple.canonical_key(DEFAULT_CANONICAL_KEY_LIMITS),
        Err(CanonicalKeyError::IneligibleKind(ValueKind::Tuple))
    );
    assert_eq!(
        structure.canonical_key(DEFAULT_CANONICAL_KEY_LIMITS),
        Err(CanonicalKeyError::IneligibleKind(ValueKind::Struct))
    );
    assert_eq!(
        enumeration.canonical_key(DEFAULT_CANONICAL_KEY_LIMITS),
        Err(CanonicalKeyError::IneligibleKind(ValueKind::Enum))
    );
    assert_eq!(
        option.canonical_key(DEFAULT_CANONICAL_KEY_LIMITS),
        Err(CanonicalKeyError::IneligibleKind(ValueKind::Option))
    );
    assert_eq!(
        result.canonical_key(DEFAULT_CANONICAL_KEY_LIMITS),
        Err(CanonicalKeyError::IneligibleKind(ValueKind::Result))
    );
    assert_eq!(
        decision.canonical_key(DEFAULT_CANONICAL_KEY_LIMITS),
        Err(CanonicalKeyError::IneligibleKind(ValueKind::Decision))
    );
    assert_eq!(
        operation_error.canonical_key(DEFAULT_CANONICAL_KEY_LIMITS),
        Err(CanonicalKeyError::IneligibleKind(ValueKind::OperationError))
    );
}

#[test]
fn public_key_bytes_are_exact_and_distinguish_json_collisions() {
    let unit = LogicalValue::unit()
        .canonical_key(DEFAULT_CANONICAL_KEY_LIMITS)
        .unwrap_or_else(|error| panic!("unit key failed: {error:?}"));
    assert_eq!(
        unit.bytes(),
        &[
            b'G', b'N', b'T', b'Y', b'K', b'E', b'Y', 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]
    );

    let integer = int(1)
        .canonical_key(DEFAULT_CANONICAL_KEY_LIMITS)
        .unwrap_or_else(|error| panic!("integer key failed: {error:?}"));
    let floating = float(1.0)
        .canonical_key(DEFAULT_CANONICAL_KEY_LIMITS)
        .unwrap_or_else(|error| panic!("float key failed: {error:?}"));
    let boolean = LogicalValue::boolean(true)
        .canonical_key(DEFAULT_CANONICAL_KEY_LIMITS)
        .unwrap_or_else(|error| panic!("boolean key failed: {error:?}"));
    let string = LogicalValue::string("A", DEFAULT_VALUE_LIMITS)
        .unwrap_or_else(|error| panic!("test string failed: {error:?}"))
        .canonical_key(DEFAULT_CANONICAL_KEY_LIMITS)
        .unwrap_or_else(|error| panic!("string key failed: {error:?}"));
    assert_eq!(
        boolean.bytes(),
        &[
            b'G', b'N', b'T', b'Y', b'K', b'E', b'Y', 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1,
        ]
    );
    assert_eq!(
        integer.bytes(),
        &[
            b'G', b'N', b'T', b'Y', b'K', b'E', b'Y', 0, 0, 1, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 8, 0,
            0, 0, 0, 0, 0, 0, 1,
        ]
    );
    assert_eq!(
        floating.bytes(),
        &[
            b'G', b'N', b'T', b'Y', b'K', b'E', b'Y', 0, 0, 1, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 8,
            0x3f, 0xf0, 0, 0, 0, 0, 0, 0,
        ]
    );
    assert_eq!(
        string.bytes(),
        &[
            b'G', b'N', b'T', b'Y', b'K', b'E', b'Y', 0, 0, 1, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 1,
            b'A',
        ]
    );
    assert_ne!(integer.bytes(), floating.bytes());
}

#[test]
fn public_key_limit_counts_the_complete_frame() {
    let limit = CanonicalKeyLimits::new(23).unwrap_or_else(|| unreachable!("positive key limit"));
    let value = LogicalValue::string("abc", DEFAULT_VALUE_LIMITS)
        .unwrap_or_else(|error| panic!("test string failed: {error:?}"));
    assert_eq!(
        value.canonical_key(limit),
        Err(CanonicalKeyError::ResourceLimit {
            limit: 23,
            required: 24,
        })
    );
    assert!(CanonicalKeyLimits::new(0).is_none());
}

#[test]
fn public_key_order_is_total_numeric_and_equality_exact() {
    let values = [
        LogicalValue::unit(),
        LogicalValue::boolean(false),
        LogicalValue::boolean(true),
        int(-2),
        int(9),
        float(-10.0),
        float(-0.0),
        float(0.5),
        LogicalValue::string("a", DEFAULT_VALUE_LIMITS)
            .unwrap_or_else(|error| panic!("test string failed: {error:?}")),
    ];
    let keys = values
        .iter()
        .map(|value| {
            value
                .canonical_key(DEFAULT_CANONICAL_KEY_LIMITS)
                .unwrap_or_else(|error| panic!("eligible scalar failed: {error:?}"))
        })
        .collect::<Vec<_>>();
    assert!(keys.windows(2).all(|pair| pair[0] < pair[1]));
    for (left_index, left) in values.iter().enumerate() {
        for (right_index, right) in values.iter().enumerate() {
            assert_eq!(
                keys[left_index].cmp(&keys[right_index]) == Ordering::Equal,
                left == right,
                "comparison and value equality differ for {left_index} and {right_index}"
            );
        }
    }

    let positive_zero = float(0.0);
    let negative_zero = float(-0.0);
    let positive_key = positive_zero
        .canonical_key(DEFAULT_CANONICAL_KEY_LIMITS)
        .unwrap_or_else(|error| panic!("positive zero key failed: {error:?}"));
    let negative_key = negative_zero
        .canonical_key(DEFAULT_CANONICAL_KEY_LIMITS)
        .unwrap_or_else(|error| panic!("negative zero key failed: {error:?}"));
    assert_eq!(positive_zero, negative_zero);
    assert_eq!(positive_key.cmp(&negative_key), Ordering::Equal);
    assert_eq!(positive_key, negative_key);
}

#[test]
fn public_content_hash_is_sha256_of_exact_key_bytes() {
    let key = LogicalValue::boolean(true)
        .canonical_key(DEFAULT_CANONICAL_KEY_LIMITS)
        .unwrap_or_else(|error| panic!("boolean key failed: {error:?}"));
    assert_eq!(
        key.sha256_hex(),
        "0cc19916bc95d57ba93c4128f27bafd62ae24e3e83956f616128de500e89e049"
    );
}
