//! Public-facade conformance for the `GNT-39.0`-`GNT-39.5` collection key, order, and `Map`
//! type-identity foundation.
//!
//! The section declares the key contract a source collection consumes and no collection type,
//! traversal, or family behavior: these lanes admit and order canonical scalar keys, refuse
//! ineligible kinds and duplicate identities, admit the identity of the one recognised `Map<K, V>`
//! form, and require every declared clause, diagnostic, and non-claim to be published in the
//! specification and the model.

use std::cmp::Ordering;
use std::fs;
use std::path::{Path, PathBuf};

use gantry::canonical_key::{
    CanonicalKey, CanonicalKeyError, CanonicalKeyLimits, DEFAULT_CANONICAL_KEY_LIMITS,
};
use gantry::ir::TypeDescriptorError;
use gantry::ir::generated::TypeKind;
use gantry::ir::{
    COLLECTION_CLAUSES, CallableKind, CollectionDiagnosticCode, CollectionError,
    CollectionKeyPolicy, CollectionKeyRefusal, CollectionKeyType, CollectionNonClaimAssertion,
    CollectionNonClaimName, MapTypeIdentity, MapValue, RangeStepContract, RangeTypeIdentity,
    RangeValue, SetTypeIdentity, SetValue, TypeDescriptor, canonical_order,
    check_collection_non_claims,
};
use gantry::numeric::{GANTRY_INT_MAXIMUM, GANTRY_INT_MINIMUM, GantryFloat, GantryInt};
use gantry::value::{DEFAULT_VALUE_LIMITS, LogicalValue};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap_or_else(|| panic!("conformance crate has a workspace parent"))
        .to_path_buf()
}

fn policy() -> CollectionKeyPolicy {
    CollectionKeyPolicy::new(DEFAULT_CANONICAL_KEY_LIMITS)
}

fn integer(value: i64) -> LogicalValue {
    LogicalValue::integer(
        GantryInt::new(value).unwrap_or_else(|| panic!("`{value}` is an admitted Int")),
    )
}

fn float(value: f64) -> LogicalValue {
    LogicalValue::float(
        GantryFloat::new(value).unwrap_or_else(|| panic!("`{value}` is a finite normalized Float")),
    )
}

fn string(value: &str) -> LogicalValue {
    LogicalValue::string(value, DEFAULT_VALUE_LIMITS)
        .unwrap_or_else(|error| panic!("the fixture String is valid: {error:?}"))
}

/// Returns the collection refusal produced by one rejected admission.
fn refuse<T>(outcome: Result<T, CollectionKeyRefusal>, context: &str) -> CollectionError {
    match outcome {
        Ok(_) => panic!("{context}: the admission must be refused"),
        Err(
            CollectionKeyRefusal::InvalidKey(error) | CollectionKeyRefusal::DuplicateKey(error),
        ) => error,
        Err(CollectionKeyRefusal::Canonical(error)) => panic!(
            "{context}: the collection contract must refuse, not the canonical contract: {error:?}"
        ),
    }
}

/// Returns the collection refusal produced by one rejected batch.
fn refuse_batch(
    outcome: Result<Vec<CanonicalKey>, CollectionKeyRefusal>,
    context: &str,
) -> CollectionError {
    match outcome {
        Ok(_) => panic!("{context}: the batch must be refused"),
        Err(
            CollectionKeyRefusal::InvalidKey(error) | CollectionKeyRefusal::DuplicateKey(error),
        ) => error,
        Err(CollectionKeyRefusal::Canonical(error)) => panic!(
            "{context}: the collection contract must refuse, not the canonical contract: {error:?}"
        ),
    }
}

/// Returns the refusal produced by one rejected non-claim check.
fn refusal(outcome: Result<(), CollectionError>, context: &str) -> CollectionError {
    match outcome {
        Ok(()) => panic!("{context}: the check must be refused"),
        Err(error) => error,
    }
}

/// Returns the refusal produced by one rejected decision of any result type.
fn rejected<T, E>(outcome: Result<T, E>, context: &str) -> E {
    match outcome {
        Ok(_) => panic!("{context}: the decision must be refused"),
        Err(error) => error,
    }
}

/// A collection key is exactly one admitted canonical scalar key (`GNT-39.1`).
#[test]
fn collection_keys_admit_exactly_the_canonical_scalar_domain() {
    let policy = policy();
    let admitted = [
        LogicalValue::unit(),
        LogicalValue::boolean(false),
        LogicalValue::boolean(true),
        integer(-9_007_199_254_740_991),
        integer(0),
        integer(7),
        float(-0.0),
        float(0.0),
        float(1.5),
        string(""),
        string("gantry"),
        string("é"),
    ];
    for candidate in admitted {
        assert!(
            policy.admit(&candidate).is_ok(),
            "{candidate:?} is an admitted collection key"
        );
    }

    let ineligible = [
        (LogicalValue::none(), "Option"),
        (
            LogicalValue::decision(true, "a declared rationale", DEFAULT_VALUE_LIMITS)
                .unwrap_or_else(|error| panic!("the fixture Decision is valid: {error:?}")),
            "Decision",
        ),
        (
            LogicalValue::list(vec![integer(1)], DEFAULT_VALUE_LIMITS)
                .unwrap_or_else(|error| panic!("the fixture List is valid: {error:?}")),
            "List",
        ),
        (
            LogicalValue::tuple(vec![integer(1), integer(2)], DEFAULT_VALUE_LIMITS)
                .unwrap_or_else(|error| panic!("the fixture Tuple is valid: {error:?}")),
            "Tuple",
        ),
    ];
    for (candidate, kind) in ineligible {
        let error = refuse(policy.admit(&candidate), kind);
        assert_eq!(error.code(), CollectionDiagnosticCode::InvalidKey);
        assert!(
            error.detail().contains(&format!("`{kind}`")),
            "the refusal names the refused kind: {}",
            error.detail()
        );
    }
}

/// Collection order is the scalar-key order of `GNT-5.15`, not frame-byte order (`GNT-39.2`).
#[test]
fn collection_order_follows_the_canonical_scalar_key_order() {
    let policy = policy();
    let key = |candidate: LogicalValue| {
        policy
            .admit(&candidate)
            .unwrap_or_else(|error| panic!("the candidate is admitted: {error:?}"))
    };

    let unit = key(LogicalValue::unit());
    let boolean_false = key(LogicalValue::boolean(false));
    let boolean_true = key(LogicalValue::boolean(true));
    let negative_int = key(integer(-1));
    let positive_int = key(integer(1));
    let float_key = key(float(0.5));
    let text = key(string("a"));
    assert_eq!(canonical_order(&unit, &boolean_false), Ordering::Less);
    assert_eq!(
        canonical_order(&boolean_false, &boolean_true),
        Ordering::Less
    );
    assert_eq!(
        canonical_order(&boolean_true, &negative_int),
        Ordering::Less
    );
    assert_eq!(canonical_order(&negative_int, &float_key), Ordering::Less);
    assert_eq!(canonical_order(&float_key, &text), Ordering::Less);
    assert_eq!(
        canonical_order(&negative_int, &positive_int),
        Ordering::Less
    );
    assert_eq!(
        canonical_order(&key(float(-1.5)), &key(float(-1.25))),
        Ordering::Less,
        "Float compares numerically"
    );
    assert_eq!(
        canonical_order(&key(string("a")), &key(string("b"))),
        Ordering::Less,
        "String compares lexicographically"
    );
    assert_eq!(
        canonical_order(&key(float(-0.0)), &key(float(0.0))),
        Ordering::Equal,
        "normalized signed zeros have one Float key"
    );
    assert_eq!(
        canonical_order(&negative_int, &negative_int.clone()),
        Ordering::Equal
    );

    // Frame bytes are not the order: the frame of an Int stores its two's-complement bits, so
    // the frame of -1 sorts above the frame of 1 while the collection order is the reverse.
    assert!(negative_int.bytes() > positive_int.bytes());
    assert_eq!(
        canonical_order(&negative_int, &positive_int),
        Ordering::Less
    );
    assert_eq!(
        canonical_order(&negative_int, &text),
        negative_int.cmp(&text)
    );
}

/// Duplicate identity uses canonical-key comparison and reports both input indices (`GNT-39.2`).
#[test]
fn duplicate_identity_refuses_with_the_first_and_first_repeated_indices() {
    let policy = policy();
    let unique = policy
        .admit_batch(&[integer(1), integer(2), string("1"), float(1.0)])
        .unwrap_or_else(|error| panic!("the batch is unique: {error:?}"));
    assert_eq!(unique.len(), 4, "cross-numeric identities stay distinct");

    let error = refuse_batch(
        policy.admit_batch(&[integer(7), string("x"), integer(7)]),
        "a repeated Int identity",
    );
    assert_eq!(error.code(), CollectionDiagnosticCode::DuplicateKey);
    assert!(
        error.detail().contains("0 and 2"),
        "the refusal reports the first and first-repeated indices: {}",
        error.detail()
    );

    let error = refuse_batch(
        policy.admit_batch(&[float(-0.0), float(0.0)]),
        "one normalized Float identity",
    );
    assert_eq!(error.code(), CollectionDiagnosticCode::DuplicateKey);
    assert!(error.detail().contains("0 and 1"), "{}", error.detail());

    let error = refuse_batch(
        policy.admit_batch(&[integer(1), LogicalValue::none()]),
        "an ineligible batch member",
    );
    assert_eq!(
        error.code(),
        CollectionDiagnosticCode::InvalidKey,
        "an ineligible candidate refuses before any identity is published"
    );
}

/// The canonical scalar-key contract's own refusals pass through unchanged (`GNT-39.1`).
#[test]
fn canonical_refusals_pass_through_without_a_new_spelling() {
    let limits = CanonicalKeyLimits::new(64).unwrap_or_else(|| panic!("64 is a positive limit"));
    let policy = CollectionKeyPolicy::new(limits);
    let oversized = string(&"a".repeat(128));
    match policy.admit(&oversized) {
        Err(CollectionKeyRefusal::Canonical(CanonicalKeyError::ResourceLimit { .. })) => {}
        other => panic!(
            "an over-limit frame stays the canonical contract's refusal, not a collection one: {other:?}"
        ),
    }
}

/// Every declared non-claim must be asserted and none presented as a guarantee (`GNT-39.3`).
#[test]
fn collection_non_claims_are_declared_and_guarded() {
    let declared = CollectionNonClaimName::ALL.map(|name| CollectionNonClaimAssertion {
        name,
        claims_as_guarantee: false,
    });
    assert_eq!(declared.len(), 6);
    assert!(check_collection_non_claims(&declared).is_ok());

    let missing = &declared[..declared.len() - 1];
    let error = refusal(check_collection_non_claims(missing), "a missing non-claim");
    assert_eq!(error.code(), CollectionDiagnosticCode::NonClaimAsGuarantee);

    let mut claimed = declared;
    claimed[0].claims_as_guarantee = true;
    let error = refusal(
        check_collection_non_claims(&claimed),
        "a non-claim presented as a guarantee",
    );
    assert_eq!(error.code(), CollectionDiagnosticCode::NonClaimAsGuarantee);
    assert!(
        error.detail().contains("presented as a guarantee"),
        "{}",
        error.detail()
    );
}

/// The `Map` type identity admits the five collection key types and refuses every other key
/// argument under the key-domain refusal (`GNT-39.5`).
#[test]
fn map_type_identity_admits_the_five_key_types_and_refuses_the_rest() {
    assert_eq!(
        CollectionKeyType::ALL.map(CollectionKeyType::canonical_text),
        ["Unit", "Bool", "Int", "Float", "String"],
        "the admitted key types are the five of `GNT-39.1` in canonical order"
    );

    let value = TypeDescriptor::STRING;
    for key in CollectionKeyType::ALL {
        let refused = TypeDescriptor::from_canonical_string(key.canonical_text())
            .unwrap_or_else(|error| panic!("`{}` decodes: {error}", key.canonical_text()));
        let identity = MapTypeIdentity::admit(&refused, &value).unwrap_or_else(|error| {
            panic!(
                "`{}` is an admitted key type: {}",
                key.canonical_text(),
                error.detail()
            )
        });
        assert_eq!(identity.key(), key);
        assert_eq!(identity.value(), &value);
        assert_eq!(
            identity.canonical_text(),
            format!("Map<{},String>", key.canonical_text()),
            "the identity is the canonical constructed-type text"
        );
    }

    let ineligible = [
        TypeDescriptor::DECISION,
        TypeDescriptor::OPERATION_ERROR,
        TypeDescriptor::NEVER,
        TypeDescriptor::list(TypeDescriptor::INT),
        TypeDescriptor::option(TypeDescriptor::INT).unwrap_or_else(|error| panic!("{error}")),
        TypeDescriptor::result(TypeDescriptor::INT, TypeDescriptor::STRING),
        TypeDescriptor::tuple(vec![TypeDescriptor::INT, TypeDescriptor::STRING])
            .unwrap_or_else(|error| panic!("a two-member tuple: {error}")),
        TypeDescriptor::callable(
            CallableKind::Function,
            vec![TypeDescriptor::INT],
            TypeDescriptor::INT,
        ),
        TypeDescriptor::from_canonical_string("crate::example::Token")
            .unwrap_or_else(|error| panic!("a declared descriptor decodes: {error}")),
    ];
    for key in ineligible {
        let text = key.canonical_string();
        let error = MapTypeIdentity::admit(&key, &value)
            .err()
            .unwrap_or_else(|| panic!("`{text}` is not an admitted collection key type"));
        assert_eq!(error.code(), CollectionDiagnosticCode::InvalidKey);
        assert_eq!(
            error.code().spelling(),
            "collection-invalid-key",
            "the refusal keeps the one registered key-domain spelling"
        );
        assert!(
            error.detail().contains(&text),
            "the refusal names the refused argument `{text}`: {}",
            error.detail()
        );
    }

    // The identity's canonical text is exact in both directions: every admitted key type decodes,
    // and the decoded identity re-renders byte-identically, including nested member descriptors.
    for (text, key) in [
        ("Map<Unit,String>", CollectionKeyType::Unit),
        ("Map<Bool,List<Int>>", CollectionKeyType::Bool),
        ("Map<Int,Result<Int,String>>", CollectionKeyType::Int),
        ("Map<Float,Option<Int>>", CollectionKeyType::Float),
        ("Map<String,Tuple<Int,String>>", CollectionKeyType::String),
    ] {
        let identity = MapTypeIdentity::from_canonical_text(text)
            .unwrap_or_else(|error| panic!("`{text}` decodes: {}", error.detail()));
        assert_eq!(identity.key(), key);
        assert_eq!(identity.canonical_text(), text);
        assert_eq!(
            MapTypeIdentity::from_canonical_text(&identity.canonical_text()).unwrap_or_else(
                |error| panic!("the rendered identity decodes: {}", error.detail())
            ),
            identity,
            "the canonical text round-trips"
        );
    }

    // Decoding admits no key the key domain refuses and no non-canonical or unadmitted member.
    for (text, code) in [
        ("Map<Decision,String>", CollectionDiagnosticCode::InvalidKey),
        ("Map<Int>", CollectionDiagnosticCode::UnadmittedType),
        (
            "Map<Int,String,Int>",
            CollectionDiagnosticCode::UnadmittedType,
        ),
        ("Map<Int,>", CollectionDiagnosticCode::UnadmittedType),
        ("map<Int,String>", CollectionDiagnosticCode::UnadmittedType),
        ("Map<Int,Missing>", CollectionDiagnosticCode::UnadmittedType),
        (
            "Map<Int,Map<Int,String>>",
            CollectionDiagnosticCode::UnadmittedType,
        ),
        ("List<Int>", CollectionDiagnosticCode::UnadmittedType),
        ("Map<Int,String> ", CollectionDiagnosticCode::UnadmittedType),
    ] {
        let error = MapTypeIdentity::from_canonical_text(text)
            .err()
            .unwrap_or_else(|| panic!("`{text}` is not the canonical text of one identity"));
        assert_eq!(error.code(), code, "`{text}`: {}", error.detail());
    }
    let refused = MapTypeIdentity::from_canonical_text("Map<Decision,String>")
        .err()
        .unwrap_or_else(|| panic!("a refused key member"));
    assert!(
        refused.detail().contains("Decision"),
        "the decoding refusal names the refused key member: {}",
        refused.detail()
    );

    // The key-member rule applies before the general rule, so an input whose key member is not one
    // of the five is refused under the key-domain spelling even when the text is also non-canonical
    // or carries a member this edition does not admit, and the refusal names the whole key member.
    for (text, named) in [
        ("Map<Decision ,String>", "Decision "),
        ("Map<Map<Int,String>,Int>", "Map<Int,String>"),
        ("Map<,String>", ""),
    ] {
        let error = MapTypeIdentity::from_canonical_text(text)
            .err()
            .unwrap_or_else(|| panic!("`{text}` is not an admitted key member"));
        assert_eq!(
            error.code(),
            CollectionDiagnosticCode::InvalidKey,
            "`{text}`"
        );
        assert_eq!(
            error.detail(),
            format!("`{named}` is not an admitted collection key type"),
            "`{text}` names the whole refused key member"
        );
    }
}

/// The `Set<K>` and `Range<T>` identities are published, admitted exactly on their element rules,
/// and exact in both directions (`GNT-39.6`).
#[test]
fn set_and_range_type_identities_are_published_and_refused() {
    // A `Set<K>` element is a collection key, so exactly the five admitted key types are admitted.
    for key in CollectionKeyType::ALL {
        let element = TypeDescriptor::from_canonical_string(key.canonical_text())
            .unwrap_or_else(|error| panic!("`{}` decodes: {error}", key.canonical_text()));
        let identity = SetTypeIdentity::admit(&element).unwrap_or_else(|error| {
            panic!(
                "`{}` is an admitted set element: {}",
                key.canonical_text(),
                error.detail()
            )
        });
        assert_eq!(identity.element(), key);
        assert_eq!(
            identity.canonical_text(),
            format!("Set<{}>", key.canonical_text())
        );
        assert_eq!(
            SetTypeIdentity::from_canonical_text(&identity.canonical_text()).unwrap_or_else(
                |error| panic!("the rendered identity decodes: {}", error.detail())
            ),
            identity,
            "the canonical text round-trips"
        );
    }
    for element in [
        TypeDescriptor::DECISION,
        TypeDescriptor::OPERATION_ERROR,
        TypeDescriptor::NEVER,
        TypeDescriptor::list(TypeDescriptor::INT),
        TypeDescriptor::option(TypeDescriptor::INT).unwrap_or_else(|error| panic!("{error}")),
        TypeDescriptor::result(TypeDescriptor::INT, TypeDescriptor::STRING),
        TypeDescriptor::tuple(vec![TypeDescriptor::INT, TypeDescriptor::STRING])
            .unwrap_or_else(|error| panic!("a two-member tuple: {error}")),
        TypeDescriptor::callable(
            CallableKind::Function,
            vec![TypeDescriptor::INT],
            TypeDescriptor::INT,
        ),
        TypeDescriptor::from_canonical_string("crate::example::Token")
            .unwrap_or_else(|error| panic!("a declared descriptor decodes: {error}")),
    ] {
        let text = element.canonical_string();
        let error = SetTypeIdentity::admit(&element)
            .err()
            .unwrap_or_else(|| panic!("`{text}` is not an admitted set element"));
        assert_eq!(error.code(), CollectionDiagnosticCode::InvalidKey);
        assert_eq!(
            error.detail(),
            format!("`{text}` is not an admitted collection key type"),
            "the set-element refusal names the whole refused argument"
        );
    }
    for (text, code) in [
        ("Set<Decision>", CollectionDiagnosticCode::InvalidKey),
        ("Set<List<Int>>", CollectionDiagnosticCode::InvalidKey),
        ("Set<Decision >", CollectionDiagnosticCode::InvalidKey),
        ("Set<Map<Int,String>>", CollectionDiagnosticCode::InvalidKey),
        ("Set<Int,Int>", CollectionDiagnosticCode::InvalidKey),
        ("Set<Int", CollectionDiagnosticCode::UnadmittedType),
        ("set<Int>", CollectionDiagnosticCode::UnadmittedType),
        ("Set<Int> ", CollectionDiagnosticCode::UnadmittedType),
        ("Map<Int,String>", CollectionDiagnosticCode::UnadmittedType),
    ] {
        let error = SetTypeIdentity::from_canonical_text(text)
            .err()
            .unwrap_or_else(|| panic!("`{text}` is not the canonical text of one Set identity"));
        assert_eq!(error.code(), code, "`{text}`: {}", error.detail());
    }

    // A `Range<T>` element is any admitted value type, and the identity publishes no step rule.
    for element in [
        TypeDescriptor::INT,
        TypeDescriptor::STRING,
        TypeDescriptor::list(TypeDescriptor::INT),
        TypeDescriptor::option(TypeDescriptor::INT).unwrap_or_else(|error| panic!("{error}")),
        TypeDescriptor::result(TypeDescriptor::INT, TypeDescriptor::STRING),
    ] {
        let identity = RangeTypeIdentity::new(element.clone())
            .unwrap_or_else(|error| panic!("the element is admitted: {}", error.detail()));
        assert_eq!(identity.element(), &element);
        assert_eq!(
            identity.canonical_text(),
            format!("Range<{}>", element.canonical_string())
        );
        assert_eq!(
            RangeTypeIdentity::from_canonical_text(&identity.canonical_text()).unwrap_or_else(
                |error| panic!("the rendered identity decodes: {}", error.detail())
            ),
            identity,
            "the canonical text round-trips"
        );
    }
    for text in [
        "Range<Int",
        "range<Int>",
        "Range<Int,Int>",
        "Range<Missing>",
        "Range<Map<Int,String>>",
        "List<Int>",
        "Range<Int> ",
    ] {
        let error = RangeTypeIdentity::from_canonical_text(text)
            .err()
            .unwrap_or_else(|| panic!("`{text}` is not the canonical text of one Range identity"));
        assert_eq!(
            error.code(),
            CollectionDiagnosticCode::UnadmittedType,
            "`{text}`"
        );
    }
}

/// The range step contract is sealed, exact, and deterministic (`GNT-39.7`).
#[test]
fn range_step_contract_is_sealed_and_deterministic() {
    assert_eq!(RangeStepContract::ALL.len(), 1);
    assert_eq!(RangeStepContract::ALL[0].element_text(), "Int");
    assert_eq!(
        RangeStepContract::sealed("Int"),
        Some(RangeStepContract::Int)
    );
    for element in [
        "Float",
        "String",
        "Bool",
        "Unit",
        "List<Int>",
        "Map<Int,String>",
        "Set<Int>",
        "Range<Int>",
        "int",
        "Decision",
    ] {
        assert_eq!(
            RangeStepContract::sealed(element),
            None,
            "`{element}` admits no sealed step contract"
        );
    }

    let contract = RangeStepContract::Int;
    let element = |value: i64| {
        GantryInt::new(value)
            .unwrap_or_else(|| panic!("`{value}` is inside the canonical Int range"))
    };
    assert_eq!(contract.successor(element(0)), Some(element(1)));
    assert_eq!(
        contract.successor(element(GANTRY_INT_MAXIMUM - 1)),
        Some(element(GANTRY_INT_MAXIMUM))
    );
    assert_eq!(contract.successor(element(GANTRY_INT_MAXIMUM)), None);
    assert_eq!(contract.predecessor(element(0)), Some(element(-1)));
    assert_eq!(
        contract.predecessor(element(GANTRY_INT_MINIMUM + 1)),
        Some(element(GANTRY_INT_MINIMUM))
    );
    assert_eq!(contract.predecessor(element(GANTRY_INT_MINIMUM)), None);

    // The step from `value` must land inside the bound: the step landing on the exclusive end bound,
    // or crossing the inclusive start bound, is the step that exhausts the range; an absent bound is
    // unbounded on that side.
    assert!(contract.forward_within(element(8), Some(element(10))));
    assert!(!contract.forward_within(element(9), Some(element(10))));
    assert!(contract.forward_within(element(0), None));
    assert!(!contract.forward_within(element(GANTRY_INT_MAXIMUM), None));
    assert!(contract.backward_within(element(1), Some(element(0))));
    assert!(!contract.backward_within(element(0), Some(element(0))));
    assert!(contract.backward_within(element(0), None));
    assert!(!contract.backward_within(element(GANTRY_INT_MINIMUM), None));

    // Stepping is deterministic: the same value, direction, and bounds produce the same outcome.
    for value in [0i64, 1, GANTRY_INT_MAXIMUM - 1, GANTRY_INT_MAXIMUM] {
        let value = element(value);
        assert_eq!(contract.successor(value), contract.successor(value));
        assert_eq!(contract.predecessor(value), contract.predecessor(value));
        assert_eq!(
            contract.forward_within(value, Some(value)),
            contract.forward_within(value, Some(value))
        );
    }
}

/// Decodes one collection identity text as a canonical type descriptor.
fn descriptor(text: &str) -> TypeDescriptor {
    TypeDescriptor::from_canonical_string(text)
        .unwrap_or_else(|error| panic!("`{text}` is one canonical type descriptor: {error:?}"))
}

/// The three collection type kinds are admitted to the closed type-kind vocabularies and the
/// general type algebra owns their canonical text (`GNT-39.5`, `GNT-39.6`).
///
/// The admission is vocabulary and descriptor algebra: the canonical-IR contract publishes the
/// three kinds, each owned by the clause that identifies it, and the algebra renders and decodes
/// the identity texts exactly under the key rule the identities own. No source form, value,
/// construction, projection, traversal, iteration, quota, schema, recovery, durability, lowering,
/// or machine representation is admitted, and `GNT-39.4` keeps the type-admission refusal.
#[test]
fn collection_type_kinds_are_admitted_and_the_algebra_owns_their_canonical_text() {
    assert_eq!(TypeKind::Map.wire_name(), "Map");
    assert_eq!(TypeKind::Set.wire_name(), "Set");
    assert_eq!(TypeKind::Range.wire_name(), "Range");

    // The closed canonical-IR kind vocabulary appends exactly these three collection kinds to the
    // published v1 order, and each cites the clause that identifies it.
    let catalog =
        fs::read_to_string(workspace_root().join("protocol/catalogs/ir-contracts-v1.json"))
            .unwrap_or_else(|error| panic!("the IR contracts catalog is readable: {error}"));
    let catalog: serde_json::Value = serde_json::from_str(&catalog)
        .unwrap_or_else(|error| panic!("the IR contracts catalog is one JSON document: {error}"));
    let kinds = catalog["type_kinds"]
        .as_array()
        .unwrap_or_else(|| panic!("the IR contracts catalog lists type kinds"));
    for (kind, owner) in [
        (TypeKind::Range, "GNT-39.6-set-and-range-type-identities"),
        (TypeKind::Set, "GNT-39.6-set-and-range-type-identities"),
        (TypeKind::Map, "GNT-39.5-map-type-identity"),
    ] {
        let entry = kinds
            .iter()
            .rev()
            .find(|entry| entry["wire"].as_str() == Some(kind.wire_name()))
            .unwrap_or_else(|| panic!("the catalog declares the {} kind", kind.wire_name()));
        assert_eq!(entry["rust"].as_str(), Some(kind.wire_name()));
        assert_eq!(entry["requirements"].as_array().map(Vec::len), Some(1));
        let cited = entry["requirements"][0].as_str().unwrap_or_default();
        assert_eq!(cited, owner);
        assert!(COLLECTION_CLAUSES.contains(&owner));
    }

    // The identity text each clause publishes is one canonical descriptor of that kind, the
    // descriptor re-renders to exactly the identity text, and its members are the identity's own
    // members in order.
    let map = MapTypeIdentity::admit(&TypeDescriptor::INT, &TypeDescriptor::STRING)
        .unwrap_or_else(|error| panic!("Int is an admitted collection key: {error:?}"));
    let map_descriptor = descriptor(&map.canonical_text());
    assert_eq!(map_descriptor.kind(), TypeKind::Map);
    assert_eq!(map_descriptor.canonical_string(), map.canonical_text());
    assert_eq!(
        map_descriptor.immediate_members(),
        vec![TypeDescriptor::INT, TypeDescriptor::STRING]
    );

    let set = SetTypeIdentity::admit(&TypeDescriptor::BOOL)
        .unwrap_or_else(|error| panic!("Bool is an admitted collection key: {error:?}"));
    let set_descriptor = descriptor(&set.canonical_text());
    assert_eq!(set_descriptor.kind(), TypeKind::Set);
    assert_eq!(set_descriptor.canonical_string(), set.canonical_text());
    assert_eq!(
        set_descriptor.immediate_members(),
        vec![TypeDescriptor::BOOL]
    );

    // A range element is any constructed value type, so the element member is not a key and the
    // `GNT-39.7` element domain is not a type-admission rule this descriptor decides.
    let element = TypeDescriptor::list(TypeDescriptor::INT);
    let range = RangeTypeIdentity::new(element.clone())
        .unwrap_or_else(|error| panic!("a list element is admitted: {}", error.detail()));
    let range_descriptor = descriptor(&range.canonical_text());
    assert_eq!(range_descriptor.kind(), TypeKind::Range);
    assert_eq!(range_descriptor.canonical_string(), range.canonical_text());
    assert_eq!(range_descriptor.immediate_members(), vec![element.clone()]);

    // The public fail-closed predicate the identity rule and the boundary rule share reports
    // exactly the descriptors that name a collection type anywhere inside them.
    for descriptor in [&map_descriptor, &set_descriptor, &range_descriptor] {
        assert!(descriptor.contains_collection_type());
    }
    let plain = TypeDescriptor::result(TypeDescriptor::INT, TypeDescriptor::STRING);
    assert!(!plain.contains_collection_type());
    assert!(!TypeDescriptor::list(plain.clone()).contains_collection_type());
    assert!(!TypeDescriptor::list(element.clone()).contains_collection_type());
    assert!(
        TypeDescriptor::list(TypeDescriptor::list(map_descriptor.clone()))
            .contains_collection_type()
    );
    assert!(
        !TypeDescriptor::callable(CallableKind::Function, vec![plain.clone()], plain.clone())
            .contains_collection_type()
    );
    assert!(
        TypeDescriptor::callable(
            CallableKind::Function,
            vec![map_descriptor.clone()],
            plain.clone()
        )
        .contains_collection_type()
    );

    // Every collection kind is structural: none carries independent primitive properties, and a
    // sealed member is carried through the descriptor exactly as it is for the other kinds.
    for descriptor in [&map_descriptor, &set_descriptor, &range_descriptor] {
        assert!(descriptor.primitive_properties().is_none());
    }
    let sealed = TypeDescriptor::map(TypeDescriptor::INT, TypeDescriptor::DECISION)
        .unwrap_or_else(|error| panic!("the value member is unrestricted: {error:?}"));
    assert_eq!(sealed.canonical_string(), "Map<Int,Decision>");
    assert!(sealed.contains_sealed_boundary());
    assert!(!map_descriptor.contains_sealed_boundary());

    // The `Map` key member and the `Set` element member are the same key domain: the algebra
    // refuses a member outside it under that rule's own refusal, and the unadmitted-member rule is
    // a second, distinct refusal.
    assert_eq!(
        TypeDescriptor::map(element.clone(), TypeDescriptor::INT),
        Err(TypeDescriptorError::InvalidCollectionKey)
    );
    assert_eq!(
        TypeDescriptor::set(element.clone()),
        Err(TypeDescriptorError::InvalidCollectionKey)
    );
    let collection_member = TypeDescriptor::map(TypeDescriptor::INT, TypeDescriptor::STRING)
        .unwrap_or_else(|error| panic!("Int and String are admitted: {error:?}"));
    assert_eq!(
        TypeDescriptor::map(TypeDescriptor::INT, collection_member.clone()),
        Err(TypeDescriptorError::InvalidCollectionMember)
    );
    assert_eq!(
        TypeDescriptor::map(
            TypeDescriptor::INT,
            TypeDescriptor::list(collection_member.clone()),
        ),
        Err(TypeDescriptorError::InvalidCollectionMember)
    );
    assert_eq!(
        TypeDescriptor::range(collection_member.clone()),
        Err(TypeDescriptorError::InvalidCollectionMember)
    );
    assert_eq!(
        TypeDescriptor::range(TypeDescriptor::list(collection_member.clone())),
        Err(TypeDescriptorError::InvalidCollectionMember)
    );
    assert_eq!(
        rejected(
            TypeDescriptor::from_canonical_string("Map<List<Int>,Int>"),
            "a collection key member",
        ),
        TypeDescriptorError::InvalidCanonicalString
    );
    assert_eq!(
        rejected(
            TypeDescriptor::from_canonical_string("Set<List<Int>>"),
            "a collection element member",
        ),
        TypeDescriptorError::InvalidCanonicalString
    );
    for malformed in [
        "Map<Int>",
        "Map<Int,Bool,Int>",
        "Map<Int,>",
        "Map<>",
        "Set<Int,Bool>",
        "Set<>",
        "Range<Int,Int>",
        "Range<>",
    ] {
        assert!(
            TypeDescriptor::from_canonical_string(malformed).is_err(),
            "`{malformed}` is not one canonical collection descriptor"
        );
    }

    // Each identity's constructor applies exactly the rule its decoder applies, and no collection
    // type is admitted as a value type at any depth, so the two public paths of one identity cannot
    // disagree: a collection member — direct, or hidden inside another member of any kind — is
    // refused as an unadmitted member by the constructor, by the decoder, and by the algebra.
    let nested = TypeDescriptor::map(TypeDescriptor::INT, TypeDescriptor::STRING)
        .unwrap_or_else(|error| panic!("the nested fixture is admitted: {error:?}"));
    let range_of_int = TypeDescriptor::range(TypeDescriptor::INT)
        .unwrap_or_else(|error| panic!("Int is an admitted element: {error:?}"));
    for (text, member) in [
        ("Map<Int,Map<Int,String>>", nested.clone()),
        ("Map<Int,Range<Int>>", range_of_int.clone()),
        (
            "Map<Int,List<Map<Int,String>>>",
            TypeDescriptor::list(nested.clone()),
        ),
    ] {
        assert_eq!(
            rejected(
                MapTypeIdentity::from_canonical_text(text),
                "the identity text"
            )
            .code(),
            CollectionDiagnosticCode::UnadmittedType,
            "`{text}`"
        );
        assert_eq!(
            rejected(
                MapTypeIdentity::admit(&TypeDescriptor::INT, &member),
                "the constructor",
            )
            .code(),
            CollectionDiagnosticCode::UnadmittedType,
            "the constructor agrees with the decoder for `{text}`"
        );
        assert_eq!(
            rejected(
                TypeDescriptor::from_canonical_string(text),
                "the descriptor text",
            ),
            TypeDescriptorError::InvalidCanonicalString,
            "the algebra refuses `{text}`"
        );
    }
    for (text, member) in [
        ("Range<Map<Int,String>>", nested.clone()),
        (
            "Range<List<Map<Int,String>>>",
            TypeDescriptor::list(nested.clone()),
        ),
    ] {
        assert_eq!(
            rejected(
                RangeTypeIdentity::from_canonical_text(text),
                "the identity text",
            )
            .code(),
            CollectionDiagnosticCode::UnadmittedType,
            "`{text}`"
        );
        assert_eq!(
            rejected(RangeTypeIdentity::new(member.clone()), "the constructor").code(),
            CollectionDiagnosticCode::UnadmittedType,
            "the constructor agrees with the decoder for `{text}`"
        );
        assert_eq!(
            rejected(
                TypeDescriptor::from_canonical_string(text),
                "the descriptor text",
            ),
            TypeDescriptorError::InvalidCanonicalString,
            "the algebra refuses `{text}`"
        );
    }
    // A collection key member is refused by the key rule before that member rule, exactly where the
    // clause publishes the ordering.
    assert_eq!(
        rejected(
            MapTypeIdentity::from_canonical_text("Map<Map<Int,String>,Int>"),
            "the identity text",
        )
        .code(),
        CollectionDiagnosticCode::InvalidKey
    );
    assert_eq!(
        rejected(
            MapTypeIdentity::from_canonical_text("Map<List<Int>,Int>"),
            "the identity text",
        )
        .code(),
        CollectionDiagnosticCode::InvalidKey
    );
    assert_eq!(
        rejected(
            SetTypeIdentity::from_canonical_text("Set<List<Int>>"),
            "the identity text",
        )
        .code(),
        CollectionDiagnosticCode::InvalidKey
    );
    assert_eq!(
        rejected(
            RangeTypeIdentity::from_canonical_text("Range<Int,Int>"),
            "the identity text",
        )
        .code(),
        CollectionDiagnosticCode::UnadmittedType
    );

    // No source form is admitted: the type-admission refusal of `GNT-39.4` stays clause-owned and
    // registered while the descriptors are nameable and decodable.
    assert_eq!(
        CollectionDiagnosticCode::UnadmittedType.spelling(),
        "collection-type-unadmitted"
    );
}

/// The `Map` and `Set` value models order their entries and refuse repeated keys (`GNT-39.8`).
#[test]
fn collection_value_models_order_entries_and_refuse_duplicates() {
    let policy = policy();
    let refused = refuse(
        MapValue::admit(
            policy,
            &[(string("beta"), integer(2)), (string("beta"), integer(3))],
        ),
        "a repeated Map key",
    );
    assert_eq!(refused.code(), CollectionDiagnosticCode::DuplicateKey);

    let map = MapValue::admit(
        policy,
        &[(string("beta"), integer(2)), (integer(1), string("one"))],
    )
    .unwrap_or_else(|error| panic!("the declared entries are admitted: {error:?}"));
    assert_eq!(map.len(), 2);
    assert!(!map.is_empty());
    let keys = map
        .entries()
        .iter()
        .map(|(key, _)| key.clone())
        .collect::<Vec<_>>();
    // The canonical collection order places `Int` before `String`.
    assert_eq!(canonical_order(&keys[0], &keys[1]), Ordering::Less);
    let one = policy
        .admit(&integer(1))
        .unwrap_or_else(|error| panic!("{error:?}"));
    assert_eq!(map.get(&one), Some(&string("one")));
    let absent = policy
        .admit(&string("absent"))
        .unwrap_or_else(|error| panic!("{error:?}"));
    assert_eq!(map.get(&absent), None);

    let set = SetValue::admit(policy, &[string("b"), integer(2), string("a")])
        .unwrap_or_else(|error| panic!("the declared elements are admitted: {error:?}"));
    assert_eq!(set.len(), 3);
    assert!(!set.is_empty());
    let element = policy
        .admit(&string("a"))
        .unwrap_or_else(|error| panic!("{error:?}"));
    assert!(set.contains(&element));
    assert!(!set.contains(&absent));
    let refused = refuse(
        SetValue::admit(policy, &[integer(1), integer(1)]),
        "a repeated Set element",
    );
    assert_eq!(refused.code(), CollectionDiagnosticCode::DuplicateKey);

    // Equal entries are one value whatever order the candidates arrive in, the canonical order is
    // the value's own order, and an empty value is admitted rather than special-cased.
    let shuffled = MapValue::admit(
        policy,
        &[(integer(1), string("one")), (string("beta"), integer(2))],
    )
    .unwrap_or_else(|error| panic!("the declared entries are admitted: {error:?}"));
    assert_eq!(shuffled, map);
    assert_eq!(shuffled.entries(), map.entries());
    let elements = set.elements();
    assert_eq!(elements.len(), 3);
    for pair in elements.windows(2) {
        assert_eq!(canonical_order(&pair[0], &pair[1]), Ordering::Less);
    }
    let empty = MapValue::admit(policy, &[]).unwrap_or_else(|error| panic!("{error:?}"));
    assert!(empty.is_empty());
    assert_eq!(empty.len(), 0);
    assert_eq!(empty.get(&one), None);
    let empty_set = SetValue::admit(policy, &[]).unwrap_or_else(|error| panic!("{error:?}"));
    assert!(empty_set.is_empty());
    assert_eq!(empty_set.elements().len(), 0);

    // The `Range` value carries its two bound positions under the sealed step contract: the start
    // bound is inclusive, the end bound exclusive, and a step that would leave the bound is
    // exhaustion rather than a refusal or a wrap.
    let bound = |value: i64| {
        GantryInt::new(value).unwrap_or_else(|| panic!("`{value}` is an admitted Int"))
    };
    let start = bound(1);
    let end = bound(4);
    let range = RangeValue::new(Some(start), Some(end));
    assert_eq!(range.start(), Some(start));
    assert_eq!(range.end(), Some(end));
    assert!(range.admits(start));
    assert!(range.admits(bound(3)));
    assert!(!range.admits(end));
    assert!(!range.admits(bound(0)));
    assert_eq!(range.forward(start), Some(bound(2)));
    assert_eq!(range.forward(bound(3)), None);
    assert_eq!(range.forward(end), None);
    assert_eq!(range.backward(bound(2)), Some(bound(1)));
    assert_eq!(range.backward(start), None);
    let unbounded = RangeValue::new(None, None);
    assert_eq!(unbounded.forward(bound(GANTRY_INT_MAXIMUM)), None);
    assert_eq!(unbounded.backward(bound(GANTRY_INT_MINIMUM)), None);

    // An absent bound is unbounded on that side, so a step there is permissive unless the step
    // itself does not exist, and exhaustion by bound is a different reason from domain exhaustion.
    assert_eq!(
        RangeValue::new(Some(start), None).forward(bound(3)),
        Some(bound(4))
    );
    assert_eq!(
        RangeValue::new(None, Some(end)).backward(bound(3)),
        Some(bound(2))
    );
    assert_eq!(
        unbounded.forward(bound(GANTRY_INT_MAXIMUM - 1)),
        Some(bound(GANTRY_INT_MAXIMUM))
    );
    let bounded = RangeValue::new(
        Some(bound(GANTRY_INT_MINIMUM)),
        Some(bound(GANTRY_INT_MAXIMUM)),
    );
    assert!(bounded.admits(bound(GANTRY_INT_MINIMUM)));
    assert!(bounded.admits(bound(GANTRY_INT_MAXIMUM - 1)));
    assert!(!bounded.admits(bound(GANTRY_INT_MAXIMUM)));
    assert_eq!(bounded.forward(bound(GANTRY_INT_MAXIMUM - 1)), None);
    assert_eq!(bounded.backward(bound(GANTRY_INT_MINIMUM)), None);

    // The step rule is result-side rather than the bound rule (`GNT-39.8`): `forward` and `backward`
    // report a step for a source position the value does not admit, and neither wraps.
    assert_eq!(range.forward(bound(0)), Some(bound(1)));
    assert_eq!(range.backward(end), Some(bound(3)));
    assert_eq!(
        range.forward(bound(GANTRY_INT_MINIMUM)),
        Some(bound(GANTRY_INT_MINIMUM + 1))
    );

    // An inverted or empty bound pair admits no position and is refused by no rule: `new` is total.
    for (pair_start, pair_end) in [(4i64, 1i64), (2, 2)] {
        let pair = RangeValue::new(Some(bound(pair_start)), Some(bound(pair_end)));
        assert_eq!(pair.start(), Some(bound(pair_start)));
        assert_eq!(pair.end(), Some(bound(pair_end)));
        for value in [
            GANTRY_INT_MINIMUM,
            0,
            1,
            3,
            pair_start,
            pair_end,
            GANTRY_INT_MAXIMUM,
        ] {
            assert!(
                !pair.admits(bound(value)),
                "`{value}` is outside the `[{pair_start},{pair_end})` pair"
            );
        }
    }
    assert_eq!(
        RangeValue::new(Some(bound(4)), Some(bound(1))).forward(bound(-5)),
        Some(bound(-4))
    );
    // An empty pair is refused by no rule either, and its step is the same result-side rule.
    let empty_pair = RangeValue::new(Some(bound(2)), Some(bound(2)));
    assert_eq!(empty_pair.forward(bound(0)), Some(bound(1)));
    assert_eq!(empty_pair.backward(bound(3)), Some(bound(2)));
}

/// Every declared clause, diagnostic, and owning clause is published (`GNT-39.0`).
#[test]
fn collection_clauses_and_diagnostics_are_published() {
    let specification = fs::read_to_string(workspace_root().join("SPEC.md"))
        .unwrap_or_else(|error| panic!("the specification is readable: {error}"));
    for clause in COLLECTION_CLAUSES {
        assert!(
            specification.contains(clause),
            "the specification declares `{clause}`"
        );
    }
    assert_eq!(CollectionDiagnosticCode::ALL.len(), 4);
    for code in CollectionDiagnosticCode::ALL {
        assert!(
            specification.contains(code.spelling()),
            "the specification names `{}`",
            code.spelling()
        );
        assert!(
            COLLECTION_CLAUSES.contains(&code.owning_clause()),
            "`{}` names a declared owning clause",
            code.spelling()
        );
    }
    let mut spellings = CollectionDiagnosticCode::ALL
        .iter()
        .map(|code| code.spelling())
        .collect::<Vec<&str>>();
    spellings.sort_unstable();
    spellings.dedup();
    assert_eq!(spellings.len(), CollectionDiagnosticCode::ALL.len());
}

/// The published note names every declared clause, diagnostic, owning clause, and non-claim.
#[test]
fn collection_note_names_every_declared_clause_diagnostic_and_non_claim() {
    let note = fs::read_to_string(workspace_root().join("docs/collections-foundation.md"))
        .unwrap_or_else(|error| panic!("the collection-foundation note is readable: {error}"));
    for clause in COLLECTION_CLAUSES {
        assert!(note.contains(clause), "the note names `{clause}`");
    }
    for code in CollectionDiagnosticCode::ALL {
        assert!(
            note.contains(code.spelling()),
            "the note names `{}`",
            code.spelling()
        );
        assert!(
            note.contains(code.owning_clause()),
            "the note names the owning clause of `{}`",
            code.spelling()
        );
        assert!(
            note.lines()
                .any(|line| line.contains(code.spelling()) && line.contains(code.owning_clause())),
            "the note pairs `{}` with its owning clause on one row",
            code.spelling()
        );
    }
    for name in CollectionNonClaimName::ALL {
        assert!(
            note.contains(name.as_str()),
            "the note names the declared non-claim `{}`",
            name.as_str()
        );
    }
    let diagnostics_section = note
        .split_once("## Diagnostics")
        .and_then(|(_, rest)| rest.split_once("\n## "))
        .map(|(body, _)| body)
        .unwrap_or_else(|| panic!("the note publishes a diagnostics section"));
    for code in CollectionDiagnosticCode::ALL {
        assert!(
            diagnostics_section
                .lines()
                .any(|line| line.contains(code.spelling()) && line.contains(code.owning_clause())),
            "the diagnostics table pairs `{}` with its owning clause on one row",
            code.spelling()
        );
    }
    assert!(
        note.contains("GNT-5.15-canonical-scalar-keys"),
        "the note names the consumed canonical scalar-key contract"
    );
}
