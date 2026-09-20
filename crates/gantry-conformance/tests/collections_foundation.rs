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
use gantry::ir::{
    COLLECTION_CLAUSES, CallableKind, CollectionDiagnosticCode, CollectionError,
    CollectionKeyPolicy, CollectionKeyRefusal, CollectionNonClaimAssertion, CollectionNonClaimName,
    MapKeyType, MapTypeIdentity, TypeDescriptor, canonical_order, check_collection_non_claims,
};
use gantry::numeric::{GantryFloat, GantryInt};
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
fn refuse(outcome: Result<CanonicalKey, CollectionKeyRefusal>, context: &str) -> CollectionError {
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
        MapKeyType::ALL.map(MapKeyType::canonical_text),
        ["Unit", "Bool", "Int", "Float", "String"],
        "the admitted key types are the five of `GNT-39.1` in canonical order"
    );

    let value = TypeDescriptor::STRING;
    for key in MapKeyType::ALL {
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
        ("Map<Unit,String>", MapKeyType::Unit),
        ("Map<Bool,List<Int>>", MapKeyType::Bool),
        ("Map<Int,Result<Int,String>>", MapKeyType::Int),
        ("Map<Float,Option<Int>>", MapKeyType::Float),
        ("Map<String,Tuple<Int,String>>", MapKeyType::String),
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
        assert!(
            error.detail().contains(named),
            "`{text}` names the whole refused key member: {}",
            error.detail()
        );
    }
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
