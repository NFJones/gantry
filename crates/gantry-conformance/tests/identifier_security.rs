//! Machine-checked conformance for identity domains and identifier security.
//!
//! These tests exercise the public model of [`gantry::ir`] for `GNT-18.0` through
//! `GNT-18.13-identity-version-pinning`. They check the pure rules the
//! specification makes normative, not a platform: no test here reads an
//! environment variable, a host path, a clock, a locale, a registry response, or a
//! filesystem, because a canonical symbolic identity, an alias map, and an
//! external-name mapping MUST NOT be derived from those things.

use std::collections::BTreeSet;
use std::sync::Arc;

use gantry::ir::identifier::{AliasMap, CollisionCondition, DeclaredName};
use gantry::ir::{
    CanonicalSymbolicIdentity, CollisionDiagnostic, ConfusableSkeleton,
    DEFAULT_NAMESPACE_MAX_SCALARS, DISPLAY_LABEL_MAX_SCALARS, DisplayLabel, ExternalName,
    ExternalNameMap, IdentifierDiagnosticCode, IdentifierError, IdentityKey, IdentityVersion,
    LookupNamespace, NameSpelling, SPELLING_LIMIT_BYTES, ScriptClassification, ScriptSet,
    SourceSpelling, SymbolicDomain, SymbolicIdentityDigest, SymbolicIdentityRecord,
    collision_condition, generated_alias, share_one_skeleton,
};
use gantry::portable::DiagnosticCategory;
use gantry::source::{
    DIAGNOSTIC_CODE_REGISTRY, DiagnosticPhase, validate_diagnostic_code_registry,
};
use gantry::unicode::script;

/// The model source guarded by the ambient-fact test.
const MODEL_SOURCE: &str = include_str!("../../gantry-ir/src/identifier.rs");

/// Returns one fixture scalar from its code point.
fn scalar(code: u32) -> char {
    char::from_u32(code).unwrap_or_else(|| unreachable!("fixture code point is a scalar"))
}

/// Returns one fixture string from its code points.
fn text(codes: &[u32]) -> String {
    codes.iter().copied().map(scalar).collect()
}

/// Returns the exact rendering one code-point escape produces, without spelling
/// the escape marker in this lane's own source.
fn escaped(code: u32) -> String {
    let marker = scalar(92);
    format!("{marker}u{{{code:04X}}}")
}

/// Returns one fixture declared name.
fn admitted(value: &str) -> DeclaredName {
    DeclaredName::new(value)
        .unwrap_or_else(|error| unreachable!("fixture name {value} is admitted: {error}"))
}

/// Returns one fixture compared spelling.
fn spelling(value: &str) -> NameSpelling {
    NameSpelling::new(value)
        .unwrap_or_else(|error| unreachable!("fixture spelling {value} is bounded: {error}"))
}

/// Returns one fixture canonical identity.
fn identity(domain: SymbolicDomain, value: &str) -> CanonicalSymbolicIdentity {
    CanonicalSymbolicIdentity::of_declared(domain, &admitted(value))
        .unwrap_or_else(|error| unreachable!("fixture identity {value} is derivable: {error}"))
}

/// Returns one fixture lookup namespace.
fn namespace(max_scalars: usize) -> LookupNamespace {
    LookupNamespace::new(max_scalars)
        .unwrap_or_else(|error| unreachable!("fixture maximum is positive: {error}"))
}

/// Returns the canonical encoding text of one identity.
fn canonical_text(value: &CanonicalSymbolicIdentity) -> String {
    std::str::from_utf8(value.canonical_bytes())
        .unwrap_or_else(|_| unreachable!("canonical bytes are JSON text"))
        .to_owned()
}

/// Returns one step of a small deterministic generator.
fn mixer(seed: u64) -> u64 {
    seed.wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407)
}

/// Returns one deterministic synthetic lane of bounded spellings.
fn synthetic_lane(count: usize) -> Vec<String> {
    let alphabet = [
        'a',
        'b',
        'z',
        'A',
        'B',
        'Z',
        '0',
        '9',
        '_',
        scalar(0x430),
        scalar(0x3B1),
        scalar(0xE9),
        scalar(0x131),
    ];
    let mut seed = 1_u64;
    (0..count)
        .map(|_| {
            seed = mixer(seed);
            let length = 1 + (seed % 6) as usize;
            (0..length)
                .map(|index| {
                    seed = mixer(seed.wrapping_add(index as u64));
                    alphabet[(seed % alphabet.len() as u64) as usize]
                })
                .collect::<String>()
        })
        .collect()
}

#[test]
fn one_canonical_identity_encoding_and_digest_per_domain() {
    assert_eq!(SymbolicDomain::ALL.len(), 12);
    let names = SymbolicDomain::ALL.map(SymbolicDomain::wire_name).to_vec();
    assert_eq!(names.iter().collect::<BTreeSet<_>>().len(), names.len());
    for domain in SymbolicDomain::ALL {
        assert_eq!(
            SymbolicDomain::from_wire_name(domain.wire_name()),
            Some(domain)
        );
        assert_eq!(SymbolicDomain::parse(domain.wire_name()), Ok(domain));
    }
    // A path is not an identity domain, so it cannot be decoded as one.
    assert_eq!(SymbolicDomain::from_wire_name("host-path"), None);
    assert!(matches!(
        SymbolicDomain::parse("host-path"),
        Err(IdentifierError::UnknownDomain { .. })
    ));
    let source_domains = SymbolicDomain::ALL
        .into_iter()
        .filter(|domain| domain.may_enter_source_identifier_domain())
        .collect::<Vec<_>>();
    assert_eq!(
        source_domains,
        vec![
            SymbolicDomain::SourceIdentifier,
            SymbolicDomain::PackageName,
            SymbolicDomain::NamespaceName
        ]
    );
    assert_eq!(IdentityVersion::PINNED.value(), 1);
    assert_eq!(IdentityVersion::UNICODE_VERSION, (16, 0, 0));
    assert_eq!(
        IdentityVersion::UNICODE_VERSION,
        gantry::unicode::UNICODE_VERSION
    );
    assert_eq!(IdentityVersion::NORMALIZATION, "nfc");
    assert!(matches!(
        IdentityVersion::new(2),
        Err(IdentifierError::UnsupportedIdentityVersion { version: 2 })
    ));

    let mut encodings = BTreeSet::new();
    let mut digests = BTreeSet::new();
    for domain in SymbolicDomain::ALL {
        let value = identity(domain, "paypal");
        let expected = format!(
            "{{\"canonical_name\":\"paypal\",\"domain\":\"{}\",\"identity_version\":1}}",
            domain.wire_name()
        );
        assert_eq!(canonical_text(&value), expected);
        assert_eq!(value.domain(), domain);
        assert_eq!(value.identity_version(), IdentityVersion::PINNED);
        assert_eq!(value.canonical_name(), "paypal");
        assert_eq!(
            value.as_str(),
            format!("{}:{}", domain.wire_name(), value.digest_hex())
        );
        assert_eq!(value.digest_hex().len(), 64);
        assert!(SymbolicIdentityDigest::from_hex(value.digest_hex()).is_ok());
        assert_eq!(
            CanonicalSymbolicIdentity::from_record(&value.record()),
            Ok(value.clone())
        );
        assert_eq!(
            canonical_text(&identity(domain, "paypal")),
            canonical_text(&value)
        );
        encodings.insert(canonical_text(&value));
        digests.insert(value.digest_hex().to_owned());
    }
    assert_eq!(encodings.len(), 12, "one canonical encoding per domain");
    assert_eq!(digests.len(), 12, "one canonical digest per domain");
}

#[test]
fn identity_record_rejects_an_unknown_property_and_an_unsupported_version() {
    assert_eq!(SymbolicIdentityRecord::VERSION, 1);
    assert_eq!(SymbolicIdentityRecord::PROPERTIES.len(), 3);
    if let Err(error) = SymbolicIdentityRecord::new(2, &[]) {
        assert_eq!(error.code(), None);
        assert_eq!(error.requirement(), "GNT-18.2-canonical-symbolic-identity");
    } else {
        unreachable!("an unsupported record version is rejected");
    }
    assert!(matches!(
        SymbolicIdentityRecord::new(1, &[("host_path", "/tmp/package")]),
        Err(IdentifierError::UnknownIdentityProperty { .. })
    ));
    assert!(matches!(
        SymbolicIdentityRecord::new(1, &[("domain", "tool-name"), ("domain", "tool-name")]),
        Err(IdentifierError::DuplicateIdentityProperty { .. })
    ));
    let missing = SymbolicIdentityRecord::new(1, &[("domain", "tool-name")])
        .unwrap_or_else(|_| unreachable!("known properties are accepted"));
    assert!(matches!(
        missing.identity(),
        Err(IdentifierError::MissingIdentityProperty {
            property: "identity_version"
        })
    ));
    let malformed = SymbolicIdentityRecord::new(
        1,
        &[
            ("canonical_name", "paypal"),
            ("domain", "tool-name"),
            ("identity_version", "two"),
        ],
    )
    .unwrap_or_else(|_| unreachable!("known properties are accepted"));
    assert!(matches!(
        malformed.identity(),
        Err(IdentifierError::MalformedIdentityProperty {
            property: "identity_version",
            ..
        })
    ));
    let unsupported = SymbolicIdentityRecord::new(
        1,
        &[
            ("canonical_name", "paypal"),
            ("domain", "tool-name"),
            ("identity_version", "2"),
        ],
    )
    .unwrap_or_else(|_| unreachable!("known properties are accepted"));
    assert!(matches!(
        unsupported.identity(),
        Err(IdentifierError::UnsupportedIdentityVersion { version: 2 })
    ));
    let record = SymbolicIdentityRecord::new(
        1,
        &[
            ("canonical_name", "paypal"),
            ("domain", "tool-name"),
            ("identity_version", "1"),
        ],
    )
    .unwrap_or_else(|_| unreachable!("known properties are accepted"));
    assert_eq!(record.version(), 1);
    assert_eq!(record.property("canonical_name"), Some("paypal"));
    assert_eq!(record.property("host_path"), None);
    assert_eq!(
        record.identity(),
        Ok(identity(SymbolicDomain::ToolName, "paypal"))
    );
    assert!(matches!(
        SymbolicIdentityDigest::from_hex("not-a-digest"),
        Err(IdentifierError::InvalidDigest { .. })
    ));
    let digest = identity(SymbolicDomain::ToolName, "paypal");
    assert_eq!(
        SymbolicIdentityDigest::from_hex(digest.digest_hex())
            .map(|value| value.as_str().to_owned()),
        Ok(digest.digest_hex().to_owned())
    );
}

#[test]
fn nfc_is_required_and_a_non_nfc_spelling_is_rejected_rather_than_normalized() {
    let decomposed = text(&[0x65, 0x301]);
    let composed = text(&[0xE9]);
    assert_ne!(decomposed, composed);
    if let Err(error) = SourceSpelling::new(&decomposed) {
        assert_eq!(error.code(), Some(IdentifierDiagnosticCode::NotNfc));
        assert_eq!(error.requirement(), "GNT-18.3-source-spelling-admission");
    } else {
        unreachable!("a non-NFC source spelling is rejected");
    }
    assert!(matches!(
        DeclaredName::new(&decomposed),
        Err(IdentifierError::NotNfc { .. })
    ));
    let admitted_spelling = SourceSpelling::new(&composed)
        .unwrap_or_else(|_| unreachable!("an NFC spelling is admitted"));
    assert_eq!(admitted_spelling.as_str(), composed);
    // The rejected spelling is never repaired into the admitted one.
    assert_eq!(
        CanonicalSymbolicIdentity::of_source(SymbolicDomain::SourceIdentifier, &admitted_spelling),
        Ok(identity(SymbolicDomain::SourceIdentifier, &composed))
    );
    let compared = spelling(&decomposed);
    assert!(!compared.is_admitted());
    assert!(!compared.is_canonically_normalized());
    assert!(spelling(&composed).is_canonically_normalized());
    assert_eq!(
        collision_condition(&compared, &spelling(&composed), &namespace(64))
            .map(|diagnostic| diagnostic.condition()),
        Some(CollisionCondition::Normalization)
    );
}

#[test]
fn default_ignorable_join_control_variation_selector_and_bidi_control_scalars_are_rejected() {
    let hostile = [
        (0x00AD_u32, "default-ignorable soft hyphen"),
        (0x200D, "join-control zero width joiner"),
        (0xFE0F, "variation-selector sixteen"),
        (0x202E, "bidi-control right-to-left override"),
    ];
    for (code, label) in hostile {
        let value = text(&[0x61, code, 0x62]);
        match SourceSpelling::new(&value) {
            Err(error) => {
                assert_eq!(
                    error.code(),
                    Some(IdentifierDiagnosticCode::IdentifierSecurity),
                    "{label}"
                );
                assert_eq!(
                    error.requirement(),
                    "GNT-18.3-source-spelling-admission",
                    "{label}"
                );
            }
            Ok(_) => unreachable!("{label} is rejected"),
        }
        assert!(
            matches!(
                DeclaredName::new(&value),
                Err(IdentifierError::ExcludedScalar { .. })
            ),
            "{label}"
        );
        // A hostile sequence never enters the collision relation either.
        assert!(
            matches!(
                NameSpelling::new(&value),
                Err(IdentifierError::ExcludedScalar { .. })
            ),
            "{label}"
        );
        // A lone hostile scalar is reported as excluded, not as a structural violation.
        let lone = text(&[code]);
        assert!(
            matches!(
                SourceSpelling::new(&lone),
                Err(IdentifierError::ExcludedScalar { .. })
            ),
            "{label}"
        );
    }
    assert_eq!(
        IdentifierDiagnosticCode::IdentifierSecurity.as_str(),
        "identifier-security"
    );
}

#[test]
fn a_confusable_pair_is_detected_while_distinct_spellings_stay_distinct_identities() {
    let latin = "paypal";
    let cyrillic = format!("payp{}l", scalar(0x430));
    let namespace = namespace(DEFAULT_NAMESPACE_MAX_SCALARS);
    assert!(share_one_skeleton(&spelling(latin), &spelling(&cyrillic)));
    assert_eq!(
        ConfusableSkeleton::of(latin),
        ConfusableSkeleton::of(&cyrillic)
    );
    let diagnostic = collision_condition(&spelling(latin), &spelling(&cyrillic), &namespace)
        .unwrap_or_else(|| unreachable!("one shared skeleton is a confusable collision"));
    assert_eq!(diagnostic.condition(), CollisionCondition::Confusable);
    assert_eq!(
        diagnostic.code(),
        Some(IdentifierDiagnosticCode::ConfusableCollision)
    );
    assert!(diagnostic.is_canonical_order());
    assert_ne!(diagnostic.first(), diagnostic.second());
    // A visual resemblance is never an identity.
    let left = identity(SymbolicDomain::ToolName, latin);
    let right = identity(SymbolicDomain::ToolName, &cyrillic);
    assert_ne!(left, right);
    assert_ne!(left.canonical_bytes(), right.canonical_bytes());
    assert_ne!(left.digest_hex(), right.digest_hex());
    assert_eq!(left.canonical_name(), latin);
    assert_eq!(right.canonical_name(), cyrillic);
    // The distinct spelling is admitted source syntax in its own right and still distinct.
    assert!(SourceSpelling::new(&cyrillic).is_ok());
    assert_ne!(
        SourceSpelling::new(&cyrillic).map(|value| value.as_str().to_owned()),
        SourceSpelling::new(latin).map(|value| value.as_str().to_owned())
    );
    // Two spellings that share no skeleton report no confusable collision.
    assert!(!share_one_skeleton(&spelling(latin), &spelling("paypaq")));
    assert!(collision_condition(&spelling(latin), &spelling("paypaq"), &namespace).is_none());
}

#[test]
fn script_mixing_is_reported_under_the_recommended_single_script_rule() {
    let single = ScriptClassification::of("paypal");
    assert!(single.is_recommended());
    assert_eq!(single.code(), None);
    assert_eq!(single.scripts().len(), 1);
    assert_eq!(single.scripts()[0].short_name(), "Latn");
    let mixed_name = format!("payp{}l", scalar(0x430));
    let mixed = ScriptClassification::of(&mixed_name);
    assert!(!mixed.is_recommended());
    assert_eq!(mixed.code(), Some(IdentifierDiagnosticCode::ScriptWarning));
    assert_eq!(mixed.requirement(), "GNT-18.4-confusable-and-script-policy");
    assert_eq!(mixed.scripts().len(), 2);
    assert_eq!(
        mixed
            .scripts()
            .iter()
            .map(|value| value.short_name())
            .collect::<Vec<_>>(),
        vec!["Cyrl", "Latn"]
    );
    assert_eq!(admitted(&mixed_name).script_classification(), mixed);
    assert_eq!(admitted(&mixed_name).scripts().len(), 2);
    assert!(!ScriptSet::of(&mixed_name).is_single_script());
    assert_eq!(ScriptSet::of("paypal").len(), 1);
    assert!(ScriptSet::of("paypal").is_single_script());
    // Common and Inherited scalars carry no script of their own.
    assert_eq!(admitted("item_1").scripts().len(), 1);
    assert!(admitted("item_1").scripts().is_single_script());
}

#[test]
fn the_collision_relation_is_symmetric_and_reports_all_six_conditions() {
    assert_eq!(CollisionCondition::ALL.len(), 6);
    for condition in CollisionCondition::ALL {
        assert_eq!(
            CollisionCondition::from_wire_name(condition.wire_name()),
            Some(condition)
        );
        assert_eq!(
            CollisionCondition::parse(condition.wire_name()),
            Ok(condition)
        );
    }
    assert_eq!(CollisionCondition::from_wire_name("fuzzy"), None);
    assert!(matches!(
        CollisionCondition::parse("fuzzy"),
        Err(IdentifierError::UnknownCollisionCondition { .. })
    ));

    let wide = namespace(DEFAULT_NAMESPACE_MAX_SCALARS).with_reserved_word("if");
    let narrow = namespace(4).with_reserved_word("if");
    let cyrillic = format!("payp{}l", scalar(0x430));
    let decomposed = text(&[0x65, 0x301]);
    let composed = text(&[0xE9]);
    let constructed = [
        (CollisionCondition::Exact, "paypal", "paypal", &wide),
        (CollisionCondition::Case, "paypal", "Paypal", &wide),
        (CollisionCondition::Truncation, "abcdef", "abcd", &narrow),
        (
            CollisionCondition::Normalization,
            decomposed.as_str(),
            composed.as_str(),
            &wide,
        ),
        (CollisionCondition::ReservedWord, "if", "ie", &wide),
        (
            CollisionCondition::Confusable,
            "paypal",
            cyrillic.as_str(),
            &wide,
        ),
    ];
    let mut reported = Vec::new();
    for (condition, left, right, facts) in constructed {
        let forward = collision_condition(&spelling(left), &spelling(right), facts);
        let backward = collision_condition(&spelling(right), &spelling(left), facts);
        assert_eq!(forward, backward, "{condition:?} is symmetric");
        let diagnostic: CollisionDiagnostic = forward
            .unwrap_or_else(|| unreachable!("{condition:?} is reported for the constructed pair"));
        assert_eq!(diagnostic.condition(), condition);
        assert!(diagnostic.is_canonical_order());
        assert!(diagnostic.first() <= diagnostic.second());
        assert_eq!(diagnostic.requirement(), "GNT-18.6-collision-relation");
        reported.push(condition);
    }
    reported.sort_unstable();
    let mut all = CollisionCondition::ALL.to_vec();
    all.sort_unstable();
    assert_eq!(
        reported, all,
        "every condition of the vocabulary is reported"
    );
    // Only the confusable condition has a published code, and no condition borrows one.
    for condition in CollisionCondition::ALL {
        let expected = if condition == CollisionCondition::Confusable {
            Some(IdentifierDiagnosticCode::ConfusableCollision)
        } else {
            None
        };
        assert_eq!(condition.code(), expected);
    }

    // Exhaustive symmetry and canonical pair order over a fixed and a generated lane.
    let mut lane = vec![
        "paypal".to_owned(),
        "Paypal".to_owned(),
        "PAYPAL".to_owned(),
        cyrillic.clone(),
        "if".to_owned(),
        "ie".to_owned(),
        "abcdef".to_owned(),
        "abcd".to_owned(),
        "abcdwxyz".to_owned(),
        decomposed.clone(),
        composed.clone(),
        "item_1".to_owned(),
    ];
    lane.extend(synthetic_lane(24));
    let spellings = lane.iter().map(|value| spelling(value)).collect::<Vec<_>>();
    assert!(spellings.len() >= 36);
    for left in &spellings {
        for right in &spellings {
            let forward = collision_condition(left, right, &wide);
            let backward = collision_condition(right, left, &wide);
            assert_eq!(forward, backward, "the relation is symmetric over the lane");
            if let Some(diagnostic) = forward {
                assert!(diagnostic.is_canonical_order());
                let smaller = if left.as_str() <= right.as_str() {
                    left.as_str()
                } else {
                    right.as_str()
                };
                assert_eq!(diagnostic.first(), smaller);
            }
        }
    }
}

#[test]
fn reserved_word_occupancy_is_rejected_in_a_lookup_namespace() {
    let facts = namespace(64)
        .with_reserved_word("else")
        .with_reserved_word("if");
    assert_eq!(
        facts.reserved_words().collect::<Vec<_>>(),
        vec!["else", "if"]
    );
    assert!(facts.is_reserved_word("if"));
    assert!(!facts.is_reserved_word("ie"));
    match facts.admit(SymbolicDomain::ToolName, &spelling("if")) {
        Err(error) => {
            assert!(matches!(
                &error,
                IdentifierError::ReservedWordUnusable { domain, name }
                    if *domain == SymbolicDomain::ToolName && name.as_ref() == "if"
            ));
            assert_eq!(error.code(), None);
            assert_eq!(error.requirement(), "GNT-18.5-reserved-word-occupancy");
        }
        Ok(_) => unreachable!("a reserved word is never usable in a lookup namespace"),
    }
    assert!(matches!(
        facts.canonical_name(SymbolicDomain::ToolName, &spelling("if")),
        Err(IdentifierError::ReservedWordUnusable { .. })
    ));
    // Reserved-word precedence is lexical and applies before any declared name resolves.
    let narrow = namespace(4).with_reserved_word("abcdefgh");
    assert!(matches!(
        narrow.admit(SymbolicDomain::ToolName, &spelling("abcdefgh")),
        Err(IdentifierError::ReservedWordUnusable { .. })
    ));
    // A name beyond the declared maximum fails naming the domain, the maximum, and the name.
    match narrow.admit(SymbolicDomain::ToolName, &spelling("abcdef")) {
        Err(error) => {
            assert!(matches!(
                &error,
                IdentifierError::NameExceedsMaximum { domain, maximum, name }
                    if *domain == SymbolicDomain::ToolName
                        && *maximum == 4
                        && name.as_ref() == "abcdef"
            ));
            assert_eq!(error.code(), None);
            assert_eq!(error.requirement(), "GNT-18.8-truncation-behaviour");
        }
        Ok(_) => unreachable!("a name beyond the declared maximum is never truncated"),
    }
    assert!(matches!(
        LookupNamespace::new(0),
        Err(IdentifierError::InvalidNamespaceMaximum { maximum: 0 })
    ));
    assert_eq!(
        facts.canonical_name(SymbolicDomain::ToolName, &spelling("paypal")),
        Ok(identity(SymbolicDomain::ToolName, "paypal"))
    );
    assert_eq!(facts.max_scalars(), 64);
}

#[test]
fn case_and_truncation_collisions_are_reported_and_never_silently_resolved() {
    let wide = namespace(DEFAULT_NAMESPACE_MAX_SCALARS);
    let narrow = namespace(4);
    // Comparison is exactly case-sensitive and never folds.
    assert_ne!(
        identity(SymbolicDomain::ToolName, "Paypal"),
        identity(SymbolicDomain::ToolName, "paypal")
    );
    let case = collision_condition(&spelling("paypal"), &spelling("Paypal"), &wide)
        .unwrap_or_else(|| unreachable!("case is a collision condition"));
    assert_eq!(case.condition(), CollisionCondition::Case);
    assert_eq!(case.code(), None);
    assert_eq!(case.first(), "Paypal");
    assert_eq!(case.second(), "paypal");
    let truncation = collision_condition(&spelling("abcdef"), &spelling("abcd"), &narrow)
        .unwrap_or_else(|| unreachable!("truncation is a collision condition"));
    assert_eq!(truncation.condition(), CollisionCondition::Truncation);
    assert_eq!(truncation.first(), "abcd");
    assert_eq!(truncation.second(), "abcdef");
    let both_beyond = collision_condition(&spelling("abcdefgh"), &spelling("abcdwxyz"), &narrow)
        .unwrap_or_else(|| unreachable!("two names beyond the maximum collide at its prefix"));
    assert_eq!(both_beyond.condition(), CollisionCondition::Truncation);
    // The declared maximum decides the relation, and the pair is never resolved by
    // preferring a declaration or a traversal order.
    assert_eq!(
        collision_condition(&spelling("abcdefgh"), &spelling("abcdwxyz"), &namespace(8)),
        None
    );
    assert_eq!(
        collision_condition(&spelling("abcd"), &spelling("abcdef"), &narrow),
        Some(truncation.clone())
    );
    assert!(truncation.is_canonical_order());
}

#[test]
fn external_names_map_injectively_or_fail_and_ignore_input_order() {
    let cyrillic = format!("payp{}l", scalar(0x430));
    let lane = [
        ExternalName::new(SymbolicDomain::ToolName, "paypal"),
        ExternalName::new(SymbolicDomain::ToolName, "Paypal"),
        ExternalName::new(SymbolicDomain::ProviderName, "paypal"),
        ExternalName::new(SymbolicDomain::PackageName, "paypal"),
        ExternalName::new(SymbolicDomain::ToolName, &cyrillic),
        ExternalName::new(SymbolicDomain::GeneratedDeclaration, "item_1"),
    ];
    let names = lane
        .into_iter()
        .map(|value| {
            value.unwrap_or_else(|error| {
                unreachable!("fixture external name is admitted as a declared name: {error}")
            })
        })
        .collect::<Vec<_>>();
    for left in &names {
        for right in &names {
            let left_identity = left
                .identity()
                .unwrap_or_else(|error| unreachable!("an external name maps: {error}"));
            let right_identity = right
                .identity()
                .unwrap_or_else(|error| unreachable!("an external name maps: {error}"));
            assert_eq!(
                left_identity == right_identity,
                left == right,
                "the external-name mapping is injective"
            );
        }
    }
    // It fails before use rather than repairing a spelling.
    assert!(matches!(
        ExternalName::new(SymbolicDomain::ToolName, &text(&[0x65, 0x301])),
        Err(IdentifierError::NotNfc { .. })
    ));
    assert!(matches!(
        ExternalName::new(
            SymbolicDomain::ToolName,
            &"a".repeat(SPELLING_LIMIT_BYTES + 1)
        ),
        Err(IdentifierError::TooLong { .. })
    ));
    // The mapping does not derive from discovery order or from an insertion order.
    let mut forward = ExternalNameMap::new();
    let mut backward = ExternalNameMap::new();
    for name in &names {
        forward
            .insert(name.clone())
            .unwrap_or_else(|error| unreachable!("the mapping is injective: {error}"));
    }
    for name in names.iter().rev() {
        backward
            .insert(name.clone())
            .unwrap_or_else(|error| unreachable!("the mapping is injective: {error}"));
    }
    assert_eq!(forward.len(), names.len());
    assert!(!forward.is_empty());
    assert_eq!(forward.canonical_bytes(), backward.canonical_bytes());
    assert_eq!(
        forward.entries().collect::<Vec<_>>(),
        backward.entries().collect::<Vec<_>>()
    );
    for name in &names {
        let value = name
            .identity()
            .unwrap_or_else(|error| unreachable!("an external name maps: {error}"));
        assert_eq!(forward.identity(name), Some(&value));
        assert_eq!(
            forward.external_name(&value),
            Some((name.domain(), name.spelling()))
        );
        assert_eq!(
            value,
            identity(name.domain(), name.spelling()),
            "the identity of an external name is its domain and its spelling"
        );
    }
}

#[test]
fn generated_aliases_are_deterministic_under_input_permutation_and_the_alias_map_round_trips() {
    // The reserved word of this namespace is the derived alias of one fixture name,
    // so the disambiguation step is exercised rather than only the escaping step.
    let namespace = namespace(DEFAULT_NAMESPACE_MAX_SCALARS).with_reserved_word("tool_if");
    let accented = format!("caf{}_1", scalar(0xE9));
    let inputs = vec![
        (SymbolicDomain::ToolName, admitted("paypal")),
        (SymbolicDomain::ToolName, admitted("Paypal")),
        (SymbolicDomain::ProviderName, admitted("paypal")),
        (SymbolicDomain::ToolName, admitted("if")),
        (SymbolicDomain::ToolName, admitted(&accented)),
        (SymbolicDomain::GeneratedDeclaration, admitted("item_1")),
    ];
    let base = AliasMap::derive(&inputs, &namespace)
        .unwrap_or_else(|error| unreachable!("aliases are derivable: {error}"));
    assert_eq!(base.len(), inputs.len());
    assert!(!base.is_empty());
    assert_eq!(base.digest_hex().len(), 64);
    assert!(!base.canonical_bytes().is_empty());
    for offset in 0..inputs.len() {
        let mut rotated = inputs.clone();
        rotated.rotate_left(offset);
        let permuted = AliasMap::derive(&rotated, &namespace)
            .unwrap_or_else(|error| unreachable!("aliases are derivable: {error}"));
        assert_eq!(permuted.canonical_bytes(), base.canonical_bytes());
        assert_eq!(permuted.digest_hex(), base.digest_hex());
        assert_eq!(
            permuted.entries().collect::<Vec<_>>(),
            base.entries().collect::<Vec<_>>()
        );
    }
    let mut reversed = inputs.clone();
    reversed.reverse();
    let reversed_map = AliasMap::derive(&reversed, &namespace)
        .unwrap_or_else(|error| unreachable!("aliases are derivable: {error}"));
    assert_eq!(reversed_map.digest_hex(), base.digest_hex());
    // Every alias round-trips and satisfies the spelling admission rules.
    for (alias, value) in base.entries() {
        assert_eq!(base.identity_of(alias), Some(value));
        assert_eq!(base.alias_of(value), Some(alias));
        assert!(
            SourceSpelling::new(alias.as_str()).is_ok(),
            "a generated alias is a legal source spelling"
        );
    }
    // A reserved word never becomes a generated alias.
    let reserved_identity = identity(SymbolicDomain::ToolName, "if");
    let reserved_alias = base
        .alias_of(&reserved_identity)
        .unwrap_or_else(|| unreachable!("the reserved-word name is mapped"));
    assert_ne!(reserved_alias.as_str(), "tool_if");
    assert!(reserved_alias.as_str().starts_with("tool_if_"));
    assert!(SourceSpelling::new(reserved_alias.as_str()).is_ok());
    // One spelling written in two domains derives two aliases, so no alias denotes
    // two identities and the reverse lookup stays a function.
    let tool_alias = base
        .alias_of(&identity(SymbolicDomain::ToolName, "paypal"))
        .unwrap_or_else(|| unreachable!("the tool name is mapped"));
    let provider_alias = base
        .alias_of(&identity(SymbolicDomain::ProviderName, "paypal"))
        .unwrap_or_else(|| unreachable!("the provider name is mapped"));
    assert_eq!(tool_alias.as_str(), "tool_paypal");
    assert_eq!(provider_alias.as_str(), "provider_paypal");
    assert_ne!(tool_alias, provider_alias);
    // The escaping and disambiguation algorithm is deterministic on its own.
    let first = generated_alias(SymbolicDomain::ToolName, &admitted(&accented), &namespace)
        .unwrap_or_else(|error| unreachable!("a free alias exists: {error}"));
    let second = generated_alias(SymbolicDomain::ToolName, &admitted(&accented), &namespace)
        .unwrap_or_else(|error| unreachable!("a free alias exists: {error}"));
    assert_eq!(first, second);
    let escaped_e_acute = format!("_u{:04X}_", 0xE9);
    let escaped_underscore = format!("_u{:04X}_", 0x5F);
    assert_eq!(
        first.as_str(),
        format!("tool_caf{escaped_e_acute}{escaped_underscore}1")
    );
}

#[test]
fn hostile_labels_render_with_code_point_escapes_and_keep_the_canonical_identity() {
    // Rendering escapes control and bidi-invisible scalars by code point, in code-point order.
    let hostile = text(&[0x61, 0x202E, 0x62, 0x202D, 0x63]);
    assert_eq!(
        DisplayLabel::escape(&hostile),
        format!("a{}b{}c", escaped(0x202E), escaped(0x202D))
    );
    assert_eq!(escaped(0x202E).chars().count(), 8);
    assert_eq!(escaped(0x202E).chars().next(), Some(scalar(92)));
    assert_eq!(escaped(0x202E).chars().last(), Some(scalar(125)));
    assert_eq!(DisplayLabel::escape("paypal"), "paypal");
    let identity = identity(SymbolicDomain::ApprovalSubject, "paypal");
    let label = DisplayLabel::new(identity.clone()).unwrap_or_else(|error| {
        unreachable!("the default bound admits the fixture label: {error}")
    });
    assert_eq!(label.as_str(), "paypal");
    assert_eq!(label.identity(), &identity);
    let other = DisplayLabel::new(identity.clone()).unwrap_or_else(|error| {
        unreachable!("the default bound admits the fixture label: {error}")
    });
    assert!(label.rendered_bytes_equal(&other));
    // A label is never the identity and never a lookup, authorization, or audit key.
    assert_ne!(label.as_str().as_bytes(), identity.canonical_bytes());
    assert_ne!(label.as_str(), identity.as_str());
    assert!(SymbolicDomain::parse(label.as_str()).is_err());
    assert_eq!(
        IdentityKey::of(label.identity()),
        IdentityKey::of(&identity)
    );
    assert_eq!(IdentityKey::of(&identity).identity(), &identity);
    assert!(label.as_str().chars().count() <= DISPLAY_LABEL_MAX_SCALARS);
    // The label is bounded: a bound it cannot meet is reported, never truncated silently.
    assert!(matches!(
        DisplayLabel::bounded(identity.clone(), 1),
        Err(IdentifierError::LabelExceedsBound { maximum: 1, .. })
    ));
    let bounded = DisplayLabel::bounded(identity.clone(), 6)
        .unwrap_or_else(|error| unreachable!("six rendered scalars fit the bound: {error}"));
    assert_eq!(bounded.as_str(), "paypal");
    assert_eq!(bounded.identity(), &identity);
}

#[test]
fn identifier_diagnostic_codes_agree_with_the_workspace_registry() {
    assert_eq!(validate_diagnostic_code_registry(), Ok(()));
    let mut meanings = Vec::new();
    for code in IdentifierDiagnosticCode::ALL {
        let definition = DIAGNOSTIC_CODE_REGISTRY
            .iter()
            .find(|definition| definition.code == code.as_str())
            .unwrap_or_else(|| unreachable!("every published identifier code is registered"));
        assert_eq!(definition.phase, DiagnosticPhase::Analysis);
        assert_eq!(definition.category, DiagnosticCategory::IdentifierSecurity);
        assert_eq!(definition.meaning, code.meaning());
        assert!(!definition.meaning.is_empty());
        assert!(code.requirement().starts_with("GNT-18."));
        assert_eq!(
            IdentifierDiagnosticCode::ALL
                .iter()
                .filter(|candidate| candidate.as_str() == code.as_str())
                .count(),
            1
        );
        meanings.push(code.meaning());
    }
    meanings.sort_unstable();
    assert!(meanings.windows(2).all(|pair| pair[0] != pair[1]));
    let registered = DIAGNOSTIC_CODE_REGISTRY
        .iter()
        .map(|definition| definition.code)
        .filter(|code| code.starts_with("identifier-"))
        .collect::<Vec<_>>();
    assert_eq!(
        registered,
        IdentifierDiagnosticCode::ALL
            .map(IdentifierDiagnosticCode::as_str)
            .to_vec()
    );
    assert_eq!(registered.len(), 4);
    assert!(registered.windows(2).all(|pair| pair[0] < pair[1]));

    // Every condition exposes its frozen code, and no condition borrows another's.
    let cyrillic = format!("payp{}l", scalar(0x430));
    let decomposed = text(&[0x65, 0x301]);
    let excluded = text(&[0x61, 0x200D, 0x62]);
    let coded = vec![
        (
            SourceSpelling::new(&decomposed)
                .err()
                .unwrap_or_else(|| unreachable!("a non-NFC spelling is rejected")),
            Some(IdentifierDiagnosticCode::NotNfc),
        ),
        (
            SourceSpelling::new(&excluded)
                .err()
                .unwrap_or_else(|| unreachable!("an excluded scalar is rejected")),
            Some(IdentifierDiagnosticCode::IdentifierSecurity),
        ),
        (
            ExternalName::new(SymbolicDomain::ToolName, &decomposed)
                .err()
                .unwrap_or_else(|| unreachable!("a non-NFC external name is rejected")),
            Some(IdentifierDiagnosticCode::NotNfc),
        ),
        (
            IdentifierError::Collision {
                first: Arc::from("paypal"),
                second: Arc::from(cyrillic.as_str()),
                condition: CollisionCondition::Confusable,
            },
            Some(IdentifierDiagnosticCode::ConfusableCollision),
        ),
        (
            IdentifierError::ScriptOutsideRecommended {
                name: Arc::from(cyrillic.as_str()),
                scripts: vec![script('a'), script(scalar(0x430))],
            },
            Some(IdentifierDiagnosticCode::ScriptWarning),
        ),
        (
            IdentifierError::Collision {
                first: Arc::from("paypal"),
                second: Arc::from("paypal"),
                condition: CollisionCondition::Exact,
            },
            None,
        ),
        (
            IdentifierError::UnknownIdentityProperty {
                property: Arc::from("host_path"),
            },
            None,
        ),
        (
            IdentifierError::DuplicateIdentityProperty {
                property: Arc::from("domain"),
            },
            None,
        ),
        (
            IdentifierError::MalformedIdentityProperty {
                property: "identity_version",
                value: Arc::from("two"),
            },
            None,
        ),
        (
            IdentifierError::ExternalNameDuplicate {
                domain: SymbolicDomain::ToolName,
                name: Arc::from("paypal"),
            },
            None,
        ),
        (
            IdentifierError::NonInjectiveMapping {
                domain: SymbolicDomain::ToolName,
                name: Arc::from("paypal"),
            },
            None,
        ),
        (
            IdentifierError::AliasDerivationFailed {
                domain: SymbolicDomain::ToolName,
                name: Arc::from("paypal"),
            },
            None,
        ),
    ];
    for (error, expected) in &coded {
        assert_eq!(error.code(), *expected, "{error}");
        assert!(error.requirement().starts_with("GNT-18."), "{error}");
        if let Some(code) = error.code() {
            assert!(code.requirement().starts_with("GNT-18."), "{error}");
        }
    }
    // A condition with no published code never borrows another condition's code.
    let uncoded = vec![
        SourceSpelling::new("")
            .err()
            .unwrap_or_else(|| unreachable!("an empty spelling is rejected")),
        SourceSpelling::new(&"a".repeat(SPELLING_LIMIT_BYTES + 1))
            .err()
            .unwrap_or_else(|| unreachable!("an over-long spelling is rejected")),
        SourceSpelling::new("1abc")
            .err()
            .unwrap_or_else(|| unreachable!("a digit may not start a spelling")),
        SourceSpelling::new("pay-pal")
            .err()
            .unwrap_or_else(|| unreachable!("a hyphen is not XID_Continue")),
        SourceSpelling::in_domain(SymbolicDomain::ToolName, "paypal")
            .err()
            .unwrap_or_else(|| unreachable!("a tool name never enters source")),
        SymbolicDomain::parse("host-path")
            .err()
            .unwrap_or_else(|| unreachable!("a path is not a domain")),
        CollisionCondition::parse("fuzzy")
            .err()
            .unwrap_or_else(|| unreachable!("a condition outside the vocabulary is an error")),
        IdentityVersion::new(2)
            .err()
            .unwrap_or_else(|| unreachable!("an unsupported version is rejected")),
        SymbolicIdentityDigest::from_hex("zz")
            .err()
            .unwrap_or_else(|| unreachable!("a malformed digest is rejected")),
        SymbolicIdentityRecord::new(2, &[])
            .err()
            .unwrap_or_else(|| unreachable!("an unsupported record version is rejected")),
        SymbolicIdentityRecord::new(1, &[("host_path", "/tmp")])
            .err()
            .unwrap_or_else(|| unreachable!("an unknown property is rejected")),
        SymbolicIdentityRecord::new(1, &[("domain", "tool-name")])
            .and_then(|record| record.identity())
            .err()
            .unwrap_or_else(|| unreachable!("a missing property is reported")),
        LookupNamespace::new(0)
            .err()
            .unwrap_or_else(|| unreachable!("a non-positive maximum is rejected")),
        namespace(4)
            .admit(SymbolicDomain::ToolName, &spelling("abcdef"))
            .err()
            .unwrap_or_else(|| unreachable!("a name beyond the maximum is rejected")),
        namespace(4)
            .with_reserved_word("abcdef")
            .admit(SymbolicDomain::ToolName, &spelling("abcdef"))
            .err()
            .unwrap_or_else(|| unreachable!("a reserved word is never usable")),
        DisplayLabel::bounded(identity(SymbolicDomain::ToolName, "paypal"), 1)
            .err()
            .unwrap_or_else(|| unreachable!("a label beyond its bound is rejected")),
    ];
    for error in &uncoded {
        assert_eq!(error.code(), None, "{error} must not borrow another code");
        assert!(error.requirement().starts_with("GNT-18."), "{error}");
    }
    // The XID admission failures and the reserved-word and truncation conditions have
    // no registered code, and none of them is reported as `identifier-security`.
    assert!(
        IdentifierError::NotXidStart { scalar: '1' }
            .code()
            .is_none()
    );
    assert!(
        IdentifierError::NotXidContinue { scalar: '-' }
            .code()
            .is_none()
    );
}

#[test]
fn no_ambient_fact_can_enter_an_identity() {
    // An identity MUST NOT derive from a host path, an environment value, a clock, a
    // locale, a discovered service, or an enumeration order, so the model declares no
    // mutable global, no interior-mutability cell, and no host filesystem, process,
    // environment, clock, path, or locale access.
    let forbidden = [
        "static mut",
        "thread_local!",
        "OnceLock",
        "RefCell",
        "Mutex",
        "std::fs",
        "std::process",
        "std::env",
        "std::path",
        "std::time",
        "SystemTime",
        "Instant",
        "PathBuf",
        "unsafe",
        "env!",
        "option_env!",
    ];
    for (index, line) in MODEL_SOURCE.lines().enumerate() {
        if line.trim_start().starts_with("//") {
            continue;
        }
        for pattern in forbidden {
            assert!(
                !line.contains(pattern),
                "crates/gantry-ir/src/identifier.rs:{} contains {pattern}",
                index + 1
            );
        }
        if line.contains("impl From<") {
            assert!(
                !line.contains("CanonicalSymbolicIdentity"),
                "an identity is not built from an ordinary representation: {}",
                index + 1
            );
        }
        if line.contains("impl") && line.contains("Display") {
            assert!(
                !line.contains("CanonicalSymbolicIdentity"),
                "a rendering is never an identity: {}",
                index + 1
            );
        }
        if line.contains("pub fn of_declared(")
            || line.contains("pub fn of_source(")
            || line.contains("pub fn of_external(")
            || line.contains("pub fn from_record(")
        {
            for ambient in [
                "path",
                "env",
                "clock",
                "time",
                "locale",
                "order",
                "discovery",
                "label",
            ] {
                assert!(
                    !line.contains(ambient),
                    "an identity constructor takes no ambient fact: {}",
                    index + 1
                );
            }
        }
    }
    // By construction: one identity is derivable through every admitted route and
    // depends on nothing else.
    let declared_identity =
        CanonicalSymbolicIdentity::of_declared(SymbolicDomain::ToolName, &admitted("paypal"))
            .unwrap_or_else(|error| unreachable!("a declared name derives an identity: {error}"));
    let external = CanonicalSymbolicIdentity::of_external(
        &ExternalName::new(SymbolicDomain::ToolName, "paypal")
            .unwrap_or_else(|error| unreachable!("an external name is admitted: {error}")),
    )
    .unwrap_or_else(|error| unreachable!("an external name derives an identity: {error}"));
    let recorded = CanonicalSymbolicIdentity::from_record(&declared_identity.record())
        .unwrap_or_else(|error| unreachable!("the record round-trips: {error}"));
    assert_eq!(declared_identity, external);
    assert_eq!(declared_identity, recorded);
    assert_eq!(
        declared_identity.canonical_bytes(),
        external.canonical_bytes()
    );
    assert_eq!(declared_identity.digest_hex(), external.digest_hex());
    let source = CanonicalSymbolicIdentity::of_source(
        SymbolicDomain::SourceIdentifier,
        &SourceSpelling::new("paypal").unwrap_or_else(|_| unreachable!("admitted")),
    )
    .unwrap_or_else(|error| unreachable!("a source spelling derives an identity: {error}"));
    assert_eq!(source, identity(SymbolicDomain::SourceIdentifier, "paypal"));
    assert_ne!(
        source, declared_identity,
        "the symbolic domain is an input of the identity"
    );
    // A label, a case variant, and a different spelling are not inputs of an identity.
    let label = DisplayLabel::new(declared_identity.clone())
        .unwrap_or_else(|error| unreachable!("the fixture label renders: {error}"));
    assert_ne!(
        label.as_str().as_bytes(),
        declared_identity.canonical_bytes()
    );
    assert_ne!(
        identity(SymbolicDomain::ToolName, "Paypal"),
        declared_identity,
        "an identity never folds case"
    );
    assert_ne!(
        identity(SymbolicDomain::ToolName, "paypals"),
        declared_identity
    );
    // Derivation is repeatable and free of any map, discovery, or traversal order.
    let names = [
        ExternalName::new(SymbolicDomain::ToolName, "paypal")
            .unwrap_or_else(|error| unreachable!("an external name is admitted: {error}")),
        ExternalName::new(SymbolicDomain::ProviderName, "paypal")
            .unwrap_or_else(|error| unreachable!("an external name is admitted: {error}")),
    ];
    let mut forward = ExternalNameMap::new();
    let mut backward = ExternalNameMap::new();
    for name in &names {
        forward
            .insert(name.clone())
            .unwrap_or_else(|error| unreachable!("the mapping is injective: {error}"));
    }
    for name in names.iter().rev() {
        backward
            .insert(name.clone())
            .unwrap_or_else(|error| unreachable!("the mapping is injective: {error}"));
    }
    assert_eq!(forward.canonical_bytes(), backward.canonical_bytes());
}
