//! Public-facade conformance for the `GNT-44.0`-`GNT-44.2` crypto foundation.
//!
//! The section declares the `std.crypto` family, its two module items, the versioned algorithm
//! identity and its exact admission rule, the frozen refusal vocabulary with its declared refusal
//! categories, the declared content-hashing algorithm with its exact vectors and input bound, and
//! the separation between these pure read-only algorithms and signing, secret-key material,
//! credentials, and protected operations: these lanes require every declared clause, module row,
//! refusal, category, vector, and bound to be published in the specification and the model, and
//! exercise the identity-admission and content-hashing rules directly.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use gantry::ir::{
    AlgorithmIdentity, CRYPTO_CLAUSES, CRYPTO_ITEMS, CryptoDiagnosticCode, CryptoError,
    CryptoModule, CryptoRefusalCategory, DECLARED_ALGORITHM_VERSION, NameClass, PackageFamily,
    SHA256_DIGEST_OCTET_LENGTH, SHA256_INPUT_OCTET_BOUND, StabilityTier,
    canonical_crypto_hierarchy, canonical_pure_hierarchy, sha256_digest,
};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap_or_else(|| panic!("conformance crate has a workspace parent"))
        .to_path_buf()
}

#[test]
fn section_44_clauses_are_published() {
    let spec = fs::read_to_string(workspace_root().join("SPEC.md"))
        .unwrap_or_else(|error| panic!("SPEC.md: {error}"));
    assert_eq!(CRYPTO_CLAUSES.len(), 3);
    let mut prior = 0_usize;
    for clause in CRYPTO_CLAUSES {
        let anchor = format!("<a id=\"{clause}\"></a>");
        let position = spec
            .find(&anchor)
            .unwrap_or_else(|| panic!("{clause} is not published"));
        assert!(
            position > prior,
            "the clauses appear in specification order"
        );
        prior = position;
        assert!(
            spec.contains(&format!("**[{clause}] ")),
            "{clause} carries no clause text"
        );
    }
    let scope_start = spec
        .find(&format!("<a id=\"{}\"></a>", CRYPTO_CLAUSES[0]))
        .unwrap_or_else(|| panic!("the scope anchor is published"));
    let contract_start = spec
        .find(&format!("<a id=\"{}\"></a>", CRYPTO_CLAUSES[1]))
        .unwrap_or_else(|| panic!("the contract anchor is published"));
    assert!(scope_start < contract_start);
    let scope = &spec[scope_start..contract_start];
    for term in [
        "`std.crypto`",
        "`hash`",
        "`signature`",
        "`crypto-unsupported-algorithm`",
        "`crypto-malformed-input`",
        "`crypto-work-limit`",
        "`GNT-35.7-bytes-and-canonical-encoding`",
    ] {
        assert!(scope.contains(term), "the scope clause must name {term}");
    }
    let hashing_start = spec
        .find(&format!("<a id=\"{}\"></a>", CRYPTO_CLAUSES[2]))
        .unwrap_or_else(|| panic!("the content-hashing anchor is published"));
    assert!(contract_start < hashing_start);
    let contract = &spec[contract_start..hashing_start];
    for term in [
        "`std.crypto::hash`",
        "`std.crypto::signature`",
        "`std.crypto::<module>::<algorithm>@<version>`",
        "`GNT-34.1-canonical-hierarchy-and-package-names`",
        "`GNT-34.2-name-classification`",
        "`GNT-34.6-stability-tiers`",
        "`sha256`",
        "`ed25519`",
        "`unsupported-algorithm`",
        "`malformed-input`",
        "`work-limit`",
        "`ExternalValue`",
    ] {
        assert!(
            contract.contains(term),
            "the contract clause must name {term}"
        );
    }
    let hashing = &spec[hashing_start..];
    for term in [
        "`std.crypto::hash::sha256@1`",
        "`SHA256_INPUT_OCTET_BOUND`",
        "`SHA256_DIGEST_OCTET_LENGTH`",
        "`sha256_digest`",
        "`Sha256Digest`",
        "`crypto-work-limit`",
        "`GNT-35.7-bytes-and-canonical-encoding`",
        "`0x6a09e667`",
        "`0x428a2f98`",
        "`0xc67178f2`",
        "`ceil((n + 9) / 64)`",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
    ] {
        assert!(
            hashing.contains(term),
            "the content-hashing clause must name {term}"
        );
    }
}

#[test]
fn crypto_surface_declares_the_two_modules() {
    let aggregate = canonical_pure_hierarchy()
        .unwrap_or_else(|error| panic!("the aggregate hierarchy is declared: {error:?}"));
    let owner = PackageFamily::Crypto.package_name();
    assert_eq!(
        aggregate
            .package(&owner)
            .unwrap_or_else(|| panic!("the aggregate hierarchy declares `{owner}`"))
            .items()
            .len(),
        0,
        "the aggregate constructor declares no family item"
    );
    let graph = canonical_crypto_hierarchy()
        .unwrap_or_else(|error| panic!("the family hierarchy is declared: {error:?}"));
    let package = graph
        .package(&owner)
        .unwrap_or_else(|| panic!("the hierarchy declares `{owner}`"));
    assert_eq!(CRYPTO_ITEMS.len(), CryptoModule::ALL.len());
    let mut expected = CryptoModule::ALL
        .iter()
        .map(|module| format!("std.crypto.{}", module.wire_name()))
        .collect::<Vec<_>>();
    expected.sort_unstable();
    assert_eq!(
        package.items().keys().cloned().collect::<Vec<_>>(),
        expected,
        "the family declares exactly one module item per declared module"
    );
    let expected_clauses: [&[&str]; 2] = [&CRYPTO_CLAUSES[..3], &CRYPTO_CLAUSES[..2]];
    for (index, (row, module)) in CRYPTO_ITEMS.iter().zip(CryptoModule::ALL).enumerate() {
        assert_eq!(row.module, module);
        assert_eq!(
            row.name,
            format!("std.crypto::{}", module.wire_name()),
            "the item name is the canonical module name"
        );
        assert_eq!(row.name, module.module_name());
        assert_eq!(row.class, NameClass::Module, "`{}` is a module", row.name);
        assert_eq!(row.tier, StabilityTier::Stable, "`{}` is stable", row.name);
        assert_eq!(
            row.clauses, expected_clauses[index],
            "`{}` publishes exactly the clauses that publish facts about its surface",
            row.name
        );
        let item = package
            .item(row.name)
            .unwrap_or_else(|| panic!("`{}` is declared", row.name));
        assert_eq!(item.class(), NameClass::Module);
        assert_eq!(item.tier(), StabilityTier::Stable);
    }
    for module in CryptoModule::ALL {
        assert_eq!(
            CryptoModule::from_module_name(module.module_name()),
            Some(module)
        );
    }
    assert!(CryptoModule::from_module_name("std.crypto::kex").is_none());
    assert!(CryptoModule::from_module_name("std.data::url").is_none());
}

#[test]
fn declared_algorithms_admit_exactly_the_declared_identity() {
    assert_eq!(DECLARED_ALGORITHM_VERSION, 1);
    for module in CryptoModule::ALL {
        let declared = AlgorithmIdentity::declared(module);
        assert_eq!(declared, module.declared_identity());
        assert_eq!(declared.module(), module);
        assert_eq!(declared.algorithm(), module.declared_algorithm());
        assert_eq!(declared.version(), DECLARED_ALGORITHM_VERSION);
        assert_eq!(
            declared.canonical_identity(),
            format!(
                "{}::{}@{}",
                module.module_name(),
                module.declared_algorithm(),
                DECLARED_ALGORITHM_VERSION
            )
        );
        assert_eq!(
            AlgorithmIdentity::admit(&declared.canonical_identity()),
            Ok(declared)
        );
        for version in [0_u16, 2_u16] {
            let presented = format!(
                "{}::{}@{version}",
                module.module_name(),
                module.declared_algorithm()
            );
            let error = match AlgorithmIdentity::admit(&presented) {
                Ok(identity) => panic!(
                    "`{presented}` must be refused, got `{}`",
                    identity.canonical_identity()
                ),
                Err(error) => error,
            };
            assert_eq!(error.code(), CryptoDiagnosticCode::UnsupportedAlgorithm);
            assert_eq!(error.requirement(), CRYPTO_CLAUSES[1]);
            assert_eq!(
                error.category(),
                CryptoRefusalCategory::UnsupportedAlgorithm
            );
            assert!(error.detail().contains(&presented), "{}", error.detail());
        }
    }
    for (presented, declared_identity) in [
        ("std.crypto::hash::sha256@01", "std.crypto::hash::sha256@1"),
        (
            "std.crypto::signature::ed25519@+1",
            "std.crypto::signature::ed25519@1",
        ),
        ("std.crypto::hash::sha512@1", "std.crypto::hash::sha256@1"),
        ("std.crypto::kex::x25519@1", "std.crypto::hash::sha256@1"),
        ("std.crypto::hash::sha256", "std.crypto::hash::sha256@1"),
        ("not-an-identity", "std.crypto::hash::sha256@1"),
    ] {
        let error = match AlgorithmIdentity::admit(presented) {
            Ok(identity) => panic!(
                "`{presented}` must be refused, got `{}`",
                identity.canonical_identity()
            ),
            Err(error) => error,
        };
        assert_eq!(error.code(), CryptoDiagnosticCode::UnsupportedAlgorithm);
        assert_eq!(error.requirement(), CRYPTO_CLAUSES[1]);
        assert_eq!(
            error.category(),
            CryptoRefusalCategory::UnsupportedAlgorithm
        );
        assert!(error.detail().contains(presented), "{}", error.detail());
        assert!(
            error.detail().contains(declared_identity),
            "the refusal names the declared identity: {}",
            error.detail()
        );
    }
}

#[test]
fn refusals_are_frozen_and_classified() {
    let mut prior: Option<&str> = None;
    let mut spellings = BTreeSet::new();
    for code in CryptoDiagnosticCode::ALL {
        let spelling = code.as_str();
        if let Some(previous) = prior {
            assert!(
                previous < spelling,
                "the refusal registry is sorted: {previous} then {spelling}"
            );
        }
        prior = Some(spelling);
        assert!(
            spellings.insert(spelling),
            "one distinct spelling per refusal"
        );
        assert!(
            !code.meaning().is_empty(),
            "every refusal publishes a meaning"
        );
        assert_eq!(code.requirement(), CRYPTO_CLAUSES[1]);
        assert!(CRYPTO_CLAUSES.contains(&code.requirement()));
    }
    assert_eq!(spellings.len(), CryptoDiagnosticCode::ALL.len());
    assert_eq!(
        spellings.iter().copied().collect::<Vec<_>>(),
        vec![
            "crypto-malformed-input",
            "crypto-unsupported-algorithm",
            "crypto-work-limit"
        ]
    );
    assert_eq!(
        CryptoDiagnosticCode::MalformedInput.category(),
        CryptoRefusalCategory::MalformedInput
    );
    assert_eq!(
        CryptoDiagnosticCode::UnsupportedAlgorithm.category(),
        CryptoRefusalCategory::UnsupportedAlgorithm
    );
    assert_eq!(
        CryptoDiagnosticCode::WorkLimit.category(),
        CryptoRefusalCategory::WorkLimit
    );
    let error = CryptoError::new(CryptoDiagnosticCode::WorkLimit, "octet 3");
    assert_eq!(error.code(), CryptoDiagnosticCode::WorkLimit);
    assert_eq!(error.code().as_str(), "crypto-work-limit");
    assert_eq!(error.detail(), "octet 3");
    assert_eq!(error.requirement(), CRYPTO_CLAUSES[1]);
    assert_eq!(error.category(), CryptoRefusalCategory::WorkLimit);
    assert_eq!(
        CryptoRefusalCategory::ALL
            .iter()
            .map(|category| category.wire_name())
            .collect::<Vec<_>>(),
        vec!["malformed-input", "unsupported-algorithm", "work-limit"]
    );
    let mut wire_spellings = BTreeSet::new();
    for category in CryptoRefusalCategory::ALL {
        assert!(
            wire_spellings.insert(category.wire_name()),
            "one wire spelling per refusal category"
        );
        assert_eq!(
            CryptoRefusalCategory::from_wire_name(category.wire_name()),
            Some(category)
        );
    }
    assert!(CryptoRefusalCategory::from_wire_name("not-a-category").is_none());
}

/// Decodes one declared lowercase-hexadecimal vector into its digest octets.
fn declared_octets(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len(), SHA256_DIGEST_OCTET_LENGTH * 2);
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |octet: u8| match octet {
                b'0'..=b'9' => octet - b'0',
                b'a'..=b'f' => octet - b'a' + 10,
                _ => panic!("a declared vector is lowercase hexadecimal"),
            };
            digit(pair[0]) * 16 + digit(pair[1])
        })
        .collect()
}

#[test]
fn sha256_digests_match_the_declared_vectors() {
    let vectors = [
        (
            "",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        (
            "abc",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ),
        (
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        ),
        (
            "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
            "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
        ),
    ];
    for (message, vector) in vectors {
        let published = sha256_digest(message.as_bytes())
            .unwrap_or_else(|error| panic!("`{message}` is admitted: {error:?}"));
        assert_eq!(
            published.octets().as_slice(),
            declared_octets(vector).as_slice(),
            "the declared vector of `{message}` is published"
        );
    }
    let long = vec![b'a'; 1_000_000];
    let published = sha256_digest(&long)
        .unwrap_or_else(|error| panic!("the declared vector is admitted: {error:?}"));
    assert_eq!(
        published.octets().as_slice(),
        declared_octets("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0")
            .as_slice(),
        "the one-million-octet declared vector is published"
    );
}

#[test]
fn sha256_input_bound_is_declared_and_enforced() {
    assert_eq!(SHA256_INPUT_OCTET_BOUND, 1_048_576);
    assert_eq!(SHA256_DIGEST_OCTET_LENGTH, 32);
    let admitted = vec![0_u8; SHA256_INPUT_OCTET_BOUND];
    let published = sha256_digest(&admitted)
        .unwrap_or_else(|error| panic!("the declared bound is admitted: {error:?}"));
    assert_eq!(published.octets().len(), SHA256_DIGEST_OCTET_LENGTH);
    let refused = vec![0_u8; SHA256_INPUT_OCTET_BOUND + 1];
    let error = match sha256_digest(&refused) {
        Ok(digest) => panic!(
            "the bound is enforced, got {} octets",
            digest.octets().len()
        ),
        Err(error) => error,
    };
    assert_eq!(error.code(), CryptoDiagnosticCode::WorkLimit);
    assert_eq!(error.code().as_str(), "crypto-work-limit");
    assert_eq!(error.requirement(), CRYPTO_CLAUSES[1]);
    assert_eq!(error.category(), CryptoRefusalCategory::WorkLimit);
    assert!(error.detail().contains("1048577"), "{}", error.detail());
    assert!(error.detail().contains("1048576"), "{}", error.detail());
}

#[test]
fn sha256_digest_is_pure_and_canonical() {
    let first = sha256_digest(b"gantry")
        .unwrap_or_else(|error| panic!("the message is admitted: {error:?}"));
    let second = sha256_digest(b"gantry")
        .unwrap_or_else(|error| panic!("the message is admitted: {error:?}"));
    assert_eq!(first, second, "equal octets publish equal digests");
    assert_eq!(first.octets().len(), SHA256_DIGEST_OCTET_LENGTH);
    let other = sha256_digest(b"gantrz")
        .unwrap_or_else(|error| panic!("the message is admitted: {error:?}"));
    assert_ne!(first, other, "distinct octets publish distinct digests");
    for length in [0_usize, 1, 55, 56, 63, 64, 65, 119, 120, 128] {
        let message = vec![0x5a_u8; length];
        let published = sha256_digest(&message)
            .unwrap_or_else(|error| panic!("{length} octets are admitted: {error:?}"));
        assert_eq!(published.octets().len(), SHA256_DIGEST_OCTET_LENGTH);
    }
}
