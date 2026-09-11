//! Machine-checked conformance for execution targets, features, and bindings.
//!
//! These tests exercise the public model of [`gantry::ir`] for `GNT-17.0`
//! through `GNT-17.13-runtime-availability-separation`. They check the pure
//! rules the specification makes normative, not a build system: no test here
//! reads an environment variable, a host path, a clock, a locale, a discovered
//! service, or a filesystem, because a target descriptor, a feature solution,
//! and an artifact binding MUST NOT be derived from those things.

use std::collections::BTreeSet;
use std::sync::Arc;

use gantry::ir::{
    AbiEnvironment, Architecture, CanonicalIrDigest, ExecutionTargetDescriptor, ExpectedInputs,
    FeatureDeclaration, FeatureDeclarations, FeatureName, FeatureSolution, FeatureSolutionDigest,
    GeneratedOutput, GeneratedOutputHash, GeneratedOutputSet, GeneratorInputs, InterfaceDigest,
    ModeAdmission, OperatingSystemFamily, PackageIdentity, PackageIdentityInputs, PackageName,
    PackageSourceIdentity, PackageVersion, PredicateOutcome, PredicateOutcomeSet,
    SelectedFeatureSet, SourceManifestDigest, TargetArtifactBinding, TargetArtifactBindingRecord,
    TargetDescriptorDigest, TargetDescriptorField, TargetDescriptorRecord, TargetDiagnosticCode,
    TargetError, TargetFactSet, TargetFactsRecord, TargetKind, TargetPredicate,
    TargetPredicateName, ToolchainIdentity,
};
use gantry::portable::DiagnosticCategory;
use gantry::protocol::ProtocolVersion;
use gantry::source::{
    DIAGNOSTIC_CODE_REGISTRY, DiagnosticPhase, validate_diagnostic_code_registry,
};
use sha2::{Digest, Sha256};

/// The model source guarded by the ambient-fact test.
const MODEL_SOURCE: &str = include_str!("../../gantry-ir/src/target.rs");

/// The exact canonical encoding of the fixture descriptor of these tests.
const CANONICAL_DESCRIPTOR: &str = concat!(
    "{\"abi\":\"gnu\",\"architecture\":\"x86_64\",\"edition\":\"2026\",",
    "\"os_family\":\"linux\",\"semantic_mode\":\"portable\",",
    "\"stdlib_contract\":{\"major\":1,\"minor\":0},\"version_of_record\":1}"
);

/// Returns one deterministic lowercase hexadecimal fixture digest.
fn hex(seed: &str) -> String {
    format!("{:x}", Sha256::digest(seed.as_bytes()))
}

/// Returns one labeled package-source-manifest digest.
fn manifest_digest(seed: &str) -> SourceManifestDigest {
    SourceManifestDigest::from_hex(&hex(seed))
        .unwrap_or_else(|_| unreachable!("fixture digest is lowercase hexadecimal"))
}

/// Returns one labeled canonical-IR digest.
fn ir_digest(seed: &str) -> CanonicalIrDigest {
    CanonicalIrDigest::from_hex(&hex(seed))
        .unwrap_or_else(|_| unreachable!("fixture digest is lowercase hexadecimal"))
}

/// Returns one standalone public-interface digest.
fn interface_digest(seed: &str) -> InterfaceDigest {
    InterfaceDigest::from_hex(&hex(seed))
        .unwrap_or_else(|_| unreachable!("fixture digest is lowercase hexadecimal"))
}

/// Returns one standalone target-descriptor digest.
fn descriptor_digest(seed: &str) -> TargetDescriptorDigest {
    TargetDescriptorDigest::from_hex(&hex(seed))
        .unwrap_or_else(|_| unreachable!("fixture digest is lowercase hexadecimal"))
}

/// Returns one standalone toolchain identity.
fn toolchain() -> ToolchainIdentity {
    ToolchainIdentity::from_hex(&hex("toolchain"))
        .unwrap_or_else(|_| unreachable!("fixture digest is lowercase hexadecimal"))
}

/// Returns the fixture package instance that owns a feature solution.
fn root(seed: &str) -> PackageIdentity {
    PackageIdentity::derive(PackageIdentityInputs::new(
        PackageName::new("app").unwrap_or_else(|_| unreachable!("fixture name is valid")),
        PackageVersion::new("1.0.0").unwrap_or_else(|_| unreachable!("fixture version is valid")),
        PackageSourceIdentity::new(
            manifest_digest(&format!("{seed}-manifest")),
            ir_digest(&format!("{seed}-ir")),
        ),
        SelectedFeatureSet::empty(),
        TargetFactSet::empty(),
        TargetFactsRecord::new(
            1,
            descriptor_digest(&format!("{seed}-descriptor")),
            FeatureSolutionDigest::from_hex(&hex(&format!("{seed}-solution")))
                .unwrap_or_else(|_| unreachable!("fixture digest is lowercase hexadecimal")),
        )
        .unwrap_or_else(|_| unreachable!("fixture selection names its version")),
        interface_digest(&format!("{seed}-interface")),
        GeneratorInputs::empty(),
    ))
}

/// Returns the fixture descriptor under the closed version-1 vocabulary.
fn descriptor_with(
    architecture: Architecture,
    operating_system: OperatingSystemFamily,
    abi_environment: AbiEnvironment,
    language_edition: &str,
    stdlib_contract: ProtocolVersion,
    mode: gantry::mode::SemanticMode,
) -> ExecutionTargetDescriptor {
    ExecutionTargetDescriptor::new(
        architecture,
        operating_system,
        abi_environment,
        language_edition,
        stdlib_contract,
        mode,
    )
    .unwrap_or_else(|_| unreachable!("fixture descriptor is well formed"))
}

/// Returns one standard-library contract version fixture.
fn stdlib(major: u64, minor: u64) -> ProtocolVersion {
    ProtocolVersion::new(major, minor).unwrap_or_else(|_| unreachable!("fixture version"))
}

/// Returns the fixture descriptor of these tests.
fn descriptor() -> ExecutionTargetDescriptor {
    descriptor_with(
        Architecture::X86_64,
        OperatingSystemFamily::Linux,
        AbiEnvironment::Gnu,
        "2026",
        stdlib(1, 0),
        gantry::mode::SemanticMode::Portable,
    )
}

/// Returns one fixture feature name.
fn feature(name: &str) -> FeatureName {
    FeatureName::new(name).unwrap_or_else(|_| unreachable!("fixture feature name is valid"))
}

/// Returns one fixture feature name list.
fn features(names: &[&str]) -> Vec<FeatureName> {
    names.iter().map(|name| feature(name)).collect()
}

/// Returns the fixture feature declarations of these tests.
fn declarations() -> FeatureDeclarations {
    FeatureDeclarations::new(&[
        FeatureDeclaration::new("a", true, &["b"])
            .unwrap_or_else(|_| unreachable!("fixture declaration is valid")),
        FeatureDeclaration::new("b", false, &[])
            .unwrap_or_else(|_| unreachable!("fixture declaration is valid")),
        FeatureDeclaration::new("c", false, &["d"])
            .unwrap_or_else(|_| unreachable!("fixture declaration is valid")),
        FeatureDeclaration::new("d", false, &[])
            .unwrap_or_else(|_| unreachable!("fixture declaration is valid")),
    ])
    .unwrap_or_else(|_| unreachable!("fixture declarations are acyclic"))
}

/// Returns one fixture feature solution over the fixture declarations.
fn solution(requested: &[&str]) -> FeatureSolution {
    FeatureSolution::unify(&declarations(), &features(requested), &root("root"))
        .unwrap_or_else(|_| unreachable!("fixture request is declared"))
}

/// Returns the fixture sealed predicate selection of these tests.
fn predicates() -> Vec<TargetPredicate> {
    vec![
        TargetPredicate::DescriptorField(TargetDescriptorField::Architecture(Architecture::X86_64)),
        TargetPredicate::DescriptorField(TargetDescriptorField::SemanticMode(
            gantry::mode::SemanticMode::Portable,
        )),
        TargetPredicate::FeatureEnabled(feature("c")),
    ]
}

/// Returns the fixture declaration of one generated output.
fn output(name: &str, seed: &str) -> GeneratedOutput {
    GeneratedOutput {
        name: Arc::from(name),
        hash: GeneratedOutputHash::from_hex(&hex(seed))
            .unwrap_or_else(|_| unreachable!("fixture digest is lowercase hexadecimal")),
    }
}

/// Returns one fixture generated-output set.
fn outputs(seed: &str) -> GeneratedOutputSet {
    GeneratedOutputSet::new(&[output("schema.json", seed)])
        .unwrap_or_else(|_| unreachable!("fixture outputs are well formed"))
}

/// Returns the fixture expected inputs of one artifact.
fn expected_inputs() -> ExpectedInputs {
    let descriptor = descriptor();
    let selected = solution(&["c"]);
    let outcomes = PredicateOutcomeSet::evaluate(
        &predicates(),
        &descriptor,
        &SelectedFeatureSet::new(&["a", "b", "c", "d"])
            .unwrap_or_else(|_| unreachable!("fixture features are valid")),
    );
    ExpectedInputs::new(
        TargetKind::Binary,
        descriptor,
        selected,
        outcomes,
        outputs("out"),
        toolchain(),
        gantry::mode::SemanticMode::Portable,
    )
    .unwrap_or_else(|_| unreachable!("fixture inputs name an admitted mode"))
}

/// Returns one fixture artifact binding.
fn fixture_binding() -> TargetArtifactBinding {
    expected_inputs()
        .bind()
        .unwrap_or_else(|_| unreachable!("fixture binding is well formed"))
}

#[test]
fn one_canonical_encoding_and_digest_for_a_descriptor() {
    let first = descriptor();
    let second = descriptor();
    // The descriptor has exactly one canonical byte encoding, and it names
    // exactly the recorded fields of `GNT-17.1-target-descriptor`.
    assert_eq!(first.normalized_bytes(), CANONICAL_DESCRIPTOR.as_bytes());
    assert_eq!(first.normalized_bytes(), second.normalized_bytes());
    assert_eq!(first.digest(), second.digest());
    assert_eq!(first.digest().as_str().len(), 64);
    assert_eq!(first.digest().as_str(), first.digest().encode_hex());
    assert_eq!(first.version(), ExecutionTargetDescriptor::VERSION);
    // The versioned record of a descriptor proves that same descriptor, and the
    // record's own version is the descriptor version.
    let record = first.record();
    assert_eq!(record.version(), TargetDescriptorRecord::VERSION);
    assert_eq!(record.descriptor(), Ok(first.clone()));
}

#[test]
fn descriptor_digest_changes_when_any_descriptor_field_changes() {
    let base = descriptor();
    let variants = [
        descriptor_with(
            Architecture::Aarch64,
            OperatingSystemFamily::Linux,
            AbiEnvironment::Gnu,
            "2026",
            stdlib(1, 0),
            gantry::mode::SemanticMode::Portable,
        ),
        descriptor_with(
            Architecture::X86_64,
            OperatingSystemFamily::Macos,
            AbiEnvironment::Gnu,
            "2026",
            stdlib(1, 0),
            gantry::mode::SemanticMode::Portable,
        ),
        descriptor_with(
            Architecture::X86_64,
            OperatingSystemFamily::Linux,
            AbiEnvironment::Musl,
            "2026",
            stdlib(1, 0),
            gantry::mode::SemanticMode::Portable,
        ),
        descriptor_with(
            Architecture::X86_64,
            OperatingSystemFamily::Linux,
            AbiEnvironment::Gnu,
            "2027",
            stdlib(1, 0),
            gantry::mode::SemanticMode::Portable,
        ),
        descriptor_with(
            Architecture::X86_64,
            OperatingSystemFamily::Linux,
            AbiEnvironment::Gnu,
            "2026",
            stdlib(1, 1),
            gantry::mode::SemanticMode::Portable,
        ),
        descriptor_with(
            Architecture::X86_64,
            OperatingSystemFamily::Linux,
            AbiEnvironment::Gnu,
            "2026",
            stdlib(1, 0),
            gantry::mode::SemanticMode::Application,
        ),
    ];
    let mut digests = BTreeSet::new();
    digests.insert(base.digest());
    for variant in &variants {
        assert_ne!(variant.normalized_bytes(), base.normalized_bytes());
        assert_ne!(variant.digest(), base.digest());
        assert!(
            digests.insert(variant.digest()),
            "every field change is a new target"
        );
    }
    assert_eq!(digests.len(), 7);
}

#[test]
fn unknown_descriptor_property_and_unsupported_version_are_rejected() {
    assert!(matches!(
        TargetDescriptorRecord::new(1, &[("host_path", "/tmp/build")]),
        Err(TargetError::DescriptorPropertyUnknown { property }) if property.as_ref() == "host_path"
    ));
    assert!(matches!(
        TargetDescriptorRecord::new(1, &[("abi", "gnu"), ("abi", "musl")]),
        Err(TargetError::DescriptorPropertyDuplicate { property }) if property.as_ref() == "abi"
    ));
    assert!(matches!(
        TargetDescriptorRecord::new(2, &[]),
        Err(TargetError::DescriptorVersionUnsupported { version: 2 })
    ));
    // A missing property is never treated as an empty property: the record is
    // rejected rather than repaired into a descriptor.
    let incomplete = TargetDescriptorRecord::new(
        1,
        &[
            ("abi", "gnu"),
            ("architecture", "x86_64"),
            ("edition", "2026"),
            ("os_family", "linux"),
        ],
    )
    .unwrap_or_else(|_| unreachable!("fixture record properties are known"));
    assert!(matches!(
        incomplete.descriptor(),
        Err(TargetError::DescriptorPropertyMissing { property })
            if property.as_ref() == "semantic_mode"
    ));
    // A field value outside the closed vocabulary of its version is invalid.
    let outside = TargetDescriptorRecord::new(
        1,
        &[
            ("abi", "gnu"),
            ("architecture", "sparc"),
            ("edition", "2026"),
            ("os_family", "linux"),
            ("semantic_mode", "portable"),
            ("stdlib_contract", "1.0"),
        ],
    )
    .unwrap_or_else(|_| unreachable!("fixture record properties are known"));
    assert!(matches!(
        outside.descriptor(),
        Err(TargetError::WireValueUnknown { field, value })
            if field == "architecture" && value.as_ref() == "sparc"
    ));
}

#[test]
fn no_ambient_fact_can_enter_a_descriptor() {
    // A target descriptor MUST NOT infer a missing field from an ambient
    // environment fact, so the model declares no mutable global, no
    // interior-mutability cell, and no host filesystem, process, environment,
    // clock, or path access. The only way to name a target here is to supply its
    // declared fields, which is what the exact canonical encoding above shows.
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
        "PathBuf",
        "unsafe",
    ];
    for (index, line) in MODEL_SOURCE.lines().enumerate() {
        if line.trim_start().starts_with("//") {
            continue;
        }
        for pattern in forbidden {
            assert!(
                !line.contains(pattern),
                "crates/gantry-ir/src/target.rs:{} contains {pattern}",
                index + 1
            );
        }
    }
    // The one descriptor constructor takes exactly the recorded fields: there is
    // no host path, environment, clock, locale, or discovered-service argument
    // to pass and no default that could supply one.
    let descriptor = descriptor();
    assert_eq!(descriptor.language_edition(), "2026");
    assert_eq!(descriptor.stdlib_contract(), stdlib(1, 0));
    assert_eq!(descriptor.mode(), gantry::mode::SemanticMode::Portable);
    assert!(
        ExecutionTargetDescriptor::new(
            Architecture::X86_64,
            OperatingSystemFamily::Linux,
            AbiEnvironment::Gnu,
            "",
            stdlib(1, 0),
            gantry::mode::SemanticMode::Portable,
        )
        .is_err(),
        "an empty edition is not inferred from ambient state"
    );
}

#[test]
fn predicate_vocabulary_is_closed() {
    assert_eq!(TargetPredicateName::ALL.len(), 2);
    assert_eq!(
        TargetPredicateName::from_wire_name("descriptor-field"),
        Some(TargetPredicateName::DescriptorField)
    );
    assert_eq!(
        TargetPredicateName::from_wire_name("feature-enabled"),
        Some(TargetPredicateName::FeatureEnabled)
    );
    // A predicate name outside the sealed table is an error rather than an
    // extension point, so no source, dependency, or build script can add one.
    assert_eq!(TargetPredicateName::from_wire_name("host-path"), None);
    assert_eq!(TargetPredicateName::from_wire_name("source-form"), None);
    assert!(matches!(
        TargetPredicate::decode("source-form", "crate::probe"),
        Err(TargetError::PredicateNameUnknown { name }) if name.as_ref() == "source-form"
    ));
    // The sealed field vocabulary is closed in both field and value.
    assert!(matches!(
        TargetPredicate::decode("descriptor-field", "host_path=/tmp"),
        Err(TargetError::WireValueUnknown { field, .. }) if field == "descriptor field"
    ));
    assert!(matches!(
        TargetPredicate::decode("descriptor-field", "architecture=sparc"),
        Err(TargetError::WireValueUnknown { field, value })
            if field == "architecture" && value.as_ref() == "sparc"
    ));
    assert_eq!(
        TargetPredicate::decode("descriptor-field", "architecture=x86_64"),
        Ok(TargetPredicate::DescriptorField(
            TargetDescriptorField::Architecture(Architecture::X86_64)
        ))
    );
    assert_eq!(
        TargetPredicate::decode("feature-enabled", "c"),
        Ok(TargetPredicate::FeatureEnabled(feature("c")))
    );
    assert!(matches!(
        TargetPredicate::decode("feature-enabled", "not a feature"),
        Err(TargetError::DeclarationInvalid { field, .. }) if field == "feature"
    ));
}

#[test]
fn predicate_evaluation_reads_only_descriptor_fields_and_declared_features() {
    let selected = SelectedFeatureSet::new(&["a", "b", "c", "d"])
        .unwrap_or_else(|_| unreachable!("fixture features are valid"));
    // Two descriptors that differ only in fields no evaluated predicate reads
    // produce the same outcomes, so the evaluated selection cannot be reading a
    // module or package graph path, another package's features, or host state.
    let linux = descriptor();
    let macos = descriptor_with(
        Architecture::X86_64,
        OperatingSystemFamily::Macos,
        AbiEnvironment::Musl,
        "2027",
        stdlib(1, 1),
        gantry::mode::SemanticMode::Portable,
    );
    let evaluated = predicates()
        .iter()
        .map(|predicate| predicate.evaluate(&linux, &selected))
        .collect::<Vec<_>>();
    let elsewhere = predicates()
        .iter()
        .map(|predicate| predicate.evaluate(&macos, &selected))
        .collect::<Vec<_>>();
    assert_eq!(evaluated, elsewhere);
    assert_eq!(
        PredicateOutcomeSet::evaluate(&predicates(), &linux, &selected),
        PredicateOutcomeSet::evaluate(&predicates(), &macos, &selected)
    );
    // A predicate whose read field does differ is unmatched, so the outcome is a
    // function of the recorded field and not of a constant.
    let aarch64 = descriptor_with(
        Architecture::Aarch64,
        OperatingSystemFamily::Linux,
        AbiEnvironment::Gnu,
        "2026",
        stdlib(1, 0),
        gantry::mode::SemanticMode::Portable,
    );
    assert!(
        !TargetPredicate::DescriptorField(TargetDescriptorField::Architecture(
            Architecture::X86_64
        ))
        .evaluate(&aarch64, &selected)
        .matched
    );
    // A feature predicate reads the declared features alone.
    let absent = SelectedFeatureSet::empty();
    assert!(
        !TargetPredicate::FeatureEnabled(feature("c"))
            .evaluate(&linux, &absent)
            .matched
    );
    assert!(
        TargetPredicate::FeatureEnabled(feature("c"))
            .evaluate(&linux, &selected)
            .matched
    );
}

#[test]
fn predicate_outcome_sets_are_order_independent() {
    let selected = SelectedFeatureSet::new(&["a", "b", "c", "d"])
        .unwrap_or_else(|_| unreachable!("fixture features are valid"));
    let descriptor = descriptor();
    let outcomes = predicates()
        .iter()
        .map(|predicate| predicate.evaluate(&descriptor, &selected))
        .collect::<Vec<_>>();
    let canonical = PredicateOutcomeSet::new(&outcomes);
    assert_eq!(canonical.len(), 3);
    assert_eq!(canonical.as_slice().len(), 3);
    let mut reversed = outcomes.clone();
    reversed.reverse();
    assert_eq!(canonical, PredicateOutcomeSet::new(&reversed));
    assert_eq!(
        canonical.digest(),
        PredicateOutcomeSet::new(&reversed).digest()
    );
    let mut rotated = outcomes.clone();
    rotated.rotate_left(1);
    assert_eq!(
        canonical.digest(),
        PredicateOutcomeSet::new(&rotated).digest()
    );
    // A duplicated outcome is one outcome.
    let duplicated = outcomes
        .iter()
        .chain(outcomes.iter())
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(
        canonical.digest(),
        PredicateOutcomeSet::new(&duplicated).digest()
    );
    // The recorded order is the canonical order, and it is sorted.
    let mut sorted = canonical.as_slice().to_vec();
    sorted.sort();
    assert_eq!(canonical.as_slice(), sorted.as_slice());
    assert_eq!(PredicateOutcomeSet::empty().len(), 0);
    // The matched flag is part of the outcome, so a differing evaluation is a
    // different recorded outcome rather than the same one.
    assert_ne!(
        PredicateOutcomeSet::new(&[PredicateOutcome::new(predicates()[2].clone(), false)]).digest(),
        PredicateOutcomeSet::new(&[PredicateOutcome::new(predicates()[2].clone(), true)]).digest()
    );
}

#[test]
fn feature_declarations_reject_cycles_unknown_names_and_duplicates() {
    let declaration = |name: &str, enables: &[&str]| {
        FeatureDeclaration::new(name, false, enables)
            .unwrap_or_else(|_| unreachable!("fixture declaration is valid"))
    };
    // A cycle is invalid rather than ignored, and it reports the offending names.
    let cycle = FeatureDeclarations::new(&[declaration("a", &["b"]), declaration("b", &["a"])]);
    match cycle {
        Err(TargetError::FeatureCycle { cycle }) => {
            let names = cycle.iter().map(FeatureName::as_str).collect::<Vec<_>>();
            assert_eq!(names, vec!["a", "b"]);
        }
        other => unreachable!("a cycle is reported as a cycle: {other:?}"),
    }
    assert!(matches!(
        FeatureDeclarations::new(&[declaration("a", &["a"])]),
        Err(TargetError::FeatureCycle { cycle }) if cycle.as_slice() == [feature("a")].as_slice()
    ));
    // A cycle is found wherever it lies, not only at the first declaration.
    assert!(matches!(
        FeatureDeclarations::new(&[
            declaration("x", &["y"]),
            declaration("y", &["z"]),
            declaration("z", &["x"]),
        ]),
        Err(TargetError::FeatureCycle { .. })
    ));
    // An enabling relation that names an undeclared feature is invalid.
    assert!(matches!(
        FeatureDeclarations::new(&[declaration("a", &["missing"])]),
        Err(TargetError::FeatureUnknown { name }) if name == feature("missing")
    ));
    // One feature declared twice by one instance is invalid.
    assert!(matches!(
        FeatureDeclarations::new(&[declaration("a", &[]), declaration("a", &["b"]), declaration("b", &[])]),
        Err(TargetError::FeatureDeclarationDuplicate { name }) if name == feature("a")
    ));
    // Declaration order never changes which names are reported.
    let first = FeatureDeclarations::new(&[declaration("a", &["b"]), declaration("b", &["a"])]);
    let second = FeatureDeclarations::new(&[declaration("b", &["a"]), declaration("a", &["b"])]);
    assert_eq!(first, second);
    assert_eq!(declarations().len(), 4);
    assert_eq!(declarations().defaults(), vec![feature("a")]);
}

#[test]
fn feature_unification_is_deterministic_under_requested_order_permutation() {
    let requested = features(&["c", "b"]);
    let permutations = [
        requested.clone(),
        vec![requested[1].clone(), requested[0].clone()],
    ];
    assert_ne!(permutations[0], permutations[1]);
    let first = FeatureSolution::unify(&declarations(), &permutations[0], &root("root"))
        .unwrap_or_else(|_| unreachable!("fixture request is declared"));
    // The selected set is the acyclic closure of the requested features and the
    // default selection, in canonical order.
    assert_eq!(
        first
            .selected()
            .iter()
            .map(FeatureName::as_str)
            .collect::<Vec<_>>(),
        vec!["a", "b", "c", "d"]
    );
    assert!(first.contains(&feature("d")));
    for permutation in &permutations {
        let permuted = FeatureSolution::unify(&declarations(), permutation, &root("root"))
            .unwrap_or_else(|_| unreachable!("fixture request is declared"));
        assert_eq!(permuted.selected(), first.selected());
        assert_eq!(permuted.digest(), first.digest());
        assert_eq!(permuted, first);
        assert_eq!(
            TargetFactsRecord::for_selection(&descriptor(), &permuted).map(|facts| facts.digest()),
            TargetFactsRecord::for_selection(&descriptor(), &first).map(|facts| facts.digest())
        );
    }
    // The same requested set in any order yields exactly one solution for one
    // package instance, and the solution names that instance.
    assert_eq!(first.root(), &root("root"));
    // The digest is a pure function of the selected features, so two instances
    // that select the same features share the solution digest, while the root
    // still names the owning instance.
    let elsewhere = FeatureSolution::unify(&declarations(), &features(&["c"]), &root("other"))
        .unwrap_or_else(|_| unreachable!("fixture request is declared"));
    assert_eq!(elsewhere.selected(), solution(&["c"]).selected());
    assert_eq!(elsewhere.digest(), solution(&["c"]).digest());
    assert_ne!(elsewhere.root(), solution(&["c"]).root());
}

#[test]
fn differing_feature_requests_produce_differing_solutions_and_facts_records() {
    let empty_request = FeatureSolution::unify(&declarations(), &[], &root("root"))
        .unwrap_or_else(|_| unreachable!("an empty request is satisfiable"));
    let selected_request = solution(&["c"]);
    assert_ne!(empty_request.selected(), selected_request.selected());
    assert_ne!(empty_request.digest(), selected_request.digest());
    let empty_facts = TargetFactsRecord::for_selection(&descriptor(), &empty_request)
        .unwrap_or_else(|_| unreachable!("fixture facts are supported"));
    let selected_facts = TargetFactsRecord::for_selection(&descriptor(), &selected_request)
        .unwrap_or_else(|_| unreachable!("fixture facts are supported"));
    assert_ne!(
        empty_facts.canonical_bytes(),
        selected_facts.canonical_bytes()
    );
    assert_ne!(empty_facts.digest(), selected_facts.digest());
    // A request the instance cannot satisfy is a static error rather than a
    // preference, and it names the instance and the offending declarations.
    match FeatureSolution::unify(&declarations(), &features(&["missing"]), &root("root")) {
        Err(TargetError::FeatureRequestUnsatisfiable {
            root: owner,
            requested,
        }) => {
            assert_eq!(*owner, root("root"));
            assert_eq!(requested, vec![feature("missing")]);
        }
        other => unreachable!("an unsatisfiable request is reported: {other:?}"),
    }
}

#[test]
fn feature_solution_digest_participates_in_the_facts_record_digest() {
    let facts = TargetFactsRecord::for_selection(&descriptor(), &solution(&["c"]))
        .unwrap_or_else(|_| unreachable!("fixture facts are supported"));
    assert_eq!(
        facts.descriptor_version(),
        ExecutionTargetDescriptor::VERSION
    );
    assert_eq!(facts.descriptor_digest(), &descriptor().digest());
    assert_eq!(facts.feature_solution_digest(), solution(&["c"]).digest());
    assert_eq!(
        facts.canonical_bytes(),
        TargetFactsRecord::for_selection(&descriptor(), &solution(&["c"]))
            .unwrap_or_else(|_| unreachable!("fixture facts are supported"))
            .canonical_bytes()
    );
    // Changing only the feature solution changes the facts and their digest.
    let other = TargetFactsRecord::for_selection(&descriptor(), &solution(&["b"]))
        .unwrap_or_else(|_| unreachable!("fixture facts are supported"));
    assert_eq!(other.descriptor_digest(), facts.descriptor_digest());
    assert_ne!(
        other.feature_solution_digest(),
        facts.feature_solution_digest()
    );
    assert_ne!(other.digest(), facts.digest());
    // The facts are the descriptor version, the normalized descriptor digest,
    // and the feature-solution digest, and an unsupported version is rejected.
    assert_eq!(
        TargetFactsRecord::new(
            ExecutionTargetDescriptor::VERSION,
            descriptor().digest(),
            solution(&["c"]).digest().clone(),
        )
        .map(|facts| facts.digest()),
        Ok(facts.digest())
    );
    assert_eq!(
        TargetFactsRecord::new(2, descriptor_digest("d"), solution(&["c"]).digest().clone()),
        Err(TargetError::DescriptorVersionUnsupported { version: 2 })
    );
    // Target facts are composed with the declared kind and entry-point facts
    // elsewhere; the landed identity inputs are unchanged here.
    assert_eq!(
        TargetFactsRecord::VERSION,
        ExecutionTargetDescriptor::VERSION
    );
}

#[test]
fn mode_admission_admits_and_rejects_for_every_target_kind() {
    let modes = [
        gantry::mode::SemanticMode::Portable,
        gantry::mode::SemanticMode::Application,
        gantry::mode::SemanticMode::Durable,
    ];
    for (kind, admitted) in ModeAdmission::TABLE {
        assert_eq!(ModeAdmission::admitted_modes(kind), admitted);
        for mode in modes {
            let admits = admitted.contains(&mode);
            assert_eq!(ModeAdmission::admits(kind, mode), admits);
            let verdict = if admits {
                Ok(())
            } else {
                Err(TargetError::ModeNotAdmitted { kind, mode })
            };
            assert_eq!(ModeAdmission::admit_mode(kind, mode), verdict);
        }
        assert!(!admitted.is_empty(), "every kind admits at least one mode");
    }
    // A non-shipping kind admits only the portable mode, and a library declares
    // no entry point, so durable execution is not admitted for either.
    for kind in [TargetKind::Test, TargetKind::Example, TargetKind::Benchmark] {
        assert!(matches!(
            ModeAdmission::admit_mode(kind, gantry::mode::SemanticMode::Durable),
            Err(TargetError::ModeNotAdmitted { kind: reported, mode })
                if reported == kind && mode == gantry::mode::SemanticMode::Durable
        ));
        assert!(matches!(
            ModeAdmission::admit_mode(kind, gantry::mode::SemanticMode::Application),
            Err(TargetError::ModeNotAdmitted { kind: reported, .. }) if reported == kind
        ));
        assert_eq!(
            ModeAdmission::admit_mode(kind, gantry::mode::SemanticMode::Portable),
            Ok(())
        );
    }
    assert!(matches!(
        ModeAdmission::admit_mode(TargetKind::Library, gantry::mode::SemanticMode::Durable),
        Err(TargetError::ModeNotAdmitted {
            kind: TargetKind::Library,
            ..
        })
    ));
    // A shipping binary target admits the whole closed `GNT-3.1` vocabulary, so
    // no mode is unadmitted for it; nothing else may add a mode to that row.
    assert_eq!(
        ModeAdmission::admitted_modes(TargetKind::Binary),
        modes.as_slice()
    );
    assert!(
        modes
            .iter()
            .all(|mode| ModeAdmission::admit_mode(TargetKind::Binary, *mode) == Ok(()))
    );
}

#[test]
fn artifact_binding_digest_changes_when_any_bound_input_changes() {
    let binding = fixture_binding();
    assert_eq!(
        binding.descriptor_version(),
        ExecutionTargetDescriptor::VERSION
    );
    assert_eq!(binding.descriptor_digest(), &descriptor().digest());
    assert_eq!(binding.feature_solution_digest(), solution(&["c"]).digest());
    assert_eq!(binding.generated_outputs(), &outputs("out"));
    assert_eq!(binding.toolchain(), &toolchain());
    assert_eq!(binding.mode(), gantry::mode::SemanticMode::Portable);
    // Every bound input participates in the binding digest.
    let variants = [
        TargetArtifactBinding::new(
            ExecutionTargetDescriptor::VERSION,
            descriptor_digest("other-descriptor"),
            binding.feature_solution_digest().clone(),
            binding.predicate_outcome_digest().clone(),
            binding.generated_outputs().clone(),
            binding.toolchain().clone(),
            binding.mode(),
        ),
        TargetArtifactBinding::new(
            ExecutionTargetDescriptor::VERSION,
            binding.descriptor_digest().clone(),
            solution(&["b"]).digest().clone(),
            binding.predicate_outcome_digest().clone(),
            binding.generated_outputs().clone(),
            binding.toolchain().clone(),
            binding.mode(),
        ),
        TargetArtifactBinding::new(
            ExecutionTargetDescriptor::VERSION,
            binding.descriptor_digest().clone(),
            binding.feature_solution_digest().clone(),
            PredicateOutcomeSet::empty().digest(),
            binding.generated_outputs().clone(),
            binding.toolchain().clone(),
            binding.mode(),
        ),
        TargetArtifactBinding::new(
            ExecutionTargetDescriptor::VERSION,
            binding.descriptor_digest().clone(),
            binding.feature_solution_digest().clone(),
            binding.predicate_outcome_digest().clone(),
            outputs("other-out"),
            binding.toolchain().clone(),
            binding.mode(),
        ),
        TargetArtifactBinding::new(
            ExecutionTargetDescriptor::VERSION,
            binding.descriptor_digest().clone(),
            binding.feature_solution_digest().clone(),
            binding.predicate_outcome_digest().clone(),
            binding.generated_outputs().clone(),
            ToolchainIdentity::from_hex(&hex("other-toolchain"))
                .unwrap_or_else(|_| unreachable!("fixture digest is lowercase hexadecimal")),
            binding.mode(),
        ),
        TargetArtifactBinding::new(
            ExecutionTargetDescriptor::VERSION,
            binding.descriptor_digest().clone(),
            binding.feature_solution_digest().clone(),
            binding.predicate_outcome_digest().clone(),
            binding.generated_outputs().clone(),
            binding.toolchain().clone(),
            gantry::mode::SemanticMode::Application,
        ),
    ];
    let mut digests = BTreeSet::new();
    digests.insert(binding.digest());
    for variant in variants {
        let variant = variant.unwrap_or_else(|_| unreachable!("fixture binding is well formed"));
        assert_ne!(variant.canonical_bytes(), binding.canonical_bytes());
        assert!(
            digests.insert(variant.digest()),
            "every bound input change is a new artifact"
        );
    }
    assert_eq!(digests.len(), 7);
    // The same inputs bind the same artifact, and a binding that disagrees with
    // the expected inputs is reported rather than repaired.
    assert_eq!(
        fixture_binding().digest(),
        expected_inputs()
            .bind()
            .unwrap_or_else(|_| unreachable!("fixture binding is well formed"))
            .digest()
    );
    assert_eq!(fixture_binding().check_matches(&expected_inputs()), Ok(()));
    let diverged = TargetArtifactBinding::new(
        ExecutionTargetDescriptor::VERSION,
        descriptor_digest("other-descriptor"),
        binding.feature_solution_digest().clone(),
        binding.predicate_outcome_digest().clone(),
        binding.generated_outputs().clone(),
        binding.toolchain().clone(),
        binding.mode(),
    )
    .unwrap_or_else(|_| unreachable!("fixture binding is well formed"));
    assert!(matches!(
        diverged.check_matches(&expected_inputs()),
        Err(TargetError::ArtifactBindingMismatch { field, expected, observed })
            if field == "descriptor_sha256"
                && expected.as_ref() == descriptor().digest().as_str()
                && observed.as_ref() == descriptor_digest("other-descriptor").as_str()
    ));
    // The divergent binding was neither repaired nor re-bound to the expected
    // inputs: it still records the descriptor digest it bound.
    assert_eq!(
        diverged.descriptor_digest(),
        &descriptor_digest("other-descriptor")
    );
    assert_ne!(diverged.digest(), binding.digest());
}

#[test]
fn binding_with_a_missing_input_or_unsupported_version_is_rejected_not_repaired() {
    let binding = fixture_binding();
    let record = binding.record();
    assert_eq!(record.version(), TargetArtifactBindingRecord::VERSION);
    assert_eq!(record.binding(), Ok(binding.clone()));
    // A binding that omits a bound input is rejected rather than repaired.
    let incomplete = TargetArtifactBindingRecord::new(
        1,
        &[
            ("descriptor_sha256", binding.descriptor_digest().as_str()),
            ("descriptor_version", "1"),
            (
                "feature_solution_sha256",
                binding.feature_solution_digest().as_str(),
            ),
            ("generated_outputs", ""),
            (
                "predicate_outcomes_sha256",
                binding.predicate_outcome_digest().as_str(),
            ),
            ("toolchain_sha256", binding.toolchain().as_str()),
        ],
    )
    .unwrap_or_else(|_| unreachable!("fixture record properties are known"));
    assert!(matches!(
        incomplete.binding(),
        Err(TargetError::ArtifactBindingMissingInput { input }) if input == "mode"
    ));
    // An unsupported record version and an unsupported descriptor version are
    // both rejected.
    assert!(matches!(
        TargetArtifactBindingRecord::new(2, &[]),
        Err(TargetError::ArtifactBindingVersionUnsupported { version: 2 })
    ));
    assert!(matches!(
        TargetArtifactBindingRecord::new(1, &[("host_path", "/tmp")]),
        Err(TargetError::ArtifactBindingPropertyUnknown { property })
            if property.as_ref() == "host_path"
    ));
    assert!(matches!(
        TargetArtifactBindingRecord::new(1, &[("mode", "portable"), ("mode", "durable")]),
        Err(TargetError::ArtifactBindingPropertyDuplicate { property })
            if property.as_ref() == "mode"
    ));
    assert!(matches!(
        TargetArtifactBinding::new(
            2,
            binding.descriptor_digest().clone(),
            binding.feature_solution_digest().clone(),
            binding.predicate_outcome_digest().clone(),
            binding.generated_outputs().clone(),
            binding.toolchain().clone(),
            binding.mode(),
        ),
        Err(TargetError::DescriptorVersionUnsupported { version: 2 })
    ));
    // An expected input record cannot name a mode the selected kind does not
    // admit, and a mode that disagrees with the descriptor is reported.
    assert!(matches!(
        ExpectedInputs::new(
            TargetKind::Test,
            descriptor(),
            solution(&["c"]),
            PredicateOutcomeSet::empty(),
            outputs("out"),
            toolchain(),
            gantry::mode::SemanticMode::Durable,
        ),
        Err(TargetError::ModeNotAdmitted {
            kind: TargetKind::Test,
            ..
        })
    ));
    assert!(matches!(
        ExpectedInputs::new(
            TargetKind::Binary,
            descriptor(),
            solution(&["c"]),
            PredicateOutcomeSet::empty(),
            outputs("out"),
            toolchain(),
            gantry::mode::SemanticMode::Application,
        ),
        Err(TargetError::ArtifactBindingMismatch { field, .. }) if field == "semantic_mode"
    ));
}

#[test]
fn every_target_diagnostic_code_is_registered_sorted_unique_with_a_non_empty_meaning() {
    assert_eq!(validate_diagnostic_code_registry(), Ok(()));
    let mut meanings = Vec::new();
    for code in TargetDiagnosticCode::ALL {
        let definition = DIAGNOSTIC_CODE_REGISTRY
            .iter()
            .find(|definition| definition.code == code.as_str())
            .unwrap_or_else(|| unreachable!("every published target code is registered"));
        assert_eq!(definition.phase, DiagnosticPhase::Package);
        assert_eq!(definition.category, DiagnosticCategory::Package);
        assert!(!definition.meaning.is_empty());
        assert_eq!(definition.meaning, code.meaning());
        assert!(code.requirement().starts_with("GNT-17."));
        assert_eq!(
            TargetDiagnosticCode::ALL
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
        .filter(|code| code.starts_with("target-") && *code != "target-capture-ineligible")
        .collect::<Vec<_>>();
    assert_eq!(
        registered,
        TargetDiagnosticCode::ALL
            .map(TargetDiagnosticCode::as_str)
            .to_vec()
    );
    assert_eq!(registered.len(), 18);
    assert!(registered.windows(2).all(|pair| pair[0] < pair[1]));
    // Every condition of the target model exposes one of those frozen codes, and
    // no condition borrows another condition's code.
    let declared = vec![
        TargetError::ArtifactBindingMismatch {
            field: "mode",
            expected: Arc::from("portable"),
            observed: Arc::from("durable"),
        },
        TargetError::ArtifactBindingMissingInput { input: "mode" },
        TargetError::ArtifactBindingPropertyDuplicate {
            property: Arc::from("mode"),
        },
        TargetError::ArtifactBindingPropertyUnknown {
            property: Arc::from("host_path"),
        },
        TargetError::ArtifactBindingVersionUnsupported { version: 2 },
        TargetError::DeclarationInvalid {
            field: "feature",
            value: Arc::from("not a feature"),
        },
        TargetError::DescriptorDigestInvalid {
            value: Arc::from("not-a-digest"),
        },
        TargetError::DescriptorPropertyDuplicate {
            property: Arc::from("abi"),
        },
        TargetError::DescriptorPropertyMissing {
            property: Arc::from("abi"),
        },
        TargetError::DescriptorPropertyUnknown {
            property: Arc::from("host_path"),
        },
        TargetError::DescriptorVersionUnsupported { version: 2 },
        TargetError::FeatureCycle {
            cycle: vec![feature("a")],
        },
        TargetError::FeatureDeclarationDuplicate { name: feature("a") },
        TargetError::FeatureRequestUnsatisfiable {
            root: Box::new(root("root")),
            requested: vec![feature("missing")],
        },
        TargetError::FeatureUnknown {
            name: feature("missing"),
        },
        TargetError::ModeNotAdmitted {
            kind: TargetKind::Test,
            mode: gantry::mode::SemanticMode::Durable,
        },
        TargetError::PredicateNameUnknown {
            name: Arc::from("source-form"),
        },
        TargetError::WireValueUnknown {
            field: "architecture",
            value: Arc::from("sparc"),
        },
    ];
    assert_eq!(declared.len(), TargetDiagnosticCode::ALL.len());
    for error in &declared {
        assert!(TargetDiagnosticCode::ALL.contains(&error.code()));
        assert_eq!(error.requirement(), error.code().requirement());
        assert!(error.requirement().starts_with("GNT-17."));
    }
    let mut codes = declared.iter().map(TargetError::code).collect::<Vec<_>>();
    codes.sort();
    assert_eq!(codes, TargetDiagnosticCode::ALL.to_vec());
    // Each condition is also renderable without exposing host state.
    assert!(!declared[0].to_string().is_empty());
}
