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
    AbiEnvironment, Architecture, BranchDeclaration, BranchMatch, BranchOutcome, CanonicalIrDigest,
    ConditionalSelectionRule, DeclaredFactKind, DeclaredFacts, ExecutionTargetDescriptor,
    ExpectedInputs, FeatureDeclaration, FeatureDeclarations, FeatureName, FeatureSolution,
    FeatureSolutionDigest, GeneratedOutput, GeneratedOutputHash, GeneratedOutputSet,
    GeneratorInputs, InterfaceDigest, ModeAdmission, OperatingSystemFamily, PackageIdentity,
    PackageIdentityInputs, PackageName, PackageSourceIdentity, PackageVersion, PredicateOutcome,
    PredicateOutcomeSet, RetainedClosure, RetainedClosureDigest, SelectedFeatureSet,
    SourceManifestDigest, TargetArtifactBinding, TargetArtifactBindingRecord,
    TargetDescriptorDigest, TargetDescriptorField, TargetDescriptorRecord, TargetDiagnosticCode,
    TargetError, TargetFactSet, TargetFactsRecord, TargetKind, TargetMatrix, TargetMatrixDigest,
    TargetMatrixEntry, TargetMatrixState, TargetPredicate, TargetPredicateName, ToolchainIdentity,
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
    let declaring = declaring();
    FeatureDeclarations::new(
        &declaring,
        &[
            FeatureDeclaration::new(&declaring, "a", true, &["b"])
                .unwrap_or_else(|_| unreachable!("fixture declaration is valid")),
            FeatureDeclaration::new(&declaring, "b", false, &[])
                .unwrap_or_else(|_| unreachable!("fixture declaration is valid")),
            FeatureDeclaration::new(&declaring, "c", false, &["d"])
                .unwrap_or_else(|_| unreachable!("fixture declaration is valid")),
            FeatureDeclaration::new(&declaring, "d", false, &[])
                .unwrap_or_else(|_| unreachable!("fixture declaration is valid")),
        ],
    )
    .unwrap_or_else(|_| unreachable!("fixture declarations are acyclic"))
}

/// Returns the fixture declaring package instance of these tests.
fn declaring() -> PackageIdentity {
    root("root")
}

/// Returns one fixture feature solution over the fixture declarations.
fn solution(requested: &[&str]) -> FeatureSolution {
    FeatureSolution::unify(&declarations(), &features(requested), &declaring())
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
    GeneratedOutput::new(
        &declaring(),
        name,
        &GeneratedOutputHash::from_hex(&hex(seed))
            .unwrap_or_else(|_| unreachable!("fixture digest is lowercase hexadecimal")),
    )
    .unwrap_or_else(|_| unreachable!("fixture output name is a legal declared name"))
}

/// Returns one fixture generated-output set.
fn outputs(seed: &str) -> GeneratedOutputSet {
    GeneratedOutputSet::new(&declaring(), &[output("schema.json", seed)])
        .unwrap_or_else(|_| unreachable!("fixture outputs are well formed"))
}

/// Returns the fixture expected inputs of one artifact.
fn expected_inputs() -> ExpectedInputs {
    ExpectedInputs::new(
        &declaring(),
        TargetKind::Binary,
        descriptor(),
        solution(&["c"]),
        &predicates(),
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

/// Returns the fixture descriptor that names the durable mode.
fn durable_descriptor() -> ExecutionTargetDescriptor {
    descriptor_with(
        Architecture::X86_64,
        OperatingSystemFamily::Linux,
        AbiEnvironment::Gnu,
        "2026",
        stdlib(1, 0),
        gantry::mode::SemanticMode::Durable,
    )
}

/// Returns the published conditional-selection rule of the declaring instance.
fn rule() -> ConditionalSelectionRule {
    ConditionalSelectionRule::new(&declaring(), ConditionalSelectionRule::IDENTITY)
        .unwrap_or_else(|_| unreachable!("the published rule identity is supported"))
}

/// Returns one declared-facts value under the closed `GNT-17.7` vocabulary.
fn facts(entries: &[(DeclaredFactKind, &str)]) -> DeclaredFacts {
    DeclaredFacts::new(&declaring(), entries)
        .unwrap_or_else(|_| unreachable!("fixture fact names are legal declared names"))
}

/// Returns one conditional branch of the declaring instance.
fn branch(guards: &[TargetPredicate], contributed: DeclaredFacts) -> BranchDeclaration {
    BranchDeclaration::new(&declaring(), rule(), guards, contributed)
}

/// Returns the guards of a declaration that every fixture predicate matches.
fn every_matched_guards() -> Vec<TargetPredicate> {
    vec![
        TargetPredicate::DescriptorField(TargetDescriptorField::Architecture(Architecture::X86_64)),
        TargetPredicate::DescriptorField(TargetDescriptorField::SemanticMode(
            gantry::mode::SemanticMode::Portable,
        )),
        TargetPredicate::FeatureEnabled(feature("b")),
    ]
}

/// Returns the guards of a declaration that exactly one fixture predicate matches.
fn partially_matched_guards() -> Vec<TargetPredicate> {
    vec![
        TargetPredicate::DescriptorField(TargetDescriptorField::Architecture(Architecture::X86_64)),
        TargetPredicate::FeatureEnabled(feature("c")),
    ]
}

/// Returns the guards of a declaration that no fixture predicate matches.
fn none_matched_guards() -> Vec<TargetPredicate> {
    vec![
        TargetPredicate::DescriptorField(TargetDescriptorField::Architecture(
            Architecture::Aarch64,
        )),
        TargetPredicate::FeatureEnabled(feature("c")),
    ]
}

/// Returns one matrix entry for the fixture descriptor and one combination.
fn matrix_entry(
    kind: TargetKind,
    mode: gantry::mode::SemanticMode,
    state: TargetMatrixState,
) -> TargetMatrixEntry {
    matrix_entry_for("matrix", kind, mode, state)
}

/// Returns one selected-feature-solution digest of this lane.
fn solution_digest(seed: &str) -> FeatureSolutionDigest {
    FeatureSolutionDigest::from_hex(&hex(seed))
        .unwrap_or_else(|_| unreachable!("fixture digest is lowercase hexadecimal"))
}

/// Returns one matrix entry under one named feature solution.
fn matrix_entry_for(
    solution_seed: &str,
    kind: TargetKind,
    mode: gantry::mode::SemanticMode,
    state: TargetMatrixState,
) -> TargetMatrixEntry {
    TargetMatrixEntry::new(
        descriptor().digest(),
        solution_digest(solution_seed),
        kind,
        mode,
        state,
    )
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
    assert_eq!(record.descriptor(&declaring()), Ok(first.clone()));
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
    let declaring = declaring();
    assert!(matches!(
        TargetDescriptorRecord::new(&declaring, 1, &[("host_path", "/tmp/build")]),
        Err(TargetError::DescriptorPropertyUnknown { instance, property })
            if *instance == declaring && property.as_ref() == "host_path"
    ));
    assert!(matches!(
        TargetDescriptorRecord::new(&declaring, 1, &[("abi", "gnu"), ("abi", "musl")]),
        Err(TargetError::DescriptorPropertyDuplicate { instance, property })
            if *instance == declaring && property.as_ref() == "abi"
    ));
    assert!(matches!(
        TargetDescriptorRecord::new(&declaring, 2, &[]),
        Err(TargetError::DescriptorVersionUnsupported { instance, version: 2 })
            if *instance == declaring
    ));
    // A missing property is never treated as an empty property: the record is
    // rejected rather than repaired into a descriptor.
    let incomplete = TargetDescriptorRecord::new(
        &declaring,
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
        incomplete.descriptor(&declaring),
        Err(TargetError::DescriptorPropertyMissing { instance, property })
            if *instance == declaring && property.as_ref() == "semantic_mode"
    ));
    // A field value outside the closed vocabulary of its version is invalid.
    let outside = TargetDescriptorRecord::new(
        &declaring,
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
        outside.descriptor(&declaring),
        Err(TargetError::WireValueUnknown { instance, field, value })
            if *instance == declaring && field == "architecture" && value.as_ref() == "sparc"
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
        TargetPredicate::decode(&declaring(), "source-form", "crate::probe"),
        Err(TargetError::PredicateNameUnknown { instance, name })
            if *instance == declaring() && name.as_ref() == "source-form"
    ));
    // The sealed field vocabulary is closed in both field and value.
    assert!(matches!(
        TargetPredicate::decode(&declaring(), "descriptor-field", "host_path=/tmp"),
        Err(TargetError::WireValueUnknown { field, .. }) if field == "descriptor field"
    ));
    assert!(matches!(
        TargetPredicate::decode(&declaring(), "descriptor-field", "architecture=sparc"),
        Err(TargetError::WireValueUnknown { instance, field, value })
            if *instance == declaring() && field == "architecture" && value.as_ref() == "sparc"
    ));
    assert_eq!(
        TargetPredicate::decode(&declaring(), "descriptor-field", "architecture=x86_64"),
        Ok(TargetPredicate::DescriptorField(
            TargetDescriptorField::Architecture(Architecture::X86_64)
        ))
    );
    assert_eq!(
        TargetPredicate::decode(&declaring(), "feature-enabled", "c"),
        Ok(TargetPredicate::FeatureEnabled(feature("c")))
    );
    assert!(matches!(
        TargetPredicate::decode(&declaring(), "feature-enabled", "not a feature"),
        Err(TargetError::FeatureNameInvalid { instance, value })
            if *instance == declaring() && value.as_ref() == "not a feature"
    ));
}

#[test]
fn predicate_evaluation_reads_only_descriptor_fields_and_declared_features() {
    // The declaring solution of one package instance is the only feature input:
    // a caller cannot evaluate a predicate against another instance's features.
    let selected = solution(&["c"]);
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
    let absent = solution(&["b"]);
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
    let selected = solution(&["c"]);
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
    let declaring = declaring();
    let declaration = |name: &str, enables: &[&str]| {
        FeatureDeclaration::new(&declaring, name, false, enables)
            .unwrap_or_else(|_| unreachable!("fixture declaration is valid"))
    };
    // A cycle is invalid rather than ignored, and it reports the offending names
    // against the instance that declared them.
    let cycle = FeatureDeclarations::new(
        &declaring,
        &[declaration("a", &["b"]), declaration("b", &["a"])],
    );
    match cycle {
        Err(TargetError::FeatureCycle { instance, cycle }) => {
            assert_eq!(*instance, declaring);
            let names = cycle.iter().map(FeatureName::as_str).collect::<Vec<_>>();
            assert_eq!(names, vec!["a", "b"]);
        }
        other => unreachable!("a cycle is reported as a cycle: {other:?}"),
    }
    assert!(matches!(
        FeatureDeclarations::new(&declaring, &[declaration("a", &["a"])]),
        Err(TargetError::FeatureCycle { cycle, .. })
            if cycle.as_slice() == [feature("a")].as_slice()
    ));
    // A cycle is found wherever it lies, not only at the first declaration.
    assert!(matches!(
        FeatureDeclarations::new(
            &declaring,
            &[
                declaration("x", &["y"]),
                declaration("y", &["z"]),
                declaration("z", &["x"]),
            ]
        ),
        Err(TargetError::FeatureCycle { .. })
    ));
    // An enabling relation that names an undeclared feature is invalid.
    assert!(matches!(
        FeatureDeclarations::new(&declaring, &[declaration("a", &["missing"])]),
        Err(TargetError::FeatureUnknown { instance, name })
            if *instance == declaring && name == feature("missing")
    ));
    // One feature declared twice by one instance is invalid.
    assert!(matches!(
        FeatureDeclarations::new(
            &declaring,
            &[declaration("a", &[]), declaration("a", &["b"]), declaration("b", &[])]
        ),
        Err(TargetError::FeatureDeclarationDuplicate { instance, name })
            if *instance == declaring && name == feature("a")
    ));
    // A feature spelling outside the closed vocabulary is invalid, and the
    // declaration names the instance that declared it.
    assert!(matches!(
        FeatureDeclaration::new(&declaring, "not a feature", false, &[]),
        Err(TargetError::FeatureNameInvalid { instance, value })
            if *instance == declaring && value.as_ref() == "not a feature"
    ));
    // Declaration order never changes which names are reported.
    let first = FeatureDeclarations::new(
        &declaring,
        &[declaration("a", &["b"]), declaration("b", &["a"])],
    );
    let second = FeatureDeclarations::new(
        &declaring,
        &[declaration("b", &["a"]), declaration("a", &["b"])],
    );
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
    let first = FeatureSolution::unify(&declarations(), &permutations[0], &declaring())
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
        let permuted = FeatureSolution::unify(&declarations(), permutation, &declaring())
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
    assert_eq!(first.root(), &declaring());
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
    let empty_request = FeatureSolution::unify(&declarations(), &[], &declaring())
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
    match FeatureSolution::unify(&declarations(), &features(&["missing"]), &declaring()) {
        Err(TargetError::FeatureRequestUnsatisfiable {
            instance: owner,
            requested,
        }) => {
            assert_eq!(*owner, declaring());
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
        Err(TargetError::TargetFactsVersionUnsupported { version: 2 })
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
    use gantry::mode::SemanticMode::{Application, Durable, Portable};

    let declaring = declaring();
    let modes = [Portable, Application, Durable];
    // The expected admission of every target kind, written out here rather than
    // read back from the table under test, so a wrong, missing, or duplicated
    // table row fails instead of confirming itself.
    let expected: [(TargetKind, &[gantry::mode::SemanticMode]); 5] = [
        (TargetKind::Library, &[Portable, Application]),
        (TargetKind::Binary, &[Portable, Application, Durable]),
        (TargetKind::Test, &[Portable]),
        (TargetKind::Example, &[Portable]),
        (TargetKind::Benchmark, &[Portable]),
    ];
    for (kind, admitted) in expected {
        assert_eq!(
            ModeAdmission::admitted_modes(kind),
            admitted,
            "the admitted modes of {} are the ones this test states",
            kind.wire_name()
        );
        for mode in modes {
            let admits = admitted.contains(&mode);
            assert_eq!(ModeAdmission::admits(kind, mode), admits);
            let verdict = if admits {
                Ok(())
            } else {
                Err(TargetError::ModeNotAdmitted {
                    instance: Box::new(declaring.clone()),
                    kind,
                    mode,
                })
            };
            assert_eq!(ModeAdmission::admit_mode(&declaring, kind, mode), verdict);
        }
        assert!(!admitted.is_empty(), "every kind admits at least one mode");
    }
    // The table covers the closed `GNT-16.6-target-kinds` vocabulary exactly
    // once, so no kind lacks an admission and no kind is listed twice.
    assert_eq!(ModeAdmission::TABLE.len(), TargetKind::ALL.len());
    let mut covered = ModeAdmission::TABLE.map(|(kind, _)| kind).to_vec();
    covered.sort();
    let mut vocabulary = TargetKind::ALL.to_vec();
    vocabulary.sort();
    assert_eq!(covered, vocabulary);
    // A non-shipping kind admits only the portable mode, and a library declares
    // no entry point, so durable execution is not admitted for either.
    for kind in [TargetKind::Test, TargetKind::Example, TargetKind::Benchmark] {
        assert!(matches!(
            ModeAdmission::admit_mode(&declaring, kind, Durable),
            Err(TargetError::ModeNotAdmitted { instance, kind: reported, mode })
                if *instance == declaring && reported == kind && mode == Durable
        ));
        assert!(matches!(
            ModeAdmission::admit_mode(&declaring, kind, Application),
            Err(TargetError::ModeNotAdmitted { kind: reported, .. }) if reported == kind
        ));
        assert_eq!(
            ModeAdmission::admit_mode(&declaring, kind, Portable),
            Ok(())
        );
    }
    assert!(matches!(
        ModeAdmission::admit_mode(&declaring, TargetKind::Library, Durable),
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
    assert!(modes.iter().all(|mode| ModeAdmission::admit_mode(
        &declaring,
        TargetKind::Binary,
        *mode
    ) == Ok(())));
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
            &declaring(),
            ExecutionTargetDescriptor::VERSION,
            descriptor_digest("other-descriptor"),
            binding.feature_solution_digest().clone(),
            binding.predicate_outcome_digest().clone(),
            binding.generated_outputs().clone(),
            binding.toolchain().clone(),
            binding.mode(),
        ),
        TargetArtifactBinding::new(
            &declaring(),
            ExecutionTargetDescriptor::VERSION,
            binding.descriptor_digest().clone(),
            solution(&["b"]).digest().clone(),
            binding.predicate_outcome_digest().clone(),
            binding.generated_outputs().clone(),
            binding.toolchain().clone(),
            binding.mode(),
        ),
        TargetArtifactBinding::new(
            &declaring(),
            ExecutionTargetDescriptor::VERSION,
            binding.descriptor_digest().clone(),
            binding.feature_solution_digest().clone(),
            PredicateOutcomeSet::empty().digest(),
            binding.generated_outputs().clone(),
            binding.toolchain().clone(),
            binding.mode(),
        ),
        TargetArtifactBinding::new(
            &declaring(),
            ExecutionTargetDescriptor::VERSION,
            binding.descriptor_digest().clone(),
            binding.feature_solution_digest().clone(),
            binding.predicate_outcome_digest().clone(),
            outputs("other-out"),
            binding.toolchain().clone(),
            binding.mode(),
        ),
        TargetArtifactBinding::new(
            &declaring(),
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
            &declaring(),
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
        &declaring(),
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
        Err(TargetError::ArtifactBindingMismatch { instance, field, expected, observed })
            if *instance == declaring()
                && field == "descriptor_sha256"
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
    let declaring = declaring();
    let binding = fixture_binding();
    let record = binding.record();
    assert_eq!(record.version(), TargetArtifactBindingRecord::VERSION);
    assert_eq!(record.binding(&declaring), Ok(binding.clone()));
    // A binding that omits a bound input is rejected rather than repaired, and
    // the rejection names the instance whose record omitted it.
    let incomplete = TargetArtifactBindingRecord::new(
        &declaring,
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
        incomplete.binding(&declaring),
        Err(TargetError::ArtifactBindingMissingInput { instance, input })
            if *instance == declaring && input == "mode"
    ));
    // An unsupported record version and an unsupported descriptor version are
    // both rejected.
    assert!(matches!(
        TargetArtifactBindingRecord::new(&declaring, 2, &[]),
        Err(TargetError::ArtifactBindingVersionUnsupported { instance, version: 2 })
            if *instance == declaring
    ));
    assert!(matches!(
        TargetArtifactBindingRecord::new(&declaring, 1, &[("host_path", "/tmp")]),
        Err(TargetError::ArtifactBindingPropertyUnknown { instance, property })
            if *instance == declaring && property.as_ref() == "host_path"
    ));
    assert!(matches!(
        TargetArtifactBindingRecord::new(
            &declaring,
            1,
            &[("mode", "portable"), ("mode", "durable")]
        ),
        Err(TargetError::ArtifactBindingPropertyDuplicate { instance, property })
            if *instance == declaring && property.as_ref() == "mode"
    ));
    assert!(matches!(
        TargetArtifactBinding::new(
            &declaring,
            2,
            binding.descriptor_digest().clone(),
            binding.feature_solution_digest().clone(),
            binding.predicate_outcome_digest().clone(),
            binding.generated_outputs().clone(),
            binding.toolchain().clone(),
            binding.mode(),
        ),
        Err(TargetError::DescriptorVersionUnsupported { instance, version: 2 })
            if *instance == declaring
    ));
    // A generated-output entry that is not the canonical `name:hash` form is an
    // unknown value of the record rather than a repaired output.
    let unshaped = TargetArtifactBindingRecord::new(
        &declaring,
        1,
        &[
            ("descriptor_sha256", binding.descriptor_digest().as_str()),
            ("descriptor_version", "1"),
            (
                "feature_solution_sha256",
                binding.feature_solution_digest().as_str(),
            ),
            ("generated_outputs", "schema.json"),
            ("mode", "portable"),
            (
                "predicate_outcomes_sha256",
                binding.predicate_outcome_digest().as_str(),
            ),
            ("toolchain_sha256", binding.toolchain().as_str()),
        ],
    )
    .unwrap_or_else(|_| unreachable!("fixture record properties are known"));
    assert!(matches!(
        unshaped.binding(&declaring),
        Err(TargetError::WireValueUnknown { instance, field, value })
            if *instance == declaring
                && field == "generated_outputs"
                && value.as_ref() == "schema.json"
    ));
    // An expected input record cannot name a mode the selected kind does not
    // admit, and a mode that disagrees with the descriptor is reported.
    assert!(matches!(
        ExpectedInputs::new(
            &declaring,
            TargetKind::Test,
            descriptor(),
            solution(&["c"]),
            &predicates(),
            outputs("out"),
            toolchain(),
            gantry::mode::SemanticMode::Durable,
        ),
        Err(TargetError::ModeNotAdmitted {
            instance,
            kind: TargetKind::Test,
            ..
        }) if *instance == declaring
    ));
    assert!(matches!(
        ExpectedInputs::new(
            &declaring,
            TargetKind::Binary,
            descriptor(),
            solution(&["c"]),
            &predicates(),
            outputs("out"),
            toolchain(),
            gantry::mode::SemanticMode::Application,
        ),
        Err(TargetError::ArtifactBindingMismatch { instance, field, .. })
            if *instance == declaring && field == "semantic_mode"
    ));
}

#[test]
fn conditional_selection_rule_is_total_and_order_independent() {
    let declaring = declaring();
    let selection = rule();
    assert_eq!(selection.identity(), ConditionalSelectionRule::IDENTITY);
    assert_eq!(selection.identity(), "gnt-conditional-selection/v1");
    // An unsupported rule identity is rejected against the instance that named
    // it rather than resolved by another rule.
    assert!(matches!(
        ConditionalSelectionRule::new(&declaring, "gnt-conditional-selection/v2"),
        Err(TargetError::SelectionRuleUnsupported { instance, rule })
            if *instance == declaring && rule.as_ref() == "gnt-conditional-selection/v2"
    ));
    // The match vocabulary is closed: every guard set is classified into exactly
    // one member, and a spelling outside the vocabulary is not a member.
    assert_eq!(BranchMatch::ALL.len(), 3);
    assert_eq!(
        BranchMatch::from_wire_name("every-matched"),
        Some(BranchMatch::EveryMatched)
    );
    assert_eq!(
        BranchMatch::from_wire_name("none-matched"),
        Some(BranchMatch::NoneMatched)
    );
    assert_eq!(
        BranchMatch::from_wire_name("partially-matched"),
        Some(BranchMatch::PartiallyMatched)
    );
    assert_eq!(BranchMatch::from_wire_name("first-match"), None);
    assert_eq!(BranchMatch::from_wire_name("last-match"), None);
    assert_eq!(BranchMatch::from_wire_name("declaration-order"), None);
    let target = descriptor();
    let selected = solution(&["b"]);
    let expected = [
        (
            branch(&every_matched_guards(), facts(&[])),
            BranchMatch::EveryMatched,
        ),
        (
            branch(&partially_matched_guards(), facts(&[])),
            BranchMatch::PartiallyMatched,
        ),
        (
            branch(&none_matched_guards(), facts(&[])),
            BranchMatch::NoneMatched,
        ),
        (branch(&[], facts(&[])), BranchMatch::EveryMatched),
    ];
    for (declaration, match_outcome) in &expected {
        let outcome = selection.evaluate(declaration, &target, &selected);
        assert_eq!(outcome.declaration(), declaration);
        assert_eq!(outcome.match_outcome(), *match_outcome);
        assert_eq!(outcome.retained(), selection.retains(*match_outcome));
        assert!(BranchMatch::ALL.contains(&outcome.match_outcome()));
        assert_eq!(
            outcome.retained(),
            *match_outcome == BranchMatch::EveryMatched
        );
    }
    // The same declaration evaluated against the same descriptor and the same
    // solution yields the same outcome under every order of its guard set.
    let mut guards = every_matched_guards();
    let canonical = branch(&guards, facts(&[]));
    let baseline = selection.evaluate(&canonical, &target, &selected);
    for _ in 0..guards.len() {
        guards.rotate_left(1);
        let permuted = branch(&guards, facts(&[]));
        assert_eq!(permuted.guards(), canonical.guards());
        assert_eq!(permuted, canonical);
        assert_eq!(selection.evaluate(&permuted, &target, &selected), baseline);
    }
    // A matching predicate in any position does not retain a guard set that only
    // partly matched, so neither the first nor the last matching predicate can
    // decide which branch is retained.
    let mut partial = partially_matched_guards();
    for _ in 0..partial.len() {
        partial.rotate_left(1);
        let outcome = selection.evaluate(&branch(&partial, facts(&[])), &target, &selected);
        assert_eq!(outcome.match_outcome(), BranchMatch::PartiallyMatched);
        assert!(
            !outcome.retained(),
            "a partly matched guard set is never retained"
        );
    }
    // Declaration order is not an input either: one declaration has one outcome
    // wherever it is evaluated.
    let declarations = expected
        .iter()
        .map(|(declaration, _)| declaration.clone())
        .collect::<Vec<_>>();
    let in_order: Vec<BranchOutcome> = declarations
        .iter()
        .map(|declaration| selection.evaluate(declaration, &target, &selected))
        .collect();
    let mut reversed_declarations = declarations.clone();
    reversed_declarations.reverse();
    let reversed = reversed_declarations
        .iter()
        .map(|declaration| selection.evaluate(declaration, &target, &selected))
        .collect::<Vec<_>>();
    for outcome in &in_order {
        assert_eq!(
            reversed
                .iter()
                .find(|candidate| candidate.declaration() == outcome.declaration()),
            Some(outcome),
            "one declaration has one outcome"
        );
    }
    // One branch of one declaration is selected, and the selection is the same
    // value under every order of the declared branches.
    let mut reversed_outcomes = in_order.clone();
    reversed_outcomes.reverse();
    let selected_branch = selection
        .retain_one(&declaring, &in_order)
        .unwrap_or_else(|_| unreachable!("a declaration site with branches is resolvable"))
        .unwrap_or_else(|| unreachable!("one declared branch is retained"));
    assert!(selected_branch.retained());
    assert_eq!(Some(selected_branch.declaration()), Some(&declarations[0]));
    assert_eq!(
        selection.retain_one(&declaring, &in_order),
        selection.retain_one(&declaring, &reversed_outcomes)
    );
    // A declaration none of whose branches is retained retains no branch.
    let unretained = [declarations[1].clone(), declarations[2].clone()]
        .iter()
        .map(|declaration| selection.evaluate(declaration, &target, &selected))
        .collect::<Vec<_>>();
    assert_eq!(selection.retain_one(&declaring, &unretained), Ok(None));
    // A declaration site that offers no branch at all cannot be resolved, and
    // the rejection names the declaring instance and the published rule rather
    // than resolving to an empty selection.
    match selection.retain_one(&declaring, &[]) {
        Err(TargetError::ConditionalSelectionUnresolved {
            instance,
            site,
            guards,
        }) => {
            assert_eq!(*instance, declaring);
            assert_eq!(site.as_ref(), ConditionalSelectionRule::IDENTITY);
            assert!(guards.is_empty());
        }
        other => unreachable!("an empty declaration site is unresolvable: {other:?}"),
    }
}

#[test]
fn inactive_branch_contributes_no_facts_and_its_contribution_is_rejected() {
    let declaring = declaring();
    let selection = rule();
    let target = descriptor();
    let selected = solution(&["b"]);
    let contributed = facts(&[
        (DeclaredFactKind::Type, "crate::Payload"),
        (DeclaredFactKind::Operation, "crate::Payload::encode"),
        (DeclaredFactKind::CapabilityRequirement, "network-egress"),
        (DeclaredFactKind::AgentTool, "filesystem-read"),
        (DeclaredFactKind::DurableState, "crate::Session"),
        (DeclaredFactKind::Implementation, "crate::PayloadImpl"),
    ]);
    let inactive = selection.evaluate(
        &branch(&none_matched_guards(), contributed.clone()),
        &target,
        &selected,
    );
    assert!(!inactive.retained());
    // An inactive branch that declares facts is rejected rather than collected,
    // and the rejection names the declaring instance and the branch.
    match RetainedClosure::check_contribution(&inactive) {
        Err(TargetError::BranchFactsInactive {
            instance,
            guards,
            kinds,
        }) => {
            assert_eq!(*instance, declaring);
            assert_eq!(
                guards,
                vec![
                    Arc::from("descriptor-field:architecture=aarch64"),
                    Arc::from("feature-enabled:c"),
                ]
            );
            assert_eq!(
                kinds,
                vec![
                    DeclaredFactKind::Type,
                    DeclaredFactKind::Implementation,
                    DeclaredFactKind::Operation,
                    DeclaredFactKind::CapabilityRequirement,
                    DeclaredFactKind::AgentTool,
                    DeclaredFactKind::DurableState,
                ]
            );
        }
        other => unreachable!("an inactive contribution is reported: {other:?}"),
    }
    assert!(RetainedClosure::checked(std::slice::from_ref(&inactive)).is_err());
    // The closure computation records none of the inactive branch's facts.
    let closure = RetainedClosure::new(std::slice::from_ref(&inactive));
    for kind in DeclaredFactKind::ALL {
        assert!(
            closure.names(kind).is_empty(),
            "an inactive branch contributes no {kind:?}"
        );
    }
    assert!(closure.is_empty());
    assert_eq!(closure.len(), 0);
    assert_eq!(closure.digest(), RetainedClosure::empty().digest());
    assert_eq!(
        closure.canonical_bytes(),
        RetainedClosure::empty().canonical_bytes()
    );
    // A retained branch contributes exactly its declared facts, in canonical
    // order, and its contribution is accepted.
    let retained_facts = facts(&[
        (DeclaredFactKind::Type, "crate::Payload"),
        (DeclaredFactKind::Type, "crate::Audit"),
        (DeclaredFactKind::Type, "crate::Payload"),
    ]);
    assert_eq!(
        retained_facts
            .names(DeclaredFactKind::Type)
            .iter()
            .map(AsRef::<str>::as_ref)
            .collect::<Vec<_>>(),
        vec!["crate::Audit", "crate::Payload"],
        "a declared set is canonically sorted and deduplicated"
    );
    let retained = selection.evaluate(
        &branch(&every_matched_guards(), retained_facts.clone()),
        &target,
        &selected,
    );
    assert!(retained.retained());
    assert_eq!(RetainedClosure::check_contribution(&retained), Ok(()));
    let closure = RetainedClosure::checked(std::slice::from_ref(&retained))
        .unwrap_or_else(|_| unreachable!("a retained contribution is accepted"));
    assert_eq!(
        closure.names(DeclaredFactKind::Type),
        retained_facts.names(DeclaredFactKind::Type)
    );
    assert_eq!(closure.len(), 2);
    assert_ne!(closure.digest(), RetainedClosure::empty().digest());
    assert_eq!(closure.digest().as_str().len(), 64);
    // An inactive branch that declares nothing is not a contribution at all.
    let silent = selection.evaluate(
        &branch(&none_matched_guards(), facts(&[])),
        &target,
        &selected,
    );
    assert!(!silent.retained());
    assert_eq!(RetainedClosure::check_contribution(&silent), Ok(()));
    // The declared-fact vocabulary rejects a name that is not a legal declared
    // name rather than ignoring it.
    assert!(matches!(
        DeclaredFacts::new(&declaring, &[(DeclaredFactKind::Type, "")]),
        Err(TargetError::DeclaredFactNameInvalid { instance, kind, value })
            if *instance == declaring && kind == DeclaredFactKind::Type && value.as_ref() == ""
    ));
    assert!(DeclaredFacts::empty().is_empty());
    assert_eq!(DeclaredFacts::empty().len(), 0);
}

#[test]
fn retained_closure_digest_changes_with_retained_facts_and_not_with_inactive_facts() {
    let selection = rule();
    let target = descriptor();
    let selected = solution(&["b"]);
    let baseline = facts(&[(DeclaredFactKind::Operation, "crate::Payload::encode")]);
    let extended = facts(&[
        (DeclaredFactKind::Operation, "crate::Payload::encode"),
        (DeclaredFactKind::AgentTool, "filesystem-read"),
    ]);
    let retained = |contributed: &DeclaredFacts| {
        selection.evaluate(
            &branch(&every_matched_guards(), contributed.clone()),
            &target,
            &selected,
        )
    };
    let baseline_closure = RetainedClosure::new(&[retained(&baseline)]);
    let extended_closure = RetainedClosure::new(&[retained(&extended)]);
    assert_ne!(
        baseline_closure.canonical_bytes(),
        extended_closure.canonical_bytes()
    );
    assert_ne!(baseline_closure.digest(), extended_closure.digest());
    assert_eq!(baseline_closure.len(), 1);
    assert_eq!(extended_closure.len(), 2);
    // The closure digest is one canonical digest spelling that round-trips, and a
    // spelling outside it is rejected rather than repaired.
    assert_eq!(extended_closure.digest().as_str().len(), 64);
    assert_eq!(
        RetainedClosureDigest::from_hex(extended_closure.digest().as_str()),
        Ok(extended_closure.digest())
    );
    assert!(matches!(
        RetainedClosureDigest::from_hex("not-a-digest"),
        Err(TargetError::ClosureDigestInvalid { value }) if value.as_ref() == "not-a-digest"
    ));
    // The closure is the union of every retained branch, so a second retained
    // branch that contributes the same facts adds nothing.
    let second_retained = selection.evaluate(
        &branch(
            &[TargetPredicate::FeatureEnabled(feature("a"))],
            extended.clone(),
        ),
        &target,
        &selected,
    );
    assert!(second_retained.retained());
    assert_eq!(
        RetainedClosure::new(&[retained(&extended), second_retained]),
        extended_closure
    );
    // An inactive branch's declared facts change nothing: the closure, its
    // canonical encoding, and its digest are the ones of an empty closure.
    let inactive_baseline = selection.evaluate(
        &branch(&none_matched_guards(), baseline.clone()),
        &target,
        &selected,
    );
    let inactive_extended = selection.evaluate(
        &branch(&none_matched_guards(), extended.clone()),
        &target,
        &selected,
    );
    assert_ne!(inactive_baseline, inactive_extended);
    assert!(!inactive_baseline.retained() && !inactive_extended.retained());
    assert_eq!(
        RetainedClosure::new(std::slice::from_ref(&inactive_baseline)),
        RetainedClosure::new(std::slice::from_ref(&inactive_extended))
    );
    assert_eq!(
        RetainedClosure::new(std::slice::from_ref(&inactive_baseline)).digest(),
        RetainedClosure::empty().digest()
    );
    assert_eq!(
        RetainedClosure::new(std::slice::from_ref(&inactive_extended)).canonical_bytes(),
        RetainedClosure::empty().canonical_bytes()
    );
    // The unchanged digest is not the result of retaining nothing at all: the
    // same facts do change the digest once their branch is retained, and both
    // inactive declarations are rejected by the strict check.
    assert_ne!(baseline_closure.digest(), RetainedClosure::empty().digest());
    assert!(RetainedClosure::checked(&[inactive_baseline, inactive_extended]).is_err());
    assert_eq!(
        RetainedClosure::new(&[retained(&extended), retained(&baseline)]),
        extended_closure,
    );
}

#[test]
fn target_matrix_coverage_rejects_an_unattested_combination() {
    use gantry::mode::SemanticMode::{Durable, Portable};

    let declaring = declaring();
    let supported = matrix_entry(TargetKind::Binary, Portable, TargetMatrixState::Supported);
    let unsupported = matrix_entry(TargetKind::Test, Durable, TargetMatrixState::Unsupported);
    let matrix = TargetMatrix::new(&declaring, &[supported.clone(), unsupported.clone()])
        .unwrap_or_else(|_| unreachable!("fixture entries name distinct combinations"));
    assert_eq!(matrix.declaring(), &declaring);
    assert_eq!(
        matrix.coverage(
            supported.descriptor(),
            supported.solution(),
            supported.kind(),
            supported.mode()
        ),
        Ok(TargetMatrixState::Supported)
    );
    assert_eq!(
        matrix.coverage(
            unsupported.descriptor(),
            unsupported.solution(),
            unsupported.kind(),
            unsupported.mode()
        ),
        Ok(TargetMatrixState::Unsupported)
    );
    // A state is explicit rather than assumed: a combination with no entry is
    // unattested, and the rejection names the combination and the instance.
    let absent = descriptor_digest("absent");
    match matrix.coverage(
        &absent,
        &solution_digest("matrix"),
        TargetKind::Example,
        Portable,
    ) {
        Err(TargetError::MatrixCoverageMissing {
            instance,
            descriptor: reported,
            solution,
            kind,
            mode,
        }) => {
            assert_eq!(*instance, declaring);
            assert_eq!(reported, absent);
            assert_eq!(solution, solution_digest("matrix"));
            assert_eq!(kind, TargetKind::Example);
            assert_eq!(mode, Portable);
        }
        other => unreachable!("an unattested combination is reported: {other:?}"),
    }
    assert!(matches!(
        matrix.admit(
            &absent,
            &solution_digest("matrix"),
            TargetKind::Example,
            Portable
        ),
        Err(TargetError::MatrixCoverageMissing { .. })
    ));
    // The feature solution is part of the combination: one descriptor, kind,
    // and mode under another solution is a different combination rather than a
    // second state for the same one.
    let other_solution = matrix_entry_for(
        "other-solution",
        TargetKind::Binary,
        Portable,
        TargetMatrixState::Unsupported,
    );
    let widened = TargetMatrix::new(&declaring, &[supported.clone(), other_solution.clone()])
        .unwrap_or_else(|_| unreachable!("the two entries name distinct combinations"));
    assert_eq!(
        widened.coverage(
            other_solution.descriptor(),
            other_solution.solution(),
            other_solution.kind(),
            other_solution.mode()
        ),
        Ok(TargetMatrixState::Unsupported)
    );
    assert_eq!(
        widened.coverage(
            supported.descriptor(),
            supported.solution(),
            supported.kind(),
            supported.mode()
        ),
        Ok(TargetMatrixState::Supported)
    );
    assert_ne!(widened.digest(), matrix.digest());
    // A combination recorded for another kind is not coverage for this one, and
    // a matrix with no entry covers nothing at all.
    assert!(matches!(
        matrix.coverage(
            unsupported.descriptor(),
            unsupported.solution(),
            TargetKind::Example,
            Durable
        ),
        Err(TargetError::MatrixCoverageMissing { .. })
    ));
    let empty = TargetMatrix::new(&declaring, &[])
        .unwrap_or_else(|_| unreachable!("an empty matrix records no duplicate"));
    assert_eq!(empty.entries().len(), 0);
    assert!(matches!(
        empty.admit(
            supported.descriptor(),
            supported.solution(),
            TargetKind::Binary,
            Portable
        ),
        Err(TargetError::MatrixCoverageMissing { .. })
    ));
    // The state vocabulary is closed: a spelling it does not name is not a
    // state, so no combination can be recorded as anything else.
    assert_eq!(TargetMatrixState::ALL.len(), 2);
    assert_eq!(
        TargetMatrixState::from_wire_name("supported"),
        Some(TargetMatrixState::Supported)
    );
    assert_eq!(
        TargetMatrixState::from_wire_name("unsupported"),
        Some(TargetMatrixState::Unsupported)
    );
    assert_eq!(TargetMatrixState::from_wire_name("attested"), None);
    assert_eq!(TargetMatrixState::from_wire_name("partial"), None);
    // A combination a target kind does not admit is still recordable as
    // unsupported, which is the coverage the matrix must carry.
    assert_eq!(unsupported.state(), TargetMatrixState::Unsupported);
    assert!(ModeAdmission::admit_mode(&declaring, TargetKind::Test, Durable).is_err());
}

#[test]
fn unsupported_target_combination_fails_with_a_diagnostic_naming_the_declaring_instance() {
    use gantry::mode::SemanticMode::{Durable, Portable};

    let declaring = declaring();
    let supported = matrix_entry(TargetKind::Binary, Portable, TargetMatrixState::Supported);
    let unsupported = matrix_entry(TargetKind::Test, Durable, TargetMatrixState::Unsupported);
    let matrix = TargetMatrix::new(&declaring, &[supported, unsupported.clone()])
        .unwrap_or_else(|_| unreachable!("fixture entries name distinct combinations"));
    // The combination is recorded, and it is recorded as unsupported rather than
    // left unattested.
    assert_eq!(
        matrix.coverage(
            unsupported.descriptor(),
            unsupported.solution(),
            TargetKind::Test,
            Durable
        ),
        Ok(TargetMatrixState::Unsupported)
    );
    match matrix.admit(
        unsupported.descriptor(),
        unsupported.solution(),
        TargetKind::Test,
        Durable,
    ) {
        Err(TargetError::MatrixCombinationUnsupported {
            instance,
            descriptor: reported,
            solution,
            kind,
            mode,
        }) => {
            assert_eq!(*instance, declaring);
            assert_eq!(reported, *unsupported.descriptor());
            assert_eq!(solution, *unsupported.solution());
            assert_eq!(kind, TargetKind::Test);
            assert_eq!(mode, Durable);
        }
        other => unreachable!("an unsupported combination is reported: {other:?}"),
    }
    let error = matrix
        .admit(
            unsupported.descriptor(),
            unsupported.solution(),
            TargetKind::Test,
            Durable,
        )
        .err()
        .unwrap_or_else(|| unreachable!("the fixture combination is unsupported"));
    assert_eq!(
        error.code(),
        TargetDiagnosticCode::MatrixCombinationUnsupported
    );
    assert_eq!(error.requirement(), "GNT-17.8-target-matrix");
    let rendered = error.to_string();
    assert!(rendered.contains("target-matrix-combination-unsupported"));
    assert!(rendered.contains(&declaring.as_str()));
    assert!(rendered.contains(unsupported.descriptor().as_str()));
    // The unsupported combination fails before any binding is produced: the step
    // that would bind the artifact is unreachable for it.
    let attempt = || -> Result<TargetArtifactBinding, TargetError> {
        matrix.admit(
            unsupported.descriptor(),
            unsupported.solution(),
            TargetKind::Test,
            Durable,
        )?;
        ExpectedInputs::new(
            &declaring,
            TargetKind::Test,
            durable_descriptor(),
            solution(&["c"]),
            &predicates(),
            outputs("out"),
            toolchain(),
            Durable,
        )
        .and_then(|inputs| inputs.bind())
    };
    assert!(matches!(
        attempt(),
        Err(TargetError::MatrixCombinationUnsupported { .. })
    ));
    // The same combination would also fail mode admission, so the matrix is the
    // step that fails first: the combination is named rather than substituted by
    // another target or by another mode.
    assert!(matches!(
        ModeAdmission::admit_mode(&declaring, TargetKind::Test, Durable),
        Err(TargetError::ModeNotAdmitted {
            kind: TargetKind::Test,
            mode: Durable,
            ..
        })
    ));
    // An explicitly supported combination is admitted here, so the matrix is not
    // refusing every combination.
    assert_eq!(
        matrix.admit(
            unsupported.descriptor(),
            unsupported.solution(),
            TargetKind::Binary,
            Portable
        ),
        Ok(())
    );
}

#[test]
fn target_matrix_digest_is_order_independent() {
    use gantry::mode::SemanticMode::{Application, Durable, Portable};

    let declaring = declaring();
    let entries = [
        matrix_entry(TargetKind::Binary, Portable, TargetMatrixState::Supported),
        matrix_entry(
            TargetKind::Binary,
            Application,
            TargetMatrixState::Supported,
        ),
        matrix_entry(TargetKind::Binary, Durable, TargetMatrixState::Unsupported),
        TargetMatrixEntry::new(
            descriptor_digest("other"),
            solution_digest("matrix"),
            TargetKind::Test,
            Portable,
            TargetMatrixState::Supported,
        ),
    ];
    let matrix = TargetMatrix::new(&declaring, &entries)
        .unwrap_or_else(|_| unreachable!("fixture entries name distinct combinations"));
    assert_eq!(matrix.entries().len(), entries.len());
    // The entries are held in canonical order, and the encoding and the digest
    // are functions of the entry set rather than of the given order.
    assert!(matrix.entries().windows(2).all(|pair| pair[0] < pair[1]));
    let mut reversed = entries.to_vec();
    reversed.reverse();
    let permuted = TargetMatrix::new(&declaring, &reversed)
        .unwrap_or_else(|_| unreachable!("a permutation records no duplicate"));
    assert_eq!(permuted.canonical_bytes(), matrix.canonical_bytes());
    assert_eq!(permuted.digest(), matrix.digest());
    assert_eq!(permuted.entries(), matrix.entries());
    let mut rotated = entries.to_vec();
    rotated.rotate_left(2);
    let permuted = TargetMatrix::new(&declaring, &rotated)
        .unwrap_or_else(|_| unreachable!("a rotation records no duplicate"));
    assert_eq!(permuted.digest(), matrix.digest());
    // The matrix digest is one canonical digest spelling that round-trips, and a
    // spelling outside it is rejected rather than repaired.
    assert_eq!(matrix.digest().as_str().len(), 64);
    assert_eq!(
        TargetMatrixDigest::from_hex(matrix.digest().as_str()),
        Ok(matrix.digest())
    );
    assert!(matches!(
        TargetMatrixDigest::from_hex("not-a-digest"),
        Err(TargetError::MatrixDigestInvalid { value }) if value.as_ref() == "not-a-digest"
    ));
    // Changing one recorded state changes the matrix and its digest.
    let mut flipped = entries.to_vec();
    flipped[2] = matrix_entry(TargetKind::Binary, Durable, TargetMatrixState::Supported);
    let flipped = TargetMatrix::new(&declaring, &flipped)
        .unwrap_or_else(|_| unreachable!("one state change records no duplicate"));
    assert_eq!(
        matrix.coverage(
            &descriptor().digest(),
            &solution_digest("matrix"),
            TargetKind::Binary,
            Durable
        ),
        Ok(TargetMatrixState::Unsupported)
    );
    assert_eq!(
        flipped.coverage(
            &descriptor().digest(),
            &solution_digest("matrix"),
            TargetKind::Binary,
            Durable
        ),
        Ok(TargetMatrixState::Supported)
    );
    assert_ne!(flipped.canonical_bytes(), matrix.canonical_bytes());
    assert_ne!(flipped.digest(), matrix.digest());
    // One combination recorded twice is rejected rather than deduplicated or
    // preferred, even when the two entries disagree.
    let mut duplicated = entries.to_vec();
    duplicated.push(matrix_entry(
        TargetKind::Binary,
        Durable,
        TargetMatrixState::Supported,
    ));
    assert!(matches!(
        TargetMatrix::new(&declaring, &duplicated),
        Err(TargetError::MatrixEntryDuplicate { instance, descriptor: reported, solution, kind, mode })
            if *instance == declaring
                && reported == descriptor().digest()
                && solution == solution_digest("matrix")
                && kind == TargetKind::Binary
                && mode == Durable
    ));
    // The declaring instance is not an input of the encoding or of the digest.
    let elsewhere = TargetMatrix::new(&root("other"), &entries)
        .unwrap_or_else(|_| unreachable!("fixture entries name distinct combinations"));
    assert_ne!(elsewhere.declaring(), matrix.declaring());
    assert_eq!(elsewhere.canonical_bytes(), matrix.canonical_bytes());
    assert_eq!(elsewhere.digest(), matrix.digest());
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
    assert_eq!(registered.len(), 33);
    assert!(registered.windows(2).all(|pair| pair[0] < pair[1]));
    // Every condition of the target model exposes one of those frozen codes, and
    // no condition borrows another condition's code.
    let declaring = declaring();
    let declared = vec![
        TargetError::ArtifactBindingDigestInvalid {
            value: Arc::from("not-a-digest"),
        },
        TargetError::ArtifactBindingMismatch {
            instance: Box::new(declaring.clone()),
            field: "mode",
            expected: Arc::from("portable"),
            observed: Arc::from("durable"),
        },
        TargetError::ArtifactBindingMissingInput {
            instance: Box::new(declaring.clone()),
            input: "mode",
        },
        TargetError::ArtifactBindingPropertyDuplicate {
            instance: Box::new(declaring.clone()),
            property: Arc::from("mode"),
        },
        TargetError::ArtifactBindingPropertyUnknown {
            instance: Box::new(declaring.clone()),
            property: Arc::from("host_path"),
        },
        TargetError::ArtifactBindingVersionUnsupported {
            instance: Box::new(declaring.clone()),
            version: 2,
        },
        TargetError::BranchFactsInactive {
            instance: Box::new(declaring.clone()),
            guards: vec![Arc::from("feature-enabled:c")],
            kinds: vec![DeclaredFactKind::Operation],
        },
        TargetError::ClosureDigestInvalid {
            value: Arc::from("not-a-digest"),
        },
        TargetError::ConditionalSelectionUnresolved {
            instance: Box::new(declaring.clone()),
            site: Arc::from("crate::main"),
            guards: vec![
                Arc::from("feature-enabled:c"),
                Arc::from("descriptor-field:architecture=x86_64"),
            ],
        },
        TargetError::DeclaredFactNameInvalid {
            instance: Box::new(declaring.clone()),
            kind: DeclaredFactKind::Type,
            value: Arc::from(""),
        },
        TargetError::DescriptorDigestInvalid {
            value: Arc::from("not-a-digest"),
        },
        TargetError::DescriptorEditionInvalid {
            value: Arc::from("2026=2027"),
        },
        TargetError::DescriptorPropertyDuplicate {
            instance: Box::new(declaring.clone()),
            property: Arc::from("abi"),
        },
        TargetError::DescriptorPropertyMissing {
            instance: Box::new(declaring.clone()),
            property: Arc::from("abi"),
        },
        TargetError::DescriptorPropertyUnknown {
            instance: Box::new(declaring.clone()),
            property: Arc::from("host_path"),
        },
        TargetError::DescriptorVersionUnsupported {
            instance: Box::new(declaring.clone()),
            version: 2,
        },
        TargetError::TargetFactsTextInvalid {
            value: Arc::from("1:descriptor:features:extra"),
        },
        TargetError::TargetFactsVersionUnsupported { version: 2 },
        TargetError::FeatureCycle {
            instance: Box::new(declaring.clone()),
            cycle: vec![feature("a")],
        },
        TargetError::FeatureDeclarationDuplicate {
            instance: Box::new(declaring.clone()),
            name: feature("a"),
        },
        TargetError::FeatureNameInvalid {
            instance: Box::new(declaring.clone()),
            value: Arc::from("not a feature"),
        },
        TargetError::FeatureRequestUnsatisfiable {
            instance: Box::new(declaring.clone()),
            requested: vec![feature("missing")],
        },
        TargetError::FeatureSolutionInstanceMismatch {
            instance: Box::new(declaring.clone()),
            solution: Box::new(root("other")),
        },
        TargetError::FeatureUnknown {
            instance: Box::new(declaring.clone()),
            name: feature("missing"),
        },
        TargetError::GeneratedOutputNameInvalid {
            instance: Box::new(declaring.clone()),
            value: Arc::from("/tmp/schema.json"),
        },
        TargetError::MatrixCombinationUnsupported {
            instance: Box::new(declaring.clone()),
            descriptor: descriptor_digest("matrix"),
            solution: solution_digest("matrix"),
            kind: TargetKind::Test,
            mode: gantry::mode::SemanticMode::Durable,
        },
        TargetError::MatrixCoverageMissing {
            instance: Box::new(declaring.clone()),
            descriptor: descriptor_digest("matrix"),
            solution: solution_digest("matrix"),
            kind: TargetKind::Example,
            mode: gantry::mode::SemanticMode::Portable,
        },
        TargetError::MatrixDigestInvalid {
            value: Arc::from("not-a-digest"),
        },
        TargetError::MatrixEntryDuplicate {
            instance: Box::new(declaring.clone()),
            descriptor: descriptor_digest("matrix"),
            solution: solution_digest("matrix"),
            kind: TargetKind::Binary,
            mode: gantry::mode::SemanticMode::Portable,
        },
        TargetError::ModeNotAdmitted {
            instance: Box::new(declaring.clone()),
            kind: TargetKind::Test,
            mode: gantry::mode::SemanticMode::Durable,
        },
        TargetError::PredicateNameUnknown {
            instance: Box::new(declaring.clone()),
            name: Arc::from("source-form"),
        },
        TargetError::SelectionRuleUnsupported {
            instance: Box::new(declaring.clone()),
            rule: Arc::from("gnt-conditional-selection/v2"),
        },
        TargetError::WireValueUnknown {
            instance: Box::new(declaring.clone()),
            field: "architecture",
            value: Arc::from("sparc"),
        },
    ];
    assert_eq!(declared.len(), TargetDiagnosticCode::ALL.len());
    for error in &declared {
        assert!(TargetDiagnosticCode::ALL.contains(&error.code()));
        assert_eq!(error.requirement(), error.code().requirement());
        assert!(error.requirement().starts_with("GNT-17."));
        // Every condition is renderable, and every rendered diagnostic names
        // its own frozen code, so a missing or unrelated rendering fails here.
        let rendered = error.to_string();
        assert!(!rendered.is_empty());
        assert!(
            rendered.contains(error.code().as_str()),
            "`{rendered}` does not name its code `{}`",
            error.code().as_str()
        );
    }
    let mut codes = declared.iter().map(TargetError::code).collect::<Vec<_>>();
    codes.sort();
    assert_eq!(codes, TargetDiagnosticCode::ALL.to_vec());
}
