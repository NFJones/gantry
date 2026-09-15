//! Machine-checked conformance for the pure Section 32 constant model.
//!
//! The tests use declared classes, operations, work records, dependency facts,
//! package state, and application state only. They neither parse source, evaluate
//! a real initializer, link a package, execute a loader, nor create runtime state.

use std::fs;
use std::path::{Path, PathBuf};

use gantry::ir::{
    ApplicationStateDeclaration, ApplicationStateOwner, CONSTANT_CLAUSES, CONSTANT_INT_LIMIT,
    CONSTANT_NON_CLAIM_ORDER, CONSTANT_NON_CLAIMS, ConstantAdmissibility, ConstantConversion,
    ConstantDeclaration, ConstantDiagnosticCode, ConstantEffect, ConstantError, ConstantExpression,
    ConstantNonClaim, ConstantNonClaimAssertion, ConstantOperation, ConstantPackage,
    ConstantRefusalReason, ConstantSelection, ConstantState, ConstantValueClass, ConstantWork,
    EvaluationLimits, PackageLoadFact, PackageStateClass, TargetKind, admit_package_state,
    check_constant_non_claims, checked_float, checked_int,
};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap_or_else(|| panic!("conformance crate has a workspace parent"))
        .to_path_buf()
}

/// Returns the refusal produced by one rejected constant decision.
fn refuse<T>(outcome: Result<T, ConstantError>, context: &str) -> ConstantError {
    match outcome {
        Ok(_) => panic!("{context}: the decision must be refused"),
        Err(error) => error,
    }
}

fn limits() -> EvaluationLimits {
    EvaluationLimits::new(64, 8, 16, 256)
        .unwrap_or_else(|error| panic!("the fixture limits are nonzero: {error}"))
}

fn expression(path: &str) -> ConstantExpression {
    ConstantExpression::new(path, &[ConstantOperation::Literal], &[])
        .unwrap_or_else(|error| panic!("the fixture initializer is admissible: {error}"))
}

fn declaration(
    path: &str,
    class: ConstantValueClass,
    dependencies: &[&str],
    exported: bool,
    selection: ConstantSelection,
) -> ConstantDeclaration {
    ConstantDeclaration::new(
        path,
        ConstantAdmissibility::Admissible(class),
        &expression(path),
        dependencies,
        exported,
        selection,
    )
    .unwrap_or_else(|error| panic!("the fixture declaration is admissible: {error}"))
}

fn evaluate(package: &mut ConstantPackage, path: &str, canonical_value: &str) {
    let work = ConstantWork::new(4, 2, 2, 8);
    package
        .record_evaluation(path, work, canonical_value)
        .unwrap_or_else(|error| panic!("the fixture constant `{path}` evaluates: {error}"));
}

fn identity_of(declarations: &[(&str, &str)]) -> String {
    let mut package = ConstantPackage::new(limits());
    for (path, value) in declarations {
        let declared = declaration(
            path,
            ConstantValueClass::Int,
            &[],
            true,
            ConstantSelection::Unconditional,
        );
        package
            .declare(declared)
            .unwrap_or_else(|error| panic!("`{path}` declares once: {error}"));
        evaluate(&mut package, path, value);
    }
    package
        .interface()
        .unwrap_or_else(|error| panic!("the fixture interface publishes: {error}"))
        .identity()
        .as_str()
        .to_owned()
}

#[test]
fn section_32_anchors_and_closed_vocabularies_are_published() {
    assert_eq!(CONSTANT_CLAUSES.len(), 13);
    let specification = fs::read_to_string(workspace_root().join("SPEC.md"))
        .unwrap_or_else(|error| panic!("could not read SPEC.md: {error}"));
    for clause in CONSTANT_CLAUSES {
        assert!(
            specification.contains(&format!("<a id=\"{clause}\"></a>")),
            "Section 32 must publish {clause}"
        );
    }
    for class in ConstantValueClass::ALL {
        assert_eq!(
            ConstantValueClass::from_wire_name(class.wire_name()),
            Some(class)
        );
    }
    assert_eq!(ConstantValueClass::ALL.len(), 11);
    assert_eq!(ConstantValueClass::from_wire_name("map"), None);
    assert_eq!(ConstantRefusalReason::ALL.len(), 10);
    for reason in ConstantRefusalReason::ALL {
        assert_eq!(
            ConstantRefusalReason::from_wire_name(reason.wire_name()),
            Some(reason)
        );
    }
    assert_eq!(ConstantOperation::ALL.len(), 16);
    for operation in ConstantOperation::ALL {
        assert_eq!(
            ConstantOperation::from_wire_name(operation.wire_name()),
            Some(operation)
        );
    }
    assert_eq!(ConstantEffect::ALL.len(), 8);
    for effect in ConstantEffect::ALL {
        assert_eq!(
            ConstantEffect::from_wire_name(effect.wire_name()),
            Some(effect)
        );
    }
    assert!(ConstantSelection::Unconditional.is_active());
    assert!(!ConstantSelection::Unconditional.is_sealed());
    assert!(ConstantSelection::SealedTargetPredicate { active: true }.is_sealed());
    assert!(!ConstantSelection::SealedFeaturePredicate { active: false }.is_active());
    assert!(!ConstantSelection::AmbientBuildHostState.is_active());
    assert_eq!(ConstantState::ALL.len(), 3);
    assert_eq!(
        ConstantState::ALL.map(ConstantState::wire_name),
        ["declared", "evaluated", "refused"]
    );
    assert_eq!(CONSTANT_NON_CLAIMS.len(), ConstantNonClaim::ALL.len());
    let spellings = ConstantDiagnosticCode::ALL
        .iter()
        .map(|code| code.as_str())
        .collect::<Vec<&str>>();
    let mut sorted = spellings.clone();
    sorted.sort_unstable();
    assert_eq!(
        spellings, sorted,
        "the frozen diagnostic registry is in canonical spelling order"
    );
    for code in ConstantDiagnosticCode::ALL {
        assert_eq!(
            ConstantDiagnosticCode::from_wire_name(code.as_str()),
            Some(code)
        );
        assert!(CONSTANT_CLAUSES.contains(&code.requirement()));
        assert!(
            specification.contains(code.as_str()),
            "Section 32.6 must publish the frozen spelling {}",
            code.as_str()
        );
    }
}

#[test]
fn declarations_bind_canonical_identity_and_reject_mutation() {
    let mut package = ConstantPackage::new(limits());
    package
        .declare(declaration(
            "pkg::A",
            ConstantValueClass::Int,
            &[],
            true,
            ConstantSelection::Unconditional,
        ))
        .unwrap_or_else(|error| panic!("`pkg::A` declares once: {error}"));
    let duplicate = declaration(
        "pkg::A",
        ConstantValueClass::Bool,
        &[],
        false,
        ConstantSelection::Unconditional,
    );
    assert_eq!(
        refuse(package.declare(duplicate), "a duplicate canonical path").code(),
        ConstantDiagnosticCode::InvalidDeclaration
    );
    assert_eq!(
        refuse(
            ConstantExpression::new("", &[ConstantOperation::Literal], &[]),
            "an empty path spelling"
        )
        .code(),
        ConstantDiagnosticCode::InvalidDeclaration
    );
    assert_eq!(
        refuse(
            ConstantDeclaration::new(
                "pkg::B",
                ConstantAdmissibility::Admissible(ConstantValueClass::Unit),
                &expression("pkg::C"),
                &[],
                false,
                ConstantSelection::Unconditional,
            ),
            "an initializer with a different path"
        )
        .code(),
        ConstantDiagnosticCode::InvalidDeclaration
    );
    assert_eq!(
        refuse(
            ConstantDeclaration::new(
                "pkg::D",
                ConstantAdmissibility::Admissible(ConstantValueClass::Int),
                &expression("pkg::D"),
                &["pkg::D"],
                false,
                ConstantSelection::Unconditional,
            ),
            "a self-declared dependency"
        )
        .code(),
        ConstantDiagnosticCode::Cycle
    );
    evaluate(&mut package, "pkg::A", "7");
    assert_eq!(package.state("pkg::A"), Some(ConstantState::Evaluated));
    assert_eq!(
        refuse(
            package.record_evaluation("pkg::A", ConstantWork::new(1, 1, 1, 1), "8"),
            "a second evaluation of an immutable constant"
        )
        .code(),
        ConstantDiagnosticCode::InvalidDeclaration
    );
    assert_eq!(
        refuse(
            package.record_refusal("pkg::A", ConstantDiagnosticCode::Overflow),
            "a refusal of an evaluated constant"
        )
        .code(),
        ConstantDiagnosticCode::InvalidDeclaration
    );
    let mut undeclared = ConstantPackage::new(limits());
    assert_eq!(
        refuse(
            undeclared.record_evaluation("pkg::Missing", ConstantWork::new(1, 1, 1, 1), "1"),
            "an undeclared constant"
        )
        .code(),
        ConstantDiagnosticCode::UnresolvedDependency
    );
}

#[test]
fn admissible_and_refused_classes_are_closed() {
    for reason in ConstantRefusalReason::ALL {
        let outcome = ConstantDeclaration::new(
            "pkg::X",
            ConstantAdmissibility::Refused(reason),
            &expression("pkg::X"),
            &[],
            true,
            ConstantSelection::Unconditional,
        );
        assert_eq!(
            refuse(outcome, "a refused constant class").code(),
            ConstantDiagnosticCode::InadmissibleType
        );
    }
    assert_eq!(
        ConstantAdmissibility::Admissible(ConstantValueClass::Float).class(),
        Some(ConstantValueClass::Float)
    );
    assert_eq!(
        ConstantAdmissibility::Refused(ConstantRefusalReason::SealedModelJudgment).class(),
        None
    );
    for class in ConstantValueClass::ALL {
        let declared = declaration(
            "pkg::Admitted",
            class,
            &[],
            true,
            ConstantSelection::Unconditional,
        );
        assert_eq!(declared.class(), class);
    }
}

#[test]
fn refused_effects_prevent_evaluation() {
    for effect in ConstantEffect::ALL {
        let outcome = ConstantExpression::new("pkg::E", &[ConstantOperation::Literal], &[effect]);
        assert_eq!(
            refuse(outcome, "an initializer with a refused effect").code(),
            ConstantDiagnosticCode::InadmissibleOperation
        );
    }
    assert_eq!(
        refuse(
            ConstantExpression::new("pkg::E", &[], &[]),
            "an initializer with no admissible operation"
        )
        .code(),
        ConstantDiagnosticCode::InadmissibleOperation
    );
    let admissible = ConstantExpression::new(
        "pkg::E",
        &[
            ConstantOperation::Literal,
            ConstantOperation::IntegerArithmetic,
            ConstantOperation::Comparison,
        ],
        &[],
    )
    .unwrap_or_else(|error| panic!("the declared operation set is admissible: {error}"));
    assert_eq!(admissible.operations().len(), 3);
}

#[test]
fn evaluation_limits_and_determinism_are_declared() {
    assert_eq!(
        refuse(EvaluationLimits::new(0, 1, 1, 1), "a zero fuel limit").code(),
        ConstantDiagnosticCode::LimitExceeded
    );
    assert_eq!(
        refuse(EvaluationLimits::new(1, 0, 1, 1), "a zero depth limit").code(),
        ConstantDiagnosticCode::LimitExceeded
    );
    let limits = limits();
    assert!(
        ConstantWork::new(
            limits.fuel(),
            limits.depth(),
            limits.members(),
            limits.encoded_bytes()
        )
        .admit(limits)
        .is_ok()
    );
    assert_eq!(
        refuse(
            ConstantWork::new(limits.fuel() + 1, 1, 1, 1).admit(limits),
            "exhausted fuel"
        )
        .code(),
        ConstantDiagnosticCode::Nontermination
    );
    assert_eq!(
        refuse(
            ConstantWork::new(1, limits.depth() + 1, 1, 1).admit(limits),
            "exceeded depth"
        )
        .code(),
        ConstantDiagnosticCode::LimitExceeded
    );
    assert_eq!(
        refuse(
            ConstantWork::new(1, 1, limits.members() + 1, 1).admit(limits),
            "exceeded member count"
        )
        .code(),
        ConstantDiagnosticCode::LimitExceeded
    );
    assert_eq!(
        refuse(
            ConstantWork::new(1, 1, 1, limits.encoded_bytes() + 1).admit(limits),
            "exceeded encoded size"
        )
        .code(),
        ConstantDiagnosticCode::LimitExceeded
    );
    assert_eq!(
        identity_of(&[("pkg::A", "1"), ("pkg::B", "2")]),
        identity_of(&[("pkg::B", "2"), ("pkg::A", "1")]),
        "declaration order must not change the canonical interface identity"
    );
    assert_ne!(
        identity_of(&[("pkg::A", "1")]),
        identity_of(&[("pkg::A", "2")]),
        "a changed canonical value must change the interface identity"
    );
}

#[test]
fn evaluation_order_is_deterministic_and_cycles_are_refused() {
    let mut package = ConstantPackage::new(limits());
    for (path, dependencies) in [
        ("pkg::C", &["pkg::B"][..]),
        ("pkg::B", &["pkg::A"][..]),
        ("pkg::A", &[][..]),
    ] {
        package
            .declare(declaration(
                path,
                ConstantValueClass::Int,
                dependencies,
                true,
                ConstantSelection::Unconditional,
            ))
            .unwrap_or_else(|error| panic!("`{path}` declares once: {error}"));
    }
    assert_eq!(
        package
            .evaluation_order()
            .unwrap_or_else(|error| panic!("the fixture graph is acyclic: {error}")),
        vec!["pkg::A", "pkg::B", "pkg::C"]
    );
    let mut imported = ConstantPackage::new(limits());
    imported
        .admit_external("dep::K")
        .unwrap_or_else(|error| panic!("the imported constant path is admissible: {error}"));
    imported
        .declare(declaration(
            "pkg::L",
            ConstantValueClass::Int,
            &["dep::K"],
            true,
            ConstantSelection::Unconditional,
        ))
        .unwrap_or_else(|error| panic!("`pkg::L` declares once: {error}"));
    assert_eq!(
        imported
            .evaluation_order()
            .unwrap_or_else(|error| panic!("an imported dependency resolves: {error}")),
        vec!["pkg::L"]
    );
    assert_eq!(
        refuse(
            imported.admit_external("pkg::L"),
            "an external path that is declared locally"
        )
        .code(),
        ConstantDiagnosticCode::InvalidDeclaration
    );
    let mut unresolved = ConstantPackage::new(limits());
    unresolved
        .declare(declaration(
            "pkg::M",
            ConstantValueClass::Int,
            &["pkg::Absent"],
            true,
            ConstantSelection::Unconditional,
        ))
        .unwrap_or_else(|error| panic!("`pkg::M` declares once: {error}"));
    assert_eq!(
        refuse(unresolved.evaluation_order(), "an unresolved dependency").code(),
        ConstantDiagnosticCode::UnresolvedDependency
    );
    let mut cycle = ConstantPackage::new(limits());
    for (path, dependencies) in [("pkg::X", &["pkg::Y"][..]), ("pkg::Y", &["pkg::X"][..])] {
        cycle
            .declare(declaration(
                path,
                ConstantValueClass::Int,
                dependencies,
                true,
                ConstantSelection::Unconditional,
            ))
            .unwrap_or_else(|error| panic!("`{path}` declares once: {error}"));
    }
    let refusal = refuse(cycle.evaluation_order(), "a dependency cycle");
    assert_eq!(refusal.code(), ConstantDiagnosticCode::Cycle);
    assert!(
        refusal.detail().contains("pkg::X"),
        "a cycle refusal names exactly one declared member: {}",
        refusal.detail()
    );
}

#[test]
fn diagnostics_are_frozen_and_refuse_overflow_and_inexact_conversion() {
    assert!(checked_int(CONSTANT_INT_LIMIT).is_ok());
    assert!(checked_int(-CONSTANT_INT_LIMIT).is_ok());
    assert_eq!(
        refuse(
            checked_int(CONSTANT_INT_LIMIT + 1),
            "an out-of-range integer"
        )
        .code(),
        ConstantDiagnosticCode::Overflow
    );
    assert_eq!(
        refuse(checked_int(i64::MIN), "the integer minimum").code(),
        ConstantDiagnosticCode::Overflow
    );
    assert!(checked_float(1.5).is_ok());
    assert_eq!(
        refuse(checked_float(f64::NAN), "a non-finite float result").code(),
        ConstantDiagnosticCode::Overflow
    );
    assert_eq!(
        refuse(checked_float(f64::INFINITY), "an infinite float result").code(),
        ConstantDiagnosticCode::Overflow
    );
    assert!(
        ConstantConversion::new(ConstantValueClass::Int, ConstantValueClass::Float, true).is_ok()
    );
    assert!(
        ConstantConversion::new(ConstantValueClass::Int, ConstantValueClass::Int, false).is_ok(),
        "an identity conversion is always exact"
    );
    let refusal = refuse(
        ConstantConversion::new(ConstantValueClass::Float, ConstantValueClass::Int, false),
        "an inexact conversion",
    );
    assert_eq!(refusal.code(), ConstantDiagnosticCode::InvalidConversion);
    let spellings = ConstantDiagnosticCode::ALL
        .iter()
        .map(|code| code.as_str())
        .collect::<Vec<&str>>();
    assert_eq!(spellings.len(), 17);
    for (index, spelling) in spellings.iter().enumerate() {
        assert!(
            !spellings[index + 1..].contains(spelling),
            "no diagnostic spelling is shared by two refusal conditions"
        );
    }
}

#[test]
fn refused_constants_publish_nothing() {
    let mut package = ConstantPackage::new(limits());
    package
        .declare(declaration(
            "pkg::A",
            ConstantValueClass::Int,
            &[],
            true,
            ConstantSelection::Unconditional,
        ))
        .unwrap_or_else(|error| panic!("`pkg::A` declares once: {error}"));
    package
        .declare(declaration(
            "pkg::B",
            ConstantValueClass::Bool,
            &[],
            true,
            ConstantSelection::Unconditional,
        ))
        .unwrap_or_else(|error| panic!("`pkg::B` declares once: {error}"));
    package
        .declare(declaration(
            "pkg::C",
            ConstantValueClass::Int,
            &["pkg::B"],
            true,
            ConstantSelection::Unconditional,
        ))
        .unwrap_or_else(|error| panic!("`pkg::C` declares once: {error}"));
    evaluate(&mut package, "pkg::A", "1");
    package
        .record_refusal("pkg::B", ConstantDiagnosticCode::InadmissibleOperation)
        .unwrap_or_else(|error| panic!("`pkg::B` refuses once: {error}"));
    assert_eq!(package.state("pkg::B"), Some(ConstantState::Refused));
    assert_eq!(
        package.refusal("pkg::B"),
        Some(ConstantDiagnosticCode::InadmissibleOperation)
    );
    assert_eq!(
        refuse(package.interface(), "a package with one refused constant").code(),
        ConstantDiagnosticCode::PartialPublicationRefused
    );
    assert_eq!(
        refuse(
            package.publish(&[TargetKind::Library]),
            "a package with one refused constant"
        )
        .code(),
        ConstantDiagnosticCode::PartialPublicationRefused
    );
    assert_eq!(
        refuse(
            package.record_evaluation("pkg::C", ConstantWork::new(1, 1, 1, 1), "1"),
            "a constant whose declared dependency is refused"
        )
        .code(),
        ConstantDiagnosticCode::PartialPublicationRefused
    );
    let mut exhausted = ConstantPackage::new(limits());
    exhausted
        .declare(declaration(
            "pkg::D",
            ConstantValueClass::Int,
            &[],
            true,
            ConstantSelection::Unconditional,
        ))
        .unwrap_or_else(|error| panic!("`pkg::D` declares once: {error}"));
    assert_eq!(
        refuse(
            exhausted.record_evaluation("pkg::D", ConstantWork::new(4096, 1, 1, 1), "1"),
            "a constant whose declared fuel is exhausted"
        )
        .code(),
        ConstantDiagnosticCode::Nontermination
    );
    assert_eq!(exhausted.state("pkg::D"), Some(ConstantState::Refused));
    assert_eq!(
        exhausted.refusal("pkg::D"),
        Some(ConstantDiagnosticCode::Nontermination)
    );
    assert_eq!(
        refuse(
            exhausted.publish(&[TargetKind::Library]),
            "a refused package"
        )
        .code(),
        ConstantDiagnosticCode::PartialPublicationRefused
    );
}

#[test]
fn interface_and_artifact_identity_bind_recorded_facts() {
    let mut package = ConstantPackage::new(limits());
    for (path, class, exported, value) in [
        ("pkg::A", ConstantValueClass::Int, true, "1"),
        ("pkg::B", ConstantValueClass::String, true, "\"b\""),
        ("pkg::C", ConstantValueClass::Bool, false, "true"),
    ] {
        package
            .declare(declaration(
                path,
                class,
                &[],
                exported,
                ConstantSelection::Unconditional,
            ))
            .unwrap_or_else(|error| panic!("`{path}` declares once: {error}"));
        evaluate(&mut package, path, value);
    }
    let interface = package
        .interface()
        .unwrap_or_else(|error| panic!("the fixture interface publishes: {error}"));
    assert_eq!(
        interface
            .entries()
            .keys()
            .map(String::as_str)
            .collect::<Vec<&str>>(),
        vec!["pkg::A", "pkg::B"],
        "only exported constants enter the interface, in canonical path order"
    );
    let identity = interface.identity();
    let binding = package
        .publish(&[TargetKind::Library, TargetKind::Binary])
        .unwrap_or_else(|error| panic!("the fixture artifact publishes: {error}"));
    assert_eq!(
        binding.targets(),
        [TargetKind::Binary, TargetKind::Library].as_slice(),
        "target kinds are recorded in canonical order"
    );
    assert_eq!(
        binding
            .evaluated()
            .iter()
            .map(String::as_str)
            .collect::<Vec<&str>>(),
        vec!["pkg::A", "pkg::B", "pkg::C"]
    );
    assert_eq!(binding.interface().as_str(), identity.as_str());
    assert!(
        binding
            .verify_presented_interface(identity.as_str())
            .is_ok()
    );
    assert_eq!(
        refuse(
            binding.verify_presented_interface("0".repeat(64).as_str()),
            "a mismatched presented interface identity"
        )
        .code(),
        ConstantDiagnosticCode::InterfaceIdentityMismatch
    );
    assert_eq!(
        refuse(
            package.publish(&[]),
            "an artifact with no declared target kind"
        )
        .code(),
        ConstantDiagnosticCode::PartialPublicationRefused
    );
    let mut changed = ConstantPackage::new(limits());
    changed
        .declare(declaration(
            "pkg::A",
            ConstantValueClass::Int,
            &[],
            true,
            ConstantSelection::Unconditional,
        ))
        .unwrap_or_else(|error| panic!("`pkg::A` declares once: {error}"));
    changed
        .declare(declaration(
            "pkg::B",
            ConstantValueClass::String,
            &[],
            true,
            ConstantSelection::Unconditional,
        ))
        .unwrap_or_else(|error| panic!("`pkg::B` declares once: {error}"));
    evaluate(&mut changed, "pkg::A", "1");
    evaluate(&mut changed, "pkg::B", "\"b\"");
    let changed_binding = changed
        .publish(&[TargetKind::Binary, TargetKind::Library])
        .unwrap_or_else(|error| panic!("the changed artifact publishes: {error}"));
    assert_ne!(
        binding.identity().as_str(),
        changed_binding.identity().as_str(),
        "the evaluated set participates in the artifact identity"
    );
}

#[test]
fn sealed_selection_gates_evaluation() {
    assert_eq!(
        refuse(
            ConstantDeclaration::new(
                "pkg::S",
                ConstantAdmissibility::Admissible(ConstantValueClass::Bool),
                &expression("pkg::S"),
                &[],
                true,
                ConstantSelection::AmbientBuildHostState,
            ),
            "an ambient build-host selection"
        )
        .code(),
        ConstantDiagnosticCode::UnsealedSelectionRefused
    );
    let mut inactive = ConstantPackage::new(limits());
    inactive
        .declare(declaration(
            "pkg::S",
            ConstantValueClass::Bool,
            &[],
            true,
            ConstantSelection::SealedFeaturePredicate { active: false },
        ))
        .unwrap_or_else(|error| panic!("a sealed inactive declaration is admissible: {error}"));
    assert_eq!(
        refuse(
            inactive.record_evaluation("pkg::S", ConstantWork::new(1, 1, 1, 1), "true"),
            "an inactive constant"
        )
        .code(),
        ConstantDiagnosticCode::InactiveEvaluationRefused
    );
    assert_eq!(
        inactive.refusal("pkg::S"),
        Some(ConstantDiagnosticCode::InactiveEvaluationRefused)
    );
    assert_eq!(
        refuse(
            inactive.publish(&[TargetKind::Library]),
            "an inactive package"
        )
        .code(),
        ConstantDiagnosticCode::PartialPublicationRefused,
        "an inactive constant contributes nothing, so the package does not publish"
    );
    let mut active = ConstantPackage::new(limits());
    active
        .declare(declaration(
            "pkg::S",
            ConstantValueClass::Bool,
            &[],
            true,
            ConstantSelection::SealedTargetPredicate { active: true },
        ))
        .unwrap_or_else(|error| panic!("a sealed active declaration is admissible: {error}"));
    evaluate(&mut active, "pkg::S", "true");
    assert!(active.publish(&[TargetKind::Library]).is_ok());
}

#[test]
fn package_load_executes_no_source() {
    assert!(admit_package_state(PackageStateClass::ImmutableConstant).is_ok());
    for (class, expected) in [
        (
            PackageStateClass::MutablePackageGlobal,
            ConstantDiagnosticCode::MutablePackageStateRefused,
        ),
        (
            PackageStateClass::SourceInitializer,
            ConstantDiagnosticCode::MutablePackageStateRefused,
        ),
        (
            PackageStateClass::LoaderHook,
            ConstantDiagnosticCode::LoaderExecutionRefused,
        ),
        (
            PackageStateClass::DependencyOrderStartupHook,
            ConstantDiagnosticCode::LoaderExecutionRefused,
        ),
    ] {
        assert_eq!(
            refuse(admit_package_state(class), "a refused package-state class").code(),
            expected
        );
    }
    for class in PackageStateClass::ALL {
        assert_eq!(
            PackageStateClass::from_wire_name(class.wire_name()),
            Some(class)
        );
    }
    assert!(PackageLoadFact::new("pkg", PackageStateClass::ImmutableConstant, false).is_ok());
    assert_eq!(
        refuse(
            PackageLoadFact::new("pkg", PackageStateClass::ImmutableConstant, true),
            "a package-load fact that reports source execution"
        )
        .code(),
        ConstantDiagnosticCode::LoaderExecutionRefused
    );
    assert_eq!(
        refuse(
            PackageLoadFact::new("pkg", PackageStateClass::MutablePackageGlobal, false),
            "a package-load fact that declares mutable package state"
        )
        .code(),
        ConstantDiagnosticCode::MutablePackageStateRefused
    );
}

#[test]
fn mutable_state_requires_an_explicit_owner() {
    for owner in [
        ApplicationStateOwner::MainOwnedValue,
        ApplicationStateOwner::SupervisedServiceTask,
        ApplicationStateOwner::HostCapability,
    ] {
        let declared = ApplicationStateDeclaration::new("app::counter", owner, true)
            .unwrap_or_else(|error| {
                panic!("`{}` is an explicit owner: {error}", owner.wire_name())
            });
        assert_eq!(declared.owner(), owner);
        assert!(declared.is_mutable());
        assert_eq!(declared.name(), "app::counter");
    }
    assert_eq!(
        refuse(
            ApplicationStateDeclaration::new("app::counter", ApplicationStateOwner::Unowned, true),
            "mutable application state with no owner"
        )
        .code(),
        ConstantDiagnosticCode::OwnerAbsent
    );
    assert!(
        ApplicationStateDeclaration::new("app::config", ApplicationStateOwner::Unowned, false)
            .is_ok(),
        "an immutable value needs no mutable-state owner"
    );
    for owner in ApplicationStateOwner::ALL {
        assert_eq!(
            ApplicationStateOwner::from_wire_name(owner.wire_name()),
            Some(owner)
        );
    }
}

#[test]
fn non_claims_are_not_presented_as_guarantees() {
    assert_eq!(CONSTANT_NON_CLAIM_ORDER, ConstantNonClaim::ALL);
    for claim in ConstantNonClaim::ALL {
        assert_eq!(
            ConstantNonClaim::from_wire_name(claim.wire_name()),
            Some(claim)
        );
        assert!(check_constant_non_claims(&[ConstantNonClaimAssertion::new(claim, false)]).is_ok());
        assert_eq!(
            refuse(
                check_constant_non_claims(&[ConstantNonClaimAssertion::new(claim, true)]),
                "a non-claim presented as a guarantee"
            )
            .code(),
            ConstantDiagnosticCode::NonClaimAsGuarantee
        );
    }
    assert_eq!(CONSTANT_NON_CLAIMS.len(), 12);
    assert!(CONSTANT_NON_CLAIMS.iter().all(|claim| !claim.is_empty()));
}
