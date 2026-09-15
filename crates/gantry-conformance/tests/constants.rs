//! Machine-checked conformance for the pure Section 32 constant model.
//!
//! The tests use declared classes, members, operations, work records, dependency
//! facts, sealed predicates, package state, and application state only. They neither
//! parse source, evaluate a real initializer, link a package, execute a loader, nor
//! create runtime state.

use std::fs;
use std::path::{Path, PathBuf};

use gantry::ir::{
    ApplicationStateDeclaration, ApplicationStateOwner, CONSTANT_CLAUSES, CONSTANT_INT_LIMIT,
    CONSTANT_NON_CLAIM_ORDER, CONSTANT_NON_CLAIMS, CanonicalPath, ConstantAdmissibility,
    ConstantConversion, ConstantDeclaration, ConstantDiagnosticCode, ConstantEffect, ConstantError,
    ConstantExpression, ConstantNonClaim, ConstantNonClaimAssertion, ConstantOperation,
    ConstantPackage, ConstantRefusalReason, ConstantSelection, ConstantState, ConstantValueClass,
    ConstantWork, EvaluationLimits, FeatureName, MAX_DECLARED_NAME_BYTES, PackageLoadFact,
    PackageStateClass, TargetKind, TargetPredicate, TargetPredicateName, admit_package_state,
    admit_sealed_predicate_name, check_constant_non_claims, checked_float, checked_int,
};

const A: &str = "crate::pkg::a";
const B: &str = "crate::pkg::b";
const C: &str = "crate::pkg::c";
const D: &str = "crate::pkg::d";
const EXTERNAL: &str = "crate::dep::k";

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

fn canonical(value: &str) -> CanonicalPath {
    CanonicalPath::new(value)
        .unwrap_or_else(|error| panic!("the fixture path {value} is canonical: {error}"))
}

fn limits() -> EvaluationLimits {
    EvaluationLimits::new(64, 8, 16, 256)
        .unwrap_or_else(|error| panic!("the fixture limits are nonzero: {error}"))
}

fn expression(path: &str) -> ConstantExpression {
    ConstantExpression::new(path, &[ConstantOperation::Literal], &[])
        .unwrap_or_else(|error| panic!("the fixture initializer is admissible: {error}"))
}

fn plain_declaration(path: &str, class: ConstantValueClass) -> ConstantDeclaration {
    declaration(path, class, &[], true, ConstantSelection::Unconditional)
}

fn declaration(
    path: &str,
    class: ConstantValueClass,
    dependencies: &[&str],
    exported: bool,
    selection: ConstantSelection,
) -> ConstantDeclaration {
    declare_with(path, class, &[], dependencies, exported, selection)
}

fn declare_with(
    path: &str,
    class: ConstantValueClass,
    members: &[ConstantAdmissibility],
    dependencies: &[&str],
    exported: bool,
    selection: ConstantSelection,
) -> ConstantDeclaration {
    ConstantDeclaration::new(
        path,
        ConstantAdmissibility::Admissible(class),
        members,
        &expression(path),
        dependencies,
        exported,
        selection,
    )
    .unwrap_or_else(|error| panic!("the fixture declaration {path} is admissible: {error}"))
}

fn evaluate(package: &mut ConstantPackage, path: &str, canonical_value: &str) {
    let work = ConstantWork::new(4, 2, 2, 8);
    package
        .record_evaluation(path, work, canonical_value)
        .unwrap_or_else(|error| panic!("the fixture constant `{path}` evaluates: {error}"));
}

fn feature_selection(feature: &str, active: bool) -> ConstantSelection {
    let name = FeatureName::new(feature)
        .unwrap_or_else(|error| panic!("the fixture feature {feature} is valid: {error}"));
    ConstantSelection::SealedPredicate {
        predicate: TargetPredicate::FeatureEnabled(name),
        active,
    }
}

fn identity_of(declarations: &[(&str, &str)]) -> String {
    let mut package = ConstantPackage::new(limits());
    for (path, value) in declarations {
        package
            .declare(plain_declaration(path, ConstantValueClass::Int))
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

fn interface_paths(package: &ConstantPackage) -> Vec<String> {
    package
        .interface()
        .unwrap_or_else(|error| panic!("the fixture interface publishes: {error}"))
        .entries()
        .keys()
        .map(|path| path.as_str().to_owned())
        .collect()
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
    assert!(ConstantValueClass::Struct.carries_members());
    assert!(!ConstantValueClass::List.carries_members());
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
        .declare(plain_declaration(A, ConstantValueClass::Int))
        .unwrap_or_else(|error| panic!("`{A}` declares once: {error}"));
    assert_eq!(
        refuse(
            package.declare(plain_declaration(A, ConstantValueClass::Bool)),
            "a duplicate canonical path"
        )
        .code(),
        ConstantDiagnosticCode::InvalidDeclaration
    );
    for spelling in [
        "",
        "   ",
        "pkg::a",
        "not a path",
        "crate::",
        "crate::a::",
        "crate::a::1bad",
    ] {
        let error = refuse(
            ConstantExpression::new(spelling, &[ConstantOperation::Literal], &[]),
            "a non-canonical path spelling",
        );
        assert_eq!(
            error.code(),
            ConstantDiagnosticCode::InvalidDeclaration,
            "`{spelling}` must be refused as non-canonical"
        );
    }
    assert_eq!(
        refuse(
            ConstantDeclaration::new(
                B,
                ConstantAdmissibility::Admissible(ConstantValueClass::Unit),
                &[],
                &expression(C),
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
                D,
                ConstantAdmissibility::Admissible(ConstantValueClass::Int),
                &[],
                &expression(D),
                &[D],
                false,
                ConstantSelection::Unconditional,
            ),
            "a self-declared dependency"
        )
        .code(),
        ConstantDiagnosticCode::Cycle
    );
    evaluate(&mut package, A, "7");
    assert_eq!(package.state(A), Some(ConstantState::Evaluated));
    assert_eq!(package.value(A), Some("7"));
    assert_eq!(
        refuse(
            package.record_evaluation(A, ConstantWork::new(1, 1, 1, 1), "8"),
            "a second evaluation of an immutable constant"
        )
        .code(),
        ConstantDiagnosticCode::InvalidDeclaration
    );
    assert_eq!(
        refuse(
            package.record_refusal(A, ConstantDiagnosticCode::Overflow),
            "a refusal of an evaluated constant"
        )
        .code(),
        ConstantDiagnosticCode::InvalidDeclaration
    );
    assert_eq!(
        package.value(A),
        Some("7"),
        "the canonical value is immutable"
    );
    let mut undeclared = ConstantPackage::new(limits());
    assert_eq!(
        refuse(
            undeclared.record_evaluation(A, ConstantWork::new(1, 1, 1, 1), "1"),
            "an undeclared constant"
        )
        .code(),
        ConstantDiagnosticCode::UnresolvedDependency
    );
    assert_eq!(canonical(A).as_str(), A);
}

#[test]
fn admissible_and_refused_classes_are_closed() {
    for reason in ConstantRefusalReason::ALL {
        let outcome = ConstantDeclaration::new(
            A,
            ConstantAdmissibility::Refused(reason),
            &[],
            &expression(A),
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
        let members = if class.carries_members() {
            vec![ConstantAdmissibility::Admissible(ConstantValueClass::Unit)]
        } else {
            Vec::new()
        };
        let declared = declare_with(
            A,
            class,
            &members,
            &[],
            true,
            ConstantSelection::Unconditional,
        );
        assert_eq!(declared.class(), class);
        assert_eq!(declared.members().len(), members.len());
    }
}

#[test]
fn struct_and_enum_members_are_adjudicated() {
    let members = [
        ConstantAdmissibility::Admissible(ConstantValueClass::Int),
        ConstantAdmissibility::Admissible(ConstantValueClass::String),
    ];
    let declared = declare_with(
        A,
        ConstantValueClass::Struct,
        &members,
        &[],
        true,
        ConstantSelection::Unconditional,
    );
    assert_eq!(declared.members().len(), 2);
    let enumeration = declare_with(
        B,
        ConstantValueClass::Enum,
        &[ConstantAdmissibility::Admissible(ConstantValueClass::Unit)],
        &[],
        true,
        ConstantSelection::Unconditional,
    );
    assert_eq!(enumeration.class(), ConstantValueClass::Enum);
    assert_eq!(
        refuse(
            ConstantDeclaration::new(
                A,
                ConstantAdmissibility::Admissible(ConstantValueClass::Enum),
                &[],
                &expression(A),
                &[],
                true,
                ConstantSelection::Unconditional,
            ),
            "a memberless enum class"
        )
        .code(),
        ConstantDiagnosticCode::InadmissibleType
    );
    assert_eq!(
        refuse(
            ConstantDeclaration::new(
                A,
                ConstantAdmissibility::Admissible(ConstantValueClass::Struct),
                &[ConstantAdmissibility::Refused(
                    ConstantRefusalReason::LiveResource
                )],
                &expression(A),
                &[],
                true,
                ConstantSelection::Unconditional,
            ),
            "a struct member with a refused class"
        )
        .code(),
        ConstantDiagnosticCode::InadmissibleType
    );
    assert_eq!(
        refuse(
            ConstantDeclaration::new(
                A,
                ConstantAdmissibility::Admissible(ConstantValueClass::Int),
                &members,
                &expression(A),
                &[],
                true,
                ConstantSelection::Unconditional,
            ),
            "members on a class that carries none"
        )
        .code(),
        ConstantDiagnosticCode::InvalidDeclaration
    );
}

#[test]
fn refused_effects_prevent_evaluation() {
    for effect in ConstantEffect::ALL {
        let outcome = ConstantExpression::new(A, &[ConstantOperation::Literal], &[effect]);
        assert_eq!(
            refuse(outcome, "an initializer with a refused effect").code(),
            ConstantDiagnosticCode::InadmissibleOperation
        );
    }
    assert_eq!(
        refuse(
            ConstantExpression::new(A, &[], &[]),
            "an initializer with no admissible operation"
        )
        .code(),
        ConstantDiagnosticCode::InadmissibleOperation
    );
    let admissible = ConstantExpression::new(
        A,
        &[
            ConstantOperation::Literal,
            ConstantOperation::IntegerArithmetic,
            ConstantOperation::Comparison,
        ],
        &[],
    )
    .unwrap_or_else(|error| panic!("the declared operation set is admissible: {error}"));
    assert_eq!(admissible.operations().len(), 3);
    assert_eq!(admissible.path().as_str(), A);
}

#[test]
fn evaluation_limits_and_determinism_are_declared() {
    assert_eq!(
        refuse(EvaluationLimits::new(0, 1, 1, 1), "a zero fuel limit").code(),
        ConstantDiagnosticCode::LimitExceeded
    );
    assert_eq!(
        refuse(EvaluationLimits::new(1, 1, 0, 1), "a zero member limit").code(),
        ConstantDiagnosticCode::LimitExceeded
    );
    assert_eq!(
        refuse(EvaluationLimits::new(1, 1, 1, 0), "a zero encoded limit").code(),
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
    for work in [
        ConstantWork::new(1, limits.depth() + 1, 1, 1),
        ConstantWork::new(1, 1, limits.members() + 1, 1),
        ConstantWork::new(1, 1, 1, limits.encoded_bytes() + 1),
    ] {
        assert_eq!(
            refuse(work.admit(limits), "a declared limit exceeded").code(),
            ConstantDiagnosticCode::LimitExceeded
        );
    }
    assert_eq!(
        identity_of(&[(A, "1"), (B, "2")]),
        identity_of(&[(B, "2"), (A, "1")]),
        "declaration order must not change the canonical interface identity"
    );
    assert_ne!(
        identity_of(&[(A, "1")]),
        identity_of(&[(A, "2")]),
        "a changed canonical value must change the interface identity"
    );
}

#[test]
fn evaluation_order_is_deterministic_and_cycles_are_refused() {
    let mut package = ConstantPackage::new(limits());
    for (path, dependencies) in [(C, &[B][..]), (B, &[A][..]), (A, &[][..])] {
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
    let order = package
        .evaluation_order()
        .unwrap_or_else(|error| panic!("the fixture graph is acyclic: {error}"));
    assert_eq!(
        order
            .iter()
            .map(CanonicalPath::as_str)
            .collect::<Vec<&str>>(),
        vec![A, B, C]
    );
    let mut reordered = ConstantPackage::new(limits());
    for (path, dependencies) in [(A, &[][..]), (C, &[B][..]), (B, &[A][..])] {
        reordered
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
        reordered
            .evaluation_order()
            .unwrap_or_else(|error| panic!("the permuted graph is acyclic: {error}"))
            .iter()
            .map(CanonicalPath::as_str)
            .collect::<Vec<&str>>(),
        vec![A, B, C],
        "declaration order must not change the evaluation order"
    );
    let mut imported = ConstantPackage::new(limits());
    imported
        .admit_external(EXTERNAL)
        .unwrap_or_else(|error| panic!("the imported constant path is admissible: {error}"));
    imported
        .declare(declaration(
            D,
            ConstantValueClass::Int,
            &[EXTERNAL],
            true,
            ConstantSelection::Unconditional,
        ))
        .unwrap_or_else(|error| panic!("`{D}` declares once: {error}"));
    assert_eq!(
        imported
            .evaluation_order()
            .unwrap_or_else(|error| panic!("an imported dependency resolves: {error}"))
            .iter()
            .map(CanonicalPath::as_str)
            .collect::<Vec<&str>>(),
        vec![D]
    );
    assert_eq!(
        refuse(
            imported.admit_external(D),
            "an external path declared locally"
        )
        .code(),
        ConstantDiagnosticCode::InvalidDeclaration
    );
    let mut unresolved = ConstantPackage::new(limits());
    unresolved
        .declare(declaration(
            D,
            ConstantValueClass::Int,
            &[B],
            true,
            ConstantSelection::Unconditional,
        ))
        .unwrap_or_else(|error| panic!("`{D}` declares once: {error}"));
    assert_eq!(
        refuse(unresolved.evaluation_order(), "an unresolved dependency").code(),
        ConstantDiagnosticCode::UnresolvedDependency
    );
}

#[test]
fn cycle_refusal_names_a_member_on_the_cycle() {
    let mut package = ConstantPackage::new(limits());
    for (path, dependencies) in [(A, &[B][..]), (B, &[C][..]), (C, &[B][..])] {
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
    let refusal = refuse(
        package.evaluation_order(),
        "a declaration blocked beside a cycle",
    );
    assert_eq!(refusal.code(), ConstantDiagnosticCode::Cycle);
    let reported = refusal
        .path()
        .unwrap_or_else(|| panic!("a cycle refusal names its declared member"))
        .as_str();
    assert!(
        reported != A,
        "`{A}` is only blocked by the cycle and must not be named"
    );
    assert!(
        reported == B || reported == C,
        "the refusal must name a member of the B/C cycle, reported `{reported}`"
    );
    let mut pure = ConstantPackage::new(limits());
    for (path, dependencies) in [(B, &[C][..]), (C, &[B][..])] {
        pure.declare(declaration(
            path,
            ConstantValueClass::Int,
            dependencies,
            true,
            ConstantSelection::Unconditional,
        ))
        .unwrap_or_else(|error| panic!("`{path}` declares once: {error}"));
    }
    let pure_refusal = refuse(pure.evaluation_order(), "a two-node cycle");
    assert_eq!(pure_refusal.code(), ConstantDiagnosticCode::Cycle);
    assert_eq!(pure_refusal.path().map(CanonicalPath::as_str), Some(B));
}

#[test]
fn evaluation_requires_dependencies_to_be_evaluated_first() {
    let mut package = ConstantPackage::new(limits());
    package
        .declare(plain_declaration(A, ConstantValueClass::Int))
        .unwrap_or_else(|error| panic!("`{A}` declares once: {error}"));
    package
        .declare(declaration(
            B,
            ConstantValueClass::Int,
            &[A],
            true,
            ConstantSelection::Unconditional,
        ))
        .unwrap_or_else(|error| panic!("`{B}` declares once: {error}"));
    let error = refuse(
        package.record_evaluation(B, ConstantWork::new(1, 1, 1, 1), "1"),
        "a declaration evaluated before its dependency",
    );
    assert_eq!(
        error.code(),
        ConstantDiagnosticCode::PartialPublicationRefused
    );
    assert_eq!(package.state(B), Some(ConstantState::Refused));
    assert_eq!(
        package.refusal(B),
        Some(ConstantDiagnosticCode::PartialPublicationRefused)
    );
    let mut ordered = ConstantPackage::new(limits());
    ordered
        .declare(plain_declaration(A, ConstantValueClass::Int))
        .unwrap_or_else(|error| panic!("`{A}` declares once: {error}"));
    ordered
        .declare(declaration(
            B,
            ConstantValueClass::Int,
            &[A],
            true,
            ConstantSelection::Unconditional,
        ))
        .unwrap_or_else(|error| panic!("`{B}` declares once: {error}"));
    evaluate(&mut ordered, A, "1");
    evaluate(&mut ordered, B, "2");
    assert!(
        ordered.publish(&[TargetKind::Library]).is_ok(),
        "an in-order package publishes"
    );
}

#[test]
fn refusals_are_transitive_through_dependency_chains() {
    let mut package = ConstantPackage::new(limits());
    for (path, dependencies) in [(C, &[][..]), (B, &[C][..]), (A, &[B][..])] {
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
    package
        .record_refusal(C, ConstantDiagnosticCode::InadmissibleOperation)
        .unwrap_or_else(|error| panic!("`{C}` refuses once: {error}"));
    assert_eq!(package.state(C), Some(ConstantState::Refused));
    assert_eq!(
        refuse(
            package.record_evaluation(B, ConstantWork::new(1, 1, 1, 1), "1"),
            "a dependent of a refused constant"
        )
        .code(),
        ConstantDiagnosticCode::PartialPublicationRefused
    );
    assert_eq!(package.state(B), Some(ConstantState::Refused));
    assert_eq!(
        package.refusal(B),
        Some(ConstantDiagnosticCode::PartialPublicationRefused)
    );
    assert_eq!(
        refuse(
            package.record_evaluation(A, ConstantWork::new(1, 1, 1, 1), "1"),
            "a dependent two steps from a refusal"
        )
        .code(),
        ConstantDiagnosticCode::PartialPublicationRefused
    );
    assert_eq!(package.state(A), Some(ConstantState::Refused));
    assert_eq!(
        package.value(A),
        None,
        "a refusal chain never records a value"
    );
    assert_eq!(
        refuse(package.publish(&[TargetKind::Library]), "a refused chain").code(),
        ConstantDiagnosticCode::PartialPublicationRefused
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
    for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        assert_eq!(
            refuse(checked_float(value), "a non-finite float result").code(),
            ConstantDiagnosticCode::Overflow
        );
    }
    assert!(
        ConstantConversion::new(ConstantValueClass::Int, ConstantValueClass::Float, true).is_ok()
    );
    assert!(
        ConstantConversion::new(ConstantValueClass::Int, ConstantValueClass::Int, false).is_ok(),
        "an identity conversion is always exact"
    );
    assert_eq!(
        refuse(
            ConstantConversion::new(ConstantValueClass::Float, ConstantValueClass::Int, false),
            "an inexact conversion"
        )
        .code(),
        ConstantDiagnosticCode::InvalidConversion
    );
    assert_eq!(ConstantDiagnosticCode::ALL.len(), 17);
    let spellings = ConstantDiagnosticCode::ALL
        .iter()
        .map(|code| code.as_str())
        .collect::<Vec<&str>>();
    for (index, spelling) in spellings.iter().enumerate() {
        assert!(
            !spellings[index + 1..].contains(spelling),
            "no diagnostic spelling is shared by two refusal conditions"
        );
    }
}

#[test]
fn refusals_report_their_clause_and_declared_constant() {
    let mut package = ConstantPackage::new(limits());
    package
        .declare(plain_declaration(A, ConstantValueClass::Int))
        .unwrap_or_else(|error| panic!("`{A}` declares once: {error}"));
    let error = refuse(
        package.record_evaluation(A, ConstantWork::new(4096, 1, 1, 1), "1"),
        "a constant whose declared fuel is exhausted",
    );
    assert_eq!(error.code(), ConstantDiagnosticCode::Nontermination);
    assert_eq!(error.requirement(), CONSTANT_CLAUSES[4]);
    assert_eq!(error.path().map(CanonicalPath::as_str), Some(A));
    assert!(!error.detail().is_empty());
    let declaration_error = refuse(
        ConstantExpression::new("pkg::a", &[ConstantOperation::Literal], &[]),
        "a non-canonical path",
    );
    assert_eq!(declaration_error.requirement(), CONSTANT_CLAUSES[1]);
    assert!(
        declaration_error.path().is_none(),
        "a refusal without a canonical path reports no declared constant"
    );
    for code in ConstantDiagnosticCode::ALL {
        assert!(CONSTANT_CLAUSES.contains(&code.requirement()));
    }
}

#[test]
fn refused_constants_publish_nothing() {
    let mut package = ConstantPackage::new(limits());
    for path in [A, B] {
        package
            .declare(plain_declaration(path, ConstantValueClass::Int))
            .unwrap_or_else(|error| panic!("`{path}` declares once: {error}"));
    }
    package
        .declare(declaration(
            D,
            ConstantValueClass::Int,
            &[B],
            true,
            ConstantSelection::Unconditional,
        ))
        .unwrap_or_else(|error| panic!("`{D}` declares once: {error}"));
    evaluate(&mut package, A, "1");
    package
        .record_refusal(B, ConstantDiagnosticCode::InadmissibleOperation)
        .unwrap_or_else(|error| panic!("`{B}` refuses once: {error}"));
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
            package.record_evaluation(D, ConstantWork::new(1, 1, 1, 1), "1"),
            "a constant whose declared dependency is refused"
        )
        .code(),
        ConstantDiagnosticCode::PartialPublicationRefused
    );
    let mut exhausted = ConstantPackage::new(limits());
    exhausted
        .declare(plain_declaration(A, ConstantValueClass::Int))
        .unwrap_or_else(|error| panic!("`{A}` declares once: {error}"));
    assert_eq!(
        refuse(
            exhausted.record_evaluation(A, ConstantWork::new(4096, 1, 1, 1), "1"),
            "a constant whose declared fuel is exhausted"
        )
        .code(),
        ConstantDiagnosticCode::Nontermination
    );
    assert_eq!(exhausted.state(A), Some(ConstantState::Refused));
    assert_eq!(
        exhausted.refusal(A),
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
    package
        .declare(declare_with(
            A,
            ConstantValueClass::Int,
            &[],
            &[],
            true,
            ConstantSelection::Unconditional,
        ))
        .unwrap_or_else(|error| panic!("`{A}` declares once: {error}"));
    package
        .declare(declare_with(
            B,
            ConstantValueClass::String,
            &[],
            &[],
            true,
            ConstantSelection::Unconditional,
        ))
        .unwrap_or_else(|error| panic!("`{B}` declares once: {error}"));
    package
        .declare(declare_with(
            C,
            ConstantValueClass::Struct,
            &[ConstantAdmissibility::Admissible(ConstantValueClass::Int)],
            &[],
            false,
            ConstantSelection::Unconditional,
        ))
        .unwrap_or_else(|error| panic!("`{C}` declares once: {error}"));
    evaluate(&mut package, A, "1");
    evaluate(&mut package, B, "\"b\"");
    evaluate(&mut package, C, "{int}");
    assert_eq!(interface_paths(&package), vec![A, B]);
    let identity = package
        .interface()
        .unwrap_or_else(|error| panic!("the fixture interface publishes: {error}"))
        .identity();
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
        vec![A, B, C]
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
    let library_only = package
        .publish(&[TargetKind::Library])
        .unwrap_or_else(|error| panic!("the single-target artifact publishes: {error}"));
    assert_ne!(
        binding.identity().as_str(),
        library_only.identity().as_str(),
        "the declared target set participates in the artifact identity"
    );
    let mut renamed = ConstantPackage::new(limits());
    renamed
        .declare(plain_declaration(D, ConstantValueClass::Int))
        .unwrap_or_else(|error| panic!("`{D}` declares once: {error}"));
    evaluate(&mut renamed, D, "1");
    let renamed_identity = renamed
        .interface()
        .unwrap_or_else(|error| panic!("the renamed interface publishes: {error}"))
        .identity();
    assert_ne!(
        identity.as_str(),
        renamed_identity.as_str(),
        "the canonical path participates in the interface identity"
    );
    let mut retyped = ConstantPackage::new(limits());
    retyped
        .declare(plain_declaration(A, ConstantValueClass::Tuple))
        .unwrap_or_else(|error| panic!("`{A}` declares once: {error}"));
    evaluate(&mut retyped, A, "1");
    let retyped_identity = retyped
        .interface()
        .unwrap_or_else(|error| panic!("the retyped interface publishes: {error}"))
        .identity();
    assert_ne!(
        identity.as_str(),
        retyped_identity.as_str(),
        "the admitted class participates in the interface identity"
    );
}

#[test]
fn sealed_selection_binds_the_target_predicate_vocabulary() {
    let selection = feature_selection("tls", true);
    assert!(selection.is_sealed());
    assert!(selection.is_active());
    assert_eq!(selection.wire_name(), "sealed-predicate");
    assert_eq!(
        selection.predicate_name(),
        Some(TargetPredicateName::FeatureEnabled)
    );
    let predicate_name = selection
        .predicate_name()
        .unwrap_or_else(|| panic!("the selection names a sealed predicate"));
    assert!(
        TargetPredicateName::ALL.contains(&predicate_name),
        "every selection names a predicate of the closed GNT-17.3 table"
    );
    assert_eq!(TargetPredicateName::ALL.len(), 2);
    assert_eq!(TargetPredicateName::from_wire_name("custom"), None);
    assert!(
        selection
            .predicate()
            .is_some_and(|predicate| predicate.wire_name() == "feature-enabled:tls")
    );
    for name in ["descriptor-field", "feature-enabled"] {
        assert!(
            admit_sealed_predicate_name(name).is_ok(),
            "`{name}` is a sealed predicate name"
        );
    }
    for name in ["custom", "", "descriptor_field"] {
        assert_eq!(
            refuse(
                admit_sealed_predicate_name(name),
                "a predicate name outside the sealed table"
            )
            .code(),
            ConstantDiagnosticCode::UnsealedSelectionRefused
        );
    }
    assert_eq!(
        refuse(
            ConstantDeclaration::new(
                A,
                ConstantAdmissibility::Admissible(ConstantValueClass::Bool),
                &[],
                &expression(A),
                &[],
                true,
                ConstantSelection::AmbientBuildHostState,
            ),
            "an ambient build-host selection"
        )
        .code(),
        ConstantDiagnosticCode::UnsealedSelectionRefused
    );
    let mut active = ConstantPackage::new(limits());
    active
        .declare(declaration(
            A,
            ConstantValueClass::Bool,
            &[],
            true,
            feature_selection("tls", true),
        ))
        .unwrap_or_else(|error| panic!("a sealed active declaration is admissible: {error}"));
    evaluate(&mut active, A, "true");
    assert!(active.publish(&[TargetKind::Library]).is_ok());
}

#[test]
fn excluded_declarations_do_not_evaluate_or_block_publication() {
    let mut inactive_only = ConstantPackage::new(limits());
    inactive_only
        .declare(declaration(
            A,
            ConstantValueClass::Bool,
            &[],
            true,
            feature_selection("tls", false),
        ))
        .unwrap_or_else(|error| panic!("a sealed inactive declaration is admissible: {error}"));
    assert!(inactive_only.selected_paths().is_empty());
    assert!(
        inactive_only
            .evaluation_order()
            .unwrap_or_else(|error| panic!("an excluded declaration needs no order: {error}"))
            .is_empty()
    );
    let interface = inactive_only
        .interface()
        .unwrap_or_else(|error| panic!("an excluded declaration blocks nothing: {error}"));
    assert!(
        interface.is_empty(),
        "an excluded declaration contributes nothing"
    );
    let binding = inactive_only
        .publish(&[TargetKind::Library])
        .unwrap_or_else(|error| panic!("an excluded package publishes: {error}"));
    assert!(binding.evaluated().is_empty());
    assert_eq!(
        refuse(
            inactive_only.record_evaluation(A, ConstantWork::new(1, 1, 1, 1), "true"),
            "an excluded constant"
        )
        .code(),
        ConstantDiagnosticCode::InactiveEvaluationRefused
    );
    let mut projected = ConstantPackage::new(limits());
    projected
        .declare(declaration(
            A,
            ConstantValueClass::Bool,
            &[],
            true,
            feature_selection("tls", false),
        ))
        .unwrap_or_else(|error| panic!("`{A}` declares once: {error}"));
    projected
        .declare(declaration(
            B,
            ConstantValueClass::Int,
            &[],
            true,
            ConstantSelection::Unconditional,
        ))
        .unwrap_or_else(|error| panic!("`{B}` declares once: {error}"));
    evaluate(&mut projected, B, "2");
    assert_eq!(interface_paths(&projected), vec![B]);
    let mut partial = ConstantPackage::new(limits());
    partial
        .declare(declaration(
            A,
            ConstantValueClass::Bool,
            &[],
            true,
            feature_selection("tls", false),
        ))
        .unwrap_or_else(|error| panic!("`{A}` declares once: {error}"));
    partial
        .declare(declaration(
            C,
            ConstantValueClass::Int,
            &[A],
            true,
            ConstantSelection::Unconditional,
        ))
        .unwrap_or_else(|error| panic!("`{C}` declares once: {error}"));
    assert_eq!(
        refuse(
            partial.evaluation_order(),
            "a dependency on an excluded constant"
        )
        .code(),
        ConstantDiagnosticCode::InactiveEvaluationRefused
    );
    assert_eq!(
        refuse(
            partial.record_evaluation(C, ConstantWork::new(1, 1, 1, 1), "1"),
            "a dependency on an excluded constant"
        )
        .code(),
        ConstantDiagnosticCode::InactiveEvaluationRefused
    );
    assert_eq!(partial.state(C), Some(ConstantState::Refused));
    assert_eq!(
        refuse(
            partial.interface(),
            "a refused selected declaration still blocks publication"
        )
        .code(),
        ConstantDiagnosticCode::PartialPublicationRefused
    );
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
    assert_eq!(
        refuse(
            ApplicationStateDeclaration::new(
                "x".repeat(MAX_DECLARED_NAME_BYTES + 1).as_str(),
                ApplicationStateOwner::MainOwnedValue,
                true,
            ),
            "an oversized declared name"
        )
        .code(),
        ConstantDiagnosticCode::InvalidDeclaration
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
    assert_eq!(CONSTANT_NON_CLAIMS.len(), 13);
    assert_eq!(ConstantNonClaim::ALL.len(), 13);
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
    assert!(CONSTANT_NON_CLAIMS.iter().all(|claim| !claim.is_empty()));
    assert!(
        CONSTANT_NON_CLAIMS
            .iter()
            .any(|claim| claim.contains("source-span")),
        "refusal rendering is a declared non-claim"
    );
}
