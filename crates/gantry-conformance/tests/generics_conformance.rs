//! Cross-layer conformance properties for generics and static traits.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use gantry::analysis::{
    AnalysisError, AnalysisStatus, TypedPackage, analyze_package_types,
    analyze_package_types_with_limits,
};
use gantry::frontend::{CompletedSyntaxPhase, validate_package_syntax};
use gantry::ir::{
    CanonicalCallableIdentity, CanonicalTemplateIdentity, TypeDescriptor, TypeExpression,
};
use gantry::portable::FrontendResourceCode;
use gantry::source::{FrontendLimits, SourceLimits};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TempDirectory(PathBuf);

impl TempDirectory {
    fn new(source: &str) -> Self {
        let suffix = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "gantry-generics-conformance-{}-{suffix}",
            std::process::id()
        ));
        fs::create_dir(&path)
            .unwrap_or_else(|error| panic!("could not create {}: {error}", path.display()));
        fs::write(path.join("main.gnt"), source)
            .unwrap_or_else(|error| panic!("could not write generic fixture: {error}"));
        Self(path)
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn generic_canonicalization_properties_are_deterministic() {
    for (left_source, right_source) in [
        (
            "struct Envelope<T> { value: T }\npure fn preserve<T>(value: T) -> T { value }\npure fn main() -> Envelope<String> { preserve(Envelope::<String> { value: \"x\" }) }",
            "struct Envelope<Value> { value: Value }\npure fn preserve<Value>(value: Value) -> Value { value }\npure fn main() -> Envelope<String> { preserve(Envelope::<String> { value: \"x\" }) }",
        ),
        (
            "trait Label { pure fn label(self) -> String; }\nstruct First {}\nstruct Second {}\nimpl Label for First { pure fn label(self) -> String { \"first\" } }\nimpl Label for Second { pure fn label(self) -> String { \"second\" } }\npure fn main(value: First) -> String { value.label() }",
            "trait Label { pure fn label(self) -> String; }\nstruct First {}\nstruct Second {}\nimpl Label for Second { pure fn label(self) -> String { \"second\" } }\nimpl Label for First { pure fn label(self) -> String { \"first\" } }\npure fn main(value: First) -> String { value.label() }",
        ),
        (
            "trait First { pure fn first(self); }\ntrait Second { pure fn second(self); }\npure fn hold<T>(value: T) -> T where T: First, T: Second { value }\nfn main() {}",
            "trait First { pure fn first(self); }\ntrait Second { pure fn second(self); }\npure fn hold<T>(value: T) -> T where T: Second, T: First { value }\nfn main() {}",
        ),
    ] {
        let left = analyze(left_source);
        let right = analyze(right_source);
        let repeated = analyze(left_source);
        assert_eq!(
            left.status(),
            AnalysisStatus::Valid,
            "{:?}",
            left.diagnostics()
        );
        assert_eq!(
            right.status(),
            AnalysisStatus::Valid,
            "{:?}",
            right.diagnostics()
        );
        assert_eq!(canonical_ir(&left), canonical_ir(&right));
        assert_eq!(canonical_ir(&left), canonical_ir(&repeated));
    }

    for expression in [
        "crate::Envelope<^0.0>",
        "Result<List<^0.0>,^self:1>",
        "Tuple<crate::Envelope<String>,Option<^0.1>>",
    ] {
        let parsed = TypeExpression::from_canonical_string(expression, 16)
            .unwrap_or_else(|error| panic!("type expression {expression} failed: {error:?}"));
        assert_eq!(parsed.as_str(), expression);
    }
    for descriptor in [
        "crate::Envelope<String>",
        "Result<List<Int>,crate::Failure<String>>",
    ] {
        let parsed = TypeDescriptor::from_canonical_string(descriptor)
            .unwrap_or_else(|error| panic!("descriptor {descriptor} failed: {error:?}"));
        assert_eq!(parsed.canonical_string(), descriptor);
    }
    for identity in [
        "crate::preserve<String>",
        "<crate::Envelope<String>>::get",
        "<crate::Envelope<String> as crate::Label>::label",
    ] {
        let parsed = CanonicalCallableIdentity::from_canonical_string(identity, 16)
            .unwrap_or_else(|error| panic!("callable {identity} failed: {error:?}"));
        assert_eq!(parsed.as_str(), identity);
    }
    for identity in [
        "crate::preserve<^0.0>",
        "<crate::Envelope<^0.0> as crate::Label>::label",
    ] {
        let parsed = CanonicalTemplateIdentity::from_canonical_string(identity, 16)
            .unwrap_or_else(|error| panic!("template {identity} failed: {error:?}"));
        assert_eq!(parsed.as_str(), identity);
    }

    let explicit = analyze(
        "trait Convert<T> { pure fn convert<U>(self, fallback: U) -> T; }\nstruct Item {}\nimpl Convert<String> for Item { pure fn convert<U>(self, fallback: U) -> String { \"converted\" } }\nfn main(value: Item) -> String { Convert::<String>::convert::<Int>(value, 1) }",
    );
    let inferred = analyze(
        "trait Convert<T> { pure fn convert<U>(self, fallback: U) -> T; }\nstruct Item {}\nimpl Convert<String> for Item { pure fn convert<U>(self, fallback: U) -> String { \"converted\" } }\nfn main(value: Item) -> String { Convert::convert(value, 1) }",
    );
    assert_eq!(
        concrete_instantiations(&explicit),
        concrete_instantiations(&inferred)
    );

    let implementations = [
        "impl<T> Label for Envelope<T> { pure fn label(self) -> String { \"generic\" } }\nimpl Label for Envelope<String> { pure fn label(self) -> String { \"specific\" } }",
        "impl Label for Envelope<String> { pure fn label(self) -> String { \"specific\" } }\nimpl<T> Label for Envelope<T> { pure fn label(self) -> String { \"generic\" } }",
    ];
    let diagnostics = implementations.map(|implementations| {
        let package = analyze(&format!(
            "trait Label {{ pure fn label(self) -> String; }}\nstruct Envelope<T> {{ value: T }}\n{implementations}\nfn main() {{}}"
        ));
        assert_eq!(package.status(), AnalysisStatus::Invalid);
        package
            .diagnostics()
            .iter()
            .filter(|diagnostic| diagnostic.code.as_str() == "overlapping-implementation")
            .map(|diagnostic| diagnostic.fields.clone())
            .collect::<Vec<_>>()
    });
    assert_eq!(diagnostics[0], diagnostics[1]);
}

#[test]
fn generic_scale_envelopes_are_charged_and_deduplicated() {
    let depth = syntax(
        "fn wrap<T>(value: T) -> List<T> { [value] }\nfn main(value: List<List<String>>) { discard wrap(value); }",
    );
    assert_eq!(
        analyze_package_types_with_limits(&depth, limits(4, 64, 64))
            .unwrap_or_else(|error| panic!("at-limit depth failed: {error:?}"))
            .status(),
        AnalysisStatus::Valid
    );
    assert_eq!(
        analyze_package_types_with_limits(&depth, limits(5, 64, 64))
            .unwrap_or_else(|error| panic!("above-limit depth failed: {error:?}"))
            .status(),
        AnalysisStatus::Valid
    );
    assert!(matches!(
        analyze_package_types_with_limits(&depth, limits(3, 64, 64)),
        Err(AnalysisError::ResourceLimit { error, .. })
            if error.code == FrontendResourceCode::ConstructedTypeDepthLimit
                && error.limit == 3
                && error.observed == Some(4)
    ));

    let instantiations = syntax(
        "pure fn preserve<T>(value: T) -> T { value }\nfn main() { discard preserve::<String>(\"x\"); discard preserve::<Int>(1); }",
    );
    let at_limit = analyze_package_types_with_limits(&instantiations, limits(64, 2, 64))
        .unwrap_or_else(|error| panic!("at-limit instantiations failed: {error:?}"));
    assert_eq!(at_limit.status(), AnalysisStatus::Valid);
    assert_eq!(at_limit.generic_instantiations().len(), 2);
    assert_eq!(
        analyze_package_types_with_limits(&instantiations, limits(64, 3, 64))
            .unwrap_or_else(|error| panic!("above-limit instantiations failed: {error:?}"))
            .status(),
        AnalysisStatus::Valid
    );
    assert!(matches!(
        analyze_package_types_with_limits(&instantiations, limits(64, 1, 64)),
        Err(AnalysisError::ResourceLimit { error, .. })
            if error.code == FrontendResourceCode::GenericInstantiationLimit
                && error.limit == 1
                && error.observed == Some(2)
    ));

    let repeated_calls = (0..64)
        .map(|_| "discard preserve::<String>(\"x\");")
        .collect::<Vec<_>>()
        .join("\n");
    let repeated = syntax(&format!(
        "pure fn preserve<T>(value: T) -> T {{ value }}\nfn main() {{\n{repeated_calls}\n}}"
    ));
    let repeated = analyze_package_types_with_limits(&repeated, limits(64, 1, 64))
        .unwrap_or_else(|error| panic!("deduplicated instantiation scale failed: {error:?}"));
    assert_eq!(repeated.status(), AnalysisStatus::Valid);
    assert_eq!(repeated.generic_instantiations().len(), 1);

    let declarations = (0..128)
        .map(|index| {
            format!(
                "struct Item{index} {{}}\nimpl Label for Item{index} {{ pure fn label(self) -> String {{ \"item\" }} }}"
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let many_candidates_source = format!(
        "trait Label {{ pure fn label(self) -> String; }}\n{declarations}\npure fn main(value: Item127) -> String {{ value.label() }}"
    );
    let candidates = analyze(&many_candidates_source);
    assert_eq!(
        candidates.status(),
        AnalysisStatus::Valid,
        "{:?}",
        candidates.diagnostics()
    );
    assert!(
        candidates
            .executable_program()
            .unwrap_or_else(|| unreachable!("source-valid package has an executable program"))
            .callable_identities()
            .iter()
            .any(|identity| identity.as_str() == "<crate::Item127 as crate::Label>::label")
    );
    let one_candidate_source = "trait Label { pure fn label(self) -> String; }\nstruct Item127 {}\nimpl Label for Item127 { pure fn label(self) -> String { \"item\" } }\npure fn main(value: Item127) -> String { value.label() }";
    assert_eq!(
        minimum_trait_steps(one_candidate_source),
        minimum_trait_steps(&many_candidates_source),
        "candidate indexing must not charge unrelated receiver constructors"
    );

    let obligation_prefix = "trait Label { pure fn label(self) -> String; }\nstruct Item {}\nstruct Envelope<T> { value: T }\nimpl Label for Item { pure fn label(self) -> String { \"item\" } }\nimpl<T> Label for Envelope<T> where T: Label { pure fn label(self) -> String { \"envelope\" } }";
    let one_obligation_source =
        format!("{obligation_prefix}\nfn main(value: Envelope<Item>) {{ discard value.label(); }}");
    let repeated_obligations = (0..64)
        .map(|_| "discard value.label();")
        .collect::<Vec<_>>()
        .join(" ");
    let repeated_obligation_source =
        format!("{obligation_prefix}\nfn main(value: Envelope<Item>) {{ {repeated_obligations} }}");
    let one_obligation_steps = minimum_trait_steps(&one_obligation_source);
    let repeated_obligation_steps = minimum_trait_steps(&repeated_obligation_source);
    assert_eq!(
        repeated_obligation_steps,
        one_obligation_steps + 63,
        "each memo hit charges one lookup without recharging candidate or predicate expansion"
    );
    let obligations = syntax(&repeated_obligation_source);
    assert_eq!(
        analyze_package_types_with_limits(&obligations, limits(64, 64, repeated_obligation_steps),)
            .unwrap_or_else(|error| panic!("memoized trait scale failed: {error:?}"))
            .status(),
        AnalysisStatus::Valid
    );
    assert_eq!(
        analyze_package_types_with_limits(
            &obligations,
            limits(64, 64, repeated_obligation_steps.saturating_add(1)),
        )
        .unwrap_or_else(|error| panic!("above-limit trait scale failed: {error:?}"))
        .status(),
        AnalysisStatus::Valid
    );
    assert!(matches!(
        analyze_package_types_with_limits(
            &obligations,
            limits(64, 64, repeated_obligation_steps.saturating_sub(1)),
        ),
        Err(AnalysisError::ResourceLimit { error, .. })
            if error.code == FrontendResourceCode::TraitResolutionStepLimit
                && error.limit == repeated_obligation_steps.saturating_sub(1)
    ));
}

fn analyze(source: &str) -> TypedPackage {
    let phase = syntax(source);
    analyze_package_types(&phase)
        .unwrap_or_else(|error| panic!("generic analysis failed operationally: {error:?}"))
}

fn syntax(source: &str) -> CompletedSyntaxPhase {
    let root = TempDirectory::new(source);
    validate_package_syntax(
        &root.0,
        SourceLimits::new(4, 1_048_576, 4_194_304, 262_144, 256)
            .unwrap_or_else(|_| unreachable!("positive source limits")),
        256,
    )
    .unwrap_or_else(|error| panic!("generic syntax failed: {error:?}"))
}

fn limits(depth: u64, instantiations: u64, trait_steps: u64) -> FrontendLimits {
    FrontendLimits::new(
        4,
        1_048_576,
        4_194_304,
        262_144,
        256,
        4_194_304,
        4_194_304,
        4_194_304,
        4_194_304,
        depth,
        instantiations,
        trait_steps,
    )
    .unwrap_or_else(|_| unreachable!("positive frontend limits"))
}

fn canonical_ir(package: &TypedPackage) -> &[u8] {
    package
        .canonical_ir()
        .unwrap_or_else(|| unreachable!("source-valid package has canonical IR"))
        .artifact()
        .canonical_bytes()
}

fn concrete_instantiations(package: &TypedPackage) -> Vec<String> {
    package
        .generic_instantiations()
        .iter()
        .map(|instantiation| instantiation.concrete().canonical_string())
        .collect()
}

fn minimum_trait_steps(source: &str) -> u64 {
    let phase = syntax(source);
    for limit in 1..=256 {
        match analyze_package_types_with_limits(&phase, limits(256, 256, limit)) {
            Ok(package) if package.status() == AnalysisStatus::Valid => return limit,
            Err(AnalysisError::ResourceLimit { error, .. })
                if error.code == FrontendResourceCode::TraitResolutionStepLimit => {}
            Ok(package) => panic!(
                "work-budget fixture was source-invalid: {:?}",
                package.diagnostics()
            ),
            Err(error) => panic!("unexpected work-budget failure at {limit}: {error:?}"),
        }
    }
    panic!("trait-resolution fixture exceeded the diagnostic work bound")
}
