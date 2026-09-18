//! External surface-parser contract coverage through the public Gantry facade.

use gantry::frontend::{ParseOutcome, Parser, SyntaxForm};
use gantry::source::{SourceLimits, SourceSnapshotBuilder};

fn parse(source: &str, token_limit: u64, diagnostic_limit: u64) -> ParseOutcome {
    let limits = SourceLimits::new(1, 2_000_000, 2_000_000, token_limit, diagnostic_limit)
        .unwrap_or_else(|_| unreachable!("positive limits"));
    let mut builder = SourceSnapshotBuilder::new(limits);
    assert!(builder.add_file("main.gnt", source.as_bytes()).is_ok());
    let mut snapshot = builder.finish();
    let (records, counters) = snapshot.records_and_counters_mut();
    let record = records
        .first()
        .unwrap_or_else(|| unreachable!("one source"));
    Parser::new(record, counters, i64::MAX as u64)
        .parse_module()
        .unwrap_or_else(|error| panic!("syntax phase failed: {error}"))
}

#[test]
fn public_parser_preserves_authored_order_spans_and_semantic_boundaries() {
    let source = r#"agents { worker }
struct Duplicate { value: Int, value: Int }
fn main() -> String {
    prompt "Summarize ${missing_name}." -> String
}
"#;
    let outcome = parse(source, 256, 8);
    assert!(outcome.is_valid(), "{:?}", outcome.diagnostics());
    let tree = outcome.tree().unwrap_or_else(|| unreachable!("valid tree"));
    let root = tree
        .node(tree.root())
        .unwrap_or_else(|| unreachable!("module root"));
    assert_eq!(root.span().bytes().start(), 0);
    assert_eq!(root.span().bytes().end(), source.len() as u64);

    let forms = root
        .children()
        .iter()
        .filter_map(|child| tree.node(*child))
        .map(|node| node.form())
        .collect::<Vec<_>>();
    assert!(matches!(forms.first(), Some(SyntaxForm::AgentsDeclaration)));
    assert!(matches!(forms.get(1), Some(SyntaxForm::StructDeclaration)));
    assert!(matches!(
        forms.get(2),
        Some(SyntaxForm::FunctionDeclaration)
    ));
    assert!(
        tree.nodes()
            .iter()
            .any(|node| matches!(node.form(), SyntaxForm::PromptExpression))
    );
}

#[test]
fn public_parser_supports_parametric_declarations_static_traits_and_generic_paths() {
    let source = r#"
struct Envelope<T> where T: Label { value: T }
enum State<T, E> { Ready(T), Failed(E) }
trait Convert<T> {
    fn convert<U>(self, fallback: U) -> T where Self: Label, U: Label,
        effects { prompt, action(read_only), background };
}
impl<T, U> Convert<U> for Envelope<T> where T: Label, U: Label {
    pure fn convert<V>(self, fallback: V) -> U where V: Label { fallback }
}
fn preserve<T>(value: T) -> T where T: Label { value }
fn main(value: Envelope<String>) {
    let next: Envelope<String> = Envelope::<String> { value: "ready" };
    discard preserve::<Envelope<String>>(next);
    discard Convert::<String>::convert::<String>(value, "fallback");
    prompt "${Envelope::<String> { value: "ok" }}";
    match State::<String, String>::Ready("ok") {
        State::<String, String>::Ready(item) => { discard item; },
        State::<String, String>::Failed(error) => { discard error; },
    }
}
"#;
    let outcome = parse(source, 2_048, 32);
    assert!(outcome.is_valid(), "{:?}", outcome.diagnostics());
    let tree = outcome.tree().unwrap_or_else(|| unreachable!("valid tree"));
    for expected in [
        SyntaxForm::TraitDeclaration,
        SyntaxForm::TraitMethodDeclaration,
        SyntaxForm::TypeParameterList,
        SyntaxForm::TypeArgumentList,
        SyntaxForm::WhereClause,
        SyntaxForm::EffectContract,
    ] {
        assert!(tree.nodes().iter().any(|node| {
            std::mem::discriminant(node.form()) == std::mem::discriminant(&expected)
        }));
    }

    for invalid in [
        "struct Broken<T { value: T }",
        "fn main() { discard value::<String>; }",
        "trait Empty { fn missing(self); }",
        "fn invalid(value: Self) -> Self { value }",
        "impl Self { pure fn invalid(self) {} }",
    ] {
        let outcome = parse(invalid, 256, 8);
        assert!(!outcome.is_valid(), "unexpectedly accepted {invalid}");
    }
}

#[test]
fn public_parser_distinguishes_statement_and_value_block_forms() {
    let source = r#"fn value(flag: Bool) -> Int {
    if flag { return 1; } else { return 2; }
}
fn contexts() -> Int {
    with worker { session(new) { 1 } }
}
fn matches(value: Int) -> Int {
    match value { _ => 1 }
}
fn effect_case(value: Int) {
    match value { _ => { discard value; } }
}
"#;
    let outcome = parse(source, 512, 8);
    assert!(outcome.is_valid(), "{:?}", outcome.diagnostics());
    let tree = outcome.tree().unwrap_or_else(|| unreachable!("valid tree"));
    assert!(
        tree.nodes()
            .iter()
            .any(|node| matches!(node.form(), SyntaxForm::WithExpression))
    );
    assert!(
        tree.nodes()
            .iter()
            .any(|node| matches!(node.form(), SyntaxForm::MatchExpression))
    );
    assert!(
        tree.nodes()
            .iter()
            .any(|node| matches!(node.form(), SyntaxForm::MatchStatement))
    );
}

#[test]
fn public_parser_reports_bounded_source_backed_recovery_diagnostics() {
    let source = "struct Broken { value Int; }\naction read_only missing( -> String;\nfn good() {}";
    let outcome = parse(source, 128, 8);
    assert!(!outcome.is_valid());
    assert!(outcome.diagnostics().len() >= 2);
    assert!(outcome.diagnostics().iter().all(|diagnostic| {
        diagnostic.code.as_str() == "unexpected-token"
            && diagnostic.phase.wire_name() == "syntax"
            && diagnostic.primary.is_some()
            && diagnostic.fields.contains_key("encountered")
            && diagnostic.fields.contains_key("expected")
    }));
    assert!(
        outcome
            .diagnostics()
            .windows(2)
            .all(|pair| pair[0].primary <= pair[1].primary)
    );

    let invalid_interpolation = parse("fn main() { prompt \"${prompt \\\"nested\\\"}\"; }", 64, 4);
    assert!(!invalid_interpolation.is_valid());
}

#[test]
fn public_parser_rejects_executable_top_level_statements() {
    for source in ["let value: Int = 1;", "return;", "prompt \"top level\";"] {
        let outcome = parse(source, 64, 4);
        assert!(!outcome.is_valid(), "unexpectedly accepted {source}");
        assert!(!outcome.diagnostics().is_empty());
    }
}

#[test]
fn public_parser_handles_adversarial_nesting_without_native_recursion() {
    let depth = 5_000;
    let mut source = String::from("fn deep(value: ");
    source.push_str(&"Option<".repeat(depth));
    source.push_str("Int");
    source.push_str(&">".repeat(depth));
    source.push_str(") -> Int { ");
    source.push_str(&"(".repeat(depth));
    source.push('1');
    source.push_str(&")".repeat(depth));
    source.push_str(" }");
    let outcome = parse(&source, 40_000, 4);
    assert!(outcome.is_valid(), "{:?}", outcome.diagnostics());
}

/// `shared` is contextual only at an inherent-method receiver and remains an identifier elsewhere.
#[test]
fn public_parser_accepts_contextual_shared_receiver_without_reserving_shared() {
    let source = r#"
struct Counter { value: Int }
impl Counter { pure fn value(shared self) -> Int { self.value } }
fn main(shared: Int, counter: Counter) -> Int { counter.value() + shared }
"#;
    let outcome = parse(source, 256, 8);
    assert!(outcome.is_valid(), "{:?}", outcome.diagnostics());
}

/// `exclusive` is contextual only at an inherent-method receiver and remains an identifier elsewhere.
#[test]
fn public_parser_accepts_contextual_exclusive_receiver_without_reserving_exclusive() {
    let source = r#"
struct Counter { value: Int }
impl Counter { fn increment(exclusive self) { self.value += 1; } }
fn main(exclusive: Int, counter: Counter) -> Int { counter.increment(); exclusive }
"#;
    let outcome = parse(source, 256, 8);
    assert!(outcome.is_valid(), "{:?}", outcome.diagnostics());
}

/// The contextual receiver form rejects incomplete and parameter-like malformed spellings.
#[test]
fn public_parser_rejects_malformed_shared_receiver_forms() {
    for source in [
        "struct Counter { value: Int } impl Counter { fn read(shared) -> Int { 1 } }",
        "struct Counter { value: Int } impl Counter { fn read(shared mut self) -> Int { 1 } }",
        "struct Counter { value: Int } impl Counter { fn read(shared self: Counter) -> Int { 1 } }",
    ] {
        let outcome = parse(source, 256, 8);
        assert!(!outcome.is_valid(), "unexpectedly accepted {source}");
        assert!(outcome.diagnostics().iter().all(|diagnostic| {
            diagnostic.code.as_str() == "unexpected-token" && diagnostic.primary.is_some()
        }));
    }
}

/// A malformed callable type spelling is refused by the parser with a structured diagnostic.
///
/// The admitted annotation form is `Fn(<parameters>) -> <result>`; a lowercase `fn(...)` spelling
/// must not reach the type phase, where it would otherwise abort internally (`3f66325e`).
#[test]
fn public_parser_rejects_malformed_callable_annotations() {
    for source in [
        "fn inc(value: Int) -> Int { value + 1 } fn main() -> Int { let f: fn(Int) -> Int = crate::inc; 0 }",
        "fn inc(value: Int) -> Int { value + 1 } fn main() -> Int { let f: fn() -> Int = crate::inc; 0 }",
        "fn inc(value: Int) -> Int { value + 1 } fn main() -> Int { let f: fn = crate::inc; 0 }",
        "fn apply(callback: fn(Int) -> Int) -> Int { 0 } fn main() -> Int { 0 }",
    ] {
        let outcome = parse(source, 256, 8);
        assert!(!outcome.is_valid(), "unexpectedly accepted {source}");
        let annotation = source
            .find(": fn")
            .or_else(|| source.find("(fn"))
            .map(|index| index as u64 + 2)
            .unwrap_or_else(|| unreachable!("each source spells the annotation"));
        assert!(
            outcome.diagnostics().iter().any(|diagnostic| {
                diagnostic.code.as_str() == "unexpected-token"
                    && diagnostic
                        .primary
                        .as_ref()
                        .is_some_and(|span| span.bytes().start() == annotation)
            }),
            "source: {source}; diagnostics: {:?}",
            outcome.diagnostics()
        );
    }
    // The admitted annotation form stays valid.
    let admitted = parse(
        "fn inc(value: Int) -> Int { value + 1 } fn main() -> Int { let f: Fn(Int) -> Int = crate::inc; 0 }",
        256,
        8,
    );
    assert!(admitted.is_valid(), "{:?}", admitted.diagnostics());
}

/// The contextual exclusive receiver form rejects incomplete and parameter-like spellings.
#[test]
fn public_parser_rejects_malformed_exclusive_receiver_forms() {
    for source in [
        "struct Counter { value: Int } impl Counter { fn update(exclusive) { } }",
        "struct Counter { value: Int } impl Counter { fn update(exclusive mut self) { } }",
        "struct Counter { value: Int } impl Counter { fn update(exclusive self: Counter) { } }",
    ] {
        let outcome = parse(source, 256, 8);
        assert!(!outcome.is_valid(), "unexpectedly accepted {source}");
        assert!(outcome.diagnostics().iter().all(|diagnostic| {
            diagnostic.code.as_str() == "unexpected-token" && diagnostic.primary.is_some()
        }));
    }
}

/// `owned self` is an admitted receiver spelling, while `owned` stays a usable identifier.
#[test]
fn public_parser_admits_owned_receiver_and_keeps_owned_contextual() {
    let admitted = parse(
        "struct Counter { value: Int } impl Counter { fn take(owned self) -> Int { self.value } }",
        256,
        8,
    );
    assert!(admitted.is_valid(), "{:?}", admitted.diagnostics());

    let identifier_use = parse(
        "fn main(owned: Int) -> Int { let owned: Int = 1; owned }",
        256,
        8,
    );
    assert!(
        identifier_use.is_valid(),
        "{:?}",
        identifier_use.diagnostics()
    );

    for source in [
        "struct Counter { value: Int } impl Counter { fn take(move self) -> Int { self.value } }",
        "struct Counter { value: Int } impl Counter { fn take(consuming self) -> Int { self.value } }",
        "struct Counter { value: Int } impl Counter { fn take(owned mut self) { } }",
        "struct Counter { value: Int } impl Counter { fn take(owned self: Counter) -> Int { self.value } }",
    ] {
        let outcome = parse(source, 256, 8);
        assert!(!outcome.is_valid(), "unexpectedly accepted {source}");
        assert!(outcome.diagnostics().iter().all(|diagnostic| {
            diagnostic.code.as_str() == "unexpected-token" && diagnostic.primary.is_some()
        }));
    }
}

/// `affine` is a contextual struct modifier, not a reserved word, and stays a valid identifier.
#[test]
fn public_parser_accepts_affine_struct_and_keeps_affine_contextual() {
    let source = r#"affine struct Token { value: Int }
affine struct Box<T> { value: T }
struct Ordinary { value: Int }
fn main(affine: Int, token: Token) -> Int { let affine_again: Int = affine; discard token; affine_again }
"#;
    let outcome = parse(source, 512, 16);
    assert!(outcome.is_valid(), "{:?}", outcome.diagnostics());
    let tree = outcome.tree().unwrap_or_else(|| unreachable!("valid tree"));
    let affine_structs = tree
        .nodes()
        .iter()
        .filter(|node| {
            matches!(node.form(), SyntaxForm::StructDeclaration)
                && node.children().iter().any(|child| {
                    tree.node(*child)
                        .is_some_and(|n| matches!(n.form(), SyntaxForm::AffineStructModifier))
                })
        })
        .count();
    assert_eq!(affine_structs, 2);
}

/// `affine` without a following `struct` is a syntax fault at item position.
#[test]
fn public_parser_rejects_affine_without_struct() {
    for source in ["affine Token { value: Int }", "affine enum State { Ready }"] {
        let outcome = parse(source, 64, 4);
        assert!(!outcome.is_valid(), "unexpectedly accepted {source}");
    }
}

/// `must_consume` is a contextual struct modifier, not a reserved word, and stays a valid identifier.
#[test]
fn public_parser_accepts_must_consume_struct_and_keeps_it_contextual() {
    let source = r#"must_consume struct Token { value: Int }
must_consume struct Box<T> { value: T }
struct Ordinary { value: Int }
fn main(must_consume: Int, token: Token) -> Int { let must_consume_again: Int = must_consume; discard token; must_consume_again }
"#;
    let outcome = parse(source, 512, 16);
    assert!(outcome.is_valid(), "{:?}", outcome.diagnostics());
    let tree = outcome.tree().unwrap_or_else(|| unreachable!("valid tree"));
    let must_consume_structs = tree
        .nodes()
        .iter()
        .filter(|node| {
            matches!(node.form(), SyntaxForm::StructDeclaration)
                && node.children().iter().any(|child| {
                    tree.node(*child)
                        .is_some_and(|n| matches!(n.form(), SyntaxForm::MustConsumeStructModifier))
                })
        })
        .count();
    assert_eq!(must_consume_structs, 2);
}

/// `must_consume` without a following `struct` is a syntax fault at item position.
#[test]
fn public_parser_rejects_must_consume_without_struct() {
    for source in [
        "must_consume Token { value: Int }",
        "must_consume enum State { Ready }",
    ] {
        let outcome = parse(source, 64, 4);
        assert!(!outcome.is_valid(), "unexpectedly accepted {source}");
        assert!(
            outcome.diagnostics().iter().any(|diagnostic| {
                diagnostic.code.as_str() == "unexpected-token"
                    && diagnostic.fields.get("expected").map(AsRef::as_ref) == Some("struct")
            }),
            "{source}: {:?}",
            outcome.diagnostics()
        );
    }
}

/// Two stacked ownership modifiers cannot precede one struct declaration.
#[test]
fn public_parser_rejects_stacked_ownership_struct_modifiers() {
    for source in [
        "affine must_consume struct Token { value: Int }",
        "must_consume affine struct Token { value: Int }",
    ] {
        let outcome = parse(source, 64, 4);
        assert!(!outcome.is_valid(), "unexpectedly accepted {source}");
        assert!(
            outcome.diagnostics().iter().any(|diagnostic| {
                diagnostic.code.as_str() == "unexpected-token"
                    && diagnostic.fields.get("expected").map(AsRef::as_ref) == Some("struct")
            }),
            "{source}: {:?}",
            outcome.diagnostics()
        );
    }
}
