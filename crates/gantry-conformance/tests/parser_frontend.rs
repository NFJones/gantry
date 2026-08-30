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
    Parser::new(record, counters)
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
fn effects(value: Int) {
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
