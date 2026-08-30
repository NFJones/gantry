//! Requirement-indexed executable evidence for the frontend lexical owner.

use std::fs;
use std::path::{Path, PathBuf};

use gantry::frontend::{
    LexContext, LexError, Lexer, PromptDelimiter, Punctuation, ReservedWord, TokenKind,
};
use gantry::source::{SourceLimits, SourceSnapshotBuilder};
use serde::Deserialize;

const EVIDENCE_ID: &str = "crates/gantry-conformance/tests/frontend_lexical_evidence.rs#lexical_requirement_vectors_cover_reviewed_clauses";

#[derive(Debug, Deserialize)]
struct EvidenceManifest {
    format: String,
    specification_sha256: String,
    issue: String,
    entries: Vec<EvidenceEntry>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
struct EvidenceEntry {
    requirement: String,
    clause: String,
}

#[derive(Debug, Deserialize)]
struct RequirementReview {
    specification_sha256: String,
    requirements: Vec<Requirement>,
}

#[derive(Debug, Deserialize)]
struct Requirement {
    id: String,
    clauses: Vec<Clause>,
}

#[derive(Debug, Deserialize)]
struct Clause {
    key: String,
    state: String,
    evidence: Vec<String>,
}

#[test]
fn reviewed_frontend_lexical_evidence_is_closed() {
    let root = workspace_root();
    let manifest: EvidenceManifest =
        read_json(&root.join("protocol/conformance/frontend-lexical-v1.json"));
    let review: RequirementReview = read_json(&root.join("protocol/requirements/reviewed-v1.json"));

    assert_eq!(manifest.format, "gantry.frontend-lexical-evidence/v1");
    assert_eq!(manifest.issue, "GNT-FE-001");
    assert_eq!(manifest.specification_sha256, review.specification_sha256);
    assert!(!manifest.entries.is_empty());
    assert!(manifest.entries.windows(2).all(|pair| pair[0] < pair[1]));

    for entry in manifest.entries {
        let clause = review
            .requirements
            .iter()
            .find(|requirement| requirement.id == entry.requirement)
            .and_then(|requirement| {
                requirement
                    .clauses
                    .iter()
                    .find(|clause| clause.key == entry.clause)
            })
            .unwrap_or_else(|| panic!("missing {}:{}", entry.requirement, entry.clause));
        assert_eq!(
            clause.state, "covered",
            "{}:{}",
            entry.requirement, entry.clause
        );
        assert_eq!(
            clause.evidence,
            [EVIDENCE_ID],
            "{}:{}",
            entry.requirement,
            entry.clause
        );
    }
}

#[test]
fn lexical_requirement_vectors_cover_reviewed_clauses() {
    let source = concat!(
        "\u{feff}/* outer /* inner */ */ action agent agents as attempt Bool break ",
        "continue crate Decision decide default detach discard else enum Err false Float fn ",
        "fork for idempotent if impl in inline Int join joinall let limit List loop match mod ",
        "mut new non_idempotent None null Ok OperationError Option prompt pure read_only Result ",
        "return retry_limit self session Some spawn String struct super true Tuple unbounded Unit ",
        "until use using when while with α_2 _ 0 1_000 2.5e+2 ",
        ":: -> => == != <= >= && || += -= *= /= %= ",
        "\"a\\n\\u{1f642}\" r#\"raw \\\\ text\"#"
    );
    with_lexer(source, 256, |lexer| {
        let reserved = [
            "action",
            "agent",
            "agents",
            "as",
            "attempt",
            "Bool",
            "break",
            "continue",
            "crate",
            "Decision",
            "decide",
            "default",
            "detach",
            "discard",
            "else",
            "enum",
            "Err",
            "false",
            "Float",
            "fn",
            "fork",
            "for",
            "idempotent",
            "if",
            "impl",
            "in",
            "inline",
            "Int",
            "join",
            "joinall",
            "let",
            "limit",
            "List",
            "loop",
            "match",
            "mod",
            "mut",
            "new",
            "non_idempotent",
            "None",
            "null",
            "Ok",
            "OperationError",
            "Option",
            "prompt",
            "pure",
            "read_only",
            "Result",
            "return",
            "retry_limit",
            "self",
            "session",
            "Some",
            "spawn",
            "String",
            "struct",
            "super",
            "true",
            "Tuple",
            "unbounded",
            "Unit",
            "until",
            "use",
            "using",
            "when",
            "while",
            "with",
        ];
        for spelling in reserved {
            assert_eq!(
                ReservedWord::from_spelling(spelling).map(ReservedWord::spelling),
                Some(spelling)
            );
            assert!(matches!(
                lexer.next(LexContext::Ordinary).map(|token| token.kind().clone()),
                Ok(TokenKind::ReservedWord(word)) if word.spelling() == spelling
            ));
        }
        assert!(matches!(
            lexer.next(LexContext::Ordinary).map(|token| token.kind().clone()),
            Ok(TokenKind::Identifier(value)) if &*value == "α_2"
        ));
        assert!(matches!(
            lexer
                .next(LexContext::Ordinary)
                .map(|token| token.kind().clone()),
            Ok(TokenKind::Punctuation(Punctuation::Underscore))
        ));
        assert!(
            matches!(lexer.next(LexContext::Ordinary).map(|token| token.kind().clone()), Ok(TokenKind::IntegerLiteral(value)) if &*value == "0")
        );
        assert!(
            matches!(lexer.next(LexContext::Ordinary).map(|token| token.kind().clone()), Ok(TokenKind::IntegerLiteral(value)) if &*value == "1_000")
        );
        assert!(
            matches!(lexer.next(LexContext::Ordinary).map(|token| token.kind().clone()), Ok(TokenKind::FloatLiteral(value)) if &*value == "2.5e+2")
        );

        for punctuation in [
            Punctuation::PathSeparator,
            Punctuation::ThinArrow,
            Punctuation::FatArrow,
            Punctuation::EqualEqual,
            Punctuation::NotEqual,
            Punctuation::LessEqual,
            Punctuation::GreaterEqual,
            Punctuation::AndAnd,
            Punctuation::OrOr,
            Punctuation::PlusEqual,
            Punctuation::MinusEqual,
            Punctuation::StarEqual,
            Punctuation::SlashEqual,
            Punctuation::PercentEqual,
        ] {
            assert!(matches!(
                lexer.next(LexContext::Ordinary).map(|token| token.kind().clone()),
                Ok(TokenKind::Punctuation(actual)) if actual == punctuation
            ));
        }
        assert!(
            matches!(lexer.next(LexContext::Ordinary).map(|token| token.kind().clone()), Ok(TokenKind::StringLiteral(value)) if &*value == "a\n🙂")
        );
        assert!(
            matches!(lexer.next(LexContext::Ordinary).map(|token| token.kind().clone()), Ok(TokenKind::RawStringLiteral(value)) if &*value == "raw \\\\ text")
        );
        assert!(matches!(
            lexer
                .next(LexContext::Ordinary)
                .map(|token| token.kind().clone()),
            Ok(TokenKind::EndOfFile)
        ));
    });

    for (source, code) in [
        ("01", "invalid-number"),
        ("1_", "invalid-number"),
        ("1e+", "invalid-number"),
        ("\"line\nfeed\"", "literal-line-terminator"),
        ("\"\\u{D800}\"", "invalid-unicode-escape"),
        ("r#\"unterminated", "unterminated-raw-string"),
        ("/* unterminated", "unterminated-block-comment"),
        ("// hidden \u{feff}\nvalue", "unexpected-byte-order-mark"),
    ] {
        with_lexer(source, 16, |lexer| {
            assert!(matches!(
                lexer.next(LexContext::Ordinary),
                Err(LexError::Diagnostic(ref diagnostic)) if diagnostic.code.as_str() == code
            ));
        });
    }

    with_lexer("123 1_2", 8, |lexer| {
        assert!(
            matches!(lexer.next(LexContext::DirectiveInteger).map(|token| token.kind().clone()), Ok(TokenKind::DirectiveInteger(value)) if &*value == "123")
        );
        assert!(
            matches!(lexer.next(LexContext::DirectiveInteger).map(|token| token.kind().clone()), Ok(TokenKind::IntegerLiteral(value)) if &*value == "1_2")
        );
    });

    with_lexer("r#\"a $$${Some(\"draft\")} z\"#", 32, |lexer| {
        let token = lexer
            .next(LexContext::PromptTemplate)
            .unwrap_or_else(|_| unreachable!("valid prompt template"));
        let TokenKind::PromptTemplate(template) = token.kind() else {
            unreachable!("prompt template token")
        };
        assert_eq!(template.delimiter(), PromptDelimiter::Raw);
        assert_eq!(template.literals(), &["a $".into(), " z".into()]);
        assert_eq!(template.interpolations()[0].source(), "Some(\"draft\")");
    });

    with_lexer("\"\"\"\n  first\n    second\\nline\n  \"\"\"", 8, |lexer| {
        let token = lexer
            .next(LexContext::PromptTemplate)
            .unwrap_or_else(|_| unreachable!("valid block prompt"));
        let TokenKind::PromptTemplate(template) = token.kind() else {
            unreachable!("prompt template token")
        };
        assert_eq!(template.delimiter(), PromptDelimiter::Block);
        assert_eq!(template.literals(), &["first\n  second\nline".into()]);
    });
}

fn with_lexer<T>(source: &str, token_limit: u64, test: impl FnOnce(&mut Lexer<'_>) -> T) -> T {
    let limits = SourceLimits::new(1, 1_000_000, 1_000_000, token_limit, 64)
        .unwrap_or_else(|_| unreachable!("positive limits"));
    let mut builder = SourceSnapshotBuilder::new(limits);
    assert!(builder.add_file("main.gnt", source.as_bytes()).is_ok());
    let mut snapshot = builder.finish();
    let (records, counters) = snapshot.records_and_counters_mut();
    let record = records
        .first()
        .unwrap_or_else(|| unreachable!("one source"));
    let mut lexer =
        Lexer::new(record, counters).unwrap_or_else(|_| unreachable!("valid UTF-8 fixture"));
    test(&mut lexer)
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> T {
    let bytes =
        fs::read(path).unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|error| panic!("could not decode {}: {error}", path.display()))
}
