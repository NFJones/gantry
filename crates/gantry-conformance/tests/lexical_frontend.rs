//! External lexical contract coverage through the public Gantry facade.

use gantry::frontend::{LexContext, LexError, Lexer, PromptDelimiter, Punctuation, TokenKind};
use gantry::portable::FrontendResourceCode;
use gantry::source::{SourceLimits, SourceSnapshotBuilder};

fn with_lexer<T>(source: &[u8], token_limit: u64, test: impl FnOnce(&mut Lexer<'_>) -> T) -> T {
    let limits = SourceLimits::new(1, 1_000_000, 1_000_000, token_limit, 64)
        .unwrap_or_else(|_| unreachable!("positive limits"));
    let mut builder = SourceSnapshotBuilder::new(limits);
    assert!(builder.add_file("main.gnt", source).is_ok());
    let mut snapshot = builder.finish();
    let (records, counters) = snapshot.records_and_counters_mut();
    let record = records
        .first()
        .unwrap_or_else(|| unreachable!("one source"));
    let lexer = Lexer::new(record, counters);
    assert!(lexer.is_ok());
    test(&mut lexer.unwrap_or_else(|_| unreachable!("checked above")))
}

#[test]
fn public_lexer_preserves_unicode_boundaries_spans_and_maximal_munch() {
    with_lexer(
        "prompt \u{105c0}_2 12.5e-1 :: -> _".as_bytes(),
        16,
        |lexer| {
            let prompt = lexer.next(LexContext::Ordinary);
            assert!(matches!(
                prompt.as_ref().map(|token| token.kind()),
                Ok(TokenKind::ReservedWord(word)) if word.spelling() == "prompt"
            ));
            assert_eq!(
                prompt
                    .as_ref()
                    .unwrap_or_else(|_| unreachable!("checked above"))
                    .span()
                    .bytes()
                    .start(),
                0
            );
            assert!(matches!(
                lexer.next(LexContext::Ordinary).map(|token| token.kind().clone()),
                Ok(TokenKind::Identifier(value)) if &*value == "\u{105c0}_2"
            ));
            assert!(matches!(
                lexer.next(LexContext::Ordinary).map(|token| token.kind().clone()),
                Ok(TokenKind::FloatLiteral(value)) if &*value == "12.5e-1"
            ));
            assert!(matches!(
                lexer
                    .next(LexContext::Ordinary)
                    .map(|token| token.kind().clone()),
                Ok(TokenKind::Punctuation(Punctuation::PathSeparator))
            ));
            assert!(matches!(
                lexer
                    .next(LexContext::Ordinary)
                    .map(|token| token.kind().clone()),
                Ok(TokenKind::Punctuation(Punctuation::ThinArrow))
            ));
            assert!(matches!(
                lexer
                    .next(LexContext::Ordinary)
                    .map(|token| token.kind().clone()),
                Ok(TokenKind::Punctuation(Punctuation::Underscore))
            ));
        },
    );
}

#[test]
fn public_prompt_scan_balances_islands_and_retains_literal_segments() {
    with_lexer(b"r#\"a $$${Some(\"draft\")} z\"#", 16, |lexer| {
        let token = lexer
            .next(LexContext::PromptTemplate)
            .unwrap_or_else(|_| unreachable!("valid prompt"));
        let TokenKind::PromptTemplate(template) = token.kind() else {
            unreachable!("prompt template token")
        };
        assert_eq!(template.delimiter(), PromptDelimiter::Raw);
        assert_eq!(template.literals(), &["a $".into(), " z".into()]);
        assert_eq!(template.interpolations().len(), 1);
        assert_eq!(template.interpolations()[0].source(), "Some(\"draft\")");
        assert_eq!(template.interpolations()[0].tokens().len(), 4);
    });
}

#[test]
fn public_lexer_reports_malformed_input_and_incremental_token_limits() {
    with_lexer(b"x y", 1, |lexer| {
        assert!(lexer.next(LexContext::Ordinary).is_ok());
        assert!(matches!(
            lexer.next(LexContext::Ordinary),
            Err(LexError::ResourceLimit(error))
                if error.code == FrontendResourceCode::SourceTokenLimit
                    && error.observed == Some(2)
        ));
    });

    with_lexer(b"\"\\u{D800}\"", 4, |lexer| {
        assert!(matches!(
            lexer.next(LexContext::Ordinary),
            Err(LexError::Diagnostic(ref diagnostic))
                if diagnostic.code.as_str() == "invalid-unicode-escape"
                    && diagnostic.primary.is_some()
        ));
    });
}

#[test]
fn deeply_nested_comments_and_interpolation_delimiters_are_iterative() {
    let mut comments = "/*".repeat(10_000);
    comments.push_str(&"*/".repeat(10_000));
    comments.push_str(" value");
    with_lexer(comments.as_bytes(), 4, |lexer| {
        assert!(matches!(
            lexer.next(LexContext::Ordinary).map(|token| token.kind().clone()),
            Ok(TokenKind::Identifier(value)) if &*value == "value"
        ));
    });

    let mut prompt = String::from("\"");
    prompt.push_str("${");
    prompt.push_str(&"(".repeat(10_000));
    prompt.push('x');
    prompt.push_str(&")".repeat(10_000));
    prompt.push_str("}\"");
    with_lexer(prompt.as_bytes(), 20_010, |lexer| {
        assert!(matches!(
            lexer.next(LexContext::PromptTemplate),
            Ok(token) if matches!(token.kind(), TokenKind::PromptTemplate(_))
        ));
    });
}
