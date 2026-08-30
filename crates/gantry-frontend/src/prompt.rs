//! Contextual prompt-template values produced by lexical scanning.

use std::sync::Arc;

use gantry_core::source::SourceSpan;

use crate::token::Token;

/// Delimiter and escape policy selected by an authored prompt template.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PromptDelimiter {
    /// An ordinary quoted template with escape decoding.
    Quoted,
    /// A variable-hash raw template with no escape decoding.
    Raw,
    /// A triple-quoted, structurally dedented block template.
    Block,
}

/// One balanced `${...}` island retained for restricted-expression parsing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InterpolationIsland {
    source: Arc<str>,
    span: SourceSpan,
    tokens: Vec<Token>,
}

impl InterpolationIsland {
    /// Constructs an island from its exact interior and ordinary token stream.
    #[must_use]
    pub(crate) fn new(source: Arc<str>, span: SourceSpan, tokens: Vec<Token>) -> Self {
        Self {
            source,
            span,
            tokens,
        }
    }

    /// Returns the exact authored text between `${` and `}`.
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Returns the exact source span excluding the interpolation delimiters.
    #[must_use]
    pub const fn span(&self) -> &SourceSpan {
        &self.span
    }

    /// Returns ordinary Gantry tokens for restricted-expression parsing.
    #[must_use]
    pub fn tokens(&self) -> &[Token] {
        &self.tokens
    }
}

/// One contextual prompt token with alternating literal segments and islands.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PromptTemplate {
    delimiter: PromptDelimiter,
    literals: Vec<Arc<str>>,
    interpolations: Vec<InterpolationIsland>,
}

impl PromptTemplate {
    /// Constructs a template whose literal count is one greater than its
    /// interpolation count.
    #[must_use]
    pub(crate) fn new(
        delimiter: PromptDelimiter,
        literals: Vec<Arc<str>>,
        interpolations: Vec<InterpolationIsland>,
    ) -> Self {
        debug_assert_eq!(literals.len(), interpolations.len().saturating_add(1));
        Self {
            delimiter,
            literals,
            interpolations,
        }
    }

    /// Returns the authored delimiter and decoding policy.
    #[must_use]
    pub const fn delimiter(&self) -> PromptDelimiter {
        self.delimiter
    }

    /// Returns decoded literal segments around interpolation placeholders.
    #[must_use]
    pub fn literals(&self) -> &[Arc<str>] {
        &self.literals
    }

    /// Returns interpolation islands in source order.
    #[must_use]
    pub fn interpolations(&self) -> &[InterpolationIsland] {
        &self.interpolations
    }
}
