//! Secure package source discovery and syntax-only frontend processing.
//!
//! This crate owns package filesystem access, source snapshot construction,
//! lexical tokenization, prompt-template scanning, and the authored-order
//! surface syntax tree. It does not own semantic analysis, rendering, or
//! ambient integration services.

mod ast;
mod lexer;
mod package;
mod parser;
mod prompt;
mod provider;
mod token;

pub use ast::{NodeId, SyntaxForm, SyntaxNode, SyntaxTree};
pub use lexer::{LexContext, LexError, Lexer};
pub use package::{
    CompletedSyntaxPhase, PackageSyntaxError, PackageSyntaxStatus, ParsedSource,
    validate_package_syntax,
};
pub use parser::{ParseError, ParseOutcome, Parser};
pub use prompt::{InterpolationIsland, PromptDelimiter, PromptTemplate};

pub use provider::{
    ModuleResolution, PackageSnapshotLoader, RootDirectorySourceProvider, SourceProvider,
    SourceProviderError, SourceReadLimits,
};
pub use token::{Punctuation, ReservedWord, Token, TokenKind};
