//! Secure package source discovery and syntax-only frontend processing.
//!
//! This crate owns package filesystem access, source snapshot construction,
//! lexical tokenization, prompt-template scanning, and the authored-order
//! surface syntax tree. The surface grammar includes parametric declarations,
//! static-trait declarations and implementations, trailing `where` clauses,
//! explicit type arguments, generic enum patterns, and contextual `Self`.
//! Parsing preserves semantically invalid but grammatical forms for the
//! analyzer and enforces constructed-type depth before retaining source forms.
//! It does not own name resolution, type inference, trait selection,
//! monomorphization, rendering, or ambient integration services.

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
    CompletedSyntaxPhase, ModuleResolutionIssue, ModuleResolutionIssueKind, PackageSyntaxError,
    PackageSyntaxStatus, ParsedSource, validate_package_syntax,
    validate_package_syntax_with_limits,
};
pub use parser::{ParseError, ParseOutcome, Parser};
pub use prompt::{InterpolationIsland, PromptDelimiter, PromptTemplate};

pub use provider::{
    ModuleResolution, PackageSnapshotLoader, RootDirectorySourceProvider, SourceProvider,
    SourceProviderError, SourceReadLimits,
};
pub use token::{Punctuation, ReservedWord, Token, TokenKind};
