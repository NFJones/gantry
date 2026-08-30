//! Secure package source discovery and syntax-only frontend processing.
//!
//! This crate owns package filesystem access, source snapshot construction,
//! lexical tokenization, and prompt-template scanning. It does not own
//! semantic analysis, rendering, or ambient integration services.

mod lexer;
mod prompt;
mod provider;
mod token;

pub use lexer::{LexContext, LexError, Lexer};
pub use prompt::{InterpolationIsland, PromptDelimiter, PromptTemplate};

pub use provider::{
    ModuleResolution, PackageSnapshotLoader, RootDirectorySourceProvider, SourceProvider,
    SourceProviderError, SourceReadLimits,
};
pub use token::{Punctuation, ReservedWord, Token, TokenKind};
