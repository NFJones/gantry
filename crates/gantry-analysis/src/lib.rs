//! Deterministic static analysis over immutable frontend syntax.
//!
//! This crate owns module graphs, package symbols, name resolution, identifier
//! security, and later semantic passes. It consumes the authored frontend tree
//! and produces canonical IR contracts without performing integration or
//! runtime work.

mod model;
mod security;
mod symbols;

pub use model::{
    AgentName, AnalysisError, AnalysisStatus, Module, ModuleId, PackageStructure,
    ResolvedReference, Symbol, SymbolId, SymbolKind,
};
pub use symbols::analyze_package_structure;
