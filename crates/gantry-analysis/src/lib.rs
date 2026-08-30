//! Deterministic static analysis over immutable frontend syntax.
//!
//! This crate owns module graphs, package symbols, name resolution, identifier
//! security, and later semantic passes. It consumes the authored frontend tree
//! and produces canonical IR contracts without performing integration or
//! runtime work.

mod bodies;
mod model;
mod security;
mod symbols;
mod types;

pub use model::{
    AgentName, AnalysisError, AnalysisStatus, Module, ModuleId, PackageStructure,
    ResolvedReference, Symbol, SymbolId, SymbolKind, TypeFact, TypedPackage,
};
pub use symbols::analyze_package_structure;
pub use types::analyze_package_types;
