//! Deterministic static analysis over immutable frontend syntax.
//!
//! This crate owns module graphs, package symbols, name resolution, identifier
//! security, generic binder construction, exact type inference, structural
//! capability proof, trait coherence and selection, effect inference, and
//! monomorphization closure. It consumes the authored frontend tree and
//! produces canonical IR, concrete schemas, and a closed executable projection
//! without performing integration or runtime work.

mod bodies;
mod effects;
mod executable;
mod generics;
mod lowering;
mod model;
mod schemas;
mod security;
mod symbols;
mod types;

pub use model::{
    AgentName, AnalysisError, AnalysisStatus, DeclaredEnumVariant, DeclaredStructField,
    DeclaredValueShape, DeclaredValueShapes, GenericTypeFact, Module, ModuleId, PackageStructure,
    ResolvedReference, Symbol, SymbolId, SymbolKind, TypeBinder, TypeBinderId, TypeFact,
    TypeParameterBinding, TypedPackage,
};
pub use symbols::analyze_package_structure;
pub use types::{
    analyze_package_types, analyze_package_types_with_artifact_limits,
    analyze_package_types_with_limits,
};
