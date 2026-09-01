//! Portable analyzer/runtime contracts for Gantry v1.
//!
//! This crate owns canonical paths, closed type descriptors, open generic type
//! expressions, concrete and template callable identities, generic analysis
//! facts, closed executable projections, and versioned IR artifact boundaries.
//! All portable type and identity encodings are explicit and depth-safe; Rust
//! display and debug representations are not protocol formats. The crate
//! deliberately depends only on `gantry-core`: surface syntax, analyzer
//! algorithms, runtime state, host services, and concrete adapters remain
//! outside this contract crate.

mod artifact;
mod callable_identity;
mod canonical;
mod effects;
mod executable;
mod facts;
pub mod generated;
mod generic;
mod manifest;
mod path;
mod primitive;
mod schema;
mod signature;
mod type_expression;
mod types;

pub use artifact::{ArtifactEncodingError, ArtifactLimits, BoundedArtifact};
pub use callable_identity::{
    CallableIdentityError, CanonicalCallableIdentity, CanonicalTemplateIdentity,
};
pub use canonical::{
    CanonicalIr, CanonicalNode, CanonicalOperationSite, CanonicalSourceMap,
    CanonicalTaskControlSite, CanonicalWorkflow, IrArtifactError, SourceMapEntry,
};
pub use effects::{EFFECT_ORDER, EffectSet};
pub use executable::{
    AggregateKind, ExecutableAction, ExecutableOperation, Instruction, InstructionKind, LoopPhase,
    MachineProgram, Parameter, ProgramError, Projection, Workflow,
};
pub use facts::{
    ActionEffectContributor, ActionInventory, CallEdge, EntryInventory, OperationSite,
    OwnershipFact, SiteContractError, StaticSiteId, StructuralPosition, TaskControlSite,
    WorkflowFacts,
};
pub use generic::{
    CanonicalImplementationIdentity, ClosedCallable, ConcreteEffect, ConcreteIdentity,
    ConcreteInstantiation, ConcreteSourceMapEntry, ExecutableProjection, GenericAnalysisFacts,
    GenericContractError, GenericTemplate, ImplementationHead, Predicate, ResolvedCall,
    SourceOriginSet, TraitContract, TraitMethodContract, TraitReference,
};
pub use manifest::{ManifestError, ManifestFile, PackageSourceManifest};
pub use path::{CanonicalPath, CanonicalPathError};
pub use primitive::{Comparison, Primitive};
pub use schema::{GeneratedSchemaObject, SchemaObjectError};
pub use signature::{ActionParameter, CanonicalSignature, SignatureError, WorkflowParameter};
pub use type_expression::{TypeExpression, TypeExpressionError};
pub use types::{TypeDescriptor, TypeDescriptorError};
