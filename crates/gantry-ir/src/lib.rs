//! Portable analyzer/runtime contracts for Gantry v1.
//!
//! This crate owns canonical paths, type descriptors, signatures, analysis
//! facts, and versioned IR artifact boundaries. It deliberately depends only
//! on `gantry-core`: surface syntax, analyzer algorithms, runtime state, host
//! services, and concrete adapters remain outside this contract crate.

mod artifact;
mod canonical;
mod effects;
mod executable;
mod facts;
pub mod generated;
mod manifest;
mod path;
mod primitive;
mod schema;
mod signature;
mod types;

pub use artifact::{ArtifactEncodingError, ArtifactLimits, BoundedArtifact};
pub use canonical::{
    CanonicalIr, CanonicalNode, CanonicalOperationSite, CanonicalSourceMap,
    CanonicalTaskControlSite, CanonicalWorkflow, IrArtifactError, SourceMapEntry,
};
pub use effects::{EFFECT_ORDER, EffectSet};
pub use executable::{
    AggregateKind, Instruction, InstructionKind, LoopPhase, MachineProgram, Parameter,
    ProgramError, Projection, Workflow,
};
pub use facts::{
    ActionEffectContributor, ActionInventory, CallEdge, EntryInventory, OperationSite,
    OwnershipFact, SiteContractError, StaticSiteId, StructuralPosition, TaskControlSite,
    WorkflowFacts,
};
pub use manifest::{ManifestError, ManifestFile, PackageSourceManifest};
pub use path::{CanonicalPath, CanonicalPathError};
pub use primitive::{Comparison, Primitive};
pub use schema::{GeneratedSchemaObject, SchemaObjectError};
pub use signature::{ActionParameter, CanonicalSignature, SignatureError, WorkflowParameter};
pub use types::{TypeDescriptor, TypeDescriptorError};
