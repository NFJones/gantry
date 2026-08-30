//! Public module, symbol, and resolution results.

use std::sync::Arc;

use gantry_core::source::{
    FrontendResourceLimit, SourceCounters, SourceSpan, StructuredDiagnostic,
};
use gantry_ir::{
    ActionInventory, CanonicalIr, CanonicalPath, CanonicalSourceMap, EntryInventory,
    GeneratedSchemaObject, MachineProgram, PackageSourceManifest, TypeDescriptor, WorkflowFacts,
};

/// Dense deterministic identifier for one discovered source module.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ModuleId(u32);

impl ModuleId {
    /// Constructs an identifier assigned in canonical module-path order.
    pub(crate) const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Returns the zero-based dense value.
    #[must_use]
    pub const fn index(self) -> u32 {
        self.0
    }
}

/// Dense deterministic identifier for one unique package item.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SymbolId(u32);

impl SymbolId {
    /// Constructs an identifier assigned in canonical item-path order.
    pub(crate) const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Returns the zero-based dense value.
    #[must_use]
    pub const fn index(self) -> u32 {
        self.0
    }
}

/// Closed package-item kinds collected before body analysis.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SymbolKind {
    /// Source module introduced by a file or inline `mod` declaration.
    Module,
    /// Declared struct type.
    Struct,
    /// Declared enum type.
    Enum,
    /// Declared free function.
    Function,
    /// Declared action.
    Action,
}

/// One source module in canonical path order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Module {
    /// Dense canonical identifier.
    pub id: ModuleId,
    /// Exact `crate::`-rooted module path. The package root is represented by
    /// the literal `crate` because [`CanonicalPath`] names items below it.
    pub path: Arc<str>,
    /// Parent module, absent only for the package root.
    pub parent: Option<ModuleId>,
    /// Complete module span in its immutable source.
    pub span: SourceSpan,
}

/// One unique package item collected independently of declaration order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Symbol {
    /// Dense canonical identifier.
    pub id: SymbolId,
    /// Containing source module.
    pub module: ModuleId,
    /// Exact NFC declared name.
    pub name: Arc<str>,
    /// Stable package item kind.
    pub kind: SymbolKind,
    /// Exact canonical package path.
    pub path: CanonicalPath,
    /// Source location of the declaration name.
    pub span: SourceSpan,
}

/// One source path resolved to a unique package item.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedReference {
    /// Complete authored path span.
    pub span: SourceSpan,
    /// Unique target item.
    pub target: SymbolId,
    /// Canonical path after import and relative-root resolution.
    pub canonical_path: CanonicalPath,
}

/// One idempotently merged package-wide agent name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentName {
    /// Exact NFC spelling.
    pub name: Arc<str>,
    /// Canonically ordered declaration locations.
    pub declarations: Vec<SourceSpan>,
}

/// Static package validity after this structural analysis stage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnalysisStatus {
    /// No analysis error was produced. Warnings may still be present.
    Valid,
    /// At least one analysis error was produced.
    Invalid,
}

/// Deterministic structural analysis output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageStructure {
    pub(crate) status: AnalysisStatus,
    pub(crate) modules: Vec<Module>,
    pub(crate) symbols: Vec<Symbol>,
    pub(crate) references: Vec<ResolvedReference>,
    pub(crate) agents: Vec<AgentName>,
    pub(crate) diagnostics: Vec<StructuredDiagnostic>,
    pub(crate) counters: SourceCounters,
}

impl PackageStructure {
    /// Returns whether this structural analysis stage accepted the package.
    #[must_use]
    pub const fn status(&self) -> AnalysisStatus {
        self.status
    }

    /// Returns modules in unsigned UTF-8 canonical-path order.
    #[must_use]
    pub fn modules(&self) -> &[Module] {
        &self.modules
    }

    /// Returns unique package items in unsigned UTF-8 canonical-path order.
    #[must_use]
    pub fn symbols(&self) -> &[Symbol] {
        &self.symbols
    }

    /// Returns resolved source paths in canonical source-span order.
    #[must_use]
    pub fn references(&self) -> &[ResolvedReference] {
        &self.references
    }

    /// Returns merged agent names in unsigned UTF-8 spelling order.
    #[must_use]
    pub fn agents(&self) -> &[AgentName] {
        &self.agents
    }

    /// Returns disclosure-neutral diagnostics in canonical machine order.
    #[must_use]
    pub fn diagnostics(&self) -> &[StructuredDiagnostic] {
        &self.diagnostics
    }

    /// Returns final package-activity counters after diagnostic charging.
    #[must_use]
    pub const fn counters(&self) -> &SourceCounters {
        &self.counters
    }
}

/// One successfully resolved canonical type annotation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TypeFact {
    /// Exact source span of the complete type annotation.
    pub span: SourceSpan,
    /// Canonical type descriptor after item and import resolution.
    pub descriptor: TypeDescriptor,
}

/// Deterministic package result after declaration type analysis.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TypedPackage {
    pub(crate) status: AnalysisStatus,
    pub(crate) structure: PackageStructure,
    pub(crate) types: Vec<TypeFact>,
    pub(crate) workflows: Vec<WorkflowFacts>,
    pub(crate) actions: Vec<ActionInventory>,
    pub(crate) entry: Option<EntryInventory>,
    pub(crate) schemas: Option<GeneratedSchemaObject>,
    pub(crate) manifest: Option<PackageSourceManifest>,
    pub(crate) canonical_ir: Option<CanonicalIr>,
    pub(crate) executable: Option<MachineProgram>,
    pub(crate) source_map: Option<CanonicalSourceMap>,
    pub(crate) diagnostics: Vec<StructuredDiagnostic>,
    pub(crate) counters: SourceCounters,
}

impl TypedPackage {
    /// Returns whether all structural and declaration-type checks passed.
    #[must_use]
    pub const fn status(&self) -> AnalysisStatus {
        self.status
    }

    /// Returns the preceding module, symbol, and resolution result.
    #[must_use]
    pub const fn structure(&self) -> &PackageStructure {
        &self.structure
    }

    /// Returns canonical type facts in source-span order.
    #[must_use]
    pub fn types(&self) -> &[TypeFact] {
        &self.types
    }

    /// Returns workflow facts in canonical workflow-path order.
    #[must_use]
    pub fn workflows(&self) -> &[WorkflowFacts] {
        &self.workflows
    }

    /// Returns action declarations in canonical action-path order.
    #[must_use]
    pub fn actions(&self) -> &[ActionInventory] {
        &self.actions
    }

    /// Returns the canonical root entry inventory when one was resolved.
    #[must_use]
    pub const fn entry(&self) -> Option<&EntryInventory> {
        self.entry.as_ref()
    }

    /// Returns the deduplicated bounded schemas for entry and operation boundaries.
    #[must_use]
    pub const fn schemas(&self) -> Option<&GeneratedSchemaObject> {
        self.schemas.as_ref()
    }

    /// Returns the immutable package-source manifest for a source-valid package.
    #[must_use]
    pub const fn manifest(&self) -> Option<&PackageSourceManifest> {
        self.manifest.as_ref()
    }

    /// Returns bounded canonical IR only for a source-valid package.
    #[must_use]
    pub const fn canonical_ir(&self) -> Option<&CanonicalIr> {
        self.canonical_ir.as_ref()
    }

    /// Returns the validated typed program consumed by the shared runtime machine.
    #[must_use]
    pub const fn executable_program(&self) -> Option<&MachineProgram> {
        self.executable.as_ref()
    }

    /// Returns the bounded source map paired with canonical IR.
    #[must_use]
    pub const fn source_map(&self) -> Option<&CanonicalSourceMap> {
        self.source_map.as_ref()
    }

    /// Returns all structural and type diagnostics in canonical machine order.
    #[must_use]
    pub fn diagnostics(&self) -> &[StructuredDiagnostic] {
        &self.diagnostics
    }

    /// Returns final package-activity counters after all retained diagnostics.
    #[must_use]
    pub const fn counters(&self) -> &SourceCounters {
        &self.counters
    }
}

/// Operational failure before structural analysis can return a judgment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AnalysisError {
    /// Semantic analysis was requested after an invalid syntax phase.
    SyntaxInvalid,
    /// The shared diagnostic limit stopped analysis at a deterministic prefix.
    ResourceLimit {
        /// Exact portable configured-limit result.
        error: FrontendResourceLimit,
        /// Canonically ordered diagnostics retained before exhaustion.
        diagnostics: Vec<StructuredDiagnostic>,
    },
    /// Frontend syntax or source relationships violated an internal contract.
    Invariant,
}

impl std::fmt::Display for AnalysisError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::SyntaxInvalid => "semantic analysis requires syntax-valid input",
            Self::ResourceLimit { .. } => "analysis diagnostic limit exceeded",
            Self::Invariant => "analysis input invariant failed",
        })
    }
}

impl std::error::Error for AnalysisError {}
