//! Pure bounded untrusted compilation and cache model.
//!
//! This module is the machine-checked model for
//! `GNT-26.0-bounded-untrusted-compilation-and-cache-semantics`. It states the closed
//! untrusted-input inventory of `GNT-26.1-untrusted-input-inventory`, the stage and unit
//! vocabularies of `GNT-26.2-stage-and-unit-vocabulary`, the finite stage budgets and
//! fail-closed cutoff of `GNT-26.3-finite-stage-budgets-and-fail-closed-cutoff`, the
//! structural expansion frontier of `GNT-26.4-structural-expansion-bounds`, the affine
//! completion evidence and atomic publication of
//! `GNT-26.5-completion-evidence-and-atomic-publication`, the typed cancellation
//! settlement of `GNT-26.6-cancellation-settlement`, the artifact loader of
//! `GNT-26.7-artifact-loader-validation`, the cache identity, validation, poisoning, and
//! replacement of `GNT-26.8-cache-identity` and
//! `GNT-26.9-cache-validation-and-poisoning`, the clean and incremental equivalence check
//! of `GNT-26.10-clean-incremental-equivalence`, the editor generation fencing of
//! `GNT-26.11-editor-work-fencing`, the generator confinement of
//! `GNT-26.12-generator-confinement`, the toolchain identity content of
//! `GNT-26.13-toolchain-identity`, and the explicit non-claims of
//! `GNT-26.14-compilation-non-claims`.
//!
//! Scope is deliberately narrow. Every rule here is a pure function of its own
//! arguments: this module reads no clock, no host path, no environment variable, no
//! locale, no process identifier, no thread identity, no network address, no installed
//! program, and no live host handle, and it exposes no constructor that accepts one.
//! Every identity is derived under its own domain separator from declared fields, so
//! equal declared inputs produce equal identities and every verdict here is reproducible
//! from its own inputs.
//!
//! Landed contracts are cited and reused rather than redeclared. The landed
//! `FrontendLimits` counters of `GNT-4.17-frontend-resource-limits` keep their codes and
//! their charging points, so this model adds a stage and unit vocabulary over them rather
//! than a second limit system; the landed
//! [`BuildHostCapability`](crate::target::BuildHostCapability) vocabulary and the landed
//! [`TargetDescriptorDigest`](crate::target::TargetDescriptorDigest) keep their meanings
//! under `GNT-17.9-build-host-authority` and `GNT-17.11-target-artifact-binding`; and
//! cancellation, durability, protection, and authority remain those of `GNT-10.12`
//! through `GNT-10.14`, Section 22, `GNT-11.*`, `GNT-15.*`, and `GNT-3-T-AUTHORITY-*`.
//!
//! Four separations stay explicit.
//!
//! * The [`ToolchainIdentity`] of this module owns the *content* of the field that
//!   `GNT-17.11-target-artifact-binding` binds opaquely. The landed opaque
//!   [`crate::target::ToolchainIdentity`] keeps that binding and is never reinterpreted
//!   here. Because the landed opaque identity already owns the crate-root name, this
//!   module's identity stays module-qualified as `gantry_ir::toolchain::ToolchainIdentity`,
//!   following the landed `identifier`-module precedent for a name claimed twice.
//! * Publication is unrepresentable without evidence: [`SealedArtifact::publish`] and
//!   [`SealedAuthorityClosure::seal`] take the affine [`CompletionEvidence`], which only
//!   [`StageRun::finish`] mints, so a cut-off run cannot publish an artifact or an
//!   authority closure at all rather than merely being refused at runtime.
//! * A failing charge consumes the [`StageRun`], so a cut-off run has no value left to
//!   finish, and [`Cutoff`] has no conversion to completion evidence and no `Clone`.
//! * The poisoning latch of [`CacheEntry`] is irreversible, and a poisoned entry refuses
//!   reuse until it is replaced under a different key, so a poisoned fact is never reused
//!   under its own key.

use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;

use crate::authority::digest_fields;
use crate::manifest::encode_hex;
use crate::target::{BuildHostCapability, GeneratedOutputHash, TargetDescriptorDigest};

/// The clause keys this model implements, in clause order.
///
/// Every diagnostic of this module names exactly one of these keys through
/// [`ToolchainDiagnosticCode::requirement`], so every refusal is attributable to the
/// clause that owns it.
pub const TOOLCHAIN_CLAUSES: [&str; 15] = [
    "GNT-26.0-bounded-untrusted-compilation-and-cache-semantics",
    "GNT-26.1-untrusted-input-inventory",
    "GNT-26.2-stage-and-unit-vocabulary",
    "GNT-26.3-finite-stage-budgets-and-fail-closed-cutoff",
    "GNT-26.4-structural-expansion-bounds",
    "GNT-26.5-completion-evidence-and-atomic-publication",
    "GNT-26.6-cancellation-settlement",
    "GNT-26.7-artifact-loader-validation",
    "GNT-26.8-cache-identity",
    "GNT-26.9-cache-validation-and-poisoning",
    "GNT-26.10-clean-incremental-equivalence",
    "GNT-26.11-editor-work-fencing",
    "GNT-26.12-generator-confinement",
    "GNT-26.13-toolchain-identity",
    "GNT-26.14-compilation-non-claims",
];

/// The greatest declared stage limit, `2^63 - 1` (`GNT-26.3`).
///
/// A limit above this value is refused, so every charge comparison and every remaining-
/// budget subtraction stays inside `u64` and no limit arithmetic wraps.
pub const MAXIMUM_STAGE_LIMIT: u64 = (1_u64 << 63) - 1;

/// Domain separator for untrusted-input inventory derivation.
const INPUT_INVENTORY_DOMAIN: &str = "gantry.toolchain-input-inventory/v1";

/// Domain separator for the completion witness of one finished stage run.
const COMPLETION_WITNESS_DOMAIN: &str = "gantry.toolchain-completion-witness/v1";

/// Domain separator for cache-key derivation.
const CACHE_KEY_DOMAIN: &str = "gantry.toolchain-cache-key/v1";

/// Domain separator for canonical-output derivation.
const CANONICAL_OUTPUT_DOMAIN: &str = "gantry.toolchain-canonical-output/v1";

/// Domain separator for generator-grant identity derivation.
const GENERATOR_GRANT_DOMAIN: &str = "gantry.toolchain-generator-grant/v1";

/// Domain separator for the artifact identity of folded admitted generator runs.
const GENERATOR_RUN_FOLD_DOMAIN: &str = "gantry.toolchain-generator-run-fold/v1";

/// Domain separator for toolchain-identity derivation.
const TOOLCHAIN_IDENTITY_DOMAIN: &str = "gantry.toolchain-identity/v1";

/// Returns whether one spelling is exactly 64 lowercase hexadecimal digits.
fn is_hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Returns whether one declared name is a legal declared name.
fn is_declared_name(value: &str) -> bool {
    !value.is_empty() && !value.chars().any(char::is_control)
}

/// Returns whether one declared digest is the reserved all-zero omitted digest.
///
/// The all-zero spelling is reserved as the *omitted* digest of one required identity input, so a
/// key that supplies it is refused as incomplete rather than published under an identity that
/// could collide with another activity's omitted input.
fn is_omitted_digest(digest: &DeclaredDigest) -> bool {
    digest.as_str().bytes().all(|byte| byte == b'0')
}

/// Returns the domain-separated digest of length-prefixed declared fields.
fn declared_digest(domain: &str, fields: &[&[u8]]) -> DeclaredDigest {
    DeclaredDigest::from_digest(digest_fields(domain, fields))
}

/// One declared digest spelling of this model.
///
/// The spelling is exactly 64 lowercase hexadecimal digits, so a digest is an identity
/// and never a display label, a version string, a path, or a discovered program spelling.
/// Two equal spellings denote the same declared value.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DeclaredDigest(Arc<str>);

impl DeclaredDigest {
    /// Decodes one exact lowercase hexadecimal digest.
    ///
    /// # Errors
    ///
    /// Returns [`CompilationError`] with code
    /// [`ToolchainDiagnosticCode::InvalidDigestSpelling`] when the value is not exactly 64
    /// lowercase hexadecimal digits, because a repaired spelling would name another
    /// identity.
    pub fn from_hex(value: &str) -> Result<Self, CompilationError> {
        if !is_hex_digest(value) {
            return Err(CompilationError::new(
                ToolchainDiagnosticCode::InvalidDigestSpelling,
                format!("the declared digest `{value}` is not 64 lowercase hexadecimal digits"),
            ));
        }
        Ok(Self(Arc::from(value)))
    }

    /// Encodes one accepted digest value.
    #[must_use]
    pub fn from_digest(bytes: [u8; 32]) -> Self {
        Self(Arc::from(encode_hex(&bytes)))
    }

    /// Returns the exact lowercase hexadecimal digest.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the same exact encoding as [`Self::as_str`].
    #[must_use]
    pub fn encode_hex(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DeclaredDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// One named unit of compilation work of `GNT-26.2-stage-and-unit-vocabulary`.
///
/// The vocabulary is closed: a stage name outside it is refused rather than treated as an
/// extension point. The members are declared in canonical stage order - the order the stages of
/// one compilation activity run in - and [`Self::ALL`] preserves that order.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ToolchainStage {
    /// `parse`
    Parse,
    /// `name-resolution`
    NameResolution,
    /// `type-effect-checking`
    TypeEffectChecking,
    /// `trait-solving`
    TraitSolving,
    /// `generic-instantiation`
    GenericInstantiation,
    /// `schema-construction`
    SchemaConstruction,
    /// `authority-closure`
    AuthorityClosure,
    /// `linking`
    Linking,
    /// `optimization`
    Optimization,
    /// `documentation`
    Documentation,
    /// `diagnostic-rendering`
    DiagnosticRendering,
    /// `generation-ingestion`
    GenerationIngestion,
    /// `cache-validation`
    CacheValidation,
    /// `editor-indexing`
    EditorIndexing,
}

/// The units charged by the parse stage (`GNT-26.2-stage-and-unit-vocabulary`).
const PARSE_UNITS: [BudgetUnit; 4] = [
    BudgetUnit::Depth,
    BudgetUnit::Count,
    BudgetUnit::Bytes,
    BudgetUnit::Work,
];

/// The units charged by the name-resolution stage.
const NAME_RESOLUTION_UNITS: [BudgetUnit; 3] =
    [BudgetUnit::Depth, BudgetUnit::Count, BudgetUnit::Work];

/// The units charged by the type-and-effect-checking stage.
const TYPE_EFFECT_CHECKING_UNITS: [BudgetUnit; 4] = [
    BudgetUnit::Depth,
    BudgetUnit::Count,
    BudgetUnit::Work,
    BudgetUnit::Memory,
];

/// The units charged by the trait-solving stage.
const TRAIT_SOLVING_UNITS: [BudgetUnit; 3] =
    [BudgetUnit::Depth, BudgetUnit::Count, BudgetUnit::Work];

/// The units charged by the generic-instantiation stage.
const GENERIC_INSTANTIATION_UNITS: [BudgetUnit; 4] = [
    BudgetUnit::Depth,
    BudgetUnit::Count,
    BudgetUnit::Work,
    BudgetUnit::Memory,
];

/// The units charged by the schema-construction stage.
const SCHEMA_CONSTRUCTION_UNITS: [BudgetUnit; 4] = [
    BudgetUnit::Depth,
    BudgetUnit::Count,
    BudgetUnit::Bytes,
    BudgetUnit::Work,
];

/// The units charged by the authority-closure stage.
const AUTHORITY_CLOSURE_UNITS: [BudgetUnit; 3] =
    [BudgetUnit::Count, BudgetUnit::Work, BudgetUnit::Memory];

/// The units charged by the linking stage.
const LINKING_UNITS: [BudgetUnit; 4] = [
    BudgetUnit::Count,
    BudgetUnit::Bytes,
    BudgetUnit::Work,
    BudgetUnit::Memory,
];

/// The units charged by the optimization stage.
const OPTIMIZATION_UNITS: [BudgetUnit; 4] = [
    BudgetUnit::Depth,
    BudgetUnit::Count,
    BudgetUnit::Work,
    BudgetUnit::Memory,
];

/// The units charged by the documentation stage.
const DOCUMENTATION_UNITS: [BudgetUnit; 3] =
    [BudgetUnit::Count, BudgetUnit::Bytes, BudgetUnit::Work];

/// The units charged by the diagnostic-rendering stage.
const DIAGNOSTIC_RENDERING_UNITS: [BudgetUnit; 2] = [BudgetUnit::Count, BudgetUnit::Bytes];

/// The units charged by the generation-ingestion stage.
const GENERATION_INGESTION_UNITS: [BudgetUnit; 3] =
    [BudgetUnit::Count, BudgetUnit::Bytes, BudgetUnit::Work];

/// The units charged by the cache-validation stage.
const CACHE_VALIDATION_UNITS: [BudgetUnit; 3] =
    [BudgetUnit::Count, BudgetUnit::Bytes, BudgetUnit::Work];

/// The units charged by the editor-indexing stage.
const EDITOR_INDEXING_UNITS: [BudgetUnit; 3] =
    [BudgetUnit::Depth, BudgetUnit::Count, BudgetUnit::Work];

impl ToolchainStage {
    /// Every stage of the closed vocabulary, in canonical stage order.
    pub const ALL: [Self; 14] = [
        Self::Parse,
        Self::NameResolution,
        Self::TypeEffectChecking,
        Self::TraitSolving,
        Self::GenericInstantiation,
        Self::SchemaConstruction,
        Self::AuthorityClosure,
        Self::Linking,
        Self::Optimization,
        Self::Documentation,
        Self::DiagnosticRendering,
        Self::GenerationIngestion,
        Self::CacheValidation,
        Self::EditorIndexing,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Parse => "parse",
            Self::NameResolution => "name-resolution",
            Self::TypeEffectChecking => "type-effect-checking",
            Self::TraitSolving => "trait-solving",
            Self::GenericInstantiation => "generic-instantiation",
            Self::SchemaConstruction => "schema-construction",
            Self::AuthorityClosure => "authority-closure",
            Self::Linking => "linking",
            Self::Optimization => "optimization",
            Self::Documentation => "documentation",
            Self::DiagnosticRendering => "diagnostic-rendering",
            Self::GenerationIngestion => "generation-ingestion",
            Self::CacheValidation => "cache-validation",
            Self::EditorIndexing => "editor-indexing",
        }
    }

    /// Returns the same exact portable spelling as [`Self::wire_name`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.wire_name()
    }

    /// Strictly decodes one exact portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.wire_name() == value)
    }

    /// Returns the units this stage charges, in canonical unit order.
    ///
    /// A stage declares exactly these units and MUST NOT charge another, so
    /// [`StageBudget::new`] refuses a limit outside this set and
    /// [`ToolchainBudget::begin_stage`] refuses a run whose applicable unit has no limit.
    #[must_use]
    pub const fn applicable_units(self) -> &'static [BudgetUnit] {
        match self {
            Self::Parse => &PARSE_UNITS,
            Self::NameResolution => &NAME_RESOLUTION_UNITS,
            Self::TypeEffectChecking => &TYPE_EFFECT_CHECKING_UNITS,
            Self::TraitSolving => &TRAIT_SOLVING_UNITS,
            Self::GenericInstantiation => &GENERIC_INSTANTIATION_UNITS,
            Self::SchemaConstruction => &SCHEMA_CONSTRUCTION_UNITS,
            Self::AuthorityClosure => &AUTHORITY_CLOSURE_UNITS,
            Self::Linking => &LINKING_UNITS,
            Self::Optimization => &OPTIMIZATION_UNITS,
            Self::Documentation => &DOCUMENTATION_UNITS,
            Self::DiagnosticRendering => &DIAGNOSTIC_RENDERING_UNITS,
            Self::GenerationIngestion => &GENERATION_INGESTION_UNITS,
            Self::CacheValidation => &CACHE_VALIDATION_UNITS,
            Self::EditorIndexing => &EDITOR_INDEXING_UNITS,
        }
    }

    /// Returns the clause anchor that bounds this stage.
    #[must_use]
    pub const fn requirement(self) -> &'static str {
        "GNT-26.3-finite-stage-budgets-and-fail-closed-cutoff"
    }
}

/// One dimension of charged work of `GNT-26.2-stage-and-unit-vocabulary`.
///
/// The vocabulary is closed: the members are declared in canonical unit order, and a charge
/// that names another unit is refused rather than approximated by one of these.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum BudgetUnit {
    /// Structural depth, as the landed constructed-type-depth counter measures it.
    Depth,
    /// Item count, as the landed token, diagnostic, and instantiation counters measure it.
    Count,
    /// Encoded byte length, as the landed artifact byte limits measure it.
    Bytes,
    /// Charged work, as the landed trait-resolution step counter measures it.
    Work,
    /// Retained memory, as a declared policy dimension rather than a host reading.
    Memory,
}

impl BudgetUnit {
    /// Every unit of the closed vocabulary, in canonical unit order.
    pub const ALL: [Self; 5] = [
        Self::Depth,
        Self::Count,
        Self::Bytes,
        Self::Work,
        Self::Memory,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Depth => "depth",
            Self::Count => "count",
            Self::Bytes => "bytes",
            Self::Work => "work",
            Self::Memory => "memory",
        }
    }

    /// Returns the same exact portable spelling as [`Self::wire_name`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.wire_name()
    }

    /// Strictly decodes one exact portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.wire_name() == value)
    }

    /// Returns the clause anchor that fixes this unit's vocabulary.
    #[must_use]
    pub const fn requirement(self) -> &'static str {
        "GNT-26.2-stage-and-unit-vocabulary"
    }
}

/// One kind of untrusted input of `GNT-26.1-untrusted-input-inventory`.
///
/// The vocabulary is closed, and the members are declared in canonical wire-name order, so
/// [`Self::rank`] is a canonical ordering key and never an insertion or discovery order.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum UntrustedInputKind {
    /// `cache-entry`
    CacheEntry,
    /// `dependency-artifact`
    DependencyArtifact,
    /// `editor-work`
    EditorWork,
    /// `feature-selection`
    FeatureSelection,
    /// `generator-output`
    GeneratorOutput,
    /// `lockfile`
    Lockfile,
    /// `manifest`
    Manifest,
    /// `source`
    Source,
    /// `target-descriptor`
    TargetDescriptor,
    /// `toolchain-configuration`
    ToolchainConfiguration,
}

impl UntrustedInputKind {
    /// Every kind of the closed vocabulary, in canonical wire-name order.
    pub const ALL: [Self; 10] = [
        Self::CacheEntry,
        Self::DependencyArtifact,
        Self::EditorWork,
        Self::FeatureSelection,
        Self::GeneratorOutput,
        Self::Lockfile,
        Self::Manifest,
        Self::Source,
        Self::TargetDescriptor,
        Self::ToolchainConfiguration,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::CacheEntry => "cache-entry",
            Self::DependencyArtifact => "dependency-artifact",
            Self::EditorWork => "editor-work",
            Self::FeatureSelection => "feature-selection",
            Self::GeneratorOutput => "generator-output",
            Self::Lockfile => "lockfile",
            Self::Manifest => "manifest",
            Self::Source => "source",
            Self::TargetDescriptor => "target-descriptor",
            Self::ToolchainConfiguration => "toolchain-configuration",
        }
    }

    /// Returns the same exact portable spelling as [`Self::wire_name`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.wire_name()
    }

    /// Strictly decodes one exact portable spelling.
    ///
    /// A spelling outside the closed vocabulary decodes to `None` rather than to a
    /// widened kind, because an input kind outside the vocabulary is never read.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.wire_name() == value)
    }

    /// Returns the canonical rank of this kind.
    #[must_use]
    pub const fn rank(self) -> usize {
        match self {
            Self::CacheEntry => 0,
            Self::DependencyArtifact => 1,
            Self::EditorWork => 2,
            Self::FeatureSelection => 3,
            Self::GeneratorOutput => 4,
            Self::Lockfile => 5,
            Self::Manifest => 6,
            Self::Source => 7,
            Self::TargetDescriptor => 8,
            Self::ToolchainConfiguration => 9,
        }
    }

    /// Returns the clause anchor that owns this kind's inventory.
    #[must_use]
    pub const fn requirement(self) -> &'static str {
        "GNT-26.1-untrusted-input-inventory"
    }
}

/// One declared untrusted input of one compilation activity (`GNT-26.1`).
///
/// The input carries its kind, one declared name, and one declared digest of the exact bytes
/// or declared values it names. The digest is an identity: a presented input whose digest
/// differs from the declared one is refused rather than substituted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UntrustedInput {
    kind: UntrustedInputKind,
    name: Arc<str>,
    digest: DeclaredDigest,
}

impl UntrustedInput {
    /// Declares one untrusted input from its digest spelling.
    ///
    /// # Errors
    ///
    /// Returns [`CompilationError`] with code [`ToolchainDiagnosticCode::InvalidDeclaredName`]
    /// when the name is empty or carries a control character, and with code
    /// [`ToolchainDiagnosticCode::InvalidDigestSpelling`] when the digest is not 64
    /// lowercase hexadecimal digits.
    pub fn new(
        kind: UntrustedInputKind,
        name: &str,
        digest: &str,
    ) -> Result<Self, CompilationError> {
        Self::with_digest(kind, name, DeclaredDigest::from_hex(digest)?)
    }

    /// Declares one untrusted input from an accepted digest value.
    ///
    /// # Errors
    ///
    /// Returns [`CompilationError`] with code [`ToolchainDiagnosticCode::InvalidDeclaredName`]
    /// when the name is empty or carries a control character.
    pub fn with_digest(
        kind: UntrustedInputKind,
        name: &str,
        digest: DeclaredDigest,
    ) -> Result<Self, CompilationError> {
        if !is_declared_name(name) {
            return Err(CompilationError::new(
                ToolchainDiagnosticCode::InvalidDeclaredName,
                format!("the declared input name `{name}` is not a legal declared name"),
            ));
        }
        Ok(Self {
            kind,
            name: Arc::from(name),
            digest,
        })
    }

    /// Returns the declared kind of this input.
    #[must_use]
    pub const fn kind(&self) -> UntrustedInputKind {
        self.kind
    }

    /// Returns the declared name of this input.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the declared digest of this input.
    #[must_use]
    pub const fn digest(&self) -> &DeclaredDigest {
        &self.digest
    }
}

/// The exact declared untrusted inputs one compilation activity observes (`GNT-26.1`).
///
/// The inventory is total over what the activity reads: an input it does not declare is
/// never read, and the inventory holds no host path, environment fact, locale, clock
/// reading, installed-program name, discovered service, or network address.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UntrustedInputInventory {
    inputs: Vec<UntrustedInput>,
}

impl UntrustedInputInventory {
    /// Declares one complete inventory in canonical order.
    ///
    /// # Errors
    ///
    /// Returns [`CompilationError`] with code
    /// [`ToolchainDiagnosticCode::EmptyInputInventory`] when no input is declared, with code
    /// [`ToolchainDiagnosticCode::DuplicateDeclaredInput`] when one kind is declared twice
    /// under one declared name, and with code
    /// [`ToolchainDiagnosticCode::NoncanonicalInputOrder`] when the declared order is not the
    /// canonical `(kind, name)` order.
    pub fn new(declared: &[UntrustedInput]) -> Result<Self, CompilationError> {
        if declared.is_empty() {
            return Err(CompilationError::new(
                ToolchainDiagnosticCode::EmptyInputInventory,
                "an untrusted-input inventory declares at least one input",
            ));
        }
        let keys = declared
            .iter()
            .map(|input| (input.kind.rank(), Arc::clone(&input.name)))
            .collect::<Vec<_>>();
        let unique = keys.iter().collect::<BTreeSet<_>>();
        if unique.len() != keys.len() {
            return Err(CompilationError::new(
                ToolchainDiagnosticCode::DuplicateDeclaredInput,
                "one declared input kind and name pair is declared twice",
            ));
        }
        if !keys.windows(2).all(|window| window[0] < window[1]) {
            return Err(CompilationError::new(
                ToolchainDiagnosticCode::NoncanonicalInputOrder,
                "declared inputs are not in canonical kind and name order",
            ));
        }
        Ok(Self {
            inputs: declared.to_vec(),
        })
    }

    /// Returns the declared inputs in canonical order.
    #[must_use]
    pub fn inputs(&self) -> &[UntrustedInput] {
        &self.inputs
    }

    /// Returns whether one input kind is declared by this inventory.
    #[must_use]
    pub fn admits(&self, kind: UntrustedInputKind) -> bool {
        self.inputs.iter().any(|input| input.kind == kind)
    }

    /// Admits one presented input, refusing an undeclared input and a differing digest.
    ///
    /// # Errors
    ///
    /// Returns [`CompilationError`] with code
    /// [`ToolchainDiagnosticCode::UndeclaredUntrustedInput`] when no declared input has this
    /// kind and name, and with code
    /// [`ToolchainDiagnosticCode::DeclaredInputDigestDiffer`] when a declared input has this
    /// kind and name but another digest, because a stale or foreign input never enters the
    /// activity under a declared identity it does not have.
    pub fn admit(&self, input: &UntrustedInput) -> Result<(), CompilationError> {
        for declared in &self.inputs {
            if declared.kind == input.kind && declared.name == input.name {
                if declared.digest == input.digest {
                    return Ok(());
                }
                return Err(CompilationError::new(
                    ToolchainDiagnosticCode::DeclaredInputDigestDiffer,
                    format!(
                        "the presented `{}` input `{}` declares digest {} but {} is declared",
                        input.kind.wire_name(),
                        input.name,
                        input.digest,
                        declared.digest
                    ),
                ));
            }
        }
        Err(CompilationError::new(
            ToolchainDiagnosticCode::UndeclaredUntrustedInput,
            format!(
                "the presented `{}` input `{}` is not declared by the inventory",
                input.kind.wire_name(),
                input.name
            ),
        ))
    }

    /// Returns the canonical digest over the declared kinds, names, and digests.
    ///
    /// Equal declared inventories produce equal digests, and a digest is never derived from
    /// the order in which an implementation discovered its inputs.
    #[must_use]
    pub fn digest(&self) -> DeclaredDigest {
        let mut fields: Vec<&[u8]> = Vec::new();
        for input in &self.inputs {
            fields.push(input.kind.wire_name().as_bytes());
            fields.push(input.name.as_bytes());
            fields.push(input.digest.as_str().as_bytes());
        }
        declared_digest(INPUT_INVENTORY_DOMAIN, &fields)
    }
}

/// The declared finite positive limits of one stage (`GNT-26.3`).
///
/// A limit exists only for a unit the stage charges, and a zero limit is refused before any
/// stage runs: a stage whose bound is not declared or is zero has no usable bound.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StageBudget {
    stage: ToolchainStage,
    limits: Vec<(BudgetUnit, u64)>,
}

impl StageBudget {
    /// Declares one stage budget in canonical unit order.
    ///
    /// # Errors
    ///
    /// Returns [`CompilationError`] with code [`ToolchainDiagnosticCode::EmptyStageBudget`]
    /// when no limit is declared, with code
    /// [`ToolchainDiagnosticCode::InapplicableStageLimit`] when a unit is not one the stage
    /// charges, with code [`ToolchainDiagnosticCode::ZeroStageLimit`] when a limit is zero,
    /// with code [`ToolchainDiagnosticCode::StageLimitTooLarge`] when a limit exceeds
    /// [`MAXIMUM_STAGE_LIMIT`], with code
    /// [`ToolchainDiagnosticCode::DuplicateBudgetUnit`] when one unit is declared twice, and
    /// with code [`ToolchainDiagnosticCode::NoncanonicalBudgetUnitOrder`] when the declared
    /// order is not canonical.
    pub fn new(
        stage: ToolchainStage,
        declared: &[(BudgetUnit, u64)],
    ) -> Result<Self, CompilationError> {
        if declared.is_empty() {
            return Err(CompilationError::new(
                ToolchainDiagnosticCode::EmptyStageBudget,
                format!("the `{}` stage declares no limit", stage.wire_name()),
            ));
        }
        let units = declared.iter().map(|(unit, _)| *unit).collect::<Vec<_>>();
        let unique = units.iter().collect::<BTreeSet<_>>();
        if unique.len() != units.len() {
            return Err(CompilationError::new(
                ToolchainDiagnosticCode::DuplicateBudgetUnit,
                format!("the `{}` stage declares one unit twice", stage.wire_name()),
            ));
        }
        if !units.windows(2).all(|window| window[0] < window[1]) {
            return Err(CompilationError::new(
                ToolchainDiagnosticCode::NoncanonicalBudgetUnitOrder,
                format!(
                    "the `{}` stage does not declare its units in canonical order",
                    stage.wire_name()
                ),
            ));
        }
        for (unit, limit) in declared {
            if !stage.applicable_units().contains(unit) {
                return Err(CompilationError::new(
                    ToolchainDiagnosticCode::InapplicableStageLimit,
                    format!(
                        "the `{}` stage does not charge `{}`",
                        stage.wire_name(),
                        unit.wire_name()
                    ),
                ));
            }
            if *limit == 0 {
                return Err(CompilationError::new(
                    ToolchainDiagnosticCode::ZeroStageLimit,
                    format!(
                        "the `{}` stage declares a zero `{}` limit",
                        stage.wire_name(),
                        unit.wire_name()
                    ),
                ));
            }
            if *limit > MAXIMUM_STAGE_LIMIT {
                return Err(CompilationError::new(
                    ToolchainDiagnosticCode::StageLimitTooLarge,
                    format!(
                        "the `{}` stage `{}` limit exceeds {MAXIMUM_STAGE_LIMIT}",
                        stage.wire_name(),
                        unit.wire_name()
                    ),
                ));
            }
        }
        Ok(Self {
            stage,
            limits: declared.to_vec(),
        })
    }

    /// Returns the stage this budget bounds.
    #[must_use]
    pub const fn stage(&self) -> ToolchainStage {
        self.stage
    }

    /// Returns the declared limit of one unit, if this budget declares one.
    #[must_use]
    pub fn limit(&self, unit: BudgetUnit) -> Option<u64> {
        self.limits
            .iter()
            .find(|(declared, _)| *declared == unit)
            .map(|(_, limit)| *limit)
    }

    /// Returns the declared units in canonical order.
    #[must_use]
    pub fn units(&self) -> Vec<BudgetUnit> {
        self.limits.iter().map(|(unit, _)| *unit).collect()
    }
}

/// One declared limits revision and its stage budgets (`GNT-26.3`).
///
/// The budget is activity policy: it is not durable execution identity, and its limits
/// revision participates in the cache key and the toolchain identity of this section.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolchainBudget {
    limits_revision: u64,
    stages: Vec<StageBudget>,
}

impl ToolchainBudget {
    /// Declares one toolchain budget in canonical stage order.
    ///
    /// # Errors
    ///
    /// Returns [`CompilationError`] with code
    /// [`ToolchainDiagnosticCode::ZeroLimitsRevision`] for revision zero, with code
    /// [`ToolchainDiagnosticCode::EmptyStageBudget`] when no stage budget is declared, with
    /// code [`ToolchainDiagnosticCode::DuplicateStageBudget`] when one stage is declared
    /// twice, and with code [`ToolchainDiagnosticCode::NoncanonicalStageBudgetOrder`] when the
    /// declared order is not canonical stage order.
    pub fn new(limits_revision: u64, declared: &[StageBudget]) -> Result<Self, CompilationError> {
        if limits_revision == 0 {
            return Err(CompilationError::new(
                ToolchainDiagnosticCode::ZeroLimitsRevision,
                "a toolchain budget declares a nonzero limits revision",
            ));
        }
        if declared.is_empty() {
            return Err(CompilationError::new(
                ToolchainDiagnosticCode::EmptyStageBudget,
                "a toolchain budget declares at least one stage budget",
            ));
        }
        let stages = declared.iter().map(StageBudget::stage).collect::<Vec<_>>();
        let unique = stages.iter().collect::<BTreeSet<_>>();
        if unique.len() != stages.len() {
            return Err(CompilationError::new(
                ToolchainDiagnosticCode::DuplicateStageBudget,
                "one stage is declared twice by one toolchain budget",
            ));
        }
        if !stages.windows(2).all(|window| window[0] < window[1]) {
            return Err(CompilationError::new(
                ToolchainDiagnosticCode::NoncanonicalStageBudgetOrder,
                "stage budgets are not declared in canonical stage order",
            ));
        }
        Ok(Self {
            limits_revision,
            stages: declared.to_vec(),
        })
    }

    /// Returns the declared limits revision.
    #[must_use]
    pub const fn limits_revision(&self) -> u64 {
        self.limits_revision
    }

    /// Returns the declared stage budgets in canonical stage order.
    #[must_use]
    pub fn stages(&self) -> &[StageBudget] {
        &self.stages
    }

    /// Returns the declared budget of one stage, if this budget declares one.
    #[must_use]
    pub fn stage_budget(&self, stage: ToolchainStage) -> Option<&StageBudget> {
        self.stages.iter().find(|budget| budget.stage == stage)
    }

    /// Begins one stage run, refusing an absent limit before the stage runs.
    ///
    /// # Errors
    ///
    /// Returns [`CompilationError`] with code
    /// [`ToolchainDiagnosticCode::StageBudgetUnadmitted`] when this budget declares no budget
    /// for the stage, and with code [`ToolchainDiagnosticCode::AbsentStageLimit`] when the
    /// stage budget omits a unit the stage charges, because a stage whose bound is not
    /// declared has no bound.
    pub fn begin_stage(&self, stage: ToolchainStage) -> Result<StageRun, CompilationError> {
        let budget = self.stage_budget(stage).ok_or_else(|| {
            CompilationError::new(
                ToolchainDiagnosticCode::StageBudgetUnadmitted,
                format!(
                    "the `{}` stage has no admitted stage budget",
                    stage.wire_name()
                ),
            )
        })?;
        for unit in stage.applicable_units() {
            if budget.limit(*unit).is_none() {
                return Err(CompilationError::new(
                    ToolchainDiagnosticCode::AbsentStageLimit,
                    format!(
                        "the `{}` stage has no declared `{}` limit",
                        stage.wire_name(),
                        unit.wire_name()
                    ),
                ));
            }
        }
        Ok(StageRun::begin(stage, budget.clone(), self.limits_revision))
    }
}

/// One declared charge against one stage, unit, limit, and observed count (`GNT-26.3`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BudgetObservation {
    stage: ToolchainStage,
    unit: BudgetUnit,
    limit: u64,
    observed: u64,
}

impl BudgetObservation {
    /// Records one declared charge.
    #[must_use]
    pub const fn new(stage: ToolchainStage, unit: BudgetUnit, limit: u64, observed: u64) -> Self {
        Self {
            stage,
            unit,
            limit,
            observed,
        }
    }

    /// Returns the charged stage.
    #[must_use]
    pub const fn stage(self) -> ToolchainStage {
        self.stage
    }

    /// Returns the charged unit.
    #[must_use]
    pub const fn unit(self) -> BudgetUnit {
        self.unit
    }

    /// Returns the declared limit.
    #[must_use]
    pub const fn limit(self) -> u64 {
        self.limit
    }

    /// Returns the observed count.
    #[must_use]
    pub const fn observed(self) -> u64 {
        self.observed
    }

    /// Returns whether the observed count exceeds the declared limit.
    #[must_use]
    pub const fn is_exceeded(self) -> bool {
        self.observed > self.limit
    }

    /// Returns the remaining budget, saturating at zero.
    #[must_use]
    pub const fn remaining(self) -> u64 {
        self.limit.saturating_sub(self.observed)
    }
}

/// One closed reason that one stage ended fail-closed (`GNT-26.3`).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CutoffReason {
    /// `limit` — a declared limit was exceeded, owned by `GNT-26.3`.
    Limit,
    /// `cancellation` — a cancellation settled the stage, owned by `GNT-26.6`.
    Cancellation,
    /// `structural-cycle` — a repeated open canonical key was interned, owned by `GNT-26.4`.
    StructuralCycle,
}

impl CutoffReason {
    /// Every reason of the closed vocabulary, in canonical wire-name order.
    pub const ALL: [Self; 3] = [Self::Cancellation, Self::Limit, Self::StructuralCycle];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Limit => "limit",
            Self::Cancellation => "cancellation",
            Self::StructuralCycle => "structural-cycle",
        }
    }

    /// Returns the same exact portable spelling as [`Self::wire_name`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.wire_name()
    }

    /// Strictly decodes one exact portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.wire_name() == value)
    }

    /// Returns the clause anchor that owns this reason.
    #[must_use]
    pub const fn requirement(self) -> &'static str {
        match self {
            Self::Limit => "GNT-26.3-finite-stage-budgets-and-fail-closed-cutoff",
            Self::Cancellation => "GNT-26.6-cancellation-settlement",
            Self::StructuralCycle => "GNT-26.4-structural-expansion-bounds",
        }
    }
}

/// One fail-closed end of one stage (`GNT-26.3`).
///
/// A cutoff is affine: it is not `Clone` and not `Copy`, it has no conversion to completion
/// evidence, and consuming it is the only way to settle the cancellation or the cycle it
/// reports, so one cutoff is reported and settled once.
#[derive(Debug, Eq, PartialEq)]
pub struct Cutoff {
    observation: BudgetObservation,
    reason: CutoffReason,
}

impl Cutoff {
    /// Ends one stage for one exceeded declared limit.
    ///
    /// # Errors
    ///
    /// Returns [`CompilationError`] with code
    /// [`ToolchainDiagnosticCode::BudgetUnexceeded`] when the observation does not exceed its
    /// declared limit, because a cutoff MUST NOT be reported for a charge within budget.
    pub fn exceeded(observation: BudgetObservation) -> Result<Self, CompilationError> {
        if !observation.is_exceeded() {
            return Err(CompilationError::new(
                ToolchainDiagnosticCode::BudgetUnexceeded,
                format!(
                    "the observed `{}` charge {} does not exceed the declared limit {}",
                    observation.unit().wire_name(),
                    observation.observed(),
                    observation.limit()
                ),
            ));
        }
        Ok(Self {
            observation,
            reason: CutoffReason::Limit,
        })
    }

    /// Settles one stage at one cancellation point.
    ///
    /// The observation records the last charge the cancelled stage observed; it is not
    /// required to exceed the declared limit, because a cancellation is not a limit
    /// exceedance.
    #[must_use]
    pub const fn cancellation(observation: BudgetObservation) -> Self {
        Self {
            observation,
            reason: CutoffReason::Cancellation,
        }
    }

    /// Ends one stage for one interned structural cycle.
    ///
    /// The observation records the charge the repeated open key would have added, so a cycle
    /// is never reported as a depth exceedance.
    #[must_use]
    pub const fn structural_cycle(observation: BudgetObservation) -> Self {
        Self {
            observation,
            reason: CutoffReason::StructuralCycle,
        }
    }

    /// Returns the observation this cutoff names.
    #[must_use]
    pub const fn observation(&self) -> BudgetObservation {
        self.observation
    }

    /// Returns the stage this cutoff ended.
    #[must_use]
    pub const fn stage(&self) -> ToolchainStage {
        self.observation.stage()
    }

    /// Returns the unit this cutoff was charged in.
    #[must_use]
    pub const fn unit(&self) -> BudgetUnit {
        self.observation.unit()
    }

    /// Returns the declared limit of this cutoff.
    #[must_use]
    pub const fn limit(&self) -> u64 {
        self.observation.limit()
    }

    /// Returns the observed count of this cutoff.
    #[must_use]
    pub const fn observed(&self) -> u64 {
        self.observation.observed()
    }

    /// Returns the closed reason of this cutoff.
    #[must_use]
    pub const fn reason(&self) -> CutoffReason {
        self.reason
    }

    /// Returns the clause anchor that owns this cutoff.
    #[must_use]
    pub const fn requirement(&self) -> &'static str {
        self.reason.requirement()
    }

    /// Returns a declared-value description of this cutoff, with no host fact in it.
    #[must_use]
    pub fn describe(&self) -> String {
        format!(
            "the `{}` stage was cut off for `{}` at {} of {} ({})",
            self.stage().wire_name(),
            self.unit().wire_name(),
            self.observed(),
            self.limit(),
            self.reason().wire_name()
        )
    }
}

/// One closed kind of canonical structural key (`GNT-26.4-structural-expansion-bounds`).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum FrontierKind {
    /// `artifact-reference`
    ArtifactReference,
    /// `declared-type`
    DeclaredType,
    /// `dependency-interface`
    DependencyInterface,
    /// `generic-instantiation`
    GenericInstantiation,
    /// `schema-node`
    SchemaNode,
    /// `trait-obligation`
    TraitObligation,
}

impl FrontierKind {
    /// Every kind of the closed vocabulary, in canonical wire-name order.
    pub const ALL: [Self; 6] = [
        Self::ArtifactReference,
        Self::DeclaredType,
        Self::DependencyInterface,
        Self::GenericInstantiation,
        Self::SchemaNode,
        Self::TraitObligation,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::ArtifactReference => "artifact-reference",
            Self::DeclaredType => "declared-type",
            Self::DependencyInterface => "dependency-interface",
            Self::GenericInstantiation => "generic-instantiation",
            Self::SchemaNode => "schema-node",
            Self::TraitObligation => "trait-obligation",
        }
    }

    /// Returns the same exact portable spelling as [`Self::wire_name`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.wire_name()
    }

    /// Strictly decodes one exact portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.wire_name() == value)
    }
}

/// One canonical structural key interned by a frontier (`GNT-26.4`).
///
/// The key is a declared kind and one declared canonical identity, so two expansions of the
/// same declared structure intern the same key and a cycle is decided from the key alone
/// rather than from a native call stack, an allocation failure, or a deadline.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FrontierKey {
    kind: FrontierKind,
    identity: Arc<str>,
}

impl FrontierKey {
    /// Declares one canonical structural key.
    ///
    /// # Errors
    ///
    /// Returns [`CompilationError`] with code [`ToolchainDiagnosticCode::InvalidDeclaredName`]
    /// when the identity is empty or carries a control character, because a key that is not a
    /// declared identity could intern twice for one declared structure.
    pub fn new(kind: FrontierKind, identity: &str) -> Result<Self, CompilationError> {
        if !is_declared_name(identity) {
            return Err(CompilationError::new(
                ToolchainDiagnosticCode::InvalidDeclaredName,
                format!("the declared structural key `{identity}` is not a legal declared name"),
            ));
        }
        Ok(Self {
            kind,
            identity: Arc::from(identity),
        })
    }

    /// Returns the declared kind of this key.
    #[must_use]
    pub const fn kind(&self) -> FrontierKind {
        self.kind
    }

    /// Returns the declared canonical identity of this key.
    #[must_use]
    pub fn identity(&self) -> &str {
        &self.identity
    }
}

/// One closed outcome of interning one canonical structural key (`GNT-26.4`).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum FrontierOutcome {
    /// `cycle` — the key is open on the current expansion path.
    Cycle,
    /// `depth-refused` — the key is deeper than the declared maximum depth.
    DepthRefused,
    /// `new` — the key was not interned before.
    New,
    /// `reused` — the key was interned before and is closed, so it is not expanded again.
    Reused,
}

impl FrontierOutcome {
    /// Every outcome of the closed vocabulary, in canonical wire-name order.
    pub const ALL: [Self; 4] = [Self::Cycle, Self::DepthRefused, Self::New, Self::Reused];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Cycle => "cycle",
            Self::DepthRefused => "depth-refused",
            Self::New => "new",
            Self::Reused => "reused",
        }
    }

    /// Returns the same exact portable spelling as [`Self::wire_name`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.wire_name()
    }

    /// Strictly decodes one exact portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.wire_name() == value)
    }

    /// Returns whether this outcome refuses expansion.
    #[must_use]
    pub const fn is_refusal(self) -> bool {
        matches!(self, Self::Cycle | Self::DepthRefused)
    }

    /// Returns the clause anchor that owns this outcome.
    #[must_use]
    pub const fn requirement(self) -> &'static str {
        "GNT-26.4-structural-expansion-bounds"
    }
}

/// One bounded structural-expansion frontier (`GNT-26.4`).
///
/// The frontier interns canonical keys and tracks which of them are open on the current
/// expansion path. A repeated open key is a structural cycle, a closed key is reused rather
/// than expanded again, and only a key that is neither open nor closed and is deeper than the
/// declared maximum depth is refused before it is retained: a repeated open key MUST NOT be
/// reported as a depth exceedance and a depth refusal MUST NOT be reported as a cycle. No
/// outcome of this frontier reads a native stack, a stack-overflow guard, an allocation
/// result, a deadline, or a memory reading.
#[derive(Debug, Eq, PartialEq)]
pub struct StructuralFrontier {
    maximum_depth: u64,
    open: BTreeSet<FrontierKey>,
    closed: BTreeSet<FrontierKey>,
    interned: usize,
}

impl StructuralFrontier {
    /// Declares one frontier with one maximum expansion depth.
    ///
    /// The depth is a `u64`, so every depth up to the greatest declared stage limit is
    /// representable without truncation. The nonzero requirement is declared model policy of
    /// `GNT-26.4-structural-expansion-bounds`: a zero-depth frontier refuses every expansion,
    /// names no admissible structure, and decides no cycle.
    ///
    /// # Errors
    ///
    /// Returns [`CompilationError`] with code
    /// [`ToolchainDiagnosticCode::FrontierZeroDepth`] when the maximum depth is zero, because
    /// a zero-depth frontier refuses every expansion and so declares no admissible structure.
    pub fn new(maximum_depth: u64) -> Result<Self, CompilationError> {
        if maximum_depth == 0 {
            return Err(CompilationError::new(
                ToolchainDiagnosticCode::FrontierZeroDepth,
                "a structural frontier declares a nonzero maximum depth",
            ));
        }
        Ok(Self {
            maximum_depth,
            open: BTreeSet::new(),
            closed: BTreeSet::new(),
            interned: 0,
        })
    }

    /// Returns the declared maximum expansion depth.
    #[must_use]
    pub const fn maximum_depth(&self) -> u64 {
        self.maximum_depth
    }

    /// Returns the number of keys this frontier has interned.
    #[must_use]
    pub const fn interned(&self) -> usize {
        self.interned
    }

    /// Returns the number of keys open on the current expansion path.
    #[must_use]
    pub fn open_keys(&self) -> usize {
        self.open.len()
    }

    /// Interns one canonical key at one declared depth.
    ///
    /// The declared checks run in one order: a repeated open key is reported as a structural
    /// cycle and a closed key is reported as reused and is not charged again, before the depth
    /// of the key is compared at all, and only a key that is neither open nor closed and is
    /// deeper than the declared maximum depth is refused before it is retained. Any other key
    /// is newly interned and left open until [`Self::close`].
    pub fn intern(&mut self, key: FrontierKey, depth: u64) -> FrontierOutcome {
        if self.open.contains(&key) {
            return FrontierOutcome::Cycle;
        }
        if self.closed.contains(&key) {
            return FrontierOutcome::Reused;
        }
        if depth > self.maximum_depth {
            return FrontierOutcome::DepthRefused;
        }
        self.open.insert(key);
        self.interned += 1;
        FrontierOutcome::New
    }

    /// Closes one interned key, so a later intern of it is reused rather than a cycle.
    ///
    /// A key that is not open is left exactly as it was, so closing twice closes once and
    /// extending the path never reopens a closed key.
    pub fn close(&mut self, key: &FrontierKey) {
        if self.open.remove(key) {
            self.closed.insert(key.clone());
        }
    }
}

/// The affine witness that one stage run finished within its declared budget (`GNT-26.5`).
///
/// Only [`StageRun::finish`] mints one. The value is affine: it is not `Clone` and not `Copy`,
/// it has no constructor of its own, and it cannot be reconstructed from a stage name, a
/// digest, a log entry, a progress observation, or a cutoff.
#[derive(Debug, Eq, PartialEq)]
pub struct CompletionEvidence {
    stage: ToolchainStage,
    limits_revision: u64,
    charges: u64,
    witness: DeclaredDigest,
}

impl CompletionEvidence {
    /// Returns the stage that finished within budget.
    #[must_use]
    pub const fn stage(&self) -> ToolchainStage {
        self.stage
    }

    /// Returns the limits revision the finished stage ran under.
    #[must_use]
    pub const fn limits_revision(&self) -> u64 {
        self.limits_revision
    }

    /// Returns the number of charges the finished stage observed.
    #[must_use]
    pub const fn charges(&self) -> u64 {
        self.charges
    }

    /// Returns the derived witness digest of this evidence.
    #[must_use]
    pub const fn witness(&self) -> &DeclaredDigest {
        &self.witness
    }
}

/// The closed outcome of one charge against one running stage (`GNT-26.3`).
#[derive(Debug)]
pub enum StageProgress {
    /// The charge is within its declared limit and the same affine run continues.
    WithinBudget(StageRun),
    /// The charge exceeded its declared limit; the run is consumed into one typed cutoff.
    CutOff(Cutoff),
    /// The charge names a unit the stage does not charge; the run is consumed into a refusal.
    Refused(CompilationError),
}

impl StageProgress {
    /// Returns whether the charge stayed within its declared limit.
    #[must_use]
    pub const fn is_within_budget(&self) -> bool {
        matches!(self, Self::WithinBudget(_))
    }

    /// Returns the cutoff this charge produced, if it produced one.
    #[must_use]
    pub const fn cutoff(&self) -> Option<&Cutoff> {
        match self {
            Self::CutOff(cutoff) => Some(cutoff),
            Self::WithinBudget(_) | Self::Refused(_) => None,
        }
    }

    /// Returns the continuing run, or the typed refusal that consumed it.
    ///
    /// # Errors
    ///
    /// Returns [`CompilationError`] with code [`ToolchainDiagnosticCode::StageCutOff`] for a
    /// cutoff and the refusal error for a unit the stage does not charge.
    pub fn into_run(self) -> Result<StageRun, CompilationError> {
        match self {
            Self::WithinBudget(run) => Ok(run),
            Self::CutOff(cutoff) => Err(CompilationError::new(
                ToolchainDiagnosticCode::StageCutOff,
                cutoff.describe(),
            )),
            Self::Refused(error) => Err(error),
        }
    }
}

/// One affine run of one stage under one admitted stage budget (`GNT-26.3`).
///
/// A run is affine: it is not `Clone` and not `Copy`, a charge consumes the run and returns it
/// only when the charge stayed within budget, so a cut-off run leaves no value that could be
/// finished, and [`Self::finish`] is therefore unreachable after a cutoff.
#[derive(Debug)]
pub struct StageRun {
    stage: ToolchainStage,
    budget: StageBudget,
    limits_revision: u64,
    charges: u64,
}

impl StageRun {
    /// Begins one run for one admitted stage budget.
    fn begin(stage: ToolchainStage, budget: StageBudget, limits_revision: u64) -> Self {
        Self {
            stage,
            budget,
            limits_revision,
            charges: 0,
        }
    }

    /// Returns the stage this run charges.
    #[must_use]
    pub const fn stage(&self) -> ToolchainStage {
        self.stage
    }

    /// Returns the limits revision this run declares.
    #[must_use]
    pub const fn limits_revision(&self) -> u64 {
        self.limits_revision
    }

    /// Returns the number of charges this run has observed.
    #[must_use]
    pub const fn charges(&self) -> u64 {
        self.charges
    }

    /// Returns the declared limit of one unit, if this run's stage budget declares one.
    #[must_use]
    pub fn declared_limit(&self, unit: BudgetUnit) -> Option<u64> {
        self.budget.limit(unit)
    }

    /// Charges one unit and observes one count.
    ///
    /// The charge is compared with the declared limit before any work or output is retained.
    /// A charge within budget returns the same run with one more recorded charge; a charge
    /// beyond the limit consumes the run into one cutoff; and a charge in a unit this stage
    /// does not charge consumes the run into a refusal rather than be charged to another unit.
    #[must_use]
    pub fn check(self, unit: BudgetUnit, observed: u64) -> StageProgress {
        let Some(limit) = self.budget.limit(unit) else {
            return StageProgress::Refused(CompilationError::new(
                ToolchainDiagnosticCode::InapplicableStageLimit,
                format!(
                    "the `{}` stage does not charge `{}`",
                    self.stage.wire_name(),
                    unit.wire_name()
                ),
            ));
        };
        let observation = BudgetObservation::new(self.stage, unit, limit, observed);
        if observation.is_exceeded() {
            return match Cutoff::exceeded(observation) {
                Ok(cutoff) => StageProgress::CutOff(cutoff),
                Err(error) => StageProgress::Refused(error),
            };
        }
        let Some(charges) = self.charges.checked_add(1) else {
            return StageProgress::Refused(CompilationError::new(
                ToolchainDiagnosticCode::StageChargeOverflow,
                format!(
                    "the `{}` stage run recorded {} charges and cannot record another",
                    self.stage.wire_name(),
                    self.charges
                ),
            ));
        };
        StageProgress::WithinBudget(Self {
            stage: self.stage,
            budget: self.budget,
            limits_revision: self.limits_revision,
            charges,
        })
    }

    /// Consumes one run that never left its budget and mints its one completion evidence.
    #[must_use]
    pub fn finish(self) -> CompletionEvidence {
        let limits_revision = self.limits_revision.to_be_bytes();
        let charges = self.charges.to_be_bytes();
        let witness = declared_digest(
            COMPLETION_WITNESS_DOMAIN,
            &[
                self.stage.wire_name().as_bytes(),
                &limits_revision,
                &charges,
            ],
        );
        CompletionEvidence {
            stage: self.stage,
            limits_revision: self.limits_revision,
            charges: self.charges,
            witness,
        }
    }
}

/// One published artifact of one stage that finished within budget (`GNT-26.5`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedArtifact {
    stage: ToolchainStage,
    digest: DeclaredDigest,
}

impl SealedArtifact {
    /// Seals one artifact under one completion evidence.
    ///
    /// The evidence is taken by value and is never duplicated, so this constructor is the only
    /// way to publish an artifact and a cut-off run cannot call it at all.
    #[must_use]
    pub fn publish(evidence: CompletionEvidence, digest: DeclaredDigest) -> Self {
        Self {
            stage: evidence.stage(),
            digest,
        }
    }

    /// Returns the stage that published this artifact.
    #[must_use]
    pub const fn stage(&self) -> ToolchainStage {
        self.stage
    }

    /// Returns the canonical digest of this artifact.
    #[must_use]
    pub const fn digest(&self) -> &DeclaredDigest {
        &self.digest
    }
}

/// One published authority closure of one stage that finished within budget (`GNT-26.5`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedAuthorityClosure {
    stage: ToolchainStage,
    digest: DeclaredDigest,
}

impl SealedAuthorityClosure {
    /// Seals one authority closure under one completion evidence.
    ///
    /// The evidence is taken by value, so a cut-off run cannot seal an authority closure and
    /// the closure is never observable in part.
    #[must_use]
    pub fn seal(evidence: CompletionEvidence, digest: DeclaredDigest) -> Self {
        Self {
            stage: evidence.stage(),
            digest,
        }
    }

    /// Returns the stage that sealed this closure.
    #[must_use]
    pub const fn stage(&self) -> ToolchainStage {
        self.stage
    }

    /// Returns the canonical digest of this closure.
    #[must_use]
    pub const fn digest(&self) -> &DeclaredDigest {
        &self.digest
    }
}

/// Refuses publication from one cutoff (`GNT-26.5`).
///
/// # Errors
///
/// Always returns [`CompilationError`] with code
/// [`ToolchainDiagnosticCode::MissingCompletionEvidence`], because a cutoff carries no
/// completion evidence and the evidence value a publication requires cannot be produced from
/// a cut-off run.
pub fn refuse_publication_after_cutoff(
    cutoff: &Cutoff,
) -> Result<SealedArtifact, CompilationError> {
    Err(CompilationError::new(
        ToolchainDiagnosticCode::MissingCompletionEvidence,
        cutoff.describe(),
    ))
}

/// One closed kind of cancellation settlement (`GNT-26.6-cancellation-settlement`).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CancellationSettlementKind {
    /// `already-finished` — the stage finished within budget before the request.
    AlreadyFinished,
    /// `cut-off` — the stage was running and settled at one cancellation point.
    CutOff,
    /// `not-started` — the stage had not begun, so no stage work ran.
    NotStarted,
}

impl CancellationSettlementKind {
    /// Every kind of the closed vocabulary, in canonical wire-name order.
    pub const ALL: [Self; 3] = [Self::AlreadyFinished, Self::CutOff, Self::NotStarted];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::AlreadyFinished => "already-finished",
            Self::CutOff => "cut-off",
            Self::NotStarted => "not-started",
        }
    }

    /// Returns the same exact portable spelling as [`Self::wire_name`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.wire_name()
    }

    /// Strictly decodes one exact portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.wire_name() == value)
    }

    /// Returns the clause anchor that owns this settlement.
    #[must_use]
    pub const fn requirement(self) -> &'static str {
        "GNT-26.6-cancellation-settlement"
    }
}

/// One typed settlement of one cancellation request at one stage (`GNT-26.6`).
///
/// A settlement is affine: it is not `Clone` and not `Copy`, and consuming a [`Cutoff`] is the
/// only way to build the cut-off kind. A settlement mints no completion evidence for the work it
/// discards, so a cancelled stage cannot seal an artifact or an authority closure; the
/// already-finished kind instead retains the completion evidence of a stage that finished within
/// its budget, because cancellation changed nothing about that stage, and yields that evidence
/// through [`Self::into_evidence`]. The shutdown, unclean-drop, drain, abortion, and
/// terminal-precedence contracts remain the landed ones of `GNT-10.12`, `GNT-10.13`, and
/// `GNT-10.14` and their Section 22 extensions.
#[derive(Debug, Eq, PartialEq)]
pub struct CancellationSettlement {
    stage: ToolchainStage,
    kind: CancellationSettlementKind,
    cutoff: Option<Cutoff>,
    evidence: Option<CompletionEvidence>,
}

impl CancellationSettlement {
    /// Settles one cancellation request for a stage that had not begun.
    #[must_use]
    pub const fn not_started(stage: ToolchainStage) -> Self {
        Self {
            stage,
            kind: CancellationSettlementKind::NotStarted,
            cutoff: None,
            evidence: None,
        }
    }

    /// Settles one cancellation request for a stage that was running.
    ///
    /// # Errors
    ///
    /// Returns [`CompilationError`] with code
    /// [`ToolchainDiagnosticCode::CancellationSettlementRefused`] when the cutoff reason is not
    /// the cancellation reason, because a cancellation MUST NOT be reported as a declared-limit
    /// exceedance or as a structural cycle.
    pub fn cut_off(cutoff: Cutoff) -> Result<Self, CompilationError> {
        if cutoff.reason() != CutoffReason::Cancellation {
            return Err(CompilationError::new(
                ToolchainDiagnosticCode::CancellationSettlementRefused,
                format!(
                    "the `{}` cutoff is not a cancellation settlement",
                    cutoff.reason().wire_name()
                ),
            ));
        }
        Ok(Self {
            stage: cutoff.stage(),
            kind: CancellationSettlementKind::CutOff,
            cutoff: Some(cutoff),
            evidence: None,
        })
    }

    /// Settles one cancellation request for a stage that already finished within budget.
    ///
    /// Cancellation changed nothing about that stage, so the finished stage keeps its completion
    /// evidence: this settlement retains the affine witness and yields it unchanged through
    /// [`Self::into_evidence`].
    #[must_use]
    pub fn already_finished(evidence: CompletionEvidence) -> Self {
        Self {
            stage: evidence.stage(),
            kind: CancellationSettlementKind::AlreadyFinished,
            cutoff: None,
            evidence: Some(evidence),
        }
    }

    /// Returns the settled stage.
    #[must_use]
    pub const fn stage(&self) -> ToolchainStage {
        self.stage
    }

    /// Returns the closed kind of this settlement.
    #[must_use]
    pub const fn kind(&self) -> CancellationSettlementKind {
        self.kind
    }

    /// Returns the cancellation cutoff this settlement consumed, if any.
    #[must_use]
    pub const fn cutoff(&self) -> Option<&Cutoff> {
        self.cutoff.as_ref()
    }

    /// Returns whether the settled stage performed stage work before settling.
    #[must_use]
    pub const fn ran_stage_work(&self) -> bool {
        !matches!(self.kind, CancellationSettlementKind::NotStarted)
    }

    /// Returns whether the settled stage had published before the request.
    #[must_use]
    pub const fn is_published(&self) -> bool {
        matches!(self.kind, CancellationSettlementKind::AlreadyFinished)
    }

    /// Yields the completion evidence this settlement retains, if it retains one.
    ///
    /// The already-finished kind retains the affine witness of the stage that finished within
    /// its budget, because cancellation changed nothing about that stage, and yields it here
    /// exactly once: the settlement is consumed, so the retained evidence is published once and
    /// is never duplicated. A settlement that discarded work retains no evidence at all.
    ///
    /// # Errors
    ///
    /// Returns [`CompilationError`] with code
    /// [`ToolchainDiagnosticCode::MissingCompletionEvidence`] for the not-started and cut-off
    /// kinds, because those settlements mint no completion evidence for the work they discard
    /// and their refusal publishes nothing.
    pub fn into_evidence(self) -> Result<CompletionEvidence, CompilationError> {
        match self.evidence {
            Some(evidence) => Ok(evidence),
            None => Err(CompilationError::new(
                ToolchainDiagnosticCode::MissingCompletionEvidence,
                format!(
                    "the `{}` stage settled cancellation as `{}` and holds no completion evidence",
                    self.stage.wire_name(),
                    self.kind.wire_name()
                ),
            )),
        }
    }
}

/// One compilation activity's per-stage admission and settlement record (`GNT-26.3`, `GNT-26.6`).
///
/// The activity owns one admitted [`ToolchainBudget`] and records which of its stages have been
/// admitted to run and which have been settled. A stage runs at most once per activity, so a
/// second admission of one stage, and an admission of a stage this activity already settled, are
/// both refused rather than merged, and a cancellation request settles exactly once per stage, so
/// a second settlement of one stage is refused. The record reads no clock, no host path, and no
/// environment fact: every verdict here is a pure function of the admitted budget and the calls
/// made on it.
#[derive(Debug, Eq, PartialEq)]
pub struct CompilationActivity {
    budget: ToolchainBudget,
    admitted: BTreeSet<ToolchainStage>,
    settled: BTreeSet<ToolchainStage>,
}

impl CompilationActivity {
    /// Opens one activity under one admitted toolchain budget.
    #[must_use]
    pub const fn new(budget: ToolchainBudget) -> Self {
        Self {
            budget,
            admitted: BTreeSet::new(),
            settled: BTreeSet::new(),
        }
    }

    /// Returns the admitted toolchain budget of this activity.
    #[must_use]
    pub const fn budget(&self) -> &ToolchainBudget {
        &self.budget
    }

    /// Returns the stages this activity admitted to run, in canonical stage order.
    #[must_use]
    pub fn admitted_stages(&self) -> Vec<ToolchainStage> {
        self.admitted.iter().copied().collect()
    }

    /// Returns the stages this activity settled, in canonical stage order.
    #[must_use]
    pub fn settled_stages(&self) -> Vec<ToolchainStage> {
        self.settled.iter().copied().collect()
    }

    /// Begins the one run of one stage of this activity.
    ///
    /// The admission is refused before the admitted budget is consulted when the stage already
    /// ran in this activity or when this activity already settled it, so a stage runs at most
    /// once per activity and a stage settled by a cancellation cutoff never runs again.
    ///
    /// # Errors
    ///
    /// Returns [`CompilationError`] with code [`ToolchainDiagnosticCode::StageAlreadyRun`] when
    /// this activity already admitted the stage or already settled it, and otherwise the refusal
    /// of [`ToolchainBudget::begin_stage`]: an unadmitted stage or an absent declared limit.
    pub fn begin_stage(&mut self, stage: ToolchainStage) -> Result<StageRun, CompilationError> {
        if self.admitted.contains(&stage) || self.settled.contains(&stage) {
            return Err(CompilationError::new(
                ToolchainDiagnosticCode::StageAlreadyRun,
                format!(
                    "the `{}` stage already ran or was already settled in this activity",
                    stage.wire_name()
                ),
            ));
        }
        let run = self.budget.begin_stage(stage)?;
        self.admitted.insert(stage);
        Ok(run)
    }

    /// Records one cancellation settlement for one stage of this activity.
    ///
    /// The settlement is returned unchanged, so the caller keeps the evidence the
    /// already-finished kind retains and can publish from it, exactly as `GNT-26.6` requires.
    ///
    /// # Errors
    ///
    /// Returns [`CompilationError`] with code
    /// [`ToolchainDiagnosticCode::StageBudgetUnadmitted`] when the settlement names a stage this
    /// activity does not admit, because a settlement that names a stage outside the activity is
    /// refused rather than merged, and when a cancellation cutoff settles a stage the activity
    /// never admitted, because a cutoff settles a running stage rather than one that never began;
    /// and with code
    /// [`ToolchainDiagnosticCode::StageAlreadySettled`] when this activity already settled that
    /// stage, because a cancellation request settles exactly once per stage.
    pub fn settle(
        &mut self,
        settlement: CancellationSettlement,
    ) -> Result<CancellationSettlement, CompilationError> {
        let stage = settlement.stage();
        if self.budget.stage_budget(stage).is_none() {
            return Err(CompilationError::new(
                ToolchainDiagnosticCode::StageBudgetUnadmitted,
                format!(
                    "the settled `{}` stage is not admitted by this activity",
                    stage.wire_name()
                ),
            ));
        }
        if settlement.kind() == CancellationSettlementKind::CutOff
            && !self.admitted.contains(&stage)
        {
            return Err(CompilationError::new(
                ToolchainDiagnosticCode::StageBudgetUnadmitted,
                format!(
                    "the cancelled `{}` stage was never admitted by this activity",
                    stage.wire_name()
                ),
            ));
        }
        if !self.settled.insert(stage) {
            return Err(CompilationError::new(
                ToolchainDiagnosticCode::StageAlreadySettled,
                format!(
                    "the `{}` stage was already settled by this activity",
                    stage.wire_name()
                ),
            ));
        }
        Ok(settlement)
    }
}

/// One closed refusal reason of the artifact loader (`GNT-26.7-artifact-loader-validation`).
///
/// Each reason owns exactly one diagnostic code, and the reasons are never merged: an oversized
/// artifact is not a malformed artifact, and a digest mismatch is not an unknown reference.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ArtifactRefusalReason {
    /// `digest-mismatch`
    DigestMismatch,
    /// `limit-exceeded`
    LimitExceeded,
    /// `malformed-structure`
    MalformedStructure,
    /// `noncanonical-references`
    NoncanonicalReferences,
    /// `unknown-reference`
    UnknownReference,
    /// `unsupported-version`
    UnsupportedVersion,
}

impl ArtifactRefusalReason {
    /// Every reason of the closed vocabulary, in canonical wire-name order.
    pub const ALL: [Self; 6] = [
        Self::DigestMismatch,
        Self::LimitExceeded,
        Self::MalformedStructure,
        Self::NoncanonicalReferences,
        Self::UnknownReference,
        Self::UnsupportedVersion,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::DigestMismatch => "digest-mismatch",
            Self::LimitExceeded => "limit-exceeded",
            Self::MalformedStructure => "malformed-structure",
            Self::NoncanonicalReferences => "noncanonical-references",
            Self::UnknownReference => "unknown-reference",
            Self::UnsupportedVersion => "unsupported-version",
        }
    }

    /// Returns the same exact portable spelling as [`Self::wire_name`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.wire_name()
    }

    /// Strictly decodes one exact portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.wire_name() == value)
    }

    /// Returns the one diagnostic code this reason owns.
    #[must_use]
    pub const fn code(self) -> ToolchainDiagnosticCode {
        match self {
            Self::DigestMismatch => ToolchainDiagnosticCode::ArtifactDigestMismatch,
            Self::LimitExceeded => ToolchainDiagnosticCode::ArtifactLimitExceeded,
            Self::MalformedStructure => ToolchainDiagnosticCode::ArtifactStructureMalformed,
            Self::NoncanonicalReferences => ToolchainDiagnosticCode::ArtifactReferencesNoncanonical,
            Self::UnknownReference => ToolchainDiagnosticCode::ArtifactReferenceUnknown,
            Self::UnsupportedVersion => ToolchainDiagnosticCode::ArtifactVersionUnsupported,
        }
    }

    /// Returns the clause anchor that owns this reason.
    #[must_use]
    pub const fn requirement(self) -> &'static str {
        "GNT-26.7-artifact-loader-validation"
    }
}

/// One precomputed artifact as a loader observes it before any fact is trusted (`GNT-26.7`).
///
/// The declared version, the declared structure outcome of the caller's bounded decoder, the
/// presented byte length, the digest the artifact declares, the digest the loader observed over
/// the presented bytes, and the declared referenced identities are the whole evidence a loader
/// has. Nothing here is a host fact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PresentedArtifact {
    version: u32,
    canonical_structure: bool,
    byte_length: u64,
    declared_digest: DeclaredDigest,
    observed_digest: DeclaredDigest,
    references: Vec<DeclaredDigest>,
}

impl PresentedArtifact {
    /// Records one presented artifact exactly as the loader observes it.
    #[must_use]
    pub fn new(
        version: u32,
        canonical_structure: bool,
        byte_length: u64,
        declared_digest: DeclaredDigest,
        observed_digest: DeclaredDigest,
        references: &[DeclaredDigest],
    ) -> Self {
        Self {
            version,
            canonical_structure,
            byte_length,
            declared_digest,
            observed_digest,
            references: references.to_vec(),
        }
    }

    /// Returns the declared artifact version.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// Returns whether the presented bytes decode as the declared canonical structure.
    #[must_use]
    pub const fn is_canonical_structure(&self) -> bool {
        self.canonical_structure
    }

    /// Returns the presented byte length.
    #[must_use]
    pub const fn byte_length(&self) -> u64 {
        self.byte_length
    }

    /// Returns the digest the artifact declares.
    #[must_use]
    pub const fn declared_digest(&self) -> &DeclaredDigest {
        &self.declared_digest
    }

    /// Returns the digest the loader observed over the presented bytes.
    #[must_use]
    pub const fn observed_digest(&self) -> &DeclaredDigest {
        &self.observed_digest
    }

    /// Returns the declared referenced identities in presented order.
    #[must_use]
    pub fn references(&self) -> &[DeclaredDigest] {
        &self.references
    }
}

/// One validated artifact whose precomputed facts may be trusted (`GNT-26.7`).
///
/// The only way to obtain one is [`ArtifactLoader::load`], so a refused artifact contributes no
/// fact at all and a partial or repaired artifact is never observable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoadedArtifact {
    version: u32,
    digest: DeclaredDigest,
    references: Vec<DeclaredDigest>,
}

impl LoadedArtifact {
    /// Returns the validated version of this artifact.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// Returns the validated digest of this artifact.
    #[must_use]
    pub const fn digest(&self) -> &DeclaredDigest {
        &self.digest
    }

    /// Returns the validated referenced identities in canonical order.
    #[must_use]
    pub fn references(&self) -> &[DeclaredDigest] {
        &self.references
    }
}

/// The declared version, byte limit, and referenced identities one loader accepts (`GNT-26.7`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactLoader {
    supported_version: u32,
    maximum_bytes: u64,
    known_references: BTreeSet<DeclaredDigest>,
}

impl ArtifactLoader {
    /// Declares one loader.
    ///
    /// The nonzero version and byte limit are declared model policy of
    /// `GNT-26.7-artifact-loader-validation`: a loader with no supported version and no bound
    /// accepts nothing it could decide and refuses no reason it should refuse, so it is refused
    /// rather than treated as a permissive loader.
    ///
    /// # Errors
    ///
    /// Returns [`CompilationError`] with code
    /// [`ToolchainDiagnosticCode::ZeroLoaderConfiguration`] when the supported version or the
    /// byte limit is zero, because a loader with no supported version and no bound accepts
    /// nothing it could decide.
    pub fn new(
        supported_version: u32,
        maximum_bytes: u64,
        known_references: &[DeclaredDigest],
    ) -> Result<Self, CompilationError> {
        if supported_version == 0 || maximum_bytes == 0 {
            return Err(CompilationError::new(
                ToolchainDiagnosticCode::ZeroLoaderConfiguration,
                "an artifact loader declares a nonzero version and byte limit",
            ));
        }
        Ok(Self {
            supported_version,
            maximum_bytes,
            known_references: known_references.iter().cloned().collect(),
        })
    }

    /// Returns the one artifact version this loader supports.
    #[must_use]
    pub const fn supported_version(&self) -> u32 {
        self.supported_version
    }

    /// Returns the declared artifact byte limit.
    #[must_use]
    pub const fn maximum_bytes(&self) -> u64 {
        self.maximum_bytes
    }

    /// Returns whether one referenced identity is declared to this loader.
    #[must_use]
    pub fn knows_reference(&self, reference: &DeclaredDigest) -> bool {
        self.known_references.contains(reference)
    }

    /// Validates one presented artifact before any precomputed fact is trusted.
    ///
    /// The declared checks run in one order: the version, the canonical structure, the
    /// canonicality of the referenced identities, the declared byte limit, the digest, and the
    /// referenced identities. Each failed check refuses with its own reason and its own code,
    /// and a refusal yields no fact at all.
    ///
    /// # Errors
    ///
    /// Returns [`CompilationError`] with the code of the first failed check: an unsupported
    /// version, a malformed structure, noncanonical references, an exceeded limit, a digest
    /// mismatch, or an unknown referenced identity.
    pub fn load(&self, presented: &PresentedArtifact) -> Result<LoadedArtifact, CompilationError> {
        let refuse = |reason: ArtifactRefusalReason, detail: String| {
            CompilationError::new(reason.code(), detail)
        };
        if presented.version != self.supported_version {
            return Err(refuse(
                ArtifactRefusalReason::UnsupportedVersion,
                format!(
                    "the presented artifact version {} is not the supported version {}",
                    presented.version, self.supported_version
                ),
            ));
        }
        if !presented.canonical_structure {
            return Err(refuse(
                ArtifactRefusalReason::MalformedStructure,
                format!("the presented artifact version {}", presented.version),
            ));
        }
        if !presented
            .references
            .windows(2)
            .all(|window| window[0] < window[1])
        {
            return Err(refuse(
                ArtifactRefusalReason::NoncanonicalReferences,
                format!("the presented artifact version {}", presented.version),
            ));
        }
        if presented.byte_length > self.maximum_bytes {
            return Err(refuse(
                ArtifactRefusalReason::LimitExceeded,
                format!(
                    "the presented artifact is {} bytes against the declared limit {}",
                    presented.byte_length, self.maximum_bytes
                ),
            ));
        }
        if presented.declared_digest != presented.observed_digest {
            return Err(refuse(
                ArtifactRefusalReason::DigestMismatch,
                format!(
                    "the presented artifact declares {} but the presented bytes digest to {}",
                    presented.declared_digest, presented.observed_digest
                ),
            ));
        }
        for reference in &presented.references {
            if !self.known_references.contains(reference) {
                return Err(refuse(
                    ArtifactRefusalReason::UnknownReference,
                    format!(
                        "the presented artifact references the undeclared identity {reference}"
                    ),
                ));
            }
        }
        Ok(LoadedArtifact {
            version: presented.version,
            digest: presented.observed_digest.clone(),
            references: presented.references.clone(),
        })
    }
}

/// One declared stage configuration of one compilation activity (`GNT-26.8-cache-identity`).
///
/// The configured stages are one canonical, sorted, deduplicated set, so the order they were
/// declared in is not part of the configuration and two activities that configure the same
/// stages derive the same cache key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StageConfiguration {
    stages: Vec<ToolchainStage>,
}

impl StageConfiguration {
    /// Declares one stage configuration.
    ///
    /// The nonempty requirement is declared model policy of
    /// `GNT-26.2-stage-and-unit-vocabulary`: a configuration selects at least one stage of the
    /// closed stage vocabulary, because a configuration that selects no stage names no stage of
    /// that vocabulary and cannot identify a result.
    ///
    /// # Errors
    ///
    /// Returns [`CompilationError`] with code
    /// [`ToolchainDiagnosticCode::EmptyStageConfiguration`] when no stage is configured, because
    /// a configuration that selects no stage cannot identify a result.
    pub fn new(declared: &[ToolchainStage]) -> Result<Self, CompilationError> {
        if declared.is_empty() {
            return Err(CompilationError::new(
                ToolchainDiagnosticCode::EmptyStageConfiguration,
                "a stage configuration selects at least one stage",
            ));
        }
        let stages = ToolchainStage::ALL
            .into_iter()
            .filter(|candidate| declared.contains(candidate))
            .collect::<Vec<_>>();
        Ok(Self { stages })
    }

    /// Returns the configured stages in canonical stage order.
    #[must_use]
    pub fn stages(&self) -> &[ToolchainStage] {
        &self.stages
    }

    /// Returns whether one stage is configured.
    #[must_use]
    pub fn configures(&self, stage: ToolchainStage) -> bool {
        self.stages.contains(&stage)
    }
}

/// The closed declared identity inputs of one cache key (`GNT-26.8`).
///
/// The input set is closed: every field is required, the feature set and the dependency
/// interface digests are canonical sets, and a supplied all-zero digest is refused as an
/// omitted input. No field of this type is a host path, a build directory, a clock reading, an
/// environment fact, a locale, a process identifier, a random value, or a file modification
/// time.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CacheKeyInputs {
    source_digest: DeclaredDigest,
    manifest_digest: DeclaredDigest,
    features: Vec<Arc<str>>,
    target_selection: TargetDescriptorDigest,
    dependency_interface_digests: Vec<DeclaredDigest>,
    toolchain_identity: DeclaredDigest,
    limits_revision: u64,
    stage_configuration: StageConfiguration,
}

impl CacheKeyInputs {
    /// Declares one complete cache identity input set.
    ///
    /// The feature names and the dependency interface digests are decoded into canonical,
    /// sorted, deduplicated sets, so the order they were given in is never part of the key.
    ///
    /// # Errors
    ///
    /// Returns [`CompilationError`] with code [`ToolchainDiagnosticCode::IncompleteCacheKey`]
    /// when a required digest is the reserved all-zero omitted digest, with code
    /// [`ToolchainDiagnosticCode::ZeroLimitsRevision`] when the limits revision is zero, and
    /// with code [`ToolchainDiagnosticCode::InvalidDeclaredName`] when a feature name is not a
    /// legal declared name.
    // The declared inputs are the closed identity vocabulary of `GNT-26.8-cache-identity`, so
    // the constructor is kept explicit rather than collapsed into a builder that could omit an
    // input.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        source_digest: DeclaredDigest,
        manifest_digest: DeclaredDigest,
        features: &[&str],
        target_selection: TargetDescriptorDigest,
        dependency_interface_digests: &[DeclaredDigest],
        toolchain_identity: DeclaredDigest,
        limits_revision: u64,
        stage_configuration: StageConfiguration,
    ) -> Result<Self, CompilationError> {
        for (name, digest) in [
            ("source", &source_digest),
            ("manifest", &manifest_digest),
            ("toolchain identity", &toolchain_identity),
        ] {
            if is_omitted_digest(digest) {
                return Err(CompilationError::new(
                    ToolchainDiagnosticCode::IncompleteCacheKey,
                    format!("the {name} digest of the cache key is omitted"),
                ));
            }
        }
        for digest in dependency_interface_digests {
            if is_omitted_digest(digest) {
                return Err(CompilationError::new(
                    ToolchainDiagnosticCode::IncompleteCacheKey,
                    "a dependency interface digest of the cache key is omitted",
                ));
            }
        }
        if limits_revision == 0 {
            return Err(CompilationError::new(
                ToolchainDiagnosticCode::ZeroLimitsRevision,
                "a cache key declares a nonzero limits revision",
            ));
        }
        let mut feature_set = BTreeSet::new();
        for feature in features {
            if !is_declared_name(feature) {
                return Err(CompilationError::new(
                    ToolchainDiagnosticCode::InvalidDeclaredName,
                    format!("the declared feature `{feature}` is not a legal declared name"),
                ));
            }
            feature_set.insert(Arc::<str>::from(*feature));
        }
        let dependency_interface_digests = dependency_interface_digests
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        Ok(Self {
            source_digest,
            manifest_digest,
            features: feature_set.into_iter().collect(),
            target_selection,
            dependency_interface_digests,
            toolchain_identity,
            limits_revision,
            stage_configuration,
        })
    }

    /// Returns the declared source digest.
    #[must_use]
    pub const fn source_digest(&self) -> &DeclaredDigest {
        &self.source_digest
    }

    /// Returns the declared package-source manifest digest.
    #[must_use]
    pub const fn manifest_digest(&self) -> &DeclaredDigest {
        &self.manifest_digest
    }

    /// Returns the selected feature names in canonical order.
    #[must_use]
    pub fn features(&self) -> &[Arc<str>] {
        &self.features
    }

    /// Returns the declared target selection.
    #[must_use]
    pub const fn target_selection(&self) -> &TargetDescriptorDigest {
        &self.target_selection
    }

    /// Returns the dependency interface digests in canonical order.
    #[must_use]
    pub fn dependency_interface_digests(&self) -> &[DeclaredDigest] {
        &self.dependency_interface_digests
    }

    /// Returns the declared toolchain identity digest.
    #[must_use]
    pub const fn toolchain_identity(&self) -> &DeclaredDigest {
        &self.toolchain_identity
    }

    /// Returns the declared limits revision.
    #[must_use]
    pub const fn limits_revision(&self) -> u64 {
        self.limits_revision
    }

    /// Returns the declared stage configuration.
    #[must_use]
    pub const fn stage_configuration(&self) -> &StageConfiguration {
        &self.stage_configuration
    }
}

/// One canonical cache key over one declared identity input set (`GNT-26.8`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CacheKey {
    inputs: CacheKeyInputs,
    digest: DeclaredDigest,
}

impl CacheKey {
    /// Derives the one canonical key of one declared input set.
    ///
    /// Equal declared inputs derive equal keys and any changed declared input derives a
    /// different key, so a result is only ever reused under the identity it was computed for.
    #[must_use]
    pub fn derive(inputs: CacheKeyInputs) -> Self {
        let mut fields: Vec<&[u8]> = Vec::new();
        fields.push(inputs.source_digest().as_str().as_bytes());
        fields.push(inputs.manifest_digest().as_str().as_bytes());
        for feature in inputs.features() {
            fields.push(feature.as_bytes());
        }
        fields.push(inputs.target_selection().as_str().as_bytes());
        for digest in inputs.dependency_interface_digests() {
            fields.push(digest.as_str().as_bytes());
        }
        fields.push(inputs.toolchain_identity().as_str().as_bytes());
        let limits_revision = inputs.limits_revision().to_be_bytes();
        fields.push(&limits_revision);
        for stage in inputs.stage_configuration().stages() {
            fields.push(stage.wire_name().as_bytes());
        }
        let digest = declared_digest(CACHE_KEY_DOMAIN, &fields);
        Self { inputs, digest }
    }

    /// Returns the declared inputs this key covers.
    #[must_use]
    pub const fn inputs(&self) -> &CacheKeyInputs {
        &self.inputs
    }

    /// Returns the canonical digest of this key.
    #[must_use]
    pub const fn digest(&self) -> &DeclaredDigest {
        &self.digest
    }
}

/// The declared byte limit one cache entry is validated against (`GNT-26.9`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheLimits {
    maximum_entry_bytes: u64,
}

impl CacheLimits {
    /// Declares one cache byte limit.
    ///
    /// The nonzero requirement is declared model policy of
    /// `GNT-26.9-cache-validation-and-poisoning`: a zero limit admits no entry and decides no
    /// reuse verdict, so it is refused rather than treated as an unlimited cache.
    ///
    /// # Errors
    ///
    /// Returns [`CompilationError`] with code [`ToolchainDiagnosticCode::CacheLimitZero`] when
    /// the limit is zero, because a zero limit admits no entry and decides nothing.
    pub fn new(maximum_entry_bytes: u64) -> Result<Self, CompilationError> {
        if maximum_entry_bytes == 0 {
            return Err(CompilationError::new(
                ToolchainDiagnosticCode::CacheLimitZero,
                "the declared cache byte limit is zero",
            ));
        }
        Ok(Self {
            maximum_entry_bytes,
        })
    }

    /// Returns the declared maximum entry byte length.
    #[must_use]
    pub const fn maximum_entry_bytes(self) -> u64 {
        self.maximum_entry_bytes
    }
}

/// One closed reuse verdict for one cache entry (`GNT-26.9-cache-validation-and-poisoning`).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CacheValidation {
    /// `digest-mismatch` — the declared and observed digests differ.
    DigestMismatch,
    /// `malformed` — the entry does not decode as the declared canonical structure.
    Malformed,
    /// `oversized` — the entry exceeds the declared byte limit.
    Oversized,
    /// `poisoned` — the entry carries the irreversible poison latch.
    Poisoned,
    /// `stale` — a declared identity input differs from the reusing activity's.
    Stale,
    /// `valid` — every declared check passed and the entry may be reused.
    Valid,
}

impl CacheValidation {
    /// Every verdict of the closed vocabulary, in canonical wire-name order.
    pub const ALL: [Self; 6] = [
        Self::DigestMismatch,
        Self::Malformed,
        Self::Oversized,
        Self::Poisoned,
        Self::Stale,
        Self::Valid,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::DigestMismatch => "digest-mismatch",
            Self::Malformed => "malformed",
            Self::Oversized => "oversized",
            Self::Poisoned => "poisoned",
            Self::Stale => "stale",
            Self::Valid => "valid",
        }
    }

    /// Returns the same exact portable spelling as [`Self::wire_name`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.wire_name()
    }

    /// Strictly decodes one exact portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.wire_name() == value)
    }

    /// Returns whether this verdict admits reuse.
    #[must_use]
    pub const fn is_reusable(self) -> bool {
        matches!(self, Self::Valid)
    }

    /// Returns the refusal code of this verdict, or `None` for a reusable verdict.
    #[must_use]
    pub const fn refusal_code(self) -> Option<ToolchainDiagnosticCode> {
        match self {
            Self::DigestMismatch => Some(ToolchainDiagnosticCode::CacheEntryDigestMismatch),
            Self::Malformed => Some(ToolchainDiagnosticCode::CacheEntryMalformed),
            Self::Oversized => Some(ToolchainDiagnosticCode::CacheEntryOversized),
            Self::Poisoned => Some(ToolchainDiagnosticCode::CacheEntryPoisoned),
            Self::Stale => Some(ToolchainDiagnosticCode::CacheEntryStale),
            Self::Valid => None,
        }
    }

    /// Returns the clause anchor that owns this verdict.
    #[must_use]
    pub const fn requirement(self) -> &'static str {
        "GNT-26.9-cache-validation-and-poisoning"
    }
}

/// The declared observations one cache validation compares against one entry (`GNT-26.9`).
///
/// Every declared identity input of [`CacheKeyInputs`] is carried here, because a validation
/// that compared fewer inputs than the key declares would reuse an entry under an identity it
/// was not computed for. The feature set and the dependency interface digests are decoded into
/// canonical, sorted, deduplicated sets on construction, so the order they were declared in is
/// never part of the comparison.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CacheObservation {
    canonical_structure: bool,
    byte_length: u64,
    recorded_digest: DeclaredDigest,
    observed_digest: DeclaredDigest,
    source_digest: DeclaredDigest,
    manifest_digest: DeclaredDigest,
    features: Vec<Arc<str>>,
    target_selection: TargetDescriptorDigest,
    dependency_interface_digests: Vec<DeclaredDigest>,
    toolchain_identity: DeclaredDigest,
    limits_revision: u64,
    stage_configuration: StageConfiguration,
}

impl CacheObservation {
    /// Records one complete set of declared cache observations.
    // The observations are the closed comparison vocabulary of `GNT-26.9`, so the constructor
    // is kept explicit rather than collapsed into a builder that could omit an observation.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        canonical_structure: bool,
        byte_length: u64,
        recorded_digest: DeclaredDigest,
        observed_digest: DeclaredDigest,
        source_digest: DeclaredDigest,
        manifest_digest: DeclaredDigest,
        features: Vec<Arc<str>>,
        target_selection: TargetDescriptorDigest,
        dependency_interface_digests: Vec<DeclaredDigest>,
        toolchain_identity: DeclaredDigest,
        limits_revision: u64,
        stage_configuration: StageConfiguration,
    ) -> Self {
        Self {
            canonical_structure,
            byte_length,
            recorded_digest,
            observed_digest,
            source_digest,
            manifest_digest,
            features: features
                .into_iter()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
            target_selection,
            dependency_interface_digests: dependency_interface_digests
                .into_iter()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
            toolchain_identity,
            limits_revision,
            stage_configuration,
        }
    }

    /// Returns whether the entry decoded as the declared canonical structure.
    #[must_use]
    pub const fn is_canonical_structure(&self) -> bool {
        self.canonical_structure
    }

    /// Returns the observed entry byte length.
    #[must_use]
    pub const fn byte_length(&self) -> u64 {
        self.byte_length
    }

    /// Returns the digest the entry records.
    #[must_use]
    pub const fn recorded_digest(&self) -> &DeclaredDigest {
        &self.recorded_digest
    }

    /// Returns the digest observed over the presented entry bytes.
    #[must_use]
    pub const fn observed_digest(&self) -> &DeclaredDigest {
        &self.observed_digest
    }

    /// Returns the source digest the reusing activity declares.
    #[must_use]
    pub const fn source_digest(&self) -> &DeclaredDigest {
        &self.source_digest
    }

    /// Returns the manifest digest the reusing activity declares.
    #[must_use]
    pub const fn manifest_digest(&self) -> &DeclaredDigest {
        &self.manifest_digest
    }

    /// Returns the selected feature names the reusing activity declares, in canonical order.
    #[must_use]
    pub fn features(&self) -> &[Arc<str>] {
        &self.features
    }

    /// Returns the target selection the reusing activity declares.
    #[must_use]
    pub const fn target_selection(&self) -> &TargetDescriptorDigest {
        &self.target_selection
    }

    /// Returns the dependency interface digests the reusing activity declares, in canonical
    /// order.
    #[must_use]
    pub fn dependency_interface_digests(&self) -> &[DeclaredDigest] {
        &self.dependency_interface_digests
    }

    /// Returns the toolchain identity the reusing activity declares.
    #[must_use]
    pub const fn toolchain_identity(&self) -> &DeclaredDigest {
        &self.toolchain_identity
    }

    /// Returns the limits revision the reusing activity declares.
    #[must_use]
    pub const fn limits_revision(&self) -> u64 {
        self.limits_revision
    }

    /// Returns the stage configuration the reusing activity declares.
    #[must_use]
    pub const fn stage_configuration(&self) -> &StageConfiguration {
        &self.stage_configuration
    }

    /// Returns whether every declared identity input of this observation equals the one the
    /// reusing activity's key declares.
    ///
    /// All eight declared inputs of [`CacheKeyInputs`] are compared: the source digest, the
    /// manifest digest, the feature set, the target selection, the dependency interface digests,
    /// the toolchain identity, the limits revision, and the stage configuration. Any single
    /// difference makes the entry stale for this activity.
    #[must_use]
    pub fn matches_inputs(&self, inputs: &CacheKeyInputs) -> bool {
        self.source_digest == inputs.source_digest
            && self.manifest_digest == inputs.manifest_digest
            && self.features == inputs.features
            && self.target_selection == inputs.target_selection
            && self.dependency_interface_digests == inputs.dependency_interface_digests
            && self.toolchain_identity == inputs.toolchain_identity
            && self.limits_revision == inputs.limits_revision
            && self.stage_configuration == inputs.stage_configuration
    }
}

/// One cache entry under one key, with the irreversible poisoning latch (`GNT-26.9`).
///
/// The entry is not `Clone`: a copy would let an unpoisoned duplicate outlive the latch. Once
/// poisoned, the entry refuses reuse at every later validation and is only replaced by a new
/// entry published under a different key.
///
/// Every key this entry was ever poisoned under is retained for the lifetime of the entry, so a
/// replacement never republishes one of those keys: an `A -> B -> A` replacement refuses the
/// second `A` exactly as the first replacement of a poisoned `A` would. The retained keys belong
/// to this entry alone, so a fresh entry published under such a key is a different entry that
/// carries no latch and no retained key.
#[derive(Debug, Eq, PartialEq)]
pub struct CacheEntry {
    key: CacheKey,
    poisoned: bool,
    poisoned_keys: BTreeSet<DeclaredDigest>,
}

impl CacheEntry {
    /// Publishes one entry under one key.
    ///
    /// A fresh entry is not the poisoned entry that may have been published under the same key
    /// before it: it carries no latch and no retained poisoned key, and nothing here makes the
    /// declared identity inputs of another entry's poisoned key trusted again.
    #[must_use]
    pub const fn new(key: CacheKey) -> Self {
        Self {
            key,
            poisoned: false,
            poisoned_keys: BTreeSet::new(),
        }
    }

    /// Returns the key this entry was published under.
    #[must_use]
    pub const fn key(&self) -> &CacheKey {
        &self.key
    }

    /// Returns whether this entry carries the poison latch.
    #[must_use]
    pub const fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// Returns whether one key has ever been poisoned on this entry.
    ///
    /// A retained key is one this entry was poisoned under, so it MUST NOT become this entry's
    /// key again: the latch is irreversible for the entry, and no replacement republishes a
    /// retained key.
    #[must_use]
    pub fn refuses_key(&self, key: &CacheKey) -> bool {
        self.poisoned_keys.contains(&key.digest)
    }

    /// Latches poisoning irreversibly for the current key.
    ///
    /// The latch is set once and is never cleared by a later validation, a restart, a partial
    /// rewrite, or an elapsed period, so this method is idempotent and one-way. The key the entry
    /// is poisoned under is retained for the lifetime of the entry, so replacing the entry cannot
    /// republish that key.
    pub fn poison(&mut self) {
        self.poisoned = true;
        self.poisoned_keys.insert(self.key.digest.clone());
    }

    /// Validates this entry against the declared limits and observations.
    ///
    /// The verdict is total and exclusive over the closed vocabulary and is decided in one
    /// declared order: the poison latch, the canonical structure, the byte limit, the digest,
    /// every declared identity input of the entry's key, and then validity. The stale verdict
    /// compares all eight declared [`CacheKeyInputs`] inputs of the reuse request against the
    /// entry's key, so a changed feature set, target selection, dependency interface digest, or
    /// stage configuration is exactly as stale as a changed source digest.
    #[must_use]
    pub fn validate(
        &self,
        limits: &CacheLimits,
        observation: &CacheObservation,
    ) -> CacheValidation {
        if self.poisoned {
            return CacheValidation::Poisoned;
        }
        if !observation.canonical_structure {
            return CacheValidation::Malformed;
        }
        if observation.byte_length > limits.maximum_entry_bytes {
            return CacheValidation::Oversized;
        }
        if observation.recorded_digest != observation.observed_digest {
            return CacheValidation::DigestMismatch;
        }
        if !observation.matches_inputs(self.key.inputs()) {
            return CacheValidation::Stale;
        }
        CacheValidation::Valid
    }

    /// Validates this entry against one declared reuse request and mints its one admitted reuse.
    ///
    /// The validation is performed here rather than accepted from the caller, so a validated
    /// reuse is representable only for an entry this call reports valid: a stale, malformed,
    /// oversized, digest-mismatched, or poisoned entry cannot produce one, and no caller-supplied
    /// verdict can bypass the declared checks of `GNT-26.9`.
    ///
    /// # Errors
    ///
    /// Returns [`CompilationError`] with the refusal code of the verdict the declared checks
    /// decide, which is the code of the poison latch, the malformed structure, the byte limit,
    /// the digest, or the declared identity inputs.
    pub fn reuse(
        &self,
        limits: &CacheLimits,
        observation: &CacheObservation,
    ) -> Result<ValidatedReuse, CompilationError> {
        let verdict = self.validate(limits, observation);
        match verdict.refusal_code() {
            None => Ok(ValidatedReuse {
                key_digest: self.key.digest.clone(),
            }),
            Some(code) => Err(CompilationError::new(
                code,
                format!(
                    "the entry under key {} was not reused as `{}`",
                    self.key.digest,
                    verdict.wire_name()
                ),
            )),
        }
    }

    /// Replaces this entry under a new key.
    ///
    /// A replacement publishes the new key and clears the latch of this entry in one step, and a
    /// refusal leaves this entry, its key, and its retained poisoned keys exactly as they were.
    /// The keys this entry was ever poisoned under are never released: a replacement key drawn
    /// from that retained set is refused whether it is the current key or a key this entry was
    /// poisoned under before an earlier replacement, so an `A -> B -> A` replacement cannot
    /// republish the poisoned key `A`.
    ///
    /// # Errors
    ///
    /// Returns [`CompilationError`] with code
    /// [`ToolchainDiagnosticCode::PoisonedKeyReused`] when the replacement key is a key this
    /// entry was poisoned under, because the same declared identity inputs cannot be trusted
    /// again.
    pub fn replace(&mut self, replacement_key: CacheKey) -> Result<(), CompilationError> {
        if self.poisoned_keys.contains(&replacement_key.digest) {
            return Err(CompilationError::new(
                ToolchainDiagnosticCode::PoisonedKeyReused,
                format!(
                    "the poisoned key {} was presented for its own replacement",
                    self.key.digest
                ),
            ));
        }
        self.key = replacement_key;
        self.poisoned = false;
        Ok(())
    }
}

/// One admitted reuse of one cache entry (`GNT-26.10-clean-incremental-equivalence`).
///
/// The value exists only for an entry whose declared checks reported [`CacheValidation::Valid`],
/// and [`CacheEntry::reuse`] is the only way to mint one: validation is performed by the minting
/// call rather than supplied by the caller, so no bypass path admits a stale, malformed,
/// oversized, digest-mismatched, or poisoned entry into reuse.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedReuse {
    key_digest: DeclaredDigest,
}

impl ValidatedReuse {
    /// Returns the digest of the cache key whose entry was reported valid and reused.
    #[must_use]
    pub const fn key_digest(&self) -> &DeclaredDigest {
        &self.key_digest
    }

    /// Returns the clause anchor that owns this reuse.
    #[must_use]
    pub const fn requirement(&self) -> &'static str {
        "GNT-26.10-clean-incremental-equivalence"
    }
}

/// One build's canonical output (`GNT-26.10-clean-incremental-equivalence`).
///
/// The per-stage outputs are one canonical, sorted, deduplicated set, so the order in which
/// stages ran and the order in which cached and recomputed stages were mixed are not part of the
/// canonical output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalOutput {
    artifact: DeclaredDigest,
    authority: DeclaredDigest,
    stages: Vec<(ToolchainStage, DeclaredDigest)>,
}

impl CanonicalOutput {
    /// Declares one canonical output from one build's published digests.
    ///
    /// # Errors
    ///
    /// Returns [`CompilationError`] with code
    /// [`ToolchainDiagnosticCode::DuplicateStageOutput`] when one stage publishes two outputs,
    /// because one stage of one build publishes at most one output.
    pub fn new(
        artifact: DeclaredDigest,
        authority: DeclaredDigest,
        stages: &[(ToolchainStage, DeclaredDigest)],
    ) -> Result<Self, CompilationError> {
        let mut ordered: Vec<(ToolchainStage, DeclaredDigest)> = Vec::with_capacity(stages.len());
        for stage in ToolchainStage::ALL {
            let mut found = stages
                .iter()
                .filter(|(declared, _)| *declared == stage)
                .map(|(_, digest)| digest.clone());
            let Some(digest) = found.next() else {
                continue;
            };
            if found.next().is_some() {
                return Err(CompilationError::new(
                    ToolchainDiagnosticCode::DuplicateStageOutput,
                    format!("the `{}` stage published two outputs", stage.wire_name()),
                ));
            }
            ordered.push((stage, digest));
        }
        if ordered.len() != stages.len() {
            return Err(CompilationError::new(
                ToolchainDiagnosticCode::DuplicateStageOutput,
                "one stage published two outputs",
            ));
        }
        Ok(Self {
            artifact,
            authority,
            stages: ordered,
        })
    }

    /// Returns the published artifact digest.
    #[must_use]
    pub const fn artifact(&self) -> &DeclaredDigest {
        &self.artifact
    }

    /// Returns the published authority-closure digest.
    #[must_use]
    pub const fn authority(&self) -> &DeclaredDigest {
        &self.authority
    }

    /// Returns the per-stage output digests in canonical stage order.
    #[must_use]
    pub fn stages(&self) -> &[(ToolchainStage, DeclaredDigest)] {
        &self.stages
    }

    /// Returns the canonical encoding of this output.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for field in [self.artifact.as_str(), self.authority.as_str()] {
            bytes.extend_from_slice(&(field.len() as u64).to_be_bytes());
            bytes.extend_from_slice(field.as_bytes());
        }
        for (stage, digest) in &self.stages {
            let name = stage.wire_name();
            bytes.extend_from_slice(&(name.len() as u64).to_be_bytes());
            bytes.extend_from_slice(name.as_bytes());
            bytes.extend_from_slice(&(digest.as_str().len() as u64).to_be_bytes());
            bytes.extend_from_slice(digest.as_str().as_bytes());
        }
        bytes
    }

    /// Returns the digest over the canonical encoding of this output.
    #[must_use]
    pub fn digest(&self) -> DeclaredDigest {
        declared_digest(CANONICAL_OUTPUT_DOMAIN, &[&self.canonical_bytes()])
    }
}

/// Reports whether one clean and one incremental build published identical canonical output
/// (`GNT-26.10`).
///
/// # Errors
///
/// Returns [`CompilationError`] with code
/// [`ToolchainDiagnosticCode::CleanIncrementalDivergence`] when the two outputs differ, naming
/// the first differing stage in canonical order, the two compared outputs, and the differing
/// declared field, because a divergence MUST NOT be reported as equality, MUST NOT be resolved
/// by preferring one build, and MUST name both digests it compared rather than reporting a
/// divergence without them.
pub fn check_clean_incremental_equivalence(
    clean: &CanonicalOutput,
    incremental: &CanonicalOutput,
) -> Result<(), CompilationError> {
    let clean_digest = clean.digest();
    let incremental_digest = incremental.digest();
    if clean_digest == incremental_digest {
        return Ok(());
    }
    let compared = format!(
        "the clean output digest is {clean_digest} and the incremental output digest is {incremental_digest}"
    );
    for (stage, digest) in &clean.stages {
        match incremental.stages.iter().find(|(other, _)| other == stage) {
            Some((_, observed)) if observed == digest => {}
            Some((_, observed)) => {
                return Err(CompilationError::new(
                    ToolchainDiagnosticCode::CleanIncrementalDivergence,
                    format!(
                        "the `{}` stage published {digest} for the clean build and {observed} for the incremental build; {compared}",
                        stage.wire_name()
                    ),
                ));
            }
            None => {
                return Err(CompilationError::new(
                    ToolchainDiagnosticCode::CleanIncrementalDivergence,
                    format!(
                        "the `{}` stage published {digest} for the clean build and published nothing for the incremental build; {compared}",
                        stage.wire_name()
                    ),
                ));
            }
        }
    }
    for (stage, digest) in &incremental.stages {
        if !clean.stages.iter().any(|(other, _)| other == stage) {
            return Err(CompilationError::new(
                ToolchainDiagnosticCode::CleanIncrementalDivergence,
                format!(
                    "the `{}` stage published nothing for the clean build and {digest} for the incremental build; {compared}",
                    stage.wire_name()
                ),
            ));
        }
    }
    if clean.artifact() != incremental.artifact() {
        return Err(CompilationError::new(
            ToolchainDiagnosticCode::CleanIncrementalDivergence,
            format!(
                "the published artifact digest is {} for the clean build and {} for the incremental build; {compared}",
                clean.artifact(),
                incremental.artifact()
            ),
        ));
    }
    Err(CompilationError::new(
        ToolchainDiagnosticCode::CleanIncrementalDivergence,
        format!(
            "the published authority-closure digest is {} for the clean build and {} for the incremental build; {compared}",
            clean.authority(),
            incremental.authority()
        ),
    ))
}

/// One editor session that publishes analyzed facts under one generation
/// (`GNT-26.11-editor-work-fencing`).
///
/// A session is not `Clone`: superseding consumes it and yields its successor, so an obsolete
/// session keeps no capability to publish and stale publication is unrepresentable rather than
/// merely refused.
#[derive(Debug, Eq, PartialEq)]
pub struct EditorSession {
    generation: u64,
}

impl EditorSession {
    /// Declares one editor session under one generation.
    ///
    /// # Errors
    ///
    /// Returns [`CompilationError`] with code
    /// [`ToolchainDiagnosticCode::ZeroEditorGeneration`] when the generation is zero, because a
    /// session without a generation cannot fence obsolete work.
    pub fn new(generation: u64) -> Result<Self, CompilationError> {
        if generation == 0 {
            return Err(CompilationError::new(
                ToolchainDiagnosticCode::ZeroEditorGeneration,
                "an editor session declares a nonzero generation",
            ));
        }
        Ok(Self { generation })
    }

    /// Returns the generation this session publishes under.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Consumes this session into its successor generation.
    ///
    /// The successor is strictly newer, so the consumed session can never publish again and
    /// every work unit of the consumed generation is obsolete. The successor is computed with
    /// checked arithmetic and is never equal to the consumed generation, because `GNT-26.11`
    /// forbids reusing a generation: a generation at the numeric ceiling has no successor at all
    /// rather than a reused one.
    ///
    /// # Errors
    ///
    /// Returns [`CompilationError`] with code
    /// [`ToolchainDiagnosticCode::EditorGenerationExhausted`] when the current generation is
    /// greater than every other `u64` value, because no strictly newer generation exists and an
    /// equal successor would reuse a generation.
    pub fn supersede(self) -> Result<Self, CompilationError> {
        let Some(generation) = self.generation.checked_add(1) else {
            return Err(CompilationError::new(
                ToolchainDiagnosticCode::EditorGenerationExhausted,
                format!(
                    "the editor generation {} has no strictly newer successor",
                    self.generation
                ),
            ));
        };
        Ok(Self { generation })
    }

    /// Publishes one unit of editor work under this generation.
    ///
    /// # Errors
    ///
    /// Returns [`CompilationError`] with code
    /// [`ToolchainDiagnosticCode::StaleEditorGeneration`] when the work names another
    /// generation, whether older or newer, and the refusal publishes nothing.
    pub fn publish(&self, work: &EditorWork) -> Result<PublishedFacts, CompilationError> {
        if work.generation != self.generation {
            return Err(CompilationError::new(
                ToolchainDiagnosticCode::StaleEditorGeneration,
                format!(
                    "the work of generation {} cannot publish under generation {}",
                    work.generation, self.generation
                ),
            ));
        }
        Ok(PublishedFacts {
            generation: self.generation,
            facts_digest: work.facts_digest.clone(),
        })
    }
}

/// One unit of editor work declared under one generation (`GNT-26.11`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EditorWork {
    generation: u64,
    facts_digest: DeclaredDigest,
}

impl EditorWork {
    /// Declares one unit of editor work.
    #[must_use]
    pub const fn new(generation: u64, facts_digest: DeclaredDigest) -> Self {
        Self {
            generation,
            facts_digest,
        }
    }

    /// Returns the generation this work was produced under.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the declared digest of the facts this work installs.
    #[must_use]
    pub const fn facts_digest(&self) -> &DeclaredDigest {
        &self.facts_digest
    }
}

/// The facts one editor generation published (`GNT-26.11`).
///
/// A published value exists only for the session's own generation, so no fact of an obsolete
/// generation is ever observable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishedFacts {
    generation: u64,
    facts_digest: DeclaredDigest,
}

impl PublishedFacts {
    /// Returns the generation that published these facts.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the declared digest of these facts.
    #[must_use]
    pub const fn facts_digest(&self) -> &DeclaredDigest {
        &self.facts_digest
    }
}

/// One declared input of one generator invocation (`GNT-26.12-generator-confinement`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeclaredGeneratorInput {
    name: Arc<str>,
    digest: DeclaredDigest,
}

impl DeclaredGeneratorInput {
    /// Declares one generator input.
    ///
    /// # Errors
    ///
    /// Returns [`CompilationError`] with code [`ToolchainDiagnosticCode::InvalidDeclaredName`]
    /// when the name is empty or carries a control character.
    pub fn new(name: &str, digest: DeclaredDigest) -> Result<Self, CompilationError> {
        if !is_declared_name(name) {
            return Err(CompilationError::new(
                ToolchainDiagnosticCode::InvalidDeclaredName,
                format!("the declared generator input `{name}` is not a legal declared name"),
            ));
        }
        Ok(Self {
            name: Arc::from(name),
            digest,
        })
    }

    /// Returns the declared input name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the declared input digest.
    #[must_use]
    pub const fn digest(&self) -> &DeclaredDigest {
        &self.digest
    }
}

/// One declared output of one generator invocation (`GNT-26.12`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeclaredGeneratorOutput {
    name: Arc<str>,
    hash: GeneratedOutputHash,
}

impl DeclaredGeneratorOutput {
    /// Declares one generator output under the landed generated-output hash of
    /// `GNT-17.11-target-artifact-binding`.
    ///
    /// # Errors
    ///
    /// Returns [`CompilationError`] with code [`ToolchainDiagnosticCode::InvalidDeclaredName`]
    /// when the name is empty or carries a control character.
    pub fn new(name: &str, hash: GeneratedOutputHash) -> Result<Self, CompilationError> {
        if !is_declared_name(name) {
            return Err(CompilationError::new(
                ToolchainDiagnosticCode::InvalidDeclaredName,
                format!("the declared generator output `{name}` is not a legal declared name"),
            ));
        }
        Ok(Self {
            name: Arc::from(name),
            hash,
        })
    }

    /// Returns the declared output name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the declared output hash.
    #[must_use]
    pub const fn hash(&self) -> &GeneratedOutputHash {
        &self.hash
    }
}

/// One declared runner capability of `GNT-17.9-build-host-authority` (`GNT-26.12`).
///
/// The landed `RunnerCapability` is declared by a package instance, so this model records the same
/// declared capability by name without importing package identity: the only way to run a produced
/// executable during the build is to present one of these, and an absent one is refused rather than
/// inferred from the build host.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeclaredRunnerCapability {
    name: Arc<str>,
}

impl DeclaredRunnerCapability {
    /// Declares one runner capability by name.
    ///
    /// # Errors
    ///
    /// Returns [`CompilationError`] with code [`ToolchainDiagnosticCode::InvalidDeclaredName`]
    /// when the name is empty or carries a control character.
    pub fn new(name: &str) -> Result<Self, CompilationError> {
        if !is_declared_name(name) {
            return Err(CompilationError::new(
                ToolchainDiagnosticCode::InvalidDeclaredName,
                format!("the declared runner capability `{name}` is not a legal declared name"),
            ));
        }
        Ok(Self {
            name: Arc::from(name),
        })
    }

    /// Returns the declared capability name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the recorded build-input name of one admitted run.
    #[must_use]
    pub fn recorded_name(&self) -> String {
        format!("runner-capability:{}", self.name)
    }
}

/// One recorded build input of `GNT-17.9-build-host-authority` (`GNT-26.12`).
///
/// A build-host fact enters artifact identity only as an entry of this shape: one declared name
/// and one recorded digest, never a host path, a machine name, a user name, a locale, an
/// environment fact, a clock reading, a discovered service, or an installed-program name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordedBuildInput {
    name: Arc<str>,
    digest: DeclaredDigest,
}

impl RecordedBuildInput {
    /// Returns the recorded build-input name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the recorded build-input digest.
    #[must_use]
    pub const fn digest(&self) -> &DeclaredDigest {
        &self.digest
    }
}

/// The declared host capabilities, inputs, and outputs one generator invocation receives
/// (`GNT-26.12`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneratorGrant {
    capabilities: Vec<BuildHostCapability>,
    inputs: Vec<DeclaredGeneratorInput>,
    outputs: Vec<DeclaredGeneratorOutput>,
}

impl GeneratorGrant {
    /// Declares one generator grant.
    ///
    /// The granted capabilities are one canonical set of the closed build-host vocabulary, and
    /// the declared inputs and outputs are one canonical set ordered by declared name.
    ///
    /// # Errors
    ///
    /// Returns [`CompilationError`] with code
    /// [`ToolchainDiagnosticCode::EmptyGeneratorCapabilities`] when no build-host capability is
    /// granted, with code [`ToolchainDiagnosticCode::DuplicateGeneratorInput`] when one input name
    /// is declared twice, and with code
    /// [`ToolchainDiagnosticCode::DuplicateGeneratorOutput`] when one output name is declared
    /// twice.
    pub fn declare(
        capabilities: &[BuildHostCapability],
        inputs: &[DeclaredGeneratorInput],
        outputs: &[DeclaredGeneratorOutput],
    ) -> Result<Self, CompilationError> {
        let capabilities = BuildHostCapability::ALL
            .into_iter()
            .filter(|candidate| capabilities.contains(candidate))
            .collect::<Vec<_>>();
        if capabilities.is_empty() {
            return Err(CompilationError::new(
                ToolchainDiagnosticCode::EmptyGeneratorCapabilities,
                "a generator grant declares at least one build-host capability",
            ));
        }
        let mut ordered_inputs: Vec<DeclaredGeneratorInput> = Vec::with_capacity(inputs.len());
        for input in inputs {
            if ordered_inputs
                .iter()
                .any(|declared| declared.name() == input.name())
            {
                return Err(CompilationError::new(
                    ToolchainDiagnosticCode::DuplicateGeneratorInput,
                    format!("the generator input `{}` is declared twice", input.name()),
                ));
            }
            ordered_inputs.push(input.clone());
        }
        ordered_inputs.sort_by(|left, right| left.name.cmp(&right.name));
        let mut ordered_outputs: Vec<DeclaredGeneratorOutput> = Vec::with_capacity(outputs.len());
        for output in outputs {
            if ordered_outputs
                .iter()
                .any(|declared| declared.name() == output.name())
            {
                return Err(CompilationError::new(
                    ToolchainDiagnosticCode::DuplicateGeneratorOutput,
                    format!("the generator output `{}` is declared twice", output.name()),
                ));
            }
            ordered_outputs.push(output.clone());
        }
        ordered_outputs.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(Self {
            capabilities,
            inputs: ordered_inputs,
            outputs: ordered_outputs,
        })
    }

    /// Returns the granted build-host capabilities in vocabulary order.
    #[must_use]
    pub fn capabilities(&self) -> &[BuildHostCapability] {
        &self.capabilities
    }

    /// Returns the declared inputs in canonical name order.
    #[must_use]
    pub fn inputs(&self) -> &[DeclaredGeneratorInput] {
        &self.inputs
    }

    /// Returns the declared outputs in canonical name order.
    #[must_use]
    pub fn outputs(&self) -> &[DeclaredGeneratorOutput] {
        &self.outputs
    }

    /// Admits one declared build-host capability.
    ///
    /// # Errors
    ///
    /// Returns [`CompilationError`] with code
    /// [`ToolchainDiagnosticCode::UndeclaredGeneratorCapability`] when the capability is not
    /// granted, because an undeclared capability MUST NOT be exercised merely because the build
    /// host provides it.
    pub fn admit_capability(
        &self,
        capability: BuildHostCapability,
    ) -> Result<(), CompilationError> {
        if !self.capabilities.contains(&capability) {
            return Err(CompilationError::new(
                ToolchainDiagnosticCode::UndeclaredGeneratorCapability,
                format!(
                    "the build-host capability `{}` is not declared by the grant",
                    capability.wire_name()
                ),
            ));
        }
        Ok(())
    }

    /// Admits one declared generator input.
    ///
    /// # Errors
    ///
    /// Returns [`CompilationError`] with code
    /// [`ToolchainDiagnosticCode::UndeclaredGeneratorInput`] when the grant declares no such input
    /// with that digest, because an undeclared input MUST NOT be read.
    pub fn admit_input(&self, input: &DeclaredGeneratorInput) -> Result<(), CompilationError> {
        if !self
            .inputs
            .iter()
            .any(|declared| declared.name() == input.name() && declared.digest == input.digest)
        {
            return Err(CompilationError::new(
                ToolchainDiagnosticCode::UndeclaredGeneratorInput,
                format!(
                    "the generator input `{}` is not declared by the grant",
                    input.name()
                ),
            ));
        }
        Ok(())
    }

    /// Admits one declared generator output.
    ///
    /// # Errors
    ///
    /// Returns [`CompilationError`] with code
    /// [`ToolchainDiagnosticCode::UndeclaredGeneratorOutput`] when the grant declares no such
    /// output with that hash, because an undeclared output MUST NOT be written.
    pub fn admit_output(&self, output: &DeclaredGeneratorOutput) -> Result<(), CompilationError> {
        if !self
            .outputs
            .iter()
            .any(|declared| declared.name() == output.name() && declared.hash == output.hash)
        {
            return Err(CompilationError::new(
                ToolchainDiagnosticCode::UndeclaredGeneratorOutput,
                format!(
                    "the generator output `{}` is not declared by the grant",
                    output.name()
                ),
            ));
        }
        Ok(())
    }

    /// Refuses execution-target authority for this grant.
    ///
    /// # Errors
    ///
    /// Always returns [`CompilationError`] with code
    /// [`ToolchainDiagnosticCode::ExecutionTargetAuthorityRefused`], because a generator receives
    /// declared build-host authority and never execution-target authority under
    /// `GNT-17.9-build-host-authority`, and no conversion from a grant into target authority,
    /// execution rights, or a descriptor fact exists.
    pub fn admit_execution_target_authority(&self) -> Result<(), CompilationError> {
        Err(CompilationError::new(
            ToolchainDiagnosticCode::ExecutionTargetAuthorityRefused,
            "a generator grant never carries execution-target authority",
        ))
    }

    /// Refuses one ambient host capability presented by spelling.
    ///
    /// # Errors
    ///
    /// Always returns [`CompilationError`] with code
    /// [`ToolchainDiagnosticCode::AmbientAuthorityRefused`], because the only admissible
    /// capability route is [`Self::admit_capability`] over the closed build-host vocabulary, and a
    /// spelling outside that vocabulary is refused rather than widened into ambient authority.
    pub fn refuse_ambient_capability(&self, spelling: &str) -> Result<(), CompilationError> {
        Err(CompilationError::new(
            ToolchainDiagnosticCode::AmbientAuthorityRefused,
            format!("the presented capability `{spelling}` is not declared build-host authority"),
        ))
    }

    /// Runs one produced executable under one declared runner capability.
    ///
    /// # Errors
    ///
    /// Returns [`CompilationError`] with code
    /// [`ToolchainDiagnosticCode::RunnerCapabilityMissing`] when no runner capability is
    /// presented, because running a produced executable during the build is never implied by a
    /// granted build-host capability and is never inferred from the build host.
    pub fn run_produced_executable(
        &self,
        runner: Option<&DeclaredRunnerCapability>,
        run_digest: DeclaredDigest,
    ) -> Result<RecordedBuildInput, CompilationError> {
        let Some(capability) = runner else {
            return Err(CompilationError::new(
                ToolchainDiagnosticCode::RunnerCapabilityMissing,
                "a produced executable runs only under a declared runner capability",
            ));
        };
        Ok(RecordedBuildInput {
            name: Arc::from(capability.recorded_name()),
            digest: run_digest,
        })
    }

    /// Admits one run of one produced executable and records it as one build input.
    ///
    /// The recorded build input keeps the recorded name of the runner capability and the declared
    /// digests of the run, and the value carries the identity of this grant, so the run enters the
    /// artifact identity only through the fold of this grant. The declared run digest enters the
    /// recorded input unchanged: no host path, machine name, user name, locale, environment fact,
    /// clock reading, discovered service, or installed-program name is added.
    ///
    /// # Errors
    ///
    /// Returns [`CompilationError`] with code
    /// [`ToolchainDiagnosticCode::RunnerCapabilityMissing`] when no runner capability is
    /// presented, because running a produced executable during the build is never implied by a
    /// granted build-host capability and is never inferred from the build host.
    pub fn admit_run(
        &self,
        runner: Option<&DeclaredRunnerCapability>,
        run_digest: DeclaredDigest,
    ) -> Result<AdmittedGeneratorRun, CompilationError> {
        Ok(AdmittedGeneratorRun {
            grant_identity: self.identity(),
            input: self.run_produced_executable(runner, run_digest)?,
        })
    }

    /// Returns the identity of this grant over its declared capabilities, inputs, and outputs.
    ///
    /// The declared input digests and declared output hashes enter this identity, so a changed or
    /// added declared input or output changes the grant identity that enters the lockfile and the
    /// artifact identity of `GNT-17.11-target-artifact-binding`.
    #[must_use]
    pub fn identity(&self) -> DeclaredDigest {
        let mut fields: Vec<&[u8]> = Vec::new();
        for capability in &self.capabilities {
            fields.push(capability.wire_name().as_bytes());
        }
        for input in &self.inputs {
            fields.push(input.name.as_bytes());
            fields.push(input.digest.as_str().as_bytes());
        }
        for output in &self.outputs {
            fields.push(output.name.as_bytes());
            fields.push(output.hash.as_str().as_bytes());
        }
        declared_digest(GENERATOR_GRANT_DOMAIN, &fields)
    }
}

/// One admitted run of one produced executable, recorded as one build input of artifact identity
/// (`GNT-26.12-generator-confinement`).
///
/// Only [`GeneratorGrant::admit_run`] mints one, so the value carries the identity of the grant
/// that admitted the run together with the one recorded build input the run contributes. A run
/// that no grant admitted is therefore unrepresentable, and [`GeneratorIdentityFold::fold`]
/// refuses a run admitted by another grant rather than letting it enter this grant's identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedGeneratorRun {
    grant_identity: DeclaredDigest,
    input: RecordedBuildInput,
}

impl AdmittedGeneratorRun {
    /// Returns the identity of the grant that admitted this run.
    #[must_use]
    pub const fn grant_identity(&self) -> &DeclaredDigest {
        &self.grant_identity
    }

    /// Returns the recorded build input this run contributes to artifact identity.
    #[must_use]
    pub const fn input(&self) -> &RecordedBuildInput {
        &self.input
    }
}

/// The admitted generator runs one activity folds into artifact identity (`GNT-26.12`).
///
/// The fold is opened under one grant's identity and records one recorded build input per admitted
/// run in recorded-name order, so equal admitted runs under an equal grant derive an equal artifact
/// identity and the order the runs were folded in is never part of the identity. Folding is pure:
/// it reads no clock, no host path, and no environment fact.
#[derive(Debug, Eq, PartialEq)]
pub struct GeneratorIdentityFold {
    grant_identity: DeclaredDigest,
    folded: Vec<(Arc<str>, DeclaredDigest)>,
}

impl GeneratorIdentityFold {
    /// Opens one fold under the identity of one grant.
    #[must_use]
    pub fn open(grant: &GeneratorGrant) -> Self {
        Self {
            grant_identity: grant.identity(),
            folded: Vec::new(),
        }
    }

    /// Returns the grant identity this fold was opened under.
    #[must_use]
    pub const fn grant_identity(&self) -> &DeclaredDigest {
        &self.grant_identity
    }

    /// Returns the folded recorded build inputs in recorded-name order.
    #[must_use]
    pub fn inputs(&self) -> &[(Arc<str>, DeclaredDigest)] {
        &self.folded
    }

    /// Folds one admitted run into the artifact identity of this fold.
    ///
    /// The returned digest is the artifact identity over the grant identity and every recorded
    /// build input folded so far, in recorded-name order, so an admitted run enters artifact
    /// identity exactly once.
    ///
    /// # Errors
    ///
    /// Returns [`CompilationError`] with code
    /// [`ToolchainDiagnosticCode::UnadmittedGeneratorRun`] when the run was admitted under another
    /// grant identity, because a run the grant never admitted MUST NOT enter its artifact identity,
    /// and with code [`ToolchainDiagnosticCode::DuplicateRecordedBuildInput`] when the recorded
    /// build input of this run is already folded, which covers both folding the same run twice and
    /// folding a second run under the same recorded name, because an admitted run becomes one
    /// recorded build input and folding it twice would count one run twice.
    pub fn fold(&mut self, run: &AdmittedGeneratorRun) -> Result<DeclaredDigest, CompilationError> {
        if run.grant_identity != self.grant_identity {
            return Err(CompilationError::new(
                ToolchainDiagnosticCode::UnadmittedGeneratorRun,
                format!(
                    "the run recorded as `{}` was admitted by the grant {} and not by this grant",
                    run.input.name(),
                    run.grant_identity
                ),
            ));
        }
        let name = Arc::<str>::from(run.input.name());
        if self
            .folded
            .iter()
            .any(|(declared, _)| declared.as_ref() == name.as_ref())
        {
            return Err(CompilationError::new(
                ToolchainDiagnosticCode::DuplicateRecordedBuildInput,
                format!(
                    "the recorded build input `{}` is already folded into this artifact identity",
                    run.input.name()
                ),
            ));
        }
        let position = self
            .folded
            .iter()
            .position(|(declared, _)| declared.as_ref() > name.as_ref())
            .map_or(self.folded.len(), |position| position);
        self.folded
            .insert(position, (name, run.input.digest.clone()));
        let mut fields: Vec<&[u8]> = Vec::new();
        fields.push(self.grant_identity.as_str().as_bytes());
        for (name, digest) in &self.folded {
            fields.push(name.as_bytes());
            fields.push(digest.as_str().as_bytes());
        }
        Ok(declared_digest(GENERATOR_RUN_FOLD_DOMAIN, &fields))
    }
}

/// One closed toolchain component vocabulary (`GNT-26.13-toolchain-identity`).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ToolchainComponentKind {
    /// `cache-validator`
    CacheValidator,
    /// `diagnostic-renderer`
    DiagnosticRenderer,
    /// `documentation-generator`
    DocumentationGenerator,
    /// `generation-ingestor`
    GenerationIngestor,
    /// `instantiator`
    Instantiator,
    /// `linker`
    Linker,
    /// `name-resolver`
    NameResolver,
    /// `optimizer`
    Optimizer,
    /// `parser`
    Parser,
    /// `schema-constructor`
    SchemaConstructor,
    /// `trait-solver`
    TraitSolver,
    /// `type-effect-checker`
    TypeEffectChecker,
}

impl ToolchainComponentKind {
    /// Every kind of the closed vocabulary, in canonical wire-name order.
    pub const ALL: [Self; 12] = [
        Self::CacheValidator,
        Self::DiagnosticRenderer,
        Self::DocumentationGenerator,
        Self::GenerationIngestor,
        Self::Instantiator,
        Self::Linker,
        Self::NameResolver,
        Self::Optimizer,
        Self::Parser,
        Self::SchemaConstructor,
        Self::TraitSolver,
        Self::TypeEffectChecker,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::CacheValidator => "cache-validator",
            Self::DiagnosticRenderer => "diagnostic-renderer",
            Self::DocumentationGenerator => "documentation-generator",
            Self::GenerationIngestor => "generation-ingestor",
            Self::Instantiator => "instantiator",
            Self::Linker => "linker",
            Self::NameResolver => "name-resolver",
            Self::Optimizer => "optimizer",
            Self::Parser => "parser",
            Self::SchemaConstructor => "schema-constructor",
            Self::TraitSolver => "trait-solver",
            Self::TypeEffectChecker => "type-effect-checker",
        }
    }

    /// Returns the same exact portable spelling as [`Self::wire_name`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.wire_name()
    }

    /// Strictly decodes one exact portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.wire_name() == value)
    }
}

/// One declared toolchain component digest (`GNT-26.13`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolchainComponent {
    kind: ToolchainComponentKind,
    digest: DeclaredDigest,
}

impl ToolchainComponent {
    /// Declares one component digest.
    #[must_use]
    pub const fn new(kind: ToolchainComponentKind, digest: DeclaredDigest) -> Self {
        Self { kind, digest }
    }

    /// Returns the declared component kind.
    #[must_use]
    pub const fn kind(&self) -> ToolchainComponentKind {
        self.kind
    }

    /// Returns the declared component digest.
    #[must_use]
    pub const fn digest(&self) -> &DeclaredDigest {
        &self.digest
    }
}

/// The closed declared inputs of one toolchain identity (`GNT-26.13`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolchainIdentityInputs {
    version: u32,
    components: Vec<ToolchainComponent>,
    limits_revision: u64,
    target_descriptor: TargetDescriptorDigest,
}

impl ToolchainIdentityInputs {
    /// Declares one complete toolchain identity input set.
    ///
    /// The components are decoded into one canonical set in vocabulary order, so the declared
    /// order of the components is never part of the identity. The nonzero version, the nonempty
    /// component set, the at-most-once component kind, and the nonzero limits revision are
    /// declared model policy of `GNT-26.13-toolchain-identity`: an identity with no version, no
    /// component, a repeated component, or no limits revision is total over no declared input and
    /// so decides nothing.
    ///
    /// # Errors
    ///
    /// Returns [`CompilationError`] with code
    /// [`ToolchainDiagnosticCode::ZeroToolchainIdentityVersion`] for version zero, with code
    /// [`ToolchainDiagnosticCode::EmptyToolchainComponents`] when no component is declared, with
    /// code [`ToolchainDiagnosticCode::DuplicateToolchainComponent`] when one component kind is
    /// declared twice, and with code [`ToolchainDiagnosticCode::ZeroLimitsRevision`] when the
    /// limits revision is zero.
    pub fn new(
        version: u32,
        components: &[ToolchainComponent],
        limits_revision: u64,
        target_descriptor: TargetDescriptorDigest,
    ) -> Result<Self, CompilationError> {
        if version == 0 {
            return Err(CompilationError::new(
                ToolchainDiagnosticCode::ZeroToolchainIdentityVersion,
                "a toolchain identity declares a nonzero version",
            ));
        }
        if components.is_empty() {
            return Err(CompilationError::new(
                ToolchainDiagnosticCode::EmptyToolchainComponents,
                "a toolchain identity declares at least one component",
            ));
        }
        if limits_revision == 0 {
            return Err(CompilationError::new(
                ToolchainDiagnosticCode::ZeroLimitsRevision,
                "a toolchain identity declares a nonzero limits revision",
            ));
        }
        let mut ordered: Vec<ToolchainComponent> = Vec::with_capacity(components.len());
        for kind in ToolchainComponentKind::ALL {
            let mut found = components.iter().filter(|component| component.kind == kind);
            let Some(component) = found.next() else {
                continue;
            };
            if found.next().is_some() {
                return Err(CompilationError::new(
                    ToolchainDiagnosticCode::DuplicateToolchainComponent,
                    format!("the `{}` component is declared twice", kind.wire_name()),
                ));
            }
            ordered.push(component.clone());
        }
        Ok(Self {
            version,
            components: ordered,
            limits_revision,
            target_descriptor,
        })
    }

    /// Returns the declared identity version.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// Returns the declared components in canonical vocabulary order.
    #[must_use]
    pub fn components(&self) -> &[ToolchainComponent] {
        &self.components
    }

    /// Returns the declared limits revision.
    #[must_use]
    pub const fn limits_revision(&self) -> u64 {
        self.limits_revision
    }

    /// Returns the declared target descriptor digest.
    #[must_use]
    pub const fn target_descriptor(&self) -> &TargetDescriptorDigest {
        &self.target_descriptor
    }
}

/// One versioned canonical toolchain identity (`GNT-26.13`).
///
/// This type owns the content of the toolchain identity field that
/// `GNT-17.11-target-artifact-binding` binds opaquely. It lives in this module rather than at the
/// crate root because the landed opaque `target::ToolchainIdentity` already owns that name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolchainIdentity {
    version: u32,
    digest: DeclaredDigest,
}

impl ToolchainIdentity {
    /// Derives the one canonical identity of one declared input set.
    ///
    /// Equal declared component digests, an equal limits revision, an equal version, and an equal
    /// target descriptor digest derive an equal identity, and changing any one of them derives a
    /// different identity.
    #[must_use]
    pub fn derive(inputs: &ToolchainIdentityInputs) -> Self {
        let mut fields: Vec<&[u8]> = Vec::new();
        let version = inputs.version.to_be_bytes();
        fields.push(&version);
        for component in &inputs.components {
            fields.push(component.kind.wire_name().as_bytes());
            fields.push(component.digest.as_str().as_bytes());
        }
        let limits_revision = inputs.limits_revision.to_be_bytes();
        fields.push(&limits_revision);
        fields.push(inputs.target_descriptor.as_str().as_bytes());
        let digest = declared_digest(TOOLCHAIN_IDENTITY_DOMAIN, &fields);
        Self {
            version: inputs.version,
            digest,
        }
    }

    /// Returns the declared identity version.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// Returns the canonical digest of this identity.
    #[must_use]
    pub const fn digest(&self) -> &DeclaredDigest {
        &self.digest
    }

    /// Returns the exact lowercase hexadecimal spelling of this identity digest.
    #[must_use]
    pub fn digest_hex(&self) -> &str {
        self.digest.as_str()
    }
}

/// One closed compilation non-claim (`GNT-26.14-compilation-non-claims`).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CompilationNonClaim {
    /// `artifact-free-of-malice`
    ArtifactFreeOfMalice,
    /// `bounded-termination`
    BoundedTermination,
    /// `cache-reuse-semantics`
    CacheReuseSemantics,
    /// `cross-toolchain-equivalence`
    CrossToolchainEquivalence,
    /// `editor-freshness`
    EditorFreshness,
    /// `exhaustion-detection`
    ExhaustionDetection,
    /// `generator-sandbox-isolation`
    GeneratorSandboxIsolation,
    /// `publication-authority`
    PublicationAuthority,
}

impl CompilationNonClaim {
    /// Every non-claim of the closed vocabulary, in canonical wire-name order.
    pub const ALL: [Self; 8] = [
        Self::ArtifactFreeOfMalice,
        Self::BoundedTermination,
        Self::CacheReuseSemantics,
        Self::CrossToolchainEquivalence,
        Self::EditorFreshness,
        Self::ExhaustionDetection,
        Self::GeneratorSandboxIsolation,
        Self::PublicationAuthority,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::ArtifactFreeOfMalice => "artifact-free-of-malice",
            Self::BoundedTermination => "bounded-termination",
            Self::CacheReuseSemantics => "cache-reuse-semantics",
            Self::CrossToolchainEquivalence => "cross-toolchain-equivalence",
            Self::EditorFreshness => "editor-freshness",
            Self::ExhaustionDetection => "exhaustion-detection",
            Self::GeneratorSandboxIsolation => "generator-sandbox-isolation",
            Self::PublicationAuthority => "publication-authority",
        }
    }

    /// Returns the same exact portable spelling as [`Self::wire_name`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.wire_name()
    }

    /// Strictly decodes one exact portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.wire_name() == value)
    }

    /// Returns the frozen non-claim statement this member publishes.
    #[must_use]
    pub const fn statement(self) -> &'static str {
        match self {
            Self::ArtifactFreeOfMalice => COMPILATION_NON_CLAIMS[0],
            Self::BoundedTermination => COMPILATION_NON_CLAIMS[1],
            Self::CacheReuseSemantics => COMPILATION_NON_CLAIMS[2],
            Self::CrossToolchainEquivalence => COMPILATION_NON_CLAIMS[3],
            Self::EditorFreshness => COMPILATION_NON_CLAIMS[4],
            Self::ExhaustionDetection => COMPILATION_NON_CLAIMS[5],
            Self::GeneratorSandboxIsolation => COMPILATION_NON_CLAIMS[6],
            Self::PublicationAuthority => COMPILATION_NON_CLAIMS[7],
        }
    }

    /// Returns the clause anchor that owns this non-claim.
    #[must_use]
    pub const fn requirement(self) -> &'static str {
        "GNT-26.14-compilation-non-claims"
    }
}

/// The frozen compilation non-claims of `GNT-26.14-compilation-non-claims`, in declared order.
pub const COMPILATION_NON_CLAIMS: [&str; 8] = [
    "No freedom from malicious content: the loader validates the declared version, structure, references, limit, and digest and claims no property the artifact does not carry.",
    "No bounded termination: the section declares finite budgets and a fail-closed cutoff and makes no promise that any declared input set finishes inside them.",
    "No cache-reuse semantics beyond the declared checks: validation decides identity, structure, size, and digest and claims nothing further.",
    "No byte-identical output across toolchain identities or limits revisions: equivalence is compared only under the same declared inputs, toolchain identity, and limits revision.",
    "No editor freshness or latency: publication is fenced by generation and no schedule, clock, or latency bound is declared.",
    "No detection of exhaustion that cannot be safely reported: resident-memory, allocator, CPU-step, and wall-clock exhaustion remain the implementation-specific exhaustion failure of the landed frontend limits.",
    "No operating-system sandbox isolation: a generator is confined to declared capabilities, inputs, outputs, and hashes, and no kernel, container, or process-isolation property is claimed.",
    "No authority from completion evidence: completion evidence admits publication and grants no capability.",
];

/// The declared order of the compilation non-claims (`GNT-26.14`).
pub const COMPILATION_NON_CLAIM_ORDER: [CompilationNonClaim; 8] = CompilationNonClaim::ALL;

/// One presented non-claim assertion (`GNT-26.14`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompilationNonClaimAssertion {
    claim: CompilationNonClaim,
    presented_as_guarantee: bool,
}

impl CompilationNonClaimAssertion {
    /// Records whether one non-claim is presented as a guarantee.
    #[must_use]
    pub const fn new(claim: CompilationNonClaim, presented_as_guarantee: bool) -> Self {
        Self {
            claim,
            presented_as_guarantee,
        }
    }

    /// Returns the non-claim this assertion names.
    #[must_use]
    pub const fn claim(&self) -> CompilationNonClaim {
        self.claim
    }

    /// Returns whether this assertion presents the non-claim as a guarantee.
    #[must_use]
    pub const fn is_presented_as_guarantee(&self) -> bool {
        self.presented_as_guarantee
    }
}

/// Checks that no compilation non-claim is presented as a guarantee (`GNT-26.14`).
///
/// # Errors
///
/// Returns [`CompilationError`] with code [`ToolchainDiagnosticCode::NonClaimAsGuarantee`] for the
/// first assertion that presents a non-claim as a guarantee, because a non-claim MUST NOT be
/// presented as a guarantee.
pub fn check_compilation_non_claims(
    assertions: &[CompilationNonClaimAssertion],
) -> Result<(), CompilationError> {
    for assertion in assertions {
        if assertion.presented_as_guarantee {
            return Err(CompilationError::new(
                ToolchainDiagnosticCode::NonClaimAsGuarantee,
                format!(
                    "the non-claim `{}` was presented as a guarantee",
                    assertion.claim.wire_name()
                ),
            ));
        }
    }
    Ok(())
}

/// One frozen compilation diagnostic code, one code per condition of Section 26.
///
/// The registry is frozen: each condition of Section 26 owns exactly one code, each code is
/// anchored to exactly one clause through [`Self::requirement`], no condition is reported under
/// another condition's code, and the members are declared in sorted code order so [`Self::ALL`]
/// preserves that order.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ToolchainDiagnosticCode {
    /// `toolchain-absent-stage-limit`
    AbsentStageLimit,
    /// `toolchain-ambient-authority-refused`
    AmbientAuthorityRefused,
    /// `toolchain-artifact-digest-mismatch`
    ArtifactDigestMismatch,
    /// `toolchain-artifact-limit-exceeded`
    ArtifactLimitExceeded,
    /// `toolchain-artifact-reference-unknown`
    ArtifactReferenceUnknown,
    /// `toolchain-artifact-references-noncanonical`
    ArtifactReferencesNoncanonical,
    /// `toolchain-artifact-structure-malformed`
    ArtifactStructureMalformed,
    /// `toolchain-artifact-version-unsupported`
    ArtifactVersionUnsupported,
    /// `toolchain-budget-unexceeded`
    BudgetUnexceeded,
    /// `toolchain-cache-entry-digest-mismatch`
    CacheEntryDigestMismatch,
    /// `toolchain-cache-entry-malformed`
    CacheEntryMalformed,
    /// `toolchain-cache-entry-oversized`
    CacheEntryOversized,
    /// `toolchain-cache-entry-poisoned`
    CacheEntryPoisoned,
    /// `toolchain-cache-entry-stale`
    CacheEntryStale,
    /// `toolchain-cache-limit-zero`
    CacheLimitZero,
    /// `toolchain-cancellation-settlement-refused`
    CancellationSettlementRefused,
    /// `toolchain-clean-incremental-divergence`
    CleanIncrementalDivergence,
    /// `toolchain-declared-input-digest-differ`
    DeclaredInputDigestDiffer,
    /// `toolchain-duplicate-budget-unit`
    DuplicateBudgetUnit,
    /// `toolchain-duplicate-declared-input`
    DuplicateDeclaredInput,
    /// `toolchain-duplicate-generator-input`
    DuplicateGeneratorInput,
    /// `toolchain-duplicate-generator-output`
    DuplicateGeneratorOutput,
    /// `toolchain-duplicate-recorded-build-input`
    DuplicateRecordedBuildInput,
    /// `toolchain-duplicate-stage-budget`
    DuplicateStageBudget,
    /// `toolchain-duplicate-stage-output`
    DuplicateStageOutput,
    /// `toolchain-duplicate-toolchain-component`
    DuplicateToolchainComponent,
    /// `toolchain-editor-generation-exhausted`
    EditorGenerationExhausted,
    /// `toolchain-empty-generator-capabilities`
    EmptyGeneratorCapabilities,
    /// `toolchain-empty-input-inventory`
    EmptyInputInventory,
    /// `toolchain-empty-stage-budget`
    EmptyStageBudget,
    /// `toolchain-empty-stage-configuration`
    EmptyStageConfiguration,
    /// `toolchain-empty-toolchain-components`
    EmptyToolchainComponents,
    /// `toolchain-execution-target-authority-refused`
    ExecutionTargetAuthorityRefused,
    /// `toolchain-frontier-zero-depth`
    FrontierZeroDepth,
    /// `toolchain-inapplicable-stage-limit`
    InapplicableStageLimit,
    /// `toolchain-incomplete-cache-key`
    IncompleteCacheKey,
    /// `toolchain-invalid-declared-name`
    InvalidDeclaredName,
    /// `toolchain-invalid-digest-spelling`
    InvalidDigestSpelling,
    /// `toolchain-missing-completion-evidence`
    MissingCompletionEvidence,
    /// `toolchain-non-claim-as-guarantee`
    NonClaimAsGuarantee,
    /// `toolchain-noncanonical-budget-unit-order`
    NoncanonicalBudgetUnitOrder,
    /// `toolchain-noncanonical-input-order`
    NoncanonicalInputOrder,
    /// `toolchain-noncanonical-stage-budget-order`
    NoncanonicalStageBudgetOrder,
    /// `toolchain-poisoned-key-reused`
    PoisonedKeyReused,
    /// `toolchain-runner-capability-missing`
    RunnerCapabilityMissing,
    /// `toolchain-stage-already-run`
    StageAlreadyRun,
    /// `toolchain-stage-already-settled`
    StageAlreadySettled,
    /// `toolchain-stage-budget-unadmitted`
    StageBudgetUnadmitted,
    /// `toolchain-stage-charge-overflow`
    StageChargeOverflow,
    /// `toolchain-stage-cut-off`
    StageCutOff,
    /// `toolchain-stage-limit-too-large`
    StageLimitTooLarge,
    /// `toolchain-stale-editor-generation`
    StaleEditorGeneration,
    /// `toolchain-unadmitted-generator-run`
    UnadmittedGeneratorRun,
    /// `toolchain-undeclared-generator-capability`
    UndeclaredGeneratorCapability,
    /// `toolchain-undeclared-generator-input`
    UndeclaredGeneratorInput,
    /// `toolchain-undeclared-generator-output`
    UndeclaredGeneratorOutput,
    /// `toolchain-undeclared-untrusted-input`
    UndeclaredUntrustedInput,
    /// `toolchain-zero-editor-generation`
    ZeroEditorGeneration,
    /// `toolchain-zero-limits-revision`
    ZeroLimitsRevision,
    /// `toolchain-zero-loader-configuration`
    ZeroLoaderConfiguration,
    /// `toolchain-zero-stage-limit`
    ZeroStageLimit,
    /// `toolchain-zero-toolchain-identity-version`
    ZeroToolchainIdentityVersion,
}

impl ToolchainDiagnosticCode {
    /// Every frozen code, in sorted code order.
    pub const ALL: [Self; 62] = [
        Self::AbsentStageLimit,
        Self::AmbientAuthorityRefused,
        Self::ArtifactDigestMismatch,
        Self::ArtifactLimitExceeded,
        Self::ArtifactReferenceUnknown,
        Self::ArtifactReferencesNoncanonical,
        Self::ArtifactStructureMalformed,
        Self::ArtifactVersionUnsupported,
        Self::BudgetUnexceeded,
        Self::CacheEntryDigestMismatch,
        Self::CacheEntryMalformed,
        Self::CacheEntryOversized,
        Self::CacheEntryPoisoned,
        Self::CacheEntryStale,
        Self::CacheLimitZero,
        Self::CancellationSettlementRefused,
        Self::CleanIncrementalDivergence,
        Self::DeclaredInputDigestDiffer,
        Self::DuplicateBudgetUnit,
        Self::DuplicateDeclaredInput,
        Self::DuplicateGeneratorInput,
        Self::DuplicateGeneratorOutput,
        Self::DuplicateRecordedBuildInput,
        Self::DuplicateStageBudget,
        Self::DuplicateStageOutput,
        Self::DuplicateToolchainComponent,
        Self::EditorGenerationExhausted,
        Self::EmptyGeneratorCapabilities,
        Self::EmptyInputInventory,
        Self::EmptyStageBudget,
        Self::EmptyStageConfiguration,
        Self::EmptyToolchainComponents,
        Self::ExecutionTargetAuthorityRefused,
        Self::FrontierZeroDepth,
        Self::InapplicableStageLimit,
        Self::IncompleteCacheKey,
        Self::InvalidDeclaredName,
        Self::InvalidDigestSpelling,
        Self::MissingCompletionEvidence,
        Self::NonClaimAsGuarantee,
        Self::NoncanonicalBudgetUnitOrder,
        Self::NoncanonicalInputOrder,
        Self::NoncanonicalStageBudgetOrder,
        Self::PoisonedKeyReused,
        Self::RunnerCapabilityMissing,
        Self::StageAlreadyRun,
        Self::StageAlreadySettled,
        Self::StageBudgetUnadmitted,
        Self::StageChargeOverflow,
        Self::StageCutOff,
        Self::StageLimitTooLarge,
        Self::StaleEditorGeneration,
        Self::UnadmittedGeneratorRun,
        Self::UndeclaredGeneratorCapability,
        Self::UndeclaredGeneratorInput,
        Self::UndeclaredGeneratorOutput,
        Self::UndeclaredUntrustedInput,
        Self::ZeroEditorGeneration,
        Self::ZeroLimitsRevision,
        Self::ZeroLoaderConfiguration,
        Self::ZeroStageLimit,
        Self::ZeroToolchainIdentityVersion,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::AbsentStageLimit => "toolchain-absent-stage-limit",
            Self::AmbientAuthorityRefused => "toolchain-ambient-authority-refused",
            Self::ArtifactDigestMismatch => "toolchain-artifact-digest-mismatch",
            Self::ArtifactLimitExceeded => "toolchain-artifact-limit-exceeded",
            Self::ArtifactReferenceUnknown => "toolchain-artifact-reference-unknown",
            Self::ArtifactReferencesNoncanonical => "toolchain-artifact-references-noncanonical",
            Self::ArtifactStructureMalformed => "toolchain-artifact-structure-malformed",
            Self::ArtifactVersionUnsupported => "toolchain-artifact-version-unsupported",
            Self::BudgetUnexceeded => "toolchain-budget-unexceeded",
            Self::CacheEntryDigestMismatch => "toolchain-cache-entry-digest-mismatch",
            Self::CacheEntryMalformed => "toolchain-cache-entry-malformed",
            Self::CacheEntryOversized => "toolchain-cache-entry-oversized",
            Self::CacheEntryPoisoned => "toolchain-cache-entry-poisoned",
            Self::CacheEntryStale => "toolchain-cache-entry-stale",
            Self::CacheLimitZero => "toolchain-cache-limit-zero",
            Self::CancellationSettlementRefused => "toolchain-cancellation-settlement-refused",
            Self::CleanIncrementalDivergence => "toolchain-clean-incremental-divergence",
            Self::DeclaredInputDigestDiffer => "toolchain-declared-input-digest-differ",
            Self::DuplicateBudgetUnit => "toolchain-duplicate-budget-unit",
            Self::DuplicateDeclaredInput => "toolchain-duplicate-declared-input",
            Self::DuplicateGeneratorInput => "toolchain-duplicate-generator-input",
            Self::DuplicateGeneratorOutput => "toolchain-duplicate-generator-output",
            Self::DuplicateRecordedBuildInput => "toolchain-duplicate-recorded-build-input",
            Self::DuplicateStageBudget => "toolchain-duplicate-stage-budget",
            Self::DuplicateStageOutput => "toolchain-duplicate-stage-output",
            Self::DuplicateToolchainComponent => "toolchain-duplicate-toolchain-component",
            Self::EditorGenerationExhausted => "toolchain-editor-generation-exhausted",
            Self::EmptyGeneratorCapabilities => "toolchain-empty-generator-capabilities",
            Self::EmptyInputInventory => "toolchain-empty-input-inventory",
            Self::EmptyStageBudget => "toolchain-empty-stage-budget",
            Self::EmptyStageConfiguration => "toolchain-empty-stage-configuration",
            Self::EmptyToolchainComponents => "toolchain-empty-toolchain-components",
            Self::ExecutionTargetAuthorityRefused => "toolchain-execution-target-authority-refused",
            Self::FrontierZeroDepth => "toolchain-frontier-zero-depth",
            Self::InapplicableStageLimit => "toolchain-inapplicable-stage-limit",
            Self::IncompleteCacheKey => "toolchain-incomplete-cache-key",
            Self::InvalidDeclaredName => "toolchain-invalid-declared-name",
            Self::InvalidDigestSpelling => "toolchain-invalid-digest-spelling",
            Self::MissingCompletionEvidence => "toolchain-missing-completion-evidence",
            Self::NonClaimAsGuarantee => "toolchain-non-claim-as-guarantee",
            Self::NoncanonicalBudgetUnitOrder => "toolchain-noncanonical-budget-unit-order",
            Self::NoncanonicalInputOrder => "toolchain-noncanonical-input-order",
            Self::NoncanonicalStageBudgetOrder => "toolchain-noncanonical-stage-budget-order",
            Self::PoisonedKeyReused => "toolchain-poisoned-key-reused",
            Self::RunnerCapabilityMissing => "toolchain-runner-capability-missing",
            Self::StageAlreadyRun => "toolchain-stage-already-run",
            Self::StageAlreadySettled => "toolchain-stage-already-settled",
            Self::StageBudgetUnadmitted => "toolchain-stage-budget-unadmitted",
            Self::StageChargeOverflow => "toolchain-stage-charge-overflow",
            Self::StageCutOff => "toolchain-stage-cut-off",
            Self::StageLimitTooLarge => "toolchain-stage-limit-too-large",
            Self::StaleEditorGeneration => "toolchain-stale-editor-generation",
            Self::UnadmittedGeneratorRun => "toolchain-unadmitted-generator-run",
            Self::UndeclaredGeneratorCapability => "toolchain-undeclared-generator-capability",
            Self::UndeclaredGeneratorInput => "toolchain-undeclared-generator-input",
            Self::UndeclaredGeneratorOutput => "toolchain-undeclared-generator-output",
            Self::UndeclaredUntrustedInput => "toolchain-undeclared-untrusted-input",
            Self::ZeroEditorGeneration => "toolchain-zero-editor-generation",
            Self::ZeroLimitsRevision => "toolchain-zero-limits-revision",
            Self::ZeroLoaderConfiguration => "toolchain-zero-loader-configuration",
            Self::ZeroStageLimit => "toolchain-zero-stage-limit",
            Self::ZeroToolchainIdentityVersion => "toolchain-zero-toolchain-identity-version",
        }
    }

    /// Returns the same exact portable spelling as [`Self::wire_name`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.wire_name()
    }

    /// Strictly decodes one exact portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.wire_name() == value)
    }

    /// Returns the clause anchor that owns this condition.
    #[must_use]
    pub const fn requirement(self) -> &'static str {
        match self {
            Self::AbsentStageLimit
            | Self::BudgetUnexceeded
            | Self::DuplicateBudgetUnit
            | Self::DuplicateStageBudget
            | Self::EmptyStageBudget
            | Self::NoncanonicalBudgetUnitOrder
            | Self::NoncanonicalStageBudgetOrder
            | Self::StageAlreadyRun
            | Self::StageBudgetUnadmitted
            | Self::StageChargeOverflow
            | Self::StageCutOff
            | Self::StageLimitTooLarge
            | Self::ZeroLimitsRevision
            | Self::ZeroStageLimit => "GNT-26.3-finite-stage-budgets-and-fail-closed-cutoff",
            Self::DeclaredInputDigestDiffer
            | Self::DuplicateDeclaredInput
            | Self::EmptyInputInventory
            | Self::InvalidDeclaredName
            | Self::InvalidDigestSpelling
            | Self::NoncanonicalInputOrder
            | Self::UndeclaredUntrustedInput => "GNT-26.1-untrusted-input-inventory",
            Self::InapplicableStageLimit => "GNT-26.2-stage-and-unit-vocabulary",
            Self::FrontierZeroDepth => "GNT-26.4-structural-expansion-bounds",
            Self::MissingCompletionEvidence => {
                "GNT-26.5-completion-evidence-and-atomic-publication"
            }
            Self::CancellationSettlementRefused | Self::StageAlreadySettled => {
                "GNT-26.6-cancellation-settlement"
            }
            Self::ArtifactDigestMismatch
            | Self::ArtifactLimitExceeded
            | Self::ArtifactReferenceUnknown
            | Self::ArtifactReferencesNoncanonical
            | Self::ArtifactStructureMalformed
            | Self::ArtifactVersionUnsupported
            | Self::ZeroLoaderConfiguration => "GNT-26.7-artifact-loader-validation",
            Self::EmptyStageConfiguration | Self::IncompleteCacheKey => "GNT-26.8-cache-identity",
            Self::CacheEntryDigestMismatch
            | Self::CacheEntryMalformed
            | Self::CacheEntryOversized
            | Self::CacheEntryPoisoned
            | Self::CacheEntryStale
            | Self::CacheLimitZero
            | Self::PoisonedKeyReused => "GNT-26.9-cache-validation-and-poisoning",
            Self::CleanIncrementalDivergence | Self::DuplicateStageOutput => {
                "GNT-26.10-clean-incremental-equivalence"
            }
            Self::EditorGenerationExhausted
            | Self::StaleEditorGeneration
            | Self::ZeroEditorGeneration => "GNT-26.11-editor-work-fencing",
            Self::AmbientAuthorityRefused
            | Self::DuplicateGeneratorInput
            | Self::DuplicateGeneratorOutput
            | Self::DuplicateRecordedBuildInput
            | Self::EmptyGeneratorCapabilities
            | Self::ExecutionTargetAuthorityRefused
            | Self::RunnerCapabilityMissing
            | Self::UnadmittedGeneratorRun
            | Self::UndeclaredGeneratorCapability
            | Self::UndeclaredGeneratorInput
            | Self::UndeclaredGeneratorOutput => "GNT-26.12-generator-confinement",
            Self::DuplicateToolchainComponent
            | Self::EmptyToolchainComponents
            | Self::ZeroToolchainIdentityVersion => "GNT-26.13-toolchain-identity",
            Self::NonClaimAsGuarantee => "GNT-26.14-compilation-non-claims",
        }
    }
}

/// One typed refusal of this model, attributed to the clause that owns it.
///
/// The code is frozen, the owning clause is derived from the code, and the detail names only
/// declared values, so a refusal is machine-usable without parsing its text and never carries a
/// host path, an environment fact, a locale, a clock reading, or a protected payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompilationError {
    code: ToolchainDiagnosticCode,
    requirement: &'static str,
    detail: Arc<str>,
}

impl CompilationError {
    /// Constructs one refusal attributed to the code's owning clause.
    pub(crate) fn new(code: ToolchainDiagnosticCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            requirement: code.requirement(),
            detail: Arc::from(detail.into()),
        }
    }

    /// Returns the frozen code of this refusal.
    #[must_use]
    pub const fn code(&self) -> ToolchainDiagnosticCode {
        self.code
    }

    /// Returns the clause anchor that owns this refusal.
    #[must_use]
    pub const fn requirement(&self) -> &'static str {
        self.requirement
    }

    /// Returns the declared-value detail of this refusal.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl fmt::Display for CompilationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code.as_str(), self.detail)
    }
}

impl std::error::Error for CompilationError {}

#[cfg(test)]
mod tests {
    use super::{
        BudgetUnit, MAXIMUM_STAGE_LIMIT, StageBudget, StageProgress, StageRun,
        ToolchainDiagnosticCode, ToolchainStage,
    };

    /// Returns one stage budget that declares one limit for every unit the stage charges.
    fn declared_budget(stage: ToolchainStage, limit: u64) -> StageBudget {
        let declared = stage
            .applicable_units()
            .iter()
            .map(|unit| (*unit, limit))
            .collect::<Vec<_>>();
        match StageBudget::new(stage, &declared) {
            Ok(budget) => budget,
            Err(error) => panic!("the declared limits of the stage are valid: {error}"),
        }
    }

    /// `GNT-26.3-finite-stage-budgets-and-fail-closed-cutoff` requires every charge arithmetic of a
    /// stage run to be checked. A run that already recorded `u64::MAX` charges has no further
    /// representable charge, so the next within-budget charge is refused with a typed refusal
    /// instead of wrapping to zero, which would let a run that observed the ceiling continue with an
    /// empty count. The greatest declared limit, `2^63 - 1` per unit, keeps the ceiling out of reach
    /// of any run assembled from declared limits alone, so this boundary case is decided here rather
    /// than through the public lane.
    #[test]
    fn a_charge_at_the_numeric_ceiling_is_refused_rather_than_wrapped() {
        let run = StageRun {
            stage: ToolchainStage::Parse,
            budget: declared_budget(ToolchainStage::Parse, 8),
            limits_revision: 1,
            charges: u64::MAX,
        };
        assert_eq!(run.charges(), u64::MAX);
        match run.check(BudgetUnit::Work, 1) {
            StageProgress::Refused(error) => {
                assert_eq!(error.code(), ToolchainDiagnosticCode::StageChargeOverflow);
                assert_eq!(
                    error.requirement(),
                    "GNT-26.3-finite-stage-budgets-and-fail-closed-cutoff"
                );
            }
            StageProgress::WithinBudget(_) => {
                panic!("the charge at the numeric ceiling is refused, not wrapped")
            }
            StageProgress::CutOff(cutoff) => {
                panic!("a charge within its declared limit is not cut off: {cutoff:?}")
            }
        }

        let at_the_greatest_limit = StageRun {
            stage: ToolchainStage::Parse,
            budget: declared_budget(ToolchainStage::Parse, MAXIMUM_STAGE_LIMIT),
            limits_revision: 1,
            charges: MAXIMUM_STAGE_LIMIT,
        };
        assert!(
            matches!(
                at_the_greatest_limit.check(BudgetUnit::Work, u64::MAX),
                StageProgress::CutOff(_)
            ),
            "a charge beyond the greatest declared limit is still cut off rather than refused"
        );
    }
}
