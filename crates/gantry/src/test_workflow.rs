//! Experimental `gantry test` workflow over the landed `std.test` harness.
//!
//! This module owns the first tooling workflow of `GNT-GP-TOOLING-RUNTIME-001`: one bounded,
//! zero-authority unit run of the package entry that the public analysis already derives. It is an
//! experimental, non-shipping workflow. It does not claim Section 16 multi-package target support,
//! compile-fail/property/benchmark/replay/durable-recovery/substitution support, editor work, or
//! any live I/O. Ordinary `Interpreter` execution defaults are unchanged.
//!
//! # Boundaries
//!
//! * The target program comes from public source analysis ([`AnalyzePackageResult`]), never from a
//!   retained-program loader, a test-name scan, a new source annotation, or a mutation of the
//!   shipping-entry interface.
//! * Exactly one declared run plan is admitted: kind `unit`, no substitutions. A kind or
//!   substitution the caller declares outside that plan is refused rather than dropped.
//! * Preflight runs before any analysis dispatch. A refused invocation publishes a structured
//!   refusal and executes no frontend stage.
//! * The workflow requires empty effects, empty operation and live-resource inventories, and an
//!   empty authority ceiling. Each is checked and published; a non-empty inventory is an admission
//!   refusal, not a warning.
//! * Frontend input, frontend stages, and diagnostics are bounded by declared policy units
//!   ([`BudgetUnit`]) separately from the runtime step bound (`--max-transitions`). Step exhaustion
//!   is not a wall-clock timeout, and no external interrupt or host cleanup support is claimed.
//!
//! # Report
//!
//! One versioned report carries the observed identities, the declared policy, the ordered target
//! results, and at most one structured refusal. It carries no source text, diagnostic message, or
//! other payload, and the reference CLI enforces a 1 MiB encoded ceiling before it writes a byte.

use std::path::Path;
use std::sync::Arc;

use gantry_core::mode::SemanticMode;
use gantry_core::portable::{IdentityKind, ProtocolFamily};
use gantry_core::protocol::{ProtocolSelection, ProtocolVersion};
use gantry_core::source::{FrontendLimits, StructuredDiagnostic};
use gantry_core::value::DEFAULT_VALUE_LIMITS;
use gantry_host::contracts::{
    BlockingWorkService, FreshIdentityAllocator, IdentitySource, UtcClock,
};

use crate::ir::toolchain::BudgetUnit;
use crate::ir::{
    AbiEnvironment, Architecture, ExecutionTargetDescriptor, InstructionKind, MachineProgram,
    OperatingSystemFamily, OperationKind, TestKind, TestRunPlan, TestSubstitution, TypeDescriptor,
    declare_test_run,
};
use crate::runtime::{
    MachineBuildError, MachineFailure, MachineLimits, TestHarness, TestHarnessRefusal,
    TestHarnessStop, TestTargetOutcome,
};

use crate::{AnalyzePackageCoordinator, AnalyzePackageRequest, AnalyzePackageStatus};

/// Published report format spelling of this workflow.
pub const TEST_WORKFLOW_REPORT_FORMAT: &str = "gantry.test-workflow/v1";

/// Published report format version.
pub const TEST_WORKFLOW_REPORT_VERSION: u32 = 1;

/// Published policy revision of this workflow.
pub const TEST_WORKFLOW_POLICY_REVISION: u64 = 1;

/// The only job cardinality this workflow declares.
pub const TEST_WORKFLOW_JOBS: u64 = 1;

/// Encoded report ceiling in bytes, owned by the workflow contract rather than by a caller.
pub const TEST_WORKFLOW_OUTPUT_CEILING_BYTES: usize = 1_048_576;

/// The declared `std.test` contract version this workflow executes under.
pub const TEST_WORKFLOW_STDLIB_CONTRACT: ProtocolVersion = ProtocolVersion { major: 1, minor: 0 };

/// Declared language-edition label of the published target descriptor.
pub const TEST_WORKFLOW_LANGUAGE_EDITION: &str = "gantry-v1";

/// Declared toolchain identity of the published facade build.
pub const TEST_WORKFLOW_TOOLCHAIN_IDENTITY: &str = concat!("gantry/", env!("CARGO_PKG_VERSION"));

/// Number of separately bounded frontend stages one complete test run performs.
///
/// Stage one is package syntax; stage two is semantic analysis. A policy that declares a smaller
/// stage bound cannot admit a test run, because the workflow refuses rather than dropping the
/// analysis stage.
pub const TEST_WORKFLOW_FRONTEND_STAGES: u64 = 2;

/// Fixed workflow call-depth ceiling of the admitted machine program.
const MAXIMUM_WORKFLOW_CALL_DEPTH: u64 = 256;

/// Fixed cooperative-yield quantum of the admitted machine program.
const DETERMINISTIC_TRANSITION_YIELD_QUANTUM: u64 = 64;

/// Fixed package-file ceiling of the derived frontend policy.
const FRONTEND_PACKAGE_FILES: u64 = 4_096;

/// Fixed artifact-byte ceiling of the derived frontend policy.
const FRONTEND_ARTIFACT_BYTES: u64 = 67_108_864;

/// Fixed constructed-type-depth ceiling of the derived frontend policy.
const FRONTEND_CONSTRUCTED_TYPE_DEPTH: u64 = 4_096;

/// Fixed generic-instantiation ceiling of the derived frontend policy.
const FRONTEND_GENERIC_INSTANTIATIONS: u64 = 65_536;

/// Fixed trait-resolution ceiling of the derived frontend policy.
const FRONTEND_TRAIT_RESOLUTION_STEPS: u64 = 65_536;

/// Requirement anchor of the first tooling workflow decision.
const REQUIREMENT_WORKFLOW: &str = "D7-first-tooling-workflow";

/// Requirement anchor of the landed `std.test` contract.
const REQUIREMENT_STD_TEST: &str = "GNT-GP-TEST-001";

/// One declared policy bound in one toolchain budget unit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TestPolicyBound {
    unit: BudgetUnit,
    limit: u64,
}

impl TestPolicyBound {
    /// Declares one bound of one unit.
    ///
    /// # Errors
    ///
    /// Returns [`TestWorkflowPolicyError::ZeroBound`] when the limit is zero, because a zero bound
    /// declares no usable ceiling.
    pub fn new(unit: BudgetUnit, limit: u64) -> Result<Self, TestWorkflowPolicyError> {
        if limit == 0 {
            return Err(TestWorkflowPolicyError::ZeroBound { unit });
        }
        Ok(Self { unit, limit })
    }

    /// Returns the declared unit.
    #[must_use]
    pub const fn unit(self) -> BudgetUnit {
        self.unit
    }

    /// Returns the declared finite limit.
    #[must_use]
    pub const fn limit(self) -> u64 {
        self.limit
    }
}

/// Why one declared test-workflow policy was refused before admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TestWorkflowPolicyError {
    /// The declared revision is zero, so the policy declares no contract revision.
    ZeroRevision,
    /// The declared job cardinality is not [`TEST_WORKFLOW_JOBS`].
    NonSingleJobs {
        /// Declared job cardinality.
        declared: u64,
    },
    /// The declared runtime step bound is zero.
    ZeroTransitionBound,
    /// The declared input bound does not use [`BudgetUnit::Bytes`].
    WrongInputUnit {
        /// Declared unit.
        declared: BudgetUnit,
    },
    /// The declared stage bound does not use [`BudgetUnit::Count`].
    WrongStageUnit {
        /// Declared unit.
        declared: BudgetUnit,
    },
    /// The declared diagnostics bound does not use [`BudgetUnit::Count`].
    WrongDiagnosticUnit {
        /// Declared unit.
        declared: BudgetUnit,
    },
    /// One declared bound is zero, so it bounds nothing.
    ZeroBound {
        /// Declared unit.
        unit: BudgetUnit,
    },
    /// The bounds derive no valid finite frontend policy.
    FrontendPolicy,
}

impl TestWorkflowPolicyError {
    /// Returns the stable refusal code of this policy error.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ZeroRevision => "undefined-policy-revision",
            Self::NonSingleJobs { .. } => "unsupported-job-cardinality",
            Self::ZeroTransitionBound => "undefined-transition-bound",
            Self::WrongInputUnit { .. } => "invalid-input-bound-unit",
            Self::WrongStageUnit { .. } => "invalid-stage-bound-unit",
            Self::WrongDiagnosticUnit { .. } => "invalid-diagnostic-bound-unit",
            Self::ZeroBound { .. } => "undefined-policy-bound",
            Self::FrontendPolicy => "invalid-frontend-policy",
        }
    }
}

/// The declared policy of one experimental unit test workflow.
///
/// Frontend input, frontend stages, and diagnostics are three separate declared bounds in the
/// closed [`BudgetUnit`] vocabulary. The runtime step bound is a fourth, independently declared
/// number. The output ceiling is fixed by the contract and cannot be raised by a caller.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TestWorkflowPolicy {
    revision: u64,
    jobs: u64,
    input: TestPolicyBound,
    stages: TestPolicyBound,
    diagnostics: TestPolicyBound,
    maximum_transitions: u64,
    frontend_limits: FrontendLimits,
}

impl TestWorkflowPolicy {
    /// Declares one complete test-workflow policy.
    ///
    /// # Errors
    ///
    /// Returns a [`TestWorkflowPolicyError`] when the revision is zero, the job cardinality is not
    /// [`TEST_WORKFLOW_JOBS`], the step bound is zero, a declared unit is not the unit its bound
    /// owns, a declared limit is zero, or the declared input and diagnostics bounds derive no valid
    /// finite frontend policy.
    pub fn new(
        revision: u64,
        jobs: u64,
        input: TestPolicyBound,
        stages: TestPolicyBound,
        diagnostics: TestPolicyBound,
        maximum_transitions: u64,
    ) -> Result<Self, TestWorkflowPolicyError> {
        if revision == 0 {
            return Err(TestWorkflowPolicyError::ZeroRevision);
        }
        if jobs != TEST_WORKFLOW_JOBS {
            return Err(TestWorkflowPolicyError::NonSingleJobs { declared: jobs });
        }
        if maximum_transitions == 0 {
            return Err(TestWorkflowPolicyError::ZeroTransitionBound);
        }
        if input.unit() != BudgetUnit::Bytes {
            return Err(TestWorkflowPolicyError::WrongInputUnit {
                declared: input.unit(),
            });
        }
        if stages.unit() != BudgetUnit::Count {
            return Err(TestWorkflowPolicyError::WrongStageUnit {
                declared: stages.unit(),
            });
        }
        if diagnostics.unit() != BudgetUnit::Count {
            return Err(TestWorkflowPolicyError::WrongDiagnosticUnit {
                declared: diagnostics.unit(),
            });
        }
        let frontend_limits = FrontendLimits::new(
            FRONTEND_PACKAGE_FILES,
            input.limit(),
            input.limit(),
            input.limit(),
            diagnostics.limit(),
            FRONTEND_ARTIFACT_BYTES,
            FRONTEND_ARTIFACT_BYTES,
            FRONTEND_ARTIFACT_BYTES,
            FRONTEND_ARTIFACT_BYTES,
            FRONTEND_CONSTRUCTED_TYPE_DEPTH,
            FRONTEND_GENERIC_INSTANTIATIONS,
            FRONTEND_TRAIT_RESOLUTION_STEPS,
        )
        .map_err(|_| TestWorkflowPolicyError::FrontendPolicy)?;
        Ok(Self {
            revision,
            jobs,
            input,
            stages,
            diagnostics,
            maximum_transitions,
            frontend_limits,
        })
    }

    /// Declares the published policy revision with the three declared bounds.
    ///
    /// # Errors
    ///
    /// Returns the same refusals as [`Self::new`] with the published revision.
    pub fn published(
        input: TestPolicyBound,
        stages: TestPolicyBound,
        diagnostics: TestPolicyBound,
        maximum_transitions: u64,
    ) -> Result<Self, TestWorkflowPolicyError> {
        Self::new(
            TEST_WORKFLOW_POLICY_REVISION,
            TEST_WORKFLOW_JOBS,
            input,
            stages,
            diagnostics,
            maximum_transitions,
        )
    }

    /// Returns the declared policy revision.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Returns the declared job cardinality.
    #[must_use]
    pub const fn jobs(&self) -> u64 {
        self.jobs
    }

    /// Returns the declared frontend input bound.
    #[must_use]
    pub const fn input(&self) -> TestPolicyBound {
        self.input
    }

    /// Returns the declared frontend stage bound.
    #[must_use]
    pub const fn stages(&self) -> TestPolicyBound {
        self.stages
    }

    /// Returns the declared diagnostics bound.
    #[must_use]
    pub const fn diagnostics(&self) -> TestPolicyBound {
        self.diagnostics
    }

    /// Returns the declared runtime step bound.
    #[must_use]
    pub const fn maximum_transitions(&self) -> u64 {
        self.maximum_transitions
    }

    /// Returns the finite frontend policy derived from the declared bounds.
    #[must_use]
    pub const fn frontend_limits(&self) -> FrontendLimits {
        self.frontend_limits
    }

    /// Returns the encoded report ceiling fixed by the workflow contract.
    #[must_use]
    pub const fn output_ceiling_bytes(&self) -> usize {
        TEST_WORKFLOW_OUTPUT_CEILING_BYTES
    }
}

/// Frozen identity facts one declared workflow expectation carries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TestWorkflowIdentity {
    source_language: ProtocolVersion,
    specification_revision: Arc<str>,
    profile_revision: Arc<str>,
    semantic_mode: SemanticMode,
    features: TestWorkflowFeatures,
    target: ExecutionTargetDescriptor,
    stdlib_contract: ProtocolVersion,
    toolchain: Arc<str>,
}

/// Compile-time facade features reported by one identity record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TestWorkflowFeatures {
    /// Whether the frontend layer is compiled.
    pub frontend: bool,
    /// Whether the analyzer layer is compiled.
    pub analyzer: bool,
    /// Whether the evaluator layer is compiled.
    pub evaluator: bool,
    /// Whether the concurrent refinement is compiled.
    pub concurrent: bool,
    /// Whether the durable refinement is compiled.
    pub durable: bool,
}

impl TestWorkflowFeatures {
    /// Returns whether every layer this workflow requires is compiled.
    #[must_use]
    pub const fn supports_workflow(self) -> bool {
        self.frontend && self.analyzer && self.evaluator
    }
}

impl From<crate::CompiledFeatures> for TestWorkflowFeatures {
    fn from(features: crate::CompiledFeatures) -> Self {
        Self {
            frontend: features.frontend,
            analyzer: features.analyzer,
            evaluator: features.evaluator,
            concurrent: features.concurrent,
            durable: features.durable,
        }
    }
}

/// Why one observed identity record cannot support the workflow.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TestWorkflowIdentityError {
    /// The selected source language is not version 1.0.
    UnsupportedSourceLanguage {
        /// Selected major version.
        major: u64,
        /// Selected minor version.
        minor: u64,
    },
    /// The selected specification revision is not the published revision.
    UnsupportedSpecificationRevision,
    /// The compiled profile revision has not been requalified against the published revision.
    StaleProfileRevision,
    /// The published target descriptor is not supported by this host identity.
    UnsupportedTarget,
    /// The compiled facade does not provide the layers this workflow requires.
    UnsupportedFeatures,
}

impl TestWorkflowIdentityError {
    /// Returns the stable refusal code of this identity error.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::UnsupportedSourceLanguage { .. } => "unsupported-source-language",
            Self::UnsupportedSpecificationRevision => "unsupported-specification-revision",
            Self::StaleProfileRevision => "stale-profile-revision",
            Self::UnsupportedTarget => "unsupported-target",
            Self::UnsupportedFeatures => "unsupported-facade-features",
        }
    }
}

impl TestWorkflowIdentity {
    /// Observes the identities this build and selection fix, without reading any host state.
    ///
    /// # Errors
    ///
    /// Returns a [`TestWorkflowIdentityError`] when the selected source language is not version
    /// 1.0, the selected specification revision is not the published revision, the compiled profile
    /// revision is not current, the published target descriptor is unsupported on this host, or the
    /// compiled facade omits a layer the workflow requires.
    pub fn observed(
        protocol_selection: &ProtocolSelection,
        toolchain: &str,
    ) -> Result<Self, TestWorkflowIdentityError> {
        let source_language = protocol_selection.version(ProtocolFamily::SourceLanguage);
        if (source_language.major, source_language.minor) != (1, 0) {
            return Err(TestWorkflowIdentityError::UnsupportedSourceLanguage {
                major: source_language.major,
                minor: source_language.minor,
            });
        }
        if protocol_selection.specification_revision()
            != crate::portable::PORTABLE_SPECIFICATION_REVISION
        {
            return Err(TestWorkflowIdentityError::UnsupportedSpecificationRevision);
        }
        if crate::PROFILE_SPECIFICATION_REVISION != crate::portable::PORTABLE_SPECIFICATION_REVISION
        {
            return Err(TestWorkflowIdentityError::StaleProfileRevision);
        }
        let features = TestWorkflowFeatures::from(crate::compiled_features());
        if !features.supports_workflow() {
            return Err(TestWorkflowIdentityError::UnsupportedFeatures);
        }
        Ok(Self {
            source_language,
            specification_revision: Arc::from(protocol_selection.specification_revision()),
            profile_revision: Arc::from(crate::PROFILE_SPECIFICATION_REVISION),
            semantic_mode: SemanticMode::Portable,
            features,
            target: published_target_descriptor()?,
            stdlib_contract: TEST_WORKFLOW_STDLIB_CONTRACT,
            toolchain: Arc::from(toolchain),
        })
    }

    /// Returns the selected source-language version.
    #[must_use]
    pub const fn source_language(&self) -> ProtocolVersion {
        self.source_language
    }

    /// Returns the selected specification revision digest.
    #[must_use]
    pub fn specification_revision(&self) -> &str {
        &self.specification_revision
    }

    /// Returns the compiled profile revision digest.
    #[must_use]
    pub fn profile_revision(&self) -> &str {
        &self.profile_revision
    }

    /// Returns the semantic mode fixed before analysis.
    #[must_use]
    pub const fn semantic_mode(&self) -> SemanticMode {
        self.semantic_mode
    }

    /// Returns the compiled facade features.
    #[must_use]
    pub const fn features(&self) -> TestWorkflowFeatures {
        self.features
    }

    /// Returns the published target descriptor.
    #[must_use]
    pub const fn target(&self) -> &ExecutionTargetDescriptor {
        &self.target
    }

    /// Returns the declared standard-library contract version.
    #[must_use]
    pub const fn stdlib_contract(&self) -> ProtocolVersion {
        self.stdlib_contract
    }

    /// Returns the caller-declared toolchain identity.
    #[must_use]
    pub fn toolchain(&self) -> &str {
        &self.toolchain
    }

    /// Returns the first identity field this record and another record disagree on.
    fn disagreement(&self, observed: &Self) -> Option<&'static str> {
        if self.source_language != observed.source_language {
            return Some("source-language");
        }
        if self.specification_revision != observed.specification_revision {
            return Some("specification-revision");
        }
        if self.profile_revision != observed.profile_revision {
            return Some("profile-revision");
        }
        if self.semantic_mode != observed.semantic_mode {
            return Some("semantic-mode");
        }
        if self.features != observed.features {
            return Some("features");
        }
        if self.target != observed.target {
            return Some("target");
        }
        if self.stdlib_contract != observed.stdlib_contract {
            return Some("stdlib-contract");
        }
        if self.toolchain != observed.toolchain {
            return Some("toolchain");
        }
        None
    }
}

/// Derives the published target descriptor from compile-time host facts only.
fn published_target_descriptor() -> Result<ExecutionTargetDescriptor, TestWorkflowIdentityError> {
    let architecture = Architecture::from_wire_name(std::env::consts::ARCH)
        .ok_or(TestWorkflowIdentityError::UnsupportedTarget)?;
    let operating_system = OperatingSystemFamily::from_wire_name(std::env::consts::OS)
        .ok_or(TestWorkflowIdentityError::UnsupportedTarget)?;
    ExecutionTargetDescriptor::new(
        architecture,
        operating_system,
        published_abi_environment(),
        TEST_WORKFLOW_LANGUAGE_EDITION,
        TEST_WORKFLOW_STDLIB_CONTRACT,
        SemanticMode::Portable,
    )
    .map_err(|_| TestWorkflowIdentityError::UnsupportedTarget)
}

/// Returns the declared ABI environment of this build.
const fn published_abi_environment() -> AbiEnvironment {
    if cfg!(target_env = "gnu") {
        AbiEnvironment::Gnu
    } else if cfg!(target_env = "musl") {
        AbiEnvironment::Musl
    } else if cfg!(target_env = "msvc") {
        AbiEnvironment::Msvc
    } else {
        AbiEnvironment::Sysv
    }
}

/// The declared inputs of one test workflow invocation.
///
/// Every collection is a declaration the caller presents: an unknown or unsupported member is
/// refused during preflight and is never silently dropped.
#[derive(Clone, Copy, Debug)]
pub struct TestWorkflowDeclarations<'a> {
    /// The single declared test kind spelling.
    pub kind: &'a str,
    /// The declared deterministic substitution spellings.
    pub substitutions: &'a [&'a str],
    /// The declared registry input spellings.
    pub registry_inputs: &'a [&'a str],
    /// The declared authority input spellings.
    pub authority_inputs: &'a [&'a str],
    /// The declared external-artifact input spellings.
    pub external_artifacts: &'a [&'a str],
}

impl TestWorkflowDeclarations<'_> {
    /// Returns declarations that admit exactly one unit target and no other input.
    #[must_use]
    pub const fn unit() -> TestWorkflowDeclarations<'static> {
        TestWorkflowDeclarations {
            kind: "unit",
            substitutions: &[],
            registry_inputs: &[],
            authority_inputs: &[],
            external_artifacts: &[],
        }
    }
}

/// The host services one test workflow requires.
#[derive(Clone, Copy)]
pub struct TestWorkflowServices<'a> {
    /// Fresh protocol-identity allocator.
    pub allocator: &'a FreshIdentityAllocator,
    /// Executor-neutral fresh identity source.
    pub identity_source: &'a dyn IdentitySource,
    /// Executor-neutral UTC clock used only for package activity settlement.
    pub clock: &'a dyn UtcClock,
    /// Executor-neutral blocking work service used by the frontend.
    pub blocking: &'a dyn BlockingWorkService,
}

/// One test workflow request.
pub struct TestWorkflowRequest<'a> {
    /// Package directory containing `main.gnt`.
    pub package_root: &'a Path,
    /// Exact complete protocol tuple selected for the activity.
    pub protocol_selection: &'a ProtocolSelection,
    /// Identity facts the caller expects the workflow to preflight against.
    pub expected_identity: &'a TestWorkflowIdentity,
    /// Declared bounded policy.
    pub policy: &'a TestWorkflowPolicy,
    /// Declared workflow inputs.
    pub declarations: TestWorkflowDeclarations<'a>,
}

/// One frontend, admission, or execution stage that produced a refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TestWorkflowStage {
    /// Declared-input and identity admission, before any analysis dispatch.
    Preflight,
    /// Package syntax and semantic analysis.
    Analysis,
    /// Target admission over the analyzed program and declared inventories.
    Admission,
    /// Bounded machine execution of the admitted target.
    Execution,
    /// Report publication.
    Output,
}

impl TestWorkflowStage {
    /// Returns the exact stable wire spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Preflight => "preflight",
            Self::Analysis => "analysis",
            Self::Admission => "admission",
            Self::Execution => "execution",
            Self::Output => "output",
        }
    }
}

/// One structured, payload-free refusal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TestWorkflowRefusal {
    stage: TestWorkflowStage,
    code: &'static str,
    requirement: &'static str,
    detail: Option<&'static str>,
}

impl TestWorkflowRefusal {
    /// Constructs one refusal from stable identifiers only.
    fn new(
        stage: TestWorkflowStage,
        code: &'static str,
        requirement: &'static str,
        detail: Option<&'static str>,
    ) -> Self {
        Self {
            stage,
            code,
            requirement,
            detail,
        }
    }

    /// Returns the stage that refused.
    #[must_use]
    pub const fn stage(&self) -> TestWorkflowStage {
        self.stage
    }

    /// Returns the stable refusal code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    /// Returns the requirement anchor that owns the refusal.
    #[must_use]
    pub const fn requirement(&self) -> &'static str {
        self.requirement
    }

    /// Returns an optional stable detail spelling, never a caller or source payload.
    #[must_use]
    pub const fn detail(&self) -> Option<&'static str> {
        self.detail
    }
}

/// One structured source span of a report diagnostic.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TestWorkflowSpan {
    path: Arc<str>,
    start: u64,
    end: u64,
}

impl TestWorkflowSpan {
    /// Returns the authored package-relative source path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the inclusive start byte offset.
    #[must_use]
    pub const fn start(&self) -> u64 {
        self.start
    }

    /// Returns the exclusive end byte offset.
    #[must_use]
    pub const fn end(&self) -> u64 {
        self.end
    }
}

/// One payload-free structured diagnostic in a report.
///
/// The workflow publishes diagnostic identity and location, never the message or the repair fields,
/// so a report cannot leak source text or captured values.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TestWorkflowDiagnostic {
    phase: &'static str,
    severity: &'static str,
    category: &'static str,
    code: Arc<str>,
    primary: Option<TestWorkflowSpan>,
}

impl TestWorkflowDiagnostic {
    /// Returns the production phase spelling.
    #[must_use]
    pub const fn phase(&self) -> &'static str {
        self.phase
    }

    /// Returns the severity spelling.
    #[must_use]
    pub const fn severity(&self) -> &'static str {
        self.severity
    }

    /// Returns the category spelling.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        self.category
    }

    /// Returns the stable diagnostic code.
    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }

    /// Returns the primary span when the diagnostic is source-backed.
    #[must_use]
    pub const fn primary(&self) -> Option<&TestWorkflowSpan> {
        self.primary.as_ref()
    }

    /// Projects one structured diagnostic without its message or repair fields.
    fn from_structured(diagnostic: &StructuredDiagnostic) -> Self {
        Self {
            phase: diagnostic.phase.wire_name(),
            severity: diagnostic.severity.wire_name(),
            category: diagnostic.category.wire_name(),
            code: Arc::from(diagnostic.code.as_str()),
            primary: diagnostic.primary.as_ref().map(|primary| TestWorkflowSpan {
                path: Arc::from(primary.source().to_string()),
                start: primary.bytes().start(),
                end: primary.bytes().end(),
            }),
        }
    }
}

/// The ordered outcome class of one admitted target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TestWorkflowTargetClassification {
    /// The machine fixed a successful outcome.
    Completed,
    /// The machine fixed a structured task-local failure.
    Failed,
    /// The target reached a state the harness cannot drive.
    Undriveable,
    /// The target reached the declared step bound without a fixed outcome.
    StepBoundExhausted,
    /// The target fixed a cancellation outcome.
    Cancelled,
}

impl TestWorkflowTargetClassification {
    /// Returns the exact stable wire spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Undriveable => "undriveable",
            Self::StepBoundExhausted => "step-bound-exhausted",
            Self::Cancelled => "cancelled",
        }
    }
}

/// The structured machine failure a failed target fixed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TestWorkflowFailure {
    code: Arc<str>,
    workflow: Arc<str>,
    site: Vec<u64>,
}

impl TestWorkflowFailure {
    /// Returns the stable runtime failure code.
    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }

    /// Returns the canonical workflow active at failure.
    #[must_use]
    pub fn workflow(&self) -> &str {
        &self.workflow
    }

    /// Returns the canonical structural site active at failure.
    #[must_use]
    pub fn site(&self) -> &[u64] {
        &self.site
    }

    /// Projects one machine failure into the report vocabulary.
    fn from_machine(failure: &MachineFailure) -> Self {
        Self {
            code: Arc::from(failure.code.wire_name()),
            workflow: Arc::from(failure.workflow.as_str()),
            site: failure.site.components().to_vec(),
        }
    }
}

/// One ordered target result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TestWorkflowTargetResult {
    name: Arc<str>,
    classification: TestWorkflowTargetClassification,
    steps: u64,
    failure: Option<TestWorkflowFailure>,
    cancellation_reason: Option<Arc<str>>,
    stop: Option<&'static str>,
    bound: Option<u64>,
}

impl TestWorkflowTargetResult {
    /// Returns the declared target name in canonical discovery order.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the outcome class.
    #[must_use]
    pub const fn classification(&self) -> TestWorkflowTargetClassification {
        self.classification
    }

    /// Returns the labelled transitions the harness observed.
    #[must_use]
    pub const fn steps(&self) -> u64 {
        self.steps
    }

    /// Returns the structured machine failure of a failed target.
    #[must_use]
    pub const fn failure(&self) -> Option<&TestWorkflowFailure> {
        self.failure.as_ref()
    }

    /// Returns the first cancellation reason of a cancelled target.
    #[must_use]
    pub fn cancellation_reason(&self) -> Option<&str> {
        self.cancellation_reason.as_deref()
    }

    /// Returns the stable stop spelling of an undriveable target.
    #[must_use]
    pub const fn stop(&self) -> Option<&'static str> {
        self.stop
    }

    /// Returns the declared step bound of an exhausted target.
    #[must_use]
    pub const fn bound(&self) -> Option<u64> {
        self.bound
    }

    /// Projects one harness target outcome into the report vocabulary.
    fn from_outcome(name: &str, outcome: &TestTargetOutcome) -> Self {
        let mut result = Self {
            name: Arc::from(name),
            classification: TestWorkflowTargetClassification::Completed,
            steps: 0,
            failure: None,
            cancellation_reason: None,
            stop: None,
            bound: None,
        };
        match outcome {
            TestTargetOutcome::Completed { steps } => {
                result.classification = TestWorkflowTargetClassification::Completed;
                result.steps = *steps;
            }
            TestTargetOutcome::Failed { steps, failure } => {
                result.classification = TestWorkflowTargetClassification::Failed;
                result.steps = *steps;
                result.failure = Some(TestWorkflowFailure::from_machine(failure));
            }
            TestTargetOutcome::Undriveable { steps, stop } => {
                result.classification = TestWorkflowTargetClassification::Undriveable;
                result.steps = *steps;
                result.stop = Some(match stop {
                    TestHarnessStop::HostDispatchPending => "host-dispatch-pending",
                    TestHarnessStop::ChildSessionPending => "child-session-pending",
                });
            }
            TestTargetOutcome::StepBoundExhausted { steps, bound } => {
                result.classification = TestWorkflowTargetClassification::StepBoundExhausted;
                result.steps = *steps;
                result.bound = Some(*bound);
            }
            TestTargetOutcome::Cancelled { steps, reason } => {
                result.classification = TestWorkflowTargetClassification::Cancelled;
                result.steps = *steps;
                result.cancellation_reason = Some(Arc::clone(reason));
            }
        }
        result
    }
}

/// The declared and admitted run-plan selection of one report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TestWorkflowSelection {
    kind: TestKind,
    substitutions: Vec<TestSubstitution>,
    jobs: u64,
    entry: Option<Arc<str>>,
}

impl TestWorkflowSelection {
    /// Returns the declared test kind.
    #[must_use]
    pub const fn kind(&self) -> TestKind {
        self.kind
    }

    /// Returns the declared substitutions in canonical declaration order.
    #[must_use]
    pub fn substitutions(&self) -> &[TestSubstitution] {
        &self.substitutions
    }

    /// Returns the declared job cardinality.
    #[must_use]
    pub const fn jobs(&self) -> u64 {
        self.jobs
    }

    /// Returns the admitted package entry path, when admission succeeded.
    #[must_use]
    pub fn entry(&self) -> Option<&str> {
        self.entry.as_deref()
    }
}

/// The observed emptiness of the inventories one admission requires to be empty.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TestWorkflowInventory {
    effects: u64,
    operations: u64,
    live_resources: u64,
    authority_ceiling_empty: bool,
}

impl TestWorkflowInventory {
    /// Returns the observed effect count of the reachable program.
    #[must_use]
    pub const fn effects(&self) -> u64 {
        self.effects
    }

    /// Returns the observed operation-site count of the reachable program.
    #[must_use]
    pub const fn operations(&self) -> u64 {
        self.operations
    }

    /// Returns the observed live-resource site count of the reachable program.
    #[must_use]
    pub const fn live_resources(&self) -> u64 {
        self.live_resources
    }

    /// Returns whether the observed authority ceiling is empty.
    #[must_use]
    pub const fn authority_ceiling_empty(&self) -> bool {
        self.authority_ceiling_empty
    }
}

/// The observed bounded source package of one report.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TestWorkflowPackage {
    files: u64,
    bytes: u64,
}

impl TestWorkflowPackage {
    /// Returns the observed package source file count.
    #[must_use]
    pub const fn files(&self) -> u64 {
        self.files
    }

    /// Returns the observed package source byte count.
    #[must_use]
    pub const fn bytes(&self) -> u64 {
        self.bytes
    }
}

/// The complete judgment of one test workflow invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TestWorkflowStatus {
    /// Every admitted target completed.
    Clean,
    /// The admitted target fixed a structured test failure.
    TestFailed,
    /// The package source is invalid.
    SourceInvalid,
    /// The package declares no admissible unit entry.
    NoTests,
    /// A declared input, identity, or admission was refused.
    Refused,
    /// The admitted target reached the declared step bound with no fixed outcome.
    Exhausted,
    /// The admitted target fixed a cancellation outcome.
    Cancelled,
    /// Analysis or execution machinery failed.
    Operational,
}

impl TestWorkflowStatus {
    /// Returns the exact stable wire spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::TestFailed => "test-failed",
            Self::SourceInvalid => "source-invalid",
            Self::NoTests => "no-tests",
            Self::Refused => "refused",
            Self::Exhausted => "exhausted",
            Self::Cancelled => "cancelled",
            Self::Operational => "operational",
        }
    }

    /// Returns whether this status is a clean completion.
    #[must_use]
    pub const fn is_clean(self) -> bool {
        matches!(self, Self::Clean)
    }
}

/// One versioned identity/policy/ordered-result/structured-refusal report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TestWorkflowReport {
    status: TestWorkflowStatus,
    identity: TestWorkflowIdentity,
    policy: TestWorkflowPolicy,
    selection: TestWorkflowSelection,
    inventory: Option<TestWorkflowInventory>,
    package: Option<TestWorkflowPackage>,
    results: Vec<TestWorkflowTargetResult>,
    refusal: Option<TestWorkflowRefusal>,
    diagnostics: Vec<TestWorkflowDiagnostic>,
    arranged_width: u64,
}

impl TestWorkflowReport {
    /// Returns the published report format spelling.
    #[must_use]
    pub const fn format(&self) -> &'static str {
        TEST_WORKFLOW_REPORT_FORMAT
    }

    /// Returns the published report format version.
    #[must_use]
    pub const fn report_version(&self) -> u32 {
        TEST_WORKFLOW_REPORT_VERSION
    }

    /// Returns the complete judgment.
    #[must_use]
    pub const fn status(&self) -> TestWorkflowStatus {
        self.status
    }

    /// Returns whether every admitted target completed.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.status.is_clean()
    }

    /// Returns the preflighted identity record.
    #[must_use]
    pub const fn identity(&self) -> &TestWorkflowIdentity {
        &self.identity
    }

    /// Returns the declared policy.
    #[must_use]
    pub const fn policy(&self) -> &TestWorkflowPolicy {
        &self.policy
    }

    /// Returns the declared and admitted run-plan selection.
    #[must_use]
    pub const fn selection(&self) -> &TestWorkflowSelection {
        &self.selection
    }

    /// Returns the observed inventory after admission.
    #[must_use]
    pub const fn inventory(&self) -> Option<&TestWorkflowInventory> {
        self.inventory.as_ref()
    }

    /// Returns the observed bounded source package.
    #[must_use]
    pub const fn package(&self) -> Option<&TestWorkflowPackage> {
        self.package.as_ref()
    }

    /// Returns one result per admitted target, in canonical target-name order.
    #[must_use]
    pub fn results(&self) -> &[TestWorkflowTargetResult] {
        &self.results
    }

    /// Returns the structured refusal, if the invocation produced one.
    #[must_use]
    pub const fn refusal(&self) -> Option<&TestWorkflowRefusal> {
        self.refusal.as_ref()
    }

    /// Returns the bounded payload-free diagnostics.
    #[must_use]
    pub fn diagnostics(&self) -> &[TestWorkflowDiagnostic] {
        &self.diagnostics
    }

    /// Returns the width the harness arranged, or zero when no run was admitted.
    #[must_use]
    pub const fn arranged_width(&self) -> u64 {
        self.arranged_width
    }

    /// Assembles one report from already-decided parts.
    fn assemble(parts: ReportParts) -> Self {
        Self {
            status: parts.status,
            identity: parts.identity,
            policy: parts.policy,
            selection: parts.selection,
            inventory: parts.inventory,
            package: parts.package,
            results: parts.results,
            refusal: parts.refusal,
            diagnostics: parts.diagnostics,
            arranged_width: parts.arranged_width,
        }
    }
}

/// The decided parts of one report, assembled by the workflow.
struct ReportParts {
    /// Complete judgment.
    status: TestWorkflowStatus,
    /// Preflighted identity record.
    identity: TestWorkflowIdentity,
    /// Declared policy.
    policy: TestWorkflowPolicy,
    /// Declared and admitted selection.
    selection: TestWorkflowSelection,
    /// Observed inventory after admission.
    inventory: Option<TestWorkflowInventory>,
    /// Observed bounded source package.
    package: Option<TestWorkflowPackage>,
    /// Ordered target results.
    results: Vec<TestWorkflowTargetResult>,
    /// Structured refusal.
    refusal: Option<TestWorkflowRefusal>,
    /// Bounded payload-free diagnostics.
    diagnostics: Vec<TestWorkflowDiagnostic>,
    /// Arranged harness width.
    arranged_width: u64,
}

/// The preflighted invocation.
struct Preflight {
    /// Observed and matched identity record.
    identity: TestWorkflowIdentity,
    /// Admitted declared run plan.
    plan: TestRunPlan,
}

/// Returns a preflight refusal before any analysis dispatch.
fn preflight_refusal(code: &'static str, detail: Option<&'static str>) -> TestWorkflowRefusal {
    TestWorkflowRefusal::new(
        TestWorkflowStage::Preflight,
        code,
        REQUIREMENT_WORKFLOW,
        detail,
    )
}

/// Preflights the declared policy, inputs, and identities without dispatching analysis.
fn preflight(request: &TestWorkflowRequest<'_>) -> Result<Preflight, TestWorkflowRefusal> {
    let policy = request.policy;
    if policy.revision() != TEST_WORKFLOW_POLICY_REVISION {
        return Err(preflight_refusal("unsupported-policy-revision", None));
    }
    if policy.jobs() != TEST_WORKFLOW_JOBS {
        return Err(preflight_refusal("unsupported-job-cardinality", None));
    }
    if policy.maximum_transitions() == 0 {
        return Err(preflight_refusal("undefined-transition-bound", None));
    }
    if policy.stages().limit() < TEST_WORKFLOW_FRONTEND_STAGES {
        return Err(preflight_refusal(
            "insufficient-frontend-stages",
            Some("syntax-and-analysis"),
        ));
    }
    let declarations = request.declarations;
    let plan =
        declare_test_run(&[declarations.kind], declarations.substitutions).map_err(|refusal| {
            let code = match refusal {
                crate::ir::TestRunRefusal::UnknownKind => "unknown-test-kind",
                crate::ir::TestRunRefusal::DuplicateKind => "conflicting-test-kind",
                crate::ir::TestRunRefusal::UnknownSubstitution => "unknown-test-substitution",
                crate::ir::TestRunRefusal::DuplicateSubstitution => "conflicting-test-substitution",
            };
            preflight_refusal(code, None)
        })?;
    match plan.kinds() {
        [TestKind::Unit] => {}
        _ => return Err(preflight_refusal("unsupported-test-kind", None)),
    }
    if !plan.substitutions().is_empty() {
        return Err(preflight_refusal("unsupported-test-substitution", None));
    }
    if let Some(code) = declared_input_refusal(declarations.registry_inputs) {
        return Err(preflight_refusal(
            if code {
                "unknown-registry-input"
            } else {
                "unsupported-registry-input"
            },
            None,
        ));
    }
    if let Some(code) = declared_input_refusal(declarations.authority_inputs) {
        return Err(preflight_refusal(
            if code {
                "unknown-authority-input"
            } else {
                "unsupported-authority-input"
            },
            None,
        ));
    }
    if let Some(code) = declared_input_refusal(declarations.external_artifacts) {
        return Err(preflight_refusal(
            if code {
                "unknown-external-artifact"
            } else {
                "unsupported-external-artifact"
            },
            None,
        ));
    }
    let observed = TestWorkflowIdentity::observed(
        request.protocol_selection,
        TEST_WORKFLOW_TOOLCHAIN_IDENTITY,
    )
    .map_err(|error| preflight_refusal(error.code(), None))?;
    if let Some(field) = request.expected_identity.disagreement(&observed) {
        return Err(preflight_refusal("identity-mismatch", Some(field)));
    }
    Ok(Preflight {
        identity: observed,
        plan,
    })
}

/// Returns whether one declared input set is refused and whether it names nothing.
///
/// `Some(true)` reports that a declared spelling is empty and therefore unknown; `Some(false)`
/// reports a declared spelling this workflow does not support. `None` reports no declaration.
fn declared_input_refusal(inputs: &[&str]) -> Option<bool> {
    if inputs.is_empty() {
        return None;
    }
    Some(inputs.iter().any(|input| input.is_empty()))
}

/// Runs one experimental unit test workflow to completion or to its first refusal.
///
/// Preflight refusals publish a report without dispatching any frontend stage. Otherwise the
/// bounded frontend stages run in their declared order, the analyzed program is admitted under the
/// declared inventories, and the admitted target executes under the declared step bound. The
/// returned report is the complete judgment; this function does not return an error type so a
/// caller cannot observe a partial success.
pub async fn run_test_workflow(
    services: TestWorkflowServices<'_>,
    request: TestWorkflowRequest<'_>,
) -> TestWorkflowReport {
    let policy = request.policy.clone();
    let preflighted = match preflight(&request) {
        Ok(preflighted) => preflighted,
        Err(refusal) => {
            let jobs = policy.jobs();
            return TestWorkflowReport::assemble(ReportParts {
                status: TestWorkflowStatus::Refused,
                identity: request.expected_identity.clone(),
                policy,
                selection: TestWorkflowSelection {
                    kind: TestKind::Unit,
                    substitutions: Vec::new(),
                    jobs,
                    entry: None,
                },
                inventory: None,
                package: None,
                results: Vec::new(),
                refusal: Some(refusal),
                diagnostics: Vec::new(),
                arranged_width: 0,
            });
        }
    };
    let plan = preflighted.plan;
    let identity = preflighted.identity;
    let coordinator = AnalyzePackageCoordinator::new(
        services.allocator,
        services.identity_source,
        services.clock,
        services.blocking,
    );
    let limits = policy.frontend_limits();
    let syntax = match coordinator
        .validate(crate::ValidatePackageRequest {
            package_root: request.package_root,
            protocol_selection: request.protocol_selection,
            frontend_limits: limits,
            event_delivery: None,
        })
        .await
    {
        Ok(syntax) => syntax,
        Err(error) => {
            return test_report_refused(
                identity,
                policy,
                plan,
                TestWorkflowRefusal::new(
                    TestWorkflowStage::Analysis,
                    error.code(),
                    REQUIREMENT_WORKFLOW,
                    None,
                ),
            );
        }
    };
    if syntax.phase.status() != crate::frontend::PackageSyntaxStatus::Valid {
        return TestWorkflowReport::assemble(ReportParts {
            status: TestWorkflowStatus::SourceInvalid,
            identity,
            policy: policy.clone(),
            selection: selection(policy.jobs(), None, &plan),
            inventory: None,
            package: None,
            results: Vec::new(),
            refusal: None,
            diagnostics: bounded_diagnostics(
                syntax.phase.diagnostics(),
                policy.diagnostics().limit(),
            ),
            arranged_width: 0,
        });
    }
    let analysis = match coordinator
        .analyze(AnalyzePackageRequest {
            package_root: request.package_root,
            protocol_selection: request.protocol_selection,
            semantic_mode: SemanticMode::Portable,
            frontend_limits: limits,
            event_delivery: None,
        })
        .await
    {
        Ok(analysis) => analysis,
        Err(error) => {
            return test_report_refused(
                identity,
                policy,
                plan,
                TestWorkflowRefusal::new(
                    TestWorkflowStage::Analysis,
                    error.code(),
                    REQUIREMENT_WORKFLOW,
                    None,
                ),
            );
        }
    };
    if analysis.status != AnalyzePackageStatus::SourceValid {
        return TestWorkflowReport::assemble(ReportParts {
            status: TestWorkflowStatus::SourceInvalid,
            identity,
            policy: policy.clone(),
            selection: selection(policy.jobs(), None, &plan),
            inventory: None,
            package: None,
            results: Vec::new(),
            refusal: None,
            diagnostics: bounded_diagnostics(analysis.diagnostics(), policy.diagnostics().limit()),
            arranged_width: 0,
        });
    }
    let Some(analyzed) = analysis.analysis.as_ref() else {
        return test_report_refused(
            identity,
            policy,
            plan,
            TestWorkflowRefusal::new(
                TestWorkflowStage::Analysis,
                "missing-analysis-inventory",
                REQUIREMENT_WORKFLOW,
                None,
            ),
        );
    };
    let package = analyzed.manifest().map(|manifest| TestWorkflowPackage {
        files: u64::try_from(manifest.files().len()).unwrap_or(u64::MAX),
        bytes: manifest.total_byte_length(),
    });
    if let Some(manifest) = analyzed.manifest()
        && manifest.source_language() != identity.source_language()
    {
        return test_report_refused(
            identity,
            policy,
            plan,
            TestWorkflowRefusal::new(
                TestWorkflowStage::Analysis,
                "source-identity-mismatch",
                REQUIREMENT_WORKFLOW,
                None,
            ),
        );
    }
    let admitted = match admit_target(analyzed, &plan, &policy, services) {
        Ok(admitted) => admitted,
        Err((status, refusal)) => {
            let jobs = policy.jobs();
            return TestWorkflowReport::assemble(ReportParts {
                status,
                identity,
                policy,
                selection: selection(jobs, None, &plan),
                inventory: None,
                package,
                results: Vec::new(),
                refusal: Some(refusal),
                diagnostics: Vec::new(),
                arranged_width: 0,
            });
        }
    };
    let run = admitted.harness.run(&plan);
    let (status, refusal) = match run {
        Ok(report) => {
            let results = report
                .results()
                .iter()
                .map(|result| {
                    TestWorkflowTargetResult::from_outcome(result.name(), result.outcome())
                })
                .collect::<Vec<_>>();
            let status = results
                .first()
                .map_or(TestWorkflowStatus::NoTests, |result| {
                    match result.classification() {
                        TestWorkflowTargetClassification::Completed => TestWorkflowStatus::Clean,
                        TestWorkflowTargetClassification::Failed => TestWorkflowStatus::TestFailed,
                        TestWorkflowTargetClassification::StepBoundExhausted => {
                            TestWorkflowStatus::Exhausted
                        }
                        TestWorkflowTargetClassification::Cancelled => {
                            TestWorkflowStatus::Cancelled
                        }
                        TestWorkflowTargetClassification::Undriveable => {
                            TestWorkflowStatus::Operational
                        }
                    }
                });
            let refusal = match status {
                TestWorkflowStatus::Exhausted => Some(TestWorkflowRefusal::new(
                    TestWorkflowStage::Execution,
                    "step-bound-exhausted",
                    REQUIREMENT_STD_TEST,
                    None,
                )),
                TestWorkflowStatus::Cancelled => Some(TestWorkflowRefusal::new(
                    TestWorkflowStage::Execution,
                    "cancelled",
                    REQUIREMENT_STD_TEST,
                    None,
                )),
                TestWorkflowStatus::Operational => Some(TestWorkflowRefusal::new(
                    TestWorkflowStage::Execution,
                    "undriveable-target",
                    REQUIREMENT_STD_TEST,
                    results.first().and_then(TestWorkflowTargetResult::stop),
                )),
                TestWorkflowStatus::Clean
                | TestWorkflowStatus::TestFailed
                | TestWorkflowStatus::SourceInvalid
                | TestWorkflowStatus::NoTests
                | TestWorkflowStatus::Refused => None,
            };
            return TestWorkflowReport::assemble(ReportParts {
                status,
                identity: identity.clone(),
                policy: policy.clone(),
                selection: selection(policy.jobs(), Some(admitted.name), &plan),
                inventory: Some(admitted.inventory),
                package,
                results,
                refusal,
                diagnostics: Vec::new(),
                arranged_width: report.arranged_width(),
            });
        }
        Err(refusal) => (
            TestWorkflowStatus::Refused,
            Some(TestWorkflowRefusal::new(
                TestWorkflowStage::Admission,
                harness_refusal_code(&refusal),
                REQUIREMENT_STD_TEST,
                None,
            )),
        ),
    };
    TestWorkflowReport::assemble(ReportParts {
        status,
        identity,
        policy: policy.clone(),
        selection: selection(policy.jobs(), None, &plan),
        inventory: None,
        package,
        results: Vec::new(),
        refusal,
        diagnostics: Vec::new(),
        arranged_width: 0,
    })
}

/// The admitted target of one run.
struct AdmittedTarget {
    /// Prepared harness holding exactly one admitted target.
    harness: TestHarness,
    /// Declared target name.
    name: String,
    /// Observed inventory of the admitted program.
    inventory: TestWorkflowInventory,
}

/// Admits the analyzed zero-argument unit entry after checking the declared inventories.
fn admit_target(
    analyzed: &crate::analysis::TypedPackage,
    plan: &TestRunPlan,
    policy: &TestWorkflowPolicy,
    services: TestWorkflowServices<'_>,
) -> Result<AdmittedTarget, (TestWorkflowStatus, TestWorkflowRefusal)> {
    if !matches!(plan.kinds(), [TestKind::Unit]) || !plan.substitutions().is_empty() {
        return Err((
            TestWorkflowStatus::Refused,
            TestWorkflowRefusal::new(
                TestWorkflowStage::Admission,
                "unsupported-test-plan",
                REQUIREMENT_STD_TEST,
                None,
            ),
        ));
    }
    let Some(entry) = analyzed.entry() else {
        return Err((
            TestWorkflowStatus::NoTests,
            TestWorkflowRefusal::new(
                TestWorkflowStage::Admission,
                "no-admissible-unit-entry",
                REQUIREMENT_STD_TEST,
                None,
            ),
        ));
    };
    if entry.parameter.is_some() {
        return Err((
            TestWorkflowStatus::Refused,
            TestWorkflowRefusal::new(
                TestWorkflowStage::Admission,
                "argument-taking-entry",
                REQUIREMENT_STD_TEST,
                None,
            ),
        ));
    }
    if entry.result != TypeDescriptor::UNIT {
        return Err((
            TestWorkflowStatus::NoTests,
            TestWorkflowRefusal::new(
                TestWorkflowStage::Admission,
                "no-unit-entry-result",
                REQUIREMENT_STD_TEST,
                None,
            ),
        ));
    }
    let Some(program) = analyzed.executable_program() else {
        return Err((
            TestWorkflowStatus::Operational,
            TestWorkflowRefusal::new(
                TestWorkflowStage::Admission,
                "missing-executable-program",
                REQUIREMENT_STD_TEST,
                None,
            ),
        ));
    };
    let Some(entry_facts) = analyzed
        .workflows()
        .iter()
        .find(|workflow| workflow.path == entry.path)
    else {
        return Err((
            TestWorkflowStatus::Operational,
            TestWorkflowRefusal::new(
                TestWorkflowStage::Admission,
                "missing-entry-workflow",
                REQUIREMENT_STD_TEST,
                None,
            ),
        ));
    };
    let effects = u64::try_from(
        analyzed
            .workflows()
            .iter()
            .filter(|workflow| !workflow.effects.is_empty())
            .count(),
    )
    .unwrap_or(u64::MAX);
    if !entry_facts.effects.is_empty() || !entry_facts.operations.is_empty() {
        return Err((
            TestWorkflowStatus::Refused,
            TestWorkflowRefusal::new(
                TestWorkflowStage::Admission,
                if entry_facts.effects.is_empty() {
                    "non-empty-operation-inventory"
                } else {
                    "non-empty-effect-inventory"
                },
                REQUIREMENT_STD_TEST,
                None,
            ),
        ));
    }
    let inventory = program_inventory(analyzed, program, policy.frontend_limits(), effects)?;
    let execution = match services
        .allocator
        .allocate(services.identity_source, IdentityKind::Execution)
    {
        Ok(execution) => execution,
        Err(_) => {
            return Err((
                TestWorkflowStatus::Operational,
                TestWorkflowRefusal::new(
                    TestWorkflowStage::Admission,
                    "identity-generation-failure",
                    REQUIREMENT_WORKFLOW,
                    None,
                ),
            ));
        }
    };
    if execution.kind() != IdentityKind::Execution {
        return Err((
            TestWorkflowStatus::Operational,
            TestWorkflowRefusal::new(
                TestWorkflowStage::Admission,
                "execution-identity-invariant",
                REQUIREMENT_WORKFLOW,
                None,
            ),
        ));
    }
    let Some(limits) = machine_limits(policy) else {
        return Err((
            TestWorkflowStatus::Operational,
            TestWorkflowRefusal::new(
                TestWorkflowStage::Admission,
                "machine-limits-invalid",
                REQUIREMENT_WORKFLOW,
                None,
            ),
        ));
    };
    let mut harness = TestHarness::new(limits);
    harness = match harness.parallel(policy.jobs()) {
        Ok(harness) => harness,
        Err(_) => {
            return Err((
                TestWorkflowStatus::Refused,
                TestWorkflowRefusal::new(
                    TestWorkflowStage::Admission,
                    "zero-parallelism",
                    REQUIREMENT_STD_TEST,
                    None,
                ),
            ));
        }
    };
    let name = entry.path.as_str().to_owned();
    if let Err(refusal) = harness.admit(
        &name,
        Arc::new(program.clone()),
        entry.path.clone(),
        execution,
    ) {
        return Err((
            TestWorkflowStatus::Refused,
            TestWorkflowRefusal::new(
                TestWorkflowStage::Admission,
                harness_refusal_code(&refusal),
                REQUIREMENT_STD_TEST,
                harness_refusal_detail(&refusal),
            ),
        ));
    }
    Ok(AdmittedTarget {
        harness,
        name,
        inventory,
    })
}

/// Collects the observed operation, live-resource, and authority inventories of one program.
fn program_inventory(
    analyzed: &crate::analysis::TypedPackage,
    program: &MachineProgram,
    limits: FrontendLimits,
    effects: u64,
) -> Result<TestWorkflowInventory, (TestWorkflowStatus, TestWorkflowRefusal)> {
    let mut operations: u64 = 0;
    let mut live_resources: u64 = 0;
    let mut actions: u64 = 0;
    let instructions = program
        .workflows()
        .iter()
        .flat_map(|workflow| workflow.instructions.iter())
        .chain(
            program
                .task_bodies()
                .iter()
                .flat_map(|body| body.instructions().iter()),
        );
    for instruction in instructions {
        match &instruction.kind {
            InstructionKind::Operation | InstructionKind::OperationWithOperands { .. } => {
                operations = operations.saturating_add(1);
            }
            InstructionKind::OperationCall { operation, .. } => {
                operations = operations.saturating_add(1);
                if operation.action.is_some() {
                    actions = actions.saturating_add(1);
                }
                if operation.section20_kind == Some(OperationKind::LiveResource) {
                    live_resources = live_resources.saturating_add(1);
                }
            }
            InstructionKind::Aggregate { .. } => {
                let capabilities = analyzed
                    .type_capabilities(&instruction.ty, limits)
                    .map_err(|_| {
                        (
                            TestWorkflowStatus::Operational,
                            TestWorkflowRefusal::new(
                                TestWorkflowStage::Admission,
                                "aggregate-resource-classification-failed",
                                REQUIREMENT_WORKFLOW,
                                None,
                            ),
                        )
                    })?;
                if capabilities.is_live_resource() {
                    live_resources = live_resources.saturating_add(1);
                }
            }
            _ => {}
        }
    }
    if operations > 0 {
        return Err((
            TestWorkflowStatus::Refused,
            TestWorkflowRefusal::new(
                TestWorkflowStage::Admission,
                "non-empty-operation-inventory",
                REQUIREMENT_STD_TEST,
                None,
            ),
        ));
    }
    if live_resources > 0 {
        return Err((
            TestWorkflowStatus::Refused,
            TestWorkflowRefusal::new(
                TestWorkflowStage::Admission,
                "non-empty-live-resource-inventory",
                REQUIREMENT_STD_TEST,
                None,
            ),
        ));
    }
    if actions > 0 {
        return Err((
            TestWorkflowStatus::Refused,
            TestWorkflowRefusal::new(
                TestWorkflowStage::Admission,
                "non-empty-authority-ceiling",
                REQUIREMENT_WORKFLOW,
                None,
            ),
        ));
    }
    if !program.task_bodies().is_empty() {
        return Err((
            TestWorkflowStatus::Refused,
            TestWorkflowRefusal::new(
                TestWorkflowStage::Admission,
                "non-empty-task-inventory",
                REQUIREMENT_STD_TEST,
                None,
            ),
        ));
    }
    Ok(TestWorkflowInventory {
        effects,
        operations,
        live_resources,
        authority_ceiling_empty: true,
    })
}

/// Derives the machine limits of one admitted run.
fn machine_limits(policy: &TestWorkflowPolicy) -> Option<MachineLimits> {
    MachineLimits::new(
        policy.maximum_transitions(),
        1,
        policy.maximum_transitions(),
        MAXIMUM_WORKFLOW_CALL_DEPTH,
        DETERMINISTIC_TRANSITION_YIELD_QUANTUM,
        DEFAULT_VALUE_LIMITS,
    )
}

/// Maps one harness refusal to its stable refusal code.
fn harness_refusal_code(refusal: &TestHarnessRefusal) -> &'static str {
    match refusal {
        TestHarnessRefusal::Empty => "empty-target-name",
        TestHarnessRefusal::Duplicate => "duplicate-target",
        TestHarnessRefusal::DuplicateIdentity => "duplicate-execution-identity",
        TestHarnessRefusal::UnsupportedKind(_) => "unsupported-test-kind",
        TestHarnessRefusal::UnsupportedSubstitution(_) => "unsupported-test-substitution",
        TestHarnessRefusal::NoTargets => "no-tests",
        TestHarnessRefusal::UnboundedStepBound => "unbounded-step-bound",
        TestHarnessRefusal::TargetRejected(_) => "target-rejected",
        TestHarnessRefusal::ZeroParallelism => "zero-parallelism",
    }
}

/// Maps one harness refusal to its stable, payload-free detail spelling.
fn harness_refusal_detail(refusal: &TestHarnessRefusal) -> Option<&'static str> {
    match refusal {
        TestHarnessRefusal::UnsupportedKind(kind) => Some(kind.wire_name()),
        TestHarnessRefusal::UnsupportedSubstitution(substitution) => Some(substitution.wire_name()),
        TestHarnessRefusal::TargetRejected(error) => Some(machine_build_error_name(error)),
        TestHarnessRefusal::Empty
        | TestHarnessRefusal::Duplicate
        | TestHarnessRefusal::DuplicateIdentity
        | TestHarnessRefusal::NoTargets
        | TestHarnessRefusal::UnboundedStepBound
        | TestHarnessRefusal::ZeroParallelism => None,
    }
}

/// Returns the stable name of one machine construction rejection.
fn machine_build_error_name(error: &MachineBuildError) -> &'static str {
    match error {
        MachineBuildError::MissingRoot => "missing-root",
        MachineBuildError::ArgumentCount => "argument-count",
        MachineBuildError::ArgumentType => "argument-type",
        MachineBuildError::InvalidExecutionIdentity => "invalid-execution-identity",
        MachineBuildError::InvalidTaskIdentity => "invalid-task-identity",
        MachineBuildError::ExecutionBudgetMismatch => "execution-budget-mismatch",
        MachineBuildError::InvalidSessionIdentity => "invalid-session-identity",
        MachineBuildError::Value(_) => "invalid-value",
        MachineBuildError::UnsupportedEffect(_) => "unsupported-effect",
    }
}

/// Builds one selection record.
fn selection(jobs: u64, entry: Option<String>, plan: &TestRunPlan) -> TestWorkflowSelection {
    TestWorkflowSelection {
        kind: plan.kinds().first().copied().unwrap_or(TestKind::Unit),
        substitutions: plan.substitutions().to_vec(),
        jobs,
        entry: entry.map(Arc::from),
    }
}

/// Builds one refusal report after a stage dispatched.
fn test_report_refused(
    identity: TestWorkflowIdentity,
    policy: TestWorkflowPolicy,
    plan: TestRunPlan,
    refusal: TestWorkflowRefusal,
) -> TestWorkflowReport {
    TestWorkflowReport::assemble(ReportParts {
        status: TestWorkflowStatus::Refused,
        identity,
        selection: selection(policy.jobs(), None, &plan),
        policy,
        inventory: None,
        package: None,
        results: Vec::new(),
        refusal: Some(refusal),
        diagnostics: Vec::new(),
        arranged_width: 0,
    })
}

/// Projects at most `limit` payload-free structured diagnostics.
fn bounded_diagnostics(
    diagnostics: &[StructuredDiagnostic],
    limit: u64,
) -> Vec<TestWorkflowDiagnostic> {
    let limit = usize::try_from(limit).unwrap_or(usize::MAX);
    diagnostics
        .iter()
        .take(limit)
        .map(TestWorkflowDiagnostic::from_structured)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        TEST_WORKFLOW_FRONTEND_STAGES, TEST_WORKFLOW_JOBS, TEST_WORKFLOW_POLICY_REVISION,
        TestPolicyBound, TestWorkflowPolicy, TestWorkflowPolicyError,
    };
    use crate::ir::toolchain::BudgetUnit;

    /// Returns one valid bound.
    fn bound(unit: BudgetUnit, limit: u64) -> TestPolicyBound {
        TestPolicyBound::new(unit, limit).unwrap_or_else(|_| unreachable!("valid bound"))
    }

    #[test]
    fn policy_refuses_zero_missing_and_non_finite_units() {
        assert_eq!(
            TestPolicyBound::new(BudgetUnit::Count, 0),
            Err(TestWorkflowPolicyError::ZeroBound {
                unit: BudgetUnit::Count
            })
        );
        assert_eq!(
            TestWorkflowPolicy::new(
                0,
                TEST_WORKFLOW_JOBS,
                bound(BudgetUnit::Bytes, 1),
                bound(BudgetUnit::Count, TEST_WORKFLOW_FRONTEND_STAGES),
                bound(BudgetUnit::Count, 16),
                1,
            ),
            Err(TestWorkflowPolicyError::ZeroRevision)
        );
        assert_eq!(
            TestWorkflowPolicy::new(
                TEST_WORKFLOW_POLICY_REVISION,
                2,
                bound(BudgetUnit::Bytes, 1),
                bound(BudgetUnit::Count, TEST_WORKFLOW_FRONTEND_STAGES),
                bound(BudgetUnit::Count, 16),
                1,
            ),
            Err(TestWorkflowPolicyError::NonSingleJobs { declared: 2 })
        );
        assert_eq!(
            TestWorkflowPolicy::new(
                TEST_WORKFLOW_POLICY_REVISION,
                TEST_WORKFLOW_JOBS,
                bound(BudgetUnit::Bytes, 1),
                bound(BudgetUnit::Count, TEST_WORKFLOW_FRONTEND_STAGES),
                bound(BudgetUnit::Count, 16),
                0,
            ),
            Err(TestWorkflowPolicyError::ZeroTransitionBound)
        );
        assert_eq!(
            TestWorkflowPolicy::new(
                TEST_WORKFLOW_POLICY_REVISION,
                TEST_WORKFLOW_JOBS,
                bound(BudgetUnit::Count, 64),
                bound(BudgetUnit::Count, TEST_WORKFLOW_FRONTEND_STAGES),
                bound(BudgetUnit::Count, 16),
                1,
            ),
            Err(TestWorkflowPolicyError::WrongInputUnit {
                declared: BudgetUnit::Count
            })
        );
    }

    #[test]
    fn published_policy_derives_separate_frontend_bounds() {
        let policy = TestWorkflowPolicy::published(
            bound(BudgetUnit::Bytes, 4096),
            bound(BudgetUnit::Count, TEST_WORKFLOW_FRONTEND_STAGES),
            bound(BudgetUnit::Count, 32),
            100,
        )
        .unwrap_or_else(|_| unreachable!("valid policy"));
        assert_eq!(policy.maximum_transitions(), 100);
        assert_eq!(policy.input().limit(), 4096);
        assert_eq!(policy.diagnostics().limit(), 32);
        assert_eq!(policy.jobs(), TEST_WORKFLOW_JOBS);
        let limits = policy.frontend_limits();
        assert_eq!(limits.maximum_package_source_bytes(), 4096);
        assert_eq!(limits.maximum_diagnostics_per_activity(), 32);
    }
}
