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

pub use gantry_core::mode::SemanticMode;

mod agent;
mod application;
mod approval;
mod artifact;
mod authority;
mod callable_identity;
mod canonical;
mod constant;
mod effects;
mod executable;
mod facts;
pub mod fault;
pub mod generated;
mod generic;
mod host_domain;
pub mod identifier;
mod lifecycle;
mod manifest;
mod metadata;
mod operation;
mod package;
mod path;
mod primitive;
mod protected;
pub mod registry;
mod resource;
mod schema;
mod secret;
mod signature;
mod target;
pub mod toolchain;
mod type_expression;
mod type_properties;
mod types;
mod wait;

// The agent fulfillment, assistant turn, tool, and session model of SPEC.md Section
// 25 is published here. Its `Turn` is named apart from the landed executable
// `TaskCompletion` and its `StreamKind` is named apart from the landed operation
// progress vocabulary, so no name of this crate root is claimed by two vocabularies
// at once.
pub use agent::{
    AGENT_CLAUSES, AGENT_NON_CLAIM_ORDER, AGENT_NON_CLAIMS, AcceptedTurn, AgentBindingRevision,
    AgentCrashCutClassification, AgentDeclaredInput, AgentDiagnosticCode, AgentError,
    AgentNonClaim, AgentNonClaimAssertion, AgentRecoveryDecision, AgentRequirement,
    AgentRequirementId, BindingFact, ChildSession, ChildSessionId, DiscoveryArtifact,
    DiscoveryPhase, DurableAgentCut, DurableAgentRecord, FinalResult, FulfillmentDescriptor,
    FulfillmentProperty, FulfillmentState, HandlerKind, HandlerUse, ParentSessionReservation,
    PreflightReport, PreflightVerdict, ProgressSignal, PropertyVerdict, ProviderNameMap,
    RawResponse, RejectedPrefix, RepairAttempt, RepairBudget, RepairOutcome, RepairPermit,
    RepairPolicy, RoundId, RoundState, SemanticStream, SessionDirective, SessionId,
    SessionReservations, StreamBudget, StreamId, StreamKind, StreamSpec, ToolDescriptor,
    ToolInvocationId, ToolInvocationRequest, ToolResultRecord, ToolResultVector, ToolSetRevision,
    ToolSetRevisionId, ToolSlotId, ToolSlotKind, Turn, TurnKind, TurnOutcome, TurnValidationCause,
    check_agent_non_claims, classify_original_turn, preflight, repair_turn, validate_raw_response,
};
// The Section 30 application entry and launch lifecycle model is declaration-only:
// it reuses Section 20 generations and Section 22 stop coordination without
// introducing a launcher, evaluator, adapter, or host trait.
pub use application::{
    APPLICATION_CLAUSES, ApplicationClass, ApplicationCoordinator, ApplicationDiagnosticCode,
    ApplicationEntries, ApplicationEntry, ApplicationError, ApplicationPhase, CapabilityGrant,
    ExitDisposition, ExitReport, FinalizationStep, FuelDisposition, FuelGrant, FuelState,
    LaunchArrangement, LaunchSnapshot, LaunchSnapshotLimits, LogicalCwd, PortableSignalClass,
    StdioArrangement, StdioChannel, StdioSet, SupervisorSettlement, admit_durable_companion,
};
pub use approval::{
    ApprovalAuditAccess, ApprovalAuditEvidence, ApprovalAuditView, ApprovalDecision,
    ApprovalDecisionId, ApprovalDiagnosticCode, ApprovalError, ApprovalOutcome,
    ApprovalOutcomeRecord, ApprovalRequestId, ApprovalSubject, ApprovalSubjectDigest,
    ApprovalSubjectInputs, ApproverPresentation, AttemptApplicability, AuditTransition,
    AuditTransitionKind, AuthenticatedActor, CommitPointResult, DecisionConstraints, DecisionScope,
    DurableApprovalCut, DurableApprovalRecord, ExternalTargetRef, FenceReason,
    HostAttestationBindingId, HostAttestationKind, HostAuthorityDigest, LeaseScope,
    LogicalExecutionId, LogicalOperationId, MappingRevision, PolicyRevision,
    ProtectedReviewChannel, ProtectedScope, RefusalReason, ResumeClass, Revalidation,
    RevocationContract, SealedPredicate, SemanticArgumentDigest, StalenessReason, StandingLease,
    revalidate,
};
pub use artifact::{ArtifactEncodingError, ArtifactLimits, BoundedArtifact};
pub use authority::{
    AUTHORITY_RIGHT_ORDER, Admission, AdmissionRequest, AncestorFences, AuthorityBindingId,
    AuthorityChangeClass, AuthorityError, AuthorityFence, AuthorityGeneration, AuthorityInstance,
    AuthorityInstanceId, AuthorityLeasePolicy, AuthorityRequirementId, AuthorityRight,
    ExternalOutcome, FenceCategory, FenceLatches, FencePoint, FenceState, GenerationRelation,
    InstanceComparison, LeaseRelation, LineageRecord, LineageRelation, RightsRelation, RightsSet,
    SharedAuthorityInstance,
};
pub use callable_identity::{
    CallableIdentityError, CanonicalCallableIdentity, CanonicalTemplateIdentity,
};
pub use canonical::{
    CanonicalIr, CanonicalNode, CanonicalOperationSite, CanonicalSourceMap,
    CanonicalTaskControlSite, CanonicalWorkflow, IrArtifactError, SourceMapEntry,
};
// The Section 32 constant, package-state, and initialization model is
// declaration-only: it records declared classes, admissible operations, bounded
// work, dependency order, publication facts, and package state without parsing,
// evaluating, linking, or executing source.
pub use constant::{
    ApplicationStateDeclaration, ApplicationStateOwner, CONSTANT_CLAUSES, CONSTANT_INT_LIMIT,
    CONSTANT_NON_CLAIM_ORDER, CONSTANT_NON_CLAIMS, ConstantAdmissibility, ConstantArtifactBinding,
    ConstantArtifactIdentity, ConstantConversion, ConstantDeclaration, ConstantDiagnosticCode,
    ConstantEffect, ConstantError, ConstantExpression, ConstantInterface, ConstantInterfaceEntry,
    ConstantInterfaceIdentity, ConstantNonClaim, ConstantNonClaimAssertion, ConstantOperation,
    ConstantPackage, ConstantRefusalReason, ConstantSelection, ConstantState, ConstantValueClass,
    ConstantWork, EvaluationLimits, MAX_CONSTANT_VALUE_BYTES, MAX_DECLARED_NAME_BYTES,
    PackageLoadFact, PackageStateClass, admit_package_state, admit_sealed_predicate_name,
    check_constant_non_claims, checked_float, checked_int,
};
pub use effects::{EFFECT_ORDER, EffectSet};
pub use executable::{
    AggregateKind, ExecutableAction, ExecutableOperation, ExecutableTaskBody,
    ExecutableTaskCapture, ExecutableTaskContext, ExecutableTaskHandle, Instruction,
    InstructionKind, LoopPhase, MachineProgram, Parameter, ProgramError, Projection,
    ReceiverSource, TaskBodyIdentity, TaskCompletion, TaskSuspension, Workflow,
};
pub use facts::{
    ActionEffectContributor, ActionInventory, CallEdge, EntryInventory, OperationSite,
    OwnershipFact, SiteContractError, StaticSiteId, StructuralPosition, TaskControlSite,
    WorkflowFacts,
};
// The fault containment model of SPEC.md Section 23 is published here. Its
// `ContainmentFailureClass` and `ContainmentSettlement` are named apart from the landed
// `GNT-20` operation ABI spellings `FailureClass` and `OperationSettlement`, so no name of
// this crate root is claimed by two vocabularies at once.
pub use fault::{
    CONTAINMENT_NON_CLAIM_NAMES, CONTAINMENT_NON_CLAIM_ORDER, Completion, ContainmentBoundary,
    ContainmentDeclaration, ContainmentDiagnosticCode, ContainmentError, ContainmentFailureClass,
    ContainmentNonClaim, ContainmentNonClaimName, ContainmentObligation, ContainmentPlan,
    ContainmentReport, ContainmentSettlement, ContainmentVerdict, EffectState,
    FAULT_CONTAINMENT_CLAUSES, ForeignFailureKind, ForeignFailureObservation, MalformedCompletion,
    ObligationRefusal, PoisonLedger, PoisonReason, ReportScope, attribute_foreign_failure,
    check_containment_declaration, poison_resource_state,
};
pub use generic::{
    CanonicalImplementationIdentity, ClosedCallable, ClosedOperationSite, ClosedTaskSite,
    ConcreteEffect, ConcreteIdentity, ConcreteInstantiation, ConcreteSourceMapEntry,
    ExecutableProjection, GenericAnalysisFacts, GenericContractError, GenericTemplate,
    ImplementationHead, Predicate, ResolvedCall, SourceOriginSet, TraitContract,
    TraitMethodContract, TraitReference,
};
// Section 29 declares portable host-domain vocabulary and adapter declarations only.
// It introduces no runtime adapter, host trait, checkpoint, evaluator, or host behavior.
pub use generated::{HostDomainCategory, HostDomainFamily, HostTarget};
pub use host_domain::{
    AdapterContractDeclaration, HOST_DOMAIN_CLAUSES, HostDomainDiagnosticCode, HostDomainError,
    HostDomainErrorKind, HostOperationFailure, HostOperationOutcome, HostProgress, HostSettlement,
    HostSettlementError, NativeMappingDeclaration, PORTABLE_MESSAGE_MAX_BYTES, ProcessConfinement,
    ProcessLifecycle, ProcessStdio, ProcessSupervision,
};
// `identifier` is re-exported here for the identifier-security surface, except
// for `AliasMap`, `CollisionCondition`, and `DeclaredName`, which the package and
// protected models already publish under those exact names; those three stay
// reachable as `gantry_ir::identifier::{AliasMap, CollisionCondition, DeclaredName}`.
pub use identifier::{
    CanonicalSymbolicIdentity, CollisionDiagnostic, ConfusableSkeleton,
    DEFAULT_NAMESPACE_MAX_SCALARS, DISPLAY_LABEL_MAX_SCALARS, DisplayLabel, ExternalName,
    ExternalNameMap, GeneratedAlias, IdentifierDiagnosticCode, IdentifierError, IdentityKey,
    IdentityVersion, LookupNamespace, NameSpelling, SPELLING_LIMIT_BYTES, ScriptClassification,
    ScriptSet, SourceSpelling, SymbolicDomain, SymbolicIdentityDigest, SymbolicIdentityRecord,
    collision_condition, generated_alias, share_one_skeleton,
};
pub use lifecycle::{
    AdmittedWork, CooperativeObservation, DurableStopCut, EmergencyCleanupWitness, EscalatedWork,
    Escalation, GracePolicy, LIFECYCLE_STOP_CLAUSES, LateResultFence, STOP_NON_CLAIM_ORDER,
    STOP_NON_CLAIMS, SafePoint, StopCause, StopCauseClass, StopCoordinator,
    StopCrashCutClassification, StopDiagnosticCode, StopError, StopNonClaim, StopNonClaimName,
    StopReport, StopRequest, StopRequestId, StopRequestJoin, StopState, StopTransition,
    TaskOutcome, TaskResult, TaskStopState,
};
pub use manifest::{ManifestError, ManifestFile, PackageSourceManifest};
// Section 31 declares bounded source metadata records only; parsing, rendering,
// lint execution, generators, and editor services remain downstream owners.
pub use metadata::{
    DependencyWarningPolicy, Deprecation, DocumentationComment, DocumentationFormat,
    DocumentationLink, ExampleDeclaration, ExampleMode, GeneratedOrigin, LintDeclaration, LintId,
    LintScope, LintSeverity, MetadataDeclarations, MetadataDiagnosticCode, MetadataError,
    MetadataSubject, SOURCE_METADATA_CLAUSES, SemanticAttribute, ToolMetadata, admit_lint_control,
};
pub use operation::{
    AdapterInstance, CrashCutClassification, DedupRecord, DedupRecordState, DedupRetentionBounds,
    DispatchAdmission, DurableOperationCut, DurableValueRecord, EffectCertainty, FailureClass,
    LiveResource, LoanId, OPERATION_ABI_CLAUSES, OperationAbi, OperationAbiDiagnosticCode,
    OperationAbiError, OperationCancellation, OperationKind, OperationSettlement, OwnerGeneration,
    PostFailureSettlement, ProgressDisposition, ProgressObservation, ProgressRecord,
    ReceiverOwnership, ResourceGenerationId, ResourceState, RetryEligibility, admit_dispatch,
    classify_effect, retry_eligibility,
};
pub use package::{
    AliasMap, AliasNamespace, AxisReport, AxisVerdict, BoundarySchemaReport,
    BoundarySchemaSubReport, BoundarySchemaSurface, CanonicalIrDigest, CollisionCondition,
    ComparedInput, ComparedInputs, CompatibilityAxis, CompatibilityReport, ConstructionPolicy,
    DeclaredCeiling, DeclaredNamespaces, DeclaredSurface, DeclaringPackageScope, DependencyAlias,
    DependencyDeclaration, DependencyInterfacePin, DurableArtifactRelation, DurableArtifactReport,
    DurableArtifactSubReport, ExhaustivenessPolicy, ExportEntry, FeatureName, GeneratorInput,
    GeneratorInputRole, GeneratorInputs, IdentityProof, Import, ImportSet, InterfaceDigest,
    InterfaceItem, InterfaceMetadata, InterfaceProof, InterfaceSeal, ItemKind, NominalFacts,
    PackageDiagnosticCode, PackageError, PackageGraph, PackageIdentity, PackageIdentityInputs,
    PackageIdentityRecord, PackageInstance, PackageName, PackageSourceIdentity, PackageVersion,
    PublicInterfaceManifest, QualifiedPath, RequirementDemand, ResolvedName, SelectedFeatureSet,
    SourceManifestDigest, TargetCondition, TargetDescriptor, TargetFactSet, TargetFacts,
    TargetKind, TargetSet, TraitFacts, UnprovenReason, UnqualifiedResolution, Visibility,
    check_ceiling,
};
pub use path::{CanonicalPath, CanonicalPathError};
pub use primitive::{Comparison, Primitive};
pub use protected::{
    AuditAccess, AuditOutcome, CleanupOutcome, CleanupReport, CrossingDeclaration,
    CrossingRejection, DECLARED_NAME_LIMIT, DeclaredName, DeclaredNameRejection, DeliveryDecision,
    DeliveryDenial, DisclosureBudget, DisclosureCharge, ENVELOPE_OBSERVATION_ORDER,
    EXCLUDED_PROTECTION_CLAIMS, EmergencyCleanup, EnvelopeClause, EnvelopeObservation,
    EnvelopeRejection, ExcludedClaimKind, ExcludedProtectionClaim, ExcludedProtectionClaimName,
    ExhaustionAccounting, FrozenDeliveryPermission, LayerValueInspection,
    NON_ERASURE_COMPONENT_ORDER, NonErasureClaim, NonErasureComponentKind, NonErasureObligation,
    NonErasureStatus, PROTECTED_DATA_CLASS_ORDER, PROVENANCE_ORIGIN_ORDER, ProjectionKind,
    ProtectedDataClass, ProtectedValue, ProtectedValueId, ProtectionPreservingTransform,
    ProvenanceOrigin, ProvenanceOriginKind, RELEASE_DESTINATION_ORDER, ReleaseAuditEvidence,
    ReleaseAuditView, ReleaseAuthorityError, ReleaseDecision, ReleaseDestination, ReleaseGrant,
    ReleaseHolderAuthority, ReleaseHolderBindingId, ReleaseHolderId, ReleaseOutcome,
    ReleaseProjection, ReleaseRejection, ReleaseSite, ReleasedValue, SemanticEnvelope,
    ValueActionBoundary, admit_crossing, combined_protection_class,
};
// The Section 28 resource-accounting model publishes whole-resource lifetime state
// separately from Section 20's operation `ResourceState`; it is a pure declaration
// model and does not add runtime registry, evaluator, journal, or host behavior.
pub use resource::{
    Charge, DurableResourceRecord, EmergencyReleaseWitness, LivenessRoot, LogicalMeasure,
    PoisonWitness, Quota, QuotaFamily, QuotaOwner, RESOURCE_CLAUSES, ResourceAction, ResourceError,
    ResourceLedger, ResourceLifetimeState, RetentionFence, SettlementBaseline,
};
pub use schema::{GeneratedSchemaObject, SchemaObjectError};
pub use secret::{
    DurableSecretReference, SECRET_NON_CLAIM_ORDER, SECRET_NON_CLAIMS, SECRET_OWNING_CLAUSE,
    SecretAuditAccess, SecretAuditEvidence, SecretAuditOutcome, SecretAuditView, SecretDurableCut,
    SecretError, SecretHolderBindingId, SecretNonClaim, SecretNonClaimName, SecretReference,
    SecretReferenceId, SecretResumeClass, SecretRevalidation, SecretStalenessReason,
    revalidate_secret,
};
pub use signature::{
    ActionParameter, CanonicalSignature, ReceiverMode, SignatureError, WorkflowParameter,
};
pub use target::{
    AbiEnvironment, Architecture, BranchDeclaration, BranchMatch, BranchOutcome,
    BuildHostAuthority, BuildHostAuthorityDigest, BuildHostCapability, BuildInput,
    BuildInputDigest, BuildInputRecord, BuildInputRecordDigest, ConditionalSelectionRule,
    DeclaredFactKind, DeclaredFacts, ExecutionTargetDescriptor, ExpectedInputs, FeatureDeclaration,
    FeatureDeclarations, FeatureSolution, FeatureSolutionDigest, GeneratedOutput,
    GeneratedOutputHash, GeneratedOutputSet, ModeAdmission, OperatingSystemFamily,
    PredicateOutcome, PredicateOutcomeDigest, PredicateOutcomeSet, RetainedClosure,
    RetainedClosureDigest, RunnerAdmission, RunnerCapability, TargetArtifactBinding,
    TargetArtifactBindingDigest, TargetArtifactBindingRecord, TargetDescriptorDigest,
    TargetDescriptorField, TargetDescriptorRecord, TargetDiagnosticCode, TargetError,
    TargetFactsDigest, TargetFactsRecord, TargetMatrix, TargetMatrixDigest, TargetMatrixEntry,
    TargetMatrixState, TargetPredicate, TargetPredicateName, ToolchainIdentity,
};
// The bounded untrusted compilation and cache model of SPEC.md Section 26 is published
// here, except for its `ToolchainIdentity`, which the landed target model already
// publishes under that exact name for the opaque field of
// `GNT-17.11-target-artifact-binding`. The Section 26 identity owns the *content* of
// that field, so it stays reachable as `gantry_ir::toolchain::ToolchainIdentity`, in the
// same way the identifier model keeps its three shared names module-qualified.
pub use toolchain::{
    AdmittedGeneratorRun, ArtifactLoader, ArtifactRefusalReason, BudgetObservation, BudgetUnit,
    COMPILATION_NON_CLAIM_ORDER, COMPILATION_NON_CLAIMS, CacheEntry, CacheKey, CacheKeyInputs,
    CacheLimits, CacheObservation, CacheValidation, CancellationSettlement,
    CancellationSettlementKind, CanonicalOutput, CompilationActivity, CompilationError,
    CompilationNonClaim, CompilationNonClaimAssertion, CompletionEvidence, Cutoff, CutoffReason,
    DeclaredDigest, DeclaredGeneratorInput, DeclaredGeneratorOutput, DeclaredRunnerCapability,
    EditorSession, EditorWork, FrontierKey, FrontierKind, FrontierOutcome, GeneratorGrant,
    GeneratorIdentityFold, LoadedArtifact, MAXIMUM_STAGE_LIMIT, PresentedArtifact, PublishedFacts,
    RecordedBuildInput, SealedArtifact, SealedAuthorityClosure, StageBudget, StageConfiguration,
    StageProgress, StageRun, StructuralFrontier, TOOLCHAIN_CLAUSES, ToolchainBudget,
    ToolchainComponent, ToolchainComponentKind, ToolchainDiagnosticCode, ToolchainIdentityInputs,
    ToolchainStage, UntrustedInput, UntrustedInputInventory, UntrustedInputKind, ValidatedReuse,
    check_clean_incremental_equivalence, check_compilation_non_claims,
    refuse_publication_after_cutoff,
};
pub use type_expression::{TypeExpression, TypeExpressionError};
pub use type_properties::{
    IndependentTypeProperties, OwnershipClass, PrimitiveTypeProperties, RecoveryProjectionClass,
    SourceProtectionClass, TransferEligibility, ValueResourceClass,
};
pub use types::{TypeDescriptor, TypeDescriptorError};
// The wait, wakeup, arbitration, and quiescence model of SPEC.md Section 24 is
// published here. Its `WaitGeneration` is named apart from the landed
// `OwnerGeneration` and `ResourceGenerationId` it cites, its `DurableWaitCut` is named
// apart from the landed lifecycle `DurableStopCut`, and its `WakeCause` is named apart
// from the landed lifecycle `StopCause`, so no name of this crate root is claimed by
// two vocabularies at once.
pub use wait::{
    Arbitration, ArbitrationDecision, ArbitrationSnapshot, ArmDisposition, ArmDispositionKind,
    ArmId, ArmObservation, ArmedAlternative, ArmedWinner, ClosureReport, DurableWaitCut,
    DurableWaitRecord, IdentityInput, LosingArmSettlement, LosingArmSettlementReport,
    NondeterminismEnvelope, PrerequisiteRef, QuiescenceClass, QuiescenceFacts, QuiescenceOutcome,
    QuiescenceRemedy, ReadinessObservation, RegistrationOutcome, WAIT_CLAUSES,
    WAIT_GRAPH_MAX_EDGES, WAIT_GRAPH_MAX_NODES, WAIT_NON_CLAIM_ORDER, WAIT_NON_CLAIMS,
    WaitDecision, WaitDiagnosticCode, WaitError, WaitGeneration, WaitGraphDiagnostic, WaitId,
    WaitNonClaimAssertion, WaitNonClaimName, WaitOwnerId, WaitRecoveryClass, WaitRecoveryDecision,
    WaitRegistration, WaitResourceId, WaitSet, WakeCause, WakeOutcome, WakeRecord,
    WithdrawalRecord, check_wait_non_claims, classify_quiescence, observe_quiescence,
};
