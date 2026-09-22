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

mod adt;
mod agent;
mod application;
mod approval;
mod artifact;
mod authority;
mod callable;
mod callable_identity;
mod canonical;
mod codec;
mod collections;
mod console;
mod constant;
mod crypto;
mod data;
mod effects;
pub mod error_semantics;
mod executable;
mod facts;
pub mod fault;
mod fs;
pub mod generated;
mod generic;
mod host_domain;
pub mod identifier;
mod io;
mod lifecycle;
mod locale;
mod manifest;
mod metadata;
mod numeric;
mod operation;
mod package;
mod path;
mod primitive;
mod prng;
mod protected;
pub mod registry;
mod resource;
mod scalar;
mod schema;
mod secret;
mod signature;
mod std_hierarchy;
mod stdlib;
mod target;
mod test_support;
mod text;
pub mod toolchain;
mod type_expression;
mod type_properties;
mod types;
mod wait;
mod workspace;

// The agent fulfillment, assistant turn, tool, and session model of SPEC.md Section
// 25 is published here. Its `Turn` is named apart from the landed executable
// `TaskCompletion` and its `StreamKind` is named apart from the landed operation
// progress vocabulary, so no name of this crate root is claimed by two vocabularies
// at once.
pub use adt::{
    ADT_CLAUSES, AdtAliasDeclaration, AdtBoundaryLabels, AdtCharge, AdtConstantBudget,
    AdtConstantSite, AdtConstantTree, AdtConstantValue, AdtConstructor, AdtConstructorIdentity,
    AdtDiagnosticCode, AdtDurableProjection, AdtError, AdtField, AdtMatchReport,
    AdtNonClaimAssertion, AdtNonClaimName, AdtPackageBuilder, AdtPackageLoad, AdtPackageModel,
    AdtPattern, AdtSubPattern, AdtTypeDeclaration, AdtVisibility, check_adt_non_claims,
};
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
    CapabilityAuthorityClosure, ExternalOutcome, FenceCategory, FenceLatches, FencePoint,
    FenceState, GenerationRelation, InstanceComparison, LeaseRelation, LineageRecord,
    LineageRelation, PreflightResolutionError, RequirementResolution, ResolvedRequirement,
    RightsRelation, RightsSet, SharedAuthorityInstance, SiteRequirementSlotId,
};
// The callable-value contract is declaration-only in this revision: no callable
// type is admitted into an artifact, and `CallableType` only realizes the
// published `GNT-37.1` identity, so these rules bind no analyzed artifact yet.
pub use callable::{
    BindingFacts, BindingState, CallAdmission, CallSettlement, CallableDiagnosticCode,
    CallableError, CallableKind, CallableLimits, CallableProjection, CallableType, CallableValue,
    CaptureAccess, CaptureCandidate, CaptureClass, CaptureDescriptor, CaptureInference,
    CaptureMode, CapturePlan, ReuseState, require_captured_row, resolve_capture_set,
    resolve_captured_row, union_row,
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
    ConstantInterfaceIdentity, ConstantMember, ConstantNonClaim, ConstantNonClaimAssertion,
    ConstantOperation, ConstantPackage, ConstantRefusalReason, ConstantSelection, ConstantState,
    ConstantValueClass, ConstantWork, EvaluationLimits, MAX_CONSTANT_PATH_BYTES,
    MAX_CONSTANT_VALUE_BYTES, MAX_DECLARED_NAME_BYTES, PackageLoadFact, PackageStateClass,
    admit_package_state, admit_sealed_predicate_name, check_constant_non_claims, checked_float,
    checked_int,
};
pub use effects::{EFFECT_ORDER, EffectSet};
pub use error_semantics::{ERROR_SEMANTICS_CLAUSES, ErrorSemanticsDiagnosticCode, FailureChannel};
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
// Section 45 publishes the common I/O foundation: the closed operation vocabulary and the
// versioned one-call request contract. It adds no adapter, host trait, or runtime availability.
pub use io::{
    IO_CLAUSES, IO_CONTRACT_VERSION, IO_ITEMS, IO_REQUEST_OCTET_BOUND, IO_SURFACE_MODES,
    IO_SURFACE_TARGETS, IoBackpressure, IoDiagnosticCode, IoError, IoItemRow, IoOperation,
    IoOutcome, IoRequest, admit_io_progress, admit_io_surface, declare_io_surface,
};
// Section 46 publishes the declared `std.console` module surface. It adds no terminal, adapter,
// capability, or runtime availability.
pub use console::{
    CONSOLE_CLAUSES, CONSOLE_DIMENSION_BOUND, CONSOLE_ITEMS, CONSOLE_OPERATION_FACTS,
    CONSOLE_SURFACE_MODES, CONSOLE_SURFACE_TARGETS, ConsoleDetection, ConsoleDiagnosticCode,
    ConsoleDimensions, ConsoleEnvelopeRule, ConsoleError, ConsoleItemRow, ConsoleOperation,
    ConsoleOperationFacts, ConsoleTerminalReport, admit_console_surface, declare_console_surface,
};
// Section 47 publishes the declared `std.fs` module surface. It adds no path, descriptor, resource,
// adapter, capability, or runtime availability.
pub use fs::{
    FS_CLAUSES, FS_ITEMS, FS_LINK_REFUSAL_CODE, FS_PATH_SEGMENT_BOUND, FS_RESOLUTION_COUNT,
    FS_SURFACE_MODES, FS_SURFACE_TARGETS, FsAction, FsDiagnosticCode, FsError, FsItemRow, FsPath,
    FsResourceOperation, admit_fs_surface, declare_fs_surface, fs_traversal_order,
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
// The Section 33 locale, calendar, civil-time, and rule-data model is
// declaration-only: it records machine formats, explicit locale values, pinned rule
// data, typed gap and repetition outcomes, snapshots, and target availability
// without consulting a host locale, a host time zone, or an installed database.
pub use locale::{
    CalendarIdentity, CivilResolution, CivilValue, CollationIdentity, Deadline, Disambiguation,
    DurableTemporalRecord, Duration, Instant, LOCALE_CLAUSES, LOCALE_NON_CLAIM_ORDER,
    LOCALE_NON_CLAIMS, LocaleDiagnosticCode, LocaleError, LocaleNonClaim, LocaleNonClaimAssertion,
    LocaleValue, MAX_CIVIL_YEAR, MAX_DURATION_SECONDS, MAX_LOCALE_IDENTIFIER_BYTES,
    MAX_OFFSET_SECONDS, MAX_PRESENTATION_TEXT_BYTES, MAX_RULE_DATA_IDENTIFIER_BYTES,
    MAX_RULE_DATA_TRANSITIONS, MIN_CIVIL_YEAR, MachineFormat, Offset, PreferenceOrigin,
    PreferenceSnapshot, PresentationText, RuleData, RuleDataArtifactBinding,
    RuleDataArtifactIdentity, RuleDataBinding, RuleDataIdentity, RuleDataKind, RuleDataUpgrade,
    TargetDataAvailability, TemporalRecoveryIdentity, ZoneTransition, check_locale_non_claims,
    classify_civil, require_rule_data_available, require_superseded_refused, resolve_civil,
};
// Section 31 declares bounded source metadata records only; parsing, rendering,
// lint execution, generators, and editor services remain downstream owners.
pub use metadata::{
    DependencyDiagnosticClass, DependencyWarningPolicy, Deprecation, DocumentationBoundary,
    DocumentationComment, DocumentationFormat, DocumentationLink, ExampleDeclaration, ExampleMode,
    GeneratedOrigin, LintControlSet, LintDeclaration, LintId, LintScope, LintSeverity,
    MetadataDeclarations, MetadataDiagnosticCode, MetadataError, MetadataSubject,
    SOURCE_METADATA_CLAUSES, SemanticAttribute, ToolMetadata, admit_lint_control,
    admit_semantic_attribute, dependency_policy_ignores, resolve_documentation_link,
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
    DependencyDeclaration, DependencyFingerprint, DependencyInterfacePin, DependencyPin,
    DurableArtifactRelation, DurableArtifactReport, DurableArtifactSubReport, ExhaustivenessPolicy,
    ExportEntry, FeatureName, GeneratorInput, GeneratorInputRole, GeneratorInputs, IdentityProof,
    Import, ImportSet, InterfaceDigest, InterfaceItem, InterfaceMetadata, InterfaceProof,
    InterfaceSeal, ItemKind, NominalFacts, PackageDiagnosticCode, PackageError, PackageGraph,
    PackageIdentity, PackageIdentityInputs, PackageIdentityRecord, PackageInstance, PackageName,
    PackageSourceIdentity, PackageVersion, PublicInterfaceManifest, QualifiedPath,
    RequirementDemand, ResolvedName, SelectedFeatureSet, SourceManifestDigest, TargetCondition,
    TargetDescriptor, TargetFactSet, TargetFacts, TargetKind, TargetSet, TraitFacts,
    UnprovenReason, UnqualifiedResolution, Visibility, check_ceiling,
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
    PoisonWitness, Quota, QuotaFamily, QuotaOwner, RESOURCE_CLAUSES, ResourceAction,
    ResourceCarrier, ResourceError, ResourceLedger, ResourceLifetimeState, RetentionFence,
    SettlementBaseline, admit_resource_carrier,
};
pub use schema::{GeneratedSchemaObject, SchemaObjectError};
pub use secret::{
    DurableSecretReference, SECRET_CLAUSES, SECRET_NON_CLAIM_ORDER, SECRET_NON_CLAIMS,
    SECRET_OWNING_CLAUSE, SecretAuditAccess, SecretAuditEvidence, SecretAuditOutcome,
    SecretAuditView, SecretDurableCut, SecretError, SecretHolderBindingId, SecretNonClaim,
    SecretNonClaimName, SecretReference, SecretReferenceId, SecretResumeClass, SecretRevalidation,
    SecretStalenessReason, revalidate_secret,
};
pub use signature::{
    ActionParameter, CanonicalSignature, ReceiverMode, SignatureError, WorkflowParameter,
};
// The Section 42 codec foundation: the declared `std.codec` family with its five modules, the
// versioned codec identity and its exact admission rule, the frozen refusal vocabulary with its
// codec categories of `GNT-29.9-codec-contract`, the canonical hex, base64, binary, dynamic JSON,
// and compression codecs of `GNT-42.2-hex-codec`, `GNT-42.3-base64-codec`,
// `GNT-42.4-binary-endian-readers-and-writers`, `GNT-42.5-bounded-dynamic-json`, and
// `GNT-42.6-compression-codec`, the closed non-claim vocabulary of `GNT-42.7-codec-non-claims`,
// and the separation between application codecs and the sealed canonical boundary and durable
// recovery projections.
pub use codec::{
    BASE64_TEXT_OCTET_BOUND, BASE64_VALUE_OCTET_BOUND, BINARY_VALUE_OCTET_BOUND, CODEC_CLAUSES,
    CODEC_ITEMS, CODEC_NON_CLAIMS, COMPRESSION_ALGORITHM_VERSION, COMPRESSION_ENCODED_OCTET_BOUND,
    COMPRESSION_VALUE_OCTET_BOUND, CodecCategory, CodecDiagnosticCode, CodecError, CodecItemRow,
    CodecKind, CodecNonClaim, CodecNonClaimAssertion, CodecVersion, DECLARED_CODEC_VERSION, Endian,
    HEX_TEXT_OCTET_BOUND, HEX_VALUE_OCTET_BOUND, JSON_DEPTH_BOUND, JSON_NODE_BOUND,
    JSON_TEXT_OCTET_BOUND, JsonValue, base64_decode, base64_encode, canonical_codec_hierarchy,
    check_codec_non_claims, compression_decode, compression_encode, declare_codec_surface,
    hex_decode, hex_encode, json_decode, json_encode, read_u16, read_u32, read_u64, write_u16,
    write_u32, write_u64,
};
// The Section 43 data foundation: the declared `std.data` family with its `http`, `mime`, and
// `url` modules, the versioned value-model identity and its exact admission rule, the frozen
// refusal vocabulary with its declared refusal categories, the URL value model of
// `GNT-43.2-url-value-model`, the MIME type value model of `GNT-43.3-mime-type-and-parameter-model`,
// the header field and field list model of `GNT-43.4-header-field-and-field-list-model`, the
// framing model of `GNT-43.5-message-framing-model`, the request and response value models and
// non-claim vocabulary of `GNT-43.6-request-and-response-value-model`, and the separation between
// these pure value models and the capability-backed network contracts of
// `GNT-29.6-dns-socket-tls-and-http-contracts`.
pub use data::{
    DATA_CLAUSES, DATA_ITEMS, DATA_NON_CLAIMS, DECLARED_DATA_VERSION, DataDiagnosticCode,
    DataError, DataItemRow, DataModule, DataNonClaim, DataRefusalCategory, DataVersion,
    FRAMING_BODY_OCTET_BOUND, FRAMING_CHUNKED_CODING, HEADER_FIELD_COUNT_BOUND,
    HEADER_NAME_TOKEN_BOUND, HEADER_TEXT_OCTET_BOUND, HEADER_VALUE_OCTET_BOUND,
    HTTP_METHOD_SCALAR_BOUND, HTTP_REASON_OCTET_BOUND, HTTP_STATUS_MAXIMUM, HTTP_STATUS_MINIMUM,
    HeaderField, HeaderFieldList, HttpMethod, HttpRequest, HttpResponse, HttpStatus,
    MIME_PARAMETER_COUNT_BOUND, MIME_PARAMETER_NAME_TOKEN_BOUND, MIME_PARAMETER_VALUE_OCTET_BOUND,
    MIME_SUBTYPE_TOKEN_BOUND, MIME_TEXT_OCTET_BOUND, MIME_TYPE_TOKEN_BOUND, MessageFraming,
    MimeType, URL_FRAGMENT_OCTET_BOUND, URL_HOST_SCALAR_BOUND, URL_LABEL_SCALAR_BOUND,
    URL_QUERY_OCTET_BOUND, URL_SCHEME_SCALAR_BOUND, URL_SEGMENT_COUNT_BOUND,
    URL_SEGMENT_OCTET_BOUND, URL_TEXT_OCTET_BOUND, URL_ZONE_SCALAR_BOUND, Url, UrlHost,
    canonical_data_hierarchy, declare_data_surface, message_framing,
};
// The Section 44 crypto foundation: the declared `std.crypto` family with its `hash` and
// `signature` modules, the versioned algorithm identity and its exact admission rule, the frozen
// refusal vocabulary with its declared refusal categories, and the separation between these pure
// read-only algorithms and signing, secret-key material, credentials, and protected operations.
pub use crypto::{
    AlgorithmIdentity, CRYPTO_CLAUSES, CRYPTO_ITEMS, CRYPTO_NON_CLAIMS, CryptoDiagnosticCode,
    CryptoError, CryptoItemRow, CryptoModule, CryptoNonClaim, CryptoRefusalCategory,
    DECLARED_ALGORITHM_VERSION, ED25519_MESSAGE_OCTET_BOUND, ED25519_PUBLIC_KEY_OCTET_LENGTH,
    ED25519_SIGNATURE_OCTET_LENGTH, Ed25519Verdict, SHA256_DIGEST_OCTET_LENGTH,
    SHA256_INPUT_OCTET_BOUND, Sha256Digest, canonical_crypto_hierarchy, declare_crypto_surface,
    ed25519_verify, sha256_digest,
};
// The Section 39 collection foundation: the key contract and canonical order, the recognised
// collection type identities, the `Map`, `Set`, and `Range` value model with its accounting,
// carriage, replacement, and traversal forms, and the one temporary cursor, with no family
// behavior of its own.
pub use collections::{
    COLLECTION_CLAUSES, COLLECTION_ITEMS, CollectionCursor, CollectionDiagnosticCode,
    CollectionEnumerate, CollectionError, CollectionFilter, CollectionItemRow, CollectionKeyPolicy,
    CollectionKeyRefusal, CollectionKeyType, CollectionMap, CollectionNonClaimAssertion,
    CollectionNonClaimName, CollectionOutcome, CollectionTake, CollectionTraversal,
    CollectionValue, CollectionValueKind, CollectionVisit, CollectionZip, MapTypeIdentity,
    MapValue, RangeStepContract, RangeTypeIdentity, RangeValue, SetTypeIdentity, SetValue,
    canonical_collections_hierarchy, canonical_order, check_collection_non_claims,
    declare_collections_surface,
};
// The Section 41 text foundation: canonical text values as finite scalar sequences with exact
// UTF-8 admission, a scalar count, canonical octets, scalar-boundary slicing, the two canonical
// normalization forms, the two full default case mappings over the pinned Unicode 16.0.0 data, a
// bounded builder, a forward scalar cursor, a canonical scalar comparison, a forward
// extended-grapheme-cluster cursor, and an explicitly bounded pattern matcher, declaring no word,
// sentence, or line segmentation, case folding, collation, formatting, parsing, captures,
// backtracking, host regular-expression semantics, or locale.
pub use text::{
    CaseMapping, NormalizationForm, PATTERN_INSTRUCTION_BOUND, PATTERN_REPEAT_BOUND,
    PATTERN_SCALAR_BOUND, PATTERN_STEP_BOUND, Pattern, TEXT_CLAUSES, TEXT_VALUE_SCALAR_BOUND,
    TextBuilder, TextDiagnosticCode, TextError, TextGraphemes, TextOrdering, TextRange,
    TextScalars, TextValue,
};
// The Section 40 deterministic numeric foundation is declaration-only: it publishes the versioned
// deterministic generator identity and its exact step, with no host entropy, global state, secure
// randomness, streaming, durability, quota, schema, recovery, encoding, or machine representation.
pub use prng::{
    DeterministicPrng, NUM_CLAUSES, PRNG_ALGORITHM, PRNG_ALGORITHM_VERSION, PRNG_MIX_FIRST,
    PRNG_MIX_SECOND, PRNG_STATE_INCREMENT, PrngAlgorithmVersion,
};
// The Section 40 numeric algorithms are declaration-only primitives: the checked integer and bit
// operations publish exact canonical values or exactly one declared deterministic failure, and the
// finite-float algorithms publish exact canonical values only, and the canonical numeric text
// helpers publish exactly the canonical spelling of a value. The canonical integer overflow modes
// apply the declared modes to the algorithms without any implicit wrapping or saturation, masking,
// coercion, implicit widening, ambient rounding, locale formatting, or host dependence.
pub use numeric::{
    BinaryBitOperation, BinaryFloatAlgorithm, CheckedIntegerAlgorithm, NEGATE_WIRE_NAME,
    NumericConversion, UnaryBitOperation, UnaryFloatAlgorithm, apply_in_mode, float_to_int,
    format_canonical_float, format_canonical_int, int_to_float, negate, parse_canonical_float,
    parse_canonical_int,
};
// The Section 34 standard-library architecture model is declaration-only: it records
// the logical package hierarchy, its dependency DAG, the edition prelude, facade
// identity, stability tiers, applicability, and the aggregate manifest without any
// physical repository layout entering an identity.
pub use std_hierarchy::canonical_std_hierarchy;
pub use stdlib::{
    CANONICAL_PRELUDE_EDITION, CANONICAL_PRELUDE_MEMBERS, FacadeReexport, FeatureSelection,
    MAX_STD_NAME_BYTES, MAX_STD_PACKAGES, NameClass, PRELUDE_BINDINGS, PackageFamily, Prelude,
    PreludeBinding, Relocation, STD_PRESENTATION_REFUSALS, STDLIB_CLAUSES, STDLIB_NON_CLAIM_ORDER,
    STDLIB_NON_CLAIMS, SelectedInstance, StabilityTier, StabilityTransition, StdContractVersion,
    StdDeprecation, StdGraph, StdGraphIdentity, StdInterfaceIdentity, StdItem, StdManifest,
    StdManifestEntry, StdName, StdPackage, StdPathInspection, StdPresentation,
    StdlibDiagnosticCode, StdlibError, StdlibNonClaim, StdlibNonClaimAssertion,
    admit_tooling_inputs, canonical_pure_hierarchy, check_layout_identity, check_stdlib_non_claims,
    inspect_presentation, require_applicable,
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
pub use test_support::{
    STD_TEST_ADMITTED_MODE, STD_TEST_CLASS, STD_TEST_NON_CLAIMS, STD_TEST_PACKAGE,
    STD_TEST_TARGET_KIND, STD_TEST_TIER, TestDiscoveryRefusal, TestExecutionRule,
    TestHarnessCapability, TestKind, TestRunPlan, TestRunRefusal, TestSubstitution,
    TestSubstitutionRefusal, bound_test_requirement, canonical_wire_name, declare_test_discovery,
    declare_test_run, declare_test_substitutions, may_acquire_ambient_authority, std_test_family,
    test_target_is_shipping_authority,
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
pub use scalar::{
    ByteBufferValue, ByteValue, BytesValue, CharValue, IntegerValue, OverflowMode, SCALAR_CLAUSES,
    ScalarDiagnosticCode, ScalarError, ScalarKind, ScalarNonClaimAssertion, ScalarNonClaimName,
    ScalarQuota, ScalarWidth, StorageStrategy, check_scalar_non_claims,
};

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
pub use workspace::{
    ContentDigest, DependencyRequirement, DependencySource, LockPolicy, MemberManifest,
    PackageRelease, ResolvedInstance, ResolvedWorkspace, SourceLocator, SourceRevision,
    WorkspaceDiagnosticCode, WorkspaceError, WorkspaceLockfile, WorkspaceManifest, solve,
    solve_with_policy, sync_lockfile,
};
