//! Public syntax-only package activity coordinator.
//!
//! The facade owns activity admission and identity allocation. Frontend code
//! owns source judgments, while `gantry-observe` owns event occurrence metadata
//! and optional delivery settlement.

use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

use gantry_core::event::{EventDraft, EventEnvelope};
#[cfg(feature = "analyzer")]
use gantry_core::event::{PackageEventPhase, package_phase_event_payload};
use gantry_core::identity::ProtocolIdentity;
#[cfg(feature = "analyzer")]
use gantry_core::portable::EventKind;
use gantry_core::portable::{IdentityKind, ProtocolFamily};
use gantry_core::protocol::ProtocolSelection;
use gantry_core::source::FrontendLimits;
#[cfg(feature = "analyzer")]
use gantry_core::source::StructuredDiagnostic;
#[cfg(feature = "analyzer")]
use gantry_frontend::PackageSyntaxStatus;
use gantry_frontend::{
    CompletedSyntaxPhase, PackageSyntaxError, PackageSyntaxStep, PackageSyntaxWork,
    RootDirectorySourceProvider, SourceProvider,
};
use gantry_host::containment::{
    AdapterPoison, catch_integration, contain_integration_future, drop_integration,
};
use gantry_host::contracts::{
    BlockingJobCompletion, BlockingWorkService, BlockingWorkSubmitError, FreshIdentityAllocator,
    IdentityAllocationError, IdentitySource, SubmittedBlockingJob, UtcClock,
};
use gantry_host::event::EventDeliveryRuntime;
use gantry_observe::{
    ActivityBarrier, ActivityDeliveryResult, DeliveryError, DeliveryKernel, EventCompleter,
    EventCompletionError, SinkPlan,
};

#[cfg(feature = "analyzer")]
use gantry_analysis::{
    AnalysisError, AnalysisStatus, GenericTypeFact, TypeBinder, TypedPackage,
    analyze_package_types_with_limits,
};
#[cfg(feature = "analyzer")]
use gantry_ir::{
    CanonicalIr, CanonicalSourceMap, ConcreteEffect, ConcreteInstantiation, ConcreteSourceMapEntry,
    ExecutableProjection, GeneratedSchemaObject, GenericTemplate, ImplementationHead,
    PackageSourceManifest, ResolvedCall, TraitContract,
};

/// One syntax-only package validation request.
pub struct ValidatePackageRequest<'a> {
    /// Package directory containing `main.gnt`.
    pub package_root: &'a Path,
    /// Exact complete protocol tuple selected for the activity.
    pub protocol_selection: &'a ProtocolSelection,
    /// Finite positive source, token, and diagnostic limits.
    pub frontend_limits: FrontendLimits,
    /// Optional immutable nondurable event sink plan.
    pub event_delivery: Option<&'a SinkPlan>,
}

/// Successful validation result, including the observable parse occurrence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatePackageResult {
    /// Fresh identity allocated before package discovery.
    pub activity_id: ProtocolIdentity,
    /// Deterministic syntax judgment and immutable source evidence.
    pub phase: CompletedSyntaxPhase,
    /// Exactly one completed physical-layer parse event.
    pub event: EventEnvelope,
    /// Optional finite sink settlement and required-sink barrier.
    pub delivery: Option<ActivityDeliveryResult>,
}

/// Operational failure for which no package judgment is returned.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ValidatePackageError {
    /// Activity identity allocation failed before discovery.
    ActivityIdentity(IdentityAllocationError),
    /// Source discovery or syntax processing failed operationally.
    Package(PackageSyntaxError),
    /// Bounded blocking admission or execution failed operationally.
    BlockingWork(PackageBlockingWorkError),
    /// Event identity, clock, or envelope completion failed after parsing.
    Event(EventCompletionError),
    /// An event plan was supplied without a delivery runtime.
    MissingDeliveryRuntime,
    /// Event delivery could not reach a finite settlement.
    Delivery(DeliveryError),
    /// A required sink exhausted after the parse occurrence was created.
    RequiredEventDelivery,
}

impl ValidatePackageError {
    /// Returns a stable operational code suitable for CLI and embedding maps.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::ActivityIdentity(_) => "identity-generation-failure",
            Self::Package(error) => error.code(),
            Self::BlockingWork(error) => error.code(),
            Self::Event(EventCompletionError::Identity(_)) => "identity-generation-failure",
            Self::Event(EventCompletionError::Clock(_)) => "executor-failure",
            Self::Event(_) => "internal",
            Self::MissingDeliveryRuntime | Self::Delivery(_) | Self::RequiredEventDelivery => {
                "required-event-delivery-failure"
            }
        }
    }
}

impl std::fmt::Display for ValidatePackageError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for ValidatePackageError {}

/// Stable package-operation failure at the blocking-work boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PackageBlockingWorkError {
    /// The configured bounded queue refused admission without waiting.
    CapacityExhausted,
    /// Submission, execution, completion, or result transfer failed.
    Internal,
}

impl PackageBlockingWorkError {
    /// Returns the exact pre-execution operational category.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::CapacityExhausted => "implementation-resource-exhaustion",
            Self::Internal => "internal",
        }
    }
}

impl std::fmt::Display for PackageBlockingWorkError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for PackageBlockingWorkError {}

#[derive(Clone, Debug, Eq, PartialEq)]
enum PackageEventError {
    Event(EventCompletionError),
    MissingDeliveryRuntime,
    Delivery(DeliveryError),
    RequiredEventDelivery,
}

impl From<PackageEventError> for ValidatePackageError {
    fn from(error: PackageEventError) -> Self {
        match error {
            PackageEventError::Event(error) => Self::Event(error),
            PackageEventError::MissingDeliveryRuntime => Self::MissingDeliveryRuntime,
            PackageEventError::Delivery(error) => Self::Delivery(error),
            PackageEventError::RequiredEventDelivery => Self::RequiredEventDelivery,
        }
    }
}

/// Source judgment returned by semantic package analysis.
#[cfg(feature = "analyzer")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnalyzePackageStatus {
    /// Syntax and every applicable static semantic rule were accepted.
    SourceValid,
    /// Syntax or static semantic diagnostics rejected the package.
    SourceInvalid,
}

#[cfg(feature = "analyzer")]
impl AnalyzePackageStatus {
    /// Returns the exact embedding and CLI result spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::SourceValid => "source-valid",
            Self::SourceInvalid => "source-invalid",
        }
    }
}

/// One semantic package-analysis request.
#[cfg(feature = "analyzer")]
pub struct AnalyzePackageRequest<'a> {
    /// Package directory containing `main.gnt`.
    pub package_root: &'a Path,
    /// Exact complete protocol tuple selected for the activity.
    pub protocol_selection: &'a ProtocolSelection,
    /// Finite source, diagnostic, and artifact limits.
    pub frontend_limits: FrontendLimits,
    /// Optional immutable nondurable event sink plan.
    pub event_delivery: Option<&'a SinkPlan>,
}

/// Completed semantic package result and its ordered physical events.
#[cfg(feature = "analyzer")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnalyzePackageResult {
    /// Fresh identity shared by every event in this package activity.
    pub activity_id: ProtocolIdentity,
    /// Exact source-valid or source-invalid judgment.
    pub status: AnalyzePackageStatus,
    /// Immutable syntax phase over which analysis was attempted.
    pub syntax: CompletedSyntaxPhase,
    /// Semantic result when syntax was valid enough to run analysis.
    pub analysis: Option<TypedPackage>,
    /// Parse followed by analysis when semantic analysis ran; otherwise parse only.
    pub events: Vec<EventEnvelope>,
    /// Optional delivery settlements in the same order as `events`.
    pub deliveries: Option<Vec<ActivityDeliveryResult>>,
}

/// Source-valid canonical artifacts returned by semantic package analysis.
///
/// This borrowed facade DTO keeps artifact ownership in [`TypedPackage`] while
/// allowing embedding consumers to obtain every versioned output directly.
#[cfg(feature = "analyzer")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnalyzePackageArtifacts<'a> {
    /// Immutable package-source audit manifest.
    pub package_source_manifest: &'a PackageSourceManifest,
    /// Canonical analysis IR, including generic facts and the closed projection.
    pub canonical_ir: &'a CanonicalIr,
    /// Canonical source map, including multi-origin concrete entries.
    pub source_map: &'a CanonicalSourceMap,
    /// Deduplicated concrete schemas for every exposed boundary root.
    pub schemas: &'a GeneratedSchemaObject,
}

/// Structured generic and trait facts returned by source-valid analysis.
///
/// Concrete instantiation arguments are the complete inferred substitutions;
/// their concrete identities and source-origin entries let tools associate
/// those substitutions with call and constructor sites without parsing text.
#[cfg(feature = "analyzer")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnalyzePackageGenericFacts<'a> {
    /// Authored generic binders in canonical declaration-span order.
    pub binders: &'a [TypeBinder],
    /// Open and closed authored type expressions with optional concrete forms.
    pub types: &'a [GenericTypeFact],
    /// Canonical source trait contracts.
    pub traits: &'a [TraitContract],
    /// Canonical inherent and trait implementation heads.
    pub implementations: &'a [ImplementationHead],
    /// Generic declared-type and callable templates.
    pub templates: &'a [GenericTemplate],
    /// Retained applications whose ordered arguments are complete substitutions.
    pub instantiations: &'a [ConcreteInstantiation],
    /// Statically resolved direct calls and selected implementation identities.
    pub resolved_calls: &'a [ResolvedCall],
    /// Exact least-fixed-point effects for concrete callables.
    pub concrete_effects: &'a [ConcreteEffect],
    /// Canonical declaration and multi-origin mappings for concrete identities.
    pub source_origins: &'a [ConcreteSourceMapEntry],
    /// Runtime-facing projection containing only closed types and direct calls.
    pub executable: &'a ExecutableProjection,
}

#[cfg(feature = "analyzer")]
impl AnalyzePackageResult {
    /// Returns ordered structured diagnostics for syntax or semantic analysis.
    ///
    /// Machine consumers should inspect these fields rather than rendered CLI
    /// text. Syntax-invalid activities obtain diagnostics from the syntax phase.
    #[must_use]
    pub fn diagnostics(&self) -> &[StructuredDiagnostic] {
        self.analysis.as_ref().map_or_else(
            || self.syntax.diagnostics(),
            |analysis| analysis.diagnostics(),
        )
    }

    /// Returns all source-valid canonical artifacts without copying their bytes.
    ///
    /// ```
    /// # fn inspect(result: &gantry::AnalyzePackageResult) {
    /// if let Some(artifacts) = result.artifacts() {
    ///     assert!(!artifacts.canonical_ir.artifact().canonical_bytes().is_empty());
    ///     assert!(!artifacts.schemas.entries().is_empty());
    /// }
    /// # }
    /// ```
    #[must_use]
    pub fn artifacts(&self) -> Option<AnalyzePackageArtifacts<'_>> {
        let analysis = self.analysis.as_ref()?;
        Some(AnalyzePackageArtifacts {
            package_source_manifest: analysis.manifest()?,
            canonical_ir: analysis.canonical_ir()?,
            source_map: analysis.source_map()?,
            schemas: analysis.schemas()?,
        })
    }

    /// Returns structured generic facts and the distinct closed projection.
    ///
    /// ```
    /// # fn inspect(result: &gantry::AnalyzePackageResult) {
    /// if let Some(facts) = result.generic_facts() {
    ///     for instantiation in facts.instantiations {
    ///         for argument in instantiation.arguments() {
    ///             assert!(!argument.canonical_string().contains('^'));
    ///         }
    ///     }
    /// }
    /// # }
    /// ```
    #[must_use]
    pub fn generic_facts(&self) -> Option<AnalyzePackageGenericFacts<'_>> {
        let analysis = self.analysis.as_ref()?;
        let canonical_ir = analysis.canonical_ir()?;
        let generic = canonical_ir.generic_facts();
        Some(AnalyzePackageGenericFacts {
            binders: analysis.type_binders(),
            types: analysis.generic_types(),
            traits: generic.traits(),
            implementations: generic.implementations(),
            templates: generic.templates(),
            instantiations: generic.instantiations(),
            resolved_calls: generic.resolved_calls(),
            concrete_effects: generic.concrete_effects(),
            source_origins: generic.source_map(),
            executable: generic.executable(),
        })
    }
}

/// Operational failure for which no source judgment is returned.
#[cfg(feature = "analyzer")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AnalyzePackageError {
    /// Activity identity allocation failed before discovery.
    ActivityIdentity(IdentityAllocationError),
    /// Source discovery or syntax processing failed operationally.
    Package(PackageSyntaxError),
    /// Bounded blocking admission or execution failed operationally.
    BlockingWork(PackageBlockingWorkError),
    /// Semantic analysis failed before producing a source judgment.
    Analysis(AnalysisError),
    /// Event identity, clock, or envelope completion failed.
    Event(EventCompletionError),
    /// An event plan was supplied without a delivery runtime.
    MissingDeliveryRuntime,
    /// Event delivery could not reach a finite settlement.
    Delivery(DeliveryError),
    /// A required sink exhausted before the activity could return its judgment.
    RequiredEventDelivery,
}

#[cfg(feature = "analyzer")]
impl AnalyzePackageError {
    /// Returns a stable operational code suitable for CLI and embedding maps.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::ActivityIdentity(_) => "identity-generation-failure",
            Self::Package(error) => error.code(),
            Self::BlockingWork(error) => error.code(),
            Self::Analysis(AnalysisError::ResourceLimit { .. }) => "frontend-resource-limit",
            Self::Analysis(AnalysisError::SyntaxInvalid | AnalysisError::Invariant) => "internal",
            Self::Event(EventCompletionError::Identity(_)) => "identity-generation-failure",
            Self::Event(EventCompletionError::Clock(_)) => "executor-failure",
            Self::Event(_) => "internal",
            Self::MissingDeliveryRuntime | Self::Delivery(_) | Self::RequiredEventDelivery => {
                "required-event-delivery-failure"
            }
        }
    }
}

#[cfg(feature = "analyzer")]
impl std::fmt::Display for AnalyzePackageError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}

#[cfg(feature = "analyzer")]
impl std::error::Error for AnalyzePackageError {}

#[cfg(feature = "analyzer")]
impl From<PackageEventError> for AnalyzePackageError {
    fn from(error: PackageEventError) -> Self {
        match error {
            PackageEventError::Event(error) => Self::Event(error),
            PackageEventError::MissingDeliveryRuntime => Self::MissingDeliveryRuntime,
            PackageEventError::Delivery(error) => Self::Delivery(error),
            PackageEventError::RequiredEventDelivery => Self::RequiredEventDelivery,
        }
    }
}

/// Stateless composition of frontend and observation services.
pub struct ValidatePackageCoordinator<'a> {
    allocator: &'a FreshIdentityAllocator,
    identity_source: &'a dyn IdentitySource,
    clock: &'a dyn UtcClock,
    blocking_work: &'a dyn BlockingWorkService,
    blocking_work_poison: AdapterPoison,
    delivery_runtime: Option<&'a dyn EventDeliveryRuntime>,
}

impl<'a> ValidatePackageCoordinator<'a> {
    /// Constructs a coordinator without configured event delivery.
    #[must_use]
    pub fn new(
        allocator: &'a FreshIdentityAllocator,
        identity_source: &'a dyn IdentitySource,
        clock: &'a dyn UtcClock,
        blocking_work: &'a dyn BlockingWorkService,
    ) -> Self {
        Self {
            allocator,
            identity_source,
            clock,
            blocking_work,
            blocking_work_poison: AdapterPoison::default(),
            delivery_runtime: None,
        }
    }

    /// Shares the adapter poison state across coordinators for one interpreter.
    #[must_use]
    pub fn with_blocking_work_poison(mut self, poison: AdapterPoison) -> Self {
        self.blocking_work_poison = poison;
        self
    }

    /// Supplies the executor-neutral runtime used only when a sink plan exists.
    #[must_use]
    pub const fn with_delivery_runtime(mut self, runtime: &'a dyn EventDeliveryRuntime) -> Self {
        self.delivery_runtime = Some(runtime);
        self
    }

    /// Allocates the activity, validates one immutable package snapshot,
    /// completes one parse occurrence, and settles optional delivery.
    pub async fn validate(
        &self,
        request: ValidatePackageRequest<'_>,
    ) -> Result<ValidatePackageResult, ValidatePackageError> {
        let source_language = request
            .protocol_selection
            .version(ProtocolFamily::SourceLanguage);
        debug_assert_eq!((source_language.major, source_language.minor), (1, 0));
        let activity_id = self
            .allocator
            .allocate(self.identity_source, IdentityKind::Activity)
            .map_err(ValidatePackageError::ActivityIdentity)?;
        let phase = self
            .run_syntax(request.package_root, request.frontend_limits)
            .await
            .map_err(|error| match error {
                PackageSyntaxRunError::Package(error) => ValidatePackageError::Package(error),
                PackageSyntaxRunError::Blocking(error) => ValidatePackageError::BlockingWork(error),
            })?;
        let draft = phase.event_draft().clone();
        let (event, delivery) = self
            .complete_and_deliver(activity_id, draft, request.event_delivery)
            .await
            .map_err(ValidatePackageError::from)?;
        Ok(ValidatePackageResult {
            activity_id,
            phase,
            event,
            delivery,
        })
    }

    #[cfg(feature = "analyzer")]
    /// Allocates one activity, completes syntax validation, runs semantic
    /// analysis only for syntax-valid input, and emits ordered physical events.
    pub async fn analyze(
        &self,
        request: AnalyzePackageRequest<'_>,
    ) -> Result<AnalyzePackageResult, AnalyzePackageError> {
        let source_language = request
            .protocol_selection
            .version(ProtocolFamily::SourceLanguage);
        debug_assert_eq!((source_language.major, source_language.minor), (1, 0));
        let activity_id = self
            .allocator
            .allocate(self.identity_source, IdentityKind::Activity)
            .map_err(AnalyzePackageError::ActivityIdentity)?;
        let syntax = self
            .run_syntax(request.package_root, request.frontend_limits)
            .await
            .map_err(|error| match error {
                PackageSyntaxRunError::Package(error) => AnalyzePackageError::Package(error),
                PackageSyntaxRunError::Blocking(error) => AnalyzePackageError::BlockingWork(error),
            })?;

        let (parse_event, parse_delivery) = self
            .complete_and_deliver(
                activity_id,
                syntax.event_draft().clone(),
                request.event_delivery,
            )
            .await
            .map_err(AnalyzePackageError::from)?;
        let mut events = vec![parse_event];
        let mut deliveries = parse_delivery.map(|delivery| vec![delivery]);

        if syntax.status() == PackageSyntaxStatus::Invalid {
            return Ok(AnalyzePackageResult {
                activity_id,
                status: AnalyzePackageStatus::SourceInvalid,
                syntax,
                analysis: None,
                events,
                deliveries,
            });
        }

        let limits = request.frontend_limits;
        let (syntax, analysis) =
            run_blocking_job(self.blocking_work, &self.blocking_work_poison, move || {
                let analysis = analyze_package_types_with_limits(&syntax, limits);
                (syntax, analysis)
            })
            .await
            .map_err(AnalyzePackageError::BlockingWork)?;
        let analysis = analysis.map_err(AnalyzePackageError::Analysis)?;
        let status = if analysis.status() == AnalysisStatus::Valid {
            AnalyzePackageStatus::SourceValid
        } else {
            AnalyzePackageStatus::SourceInvalid
        };
        let analysis_draft = EventDraft::new(
            EventKind::Analysis,
            package_phase_event_payload(
                PackageEventPhase::Analysis,
                status == AnalyzePackageStatus::SourceValid,
                analysis.diagnostics(),
            ),
        );
        let (analysis_event, analysis_delivery) = self
            .complete_and_deliver(activity_id, analysis_draft, request.event_delivery)
            .await
            .map_err(AnalyzePackageError::from)?;
        events.push(analysis_event);
        if let (Some(deliveries), Some(delivery)) = (&mut deliveries, analysis_delivery) {
            deliveries.push(delivery);
        }

        Ok(AnalyzePackageResult {
            activity_id,
            status,
            syntax,
            analysis: Some(analysis),
            events,
            deliveries,
        })
    }

    async fn run_syntax(
        &self,
        package_root: &Path,
        limits: FrontendLimits,
    ) -> Result<CompletedSyntaxPhase, PackageSyntaxRunError> {
        let root = package_root.to_path_buf();
        let provider =
            run_blocking_job(self.blocking_work, &self.blocking_work_poison, move || {
                RootDirectorySourceProvider::open(&root)
            })
            .await
            .map_err(PackageSyntaxRunError::Blocking)?
            .map_err(|error| PackageSyntaxRunError::Package(PackageSyntaxError::Source(error)))?;
        let provider: Arc<dyn SourceProvider> = Arc::new(provider);
        let mut step = PackageSyntaxWork::begin(
            limits.source_limits(),
            limits.maximum_constructed_type_depth(),
        )
        .map_err(PackageSyntaxRunError::Package)?;
        loop {
            step = match step {
                PackageSyntaxStep::Acquire(work, request) => {
                    let owned_request = request.clone();
                    let provider = Arc::clone(&provider);
                    let acquisition = run_blocking_job(
                        self.blocking_work,
                        &self.blocking_work_poison,
                        move || owned_request.acquire(provider.as_ref()),
                    )
                    .await
                    .map_err(PackageSyntaxRunError::Blocking)?;
                    run_blocking_job(self.blocking_work, &self.blocking_work_poison, move || {
                        work.accept_acquisition(request, acquisition)
                    })
                    .await
                    .map_err(PackageSyntaxRunError::Blocking)?
                    .map_err(PackageSyntaxRunError::Package)?
                }
                PackageSyntaxStep::Parse(work) => {
                    run_blocking_job(self.blocking_work, &self.blocking_work_poison, move || {
                        work.parse_next()
                    })
                    .await
                    .map_err(PackageSyntaxRunError::Blocking)?
                    .map_err(PackageSyntaxRunError::Package)?
                }
                PackageSyntaxStep::Complete(phase) => return Ok(phase),
            };
        }
    }

    #[cfg(feature = "evaluator")]
    pub(crate) async fn deliver_completed_events(
        &self,
        events: &[EventEnvelope],
        plan: Option<&SinkPlan>,
    ) -> Result<Option<Vec<ActivityDeliveryResult>>, AnalyzePackageError> {
        let Some(plan) = plan else {
            return Ok(None);
        };
        let mut deliveries = Vec::with_capacity(events.len());
        for event in events {
            deliveries.push(
                self.deliver_completed_event(event.clone(), plan)
                    .await
                    .map_err(AnalyzePackageError::from)?,
            );
        }
        Ok(Some(deliveries))
    }

    async fn complete_and_deliver(
        &self,
        activity_id: ProtocolIdentity,
        draft: EventDraft,
        plan: Option<&SinkPlan>,
    ) -> Result<(EventEnvelope, Option<ActivityDeliveryResult>), PackageEventError> {
        let event = EventCompleter::new(self.allocator, self.identity_source, self.clock)
            .complete(activity_id, draft)
            .await
            .map_err(PackageEventError::Event)?;
        let delivery = match plan {
            Some(plan) => Some(self.deliver_completed_event(event.clone(), plan).await?),
            None => None,
        };
        Ok((event, delivery))
    }

    async fn deliver_completed_event(
        &self,
        event: EventEnvelope,
        plan: &SinkPlan,
    ) -> Result<ActivityDeliveryResult, PackageEventError> {
        if plan.registrations().is_empty() {
            return Ok(ActivityDeliveryResult {
                barrier: ActivityBarrier::Delivered,
                settlements: Vec::new(),
            });
        }
        let runtime = self
            .delivery_runtime
            .ok_or(PackageEventError::MissingDeliveryRuntime)?;
        let result = DeliveryKernel::new(self.allocator, self.identity_source, runtime)
            .deliver(event, &[], plan)
            .await
            .map_err(PackageEventError::Delivery)?;
        if matches!(result.barrier, ActivityBarrier::RequiredExhausted { .. }) {
            return Err(PackageEventError::RequiredEventDelivery);
        }
        Ok(result)
    }
}

enum PackageSyntaxRunError {
    Package(PackageSyntaxError),
    Blocking(PackageBlockingWorkError),
}

struct CancelQueuedOnDrop {
    handle: Option<Arc<dyn SubmittedBlockingJob>>,
    poison: AdapterPoison,
    settled: bool,
}

impl CancelQueuedOnDrop {
    fn finish(mut self) -> Result<(), PackageBlockingWorkError> {
        self.settled = true;
        drop_integration(&self.poison, &mut self.handle)
            .map_err(|_| PackageBlockingWorkError::Internal)
    }
}

impl Drop for CancelQueuedOnDrop {
    fn drop(&mut self) {
        if !self.settled {
            let _ = self
                .handle
                .as_ref()
                .map(|handle| catch_integration(&self.poison, || handle.cancel_before_start()));
        }
        let _ = drop_integration(&self.poison, &mut self.handle);
    }
}

async fn run_blocking_job<T, F>(
    service: &dyn BlockingWorkService,
    poison: &AdapterPoison,
    work: F,
) -> Result<T, PackageBlockingWorkError>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let result = Arc::new(Mutex::new(None));
    let job_result = Arc::clone(&result);
    let job = Box::new(move || {
        *lock_package_result(&job_result) = Some(work());
    });
    let handle = catch_integration(poison, || service.submit(job))
        .map_err(|_| PackageBlockingWorkError::Internal)?
        .map_err(|error| match error {
            BlockingWorkSubmitError::CapacityExhausted => {
                PackageBlockingWorkError::CapacityExhausted
            }
            BlockingWorkSubmitError::Failed(_) => PackageBlockingWorkError::Internal,
        })?;
    let handle_poison = AdapterPoison::default();
    let cancellation = CancelQueuedOnDrop {
        handle: Some(handle),
        poison: handle_poison.clone(),
        settled: false,
    };
    let observer = cancellation
        .handle
        .as_ref()
        .ok_or(PackageBlockingWorkError::Internal)?;
    let completion = catch_integration(&handle_poison, || observer.completion())
        .map_err(|_| PackageBlockingWorkError::Internal)?;
    let completion = contain_integration_future(completion, handle_poison)
        .await
        .map_err(|_| PackageBlockingWorkError::Internal)?;
    cancellation.finish()?;
    match completion {
        BlockingJobCompletion::Completed => lock_package_result(&result)
            .take()
            .ok_or(PackageBlockingWorkError::Internal),
        BlockingJobCompletion::CancelledBeforeStart
        | BlockingJobCompletion::Panicked
        | BlockingJobCompletion::Failed(_) => Err(PackageBlockingWorkError::Internal),
    }
}

fn lock_package_result<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::fs;
    use std::future::Future;
    use std::path::PathBuf;
    use std::pin::pin;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::task::{Context, Poll, Waker};

    use gantry_core::portable::{
        EventLayer, IdentityKind, PORTABLE_SPECIFICATION_REVISION, PROTOCOL_FAMILY_DEFINITIONS,
    };
    use gantry_core::protocol::{ProtocolSelection, ProtocolVersion, SelectedProtocol};
    use gantry_core::source::FrontendLimits;
    use gantry_core::timestamp::UtcTimestamp;
    use gantry_frontend::PackageSyntaxStatus;
    use gantry_host::contracts::{HostError, HostFuture, IdentitySource, UtcClock};

    use super::{ValidatePackageCoordinator, ValidatePackageError, ValidatePackageRequest};
    use crate::host::contracts::FreshIdentityAllocator;

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    struct TempDirectory(PathBuf);

    impl TempDirectory {
        fn new(source: &[u8]) -> Self {
            let suffix = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "gantry-validate-package-{}-{suffix}",
                std::process::id()
            ));
            assert!(fs::create_dir(&path).is_ok());
            assert!(fs::write(path.join("main.gnt"), source).is_ok());
            Self(path)
        }
    }

    impl Drop for TempDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct ScriptedIdentitySource(Mutex<VecDeque<Result<[u8; 32], HostError>>>);

    impl IdentitySource for ScriptedIdentitySource {
        fn fresh_material(&self, _kind: IdentityKind) -> Result<[u8; 32], HostError> {
            self.0
                .lock()
                .map_err(|_| failure("identity-state"))?
                .pop_front()
                .unwrap_or_else(|| Err(failure("identity-exhausted")))
        }
    }

    struct FixedClock;

    impl UtcClock for FixedClock {
        fn utc_now<'a>(&'a self) -> HostFuture<'a, Result<UtcTimestamp, HostError>> {
            Box::pin(async { UtcTimestamp::from_unix_seconds(0, 7).map_err(|_| failure("clock")) })
        }
    }

    #[test]
    fn activity_identity_precedes_discovery_and_parse_event_metadata() {
        let root = TempDirectory::new(b"fn main() {}");
        let identities =
            ScriptedIdentitySource(Mutex::new(VecDeque::from([Ok([1; 32]), Ok([2; 32])])));
        let allocator = FreshIdentityAllocator::default();
        let blocking = gantry_runtime::BoundedBlockingWorkService::new(8, 8)
            .unwrap_or_else(|_| unreachable!("positive test capacities"));
        let coordinator =
            ValidatePackageCoordinator::new(&allocator, &identities, &FixedClock, &blocking);
        let selection = selection();
        let result = block_on(coordinator.validate(request(&root.0, &selection)));
        assert!(result.is_ok());
        let result = result.unwrap_or_else(|_| unreachable!("checked above"));
        assert_eq!(result.activity_id.kind(), IdentityKind::Activity);
        assert_eq!(result.event.event_id().kind(), IdentityKind::Event);
        assert_eq!(result.event.activity_id(), result.activity_id);
        assert_eq!(result.event.layer(), EventLayer::Physical);
        assert_eq!(result.phase.status(), PackageSyntaxStatus::Valid);
        assert!(result.event.execution_id().is_none());
    }

    #[test]
    fn identity_failure_returns_before_package_discovery() {
        let missing = std::env::temp_dir().join("gantry-validation-missing-root");
        let identities = ScriptedIdentitySource(Mutex::new(VecDeque::from([Err(failure(
            "identity-source-failure",
        ))])));
        let allocator = FreshIdentityAllocator::default();
        let blocking = gantry_runtime::BoundedBlockingWorkService::new(8, 8)
            .unwrap_or_else(|_| unreachable!("positive test capacities"));
        let coordinator =
            ValidatePackageCoordinator::new(&allocator, &identities, &FixedClock, &blocking);
        let selection = selection();
        let result = block_on(coordinator.validate(request(&missing, &selection)));
        assert!(matches!(
            result,
            Err(ValidatePackageError::ActivityIdentity(_))
        ));
    }

    fn request<'a>(
        root: &'a std::path::Path,
        selection: &'a ProtocolSelection,
    ) -> ValidatePackageRequest<'a> {
        ValidatePackageRequest {
            package_root: root,
            protocol_selection: selection,
            frontend_limits: FrontendLimits::new(
                32, 1_048_576, 4_194_304, 262_144, 256, 4_194_304, 4_194_304, 4_194_304, 4_194_304,
                256, 65_536, 1_000_000,
            )
            .unwrap_or_else(|_| unreachable!("positive limits")),
            event_delivery: None,
        }
    }

    fn selection() -> ProtocolSelection {
        ProtocolSelection::new(
            PORTABLE_SPECIFICATION_REVISION,
            PROTOCOL_FAMILY_DEFINITIONS
                .iter()
                .map(|definition| SelectedProtocol {
                    family: definition.family,
                    version: ProtocolVersion {
                        major: definition.major,
                        minor: definition.minor,
                    },
                })
                .collect(),
        )
        .unwrap_or_else(|_| unreachable!("published selection"))
    }

    fn failure(code: &str) -> HostError {
        HostError {
            code: code.into(),
            protected_diagnostic: None,
        }
    }

    fn block_on<F: Future>(future: F) -> F::Output {
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        let mut future = pin!(future);
        loop {
            match future.as_mut().poll(&mut context) {
                Poll::Ready(output) => return output,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }
}
