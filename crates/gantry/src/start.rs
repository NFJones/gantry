//! Public nondurable pre-execution coordination and acceptance.

use std::fmt;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;

use gantry_analysis::{AnalysisStatus, TypedPackage};
use gantry_core::canonical_json::CanonicalJson;
use gantry_core::event::EventEnvelope;
use gantry_core::identity::ProtocolIdentity;
use gantry_core::portable::{IdentityKind, StartFailureCategory};
use gantry_core::protocol::{ProtocolAdvertisement, ProtocolSelection};
use gantry_core::schema::{NormalizationError, SchemaValidator, ValidationError};
use gantry_core::strict_json::{JsonError, JsonLimits, JsonNode, StrictJsonDocument};
pub use gantry_host::contracts::{ActionMappingRevision, AgentMappingRevision, MappingRevisions};
use gantry_host::contracts::{
    EmbeddingVersion, EnvelopeError, FreshIdentityAllocator, HostError, HostRequest, HostResponse,
    IdentityAllocationError, IntegrationPreflight,
};
use gantry_host::embedding::EmbeddingOperation;
use gantry_ir::TypeDescriptor;
use gantry_observe::{ActivityDeliveryResult, SinkPlan};
use gantry_runtime::{
    AcceptExecutionError, AdapterPoison, AdmissionKind, BoundaryFailure, CanonicalTranscriptV1,
    ExecutionHandle, InterpreterConfiguration, InterpreterLifecycle, LifecycleError,
    OperationAdmission, OwnedActivityError,
};

use crate::{
    AnalyzePackageCoordinator, AnalyzePackageError, AnalyzePackageRequest, AnalyzePackageResult,
    AnalyzePackageStatus,
};

pub(crate) type OwnedEventDeliveryFuture = Pin<
    Box<
        dyn Future<Output = Result<Option<Vec<ActivityDeliveryResult>>, AnalyzePackageError>>
            + Send
            + 'static,
    >,
>;
pub(crate) type OwnedEventDeliveryFactory =
    Arc<dyn Fn(Vec<EventEnvelope>, SinkPlan) -> OwnedEventDeliveryFuture + Send + Sync>;

/// One raw optional root-session specification supplied before acceptance.
#[derive(Clone, Copy, Debug)]
pub struct RootSessionSpecification<'a> {
    /// Caller-supplied canonical session identity.
    pub id: ProtocolIdentity,
    /// Optional strict-JSON canonical transcript. Omission means `[]`.
    pub transcript: Option<&'a [u8]>,
    /// Optional opaque integration lookup bytes carried only to new-run preflight.
    pub opaque_lookup_material: Option<&'a [u8]>,
}

/// Root-session provenance retained as Gantry state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootSessionProvenance {
    /// The embedding supplied and resolved the logical session identity.
    EmbedderSupplied,
    /// Gantry allocated a fresh empty root identity.
    GantryCreated,
}

impl RootSessionProvenance {
    const fn wire_name(self) -> &'static str {
        match self {
            Self::EmbedderSupplied => "embedder-supplied",
            Self::GantryCreated => "gantry-created",
        }
    }
}

/// Validated root-session state fixed before execution acceptance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootSessionState {
    /// Stable logical root-session identity.
    pub id: ProtocolIdentity,
    /// Identity ownership class.
    pub provenance: RootSessionProvenance,
    /// Complete normalized canonical transcript JSON.
    pub transcript: CanonicalTranscriptV1,
}

/// One validated and normalized raw entry input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedEntryInput {
    /// Exact static entry parameter type.
    pub ty: TypeDescriptor,
    /// Complete normalized RFC 8785 entry value.
    pub canonical_json: CanonicalJson,
}

/// Public nondurable start request.
pub struct StartExecutionRequest<'a> {
    /// Package directory containing `main.gnt`.
    pub package_root: &'a Path,
    /// Exact selected protocol tuple.
    pub protocol_selection: &'a ProtocolSelection,
    /// Every required peer advertisement for this composition.
    pub required_peers: &'a [ProtocolAdvertisement],
    /// Optional raw strict-JSON entry bytes.
    pub entry_input: Option<&'a [u8]>,
    /// Optional embedder-supplied root session.
    pub root_session: Option<RootSessionSpecification<'a>>,
    /// Optional immutable pre-execution activity event plan.
    pub event_delivery: Option<&'a SinkPlan>,
}

/// Accepted nondurable execution state before or during internally owned `main` evaluation.
#[derive(Clone)]
pub struct StartExecutionAccepted {
    /// Fresh execution identity accepted only at the final boundary.
    pub execution_id: ProtocolIdentity,
    /// In-process observation and cancellation handle.
    pub handle: ExecutionHandle,
    /// Completed parse/analysis activity and its physical events.
    pub package_activity: Box<AnalyzePackageResult>,
    /// Validated entry value, absent when `main` has no parameter.
    pub entry_input: Option<ValidatedEntryInput>,
    /// Root session fixed for the accepted execution.
    pub root_session: RootSessionState,
    /// Agent/action mapping revisions fixed by preflight for this run.
    pub mapping_revisions: MappingRevisions,
    /// Effective event delivery plan fixed for the accepted execution.
    pub(crate) event_delivery: SinkPlan,
    automatic_driver: bool,
}

impl fmt::Debug for StartExecutionAccepted {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StartExecutionAccepted")
            .field("execution_id", &self.execution_id)
            .field("handle", &self.handle)
            .field("package_activity", &self.package_activity)
            .field("entry_input", &self.entry_input)
            .field("root_session", &self.root_session)
            .field("mapping_revisions", &self.mapping_revisions)
            .field("event_delivery", &self.event_delivery.registrations().len())
            .field("automatic_driver", &self.automatic_driver)
            .finish()
    }
}

impl StartExecutionAccepted {
    pub(crate) fn mark_automatic_driver(&mut self) {
        self.automatic_driver = true;
    }

    pub(crate) const fn has_automatic_driver(&self) -> bool {
        self.automatic_driver
    }
}

/// Structured rejection before any execution identity becomes accepted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StartExecutionFailure {
    /// Exact portable start-failure category.
    pub category: StartFailureCategory,
    /// Stable category-local code.
    pub code: Arc<str>,
    /// Completed package activity when rejection occurred after its judgment.
    pub package_activity: Option<Box<AnalyzePackageResult>>,
}

/// Canonical nondurable start result union.
#[derive(Debug)]
pub enum StartExecutionResult {
    /// Successful preflight accepted one in-process execution.
    Accepted(Box<StartExecutionAccepted>),
    /// Pre-acceptance work rejected without an accepted execution identity.
    Rejected(StartExecutionFailure),
}

/// Complete pre-acceptance state retained while an execution crosses its acceptance boundary.
pub(crate) struct PreparedExecutionStart {
    pub(crate) admission: OperationAdmission,
    pub(crate) execution_id: ProtocolIdentity,
    pub(crate) package_activity: AnalyzePackageResult,
    pub(crate) entry_input: Option<ValidatedEntryInput>,
    pub(crate) root_session: RootSessionState,
    pub(crate) mapping_revisions: MappingRevisions,
    pub(crate) event_delivery: SinkPlan,
}

impl PreparedExecutionStart {
    /// Reserves lifecycle ownership before a durable acceptance record is committed.
    #[cfg(feature = "durable")]
    pub(crate) fn reserve_state(&mut self) -> Result<(), StartExecutionFailure> {
        self.admission
            .reserve_execution(self.execution_id)
            .map_err(accept_failure)
    }

    /// Publishes lifecycle state after the durable acceptance record commits.
    #[cfg(feature = "durable")]
    pub(crate) fn accept_reserved_state(
        mut self,
    ) -> Result<StartExecutionAccepted, StartExecutionFailure> {
        let handle = self
            .admission
            .accept_reserved_execution(self.execution_id)
            .map_err(|error| {
                with_package_activity(accept_failure(error), self.package_activity.clone())
            })?;
        Ok(StartExecutionAccepted {
            execution_id: self.execution_id,
            handle,
            package_activity: Box::new(self.package_activity),
            entry_input: self.entry_input,
            root_session: self.root_session,
            mapping_revisions: self.mapping_revisions,
            event_delivery: self.event_delivery,
            automatic_driver: false,
        })
    }

    /// Transfers prepared work into lifecycle state after its acceptance boundary is established.
    pub(crate) fn accept_state(mut self) -> Result<StartExecutionAccepted, StartExecutionFailure> {
        let handle = match self.admission.accept_execution(self.execution_id) {
            Ok(handle) => handle,
            Err(error) => {
                return Err(with_package_activity(
                    accept_failure(error),
                    self.package_activity,
                ));
            }
        };
        Ok(StartExecutionAccepted {
            execution_id: self.execution_id,
            handle,
            package_activity: Box::new(self.package_activity),
            entry_input: self.entry_input,
            root_session: self.root_session,
            mapping_revisions: self.mapping_revisions,
            event_delivery: self.event_delivery,
            automatic_driver: false,
        })
    }

    /// Transfers prepared work into the ordinary nondurable lifecycle acceptance boundary.
    pub(crate) fn accept(self) -> StartExecutionResult {
        match self.accept_state() {
            Ok(accepted) => StartExecutionResult::Accepted(Box::new(accepted)),
            Err(failure) => StartExecutionResult::Rejected(failure),
        }
    }
}

/// Ordered pre-execution coordinator over existing semantic and lifecycle owners.
pub struct StartExecutionCoordinator<'a> {
    pub(crate) package: &'a AnalyzePackageCoordinator<'a>,
    pub(crate) lifecycle: &'a InterpreterLifecycle,
    configuration: &'a InterpreterConfiguration,
    allocator: &'a FreshIdentityAllocator,
    preflight: Arc<dyn IntegrationPreflight>,
    preflight_poison: AdapterPoison,
    owned_event_delivery: Option<OwnedEventDeliveryFactory>,
}

impl<'a> StartExecutionCoordinator<'a> {
    /// Binds package activity, lifecycle, configuration, identity, and preflight owners.
    #[must_use]
    pub fn new(
        package: &'a AnalyzePackageCoordinator<'a>,
        lifecycle: &'a InterpreterLifecycle,
        configuration: &'a InterpreterConfiguration,
        allocator: &'a FreshIdentityAllocator,
        preflight: Arc<dyn IntegrationPreflight>,
    ) -> Self {
        Self {
            package,
            lifecycle,
            configuration,
            allocator,
            preflight,
            preflight_poison: AdapterPoison::default(),
            owned_event_delivery: None,
        }
    }

    /// Supplies an owner factory for caller-independent package-event delivery.
    ///
    /// The factory must retain every runtime, plan, allocator, and identity
    /// dependency needed by the returned future.
    #[must_use]
    #[allow(dead_code)]
    pub(crate) fn with_owned_event_delivery(mut self, factory: OwnedEventDeliveryFactory) -> Self {
        self.owned_event_delivery = Some(factory);
        self
    }

    /// Runs ordered nondurable preflight and accepts before any evaluation or hook creation.
    pub async fn start(&self, request: StartExecutionRequest<'_>) -> StartExecutionResult {
        match self.prepare(request).await {
            Ok(prepared) => prepared.accept(),
            Err(failure) => StartExecutionResult::Rejected(failure),
        }
    }

    /// Runs all shared pre-acceptance work while retaining lifecycle admission ownership.
    pub(crate) async fn prepare(
        &self,
        request: StartExecutionRequest<'_>,
    ) -> Result<PreparedExecutionStart, StartExecutionFailure> {
        let admission = match self.lifecycle.admit(AdmissionKind::NewWork) {
            Ok(admission) => admission,
            Err(error) => return Err(lifecycle_failure(error)),
        };
        let event_delivery = request.event_delivery.cloned().unwrap_or_default();

        for peer in request.required_peers {
            if request.protocol_selection.require_peer(peer).is_err() {
                return Err(failure(
                    StartFailureCategory::IntegrationPreflight,
                    "unsupported-protocol-selection",
                ));
            }
        }

        let mut package_activity = match self
            .package
            .analyze(AnalyzePackageRequest {
                package_root: request.package_root,
                protocol_selection: request.protocol_selection,
                frontend_limits: self.configuration.required().frontend_limits,
                event_delivery: None,
            })
            .await
        {
            Ok(activity) => activity,
            Err(error) => return Err(analyze_failure(error)),
        };
        if package_activity.status != AnalyzePackageStatus::SourceValid {
            let category = if package_activity.analysis.is_some() {
                StartFailureCategory::Analysis
            } else {
                StartFailureCategory::Syntax
            };
            return Err(with_package_activity(
                failure(category, "source-invalid"),
                package_activity,
            ));
        }

        let analysis = package_activity
            .analysis
            .as_ref()
            .unwrap_or_else(|| unreachable!("source-valid activity retains analysis"));
        if analysis.status() != AnalysisStatus::Valid {
            return Err(with_package_activity(
                failure(StartFailureCategory::Analysis, "source-invalid"),
                package_activity,
            ));
        }
        let entry_input =
            match validate_entry_input(analysis, request.entry_input, self.configuration) {
                Ok(input) => input,
                Err(failure) => {
                    return Err(with_package_activity(failure, package_activity));
                }
            };
        let mapping_revisions = match self.resolve_mappings(analysis).await {
            Ok(revisions) => revisions,
            Err(failure) => return Err(with_package_activity(failure, package_activity)),
        };
        let supplied_root = if let Some(specification) = request.root_session {
            let root = match self.supplied_root_session(specification) {
                Ok(root) => root,
                Err(failure) => {
                    return Err(with_package_activity(failure, package_activity));
                }
            };
            if let Err(failure) = self.resolve_root_session(&root, specification).await {
                return Err(with_package_activity(failure, package_activity));
            }
            Some(root)
        } else {
            None
        };
        let delivery = if event_delivery.registrations().is_empty() {
            self.package
                .deliver_completed_events(&package_activity.events, Some(&event_delivery))
                .await
        } else {
            match &self.owned_event_delivery {
                Some(factory) => match self
                    .lifecycle
                    .call_owned_event_delivery(factory(
                        package_activity.events.clone(),
                        event_delivery.clone(),
                    ))
                    .await
                {
                    Ok(delivery) => delivery,
                    Err(error) => {
                        return Err(with_package_activity(
                            owned_event_delivery_failure(error),
                            package_activity,
                        ));
                    }
                },
                None => {
                    self.package
                        .deliver_completed_events(&package_activity.events, Some(&event_delivery))
                        .await
                }
            }
        };
        match delivery {
            Ok(deliveries) => package_activity.deliveries = deliveries,
            Err(error) => {
                return Err(with_package_activity(
                    analyze_failure(error),
                    package_activity,
                ));
            }
        }
        let root_session = match supplied_root {
            Some(root) => root,
            None => match self.fresh_root_session() {
                Ok(root) => root,
                Err(failure) => {
                    return Err(with_package_activity(failure, package_activity));
                }
            },
        };
        let execution_id = match self.allocator.allocate(
            self.configuration.identity_source(),
            IdentityKind::Execution,
        ) {
            Ok(identity) => identity,
            Err(error) => {
                return Err(with_package_activity(
                    identity_failure(error, "execution-identity-source-failure"),
                    package_activity,
                ));
            }
        };

        if execution_id.kind() != IdentityKind::Execution {
            return Err(with_package_activity(
                failure(
                    StartFailureCategory::Internal,
                    "execution-identity-invariant",
                ),
                package_activity,
            ));
        }

        Ok(PreparedExecutionStart {
            admission,
            execution_id,
            package_activity,
            entry_input,
            root_session,
            mapping_revisions,
            event_delivery,
        })
    }

    fn supplied_root_session(
        &self,
        specification: RootSessionSpecification<'_>,
    ) -> Result<RootSessionState, StartExecutionFailure> {
        if specification.id.kind() != IdentityKind::Session {
            return Err(failure(
                StartFailureCategory::IntegrationPreflight,
                "invalid-root-session-identity",
            ));
        }
        let transcript = match specification.transcript {
            Some(bytes) => {
                CanonicalTranscriptV1::decode(bytes, self.configuration.required().value_limits)
                    .map_err(|_| {
                        failure(
                            StartFailureCategory::IntegrationPreflight,
                            "invalid-root-session-transcript",
                        )
                    })?
            }
            None => CanonicalTranscriptV1::empty(),
        };
        Ok(RootSessionState {
            id: specification.id,
            provenance: RootSessionProvenance::EmbedderSupplied,
            transcript,
        })
    }

    fn fresh_root_session(&self) -> Result<RootSessionState, StartExecutionFailure> {
        let id = self
            .allocator
            .allocate(self.configuration.identity_source(), IdentityKind::Session)
            .map_err(|error| identity_failure(error, "root-session-identity-source-failure"))?;
        let transcript = CanonicalTranscriptV1::empty();
        Ok(RootSessionState {
            id,
            provenance: RootSessionProvenance::GantryCreated,
            transcript,
        })
    }

    async fn resolve_mappings(
        &self,
        analysis: &TypedPackage,
    ) -> Result<MappingRevisions, StartExecutionFailure> {
        let agents = analysis
            .structure()
            .agents()
            .iter()
            .map(|agent| agent.name.as_ref())
            .collect::<Vec<_>>();
        let actions = analysis
            .actions()
            .iter()
            .map(|action| action.signature.as_str())
            .collect::<Vec<_>>();
        if agents.is_empty() && actions.is_empty() {
            return Ok(MappingRevisions::default());
        }
        let payload = format!(
            "{{\"action_signatures\":{},\"agent_names\":{}}}",
            json_string_array(&actions),
            json_string_array(&agents),
        );
        let response = self
            .call_preflight(EmbeddingOperation::ResolveMappings, payload)
            .await?;
        decode_mapping_revisions(&response, !agents.is_empty(), !actions.is_empty())
    }

    async fn resolve_root_session(
        &self,
        root: &RootSessionState,
        specification: RootSessionSpecification<'_>,
    ) -> Result<(), StartExecutionFailure> {
        let opaque = specification
            .opaque_lookup_material
            .map_or_else(|| "null".to_owned(), |bytes| json_string(&hex(bytes)));
        let transcript = std::str::from_utf8(root.transcript.bytes())
            .unwrap_or_else(|_| unreachable!("canonical JSON is UTF-8"));
        let payload = format!(
            "{{\"session_descriptors\":[{{\"opaque_lookup_material\":{opaque},\"provenance\":{},\"session_id\":{},\"transcript\":{transcript}}}]}}",
            json_string(root.provenance.wire_name()),
            json_string(&root.id.to_string()),
        );
        let response = self
            .call_preflight(EmbeddingOperation::ResolveSessions, payload)
            .await?;
        require_resolved(&response)
    }

    pub(crate) async fn call_preflight(
        &self,
        operation: EmbeddingOperation,
        payload: String,
    ) -> Result<HostResponse, StartExecutionFailure> {
        let request = HostRequest::new(
            EmbeddingVersion::V1,
            operation,
            Arc::<[u8]>::from(payload.into_bytes()),
        )
        .map_err(envelope_failure)?;
        let response = self
            .lifecycle
            .call_owned_preflight(
                Arc::clone(&self.preflight),
                self.preflight_poison.clone(),
                request,
            )
            .await
            .map_err(owned_activity_failure)?;
        if response.version() != EmbeddingVersion::V1 || response.operation() != operation {
            return Err(failure(
                StartFailureCategory::IntegrationPreflight,
                "invalid-preflight-response",
            ));
        }
        Ok(response)
    }

    pub(crate) fn fresh_activity_id(&self) -> Result<ProtocolIdentity, StartExecutionFailure> {
        self.allocator
            .allocate(self.configuration.identity_source(), IdentityKind::Activity)
            .map_err(|error| identity_failure(error, "resume-activity-identity-source-failure"))
    }
}

pub(crate) fn decode_mapping_revisions(
    response: &HostResponse,
    expects_agent: bool,
    expects_action: bool,
) -> Result<MappingRevisions, StartExecutionFailure> {
    let bytes = response.canonical_bytes();
    let length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    let document = StrictJsonDocument::decode(
        bytes,
        JsonLimits {
            maximum_bytes: length,
            maximum_nesting_depth: 2,
            maximum_nodes: 4,
            maximum_string_scalars: length,
            maximum_list_items: 1,
        },
    )
    .map_err(|_| invalid_preflight_response())?;
    let canonical =
        CanonicalJson::from_document(&document).map_err(|_| invalid_preflight_response())?;
    if canonical.bytes() != bytes {
        return Err(invalid_preflight_response());
    }
    let JsonNode::Object(members) = document
        .node(document.root())
        .ok_or_else(invalid_preflight_response)?
    else {
        return Err(invalid_preflight_response());
    };
    let mut result = None;
    let mut agent = None;
    let mut action = None;
    for (name, value) in members {
        let JsonNode::String(value) = document
            .node(*value)
            .ok_or_else(invalid_preflight_response)?
        else {
            return Err(invalid_preflight_response());
        };
        match name.as_ref() {
            "result" => result = Some(value.as_ref()),
            "agent_mapping_revision" if expects_agent && !value.is_empty() => {
                agent = Some(
                    AgentMappingRevision::new(Arc::clone(value))
                        .map_err(|_| invalid_preflight_response())?,
                );
            }
            "action_mapping_revision" if expects_action && !value.is_empty() => {
                action = Some(
                    ActionMappingRevision::new(Arc::clone(value))
                        .map_err(|_| invalid_preflight_response())?,
                );
            }
            _ => return Err(invalid_preflight_response()),
        }
    }
    if result != Some("resolved")
        || expects_agent != agent.is_some()
        || expects_action != action.is_some()
    {
        return Err(invalid_preflight_response());
    }
    Ok(MappingRevisions { agent, action })
}

pub(crate) fn require_resolved(response: &HostResponse) -> Result<(), StartExecutionFailure> {
    if response.canonical_bytes() == b"{\"result\":\"resolved\"}" {
        Ok(())
    } else {
        Err(failure(
            StartFailureCategory::IntegrationPreflight,
            "unresolved-preflight-dependency",
        ))
    }
}

fn invalid_preflight_response() -> StartExecutionFailure {
    failure(
        StartFailureCategory::IntegrationPreflight,
        "invalid-preflight-response",
    )
}

fn validate_entry_input(
    analysis: &TypedPackage,
    input: Option<&[u8]>,
    configuration: &InterpreterConfiguration,
) -> Result<Option<ValidatedEntryInput>, StartExecutionFailure> {
    let entry = analysis
        .entry()
        .ok_or_else(|| failure(StartFailureCategory::Internal, "missing-entry-inventory"))?;
    let Some(parameter) = &entry.parameter else {
        return if input.is_none() {
            Ok(None)
        } else {
            Err(failure(
                StartFailureCategory::EntryInputValidation,
                "unexpected-entry-input",
            ))
        };
    };
    let input = input.ok_or_else(|| {
        failure(
            StartFailureCategory::EntryInputValidation,
            "missing-entry-input",
        )
    })?;
    let limits = json_limits(
        configuration,
        configuration.required().maximum_entry_input_bytes,
    );
    let document =
        StrictJsonDocument::decode(input, limits).map_err(|error| entry_json_failure(&error))?;
    let schema = analysis
        .schemas()
        .and_then(|schemas| {
            schemas
                .entries()
                .iter()
                .find(|(candidate, _)| candidate == parameter)
                .map(|(_, schema)| Arc::clone(schema))
        })
        .ok_or_else(|| failure(StartFailureCategory::Internal, "missing-entry-schema"))?;
    let validator = SchemaValidator::compile(schema, schema_limits(configuration))
        .map_err(|_| failure(StartFailureCategory::Internal, "invalid-entry-schema"))?;
    let canonical_json = validator
        .normalize(&document, limits)
        .map_err(entry_normalization_failure)?;
    Ok(Some(ValidatedEntryInput {
        ty: parameter.clone(),
        canonical_json,
    }))
}

fn json_limits(configuration: &InterpreterConfiguration, maximum_bytes: u64) -> JsonLimits {
    let values = configuration.required().value_limits;
    JsonLimits {
        maximum_bytes,
        maximum_nesting_depth: values.maximum_nesting_depth(),
        maximum_nodes: values.maximum_nodes(),
        maximum_string_scalars: values.maximum_string_scalars(),
        maximum_list_items: values.maximum_list_items(),
    }
}

fn schema_limits(configuration: &InterpreterConfiguration) -> JsonLimits {
    json_limits(
        configuration,
        configuration
            .required()
            .frontend_limits
            .maximum_generated_schema_bytes(),
    )
}

fn analyze_failure(error: AnalyzePackageError) -> StartExecutionFailure {
    match error {
        AnalyzePackageError::ActivityIdentity(error) => {
            identity_failure(error, "activity-identity-source-failure")
        }
        AnalyzePackageError::Package(error) if error.frontend_resource_limit().is_some() => {
            failure(StartFailureCategory::FrontendResourceLimit, error.code())
        }
        AnalyzePackageError::Package(error) => failure(StartFailureCategory::Syntax, error.code()),
        AnalyzePackageError::Analysis(gantry_analysis::AnalysisError::ResourceLimit { .. }) => {
            failure(
                StartFailureCategory::FrontendResourceLimit,
                "frontend-resource-limit",
            )
        }
        AnalyzePackageError::Analysis(_) => failure(StartFailureCategory::Internal, "internal"),
        AnalyzePackageError::Event(_)
        | AnalyzePackageError::MissingDeliveryRuntime
        | AnalyzePackageError::Delivery(_)
        | AnalyzePackageError::RequiredEventDelivery => failure(
            StartFailureCategory::RequiredEventDelivery,
            "required-event-delivery-failure",
        ),
    }
}

fn entry_json_failure(error: &JsonError) -> StartExecutionFailure {
    let code = match error {
        JsonError::ResourceLimit { .. } => "entry-input-resource-limit",
        JsonError::InvalidUtf8 => "entry-input-invalid-utf8",
        JsonError::Empty => "entry-input-empty",
        JsonError::TrailingData { .. } => "entry-input-trailing-data",
        JsonError::DuplicateMember { .. } => "entry-input-duplicate-member",
        JsonError::UnpairedSurrogate { .. } => "entry-input-unpaired-surrogate",
        JsonError::Syntax { .. } => "entry-input-invalid-json",
    };
    failure(StartFailureCategory::EntryInputValidation, code)
}

fn entry_normalization_failure(error: NormalizationError) -> StartExecutionFailure {
    match error {
        NormalizationError::Validation(errors) => validation_failure(errors),
        NormalizationError::Json(error) => entry_json_failure(&error),
        NormalizationError::Schema(_) | NormalizationError::Canonical(_) => failure(
            StartFailureCategory::Internal,
            "entry-normalization-invariant",
        ),
    }
}

fn validation_failure(errors: Vec<ValidationError>) -> StartExecutionFailure {
    let code = errors
        .first()
        .map(|error| format!("entry-input-schema{}", error.instance_location))
        .unwrap_or_else(|| "entry-input-schema-validation".to_owned());
    failure(StartFailureCategory::EntryInputValidation, code)
}

fn lifecycle_failure(error: LifecycleError) -> StartExecutionFailure {
    failure(StartFailureCategory::Lifecycle, error.code.wire_name())
}

fn identity_failure(error: IdentityAllocationError, code: &str) -> StartExecutionFailure {
    let code = match error {
        IdentityAllocationError::Source(_) => code,
        IdentityAllocationError::CollisionLimit => "identity-collision-limit",
        IdentityAllocationError::RegistryUnavailable => "identity-registry-unavailable",
        IdentityAllocationError::WrongOrigin => "identity-origin-invariant",
    };
    failure(StartFailureCategory::IntegrationPreflight, code)
}

fn boundary_failure(_error: BoundaryFailure) -> StartExecutionFailure {
    failure(
        StartFailureCategory::IntegrationPreflight,
        "integration-panic",
    )
}

fn host_failure(error: HostError) -> StartExecutionFailure {
    StartExecutionFailure {
        category: StartFailureCategory::IntegrationPreflight,
        code: error.code,
        package_activity: None,
    }
}

fn owned_activity_failure(error: OwnedActivityError) -> StartExecutionFailure {
    match error {
        OwnedActivityError::Admission(_) => failure(
            StartFailureCategory::ImplementationResourceExhaustion,
            "public-activity-capacity",
        ),
        OwnedActivityError::Executor(_) => failure(
            StartFailureCategory::ImplementationResourceExhaustion,
            "public-activity-submission-failure",
        ),
        OwnedActivityError::Host(error) => host_failure(error),
        OwnedActivityError::Boundary(error) => boundary_failure(error),
    }
}

fn owned_event_delivery_failure(error: OwnedActivityError) -> StartExecutionFailure {
    match error {
        OwnedActivityError::Admission(_) => failure(
            StartFailureCategory::ImplementationResourceExhaustion,
            "event-delivery-capacity",
        ),
        OwnedActivityError::Executor(_) => failure(
            StartFailureCategory::ImplementationResourceExhaustion,
            "event-delivery-submission-failure",
        ),
        OwnedActivityError::Host(error) => host_failure(error),
        OwnedActivityError::Boundary(error) => boundary_failure(error),
    }
}

fn envelope_failure(_error: EnvelopeError) -> StartExecutionFailure {
    failure(
        StartFailureCategory::Internal,
        "preflight-envelope-invariant",
    )
}

fn accept_failure(_error: AcceptExecutionError) -> StartExecutionFailure {
    failure(
        StartFailureCategory::Internal,
        "execution-acceptance-invariant",
    )
}

fn failure(category: StartFailureCategory, code: impl Into<Arc<str>>) -> StartExecutionFailure {
    StartExecutionFailure {
        category,
        code: code.into(),
        package_activity: None,
    }
}

fn with_package_activity(
    mut failure: StartExecutionFailure,
    package_activity: AnalyzePackageResult,
) -> StartExecutionFailure {
    failure.package_activity = Some(Box::new(package_activity));
    failure
}

fn json_string_array(values: &[&str]) -> String {
    format!(
        "[{}]",
        values
            .iter()
            .map(|value| json_string(value))
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn json_string(value: &str) -> String {
    let mut output = String::from("\"");
    for scalar in value.chars() {
        match scalar {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{08}' => output.push_str("\\b"),
            '\u{09}' => output.push_str("\\t"),
            '\u{0a}' => output.push_str("\\n"),
            '\u{0c}' => output.push_str("\\f"),
            '\u{0d}' => output.push_str("\\r"),
            value if value <= '\u{1f}' => output.push_str(&format!("\\u{:04x}", value as u32)),
            value => output.push(value),
        }
    }
    output.push('"');
    output
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
