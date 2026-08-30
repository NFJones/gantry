//! Public nondurable pre-execution coordination and acceptance.

use std::path::Path;
use std::sync::Arc;

use gantry_analysis::{AnalysisStatus, TypedPackage};
use gantry_core::canonical_json::CanonicalJson;
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
use gantry_observe::SinkPlan;
use gantry_runtime::{
    AcceptExecutionError, AdapterPoison, AdmissionKind, BoundaryFailure, ExecutionHandle,
    InterpreterConfiguration, InterpreterLifecycle, LifecycleError,
};

use crate::{
    AnalyzePackageCoordinator, AnalyzePackageError, AnalyzePackageRequest, AnalyzePackageResult,
    AnalyzePackageStatus,
};

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
    pub transcript: CanonicalJson,
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

/// Accepted nondurable execution state before `main` evaluation.
#[derive(Debug)]
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

/// Ordered pre-execution coordinator over existing semantic and lifecycle owners.
pub struct StartExecutionCoordinator<'a> {
    package: &'a AnalyzePackageCoordinator<'a>,
    lifecycle: &'a InterpreterLifecycle,
    configuration: &'a InterpreterConfiguration,
    allocator: &'a FreshIdentityAllocator,
    preflight: &'a dyn IntegrationPreflight,
    preflight_poison: AdapterPoison,
}

impl<'a> StartExecutionCoordinator<'a> {
    /// Binds package activity, lifecycle, configuration, identity, and preflight owners.
    #[must_use]
    pub fn new(
        package: &'a AnalyzePackageCoordinator<'a>,
        lifecycle: &'a InterpreterLifecycle,
        configuration: &'a InterpreterConfiguration,
        allocator: &'a FreshIdentityAllocator,
        preflight: &'a dyn IntegrationPreflight,
    ) -> Self {
        Self {
            package,
            lifecycle,
            configuration,
            allocator,
            preflight,
            preflight_poison: AdapterPoison::default(),
        }
    }

    /// Runs ordered nondurable preflight and accepts before any evaluation or hook creation.
    pub async fn start(&self, request: StartExecutionRequest<'_>) -> StartExecutionResult {
        let mut admission = match self.lifecycle.admit(AdmissionKind::NewWork) {
            Ok(admission) => admission,
            Err(error) => return rejected(lifecycle_failure(error), None),
        };

        for peer in request.required_peers {
            if request.protocol_selection.require_peer(peer).is_err() {
                return rejected(
                    failure(
                        StartFailureCategory::IntegrationPreflight,
                        "unsupported-protocol-selection",
                    ),
                    None,
                );
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
            Err(error) => return rejected(analyze_failure(error), None),
        };
        if package_activity.status != AnalyzePackageStatus::SourceValid {
            let category = if package_activity.analysis.is_some() {
                StartFailureCategory::Analysis
            } else {
                StartFailureCategory::Syntax
            };
            return rejected(failure(category, "source-invalid"), Some(package_activity));
        }

        let analysis = package_activity
            .analysis
            .as_ref()
            .unwrap_or_else(|| unreachable!("source-valid activity retains analysis"));
        if analysis.status() != AnalysisStatus::Valid {
            return rejected(
                failure(StartFailureCategory::Analysis, "source-invalid"),
                Some(package_activity),
            );
        }
        let entry_input =
            match validate_entry_input(analysis, request.entry_input, self.configuration) {
                Ok(input) => input,
                Err(failure) => return rejected(failure, Some(package_activity)),
            };
        let mapping_revisions = match self.resolve_mappings(analysis).await {
            Ok(revisions) => revisions,
            Err(failure) => return rejected(failure, Some(package_activity)),
        };
        let supplied_root = if let Some(specification) = request.root_session {
            let root = match self.supplied_root_session(specification) {
                Ok(root) => root,
                Err(failure) => return rejected(failure, Some(package_activity)),
            };
            if let Err(failure) = self.resolve_root_session(&root, specification).await {
                return rejected(failure, Some(package_activity));
            }
            Some(root)
        } else {
            None
        };
        match self
            .package
            .deliver_completed_events(&package_activity.events, request.event_delivery)
            .await
        {
            Ok(deliveries) => package_activity.deliveries = deliveries,
            Err(error) => return rejected(analyze_failure(error), Some(package_activity)),
        }
        let root_session = match supplied_root {
            Some(root) => root,
            None => match self.fresh_root_session() {
                Ok(root) => root,
                Err(failure) => return rejected(failure, Some(package_activity)),
            },
        };
        let execution_id = match self.allocator.allocate(
            self.configuration.identity_source(),
            IdentityKind::Execution,
        ) {
            Ok(identity) => identity,
            Err(error) => {
                return rejected(
                    identity_failure(error, "execution-identity-source-failure"),
                    Some(package_activity),
                );
            }
        };

        if execution_id.kind() != IdentityKind::Execution {
            return rejected(
                failure(
                    StartFailureCategory::Internal,
                    "execution-identity-invariant",
                ),
                Some(package_activity),
            );
        }

        let handle = match admission.accept_execution(execution_id) {
            Ok(handle) => handle,
            Err(error) => {
                return rejected(accept_failure(error), Some(package_activity));
            }
        };
        StartExecutionResult::Accepted(Box::new(StartExecutionAccepted {
            execution_id,
            handle,
            package_activity: Box::new(package_activity),
            entry_input,
            root_session,
            mapping_revisions,
        }))
    }

    fn supplied_root_session(
        &self,
        specification: RootSessionSpecification<'_>,
    ) -> Result<RootSessionState, StartExecutionFailure> {
        let limits = json_limits(
            self.configuration,
            self.configuration.required().maximum_entry_input_bytes,
        );
        if specification.id.kind() != IdentityKind::Session {
            return Err(failure(
                StartFailureCategory::IntegrationPreflight,
                "invalid-root-session-identity",
            ));
        }
        let bytes = specification.transcript.unwrap_or(b"[]");
        let document = StrictJsonDocument::decode(bytes, limits).map_err(|_| {
            failure(
                StartFailureCategory::IntegrationPreflight,
                "invalid-root-session-transcript",
            )
        })?;
        if !matches!(document.node(document.root()), Some(JsonNode::Array(_))) {
            return Err(failure(
                StartFailureCategory::IntegrationPreflight,
                "invalid-root-session-transcript",
            ));
        }
        let transcript = CanonicalJson::from_document(&document).map_err(|_| {
            failure(
                StartFailureCategory::IntegrationPreflight,
                "invalid-root-session-transcript",
            )
        })?;
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
        let limits = json_limits(
            self.configuration,
            self.configuration.required().maximum_entry_input_bytes,
        );
        let transcript = StrictJsonDocument::decode(&b"[]"[..], limits)
            .and_then(|document| {
                CanonicalJson::from_document(&document).map_err(|_| JsonError::Syntax { offset: 0 })
            })
            .map_err(|_| failure(StartFailureCategory::Internal, "root-session-invariant"))?;
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

    async fn call_preflight(
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
        let future = self
            .lifecycle
            .catch_adapter(&self.preflight_poison, || self.preflight.call(request))
            .map_err(boundary_failure)?;
        let response = self
            .lifecycle
            .contain_adapter_future(future, self.preflight_poison.clone())
            .await
            .map_err(boundary_failure)?
            .map_err(host_failure)?;
        if response.version() != EmbeddingVersion::V1 || response.operation() != operation {
            return Err(failure(
                StartFailureCategory::IntegrationPreflight,
                "invalid-preflight-response",
            ));
        }
        Ok(response)
    }
}

fn decode_mapping_revisions(
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

fn require_resolved(response: &HostResponse) -> Result<(), StartExecutionFailure> {
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

fn rejected(
    mut failure: StartExecutionFailure,
    package_activity: Option<AnalyzePackageResult>,
) -> StartExecutionResult {
    failure.package_activity = package_activity.map(Box::new);
    StartExecutionResult::Rejected(failure)
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
