//! Canonical v1 task-context and operation-hook request codecs.

use std::sync::Arc;

use gantry_core::canonical_json::CanonicalJson;
use gantry_core::identity::ProtocolIdentity;
use gantry_core::portable::IdentityKind;
use gantry_core::strict_json::{JsonLimits, JsonNode, StrictJsonDocument};
use gantry_core::value::ValueLimits;
use gantry_host::contracts::{
    ActionMappingRevision, AgentMappingRevision, EmbeddingVersion, FreshIdentityAllocator,
    HostRequest, IdentityAllocationError, IdentitySource,
};
use gantry_host::embedding::EmbeddingOperation;
use gantry_ir::generated::{OperationSiteKind, RecoveryClass, TypeKind};
use gantry_ir::{CanonicalPath, CanonicalSignature, StructuralPosition, TypeDescriptor};

/// Root-session ownership retained in a task context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootSessionProvenanceV1 {
    /// The embedding supplied and resolved the root session.
    EmbedderSupplied,
    /// Gantry allocated the root session.
    GantryCreated,
}

impl RootSessionProvenanceV1 {
    const fn wire_name(self) -> &'static str {
        match self {
            Self::EmbedderSupplied => "embedder-supplied",
            Self::GantryCreated => "gantry-created",
        }
    }
}

/// Base-session fields fixed when one task is created.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TaskSessionContextV1 {
    /// The root task uses the execution root session directly.
    Root {
        /// Root logical-session identity.
        root_session_id: ProtocolIdentity,
        /// Root-session ownership class.
        provenance: RootSessionProvenanceV1,
    },
    /// A spawned task uses one creation-time fork of its parent's session.
    Forked {
        /// Forked base-session identity.
        base_session_id: ProtocolIdentity,
        /// Parent session captured at task creation.
        parent_session_id: ProtocolIdentity,
        /// Execution root-session identity.
        root_session_id: ProtocolIdentity,
        /// Root-session ownership class.
        root_provenance: RootSessionProvenanceV1,
    },
}

/// Exact v1 context supplied only when a task lazily creates its hook.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskContextV1 {
    /// Accepted execution identity.
    pub execution_id: ProtocolIdentity,
    /// Stable logical task identity.
    pub task_id: ProtocolIdentity,
    /// Agent selection inherited at task creation, when any.
    pub inherited_agent: Option<Arc<str>>,
    /// Base and root session fields fixed at task creation.
    pub session: TaskSessionContextV1,
}

impl TaskContextV1 {
    /// Validates typed identities and constructs the canonical `CreateHook` request.
    pub fn into_host_request(self) -> Result<HostRequest, HookRequestError> {
        require_kind(self.execution_id, IdentityKind::Execution)?;
        require_kind(self.task_id, IdentityKind::Task)?;
        let mut context = String::from("{\"base_session_id\":");
        match &self.session {
            TaskSessionContextV1::Root {
                root_session_id,
                provenance,
            } => {
                require_kind(*root_session_id, IdentityKind::Session)?;
                push_json_string(&mut context, &root_session_id.to_string());
                context.push_str(",\"execution_id\":");
                push_json_string(&mut context, &self.execution_id.to_string());
                context.push_str(",\"inherited_agent\":");
                push_optional_string(&mut context, self.inherited_agent.as_deref());
                context.push_str(",\"root_session_id\":");
                push_json_string(&mut context, &root_session_id.to_string());
                context.push_str(",\"root_session_provenance\":");
                push_json_string(&mut context, provenance.wire_name());
            }
            TaskSessionContextV1::Forked {
                base_session_id,
                parent_session_id,
                root_session_id,
                root_provenance,
            } => {
                for identity in [base_session_id, parent_session_id, root_session_id] {
                    require_kind(*identity, IdentityKind::Session)?;
                }
                push_json_string(&mut context, &base_session_id.to_string());
                context.push_str(",\"execution_id\":");
                push_json_string(&mut context, &self.execution_id.to_string());
                context.push_str(",\"inherited_agent\":");
                push_optional_string(&mut context, self.inherited_agent.as_deref());
                context.push_str(",\"parent_session_id\":");
                push_json_string(&mut context, &parent_session_id.to_string());
                context.push_str(",\"root_session_id\":");
                push_json_string(&mut context, &root_session_id.to_string());
                context.push_str(",\"root_session_provenance\":");
                push_json_string(&mut context, root_provenance.wire_name());
                context.push_str(",\"session_creation_mode\":\"fork\"");
            }
        }
        context.push_str(",\"task_id\":");
        push_json_string(&mut context, &self.task_id.to_string());
        context.push('}');
        let bytes = format!("{{\"task_context\":{context}}}").into_bytes();
        host_request(EmbeddingOperation::CreateHook, bytes)
    }
}

/// One canonical typed action argument in declaration order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TypedActionArgumentV1 {
    /// Declared parameter name.
    pub name: Arc<str>,
    /// Canonical static type.
    pub ty: TypeDescriptor,
    /// Captured canonical value.
    pub value: CanonicalJson,
}

/// One model interpolation input in source order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InterpolationInputV1 {
    /// Zero-based source position.
    pub position: u64,
    /// Canonical static type.
    pub ty: TypeDescriptor,
    /// Captured canonical value.
    pub value: CanonicalJson,
}

/// One named model input in source order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamedInputV1 {
    /// Unique authored input name.
    pub name: Arc<str>,
    /// Canonical static type.
    pub ty: TypeDescriptor,
    /// Captured canonical value.
    pub value: CanonicalJson,
}

/// Session use carried by one model request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ModelSessionUseV1 {
    /// Reuse an already established active session.
    Inline,
    /// Establish one operation-local session through this request.
    Create {
        /// Exact `fork` or `new` directive.
        mode: Arc<str>,
        /// New logical-session identity.
        session_id: ProtocolIdentity,
        /// Enclosing logical-session identity.
        parent_session_id: ProtocolIdentity,
        /// Root logical-session identity.
        root_session_id: ProtocolIdentity,
        /// Stable creation provenance.
        provenance: Arc<str>,
    },
}

/// Immutable action-specific semantic request fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionOperationRequestV1 {
    /// Canonical declared action path.
    pub path: CanonicalPath,
    /// Canonical declaration signature.
    pub signature: CanonicalSignature,
    /// Declared recovery class.
    pub recovery: RecoveryClass,
    /// Run-scoped action mapping revision.
    pub mapping_revision: ActionMappingRevision,
    /// Captured arguments in declaration order.
    pub arguments: Vec<TypedActionArgumentV1>,
}

/// Immutable prompt/decision semantic request fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelOperationRequestV1 {
    /// Selected logical agent.
    pub selected_agent: Arc<str>,
    /// Run-scoped agent mapping revision.
    pub mapping_revision: AgentMappingRevision,
    /// Redacted literal template segments.
    pub template_segments: Vec<Arc<str>>,
    /// Fully rendered prompt.
    pub rendered_prompt: Arc<str>,
    /// Captured interpolation inputs in source order.
    pub interpolation_inputs: Vec<InterpolationInputV1>,
    /// Captured named inputs in source order.
    pub named_inputs: Vec<NamedInputV1>,
    /// Canonical transcript before this operation.
    pub transcript: CanonicalJson,
    /// Active logical-session identity.
    pub active_session_id: ProtocolIdentity,
    /// Optional active-session parent.
    pub parent_session_id: Option<ProtocolIdentity>,
    /// Root logical-session identity.
    pub root_session_id: ProtocolIdentity,
    /// Inline reuse or operation-local creation.
    pub session_use: ModelSessionUseV1,
}

/// Immutable common operation request fields captured after source inputs are values.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationRequestHeaderV1 {
    /// Accepted execution identity.
    pub execution_id: ProtocolIdentity,
    /// Stable logical task identity.
    pub task_id: ProtocolIdentity,
    /// Stable logical operation identity.
    pub operation_id: ProtocolIdentity,
    /// Prompt, decision, or action kind.
    pub kind: OperationSiteKind,
    /// Expected canonical result type.
    pub expected_type: TypeDescriptor,
    /// Expected canonical JSON Schema object.
    pub expected_schema: Arc<[u8]>,
    /// Effective raw hook-output byte limit.
    pub maximum_hook_output_bytes: u64,
    /// Effective logical value limits.
    pub value_limits: ValueLimits,
    /// Canonical containing workflow.
    pub workflow: CanonicalPath,
    /// Canonical structural operation site.
    pub site: StructuralPosition,
}

/// Machine-readable category for one repair validation error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidationErrorCategoryV1 {
    /// Invalid UTF-8.
    Utf8,
    /// JSON syntax failure.
    JsonSyntax,
    /// Duplicate JSON member.
    JsonDuplicateKey,
    /// Invalid Unicode scalar sequence.
    JsonUnicode,
    /// JSON Schema mismatch.
    Schema,
    /// Effective resource limit.
    ResourceLimit,
}

impl ValidationErrorCategoryV1 {
    const fn wire_name(self) -> &'static str {
        match self {
            Self::Utf8 => "utf8",
            Self::JsonSyntax => "json-syntax",
            Self::JsonDuplicateKey => "json-duplicate-key",
            Self::JsonUnicode => "json-unicode",
            Self::Schema => "schema",
            Self::ResourceLimit => "resource-limit",
        }
    }
}

/// One canonical structured-output repair error without raw integration bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidationErrorV1 {
    /// Exact machine-readable category.
    pub category: ValidationErrorCategoryV1,
    /// Optional JSON Pointer into the instance.
    pub instance_location: Option<Arc<str>>,
    /// Human-readable bounded explanation.
    pub message: Arc<str>,
    /// Optional JSON Pointer into the schema.
    pub schema_location: Option<Arc<str>>,
}

/// One immutable semantic request captured for all physical dispatches.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CapturedOperationRequestV1 {
    /// Prompt or decision request.
    Model {
        /// Common request header.
        header: OperationRequestHeaderV1,
        /// Model-specific fields.
        body: Box<ModelOperationRequestV1>,
    },
    /// Harness action request.
    Action {
        /// Common request header.
        header: OperationRequestHeaderV1,
        /// Action-specific fields.
        body: ActionOperationRequestV1,
    },
}

impl CapturedOperationRequestV1 {
    /// Returns the immutable common header shared by every physical dispatch.
    #[must_use]
    pub const fn header(&self) -> &OperationRequestHeaderV1 {
        match self {
            Self::Model { header, .. } | Self::Action { header, .. } => header,
        }
    }

    /// Validates immutable fields before any dispatch identity is allocated.
    pub fn validate(&self) -> Result<(), HookRequestError> {
        let header = self.header();
        require_kind(header.execution_id, IdentityKind::Execution)?;
        require_kind(header.task_id, IdentityKind::Task)?;
        require_kind(header.operation_id, IdentityKind::Operation)?;
        validate_schema(&header.expected_schema)?;
        match self {
            Self::Model { header, body } => {
                if !matches!(
                    header.kind,
                    OperationSiteKind::Prompt | OperationSiteKind::Decide
                ) || body.selected_agent.is_empty()
                {
                    return Err(HookRequestError::InvalidShape);
                }
                require_kind(body.active_session_id, IdentityKind::Session)?;
                require_kind(body.root_session_id, IdentityKind::Session)?;
                if let Some(parent) = body.parent_session_id {
                    require_kind(parent, IdentityKind::Session)?;
                }
                validate_session_use(&body.session_use)?;
            }
            Self::Action { header, body } => {
                if header.kind != OperationSiteKind::Action
                    || body
                        .arguments
                        .iter()
                        .any(|argument| argument.name.is_empty())
                {
                    return Err(HookRequestError::InvalidShape);
                }
            }
        }
        Ok(())
    }

    /// Allocates one fresh physical dispatch and encodes the exact immutable request.
    pub fn prepare_dispatch(
        &self,
        allocator: &FreshIdentityAllocator,
        identity_source: &dyn IdentitySource,
        validation_attempt: u64,
        recovery_dispatch: u64,
        validation_errors: &[ValidationErrorV1],
    ) -> Result<PreparedHookDispatch, HookRequestError> {
        self.validate()?;
        if validation_attempt == 0 && !validation_errors.is_empty()
            || validation_attempt > 0 && validation_errors.is_empty()
            || validation_errors
                .iter()
                .any(|error| error.message.is_empty())
        {
            return Err(HookRequestError::InvalidRepairState);
        }
        let dispatch_id = allocator
            .allocate(identity_source, IdentityKind::Dispatch)
            .map_err(HookRequestError::Identity)?;
        let bytes = encode_dispatch(
            self,
            dispatch_id,
            validation_attempt,
            recovery_dispatch,
            validation_errors,
        );
        Ok(PreparedHookDispatch {
            dispatch_id,
            request: host_request(EmbeddingOperation::DispatchOperation, bytes)?,
        })
    }
}

/// One fresh physical hook invocation prepared from immutable semantic input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedHookDispatch {
    /// Fresh physical dispatch identity.
    pub dispatch_id: ProtocolIdentity,
    /// Exact versioned `DispatchOperation` request.
    pub request: HostRequest,
}

/// Rejection while validating or encoding one hook boundary request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HookRequestError {
    /// A typed identity has the wrong kind.
    IdentityKind,
    /// Fresh dispatch allocation failed.
    Identity(IdentityAllocationError),
    /// Required and forbidden fields disagree with the operation kind.
    InvalidShape,
    /// Expected schema bytes are not one canonical JSON object.
    InvalidSchema,
    /// Validation attempt and repair errors disagree.
    InvalidRepairState,
    /// Host-envelope construction rejected the fixed v1 operation.
    Envelope,
}

fn encode_dispatch(
    captured: &CapturedOperationRequestV1,
    dispatch_id: ProtocolIdentity,
    validation_attempt: u64,
    recovery_dispatch: u64,
    validation_errors: &[ValidationErrorV1],
) -> Vec<u8> {
    let header = captured.header();
    let mut output = String::from("{\"cancellation\":\"gantry-token\",\"operation_request\":{");
    if let CapturedOperationRequestV1::Action { body, .. } = captured {
        output.push_str("\"action\":{");
        output.push_str("\"action_mapping_revision\":");
        push_json_string(&mut output, body.mapping_revision.as_str());
        output.push_str(",\"arguments\":[");
        push_action_arguments(&mut output, &body.arguments);
        output.push_str("],\"canonical_path\":");
        push_json_string(&mut output, body.path.as_str());
        output.push_str(",\"canonical_signature\":");
        push_json_string(&mut output, body.signature.as_str());
        output.push_str(",\"recovery_class\":");
        push_json_string(&mut output, body.recovery.wire_name());
        output.push_str("},");
    }
    output.push_str("\"dispatch_id\":");
    push_json_string(&mut output, &dispatch_id.to_string());
    output.push_str(",\"execution_id\":");
    push_json_string(&mut output, &header.execution_id.to_string());
    output.push_str(",\"expected_json_schema\":");
    output.push_str(std::str::from_utf8(&header.expected_schema).unwrap_or("{}"));
    output.push_str(",\"expected_result_kind\":");
    push_json_string(&mut output, expected_result_kind(&header.expected_type));
    output.push_str(",\"expected_type\":");
    push_json_string(&mut output, &header.expected_type.canonical_string());
    output.push_str(",\"guidance\":");
    push_json_string(&mut output, &guidance(header, captured));
    output.push_str(",\"limits\":{");
    output.push_str(&format!(
        "\"maximum_hook_output_bytes\":{},\"maximum_list_items\":{},\"maximum_nesting_depth\":{},\"maximum_nodes\":{},\"maximum_string_scalars\":{}",
        header.maximum_hook_output_bytes,
        header.value_limits.maximum_list_items(),
        header.value_limits.maximum_nesting_depth(),
        header.value_limits.maximum_nodes(),
        header.value_limits.maximum_string_scalars(),
    ));
    if let CapturedOperationRequestV1::Model { body, .. } = captured {
        output.push_str("},\"model\":{");
        push_model_body(&mut output, body);
        output.push('}');
    } else {
        output.push('}');
    }
    output.push_str(",\"operation_id\":");
    push_json_string(&mut output, &header.operation_id.to_string());
    output.push_str(",\"operation_kind\":");
    push_json_string(&mut output, header.kind.wire_name());
    output.push_str(",\"protocol\":{\"major\":1,\"minor\":0},\"recovery_dispatch\":");
    output.push_str(&recovery_dispatch.to_string());
    output.push_str(",\"site\":{\"position\":[");
    for (index, component) in header.site.components().iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        push_json_string(&mut output, &component.to_string());
    }
    output.push_str("],\"workflow\":");
    push_json_string(&mut output, header.workflow.as_str());
    output.push_str("},\"task_id\":");
    push_json_string(&mut output, &header.task_id.to_string());
    output.push_str(",\"validation_attempt\":");
    output.push_str(&validation_attempt.to_string());
    if !validation_errors.is_empty() {
        output.push_str(",\"validation_errors\":[");
        push_validation_errors(&mut output, validation_errors);
        output.push(']');
    }
    output.push_str("}}");
    output.into_bytes()
}

fn push_action_arguments(output: &mut String, arguments: &[TypedActionArgumentV1]) {
    for (index, argument) in arguments.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        output.push_str("{\"name\":");
        push_json_string(output, &argument.name);
        output.push_str(",\"type\":");
        push_json_string(output, &argument.ty.canonical_string());
        output.push_str(",\"value\":");
        push_canonical(output, &argument.value);
        output.push('}');
    }
}

fn push_model_body(output: &mut String, body: &ModelOperationRequestV1) {
    output.push_str("\"active_session_id\":");
    push_json_string(output, &body.active_session_id.to_string());
    output.push_str(",\"agent_mapping_revision\":");
    push_json_string(output, body.mapping_revision.as_str());
    output.push_str(",\"interpolation_inputs\":[");
    for (index, input) in body.interpolation_inputs.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        output.push_str("{\"position\":");
        output.push_str(&input.position.to_string());
        output.push_str(",\"type\":");
        push_json_string(output, &input.ty.canonical_string());
        output.push_str(",\"value\":");
        push_canonical(output, &input.value);
        output.push('}');
    }
    output.push_str("],\"named_inputs\":[");
    for (index, input) in body.named_inputs.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        output.push_str("{\"name\":");
        push_json_string(output, &input.name);
        output.push_str(",\"type\":");
        push_json_string(output, &input.ty.canonical_string());
        output.push_str(",\"value\":");
        push_canonical(output, &input.value);
        output.push('}');
    }
    if let Some(parent) = body.parent_session_id {
        output.push_str("],\"parent_session_id\":");
        push_json_string(output, &parent.to_string());
    } else {
        output.push(']');
    }
    output.push_str(",\"rendered_prompt\":");
    push_json_string(output, &body.rendered_prompt);
    output.push_str(",\"root_session_id\":");
    push_json_string(output, &body.root_session_id.to_string());
    output.push_str(",\"selected_agent\":");
    push_json_string(output, &body.selected_agent);
    output.push_str(",\"session_use\":");
    push_session_use(output, &body.session_use);
    output.push_str(",\"template_representation\":[");
    for (index, segment) in body.template_segments.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        push_json_string(output, segment);
    }
    output.push_str("],\"transcript\":");
    push_canonical(output, &body.transcript);
}

fn push_session_use(output: &mut String, session_use: &ModelSessionUseV1) {
    match session_use {
        ModelSessionUseV1::Inline => output.push_str("{\"kind\":\"inline\"}"),
        ModelSessionUseV1::Create {
            mode,
            session_id,
            parent_session_id,
            root_session_id,
            provenance,
        } => {
            output.push_str("{\"kind\":\"create\",\"mode\":");
            push_json_string(output, mode);
            output.push_str(",\"parent_session_id\":");
            push_json_string(output, &parent_session_id.to_string());
            output.push_str(",\"provenance\":");
            push_json_string(output, provenance);
            output.push_str(",\"root_session_id\":");
            push_json_string(output, &root_session_id.to_string());
            output.push_str(",\"session_id\":");
            push_json_string(output, &session_id.to_string());
            output.push('}');
        }
    }
}

fn push_validation_errors(output: &mut String, errors: &[ValidationErrorV1]) {
    for (index, error) in errors.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        output.push_str("{\"category\":");
        push_json_string(output, error.category.wire_name());
        if let Some(location) = &error.instance_location {
            output.push_str(",\"instance_location\":");
            push_json_string(output, location);
        }
        output.push_str(",\"message\":");
        push_json_string(output, &error.message);
        if let Some(location) = &error.schema_location {
            output.push_str(",\"schema_location\":");
            push_json_string(output, location);
        }
        output.push('}');
    }
}

fn guidance(header: &OperationRequestHeaderV1, captured: &CapturedOperationRequestV1) -> String {
    let input = match captured {
        CapturedOperationRequestV1::Model { body, .. } => format!(
            "model input has {} interpolation values and {} named inputs",
            body.interpolation_inputs.len(),
            body.named_inputs.len()
        ),
        CapturedOperationRequestV1::Action { body, .. } => {
            format!(
                "action input has {} ordered arguments",
                body.arguments.len()
            )
        }
    };
    format!(
        "Return exactly one strict JSON text with no prose or Markdown. Expected {} result of type {}; unknown struct properties are rejected and schema defaults define omissions. {input}. Limits: bytes={}, depth={}, nodes={}, string-scalars={}, list-items={}.",
        expected_result_kind(&header.expected_type),
        header.expected_type.canonical_string(),
        header.maximum_hook_output_bytes,
        header.value_limits.maximum_nesting_depth(),
        header.value_limits.maximum_nodes(),
        header.value_limits.maximum_string_scalars(),
        header.value_limits.maximum_list_items(),
    )
}

fn expected_result_kind(ty: &TypeDescriptor) -> &'static str {
    match ty.kind() {
        TypeKind::Unit => "unit",
        TypeKind::Decision => "decision",
        _ => "value",
    }
}

fn validate_schema(bytes: &[u8]) -> Result<(), HookRequestError> {
    let length = u64::try_from(bytes.len()).map_err(|_| HookRequestError::InvalidSchema)?;
    let document = StrictJsonDocument::decode(
        bytes,
        JsonLimits {
            maximum_bytes: length,
            maximum_nesting_depth: length.max(1),
            maximum_nodes: length.max(1),
            maximum_string_scalars: length.max(1),
            maximum_list_items: length.max(1),
        },
    )
    .map_err(|_| HookRequestError::InvalidSchema)?;
    if !matches!(document.node(document.root()), Some(JsonNode::Object(_))) {
        return Err(HookRequestError::InvalidSchema);
    }
    let canonical =
        CanonicalJson::from_document(&document).map_err(|_| HookRequestError::InvalidSchema)?;
    if canonical.bytes() != bytes {
        return Err(HookRequestError::InvalidSchema);
    }
    Ok(())
}

fn validate_session_use(session_use: &ModelSessionUseV1) -> Result<(), HookRequestError> {
    if let ModelSessionUseV1::Create {
        mode,
        session_id,
        parent_session_id,
        root_session_id,
        provenance,
    } = session_use
    {
        if !matches!(mode.as_ref(), "fork" | "new") || provenance.is_empty() {
            return Err(HookRequestError::InvalidShape);
        }
        for identity in [session_id, parent_session_id, root_session_id] {
            require_kind(*identity, IdentityKind::Session)?;
        }
    }
    Ok(())
}

fn require_kind(
    identity: ProtocolIdentity,
    expected: IdentityKind,
) -> Result<(), HookRequestError> {
    if identity.kind() == expected {
        Ok(())
    } else {
        Err(HookRequestError::IdentityKind)
    }
}

fn host_request(
    operation: EmbeddingOperation,
    bytes: Vec<u8>,
) -> Result<HostRequest, HookRequestError> {
    HostRequest::new(EmbeddingVersion::V1, operation, Arc::from(bytes))
        .map_err(|_| HookRequestError::Envelope)
}

fn push_optional_string(output: &mut String, value: Option<&str>) {
    if let Some(value) = value {
        push_json_string(output, value);
    } else {
        output.push_str("null");
    }
}

fn push_canonical(output: &mut String, value: &CanonicalJson) {
    output.push_str(
        std::str::from_utf8(value.bytes())
            .unwrap_or_else(|_| unreachable!("canonical JSON is UTF-8")),
    );
}

fn push_json_string(output: &mut String, value: &str) {
    output.push('"');
    for scalar in value.chars() {
        match scalar {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{08}' => output.push_str("\\b"),
            '\u{09}' => output.push_str("\\t"),
            '\n' => output.push_str("\\n"),
            '\u{0c}' => output.push_str("\\f"),
            '\r' => output.push_str("\\r"),
            value if value <= '\u{1f}' => output.push_str(&format!("\\u{:04x}", value as u32)),
            value => output.push(value),
        }
    }
    output.push('"');
}

#[cfg(test)]
mod tests {
    use gantry_core::strict_json::StrictJsonDocument;
    use gantry_core::value::DEFAULT_VALUE_LIMITS;
    use gantry_host::contracts::HostError;
    use gantry_ir::ActionParameter;

    use super::*;

    struct Identities(u8);

    impl IdentitySource for Identities {
        fn fresh_material(&self, _: IdentityKind) -> Result<[u8; 32], HostError> {
            Ok([self.0; 32])
        }
    }

    #[test]
    fn task_context_excludes_trace_fields_and_is_canonical() {
        let request = TaskContextV1 {
            execution_id: fresh(IdentityKind::Execution, 1),
            task_id: derived(IdentityKind::Task, b"task"),
            inherited_agent: Some(Arc::from("worker")),
            session: TaskSessionContextV1::Root {
                root_session_id: fresh(IdentityKind::Session, 2),
                provenance: RootSessionProvenanceV1::GantryCreated,
            },
        }
        .into_host_request()
        .unwrap_or_else(|error| panic!("task context failed: {error:?}"));
        let text = std::str::from_utf8(request.canonical_bytes())
            .unwrap_or_else(|error| panic!("task context was not UTF-8: {error}"));
        assert!(text.contains("\"task_context\""));
        for forbidden in ["workflow", "branch", "parent_task", "source", "ancestry"] {
            assert!(!text.contains(forbidden));
        }
        assert_canonical(request.canonical_bytes());
    }

    #[test]
    fn action_dispatch_is_canonical_stable_and_has_fresh_physical_identity() {
        let action = CanonicalPath::new("crate::lookup")
            .unwrap_or_else(|error| panic!("action path failed: {error}"));
        let parameter = ActionParameter::new("key", TypeDescriptor::STRING)
            .unwrap_or_else(|error| panic!("action parameter failed: {error}"));
        let value = canonical(br#""value""#);
        let captured = CapturedOperationRequestV1::Action {
            header: header(OperationSiteKind::Action, TypeDescriptor::STRING),
            body: ActionOperationRequestV1 {
                path: action.clone(),
                signature: CanonicalSignature::action(
                    RecoveryClass::ReadOnly,
                    &action,
                    &[parameter],
                    &TypeDescriptor::STRING,
                ),
                recovery: RecoveryClass::ReadOnly,
                mapping_revision: ActionMappingRevision::new("actions-v1")
                    .unwrap_or_else(|error| panic!("mapping revision failed: {error:?}")),
                arguments: vec![TypedActionArgumentV1 {
                    name: Arc::from("key"),
                    ty: TypeDescriptor::STRING,
                    value,
                }],
            },
        };
        let first = captured
            .prepare_dispatch(
                &FreshIdentityAllocator::default(),
                &Identities(7),
                0,
                0,
                &[],
            )
            .unwrap_or_else(|error| panic!("first dispatch failed: {error:?}"));
        let second = captured
            .prepare_dispatch(
                &FreshIdentityAllocator::default(),
                &Identities(8),
                0,
                0,
                &[],
            )
            .unwrap_or_else(|error| panic!("second dispatch failed: {error:?}"));
        assert_ne!(first.dispatch_id, second.dispatch_id);
        let first_text = std::str::from_utf8(first.request.canonical_bytes())
            .unwrap_or_else(|error| panic!("dispatch was not UTF-8: {error}"));
        assert!(first_text.contains("\"action_mapping_revision\":\"actions-v1\""));
        assert!(first_text.contains(
            "\"canonical_signature\":\"action[read_only] crate::lookup(key:String)->String\""
        ));
        for forbidden in [
            "selected_agent",
            "session_use",
            "source",
            "provider_history",
        ] {
            assert!(!first_text.contains(forbidden));
        }
        assert_canonical(first.request.canonical_bytes());
    }

    fn header(kind: OperationSiteKind, expected_type: TypeDescriptor) -> OperationRequestHeaderV1 {
        OperationRequestHeaderV1 {
            execution_id: fresh(IdentityKind::Execution, 1),
            task_id: derived(IdentityKind::Task, b"task"),
            operation_id: derived(IdentityKind::Operation, b"operation"),
            kind,
            expected_type,
            expected_schema: Arc::from(&br#"{"type":"string"}"#[..]),
            maximum_hook_output_bytes: 1_024,
            value_limits: DEFAULT_VALUE_LIMITS,
            workflow: CanonicalPath::new("crate::main")
                .unwrap_or_else(|error| panic!("workflow path failed: {error}")),
            site: StructuralPosition::new(vec![1, 2])
                .unwrap_or_else(|error| panic!("site failed: {error}")),
        }
    }

    fn fresh(kind: IdentityKind, byte: u8) -> ProtocolIdentity {
        ProtocolIdentity::from_fresh_material(kind, [byte; 32])
            .unwrap_or_else(|error| panic!("fresh identity failed: {error}"))
    }

    fn derived(kind: IdentityKind, key: &[u8]) -> ProtocolIdentity {
        ProtocolIdentity::derive(kind, key)
            .unwrap_or_else(|error| panic!("derived identity failed: {error}"))
    }

    fn canonical(bytes: &[u8]) -> CanonicalJson {
        let length = u64::try_from(bytes.len())
            .unwrap_or_else(|_| panic!("fixture length was not representable"));
        let document = StrictJsonDocument::decode(
            bytes,
            JsonLimits {
                maximum_bytes: length,
                maximum_nesting_depth: 16,
                maximum_nodes: length,
                maximum_string_scalars: length,
                maximum_list_items: length,
            },
        )
        .unwrap_or_else(|error| panic!("JSON decode failed: {error:?}"));
        CanonicalJson::from_document(&document)
            .unwrap_or_else(|error| panic!("canonical JSON failed: {error:?}"))
    }

    fn assert_canonical(bytes: &[u8]) {
        assert_eq!(canonical(bytes).bytes(), bytes);
    }
}
