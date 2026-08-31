//! Canonical logical-session transcripts and establishment boundaries.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use gantry_core::canonical_json::CanonicalJson;
use gantry_core::identity::ProtocolIdentity;
use gantry_core::portable::IdentityKind;
use gantry_core::strict_json::{JsonError, JsonLimits, JsonNode, JsonNodeId, StrictJsonDocument};
use gantry_core::value::ValueLimits;
use gantry_host::contracts::{
    EmbeddingVersion, EnvelopeError, HostError, HostRequest, IntegrationPreflight,
};
use gantry_host::embedding::EmbeddingOperation;
use gantry_ir::generated::{OperationSiteKind, TypeKind};
use gantry_ir::{StructuralPosition, TypeDescriptor};

use crate::{
    AdapterPoison, BoundaryFailure, InterpolationInputV1, InterpreterLifecycle, NamedInputV1,
};

#[cfg(feature = "durable")]
mod checkpoint_codec;
#[cfg(feature = "durable")]
use checkpoint_codec::{decode_session_checkpoint, encode_session_checkpoint};

const TRANSCRIPT_PREFIX: &str = "{\"protocol\":{\"major\":1,\"minor\":0},\"turns\":[";
const TRANSCRIPT_SUFFIX: &str = "]}";

/// Exact accepted-result kind retained in one transcript turn.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TranscriptResultKindV1 {
    /// An ordinary typed value.
    Value,
    /// The sole `Unit` value.
    Unit,
    /// A sealed `Decision` value.
    Decision,
}

impl TranscriptResultKindV1 {
    const fn wire_name(self) -> &'static str {
        match self {
            Self::Value => "value",
            Self::Unit => "unit",
            Self::Decision => "decision",
        }
    }
}

/// One normalized accepted model result retained in a transcript turn.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptedTranscriptResultV1 {
    /// Exact result-kind discriminator.
    pub kind: TranscriptResultKindV1,
    /// Canonical static result type.
    pub ty: TypeDescriptor,
    /// Normalized canonical strict-JSON result.
    pub value: CanonicalJson,
}

/// One canonical accepted prompt or decision exchange.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TranscriptTurnV1 {
    /// Prompt or decision operation kind.
    pub operation_kind: OperationSiteKind,
    /// Redacted literal template segments.
    pub template_representation: Vec<Arc<str>>,
    /// Fully rendered prompt.
    pub rendered_prompt: Arc<str>,
    /// Interpolation values in source order.
    pub interpolation_inputs: Vec<InterpolationInputV1>,
    /// Named `using` inputs in source order.
    pub using_inputs: Vec<NamedInputV1>,
    /// Selected logical agent.
    pub selected_agent: Arc<str>,
    /// Accepted normalized result.
    pub accepted_result: AcceptedTranscriptResultV1,
}

/// Complete canonical v1 logical-session transcript.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalTranscriptV1 {
    canonical: CanonicalJson,
}

impl CanonicalTranscriptV1 {
    /// Constructs the exact empty v1 transcript.
    #[must_use]
    pub fn empty() -> Self {
        Self::decode(
            format!("{TRANSCRIPT_PREFIX}{TRANSCRIPT_SUFFIX}").as_bytes(),
            ValueLimits::new(u64::MAX, u64::MAX, u64::MAX, u64::MAX)
                .unwrap_or_else(|| unreachable!("maximum limits are positive")),
        )
        .unwrap_or_else(|_| unreachable!("empty transcript is valid"))
    }

    /// Decodes one exact canonical transcript and validates every closed field.
    pub fn decode(bytes: &[u8], limits: ValueLimits) -> Result<Self, TranscriptError> {
        let document = decode_transcript(bytes, limits)?;
        validate_transcript_document(&document)?;
        let canonical =
            CanonicalJson::from_document(&document).map_err(|_| TranscriptError::Invalid)?;
        if canonical.bytes() != bytes {
            return Err(TranscriptError::Invalid);
        }
        Ok(Self { canonical })
    }

    /// Returns the exact canonical transcript bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        self.canonical.bytes()
    }

    /// Returns the canonical JSON owner used by hook requests and durable state.
    #[must_use]
    pub const fn canonical_json(&self) -> &CanonicalJson {
        &self.canonical
    }

    /// Validates a complete proposed transcript before atomically appending one turn.
    pub fn append(
        &mut self,
        turn: &TranscriptTurnV1,
        limits: ValueLimits,
    ) -> Result<(), TranscriptError> {
        validate_turn(turn)?;
        let current = std::str::from_utf8(self.bytes()).map_err(|_| TranscriptError::Invalid)?;
        let inner = current
            .strip_prefix(TRANSCRIPT_PREFIX)
            .and_then(|value| value.strip_suffix(TRANSCRIPT_SUFFIX))
            .ok_or(TranscriptError::Invalid)?;
        let mut candidate = String::from(TRANSCRIPT_PREFIX);
        candidate.push_str(inner);
        if !inner.is_empty() {
            candidate.push(',');
        }
        push_turn(&mut candidate, turn);
        candidate.push_str(TRANSCRIPT_SUFFIX);
        let proposed = Self::decode(candidate.as_bytes(), limits)?;
        *self = proposed;
        Ok(())
    }
}

/// Transcript validation or atomic-extension failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TranscriptError {
    /// The bytes are not one exact closed canonical v1 transcript.
    Invalid,
    /// The complete transcript exceeds an effective value limit.
    Limit,
}

/// Logical-session creation mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionCreationModeV1 {
    /// Embedder-supplied root resolved during start preflight.
    EmbedderRoot,
    /// Gantry-created root established before first model use.
    GantryRoot,
    /// Fresh empty non-root session.
    New,
    /// Creation-time snapshot of the enclosing session.
    Fork,
}

impl SessionCreationModeV1 {
    const fn wire_name(self) -> &'static str {
        match self {
            Self::EmbedderRoot => "embedder-root",
            Self::GantryRoot => "gantry-root",
            Self::New => "new",
            Self::Fork => "fork",
        }
    }
}

/// Integration establishment path for one logical session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionEstablishmentV1 {
    /// `ResolveSessions` already resolved this embedder root.
    ResolvedPreflight,
    /// `EstablishSession` must run before first use or use as a parent.
    Separate,
    /// One operation request carries `session-use = create`.
    OperationRequest,
}

/// One Gantry-owned logical-session record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogicalSessionV1 {
    /// Accepted execution that owns this logical session.
    pub execution_id: ProtocolIdentity,
    /// Stable logical-session identity.
    pub id: ProtocolIdentity,
    /// Optional enclosing session.
    pub parent: Option<ProtocolIdentity>,
    /// Execution root session.
    pub root: ProtocolIdentity,
    /// Exact creation mode.
    pub mode: SessionCreationModeV1,
    /// Integration establishment path.
    pub establishment: SessionEstablishmentV1,
    /// Creator task for non-root sessions.
    pub creator_task: Option<ProtocolIdentity>,
    /// Canonical creation site for non-root sessions.
    pub creation_site: Option<StructuralPosition>,
    /// Zero-based dynamic occurrence at the creation site for non-root sessions.
    pub creation_occurrence: Option<u64>,
    /// Gantry-owned authoritative canonical transcript.
    pub transcript: CanonicalTranscriptV1,
}

/// One execution-scoped logical-session registry.
#[derive(Debug)]
pub struct LogicalSessionRegistryV1 {
    execution_id: ProtocolIdentity,
    sessions: BTreeMap<ProtocolIdentity, LogicalSessionV1>,
    keys: BTreeMap<ProtocolIdentity, Arc<[u8]>>,
}

/// Complete execution-scoped logical-session recovery state.
#[cfg(feature = "durable")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogicalSessionRegistryCheckpointV1 {
    execution_id: ProtocolIdentity,
    sessions: BTreeMap<ProtocolIdentity, LogicalSessionV1>,
    keys: BTreeMap<ProtocolIdentity, Arc<[u8]>>,
}

#[cfg(feature = "durable")]
impl LogicalSessionRegistryCheckpointV1 {
    /// Returns the accepted execution represented by this checkpoint.
    #[must_use]
    pub const fn execution_id(&self) -> ProtocolIdentity {
        self.execution_id
    }

    /// Returns the number of retained logical sessions.
    #[must_use]
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Encodes the unique version-one logical-session checkpoint.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        encode_session_checkpoint(self)
    }

    /// Decodes one exact version-one session checkpoint.
    pub fn decode(bytes: &[u8], limits: ValueLimits) -> Result<Self, SessionRecoveryError> {
        decode_session_checkpoint(bytes, limits)
    }
}

/// Rejection of malformed or inconsistent logical-session recovery state.
#[cfg(feature = "durable")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionRecoveryError {
    /// Checkpoint bytes are truncated, noncanonical, or use another version.
    InvalidEncoding,
    /// Session descriptors, parentage, transcripts, or derivation keys disagree.
    InvalidCheckpoint,
}

impl LogicalSessionRegistryV1 {
    /// Creates a registry containing one accepted root session.
    pub fn new(
        execution_id: ProtocolIdentity,
        root_id: ProtocolIdentity,
        mode: SessionCreationModeV1,
        transcript: CanonicalTranscriptV1,
    ) -> Result<Self, SessionError> {
        require_identity(execution_id, IdentityKind::Execution)?;
        require_identity(root_id, IdentityKind::Session)?;
        if !matches!(
            mode,
            SessionCreationModeV1::EmbedderRoot | SessionCreationModeV1::GantryRoot
        ) {
            return Err(SessionError::InvalidDescriptor);
        }
        let establishment = if mode == SessionCreationModeV1::EmbedderRoot {
            SessionEstablishmentV1::ResolvedPreflight
        } else {
            SessionEstablishmentV1::Separate
        };
        let root = LogicalSessionV1 {
            execution_id,
            id: root_id,
            parent: None,
            root: root_id,
            mode,
            establishment,
            creator_task: None,
            creation_site: None,
            creation_occurrence: None,
            transcript,
        };
        Ok(Self {
            execution_id,
            sessions: BTreeMap::from([(root_id, root)]),
            keys: BTreeMap::new(),
        })
    }

    /// Returns one immutable logical-session record.
    #[must_use]
    pub fn get(&self, id: ProtocolIdentity) -> Option<&LogicalSessionV1> {
        self.sessions.get(&id)
    }

    /// Returns one mutable logical-session record for atomic transcript extension.
    pub fn get_mut(&mut self, id: ProtocolIdentity) -> Option<&mut LogicalSessionV1> {
        self.sessions.get_mut(&id)
    }

    /// Returns all logical sessions in canonical identity order.
    pub fn sessions(&self) -> impl Iterator<Item = &LogicalSessionV1> {
        self.sessions.values()
    }

    /// Captures complete typed session and transcript state for durable recovery.
    #[cfg(feature = "durable")]
    #[must_use]
    pub fn checkpoint(&self) -> LogicalSessionRegistryCheckpointV1 {
        LogicalSessionRegistryCheckpointV1 {
            execution_id: self.execution_id,
            sessions: self.sessions.clone(),
            keys: self.keys.clone(),
        }
    }

    /// Reconstructs the session registry from one validated durable checkpoint.
    #[cfg(feature = "durable")]
    pub fn recover_from_checkpoint(
        checkpoint: LogicalSessionRegistryCheckpointV1,
    ) -> Result<Self, SessionRecoveryError> {
        validate_session_checkpoint(&checkpoint)?;
        Ok(Self {
            execution_id: checkpoint.execution_id,
            sessions: checkpoint.sessions,
            keys: checkpoint.keys,
        })
    }

    #[cfg(all(test, feature = "concurrent"))]
    /// Returns the number of records for sibling-module invariant tests.
    pub(crate) fn len(&self) -> usize {
        self.sessions.len()
    }

    /// Creates or deterministically replays one non-root `new` or `fork` session.
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        &mut self,
        parent_id: ProtocolIdentity,
        creator_task: ProtocolIdentity,
        site: StructuralPosition,
        occurrence: u64,
        mode: SessionCreationModeV1,
        establishment: SessionEstablishmentV1,
    ) -> Result<&LogicalSessionV1, SessionError> {
        require_identity(creator_task, IdentityKind::Task)?;
        if !matches!(
            mode,
            SessionCreationModeV1::New | SessionCreationModeV1::Fork
        ) || establishment == SessionEstablishmentV1::ResolvedPreflight
        {
            return Err(SessionError::InvalidDescriptor);
        }
        let parent = self
            .sessions
            .get(&parent_id)
            .ok_or(SessionError::UnknownParent)?;
        let key = session_key(
            self.execution_id,
            parent_id,
            parent.root,
            creator_task,
            &site,
            occurrence,
            mode,
        );
        let id = ProtocolIdentity::derive(IdentityKind::Session, &key)
            .map_err(|_| SessionError::IdentityInvariant)?;
        if id == parent.root {
            return Err(SessionError::IdentityInvariant);
        }
        if let Some(existing_key) = self.keys.get(&id) {
            if existing_key.as_ref() != key.as_slice() {
                return Err(SessionError::IdentityInvariant);
            }
            return self
                .sessions
                .get(&id)
                .ok_or(SessionError::IdentityInvariant);
        }
        if self.sessions.contains_key(&id) {
            return Err(SessionError::IdentityInvariant);
        }
        let transcript = if mode == SessionCreationModeV1::Fork {
            parent.transcript.clone()
        } else {
            CanonicalTranscriptV1::empty()
        };
        let session = LogicalSessionV1 {
            execution_id: self.execution_id,
            id,
            parent: Some(parent_id),
            root: parent.root,
            mode,
            establishment,
            creator_task: Some(creator_task),
            creation_site: Some(site),
            creation_occurrence: Some(occurrence),
            transcript,
        };
        self.keys.insert(id, Arc::from(key));
        self.sessions.insert(id, session);
        self.sessions
            .get(&id)
            .ok_or(SessionError::IdentityInvariant)
    }
}

/// Logical-session registry failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionError {
    /// One typed identity has the wrong kind.
    IdentityKind,
    /// The requested enclosing session is absent.
    UnknownParent,
    /// Session metadata uses an invalid mode or establishment combination.
    InvalidDescriptor,
    /// Deterministic identity derivation disagreed with live execution state.
    IdentityInvariant,
}

/// Structured failure at the separate `EstablishSession` boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionEstablishmentError {
    /// Session descriptor or envelope construction failed before integration invocation.
    InvalidRequest,
    /// Integration code returned a structured host failure.
    Host(HostError),
    /// Integration code panicked while invoked, polled, or destroyed.
    Boundary(BoundaryFailure),
    /// The integration returned another version, operation, or result shape.
    InvalidResponse,
}

/// Idempotent execution-scoped `EstablishSession` coordinator.
pub struct SessionEstablisher<'a> {
    lifecycle: &'a InterpreterLifecycle,
    preflight: &'a dyn IntegrationPreflight,
    poison: AdapterPoison,
    established: BTreeSet<(ProtocolIdentity, ProtocolIdentity)>,
}

impl<'a> SessionEstablisher<'a> {
    /// Binds one integration preflight owner without invoking it.
    #[must_use]
    pub fn new(
        lifecycle: &'a InterpreterLifecycle,
        preflight: &'a dyn IntegrationPreflight,
        poison: AdapterPoison,
    ) -> Self {
        Self {
            lifecycle,
            preflight,
            poison,
            established: BTreeSet::new(),
        }
    }

    /// Establishes one separately created session at most once per in-process run.
    pub async fn establish(
        &mut self,
        execution_id: ProtocolIdentity,
        session: &LogicalSessionV1,
    ) -> Result<(), SessionEstablishmentError> {
        require_identity(execution_id, IdentityKind::Execution)
            .map_err(|_| SessionEstablishmentError::InvalidRequest)?;
        if session.execution_id != execution_id {
            return Err(SessionEstablishmentError::InvalidRequest);
        }
        if session.establishment != SessionEstablishmentV1::Separate {
            return Ok(());
        }
        let key = (execution_id, session.id);
        if self.established.contains(&key) {
            return Ok(());
        }
        let request = establish_request(execution_id, session)?;
        let future = self
            .lifecycle
            .catch_adapter(&self.poison, || self.preflight.call(request))
            .map_err(SessionEstablishmentError::Boundary)?;
        let response = self
            .lifecycle
            .contain_adapter_future(future, self.poison.clone())
            .await
            .map_err(SessionEstablishmentError::Boundary)?
            .map_err(SessionEstablishmentError::Host)?;
        if response.version() != EmbeddingVersion::V1
            || response.operation() != EmbeddingOperation::EstablishSession
            || response.canonical_bytes() != b"{\"result\":\"established\"}"
        {
            return Err(SessionEstablishmentError::InvalidResponse);
        }
        self.established.insert(key);
        Ok(())
    }
}

fn decode_transcript(
    bytes: &[u8],
    limits: ValueLimits,
) -> Result<StrictJsonDocument, TranscriptError> {
    let maximum_bytes = u64::try_from(bytes.len()).map_err(|_| TranscriptError::Limit)?;
    StrictJsonDocument::decode(
        bytes,
        JsonLimits {
            maximum_bytes,
            maximum_nesting_depth: limits.maximum_nesting_depth(),
            maximum_nodes: limits.maximum_nodes(),
            maximum_string_scalars: limits.maximum_string_scalars(),
            maximum_list_items: limits.maximum_list_items(),
        },
    )
    .map_err(|error| match error {
        JsonError::ResourceLimit { .. } => TranscriptError::Limit,
        _ => TranscriptError::Invalid,
    })
}

fn validate_transcript_document(document: &StrictJsonDocument) -> Result<(), TranscriptError> {
    let root = object(document, document.root(), &["protocol", "turns"])?;
    let protocol = object(document, member(root, "protocol")?, &["major", "minor"])?;
    if integer(document, member(protocol, "major")?) != Some(1)
        || integer(document, member(protocol, "minor")?) != Some(0)
    {
        return Err(TranscriptError::Invalid);
    }
    let turns = array(document, member(root, "turns")?)?;
    for turn in turns {
        validate_turn_node(document, *turn)?;
    }
    Ok(())
}

fn validate_turn_node(
    document: &StrictJsonDocument,
    id: JsonNodeId,
) -> Result<(), TranscriptError> {
    let turn = object(
        document,
        id,
        &[
            "accepted_result",
            "interpolation_inputs",
            "operation_kind",
            "rendered_prompt",
            "selected_agent",
            "template_representation",
            "using_inputs",
        ],
    )?;
    if !matches!(
        string(document, member(turn, "operation_kind")?),
        Some("prompt" | "decide")
    ) || string(document, member(turn, "rendered_prompt")?).is_none()
        || string(document, member(turn, "selected_agent")?).is_none_or(str::is_empty)
    {
        return Err(TranscriptError::Invalid);
    }
    for segment in array(document, member(turn, "template_representation")?)? {
        if string(document, *segment).is_none() {
            return Err(TranscriptError::Invalid);
        }
    }
    validate_inputs(document, member(turn, "interpolation_inputs")?, true)?;
    validate_inputs(document, member(turn, "using_inputs")?, false)?;
    let result = object(
        document,
        member(turn, "accepted_result")?,
        &["kind", "type", "value"],
    )?;
    let kind = string(document, member(result, "kind")?).ok_or(TranscriptError::Invalid)?;
    let ty = string(document, member(result, "type")?).ok_or(TranscriptError::Invalid)?;
    let ty = TypeDescriptor::from_canonical_string(ty).map_err(|_| TranscriptError::Invalid)?;
    if !matches!(kind, "value" | "unit" | "decision")
        || kind == "unit" && ty.kind() != TypeKind::Unit
        || kind == "decision" && ty.kind() != TypeKind::Decision
        || kind == "value" && matches!(ty.kind(), TypeKind::Unit | TypeKind::Decision)
    {
        return Err(TranscriptError::Invalid);
    }
    Ok(())
}

fn validate_inputs(
    document: &StrictJsonDocument,
    id: JsonNodeId,
    interpolation: bool,
) -> Result<(), TranscriptError> {
    let mut names = BTreeSet::new();
    for (index, input) in array(document, id)?.iter().enumerate() {
        let fields: &[&str] = if interpolation {
            &["position", "type", "value"]
        } else {
            &["name", "type", "value"]
        };
        let input = object(document, *input, fields)?;
        if interpolation {
            if integer(document, member(input, "position")?)
                != u64::try_from(index)
                    .ok()
                    .and_then(|value| i64::try_from(value).ok())
            {
                return Err(TranscriptError::Invalid);
            }
        } else {
            let name = string(document, member(input, "name")?)
                .filter(|name| !name.is_empty())
                .ok_or(TranscriptError::Invalid)?;
            if !names.insert(name) {
                return Err(TranscriptError::Invalid);
            }
        }
        let ty = string(document, member(input, "type")?).ok_or(TranscriptError::Invalid)?;
        TypeDescriptor::from_canonical_string(ty).map_err(|_| TranscriptError::Invalid)?;
    }
    Ok(())
}

fn validate_turn(turn: &TranscriptTurnV1) -> Result<(), TranscriptError> {
    let mut using_names = BTreeSet::new();
    if !matches!(
        turn.operation_kind,
        OperationSiteKind::Prompt | OperationSiteKind::Decide
    ) || turn.selected_agent.is_empty()
        || turn
            .interpolation_inputs
            .iter()
            .enumerate()
            .any(|(index, input)| u64::try_from(index).ok() != Some(input.position))
        || turn
            .using_inputs
            .iter()
            .any(|input| input.name.is_empty() || !using_names.insert(input.name.as_ref()))
    {
        return Err(TranscriptError::Invalid);
    }
    let result = &turn.accepted_result;
    if result.kind == TranscriptResultKindV1::Unit && result.ty.kind() != TypeKind::Unit
        || result.kind == TranscriptResultKindV1::Decision && result.ty.kind() != TypeKind::Decision
        || result.kind == TranscriptResultKindV1::Value
            && matches!(result.ty.kind(), TypeKind::Unit | TypeKind::Decision)
    {
        return Err(TranscriptError::Invalid);
    }
    Ok(())
}

fn push_turn(output: &mut String, turn: &TranscriptTurnV1) {
    output.push_str("{\"accepted_result\":{\"kind\":");
    push_json_string(output, turn.accepted_result.kind.wire_name());
    output.push_str(",\"type\":");
    push_json_string(output, &turn.accepted_result.ty.canonical_string());
    output.push_str(",\"value\":");
    push_canonical(output, &turn.accepted_result.value);
    output.push_str("},\"interpolation_inputs\":[");
    for (index, input) in turn.interpolation_inputs.iter().enumerate() {
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
    output.push_str("],\"operation_kind\":");
    push_json_string(output, turn.operation_kind.wire_name());
    output.push_str(",\"rendered_prompt\":");
    push_json_string(output, &turn.rendered_prompt);
    output.push_str(",\"selected_agent\":");
    push_json_string(output, &turn.selected_agent);
    output.push_str(",\"template_representation\":[");
    for (index, segment) in turn.template_representation.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        push_json_string(output, segment);
    }
    output.push_str("],\"using_inputs\":[");
    for (index, input) in turn.using_inputs.iter().enumerate() {
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
    output.push_str("]}");
}

fn establish_request(
    execution_id: ProtocolIdentity,
    session: &LogicalSessionV1,
) -> Result<HostRequest, SessionEstablishmentError> {
    require_identity(session.id, IdentityKind::Session)
        .map_err(|_| SessionEstablishmentError::InvalidRequest)?;
    let mut descriptor = String::from("{\"creation_mode\":");
    push_json_string(&mut descriptor, session.mode.wire_name());
    if let Some(creator) = session.creator_task {
        require_identity(creator, IdentityKind::Task)
            .map_err(|_| SessionEstablishmentError::InvalidRequest)?;
        descriptor.push_str(",\"creator_task_id\":");
        push_json_string(&mut descriptor, &creator.to_string());
    }
    descriptor.push_str(",\"execution_id\":");
    push_json_string(&mut descriptor, &execution_id.to_string());
    if let Some(parent) = session.parent {
        descriptor.push_str(",\"parent_session_id\":");
        push_json_string(&mut descriptor, &parent.to_string());
    }
    descriptor.push_str(",\"root_session_id\":");
    push_json_string(&mut descriptor, &session.root.to_string());
    descriptor.push_str(",\"session_id\":");
    push_json_string(&mut descriptor, &session.id.to_string());
    descriptor.push_str(",\"transcript\":");
    descriptor.push_str(
        std::str::from_utf8(session.transcript.bytes())
            .map_err(|_| SessionEstablishmentError::InvalidRequest)?,
    );
    descriptor.push('}');
    HostRequest::new(
        EmbeddingVersion::V1,
        EmbeddingOperation::EstablishSession,
        Arc::from(format!("{{\"session_descriptor\":{descriptor}}}").into_bytes()),
    )
    .map_err(|_error: EnvelopeError| SessionEstablishmentError::InvalidRequest)
}

fn session_key(
    execution_id: ProtocolIdentity,
    parent_id: ProtocolIdentity,
    root_id: ProtocolIdentity,
    creator_task: ProtocolIdentity,
    site: &StructuralPosition,
    occurrence: u64,
    mode: SessionCreationModeV1,
) -> Vec<u8> {
    let mut output = String::from("{\"creator_task\":");
    push_json_string(&mut output, &creator_task.to_string());
    output.push_str(",\"execution\":");
    push_json_string(&mut output, &execution_id.to_string());
    output.push_str(",\"mode\":");
    push_json_string(&mut output, mode.wire_name());
    output.push_str(",\"occurrence\":");
    output.push_str(&occurrence.to_string());
    output.push_str(",\"parent\":");
    push_json_string(&mut output, &parent_id.to_string());
    output.push_str(",\"root\":");
    push_json_string(&mut output, &root_id.to_string());
    output.push_str(",\"site\":[");
    for (index, component) in site.components().iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        output.push_str(&component.to_string());
    }
    output.push_str("]}");
    output.into_bytes()
}

#[cfg(feature = "durable")]
fn validate_session_checkpoint(
    checkpoint: &LogicalSessionRegistryCheckpointV1,
) -> Result<(), SessionRecoveryError> {
    if checkpoint.execution_id.kind() != IdentityKind::Execution || checkpoint.sessions.is_empty() {
        return Err(SessionRecoveryError::InvalidCheckpoint);
    }
    let roots = checkpoint
        .sessions
        .values()
        .filter(|session| session.parent.is_none())
        .collect::<Vec<_>>();
    if roots.len() != 1 {
        return Err(SessionRecoveryError::InvalidCheckpoint);
    }
    let root = roots[0];
    if root.execution_id != checkpoint.execution_id
        || root.id.kind() != IdentityKind::Session
        || root.root != root.id
        || !matches!(
            root.mode,
            SessionCreationModeV1::EmbedderRoot | SessionCreationModeV1::GantryRoot
        )
        || root.creator_task.is_some()
        || root.creation_site.is_some()
        || root.creation_occurrence.is_some()
        || checkpoint.keys.contains_key(&root.id)
    {
        return Err(SessionRecoveryError::InvalidCheckpoint);
    }
    for (id, session) in &checkpoint.sessions {
        if *id != session.id
            || session.execution_id != checkpoint.execution_id
            || session.id.kind() != IdentityKind::Session
            || session.root != root.id
        {
            return Err(SessionRecoveryError::InvalidCheckpoint);
        }
        if session.parent.is_none() {
            continue;
        }
        let parent = session
            .parent
            .and_then(|parent| checkpoint.sessions.get(&parent))
            .ok_or(SessionRecoveryError::InvalidCheckpoint)?;
        let creator = session
            .creator_task
            .filter(|creator| creator.kind() == IdentityKind::Task)
            .ok_or(SessionRecoveryError::InvalidCheckpoint)?;
        let site = session
            .creation_site
            .as_ref()
            .ok_or(SessionRecoveryError::InvalidCheckpoint)?;
        let occurrence = session
            .creation_occurrence
            .ok_or(SessionRecoveryError::InvalidCheckpoint)?;
        if parent.root != root.id
            || !matches!(
                session.mode,
                SessionCreationModeV1::New | SessionCreationModeV1::Fork
            )
            || session.establishment == SessionEstablishmentV1::ResolvedPreflight
        {
            return Err(SessionRecoveryError::InvalidCheckpoint);
        }
        let key = checkpoint
            .keys
            .get(id)
            .ok_or(SessionRecoveryError::InvalidCheckpoint)?;
        let expected_key = session_key(
            checkpoint.execution_id,
            parent.id,
            root.id,
            creator,
            site,
            occurrence,
            session.mode,
        );
        if key.as_ref() != expected_key.as_slice()
            || ProtocolIdentity::derive(IdentityKind::Session, &expected_key)
                .ok()
                .as_ref()
                != Some(id)
        {
            return Err(SessionRecoveryError::InvalidCheckpoint);
        }
    }
    if checkpoint.keys.len().saturating_add(1) != checkpoint.sessions.len()
        || checkpoint
            .keys
            .keys()
            .any(|id| !checkpoint.sessions.contains_key(id))
    {
        return Err(SessionRecoveryError::InvalidCheckpoint);
    }
    Ok(())
}

fn require_identity(
    identity: ProtocolIdentity,
    expected: IdentityKind,
) -> Result<(), SessionError> {
    if identity.kind() == expected {
        Ok(())
    } else {
        Err(SessionError::IdentityKind)
    }
}

fn object<'a>(
    document: &'a StrictJsonDocument,
    id: JsonNodeId,
    fields: &[&str],
) -> Result<&'a [(Arc<str>, JsonNodeId)], TranscriptError> {
    let Some(JsonNode::Object(members)) = document.node(id) else {
        return Err(TranscriptError::Invalid);
    };
    if members.len() != fields.len()
        || !fields
            .iter()
            .all(|field| members.iter().any(|(name, _)| name.as_ref() == *field))
    {
        return Err(TranscriptError::Invalid);
    }
    Ok(members)
}

fn member(members: &[(Arc<str>, JsonNodeId)], name: &str) -> Result<JsonNodeId, TranscriptError> {
    members
        .iter()
        .find(|(candidate, _)| candidate.as_ref() == name)
        .map(|(_, id)| *id)
        .ok_or(TranscriptError::Invalid)
}

fn array(document: &StrictJsonDocument, id: JsonNodeId) -> Result<&[JsonNodeId], TranscriptError> {
    match document.node(id) {
        Some(JsonNode::Array(items)) => Ok(items),
        _ => Err(TranscriptError::Invalid),
    }
}

fn string(document: &StrictJsonDocument, id: JsonNodeId) -> Option<&str> {
    match document.node(id) {
        Some(JsonNode::String(value)) => Some(value),
        _ => None,
    }
}

fn integer(document: &StrictJsonDocument, id: JsonNodeId) -> Option<i64> {
    match document.node(id) {
        Some(JsonNode::Number(value)) => value.to_gantry_int().ok(),
        _ => None,
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
    use gantry_ir::TypeDescriptor;

    use super::*;

    #[test]
    fn transcript_append_is_canonical_and_atomic_at_limits() {
        let mut transcript = CanonicalTranscriptV1::empty();
        let first_turn = turn("hello");
        transcript
            .append(&first_turn, DEFAULT_VALUE_LIMITS)
            .unwrap_or_else(|error| panic!("append failed: {error:?}"));
        assert!(std::str::from_utf8(transcript.bytes()).is_ok_and(|value| {
            value.starts_with(TRANSCRIPT_PREFIX)
                && value.contains("\"operation_kind\":\"prompt\"")
                && value.ends_with(TRANSCRIPT_SUFFIX)
        }));

        let before = transcript.clone();
        let tiny =
            ValueLimits::new(32, 256, 2, 16).unwrap_or_else(|| unreachable!("positive limits"));
        assert_eq!(
            transcript.append(&turn("too long"), tiny),
            Err(TranscriptError::Limit)
        );
        assert_eq!(transcript, before);
    }

    #[test]
    fn registry_new_and_fork_preserve_creation_time_transcripts() {
        let execution = fresh(IdentityKind::Execution, 1);
        let root = fresh(IdentityKind::Session, 2);
        let task = ProtocolIdentity::derive(IdentityKind::Task, b"task")
            .unwrap_or_else(|error| panic!("task identity failed: {error}"));
        let mut registry = LogicalSessionRegistryV1::new(
            execution,
            root,
            SessionCreationModeV1::GantryRoot,
            CanonicalTranscriptV1::empty(),
        )
        .unwrap_or_else(|error| panic!("registry failed: {error:?}"));
        registry
            .get_mut(root)
            .unwrap_or_else(|| panic!("root missing"))
            .transcript
            .append(&turn("root"), DEFAULT_VALUE_LIMITS)
            .unwrap_or_else(|error| panic!("root append failed: {error:?}"));
        let site =
            StructuralPosition::new(vec![1]).unwrap_or_else(|error| panic!("site failed: {error}"));
        let fork = registry
            .create(
                root,
                task,
                site.clone(),
                0,
                SessionCreationModeV1::Fork,
                SessionEstablishmentV1::Separate,
            )
            .unwrap_or_else(|error| panic!("fork failed: {error:?}"))
            .clone();
        let new = registry
            .create(
                root,
                task,
                site,
                1,
                SessionCreationModeV1::New,
                SessionEstablishmentV1::OperationRequest,
            )
            .unwrap_or_else(|error| panic!("new failed: {error:?}"))
            .clone();
        assert_eq!(
            fork.transcript,
            registry
                .get(root)
                .unwrap_or_else(|| unreachable!())
                .transcript
        );
        assert_eq!(new.transcript, CanonicalTranscriptV1::empty());
        assert_ne!(fork.id, new.id);

        #[cfg(feature = "durable")]
        {
            let checkpoint = registry.checkpoint();
            let bytes = checkpoint.canonical_bytes();
            let decoded = LogicalSessionRegistryCheckpointV1::decode(&bytes, DEFAULT_VALUE_LIMITS)
                .unwrap_or_else(|error| panic!("session checkpoint decode failed: {error:?}"));
            assert_eq!(decoded, checkpoint);
            let recovered = LogicalSessionRegistryV1::recover_from_checkpoint(decoded)
                .unwrap_or_else(|error| panic!("session recovery failed: {error:?}"));
            assert_eq!(recovered.get(fork.id), Some(&fork));
            assert_eq!(recovered.get(new.id), Some(&new));
        }
    }

    fn turn(prompt: &str) -> TranscriptTurnV1 {
        TranscriptTurnV1 {
            operation_kind: OperationSiteKind::Prompt,
            template_representation: vec![Arc::from("template")],
            rendered_prompt: Arc::from(prompt),
            interpolation_inputs: Vec::new(),
            using_inputs: Vec::new(),
            selected_agent: Arc::from("worker"),
            accepted_result: AcceptedTranscriptResultV1 {
                kind: TranscriptResultKindV1::Value,
                ty: TypeDescriptor::STRING,
                value: canonical(br#""ok""#),
            },
        }
    }

    fn canonical(bytes: &[u8]) -> CanonicalJson {
        let document = StrictJsonDocument::decode(
            bytes,
            JsonLimits {
                maximum_bytes: 1_024,
                maximum_nesting_depth: 16,
                maximum_nodes: 128,
                maximum_string_scalars: 128,
                maximum_list_items: 128,
            },
        )
        .unwrap_or_else(|error| panic!("JSON failed: {error:?}"));
        CanonicalJson::from_document(&document)
            .unwrap_or_else(|error| panic!("canonical JSON failed: {error:?}"))
    }

    fn fresh(kind: IdentityKind, byte: u8) -> ProtocolIdentity {
        ProtocolIdentity::from_fresh_material(kind, [byte; 32])
            .unwrap_or_else(|error| panic!("identity failed: {error}"))
    }
}
