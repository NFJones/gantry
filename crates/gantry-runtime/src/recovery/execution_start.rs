//! Versioned sequence-one execution-start evidence.

use std::sync::Arc;

use gantry_core::identity::ProtocolIdentity;
use gantry_core::portable::{CancellationReasonCategory, IdentityKind};
use gantry_core::strict_json::{JsonLimits, StrictJsonDocument};
use gantry_host::journal::{
    BatchLocalEvidenceId, JournalContractError, JournalEvidenceReferenceV1, UnfinalizedEvidenceV1,
};
use gantry_ir::MachineProgram;

use crate::machine::{decode_machine_program, encode_machine_program};
use crate::{CancellationCausalIdentity, CancellationReason};

use super::{
    DurableCommitCutV1, DurableEvidenceError, DurableLogicalEvidenceV1, decode_hex, encode_hex,
    field, is_canonical_json, object, push_json_string, require_exact_fields, string,
};

/// Exact sequence-one record that binds immutable execution metadata to recoverable state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableExecutionStartV1 {
    execution_id: ProtocolIdentity,
    task_id: ProtocolIdentity,
    metadata: Arc<[u8]>,
    program: Arc<[u8]>,
    state: DurableLogicalEvidenceV1,
}

impl DurableExecutionStartV1 {
    /// Constructs one execution-start record over canonical immutable metadata and a checkpoint.
    pub fn new(
        execution_id: ProtocolIdentity,
        task_id: ProtocolIdentity,
        program: &MachineProgram,
        metadata: impl Into<Arc<[u8]>>,
        state: DurableLogicalEvidenceV1,
    ) -> Result<Self, DurableEvidenceError> {
        let metadata = metadata.into();
        if execution_id.kind() != IdentityKind::Execution
            || task_id.kind() != IdentityKind::Task
            || state.execution_id() != execution_id
            || state.task_id() != task_id
            || state.cut() != DurableCommitCutV1::Checkpoint
            || !is_canonical_json(&metadata)
        {
            return Err(DurableEvidenceError::InvalidExecutionStart);
        }
        Ok(Self {
            execution_id,
            task_id,
            metadata,
            program: Arc::from(encode_machine_program(program)),
            state,
        })
    }

    /// Returns the fresh execution identity accepted by this record.
    #[must_use]
    pub const fn execution_id(&self) -> ProtocolIdentity {
        self.execution_id
    }

    /// Returns the stable root task identity bound to sequence one.
    #[must_use]
    pub const fn task_id(&self) -> ProtocolIdentity {
        self.task_id
    }

    /// Returns exact canonical immutable start metadata bytes.
    #[must_use]
    pub fn metadata(&self) -> &[u8] {
        &self.metadata
    }

    /// Reconstructs the exact analyzer-owned executable program retained at sequence one.
    pub fn program(&self) -> Result<MachineProgram, DurableEvidenceError> {
        decode_machine_program(&self.program).map_err(DurableEvidenceError::Checkpoint)
    }

    /// Returns the embedded same-machine checkpoint evidence.
    #[must_use]
    pub const fn state(&self) -> &DurableLogicalEvidenceV1 {
        &self.state
    }

    /// Encodes the unique version-one sequence-one body.
    #[must_use]
    pub fn canonical_body(&self) -> Vec<u8> {
        let mut output = String::from("{\"execution_id\":");
        push_json_string(&mut output, &self.execution_id.to_string());
        output.push_str(",\"format\":\"gantry.execution-start/v1\",\"metadata\":");
        push_json_string(&mut output, &encode_hex(&self.metadata));
        output.push_str(",\"program\":");
        push_json_string(&mut output, &encode_hex(&self.program));
        output.push_str(",\"state\":");
        push_json_string(&mut output, &encode_hex(&self.state.canonical_body()));
        output.push_str(",\"task_id\":");
        push_json_string(&mut output, &self.task_id.to_string());
        output.push('}');
        output.into_bytes()
    }

    /// Decodes one exact version-one sequence-one body against its immutable program.
    pub fn decode(program: &MachineProgram, body: &[u8]) -> Result<Self, DurableEvidenceError> {
        let maximum_bytes =
            u64::try_from(body.len()).map_err(|_| DurableEvidenceError::Encoding)?;
        let document = gantry_core::strict_json::StrictJsonDocument::decode(
            body,
            gantry_core::strict_json::JsonLimits {
                maximum_bytes,
                maximum_nesting_depth: maximum_bytes.max(1),
                maximum_nodes: maximum_bytes.max(1),
                maximum_string_scalars: maximum_bytes.max(1),
                maximum_list_items: maximum_bytes.max(1),
            },
        )
        .map_err(|_| DurableEvidenceError::Encoding)?;
        let root = object(&document, document.root())?;
        require_exact_fields(
            root,
            &[
                "execution_id",
                "format",
                "metadata",
                "program",
                "state",
                "task_id",
            ],
        )?;
        if string(&document, field(root, "format")?)? != "gantry.execution-start/v1" {
            return Err(DurableEvidenceError::Encoding);
        }
        let execution_id = ProtocolIdentity::parse_kind(
            string(&document, field(root, "execution_id")?)?,
            IdentityKind::Execution,
        )
        .map_err(|_| DurableEvidenceError::Encoding)?;
        let task_id = ProtocolIdentity::parse_kind(
            string(&document, field(root, "task_id")?)?,
            IdentityKind::Task,
        )
        .map_err(|_| DurableEvidenceError::Encoding)?;
        let metadata = Arc::<[u8]>::from(decode_hex(string(&document, field(root, "metadata")?)?)?);
        let retained_program =
            Arc::<[u8]>::from(decode_hex(string(&document, field(root, "program")?)?)?);
        let decoded_program =
            decode_machine_program(&retained_program).map_err(DurableEvidenceError::Checkpoint)?;
        if &decoded_program != program {
            return Err(DurableEvidenceError::InvalidExecutionStart);
        }
        let state_bytes = decode_hex(string(&document, field(root, "state")?)?)?;
        let state = DurableLogicalEvidenceV1::decode(program, &state_bytes)?;
        let decoded = Self::new(execution_id, task_id, program, metadata, state)?;
        if decoded.canonical_body() != body {
            return Err(DurableEvidenceError::Encoding);
        }
        Ok(decoded)
    }

    /// Extracts and validates the retained executable program before full prefix projection.
    pub fn retained_program(body: &[u8]) -> Result<MachineProgram, DurableEvidenceError> {
        let maximum_bytes =
            u64::try_from(body.len()).map_err(|_| DurableEvidenceError::Encoding)?;
        let document = gantry_core::strict_json::StrictJsonDocument::decode(
            body,
            gantry_core::strict_json::JsonLimits {
                maximum_bytes,
                maximum_nesting_depth: maximum_bytes.max(1),
                maximum_nodes: maximum_bytes.max(1),
                maximum_string_scalars: maximum_bytes.max(1),
                maximum_list_items: maximum_bytes.max(1),
            },
        )
        .map_err(|_| DurableEvidenceError::Encoding)?;
        let root = object(&document, document.root())?;
        require_exact_fields(
            root,
            &[
                "execution_id",
                "format",
                "metadata",
                "program",
                "state",
                "task_id",
            ],
        )?;
        if string(&document, field(root, "format")?)? != "gantry.execution-start/v1" {
            return Err(DurableEvidenceError::Encoding);
        }
        decode_machine_program(&decode_hex(string(&document, field(root, "program")?)?)?)
            .map_err(DurableEvidenceError::Checkpoint)
    }

    /// Wraps sequence one for an atomic fenced journal commit.
    pub fn unfinalized(
        &self,
        batch_local_id: BatchLocalEvidenceId,
    ) -> Result<UnfinalizedEvidenceV1, DurableEvidenceError> {
        UnfinalizedEvidenceV1::new(
            batch_local_id,
            "gantry.execution-start/v1",
            self.canonical_body(),
            Arc::<[JournalEvidenceReferenceV1]>::from([]),
            Arc::from([]),
        )
        .map_err(|error: JournalContractError| DurableEvidenceError::Journal(error))
    }
}

/// Canonical first-effective cancellation evidence committed before task signalling.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableCancellationEvidenceV1 {
    reason: CancellationReason,
    state: DurableLogicalEvidenceV1,
}

impl DurableCancellationEvidenceV1 {
    /// Constructs cancellation evidence over the complete state at the cancellation cut.
    pub fn new(
        reason: CancellationReason,
        state: DurableLogicalEvidenceV1,
    ) -> Result<Self, DurableEvidenceError> {
        let causal_identity_valid = reason
            .causal_identity
            .is_none_or(|identity| match identity {
                CancellationCausalIdentity::Operation(identity) => {
                    identity.kind() == IdentityKind::Operation
                }
                CancellationCausalIdentity::Task(identity) => identity.kind() == IdentityKind::Task,
            });
        if state.cut() != DurableCommitCutV1::Cancellation || !causal_identity_valid {
            return Err(DurableEvidenceError::Encoding);
        }
        Ok(Self { reason, state })
    }

    /// Returns the first effective cancellation reason.
    #[must_use]
    pub const fn reason(&self) -> &CancellationReason {
        &self.reason
    }

    /// Returns the complete logical state committed with cancellation.
    #[must_use]
    pub const fn state(&self) -> &DurableLogicalEvidenceV1 {
        &self.state
    }

    /// Encodes the unique canonical cancellation evidence body.
    #[must_use]
    pub fn canonical_body(&self) -> Vec<u8> {
        let mut output = String::from("{\"causal_identity\":");
        match self.reason.causal_identity {
            Some(CancellationCausalIdentity::Operation(identity)) => {
                output.push_str("{\"identity\":");
                push_json_string(&mut output, &identity.to_string());
                output.push_str(",\"kind\":\"operation\"}");
            }
            Some(CancellationCausalIdentity::Task(identity)) => {
                output.push_str("{\"identity\":");
                push_json_string(&mut output, &identity.to_string());
                output.push_str(",\"kind\":\"task\"}");
            }
            None => output.push_str("null"),
        }
        output.push_str(",\"category\":");
        push_json_string(&mut output, self.reason.category.wire_name());
        output.push_str(",\"format\":\"gantry.cancellation/v1\",\"message\":");
        super::push_optional_string(&mut output, self.reason.message.as_deref());
        output.push_str(",\"state\":");
        push_json_string(&mut output, &encode_hex(&self.state.canonical_body()));
        output.push('}');
        output.into_bytes()
    }

    /// Decodes one exact canonical cancellation body against its immutable program.
    pub fn decode(program: &MachineProgram, body: &[u8]) -> Result<Self, DurableEvidenceError> {
        let document = decode_snapshot_document(body)?;
        let root = object(&document, document.root())?;
        require_exact_fields(
            root,
            &["causal_identity", "category", "format", "message", "state"],
        )?;
        if string(&document, field(root, "format")?)? != "gantry.cancellation/v1" {
            return Err(DurableEvidenceError::Encoding);
        }
        let category = CancellationReasonCategory::from_wire_name(string(
            &document,
            field(root, "category")?,
        )?)
        .ok_or(DurableEvidenceError::Encoding)?;
        let causal_identity = match document.node(field(root, "causal_identity")?) {
            Some(gantry_core::strict_json::JsonNode::Null) => None,
            Some(gantry_core::strict_json::JsonNode::Object(value)) => {
                require_exact_fields(value, &["identity", "kind"])?;
                let kind = string(&document, field(value, "kind")?)?;
                let (identity_kind, wrap): (
                    IdentityKind,
                    fn(ProtocolIdentity) -> CancellationCausalIdentity,
                ) = match kind {
                    "operation" => (
                        IdentityKind::Operation,
                        CancellationCausalIdentity::Operation,
                    ),
                    "task" => (IdentityKind::Task, CancellationCausalIdentity::Task),
                    _ => return Err(DurableEvidenceError::Encoding),
                };
                let identity = ProtocolIdentity::parse_kind(
                    string(&document, field(value, "identity")?)?,
                    identity_kind,
                )
                .map_err(|_| DurableEvidenceError::Encoding)?;
                Some(wrap(identity))
            }
            _ => return Err(DurableEvidenceError::Encoding),
        };
        let reason = CancellationReason::new(
            category,
            optional_arc_string(&document, field(root, "message")?)?,
            causal_identity,
            u64::MAX,
        )
        .map_err(|_| DurableEvidenceError::Encoding)?;
        let state = DurableLogicalEvidenceV1::decode(
            program,
            &decode_hex(string(&document, field(root, "state")?)?)?,
        )?;
        let decoded = Self::new(reason, state)?;
        if decoded.canonical_body() != body {
            return Err(DurableEvidenceError::Encoding);
        }
        Ok(decoded)
    }

    /// Wraps cancellation for one causally linked atomic journal commit.
    pub fn unfinalized(
        &self,
        batch_local_id: BatchLocalEvidenceId,
        references: impl Into<Arc<[JournalEvidenceReferenceV1]>>,
    ) -> Result<UnfinalizedEvidenceV1, DurableEvidenceError> {
        UnfinalizedEvidenceV1::new(
            batch_local_id,
            "gantry.cancellation/v1",
            self.canonical_body(),
            references,
            Arc::from([]),
        )
        .map_err(DurableEvidenceError::Journal)
    }
}

/// Complete compatible mutable-policy and mapping revision active for one execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableExecutionStateV1 {
    execution_id: ProtocolIdentity,
    mutable_policy: Arc<[u8]>,
    agent_mapping_revision: Option<Arc<str>>,
    action_mapping_revision: Option<Arc<str>>,
}

impl DurableExecutionStateV1 {
    /// Constructs one complete execution-state revision before resumed work continues.
    pub fn new(
        execution_id: ProtocolIdentity,
        mutable_policy: impl Into<Arc<[u8]>>,
        agent_mapping_revision: Option<Arc<str>>,
        action_mapping_revision: Option<Arc<str>>,
    ) -> Result<Self, DurableEvidenceError> {
        let mutable_policy = mutable_policy.into();
        if execution_id.kind() != IdentityKind::Execution
            || !is_canonical_json(&mutable_policy)
            || agent_mapping_revision
                .as_ref()
                .is_some_and(|value| value.is_empty())
            || action_mapping_revision
                .as_ref()
                .is_some_and(|value| value.is_empty())
        {
            return Err(DurableEvidenceError::InvalidExecutionState);
        }
        Ok(Self {
            execution_id,
            mutable_policy,
            agent_mapping_revision,
            action_mapping_revision,
        })
    }

    /// Returns the accepted execution whose active state is revised.
    #[must_use]
    pub const fn execution_id(&self) -> ProtocolIdentity {
        self.execution_id
    }

    /// Returns the complete canonical mutable policy active after this revision.
    #[must_use]
    pub fn mutable_policy(&self) -> &[u8] {
        &self.mutable_policy
    }

    /// Returns the active logical-agent mapping revision, when applicable.
    #[must_use]
    pub fn agent_mapping_revision(&self) -> Option<&str> {
        self.agent_mapping_revision.as_deref()
    }

    /// Returns the active action mapping revision, when applicable.
    #[must_use]
    pub fn action_mapping_revision(&self) -> Option<&str> {
        self.action_mapping_revision.as_deref()
    }

    /// Encodes the unique canonical execution-state evidence body.
    #[must_use]
    pub fn canonical_body(&self) -> Vec<u8> {
        let mut output = String::from("{\"action_mapping_revision\":");
        super::push_optional_string(&mut output, self.action_mapping_revision());
        output.push_str(",\"agent_mapping_revision\":");
        super::push_optional_string(&mut output, self.agent_mapping_revision());
        output.push_str(",\"execution_id\":");
        push_json_string(&mut output, &self.execution_id.to_string());
        output.push_str(",\"format\":\"gantry.execution-state/v1\",\"mutable_policy\":");
        output.push_str(
            std::str::from_utf8(&self.mutable_policy)
                .unwrap_or_else(|_| unreachable!("canonical JSON is UTF-8")),
        );
        output.push('}');
        output.into_bytes()
    }

    /// Decodes one exact canonical execution-state revision.
    pub fn decode(body: &[u8]) -> Result<Self, DurableEvidenceError> {
        let document = decode_snapshot_document(body)?;
        let root = object(&document, document.root())?;
        require_exact_fields(
            root,
            &[
                "action_mapping_revision",
                "agent_mapping_revision",
                "execution_id",
                "format",
                "mutable_policy",
            ],
        )?;
        if string(&document, field(root, "format")?)? != "gantry.execution-state/v1" {
            return Err(DurableEvidenceError::Encoding);
        }
        let execution_id = ProtocolIdentity::parse_kind(
            string(&document, field(root, "execution_id")?)?,
            IdentityKind::Execution,
        )
        .map_err(|_| DurableEvidenceError::Encoding)?;
        let mutable_policy = canonical_node(&document, field(root, "mutable_policy")?)?;
        let decoded = Self::new(
            execution_id,
            Arc::<[u8]>::from(mutable_policy),
            optional_arc_string(&document, field(root, "agent_mapping_revision")?)?,
            optional_arc_string(&document, field(root, "action_mapping_revision")?)?,
        )?;
        if decoded.canonical_body() != body {
            return Err(DurableEvidenceError::Encoding);
        }
        Ok(decoded)
    }

    /// Wraps this revision for one causally linked atomic journal commit.
    pub fn unfinalized(
        &self,
        batch_local_id: BatchLocalEvidenceId,
        references: impl Into<Arc<[JournalEvidenceReferenceV1]>>,
    ) -> Result<UnfinalizedEvidenceV1, DurableEvidenceError> {
        UnfinalizedEvidenceV1::new(
            batch_local_id,
            "gantry.execution-state/v1",
            self.canonical_body(),
            references,
            Arc::from([]),
        )
        .map_err(DurableEvidenceError::Journal)
    }
}

/// Versioned compacted recovery state retaining sequence-one identity and the latest checkpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableRecoverySnapshotV1 {
    execution_start: DurableExecutionStartV1,
    execution_state: Option<DurableExecutionStateV1>,
    state: DurableLogicalEvidenceV1,
}

impl DurableRecoverySnapshotV1 {
    /// Constructs a compacted recovery snapshot over one execution's immutable start and state.
    pub fn new(
        execution_start: DurableExecutionStartV1,
        state: DurableLogicalEvidenceV1,
    ) -> Result<Self, DurableEvidenceError> {
        Self::new_with_execution_state(execution_start, None, state)
    }

    /// Constructs a compacted snapshot retaining the latest compatible execution state.
    pub fn new_with_execution_state(
        execution_start: DurableExecutionStartV1,
        execution_state: Option<DurableExecutionStateV1>,
        state: DurableLogicalEvidenceV1,
    ) -> Result<Self, DurableEvidenceError> {
        if state.execution_id() != execution_start.execution_id()
            || state.task_id() != execution_start.task_id()
            || execution_state
                .as_ref()
                .is_some_and(|revision| revision.execution_id() != execution_start.execution_id())
        {
            return Err(DurableEvidenceError::MixedExecution);
        }
        Ok(Self {
            execution_start,
            execution_state,
            state,
        })
    }

    /// Returns the retained immutable execution-start record.
    #[must_use]
    pub const fn execution_start(&self) -> &DurableExecutionStartV1 {
        &self.execution_start
    }

    /// Returns the latest compatible execution-state revision retained by compaction.
    #[must_use]
    pub const fn execution_state(&self) -> Option<&DurableExecutionStateV1> {
        self.execution_state.as_ref()
    }

    /// Returns the latest logical state represented by the snapshot frontier.
    #[must_use]
    pub const fn state(&self) -> &DurableLogicalEvidenceV1 {
        &self.state
    }

    /// Encodes the unique compacted recovery snapshot body.
    #[must_use]
    pub fn canonical_body(&self) -> Vec<u8> {
        let mut output = String::from("{\"execution_start\":");
        push_json_string(
            &mut output,
            &encode_hex(&self.execution_start.canonical_body()),
        );
        output.push_str(",\"execution_state\":");
        match &self.execution_state {
            Some(state) => push_json_string(&mut output, &encode_hex(&state.canonical_body())),
            None => output.push_str("null"),
        }
        output.push_str(",\"format\":\"gantry.recovery-snapshot/v1\",\"state\":");
        push_json_string(&mut output, &encode_hex(&self.state.canonical_body()));
        output.push('}');
        output.into_bytes()
    }

    /// Decodes one exact compacted recovery snapshot against its retained executable program.
    pub fn decode(program: &MachineProgram, body: &[u8]) -> Result<Self, DurableEvidenceError> {
        let document = decode_snapshot_document(body)?;
        let root = object(&document, document.root())?;
        require_exact_fields(
            root,
            &["execution_start", "execution_state", "format", "state"],
        )?;
        if string(&document, field(root, "format")?)? != "gantry.recovery-snapshot/v1" {
            return Err(DurableEvidenceError::Encoding);
        }
        let execution_start = DurableExecutionStartV1::decode(
            program,
            &decode_hex(string(&document, field(root, "execution_start")?)?)?,
        )?;
        let execution_state = match document.node(field(root, "execution_state")?) {
            Some(gantry_core::strict_json::JsonNode::Null) => None,
            Some(gantry_core::strict_json::JsonNode::String(value)) => {
                Some(DurableExecutionStateV1::decode(&decode_hex(value)?)?)
            }
            _ => return Err(DurableEvidenceError::Encoding),
        };
        let state = DurableLogicalEvidenceV1::decode(
            program,
            &decode_hex(string(&document, field(root, "state")?)?)?,
        )?;
        let decoded = Self::new_with_execution_state(execution_start, execution_state, state)?;
        if decoded.canonical_body() != body {
            return Err(DurableEvidenceError::Encoding);
        }
        Ok(decoded)
    }

    /// Extracts the retained executable program before decoding the latest logical state.
    pub fn retained_program(body: &[u8]) -> Result<MachineProgram, DurableEvidenceError> {
        let document = decode_snapshot_document(body)?;
        let root = object(&document, document.root())?;
        require_exact_fields(
            root,
            &["execution_start", "execution_state", "format", "state"],
        )?;
        if string(&document, field(root, "format")?)? != "gantry.recovery-snapshot/v1" {
            return Err(DurableEvidenceError::Encoding);
        }
        DurableExecutionStartV1::retained_program(&decode_hex(string(
            &document,
            field(root, "execution_start")?,
        )?)?)
    }
}

fn decode_snapshot_document(body: &[u8]) -> Result<StrictJsonDocument, DurableEvidenceError> {
    let maximum_bytes = u64::try_from(body.len()).map_err(|_| DurableEvidenceError::Encoding)?;
    StrictJsonDocument::decode(
        body,
        JsonLimits {
            maximum_bytes,
            maximum_nesting_depth: maximum_bytes.max(1),
            maximum_nodes: maximum_bytes.max(1),
            maximum_string_scalars: maximum_bytes.max(1),
            maximum_list_items: maximum_bytes.max(1),
        },
    )
    .map_err(|_| DurableEvidenceError::Encoding)
}

fn optional_arc_string(
    document: &StrictJsonDocument,
    id: gantry_core::strict_json::JsonNodeId,
) -> Result<Option<Arc<str>>, DurableEvidenceError> {
    match document.node(id) {
        Some(gantry_core::strict_json::JsonNode::Null) => Ok(None),
        Some(gantry_core::strict_json::JsonNode::String(value)) => Ok(Some(Arc::clone(value))),
        _ => Err(DurableEvidenceError::Encoding),
    }
}

enum CanonicalNodeTask {
    Node(gantry_core::strict_json::JsonNodeId),
    Byte(char),
    String(Arc<str>),
}

fn canonical_node(
    document: &StrictJsonDocument,
    id: gantry_core::strict_json::JsonNodeId,
) -> Result<Vec<u8>, DurableEvidenceError> {
    use gantry_core::strict_json::JsonNode;

    let mut output = String::new();
    let mut work = vec![CanonicalNodeTask::Node(id)];
    while let Some(task) = work.pop() {
        match task {
            CanonicalNodeTask::Byte(value) => output.push(value),
            CanonicalNodeTask::String(value) => push_json_string(&mut output, &value),
            CanonicalNodeTask::Node(id) => match document.node(id) {
                Some(JsonNode::Null) => output.push_str("null"),
                Some(JsonNode::Bool(true)) => output.push_str("true"),
                Some(JsonNode::Bool(false)) => output.push_str("false"),
                Some(JsonNode::Number(value)) => output.push_str(value.lexeme()),
                Some(JsonNode::String(value)) => push_json_string(&mut output, value),
                Some(JsonNode::Array(items)) => {
                    output.push('[');
                    let mut sequence = Vec::with_capacity(items.len().saturating_mul(2));
                    for (index, item) in items.iter().copied().enumerate() {
                        if index > 0 {
                            sequence.push(CanonicalNodeTask::Byte(','));
                        }
                        sequence.push(CanonicalNodeTask::Node(item));
                    }
                    sequence.push(CanonicalNodeTask::Byte(']'));
                    work.extend(sequence.into_iter().rev());
                }
                Some(JsonNode::Object(members)) => {
                    output.push('{');
                    let mut sequence = Vec::with_capacity(members.len().saturating_mul(4));
                    for (index, (name, value)) in members.iter().enumerate() {
                        if index > 0 {
                            sequence.push(CanonicalNodeTask::Byte(','));
                        }
                        sequence.push(CanonicalNodeTask::String(Arc::clone(name)));
                        sequence.push(CanonicalNodeTask::Byte(':'));
                        sequence.push(CanonicalNodeTask::Node(*value));
                    }
                    sequence.push(CanonicalNodeTask::Byte('}'));
                    work.extend(sequence.into_iter().rev());
                }
                None => return Err(DurableEvidenceError::Encoding),
            },
        }
    }
    Ok(output.into_bytes())
}
