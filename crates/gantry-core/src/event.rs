//! Portable event-envelope and protected-reference contracts.

use std::fmt;
use std::sync::Arc;

use crate::identity::ProtocolIdentity;
use crate::portable::{EventKind, EventLayer, IdentityKind, ProtectedReferenceClass};
use crate::source::SourceSpan;
use crate::timestamp::UtcTimestamp;

/// Exact version of the Gantry event protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EventVersion {
    /// Event protocol major version.
    pub major: u64,
    /// Event protocol minor version.
    pub minor: u64,
}

impl EventVersion {
    /// Published Gantry v1 event protocol version.
    pub const V1: Self = Self { major: 1, minor: 0 };
}

/// One stable reference to protected bytes omitted from an event envelope.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ProtectedReference {
    key: Arc<str>,
    class: ProtectedReferenceClass,
}

impl ProtectedReference {
    /// Constructs a nonempty protected reference key and permission class.
    pub fn new(
        key: impl Into<Arc<str>>,
        class: ProtectedReferenceClass,
    ) -> Result<Self, EventContractError> {
        let key = key.into();
        if key.is_empty() {
            return Err(EventContractError::EmptyProtectedReference);
        }
        Ok(Self { key, class })
    }

    /// Returns the stable reference key.
    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }

    /// Returns the protected payload class.
    #[must_use]
    pub const fn class(&self) -> ProtectedReferenceClass {
        self.class
    }
}

/// Immutable, already validated kind-specific event payload bytes.
///
/// Canonical event schemas, rather than this Rust wrapper, define the payload
/// meaning. Semantic owners construct these bytes only after validating the
/// applicable event-kind schema.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventPayload(Arc<[u8]>);

impl EventPayload {
    /// Wraps nonempty validated canonical payload bytes.
    pub fn from_validated_canonical_bytes(
        bytes: impl Into<Arc<[u8]>>,
    ) -> Result<Self, EventContractError> {
        let bytes = bytes.into();
        if bytes.is_empty() {
            return Err(EventContractError::EmptyPayload);
        }
        Ok(Self(bytes))
    }

    /// Returns the exact immutable payload bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Typed event data supplied by a semantic owner before occurrence metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventDraft {
    kind: EventKind,
    execution_id: Option<ProtocolIdentity>,
    source: Option<SourceSpan>,
    task_id: Option<ProtocolIdentity>,
    operation_id: Option<ProtocolIdentity>,
    causal_ids: Arc<[ProtocolIdentity]>,
    per_task_sequence: Option<u64>,
    payload: EventPayload,
    protected_references: Arc<[ProtectedReference]>,
}

impl EventDraft {
    /// Constructs a draft with no optional causal context.
    #[must_use]
    pub fn new(kind: EventKind, payload: EventPayload) -> Self {
        Self {
            kind,
            execution_id: None,
            source: None,
            task_id: None,
            operation_id: None,
            causal_ids: Arc::from([]),
            per_task_sequence: None,
            payload,
            protected_references: Arc::from([]),
        }
    }

    /// Sets an execution identity of the exact required kind.
    pub fn with_execution_id(
        mut self,
        identity: ProtocolIdentity,
    ) -> Result<Self, EventContractError> {
        require_kind(identity, IdentityKind::Execution)?;
        self.execution_id = Some(identity);
        Ok(self)
    }

    /// Sets the source span that caused the event.
    #[must_use]
    pub fn with_source(mut self, source: SourceSpan) -> Self {
        self.source = Some(source);
        self
    }

    /// Sets a task identity and its per-task event sequence.
    pub fn with_task(
        mut self,
        identity: ProtocolIdentity,
        sequence: u64,
    ) -> Result<Self, EventContractError> {
        require_kind(identity, IdentityKind::Task)?;
        self.task_id = Some(identity);
        self.per_task_sequence = Some(sequence);
        Ok(self)
    }

    /// Sets an operation identity of the exact required kind.
    pub fn with_operation_id(
        mut self,
        identity: ProtocolIdentity,
    ) -> Result<Self, EventContractError> {
        require_kind(identity, IdentityKind::Operation)?;
        self.operation_id = Some(identity);
        Ok(self)
    }

    /// Sets causal identities in their canonical semantic order.
    #[must_use]
    pub fn with_causal_ids(mut self, identities: impl Into<Arc<[ProtocolIdentity]>>) -> Self {
        self.causal_ids = identities.into();
        self
    }

    /// Sets the stable protected references carried by the envelope.
    pub fn with_protected_references(
        mut self,
        references: impl Into<Arc<[ProtectedReference]>>,
    ) -> Result<Self, EventContractError> {
        let references = references.into();
        let mut keys = references
            .iter()
            .map(ProtectedReference::key)
            .collect::<Vec<_>>();
        keys.sort_unstable();
        if keys.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(EventContractError::DuplicateProtectedReference);
        }
        self.protected_references = references;
        Ok(self)
    }

    /// Returns the exact event kind.
    #[must_use]
    pub const fn kind(&self) -> EventKind {
        self.kind
    }
}

/// One completed immutable standard event occurrence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventEnvelope {
    version: EventVersion,
    event_id: ProtocolIdentity,
    activity_id: ProtocolIdentity,
    timestamp: UtcTimestamp,
    draft: EventDraft,
}

impl EventEnvelope {
    /// Completes a typed draft with occurrence metadata.
    pub fn complete(
        event_id: ProtocolIdentity,
        activity_id: ProtocolIdentity,
        timestamp: UtcTimestamp,
        draft: EventDraft,
    ) -> Result<Self, EventContractError> {
        require_kind(event_id, IdentityKind::Event)?;
        require_kind(activity_id, IdentityKind::Activity)?;
        Ok(Self {
            version: EventVersion::V1,
            event_id,
            activity_id,
            timestamp,
            draft,
        })
    }

    /// Returns the exact event protocol version.
    #[must_use]
    pub const fn version(&self) -> EventVersion {
        self.version
    }

    /// Returns the globally scoped event identity.
    #[must_use]
    pub const fn event_id(&self) -> ProtocolIdentity {
        self.event_id
    }

    /// Returns the caller-owned activity identity.
    #[must_use]
    pub const fn activity_id(&self) -> ProtocolIdentity {
        self.activity_id
    }

    /// Returns the event kind.
    #[must_use]
    pub const fn kind(&self) -> EventKind {
        self.draft.kind
    }

    /// Returns the kind's required observation layer.
    #[must_use]
    pub const fn layer(&self) -> EventLayer {
        self.draft.kind.layer()
    }

    /// Returns the immutable creation timestamp.
    #[must_use]
    pub fn timestamp(&self) -> &UtcTimestamp {
        &self.timestamp
    }

    /// Returns the optional execution identity.
    #[must_use]
    pub const fn execution_id(&self) -> Option<ProtocolIdentity> {
        self.draft.execution_id
    }

    /// Returns the optional source span.
    #[must_use]
    pub fn source(&self) -> Option<&SourceSpan> {
        self.draft.source.as_ref()
    }

    /// Returns the optional task identity.
    #[must_use]
    pub const fn task_id(&self) -> Option<ProtocolIdentity> {
        self.draft.task_id
    }

    /// Returns the optional operation identity.
    #[must_use]
    pub const fn operation_id(&self) -> Option<ProtocolIdentity> {
        self.draft.operation_id
    }

    /// Returns causal identities in canonical semantic order.
    #[must_use]
    pub fn causal_ids(&self) -> &[ProtocolIdentity] {
        &self.draft.causal_ids
    }

    /// Returns the task-local sequence when the event is task-backed.
    #[must_use]
    pub const fn per_task_sequence(&self) -> Option<u64> {
        self.draft.per_task_sequence
    }

    /// Returns the kind-specific canonical payload bytes.
    #[must_use]
    pub fn payload(&self) -> &EventPayload {
        &self.draft.payload
    }

    /// Returns protected references without sink-specific projection state.
    #[must_use]
    pub fn protected_references(&self) -> &[ProtectedReference] {
        &self.draft.protected_references
    }
}

/// Rejection while constructing portable event data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventContractError {
    /// A typed identity field received another identity kind.
    IdentityKind,
    /// A protected reference key was empty.
    EmptyProtectedReference,
    /// Two protected references used the same key.
    DuplicateProtectedReference,
    /// A kind-specific payload contained no canonical bytes.
    EmptyPayload,
}

impl fmt::Display for EventContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::IdentityKind => "event identity kind does not match its typed field",
            Self::EmptyProtectedReference => "protected event reference is empty",
            Self::DuplicateProtectedReference => "protected event reference key is duplicated",
            Self::EmptyPayload => "event payload is empty",
        })
    }
}

impl std::error::Error for EventContractError {}

fn require_kind(
    identity: ProtocolIdentity,
    expected: IdentityKind,
) -> Result<(), EventContractError> {
    if identity.kind() == expected {
        Ok(())
    } else {
        Err(EventContractError::IdentityKind)
    }
}
