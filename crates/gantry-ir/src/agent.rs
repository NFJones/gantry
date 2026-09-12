//! Pure agent fulfillment, assistant turn, tool, and session model.
//!
//! This module is the machine-checked model for
//! `GNT-25.0-agent-fulfillment-assistant-turns-tools-and-sessions`. It states the
//! package-scoped agent requirement and machine-checkable fulfillment descriptor of
//! `GNT-25.1-agent-requirements-and-fulfillment`, the complete-or-named refusal of
//! `GNT-25.2-fulfillment-preflight`, the exactly-one-of-two canonical assistant turn
//! of `GNT-25.3-assistant-turns`, the bounded repair and non-dispatching rejected
//! prefix of `GNT-25.4-turn-validation-and-repair`, the stable round identity and
//! ordered durable cuts of `GNT-25.5-round-identity-and-durable-cuts`, the
//! package-qualified slots and immutable tool-set revisions of
//! `GNT-25.6-tool-slots-and-tool-set-revisions`, the ordinary callable semantics and
//! ordered settlement of `GNT-25.7-source-handlers`, the parent reservation and
//! stable child sessions of `GNT-25.8-sessions-and-child-sessions`, the typed,
//! bounded, restart-safe semantic stream of `GNT-25.9-streaming-and-progress`, and the
//! explicit non-claims of `GNT-25.10-agent-non-claims`.
//!
//! Scope is deliberately narrow. Every rule here is a pure function of its own
//! arguments: this module reads no provider, clock, host path, environment variable,
//! locale, socket, network address, process identifier, thread identity, or adapter
//! handle, and it exposes no constructor that accepts one. A provider name map is
//! declared data and a provider display name is never authority: no method here
//! resolves a slot from a display spelling the map does not name. Every identity is
//! derived from declared fields under its own domain separator, so equal declared
//! inputs produce equal identities and every verdict here is reproducible from its
//! own inputs.
//!
//! Landed contracts are cited and reused rather than redeclared: a tool descriptor
//! carries the landed [`EffectSet`] of `GNT-3-T-EFFECTS` and `GNT-3-T-EFFECT-ROWS`,
//! the landed [`AuthorityRequirementId`] of the `GNT-3-T-AUTHORITY-*` capability
//! contracts, the landed [`RecoveryClass`] of the generated contract vocabulary, and
//! the landed [`RetryEligibility`] of
//! `GNT-20.6-ambiguous-effect-classification-and-retry-eligibility`. Approval, wait,
//! protection, and durability remain those of Sections 19, 21, and 24 and of
//! `GNT-11.*` and `GNT-15.*`; this model grants no approval and settles no wait.
//!
//! Four separations stay explicit.
//!
//! * One raw response receives exactly one [`TurnOutcome`]: an accepted canonical
//!   [`Turn`], a model refusal, a malformed response, or one typed
//!   [`TurnValidationCause`]. A refusal and a malformed response are distinct
//!   outcomes, and no tool request is dispatched before the whole turn is accepted;
//!   the raw cut commits a domain-separated witness, so recovery refuses a raw
//!   response other than the committed one.
//! * A [`RejectedPrefix`] is affine and its only non-refusing consumer is one repair
//!   attempt; [`RejectedPrefix::admit_dispatch`] always refuses, so a rejected prefix
//!   never reaches a child. [`HandlerUse`] is affine too, so a single-use handler is
//!   consumed once and never invoked twice through a copy.
//! * [`DurableAgentCut::advance`] moves one step at a time: a skip and a regression
//!   are each refused, and a committed cut is never replayed, so a resumed round
//!   neither repeats an accepted turn nor repeats a settled tool position. A
//!   settlement commits only when its positions are exactly the committed accepted
//!   turn's request positions.
//! * [`ToolSetRevision`] is immutable once built and
//!   [`ToolSetRevision::add_descriptor`] always refuses, so no round can call a
//!   descriptor that a mid-loop mutation added.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

use crate::authority::{AuthorityRequirementId, digest_fields};
use crate::effects::EffectSet;
use crate::generated::RecoveryClass;
use crate::manifest::encode_hex;
use crate::operation::RetryEligibility;

/// The clause keys this model implements, in clause order.
///
/// Every diagnostic of this module names exactly one of these keys through
/// [`AgentDiagnosticCode::requirement`], so every refusal is attributable to the
/// clause that owns it.
pub const AGENT_CLAUSES: [&str; 11] = [
    "GNT-25.0-agent-fulfillment-assistant-turns-tools-and-sessions",
    "GNT-25.1-agent-requirements-and-fulfillment",
    "GNT-25.2-fulfillment-preflight",
    "GNT-25.3-assistant-turns",
    "GNT-25.4-turn-validation-and-repair",
    "GNT-25.5-round-identity-and-durable-cuts",
    "GNT-25.6-tool-slots-and-tool-set-revisions",
    "GNT-25.7-source-handlers",
    "GNT-25.8-sessions-and-child-sessions",
    "GNT-25.9-streaming-and-progress",
    "GNT-25.10-agent-non-claims",
];

/// Domain separator for agent-requirement identity derivation.
const AGENT_REQUIREMENT_DOMAIN: &str = "gantry.agent-requirement/v1";

/// Domain separator for tool-slot identity derivation.
const TOOL_SLOT_DOMAIN: &str = "gantry.tool-slot/v1";

/// Domain separator for tool-set revision identity derivation.
const TOOL_SET_REVISION_DOMAIN: &str = "gantry.tool-set-revision/v1";

/// Domain separator for tool-invocation identity derivation.
const TOOL_INVOCATION_DOMAIN: &str = "gantry.tool-invocation/v1";

/// Domain separator for round identity derivation.
const ROUND_DOMAIN: &str = "gantry.agent-round/v1";

/// Domain separator for child-session identity derivation.
const CHILD_SESSION_DOMAIN: &str = "gantry.child-session/v1";

/// Domain separator for the committed raw-response witness.
const RAW_RESPONSE_WITNESS_DOMAIN: &str = "gantry.agent-raw-response/v1";

/// One declared text input of this model.
///
/// The vocabulary is closed and each member owns its own requirement anchor, so a
/// refusal that names a declared input names exactly one of these and never an
/// unspecified field. The members are listed in canonical wire-name order.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AgentDeclaredInput {
    /// One final result payload.
    FinalResult,
    /// One declaring package name.
    Package,
    /// One declared provider name.
    ProviderName,
    /// One agent requirement name.
    Requirement,
    /// One declared result code of one settled tool result.
    ResultCode,
    /// One canonical schema digest.
    SchemaDigest,
    /// One parent or child session name.
    Session,
    /// One package-qualified tool slot name.
    Slot,
    /// One stream identity.
    Stream,
}

impl AgentDeclaredInput {
    /// Every member of the closed vocabulary, in canonical wire-name order.
    pub const ALL: [Self; 9] = [
        Self::FinalResult,
        Self::Package,
        Self::ProviderName,
        Self::Requirement,
        Self::ResultCode,
        Self::SchemaDigest,
        Self::Session,
        Self::Slot,
        Self::Stream,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::FinalResult => "final-result",
            Self::Package => "package",
            Self::ProviderName => "provider-name",
            Self::Requirement => "requirement",
            Self::ResultCode => "result-code",
            Self::SchemaDigest => "schema-digest",
            Self::Session => "session",
            Self::Slot => "slot",
            Self::Stream => "stream",
        }
    }

    /// Returns the same exact portable spelling as [`Self::wire_name`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.wire_name()
    }

    /// Strictly decodes one exact portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.wire_name() == value)
    }

    /// Returns the clause anchor that owns an empty declared input of this kind.
    #[must_use]
    pub const fn requirement(self) -> &'static str {
        match self {
            Self::Package | Self::Requirement | Self::Slot | Self::SchemaDigest => {
                "GNT-25.1-agent-requirements-and-fulfillment"
            }
            Self::ProviderName => "GNT-25.2-fulfillment-preflight",
            Self::FinalResult => "GNT-25.3-assistant-turns",
            Self::ResultCode => "GNT-25.7-source-handlers",
            Self::Session => "GNT-25.8-sessions-and-child-sessions",
            Self::Stream => "GNT-25.9-streaming-and-progress",
        }
    }
}

/// One property of the closed fulfillment-property vocabulary
/// (`GNT-25.1-agent-requirements-and-fulfillment`).
///
/// The vocabulary is exactly ten properties: modalities, structured output and
/// repair, sessions, transcripts, context, streaming, retrieval, tools, limits, and
/// data handling. Each has one frozen spelling and one frozen meaning, and no clause
/// of Section 25 introduces an eleventh property or a property inferred from provider
/// behaviour. The members are declared in canonical wire-name order, so the derived
/// order of [`Self::ALL`] is the wire-name order.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum FulfillmentProperty {
    /// The declared modality set of the agent.
    Context,
    /// The declared data handling contract.
    DataHandling,
    /// The declared explicit limit set.
    Limits,
    /// The declared input and output modalities.
    Modalities,
    /// The declared retrieval contract.
    Retrieval,
    /// The declared session contract.
    Sessions,
    /// The declared streaming contract.
    Streaming,
    /// The declared structured output schema and its repair rule.
    StructuredOutput,
    /// The declared tool-set contract.
    Tools,
    /// The declared transcript contract.
    Transcripts,
}

impl FulfillmentProperty {
    /// Every member of the closed vocabulary, in canonical wire-name order.
    pub const ALL: [Self; 10] = [
        Self::Context,
        Self::DataHandling,
        Self::Limits,
        Self::Modalities,
        Self::Retrieval,
        Self::Sessions,
        Self::Streaming,
        Self::StructuredOutput,
        Self::Tools,
        Self::Transcripts,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Context => "context",
            Self::DataHandling => "data-handling",
            Self::Limits => "limits",
            Self::Modalities => "modalities",
            Self::Retrieval => "retrieval",
            Self::Sessions => "sessions",
            Self::Streaming => "streaming",
            Self::StructuredOutput => "structured-output",
            Self::Tools => "tools",
            Self::Transcripts => "transcripts",
        }
    }

    /// Returns the same exact portable spelling as [`Self::wire_name`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.wire_name()
    }

    /// Strictly decodes one exact portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.wire_name() == value)
    }

    /// Returns the clause anchor that owns this property.
    #[must_use]
    pub const fn requirement(self) -> &'static str {
        "GNT-25.1-agent-requirements-and-fulfillment"
    }
}

/// One per-property fulfillment state of preflight
/// (`GNT-25.2-fulfillment-preflight`).
///
/// The state vocabulary is closed: bound, unsupported, and missing. Missing is the
/// state of a property the binding revision declares no fact for at all; it is never
/// merged into bound, because preflight never defaults a missing fact to supported.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum FulfillmentState {
    /// The binding revision declares the property bound.
    Bound,
    /// The binding revision declares no fact at all for the property.
    Missing,
    /// The binding revision declares the property unsupported.
    Unsupported,
}

impl FulfillmentState {
    /// Every member of the closed vocabulary, in canonical wire-name order.
    pub const ALL: [Self; 3] = [Self::Bound, Self::Missing, Self::Unsupported];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Bound => "bound",
            Self::Missing => "missing",
            Self::Unsupported => "unsupported",
        }
    }

    /// Returns the same exact portable spelling as [`Self::wire_name`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.wire_name()
    }

    /// Strictly decodes one exact portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.wire_name() == value)
    }

    /// Returns the clause anchor that owns this state.
    #[must_use]
    pub const fn requirement(self) -> &'static str {
        "GNT-25.2-fulfillment-preflight"
    }
}

/// One closed preflight verdict (`GNT-25.2-fulfillment-preflight`).
///
/// Complete admits the loop; unsupported and incomplete each refuse it while naming
/// the exact property that refused it. There is no generic refusal verdict.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum PreflightVerdict {
    /// Every declared property is bound.
    Complete,
    /// At least one declared property has no declared binding fact.
    Incomplete,
    /// At least one declared property is declared unsupported.
    Unsupported,
}

impl PreflightVerdict {
    /// Every member of the closed vocabulary, in canonical wire-name order.
    pub const ALL: [Self; 3] = [Self::Complete, Self::Incomplete, Self::Unsupported];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Incomplete => "incomplete",
            Self::Unsupported => "unsupported",
        }
    }

    /// Returns the same exact portable spelling as [`Self::wire_name`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.wire_name()
    }

    /// Strictly decodes one exact portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.wire_name() == value)
    }

    /// Returns whether this verdict admits the loop.
    #[must_use]
    pub const fn admits_loop(self) -> bool {
        matches!(self, Self::Complete)
    }

    /// Returns the clause anchor that owns this verdict.
    #[must_use]
    pub const fn requirement(self) -> &'static str {
        "GNT-25.2-fulfillment-preflight"
    }
}

/// One kind of canonical assistant turn (`GNT-25.3-assistant-turns`).
///
/// The vocabulary is exactly two kinds: a final result and a nonempty tool-request
/// set. There is no third kind and no mixed kind.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TurnKind {
    /// A final result and no tool request.
    Final,
    /// A nonempty tool-request set and no final result.
    Tools,
}

impl TurnKind {
    /// Every member of the closed vocabulary, in canonical wire-name order.
    pub const ALL: [Self; 2] = [Self::Final, Self::Tools];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Final => "final",
            Self::Tools => "tools",
        }
    }

    /// Returns the same exact portable spelling as [`Self::wire_name`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.wire_name()
    }

    /// Strictly decodes one exact portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.wire_name() == value)
    }

    /// Returns the clause anchor that owns this kind.
    #[must_use]
    pub const fn requirement(self) -> &'static str {
        "GNT-25.3-assistant-turns"
    }
}

/// One typed cause of an invalid assistant turn (`GNT-25.3-assistant-turns`).
///
/// The cause vocabulary is closed and each condition owns its own cause, so no
/// condition is reported under another condition's cause or under a generic cause.
/// The members are declared in canonical wire-name order.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TurnValidationCause {
    /// One request position was declared twice.
    DuplicateToolPosition,
    /// One tool slot was requested twice in one turn.
    DuplicateToolSlot,
    /// A final result was declared but its payload was empty.
    EmptyFinalResult,
    /// The response declared neither a final result nor a tool request.
    EmptyResponse,
    /// The response declared an empty tool-request set.
    EmptyToolSet,
    /// The response declared a final result and tool requests together.
    MixedFinalAndTools,
    /// A request position is outside the frozen contiguous request order.
    PositionOutsideFrozenOrder,
    /// The request schema digest differs from the frozen descriptor.
    SchemaMismatch,
    /// The response names a tool-set revision other than the frozen one.
    StaleToolSetRevision,
    /// The request names a slot outside the frozen tool-set revision.
    UnknownToolSlot,
}

impl TurnValidationCause {
    /// Every member of the closed vocabulary, in canonical wire-name order.
    pub const ALL: [Self; 10] = [
        Self::DuplicateToolPosition,
        Self::DuplicateToolSlot,
        Self::EmptyFinalResult,
        Self::EmptyResponse,
        Self::EmptyToolSet,
        Self::MixedFinalAndTools,
        Self::PositionOutsideFrozenOrder,
        Self::SchemaMismatch,
        Self::StaleToolSetRevision,
        Self::UnknownToolSlot,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::DuplicateToolPosition => "duplicate-tool-position",
            Self::DuplicateToolSlot => "duplicate-tool-slot",
            Self::EmptyFinalResult => "empty-final-result",
            Self::EmptyResponse => "empty-response",
            Self::EmptyToolSet => "empty-tool-set",
            Self::MixedFinalAndTools => "mixed-final-and-tools",
            Self::PositionOutsideFrozenOrder => "position-outside-frozen-order",
            Self::SchemaMismatch => "schema-mismatch",
            Self::StaleToolSetRevision => "stale-tool-set-revision",
            Self::UnknownToolSlot => "unknown-tool-slot",
        }
    }

    /// Returns the same exact portable spelling as [`Self::wire_name`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.wire_name()
    }

    /// Strictly decodes one exact portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.wire_name() == value)
    }

    /// Returns the clause anchor that owns this cause.
    #[must_use]
    pub const fn requirement(self) -> &'static str {
        "GNT-25.3-assistant-turns"
    }
}

/// One closed outcome of one repair decision (`GNT-25.4-turn-validation-and-repair`).
///
/// Accepted is the original turn accepted without any repair; repaired is a repaired
/// raw response that passed whole-turn validation; exhausted is the finite bound
/// reached; refused is a repair attempt that did not produce an accepted turn. No
/// outcome admits a rejected prefix to dispatch.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RepairOutcome {
    /// The original turn was accepted without repair.
    Accepted,
    /// The repair bound was exhausted.
    Exhausted,
    /// The repair attempt did not produce an accepted turn.
    Refused,
    /// A repaired response passed whole-turn validation.
    Repaired,
}

impl RepairOutcome {
    /// Every member of the closed vocabulary, in canonical wire-name order.
    pub const ALL: [Self; 4] = [
        Self::Accepted,
        Self::Exhausted,
        Self::Refused,
        Self::Repaired,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Exhausted => "exhausted",
            Self::Refused => "refused",
            Self::Repaired => "repaired",
        }
    }

    /// Returns the same exact portable spelling as [`Self::wire_name`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.wire_name()
    }

    /// Strictly decodes one exact portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.wire_name() == value)
    }

    /// Returns the clause anchor that owns this outcome.
    #[must_use]
    pub const fn requirement(self) -> &'static str {
        "GNT-25.4-turn-validation-and-repair"
    }
}

/// One kind of tool slot of the closed slot-kind vocabulary
/// (`GNT-25.6-tool-slots-and-tool-set-revisions`).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ToolSlotKind {
    /// A composite slot resolved from declared component slots.
    Composite,
    /// A provider tool slot of one declared provider binding.
    ProviderTool,
    /// A slot implemented by one ordinary source handler.
    SourceHandler,
}

impl ToolSlotKind {
    /// Every member of the closed vocabulary, in canonical wire-name order.
    pub const ALL: [Self; 3] = [Self::Composite, Self::ProviderTool, Self::SourceHandler];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Composite => "composite",
            Self::ProviderTool => "provider-tool",
            Self::SourceHandler => "source-handler",
        }
    }

    /// Returns the same exact portable spelling as [`Self::wire_name`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.wire_name()
    }

    /// Strictly decodes one exact portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.wire_name() == value)
    }

    /// Returns the clause anchor that owns this kind.
    #[must_use]
    pub const fn requirement(self) -> &'static str {
        "GNT-25.6-tool-slots-and-tool-set-revisions"
    }
}

/// One ordinary callable kind of a source handler (`GNT-25.7-source-handlers`).
///
/// The vocabulary is exactly the three declared source callable kinds: `Fn`, `FnMut`,
/// and `FnOnce`. Admission is decided by the declared kind and never by a synthetic
/// capability, and a single-use handler is consumed at most once.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum HandlerKind {
    /// A callable that admits repeated shared invocations.
    Fn,
    /// A callable that admits sequential exclusive invocations.
    FnMut,
    /// A callable that admits exactly one invocation.
    FnOnce,
}

impl HandlerKind {
    /// Every member of the closed vocabulary, in canonical wire-name order.
    pub const ALL: [Self; 3] = [Self::Fn, Self::FnMut, Self::FnOnce];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Fn => "fn",
            Self::FnMut => "fn-mut",
            Self::FnOnce => "fn-once",
        }
    }

    /// Returns the same exact portable spelling as [`Self::wire_name`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.wire_name()
    }

    /// Strictly decodes one exact portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.wire_name() == value)
    }

    /// Returns whether this kind admits more than one invocation.
    #[must_use]
    pub const fn admits_repeated_invocations(self) -> bool {
        matches!(self, Self::Fn | Self::FnMut)
    }

    /// Returns the clause anchor that owns this kind.
    #[must_use]
    pub const fn requirement(self) -> &'static str {
        "GNT-25.7-source-handlers"
    }
}

/// One closed session directive (`GNT-25.8-sessions-and-child-sessions`).
///
/// A reserved parent transcript admits a derived child; a direct reentry into the
/// reserved parent transcript is refused rather than interleaved.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SessionDirective {
    /// An unreserved session admits ordinary entry.
    Admit,
    /// A reserved parent admits a derived child session.
    DeriveChild,
    /// A reentry into a reserved parent transcript is refused.
    RefuseReentry,
    /// An unreserved session admits ordinary resumption.
    Resume,
}

impl SessionDirective {
    /// Every member of the closed vocabulary, in canonical wire-name order.
    pub const ALL: [Self; 4] = [
        Self::Admit,
        Self::DeriveChild,
        Self::RefuseReentry,
        Self::Resume,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Admit => "admit",
            Self::DeriveChild => "derive-child",
            Self::RefuseReentry => "refuse-reentry",
            Self::Resume => "resume",
        }
    }

    /// Returns the same exact portable spelling as [`Self::wire_name`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.wire_name()
    }

    /// Strictly decodes one exact portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.wire_name() == value)
    }

    /// Returns the clause anchor that owns this directive.
    #[must_use]
    pub const fn requirement(self) -> &'static str {
        "GNT-25.8-sessions-and-child-sessions"
    }
}

/// One kind of stream of the closed stream-kind vocabulary
/// (`GNT-25.9-streaming-and-progress`).
///
/// Semantic is the typed, bounded, authority-safe, restart-safe kind that may carry
/// items of an accepted turn contract; progress is a nonsemantic presentation update
/// that no accepted turn or source result observes.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum StreamKind {
    /// A nonsemantic presentation update.
    Progress,
    /// A typed and bounded stream of an accepted turn contract.
    Semantic,
}

impl StreamKind {
    /// Every member of the closed vocabulary, in canonical wire-name order.
    pub const ALL: [Self; 2] = [Self::Progress, Self::Semantic];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Progress => "progress",
            Self::Semantic => "semantic",
        }
    }

    /// Returns the same exact portable spelling as [`Self::wire_name`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.wire_name()
    }

    /// Strictly decodes one exact portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.wire_name() == value)
    }

    /// Returns whether this kind is the semantic stream kind.
    #[must_use]
    pub const fn is_semantic(self) -> bool {
        matches!(self, Self::Semantic)
    }

    /// Returns whether this kind can affect a source result or an accepted turn.
    ///
    /// A progress observation never can: it cannot create, change, or complete a
    /// final result, add or settle a tool request, or advance a durable cut.
    #[must_use]
    pub const fn affects_source_result(self) -> bool {
        matches!(self, Self::Semantic)
    }

    /// Returns whether this kind advances a durable cut.
    #[must_use]
    pub const fn advances_durable_cut(self) -> bool {
        matches!(self, Self::Semantic)
    }

    /// Returns whether this kind grants an approval.
    ///
    /// No stream kind does: every tool invocation remains subject to the landed
    /// approval and authority contracts.
    #[must_use]
    pub const fn grants_approval(self) -> bool {
        false
    }

    /// Returns the clause anchor that owns this kind.
    #[must_use]
    pub const fn requirement(self) -> &'static str {
        "GNT-25.9-streaming-and-progress"
    }
}

/// One phase of the discovery boundary (`GNT-25.2-fulfillment-preflight`).
///
/// Discovery happens at analyze, link, or preflight time and yields a new binding
/// revision artifact; it never mutates the revision a running loop already holds.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DiscoveryPhase {
    /// The analyze phase.
    Analyze,
    /// The link phase.
    Link,
    /// The preflight phase.
    Preflight,
}

impl DiscoveryPhase {
    /// Every member of the closed vocabulary, in canonical wire-name order.
    pub const ALL: [Self; 3] = [Self::Analyze, Self::Link, Self::Preflight];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Analyze => "analyze",
            Self::Link => "link",
            Self::Preflight => "preflight",
        }
    }

    /// Returns the same exact portable spelling as [`Self::wire_name`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.wire_name()
    }

    /// Strictly decodes one exact portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.wire_name() == value)
    }

    /// Returns whether this phase admits discovery.
    #[must_use]
    pub const fn admits_discovery(self) -> bool {
        matches!(self, Self::Analyze | Self::Link | Self::Preflight)
    }

    /// Returns the clause anchor that owns this phase.
    #[must_use]
    pub const fn requirement(self) -> &'static str {
        "GNT-25.2-fulfillment-preflight"
    }
}

/// One published non-claim of the closed agent non-claim vocabulary
/// (`GNT-25.10-agent-non-claims`).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AgentNonClaim {
    /// A provider display name carries no authority.
    DisplayNameAuthority,
    /// A tool set cannot be mutated mid-loop.
    MidLoopToolMutation,
    /// A model cannot approve its own request.
    ModelSelfApproval,
    /// A rejected prefix cannot be dispatched.
    PrefixDispatch,
    /// No provider response shape is semantics.
    ProviderResponseShapeAsSemantics,
    /// A handler failure has no synthetic recovery class.
    SyntheticHandlerRecoveryClass,
}

impl AgentNonClaim {
    /// Every member of the closed vocabulary, in canonical wire-name order.
    pub const ALL: [Self; 6] = [
        Self::DisplayNameAuthority,
        Self::MidLoopToolMutation,
        Self::ModelSelfApproval,
        Self::PrefixDispatch,
        Self::ProviderResponseShapeAsSemantics,
        Self::SyntheticHandlerRecoveryClass,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::DisplayNameAuthority => "display-name-authority",
            Self::MidLoopToolMutation => "mid-loop-tool-mutation",
            Self::ModelSelfApproval => "model-self-approval",
            Self::PrefixDispatch => "prefix-dispatch",
            Self::ProviderResponseShapeAsSemantics => "provider-response-shape-as-semantics",
            Self::SyntheticHandlerRecoveryClass => "synthetic-handler-recovery-class",
        }
    }

    /// Returns the same exact portable spelling as [`Self::wire_name`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.wire_name()
    }

    /// Strictly decodes one exact portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.wire_name() == value)
    }

    /// Returns the frozen non-claim statement this member publishes.
    #[must_use]
    pub const fn statement(self) -> &'static str {
        match self {
            Self::DisplayNameAuthority => AGENT_NON_CLAIMS[0],
            Self::MidLoopToolMutation => AGENT_NON_CLAIMS[1],
            Self::ModelSelfApproval => AGENT_NON_CLAIMS[2],
            Self::PrefixDispatch => AGENT_NON_CLAIMS[3],
            Self::ProviderResponseShapeAsSemantics => AGENT_NON_CLAIMS[4],
            Self::SyntheticHandlerRecoveryClass => AGENT_NON_CLAIMS[5],
        }
    }

    /// Returns the clause anchor that owns this non-claim.
    #[must_use]
    pub const fn requirement(self) -> &'static str {
        "GNT-25.10-agent-non-claims"
    }
}

/// The frozen agent non-claims of `GNT-25.10-agent-non-claims`, in declared order.
pub const AGENT_NON_CLAIMS: [&str; 6] = [
    "No display-name authority: a provider name map is explicit declared data and a display name never resolves a tool slot.",
    "No mid-loop tool mutation: a tool-set revision is immutable once a loop starts and an added, removed, or replaced descriptor is refused.",
    "No model self-approval: every tool invocation remains subject to the landed approval and authority contracts, and no clause of Section 25 grants an approval.",
    "No prefix dispatch: a turn is validated whole and a rejected prefix is consumed only by a bounded repair attempt.",
    "No provider response shape as semantics: a raw response is undecoded input and no provider field name, envelope kind, error code, or display spelling is a normative term.",
    "No synthetic handler recovery class: a handler failure is the ordinary failure of the landed operation and fault contracts.",
];

/// The declared order of the agent non-claims (`GNT-25.10-agent-non-claims`).
pub const AGENT_NON_CLAIM_ORDER: [AgentNonClaim; 6] = AgentNonClaim::ALL;

/// One presented non-claim assertion (`GNT-25.10-agent-non-claims`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AgentNonClaimAssertion {
    claim: AgentNonClaim,
    presented_as_guarantee: bool,
}

impl AgentNonClaimAssertion {
    /// Records whether one non-claim is presented as a guarantee.
    #[must_use]
    pub const fn new(claim: AgentNonClaim, presented_as_guarantee: bool) -> Self {
        Self {
            claim,
            presented_as_guarantee,
        }
    }

    /// Returns the non-claim this assertion names.
    #[must_use]
    pub const fn claim(&self) -> AgentNonClaim {
        self.claim
    }

    /// Returns whether this assertion presents the non-claim as a guarantee.
    #[must_use]
    pub const fn is_presented_as_guarantee(&self) -> bool {
        self.presented_as_guarantee
    }
}

/// Checks that no agent non-claim is presented as a guarantee
/// (`GNT-25.10-agent-non-claims`).
///
/// # Errors
///
/// Returns [`AgentError`] with code [`AgentDiagnosticCode::NonClaimAsGuarantee`] for
/// the first assertion that presents a non-claim as a guarantee, because a non-claim
/// MUST NOT be presented as a guarantee.
pub fn check_agent_non_claims(assertions: &[AgentNonClaimAssertion]) -> Result<(), AgentError> {
    for assertion in assertions {
        if assertion.presented_as_guarantee {
            return Err(AgentError::new(
                AgentDiagnosticCode::NonClaimAsGuarantee,
                format!(
                    "the non-claim `{}` was presented as a guarantee",
                    assertion.claim.wire_name()
                ),
            ));
        }
    }
    Ok(())
}

/// One frozen agent diagnostic code, one code per condition of Section 25.
///
/// The registry is frozen: each condition of Section 25 owns exactly one code, each
/// code is anchored to exactly one clause through [`Self::requirement`], and no
/// condition is reported under another condition's code. The members are declared in
/// sorted code order and [`Self::ALL`] preserves that order.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AgentDiagnosticCode {
    /// `agent-authority-requirement-refused`
    AuthorityRequirementRefused,
    /// `agent-committed-value-differs`
    CommittedValueDiffers,
    /// `agent-cut-already-committed`
    CutAlreadyCommitted,
    /// `agent-cut-not-committed`
    CutNotCommitted,
    /// `agent-cut-regression`
    CutRegression,
    /// `agent-cut-skip`
    CutSkip,
    /// `agent-duplicate-binding-fact`
    DuplicateBindingFact,
    /// `agent-duplicate-fulfillment-property`
    DuplicateFulfillmentProperty,
    /// `agent-duplicate-provider-name`
    DuplicateProviderName,
    /// `agent-duplicate-tool-position`
    DuplicateToolPosition,
    /// `agent-duplicate-tool-result`
    DuplicateToolResult,
    /// `agent-duplicate-tool-slot`
    DuplicateToolSlot,
    /// `agent-effect-exceeds-admission`
    EffectExceedsAdmission,
    /// `agent-empty-declared-identity`
    EmptyDeclaredIdentity,
    /// `agent-empty-final-result`
    EmptyFinalResult,
    /// `agent-empty-fulfillment-declaration`
    EmptyFulfillmentDeclaration,
    /// `agent-empty-tool-set`
    EmptyToolSet,
    /// `agent-handler-already-consumed`
    HandlerAlreadyConsumed,
    /// `agent-illegal-round-transition`
    IllegalRoundTransition,
    /// `agent-immutable-tool-set-revision`
    ImmutableToolSetRevision,
    /// `agent-missing-binding-fact-state`
    MissingBindingFactState,
    /// `agent-missing-tool-result`
    MissingToolResult,
    /// `agent-mixed-final-and-tools`
    MixedFinalAndTools,
    /// `agent-no-open-tool-requests`
    NoOpenToolRequests,
    /// `agent-non-claim-as-guarantee`
    NonClaimAsGuarantee,
    /// `agent-noncanonical-binding-fact-order`
    NoncanonicalBindingFactOrder,
    /// `agent-noncanonical-descriptor-order`
    NoncanonicalDescriptorOrder,
    /// `agent-noncanonical-fulfillment-order`
    NoncanonicalFulfillmentOrder,
    /// `agent-nonsemantic-stream-presented-as-semantic`
    NonsemanticStreamPresentedAsSemantic,
    /// `agent-parent-reentry-refused`
    ParentReentryRefused,
    /// `agent-position-outside-frozen-order`
    PositionOutsideFrozenOrder,
    /// `agent-prefix-dispatch-refused`
    PrefixDispatchRefused,
    /// `agent-preflight-refused`
    PreflightRefused,
    /// `agent-progress-settlement-claim-refused`
    ProgressSettlementClaimRefused,
    /// `agent-repair-bound-exhausted`
    RepairBoundExhausted,
    /// `agent-reservation-released`
    ReservationReleased,
    /// `agent-schema-mismatch`
    SchemaMismatch,
    /// `agent-second-reservation`
    SecondReservation,
    /// `agent-stale-tool-set-revision`
    StaleToolSetRevision,
    /// `agent-stream-budget-exceeded`
    StreamBudgetExceeded,
    /// `agent-stream-position-regression`
    StreamPositionRegression,
    /// `agent-unbounded-semantic-stream`
    UnboundedSemanticStream,
    /// `agent-unchanged-discovery-artifact`
    UnchangedDiscoveryArtifact,
    /// `agent-unknown-tool-position`
    UnknownToolPosition,
    /// `agent-unknown-tool-slot`
    UnknownToolSlot,
    /// `agent-unsafe-semantic-stream-authority`
    UnsafeSemanticStreamAuthority,
    /// `agent-untyped-semantic-stream`
    UntypedSemanticStream,
    /// `agent-wildcard-fulfillment-declaration`
    WildcardFulfillmentDeclaration,
    /// `agent-wildcard-provider-name`
    WildcardProviderName,
    /// `agent-zero-repair-bound`
    ZeroRepairBound,
}

impl AgentDiagnosticCode {
    /// Every frozen code, in sorted code order.
    pub const ALL: [Self; 50] = [
        Self::AuthorityRequirementRefused,
        Self::CommittedValueDiffers,
        Self::CutAlreadyCommitted,
        Self::CutNotCommitted,
        Self::CutRegression,
        Self::CutSkip,
        Self::DuplicateBindingFact,
        Self::DuplicateFulfillmentProperty,
        Self::DuplicateProviderName,
        Self::DuplicateToolPosition,
        Self::DuplicateToolResult,
        Self::DuplicateToolSlot,
        Self::EffectExceedsAdmission,
        Self::EmptyDeclaredIdentity,
        Self::EmptyFinalResult,
        Self::EmptyFulfillmentDeclaration,
        Self::EmptyToolSet,
        Self::HandlerAlreadyConsumed,
        Self::IllegalRoundTransition,
        Self::ImmutableToolSetRevision,
        Self::MissingBindingFactState,
        Self::MissingToolResult,
        Self::MixedFinalAndTools,
        Self::NoOpenToolRequests,
        Self::NonClaimAsGuarantee,
        Self::NoncanonicalBindingFactOrder,
        Self::NoncanonicalDescriptorOrder,
        Self::NoncanonicalFulfillmentOrder,
        Self::NonsemanticStreamPresentedAsSemantic,
        Self::ParentReentryRefused,
        Self::PositionOutsideFrozenOrder,
        Self::PrefixDispatchRefused,
        Self::PreflightRefused,
        Self::ProgressSettlementClaimRefused,
        Self::RepairBoundExhausted,
        Self::ReservationReleased,
        Self::SchemaMismatch,
        Self::SecondReservation,
        Self::StaleToolSetRevision,
        Self::StreamBudgetExceeded,
        Self::StreamPositionRegression,
        Self::UnboundedSemanticStream,
        Self::UnchangedDiscoveryArtifact,
        Self::UnknownToolPosition,
        Self::UnknownToolSlot,
        Self::UnsafeSemanticStreamAuthority,
        Self::UntypedSemanticStream,
        Self::WildcardFulfillmentDeclaration,
        Self::WildcardProviderName,
        Self::ZeroRepairBound,
    ];

    /// Returns the exact frozen code spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthorityRequirementRefused => "agent-authority-requirement-refused",
            Self::CommittedValueDiffers => "agent-committed-value-differs",
            Self::CutAlreadyCommitted => "agent-cut-already-committed",
            Self::CutNotCommitted => "agent-cut-not-committed",
            Self::CutRegression => "agent-cut-regression",
            Self::CutSkip => "agent-cut-skip",
            Self::DuplicateBindingFact => "agent-duplicate-binding-fact",
            Self::DuplicateFulfillmentProperty => "agent-duplicate-fulfillment-property",
            Self::DuplicateProviderName => "agent-duplicate-provider-name",
            Self::DuplicateToolPosition => "agent-duplicate-tool-position",
            Self::DuplicateToolResult => "agent-duplicate-tool-result",
            Self::DuplicateToolSlot => "agent-duplicate-tool-slot",
            Self::EffectExceedsAdmission => "agent-effect-exceeds-admission",
            Self::EmptyDeclaredIdentity => "agent-empty-declared-identity",
            Self::EmptyFinalResult => "agent-empty-final-result",
            Self::EmptyFulfillmentDeclaration => "agent-empty-fulfillment-declaration",
            Self::EmptyToolSet => "agent-empty-tool-set",
            Self::HandlerAlreadyConsumed => "agent-handler-already-consumed",
            Self::IllegalRoundTransition => "agent-illegal-round-transition",
            Self::ImmutableToolSetRevision => "agent-immutable-tool-set-revision",
            Self::MissingBindingFactState => "agent-missing-binding-fact-state",
            Self::MissingToolResult => "agent-missing-tool-result",
            Self::MixedFinalAndTools => "agent-mixed-final-and-tools",
            Self::NoOpenToolRequests => "agent-no-open-tool-requests",
            Self::NonClaimAsGuarantee => "agent-non-claim-as-guarantee",
            Self::NoncanonicalBindingFactOrder => "agent-noncanonical-binding-fact-order",
            Self::NoncanonicalDescriptorOrder => "agent-noncanonical-descriptor-order",
            Self::NoncanonicalFulfillmentOrder => "agent-noncanonical-fulfillment-order",
            Self::NonsemanticStreamPresentedAsSemantic => {
                "agent-nonsemantic-stream-presented-as-semantic"
            }
            Self::ParentReentryRefused => "agent-parent-reentry-refused",
            Self::PositionOutsideFrozenOrder => "agent-position-outside-frozen-order",
            Self::PrefixDispatchRefused => "agent-prefix-dispatch-refused",
            Self::PreflightRefused => "agent-preflight-refused",
            Self::ProgressSettlementClaimRefused => "agent-progress-settlement-claim-refused",
            Self::RepairBoundExhausted => "agent-repair-bound-exhausted",
            Self::ReservationReleased => "agent-reservation-released",
            Self::SchemaMismatch => "agent-schema-mismatch",
            Self::SecondReservation => "agent-second-reservation",
            Self::StaleToolSetRevision => "agent-stale-tool-set-revision",
            Self::StreamBudgetExceeded => "agent-stream-budget-exceeded",
            Self::StreamPositionRegression => "agent-stream-position-regression",
            Self::UnboundedSemanticStream => "agent-unbounded-semantic-stream",
            Self::UnchangedDiscoveryArtifact => "agent-unchanged-discovery-artifact",
            Self::UnknownToolPosition => "agent-unknown-tool-position",
            Self::UnknownToolSlot => "agent-unknown-tool-slot",
            Self::UnsafeSemanticStreamAuthority => "agent-unsafe-semantic-stream-authority",
            Self::UntypedSemanticStream => "agent-untyped-semantic-stream",
            Self::WildcardFulfillmentDeclaration => "agent-wildcard-fulfillment-declaration",
            Self::WildcardProviderName => "agent-wildcard-provider-name",
            Self::ZeroRepairBound => "agent-zero-repair-bound",
        }
    }

    /// Returns the same exact frozen code spelling as [`Self::as_str`].
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        self.as_str()
    }

    /// Returns the frozen one-line meaning of this code.
    #[must_use]
    pub const fn meaning(self) -> &'static str {
        match self {
            Self::AuthorityRequirementRefused => {
                "the invocation authority requirement was not admitted"
            }
            Self::CommittedValueDiffers => {
                "a presented raw response, turn, position, or final result differs from the committed value"
            }
            Self::CutAlreadyCommitted => "the durable cut was already committed for the round",
            Self::CutNotCommitted => "the durable cut was not committed for the round",
            Self::CutRegression => "a durable cut would move backwards",
            Self::CutSkip => "a durable cut would skip an uncommitted cut",
            Self::DuplicateBindingFact => "one binding property was declared twice",
            Self::DuplicateFulfillmentProperty => "one fulfillment property was declared twice",
            Self::DuplicateProviderName => "one provider name was declared twice in a tool set",
            Self::DuplicateToolPosition => "one request position was declared twice",
            Self::DuplicateToolResult => "one tool-result position was settled twice",
            Self::DuplicateToolSlot => "one tool slot was declared or requested twice",
            Self::EffectExceedsAdmission => {
                "an invocation effect set exceeds the admitted effect set"
            }
            Self::EmptyDeclaredIdentity => "a declared identity was empty or whitespace only",
            Self::EmptyFinalResult => "a final result was declared with an empty payload",
            Self::EmptyFulfillmentDeclaration => "a fulfillment descriptor declared no property",
            Self::EmptyToolSet => "a tool-request set was declared empty",
            Self::HandlerAlreadyConsumed => {
                "a single-use handler was invoked after it was consumed"
            }
            Self::IllegalRoundTransition => "the round transition is not admitted",
            Self::ImmutableToolSetRevision => "a tool-set revision was mutated after it was built",
            Self::MissingBindingFactState => {
                "a binding fact declared the preflight-only missing state"
            }
            Self::MissingToolResult => "one tool-result position was not settled",
            Self::MixedFinalAndTools => "a turn declared a final result and tool requests together",
            Self::NoOpenToolRequests => {
                "a parent transcript was reserved with no open tool request"
            }
            Self::NonClaimAsGuarantee => "an agent non-claim was presented as a guarantee",
            Self::NoncanonicalBindingFactOrder => {
                "binding facts were declared out of canonical property order"
            }
            Self::NoncanonicalDescriptorOrder => {
                "tool descriptors were declared out of canonical slot order"
            }
            Self::NoncanonicalFulfillmentOrder => {
                "fulfillment properties were declared out of canonical order"
            }
            Self::NonsemanticStreamPresentedAsSemantic => {
                "a progress stream was presented as a semantic stream"
            }
            Self::ParentReentryRefused => "a reentry into a reserved parent transcript was refused",
            Self::PositionOutsideFrozenOrder => {
                "a request position is outside the frozen contiguous request order"
            }
            Self::PrefixDispatchRefused => "a rejected prefix was presented for dispatch",
            Self::PreflightRefused => {
                "preflight refused the binding while naming the unbound property"
            }
            Self::ProgressSettlementClaimRefused => {
                "a progress observation claimed to settle an accepted turn or tool result"
            }
            Self::RepairBoundExhausted => "the finite repair attempt bound was exhausted",
            Self::ReservationReleased => "the parent session reservation was already released",
            Self::SchemaMismatch => "a request schema digest differs from the frozen descriptor",
            Self::SecondReservation => "the parent transcript already holds a reservation",
            Self::StaleToolSetRevision => {
                "a raw response names a tool-set revision other than the frozen one"
            }
            Self::StreamBudgetExceeded => "a semantic stream item exceeds its declared budget",
            Self::StreamPositionRegression => "a semantic stream position would move backwards",
            Self::UnboundedSemanticStream => {
                "a semantic stream declares no finite item or byte bound"
            }
            Self::UnchangedDiscoveryArtifact => {
                "discovery presented the same revision identity it started from"
            }
            Self::UnknownToolPosition => {
                "a tool-result position is outside the accepted request set"
            }
            Self::UnknownToolSlot => "a request names a slot outside the frozen tool-set revision",
            Self::UnsafeSemanticStreamAuthority => {
                "a semantic stream declared no authority or more authority than its owner"
            }
            Self::UntypedSemanticStream => "a semantic stream was presented with no stream kind",
            Self::WildcardFulfillmentDeclaration => {
                "a fulfillment descriptor claimed every property without naming one"
            }
            Self::WildcardProviderName => "a provider name map declared a wildcard mapping",
            Self::ZeroRepairBound => "a repair policy declared a zero attempt bound",
        }
    }

    /// Returns the clause anchor that owns this code.
    ///
    /// [`Self::EmptyDeclaredIdentity`] is attributed by the specific declared input
    /// through [`AgentError::requirement`], because a session identity and a stream
    /// identity are owned by different clauses.
    #[must_use]
    pub const fn requirement(self) -> &'static str {
        match self {
            Self::DuplicateFulfillmentProperty
            | Self::EmptyDeclaredIdentity
            | Self::EmptyFulfillmentDeclaration
            | Self::NoncanonicalFulfillmentOrder
            | Self::WildcardFulfillmentDeclaration => "GNT-25.1-agent-requirements-and-fulfillment",
            Self::DuplicateBindingFact
            | Self::MissingBindingFactState
            | Self::NoncanonicalBindingFactOrder
            | Self::PreflightRefused
            | Self::UnchangedDiscoveryArtifact
            | Self::WildcardProviderName => "GNT-25.2-fulfillment-preflight",
            Self::DuplicateToolPosition
            | Self::EmptyFinalResult
            | Self::EmptyToolSet
            | Self::MixedFinalAndTools
            | Self::PositionOutsideFrozenOrder
            | Self::SchemaMismatch
            | Self::StaleToolSetRevision
            | Self::UnknownToolSlot => "GNT-25.3-assistant-turns",
            Self::PrefixDispatchRefused | Self::RepairBoundExhausted | Self::ZeroRepairBound => {
                "GNT-25.4-turn-validation-and-repair"
            }
            Self::CommittedValueDiffers
            | Self::CutAlreadyCommitted
            | Self::CutNotCommitted
            | Self::CutRegression
            | Self::CutSkip
            | Self::IllegalRoundTransition => "GNT-25.5-round-identity-and-durable-cuts",
            Self::AuthorityRequirementRefused
            | Self::DuplicateProviderName
            | Self::DuplicateToolSlot
            | Self::EffectExceedsAdmission
            | Self::ImmutableToolSetRevision
            | Self::NoncanonicalDescriptorOrder => "GNT-25.6-tool-slots-and-tool-set-revisions",
            Self::DuplicateToolResult
            | Self::HandlerAlreadyConsumed
            | Self::MissingToolResult
            | Self::UnknownToolPosition => "GNT-25.7-source-handlers",
            Self::NoOpenToolRequests
            | Self::ParentReentryRefused
            | Self::ReservationReleased
            | Self::SecondReservation => "GNT-25.8-sessions-and-child-sessions",
            Self::NonsemanticStreamPresentedAsSemantic
            | Self::ProgressSettlementClaimRefused
            | Self::StreamBudgetExceeded
            | Self::StreamPositionRegression
            | Self::UnboundedSemanticStream
            | Self::UnsafeSemanticStreamAuthority
            | Self::UntypedSemanticStream => "GNT-25.9-streaming-and-progress",
            Self::NonClaimAsGuarantee => "GNT-25.10-agent-non-claims",
        }
    }
}

/// One typed refusal of the agent model.
///
/// The error carries the frozen [`AgentDiagnosticCode`] of the condition, the clause
/// anchor that owns it, and a detail naming the declared values, so a caller can
/// attribute a refusal to exactly one condition and one clause. Construction is
/// crate-internal: an external caller observes refusals through the model operations
/// rather than compounding new conditions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentError {
    code: AgentDiagnosticCode,
    requirement: &'static str,
    detail: Arc<str>,
}

impl AgentError {
    /// Constructs one refusal attributed to the code's owning clause.
    pub(crate) fn new(code: AgentDiagnosticCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            requirement: code.requirement(),
            detail: Arc::from(detail.into()),
        }
    }

    /// Constructs one refusal attributed to an explicit owning clause.
    ///
    /// The explicit attribution is used by [`Self::EmptyDeclaredIdentity`]-style
    /// conditions, whose owning clause depends on which declared input was empty.
    pub(crate) fn attributed(
        code: AgentDiagnosticCode,
        requirement: &'static str,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            code,
            requirement,
            detail: Arc::from(detail.into()),
        }
    }

    /// Returns the frozen code of this refusal.
    #[must_use]
    pub const fn code(&self) -> AgentDiagnosticCode {
        self.code
    }

    /// Returns the clause anchor that owns this refusal.
    #[must_use]
    pub const fn requirement(&self) -> &'static str {
        self.requirement
    }

    /// Returns the declared-value detail of this refusal.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl fmt::Display for AgentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code.as_str(), self.detail)
    }
}

impl std::error::Error for AgentError {}

/// Validates one declared text input and returns it as shared text.
///
/// # Errors
///
/// Returns an [`AgentError`] with code [`AgentDiagnosticCode::EmptyDeclaredIdentity`]
/// when the declared text is empty or whitespace only, attributed to the clause that
/// owns the declared input.
fn declared_text(value: &str, input: AgentDeclaredInput) -> Result<Arc<str>, AgentError> {
    if value.trim().is_empty() {
        return Err(AgentError::attributed(
            AgentDiagnosticCode::EmptyDeclaredIdentity,
            input.requirement(),
            format!(
                "the declared `{}` is empty or whitespace only",
                input.wire_name()
            ),
        ));
    }
    Ok(Arc::from(value))
}

/// One stable package-scoped agent requirement identity
/// (`GNT-25.1-agent-requirements-and-fulfillment`).
///
/// The identity is derived from the declaring package and the declared requirement
/// name under its own domain separator and from nothing else, so no provider name,
/// host handle, or adapter fact enters it.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AgentRequirementId {
    text: Arc<str>,
}

impl AgentRequirementId {
    /// Derives one agent requirement identity from its declared package and name.
    ///
    /// # Errors
    ///
    /// Returns an [`AgentError`] with code [`AgentDiagnosticCode::EmptyDeclaredIdentity`]
    /// when the package or the requirement name is empty or whitespace only.
    pub fn derive(package: &str, name: &str) -> Result<Self, AgentError> {
        let package = declared_text(package, AgentDeclaredInput::Package)?;
        let name = declared_text(name, AgentDeclaredInput::Requirement)?;
        let digest = digest_fields(
            AGENT_REQUIREMENT_DOMAIN,
            &[package.as_bytes(), name.as_bytes()],
        );
        Ok(Self {
            text: Arc::from(format!("agent-requirement:{}", encode_hex(&digest))),
        })
    }

    /// Returns the exact portable identity spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Returns the lowercase digest text without the identity prefix.
    #[must_use]
    pub fn digest_hex(&self) -> &str {
        self.text
            .strip_prefix("agent-requirement:")
            .unwrap_or(&self.text)
    }
}

impl fmt::Display for AgentRequirementId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.text)
    }
}

/// One stable, package-qualified tool slot identity
/// (`GNT-25.6-tool-slots-and-tool-set-revisions`).
///
/// The identity is derived from the declared package and the declared slot name and
/// never from a provider display name, a host handle, a network address, or an
/// adapter fact, so the same slot identity denotes the same declared tool for the
/// life of the loop.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ToolSlotId {
    text: Arc<str>,
}

impl ToolSlotId {
    /// Derives one tool slot identity from its declared package and slot name.
    ///
    /// # Errors
    ///
    /// Returns an [`AgentError`] with code [`AgentDiagnosticCode::EmptyDeclaredIdentity`]
    /// when the package or the slot name is empty or whitespace only.
    pub fn derive(package: &str, name: &str) -> Result<Self, AgentError> {
        let package = declared_text(package, AgentDeclaredInput::Package)?;
        let name = declared_text(name, AgentDeclaredInput::Slot)?;
        let digest = digest_fields(TOOL_SLOT_DOMAIN, &[package.as_bytes(), name.as_bytes()]);
        Ok(Self {
            text: Arc::from(format!("tool-slot:{}", encode_hex(&digest))),
        })
    }

    /// Returns the exact portable identity spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Returns the lowercase digest text without the identity prefix.
    #[must_use]
    pub fn digest_hex(&self) -> &str {
        self.text.strip_prefix("tool-slot:").unwrap_or(&self.text)
    }
}

impl fmt::Display for ToolSlotId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.text)
    }
}

/// One immutable tool-set revision identity
/// (`GNT-25.6-tool-slots-and-tool-set-revisions`).
///
/// The identity is derived from the declared revision counter and the ordered slot,
/// provider name, and schema digest of every descriptor, so a revision that differs
/// in any declared descriptor is a different revision.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ToolSetRevisionId {
    text: Arc<str>,
}

impl ToolSetRevisionId {
    /// Derives one tool-set revision identity from its ordered descriptors.
    ///
    /// Every declared descriptor fact enters the derivation: the slot, the provider
    /// name, the schema digest, the canonical effect set, the authority requirement,
    /// the recovery class, and the retry eligibility. A revision that differs in any
    /// of them has a distinct identity, so a widened effect set, a mutated authority
    /// or recovery fact, or a changed retry eligibility is refused as a different
    /// revision rather than resolved to the frozen one.
    #[must_use]
    pub fn derive(revision: u64, descriptors: &[ToolDescriptor]) -> Self {
        let mut fields: Vec<Vec<u8>> = Vec::with_capacity(1 + descriptors.len() * 4);
        fields.push(revision.to_be_bytes().to_vec());
        for descriptor in descriptors {
            fields.push(descriptor.slot().as_str().as_bytes().to_vec());
            fields.push(descriptor.provider_name().as_bytes().to_vec());
            fields.push(descriptor.schema_digest().as_bytes().to_vec());
            for effect in descriptor.effects().iter() {
                fields.push(effect.wire_name().as_bytes().to_vec());
            }
            fields.push(descriptor.authority().as_str().as_bytes().to_vec());
            fields.push(descriptor.recovery().wire_name().as_bytes().to_vec());
            fields.push(descriptor.retry().wire_name().as_bytes().to_vec());
        }
        let refs: Vec<&[u8]> = fields.iter().map(Vec::as_slice).collect();
        let digest = digest_fields(TOOL_SET_REVISION_DOMAIN, &refs);
        Self {
            text: Arc::from(format!("tool-set-revision:{}", encode_hex(&digest))),
        }
    }

    /// Returns the exact portable identity spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Returns the lowercase digest text without the identity prefix.
    #[must_use]
    pub fn digest_hex(&self) -> &str {
        self.text
            .strip_prefix("tool-set-revision:")
            .unwrap_or(&self.text)
    }
}

impl fmt::Display for ToolSetRevisionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.text)
    }
}

/// One stable tool-invocation identity (`GNT-25.3-assistant-turns`).
///
/// The identity is derived from the frozen revision, the tool slot, and the declared
/// request position, so one request position of one revision is one invocation.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ToolInvocationId {
    text: Arc<str>,
}

impl ToolInvocationId {
    /// Derives one tool-invocation identity from its revision, slot, and position.
    #[must_use]
    pub fn derive(revision: &ToolSetRevisionId, slot: &ToolSlotId, position: u32) -> Self {
        let digest = digest_fields(
            TOOL_INVOCATION_DOMAIN,
            &[
                revision.as_str().as_bytes(),
                slot.as_str().as_bytes(),
                &position.to_be_bytes(),
            ],
        );
        Self {
            text: Arc::from(format!("tool-invocation:{}", encode_hex(&digest))),
        }
    }

    /// Returns the exact portable identity spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }
}

impl fmt::Display for ToolInvocationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.text)
    }
}

/// One stable parent or child session identity (`GNT-25.8-sessions-and-child-sessions`).
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SessionId {
    text: Arc<str>,
}

impl SessionId {
    /// Constructs one session identity from its declared session name.
    ///
    /// # Errors
    ///
    /// Returns an [`AgentError`] with code [`AgentDiagnosticCode::EmptyDeclaredIdentity`]
    /// when the declared name is empty or whitespace only.
    pub fn new(name: &str) -> Result<Self, AgentError> {
        Ok(Self {
            text: declared_text(name, AgentDeclaredInput::Session)?,
        })
    }

    /// Returns the exact portable identity spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.text)
    }
}

/// One stable child-session identity (`GNT-25.8-sessions-and-child-sessions`).
///
/// The identity is derived from the parent session identity and the declared child
/// ordinal, so equal declared inputs produce equal child identities and the same
/// child is the same session across a resume.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ChildSessionId {
    text: Arc<str>,
}

impl ChildSessionId {
    /// Derives one child-session identity from its parent and declared ordinal.
    #[must_use]
    pub fn derive(parent: &SessionId, ordinal: u32) -> Self {
        let digest = digest_fields(
            CHILD_SESSION_DOMAIN,
            &[parent.as_str().as_bytes(), &ordinal.to_be_bytes()],
        );
        Self {
            text: Arc::from(format!("child-session:{}", encode_hex(&digest))),
        }
    }

    /// Returns the exact portable identity spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Returns the lowercase digest text without the identity prefix.
    #[must_use]
    pub fn digest_hex(&self) -> &str {
        self.text
            .strip_prefix("child-session:")
            .unwrap_or(&self.text)
    }
}

impl fmt::Display for ChildSessionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.text)
    }
}

/// One stable round identity (`GNT-25.5-round-identity-and-durable-cuts`).
///
/// The identity is derived from the owning session, the accepted turn position of
/// that session, and the declared round ordinal, and from nothing else.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RoundId {
    text: Arc<str>,
}

impl RoundId {
    /// Derives one round identity from its session, accepted position, and ordinal.
    #[must_use]
    pub fn derive(session: &SessionId, accepted_position: u32, ordinal: u64) -> Self {
        let digest = digest_fields(
            ROUND_DOMAIN,
            &[
                session.as_str().as_bytes(),
                &accepted_position.to_be_bytes(),
                &ordinal.to_be_bytes(),
            ],
        );
        Self {
            text: Arc::from(format!("agent-round:{}", encode_hex(&digest))),
        }
    }

    /// Returns the exact portable identity spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Returns the lowercase digest text without the identity prefix.
    #[must_use]
    pub fn digest_hex(&self) -> &str {
        self.text.strip_prefix("agent-round:").unwrap_or(&self.text)
    }
}

impl fmt::Display for RoundId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.text)
    }
}

/// One package-scoped agent requirement with one machine-checkable fulfillment
/// descriptor (`GNT-25.1-agent-requirements-and-fulfillment`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentRequirement {
    id: AgentRequirementId,
    package: Arc<str>,
    descriptor: FulfillmentDescriptor,
}

impl AgentRequirement {
    /// Constructs one package-scoped agent requirement.
    ///
    /// # Errors
    ///
    /// Returns an [`AgentError`] with code [`AgentDiagnosticCode::EmptyDeclaredIdentity`]
    /// when the declared package or requirement name is empty or whitespace only.
    pub fn new(
        package: &str,
        name: &str,
        descriptor: FulfillmentDescriptor,
    ) -> Result<Self, AgentError> {
        let package = declared_text(package, AgentDeclaredInput::Package)?;
        let id = AgentRequirementId::derive(&package, name)?;
        Ok(Self {
            id,
            package,
            descriptor,
        })
    }

    /// Returns the stable requirement identity.
    #[must_use]
    pub const fn id(&self) -> &AgentRequirementId {
        &self.id
    }

    /// Returns the declaring package name.
    #[must_use]
    pub fn package(&self) -> &str {
        &self.package
    }

    /// Returns the one fulfillment descriptor of this requirement.
    #[must_use]
    pub const fn descriptor(&self) -> &FulfillmentDescriptor {
        &self.descriptor
    }
}

/// One fulfillment descriptor of a closed, nonempty property set
/// (`GNT-25.1-agent-requirements-and-fulfillment`).
///
/// The descriptor declares its properties in canonical order and refuses an empty
/// declaration, a repeated property, and a noncanonical declaration order. A wildcard
/// declaration is not representable: [`Self::wildcard`] always refuses, because a
/// wildcard would silently absorb whatever a binding happens to provide.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FulfillmentDescriptor {
    properties: Vec<FulfillmentProperty>,
}

impl FulfillmentDescriptor {
    /// Constructs one descriptor from its declared properties.
    ///
    /// The properties must be declared in strictly increasing canonical order; a
    /// noncanonical declaration order is refused rather than sorted into canonical
    /// order, so the declaration a caller presents is exactly the declaration checked.
    ///
    /// # Errors
    ///
    /// Returns an [`AgentError`] with code
    /// [`AgentDiagnosticCode::EmptyFulfillmentDeclaration`] when no property is
    /// declared, and one with code [`AgentDiagnosticCode::DuplicateFulfillmentProperty`]
    /// when one property is declared twice, and one with code
    /// [`AgentDiagnosticCode::NoncanonicalFulfillmentOrder`] when the properties are
    /// not in canonical order.
    pub fn new(properties: &[FulfillmentProperty]) -> Result<Self, AgentError> {
        if properties.is_empty() {
            return Err(AgentError::new(
                AgentDiagnosticCode::EmptyFulfillmentDeclaration,
                "a fulfillment descriptor declares at least one property",
            ));
        }
        for pair in properties.windows(2) {
            if pair[0] == pair[1] {
                return Err(AgentError::new(
                    AgentDiagnosticCode::DuplicateFulfillmentProperty,
                    format!("the property `{}` was declared twice", pair[0].wire_name()),
                ));
            }
            if pair[0] > pair[1] {
                return Err(AgentError::new(
                    AgentDiagnosticCode::NoncanonicalFulfillmentOrder,
                    format!(
                        "the property `{}` precedes the property `{}` out of canonical order",
                        pair[1].wire_name(),
                        pair[0].wire_name()
                    ),
                ));
            }
        }
        Ok(Self {
            properties: properties.to_vec(),
        })
    }

    /// Refuses one wildcard declaration (`GNT-25.1-agent-requirements-and-fulfillment`).
    ///
    /// # Errors
    ///
    /// Always returns an [`AgentError`] with code
    /// [`AgentDiagnosticCode::WildcardFulfillmentDeclaration`], because a descriptor
    /// that claims every property without naming one cannot be checked by preflight.
    pub fn wildcard() -> Result<Self, AgentError> {
        Err(AgentError::new(
            AgentDiagnosticCode::WildcardFulfillmentDeclaration,
            "a fulfillment descriptor names its properties instead of claiming a wildcard",
        ))
    }

    /// Returns the declared properties in canonical order.
    #[must_use]
    pub fn properties(&self) -> &[FulfillmentProperty] {
        &self.properties
    }

    /// Returns whether one property is declared.
    #[must_use]
    pub fn contains(&self, property: FulfillmentProperty) -> bool {
        self.properties.contains(&property)
    }

    /// Returns the declared property count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.properties.len()
    }

    /// Returns whether no property is declared, which cannot occur.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.properties.is_empty()
    }
}

/// One declared binding fact of one property (`GNT-25.2-fulfillment-preflight`).
///
/// A binding fact is either bound or unsupported; the preflight-only missing state is
/// not declarable as a fact, because missing is exactly the absence of a fact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BindingFact {
    property: FulfillmentProperty,
    state: FulfillmentState,
}

impl BindingFact {
    /// Constructs one declared binding fact.
    ///
    /// # Errors
    ///
    /// Returns an [`AgentError`] with code [`AgentDiagnosticCode::MissingBindingFactState`]
    /// when the declared state is the preflight-only missing state.
    pub fn new(property: FulfillmentProperty, state: FulfillmentState) -> Result<Self, AgentError> {
        if state == FulfillmentState::Missing {
            return Err(AgentError::new(
                AgentDiagnosticCode::MissingBindingFactState,
                format!(
                    "the binding fact of `{}` cannot declare the missing state",
                    property.wire_name()
                ),
            ));
        }
        Ok(Self { property, state })
    }

    /// Returns the property this fact declares.
    #[must_use]
    pub const fn property(&self) -> FulfillmentProperty {
        self.property
    }

    /// Returns the declared state of this fact.
    #[must_use]
    pub const fn state(&self) -> FulfillmentState {
        self.state
    }
}

/// One explicit provider name map (`GNT-25.2-fulfillment-preflight`).
///
/// The map is declared data: it maps declared provider names to canonical tool slots,
/// it refuses an empty or wildcard mapping, and it carries no authority. A provider
/// display name that the map does not name never resolves a slot.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProviderNameMap {
    entries: BTreeMap<Arc<str>, ToolSlotId>,
}

impl ProviderNameMap {
    /// Constructs one explicit name map from declared provider-name entries.
    ///
    /// # Errors
    ///
    /// Returns an [`AgentError`] with code [`AgentDiagnosticCode::WildcardProviderName`]
    /// for a wildcard mapping, one with code [`AgentDiagnosticCode::EmptyDeclaredIdentity`]
    /// for an empty provider name, and one with code
    /// [`AgentDiagnosticCode::DuplicateProviderName`] for a repeated provider name.
    pub fn new(entries: &[(&str, ToolSlotId)]) -> Result<Self, AgentError> {
        let mut map = BTreeMap::new();
        for (name, slot) in entries {
            if *name == "*" {
                return Err(AgentError::new(
                    AgentDiagnosticCode::WildcardProviderName,
                    "a provider name map names its provider entries instead of a wildcard",
                ));
            }
            let name = declared_text(name, AgentDeclaredInput::ProviderName)?;
            if map.insert(name.clone(), slot.clone()).is_some() {
                return Err(AgentError::new(
                    AgentDiagnosticCode::DuplicateProviderName,
                    format!("the provider name `{name}` was declared twice"),
                ));
            }
        }
        Ok(Self { entries: map })
    }

    /// Constructs one empty name map.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Resolves one explicitly declared provider name to its canonical tool slot.
    ///
    /// A display spelling or description the map does not name returns `None` and
    /// never resolves to a slot.
    #[must_use]
    pub fn resolve(&self, provider_name: &str) -> Option<&ToolSlotId> {
        self.entries.get(provider_name)
    }

    /// Returns whether the map declares no entry.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the declared entries in provider-name order.
    pub fn entries(&self) -> impl Iterator<Item = (&str, &ToolSlotId)> {
        self.entries
            .iter()
            .map(|(name, slot)| (name.as_ref(), slot))
    }
}

/// One declared binding revision (`GNT-25.2-fulfillment-preflight`).
///
/// The revision declares one state per property in canonical property order, refuses a
/// repeated property and a noncanonical declaration order, and carries its explicit
/// provider name map. Two revisions with the same provider and revision counter are
/// the same revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentBindingRevision {
    provider: Arc<str>,
    revision: u64,
    facts: Vec<BindingFact>,
    name_map: ProviderNameMap,
}

impl AgentBindingRevision {
    /// Constructs one binding revision from its declared facts and name map.
    ///
    /// # Errors
    ///
    /// Returns an [`AgentError`] with code [`AgentDiagnosticCode::EmptyDeclaredIdentity`]
    /// when the provider name is empty or whitespace only, and one with code
    /// [`AgentDiagnosticCode::DuplicateBindingFact`] when one property is declared
    /// twice, and one with code [`AgentDiagnosticCode::NoncanonicalBindingFactOrder`]
    /// when the facts are not in canonical property order.
    pub fn new(
        provider: &str,
        revision: u64,
        facts: &[BindingFact],
        name_map: ProviderNameMap,
    ) -> Result<Self, AgentError> {
        let provider = declared_text(provider, AgentDeclaredInput::ProviderName)?;
        for pair in facts.windows(2) {
            if pair[0].property() == pair[1].property() {
                return Err(AgentError::new(
                    AgentDiagnosticCode::DuplicateBindingFact,
                    format!(
                        "the binding property `{}` was declared twice",
                        pair[0].property().wire_name()
                    ),
                ));
            }
            if pair[0].property() > pair[1].property() {
                return Err(AgentError::new(
                    AgentDiagnosticCode::NoncanonicalBindingFactOrder,
                    format!(
                        "the binding property `{}` precedes the binding property `{}` out of canonical order",
                        pair[1].property().wire_name(),
                        pair[0].property().wire_name()
                    ),
                ));
            }
        }
        Ok(Self {
            provider,
            revision,
            facts: facts.to_vec(),
            name_map,
        })
    }

    /// Returns the declared provider name.
    #[must_use]
    pub fn provider(&self) -> &str {
        &self.provider
    }

    /// Returns the declared revision counter.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Returns the declared facts in canonical property order.
    #[must_use]
    pub fn facts(&self) -> &[BindingFact] {
        &self.facts
    }

    /// Returns the explicit provider name map of this revision.
    #[must_use]
    pub const fn name_map(&self) -> &ProviderNameMap {
        &self.name_map
    }

    /// Returns the declared state of one property, if the revision declares one.
    #[must_use]
    pub fn state_for(&self, property: FulfillmentProperty) -> Option<FulfillmentState> {
        self.facts
            .iter()
            .find(|fact| fact.property() == property)
            .map(BindingFact::state)
    }

    /// Returns whether two revisions declare the same provider and revision counter.
    #[must_use]
    pub fn same_revision_as(&self, other: &Self) -> bool {
        self.provider == other.provider && self.revision == other.revision
    }
}

/// One discovery artifact of the analyze, link, and preflight boundary
/// (`GNT-25.2-fulfillment-preflight`).
///
/// Discovery yields a new binding revision with its own identity; it never mutates,
/// widens, or retrofits the revision a running loop already holds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveryArtifact {
    phase: DiscoveryPhase,
    source: AgentBindingRevision,
    discovered: AgentBindingRevision,
}

impl DiscoveryArtifact {
    /// Records one discovery result over its source revision.
    ///
    /// # Errors
    ///
    /// Returns an [`AgentError`] with code
    /// [`AgentDiagnosticCode::UnchangedDiscoveryArtifact`] when the discovered
    /// revision declares the same provider and revision counter as the source, because
    /// discovery yields a new artifact rather than the revision it started from.
    pub fn discover(
        phase: DiscoveryPhase,
        source: AgentBindingRevision,
        discovered: AgentBindingRevision,
    ) -> Result<Self, AgentError> {
        if source.same_revision_as(&discovered) {
            return Err(AgentError::new(
                AgentDiagnosticCode::UnchangedDiscoveryArtifact,
                format!(
                    "discovery in the `{}` phase presented the revision it started from",
                    phase.wire_name()
                ),
            ));
        }
        Ok(Self {
            phase,
            source,
            discovered,
        })
    }

    /// Returns the discovery phase.
    #[must_use]
    pub const fn phase(&self) -> DiscoveryPhase {
        self.phase
    }

    /// Returns the source revision discovery started from.
    #[must_use]
    pub const fn source(&self) -> &AgentBindingRevision {
        &self.source
    }

    /// Returns the new discovered revision.
    #[must_use]
    pub const fn discovered(&self) -> &AgentBindingRevision {
        &self.discovered
    }

    /// Consumes the artifact and returns the new discovered revision.
    #[must_use]
    pub fn into_revision(self) -> AgentBindingRevision {
        self.discovered
    }
}

/// One per-property verdict of preflight (`GNT-25.2-fulfillment-preflight`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PropertyVerdict {
    property: FulfillmentProperty,
    state: FulfillmentState,
}

impl PropertyVerdict {
    /// Returns the property this verdict decides.
    #[must_use]
    pub const fn property(&self) -> FulfillmentProperty {
        self.property
    }

    /// Returns the decided per-property state.
    #[must_use]
    pub const fn state(&self) -> FulfillmentState {
        self.state
    }
}

/// One complete preflight report of one requirement against one binding revision
/// (`GNT-25.2-fulfillment-preflight`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreflightReport {
    verdict: PreflightVerdict,
    verdicts: Vec<PropertyVerdict>,
    unsupported: Option<FulfillmentProperty>,
    missing: Option<FulfillmentProperty>,
}

impl PreflightReport {
    /// Returns the one preflight verdict.
    #[must_use]
    pub const fn verdict(&self) -> PreflightVerdict {
        self.verdict
    }

    /// Returns the per-property verdicts in canonical property order.
    #[must_use]
    pub fn verdicts(&self) -> &[PropertyVerdict] {
        &self.verdicts
    }

    /// Returns the first unsupported property in canonical order, if any.
    #[must_use]
    pub const fn unsupported(&self) -> Option<FulfillmentProperty> {
        self.unsupported
    }

    /// Returns the first property with no declared fact, if any.
    #[must_use]
    pub const fn missing(&self) -> Option<FulfillmentProperty> {
        self.missing
    }

    /// Returns the exact property that refused the binding, if any.
    ///
    /// An unsupported property takes precedence over a missing property, so the
    /// report always names one exact property rather than a generic refusal.
    #[must_use]
    pub const fn refused_property(&self) -> Option<FulfillmentProperty> {
        match self.unsupported {
            Some(property) => Some(property),
            None => self.missing,
        }
    }

    /// Returns whether preflight proved a complete compatible binding.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.verdict.admits_loop()
    }

    /// Requires the complete verdict, refusing while naming the unbound property.
    ///
    /// # Errors
    ///
    /// Returns an [`AgentError`] with code [`AgentDiagnosticCode::PreflightRefused`]
    /// naming the exact property that refused the binding, and never a generic refusal.
    pub fn require_complete(&self) -> Result<(), AgentError> {
        match self.refused_property() {
            Some(property) => Err(AgentError::new(
                AgentDiagnosticCode::PreflightRefused,
                format!(
                    "the property `{}` refused the binding with verdict `{}`",
                    property.wire_name(),
                    self.verdict.wire_name()
                ),
            )),
            None => Ok(()),
        }
    }
}

/// Decides preflight over one requirement and one binding revision
/// (`GNT-25.2-fulfillment-preflight`).
///
/// The decision is total and exclusive over declared facts: every declared property
/// receives exactly one [`FulfillmentState`], and the verdict is complete only when
/// every property is bound. An unsupported property is named exactly, and a property
/// the revision declares no fact for is missing rather than defaulted to bound.
#[must_use]
pub fn preflight(
    requirement: &AgentRequirement,
    binding: &AgentBindingRevision,
) -> PreflightReport {
    let mut verdicts = Vec::with_capacity(requirement.descriptor().properties().len());
    for property in requirement.descriptor().properties() {
        let state = match binding.state_for(*property) {
            Some(FulfillmentState::Bound) => FulfillmentState::Bound,
            Some(FulfillmentState::Unsupported) => FulfillmentState::Unsupported,
            Some(FulfillmentState::Missing) | None => FulfillmentState::Missing,
        };
        verdicts.push(PropertyVerdict {
            property: *property,
            state,
        });
    }
    let unsupported = verdicts
        .iter()
        .find(|verdict| verdict.state == FulfillmentState::Unsupported)
        .map(|verdict| verdict.property);
    let missing = verdicts
        .iter()
        .find(|verdict| verdict.state == FulfillmentState::Missing)
        .map(|verdict| verdict.property);
    let verdict = if unsupported.is_some() {
        PreflightVerdict::Unsupported
    } else if missing.is_some() {
        PreflightVerdict::Incomplete
    } else {
        PreflightVerdict::Complete
    };
    PreflightReport {
        verdict,
        verdicts,
        unsupported,
        missing,
    }
}

/// One declared tool descriptor of a tool-set revision
/// (`GNT-25.6-tool-slots-and-tool-set-revisions`).
///
/// The descriptor declares the slot, the slot kind, the explicit provider name, the
/// canonical schema digest, the landed effect set, the landed authority requirement,
/// and the landed recovery facts. It carries no host handle and no provider payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolDescriptor {
    slot: ToolSlotId,
    kind: ToolSlotKind,
    provider_name: Arc<str>,
    schema_digest: Arc<str>,
    effects: EffectSet,
    authority: AuthorityRequirementId,
    recovery: RecoveryClass,
    retry: RetryEligibility,
}

impl ToolDescriptor {
    /// Constructs one tool descriptor from its declared facts.
    ///
    /// # Errors
    ///
    /// Returns an [`AgentError`] with code [`AgentDiagnosticCode::EmptyDeclaredIdentity`]
    /// when the provider name or the schema digest is empty or whitespace only.
    #[allow(clippy::too_many_arguments)]
    #[must_use = "a tool descriptor must be admitted into a tool-set revision"]
    pub fn new(
        slot: ToolSlotId,
        kind: ToolSlotKind,
        provider_name: &str,
        schema_digest: &str,
        effects: EffectSet,
        authority: AuthorityRequirementId,
        recovery: RecoveryClass,
        retry: RetryEligibility,
    ) -> Result<Self, AgentError> {
        Ok(Self {
            slot,
            kind,
            provider_name: declared_text(provider_name, AgentDeclaredInput::ProviderName)?,
            schema_digest: declared_text(schema_digest, AgentDeclaredInput::SchemaDigest)?,
            effects,
            authority,
            recovery,
            retry,
        })
    }

    /// Returns the package-qualified slot of this descriptor.
    #[must_use]
    pub const fn slot(&self) -> &ToolSlotId {
        &self.slot
    }

    /// Returns the declared slot kind.
    #[must_use]
    pub const fn kind(&self) -> ToolSlotKind {
        self.kind
    }

    /// Returns the explicit provider name of this descriptor.
    #[must_use]
    pub fn provider_name(&self) -> &str {
        &self.provider_name
    }

    /// Returns the canonical schema digest of this descriptor.
    #[must_use]
    pub fn schema_digest(&self) -> &str {
        &self.schema_digest
    }

    /// Returns the landed effect set of this descriptor.
    #[must_use]
    pub const fn effects(&self) -> EffectSet {
        self.effects
    }

    /// Returns the landed authority requirement of this descriptor.
    #[must_use]
    pub const fn authority(&self) -> &AuthorityRequirementId {
        &self.authority
    }

    /// Returns the landed recovery class of this descriptor.
    #[must_use]
    pub const fn recovery(&self) -> RecoveryClass {
        self.recovery
    }

    /// Returns the landed retry eligibility of this descriptor.
    #[must_use]
    pub const fn retry(&self) -> RetryEligibility {
        self.retry
    }

    /// Returns whether one presented schema digest is the frozen digest.
    #[must_use]
    pub fn admits_schema(&self, schema_digest: &str) -> bool {
        self.schema_digest.as_ref() == schema_digest
    }

    /// Checks the descriptor effect set against the admitted effect set.
    ///
    /// # Errors
    ///
    /// Returns an [`AgentError`] with code [`AgentDiagnosticCode::EffectExceedsAdmission`]
    /// when one declared effect is not in the admitted set, because a descriptor or
    /// schema mismatch fails closed rather than widening the admission.
    pub fn check_effects(&self, available: EffectSet) -> Result<(), AgentError> {
        for effect in self.effects.iter() {
            if !available.contains(effect) {
                return Err(AgentError::new(
                    AgentDiagnosticCode::EffectExceedsAdmission,
                    format!(
                        "the descriptor of `{}` declares an effect outside the admitted set",
                        self.slot
                    ),
                ));
            }
        }
        Ok(())
    }

    /// Checks the descriptor authority requirement against one admission decision.
    ///
    /// # Errors
    ///
    /// Returns an [`AgentError`] with code
    /// [`AgentDiagnosticCode::AuthorityRequirementRefused`] when the landed authority
    /// contracts did not admit the declared requirement.
    pub fn check_authority(&self, admitted: bool) -> Result<(), AgentError> {
        if admitted {
            return Ok(());
        }
        Err(AgentError::new(
            AgentDiagnosticCode::AuthorityRequirementRefused,
            format!(
                "the authority requirement of `{}` was not admitted",
                self.slot
            ),
        ))
    }
}

/// One immutable tool-set revision (`GNT-25.6-tool-slots-and-tool-set-revisions`).
///
/// The revision holds one descriptor per package-qualified slot in canonical slot
/// order, refuses a repeated slot, a repeated provider name, and a noncanonical
/// descriptor order, and refuses every mutation once built.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolSetRevision {
    revision: u64,
    id: ToolSetRevisionId,
    descriptors: Vec<ToolDescriptor>,
}

impl ToolSetRevision {
    /// Constructs one immutable tool-set revision from ordered descriptors.
    ///
    /// # Errors
    ///
    /// Returns an [`AgentError`] with code [`AgentDiagnosticCode::DuplicateToolSlot`]
    /// for a repeated slot, one with code [`AgentDiagnosticCode::DuplicateProviderName`]
    /// for a repeated provider name, and one with code
    /// [`AgentDiagnosticCode::NoncanonicalDescriptorOrder`] when descriptors are not in
    /// strictly increasing canonical slot order.
    pub fn new(revision: u64, descriptors: Vec<ToolDescriptor>) -> Result<Self, AgentError> {
        let mut prior_slot: Option<&ToolSlotId> = None;
        let mut provider_names = BTreeSet::new();
        for descriptor in &descriptors {
            if let Some(prior) = prior_slot {
                if prior == descriptor.slot() {
                    return Err(AgentError::new(
                        AgentDiagnosticCode::DuplicateToolSlot,
                        format!("the slot `{}` was declared twice", descriptor.slot()),
                    ));
                }
                if prior > descriptor.slot() {
                    return Err(AgentError::new(
                        AgentDiagnosticCode::NoncanonicalDescriptorOrder,
                        format!(
                            "the descriptor of `{}` follows the descriptor of `{prior}` out of order",
                            descriptor.slot()
                        ),
                    ));
                }
            }
            prior_slot = Some(descriptor.slot());
            if !provider_names.insert(descriptor.provider_name().to_owned()) {
                return Err(AgentError::new(
                    AgentDiagnosticCode::DuplicateProviderName,
                    format!(
                        "the provider name `{}` was declared twice in the tool set",
                        descriptor.provider_name()
                    ),
                ));
            }
        }
        let id = ToolSetRevisionId::derive(revision, &descriptors);
        Ok(Self {
            revision,
            id,
            descriptors,
        })
    }

    /// Returns the stable revision identity.
    #[must_use]
    pub const fn id(&self) -> &ToolSetRevisionId {
        &self.id
    }

    /// Returns the declared revision counter.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Returns the descriptors in canonical slot order.
    #[must_use]
    pub fn descriptors(&self) -> &[ToolDescriptor] {
        &self.descriptors
    }

    /// Returns the descriptor of one slot, if the revision declares it.
    #[must_use]
    pub fn descriptor_for(&self, slot: &ToolSlotId) -> Option<&ToolDescriptor> {
        self.descriptors
            .iter()
            .find(|descriptor| descriptor.slot() == slot)
    }

    /// Refuses one mid-loop descriptor addition.
    ///
    /// # Errors
    ///
    /// Always returns an [`AgentError`] with code
    /// [`AgentDiagnosticCode::ImmutableToolSetRevision`], because a tool-set revision
    /// is immutable once built and a mid-loop mutation would let a later round call a
    /// tool no accepted turn declared.
    pub fn add_descriptor(&mut self, descriptor: ToolDescriptor) -> Result<(), AgentError> {
        Err(AgentError::new(
            AgentDiagnosticCode::ImmutableToolSetRevision,
            format!(
                "the tool-set revision `{}` is immutable; the descriptor of `{}` was not added",
                self.id,
                descriptor.slot()
            ),
        ))
    }

    /// Admits one tool invocation against the frozen revision.
    ///
    /// # Errors
    ///
    /// Returns an [`AgentError`] with code [`AgentDiagnosticCode::UnknownToolSlot`]
    /// when the request names a slot the revision does not declare, and one with code
    /// [`AgentDiagnosticCode::SchemaMismatch`] when the request schema digest differs
    /// from the frozen descriptor. The refusal never coerces, substitutes, or resolves
    /// the request by provider behaviour.
    pub fn admit_invocation(
        &self,
        request: &ToolInvocationRequest,
    ) -> Result<&ToolDescriptor, AgentError> {
        let Some(descriptor) = self.descriptor_for(request.slot()) else {
            return Err(AgentError::new(
                AgentDiagnosticCode::UnknownToolSlot,
                format!(
                    "the request names the slot `{}` outside the frozen revision `{}`",
                    request.slot(),
                    self.id
                ),
            ));
        };
        if !descriptor.admits_schema(request.schema_digest()) {
            return Err(AgentError::new(
                AgentDiagnosticCode::SchemaMismatch,
                format!(
                    "the request of `{}` presents a schema digest other than the frozen one",
                    request.slot()
                ),
            ));
        }
        Ok(descriptor)
    }
}

/// One declared tool-invocation request of one assistant turn
/// (`GNT-25.3-assistant-turns`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolInvocationRequest {
    position: u32,
    slot: ToolSlotId,
    schema_digest: Arc<str>,
}

impl ToolInvocationRequest {
    /// Constructs one request from its declared position, slot, and schema digest.
    ///
    /// # Errors
    ///
    /// Returns an [`AgentError`] with code [`AgentDiagnosticCode::EmptyDeclaredIdentity`]
    /// when the schema digest is empty or whitespace only.
    pub fn new(position: u32, slot: ToolSlotId, schema_digest: &str) -> Result<Self, AgentError> {
        Ok(Self {
            position,
            slot,
            schema_digest: declared_text(schema_digest, AgentDeclaredInput::SchemaDigest)?,
        })
    }

    /// Returns the declared request position.
    #[must_use]
    pub const fn position(&self) -> u32 {
        self.position
    }

    /// Returns the requested tool slot.
    #[must_use]
    pub const fn slot(&self) -> &ToolSlotId {
        &self.slot
    }

    /// Returns the presented schema digest.
    #[must_use]
    pub fn schema_digest(&self) -> &str {
        &self.schema_digest
    }

    /// Derives the invocation identity of this request against one frozen revision.
    #[must_use]
    pub fn invocation_id(&self, revision: &ToolSetRevisionId) -> ToolInvocationId {
        ToolInvocationId::derive(revision, &self.slot, self.position)
    }
}

/// One final result of a canonical assistant turn (`GNT-25.3-assistant-turns`).
///
/// A final result is one declared payload and is immutable once accepted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinalResult {
    text: Arc<str>,
}

impl FinalResult {
    /// Constructs one final result from its declared payload.
    ///
    /// # Errors
    ///
    /// Returns an [`AgentError`] with code [`AgentDiagnosticCode::EmptyDeclaredIdentity`]
    /// when the payload is empty or whitespace only.
    pub fn new(text: &str) -> Result<Self, AgentError> {
        Ok(Self {
            text: declared_text(text, AgentDeclaredInput::FinalResult)?,
        })
    }

    /// Returns the declared payload.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }
}

/// One canonical assistant turn (`GNT-25.3-assistant-turns`).
///
/// The turn is exactly one of two kinds: a final result, or a nonempty tool-request
/// set in canonical request order. A mixed turn and an empty tool-request set are not
/// representable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Turn {
    kind: TurnKind,
    final_result: Option<FinalResult>,
    tool_requests: Vec<ToolInvocationRequest>,
}

impl Turn {
    /// Constructs one final-result turn.
    ///
    /// # Errors
    ///
    /// Returns an [`AgentError`] with code [`AgentDiagnosticCode::EmptyDeclaredIdentity`]
    /// when the declared payload is empty or whitespace only.
    pub fn final_text(text: &str) -> Result<Self, AgentError> {
        Ok(Self {
            kind: TurnKind::Final,
            final_result: Some(FinalResult::new(text)?),
            tool_requests: Vec::new(),
        })
    }

    /// Constructs one tool-request turn from a nonempty request set.
    ///
    /// The requests are normalized into canonical ascending request order, and one
    /// repeated position is refused.
    ///
    /// # Errors
    ///
    /// Returns an [`AgentError`] with code [`AgentDiagnosticCode::EmptyToolSet`] when
    /// no request is declared, and one with code
    /// [`AgentDiagnosticCode::DuplicateToolPosition`] when one position is declared
    /// twice.
    pub fn tools(mut requests: Vec<ToolInvocationRequest>) -> Result<Self, AgentError> {
        if requests.is_empty() {
            return Err(AgentError::new(
                AgentDiagnosticCode::EmptyToolSet,
                "a tool-request turn declares at least one request",
            ));
        }
        requests.sort_by_key(ToolInvocationRequest::position);
        for pair in requests.windows(2) {
            if pair[0].position() == pair[1].position() {
                return Err(AgentError::new(
                    AgentDiagnosticCode::DuplicateToolPosition,
                    format!(
                        "the request position {} was declared twice",
                        pair[0].position()
                    ),
                ));
            }
        }
        Ok(Self {
            kind: TurnKind::Tools,
            final_result: None,
            tool_requests: requests,
        })
    }

    /// Refuses one mixed final-and-tools turn.
    ///
    /// # Errors
    ///
    /// Always returns an [`AgentError`] with code
    /// [`AgentDiagnosticCode::MixedFinalAndTools`], because a canonical turn is exactly
    /// one of its two kinds and never a mixed one.
    pub fn mixed(
        final_text: &str,
        requests: Vec<ToolInvocationRequest>,
    ) -> Result<Self, AgentError> {
        let _ = (final_text, requests.len());
        Err(AgentError::new(
            AgentDiagnosticCode::MixedFinalAndTools,
            "a canonical turn declares either a final result or a nonempty tool-request set",
        ))
    }

    /// Returns the turn kind.
    #[must_use]
    pub const fn kind(&self) -> TurnKind {
        self.kind
    }

    /// Returns whether this turn is a final-result turn.
    #[must_use]
    pub const fn is_final(&self) -> bool {
        matches!(self.kind, TurnKind::Final)
    }

    /// Returns the final-result payload, if this turn carries one.
    #[must_use]
    pub fn final_result(&self) -> Option<&FinalResult> {
        self.final_result.as_ref()
    }

    /// Returns the tool requests in canonical request order.
    #[must_use]
    pub fn tool_requests(&self) -> &[ToolInvocationRequest] {
        &self.tool_requests
    }
}

/// One accepted canonical assistant turn (`GNT-25.3-assistant-turns`).
///
/// The accepted turn is the whole-turn validation witness of one round; it is created
/// only by [`validate_raw_response`], so no caller can accept a turn in part.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptedTurn {
    turn: Turn,
}

impl AcceptedTurn {
    /// Returns the accepted canonical turn.
    #[must_use]
    pub const fn turn(&self) -> &Turn {
        &self.turn
    }

    /// Consumes the witness and returns the accepted turn.
    #[must_use]
    pub fn into_turn(self) -> Turn {
        self.turn
    }
}

/// One decoded raw model response before whole-turn validation
/// (`GNT-25.3-assistant-turns`).
///
/// The raw response is undecoded input: it may carry a final payload, a request set,
/// a declared revision it was produced against, a model refusal, or a malformed
/// marker. Validation classifies it as exactly one [`TurnOutcome`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawResponse {
    final_text: Option<Arc<str>>,
    tool_requests: Vec<ToolInvocationRequest>,
    produced_against: Option<ToolSetRevisionId>,
    refused: bool,
    malformed: bool,
}

impl RawResponse {
    /// Constructs one raw final-result response from its declared payload.
    #[must_use]
    pub fn text(text: &str) -> Self {
        Self {
            final_text: Some(Arc::from(text)),
            tool_requests: Vec::new(),
            produced_against: None,
            refused: false,
            malformed: false,
        }
    }

    /// Constructs one raw tool-request response from its declared requests.
    #[must_use]
    pub fn tools(tool_requests: Vec<ToolInvocationRequest>) -> Self {
        Self {
            final_text: None,
            tool_requests,
            produced_against: None,
            refused: false,
            malformed: false,
        }
    }

    /// Constructs one undecoded raw response carrying a final payload and requests.
    ///
    /// A raw response is undecoded input, so this mixed shape is representable here;
    /// [`validate_raw_response`] classifies it as invalid with the mixed cause rather
    /// than coercing it into a canonical turn.
    #[must_use]
    pub fn mixed(text: &str, tool_requests: Vec<ToolInvocationRequest>) -> Self {
        Self {
            final_text: Some(Arc::from(text)),
            tool_requests,
            produced_against: None,
            refused: false,
            malformed: false,
        }
    }

    /// Constructs one well-formed model refusal.
    #[must_use]
    pub const fn refusal() -> Self {
        Self {
            final_text: None,
            tool_requests: Vec::new(),
            produced_against: None,
            refused: true,
            malformed: false,
        }
    }

    /// Constructs one malformed response marker.
    #[must_use]
    pub const fn malformed() -> Self {
        Self {
            final_text: None,
            tool_requests: Vec::new(),
            produced_against: None,
            refused: false,
            malformed: true,
        }
    }

    /// Declares the frozen revision this response was produced against.
    #[must_use]
    pub fn against(mut self, revision: &ToolSetRevision) -> Self {
        self.produced_against = Some(revision.id().clone());
        self
    }

    /// Returns the declared final payload, if any.
    #[must_use]
    pub fn final_text(&self) -> Option<&str> {
        self.final_text.as_deref()
    }

    /// Returns the declared requests in declaration order.
    #[must_use]
    pub fn tool_requests(&self) -> &[ToolInvocationRequest] {
        &self.tool_requests
    }

    /// Returns the revision this response was produced against, if declared.
    #[must_use]
    pub const fn produced_against(&self) -> Option<&ToolSetRevisionId> {
        self.produced_against.as_ref()
    }

    /// Returns whether the response is a well-formed model refusal.
    #[must_use]
    pub const fn is_refused(&self) -> bool {
        self.refused
    }

    /// Returns whether the response is malformed.
    #[must_use]
    pub const fn is_malformed(&self) -> bool {
        self.malformed
    }
}

/// One classification of one raw response (`GNT-25.3-assistant-turns`).
///
/// The outcome is exactly one of four: accepted, refused by the model, malformed, or
/// invalid with one typed cause. A refusal and a malformed response are distinct
/// outcomes and are never merged.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TurnOutcome {
    /// The whole turn was accepted.
    Accepted(AcceptedTurn),
    /// The turn was invalid with one typed cause.
    Invalid(TurnValidationCause),
    /// The response could not be decoded into a canonical turn.
    Malformed,
    /// The model well-formedly refused to produce a result.
    Refused,
}

impl TurnOutcome {
    /// Returns the accepted turn, if the outcome accepted one.
    #[must_use]
    pub const fn accepted_turn(&self) -> Option<&AcceptedTurn> {
        match self {
            Self::Accepted(turn) => Some(turn),
            Self::Invalid(_) | Self::Malformed | Self::Refused => None,
        }
    }

    /// Returns the typed invalid cause, if the outcome is invalid.
    #[must_use]
    pub const fn cause(&self) -> Option<TurnValidationCause> {
        match self {
            Self::Invalid(cause) => Some(*cause),
            Self::Accepted(_) | Self::Malformed | Self::Refused => None,
        }
    }

    /// Returns whether the outcome accepted the turn.
    #[must_use]
    pub const fn is_accepted(&self) -> bool {
        matches!(self, Self::Accepted(_))
    }

    /// Returns the exact portable outcome spelling.
    #[must_use]
    pub const fn wire_name(&self) -> &'static str {
        match self {
            Self::Accepted(_) => "accepted",
            Self::Invalid(_) => "invalid",
            Self::Malformed => "malformed",
            Self::Refused => "refused",
        }
    }
}

/// Validates one raw response whole against one frozen tool-set revision
/// (`GNT-25.3-assistant-turns`).
///
/// The classification is total: one raw response receives exactly one
/// [`TurnOutcome`], and no request is dispatched, recorded, or reserved before the
/// whole turn is accepted. Malformed wins over refusal when both markers are set,
/// because an undecodable response cannot carry a well-formed refusal.
#[must_use]
pub fn validate_raw_response(raw: &RawResponse, revision: &ToolSetRevision) -> TurnOutcome {
    if raw.is_malformed() {
        return TurnOutcome::Malformed;
    }
    if raw.is_refused() {
        return TurnOutcome::Refused;
    }
    if let Some(produced_against) = raw.produced_against()
        && produced_against != revision.id()
    {
        return TurnOutcome::Invalid(TurnValidationCause::StaleToolSetRevision);
    }
    if let Some(text) = raw.final_text() {
        if !raw.tool_requests().is_empty() {
            return TurnOutcome::Invalid(TurnValidationCause::MixedFinalAndTools);
        }
        if text.trim().is_empty() {
            return TurnOutcome::Invalid(TurnValidationCause::EmptyFinalResult);
        }
        return match Turn::final_text(text) {
            Ok(turn) => TurnOutcome::Accepted(AcceptedTurn { turn }),
            Err(_) => TurnOutcome::Invalid(TurnValidationCause::EmptyFinalResult),
        };
    }
    if raw.tool_requests().is_empty() {
        return TurnOutcome::Invalid(TurnValidationCause::EmptyResponse);
    }
    let mut seen_positions = BTreeSet::new();
    let mut seen_slots = BTreeSet::new();
    let mut ordered = raw.tool_requests().to_vec();
    ordered.sort_by_key(ToolInvocationRequest::position);
    for (index, request) in ordered.iter().enumerate() {
        if !seen_positions.insert(request.position()) {
            return TurnOutcome::Invalid(TurnValidationCause::DuplicateToolPosition);
        }
        if usize::try_from(request.position()).ok() != Some(index) {
            return TurnOutcome::Invalid(TurnValidationCause::PositionOutsideFrozenOrder);
        }
        if !seen_slots.insert(request.slot().clone()) {
            return TurnOutcome::Invalid(TurnValidationCause::DuplicateToolSlot);
        }
        let Some(descriptor) = revision.descriptor_for(request.slot()) else {
            return TurnOutcome::Invalid(TurnValidationCause::UnknownToolSlot);
        };
        if !descriptor.admits_schema(request.schema_digest()) {
            return TurnOutcome::Invalid(TurnValidationCause::SchemaMismatch);
        }
    }
    match Turn::tools(raw.tool_requests().to_vec()) {
        Ok(turn) => TurnOutcome::Accepted(AcceptedTurn { turn }),
        Err(_) => TurnOutcome::Invalid(TurnValidationCause::DuplicateToolPosition),
    }
}

/// One affine rejected prefix of one invalid turn (`GNT-25.4-turn-validation-and-repair`).
///
/// The prefix holds the requests the rejected turn named, in declaration order. It is
/// affine: it derives neither `Clone` nor `Copy`, it is produced once and consumed
/// once by one repair attempt, and it never dispatches.
#[derive(Debug, Eq, PartialEq)]
pub struct RejectedPrefix {
    requests: Vec<ToolInvocationRequest>,
    cause: TurnValidationCause,
}

impl RejectedPrefix {
    /// Records the rejected prefix of one raw response.
    #[must_use]
    pub fn of(raw: &RawResponse, cause: TurnValidationCause) -> Self {
        Self {
            requests: raw.tool_requests().to_vec(),
            cause,
        }
    }

    /// Returns the rejected requests in declaration order.
    #[must_use]
    pub fn requests(&self) -> &[ToolInvocationRequest] {
        &self.requests
    }

    /// Returns the typed cause that rejected the turn.
    #[must_use]
    pub const fn cause(&self) -> TurnValidationCause {
        self.cause
    }

    /// Returns the rejected request count.
    #[must_use]
    pub fn request_count(&self) -> usize {
        self.requests.len()
    }

    /// Refuses one direct dispatch of the rejected prefix.
    ///
    /// # Errors
    ///
    /// Always returns an [`AgentError`] with code
    /// [`AgentDiagnosticCode::PrefixDispatchRefused`], because the only admitted
    /// consumer of a rejected prefix is one bounded repair attempt.
    pub fn admit_dispatch(&self) -> Result<(), AgentError> {
        Err(AgentError::new(
            AgentDiagnosticCode::PrefixDispatchRefused,
            format!(
                "the rejected prefix of `{}` ({} request(s)) never dispatches",
                self.cause.wire_name(),
                self.requests.len()
            ),
        ))
    }
}

/// One finite repair policy (`GNT-25.4-turn-validation-and-repair`).
///
/// The policy declares a finite positive attempt bound; a zero bound is refused,
/// because it could not admit even one bounded repair.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RepairPolicy {
    max_attempts: u32,
}

impl RepairPolicy {
    /// Constructs one repair policy with a finite positive attempt bound.
    ///
    /// # Errors
    ///
    /// Returns an [`AgentError`] with code [`AgentDiagnosticCode::ZeroRepairBound`]
    /// when the declared bound is zero.
    pub fn new(max_attempts: u32) -> Result<Self, AgentError> {
        if max_attempts == 0 {
            return Err(AgentError::new(
                AgentDiagnosticCode::ZeroRepairBound,
                "a repair policy declares a finite positive attempt bound",
            ));
        }
        Ok(Self { max_attempts })
    }

    /// Returns the declared finite attempt bound.
    #[must_use]
    pub const fn max_attempts(&self) -> u32 {
        self.max_attempts
    }
}

/// One affine admitted repair permit (`GNT-25.4-turn-validation-and-repair`).
///
/// The permit is affine and consumes exactly one unit of the declared bound; it is
/// consumed by [`Self::consume`].
#[derive(Debug, Eq, PartialEq)]
pub struct RepairPermit {
    attempt: u32,
    max_attempts: u32,
}

impl RepairPermit {
    /// Returns the one-based attempt number of this permit.
    #[must_use]
    pub const fn attempt(&self) -> u32 {
        self.attempt
    }

    /// Returns the finite bound this permit was admitted under.
    #[must_use]
    pub const fn max_attempts(&self) -> u32 {
        self.max_attempts
    }

    /// Consumes this permit with one rejected prefix into one repair attempt.
    #[must_use]
    pub fn consume(self, prefix: RejectedPrefix) -> RepairAttempt {
        RepairAttempt {
            attempt: self.attempt,
            prefix,
        }
    }
}

/// One affine repair attempt over one rejected prefix
/// (`GNT-25.4-turn-validation-and-repair`).
#[derive(Debug, Eq, PartialEq)]
pub struct RepairAttempt {
    attempt: u32,
    prefix: RejectedPrefix,
}

impl RepairAttempt {
    /// Returns the one-based attempt number of this attempt.
    #[must_use]
    pub const fn attempt(&self) -> u32 {
        self.attempt
    }

    /// Returns the rejected prefix this attempt consumes.
    #[must_use]
    pub const fn prefix(&self) -> &RejectedPrefix {
        &self.prefix
    }

    /// Validates one repaired raw response whole and consumes the attempt.
    ///
    /// The repaired response is a new whole raw response: the rejected prefix is
    /// never dispatched, and the outcome is [`RepairOutcome::Repaired`] only when the
    /// new response passes whole-turn validation.
    #[must_use]
    pub fn validate_repaired(
        self,
        repaired: &RawResponse,
        revision: &ToolSetRevision,
    ) -> RepairOutcome {
        match validate_raw_response(repaired, revision) {
            TurnOutcome::Accepted(_) => RepairOutcome::Repaired,
            TurnOutcome::Invalid(_) | TurnOutcome::Malformed | TurnOutcome::Refused => {
                RepairOutcome::Refused
            }
        }
    }
}

/// One finite repair budget (`GNT-25.4-turn-validation-and-repair`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepairBudget {
    policy: RepairPolicy,
    used: u32,
}

impl RepairBudget {
    /// Constructs one empty budget under a declared policy.
    #[must_use]
    pub const fn new(policy: RepairPolicy) -> Self {
        Self { policy, used: 0 }
    }

    /// Returns the consumed attempt count.
    #[must_use]
    pub const fn used(&self) -> u32 {
        self.used
    }

    /// Returns the remaining attempt count.
    #[must_use]
    pub const fn remaining(&self) -> u32 {
        self.policy.max_attempts() - self.used
    }

    /// Admits one repair attempt and consumes one unit of the finite bound.
    ///
    /// # Errors
    ///
    /// Returns an [`AgentError`] with code [`AgentDiagnosticCode::RepairBoundExhausted`]
    /// when the finite bound is exhausted, so no repair retries unboundedly.
    pub fn admit_attempt(&mut self) -> Result<RepairPermit, AgentError> {
        if self.used >= self.policy.max_attempts() {
            return Err(AgentError::new(
                AgentDiagnosticCode::RepairBoundExhausted,
                format!(
                    "the declared repair bound {} is exhausted",
                    self.policy.max_attempts()
                ),
            ));
        }
        self.used += 1;
        Ok(RepairPermit {
            attempt: self.used,
            max_attempts: self.policy.max_attempts(),
        })
    }
}

/// Classifies one original turn outcome before any repair attempt
/// (`GNT-25.4-turn-validation-and-repair`).
#[must_use]
pub fn classify_original_turn(outcome: &TurnOutcome) -> RepairOutcome {
    match outcome {
        TurnOutcome::Accepted(_) => RepairOutcome::Accepted,
        TurnOutcome::Invalid(_) | TurnOutcome::Malformed | TurnOutcome::Refused => {
            RepairOutcome::Refused
        }
    }
}

/// Repairs one rejected prefix under a finite budget and validates the repaired
/// whole response (`GNT-25.4-turn-validation-and-repair`).
///
/// The function admits one attempt when the bound permits, consumes the prefix into
/// that attempt, and validates the new whole raw response. When the bound is
/// exhausted the outcome is [`RepairOutcome::Exhausted`] and the prefix never
/// dispatches.
#[must_use]
pub fn repair_turn(
    prefix: RejectedPrefix,
    budget: &mut RepairBudget,
    repaired: &RawResponse,
    revision: &ToolSetRevision,
) -> RepairOutcome {
    match budget.admit_attempt() {
        Ok(permit) => permit.consume(prefix).validate_repaired(repaired, revision),
        Err(_) => RepairOutcome::Exhausted,
    }
}

/// One state of the round lifecycle (`GNT-25.5-round-identity-and-durable-cuts`).
///
/// The state vocabulary is closed and the admitted transitions form a finite table:
/// [`Self::AwaitingRaw`] validates into [`Self::Validating`]; a repair returns
/// [`Self::Validating`] to [`Self::AwaitingRaw`]; a whole validated turn is
/// [`Self::Accepted`]; an accepted tool turn dispatches into [`Self::Dispatching`];
/// dispatch settles into [`Self::Settled`]; and an accepted final turn or a settled
/// tool turn completes into [`Self::Final`]. No other transition is admitted.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RoundState {
    /// One whole validated turn was accepted.
    Accepted,
    /// The round awaits one raw response.
    AwaitingRaw,
    /// An accepted tool turn is dispatching children.
    Dispatching,
    /// The round committed its final result.
    Final,
    /// The tool-request set settled.
    Settled,
    /// One raw response is under whole-turn validation.
    Validating,
}

impl RoundState {
    /// Every member of the closed vocabulary, in canonical wire-name order.
    pub const ALL: [Self; 6] = [
        Self::Accepted,
        Self::AwaitingRaw,
        Self::Dispatching,
        Self::Final,
        Self::Settled,
        Self::Validating,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::AwaitingRaw => "awaiting-raw",
            Self::Dispatching => "dispatching",
            Self::Final => "final",
            Self::Settled => "settled",
            Self::Validating => "validating",
        }
    }

    /// Returns the same exact portable spelling as [`Self::wire_name`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.wire_name()
    }

    /// Strictly decodes one exact portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.wire_name() == value)
    }

    /// Returns whether one transition is admitted.
    #[must_use]
    pub const fn admits_transition(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::AwaitingRaw, Self::Validating)
                | (Self::Validating, Self::Accepted)
                | (Self::Validating, Self::AwaitingRaw)
                | (Self::Accepted, Self::Dispatching)
                | (Self::Accepted, Self::Final)
                | (Self::Dispatching, Self::Settled)
                | (Self::Settled, Self::Final)
        )
    }

    /// Advances to one admitted next state.
    ///
    /// # Errors
    ///
    /// Returns an [`AgentError`] with code [`AgentDiagnosticCode::IllegalRoundTransition`]
    /// when the transition is not in the admitted table.
    pub fn advance(self, next: Self) -> Result<Self, AgentError> {
        if self.admits_transition(next) {
            return Ok(next);
        }
        Err(AgentError::new(
            AgentDiagnosticCode::IllegalRoundTransition,
            format!(
                "the round transition from `{}` to `{}` is not admitted",
                self.wire_name(),
                next.wire_name()
            ),
        ))
    }
}

/// One ordered durable cut of one round (`GNT-25.5-round-identity-and-durable-cuts`).
///
/// The cut chain is exactly raw, accepted, tool-result, and final, in that order.
/// [`Self::ALL`] is cut order, not wire-name order, because the chain is ordered.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DurableAgentCut {
    /// The presented raw response is committed.
    Raw,
    /// The one accepted turn is committed.
    Accepted,
    /// The settled tool-result vector is committed.
    ToolResults,
    /// The final result is committed.
    Final,
}

impl DurableAgentCut {
    /// Every member of the chain, in cut order.
    pub const ALL: [Self; 4] = [Self::Raw, Self::Accepted, Self::ToolResults, Self::Final];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Raw => "raw",
            Self::Accepted => "accepted",
            Self::ToolResults => "tool-result",
            Self::Final => "final",
        }
    }

    /// Returns the same exact portable spelling as [`Self::wire_name`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.wire_name()
    }

    /// Strictly decodes one exact portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.wire_name() == value)
    }

    /// Returns the declared rank of this cut in the chain.
    #[must_use]
    pub const fn rank(self) -> u8 {
        match self {
            Self::Raw => 0,
            Self::Accepted => 1,
            Self::ToolResults => 2,
            Self::Final => 3,
        }
    }

    /// Advances the committed cut by one admissible step.
    ///
    /// Advancing to the same cut is stuttering and commits nothing twice. A cut that
    /// would skip an uncommitted cut and a cut that would move backwards are each
    /// refused rather than applied.
    ///
    /// # Errors
    ///
    /// Returns an [`AgentError`] with code [`AgentDiagnosticCode::CutSkip`] for a skip
    /// and one with code [`AgentDiagnosticCode::CutRegression`] for a regression.
    pub fn advance(self, next: Self) -> Result<Self, AgentError> {
        if next == self {
            return Ok(self);
        }
        if next.rank() < self.rank() {
            return Err(AgentError::new(
                AgentDiagnosticCode::CutRegression,
                format!(
                    "the cut `{}` would move backwards from `{}`",
                    next.wire_name(),
                    self.wire_name()
                ),
            ));
        }
        if next.rank() > self.rank() + 1 {
            return Err(AgentError::new(
                AgentDiagnosticCode::CutSkip,
                format!(
                    "the cut `{}` would skip an uncommitted cut after `{}`",
                    next.wire_name(),
                    self.wire_name()
                ),
            ));
        }
        Ok(next)
    }

    /// Returns the clause anchor that owns this cut.
    #[must_use]
    pub const fn requirement(self) -> &'static str {
        "GNT-25.5-round-identity-and-durable-cuts"
    }
}

/// One crash-cut classification of one committed round
/// (`GNT-25.5-round-identity-and-durable-cuts`).
///
/// The classification is decided from the committed cut alone and names the one
/// resume decision recovery applies.
#[allow(clippy::enum_variant_names)] // each member names the committed cut it classifies
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AgentCrashCutClassification {
    /// The accepted cut is committed.
    AcceptedCommitted,
    /// The final cut is committed and immutable.
    FinalCommitted,
    /// The raw cut is committed.
    RawCommitted,
    /// The tool-result cut is committed.
    ToolResultsCommitted,
}

impl AgentCrashCutClassification {
    /// Every member of the closed vocabulary, in canonical wire-name order.
    pub const ALL: [Self; 4] = [
        Self::AcceptedCommitted,
        Self::FinalCommitted,
        Self::RawCommitted,
        Self::ToolResultsCommitted,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::AcceptedCommitted => "accepted-committed",
            Self::FinalCommitted => "final-committed",
            Self::RawCommitted => "raw-committed",
            Self::ToolResultsCommitted => "tool-results-committed",
        }
    }

    /// Returns the same exact portable spelling as [`Self::wire_name`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.wire_name()
    }

    /// Strictly decodes one exact portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.wire_name() == value)
    }

    /// Classifies one committed cut.
    #[must_use]
    pub const fn of(cut: DurableAgentCut) -> Self {
        match cut {
            DurableAgentCut::Raw => Self::RawCommitted,
            DurableAgentCut::Accepted => Self::AcceptedCommitted,
            DurableAgentCut::ToolResults => Self::ToolResultsCommitted,
            DurableAgentCut::Final => Self::FinalCommitted,
        }
    }

    /// Returns the one resume decision this classification applies.
    #[must_use]
    pub const fn resume_decision(self) -> AgentRecoveryDecision {
        match self {
            Self::RawCommitted => AgentRecoveryDecision::RawValidation,
            Self::AcceptedCommitted => AgentRecoveryDecision::AcceptedDispatch { next_position: 0 },
            Self::ToolResultsCommitted => AgentRecoveryDecision::FinalAssembly,
            Self::FinalCommitted => AgentRecoveryDecision::CommittedFinal,
        }
    }
}

/// One resume decision of one committed round (`GNT-25.5-round-identity-and-durable-cuts`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentRecoveryDecision {
    /// Resume child dispatch at the first unsettled request position.
    AcceptedDispatch {
        /// The first unsettled request position of the committed accepted turn.
        next_position: u32,
    },
    /// Return the committed final result unchanged.
    CommittedFinal,
    /// Assemble the final result from the committed tool-result vector.
    FinalAssembly,
    /// Revalidate the committed raw response whole.
    RawValidation,
}

impl AgentRecoveryDecision {
    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::AcceptedDispatch { .. } => "accepted-dispatch",
            Self::CommittedFinal => "committed-final",
            Self::FinalAssembly => "final-assembly",
            Self::RawValidation => "raw-validation",
        }
    }

    /// Returns the first unsettled request position, if this decision dispatches.
    #[must_use]
    pub const fn next_position(self) -> Option<u32> {
        match self {
            Self::AcceptedDispatch { next_position } => Some(next_position),
            Self::CommittedFinal | Self::FinalAssembly | Self::RawValidation => None,
        }
    }
}

/// One domain-separated witness of one presented raw response
/// (`GNT-25.5-round-identity-and-durable-cuts`).
///
/// The witness commits the declared shape of the presented raw response at the raw cut
/// without storing the response itself, so recovery validates the same raw response and
/// refuses a different one.
#[derive(Clone, Debug, Eq, PartialEq)]
struct RawResponseWitness {
    digest: Arc<str>,
}

impl RawResponseWitness {
    /// Derives the witness of one presented raw response.
    fn of(raw: &RawResponse) -> Self {
        let mut fields: Vec<Vec<u8>> = vec![
            vec![u8::from(raw.is_malformed())],
            vec![u8::from(raw.is_refused())],
        ];
        match raw.final_text() {
            Some(text) => {
                fields.push(vec![1]);
                fields.push(text.as_bytes().to_vec());
            }
            None => {
                fields.push(vec![0]);
                fields.push(Vec::new());
            }
        }
        match raw.produced_against() {
            Some(revision) => {
                fields.push(vec![1]);
                fields.push(revision.as_str().as_bytes().to_vec());
            }
            None => {
                fields.push(vec![0]);
                fields.push(Vec::new());
            }
        }
        fields.push(
            u64::try_from(raw.tool_requests().len())
                .unwrap_or(u64::MAX)
                .to_be_bytes()
                .to_vec(),
        );
        for request in raw.tool_requests() {
            fields.push(request.position().to_be_bytes().to_vec());
            fields.push(request.slot().as_str().as_bytes().to_vec());
            fields.push(request.schema_digest().as_bytes().to_vec());
        }
        let refs: Vec<&[u8]> = fields.iter().map(Vec::as_slice).collect();
        let digest = digest_fields(RAW_RESPONSE_WITNESS_DOMAIN, &refs);
        Self {
            digest: Arc::from(encode_hex(&digest)),
        }
    }
}

/// One durable round record of the four-cut chain
/// (`GNT-25.5-round-identity-and-durable-cuts`).
///
/// The record holds one round identity, one committed cut, and the accepted turn,
/// settled vector, and final result committed so far. Recovery resumes from the
/// committed cut alone and never repeats an accepted turn, a settled position, or a
/// final result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableAgentRecord {
    round: RoundId,
    raw: RawResponseWitness,
    cut: DurableAgentCut,
    accepted: Option<AcceptedTurn>,
    settled: Option<ToolResultVector>,
    final_result: Option<FinalResult>,
}

impl DurableAgentRecord {
    /// Opens one round record with its raw cut committed to one presented raw response.
    ///
    /// The raw cut records a domain-separated witness of the presented raw response, so
    /// recovery validates the same raw response and refuses a different one.
    #[must_use]
    pub fn open(round: RoundId, raw: &RawResponse) -> Self {
        Self {
            round,
            raw: RawResponseWitness::of(raw),
            cut: DurableAgentCut::Raw,
            accepted: None,
            settled: None,
            final_result: None,
        }
    }

    /// Returns the stable round identity.
    #[must_use]
    pub const fn round(&self) -> &RoundId {
        &self.round
    }

    /// Returns the committed cut.
    #[must_use]
    pub const fn cut(&self) -> DurableAgentCut {
        self.cut
    }

    /// Classifies the committed cut for crash recovery.
    #[must_use]
    pub const fn crash_cut(&self) -> AgentCrashCutClassification {
        AgentCrashCutClassification::of(self.cut)
    }

    /// Returns the committed accepted turn, if the accepted cut is committed.
    #[must_use]
    pub const fn accepted_turn(&self) -> Option<&AcceptedTurn> {
        self.accepted.as_ref()
    }

    /// Returns the committed tool-result vector, if the tool-result cut is committed.
    #[must_use]
    pub const fn settled_results(&self) -> Option<&ToolResultVector> {
        self.settled.as_ref()
    }

    /// Returns the committed final result, if the final cut is committed.
    #[must_use]
    pub const fn final_result(&self) -> Option<&FinalResult> {
        self.final_result.as_ref()
    }

    /// Commits the accepted cut with one whole accepted turn.
    ///
    /// # Errors
    ///
    /// Returns an [`AgentError`] with code [`AgentDiagnosticCode::CutAlreadyCommitted`]
    /// when the accepted cut is already committed, because an accepted turn is
    /// committed once and never repeated.
    pub fn commit_accepted(&mut self, turn: AcceptedTurn) -> Result<(), AgentError> {
        if self.cut != DurableAgentCut::Raw {
            return Err(AgentError::new(
                AgentDiagnosticCode::CutAlreadyCommitted,
                format!(
                    "the round `{}` already committed the `{}` cut",
                    self.round,
                    self.cut.wire_name()
                ),
            ));
        }
        self.cut = self.cut.advance(DurableAgentCut::Accepted)?;
        self.accepted = Some(turn);
        Ok(())
    }

    /// Commits the tool-result cut with one settled tool-result vector.
    ///
    /// The settlement must cover exactly the request positions of the committed
    /// accepted turn: an omitted position, a duplicate, and a position outside the
    /// accepted request set are each refused before any cut advances, so a partially
    /// settled turn is never committed as a whole one.
    ///
    /// # Errors
    ///
    /// Returns an [`AgentError`] with code [`AgentDiagnosticCode::IllegalRoundTransition`]
    /// when the accepted cut is not committed, because a settlement is committed only
    /// over a committed accepted turn, one with code
    /// [`AgentDiagnosticCode::UnknownToolPosition`] when a settled position is not a
    /// request position of the committed accepted turn, and one with code
    /// [`AgentDiagnosticCode::MissingToolResult`] when a request position of the
    /// committed accepted turn is not settled.
    pub fn commit_tool_results(&mut self, vector: ToolResultVector) -> Result<(), AgentError> {
        if self.cut != DurableAgentCut::Accepted {
            return Err(AgentError::new(
                AgentDiagnosticCode::IllegalRoundTransition,
                format!(
                    "the round `{}` cannot commit the tool-result cut from the `{}` cut",
                    self.round,
                    self.cut.wire_name()
                ),
            ));
        }
        let Some(accepted) = &self.accepted else {
            return Err(AgentError::new(
                AgentDiagnosticCode::IllegalRoundTransition,
                format!(
                    "the round `{}` cannot commit the tool-result cut without a committed accepted turn",
                    self.round
                ),
            ));
        };
        let expected: BTreeSet<u32> = accepted
            .turn()
            .tool_requests()
            .iter()
            .map(ToolInvocationRequest::position)
            .collect();
        let settled = vector.positions();
        for position in &settled {
            if !expected.contains(position) {
                return Err(AgentError::new(
                    AgentDiagnosticCode::UnknownToolPosition,
                    format!(
                        "the position {position} is not a request position of the committed accepted turn of `{}`",
                        self.round
                    ),
                ));
            }
        }
        if settled.len() != expected.len() {
            return Err(AgentError::new(
                AgentDiagnosticCode::MissingToolResult,
                format!(
                    "{} of the {} accepted request positions of `{}` were settled",
                    settled.len(),
                    expected.len(),
                    self.round
                ),
            ));
        }
        self.cut = self.cut.advance(DurableAgentCut::ToolResults)?;
        self.settled = Some(vector);
        Ok(())
    }

    /// Commits the final cut with one final result.
    ///
    /// A final-result accepted turn commits its empty tool-result settlement before
    /// the final cut, so the four-cut chain stays strict; a tool turn commits the
    /// final cut from its committed tool-result cut.
    ///
    /// # Errors
    ///
    /// Returns an [`AgentError`] with code [`AgentDiagnosticCode::IllegalRoundTransition`]
    /// when neither the accepted final turn nor the committed tool-result vector is in
    /// place, and one with code [`AgentDiagnosticCode::CutAlreadyCommitted`] when the
    /// final cut is already committed.
    pub fn commit_final(&mut self, result: FinalResult) -> Result<(), AgentError> {
        if self.cut == DurableAgentCut::Final {
            return Err(AgentError::new(
                AgentDiagnosticCode::CutAlreadyCommitted,
                format!("the round `{}` already committed the final cut", self.round),
            ));
        }
        if self.cut == DurableAgentCut::Accepted {
            let is_final_turn = self
                .accepted
                .as_ref()
                .is_some_and(|turn| turn.turn().is_final());
            if !is_final_turn {
                return Err(AgentError::new(
                    AgentDiagnosticCode::IllegalRoundTransition,
                    format!(
                        "the round `{}` cannot commit the final cut from the `{}` cut",
                        self.round,
                        self.cut.wire_name()
                    ),
                ));
            }
            let empty_settlement = ToolResultVector::settle(&[], 0)?;
            self.cut = self.cut.advance(DurableAgentCut::ToolResults)?;
            self.settled = Some(empty_settlement);
        } else if self.cut != DurableAgentCut::ToolResults {
            return Err(AgentError::new(
                AgentDiagnosticCode::IllegalRoundTransition,
                format!(
                    "the round `{}` cannot commit the final cut from the `{}` cut",
                    self.round,
                    self.cut.wire_name()
                ),
            ));
        }
        self.cut = self.cut.advance(DurableAgentCut::Final)?;
        self.final_result = Some(result);
        Ok(())
    }

    /// Verifies one presented turn against the committed accepted turn.
    ///
    /// # Errors
    ///
    /// Returns an [`AgentError`] with code [`AgentDiagnosticCode::CommittedValueDiffers`]
    /// when the presented turn differs from the committed one, and one with code
    /// [`AgentDiagnosticCode::CutNotCommitted`] when the accepted cut is not committed.
    pub fn verify_presented_turn(&self, presented: &Turn) -> Result<(), AgentError> {
        match &self.accepted {
            Some(committed) if committed.turn() == presented => Ok(()),
            Some(_) => Err(AgentError::new(
                AgentDiagnosticCode::CommittedValueDiffers,
                format!(
                    "the presented turn of `{}` differs from the committed turn",
                    self.round
                ),
            )),
            None => Err(AgentError::new(
                AgentDiagnosticCode::CutNotCommitted,
                format!("the accepted cut of `{}` is not committed", self.round),
            )),
        }
    }

    /// Verifies one presented final result against the committed final result.
    ///
    /// # Errors
    ///
    /// Returns an [`AgentError`] with code [`AgentDiagnosticCode::CommittedValueDiffers`]
    /// when the presented result differs from the committed one, and one with code
    /// [`AgentDiagnosticCode::CutNotCommitted`] when the final cut is not committed.
    pub fn verify_presented_final(&self, presented: &FinalResult) -> Result<(), AgentError> {
        match &self.final_result {
            Some(committed) if committed == presented => Ok(()),
            Some(_) => Err(AgentError::new(
                AgentDiagnosticCode::CommittedValueDiffers,
                format!(
                    "the presented final result of `{}` differs from the committed result",
                    self.round
                ),
            )),
            None => Err(AgentError::new(
                AgentDiagnosticCode::CutNotCommitted,
                format!("the final cut of `{}` is not committed", self.round),
            )),
        }
    }

    /// Verifies one presented raw response against the committed raw cut.
    ///
    /// # Errors
    ///
    /// Returns an [`AgentError`] with code [`AgentDiagnosticCode::CommittedValueDiffers`]
    /// when the presented raw response differs from the one committed at the raw cut, so
    /// recovery never resumes from a raw response other than the committed one.
    pub fn verify_presented_raw(&self, presented: &RawResponse) -> Result<(), AgentError> {
        if RawResponseWitness::of(presented) == self.raw {
            return Ok(());
        }
        Err(AgentError::new(
            AgentDiagnosticCode::CommittedValueDiffers,
            format!(
                "the presented raw response of `{}` differs from the committed raw response",
                self.round
            ),
        ))
    }

    /// Admits one nonsemantic progress observation over this round's committed values.
    ///
    /// # Errors
    ///
    /// Returns an [`AgentError`] with code
    /// [`AgentDiagnosticCode::ProgressSettlementClaimRefused`] when the observation
    /// claims to settle this round's accepted turn or its tool results, because a
    /// progress observation cannot settle an accepted turn, a tool result, or a cut.
    pub fn admit_progress(
        &self,
        claims_accepted_turn: bool,
        claims_tool_result: bool,
    ) -> Result<ProgressSignal, AgentError> {
        ProgressSignal::admit(claims_accepted_turn, claims_tool_result)
    }

    /// Decides what recovery resumes from the committed cut alone.
    #[must_use]
    pub fn resume(&self) -> AgentRecoveryDecision {
        match self.cut {
            DurableAgentCut::Raw => AgentRecoveryDecision::RawValidation,
            DurableAgentCut::Accepted => AgentRecoveryDecision::AcceptedDispatch {
                next_position: self.next_unsettled_position(),
            },
            DurableAgentCut::ToolResults => AgentRecoveryDecision::FinalAssembly,
            DurableAgentCut::Final => AgentRecoveryDecision::CommittedFinal,
        }
    }

    /// Returns the first request position of the accepted turn that is not settled.
    fn next_unsettled_position(&self) -> u32 {
        let settled = self
            .settled
            .as_ref()
            .map(ToolResultVector::positions)
            .unwrap_or_default();
        let Some(accepted) = &self.accepted else {
            return 0;
        };
        for request in accepted.turn().tool_requests() {
            if !settled.contains(&request.position()) {
                return request.position();
            }
        }
        u32::try_from(accepted.turn().tool_requests().len()).unwrap_or(u32::MAX)
    }
}

/// One derived child session of one open parent reservation
/// (`GNT-25.8-sessions-and-child-sessions`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChildSession {
    id: ChildSessionId,
    parent: SessionId,
    ordinal: u32,
}

impl ChildSession {
    /// Returns the stable child-session identity.
    #[must_use]
    pub const fn id(&self) -> &ChildSessionId {
        &self.id
    }

    /// Returns the parent session identity.
    #[must_use]
    pub const fn parent(&self) -> &SessionId {
        &self.parent
    }

    /// Returns the declared child ordinal.
    #[must_use]
    pub const fn ordinal(&self) -> u32 {
        self.ordinal
    }
}

/// One open parent transcript reservation
/// (`GNT-25.8-sessions-and-child-sessions`).
///
/// The reservation is held while one round has open tool requests. It derives stable
/// child sessions and refuses a direct reentry into the reserved parent transcript.
/// The registry is the single authority for its state: derivation and release both
/// consult the registry, so an outstanding handle can never derive a child after the
/// registry released its reservation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParentSessionReservation {
    parent: SessionId,
    round: RoundId,
    open_tool_requests: u32,
}

impl ParentSessionReservation {
    /// Returns the reserved parent session identity.
    #[must_use]
    pub const fn parent(&self) -> &SessionId {
        &self.parent
    }

    /// Returns the round that holds the reservation.
    #[must_use]
    pub const fn round(&self) -> &RoundId {
        &self.round
    }

    /// Returns the open tool-request count the reservation was admitted with.
    #[must_use]
    pub const fn open_tool_requests(&self) -> u32 {
        self.open_tool_requests
    }

    /// Returns whether the registry no longer holds this reservation.
    #[must_use]
    pub fn is_released(&self, registry: &SessionReservations) -> bool {
        !registry.holds(&self.parent, &self.round)
    }

    /// Derives one stable child session from this reservation.
    ///
    /// A repeated derivation of the same ordinal returns the same child identity, and
    /// another ordinal returns a distinct child. The registry is the single authority:
    /// a child is derived only while the registry still holds this round's reservation.
    ///
    /// # Errors
    ///
    /// Returns an [`AgentError`] with code [`AgentDiagnosticCode::ReservationReleased`]
    /// when the registry no longer holds this round's reservation.
    pub fn derive_child(
        &self,
        registry: &SessionReservations,
        ordinal: u32,
    ) -> Result<ChildSession, AgentError> {
        if !registry.holds(&self.parent, &self.round) {
            return Err(AgentError::new(
                AgentDiagnosticCode::ReservationReleased,
                format!(
                    "the registry does not hold the reservation of `{}` for round `{}`, which derives no child",
                    self.parent, self.round
                ),
            ));
        }
        Ok(ChildSession {
            id: ChildSessionId::derive(&self.parent, ordinal),
            parent: self.parent.clone(),
            ordinal,
        })
    }

    /// Refuses one direct reentry into the reserved parent transcript.
    ///
    /// # Errors
    ///
    /// Always returns an [`AgentError`] with code
    /// [`AgentDiagnosticCode::ParentReentryRefused`] while the reservation is held.
    pub fn reenter_parent(&self) -> Result<(), AgentError> {
        Err(AgentError::new(
            AgentDiagnosticCode::ParentReentryRefused,
            format!(
                "the transcript of `{}` is reserved by the round `{}` and is not re-entered",
                self.parent, self.round
            ),
        ))
    }

    /// Decides the session directive of one requested entry.
    #[must_use]
    pub const fn directive(&self, reentering_parent: bool) -> SessionDirective {
        if reentering_parent {
            SessionDirective::RefuseReentry
        } else {
            SessionDirective::DeriveChild
        }
    }

    /// Releases this reservation in the registry.
    ///
    /// # Errors
    ///
    /// Returns an [`AgentError`] with code [`AgentDiagnosticCode::ReservationReleased`]
    /// when the registry no longer holds this round's reservation, because a release
    /// happens once and the registry is the single authority.
    pub fn release(&self, registry: &mut SessionReservations) -> Result<(), AgentError> {
        registry.release_round(&self.parent, &self.round)
    }
}

/// One registry of held parent transcript reservations
/// (`GNT-25.8-sessions-and-child-sessions`).
///
/// The registry holds at most one reservation per parent transcript, refuses a second
/// reservation, refuses a reservation with no open tool request, and decides the
/// session directive of one requested entry.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SessionReservations {
    held: BTreeMap<SessionId, RoundId>,
}

impl SessionReservations {
    /// Constructs one empty reservation registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Reserves one parent transcript for one round with open tool requests.
    ///
    /// # Errors
    ///
    /// Returns an [`AgentError`] with code [`AgentDiagnosticCode::NoOpenToolRequests`]
    /// when no tool request is open, and one with code
    /// [`AgentDiagnosticCode::SecondReservation`] when the parent transcript already
    /// holds a reservation.
    pub fn reserve(
        &mut self,
        parent: &SessionId,
        round: &RoundId,
        open_tool_requests: u32,
    ) -> Result<ParentSessionReservation, AgentError> {
        if open_tool_requests == 0 {
            return Err(AgentError::new(
                AgentDiagnosticCode::NoOpenToolRequests,
                format!(
                    "the transcript of `{parent}` is reserved only while a tool request is open"
                ),
            ));
        }
        if self.held.contains_key(parent) {
            return Err(AgentError::new(
                AgentDiagnosticCode::SecondReservation,
                format!("the transcript of `{parent}` already holds a reservation"),
            ));
        }
        self.held.insert(parent.clone(), round.clone());
        Ok(ParentSessionReservation {
            parent: parent.clone(),
            round: round.clone(),
            open_tool_requests,
        })
    }

    /// Returns whether one parent transcript currently holds a reservation.
    #[must_use]
    pub fn is_reserved(&self, parent: &SessionId) -> bool {
        self.held.contains_key(parent)
    }

    /// Returns whether one round currently holds one transcript's reservation.
    ///
    /// The registry is the single authority for reservation state, so this is the
    /// check a derivation and a round-checked release consult.
    #[must_use]
    pub fn holds(&self, parent: &SessionId, round: &RoundId) -> bool {
        self.held.get(parent).is_some_and(|held| held == round)
    }

    /// Releases one parent transcript reservation.
    ///
    /// The registry is the single authority: after this release no outstanding handle
    /// of the removed reservation can derive a child.
    ///
    /// # Errors
    ///
    /// Returns an [`AgentError`] with code [`AgentDiagnosticCode::ReservationReleased`]
    /// when the parent transcript holds no reservation to release.
    pub fn release(&mut self, parent: &SessionId) -> Result<(), AgentError> {
        if self.held.remove(parent).is_some() {
            return Ok(());
        }
        Err(AgentError::new(
            AgentDiagnosticCode::ReservationReleased,
            format!("the transcript of `{parent}` holds no reservation to release"),
        ))
    }

    /// Releases one round's reservation of one transcript.
    ///
    /// A release removes only the reservation of the named round, so a stale handle can
    /// never release a reservation another round has since taken.
    ///
    /// # Errors
    ///
    /// Returns an [`AgentError`] with code [`AgentDiagnosticCode::ReservationReleased`]
    /// when the transcript holds no reservation of that round, because a release happens
    /// once and never releases another round's reservation.
    pub fn release_round(&mut self, parent: &SessionId, round: &RoundId) -> Result<(), AgentError> {
        if self.holds(parent, round) {
            self.held.remove(parent);
            return Ok(());
        }
        Err(AgentError::new(
            AgentDiagnosticCode::ReservationReleased,
            format!(
                "the transcript of `{parent}` holds no reservation of round `{round}` to release"
            ),
        ))
    }

    /// Decides the session directive of one requested entry into one transcript.
    ///
    /// A reserved transcript admits a derived child or refuses a direct reentry; an
    /// unreserved transcript admits ordinary entry or resumption.
    #[must_use]
    pub fn directive(&self, parent: &SessionId, reentering_parent: bool) -> SessionDirective {
        match (self.held.contains_key(parent), reentering_parent) {
            (true, true) => SessionDirective::RefuseReentry,
            (true, false) => SessionDirective::DeriveChild,
            (false, true) => SessionDirective::Resume,
            (false, false) => SessionDirective::Admit,
        }
    }
}

/// One admitted handler use of one source callable (`GNT-25.7-source-handlers`).
///
/// The use admits invocations under the declared callable kind. An `FnOnce` handler is
/// consumed by its first admitted invocation and refuses a second; `Fn` and `FnMut`
/// handlers admit repeated invocations under their declared kind. The use is affine: it
/// derives neither `Clone` nor `Copy`, and consumption is tracked on the value, so an
/// `FnOnce` handler can never be invoked twice through a copy.
#[derive(Debug, Eq, PartialEq)]
pub struct HandlerUse {
    kind: HandlerKind,
    slot: ToolSlotId,
    calls: u32,
    consumed: bool,
}

impl HandlerUse {
    /// Admits one handler use of one slot under its declared callable kind.
    #[must_use]
    pub const fn admit(kind: HandlerKind, slot: ToolSlotId) -> Self {
        Self {
            kind,
            slot,
            calls: 0,
            consumed: false,
        }
    }

    /// Returns the declared callable kind.
    #[must_use]
    pub const fn kind(&self) -> HandlerKind {
        self.kind
    }

    /// Returns the implemented tool slot.
    #[must_use]
    pub const fn slot(&self) -> &ToolSlotId {
        &self.slot
    }

    /// Returns the admitted invocation count.
    #[must_use]
    pub const fn calls(&self) -> u32 {
        self.calls
    }

    /// Returns whether the single-use handler was consumed.
    #[must_use]
    pub const fn is_consumed(&self) -> bool {
        self.consumed
    }

    /// Admits one invocation of this handler use.
    ///
    /// # Errors
    ///
    /// Returns an [`AgentError`] with code [`AgentDiagnosticCode::HandlerAlreadyConsumed`]
    /// when the single-use handler was already consumed, so an `FnOnce` handler is
    /// consumed at most once and never replayed.
    pub fn call(&mut self) -> Result<(), AgentError> {
        if self.consumed {
            return Err(AgentError::new(
                AgentDiagnosticCode::HandlerAlreadyConsumed,
                format!(
                    "the `{}` handler of `{}` was already consumed",
                    self.kind.wire_name(),
                    self.slot
                ),
            ));
        }
        self.calls = self.calls.saturating_add(1);
        if !self.kind.admits_repeated_invocations() {
            self.consumed = true;
        }
        Ok(())
    }
}

/// One settled tool result of one request position (`GNT-25.7-source-handlers`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolResultRecord {
    position: u32,
    code: Arc<str>,
    failed: bool,
}

impl ToolResultRecord {
    /// Constructs one settled tool result from its position, code, and failure flag.
    ///
    /// # Errors
    ///
    /// Returns an [`AgentError`] with code [`AgentDiagnosticCode::EmptyDeclaredIdentity`]
    /// when the declared result code is empty or whitespace only.
    pub fn new(position: u32, code: &str, failed: bool) -> Result<Self, AgentError> {
        Ok(Self {
            position,
            code: declared_text(code, AgentDeclaredInput::ResultCode)?,
            failed,
        })
    }

    /// Returns the request position this result settles.
    #[must_use]
    pub const fn position(&self) -> u32 {
        self.position
    }

    /// Returns the declared result code.
    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }

    /// Returns whether the settled invocation failed.
    #[must_use]
    pub const fn failed(&self) -> bool {
        self.failed
    }
}

/// One settled tool-result vector in canonical request order
/// (`GNT-25.7-source-handlers`).
///
/// The vector settles one result per accepted request position, in canonical request
/// order, no matter in which order the handler invocations completed. A duplicate
/// position, a missing position, and a position outside the accepted set are refused.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolResultVector {
    results: Vec<ToolResultRecord>,
}

impl ToolResultVector {
    /// Settles one result per accepted request position into canonical request order.
    ///
    /// # Errors
    ///
    /// Returns an [`AgentError`] with code [`AgentDiagnosticCode::UnknownToolPosition`]
    /// for a position outside the accepted set, one with code
    /// [`AgentDiagnosticCode::DuplicateToolResult`] for a repeated position, and one
    /// with code [`AgentDiagnosticCode::MissingToolResult`] for an unsettled position.
    pub fn settle(records: &[ToolResultRecord], expected: u32) -> Result<Self, AgentError> {
        let mut positions = BTreeSet::new();
        for record in records {
            if record.position() >= expected {
                return Err(AgentError::new(
                    AgentDiagnosticCode::UnknownToolPosition,
                    format!(
                        "the position {} is outside the accepted request set of {expected}",
                        record.position()
                    ),
                ));
            }
            if !positions.insert(record.position()) {
                return Err(AgentError::new(
                    AgentDiagnosticCode::DuplicateToolResult,
                    format!("the position {} was settled twice", record.position()),
                ));
            }
        }
        if positions.len() != usize::try_from(expected).unwrap_or(usize::MAX) {
            return Err(AgentError::new(
                AgentDiagnosticCode::MissingToolResult,
                format!(
                    "{} of the {expected} accepted request positions were settled",
                    positions.len()
                ),
            ));
        }
        let mut ordered = records.to_vec();
        ordered.sort_by_key(ToolResultRecord::position);
        Ok(Self { results: ordered })
    }

    /// Returns the settled results in canonical request order.
    #[must_use]
    pub fn results(&self) -> &[ToolResultRecord] {
        &self.results
    }

    /// Returns the settled positions in canonical request order.
    #[must_use]
    pub fn positions(&self) -> Vec<u32> {
        self.results
            .iter()
            .map(ToolResultRecord::position)
            .collect()
    }

    /// Returns the settled result count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.results.len()
    }

    /// Returns whether no result is settled.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.results.is_empty()
    }
}

/// One declared stream identity (`GNT-25.9-streaming-and-progress`).
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StreamId {
    text: Arc<str>,
}

impl StreamId {
    /// Constructs one stream identity from its declared name.
    ///
    /// # Errors
    ///
    /// Returns an [`AgentError`] with code [`AgentDiagnosticCode::EmptyDeclaredIdentity`]
    /// when the declared name is empty or whitespace only.
    pub fn new(name: &str) -> Result<Self, AgentError> {
        Ok(Self {
            text: declared_text(name, AgentDeclaredInput::Stream)?,
        })
    }

    /// Returns the exact portable identity spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }
}

impl fmt::Display for StreamId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.text)
    }
}

/// One finite stream budget (`GNT-25.9-streaming-and-progress`).
///
/// A semantic stream admission consumes the budget; a progress observation is
/// nonsemantic and never consumes it. The budget admits no unbounded semantic stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StreamBudget {
    max_items: u64,
    max_bytes: u64,
}

impl StreamBudget {
    /// Constructs one finite stream budget from its declared bounds.
    #[must_use]
    pub const fn new(max_items: u64, max_bytes: u64) -> Self {
        Self {
            max_items,
            max_bytes,
        }
    }

    /// Returns the declared finite item bound.
    #[must_use]
    pub const fn max_items(&self) -> u64 {
        self.max_items
    }

    /// Returns the declared finite byte bound.
    #[must_use]
    pub const fn max_bytes(&self) -> u64 {
        self.max_bytes
    }

    /// Admits one stream observation against the budget.
    ///
    /// A progress observation is admitted without consuming the semantic budget,
    /// because nonsemantic progress cannot affect a source result or an accepted turn.
    ///
    /// # Errors
    ///
    /// Returns an [`AgentError`] with code [`AgentDiagnosticCode::StreamBudgetExceeded`]
    /// when a semantic observation exceeds the declared item or byte bound.
    pub fn admit(&self, kind: StreamKind, items: u64, bytes: u64) -> Result<(), AgentError> {
        if !kind.is_semantic() {
            return Ok(());
        }
        if items > self.max_items {
            return Err(AgentError::new(
                AgentDiagnosticCode::StreamBudgetExceeded,
                format!(
                    "{items} items exceed the declared semantic item bound {}",
                    self.max_items
                ),
            ));
        }
        if bytes > self.max_bytes {
            return Err(AgentError::new(
                AgentDiagnosticCode::StreamBudgetExceeded,
                format!(
                    "{bytes} bytes exceed the declared semantic byte bound {}",
                    self.max_bytes
                ),
            ));
        }
        Ok(())
    }
}

/// One declared stream specification before semantic admission
/// (`GNT-25.9-streaming-and-progress`).
///
/// The specification declares one stream kind, finite item and byte bounds, and the
/// landed authority requirement of its owning round or tool invocation. Admission
/// refuses a semantic stream whose authority facts are missing or unsafe.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamSpec {
    id: StreamId,
    kind: Option<StreamKind>,
    max_items: Option<u64>,
    max_bytes: Option<u64>,
    authority: Option<AuthorityRequirementId>,
}

impl StreamSpec {
    /// Constructs one stream specification from its declared kind and bounds.
    ///
    /// The authority requirement is undeclared until [`Self::with_authority`] declares
    /// it; a semantic stream admitted without one is refused as unsafe.
    #[must_use]
    pub const fn new(
        id: StreamId,
        kind: Option<StreamKind>,
        max_items: Option<u64>,
        max_bytes: Option<u64>,
    ) -> Self {
        Self {
            id,
            kind,
            max_items,
            max_bytes,
            authority: None,
        }
    }

    /// Declares the landed authority requirement owned by this stream's round or tool
    /// invocation.
    #[must_use]
    pub fn with_authority(mut self, authority: &AuthorityRequirementId) -> Self {
        self.authority = Some(authority.clone());
        self
    }

    /// Returns the declared stream identity.
    #[must_use]
    pub const fn id(&self) -> &StreamId {
        &self.id
    }

    /// Returns the declared stream kind, if any.
    #[must_use]
    pub const fn kind(&self) -> Option<StreamKind> {
        self.kind
    }

    /// Returns the declared finite item bound, if any.
    #[must_use]
    pub const fn max_items(&self) -> Option<u64> {
        self.max_items
    }

    /// Returns the declared finite byte bound, if any.
    #[must_use]
    pub const fn max_bytes(&self) -> Option<u64> {
        self.max_bytes
    }

    /// Returns the declared authority requirement, if any.
    #[must_use]
    pub const fn authority(&self) -> Option<&AuthorityRequirementId> {
        self.authority.as_ref()
    }
}

/// One admitted semantic stream (`GNT-25.9-streaming-and-progress`).
///
/// A semantic stream is typed, finitely bounded, authority-safe, and restart-safe.
/// Its durable position advances only by a strictly greater committed position, so a
/// replay resumes after the committed position without repeating an item.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SemanticStream {
    id: StreamId,
    budget: StreamBudget,
    position: u64,
}

impl SemanticStream {
    /// Admits one semantic stream specification against its owning authority.
    ///
    /// The stream must declare the landed authority requirement of the round or tool
    /// invocation that owns it, and that requirement must be the owner's own; a stream
    /// whose authority facts are missing or unsafe is refused rather than admitted.
    ///
    /// # Errors
    ///
    /// Returns an [`AgentError`] with code
    /// [`AgentDiagnosticCode::UntypedSemanticStream`] when no stream kind is declared,
    /// one with code [`AgentDiagnosticCode::NonsemanticStreamPresentedAsSemantic`] when
    /// the declared kind is progress, and one with code
    /// [`AgentDiagnosticCode::UnboundedSemanticStream`] when the item or byte bound is
    /// absent, and one with code [`AgentDiagnosticCode::UnsafeSemanticStreamAuthority`]
    /// when the declared authority requirement is missing or differs from the owner's.
    pub fn admit(spec: StreamSpec, owner: &AuthorityRequirementId) -> Result<Self, AgentError> {
        let Some(kind) = spec.kind() else {
            return Err(AgentError::new(
                AgentDiagnosticCode::UntypedSemanticStream,
                format!(
                    "the semantic stream `{}` declares no stream kind",
                    spec.id()
                ),
            ));
        };
        if !kind.is_semantic() {
            return Err(AgentError::new(
                AgentDiagnosticCode::NonsemanticStreamPresentedAsSemantic,
                format!(
                    "the progress stream `{}` is not a semantic stream",
                    spec.id()
                ),
            ));
        }
        let (Some(max_items), Some(max_bytes)) = (spec.max_items(), spec.max_bytes()) else {
            return Err(AgentError::new(
                AgentDiagnosticCode::UnboundedSemanticStream,
                format!(
                    "the semantic stream `{}` declares no finite item and byte bound",
                    spec.id()
                ),
            ));
        };
        let Some(declared) = spec.authority() else {
            return Err(AgentError::new(
                AgentDiagnosticCode::UnsafeSemanticStreamAuthority,
                format!(
                    "the semantic stream `{}` declares no authority requirement",
                    spec.id()
                ),
            ));
        };
        if declared != owner {
            return Err(AgentError::new(
                AgentDiagnosticCode::UnsafeSemanticStreamAuthority,
                format!(
                    "the semantic stream `{}` declares an authority requirement other than its owner's",
                    spec.id()
                ),
            ));
        }
        Ok(Self {
            id: spec.id().clone(),
            budget: StreamBudget::new(max_items, max_bytes),
            position: 0,
        })
    }

    /// Returns the stream identity.
    #[must_use]
    pub const fn id(&self) -> &StreamId {
        &self.id
    }

    /// Returns the finite stream budget.
    #[must_use]
    pub const fn budget(&self) -> StreamBudget {
        self.budget
    }

    /// Returns the committed stream position.
    #[must_use]
    pub const fn position(&self) -> u64 {
        self.position
    }

    /// Admits one semantic observation against the finite budget.
    ///
    /// # Errors
    ///
    /// Returns an [`AgentError`] with code [`AgentDiagnosticCode::StreamBudgetExceeded`]
    /// when the observation exceeds the declared finite bound.
    pub fn admit_observation(&self, items: u64, bytes: u64) -> Result<(), AgentError> {
        self.budget.admit(StreamKind::Semantic, items, bytes)
    }

    /// Commits one strictly greater stream position.
    ///
    /// # Errors
    ///
    /// Returns an [`AgentError`] with code
    /// [`AgentDiagnosticCode::StreamPositionRegression`] when the presented position is
    /// not strictly greater than the committed one, so a replay never repeats an item.
    pub fn commit_position(&mut self, next: u64) -> Result<(), AgentError> {
        if next <= self.position {
            return Err(AgentError::new(
                AgentDiagnosticCode::StreamPositionRegression,
                format!(
                    "the presented position {next} does not follow the committed {}",
                    self.position
                ),
            ));
        }
        self.position = next;
        Ok(())
    }
}

/// One admitted nonsemantic progress observation (`GNT-25.9-streaming-and-progress`).
///
/// A progress observation is a presentation update outside every accepted turn: it
/// cannot create, change, or complete a final result, cannot add or settle a tool
/// request, cannot advance a durable cut, and cannot be presented as the source result
/// of a round. Admission refuses any claim to settle an accepted turn or a tool result,
/// and both accessors are permanently false, so no admitted progress signal can ever be
/// read as settling one.
#[derive(Debug, Eq, PartialEq)]
pub struct ProgressSignal;

impl ProgressSignal {
    /// Admits one nonsemantic progress observation that claims no settlement.
    ///
    /// # Errors
    ///
    /// Returns an [`AgentError`] with code
    /// [`AgentDiagnosticCode::ProgressSettlementClaimRefused`] when the observation
    /// claims to settle an accepted turn or a tool result.
    pub fn admit(claims_accepted_turn: bool, claims_tool_result: bool) -> Result<Self, AgentError> {
        if claims_accepted_turn || claims_tool_result {
            return Err(AgentError::new(
                AgentDiagnosticCode::ProgressSettlementClaimRefused,
                "a progress observation cannot settle an accepted turn or a tool result",
            ));
        }
        let signal = Self;
        debug_assert!(
            !signal.claims_accepted_turn() && !signal.claims_tool_result(),
            "an admitted progress signal must never claim settlement"
        );
        Ok(signal)
    }

    /// Returns whether this observation claims to settle an accepted turn.
    #[must_use]
    pub const fn claims_accepted_turn(&self) -> bool {
        false
    }

    /// Returns whether this observation claims to settle a tool result.
    #[must_use]
    pub const fn claims_tool_result(&self) -> bool {
        false
    }
}
