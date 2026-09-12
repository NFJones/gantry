//! Pure protected-value, semantic-envelope, release, and cleanup model.
//!
//! This module is the machine-checked definition model for
//! `GNT-15.10-protected-values`, `GNT-15.10-semantic-envelope`,
//! `GNT-15.10-release-operation`, `GNT-15.10-emergency-cleanup`, and
//! `GNT-15.10-protection-invariants`. It states what a protected value is,
//! which observations of one must be classified, in what order a release
//! decision is taken, what emergency cleanup may do, and which components must
//! not erase protection.
//!
//! Scope is deliberately narrow: this module models the class and destination
//! vocabularies, protected-value identity, the release decision order, the
//! disclosure budget, the semantic envelope, and sealed cleanup. It is not the
//! runtime protection store and it never holds a payload. Careful readers can
//! reproduce every rule it states from its own arguments, because there is no
//! protected byte anywhere in the crate.
//!
//! What the specification forbids for source code (destructuring, sizing,
//! comparing, formatting, rendering, interpolating, serializing, branching on,
//! emitting as telemetry, or supplying a protected value to a model) is carried
//! here by the absence of `Debug`, `Display`, `Serialize`, `PartialEq`, `len`,
//! and `into_inner` on [`ProtectedValue`], and by the absence of any byte-level
//! constructor or deserializer. A protected value's identity is a
//! domain-separated digest of its declared class and declared provenance label,
//! never of protected bytes, so comparing identities is ordinary while
//! comparing contents is not expressible.
//!
//! Separations stay explicit:
//!
//! * a [`ReleaseGrant`] is not an authority instance and has no free
//!   constructor: only a [`ReleaseHolderAuthority`] derives one, it narrows a
//!   declared class set and a declared destination set, and neither an
//!   [`AuthorityRight`] nor an authority instance substitutes for it, so
//!   operation authority never implies release;
//! * a [`ReleaseSite`] decision checks the declared data-class and destination
//!   pair, the grant, and the disclosure budget in that order and only then
//!   produces a projection. A rejection therefore never charges the budget,
//!   never emits audit evidence, and never distinguishes which protected bit
//!   caused it;
//! * the transport side decides delivery separately from release: a
//!   [`FrozenDeliveryPermission`] never widens a declared destination class and
//!   never admits delivery under a denied release, and transport denial is not a
//!   release rejection category;
//! * protected audit evidence is reachable only through [`ReleaseAuditView`],
//!   which an [`AuditAccess`] capability gates and which carries declared
//!   metadata only;
//! * declared provenance is a [`ProvenanceOrigin`] of one closed kind and one
//!   validated name, never free text, so no payload byte can be supplied as
//!   provenance;
//! * every non-erasure obligation stays [`NonErasureStatus::Unproven`] until
//!   citable evidence is attached, and an unproven component is never reported
//!   as safe.
//!
//! [`AuthorityRight`]: crate::authority::AuthorityRight

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use sha2::{Digest, Sha256};

use crate::CanonicalImplementationIdentity;
use crate::manifest::encode_hex;
use crate::type_properties::{RecoveryProjectionClass, SourceProtectionClass};

/// Domain separator for canonical protected-value identity derivation.
const PROTECTED_VALUE_DOMAIN: &str = "gantry.protected-value/v1";

/// Domain separator for canonical release-holder identity derivation.
const RELEASE_HOLDER_DOMAIN: &str = "gantry.release-holder/v1";

/// Returns one length-prefixed, domain-separated SHA-256 digest over fields.
///
/// Length prefixes keep distinct field sequences distinct, so a class and a
/// provenance label cannot be confused with a differently split pair of the
/// same concatenated text.
fn digest_fields(domain: &str, fields: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    for field in fields {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    hasher.finalize().into()
}

/// Returns one length-prefixed encoding of a declared name or binding text.
fn encode_text(value: &str) -> String {
    format!("{}:{value}", value.len())
}

/// Returns whether one byte is part of the canonical declaration spelling.
fn canonical_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/' | b'#')
}

/// All protected data classes in the fixed reporting order of this module.
///
/// `SPEC.md` defines no normative order over classes, so this order is a
/// deterministic presentation order only: it fixes how listings and portable
/// spellings are emitted and carries no protection of its own.
pub const PROTECTED_DATA_CLASS_ORDER: [ProtectedDataClass; 14] = [
    ProtectedDataClass::SourceText,
    ProtectedDataClass::EntryInput,
    ProtectedDataClass::InterpolationArgument,
    ProtectedDataClass::NamedInput,
    ProtectedDataClass::ActionArgument,
    ProtectedDataClass::RenderedPrompt,
    ProtectedDataClass::SessionIdentifier,
    ProtectedDataClass::RawHookOutput,
    ProtectedDataClass::NormalizedValue,
    ProtectedDataClass::DecisionRationale,
    ProtectedDataClass::DeclineReason,
    ProtectedDataClass::HookFailureMessage,
    ProtectedDataClass::JournalRecord,
    ProtectedDataClass::ProtectedEventPayload,
];

/// One closed protected data class.
///
/// Every protected value carries exactly one class. The vocabulary mirrors the
/// potentially sensitive integration data named by `GNT-15.10`: source, entry
/// input, interpolation arguments, named inputs, action arguments, rendered
/// prompts, session identifiers, raw hook output, normalized values, decision
/// rationales, decline reasons, hook-failure messages, journals, and protected
/// event payloads. It is a closed portable spelling set: changing it requires a
/// protocol catalog change and regeneration, never a hand edit of generated
/// protocol bindings.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ProtectedDataClass {
    /// Authored or validated source text.
    SourceText,
    /// One entry input value.
    EntryInput,
    /// One interpolation argument.
    InterpolationArgument,
    /// One named input.
    NamedInput,
    /// One action argument.
    ActionArgument,
    /// One rendered prompt.
    RenderedPrompt,
    /// One session identifier.
    SessionIdentifier,
    /// Raw hook output.
    RawHookOutput,
    /// One normalized value.
    NormalizedValue,
    /// One decision rationale.
    DecisionRationale,
    /// One decline reason.
    DeclineReason,
    /// One hook-failure message.
    HookFailureMessage,
    /// One journal record payload.
    JournalRecord,
    /// One protected event payload.
    ProtectedEventPayload,
}

impl ProtectedDataClass {
    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::SourceText => "source-text",
            Self::EntryInput => "entry-input",
            Self::InterpolationArgument => "interpolation-argument",
            Self::NamedInput => "named-input",
            Self::ActionArgument => "action-argument",
            Self::RenderedPrompt => "rendered-prompt",
            Self::SessionIdentifier => "session-identifier",
            Self::RawHookOutput => "raw-hook-output",
            Self::NormalizedValue => "normalized-value",
            Self::DecisionRationale => "decision-rationale",
            Self::DeclineReason => "decline-reason",
            Self::HookFailureMessage => "hook-failure-message",
            Self::JournalRecord => "journal-record",
            Self::ProtectedEventPayload => "protected-event-payload",
        }
    }

    /// Strictly decodes one exact portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        PROTECTED_DATA_CLASS_ORDER
            .into_iter()
            .find(|class| class.wire_name() == value)
    }
}

/// All release destinations in the fixed reporting order of this module.
pub const RELEASE_DESTINATION_ORDER: [ReleaseDestination; 5] = [
    ReleaseDestination::OrdinarySource,
    ReleaseDestination::ProtectedJournal,
    ReleaseDestination::DiagnosticSink,
    ReleaseDestination::ProviderModel,
    ReleaseDestination::NullTelemetry,
];

/// One closed release destination class.
///
/// The class is closed: a destination outside it cannot receive a release, and
/// a release site must declare the data-class and destination pair before
/// evaluation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ReleaseDestination {
    /// Ordinary source code, which is the only destination that declassifies.
    OrdinarySource,
    /// A protected journal record, which does not declassify.
    ProtectedJournal,
    /// A diagnostic sink governed by its capability and redaction policy.
    DiagnosticSink,
    /// A provider or model input.
    ProviderModel,
    /// The null destination: telemetry and sealed emergency cleanup.
    NullTelemetry,
}

impl ReleaseDestination {
    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::OrdinarySource => "ordinary-source",
            Self::ProtectedJournal => "protected-journal",
            Self::DiagnosticSink => "diagnostic-sink",
            Self::ProviderModel => "provider-model",
            Self::NullTelemetry => "null-telemetry",
        }
    }

    /// Strictly decodes one exact portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        RELEASE_DESTINATION_ORDER
            .into_iter()
            .find(|destination| destination.wire_name() == value)
    }

    /// Returns whether this is the null destination.
    #[must_use]
    pub const fn is_null(self) -> bool {
        matches!(self, Self::NullTelemetry)
    }
}

/// One validated canonical declared name.
///
/// A declared name is ordinary metadata rather than payload: it is non-empty
/// ASCII, within [`DECLARED_NAME_LIMIT`], and drawn from the canonical
/// declaration spelling of ASCII alphanumerics and `-`, `_`, `.`, `:`, `/`, and
/// `#`. It is the only free text this model accepts, so arbitrary payload bytes
/// can never be supplied where a name is declared.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct DeclaredName(Arc<str>);

/// The largest accepted declared name.
pub const DECLARED_NAME_LIMIT: usize = 96;

/// Why one declared name was rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeclaredNameRejection {
    /// The name was empty.
    Empty,
    /// The name exceeded [`DECLARED_NAME_LIMIT`].
    TooLong,
    /// The name contained a non-ASCII character.
    NonAscii,
    /// The name contained whitespace or a control character.
    ControlOrWhitespace,
    /// The name contained a character outside the canonical declaration spelling.
    NonCanonicalCharacter,
}

impl DeclaredNameRejection {
    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::TooLong => "too-long",
            Self::NonAscii => "non-ascii",
            Self::ControlOrWhitespace => "control-or-whitespace",
            Self::NonCanonicalCharacter => "non-canonical-character",
        }
    }
}

impl DeclaredName {
    /// Validates one canonical declared name.
    pub fn new(value: &str) -> Result<Self, DeclaredNameRejection> {
        if value.is_empty() {
            return Err(DeclaredNameRejection::Empty);
        }
        if value.len() > DECLARED_NAME_LIMIT {
            return Err(DeclaredNameRejection::TooLong);
        }
        if !value.is_ascii() {
            return Err(DeclaredNameRejection::NonAscii);
        }
        if value
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
        {
            return Err(DeclaredNameRejection::ControlOrWhitespace);
        }
        if !value.bytes().all(canonical_name_byte) {
            return Err(DeclaredNameRejection::NonCanonicalCharacter);
        }
        Ok(Self(Arc::from(value)))
    }

    /// Returns the exact declared name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One closed provenance origin kind.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ProvenanceOriginKind {
    /// The integration boundary that received the payload.
    IntegrationBoundary,
    /// A declared protection-preserving transformation.
    ProtectionPreservingTransform,
    /// The protection layer, creating a value under a declared contract.
    ProtectionLayer,
    /// Recovery replay of one durable protected record.
    RecoveryReplay,
}

/// All provenance origin kinds in the fixed reporting order of this module.
pub const PROVENANCE_ORIGIN_ORDER: [ProvenanceOriginKind; 4] = [
    ProvenanceOriginKind::IntegrationBoundary,
    ProvenanceOriginKind::ProtectionPreservingTransform,
    ProvenanceOriginKind::ProtectionLayer,
    ProvenanceOriginKind::RecoveryReplay,
];

impl ProvenanceOriginKind {
    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::IntegrationBoundary => "integration-boundary",
            Self::ProtectionPreservingTransform => "protection-preserving-transform",
            Self::ProtectionLayer => "protection-layer",
            Self::RecoveryReplay => "recovery-replay",
        }
    }

    /// Strictly decodes one exact portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        PROVENANCE_ORIGIN_ORDER
            .into_iter()
            .find(|kind| kind.wire_name() == value)
    }
}

/// One declared provenance origin: one closed kind and one canonical name.
///
/// Provenance is a declaration rather than a payload: the kind is closed and the
/// name is a [`DeclaredName`], so payload bytes, payload encodings, and
/// payload-derived text can never be supplied as provenance.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ProvenanceOrigin {
    kind: ProvenanceOriginKind,
    name: DeclaredName,
}

impl ProvenanceOrigin {
    /// Declares one origin of one closed kind and one canonical name.
    ///
    /// Rejects a name that is empty, non-ASCII, contains whitespace or a control
    /// character, or exceeds [`DECLARED_NAME_LIMIT`].
    pub fn new(kind: ProvenanceOriginKind, name: &str) -> Result<Self, DeclaredNameRejection> {
        Ok(Self {
            kind,
            name: DeclaredName::new(name)?,
        })
    }

    /// Returns the closed origin kind.
    #[must_use]
    pub const fn kind(&self) -> ProvenanceOriginKind {
        self.kind
    }

    /// Returns the canonical declared name.
    #[must_use]
    pub fn name(&self) -> &DeclaredName {
        &self.name
    }
}

/// One canonical protected-value identity.
///
/// The identity is a domain-separated SHA-256 digest over the declared class and
/// the declared provenance origin. It contains no payload bytes, it has no
/// public constructor from bytes, and no deserializer: it cannot be built from
/// an ordinary representation of a value. Observing an identity is an ordinary
/// observation because identity is not content.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProtectedValueId(Arc<str>);

impl ProtectedValueId {
    /// Derives one identity from a declared class and declared origin.
    fn derive(class: ProtectedDataClass, origin: &ProvenanceOrigin) -> Self {
        let digest = digest_fields(
            PROTECTED_VALUE_DOMAIN,
            &[
                class.wire_name().as_bytes(),
                origin.kind().wire_name().as_bytes(),
                origin.name().as_str().as_bytes(),
            ],
        );
        Self(Arc::from(format!("protected:{}", encode_hex(&digest))))
    }

    /// Returns the exact portable identity spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the lowercase digest text without the identity prefix.
    #[must_use]
    pub fn digest_hex(&self) -> &str {
        self.0.strip_prefix("protected:").unwrap_or(&self.0)
    }

    /// Returns this identity as a declared name.
    ///
    /// The canonical identity spelling is fixed by [`Self::derive`]: an ASCII
    /// prefix and lowercase hexadecimal digits, well within
    /// [`DECLARED_NAME_LIMIT`], so it is always a valid declared name.
    fn as_declared_name(&self) -> DeclaredName {
        DeclaredName(Arc::clone(&self.0))
    }
}

/// One opaque protected value.
///
/// This type deliberately implements none of `Debug`, `Display`, `Serialize`,
/// `PartialEq`, `len`, or `into_inner`, and it stores only a declared class and
/// an identity, so an ordinary observation of its contents is not expressible.
pub struct ProtectedValue {
    id: ProtectedValueId,
    class: ProtectedDataClass,
}

impl ProtectedValue {
    /// Seals one declared class and declared origin as a protected value.
    ///
    /// The protection layer owns creation. There is no byte-level constructor
    /// and no deserializer, provenance is a validated declaration rather than
    /// free text, and the identity depends on the declared class and declared
    /// origin only, so two sealings of one class and origin share one identity
    /// whatever payload the integration boundary carried.
    #[must_use]
    pub fn seal(class: ProtectedDataClass, origin: ProvenanceOrigin) -> Self {
        Self {
            id: ProtectedValueId::derive(class, &origin),
            class,
        }
    }

    /// Returns the declared data class.
    #[must_use]
    pub const fn class(&self) -> ProtectedDataClass {
        self.class
    }

    /// Returns the layer-1 readability and inspectability of this value.
    ///
    /// Layer 1 is the only layer Gantry source reads, and it may still contain
    /// values source cannot inspect: readability of the layer and
    /// inspectability of a value are separate claims, so this value is readable
    /// by source without being inspectable by it.
    #[must_use]
    pub const fn layer_one_inspection(&self) -> LayerValueInspection {
        LayerValueInspection {
            layer: 1,
            readable_by_source: true,
            inspectable_by_source: false,
        }
    }

    /// Returns the canonical identity.
    #[must_use]
    pub const fn id(&self) -> &ProtectedValueId {
        &self.id
    }

    /// Returns whether this is a protected value, which is always true.
    ///
    /// A protected value is not an ordinary value and not an external value;
    /// this positive control makes that definitional claim observable.
    #[must_use]
    pub const fn is_protected(&self) -> bool {
        true
    }

    /// Returns whether this value is an external value, which is never true.
    #[must_use]
    pub const fn is_external_value(&self) -> bool {
        false
    }

    /// Returns the reused source-protection classification, which is `Sealed`.
    #[must_use]
    pub const fn protection_class(&self) -> SourceProtectionClass {
        SourceProtectionClass::Sealed
    }

    /// Returns the reused recovery projection, which is `SealedValue`.
    #[must_use]
    pub const fn recovery_projection(&self) -> RecoveryProjectionClass {
        RecoveryProjectionClass::SealedValue
    }
}

/// Returns the conservative protection class of an output that combines a
/// protected input with an ordinary one.
///
/// `Unsealed` never means nonsensitive: it records only that the classification
/// itself imposes no sealing requirement, so an ordinary input can never lower
/// the class of an output that also depends on a protected input.
#[must_use]
pub const fn combined_protection_class(
    protected: SourceProtectionClass,
    ordinary: SourceProtectionClass,
) -> SourceProtectionClass {
    protected.combine(ordinary)
}

/// One declared protection-preserving transformation.
///
/// A transformation may consume a protected value only when it declares the
/// input class it consumes, the output class it produces, the projection it
/// applies, and the semantic envelope that classifies every language-visible
/// consequence of its protected inputs. Every output stays protected, and
/// dependence is conservative: combining an ordinary input with a protected one
/// keeps the result protected.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectionPreservingTransform {
    input: ProtectedDataClass,
    output: ProtectedDataClass,
    projection: ProjectionKind,
    envelope: SemanticEnvelope,
}

impl ProtectionPreservingTransform {
    /// Declares one protection-preserving transformation and its envelope.
    ///
    /// The declaration is refused when the envelope leaves any language-visible
    /// consequence unclassified: an unclassified consequence is treated as
    /// protected rather than ordinary, so a contract cannot be declared on an
    /// envelope that silently omits one.
    pub fn declare(
        input: ProtectedDataClass,
        output: ProtectedDataClass,
        projection: ProjectionKind,
        envelope: SemanticEnvelope,
    ) -> Result<Self, EnvelopeRejection> {
        let unclassified = envelope.unclassified();
        if !unclassified.is_empty() {
            return Err(EnvelopeRejection { unclassified });
        }
        Ok(Self {
            input,
            output,
            projection,
            envelope,
        })
    }

    /// Returns the declared input class.
    #[must_use]
    pub const fn input(&self) -> ProtectedDataClass {
        self.input
    }

    /// Returns the declared output class.
    #[must_use]
    pub const fn output(&self) -> ProtectedDataClass {
        self.output
    }

    /// Returns the declared projection.
    #[must_use]
    pub const fn projection(&self) -> ProjectionKind {
        self.projection
    }

    /// Returns the attached semantic envelope.
    #[must_use]
    pub const fn envelope(&self) -> &SemanticEnvelope {
        &self.envelope
    }

    /// Consumes one value of the declared input class and returns a protected
    /// value of the declared output class.
    ///
    /// Returns `None` when the value's class is not the declared input class, so
    /// a transformation cannot consume a class its contract never named. The
    /// output stays protected and derives its provenance from the consumed
    /// value's canonical identity, never from its contents.
    #[must_use]
    pub fn apply(&self, value: &ProtectedValue) -> Option<ProtectedValue> {
        if value.class() != self.input {
            return None;
        }
        let origin = ProvenanceOrigin {
            kind: ProvenanceOriginKind::ProtectionPreservingTransform,
            name: value.id().as_declared_name(),
        };
        Some(ProtectedValue::seal(self.output, origin))
    }
}

/// One value-action boundary that a protected value must not cross undeclared.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ValueActionBoundary {
    /// An action argument position.
    ActionArgument,
    /// An entry input position.
    EntryInput,
    /// A workflow result position.
    WorkflowResult,
    /// A task result position.
    TaskResult,
    /// An operation result position.
    OperationResult,
    /// An ordinary protocol envelope.
    ProtocolEnvelope,
}

impl ValueActionBoundary {
    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::ActionArgument => "action-argument",
            Self::EntryInput => "entry-input",
            Self::WorkflowResult => "workflow-result",
            Self::TaskResult => "task-result",
            Self::OperationResult => "operation-result",
            Self::ProtocolEnvelope => "protocol-envelope",
        }
    }
}

/// One dedicated protocol declaration that admits a boundary crossing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CrossingDeclaration {
    boundary: ValueActionBoundary,
    class: ProtectedDataClass,
}

impl CrossingDeclaration {
    /// Declares one admitted boundary crossing for one class.
    #[must_use]
    pub const fn new(boundary: ValueActionBoundary, class: ProtectedDataClass) -> Self {
        Self { boundary, class }
    }

    /// Returns the declared boundary.
    #[must_use]
    pub const fn boundary(self) -> ValueActionBoundary {
        self.boundary
    }

    /// Returns the declared class.
    #[must_use]
    pub const fn class(self) -> ProtectedDataClass {
        self.class
    }
}

/// Why one value-action boundary crossing was rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CrossingRejection {
    /// No dedicated protocol declared the crossing.
    UndeclaredProtocol,
    /// The declaration names another boundary.
    BoundaryMismatch,
    /// The declaration names another class.
    ClassMismatch,
}

impl CrossingRejection {
    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::UndeclaredProtocol => "undeclared-protocol",
            Self::BoundaryMismatch => "boundary-mismatch",
            Self::ClassMismatch => "class-mismatch",
        }
    }
}

/// Admits or rejects one crossing of one value-action boundary.
///
/// A crossing is permitted only when a dedicated protocol declares the
/// boundary and accepts the value's class; absent that declaration the
/// crossing is an admission failure rather than a runtime decision.
pub fn admit_crossing(
    value: &ProtectedValue,
    boundary: ValueActionBoundary,
    declaration: Option<&CrossingDeclaration>,
) -> Result<(), CrossingRejection> {
    let Some(declaration) = declaration else {
        return Err(CrossingRejection::UndeclaredProtocol);
    };
    if declaration.boundary() != boundary {
        return Err(CrossingRejection::BoundaryMismatch);
    }
    if declaration.class() != value.class() {
        return Err(CrossingRejection::ClassMismatch);
    }
    Ok(())
}

/// Readability and inspectability of one protected value at layer 1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LayerValueInspection {
    layer: u8,
    readable_by_source: bool,
    inspectable_by_source: bool,
}

impl LayerValueInspection {
    /// Returns the observation layer, which is layer 1.
    #[must_use]
    pub const fn layer(self) -> u8 {
        self.layer
    }

    /// Returns whether Gantry source may name this value.
    #[must_use]
    pub const fn readable_by_source(self) -> bool {
        self.readable_by_source
    }

    /// Returns whether Gantry source may inspect this value's contents.
    #[must_use]
    pub const fn inspectable_by_source(self) -> bool {
        self.inspectable_by_source
    }
}

/// One declared release projection.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ProjectionKind {
    /// Deliver the protected value itself to the declared destination.
    Verbatim,
    /// Deliver a value of the same class with redacted contents.
    Redacted,
    /// Deliver only a declared shape with no protected contents.
    Structural,
}

impl ProjectionKind {
    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Verbatim => "verbatim",
            Self::Redacted => "redacted",
            Self::Structural => "structural",
        }
    }
}

/// One accepted release projection: declared metadata only.
///
/// A projection names the applied transformation, the released class, and the
/// destination. It carries no payload and no payload-derived bit, so two
/// accepted releases of the same class and destination are indistinguishable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReleaseProjection {
    kind: ProjectionKind,
    class: ProtectedDataClass,
    destination: ReleaseDestination,
}

impl ReleaseProjection {
    /// Constructs one accepted projection from declared metadata.
    #[must_use]
    pub const fn new(
        kind: ProjectionKind,
        class: ProtectedDataClass,
        destination: ReleaseDestination,
    ) -> Self {
        Self {
            kind,
            class,
            destination,
        }
    }

    /// Returns the applied projection.
    #[must_use]
    pub const fn kind(self) -> ProjectionKind {
        self.kind
    }

    /// Returns the released class.
    #[must_use]
    pub const fn class(self) -> ProtectedDataClass {
        self.class
    }

    /// Returns the destination the value was released to.
    #[must_use]
    pub const fn destination(self) -> ReleaseDestination {
        self.destination
    }
}

/// Why one release was rejected.
///
/// The three categories are selected from declared ordinary policy and ordinary
/// accounting, never from protected contents, so a rejection never distinguishes
/// which protected bit caused it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseRejection {
    /// The declared class does not cover the value's class.
    ClassMismatch,
    /// The declared destination does not cover the requested destination.
    DestinationMismatch,
    /// The disclosure budget cannot satisfy the next charge.
    BudgetExhausted,
}

impl ReleaseRejection {
    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::ClassMismatch => "class-mismatch",
            Self::DestinationMismatch => "destination-mismatch",
            Self::BudgetExhausted => "budget-exhausted",
        }
    }
}

/// One release decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseDecision {
    /// The release was accepted and applied the named projection.
    Accepted(ReleaseProjection),
    /// The release was rejected before any projection of the value.
    Rejected(ReleaseRejection),
}

impl ReleaseDecision {
    /// Returns whether the release was accepted.
    #[must_use]
    pub const fn is_accepted(self) -> bool {
        matches!(self, Self::Accepted(_))
    }

    /// Returns the accepted projection, if any.
    #[must_use]
    pub const fn projection(self) -> Option<ReleaseProjection> {
        match self {
            Self::Accepted(projection) => Some(projection),
            Self::Rejected(_) => None,
        }
    }

    /// Returns the rejection category, if any.
    #[must_use]
    pub const fn rejection(self) -> Option<ReleaseRejection> {
        match self {
            Self::Accepted(_) => None,
            Self::Rejected(rejection) => Some(rejection),
        }
    }
}

/// The outcome recorded by release audit evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditOutcome {
    /// The release was accepted and charged.
    Accepted,
    /// The release was rejected without charge.
    Rejected,
}

impl AuditOutcome {
    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
        }
    }
}

/// One payload-independent exhaustion accounting record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExhaustionAccounting {
    /// Accepted releases charged so far.
    pub accepted: u64,
    /// Budget remaining after the last charge.
    pub remaining: u64,
    /// The charge one accepted release consumes.
    pub charge: u64,
}

/// One nonzero disclosure charge.
///
/// A charge of zero would make exhaustion unreachable and its refusal
/// non-deterministic, so zero is not representable: a charge is either absent or
/// positive, and a budget carrying it always exhausts after
/// `remaining / charge` accepted releases.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DisclosureCharge(u64);

impl DisclosureCharge {
    /// Returns one charge, or `None` when the value is zero.
    #[must_use]
    pub const fn new(value: u64) -> Option<Self> {
        if value == 0 { None } else { Some(Self(value)) }
    }

    /// Returns the charge one accepted release consumes.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }
}

/// One monotone disclosure budget, charged per accepted release.
///
/// The initial value and the charge are ordinary declared configuration, and the
/// charge is nonzero by construction. The budget is monotone: a charge can only
/// reduce the remaining budget, and exhaustion is deterministic in the ordinary
/// accounting alone, so the same state refuses every payload of the same class
/// and destination identically.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DisclosureBudget {
    remaining: u64,
    charge: DisclosureCharge,
    accepted: u64,
}

impl DisclosureBudget {
    /// Creates one budget with a declared initial value and a nonzero charge.
    #[must_use]
    pub const fn new(remaining: u64, charge: DisclosureCharge) -> Self {
        Self {
            remaining,
            charge,
            accepted: 0,
        }
    }

    /// Returns the remaining budget.
    #[must_use]
    pub const fn remaining(self) -> u64 {
        self.remaining
    }

    /// Returns the nonzero charge one accepted release consumes.
    #[must_use]
    pub const fn charge(self) -> DisclosureCharge {
        self.charge
    }

    /// Returns the number of accepted releases charged so far.
    #[must_use]
    pub const fn accepted(self) -> u64 {
        self.accepted
    }

    /// Returns whether the next charge cannot be satisfied.
    #[must_use]
    pub const fn is_exhausted(self) -> bool {
        self.remaining < self.charge.value()
    }

    /// Returns the budget after one charge, or `None` when it is exhausted.
    #[must_use]
    pub const fn after_charge(self) -> Option<Self> {
        if self.remaining < self.charge.value() {
            return None;
        }
        Some(Self {
            remaining: self.remaining - self.charge.value(),
            charge: self.charge,
            accepted: self.accepted + 1,
        })
    }

    /// Returns the payload-independent accounting published with a refusal.
    #[must_use]
    pub const fn accounting(self) -> ExhaustionAccounting {
        ExhaustionAccounting {
            accepted: self.accepted,
            remaining: self.remaining,
            charge: self.charge.value(),
        }
    }
}

/// One protected audit record emitted by an accepted release.
///
/// The evidence names the release site, the data class, the destination, the
/// projection, the budget consumption, and the outcome. It contains no payload
/// bytes, no payload encoding, and no payload-derived digest or bit, and it is
/// itself protected because it relates to protected data: it implements no
/// rendering trait and no deserializer, and its fields are reachable only
/// through [`ReleaseAuditEvidence::view`] under an [`AuditAccess`] capability.
#[derive(Clone, Eq, PartialEq)]
pub struct ReleaseAuditEvidence {
    site: Arc<str>,
    class: ProtectedDataClass,
    destination: ReleaseDestination,
    projection: ProjectionKind,
    budget_consumed: u64,
    budget_remaining: u64,
    outcome: AuditOutcome,
}

/// One capability that admits the declared view of protected audit evidence.
///
/// Audit evidence is a protected channel, so observing it is an explicit, typed
/// act rather than an ordinary field read or rendering. The protection store
/// holds this capability and issues it to the capability that governs access to
/// the stored evidence; no ordinary value, identity, or authority right mints
/// one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditAccess(());

impl AuditAccess {
    /// Returns the audit-access capability of the protection store.
    #[must_use]
    pub const fn granted() -> Self {
        Self(())
    }
}

/// The declared view of one audit record: ordinary metadata and no payload.
///
/// The view names the release site, the released class, the destination, the
/// applied projection, the budget accounting, and the outcome. It carries no
/// payload byte and no payload-derived bit, so it is ordinary settlement once
/// the applicable capability has admitted it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReleaseAuditView<'a> {
    site: &'a str,
    class: ProtectedDataClass,
    destination: ReleaseDestination,
    projection: ProjectionKind,
    budget_consumed: u64,
    budget_remaining: u64,
    outcome: AuditOutcome,
}

impl<'a> ReleaseAuditView<'a> {
    /// Returns the release site name.
    #[must_use]
    pub const fn site(self) -> &'a str {
        self.site
    }

    /// Returns the released data class.
    #[must_use]
    pub const fn class(self) -> ProtectedDataClass {
        self.class
    }

    /// Returns the destination class.
    #[must_use]
    pub const fn destination(self) -> ReleaseDestination {
        self.destination
    }

    /// Returns the applied projection.
    #[must_use]
    pub const fn projection(self) -> ProjectionKind {
        self.projection
    }

    /// Returns the budget consumed by this release.
    #[must_use]
    pub const fn budget_consumed(self) -> u64 {
        self.budget_consumed
    }

    /// Returns the budget remaining after this release.
    #[must_use]
    pub const fn budget_remaining(self) -> u64 {
        self.budget_remaining
    }

    /// Returns the recorded outcome.
    #[must_use]
    pub const fn outcome(self) -> AuditOutcome {
        self.outcome
    }

    /// Returns the canonical view text, which contains no payload bytes.
    #[must_use]
    pub fn canonical_text(self) -> String {
        format!(
            "site={};class={};destination={};projection={};consumed={};remaining={};outcome={}",
            self.site,
            self.class.wire_name(),
            self.destination.wire_name(),
            self.projection.wire_name(),
            self.budget_consumed,
            self.budget_remaining,
            self.outcome.wire_name(),
        )
    }
}

impl ReleaseAuditEvidence {
    /// Returns the declared view of this evidence under one access capability.
    ///
    /// This is the only path to the evidence's fields, so no rendering, field
    /// read, or serialization reaches them without the capability.
    #[must_use]
    pub fn view(&self, _access: &AuditAccess) -> ReleaseAuditView<'_> {
        ReleaseAuditView {
            site: &self.site,
            class: self.class,
            destination: self.destination,
            projection: self.projection,
            budget_consumed: self.budget_consumed,
            budget_remaining: self.budget_remaining,
            outcome: self.outcome,
        }
    }
}

/// One ordinary value produced by an accepted release.
///
/// A release returns an ordinary value only after it is accepted, so this type
/// has no public constructor: it is created on the accepted path alone. It
/// carries the accepted projection, its class, and its destination, and it is
/// ordinary for every later rule that governs ordinary values, which is what
/// `release to ordinary source produces a value governed by ordinary rules`
/// means here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReleasedValue {
    projection: ReleaseProjection,
}

impl ReleasedValue {
    /// Returns the accepted projection that produced this value.
    #[must_use]
    pub const fn projection(self) -> ReleaseProjection {
        self.projection
    }

    /// Returns the applied projection kind.
    #[must_use]
    pub const fn kind(self) -> ProjectionKind {
        self.projection.kind()
    }

    /// Returns the released class.
    #[must_use]
    pub const fn class(self) -> ProtectedDataClass {
        self.projection.class()
    }

    /// Returns the destination the value was released to.
    #[must_use]
    pub const fn destination(self) -> ReleaseDestination {
        self.projection.destination()
    }

    /// Returns whether this value is protected, which is never true.
    #[must_use]
    pub const fn is_protected(self) -> bool {
        false
    }

    /// Returns whether this value is ordinary, which is always true.
    #[must_use]
    pub const fn is_ordinary(self) -> bool {
        true
    }
}

/// One release attempt, with the ordinary value, budget, and evidence it produced.
///
/// The carried budget makes the check order observable: a rejected release leaves
/// the budget exactly as it was, produces no ordinary value, and emits no audit
/// evidence, because no projection and no charge occurred. The evidence itself is
/// not carried out of the attempt: only its declared view is, and only under an
/// [`AuditAccess`] capability.
#[derive(Clone, Eq, PartialEq)]
pub struct ReleaseOutcome {
    decision: ReleaseDecision,
    budget: DisclosureBudget,
    released: Option<ReleasedValue>,
    evidence: Option<ReleaseAuditEvidence>,
}

impl ReleaseOutcome {
    /// Builds one rejected outcome with an uncharged budget.
    const fn rejected(rejection: ReleaseRejection, budget: DisclosureBudget) -> Self {
        Self {
            decision: ReleaseDecision::Rejected(rejection),
            budget,
            released: None,
            evidence: None,
        }
    }

    /// Returns the release decision.
    #[must_use]
    pub const fn decision(&self) -> ReleaseDecision {
        self.decision
    }

    /// Returns the accepted projection, if the release was accepted.
    #[must_use]
    pub const fn projection(&self) -> Option<ReleaseProjection> {
        self.decision.projection()
    }

    /// Returns the budget state after the attempt.
    #[must_use]
    pub const fn budget(&self) -> DisclosureBudget {
        self.budget
    }

    /// Returns the ordinary value of an accepted release, if any.
    ///
    /// A rejected release produces no ordinary value, so an ordinary value never
    /// exists before acceptance.
    #[must_use]
    pub const fn released_value(&self) -> Option<ReleasedValue> {
        self.released
    }

    /// Returns the declared view of the audit evidence of an accepted release.
    ///
    /// Evidence is reachable only through the supplied capability.
    #[must_use]
    pub fn audit_view(&self, access: &AuditAccess) -> Option<ReleaseAuditView<'_>> {
        self.evidence.as_ref().map(|evidence| evidence.view(access))
    }
}

/// One declared release site.
///
/// The site declares its data-class and destination pairs, and its projections,
/// before any evaluation. Release checks the declarations, the grant, and the
/// budget in that order and only then produces a projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseSite {
    name: Arc<str>,
    declared: BTreeSet<(ProtectedDataClass, ReleaseDestination, ProjectionKind)>,
}

impl ReleaseSite {
    /// Creates one release site with no declared pair.
    #[must_use]
    pub fn new(name: &str) -> Self {
        Self {
            name: Arc::from(name),
            declared: BTreeSet::new(),
        }
    }

    /// Declares one data-class, destination, and projection triple.
    #[must_use]
    pub fn declare(
        mut self,
        class: ProtectedDataClass,
        destination: ReleaseDestination,
        projection: ProjectionKind,
    ) -> Self {
        self.declared.insert((class, destination, projection));
        self
    }

    /// Returns the declared site name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns whether this site declares the class with any destination.
    #[must_use]
    pub fn declares_class(&self, class: ProtectedDataClass) -> bool {
        self.declared
            .iter()
            .any(|(declared, _, _)| *declared == class)
    }

    /// Returns whether this site declares the exact class and destination pair.
    #[must_use]
    pub fn declares(&self, class: ProtectedDataClass, destination: ReleaseDestination) -> bool {
        self.projection(class, destination).is_some()
    }

    /// Returns the declared projection of one class and destination pair.
    #[must_use]
    pub fn projection(
        &self,
        class: ProtectedDataClass,
        destination: ReleaseDestination,
    ) -> Option<ProjectionKind> {
        self.declared
            .iter()
            .find(|(declared, declared_destination, _)| {
                *declared == class && *declared_destination == destination
            })
            .map(|(_, _, projection)| *projection)
    }

    /// Evaluates one release of one protected value.
    ///
    /// The declaration check, class applicability, destination applicability,
    /// the grant's declared release site, and budget exhaustion all precede any
    /// projection of the value, so a rejection is payload-independent and never
    /// charges the budget. A grant derived by an authority bound to another site
    /// is refused as a [`ReleaseRejection::DestinationMismatch`].
    #[must_use]
    pub fn release(
        &self,
        grant: &ReleaseGrant,
        value: &ProtectedValue,
        destination: ReleaseDestination,
        budget: &mut DisclosureBudget,
    ) -> ReleaseOutcome {
        let class = value.class();
        if !self.declares_class(class) || !grant.contains_class(class) {
            return ReleaseOutcome::rejected(ReleaseRejection::ClassMismatch, *budget);
        }
        let Some(projection) = self.projection(class, destination) else {
            return ReleaseOutcome::rejected(ReleaseRejection::DestinationMismatch, *budget);
        };
        if !grant.contains_destination(destination) {
            return ReleaseOutcome::rejected(ReleaseRejection::DestinationMismatch, *budget);
        }
        // A grant carries the release site of the authority that derived it, so
        // it does not authorize another site's declaration. In the closed
        // rejection vocabulary that is a destination mismatch, and it is decided
        // here before any charge or projection of the payload.
        if grant.site() != self.name() {
            return ReleaseOutcome::rejected(ReleaseRejection::DestinationMismatch, *budget);
        }
        let Some(charged) = budget.after_charge() else {
            return ReleaseOutcome::rejected(ReleaseRejection::BudgetExhausted, *budget);
        };
        let evidence = ReleaseAuditEvidence {
            site: Arc::clone(&self.name),
            class,
            destination,
            projection,
            budget_consumed: budget.charge().value(),
            budget_remaining: charged.remaining(),
            outcome: AuditOutcome::Accepted,
        };
        let released = ReleaseProjection::new(projection, class, destination);
        *budget = charged;
        ReleaseOutcome {
            decision: ReleaseDecision::Accepted(released),
            budget: charged,
            released: Some(ReleasedValue {
                projection: released,
            }),
            evidence: Some(evidence),
        }
    }
}

/// One finite release permission derived from one holder authority.
///
/// A grant narrows like a rights set: attenuation intersects, so it can only
/// remove permission. A grant is not an authority instance and has no free
/// constructor and no deserializer: only a [`ReleaseHolderAuthority`] derives
/// one, no authority right and no instance substitutes for it, and holding
/// authority over an operation that handles protected data never creates release
/// permission. A grant is derived from one holder authority and carries that
/// authority's declared release site, so it authorizes releases only at that
/// site.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseGrant {
    holder: ReleaseHolderId,
    binding: ReleaseHolderBindingId,
    classes: BTreeSet<ProtectedDataClass>,
    destinations: BTreeSet<ReleaseDestination>,
}

impl ReleaseGrant {
    /// Returns the holder identity this grant was derived from.
    #[must_use]
    pub const fn holder(&self) -> &ReleaseHolderId {
        &self.holder
    }

    /// Returns whether the grant permits nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.classes.is_empty() || self.destinations.is_empty()
    }

    /// Returns the number of declared classes.
    #[must_use]
    pub fn class_count(&self) -> usize {
        self.classes.len()
    }

    /// Returns the number of declared destinations.
    #[must_use]
    pub fn destination_count(&self) -> usize {
        self.destinations.len()
    }

    /// Returns whether the grant names one class.
    #[must_use]
    pub fn contains_class(&self, class: ProtectedDataClass) -> bool {
        self.classes.contains(&class)
    }

    /// Returns whether the grant names one destination.
    #[must_use]
    pub fn contains_destination(&self, destination: ReleaseDestination) -> bool {
        self.destinations.contains(&destination)
    }

    /// Returns whether the grant covers one complete pair.
    #[must_use]
    pub fn covers(&self, class: ProtectedDataClass, destination: ReleaseDestination) -> bool {
        self.contains_class(class) && self.contains_destination(destination)
    }

    /// Returns the downstream integration binding this grant was derived under.
    ///
    /// The binding names the declared release site of the authority that derived
    /// the grant.
    #[must_use]
    pub const fn binding(&self) -> &ReleaseHolderBindingId {
        &self.binding
    }

    /// Returns the declared release site this grant was derived for.
    ///
    /// A release site other than this one is not authorized by the grant, so a
    /// caller can ask a grant where it may be used without evaluating a release.
    #[must_use]
    pub fn site(&self) -> &str {
        self.binding.site()
    }

    /// Returns the declared classes in reporting order.
    pub fn classes(&self) -> impl Iterator<Item = ProtectedDataClass> + '_ {
        PROTECTED_DATA_CLASS_ORDER
            .into_iter()
            .filter(|class| self.contains_class(*class))
    }

    /// Returns the declared destinations in reporting order.
    pub fn destinations(&self) -> impl Iterator<Item = ReleaseDestination> + '_ {
        RELEASE_DESTINATION_ORDER
            .into_iter()
            .filter(|destination| self.contains_destination(*destination))
    }

    /// Returns whether every pair of this grant is also a pair of `other`.
    #[must_use]
    pub fn is_subset_of(&self, other: &Self) -> bool {
        self.classes.is_subset(&other.classes) && self.destinations.is_subset(&other.destinations)
    }

    /// Returns whether this grant is a strict subset of `other`.
    #[must_use]
    pub fn is_strict_subset_of(&self, other: &Self) -> bool {
        self.is_subset_of(other) && self != other
    }

    /// Returns the intersection of two grants, which only narrows permission.
    ///
    /// The result keeps the holder and the declared release site of `self`, so
    /// attenuation never moves a grant to another site.
    #[must_use]
    pub fn attenuate(&self, other: &Self) -> Self {
        Self {
            holder: self.holder.clone(),
            binding: self.binding.clone(),
            classes: self.classes.intersection(&other.classes).copied().collect(),
            destinations: self
                .destinations
                .intersection(&other.destinations)
                .copied()
                .collect(),
        }
    }
}

/// One canonical release-holder identity.
///
/// The identity is a domain-separated SHA-256 digest over the declared release
/// site, the downstream integration binding that owns the holder, and the
/// declared class and destination sets. It has no public constructor and no
/// deserializer, so it cannot be built from an ordinary representation of a
/// holder.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ReleaseHolderId(Arc<str>);

impl ReleaseHolderId {
    /// Derives one holder identity from a binding and one declared permission.
    fn derive(
        binding: &ReleaseHolderBindingId,
        classes: &BTreeSet<ProtectedDataClass>,
        destinations: &BTreeSet<ReleaseDestination>,
    ) -> Self {
        let class_text = PROTECTED_DATA_CLASS_ORDER
            .into_iter()
            .filter(|class| classes.contains(class))
            .map(ProtectedDataClass::wire_name)
            .collect::<Vec<_>>()
            .join(",");
        let destination_text = RELEASE_DESTINATION_ORDER
            .into_iter()
            .filter(|destination| destinations.contains(destination))
            .map(ReleaseDestination::wire_name)
            .collect::<Vec<_>>()
            .join(",");
        let digest = digest_fields(
            RELEASE_HOLDER_DOMAIN,
            &[
                binding.as_str().as_bytes(),
                class_text.as_bytes(),
                destination_text.as_bytes(),
            ],
        );
        Self(Arc::from(format!("release-holder:{}", encode_hex(&digest))))
    }

    /// Returns the exact portable identity spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the lowercase digest text without the identity prefix.
    #[must_use]
    pub fn digest_hex(&self) -> &str {
        self.0.strip_prefix("release-holder:").unwrap_or(&self.0)
    }
}

/// One downstream integration binding that owns release-holder identity.
///
/// A release holder is an integration artifact: the binding names the declared
/// release site and the selected implementation identity that owns the holder,
/// and it is owned downstream of this model.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseHolderBindingId {
    site: Arc<str>,
    text: Arc<str>,
}

impl ReleaseHolderBindingId {
    /// Constructs the binding of one declared release site to the downstream
    /// integration that owns the holder.
    #[must_use]
    pub fn new(site: &DeclaredName, integration: &CanonicalImplementationIdentity) -> Self {
        Self {
            site: Arc::from(site.as_str()),
            text: Arc::from(format!(
                "release-holder-binding:{}:{}",
                encode_text(site.as_str()),
                encode_text(integration.as_str())
            )),
        }
    }

    /// Returns the declared release site of this binding.
    #[must_use]
    pub fn site(&self) -> &str {
        &self.site
    }

    /// Returns the exact portable binding spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }
}

/// Why one release-holder authority was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseAuthorityError {
    /// The integration binding names another release site.
    SiteMismatch,
}

impl ReleaseAuthorityError {
    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::SiteMismatch => "site-mismatch",
        }
    }
}

/// One release-holder authority: the declared site, the integration binding, and
/// the class and destination sets the holder may release.
///
/// Holder authority is independently required for a release, and it is the only
/// source of a [`ReleaseGrant`]. The type is opaque: it has no public byte
/// constructor and no deserializer, so an ordinary value cannot be turned into
/// release authority, and attenuation of authority only narrows it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseHolderAuthority {
    id: ReleaseHolderId,
    binding: ReleaseHolderBindingId,
    classes: BTreeSet<ProtectedDataClass>,
    destinations: BTreeSet<ReleaseDestination>,
}

impl ReleaseHolderAuthority {
    /// Binds one declared release site to the integration that holds authority
    /// over it, with the class and destination sets it may release.
    ///
    /// Returns `Err(ReleaseAuthorityError::SiteMismatch)` when the binding names
    /// another site. An empty class or destination set grants nothing, which is
    /// how a holder that may release nothing is expressed.
    pub fn bind(
        site: &DeclaredName,
        binding: ReleaseHolderBindingId,
        classes: &[ProtectedDataClass],
        destinations: &[ReleaseDestination],
    ) -> Result<Self, ReleaseAuthorityError> {
        if binding.site() != site.as_str() {
            return Err(ReleaseAuthorityError::SiteMismatch);
        }
        let classes = classes.iter().copied().collect::<BTreeSet<_>>();
        let destinations = destinations.iter().copied().collect::<BTreeSet<_>>();
        let id = ReleaseHolderId::derive(&binding, &classes, &destinations);
        Ok(Self {
            id,
            binding,
            classes,
            destinations,
        })
    }

    /// Returns the canonical holder identity.
    #[must_use]
    pub const fn id(&self) -> &ReleaseHolderId {
        &self.id
    }

    /// Returns the downstream integration binding.
    #[must_use]
    pub const fn binding(&self) -> &ReleaseHolderBindingId {
        &self.binding
    }

    /// Returns the declared release site.
    #[must_use]
    pub fn site(&self) -> &str {
        self.binding.site()
    }

    /// Returns the declared classes in reporting order.
    pub fn classes(&self) -> impl Iterator<Item = ProtectedDataClass> + '_ {
        PROTECTED_DATA_CLASS_ORDER
            .into_iter()
            .filter(|class| self.classes.contains(class))
    }

    /// Returns the declared destinations in reporting order.
    pub fn destinations(&self) -> impl Iterator<Item = ReleaseDestination> + '_ {
        RELEASE_DESTINATION_ORDER
            .into_iter()
            .filter(|destination| self.destinations.contains(destination))
    }

    /// Returns whether this authority grants nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.classes.is_empty() || self.destinations.is_empty()
    }

    /// Returns the release grant of this authority.
    ///
    /// This is the only way to obtain a [`ReleaseGrant`]: a grant is derived from
    /// holder authority alone, and no authority right, authority instance,
    /// ordinary value, or deserializer produces one.
    #[must_use]
    pub fn grant(&self) -> ReleaseGrant {
        ReleaseGrant {
            holder: self.id.clone(),
            binding: self.binding.clone(),
            classes: self.classes.clone(),
            destinations: self.destinations.clone(),
        }
    }

    /// Returns the authority that may release only the named classes and
    /// destinations of this authority, which is always a narrowing.
    #[must_use]
    pub fn attenuate(
        &self,
        classes: &[ProtectedDataClass],
        destinations: &[ReleaseDestination],
    ) -> Self {
        let classes = classes
            .iter()
            .copied()
            .filter(|class| self.classes.contains(class))
            .collect::<BTreeSet<_>>();
        let destinations = destinations
            .iter()
            .copied()
            .filter(|destination| self.destinations.contains(destination))
            .collect::<BTreeSet<_>>();
        let id = ReleaseHolderId::derive(&self.binding, &classes, &destinations);
        Self {
            id,
            binding: self.binding.clone(),
            classes,
            destinations,
        }
    }
}

/// One frozen per-event delivery permission, captured at event creation.
///
/// The transport side owns this decision: the frozen sink and class set decide
/// whether a protected payload class may reach a sink, recovery must not
/// re-decide them from current configuration, and no release decision widens or
/// overrides them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrozenDeliveryPermission {
    sink: ReleaseDestination,
    classes: BTreeSet<ProtectedDataClass>,
}

impl FrozenDeliveryPermission {
    /// Freezes one permitted sink and class set at event creation.
    #[must_use]
    pub fn frozen(sink: ReleaseDestination, classes: &[ProtectedDataClass]) -> Self {
        Self {
            sink,
            classes: classes.iter().copied().collect(),
        }
    }

    /// Returns the frozen sink.
    #[must_use]
    pub const fn sink(&self) -> ReleaseDestination {
        self.sink
    }

    /// Returns whether the frozen permission admits one protected payload class.
    ///
    /// The answer depends only on the captured set, never on current
    /// configuration or on a later release decision.
    #[must_use]
    pub fn admits(&self, class: ProtectedDataClass) -> bool {
        self.classes.contains(&class)
    }

    /// Decides delivery for one release outcome, separately from the release
    /// decision.
    ///
    /// Delivery is denied when no release was accepted, when the frozen
    /// permission does not admit the value's class, or when the transport sink is
    /// not the destination class the release declared. An admission therefore
    /// never widens a declared destination class, and an accepted release never
    /// overrides a frozen permission that denies access.
    #[must_use]
    pub fn deliver(
        &self,
        outcome: &ReleaseOutcome,
        value: &ProtectedValue,
        sink: ReleaseDestination,
    ) -> DeliveryDecision {
        let Some(projection) = outcome.projection() else {
            return DeliveryDecision::Denied(DeliveryDenial::NoAcceptedRelease);
        };
        if sink != self.sink || projection.destination() != self.sink {
            return DeliveryDecision::Denied(DeliveryDenial::DestinationWidened);
        }
        if !self.admits(value.class()) {
            return DeliveryDecision::Denied(DeliveryDenial::FrozenPermissionDenies);
        }
        DeliveryDecision::Delivered
    }
}

/// The transport-side delivery decision of one release outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryDecision {
    /// The frozen permission admitted the payload class and the declared
    /// destination, and an accepted release covered the payload.
    Delivered,
    /// The transport side denied delivery.
    Denied(DeliveryDenial),
}

impl DeliveryDecision {
    /// Returns whether the payload class may reach the sink.
    #[must_use]
    pub const fn is_delivered(self) -> bool {
        matches!(self, Self::Delivered)
    }

    /// Returns the transport denial, if any.
    #[must_use]
    pub const fn denial(self) -> Option<DeliveryDenial> {
        match self {
            Self::Delivered => None,
            Self::Denied(denial) => Some(denial),
        }
    }
}

/// Why the transport side denied delivery.
///
/// These are not release rejection categories: a release rejection is selected
/// from the declared class, the declared destination, and the budget, while a
/// transport denial is decided by the frozen permission captured at event
/// creation and by the absence of an accepted release.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryDenial {
    /// No accepted release covers the payload.
    NoAcceptedRelease,
    /// The frozen permission does not admit the payload class.
    FrozenPermissionDenies,
    /// The transport sink is not the destination class the release declared.
    DestinationWidened,
}

impl DeliveryDenial {
    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::NoAcceptedRelease => "no-accepted-release",
            Self::FrozenPermissionDenies => "frozen-permission-denies",
            Self::DestinationWidened => "destination-widened",
        }
    }
}

/// All semantic-envelope observations in the fixed reporting order of this
/// module.
pub const ENVELOPE_OBSERVATION_ORDER: [EnvelopeObservation; 10] = [
    EnvelopeObservation::SuccessOrFailure,
    EnvelopeObservation::ResultVariant,
    EnvelopeObservation::OutputPresence,
    EnvelopeObservation::OutputSize,
    EnvelopeObservation::DiagnosticText,
    EnvelopeObservation::RetryDecision,
    EnvelopeObservation::ReadinessOrder,
    EnvelopeObservation::TaskOrChannelOutcome,
    EnvelopeObservation::Termination,
    EnvelopeObservation::SemanticQuotaCharge,
];

/// One language-visible consequence of an operation over protected inputs.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum EnvelopeObservation {
    /// Success or failure of the operation.
    SuccessOrFailure,
    /// The chosen result variant.
    ResultVariant,
    /// Whether an output was produced.
    OutputPresence,
    /// How large a produced output is.
    OutputSize,
    /// Diagnostic text and its subject.
    DiagnosticText,
    /// The retry decision and any recorded cause.
    RetryDecision,
    /// Readiness or ordering among observations.
    ReadinessOrder,
    /// The outcome of a task or channel operation.
    TaskOrChannelOutcome,
    /// Termination and its reason.
    Termination,
    /// Any semantic quota charge.
    SemanticQuotaCharge,
}

impl EnvelopeObservation {
    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::SuccessOrFailure => "success-or-failure",
            Self::ResultVariant => "result-variant",
            Self::OutputPresence => "output-presence",
            Self::OutputSize => "output-size",
            Self::DiagnosticText => "diagnostic-text",
            Self::RetryDecision => "retry-decision",
            Self::ReadinessOrder => "readiness-order",
            Self::TaskOrChannelOutcome => "task-or-channel-outcome",
            Self::Termination => "termination",
            Self::SemanticQuotaCharge => "semantic-quota-charge",
        }
    }

    /// Strictly decodes one exact portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        ENVELOPE_OBSERVATION_ORDER
            .into_iter()
            .find(|observation| observation.wire_name() == value)
    }
}

/// The classification of one envelope observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnvelopeClause {
    /// A protected clause, whose classification is selected from protected
    /// contents.
    Protected,
    /// An ordinary clause, provably independent of protected contents.
    OrdinaryPayloadIndependent,
}

impl EnvelopeClause {
    /// Returns whether this clause is protected.
    #[must_use]
    pub const fn is_protected(self) -> bool {
        matches!(self, Self::Protected)
    }

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Protected => "protected",
            Self::OrdinaryPayloadIndependent => "ordinary-payload-independent",
        }
    }
}

/// Why one protection-preserving declaration was refused.
///
/// A refusal names the language-visible consequences the declaration left
/// unclassified. Each of them is treated as protected, so a refusal never
/// publishes an ordinary classification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvelopeRejection {
    unclassified: Vec<EnvelopeObservation>,
}

impl EnvelopeRejection {
    /// Returns the language-visible consequences left unclassified.
    #[must_use]
    pub fn unclassified(&self) -> &[EnvelopeObservation] {
        &self.unclassified
    }
}

/// One semantic envelope: a classification per observation.
///
/// An observation the contract leaves unclassified is treated as protected, so
/// an incomplete envelope never lowers a classification.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SemanticEnvelope {
    classified: BTreeMap<EnvelopeObservation, EnvelopeClause>,
}

impl SemanticEnvelope {
    /// Creates one empty envelope.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds or replaces one declared classification.
    #[must_use]
    pub fn classify(mut self, observation: EnvelopeObservation, clause: EnvelopeClause) -> Self {
        self.classified.insert(observation, clause);
        self
    }

    /// Returns the declared classification of one observation, if any.
    #[must_use]
    pub fn declared(&self, observation: EnvelopeObservation) -> Option<EnvelopeClause> {
        self.classified.get(&observation).copied()
    }

    /// Returns the effective classification, defaulting to protected.
    #[must_use]
    pub fn effective(&self, observation: EnvelopeObservation) -> EnvelopeClause {
        self.declared(observation)
            .unwrap_or(EnvelopeClause::Protected)
    }

    /// Returns whether every observation is classified.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.unclassified().is_empty()
    }

    /// Returns the observations this envelope leaves unclassified.
    #[must_use]
    pub fn unclassified(&self) -> Vec<EnvelopeObservation> {
        ENVELOPE_OBSERVATION_ORDER
            .into_iter()
            .filter(|observation| self.declared(*observation).is_none())
            .collect()
    }
}

/// The outcome of one emergency-cleanup run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CleanupOutcome {
    /// Every requested value was consumed.
    Completed,
    /// The declared work bound stopped the run early.
    Bounded,
    /// The existing authority and budget refused the run.
    Refused,
    /// The run was interrupted.
    Interrupted,
}

impl CleanupOutcome {
    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Bounded => "bounded",
            Self::Refused => "refused",
            Self::Interrupted => "interrupted",
        }
    }
}

/// One payload-independent cleanup report.
///
/// The report is ordinary settlement computed from ordinary accounting. It names
/// the outcome and the ordinary booleans only: the number, the size, and the
/// class distribution of the values cleanup consumed are not observable from it,
/// and no payload and no payload-derived bit appears in it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CleanupReport {
    outcome: CleanupOutcome,
    callbacks_invoked: bool,
    source_semantics_changed: bool,
    durable_prefix_only: bool,
}

impl CleanupReport {
    /// Returns the ordinary settlement of one cleanup outcome.
    const fn settled(outcome: CleanupOutcome) -> Self {
        Self {
            outcome,
            callbacks_invoked: false,
            source_semantics_changed: false,
            durable_prefix_only: true,
        }
    }

    /// Returns the cleanup outcome.
    #[must_use]
    pub const fn outcome(self) -> CleanupOutcome {
        self.outcome
    }

    /// Returns whether a source callback ran, which is never true.
    #[must_use]
    pub const fn callbacks_invoked(self) -> bool {
        self.callbacks_invoked
    }

    /// Returns whether cleanup changed source semantics, which is never true.
    #[must_use]
    pub const fn source_semantics_changed(self) -> bool {
        self.source_semantics_changed
    }

    /// Returns whether recovery promises only the durable prefix.
    #[must_use]
    pub const fn durable_prefix_only(self) -> bool {
        self.durable_prefix_only
    }
}

/// Sealed emergency cleanup of protected values.
///
/// Cleanup runs with no source callback, no source-visible scope, and no
/// declassification. It may release only to the pre-declared null destination
/// under authority that already exists, it never acquires or extends release
/// authority, and it is bounded in time and work so that the protection layer
/// cannot stall an interpreter indefinitely.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EmergencyCleanup {
    budget: DisclosureBudget,
    work_limit: u64,
}

impl EmergencyCleanup {
    /// Creates one sealed cleanup with an existing budget and work bound.
    #[must_use]
    pub const fn sealed(budget: DisclosureBudget, work_limit: u64) -> Self {
        Self { budget, work_limit }
    }

    /// Returns the only destination cleanup may use, which is the null one.
    #[must_use]
    pub const fn destination(self) -> ReleaseDestination {
        ReleaseDestination::NullTelemetry
    }

    /// Returns whether cleanup accepts a source callback, which is never true.
    #[must_use]
    pub const fn accepts_source_callback(self) -> bool {
        false
    }

    /// Returns whether cleanup may declassify a protected value, never true.
    #[must_use]
    pub const fn declassifies(self) -> bool {
        false
    }

    /// Returns whether cleanup may acquire or extend release authority, never
    /// true.
    #[must_use]
    pub const fn extends_authority(self) -> bool {
        false
    }

    /// Returns the declared work bound.
    #[must_use]
    pub const fn work_limit(self) -> u64 {
        self.work_limit
    }

    /// Runs cleanup over the supplied protected values.
    ///
    /// Only the declared work bound and the ordinary budget accounting decide the
    /// outcome, so two runs over different classes and different values produce
    /// the same report, and the report never publishes how many values were
    /// consumed. The charge of the existing budget is nonzero by construction, so
    /// the run is refused deterministically once the budget cannot charge it.
    #[must_use]
    pub fn run(self, values: &[&ProtectedValue]) -> CleanupReport {
        let requested = values.len() as u64;
        if requested == 0 {
            return CleanupReport::settled(CleanupOutcome::Completed);
        }
        let bounded = requested.min(self.work_limit);
        let affordable = bounded.min(self.budget.remaining() / self.budget.charge().value());
        if affordable == 0 {
            return CleanupReport::settled(CleanupOutcome::Refused);
        }
        CleanupReport::settled(if affordable < requested {
            CleanupOutcome::Bounded
        } else {
            CleanupOutcome::Completed
        })
    }

    /// Reports one cleanup interrupted before completion.
    ///
    /// The report carries the outcome and the ordinary booleans only, so an
    /// interrupted run publishes neither the number nor the class distribution of
    /// the values it consumed.
    #[must_use]
    pub const fn interrupted() -> CleanupReport {
        CleanupReport::settled(CleanupOutcome::Interrupted)
    }
}

/// All component kinds that owe a non-erasure obligation.
pub const NON_ERASURE_COMPONENT_ORDER: [NonErasureComponentKind; 7] = [
    NonErasureComponentKind::Codec,
    NonErasureComponentKind::Diagnostic,
    NonErasureComponentKind::Event,
    NonErasureComponentKind::DependencyEdge,
    NonErasureComponentKind::Tool,
    NonErasureComponentKind::ProviderAdapter,
    NonErasureComponentKind::GeneratedSchema,
];

/// One closed component kind that must not erase protection.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum NonErasureComponentKind {
    /// A codec that could round-trip a protected value.
    Codec,
    /// A diagnostic that could render one.
    Diagnostic,
    /// An event that could carry one.
    Event,
    /// A dependency edge that could treat one as an ordinary value.
    DependencyEdge,
    /// A tool that could inspect one.
    Tool,
    /// A provider adapter that could receive one.
    ProviderAdapter,
    /// A generated schema that could declare one as an ordinary wire field.
    GeneratedSchema,
}

impl NonErasureComponentKind {
    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Codec => "codec",
            Self::Diagnostic => "diagnostic",
            Self::Event => "event",
            Self::DependencyEdge => "dependency-edge",
            Self::Tool => "tool",
            Self::ProviderAdapter => "provider-adapter",
            Self::GeneratedSchema => "generated-schema",
        }
    }

    /// Strictly decodes one exact portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        NON_ERASURE_COMPONENT_ORDER
            .into_iter()
            .find(|kind| kind.wire_name() == value)
    }
}

/// The proof one component's contract claims for its non-erasure obligation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NonErasureClaim {
    /// The component cannot be reached with a protected value.
    UnreachableWithProtectedValue,
    /// The component's contract keeps the value protected.
    ProtectionPreserving,
    /// The component is an ordinary-data component.
    NotApplicable,
}

/// The status of one non-erasure obligation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NonErasureStatus {
    /// No citable evidence is attached, so the component is unproven.
    Unproven,
    /// Citable evidence shows the component cannot be reached with a protected value.
    UnreachableWithProtectedValue,
    /// Citable evidence shows the component's contract keeps the value protected.
    ProtectionPreserving,
    /// Citable evidence and its own justification show the component handles
    /// ordinary data only.
    NotApplicable,
}

impl NonErasureStatus {
    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Unproven => "unproven",
            Self::UnreachableWithProtectedValue => "unreachable-with-protected-value",
            Self::ProtectionPreserving => "protection-preserving",
            Self::NotApplicable => "not-applicable",
        }
    }

    /// Returns whether this status reports a proven component.
    ///
    /// [`Self::Unproven`] is never proven.
    #[must_use]
    pub const fn is_proven(self) -> bool {
        !matches!(self, Self::Unproven)
    }
}

/// One non-erasure obligation of one component.
///
/// The obligation is a negative-evidence obligation: it stays
/// [`NonErasureStatus::Unproven`] until citable evidence is attached, an unproven
/// component is never reported as safe, and an absence of observed leakage is not
/// evidence of non-erasure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NonErasureObligation {
    kind: NonErasureComponentKind,
    subject: Arc<str>,
    claim: NonErasureClaim,
    justification: Option<Arc<str>>,
    evidence: Vec<Arc<str>>,
}

impl NonErasureObligation {
    /// Opens one obligation for one declared component.
    ///
    /// The obligation starts unproven with no evidence and no justification.
    #[must_use]
    pub fn open(kind: NonErasureComponentKind, subject: &str) -> Self {
        Self {
            kind,
            subject: Arc::from(subject),
            claim: NonErasureClaim::ProtectionPreserving,
            justification: None,
            evidence: Vec::new(),
        }
    }

    /// Opens one obligation whose contract claims to keep protection.
    #[must_use]
    pub fn protection_preserving(kind: NonErasureComponentKind, subject: &str) -> Self {
        Self::open(kind, subject)
    }

    /// Opens one obligation whose component is shown unreachable with a protected
    /// value.
    #[must_use]
    pub fn unreachable(kind: NonErasureComponentKind, subject: &str) -> Self {
        Self {
            claim: NonErasureClaim::UnreachableWithProtectedValue,
            ..Self::open(kind, subject)
        }
    }

    /// Opens one obligation for an ordinary-data component, which needs its own
    /// justification.
    ///
    /// Returns `None` when the justification is empty: the ordinary-data case is a
    /// claim about one component, never a default.
    #[must_use]
    pub fn not_applicable(
        kind: NonErasureComponentKind,
        subject: &str,
        justification: &str,
    ) -> Option<Self> {
        if justification.is_empty() {
            return None;
        }
        Some(Self {
            claim: NonErasureClaim::NotApplicable,
            justification: Some(Arc::from(justification)),
            ..Self::open(kind, subject)
        })
    }

    /// Attaches one citable evidence anchor and returns the updated obligation.
    ///
    /// An empty anchor is not evidence and changes nothing.
    #[must_use]
    pub fn with_evidence(mut self, evidence: &str) -> Self {
        if !evidence.is_empty() {
            self.evidence.push(Arc::from(evidence));
        }
        self
    }

    /// Returns the component kind.
    #[must_use]
    pub const fn kind(&self) -> NonErasureComponentKind {
        self.kind
    }

    /// Returns the declared component subject.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Returns the cited evidence anchors.
    #[must_use]
    pub fn evidence(&self) -> &[Arc<str>] {
        &self.evidence
    }

    /// Returns the ordinary-data justification, if one was declared.
    #[must_use]
    pub fn justification(&self) -> Option<&str> {
        self.justification.as_deref()
    }

    /// Returns the status of this obligation.
    ///
    /// An obligation with no evidence is unproven whatever it claims, and an
    /// ordinary-data claim without its own justification is unproven too.
    #[must_use]
    pub fn status(&self) -> NonErasureStatus {
        if self.evidence.is_empty() {
            return NonErasureStatus::Unproven;
        }
        match self.claim {
            NonErasureClaim::UnreachableWithProtectedValue => {
                NonErasureStatus::UnreachableWithProtectedValue
            }
            NonErasureClaim::ProtectionPreserving => NonErasureStatus::ProtectionPreserving,
            NonErasureClaim::NotApplicable if self.justification.is_some() => {
                NonErasureStatus::NotApplicable
            }
            NonErasureClaim::NotApplicable => NonErasureStatus::Unproven,
        }
    }

    /// Returns whether this obligation is reported as safe.
    ///
    /// This is the only safety report the model offers, and it is never true for
    /// an unproven component.
    #[must_use]
    pub fn is_reported_safe(&self) -> bool {
        self.status().is_proven()
    }
}

/// Whether one excluded claim is a property the bounded claim does not promise or
/// a practice it prohibits.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ExcludedClaimKind {
    /// A stronger property the bounded claim does not promise.
    NotPromised,
    /// A practice the bounded claim prohibits.
    Prohibited,
}

impl ExcludedClaimKind {
    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::NotPromised => "not-promised",
            Self::Prohibited => "prohibited",
        }
    }
}

/// One exact claim the bounded claim of `GNT-15.10` excludes.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ExcludedProtectionClaimName {
    /// The section does not promise full noninterference after release.
    FullNoninterferenceAfterRelease,
    /// It does not promise a physical or microarchitectural side-channel
    /// guarantee.
    PhysicalSideChannels,
    /// It prohibits declassifying a protected value without a declared release.
    ImplicitDeclassification,
    /// It prohibits equating operation authority with release authority.
    AuthorityIsReleaseAuthority,
}

impl ExcludedProtectionClaimName {
    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::FullNoninterferenceAfterRelease => "full-noninterference-after-release",
            Self::PhysicalSideChannels => "physical-side-channels",
            Self::ImplicitDeclassification => "implicit-declassification",
            Self::AuthorityIsReleaseAuthority => "authority-is-release-authority",
        }
    }
}

/// One excluded protection claim, of one exact kind and one exact name.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ExcludedProtectionClaim {
    kind: ExcludedClaimKind,
    name: ExcludedProtectionClaimName,
}

impl ExcludedProtectionClaim {
    /// Returns whether this claim is a property the bounded claim does not
    /// promise.
    #[must_use]
    pub const fn is_not_promised(self) -> bool {
        matches!(self.kind, ExcludedClaimKind::NotPromised)
    }

    /// Returns whether this claim is a practice the bounded claim prohibits.
    #[must_use]
    pub const fn is_prohibited(self) -> bool {
        matches!(self.kind, ExcludedClaimKind::Prohibited)
    }

    /// Returns the kind of exclusion.
    #[must_use]
    pub const fn kind(self) -> ExcludedClaimKind {
        self.kind
    }

    /// Returns the exact claim name.
    #[must_use]
    pub const fn name(self) -> ExcludedProtectionClaimName {
        self.name
    }

    /// Returns the exact portable spelling of the excluded claim.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        self.name.wire_name()
    }
}

/// All claims the bounded claim of `GNT-15.10` excludes: two stronger properties
/// it does not promise and two practices it prohibits.
///
/// The order is a fixed presentation order: the two un-promised properties come
/// first and the two prohibitions follow them.
pub const EXCLUDED_PROTECTION_CLAIMS: [ExcludedProtectionClaim; 4] = [
    ExcludedProtectionClaim {
        kind: ExcludedClaimKind::NotPromised,
        name: ExcludedProtectionClaimName::FullNoninterferenceAfterRelease,
    },
    ExcludedProtectionClaim {
        kind: ExcludedClaimKind::NotPromised,
        name: ExcludedProtectionClaimName::PhysicalSideChannels,
    },
    ExcludedProtectionClaim {
        kind: ExcludedClaimKind::Prohibited,
        name: ExcludedProtectionClaimName::ImplicitDeclassification,
    },
    ExcludedProtectionClaim {
        kind: ExcludedClaimKind::Prohibited,
        name: ExcludedProtectionClaimName::AuthorityIsReleaseAuthority,
    },
];

#[cfg(test)]
mod tests;
