//! Pure dynamic-authorization and authenticated-approval model.
//!
//! This module is the machine-checked model for `GNT-19.0` through
//! `GNT-19.10-approval-audit-evidence`. It states approval request identity
//! (`GNT-19.1-approval-request-identity`), the canonical approval subject
//! (`GNT-19.2-approval-subject`), authenticated approver identity
//! (`GNT-19.3-authenticated-approver-identity`), approver presentation fidelity
//! (`GNT-19.4-approver-presentation-fidelity`), decision scope and standing
//! authority (`GNT-19.5-decision-scope-and-standing-authority`), decision
//! linearization and revalidation
//! (`GNT-19.6-decision-linearization-and-revalidation`), durable request and
//! decision cuts (`GNT-19.7-durable-request-and-decision-cuts`), the approval
//! outcome taxonomy (`GNT-19.8-approval-outcome-taxonomy`), execution and
//! release separation (`GNT-19.9-execution-and-release-separation`), and
//! approval audit evidence (`GNT-19.10-approval-audit-evidence`).
//!
//! Scope is deliberately narrow. Every rule here is a pure function of its own
//! arguments: this module reads no host path, environment variable, clock,
//! locale, filesystem, or service, and it exposes no constructor that accepts
//! one. Expiry and admission instants are explicit logical microseconds supplied
//! by the caller under the landed admission model of
//! `GNT-3-T-AUTHORITY-ADMISSION`, so revalidation is reproducible from its own
//! arguments, and equal subjects produce equal canonical bytes, equal digests,
//! and equal request identities under every construction order. This module is
//! not an approval store, not an adapter, and not a policy evaluator.
//!
//! Landed types are reused rather than redeclared. The selected capability
//! instance, its requirement identity, generation, rights, lease, lineage, and
//! fencing are the landed ones of the authority model; the protected class,
//! destination, projection, disclosure charge, holder authority, and release
//! grant are the landed ones of the protected model; the recovery class, static
//! site identity, typed callable identity, and effect summary are the landed
//! ones of this crate. This module adds no second rights lattice, no second
//! lineage relation, no second protected-class or destination vocabulary, and no
//! second recovery rule.
//!
//! Four separations stay explicit.
//!
//! * An [`ApprovalRequestId`] is a domain-separated digest of the canonical
//!   subject alone: it has no free constructor and no deserializer, and no path
//!   from a provider identifier, correlation token, or transport message number,
//!   so a provider handle can never be a request identity, a resumption key, or
//!   evidence that a decision exists.
//! * An [`AuthenticatedActor`] is a sealed host-attested type distinct from
//!   every subject input, obtainable only from a host-attested binding, and the
//!   attestation kind is part of the value, so no argument, prompt, header,
//!   environment fact, presentation label, or adapter field participates in an
//!   approver identity. Host authentication is itself the embedding host's
//!   obligation: this pure model states the type boundary and never verifies that
//!   a host performed the authentication a binding declares.
//! * An [`ApprovalDecision`] never joins approval to release authority: a
//!   [`ReleaseGrant`] is derived only from a [`ReleaseHolderAuthority`], and
//!   [`ApprovalDecision::release_grant`] refuses every subject that does not name
//!   exactly the declared protected class and destination pair.
//! * Reusable authority is never an approval cache. A [`StandingLease`] is
//!   obtainable only by attenuation of a landed capability instance, carries its
//!   own identity, lineage, rights, expiration, and revocation contract, and the
//!   module exposes no cache, no mapping from a request or subject to a decision,
//!   and no way to widen a decision that a later revalidation found stale.
//!
//! [`ReleaseGrant`]: crate::protected::ReleaseGrant
//! [`ReleaseHolderAuthority`]: crate::protected::ReleaseHolderAuthority

use std::fmt;
use std::sync::Arc;

use crate::authority::{
    Admission, AdmissionRequest, AuthorityError, AuthorityGeneration, AuthorityInstance,
    AuthorityInstanceId, AuthorityLeasePolicy, AuthorityRequirementId, AuthorityRight,
    ExternalOutcome, FenceCategory, FencePoint, LineageRecord, RightsSet, digest_fields,
};
use crate::generated::RecoveryClass;
use crate::manifest::encode_hex;
use crate::protected::{
    DeclaredName, DisclosureBudget, DisclosureCharge, ProjectionKind, ProtectedDataClass,
    ReleaseDestination, ReleaseGrant, ReleaseHolderAuthority, ReleaseProjection, ReleaseSite,
};
use crate::{
    CanonicalCallableIdentity, CanonicalImplementationIdentity, CanonicalPath, EffectSet,
    StaticSiteId, TargetFactsDigest,
};

/// Domain separator for the canonical approval-request encoding.
const APPROVAL_REQUEST_DOMAIN: &str = "gantry.approval-request/v1";

/// Domain separator for the canonical approval-subject encoding.
const SUBJECT_DOMAIN: &str = "gantry.approval-subject/v1";

/// Domain separator for the canonical approval-decision encoding.
const DECISION_DOMAIN: &str = "gantry.approval-decision/v1";

/// Domain separator for the canonical logical-execution encoding.
const EXECUTION_DOMAIN: &str = "gantry.logical-execution/v1";

/// Domain separator for the canonical logical-operation encoding.
const OPERATION_DOMAIN: &str = "gantry.logical-operation/v1";

/// Domain separator for the canonical host-attestation binding encoding.
const ATTESTATION_DOMAIN: &str = "gantry.host-attestation/v1";

/// One frozen published diagnostic identity of the approval model.
///
/// `SPEC.md` assigns no exact approval diagnostic code: its code namespaces are
/// implementation-defined except where the specification assigns an exact code,
/// so this module publishes the registry below, one code per condition it
/// decides, each anchored to the clause that owns that condition. The variant
/// order is the sorted code order, so [`Self::ALL`] is already the order a code
/// registry requires, and no condition is reported under another condition's
/// code. The seven outcome codes are the distinct diagnostics
/// `GNT-19.8-approval-outcome-taxonomy` requires for its seven bounded outcomes.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ApprovalDiagnosticCode {
    /// `approval-adapter-failure`
    AdapterFailure,
    /// `approval-admission-not-of-subject`
    AdmissionNotOfSubject,
    /// `approval-admission-without-positive-decision`
    AdmissionWithoutPositiveDecision,
    /// `approval-cancellation`
    Cancellation,
    /// `approval-cut-out-of-order`
    CutOutOfOrder,
    /// `approval-decision-not-committed`
    DecisionNotCommitted,
    /// `approval-decision-not-of-request`
    DecisionNotOfRequest,
    /// `approval-decision-outlives-lease`
    DecisionOutlivesLease,
    /// `approval-denial`
    Denial,
    /// `approval-expiration`
    Expiration,
    /// `approval-incomplete-subject`
    IncompleteSubject,
    /// `approval-invalid-digest`
    InvalidDigest,
    /// `approval-malformed-decision`
    MalformedDecision,
    /// `approval-positive-decision`
    PositiveDecision,
    /// `approval-presentation-conceals-scope`
    PresentationConcealsScope,
    /// `approval-revocation-not-contractual`
    RevocationNotContractual,
    /// `approval-scope-mismatch`
    ScopeMismatch,
    /// `approval-second-request-for-operation`
    SecondRequestForOperation,
    /// `approval-unavailable-approver`
    UnavailableApprover,
    /// `approval-unbounded-lease`
    UnboundedLease,
    /// `approval-unknown-request`
    UnknownRequest,
}

impl ApprovalDiagnosticCode {
    /// Every published code, in sorted code order.
    pub const ALL: [Self; 21] = [
        Self::AdapterFailure,
        Self::AdmissionNotOfSubject,
        Self::AdmissionWithoutPositiveDecision,
        Self::Cancellation,
        Self::CutOutOfOrder,
        Self::DecisionNotCommitted,
        Self::DecisionNotOfRequest,
        Self::DecisionOutlivesLease,
        Self::Denial,
        Self::Expiration,
        Self::IncompleteSubject,
        Self::InvalidDigest,
        Self::MalformedDecision,
        Self::PositiveDecision,
        Self::PresentationConcealsScope,
        Self::RevocationNotContractual,
        Self::ScopeMismatch,
        Self::SecondRequestForOperation,
        Self::UnavailableApprover,
        Self::UnboundedLease,
        Self::UnknownRequest,
    ];

    /// Returns the exact frozen code spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AdapterFailure => "approval-adapter-failure",
            Self::AdmissionNotOfSubject => "approval-admission-not-of-subject",
            Self::AdmissionWithoutPositiveDecision => {
                "approval-admission-without-positive-decision"
            }
            Self::Cancellation => "approval-cancellation",
            Self::CutOutOfOrder => "approval-cut-out-of-order",
            Self::DecisionNotCommitted => "approval-decision-not-committed",
            Self::DecisionNotOfRequest => "approval-decision-not-of-request",
            Self::DecisionOutlivesLease => "approval-decision-outlives-lease",
            Self::Denial => "approval-denial",
            Self::Expiration => "approval-expiration",
            Self::IncompleteSubject => "approval-incomplete-subject",
            Self::InvalidDigest => "approval-invalid-digest",
            Self::MalformedDecision => "approval-malformed-decision",
            Self::PositiveDecision => "approval-positive-decision",
            Self::PresentationConcealsScope => "approval-presentation-conceals-scope",
            Self::RevocationNotContractual => "approval-revocation-not-contractual",
            Self::ScopeMismatch => "approval-scope-mismatch",
            Self::SecondRequestForOperation => "approval-second-request-for-operation",
            Self::UnavailableApprover => "approval-unavailable-approver",
            Self::UnboundedLease => "approval-unbounded-lease",
            Self::UnknownRequest => "approval-unknown-request",
        }
    }

    /// Returns the same exact frozen code spelling as [`Self::as_str`].
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        self.as_str()
    }

    /// Returns the frozen meaning registered for this code.
    #[must_use]
    pub const fn meaning(self) -> &'static str {
        match self {
            Self::AdapterFailure => {
                "The component that carries a request to an approver or a decision back failed; this is its own outcome rather than another outcome's failure."
            }
            Self::AdmissionNotOfSubject => {
                "An admission recorded as the commit-point result does not name the subject it is recorded against: its authority generation or its settlement rule disagrees with the subject of the decision."
            }
            Self::AdmissionWithoutPositiveDecision => {
                "An admission, or a durable admitted cut, was recorded for a decision that did not grant the request."
            }
            Self::Cancellation => "The approval wait was cancelled before any decision.",
            Self::CutOutOfOrder => {
                "A durable approval cut was reached out of order: a decision before the committed request, or a dispatch before the committed decision."
            }
            Self::DecisionNotCommitted => {
                "A durable approval cut that requires a committed decision was reached with no decision committed."
            }
            Self::DecisionNotOfRequest => {
                "The decision presented for commit is not the decision of the committed request of this interaction."
            }
            Self::DecisionOutlivesLease => {
                "A decision's validity bound outlives the expiration of the standing lease it stands on."
            }
            Self::Denial => "The approver denied the request.",
            Self::Expiration => "The approval wait expired with no decision.",
            Self::IncompleteSubject => {
                "One canonical subject input of GNT-19.2-approval-subject is absent, so no subject can be built."
            }
            Self::InvalidDigest => {
                "A digest or revision spelling bound by the subject or by a host-attested binding is not 64 lowercase hexadecimal digits."
            }
            Self::MalformedDecision => "The decision received from an approver was malformed.",
            Self::PositiveDecision => "The approver granted the request.",
            Self::PresentationConcealsScope => {
                "A presentation that withholds or abstracts a protected element is combined with reusable standing authority, which would let the decision cover semantics it did not disclose."
            }
            Self::RevocationNotContractual => {
                "The declared revocation contract of a standing lease does not admit a revocation by this holder."
            }
            Self::ScopeMismatch => {
                "A decision scope does not name the subject it is bound to: a one-shot scope names another logical operation identity, or a standing-lease scope disagrees with the lease presented with the decision."
            }
            Self::SecondRequestForOperation => {
                "One logical operation identity already has a committed approval request, and a second request for it is refused."
            }
            Self::UnavailableApprover => "No approver was available to decide the request.",
            Self::UnboundedLease => {
                "A standing lease carries no expiration, so it is not a bounded lease."
            }
            Self::UnknownRequest => {
                "A resumption presents a request identity that is not the committed identity of any pending approval interaction."
            }
        }
    }

    /// Returns the requirement anchor this code implements.
    #[must_use]
    pub const fn requirement(self) -> &'static str {
        match self {
            Self::AdapterFailure
            | Self::Cancellation
            | Self::Denial
            | Self::Expiration
            | Self::MalformedDecision
            | Self::PositiveDecision
            | Self::UnavailableApprover => "GNT-19.8-approval-outcome-taxonomy",
            Self::AdmissionWithoutPositiveDecision => {
                "GNT-19.6-decision-linearization-and-revalidation"
            }
            Self::CutOutOfOrder
            | Self::DecisionNotCommitted
            | Self::DecisionNotOfRequest
            | Self::SecondRequestForOperation => "GNT-19.7-durable-request-and-decision-cuts",
            Self::DecisionOutlivesLease
            | Self::RevocationNotContractual
            | Self::ScopeMismatch
            | Self::UnboundedLease => "GNT-19.5-decision-scope-and-standing-authority",
            Self::AdmissionNotOfSubject => "GNT-19.10-approval-audit-evidence",
            Self::IncompleteSubject | Self::InvalidDigest => "GNT-19.2-approval-subject",
            Self::PresentationConcealsScope => "GNT-19.4-approver-presentation-fidelity",
            Self::UnknownRequest => "GNT-19.1-approval-request-identity",
        }
    }
}

/// Failure of one approval-model operation.
///
/// One variant deliberately has no approval code: an attenuation that the landed
/// authority model refuses is reported as [`ApprovalError::AttenuationRefused`],
/// which exposes the landed condition and the landed code for it, so no second
/// code is published for a condition another registry already owns.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ApprovalError {
    /// An admission recorded as the commit-point result does not name the subject
    /// it is recorded against: its generation or its settlement rule disagrees
    /// with the subject of the decision.
    AdmissionNotOfSubject,
    /// An admission, or an admitted durable cut, was recorded for a decision that
    /// did not grant the request.
    AdmissionWithoutPositiveDecision,
    /// A standing lease could not be derived by attenuation from the presented
    /// capability instance.
    AttenuationRefused {
        /// The landed authority failure that refused the attenuation.
        landed: AuthorityError,
    },
    /// A decision reached a durable cut out of order.
    CutOutOfOrder {
        /// The cut the interaction was at.
        from: DurableApprovalCut,
        /// The cut that was requested.
        to: DurableApprovalCut,
    },
    /// A durable cut that requires a committed decision was reached with no
    /// decision committed.
    DecisionNotCommitted {
        /// The cut that requires the committed decision.
        to: DurableApprovalCut,
    },
    /// The decision presented for commit is not the decision of the committed
    /// request of this interaction.
    DecisionNotOfRequest {
        /// The request identity the presented decision names.
        request: Arc<str>,
    },
    /// A decision's validity bound outlives the lease it stands on.
    DecisionOutlivesLease,
    /// One canonical subject input is absent.
    IncompleteSubject {
        /// The absent input, named by its subject role.
        input: &'static str,
    },
    /// A digest or revision spelling is not 64 lowercase hexadecimal digits.
    InvalidDigest {
        /// The rejected spelling.
        value: Arc<str>,
    },
    /// A redacted presentation cannot carry reusable standing authority.
    PresentationConcealsScope,
    /// The revocation contract does not admit this holder's revocation.
    RevocationNotContractual,
    /// A decision scope does not name the subject it is bound to.
    ScopeMismatch,
    /// One logical operation identity already has a committed request.
    SecondRequestForOperation {
        /// The logical operation identity that already has a request.
        operation: Arc<str>,
    },
    /// A standing lease carries no expiration.
    UnboundedLease,
    /// A resumption presents a request identity that is not committed here.
    UnknownRequest {
        /// The request identity that was presented.
        request: Arc<str>,
    },
}

impl ApprovalError {
    /// Returns the frozen approval code of this condition, when one exists.
    ///
    /// [`Self::AttenuationRefused`] reports a condition the landed authority
    /// model already registers, so it returns `None` here and exposes that code
    /// through [`Self::landed_code`] instead.
    #[must_use]
    pub const fn code(&self) -> Option<ApprovalDiagnosticCode> {
        match self {
            Self::AdmissionNotOfSubject => Some(ApprovalDiagnosticCode::AdmissionNotOfSubject),
            Self::AdmissionWithoutPositiveDecision => {
                Some(ApprovalDiagnosticCode::AdmissionWithoutPositiveDecision)
            }
            Self::AttenuationRefused { .. } => None,
            Self::CutOutOfOrder { .. } => Some(ApprovalDiagnosticCode::CutOutOfOrder),
            Self::DecisionNotCommitted { .. } => Some(ApprovalDiagnosticCode::DecisionNotCommitted),
            Self::DecisionNotOfRequest { .. } => Some(ApprovalDiagnosticCode::DecisionNotOfRequest),
            Self::DecisionOutlivesLease => Some(ApprovalDiagnosticCode::DecisionOutlivesLease),
            Self::IncompleteSubject { .. } => Some(ApprovalDiagnosticCode::IncompleteSubject),
            Self::InvalidDigest { .. } => Some(ApprovalDiagnosticCode::InvalidDigest),
            Self::PresentationConcealsScope => {
                Some(ApprovalDiagnosticCode::PresentationConcealsScope)
            }
            Self::RevocationNotContractual => {
                Some(ApprovalDiagnosticCode::RevocationNotContractual)
            }
            Self::ScopeMismatch => Some(ApprovalDiagnosticCode::ScopeMismatch),
            Self::SecondRequestForOperation { .. } => {
                Some(ApprovalDiagnosticCode::SecondRequestForOperation)
            }
            Self::UnboundedLease => Some(ApprovalDiagnosticCode::UnboundedLease),
            Self::UnknownRequest { .. } => Some(ApprovalDiagnosticCode::UnknownRequest),
        }
    }

    /// Returns the exact frozen code another landed registry publishes for this
    /// condition, when this model has none of its own.
    #[must_use]
    pub const fn landed_code(&self) -> Option<&'static str> {
        match self {
            Self::AttenuationRefused { landed } => Some(landed.code()),
            _ => None,
        }
    }

    /// Returns the requirement anchor that owns this condition.
    #[must_use]
    pub const fn requirement(&self) -> &'static str {
        match self.code() {
            Some(code) => code.requirement(),
            None => "GNT-19.5-decision-scope-and-standing-authority",
        }
    }
}

impl fmt::Display for ApprovalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // A condition another registry owns is rendered under that registry's
        // code, so a rendered diagnostic always names the code a consumer
        // matches on, and every other condition names its approval code first.
        if let Self::AttenuationRefused { landed } = self {
            return write!(formatter, "{landed}");
        }
        if let Some(code) = self.code() {
            formatter.write_str(code.as_str())?;
            formatter.write_str(": ")?;
        }
        match self {
            Self::AdmissionNotOfSubject => formatter
                .write_str("the admission does not name the subject it is recorded against"),
            Self::AdmissionWithoutPositiveDecision => {
                formatter.write_str("an admission requires a decision that granted the request")
            }
            Self::AttenuationRefused { .. } => formatter.write_str("attenuation refused"),
            Self::CutOutOfOrder { from, to } => write!(
                formatter,
                "cut `{}` cannot be reached from `{}`",
                to.wire_name(),
                from.wire_name()
            ),
            Self::DecisionNotCommitted { to } => write!(
                formatter,
                "cut `{}` requires a committed decision",
                to.wire_name()
            ),
            Self::DecisionNotOfRequest { request } => write!(
                formatter,
                "decision of request `{request}` is not the committed request of this interaction"
            ),
            Self::DecisionOutlivesLease => {
                formatter.write_str("the decision outlives the standing lease it stands on")
            }
            Self::IncompleteSubject { input } => {
                write!(formatter, "subject input `{input}` is absent")
            }
            Self::InvalidDigest { value } => write!(
                formatter,
                "`{value}` is not a lowercase hexadecimal SHA-256 digest"
            ),
            Self::PresentationConcealsScope => formatter
                .write_str("a redacted presentation cannot carry reusable standing authority"),
            Self::RevocationNotContractual => {
                formatter.write_str("the revocation contract does not admit this revocation")
            }
            Self::ScopeMismatch => {
                formatter.write_str("the decision scope does not name the subject it is bound to")
            }
            Self::SecondRequestForOperation { operation } => write!(
                formatter,
                "logical operation `{operation}` already has a committed request"
            ),
            Self::UnboundedLease => {
                formatter.write_str("a standing lease must carry its own expiration")
            }
            Self::UnknownRequest { request } => write!(
                formatter,
                "request `{request}` is not the committed request of this interaction"
            ),
        }
    }
}

impl std::error::Error for ApprovalError {}

/// Validates one lowercase hexadecimal SHA-256 digest spelling.
fn validate_digest(value: &str) -> Result<(), ApprovalError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ApprovalError::InvalidDigest {
            value: Arc::from(value),
        });
    }
    Ok(())
}

/// Encodes one field as its exact bytes.
fn text(value: &str) -> Vec<u8> {
    value.as_bytes().to_vec()
}

/// Encodes one number as its big-endian bytes.
fn number(value: u64) -> Vec<u8> {
    value.to_be_bytes().to_vec()
}

/// Encodes one structural route as fixed-width big-endian components.
fn components(values: &[u64]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(values.len() * 8);
    for value in values {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    bytes
}

/// Borrows one field sequence for domain-separated digesting.
fn as_slices(fields: &[Vec<u8>]) -> Vec<&[u8]> {
    fields.iter().map(Vec::as_slice).collect()
}

/// Encodes one field sequence with length prefixes under one domain.
fn encode_fields(domain: &str, fields: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(domain.as_bytes());
    bytes.push(0);
    for field in fields {
        let length = u64::try_from(field.len()).unwrap_or(u64::MAX);
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(field);
    }
    bytes
}

/// Returns one required subject input or the fail-closed rejection naming it.
fn required<T>(value: Option<T>, input: &'static str) -> Result<T, ApprovalError> {
    value.ok_or(ApprovalError::IncompleteSubject { input })
}

macro_rules! approval_digest_type {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(Arc<str>);

        impl $name {
            /// Decodes one exact lowercase hexadecimal SHA-256 digest.
            pub fn from_hex(value: &str) -> Result<Self, ApprovalError> {
                validate_digest(value)?;
                Ok(Self(Arc::from(value)))
            }

            /// Encodes one accepted digest.
            #[must_use]
            pub fn from_digest(digest: [u8; 32]) -> Self {
                Self(Arc::from(encode_hex(&digest)))
            }

            /// Returns the exact lowercase hexadecimal digest.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

approval_digest_type!(
    SemanticArgumentDigest,
    "One canonical digest of the semantic arguments of one operation (GNT-19.2-approval-subject)."
);
approval_digest_type!(
    MappingRevision,
    "One mapping revision bound by one approval subject (GNT-19.2-approval-subject)."
);
approval_digest_type!(
    PolicyRevision,
    "One effective policy revision bound by one approval subject (GNT-19.2-approval-subject)."
);
approval_digest_type!(
    ApprovalSubjectDigest,
    "One digest of the canonical bytes of one approval subject (GNT-19.2-approval-subject)."
);
approval_digest_type!(
    ApprovalDecisionId,
    "One identity of one recorded approval decision (GNT-19.10-approval-audit-evidence)."
);
approval_digest_type!(
    HostAuthorityDigest,
    "One digest of the host authority that attests one authenticated actor (GNT-19.3-authenticated-approver-identity). A value decoded by `from_hex` is a host-supplied declaration: this model validates only the spelling, and it never verifies the host authentication the digest stands for."
);

/// One canonical logical-execution identity.
///
/// The identity is a domain-separated SHA-256 digest over one harness entry
/// callable and one declared execution label. No process identifier, session
/// identifier, adapter handle, host path, clock reading, or locale participates,
/// so a resumed execution keeps its identity while a rerun of the same entry is
/// a distinct logical execution.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LogicalExecutionId(Arc<str>);

impl LogicalExecutionId {
    /// Derives one logical-execution identity from an entry and a declared label.
    #[must_use]
    pub fn derive(entry: &CanonicalCallableIdentity, label: &DeclaredName) -> Self {
        let digest = digest_fields(
            EXECUTION_DOMAIN,
            &[entry.as_str().as_bytes(), label.as_str().as_bytes()],
        );
        Self(Arc::from(format!(
            "logical-execution:{}",
            encode_hex(&digest)
        )))
    }

    /// Returns the exact portable identity spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the lowercase digest text without the identity prefix.
    #[must_use]
    pub fn digest_hex(&self) -> &str {
        self.0.strip_prefix("logical-execution:").unwrap_or(&self.0)
    }
}

/// One stable logical operation identity.
///
/// The identity is a domain-separated SHA-256 digest over one operation
/// declaration and one exact source site, which are the abstract requirement and
/// operation-site inputs of `GNT-6.5-abstract-requirements`, so it is stable
/// across the process, session, adapter, and provider that carry one operation.
/// It is distinct from a capability requirement identity, a capability-instance
/// identity, a callable identity, and an approval request identity.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LogicalOperationId(Arc<str>);

impl LogicalOperationId {
    /// Derives the stable identity of one declaration and one exact source site.
    #[must_use]
    pub fn derive(declaration: &CanonicalPath, site: &StaticSiteId) -> Self {
        let digest = digest_fields(
            OPERATION_DOMAIN,
            &[
                declaration.as_str().as_bytes(),
                site.workflow().as_str().as_bytes(),
                &components(site.position().components()),
            ],
        );
        Self(Arc::from(format!(
            "logical-operation:{}",
            encode_hex(&digest)
        )))
    }

    /// Returns the exact portable identity spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the lowercase digest text without the identity prefix.
    #[must_use]
    pub fn digest_hex(&self) -> &str {
        self.0.strip_prefix("logical-operation:").unwrap_or(&self.0)
    }
}

/// One closed host-attestation kind.
///
/// The kind is part of an authenticated actor, so a host-session attestation and
/// a host-service attestation never become one value and never substitute for
/// each other.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum HostAttestationKind {
    /// The embedding host attested from its own interactive session state.
    HostSession,
    /// The embedding host attested a host-governed service identity.
    HostService,
}

impl HostAttestationKind {
    /// Every member of the closed vocabulary, in wire-name order.
    pub const ALL: [Self; 2] = [Self::HostSession, Self::HostService];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::HostSession => "host-session",
            Self::HostService => "host-service",
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
}

/// One host-governed attestation binding.
///
/// The binding names the host-attested kind and the digest of the host authority
/// that attested it, and it is owned upstream of this model by the embedding
/// host. It is a typed, structured value rather than free text, so no ordinary
/// string, prompt, header, environment fact, presentation label, or
/// adapter-supplied field can be supplied where an attestation binding is
/// required.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostAttestationBindingId {
    kind: HostAttestationKind,
    authority: HostAuthorityDigest,
    text: Arc<str>,
}

impl HostAttestationBindingId {
    /// Binds one attestation kind to one host-authority digest.
    #[must_use]
    pub fn new(kind: HostAttestationKind, authority: HostAuthorityDigest) -> Self {
        let digest = digest_fields(
            ATTESTATION_DOMAIN,
            &[kind.wire_name().as_bytes(), authority.as_str().as_bytes()],
        );
        Self {
            kind,
            authority,
            text: Arc::from(format!("host-attestation:{}", encode_hex(&digest))),
        }
    }

    /// Returns the host-attested kind.
    #[must_use]
    pub const fn kind(&self) -> HostAttestationKind {
        self.kind
    }

    /// Returns the attested host-authority digest.
    #[must_use]
    pub const fn authority(&self) -> &HostAuthorityDigest {
        &self.authority
    }

    /// Returns the exact portable binding spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }
}

/// One authenticated requester, approver, tenant, and policy identity.
///
/// The identities are host-governed and are established only from a
/// host-attested binding: the attestation kind is part of the value, and every
/// identity is a declared name supplied by the embedding host together with that
/// binding. There is no constructor from free strings, so no argument, prompt,
/// header, environment fact, presentation label, or adapter field becomes an
/// approver identity, and an absent, unauthenticated, or ambiguous identity is
/// not representable as an approval. This is a sealed host-attested type distinct
/// from every subject input of [`ApprovalSubjectInputs`]: no field of a subject
/// record supplies, overrides, or shares a value with it. Host authentication is
/// the embedding host's obligation, which the pure model cannot verify.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedActor {
    binding: HostAttestationBindingId,
    requester: DeclaredName,
    approver: DeclaredName,
    tenant: DeclaredName,
    policy: DeclaredName,
}

impl AuthenticatedActor {
    /// Establishes one authenticated actor from a host-attested binding.
    ///
    /// This is the only path to an [`AuthenticatedActor`], and every identity it
    /// carries is a validated declared name rather than free text.
    ///
    /// The value is a sealed host-attested type distinct from every subject input:
    /// no argument, prompt, header, environment fact, presentation label, or
    /// adapter field participates in actor identity. The call records the declared
    /// binding as given; host authentication itself is the embedding host's
    /// obligation, so this pure model cannot verify that the host performed the
    /// authentication the binding names.
    #[must_use]
    pub fn attest(
        binding: &HostAttestationBindingId,
        requester: &DeclaredName,
        approver: &DeclaredName,
        tenant: &DeclaredName,
        policy: &DeclaredName,
    ) -> Self {
        Self {
            binding: binding.clone(),
            requester: requester.clone(),
            approver: approver.clone(),
            tenant: tenant.clone(),
            policy: policy.clone(),
        }
    }

    /// Returns the host-attested binding this actor was established from.
    #[must_use]
    pub const fn binding(&self) -> &HostAttestationBindingId {
        &self.binding
    }

    /// Returns the attestation kind that established this actor.
    #[must_use]
    pub const fn attestation(&self) -> HostAttestationKind {
        self.binding.kind()
    }

    /// Returns the authenticated requester identity.
    #[must_use]
    pub const fn requester(&self) -> &DeclaredName {
        &self.requester
    }

    /// Returns the authenticated approver identity.
    #[must_use]
    pub const fn approver(&self) -> &DeclaredName {
        &self.approver
    }

    /// Returns the authenticated tenant identity.
    #[must_use]
    pub const fn tenant(&self) -> &DeclaredName {
        &self.tenant
    }

    /// Returns the authenticated policy identity.
    #[must_use]
    pub const fn policy(&self) -> &DeclaredName {
        &self.policy
    }

    /// Returns the canonical text of this actor, which contains no credential.
    #[must_use]
    pub fn canonical_text(&self) -> String {
        format!(
            "attestation={};binding={};requester={};approver={};tenant={};policy={}",
            self.binding.kind().wire_name(),
            self.binding.as_str(),
            self.requester.as_str(),
            self.approver.as_str(),
            self.tenant.as_str(),
            self.policy.as_str(),
        )
    }
}

/// One sealed, versioned predicate whose exact meaning is part of the request.
///
/// A predicate is a declared name, a version, and the digest of its exact
/// meaning. It is the only substitute `GNT-19.4-approver-presentation-fidelity`
/// admits for a protected argument a policy cannot show: not a display label, not
/// a truncated value, not the digest of the withheld value, and not a
/// model-generated summary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedPredicate {
    name: DeclaredName,
    version: u32,
    meaning: SemanticArgumentDigest,
}

impl SealedPredicate {
    /// Seals one predicate name, version, and exact-meaning digest.
    #[must_use]
    pub const fn new(name: DeclaredName, version: u32, meaning: SemanticArgumentDigest) -> Self {
        Self {
            name,
            version,
            meaning,
        }
    }

    /// Returns the declared predicate name.
    #[must_use]
    pub const fn name(&self) -> &DeclaredName {
        &self.name
    }

    /// Returns the predicate version.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// Returns the digest of the predicate's exact meaning.
    #[must_use]
    pub const fn meaning(&self) -> &SemanticArgumentDigest {
        &self.meaning
    }

    /// Returns the canonical text of this predicate.
    #[must_use]
    pub fn canonical_text(&self) -> String {
        format!(
            "sealed-predicate:{}:{}:{}",
            self.name.as_str(),
            self.version,
            self.meaning.as_str()
        )
    }
}

/// One separately authorized protected review channel.
///
/// The channel carries the sealed predicate of a presentation that withholds a
/// protected element, so the predicate's exact meaning enters the request subject
/// instead of widening what the decision is taken to cover.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectedReviewChannel {
    predicate: SealedPredicate,
}

impl ProtectedReviewChannel {
    /// Opens the sealed-predicate review channel of one predicate.
    #[must_use]
    pub const fn sealed(predicate: SealedPredicate) -> Self {
        Self { predicate }
    }

    /// Returns the sealed predicate this channel decides on.
    #[must_use]
    pub const fn predicate(&self) -> &SealedPredicate {
        &self.predicate
    }

    /// Returns the canonical text of this channel.
    #[must_use]
    pub fn canonical_text(&self) -> String {
        self.predicate.canonical_text()
    }
}

/// The bounded rendering an approver is shown.
///
/// A faithful presentation discloses every semantic element of the subject. A
/// redacted or summarized presentation must carry the sealed-predicate review
/// channel it was decided on, so it cannot exist without the exact meaning of the
/// predicate it substitutes, and it can never be decoded back into a faithful
/// presentation.
///
/// [`ApproverPresentation::Faithful`] is a declaration the embedding host makes,
/// and the model cannot falsify it: nothing here observes what an approver was
/// actually shown. The two rules this model does enforce about a presentation are
/// the sealed-predicate requirement, which makes a presentation that withholds or
/// abstracts an element carry the exact meaning it substitutes, and the
/// redaction-with-standing-authority rule, which refuses such a presentation
/// together with reusable standing authority as
/// [`ApprovalError::PresentationConcealsScope`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ApproverPresentation {
    /// The presentation discloses every semantic element of the subject.
    Faithful,
    /// The presentation withholds or abstracts an element, and is decided on the
    /// sealed predicate its review channel carries.
    RedactedWithinDeclaredScope(ProtectedReviewChannel),
}

impl ApproverPresentation {
    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(&self) -> &'static str {
        match self {
            Self::Faithful => "faithful",
            Self::RedactedWithinDeclaredScope(_) => "redacted-within-declared-scope",
        }
    }

    /// Returns the same exact portable spelling as [`Self::wire_name`].
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        self.wire_name()
    }

    /// Returns whether the presentation is declared faithful.
    ///
    /// The declaration is the host's: the model records it and cannot falsify it.
    #[must_use]
    pub const fn is_faithful(&self) -> bool {
        matches!(self, Self::Faithful)
    }

    /// Returns the sealed-predicate review channel, when the presentation
    /// withholds an element.
    #[must_use]
    pub const fn channel(&self) -> Option<&ProtectedReviewChannel> {
        match self {
            Self::Faithful => None,
            Self::RedactedWithinDeclaredScope(channel) => Some(channel),
        }
    }

    /// Returns the canonical text of this presentation.
    #[must_use]
    pub fn canonical_text(&self) -> String {
        match self {
            Self::Faithful => Self::Faithful.wire_name().to_owned(),
            Self::RedactedWithinDeclaredScope(channel) => {
                format!("{}+{}", self.wire_name(), channel.canonical_text())
            }
        }
    }
}

/// The protected reach of one operation under `GNT-15.10-protected-values`.
///
/// The scope names the landed protected class, the landed release destination, the
/// exact destination-specific release projection, and the disclosure charge the
/// operation would reach. It reuses the landed projection type rather than
/// restating it, so the class and destination of the scope and of the projection
/// can never disagree.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtectedScope {
    projection: ReleaseProjection,
    charge: DisclosureCharge,
}

impl ProtectedScope {
    /// Binds one declared projection kind, class, destination, and charge.
    #[must_use]
    pub const fn new(
        projection: ProjectionKind,
        class: ProtectedDataClass,
        destination: ReleaseDestination,
        charge: DisclosureCharge,
    ) -> Self {
        Self {
            projection: ReleaseProjection::new(projection, class, destination),
            charge,
        }
    }

    /// Returns the protected class the operation would reach.
    #[must_use]
    pub const fn class(&self) -> ProtectedDataClass {
        self.projection.class()
    }

    /// Returns the destination the operation would reach.
    #[must_use]
    pub const fn destination(&self) -> ReleaseDestination {
        self.projection.destination()
    }

    /// Returns the exact destination-specific release projection.
    #[must_use]
    pub const fn projection(&self) -> ReleaseProjection {
        self.projection
    }

    /// Returns the disclosure charge of one accepted release.
    #[must_use]
    pub const fn charge(&self) -> DisclosureCharge {
        self.charge
    }

    /// Returns the canonical text of this scope.
    #[must_use]
    pub fn canonical_text(&self) -> String {
        format!(
            "class={};destination={};projection={};charge={}",
            self.class().wire_name(),
            self.destination().wire_name(),
            self.projection().kind().wire_name(),
            self.charge.value(),
        )
    }
}

/// The attempts and retries one decision covers.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AttemptApplicability {
    /// Only the transport attempts and retries the operation's own recovery
    /// class and retry policy already permit.
    RecoveryPolicy,
    /// Exactly one attempt, with no retry.
    Single,
}

impl AttemptApplicability {
    /// Every member of the closed vocabulary, in wire-name order.
    pub const ALL: [Self; 2] = [Self::RecoveryPolicy, Self::Single];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::RecoveryPolicy => "recovery-policy",
            Self::Single => "single",
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
}

/// The declared revocation contract of one standing lease.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RevocationContract {
    /// Only the issuing lineage holder may revoke the lease.
    IssuerOnly,
    /// The lease holder and the issuing lineage holder may revoke the lease.
    IssuerOrHolder,
}

impl RevocationContract {
    /// Every member of the closed vocabulary, in wire-name order.
    pub const ALL: [Self; 2] = [Self::IssuerOnly, Self::IssuerOrHolder];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::IssuerOnly => "issuer-only",
            Self::IssuerOrHolder => "issuer-or-holder",
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
}

/// The declared scope of one standing lease: lineage, rights, expiry, revocation.
///
/// The declared fields are private and the type is produced only by
/// [`StandingLease::lease_scope`], so a lease scope is obtainable only by
/// attenuating a landed capability instance under
/// `GNT-3-T-AUTHORITY-LINEAGE`. It is a declaration rather than live authority:
/// it carries no fence, no admitted work, and no reusable decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeaseScope {
    instance: AuthorityInstanceId,
    root: AuthorityInstanceId,
    lineage: Arc<[AuthorityInstanceId]>,
    rights: RightsSet,
    expiry: AuthorityLeasePolicy,
    revocation: RevocationContract,
}

impl LeaseScope {
    /// Returns the lease's own instance identity.
    #[must_use]
    pub const fn instance(&self) -> &AuthorityInstanceId {
        &self.instance
    }

    /// Returns the lineage root the lease descends from.
    #[must_use]
    pub const fn root(&self) -> &AuthorityInstanceId {
        &self.root
    }

    /// Returns the ancestor identities from the root to the lease.
    #[must_use]
    pub fn lineage(&self) -> &[AuthorityInstanceId] {
        &self.lineage
    }

    /// Returns the rights this lease carries.
    #[must_use]
    pub const fn rights(&self) -> RightsSet {
        self.rights
    }

    /// Returns the lease expiration policy.
    #[must_use]
    pub const fn expiry(&self) -> AuthorityLeasePolicy {
        self.expiry
    }

    /// Returns the absolute expiry instant of this lease.
    #[must_use]
    pub const fn expires_at_us(&self) -> Option<u64> {
        self.expiry.expires_at_us()
    }

    /// Returns the declared revocation contract.
    #[must_use]
    pub const fn revocation(&self) -> RevocationContract {
        self.revocation
    }

    /// Returns whether this lease's delegation contract admits further
    /// attenuation, which is the landed delegate right of the scope.
    #[must_use]
    pub const fn is_delegable(&self) -> bool {
        self.rights.contains(AuthorityRight::Delegate)
    }

    /// Returns whether the lease expiration still permits admission at `now_us`.
    #[must_use]
    pub const fn permits(&self, now_us: u64) -> bool {
        self.expiry.permits(now_us)
    }

    /// Returns the canonical text of this lease scope.
    #[must_use]
    pub fn canonical_text(&self) -> String {
        format!(
            "standing-lease:instance={};root={};lineage={};rights={};expiry={};expires-at-us={};revocation={}",
            self.instance.as_str(),
            self.root.as_str(),
            self.lineage
                .iter()
                .map(AuthorityInstanceId::as_str)
                .collect::<Vec<_>>()
                .join(">"),
            self.rights.wire_names().join(","),
            self.expiry.wire_name(),
            self.expiry.expires_at_us().unwrap_or(0),
            self.revocation.wire_name(),
        )
    }
}

/// One bounded standing lease: reusable authority rather than an approval cache.
///
/// A lease is obtainable only by attenuating an existing capability instance, so
/// it can only narrow the rights, generation, and lease of the authority it
/// descends from. It carries its own identity, lineage, rights, expiration, and
/// revocation contract; it carries no request, no subject, and no decision, and
/// this module exposes no cache that maps a request or subject to a decision.
#[derive(Debug, Eq, PartialEq)]
pub struct StandingLease {
    instance: AuthorityInstance,
    revocation: RevocationContract,
}

impl StandingLease {
    /// Derives one lease by attenuating an existing capability instance.
    ///
    /// A lease must be bounded, so an unleased attenuation is refused rather than
    /// reported as a lease with no expiration, and a refused attenuation reports
    /// the landed authority condition unchanged.
    pub fn attenuate(
        source: &AuthorityInstance,
        rights: RightsSet,
        lease: AuthorityLeasePolicy,
        revocation: RevocationContract,
    ) -> Result<Self, ApprovalError> {
        if lease == AuthorityLeasePolicy::Unleased {
            return Err(ApprovalError::UnboundedLease);
        }
        let instance = source
            .attenuate(rights, lease)
            .map_err(|landed| ApprovalError::AttenuationRefused { landed })?;
        Ok(Self {
            instance,
            revocation,
        })
    }

    /// Derives one further lease by delegating this lease under the landed
    /// delegate right, which is a narrowing rather than a widening.
    pub fn delegate(
        &self,
        rights: RightsSet,
        lease: AuthorityLeasePolicy,
        revocation: RevocationContract,
    ) -> Result<Self, ApprovalError> {
        if lease == AuthorityLeasePolicy::Unleased {
            return Err(ApprovalError::UnboundedLease);
        }
        let instance = self
            .instance
            .delegate(rights, lease)
            .map_err(|landed| ApprovalError::AttenuationRefused { landed })?;
        Ok(Self {
            instance,
            revocation,
        })
    }

    /// Returns the attenuated capability instance this lease stands on.
    #[must_use]
    pub const fn instance(&self) -> &AuthorityInstance {
        &self.instance
    }

    /// Returns the lease's instance identity.
    #[must_use]
    pub const fn id(&self) -> &AuthorityInstanceId {
        self.instance.id()
    }

    /// Returns the lineage root of this lease.
    #[must_use]
    pub const fn root(&self) -> &AuthorityInstanceId {
        self.instance.root()
    }

    /// Returns the rights this lease carries.
    #[must_use]
    pub const fn rights(&self) -> RightsSet {
        self.instance.rights()
    }

    /// Returns the lease expiration policy.
    #[must_use]
    pub const fn expiry(&self) -> AuthorityLeasePolicy {
        self.instance.lease()
    }

    /// Returns the absolute expiry instant of this lease.
    #[must_use]
    pub const fn expires_at_us(&self) -> Option<u64> {
        self.instance.lease().expires_at_us()
    }

    /// Returns the declared revocation contract.
    #[must_use]
    pub const fn revocation(&self) -> RevocationContract {
        self.revocation
    }

    /// Returns whether this lease's delegation contract admits further
    /// attenuation.
    #[must_use]
    pub const fn is_delegable(&self) -> bool {
        self.instance.rights().contains(AuthorityRight::Delegate)
    }

    /// Returns the fence category that fenced this lease, when one did.
    #[must_use]
    pub fn fenced(&self) -> Option<FenceCategory> {
        self.instance
            .fence_state()
            .point()
            .map(FencePoint::category)
    }

    /// Returns whether this lease was revoked, even when expiry fenced it first.
    #[must_use]
    pub fn is_revoked(&self) -> bool {
        self.instance.fence_latches().revocation().is_some()
    }

    /// Returns whether this lease still permits admission at `now_us`.
    #[must_use]
    pub fn permits(&self, now_us: u64) -> bool {
        self.fenced().is_none() && self.instance.lease().permits(now_us)
    }

    /// Returns the identity of the issuer whose authority this lease stands on.
    ///
    /// The issuer is the immediate ancestor of the lease instance in its lineage,
    /// or the lineage root when the lease instance has no ancestor, so a lease
    /// attenuated from an already-derived instance names the instance it was
    /// attenuated from.
    fn issuer(&self) -> &AuthorityInstanceId {
        self.instance
            .parent()
            .unwrap_or_else(|| self.instance.root())
    }

    /// Returns whether one identity is admitted by this lease's revocation
    /// contract.
    ///
    /// `IssuerOnly` admits the issuer alone; `IssuerOrHolder` admits the issuer and
    /// the lease holder.
    fn admits_revoker(&self, revoker: &AuthorityInstanceId) -> bool {
        match self.revocation {
            RevocationContract::IssuerOnly => revoker == self.issuer(),
            RevocationContract::IssuerOrHolder => {
                revoker == self.issuer() || revoker == self.instance.id()
            }
        }
    }

    /// Revokes this lease at its own linearization point.
    ///
    /// The declared revocation contract is the holder mapping.
    /// [`RevocationContract::IssuerOnly`] admits only the issuer: the immediate
    /// ancestor [`AuthorityInstance::parent`] of the lease instance, or the lineage
    /// root [`StandingLease::root`] when the instance has no ancestor.
    /// [`RevocationContract::IssuerOrHolder`] admits the issuer and the lease
    /// holder [`StandingLease::id`]. Any other revoker is refused as
    /// [`ApprovalError::RevocationNotContractual`] without fencing the lease, so a
    /// non-contractual revocation is reported rather than silently ignored, and a
    /// repeated permitted revocation returns the point the lease already held.
    pub fn revoke(&mut self, revoker: &AuthorityInstanceId) -> Result<FencePoint, ApprovalError> {
        if !self.admits_revoker(revoker) {
            return Err(ApprovalError::RevocationNotContractual);
        }
        Ok(self.instance.revoke())
    }

    /// Returns the declared decision scope of this lease.
    #[must_use]
    pub fn scope(&self) -> DecisionScope {
        DecisionScope::StandingLease(self.lease_scope())
    }

    /// Returns the declared lease scope of this lease.
    #[must_use]
    pub fn lease_scope(&self) -> LeaseScope {
        let mut lineage = self.instance.lineage().to_vec();
        lineage.push(self.instance.id().clone());
        LeaseScope {
            instance: self.instance.id().clone(),
            root: self.instance.root().clone(),
            lineage: Arc::from(lineage),
            rights: self.instance.rights(),
            expiry: self.instance.lease(),
            revocation: self.revocation,
        }
    }
}

/// The exact operation identity, attempts, lifetime, and constraints one decision
/// covers.
///
/// The default is one decision for one logical operation identity:
/// [`DecisionScope::OneShot`] names that operation and no other. Reusable
/// authority is never the default and is never an approval cache: a
/// [`DecisionScope::StandingLease`] is obtainable only by attenuation, and reusing
/// a decision across a new logical operation identity, a changed argument, a
/// widened destination, a newer policy revision, or a later authority generation
/// is refused by revalidation rather than reported as a decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DecisionScope {
    /// One decision for exactly one logical operation identity.
    OneShot {
        /// The logical operation identity this decision covers.
        operation: LogicalOperationId,
    },
    /// Reusable authority derived by attenuation, with its own lineage, rights,
    /// expiration, and revocation contract.
    StandingLease(LeaseScope),
}

impl DecisionScope {
    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(&self) -> &'static str {
        match self {
            Self::OneShot { .. } => "one-shot",
            Self::StandingLease(_) => "standing-lease",
        }
    }

    /// Returns the same exact portable spelling as [`Self::wire_name`].
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        self.wire_name()
    }

    /// Returns whether this scope covers exactly one logical operation identity.
    #[must_use]
    pub const fn is_one_shot(&self) -> bool {
        matches!(self, Self::OneShot { .. })
    }

    /// Returns the single logical operation identity this scope covers, when it
    /// covers exactly one.
    ///
    /// A standing lease is reusable authority rather than an operation decision:
    /// it reports `None` here, because it covers the operation its subject names
    /// and no further operation identity, argument set, destination, policy
    /// revision, or authority generation.
    #[must_use]
    pub const fn one_shot_operation(&self) -> Option<&LogicalOperationId> {
        match self {
            Self::OneShot { operation } => Some(operation),
            Self::StandingLease(_) => None,
        }
    }

    /// Returns the declared lease scope, when this scope is a standing lease.
    #[must_use]
    pub const fn lease_scope(&self) -> Option<&LeaseScope> {
        match self {
            Self::OneShot { .. } => None,
            Self::StandingLease(scope) => Some(scope),
        }
    }

    /// Returns the canonical text of this scope.
    #[must_use]
    pub fn canonical_text(&self) -> String {
        match self {
            Self::OneShot { operation } => format!("one-shot:{}", operation.as_str()),
            Self::StandingLease(scope) => scope.canonical_text(),
        }
    }
}

/// The decision constraints bound by one approval subject.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecisionConstraints {
    scope: DecisionScope,
    expires_at_us: u64,
    attempts: AttemptApplicability,
}

impl DecisionConstraints {
    /// Binds one decision scope, expiry, and attempt applicability.
    ///
    /// A decision that stands on a standing lease must not outlive that lease, so
    /// a validity bound beyond the lease expiration is refused rather than
    /// reported as a bounded decision.
    pub fn new(
        scope: DecisionScope,
        expires_at_us: u64,
        attempts: AttemptApplicability,
    ) -> Result<Self, ApprovalError> {
        if let Some(lease) = scope.lease_scope() {
            match lease.expires_at_us() {
                Some(expires) if expires_at_us <= expires => {}
                Some(_) => return Err(ApprovalError::DecisionOutlivesLease),
                None => return Err(ApprovalError::UnboundedLease),
            }
        }
        Ok(Self {
            scope,
            expires_at_us,
            attempts,
        })
    }

    /// Returns the decision scope.
    #[must_use]
    pub const fn scope(&self) -> &DecisionScope {
        &self.scope
    }

    /// Returns the decision's absolute validity bound.
    #[must_use]
    pub const fn expires_at_us(&self) -> u64 {
        self.expires_at_us
    }

    /// Returns the attempt applicability of this decision.
    #[must_use]
    pub const fn attempts(&self) -> AttemptApplicability {
        self.attempts
    }
}

/// One reference to the external target an operation would reach.
///
/// The reference names the selected downstream integration identity and the
/// digest of the landed target facts of the platform it reaches. Both inputs are
/// typed landed identities, so no host path, endpoint text, environment value, or
/// clock reading becomes a target reference.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalTargetRef {
    integration: CanonicalImplementationIdentity,
    target_facts: TargetFactsDigest,
}

impl ExternalTargetRef {
    /// Binds one selected integration identity to one target-facts digest.
    #[must_use]
    pub const fn new(
        integration: CanonicalImplementationIdentity,
        target_facts: TargetFactsDigest,
    ) -> Self {
        Self {
            integration,
            target_facts,
        }
    }

    /// Returns the selected downstream integration identity.
    #[must_use]
    pub const fn integration(&self) -> &CanonicalImplementationIdentity {
        &self.integration
    }

    /// Returns the digest of the landed target facts of the reached platform.
    #[must_use]
    pub const fn target_facts(&self) -> &TargetFactsDigest {
        &self.target_facts
    }

    /// Returns the canonical text of this reference.
    #[must_use]
    pub fn canonical_text(&self) -> String {
        format!(
            "integration={};target-facts={}",
            self.integration.as_str(),
            self.target_facts.as_str()
        )
    }
}

/// The canonical semantic subject of one approval request.
///
/// The subject binds exactly the inputs of `GNT-19.2-approval-subject` and no
/// others: the logical execution and task, the operation declaration and its exact
/// site, the stable logical operation identity, the semantic-argument digest, the
/// bounded approver presentation, the selected capability instance with its
/// authority-requirement identity, instance identity, and generation, the
/// authority lineage, the mapping revision, the effective policy revision, the
/// recovery class, the external target and effect summary, the protected scope the
/// operation would reach, and the decision's scope, expiry, attempt applicability,
/// and constraints.
///
/// Two requests are one subject if and only if their canonical subject bytes are
/// identical, so the subject is never reconstructed from a presentation, a
/// provider handle, or a mutable configuration, and every accessor here is an
/// accessor of the bound input rather than a recomputation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalSubject {
    execution: LogicalExecutionId,
    task: CanonicalCallableIdentity,
    declaration: CanonicalPath,
    site: StaticSiteId,
    operation: LogicalOperationId,
    arguments: SemanticArgumentDigest,
    presentation: ApproverPresentation,
    requirement: AuthorityRequirementId,
    instance: AuthorityInstanceId,
    generation: AuthorityGeneration,
    lineage: LineageRecord,
    mapping: MappingRevision,
    policy: PolicyRevision,
    recovery: RecoveryClass,
    target: ExternalTargetRef,
    effects: EffectSet,
    scope: ProtectedScope,
    constraints: DecisionConstraints,
}

impl ApprovalSubject {
    /// Returns the canonical bytes of this subject.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        encode_fields(SUBJECT_DOMAIN, &self.fields())
    }

    /// Returns the domain-separated digest of the canonical subject bytes.
    #[must_use]
    pub fn digest(&self) -> ApprovalSubjectDigest {
        ApprovalSubjectDigest::from_digest(digest_fields(
            SUBJECT_DOMAIN,
            &as_slices(&self.fields()),
        ))
    }

    /// Returns the bound logical execution.
    #[must_use]
    pub const fn execution(&self) -> &LogicalExecutionId {
        &self.execution
    }

    /// Returns the bound task identity.
    #[must_use]
    pub const fn task(&self) -> &CanonicalCallableIdentity {
        &self.task
    }

    /// Returns the bound operation declaration.
    #[must_use]
    pub const fn declaration(&self) -> &CanonicalPath {
        &self.declaration
    }

    /// Returns the bound exact operation site.
    #[must_use]
    pub const fn site(&self) -> &StaticSiteId {
        &self.site
    }

    /// Returns the bound stable logical operation identity.
    #[must_use]
    pub const fn operation(&self) -> &LogicalOperationId {
        &self.operation
    }

    /// Returns the bound semantic-argument digest.
    #[must_use]
    pub const fn arguments(&self) -> &SemanticArgumentDigest {
        &self.arguments
    }

    /// Returns the bound approver presentation.
    #[must_use]
    pub const fn presentation(&self) -> &ApproverPresentation {
        &self.presentation
    }

    /// Returns the bound authority-requirement identity.
    #[must_use]
    pub const fn requirement(&self) -> &AuthorityRequirementId {
        &self.requirement
    }

    /// Returns the identity of the selected capability instance.
    #[must_use]
    pub const fn instance(&self) -> &AuthorityInstanceId {
        &self.instance
    }

    /// Returns the generation of the selected capability instance.
    #[must_use]
    pub const fn generation(&self) -> AuthorityGeneration {
        self.generation
    }

    /// Returns the bound authority lineage record.
    #[must_use]
    pub const fn lineage(&self) -> &LineageRecord {
        &self.lineage
    }

    /// Returns the bound mapping revision.
    #[must_use]
    pub const fn mapping(&self) -> &MappingRevision {
        &self.mapping
    }

    /// Returns the bound effective policy revision.
    #[must_use]
    pub const fn policy(&self) -> &PolicyRevision {
        &self.policy
    }

    /// Returns the bound recovery class.
    #[must_use]
    pub const fn recovery(&self) -> RecoveryClass {
        self.recovery
    }

    /// Returns the bound external target reference.
    #[must_use]
    pub const fn target(&self) -> &ExternalTargetRef {
        &self.target
    }

    /// Returns the bound effect summary.
    #[must_use]
    pub const fn effects(&self) -> EffectSet {
        self.effects
    }

    /// Returns the bound protected scope.
    #[must_use]
    pub const fn scope(&self) -> &ProtectedScope {
        &self.scope
    }

    /// Returns the bound decision constraints.
    #[must_use]
    pub const fn constraints(&self) -> &DecisionConstraints {
        &self.constraints
    }

    /// Returns the ordered canonical fields of this subject.
    fn fields(&self) -> Vec<Vec<u8>> {
        vec![
            text(self.execution.as_str()),
            text(self.task.as_str()),
            text(self.declaration.as_str()),
            text(self.site.workflow().as_str()),
            components(self.site.position().components()),
            text(self.operation.as_str()),
            text(self.arguments.as_str()),
            text(&self.presentation.canonical_text()),
            text(self.requirement.as_str()),
            text(self.instance.as_str()),
            number(self.generation.value()),
            text(self.lineage.instance().as_str()),
            text(
                self.lineage
                    .parent()
                    .map_or("", AuthorityInstanceId::as_str),
            ),
            text(self.lineage.root().as_str()),
            number(self.lineage.generation().value()),
            vec![self.lineage.rights().bits()],
            text(self.lineage.lease().wire_name()),
            number(self.lineage.lease().expires_at_us().unwrap_or(0)),
            text(self.mapping.as_str()),
            text(self.policy.as_str()),
            text(self.recovery.wire_name()),
            text(&self.target.canonical_text()),
            text(
                &self
                    .effects
                    .iter()
                    .map(|effect| effect.wire_name())
                    .collect::<Vec<_>>()
                    .join(","),
            ),
            text(self.scope.class().wire_name()),
            text(self.scope.destination().wire_name()),
            text(self.scope.projection().kind().wire_name()),
            number(self.scope.charge().value()),
            text(self.constraints.scope().wire_name()),
            text(&self.constraints.scope().canonical_text()),
            number(self.constraints.expires_at_us()),
            text(self.constraints.attempts().wire_name()),
        ]
    }
}

/// One partial approval-subject input record.
///
/// Every input of `GNT-19.2-approval-subject` is supplied by name through one
/// setter, and [`ApprovalSubjectInputs::build`] fails closed while an input is
/// absent. Because each input is an owned typed value, the canonical bytes,
/// digest, and request identity of one complete input record depend on the inputs
/// alone and never on the order the setters were called in.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ApprovalSubjectInputs {
    execution: Option<LogicalExecutionId>,
    task: Option<CanonicalCallableIdentity>,
    declaration: Option<CanonicalPath>,
    site: Option<StaticSiteId>,
    operation: Option<LogicalOperationId>,
    arguments: Option<SemanticArgumentDigest>,
    presentation: Option<ApproverPresentation>,
    requirement: Option<AuthorityRequirementId>,
    instance: Option<AuthorityInstanceId>,
    generation: Option<AuthorityGeneration>,
    lineage: Option<LineageRecord>,
    mapping: Option<MappingRevision>,
    policy: Option<PolicyRevision>,
    recovery: Option<RecoveryClass>,
    target: Option<ExternalTargetRef>,
    effects: Option<EffectSet>,
    scope: Option<ProtectedScope>,
    constraints: Option<DecisionConstraints>,
}

impl ApprovalSubjectInputs {
    /// Binds the logical execution of the request.
    #[must_use]
    pub fn with_execution(mut self, execution: LogicalExecutionId) -> Self {
        self.execution = Some(execution);
        self
    }

    /// Binds the logical task of the request.
    #[must_use]
    pub fn with_task(mut self, task: CanonicalCallableIdentity) -> Self {
        self.task = Some(task);
        self
    }

    /// Binds the operation declaration.
    #[must_use]
    pub fn with_declaration(mut self, declaration: CanonicalPath) -> Self {
        self.declaration = Some(declaration);
        self
    }

    /// Binds the exact operation site.
    #[must_use]
    pub fn with_site(mut self, site: StaticSiteId) -> Self {
        self.site = Some(site);
        self
    }

    /// Binds the stable logical operation identity.
    #[must_use]
    pub fn with_operation(mut self, operation: LogicalOperationId) -> Self {
        self.operation = Some(operation);
        self
    }

    /// Binds the semantic-argument digest.
    #[must_use]
    pub fn with_arguments(mut self, arguments: SemanticArgumentDigest) -> Self {
        self.arguments = Some(arguments);
        self
    }

    /// Binds the bounded approver presentation.
    #[must_use]
    pub fn with_presentation(mut self, presentation: ApproverPresentation) -> Self {
        self.presentation = Some(presentation);
        self
    }

    /// Binds the authority-requirement identity.
    #[must_use]
    pub fn with_requirement(mut self, requirement: AuthorityRequirementId) -> Self {
        self.requirement = Some(requirement);
        self
    }

    /// Binds the selected capability-instance identity.
    #[must_use]
    pub fn with_instance(mut self, instance: AuthorityInstanceId) -> Self {
        self.instance = Some(instance);
        self
    }

    /// Binds the selected capability-instance generation.
    #[must_use]
    pub fn with_generation(mut self, generation: AuthorityGeneration) -> Self {
        self.generation = Some(generation);
        self
    }

    /// Binds the authority lineage record of the selected instance.
    #[must_use]
    pub fn with_lineage(mut self, lineage: LineageRecord) -> Self {
        self.lineage = Some(lineage);
        self
    }

    /// Binds the mapping revision.
    #[must_use]
    pub fn with_mapping(mut self, mapping: MappingRevision) -> Self {
        self.mapping = Some(mapping);
        self
    }

    /// Binds the effective policy revision.
    #[must_use]
    pub fn with_policy(mut self, policy: PolicyRevision) -> Self {
        self.policy = Some(policy);
        self
    }

    /// Binds the recovery class.
    #[must_use]
    pub fn with_recovery(mut self, recovery: RecoveryClass) -> Self {
        self.recovery = Some(recovery);
        self
    }

    /// Binds the external target reference.
    #[must_use]
    pub fn with_target(mut self, target: ExternalTargetRef) -> Self {
        self.target = Some(target);
        self
    }

    /// Binds the effect summary.
    #[must_use]
    pub fn with_effects(mut self, effects: EffectSet) -> Self {
        self.effects = Some(effects);
        self
    }

    /// Binds the protected scope the operation would reach.
    #[must_use]
    pub fn with_scope(mut self, scope: ProtectedScope) -> Self {
        self.scope = Some(scope);
        self
    }

    /// Binds the decision constraints.
    #[must_use]
    pub fn with_constraints(mut self, constraints: DecisionConstraints) -> Self {
        self.constraints = Some(constraints);
        self
    }

    /// Builds the canonical subject, or fails closed naming the absent input.
    ///
    /// A one-shot scope must name the subject's own logical operation identity,
    /// and a presentation that conceals an element must not carry reusable
    /// standing authority, so neither inconsistency can reach a subject.
    pub fn build(self) -> Result<ApprovalSubject, ApprovalError> {
        let execution = required(self.execution, "execution")?;
        let task = required(self.task, "task")?;
        let declaration = required(self.declaration, "declaration")?;
        let site = required(self.site, "site")?;
        let operation = required(self.operation, "operation")?;
        let arguments = required(self.arguments, "arguments")?;
        let presentation = required(self.presentation, "presentation")?;
        let requirement = required(self.requirement, "requirement")?;
        let instance = required(self.instance, "instance")?;
        let generation = required(self.generation, "generation")?;
        let lineage = required(self.lineage, "lineage")?;
        let mapping = required(self.mapping, "mapping")?;
        let policy = required(self.policy, "policy")?;
        let recovery = required(self.recovery, "recovery")?;
        let target = required(self.target, "target")?;
        let effects = required(self.effects, "effects")?;
        let scope = required(self.scope, "scope")?;
        let constraints = required(self.constraints, "constraints")?;
        if matches!(
            &presentation,
            ApproverPresentation::RedactedWithinDeclaredScope(_)
        ) && constraints.scope().lease_scope().is_some()
        {
            return Err(ApprovalError::PresentationConcealsScope);
        }
        if let Some(bound) = constraints.scope().one_shot_operation()
            && bound != &operation
        {
            return Err(ApprovalError::ScopeMismatch);
        }
        Ok(ApprovalSubject {
            execution,
            task,
            declaration,
            site,
            operation,
            arguments,
            presentation,
            requirement,
            instance,
            generation,
            lineage,
            mapping,
            policy,
            recovery,
            target,
            effects,
            scope,
            constraints,
        })
    }
}

/// One stable approval-request identity.
///
/// The identity is a domain-separated SHA-256 digest of the canonical subject
/// bytes alone. It has no public constructor, no decoder, and no deserializer, and
/// no provider request identifier, correlation token, or transport message number
/// participates, so it is independent of the process, session, approver, or
/// adapter that carries the request while remaining distinct from the subject
/// digest and from every operation, requirement, instance, and decision identity.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ApprovalRequestId(Arc<str>);

impl ApprovalRequestId {
    /// Derives the request identity of one canonical subject.
    #[must_use]
    pub fn of(subject: &ApprovalSubject) -> Self {
        let bytes = subject.canonical_bytes();
        Self(Arc::from(format!(
            "approval-request:{}",
            encode_hex(&digest_fields(APPROVAL_REQUEST_DOMAIN, &[&bytes]))
        )))
    }

    /// Returns the exact portable identity spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the lowercase digest text without the identity prefix.
    #[must_use]
    pub fn digest_hex(&self) -> &str {
        self.0.strip_prefix("approval-request:").unwrap_or(&self.0)
    }
}

/// One member of the closed approval outcome vocabulary.
///
/// The vocabulary is exactly the seven bounded outcomes of
/// `GNT-19.8-approval-outcome-taxonomy`, and it deliberately has no unknown or
/// ambiguous variant: an approval wait can neither fabricate an unknown operation
/// outcome for an operation that was definitely not admitted nor erase an unknown
/// outcome once target work may have begun. Each outcome is distinct and carries
/// its own diagnostic through [`ApprovalOutcome::code`].
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ApprovalOutcome {
    /// The approver granted the request.
    PositiveDecision,
    /// The approver denied the request.
    Denial,
    /// The approval wait expired.
    Expiration,
    /// The approval wait was cancelled.
    Cancellation,
    /// The approval adapter failed.
    AdapterFailure,
    /// The decision received was malformed.
    MalformedDecision,
    /// No approver was available.
    UnavailableApprover,
}

impl ApprovalOutcome {
    /// Every member of the closed vocabulary, in wire-name order.
    pub const ALL: [Self; 7] = [
        Self::PositiveDecision,
        Self::Denial,
        Self::Expiration,
        Self::Cancellation,
        Self::AdapterFailure,
        Self::MalformedDecision,
        Self::UnavailableApprover,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::PositiveDecision => "positive-decision",
            Self::Denial => "denial",
            Self::Expiration => "expiration",
            Self::Cancellation => "cancellation",
            Self::AdapterFailure => "approval-adapter-failure",
            Self::MalformedDecision => "malformed-decision",
            Self::UnavailableApprover => "unavailable-approver",
        }
    }

    /// Returns the same exact portable spelling as [`Self::wire_name`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.wire_name()
    }

    /// Strictly decodes one exact portable spelling.
    ///
    /// An unknown outcome has no representation: the closed vocabulary reports
    /// `None` rather than an unknown member, so a decision cannot be decoded into
    /// an outcome the specification does not define.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.wire_name() == value)
    }

    /// Returns the distinct frozen diagnostic code of this outcome.
    #[must_use]
    pub const fn code(self) -> ApprovalDiagnosticCode {
        match self {
            Self::PositiveDecision => ApprovalDiagnosticCode::PositiveDecision,
            Self::Denial => ApprovalDiagnosticCode::Denial,
            Self::Expiration => ApprovalDiagnosticCode::Expiration,
            Self::Cancellation => ApprovalDiagnosticCode::Cancellation,
            Self::AdapterFailure => ApprovalDiagnosticCode::AdapterFailure,
            Self::MalformedDecision => ApprovalDiagnosticCode::MalformedDecision,
            Self::UnavailableApprover => ApprovalDiagnosticCode::UnavailableApprover,
        }
    }

    /// Returns whether this outcome is a positive decision.
    #[must_use]
    pub const fn is_positive(self) -> bool {
        matches!(self, Self::PositiveDecision)
    }
}

/// One recorded outcome of one approval interaction.
///
/// The two states are deliberately distinct. An operation that never passed the
/// admission commit point has no effect and no external outcome, so its record
/// carries an approval-wait outcome and can never report ambiguity. An operation
/// that passed admission records the observed external outcome of the landed
/// model and carries no approval-wait outcome at all, so an ambiguous external
/// outcome is never reclassified as denied, expired, cancelled, or failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApprovalOutcomeRecord {
    /// The operation never reached the admission commit point.
    NotAdmitted {
        /// The approval-wait outcome that ended the interaction.
        outcome: ApprovalOutcome,
    },
    /// The operation passed admission and settles under its recovery class.
    Admitted {
        /// The landed admission whose settlement rule applies.
        admission: Admission,
        /// The external outcome as observed, never reclassified.
        observed: ExternalOutcome,
    },
}

impl ApprovalOutcomeRecord {
    /// Records one approval interaction that never reached the commit point.
    #[must_use]
    pub const fn not_admitted(outcome: ApprovalOutcome) -> Self {
        Self::NotAdmitted { outcome }
    }

    /// Records one admitted operation and its observed external outcome.
    #[must_use]
    pub const fn admitted(admission: Admission, observed: ExternalOutcome) -> Self {
        Self::Admitted {
            admission,
            observed,
        }
    }

    /// Returns the admission sequence number, when the operation was admitted.
    #[must_use]
    pub const fn admission_sequence(&self) -> Option<u64> {
        match self {
            Self::NotAdmitted { .. } => None,
            Self::Admitted { admission, .. } => Some(admission.sequence()),
        }
    }

    /// Returns the approval-wait outcome, which admitted work never carries.
    #[must_use]
    pub const fn approval_outcome(&self) -> Option<ApprovalOutcome> {
        match self {
            Self::NotAdmitted { outcome } => Some(*outcome),
            Self::Admitted { .. } => None,
        }
    }

    /// Returns the observed external outcome of admitted work.
    ///
    /// The observed outcome is returned through the landed settlement rule, which
    /// never reclassifies it, so an ambiguous outcome stays ambiguous.
    #[must_use]
    pub const fn external_outcome(&self) -> Option<ExternalOutcome> {
        match self {
            Self::NotAdmitted { .. } => None,
            Self::Admitted {
                admission,
                observed,
            } => Some(admission.settles(*observed)),
        }
    }

    /// Returns whether this record is ambiguous.
    ///
    /// An operation that was definitely not admitted has no effect and no
    /// external outcome, so it is never ambiguous; only an admitted operation
    /// whose external outcome is ambiguous reports ambiguity.
    #[must_use]
    pub fn is_ambiguous(&self) -> bool {
        matches!(self.external_outcome(), Some(ExternalOutcome::Ambiguous))
    }
}

/// One committed durable approval cut.
///
/// The cuts are ordered by the commits `GNT-19.7-durable-request-and-decision-cuts`
/// requires: the canonical request is committed before the implementation waits on
/// an external approver, the authenticated decision is committed before dispatch,
/// and admission and dispatch follow in that order. A cut can therefore be reached
/// only from its predecessor, so a decision before a committed request and a
/// dispatch before a committed decision are both refused.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DurableApprovalCut {
    /// The canonical request is durably committed before the wait begins.
    RequestCommitted,
    /// The authenticated decision is durably committed before dispatch.
    DecisionCommitted,
    /// The operation passed the admission commit point.
    Admitted,
    /// The operation was dispatched to its external target.
    Dispatched,
}

impl DurableApprovalCut {
    /// Every member of the closed vocabulary, in the required cut order.
    pub const ALL: [Self; 4] = [
        Self::RequestCommitted,
        Self::DecisionCommitted,
        Self::Admitted,
        Self::Dispatched,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::RequestCommitted => "request-committed",
            Self::DecisionCommitted => "decision-committed",
            Self::Admitted => "admitted",
            Self::Dispatched => "dispatched",
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

    /// Returns the position of this cut in the required commit order.
    #[must_use]
    pub const fn rank(self) -> u8 {
        match self {
            Self::RequestCommitted => 0,
            Self::DecisionCommitted => 1,
            Self::Admitted => 2,
            Self::Dispatched => 3,
        }
    }

    /// Advances one durable cut to its immediate successor, or fails closed.
    ///
    /// A cut that is not the immediate successor of the current one is refused
    /// without recording anything, so a dispatch can never be committed before a
    /// decision and a decision can never be committed before a request.
    pub const fn advance(self, next: Self) -> Result<Self, ApprovalError> {
        if next.rank() == self.rank() + 1 {
            Ok(next)
        } else {
            Err(ApprovalError::CutOutOfOrder {
                from: self,
                to: next,
            })
        }
    }

    /// Classifies one resumed execution after a crash at this cut.
    ///
    /// The three resumes of `GNT-19.7-durable-request-and-decision-cuts` are
    /// distinct. A crash at the committed request resumes the pending approval wait
    /// through its stable identity, before any decision is committed. A crash after
    /// the decision commit and before dispatch continues only under the same
    /// still-valid decision and operation identity. A crash after dispatch uses the
    /// target operation's recovery state and never solicits a second approval for
    /// work that may already have begun.
    #[must_use]
    pub const fn classify_resume(self) -> ResumeClass {
        match self {
            Self::RequestCommitted => ResumeClass::PendingDecision,
            Self::DecisionCommitted | Self::Admitted => ResumeClass::SameDecision,
            Self::Dispatched => ResumeClass::OperationRecovery,
        }
    }
}

/// How one resumed execution continues after a crash.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResumeClass {
    /// The committed request resumes the pending approval wait through its stable
    /// identity, before any decision is committed
    /// (`GNT-19.7-durable-request-and-decision-cuts`).
    PendingDecision,
    /// The execution continues under the same still-valid decision and operation
    /// identity.
    SameDecision,
    /// The execution hands off to the target operation's recovery state.
    OperationRecovery,
}

impl ResumeClass {
    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::PendingDecision => "pending-decision",
            Self::SameDecision => "same-decision",
            Self::OperationRecovery => "operation-recovery",
        }
    }

    /// Returns the same exact portable spelling as [`Self::wire_name`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.wire_name()
    }
}

/// One durable approval interaction, keyed by its stable request identity.
///
/// The record is created only by committing the request cut of one canonical
/// subject, so there is no way to begin at a later cut and no cache of decisions: a
/// pending decision resumes through the identity it was committed under, and the
/// model refuses a second request for one logical operation identity on resume.
/// The decision cut is reachable only through [`Self::commit_decision`], so a
/// committed decision always carries the decision identity and the outcome it was
/// committed with. Storage-level uniqueness of one pending request per logical
/// operation identity is the durable journal's obligation under
/// `GNT-19.7-durable-request-and-decision-cuts`; this model states the identity
/// rule and the cut order, not the journal's uniqueness constraint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableApprovalRecord {
    request: ApprovalRequestId,
    operation: LogicalOperationId,
    cut: DurableApprovalCut,
    decision: Option<ApprovalDecisionId>,
    outcome: Option<ApprovalOutcome>,
}

impl DurableApprovalRecord {
    /// Commits the request cut of one canonical subject.
    #[must_use]
    pub fn commit_request(subject: &ApprovalSubject) -> Self {
        Self {
            request: ApprovalRequestId::of(subject),
            operation: subject.operation().clone(),
            cut: DurableApprovalCut::RequestCommitted,
            decision: None,
            outcome: None,
        }
    }

    /// Returns the committed request identity.
    #[must_use]
    pub const fn request(&self) -> &ApprovalRequestId {
        &self.request
    }

    /// Returns the logical operation identity this interaction serves.
    #[must_use]
    pub const fn operation(&self) -> &LogicalOperationId {
        &self.operation
    }

    /// Returns the cut this interaction has reached.
    #[must_use]
    pub const fn cut(&self) -> DurableApprovalCut {
        self.cut
    }

    /// Returns the committed decision identity, when a decision is committed.
    #[must_use]
    pub const fn decision(&self) -> Option<&ApprovalDecisionId> {
        match &self.decision {
            Some(decision) => Some(decision),
            None => None,
        }
    }

    /// Returns the committed approval outcome, when a decision is committed.
    #[must_use]
    pub const fn outcome(&self) -> Option<ApprovalOutcome> {
        self.outcome
    }

    /// Commits one decision over the committed request of this interaction.
    ///
    /// This is the only path to the [`DurableApprovalCut::DecisionCommitted`] cut.
    /// A decision presented at another cut is refused as
    /// [`ApprovalError::CutOutOfOrder`], and a decision whose subject does not
    /// reproduce the committed request identity is refused as
    /// [`ApprovalError::DecisionNotOfRequest`], both without recording anything. On
    /// success the interaction stands at the decision cut and carries the decision
    /// identity and the outcome it was committed with.
    pub fn commit_decision(mut self, decision: &ApprovalDecision) -> Result<Self, ApprovalError> {
        if self.cut != DurableApprovalCut::RequestCommitted {
            return Err(ApprovalError::CutOutOfOrder {
                from: self.cut,
                to: DurableApprovalCut::DecisionCommitted,
            });
        }
        let presented = ApprovalRequestId::of(decision.subject());
        if presented != self.request {
            return Err(ApprovalError::DecisionNotOfRequest {
                request: Arc::from(presented.as_str()),
            });
        }
        self.cut = DurableApprovalCut::DecisionCommitted;
        self.decision = Some(decision.id());
        self.outcome = Some(decision.outcome());
        Ok(self)
    }

    /// Advances this interaction to its immediate successor cut.
    ///
    /// The immediate-successor rule of [`DurableApprovalCut::advance`] applies
    /// first, and every cut that requires committed state is then refused without
    /// recording anything. The decision cut is never reached here, because
    /// [`Self::commit_decision`] is its only path. The admitted cut requires a
    /// committed decision whose outcome granted the request, and the dispatched cut
    /// requires a committed decision.
    pub fn advance(self, next: DurableApprovalCut) -> Result<Self, ApprovalError> {
        let cut = self.cut.advance(next)?;
        match next {
            DurableApprovalCut::RequestCommitted => Ok(Self { cut, ..self }),
            DurableApprovalCut::DecisionCommitted => {
                Err(ApprovalError::DecisionNotCommitted { to: next })
            }
            DurableApprovalCut::Admitted => {
                self.committed_decision(next)?;
                if !self.committed_outcome_is_positive() {
                    return Err(ApprovalError::AdmissionWithoutPositiveDecision);
                }
                Ok(Self { cut, ..self })
            }
            DurableApprovalCut::Dispatched => {
                self.committed_decision(next)?;
                Ok(Self { cut, ..self })
            }
        }
    }

    /// Returns the committed decision identity, or refuses the cut that needs it.
    fn committed_decision(
        &self,
        to: DurableApprovalCut,
    ) -> Result<&ApprovalDecisionId, ApprovalError> {
        self.decision
            .as_ref()
            .ok_or(ApprovalError::DecisionNotCommitted { to })
    }

    /// Returns whether the committed outcome granted the request.
    ///
    /// A record with no committed decision has no committed outcome either, so this
    /// reports `false` rather than assuming a decision.
    fn committed_outcome_is_positive(&self) -> bool {
        self.outcome.is_some_and(ApprovalOutcome::is_positive)
    }

    /// Resumes this interaction for one subject through its stable identity.
    ///
    /// A subject whose canonical bytes reproduce the committed request identity
    /// resumes that interaction. A second request for the same logical operation
    /// identity is refused rather than committed, and a request identity that is
    /// not this interaction's is refused as unknown.
    pub fn resume(&self, subject: &ApprovalSubject) -> Result<DurableApprovalCut, ApprovalError> {
        if ApprovalRequestId::of(subject) == self.request {
            return Ok(self.cut);
        }
        if subject.operation() == &self.operation {
            return Err(ApprovalError::SecondRequestForOperation {
                operation: Arc::from(self.operation.as_str()),
            });
        }
        Err(ApprovalError::UnknownRequest {
            request: Arc::from(ApprovalRequestId::of(subject).as_str()),
        })
    }

    /// Classifies one resume of this interaction after a crash.
    #[must_use]
    pub const fn classify_resume(&self) -> ResumeClass {
        self.cut.classify_resume()
    }
}

/// Why one decision no longer matches the operation about to be admitted.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum StalenessReason {
    /// The semantic arguments or their canonical digest changed.
    Argument,
    /// The decision's scope or the protected release scope no longer matches:
    /// another logical operation identity, another class, destination,
    /// projection, or disclosure charge, or another attempt applicability.
    Scope,
    /// The selected capability instance, its descendant lineage, or the authority
    /// generation changed.
    Generation,
    /// The mapping revision changed.
    Mapping,
    /// The effective policy revision changed.
    Policy,
    /// The decision's declared validity bound changed.
    Lifetime,
    /// The bound approver presentation, including the sealed predicate that
    /// carries its meaning, changed.
    Presentation,
    /// One remaining bound subject input changed, so no difference is ever
    /// reported as fresh.
    Subject,
}

impl StalenessReason {
    /// Every member of the closed vocabulary, in reporting order.
    pub const ALL: [Self; 8] = [
        Self::Argument,
        Self::Scope,
        Self::Generation,
        Self::Mapping,
        Self::Policy,
        Self::Lifetime,
        Self::Presentation,
        Self::Subject,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Argument => "argument",
            Self::Scope => "scope",
            Self::Generation => "generation",
            Self::Mapping => "mapping",
            Self::Policy => "policy",
            Self::Lifetime => "lifetime",
            Self::Presentation => "presentation",
            Self::Subject => "subject",
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
}

/// Why one admission was fenced before it was committed.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum FenceReason {
    /// Authority the decision stands on was revoked.
    Revocation,
    /// The decision or the lease it stands on reached its expiry.
    Expiry,
}

impl FenceReason {
    /// Every member of the closed vocabulary, in reporting order.
    pub const ALL: [Self; 2] = [Self::Revocation, Self::Expiry];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Revocation => "revocation",
            Self::Expiry => "expiry",
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
}

/// The verdict of one revalidation immediately before host admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Revalidation {
    /// Every revalidated input still matches, so the decision may be admitted.
    Fresh,
    /// A semantic input changed, so the decision is stale and must not dispatch.
    Stale(StalenessReason),
    /// Revocation or expiry fenced the admission before it was committed.
    Fenced(FenceReason),
}

impl Revalidation {
    /// Returns whether the decision may still be admitted.
    #[must_use]
    pub const fn is_fresh(self) -> bool {
        matches!(self, Self::Fresh)
    }

    /// Returns the staleness that refused this admission, when it is stale.
    #[must_use]
    pub const fn staleness(self) -> Option<StalenessReason> {
        match self {
            Self::Stale(reason) => Some(reason),
            Self::Fresh | Self::Fenced(_) => None,
        }
    }

    /// Returns the fencing that refused this admission, when it is fenced.
    #[must_use]
    pub const fn fence(self) -> Option<FenceReason> {
        match self {
            Self::Fenced(reason) => Some(reason),
            Self::Fresh | Self::Stale(_) => None,
        }
    }

    /// Returns the recorded refusal, when the decision was not fresh.
    #[must_use]
    pub const fn refusal(self) -> Option<RefusalReason> {
        match self {
            Self::Fresh => None,
            Self::Stale(reason) => Some(RefusalReason::Stale(reason)),
            Self::Fenced(reason) => Some(RefusalReason::Fenced(reason)),
        }
    }
}

/// Why one admission was refused at the commit point.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RefusalReason {
    /// The bound subject no longer matched.
    Stale(StalenessReason),
    /// Revocation or expiry fenced the admission.
    Fenced(FenceReason),
}

impl RefusalReason {
    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Stale(_) => "stale",
            Self::Fenced(_) => "fenced",
        }
    }

    /// Returns the staleness reason, when the refusal was staleness.
    #[must_use]
    pub const fn staleness(self) -> Option<StalenessReason> {
        match self {
            Self::Stale(reason) => Some(reason),
            Self::Fenced(_) => None,
        }
    }

    /// Returns the fence reason, when the refusal was fencing.
    #[must_use]
    pub const fn fence(self) -> Option<FenceReason> {
        match self {
            Self::Fenced(reason) => Some(reason),
            Self::Stale(_) => None,
        }
    }
}

/// One recorded admission or refusal result at the single commit point.
///
/// An admitted result carries the [`Admission`] the authority instance actually
/// committed for the operation, so a commit point names the authority generation
/// and the settlement rule that admitted the work rather than a bare verdict that
/// something was admitted. [`Admission`] is `Copy`, so this result stays `Copy`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitPointResult {
    /// The operation passed the admission commit point, carrying the admission the
    /// authority instance committed.
    Admitted(Admission),
    /// The operation was refused at the commit point.
    Refused(RefusalReason),
}

impl CommitPointResult {
    /// Records one admission at the commit point.
    ///
    /// The admission is the landed value the authority instance returned for the
    /// admitted operation, so an admitted commit point always names the generation
    /// and the settlement rule that admitted it.
    #[must_use]
    pub const fn admitted(admission: Admission) -> Self {
        Self::Admitted(admission)
    }

    /// Records one refusal, or reports that a fresh verdict refused nothing.
    #[must_use]
    pub const fn refused(verdict: Revalidation) -> Option<Self> {
        match verdict.refusal() {
            Some(reason) => Some(Self::Refused(reason)),
            None => None,
        }
    }

    /// Returns whether the operation passed the admission commit point.
    #[must_use]
    pub const fn is_admitted(&self) -> bool {
        matches!(self, Self::Admitted(_))
    }

    /// Returns the admission the authority instance committed, when the operation
    /// was admitted.
    #[must_use]
    pub const fn admission(&self) -> Option<&Admission> {
        match self {
            Self::Admitted(admission) => Some(admission),
            Self::Refused(_) => None,
        }
    }

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Admitted(_) => "admitted",
            Self::Refused(_) => "refused",
        }
    }

    /// Returns the refusal, when the operation was refused.
    #[must_use]
    pub const fn refusal(self) -> Option<RefusalReason> {
        match self {
            Self::Admitted(_) => None,
            Self::Refused(reason) => Some(reason),
        }
    }
}

/// One decision recorded over one canonical subject.
///
/// A decision is an ordinary record of a decision that was taken: it carries the
/// subject it was taken over, the outcome, the authenticated actor that decided
/// it, the instant it was issued, and, when its scope is a standing lease, the
/// attenuated lease it stands on. It is not an admission, it is not a release
/// authorization, and it is never repaired or widened: a later revalidation either
/// reports it fresh or refuses the admission.
#[derive(Debug, Eq, PartialEq)]
pub struct ApprovalDecision {
    subject: ApprovalSubject,
    outcome: ApprovalOutcome,
    actor: AuthenticatedActor,
    issued_at_us: u64,
    lease: Option<StandingLease>,
}

impl ApprovalDecision {
    /// Records one decision over one canonical subject.
    ///
    /// A standing-lease scope must be presented together with the attenuated lease
    /// that declares exactly that scope, so a decision can never claim reusable
    /// authority it does not hold, and a decision that presents a lease for another
    /// scope is refused.
    pub fn new(
        subject: ApprovalSubject,
        outcome: ApprovalOutcome,
        actor: &AuthenticatedActor,
        issued_at_us: u64,
        lease: Option<StandingLease>,
    ) -> Result<Self, ApprovalError> {
        match (subject.constraints().scope().lease_scope(), &lease) {
            (None, None) => {}
            (Some(declared), Some(presented)) if presented.lease_scope() == *declared => {}
            _ => return Err(ApprovalError::ScopeMismatch),
        }
        Ok(Self {
            subject,
            outcome,
            actor: actor.clone(),
            issued_at_us,
            lease,
        })
    }

    /// Returns the canonical subject this decision was taken over.
    #[must_use]
    pub const fn subject(&self) -> &ApprovalSubject {
        &self.subject
    }

    /// Returns the outcome this decision recorded.
    #[must_use]
    pub const fn outcome(&self) -> ApprovalOutcome {
        self.outcome
    }

    /// Returns whether this decision granted the request.
    #[must_use]
    pub const fn is_positive(&self) -> bool {
        self.outcome.is_positive()
    }

    /// Returns the authenticated actor that decided the request.
    #[must_use]
    pub const fn actor(&self) -> &AuthenticatedActor {
        &self.actor
    }

    /// Returns the instant the decision was issued.
    #[must_use]
    pub const fn issued_at_us(&self) -> u64 {
        self.issued_at_us
    }

    /// Returns the decision's absolute validity bound.
    #[must_use]
    pub const fn expires_at_us(&self) -> u64 {
        self.subject.constraints().expires_at_us()
    }

    /// Returns the decision scope bound by the subject.
    #[must_use]
    pub const fn scope(&self) -> &DecisionScope {
        self.subject.constraints().scope()
    }

    /// Returns the standing lease this decision stands on, when it has one.
    #[must_use]
    pub const fn lease(&self) -> Option<&StandingLease> {
        self.lease.as_ref()
    }

    /// Returns the canonical bytes of this decision.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut fields = self.subject.fields();
        fields.push(text(self.outcome.wire_name()));
        fields.push(text(&self.actor.canonical_text()));
        fields.push(number(self.issued_at_us));
        fields.push(text(self.scope().wire_name()));
        encode_fields(DECISION_DOMAIN, &fields)
    }

    /// Returns the stable identity of this decision.
    #[must_use]
    pub fn id(&self) -> ApprovalDecisionId {
        let bytes = self.canonical_bytes();
        ApprovalDecisionId::from_digest(digest_fields(DECISION_DOMAIN, &[&bytes]))
    }

    /// Revalidates this decision against the subject about to be admitted.
    #[must_use]
    pub fn revalidate(
        &self,
        subject: &ApprovalSubject,
        request: &AdmissionRequest,
    ) -> Revalidation {
        revalidate(subject, self, request)
    }

    /// Returns the release grant of one holder authority for this decision.
    ///
    /// Approval alone releases nothing: this is the only path from a decision to a
    /// release permission, and it enforces the whole correspondence between the
    /// decision and the release it would authorize, in this order:
    ///
    /// 1. the decision must grant the request;
    /// 2. the release-holder authority must declare the subject's protected class
    ///    and destination;
    /// 3. the logical instant of the release must precede the decision's validity
    ///    bound (`now_us < expires_at_us`);
    /// 4. a decision standing on a standing lease must still be permitted by that
    ///    lease at that instant, so a revoked or expired lease releases nothing;
    /// 5. the release site must declare the subject's protected class;
    /// 6. the site's declared projection for the subject's class and destination
    ///    pair must be exactly the projection the subject's scope declares;
    /// 7. the disclosure budget must carry exactly the charge the subject's scope
    ///    declares.
    ///
    /// A release that fails any check yields `None` rather than a narrowed grant,
    /// and the grant is derived from that holder authority alone, so no authority
    /// right, capability instance, admission request, or ordinary value substitutes
    /// for it, and execution authority never implies release.
    #[must_use]
    pub fn release_grant(
        &self,
        holder: &ReleaseHolderAuthority,
        site: &ReleaseSite,
        budget: &DisclosureBudget,
        now_us: u64,
    ) -> Option<ReleaseGrant> {
        if !self.is_positive() {
            return None;
        }
        let scope = self.subject.scope();
        if !holder.classes().any(|class| class == scope.class())
            || !holder
                .destinations()
                .any(|destination| destination == scope.destination())
        {
            return None;
        }
        if now_us >= self.expires_at_us() {
            return None;
        }
        if !lease_permits(self.lease.as_ref(), now_us) {
            return None;
        }
        if !site_declares_scope_projection(site, *scope) {
            return None;
        }
        if !budget_charges_scope(budget, *scope) {
            return None;
        }
        Some(
            holder
                .attenuate(&[scope.class()], &[scope.destination()])
                .grant(),
        )
    }
}

/// Returns whether one optional standing lease still permits admission at
/// `now_us`.
///
/// A decision that stands on no lease is not restricted by a lease; a decision
/// that stands on one is permitted only while that lease still permits the
/// instant, so a revoked or expired lease releases nothing.
fn lease_permits(lease: Option<&StandingLease>, now_us: u64) -> bool {
    match lease {
        Some(lease) => lease.permits(now_us),
        None => true,
    }
}

/// Returns whether one release site declares the protected class of a scope and
/// exactly the projection that scope declares for its class and destination pair.
///
/// The site must declare the class, so a site that declares nothing for it refuses
/// the release, and its declared projection must agree with the scope, so a release
/// is never granted for a weaker projection than the decision was taken over.
fn site_declares_scope_projection(site: &ReleaseSite, scope: ProtectedScope) -> bool {
    site.declares_class(scope.class())
        && site.projection(scope.class(), scope.destination()) == Some(scope.projection().kind())
}

/// Returns whether one disclosure budget carries exactly the charge the protected
/// scope declares.
fn budget_charges_scope(budget: &DisclosureBudget, scope: ProtectedScope) -> bool {
    budget.charge() == scope.charge()
}

/// Revalidates one decision against the subject about to be admitted.
///
/// The revalidation is the fail-closed check `GNT-19.6` requires immediately
/// before host admission at the single commit point of
/// `GNT-3-T-AUTHORITY-ADMISSION`:
///
/// 1. revocation and expiry that fence the admission before it is committed,
///    which covers the landed revocation and the expiry of the decision and of the
///    lease it stands on;
/// 2. the arguments about to be dispatched;
/// 3. the selected capability instance, its descendant lineage, and the authority
///    generation, including the generation the caller presents;
/// 4. the mapping revision;
/// 5. the effective policy revision;
/// 6. the decision's scope and the protected release scope;
/// 7. the decision's remaining lifetime;
/// 8. the bound presentation, including the sealed predicate that carries the
///    meaning of a presentation that withheld an element;
/// 9. every remaining bound subject input.
///
/// The function is pure and returns a verdict only: it never dispatches, never
/// patches, never reinterprets, and never widens a stale decision, so a subject that
/// changed at all is reported rather than repaired.
#[must_use]
pub fn revalidate(
    subject: &ApprovalSubject,
    decision: &ApprovalDecision,
    request: &AdmissionRequest,
) -> Revalidation {
    if let Some(lease) = decision.lease() {
        if let Some(category) = lease.fenced() {
            return Revalidation::Fenced(match category {
                FenceCategory::Revocation => FenceReason::Revocation,
                FenceCategory::Expiry => FenceReason::Expiry,
            });
        }
        if let Some(expires_at) = lease.expires_at_us()
            && request.now_us >= expires_at
        {
            return Revalidation::Fenced(FenceReason::Expiry);
        }
    }
    if request.now_us >= decision.expires_at_us() {
        return Revalidation::Fenced(FenceReason::Expiry);
    }
    let decided = decision.subject();
    if subject.arguments() != decided.arguments() {
        return Revalidation::Stale(StalenessReason::Argument);
    }
    if subject.instance() != decided.instance()
        || subject.lineage() != decided.lineage()
        || subject.generation() != decided.generation()
        || request.generation != subject.generation()
    {
        return Revalidation::Stale(StalenessReason::Generation);
    }
    if subject.mapping() != decided.mapping() {
        return Revalidation::Stale(StalenessReason::Mapping);
    }
    if subject.policy() != decided.policy() {
        return Revalidation::Stale(StalenessReason::Policy);
    }
    if subject.scope() != decided.scope()
        || subject.constraints().scope() != decided.constraints().scope()
        || subject.constraints().attempts() != decided.constraints().attempts()
    {
        return Revalidation::Stale(StalenessReason::Scope);
    }
    if subject.constraints().expires_at_us() != decided.constraints().expires_at_us() {
        return Revalidation::Stale(StalenessReason::Lifetime);
    }
    if subject.presentation() != decided.presentation() {
        return Revalidation::Stale(StalenessReason::Presentation);
    }
    if request.recovery != subject.recovery() || subject.digest() != decided.digest() {
        return Revalidation::Stale(StalenessReason::Subject);
    }
    Revalidation::Fresh
}

/// One later revocation, expiry, or supersession of a decision.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AuditTransitionKind {
    /// The decision's authority expired later.
    Expiry,
    /// The decision's authority was revoked later.
    Revocation,
    /// A later decision superseded this one.
    Supersession,
}

impl AuditTransitionKind {
    /// Every member of the closed vocabulary, in wire-name order.
    pub const ALL: [Self; 3] = [Self::Expiry, Self::Revocation, Self::Supersession];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Expiry => "expiry",
            Self::Revocation => "revocation",
            Self::Supersession => "supersession",
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
}

/// One later transition recorded for one decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditTransition {
    kind: AuditTransitionKind,
    at_us: u64,
}

impl AuditTransition {
    /// Records one later transition at one logical instant.
    #[must_use]
    pub const fn new(kind: AuditTransitionKind, at_us: u64) -> Self {
        Self { kind, at_us }
    }

    /// Returns the transition kind.
    #[must_use]
    pub const fn kind(self) -> AuditTransitionKind {
        self.kind
    }

    /// Returns the logical instant of the transition.
    #[must_use]
    pub const fn at_us(self) -> u64 {
        self.at_us
    }

    /// Returns the canonical text of this transition.
    #[must_use]
    pub fn canonical_text(self) -> String {
        format!("{}@{}", self.kind.wire_name(), self.at_us)
    }
}

/// One capability that admits the declared view of approval audit evidence.
///
/// Approval audit evidence is a protected channel, because it names the
/// authenticated actor that decided the request, so observing it is an explicit,
/// typed act rather than an ordinary field read or rendering. The evidence store
/// holds this capability and issues it to a holder whose declared rights cover the
/// audit record of an admitted operation; no ordinary value, identity, or adapter
/// field mints one, and the capability is a declared-rights gate rather than
/// cryptographic enforcement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApprovalAuditAccess(());

impl ApprovalAuditAccess {
    /// Returns the approval-audit capability of the approval evidence store for one
    /// holder whose bound instance carries the observe right.
    ///
    /// The evidence store issues this capability to a holder whose declared rights
    /// contain [`AuthorityRight::Observe`], the landed right of reading the audit
    /// record of an admitted operation; a rights set without it is refused rather
    /// than narrowed. This constructor is the declared-rights gate, not
    /// cryptographic enforcement: it checks the rights the holder declares, and this
    /// pure model cannot verify that a host bound them.
    #[must_use]
    pub const fn grant(rights: RightsSet) -> Option<Self> {
        if rights.contains(AuthorityRight::Observe) {
            Some(Self(()))
        } else {
            None
        }
    }
}

/// Returns whether one admission names the subject it is recorded against.
///
/// The admission must have admitted the subject's authority generation and must
/// settle under the subject's recovery class, so recorded evidence never attributes
/// another generation's or another settlement rule's admission to this subject.
fn admission_is_of_subject(admission: &Admission, subject: &ApprovalSubject) -> bool {
    admission.generation() == subject.generation()
        && admission.settlement_rule() == subject.recovery()
}

/// One approval audit record: declared metadata only.
///
/// The evidence identifies the request, the decision, the authenticated actor that
/// decided it, the policy and its effective revision, the scope and constraints the
/// decision carries, its validity bounds, the admission or refusal result at the
/// commit point, and every later revocation, expiry, or supersession. It carries no
/// credential, no approval secret, no protected argument or content, no digest of a
/// protected argument, and no protected comment, and it is itself protected: it
/// implements no rendering trait and no deserializer, and its fields are reachable
/// only through [`ApprovalAuditEvidence::view`] under an [`ApprovalAuditAccess`]
/// capability.
#[derive(Clone, Eq, PartialEq)]
pub struct ApprovalAuditEvidence {
    request: ApprovalRequestId,
    decision: ApprovalDecisionId,
    requester: DeclaredName,
    approver: DeclaredName,
    tenant: DeclaredName,
    policy: DeclaredName,
    policy_revision: PolicyRevision,
    scope: Arc<str>,
    issued_at_us: u64,
    expires_at_us: u64,
    outcome: ApprovalOutcome,
    commit_point: CommitPointResult,
    transitions: Vec<AuditTransition>,
}

impl ApprovalAuditEvidence {
    /// Records one approval interaction and its commit-point result.
    ///
    /// An admitted commit point is accepted only for a decision that granted the
    /// request and only for the admission of the subject that decision was taken
    /// over: the admission must name the subject's authority generation and must
    /// settle under the subject's recovery class, so evidence never records that
    /// another generation, or another settlement rule, admitted this subject. A
    /// refusal commit point is accepted under any decision outcome, because a
    /// positive decision can be refused at the commit point.
    pub fn record(
        decision: &ApprovalDecision,
        commit_point: CommitPointResult,
    ) -> Result<Self, ApprovalError> {
        if let Some(admission) = commit_point.admission() {
            if !decision.is_positive() {
                return Err(ApprovalError::AdmissionWithoutPositiveDecision);
            }
            if !admission_is_of_subject(admission, decision.subject()) {
                return Err(ApprovalError::AdmissionNotOfSubject);
            }
        }
        let subject = decision.subject();
        let actor = decision.actor();
        Ok(Self {
            request: ApprovalRequestId::of(subject),
            decision: decision.id(),
            requester: actor.requester().clone(),
            approver: actor.approver().clone(),
            tenant: actor.tenant().clone(),
            policy: actor.policy().clone(),
            policy_revision: subject.policy().clone(),
            scope: Arc::from(subject.constraints().scope().canonical_text()),
            issued_at_us: decision.issued_at_us(),
            expires_at_us: decision.expires_at_us(),
            outcome: decision.outcome(),
            commit_point,
            transitions: Vec::new(),
        })
    }

    /// Returns this evidence with one later transition appended.
    #[must_use]
    pub fn with_transition(mut self, transition: AuditTransition) -> Self {
        self.transitions.push(transition);
        self
    }

    /// Returns the declared view of this evidence under one access capability.
    ///
    /// This is the only path to the evidence's fields, so no rendering, field read,
    /// or serialization reaches them without the capability.
    #[must_use]
    pub fn view(&self, _access: &ApprovalAuditAccess) -> ApprovalAuditView<'_> {
        ApprovalAuditView {
            request: &self.request,
            decision: &self.decision,
            requester: &self.requester,
            approver: &self.approver,
            tenant: &self.tenant,
            policy: &self.policy,
            policy_revision: &self.policy_revision,
            scope: &self.scope,
            issued_at_us: self.issued_at_us,
            expires_at_us: self.expires_at_us,
            outcome: self.outcome,
            commit_point: self.commit_point,
            transitions: &self.transitions,
        }
    }
}

/// The declared view of one approval audit record: ordinary metadata, no payload.
///
/// The view names the request, the decision, the authenticated identities, the
/// policy and its effective revision, the scope, the validity bounds, the outcome,
/// the commit-point result, and the later transitions. It carries no credential, no
/// approval secret, and no protected argument or content, so it is ordinary
/// settlement once the applicable capability has admitted it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApprovalAuditView<'a> {
    request: &'a ApprovalRequestId,
    decision: &'a ApprovalDecisionId,
    requester: &'a DeclaredName,
    approver: &'a DeclaredName,
    tenant: &'a DeclaredName,
    policy: &'a DeclaredName,
    policy_revision: &'a PolicyRevision,
    scope: &'a str,
    issued_at_us: u64,
    expires_at_us: u64,
    outcome: ApprovalOutcome,
    commit_point: CommitPointResult,
    transitions: &'a [AuditTransition],
}

impl<'a> ApprovalAuditView<'a> {
    /// Returns the request identity of the interaction.
    #[must_use]
    pub const fn request(self) -> &'a ApprovalRequestId {
        self.request
    }

    /// Returns the decision identity of the interaction.
    #[must_use]
    pub const fn decision(self) -> &'a ApprovalDecisionId {
        self.decision
    }

    /// Returns the authenticated requester identity.
    #[must_use]
    pub const fn requester(self) -> &'a DeclaredName {
        self.requester
    }

    /// Returns the authenticated approver identity.
    #[must_use]
    pub const fn approver(self) -> &'a DeclaredName {
        self.approver
    }

    /// Returns the authenticated tenant identity.
    #[must_use]
    pub const fn tenant(self) -> &'a DeclaredName {
        self.tenant
    }

    /// Returns the authenticated policy identity.
    #[must_use]
    pub const fn policy(self) -> &'a DeclaredName {
        self.policy
    }

    /// Returns the effective policy revision of the decision.
    #[must_use]
    pub const fn policy_revision(self) -> &'a PolicyRevision {
        self.policy_revision
    }

    /// Returns the canonical scope text of the decision.
    #[must_use]
    pub const fn scope(self) -> &'a str {
        self.scope
    }

    /// Returns the instant the decision was issued.
    #[must_use]
    pub const fn issued_at_us(self) -> u64 {
        self.issued_at_us
    }

    /// Returns the decision's absolute validity bound.
    #[must_use]
    pub const fn expires_at_us(self) -> u64 {
        self.expires_at_us
    }

    /// Returns the recorded outcome.
    #[must_use]
    pub const fn outcome(self) -> ApprovalOutcome {
        self.outcome
    }

    /// Returns the recorded commit-point result.
    #[must_use]
    pub const fn commit_point(self) -> CommitPointResult {
        self.commit_point
    }

    /// Returns the later transitions recorded for this decision.
    #[must_use]
    pub const fn transitions(self) -> &'a [AuditTransition] {
        self.transitions
    }

    /// Returns the canonical view text, which contains no protected content.
    #[must_use]
    pub fn canonical_text(self) -> String {
        let transitions = self
            .transitions
            .iter()
            .map(|transition| transition.canonical_text())
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "request={};decision={};requester={};approver={};tenant={};policy={};policy-revision={};scope={};issued-at-us={};expires-at-us={};outcome={};commit-point={};transitions={}",
            self.request.as_str(),
            self.decision.as_str(),
            self.requester.as_str(),
            self.approver.as_str(),
            self.tenant.as_str(),
            self.policy.as_str(),
            self.policy_revision.as_str(),
            self.scope,
            self.issued_at_us,
            self.expires_at_us,
            self.outcome.wire_name(),
            self.commit_point.wire_name(),
            transitions,
        )
    }
}
