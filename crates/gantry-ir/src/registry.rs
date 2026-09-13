//! Pure authenticated package-acquisition and registry-trust model.
//!
//! This module is the machine-checked model for `SPEC.md` Section 27, clauses
//! `GNT-27.0-authenticated-package-acquisition-and-registry-trust` through
//! `GNT-27.14-registry-non-claims`.
//!
//! Scope is deliberately narrow. Every rule here is a pure function of its own
//! arguments: this module reads no clock, no host path, no environment variable, no
//! network response, no registry answer, and no live handle, and it exposes no
//! constructor that accepts one. Freshness is decided over an explicitly supplied
//! [`EpochObservation`] and one explicitly declared expiry bound, never over the system
//! clock, and acquisition evidence is decided over explicitly supplied checkout,
//! vendor, and mirror declarations, never over a performed fetch.
//!
//! Canonical identity text is explicit and stable. Every identity here is derived under
//! its own domain separator from declared fields, so equal declared inputs produce
//! equal identities and equal digests, and Rust `Debug` and `Display` renderings are
//! presentation only and are never protocol identities.
//!
//! Landed contracts are cited and reused rather than redeclared.
//! [`PackageName`](crate::package::PackageName), [`PackageVersion`], [`FeatureName`],
//! and [`TargetKind`] keep their landed meanings and their landed validations, so the
//! package vocabulary of `GNT-16.6-target-kinds` and
//! `GNT-16.7-public-interface-manifest` is not restated here; the landed
//! `gantry_core::unicode` helpers decide normalization and confusability so this model
//! invents no second Unicode policy; and `gantry_core::protocol::ProtocolVersion` tags
//! the snapshot format rather than a private version number.
//!
//! Three separations stay explicit.
//!
//! * A configuration alias is never a semantic identity: [`AliasBindings`] decides the
//!   bound authenticated identity of one alias and refuses the request that asks the
//!   alias spelling itself to stand as an identity.
//! * Trust is never ambient: [`TrustStore::verify`] admits a snapshot only through an
//!   explicitly declared root or one of its narrowing delegations, so an empty store,
//!   an unknown publisher, and an out-of-scope delegation are three distinct refusals.
//! * Every verification refusal carries [`Attribution`], the causing declaration's
//!   index and identity (or, when no declaration binds the causing entry, that entry's
//!   index and its unbound identity), so no trust or freshness refusal is reported
//!   without the declaration that caused it.

// The diagnostic, refusal, and code-carrying values deliberately retain whole
// identities so a rejected publication, snapshot, or acquisition reports the exact
// identity it disagreed with. Boxing those fields would hide identity behind an
// allocation at every construction and match site, so this module answers the size
// lints explicitly instead of weakening its own diagnostics.
#![allow(clippy::result_large_err)]
#![allow(clippy::large_enum_variant)]

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use gantry_core::protocol::ProtocolVersion;
use gantry_core::unicode::{
    confusable_skeleton, is_nfc, is_xid_continue, is_xid_start, normalize_nfc, to_full_lowercase,
};

use crate::authority::digest_fields;
use crate::manifest::encode_hex;
use crate::package::{DependencyAlias, FeatureName, PackageName, PackageVersion, TargetKind};

/// Clause key of the section itself.
const SECTION_CLAUSE: &str = "GNT-27.0-authenticated-package-acquisition-and-registry-trust";
/// Clause key of canonical source identity.
const SOURCE_IDENTITY_CLAUSE: &str =
    "GNT-27.1-immutable-source-identity-and-source-kind-vocabulary";
/// Clause key of canonical names.
const NAME_CLAUSE: &str = "GNT-27.2-canonical-publication-names-and-external-name-mapping";
/// Clause key of the metadata snapshot.
const SNAPSHOT_CLAUSE: &str = "GNT-27.3-authenticated-metadata-snapshot-and-client-verification";
/// Clause key of trust roots and delegation.
const TRUST_CLAUSE: &str = "GNT-27.4-trust-roots-and-delegated-authority";
/// Clause key of key rotation and compromise recovery.
const KEY_CLAUSE: &str = "GNT-27.5-signing-key-rotation-and-compromise-recovery";
/// Clause key of expiry and freshness.
const FRESHNESS_CLAUSE: &str = "GNT-27.6-expiry-freshness-and-offline-mode";
/// Clause key of rollback and freeze resistance.
const ROLLBACK_CLAUSE: &str = "GNT-27.7-rollback-and-freeze-resistance";
/// Clause key of publication immutability.
const PUBLICATION_CLAUSE: &str = "GNT-27.8-publication-immutability";
/// Clause key of yank semantics.
const YANK_CLAUSE: &str = "GNT-27.9-yank-semantics";
/// Clause key of security revocation.
const REVOCATION_CLAUSE: &str = "GNT-27.10-security-revocation-and-durable-execution-policy";
/// Clause key of pinned VCS, path, and vendor verification.
const ACQUISITION_CLAUSE: &str = "GNT-27.11-vcs-path-and-vendor-source-verification";
/// Clause key of lockfile evidence.
const LOCKFILE_CLAUSE: &str = "GNT-27.12-lockfile-evidence-binding";
/// Clause key of failure attribution.
const ATTRIBUTION_CLAUSE: &str = "GNT-27.13-trust-failure-attribution";
/// Clause key of the section's explicit non-claims.
const NON_CLAIMS_CLAUSE: &str = "GNT-27.14-registry-non-claims";

/// The clause keys this model implements, in clause order.
///
/// Every diagnostic names exactly one of these keys through
/// [`RegistryDiagnosticCode::clause`], and every [`RegistryError`] names one through
/// [`RegistryError::clause`], so every refusal is attributable to the clause that owns
/// it.
pub const REGISTRY_CLAUSES: [&str; 15] = [
    SECTION_CLAUSE,
    SOURCE_IDENTITY_CLAUSE,
    NAME_CLAUSE,
    SNAPSHOT_CLAUSE,
    TRUST_CLAUSE,
    KEY_CLAUSE,
    FRESHNESS_CLAUSE,
    ROLLBACK_CLAUSE,
    PUBLICATION_CLAUSE,
    YANK_CLAUSE,
    REVOCATION_CLAUSE,
    ACQUISITION_CLAUSE,
    LOCKFILE_CLAUSE,
    ATTRIBUTION_CLAUSE,
    NON_CLAIMS_CLAUSE,
];

/// One closed non-claim of `GNT-27.14-registry-non-claims`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RegistryNonClaim {
    /// Verified provenance does not establish safety, correctness, or compatibility.
    VerifiedProvenanceSafety,
    /// The model does not operate or rely on a transparency log.
    TransparencyLogOperation,
    /// A registry is not trusted beyond entries authenticated under a declared root.
    RegistryHonestyBeyondVerifiedEntries,
    /// A mirror or vendor copy is not equivalent beyond its compared authenticated snapshot.
    TransportUniverseEquivalence,
    /// A yank is not a security statement.
    YankSecurityStatement,
    /// A revocation does not prevent an already linked executable from running.
    RevocationRetroactiveExecutionPrevention,
    /// An offline result is not current.
    OfflineCurrentness,
    /// Resolution is not promised to terminate or succeed.
    ResolutionTerminationOrAvailability,
    /// Durable execution is not promised to migrate automatically.
    AutomaticDurableMigration,
}

impl RegistryNonClaim {
    /// Every registry non-claim in the declared Section 27.14 order.
    pub const ALL: [Self; 9] = [
        Self::VerifiedProvenanceSafety,
        Self::TransparencyLogOperation,
        Self::RegistryHonestyBeyondVerifiedEntries,
        Self::TransportUniverseEquivalence,
        Self::YankSecurityStatement,
        Self::RevocationRetroactiveExecutionPrevention,
        Self::OfflineCurrentness,
        Self::ResolutionTerminationOrAvailability,
        Self::AutomaticDurableMigration,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::VerifiedProvenanceSafety => "verified-provenance-safety",
            Self::TransparencyLogOperation => "transparency-log-operation",
            Self::RegistryHonestyBeyondVerifiedEntries => {
                "registry-honesty-beyond-verified-entries"
            }
            Self::TransportUniverseEquivalence => "transport-universe-equivalence",
            Self::YankSecurityStatement => "yank-security-statement",
            Self::RevocationRetroactiveExecutionPrevention => {
                "revocation-retroactive-execution-prevention"
            }
            Self::OfflineCurrentness => "offline-currentness",
            Self::ResolutionTerminationOrAvailability => "resolution-termination-or-availability",
            Self::AutomaticDurableMigration => "automatic-durable-migration",
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
            Self::VerifiedProvenanceSafety => REGISTRY_NON_CLAIMS[0],
            Self::TransparencyLogOperation => REGISTRY_NON_CLAIMS[1],
            Self::RegistryHonestyBeyondVerifiedEntries => REGISTRY_NON_CLAIMS[2],
            Self::TransportUniverseEquivalence => REGISTRY_NON_CLAIMS[3],
            Self::YankSecurityStatement => REGISTRY_NON_CLAIMS[4],
            Self::RevocationRetroactiveExecutionPrevention => REGISTRY_NON_CLAIMS[5],
            Self::OfflineCurrentness => REGISTRY_NON_CLAIMS[6],
            Self::ResolutionTerminationOrAvailability => REGISTRY_NON_CLAIMS[7],
            Self::AutomaticDurableMigration => REGISTRY_NON_CLAIMS[8],
        }
    }

    /// Returns the requirement anchor that owns this non-claim.
    #[must_use]
    pub const fn requirement(self) -> &'static str {
        NON_CLAIMS_CLAUSE
    }
}

/// The frozen registry non-claims of `GNT-27.14-registry-non-claims`, in declared order.
pub const REGISTRY_NON_CLAIMS: [&str; 9] = [
    "No source safety, correctness, or behavioral compatibility guarantee from verified provenance: authenticated metadata establishes declared authorization over declared bytes and nothing further.",
    "No transparency-log operation, append-only behavior, or equivocation-detection guarantee: such a log may strengthen audit and is not a substitute for client verification and trusted-root lifecycle.",
    "No registry-honesty guarantee beyond entries verified under a declared root: an entry no declared authority covers is refused rather than trusted.",
    "No nominal-universe equivalence from a mirror, vendor copy, or substitution: Section 27 compares one declared authenticated snapshot and claims nothing further.",
    "No security claim from a yank: yanks change ordinary new resolution while Section 27.10 owns revocation.",
    "No prevention of an already linked executable from running after revocation: revocation is a declared policy input and never rewrites, reinterprets, or substitutes an existing artifact.",
    "No currentness guarantee from an offline result: offline verification reports declared age and never claims an online check.",
    "No resolution termination or success guarantee: this section fixes declared checks and refusals, not a schedule or availability.",
    "No automatic durable-execution migration guarantee: cancellation, drain, and migration facilities remain profile-gated.",
];

/// The declared order of the registry non-claims (`GNT-27.14`).
pub const REGISTRY_NON_CLAIM_ORDER: [RegistryNonClaim; 9] = RegistryNonClaim::ALL;

/// A Section 27.14 non-claim was presented as a guarantee.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistryNonClaimError {
    claim: RegistryNonClaim,
}

impl RegistryNonClaimError {
    /// Returns the non-claim that was overstated.
    #[must_use]
    pub const fn claim(self) -> RegistryNonClaim {
        self.claim
    }

    /// Returns the exact requirement anchor that owns this violation.
    #[must_use]
    pub const fn requirement_anchor(self) -> &'static str {
        NON_CLAIMS_CLAUSE
    }
}

/// One presented Section 27.14 non-claim assertion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistryNonClaimAssertion {
    claim: RegistryNonClaim,
    presented_as_guarantee: bool,
}

impl RegistryNonClaimAssertion {
    /// Records whether one registry non-claim is presented as a guarantee.
    #[must_use]
    pub const fn new(claim: RegistryNonClaim, presented_as_guarantee: bool) -> Self {
        Self {
            claim,
            presented_as_guarantee,
        }
    }

    /// Returns the non-claim this assertion names.
    #[must_use]
    pub const fn claim(&self) -> RegistryNonClaim {
        self.claim
    }

    /// Returns whether this assertion presents the non-claim as a guarantee.
    #[must_use]
    pub const fn is_presented_as_guarantee(&self) -> bool {
        self.presented_as_guarantee
    }
}

/// Refuses any presentation of a Section 27.14 non-claim as a guarantee.
///
/// # Errors
///
/// Returns [`RegistryNonClaimError`] for the first assertion that overstates a non-claim as a
/// guarantee.
pub fn check_registry_non_claims(
    assertions: &[RegistryNonClaimAssertion],
) -> Result<(), RegistryNonClaimError> {
    for assertion in assertions {
        if assertion.presented_as_guarantee {
            return Err(RegistryNonClaimError {
                claim: assertion.claim,
            });
        }
    }
    Ok(())
}

/// The greatest admitted number of scalars in one registry name.
pub const REGISTRY_NAME_SCALAR_LIMIT: usize = 256;

/// Domain separator for canonical source-identity derivation.
const SOURCE_IDENTITY_DOMAIN: &str = "gantry.registry-source-identity/v1";
/// Domain separator for canonical registry-name derivation.
const NAME_IDENTITY_DOMAIN: &str = "gantry.registry-name-identity/v1";
/// Domain separator for generated external-name aliases.
const EXTERNAL_ALIAS_DOMAIN: &str = "gantry.registry-external-alias/v1";
/// Domain separator for the canonical metadata-snapshot encoding.
const SNAPSHOT_DOMAIN: &str = "gantry.registry-metadata-snapshot/v1";
/// Domain separator for the authenticated snapshot identity.
const SNAPSHOT_IDENTITY_DOMAIN: &str = "gantry.registry-snapshot-identity/v1";
/// Domain separator for declared signature values.
const SIGNATURE_DOMAIN: &str = "gantry.registry-declared-signature/v1";
/// Domain separator for authenticated delegation evidence.
const DELEGATION_DOMAIN: &str = "gantry.registry-delegation-evidence/v1";
/// Domain separator for authenticated key-rotation evidence.
const ROTATION_DOMAIN: &str = "gantry.registry-rotation-evidence/v1";
/// Domain separator for authenticated compromise-recovery evidence.
const COMPROMISE_DOMAIN: &str = "gantry.registry-compromise-evidence/v1";
/// Domain separator for advisory authorization digests.
const ADVISORY_DOMAIN: &str = "gantry.registry-advisory/v1";
/// Domain separator for the canonical lockfile encoding.
const LOCKFILE_DOMAIN: &str = "gantry.registry-lockfile/v1";
/// Domain separator for one lockfile record's evidence digest.
const LOCKFILE_RECORD_DOMAIN: &str = "gantry.registry-lockfile-record/v1";
/// Domain separator for the lockfile feature collection attestation.
const LOCKFILE_FEATURES_DOMAIN: &str = "gantry.registry-lockfile-features/v1";
/// Domain separator for the lockfile target collection attestation.
const LOCKFILE_TARGETS_DOMAIN: &str = "gantry.registry-lockfile-targets/v1";
/// Domain separator for the lockfile target-artifact collection attestation.
const LOCKFILE_TARGET_ARTIFACTS_DOMAIN: &str = "gantry.registry-lockfile-target-artifacts/v1";
/// Domain separator for the lockfile dependency collection attestation.
const LOCKFILE_DEPENDENCIES_DOMAIN: &str = "gantry.registry-lockfile-dependencies/v1";
/// Domain separator for the lockfile interface-digest collection attestation.
const LOCKFILE_INTERFACES_DOMAIN: &str = "gantry.registry-lockfile-interfaces/v1";
/// Domain separator for the lockfile generator-input collection attestation.
const LOCKFILE_GENERATOR_INPUTS_DOMAIN: &str = "gantry.registry-lockfile-generator-inputs/v1";
/// Domain separator for one complete target-qualified artifact set.
const TARGET_ARTIFACT_SET_DOMAIN: &str = "gantry.registry-target-artifact-set/v1";

/// Returns the lowercase hexadecimal spelling of one digest.
fn hex(digest: &[u8; 32]) -> String {
    encode_hex(digest)
}

/// Attests one canonical lockfile collection under its own domain and cardinality.
///
/// The count prevents an empty member from being confused with an omitted collection, while the
/// separate domains prevent otherwise byte-identical interface, generator, dependency, target,
/// and artifact collections from being retagged as one another.
fn attest_lockfile_collection(domain: &str, values: impl IntoIterator<Item = Vec<u8>>) -> [u8; 32] {
    let values = values.into_iter().collect::<Vec<_>>();
    let count = (values.len() as u64).to_be_bytes();
    let mut fields = Vec::with_capacity(values.len() + 1);
    fields.push(count.as_slice());
    fields.extend(values.iter().map(Vec::as_slice));
    digest_fields(domain, &fields)
}

/// Returns whether one spelling is exactly 64 lowercase hexadecimal digits.
fn is_hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Returns whether one spelling is admitted as a declaration name.
fn is_declared_spelling(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

/// Appends one JSON string literal in the canonical encoding style of this crate.
fn push_json_string(output: &mut String, value: &str) {
    output.push('"');
    for scalar in value.chars() {
        match scalar {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            control if control.is_control() => {
                output.push_str(&format!("\\u{:04x}", u32::from(control)));
            }
            other => output.push(other),
        }
    }
    output.push('"');
}

/// Escapes one admitted name into one unambiguous ASCII alias spelling.
///
/// Every scalar that is not an ASCII letter or digit is escaped as `_u` + its
/// uppercase hexadecimal code point + `_`, and a literal `_` is escaped too, so the
/// escape is injective, the result is a legal ASCII alias, and two distinct admitted
/// names never produce one escaped spelling.
fn escape_spelling(value: &str) -> String {
    let mut output = String::new();
    for scalar in value.chars() {
        if scalar.is_ascii_alphanumeric() {
            output.push(scalar);
        } else {
            output.push_str(&format!("_u{:X}_", u32::from(scalar)));
        }
    }
    output
}

/// The closed trust-failure reason vocabulary of `GNT-27.13`.
///
/// These reasons are independent of diagnostic-code evolution.  A structured refusal carries
/// exactly one member of this vocabulary and the requirement anchor that owns it, so callers
/// never have to infer a trust decision from rendered prose or a loosely related error code.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TrustFailureReason {
    /// No declared trust root governs the requested source.
    AbsentTrustRoot,
    /// A presented signing authority is not declared for the required decision.
    UnauthorizedSigningAuthority,
    /// A declared delegation does not cover the required coordinates.
    InsufficientDelegationScope,
    /// The presented delegation evidence does not form a complete root-to-signer chain.
    IncompleteDelegationChain,
    /// A delegation is not valid at the declared sequence or epoch.
    DelegationNotCurrentlyValid,
    /// A metadata snapshot is outside its declared validity window.
    ExpiredMetadataSnapshot,
    /// No explicit instant was supplied for a freshness decision.
    MissingObservedInstant,
    /// A pinned snapshot is stale for its declared offline witness.
    StaleSnapshot,
    /// A snapshot sequence is below the retained minimum.
    RolledBackSequence,
    /// One retained sequence names different snapshot contents.
    EquivocatedSequence,
    /// No authenticated successor arrived before the retained staleness bound elapsed.
    DetectedFreeze,
    /// A publication name is not canonical.
    NoncanonicalPublicationName,
    /// A publication name is structurally malformed for its declared name domain.
    MalformedPublicationName,
    /// Two publication names collide under the canonical relation.
    CanonicalNameCollision,
    /// A published tuple names bytes different from its retained immutable record.
    PublicationImmutabilityViolation,
    /// Ordinary new resolution selected a yanked release.
    YankedRelease,
    /// An authenticated advisory revokes the requested artifact.
    RevokedArtifact,
    /// A version-control revision is not the authenticated immutable revision.
    UnverifiedSourceRevision,
    /// Delivered source-tree or acquisition evidence differs from its authenticated identity.
    UnverifiedSourceTreeIdentity,
    /// A lockfile record is incomplete, extra, stale, or cannot be authenticated.
    UnverifiableLockfileRecord,
    /// A lockfile declaration or historical-evidence record is structurally invalid.
    InvalidLockfileRecord,
    /// No valid pinned snapshot is available for explicit offline use.
    UnavailablePinnedSnapshot,
    /// Multiple roots would be combined without an explicit declared policy.
    UndeclaredTrustDisjunction,
    /// A declared source identity is malformed.
    MalformedSourceIdentity,
    /// A request attempted fallback between closed source kinds.
    SourceKindFallback,
    /// No declaration binds the requested source identity.
    UndeclaredSourceIdentity,
    /// A configuration alias was presented as a semantic source identity.
    ConfigurationAliasAsIdentity,
    /// A required declared value is structurally invalid.
    InvalidDeclaration,
    /// A VCS, path, vendor, or mirror declaration is structurally invalid.
    InvalidAcquisitionDeclaration,
    /// A security-advisory declaration is structurally invalid.
    InvalidSecurityAdvisory,
    /// A snapshot format version is not supported by this model.
    UnsupportedSnapshotVersion,
    /// A snapshot entry is malformed, incomplete, or duplicate.
    InvalidSnapshotEntry,
    /// Snapshot issuance, expiry, or observation epochs are inconsistent.
    InconsistentSnapshotEpoch,
    /// A signing authority was compromised for the requested decision.
    CompromisedSigningAuthority,
    /// A signing authority was superseded for the requested decision.
    SupersededSigningAuthority,
    /// Key-rotation evidence is incomplete or invalid.
    InvalidRotationEvidence,
    /// The retained greatest sequence has no authenticated content digest.
    RetainedSnapshotContentMissing,
    /// More than one retained state was supplied for one source identity.
    RetainedStateAmbiguous,
    /// Retained rotation or compromise facts are incomplete.
    RetainedLifecycleFactsMissing,
    /// A request attempted to substitute code for an affected artifact.
    ArtifactSubstitutionRefused,
    /// A refusal has no declaration attribution.
    FailureAttributionMissing,
}

impl TrustFailureReason {
    /// Every member of the closed vocabulary, in specification order.
    pub const ALL: [Self; 41] = [
        Self::AbsentTrustRoot,
        Self::UnauthorizedSigningAuthority,
        Self::InsufficientDelegationScope,
        Self::IncompleteDelegationChain,
        Self::DelegationNotCurrentlyValid,
        Self::ExpiredMetadataSnapshot,
        Self::MissingObservedInstant,
        Self::StaleSnapshot,
        Self::RolledBackSequence,
        Self::EquivocatedSequence,
        Self::DetectedFreeze,
        Self::NoncanonicalPublicationName,
        Self::MalformedPublicationName,
        Self::CanonicalNameCollision,
        Self::PublicationImmutabilityViolation,
        Self::YankedRelease,
        Self::RevokedArtifact,
        Self::UnverifiedSourceRevision,
        Self::UnverifiedSourceTreeIdentity,
        Self::UnverifiableLockfileRecord,
        Self::InvalidLockfileRecord,
        Self::UnavailablePinnedSnapshot,
        Self::UndeclaredTrustDisjunction,
        Self::MalformedSourceIdentity,
        Self::SourceKindFallback,
        Self::UndeclaredSourceIdentity,
        Self::ConfigurationAliasAsIdentity,
        Self::InvalidDeclaration,
        Self::InvalidAcquisitionDeclaration,
        Self::InvalidSecurityAdvisory,
        Self::UnsupportedSnapshotVersion,
        Self::InvalidSnapshotEntry,
        Self::InconsistentSnapshotEpoch,
        Self::CompromisedSigningAuthority,
        Self::SupersededSigningAuthority,
        Self::InvalidRotationEvidence,
        Self::RetainedSnapshotContentMissing,
        Self::RetainedStateAmbiguous,
        Self::RetainedLifecycleFactsMissing,
        Self::ArtifactSubstitutionRefused,
        Self::FailureAttributionMissing,
    ];

    /// Returns the exact Section 27 anchor that owns this reason.
    #[must_use]
    pub const fn anchor(self) -> &'static str {
        match self {
            Self::AbsentTrustRoot
            | Self::UnauthorizedSigningAuthority
            | Self::InsufficientDelegationScope
            | Self::IncompleteDelegationChain
            | Self::DelegationNotCurrentlyValid
            | Self::UndeclaredTrustDisjunction => TRUST_CLAUSE,
            Self::ExpiredMetadataSnapshot
            | Self::MissingObservedInstant
            | Self::StaleSnapshot
            | Self::UnavailablePinnedSnapshot => FRESHNESS_CLAUSE,
            Self::RolledBackSequence | Self::EquivocatedSequence | Self::DetectedFreeze => {
                ROLLBACK_CLAUSE
            }
            Self::NoncanonicalPublicationName
            | Self::MalformedPublicationName
            | Self::CanonicalNameCollision => NAME_CLAUSE,
            Self::PublicationImmutabilityViolation => PUBLICATION_CLAUSE,
            Self::YankedRelease => YANK_CLAUSE,
            Self::RevokedArtifact => REVOCATION_CLAUSE,
            Self::UnverifiedSourceRevision | Self::UnverifiedSourceTreeIdentity => {
                ACQUISITION_CLAUSE
            }
            Self::UnverifiableLockfileRecord | Self::InvalidLockfileRecord => LOCKFILE_CLAUSE,
            Self::MalformedSourceIdentity
            | Self::SourceKindFallback
            | Self::UndeclaredSourceIdentity
            | Self::ConfigurationAliasAsIdentity => SOURCE_IDENTITY_CLAUSE,
            Self::InvalidDeclaration => SECTION_CLAUSE,
            Self::InvalidAcquisitionDeclaration => ACQUISITION_CLAUSE,
            Self::InvalidSecurityAdvisory => REVOCATION_CLAUSE,
            Self::UnsupportedSnapshotVersion | Self::InvalidSnapshotEntry => SNAPSHOT_CLAUSE,
            Self::InconsistentSnapshotEpoch => FRESHNESS_CLAUSE,
            Self::CompromisedSigningAuthority
            | Self::SupersededSigningAuthority
            | Self::InvalidRotationEvidence => KEY_CLAUSE,
            Self::RetainedSnapshotContentMissing
            | Self::RetainedStateAmbiguous
            | Self::RetainedLifecycleFactsMissing => ROLLBACK_CLAUSE,
            Self::ArtifactSubstitutionRefused => REVOCATION_CLAUSE,
            Self::FailureAttributionMissing => ATTRIBUTION_CLAUSE,
        }
    }

    /// Classifies one structured registry refusal under the closed Section 27 vocabulary.
    #[must_use]
    pub const fn for_error(error: &RegistryError) -> Self {
        match error {
            RegistryError::NameNoncanonical { .. } => Self::NoncanonicalPublicationName,
            RegistryError::NameMalformed { .. } => Self::MalformedPublicationName,
            RegistryError::NameCollision { .. } | RegistryError::ExternalAliasCollision { .. } => {
                Self::CanonicalNameCollision
            }
            RegistryError::SignatureUnverified { .. }
            | RegistryError::PublisherUnauthorized { .. } => Self::UnauthorizedSigningAuthority,
            RegistryError::DelegationOutOfScope { .. } => Self::InsufficientDelegationScope,
            RegistryError::DelegationChainIncomplete { .. } => Self::IncompleteDelegationChain,
            RegistryError::DelegationNotCurrentlyValid { .. } => Self::DelegationNotCurrentlyValid,
            RegistryError::TrustRootAbsent { .. } => Self::AbsentTrustRoot,
            RegistryError::TrustDecisionDisjunction { .. } => Self::UndeclaredTrustDisjunction,
            RegistryError::SnapshotExpired { .. } => Self::ExpiredMetadataSnapshot,
            RegistryError::ObservedInstantMissing { .. } => Self::MissingObservedInstant,
            RegistryError::PinnedSnapshotStale { .. } => Self::StaleSnapshot,
            RegistryError::PinnedSnapshotUnavailable { .. } => Self::UnavailablePinnedSnapshot,
            RegistryError::Rollback { .. } => Self::RolledBackSequence,
            RegistryError::FreezeEquivocation { .. } => Self::EquivocatedSequence,
            RegistryError::FreezeDetected { .. } => Self::DetectedFreeze,
            RegistryError::PublicationImmutable { .. } => Self::PublicationImmutabilityViolation,
            RegistryError::ReleaseYanked { .. } | RegistryError::LockfileRewriteRefused { .. } => {
                Self::YankedRelease
            }
            RegistryError::AdvisoryRefusesBuild { .. } => Self::RevokedArtifact,
            RegistryError::LockfileEvidenceStale { .. }
            | RegistryError::LockfileEvidenceUnbound { .. } => Self::UnverifiableLockfileRecord,
            RegistryError::LockfileDeclarationInvalid { .. } => Self::InvalidLockfileRecord,
            RegistryError::PinMismatch {
                defect: PinDefect::Commit,
                ..
            }
            | RegistryError::VcsPinIdentityMismatch { .. } => Self::UnverifiedSourceRevision,
            RegistryError::PinMismatch { .. }
            | RegistryError::ContentMismatch { .. }
            | RegistryError::ModifiedPath { .. }
            | RegistryError::VendorMismatch { .. }
            | RegistryError::MirrorIdentityMismatch { .. } => Self::UnverifiedSourceTreeIdentity,
            RegistryError::SourceIdentityMalformed { .. } => Self::MalformedSourceIdentity,
            RegistryError::SourceKindFallback { .. } => Self::SourceKindFallback,
            RegistryError::SourceNotDeclared { .. } => Self::UndeclaredSourceIdentity,
            RegistryError::ConfigAliasNotIdentity { .. } => Self::ConfigurationAliasAsIdentity,
            RegistryError::DeclarationInvalid { .. } => Self::InvalidDeclaration,
            RegistryError::AcquisitionDeclarationInvalid { .. } => {
                Self::InvalidAcquisitionDeclaration
            }
            RegistryError::AdvisoryDeclarationInvalid { .. } => Self::InvalidSecurityAdvisory,
            RegistryError::SnapshotVersionUnsupported { .. } => Self::UnsupportedSnapshotVersion,
            RegistryError::SnapshotEntryInvalid { .. } => Self::InvalidSnapshotEntry,
            RegistryError::SnapshotEpochInconsistent { .. } => Self::InconsistentSnapshotEpoch,
            RegistryError::KeyCompromised { .. } => Self::CompromisedSigningAuthority,
            RegistryError::KeySuperseded { .. } => Self::SupersededSigningAuthority,
            RegistryError::RotationEvidenceInvalid { .. } => Self::InvalidRotationEvidence,
            RegistryError::RetainedContentMissing { .. } => Self::RetainedSnapshotContentMissing,
            RegistryError::RetainedStateAmbiguous { .. } => Self::RetainedStateAmbiguous,
            RegistryError::RetainedLifecycleFactsMissing { .. } => {
                Self::RetainedLifecycleFactsMissing
            }
            RegistryError::AdvisorySubstitutionRefused { .. } => Self::ArtifactSubstitutionRefused,
            RegistryError::AttributionMissing { .. } => Self::FailureAttributionMissing,
        }
    }
}

/// One frozen published diagnostic identity of this model.
///
/// The codes are frozen: a consumer matches on [`Self::as_str`], and the meanings are
/// the ones registered for the registry category. The variant order is the sorted code
/// order, so [`Self::ALL`] is already in the order the registry requires.
///
/// A condition this module can decide but that has no published code is a typed
/// [`RegistryError`] variant whose [`RegistryError::code`] is `None`; such a condition
/// MUST NOT be reported under another condition's code.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RegistryDiagnosticCode {
    /// `registry-advisory-refuses-build`
    AdvisoryRefusesBuild,
    /// `registry-advisory-substitution-refused`
    AdvisorySubstitutionRefused,
    /// `registry-attribution-missing`
    AttributionMissing,
    /// `registry-config-alias-not-identity`
    ConfigAliasNotIdentity,
    /// `registry-content-mismatch`
    ContentMismatch,
    /// `registry-delegation-out-of-scope`
    DelegationOutOfScope,
    /// `registry-external-alias-collision`
    ExternalAliasCollision,
    /// `registry-freeze-detected`
    FreezeDetected,
    /// `registry-freeze-equivocation`
    FreezeEquivocation,
    /// `registry-key-compromised`
    KeyCompromised,
    /// `registry-key-superseded`
    KeySuperseded,
    /// `registry-lockfile-evidence-stale`
    LockfileEvidenceStale,
    /// `registry-lockfile-evidence-unbound`
    LockfileEvidenceUnbound,
    /// `registry-lockfile-rewrite-refused`
    LockfileRewriteRefused,
    /// `registry-mirror-identity-mismatch`
    MirrorIdentityMismatch,
    /// `registry-modified-path`
    ModifiedPath,
    /// `registry-name-collision`
    NameCollision,
    /// `registry-name-noncanonical`
    NameNoncanonical,
    /// `registry-pinned-snapshot-stale`
    PinnedSnapshotStale,
    /// `registry-publication-immutable`
    PublicationImmutable,
    /// `registry-publisher-unauthorized`
    PublisherUnauthorized,
    /// `registry-release-yanked`
    ReleaseYanked,
    /// `registry-rollback`
    Rollback,
    /// `registry-rotation-evidence-invalid`
    RotationEvidenceInvalid,
    /// `registry-signature-unverified`
    SignatureUnverified,
    /// `registry-snapshot-entry-invalid`
    SnapshotEntryInvalid,
    /// `registry-snapshot-epoch-inconsistent`
    SnapshotEpochInconsistent,
    /// `registry-snapshot-expired`
    SnapshotExpired,
    /// `registry-snapshot-version-unsupported`
    SnapshotVersionUnsupported,
    /// `registry-source-kind-fallback`
    SourceKindFallback,
    /// `registry-source-not-declared`
    SourceNotDeclared,
    /// `registry-vcs-pin-mismatch`
    VcsPinMismatch,
    /// `registry-vendor-mismatch`
    VendorMismatch,
}

impl RegistryDiagnosticCode {
    /// Every published code, in sorted code order.
    pub const ALL: [Self; 33] = [
        Self::AdvisoryRefusesBuild,
        Self::AdvisorySubstitutionRefused,
        Self::AttributionMissing,
        Self::ConfigAliasNotIdentity,
        Self::ContentMismatch,
        Self::DelegationOutOfScope,
        Self::ExternalAliasCollision,
        Self::FreezeDetected,
        Self::FreezeEquivocation,
        Self::KeyCompromised,
        Self::KeySuperseded,
        Self::LockfileEvidenceStale,
        Self::LockfileEvidenceUnbound,
        Self::LockfileRewriteRefused,
        Self::MirrorIdentityMismatch,
        Self::ModifiedPath,
        Self::NameCollision,
        Self::NameNoncanonical,
        Self::PinnedSnapshotStale,
        Self::PublicationImmutable,
        Self::PublisherUnauthorized,
        Self::ReleaseYanked,
        Self::Rollback,
        Self::RotationEvidenceInvalid,
        Self::SignatureUnverified,
        Self::SnapshotEntryInvalid,
        Self::SnapshotEpochInconsistent,
        Self::SnapshotExpired,
        Self::SnapshotVersionUnsupported,
        Self::SourceKindFallback,
        Self::SourceNotDeclared,
        Self::VcsPinMismatch,
        Self::VendorMismatch,
    ];

    /// Returns the exact frozen code spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AdvisoryRefusesBuild => "registry-advisory-refuses-build",
            Self::AdvisorySubstitutionRefused => "registry-advisory-substitution-refused",
            Self::AttributionMissing => "registry-attribution-missing",
            Self::ConfigAliasNotIdentity => "registry-config-alias-not-identity",
            Self::ContentMismatch => "registry-content-mismatch",
            Self::DelegationOutOfScope => "registry-delegation-out-of-scope",
            Self::ExternalAliasCollision => "registry-external-alias-collision",
            Self::FreezeDetected => "registry-freeze-detected",
            Self::FreezeEquivocation => "registry-freeze-equivocation",
            Self::KeyCompromised => "registry-key-compromised",
            Self::KeySuperseded => "registry-key-superseded",
            Self::LockfileEvidenceStale => "registry-lockfile-evidence-stale",
            Self::LockfileEvidenceUnbound => "registry-lockfile-evidence-unbound",
            Self::LockfileRewriteRefused => "registry-lockfile-rewrite-refused",
            Self::MirrorIdentityMismatch => "registry-mirror-identity-mismatch",
            Self::ModifiedPath => "registry-modified-path",
            Self::NameCollision => "registry-name-collision",
            Self::NameNoncanonical => "registry-name-noncanonical",
            Self::PinnedSnapshotStale => "registry-pinned-snapshot-stale",
            Self::PublicationImmutable => "registry-publication-immutable",
            Self::PublisherUnauthorized => "registry-publisher-unauthorized",
            Self::ReleaseYanked => "registry-release-yanked",
            Self::Rollback => "registry-rollback",
            Self::RotationEvidenceInvalid => "registry-rotation-evidence-invalid",
            Self::SignatureUnverified => "registry-signature-unverified",
            Self::SnapshotEntryInvalid => "registry-snapshot-entry-invalid",
            Self::SnapshotEpochInconsistent => "registry-snapshot-epoch-inconsistent",
            Self::SnapshotExpired => "registry-snapshot-expired",
            Self::SnapshotVersionUnsupported => "registry-snapshot-version-unsupported",
            Self::SourceKindFallback => "registry-source-kind-fallback",
            Self::SourceNotDeclared => "registry-source-not-declared",
            Self::VcsPinMismatch => "registry-vcs-pin-mismatch",
            Self::VendorMismatch => "registry-vendor-mismatch",
        }
    }

    /// Returns the clause that owns this code.
    #[must_use]
    pub const fn clause(self) -> &'static str {
        match self {
            Self::AdvisoryRefusesBuild | Self::AdvisorySubstitutionRefused => REVOCATION_CLAUSE,
            Self::AttributionMissing => ATTRIBUTION_CLAUSE,
            Self::ConfigAliasNotIdentity | Self::SourceKindFallback | Self::SourceNotDeclared => {
                SOURCE_IDENTITY_CLAUSE
            }
            Self::ContentMismatch
            | Self::MirrorIdentityMismatch
            | Self::ModifiedPath
            | Self::VcsPinMismatch
            | Self::VendorMismatch => ACQUISITION_CLAUSE,
            Self::DelegationOutOfScope
            | Self::PublisherUnauthorized
            | Self::SignatureUnverified => TRUST_CLAUSE,
            Self::ExternalAliasCollision | Self::NameCollision | Self::NameNoncanonical => {
                NAME_CLAUSE
            }
            Self::FreezeDetected | Self::FreezeEquivocation | Self::Rollback => ROLLBACK_CLAUSE,
            Self::KeyCompromised | Self::KeySuperseded | Self::RotationEvidenceInvalid => {
                KEY_CLAUSE
            }
            Self::LockfileEvidenceStale | Self::LockfileEvidenceUnbound => LOCKFILE_CLAUSE,
            Self::LockfileRewriteRefused | Self::ReleaseYanked => YANK_CLAUSE,
            Self::PinnedSnapshotStale | Self::SnapshotEpochInconsistent | Self::SnapshotExpired => {
                FRESHNESS_CLAUSE
            }
            Self::PublicationImmutable => PUBLICATION_CLAUSE,
            Self::SnapshotEntryInvalid | Self::SnapshotVersionUnsupported => SNAPSHOT_CLAUSE,
        }
    }

    /// Returns the frozen meaning registered for this code.
    #[must_use]
    pub const fn meaning(self) -> &'static str {
        match self {
            Self::AdvisoryRefusesBuild => {
                "An authenticated advisory covers the requested artifact, so the build or run is refused."
            }
            Self::AdvisorySubstitutionRefused => {
                "A request asked a revocation to substitute code, which no advisory may do."
            }
            Self::AttributionMissing => {
                "A snapshot entry has no bound declaration, so the refusal cannot be attributed to a declaration."
            }
            Self::ConfigAliasNotIdentity => {
                "A configuration alias was asked to stand as a semantic source identity."
            }
            Self::ContentMismatch => {
                "A pinned tree's content digest differs from the digest its pin authenticates."
            }
            Self::DelegationOutOfScope => {
                "A delegation or entry lies outside the authority that would have to contain it."
            }
            Self::ExternalAliasCollision => {
                "Two external names share one alias skeleton, so neither can be mapped collision-free."
            }
            Self::FreezeDetected => {
                "The greatest admitted snapshot exceeded its declared maximum staleness."
            }
            Self::FreezeEquivocation => {
                "One sequence number names two different snapshot contents."
            }
            Self::KeyCompromised => {
                "A compromised key signed metadata at or after its declared compromise."
            }
            Self::KeySuperseded => {
                "A key superseded by a rotation signed metadata after the rotation took effect."
            }
            Self::LockfileEvidenceStale => {
                "A lockfile record's evidence is tampered, stale, or bound to another source, snapshot, or release."
            }
            Self::LockfileEvidenceUnbound => {
                "A dependency declaration has no lockfile evidence, so its source is not parsed."
            }
            Self::LockfileRewriteRefused => {
                "A rewrite would silently drop a locked release that a yank removed from ordinary resolution."
            }
            Self::MirrorIdentityMismatch => {
                "A mirror presents a different authenticated snapshot identity or source identity."
            }
            Self::ModifiedPath => {
                "A pinned tree carries a modified path, so it is not the authenticated content."
            }
            Self::NameCollision => {
                "Two admitted and distinct name spellings collide in one name kind."
            }
            Self::NameNoncanonical => "A publication name is not in canonical normalization form.",
            Self::PinnedSnapshotStale => {
                "An offline pinned snapshot is observed beyond the declared bound of its pin."
            }
            Self::PublicationImmutable => {
                "An authenticated publication tuple names different bytes than the recorded publication."
            }
            Self::PublisherUnauthorized => {
                "An entry's publisher or signer holds no declared authority for its coordinates."
            }
            Self::ReleaseYanked => "A yanked release is refused for ordinary new resolution.",
            Self::Rollback => "A snapshot is older than the retained minimum trusted sequence.",
            Self::RotationEvidenceInvalid => {
                "Rotation evidence is not valid under both the retired key and the new key."
            }
            Self::SignatureUnverified => {
                "No declared signature verifies under the material of its declared key."
            }
            Self::SnapshotEntryInvalid => {
                "A snapshot entry is malformed, omitted, or declared twice."
            }
            Self::SnapshotEpochInconsistent => {
                "A snapshot's declared epochs do not order its issuance before its expiry or observation."
            }
            Self::SnapshotExpired => {
                "An online freshness observation is past the declared expiry of the snapshot."
            }
            Self::SnapshotVersionUnsupported => {
                "A metadata snapshot carries a format version this model does not define."
            }
            Self::SourceKindFallback => {
                "A resolution request would fall back to another source kind for the same identity text."
            }
            Self::SourceNotDeclared => "No declaration binds the requested source identity.",
            Self::VcsPinMismatch => {
                "A checkout's source identity or pinned commit differs from the pin."
            }
            Self::VendorMismatch => {
                "A vendored directory presents a different snapshot identity, entry, or artifact than the authenticated one."
            }
        }
    }
}

/// One defect of a malformed name spelling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NameDefect {
    /// The spelling is empty.
    Empty,
    /// The spelling exceeds [`REGISTRY_NAME_SCALAR_LIMIT`] scalars.
    TooLong,
    /// The spelling carries a scalar its name kind does not admit.
    IllegalCharacter,
    /// A dotted spelling carries an empty segment.
    EmptySegment,
}

/// One defect of an unverified signature or an unauthorized publisher.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationDefect {
    /// No root or delegation names the entry's publisher identity at all.
    UnknownPublisher,
    /// The publisher's key produced no verifying signature over the snapshot.
    UnverifiedSigner,
}

/// One defect of rotation evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RotationDefect {
    /// The retired key's material is unknown to the store.
    OldKeyUnknown,
    /// The new key's material was not supplied.
    NewKeyUnknown,
    /// Declared successor material conflicts with the store's canonical material.
    SuccessorMaterialConflict,
    /// The retired key's signature does not verify over the rotation payload.
    OldKeyUnverified,
    /// The new key's signature does not verify over the rotation payload.
    NewKeyUnverified,
    /// Another overlapping rotation already names a different successor authority.
    ConflictingSuccessor,
    /// The rotation is not later than an already admitted rotation from the same authority.
    Backdated,
    /// The signed source, scope, declarer, or timing evidence does not match the rotation.
    ContextMismatch,
}

/// One defect of a lockfile record's evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceDefect {
    /// The record binds another source identity than its declaration.
    ChangedSource,
    /// The record's declared evidence digest differs from its recomputed evidence.
    TamperedEvidence,
    /// The record binds another snapshot identity than the verified snapshot.
    ChangedSnapshot,
    /// The verified snapshot does not record the release the record names.
    UnrecordedRelease,
    /// The lockfile carries a record that no declared dependency owns.
    ExtraRecord,
    /// A locked dependency has no target-qualified record in the lockfile closure.
    MissingDependency,
    /// A complete delivered release coordinate differs from the locked evidence.
    ChangedDelivery,
}

/// One defect of a pinned acquisition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PinDefect {
    /// The checkout's source identity differs from the pin's.
    SourceIdentity,
    /// The checkout's commit differs from the pin's commit.
    Commit,
}

/// One defect of a vendored directory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VendorDefect {
    /// The directory binds another source identity than the declaration.
    SourceIdentity,
    /// The directory presents another authenticated snapshot identity.
    SnapshotIdentity,
    /// The authenticated snapshot does not record the vendored release.
    UnknownEntry,
    /// The vendored release carries another artifact digest than the snapshot records.
    ChangedArtifact,
    /// The vendored release carries another manifest digest than the snapshot records.
    ChangedManifest,
    /// The vendored release carries another source-content digest than the snapshot records.
    ChangedSourceContent,
    /// The vendored release carries another generated-output digest than the snapshot records.
    ChangedGenerated,
    /// The vendored release carries another public-interface digest than the snapshot records.
    ChangedInterface,
    /// The vendored release carries another target-qualified artifact set than the snapshot.
    ChangedTargetArtifacts,
}

/// One defect of a mirror binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MirrorDefect {
    /// The mirror presents another source identity than the declaration.
    SourceIdentity,
    /// The mirror presents another authenticated snapshot identity.
    SnapshotIdentity,
}

/// One defect of a recorded publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationDefect {
    /// The ledger records no publication of the tuple at all.
    Unrecorded,
    /// The tuple names different manifest bytes.
    ChangedManifest,
    /// The tuple names different complete source-content bytes.
    ChangedSourceContent,
    /// The tuple names different generated-output bytes.
    ChangedGenerated,
    /// The tuple names different public-interface bytes.
    ChangedInterface,
    /// The tuple names different artifact bytes.
    ChangedArtifact,
    /// The tuple names a different target-qualified artifact set.
    ChangedTargetArtifacts,
    /// The tuple names different source identity than the recorded publication.
    ChangedSource,
}

/// One typed condition this model decides.
///
/// A condition with a published code reports it through [`Self::code`]; the conditions
/// whose `code` is `None` are structural declaration defects that MUST NOT be reported
/// under another condition's code. Every condition still names its owning clause through
/// [`Self::clause`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegistryError {
    /// A canonical source-identity text is empty, noncanonical, or carries a control scalar.
    SourceIdentityMalformed {
        /// The declared source kind.
        kind: SourceKind,
        /// The rejected identity text.
        text: Arc<str>,
    },
    /// A resolution request would fall back to another source kind.
    SourceKindFallback {
        /// The kind the declaration binds.
        declared: SourceKind,
        /// The kind the request asked for.
        requested: SourceKind,
        /// The identity text that both kinds name.
        text: Arc<str>,
    },
    /// No declaration binds the requested source identity.
    SourceNotDeclared {
        /// The requested identity.
        requested: SourceIdentity,
    },
    /// A configuration alias was asked to stand as a semantic identity.
    ConfigAliasNotIdentity {
        /// The alias spelling.
        alias: Arc<str>,
    },
    /// A lockfile declaration or historical-evidence record is structurally invalid.
    LockfileDeclarationInvalid {
        /// The named lockfile field.
        field: &'static str,
        /// The rejected value.
        value: Arc<str>,
    },
    /// A VCS, path, vendor, or mirror declaration is structurally invalid.
    AcquisitionDeclarationInvalid {
        /// The named acquisition field.
        field: &'static str,
        /// The rejected value.
        value: Arc<str>,
    },
    /// A security-advisory declaration is structurally invalid.
    AdvisoryDeclarationInvalid {
        /// The named advisory field.
        field: &'static str,
        /// The rejected value.
        value: Arc<str>,
    },
    /// A structural declaration is malformed outside a specific clause's vocabulary.
    DeclarationInvalid {
        /// The named field.
        field: &'static str,
        /// The rejected value.
        value: Arc<str>,
    },
    /// A publication name is not in canonical normalization form.
    NameNoncanonical {
        /// The name kind.
        kind: RegistryNameKind,
        /// The rejected spelling.
        spelling: Arc<str>,
        /// The canonical spelling that was required.
        canonical: Arc<str>,
    },
    /// A name spelling is malformed for its kind.
    NameMalformed {
        /// The name kind.
        kind: RegistryNameKind,
        /// The rejected spelling.
        spelling: Arc<str>,
        /// The defect.
        defect: NameDefect,
    },
    /// Two admitted names collide in one name kind.
    NameCollision {
        /// The name kind.
        kind: RegistryNameKind,
        /// One name of the colliding pair, in canonical order.
        first: Arc<str>,
        /// The other name of the pair, never smaller than `first`.
        second: Arc<str>,
        /// The collision relation.
        condition: NameCollisionKind,
    },
    /// Two external names share one alias skeleton.
    ExternalAliasCollision {
        /// The alias spelling that is already occupied.
        alias: Arc<str>,
        /// The external name that could not be mapped.
        conflicting: Arc<str>,
    },
    /// A snapshot carries an unsupported format version.
    SnapshotVersionUnsupported {
        /// The unsupported version.
        version: ProtocolVersion,
    },
    /// A snapshot entry is malformed, omitted, or declared twice.
    SnapshotEntryInvalid {
        /// The named field.
        field: &'static str,
        /// The rejected value.
        value: Arc<str>,
    },
    /// A snapshot's declared epochs are inconsistent.
    SnapshotEpochInconsistent {
        /// The declared issuance epoch.
        issue_epoch: u64,
        /// The observed or declared expiry epoch that disagrees.
        observed_epoch: u64,
    },
    /// An online freshness observation is past the declared expiry.
    SnapshotExpired {
        /// The snapshot sequence.
        sequence: u64,
        /// The declared expiry epoch.
        expiry_epoch: u64,
        /// The observed epoch.
        observed_epoch: u64,
    },
    /// Freshness verification was requested without an explicit declared observation epoch.
    ObservedInstantMissing {
        /// The snapshot sequence whose freshness could not be observed.
        sequence: u64,
    },
    /// An offline pin is observed beyond its declared bound.
    PinnedSnapshotStale {
        /// The epoch the pin was taken at.
        pinned_epoch: u64,
        /// The declared bound of the pin.
        expires_at: u64,
        /// The observed epoch.
        observed_epoch: u64,
    },
    /// An offline check did not present the already verified witness for this snapshot.
    PinnedSnapshotUnavailable {
        /// The source whose prior verified snapshot was required.
        source: SourceIdentity,
        /// The snapshot that needed an offline witness.
        snapshot: SnapshotIdentity,
    },
    /// No declared signature verifies under the material of its declared key.
    SignatureUnverified {
        /// The key whose signature could not be verified.
        key: KeyId,
    },
    /// An entry's publisher or signer holds no declared authority.
    PublisherUnauthorized {
        /// The publisher name.
        publisher: Arc<str>,
        /// The publisher key.
        key: KeyId,
        /// The defect.
        defect: AuthorizationDefect,
    },
    /// A delegation or entry lies outside the authority that would contain it.
    DelegationOutOfScope {
        /// The key whose authority is at issue.
        key: KeyId,
        /// The widest authority that was found, when any was found at all.
        authority: Option<AuthorityScope>,
        /// The scope that is not contained.
        declared: AuthorityScope,
    },
    /// Presented delegation evidence cannot reach its declarer from a declared root.
    DelegationChainIncomplete {
        /// The unattested delegator key.
        key: KeyId,
    },
    /// A matching delegation is outside its declared epoch or sequence validity window.
    DelegationNotCurrentlyValid {
        /// The delegate key whose timing window excluded the decision.
        key: KeyId,
        /// The requested snapshot sequence.
        sequence: u64,
        /// The declared observation epoch.
        epoch: u64,
    },
    /// A compromised key signed metadata at or after its declared compromise.
    KeyCompromised {
        /// The compromised key.
        key: KeyId,
        /// The sequence at which the compromise takes effect.
        sequence: u64,
    },
    /// A superseded key signed metadata after the rotation took effect.
    KeySuperseded {
        /// The retired key.
        key: KeyId,
        /// The sequence at which the rotation takes effect.
        sequence: u64,
    },
    /// Rotation evidence is not valid under both keys.
    RotationEvidenceInvalid {
        /// The retired key.
        old_key: KeyId,
        /// The new key.
        new_key: KeyId,
        /// The defect.
        defect: RotationDefect,
    },
    /// A snapshot is older than the retained minimum trusted sequence.
    Rollback {
        /// The declared sequence of the refused snapshot.
        declared: u64,
        /// The retained minimum trusted sequence.
        retained_minimum: u64,
    },
    /// The retained greatest sequence omitted the digest that authenticates it.
    RetainedContentMissing {
        /// The retained greatest sequence whose digest was absent.
        sequence: u64,
    },
    /// More than one retained state was supplied for one source identity.
    RetainedStateAmbiguous {
        /// The source identity whose state was duplicated.
        source: SourceIdentity,
        /// The number of supplied states for that source.
        supplied: usize,
    },
    /// Retained source state omitted authenticated rotation or compromise evidence.
    RetainedLifecycleFactsMissing {
        /// The source whose retained lifecycle facts are incomplete.
        source: SourceIdentity,
    },
    /// One sequence number names two different snapshot contents.
    FreezeEquivocation {
        /// The equivocated sequence.
        sequence: u64,
        /// The retained content digest of that sequence.
        retained: [u8; 32],
        /// The observed content digest of that sequence.
        observed: [u8; 32],
    },
    /// The greatest admitted snapshot has exceeded its declared staleness bound.
    FreezeDetected {
        /// The last admitted snapshot sequence.
        sequence: u64,
        /// The declared maximum permitted age.
        maximum_staleness: u64,
        /// The explicit epoch at which the freeze was detected.
        observed_epoch: u64,
    },
    /// An authenticated publication tuple names different bytes.
    PublicationImmutable {
        /// The published namespace.
        namespace: RegistryName,
        /// The published package.
        package: RegistryName,
        /// The published version.
        version: PackageVersion,
        /// The defect.
        defect: PublicationDefect,
        /// The recorded digest that disagrees.
        recorded: [u8; 32],
        /// The observed digest that disagrees.
        observed: [u8; 32],
    },
    /// A yanked release is refused for ordinary new resolution.
    ReleaseYanked {
        /// The authenticated source identity that owns the release.
        source: SourceIdentity,
        /// The package name.
        package: Arc<str>,
        /// The yanked version.
        version: Arc<str>,
        /// The greatest authenticated snapshot sequence that declared the yank.
        sequence: u64,
    },
    /// A rewrite would silently drop a locked yanked release.
    LockfileRewriteRefused {
        /// The release the rewrite would drop.
        release: Arc<str>,
    },
    /// An authenticated advisory covers the requested artifact.
    AdvisoryRefusesBuild {
        /// The advisory identity.
        advisory: Arc<str>,
        /// The advisory severity.
        severity: Severity,
    },
    /// A request asked a revocation to substitute code.
    AdvisorySubstitutionRefused {
        /// The substitute that was requested.
        requested: Arc<str>,
    },
    /// A checkout's source identity or pinned commit differs from the pin.
    PinMismatch {
        /// The pinned value.
        expected: Arc<str>,
        /// The observed value.
        observed: Arc<str>,
        /// The defect.
        defect: PinDefect,
    },
    /// A VCS pin names a commit other than the one encoded by its source identity.
    VcsPinIdentityMismatch {
        /// The commit encoded by the VCS source identity.
        expected: Arc<str>,
        /// The distinct commit the pin declared.
        observed: Arc<str>,
    },
    /// A pinned tree's content digest differs from the digest its pin authenticates.
    ContentMismatch {
        /// The pinned content digest.
        expected: [u8; 32],
        /// The observed content digest.
        observed: [u8; 32],
    },
    /// A pinned tree carries a modified path.
    ModifiedPath {
        /// The first modified path in canonical order.
        path: Arc<str>,
    },
    /// A vendored directory presents another snapshot identity, entry, or artifact.
    VendorMismatch {
        /// The expected value.
        expected: Arc<str>,
        /// The observed value.
        observed: Arc<str>,
        /// The defect.
        defect: VendorDefect,
    },
    /// A mirror presents a different identity.
    MirrorIdentityMismatch {
        /// The mirror spelling.
        mirror: Arc<str>,
        /// The expected identity digest.
        expected: Arc<str>,
        /// The observed identity digest.
        observed: Arc<str>,
        /// The defect.
        defect: MirrorDefect,
    },
    /// A lockfile record's evidence is stale or tampered.
    LockfileEvidenceStale {
        /// The record index in canonical record order.
        record: usize,
        /// The defect.
        defect: EvidenceDefect,
        /// The expected digest.
        expected: [u8; 32],
        /// The observed digest.
        observed: [u8; 32],
    },
    /// A dependency declaration has no lockfile evidence.
    LockfileEvidenceUnbound {
        /// The unbound declaration index.
        declaration: usize,
    },
    /// A snapshot entry has no bound declaration.
    AttributionMissing {
        /// The number of declarations supplied.
        declared: usize,
        /// The number of entries that were attributed before the refusal.
        attributed: usize,
    },
    /// No declared trust root governs the snapshot's authenticated source.
    TrustRootAbsent {
        /// The source for which no root was declared.
        source: SourceIdentity,
    },
    /// Several roots would be combined without an explicit source-scoped policy.
    TrustDecisionDisjunction {
        /// The source whose roots require an explicit selection policy.
        source: SourceIdentity,
    },
}

impl RegistryError {
    /// Returns the frozen published diagnostic identity of this condition.
    ///
    /// `None` means the condition has no published code and MUST NOT be reported under
    /// another condition's code.
    #[must_use]
    pub fn code(&self) -> Option<RegistryDiagnosticCode> {
        match self {
            Self::SourceKindFallback { .. } => Some(RegistryDiagnosticCode::SourceKindFallback),
            Self::SourceNotDeclared { .. } => Some(RegistryDiagnosticCode::SourceNotDeclared),
            Self::ConfigAliasNotIdentity { .. } => {
                Some(RegistryDiagnosticCode::ConfigAliasNotIdentity)
            }
            Self::NameNoncanonical { .. } => Some(RegistryDiagnosticCode::NameNoncanonical),
            Self::NameCollision { .. } => Some(RegistryDiagnosticCode::NameCollision),
            Self::ExternalAliasCollision { .. } => {
                Some(RegistryDiagnosticCode::ExternalAliasCollision)
            }
            Self::SnapshotVersionUnsupported { .. } => {
                Some(RegistryDiagnosticCode::SnapshotVersionUnsupported)
            }
            Self::SnapshotEntryInvalid { .. } => Some(RegistryDiagnosticCode::SnapshotEntryInvalid),
            Self::SnapshotEpochInconsistent { .. } => {
                Some(RegistryDiagnosticCode::SnapshotEpochInconsistent)
            }
            Self::SnapshotExpired { .. } => Some(RegistryDiagnosticCode::SnapshotExpired),
            Self::PinnedSnapshotStale { .. } => Some(RegistryDiagnosticCode::PinnedSnapshotStale),
            Self::SignatureUnverified { .. } => Some(RegistryDiagnosticCode::SignatureUnverified),
            Self::PublisherUnauthorized { .. } => {
                Some(RegistryDiagnosticCode::PublisherUnauthorized)
            }
            Self::DelegationOutOfScope { .. } => Some(RegistryDiagnosticCode::DelegationOutOfScope),
            Self::KeyCompromised { .. } => Some(RegistryDiagnosticCode::KeyCompromised),
            Self::KeySuperseded { .. } => Some(RegistryDiagnosticCode::KeySuperseded),
            Self::RotationEvidenceInvalid { .. } => {
                Some(RegistryDiagnosticCode::RotationEvidenceInvalid)
            }
            Self::Rollback { .. } => Some(RegistryDiagnosticCode::Rollback),
            Self::FreezeEquivocation { .. } => Some(RegistryDiagnosticCode::FreezeEquivocation),
            Self::FreezeDetected { .. } => Some(RegistryDiagnosticCode::FreezeDetected),
            Self::PublicationImmutable { .. } => Some(RegistryDiagnosticCode::PublicationImmutable),
            Self::ReleaseYanked { .. } => Some(RegistryDiagnosticCode::ReleaseYanked),
            Self::LockfileRewriteRefused { .. } => {
                Some(RegistryDiagnosticCode::LockfileRewriteRefused)
            }
            Self::AdvisoryRefusesBuild { .. } => Some(RegistryDiagnosticCode::AdvisoryRefusesBuild),
            Self::AdvisorySubstitutionRefused { .. } => {
                Some(RegistryDiagnosticCode::AdvisorySubstitutionRefused)
            }
            Self::PinMismatch { .. } | Self::VcsPinIdentityMismatch { .. } => {
                Some(RegistryDiagnosticCode::VcsPinMismatch)
            }
            Self::ContentMismatch { .. } => Some(RegistryDiagnosticCode::ContentMismatch),
            Self::ModifiedPath { .. } => Some(RegistryDiagnosticCode::ModifiedPath),
            Self::VendorMismatch { .. } => Some(RegistryDiagnosticCode::VendorMismatch),
            Self::MirrorIdentityMismatch { .. } => {
                Some(RegistryDiagnosticCode::MirrorIdentityMismatch)
            }
            Self::LockfileEvidenceStale { .. } => {
                Some(RegistryDiagnosticCode::LockfileEvidenceStale)
            }
            Self::LockfileEvidenceUnbound { .. } => {
                Some(RegistryDiagnosticCode::LockfileEvidenceUnbound)
            }
            Self::AttributionMissing { .. } => Some(RegistryDiagnosticCode::AttributionMissing),
            Self::SourceIdentityMalformed { .. }
            | Self::LockfileDeclarationInvalid { .. }
            | Self::AcquisitionDeclarationInvalid { .. }
            | Self::AdvisoryDeclarationInvalid { .. }
            | Self::DeclarationInvalid { .. }
            | Self::NameMalformed { .. }
            | Self::ObservedInstantMissing { .. }
            | Self::PinnedSnapshotUnavailable { .. }
            | Self::DelegationChainIncomplete { .. }
            | Self::DelegationNotCurrentlyValid { .. }
            | Self::RetainedContentMissing { .. }
            | Self::RetainedStateAmbiguous { .. }
            | Self::RetainedLifecycleFactsMissing { .. }
            | Self::TrustRootAbsent { .. }
            | Self::TrustDecisionDisjunction { .. } => None,
        }
    }

    /// Returns the clause that owns this condition.
    #[must_use]
    pub const fn clause(&self) -> &'static str {
        match self {
            Self::SourceIdentityMalformed { .. }
            | Self::SourceKindFallback { .. }
            | Self::SourceNotDeclared { .. }
            | Self::ConfigAliasNotIdentity { .. } => SOURCE_IDENTITY_CLAUSE,
            Self::LockfileDeclarationInvalid { .. } => LOCKFILE_CLAUSE,
            Self::AcquisitionDeclarationInvalid { .. } => ACQUISITION_CLAUSE,
            Self::AdvisoryDeclarationInvalid { .. } => REVOCATION_CLAUSE,
            Self::NameNoncanonical { .. }
            | Self::NameMalformed { .. }
            | Self::NameCollision { .. }
            | Self::ExternalAliasCollision { .. } => NAME_CLAUSE,
            Self::SnapshotVersionUnsupported { .. } | Self::SnapshotEntryInvalid { .. } => {
                SNAPSHOT_CLAUSE
            }
            Self::SignatureUnverified { .. }
            | Self::PublisherUnauthorized { .. }
            | Self::DelegationOutOfScope { .. }
            | Self::DelegationChainIncomplete { .. }
            | Self::DelegationNotCurrentlyValid { .. }
            | Self::TrustRootAbsent { .. }
            | Self::TrustDecisionDisjunction { .. } => TRUST_CLAUSE,
            Self::KeyCompromised { .. }
            | Self::KeySuperseded { .. }
            | Self::RotationEvidenceInvalid { .. } => KEY_CLAUSE,
            Self::SnapshotEpochInconsistent { .. }
            | Self::SnapshotExpired { .. }
            | Self::ObservedInstantMissing { .. }
            | Self::PinnedSnapshotUnavailable { .. }
            | Self::PinnedSnapshotStale { .. } => FRESHNESS_CLAUSE,
            Self::Rollback { .. }
            | Self::RetainedContentMissing { .. }
            | Self::RetainedStateAmbiguous { .. }
            | Self::RetainedLifecycleFactsMissing { .. }
            | Self::FreezeEquivocation { .. }
            | Self::FreezeDetected { .. } => ROLLBACK_CLAUSE,
            Self::PublicationImmutable { .. } => PUBLICATION_CLAUSE,
            Self::ReleaseYanked { .. } | Self::LockfileRewriteRefused { .. } => YANK_CLAUSE,
            Self::AdvisoryRefusesBuild { .. } | Self::AdvisorySubstitutionRefused { .. } => {
                REVOCATION_CLAUSE
            }
            Self::PinMismatch { .. }
            | Self::VcsPinIdentityMismatch { .. }
            | Self::ContentMismatch { .. }
            | Self::ModifiedPath { .. }
            | Self::VendorMismatch { .. }
            | Self::MirrorIdentityMismatch { .. } => ACQUISITION_CLAUSE,
            Self::LockfileEvidenceStale { .. } | Self::LockfileEvidenceUnbound { .. } => {
                LOCKFILE_CLAUSE
            }
            Self::AttributionMissing { .. } => ATTRIBUTION_CLAUSE,
            Self::DeclarationInvalid { .. } => SECTION_CLAUSE,
        }
    }

    /// Returns the closed Section 27 failure reason of this refused condition.
    #[must_use]
    pub const fn trust_failure_reason(&self) -> TrustFailureReason {
        TrustFailureReason::for_error(self)
    }

    /// Returns the requirement anchor that owns this error's closed failure reason.
    #[must_use]
    pub const fn requirement_anchor(&self) -> &'static str {
        self.trust_failure_reason().anchor()
    }
}

/// The declaration a refusal is attributed to.
///
/// `index` is the causing declaration's index when a declaration binds it, and the
/// causing entry's index otherwise; `is_bound` reports which of the two holds. Every
/// trust and freshness refusal of this model carries one, so a refusal is never reported
/// without the identity that caused it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Attribution {
    index: usize,
    coordinate: Option<DeclarationCoordinate>,
    identity: SourceIdentity,
    bound: bool,
}

impl Attribution {
    /// Attributes one refusal to one declaration.
    #[must_use]
    pub fn declared(
        index: usize,
        coordinate: DeclarationCoordinate,
        identity: SourceIdentity,
    ) -> Self {
        Self {
            index,
            coordinate: Some(coordinate),
            identity,
            bound: true,
        }
    }

    /// Attributes one refusal to one entry that no declaration binds.
    #[must_use]
    pub fn unbound(index: usize, identity: SourceIdentity) -> Self {
        Self {
            index,
            coordinate: None,
            identity,
            bound: false,
        }
    }

    /// Returns the causing declaration or entry index.
    #[must_use]
    pub const fn index(&self) -> usize {
        self.index
    }

    /// Returns the exact declared coordinate, when a declaration supplied this attribution.
    #[must_use]
    pub const fn coordinate(&self) -> Option<&DeclarationCoordinate> {
        self.coordinate.as_ref()
    }

    /// Returns the causing source identity.
    #[must_use]
    pub const fn identity(&self) -> &SourceIdentity {
        &self.identity
    }

    /// Returns whether a declaration supplied this attribution.
    #[must_use]
    pub const fn is_bound(&self) -> bool {
        self.bound
    }
}

/// One typed refusal attributed to the declaration that caused it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistryRefusal {
    condition: RegistryError,
    attribution: Attribution,
    entry: Option<usize>,
    dependency: Option<LockedDependency>,
}

impl RegistryRefusal {
    /// Attributes one condition to one declaration.
    #[must_use]
    pub fn at(condition: RegistryError, declaration: &SourceDeclaration) -> Self {
        Self {
            condition,
            attribution: Attribution::declared(
                declaration.index(),
                declaration.coordinate().clone(),
                declaration.identity().clone(),
            ),
            entry: None,
            dependency: None,
        }
    }

    /// Attributes one condition to one declaration and one snapshot entry.
    #[must_use]
    pub fn at_entry(
        condition: RegistryError,
        declaration: &SourceDeclaration,
        entry: usize,
    ) -> Self {
        Self {
            condition,
            attribution: Attribution::declared(
                declaration.index(),
                declaration.coordinate().clone(),
                declaration.identity().clone(),
            ),
            entry: Some(entry),
            dependency: None,
        }
    }

    /// Attributes one condition to one entry that no declaration binds.
    #[must_use]
    pub fn unbound(condition: RegistryError, entry: usize, identity: SourceIdentity) -> Self {
        Self {
            condition,
            attribution: Attribution::unbound(entry, identity),
            entry: Some(entry),
            dependency: None,
        }
    }

    /// Returns this refusal with one causing entry recorded.
    #[must_use]
    pub fn with_entry(mut self, entry: usize) -> Self {
        self.entry = Some(entry);
        self
    }

    /// Returns this refusal with the exact dependency edge that caused it.
    #[must_use]
    pub fn with_dependency(mut self, dependency: &LockedDependency) -> Self {
        self.dependency = Some(dependency.clone());
        self
    }

    /// Returns the condition.
    #[must_use]
    pub const fn condition(&self) -> &RegistryError {
        &self.condition
    }

    /// Returns the frozen published code of the condition, when it has one.
    #[must_use]
    pub fn code(&self) -> Option<RegistryDiagnosticCode> {
        self.condition.code()
    }

    /// Returns the clause that owns the condition.
    #[must_use]
    pub const fn clause(&self) -> &'static str {
        self.condition.clause()
    }

    /// Returns the closed failure reason that stopped this decision.
    #[must_use]
    pub const fn reason(&self) -> TrustFailureReason {
        self.condition.trust_failure_reason()
    }

    /// Returns the exact requirement anchor that owns this refusal's closed reason.
    #[must_use]
    pub const fn requirement_anchor(&self) -> &'static str {
        self.reason().anchor()
    }

    /// Returns the attribution.
    #[must_use]
    pub const fn attribution(&self) -> &Attribution {
        &self.attribution
    }

    /// Returns the causing declaration or entry index.
    #[must_use]
    pub const fn declaration_index(&self) -> usize {
        self.attribution.index()
    }

    /// Returns the causing source identity.
    #[must_use]
    pub const fn declaration_identity(&self) -> &SourceIdentity {
        self.attribution.identity()
    }

    /// Returns whether a declaration supplied the attribution.
    #[must_use]
    pub const fn is_bound(&self) -> bool {
        self.attribution.is_bound()
    }

    /// Returns the causing snapshot entry, when the condition names one.
    #[must_use]
    pub const fn causing_entry(&self) -> Option<usize> {
        self.entry
    }

    /// Returns the exact parent-to-dependency edge that caused this refusal, when any.
    #[must_use]
    pub const fn causing_dependency(&self) -> Option<&LockedDependency> {
        self.dependency.as_ref()
    }
}

impl fmt::Display for RegistryRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.code() {
            Some(code) => write!(
                formatter,
                "{} (attributed to {}): {:?}",
                code.as_str(),
                self.attribution.index(),
                self.condition
            ),
            None => write!(
                formatter,
                "unpublished condition (attributed to {}): {:?}",
                self.attribution.index(),
                self.condition
            ),
        }
    }
}

/// The closed source-kind vocabulary of `GNT-27.1-source-identity`.
///
/// Resolution never falls back between kinds, so a registry source, a version-control
/// source, a path source, and a vendored source are four separate universes of identity
/// even when their identity texts share one tail.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SourceKind {
    /// A registry source acquired from one authenticated registry identity.
    Registry,
    /// A version-control source at one pinned commit.
    Vcs,
    /// A local path source.
    Path,
    /// A vendored source committed into the tree.
    Vendored,
}

impl SourceKind {
    /// Every kind of the closed vocabulary, in vocabulary order.
    pub const ALL: [Self; 4] = [Self::Registry, Self::Vcs, Self::Path, Self::Vendored];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Registry => "registry",
            Self::Vcs => "vcs",
            Self::Path => "path",
            Self::Vendored => "vendored",
        }
    }

    /// Parses one exact portable spelling, rejecting anything outside the vocabulary.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.wire_name() == value)
    }
}

/// One canonical source identity.
///
/// The identity is the pair of its kind and its canonical identity text, and its digest
/// is derived under a domain separator from exactly those two declared fields. The text is
/// explicit and stable: it is never a host path, a working directory, a transport, a
/// display form, or a fetch result.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SourceIdentity {
    kind: SourceKind,
    canonical: Arc<str>,
    digest: [u8; 32],
}

impl SourceIdentity {
    /// Validates one canonical identity text of one source kind.
    fn new(kind: SourceKind, canonical_text: &str) -> Result<Self, RegistryError> {
        if canonical_text.is_empty()
            || !is_nfc(canonical_text)
            || canonical_text.chars().any(char::is_control)
            || canonical_text.contains("//")
            || canonical_text.starts_with('/')
            || canonical_text.contains("\\")
        {
            return Err(RegistryError::SourceIdentityMalformed {
                kind,
                text: Arc::from(canonical_text),
            });
        }
        let digest = digest_fields(
            SOURCE_IDENTITY_DOMAIN,
            &[kind.wire_name().as_bytes(), canonical_text.as_bytes()],
        );
        Ok(Self {
            kind,
            canonical: Arc::from(canonical_text),
            digest,
        })
    }

    /// Returns the identity of one authenticated registry service.
    ///
    /// A registry identity deliberately names the registry, not a namespace or package that
    /// registry serves. Package coordinates are publication fields inside a snapshot, while
    /// this value selects the nominal source and its trust root.
    pub fn registry(registry: &str) -> Result<Self, RegistryError> {
        if registry.is_empty()
            || registry.contains(':')
            || registry.contains('/')
            || registry.contains('\\')
            || registry.chars().any(char::is_control)
        {
            return Err(RegistryError::SourceIdentityMalformed {
                kind: SourceKind::Registry,
                text: Arc::from(registry),
            });
        }
        Self::new(SourceKind::Registry, &format!("registry:{registry}"))
    }

    /// Returns the identity of one version-control source at one pinned commit.
    pub fn vcs(url: &str, commit: &CommitId) -> Result<Self, RegistryError> {
        if url.contains("://") || url.starts_with('/') || url.contains('\\') {
            return Err(RegistryError::SourceIdentityMalformed {
                kind: SourceKind::Vcs,
                text: Arc::from(url),
            });
        }
        Self::new(SourceKind::Vcs, &format!("vcs:{url}@{}", commit.as_str()))
    }

    /// Returns the identity of one local path source.
    pub fn path(canonical: &str) -> Result<Self, RegistryError> {
        if canonical.starts_with('/') || canonical.contains('\\') || canonical.contains("..") {
            return Err(RegistryError::SourceIdentityMalformed {
                kind: SourceKind::Path,
                text: Arc::from(canonical),
            });
        }
        Self::new(SourceKind::Path, &format!("path:{canonical}"))
    }

    /// Returns the identity of one vendored source.
    pub fn vendored(relative: &str) -> Result<Self, RegistryError> {
        if relative.starts_with('/') || relative.contains('\\') || relative.contains("..") {
            return Err(RegistryError::SourceIdentityMalformed {
                kind: SourceKind::Vendored,
                text: Arc::from(relative),
            });
        }
        Self::new(SourceKind::Vendored, &format!("vendored:{relative}"))
    }

    /// Returns the source kind.
    #[must_use]
    pub const fn kind(&self) -> SourceKind {
        self.kind
    }

    /// Returns the one canonical identity text.
    #[must_use]
    pub fn canonical_text(&self) -> &str {
        &self.canonical
    }

    /// Returns the kind-independent identity text used only to detect forbidden substitutions.
    fn nominal_text(&self) -> &str {
        let mut text = self.canonical.as_ref();
        while let Some((prefix, rest)) = text.split_once(':') {
            if SourceKind::ALL
                .iter()
                .any(|kind| kind.wire_name() == prefix)
            {
                text = rest;
            } else {
                break;
            }
        }
        text
    }

    /// Returns the one canonical byte encoding of the identity text.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        self.canonical.as_bytes()
    }

    /// Returns the domain-separated identity digest.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// Returns the lowercase hexadecimal identity digest.
    #[must_use]
    pub fn digest_hex(&self) -> String {
        hex(&self.digest)
    }
}

/// One declared, machine-usable coordinate of a dependency declaration.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DeclarationCoordinate(Arc<str>);

impl DeclarationCoordinate {
    /// Validates one explicit source declaration coordinate.
    pub fn new(value: &str) -> Result<Self, RegistryError> {
        if value.is_empty() || value.chars().any(char::is_control) {
            return Err(RegistryError::DeclarationInvalid {
                field: "declaration coordinate",
                value: Arc::from(value),
            });
        }
        Ok(Self(Arc::from(value)))
    }

    /// Returns the exact declared coordinate.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One dependency declaration and the one source identity it binds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceDeclaration {
    index: usize,
    coordinate: DeclarationCoordinate,
    alias: RegistryName,
    identity: SourceIdentity,
}

impl SourceDeclaration {
    /// Validates one declaration by index, exact coordinate, alias, and bound identity.
    pub fn new(
        index: usize,
        coordinate: &str,
        alias: &str,
        identity: SourceIdentity,
    ) -> Result<Self, RegistryError> {
        Ok(Self {
            index,
            coordinate: DeclarationCoordinate::new(coordinate)?,
            alias: RegistryName::new(RegistryNameKind::DependencyAlias, alias)?,
            identity,
        })
    }

    /// Returns the declaration index.
    #[must_use]
    pub const fn index(&self) -> usize {
        self.index
    }

    /// Returns the exact declared coordinate used for machine-readable attribution.
    #[must_use]
    pub const fn coordinate(&self) -> &DeclarationCoordinate {
        &self.coordinate
    }

    /// Returns the local alias name.
    #[must_use]
    pub const fn alias(&self) -> &RegistryName {
        &self.alias
    }

    /// Returns the bound canonical source identity.
    #[must_use]
    pub const fn identity(&self) -> &SourceIdentity {
        &self.identity
    }

    /// Attributes one condition to this declaration.
    #[must_use]
    pub fn refusal(&self, condition: RegistryError) -> RegistryRefusal {
        RegistryRefusal::at(condition, self)
    }
}

/// Requires one presented source to equal the identity bound by its declaration.
///
/// Public acquisition and advisory boundaries call this before their substantive checks so a
/// foreign source cannot borrow another declaration's authority or diagnostics.
fn require_declared_source(
    declaration: &SourceDeclaration,
    source: &SourceIdentity,
) -> Result<(), RegistryRefusal> {
    if source == declaration.identity() {
        Ok(())
    } else {
        Err(declaration.refusal(RegistryError::SourceNotDeclared {
            requested: source.clone(),
        }))
    }
}

/// Refuses a declaration set whose indices cannot identify one dependency edge each.
fn validate_declaration_indices(declarations: &[SourceDeclaration]) -> Result<(), RegistryRefusal> {
    for (index, declaration) in declarations.iter().enumerate() {
        if declarations[..index]
            .iter()
            .any(|prior| prior.index() == declaration.index())
        {
            return Err(declaration.refusal(RegistryError::DeclarationInvalid {
                field: "source declaration index",
                value: Arc::from(declaration.index().to_string()),
            }));
        }
    }
    Ok(())
}

/// Resolves one requested source identity among the declared ones.
///
/// Resolution binds the declaration whose canonical identity equals the request, and it
/// never falls back between kinds and never resolves to a same-named source of another
/// kind: a request whose identity text matches a declaration of another kind is refused as
/// [`RegistryError::SourceKindFallback`], and a request no declaration binds is refused as
/// [`RegistryError::SourceNotDeclared`]. Both refusals are attributed to the declaration
/// that required the source.
pub fn resolve_source<'a>(
    declarations: &'a [SourceDeclaration],
    requiring: &SourceDeclaration,
    requested: &SourceIdentity,
) -> Result<&'a SourceDeclaration, RegistryRefusal> {
    validate_declaration_indices(declarations)?;
    if let Some(found) = declarations
        .iter()
        .find(|declaration| declaration.identity() == requested)
    {
        return Ok(found);
    }
    if let Some(other) = declarations.iter().find(|declaration| {
        declaration.identity().kind() != requested.kind()
            && declaration.identity().nominal_text() == requested.nominal_text()
    }) {
        return Err(requiring.refusal(RegistryError::SourceKindFallback {
            declared: other.identity().kind(),
            requested: requested.kind(),
            text: Arc::from(requested.canonical_text()),
        }));
    }
    Err(requiring.refusal(RegistryError::SourceNotDeclared {
        requested: requested.clone(),
    }))
}

/// One local configuration alias name.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ConfigurationAlias(Arc<str>);

impl ConfigurationAlias {
    /// Validates one configuration alias spelling.
    pub fn new(value: &str) -> Result<Self, RegistryError> {
        if !is_declared_spelling(value) {
            return Err(RegistryError::DeclarationInvalid {
                field: "configuration alias",
                value: Arc::from(value),
            });
        }
        Ok(Self(Arc::from(value)))
    }

    /// Returns the exact alias spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One configuration alias and the authenticated identity it binds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AliasBinding {
    alias: ConfigurationAlias,
    identity: SourceIdentity,
}

impl AliasBinding {
    /// Validates one alias binding.
    pub fn new(alias: &str, identity: SourceIdentity) -> Result<Self, RegistryError> {
        Ok(Self {
            alias: ConfigurationAlias::new(alias)?,
            identity,
        })
    }

    /// Returns the alias name.
    #[must_use]
    pub const fn alias(&self) -> &ConfigurationAlias {
        &self.alias
    }

    /// Returns the authenticated identity the alias binds.
    #[must_use]
    pub const fn identity(&self) -> &SourceIdentity {
        &self.identity
    }
}

/// The configuration aliases of one workspace and their bound identities.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AliasBindings {
    bindings: BTreeMap<ConfigurationAlias, SourceIdentity>,
}

impl AliasBindings {
    /// Builds one alias map, refusing one alias bound twice.
    pub fn new(bindings: &[AliasBinding]) -> Result<Self, RegistryError> {
        let mut map = BTreeMap::new();
        for binding in bindings {
            if map
                .insert(binding.alias.clone(), binding.identity.clone())
                .is_some()
            {
                return Err(RegistryError::DeclarationInvalid {
                    field: "configuration alias",
                    value: Arc::from(binding.alias.as_str()),
                });
            }
        }
        Ok(Self { bindings: map })
    }

    /// Returns the authenticated identity one alias binds.
    #[must_use]
    pub fn bound_identity(&self, alias: &ConfigurationAlias) -> Option<&SourceIdentity> {
        self.bindings.get(alias)
    }

    /// Returns the number of bound aliases.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bindings.len()
    }

    /// Returns whether no alias is bound.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bindings.is_empty()
    }

    /// Decides that one alias is not a semantic identity.
    ///
    /// An alias is a local configuration name that binds an authenticated identity; it is
    /// never itself a semantic source identity, so the answer to "what identity is this
    /// alias?" is always a refusal. A bound alias is refused as
    /// [`RegistryError::ConfigAliasNotIdentity`], because the alias spelling must not be
    /// used where a canonical identity is required, and an unbound alias is refused as
    /// [`RegistryError::SourceNotDeclared`]. The identity an alias *binds* stays available
    /// through [`Self::bound_identity`].
    pub fn semantic_identity(
        &self,
        requiring: &SourceDeclaration,
        alias: &ConfigurationAlias,
    ) -> Result<SourceIdentity, RegistryRefusal> {
        match self.bindings.get(alias) {
            Some(_) => Err(requiring.refusal(RegistryError::ConfigAliasNotIdentity {
                alias: Arc::from(alias.as_str()),
            })),
            None => {
                let requested = SourceIdentity::new(SourceKind::Registry, alias.as_str())
                    .map_err(|error| requiring.refusal(error))?;
                Err(requiring.refusal(RegistryError::SourceNotDeclared { requested }))
            }
        }
    }
}

/// The closed name-kind vocabulary of `GNT-27.2-canonical-names`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RegistryNameKind {
    /// A package name.
    Package,
    /// A namespace name, which may be dotted.
    Namespace,
    /// A publisher name, which may be dotted.
    Publisher,
    /// A dependency-alias name.
    DependencyAlias,
}

impl RegistryNameKind {
    /// Every kind of the closed vocabulary, in vocabulary order.
    pub const ALL: [Self; 4] = [
        Self::Package,
        Self::Namespace,
        Self::Publisher,
        Self::DependencyAlias,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Package => "package",
            Self::Namespace => "namespace",
            Self::Publisher => "publisher",
            Self::DependencyAlias => "dependency-alias",
        }
    }

    /// Parses one exact portable spelling, rejecting anything outside the vocabulary.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.wire_name() == value)
    }

    /// Returns whether this kind admits dotted segment spellings.
    #[must_use]
    pub const fn is_dotted(self) -> bool {
        matches!(self, Self::Namespace | Self::Publisher)
    }
}

/// Returns the defect of one spelling that one name kind does not admit.
fn name_defect(kind: RegistryNameKind, value: &str) -> Option<NameDefect> {
    if value.is_empty() {
        return Some(NameDefect::Empty);
    }
    if value.chars().count() > REGISTRY_NAME_SCALAR_LIMIT {
        return Some(NameDefect::TooLong);
    }
    match kind {
        RegistryNameKind::Package => match PackageName::new(value) {
            Ok(_) => None,
            Err(_) => Some(NameDefect::IllegalCharacter),
        },
        RegistryNameKind::DependencyAlias => match DependencyAlias::new(value) {
            Ok(_) => None,
            Err(_) => Some(NameDefect::IllegalCharacter),
        },
        RegistryNameKind::Namespace | RegistryNameKind::Publisher => {
            for segment in value.split('.') {
                if segment.is_empty() {
                    return Some(NameDefect::EmptySegment);
                }
                let mut scalars = segment.chars();
                let first = scalars.next();
                if !first.is_some_and(|scalar| scalar == '_' || is_xid_start(scalar)) {
                    return Some(NameDefect::IllegalCharacter);
                }
                if !scalars.all(|scalar| is_xid_continue(scalar) || scalar == '-') {
                    return Some(NameDefect::IllegalCharacter);
                }
            }
            None
        }
    }
}

/// One canonical registry name of one name kind.
///
/// The canonical spelling is the one byte representation of the name: it is NFC, it is the
/// spelling every equality and ordering decision here uses, and its digest is derived from
/// the kind and that spelling. Two spellings that are canonically equivalent without being
/// byte-identical never become two names, because the noncanonical one is refused rather
/// than normalized silently.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RegistryName {
    kind: RegistryNameKind,
    canonical: Arc<str>,
    digest: [u8; 32],
}

impl RegistryName {
    /// Validates one name spelling of one kind.
    pub fn new(kind: RegistryNameKind, value: &str) -> Result<Self, RegistryError> {
        if let Some(defect) = name_defect(kind, value) {
            return Err(RegistryError::NameMalformed {
                kind,
                spelling: Arc::from(value),
                defect,
            });
        }
        if !is_nfc(value) {
            return Err(RegistryError::NameNoncanonical {
                kind,
                spelling: Arc::from(value),
                canonical: Arc::from(normalize_nfc(value)),
            });
        }
        let digest = digest_fields(
            NAME_IDENTITY_DOMAIN,
            &[kind.wire_name().as_bytes(), value.as_bytes()],
        );
        Ok(Self {
            kind,
            canonical: Arc::from(value),
            digest,
        })
    }

    /// Validates one package name.
    pub fn package(value: &str) -> Result<Self, RegistryError> {
        Self::new(RegistryNameKind::Package, value)
    }

    /// Validates one namespace name.
    pub fn namespace(value: &str) -> Result<Self, RegistryError> {
        Self::new(RegistryNameKind::Namespace, value)
    }

    /// Validates one publisher name.
    pub fn publisher(value: &str) -> Result<Self, RegistryError> {
        Self::new(RegistryNameKind::Publisher, value)
    }

    /// Validates one dependency-alias name.
    pub fn dependency_alias(value: &str) -> Result<Self, RegistryError> {
        Self::new(RegistryNameKind::DependencyAlias, value)
    }

    /// Returns the name kind.
    #[must_use]
    pub const fn kind(&self) -> RegistryNameKind {
        self.kind
    }

    /// Returns the one canonical spelling.
    #[must_use]
    pub fn spelling(&self) -> &str {
        &self.canonical
    }

    /// Returns the one canonical byte encoding.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        self.canonical.as_bytes()
    }

    /// Returns the domain-separated name digest.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// Returns the lowercase hexadecimal name digest.
    #[must_use]
    pub fn digest_hex(&self) -> String {
        hex(&self.digest)
    }

    /// Returns the confusable skeleton of the case-folded canonical spelling.
    #[must_use]
    pub fn skeleton(&self) -> String {
        confusable_skeleton(&to_full_lowercase(&self.canonical))
    }
}

/// The closed collision-relation vocabulary of `GNT-27.2-canonical-names`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum NameCollisionKind {
    /// The two canonical spellings are byte-identical.
    Exact,
    /// The two canonical spellings are equal under the pinned full case mappings.
    Case,
    /// The two canonical spellings share one confusable skeleton.
    Confusable,
}

impl NameCollisionKind {
    /// Every condition of the closed vocabulary, in precedence order.
    pub const ALL: [Self; 3] = [Self::Exact, Self::Case, Self::Confusable];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Case => "case",
            Self::Confusable => "confusable",
        }
    }
}

/// One decided collision between two names of one kind.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NameCollision {
    first: RegistryName,
    second: RegistryName,
    condition: NameCollisionKind,
}

impl NameCollision {
    /// Records one colliding pair in canonical order.
    #[must_use]
    pub fn new(left: &RegistryName, right: &RegistryName, condition: NameCollisionKind) -> Self {
        if left <= right {
            Self {
                first: left.clone(),
                second: right.clone(),
                condition,
            }
        } else {
            Self {
                first: right.clone(),
                second: left.clone(),
                condition,
            }
        }
    }

    /// Returns the first name in canonical order.
    #[must_use]
    pub const fn first(&self) -> &RegistryName {
        &self.first
    }

    /// Returns the second name in canonical order.
    #[must_use]
    pub const fn second(&self) -> &RegistryName {
        &self.second
    }

    /// Returns the collision condition.
    #[must_use]
    pub const fn condition(&self) -> NameCollisionKind {
        self.condition
    }
}

/// Decides the collision relation of two names of one kind.
///
/// The relation is symmetric, total over compared pairs, and independent of declaration
/// and discovery order: it reads only the two canonical spellings, and the diagnostic
/// carries the pair in canonical byte order. Names of two different kinds never collide,
/// because the kinds are separate vocabularies rather than one namespace. Conditions are
/// reported in vocabulary order, so a pair that satisfies more than one condition is
/// reported under the first one in that order, and a collision is never resolved by
/// preferring a declaration, a publisher, or a discovery order.
#[must_use]
pub fn collision(left: &RegistryName, right: &RegistryName) -> Option<NameCollision> {
    if left.kind() != right.kind() {
        return None;
    }
    if left.spelling() == right.spelling() {
        return Some(NameCollision::new(left, right, NameCollisionKind::Exact));
    }
    if to_full_lowercase(left.spelling()) == to_full_lowercase(right.spelling()) {
        return Some(NameCollision::new(left, right, NameCollisionKind::Case));
    }
    if left.skeleton() == right.skeleton() {
        return Some(NameCollision::new(
            left,
            right,
            NameCollisionKind::Confusable,
        ));
    }
    None
}

/// The publication names one registry has admitted.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PublicationNameSet {
    admitted: Vec<RegistryName>,
}

impl PublicationNameSet {
    /// Constructs one empty publication name set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Admits one canonical publication name.
    ///
    /// The same name admitted twice is admitted once and is not a collision. A distinct
    /// spelling that collides with an admitted one is refused as
    /// [`RegistryError::NameCollision`] instead of being preferred, renamed, or silently
    /// normalized.
    pub fn admit(&mut self, name: RegistryName) -> Result<(), RegistryError> {
        for existing in &self.admitted {
            if let Some(found) = collision(existing, &name) {
                if found.condition() == NameCollisionKind::Exact {
                    return Ok(());
                }
                return Err(RegistryError::NameCollision {
                    kind: name.kind(),
                    first: Arc::from(found.first().spelling()),
                    second: Arc::from(found.second().spelling()),
                    condition: found.condition(),
                });
            }
        }
        self.admitted.push(name);
        self.admitted.sort();
        Ok(())
    }

    /// Returns whether one name is admitted.
    #[must_use]
    pub fn contains(&self, name: &RegistryName) -> bool {
        self.admitted.contains(name)
    }

    /// Returns the admitted names in canonical order.
    #[must_use]
    pub fn names(&self) -> &[RegistryName] {
        &self.admitted
    }

    /// Returns the number of admitted names.
    #[must_use]
    pub fn len(&self) -> usize {
        self.admitted.len()
    }

    /// Returns whether no name is admitted.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.admitted.is_empty()
    }
}

/// One external name of one registry kind.
///
/// An external name arrives in whatever spelling its source publishes. It is canonicalized
/// once, here, and never acquires a second byte representation afterwards.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ExternalName {
    kind: RegistryNameKind,
    canonical: Arc<str>,
}

impl ExternalName {
    /// Canonicalizes and admits one external name of one kind.
    pub fn new(kind: RegistryNameKind, value: &str) -> Result<Self, RegistryError> {
        let canonical = normalize_nfc(value);
        let name = RegistryName::new(kind, &canonical)?;
        Ok(Self {
            kind,
            canonical: Arc::from(name.spelling()),
        })
    }

    /// Returns the name kind.
    #[must_use]
    pub const fn kind(&self) -> RegistryNameKind {
        self.kind
    }

    /// Returns the canonical spelling.
    #[must_use]
    pub fn spelling(&self) -> &str {
        &self.canonical
    }

    /// Returns the confusable skeleton of the case-folded canonical spelling.
    #[must_use]
    pub fn skeleton(&self) -> String {
        confusable_skeleton(&to_full_lowercase(&self.canonical))
    }
}

/// One generated source alias for one external name.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SourceAlias(Arc<str>);

impl SourceAlias {
    /// Returns the exact generated spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The injective external-name-to-alias mapping of `GNT-27.2-canonical-names`.
///
/// Every external name maps to exactly one alias, or it fails before use. Two external
/// names of one kind that share one skeleton are refused rather than disambiguated, because
/// a reader cannot tell them apart. The alias itself derives from the canonical name alone
/// and never from an insertion order, a discovery order, a counter, or a clock, so the same
/// names produce the same aliases under every insertion order.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ExternalAliasMap {
    by_name: BTreeMap<ExternalName, SourceAlias>,
    by_alias: BTreeMap<SourceAlias, ExternalName>,
}

impl ExternalAliasMap {
    /// Constructs one empty mapping.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Maps one external name to one explicit collision-free alias.
    pub fn insert(&mut self, name: ExternalName) -> Result<SourceAlias, RegistryError> {
        if let Some(existing) = self.by_name.get(&name) {
            return Ok(existing.clone());
        }
        for (other, alias) in &self.by_name {
            if other.kind() == name.kind() && other.skeleton() == name.skeleton() {
                return Err(RegistryError::ExternalAliasCollision {
                    alias: Arc::from(alias.as_str()),
                    conflicting: Arc::from(name.spelling()),
                });
            }
        }
        let alias = self.derive_alias(&name);
        self.by_alias.insert(alias.clone(), name.clone());
        self.by_name.insert(name, alias.clone());
        Ok(alias)
    }

    /// Returns the alias one external name maps to.
    #[must_use]
    pub fn alias(&self, name: &ExternalName) -> Option<&SourceAlias> {
        self.by_name.get(name)
    }

    /// Returns the external name one alias maps from.
    #[must_use]
    pub fn external(&self, alias: &SourceAlias) -> Option<&ExternalName> {
        self.by_alias.get(alias)
    }

    /// Returns the number of mapped external names.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_name.len()
    }

    /// Returns whether the mapping is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }

    /// Derives one alias from one canonical name, extending a digest suffix until free.
    fn derive_alias(&self, name: &ExternalName) -> SourceAlias {
        let base = format!(
            "ext_{}_{}",
            name.kind().wire_name(),
            escape_spelling(name.spelling())
        );
        if !self.is_occupied(&base) {
            return SourceAlias(Arc::from(base));
        }
        let digest = hex(&digest_fields(
            EXTERNAL_ALIAS_DOMAIN,
            &[
                name.kind().wire_name().as_bytes(),
                name.spelling().as_bytes(),
            ],
        ));
        let mut suffix_length = 4;
        while suffix_length <= digest.len() {
            let candidate = format!("{base}_{}", &digest[..suffix_length]);
            if !self.is_occupied(&candidate) {
                return SourceAlias(Arc::from(candidate));
            }
            suffix_length += 4;
        }
        SourceAlias(Arc::from(base))
    }

    /// Returns whether one alias spelling is already occupied.
    fn is_occupied(&self, spelling: &str) -> bool {
        self.by_alias.keys().any(|alias| alias.as_str() == spelling)
    }
}

/// One declared signing-key identity.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct KeyId(Arc<str>);

impl KeyId {
    /// Validates one declared key identity spelling.
    pub fn new(value: &str) -> Result<Self, RegistryError> {
        if !is_declared_spelling(value) {
            return Err(RegistryError::DeclarationInvalid {
                field: "key id",
                value: Arc::from(value),
            });
        }
        Ok(Self(Arc::from(value)))
    }

    /// Returns the exact key identity spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One declared trust-root identity.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RootId(Arc<str>);

impl RootId {
    /// Validates one trust-root identity spelling.
    pub fn new(value: &str) -> Result<Self, RegistryError> {
        if !is_declared_spelling(value) {
            return Err(RegistryError::DeclarationInvalid {
                field: "root id",
                value: Arc::from(value),
            });
        }
        Ok(Self(Arc::from(value)))
    }

    /// Returns the exact trust-root identity spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One key and its declared material digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyRecord {
    key: KeyId,
    material: [u8; 32],
}

impl KeyRecord {
    /// Validates one key record whose material is not the reserved omitted digest.
    pub fn new(key: KeyId, material: [u8; 32]) -> Result<Self, RegistryError> {
        if material.iter().all(|byte| *byte == 0) {
            return Err(RegistryError::DeclarationInvalid {
                field: "key material",
                value: Arc::from(key.as_str()),
            });
        }
        Ok(Self { key, material })
    }

    /// Returns the key identity.
    #[must_use]
    pub const fn key(&self) -> &KeyId {
        &self.key
    }

    /// Returns the declared material digest.
    #[must_use]
    pub const fn material(&self) -> [u8; 32] {
        self.material
    }
}

/// Returns the declared signature digest one key produces over one payload digest.
fn signature_digest(key: &KeyId, material: &[u8; 32], payload: [u8; 32]) -> [u8; 32] {
    digest_fields(
        SIGNATURE_DOMAIN,
        &[key.as_str().as_bytes(), &material[..], &payload[..]],
    )
}

/// One declared signature value over one payload digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeclaredSignature {
    key: KeyId,
    digest: [u8; 32],
}

impl DeclaredSignature {
    /// Declares one signature value of one key over one payload digest.
    #[must_use]
    pub const fn declared(key: KeyId, digest: [u8; 32]) -> Self {
        Self { key, digest }
    }

    /// Returns the signing key identity.
    #[must_use]
    pub const fn key(&self) -> &KeyId {
        &self.key
    }

    /// Returns the declared signature digest.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

/// Returns the signature one key produces over one payload digest.
#[must_use]
pub fn declared_signature(key: &KeyRecord, payload: [u8; 32]) -> DeclaredSignature {
    DeclaredSignature {
        key: key.key.clone(),
        digest: signature_digest(&key.key, &key.material, payload),
    }
}

/// One publisher identity: one publisher name and one signing key.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PublisherIdentity {
    name: RegistryName,
    key: KeyId,
}

impl PublisherIdentity {
    /// Validates one publisher identity whose name is a publisher name.
    pub fn new(name: RegistryName, key: KeyId) -> Result<Self, RegistryError> {
        if name.kind() != RegistryNameKind::Publisher {
            return Err(RegistryError::DeclarationInvalid {
                field: "publisher name",
                value: Arc::from(name.spelling()),
            });
        }
        Ok(Self { name, key })
    }

    /// Validates one publisher identity from one name spelling and one key spelling.
    pub fn of(name: &str, key: &str) -> Result<Self, RegistryError> {
        Self::new(RegistryName::publisher(name)?, KeyId::new(key)?)
    }

    /// Returns the publisher name.
    #[must_use]
    pub const fn name(&self) -> &RegistryName {
        &self.name
    }

    /// Returns the publisher key.
    #[must_use]
    pub const fn key(&self) -> &KeyId {
        &self.key
    }
}

/// The closed publication-state vocabulary of `GNT-27.3-metadata-snapshot`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum PublicationState {
    /// The release is published and resolvable for ordinary new resolution.
    Published,
    /// The release is yanked: reproducible from a lockfile, never resolved anew.
    Yanked,
}

impl PublicationState {
    /// Every state of the closed vocabulary, in vocabulary order.
    pub const ALL: [Self; 2] = [Self::Published, Self::Yanked];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Published => "published",
            Self::Yanked => "yanked",
        }
    }

    /// Parses one exact portable spelling, rejecting anything outside the vocabulary.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|state| state.wire_name() == value)
    }

    /// Returns whether this state resolves for ordinary new resolution.
    #[must_use]
    pub const fn is_resolvable(self) -> bool {
        matches!(self, Self::Published)
    }
}

/// One target-qualified immutable artifact of one published release.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct TargetArtifact {
    target: TargetKind,
    digest: [u8; 32],
}

impl TargetArtifact {
    /// Validates one non-omitted artifact digest for one declared target kind.
    pub fn new(target: TargetKind, digest: [u8; 32]) -> Result<Self, RegistryError> {
        if digest.iter().all(|byte| *byte == 0) {
            return Err(RegistryError::DeclarationInvalid {
                field: "target artifact",
                value: Arc::from(target.wire_name()),
            });
        }
        Ok(Self { target, digest })
    }

    /// Returns the target kind this artifact is built for.
    #[must_use]
    pub const fn target(&self) -> TargetKind {
        self.target
    }

    /// Returns the immutable digest of this target artifact.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// Returns one stable text form for canonical evidence encodings.
    #[must_use]
    pub fn canonical_text(&self) -> String {
        format!("{}#{}", self.target.wire_name(), hex(&self.digest))
    }
}

/// Returns the stable digest of one complete target-qualified artifact set.
fn target_artifact_set_digest(artifacts: &[TargetArtifact]) -> [u8; 32] {
    let mut fields = artifacts
        .iter()
        .map(TargetArtifact::canonical_text)
        .collect::<Vec<_>>();
    fields.sort();
    fields.dedup();
    let borrowed = fields.iter().map(String::as_bytes).collect::<Vec<_>>();
    digest_fields(TARGET_ARTIFACT_SET_DOMAIN, &borrowed)
}

/// One declared dependency of one snapshot entry.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SnapshotDependency {
    alias: RegistryName,
    source: SourceIdentity,
    namespace: RegistryName,
    package: RegistryName,
    version: PackageVersion,
    target: TargetKind,
    snapshot: SnapshotIdentity,
}

impl SnapshotDependency {
    /// Validates one source- and target-qualified dependency of one snapshot entry.
    pub fn new(
        alias: &str,
        source: SourceIdentity,
        namespace: &str,
        package: &str,
        version: &str,
        target: TargetKind,
        snapshot: SnapshotIdentity,
    ) -> Result<Self, RegistryError> {
        Ok(Self {
            alias: RegistryName::dependency_alias(alias)?,
            source,
            namespace: RegistryName::namespace(namespace)?,
            package: RegistryName::package(package)?,
            version: version_of(version)?,
            target,
            snapshot,
        })
    }

    /// Returns the local dependency alias.
    #[must_use]
    pub const fn alias(&self) -> &RegistryName {
        &self.alias
    }

    /// Returns the authenticated source identity of the dependency.
    #[must_use]
    pub const fn source(&self) -> &SourceIdentity {
        &self.source
    }

    /// Returns the depended namespace.
    #[must_use]
    pub const fn namespace(&self) -> &RegistryName {
        &self.namespace
    }

    /// Returns the depended package name.
    #[must_use]
    pub const fn package(&self) -> &RegistryName {
        &self.package
    }

    /// Returns the depended exact version.
    #[must_use]
    pub const fn version(&self) -> &PackageVersion {
        &self.version
    }

    /// Returns the target whose artifact this dependency requires.
    #[must_use]
    pub const fn target(&self) -> TargetKind {
        self.target
    }

    /// Returns the authenticated snapshot identity that proves this dependency.
    #[must_use]
    pub const fn snapshot(&self) -> SnapshotIdentity {
        self.snapshot
    }

    /// Returns one stable text form of this dependency for canonical encoding.
    #[must_use]
    pub fn canonical_text(&self) -> String {
        format!(
            "{}:{}/{}/{}/{}@{}?target={}#{}",
            self.alias.spelling(),
            self.alias.kind().wire_name(),
            self.source.canonical_text(),
            self.namespace.spelling(),
            self.package.spelling(),
            self.version.as_str(),
            self.target.wire_name(),
            self.snapshot.digest_hex()
        )
    }
}

/// One declared release entry of one metadata snapshot.
///
/// An entry binds the `(namespace, package, version)` tuple to the manifest and artifact
/// digests of the published release, the authenticated source identity it came from, its
/// declared dependencies, its publication state, and the publisher and signer identity
/// that authorized it. An entry whose manifest or artifact digest is the reserved omitted
/// digest is refused by [`MetadataSnapshot::new`], so an entry never stands for content it
/// does not name.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SnapshotEntry {
    namespace: RegistryName,
    package: RegistryName,
    version: PackageVersion,
    manifest: [u8; 32],
    artifact: [u8; 32],
    target_artifacts: Vec<TargetArtifact>,
    source_content: [u8; 32],
    generated: [u8; 32],
    interface: [u8; 32],
    source: SourceIdentity,
    dependencies: Vec<SnapshotDependency>,
    publication: PublicationState,
    publisher: PublisherIdentity,
}

impl SnapshotEntry {
    /// Starts one entry for one namespace, package, version, and publisher.
    pub fn new(
        source: SourceIdentity,
        namespace: &str,
        package: &str,
        version: &str,
        publisher: PublisherIdentity,
    ) -> Result<Self, RegistryError> {
        let namespace = RegistryName::namespace(namespace)?;
        let package = RegistryName::package(package)?;
        let version = version_of(version)?;
        Ok(Self {
            namespace,
            package,
            version,
            manifest: [0; 32],
            artifact: [0; 32],
            target_artifacts: Vec::new(),
            source_content: [0; 32],
            generated: [0; 32],
            interface: [0; 32],
            source,
            dependencies: Vec::new(),
            publication: PublicationState::Published,
            publisher,
        })
    }

    /// Returns this entry with one published manifest digest.
    #[must_use]
    pub fn with_manifest(mut self, manifest: [u8; 32]) -> Self {
        self.manifest = manifest;
        self
    }

    /// Returns this entry with one published artifact digest.
    #[must_use]
    pub fn with_artifact(mut self, artifact: [u8; 32]) -> Self {
        self.artifact = artifact;
        self
    }

    /// Returns this entry with one target-qualified immutable artifact.
    #[must_use]
    pub fn with_target_artifact(mut self, artifact: TargetArtifact) -> Self {
        self.target_artifacts.push(artifact);
        self.target_artifacts.sort();
        self.target_artifacts.dedup();
        self
    }

    /// Returns this entry with the complete published source-content digest.
    #[must_use]
    pub fn with_source_content(mut self, source_content: [u8; 32]) -> Self {
        self.source_content = source_content;
        self
    }

    /// Returns this entry with the published generated-output digest.
    #[must_use]
    pub fn with_generated(mut self, generated: [u8; 32]) -> Self {
        self.generated = generated;
        self
    }

    /// Returns this entry with the published public-interface digest.
    #[must_use]
    pub fn with_interface(mut self, interface: [u8; 32]) -> Self {
        self.interface = interface;
        self
    }

    /// Returns this entry with one authenticated source identity.
    #[must_use]
    pub fn with_source(mut self, source: SourceIdentity) -> Self {
        self.source = source;
        self
    }

    /// Returns this entry with one more declared dependency.
    #[must_use]
    pub fn with_dependency(mut self, dependency: SnapshotDependency) -> Self {
        self.dependencies.push(dependency);
        self
    }

    /// Returns this entry with one publication state.
    #[must_use]
    pub fn with_publication(mut self, publication: PublicationState) -> Self {
        self.publication = publication;
        self
    }

    /// Returns the entry's namespace.
    #[must_use]
    pub const fn namespace(&self) -> &RegistryName {
        &self.namespace
    }

    /// Returns the entry's package name.
    #[must_use]
    pub const fn package(&self) -> &RegistryName {
        &self.package
    }

    /// Returns the entry's exact version.
    #[must_use]
    pub const fn version(&self) -> &PackageVersion {
        &self.version
    }

    /// Returns the published manifest digest.
    #[must_use]
    pub const fn manifest(&self) -> [u8; 32] {
        self.manifest
    }

    /// Returns the published artifact digest.
    #[must_use]
    pub const fn artifact(&self) -> [u8; 32] {
        self.artifact
    }

    /// Returns the complete target-qualified immutable artifact set.
    #[must_use]
    pub fn target_artifacts(&self) -> &[TargetArtifact] {
        &self.target_artifacts
    }

    /// Returns the complete published source-content digest.
    #[must_use]
    pub const fn source_content(&self) -> [u8; 32] {
        self.source_content
    }

    /// Returns the published generated-output digest.
    #[must_use]
    pub const fn generated(&self) -> [u8; 32] {
        self.generated
    }

    /// Returns the published public-interface digest.
    #[must_use]
    pub const fn interface(&self) -> [u8; 32] {
        self.interface
    }

    /// Returns the authenticated source identity.
    #[must_use]
    pub const fn source(&self) -> &SourceIdentity {
        &self.source
    }

    /// Returns the declared dependencies.
    #[must_use]
    pub fn dependencies(&self) -> &[SnapshotDependency] {
        &self.dependencies
    }

    /// Returns the publication state.
    #[must_use]
    pub const fn publication(&self) -> PublicationState {
        self.publication
    }

    /// Returns the publisher and signer identity.
    #[must_use]
    pub const fn publisher(&self) -> &PublisherIdentity {
        &self.publisher
    }

    /// Returns whether this entry resolves for ordinary new resolution.
    #[must_use]
    pub const fn is_resolvable(&self) -> bool {
        self.publication.is_resolvable()
    }
}

/// One authenticated snapshot identity.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SnapshotIdentity([u8; 32]);

impl SnapshotIdentity {
    /// Constructs one snapshot identity from one digest.
    #[must_use]
    pub const fn from_digest(digest: [u8; 32]) -> Self {
        Self(digest)
    }

    /// Returns the identity digest.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.0
    }

    /// Returns the lowercase hexadecimal identity digest.
    #[must_use]
    pub fn digest_hex(&self) -> String {
        hex(&self.0)
    }
}

/// Appends the canonical encoding of one snapshot entry.
fn push_entry(output: &mut String, entry: &SnapshotEntry) {
    output.push('{');
    output.push_str("\"artifact\":");
    push_json_string(output, &hex(&entry.artifact()));
    output.push_str(",\"target_artifacts\":[");
    for (index, artifact) in entry.target_artifacts().iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        push_json_string(output, &artifact.canonical_text());
    }
    output.push(']');
    output.push_str(",\"generated\":");
    push_json_string(output, &hex(&entry.generated()));
    output.push_str(",\"interface\":");
    push_json_string(output, &hex(&entry.interface()));
    output.push_str(",\"dependencies\":[");
    let mut dependencies = entry
        .dependencies()
        .iter()
        .map(SnapshotDependency::canonical_text)
        .collect::<Vec<_>>();
    dependencies.sort();
    dependencies.dedup();
    for (index, dependency) in dependencies.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        push_json_string(output, dependency);
    }
    output.push_str("],\"manifest\":");
    push_json_string(output, &hex(&entry.manifest()));
    output.push_str(",\"source_content\":");
    push_json_string(output, &hex(&entry.source_content()));
    output.push_str(",\"namespace\":");
    push_json_string(output, entry.namespace().spelling());
    output.push_str(",\"package\":");
    push_json_string(output, entry.package().spelling());
    output.push_str(",\"publication\":");
    push_json_string(output, entry.publication().wire_name());
    output.push_str(",\"publisher\":{\"key\":");
    push_json_string(output, entry.publisher().key().as_str());
    output.push_str(",\"name\":");
    push_json_string(output, entry.publisher().name().spelling());
    output.push_str("},\"source\":{\"identity\":");
    push_json_string(output, entry.source().canonical_text());
    output.push_str(",\"kind\":");
    push_json_string(output, entry.source().kind().wire_name());
    output.push_str("},\"version\":");
    push_json_string(output, entry.version().as_str());
    output.push('}');
}

/// Returns the canonical encoding of one snapshot over its declared fields.
fn snapshot_canonical_bytes(
    version: ProtocolVersion,
    source: &SourceIdentity,
    sequence: u64,
    issue_epoch: u64,
    expiry_epoch: u64,
    entries: &[SnapshotEntry],
) -> String {
    let mut output = String::from("{\"entries\":[");
    for (index, entry) in entries.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        push_entry(&mut output, entry);
    }
    output.push_str("],\"source\":{");
    output.push_str("\"identity\":");
    push_json_string(&mut output, source.canonical_text());
    output.push_str(",\"kind\":");
    push_json_string(&mut output, source.kind().wire_name());
    output.push_str("},\"expiry_epoch\":");
    output.push_str(&expiry_epoch.to_string());
    output.push_str(",\"issue_epoch\":");
    output.push_str(&issue_epoch.to_string());
    output.push_str(",\"sequence\":");
    output.push_str(&sequence.to_string());
    output.push_str(",\"version\":");
    push_json_string(&mut output, &format!("{}.{}", version.major, version.minor));
    output.push('}');
    output
}

/// Returns one stable text coordinate of one release tuple.
fn coordinate_text(
    namespace: &RegistryName,
    package: &RegistryName,
    version: &PackageVersion,
) -> String {
    format!(
        "{}/{}@{}",
        namespace.spelling(),
        package.spelling(),
        version.as_str()
    )
}

/// Validates one exact version value, reporting a declaration defect.
fn version_of(value: &str) -> Result<PackageVersion, RegistryError> {
    match PackageVersion::new(value) {
        Ok(version) => Ok(version),
        Err(_) => Err(RegistryError::DeclarationInvalid {
            field: "version",
            value: Arc::from(value),
        }),
    }
}

/// One versioned metadata snapshot over one monotone sequence number.
///
/// The snapshot is a pure value: it carries no trust decision, no registry answer, and no
/// clock reading. Its canonical encoding sorts its entries, so permuted entries produce
/// one canonical encoding, one content digest, and one identity, and its format version is
/// the landed [`ProtocolVersion`] rather than a private number.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetadataSnapshot {
    version: ProtocolVersion,
    source: SourceIdentity,
    sequence: u64,
    issue_epoch: u64,
    expiry_epoch: u64,
    entries: Vec<SnapshotEntry>,
    canonical: Arc<[u8]>,
    digest: [u8; 32],
}

impl MetadataSnapshot {
    /// The snapshot format version this model defines.
    pub const VERSION: ProtocolVersion = ProtocolVersion { major: 1, minor: 0 };

    /// Builds one snapshot over one declared sequence, epoch window, and entry set.
    ///
    /// An unsupported format version, an empty entry set, an expiry not strictly after the
    /// issuance, a reserved omitted manifest or artifact digest, and one release tuple
    /// declared twice are each refused before any snapshot value exists, so a snapshot is
    /// never constructed that could not be verified afterwards.
    pub fn new(
        version: ProtocolVersion,
        source: SourceIdentity,
        sequence: u64,
        issue_epoch: u64,
        expiry_epoch: u64,
        entries: &[SnapshotEntry],
    ) -> Result<Self, RegistryError> {
        if version != Self::VERSION {
            return Err(RegistryError::SnapshotVersionUnsupported { version });
        }
        if entries.is_empty() {
            return Err(RegistryError::SnapshotEntryInvalid {
                field: "entries",
                value: Arc::from("empty"),
            });
        }
        if expiry_epoch <= issue_epoch {
            return Err(RegistryError::SnapshotEpochInconsistent {
                issue_epoch,
                observed_epoch: expiry_epoch,
            });
        }
        let mut ordered = entries.to_vec();
        ordered.sort();
        for entry in &ordered {
            if entry.source() != &source {
                return Err(RegistryError::SnapshotEntryInvalid {
                    field: "source",
                    value: Arc::from(entry.source().canonical_text()),
                });
            }
            if entry.manifest().iter().all(|byte| *byte == 0) {
                return Err(RegistryError::SnapshotEntryInvalid {
                    field: "manifest",
                    value: Arc::from(coordinate_text(
                        entry.namespace(),
                        entry.package(),
                        entry.version(),
                    )),
                });
            }
            if entry.source_content().iter().all(|byte| *byte == 0) {
                return Err(RegistryError::SnapshotEntryInvalid {
                    field: "source content",
                    value: Arc::from(coordinate_text(
                        entry.namespace(),
                        entry.package(),
                        entry.version(),
                    )),
                });
            }
            if entry.generated().iter().all(|byte| *byte == 0) {
                return Err(RegistryError::SnapshotEntryInvalid {
                    field: "generated",
                    value: Arc::from(coordinate_text(
                        entry.namespace(),
                        entry.package(),
                        entry.version(),
                    )),
                });
            }
            if entry.interface().iter().all(|byte| *byte == 0) {
                return Err(RegistryError::SnapshotEntryInvalid {
                    field: "interface",
                    value: Arc::from(coordinate_text(
                        entry.namespace(),
                        entry.package(),
                        entry.version(),
                    )),
                });
            }
            if entry.artifact().iter().all(|byte| *byte == 0) {
                return Err(RegistryError::SnapshotEntryInvalid {
                    field: "artifact",
                    value: Arc::from(coordinate_text(
                        entry.namespace(),
                        entry.package(),
                        entry.version(),
                    )),
                });
            }
            if entry.target_artifacts().is_empty() {
                return Err(RegistryError::SnapshotEntryInvalid {
                    field: "target artifacts",
                    value: Arc::from(coordinate_text(
                        entry.namespace(),
                        entry.package(),
                        entry.version(),
                    )),
                });
            }
            for pair in entry.target_artifacts().windows(2) {
                if pair[0].target() == pair[1].target() {
                    return Err(RegistryError::SnapshotEntryInvalid {
                        field: "target artifact",
                        value: Arc::from(pair[1].target().wire_name()),
                    });
                }
            }
        }
        for pair in ordered.windows(2) {
            if pair[0].namespace() == pair[1].namespace()
                && pair[0].package() == pair[1].package()
                && pair[0].version() == pair[1].version()
            {
                return Err(RegistryError::SnapshotEntryInvalid {
                    field: "entry",
                    value: Arc::from(coordinate_text(
                        pair[1].namespace(),
                        pair[1].package(),
                        pair[1].version(),
                    )),
                });
            }
        }
        let canonical = snapshot_canonical_bytes(
            version,
            &source,
            sequence,
            issue_epoch,
            expiry_epoch,
            &ordered,
        );
        let digest = digest_fields(SNAPSHOT_DOMAIN, &[canonical.as_bytes()]);
        Ok(Self {
            version,
            source,
            sequence,
            issue_epoch,
            expiry_epoch,
            entries: ordered,
            canonical: Arc::from(canonical.into_bytes()),
            digest,
        })
    }

    /// Returns the snapshot format version.
    #[must_use]
    pub const fn version(&self) -> ProtocolVersion {
        self.version
    }

    /// Returns the one authenticated source this snapshot covers.
    #[must_use]
    pub const fn source(&self) -> &SourceIdentity {
        &self.source
    }

    /// Returns the monotone sequence number.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the declared issuance epoch.
    #[must_use]
    pub const fn issue_epoch(&self) -> u64 {
        self.issue_epoch
    }

    /// Returns the declared expiry epoch, which is exclusive.
    #[must_use]
    pub const fn expiry_epoch(&self) -> u64 {
        self.expiry_epoch
    }

    /// Returns the entries in canonical order.
    #[must_use]
    pub fn entries(&self) -> &[SnapshotEntry] {
        &self.entries
    }

    /// Returns one entry by its release tuple.
    #[must_use]
    pub fn entry(
        &self,
        namespace: &RegistryName,
        package: &RegistryName,
        version: &PackageVersion,
    ) -> Option<&SnapshotEntry> {
        self.entries.iter().find(|entry| {
            entry.namespace() == namespace
                && entry.package() == package
                && entry.version() == version
        })
    }

    /// Returns the first canonical-name collision that would make this snapshot inadmissible.
    ///
    /// Construction preserves declared snapshot evidence for diagnostics.  Admission performs
    /// this check after it can attribute the offending entry to its presenting declaration.
    fn first_name_collision(&self) -> Option<(usize, RegistryError)> {
        let mut namespaces = PublicationNameSet::new();
        let mut publishers = PublicationNameSet::new();
        let mut packages: BTreeMap<RegistryName, PublicationNameSet> = BTreeMap::new();
        for (index, entry) in self.entries.iter().enumerate() {
            for name in [entry.namespace(), entry.publisher().name()] {
                let names = if name.kind() == RegistryNameKind::Namespace {
                    &mut namespaces
                } else {
                    &mut publishers
                };
                if let Err(error) = names.admit(name.clone()) {
                    return Some((index, error));
                }
            }
            let names = packages.entry(entry.namespace().clone()).or_default();
            if let Err(error) = names.admit(entry.package().clone()) {
                return Some((index, error));
            }
        }
        None
    }

    /// Returns the one canonical encoding of this snapshot.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }

    /// Returns the content digest of the canonical entry set.
    #[must_use]
    pub const fn content_digest(&self) -> [u8; 32] {
        self.digest
    }

    /// Returns the lowercase hexadecimal content digest.
    #[must_use]
    pub fn content_digest_hex(&self) -> String {
        hex(&self.digest)
    }

    /// Returns the authenticated snapshot identity.
    ///
    /// The identity binds the content digest, the sequence, and the format version, so two
    /// snapshots that differ in any of the three are two identities rather than one.
    #[must_use]
    pub fn identity(&self) -> SnapshotIdentity {
        SnapshotIdentity(digest_fields(
            SNAPSHOT_IDENTITY_DOMAIN,
            &[
                &self.digest[..],
                &self.sequence.to_be_bytes()[..],
                &self.version.major.to_be_bytes()[..],
                &self.version.minor.to_be_bytes()[..],
            ],
        ))
    }
}

/// One authority scope: a namespace, optionally narrowed to one package within it.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AuthorityScope {
    namespace: RegistryName,
    package: Option<RegistryName>,
}

impl AuthorityScope {
    /// Validates one whole-namespace scope.
    pub fn of_namespace(namespace: &str) -> Result<Self, RegistryError> {
        Ok(Self {
            namespace: RegistryName::namespace(namespace)?,
            package: None,
        })
    }

    /// Validates one scope narrowed to one package of one namespace.
    pub fn of_package(namespace: &str, package: &str) -> Result<Self, RegistryError> {
        Ok(Self {
            namespace: RegistryName::namespace(namespace)?,
            package: Some(RegistryName::package(package)?),
        })
    }

    /// Builds the scope of one already admitted coordinate pair.
    #[must_use]
    pub fn of(namespace: &RegistryName, package: &RegistryName) -> Self {
        Self {
            namespace: namespace.clone(),
            package: Some(package.clone()),
        }
    }

    /// Returns the scoped namespace.
    #[must_use]
    pub const fn namespace(&self) -> &RegistryName {
        &self.namespace
    }

    /// Returns the scoped package, when the scope is narrowed to one package.
    #[must_use]
    pub const fn package(&self) -> Option<&RegistryName> {
        self.package.as_ref()
    }

    /// Returns whether this scope covers one coordinate pair.
    #[must_use]
    pub fn covers(&self, namespace: &RegistryName, package: &RegistryName) -> bool {
        self.namespace == *namespace
            && match &self.package {
                None => true,
                Some(held) => held == package,
            }
    }

    /// Returns whether this scope contains another scope.
    ///
    /// The relation is the narrowing relation of `GNT-27.4-trust-roots-and-delegation`: a
    /// delegation is admitted only when the authority it derives from contains its scope, so
    /// a delegation never widens, while narrowing a namespace to one package of it is
    /// admitted.
    #[must_use]
    pub fn contains(&self, other: &Self) -> bool {
        if self.namespace != other.namespace {
            return false;
        }
        match (&self.package, &other.package) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some(left), Some(right)) => left == right,
        }
    }

    /// Returns whether these scopes share at least one publication coordinate.
    ///
    /// A retired key cannot create a new delegation whose scope includes any coordinate the
    /// retirement removed, even if the new evidence backdates its own validity window or
    /// attempts to widen the retired package back to its namespace.  Existing delegations
    /// retain their recorded chains; this relation only decides a new admission.
    #[must_use]
    pub fn overlaps(&self, other: &Self) -> bool {
        self.namespace == other.namespace
            && match (&self.package, &other.package) {
                (Some(left), Some(right)) => left == right,
                _ => true,
            }
    }
}

/// One explicit trust root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustRoot {
    id: RootId,
    source: SourceIdentity,
    publisher: PublisherIdentity,
    scope: AuthorityScope,
}

impl TrustRoot {
    /// Validates one declared trust root for exactly one authenticated source.
    pub fn new(
        id: &str,
        source: SourceIdentity,
        publisher: PublisherIdentity,
        scope: AuthorityScope,
    ) -> Result<Self, RegistryError> {
        Ok(Self {
            id: RootId::new(id)?,
            source,
            publisher,
            scope,
        })
    }

    /// Constructs a trust root explicitly bound to one authenticated source identity.
    pub fn for_source(
        id: &str,
        source: SourceIdentity,
        publisher: PublisherIdentity,
        scope: AuthorityScope,
    ) -> Result<Self, RegistryError> {
        Self::new(id, source, publisher, scope)
    }

    /// Returns the authenticated source this root governs.
    #[must_use]
    pub const fn source(&self) -> &SourceIdentity {
        &self.source
    }

    /// Returns the root identity.
    #[must_use]
    pub const fn id(&self) -> &RootId {
        &self.id
    }

    /// Returns the root publisher identity.
    #[must_use]
    pub const fn publisher(&self) -> &PublisherIdentity {
        &self.publisher
    }

    /// Returns the authority scope the root holds.
    #[must_use]
    pub const fn scope(&self) -> &AuthorityScope {
        &self.scope
    }
}

/// One delegated authority, which never widens the authority it derives from.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Delegation {
    source: SourceIdentity,
    delegator: PublisherIdentity,
    delegate: PublisherIdentity,
    scope: AuthorityScope,
    not_before_epoch: u64,
    expiry_epoch: u64,
    effective_sequence: u64,
    signature: DeclaredSignature,
}

/// The declared validity interval and activation sequence of one delegation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DelegationTiming {
    not_before_epoch: u64,
    expiry_epoch: u64,
    effective_sequence: u64,
}

impl DelegationTiming {
    /// Declares one non-empty validity interval and its activation sequence.
    pub fn new(
        not_before_epoch: u64,
        expiry_epoch: u64,
        effective_sequence: u64,
    ) -> Result<Self, RegistryError> {
        if expiry_epoch <= not_before_epoch {
            return Err(RegistryError::SnapshotEpochInconsistent {
                issue_epoch: not_before_epoch,
                observed_epoch: expiry_epoch,
            });
        }
        Ok(Self {
            not_before_epoch,
            expiry_epoch,
            effective_sequence,
        })
    }

    /// Returns the first epoch in which the delegation is valid.
    #[must_use]
    pub const fn not_before_epoch(self) -> u64 {
        self.not_before_epoch
    }

    /// Returns the exclusive expiry epoch.
    #[must_use]
    pub const fn expiry_epoch(self) -> u64 {
        self.expiry_epoch
    }

    /// Returns the sequence at which the delegation takes effect.
    #[must_use]
    pub const fn effective_sequence(self) -> u64 {
        self.effective_sequence
    }
}

impl Delegation {
    /// Declares authenticated source-scoped delegation evidence.
    ///
    /// The signature is verified against the declarer's material by [`TrustStore::new`],
    /// after the complete root-to-delegator chain has been established. The canonical payload
    /// binds the source, both identities, scope, validity window, and effective sequence.
    pub fn authenticated(
        source: SourceIdentity,
        delegator: PublisherIdentity,
        delegate: PublisherIdentity,
        scope: AuthorityScope,
        timing: DelegationTiming,
        signature: DeclaredSignature,
    ) -> Result<Self, RegistryError> {
        if signature.key() != delegator.key() {
            return Err(RegistryError::DeclarationInvalid {
                field: "delegation signature",
                value: Arc::from(signature.key().as_str()),
            });
        }
        Ok(Self {
            source,
            delegator,
            delegate,
            scope,
            not_before_epoch: timing.not_before_epoch(),
            expiry_epoch: timing.expiry_epoch(),
            effective_sequence: timing.effective_sequence(),
            signature,
        })
    }

    /// Derives the exact payload a declarer must sign for one delegation.
    #[must_use]
    pub fn payload(
        source: &SourceIdentity,
        delegator: &PublisherIdentity,
        delegate: &PublisherIdentity,
        scope: &AuthorityScope,
        not_before_epoch: u64,
        expiry_epoch: u64,
        effective_sequence: u64,
    ) -> [u8; 32] {
        digest_fields(
            DELEGATION_DOMAIN,
            &[
                &source.digest()[..],
                delegator.name().spelling().as_bytes(),
                delegator.key().as_str().as_bytes(),
                delegate.name().spelling().as_bytes(),
                delegate.key().as_str().as_bytes(),
                scope.namespace().spelling().as_bytes(),
                scope
                    .package()
                    .map_or(b"".as_slice(), |package| package.spelling().as_bytes()),
                &not_before_epoch.to_be_bytes()[..],
                &expiry_epoch.to_be_bytes()[..],
                &effective_sequence.to_be_bytes()[..],
            ],
        )
    }

    /// Returns the canonical evidence payload that authenticates this delegation.
    #[must_use]
    pub fn evidence_digest(&self) -> [u8; 32] {
        Self::payload(
            &self.source,
            &self.delegator,
            &self.delegate,
            &self.scope,
            self.not_before_epoch,
            self.expiry_epoch,
            self.effective_sequence,
        )
    }

    /// Returns the authenticated source this delegation governs.
    #[must_use]
    pub const fn source(&self) -> &SourceIdentity {
        &self.source
    }

    /// Returns the delegating publisher identity.
    #[must_use]
    pub const fn delegator(&self) -> &PublisherIdentity {
        &self.delegator
    }

    /// Returns the delegated publisher identity.
    #[must_use]
    pub const fn delegate(&self) -> &PublisherIdentity {
        &self.delegate
    }

    /// Returns the delegated scope.
    #[must_use]
    pub const fn scope(&self) -> &AuthorityScope {
        &self.scope
    }

    /// Returns the first epoch in which this delegation is valid.
    #[must_use]
    pub const fn not_before_epoch(&self) -> u64 {
        self.not_before_epoch
    }

    /// Returns the exclusive expiry epoch of this delegation.
    #[must_use]
    pub const fn expiry_epoch(&self) -> u64 {
        self.expiry_epoch
    }

    /// Returns the sequence the delegation takes effect at.
    #[must_use]
    pub const fn effective_sequence(&self) -> u64 {
        self.effective_sequence
    }

    /// Returns the declarer's authenticated signature.
    #[must_use]
    pub const fn signature(&self) -> &DeclaredSignature {
        &self.signature
    }

    /// Returns whether this evidence is active at the declared observation epoch and sequence.
    #[must_use]
    pub const fn active_at(&self, epoch: u64, sequence: u64) -> bool {
        self.not_before_epoch <= epoch
            && epoch < self.expiry_epoch
            && self.effective_sequence <= sequence
    }
}

/// One admitted delegation together with the root that anchors it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedDelegation {
    delegation: Delegation,
    root: RootId,
    root_key: KeyId,
    ancestors: Vec<KeyId>,
}

impl AdmittedDelegation {
    /// Returns the admitted delegation.
    #[must_use]
    pub const fn delegation(&self) -> &Delegation {
        &self.delegation
    }

    /// Returns the root identity this delegation is anchored in.
    #[must_use]
    pub const fn root(&self) -> &RootId {
        &self.root
    }

    /// Returns the root key this delegation is anchored in.
    #[must_use]
    pub const fn root_key(&self) -> &KeyId {
        &self.root_key
    }

    /// Returns the delegating keys this delegation's authority passes through.
    ///
    /// A compromise of any of them revokes the delegated authority, which is what
    /// `GNT-27.5-key-rotation-and-compromise-recovery` requires of a compromised key.
    #[must_use]
    pub fn ancestors(&self) -> &[KeyId] {
        &self.ancestors
    }
}

/// One authenticated source-scoped compromise of one key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Compromise {
    source: SourceIdentity,
    scope: AuthorityScope,
    declarer: PublisherIdentity,
    key: KeyId,
    effective_sequence: u64,
    observation_epoch: u64,
    signature: DeclaredSignature,
}

impl Compromise {
    /// Declares signed evidence that revokes one key for one source and authority scope.
    pub fn authenticated(
        source: SourceIdentity,
        scope: AuthorityScope,
        declarer: PublisherIdentity,
        key: KeyId,
        effective_sequence: u64,
        observation_epoch: u64,
        signature: DeclaredSignature,
    ) -> Result<Self, RegistryError> {
        if signature.key() != declarer.key() {
            return Err(RegistryError::DeclarationInvalid {
                field: "compromise signature",
                value: Arc::from(signature.key().as_str()),
            });
        }
        Ok(Self {
            source,
            scope,
            declarer,
            key,
            effective_sequence,
            observation_epoch,
            signature,
        })
    }

    /// Derives the canonical payload authenticated by the declaring authority.
    #[must_use]
    pub fn payload(
        source: &SourceIdentity,
        scope: &AuthorityScope,
        declarer: &PublisherIdentity,
        key: &KeyId,
        effective_sequence: u64,
        observation_epoch: u64,
    ) -> [u8; 32] {
        digest_fields(
            COMPROMISE_DOMAIN,
            &[
                &source.digest()[..],
                scope.namespace().spelling().as_bytes(),
                scope
                    .package()
                    .map_or(b"".as_slice(), |package| package.spelling().as_bytes()),
                declarer.name().spelling().as_bytes(),
                declarer.key().as_str().as_bytes(),
                key.as_str().as_bytes(),
                &effective_sequence.to_be_bytes()[..],
                &observation_epoch.to_be_bytes()[..],
            ],
        )
    }

    /// Returns the canonical evidence digest that the declaring authority signed.
    #[must_use]
    pub fn evidence_digest(&self) -> [u8; 32] {
        Self::payload(
            &self.source,
            &self.scope,
            &self.declarer,
            &self.key,
            self.effective_sequence,
            self.observation_epoch,
        )
    }

    /// Returns the source whose authority this compromise revokes.
    #[must_use]
    pub const fn source(&self) -> &SourceIdentity {
        &self.source
    }

    /// Returns the affected authority scope.
    #[must_use]
    pub const fn scope(&self) -> &AuthorityScope {
        &self.scope
    }

    /// Returns the authority that authenticated this compromise.
    #[must_use]
    pub const fn declarer(&self) -> &PublisherIdentity {
        &self.declarer
    }

    /// Returns the compromised key.
    #[must_use]
    pub const fn key(&self) -> &KeyId {
        &self.key
    }

    /// Returns the sequence the compromise takes effect at.
    #[must_use]
    pub const fn effective_sequence(&self) -> u64 {
        self.effective_sequence
    }

    /// Returns the declared epoch at which this compromise was observed.
    #[must_use]
    pub const fn observation_epoch(&self) -> u64 {
        self.observation_epoch
    }

    /// Returns the declaring authority's signature over this compromise evidence.
    #[must_use]
    pub const fn signature(&self) -> &DeclaredSignature {
        &self.signature
    }

    /// Returns whether this compromise covers one source coordinate at one sequence.
    #[must_use]
    pub fn covers(
        &self,
        source: &SourceIdentity,
        namespace: &RegistryName,
        package: &RegistryName,
        sequence: u64,
    ) -> bool {
        self.source == *source
            && self.scope.covers(namespace, package)
            && sequence >= self.effective_sequence
    }
}

/// One source-scoped rotation with evidence valid under both the retiring and successor keys.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RotationEvidence {
    source: SourceIdentity,
    scope: AuthorityScope,
    declarer: PublisherIdentity,
    old_key: KeyId,
    new_key: KeyId,
    old_signature: Option<DeclaredSignature>,
    new_signature: DeclaredSignature,
    effective_sequence: u64,
    effective_epoch: u64,
    overlap_end_epoch: u64,
}

/// The source-scoped context that both signatures authenticate for a rotation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RotationContext {
    source: SourceIdentity,
    scope: AuthorityScope,
    declarer: PublisherIdentity,
    old_key: KeyId,
    new_key: KeyId,
    effective_sequence: u64,
    effective_epoch: u64,
    overlap_end_epoch: u64,
}

/// The declared sequence and epoch window in which one key rotation takes effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RotationTiming {
    effective_sequence: u64,
    effective_epoch: u64,
    overlap_end_epoch: u64,
}

impl RotationTiming {
    /// Validates one explicit sequence and epoch overlap window for a rotation.
    pub fn new(
        effective_sequence: u64,
        effective_epoch: u64,
        overlap_end_epoch: u64,
    ) -> Result<Self, RegistryError> {
        if overlap_end_epoch <= effective_epoch {
            return Err(RegistryError::DeclarationInvalid {
                field: "rotation overlap epoch",
                value: Arc::from(overlap_end_epoch.to_string()),
            });
        }
        Ok(Self {
            effective_sequence,
            effective_epoch,
            overlap_end_epoch,
        })
    }

    /// Returns the first snapshot sequence to which the rotation applies.
    #[must_use]
    pub const fn effective_sequence(self) -> u64 {
        self.effective_sequence
    }

    /// Returns the first epoch of the overlap window.
    #[must_use]
    pub const fn effective_epoch(self) -> u64 {
        self.effective_epoch
    }

    /// Returns the exclusive epoch at which the retiring key stops admitting.
    #[must_use]
    pub const fn overlap_end_epoch(self) -> u64 {
        self.overlap_end_epoch
    }
}

impl RotationContext {
    /// Declares the complete source-scoped context of one rotation.
    pub fn new(
        source: SourceIdentity,
        scope: AuthorityScope,
        declarer: PublisherIdentity,
        old_key: KeyId,
        new_key: KeyId,
        timing: RotationTiming,
    ) -> Result<Self, RegistryError> {
        if declarer.key() != &old_key {
            return Err(RegistryError::RotationEvidenceInvalid {
                old_key,
                new_key,
                defect: RotationDefect::ContextMismatch,
            });
        }
        Ok(Self {
            source,
            scope,
            declarer,
            old_key,
            new_key,
            effective_sequence: timing.effective_sequence(),
            effective_epoch: timing.effective_epoch(),
            overlap_end_epoch: timing.overlap_end_epoch(),
        })
    }
}

/// The two signatures that authenticate one declared rotation context.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RotationSignatures {
    old: Option<DeclaredSignature>,
    new: DeclaredSignature,
}

impl RotationSignatures {
    /// Pairs the retiring and successor signatures for one rotation.
    #[must_use]
    pub const fn new(old: DeclaredSignature, new: DeclaredSignature) -> Self {
        Self {
            old: Some(old),
            new,
        }
    }

    /// Supplies the successor signature when independently delegated authority replaces
    /// retiring-key cooperation.
    #[must_use]
    pub const fn successor_only(new: DeclaredSignature) -> Self {
        Self { old: None, new }
    }
}

impl RotationEvidence {
    /// Declares canonical evidence for one source-scoped key rotation.
    pub fn authenticated(
        context: RotationContext,
        signatures: RotationSignatures,
    ) -> Result<Self, RegistryError> {
        if signatures
            .old
            .as_ref()
            .is_some_and(|old| old.key() != &context.old_key)
            || signatures.new.key() != &context.new_key
        {
            return Err(RegistryError::RotationEvidenceInvalid {
                old_key: context.old_key,
                new_key: context.new_key,
                defect: RotationDefect::ContextMismatch,
            });
        }
        Ok(Self {
            source: context.source,
            scope: context.scope,
            declarer: context.declarer,
            old_key: context.old_key,
            new_key: context.new_key,
            old_signature: signatures.old,
            new_signature: signatures.new,
            effective_sequence: context.effective_sequence,
            effective_epoch: context.effective_epoch,
            overlap_end_epoch: context.overlap_end_epoch,
        })
    }

    /// Derives the canonical payload both signing keys must authenticate.
    #[must_use]
    pub fn payload(
        source: &SourceIdentity,
        scope: &AuthorityScope,
        declarer: &PublisherIdentity,
        old_key: &KeyId,
        new_key: &KeyId,
        timing: RotationTiming,
    ) -> [u8; 32] {
        digest_fields(
            ROTATION_DOMAIN,
            &[
                &source.digest()[..],
                scope.namespace().spelling().as_bytes(),
                scope
                    .package()
                    .map_or(b"".as_slice(), |package| package.spelling().as_bytes()),
                declarer.name().spelling().as_bytes(),
                declarer.key().as_str().as_bytes(),
                old_key.as_str().as_bytes(),
                new_key.as_str().as_bytes(),
                &timing.effective_sequence().to_be_bytes()[..],
                &timing.effective_epoch().to_be_bytes()[..],
                &timing.overlap_end_epoch().to_be_bytes()[..],
            ],
        )
    }

    /// Returns the canonical payload authenticated by both signatures.
    #[must_use]
    pub fn evidence_digest(&self) -> [u8; 32] {
        Self::payload(
            &self.source,
            &self.scope,
            &self.declarer,
            &self.old_key,
            &self.new_key,
            RotationTiming {
                effective_sequence: self.effective_sequence,
                effective_epoch: self.effective_epoch,
                overlap_end_epoch: self.overlap_end_epoch,
            },
        )
    }

    /// Returns the authenticated source this rotation governs.
    #[must_use]
    pub const fn source(&self) -> &SourceIdentity {
        &self.source
    }

    /// Returns the authority scope this rotation governs.
    #[must_use]
    pub const fn scope(&self) -> &AuthorityScope {
        &self.scope
    }

    /// Returns the retiring authority that declared this rotation.
    #[must_use]
    pub const fn declarer(&self) -> &PublisherIdentity {
        &self.declarer
    }

    /// Returns the retired key.
    #[must_use]
    pub const fn old_key(&self) -> &KeyId {
        &self.old_key
    }

    /// Returns the new key.
    #[must_use]
    pub const fn new_key(&self) -> &KeyId {
        &self.new_key
    }

    /// Returns the canonical rotation payload digest.
    #[must_use]
    pub fn payload_digest(&self) -> [u8; 32] {
        self.evidence_digest()
    }

    /// Returns the retired key's declared signature when it cooperated in the rotation.
    #[must_use]
    pub const fn old_signature(&self) -> Option<&DeclaredSignature> {
        self.old_signature.as_ref()
    }

    /// Returns the new key's declared signature.
    #[must_use]
    pub const fn new_signature(&self) -> &DeclaredSignature {
        &self.new_signature
    }

    /// Returns the sequence the rotation takes effect at.
    #[must_use]
    pub const fn effective_sequence(&self) -> u64 {
        self.effective_sequence
    }

    /// Returns the first declared epoch of the overlap window.
    #[must_use]
    pub const fn effective_epoch(&self) -> u64 {
        self.effective_epoch
    }

    /// Returns the exclusive declared epoch at which the retired key stops admitting.
    #[must_use]
    pub const fn overlap_end_epoch(&self) -> u64 {
        self.overlap_end_epoch
    }
}

/// One authority one key holds that contains one scope.
#[derive(Clone, Debug, Eq, PartialEq)]
struct Anchor {
    root: RootId,
    root_key: KeyId,
    ancestors: Vec<KeyId>,
    delegated: bool,
    scope: AuthorityScope,
    not_before_epoch: u64,
    expiry_epoch: u64,
    effective_sequence: u64,
}

/// One source-scoped authority decision requested at declared sequence and epoch.
#[derive(Clone, Copy, Debug)]
struct AuthorityQuery<'a> {
    source: &'a SourceIdentity,
    publisher: &'a PublisherIdentity,
    namespace: &'a RegistryName,
    package: &'a RegistryName,
    sequence: u64,
    epoch: u64,
    root_policy: Option<&'a RootSelectionPolicy>,
}

/// The explicit trust store of one workspace.
///
/// The store holds exactly the roots it is given, the delegations each root admits, the
/// declared key material, the declared rotations, and the declared compromises. There is no
/// ambient root, no fallback key, and no discovery path: a publisher that no root and no
/// delegation names is unauthorized, whatever else the store holds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustStore {
    roots: Vec<TrustRoot>,
    materials: BTreeMap<KeyId, [u8; 32]>,
    delegations: Vec<AdmittedDelegation>,
    rotations: Vec<RotationEvidence>,
    rotation_roots: BTreeMap<[u8; 32], Vec<RootId>>,
    compromises: Vec<Compromise>,
    compromise_roots: BTreeMap<[u8; 32], Vec<RootId>>,
}

impl TrustStore {
    /// Builds one trust store from explicit roots, key material, and delegations.
    ///
    /// A duplicate root identity or key identity is refused. A delegation is admitted only
    /// when its delegator already holds an authority that contains the delegated scope, and
    /// delegations are admitted in one declared order (by sequence, then delegator, then
    /// delegate), so a chain is admitted from its root outwards and a delegation that would
    /// widen the authority it derives from is refused as
    /// [`RegistryError::DelegationOutOfScope`] rather than narrowed silently.
    pub fn new(
        roots: &[TrustRoot],
        keys: &[KeyRecord],
        delegations: &[Delegation],
    ) -> Result<Self, RegistryError> {
        Self::new_with_root_selection(roots, keys, delegations, &RootSelectionPolicy::Unspecified)
    }

    /// Builds one trust store while explicitly selecting roots for initial delegations.
    ///
    /// Initial delegation construction evaluates exactly the supplied policy. This prevents
    /// an unordered initial delegation list from implicitly choosing one of several roots.
    pub fn new_with_root_selection(
        roots: &[TrustRoot],
        keys: &[KeyRecord],
        delegations: &[Delegation],
        root_policy: &RootSelectionPolicy,
    ) -> Result<Self, RegistryError> {
        let mut materials = BTreeMap::new();
        for key in keys {
            if materials
                .insert(key.key().clone(), key.material())
                .is_some()
            {
                return Err(RegistryError::DeclarationInvalid {
                    field: "key id",
                    value: Arc::from(key.key().as_str()),
                });
            }
        }
        for (index, root) in roots.iter().enumerate() {
            if roots[..index].iter().any(|other| other.id() == root.id()) {
                return Err(RegistryError::DeclarationInvalid {
                    field: "root id",
                    value: Arc::from(root.id().as_str()),
                });
            }
        }
        let mut store = Self {
            roots: roots.to_vec(),
            materials,
            delegations: Vec::new(),
            rotations: Vec::new(),
            rotation_roots: BTreeMap::new(),
            compromises: Vec::new(),
            compromise_roots: BTreeMap::new(),
        };
        let mut pending = delegations.to_vec();
        pending.sort_by(|left, right| {
            (
                left.effective_sequence(),
                left.delegator().key().as_str(),
                left.delegate().key().as_str(),
            )
                .cmp(&(
                    right.effective_sequence(),
                    right.delegator().key().as_str(),
                    right.delegate().key().as_str(),
                ))
        });
        while !pending.is_empty() {
            let admitted = pending.iter().position(|delegation| {
                store
                    .anchor_for(
                        delegation.source(),
                        delegation.delegator(),
                        delegation.scope(),
                        delegation.not_before_epoch(),
                        delegation.expiry_epoch(),
                        delegation.effective_sequence(),
                        root_policy,
                    )
                    .is_some()
            });
            let Some(index) = admitted else {
                return store
                    .admit_delegation_with_root_selection(pending.remove(0), root_policy)
                    .map(|()| store);
            };
            store.admit_delegation_with_root_selection(pending.remove(index), root_policy)?;
        }
        Ok(store)
    }

    /// Returns the explicit roots of this store, in declared order.
    #[must_use]
    pub fn roots(&self) -> &[TrustRoot] {
        &self.roots
    }

    /// Returns the admitted delegations, in admission order.
    #[must_use]
    pub fn delegations(&self) -> &[AdmittedDelegation] {
        &self.delegations
    }

    /// Returns the admitted rotations in canonical sealed-batch order.
    #[must_use]
    pub fn rotations(&self) -> &[RotationEvidence] {
        &self.rotations
    }

    /// Returns the recorded compromises, in recorded order.
    #[must_use]
    pub fn compromises(&self) -> &[Compromise] {
        &self.compromises
    }

    /// Returns the declared material of one key.
    #[must_use]
    pub fn material(&self, key: &KeyId) -> Option<[u8; 32]> {
        self.materials.get(key).copied()
    }

    /// Returns whether one declared signature verifies under the material of its key.
    ///
    /// A signature of a key whose material the store does not hold never verifies, so an
    /// unknown key is refused rather than trusted.
    #[must_use]
    pub fn verifies(&self, signature: &DeclaredSignature, payload: [u8; 32]) -> bool {
        match self.materials.get(signature.key()) {
            Some(material) => {
                signature_digest(signature.key(), material, payload) == signature.digest()
            }
            None => false,
        }
    }

    /// Returns whether one rotation fact was admitted under a root the current policy permits.
    fn rotation_fact_permitted(&self, digest: [u8; 32], root_policy: &RootSelectionPolicy) -> bool {
        self.rotation_roots
            .get(&digest)
            .is_some_and(|roots| roots.iter().any(|root| root_policy.permits(root)))
    }

    /// Returns whether one compromise fact was admitted under a root the current policy permits.
    fn compromise_fact_permitted(
        &self,
        digest: [u8; 32],
        root_policy: &RootSelectionPolicy,
    ) -> bool {
        self.compromise_roots
            .get(&digest)
            .is_some_and(|roots| roots.iter().any(|root| root_policy.permits(root)))
    }

    /// Adds one delegation, refusing one that would widen its delegator's authority.
    pub fn delegate(
        &mut self,
        declaration: &SourceDeclaration,
        delegation: Delegation,
    ) -> Result<(), RegistryRefusal> {
        self.delegate_with_root_selection(
            declaration,
            delegation,
            &RootSelectionPolicy::Unspecified,
        )
    }

    /// Adds one delegation under one explicit source-root policy.
    pub fn delegate_with_root_selection(
        &mut self,
        declaration: &SourceDeclaration,
        delegation: Delegation,
        root_policy: &RootSelectionPolicy,
    ) -> Result<(), RegistryRefusal> {
        if delegation.source() != declaration.identity() {
            return Err(declaration.refusal(RegistryError::SourceNotDeclared {
                requested: delegation.source().clone(),
            }));
        }
        self.validate_root_selection(declaration, delegation.source(), root_policy)?;
        self.admit_delegation_with_root_selection(delegation, root_policy)
            .map_err(|error| declaration.refusal(error))
    }

    /// Admits signed source-scoped evidence that revokes one authority.
    ///
    /// The declaring authority must already hold the affected source scope at the declared
    /// sequence, and its signature must verify over the complete evidence. A failed admission
    /// leaves the store unchanged, so an unauthenticated or cross-source compromise cannot
    /// revoke authority accidentally.
    pub fn compromise(
        &mut self,
        declaration: &SourceDeclaration,
        evidence: Compromise,
    ) -> Result<(), RegistryRefusal> {
        self.compromise_with_root_selection(
            declaration,
            evidence,
            &RootSelectionPolicy::Unspecified,
        )
    }

    /// Admits signed compromise evidence under one explicit source-root policy.
    pub fn compromise_with_root_selection(
        &mut self,
        declaration: &SourceDeclaration,
        evidence: Compromise,
        root_policy: &RootSelectionPolicy,
    ) -> Result<(), RegistryRefusal> {
        if evidence.source() != declaration.identity() {
            return Err(declaration.refusal(RegistryError::SourceNotDeclared {
                requested: evidence.source().clone(),
            }));
        }
        self.validate_root_selection(declaration, evidence.source(), root_policy)?;
        if !self.verifies(evidence.signature(), evidence.evidence_digest()) {
            return Err(declaration.refusal(RegistryError::SignatureUnverified {
                key: evidence.signature().key().clone(),
            }));
        }
        if let Some(rotation) = self.superseded_at(
            evidence.source(),
            evidence.scope(),
            evidence.declarer().key(),
            evidence.effective_sequence(),
            evidence.observation_epoch(),
            root_policy,
        ) {
            return Err(declaration.refusal(RegistryError::KeySuperseded {
                key: rotation.old_key().clone(),
                sequence: rotation.effective_sequence(),
            }));
        }
        let Some(root) = self.authorizes_compromise(&evidence, root_policy) else {
            return Err(declaration.refusal(RegistryError::PublisherUnauthorized {
                publisher: Arc::from(evidence.declarer().name().spelling()),
                key: evidence.declarer().key().clone(),
                defect: AuthorizationDefect::UnknownPublisher,
            }));
        };
        let digest = evidence.evidence_digest();
        self.compromises.push(evidence);
        let roots = self.compromise_roots.entry(digest).or_default();
        if !roots.contains(&root) {
            roots.push(root);
        }
        roots.sort();
        Ok(())
    }

    /// Atomically admits one finite, sealed set of rotations.
    ///
    /// Every complete evidence form is verified before equal contexts are deduplicated or any
    /// lifecycle fact is retained. Complete forms have a total canonical order, and invalid
    /// forms are aggregated by fixed verification precedence. Competing or backdated candidates
    /// therefore refuse the entire set rather than allowing its input order to choose an
    /// authoritative successor. A retiring-key signature is required unless the successor
    /// already holds independently delegated same-or-wider authority. The successor signature
    /// and material are always required, and a rotation whose retired key is already compromised
    /// at the rotation's own sequence is refused, so a compromise cannot be papered over by a
    /// rotation signed with the compromised key itself.
    pub fn rotate_batch(
        &mut self,
        declaration: &SourceDeclaration,
        evidence: &[RotationEvidence],
        keys: &[KeyRecord],
    ) -> Result<(), RegistryRefusal> {
        self.rotate_batch_with_root_selection(
            declaration,
            evidence,
            keys,
            &RootSelectionPolicy::Unspecified,
        )
    }

    /// Atomically admits one finite, sealed rotation set under one source-root policy.
    pub fn rotate_batch_with_root_selection(
        &mut self,
        declaration: &SourceDeclaration,
        evidence: &[RotationEvidence],
        keys: &[KeyRecord],
        root_policy: &RootSelectionPolicy,
    ) -> Result<(), RegistryRefusal> {
        let mut sealed = evidence.to_vec();
        sealed.sort_by(Self::canonical_rotation_order);
        for candidate in &sealed {
            Self::require_declared_source(declaration, candidate.source())?;
        }
        self.validate_root_selection(declaration, declaration.identity(), root_policy)?;
        if let Some((candidate, defect)) =
            self.sealed_rotation_signature_defect(&sealed, keys, root_policy)
        {
            return Err(declaration.refusal(RegistryError::RotationEvidenceInvalid {
                old_key: candidate.old_key().clone(),
                new_key: candidate.new_key().clone(),
                defect,
            }));
        }
        sealed.dedup_by(|left, right| left.evidence_digest() == right.evidence_digest());
        if let Some((candidate, defect)) = self.rotation_batch_admission_defect(&sealed) {
            return Err(declaration.refusal(RegistryError::RotationEvidenceInvalid {
                old_key: candidate.old_key().clone(),
                new_key: candidate.new_key().clone(),
                defect,
            }));
        }
        let mut staged = self.clone();
        for candidate in sealed {
            staged.rotate_sealed_with_root_selection(declaration, candidate, keys, root_policy)?;
        }
        staged.rotations.sort_by(Self::canonical_rotation_order);
        *self = staged;
        Ok(())
    }

    /// Returns the fixed-precedence signature defect in one sealed candidate set.
    ///
    /// Every candidate is examined before this returns. Ties use the complete evidence order,
    /// so a sealed set yields one refusal regardless of presentation order.
    fn sealed_rotation_signature_defect<'a>(
        &self,
        evidence: &'a [RotationEvidence],
        keys: &[KeyRecord],
        root_policy: &RootSelectionPolicy,
    ) -> Option<(&'a RotationEvidence, RotationDefect)> {
        evidence
            .iter()
            .filter_map(|candidate| {
                self.verify_sealed_rotation_signatures(candidate, keys, root_policy)
                    .err()
                    .map(|defect| (candidate, defect))
            })
            .min_by(|(left, left_defect), (right, right_defect)| {
                Self::sealed_rotation_defect_precedence(*left_defect)
                    .cmp(&Self::sealed_rotation_defect_precedence(*right_defect))
                    .then_with(|| Self::canonical_rotation_order(left, right))
            })
    }

    /// Verifies one complete signature form before sealed-context deduplication.
    ///
    /// The successor signature is mandatory. A retiring signature, when present, is also
    /// verified even when independent successor authority means it is not required for
    /// admission. When it is absent, independent successor authority is required. This boundary
    /// check cannot retain lifecycle facts and prevents a forged or incomplete duplicate from
    /// being discarded because it shares a signed context with a valid one.
    fn verify_sealed_rotation_signatures(
        &self,
        evidence: &RotationEvidence,
        keys: &[KeyRecord],
        root_policy: &RootSelectionPolicy,
    ) -> Result<(), RotationDefect> {
        let new_material = self.rotation_successor_material(evidence, keys)?;
        if evidence.new_signature().key() != evidence.new_key()
            || signature_digest(evidence.new_key(), &new_material, evidence.payload_digest())
                != evidence.new_signature().digest()
        {
            return Err(RotationDefect::NewKeyUnverified);
        }
        if let Some(old_signature) = evidence.old_signature() {
            let old_material = self
                .materials
                .get(evidence.old_key())
                .copied()
                .or_else(|| {
                    keys.iter()
                        .find(|record| record.key() == evidence.old_key())
                        .map(KeyRecord::material)
                })
                .ok_or(RotationDefect::OldKeyUnknown)?;
            if old_signature.key() != evidence.old_key()
                || signature_digest(evidence.old_key(), &old_material, evidence.payload_digest())
                    != old_signature.digest()
            {
                return Err(RotationDefect::OldKeyUnverified);
            }
        } else if self
            .authorizes_rotation_successor(evidence, root_policy)
            .is_none()
        {
            return Err(if self.materials.contains_key(evidence.old_key()) {
                RotationDefect::OldKeyUnverified
            } else {
                RotationDefect::OldKeyUnknown
            });
        }
        Ok(())
    }

    /// Validates and stages one member of an already sealed rotation set.
    fn rotate_sealed_with_root_selection(
        &mut self,
        declaration: &SourceDeclaration,
        evidence: RotationEvidence,
        keys: &[KeyRecord],
        root_policy: &RootSelectionPolicy,
    ) -> Result<(), RegistryRefusal> {
        Self::require_declared_source(declaration, evidence.source())?;
        self.validate_root_selection(declaration, evidence.source(), root_policy)?;
        let digest = evidence.evidence_digest();
        let already_admitted = self
            .rotations
            .iter()
            .any(|existing| existing.evidence_digest() == digest);
        if let Some(rotation) = self.superseded_at(
            evidence.source(),
            evidence.scope(),
            evidence.old_key(),
            evidence.effective_sequence(),
            evidence.effective_epoch(),
            root_policy,
        ) {
            return Err(declaration.refusal(RegistryError::KeySuperseded {
                key: rotation.old_key().clone(),
                sequence: rotation.effective_sequence(),
            }));
        }
        if !already_admitted
            && let Some(defect) = self.existing_rotation_admission_defect(&evidence)
        {
            return Err(declaration.refusal(RegistryError::RotationEvidenceInvalid {
                old_key: evidence.old_key().clone(),
                new_key: evidence.new_key().clone(),
                defect,
            }));
        }
        let successor_authority = self.authorizes_rotation_successor(&evidence, root_policy);
        let requires_old_cooperation = successor_authority.is_none();
        let Some(root) =
            successor_authority.or_else(|| self.authorizes_rotation(&evidence, root_policy))
        else {
            return Err(declaration.refusal(RegistryError::RotationEvidenceInvalid {
                old_key: evidence.old_key().clone(),
                new_key: evidence.new_key().clone(),
                defect: RotationDefect::ContextMismatch,
            }));
        };
        let new_material = match self.rotation_successor_material(&evidence, keys) {
            Ok(material) => material,
            Err(defect) => {
                return Err(declaration.refusal(RegistryError::RotationEvidenceInvalid {
                    old_key: evidence.old_key().clone(),
                    new_key: evidence.new_key().clone(),
                    defect,
                }));
            }
        };
        if requires_old_cooperation {
            let Some(old_material) = self.materials.get(evidence.old_key()).copied() else {
                return Err(declaration.refusal(RegistryError::RotationEvidenceInvalid {
                    old_key: evidence.old_key().clone(),
                    new_key: evidence.new_key().clone(),
                    defect: RotationDefect::OldKeyUnknown,
                }));
            };
            let Some(old_signature) = evidence.old_signature() else {
                return Err(declaration.refusal(RegistryError::RotationEvidenceInvalid {
                    old_key: evidence.old_key().clone(),
                    new_key: evidence.new_key().clone(),
                    defect: RotationDefect::OldKeyUnverified,
                }));
            };
            if old_signature.key() != evidence.old_key()
                || signature_digest(evidence.old_key(), &old_material, evidence.payload_digest())
                    != old_signature.digest()
            {
                return Err(declaration.refusal(RegistryError::RotationEvidenceInvalid {
                    old_key: evidence.old_key().clone(),
                    new_key: evidence.new_key().clone(),
                    defect: RotationDefect::OldKeyUnverified,
                }));
            }
        }
        if evidence.new_signature().key() != evidence.new_key()
            || signature_digest(evidence.new_key(), &new_material, evidence.payload_digest())
                != evidence.new_signature().digest()
        {
            return Err(declaration.refusal(RegistryError::RotationEvidenceInvalid {
                old_key: evidence.old_key().clone(),
                new_key: evidence.new_key().clone(),
                defect: RotationDefect::NewKeyUnverified,
            }));
        }
        if let Some(compromise) = self.revoked_for_scope(
            evidence.source(),
            evidence.scope(),
            evidence.old_key(),
            evidence.effective_sequence(),
            root_policy,
        ) {
            return Err(declaration.refusal(RegistryError::KeyCompromised {
                key: compromise.key().clone(),
                sequence: compromise.effective_sequence(),
            }));
        }
        let mut materials = self.materials.clone();
        materials
            .entry(evidence.new_key().clone())
            .or_insert(new_material);
        let mut rotations = self.rotations.clone();
        if !already_admitted {
            rotations.push(evidence);
        }
        let mut rotation_roots = self.rotation_roots.clone();
        let roots = rotation_roots.entry(digest).or_default();
        if !roots.contains(&root) {
            roots.push(root);
        }
        roots.sort();
        self.materials = materials;
        self.rotations = rotations;
        self.rotation_roots = rotation_roots;
        Ok(())
    }

    /// Returns the one canonical successor material or the conflict that prevents rotation.
    fn rotation_successor_material(
        &self,
        evidence: &RotationEvidence,
        keys: &[KeyRecord],
    ) -> Result<[u8; 32], RotationDefect> {
        let supplied = keys
            .iter()
            .filter(|record| record.key() == evidence.new_key())
            .map(KeyRecord::material)
            .collect::<Vec<_>>();
        let supplied_material = supplied.first().copied();
        if supplied_material.is_some_and(|material| supplied.iter().any(|other| *other != material))
        {
            return Err(RotationDefect::SuccessorMaterialConflict);
        }
        let stored_material = self.materials.get(evidence.new_key()).copied();
        if let (Some(stored), Some(supplied)) = (stored_material, supplied_material)
            && stored != supplied
        {
            return Err(RotationDefect::SuccessorMaterialConflict);
        }
        stored_material
            .or(supplied_material)
            .ok_or(RotationDefect::NewKeyUnknown)
    }

    /// Returns the order in which sealed-boundary signature defects take precedence.
    ///
    /// This preserves the per-candidate verification order while making a batch that contains
    /// several invalid forms independent of its candidate order.
    const fn sealed_rotation_defect_precedence(defect: RotationDefect) -> u8 {
        match defect {
            RotationDefect::SuccessorMaterialConflict => 0,
            RotationDefect::NewKeyUnknown => 1,
            RotationDefect::NewKeyUnverified => 2,
            RotationDefect::OldKeyUnknown => 3,
            RotationDefect::OldKeyUnverified => 4,
            RotationDefect::ContextMismatch => 5,
            RotationDefect::ConflictingSuccessor => 6,
            RotationDefect::Backdated => 7,
        }
    }

    /// Returns the first canonical lifecycle conflict in one sealed rotation set.
    fn rotation_batch_admission_defect<'a>(
        &self,
        evidence: &'a [RotationEvidence],
    ) -> Option<(&'a RotationEvidence, RotationDefect)> {
        for (index, candidate) in evidence.iter().enumerate() {
            for competing in &evidence[index + 1..] {
                if let Some(defect) = Self::rotation_conflict(candidate, competing) {
                    return Some((candidate, defect));
                }
            }
        }
        None
    }

    /// Returns the lifecycle conflict with already retained facts after supersession is checked.
    fn existing_rotation_admission_defect(
        &self,
        evidence: &RotationEvidence,
    ) -> Option<RotationDefect> {
        self.rotations.iter().find_map(|existing| {
            (existing.evidence_digest() != evidence.evidence_digest())
                .then(|| Self::rotation_conflict(existing, evidence))
                .flatten()
        })
    }

    /// Classifies one symmetric lifecycle conflict without selecting either record.
    fn rotation_conflict(
        left: &RotationEvidence,
        right: &RotationEvidence,
    ) -> Option<RotationDefect> {
        if left.source() != right.source() || !left.scope().overlaps(right.scope()) {
            return None;
        }
        if left.old_key() == right.old_key() {
            return if left.new_key() == right.new_key()
                && left.effective_sequence() != right.effective_sequence()
            {
                Some(RotationDefect::Backdated)
            } else {
                Some(RotationDefect::ConflictingSuccessor)
            };
        }
        (left.new_key() == right.new_key()).then_some(RotationDefect::ConflictingSuccessor)
    }

    /// Orders complete lifecycle evidence independently of presentation or iteration order.
    fn canonical_rotation_order(
        left: &RotationEvidence,
        right: &RotationEvidence,
    ) -> std::cmp::Ordering {
        left.effective_sequence()
            .cmp(&right.effective_sequence())
            .then_with(|| left.effective_epoch().cmp(&right.effective_epoch()))
            .then_with(|| left.overlap_end_epoch().cmp(&right.overlap_end_epoch()))
            .then_with(|| left.evidence_digest().cmp(&right.evidence_digest()))
            .then_with(|| {
                left.old_signature()
                    .is_some()
                    .cmp(&right.old_signature().is_some())
            })
            .then_with(|| {
                left.old_signature()
                    .map(|signature| signature.key().as_str())
                    .cmp(
                        &right
                            .old_signature()
                            .map(|signature| signature.key().as_str()),
                    )
            })
            .then_with(|| {
                left.old_signature()
                    .map(DeclaredSignature::digest)
                    .cmp(&right.old_signature().map(DeclaredSignature::digest))
            })
            .then_with(|| {
                left.new_signature()
                    .key()
                    .as_str()
                    .cmp(right.new_signature().key().as_str())
            })
            .then_with(|| {
                left.new_signature()
                    .digest()
                    .cmp(&right.new_signature().digest())
            })
    }

    /// Returns the authority that authorizes one entry's publisher at one sequence.
    ///
    /// This compatibility entry point treats the explicit sequence as the observation epoch.
    /// Snapshot verification uses [`Self::authorize_at`] with the snapshot's declared epoch.
    pub fn authorize(
        &self,
        declaration: &SourceDeclaration,
        entry: &SnapshotEntry,
        sequence: u64,
    ) -> Result<AuthorityGrant, RegistryRefusal> {
        self.authorize_with_root_selection(
            declaration,
            entry,
            sequence,
            &RootSelectionPolicy::Unspecified,
        )
    }

    /// Returns the authority for one entry under one explicit source-root policy.
    pub fn authorize_with_root_selection(
        &self,
        declaration: &SourceDeclaration,
        entry: &SnapshotEntry,
        sequence: u64,
        root_policy: &RootSelectionPolicy,
    ) -> Result<AuthorityGrant, RegistryRefusal> {
        self.authorize_at(declaration, entry, sequence, sequence, Some(root_policy))
    }

    /// Returns the authority that authorizes one entry at its declared observation epoch.
    fn authorize_at(
        &self,
        declaration: &SourceDeclaration,
        entry: &SnapshotEntry,
        sequence: u64,
        epoch: u64,
        root_policy: Option<&RootSelectionPolicy>,
    ) -> Result<AuthorityGrant, RegistryRefusal> {
        self.authorize_coordinates_at(
            declaration,
            AuthorityQuery {
                source: entry.source(),
                publisher: entry.publisher(),
                namespace: entry.namespace(),
                package: entry.package(),
                sequence,
                epoch,
                root_policy,
            },
        )
    }

    /// Returns the authority that authorizes one publisher at one coordinate pair.
    ///
    /// The decision reads only declared roots, admitted delegations, declared rotations, and
    /// recorded compromises. A compromised or superseded publisher key is refused as
    /// [`RegistryError::KeyCompromised`] or [`RegistryError::KeySuperseded`]; a publisher no
    /// root and no delegation names is refused as [`RegistryError::PublisherUnauthorized`];
    /// and a named publisher whose authority does not cover the coordinates is refused as
    /// [`RegistryError::DelegationOutOfScope`].
    pub fn authorize_coordinates(
        &self,
        declaration: &SourceDeclaration,
        source: &SourceIdentity,
        publisher: &PublisherIdentity,
        namespace: &RegistryName,
        package: &RegistryName,
        sequence: u64,
    ) -> Result<AuthorityGrant, RegistryRefusal> {
        self.authorize_coordinates_with_root_selection(
            declaration,
            source,
            publisher,
            namespace,
            package,
            sequence,
            &RootSelectionPolicy::Unspecified,
        )
    }

    /// Returns source-scoped authority under one explicit root-selection policy.
    #[allow(clippy::too_many_arguments)]
    pub fn authorize_coordinates_with_root_selection(
        &self,
        declaration: &SourceDeclaration,
        source: &SourceIdentity,
        publisher: &PublisherIdentity,
        namespace: &RegistryName,
        package: &RegistryName,
        sequence: u64,
        root_policy: &RootSelectionPolicy,
    ) -> Result<AuthorityGrant, RegistryRefusal> {
        self.authorize_coordinates_at(
            declaration,
            AuthorityQuery {
                source,
                publisher,
                namespace,
                package,
                sequence,
                epoch: sequence,
                root_policy: Some(root_policy),
            },
        )
    }

    /// Returns source-scoped authority at one explicit epoch and sequence.
    fn authorize_coordinates_at(
        &self,
        declaration: &SourceDeclaration,
        query: AuthorityQuery<'_>,
    ) -> Result<AuthorityGrant, RegistryRefusal> {
        Self::require_declared_source(declaration, query.source)?;
        let unspecified = RootSelectionPolicy::Unspecified;
        let root_policy = query.root_policy.unwrap_or(&unspecified);
        let roots = self
            .roots
            .iter()
            .filter(|root| root.source() == query.source)
            .collect::<Vec<_>>();
        root_policy
            .validate_for(query.source, &roots)
            .map_err(|error| declaration.refusal(error))?;
        let requested_scope = AuthorityScope::of(query.namespace, query.package);
        let chain = self.authority_chain(
            query.source,
            &requested_scope,
            query.publisher.key(),
            query.sequence,
            query.epoch,
            root_policy,
        );
        if let Some(compromise) = chain.iter().find_map(|key| {
            self.revoked_at(
                query.source,
                query.namespace,
                query.package,
                key,
                query.sequence,
                root_policy,
            )
        }) {
            return Err(declaration.refusal(RegistryError::KeyCompromised {
                key: compromise.key().clone(),
                sequence: compromise.effective_sequence(),
            }));
        }
        if let Some(rotation) = self.superseded_at(
            query.source,
            &requested_scope,
            query.publisher.key(),
            query.sequence,
            query.epoch,
            root_policy,
        ) {
            return Err(declaration.refusal(RegistryError::KeySuperseded {
                key: rotation.old_key().clone(),
                sequence: rotation.effective_sequence(),
            }));
        }
        let mut found: Option<AuthorityScope> = None;
        let mut inactive: Option<KeyId> = None;
        let mut revoked: Option<KeyId> = None;
        for key in &chain {
            for root in &self.roots {
                if root.source() != query.source
                    || root.publisher().name() != query.publisher.name()
                    || root.publisher().key() != key
                    || !root_policy.permits(root.id())
                {
                    continue;
                }
                if root.scope().covers(query.namespace, query.package) {
                    return Ok(AuthorityGrant {
                        root: root.id().clone(),
                        root_key: root.publisher().key().clone(),
                        authorized_by: query.publisher.key().clone(),
                        inherited_from: (key != query.publisher.key()).then(|| key.clone()),
                        delegated: false,
                        scope: root.scope().clone(),
                    });
                }
                found = Some(root.scope().clone());
            }
            for admitted in &self.delegations {
                if admitted.delegation().source() != query.source
                    || admitted.delegation().delegate().name() != query.publisher.name()
                    || admitted.delegation().delegate().key() != key
                    || !root_policy.permits(admitted.root())
                {
                    continue;
                }
                if !admitted.delegation().active_at(query.epoch, query.sequence) {
                    inactive = Some(key.clone());
                    continue;
                }
                if let Some(replacement) = self.chain_revoked(
                    admitted,
                    query.source,
                    query.namespace,
                    query.package,
                    query.sequence,
                    root_policy,
                ) {
                    revoked = Some(replacement);
                    continue;
                }
                if admitted
                    .delegation()
                    .scope()
                    .covers(query.namespace, query.package)
                {
                    return Ok(AuthorityGrant {
                        root: admitted.root().clone(),
                        root_key: admitted.root_key().clone(),
                        authorized_by: query.publisher.key().clone(),
                        inherited_from: (key != query.publisher.key()).then(|| key.clone()),
                        delegated: true,
                        scope: admitted.delegation().scope().clone(),
                    });
                }
                found = Some(admitted.delegation().scope().clone());
            }
        }
        if let Some(key) = revoked {
            return Err(declaration.refusal(RegistryError::KeyCompromised {
                key,
                sequence: query.sequence,
            }));
        }
        if let Some(key) = inactive {
            return Err(
                declaration.refusal(RegistryError::DelegationNotCurrentlyValid {
                    key,
                    sequence: query.sequence,
                    epoch: query.epoch,
                }),
            );
        }
        match found {
            Some(authority) => Err(declaration.refusal(RegistryError::DelegationOutOfScope {
                key: query.publisher.key().clone(),
                authority: Some(authority),
                declared: AuthorityScope::of(query.namespace, query.package),
            })),
            None => Err(declaration.refusal(RegistryError::PublisherUnauthorized {
                publisher: Arc::from(query.publisher.name().spelling()),
                key: query.publisher.key().clone(),
                defect: AuthorizationDefect::UnknownPublisher,
            })),
        }
    }

    /// Validates one lifecycle decision against its declared source-root policy.
    fn validate_root_selection(
        &self,
        declaration: &SourceDeclaration,
        source: &SourceIdentity,
        root_policy: &RootSelectionPolicy,
    ) -> Result<(), RegistryRefusal> {
        let roots = self
            .roots
            .iter()
            .filter(|root| root.source() == source)
            .collect::<Vec<_>>();
        root_policy
            .validate_for(source, &roots)
            .map_err(|error| declaration.refusal(error))
    }

    /// Refuses an authority decision whose presented source differs from its declaration.
    fn require_declared_source(
        declaration: &SourceDeclaration,
        source: &SourceIdentity,
    ) -> Result<(), RegistryRefusal> {
        if source != declaration.identity() {
            return Err(declaration.refusal(RegistryError::SourceNotDeclared {
                requested: source.clone(),
            }));
        }
        Ok(())
    }

    /// Admits one delegation into this store, or reports the widening it would perform.
    /// Admits one delegation under the declared source-root policy.
    fn admit_delegation_with_root_selection(
        &mut self,
        delegation: Delegation,
        root_policy: &RootSelectionPolicy,
    ) -> Result<(), RegistryError> {
        let roots = self
            .roots
            .iter()
            .filter(|root| root.source() == delegation.source())
            .collect::<Vec<_>>();
        root_policy.validate_for(delegation.source(), &roots)?;
        if !self.verifies(delegation.signature(), delegation.evidence_digest()) {
            return Err(RegistryError::SignatureUnverified {
                key: delegation.signature().key().clone(),
            });
        }
        if let Some(rotation) = self.retired_for_new_delegation(&delegation, &[], root_policy) {
            return Err(RegistryError::KeySuperseded {
                key: rotation.old_key().clone(),
                sequence: rotation.effective_sequence(),
            });
        }
        match self.anchor_for(
            delegation.source(),
            delegation.delegator(),
            delegation.scope(),
            delegation.not_before_epoch(),
            delegation.expiry_epoch(),
            delegation.effective_sequence(),
            root_policy,
        ) {
            Some(anchor) => {
                if anchor
                    .ancestors
                    .iter()
                    .any(|key| key == delegation.delegate().key())
                {
                    return Err(RegistryError::DelegationChainIncomplete {
                        key: delegation.delegate().key().clone(),
                    });
                }
                if anchor.delegated
                    && let Some(rotation) =
                        self.retired_for_new_delegation(&delegation, &anchor.ancestors, root_policy)
                {
                    return Err(RegistryError::KeySuperseded {
                        key: rotation.old_key().clone(),
                        sequence: rotation.effective_sequence(),
                    });
                }
                self.delegations.push(AdmittedDelegation {
                    delegation,
                    root: anchor.root,
                    root_key: anchor.root_key,
                    ancestors: anchor.ancestors,
                });
                Ok(())
            }
            None => match self.any_scope(delegation.delegator()) {
                Some(authority) => Err(RegistryError::DelegationOutOfScope {
                    key: delegation.delegator().key().clone(),
                    authority: Some(authority),
                    declared: delegation.scope().clone(),
                }),
                None => Err(RegistryError::DelegationChainIncomplete {
                    key: delegation.delegator().key().clone(),
                }),
            },
        }
    }

    /// Returns the authority one key holds that contains one scope.
    #[allow(clippy::too_many_arguments)]
    fn anchor_for(
        &self,
        source: &SourceIdentity,
        publisher: &PublisherIdentity,
        scope: &AuthorityScope,
        not_before_epoch: u64,
        expiry_epoch: u64,
        effective_sequence: u64,
        root_policy: &RootSelectionPolicy,
    ) -> Option<Anchor> {
        let inherited = self.authority_chain(
            source,
            scope,
            publisher.key(),
            effective_sequence,
            not_before_epoch,
            root_policy,
        );
        for root in &self.roots {
            if root.source() != source
                || root.publisher().name() != publisher.name()
                || !inherited.contains(root.publisher().key())
                || !root.scope().contains(scope)
                || !root_policy.permits(root.id())
            {
                continue;
            }
            let mut ancestors = inherited.clone();
            ancestors.reverse();
            return Some(Anchor {
                root: root.id().clone(),
                root_key: root.publisher().key().clone(),
                ancestors,
                delegated: false,
                scope: root.scope().clone(),
                not_before_epoch: 0,
                expiry_epoch: u64::MAX,
                effective_sequence: 0,
            });
        }
        for admitted in &self.delegations {
            let parent = admitted.delegation();
            if parent.source() == source
                && parent.delegate().name() == publisher.name()
                && inherited.contains(parent.delegate().key())
                && parent.scope().contains(scope)
                && root_policy.permits(admitted.root())
                && parent.not_before_epoch() <= not_before_epoch
                && expiry_epoch <= parent.expiry_epoch()
                && parent.effective_sequence() <= effective_sequence
            {
                let mut ancestors = admitted.ancestors().to_vec();
                for key in inherited.iter().rev() {
                    if !ancestors.contains(key) {
                        ancestors.push(key.clone());
                    }
                }
                return Some(Anchor {
                    root: admitted.root().clone(),
                    root_key: admitted.root_key().clone(),
                    ancestors,
                    delegated: true,
                    scope: parent.scope().clone(),
                    not_before_epoch: parent.not_before_epoch(),
                    expiry_epoch: parent.expiry_epoch(),
                    effective_sequence: parent.effective_sequence(),
                });
            }
        }
        None
    }

    /// Returns one authority scope one key holds, when it holds any.
    fn any_scope(&self, publisher: &PublisherIdentity) -> Option<AuthorityScope> {
        for root in &self.roots {
            if root.publisher() == publisher {
                return Some(root.scope().clone());
            }
        }
        for admitted in &self.delegations {
            if admitted.delegation().delegate() == publisher {
                return Some(admitted.delegation().scope().clone());
            }
        }
        None
    }

    /// Returns any retained compromise that covers one source coordinate.
    fn revoked_at(
        &self,
        source: &SourceIdentity,
        namespace: &RegistryName,
        package: &RegistryName,
        key: &KeyId,
        _sequence: u64,
        root_policy: &RootSelectionPolicy,
    ) -> Option<&Compromise> {
        self.compromises.iter().find(|compromise| {
            compromise.key() == key
                && compromise.source() == source
                && compromise.scope().covers(namespace, package)
                && self.compromise_fact_permitted(compromise.evidence_digest(), root_policy)
        })
    }

    /// Returns any retained compromise that revokes one authority scope.
    fn revoked_for_scope(
        &self,
        source: &SourceIdentity,
        scope: &AuthorityScope,
        key: &KeyId,
        _sequence: u64,
        root_policy: &RootSelectionPolicy,
    ) -> Option<&Compromise> {
        self.compromises.iter().find(|compromise| {
            compromise.key() == key
                && compromise.source() == source
                && compromise.scope().contains(scope)
                && self.compromise_fact_permitted(compromise.evidence_digest(), root_policy)
        })
    }

    /// Returns the rotation that superseded one key for one source authority scope.
    fn superseded_at(
        &self,
        source: &SourceIdentity,
        scope: &AuthorityScope,
        key: &KeyId,
        sequence: u64,
        epoch: u64,
        root_policy: &RootSelectionPolicy,
    ) -> Option<&RotationEvidence> {
        self.rotations.iter().find(|rotation| {
            rotation.source() == source
                && rotation.scope().contains(scope)
                && rotation.old_key() == key
                && rotation.effective_sequence() <= sequence
                && rotation.overlap_end_epoch() <= epoch
                && self.rotation_fact_permitted(rotation.evidence_digest(), root_policy)
        })
    }

    /// Returns a stored retirement that prevents a new delegation from reusing its authority.
    ///
    /// Admission is a current lifecycle decision. A delegation presented after a retirement
    /// cannot revive the retired key by backdating its validity coordinates or widening from a
    /// retired package to its namespace. Delegations admitted before the retirement remain in
    /// the store and are evaluated as their recorded chains.
    fn retired_for_new_delegation(
        &self,
        delegation: &Delegation,
        ancestors: &[KeyId],
        root_policy: &RootSelectionPolicy,
    ) -> Option<&RotationEvidence> {
        self.rotations.iter().find(|rotation| {
            rotation.source() == delegation.source()
                && (ancestors.contains(rotation.old_key())
                    || rotation.old_key() == delegation.delegator().key())
                && rotation.scope().overlaps(delegation.scope())
                && self.rotation_fact_permitted(rotation.evidence_digest(), root_policy)
        })
    }

    /// Returns one key and the retired keys whose source-scoped authority it inherited.
    ///
    /// The chain walks rotations backwards, from the most recent successor to the retired keys
    /// it replaced, and includes only the rotations already in effect at one sequence, so a key
    /// never inherits authority from a rotation that has not taken effect yet and a retired key
    /// never inherits authority from its own successor.
    fn authority_chain(
        &self,
        source: &SourceIdentity,
        scope: &AuthorityScope,
        key: &KeyId,
        sequence: u64,
        epoch: u64,
        root_policy: &RootSelectionPolicy,
    ) -> Vec<KeyId> {
        let mut chain = vec![key.clone()];
        let mut current = key.clone();
        loop {
            let retired = self
                .rotations
                .iter()
                .find(|rotation| {
                    rotation.source() == source
                        && rotation.scope().contains(scope)
                        && rotation.new_key() == &current
                        && rotation.effective_sequence() <= sequence
                        && rotation.effective_epoch() <= epoch
                        && self.rotation_fact_permitted(rotation.evidence_digest(), root_policy)
                })
                .map(|rotation| rotation.old_key().clone());
            match retired {
                Some(retired) if !chain.contains(&retired) => {
                    chain.push(retired.clone());
                    current = retired;
                }
                _ => return chain,
            }
        }
    }

    /// Returns the root that authorizes one rotation declarer for its complete overlap window.
    fn authorizes_rotation(
        &self,
        evidence: &RotationEvidence,
        root_policy: &RootSelectionPolicy,
    ) -> Option<RootId> {
        let chain = self.authority_chain(
            evidence.source(),
            evidence.scope(),
            evidence.declarer().key(),
            evidence.effective_sequence(),
            evidence.effective_epoch(),
            root_policy,
        );
        if chain.iter().any(|key| {
            self.revoked_for_scope(
                evidence.source(),
                evidence.scope(),
                key,
                evidence.effective_sequence(),
                root_policy,
            )
            .is_some()
        }) {
            return None;
        }
        chain.iter().find_map(|key| {
            self.roots
                .iter()
                .find(|root| {
                    root.source() == evidence.source()
                        && root.publisher().name() == evidence.declarer().name()
                        && root.publisher().key() == key
                        && root.scope().contains(evidence.scope())
                        && root_policy.permits(root.id())
                })
                .map(|root| root.id().clone())
                .or_else(|| {
                    self.delegations
                        .iter()
                        .find(|admitted| {
                            let delegation = admitted.delegation();
                            delegation.source() == evidence.source()
                                && delegation.delegate().name() == evidence.declarer().name()
                                && delegation.delegate().key() == key
                                && delegation.scope().contains(evidence.scope())
                                && root_policy.permits(admitted.root())
                                && delegation.active_at(
                                    evidence.effective_epoch(),
                                    evidence.effective_sequence(),
                                )
                                && evidence.overlap_end_epoch() <= delegation.expiry_epoch()
                                && self
                                    .chain_revoked_for_scope(
                                        admitted,
                                        evidence.source(),
                                        evidence.scope(),
                                        evidence.effective_sequence(),
                                        root_policy,
                                    )
                                    .is_none()
                        })
                        .map(|admitted| admitted.root().clone())
                })
        })
    }

    /// Returns the root that independently authorizes a rotation successor.
    ///
    /// A successor already delegated from the selected root over the same scope or a wider
    /// one is an alternative to deriving its authority solely from the retiring key. The
    /// rotation still requires successor signature and material; this only selects the root
    /// whose authority admits the lifecycle fact.
    fn authorizes_rotation_successor(
        &self,
        evidence: &RotationEvidence,
        root_policy: &RootSelectionPolicy,
    ) -> Option<RootId> {
        self.roots
            .iter()
            .find(|root| {
                root.source() == evidence.source()
                    && root.publisher().name() == evidence.declarer().name()
                    && root.publisher().key() == evidence.new_key()
                    && root.scope().contains(evidence.scope())
                    && root_policy.permits(root.id())
            })
            .map(|root| root.id().clone())
            .or_else(|| {
                self.delegations
                    .iter()
                    .find(|admitted| {
                        let delegation = admitted.delegation();
                        delegation.source() == evidence.source()
                            && delegation.delegate().name() == evidence.declarer().name()
                            && delegation.delegate().key() == evidence.new_key()
                            && delegation.scope().contains(evidence.scope())
                            && root_policy.permits(admitted.root())
                            && delegation.active_at(
                                evidence.effective_epoch(),
                                evidence.effective_sequence(),
                            )
                            && evidence.overlap_end_epoch() <= delegation.expiry_epoch()
                            && self
                                .chain_revoked_for_scope(
                                    admitted,
                                    evidence.source(),
                                    evidence.scope(),
                                    evidence.effective_sequence(),
                                    root_policy,
                                )
                                .is_none()
                    })
                    .map(|admitted| admitted.root().clone())
            })
    }

    /// Returns the root that authorizes one compromise at its declared observation epoch.
    fn authorizes_compromise(
        &self,
        evidence: &Compromise,
        root_policy: &RootSelectionPolicy,
    ) -> Option<RootId> {
        if self
            .superseded_at(
                evidence.source(),
                evidence.scope(),
                evidence.declarer().key(),
                evidence.effective_sequence(),
                evidence.observation_epoch(),
                root_policy,
            )
            .is_some()
        {
            return None;
        }
        let chain = self.authority_chain(
            evidence.source(),
            evidence.scope(),
            evidence.declarer().key(),
            evidence.effective_sequence(),
            evidence.observation_epoch(),
            root_policy,
        );
        if chain.iter().any(|key| {
            self.revoked_for_scope(
                evidence.source(),
                evidence.scope(),
                key,
                evidence.effective_sequence(),
                root_policy,
            )
            .is_some()
        }) {
            return None;
        }
        chain.iter().find_map(|key| {
            self.roots
                .iter()
                .find(|root| {
                    root.source() == evidence.source()
                        && root.publisher().name() == evidence.declarer().name()
                        && root.publisher().key() == key
                        && root.scope().contains(evidence.scope())
                        && root_policy.permits(root.id())
                })
                .map(|root| root.id().clone())
                .or_else(|| {
                    self.delegations
                        .iter()
                        .find(|admitted| {
                            let delegation = admitted.delegation();
                            delegation.source() == evidence.source()
                                && delegation.delegate().name() == evidence.declarer().name()
                                && delegation.delegate().key() == key
                                && delegation.scope().contains(evidence.scope())
                                && root_policy.permits(admitted.root())
                                && delegation.active_at(
                                    evidence.observation_epoch(),
                                    evidence.effective_sequence(),
                                )
                                && self
                                    .chain_revoked_for_scope(
                                        admitted,
                                        evidence.source(),
                                        evidence.scope(),
                                        evidence.effective_sequence(),
                                        root_policy,
                                    )
                                    .is_none()
                        })
                        .map(|admitted| admitted.root().clone())
                })
        })
    }

    /// Returns the first compromised key of a delegation chain at one source coordinate.
    fn chain_revoked(
        &self,
        admitted: &AdmittedDelegation,
        source: &SourceIdentity,
        namespace: &RegistryName,
        package: &RegistryName,
        sequence: u64,
        root_policy: &RootSelectionPolicy,
    ) -> Option<KeyId> {
        admitted.ancestors().iter().find_map(|key| {
            self.revoked_at(source, namespace, package, key, sequence, root_policy)
                .map(|compromise| compromise.key().clone())
        })
    }

    /// Returns the first compromised key of a delegation chain over one authority scope.
    fn chain_revoked_for_scope(
        &self,
        admitted: &AdmittedDelegation,
        source: &SourceIdentity,
        scope: &AuthorityScope,
        sequence: u64,
        root_policy: &RootSelectionPolicy,
    ) -> Option<KeyId> {
        admitted.ancestors().iter().find_map(|key| {
            self.revoked_for_scope(source, scope, key, sequence, root_policy)
                .map(|compromise| compromise.key().clone())
        })
    }
}

/// The authority that admitted one publisher, entry, or advisory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityGrant {
    root: RootId,
    root_key: KeyId,
    authorized_by: KeyId,
    inherited_from: Option<KeyId>,
    delegated: bool,
    scope: AuthorityScope,
}

impl AuthorityGrant {
    /// Returns the anchoring root identity.
    #[must_use]
    pub const fn root(&self) -> &RootId {
        &self.root
    }

    /// Returns the anchoring root key.
    #[must_use]
    pub const fn root_key(&self) -> &KeyId {
        &self.root_key
    }

    /// Returns the key that signed the admitted publication.
    #[must_use]
    pub const fn authorized_by(&self) -> &KeyId {
        &self.authorized_by
    }

    /// Returns the retired key whose authority this grant inherited, when any.
    #[must_use]
    pub const fn inherited_from(&self) -> Option<&KeyId> {
        self.inherited_from.as_ref()
    }

    /// Returns whether this grant inherits the authority of a retired key.
    #[must_use]
    pub const fn is_inherited(&self) -> bool {
        self.inherited_from.is_some()
    }

    /// Returns the authority scope that admitted the publication.
    #[must_use]
    pub const fn scope(&self) -> &AuthorityScope {
        &self.scope
    }

    /// Returns whether a delegation rather than the root itself authorized this grant.
    #[must_use]
    pub const fn is_delegated(&self) -> bool {
        self.delegated
    }
}

/// One explicitly supplied epoch observation.
///
/// The epoch is a declared input, never a clock reading: freshness is decided over this
/// value and one declared expiry bound alone.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct EpochObservation {
    epoch: u64,
    present: bool,
}

impl EpochObservation {
    /// Observes one declared epoch.
    #[must_use]
    pub const fn at(epoch: u64) -> Self {
        Self {
            epoch,
            present: true,
        }
    }

    /// Deliberately omits the instant required for a freshness decision.
    #[must_use]
    pub const fn missing() -> Self {
        Self {
            epoch: 0,
            present: false,
        }
    }

    /// Returns the observed epoch.
    #[must_use]
    pub const fn epoch(self) -> u64 {
        self.epoch
    }

    /// Returns whether this observation carries its required declared instant.
    #[must_use]
    pub const fn is_present(self) -> bool {
        self.present
    }
}

/// One non-forgeable witness of a source snapshot verified before offline use.
///
/// This evidence is minted only by [`VerifiedSnapshot::offline_witness`]. It binds one source,
/// snapshot identity, sequence, and declared offline expiry, so offline verification cannot
/// manufacture a pin for a snapshot or source that did not previously verify.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OfflineSnapshotWitness {
    source: SourceIdentity,
    snapshot: SnapshotIdentity,
    sequence: u64,
    pin_expiry_epoch: u64,
}

impl OfflineSnapshotWitness {
    /// Returns the source this previously verified witness admits.
    #[must_use]
    pub const fn source(&self) -> &SourceIdentity {
        &self.source
    }

    /// Returns the authenticated snapshot identity this witness admits.
    #[must_use]
    pub const fn snapshot(&self) -> SnapshotIdentity {
        self.snapshot
    }

    /// Returns the verified snapshot sequence this witness admits.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the declared inclusive offline expiry bound.
    #[must_use]
    pub const fn pin_expiry_epoch(&self) -> u64 {
        self.pin_expiry_epoch
    }
}

/// One freshness mode of `GNT-27.6-expiry-and-freshness`.
///
/// An online check is bounded by the snapshot's own declared expiry. An offline check requires
/// a prior verified source-scoped witness, reports age from the snapshot issue epoch, and never
/// implies an online freshness check.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FreshnessMode {
    /// An online check against the snapshot's declared expiry.
    Online,
    /// An offline check against one prior verified source-scoped snapshot witness.
    Offline(OfflineSnapshotWitness),
    /// An explicit offline request that did not provide a prior verified witness.
    OfflineUnavailable,
}

impl FreshnessMode {
    /// Returns the online freshness mode.
    #[must_use]
    pub const fn online() -> Self {
        Self::Online
    }

    /// Selects explicit offline freshness using a previously verified witness.
    #[must_use]
    pub fn offline(witness: OfflineSnapshotWitness) -> Self {
        Self::Offline(witness)
    }

    /// Selects offline verification without evidence, which fails closed.
    #[must_use]
    pub const fn offline_unavailable() -> Self {
        Self::OfflineUnavailable
    }

    /// Returns whether this mode is an online check.
    #[must_use]
    pub const fn is_online(&self) -> bool {
        matches!(self, Self::Online)
    }
}

/// The freshness decision of one verified snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FreshnessReport {
    mode: FreshnessMode,
    observed_epoch: u64,
    issue_epoch: u64,
    expiry_epoch: u64,
    age: u64,
    online: bool,
    snapshot_expired: bool,
}

impl FreshnessReport {
    /// Returns the freshness mode that decided this report.
    #[must_use]
    pub fn mode(&self) -> FreshnessMode {
        self.mode.clone()
    }

    /// Returns the observed epoch.
    #[must_use]
    pub const fn observed_epoch(&self) -> u64 {
        self.observed_epoch
    }

    /// Returns the declared issuance epoch the age is measured from.
    #[must_use]
    pub const fn issue_epoch(&self) -> u64 {
        self.issue_epoch
    }

    /// Returns the declared expiry epoch of the snapshot.
    #[must_use]
    pub const fn expiry_epoch(&self) -> u64 {
        self.expiry_epoch
    }

    /// Returns the reported age of the snapshot at the observed epoch.
    #[must_use]
    pub const fn age(&self) -> u64 {
        self.age
    }

    /// Returns whether this report came from an online check.
    #[must_use]
    pub const fn is_online(&self) -> bool {
        self.online
    }

    /// Returns whether the snapshot's own expiry has passed at the observed epoch.
    ///
    /// The flag is reported rather than enforced for a pinned offline check, which is what
    /// distinguishes a pinned observation from an online verification.
    #[must_use]
    pub const fn snapshot_expired(&self) -> bool {
        self.snapshot_expired
    }
}

/// Decides the freshness window of one snapshot, failing closed.
fn evaluate_freshness(
    snapshot: &MetadataSnapshot,
    observation: EpochObservation,
    mode: FreshnessMode,
    anchor: &SourceDeclaration,
) -> Result<FreshnessReport, RegistryRefusal> {
    if !observation.is_present() {
        return Err(anchor.refusal(RegistryError::ObservedInstantMissing {
            sequence: snapshot.sequence(),
        }));
    }
    let observed = observation.epoch();
    let expired = observed >= snapshot.expiry_epoch();
    match mode {
        FreshnessMode::Online => {
            if observed < snapshot.issue_epoch() {
                return Err(anchor.refusal(RegistryError::SnapshotEpochInconsistent {
                    issue_epoch: snapshot.issue_epoch(),
                    observed_epoch: observed,
                }));
            }
            if expired {
                return Err(anchor.refusal(RegistryError::SnapshotExpired {
                    sequence: snapshot.sequence(),
                    expiry_epoch: snapshot.expiry_epoch(),
                    observed_epoch: observed,
                }));
            }
            Ok(FreshnessReport {
                mode,
                observed_epoch: observed,
                issue_epoch: snapshot.issue_epoch(),
                expiry_epoch: snapshot.expiry_epoch(),
                age: observed - snapshot.issue_epoch(),
                online: true,
                snapshot_expired: false,
            })
        }
        FreshnessMode::Offline(ref witness) => {
            if witness.source() != anchor.identity()
                || witness.snapshot() != snapshot.identity()
                || witness.sequence() != snapshot.sequence()
            {
                return Err(anchor.refusal(RegistryError::PinnedSnapshotStale {
                    pinned_epoch: snapshot.issue_epoch(),
                    expires_at: witness.pin_expiry_epoch(),
                    observed_epoch: observed,
                }));
            }
            if witness.pin_expiry_epoch() < snapshot.issue_epoch()
                || observed < snapshot.issue_epoch()
            {
                return Err(anchor.refusal(RegistryError::SnapshotEpochInconsistent {
                    issue_epoch: snapshot.issue_epoch(),
                    observed_epoch: observed,
                }));
            }
            if expired {
                return Err(anchor.refusal(RegistryError::SnapshotExpired {
                    sequence: snapshot.sequence(),
                    expiry_epoch: snapshot.expiry_epoch(),
                    observed_epoch: observed,
                }));
            }
            if observed > witness.pin_expiry_epoch() {
                return Err(anchor.refusal(RegistryError::PinnedSnapshotStale {
                    pinned_epoch: snapshot.issue_epoch(),
                    expires_at: witness.pin_expiry_epoch(),
                    observed_epoch: observed,
                }));
            }
            Ok(FreshnessReport {
                mode,
                observed_epoch: observed,
                issue_epoch: snapshot.issue_epoch(),
                expiry_epoch: snapshot.expiry_epoch(),
                age: observed - snapshot.issue_epoch(),
                online: false,
                snapshot_expired: false,
            })
        }
        FreshnessMode::OfflineUnavailable => {
            Err(anchor.refusal(RegistryError::PinnedSnapshotUnavailable {
                source: snapshot.source().clone(),
                snapshot: snapshot.identity(),
            }))
        }
    }
}

/// One retained minimum trusted sequence and its retained contents.
///
/// The retained state is the rollback and freeze evidence of
/// `GNT-27.7-rollback-and-freeze-resistance`: a snapshot below the retained minimum is a
/// rollback, and one sequence that already carries another content digest is a freeze or
/// equivocation. It is always bound to one source identity: retained evidence from another
/// source cannot authorize, roll back, or freeze this source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetainedState {
    source: SourceIdentity,
    minimum_sequence: u64,
    content: BTreeMap<u64, [u8; 32]>,
    maximum_staleness: Option<u64>,
    expiry_epoch: Option<u64>,
    lifecycle_root_policy: Option<RootSelectionPolicy>,
    rotation_facts: Vec<[u8; 32]>,
    revocation_facts: Vec<[u8; 32]>,
    advisory_facts: Vec<[u8; 32]>,
}

impl RetainedState {
    /// Constructs retained rollback evidence for exactly one authenticated source.
    #[must_use]
    pub fn for_source(source: SourceIdentity, minimum_sequence: u64) -> Self {
        Self {
            source,
            minimum_sequence,
            content: BTreeMap::new(),
            maximum_staleness: None,
            expiry_epoch: None,
            lifecycle_root_policy: None,
            rotation_facts: Vec::new(),
            revocation_facts: Vec::new(),
            advisory_facts: Vec::new(),
        }
    }

    /// Returns the authenticated source this retained state belongs to.
    #[must_use]
    pub const fn source(&self) -> &SourceIdentity {
        &self.source
    }

    /// Returns this retained source state with its declared maximum metadata staleness.
    #[must_use]
    pub fn with_maximum_staleness(mut self, epochs: u64) -> Self {
        self.maximum_staleness = Some(epochs);
        self
    }

    /// Returns this state with the expiry of its greatest admitted snapshot.
    #[must_use]
    pub fn with_expiry_epoch(mut self, expiry_epoch: u64) -> Self {
        self.expiry_epoch = Some(expiry_epoch);
        self
    }

    /// Binds retained lifecycle facts to the declared root policy that verified them.
    #[must_use]
    pub fn with_lifecycle_root_policy(mut self, policy: RootSelectionPolicy) -> Self {
        self.lifecycle_root_policy = Some(policy);
        self
    }

    /// Returns the declared root policy that verified retained lifecycle facts.
    #[must_use]
    pub const fn lifecycle_root_policy(&self) -> Option<&RootSelectionPolicy> {
        self.lifecycle_root_policy.as_ref()
    }

    /// Records one canonical rotation fact admitted for this source.
    #[must_use]
    pub fn with_rotation_fact(mut self, fact: [u8; 32]) -> Self {
        self.rotation_facts.push(fact);
        self.rotation_facts.sort_unstable();
        self.rotation_facts.dedup();
        self
    }

    /// Records one canonical revocation fact admitted for this source.
    #[must_use]
    pub fn with_revocation_fact(mut self, fact: [u8; 32]) -> Self {
        self.revocation_facts.push(fact);
        self.revocation_facts.sort_unstable();
        self.revocation_facts.dedup();
        self
    }

    /// Records one canonical authenticated advisory fact admitted for this source.
    #[must_use]
    pub fn with_advisory_fact(mut self, fact: [u8; 32]) -> Self {
        self.advisory_facts.push(fact);
        self.advisory_facts.sort_unstable();
        self.advisory_facts.dedup();
        self
    }

    /// Returns the declared maximum metadata staleness, when this source fixed one.
    #[must_use]
    pub const fn maximum_staleness(&self) -> Option<u64> {
        self.maximum_staleness
    }

    /// Returns the expiry of the greatest admitted snapshot, when retained.
    #[must_use]
    pub const fn expiry_epoch(&self) -> Option<u64> {
        self.expiry_epoch
    }

    /// Returns admitted rotation facts for this source in canonical order.
    #[must_use]
    pub fn rotation_facts(&self) -> &[[u8; 32]] {
        &self.rotation_facts
    }

    /// Returns admitted revocation facts for this source in canonical order.
    #[must_use]
    pub fn revocation_facts(&self) -> &[[u8; 32]] {
        &self.revocation_facts
    }

    /// Returns admitted advisory facts for this source in canonical order.
    #[must_use]
    pub fn advisory_facts(&self) -> &[[u8; 32]] {
        &self.advisory_facts
    }

    /// Returns this state with one retained sequence content.
    #[must_use]
    pub fn with_content(mut self, sequence: u64, digest: [u8; 32]) -> Self {
        self.content.insert(sequence, digest);
        self
    }

    /// Returns whether this retained state records exactly the admitted lifecycle facts.
    #[must_use]
    fn has_lifecycle_facts(
        &self,
        rotation_facts: &[[u8; 32]],
        revocation_facts: &[[u8; 32]],
        advisory_facts: &[[u8; 32]],
        root_policy: &RootSelectionPolicy,
    ) -> bool {
        let facts_match = self.rotation_facts == rotation_facts
            && self.revocation_facts == revocation_facts
            && self.advisory_facts == advisory_facts;
        facts_match
            && ((rotation_facts.is_empty()
                && revocation_facts.is_empty()
                && advisory_facts.is_empty())
                || self
                    .lifecycle_root_policy
                    .as_ref()
                    .is_some_and(|retained| root_policy.preserves(retained)))
    }

    /// Returns the retained minimum trusted sequence.
    #[must_use]
    pub const fn minimum_sequence(&self) -> u64 {
        self.minimum_sequence
    }

    /// Returns the retained content digest of one sequence.
    #[must_use]
    pub fn retained_content(&self, sequence: u64) -> Option<[u8; 32]> {
        self.content.get(&sequence).copied()
    }

    /// Returns the retained sequence numbers in ascending order.
    pub fn sequences(&self) -> impl Iterator<Item = u64> + '_ {
        self.content.keys().copied()
    }

    /// Advances the retained state over one accepted sequence and content digest.
    pub fn advance(&mut self, sequence: u64, digest: [u8; 32]) {
        self.content.insert(sequence, digest);
        self.minimum_sequence = self.minimum_sequence.max(sequence);
    }
}

/// The complete immutable fields observed for one published release tuple.
#[derive(Clone, Copy, Debug)]
struct PublicationObservation<'a> {
    manifest: [u8; 32],
    source_content: [u8; 32],
    generated: [u8; 32],
    interface: [u8; 32],
    source: &'a SourceIdentity,
    artifact: [u8; 32],
    target_artifacts: &'a [TargetArtifact],
}

/// One recorded authenticated publication of one release tuple.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicationRecord {
    namespace: RegistryName,
    publisher: RegistryName,
    package: RegistryName,
    version: PackageVersion,
    manifest: [u8; 32],
    source_content: [u8; 32],
    generated: [u8; 32],
    interface: [u8; 32],
    source: SourceIdentity,
    artifact: [u8; 32],
    target_artifacts: Vec<TargetArtifact>,
}

impl PublicationRecord {
    /// Records the publication one snapshot entry names.
    #[must_use]
    pub fn of(entry: &SnapshotEntry) -> Self {
        Self {
            namespace: entry.namespace().clone(),
            publisher: entry.publisher().name().clone(),
            package: entry.package().clone(),
            version: entry.version().clone(),
            manifest: entry.manifest(),
            source_content: entry.source_content(),
            generated: entry.generated(),
            interface: entry.interface(),
            source: entry.source().clone(),
            artifact: entry.artifact(),
            target_artifacts: entry.target_artifacts().to_vec(),
        }
    }

    /// Returns the published namespace.
    #[must_use]
    pub const fn namespace(&self) -> &RegistryName {
        &self.namespace
    }

    /// Returns the published publisher name.
    #[must_use]
    pub const fn publisher(&self) -> &RegistryName {
        &self.publisher
    }

    /// Returns the published package name.
    #[must_use]
    pub const fn package(&self) -> &RegistryName {
        &self.package
    }

    /// Returns the published version.
    #[must_use]
    pub const fn version(&self) -> &PackageVersion {
        &self.version
    }

    /// Returns the published manifest digest.
    #[must_use]
    pub const fn manifest(&self) -> [u8; 32] {
        self.manifest
    }

    /// Returns the immutable published source-content digest.
    #[must_use]
    pub const fn source_content(&self) -> [u8; 32] {
        self.source_content
    }

    /// Returns the immutable published generated-output digest.
    #[must_use]
    pub const fn generated(&self) -> [u8; 32] {
        self.generated
    }

    /// Returns the immutable published public-interface digest.
    #[must_use]
    pub const fn interface(&self) -> [u8; 32] {
        self.interface
    }

    /// Returns the authenticated source identity of the publication.
    #[must_use]
    pub const fn source(&self) -> &SourceIdentity {
        &self.source
    }

    /// Returns the published artifact digest.
    #[must_use]
    pub const fn artifact(&self) -> [u8; 32] {
        self.artifact
    }

    /// Returns the immutable target-qualified artifact set.
    #[must_use]
    pub fn target_artifacts(&self) -> &[TargetArtifact] {
        &self.target_artifacts
    }

    /// Returns the first disagreeing immutable field and its recorded and observed digests.
    fn disagreeing(
        &self,
        observed: PublicationObservation<'_>,
    ) -> Option<(PublicationDefect, [u8; 32], [u8; 32])> {
        if self.manifest != observed.manifest {
            return Some((
                PublicationDefect::ChangedManifest,
                self.manifest,
                observed.manifest,
            ));
        }
        if self.source_content != observed.source_content {
            return Some((
                PublicationDefect::ChangedSourceContent,
                self.source_content,
                observed.source_content,
            ));
        }
        if self.generated != observed.generated {
            return Some((
                PublicationDefect::ChangedGenerated,
                self.generated,
                observed.generated,
            ));
        }
        if self.interface != observed.interface {
            return Some((
                PublicationDefect::ChangedInterface,
                self.interface,
                observed.interface,
            ));
        }
        if self.artifact != observed.artifact {
            return Some((
                PublicationDefect::ChangedArtifact,
                self.artifact,
                observed.artifact,
            ));
        }
        if self.target_artifacts != observed.target_artifacts {
            return Some((
                PublicationDefect::ChangedTargetArtifacts,
                target_artifact_set_digest(&self.target_artifacts),
                target_artifact_set_digest(observed.target_artifacts),
            ));
        }
        if self.source != *observed.source {
            return Some((
                PublicationDefect::ChangedSource,
                self.source.digest(),
                observed.source.digest(),
            ));
        }
        None
    }
}

/// The outcome of one publication admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationAdmission {
    /// The tuple was not recorded and is recorded now.
    Recorded,
    /// The tuple was already recorded with exactly these bytes.
    Identical,
}

/// The authenticated publications one local store has admitted.
///
/// An authenticated `(namespace, package, version)` tuple can never name different manifest,
/// source, or artifact bytes: a differing publication is refused rather than replacing the
/// recorded one, and a correction requires a new version.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PublicationLedger {
    records: BTreeMap<(SourceIdentity, String, String, String), PublicationRecord>,
    names: BTreeMap<SourceIdentity, PublicationNameOccupancy>,
}

/// The canonical publication names retained for one authenticated source.
///
/// Names remain occupied after the snapshot that first admitted them, so a later snapshot
/// cannot introduce a case or confusable collision by omitting the earlier release from its
/// own entry list.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct PublicationNameOccupancy {
    namespaces: PublicationNameSet,
    publishers: PublicationNameSet,
    packages: BTreeMap<RegistryName, PublicationNameSet>,
}

impl PublicationNameOccupancy {
    /// Admits every publication name of one record atomically.
    fn admit(&mut self, record: &PublicationRecord) -> Result<(), RegistryError> {
        let mut next = self.clone();
        next.namespaces.admit(record.namespace().clone())?;
        next.publishers.admit(record.publisher().clone())?;
        next.packages
            .entry(record.namespace().clone())
            .or_default()
            .admit(record.package().clone())?;
        *self = next;
        Ok(())
    }
}

impl PublicationLedger {
    /// Constructs one empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the ledger key of one release tuple.
    fn key(
        source: &SourceIdentity,
        namespace: &RegistryName,
        package: &RegistryName,
        version: &PackageVersion,
    ) -> (SourceIdentity, String, String, String) {
        (
            source.clone(),
            namespace.spelling().to_owned(),
            package.spelling().to_owned(),
            version.as_str().to_owned(),
        )
    }

    /// Admits one already authenticated publication record to this ledger.
    ///
    /// This private primitive is reachable only through [`Self::admit_verified`], which
    /// verifies the whole snapshot before atomically retaining any of its occupancy.
    fn admit_record(
        &mut self,
        declaration: &SourceDeclaration,
        record: PublicationRecord,
    ) -> Result<PublicationAdmission, RegistryRefusal> {
        if record.source() != declaration.identity() {
            return Err(declaration.refusal(RegistryError::SourceNotDeclared {
                requested: record.source().clone(),
            }));
        }
        let mut names = self.names.get(record.source()).cloned().unwrap_or_default();
        names
            .admit(&record)
            .map_err(|error| declaration.refusal(error))?;
        let key = Self::key(
            record.source(),
            record.namespace(),
            record.package(),
            record.version(),
        );
        match self.records.get(&key) {
            Some(existing) => {
                match existing.disagreeing(PublicationObservation {
                    manifest: record.manifest(),
                    source_content: record.source_content(),
                    generated: record.generated(),
                    interface: record.interface(),
                    source: record.source(),
                    artifact: record.artifact(),
                    target_artifacts: record.target_artifacts(),
                }) {
                    Some((defect, recorded, observed)) => Err(RegistryRefusal::at(
                        RegistryError::PublicationImmutable {
                            namespace: record.namespace().clone(),
                            package: record.package().clone(),
                            version: record.version().clone(),
                            defect,
                            recorded,
                            observed,
                        },
                        declaration,
                    )),
                    None => Ok(PublicationAdmission::Identical),
                }
            }
            None => {
                self.records.insert(key, record);
                self.names.insert(declaration.identity().clone(), names);
                Ok(PublicationAdmission::Recorded)
            }
        }
    }

    /// Admits every publication of one verified snapshot atomically.
    ///
    /// Raw entries cannot occupy this ledger: the caller must first obtain
    /// [`VerifiedSnapshot`] from [`TrustStore::verify`]. Every entry's exact declaration is
    /// then recovered from that authenticated decision, so a missing or ambiguous declaration
    /// refuses without retaining a partial name or publication record.
    pub fn admit_verified(
        &mut self,
        verified: &VerifiedSnapshot<'_>,
        declarations: &[SourceDeclaration],
    ) -> Result<(), RegistryRefusal> {
        let mut next = self.clone();
        for (entry_index, entry) in verified.entries().iter().enumerate() {
            let Some(authority) = verified.authority(entry_index) else {
                return Err(RegistryRefusal::unbound(
                    RegistryError::AttributionMissing {
                        declared: declarations.len(),
                        attributed: entry_index,
                    },
                    entry_index,
                    entry.source().clone(),
                ));
            };
            let matches = declarations
                .iter()
                .filter(|declaration| {
                    declaration.index() == authority.declaration()
                        && declaration.identity() == entry.source()
                })
                .collect::<Vec<_>>();
            let [declaration] = matches.as_slice() else {
                return Err(RegistryRefusal::unbound(
                    RegistryError::AttributionMissing {
                        declared: declarations.len(),
                        attributed: entry_index,
                    },
                    entry_index,
                    entry.source().clone(),
                ));
            };
            next.admit_record(declaration, PublicationRecord::of(entry))?;
        }
        *self = next;
        Ok(())
    }

    /// Returns the first collision between a snapshot and names retained from prior admissions.
    fn first_name_collision(&self, snapshot: &MetadataSnapshot) -> Option<(usize, RegistryError)> {
        let mut names = self
            .names
            .get(snapshot.source())
            .cloned()
            .unwrap_or_default();
        for (index, entry) in snapshot.entries().iter().enumerate() {
            if let Err(error) = names.admit(&PublicationRecord::of(entry)) {
                return Some((index, error));
            }
        }
        None
    }

    /// Returns the recorded publication of one release tuple.
    #[must_use]
    pub fn record(
        &self,
        namespace: &RegistryName,
        package: &RegistryName,
        version: &PackageVersion,
    ) -> Option<&PublicationRecord> {
        self.records.values().find(|record| {
            record.namespace() == namespace
                && record.package() == package
                && record.version() == version
        })
    }

    /// Returns the recorded publication for one source-scoped release tuple.
    #[must_use]
    pub fn record_for(
        &self,
        source: &SourceIdentity,
        namespace: &RegistryName,
        package: &RegistryName,
        version: &PackageVersion,
    ) -> Option<&PublicationRecord> {
        self.records
            .get(&Self::key(source, namespace, package, version))
    }

    /// Returns the number of recorded publications.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Returns whether no publication is recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

/// The declared root-selection policy for a source verification.
///
/// A source with one root needs no disjunction. When several roots govern a source, a caller
/// must explicitly select one or enumerate the roots whose disjunction it intends to use; the
/// verifier never combines roots merely because each can establish part of an authority chain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RootSelectionPolicy {
    /// No disjunction was declared; this is valid only when exactly one root governs a source.
    Unspecified,
    /// Verification may use exactly this root.
    Selected(RootId),
    /// Verification may use one root from this explicitly declared set.
    Enumerated(Vec<RootId>),
}

impl RootSelectionPolicy {
    /// Selects exactly one declared root.
    #[must_use]
    pub fn selected(root: RootId) -> Self {
        Self::Selected(root)
    }

    /// Declares the only roots whose disjunction may admit a source.
    #[must_use]
    pub fn enumerated(roots: &[RootId]) -> Self {
        let mut roots = roots.to_vec();
        roots.sort();
        roots.dedup();
        Self::Enumerated(roots)
    }

    /// Returns whether this policy permits one root identity.
    #[must_use]
    fn permits(&self, root: &RootId) -> bool {
        match self {
            Self::Unspecified => true,
            Self::Selected(selected) => selected == root,
            Self::Enumerated(roots) => roots.contains(root),
        }
    }

    /// Returns whether a later verification policy preserves every root a retained policy
    /// could have used to authenticate lifecycle facts.
    #[must_use]
    fn preserves(&self, retained: &Self) -> bool {
        match (self, retained) {
            (_, Self::Unspecified) | (Self::Unspecified, _) => true,
            (Self::Selected(current), Self::Selected(previous)) => current == previous,
            (Self::Selected(current), Self::Enumerated(previous)) => {
                previous.len() == 1 && previous.contains(current)
            }
            (Self::Enumerated(current), Self::Selected(previous)) => current.contains(previous),
            (Self::Enumerated(current), Self::Enumerated(previous)) => {
                previous.iter().all(|root| current.contains(root))
            }
        }
    }

    /// Validates this policy against the roots declared for one source.
    ///
    /// An unspecified policy is sufficient only for a source with exactly one root. Multiple
    /// roots require one selected root or an explicit, non-empty enumerated disjunction; each
    /// named root must govern the same source rather than being borrowed from another source.
    fn validate_for(
        &self,
        source: &SourceIdentity,
        roots: &[&TrustRoot],
    ) -> Result<(), RegistryError> {
        if roots.is_empty() {
            return Err(RegistryError::TrustRootAbsent {
                source: source.clone(),
            });
        }
        match self {
            Self::Unspecified if roots.len() == 1 => Ok(()),
            Self::Unspecified => Err(RegistryError::TrustDecisionDisjunction {
                source: source.clone(),
            }),
            Self::Selected(selected) if roots.iter().any(|root| root.id() == selected) => Ok(()),
            Self::Selected(_) => Err(RegistryError::TrustRootAbsent {
                source: source.clone(),
            }),
            Self::Enumerated(selected)
                if !selected.is_empty()
                    && selected
                        .iter()
                        .all(|root| roots.iter().any(|candidate| candidate.id() == root)) =>
            {
                Ok(())
            }
            Self::Enumerated(_) => Err(RegistryError::TrustDecisionDisjunction {
                source: source.clone(),
            }),
        }
    }
}

/// One explicitly supplied verification input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationInput<'a> {
    declarations: &'a [SourceDeclaration],
    snapshot: &'a MetadataSnapshot,
    signatures: &'a [DeclaredSignature],
    retained: &'a [RetainedState],
    advisories: Option<&'a AdvisoryStore>,
    publications: &'a PublicationLedger,
    observation: EpochObservation,
    freshness: FreshnessMode,
    root_policy: RootSelectionPolicy,
    snapshot_declaration: Option<usize>,
}

impl<'a> VerificationInput<'a> {
    /// Builds one verification input from explicit declarations and evidence.
    #[must_use]
    pub fn new(
        declarations: &'a [SourceDeclaration],
        snapshot: &'a MetadataSnapshot,
        signatures: &'a [DeclaredSignature],
        retained: &'a [RetainedState],
        publications: &'a PublicationLedger,
        observation: EpochObservation,
        freshness: FreshnessMode,
    ) -> Self {
        Self {
            declarations,
            snapshot,
            signatures,
            retained,
            advisories: None,
            publications,
            observation,
            freshness,
            root_policy: RootSelectionPolicy::Unspecified,
            snapshot_declaration: None,
        }
    }

    /// Returns the declared source declarations.
    #[must_use]
    pub const fn declarations(&self) -> &'a [SourceDeclaration] {
        self.declarations
    }

    /// Returns the snapshot under verification.
    #[must_use]
    pub const fn snapshot(&self) -> &'a MetadataSnapshot {
        self.snapshot
    }

    /// Returns the declared signatures over the snapshot content digest.
    #[must_use]
    pub const fn signatures(&self) -> &'a [DeclaredSignature] {
        self.signatures
    }

    /// Returns the source-scoped retained rollback and freeze evidence.
    #[must_use]
    pub const fn retained(&self) -> &'a [RetainedState] {
        self.retained
    }

    /// Returns this input with the complete authenticated advisory lifecycle evidence.
    #[must_use]
    pub fn with_advisories(mut self, advisories: &'a AdvisoryStore) -> Self {
        self.advisories = Some(advisories);
        self
    }

    /// Returns the complete immutable-publication ledger required for verification.
    #[must_use]
    pub const fn publications(&self) -> &'a PublicationLedger {
        self.publications
    }

    /// Returns the explicit epoch observation.
    #[must_use]
    pub const fn observation(&self) -> EpochObservation {
        self.observation
    }

    /// Returns the declared freshness mode.
    #[must_use]
    pub fn freshness(&self) -> FreshnessMode {
        self.freshness.clone()
    }

    /// Returns this input with its explicit multi-root policy.
    #[must_use]
    pub fn with_root_selection(mut self, policy: RootSelectionPolicy) -> Self {
        self.root_policy = policy;
        self
    }

    /// Records the exact dependency declaration that presented this snapshot-wide evidence.
    ///
    /// Entry failures already carry their own declaration.  A signature, root-policy, or
    /// freshness failure spans the snapshot, so callers with several declarations for one
    /// source must provide this edge to preserve exact attribution.
    #[must_use]
    pub fn with_snapshot_declaration(mut self, declaration: usize) -> Self {
        self.snapshot_declaration = Some(declaration);
        self
    }

    /// Returns the policy that selects roots for this verification.
    #[must_use]
    pub const fn root_selection(&self) -> &RootSelectionPolicy {
        &self.root_policy
    }

    /// Returns the explicitly presented declaration for snapshot-wide evidence.
    fn snapshot_declaration(&self) -> Option<&'a SourceDeclaration> {
        self.snapshot_declaration.and_then(|index| {
            self.declarations.iter().find(|declaration| {
                declaration.index() == index && declaration.identity() == self.snapshot.source()
            })
        })
    }
}

/// The authority that admitted one entry of one verified snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EntryAuthority {
    entry: usize,
    declaration: usize,
    grant: AuthorityGrant,
}

impl EntryAuthority {
    /// Returns the entry index.
    #[must_use]
    pub const fn entry(&self) -> usize {
        self.entry
    }

    /// Returns the declaration index that bound the entry.
    #[must_use]
    pub const fn declaration(&self) -> usize {
        self.declaration
    }

    /// Returns the authority that admitted the entry.
    #[must_use]
    pub const fn grant(&self) -> &AuthorityGrant {
        &self.grant
    }
}

/// One verified metadata snapshot.
///
/// The value exists only through [`TrustStore::verify`], so a snapshot that failed any rule
/// has no verified form at all rather than a form whose verdict is remembered separately.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedSnapshot<'a> {
    snapshot: &'a MetadataSnapshot,
    identity: SnapshotIdentity,
    freshness: FreshnessReport,
    authorities: Vec<EntryAuthority>,
    root_policy: RootSelectionPolicy,
}

impl<'a> VerifiedSnapshot<'a> {
    /// Returns the verified snapshot.
    #[must_use]
    pub fn snapshot(&self) -> &'a MetadataSnapshot {
        self.snapshot
    }

    /// Returns the authenticated snapshot identity.
    #[must_use]
    pub const fn identity(&self) -> SnapshotIdentity {
        self.identity
    }

    /// Returns the freshness decision.
    #[must_use]
    pub fn freshness(&self) -> FreshnessReport {
        self.freshness.clone()
    }

    /// Derives an explicit offline witness for one source this snapshot already verified.
    ///
    /// The caller supplies the declared offline bound, but cannot manufacture the source,
    /// snapshot identity, or sequence: all three come from this verified snapshot.
    pub fn offline_witness(
        &self,
        source: &SourceIdentity,
        pin_expiry_epoch: u64,
    ) -> Result<OfflineSnapshotWitness, RegistryError> {
        if pin_expiry_epoch < self.snapshot.issue_epoch()
            || pin_expiry_epoch > self.snapshot.expiry_epoch()
        {
            return Err(RegistryError::SnapshotEpochInconsistent {
                issue_epoch: self.snapshot.issue_epoch(),
                observed_epoch: pin_expiry_epoch,
            });
        }
        if self.snapshot.source() != source {
            return Err(RegistryError::SourceNotDeclared {
                requested: source.clone(),
            });
        }
        Ok(OfflineSnapshotWitness {
            source: source.clone(),
            snapshot: self.identity,
            sequence: self.snapshot.sequence(),
            pin_expiry_epoch,
        })
    }

    /// Returns the per-entry authorities in entry order.
    #[must_use]
    pub fn authorities(&self) -> &[EntryAuthority] {
        &self.authorities
    }

    /// Returns the declared root policy that authenticated this snapshot.
    #[must_use]
    pub const fn root_policy(&self) -> &RootSelectionPolicy {
        &self.root_policy
    }

    /// Returns the authority that admitted one entry.
    #[must_use]
    pub fn authority(&self, entry: usize) -> Option<&EntryAuthority> {
        self.authorities
            .iter()
            .find(|authority| authority.entry() == entry)
    }

    /// Returns the entries of the verified snapshot, in canonical order.
    #[must_use]
    pub fn entries(&self) -> &'a [SnapshotEntry] {
        self.snapshot.entries()
    }

    /// Binds lockfile evidence only after this snapshot has passed authenticated verification.
    ///
    /// This is the pre-parse gate for a single-source acquisition. Multi-source lockfiles
    /// use [`Self::bind_lockfile_closure`] to require a verified snapshot for every source.
    pub fn bind_lockfile(
        &self,
        lockfile: &'a Lockfile,
        declarations: &'a [SourceDeclaration],
    ) -> Result<EvidenceGate<'a>, RegistryRefusal> {
        lockfile.bind(declarations, &[self.snapshot])
    }

    /// Binds every lockfile record to one verified source snapshot before acquisition.
    ///
    /// The receiver proves its own source and every additional verified snapshot proves one
    /// other source. A record or transitive dependency whose source has no verified snapshot is
    /// refused rather than being treated as evidence under the receiver's source.
    pub fn bind_lockfile_closure(
        &self,
        lockfile: &'a Lockfile,
        declarations: &'a [SourceDeclaration],
        additional: &[&VerifiedSnapshot<'a>],
    ) -> Result<EvidenceGate<'a>, RegistryRefusal> {
        let mut snapshots = vec![self.snapshot];
        snapshots.extend(additional.iter().map(|verified| verified.snapshot()));
        lockfile.bind(declarations, &snapshots)
    }
}

impl TrustStore {
    /// Derives the durable source state that a verified snapshot contributes.
    ///
    /// The returned state retains the snapshot content, its exclusive expiry, and every
    /// source-scoped rotation or compromise fact effective at that sequence. Callers persist
    /// this declared value rather than reconstructing lifecycle history from a cache.
    #[must_use]
    pub fn retained_state(&self, verified: &VerifiedSnapshot<'_>) -> RetainedState {
        let snapshot = verified.snapshot();
        let (rotation_facts, revocation_facts) = self.lifecycle_facts(
            snapshot.source(),
            snapshot.sequence(),
            verified.root_policy(),
        );
        let retained = RetainedState::for_source(snapshot.source().clone(), snapshot.sequence())
            .with_content(snapshot.sequence(), snapshot.content_digest())
            .with_expiry_epoch(snapshot.expiry_epoch())
            .with_lifecycle_root_policy(verified.root_policy().clone());
        let retained = rotation_facts
            .into_iter()
            .fold(retained, |state, fact| state.with_rotation_fact(fact));
        revocation_facts
            .into_iter()
            .fold(retained, |state, fact| state.with_revocation_fact(fact))
    }

    /// Derives durable source state including authenticated advisory facts admitted by this
    /// store under the verified root policy.
    #[must_use]
    pub fn retained_state_with_advisories(
        &self,
        verified: &VerifiedSnapshot<'_>,
        advisories: &AdvisoryStore,
    ) -> RetainedState {
        advisories
            .lifecycle_facts(
                verified.snapshot().source(),
                verified.snapshot().sequence(),
                verified.root_policy(),
            )
            .into_iter()
            .fold(self.retained_state(verified), |state, fact| {
                state.with_advisory_fact(fact)
            })
    }

    /// Returns canonical authenticated lifecycle facts effective for one source sequence.
    fn lifecycle_facts(
        &self,
        source: &SourceIdentity,
        sequence: u64,
        root_policy: &RootSelectionPolicy,
    ) -> (Vec<[u8; 32]>, Vec<[u8; 32]>) {
        let mut rotation_facts = self
            .rotations
            .iter()
            .filter(|rotation| {
                rotation.source() == source
                    && rotation.effective_sequence() <= sequence
                    && self.rotation_fact_permitted(rotation.evidence_digest(), root_policy)
            })
            .map(RotationEvidence::evidence_digest)
            .collect::<Vec<_>>();
        rotation_facts.sort_unstable();
        rotation_facts.dedup();
        let mut revocation_facts = self
            .compromises
            .iter()
            .filter(|compromise| {
                compromise.source() == source
                    && compromise.effective_sequence() <= sequence
                    && self.compromise_fact_permitted(compromise.evidence_digest(), root_policy)
            })
            .map(Compromise::evidence_digest)
            .collect::<Vec<_>>();
        revocation_facts.sort_unstable();
        revocation_facts.dedup();
        (rotation_facts, revocation_facts)
    }

    /// Verifies one metadata snapshot against this store and the supplied evidence.
    ///
    /// The decision applies one fixed order, so two inputs that trip two rules report the
    /// same first rule: attribution binding, then global signature verification, then the
    /// retained rollback and freeze state, then each entry's signer verification, key state,
    /// publisher authority, scope, and recorded publication, and finally the freshness
    /// window. Every refusal carries the declaration that caused it, and an entry that no
    /// declaration binds is refused as [`RegistryError::AttributionMissing`] before any
    /// other check reads that entry, so no refusal is ever reported without attribution.
    ///
    /// A refusal that concerns the snapshot rather than one entry is attributed to the
    /// declaration that binds the first entry in canonical order, so the attribution of a
    /// snapshot-level refusal is a function of the declared entry set and not of the order in
    /// which entries or declarations were supplied.
    pub fn verify<'a>(
        &'a self,
        input: &'a VerificationInput<'a>,
    ) -> Result<VerifiedSnapshot<'a>, RegistryRefusal> {
        let snapshot = input.snapshot();
        let entries = snapshot.entries();
        let declarations = input.declarations();
        if declarations.is_empty() {
            return Err(RegistryRefusal::unbound(
                RegistryError::AttributionMissing {
                    declared: 0,
                    attributed: 0,
                },
                0,
                entries[0].source().clone(),
            ));
        }
        validate_declaration_indices(declarations)?;
        let mut attributed: Vec<&'a SourceDeclaration> = Vec::new();
        for (index, entry) in entries.iter().enumerate() {
            let candidates = declarations
                .iter()
                .filter(|declaration| declaration.identity() == entry.source())
                .collect::<Vec<_>>();
            let exact = candidates
                .iter()
                .copied()
                .filter(|declaration| declaration.alias().spelling() == entry.package().spelling())
                .collect::<Vec<_>>();
            if exact.len() == 1 {
                attributed.push(exact[0]);
            } else if exact.is_empty() && candidates.len() == 1 {
                attributed.push(candidates[0]);
            } else {
                return Err(RegistryRefusal::unbound(
                    RegistryError::AttributionMissing {
                        declared: declarations.len(),
                        attributed: attributed.len(),
                    },
                    index,
                    entry.source().clone(),
                ));
            }
        }
        let entry_anchor = attributed[0];
        let snapshot_anchor = input.snapshot_declaration();
        let snapshot_refusal = |condition| {
            snapshot_anchor.map_or_else(
                || {
                    RegistryRefusal::unbound(
                        RegistryError::AttributionMissing {
                            declared: declarations.len(),
                            attributed: attributed.len(),
                        },
                        0,
                        snapshot.source().clone(),
                    )
                },
                |declaration| declaration.refusal(condition),
            )
        };
        let roots = self
            .roots
            .iter()
            .filter(|root| root.source() == snapshot.source())
            .collect::<Vec<_>>();
        input
            .root_selection()
            .validate_for(snapshot.source(), &roots)
            .map_err(snapshot_refusal)?;
        let content = snapshot.content_digest();
        let verifying = input
            .signatures()
            .iter()
            .filter(|signature| self.verifies(signature, content))
            .map(|signature| signature.key().clone())
            .collect::<Vec<_>>();
        if verifying.is_empty() {
            let key = input
                .signatures()
                .first()
                .map(|signature| signature.key().clone())
                .unwrap_or_else(|| entries[0].publisher().key().clone());
            return Err(snapshot_refusal(RegistryError::SignatureUnverified { key }));
        }
        let mut authorities = Vec::new();
        for (index, entry) in entries.iter().enumerate() {
            let declaration = attributed[index];
            if !verifying.contains(entry.publisher().key()) {
                return Err(RegistryRefusal::at_entry(
                    RegistryError::PublisherUnauthorized {
                        publisher: Arc::from(entry.publisher().name().spelling()),
                        key: entry.publisher().key().clone(),
                        defect: AuthorizationDefect::UnverifiedSigner,
                    },
                    declaration,
                    index,
                ));
            }
            let grant = self
                .authorize_at(
                    declaration,
                    entry,
                    snapshot.sequence(),
                    snapshot.issue_epoch(),
                    Some(input.root_selection()),
                )
                .map_err(|refusal| refusal.with_entry(index))?;
            authorities.push(EntryAuthority {
                entry: index,
                declaration: declaration.index(),
                grant,
            });
        }
        let freshness = match snapshot_anchor {
            Some(declaration) => evaluate_freshness(
                snapshot,
                input.observation(),
                input.freshness(),
                declaration,
            )?,
            None => {
                let report = evaluate_freshness(
                    snapshot,
                    input.observation(),
                    input.freshness(),
                    entry_anchor,
                );
                match report {
                    Ok(report) => report,
                    Err(refusal) => return Err(snapshot_refusal(refusal.condition().clone())),
                }
            }
        };
        for (index, entry) in entries.iter().enumerate() {
            let declaration = attributed[index];
            let retained = input
                .retained()
                .iter()
                .filter(|retained| retained.source() == entry.source())
                .collect::<Vec<_>>();
            let retained = match retained.as_slice() {
                [] => {
                    return Err(RegistryRefusal::at_entry(
                        RegistryError::SourceNotDeclared {
                            requested: entry.source().clone(),
                        },
                        declaration,
                        index,
                    ));
                }
                [retained] => *retained,
                supplied => {
                    return Err(RegistryRefusal::at_entry(
                        RegistryError::RetainedStateAmbiguous {
                            source: entry.source().clone(),
                            supplied: supplied.len(),
                        },
                        declaration,
                        index,
                    ));
                }
            };
            let (rotation_facts, revocation_facts) =
                self.lifecycle_facts(entry.source(), snapshot.sequence(), input.root_selection());
            let advisory_facts = input.advisories.map_or_else(Vec::new, |advisories| {
                advisories.lifecycle_facts(
                    entry.source(),
                    snapshot.sequence(),
                    input.root_selection(),
                )
            });
            if !retained.has_lifecycle_facts(
                &rotation_facts,
                &revocation_facts,
                &advisory_facts,
                input.root_selection(),
            ) {
                return Err(RegistryRefusal::at_entry(
                    RegistryError::RetainedLifecycleFactsMissing {
                        source: entry.source().clone(),
                    },
                    declaration,
                    index,
                ));
            }
            if snapshot.sequence() < retained.minimum_sequence() {
                return Err(RegistryRefusal::at_entry(
                    RegistryError::Rollback {
                        declared: snapshot.sequence(),
                        retained_minimum: retained.minimum_sequence(),
                    },
                    declaration,
                    index,
                ));
            }
            if retained.minimum_sequence() != 0
                && snapshot.sequence() == retained.minimum_sequence()
                && retained.retained_content(snapshot.sequence()).is_none()
            {
                return Err(RegistryRefusal::at_entry(
                    RegistryError::RetainedContentMissing {
                        sequence: snapshot.sequence(),
                    },
                    declaration,
                    index,
                ));
            }
            if let Some(retained_content) = retained.retained_content(snapshot.sequence())
                && retained_content != content
            {
                return Err(RegistryRefusal::at_entry(
                    RegistryError::FreezeEquivocation {
                        sequence: snapshot.sequence(),
                        retained: retained_content,
                        observed: content,
                    },
                    declaration,
                    index,
                ));
            }
            if snapshot.sequence() <= retained.minimum_sequence()
                && let (Some(maximum_staleness), Some(expiry_epoch)) =
                    (retained.maximum_staleness(), retained.expiry_epoch())
                && input.observation().epoch() > expiry_epoch.saturating_add(maximum_staleness)
            {
                return Err(RegistryRefusal::at_entry(
                    RegistryError::FreezeDetected {
                        sequence: retained.minimum_sequence(),
                        maximum_staleness,
                        observed_epoch: input.observation().epoch(),
                    },
                    declaration,
                    index,
                ));
            }
        }
        if let Some((index, condition)) = snapshot
            .first_name_collision()
            .or_else(|| input.publications().first_name_collision(snapshot))
        {
            return Err(RegistryRefusal::at_entry(
                condition,
                attributed[index],
                index,
            ));
        }
        for (index, entry) in entries.iter().enumerate() {
            let declaration = attributed[index];
            if let Some(record) = input.publications().record_for(
                entry.source(),
                entry.namespace(),
                entry.package(),
                entry.version(),
            ) && let Some((defect, recorded, observed)) =
                record.disagreeing(PublicationObservation {
                    manifest: entry.manifest(),
                    source_content: entry.source_content(),
                    generated: entry.generated(),
                    interface: entry.interface(),
                    source: entry.source(),
                    artifact: entry.artifact(),
                    target_artifacts: entry.target_artifacts(),
                })
            {
                return Err(RegistryRefusal::at_entry(
                    RegistryError::PublicationImmutable {
                        namespace: entry.namespace().clone(),
                        package: entry.package().clone(),
                        version: entry.version().clone(),
                        defect,
                        recorded,
                        observed,
                    },
                    declaration,
                    index,
                ));
            }
        }
        Ok(VerifiedSnapshot {
            snapshot,
            identity: snapshot.identity(),
            freshness,
            authorities,
            root_policy: input.root_selection().clone(),
        })
    }
}

/// One pinned version-control commit identity.
///
/// A commit identity is either the 40-digit abbreviated object identity or the 64-digit
/// content identity, in lowercase hexadecimal. An uppercase or truncated spelling is
/// refused rather than folded, so one commit has exactly one spelling.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CommitId(Arc<str>);

impl CommitId {
    /// Validates one lowercase hexadecimal commit identity of 40 or 64 digits.
    pub fn new(value: &str) -> Result<Self, RegistryError> {
        let canonical = if value.len() == 40 {
            value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        } else {
            is_hex_digest(value)
        };
        if !canonical {
            return Err(RegistryError::AcquisitionDeclarationInvalid {
                field: "commit id",
                value: Arc::from(value),
            });
        }
        Ok(Self(Arc::from(value)))
    }

    /// Returns the exact commit identity spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One version-control pin: one source identity, one commit, one content digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VcsPin {
    source: SourceIdentity,
    commit: CommitId,
    content: [u8; 32],
}

impl VcsPin {
    /// Validates one version-control pin of one version-control source identity.
    pub fn new(
        source: SourceIdentity,
        commit: &str,
        content: [u8; 32],
    ) -> Result<Self, RegistryError> {
        if source.kind() != SourceKind::Vcs {
            return Err(RegistryError::AcquisitionDeclarationInvalid {
                field: "vcs pin source",
                value: Arc::from(source.canonical_text()),
            });
        }
        let commit = CommitId::new(commit)?;
        let encoded = source
            .canonical_text()
            .rsplit_once('@')
            .map_or("", |(_, encoded)| encoded);
        if encoded != commit.as_str() {
            return Err(RegistryError::VcsPinIdentityMismatch {
                expected: Arc::from(encoded),
                observed: Arc::from(commit.as_str()),
            });
        }
        if content.iter().all(|byte| *byte == 0) {
            return Err(RegistryError::AcquisitionDeclarationInvalid {
                field: "vcs pin content",
                value: Arc::from("omitted"),
            });
        }
        Ok(Self {
            source,
            commit,
            content,
        })
    }

    /// Returns the pinned source identity.
    #[must_use]
    pub const fn source(&self) -> &SourceIdentity {
        &self.source
    }

    /// Returns the pinned commit.
    #[must_use]
    pub const fn commit(&self) -> &CommitId {
        &self.commit
    }

    /// Returns the pinned content digest.
    #[must_use]
    pub const fn content(&self) -> [u8; 32] {
        self.content
    }
}

/// One path or vendored pin: one source identity and one content digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PathPin {
    source: SourceIdentity,
    content: [u8; 32],
}

impl PathPin {
    /// Validates one path or vendored pin.
    pub fn new(source: SourceIdentity, content: [u8; 32]) -> Result<Self, RegistryError> {
        if !matches!(source.kind(), SourceKind::Path | SourceKind::Vendored) {
            return Err(RegistryError::AcquisitionDeclarationInvalid {
                field: "path pin source",
                value: Arc::from(source.canonical_text()),
            });
        }
        if content.iter().all(|byte| *byte == 0) {
            return Err(RegistryError::AcquisitionDeclarationInvalid {
                field: "path pin content",
                value: Arc::from("omitted"),
            });
        }
        Ok(Self { source, content })
    }

    /// Returns the pinned source identity.
    #[must_use]
    pub const fn source(&self) -> &SourceIdentity {
        &self.source
    }

    /// Returns the pinned content digest.
    #[must_use]
    pub const fn content(&self) -> [u8; 32] {
        self.content
    }
}

/// One observed tree, as it was supplied to verification.
///
/// The tree carries the observed source identity, the observed commit when the source kind
/// has one, the observed content digest, and every modified path that was detected. A tree
/// with any modified path is refused, because a modified working tree is not the content the
/// pin authenticates.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PinnedTree {
    source: SourceIdentity,
    commit: Option<CommitId>,
    content: [u8; 32],
    modified_paths: Vec<Arc<str>>,
}

impl PinnedTree {
    /// Declares one observed tree with one observed content digest.
    #[must_use]
    pub fn observed(source: SourceIdentity, commit: Option<CommitId>, content: [u8; 32]) -> Self {
        Self {
            source,
            commit,
            content,
            modified_paths: Vec::new(),
        }
    }

    /// Returns this tree with one more detected modified path, kept in canonical order.
    #[must_use]
    pub fn modified(mut self, path: &str) -> Self {
        self.modified_paths.push(Arc::from(path));
        self.modified_paths.sort();
        self
    }

    /// Returns the observed source identity.
    #[must_use]
    pub const fn source(&self) -> &SourceIdentity {
        &self.source
    }

    /// Returns the observed commit, when the observed source has one.
    #[must_use]
    pub const fn commit(&self) -> Option<&CommitId> {
        self.commit.as_ref()
    }

    /// Returns the observed content digest.
    #[must_use]
    pub const fn content(&self) -> [u8; 32] {
        self.content
    }

    /// Returns the detected modified paths in canonical order.
    #[must_use]
    pub fn modified_paths(&self) -> &[Arc<str>] {
        &self.modified_paths
    }

    /// Returns whether no modified path was detected.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.modified_paths.is_empty()
    }
}

/// One verified content digest.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct VerifiedContent {
    source: SourceIdentity,
    digest: [u8; 32],
}

impl VerifiedContent {
    /// Returns the source identity whose content this proof verified.
    #[must_use]
    pub const fn source(&self) -> &SourceIdentity {
        &self.source
    }

    /// Returns the verified content digest.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// Returns the lowercase hexadecimal verified content digest.
    #[must_use]
    pub fn hex(&self) -> String {
        hex(&self.digest)
    }
}

/// One verified pinned checkout.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedCheckout {
    source: SourceIdentity,
    commit: CommitId,
    content: VerifiedContent,
}

impl VerifiedCheckout {
    /// Returns the source identity whose pinned tree this proof verified.
    #[must_use]
    pub const fn source(&self) -> &SourceIdentity {
        &self.source
    }

    /// Returns the verified commit.
    #[must_use]
    pub const fn commit(&self) -> &CommitId {
        &self.commit
    }

    /// Returns the verified content digest.
    #[must_use]
    pub const fn content(&self) -> &VerifiedContent {
        &self.content
    }
}

/// Immutable source proof required for direct version-control and path acquisition.
///
/// The proof types can only be obtained through [`verify_pinned_tree`] or
/// [`verify_path_tree`], so final acquisition cannot substitute delivery bytes for a mutable
/// checkout or path observation after those checks have completed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AcquisitionProof {
    /// A verified immutable version-control checkout.
    Vcs(VerifiedCheckout),
    /// Verified immutable content of a path source.
    Path(VerifiedContent),
}

/// Verifies one observed tree against one version-control pin.
///
/// The checks apply in one fixed order: the source identity, the pinned commit, the detected
/// modified paths, and the content digest. A mismatch of the source identity or the commit
/// is refused as [`RegistryError::PinMismatch`], any modified path is refused as
/// [`RegistryError::ModifiedPath`], and a differing content digest is refused as
/// [`RegistryError::ContentMismatch`].
pub fn verify_pinned_tree(
    declaration: &SourceDeclaration,
    pin: &VcsPin,
    tree: &PinnedTree,
) -> Result<VerifiedCheckout, RegistryRefusal> {
    require_declared_source(declaration, pin.source())?;
    require_declared_source(declaration, tree.source())?;
    if tree.source() != pin.source() {
        return Err(declaration.refusal(RegistryError::PinMismatch {
            expected: Arc::from(pin.source().canonical_text()),
            observed: Arc::from(tree.source().canonical_text()),
            defect: PinDefect::SourceIdentity,
        }));
    }
    if tree.commit() != Some(pin.commit()) {
        return Err(declaration.refusal(RegistryError::PinMismatch {
            expected: Arc::from(pin.commit().as_str()),
            observed: Arc::from(tree.commit().map(CommitId::as_str).unwrap_or("unpinned")),
            defect: PinDefect::Commit,
        }));
    }
    if let Some(path) = tree.modified_paths().first() {
        return Err(declaration.refusal(RegistryError::ModifiedPath {
            path: Arc::from(path.as_ref()),
        }));
    }
    if tree.content() != pin.content() {
        return Err(declaration.refusal(RegistryError::ContentMismatch {
            expected: pin.content(),
            observed: tree.content(),
        }));
    }
    Ok(VerifiedCheckout {
        source: pin.source().clone(),
        commit: pin.commit().clone(),
        content: VerifiedContent {
            source: pin.source().clone(),
            digest: pin.content(),
        },
    })
}

/// Verifies one observed tree against one path or vendored pin.
pub fn verify_path_tree(
    declaration: &SourceDeclaration,
    pin: &PathPin,
    tree: &PinnedTree,
) -> Result<VerifiedContent, RegistryRefusal> {
    require_declared_source(declaration, pin.source())?;
    require_declared_source(declaration, tree.source())?;
    if tree.source() != pin.source() {
        return Err(declaration.refusal(RegistryError::PinMismatch {
            expected: Arc::from(pin.source().canonical_text()),
            observed: Arc::from(tree.source().canonical_text()),
            defect: PinDefect::SourceIdentity,
        }));
    }
    if let Some(path) = tree.modified_paths().first() {
        return Err(declaration.refusal(RegistryError::ModifiedPath {
            path: Arc::from(path.as_ref()),
        }));
    }
    if tree.content() != pin.content() {
        return Err(declaration.refusal(RegistryError::ContentMismatch {
            expected: pin.content(),
            observed: tree.content(),
        }));
    }
    Ok(VerifiedContent {
        source: pin.source().clone(),
        digest: pin.content(),
    })
}

/// One packaged release a vendored directory carries.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct VendorEntry {
    namespace: RegistryName,
    package: RegistryName,
    version: PackageVersion,
    manifest: [u8; 32],
    source_content: [u8; 32],
    generated: [u8; 32],
    interface: [u8; 32],
    artifact: [u8; 32],
    target_artifacts: Vec<TargetArtifact>,
}

impl VendorEntry {
    /// Validates one vendored release entry with every immutable release digest.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        namespace: &str,
        package: &str,
        version: &str,
        manifest: [u8; 32],
        source_content: [u8; 32],
        generated: [u8; 32],
        interface: [u8; 32],
        artifact: [u8; 32],
    ) -> Result<Self, RegistryError> {
        Ok(Self {
            namespace: RegistryName::namespace(namespace)?,
            package: RegistryName::package(package)?,
            version: version_of(version)?,
            manifest,
            source_content,
            generated,
            interface,
            artifact,
            target_artifacts: Vec::new(),
        })
    }

    /// Returns the vendored namespace.
    #[must_use]
    pub const fn namespace(&self) -> &RegistryName {
        &self.namespace
    }

    /// Returns the vendored package name.
    #[must_use]
    pub const fn package(&self) -> &RegistryName {
        &self.package
    }

    /// Returns the vendored version.
    #[must_use]
    pub const fn version(&self) -> &PackageVersion {
        &self.version
    }

    /// Returns the vendored manifest digest.
    #[must_use]
    pub const fn manifest(&self) -> [u8; 32] {
        self.manifest
    }

    /// Returns the vendored complete source-content digest.
    #[must_use]
    pub const fn source_content(&self) -> [u8; 32] {
        self.source_content
    }

    /// Returns the vendored generated-output digest.
    #[must_use]
    pub const fn generated(&self) -> [u8; 32] {
        self.generated
    }

    /// Returns the vendored public-interface digest.
    #[must_use]
    pub const fn interface(&self) -> [u8; 32] {
        self.interface
    }

    /// Returns the vendored artifact digest.
    #[must_use]
    pub const fn artifact(&self) -> [u8; 32] {
        self.artifact
    }

    /// Returns this vendored release with one target-qualified immutable artifact.
    #[must_use]
    pub fn with_target_artifact(mut self, artifact: TargetArtifact) -> Self {
        self.target_artifacts.push(artifact);
        self.target_artifacts.sort();
        self.target_artifacts.dedup();
        self
    }

    /// Returns the vendored target-qualified artifact set in canonical order.
    #[must_use]
    pub fn target_artifacts(&self) -> &[TargetArtifact] {
        &self.target_artifacts
    }
}

/// One vendored directory as it is committed into the tree.
///
/// A vendored directory must present the authenticated source and snapshot identity of the
/// acquisition it replaces. This comparison proves only those declared identities; it does not
/// claim general equivalence between vendor and registry universes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VendorDirectory {
    source: SourceIdentity,
    snapshot: SnapshotIdentity,
    entries: Vec<VendorEntry>,
}

impl VendorDirectory {
    /// Validates one vendored directory of one authenticated snapshot identity.
    pub fn new(
        source: SourceIdentity,
        snapshot: SnapshotIdentity,
        entries: &[VendorEntry],
    ) -> Result<Self, RegistryError> {
        if entries.is_empty() {
            return Err(RegistryError::AcquisitionDeclarationInvalid {
                field: "vendor entries",
                value: Arc::from("empty"),
            });
        }
        let mut ordered = entries.to_vec();
        ordered.sort();
        for pair in ordered.windows(2) {
            if pair[0].namespace() == pair[1].namespace()
                && pair[0].package() == pair[1].package()
                && pair[0].version() == pair[1].version()
            {
                return Err(RegistryError::AcquisitionDeclarationInvalid {
                    field: "vendor entry",
                    value: Arc::from(format!(
                        "{}/{}@{}",
                        pair[1].namespace().spelling(),
                        pair[1].package().spelling(),
                        pair[1].version().as_str()
                    )),
                });
            }
        }
        Ok(Self {
            source,
            snapshot,
            entries: ordered,
        })
    }

    /// Returns the vendored source identity.
    #[must_use]
    pub const fn source(&self) -> &SourceIdentity {
        &self.source
    }

    /// Returns the authenticated snapshot identity the directory presents.
    #[must_use]
    pub const fn snapshot(&self) -> SnapshotIdentity {
        self.snapshot
    }

    /// Returns the vendored release entries in canonical order.
    #[must_use]
    pub fn entries(&self) -> &[VendorEntry] {
        &self.entries
    }
}

/// The decision of one vendored verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VendorReport {
    source: SourceIdentity,
    identity: SnapshotIdentity,
    entries: usize,
}

impl VendorReport {
    /// Returns the authenticated source identity whose vendor proof was confirmed.
    #[must_use]
    pub const fn source(&self) -> &SourceIdentity {
        &self.source
    }

    /// Returns the authenticated snapshot identity that was confirmed.
    #[must_use]
    pub const fn identity(&self) -> SnapshotIdentity {
        self.identity
    }

    /// Returns the number of confirmed vendored releases.
    #[must_use]
    pub const fn entries(&self) -> usize {
        self.entries
    }
}

/// Verifies one vendored directory against one already authenticated snapshot.
///
/// A raw [`MetadataSnapshot`] cannot authorize vendoring: only a [`VerifiedSnapshot`] proves
/// the source, signatures, freshness, retained-state, and immutable-publication checks that
/// precede delivery verification.
pub fn verify_vendor(
    declaration: &SourceDeclaration,
    vendor: &VendorDirectory,
    verified: &VerifiedSnapshot<'_>,
) -> Result<VendorReport, RegistryRefusal> {
    let snapshot = verified.snapshot();
    if vendor.source() != declaration.identity() {
        return Err(declaration.refusal(RegistryError::VendorMismatch {
            expected: Arc::from(declaration.identity().digest_hex()),
            observed: Arc::from(vendor.source().digest_hex()),
            defect: VendorDefect::SourceIdentity,
        }));
    }
    if vendor.snapshot() != snapshot.identity() {
        return Err(declaration.refusal(RegistryError::VendorMismatch {
            expected: Arc::from(snapshot.identity().digest_hex()),
            observed: Arc::from(vendor.snapshot().digest_hex()),
            defect: VendorDefect::SnapshotIdentity,
        }));
    }
    if vendor.entries().len() != snapshot.entries().len() {
        return Err(declaration.refusal(RegistryError::VendorMismatch {
            expected: Arc::from(snapshot.entries().len().to_string()),
            observed: Arc::from(vendor.entries().len().to_string()),
            defect: VendorDefect::UnknownEntry,
        }));
    }
    for entry in vendor.entries() {
        match snapshot.entries().iter().find(|candidate| {
            candidate.source() == declaration.identity()
                && candidate.namespace() == entry.namespace()
                && candidate.package() == entry.package()
                && candidate.version() == entry.version()
        }) {
            Some(candidate) => {
                if candidate.manifest() != entry.manifest() {
                    return Err(declaration.refusal(RegistryError::VendorMismatch {
                        expected: Arc::from(hex(&candidate.manifest())),
                        observed: Arc::from(hex(&entry.manifest())),
                        defect: VendorDefect::ChangedManifest,
                    }));
                }
                if candidate.source_content() != entry.source_content() {
                    return Err(declaration.refusal(RegistryError::VendorMismatch {
                        expected: Arc::from(hex(&candidate.source_content())),
                        observed: Arc::from(hex(&entry.source_content())),
                        defect: VendorDefect::ChangedSourceContent,
                    }));
                }
                if candidate.generated() != entry.generated() {
                    return Err(declaration.refusal(RegistryError::VendorMismatch {
                        expected: Arc::from(hex(&candidate.generated())),
                        observed: Arc::from(hex(&entry.generated())),
                        defect: VendorDefect::ChangedGenerated,
                    }));
                }
                if candidate.interface() != entry.interface() {
                    return Err(declaration.refusal(RegistryError::VendorMismatch {
                        expected: Arc::from(hex(&candidate.interface())),
                        observed: Arc::from(hex(&entry.interface())),
                        defect: VendorDefect::ChangedInterface,
                    }));
                }
                if candidate.artifact() != entry.artifact() {
                    return Err(declaration.refusal(RegistryError::VendorMismatch {
                        expected: Arc::from(hex(&candidate.artifact())),
                        observed: Arc::from(hex(&entry.artifact())),
                        defect: VendorDefect::ChangedArtifact,
                    }));
                }
                if target_artifact_set_digest(candidate.target_artifacts())
                    != target_artifact_set_digest(entry.target_artifacts())
                {
                    return Err(declaration.refusal(RegistryError::VendorMismatch {
                        expected: Arc::from(hex(&target_artifact_set_digest(
                            candidate.target_artifacts(),
                        ))),
                        observed: Arc::from(hex(&target_artifact_set_digest(
                            entry.target_artifacts(),
                        ))),
                        defect: VendorDefect::ChangedTargetArtifacts,
                    }));
                }
            }
            None => {
                return Err(declaration.refusal(RegistryError::VendorMismatch {
                    expected: Arc::from(snapshot.identity().digest_hex()),
                    observed: Arc::from(format!(
                        "{}/{}@{}",
                        entry.namespace().spelling(),
                        entry.package().spelling(),
                        entry.version().as_str()
                    )),
                    defect: VendorDefect::UnknownEntry,
                }));
            }
        }
    }
    Ok(VendorReport {
        source: snapshot.source().clone(),
        identity: snapshot.identity(),
        entries: vendor.entries().len(),
    })
}

/// One mirror that presents one authenticated snapshot identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MirrorBinding {
    mirror: Arc<str>,
    source: SourceIdentity,
    presented: SnapshotIdentity,
}

impl MirrorBinding {
    /// Validates one mirror binding over one presented snapshot identity.
    pub fn new(
        mirror: &str,
        source: SourceIdentity,
        presented: SnapshotIdentity,
    ) -> Result<Self, RegistryError> {
        if mirror.is_empty() || mirror.chars().any(char::is_control) {
            return Err(RegistryError::AcquisitionDeclarationInvalid {
                field: "mirror",
                value: Arc::from(mirror),
            });
        }
        Ok(Self {
            mirror: Arc::from(mirror),
            source,
            presented,
        })
    }

    /// Returns the mirror spelling.
    #[must_use]
    pub fn mirror(&self) -> &str {
        &self.mirror
    }

    /// Returns the source identity the mirror serves.
    #[must_use]
    pub const fn source(&self) -> &SourceIdentity {
        &self.source
    }

    /// Returns the snapshot identity the mirror presents.
    #[must_use]
    pub const fn presented(&self) -> SnapshotIdentity {
        self.presented
    }
}

/// Admits one release for ordinary new resolution from the greatest verified source state.
///
/// A yank removes a release from ordinary new resolution without rewriting anything durable:
/// an existing verified lockfile stays reproducible through [`Lockfile::replay`], so a yank
/// never invalidates a lockfile and never rewrites one silently. The caller must supply the
/// retained greatest state for the declaration source; a raw snapshot, a stale state, or state
/// retained for another source can therefore never decide a yank.
pub fn resolve_new_release<'a>(
    declaration: &SourceDeclaration,
    verified: &VerifiedSnapshot<'_>,
    greatest: &RetainedState,
    entry: &'a SnapshotEntry,
) -> Result<&'a SnapshotEntry, RegistryRefusal> {
    let snapshot = verified.snapshot();
    if entry.source() != declaration.identity()
        || snapshot.entry(entry.namespace(), entry.package(), entry.version()) != Some(entry)
    {
        return Err(declaration.refusal(RegistryError::SourceNotDeclared {
            requested: entry.source().clone(),
        }));
    }
    if greatest.source() != declaration.identity() {
        return Err(declaration.refusal(RegistryError::SourceNotDeclared {
            requested: greatest.source().clone(),
        }));
    }
    if greatest.minimum_sequence() != snapshot.sequence() {
        return Err(declaration.refusal(RegistryError::Rollback {
            declared: snapshot.sequence(),
            retained_minimum: greatest.minimum_sequence(),
        }));
    }
    let observed = snapshot.content_digest();
    let Some(retained) = greatest.retained_content(snapshot.sequence()) else {
        return Err(declaration.refusal(RegistryError::RetainedContentMissing {
            sequence: snapshot.sequence(),
        }));
    };
    if retained != observed {
        return Err(declaration.refusal(RegistryError::FreezeEquivocation {
            sequence: snapshot.sequence(),
            retained,
            observed,
        }));
    }
    match entry.publication() {
        PublicationState::Published => Ok(entry),
        PublicationState::Yanked => Err(declaration.refusal(RegistryError::ReleaseYanked {
            source: entry.source().clone(),
            package: Arc::from(entry.package().spelling()),
            version: Arc::from(entry.version().as_str()),
            sequence: snapshot.sequence(),
        })),
    }
}

/// One locked dependency of one lockfile record.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct LockedDependency {
    alias: RegistryName,
    source: SourceIdentity,
    namespace: RegistryName,
    package: RegistryName,
    version: PackageVersion,
    target: TargetKind,
    snapshot: SnapshotIdentity,
}

impl LockedDependency {
    /// Validates one source- and target-qualified locked dependency over one locked snapshot.
    pub fn new(
        alias: &str,
        source: SourceIdentity,
        namespace: &str,
        package: &str,
        version: &str,
        target: TargetKind,
        snapshot: SnapshotIdentity,
    ) -> Result<Self, RegistryError> {
        Ok(Self {
            alias: RegistryName::dependency_alias(alias)?,
            source,
            namespace: RegistryName::namespace(namespace)?,
            package: RegistryName::package(package)?,
            version: version_of(version)?,
            target,
            snapshot,
        })
    }

    /// Returns the local dependency alias.
    #[must_use]
    pub const fn alias(&self) -> &RegistryName {
        &self.alias
    }

    /// Returns the authenticated source identity of the locked dependency.
    #[must_use]
    pub const fn source(&self) -> &SourceIdentity {
        &self.source
    }

    /// Returns the locked dependency namespace.
    #[must_use]
    pub const fn namespace(&self) -> &RegistryName {
        &self.namespace
    }

    /// Returns the locked package name.
    #[must_use]
    pub const fn package(&self) -> &RegistryName {
        &self.package
    }

    /// Returns the locked exact version.
    #[must_use]
    pub const fn version(&self) -> &PackageVersion {
        &self.version
    }

    /// Returns the target whose artifact this locked dependency requires.
    #[must_use]
    pub const fn target(&self) -> TargetKind {
        self.target
    }

    /// Returns the locked snapshot identity.
    #[must_use]
    pub const fn snapshot(&self) -> SnapshotIdentity {
        self.snapshot
    }

    /// Returns one stable text form of this locked dependency for evidence derivation.
    #[must_use]
    pub fn canonical_text(&self) -> String {
        format!(
            "{}:{}/{}/{}/{}@{}?target={}#{}",
            self.alias.spelling(),
            self.alias.kind().wire_name(),
            self.source.canonical_text(),
            self.namespace.spelling(),
            self.package.spelling(),
            self.version.as_str(),
            self.target.wire_name(),
            self.snapshot.digest_hex()
        )
    }

    /// Returns whether this locked identity names exactly one snapshot dependency.
    fn matches_snapshot_dependency(&self, dependency: &SnapshotDependency) -> bool {
        self.alias == *dependency.alias()
            && self.source == *dependency.source()
            && self.namespace == *dependency.namespace()
            && self.package == *dependency.package()
            && self.version == *dependency.version()
            && self.target == dependency.target()
            && self.snapshot == dependency.snapshot()
    }
}

/// The declared features, targets, dependencies, interface digests, and generator inputs of
/// one lockfile record.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LockfileInputs {
    /// The selected feature names.
    pub features: Vec<FeatureName>,
    /// The selected target kinds.
    pub targets: Vec<TargetKind>,
    /// The complete target-qualified artifact set.
    pub target_artifacts: Vec<TargetArtifact>,
    /// The locked dependencies.
    pub dependencies: Vec<LockedDependency>,
    /// The pinned interface digests.
    pub interfaces: Vec<[u8; 32]>,
    /// The declared generator input digests.
    pub generator_inputs: Vec<[u8; 32]>,
}

/// One canonical lockfile record binding one declaration's evidence.
///
/// The record binds the source identity, the snapshot proof, the exact version, the features,
/// the targets, the dependencies, the interface digests, and the generator inputs of one
/// declaration, and it carries the evidence digest those fields derive. A record restored
/// from durable bytes carries the evidence that durable form declared, so a stale or tampered
/// record is detectable by recomputation rather than trusted because it parsed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LockfileRecord {
    declaration: usize,
    namespace: RegistryName,
    package: RegistryName,
    version: PackageVersion,
    source: SourceIdentity,
    snapshot: SnapshotIdentity,
    publication: PublicationState,
    manifest: [u8; 32],
    source_content: [u8; 32],
    generated: [u8; 32],
    interface: [u8; 32],
    artifact: [u8; 32],
    features: Vec<FeatureName>,
    targets: Vec<TargetKind>,
    target_artifacts: Vec<TargetArtifact>,
    dependencies: Vec<LockedDependency>,
    interfaces: Vec<[u8; 32]>,
    generator_inputs: Vec<[u8; 32]>,
    evidence: [u8; 32],
}

impl LockfileRecord {
    /// Mints fresh lockfile evidence from a verified new-resolution decision.
    ///
    /// The verified snapshot and its retained greatest state prevent a fresh record from
    /// bypassing yank or rollback checks. Every target-qualified artifact is also checked at
    /// the new-resolution advisory boundary before the record can exist. Historical durable
    /// evidence is instead represented by [`Self::historical`] or [`Self::restore`].
    pub fn mint(
        entry: &SnapshotEntry,
        verified: &VerifiedSnapshot<'_>,
        greatest: &RetainedState,
        declaration: &SourceDeclaration,
        inputs: LockfileInputs,
        advisories: &AdvisoryStore,
    ) -> Result<Self, RegistryRefusal> {
        resolve_new_release(declaration, verified, greatest, entry)?;
        for artifact in entry.target_artifacts() {
            let request = RunRequest::new(
                entry.source().clone(),
                entry.namespace().spelling(),
                entry.package().spelling(),
                entry.version().as_str(),
                artifact.target(),
                artifact.digest(),
            )
            .map_err(|error| RegistryRefusal::at(error, declaration))?;
            advisories.admit_new_resolution(declaration, &request)?;
        }
        Self::bound(entry, verified.snapshot(), declaration, inputs, None)
            .map_err(|error| RegistryRefusal::at(error, declaration))
    }

    /// Restores verified historical lockfile evidence without performing new resolution.
    ///
    /// Historical evidence must have been authenticated while its release was published. A
    /// later yank or advisory therefore cannot be laundered into a fresh resolution, while
    /// the authenticated earlier record remains reproducible. New evidence must use
    /// [`Self::mint`].
    pub fn historical(
        entry: &SnapshotEntry,
        verified: &VerifiedSnapshot<'_>,
        greatest: &RetainedState,
        declaration: &SourceDeclaration,
        inputs: LockfileInputs,
    ) -> Result<Self, RegistryRefusal> {
        Self::verify_historical(entry, verified, greatest, declaration)?;
        Self::bound(entry, verified.snapshot(), declaration, inputs, None)
            .map_err(|error| RegistryRefusal::at(error, declaration))
    }

    /// Restores one historical record from durable bytes after its prior authentication.
    pub fn restore(
        entry: &SnapshotEntry,
        verified: &VerifiedSnapshot<'_>,
        greatest: &RetainedState,
        declaration: &SourceDeclaration,
        inputs: LockfileInputs,
        evidence: [u8; 32],
    ) -> Result<Self, RegistryRefusal> {
        Self::verify_historical(entry, verified, greatest, declaration)?;
        Self::bound(
            entry,
            verified.snapshot(),
            declaration,
            inputs,
            Some(evidence),
        )
        .map_err(|error| RegistryRefusal::at(error, declaration))
    }

    /// Proves that a historical record predates any later yank or revocation decision.
    fn verify_historical(
        entry: &SnapshotEntry,
        verified: &VerifiedSnapshot<'_>,
        greatest: &RetainedState,
        declaration: &SourceDeclaration,
    ) -> Result<(), RegistryRefusal> {
        let snapshot = verified.snapshot();
        if entry.source() != declaration.identity() {
            return Err(declaration.refusal(RegistryError::SourceNotDeclared {
                requested: entry.source().clone(),
            }));
        }
        if snapshot.entry(entry.namespace(), entry.package(), entry.version()) != Some(entry) {
            return Err(
                declaration.refusal(RegistryError::LockfileDeclarationInvalid {
                    field: "lockfile record release",
                    value: Arc::from(coordinate_text(
                        entry.namespace(),
                        entry.package(),
                        entry.version(),
                    )),
                }),
            );
        }
        if greatest.source() != declaration.identity() {
            return Err(declaration.refusal(RegistryError::SourceNotDeclared {
                requested: greatest.source().clone(),
            }));
        }
        if greatest.minimum_sequence() != snapshot.sequence() {
            return Err(declaration.refusal(RegistryError::Rollback {
                declared: snapshot.sequence(),
                retained_minimum: greatest.minimum_sequence(),
            }));
        }
        let Some(retained) = greatest.retained_content(snapshot.sequence()) else {
            return Err(declaration.refusal(RegistryError::RetainedContentMissing {
                sequence: snapshot.sequence(),
            }));
        };
        if retained != snapshot.content_digest() {
            return Err(declaration.refusal(RegistryError::FreezeEquivocation {
                sequence: snapshot.sequence(),
                retained,
                observed: snapshot.content_digest(),
            }));
        }
        if entry.publication() != PublicationState::Published {
            return Err(declaration.refusal(RegistryError::ReleaseYanked {
                source: entry.source().clone(),
                package: Arc::from(entry.package().spelling()),
                version: Arc::from(entry.version().as_str()),
                sequence: snapshot.sequence(),
            }));
        }
        Ok(())
    }

    /// Binds one record, deriving its evidence unless one is declared.
    fn bound(
        entry: &SnapshotEntry,
        snapshot: &MetadataSnapshot,
        declaration: &SourceDeclaration,
        inputs: LockfileInputs,
        evidence: Option<[u8; 32]>,
    ) -> Result<Self, RegistryError> {
        if entry.source() != declaration.identity() {
            return Err(RegistryError::LockfileDeclarationInvalid {
                field: "lockfile record source",
                value: Arc::from(entry.source().canonical_text()),
            });
        }
        if snapshot.entry(entry.namespace(), entry.package(), entry.version()) != Some(entry) {
            return Err(RegistryError::LockfileDeclarationInvalid {
                field: "lockfile record release",
                value: Arc::from(coordinate_text(
                    entry.namespace(),
                    entry.package(),
                    entry.version(),
                )),
            });
        }
        let mut features = inputs.features;
        features.sort();
        features.dedup();
        let mut targets = inputs.targets;
        targets.sort();
        targets.dedup();
        let mut target_artifacts = inputs.target_artifacts;
        target_artifacts.sort();
        target_artifacts.dedup();
        let mut snapshot_target_artifacts = entry.target_artifacts().to_vec();
        snapshot_target_artifacts.sort();
        snapshot_target_artifacts.dedup();
        let artifact_targets = target_artifacts
            .iter()
            .map(TargetArtifact::target)
            .collect::<Vec<_>>();
        if target_artifacts != snapshot_target_artifacts || targets != artifact_targets {
            return Err(RegistryError::LockfileDeclarationInvalid {
                field: "lockfile record targets",
                value: Arc::from(coordinate_text(
                    entry.namespace(),
                    entry.package(),
                    entry.version(),
                )),
            });
        }
        let mut dependencies = inputs.dependencies;
        dependencies.sort();
        dependencies.dedup();
        let mut snapshot_dependencies = entry.dependencies().to_vec();
        snapshot_dependencies.sort();
        snapshot_dependencies.dedup();
        if dependencies.len() != snapshot_dependencies.len()
            || !dependencies.iter().zip(&snapshot_dependencies).all(
                |(locked, snapshot_dependency)| {
                    locked.matches_snapshot_dependency(snapshot_dependency)
                },
            )
        {
            return Err(RegistryError::LockfileDeclarationInvalid {
                field: "lockfile record dependencies",
                value: Arc::from(coordinate_text(
                    entry.namespace(),
                    entry.package(),
                    entry.version(),
                )),
            });
        }
        let mut interfaces = inputs.interfaces;
        interfaces.sort();
        interfaces.dedup();
        let mut generator_inputs = inputs.generator_inputs;
        generator_inputs.sort();
        generator_inputs.dedup();
        let mut record = Self {
            declaration: declaration.index(),
            namespace: entry.namespace().clone(),
            package: entry.package().clone(),
            version: entry.version().clone(),
            source: entry.source().clone(),
            snapshot: snapshot.identity(),
            publication: entry.publication(),
            manifest: entry.manifest(),
            source_content: entry.source_content(),
            generated: entry.generated(),
            interface: entry.interface(),
            artifact: entry.artifact(),
            features,
            targets,
            target_artifacts,
            dependencies,
            interfaces,
            generator_inputs,
            evidence: [0; 32],
        };
        let derived = record.attest();
        record.evidence = evidence.unwrap_or(derived);
        Ok(record)
    }

    /// Returns the recomputed evidence digest of this record.
    ///
    /// The evidence digests the set of each declared part, so one record has one evidence
    /// digest under every permutation of its feature, target, dependency, interface, and
    /// generator-input lists.
    #[must_use]
    pub fn attest(&self) -> [u8; 32] {
        let mut fields: Vec<Vec<u8>> = vec![
            self.declaration.to_be_bytes().to_vec(),
            self.namespace.spelling().as_bytes().to_vec(),
            self.package.spelling().as_bytes().to_vec(),
            self.version.as_str().as_bytes().to_vec(),
            self.source.digest().to_vec(),
            self.snapshot.digest().to_vec(),
            self.publication.wire_name().as_bytes().to_vec(),
            self.manifest.to_vec(),
            self.source_content.to_vec(),
            self.generated.to_vec(),
            self.interface.to_vec(),
            self.artifact.to_vec(),
        ];
        fields.extend([
            attest_lockfile_collection(
                LOCKFILE_FEATURES_DOMAIN,
                self.features
                    .iter()
                    .map(|name| name.as_str().as_bytes().to_vec()),
            )
            .to_vec(),
            attest_lockfile_collection(
                LOCKFILE_TARGETS_DOMAIN,
                self.targets
                    .iter()
                    .map(|kind| kind.wire_name().as_bytes().to_vec()),
            )
            .to_vec(),
            attest_lockfile_collection(
                LOCKFILE_TARGET_ARTIFACTS_DOMAIN,
                self.target_artifacts
                    .iter()
                    .map(|artifact| artifact.canonical_text().into_bytes()),
            )
            .to_vec(),
            attest_lockfile_collection(
                LOCKFILE_DEPENDENCIES_DOMAIN,
                self.dependencies
                    .iter()
                    .map(|dependency| dependency.canonical_text().into_bytes()),
            )
            .to_vec(),
            attest_lockfile_collection(
                LOCKFILE_INTERFACES_DOMAIN,
                self.interfaces.iter().map(|digest| digest.to_vec()),
            )
            .to_vec(),
            attest_lockfile_collection(
                LOCKFILE_GENERATOR_INPUTS_DOMAIN,
                self.generator_inputs.iter().map(|digest| digest.to_vec()),
            )
            .to_vec(),
        ]);
        let borrowed = fields.iter().map(Vec::as_slice).collect::<Vec<_>>();
        digest_fields(LOCKFILE_RECORD_DOMAIN, &borrowed)
    }

    /// Returns the bound declaration index.
    #[must_use]
    pub const fn declaration(&self) -> usize {
        self.declaration
    }

    /// Returns the bound namespace.
    #[must_use]
    pub const fn namespace(&self) -> &RegistryName {
        &self.namespace
    }

    /// Returns the bound package name.
    #[must_use]
    pub const fn package(&self) -> &RegistryName {
        &self.package
    }

    /// Returns the bound exact version.
    #[must_use]
    pub const fn version(&self) -> &PackageVersion {
        &self.version
    }

    /// Returns the bound source identity.
    #[must_use]
    pub const fn source(&self) -> &SourceIdentity {
        &self.source
    }

    /// Returns the bound snapshot proof.
    #[must_use]
    pub const fn snapshot(&self) -> SnapshotIdentity {
        self.snapshot
    }

    /// Returns the recorded publication state.
    #[must_use]
    pub const fn publication(&self) -> PublicationState {
        self.publication
    }

    /// Returns the bound manifest digest.
    #[must_use]
    pub const fn manifest(&self) -> [u8; 32] {
        self.manifest
    }

    /// Returns the bound complete source-content digest.
    #[must_use]
    pub const fn source_content(&self) -> [u8; 32] {
        self.source_content
    }

    /// Returns the bound generated-output digest.
    #[must_use]
    pub const fn generated(&self) -> [u8; 32] {
        self.generated
    }

    /// Returns the bound public-interface digest.
    #[must_use]
    pub const fn interface(&self) -> [u8; 32] {
        self.interface
    }

    /// Returns the bound artifact digest.
    #[must_use]
    pub const fn artifact(&self) -> [u8; 32] {
        self.artifact
    }

    /// Returns the recorded feature names in canonical order.
    #[must_use]
    pub fn features(&self) -> &[FeatureName] {
        &self.features
    }

    /// Returns the recorded target kinds in canonical order.
    #[must_use]
    pub fn targets(&self) -> &[TargetKind] {
        &self.targets
    }

    /// Returns the target-qualified immutable artifact evidence in canonical order.
    #[must_use]
    pub fn target_artifacts(&self) -> &[TargetArtifact] {
        &self.target_artifacts
    }

    /// Returns the recorded dependencies in canonical order.
    #[must_use]
    pub fn dependencies(&self) -> &[LockedDependency] {
        &self.dependencies
    }

    /// Returns the recorded interface digests in canonical order.
    #[must_use]
    pub fn interfaces(&self) -> &[[u8; 32]] {
        &self.interfaces
    }

    /// Returns the recorded generator input digests in canonical order.
    #[must_use]
    pub fn generator_inputs(&self) -> &[[u8; 32]] {
        &self.generator_inputs
    }

    /// Returns the evidence digest this record carries.
    #[must_use]
    pub const fn evidence(&self) -> [u8; 32] {
        self.evidence
    }
}

/// One canonical lockfile over one set of records.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Lockfile {
    records: Vec<LockfileRecord>,
    canonical: Arc<[u8]>,
    digest: [u8; 32],
}

impl Lockfile {
    /// Builds one lockfile from records, refusing one declaration recorded twice.
    pub fn new(records: &[LockfileRecord]) -> Result<Self, RegistryError> {
        let mut ordered = records.to_vec();
        ordered.sort_by_key(LockfileRecord::declaration);
        for pair in ordered.windows(2) {
            if pair[0].declaration() == pair[1].declaration() {
                return Err(RegistryError::LockfileDeclarationInvalid {
                    field: "lockfile declaration",
                    value: Arc::from(pair[1].declaration().to_string()),
                });
            }
        }
        let mut canonical = String::from("{\"records\":[");
        for (index, record) in ordered.iter().enumerate() {
            if index > 0 {
                canonical.push(',');
            }
            canonical.push_str("{\"declaration\":");
            canonical.push_str(&record.declaration().to_string());
            canonical.push_str(",\"evidence\":");
            push_json_string(&mut canonical, &hex(&record.evidence()));
            canonical.push_str(",\"artifact\":");
            push_json_string(&mut canonical, &hex(&record.artifact()));
            canonical.push_str(",\"target_artifacts\":[");
            for (artifact_index, artifact) in record.target_artifacts().iter().enumerate() {
                if artifact_index > 0 {
                    canonical.push(',');
                }
                push_json_string(&mut canonical, &artifact.canonical_text());
            }
            canonical.push(']');
            canonical.push_str(",\"generated\":");
            push_json_string(&mut canonical, &hex(&record.generated()));
            canonical.push_str(",\"interface\":");
            push_json_string(&mut canonical, &hex(&record.interface()));
            canonical.push_str(",\"manifest\":");
            push_json_string(&mut canonical, &hex(&record.manifest()));
            canonical.push_str(",\"namespace\":");
            push_json_string(&mut canonical, record.namespace().spelling());
            canonical.push_str(",\"package\":");
            push_json_string(&mut canonical, record.package().spelling());
            canonical.push_str(",\"publication\":");
            push_json_string(&mut canonical, record.publication().wire_name());
            canonical.push_str(",\"snapshot\":");
            push_json_string(&mut canonical, &record.snapshot().digest_hex());
            canonical.push_str(",\"source\":");
            push_json_string(&mut canonical, record.source().canonical_text());
            canonical.push_str(",\"source_content\":");
            push_json_string(&mut canonical, &hex(&record.source_content()));
            canonical.push_str(",\"version\":");
            push_json_string(&mut canonical, record.version().as_str());
            canonical.push('}');
        }
        canonical.push_str("]}");
        let digest = digest_fields(LOCKFILE_DOMAIN, &[canonical.as_bytes()]);
        Ok(Self {
            records: ordered,
            canonical: Arc::from(canonical.into_bytes()),
            digest,
        })
    }

    /// Returns the records in declaration order.
    #[must_use]
    pub fn records(&self) -> &[LockfileRecord] {
        &self.records
    }

    /// Returns one record by declaration index.
    #[must_use]
    pub fn record(&self, declaration: usize) -> Option<&LockfileRecord> {
        self.records
            .iter()
            .find(|record| record.declaration() == declaration)
    }

    /// Returns the one canonical encoding of this lockfile.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }

    /// Returns the lockfile digest.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// Returns the lowercase hexadecimal lockfile digest.
    #[must_use]
    pub fn digest_hex(&self) -> String {
        hex(&self.digest)
    }

    /// Replays one existing lockfile, admitting a yanked locked release.
    ///
    /// Replay is not resolution: a lockfile that recorded a release before it was yanked stays
    /// reproducible, so the records come back unchanged and a yank never rewrites them.
    #[must_use]
    pub fn replay(&self) -> &[LockfileRecord] {
        &self.records
    }

    /// Refuses a single-source rewrite that would silently drop a currently yanked release.
    ///
    /// A lockfile containing another source needs [`Self::rewrite_kept_closure`] so every
    /// source represented in its records supplies its greatest verified snapshot.
    pub fn rewrite_kept(
        &self,
        declaration: &SourceDeclaration,
        kept: &[usize],
        verified: &VerifiedSnapshot<'_>,
        greatest: &RetainedState,
    ) -> Result<Self, RegistryRefusal> {
        self.rewrite_kept_closure(
            std::slice::from_ref(declaration),
            kept,
            &[(verified, greatest)],
        )
    }

    /// Refuses a rewrite that drops a release yanked by any greatest verified source state.
    ///
    /// Every source represented in this lockfile must provide one verified snapshot and its
    /// matching retained greatest state. A missing source proof, rollback, or equivocation
    /// refuses the whole rewrite rather than leaving a foreign record outside yank protection.
    pub fn rewrite_kept_closure(
        &self,
        declarations: &[SourceDeclaration],
        kept: &[usize],
        greatest: &[(&VerifiedSnapshot<'_>, &RetainedState)],
    ) -> Result<Self, RegistryRefusal> {
        if self.records.is_empty() {
            return Self::new(&[]).map_err(|error| {
                RegistryRefusal::unbound(
                    error,
                    0,
                    SourceIdentity::registry("empty-lockfile")
                        .unwrap_or_else(|_| unreachable!("fixed source identity is valid")),
                )
            });
        }
        if let Some(index) = kept
            .iter()
            .copied()
            .find(|index| *index >= self.records.len())
        {
            let record = &self.records[0];
            let declaration = rewrite_declaration(declarations, record, 0)?;
            return Err(
                declaration.refusal(RegistryError::LockfileDeclarationInvalid {
                    field: "lockfile rewrite kept",
                    value: Arc::from(index.to_string()),
                }),
            );
        }
        let mut snapshots = BTreeMap::new();
        for (record_index, record) in self.records.iter().enumerate() {
            let declaration = rewrite_declaration(declarations, record, record_index)?;
            if snapshots.contains_key(record.source()) {
                continue;
            }
            let candidates = greatest
                .iter()
                .filter(|(verified, retained)| {
                    verified.snapshot().source() == record.source()
                        && retained.source() == record.source()
                })
                .collect::<Vec<_>>();
            let (verified, retained) = match candidates.as_slice() {
                [] => {
                    return Err(declaration.refusal(RegistryError::SourceNotDeclared {
                        requested: record.source().clone(),
                    }));
                }
                [candidate] => *candidate,
                supplied => {
                    return Err(declaration.refusal(RegistryError::RetainedStateAmbiguous {
                        source: record.source().clone(),
                        supplied: supplied.len(),
                    }));
                }
            };
            let snapshot = verified.snapshot();
            if retained.minimum_sequence() != snapshot.sequence() {
                return Err(declaration.refusal(RegistryError::Rollback {
                    declared: snapshot.sequence(),
                    retained_minimum: retained.minimum_sequence(),
                }));
            }
            let observed = snapshot.content_digest();
            if retained.retained_content(snapshot.sequence()) != Some(observed) {
                return Err(declaration.refusal(RegistryError::FreezeEquivocation {
                    sequence: snapshot.sequence(),
                    retained: retained
                        .retained_content(snapshot.sequence())
                        .unwrap_or([0; 32]),
                    observed,
                }));
            }
            snapshots.insert(record.source().clone(), snapshot);
        }
        let mut records = Vec::new();
        for (index, record) in self.records.iter().enumerate() {
            let declaration = rewrite_declaration(declarations, record, index)?;
            if kept.contains(&index) {
                records.push(record.clone());
                continue;
            }
            let currently_yanked = snapshots[record.source()]
                .entry(record.namespace(), record.package(), record.version())
                .is_some_and(|entry| entry.publication() == PublicationState::Yanked);
            if record.publication() == PublicationState::Yanked || currently_yanked {
                return Err(declaration.refusal(RegistryError::LockfileRewriteRefused {
                    release: Arc::from(coordinate_text(
                        record.namespace(),
                        record.package(),
                        record.version(),
                    )),
                }));
            }
        }
        let declaration = rewrite_declaration(declarations, &self.records[0], 0)?;
        Self::new(&records).map_err(|error| declaration.refusal(error))
    }

    /// Binds every declaration's evidence before any source is parsed.
    ///
    /// Binding refuses a declaration without a record, a record that binds another source than
    /// its declaration, a record whose declared evidence differs from its recomputed evidence,
    /// a record bound to another snapshot than the verified one, and a record whose release the
    /// verified snapshot does not record. Only when every declaration is bound does the
    /// returned [`EvidenceGate`] exist, so resolution has no path to parse a source whose
    /// evidence is not bound.
    fn bind<'a>(
        &'a self,
        declarations: &'a [SourceDeclaration],
        snapshots: &[&'a MetadataSnapshot],
    ) -> Result<EvidenceGate<'a>, RegistryRefusal> {
        let snapshot = snapshots[0];
        if declarations.is_empty() {
            return Err(RegistryRefusal::unbound(
                RegistryError::AttributionMissing {
                    declared: 0,
                    attributed: 0,
                },
                0,
                snapshot.entries()[0].source().clone(),
            ));
        }
        validate_declaration_indices(declarations)?;
        let mut bound = Vec::new();
        for declaration in declarations {
            let found = self
                .records
                .iter()
                .enumerate()
                .filter(|(_, record)| record.declaration() == declaration.index())
                .collect::<Vec<_>>();
            let (index, record) = match found.as_slice() {
                [] => {
                    return Err(RegistryRefusal::at(
                        RegistryError::LockfileEvidenceUnbound {
                            declaration: declaration.index(),
                        },
                        declaration,
                    ));
                }
                [(index, record)] => (*index, *record),
                _ => {
                    return Err(RegistryRefusal::at(
                        RegistryError::LockfileDeclarationInvalid {
                            field: "lockfile record binding",
                            value: Arc::from(declaration.index().to_string()),
                        },
                        declaration,
                    ));
                }
            };
            if record.source() != declaration.identity() {
                return Err(RegistryRefusal::at(
                    RegistryError::LockfileEvidenceStale {
                        record: index,
                        defect: EvidenceDefect::ChangedSource,
                        expected: declaration.identity().digest(),
                        observed: record.source().digest(),
                    },
                    declaration,
                ));
            }
            let attested = record.attest();
            if attested != record.evidence() {
                return Err(RegistryRefusal::at(
                    RegistryError::LockfileEvidenceStale {
                        record: index,
                        defect: EvidenceDefect::TamperedEvidence,
                        expected: attested,
                        observed: record.evidence(),
                    },
                    declaration,
                ));
            }
            let Some(source_snapshot) = snapshots.iter().copied().find(|candidate| {
                candidate.source() == record.source() && candidate.identity() == record.snapshot()
            }) else {
                return Err(RegistryRefusal::at(
                    RegistryError::LockfileEvidenceStale {
                        record: index,
                        defect: EvidenceDefect::ChangedSnapshot,
                        expected: snapshot.identity().digest(),
                        observed: record.snapshot().digest(),
                    },
                    declaration,
                ));
            };
            if record.snapshot() != source_snapshot.identity() {
                return Err(RegistryRefusal::at(
                    RegistryError::LockfileEvidenceStale {
                        record: index,
                        defect: EvidenceDefect::ChangedSnapshot,
                        expected: source_snapshot.identity().digest(),
                        observed: record.snapshot().digest(),
                    },
                    declaration,
                ));
            }
            let release_matches = source_snapshot
                .entry(record.namespace(), record.package(), record.version())
                .is_some_and(|entry| {
                    let mut dependencies = entry.dependencies().to_vec();
                    dependencies.sort();
                    dependencies.dedup();
                    entry.source() == record.source()
                        && entry.publication() == record.publication()
                        && entry.manifest() == record.manifest()
                        && entry.source_content() == record.source_content()
                        && entry.generated() == record.generated()
                        && entry.interface() == record.interface()
                        && entry.artifact() == record.artifact()
                        && entry.target_artifacts() == record.target_artifacts()
                        && record.dependencies().len() == dependencies.len()
                        && record.dependencies().iter().zip(&dependencies).all(
                            |(locked, dependency)| locked.matches_snapshot_dependency(dependency),
                        )
                });
            if !release_matches {
                return Err(RegistryRefusal::at(
                    RegistryError::LockfileEvidenceStale {
                        record: index,
                        defect: EvidenceDefect::UnrecordedRelease,
                        expected: source_snapshot.content_digest(),
                        observed: record.snapshot().digest(),
                    },
                    declaration,
                ));
            }
            for dependency in record.dependencies() {
                let snapshot_verified = snapshots.iter().copied().any(|candidate| {
                    candidate.source() == dependency.source()
                        && candidate.identity() == dependency.snapshot()
                });
                let covered = self.records.iter().any(|candidate| {
                    candidate.source() == dependency.source()
                        && candidate.namespace() == dependency.namespace()
                        && candidate.package() == dependency.package()
                        && candidate.version() == dependency.version()
                        && candidate.snapshot() == dependency.snapshot()
                        && candidate
                            .target_artifacts()
                            .iter()
                            .any(|artifact| artifact.target() == dependency.target())
                });
                if !snapshot_verified || !covered {
                    return Err(RegistryRefusal::at(
                        RegistryError::LockfileEvidenceStale {
                            record: index,
                            defect: EvidenceDefect::MissingDependency,
                            expected: dependency.snapshot().digest(),
                            observed: [0; 32],
                        },
                        declaration,
                    )
                    .with_dependency(dependency));
                }
            }
            bound.push(declaration.index());
        }
        if let Some((index, record)) = self
            .records
            .iter()
            .enumerate()
            .find(|(_, record)| !bound.contains(&record.declaration()))
        {
            return Err(RegistryRefusal::unbound(
                RegistryError::LockfileEvidenceStale {
                    record: index,
                    defect: EvidenceDefect::ExtraRecord,
                    expected: snapshot.identity().digest(),
                    observed: record.snapshot().digest(),
                },
                index,
                record.source().clone(),
            ));
        }
        Ok(EvidenceGate {
            lockfile: self,
            snapshot,
            declarations,
            bound,
        })
    }
}

/// Finds the unique declaration that owns one record considered during a rewrite.
///
/// A rewrite has no fallback declaration: a missing or ambiguous edge is itself an
/// attributable failure, so the caller never indexes an empty declaration slice.
fn rewrite_declaration<'a>(
    declarations: &'a [SourceDeclaration],
    record: &LockfileRecord,
    record_index: usize,
) -> Result<&'a SourceDeclaration, RegistryRefusal> {
    let matches = declarations
        .iter()
        .filter(|declaration| {
            declaration.index() == record.declaration() && declaration.identity() == record.source()
        })
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [declaration] => Ok(*declaration),
        _ => Err(RegistryRefusal::unbound(
            RegistryError::AttributionMissing {
                declared: declarations.len(),
                attributed: record_index,
            },
            record_index,
            record.source().clone(),
        )),
    }
}

/// The evidence witness that admits parsing one declaration's source.
///
/// The witness exists only through [`Lockfile::bind`], so a caller has no way to reach a
/// source-parsing decision whose evidence was not bound first.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceGate<'a> {
    lockfile: &'a Lockfile,
    snapshot: &'a MetadataSnapshot,
    declarations: &'a [SourceDeclaration],
    bound: Vec<usize>,
}

/// The verified route by which a final acquisition received its delivered bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcquisitionRoute {
    kind: AcquisitionRouteKind,
    mirror: Option<Arc<str>>,
    source: Option<SourceIdentity>,
    snapshot: Option<SnapshotIdentity>,
}

/// The non-forgeable delivery kind retained by one final acquisition admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcquisitionRouteKind {
    /// The declared source delivered the lockfile-bound bytes directly.
    Direct,
    /// A verified vendor proof bound the delivery to this source and snapshot.
    Vendor,
    /// A verified mirror proof bound the delivery to this source and snapshot.
    Mirror,
}

impl AcquisitionRoute {
    fn direct(source: SourceIdentity, snapshot: SnapshotIdentity) -> Self {
        Self {
            kind: AcquisitionRouteKind::Direct,
            mirror: None,
            source: Some(source),
            snapshot: Some(snapshot),
        }
    }

    fn vendor(source: SourceIdentity, snapshot: SnapshotIdentity) -> Self {
        Self {
            kind: AcquisitionRouteKind::Vendor,
            mirror: None,
            source: Some(source),
            snapshot: Some(snapshot),
        }
    }

    fn verified_mirror(
        mirror: Arc<str>,
        source: SourceIdentity,
        snapshot: SnapshotIdentity,
    ) -> Self {
        Self {
            kind: AcquisitionRouteKind::Mirror,
            mirror: Some(mirror),
            source: Some(source),
            snapshot: Some(snapshot),
        }
    }

    /// Returns the delivery kind proven during final admission.
    #[must_use]
    pub const fn kind(&self) -> AcquisitionRouteKind {
        self.kind
    }

    /// Returns the verified mirror spelling, when mirror delivery was admitted.
    #[must_use]
    pub fn mirror(&self) -> Option<&str> {
        self.mirror.as_deref()
    }

    /// Returns the authenticated source verified for this delivery route.
    #[must_use]
    pub const fn source(&self) -> Option<&SourceIdentity> {
        self.source.as_ref()
    }

    /// Returns the authenticated snapshot verified for this delivery route.
    #[must_use]
    pub const fn snapshot(&self) -> Option<SnapshotIdentity> {
        self.snapshot
    }
}

/// The one final witness that admits acquisition of one delivered release.
///
/// This witness exists only after a [`VerifiedSnapshot`] bound the complete lockfile and
/// [`EvidenceGate::admit_acquisition`] checked the delivered bytes and the selected advisory
/// boundary. It therefore carries one source, snapshot, declaration, publication state, and
/// artifact identity without making any of them independently forgeable admission evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcquisitionAdmission<'a> {
    source: &'a SourceIdentity,
    snapshot: SnapshotIdentity,
    declaration: usize,
    route: AcquisitionRoute,
    publication: PublicationState,
    target: TargetKind,
    artifact: [u8; 32],
}

impl<'a> AcquisitionAdmission<'a> {
    /// Returns the authenticated source identity admitted for acquisition.
    #[must_use]
    pub const fn source(&self) -> &'a SourceIdentity {
        self.source
    }

    /// Returns the verified snapshot identity that admitted this acquisition.
    #[must_use]
    pub const fn snapshot(&self) -> SnapshotIdentity {
        self.snapshot
    }

    /// Returns the declaration whose lockfile evidence admitted this acquisition.
    #[must_use]
    pub const fn declaration(&self) -> usize {
        self.declaration
    }

    /// Returns the verified delivery route and retained source proof for this acquisition.
    #[must_use]
    pub const fn route(&self) -> &AcquisitionRoute {
        &self.route
    }

    /// Returns the authenticated publication state bound by the lockfile record.
    #[must_use]
    pub const fn publication(&self) -> PublicationState {
        self.publication
    }

    /// Returns the target whose immutable artifact passed final acquisition.
    #[must_use]
    pub const fn target(&self) -> TargetKind {
        self.target
    }

    /// Returns the exact delivered artifact digest that passed admission.
    #[must_use]
    pub const fn artifact(&self) -> [u8; 32] {
        self.artifact
    }
}

/// One complete release byte set presented for parsing.
///
/// This is a delivery observation, not a trust decision. [`EvidenceGate::admit_parse`] compares
/// every coordinate with the authenticated lockfile record before any delivered bytes are parsed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveredRelease {
    source: SourceIdentity,
    route: AcquisitionRoute,
    proof: Option<AcquisitionProof>,
    namespace: RegistryName,
    package: RegistryName,
    version: PackageVersion,
    publication: PublicationState,
    manifest: [u8; 32],
    source_content: [u8; 32],
    generated: [u8; 32],
    interface: [u8; 32],
    artifact: [u8; 32],
    target_artifacts: Vec<TargetArtifact>,
    dependencies: Vec<SnapshotDependency>,
}

impl DeliveredRelease {
    /// Declares the byte digests and authenticated route of a direct delivery.
    #[must_use]
    pub fn direct(entry: &SnapshotEntry, snapshot: SnapshotIdentity) -> Self {
        Self {
            source: entry.source().clone(),
            route: AcquisitionRoute::direct(entry.source().clone(), snapshot),
            proof: None,
            namespace: entry.namespace().clone(),
            package: entry.package().clone(),
            version: entry.version().clone(),
            publication: entry.publication(),
            manifest: entry.manifest(),
            source_content: entry.source_content(),
            generated: entry.generated(),
            interface: entry.interface(),
            artifact: entry.artifact(),
            target_artifacts: entry.target_artifacts().to_vec(),
            dependencies: entry.dependencies().to_vec(),
        }
    }

    /// Declares the byte digests and verified vendor route of a delivery.
    #[must_use]
    pub fn vendor(entry: &SnapshotEntry, report: &VendorReport) -> Self {
        Self {
            source: entry.source().clone(),
            route: AcquisitionRoute::vendor(report.source().clone(), report.identity()),
            proof: None,
            namespace: entry.namespace().clone(),
            package: entry.package().clone(),
            version: entry.version().clone(),
            publication: entry.publication(),
            manifest: entry.manifest(),
            source_content: entry.source_content(),
            generated: entry.generated(),
            interface: entry.interface(),
            artifact: entry.artifact(),
            target_artifacts: entry.target_artifacts().to_vec(),
            dependencies: entry.dependencies().to_vec(),
        }
    }

    /// Declares the byte digests and verified mirror route of a delivery.
    #[must_use]
    pub fn mirror(entry: &SnapshotEntry, report: &MirrorReport) -> Self {
        Self {
            source: entry.source().clone(),
            route: AcquisitionRoute::verified_mirror(
                Arc::from(report.mirror()),
                report.source().clone(),
                report.identity(),
            ),
            proof: None,
            namespace: entry.namespace().clone(),
            package: entry.package().clone(),
            version: entry.version().clone(),
            publication: entry.publication(),
            manifest: entry.manifest(),
            source_content: entry.source_content(),
            generated: entry.generated(),
            interface: entry.interface(),
            artifact: entry.artifact(),
            target_artifacts: entry.target_artifacts().to_vec(),
            dependencies: entry.dependencies().to_vec(),
        }
    }

    /// Binds a verified immutable VCS checkout to this delivery.
    #[must_use]
    pub fn with_vcs_proof(mut self, proof: VerifiedCheckout) -> Self {
        self.proof = Some(AcquisitionProof::Vcs(proof));
        self
    }

    /// Binds verified immutable path content to this delivery.
    #[must_use]
    pub fn with_path_proof(mut self, proof: VerifiedContent) -> Self {
        self.proof = Some(AcquisitionProof::Path(proof));
        self
    }

    /// Returns this delivery with changed target artifacts while preserving its route evidence.
    #[must_use]
    pub fn with_target_artifacts(mut self, target_artifacts: Vec<TargetArtifact>) -> Self {
        self.target_artifacts = target_artifacts;
        self
    }
}

impl<'a> EvidenceGate<'a> {
    /// Returns the bound lockfile.
    #[must_use]
    pub const fn lockfile(&self) -> &'a Lockfile {
        self.lockfile
    }

    /// Returns the authenticated snapshot identity the evidence was bound against.
    #[must_use]
    pub fn snapshot(&self) -> SnapshotIdentity {
        self.snapshot.identity()
    }

    /// Returns the number of bound declarations.
    #[must_use]
    pub fn bound(&self) -> usize {
        self.bound.len()
    }

    /// Verifies all lockfile-bound delivery coordinates before acquisition can parse a release.
    fn admit_parse(
        &self,
        declaration_index: usize,
        delivered: &DeliveredRelease,
    ) -> Result<&'a SourceIdentity, RegistryRefusal> {
        let declaration = match self
            .declarations
            .iter()
            .find(|declaration| declaration.index() == declaration_index)
        {
            Some(declaration) => declaration,
            None => {
                return Err(RegistryRefusal::unbound(
                    RegistryError::AttributionMissing {
                        declared: self.declarations.len(),
                        attributed: 0,
                    },
                    declaration_index,
                    delivered.source.clone(),
                ));
            }
        };
        if !self.bound.contains(&declaration_index) {
            return Err(RegistryRefusal::at(
                RegistryError::LockfileEvidenceUnbound {
                    declaration: declaration_index,
                },
                declaration,
            ));
        }
        let Some(record) = self.lockfile.record(declaration_index) else {
            return Err(RegistryRefusal::at(
                RegistryError::LockfileEvidenceUnbound {
                    declaration: declaration_index,
                },
                declaration,
            ));
        };
        if delivered.namespace != *record.namespace()
            || delivered.package != *record.package()
            || delivered.version != *record.version()
            || delivered.publication != record.publication()
        {
            return Err(RegistryRefusal::at(
                RegistryError::LockfileEvidenceStale {
                    record: declaration_index,
                    defect: EvidenceDefect::ChangedDelivery,
                    expected: record.artifact(),
                    observed: delivered.artifact,
                },
                declaration,
            ));
        }
        let expected = [
            record.source().digest(),
            record.manifest(),
            record.source_content(),
            record.generated(),
            record.interface(),
            record.artifact(),
        ];
        let observed = [
            delivered.source.digest(),
            delivered.manifest,
            delivered.source_content,
            delivered.generated,
            delivered.interface,
            delivered.artifact,
        ];
        if let Some((expected, observed)) = expected
            .into_iter()
            .zip(observed)
            .find(|(expected, observed)| expected != observed)
        {
            return Err(RegistryRefusal::at(
                RegistryError::LockfileEvidenceStale {
                    record: declaration_index,
                    defect: EvidenceDefect::ChangedDelivery,
                    expected,
                    observed,
                },
                declaration,
            ));
        }
        let expected_targets = target_artifact_set_digest(record.target_artifacts());
        let observed_targets = target_artifact_set_digest(&delivered.target_artifacts);
        if expected_targets != observed_targets {
            return Err(RegistryRefusal::at(
                RegistryError::LockfileEvidenceStale {
                    record: declaration_index,
                    defect: EvidenceDefect::ChangedDelivery,
                    expected: expected_targets,
                    observed: observed_targets,
                },
                declaration,
            ));
        }
        let mut expected_dependencies = record.dependencies().to_vec();
        expected_dependencies.sort();
        expected_dependencies.dedup();
        let mut observed_dependencies = delivered.dependencies.clone();
        observed_dependencies.sort();
        observed_dependencies.dedup();
        if expected_dependencies.len() != observed_dependencies.len()
            || !expected_dependencies
                .iter()
                .zip(&observed_dependencies)
                .all(|(locked, delivered)| locked.matches_snapshot_dependency(delivered))
        {
            let expected = attest_lockfile_collection(
                LOCKFILE_DEPENDENCIES_DOMAIN,
                expected_dependencies
                    .iter()
                    .map(|dependency| dependency.canonical_text().into_bytes()),
            );
            let observed = attest_lockfile_collection(
                LOCKFILE_DEPENDENCIES_DOMAIN,
                observed_dependencies
                    .iter()
                    .map(|dependency| dependency.canonical_text().into_bytes()),
            );
            return Err(RegistryRefusal::at(
                RegistryError::LockfileEvidenceStale {
                    record: declaration_index,
                    defect: EvidenceDefect::ChangedDelivery,
                    expected,
                    observed,
                },
                declaration,
            ));
        }
        Ok(declaration.identity())
    }

    /// Admits one delivered release for a new build after every acquisition check succeeds.
    ///
    /// The returned witness closes the verified snapshot, whole-lockfile closure, immutable
    /// publication state, complete delivered bytes, and the declared new-build revocation
    /// boundary in one value. A yanked record remains reproducible here because this is an
    /// existing lockfile acquisition; [`resolve_new_release`] separately refuses a new yank
    /// selection before it can produce lockfile evidence.
    pub fn admit_acquisition(
        &self,
        declaration_index: usize,
        target: TargetKind,
        delivered: &DeliveredRelease,
        advisories: &AdvisoryStore,
    ) -> Result<AcquisitionAdmission<'a>, RegistryRefusal> {
        let declaration = match self
            .declarations
            .iter()
            .find(|declaration| declaration.index() == declaration_index)
        {
            Some(declaration) => declaration,
            None => {
                return Err(RegistryRefusal::unbound(
                    RegistryError::AttributionMissing {
                        declared: self.declarations.len(),
                        attributed: 0,
                    },
                    declaration_index,
                    delivered.source.clone(),
                ));
            }
        };
        let Some(record) = self.lockfile.record(declaration_index) else {
            return Err(RegistryRefusal::at(
                RegistryError::LockfileEvidenceUnbound {
                    declaration: declaration_index,
                },
                declaration,
            ));
        };
        let Some(target_artifact) = record
            .target_artifacts()
            .iter()
            .find(|artifact| artifact.target() == target)
        else {
            return Err(declaration.refusal(RegistryError::LockfileEvidenceStale {
                record: declaration_index,
                defect: EvidenceDefect::ChangedDelivery,
                expected: target_artifact_set_digest(record.target_artifacts()),
                observed: [0; 32],
            }));
        };
        let request = RunRequest::new(
            declaration.identity().clone(),
            record.namespace().spelling(),
            record.package().spelling(),
            record.version().as_str(),
            target,
            target_artifact.digest(),
        )
        .map_err(|error| RegistryRefusal::at(error, declaration))?;
        advisories.admit_new_build(declaration, &request)?;
        let source = self.admit_parse(declaration_index, delivered)?;
        if delivered.route.source() != Some(source)
            || delivered.route.snapshot() != Some(record.snapshot())
        {
            return Err(declaration.refusal(RegistryError::MirrorIdentityMismatch {
                mirror: Arc::from("delivery route"),
                expected: Arc::from(format!(
                    "{}#{}",
                    source.digest_hex(),
                    record.snapshot().digest_hex()
                )),
                observed: Arc::from(format!(
                    "{}#{}",
                    delivered
                        .route
                        .source()
                        .map_or_else(|| String::from("missing"), SourceIdentity::digest_hex),
                    delivered
                        .route
                        .snapshot()
                        .map_or_else(|| String::from("missing"), |snapshot| snapshot.digest_hex(),)
                )),
                defect: MirrorDefect::SnapshotIdentity,
            }));
        }
        match (source.kind(), delivered.proof.as_ref()) {
            (SourceKind::Vcs, Some(AcquisitionProof::Vcs(proof)))
                if proof.source() == source
                    && proof.content().digest() == record.source_content() => {}
            (SourceKind::Path, Some(AcquisitionProof::Path(proof)))
                if proof.source() == source && proof.digest() == record.source_content() => {}
            (SourceKind::Vendored, Some(AcquisitionProof::Path(proof)))
                if proof.source() == source && proof.digest() == record.source_content() => {}
            (SourceKind::Vendored, _) if delivered.route.kind() == AcquisitionRouteKind::Vendor => {
            }
            (SourceKind::Vcs, _) => {
                return Err(declaration.refusal(RegistryError::PinMismatch {
                    expected: Arc::from(source.canonical_text()),
                    observed: Arc::from("verified VCS checkout required"),
                    defect: PinDefect::SourceIdentity,
                }));
            }
            (SourceKind::Path, _) => {
                return Err(declaration.refusal(RegistryError::ContentMismatch {
                    expected: record.source_content(),
                    observed: [0; 32],
                }));
            }
            (SourceKind::Vendored, _) => {
                return Err(declaration.refusal(RegistryError::ContentMismatch {
                    expected: record.source_content(),
                    observed: [0; 32],
                }));
            }
            _ => {}
        }
        Ok(AcquisitionAdmission {
            source,
            snapshot: record.snapshot(),
            declaration: declaration_index,
            route: delivered.route.clone(),
            publication: record.publication(),
            target,
            artifact: target_artifact.digest(),
        })
    }
}

/// Verifies one mirror binding against one already authenticated snapshot.
///
/// A mirror is admitted only when it serves the declared source identity and presents its
/// authenticated snapshot identity. A differing source or snapshot is refused; success proves
/// only those compared declarations and never general transport equivalence.
pub fn verify_mirror(
    declaration: &SourceDeclaration,
    binding: &MirrorBinding,
    verified: &VerifiedSnapshot<'_>,
) -> Result<MirrorReport, RegistryRefusal> {
    let snapshot = verified.snapshot();
    require_declared_source(declaration, snapshot.source())?;
    require_declared_source(declaration, binding.source())?;
    if binding.source() != declaration.identity() {
        return Err(declaration.refusal(RegistryError::MirrorIdentityMismatch {
            mirror: Arc::from(binding.mirror()),
            expected: Arc::from(declaration.identity().digest_hex()),
            observed: Arc::from(binding.source().digest_hex()),
            defect: MirrorDefect::SourceIdentity,
        }));
    }
    if binding.presented() != snapshot.identity() {
        return Err(declaration.refusal(RegistryError::MirrorIdentityMismatch {
            mirror: Arc::from(binding.mirror()),
            expected: Arc::from(snapshot.identity().digest_hex()),
            observed: Arc::from(binding.presented().digest_hex()),
            defect: MirrorDefect::SnapshotIdentity,
        }));
    }
    Ok(MirrorReport {
        mirror: binding.mirror.clone(),
        source: binding.source.clone(),
        identity: binding.presented(),
    })
}

/// The source-bound proof produced by [`verify_mirror`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MirrorReport {
    mirror: Arc<str>,
    source: SourceIdentity,
    identity: SnapshotIdentity,
}

impl MirrorReport {
    /// Returns the verified mirror spelling.
    #[must_use]
    pub fn mirror(&self) -> &str {
        &self.mirror
    }

    /// Returns the authenticated source identity the mirror was verified to serve.
    #[must_use]
    pub const fn source(&self) -> &SourceIdentity {
        &self.source
    }

    /// Returns the authenticated snapshot identity the mirror was verified to present.
    #[must_use]
    pub const fn identity(&self) -> SnapshotIdentity {
        self.identity
    }
}

/// The policy boundary at which an advisory may refuse a matching artifact.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AdvisoryBoundary {
    /// Ordinary resolution is selecting a release for the first time.
    NewResolution,
    /// A verified release is entering a new build.
    NewBuild,
    /// A release is about to execute.
    Execution,
}

/// The closed policy-severity vocabulary of `GNT-27.10-security-revocation`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Severity {
    /// Records the advisory without refusing resolution, builds, or execution.
    AdvisoryOnly,
    /// Refuses only a newly selected release.
    RefuseNewResolution,
    /// Refuses a new build using the affected artifact.
    RefuseNewBuild,
    /// Refuses every execution of the affected artifact.
    RefuseAllExecution,
}

impl Severity {
    /// Every severity of the closed vocabulary, in vocabulary order.
    pub const ALL: [Self; 4] = [
        Self::AdvisoryOnly,
        Self::RefuseNewResolution,
        Self::RefuseNewBuild,
        Self::RefuseAllExecution,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::AdvisoryOnly => "advisory-only",
            Self::RefuseNewResolution => "refuse-new-resolution",
            Self::RefuseNewBuild => "refuse-new-build",
            Self::RefuseAllExecution => "refuse-all-execution",
        }
    }

    /// Parses one exact portable spelling, rejecting anything outside the vocabulary.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|severity| severity.wire_name() == value)
    }

    /// Returns whether this severity refuses exactly the specified policy boundary.
    #[must_use]
    pub const fn refuses(self, boundary: AdvisoryBoundary) -> bool {
        matches!(
            (self, boundary),
            (Self::RefuseNewResolution, AdvisoryBoundary::NewResolution)
                | (Self::RefuseNewBuild, AdvisoryBoundary::NewBuild)
                | (Self::RefuseAllExecution, AdvisoryBoundary::Execution)
        )
    }
}

/// One advisory identity.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AdvisoryId(Arc<str>);

impl AdvisoryId {
    /// Validates one advisory identity spelling.
    pub fn new(value: &str) -> Result<Self, RegistryError> {
        if !is_declared_spelling(value) {
            return Err(RegistryError::AdvisoryDeclarationInvalid {
                field: "advisory id",
                value: Arc::from(value),
            });
        }
        Ok(Self(Arc::from(value)))
    }

    /// Returns the exact advisory identity spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The explicit scope of one advisory.
///
/// The scope names one namespace, one package, and the exact artifact digests it covers, and it
/// covers nothing else: an advisory for one artifact never refuses another artifact of the same
/// release, and it never refuses another release of the same package.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdvisoryScope {
    source: SourceIdentity,
    namespace: RegistryName,
    package: RegistryName,
    version: PackageVersion,
    artifacts: Vec<TargetArtifact>,
}

impl AdvisoryScope {
    /// Validates one advisory scope over one non-empty target-qualified artifact set.
    pub fn new(
        source: SourceIdentity,
        namespace: &str,
        package: &str,
        version: &str,
        artifacts: &[TargetArtifact],
    ) -> Result<Self, RegistryError> {
        if artifacts.is_empty() {
            return Err(RegistryError::AdvisoryDeclarationInvalid {
                field: "advisory artifacts",
                value: Arc::from("empty"),
            });
        }
        let mut artifacts = artifacts.to_vec();
        artifacts.sort();
        artifacts.dedup();
        Ok(Self {
            source,
            namespace: RegistryName::namespace(namespace)?,
            package: RegistryName::package(package)?,
            version: version_of(version)?,
            artifacts,
        })
    }

    /// Returns the authenticated source identity this scope names.
    #[must_use]
    pub const fn source(&self) -> &SourceIdentity {
        &self.source
    }

    /// Returns the scoped namespace.
    #[must_use]
    pub const fn namespace(&self) -> &RegistryName {
        &self.namespace
    }

    /// Returns the scoped package name.
    #[must_use]
    pub const fn package(&self) -> &RegistryName {
        &self.package
    }

    /// Returns the scoped exact package version.
    #[must_use]
    pub const fn version(&self) -> &PackageVersion {
        &self.version
    }

    /// Returns the covered target-qualified artifacts in canonical order.
    #[must_use]
    pub fn artifacts(&self) -> &[TargetArtifact] {
        &self.artifacts
    }

    /// Returns whether this scope covers one namespace, package, version, and target artifact.
    #[must_use]
    pub fn covers(
        &self,
        source: &SourceIdentity,
        namespace: &RegistryName,
        package: &RegistryName,
        version: &PackageVersion,
        target: TargetKind,
        artifact: [u8; 32],
    ) -> bool {
        self.source == *source
            && self.namespace == *namespace
            && self.package == *package
            && self.version == *version
            && self
                .artifacts
                .iter()
                .any(|candidate| candidate.target() == target && candidate.digest() == artifact)
    }
}

/// One advisory with an explicit scope and severity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecurityAdvisory {
    id: AdvisoryId,
    scope: AdvisoryScope,
    severity: Severity,
}

impl SecurityAdvisory {
    /// Validates one advisory.
    pub fn new(id: &str, scope: AdvisoryScope, severity: Severity) -> Result<Self, RegistryError> {
        Ok(Self {
            id: AdvisoryId::new(id)?,
            scope,
            severity,
        })
    }

    /// Returns the advisory identity.
    #[must_use]
    pub const fn id(&self) -> &AdvisoryId {
        &self.id
    }

    /// Returns the advisory scope.
    #[must_use]
    pub const fn scope(&self) -> &AdvisoryScope {
        &self.scope
    }

    /// Returns the advisory severity.
    #[must_use]
    pub const fn severity(&self) -> Severity {
        self.severity
    }

    /// Returns the advisory authorization payload digest.
    ///
    /// The digest binds the identity, the severity, and the exact scope, so an advisory
    /// signature never authorizes a wider scope or another severity than the one declared.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let mut fields: Vec<Vec<u8>> = vec![
            self.id.as_str().as_bytes().to_vec(),
            self.severity.wire_name().as_bytes().to_vec(),
            self.scope.source().digest().to_vec(),
            self.scope.namespace().spelling().as_bytes().to_vec(),
            self.scope.package().spelling().as_bytes().to_vec(),
            self.scope.version().as_str().as_bytes().to_vec(),
        ];
        fields.extend(
            self.scope
                .artifacts()
                .iter()
                .map(|artifact| artifact.canonical_text().into_bytes()),
        );
        let borrowed = fields.iter().map(Vec::as_slice).collect::<Vec<_>>();
        digest_fields(ADVISORY_DOMAIN, &borrowed)
    }
}

/// One request to build or run one artifact.
///
/// A request may declare a substitute for the requested artifact. A substitute is never
/// admitted: it exists as a declaration precisely so that asking for it is refused rather than
/// silently applied.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunRequest {
    source: SourceIdentity,
    namespace: RegistryName,
    package: RegistryName,
    version: PackageVersion,
    target: TargetKind,
    artifact: [u8; 32],
    durable: bool,
    substitute: Option<SourceIdentity>,
}

impl RunRequest {
    /// Validates one build or run request for one target-qualified artifact.
    pub fn new(
        source: SourceIdentity,
        namespace: &str,
        package: &str,
        version: &str,
        target: TargetKind,
        artifact: [u8; 32],
    ) -> Result<Self, RegistryError> {
        Ok(Self {
            source,
            namespace: RegistryName::namespace(namespace)?,
            package: RegistryName::package(package)?,
            version: version_of(version)?,
            target,
            artifact,
            durable: false,
            substitute: None,
        })
    }

    /// Returns this request as one durable run request.
    #[must_use]
    pub fn durable(mut self) -> Self {
        self.durable = true;
        self
    }

    /// Returns this request with one declared substitute.
    #[must_use]
    pub fn with_substitute(mut self, substitute: SourceIdentity) -> Self {
        self.substitute = Some(substitute);
        self
    }

    /// Returns the authenticated source identity of the requested artifact.
    #[must_use]
    pub const fn source(&self) -> &SourceIdentity {
        &self.source
    }

    /// Returns the requested namespace.
    #[must_use]
    pub const fn namespace(&self) -> &RegistryName {
        &self.namespace
    }

    /// Returns the requested package name.
    #[must_use]
    pub const fn package(&self) -> &RegistryName {
        &self.package
    }

    /// Returns the requested exact package version.
    #[must_use]
    pub const fn version(&self) -> &PackageVersion {
        &self.version
    }

    /// Returns the target of the requested artifact.
    #[must_use]
    pub const fn target(&self) -> TargetKind {
        self.target
    }

    /// Returns the requested artifact digest.
    #[must_use]
    pub const fn artifact(&self) -> [u8; 32] {
        self.artifact
    }

    /// Returns whether this is a durable run request.
    #[must_use]
    pub const fn is_durable(&self) -> bool {
        self.durable
    }

    /// Returns the declared substitute, when one was requested.
    #[must_use]
    pub const fn substitute(&self) -> Option<&SourceIdentity> {
        self.substitute.as_ref()
    }
}

/// One admitted build or run of one artifact.
///
/// The admitted artifact is exactly the requested artifact, and there is no constructor for an
/// admitted run of substituted code, so a revocation never substitutes code into a durable run
/// and never rewrites a lockfile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmittedRun {
    artifact: [u8; 32],
    durable: bool,
}

impl AdmittedRun {
    /// Returns the admitted artifact digest.
    #[must_use]
    pub const fn artifact(&self) -> [u8; 32] {
        self.artifact
    }

    /// Returns whether the admitted run is durable.
    #[must_use]
    pub const fn is_durable(&self) -> bool {
        self.durable
    }
}

/// The authenticated advisories one workspace holds.
#[derive(Clone, Debug, Eq, PartialEq)]
struct AdmittedAdvisoryFact {
    source: SourceIdentity,
    effective_sequence: u64,
    digest: [u8; 32],
    roots: Vec<RootId>,
}

/// The authenticated advisories one workspace holds.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AdvisoryStore {
    advisories: Vec<SecurityAdvisory>,
    facts: Vec<AdmittedAdvisoryFact>,
}

impl AdvisoryStore {
    /// Constructs one empty advisory store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Admits one authenticated advisory.
    ///
    /// An advisory enters the store only through its publisher identity, a signature of that
    /// identity's key over its own authorization payload, and an authority that covers its
    /// declared scope. An unverified signature or an out-of-scope publisher is refused, so no
    /// advisory is admitted on the strength of its text alone.
    pub fn admit(
        &mut self,
        declaration: &SourceDeclaration,
        advisory: SecurityAdvisory,
        signature: DeclaredSignature,
        publisher: PublisherIdentity,
        trust: &TrustStore,
        sequence: u64,
    ) -> Result<(), RegistryRefusal> {
        self.admit_with_root_selection(
            declaration,
            advisory,
            signature,
            publisher,
            trust,
            sequence,
            &RootSelectionPolicy::Unspecified,
        )
    }

    /// Admits one authenticated advisory under one explicit source-root policy.
    #[allow(clippy::too_many_arguments)]
    pub fn admit_with_root_selection(
        &mut self,
        declaration: &SourceDeclaration,
        advisory: SecurityAdvisory,
        signature: DeclaredSignature,
        publisher: PublisherIdentity,
        trust: &TrustStore,
        sequence: u64,
        root_policy: &RootSelectionPolicy,
    ) -> Result<(), RegistryRefusal> {
        require_declared_source(declaration, advisory.scope().source())?;
        if signature.key() != publisher.key() || !trust.verifies(&signature, advisory.digest()) {
            return Err(declaration.refusal(RegistryError::SignatureUnverified {
                key: signature.key().clone(),
            }));
        }
        let grant = trust.authorize_coordinates_with_root_selection(
            declaration,
            advisory.scope().source(),
            &publisher,
            advisory.scope().namespace(),
            advisory.scope().package(),
            sequence,
            root_policy,
        )?;
        let digest = advisory.digest();
        let source = advisory.scope().source().clone();
        self.advisories.push(advisory);
        if let Some(fact) = self.facts.iter_mut().find(|fact| fact.digest == digest) {
            if !fact.roots.contains(grant.root()) {
                fact.roots.push(grant.root().clone());
                fact.roots.sort();
            }
        } else {
            self.facts.push(AdmittedAdvisoryFact {
                source,
                effective_sequence: sequence,
                digest,
                roots: vec![grant.root().clone()],
            });
        }
        Ok(())
    }

    /// Returns the admitted advisories in admission order.
    #[must_use]
    pub fn advisories(&self) -> &[SecurityAdvisory] {
        &self.advisories
    }

    /// Returns the number of admitted advisories.
    #[must_use]
    pub fn len(&self) -> usize {
        self.advisories.len()
    }

    /// Returns whether no advisory is admitted.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.advisories.is_empty()
    }

    /// Returns canonical advisory lifecycle facts effective for one source and root policy.
    fn lifecycle_facts(
        &self,
        source: &SourceIdentity,
        sequence: u64,
        root_policy: &RootSelectionPolicy,
    ) -> Vec<[u8; 32]> {
        let mut facts = self
            .facts
            .iter()
            .filter(|fact| {
                fact.source == *source
                    && fact.effective_sequence <= sequence
                    && fact.roots.iter().any(|root| root_policy.permits(root))
            })
            .map(|fact| fact.digest)
            .collect::<Vec<_>>();
        facts.sort_unstable();
        facts.dedup();
        facts
    }

    /// Decides whether an affected artifact may be selected by new resolution.
    ///
    /// Only [`Severity::RefuseNewResolution`] refuses this boundary. Advisory-only, build, and
    /// execution policy remain distinct decisions so an advisory never changes a lockfile or
    /// silently substitutes another artifact.
    pub fn admit_new_resolution(
        &self,
        declaration: &SourceDeclaration,
        request: &RunRequest,
    ) -> Result<(), RegistryRefusal> {
        self.admit_boundary(declaration, request, AdvisoryBoundary::NewResolution)
    }

    /// Decides whether an affected artifact may enter a new build.
    ///
    /// Only [`Severity::RefuseNewBuild`] refuses this boundary. This does not reinterpret an
    /// existing lockfile or expand an execution refusal into a build refusal.
    pub fn admit_new_build(
        &self,
        declaration: &SourceDeclaration,
        request: &RunRequest,
    ) -> Result<(), RegistryRefusal> {
        self.admit_boundary(declaration, request, AdvisoryBoundary::NewBuild)
    }

    /// Decides one execution against every admitted advisory.
    ///
    /// Only [`Severity::RefuseAllExecution`] refuses this boundary. A declared substitute is
    /// always refused, because no advisory may rewrite a lockfile or substitute code into a
    /// durable execution.
    pub fn admit_run(
        &self,
        declaration: &SourceDeclaration,
        request: &RunRequest,
    ) -> Result<AdmittedRun, RegistryRefusal> {
        self.admit_boundary(declaration, request, AdvisoryBoundary::Execution)?;
        Ok(AdmittedRun {
            artifact: request.artifact(),
            durable: request.is_durable(),
        })
    }

    /// Applies one exact advisory refusal boundary without widening another one.
    fn admit_boundary(
        &self,
        declaration: &SourceDeclaration,
        request: &RunRequest,
        boundary: AdvisoryBoundary,
    ) -> Result<(), RegistryRefusal> {
        require_declared_source(declaration, request.source())?;
        if let Some(substitute) = request.substitute() {
            return Err(
                declaration.refusal(RegistryError::AdvisorySubstitutionRefused {
                    requested: Arc::from(substitute.canonical_text()),
                }),
            );
        }
        if let Some(advisory) = self.advisories.iter().find(|advisory| {
            advisory.severity().refuses(boundary)
                && advisory.scope().covers(
                    request.source(),
                    request.namespace(),
                    request.package(),
                    request.version(),
                    request.target(),
                    request.artifact(),
                )
        }) {
            return Err(declaration.refusal(RegistryError::AdvisoryRefusesBuild {
                advisory: Arc::from(advisory.id().as_str()),
                severity: advisory.severity(),
            }));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    use super::*;

    /// Returns one declared digest derived from one declared seed.
    fn declared(seed: &str) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(seed.as_bytes());
        hasher.finalize().into()
    }

    /// Returns one validated name of one kind.
    fn name(kind: RegistryNameKind, spelling: &str) -> RegistryName {
        match RegistryName::new(kind, spelling) {
            Ok(name) => name,
            Err(error) => panic!("the declared name is valid: {error:?}"),
        }
    }

    /// Returns one registry service identity for the namespace that publishes a package.
    fn source_of(namespace: &str, package: &str) -> SourceIdentity {
        let _ = package;
        match SourceIdentity::registry(&format!("{namespace}-registry")) {
            Ok(identity) => identity,
            Err(error) => panic!("the declared source identity is valid: {error:?}"),
        }
    }

    /// Returns one source declaration.
    fn declaration(index: usize, alias: &str, identity: SourceIdentity) -> SourceDeclaration {
        match SourceDeclaration::new(index, &format!("test:declaration:{index}"), alias, identity) {
            Ok(declaration) => declaration,
            Err(error) => panic!("the declared declaration is valid: {error:?}"),
        }
    }

    /// Returns one publisher identity.
    fn publisher(name: &str, key: &str) -> PublisherIdentity {
        match PublisherIdentity::of(name, key) {
            Ok(publisher) => publisher,
            Err(error) => panic!("the declared publisher is valid: {error:?}"),
        }
    }

    /// Returns one key record.
    fn key(spelling: &str) -> KeyRecord {
        let key = match KeyId::new(spelling) {
            Ok(key) => key,
            Err(error) => panic!("the declared key identity is valid: {error:?}"),
        };
        match KeyRecord::new(key, declared(spelling)) {
            Ok(record) => record,
            Err(error) => panic!("the declared key record is valid: {error:?}"),
        }
    }

    /// Returns canonical dual-signed rotation evidence for one source-scoped authority.
    fn rotation(
        source: SourceIdentity,
        scope: AuthorityScope,
        old: &KeyRecord,
        new: &KeyRecord,
        effective_sequence: u64,
        old_signature: DeclaredSignature,
        new_signature: DeclaredSignature,
    ) -> RotationEvidence {
        let timing = match RotationTiming::new(
            effective_sequence,
            effective_sequence,
            effective_sequence.saturating_add(1),
        ) {
            Ok(timing) => timing,
            Err(error) => panic!("the declared rotation timing is valid: {error:?}"),
        };
        let context = match RotationContext::new(
            source,
            scope,
            publisher("acme", old.key().as_str()),
            old.key().clone(),
            new.key().clone(),
            timing,
        ) {
            Ok(context) => context,
            Err(error) => panic!("the declared rotation context is valid: {error:?}"),
        };
        match RotationEvidence::authenticated(
            context,
            RotationSignatures::new(old_signature, new_signature),
        ) {
            Ok(evidence) => evidence,
            Err(error) => panic!("the declared rotation evidence is valid: {error:?}"),
        }
    }

    /// Returns one published snapshot entry.
    fn entry(
        namespace: &str,
        package: &str,
        version: &str,
        publisher: &PublisherIdentity,
        manifest: &str,
        artifact: &str,
    ) -> SnapshotEntry {
        match SnapshotEntry::new(
            source_of(namespace, package),
            namespace,
            package,
            version,
            publisher.clone(),
        ) {
            Ok(entry) => entry
                .with_manifest(declared(manifest))
                .with_artifact(declared(artifact))
                .with_target_artifact(
                    match TargetArtifact::new(TargetKind::Library, declared(artifact)) {
                        Ok(target_artifact) => target_artifact,
                        Err(error) => panic!("the declared target artifact is valid: {error:?}"),
                    },
                )
                .with_source_content(declared(&format!("source:{manifest}")))
                .with_generated(declared(&format!("generated:{artifact}")))
                .with_interface(declared(&format!("interface:{manifest}"))),
            Err(error) => panic!("the declared entry is valid: {error:?}"),
        }
    }

    /// Returns one metadata snapshot over one epoch window.
    fn snapshot_of(
        sequence: u64,
        issue_epoch: u64,
        expiry_epoch: u64,
        entries: &[SnapshotEntry],
    ) -> MetadataSnapshot {
        match MetadataSnapshot::new(
            MetadataSnapshot::VERSION,
            entries[0].source().clone(),
            sequence,
            issue_epoch,
            expiry_epoch,
            entries,
        ) {
            Ok(snapshot) => snapshot,
            Err(error) => panic!("the declared snapshot is valid: {error:?}"),
        }
    }

    /// Returns authenticated snapshot evidence for one test fixture.
    fn authenticated_fixture(
        declaration: &SourceDeclaration,
        snapshot: &MetadataSnapshot,
    ) -> (TrustStore, RetainedState, Vec<DeclaredSignature>) {
        let entry = &snapshot.entries()[0];
        let record = key(entry.publisher().key().as_str());
        let store = match TrustStore::new(
            &[root(
                "fixture-root",
                snapshot.source().clone(),
                entry.publisher().clone(),
                scope_of_namespace(entry.namespace().spelling()),
            )],
            std::slice::from_ref(&record),
            &[],
        ) {
            Ok(store) => store,
            Err(error) => panic!("the fixture trust store is valid: {error:?}"),
        };
        let retained = RetainedState::for_source(snapshot.source().clone(), snapshot.sequence())
            .with_content(snapshot.sequence(), snapshot.content_digest());
        let signatures = vec![declared_signature(&record, snapshot.content_digest())];
        let _ = declaration;
        (store, retained, signatures)
    }

    /// Returns one ledger whose occupancy entered through snapshot verification.
    fn ledger_of(
        declaration: &SourceDeclaration,
        snapshot: &MetadataSnapshot,
    ) -> PublicationLedger {
        let (store, retained, signatures) = authenticated_fixture(declaration, snapshot);
        let declarations = [declaration.clone()];
        let empty = PublicationLedger::new();
        let input = VerificationInput::new(
            &declarations,
            snapshot,
            &signatures,
            std::slice::from_ref(&retained),
            &empty,
            EpochObservation::at(snapshot.issue_epoch()),
            FreshnessMode::online(),
        );
        let verified = match store.verify(&input) {
            Ok(verified) => verified,
            Err(refusal) => panic!("the fixture snapshot verifies: {refusal}"),
        };
        let mut ledger = PublicationLedger::new();
        match ledger.admit_verified(&verified, &declarations) {
            Ok(()) => ledger,
            Err(refusal) => panic!("the verified snapshot occupies the ledger: {refusal}"),
        }
    }

    /// Returns one historical lockfile record bound to authenticated evidence.
    fn record_of(
        entry: &SnapshotEntry,
        snapshot: &MetadataSnapshot,
        declaration: &SourceDeclaration,
    ) -> LockfileRecord {
        let (store, retained, signatures) = authenticated_fixture(declaration, snapshot);
        let declarations = [declaration.clone()];
        let empty = PublicationLedger::new();
        let input = VerificationInput::new(
            &declarations,
            snapshot,
            &signatures,
            std::slice::from_ref(&retained),
            &empty,
            EpochObservation::at(snapshot.issue_epoch()),
            FreshnessMode::online(),
        );
        let verified = match store.verify(&input) {
            Ok(verified) => verified,
            Err(refusal) => panic!("the fixture snapshot verifies: {refusal}"),
        };
        match LockfileRecord::historical(
            entry,
            &verified,
            &retained,
            declaration,
            LockfileInputs {
                targets: entry
                    .target_artifacts()
                    .iter()
                    .map(TargetArtifact::target)
                    .collect(),
                target_artifacts: entry.target_artifacts().to_vec(),
                ..LockfileInputs::default()
            },
        ) {
            Ok(record) => record,
            Err(refusal) => panic!("the declared historical record is valid: {refusal}"),
        }
    }

    /// Returns one package scope.
    fn scope_of_package(namespace: &str, package: &str) -> AuthorityScope {
        match AuthorityScope::of_package(namespace, package) {
            Ok(scope) => scope,
            Err(error) => panic!("the declared package scope is valid: {error:?}"),
        }
    }

    /// Returns one whole-namespace scope.
    fn scope_of_namespace(namespace: &str) -> AuthorityScope {
        match AuthorityScope::of_namespace(namespace) {
            Ok(scope) => scope,
            Err(error) => panic!("the declared namespace scope is valid: {error:?}"),
        }
    }

    /// Returns one source-scoped trust root.
    fn root(
        id: &str,
        source: SourceIdentity,
        publisher: PublisherIdentity,
        scope: AuthorityScope,
    ) -> TrustRoot {
        match TrustRoot::new(id, source, publisher, scope) {
            Ok(root) => root,
            Err(error) => panic!("the declared trust root is valid: {error:?}"),
        }
    }

    /// Returns authenticated delegation evidence over one source-scoped grant.
    fn delegation(
        source: SourceIdentity,
        delegator: PublisherIdentity,
        delegate: PublisherIdentity,
        scope: AuthorityScope,
        effective_sequence: u64,
        key: &KeyRecord,
    ) -> Delegation {
        let timing = match DelegationTiming::new(0, u64::MAX, effective_sequence) {
            Ok(timing) => timing,
            Err(error) => panic!("the declared delegation timing is valid: {error:?}"),
        };
        let payload = Delegation::payload(
            &source,
            &delegator,
            &delegate,
            &scope,
            timing.not_before_epoch(),
            timing.expiry_epoch(),
            timing.effective_sequence(),
        );
        match Delegation::authenticated(
            source,
            delegator,
            delegate,
            scope,
            timing,
            declared_signature(key, payload),
        ) {
            Ok(delegation) => delegation,
            Err(error) => panic!("the declared delegation is valid: {error:?}"),
        }
    }

    /// `GNT-27.0` requires every published code to name exactly one clause of the section.
    #[test]
    fn registry_clause_inventory_owns_every_published_code() {
        assert_eq!(REGISTRY_CLAUSES.len(), 15);
        let mut clauses = REGISTRY_CLAUSES.to_vec();
        clauses.sort_unstable();
        clauses.dedup();
        assert_eq!(clauses.len(), REGISTRY_CLAUSES.len());
        assert_eq!(REGISTRY_CLAUSES[0], SECTION_CLAUSE);
        let mut codes = RegistryDiagnosticCode::ALL.to_vec();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), RegistryDiagnosticCode::ALL.len());
        for code in RegistryDiagnosticCode::ALL {
            assert!(
                REGISTRY_CLAUSES.contains(&code.clause()),
                "{} names no clause of the section",
                code.as_str()
            );
            assert_eq!(code.as_str(), code.as_str().to_lowercase());
            assert!(!code.meaning().is_empty());
        }
    }

    /// `GNT-27.1` requires resolution to bind the exact declared identity and never to fall
    /// back between kinds or to a same-named source of another kind.
    #[test]
    fn registry_source_resolution_never_falls_back_between_kinds() {
        let registry = source_of("acme", "widget");
        let commit = match CommitId::new(&"a".repeat(40)) {
            Ok(commit) => commit,
            Err(error) => panic!("the declared commit is valid: {error:?}"),
        };
        let vcs = match SourceIdentity::vcs("acme.widget", &commit) {
            Ok(identity) => identity,
            Err(error) => panic!("the declared identity is valid: {error:?}"),
        };
        let declarations = vec![
            declaration(0, "widget", registry.clone()),
            declaration(1, "widget_vcs", vcs.clone()),
        ];
        assert!(matches!(
            resolve_source(&declarations, &declarations[0], &registry),
            Ok(found) if found.index() == 0
        ));
        assert!(matches!(
            resolve_source(&declarations, &declarations[1], &vcs),
            Ok(found) if found.index() == 1
        ));
        let same_text = match SourceIdentity::new(SourceKind::Path, registry.canonical_text()) {
            Ok(identity) => identity,
            Err(error) => panic!("the declared identity text is valid: {error:?}"),
        };
        match resolve_source(&declarations, &declarations[0], &same_text) {
            Err(refusal) => {
                assert_eq!(
                    refusal.code(),
                    Some(RegistryDiagnosticCode::SourceKindFallback)
                );
                assert_eq!(
                    refusal.clause(),
                    "GNT-27.1-immutable-source-identity-and-source-kind-vocabulary"
                );
                assert!(refusal.is_bound());
                assert_eq!(refusal.declaration_index(), 0);
            }
            Ok(_) => panic!("a request for another kind is not resolved"),
        }
        let unknown = source_of("other", "other");
        match resolve_source(&declarations, &declarations[0], &unknown) {
            Err(refusal) => {
                assert_eq!(
                    refusal.code(),
                    Some(RegistryDiagnosticCode::SourceNotDeclared)
                );
            }
            Ok(_) => panic!("an undeclared source is not resolved"),
        }
    }

    /// `GNT-27.2` requires one canonical byte representation per name, refuses noncanonical
    /// spellings, and refuses canonical collisions instead of resolving them.
    #[test]
    fn registry_names_are_canonical_and_collision_free() {
        let decomposed = "cafe\u{301}";
        match RegistryName::namespace(decomposed) {
            Err(error) => {
                assert_eq!(error.code(), Some(RegistryDiagnosticCode::NameNoncanonical));
                assert_eq!(
                    error.clause(),
                    "GNT-27.2-canonical-publication-names-and-external-name-mapping"
                );
            }
            Ok(_) => panic!("a decomposed spelling is not a canonical publication name"),
        }
        let mut admitted = PublicationNameSet::new();
        assert!(
            admitted
                .admit(name(RegistryNameKind::Publisher, "Acme"))
                .is_ok()
        );
        assert!(
            admitted
                .admit(name(RegistryNameKind::Publisher, "Acme"))
                .is_ok()
        );
        match admitted.admit(name(RegistryNameKind::Publisher, "acme")) {
            Err(error) => {
                assert_eq!(error.code(), Some(RegistryDiagnosticCode::NameCollision));
            }
            Ok(()) => panic!("a case-folded collision is refused"),
        }
        assert!(
            collision(
                &name(RegistryNameKind::Package, "widget"),
                &name(RegistryNameKind::Namespace, "widget")
            )
            .is_none()
        );
        let mut aliases = ExternalAliasMap::new();
        let first = match ExternalName::new(RegistryNameKind::Package, "widget") {
            Ok(name) => name,
            Err(error) => panic!("the declared external name is valid: {error:?}"),
        };
        let second = match ExternalName::new(RegistryNameKind::Package, "WIDGET") {
            Ok(name) => name,
            Err(error) => panic!("the declared external name is valid: {error:?}"),
        };
        assert!(aliases.insert(first.clone()).is_ok());
        match aliases.insert(second) {
            Err(error) => {
                assert_eq!(
                    error.code(),
                    Some(RegistryDiagnosticCode::ExternalAliasCollision)
                );
            }
            Ok(_) => panic!("two external names sharing one skeleton are refused"),
        }
        assert_eq!(
            aliases.alias(&first).map(SourceAlias::as_str),
            Some("ext_package_widget")
        );
    }

    /// `GNT-27.3` requires one canonical snapshot encoding and refuses an entry that omits the
    /// content it stands for.
    #[test]
    fn registry_snapshots_are_order_independent_and_refuse_omitted_content() {
        let acme = publisher("acme", "acme-key");
        let widget = entry("acme", "widget", "1.0.0", &acme, "manifest-a", "artifact-a");
        let gadget = entry("acme", "gadget", "1.0.0", &acme, "manifest-b", "artifact-b");
        let forward = snapshot_of(7, 100, 200, &[widget.clone(), gadget.clone()]);
        let reverse = snapshot_of(7, 100, 200, &[gadget, widget]);
        assert_eq!(forward.canonical_bytes(), reverse.canonical_bytes());
        assert_eq!(forward.content_digest(), reverse.content_digest());
        assert_eq!(forward.identity(), reverse.identity());
        let omitted = match SnapshotEntry::new(
            source_of("acme", "widget"),
            "acme",
            "widget",
            "2.0.0",
            acme,
        ) {
            Ok(entry) => entry.with_manifest(declared("manifest-c")),
            Err(error) => panic!("the declared entry is valid: {error:?}"),
        };
        match MetadataSnapshot::new(
            MetadataSnapshot::VERSION,
            omitted.source().clone(),
            7,
            100,
            200,
            &[omitted],
        ) {
            Err(error) => {
                assert_eq!(
                    error.code(),
                    Some(RegistryDiagnosticCode::SnapshotEntryInvalid)
                );
            }
            Ok(_) => panic!("an omitted artifact digest is refused"),
        }
    }

    /// `GNT-27.4` requires a delegation to narrow, never to widen, and requires an unnamed
    /// publisher to hold no authority at all.
    #[test]
    fn registry_delegations_never_widen_authority() {
        let acme = publisher("acme", "root-key");
        let tools = publisher("acme-tools", "delegate-key");
        let keys = vec![key("root-key"), key("delegate-key")];
        let acme_root = root(
            "acme-root",
            source_of("acme", "widget"),
            acme.clone(),
            scope_of_package("acme", "widget"),
        );
        let widening = delegation(
            source_of("acme", "widget"),
            acme.clone(),
            tools.clone(),
            scope_of_namespace("acme"),
            1,
            &keys[0],
        );
        match TrustStore::new(std::slice::from_ref(&acme_root), &keys, &[widening]) {
            Err(error) => {
                assert_eq!(
                    error.code(),
                    Some(RegistryDiagnosticCode::DelegationOutOfScope)
                );
                assert_eq!(
                    error.clause(),
                    "GNT-27.4-trust-roots-and-delegated-authority"
                );
            }
            Ok(_) => panic!("a widening delegation is refused"),
        }
        let narrowing = delegation(
            source_of("acme", "widget"),
            acme,
            tools,
            scope_of_package("acme", "widget"),
            1,
            &keys[0],
        );
        let store = match TrustStore::new(&[acme_root], &keys, &[narrowing]) {
            Ok(store) => store,
            Err(error) => panic!("a narrowing delegation is admitted: {error:?}"),
        };
        assert_eq!(store.delegations().len(), 1);
        let inside = entry(
            "acme",
            "widget",
            "1.0.0",
            &publisher("acme-tools", "delegate-key"),
            "manifest-a",
            "artifact-a",
        );
        let inside_declaration = declaration(0, "widget", inside.source().clone());
        assert!(store.authorize(&inside_declaration, &inside, 2).is_ok());
        let outside = entry(
            "acme",
            "gadget",
            "1.0.0",
            &publisher("acme-tools", "delegate-key"),
            "manifest-b",
            "artifact-b",
        );
        let outside_declaration = declaration(1, "gadget", outside.source().clone());
        match store.authorize(&outside_declaration, &outside, 2) {
            Err(refusal) => {
                assert_eq!(
                    refusal.code(),
                    Some(RegistryDiagnosticCode::DelegationOutOfScope)
                );
                assert_eq!(refusal.declaration_index(), 1);
            }
            Ok(_) => panic!("an out-of-scope entry is refused"),
        }
        let stranger = entry(
            "other",
            "widget",
            "1.0.0",
            &publisher("stranger", "stranger-key"),
            "manifest-c",
            "artifact-c",
        );
        let stranger_declaration = declaration(2, "stranger", stranger.source().clone());
        match store.authorize(&stranger_declaration, &stranger, 2) {
            Err(refusal) => {
                assert_eq!(refusal.code(), None);
                assert_eq!(refusal.reason(), TrustFailureReason::AbsentTrustRoot);
            }
            Ok(_) => panic!("an unnamed publisher holds no authority"),
        }
    }

    /// `GNT-27.5` requires rotation evidence to be valid under both keys.
    #[test]
    fn registry_rotation_requires_evidence_under_both_keys() {
        let old = key("old-key");
        let new = key("new-key");
        let declaration = declaration(0, "widget", source_of("acme", "widget"));
        let source = declaration.identity().clone();
        let scope = scope_of_package("acme", "widget");
        let acme = publisher("acme", old.key().as_str());
        let timing = match RotationTiming::new(4, 4, 5) {
            Ok(timing) => timing,
            Err(error) => panic!("the declared rotation timing is valid: {error:?}"),
        };
        let payload =
            RotationEvidence::payload(&source, &scope, &acme, old.key(), new.key(), timing);
        let root = root("acme-root", source.clone(), acme, scope.clone());
        let mut store = match TrustStore::new(&[root], std::slice::from_ref(&old), &[]) {
            Ok(store) => store,
            Err(error) => panic!("the declared store is valid: {error:?}"),
        };
        let forged = rotation(
            source.clone(),
            scope.clone(),
            &old,
            &new,
            4,
            declared_signature(&old, payload),
            DeclaredSignature::declared(new.key().clone(), declared("forged-signature")),
        );
        match store.rotate_batch(
            &declaration,
            std::slice::from_ref(&forged),
            std::slice::from_ref(&new),
        ) {
            Err(refusal) => {
                assert_eq!(
                    refusal.code(),
                    Some(RegistryDiagnosticCode::RotationEvidenceInvalid)
                );
                assert_eq!(
                    refusal.clause(),
                    "GNT-27.5-signing-key-rotation-and-compromise-recovery"
                );
            }
            Ok(()) => panic!("evidence under one key is not a rotation"),
        }
        let evidence = rotation(
            source,
            scope,
            &old,
            &new,
            4,
            declared_signature(&old, payload),
            declared_signature(&new, payload),
        );
        match store.rotate_batch(
            &declaration,
            std::slice::from_ref(&evidence),
            std::slice::from_ref(&new),
        ) {
            Ok(()) => assert_eq!(store.rotations().len(), 1),
            Err(refusal) => panic!("evidence under both keys is admitted: {refusal}"),
        }
    }

    /// `GNT-27.5` requires a compromised key to revoke its authority from the declared
    /// sequence on, and to keep authorizing metadata that precedes it.
    #[test]
    fn registry_compromise_revokes_authority_from_its_sequence() {
        let record = key("acme-key");
        let acme_root = root(
            "acme-root",
            source_of("acme", "widget"),
            publisher("acme", "acme-key"),
            scope_of_package("acme", "widget"),
        );
        let mut store = match TrustStore::new(&[acme_root], std::slice::from_ref(&record), &[]) {
            Ok(store) => store,
            Err(error) => panic!("the declared store is valid: {error:?}"),
        };
        let entry = entry(
            "acme",
            "widget",
            "1.0.0",
            &publisher("acme", "acme-key"),
            "manifest-a",
            "artifact-a",
        );
        let declaration = declaration(0, "widget", entry.source().clone());
        assert!(store.authorize(&declaration, &entry, 9).is_ok());
        let scope = scope_of_package("acme", "widget");
        let declarer = publisher("acme", "acme-key");
        let payload = Compromise::payload(entry.source(), &scope, &declarer, record.key(), 10, 100);
        let compromise = match Compromise::authenticated(
            entry.source().clone(),
            scope,
            declarer,
            record.key().clone(),
            10,
            100,
            declared_signature(&record, payload),
        ) {
            Ok(compromise) => compromise,
            Err(error) => panic!("the declared compromise evidence is valid: {error:?}"),
        };
        match store.compromise(&declaration, compromise) {
            Ok(()) => {}
            Err(refusal) => panic!("the declared compromise is admitted: {refusal}"),
        }
        assert!(store.authorize(&declaration, &entry, 9).is_err());
        match store.authorize(&declaration, &entry, 10) {
            Err(refusal) => {
                assert_eq!(refusal.code(), Some(RegistryDiagnosticCode::KeyCompromised));
                assert!(refusal.is_bound());
            }
            Ok(_) => panic!("a compromised key holds no authority at its compromise"),
        }
    }

    /// `GNT-27.6`, `GNT-27.7`, and `GNT-27.13` require one ordered verification that fails
    /// closed, attributes every refusal, and decides freshness over declared epochs alone.
    #[test]
    fn registry_verification_is_attributed_and_fails_closed() {
        let record = key("acme-key");
        let acme = publisher("acme", "acme-key");
        let acme_root = root(
            "acme-root",
            source_of("acme", "widget"),
            acme.clone(),
            scope_of_package("acme", "widget"),
        );
        let store = match TrustStore::new(&[acme_root], std::slice::from_ref(&record), &[]) {
            Ok(store) => store,
            Err(error) => panic!("the declared store is valid: {error:?}"),
        };
        let widget = entry("acme", "widget", "1.0.0", &acme, "manifest-a", "artifact-a");
        let snapshot = snapshot_of(4, 100, 200, std::slice::from_ref(&widget));
        let declaration = declaration(0, "widget", widget.source().clone());
        let declarations = vec![declaration.clone()];
        let ledger = ledger_of(&declaration, &snapshot);
        let retained = RetainedState::for_source(widget.source().clone(), 1);
        let signatures = vec![declared_signature(&record, snapshot.content_digest())];
        let fresh = VerificationInput::new(
            &declarations,
            &snapshot,
            &signatures,
            std::slice::from_ref(&retained),
            &ledger,
            EpochObservation::at(150),
            FreshnessMode::online(),
        );
        let verified = match store.verify(&fresh) {
            Ok(verified) => verified,
            Err(refusal) => panic!("the declared snapshot verifies: {refusal}"),
        };
        assert_eq!(verified.identity(), snapshot.identity());
        assert!(verified.freshness().is_online());
        assert_eq!(verified.freshness().age(), 50);
        assert_eq!(
            verified.authority(0).map(EntryAuthority::declaration),
            Some(0)
        );
        assert_eq!(verified.entries().len(), 1);
        let offline_witness = match verified.offline_witness(declaration.identity(), 199) {
            Ok(witness) => witness,
            Err(error) => panic!("the verified snapshot mints an offline witness: {error:?}"),
        };
        assert!(
            verified
                .offline_witness(declaration.identity(), 200)
                .is_ok()
        );
        let expired = VerificationInput::new(
            &declarations,
            &snapshot,
            &signatures,
            std::slice::from_ref(&retained),
            &ledger,
            EpochObservation::at(200),
            FreshnessMode::online(),
        )
        .with_snapshot_declaration(declaration.index());
        match store.verify(&expired) {
            Err(refusal) => {
                assert_eq!(
                    refusal.code(),
                    Some(RegistryDiagnosticCode::SnapshotExpired)
                );
                assert_eq!(
                    refusal.clause(),
                    "GNT-27.6-expiry-freshness-and-offline-mode"
                );
                assert!(refusal.is_bound());
                assert_eq!(refusal.declaration_index(), 0);
                assert_eq!(refusal.causing_entry(), None);
            }
            Ok(_) => panic!("an observation past the declared expiry is refused"),
        }
        let offline = VerificationInput::new(
            &declarations,
            &snapshot,
            &signatures,
            std::slice::from_ref(&retained),
            &ledger,
            EpochObservation::at(199),
            FreshnessMode::offline(offline_witness.clone()),
        );
        match store.verify(&offline) {
            Ok(verified) => {
                assert!(!verified.freshness().is_online());
                assert!(!verified.freshness().snapshot_expired());
                assert_eq!(verified.freshness().age(), 99);
            }
            Err(refusal) => {
                panic!("a pinned observation inside its validity is admitted: {refusal}")
            }
        }
        let expired_offline = VerificationInput::new(
            &declarations,
            &snapshot,
            &signatures,
            std::slice::from_ref(&retained),
            &ledger,
            EpochObservation::at(200),
            FreshnessMode::offline(offline_witness),
        )
        .with_snapshot_declaration(declaration.index());
        match store.verify(&expired_offline) {
            Err(refusal) => {
                assert_eq!(
                    refusal.code(),
                    Some(RegistryDiagnosticCode::SnapshotExpired)
                );
            }
            Ok(_) => panic!("an offline witness never extends snapshot validity"),
        }
        let rolled_back = RetainedState::for_source(widget.source().clone(), 9);
        let rollback = VerificationInput::new(
            &declarations,
            &snapshot,
            &signatures,
            std::slice::from_ref(&rolled_back),
            &ledger,
            EpochObservation::at(150),
            FreshnessMode::online(),
        );
        match store.verify(&rollback) {
            Err(refusal) => assert_eq!(refusal.code(), Some(RegistryDiagnosticCode::Rollback)),
            Ok(_) => panic!("a snapshot below the retained minimum is refused"),
        }
        let equivocated = RetainedState::for_source(widget.source().clone(), 1)
            .with_content(4, declared("other-content"));
        let freeze = VerificationInput::new(
            &declarations,
            &snapshot,
            &signatures,
            std::slice::from_ref(&equivocated),
            &ledger,
            EpochObservation::at(150),
            FreshnessMode::online(),
        );
        match store.verify(&freeze) {
            Err(refusal) => {
                assert_eq!(
                    refusal.code(),
                    Some(RegistryDiagnosticCode::FreezeEquivocation)
                );
            }
            Ok(_) => panic!("one sequence with two contents is refused"),
        }
        let foreign = source_of("other", "widget");
        let unbound_entry = widget.clone().with_source(foreign.clone());
        let unbound_snapshot = snapshot_of(5, 100, 200, &[unbound_entry]);
        let unbound_signatures = vec![declared_signature(
            &record,
            unbound_snapshot.content_digest(),
        )];
        let unbound = VerificationInput::new(
            &declarations,
            &unbound_snapshot,
            &unbound_signatures,
            std::slice::from_ref(&retained),
            &ledger,
            EpochObservation::at(150),
            FreshnessMode::online(),
        );
        match store.verify(&unbound) {
            Err(refusal) => {
                assert_eq!(
                    refusal.code(),
                    Some(RegistryDiagnosticCode::AttributionMissing)
                );
                assert!(!refusal.is_bound());
                assert_eq!(refusal.causing_entry(), Some(0));
                assert_eq!(refusal.declaration_identity(), &foreign);
            }
            Ok(_) => panic!("an entry no declaration binds is refused before parsing"),
        }
    }

    /// `GNT-27.8` requires one authenticated tuple to name one set of bytes forever.
    #[test]
    fn registry_publications_are_immutable() {
        let declaration = declaration(0, "widget", source_of("acme", "widget"));
        let acme = publisher("acme", "acme-key");
        let first = entry("acme", "widget", "1.0.0", &acme, "manifest-a", "artifact-a");
        let first_snapshot = snapshot_of(3, 100, 200, std::slice::from_ref(&first));
        let ledger = ledger_of(&declaration, &first_snapshot);
        let root = root(
            "acme-root",
            declaration.identity().clone(),
            acme.clone(),
            scope_of_package("acme", "widget"),
        );
        let store = match TrustStore::new(&[root], std::slice::from_ref(&key("acme-key")), &[]) {
            Ok(store) => store,
            Err(error) => panic!("the declared store is valid: {error:?}"),
        };
        let changed = entry("acme", "widget", "1.0.0", &acme, "manifest-a", "artifact-z");
        let changed_snapshot = snapshot_of(4, 100, 200, std::slice::from_ref(&changed));
        let changed_retained = RetainedState::for_source(declaration.identity().clone(), 1);
        let changed_signatures = [declared_signature(
            &key("acme-key"),
            changed_snapshot.content_digest(),
        )];
        let changed_input = VerificationInput::new(
            std::slice::from_ref(&declaration),
            &changed_snapshot,
            &changed_signatures,
            std::slice::from_ref(&changed_retained),
            &ledger,
            EpochObservation::at(150),
            FreshnessMode::online(),
        );
        match store.verify(&changed_input) {
            Err(refusal) => {
                assert_eq!(
                    refusal.code(),
                    Some(RegistryDiagnosticCode::PublicationImmutable)
                );
                assert_eq!(refusal.clause(), "GNT-27.8-publication-immutability");
            }
            Ok(_) => panic!("a differing publication is refused"),
        }
        assert_eq!(ledger.len(), 1);
    }

    /// `GNT-27.12` requires every declaration's evidence to be bound before any source is
    /// parsed, and requires stale or tampered evidence to be detected by recomputation.
    #[test]
    fn registry_lockfile_evidence_binds_before_parsing() {
        let acme = publisher("acme", "acme-key");
        let widget = entry("acme", "widget", "1.0.0", &acme, "manifest-a", "artifact-a");
        let snapshot = snapshot_of(4, 100, 200, std::slice::from_ref(&widget));
        let declaration = declaration(0, "widget", widget.source().clone());
        let declarations = vec![declaration.clone()];
        let record = record_of(&widget, &snapshot, &declaration);
        assert_eq!(record.evidence(), record.attest());
        let lockfile = match Lockfile::new(std::slice::from_ref(&record)) {
            Ok(lockfile) => lockfile,
            Err(error) => panic!("the declared lockfile is valid: {error:?}"),
        };
        let gate = match lockfile.bind(&declarations, &[&snapshot]) {
            Ok(gate) => gate,
            Err(refusal) => panic!("the declared evidence binds: {refusal}"),
        };
        assert_eq!(gate.bound(), 1);
        assert_eq!(gate.snapshot(), snapshot.identity());
        assert_eq!(
            gate.admit_parse(0, &DeliveredRelease::direct(&widget, snapshot.identity()))
                .map(SourceIdentity::canonical_text),
            Ok(declaration.identity().canonical_text())
        );
        let (store, retained, signatures) = authenticated_fixture(&declaration, &snapshot);
        let empty = PublicationLedger::new();
        let verification = VerificationInput::new(
            std::slice::from_ref(&declaration),
            &snapshot,
            &signatures,
            std::slice::from_ref(&retained),
            &empty,
            EpochObservation::at(snapshot.issue_epoch()),
            FreshnessMode::online(),
        );
        let verified = match store.verify(&verification) {
            Ok(verified) => verified,
            Err(refusal) => panic!("the declared snapshot verifies: {refusal}"),
        };
        let tampered = match LockfileRecord::restore(
            &widget,
            &verified,
            &retained,
            &declaration,
            LockfileInputs {
                targets: widget
                    .target_artifacts()
                    .iter()
                    .map(TargetArtifact::target)
                    .collect(),
                target_artifacts: widget.target_artifacts().to_vec(),
                ..LockfileInputs::default()
            },
            declared("tampered-evidence"),
        ) {
            Ok(record) => record,
            Err(error) => panic!("the restored record is valid: {error:?}"),
        };
        let tampered_lockfile = match Lockfile::new(&[tampered]) {
            Ok(lockfile) => lockfile,
            Err(error) => panic!("the declared lockfile is valid: {error:?}"),
        };
        match tampered_lockfile.bind(&declarations, &[&snapshot]) {
            Err(refusal) => {
                assert_eq!(
                    refusal.code(),
                    Some(RegistryDiagnosticCode::LockfileEvidenceStale)
                );
                assert_eq!(refusal.clause(), "GNT-27.12-lockfile-evidence-binding");
            }
            Ok(_) => panic!("tampered evidence is refused"),
        }
        let unbound = vec![
            declaration.clone(),
            self::declaration(1, "gadget", source_of("acme", "gadget")),
        ];
        match lockfile.bind(&unbound, &[&snapshot]) {
            Err(refusal) => {
                assert_eq!(
                    refusal.code(),
                    Some(RegistryDiagnosticCode::LockfileEvidenceUnbound)
                );
                assert_eq!(refusal.declaration_index(), 1);
            }
            Ok(_) => panic!("a declaration without evidence is refused"),
        }
        let other = entry("acme", "gadget", "1.0.0", &acme, "manifest-b", "artifact-b");
        let other_snapshot = snapshot_of(5, 100, 200, &[widget, other]);
        match lockfile.bind(&declarations, &[&other_snapshot]) {
            Err(refusal) => {
                assert_eq!(
                    refusal.code(),
                    Some(RegistryDiagnosticCode::LockfileEvidenceStale)
                );
            }
            Ok(_) => panic!("evidence bound to another snapshot is stale"),
        }
    }

    /// `GNT-27.9` requires a yank to remove a release from ordinary resolution without ever
    /// rewriting a lockfile.
    #[test]
    fn registry_yanks_never_rewrite_a_lockfile() {
        let record = key("acme-key");
        let acme = publisher("acme", "acme-key");
        let published = entry("acme", "widget", "1.0.0", &acme, "manifest-a", "artifact-a");
        let yanked = published.clone().with_publication(PublicationState::Yanked);
        let published_snapshot = snapshot_of(3, 100, 200, std::slice::from_ref(&published));
        let snapshot = snapshot_of(4, 100, 200, std::slice::from_ref(&yanked));
        let declaration = declaration(0, "widget", yanked.source().clone());
        let declarations = vec![declaration.clone()];
        let root = root(
            "acme-root",
            declaration.identity().clone(),
            acme.clone(),
            scope_of_package("acme", "widget"),
        );
        let store = match TrustStore::new(&[root], std::slice::from_ref(&record), &[]) {
            Ok(store) => store,
            Err(error) => panic!("the declared store is valid: {error:?}"),
        };
        let published_ledger = ledger_of(&declaration, &published_snapshot);
        let published_retained = RetainedState::for_source(declaration.identity().clone(), 3)
            .with_content(3, published_snapshot.content_digest());
        let published_signatures = vec![declared_signature(
            &record,
            published_snapshot.content_digest(),
        )];
        let published_input = VerificationInput::new(
            &declarations,
            &published_snapshot,
            &published_signatures,
            std::slice::from_ref(&published_retained),
            &published_ledger,
            EpochObservation::at(150),
            FreshnessMode::online(),
        );
        let published_verified = match store.verify(&published_input) {
            Ok(verified) => verified,
            Err(refusal) => panic!("the published snapshot verifies: {refusal}"),
        };
        let ledger = ledger_of(&declaration, &snapshot);
        let retained = RetainedState::for_source(declaration.identity().clone(), 4)
            .with_content(4, snapshot.content_digest());
        let signatures = vec![declared_signature(&record, snapshot.content_digest())];
        let input = VerificationInput::new(
            &declarations,
            &snapshot,
            &signatures,
            std::slice::from_ref(&retained),
            &ledger,
            EpochObservation::at(150),
            FreshnessMode::online(),
        );
        let verified = match store.verify(&input) {
            Ok(verified) => verified,
            Err(refusal) => panic!("the yanked snapshot verifies: {refusal}"),
        };
        assert!(
            resolve_new_release(
                &declaration,
                &published_verified,
                &published_retained,
                &published
            )
            .is_ok()
        );
        match resolve_new_release(&declaration, &verified, &retained, &yanked) {
            Err(refusal) => {
                assert_eq!(refusal.code(), Some(RegistryDiagnosticCode::ReleaseYanked));
                assert_eq!(refusal.clause(), "GNT-27.9-yank-semantics");
            }
            Ok(_) => panic!("a yanked release is not resolved anew"),
        }
        let record = record_of(&published, &published_snapshot, &declaration);
        let lockfile = match Lockfile::new(&[record]) {
            Ok(lockfile) => lockfile,
            Err(error) => panic!("the declared lockfile is valid: {error:?}"),
        };
        assert_eq!(lockfile.replay().len(), 1);
        assert_eq!(
            lockfile.replay()[0].publication(),
            PublicationState::Published
        );
        match lockfile.rewrite_kept(&declaration, &[], &verified, &retained) {
            Err(refusal) => {
                assert_eq!(
                    refusal.code(),
                    Some(RegistryDiagnosticCode::LockfileRewriteRefused)
                );
            }
            Ok(_) => panic!("a rewrite dropping a yanked release is refused"),
        }
        match lockfile.rewrite_kept(&declaration, &[0], &verified, &retained) {
            Ok(kept) => assert_eq!(kept.replay().len(), 1),
            Err(refusal) => panic!("a rewrite keeping every record is admitted: {refusal}"),
        }
    }

    /// `GNT-27.10` requires an authenticated advisory to refuse the affected artifact and never
    /// to substitute code or rewrite a lockfile.
    #[test]
    fn registry_advisories_refuse_builds_but_never_substitute_code() {
        let record = key("acme-key");
        let acme = publisher("acme", "acme-key");
        let acme_root = root(
            "acme-root",
            source_of("acme", "widget"),
            acme.clone(),
            scope_of_package("acme", "widget"),
        );
        let store = match TrustStore::new(&[acme_root], std::slice::from_ref(&record), &[]) {
            Ok(store) => store,
            Err(error) => panic!("the declared store is valid: {error:?}"),
        };
        let declaration = declaration(0, "widget", source_of("acme", "widget"));
        let scope = match AdvisoryScope::new(
            source_of("acme", "widget"),
            "acme",
            "widget",
            "1.0.0",
            &[
                match TargetArtifact::new(TargetKind::Library, declared("artifact-a")) {
                    Ok(artifact) => artifact,
                    Err(error) => panic!("the declared target artifact is valid: {error:?}"),
                },
            ],
        ) {
            Ok(scope) => scope,
            Err(error) => panic!("the declared advisory scope is valid: {error:?}"),
        };
        let advisory = match SecurityAdvisory::new("GNT-ADV-1", scope, Severity::RefuseAllExecution)
        {
            Ok(advisory) => advisory,
            Err(error) => panic!("the declared advisory is valid: {error:?}"),
        };
        let signature = declared_signature(&record, advisory.digest());
        let mut advisories = AdvisoryStore::new();
        match advisories.admit(
            &declaration,
            advisory.clone(),
            signature,
            acme.clone(),
            &store,
            5,
        ) {
            Ok(()) => assert_eq!(advisories.len(), 1),
            Err(refusal) => panic!("the authenticated advisory is admitted: {refusal}"),
        }
        let covered = match RunRequest::new(
            source_of("acme", "widget"),
            "acme",
            "widget",
            "1.0.0",
            TargetKind::Library,
            declared("artifact-a"),
        ) {
            Ok(request) => request.durable(),
            Err(error) => panic!("the declared request is valid: {error:?}"),
        };
        match advisories.admit_run(&declaration, &covered) {
            Err(refusal) => {
                assert_eq!(
                    refusal.code(),
                    Some(RegistryDiagnosticCode::AdvisoryRefusesBuild)
                );
                assert_eq!(
                    refusal.clause(),
                    "GNT-27.10-security-revocation-and-durable-execution-policy"
                );
            }
            Ok(_) => panic!("a covered artifact is refused"),
        }
        let substitute = covered
            .clone()
            .with_substitute(source_of("other", "widget"));
        match advisories.admit_run(&declaration, &substitute) {
            Err(refusal) => {
                assert_eq!(
                    refusal.code(),
                    Some(RegistryDiagnosticCode::AdvisorySubstitutionRefused)
                );
            }
            Ok(_) => panic!("a revocation never substitutes code"),
        }
        let unaffected = match RunRequest::new(
            source_of("acme", "widget"),
            "acme",
            "widget",
            "1.0.0",
            TargetKind::Library,
            declared("artifact-b"),
        ) {
            Ok(request) => request,
            Err(error) => panic!("the declared request is valid: {error:?}"),
        };
        match advisories.admit_run(&declaration, &unaffected) {
            Ok(admitted) => {
                assert_eq!(admitted.artifact(), declared("artifact-b"));
                assert!(!admitted.is_durable());
            }
            Err(refusal) => panic!("an unaffected artifact is admitted: {refusal}"),
        }
        let forged = DeclaredSignature::declared(record.key().clone(), declared("forged"));
        let mut other = AdvisoryStore::new();
        match other.admit(&declaration, advisory, forged, acme, &store, 5) {
            Err(refusal) => {
                assert_eq!(
                    refusal.code(),
                    Some(RegistryDiagnosticCode::SignatureUnverified)
                );
            }
            Ok(()) => panic!("an unverified advisory is refused"),
        }
    }

    /// `GNT-27.11` requires a pinned checkout to match its pin exactly and to carry no modified
    /// path.
    #[test]
    fn registry_pinned_trees_refuse_modified_paths_and_changed_content() {
        let spelling = "a".repeat(40);
        let commit = match CommitId::new(&spelling) {
            Ok(commit) => commit,
            Err(error) => panic!("the declared commit is valid: {error:?}"),
        };
        let source = match SourceIdentity::vcs("acme.widget", &commit) {
            Ok(identity) => identity,
            Err(error) => panic!("the declared identity is valid: {error:?}"),
        };
        let pin = match VcsPin::new(source.clone(), &spelling, declared("content-a")) {
            Ok(pin) => pin,
            Err(error) => panic!("the declared pin is valid: {error:?}"),
        };
        let declaration = declaration(0, "widget", source.clone());
        let clean =
            PinnedTree::observed(source.clone(), Some(commit.clone()), declared("content-a"));
        match verify_pinned_tree(&declaration, &pin, &clean) {
            Ok(checkout) => {
                assert_eq!(checkout.content().digest(), declared("content-a"));
                assert_eq!(checkout.commit(), pin.commit());
            }
            Err(refusal) => panic!("a clean pinned checkout verifies: {refusal}"),
        }
        let modified = clean.clone().modified("crate::lib");
        match verify_pinned_tree(&declaration, &pin, &modified) {
            Err(refusal) => {
                assert_eq!(refusal.code(), Some(RegistryDiagnosticCode::ModifiedPath));
                assert_eq!(
                    refusal.clause(),
                    "GNT-27.11-vcs-path-and-vendor-source-verification"
                );
            }
            Ok(_) => panic!("a modified path is refused"),
        }
        let changed = PinnedTree::observed(source, Some(commit), declared("content-z"));
        match verify_pinned_tree(&declaration, &pin, &changed) {
            Err(refusal) => {
                assert_eq!(
                    refusal.code(),
                    Some(RegistryDiagnosticCode::ContentMismatch)
                );
            }
            Ok(_) => panic!("changed content is refused"),
        }
        let unpinned = PinnedTree::observed(pin.source().clone(), None, declared("content-a"));
        match verify_pinned_tree(&declaration, &pin, &unpinned) {
            Err(refusal) => {
                assert_eq!(refusal.code(), Some(RegistryDiagnosticCode::VcsPinMismatch))
            }
            Ok(_) => panic!("an unpinned checkout is refused"),
        }
    }
}
