//! Pure symbolic-domain, canonical-identity, and identifier-security model.
//!
//! This module is the machine-checked identity and identifier-security model for
//! `GNT-18.0` through `GNT-18.13-identity-version-pinning`. It decides the closed
//! domain list of `GNT-18.1-symbolic-identity-domains`, one canonical byte
//! encoding and typed digest per domain, the source-spelling admission of
//! `GNT-18.3-source-spelling-admission`, the confusable-skeleton and Recommended
//! single-script policy of `GNT-18.4-confusable-and-script-policy`, reserved-word
//! occupancy, the symmetric collision relation of `GNT-18.6-collision-relation`,
//! external-name mapping, generated-alias derivation, hostile-label rendering,
//! and typed identity authority.
//!
//! Source-spelling admission cites `GNT-4.12` and `GNT-13.2` rather than
//! restating them: every NFC, `XID_Start`, `XID_Continue`, excluded-scalar,
//! Reserved-script, skeleton, and case-mapping decision is taken from
//! `gantry_core::unicode`, whose tables are the pinned Unicode 16.0.0 tables and
//! the pinned UTS #39 skeleton tables. This module defines no scalar class of its
//! own and offers no weaker path into a name.
//!
//! Scope is deliberately narrow. Every rule here is a pure function of its own
//! arguments: this module never reads a host path, an environment variable, a
//! clock, a locale, a registry, or a discovery, response, or traversal order, and
//! it exposes no constructor that accepts one. An identity is derived from one
//! symbolic domain and one admitted spelling and from nothing else: no display
//! label, host path, discovery order, or graph path participates, two identities
//! are the same identity if and only if their canonical bytes are identical, and
//! the same unordered inputs produce the same canonical bytes, digests, aliases,
//! and diagnostics under every permutation.
//!
//! A display label is presentation. It is bounded, renders control and
//! bidi-invisible scalars escaped by code point, keeps the canonical identity
//! available beside it, and implements no equality, ordering, or hashing, so no
//! label can become a lookup, authorization, policy, approval, transcript, audit,
//! or durable-recovery key; those decisions use [`IdentityKey`].
//!
//! Rust `Debug` and `Display` renderings are presentation only and are never
//! protocol identities. The exact portable identity spelling is
//! [`CanonicalSymbolicIdentity::as_str`], which renders the canonical identity and
//! is never a label.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use gantry_core::unicode::{
    Script, UNICODE_VERSION, confusable_skeleton, is_identifier_recommended,
    is_identifier_security_excluded, is_nfc, is_xid_continue, is_xid_start, normalize_nfc, script,
    to_full_lowercase,
};

use crate::authority::digest_fields;
use crate::manifest::encode_hex;

/// Domain separator for canonical symbolic-identity derivation.
const IDENTITY_DOMAIN: &str = "gantry.symbolic-identity/v1";

/// Domain separator for canonical generated-alias maps.
const ALIAS_MAP_DOMAIN: &str = "gantry.identifier-alias-map/v1";

/// The largest accepted spelling, in bytes.
pub const SPELLING_LIMIT_BYTES: usize = 512;

/// The default number of scalars one display label may render.
pub const DISPLAY_LABEL_MAX_SCALARS: usize = 256;

/// The default declared maximum length of a lookup namespace, in scalars.
pub const DEFAULT_NAMESPACE_MAX_SCALARS: usize = 64;

/// The four-letter Unicode short name of the Common script value.
const SCRIPT_COMMON: &str = "Zyyy";

/// The four-letter Unicode short name of the Inherited script value.
const SCRIPT_INHERITED: &str = "Zinh";

/// One frozen published diagnostic identity of this model.
///
/// The codes are frozen and are the ones already registered for the identifier
/// category; a consumer matches on [`Self::as_str`], and no code is invented
/// here. The variant order is the sorted code order, so [`Self::ALL`] is already
/// in the order the registry requires.
///
/// A condition this module can decide but that has no published code is a typed
/// [`IdentifierError`] variant whose [`IdentifierError::code`] is `None`; such a
/// condition MUST NOT be reported under another condition's code.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum IdentifierDiagnosticCode {
    /// `identifier-confusable-collision`
    ConfusableCollision,
    /// `identifier-not-nfc`
    NotNfc,
    /// `identifier-script-warning`
    ScriptWarning,
    /// `identifier-security`
    IdentifierSecurity,
}

impl IdentifierDiagnosticCode {
    /// Every published code of this model, in sorted code order.
    pub const ALL: [Self; 4] = [
        Self::ConfusableCollision,
        Self::NotNfc,
        Self::ScriptWarning,
        Self::IdentifierSecurity,
    ];

    /// Returns the exact frozen code spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ConfusableCollision => "identifier-confusable-collision",
            Self::NotNfc => "identifier-not-nfc",
            Self::ScriptWarning => "identifier-script-warning",
            Self::IdentifierSecurity => "identifier-security",
        }
    }

    /// Returns the meaning already registered for this code.
    #[must_use]
    pub const fn meaning(self) -> &'static str {
        match self {
            Self::ConfusableCollision => {
                "Distinct identifier spellings share one Unicode 16 confusable skeleton."
            }
            Self::NotNfc => "An identifier spelling is not already Unicode 16 NFC.",
            Self::ScriptWarning => "An identifier is outside one Recommended single-script set.",
            Self::IdentifierSecurity => {
                "An identifier contains a Unicode scalar excluded by Gantry security rules."
            }
        }
    }

    /// Returns the clause that owns this condition.
    #[must_use]
    pub const fn requirement(self) -> &'static str {
        match self {
            Self::ConfusableCollision | Self::ScriptWarning => {
                "GNT-18.4-confusable-and-script-policy"
            }
            Self::NotNfc | Self::IdentifierSecurity => "GNT-18.3-source-spelling-admission",
        }
    }
}

/// One member of the closed identity-carrying domain list of
/// `GNT-18.1-symbolic-identity-domains`.
///
/// Only the domains whose spellings may enter the source identifier domain are
/// source spellings: every other domain of this list is a declared name that MUST
/// NOT enter it, which is what [`Self::may_enter_source_identifier_domain`]
/// decides.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SymbolicDomain {
    /// Source identifiers.
    SourceIdentifier,
    /// Package names.
    PackageName,
    /// Namespace names.
    NamespaceName,
    /// Feature names.
    FeatureName,
    /// Dependency-alias names.
    DependencyAliasName,
    /// Generated declarations.
    GeneratedDeclaration,
    /// Agent slots.
    AgentSlot,
    /// Capability slots.
    CapabilitySlot,
    /// Tools.
    ToolName,
    /// Providers.
    ProviderName,
    /// Policy subjects.
    PolicySubject,
    /// Approval subjects.
    ApprovalSubject,
}

impl SymbolicDomain {
    /// Every domain of the closed list, in the order the clause publishes it.
    pub const ALL: [Self; 12] = [
        Self::SourceIdentifier,
        Self::PackageName,
        Self::NamespaceName,
        Self::FeatureName,
        Self::DependencyAliasName,
        Self::GeneratedDeclaration,
        Self::AgentSlot,
        Self::CapabilitySlot,
        Self::ToolName,
        Self::ProviderName,
        Self::PolicySubject,
        Self::ApprovalSubject,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::SourceIdentifier => "source-identifier",
            Self::PackageName => "package-name",
            Self::NamespaceName => "namespace-name",
            Self::FeatureName => "feature-name",
            Self::DependencyAliasName => "dependency-alias-name",
            Self::GeneratedDeclaration => "generated-declaration",
            Self::AgentSlot => "agent-slot",
            Self::CapabilitySlot => "capability-slot",
            Self::ToolName => "tool-name",
            Self::ProviderName => "provider-name",
            Self::PolicySubject => "policy-subject",
            Self::ApprovalSubject => "approval-subject",
        }
    }

    /// Parses one exact portable spelling, rejecting anything outside the list.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|domain| domain.wire_name() == value)
    }

    /// Decodes one domain, reporting a spelling outside the list.
    pub fn parse(value: &str) -> Result<Self, IdentifierError> {
        Self::from_wire_name(value).ok_or_else(|| IdentifierError::UnknownDomain {
            spelling: Arc::from(value),
        })
    }

    /// Returns whether this domain's spellings may enter the source identifier domain.
    #[must_use]
    pub const fn may_enter_source_identifier_domain(self) -> bool {
        matches!(
            self,
            Self::SourceIdentifier | Self::PackageName | Self::NamespaceName
        )
    }

    /// Returns the closed alias prefix of this domain.
    ///
    /// A generated alias carries this prefix, so two domains of one alias map
    /// never derive one alias from one spelling and a generated alias is a pure
    /// function of one domain, one name, and the declared namespace facts.
    #[must_use]
    pub const fn alias_prefix(self) -> &'static str {
        match self {
            Self::SourceIdentifier => "src",
            Self::PackageName => "pkg",
            Self::NamespaceName => "ns",
            Self::FeatureName => "feature",
            Self::DependencyAliasName => "alias",
            Self::GeneratedDeclaration => "gen",
            Self::AgentSlot => "agent",
            Self::CapabilitySlot => "cap",
            Self::ToolName => "tool",
            Self::ProviderName => "provider",
            Self::PolicySubject => "policy",
            Self::ApprovalSubject => "approval",
        }
    }
}

/// One member of the closed collision-condition vocabulary of
/// `GNT-18.6-collision-relation`.
///
/// [`Self::ALL`] is the vocabulary order of the clause, which is also the
/// precedence order [`collision_condition`] applies, so a pair that satisfies
/// more than one condition is reported under the first one in this order and
/// never under an order-dependent choice.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CollisionCondition {
    /// The two spellings are byte-identical.
    Exact,
    /// The two spellings are equal under the pinned full case mappings.
    Case,
    /// The two spellings share one prefix at the declared maximum length.
    Truncation,
    /// The two spellings are canonically equivalent without being byte-identical.
    Normalization,
    /// One of the two spellings is a reserved word of the selected edition.
    ReservedWord,
    /// The two spellings share one UTS #39 confusable skeleton.
    Confusable,
}

impl CollisionCondition {
    /// Every collision condition, in the vocabulary and precedence order.
    pub const ALL: [Self; 6] = [
        Self::Exact,
        Self::Case,
        Self::Truncation,
        Self::Normalization,
        Self::ReservedWord,
        Self::Confusable,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Case => "case",
            Self::Truncation => "truncation",
            Self::Normalization => "normalization",
            Self::ReservedWord => "reserved-word",
            Self::Confusable => "confusable",
        }
    }

    /// Parses one exact portable spelling, rejecting anything outside the list.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|condition| condition.wire_name() == value)
    }

    /// Decodes one collision condition, reporting a spelling outside the list.
    pub fn parse(value: &str) -> Result<Self, IdentifierError> {
        Self::from_wire_name(value).ok_or_else(|| IdentifierError::UnknownCollisionCondition {
            spelling: Arc::from(value),
        })
    }

    /// Returns the frozen published code of this condition, if it has one.
    #[must_use]
    pub const fn code(self) -> Option<IdentifierDiagnosticCode> {
        match self {
            Self::Confusable => Some(IdentifierDiagnosticCode::ConfusableCollision),
            Self::Exact
            | Self::Case
            | Self::Truncation
            | Self::Normalization
            | Self::ReservedWord => None,
        }
    }

    /// Returns the clause that owns this condition.
    #[must_use]
    pub const fn requirement(self) -> &'static str {
        "GNT-18.6-collision-relation"
    }
}

/// One identity version of `GNT-18.13-identity-version-pinning`.
///
/// The Unicode version, the normalization form, the case-folding set, the UTS #39
/// skeleton version, and the encoding identity are pinned together in this one
/// version, and only this version is supported: an identity recorded under any
/// other version is rejected rather than re-interpreted.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct IdentityVersion(u32);

impl IdentityVersion {
    /// The only supported identity version.
    pub const PINNED: Self = Self(1);

    /// The pinned Unicode version, taken from the pinned tables.
    pub const UNICODE_VERSION: (u8, u8, u8) = UNICODE_VERSION;

    /// The pinned normalization form.
    pub const NORMALIZATION: &'static str = "nfc";

    /// The pinned case-folding set.
    pub const CASE_FOLDING: &'static str = "full-locale-independent";

    /// The pinned UTS #39 skeleton version.
    pub const SKELETON: &'static str = "uts39-16.0.0";

    /// The pinned encoding identity.
    pub const ENCODING: &'static str = "gantry.symbolic-identity/v1";

    /// Decodes one supported identity version.
    pub fn new(version: u32) -> Result<Self, IdentifierError> {
        if version == Self::PINNED.value() {
            Ok(Self(version))
        } else {
            Err(IdentifierError::UnsupportedIdentityVersion { version })
        }
    }

    /// Returns the numeric identity version.
    #[must_use]
    pub const fn value(self) -> u32 {
        self.0
    }
}

/// One typed canonical-symbolic-identity digest.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SymbolicIdentityDigest(Arc<str>);

impl SymbolicIdentityDigest {
    /// Decodes one exact lowercase hexadecimal SHA-256 digest.
    pub fn from_hex(value: &str) -> Result<Self, IdentifierError> {
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

/// Validates one lowercase hexadecimal SHA-256 digest spelling.
fn validate_digest(value: &str) -> Result<(), IdentifierError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(IdentifierError::InvalidDigest {
            value: Arc::from(value),
        });
    }
    Ok(())
}

/// One versioned symbolic-identity record of
/// `GNT-18.2-canonical-symbolic-identity`.
///
/// The record carries one canonical symbolic identity as closed properties. An
/// unsupported record version or an unknown record property is rejected, never
/// repaired, and a record that cannot establish every input is reported rather
/// than asserted equal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SymbolicIdentityRecord {
    version: u32,
    properties: BTreeMap<Arc<str>, Arc<str>>,
}

impl SymbolicIdentityRecord {
    /// The only supported identity-record version.
    pub const VERSION: u32 = 1;

    /// The closed property vocabulary of an identity record.
    pub const PROPERTIES: [&'static str; 3] = ["canonical_name", "domain", "identity_version"];

    /// Decodes one closed identity record, rejecting unknown properties.
    pub fn new(version: u32, properties: &[(&str, &str)]) -> Result<Self, IdentifierError> {
        if version != Self::VERSION {
            return Err(IdentifierError::UnsupportedIdentityVersion { version });
        }
        let mut decoded = BTreeMap::new();
        for (key, value) in properties {
            if !Self::PROPERTIES.contains(key) {
                return Err(IdentifierError::UnknownIdentityProperty {
                    property: Arc::from(*key),
                });
            }
            if decoded.insert(Arc::from(*key), Arc::from(*value)).is_some() {
                return Err(IdentifierError::DuplicateIdentityProperty {
                    property: Arc::from(*key),
                });
            }
        }
        Ok(Self {
            version,
            properties: decoded,
        })
    }

    /// Encodes the record of one canonical identity.
    #[must_use]
    pub fn of_identity(identity: &CanonicalSymbolicIdentity) -> Self {
        let mut properties = BTreeMap::new();
        properties.insert(
            Arc::from("canonical_name"),
            Arc::from(identity.canonical_name()),
        );
        properties.insert(
            Arc::from("domain"),
            Arc::from(identity.domain().wire_name()),
        );
        properties.insert(
            Arc::from("identity_version"),
            Arc::from(identity.identity_version().value().to_string()),
        );
        Self {
            version: Self::VERSION,
            properties,
        }
    }

    /// Returns the record version.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// Returns one recorded property value.
    #[must_use]
    pub fn property(&self, key: &str) -> Option<&str> {
        self.properties.get(key).map(AsRef::as_ref)
    }

    /// Reconstructs the canonical identity this record carries.
    pub fn identity(&self) -> Result<CanonicalSymbolicIdentity, IdentifierError> {
        let domain = SymbolicDomain::parse(self.require("domain")?)?;
        let version = self.require("identity_version")?;
        let version =
            version
                .parse::<u32>()
                .map_err(|_| IdentifierError::MalformedIdentityProperty {
                    property: "identity_version",
                    value: Arc::from(version),
                })?;
        IdentityVersion::new(version)?;
        let name = DeclaredName::new(self.require("canonical_name")?)?;
        CanonicalSymbolicIdentity::of_declared(domain, &name)
    }

    /// Returns one required property or reports it missing.
    fn require(&self, key: &'static str) -> Result<&str, IdentifierError> {
        self.properties
            .get(key)
            .map(AsRef::as_ref)
            .ok_or(IdentifierError::MissingIdentityProperty { property: key })
    }
}

/// One canonical symbolic identity of
/// `GNT-18.2-canonical-symbolic-identity`.
///
/// The identity of one entry of a symbolic domain is its canonical byte encoding.
/// Equality, ordering, and hashing read exactly those bytes, so two identities are
/// the same identity if and only if their canonical bytes are identical. The
/// identity is derived from one symbolic domain and one admitted spelling, and it
/// is never derived from a display label, a host path, a discovery order, or a
/// graph path: no constructor of this type accepts one.
#[derive(Clone, Debug)]
pub struct CanonicalSymbolicIdentity {
    domain: SymbolicDomain,
    identity_version: IdentityVersion,
    canonical_name: Arc<str>,
    canonical: Arc<[u8]>,
    digest: SymbolicIdentityDigest,
}

impl CanonicalSymbolicIdentity {
    /// Derives the one canonical identity of one declared name.
    pub fn of_declared(
        domain: SymbolicDomain,
        name: &DeclaredName,
    ) -> Result<Self, IdentifierError> {
        Self::encode(domain, name.as_str())
    }

    /// Derives the one canonical identity of one admitted source spelling.
    ///
    /// Only a domain whose spellings may enter the source identifier domain is
    /// accepted, because every other domain of
    /// `GNT-18.1-symbolic-identity-domains` is a declared name that MUST NOT
    /// enter it.
    pub fn of_source(
        domain: SymbolicDomain,
        spelling: &SourceSpelling,
    ) -> Result<Self, IdentifierError> {
        if !domain.may_enter_source_identifier_domain() {
            return Err(IdentifierError::DomainNotSourceAdmissible { domain });
        }
        Self::encode(domain, spelling.as_str())
    }

    /// Derives the one canonical identity of one external name.
    pub fn of_external(name: &ExternalName) -> Result<Self, IdentifierError> {
        Self::encode(name.domain(), name.spelling())
    }

    /// Decodes the identity one versioned record carries.
    pub fn from_record(record: &SymbolicIdentityRecord) -> Result<Self, IdentifierError> {
        record.identity()
    }

    /// Encodes one identity over one admitted spelling.
    fn encode(domain: SymbolicDomain, name: &str) -> Result<Self, IdentifierError> {
        let canonical = encode_identity(domain, IdentityVersion::PINNED, name);
        let digest = SymbolicIdentityDigest::from_digest(digest_fields(
            IDENTITY_DOMAIN,
            &[canonical.as_bytes()],
        ));
        Ok(Self {
            domain,
            identity_version: IdentityVersion::PINNED,
            canonical_name: Arc::from(name),
            canonical: Arc::from(canonical.as_bytes()),
            digest,
        })
    }

    /// Returns the symbolic domain of this identity.
    #[must_use]
    pub const fn domain(&self) -> SymbolicDomain {
        self.domain
    }

    /// Returns the identity version this identity is recorded under.
    #[must_use]
    pub const fn identity_version(&self) -> IdentityVersion {
        self.identity_version
    }

    /// Returns the admitted spelling this identity was derived from.
    #[must_use]
    pub fn canonical_name(&self) -> &str {
        &self.canonical_name
    }

    /// Returns the one canonical byte encoding.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }

    /// Returns the typed identity digest.
    #[must_use]
    pub const fn digest(&self) -> &SymbolicIdentityDigest {
        &self.digest
    }

    /// Returns the lowercase hexadecimal identity digest.
    #[must_use]
    pub fn digest_hex(&self) -> &str {
        self.digest.as_str()
    }

    /// Returns the versioned record that carries this identity.
    #[must_use]
    pub fn record(&self) -> SymbolicIdentityRecord {
        SymbolicIdentityRecord::of_identity(self)
    }

    /// Returns the exact portable identity spelling of this identity.
    #[must_use]
    pub fn as_str(&self) -> String {
        format!("{}:{}", self.domain.wire_name(), self.digest.as_str())
    }

    /// Returns the typed key of this identity.
    #[must_use]
    pub fn key(&self) -> IdentityKey {
        IdentityKey::of(self)
    }
}

impl PartialEq for CanonicalSymbolicIdentity {
    fn eq(&self, other: &Self) -> bool {
        self.canonical == other.canonical
    }
}

impl Eq for CanonicalSymbolicIdentity {}

impl Hash for CanonicalSymbolicIdentity {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.canonical.hash(state);
    }
}

impl PartialOrd for CanonicalSymbolicIdentity {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CanonicalSymbolicIdentity {
    fn cmp(&self, other: &Self) -> Ordering {
        self.canonical.cmp(&other.canonical)
    }
}

/// One admitted source spelling of the source identifier domain.
///
/// The constructor admits a spelling only when it satisfies the landed `GNT-4.12`
/// and `GNT-13.2` rules: it is in NFC; every scalar satisfies the Unicode 16.0.0
/// `XID_Start` and `XID_Continue` rules those blocks fix; and no scalar is a
/// default-ignorable, join-control, variation-selector, or bidi-control scalar. It
/// cites those blocks and adds no scalar class and no weaker path, and a spelling
/// that is not already NFC is rejected rather than normalized.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SourceSpelling(Arc<str>);

impl SourceSpelling {
    /// Admits one source spelling under the landed `GNT-4.12` and `GNT-13.2` rules.
    pub fn new(value: &str) -> Result<Self, IdentifierError> {
        admit(value)?;
        Ok(Self(Arc::from(value)))
    }

    /// Admits one source spelling in a domain whose spellings may enter source.
    pub fn in_domain(domain: SymbolicDomain, value: &str) -> Result<Self, IdentifierError> {
        if !domain.may_enter_source_identifier_domain() {
            return Err(IdentifierError::DomainNotSourceAdmissible { domain });
        }
        Self::new(value)
    }

    /// Returns the exact admitted spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns this spelling as one compared spelling of the collision relation.
    #[must_use]
    pub fn spelling(&self) -> NameSpelling {
        NameSpelling(self.0.clone())
    }
}

/// One admitted declared name of a lookup namespace.
///
/// A declared name is admitted under the same cited `GNT-4.12` and `GNT-13.2`
/// rules as [`SourceSpelling`], so a declared name is always a spelling the
/// identifier rules admit and never a repaired spelling.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DeclaredName(Arc<str>);

impl DeclaredName {
    /// Admits one declared name under the landed `GNT-4.12` and `GNT-13.2` rules.
    pub fn new(value: &str) -> Result<Self, IdentifierError> {
        admit(value)?;
        Ok(Self(Arc::from(value)))
    }

    /// Returns the exact admitted name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns this name as one compared spelling of the collision relation.
    #[must_use]
    pub fn spelling(&self) -> NameSpelling {
        NameSpelling(self.0.clone())
    }

    /// Returns the scripts this name carries.
    #[must_use]
    pub fn scripts(&self) -> ScriptSet {
        ScriptSet::of(&self.0)
    }

    /// Returns the Recommended single-script verdict of this name.
    #[must_use]
    pub fn script_classification(&self) -> ScriptClassification {
        ScriptClassification::of(&self.0)
    }

    /// Returns the UTS #39 confusable skeleton of this name.
    #[must_use]
    pub fn skeleton(&self) -> ConfusableSkeleton {
        ConfusableSkeleton::of(&self.0)
    }
}

/// One spelling the collision relation of `GNT-18.6-collision-relation` compares.
///
/// A collision is decided between spellings as they are written, including a
/// spelling that `GNT-18.3-source-spelling-admission` rejects, so this type
/// refuses only the empty spelling, an over-long spelling, and a spelling that
/// carries a control or excluded scalar: a hostile sequence never enters the
/// relation, while a non-NFC spelling enters it and is reported under its
/// collision condition instead of being silently normalized. This type is never an
/// identity, a lookup key, or authority.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NameSpelling(Arc<str>);

impl NameSpelling {
    /// Admits one compared spelling.
    pub fn new(value: &str) -> Result<Self, IdentifierError> {
        if value.is_empty() {
            return Err(IdentifierError::EmptySpelling);
        }
        if value.len() > SPELLING_LIMIT_BYTES {
            return Err(IdentifierError::TooLong {
                maximum: SPELLING_LIMIT_BYTES,
                spelling: Arc::from(value),
            });
        }
        for scalar in value.chars() {
            if is_excluded_scalar(scalar) {
                return Err(IdentifierError::ExcludedScalar { scalar });
            }
        }
        Ok(Self(Arc::from(value)))
    }

    /// Returns the exact compared spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns whether this spelling is admitted by the spelling rules.
    #[must_use]
    pub fn is_admitted(&self) -> bool {
        admit(&self.0).is_ok()
    }

    /// Returns whether this spelling is already in the pinned NFC.
    #[must_use]
    pub fn is_canonically_normalized(&self) -> bool {
        is_nfc(&self.0)
    }

    /// Returns the UTS #39 confusable skeleton of this spelling.
    #[must_use]
    pub fn skeleton(&self) -> ConfusableSkeleton {
        ConfusableSkeleton::of(&self.0)
    }

    /// Returns the scripts this spelling carries.
    #[must_use]
    pub fn scripts(&self) -> ScriptSet {
        ScriptSet::of(&self.0)
    }
}

impl From<&DeclaredName> for NameSpelling {
    fn from(value: &DeclaredName) -> Self {
        value.spelling()
    }
}

impl From<&SourceSpelling> for NameSpelling {
    fn from(value: &SourceSpelling) -> Self {
        value.spelling()
    }
}

impl From<&ExternalName> for NameSpelling {
    fn from(value: &ExternalName) -> Self {
        NameSpelling(value.spelling.clone())
    }
}

/// Admits one spelling under the landed `GNT-4.12` and `GNT-13.2` rules.
///
/// The rules are cited and not restated: this function asks
/// `gantry_core::unicode` for the pinned NFC, `XID_Start`, `XID_Continue`, and
/// excluded-scalar decisions and adds no scalar class and no weaker path. A
/// hostile scalar is reported before any structural rule, so an excluded scalar
/// is never reported as a structural violation.
fn admit(value: &str) -> Result<(), IdentifierError> {
    if value.is_empty() {
        return Err(IdentifierError::EmptySpelling);
    }
    if value.len() > SPELLING_LIMIT_BYTES {
        return Err(IdentifierError::TooLong {
            maximum: SPELLING_LIMIT_BYTES,
            spelling: Arc::from(value),
        });
    }
    for scalar in value.chars() {
        if is_excluded_scalar(scalar) {
            return Err(IdentifierError::ExcludedScalar { scalar });
        }
    }
    if !is_nfc(value) {
        return Err(IdentifierError::NotNfc {
            spelling: Arc::from(value),
        });
    }
    let mut scalars = value.chars();
    let first = scalars.next().unwrap_or('_');
    if !(first == '_' || is_xid_start(first)) {
        return Err(IdentifierError::NotXidStart { scalar: first });
    }
    for scalar in value.chars() {
        if !is_xid_continue(scalar) {
            return Err(IdentifierError::NotXidContinue { scalar });
        }
    }
    Ok(())
}

/// Returns whether one scalar is refused wherever a spelling enters this model.
fn is_excluded_scalar(scalar: char) -> bool {
    scalar.is_control() || is_identifier_security_excluded(scalar)
}

/// One UTS #39 confusable skeleton under the pinned Unicode version.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ConfusableSkeleton(Arc<str>);

impl ConfusableSkeleton {
    /// Computes the skeleton of one spelling under the pinned Unicode version.
    #[must_use]
    pub fn of(value: &str) -> Self {
        Self(Arc::from(confusable_skeleton(value)))
    }

    /// Returns the exact skeleton.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Returns whether two spellings share one confusable skeleton.
///
/// A shared skeleton is a collision condition and never an identity: a visual
/// resemblance is never an identity, so two spellings that share one skeleton stay
/// two canonical symbolic identities, and identity remains decided by the
/// canonical bytes of `GNT-18.2-canonical-symbolic-identity`.
#[must_use]
pub fn share_one_skeleton(left: &NameSpelling, right: &NameSpelling) -> bool {
    left.as_str() != right.as_str()
        && confusable_skeleton(left.as_str()) == confusable_skeleton(right.as_str())
}

/// The scripts one spelling carries under the pinned Unicode version.
///
/// The Common (`Zyyy`) and Inherited (`Zinh`) values carry no script of their own
/// and do not join the set, so a digit or a combining mark never makes a name
/// multi-script.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScriptSet(Vec<Script>);

impl ScriptSet {
    /// Computes the script set of one spelling.
    #[must_use]
    pub fn of(value: &str) -> Self {
        let mut scripts = value
            .chars()
            .map(script)
            .filter(|value| {
                let name = value.short_name();
                name != SCRIPT_COMMON && name != SCRIPT_INHERITED
            })
            .collect::<Vec<_>>();
        scripts.sort_unstable_by_key(|value| value.short_name());
        scripts.dedup();
        Self(scripts)
    }

    /// Returns the scripts in deterministic short-name order.
    #[must_use]
    pub fn scripts(&self) -> &[Script] {
        &self.0
    }

    /// Returns the number of distinct scripts.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether the spelling carries no script of its own.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns whether the spelling carries at most one script.
    #[must_use]
    pub fn is_single_script(&self) -> bool {
        self.0.len() <= 1
    }
}

/// The Recommended single-script verdict of
/// `GNT-18.4-confusable-and-script-policy`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ScriptClassification {
    /// One script that UTS #39 recommends, with every scalar recommended.
    Recommended {
        /// The single script of the name.
        script: Script,
    },
    /// A name outside the Recommended single-script set.
    OutsideRecommended {
        /// The scripts the name carries, in deterministic order.
        scripts: Vec<Script>,
    },
}

impl ScriptClassification {
    /// Classifies one spelling under the Recommended single-script rule.
    #[must_use]
    pub fn of(value: &str) -> Self {
        let scripts = ScriptSet::of(value);
        let recommended = value.chars().all(is_identifier_recommended);
        match scripts.scripts() {
            [script] if recommended => Self::Recommended { script: *script },
            _ => Self::OutsideRecommended {
                scripts: scripts.scripts().to_vec(),
            },
        }
    }

    /// Returns the scripts the name carries.
    #[must_use]
    pub fn scripts(&self) -> &[Script] {
        match self {
            Self::Recommended { script } => std::slice::from_ref(script),
            Self::OutsideRecommended { scripts } => scripts,
        }
    }

    /// Returns whether the name is inside the Recommended single-script set.
    #[must_use]
    pub const fn is_recommended(&self) -> bool {
        matches!(self, Self::Recommended { .. })
    }

    /// Returns the frozen published code of this verdict, if it has one.
    #[must_use]
    pub const fn code(&self) -> Option<IdentifierDiagnosticCode> {
        match self {
            Self::Recommended { .. } => None,
            Self::OutsideRecommended { .. } => Some(IdentifierDiagnosticCode::ScriptWarning),
        }
    }

    /// Returns the clause that owns this verdict.
    #[must_use]
    pub const fn requirement(&self) -> &'static str {
        "GNT-18.4-confusable-and-script-policy"
    }
}

/// One reported collision, carrying its pair in canonical order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CollisionDiagnostic {
    first: Arc<str>,
    second: Arc<str>,
    condition: CollisionCondition,
}

impl CollisionDiagnostic {
    /// Reports one collision, ordering the pair by canonical byte order.
    #[must_use]
    pub fn new(left: &NameSpelling, right: &NameSpelling, condition: CollisionCondition) -> Self {
        let (first, second) = if left.as_str() <= right.as_str() {
            (left.as_str(), right.as_str())
        } else {
            (right.as_str(), left.as_str())
        };
        Self {
            first: Arc::from(first),
            second: Arc::from(second),
            condition,
        }
    }

    /// Returns the smaller spelling of the pair.
    #[must_use]
    pub fn first(&self) -> &str {
        &self.first
    }

    /// Returns the larger spelling of the pair.
    #[must_use]
    pub fn second(&self) -> &str {
        &self.second
    }

    /// Returns the collision condition.
    #[must_use]
    pub const fn condition(&self) -> CollisionCondition {
        self.condition
    }

    /// Returns the frozen published code of this collision, if it has one.
    #[must_use]
    pub const fn code(&self) -> Option<IdentifierDiagnosticCode> {
        self.condition.code()
    }

    /// Returns the clause that owns this collision.
    #[must_use]
    pub const fn requirement(&self) -> &'static str {
        self.condition.requirement()
    }

    /// Returns whether the pair is in canonical byte order.
    #[must_use]
    pub fn is_canonical_order(&self) -> bool {
        self.first <= self.second
    }
}

/// Decides the symmetric collision relation of `GNT-18.6-collision-relation`.
///
/// The relation is total over compared spelling pairs, symmetric
/// (`collision_condition(a, b, namespace) == collision_condition(b, a, namespace)`
/// for every pair and every namespace), and independent of declaration,
/// insertion, discovery, and traversal order: it reads only the two spellings and
/// the declared namespace facts, and the diagnostic it returns carries the pair in
/// canonical byte order, so neither declaration order nor traversal order decides
/// an outcome. Conditions are reported in the vocabulary order of the clause, so a
/// pair that satisfies more than one condition is reported under the first one in
/// that order, and a collision is never resolved by preferring a declaration, a
/// discovery order, or a display form.
#[must_use]
pub fn collision_condition(
    left: &NameSpelling,
    right: &NameSpelling,
    namespace: &LookupNamespace,
) -> Option<CollisionDiagnostic> {
    if left.as_str() == right.as_str() {
        return Some(CollisionDiagnostic::new(
            left,
            right,
            CollisionCondition::Exact,
        ));
    }
    if to_full_lowercase(left.as_str()) == to_full_lowercase(right.as_str()) {
        return Some(CollisionDiagnostic::new(
            left,
            right,
            CollisionCondition::Case,
        ));
    }
    if truncation_collision(left.as_str(), right.as_str(), namespace.max_scalars()) {
        return Some(CollisionDiagnostic::new(
            left,
            right,
            CollisionCondition::Truncation,
        ));
    }
    if normalize_nfc(left.as_str()) == normalize_nfc(right.as_str()) {
        return Some(CollisionDiagnostic::new(
            left,
            right,
            CollisionCondition::Normalization,
        ));
    }
    if namespace.is_reserved_word(left.as_str()) || namespace.is_reserved_word(right.as_str()) {
        return Some(CollisionDiagnostic::new(
            left,
            right,
            CollisionCondition::ReservedWord,
        ));
    }
    if confusable_skeleton(left.as_str()) == confusable_skeleton(right.as_str()) {
        return Some(CollisionDiagnostic::new(
            left,
            right,
            CollisionCondition::Confusable,
        ));
    }
    None
}

/// Returns whether two spellings collide by truncation at one declared maximum.
fn truncation_collision(left: &str, right: &str, max_scalars: usize) -> bool {
    let beyond = left.chars().count() > max_scalars || right.chars().count() > max_scalars;
    beyond && prefix_scalars(left, max_scalars) == prefix_scalars(right, max_scalars)
}

/// Returns the leading scalars of one spelling up to one maximum.
fn prefix_scalars(value: &str, max_scalars: usize) -> String {
    value.chars().take(max_scalars).collect()
}

/// One lookup namespace: the declared maximum length and the closed published
/// reserved-word set of the selected edition.
///
/// Reserved words are consumed exactly as `GNT-13.2` publishes them and are never
/// redefined or extended per domain; a name equal to a reserved word is never
/// usable here, because reserved-word precedence is lexical and applies before any
/// declared name resolves.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LookupNamespace {
    max_scalars: usize,
    reserved_words: BTreeSet<Arc<str>>,
}

impl LookupNamespace {
    /// Constructs one empty namespace with one declared maximum length.
    pub fn new(max_scalars: usize) -> Result<Self, IdentifierError> {
        if max_scalars == 0 {
            return Err(IdentifierError::InvalidNamespaceMaximum {
                maximum: max_scalars,
            });
        }
        Ok(Self {
            max_scalars,
            reserved_words: BTreeSet::new(),
        })
    }

    /// Inserts one reserved word of the selected edition.
    #[must_use]
    pub fn with_reserved_word(mut self, word: &str) -> Self {
        self.reserved_words.insert(Arc::from(word));
        self
    }

    /// Returns the declared maximum length of this namespace, in scalars.
    #[must_use]
    pub const fn max_scalars(&self) -> usize {
        self.max_scalars
    }

    /// Returns the reserved words in canonical order.
    pub fn reserved_words(&self) -> impl Iterator<Item = &str> {
        self.reserved_words.iter().map(AsRef::as_ref)
    }

    /// Returns whether one spelling is a reserved word of the selected edition.
    #[must_use]
    pub fn is_reserved_word(&self, value: &str) -> bool {
        self.reserved_words.contains(value)
    }

    /// Returns whether one admitted name may occupy this namespace.
    ///
    /// Admission is first, lexical reserved-word precedence is second, and the
    /// declared maximum length is last: a name equal to a reserved word is refused
    /// here, and a name beyond the declared maximum fails naming the domain, the
    /// declared maximum, and the offending name instead of being truncated.
    pub fn admit(
        &self,
        domain: SymbolicDomain,
        spelling: &NameSpelling,
    ) -> Result<DeclaredName, IdentifierError> {
        let name = DeclaredName::new(spelling.as_str())?;
        if self.is_reserved_word(name.as_str()) {
            return Err(IdentifierError::ReservedWordUnusable {
                domain,
                name: Arc::from(name.as_str()),
            });
        }
        if name.as_str().chars().count() > self.max_scalars {
            return Err(IdentifierError::NameExceedsMaximum {
                domain,
                maximum: self.max_scalars,
                name: Arc::from(name.as_str()),
            });
        }
        Ok(name)
    }

    /// Resolves one declared spelling to its canonical name in this namespace.
    pub fn canonical_name(
        &self,
        domain: SymbolicDomain,
        spelling: &NameSpelling,
    ) -> Result<CanonicalSymbolicIdentity, IdentifierError> {
        let name = self.admit(domain, spelling)?;
        CanonicalSymbolicIdentity::of_declared(domain, &name)
    }

    /// Decides the relation of `GNT-18.6-collision-relation` for two declared names.
    #[must_use]
    pub fn collision(
        &self,
        left: &DeclaredName,
        right: &DeclaredName,
    ) -> Option<CollisionDiagnostic> {
        collision_condition(&left.spelling(), &right.spelling(), self)
    }
}

/// One name owned by a registry, a publisher, a provider, an external package, or
/// an imported tool (`GNT-18.9-external-name-mapping`).
///
/// An external name is admitted as a declared name and never as source syntax, and
/// no normalization, case folding, transliteration, or visual resemblance turns it
/// into source syntax.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ExternalName {
    domain: SymbolicDomain,
    spelling: Arc<str>,
}

impl ExternalName {
    /// Admits one external name of one domain, or fails before use.
    pub fn new(domain: SymbolicDomain, value: &str) -> Result<Self, IdentifierError> {
        DeclaredName::new(value)?;
        Ok(Self {
            domain,
            spelling: Arc::from(value),
        })
    }

    /// Returns the domain of this external name.
    #[must_use]
    pub const fn domain(&self) -> SymbolicDomain {
        self.domain
    }

    /// Returns the exact external spelling.
    #[must_use]
    pub fn spelling(&self) -> &str {
        &self.spelling
    }

    /// Maps this external name to exactly one canonical typed identity, or fails.
    pub fn identity(&self) -> Result<CanonicalSymbolicIdentity, IdentifierError> {
        CanonicalSymbolicIdentity::of_external(self)
    }
}

/// The injective external-name-to-identity mapping of
/// `GNT-18.9-external-name-mapping`.
///
/// Every external name maps injectively to exactly one canonical typed identity,
/// or it fails before use. The mapping derives from the external name alone and
/// never from discovery order, response order, or a display string, so the same
/// set of names produces the same canonical bytes and the same digest under every
/// insertion order.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ExternalNameMap {
    by_name: BTreeMap<(SymbolicDomain, Arc<str>), CanonicalSymbolicIdentity>,
    by_identity: BTreeMap<CanonicalSymbolicIdentity, (SymbolicDomain, Arc<str>)>,
}

impl ExternalNameMap {
    /// Constructs one empty mapping.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts one external name, or reports the mapping non-injective.
    ///
    /// The identity of an external name is a pure function of its domain and its
    /// admitted spelling, so two distinct external names must map to two distinct
    /// identities. A registration that would map two distinct external names to
    /// one identity is refused rather than resolved by preferring one of them.
    pub fn insert(&mut self, name: ExternalName) -> Result<(), IdentifierError> {
        let identity = CanonicalSymbolicIdentity::of_external(&name)?;
        let key = (name.domain, name.spelling.clone());
        if let Some((existing_domain, existing_name)) = self.by_identity.get(&identity)
            && (*existing_domain, existing_name.clone()) != key
        {
            return Err(IdentifierError::NonInjectiveMapping {
                domain: name.domain,
                name: name.spelling,
            });
        }
        self.by_name.insert(key.clone(), identity.clone());
        self.by_identity.insert(identity, key);
        Ok(())
    }

    /// Returns the identity one external name maps to.
    #[must_use]
    pub fn identity(&self, name: &ExternalName) -> Option<&CanonicalSymbolicIdentity> {
        self.by_name.get(&(name.domain, name.spelling.clone()))
    }

    /// Returns the external name one identity is mapped from.
    #[must_use]
    pub fn external_name(
        &self,
        identity: &CanonicalSymbolicIdentity,
    ) -> Option<(SymbolicDomain, &str)> {
        self.by_identity
            .get(identity)
            .map(|(domain, name)| (*domain, name.as_ref()))
    }

    /// Returns the entries in canonical (domain, spelling) order.
    pub fn entries(
        &self,
    ) -> impl Iterator<Item = (SymbolicDomain, &str, &CanonicalSymbolicIdentity)> {
        self.by_name
            .iter()
            .map(|((domain, name), identity)| (*domain, name.as_ref(), identity))
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

    /// Returns the one canonical encoding of this mapping.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut output = String::from("{\"external_names\":[");
        for (index, ((domain, name), identity)) in self.by_name.iter().enumerate() {
            if index > 0 {
                output.push(',');
            }
            output.push_str("{\"domain\":");
            push_json_string(&mut output, domain.wire_name());
            output.push_str(",\"identity_digest\":");
            push_json_string(&mut output, identity.digest_hex());
            output.push_str(",\"name\":");
            push_json_string(&mut output, name);
            output.push('}');
        }
        output.push(']');
        output.push('}');
        output.into_bytes()
    }
}

/// One generated source spelling produced for a declared name
/// (`GNT-18.10-generated-alias-derivation`).
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GeneratedAlias(Arc<str>);

impl GeneratedAlias {
    /// Returns the exact generated spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Derives one generated alias with the one deterministic escaping and
/// disambiguation algorithm of `GNT-18.10-generated-alias-derivation`.
///
/// Escaping: the alias begins with the closed [`SymbolicDomain::alias_prefix`] of
/// its domain, then escapes every scalar of the canonical name that is not an ASCII
/// letter or digit as `_u` + its uppercase hexadecimal code point + `_`. A literal
/// `_` is escaped too, so the escape is unambiguous, the result is ASCII, the alias
/// always starts with a letter, and the alias is a legal source spelling of its
/// domain. Because the domain prefix is part of the alias, one spelling written in
/// two domains derives two aliases, and one alias is never derived for two
/// identities.
///
/// Disambiguation: when the escaped form is occupied — it is a reserved word of
/// the namespace, it is not admitted, or it exceeds the declared maximum — the
/// algorithm appends `_` and the leading hexadecimal digits of the canonical
/// identity digest, extending that prefix until the name is free. The suffix comes
/// from the identity of the name, never from a counter, an enumeration, a
/// discovery order, a graph order, a host path, the clock, the locale, or an
/// ambient environment fact, so the same name yields the same alias in every run
/// and under every input order. When no escaped and disambiguated spelling fits the
/// declared maximum of the namespace, the derivation fails naming the domain and
/// the name rather than truncating the alias, because `GNT-18.8-truncation-behaviour`
/// admits no silent truncation.
pub fn generated_alias(
    domain: SymbolicDomain,
    name: &DeclaredName,
    namespace: &LookupNamespace,
) -> Result<GeneratedAlias, IdentifierError> {
    let identity = CanonicalSymbolicIdentity::of_declared(domain, name)?;
    let escaped = format!(
        "{}_{}",
        domain.alias_prefix(),
        escape_spelling(name.as_str())
    );
    if !occupied(namespace, &escaped) {
        return Ok(GeneratedAlias(Arc::from(escaped)));
    }
    let digest = identity.digest_hex().to_owned();
    let mut suffix_length = 4;
    loop {
        let candidate = format!("{escaped}_{}", &digest[..suffix_length]);
        if !occupied(namespace, &candidate) {
            return Ok(GeneratedAlias(Arc::from(candidate)));
        }
        if suffix_length >= digest.len() {
            return Err(IdentifierError::AliasDerivationFailed {
                domain,
                name: Arc::from(name.as_str()),
            });
        }
        suffix_length += 4;
    }
}

/// Escapes one admitted spelling for a generated alias.
fn escape_spelling(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for scalar in value.chars() {
        if scalar.is_ascii_alphanumeric() {
            output.push(scalar);
        } else {
            output.push('_');
            output.push('u');
            output.push_str(&format!("{:04X}", scalar as u32));
            output.push('_');
        }
    }
    output
}

/// Returns whether one generated spelling is occupied in one namespace.
fn occupied(namespace: &LookupNamespace, value: &str) -> bool {
    if namespace.is_reserved_word(value) || value.chars().count() > namespace.max_scalars() {
        return true;
    }
    match NameSpelling::new(value) {
        Ok(spelling) => !spelling.is_admitted(),
        Err(_) => true,
    }
}

/// One deterministic machine-readable generated-alias-to-identity map
/// (`GNT-18.10-generated-alias-derivation`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AliasMap {
    entries: BTreeMap<GeneratedAlias, CanonicalSymbolicIdentity>,
    by_identity: BTreeMap<CanonicalSymbolicIdentity, GeneratedAlias>,
    canonical: Arc<[u8]>,
    digest: SymbolicIdentityDigest,
}

impl AliasMap {
    /// Derives one alias map for one unordered set of declared names.
    ///
    /// The inputs are ordered by domain and canonical spelling before derivation,
    /// so the same set of names produces the same aliases, the same canonical
    /// bytes, and the same digest under every input order.
    pub fn derive(
        names: &[(SymbolicDomain, DeclaredName)],
        namespace: &LookupNamespace,
    ) -> Result<Self, IdentifierError> {
        let mut ordered = names.to_vec();
        ordered.sort_by(|left, right| {
            left.0
                .wire_name()
                .cmp(right.0.wire_name())
                .then_with(|| left.1.as_str().cmp(right.1.as_str()))
        });
        let mut entries = BTreeMap::new();
        let mut by_identity = BTreeMap::new();
        for (domain, name) in &ordered {
            let identity = CanonicalSymbolicIdentity::of_declared(*domain, name)?;
            let alias = generated_alias(*domain, name, namespace)?;
            if entries.insert(alias.clone(), identity.clone()).is_some() {
                return Err(IdentifierError::AliasDerivationFailed {
                    domain: *domain,
                    name: Arc::from(name.as_str()),
                });
            }
            by_identity.insert(identity, alias);
        }
        let canonical = encode_alias_map(&entries);
        let digest =
            SymbolicIdentityDigest::from_digest(digest_fields(ALIAS_MAP_DOMAIN, &[&canonical]));
        Ok(Self {
            entries,
            by_identity,
            canonical: Arc::from(canonical.as_slice()),
            digest,
        })
    }

    /// Returns the entries in canonical alias order.
    pub fn entries(&self) -> impl Iterator<Item = (&GeneratedAlias, &CanonicalSymbolicIdentity)> {
        self.entries.iter()
    }

    /// Returns the identity one generated alias denotes.
    #[must_use]
    pub fn identity_of(&self, alias: &GeneratedAlias) -> Option<&CanonicalSymbolicIdentity> {
        self.entries.get(alias)
    }

    /// Returns the generated alias of one canonical identity.
    #[must_use]
    pub fn alias_of(&self, identity: &CanonicalSymbolicIdentity) -> Option<&GeneratedAlias> {
        self.by_identity.get(identity)
    }

    /// Returns the number of mapped aliases.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether the map is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the one canonical encoding.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }

    /// Returns the typed alias-map digest.
    #[must_use]
    pub const fn digest(&self) -> &SymbolicIdentityDigest {
        &self.digest
    }

    /// Returns the lowercase hexadecimal alias-map digest.
    #[must_use]
    pub fn digest_hex(&self) -> &str {
        self.digest.as_str()
    }
}

/// Encodes one alias map over its entries in canonical alias order.
fn encode_alias_map(entries: &BTreeMap<GeneratedAlias, CanonicalSymbolicIdentity>) -> Vec<u8> {
    let mut output = String::from("{\"aliases\":[");
    for (index, (alias, identity)) in entries.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        output.push_str("{\"alias\":");
        push_json_string(&mut output, alias.as_str());
        output.push_str(",\"domain\":");
        push_json_string(&mut output, identity.domain().wire_name());
        output.push_str(",\"identity_digest\":");
        push_json_string(&mut output, identity.digest_hex());
        output.push('}');
    }
    output.push_str("],\"identity_version\":");
    output.push_str(&IdentityVersion::PINNED.value().to_string());
    output.push('}');
    output.into_bytes()
}

/// One bounded presentation label derived from one canonical symbolic identity
/// (`GNT-18.11-hostile-label-rendering`).
///
/// A label is presentation only. It implements no equality, ordering, or hashing,
/// so it cannot become a lookup, authorization, policy, approval, transcript,
/// audit, or durable-recovery key: `GNT-18.12-typed-identity-authority` requires
/// [`IdentityKey`] for every such decision, and the canonical identity is always
/// available beside the label. Two labels are equal only by their rendered bytes,
/// which [`Self::rendered_bytes_equal`] reports explicitly.
#[derive(Clone, Debug)]
pub struct DisplayLabel {
    identity: CanonicalSymbolicIdentity,
    rendered: Arc<str>,
}

impl DisplayLabel {
    /// Renders the bounded standard label of one canonical identity.
    pub fn new(identity: CanonicalSymbolicIdentity) -> Result<Self, IdentifierError> {
        Self::bounded(identity, DISPLAY_LABEL_MAX_SCALARS)
    }

    /// Renders one bounded label of at most `max_scalars` rendered scalars.
    pub fn bounded(
        identity: CanonicalSymbolicIdentity,
        max_scalars: usize,
    ) -> Result<Self, IdentifierError> {
        let rendered = Self::escape(identity.canonical_name());
        if rendered.chars().count() > max_scalars {
            return Err(IdentifierError::LabelExceedsBound {
                maximum: max_scalars,
                name: Arc::from(identity.canonical_name()),
            });
        }
        Ok(Self {
            identity,
            rendered: Arc::from(rendered),
        })
    }

    /// Returns the rendered bytes of the label.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.rendered
    }

    /// Returns the canonical symbolic identity the label was derived from.
    #[must_use]
    pub const fn identity(&self) -> &CanonicalSymbolicIdentity {
        &self.identity
    }

    /// Returns whether two labels render the same bytes.
    #[must_use]
    pub fn rendered_bytes_equal(&self, other: &Self) -> bool {
        self.rendered == other.rendered
    }

    /// Renders one name with code-point escapes, in code-point order.
    ///
    /// Every control scalar and every scalar the identifier-security rules exclude
    /// is written as `\u{XXXX}` with at least four uppercase hexadecimal digits. No
    /// scalar is reordered, no bidi reordering is applied, and no font-dependent
    /// equality exists here, so an embedded sequence can never retarget a label.
    #[must_use]
    pub fn escape(value: &str) -> String {
        let mut output = String::with_capacity(value.len());
        for scalar in value.chars() {
            if is_excluded_scalar(scalar) {
                output.push_str(&format!("\\u{{{:04X}}}", scalar as u32));
            } else {
                output.push(scalar);
            }
        }
        output
    }
}

/// The typed identity every lookup, authorization, policy, approval, transcript,
/// audit, and durable-recovery decision uses
/// (`GNT-18.12-typed-identity-authority`).
///
/// Copying, retyping, or re-rendering an identifier or a label copies a name and
/// never copies authority, and the only way to build this key is from the canonical
/// typed identity of its domain: no display string, host path, or spelled name
/// constructs one.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct IdentityKey(CanonicalSymbolicIdentity);

impl IdentityKey {
    /// Wraps one canonical symbolic identity as the key of one decision.
    #[must_use]
    pub fn of(identity: &CanonicalSymbolicIdentity) -> Self {
        Self(identity.clone())
    }

    /// Returns the canonical symbolic identity of this key.
    #[must_use]
    pub const fn identity(&self) -> &CanonicalSymbolicIdentity {
        &self.0
    }
}

/// One rejected or reported condition of the identifier-security model.
///
/// Every variant exposes the frozen published diagnostic code it is reported under
/// through [`Self::code`] and the clause that owns it through
/// [`Self::requirement`]. A condition with no published code reports `None` and is
/// never reported under another condition's code.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IdentifierError {
    /// The spelling was empty.
    EmptySpelling,
    /// The spelling exceeded [`SPELLING_LIMIT_BYTES`].
    TooLong {
        /// The largest accepted spelling, in bytes.
        maximum: usize,
        /// The rejected spelling.
        spelling: Arc<str>,
    },
    /// The spelling carried a control or identifier-security-excluded scalar.
    ExcludedScalar {
        /// The rejected scalar.
        scalar: char,
    },
    /// The spelling was not already in the pinned NFC.
    NotNfc {
        /// The rejected spelling.
        spelling: Arc<str>,
    },
    /// The first scalar was neither `_` nor `XID_Start`.
    NotXidStart {
        /// The rejected scalar.
        scalar: char,
    },
    /// One scalar was not `XID_Continue`.
    NotXidContinue {
        /// The rejected scalar.
        scalar: char,
    },
    /// The domain spelling was outside the closed domain list.
    UnknownDomain {
        /// The rejected spelling.
        spelling: Arc<str>,
    },
    /// The collision-condition spelling was outside the closed vocabulary.
    UnknownCollisionCondition {
        /// The rejected spelling.
        spelling: Arc<str>,
    },
    /// The identity version is not the supported one.
    UnsupportedIdentityVersion {
        /// The unsupported version.
        version: u32,
    },
    /// The identity record carried a property this version does not define.
    UnknownIdentityProperty {
        /// The unknown property name.
        property: Arc<str>,
    },
    /// The identity record omitted a required property.
    MissingIdentityProperty {
        /// The missing property name.
        property: &'static str,
    },
    /// The identity record declared one property twice.
    DuplicateIdentityProperty {
        /// The duplicated property name.
        property: Arc<str>,
    },
    /// One recorded property value was malformed.
    MalformedIdentityProperty {
        /// The malformed property name.
        property: &'static str,
        /// The rejected value.
        value: Arc<str>,
    },
    /// A digest is not 64 lowercase hexadecimal digits.
    InvalidDigest {
        /// The rejected digest text.
        value: Arc<str>,
    },
    /// The spelling is not admitted to the source identifier domain.
    DomainNotSourceAdmissible {
        /// The domain whose spellings may not enter source.
        domain: SymbolicDomain,
    },
    /// A name equal to a reserved word is never usable in a lookup namespace.
    ReservedWordUnusable {
        /// The domain the name was declared in.
        domain: SymbolicDomain,
        /// The rejected name.
        name: Arc<str>,
    },
    /// A name exceeded the declared maximum length of its namespace.
    NameExceedsMaximum {
        /// The domain the name was declared in.
        domain: SymbolicDomain,
        /// The declared maximum length, in scalars.
        maximum: usize,
        /// The offending name.
        name: Arc<str>,
    },
    /// The declared maximum length of one namespace is not positive.
    InvalidNamespaceMaximum {
        /// The rejected declared maximum.
        maximum: usize,
    },
    /// Two spellings collide under the collision relation.
    Collision {
        /// One spelling of the colliding pair, in canonical order.
        first: Arc<str>,
        /// The other spelling of the colliding pair, never smaller than `first`.
        second: Arc<str>,
        /// The collision condition.
        condition: CollisionCondition,
    },
    /// A name is outside the Recommended single-script set.
    ScriptOutsideRecommended {
        /// The offending name.
        name: Arc<str>,
        /// The scripts the name carries, in deterministic order.
        scripts: Vec<Script>,
    },
    /// An external name was registered twice with different identities.
    ExternalNameDuplicate {
        /// The domain of the duplicated registration.
        domain: SymbolicDomain,
        /// The duplicated external name.
        name: Arc<str>,
    },
    /// Two distinct external names would map to one canonical identity.
    NonInjectiveMapping {
        /// The domain of the refused registration.
        domain: SymbolicDomain,
        /// The refused external name.
        name: Arc<str>,
    },
    /// No deterministic generated alias could be derived for one name.
    AliasDerivationFailed {
        /// The domain of the name.
        domain: SymbolicDomain,
        /// The offending name.
        name: Arc<str>,
    },
    /// One rendered label exceeded its bound.
    LabelExceedsBound {
        /// The declared maximum, in rendered scalars.
        maximum: usize,
        /// The name whose label exceeded the bound.
        name: Arc<str>,
    },
}

impl IdentifierError {
    /// Returns the frozen published diagnostic identity of this condition.
    ///
    /// `None` means the condition has no published code and MUST NOT be reported
    /// under another condition's code.
    #[must_use]
    pub const fn code(&self) -> Option<IdentifierDiagnosticCode> {
        match self {
            Self::ExcludedScalar { .. } => Some(IdentifierDiagnosticCode::IdentifierSecurity),
            Self::NotNfc { .. } => Some(IdentifierDiagnosticCode::NotNfc),
            Self::Collision { condition, .. } => condition.code(),
            Self::ScriptOutsideRecommended { .. } => Some(IdentifierDiagnosticCode::ScriptWarning),
            Self::EmptySpelling
            | Self::TooLong { .. }
            | Self::NotXidStart { .. }
            | Self::NotXidContinue { .. }
            | Self::UnknownDomain { .. }
            | Self::UnknownCollisionCondition { .. }
            | Self::UnsupportedIdentityVersion { .. }
            | Self::UnknownIdentityProperty { .. }
            | Self::MissingIdentityProperty { .. }
            | Self::DuplicateIdentityProperty { .. }
            | Self::MalformedIdentityProperty { .. }
            | Self::InvalidDigest { .. }
            | Self::DomainNotSourceAdmissible { .. }
            | Self::ReservedWordUnusable { .. }
            | Self::NameExceedsMaximum { .. }
            | Self::InvalidNamespaceMaximum { .. }
            | Self::ExternalNameDuplicate { .. }
            | Self::NonInjectiveMapping { .. }
            | Self::AliasDerivationFailed { .. }
            | Self::LabelExceedsBound { .. } => None,
        }
    }

    /// Returns the clause that owns this condition.
    #[must_use]
    pub const fn requirement(&self) -> &'static str {
        match self {
            Self::EmptySpelling
            | Self::TooLong { .. }
            | Self::ExcludedScalar { .. }
            | Self::NotNfc { .. }
            | Self::NotXidStart { .. }
            | Self::NotXidContinue { .. }
            | Self::DomainNotSourceAdmissible { .. } => "GNT-18.3-source-spelling-admission",
            Self::UnknownDomain { .. } => "GNT-18.1-symbolic-identity-domains",
            Self::UnknownCollisionCondition { .. }
            | Self::Collision { .. }
            | Self::InvalidNamespaceMaximum { .. } => "GNT-18.6-collision-relation",
            Self::UnsupportedIdentityVersion { .. }
            | Self::UnknownIdentityProperty { .. }
            | Self::MissingIdentityProperty { .. }
            | Self::DuplicateIdentityProperty { .. }
            | Self::MalformedIdentityProperty { .. }
            | Self::InvalidDigest { .. } => "GNT-18.2-canonical-symbolic-identity",
            Self::ScriptOutsideRecommended { .. } => "GNT-18.4-confusable-and-script-policy",
            Self::ReservedWordUnusable { .. } => "GNT-18.5-reserved-word-occupancy",
            Self::NameExceedsMaximum { .. } => "GNT-18.8-truncation-behaviour",
            Self::ExternalNameDuplicate { .. } | Self::NonInjectiveMapping { .. } => {
                "GNT-18.9-external-name-mapping"
            }
            Self::AliasDerivationFailed { .. } => "GNT-18.10-generated-alias-derivation",
            Self::LabelExceedsBound { .. } => "GNT-18.11-hostile-label-rendering",
        }
    }
}

impl fmt::Display for IdentifierError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptySpelling => formatter.write_str("identifier spelling is empty"),
            Self::TooLong { maximum, spelling } => write!(
                formatter,
                "identifier spelling `{spelling}` exceeds {maximum} bytes"
            ),
            Self::ExcludedScalar { scalar } => write!(
                formatter,
                "identifier contains the excluded scalar U+{:04X}",
                *scalar as u32
            ),
            Self::NotNfc { spelling } => {
                write!(formatter, "identifier spelling `{spelling}` is not NFC")
            }
            Self::NotXidStart { scalar } => write!(
                formatter,
                "identifier starts with U+{:04X}, which is not XID_Start",
                *scalar as u32
            ),
            Self::NotXidContinue { scalar } => write!(
                formatter,
                "identifier contains U+{:04X}, which is not XID_Continue",
                *scalar as u32
            ),
            Self::UnknownDomain { spelling } => {
                write!(formatter, "`{spelling}` is not a symbolic domain")
            }
            Self::UnknownCollisionCondition { spelling } => {
                write!(formatter, "`{spelling}` is not a collision condition")
            }
            Self::UnsupportedIdentityVersion { version } => {
                write!(formatter, "identity version {version} is not supported")
            }
            Self::UnknownIdentityProperty { property } => {
                write!(
                    formatter,
                    "identity record property `{property}` is unknown"
                )
            }
            Self::MissingIdentityProperty { property } => {
                write!(
                    formatter,
                    "identity record property `{property}` is missing"
                )
            }
            Self::DuplicateIdentityProperty { property } => {
                write!(
                    formatter,
                    "identity record property `{property}` is declared twice"
                )
            }
            Self::MalformedIdentityProperty { property, value } => {
                write!(
                    formatter,
                    "identity record property `{property}` is malformed: `{value}`"
                )
            }
            Self::InvalidDigest { value } => {
                write!(
                    formatter,
                    "`{value}` is not a lowercase hexadecimal SHA-256 digest"
                )
            }
            Self::DomainNotSourceAdmissible { domain } => write!(
                formatter,
                "the {} domain must not enter the source identifier domain",
                domain.wire_name()
            ),
            Self::ReservedWordUnusable { domain, name } => write!(
                formatter,
                "`{name}` is a reserved word and is not usable in the {} domain",
                domain.wire_name()
            ),
            Self::NameExceedsMaximum {
                domain,
                maximum,
                name,
            } => write!(
                formatter,
                "`{name}` exceeds the declared maximum of {maximum} scalars in the {} domain",
                domain.wire_name()
            ),
            Self::InvalidNamespaceMaximum { maximum } => {
                write!(
                    formatter,
                    "a declared maximum of {maximum} scalars is not positive"
                )
            }
            Self::Collision {
                first,
                second,
                condition,
            } => write!(
                formatter,
                "`{first}` collides with `{second}` under the {} condition",
                condition.wire_name()
            ),
            Self::ScriptOutsideRecommended { name, scripts } => write!(
                formatter,
                "`{name}` is outside one Recommended single-script set: {}",
                scripts
                    .iter()
                    .map(|value| value.short_name())
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            Self::ExternalNameDuplicate { domain, name } => write!(
                formatter,
                "external name `{name}` of the {} domain is registered twice",
                domain.wire_name()
            ),
            Self::NonInjectiveMapping { domain, name } => write!(
                formatter,
                "external name `{name}` of the {} domain does not map injectively",
                domain.wire_name()
            ),
            Self::AliasDerivationFailed { domain, name } => write!(
                formatter,
                "no generated alias is free for `{name}` in the {} domain",
                domain.wire_name()
            ),
            Self::LabelExceedsBound { maximum, name } => write!(
                formatter,
                "the label of `{name}` exceeds {maximum} rendered scalars"
            ),
        }
    }
}

impl std::error::Error for IdentifierError {}

/// Encodes the one canonical byte encoding of one identity input.
fn encode_identity(domain: SymbolicDomain, version: IdentityVersion, name: &str) -> String {
    let mut output = String::from("{\"canonical_name\":");
    push_json_string(&mut output, name);
    output.push_str(",\"domain\":");
    push_json_string(&mut output, domain.wire_name());
    output.push_str(",\"identity_version\":");
    output.push_str(&version.value().to_string());
    output.push('}');
    output
}

/// Appends one JSON string.
fn push_json_string(output: &mut String, value: &str) {
    output.push('"');
    for scalar in value.chars() {
        match scalar {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{08}' => output.push_str("\\b"),
            '\u{0c}' => output.push_str("\\f"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            scalar if scalar <= '\u{1f}' => {
                output.push_str(&format!("\\u{:04x}", scalar as u32));
            }
            scalar => output.push(scalar),
        }
    }
    output.push('"');
}

#[cfg(test)]
mod tests {
    use super::{
        CanonicalSymbolicIdentity, CollisionCondition, DEFAULT_NAMESPACE_MAX_SCALARS, DeclaredName,
        IdentifierError, LookupNamespace, NameSpelling, ScriptClassification, SourceSpelling,
        SymbolicDomain, collision_condition, generated_alias,
    };

    fn declared(value: &str) -> DeclaredName {
        DeclaredName::new(value).unwrap_or_else(|_| unreachable!("fixture name is admitted"))
    }

    fn namespace() -> LookupNamespace {
        LookupNamespace::new(4).unwrap_or_else(|_| unreachable!("positive declared maximum"))
    }

    #[test]
    fn canonical_encoding_is_explicit_and_stable() {
        let identity = CanonicalSymbolicIdentity::of_declared(
            SymbolicDomain::SourceIdentifier,
            &declared("paypal"),
        )
        .unwrap_or_else(|_| unreachable!("fixture name is admitted"));
        assert_eq!(
            std::str::from_utf8(identity.canonical_bytes())
                .unwrap_or_else(|_| unreachable!("canonical bytes are JSON text")),
            "{\"canonical_name\":\"paypal\",\"domain\":\"source-identifier\",\"identity_version\":1}"
        );
        assert_eq!(identity.digest_hex().len(), 64);
        assert_eq!(
            identity.as_str(),
            format!("source-identifier:{}", identity.digest_hex())
        );
        assert_eq!(
            CanonicalSymbolicIdentity::of_source(
                SymbolicDomain::SourceIdentifier,
                &SourceSpelling::new("paypal").unwrap_or_else(|_| unreachable!("admitted"))
            )
            .unwrap_or_else(|_| unreachable!("source spelling is admitted")),
            identity
        );
    }

    #[test]
    fn the_collision_relation_is_symmetric_over_a_spelling_lane() {
        let namespace = namespace().with_reserved_word("if");
        let lane = [
            "paypal",
            "Paypal",
            "paypa\u{0131}",
            "\u{0440}aypal",
            "if",
            "abcdef",
            "abcd",
            "e\u{0301}",
            "\u{00e9}",
        ];
        let spellings = lane
            .iter()
            .map(|value| {
                NameSpelling::new(value)
                    .unwrap_or_else(|_| unreachable!("lane spelling is bounded"))
            })
            .collect::<Vec<_>>();
        for left in &spellings {
            for right in &spellings {
                assert_eq!(
                    collision_condition(left, right, &namespace),
                    collision_condition(right, left, &namespace)
                );
                if let Some(diagnostic) = collision_condition(left, right, &namespace) {
                    assert!(diagnostic.is_canonical_order());
                }
            }
        }
        assert_eq!(
            collision_condition(&spellings[7], &spellings[8], &namespace)
                .map(|diagnostic| diagnostic.condition()),
            Some(CollisionCondition::Normalization)
        );
    }

    #[test]
    fn generated_aliases_escape_and_disambiguate_deterministically() {
        let wide = LookupNamespace::new(DEFAULT_NAMESPACE_MAX_SCALARS)
            .unwrap_or_else(|_| unreachable!("positive declared maximum"));
        let escaped = generated_alias(SymbolicDomain::ToolName, &declared("caf\u{00e9}_1"), &wide)
            .unwrap_or_else(|_| unreachable!("a free alias exists"));
        assert_eq!(escaped.as_str(), "tool_caf_u00E9__u005F_1");
        let reserved = generated_alias(SymbolicDomain::ToolName, &declared("if"), &wide)
            .unwrap_or_else(|_| unreachable!("a free alias exists"));
        assert_eq!(reserved.as_str(), "tool_if");
        let disambiguated = generated_alias(
            SymbolicDomain::ToolName,
            &declared("if"),
            &wide.clone().with_reserved_word("tool_if"),
        )
        .unwrap_or_else(|_| unreachable!("a free alias exists"));
        assert!(disambiguated.as_str().starts_with("tool_if_"));
        // A declared maximum no escaped alias can meet fails rather than truncating.
        assert!(matches!(
            generated_alias(
                SymbolicDomain::ToolName,
                &declared("caf\u{00e9}_1"),
                &namespace()
            ),
            Err(IdentifierError::AliasDerivationFailed { .. })
        ));
        assert_eq!(wide.max_scalars(), DEFAULT_NAMESPACE_MAX_SCALARS);
    }

    #[test]
    fn script_classification_reports_mixed_scripts_once() {
        assert!(ScriptClassification::of("paypal").is_recommended());
        assert!(!ScriptClassification::of("payp\u{0430}l").is_recommended());
    }
}
