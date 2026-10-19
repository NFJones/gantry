//! Declaration-layer policy model for application-native directory handles of SPEC.md Section 52.
//!
//! The module publishes the closed requirement, mapping, fact-binding, issuance, revocation,
//! settlement, child-projection, and durability policy that Section 52 declares. It is a pure
//! deterministic model: it materializes no native handle, opens no directory, performs no host
//! I/O, reads no ambient process state, and grants no directory authority. Every decision is a
//! function of explicit inputs, and every refusal names exactly one published condition.
//!
//! The model consumes rather than restates the landed contracts it binds: the typed capability
//! requirement identity, rights set, authority generation, and live fence of the authority
//! contract, the resource-generation identity of the operation contract, the logical execution
//! identity of the approval contract, the task-body identity of the executable contract, and the
//! declared application-only semantic mode.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use gantry_core::mode::SemanticMode;

use crate::approval::LogicalExecutionId;
use crate::authority::{
    AuthorityFence, AuthorityGeneration, AuthorityRequirementId, FenceState, RightsSet,
};
use crate::executable::TaskBodyIdentity;
use crate::operation::{OwnerGeneration, ResourceGenerationId};

/// The Section 52 clauses this model implements, in specification order.
pub const NATIVE_DIRECTORY_CLAUSES: [&str; 10] = [
    "GNT-52.0-native-directory-foundation-scope",
    "GNT-52.1-native-directory-requirement-and-mapping-policy",
    "GNT-52.2-native-directory-path-and-fact-binding",
    "GNT-52.3-native-directory-exclusive-issuance-and-ownership",
    "GNT-52.4-native-directory-revocation-fencing",
    "GNT-52.5-native-directory-completion-and-late-response",
    "GNT-52.6-native-directory-durable-exclusion",
    "GNT-52.7-native-directory-child-projection",
    "GNT-52.8-native-directory-refusal-vocabulary",
    "GNT-52.9-native-directory-non-claims",
];

/// The closed refusal set of the native-directory model.
///
/// Every variant names one condition of Section 52 and exactly one owning clause declares it.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum NativeDirectoryDiagnosticCode {
    /// A child projection requested a right the parent does not hold.
    Amplification,
    /// A second live handle was requested for one attached slot.
    DuplicateIssuance,
    /// The declared rights set is empty.
    EmptyRights,
    /// Presented subject facts belong to another subject.
    ForeignSubject,
    /// A child relative text is absolute, empty, escaping, or malformed.
    InvalidChildPath,
    /// A native path text is empty, relative, or carries a refused scalar.
    InvalidPath,
    /// A declared slot identity is empty or carries a refused scalar.
    InvalidSlotIdentity,
    /// A completion was presented after the subject settled.
    LateCompletion,
    /// A native handle can never resurrect from durable state.
    NeverResurrects,
    /// No live issuance exists for the presented slot.
    NotLive,
    /// A handle path differs from the declared path of its attached slot.
    PathBindingRefused,
    /// A path or digest presentation carries no authority.
    PathGrantsNoAuthority,
    /// The presented requirement identity is not the held one.
    RequirementMismatch,
    /// The authority generation is fenced by revocation.
    Revoked,
    /// A reissued slot names an owner generation that does not succeed the settled one.
    StaleGeneration,
    /// The target and case combination is not a declared mapping.
    UndeclaredMapping,
    /// The declared semantic mode is not the application mode.
    UnsupportedMode,
    /// The declared mapping cannot preserve a presented name or relative text.
    UnsupportedRepresentation,
}

impl NativeDirectoryDiagnosticCode {
    /// Every declared code, in canonical order.
    pub const ALL: [Self; 18] = [
        Self::Amplification,
        Self::DuplicateIssuance,
        Self::EmptyRights,
        Self::ForeignSubject,
        Self::InvalidChildPath,
        Self::InvalidPath,
        Self::InvalidSlotIdentity,
        Self::LateCompletion,
        Self::NeverResurrects,
        Self::NotLive,
        Self::PathBindingRefused,
        Self::PathGrantsNoAuthority,
        Self::RequirementMismatch,
        Self::Revoked,
        Self::StaleGeneration,
        Self::UndeclaredMapping,
        Self::UnsupportedMode,
        Self::UnsupportedRepresentation,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Amplification => "native-dir-amplification",
            Self::DuplicateIssuance => "native-dir-duplicate-issuance",
            Self::EmptyRights => "native-dir-empty-rights",
            Self::ForeignSubject => "native-dir-foreign-subject",
            Self::InvalidChildPath => "native-dir-invalid-child-path",
            Self::InvalidPath => "native-dir-invalid-path",
            Self::InvalidSlotIdentity => "native-dir-invalid-slot-identity",
            Self::LateCompletion => "native-dir-late-completion",
            Self::NeverResurrects => "native-dir-never-resurrects",
            Self::NotLive => "native-dir-not-live",
            Self::PathBindingRefused => "native-dir-path-binding-refused",
            Self::PathGrantsNoAuthority => "native-dir-path-grants-no-authority",
            Self::RequirementMismatch => "native-dir-requirement-mismatch",
            Self::Revoked => "native-dir-revoked",
            Self::StaleGeneration => "native-dir-stale-generation",
            Self::UndeclaredMapping => "native-dir-undeclared-mapping",
            Self::UnsupportedMode => "native-dir-unsupported-mode",
            Self::UnsupportedRepresentation => "native-dir-unsupported-representation",
        }
    }

    /// Returns the one clause of Section 52 that declares this condition.
    #[must_use]
    pub fn clause(self) -> &'static str {
        match self {
            Self::EmptyRights
            | Self::InvalidPath
            | Self::UndeclaredMapping
            | Self::UnsupportedMode
            | Self::UnsupportedRepresentation => NATIVE_DIRECTORY_CLAUSES[1],
            Self::ForeignSubject | Self::PathBindingRefused | Self::RequirementMismatch => {
                NATIVE_DIRECTORY_CLAUSES[2]
            }
            Self::DuplicateIssuance
            | Self::InvalidSlotIdentity
            | Self::NotLive
            | Self::StaleGeneration => NATIVE_DIRECTORY_CLAUSES[3],
            Self::Revoked => NATIVE_DIRECTORY_CLAUSES[4],
            Self::LateCompletion => NATIVE_DIRECTORY_CLAUSES[5],
            Self::NeverResurrects | Self::PathGrantsNoAuthority => NATIVE_DIRECTORY_CLAUSES[6],
            Self::Amplification | Self::InvalidChildPath => NATIVE_DIRECTORY_CLAUSES[7],
        }
    }
}

/// One typed refusal of the native-directory model.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeDirectoryRefusal {
    code: NativeDirectoryDiagnosticCode,
    detail: String,
}

impl NativeDirectoryRefusal {
    fn new(code: NativeDirectoryDiagnosticCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }

    /// Returns the exact refusal code.
    #[must_use]
    pub const fn code(&self) -> NativeDirectoryDiagnosticCode {
        self.code
    }

    /// Returns the exact refusal detail.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }

    /// Returns the portable spelling of the refusal code.
    #[must_use]
    pub fn spelling(&self) -> &'static str {
        self.code.as_str()
    }
}

impl fmt::Display for NativeDirectoryRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code.as_str(), self.detail)
    }
}

impl std::error::Error for NativeDirectoryRefusal {}

/// The closed target set whose native directory mapping Section 52 declares.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum NativeDirectoryTarget {
    /// The Linux mapping, which is exact and case-sensitive.
    Linux,
    /// The macOS mapping, which carries one explicit case policy.
    MacOs,
}

impl NativeDirectoryTarget {
    /// Every declared target, in canonical order.
    pub const ALL: [Self; 2] = [Self::Linux, Self::MacOs];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Linux => "linux",
            Self::MacOs => "macos",
        }
    }
}

/// The closed case policy one declared target mapping carries.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum NativeDirectoryCase {
    /// Names compare exactly, scalar for scalar.
    Sensitive,
    /// Names compare after a declared uppercase-ASCII fold and admit ASCII scalars only.
    AsciiInsensitive,
}

impl NativeDirectoryCase {
    /// Every declared case policy, in canonical order.
    pub const ALL: [Self; 2] = [Self::Sensitive, Self::AsciiInsensitive];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Sensitive => "sensitive",
            Self::AsciiInsensitive => "ascii-insensitive",
        }
    }
}

/// The exact relation of two admitted native names under one declared mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeDirectoryComparison {
    /// The two names are the same scalar sequence.
    Identical,
    /// The two names differ only by uppercase ASCII scalars of a declared ASCII fold.
    EqualUnderDeclaredAsciiFold,
    /// The two names are distinct under the declared mapping.
    Distinct,
}

/// One declared target mapping for native directory names.
///
/// A mapping is declared data. It is never an ambient host observation, a lookup key, or a grant
/// of authority, and a target case behaviour this section does not declare is not admitted.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct NativeDirectoryMapping {
    target: NativeDirectoryTarget,
    case: NativeDirectoryCase,
}

impl NativeDirectoryMapping {
    /// The Linux mapping, which is exact and case-sensitive.
    pub const LINUX_SENSITIVE: Self =
        Self::declared(NativeDirectoryTarget::Linux, NativeDirectoryCase::Sensitive);

    /// The macOS mapping that preserves exact scalars.
    pub const MACOS_SENSITIVE: Self =
        Self::declared(NativeDirectoryTarget::MacOs, NativeDirectoryCase::Sensitive);

    /// The macOS mapping that folds uppercase ASCII and admits ASCII scalars only.
    pub const MACOS_ASCII_INSENSITIVE: Self = Self::declared(
        NativeDirectoryTarget::MacOs,
        NativeDirectoryCase::AsciiInsensitive,
    );

    /// Every declared mapping, in canonical order.
    pub const DECLARED: [Self; 3] = [
        Self::LINUX_SENSITIVE,
        Self::MACOS_SENSITIVE,
        Self::MACOS_ASCII_INSENSITIVE,
    ];

    const fn declared(target: NativeDirectoryTarget, case: NativeDirectoryCase) -> Self {
        Self { target, case }
    }

    /// Admits one declared target and case combination.
    ///
    /// # Errors
    ///
    /// Returns [NativeDirectoryDiagnosticCode::UndeclaredMapping] for a combination Section 52 does
    /// not declare, rather than inferring one from the host.
    pub fn new(
        target: NativeDirectoryTarget,
        case: NativeDirectoryCase,
    ) -> Result<Self, NativeDirectoryRefusal> {
        let mapping = Self::declared(target, case);
        if Self::DECLARED.contains(&mapping) {
            Ok(mapping)
        } else {
            Err(NativeDirectoryRefusal::new(
                NativeDirectoryDiagnosticCode::UndeclaredMapping,
                "the declared target and case are not a declared native directory mapping",
            ))
        }
    }

    /// Returns the declared target.
    #[must_use]
    pub const fn target(self) -> NativeDirectoryTarget {
        self.target
    }

    /// Returns the declared case policy.
    #[must_use]
    pub const fn case(self) -> NativeDirectoryCase {
        self.case
    }

    /// Admits one absolute native directory path text under this mapping.
    ///
    /// # Errors
    ///
    /// Returns [NativeDirectoryDiagnosticCode::InvalidPath] for an empty, relative, or
    /// control-carrying text, and [NativeDirectoryDiagnosticCode::UnsupportedRepresentation] when
    /// this mapping cannot preserve a presented scalar.
    pub fn admit_name(self, text: &str) -> Result<(), NativeDirectoryRefusal> {
        if text.is_empty() || !text.starts_with('/') {
            return Err(NativeDirectoryRefusal::new(
                NativeDirectoryDiagnosticCode::InvalidPath,
                "a native directory path text is nonempty and absolute",
            ));
        }
        if text.chars().any(char::is_control) || text.as_bytes().contains(&0) {
            return Err(NativeDirectoryRefusal::new(
                NativeDirectoryDiagnosticCode::InvalidPath,
                "a native directory path text carries a refused scalar",
            ));
        }
        self.preservation(text)
    }

    /// Admits one child projection text under this mapping.
    ///
    /// # Errors
    ///
    /// Returns [NativeDirectoryDiagnosticCode::InvalidChildPath] for an empty, absolute,
    /// escaping, or control-carrying text, and
    /// [NativeDirectoryDiagnosticCode::UnsupportedRepresentation] when this mapping cannot preserve
    /// a presented scalar.
    pub fn admit_child_name(self, text: &str) -> Result<(), NativeDirectoryRefusal> {
        if text.is_empty() || text.starts_with('/') {
            return Err(NativeDirectoryRefusal::new(
                NativeDirectoryDiagnosticCode::InvalidChildPath,
                "a child projection text is nonempty and relative",
            ));
        }
        if text.chars().any(char::is_control)
            || text.as_bytes().contains(&0)
            || text.split('/').any(|segment| segment == "..")
        {
            return Err(NativeDirectoryRefusal::new(
                NativeDirectoryDiagnosticCode::InvalidChildPath,
                "a child projection text neither escapes nor carries a refused scalar",
            ));
        }
        self.preservation(text)
    }

    fn preservation(self, text: &str) -> Result<(), NativeDirectoryRefusal> {
        if self.case == NativeDirectoryCase::AsciiInsensitive && !text.is_ascii() {
            return Err(NativeDirectoryRefusal::new(
                NativeDirectoryDiagnosticCode::UnsupportedRepresentation,
                "the declared mapping preserves ASCII scalars only",
            ));
        }
        Ok(())
    }

    /// Compares two admitted names under this declared mapping.
    #[must_use]
    pub fn compare(self, left: &str, right: &str) -> NativeDirectoryComparison {
        if left == right {
            return NativeDirectoryComparison::Identical;
        }
        if self.case == NativeDirectoryCase::AsciiInsensitive
            && fold_ascii(left) == fold_ascii(right)
        {
            return NativeDirectoryComparison::EqualUnderDeclaredAsciiFold;
        }
        NativeDirectoryComparison::Distinct
    }
}

/// One admitted absolute native directory path text.
///
/// The text is descriptive data only: it never authenticates a slot, never reconstructs a handle,
/// and never grants a right.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeDirectoryPath(String);

impl NativeDirectoryPath {
    /// Admits one absolute path text under one declared mapping.
    ///
    /// # Errors
    ///
    /// Returns the mapping admission refusal of the declared target mapping.
    pub fn new(
        text: &str,
        mapping: NativeDirectoryMapping,
    ) -> Result<Self, NativeDirectoryRefusal> {
        mapping.admit_name(text)?;
        Ok(Self(text.to_owned()))
    }

    /// Returns the exact admitted text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns whether this value grants authority, which it never does.
    #[must_use]
    pub const fn grants_authority(&self) -> bool {
        false
    }
}

impl fmt::Display for NativeDirectoryPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// One attached native directory slot and the path it declares.
///
/// The slot identity is a declared fact of the attached subject. Naming it is never authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeDirectorySlot {
    identity: Arc<str>,
    path: NativeDirectoryPath,
}

impl NativeDirectorySlot {
    /// Declares one attached slot identity and its declared path.
    ///
    /// # Errors
    ///
    /// Returns [NativeDirectoryDiagnosticCode::InvalidSlotIdentity] for an empty or
    /// control-carrying identity.
    pub fn new(identity: &str, path: NativeDirectoryPath) -> Result<Self, NativeDirectoryRefusal> {
        if identity.is_empty() || identity.chars().any(char::is_control) {
            return Err(NativeDirectoryRefusal::new(
                NativeDirectoryDiagnosticCode::InvalidSlotIdentity,
                "an attached slot identity is nonempty and carries no control scalar",
            ));
        }
        Ok(Self {
            identity: Arc::from(identity),
            path,
        })
    }

    /// Returns the declared attached slot identity.
    #[must_use]
    pub fn identity(&self) -> &str {
        &self.identity
    }

    /// Returns the declared attached path, which grants no authority.
    #[must_use]
    pub const fn path(&self) -> &NativeDirectoryPath {
        &self.path
    }
}

/// The exact declared facts one native directory subject binds.
///
/// The facts carry execution and task provenance, so counters that coincide across executions or
/// tasks never identify one subject.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeDirectorySubjectFacts {
    generation: ResourceGenerationId,
    execution: LogicalExecutionId,
    task: TaskBodyIdentity,
    owner: OwnerGeneration,
}

impl NativeDirectorySubjectFacts {
    /// Declares the exact facts of one subject.
    #[must_use]
    pub const fn new(
        generation: ResourceGenerationId,
        execution: LogicalExecutionId,
        task: TaskBodyIdentity,
        owner: OwnerGeneration,
    ) -> Self {
        Self {
            generation,
            execution,
            task,
            owner,
        }
    }

    /// Returns the resource generation of the subject.
    #[must_use]
    pub const fn generation(&self) -> &ResourceGenerationId {
        &self.generation
    }

    /// Returns the logical execution of the subject.
    #[must_use]
    pub const fn execution(&self) -> &LogicalExecutionId {
        &self.execution
    }

    /// Returns the task body of the subject.
    #[must_use]
    pub const fn task(&self) -> &TaskBodyIdentity {
        &self.task
    }

    /// Returns the owner generation of the subject.
    #[must_use]
    pub const fn owner(&self) -> OwnerGeneration {
        self.owner
    }
}

/// The closed operation requirement a native directory authority is declared for.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum NativeDirectoryRequirementKind {
    /// Open one native directory.
    Open,
    /// Enumerate one native directory.
    Enumerate,
    /// Open one child through an attenuated projection.
    OpenChild,
}

impl NativeDirectoryRequirementKind {
    /// Every declared requirement kind, in canonical order.
    pub const ALL: [Self; 3] = [Self::Open, Self::Enumerate, Self::OpenChild];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Enumerate => "enumerate",
            Self::OpenChild => "open-child",
        }
    }
}

/// One typed native directory requirement identity.
///
/// The identity is the canonical capability requirement identity of the authority contract plus
/// the declared operation requirement kind. Every route compares this exact identity, so a stored
/// but uncompared identity is not authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeDirectoryRequirement {
    identity: AuthorityRequirementId,
    kind: NativeDirectoryRequirementKind,
}

impl NativeDirectoryRequirement {
    /// Declares one typed requirement from its canonical identity and kind.
    #[must_use]
    pub const fn new(
        identity: AuthorityRequirementId,
        kind: NativeDirectoryRequirementKind,
    ) -> Self {
        Self { identity, kind }
    }

    /// Returns the canonical requirement identity.
    #[must_use]
    pub const fn identity(&self) -> &AuthorityRequirementId {
        &self.identity
    }

    /// Returns the declared requirement kind.
    #[must_use]
    pub const fn kind(&self) -> NativeDirectoryRequirementKind {
        self.kind
    }

    /// Returns the exact portable identity spelling of the requirement.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.identity.as_str()
    }
}

/// Exact declared authority for one native directory handle.
///
/// The authority binds the typed requirement, the declared rights, the declared target mapping,
/// the semantic mode, the exact subject facts, the declared path, and the authority generation
/// whose live fence every route consults.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeDirectoryAuthority {
    requirement: NativeDirectoryRequirement,
    rights: RightsSet,
    mapping: NativeDirectoryMapping,
    mode: SemanticMode,
    facts: NativeDirectorySubjectFacts,
    path: NativeDirectoryPath,
    fence_generation: AuthorityGeneration,
}

impl NativeDirectoryAuthority {
    /// Declares one exact authority for one subject.
    ///
    /// # Errors
    ///
    /// Returns [NativeDirectoryDiagnosticCode::EmptyRights] for an empty rights set and
    /// [NativeDirectoryDiagnosticCode::UnsupportedMode] for a mode other than the application
    /// mode.
    pub fn declare(
        requirement: NativeDirectoryRequirement,
        rights: RightsSet,
        mapping: NativeDirectoryMapping,
        mode: SemanticMode,
        facts: NativeDirectorySubjectFacts,
        path: NativeDirectoryPath,
        fence_generation: AuthorityGeneration,
    ) -> Result<Self, NativeDirectoryRefusal> {
        if rights.is_empty() {
            return Err(NativeDirectoryRefusal::new(
                NativeDirectoryDiagnosticCode::EmptyRights,
                "a native directory authority declares at least one right",
            ));
        }
        if !matches!(mode, SemanticMode::Application) {
            return Err(NativeDirectoryRefusal::new(
                NativeDirectoryDiagnosticCode::UnsupportedMode,
                "native directory handles apply to the application mode only",
            ));
        }
        Ok(Self {
            requirement,
            rights,
            mapping,
            mode,
            facts,
            path,
            fence_generation,
        })
    }

    /// Returns the typed requirement identity.
    #[must_use]
    pub const fn requirement(&self) -> &NativeDirectoryRequirement {
        &self.requirement
    }

    /// Returns the declared rights.
    #[must_use]
    pub const fn rights(&self) -> RightsSet {
        self.rights
    }

    /// Returns the declared target mapping.
    #[must_use]
    pub const fn mapping(&self) -> NativeDirectoryMapping {
        self.mapping
    }

    /// Returns the declared semantic mode.
    #[must_use]
    pub const fn mode(&self) -> SemanticMode {
        self.mode
    }

    /// Returns the exact subject facts.
    #[must_use]
    pub const fn facts(&self) -> &NativeDirectorySubjectFacts {
        &self.facts
    }

    /// Returns the declared path, which grants no authority.
    #[must_use]
    pub const fn path(&self) -> &NativeDirectoryPath {
        &self.path
    }

    /// Returns the authority generation whose live fence every route consults.
    #[must_use]
    pub const fn fence_generation(&self) -> AuthorityGeneration {
        self.fence_generation
    }
}

/// One live application-native directory handle.
///
/// The handle is affine: it implements neither clone nor copy, settling it consumes it, and a child
/// receives an explicit attenuation instead of this value.
#[derive(Debug)]
pub struct NativeDirectoryHandle {
    slot: NativeDirectorySlot,
    authority: NativeDirectoryAuthority,
}

impl NativeDirectoryHandle {
    /// Returns the attached slot.
    #[must_use]
    pub const fn slot(&self) -> &NativeDirectorySlot {
        &self.slot
    }

    /// Returns the exact declared authority.
    #[must_use]
    pub const fn authority(&self) -> &NativeDirectoryAuthority {
        &self.authority
    }

    /// Returns the declared path, which grants no authority.
    #[must_use]
    pub const fn path(&self) -> &NativeDirectoryPath {
        &self.authority.path
    }
}

/// One declared completion cut for a native directory handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeDirectoryCompletion {
    /// Semantic work completed at the declared logical instant.
    Completed {
        /// Declared logical settlement instant.
        settled_at: u64,
    },
    /// Cancellation settled the handle at the declared logical instant.
    Cancelled {
        /// Declared logical settlement instant.
        settled_at: u64,
    },
    /// A completion presented after the subject settled.
    Late {
        /// Declared logical instant of the late presentation.
        settled_at: u64,
    },
}

/// One recorded settlement winner of one attached slot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeDirectorySettlementWinner {
    slot_identity: Arc<str>,
    owner: OwnerGeneration,
    cancelled: bool,
    settled_at: u64,
}

impl NativeDirectorySettlementWinner {
    /// Returns the settled slot identity.
    #[must_use]
    pub fn slot_identity(&self) -> &str {
        &self.slot_identity
    }

    /// Returns the owner generation that settled the slot.
    #[must_use]
    pub const fn owner(&self) -> OwnerGeneration {
        self.owner
    }

    /// Returns whether cancellation won the settlement.
    #[must_use]
    pub const fn is_cancellation(&self) -> bool {
        self.cancelled
    }

    /// Returns the declared logical settlement instant.
    #[must_use]
    pub const fn settled_at(&self) -> u64 {
        self.settled_at
    }
}

/// The live issuance ledger of the declared native directory slots.
///
/// The ledger admits at most one live issuance per attached slot, keeps the live authority that
/// every route re-authenticates, consults one live authority fence per generation, and records one
/// settlement winner per slot.
#[derive(Debug, Default)]
pub struct NativeDirectoryLedger {
    fences: BTreeMap<AuthorityGeneration, AuthorityFence>,
    live: BTreeMap<Arc<str>, NativeDirectoryAuthority>,
    settled: BTreeMap<Arc<str>, NativeDirectorySettlementWinner>,
}

impl NativeDirectoryLedger {
    /// Returns the empty ledger, which issues nothing.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Issues one live handle over one attached slot.
    ///
    /// # Errors
    ///
    /// Returns [NativeDirectoryDiagnosticCode::Revoked] for a fenced generation,
    /// [NativeDirectoryDiagnosticCode::DuplicateIssuance] for a second live issuance of one slot,
    /// [NativeDirectoryDiagnosticCode::PathBindingRefused] when the declared paths disagree, and
    /// [NativeDirectoryDiagnosticCode::StaleGeneration] when a reissued slot names an owner that
    /// does not succeed the settled owner.
    pub fn issue(
        &mut self,
        slot: NativeDirectorySlot,
        authority: NativeDirectoryAuthority,
    ) -> Result<NativeDirectoryHandle, NativeDirectoryRefusal> {
        if self.is_fenced(authority.fence_generation()) {
            return Err(NativeDirectoryRefusal::new(
                NativeDirectoryDiagnosticCode::Revoked,
                "the authority generation is fenced by revocation",
            ));
        }
        if self.live.contains_key(slot.identity()) {
            return Err(NativeDirectoryRefusal::new(
                NativeDirectoryDiagnosticCode::DuplicateIssuance,
                "one attached slot carries at most one live native directory handle",
            ));
        }
        if authority.path() != slot.path() {
            return Err(NativeDirectoryRefusal::new(
                NativeDirectoryDiagnosticCode::PathBindingRefused,
                "the declared handle path differs from the attached slot path",
            ));
        }
        if let Some(previous) = self.settled.get(slot.identity())
            && !authority.facts().owner().succeeds(previous.owner())
        {
            return Err(NativeDirectoryRefusal::new(
                NativeDirectoryDiagnosticCode::StaleGeneration,
                "a reissued slot names an owner generation that does not succeed the settled one",
            ));
        }
        self.live
            .insert(Arc::from(slot.identity()), authority.clone());
        Ok(NativeDirectoryHandle { slot, authority })
    }

    /// Revokes one authority generation through its live fence.
    ///
    /// Revocation fences every later issuance and route of that generation, including the routes of
    /// handles already issued, and it neither withdraws admitted work nor cancels the settlement
    /// obligation.
    pub fn revoke(&mut self, generation: AuthorityGeneration) {
        self.fences
            .entry(generation)
            .or_insert_with(|| AuthorityFence::new(generation))
            .revoke();
    }

    /// Returns the live fencing decision of one generation, when it is known.
    #[must_use]
    pub fn fence_state(&self, generation: AuthorityGeneration) -> Option<FenceState> {
        self.fences.get(&generation).map(|fence| fence.state())
    }

    fn is_fenced(&self, generation: AuthorityGeneration) -> bool {
        self.fence_state(generation)
            .is_some_and(FenceState::is_fenced)
    }

    /// Returns the recorded settlement winner of one slot, when it settled.
    #[must_use]
    pub fn settlement(&self, slot_identity: &str) -> Option<&NativeDirectorySettlementWinner> {
        self.settled.get(slot_identity)
    }

    /// Re-authenticates one route through one live handle.
    ///
    /// # Errors
    ///
    /// Returns [NativeDirectoryDiagnosticCode::NotLive] when the slot holds no live issuance,
    /// [NativeDirectoryDiagnosticCode::Revoked] for a fenced generation,
    /// [NativeDirectoryDiagnosticCode::ForeignSubject] when the presented handle or facts belong
    /// to another subject, and [NativeDirectoryDiagnosticCode::RequirementMismatch] when the
    /// presented requirement identity is not the held one.
    pub fn route(
        &self,
        handle: &NativeDirectoryHandle,
        requirement: &NativeDirectoryRequirement,
        facts: &NativeDirectorySubjectFacts,
    ) -> Result<(), NativeDirectoryRefusal> {
        let live = self.live.get(handle.slot.identity()).ok_or_else(|| {
            NativeDirectoryRefusal::new(
                NativeDirectoryDiagnosticCode::NotLive,
                "no live native directory issuance exists for the presented slot",
            )
        })?;
        if self.is_fenced(live.fence_generation()) {
            return Err(NativeDirectoryRefusal::new(
                NativeDirectoryDiagnosticCode::Revoked,
                "the authority generation is fenced by revocation",
            ));
        }
        if live != handle.authority() {
            return Err(NativeDirectoryRefusal::new(
                NativeDirectoryDiagnosticCode::ForeignSubject,
                "the presented handle is not the live issuance of this slot",
            ));
        }
        if requirement != live.requirement() {
            return Err(NativeDirectoryRefusal::new(
                NativeDirectoryDiagnosticCode::RequirementMismatch,
                "the presented requirement identity is not the held one",
            ));
        }
        if facts != live.facts() {
            return Err(NativeDirectoryRefusal::new(
                NativeDirectoryDiagnosticCode::ForeignSubject,
                "the presented subject facts belong to another subject",
            ));
        }
        Ok(())
    }

    /// Settles one live handle exactly once, consuming it.
    ///
    /// Settlement stays admissible after revocation, because revocation fences new routes and never
    /// cancels the settlement obligation.
    ///
    /// # Errors
    ///
    /// Returns [NativeDirectoryDiagnosticCode::LateCompletion] for a late or repeated completion,
    /// [NativeDirectoryDiagnosticCode::NotLive] for a slot that never lived, and
    /// [NativeDirectoryDiagnosticCode::ForeignSubject] for a handle that is not the live issuance.
    pub fn settle(
        &mut self,
        handle: NativeDirectoryHandle,
        completion: NativeDirectoryCompletion,
    ) -> Result<NativeDirectorySettlementWinner, NativeDirectoryRefusal> {
        let (cancelled, settled_at) = admit_completion(completion)?;
        let identity: Arc<str> = Arc::from(handle.slot.identity());
        let owner = match self.live.get(&identity) {
            Some(live) => {
                if *live != *handle.authority() {
                    return Err(NativeDirectoryRefusal::new(
                        NativeDirectoryDiagnosticCode::ForeignSubject,
                        "the settled handle is not the live issuance of this slot",
                    ));
                }
                live.facts().owner()
            }
            None if self.settled.contains_key(&identity) => {
                return Err(NativeDirectoryRefusal::new(
                    NativeDirectoryDiagnosticCode::LateCompletion,
                    "this slot already settled, so a later completion is refused without effect",
                ));
            }
            None => {
                return Err(NativeDirectoryRefusal::new(
                    NativeDirectoryDiagnosticCode::NotLive,
                    "no live native directory issuance exists for the presented slot",
                ));
            }
        };
        Ok(self.record_settlement(identity, owner, cancelled, settled_at))
    }

    /// Settles one slot from a presented completion that carries its exact facts.
    ///
    /// This is the route an I/O completion takes. It refuses a completion of another subject and
    /// every completion presented after the slot settled.
    ///
    /// # Errors
    ///
    /// Returns [NativeDirectoryDiagnosticCode::LateCompletion] for a late or repeated completion,
    /// [NativeDirectoryDiagnosticCode::NotLive] for a slot that never lived,
    /// [NativeDirectoryDiagnosticCode::PathBindingRefused] when the presented path is not the
    /// declared one, and [NativeDirectoryDiagnosticCode::ForeignSubject] for another subject.
    pub fn settle_completion(
        &mut self,
        slot: &NativeDirectorySlot,
        facts: &NativeDirectorySubjectFacts,
        completion: NativeDirectoryCompletion,
    ) -> Result<NativeDirectorySettlementWinner, NativeDirectoryRefusal> {
        let (cancelled, settled_at) = admit_completion(completion)?;
        let identity: Arc<str> = Arc::from(slot.identity());
        let owner = match self.live.get(&identity) {
            Some(live) => {
                if live.path() != slot.path() {
                    return Err(NativeDirectoryRefusal::new(
                        NativeDirectoryDiagnosticCode::PathBindingRefused,
                        "the presented slot path is not the declared path of this issuance",
                    ));
                }
                if live.facts() != facts {
                    return Err(NativeDirectoryRefusal::new(
                        NativeDirectoryDiagnosticCode::ForeignSubject,
                        "the presented completion facts belong to another subject",
                    ));
                }
                facts.owner()
            }
            None if self.settled.contains_key(&identity) => {
                return Err(NativeDirectoryRefusal::new(
                    NativeDirectoryDiagnosticCode::LateCompletion,
                    "this slot already settled, so a later completion is refused without effect",
                ));
            }
            None => {
                return Err(NativeDirectoryRefusal::new(
                    NativeDirectoryDiagnosticCode::NotLive,
                    "no live native directory issuance exists for the presented slot",
                ));
            }
        };
        Ok(self.record_settlement(identity, owner, cancelled, settled_at))
    }

    fn record_settlement(
        &mut self,
        identity: Arc<str>,
        owner: OwnerGeneration,
        cancelled: bool,
        settled_at: u64,
    ) -> NativeDirectorySettlementWinner {
        self.live.remove(&identity);
        let winner = NativeDirectorySettlementWinner {
            slot_identity: identity.clone(),
            owner,
            cancelled,
            settled_at,
        };
        self.settled.insert(identity, winner.clone());
        winner
    }

    /// Projects one explicit attenuated child grant from one authenticated parent handle.
    ///
    /// # Errors
    ///
    /// Returns [NativeDirectoryDiagnosticCode::Amplification] for a widened rights set,
    /// [NativeDirectoryDiagnosticCode::InvalidChildPath] for an absolute, escaping, or malformed
    /// relative text, [NativeDirectoryDiagnosticCode::UnsupportedRepresentation] when the
    /// inherited mapping cannot preserve the child text, and the route refusal otherwise.
    pub fn project_child(
        &self,
        handle: &NativeDirectoryHandle,
        grant: &NativeDirectoryChildGrant,
    ) -> Result<NativeDirectoryChildProjection, NativeDirectoryRefusal> {
        let live = self.live.get(handle.slot.identity()).ok_or_else(|| {
            NativeDirectoryRefusal::new(
                NativeDirectoryDiagnosticCode::NotLive,
                "no live native directory issuance exists for the presented slot",
            )
        })?;
        if self.is_fenced(live.fence_generation()) {
            return Err(NativeDirectoryRefusal::new(
                NativeDirectoryDiagnosticCode::Revoked,
                "the authority generation is fenced by revocation",
            ));
        }
        if live != handle.authority() {
            return Err(NativeDirectoryRefusal::new(
                NativeDirectoryDiagnosticCode::ForeignSubject,
                "the presented handle is not the live issuance of this slot",
            ));
        }
        if !grant.rights().is_subset_of(live.rights()) {
            return Err(NativeDirectoryRefusal::new(
                NativeDirectoryDiagnosticCode::Amplification,
                "a child projection requests a right the parent does not hold",
            ));
        }
        live.mapping().admit_child_name(grant.relative())?;
        Ok(NativeDirectoryChildProjection {
            rights: grant.rights(),
            relative: grant.relative().to_owned(),
            mapping: live.mapping(),
            lineage: NativeDirectoryLineage {
                parent: live.facts().clone(),
            },
        })
    }
}

/// One explicit attenuated child grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeDirectoryChildGrant {
    rights: RightsSet,
    relative: String,
}

impl NativeDirectoryChildGrant {
    /// Declares one child grant from a right set and a relative text.
    #[must_use]
    pub fn new(rights: RightsSet, relative: impl Into<String>) -> Self {
        Self {
            rights,
            relative: relative.into(),
        }
    }

    /// Returns the requested rights.
    #[must_use]
    pub const fn rights(&self) -> RightsSet {
        self.rights
    }

    /// Returns the requested relative text.
    #[must_use]
    pub fn relative(&self) -> &str {
        &self.relative
    }
}

/// The exact parent facts one attenuated child projection retains as lineage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeDirectoryLineage {
    parent: NativeDirectorySubjectFacts,
}

impl NativeDirectoryLineage {
    /// Returns the exact parent subject facts of this projection.
    #[must_use]
    pub const fn parent(&self) -> &NativeDirectorySubjectFacts {
        &self.parent
    }
}

/// One exact attenuated child projection of one live handle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeDirectoryChildProjection {
    rights: RightsSet,
    relative: String,
    mapping: NativeDirectoryMapping,
    lineage: NativeDirectoryLineage,
}

impl NativeDirectoryChildProjection {
    /// Returns the attenuated rights.
    #[must_use]
    pub const fn rights(&self) -> RightsSet {
        self.rights
    }

    /// Returns the admitted relative text.
    #[must_use]
    pub fn relative(&self) -> &str {
        &self.relative
    }

    /// Returns the inherited target mapping.
    #[must_use]
    pub const fn mapping(&self) -> NativeDirectoryMapping {
        self.mapping
    }

    /// Returns the retained parent lineage.
    #[must_use]
    pub const fn lineage(&self) -> &NativeDirectoryLineage {
        &self.lineage
    }
}

/// Returns the admitted cut of one presented completion.
fn admit_completion(
    completion: NativeDirectoryCompletion,
) -> Result<(bool, u64), NativeDirectoryRefusal> {
    match completion {
        NativeDirectoryCompletion::Completed { settled_at } => Ok((false, settled_at)),
        NativeDirectoryCompletion::Cancelled { settled_at } => Ok((true, settled_at)),
        NativeDirectoryCompletion::Late { settled_at } => Err(NativeDirectoryRefusal::new(
            NativeDirectoryDiagnosticCode::LateCompletion,
            format!(
                "a late native directory completion at {} is refused without effect",
                settled_at
            ),
        )),
    }
}

/// The closed durable presentation of a native directory fact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NativeDirectoryDurablePresentation {
    /// A process-local native handle.
    Handle,
    /// A path string.
    Path(String),
    /// A content digest.
    Digest(String),
    /// Portable logical working-directory text.
    LogicalText(String),
}

/// The only value a durable native-directory presentation may recover.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeDirectoryRecovery {
    logical_text: String,
}

impl NativeDirectoryRecovery {
    /// Returns the recovered logical text, which is data and grants no authority.
    #[must_use]
    pub fn logical_text(&self) -> &str {
        &self.logical_text
    }
}

/// Recovers only portable logical text.
///
/// # Errors
///
/// Returns [NativeDirectoryDiagnosticCode::NeverResurrects] for a native handle presentation and
/// [NativeDirectoryDiagnosticCode::PathGrantsNoAuthority] for a path or digest presentation.
pub fn recover_native_directory(
    presentation: NativeDirectoryDurablePresentation,
) -> Result<NativeDirectoryRecovery, NativeDirectoryRefusal> {
    match presentation {
        NativeDirectoryDurablePresentation::Handle => Err(NativeDirectoryRefusal::new(
            NativeDirectoryDiagnosticCode::NeverResurrects,
            "a native directory handle never resurrects from durable state",
        )),
        NativeDirectoryDurablePresentation::Path(..)
        | NativeDirectoryDurablePresentation::Digest(..) => Err(NativeDirectoryRefusal::new(
            NativeDirectoryDiagnosticCode::PathGrantsNoAuthority,
            "a path or digest presentation grants no native directory authority",
        )),
        NativeDirectoryDurablePresentation::LogicalText(logical_text) => {
            Ok(NativeDirectoryRecovery { logical_text })
        }
    }
}

/// Folds uppercase ASCII scalars and leaves every other scalar exact.
fn fold_ascii(text: &str) -> String {
    text.chars()
        .map(|scalar| {
            if scalar.is_ascii_uppercase() {
                scalar.to_ascii_lowercase()
            } else {
                scalar
            }
        })
        .collect()
}
