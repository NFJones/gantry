//! Workspace manifests, deterministic dependency solving, and lockfile binding.
//!
//! `SPEC.md` states in its package section that it defines no lockfile format
//! and that `PACKAGE-001` owns one, so this module owns the workspace and
//! lockfile contract. Scope is deliberately pure: the model never reads a host
//! path, never opens a network connection, never parses or executes package
//! source, and never mutates an input. Every fact it decides is reproducible
//! from its own arguments.
//!
//! Three rules make resolution deterministic and explicit.
//!
//! 1. An instance is keyed by package name, exact version, and selected feature
//!    set, so simultaneous versions and feature selections stay distinct
//!    instances instead of being unified into one.
//! 2. No version is selected implicitly. A requirement matching zero releases is
//!    refused as unresolved and a requirement matching more than one is refused
//!    as ambiguous, so dependency or filesystem order cannot change which
//!    instance a name resolves to, and a newer release never wins by accident.
//! 3. A lockfile binds source, version, features, targets, dependencies,
//!    interface digest, and generator inputs. It is verified before use and is
//!    rewritten only when policy explicitly permits an update, so no lockfile
//!    rewrite is silent and no frozen lockfile is discarded by an offline build.
//!
//! Undeclared transitive access stays inaccessible: resolution exposes exactly
//! the dependency edges a package itself declares, and reaching through a
//! dependency's own dependencies is never implied.
//!
//! Rust `Debug` and `Display` renderings are presentation only. The portable
//! lockfile format is [`WorkspaceLockfile::canonical_text`].

#![allow(clippy::result_large_err)]

use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;

use crate::authority::digest_fields;
use crate::manifest::encode_hex;
use crate::package::{
    GeneratorInput, GeneratorInputRole, GeneratorInputs, PackageName, PackageVersion,
    SelectedFeatureSet, TargetFactSet, TargetFacts, TargetKind,
};

/// Domain separator for one canonical lockfile entry identity.
const ENTRY_DOMAIN: &str = "gantry.workspace-lockfile-entry/v1";

/// Domain separator for the canonical lockfile text digest.
const LOCKFILE_DOMAIN: &str = "gantry.workspace-lockfile/v1";

/// One frozen published diagnostic identity of this model.
///
/// The codes are frozen: a consumer matches on [`Self::as_str`], and no spelling
/// is shared by two refusal conditions. The variant order is the sorted code
/// order, so [`Self::ALL`] is already in registry order.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum WorkspaceDiagnosticCode {
    /// `workspace-alias-collision`
    AliasCollision,
    /// `workspace-member-duplicate`
    DuplicateMember,
    /// `workspace-generator-input-mismatch`
    GeneratorInputMismatch,
    /// `workspace-instance-not-shipping`
    InstanceNotShipping,
    /// `workspace-lockfile-rewrite-refused`
    LockfileRewriteRefused,
    /// `workspace-lockfile-stale`
    LockfileStale,
    /// `workspace-lockfile-tampered`
    LockfileTampered,
    /// `workspace-lockfile-version-unsupported`
    LockfileVersionUnsupported,
    /// `workspace-member-not-contained`
    MemberNotContained,
    /// `workspace-offline-source-unavailable`
    OfflineSourceUnavailable,
    /// `workspace-solve-conflict`
    SolveConflict,
    /// `workspace-source-refused`
    SourceRefused,
    /// `workspace-vendored-source-mismatch`
    VendoredSourceMismatch,
}

impl WorkspaceDiagnosticCode {
    /// Every published code, in sorted code order.
    pub const ALL: [Self; 13] = [
        Self::AliasCollision,
        Self::DuplicateMember,
        Self::GeneratorInputMismatch,
        Self::InstanceNotShipping,
        Self::LockfileRewriteRefused,
        Self::LockfileStale,
        Self::LockfileTampered,
        Self::LockfileVersionUnsupported,
        Self::MemberNotContained,
        Self::OfflineSourceUnavailable,
        Self::SolveConflict,
        Self::SourceRefused,
        Self::VendoredSourceMismatch,
    ];

    /// Returns the exact frozen code spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AliasCollision => "workspace-alias-collision",
            Self::DuplicateMember => "workspace-member-duplicate",
            Self::GeneratorInputMismatch => "workspace-generator-input-mismatch",
            Self::InstanceNotShipping => "workspace-instance-not-shipping",
            Self::LockfileRewriteRefused => "workspace-lockfile-rewrite-refused",
            Self::LockfileStale => "workspace-lockfile-stale",
            Self::LockfileTampered => "workspace-lockfile-tampered",
            Self::LockfileVersionUnsupported => "workspace-lockfile-version-unsupported",
            Self::MemberNotContained => "workspace-member-not-contained",
            Self::OfflineSourceUnavailable => "workspace-offline-source-unavailable",
            Self::SolveConflict => "workspace-solve-conflict",
            Self::SourceRefused => "workspace-source-refused",
            Self::VendoredSourceMismatch => "workspace-vendored-source-mismatch",
        }
    }

    /// Returns the frozen meaning registered for this code.
    #[must_use]
    pub const fn meaning(self) -> &'static str {
        match self {
            Self::AliasCollision => {
                "A dependency alias collides with another declared name in its workspace."
            }
            Self::DuplicateMember => "Two workspace members declare the same package name.",
            Self::GeneratorInputMismatch => {
                "A lockfile entry's generator inputs differ from the resolved release's."
            }
            Self::InstanceNotShipping => {
                "A resolved instance declares no shipping target, so it cannot be part of a resolution."
            }
            Self::LockfileRewriteRefused => {
                "A resolution differing from the lockfile would require an update policy that forbids one."
            }
            Self::LockfileStale => {
                "A lockfile records a different instance set than the current resolution."
            }
            Self::LockfileTampered => {
                "A lockfile entry does not match the identity recomputed from its own fields."
            }
            Self::LockfileVersionUnsupported => {
                "A lockfile declares a format version this model does not implement."
            }
            Self::MemberNotContained => {
                "A workspace member root is not inside the declared workspace root."
            }
            Self::OfflineSourceUnavailable => {
                "An offline policy received a requirement whose source needs authenticated acquisition."
            }
            Self::SolveConflict => {
                "A dependency requirement matches zero releases or more than one release."
            }
            Self::SourceRefused => {
                "A dependency source locator, revision, or digest is malformed or movable."
            }
            Self::VendoredSourceMismatch => {
                "A vendored requirement's declared digest differs from the vendored release's."
            }
        }
    }
}

/// One refused workspace, source, resolution, or lockfile decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkspaceError {
    /// A dependency alias collides with another declared name.
    AliasCollision {
        /// The declaring member.
        member: PackageName,
        /// The colliding alias.
        alias: PackageName,
    },
    /// Two workspace members declare the same package name.
    DuplicateMember {
        /// The duplicated member name.
        member: PackageName,
    },
    /// A lockfile entry's generator inputs differ from the resolved release's.
    GeneratorInputMismatch {
        /// The package whose generator inputs differ.
        package: PackageName,
    },
    /// A resolved instance declares no shipping target.
    InstanceNotShipping {
        /// The instance without a shipping target.
        package: PackageName,
    },
    /// A lockfile rewrite was refused because policy forbids an update.
    LockfileRewriteRefused {
        /// Entries recorded by the lockfile.
        locked: usize,
        /// Instances the current resolution produced.
        resolved: usize,
    },
    /// A lockfile records a different instance set than the current resolution.
    LockfileStale {
        /// Entries recorded by the lockfile.
        locked: usize,
        /// Instances the current resolution produced.
        resolved: usize,
    },
    /// A lockfile entry disagrees with its own recomputed identity.
    LockfileTampered {
        /// The exact recorded identity text.
        identity: Arc<str>,
    },
    /// A lockfile declares an unsupported format version.
    LockfileVersionUnsupported {
        /// The declared version.
        version: u32,
    },
    /// A member root is not inside the workspace root.
    MemberNotContained {
        /// The member package name.
        member: PackageName,
        /// The declared workspace root text.
        root: Arc<str>,
        /// The declared member root text.
        path: Arc<str>,
    },
    /// An offline policy received a requirement needing authenticated acquisition.
    OfflineSourceUnavailable {
        /// The package whose source needs acquisition.
        package: PackageName,
    },
    /// A requirement matched zero or more than one release.
    SolveConflict {
        /// The alias or dependency name under resolution.
        alias: PackageName,
        /// The exact refusal detail.
        detail: Arc<str>,
    },
    /// A locator, revision, or digest is malformed or movable.
    SourceRefused {
        /// The exact refused value.
        detail: Arc<str>,
    },
    /// A vendored requirement's digest differs from the vendored release's.
    VendoredSourceMismatch {
        /// The package under resolution.
        package: PackageName,
        /// The declared requirement digest.
        expected: Arc<str>,
        /// The vendored release digest.
        found: Arc<str>,
    },
}

impl WorkspaceError {
    /// Returns the published code owning this refusal, if one is registered.
    #[must_use]
    pub fn code(&self) -> WorkspaceDiagnosticCode {
        match self {
            Self::AliasCollision { .. } => WorkspaceDiagnosticCode::AliasCollision,
            Self::DuplicateMember { .. } => WorkspaceDiagnosticCode::DuplicateMember,
            Self::GeneratorInputMismatch { .. } => WorkspaceDiagnosticCode::GeneratorInputMismatch,
            Self::InstanceNotShipping { .. } => WorkspaceDiagnosticCode::InstanceNotShipping,
            Self::LockfileRewriteRefused { .. } => WorkspaceDiagnosticCode::LockfileRewriteRefused,
            Self::LockfileStale { .. } => WorkspaceDiagnosticCode::LockfileStale,
            Self::LockfileTampered { .. } => WorkspaceDiagnosticCode::LockfileTampered,
            Self::LockfileVersionUnsupported { .. } => {
                WorkspaceDiagnosticCode::LockfileVersionUnsupported
            }
            Self::MemberNotContained { .. } => WorkspaceDiagnosticCode::MemberNotContained,
            Self::OfflineSourceUnavailable { .. } => {
                WorkspaceDiagnosticCode::OfflineSourceUnavailable
            }
            Self::SolveConflict { .. } => WorkspaceDiagnosticCode::SolveConflict,
            Self::SourceRefused { .. } => WorkspaceDiagnosticCode::SourceRefused,
            Self::VendoredSourceMismatch { .. } => WorkspaceDiagnosticCode::VendoredSourceMismatch,
        }
    }

    /// Returns the exact frozen code spelling of this refusal.
    #[must_use]
    pub fn code_str(&self) -> &'static str {
        self.code().as_str()
    }
}

impl fmt::Display for WorkspaceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.code().as_str())
    }
}

impl std::error::Error for WorkspaceError {}

/// Refuses one source locator that no canonical format can carry exactly.
fn validate_locator(value: &str) -> Result<(), WorkspaceError> {
    let refused = value.is_empty()
        || value.starts_with('/')
        || value.ends_with('/')
        || value
            .split('/')
            .any(|segment| segment == "." || segment == "..")
        || value
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte == b',' || byte.is_ascii_control());
    if refused {
        return Err(WorkspaceError::SourceRefused {
            detail: Arc::from(value),
        });
    }
    Ok(())
}

/// Refuses one digest spelling that is not exactly 64 lowercase hex digits.
fn validate_digest(value: &str) -> Result<(), WorkspaceError> {
    let valid = value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if !valid {
        return Err(WorkspaceError::SourceRefused {
            detail: Arc::from(value),
        });
    }
    Ok(())
}

/// One validated source locator.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SourceLocator(Arc<str>);

impl SourceLocator {
    /// Validates one exact source locator.
    pub fn new(value: &str) -> Result<Self, WorkspaceError> {
        validate_locator(value)?;
        Ok(Self(Arc::from(value)))
    }

    /// Returns the exact locator text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One immutable source-control revision: exactly 40 lowercase hex digits.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SourceRevision(Arc<str>);

impl SourceRevision {
    /// Validates one immutable revision.
    ///
    /// A branch, tag, or moving reference is refused: a locked input is an exact
    /// revision, and a movable reference would let the same lockfile acquire
    /// different bytes.
    pub fn new(value: &str) -> Result<Self, WorkspaceError> {
        let valid = value.len() == 40
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        if !valid {
            return Err(WorkspaceError::SourceRefused {
                detail: Arc::from(value),
            });
        }
        Ok(Self(Arc::from(value)))
    }

    /// Returns the exact revision text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One validated lowercase hexadecimal SHA-256 digest.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ContentDigest(Arc<str>);

impl ContentDigest {
    /// Validates one digest spelling.
    pub fn new(value: &str) -> Result<Self, WorkspaceError> {
        validate_digest(value)?;
        Ok(Self(Arc::from(value)))
    }

    /// Encodes one digest value.
    #[must_use]
    pub fn from_digest(digest: [u8; 32]) -> Self {
        Self(Arc::from(encode_hex(&digest).as_str()))
    }

    /// Returns the exact digest text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One declared dependency source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DependencySource {
    /// A workspace-local or declared path source.
    Path {
        /// The declared root.
        root: SourceLocator,
    },
    /// A source-control source pinned to one immutable revision.
    Vcs {
        /// The repository locator.
        locator: SourceLocator,
        /// The exact immutable revision.
        revision: SourceRevision,
    },
    /// An authenticated registry release.
    Registry {
        /// The declared registry identity.
        registry: SourceLocator,
        /// The exact released version.
        version: PackageVersion,
    },
    /// A vendored source checked against one declared content digest.
    Vendored {
        /// The vendored root.
        root: SourceLocator,
        /// The declared content digest.
        digest: ContentDigest,
    },
}

impl DependencySource {
    /// Returns the exact portable source-kind spelling.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Path { .. } => "path",
            Self::Vcs { .. } => "vcs",
            Self::Registry { .. } => "registry",
            Self::Vendored { .. } => "vendored",
        }
    }

    /// Returns whether this source needs authenticated acquisition.
    #[must_use]
    pub const fn requires_acquisition(&self) -> bool {
        matches!(self, Self::Registry { .. })
    }

    /// Encodes this source as one canonical comma-separated token.
    #[must_use]
    pub fn canonical_text(&self) -> String {
        match self {
            Self::Path { root } => format!("path,{}", root.as_str()),
            Self::Vcs { locator, revision } => {
                format!("vcs,{},{} ", locator.as_str(), revision.as_str())
                    .trim_end()
                    .to_owned()
            }
            Self::Registry { registry, version } => {
                format!("registry,{},{}", registry.as_str(), version.as_str())
            }
            Self::Vendored { root, digest } => {
                format!("vendored,{},{}", root.as_str(), digest.as_str())
            }
        }
    }

    /// Strictly decodes one canonical source token.
    pub fn parse(text: &str) -> Result<Self, WorkspaceError> {
        let mut fields = text.split(',');
        let kind = fields.next().unwrap_or_default();
        let first = fields.next().unwrap_or_default();
        let second = fields.next().unwrap_or_default();
        if fields.next().is_some() {
            return Err(WorkspaceError::SourceRefused {
                detail: Arc::from(text),
            });
        }
        match kind {
            "path" if second.is_empty() => Ok(Self::Path {
                root: SourceLocator::new(first)?,
            }),
            "vcs" => Ok(Self::Vcs {
                locator: SourceLocator::new(first)?,
                revision: SourceRevision::new(second)?,
            }),
            "registry" => Ok(Self::Registry {
                registry: SourceLocator::new(first)?,
                version: PackageVersion::new(second).map_err(|_| {
                    WorkspaceError::SourceRefused {
                        detail: Arc::from(text),
                    }
                })?,
            }),
            "vendored" => Ok(Self::Vendored {
                root: SourceLocator::new(first)?,
                digest: ContentDigest::new(second)?,
            }),
            _ => Err(WorkspaceError::SourceRefused {
                detail: Arc::from(text),
            }),
        }
    }
}

/// One declared dependency requirement of one member or release.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DependencyRequirement {
    alias: PackageName,
    source: DependencySource,
    features: SelectedFeatureSet,
}

impl DependencyRequirement {
    /// Constructs one declared requirement.
    #[must_use]
    pub const fn new(
        alias: PackageName,
        source: DependencySource,
        features: SelectedFeatureSet,
    ) -> Self {
        Self {
            alias,
            source,
            features,
        }
    }

    /// Returns the declared alias.
    #[must_use]
    pub const fn alias(&self) -> &PackageName {
        &self.alias
    }

    /// Returns the declared source.
    #[must_use]
    pub const fn source(&self) -> &DependencySource {
        &self.source
    }

    /// Returns the declared feature selection.
    #[must_use]
    pub const fn features(&self) -> &SelectedFeatureSet {
        &self.features
    }
}

/// One workspace member manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemberManifest {
    name: PackageName,
    version: PackageVersion,
    root: SourceLocator,
    targets: TargetFactSet,
    interface_digest: ContentDigest,
    dependencies: Vec<DependencyRequirement>,
}

impl MemberManifest {
    /// Constructs one member manifest.
    ///
    /// An alias declared twice, or an alias naming the member itself, is refused
    /// as a collision rather than resolved by declaration order.
    pub fn new(
        name: PackageName,
        version: PackageVersion,
        root: SourceLocator,
        targets: TargetFactSet,
        interface_digest: ContentDigest,
        dependencies: &[DependencyRequirement],
    ) -> Result<Self, WorkspaceError> {
        let mut aliases: BTreeSet<&str> = BTreeSet::new();
        for requirement in dependencies {
            let alias = requirement.alias.as_str();
            if alias == name.as_str() || !aliases.insert(alias) {
                return Err(WorkspaceError::AliasCollision {
                    member: name.clone(),
                    alias: requirement.alias.clone(),
                });
            }
        }
        Ok(Self {
            name,
            version,
            root,
            targets,
            interface_digest,
            dependencies: dependencies.to_vec(),
        })
    }

    /// Returns the member package name.
    #[must_use]
    pub const fn name(&self) -> &PackageName {
        &self.name
    }

    /// Returns the exact member version.
    #[must_use]
    pub const fn version(&self) -> &PackageVersion {
        &self.version
    }

    /// Returns the member root.
    #[must_use]
    pub const fn root(&self) -> &SourceLocator {
        &self.root
    }

    /// Returns the declared targets.
    #[must_use]
    pub const fn targets(&self) -> &TargetFactSet {
        &self.targets
    }

    /// Returns the declared member interface digest.
    #[must_use]
    pub const fn interface_digest(&self) -> &ContentDigest {
        &self.interface_digest
    }

    /// Returns the declared requirements.
    #[must_use]
    pub fn dependencies(&self) -> &[DependencyRequirement] {
        &self.dependencies
    }
}

/// One declared workspace manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceManifest {
    name: PackageName,
    root: SourceLocator,
    members: Vec<MemberManifest>,
}

impl WorkspaceManifest {
    /// Constructs one workspace manifest.
    ///
    /// Member names are unique, every member root is contained in the workspace
    /// root, and no dependency alias collides with any declared member name.
    pub fn new(
        name: PackageName,
        root: SourceLocator,
        members: &[MemberManifest],
    ) -> Result<Self, WorkspaceError> {
        let mut names: BTreeSet<&str> = BTreeSet::new();
        for member in members {
            if !names.insert(member.name.as_str()) {
                return Err(WorkspaceError::DuplicateMember {
                    member: member.name.clone(),
                });
            }
            let member_root = member.root.as_str();
            let contained = member_root == root.as_str()
                || member_root
                    .strip_prefix(root.as_str())
                    .is_some_and(|rest| rest.starts_with('/'));
            if !contained {
                return Err(WorkspaceError::MemberNotContained {
                    member: member.name.clone(),
                    root: Arc::from(root.as_str()),
                    path: Arc::from(member_root),
                });
            }
        }
        for member in members {
            for requirement in &member.dependencies {
                if names.contains(requirement.alias.as_str()) {
                    return Err(WorkspaceError::AliasCollision {
                        member: member.name.clone(),
                        alias: requirement.alias.clone(),
                    });
                }
            }
        }
        Ok(Self {
            name,
            root,
            members: members.to_vec(),
        })
    }

    /// Returns the workspace name.
    #[must_use]
    pub const fn name(&self) -> &PackageName {
        &self.name
    }

    /// Returns the workspace root.
    #[must_use]
    pub const fn root(&self) -> &SourceLocator {
        &self.root
    }

    /// Returns the declared members in declaration order.
    #[must_use]
    pub fn members(&self) -> &[MemberManifest] {
        &self.members
    }
}

/// One release available to resolution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageRelease {
    name: PackageName,
    version: PackageVersion,
    source: DependencySource,
    targets: TargetFactSet,
    interface_digest: ContentDigest,
    generator_inputs: GeneratorInputs,
    dependencies: Vec<PackageName>,
}

impl PackageRelease {
    /// Constructs one available release.
    #[must_use]
    pub const fn new(
        name: PackageName,
        version: PackageVersion,
        source: DependencySource,
        targets: TargetFactSet,
        interface_digest: ContentDigest,
        generator_inputs: GeneratorInputs,
        dependencies: Vec<PackageName>,
    ) -> Self {
        Self {
            name,
            version,
            source,
            targets,
            interface_digest,
            generator_inputs,
            dependencies,
        }
    }

    /// Returns the released package name.
    #[must_use]
    pub const fn name(&self) -> &PackageName {
        &self.name
    }

    /// Returns the exact released version.
    #[must_use]
    pub const fn version(&self) -> &PackageVersion {
        &self.version
    }

    /// Returns the release source.
    #[must_use]
    pub const fn source(&self) -> &DependencySource {
        &self.source
    }

    /// Returns the released targets.
    #[must_use]
    pub const fn targets(&self) -> &TargetFactSet {
        &self.targets
    }

    /// Returns the published interface digest.
    #[must_use]
    pub const fn interface_digest(&self) -> &ContentDigest {
        &self.interface_digest
    }

    /// Returns the declared generator inputs.
    #[must_use]
    pub const fn generator_inputs(&self) -> &GeneratorInputs {
        &self.generator_inputs
    }

    /// Returns the declared dependency names.
    #[must_use]
    pub fn dependencies(&self) -> &[PackageName] {
        &self.dependencies
    }
}

/// One resolved package instance and its bound identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedInstance {
    identity: ContentDigest,
    name: PackageName,
    version: PackageVersion,
    features: SelectedFeatureSet,
    targets: TargetFactSet,
    dependencies: Vec<PackageName>,
    interface_digest: ContentDigest,
    generator_inputs: GeneratorInputs,
    source: DependencySource,
}

impl ResolvedInstance {
    /// Returns the canonical instance identity.
    #[must_use]
    pub const fn identity(&self) -> &ContentDigest {
        &self.identity
    }

    /// Returns the exact instance identity text.
    #[must_use]
    pub fn identity_hex(&self) -> &str {
        self.identity.as_str()
    }

    /// Returns the instance package name.
    #[must_use]
    pub const fn name(&self) -> &PackageName {
        &self.name
    }

    /// Returns the exact instance version.
    #[must_use]
    pub const fn version(&self) -> &PackageVersion {
        &self.version
    }

    /// Returns the selected feature set.
    #[must_use]
    pub const fn features(&self) -> &SelectedFeatureSet {
        &self.features
    }

    /// Returns the instance targets.
    #[must_use]
    pub const fn targets(&self) -> &TargetFactSet {
        &self.targets
    }

    /// Returns exactly the dependency edges this instance declares.
    #[must_use]
    pub fn dependencies(&self) -> &[PackageName] {
        &self.dependencies
    }

    /// Returns the bound interface digest.
    #[must_use]
    pub const fn interface_digest(&self) -> &ContentDigest {
        &self.interface_digest
    }

    /// Returns the bound generator inputs.
    #[must_use]
    pub const fn generator_inputs(&self) -> &GeneratorInputs {
        &self.generator_inputs
    }

    /// Returns the bound source.
    #[must_use]
    pub const fn source(&self) -> &DependencySource {
        &self.source
    }
}

/// One resolved workspace with canonical instance identities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedWorkspace {
    instances: Vec<ResolvedInstance>,
}

impl ResolvedWorkspace {
    /// Returns every instance in canonical identity order.
    #[must_use]
    pub fn instances(&self) -> &[ResolvedInstance] {
        &self.instances
    }

    /// Returns the instance carrying exactly one identity.
    #[must_use]
    pub fn instance(&self, identity: &str) -> Option<&ResolvedInstance> {
        self.instances
            .iter()
            .find(|instance| instance.identity.as_str() == identity)
    }

    /// Returns the instance carrying exactly one name, version, and feature set.
    #[must_use]
    pub fn instance_of(
        &self,
        name: &str,
        version: &str,
        features: &SelectedFeatureSet,
    ) -> Option<&ResolvedInstance> {
        self.instances.iter().find(|instance| {
            instance.name.as_str() == name
                && instance.version.as_str() == version
                && instance.features == *features
        })
    }

    /// Returns every instance count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.instances.len()
    }

    /// Returns whether this resolution carries no instance.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.instances.is_empty()
    }
}

/// One explicit offline and update policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LockPolicy {
    /// Whether sources needing authenticated acquisition are refused.
    pub offline: bool,
    /// Whether an explicit lockfile update is permitted.
    pub allow_update: bool,
}

impl LockPolicy {
    /// The ordinary policy: acquisition allowed, updates explicit and permitted.
    #[must_use]
    pub const fn online_reviewable_update() -> Self {
        Self {
            offline: false,
            allow_update: true,
        }
    }

    /// A frozen offline policy: no acquisition and no lockfile update.
    #[must_use]
    pub const fn frozen_offline() -> Self {
        Self {
            offline: true,
            allow_update: false,
        }
    }

    /// An online policy that never rewrites a lockfile.
    #[must_use]
    pub const fn online_frozen() -> Self {
        Self {
            offline: false,
            allow_update: false,
        }
    }
}

impl Default for LockPolicy {
    fn default() -> Self {
        Self::online_reviewable_update()
    }
}

/// Returns the canonical feature key of one selection.
fn feature_key(features: &SelectedFeatureSet) -> String {
    let mut names: Vec<&str> = features.names().collect();
    names.sort_unstable();
    names.join("+")
}

/// Returns the canonical target token for one target fact.
fn target_token(facts: &TargetFacts) -> String {
    match facts.entry_point() {
        Some(entry) => format!("{}:{}", facts.kind().wire_name(), entry.as_str()),
        None => facts.kind().wire_name().to_owned(),
    }
}

/// Returns the canonical target token list of one target set.
fn target_tokens(targets: &TargetFactSet) -> Vec<String> {
    let mut tokens: Vec<String> = targets.as_slice().iter().map(target_token).collect();
    tokens.sort_unstable();
    tokens.dedup();
    tokens
}

/// Returns the canonical generator-input token list.
fn generator_tokens(inputs: &GeneratorInputs) -> Vec<String> {
    let mut tokens: Vec<String> = inputs
        .as_slice()
        .iter()
        .map(|entry| format!("{}:{}:{}", entry.role.wire_name(), entry.name, entry.digest))
        .collect();
    tokens.sort_unstable();
    tokens.dedup();
    tokens
}

/// Returns the canonical dependency-name list.
fn dependency_names(dependencies: &[PackageName]) -> Vec<String> {
    let mut names: Vec<String> = dependencies
        .iter()
        .map(|name| name.as_str().to_owned())
        .collect();
    names.sort_unstable();
    names.dedup();
    names
}

/// Returns whether one target set carries at least one shipping target.
fn has_shipping_target(targets: &TargetFactSet) -> bool {
    targets
        .as_slice()
        .iter()
        .any(|facts| facts.kind().is_shipping())
}

/// Derives one canonical instance identity from exactly the bound facts.
// The argument list is the identity's own field list: name, version, features,
// targets, dependencies, interface digest, generator inputs, and source are
// exactly what a lockfile entry binds, so grouping them would only rename the
// same set. The arity lint is answered explicitly instead of being hidden.
#[allow(clippy::too_many_arguments)]
fn derive_identity(
    name: &PackageName,
    version: &PackageVersion,
    features: &SelectedFeatureSet,
    targets: &TargetFactSet,
    dependencies: &[String],
    interface_digest: &ContentDigest,
    generator_inputs: &GeneratorInputs,
    source: &DependencySource,
) -> ContentDigest {
    let feature_key = feature_key(features);
    let target_key = target_tokens(targets).join(",");
    let dependency_key = dependencies.join(",");
    let generator_key = generator_tokens(generator_inputs).join(",");
    let source_key = source.canonical_text();
    ContentDigest::from_digest(digest_fields(
        ENTRY_DOMAIN,
        &[
            name.as_str().as_bytes(),
            version.as_str().as_bytes(),
            feature_key.as_bytes(),
            target_key.as_bytes(),
            dependency_key.as_bytes(),
            interface_digest.as_str().as_bytes(),
            generator_key.as_bytes(),
            source_key.as_bytes(),
        ],
    ))
}

/// Returns whether one requirement's source matches one release's source.
fn source_matches(
    requirement: &DependencyRequirement,
    release: &PackageRelease,
) -> Result<bool, WorkspaceError> {
    match (requirement.source(), release.source()) {
        (DependencySource::Path { root }, DependencySource::Path { root: other }) => {
            Ok(root == other)
        }
        (
            DependencySource::Vcs { locator, revision },
            DependencySource::Vcs {
                locator: other_locator,
                revision: other_revision,
            },
        ) => Ok(locator == other_locator && revision == other_revision),
        (
            DependencySource::Registry { registry, version },
            DependencySource::Registry {
                registry: other_registry,
                version: other_version,
            },
        ) => Ok(registry == other_registry && version == other_version),
        (
            DependencySource::Vendored { root, digest },
            DependencySource::Vendored {
                root: other_root,
                digest: other_digest,
            },
        ) => {
            if root != other_root {
                return Ok(false);
            }
            if digest != other_digest {
                return Err(WorkspaceError::VendoredSourceMismatch {
                    package: requirement.alias().clone(),
                    expected: Arc::from(digest.as_str()),
                    found: Arc::from(other_digest.as_str()),
                });
            }
            Ok(true)
        }
        _ => Ok(false),
    }
}

/// Selects exactly one release for one requirement.
fn select_release<'a>(
    releases: &'a [PackageRelease],
    requirement: &DependencyRequirement,
    policy: &LockPolicy,
) -> Result<&'a PackageRelease, WorkspaceError> {
    if policy.offline && requirement.source().requires_acquisition() {
        return Err(WorkspaceError::OfflineSourceUnavailable {
            package: requirement.alias().clone(),
        });
    }
    let mut matched: Vec<&PackageRelease> = Vec::new();
    for release in releases {
        if release.name() == requirement.alias() && source_matches(requirement, release)? {
            matched.push(release);
        }
    }
    match matched.as_slice() {
        [only] => Ok(only),
        [] => Err(WorkspaceError::SolveConflict {
            alias: requirement.alias().clone(),
            detail: Arc::from("no release matches the declared source and version"),
        }),
        _ => Err(WorkspaceError::SolveConflict {
            alias: requirement.alias().clone(),
            detail: Arc::from("more than one release matches; no version is selected implicitly"),
        }),
    }
}

/// Builds one instance from one release and one feature selection.
fn release_instance(
    release: &PackageRelease,
    features: &SelectedFeatureSet,
) -> Result<ResolvedInstance, WorkspaceError> {
    if !has_shipping_target(release.targets()) {
        return Err(WorkspaceError::InstanceNotShipping {
            package: release.name().clone(),
        });
    }
    let dependencies = dependency_names(release.dependencies());
    let identity = derive_identity(
        release.name(),
        release.version(),
        features,
        release.targets(),
        &dependencies,
        release.interface_digest(),
        release.generator_inputs(),
        release.source(),
    );
    Ok(ResolvedInstance {
        identity,
        name: release.name().clone(),
        version: release.version().clone(),
        features: features.clone(),
        targets: release.targets().clone(),
        dependencies: release
            .dependencies()
            .iter()
            .filter(|name| dependencies.contains(&name.as_str().to_owned()))
            .cloned()
            .collect(),
        interface_digest: release.interface_digest().clone(),
        generator_inputs: release.generator_inputs().clone(),
        source: release.source().clone(),
    })
}

/// Builds one member instance.
fn member_instance(
    member: &MemberManifest,
    dependencies: &[PackageName],
) -> Result<ResolvedInstance, WorkspaceError> {
    if !has_shipping_target(member.targets()) {
        return Err(WorkspaceError::InstanceNotShipping {
            package: member.name().clone(),
        });
    }
    let features = SelectedFeatureSet::empty();
    let generator_inputs = GeneratorInputs::empty();
    let names = dependency_names(dependencies);
    let source = DependencySource::Path {
        root: member.root().clone(),
    };
    let identity = derive_identity(
        member.name(),
        member.version(),
        &features,
        member.targets(),
        &names,
        member.interface_digest(),
        &generator_inputs,
        &source,
    );
    Ok(ResolvedInstance {
        identity,
        name: member.name().clone(),
        version: member.version().clone(),
        features,
        targets: member.targets().clone(),
        dependencies: dependencies.to_vec(),
        interface_digest: member.interface_digest().clone(),
        generator_inputs,
        source,
    })
}

/// Resolves one workspace under the ordinary policy.
pub fn solve(
    workspace: &WorkspaceManifest,
    releases: &[PackageRelease],
) -> Result<ResolvedWorkspace, WorkspaceError> {
    solve_with_policy(workspace, releases, &LockPolicy::default())
}

/// Resolves one workspace under one explicit policy.
///
/// Resolution is order-independent: members, requirements, releases, and
/// declared dependency names are folded through sorted keys, and the resulting
/// instance list carries canonical identity order, so permuting any input
/// produces the same instances with the same identities.
pub fn solve_with_policy(
    workspace: &WorkspaceManifest,
    releases: &[PackageRelease],
    policy: &LockPolicy,
) -> Result<ResolvedWorkspace, WorkspaceError> {
    let mut selected: BTreeSet<(String, String, String)> = BTreeSet::new();
    let mut instances: Vec<ResolvedInstance> = Vec::new();

    for member in workspace.members() {
        let mut direct: Vec<PackageName> = Vec::new();
        for requirement in member.dependencies() {
            let release = select_release(releases, requirement, policy)?;
            direct.push(release.name().clone());
            let key = (
                release.name().as_str().to_owned(),
                release.version().as_str().to_owned(),
                feature_key(requirement.features()),
            );
            if selected.insert(key) {
                instances.push(release_instance(release, requirement.features())?);
            }
        }
        let key = (
            member.name().as_str().to_owned(),
            member.version().as_str().to_owned(),
            String::new(),
        );
        if selected.insert(key) {
            instances.push(member_instance(member, &direct)?);
        }
    }

    let mut cursor = 0_usize;
    while cursor < instances.len() {
        let declared = dependency_names(instances[cursor].dependencies());
        for name in declared {
            let already = instances
                .iter()
                .any(|instance| instance.name().as_str() == name);
            if already {
                continue;
            }
            let mut matched: Vec<&PackageRelease> = Vec::new();
            for release in releases {
                if release.name().as_str() == name {
                    matched.push(release);
                }
            }
            let alias = PackageName::new(&name).map_err(|_| WorkspaceError::SolveConflict {
                alias: instances[cursor].name().clone(),
                detail: Arc::from("declared dependency name is not a valid package name"),
            })?;
            match matched.as_slice() {
                [only] => {
                    let features = SelectedFeatureSet::empty();
                    let key = (
                        only.name().as_str().to_owned(),
                        only.version().as_str().to_owned(),
                        feature_key(&features),
                    );
                    if selected.insert(key) {
                        instances.push(release_instance(only, &features)?);
                    }
                }
                [] => {
                    return Err(WorkspaceError::SolveConflict {
                        alias,
                        detail: Arc::from("no release matches the declared dependency name"),
                    });
                }
                _ => {
                    return Err(WorkspaceError::SolveConflict {
                        alias,
                        detail: Arc::from(
                            "more than one release matches; no version is selected implicitly",
                        ),
                    });
                }
            }
        }
        cursor += 1;
    }

    instances.sort_by(|left, right| left.identity.as_str().cmp(right.identity.as_str()));
    Ok(ResolvedWorkspace { instances })
}

/// One persisted resolution binding every instance of one workspace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceLockfile {
    version: u32,
    entries: Vec<ResolvedInstance>,
}

impl WorkspaceLockfile {
    /// The lockfile format version this model implements.
    pub const SUPPORTED_VERSION: u32 = 1;

    /// Binds one resolution into a lockfile.
    #[must_use]
    pub fn from_resolved(resolved: &ResolvedWorkspace) -> Self {
        Self {
            version: Self::SUPPORTED_VERSION,
            entries: resolved.instances().to_vec(),
        }
    }

    /// Returns the declared format version.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// Returns every bound entry in canonical identity order.
    #[must_use]
    pub fn entries(&self) -> &[ResolvedInstance] {
        &self.entries
    }

    /// Encodes this lockfile as canonical line-oriented text.
    #[must_use]
    pub fn canonical_text(&self) -> String {
        let mut text = format!("gantry-workspace-lockfile {}\n", self.version);
        let mut entries = self.entries.clone();
        entries.sort_by(|left, right| left.identity.as_str().cmp(right.identity.as_str()));
        for entry in entries {
            let features = feature_key(entry.features());
            let targets = target_tokens(entry.targets()).join("+");
            let dependencies = dependency_names(entry.dependencies()).join("+");
            let generators = generator_tokens(entry.generator_inputs()).join("+");
            text.push_str(&format!(
                "entry {} {} {} {} {} {} {} {} {}\n",
                entry.identity_hex(),
                entry.name().as_str(),
                entry.version().as_str(),
                empty_as_dash(&features),
                empty_as_dash(&targets),
                empty_as_dash(&dependencies),
                entry.interface_digest().as_str(),
                empty_as_dash(&generators),
                entry.source().canonical_text(),
            ));
        }
        text
    }

    /// Returns the canonical text digest of this lockfile.
    #[must_use]
    pub fn text_digest(&self) -> ContentDigest {
        ContentDigest::from_digest(digest_fields(
            LOCKFILE_DOMAIN,
            &[self.canonical_text().as_bytes()],
        ))
    }

    /// Strictly decodes canonical lockfile text.
    ///
    /// Every entry's identity is recomputed from its own fields, so an entry
    /// whose fields were edited no longer carries the identity it presents and
    /// is refused as tampered rather than accepted.
    pub fn parse(text: &str) -> Result<Self, WorkspaceError> {
        let mut lines = text.lines();
        let header = lines.next().unwrap_or_default();
        let version_text = header
            .strip_prefix("gantry-workspace-lockfile ")
            .ok_or_else(|| WorkspaceError::SourceRefused {
                detail: Arc::from(header),
            })?;
        let version: u32 = version_text
            .parse()
            .map_err(|_| WorkspaceError::SourceRefused {
                detail: Arc::from(version_text),
            })?;
        if version != Self::SUPPORTED_VERSION {
            return Err(WorkspaceError::LockfileVersionUnsupported { version });
        }
        let mut entries: Vec<ResolvedInstance> = Vec::new();
        for line in lines {
            if line.trim().is_empty() {
                continue;
            }
            let mut fields = line.split(' ');
            if fields.next() != Some("entry") {
                return Err(WorkspaceError::SourceRefused {
                    detail: Arc::from(line),
                });
            }
            let identity = ContentDigest::new(fields.next().unwrap_or_default())?;
            let name = PackageName::new(fields.next().unwrap_or_default()).map_err(|_| {
                WorkspaceError::SourceRefused {
                    detail: Arc::from(line),
                }
            })?;
            let version = PackageVersion::new(fields.next().unwrap_or_default()).map_err(|_| {
                WorkspaceError::SourceRefused {
                    detail: Arc::from(line),
                }
            })?;
            let features = parse_features(fields.next().unwrap_or_default())?;
            let targets = parse_targets(fields.next().unwrap_or_default())?;
            let dependencies = parse_dependencies(fields.next().unwrap_or_default())?;
            let interface_digest = ContentDigest::new(fields.next().unwrap_or_default())?;
            let generator_inputs = parse_generators(fields.next().unwrap_or_default())?;
            let source = DependencySource::parse(fields.next().unwrap_or_default())?;
            if fields.next().is_some() {
                return Err(WorkspaceError::SourceRefused {
                    detail: Arc::from(line),
                });
            }
            let names = dependency_names(&dependencies);
            let recomputed = derive_identity(
                &name,
                &version,
                &features,
                &targets,
                &names,
                &interface_digest,
                &generator_inputs,
                &source,
            );
            if recomputed != identity {
                return Err(WorkspaceError::LockfileTampered {
                    identity: Arc::from(identity.as_str()),
                });
            }
            entries.push(ResolvedInstance {
                identity,
                name,
                version,
                features,
                targets,
                dependencies,
                interface_digest,
                generator_inputs,
                source,
            });
        }
        entries.sort_by(|left, right| left.identity.as_str().cmp(right.identity.as_str()));
        Ok(Self { version, entries })
    }

    /// Verifies this lockfile against one resolution.
    ///
    /// A different entry set is a stale lockfile; an entry that disagrees with
    /// the resolved instance identity is a tampered or substituted binding.
    pub fn verify(&self, resolved: &ResolvedWorkspace) -> Result<(), WorkspaceError> {
        if self.entries.len() != resolved.len() {
            return Err(WorkspaceError::LockfileStale {
                locked: self.entries.len(),
                resolved: resolved.len(),
            });
        }
        for (locked, current) in self.entries.iter().zip(resolved.instances()) {
            if locked.identity != current.identity {
                return Err(WorkspaceError::LockfileTampered {
                    identity: Arc::from(locked.identity_hex()),
                });
            }
        }
        Ok(())
    }

    /// Verifies every bound generator input against the resolved releases.
    pub fn verify_releases(&self, releases: &[PackageRelease]) -> Result<(), WorkspaceError> {
        for entry in &self.entries {
            let matched = releases.iter().find(|release| {
                release.name() == entry.name()
                    && release.version() == entry.version()
                    && release.source() == entry.source()
            });
            let Some(release) = matched else {
                continue;
            };
            if release.generator_inputs() != entry.generator_inputs() {
                return Err(WorkspaceError::GeneratorInputMismatch {
                    package: entry.name().clone(),
                });
            }
        }
        Ok(())
    }
}

/// Returns one text field, spelling an empty collection as `-`.
fn empty_as_dash(value: &str) -> &str {
    if value.is_empty() { "-" } else { value }
}

/// Decodes one feature field.
fn parse_features(text: &str) -> Result<SelectedFeatureSet, WorkspaceError> {
    if text == "-" {
        return Ok(SelectedFeatureSet::empty());
    }
    let names: Vec<&str> = text.split('+').collect();
    SelectedFeatureSet::new(&names).map_err(|_| WorkspaceError::SourceRefused {
        detail: Arc::from(text),
    })
}

/// Decodes one target field.
fn parse_targets(text: &str) -> Result<TargetFactSet, WorkspaceError> {
    if text == "-" {
        return Ok(TargetFactSet::empty());
    }
    let mut facts: Vec<TargetFacts> = Vec::new();
    for token in text.split('+') {
        let (kind_text, path_text) = match token.split_once(':') {
            Some((kind, path)) => (kind, Some(path)),
            None => (token, None),
        };
        let kind =
            TargetKind::from_wire_name(kind_text).ok_or_else(|| WorkspaceError::SourceRefused {
                detail: Arc::from(token),
            })?;
        let entry = match path_text {
            Some(path) => Some(crate::CanonicalPath::new(path).map_err(|_| {
                WorkspaceError::SourceRefused {
                    detail: Arc::from(token),
                }
            })?),
            None => None,
        };
        facts.push(
            TargetFacts::new(kind, entry).map_err(|_| WorkspaceError::SourceRefused {
                detail: Arc::from(token),
            })?,
        );
    }
    Ok(TargetFactSet::new(&facts))
}

/// Decodes one dependency field.
fn parse_dependencies(text: &str) -> Result<Vec<PackageName>, WorkspaceError> {
    if text == "-" {
        return Ok(Vec::new());
    }
    let mut names: Vec<PackageName> = Vec::new();
    for token in text.split('+') {
        names.push(
            PackageName::new(token).map_err(|_| WorkspaceError::SourceRefused {
                detail: Arc::from(token),
            })?,
        );
    }
    Ok(names)
}

/// Decodes one generator-input field.
fn parse_generators(text: &str) -> Result<GeneratorInputs, WorkspaceError> {
    if text == "-" {
        return Ok(GeneratorInputs::empty());
    }
    let mut entries: Vec<GeneratorInput> = Vec::new();
    for token in text.split('+') {
        let mut fields = token.split(':');
        let role = fields.next().unwrap_or_default();
        let name = fields.next().unwrap_or_default();
        let digest = fields.next().unwrap_or_default();
        if fields.next().is_some() {
            return Err(WorkspaceError::SourceRefused {
                detail: Arc::from(token),
            });
        }
        let role = GeneratorInputRole::from_wire_name(role).ok_or_else(|| {
            WorkspaceError::SourceRefused {
                detail: Arc::from(token),
            }
        })?;
        entries.push(GeneratorInput::new(name, role, digest).map_err(|_| {
            WorkspaceError::SourceRefused {
                detail: Arc::from(token),
            }
        })?);
    }
    GeneratorInputs::new(&entries).map_err(|_| WorkspaceError::SourceRefused {
        detail: Arc::from(text),
    })
}

/// Verifies or explicitly updates one lockfile under one policy.
///
/// A resolution that already matches the lockfile is returned unchanged. A
/// differing resolution is refused when policy forbids an update, and an offline
/// policy additionally refuses any instance whose source needs acquisition.
pub fn sync_lockfile(
    lockfile: &WorkspaceLockfile,
    resolved: &ResolvedWorkspace,
    policy: &LockPolicy,
) -> Result<WorkspaceLockfile, WorkspaceError> {
    if lockfile.verify(resolved).is_ok() {
        return Ok(lockfile.clone());
    }
    if !policy.allow_update {
        return Err(WorkspaceError::LockfileRewriteRefused {
            locked: lockfile.entries().len(),
            resolved: resolved.len(),
        });
    }
    if policy.offline {
        for instance in resolved.instances() {
            if instance.source().requires_acquisition() {
                return Err(WorkspaceError::OfflineSourceUnavailable {
                    package: instance.name().clone(),
                });
            }
        }
    }
    Ok(WorkspaceLockfile::from_resolved(resolved))
}
