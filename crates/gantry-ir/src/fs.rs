//! Declared `std.fs` surface model for `SPEC.md` Section 47.
//!
//! This module publishes the canonical module and item rows of the `std.fs` family and their
//! applicability, the path value contract of `std.fs::path`, the whole-object action vocabulary of
//! `std.fs::action`, and the resource operation vocabulary of `std.fs::resource` with its
//! consumption of the common I/O contract and its content-mutation fact, the read-only grant
//! refusal over both vocabularies, the declared instance state vocabulary, and the declared
//! canonical traversal order of entry names, the declared link policy of a resolved entry, and the
//! declared refusal conditions of an action and a resource operation. It is not a descriptor, an
//! open handle, a live resource instance, an adapter, a capability, or a runtime availability, and
//! it performs no I/O: every decision it publishes is a deterministic function of its declared
//! arguments alone.

use std::fmt;

use crate::generated::RecoveryClass;
use crate::io::IoOperation;
use crate::package::TargetKind;
use crate::resource::ResourceCarrier;
use crate::stdlib::{
    NameClass, PackageFamily, StabilityTier, StdGraph, StdItem, StdPackage, StdlibDiagnosticCode,
    StdlibError,
};
use gantry_core::mode::SemanticMode;

/// The Section 47 clauses implemented by this pure model, in declaration order.
pub const FS_CLAUSES: [&str; 15] = [
    "GNT-47.0-filesystem-foundation-scope",
    "GNT-47.1-filesystem-modules-and-item-rows",
    "GNT-47.2-filesystem-path-values",
    "GNT-47.3-filesystem-action-values",
    "GNT-47.4-filesystem-resource-operations",
    "GNT-47.5-filesystem-resource-state",
    "GNT-47.6-filesystem-traversal",
    "GNT-47.7-filesystem-action-grants",
    "GNT-47.8-filesystem-link-policy",
    "GNT-47.9-filesystem-replacement",
    "GNT-47.10-filesystem-declared-limits",
    "GNT-47.11-filesystem-case-identity",
    "GNT-47.12-filesystem-operation-refusals",
    "GNT-47.13-filesystem-partial-progress-and-settlement",
    "GNT-47.14-filesystem-durable-carriers",
];

/// The declared semantic mode of every `std.fs` item row.
pub const FS_SURFACE_MODES: [SemanticMode; 1] = [SemanticMode::Application];

/// The declared target kinds of every `std.fs` item row.
pub const FS_SURFACE_TARGETS: [TargetKind; 2] = [TargetKind::Library, TargetKind::Binary];

/// One declared public module of `std.fs` and the clauses that publish it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FsItemRow {
    /// The canonical logical item name.
    pub name: &'static str,
    /// The declared name classification of `GNT-34.2-name-classification`.
    pub class: NameClass,
    /// The declared stability tier of `GNT-34.6-stability-tiers`.
    pub tier: StabilityTier,
    /// The section clauses this item publishes, in specification order.
    pub clauses: &'static [&'static str],
}

/// The declared public modules of `std.fs`, in canonical name order.
///
/// The rows are declared by `GNT-47.1-filesystem-modules-and-item-rows`, and each row lists the
/// clauses that publish its own contract, in specification order; the family carries no second
/// vocabulary, no path value, no descriptor, and no live resource, and every row's applicability
/// is its owning package's application-mode applicability over the library and binary targets.
pub const FS_ITEMS: [FsItemRow; 3] = [
    FsItemRow {
        name: "std.fs::action",
        class: NameClass::Module,
        tier: StabilityTier::Stable,
        clauses: &[
            "GNT-47.0-filesystem-foundation-scope",
            "GNT-47.1-filesystem-modules-and-item-rows",
            "GNT-47.3-filesystem-action-values",
            "GNT-47.7-filesystem-action-grants",
            "GNT-47.8-filesystem-link-policy",
            "GNT-47.9-filesystem-replacement",
            "GNT-47.10-filesystem-declared-limits",
            "GNT-47.12-filesystem-operation-refusals",
            "GNT-47.13-filesystem-partial-progress-and-settlement",
        ],
    },
    FsItemRow {
        name: "std.fs::path",
        class: NameClass::Module,
        tier: StabilityTier::Stable,
        clauses: &[
            "GNT-47.0-filesystem-foundation-scope",
            "GNT-47.1-filesystem-modules-and-item-rows",
            "GNT-47.2-filesystem-path-values",
            "GNT-47.6-filesystem-traversal",
            "GNT-47.10-filesystem-declared-limits",
            "GNT-47.11-filesystem-case-identity",
        ],
    },
    FsItemRow {
        name: "std.fs::resource",
        class: NameClass::Module,
        tier: StabilityTier::Stable,
        clauses: &[
            "GNT-47.0-filesystem-foundation-scope",
            "GNT-47.1-filesystem-modules-and-item-rows",
            "GNT-47.4-filesystem-resource-operations",
            "GNT-47.5-filesystem-resource-state",
            "GNT-47.8-filesystem-link-policy",
            "GNT-47.10-filesystem-declared-limits",
            "GNT-47.12-filesystem-operation-refusals",
            "GNT-47.13-filesystem-partial-progress-and-settlement",
            "GNT-47.14-filesystem-durable-carriers",
        ],
    },
];

/// Declares the published item surface of `std.fs` over one standard-library graph
/// (`GNT-34.6-stability-tiers`, `GNT-34.8-defining-identity-and-interface-digest`).
///
/// The owning package must already be declared, and each item takes that package's declared modes
/// and targets, so an item is never applicable outside its own package's applicability
/// (`GNT-34.7-applicability-and-feature-granularity`). A second declaration of one item is refused
/// by the graph rather than merged.
pub fn declare_fs_surface(graph: &mut StdGraph) -> Result<(), StdlibError> {
    let owner = PackageFamily::Fs.package_name();
    let (modes, targets, present) = {
        let package = graph.package(&owner).ok_or_else(|| {
            StdlibError::new(
                StdlibDiagnosticCode::UnknownEdge,
                format!("`{owner}` is not declared, so its item surface cannot be declared"),
            )
        })?;
        validate_fs_surface_package(graph, package)?;
        (
            package.modes().iter().copied().collect::<Vec<_>>(),
            package.targets().iter().copied().collect::<Vec<_>>(),
            FS_ITEMS
                .iter()
                .filter(|row| package.item(row.name).is_some())
                .count(),
        )
    };
    if present == FS_ITEMS.len() {
        let row = FS_ITEMS[0];
        return graph.declare_item(StdItem::new(
            row.name, row.class, row.tier, &modes, &targets,
        )?);
    }
    for row in FS_ITEMS {
        graph.declare_item(StdItem::new(
            row.name, row.class, row.tier, &modes, &targets,
        )?)?;
    }
    Ok(())
}

/// Admits an already-declared `std.fs` surface as exactly the three declared module rows.
///
/// The declared applicability must be exactly the application semantic mode over the library and
/// binary target kinds, no item outside the three declared rows may exist, and no row may be
/// missing; each violation is refused under its declared diagnostic rather than repaired.
pub fn admit_fs_surface(graph: &StdGraph) -> Result<(), StdlibError> {
    let owner = PackageFamily::Fs.package_name();
    let package = graph.package(&owner).ok_or_else(|| {
        StdlibError::new(
            StdlibDiagnosticCode::UnknownEdge,
            format!("`{owner}` is not declared, so its item surface cannot be admitted"),
        )
    })?;
    validate_fs_surface_package(graph, package)?;
    if FS_ITEMS.iter().any(|row| package.item(row.name).is_none()) {
        return Err(StdlibError::new(
            StdlibDiagnosticCode::InvalidNameClassification,
            "the declared std.fs item surface is incomplete".to_owned(),
        ));
    }
    Ok(())
}

/// Validates the declared applicability, the closed item set, and the surface's atomicity.
fn validate_fs_surface_package(graph: &StdGraph, package: &StdPackage) -> Result<(), StdlibError> {
    if package.modes().iter().copied().ne(FS_SURFACE_MODES)
        || package.targets().iter().copied().ne(FS_SURFACE_TARGETS)
    {
        return Err(StdlibError::new(
            StdlibDiagnosticCode::UnsupportedApplicability,
            format!(
                "`{}` must declare exactly the application mode over the library and binary targets",
                package.name()
            ),
        ));
    }
    let owner = package.name();
    if graph.names().iter().any(|name| name.owner() == owner) {
        return Err(StdlibError::new(
            StdlibDiagnosticCode::InvalidNameClassification,
            format!("`{owner}` declares a name outside its three declared modules"),
        ));
    }
    let present = FS_ITEMS
        .iter()
        .filter(|row| package.item(row.name).is_some())
        .count();
    if package.items().len() != present {
        return Err(StdlibError::new(
            StdlibDiagnosticCode::InvalidNameClassification,
            "a declared name outside the three std.fs modules is refused".to_owned(),
        ));
    }
    if present != 0 && present != FS_ITEMS.len() {
        return Err(StdlibError::new(
            StdlibDiagnosticCode::InvalidNameClassification,
            "the std.fs item surface is partially declared".to_owned(),
        ));
    }
    for row in FS_ITEMS {
        let Some(item) = package.item(row.name) else {
            continue;
        };
        if item.class() != row.class || item.tier() != row.tier {
            return Err(StdlibError::new(
                StdlibDiagnosticCode::InvalidNameClassification,
                format!("`{}` does not declare its row's class and tier", row.name),
            ));
        }
        if item.modes().iter().copied().ne(FS_SURFACE_MODES)
            || item.targets().iter().copied().ne(FS_SURFACE_TARGETS)
        {
            return Err(StdlibError::new(
                StdlibDiagnosticCode::UnsupportedApplicability,
                format!("`{}` does not declare its row's applicability", row.name),
            ));
        }
    }
    Ok(())
}

/// The largest segment count one declared `std.fs` path value may carry.
pub const FS_PATH_SEGMENT_BOUND: usize = 256;

/// The declared number of resolutions one operation of this section performs for its path value.
pub const FS_RESOLUTION_COUNT: u32 = 1;

/// One declared condition under which an operation of this section is refused
/// (`GNT-47.12-filesystem-operation-refusals`).
///
/// A refusal condition publishes no diagnostic spelling and no code of `FsDiagnosticCode`: the
/// frozen registry of `GNT-47.0-filesystem-foundation-scope` keeps its two codes, both owned by
/// `GNT-47.2-filesystem-path-values`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum FsRefusalCondition {
    /// The declared target state does not admit the operation's declared effect.
    TargetStateUnadmitted,
    /// The target reports a collision under its own case behaviour.
    FoldingTargetCollision,
}

/// Every declared refusal condition, in declaration order.
pub const FS_REFUSAL_CONDITIONS: [FsRefusalCondition; 2] = [
    FsRefusalCondition::TargetStateUnadmitted,
    FsRefusalCondition::FoldingTargetCollision,
];

/// The declared target state of the object a path value of `GNT-47.2-filesystem-path-values` names.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum FsTargetState {
    /// No object is named by the declared path value.
    Absent,
    /// One object is named by the declared path value.
    Present,
}

/// The declared refusal conditions of an operation that resolves the declared path value of its
/// caller: each whole-object action and the `open` resource operation.
const PATH_RESOLVING_REFUSAL_CONDITIONS: [FsRefusalCondition; 2] = [
    FsRefusalCondition::TargetStateUnadmitted,
    FsRefusalCondition::FoldingTargetCollision,
];

/// One declared filesystem refusal condition of `GNT-47.2-filesystem-path-values`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum FsDiagnosticCode {
    /// A reserved component was presented instead of a plain segment.
    PathEscape,
    /// A declared segment, root, or count lies outside its declared range.
    PathInvalid,
}

impl FsDiagnosticCode {
    /// Every declared code, in exact wire-name order.
    pub const ALL: [Self; 2] = [Self::PathEscape, Self::PathInvalid];

    /// Returns the registered diagnostic spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PathEscape => "fs-path-escape",
            Self::PathInvalid => "fs-path-invalid",
        }
    }
}

/// One typed refusal from the filesystem path value model.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FsError {
    /// A reserved component was presented instead of a plain segment.
    PathEscape {
        /// The reserved component exactly as presented.
        component: &'static str,
        /// The zero-based position of the segment that carried it.
        position: u32,
    },
    /// A declared segment, root, or count lies outside its declared range.
    PathInvalid {
        /// The declared fact exactly as presented.
        detail: String,
        /// The zero-based position of the offending segment, or zero for a root or count.
        position: u32,
    },
}

impl FsError {
    /// Returns the registered diagnostic code of this refusal.
    #[must_use]
    pub const fn code(&self) -> FsDiagnosticCode {
        match self {
            Self::PathEscape { .. } => FsDiagnosticCode::PathEscape,
            Self::PathInvalid { .. } => FsDiagnosticCode::PathInvalid,
        }
    }

    /// Returns the position of the segment this refusal names.
    #[must_use]
    pub const fn position(&self) -> u32 {
        match self {
            Self::PathEscape { position, .. } | Self::PathInvalid { position, .. } => *position,
        }
    }

    /// Returns the reserved component, when this refusal names one.
    #[must_use]
    pub const fn component(&self) -> Option<&'static str> {
        match self {
            Self::PathEscape { component, .. } => Some(*component),
            Self::PathInvalid { .. } => None,
        }
    }

    /// Returns the declared fact this refusal names.
    #[must_use]
    pub fn detail(&self) -> &str {
        match self {
            Self::PathEscape { component, .. } => component,
            Self::PathInvalid { detail, .. } => detail,
        }
    }
}

impl fmt::Display for FsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PathEscape {
                component,
                position,
            } => write!(
                formatter,
                "the reserved component `{component}` at position {position} is refused"
            ),
            Self::PathInvalid { detail, position } => write!(
                formatter,
                "the declared path fact `{detail}` at position {position} is outside its declared range"
            ),
        }
    }
}

impl std::error::Error for FsError {}

/// One admitted `std.fs` path value of `GNT-47.2-filesystem-path-values`: a declared root and its
/// ordered segments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FsPath {
    root: String,
    segments: Vec<String>,
}

impl FsPath {
    /// Admits one path value of a declared root and its declared segments.
    ///
    /// A root that is empty, carries a separator, or carries a home or environment marker is
    /// refused under `fs-path-invalid`, and a segment outside the declared rules is refused under
    /// `fs-path-invalid` or `fs-path-escape` rather than normalized, dropped, or resolved.
    pub fn rooted(root: &str, segments: &[&str]) -> Result<Self, FsError> {
        validate_root(root)?;
        validate_segments(segments, 0)?;
        Ok(Self {
            root: root.to_owned(),
            segments: segments
                .iter()
                .map(|segment| (*segment).to_owned())
                .collect(),
        })
    }

    /// Extends one admitted path value with declared segments, refusing rather than rewriting.
    pub fn join(&self, segments: &[&str]) -> Result<Self, FsError> {
        validate_segments(segments, self.segments.len() as u32)?;
        let mut joined = self.segments.clone();
        joined.extend(segments.iter().map(|segment| (*segment).to_owned()));
        Ok(Self {
            root: self.root.clone(),
            segments: joined,
        })
    }

    /// Returns the declared root.
    #[must_use]
    pub fn root(&self) -> &str {
        &self.root
    }

    /// Returns the declared segments, in declared order.
    #[must_use]
    pub fn segments(&self) -> &[String] {
        &self.segments
    }

    /// Returns the canonical spelling of the declared root and segments.
    #[must_use]
    pub fn canonical_spelling(&self) -> String {
        let mut spelling = self.root.clone();
        for segment in &self.segments {
            spelling.push('/');
            spelling.push_str(segment);
        }
        spelling
    }
}

/// Validates one declared root under the rules of `GNT-47.2-filesystem-path-values`.
///
/// A root is a portable name: ASCII lower-case letters, digits, and `_`, whose first scalar is a
/// lower-case letter. An empty root, a root carrying a separator, and a root carrying a home or
/// environment marker are all refused by that one predicate rather than by a second rule.
fn validate_root(root: &str) -> Result<(), FsError> {
    let mut scalars = root.chars();
    let portable = match scalars.next() {
        Some(first) if first.is_ascii_lowercase() => scalars
            .all(|scalar| scalar.is_ascii_lowercase() || scalar.is_ascii_digit() || scalar == '_'),
        _ => false,
    };
    if !portable {
        return Err(FsError::PathInvalid {
            detail: format!("the declared root `{root}` is not a portable name"),
            position: 0,
        });
    }
    Ok(())
}

/// Validates declared segments of `GNT-47.2-filesystem-path-values`.
///
/// A refused segment names its position within the declared value, offset by `base`; a refusal the
/// declared count produced names zero rather than a segment position, whatever the offset.
fn validate_segments(segments: &[&str], base: u32) -> Result<(), FsError> {
    if segments.is_empty() {
        return Err(FsError::PathInvalid {
            detail: format!("the declared segment count 0 is outside 1..={FS_PATH_SEGMENT_BOUND}"),
            position: 0,
        });
    }
    let total = base as usize + segments.len();
    if total > FS_PATH_SEGMENT_BOUND {
        return Err(FsError::PathInvalid {
            detail: format!(
                "the declared segment count {total} is outside 1..={FS_PATH_SEGMENT_BOUND}"
            ),
            position: 0,
        });
    }
    for (offset, segment) in segments.iter().enumerate() {
        validate_portable_name(segment, base + offset as u32)?;
    }
    Ok(())
}

/// Validates one declared name against the declared segment domain of
/// `GNT-47.2-filesystem-path-values`, naming `position` in a refusal.
///
/// The name domain carries no count rule: a path value bounds its own segment sequence, while a
/// traversal publishes one name per entry and declares no bound on the number of entries.
fn validate_portable_name(name: &str, position: u32) -> Result<(), FsError> {
    if name == "." || name == ".." {
        return Err(FsError::PathEscape {
            component: if name == "." { "." } else { ".." },
            position,
        });
    }
    if name.is_empty() {
        return Err(FsError::PathInvalid {
            detail: "an empty declared segment".to_owned(),
            position,
        });
    }
    if name.contains('/') || name.contains('\\') {
        return Err(FsError::PathInvalid {
            detail: format!("the declared segment `{name}` carries a separator"),
            position,
        });
    }
    if name.chars().any(char::is_control) {
        return Err(FsError::PathInvalid {
            detail: format!("the declared segment `{name}` carries a control scalar"),
            position,
        });
    }
    Ok(())
}

/// One declared whole-object filesystem action of `GNT-47.3-filesystem-action-values`.
///
/// Each action consumes one path value of `GNT-47.2-filesystem-path-values` and no ambient
/// location, and each states exactly one recovery class of the action-declaration rule: a read is
/// `read_only`, while a create, a replace, and a remove are `non_idempotent`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum FsAction {
    /// Creates one object at a declared path.
    Create,
    /// Reads one object at a declared path.
    Read,
    /// Replaces one object at a declared path.
    Replace,
    /// Removes one object at a declared path.
    Remove,
}

impl FsAction {
    /// Every declared action, in canonical order.
    pub const ALL: [Self; 4] = [Self::Create, Self::Read, Self::Replace, Self::Remove];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Read => "read",
            Self::Replace => "replace",
            Self::Remove => "remove",
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
            .find(|action| action.wire_name() == value)
    }

    /// Returns the declared recovery class of this action.
    #[must_use]
    pub const fn declared_recovery_class(self) -> RecoveryClass {
        match self {
            Self::Read => RecoveryClass::ReadOnly,
            Self::Create | Self::Replace | Self::Remove => RecoveryClass::NonIdempotent,
        }
    }

    /// Returns whether this action declares an externally visible mutation of the object's content.
    ///
    /// Exactly a create, a replace, and a remove declare one, so a read-only grant refuses exactly
    /// those three; a read declares none, and a grant's read-only status never changes the fact.
    #[must_use]
    pub const fn declares_content_mutation(self) -> bool {
        matches!(self, Self::Create | Self::Replace | Self::Remove)
    }

    /// Returns the declared target state this action does not admit.
    ///
    /// A `create` names a present target state, because an object that is already named does not
    /// admit creation, while a `read`, a `replace`, and a `remove` name an absent one, because no
    /// object is named for that action to publish, replace, or remove.
    #[must_use]
    pub const fn unadmitted_target_state(self) -> Option<FsTargetState> {
        match self {
            Self::Create => Some(FsTargetState::Present),
            Self::Read | Self::Replace | Self::Remove => Some(FsTargetState::Absent),
        }
    }

    /// Returns the declared refusal conditions of this action, in declaration order.
    #[must_use]
    pub const fn refusal_conditions(self) -> &'static [FsRefusalCondition] {
        &PATH_RESOLVING_REFUSAL_CONDITIONS
    }
}

/// The declared replacement action of `GNT-47.9-filesystem-replacement`.
pub const FS_REPLACEMENT_ACTION: FsAction = FsAction::Replace;

/// One declared outcome of the replacement contract of `GNT-47.9-filesystem-replacement`.
///
/// The vocabulary has exactly one member and publishes no spelling of it: the outcome is a
/// declaration-layer name rather than a wire spelling, an event name, or a diagnostic.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum FsReplacementOutcome {
    /// The complete declared object replaced the complete named object.
    Replaced,
}

/// Every declared replacement outcome of `GNT-47.9-filesystem-replacement`, in declaration order.
pub const FS_REPLACEMENT_OUTCOMES: [FsReplacementOutcome; 1] = [FsReplacementOutcome::Replaced];

/// One declared resource operation of `GNT-47.4-filesystem-resource-operations`.
///
/// Each operation names one path value of `GNT-47.2-filesystem-path-values` and the grant the
/// caller presents. A read, a write, and a seek each consume exactly one admitted request of the
/// common I/O contract of `GNT-45.1-bounded-one-call-io-contract`; no other operation consumes a
/// request, declares an octet quantity, or publishes a progress observation here. The declared
/// order is the clause's declared resource-operation order, not wire-name order, and it publishes
/// no sequencing or precedence rule between two operations.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum FsResourceOperation {
    /// The declared `open` operation.
    Open,
    /// The declared `read` operation.
    Read,
    /// The declared `write` operation.
    Write,
    /// The declared `seek` operation.
    Seek,
    /// The declared `flush` operation.
    Flush,
    /// The declared `sync` operation.
    Sync,
    /// The declared `truncate` operation.
    Truncate,
    /// The declared `close` operation.
    Close,
    /// The declared `lock` operation.
    Lock,
    /// The declared `watch` operation.
    Watch,
}

impl FsResourceOperation {
    /// Every declared resource operation, in canonical order.
    pub const ALL: [Self; 10] = [
        Self::Open,
        Self::Read,
        Self::Write,
        Self::Seek,
        Self::Flush,
        Self::Sync,
        Self::Truncate,
        Self::Close,
        Self::Lock,
        Self::Watch,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Read => "read",
            Self::Write => "write",
            Self::Seek => "seek",
            Self::Flush => "flush",
            Self::Sync => "sync",
            Self::Truncate => "truncate",
            Self::Close => "close",
            Self::Lock => "lock",
            Self::Watch => "watch",
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
            .find(|operation| operation.wire_name() == value)
    }

    /// Returns the declared `std.io` request kind this operation consumes, if any.
    ///
    /// A read consumes one read request, a write consumes one write request, and a seek consumes
    /// one seek request; no other declared operation consumes a request in this clause.
    #[must_use]
    pub const fn declared_request_kind(self) -> Option<IoOperation> {
        match self {
            Self::Read => Some(IoOperation::Read),
            Self::Write => Some(IoOperation::Write),
            Self::Seek => Some(IoOperation::Seek),
            Self::Open
            | Self::Flush
            | Self::Sync
            | Self::Truncate
            | Self::Close
            | Self::Lock
            | Self::Watch => None,
        }
    }

    /// Returns whether this operation declares an externally visible mutation of the object's
    /// content.
    ///
    /// Exactly a write and a truncate declare one, so a read-only grant refuses exactly those two;
    /// every other declared operation declares no content mutation, and a grant's read-only status
    /// never changes that fact.
    #[must_use]
    pub const fn declares_content_mutation(self) -> bool {
        matches!(self, Self::Write | Self::Truncate)
    }

    /// Returns whether this operation declares a partial-progress observation.
    ///
    /// Exactly a read, a write, and a seek declare one: no other declared operation publishes a
    /// partial-progress observation, and no operation publishes a second one.
    #[must_use]
    pub const fn declares_partial_progress(self) -> bool {
        matches!(self, Self::Read | Self::Write | Self::Seek)
    }

    /// Returns the declared target state this operation does not admit, if any.
    ///
    /// Only `open` names one: it is refused when the declared target state is absent. The nine
    /// operations that apply to one admitted instance of `GNT-47.5-filesystem-resource-state`
    /// declare no condition of `GNT-47.12-filesystem-operation-refusals`.
    #[must_use]
    pub const fn unadmitted_target_state(self) -> Option<FsTargetState> {
        match self {
            Self::Open => Some(FsTargetState::Absent),
            Self::Read
            | Self::Write
            | Self::Seek
            | Self::Flush
            | Self::Sync
            | Self::Truncate
            | Self::Close
            | Self::Lock
            | Self::Watch => None,
        }
    }

    /// Returns the declared refusal conditions of this operation, in declaration order.
    #[must_use]
    pub const fn refusal_conditions(self) -> &'static [FsRefusalCondition] {
        match self {
            Self::Open => &PATH_RESOLVING_REFUSAL_CONDITIONS,
            Self::Read
            | Self::Write
            | Self::Seek
            | Self::Flush
            | Self::Sync
            | Self::Truncate
            | Self::Close
            | Self::Lock
            | Self::Watch => &[],
        }
    }
}

/// The declared partial-progress operations of
/// `GNT-47.13-filesystem-partial-progress-and-settlement`, in declared order.
///
/// Each one consumes exactly one admitted request of `GNT-45.1-bounded-one-call-io-contract` and
/// publishes exactly one progress observation; no other declared operation publishes one.
pub const FS_PARTIAL_PROGRESS_OPERATIONS: [FsResourceOperation; 3] = [
    FsResourceOperation::Read,
    FsResourceOperation::Write,
    FsResourceOperation::Seek,
];

/// The one durable carrier admissible for an admitted instance of this section
/// (`GNT-47.14-filesystem-durable-carriers`): the declared durable reconstruction record.
pub const FS_DURABLE_CARRIER: ResourceCarrier = ResourceCarrier::ReconstructionRecord;

/// Returns whether `carrier` may carry the declared facts of an admitted instance of this section.
///
/// Exactly the declared durable reconstruction record of
/// `GNT-28.7-durable-resource-reconstruction` is admissible; ordinary serialization and ordinary
/// durable state carry no reconstruction contract and are refused rather than decoded or repaired.
#[must_use]
pub const fn fs_durable_carrier_is_admissible(carrier: ResourceCarrier) -> bool {
    matches!(carrier, ResourceCarrier::ReconstructionRecord)
}

/// Returns the declared canonical traversal order of `names`.
///
/// The order is ascending by Unicode scalar value over each declared name and is never a host
/// directory order, and every name is checked against the declared segment domain of
/// `GNT-47.2-filesystem-path-values` before it is published. The traversal carries no bound on the
/// number of entries.
///
/// # Errors
///
/// Returns the path diagnostic of the first entry whose name is outside the declared segment
/// domain, positioned at that entry's zero-based ordinal within the traversal.
pub fn fs_traversal_order(names: &[&str]) -> Result<Vec<String>, FsError> {
    let mut ordered = Vec::with_capacity(names.len());
    for (position, name) in names.iter().enumerate() {
        validate_portable_name(name, position as u32)?;
        ordered.push((*name).to_owned());
    }
    ordered.sort_unstable();
    Ok(ordered)
}
