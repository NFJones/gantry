//! Declared `std.fs` surface model for `SPEC.md` Section 47.
//!
//! This module publishes the canonical module and item rows of the `std.fs` family and their exact
//! applicability. It is not a path, a rooted directory, a descriptor, an adapter, a capability, or
//! a resource, and it performs no I/O: every decision is a deterministic function of the declared
//! standard-library graph it is handed.

use std::fmt;

use crate::generated::RecoveryClass;
use crate::package::TargetKind;
use crate::stdlib::{
    NameClass, PackageFamily, StabilityTier, StdGraph, StdItem, StdPackage, StdlibDiagnosticCode,
    StdlibError,
};
use gantry_core::mode::SemanticMode;

/// The Section 47 clauses implemented by this pure model, in declaration order.
pub const FS_CLAUSES: [&str; 4] = [
    "GNT-47.0-filesystem-foundation-scope",
    "GNT-47.1-filesystem-modules-and-item-rows",
    "GNT-47.2-filesystem-path-values",
    "GNT-47.3-filesystem-action-values",
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
/// The rows are declared by `GNT-47.1-filesystem-modules-and-item-rows` alone; the family carries no
/// second vocabulary, no path value, no descriptor, and no resource, and every row's applicability
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
        ],
    },
    FsItemRow {
        name: "std.fs::resource",
        class: NameClass::Module,
        tier: StabilityTier::Stable,
        clauses: &[
            "GNT-47.0-filesystem-foundation-scope",
            "GNT-47.1-filesystem-modules-and-item-rows",
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

/// Validates declared segments, offsetting reported positions by `base`.
fn validate_segments(segments: &[&str], base: u32) -> Result<(), FsError> {
    if segments.is_empty() {
        return Err(FsError::PathInvalid {
            detail: format!("the declared segment count 0 is outside 1..={FS_PATH_SEGMENT_BOUND}"),
            position: base,
        });
    }
    let total = base as usize + segments.len();
    if total > FS_PATH_SEGMENT_BOUND {
        return Err(FsError::PathInvalid {
            detail: format!(
                "the declared segment count {total} is outside 1..={FS_PATH_SEGMENT_BOUND}"
            ),
            position: base,
        });
    }
    for (offset, segment) in segments.iter().enumerate() {
        let position = base + offset as u32;
        if *segment == "." || *segment == ".." {
            return Err(FsError::PathEscape {
                component: if *segment == "." { "." } else { ".." },
                position,
            });
        }
        if segment.is_empty() {
            return Err(FsError::PathInvalid {
                detail: "an empty declared segment".to_owned(),
                position,
            });
        }
        if segment.contains('/') || segment.contains('\\') {
            return Err(FsError::PathInvalid {
                detail: format!("the declared segment `{segment}` carries a separator"),
                position,
            });
        }
        if segment.chars().any(char::is_control) {
            return Err(FsError::PathInvalid {
                detail: format!("the declared segment `{segment}` carries a control scalar"),
                position,
            });
        }
    }
    Ok(())
}

/// One declared whole-object filesystem action of `GNT-47.3-filesystem-action-values`.
///
/// Each action consumes one path value of `GNT-47.2-filesystem-path-values` and no ambient
/// location, and each states exactly one recovery class of the action-declaration rule: a read is
/// `idempotent`, while a create, a replace, and a remove are `non_idempotent`.
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
            Self::Read => RecoveryClass::Idempotent,
            Self::Create | Self::Replace | Self::Remove => RecoveryClass::NonIdempotent,
        }
    }
}
