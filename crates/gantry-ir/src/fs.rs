//! Declared `std.fs` surface model for `SPEC.md` Section 47.
//!
//! This module publishes the canonical module and item rows of the `std.fs` family and their exact
//! applicability. It is not a path, a rooted directory, a descriptor, an adapter, a capability, or
//! a resource, and it performs no I/O: every decision is a deterministic function of the declared
//! standard-library graph it is handed.

use crate::package::TargetKind;
use crate::stdlib::{
    NameClass, PackageFamily, StabilityTier, StdGraph, StdItem, StdPackage, StdlibDiagnosticCode,
    StdlibError,
};
use gantry_core::mode::SemanticMode;

/// The Section 47 clauses implemented by this pure model, in declaration order.
pub const FS_CLAUSES: [&str; 2] = [
    "GNT-47.0-filesystem-foundation-scope",
    "GNT-47.1-filesystem-modules-and-item-rows",
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
        ],
    },
    FsItemRow {
        name: "std.fs::path",
        class: NameClass::Module,
        tier: StabilityTier::Stable,
        clauses: &[
            "GNT-47.0-filesystem-foundation-scope",
            "GNT-47.1-filesystem-modules-and-item-rows",
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
