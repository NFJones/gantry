//! Declared `std.observe` surface model for `SPEC.md` Section 48.
//!
//! This module publishes only the canonical module rows and their applicability. It is not a
//! telemetry sink, runtime event stream, protected-data release mechanism, adapter, or runtime
//! availability, and it performs no observation or I/O.

use crate::package::TargetKind;
use crate::stdlib::{
    NameClass, PackageFamily, StabilityTier, StdGraph, StdItem, StdPackage, StdlibDiagnosticCode,
    StdlibError,
};
use gantry_core::mode::SemanticMode;

/// The Section 48 clauses implemented by this pure model, in declaration order.
pub const OBSERVE_CLAUSES: [&str; 2] = [
    "GNT-48.0-observe-foundation-scope",
    "GNT-48.1-observe-modules-and-item-rows",
];

/// The declared semantic mode of every `std.observe` item row.
pub const OBSERVE_SURFACE_MODES: [SemanticMode; 1] = [SemanticMode::Application];

/// The declared target kinds of every `std.observe` item row.
pub const OBSERVE_SURFACE_TARGETS: [TargetKind; 2] = [TargetKind::Library, TargetKind::Binary];

/// One declared public module of `std.observe` and the clauses that publish it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObserveItemRow {
    /// The canonical logical item name.
    pub name: &'static str,
    /// The declared name classification of `GNT-34.2-name-classification`.
    pub class: NameClass,
    /// The declared stability tier of `GNT-34.6-stability-tiers`.
    pub tier: StabilityTier,
    /// The section clauses this item publishes, in specification order.
    pub clauses: &'static [&'static str],
}

/// The declared public modules of `std.observe`, in canonical name order.
pub const OBSERVE_ITEMS: [ObserveItemRow; 3] = [
    ObserveItemRow {
        name: "std.observe::log",
        class: NameClass::Module,
        tier: StabilityTier::Stable,
        clauses: &[
            "GNT-48.0-observe-foundation-scope",
            "GNT-48.1-observe-modules-and-item-rows",
        ],
    },
    ObserveItemRow {
        name: "std.observe::metric",
        class: NameClass::Module,
        tier: StabilityTier::Stable,
        clauses: &[
            "GNT-48.0-observe-foundation-scope",
            "GNT-48.1-observe-modules-and-item-rows",
        ],
    },
    ObserveItemRow {
        name: "std.observe::trace",
        class: NameClass::Module,
        tier: StabilityTier::Stable,
        clauses: &[
            "GNT-48.0-observe-foundation-scope",
            "GNT-48.1-observe-modules-and-item-rows",
        ],
    },
];

/// Declares the published item surface of `std.observe` over one standard-library graph.
pub fn declare_observe_surface(graph: &mut StdGraph) -> Result<(), StdlibError> {
    let owner = PackageFamily::Observe.package_name();
    let (modes, targets, present) = {
        let package = graph.package(&owner).ok_or_else(|| {
            StdlibError::new(
                StdlibDiagnosticCode::UnknownEdge,
                format!("`{owner}` is not declared, so its item surface cannot be declared"),
            )
        })?;
        validate_observe_surface_package(graph, package)?;
        (
            package.modes().iter().copied().collect::<Vec<_>>(),
            package.targets().iter().copied().collect::<Vec<_>>(),
            OBSERVE_ITEMS
                .iter()
                .filter(|row| package.item(row.name).is_some())
                .count(),
        )
    };
    if present == OBSERVE_ITEMS.len() {
        let row = OBSERVE_ITEMS[0];
        return graph.declare_item(StdItem::new(
            row.name, row.class, row.tier, &modes, &targets,
        )?);
    }
    for row in OBSERVE_ITEMS {
        graph.declare_item(StdItem::new(
            row.name, row.class, row.tier, &modes, &targets,
        )?)?;
    }
    Ok(())
}

/// Admits an already-declared `std.observe` surface as exactly its three module rows.
pub fn admit_observe_surface(graph: &StdGraph) -> Result<(), StdlibError> {
    let owner = PackageFamily::Observe.package_name();
    let package = graph.package(&owner).ok_or_else(|| {
        StdlibError::new(
            StdlibDiagnosticCode::UnknownEdge,
            format!("`{owner}` is not declared, so its item surface cannot be admitted"),
        )
    })?;
    validate_observe_surface_package(graph, package)?;
    if OBSERVE_ITEMS
        .iter()
        .any(|row| package.item(row.name).is_none())
    {
        return Err(StdlibError::new(
            StdlibDiagnosticCode::InvalidNameClassification,
            "the declared std.observe item surface is incomplete".to_owned(),
        ));
    }
    Ok(())
}

/// Validates the declared applicability, the closed item set, and the surface's atomicity.
fn validate_observe_surface_package(
    graph: &StdGraph,
    package: &StdPackage,
) -> Result<(), StdlibError> {
    if package.modes().iter().copied().ne(OBSERVE_SURFACE_MODES)
        || package
            .targets()
            .iter()
            .copied()
            .ne(OBSERVE_SURFACE_TARGETS)
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
    let present = OBSERVE_ITEMS
        .iter()
        .filter(|row| package.item(row.name).is_some())
        .count();
    if package.items().len() != present {
        return Err(StdlibError::new(
            StdlibDiagnosticCode::InvalidNameClassification,
            "a declared name outside the three std.observe modules is refused".to_owned(),
        ));
    }
    if present != 0 && present != OBSERVE_ITEMS.len() {
        return Err(StdlibError::new(
            StdlibDiagnosticCode::InvalidNameClassification,
            "the std.observe item surface is partially declared".to_owned(),
        ));
    }
    for row in OBSERVE_ITEMS {
        let Some(item) = package.item(row.name) else {
            continue;
        };
        if item.class() != row.class || item.tier() != row.tier {
            return Err(StdlibError::new(
                StdlibDiagnosticCode::InvalidNameClassification,
                format!("`{}` does not declare its row's class and tier", row.name),
            ));
        }
        if item.modes().iter().copied().ne(OBSERVE_SURFACE_MODES)
            || item.targets().iter().copied().ne(OBSERVE_SURFACE_TARGETS)
        {
            return Err(StdlibError::new(
                StdlibDiagnosticCode::UnsupportedApplicability,
                format!("`{}` does not declare its row's applicability", row.name),
            ));
        }
    }
    Ok(())
}
