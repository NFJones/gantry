//! Declared `std.console` surface model for `SPEC.md` Section 46.
//!
//! This module publishes the canonical module and item rows of the `std.console` family and their
//! exact applicability. It is not a terminal, a descriptor, an adapter, a capability, or a
//! renderer, and it performs no I/O: every decision is a deterministic function of the declared
//! standard-library graph it is handed.

use crate::package::TargetKind;
use crate::stdlib::{
    NameClass, PackageFamily, StabilityTier, StdGraph, StdItem, StdPackage, StdlibDiagnosticCode,
    StdlibError,
};
use gantry_core::mode::SemanticMode;

/// The Section 46 clauses implemented by this pure model, in declaration order.
pub const CONSOLE_CLAUSES: [&str; 2] = [
    "GNT-46.0-console-foundation-scope",
    "GNT-46.1-console-modules-and-item-rows",
];

/// The declared semantic mode of every `std.console` item row.
pub const CONSOLE_SURFACE_MODES: [SemanticMode; 1] = [SemanticMode::Application];

/// The declared target kinds of every `std.console` item row.
pub const CONSOLE_SURFACE_TARGETS: [TargetKind; 2] = [TargetKind::Library, TargetKind::Binary];

/// One declared public module of `std.console` and the clauses that publish it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConsoleItemRow {
    /// The canonical logical item name.
    pub name: &'static str,
    /// The declared name classification of `GNT-34.2-name-classification`.
    pub class: NameClass,
    /// The declared stability tier of `GNT-34.6-stability-tiers`.
    pub tier: StabilityTier,
    /// The section clauses this item publishes, in specification order.
    pub clauses: &'static [&'static str],
}

/// The declared public modules of `std.console`, in canonical order.
///
/// The rows are declared by `GNT-46.1-console-modules-and-item-rows` alone; the family carries no
/// second vocabulary, no terminal handle, and no escape-sequence surface, and every row's
/// applicability is its owning package's application-mode applicability over the library and
/// binary targets.
pub const CONSOLE_ITEMS: [ConsoleItemRow; 4] = [
    ConsoleItemRow {
        name: "std.console::input",
        class: NameClass::Module,
        tier: StabilityTier::Stable,
        clauses: &[
            "GNT-46.0-console-foundation-scope",
            "GNT-46.1-console-modules-and-item-rows",
        ],
    },
    ConsoleItemRow {
        name: "std.console::output",
        class: NameClass::Module,
        tier: StabilityTier::Stable,
        clauses: &[
            "GNT-46.0-console-foundation-scope",
            "GNT-46.1-console-modules-and-item-rows",
        ],
    },
    ConsoleItemRow {
        name: "std.console::terminal",
        class: NameClass::Module,
        tier: StabilityTier::Stable,
        clauses: &[
            "GNT-46.0-console-foundation-scope",
            "GNT-46.1-console-modules-and-item-rows",
        ],
    },
    ConsoleItemRow {
        name: "std.console::control",
        class: NameClass::Module,
        tier: StabilityTier::Stable,
        clauses: &[
            "GNT-46.0-console-foundation-scope",
            "GNT-46.1-console-modules-and-item-rows",
        ],
    },
];

/// Declares the published item surface of `std.console` over one standard-library graph
/// (`GNT-34.6-stability-tiers`, `GNT-34.8-defining-identity-and-interface-digest`).
///
/// The owning package must already be declared, and each item takes that package's declared modes
/// and targets, so an item is never applicable outside its own package's applicability
/// (`GNT-34.7-applicability-and-feature-granularity`). A second declaration of one item is refused
/// by the graph rather than merged.
pub fn declare_console_surface(graph: &mut StdGraph) -> Result<(), StdlibError> {
    let owner = PackageFamily::Console.package_name();
    let (modes, targets, present) = {
        let package = graph.package(&owner).ok_or_else(|| {
            StdlibError::new(
                StdlibDiagnosticCode::UnknownEdge,
                format!("`{owner}` is not declared, so its item surface cannot be declared"),
            )
        })?;
        validate_console_surface_package(graph, package)?;
        (
            package.modes().iter().copied().collect::<Vec<_>>(),
            package.targets().iter().copied().collect::<Vec<_>>(),
            CONSOLE_ITEMS
                .iter()
                .filter(|row| package.item(row.name).is_some())
                .count(),
        )
    };
    if present == CONSOLE_ITEMS.len() {
        let row = CONSOLE_ITEMS[0];
        return graph.declare_item(StdItem::new(
            row.name, row.class, row.tier, &modes, &targets,
        )?);
    }
    for row in CONSOLE_ITEMS {
        graph.declare_item(StdItem::new(
            row.name, row.class, row.tier, &modes, &targets,
        )?)?;
    }
    Ok(())
}

/// Admits an already-declared `std.console` surface as exactly the four declared module rows.
///
/// The declared applicability must be exactly the application semantic mode over the library and
/// binary target kinds, no item outside the four declared rows may exist, and no row may be
/// missing; each violation is refused under its declared diagnostic rather than repaired.
pub fn admit_console_surface(graph: &StdGraph) -> Result<(), StdlibError> {
    let owner = PackageFamily::Console.package_name();
    let package = graph.package(&owner).ok_or_else(|| {
        StdlibError::new(
            StdlibDiagnosticCode::UnknownEdge,
            format!("`{owner}` is not declared, so its item surface cannot be admitted"),
        )
    })?;
    validate_console_surface_package(graph, package)?;
    if CONSOLE_ITEMS
        .iter()
        .any(|row| package.item(row.name).is_none())
    {
        return Err(StdlibError::new(
            StdlibDiagnosticCode::InvalidNameClassification,
            "the declared std.console item surface is incomplete".to_owned(),
        ));
    }
    Ok(())
}

/// Validates the declared applicability, the closed item set, and the surface's atomicity.
fn validate_console_surface_package(
    graph: &StdGraph,
    package: &StdPackage,
) -> Result<(), StdlibError> {
    if package.modes().iter().copied().ne(CONSOLE_SURFACE_MODES)
        || package
            .targets()
            .iter()
            .copied()
            .ne(CONSOLE_SURFACE_TARGETS)
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
            format!("`{owner}` declares a name outside its four declared modules"),
        ));
    }
    let present = CONSOLE_ITEMS
        .iter()
        .filter(|row| package.item(row.name).is_some())
        .count();
    if package.items().len() != present {
        return Err(StdlibError::new(
            StdlibDiagnosticCode::InvalidNameClassification,
            "a declared name outside the four std.console modules is refused".to_owned(),
        ));
    }
    if present != 0 && present != CONSOLE_ITEMS.len() {
        return Err(StdlibError::new(
            StdlibDiagnosticCode::InvalidNameClassification,
            "the std.console item surface is partially declared".to_owned(),
        ));
    }
    for row in CONSOLE_ITEMS {
        let Some(item) = package.item(row.name) else {
            continue;
        };
        if item.class() != row.class || item.tier() != row.tier {
            return Err(StdlibError::new(
                StdlibDiagnosticCode::InvalidNameClassification,
                format!("`{}` does not declare its row's class and tier", row.name),
            ));
        }
        if item.modes().iter().copied().ne(CONSOLE_SURFACE_MODES)
            || item.targets().iter().copied().ne(CONSOLE_SURFACE_TARGETS)
        {
            return Err(StdlibError::new(
                StdlibDiagnosticCode::UnsupportedApplicability,
                format!("`{}` does not declare its row's applicability", row.name),
            ));
        }
    }
    Ok(())
}
