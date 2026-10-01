//! Declared `std.env` surface model for `SPEC.md` Section 49.
//!
//! This module publishes only the canonical module rows and their applicability. It does not
//! read or mutate process state, grant environment or directory authority, or provide adapters.

use crate::package::TargetKind;
use crate::stdlib::{
    NameClass, PackageFamily, StabilityTier, StdGraph, StdItem, StdPackage, StdlibDiagnosticCode,
    StdlibError,
};
use gantry_core::mode::SemanticMode;

/// The Section 49 clauses implemented by this pure model, in declaration order.
pub const ENV_CLAUSES: [&str; 2] = [
    "GNT-49.0-environment-foundation-scope",
    "GNT-49.1-environment-modules-and-item-rows",
];

/// The declared semantic mode of every `std.env` item row.
pub const ENV_SURFACE_MODES: [SemanticMode; 1] = [SemanticMode::Application];

/// The declared target kinds of every `std.env` item row.
pub const ENV_SURFACE_TARGETS: [TargetKind; 2] = [TargetKind::Library, TargetKind::Binary];

/// One declared public module of `std.env` and the clauses that publish it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnvItemRow {
    /// The canonical logical item name.
    pub name: &'static str,
    /// The declared name classification of `GNT-34.2-name-classification`.
    pub class: NameClass,
    /// The declared stability tier of `GNT-34.6-stability-tiers`.
    pub tier: StabilityTier,
    /// The section clauses this item publishes, in specification order.
    pub clauses: &'static [&'static str],
}

/// The declared public modules of `std.env`, in canonical name order.
pub const ENV_ITEMS: [EnvItemRow; 3] = [
    EnvItemRow {
        name: "std.env::arguments",
        class: NameClass::Module,
        tier: StabilityTier::Stable,
        clauses: &[
            "GNT-49.0-environment-foundation-scope",
            "GNT-49.1-environment-modules-and-item-rows",
        ],
    },
    EnvItemRow {
        name: "std.env::environment",
        class: NameClass::Module,
        tier: StabilityTier::Stable,
        clauses: &[
            "GNT-49.0-environment-foundation-scope",
            "GNT-49.1-environment-modules-and-item-rows",
        ],
    },
    EnvItemRow {
        name: "std.env::working_directory",
        class: NameClass::Module,
        tier: StabilityTier::Stable,
        clauses: &[
            "GNT-49.0-environment-foundation-scope",
            "GNT-49.1-environment-modules-and-item-rows",
        ],
    },
];

/// Declares the canonical pure hierarchy plus the `std.env` declaration surface.
pub fn canonical_env_hierarchy() -> Result<StdGraph, StdlibError> {
    let mut graph = crate::stdlib::canonical_pure_hierarchy()?;
    declare_env_package(&mut graph)?;
    Ok(graph)
}

/// Adds the capability-backed `std.env` package and its closed module surface to a graph.
pub fn declare_env_package(graph: &mut StdGraph) -> Result<(), StdlibError> {
    graph.declare(StdPackage::new(
        PackageFamily::Env,
        NameClass::Package,
        StabilityTier::Stable,
        &ENV_SURFACE_MODES,
        &ENV_SURFACE_TARGETS,
        &[],
        &[],
    )?)?;
    declare_env_surface(graph)
}

/// Declares the published item surface of `std.env` over one standard-library graph.
pub fn declare_env_surface(graph: &mut StdGraph) -> Result<(), StdlibError> {
    let owner = PackageFamily::Env.package_name();
    let (modes, targets, present) = {
        let package = graph.package(&owner).ok_or_else(|| {
            StdlibError::new(
                StdlibDiagnosticCode::UnknownEdge,
                format!("`{owner}` is not declared, so its item surface cannot be declared"),
            )
        })?;
        validate_env_surface_package(graph, package)?;
        (
            package.modes().iter().copied().collect::<Vec<_>>(),
            package.targets().iter().copied().collect::<Vec<_>>(),
            ENV_ITEMS
                .iter()
                .filter(|row| package.item(row.name).is_some())
                .count(),
        )
    };
    if present == ENV_ITEMS.len() {
        let row = ENV_ITEMS[0];
        return graph.declare_item(StdItem::new(
            row.name, row.class, row.tier, &modes, &targets,
        )?);
    }
    for row in ENV_ITEMS {
        graph.declare_item(StdItem::new(
            row.name, row.class, row.tier, &modes, &targets,
        )?)?;
    }
    Ok(())
}

/// Admits an already-declared `std.env` surface as exactly its three module rows.
pub fn admit_env_surface(graph: &StdGraph) -> Result<(), StdlibError> {
    let owner = PackageFamily::Env.package_name();
    let package = graph.package(&owner).ok_or_else(|| {
        StdlibError::new(
            StdlibDiagnosticCode::UnknownEdge,
            format!("`{owner}` is not declared, so its item surface cannot be admitted"),
        )
    })?;
    validate_env_surface_package(graph, package)?;
    if ENV_ITEMS.iter().any(|row| package.item(row.name).is_none()) {
        return Err(StdlibError::new(
            StdlibDiagnosticCode::InvalidNameClassification,
            "the declared std.env item surface is incomplete".to_owned(),
        ));
    }
    Ok(())
}

/// Validates the declared applicability, the closed item set, and the surface's atomicity.
fn validate_env_surface_package(graph: &StdGraph, package: &StdPackage) -> Result<(), StdlibError> {
    if package.modes().iter().copied().ne(ENV_SURFACE_MODES)
        || package.targets().iter().copied().ne(ENV_SURFACE_TARGETS)
    {
        return Err(StdlibError::new(
            StdlibDiagnosticCode::UnsupportedApplicability,
            format!(
                "`{}` must declare exactly the application mode over the library and binary targets",
                package.name()
            ),
        ));
    }
    if package.exports().iter().any(|export| {
        !ENV_ITEMS
            .iter()
            .any(|row| export == &row.name.replace("::", "."))
    }) {
        return Err(StdlibError::new(
            StdlibDiagnosticCode::InvalidNameClassification,
            "a package export outside the three std.env modules is refused".to_owned(),
        ));
    }
    let owner = package.name();
    if graph.names().iter().any(|name| name.owner() == owner) {
        return Err(StdlibError::new(
            StdlibDiagnosticCode::InvalidNameClassification,
            format!("`{owner}` declares a name outside its three declared modules"),
        ));
    }
    let present = ENV_ITEMS
        .iter()
        .filter(|row| package.item(row.name).is_some())
        .count();
    if package.items().len() != present {
        return Err(StdlibError::new(
            StdlibDiagnosticCode::InvalidNameClassification,
            "a declared name outside the three std.env modules is refused".to_owned(),
        ));
    }
    if present != 0 && present != ENV_ITEMS.len() {
        return Err(StdlibError::new(
            StdlibDiagnosticCode::InvalidNameClassification,
            "the std.env item surface is partially declared".to_owned(),
        ));
    }
    for row in ENV_ITEMS {
        let Some(item) = package.item(row.name) else {
            continue;
        };
        if item.class() != row.class || item.tier() != row.tier {
            return Err(StdlibError::new(
                StdlibDiagnosticCode::InvalidNameClassification,
                format!("`{}` does not declare its row's class and tier", row.name),
            ));
        }
        if item.modes().iter().copied().ne(ENV_SURFACE_MODES)
            || item.targets().iter().copied().ne(ENV_SURFACE_TARGETS)
        {
            return Err(StdlibError::new(
                StdlibDiagnosticCode::UnsupportedApplicability,
                format!("`{}` does not declare its row's applicability", row.name),
            ));
        }
    }
    Ok(())
}
