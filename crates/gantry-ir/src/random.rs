//! Declared `std.random` module-name set for `SPEC.md` Section 50.
//!
//! This module publishes only the canonical module row of the capability-backed `std.random`
//! family, its classification, its tier, its application-only applicability over the library and
//! binary target kinds, the clauses that publish it, and the exported-item surface that declares
//! that row in the package graph. It is not a draw API, an entropy source,
//! a capability or authority grant, an adapter, or runtime availability, and it performs no I/O
//! and consumes no host entropy.

use crate::TargetKind;
use crate::stdlib::{
    DeclaredModuleRow, NameClass, PackageFamily, StabilityTier, StdGraph, StdItem, StdPackage,
    StdlibDiagnosticCode, StdlibError,
};
use gantry_core::mode::SemanticMode;

/// The clauses that declare the closed `std.random` module set, in specification order.
pub const RANDOM_MODULE_CLAUSES: [&str; 2] = [
    "GNT-50.0-random-foundation-scope",
    "GNT-50.1-random-modules-and-item-rows",
];

/// The declared semantic mode of the `std.random` module row of `GNT-50.1`.
pub const RANDOM_MODULE_MODES: [SemanticMode; 1] = [SemanticMode::Application];

/// The declared target kinds of the `std.random` module row of `GNT-50.1`.
pub const RANDOM_MODULE_TARGETS: [TargetKind; 2] = [TargetKind::Library, TargetKind::Binary];

/// The declared public module of `std.random` (`GNT-50.1`).
///
/// The row binds the scope clause and the naming clause, in specification order. It declares a
/// capability-backed namespace only: it publishes no draw operation, callable signature, request
/// or byte bound, failure mapping, settlement rule, capability or authority grant, or runtime
/// availability.
pub const RANDOM_MODULE_ROWS: [DeclaredModuleRow; 1] = [DeclaredModuleRow {
    name: "std.random::entropy",
    class: NameClass::Module,
    tier: StabilityTier::Stable,
    modes: &RANDOM_MODULE_MODES,
    targets: &RANDOM_MODULE_TARGETS,
    clauses: &[
        "GNT-50.0-random-foundation-scope",
        "GNT-50.1-random-modules-and-item-rows",
    ],
}];
/// The exported-item row of `std.random` of `GNT-34.6-stability-tiers` and
/// `GNT-34.8-defining-identity-and-interface-digest`, derived from the closed module set of
/// `GNT-50.1-random-modules-and-item-rows`.
///
/// The row is exactly the [`DeclaredModuleRow`] value the naming clause publishes, so the exported
/// item is never invented beside its owning clause: its name, classification, tier, applicability,
/// and clause list are the ones the reviewed clause set already fixes. It declares a
/// capability-backed namespace only and publishes no draw operation, callable signature, request
/// or byte bound, capability or authority grant, or runtime availability.
pub const RANDOM_ITEMS: [DeclaredModuleRow; 1] = RANDOM_MODULE_ROWS;

/// Declares the capability-backed `std.random` package and its closed item surface.
///
/// The package is application-only over the library and binary targets and carries no dependency
/// edge, so the family stays outside the pure dependency DAG of `GNT-34.3-acyclic-internal-
/// dependency-dag` as `GNT-50.0-random-foundation-scope` requires. Declaring the package adds no
/// draw operation, entropy source, capability grant, adapter, or runtime availability.
pub fn declare_random_package(graph: &mut StdGraph) -> Result<(), StdlibError> {
    graph.declare(StdPackage::new(
        PackageFamily::Random,
        NameClass::Package,
        StabilityTier::Stable,
        &RANDOM_MODULE_MODES,
        &RANDOM_MODULE_TARGETS,
        &[],
        &[],
    )?)?;
    declare_random_surface(graph)
}

/// Declares the published item surface of `std.random` over one standard-library graph
/// (`GNT-34.6-stability-tiers`, `GNT-34.8-defining-identity-and-interface-digest`).
///
/// The owning package must already be declared, and the item carries the application-only
/// applicability of its clause row. A package whose applicability, exports, names, item metadata,
/// or item set differs from the row is refused before any item is declared, and a second
/// declaration of the item is refused by the graph rather than merged.
pub fn declare_random_surface(graph: &mut StdGraph) -> Result<(), StdlibError> {
    let owner = PackageFamily::Random.package_name();
    let present = {
        let package = graph.package(&owner).ok_or_else(|| {
            StdlibError::new(
                StdlibDiagnosticCode::UnknownEdge,
                format!("`{owner}` is not declared, so its item surface cannot be declared"),
            )
        })?;
        crate::stdlib::validate_declared_surface(
            graph,
            package,
            &RANDOM_ITEMS,
            &RANDOM_MODULE_MODES,
            &RANDOM_MODULE_TARGETS,
        )?;
        RANDOM_ITEMS
            .iter()
            .filter(|row| package.item(row.name).is_some())
            .count()
    };
    if present == RANDOM_ITEMS.len() {
        let row = RANDOM_ITEMS[0];
        return graph.declare_item(StdItem::new(
            row.name,
            row.class,
            row.tier,
            row.modes,
            row.targets,
        )?);
    }
    for row in RANDOM_ITEMS {
        graph.declare_item(StdItem::new(
            row.name,
            row.class,
            row.tier,
            row.modes,
            row.targets,
        )?)?;
    }
    Ok(())
}

/// Admits an already-declared `std.random` surface as exactly its one module row.
pub fn admit_random_surface(graph: &StdGraph) -> Result<(), StdlibError> {
    let owner = PackageFamily::Random.package_name();
    let package = graph.package(&owner).ok_or_else(|| {
        StdlibError::new(
            StdlibDiagnosticCode::UnknownEdge,
            format!("`{owner}` is not declared, so its item surface cannot be admitted"),
        )
    })?;
    crate::stdlib::validate_declared_surface(
        graph,
        package,
        &RANDOM_ITEMS,
        &RANDOM_MODULE_MODES,
        &RANDOM_MODULE_TARGETS,
    )?;
    if RANDOM_ITEMS
        .iter()
        .any(|row| package.item(row.name).is_none())
    {
        return Err(StdlibError::new(
            StdlibDiagnosticCode::InvalidNameClassification,
            "the declared std.random item surface is incomplete".to_owned(),
        ));
    }
    Ok(())
}

/// Returns the canonical pure hierarchy with the capability-backed `std.random` package and its
/// published item surface declared (`GNT-34.6-stability-tiers`,
/// `GNT-34.8-defining-identity-and-interface-digest`).
///
/// The family owns this declaration, so `canonical_pure_hierarchy` keeps carrying the pure packages
/// only while this constructor adds the capability package and the clause-derived item row. The
/// added package declares no dependency edge, so it joins the graph without changing the pure
/// dependency order.
pub fn canonical_random_hierarchy() -> Result<StdGraph, StdlibError> {
    let mut graph = crate::stdlib::canonical_pure_hierarchy()?;
    declare_random_package(&mut graph)?;
    Ok(graph)
}
