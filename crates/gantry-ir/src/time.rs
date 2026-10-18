//! Declared `std.time` module-name set for `SPEC.md` Section 51.
//!
//! This module publishes the six canonical module rows of the capability-backed `std.time`
//! family, their classification, tier, application-only applicability over the library and
//! binary target kinds, the clauses that publish them, and the declare and admit surfaces that
//! refuse a missing, extra, duplicate, wrong-class, wrong-tier, or wrong-applicability row.
//!
//! It consumes Section 33 rather than restating it: civil-time, locale, and rule-data semantics
//! remain owned by `GNT-33`, and monotonic and wall separation remains owned by
//! `GNT-33.9-monotonic-and-wall-separation`. The module is deliberately not a clock, timer,
//! scheduler, timezone upgrade, host adapter, capability grant, or durable reconstruction, and
//! it performs no I/O and reads no host time.

use crate::TargetKind;
use crate::stdlib::{
    DeclaredModuleRow, NameClass, PackageFamily, StabilityTier, StdGraph, StdItem, StdPackage,
    StdlibDiagnosticCode, StdlibError,
};
use gantry_core::mode::SemanticMode;

/// The Section 51 clauses this declaration slice publishes, in specification order.
pub const TIME_CLAUSES: [&str; 3] = [
    "GNT-51.0-time-foundation-scope",
    "GNT-51.1-time-modules-and-item-rows",
    "GNT-51.2-time-declaration-non-claims",
];

/// The scope and row-owning clauses every `std.time` module row binds, in specification order.
pub const TIME_MODULE_CLAUSES: [&str; 2] = [
    "GNT-51.0-time-foundation-scope",
    "GNT-51.1-time-modules-and-item-rows",
];

/// The declared semantic mode of every `std.time` module row of `GNT-51.1`.
pub const TIME_MODULE_MODES: [SemanticMode; 1] = [SemanticMode::Application];

/// The declared target kinds of every `std.time` module row of `GNT-51.1`.
pub const TIME_MODULE_TARGETS: [TargetKind; 2] = [TargetKind::Library, TargetKind::Binary];

/// The declared public modules of `std.time` (`GNT-51.1`), in canonical name order.
///
/// Each row binds the scope clause and the row-owning clause, in specification order. A row
/// declares a capability-backed namespace only: it publishes no clock, timer, scheduler, civil
/// ambiguity, rule-data identity, durable reconstruction, host operation, capability grant, or
/// runtime availability.
pub const TIME_MODULE_ROWS: [DeclaredModuleRow; 6] = [
    DeclaredModuleRow {
        name: "std.time::civil",
        class: NameClass::Module,
        tier: StabilityTier::Stable,
        modes: &TIME_MODULE_MODES,
        targets: &TIME_MODULE_TARGETS,
        clauses: &TIME_MODULE_CLAUSES,
    },
    DeclaredModuleRow {
        name: "std.time::clocks",
        class: NameClass::Module,
        tier: StabilityTier::Stable,
        modes: &TIME_MODULE_MODES,
        targets: &TIME_MODULE_TARGETS,
        clauses: &TIME_MODULE_CLAUSES,
    },
    DeclaredModuleRow {
        name: "std.time::locale",
        class: NameClass::Module,
        tier: StabilityTier::Stable,
        modes: &TIME_MODULE_MODES,
        targets: &TIME_MODULE_TARGETS,
        clauses: &TIME_MODULE_CLAUSES,
    },
    DeclaredModuleRow {
        name: "std.time::rule_data",
        class: NameClass::Module,
        tier: StabilityTier::Stable,
        modes: &TIME_MODULE_MODES,
        targets: &TIME_MODULE_TARGETS,
        clauses: &TIME_MODULE_CLAUSES,
    },
    DeclaredModuleRow {
        name: "std.time::timers",
        class: NameClass::Module,
        tier: StabilityTier::Stable,
        modes: &TIME_MODULE_MODES,
        targets: &TIME_MODULE_TARGETS,
        clauses: &TIME_MODULE_CLAUSES,
    },
    DeclaredModuleRow {
        name: "std.time::values",
        class: NameClass::Module,
        tier: StabilityTier::Stable,
        modes: &TIME_MODULE_MODES,
        targets: &TIME_MODULE_TARGETS,
        clauses: &TIME_MODULE_CLAUSES,
    },
];

/// The exported-item rows of `std.time` of `GNT-34.6-stability-tiers` and
/// `GNT-34.8-defining-identity-and-interface-digest`, derived from `GNT-51.1`.
///
/// The rows are exactly the [`DeclaredModuleRow`] values the row-owning clause publishes, so an
/// exported item is never invented beside its owning clause.
pub const TIME_ITEMS: [DeclaredModuleRow; 6] = TIME_MODULE_ROWS;

/// Validates one candidate `std.time` module row set against the closed published set.
///
/// The check is deterministic and atomic: a set that omits, adds, duplicates, or reorders a row,
/// or that changes the class, tier, applicability, or clause binding of a row, is refused before
/// any graph mutation rather than repaired or inferred. A missing or extra row, a duplicated or reordered row, and a wrong class or clause binding
/// are refused under `std-invalid-name-classification` of `GNT-34.2-name-classification`; a wrong
/// tier is refused under `std-invalid-stability-transition` of `GNT-34.6-stability-tiers`; and a
/// wrong mode or target set is refused under `std-unsupported-applicability` of
/// `GNT-34.7-applicability-and-feature-granularity`.
pub fn validate_time_module_rows(rows: &[DeclaredModuleRow]) -> Result<(), StdlibError> {
    if rows.len() != TIME_MODULE_ROWS.len() {
        return Err(StdlibError::new(
            StdlibDiagnosticCode::InvalidNameClassification,
            "the declared std.time surface must contain exactly six module rows".to_owned(),
        ));
    }
    for (index, row) in rows.iter().enumerate() {
        if rows[..index].iter().any(|prior| prior.name == row.name) {
            return Err(StdlibError::new(
                StdlibDiagnosticCode::InvalidNameClassification,
                format!("the std.time module row `{}` is declared twice", row.name),
            ));
        }
        let Some(declared) = TIME_MODULE_ROWS.get(index) else {
            return Err(StdlibError::new(
                StdlibDiagnosticCode::InvalidNameClassification,
                "the declared std.time surface has more rows than its clause".to_owned(),
            ));
        };
        if row.name != declared.name {
            return Err(StdlibError::new(
                StdlibDiagnosticCode::InvalidNameClassification,
                format!(
                    "`{}` is not the canonical std.time module at position {}",
                    row.name, index
                ),
            ));
        }
        if row.class != NameClass::Module {
            return Err(StdlibError::new(
                StdlibDiagnosticCode::InvalidNameClassification,
                format!("`{}` is not declared as a module", row.name),
            ));
        }
        if row.tier != StabilityTier::Stable {
            return Err(StdlibError::new(
                StdlibDiagnosticCode::InvalidStabilityTransition,
                format!("`{}` is not declared at the stable tier", row.name),
            ));
        }
        if row.modes != TIME_MODULE_MODES.as_slice()
            || row.targets != TIME_MODULE_TARGETS.as_slice()
        {
            return Err(StdlibError::new(
                StdlibDiagnosticCode::UnsupportedApplicability,
                format!("`{}` does not declare its row applicability", row.name),
            ));
        }
        if row.clauses != TIME_MODULE_CLAUSES.as_slice() {
            return Err(StdlibError::new(
                StdlibDiagnosticCode::InvalidNameClassification,
                format!("`{}` does not bind its row-owning clauses", row.name),
            ));
        }
    }
    Ok(())
}

/// Declares the capability-backed `std.time` package and its closed item surface.
///
/// The package is application-only over the library and binary targets and carries no dependency
/// edge, so the family stays outside the pure dependency DAG of
/// `GNT-34.3-acyclic-internal-dependency-dag`. Declaring the package adds no clock, timer,
/// scheduler, capability grant, adapter, or runtime availability.
pub fn declare_time_package(graph: &mut StdGraph) -> Result<(), StdlibError> {
    graph.declare(StdPackage::new(
        PackageFamily::Time,
        NameClass::Package,
        StabilityTier::Stable,
        &TIME_MODULE_MODES,
        &TIME_MODULE_TARGETS,
        &[],
        &[],
    )?)?;
    declare_time_surface(graph)
}

/// Declares the published item surface of `std.time` over one standard-library graph.
///
/// The owning package must already be declared, and its applicability, exports, names, item
/// metadata, and item set must match the closed rows before any item is declared. A refusal
/// leaves the graph exactly as it was declared, and a second declaration of a complete surface
/// is refused by the graph rather than merged.
pub fn declare_time_surface(graph: &mut StdGraph) -> Result<(), StdlibError> {
    validate_time_module_rows(&TIME_MODULE_ROWS)?;
    let owner = PackageFamily::Time.package_name();
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
            &TIME_ITEMS,
            &TIME_MODULE_MODES,
            &TIME_MODULE_TARGETS,
        )?;
        TIME_ITEMS
            .iter()
            .filter(|row| package.item(row.name).is_some())
            .count()
    };
    if present == TIME_ITEMS.len() {
        let Some(row) = TIME_ITEMS.first() else {
            return Ok(());
        };
        return graph.declare_item(StdItem::new(
            row.name,
            row.class,
            row.tier,
            row.modes,
            row.targets,
        )?);
    }
    for row in TIME_ITEMS {
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

/// Admits an already-declared `std.time` surface as exactly its six module rows.
///
/// A missing, extra, duplicate, wrong-class, wrong-tier, wrong-applicability, or wrong-clause row
/// is refused and the graph is never mutated.
pub fn admit_time_surface(graph: &StdGraph) -> Result<(), StdlibError> {
    validate_time_module_rows(&TIME_MODULE_ROWS)?;
    let owner = PackageFamily::Time.package_name();
    let package = graph.package(&owner).ok_or_else(|| {
        StdlibError::new(
            StdlibDiagnosticCode::UnknownEdge,
            format!("`{owner}` is not declared, so its item surface cannot be admitted"),
        )
    })?;
    crate::stdlib::validate_declared_surface(
        graph,
        package,
        &TIME_ITEMS,
        &TIME_MODULE_MODES,
        &TIME_MODULE_TARGETS,
    )?;
    if TIME_ITEMS
        .iter()
        .any(|row| package.item(row.name).is_none())
    {
        return Err(StdlibError::new(
            StdlibDiagnosticCode::InvalidNameClassification,
            "the declared std.time item surface is incomplete".to_owned(),
        ));
    }
    Ok(())
}

/// Returns the canonical pure hierarchy with the capability-backed `std.time` package and its
/// published item surface declared.
///
/// The family owns this declaration, so `canonical_pure_hierarchy` keeps carrying the pure
/// packages only while this constructor adds the capability package and the clause-derived item
/// rows. The added package declares no dependency edge, so it joins the graph without changing
/// the pure dependency order.
pub fn canonical_time_hierarchy() -> Result<StdGraph, StdlibError> {
    let mut graph = crate::stdlib::canonical_pure_hierarchy()?;
    declare_time_package(&mut graph)?;
    Ok(graph)
}
