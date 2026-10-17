//! Declared `std.random` module-name set for `SPEC.md` Section 50.
//!
//! This module publishes only the canonical module row of the capability-backed `std.random`
//! family, its classification, its tier, its application-only applicability over the library and
//! binary target kinds, and the clauses that publish it. It is not a draw API, an entropy source,
//! a capability or authority grant, an adapter, or runtime availability, and it performs no I/O
//! and consumes no host entropy.

use crate::TargetKind;
use crate::stdlib::{DeclaredModuleRow, NameClass, StabilityTier};
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
