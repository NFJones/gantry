//! The canonical aggregate `std` hierarchy of Section 34: the base pure hierarchy of
//! `crate::stdlib` with every declared family item surface composed onto it in canonical order.
//!
//! The aggregate is assembled, not authored, here: each family keeps ownership of its own item
//! rows (`declare_collections_surface`, `declare_codec_surface`, `declare_crypto_surface`,
//! `declare_data_surface`), and this module composes their published surfaces so package tests,
//! tooling, cross-gate applications, and publication read one graph.

use crate::stdlib::{StdGraph, StdlibError};
use crate::{codec, collections, crypto, data};

/// Composes the canonical aggregate `std` hierarchy with every declared family item surface
/// (`GNT-34.6-stability-tiers`, `GNT-34.8-defining-identity-and-interface-digest`).
///
/// The base hierarchy carries packages, applicability, edges, and the enumerated prelude; each
/// declaration below adds one family's published item rows in canonical family order, and a
/// family that declares no item surface composes an empty surface rather than a substitute one.
pub fn canonical_std_hierarchy() -> Result<StdGraph, StdlibError> {
    let mut graph = crate::stdlib::canonical_pure_hierarchy()?;
    collections::declare_collections_surface(&mut graph)?;
    codec::declare_codec_surface(&mut graph)?;
    crypto::declare_crypto_surface(&mut graph)?;
    data::declare_data_surface(&mut graph)?;
    Ok(graph)
}
