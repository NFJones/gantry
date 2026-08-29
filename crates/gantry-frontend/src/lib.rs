//! Secure package source discovery and immutable snapshot assembly.
//!
//! This crate owns package filesystem access and source snapshot construction.
//! It does not own lexing, parsing, semantic analysis, rendering, or ambient
//! integration services.

mod provider;

pub use provider::{
    ModuleResolution, PackageSnapshotLoader, RootDirectorySourceProvider, SourceProvider,
    SourceProviderError, SourceReadLimits,
};
