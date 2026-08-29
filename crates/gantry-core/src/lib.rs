//! Portable deterministic contracts shared by Gantry implementation layers.
//!
//! Source, diagnostic, value, identity, and other core semantics are added by
//! their owning issues. This crate has no ambient I/O or orchestration role.

pub mod identity;
pub mod portable;
pub mod profile;
pub mod protocol;
pub mod source;
pub mod timestamp;
pub mod unicode;
