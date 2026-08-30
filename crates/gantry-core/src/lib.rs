//! Portable deterministic contracts shared by Gantry implementation layers.
//!
//! Source, diagnostic, value, identity, and other core semantics are added by
//! their owning issues. This crate has no ambient I/O or orchestration role.

pub mod canonical_json;
pub mod event;
pub mod identity;
pub mod numeric;
pub mod portable;
pub mod profile;
pub mod protocol;
pub mod schema;
pub mod source;
pub mod strict_json;
pub mod timestamp;
pub mod unicode;
pub mod value;
