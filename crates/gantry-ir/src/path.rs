//! Canonical `crate::`-rooted item paths.

use std::fmt;
use std::sync::Arc;

use gantry_core::unicode::{is_nfc, is_xid_continue, is_xid_start};

/// One exact NFC, `crate::`-rooted item path.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CanonicalPath(Arc<str>);

impl CanonicalPath {
    /// Validates one canonical item path without normalizing authored input.
    pub fn new(value: &str) -> Result<Self, CanonicalPathError> {
        let relative = value
            .strip_prefix("crate::")
            .ok_or(CanonicalPathError::NotCrateRooted)?;
        if relative.is_empty() {
            return Err(CanonicalPathError::MissingSegment);
        }
        if !is_nfc(value) {
            return Err(CanonicalPathError::NotNfc);
        }
        for segment in relative.split("::") {
            if segment.is_empty() {
                return Err(CanonicalPathError::MissingSegment);
            }
            let mut scalars = segment.chars();
            if !scalars
                .next()
                .is_some_and(|scalar| scalar == '_' || is_xid_start(scalar))
                || !scalars.all(is_xid_continue)
            {
                return Err(CanonicalPathError::InvalidSegment);
            }
        }
        Ok(Self(Arc::from(value)))
    }

    /// Returns the exact canonical spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CanonicalPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Rejection of a noncanonical item path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CanonicalPathError {
    /// The path does not begin with the exact `crate::` root.
    NotCrateRooted,
    /// No item segment follows the root or a separator is empty.
    MissingSegment,
    /// A segment is not one Unicode 16 XID identifier.
    InvalidSegment,
    /// The exact spelling is not already Unicode 16 NFC.
    NotNfc,
}

impl fmt::Display for CanonicalPathError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NotCrateRooted => "canonical path is not crate-rooted",
            Self::MissingSegment => "canonical path has no item segment",
            Self::InvalidSegment => "canonical path contains an invalid identifier",
            Self::NotNfc => "canonical path is not Unicode 16 NFC",
        })
    }
}

impl std::error::Error for CanonicalPathError {}

#[cfg(test)]
mod tests {
    use super::{CanonicalPath, CanonicalPathError};

    #[test]
    fn accepts_exact_crate_rooted_nfc_paths() {
        let path = CanonicalPath::new("crate::quality::Résumé");
        assert!(path.is_ok());
        assert_eq!(
            path.map(|path| path.to_string()),
            Ok("crate::quality::Résumé".to_owned())
        );
        assert!(CanonicalPath::new("crate::_private::item_2").is_ok());
    }

    #[test]
    fn rejects_relative_empty_non_identifier_and_non_nfc_paths() {
        assert_eq!(
            CanonicalPath::new("self::item"),
            Err(CanonicalPathError::NotCrateRooted)
        );
        assert_eq!(
            CanonicalPath::new("crate::"),
            Err(CanonicalPathError::MissingSegment)
        );
        assert_eq!(
            CanonicalPath::new("crate::module::"),
            Err(CanonicalPathError::MissingSegment)
        );
        assert_eq!(
            CanonicalPath::new("crate::bad-name"),
            Err(CanonicalPathError::InvalidSegment)
        );
        assert_eq!(
            CanonicalPath::new("crate::A\u{301}"),
            Err(CanonicalPathError::NotNfc)
        );
    }
}
