//! Exact protocol versions, selection, and peer compatibility checks.

use std::fmt;

use crate::identity::{IdentityError, decode_lower_hex};
use crate::portable::{
    PORTABLE_SPECIFICATION_REVISION, PROTOCOL_FAMILIES, PROTOCOL_FAMILY_DEFINITIONS, ProtocolFamily,
};

/// Largest exact integer permitted in a protocol version component.
pub const MAXIMUM_PROTOCOL_COMPONENT: u64 = 9_007_199_254_740_991;

/// One exact protocol major/minor version.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ProtocolVersion {
    /// Major protocol version.
    pub major: u64,
    /// Minor protocol version.
    pub minor: u64,
}

impl ProtocolVersion {
    /// Constructs a bounded exact protocol version.
    pub const fn new(major: u64, minor: u64) -> Result<Self, ProtocolSelectionError> {
        if major > MAXIMUM_PROTOCOL_COMPONENT || minor > MAXIMUM_PROTOCOL_COMPONENT {
            return Err(ProtocolSelectionError::VersionOutOfRange);
        }
        Ok(Self { major, minor })
    }
}

/// One selected family/version pair.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SelectedProtocol {
    /// Protocol family.
    pub family: ProtocolFamily,
    /// Exact selected version.
    pub version: ProtocolVersion,
}

/// The exact complete protocol tuple for one activity or execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtocolSelection {
    specification_revision: [u8; 32],
    protocols: Vec<SelectedProtocol>,
}

impl ProtocolSelection {
    /// Constructs a complete, canonically ordered selection.
    pub fn new(
        specification_revision: &str,
        protocols: Vec<SelectedProtocol>,
    ) -> Result<Self, ProtocolSelectionError> {
        let specification_revision = decode_revision(specification_revision)?;
        if specification_revision != decode_revision(PORTABLE_SPECIFICATION_REVISION)? {
            return Err(ProtocolSelectionError::UnsupportedSpecificationRevision);
        }
        validate_complete_protocols(&protocols)?;
        if protocols
            .iter()
            .zip(PROTOCOL_FAMILY_DEFINITIONS)
            .any(|(selected, supported)| {
                selected.family != supported.family
                    || selected.version.major != supported.major
                    || selected.version.minor != supported.minor
            })
        {
            return Err(ProtocolSelectionError::UnsupportedVersion);
        }
        Ok(Self {
            specification_revision,
            protocols,
        })
    }

    /// Returns the lowercase specification-revision digest.
    #[must_use]
    pub fn specification_revision(&self) -> String {
        self.specification_revision
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    /// Returns all selected protocols in canonical family order.
    #[must_use]
    pub fn protocols(&self) -> &[SelectedProtocol] {
        &self.protocols
    }

    /// Returns the selected version for one family.
    #[must_use]
    pub fn version(&self, family: ProtocolFamily) -> ProtocolVersion {
        self.protocols
            .iter()
            .find(|selected| selected.family == family)
            .map(|selected| selected.version)
            .unwrap_or(ProtocolVersion { major: 0, minor: 0 })
    }

    /// Verifies this selection against one required peer advertisement.
    pub fn require_peer(&self, peer: &ProtocolAdvertisement) -> Result<(), ProtocolSelectionError> {
        if self.specification_revision != peer.specification_revision {
            return Err(ProtocolSelectionError::SpecificationRevisionMismatch);
        }
        for selected in &self.protocols {
            if !peer.supported.contains(selected) {
                return Err(ProtocolSelectionError::UnsupportedVersion);
            }
        }
        Ok(())
    }
}

/// One peer's finite exact protocol advertisement for one publication set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtocolAdvertisement {
    specification_revision: [u8; 32],
    supported: Vec<SelectedProtocol>,
}

impl ProtocolAdvertisement {
    /// Constructs a finite peer advertisement.
    pub fn new(
        specification_revision: &str,
        mut supported: Vec<SelectedProtocol>,
    ) -> Result<Self, ProtocolSelectionError> {
        let specification_revision = decode_revision(specification_revision)?;
        supported.sort_by_key(|selected| (selected.family, selected.version));
        if supported.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(ProtocolSelectionError::DuplicateVersion);
        }
        Ok(Self {
            specification_revision,
            supported,
        })
    }
}

/// Failure to construct or validate an exact protocol selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolSelectionError {
    /// A version component exceeds the exact JSON integer bound.
    VersionOutOfRange,
    /// The specification digest is not exactly 64 lowercase hexadecimal digits.
    InvalidSpecificationRevision,
    /// The specification revision is not implemented by this build.
    UnsupportedSpecificationRevision,
    /// A selected family is missing, duplicated, or out of canonical order.
    IncompleteProtocolSelection,
    /// A peer advertised the same exact family/version more than once.
    DuplicateVersion,
    /// The selected protocol version is absent from a required peer.
    UnsupportedVersion,
    /// The selection and peer came from different specification revisions.
    SpecificationRevisionMismatch,
}

impl fmt::Display for ProtocolSelectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::VersionOutOfRange => "protocol version component exceeds the exact bound",
            Self::InvalidSpecificationRevision => "specification revision is not lowercase SHA-256",
            Self::UnsupportedSpecificationRevision => {
                "specification revision is not implemented by this build"
            }
            Self::IncompleteProtocolSelection => "protocol selection is incomplete or noncanonical",
            Self::DuplicateVersion => "protocol advertisement contains a duplicate exact version",
            Self::UnsupportedVersion => "required peer does not support the selected exact version",
            Self::SpecificationRevisionMismatch => {
                "protocol selection uses another publication revision"
            }
        })
    }
}

impl std::error::Error for ProtocolSelectionError {}

fn validate_complete_protocols(
    protocols: &[SelectedProtocol],
) -> Result<(), ProtocolSelectionError> {
    if protocols.len() != PROTOCOL_FAMILIES.len()
        || protocols
            .iter()
            .zip(PROTOCOL_FAMILIES)
            .any(|(selected, expected)| selected.family != *expected)
    {
        return Err(ProtocolSelectionError::IncompleteProtocolSelection);
    }
    Ok(())
}

fn decode_revision(value: &str) -> Result<[u8; 32], ProtocolSelectionError> {
    decode_lower_hex(value).map_err(|error| match error {
        IdentityError::InvalidLength | IdentityError::InvalidHexadecimal => {
            ProtocolSelectionError::InvalidSpecificationRevision
        }
        _ => ProtocolSelectionError::InvalidSpecificationRevision,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        MAXIMUM_PROTOCOL_COMPONENT, ProtocolAdvertisement, ProtocolSelection,
        ProtocolSelectionError, ProtocolVersion, SelectedProtocol,
    };
    use crate::portable::{PORTABLE_SPECIFICATION_REVISION, PROTOCOL_FAMILIES, ProtocolFamily};

    fn selected(version: ProtocolVersion) -> Vec<SelectedProtocol> {
        PROTOCOL_FAMILIES
            .iter()
            .copied()
            .map(|family| SelectedProtocol { family, version })
            .collect()
    }

    #[test]
    fn complete_selection_matches_an_exact_peer() {
        let version = ProtocolVersion::new(1, 0).unwrap_or_else(|_| unreachable!());
        let revision = PORTABLE_SPECIFICATION_REVISION;
        let selection = ProtocolSelection::new(revision, selected(version));
        let peer = ProtocolAdvertisement::new(revision, selected(version));
        assert!(selection.is_ok());
        assert!(peer.is_ok());
        let selection = selection.unwrap_or_else(|_| unreachable!());
        let peer = peer.unwrap_or_else(|_| unreachable!());
        assert_eq!(selection.require_peer(&peer), Ok(()));
        assert_eq!(selection.version(ProtocolFamily::Event), version);
    }

    #[test]
    fn rejects_missing_family_and_publication_mismatch() {
        let version = ProtocolVersion::new(1, 0).unwrap_or_else(|_| unreachable!());
        let mut incomplete = selected(version);
        incomplete.pop();
        assert!(matches!(
            ProtocolSelection::new(PORTABLE_SPECIFICATION_REVISION, incomplete),
            Err(ProtocolSelectionError::IncompleteProtocolSelection)
        ));

        let selection = ProtocolSelection::new(PORTABLE_SPECIFICATION_REVISION, selected(version));
        let peer = ProtocolAdvertisement::new(&"cd".repeat(32), selected(version));
        assert!(selection.is_ok() && peer.is_ok());
        assert_eq!(
            selection
                .unwrap_or_else(|_| unreachable!())
                .require_peer(&peer.unwrap_or_else(|_| unreachable!())),
            Err(ProtocolSelectionError::SpecificationRevisionMismatch)
        );
    }

    #[test]
    fn rejects_out_of_range_version_and_invalid_revision() {
        assert_eq!(
            ProtocolVersion::new(MAXIMUM_PROTOCOL_COMPONENT + 1, 0),
            Err(ProtocolSelectionError::VersionOutOfRange)
        );
        let version = ProtocolVersion::new(1, 0).unwrap_or_else(|_| unreachable!());
        assert!(matches!(
            ProtocolSelection::new(&"AB".repeat(32), selected(version)),
            Err(ProtocolSelectionError::InvalidSpecificationRevision)
        ));
        assert_eq!(
            ProtocolSelection::new(&"ab".repeat(32), selected(version)),
            Err(ProtocolSelectionError::UnsupportedSpecificationRevision)
        );

        let unsupported = ProtocolVersion::new(1, 1).unwrap_or_else(|_| unreachable!());
        assert_eq!(
            ProtocolSelection::new(PORTABLE_SPECIFICATION_REVISION, selected(unsupported)),
            Err(ProtocolSelectionError::UnsupportedVersion)
        );
    }
}
