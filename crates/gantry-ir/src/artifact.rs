//! Bounded canonical artifact envelopes and exact identities.

use std::sync::Arc;

use gantry_core::portable::FrontendResourceCode;
use gantry_core::source::{FrontendLimits, FrontendResourceLimit};
use sha2::{Digest, Sha256};

use crate::generated::ArtifactKind;

/// Finite byte limits for the four artifacts emitted by analyzer work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArtifactLimits {
    /// Maximum canonical package-source-manifest bytes.
    pub package_source_manifest_bytes: u64,
    /// Maximum canonical IR bytes.
    pub canonical_ir_bytes: u64,
    /// Maximum canonical source-map bytes.
    pub source_map_bytes: u64,
    /// Maximum canonical generated-schema object bytes.
    pub generated_schema_bytes: u64,
}

impl From<FrontendLimits> for ArtifactLimits {
    fn from(limits: FrontendLimits) -> Self {
        Self {
            package_source_manifest_bytes: limits.maximum_package_source_manifest_bytes(),
            canonical_ir_bytes: limits.maximum_canonical_ir_bytes(),
            source_map_bytes: limits.maximum_source_map_bytes(),
            generated_schema_bytes: limits.maximum_generated_schema_bytes(),
        }
    }
}

/// One complete canonical artifact admitted under its portable byte limit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundedArtifact {
    kind: ArtifactKind,
    bytes: Arc<[u8]>,
    sha256: [u8; 32],
}

impl BoundedArtifact {
    /// Admits already canonical bytes only when the complete artifact fits.
    ///
    /// No identity is returned for an oversized artifact.
    pub fn from_validated_canonical_bytes(
        kind: ArtifactKind,
        bytes: impl Into<Arc<[u8]>>,
        limits: ArtifactLimits,
    ) -> Result<Self, ArtifactEncodingError> {
        let bytes = bytes.into();
        if bytes.is_empty() {
            return Err(ArtifactEncodingError::Empty);
        }
        let limit = artifact_limit(kind, limits);
        let observed = u64::try_from(bytes.len()).ok();
        if observed.is_none_or(|observed| observed > limit) {
            return Err(ArtifactEncodingError::ResourceLimit(
                FrontendResourceLimit {
                    code: resource_code(kind),
                    limit,
                    observed,
                },
            ));
        }
        let sha256 = Sha256::digest(&bytes).into();
        Ok(Self {
            kind,
            bytes,
            sha256,
        })
    }

    /// Returns the exact artifact kind.
    #[must_use]
    pub const fn kind(&self) -> ArtifactKind {
        self.kind
    }

    /// Returns the complete immutable canonical bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns lowercase SHA-256 over the complete admitted bytes.
    #[must_use]
    pub fn sha256_hex(&self) -> String {
        self.sha256
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
}

/// Incremental canonical encoder that rejects a write before it exceeds the
/// selected artifact's portable byte limit.
pub(crate) struct CanonicalArtifactEncoder {
    kind: ArtifactKind,
    limit: u64,
    bytes: Vec<u8>,
}

impl CanonicalArtifactEncoder {
    /// Starts one bounded encoding without preallocating the configured limit.
    #[must_use]
    pub(crate) fn new(kind: ArtifactKind, limits: ArtifactLimits) -> Self {
        Self {
            kind,
            limit: artifact_limit(kind, limits),
            bytes: Vec::new(),
        }
    }

    /// Appends UTF-8 bytes only when the resulting complete prefix still fits.
    pub(crate) fn push_str(&mut self, value: &str) -> Result<(), ArtifactEncodingError> {
        self.push_bytes(value.as_bytes())
    }

    /// Appends one byte only when the resulting complete prefix still fits.
    pub(crate) fn push_byte(&mut self, value: u8) -> Result<(), ArtifactEncodingError> {
        self.push_bytes(&[value])
    }

    /// Finishes the nonempty canonical artifact and computes its identity.
    pub(crate) fn finish(self) -> Result<BoundedArtifact, ArtifactEncodingError> {
        BoundedArtifact::from_validated_canonical_bytes(
            self.kind,
            self.bytes,
            ArtifactLimits {
                package_source_manifest_bytes: self.limit,
                canonical_ir_bytes: self.limit,
                source_map_bytes: self.limit,
                generated_schema_bytes: self.limit,
            },
        )
    }

    fn push_bytes(&mut self, value: &[u8]) -> Result<(), ArtifactEncodingError> {
        let current = u64::try_from(self.bytes.len()).ok();
        let amount = u64::try_from(value.len()).ok();
        let observed =
            current.and_then(|current| amount.and_then(|amount| current.checked_add(amount)));
        if observed.is_none_or(|observed| observed > self.limit) {
            return Err(ArtifactEncodingError::ResourceLimit(
                FrontendResourceLimit {
                    code: resource_code(self.kind),
                    limit: self.limit,
                    observed,
                },
            ));
        }
        self.bytes.extend_from_slice(value);
        Ok(())
    }
}

/// Failure while admitting one canonical analyzer artifact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactEncodingError {
    /// Canonical bytes must not be empty.
    Empty,
    /// The complete artifact exceeds its exact portable byte limit.
    ResourceLimit(FrontendResourceLimit),
}

impl std::fmt::Display for ArtifactEncodingError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => formatter.write_str("canonical artifact is empty"),
            Self::ResourceLimit(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for ArtifactEncodingError {}

const fn artifact_limit(kind: ArtifactKind, limits: ArtifactLimits) -> u64 {
    match kind {
        ArtifactKind::CanonicalIr => limits.canonical_ir_bytes,
        ArtifactKind::GeneratedSchemaObject => limits.generated_schema_bytes,
        ArtifactKind::PackageSourceManifest => limits.package_source_manifest_bytes,
        ArtifactKind::SourceMap => limits.source_map_bytes,
    }
}

const fn resource_code(kind: ArtifactKind) -> FrontendResourceCode {
    match kind {
        ArtifactKind::CanonicalIr => FrontendResourceCode::CanonicalIrByteLimit,
        ArtifactKind::GeneratedSchemaObject => FrontendResourceCode::GeneratedSchemaByteLimit,
        ArtifactKind::PackageSourceManifest => FrontendResourceCode::PackageSourceManifestByteLimit,
        ArtifactKind::SourceMap => FrontendResourceCode::SourceMapByteLimit,
    }
}

#[cfg(test)]
mod tests {
    use super::{ArtifactEncodingError, ArtifactLimits, BoundedArtifact};
    use crate::generated::ArtifactKind;
    use gantry_core::portable::FrontendResourceCode;

    fn limits(limit: u64) -> ArtifactLimits {
        ArtifactLimits {
            package_source_manifest_bytes: limit,
            canonical_ir_bytes: limit,
            source_map_bytes: limit,
            generated_schema_bytes: limit,
        }
    }

    #[test]
    fn artifacts_enforce_exact_boundaries_before_identity() {
        let at = BoundedArtifact::from_validated_canonical_bytes(
            ArtifactKind::CanonicalIr,
            &b"{}"[..],
            limits(2),
        );
        assert!(at.is_ok());
        assert_eq!(at.map(|artifact| artifact.sha256_hex().len()), Ok(64));

        let above = BoundedArtifact::from_validated_canonical_bytes(
            ArtifactKind::CanonicalIr,
            &b"{}"[..],
            limits(1),
        );
        assert!(matches!(
            above,
            Err(ArtifactEncodingError::ResourceLimit(error))
                if error.code == FrontendResourceCode::CanonicalIrByteLimit
                    && error.observed == Some(2)
        ));
    }
}
