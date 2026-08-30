//! Canonical package-source manifests over immutable source snapshots.

use gantry_core::protocol::ProtocolVersion;
use gantry_core::source::{PackagePath, SourceSnapshot};

use crate::artifact::{
    ArtifactEncodingError, ArtifactLimits, BoundedArtifact, CanonicalArtifactEncoder,
};
use crate::generated::ArtifactKind;

/// One selected source file recorded by package audit provenance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestFile {
    package_path: PackagePath,
    byte_length: u64,
    sha256: [u8; 32],
}

impl ManifestFile {
    /// Returns the exact package-relative path.
    #[must_use]
    pub const fn package_path(&self) -> &PackagePath {
        &self.package_path
    }

    /// Returns the exact immutable byte length.
    #[must_use]
    pub const fn byte_length(&self) -> u64 {
        self.byte_length
    }

    /// Returns the lowercase SHA-256 digest of the exact source bytes.
    #[must_use]
    pub fn sha256_hex(&self) -> String {
        encode_hex(&self.sha256)
    }
}

/// One versioned canonical package-source manifest and its admitted identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageSourceManifest {
    source_language: ProtocolVersion,
    files: Vec<ManifestFile>,
    total_byte_length: u64,
    artifact: BoundedArtifact,
}

impl PackageSourceManifest {
    /// Constructs a complete manifest from one already immutable snapshot.
    ///
    /// Files retain the snapshot's unsigned-UTF-8 path order. The identity is
    /// created only after complete canonical encoding satisfies the manifest
    /// byte limit.
    pub fn from_snapshot(
        snapshot: &SourceSnapshot,
        source_language: ProtocolVersion,
        limits: ArtifactLimits,
    ) -> Result<Self, ManifestError> {
        if (source_language.major, source_language.minor) != (1, 0) {
            return Err(ManifestError::UnsupportedSourceLanguage);
        }
        let mut files = Vec::with_capacity(snapshot.records().len());
        let mut total_byte_length = 0_u64;
        for record in snapshot.records() {
            total_byte_length = total_byte_length
                .checked_add(record.byte_len())
                .ok_or(ManifestError::ByteLengthOverflow)?;
            files.push(ManifestFile {
                package_path: record.id().package_path().clone(),
                byte_length: record.byte_len(),
                sha256: record.sha256(),
            });
        }
        if !files
            .iter()
            .any(|file| file.package_path.as_str() == "main.gnt")
        {
            return Err(ManifestError::MissingRootFile);
        }
        if files.windows(2).any(|pair| {
            pair[0].package_path.as_str().as_bytes() >= pair[1].package_path.as_str().as_bytes()
        }) {
            return Err(ManifestError::NoncanonicalFileOrder);
        }

        let artifact = encode_manifest(source_language, &files, total_byte_length, limits)
            .map_err(ManifestError::Encoding)?;
        Ok(Self {
            source_language,
            files,
            total_byte_length,
            artifact,
        })
    }

    /// Returns the selected source-language protocol version.
    #[must_use]
    pub const fn source_language(&self) -> ProtocolVersion {
        self.source_language
    }

    /// Returns every selected file in unsigned-UTF-8 path order.
    #[must_use]
    pub fn files(&self) -> &[ManifestFile] {
        &self.files
    }

    /// Returns the checked sum of all exact file byte lengths.
    #[must_use]
    pub const fn total_byte_length(&self) -> u64 {
        self.total_byte_length
    }

    /// Returns the bounded canonical bytes and accepted manifest identity.
    #[must_use]
    pub const fn artifact(&self) -> &BoundedArtifact {
        &self.artifact
    }
}

/// Rejection while constructing package audit provenance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifestError {
    /// The source-language version is not the published v1 version.
    UnsupportedSourceLanguage,
    /// The immutable snapshot does not contain `main.gnt` as its first path.
    MissingRootFile,
    /// Snapshot file paths are not strictly ordered by unsigned UTF-8 bytes.
    NoncanonicalFileOrder,
    /// The checked total source byte length overflowed.
    ByteLengthOverflow,
    /// Complete canonical encoding was empty or exceeded its portable limit.
    Encoding(ArtifactEncodingError),
}

impl std::fmt::Display for ManifestError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedSourceLanguage => {
                formatter.write_str("unsupported manifest source-language version")
            }
            Self::MissingRootFile => formatter.write_str("manifest root file is missing"),
            Self::NoncanonicalFileOrder => {
                formatter.write_str("manifest files are not in canonical order")
            }
            Self::ByteLengthOverflow => formatter.write_str("manifest byte length overflowed"),
            Self::Encoding(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for ManifestError {}

fn encode_manifest(
    source_language: ProtocolVersion,
    files: &[ManifestFile],
    total_byte_length: u64,
    limits: ArtifactLimits,
) -> Result<BoundedArtifact, ArtifactEncodingError> {
    let mut output = CanonicalArtifactEncoder::new(ArtifactKind::PackageSourceManifest, limits);
    output.push_str("{\"files\":[")?;
    for (index, file) in files.iter().enumerate() {
        if index > 0 {
            output.push_byte(b',')?;
        }
        output.push_str("{\"byte_length\":\"")?;
        output.push_str(&file.byte_length.to_string())?;
        output.push_str("\",\"package_path\":")?;
        push_json_string(&mut output, file.package_path.as_str())?;
        output.push_str(",\"sha256\":\"")?;
        output.push_str(&encode_hex(&file.sha256))?;
        output.push_str("\"}")?;
    }
    output.push_str("],\"root_file\":\"main.gnt\",\"source_language\":{\"major\":")?;
    output.push_str(&source_language.major.to_string())?;
    output.push_str(",\"minor\":")?;
    output.push_str(&source_language.minor.to_string())?;
    output.push_str("},\"total_byte_length\":\"")?;
    output.push_str(&total_byte_length.to_string())?;
    output.push_str("\"}")?;
    output.finish()
}

fn push_json_string(
    output: &mut CanonicalArtifactEncoder,
    value: &str,
) -> Result<(), ArtifactEncodingError> {
    output.push_byte(b'"')?;
    for scalar in value.chars() {
        match scalar {
            '"' => output.push_str("\\\"")?,
            '\\' => output.push_str("\\\\")?,
            '\u{08}' => output.push_str("\\b")?,
            '\u{0c}' => output.push_str("\\f")?,
            '\n' => output.push_str("\\n")?,
            '\r' => output.push_str("\\r")?,
            '\t' => output.push_str("\\t")?,
            value if value <= '\u{1f}' => {
                output.push_str(&format!("\\u{:04x}", value as u32))?;
            }
            value => output.push_str(value.encode_utf8(&mut [0; 4]))?,
        }
    }
    output.push_byte(b'"')?;
    Ok(())
}

fn encode_hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use gantry_core::protocol::ProtocolVersion;
    use gantry_core::source::{SourceLimits, SourceSnapshotBuilder};

    use super::{ArtifactLimits, ManifestError, PackageSourceManifest};

    fn limits(limit: u64) -> ArtifactLimits {
        ArtifactLimits {
            package_source_manifest_bytes: limit,
            canonical_ir_bytes: limit,
            source_map_bytes: limit,
            generated_schema_bytes: limit,
        }
    }

    #[test]
    fn root_and_multi_file_manifests_are_canonical_and_bounded() {
        let source_limits =
            SourceLimits::new(2, 64, 128, 1, 1).unwrap_or_else(|_| unreachable!("positive limits"));
        let mut builder = SourceSnapshotBuilder::new(source_limits);
        assert!(builder.add_file("z.gnt", b"z").is_ok());
        assert!(builder.add_file("main.gnt", b"fn main() {}").is_ok());
        let snapshot = builder.finish();
        let manifest = PackageSourceManifest::from_snapshot(
            &snapshot,
            ProtocolVersion { major: 1, minor: 0 },
            limits(4_096),
        );
        assert!(manifest.is_ok());
        let manifest = manifest.unwrap_or_else(|_| unreachable!("checked above"));
        assert_eq!(
            manifest
                .files()
                .iter()
                .map(|file| file.package_path().as_str())
                .collect::<Vec<_>>(),
            ["main.gnt", "z.gnt"]
        );
        assert_eq!(manifest.total_byte_length(), 13);
        assert_eq!(manifest.artifact().sha256_hex().len(), 64);
        let text = std::str::from_utf8(manifest.artifact().canonical_bytes());
        assert!(text.is_ok_and(|text| {
            text.starts_with("{\"files\":[{\"byte_length\":\"12\",\"package_path\":\"main.gnt\"")
                && text.ends_with("\"total_byte_length\":\"13\"}")
        }));

        let above = PackageSourceManifest::from_snapshot(
            &snapshot,
            ProtocolVersion { major: 1, minor: 0 },
            limits(1),
        );
        assert!(matches!(above, Err(ManifestError::Encoding(_))));
    }

    #[test]
    fn root_file_need_not_sort_first_in_the_manifest() {
        let source_limits =
            SourceLimits::new(2, 64, 128, 1, 1).unwrap_or_else(|_| unreachable!("positive limits"));
        let mut builder = SourceSnapshotBuilder::new(source_limits);
        assert!(builder.add_file("0.gnt", b"zero").is_ok());
        assert!(builder.add_file("main.gnt", b"fn main() {}").is_ok());
        let snapshot = builder.finish();
        let manifest = PackageSourceManifest::from_snapshot(
            &snapshot,
            ProtocolVersion { major: 1, minor: 0 },
            limits(4_096),
        );
        assert!(manifest.is_ok());
        let manifest = manifest.unwrap_or_else(|_| unreachable!("checked above"));
        assert_eq!(
            manifest
                .files()
                .iter()
                .map(|file| file.package_path().as_str())
                .collect::<Vec<_>>(),
            ["0.gnt", "main.gnt"]
        );
    }

    #[test]
    fn manifest_rejects_missing_root_and_other_versions() {
        let source_limits =
            SourceLimits::new(1, 64, 64, 1, 1).unwrap_or_else(|_| unreachable!("positive limits"));
        let mut builder = SourceSnapshotBuilder::new(source_limits);
        assert!(builder.add_file("other.gnt", b"fn other() {}").is_ok());
        let snapshot = builder.finish();
        assert_eq!(
            PackageSourceManifest::from_snapshot(
                &snapshot,
                ProtocolVersion { major: 1, minor: 0 },
                limits(4_096),
            ),
            Err(ManifestError::MissingRootFile)
        );
        assert_eq!(
            PackageSourceManifest::from_snapshot(
                &snapshot,
                ProtocolVersion { major: 2, minor: 0 },
                limits(4_096),
            ),
            Err(ManifestError::UnsupportedSourceLanguage)
        );
    }
}
