//! Canonical generated-schema objects keyed by type descriptor.

use std::sync::Arc;

use crate::TypeDescriptor;
use crate::artifact::{
    ArtifactEncodingError, ArtifactLimits, BoundedArtifact, CanonicalArtifactEncoder,
};
use crate::generated::ArtifactKind;

/// One deduplicated canonical generated-schema object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneratedSchemaObject {
    entries: Vec<(TypeDescriptor, Arc<[u8]>)>,
    artifact: BoundedArtifact,
}

impl GeneratedSchemaObject {
    /// Constructs a canonical object from descriptor-ordered schema bytes.
    ///
    /// Each value must be one nonempty canonical JSON object. A descriptor may
    /// occur only once even when several operation boundaries reference it.
    pub fn new(
        entries: Vec<(TypeDescriptor, Arc<[u8]>)>,
        limits: ArtifactLimits,
    ) -> Result<Self, SchemaObjectError> {
        if entries.windows(2).any(|pair| {
            pair[0].0.canonical_string().as_bytes() >= pair[1].0.canonical_string().as_bytes()
        }) {
            return Err(SchemaObjectError::NoncanonicalOrder);
        }
        if entries.iter().any(|(_, schema)| {
            schema.is_empty()
                || schema.first() != Some(&b'{')
                || schema.last() != Some(&b'}')
                || std::str::from_utf8(schema).is_err()
        }) {
            return Err(SchemaObjectError::InvalidSchemaBytes);
        }
        let artifact = encode(&entries, limits).map_err(SchemaObjectError::Encoding)?;
        Ok(Self { entries, artifact })
    }

    /// Returns entries in canonical type-descriptor order.
    #[must_use]
    pub fn entries(&self) -> &[(TypeDescriptor, Arc<[u8]>)] {
        &self.entries
    }

    /// Returns the complete bounded canonical object bytes.
    #[must_use]
    pub const fn artifact(&self) -> &BoundedArtifact {
        &self.artifact
    }
}

/// Rejection while constructing the generated-schema object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchemaObjectError {
    /// Type descriptors are duplicated or not in canonical order.
    NoncanonicalOrder,
    /// A schema value is empty, non-UTF-8, or not a JSON object encoding.
    InvalidSchemaBytes,
    /// Complete canonical encoding exceeded the generated-schema byte limit.
    Encoding(ArtifactEncodingError),
}

impl std::fmt::Display for SchemaObjectError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoncanonicalOrder => {
                formatter.write_str("generated schemas are not canonically ordered")
            }
            Self::InvalidSchemaBytes => formatter.write_str("generated schema bytes are invalid"),
            Self::Encoding(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for SchemaObjectError {}

fn encode(
    entries: &[(TypeDescriptor, Arc<[u8]>)],
    limits: ArtifactLimits,
) -> Result<BoundedArtifact, ArtifactEncodingError> {
    let mut output = CanonicalArtifactEncoder::new(ArtifactKind::GeneratedSchemaObject, limits);
    output.push_byte(b'{')?;
    for (index, (descriptor, schema)) in entries.iter().enumerate() {
        if index > 0 {
            output.push_byte(b',')?;
        }
        push_json_string(&mut output, &descriptor.canonical_string())?;
        output.push_byte(b':')?;
        output.push_str(
            std::str::from_utf8(schema)
                .unwrap_or_else(|_| unreachable!("constructor validates schema UTF-8")),
        )?;
    }
    output.push_byte(b'}')?;
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use gantry_core::portable::FrontendResourceCode;

    use super::{GeneratedSchemaObject, SchemaObjectError};
    use crate::{ArtifactLimits, TypeDescriptor};

    fn limits(limit: u64) -> ArtifactLimits {
        ArtifactLimits {
            package_source_manifest_bytes: limit,
            canonical_ir_bytes: limit,
            source_map_bytes: limit,
            generated_schema_bytes: limit,
        }
    }

    #[test]
    fn schema_objects_are_deduplicated_ordered_and_bounded() {
        let entries = vec![
            (
                TypeDescriptor::BOOL,
                Arc::from(&b"{\"type\":\"boolean\"}"[..]),
            ),
            (
                TypeDescriptor::STRING,
                Arc::from(&b"{\"type\":\"string\"}"[..]),
            ),
        ];
        let object = GeneratedSchemaObject::new(entries.clone(), limits(4_096));
        assert!(object.is_ok());
        let object = object.unwrap_or_else(|_| unreachable!("checked above"));
        assert_eq!(
            std::str::from_utf8(object.artifact().canonical_bytes()),
            Ok("{\"Bool\":{\"type\":\"boolean\"},\"String\":{\"type\":\"string\"}}")
        );

        assert_eq!(
            GeneratedSchemaObject::new(vec![entries[0].clone(), entries[0].clone()], limits(4_096)),
            Err(SchemaObjectError::NoncanonicalOrder)
        );
        assert_eq!(
            GeneratedSchemaObject::new(
                vec![
                    (
                        TypeDescriptor::STRING,
                        Arc::from(&b"{\"type\":\"string\"}"[..])
                    ),
                    (
                        TypeDescriptor::BOOL,
                        Arc::from(&b"{\"type\":\"boolean\"}"[..])
                    ),
                ],
                limits(4_096),
            ),
            Err(SchemaObjectError::NoncanonicalOrder)
        );
        assert!(matches!(
            GeneratedSchemaObject::new(entries, limits(1)),
            Err(SchemaObjectError::Encoding(ArtifactEncodingError::ResourceLimit(error)))
                if error.code == FrontendResourceCode::GeneratedSchemaByteLimit
        ));
    }

    use crate::ArtifactEncodingError;
}
