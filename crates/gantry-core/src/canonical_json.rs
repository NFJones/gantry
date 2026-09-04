//! Iterative RFC 8785 encoding and SHA-256 identities for admitted JSON trees.

use std::cmp::Ordering;
use std::sync::Arc;

use sha2::{Digest, Sha256};

use crate::numeric::canonical_binary64;
use crate::strict_json::{JsonNode, JsonNodeId, NumberError, StrictJsonDocument};

/// Complete RFC 8785 canonical bytes and their exact SHA-256 identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalJson {
    bytes: Arc<[u8]>,
    sha256: [u8; 32],
}

impl CanonicalJson {
    /// Canonicalizes one admitted strict JSON tree without recursive host calls.
    pub fn from_document(document: &StrictJsonDocument) -> Result<Self, CanonicalJsonError> {
        let bytes = encode_node(document, document.root())?;
        Ok(Self::from_encoded_bytes(bytes))
    }

    /// Canonicalizes one admitted strict JSON subtree without recursive host calls.
    pub fn from_node(
        document: &StrictJsonDocument,
        root: JsonNodeId,
    ) -> Result<Self, CanonicalJsonError> {
        let bytes = encode_node(document, root)?;
        Ok(Self::from_encoded_bytes(bytes))
    }

    /// Retains already canonical bytes and computes their exact SHA-256 identity.
    pub(crate) fn from_encoded_bytes(bytes: Vec<u8>) -> Self {
        let sha256 = Sha256::digest(&bytes).into();
        Self {
            bytes: Arc::from(bytes),
            sha256,
        }
    }

    /// Returns the complete RFC 8785 UTF-8 encoding.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns lowercase SHA-256 over exactly the canonical bytes.
    #[must_use]
    pub fn sha256_hex(&self) -> String {
        self.sha256
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
}

/// Failure while canonicalizing an already admitted strict JSON tree.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CanonicalJsonError {
    /// An arena edge does not resolve inside its owning document.
    InvalidNode,
    /// A number cannot be represented as finite binary64.
    Number(NumberError),
}

enum EncodeTask {
    Node(JsonNodeId),
    Byte(u8),
    String(Arc<str>),
}

fn encode_node(
    document: &StrictJsonDocument,
    root: JsonNodeId,
) -> Result<Vec<u8>, CanonicalJsonError> {
    let mut output = Vec::new();
    let mut work = vec![EncodeTask::Node(root)];
    while let Some(task) = work.pop() {
        match task {
            EncodeTask::Byte(byte) => output.push(byte),
            EncodeTask::String(value) => push_json_string(&mut output, &value),
            EncodeTask::Node(id) => {
                match document.node(id).ok_or(CanonicalJsonError::InvalidNode)? {
                    JsonNode::Null => output.extend_from_slice(b"null"),
                    JsonNode::Bool(true) => output.extend_from_slice(b"true"),
                    JsonNode::Bool(false) => output.extend_from_slice(b"false"),
                    JsonNode::Number(number) => {
                        let value = number
                            .to_gantry_float()
                            .map_err(CanonicalJsonError::Number)?;
                        output.extend_from_slice(canonical_binary64(value).as_bytes());
                    }
                    JsonNode::String(value) => push_json_string(&mut output, value),
                    JsonNode::Array(items) => {
                        output.push(b'[');
                        let mut sequence = Vec::with_capacity(items.len().saturating_mul(2));
                        for (index, item) in items.iter().copied().enumerate() {
                            if index > 0 {
                                sequence.push(EncodeTask::Byte(b','));
                            }
                            sequence.push(EncodeTask::Node(item));
                        }
                        sequence.push(EncodeTask::Byte(b']'));
                        work.extend(sequence.into_iter().rev());
                    }
                    JsonNode::Object(members) => {
                        output.push(b'{');
                        let mut members = members.clone();
                        members.sort_by(|left, right| utf16_cmp(&left.0, &right.0));
                        let mut sequence = Vec::with_capacity(members.len().saturating_mul(4));
                        for (index, (name, value)) in members.into_iter().enumerate() {
                            if index > 0 {
                                sequence.push(EncodeTask::Byte(b','));
                            }
                            sequence.push(EncodeTask::String(name));
                            sequence.push(EncodeTask::Byte(b':'));
                            sequence.push(EncodeTask::Node(value));
                        }
                        sequence.push(EncodeTask::Byte(b'}'));
                        work.extend(sequence.into_iter().rev());
                    }
                }
            }
        }
    }
    Ok(output)
}

fn utf16_cmp(left: &str, right: &str) -> Ordering {
    left.encode_utf16().cmp(right.encode_utf16())
}

fn push_json_string(output: &mut Vec<u8>, value: &str) {
    output.push(b'"');
    for scalar in value.chars() {
        match scalar {
            '"' => output.extend_from_slice(b"\\\""),
            '\\' => output.extend_from_slice(b"\\\\"),
            '\u{08}' => output.extend_from_slice(b"\\b"),
            '\u{09}' => output.extend_from_slice(b"\\t"),
            '\u{0a}' => output.extend_from_slice(b"\\n"),
            '\u{0c}' => output.extend_from_slice(b"\\f"),
            '\u{0d}' => output.extend_from_slice(b"\\r"),
            value if value <= '\u{1f}' => {
                output.extend_from_slice(format!("\\u{:04x}", value as u32).as_bytes());
            }
            value => {
                let mut encoded = [0_u8; 4];
                output.extend_from_slice(value.encode_utf8(&mut encoded).as_bytes());
            }
        }
    }
    output.push(b'"');
}

#[cfg(test)]
mod tests {
    use super::CanonicalJson;
    use crate::strict_json::{JsonLimits, StrictJsonDocument};

    fn decode(source: &[u8], depth: u64, nodes: u64) -> StrictJsonDocument {
        StrictJsonDocument::decode(
            source,
            JsonLimits {
                maximum_bytes: u64::try_from(source.len())
                    .unwrap_or_else(|_| unreachable!("fixture length fits")),
                maximum_nesting_depth: depth,
                maximum_nodes: nodes,
                maximum_string_scalars: 1_000_000,
                maximum_list_items: 1_000_000,
            },
        )
        .unwrap_or_else(|error| panic!("strict JSON fixture failed: {error:?}"))
    }

    #[test]
    fn canonicalization_sorts_utf16_keys_numbers_and_escapes() {
        let document = decode(
            &br#"{"\uE000":1e20,"\uD800\uDC00":1e21,"text":"\u000f\n\"\\"}"#[..],
            2,
            4,
        );
        let canonical = CanonicalJson::from_document(&document)
            .unwrap_or_else(|error| panic!("canonicalization failed: {error:?}"));
        assert_eq!(
            std::str::from_utf8(canonical.bytes()),
            Ok("{\"text\":\"\\u000f\\n\\\"\\\\\",\"𐀀\":1e+21,\"\":100000000000000000000}")
        );
        assert_eq!(canonical.sha256_hex().len(), 64);
    }

    #[test]
    fn canonicalization_is_stack_safe_for_deep_admitted_trees() {
        let depth = 10_000;
        let mut source = "[".repeat(depth);
        source.push_str("null");
        source.push_str(&"]".repeat(depth));
        let document = decode(source.as_bytes(), depth as u64 + 1, depth as u64 + 1);
        let canonical = CanonicalJson::from_document(&document)
            .unwrap_or_else(|error| panic!("canonicalization failed: {error:?}"));
        assert_eq!(canonical.bytes(), source.as_bytes());
    }
}
