//! Versioned canonical key identities for the sealed portable scalar domain.

use std::cmp::Ordering;
use std::sync::Arc;

use sha2::{Digest, Sha256};

use crate::numeric::{GantryFloat, GantryInt};
use crate::value::{LogicalValue, LogicalValueView, ValueKind};

const MAGIC: &[u8; 8] = b"GNTYKEY\0";
const HEADER_BYTES: u64 = 21;

/// Canonical scalar-key format major version.
pub const CANONICAL_KEY_FORMAT_MAJOR: u16 = 1;
/// Canonical scalar-key format minor version.
pub const CANONICAL_KEY_FORMAT_MINOR: u16 = 0;

/// Default maximum for one complete canonical scalar key.
///
/// This admits the largest String allowed by [`crate::value::DEFAULT_VALUE_LIMITS`]
/// when every scalar requires four UTF-8 bytes, plus the fixed frame.
pub const DEFAULT_CANONICAL_KEY_LIMITS: CanonicalKeyLimits = CanonicalKeyLimits {
    maximum_bytes: 4_194_325,
};

/// Finite positive byte limit for one complete canonical scalar key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CanonicalKeyLimits {
    maximum_bytes: u64,
}

impl CanonicalKeyLimits {
    /// Constructs a limit, rejecting zero because every key limit is positive.
    #[must_use]
    pub const fn new(maximum_bytes: u64) -> Option<Self> {
        if maximum_bytes == 0 {
            None
        } else {
            Some(Self { maximum_bytes })
        }
    }

    /// Returns the maximum complete framed-key byte length.
    #[must_use]
    pub const fn maximum_bytes(self) -> u64 {
        self.maximum_bytes
    }
}

/// Failure to admit a logical value into the canonical scalar-key domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CanonicalKeyError {
    /// The value is structural or belongs to a sealed non-key domain.
    IneligibleKind(ValueKind),
    /// The frame does not begin with the canonical scalar-key magic bytes.
    InvalidMagic,
    /// The frame names a format version this decoder does not support.
    UnsupportedVersion {
        /// Encoded format major version.
        major: u16,
        /// Encoded format minor version.
        minor: u16,
    },
    /// The frame contains an unknown scalar tag.
    UnknownTag(u8),
    /// The frame is shorter than its header or declared payload length.
    InvalidFrameLength,
    /// Bytes remain after the declared payload.
    TrailingData,
    /// The payload length is not canonical for its scalar tag.
    InvalidPayloadLength,
    /// A Bool payload is neither zero nor one.
    InvalidBool,
    /// An Int payload is outside the portable Gantry range.
    InvalidInt,
    /// A Float payload encodes infinity or NaN.
    NonFiniteFloat,
    /// A Float payload encodes negative zero instead of normalized positive zero.
    NonCanonicalNegativeZero,
    /// A String payload is not valid UTF-8.
    InvalidUtf8,
    /// The complete versioned frame exceeds the effective byte limit.
    ResourceLimit {
        /// Effective configured maximum.
        limit: u64,
        /// Exact required complete frame length.
        required: u64,
    },
}

/// Canonical bytes, deterministic content hash, and total order for one scalar key.
///
/// Equality is exact byte equality. Ordering is the scalar contract's semantic
/// order rather than lexicographic frame order, and therefore reports equal
/// exactly when the admitted logical values compare equal.
#[derive(Clone, Debug)]
pub struct CanonicalKey {
    bytes: Arc<[u8]>,
    sha256: [u8; 32],
}

impl CanonicalKey {
    /// Admits and frames one eligible logical scalar under `limits`.
    pub fn from_value(
        value: &LogicalValue,
        limits: CanonicalKeyLimits,
    ) -> Result<Self, CanonicalKeyError> {
        let (tag, payload) = match value.view() {
            LogicalValueView::Unit => (0_u8, Payload::Empty),
            LogicalValueView::Bool(value) => (1, Payload::Bool([u8::from(value)])),
            LogicalValueView::Int(value) => (2, Payload::Fixed(value.get().to_be_bytes())),
            LogicalValueView::Float(value) => {
                (3, Payload::Fixed(value.get().to_bits().to_be_bytes()))
            }
            LogicalValueView::String(value) => (4, Payload::String(value)),
            _ => return Err(CanonicalKeyError::IneligibleKind(value.kind())),
        };
        let payload_length = u64::try_from(payload.bytes().len()).unwrap_or(u64::MAX);
        let required = HEADER_BYTES.saturating_add(payload_length);
        if required > limits.maximum_bytes {
            return Err(CanonicalKeyError::ResourceLimit {
                limit: limits.maximum_bytes,
                required,
            });
        }

        let mut bytes =
            Vec::with_capacity(payload.bytes().len().saturating_add(HEADER_BYTES as usize));
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&CANONICAL_KEY_FORMAT_MAJOR.to_be_bytes());
        bytes.extend_from_slice(&CANONICAL_KEY_FORMAT_MINOR.to_be_bytes());
        bytes.push(tag);
        bytes.extend_from_slice(&payload_length.to_be_bytes());
        bytes.extend_from_slice(payload.bytes());
        let sha256 = Sha256::digest(&bytes).into();
        Ok(Self {
            bytes: Arc::from(bytes),
            sha256,
        })
    }

    /// Decodes one exact format-version-1.0 frame under `limits`.
    ///
    /// Validation rejects unsupported framing and every payload that cannot
    /// have been produced by [`Self::from_value`]. The input is retained and
    /// hashed only after its complete frame is valid.
    pub fn from_bytes(bytes: &[u8], limits: CanonicalKeyLimits) -> Result<Self, CanonicalKeyError> {
        let required = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        if required > limits.maximum_bytes {
            return Err(CanonicalKeyError::ResourceLimit {
                limit: limits.maximum_bytes,
                required,
            });
        }
        if bytes.len() < HEADER_BYTES as usize {
            return Err(CanonicalKeyError::InvalidFrameLength);
        }
        if &bytes[..MAGIC.len()] != MAGIC {
            return Err(CanonicalKeyError::InvalidMagic);
        }

        let major = u16::from_be_bytes([bytes[8], bytes[9]]);
        let minor = u16::from_be_bytes([bytes[10], bytes[11]]);
        if (major, minor) != (CANONICAL_KEY_FORMAT_MAJOR, CANONICAL_KEY_FORMAT_MINOR) {
            return Err(CanonicalKeyError::UnsupportedVersion { major, minor });
        }

        let tag = bytes[12];
        if tag > 4 {
            return Err(CanonicalKeyError::UnknownTag(tag));
        }
        let payload_length = u64::from_be_bytes([
            bytes[13], bytes[14], bytes[15], bytes[16], bytes[17], bytes[18], bytes[19], bytes[20],
        ]);
        let actual_payload_length = required - HEADER_BYTES;
        if actual_payload_length < payload_length {
            return Err(CanonicalKeyError::InvalidFrameLength);
        }
        if actual_payload_length > payload_length {
            return Err(CanonicalKeyError::TrailingData);
        }

        let payload = &bytes[HEADER_BYTES as usize..];
        validate_payload(tag, payload)?;
        let sha256 = Sha256::digest(bytes).into();
        Ok(Self {
            bytes: Arc::from(bytes),
            sha256,
        })
    }

    /// Returns the complete canonical versioned frame.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the SHA-256 digest over exactly [`Self::bytes`].
    #[must_use]
    pub const fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }

    /// Returns lowercase hexadecimal SHA-256 over exactly [`Self::bytes`].
    #[must_use]
    pub fn sha256_hex(&self) -> String {
        self.sha256
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
}

enum Payload<'a> {
    Empty,
    Bool([u8; 1]),
    Fixed([u8; 8]),
    String(&'a str),
}

impl Payload<'_> {
    fn bytes(&self) -> &[u8] {
        match self {
            Self::Empty => &[],
            Self::Bool(bytes) => bytes,
            Self::Fixed(bytes) => bytes,
            Self::String(value) => value.as_bytes(),
        }
    }
}

fn validate_payload(tag: u8, payload: &[u8]) -> Result<(), CanonicalKeyError> {
    let expected_length = match tag {
        0 => 0,
        1 => 1,
        2 | 3 => 8,
        4 => payload.len(),
        _ => unreachable!("the scalar tag was validated before its payload"),
    };
    if payload.len() != expected_length {
        return Err(CanonicalKeyError::InvalidPayloadLength);
    }
    match tag {
        0 => {}
        1 if payload[0] > 1 => return Err(CanonicalKeyError::InvalidBool),
        1 => {}
        2 if GantryInt::new(decode_i64(payload)).is_none() => {
            return Err(CanonicalKeyError::InvalidInt);
        }
        2 => {}
        3 => {
            let value = decode_f64(payload);
            if !value.is_finite() {
                return Err(CanonicalKeyError::NonFiniteFloat);
            }
            if value.to_bits() == (-0.0_f64).to_bits() {
                return Err(CanonicalKeyError::NonCanonicalNegativeZero);
            }
            debug_assert!(GantryFloat::new(value).is_some());
        }
        4 if std::str::from_utf8(payload).is_err() => {
            return Err(CanonicalKeyError::InvalidUtf8);
        }
        4 => {}
        _ => unreachable!("the scalar tag was validated before its payload"),
    }
    Ok(())
}

impl PartialEq for CanonicalKey {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl Eq for CanonicalKey {}

impl PartialOrd for CanonicalKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CanonicalKey {
    fn cmp(&self, other: &Self) -> Ordering {
        let tag_order = self.bytes[12].cmp(&other.bytes[12]);
        if tag_order != Ordering::Equal {
            return tag_order;
        }
        let left = &self.bytes[HEADER_BYTES as usize..];
        let right = &other.bytes[HEADER_BYTES as usize..];
        match self.bytes[12] {
            0 => Ordering::Equal,
            1 | 4 => left.cmp(right),
            2 => decode_i64(left).cmp(&decode_i64(right)),
            3 => decode_f64(left).total_cmp(&decode_f64(right)),
            _ => unreachable!("canonical keys contain a known scalar tag"),
        }
    }
}

fn decode_i64(bytes: &[u8]) -> i64 {
    i64::from_be_bytes(
        bytes
            .try_into()
            .unwrap_or_else(|_| unreachable!("canonical Int payload is eight bytes")),
    )
}

fn decode_f64(bytes: &[u8]) -> f64 {
    f64::from_bits(u64::from_be_bytes(bytes.try_into().unwrap_or_else(|_| {
        unreachable!("canonical Float payload is eight bytes")
    })))
}
