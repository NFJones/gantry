//! Strict Gantry protocol identities and deterministic identity derivation.

use std::fmt;

use sha2::{Digest, Sha256};

use crate::portable::{IdentityKind, IdentityOrigin};

const IDENTITY_BYTES: usize = 32;
const IDENTITY_HEX_BYTES: usize = IDENTITY_BYTES * 2;

/// One validated Gantry occurrence identity.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProtocolIdentity {
    kind: IdentityKind,
    material: [u8; IDENTITY_BYTES],
}

impl ProtocolIdentity {
    /// Constructs an identity from fresh source material.
    ///
    /// Only kinds whose catalog origin admits fresh material are accepted.
    pub fn from_fresh_material(
        kind: IdentityKind,
        material: [u8; IDENTITY_BYTES],
    ) -> Result<Self, IdentityError> {
        if !matches!(
            kind.origin(),
            IdentityOrigin::Fresh | IdentityOrigin::FreshOrDerived
        ) {
            return Err(IdentityError::WrongOrigin);
        }
        Ok(Self { kind, material })
    }

    /// Constructs a storage-assigned evidence identity.
    pub const fn from_storage_material(material: [u8; IDENTITY_BYTES]) -> Self {
        Self {
            kind: IdentityKind::Evidence,
            material,
        }
    }

    /// Derives a task, operation, or non-root session identity.
    ///
    /// `canonical_key` must be the exact RFC 8785 bytes of the applicable
    /// published identity-key object. Canonical JSON construction is owned by
    /// the value kernel; this function owns only the specified framing/hash.
    pub fn derive(kind: IdentityKind, canonical_key: &[u8]) -> Result<Self, IdentityError> {
        if !matches!(
            kind,
            IdentityKind::Task | IdentityKind::Operation | IdentityKind::Session
        ) {
            return Err(IdentityError::WrongOrigin);
        }
        let mut hasher = Sha256::new();
        hasher.update(b"gantry-v1-identity\0");
        hasher.update(kind.wire_name().as_bytes());
        hasher.update([0]);
        hasher.update(canonical_key);
        let material: [u8; IDENTITY_BYTES] = hasher.finalize().into();
        Ok(Self { kind, material })
    }

    /// Parses one exact `KIND:HEX` wire value.
    pub fn parse(value: &str) -> Result<Self, IdentityError> {
        let (kind, hexadecimal) = value
            .split_once(':')
            .ok_or(IdentityError::MissingSeparator)?;
        if hexadecimal.contains(':') {
            return Err(IdentityError::InvalidLength);
        }
        let kind = IdentityKind::from_wire_name(kind).ok_or(IdentityError::UnknownKind)?;
        let material = decode_lower_hex(hexadecimal)?;
        Ok(Self { kind, material })
    }

    /// Parses one identity and requires the expected kind.
    pub fn parse_kind(value: &str, expected: IdentityKind) -> Result<Self, IdentityError> {
        let identity = Self::parse(value)?;
        if identity.kind != expected {
            return Err(IdentityError::KindMismatch);
        }
        Ok(identity)
    }

    /// Returns the identity kind.
    #[must_use]
    pub const fn kind(self) -> IdentityKind {
        self.kind
    }

    /// Returns the exact 256-bit identity material.
    #[must_use]
    pub const fn material(self) -> [u8; IDENTITY_BYTES] {
        self.material
    }
}

impl fmt::Display for ProtocolIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.kind.wire_name())?;
        formatter.write_str(":")?;
        for byte in self.material {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Failure to decode or construct a protocol identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityError {
    /// The kind/material separator is absent.
    MissingSeparator,
    /// The kind token is not in the closed catalog.
    UnknownKind,
    /// The hexadecimal portion does not contain exactly 64 bytes.
    InvalidLength,
    /// The hexadecimal portion is not lowercase hexadecimal.
    InvalidHexadecimal,
    /// The parsed kind differs from the field's required kind.
    KindMismatch,
    /// The requested construction path is invalid for this kind.
    WrongOrigin,
}

impl fmt::Display for IdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::MissingSeparator => "identity is missing its kind separator",
            Self::UnknownKind => "identity has an unknown kind",
            Self::InvalidLength => "identity does not contain 64 hexadecimal digits",
            Self::InvalidHexadecimal => "identity material is not lowercase hexadecimal",
            Self::KindMismatch => "identity kind does not match the typed field",
            Self::WrongOrigin => "identity kind cannot use this construction path",
        })
    }
}

impl std::error::Error for IdentityError {}

pub(crate) fn decode_lower_hex(value: &str) -> Result<[u8; IDENTITY_BYTES], IdentityError> {
    if value.len() != IDENTITY_HEX_BYTES {
        return Err(IdentityError::InvalidLength);
    }
    let mut output = [0_u8; IDENTITY_BYTES];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (decode_nibble(pair[0])? << 4) | decode_nibble(pair[1])?;
    }
    Ok(output)
}

fn decode_nibble(byte: u8) -> Result<u8, IdentityError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(IdentityError::InvalidHexadecimal),
    }
}

#[cfg(test)]
mod tests {
    use super::{IdentityError, ProtocolIdentity};
    use crate::portable::IdentityKind;

    #[test]
    fn wire_round_trip_is_exact() {
        let identity = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0xab; 32]);
        assert!(identity.is_ok());
        let identity = identity.unwrap_or_else(|_| unreachable!("checked above"));
        let wire = identity.to_string();
        assert_eq!(wire, format!("execution:{}", "ab".repeat(32)));
        assert_eq!(ProtocolIdentity::parse(&wire), Ok(identity));
    }

    #[test]
    fn rejects_wrong_kind_case_and_length() {
        let valid = format!("execution:{}", "00".repeat(32));
        assert_eq!(
            ProtocolIdentity::parse_kind(&valid, IdentityKind::Event),
            Err(IdentityError::KindMismatch)
        );
        assert_eq!(
            ProtocolIdentity::parse(&format!("execution:{}", "AA".repeat(32))),
            Err(IdentityError::InvalidHexadecimal)
        );
        assert_eq!(
            ProtocolIdentity::parse("execution:00"),
            Err(IdentityError::InvalidLength)
        );
    }

    #[test]
    fn derivation_uses_the_specified_framing() {
        let identity = ProtocolIdentity::derive(IdentityKind::Task, b"{}");
        assert!(identity.is_ok());
        let identity = identity.unwrap_or_else(|_| unreachable!("checked above"));
        assert_eq!(identity.kind(), IdentityKind::Task);
        assert_eq!(identity.material().len(), 32);
        assert_eq!(
            ProtocolIdentity::derive(IdentityKind::Execution, b"{}"),
            Err(IdentityError::WrongOrigin)
        );
    }
}
