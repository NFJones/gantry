//! Closed Gantry v1 type algebra and canonical descriptors.

use std::fmt;

use crate::CanonicalPath;
use crate::generated::TypeKind;

/// One well-formed Gantry v1 type descriptor.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TypeDescriptor {
    kind: TypeKind,
    tokens: Vec<TypeToken>,
    contains_sealed_boundary: bool,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
enum TypeToken {
    Primitive(TypeKind),
    Declared(CanonicalPath),
    Open(TypeKind),
    Comma,
    Close,
}

impl TypeDescriptor {
    /// The sealed `Unit` type.
    pub const UNIT: Self = Self::primitive(TypeKind::Unit, false);
    /// The sealed `Bool` type.
    pub const BOOL: Self = Self::primitive(TypeKind::Bool, false);
    /// The sealed `Int` type.
    pub const INT: Self = Self::primitive(TypeKind::Int, false);
    /// The sealed `Float` type.
    pub const FLOAT: Self = Self::primitive(TypeKind::Float, false);
    /// The sealed `String` type.
    pub const STRING: Self = Self::primitive(TypeKind::String, false);
    /// The sealed `Decision` type.
    pub const DECISION: Self = Self::primitive(TypeKind::Decision, true);
    /// The sealed `OperationError` type.
    pub const OPERATION_ERROR: Self = Self::primitive(TypeKind::OperationError, true);

    const fn primitive(kind: TypeKind, contains_sealed_boundary: bool) -> Self {
        Self {
            kind,
            tokens: Vec::new(),
            contains_sealed_boundary,
        }
    }

    /// Constructs one declared struct or enum type.
    #[must_use]
    pub fn declared(path: CanonicalPath) -> Self {
        Self {
            kind: TypeKind::Declared,
            tokens: vec![TypeToken::Declared(path)],
            contains_sealed_boundary: false,
        }
    }

    /// Returns the canonical path when this is a declared package type.
    #[must_use]
    pub fn declared_path(&self) -> Option<&CanonicalPath> {
        match self.tokens.first() {
            Some(TypeToken::Declared(path)) => Some(path),
            _ => None,
        }
    }

    /// Constructs `Option<T>`, rejecting the two wire-ambiguous immediate members.
    pub fn option(member: Self) -> Result<Self, TypeDescriptorError> {
        if matches!(member.kind, TypeKind::Unit | TypeKind::Option) {
            return Err(TypeDescriptorError::InvalidOptionMember);
        }
        let contains_sealed_boundary = member.contains_sealed_boundary;
        let mut tokens = vec![TypeToken::Open(TypeKind::Option)];
        tokens.extend(member.into_tokens());
        tokens.push(TypeToken::Close);
        Ok(Self {
            kind: TypeKind::Option,
            tokens,
            contains_sealed_boundary,
        })
    }

    /// Constructs `Result<T,E>`.
    #[must_use]
    pub fn result(ok: Self, error: Self) -> Self {
        let contains_sealed_boundary =
            ok.contains_sealed_boundary || error.contains_sealed_boundary;
        let mut tokens = vec![TypeToken::Open(TypeKind::Result)];
        tokens.extend(ok.into_tokens());
        tokens.push(TypeToken::Comma);
        tokens.extend(error.into_tokens());
        tokens.push(TypeToken::Close);
        Self {
            kind: TypeKind::Result,
            tokens,
            contains_sealed_boundary,
        }
    }

    /// Constructs `List<T>`.
    #[must_use]
    pub fn list(member: Self) -> Self {
        let contains_sealed_boundary = member.contains_sealed_boundary;
        let mut tokens = vec![TypeToken::Open(TypeKind::List)];
        tokens.extend(member.into_tokens());
        tokens.push(TypeToken::Close);
        Self {
            kind: TypeKind::List,
            tokens,
            contains_sealed_boundary,
        }
    }

    /// Constructs a fixed tuple with at least two members.
    pub fn tuple(members: Vec<Self>) -> Result<Self, TypeDescriptorError> {
        if members.len() < 2 {
            return Err(TypeDescriptorError::TupleArity);
        }
        let contains_sealed_boundary = members.iter().any(|member| member.contains_sealed_boundary);
        let mut tokens = vec![TypeToken::Open(TypeKind::Tuple)];
        for (index, member) in members.into_iter().enumerate() {
            if index > 0 {
                tokens.push(TypeToken::Comma);
            }
            tokens.extend(member.into_tokens());
        }
        tokens.push(TypeToken::Close);
        Ok(Self {
            kind: TypeKind::Tuple,
            tokens,
            contains_sealed_boundary,
        })
    }

    /// Returns whether this type recursively contains a sealed judgment or operation error.
    #[must_use]
    pub const fn contains_sealed_boundary(&self) -> bool {
        self.contains_sealed_boundary
    }

    /// Returns the outermost closed type kind.
    #[must_use]
    pub const fn kind(&self) -> TypeKind {
        self.kind
    }

    /// Returns the immediate members of one constructed type.
    ///
    /// Primitive and declared types have no members. The flat token walk is
    /// independent of descriptor nesting depth and does not recurse.
    #[must_use]
    pub fn immediate_members(&self) -> Vec<Self> {
        if self.tokens.len() < 3 || !matches!(self.tokens.first(), Some(TypeToken::Open(_))) {
            return Vec::new();
        }
        let mut members = Vec::new();
        let mut start = 1_usize;
        let mut depth = 0_usize;
        for index in 1..self.tokens.len().saturating_sub(1) {
            match &self.tokens[index] {
                TypeToken::Open(_) => depth = depth.saturating_add(1),
                TypeToken::Close => depth = depth.saturating_sub(1),
                TypeToken::Comma if depth == 0 => {
                    if let Some(member) = Self::from_token_slice(&self.tokens[start..index]) {
                        members.push(member);
                    }
                    start = index.saturating_add(1);
                }
                _ => {}
            }
        }
        if let Some(member) = Self::from_token_slice(
            self.tokens
                .get(start..self.tokens.len().saturating_sub(1))
                .unwrap_or_default(),
        ) {
            members.push(member);
        }
        members
    }

    /// Encodes the exact whitespace-free canonical descriptor without native recursion.
    #[must_use]
    pub fn canonical_string(&self) -> String {
        let mut output = String::new();
        if self.tokens.is_empty() {
            output.push_str(self.kind.wire_name());
            return output;
        }
        for token in &self.tokens {
            match token {
                TypeToken::Primitive(kind) => output.push_str(kind.wire_name()),
                TypeToken::Declared(path) => output.push_str(path.as_str()),
                TypeToken::Open(kind) => {
                    output.push_str(kind.wire_name());
                    output.push('<');
                }
                TypeToken::Comma => output.push(','),
                TypeToken::Close => output.push('>'),
            }
        }
        output
    }

    fn into_tokens(self) -> Vec<TypeToken> {
        if self.tokens.is_empty() {
            vec![TypeToken::Primitive(self.kind)]
        } else {
            self.tokens
        }
    }

    fn from_token_slice(tokens: &[TypeToken]) -> Option<Self> {
        let kind = match tokens.first()? {
            TypeToken::Primitive(kind) | TypeToken::Open(kind) => *kind,
            TypeToken::Declared(_) => TypeKind::Declared,
            TypeToken::Comma | TypeToken::Close => return None,
        };
        let contains_sealed_boundary = tokens.iter().any(|token| {
            matches!(
                token,
                TypeToken::Primitive(TypeKind::Decision | TypeKind::OperationError)
            )
        });
        let tokens = if tokens.len() == 1 && matches!(tokens[0], TypeToken::Primitive(_)) {
            Vec::new()
        } else {
            tokens.to_vec()
        };
        Some(Self {
            kind,
            tokens,
            contains_sealed_boundary,
        })
    }
}

impl fmt::Display for TypeDescriptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.canonical_string())
    }
}

/// Rejection of an ill-formed constructed type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TypeDescriptorError {
    /// `Option<Unit>` and an immediate nested `Option` are wire-ambiguous.
    InvalidOptionMember,
    /// A tuple has fewer than two members.
    TupleArity,
}

impl fmt::Display for TypeDescriptorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidOptionMember => "option member is not permitted",
            Self::TupleArity => "tuple requires at least two members",
        })
    }
}

impl std::error::Error for TypeDescriptorError {}

#[cfg(test)]
mod tests {
    use super::{TypeDescriptor, TypeDescriptorError};
    use crate::CanonicalPath;

    #[test]
    fn canonical_descriptors_cover_the_closed_type_algebra() {
        let report = TypeDescriptor::declared(
            CanonicalPath::new("crate::domain::Report")
                .unwrap_or_else(|_| unreachable!("constant path is canonical")),
        );
        let pair = TypeDescriptor::tuple(vec![TypeDescriptor::INT, TypeDescriptor::STRING]);
        assert!(pair.is_ok());
        let result = TypeDescriptor::result(
            TypeDescriptor::list(report.clone()),
            TypeDescriptor::option(TypeDescriptor::STRING)
                .unwrap_or_else(|_| unreachable!("String is an option member")),
        );
        assert_eq!(
            result.canonical_string(),
            "Result<List<crate::domain::Report>,Option<String>>"
        );
        assert_eq!(
            report.declared_path().map(CanonicalPath::as_str),
            Some("crate::domain::Report")
        );
        assert_eq!(TypeDescriptor::STRING.declared_path(), None);
    }

    #[test]
    fn rejects_ambiguous_options_and_short_tuples() {
        assert_eq!(
            TypeDescriptor::option(TypeDescriptor::UNIT),
            Err(TypeDescriptorError::InvalidOptionMember)
        );
        let nested = TypeDescriptor::option(TypeDescriptor::STRING)
            .unwrap_or_else(|_| unreachable!("String is an option member"));
        assert_eq!(
            TypeDescriptor::option(nested),
            Err(TypeDescriptorError::InvalidOptionMember)
        );
        assert_eq!(
            TypeDescriptor::tuple(vec![TypeDescriptor::INT]),
            Err(TypeDescriptorError::TupleArity)
        );
    }

    #[test]
    fn deep_descriptors_encode_without_native_recursion() {
        let mut value = TypeDescriptor::INT;
        for _ in 0..10_000 {
            value = TypeDescriptor::list(value);
        }
        let encoded = value.canonical_string();
        assert!(encoded.starts_with("List<List<List<"));
        assert!(encoded.ends_with(">>>"));
    }

    #[test]
    fn constructed_members_are_recovered_from_flat_tokens() {
        let value = TypeDescriptor::result(
            TypeDescriptor::list(TypeDescriptor::INT),
            TypeDescriptor::option(TypeDescriptor::STRING)
                .unwrap_or_else(|_| unreachable!("String is an option member")),
        );
        let members = value.immediate_members();
        assert_eq!(members.len(), 2);
        assert_eq!(members[0].canonical_string(), "List<Int>");
        assert_eq!(members[1].canonical_string(), "Option<String>");
        assert_eq!(members[1].immediate_members(), [TypeDescriptor::STRING]);
        assert!(TypeDescriptor::INT.immediate_members().is_empty());
    }
}
