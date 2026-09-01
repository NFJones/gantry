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
    OpenDeclared(CanonicalPath),
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

    /// Constructs one closed declared type with ordered concrete arguments.
    #[must_use]
    pub fn declared_with_arguments(path: CanonicalPath, arguments: Vec<Self>) -> Self {
        if arguments.is_empty() {
            return Self::declared(path);
        }
        let contains_sealed_boundary = arguments
            .iter()
            .any(|argument| argument.contains_sealed_boundary);
        let mut tokens = vec![TypeToken::OpenDeclared(path)];
        for (index, argument) in arguments.into_iter().enumerate() {
            if index > 0 {
                tokens.push(TypeToken::Comma);
            }
            tokens.extend(argument.into_tokens());
        }
        tokens.push(TypeToken::Close);
        Self {
            kind: TypeKind::Declared,
            tokens,
            contains_sealed_boundary,
        }
    }

    /// Returns the canonical path when this is a declared package type.
    #[must_use]
    pub fn declared_path(&self) -> Option<&CanonicalPath> {
        match self.tokens.first() {
            Some(TypeToken::Declared(path) | TypeToken::OpenDeclared(path)) => Some(path),
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
        if self.tokens.len() < 3
            || !matches!(
                self.tokens.first(),
                Some(TypeToken::Open(_) | TypeToken::OpenDeclared(_))
            )
        {
            return Vec::new();
        }
        let mut members = Vec::new();
        let mut start = 1_usize;
        let mut depth = 0_usize;
        for index in 1..self.tokens.len().saturating_sub(1) {
            match &self.tokens[index] {
                TypeToken::Open(_) | TypeToken::OpenDeclared(_) => {
                    depth = depth.saturating_add(1);
                }
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
                TypeToken::OpenDeclared(path) => {
                    output.push_str(path.as_str());
                    output.push('<');
                }
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

    /// Decodes one exact canonical descriptor without native recursion.
    ///
    /// Use [`Self::from_canonical_string_with_depth_limit`] when decoding is
    /// governed by one frontend activity's constructed-type policy.
    pub fn from_canonical_string(value: &str) -> Result<Self, TypeDescriptorError> {
        Self::from_canonical_string_with_depth_limit(value, u64::MAX)
    }

    /// Decodes one exact canonical descriptor under an inclusive depth limit.
    pub fn from_canonical_string_with_depth_limit(
        value: &str,
        maximum_constructed_type_depth: u64,
    ) -> Result<Self, TypeDescriptorError> {
        if value.is_empty() || value.bytes().any(|byte| byte.is_ascii_whitespace()) {
            return Err(TypeDescriptorError::InvalidCanonicalString);
        }
        let mut parser = DescriptorParser::new(value, maximum_constructed_type_depth);
        let descriptor = parser.parse().map_err(|error| match error {
            TypeDescriptorError::ConstructedTypeDepth { .. } => error,
            _ => TypeDescriptorError::InvalidCanonicalString,
        })?;
        if descriptor.canonical_string() != value {
            return Err(TypeDescriptorError::InvalidCanonicalString);
        }
        Ok(descriptor)
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
            TypeToken::Declared(_) | TypeToken::OpenDeclared(_) => TypeKind::Declared,
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
    /// Input is not one exact canonical v1 type descriptor.
    InvalidCanonicalString,
    /// A decoded descriptor exceeds the configured constructed-type depth.
    ConstructedTypeDepth {
        /// Configured inclusive maximum depth.
        limit: u64,
        /// First rejected depth.
        observed: u64,
    },
}

impl fmt::Display for TypeDescriptorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidOptionMember => "option member is not permitted",
            Self::TupleArity => "tuple requires at least two members",
            Self::InvalidCanonicalString => "type descriptor is not canonical",
            Self::ConstructedTypeDepth { .. } => {
                "type descriptor exceeds the constructed-type depth limit"
            }
        })
    }
}

impl std::error::Error for TypeDescriptorError {}

#[derive(Clone)]
enum ContainerKind {
    Option,
    Result,
    List,
    Tuple,
    Declared(CanonicalPath),
}

struct ContainerFrame {
    kind: ContainerKind,
    members: Vec<TypeDescriptor>,
}

struct DescriptorParser<'a> {
    source: &'a str,
    cursor: usize,
    frames: Vec<ContainerFrame>,
    value: Option<TypeDescriptor>,
    maximum_constructed_type_depth: u64,
}

impl<'a> DescriptorParser<'a> {
    fn new(source: &'a str, maximum_constructed_type_depth: u64) -> Self {
        Self {
            source,
            cursor: 0,
            frames: Vec::new(),
            value: None,
            maximum_constructed_type_depth,
        }
    }

    fn parse(&mut self) -> Result<TypeDescriptor, TypeDescriptorError> {
        loop {
            if self.value.is_none() {
                self.parse_atom()?;
                continue;
            }
            let value = self
                .value
                .take()
                .ok_or(TypeDescriptorError::InvalidCanonicalString)?;
            let delimiter = self.byte();
            let Some(frame) = self.frames.last_mut() else {
                if self.cursor == self.source.len() {
                    return Ok(value);
                }
                return Err(TypeDescriptorError::InvalidCanonicalString);
            };
            frame.members.push(value);
            match &frame.kind {
                ContainerKind::Option | ContainerKind::List => {
                    if frame.members.len() != 1 || delimiter != Some(b'>') {
                        return Err(TypeDescriptorError::InvalidCanonicalString);
                    }
                    self.cursor += 1;
                    self.close_frame()?;
                }
                ContainerKind::Result => match (frame.members.len(), delimiter) {
                    (1, Some(b',')) => self.cursor += 1,
                    (2, Some(b'>')) => {
                        self.cursor += 1;
                        self.close_frame()?;
                    }
                    _ => return Err(TypeDescriptorError::InvalidCanonicalString),
                },
                ContainerKind::Tuple => match delimiter {
                    Some(b',') => self.cursor += 1,
                    Some(b'>') if frame.members.len() >= 2 => {
                        self.cursor += 1;
                        self.close_frame()?;
                    }
                    _ => return Err(TypeDescriptorError::InvalidCanonicalString),
                },
                ContainerKind::Declared(_) => match delimiter {
                    Some(b',') => self.cursor += 1,
                    Some(b'>') if !frame.members.is_empty() => {
                        self.cursor += 1;
                        self.close_frame()?;
                    }
                    _ => return Err(TypeDescriptorError::InvalidCanonicalString),
                },
            }
        }
    }

    fn parse_atom(&mut self) -> Result<(), TypeDescriptorError> {
        self.check_depth()?;
        for (name, descriptor) in [
            ("Unit", Self::primitive(TypeDescriptor::UNIT)),
            ("Bool", Self::primitive(TypeDescriptor::BOOL)),
            ("Int", Self::primitive(TypeDescriptor::INT)),
            ("Float", Self::primitive(TypeDescriptor::FLOAT)),
            ("String", Self::primitive(TypeDescriptor::STRING)),
            ("Decision", Self::primitive(TypeDescriptor::DECISION)),
            (
                "OperationError",
                Self::primitive(TypeDescriptor::OPERATION_ERROR),
            ),
        ] {
            if self.consume_word(name) {
                self.value = Some(descriptor);
                return Ok(());
            }
        }
        for (prefix, kind) in [
            ("Option<", ContainerKind::Option),
            ("Result<", ContainerKind::Result),
            ("List<", ContainerKind::List),
            ("Tuple<", ContainerKind::Tuple),
        ] {
            if self.source[self.cursor..].starts_with(prefix) {
                self.cursor += prefix.len();
                self.frames.push(ContainerFrame {
                    kind,
                    members: Vec::new(),
                });
                return Ok(());
            }
        }
        let end = self.source[self.cursor..]
            .find([',', '>', '<'])
            .map_or(self.source.len(), |offset| self.cursor + offset);
        let path = self
            .source
            .get(self.cursor..end)
            .ok_or(TypeDescriptorError::InvalidCanonicalString)?;
        let path =
            CanonicalPath::new(path).map_err(|_| TypeDescriptorError::InvalidCanonicalString)?;
        self.cursor = end;
        if self.byte() == Some(b'<') {
            self.cursor += 1;
            self.frames.push(ContainerFrame {
                kind: ContainerKind::Declared(path),
                members: Vec::new(),
            });
        } else {
            self.value = Some(TypeDescriptor::declared(path));
        }
        Ok(())
    }

    fn close_frame(&mut self) -> Result<(), TypeDescriptorError> {
        let frame = self
            .frames
            .pop()
            .ok_or(TypeDescriptorError::InvalidCanonicalString)?;
        self.value = Some(match frame.kind {
            ContainerKind::Option => TypeDescriptor::option(
                frame
                    .members
                    .into_iter()
                    .next()
                    .ok_or(TypeDescriptorError::InvalidCanonicalString)?,
            )?,
            ContainerKind::Result => {
                let mut members = frame.members.into_iter();
                let ok = members
                    .next()
                    .ok_or(TypeDescriptorError::InvalidCanonicalString)?;
                let error = members
                    .next()
                    .ok_or(TypeDescriptorError::InvalidCanonicalString)?;
                TypeDescriptor::result(ok, error)
            }
            ContainerKind::List => TypeDescriptor::list(
                frame
                    .members
                    .into_iter()
                    .next()
                    .ok_or(TypeDescriptorError::InvalidCanonicalString)?,
            ),
            ContainerKind::Tuple => TypeDescriptor::tuple(frame.members)?,
            ContainerKind::Declared(path) => {
                TypeDescriptor::declared_with_arguments(path, frame.members)
            }
        });
        Ok(())
    }

    fn check_depth(&self) -> Result<(), TypeDescriptorError> {
        let observed = u64::try_from(self.frames.len())
            .ok()
            .and_then(|depth| depth.checked_add(1))
            .ok_or(TypeDescriptorError::InvalidCanonicalString)?;
        if observed > self.maximum_constructed_type_depth {
            return Err(TypeDescriptorError::ConstructedTypeDepth {
                limit: self.maximum_constructed_type_depth,
                observed,
            });
        }
        Ok(())
    }

    fn consume_word(&mut self, word: &str) -> bool {
        if !self.source[self.cursor..].starts_with(word) {
            return false;
        }
        let end = self.cursor + word.len();
        if !matches!(self.source.as_bytes().get(end), None | Some(b',' | b'>')) {
            return false;
        }
        self.cursor = end;
        true
    }

    fn byte(&self) -> Option<u8> {
        self.source.as_bytes().get(self.cursor).copied()
    }

    const fn primitive(value: TypeDescriptor) -> TypeDescriptor {
        value
    }
}

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
        let envelope = TypeDescriptor::declared_with_arguments(
            CanonicalPath::new("crate::domain::Envelope")
                .unwrap_or_else(|_| unreachable!("constant path is canonical")),
            vec![result.clone()],
        );
        assert_eq!(
            envelope.canonical_string(),
            "crate::domain::Envelope<Result<List<crate::domain::Report>,Option<String>>>"
        );
        assert_eq!(envelope.immediate_members(), [result]);
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

    #[test]
    fn canonical_descriptors_round_trip_and_reject_noncanonical_forms() {
        for value in [
            "Unit",
            "crate::domain::Report",
            "Option<String>",
            "Result<List<crate::domain::Report>,Tuple<Int,String>>",
            "crate::domain::Envelope<Result<Int,String>>",
        ] {
            assert_eq!(
                TypeDescriptor::from_canonical_string_with_depth_limit(value, 16)
                    .map(|descriptor| descriptor.canonical_string()),
                Ok(value.to_owned())
            );
        }
        for value in [
            "",
            " String",
            "Option<Unit>",
            "Option<Option<String>>",
            "Result<Int>",
            "Tuple<Int>",
            "List<Int>>",
            "crate::bad-name",
        ] {
            assert_eq!(
                TypeDescriptor::from_canonical_string_with_depth_limit(value, 16),
                Err(TypeDescriptorError::InvalidCanonicalString)
            );
        }
        assert_eq!(
            TypeDescriptor::from_canonical_string_with_depth_limit("List<Int>", 1),
            Err(TypeDescriptorError::ConstructedTypeDepth {
                limit: 1,
                observed: 2,
            })
        );
        assert!(TypeDescriptor::from_canonical_string_with_depth_limit("List<Int>", 2).is_ok());
    }
}
