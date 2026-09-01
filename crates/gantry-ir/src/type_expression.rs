//! Canonical generic type expressions retained only by analysis artifacts.

use std::fmt;
use std::sync::Arc;

use crate::generated::{TypeExpressionKind, TypeKind};
use crate::{CanonicalPath, TypeDescriptor};

/// One canonical generic type expression with bounded, nonrecursive decoding.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TypeExpression {
    canonical: Arc<str>,
    kind: TypeExpressionKind,
    depth: u64,
    closed: bool,
}

impl TypeExpression {
    /// Admits one already closed descriptor under the constructed-type limit.
    pub fn closed(
        descriptor: &TypeDescriptor,
        maximum_constructed_type_depth: u64,
    ) -> Result<Self, TypeExpressionError> {
        Self::from_canonical_string(
            &descriptor.canonical_string(),
            maximum_constructed_type_depth,
        )
    }

    /// Constructs one binder-qualified parameter leaf as `^B.P`.
    pub fn parameter(
        binder_depth: u64,
        parameter_ordinal: u64,
        maximum_constructed_type_depth: u64,
    ) -> Result<Self, TypeExpressionError> {
        Self::from_canonical_string(
            &format!("^{binder_depth}.{parameter_ordinal}"),
            maximum_constructed_type_depth,
        )
    }

    /// Constructs one binder-qualified contextual `Self` leaf as `^self:B`.
    pub fn self_type(
        binder_depth: u64,
        maximum_constructed_type_depth: u64,
    ) -> Result<Self, TypeExpressionError> {
        Self::from_canonical_string(
            &format!("^self:{binder_depth}"),
            maximum_constructed_type_depth,
        )
    }

    /// Constructs `Option<T>`.
    pub fn option(
        member: Self,
        maximum_constructed_type_depth: u64,
    ) -> Result<Self, TypeExpressionError> {
        Self::application(
            "Option",
            [member].as_slice(),
            maximum_constructed_type_depth,
        )
    }

    /// Constructs `Result<T,E>`.
    pub fn result(
        ok: Self,
        error: Self,
        maximum_constructed_type_depth: u64,
    ) -> Result<Self, TypeExpressionError> {
        Self::application(
            "Result",
            [ok, error].as_slice(),
            maximum_constructed_type_depth,
        )
    }

    /// Constructs `List<T>`.
    pub fn list(
        member: Self,
        maximum_constructed_type_depth: u64,
    ) -> Result<Self, TypeExpressionError> {
        Self::application("List", [member].as_slice(), maximum_constructed_type_depth)
    }

    /// Constructs a fixed tuple with at least two members.
    pub fn tuple(
        members: Vec<Self>,
        maximum_constructed_type_depth: u64,
    ) -> Result<Self, TypeExpressionError> {
        Self::application("Tuple", &members, maximum_constructed_type_depth)
    }

    /// Constructs one declared type with ordered template arguments.
    pub fn declared(
        path: CanonicalPath,
        arguments: Vec<Self>,
        maximum_constructed_type_depth: u64,
    ) -> Result<Self, TypeExpressionError> {
        if arguments.is_empty() {
            return Self::from_canonical_string(path.as_str(), maximum_constructed_type_depth);
        }
        Self::application(path.as_str(), &arguments, maximum_constructed_type_depth)
    }

    /// Decodes one exact canonical expression under an inclusive depth limit.
    pub fn from_canonical_string(
        value: &str,
        maximum_constructed_type_depth: u64,
    ) -> Result<Self, TypeExpressionError> {
        if value.is_empty() || value.bytes().any(|byte| byte.is_ascii_whitespace()) {
            return Err(TypeExpressionError::InvalidCanonicalString);
        }
        let summary = ExpressionParser::new(value, maximum_constructed_type_depth).parse()?;
        Ok(Self {
            canonical: Arc::from(value),
            kind: summary.kind,
            depth: summary.depth,
            closed: summary.closed,
        })
    }

    /// Returns the canonical template encoding.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.canonical
    }

    /// Returns the portable expression classification.
    #[must_use]
    pub const fn kind(&self) -> TypeExpressionKind {
        self.kind
    }

    /// Returns the exact constructed-type depth.
    #[must_use]
    pub const fn depth(&self) -> u64 {
        self.depth
    }

    /// Returns whether the expression contains no parameter or `Self` leaf.
    #[must_use]
    pub const fn is_closed(&self) -> bool {
        self.closed
    }

    /// Converts a closed expression to the runtime descriptor algebra.
    pub fn to_descriptor(
        &self,
        maximum_constructed_type_depth: u64,
    ) -> Result<TypeDescriptor, TypeExpressionError> {
        if !self.closed {
            return Err(TypeExpressionError::OpenExpression);
        }
        TypeDescriptor::from_canonical_string_with_depth_limit(
            self.as_str(),
            maximum_constructed_type_depth,
        )
        .map_err(|_| TypeExpressionError::InvalidCanonicalString)
    }

    fn application(
        constructor: &str,
        arguments: &[Self],
        maximum_constructed_type_depth: u64,
    ) -> Result<Self, TypeExpressionError> {
        let mut canonical = String::from(constructor);
        canonical.push('<');
        for (index, argument) in arguments.iter().enumerate() {
            if index > 0 {
                canonical.push(',');
            }
            canonical.push_str(argument.as_str());
        }
        canonical.push('>');
        Self::from_canonical_string(&canonical, maximum_constructed_type_depth)
    }
}

impl fmt::Display for TypeExpression {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Rejection of a malformed or over-limit generic type expression.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TypeExpressionError {
    /// Input is not one exact canonical template expression.
    InvalidCanonicalString,
    /// A decoded expression exceeds the configured constructed-type depth.
    ConstructedTypeDepth {
        /// Configured inclusive maximum depth.
        limit: u64,
        /// First rejected depth.
        observed: u64,
    },
    /// An open expression was requested as a runtime descriptor.
    OpenExpression,
}

impl fmt::Display for TypeExpressionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidCanonicalString => "type expression is not canonical",
            Self::ConstructedTypeDepth { .. } => {
                "type expression exceeds the constructed-type depth limit"
            }
            Self::OpenExpression => "open type expression has no runtime descriptor",
        })
    }
}

impl std::error::Error for TypeExpressionError {}

#[derive(Clone)]
enum ExpressionContainer {
    Option,
    Result,
    List,
    Tuple,
    Declared,
}

struct ExpressionFrame {
    container: ExpressionContainer,
    members: Vec<ExpressionSummary>,
}

#[derive(Clone, Copy)]
struct ExpressionSummary {
    kind: TypeExpressionKind,
    outer_type: Option<TypeKind>,
    depth: u64,
    closed: bool,
}

struct ExpressionParser<'a> {
    source: &'a str,
    cursor: usize,
    frames: Vec<ExpressionFrame>,
    value: Option<ExpressionSummary>,
    maximum_constructed_type_depth: u64,
}

impl<'a> ExpressionParser<'a> {
    fn new(source: &'a str, maximum_constructed_type_depth: u64) -> Self {
        Self {
            source,
            cursor: 0,
            frames: Vec::new(),
            value: None,
            maximum_constructed_type_depth,
        }
    }

    fn parse(mut self) -> Result<ExpressionSummary, TypeExpressionError> {
        loop {
            if self.value.is_none() {
                self.parse_atom()?;
                continue;
            }
            let value = self
                .value
                .take()
                .ok_or(TypeExpressionError::InvalidCanonicalString)?;
            let delimiter = self.byte();
            let Some(frame) = self.frames.last_mut() else {
                if self.cursor == self.source.len() {
                    return Ok(value);
                }
                return Err(TypeExpressionError::InvalidCanonicalString);
            };
            frame.members.push(value);
            match &frame.container {
                ExpressionContainer::Option | ExpressionContainer::List => {
                    if frame.members.len() != 1 || delimiter != Some(b'>') {
                        return Err(TypeExpressionError::InvalidCanonicalString);
                    }
                    self.cursor += 1;
                    self.close_frame()?;
                }
                ExpressionContainer::Result => match (frame.members.len(), delimiter) {
                    (1, Some(b',')) => self.cursor += 1,
                    (2, Some(b'>')) => {
                        self.cursor += 1;
                        self.close_frame()?;
                    }
                    _ => return Err(TypeExpressionError::InvalidCanonicalString),
                },
                ExpressionContainer::Tuple => match delimiter {
                    Some(b',') => self.cursor += 1,
                    Some(b'>') if frame.members.len() >= 2 => {
                        self.cursor += 1;
                        self.close_frame()?;
                    }
                    _ => return Err(TypeExpressionError::InvalidCanonicalString),
                },
                ExpressionContainer::Declared => match delimiter {
                    Some(b',') => self.cursor += 1,
                    Some(b'>') if !frame.members.is_empty() => {
                        self.cursor += 1;
                        self.close_frame()?;
                    }
                    _ => return Err(TypeExpressionError::InvalidCanonicalString),
                },
            }
        }
    }

    fn parse_atom(&mut self) -> Result<(), TypeExpressionError> {
        self.check_depth()?;
        if self.source[self.cursor..].starts_with("^self:") {
            self.cursor += "^self:".len();
            self.parse_decimal()?;
            self.value = Some(ExpressionSummary {
                kind: TypeExpressionKind::SelfType,
                outer_type: None,
                depth: 1,
                closed: false,
            });
            return Ok(());
        }
        if self.byte() == Some(b'^') {
            self.cursor += 1;
            self.parse_decimal()?;
            if self.byte() != Some(b'.') {
                return Err(TypeExpressionError::InvalidCanonicalString);
            }
            self.cursor += 1;
            self.parse_decimal()?;
            self.value = Some(ExpressionSummary {
                kind: TypeExpressionKind::Parameter,
                outer_type: None,
                depth: 1,
                closed: false,
            });
            return Ok(());
        }
        for (name, kind) in [
            ("Unit", TypeKind::Unit),
            ("Bool", TypeKind::Bool),
            ("Int", TypeKind::Int),
            ("Float", TypeKind::Float),
            ("String", TypeKind::String),
            ("Decision", TypeKind::Decision),
            ("OperationError", TypeKind::OperationError),
        ] {
            if self.consume_word(name) {
                self.value = Some(ExpressionSummary {
                    kind: TypeExpressionKind::Primitive,
                    outer_type: Some(kind),
                    depth: 1,
                    closed: true,
                });
                return Ok(());
            }
        }
        for (prefix, container) in [
            ("Option<", ExpressionContainer::Option),
            ("Result<", ExpressionContainer::Result),
            ("List<", ExpressionContainer::List),
            ("Tuple<", ExpressionContainer::Tuple),
        ] {
            if self.source[self.cursor..].starts_with(prefix) {
                self.cursor += prefix.len();
                self.frames.push(ExpressionFrame {
                    container,
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
            .ok_or(TypeExpressionError::InvalidCanonicalString)?;
        CanonicalPath::new(path).map_err(|_| TypeExpressionError::InvalidCanonicalString)?;
        self.cursor = end;
        if self.byte() == Some(b'<') {
            self.cursor += 1;
            self.frames.push(ExpressionFrame {
                container: ExpressionContainer::Declared,
                members: Vec::new(),
            });
        } else {
            self.value = Some(ExpressionSummary {
                kind: TypeExpressionKind::DeclaredApplication,
                outer_type: Some(TypeKind::Declared),
                depth: 1,
                closed: true,
            });
        }
        Ok(())
    }

    fn close_frame(&mut self) -> Result<(), TypeExpressionError> {
        let frame = self
            .frames
            .pop()
            .ok_or(TypeExpressionError::InvalidCanonicalString)?;
        let depth = frame
            .members
            .iter()
            .map(|member| member.depth)
            .max()
            .and_then(|depth| depth.checked_add(1))
            .ok_or(TypeExpressionError::InvalidCanonicalString)?;
        if depth > self.maximum_constructed_type_depth {
            return Err(TypeExpressionError::ConstructedTypeDepth {
                limit: self.maximum_constructed_type_depth,
                observed: depth,
            });
        }
        if matches!(frame.container, ExpressionContainer::Option)
            && frame.members.first().is_some_and(|member| {
                matches!(member.outer_type, Some(TypeKind::Unit | TypeKind::Option))
            })
        {
            return Err(TypeExpressionError::InvalidCanonicalString);
        }
        let (kind, outer_type) = match frame.container {
            ExpressionContainer::Option => (
                TypeExpressionKind::BuiltinApplication,
                Some(TypeKind::Option),
            ),
            ExpressionContainer::Result => (
                TypeExpressionKind::BuiltinApplication,
                Some(TypeKind::Result),
            ),
            ExpressionContainer::List => {
                (TypeExpressionKind::BuiltinApplication, Some(TypeKind::List))
            }
            ExpressionContainer::Tuple => (
                TypeExpressionKind::BuiltinApplication,
                Some(TypeKind::Tuple),
            ),
            ExpressionContainer::Declared => (
                TypeExpressionKind::DeclaredApplication,
                Some(TypeKind::Declared),
            ),
        };
        self.value = Some(ExpressionSummary {
            kind,
            outer_type,
            depth,
            closed: frame.members.iter().all(|member| member.closed),
        });
        Ok(())
    }

    fn check_depth(&self) -> Result<(), TypeExpressionError> {
        let observed = u64::try_from(self.frames.len())
            .ok()
            .and_then(|depth| depth.checked_add(1))
            .ok_or(TypeExpressionError::InvalidCanonicalString)?;
        if observed > self.maximum_constructed_type_depth {
            return Err(TypeExpressionError::ConstructedTypeDepth {
                limit: self.maximum_constructed_type_depth,
                observed,
            });
        }
        Ok(())
    }

    fn parse_decimal(&mut self) -> Result<(), TypeExpressionError> {
        let start = self.cursor;
        while self.byte().is_some_and(|byte| byte.is_ascii_digit()) {
            self.cursor += 1;
        }
        let value = self
            .source
            .get(start..self.cursor)
            .ok_or(TypeExpressionError::InvalidCanonicalString)?;
        if value.is_empty()
            || value.len() > 1 && value.starts_with('0')
            || value.parse::<u64>().is_err()
        {
            return Err(TypeExpressionError::InvalidCanonicalString);
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
}

#[cfg(test)]
mod tests {
    use super::{TypeExpression, TypeExpressionError};
    use crate::{CanonicalPath, TypeDescriptor};

    #[test]
    fn canonical_expressions_use_binder_ordinals_not_source_names() {
        let parameter = TypeExpression::parameter(0, 1, 8)
            .unwrap_or_else(|_| unreachable!("bounded parameter is valid"));
        let envelope = TypeExpression::declared(
            CanonicalPath::new("crate::Envelope")
                .unwrap_or_else(|_| unreachable!("constant path is canonical")),
            vec![parameter],
            8,
        )
        .unwrap_or_else(|_| unreachable!("bounded application is valid"));
        assert_eq!(envelope.as_str(), "crate::Envelope<^0.1>");
        assert_eq!(envelope.depth(), 2);
        assert!(!envelope.is_closed());
        assert_eq!(
            envelope.to_descriptor(8),
            Err(TypeExpressionError::OpenExpression)
        );
    }

    #[test]
    fn closed_expressions_convert_to_runtime_descriptors() {
        let expression = TypeExpression::closed(
            &TypeDescriptor::declared_with_arguments(
                CanonicalPath::new("crate::Envelope")
                    .unwrap_or_else(|_| unreachable!("constant path is canonical")),
                vec![TypeDescriptor::STRING],
            ),
            8,
        )
        .unwrap_or_else(|_| unreachable!("closed descriptor is valid"));
        assert!(expression.is_closed());
        assert_eq!(
            expression
                .to_descriptor(8)
                .map(|value| value.canonical_string()),
            Ok("crate::Envelope<String>".to_owned())
        );
    }

    #[test]
    fn strict_expression_decode_rejects_malformed_and_over_limit_inputs() {
        for value in [
            "^00.0",
            "^0.01",
            "^self:00",
            "Tuple<^0.0>",
            "crate::Envelope<>",
            "List<^0.0>>",
        ] {
            assert_eq!(
                TypeExpression::from_canonical_string(value, 8),
                Err(TypeExpressionError::InvalidCanonicalString)
            );
        }
        assert_eq!(
            TypeExpression::from_canonical_string("List<^0.0>", 1),
            Err(TypeExpressionError::ConstructedTypeDepth {
                limit: 1,
                observed: 2,
            })
        );
    }

    #[test]
    fn deeply_nested_expression_decode_uses_an_explicit_stack() {
        let depth = 10_000_u64;
        let mut canonical = "List<".repeat(depth as usize);
        canonical.push_str("^0.0");
        canonical.push_str(&">".repeat(depth as usize));
        let expression = TypeExpression::from_canonical_string(&canonical, depth + 1)
            .unwrap_or_else(|_| unreachable!("expression is exactly at limit"));
        assert_eq!(expression.depth(), depth + 1);
        assert!(!expression.is_closed());
    }
}
