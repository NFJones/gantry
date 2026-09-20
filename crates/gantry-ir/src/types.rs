//! Closed Gantry v1 type algebra and canonical descriptors.

use std::fmt;

use crate::CanonicalPath;
use crate::callable::{CallableKind, CallableType};
use crate::collections::{
    CollectionDiagnosticCode, CollectionError, MapTypeIdentity, RangeTypeIdentity, SetTypeIdentity,
};
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
    OpenCallable(CallableKind),
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

    /// The uninhabited `Never` type.
    pub const NEVER: Self = Self::primitive(TypeKind::Never, true);

    /// Reports whether this descriptor names the uninhabited type anywhere within it.
    #[must_use]
    pub fn contains_never(&self) -> bool {
        if self.kind == TypeKind::Never {
            return true;
        }
        self.immediate_members()
            .iter()
            .any(|member| member.contains_never())
    }

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

    /// Constructs `Map<K,V>` from one admitted collection key type and any value type.
    ///
    /// The key rule is owned by `GNT-39.1` and `GNT-39.5`: the key member is admitted exactly when
    /// it is one of the five admitted collection key types, so this descriptor names no key the
    /// key domain refuses. The value member is carried unchanged, and `GNT-39.5` admits no value
    /// member rule. Building one descriptor decides no type admission and publishes no value,
    /// construction, projection, iteration, traversal, mutation, quota, schema, recovery,
    /// durability, boundary encoding, lowering, or machine representation.
    pub fn map(key: Self, value: Self) -> Result<Self, TypeDescriptorError> {
        MapTypeIdentity::admit(&key, &value).map_err(collection_refusal)?;
        let contains_sealed_boundary =
            key.contains_sealed_boundary || value.contains_sealed_boundary;
        let mut tokens = vec![TypeToken::Open(TypeKind::Map)];
        tokens.extend(key.into_tokens());
        tokens.push(TypeToken::Comma);
        tokens.extend(value.into_tokens());
        tokens.push(TypeToken::Close);
        Ok(Self {
            kind: TypeKind::Map,
            tokens,
            contains_sealed_boundary,
        })
    }

    /// Constructs `Set<K>` from one admitted collection key type.
    ///
    /// A set element is a collection key, so the element rule is the same key rule `GNT-39.6`
    /// states for the `Set<K>` identity, owned by the same key vocabulary and applied here by the
    /// identity that publishes it.
    pub fn set(element: Self) -> Result<Self, TypeDescriptorError> {
        SetTypeIdentity::admit(&element).map_err(collection_refusal)?;
        let contains_sealed_boundary = element.contains_sealed_boundary;
        let mut tokens = vec![TypeToken::Open(TypeKind::Set)];
        tokens.extend(element.into_tokens());
        tokens.push(TypeToken::Close);
        Ok(Self {
            kind: TypeKind::Set,
            tokens,
            contains_sealed_boundary,
        })
    }

    /// Constructs `Range<T>` over any constructed element type the identity admits.
    ///
    /// `GNT-39.6` publishes the element argument, applies no key rule to it, and admits no
    /// collection type as a value type, so the element rule is exactly the identity's own rule: the
    /// element names no collection type anywhere inside it. The sealed step contract of `GNT-39.7`
    /// is a separate clause that admits element types for stepping, not for this type.
    pub fn range(element: Self) -> Result<Self, TypeDescriptorError> {
        let element = RangeTypeIdentity::new(element)
            .map_err(collection_refusal)?
            .element()
            .clone();
        let contains_sealed_boundary = element.contains_sealed_boundary;
        let mut tokens = vec![TypeToken::Open(TypeKind::Range)];
        tokens.extend(element.into_tokens());
        tokens.push(TypeToken::Close);
        Ok(Self {
            kind: TypeKind::Range,
            tokens,
            contains_sealed_boundary,
        })
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

    /// Constructs one callable type over its declared parameter and result types.
    ///
    /// The descriptor carries the ordered parameter types and the result type as
    /// its members, so a callable type is one constructed type whose canonical
    /// spelling is `Callable<Fn,Int,Bool>` for `Fn(Int) -> Bool` and whose
    /// identity is the tuple `GNT-37.1` defines. It carries no capture plan, no
    /// declared effect row, and no reuse state, because a callable type is that
    /// identity and nothing else, and it is never a canonical scalar key, an
    /// external value, or a durable projection.
    pub fn callable(kind: CallableKind, parameters: Vec<Self>, result: Self) -> Self {
        let contains_sealed_boundary = parameters
            .iter()
            .any(|parameter| parameter.contains_sealed_boundary)
            || result.contains_sealed_boundary;
        let no_parameters = parameters.is_empty();
        let mut tokens = vec![TypeToken::OpenCallable(kind)];
        for (index, parameter) in parameters.into_iter().enumerate() {
            if index > 0 {
                tokens.push(TypeToken::Comma);
            }
            tokens.extend(parameter.into_tokens());
        }
        if !no_parameters {
            tokens.push(TypeToken::Comma);
        }
        tokens.extend(result.into_tokens());
        tokens.push(TypeToken::Close);
        Self {
            kind: TypeKind::Callable,
            tokens,
            contains_sealed_boundary,
        }
    }

    /// Returns the callable type this descriptor names, or `None` for another type.
    ///
    /// The reuse kind, ordered parameter types, and result type are recovered from
    /// the descriptor's own members, so the identity a descriptor carries is
    /// recomputed from the descriptor instead of being trusted as a stored claim.
    pub fn callable_type(&self) -> Option<CallableType> {
        let TypeToken::OpenCallable(kind) = self.tokens.first()? else {
            return None;
        };
        let mut members = self.immediate_members().into_iter();
        let result = members.next_back()?;
        let parameters = members
            .map(|parameter| parameter.canonical_string())
            .collect::<Vec<_>>();
        CallableType::from_canonical_parts(*kind, parameters, &result.canonical_string()).ok()
    }

    /// Returns whether this type recursively contains a sealed judgment or operation error.
    #[must_use]
    pub const fn contains_sealed_boundary(&self) -> bool {
        self.contains_sealed_boundary
    }

    /// Returns independent v1 primitive properties, or `None` for a structural type.
    ///
    /// Declared fields and aggregate members must be checked with their complete
    /// declaration graph, not inferred from nominal arguments or descriptor flags.
    #[must_use]
    pub const fn primitive_properties(&self) -> Option<crate::PrimitiveTypeProperties> {
        crate::PrimitiveTypeProperties::for_kind(self.kind)
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
    ///
    /// A callable type's members are its ordered parameter types followed by its
    /// result type. Those positions name closed types, so a callable type never
    /// carries a substitutable generic member; read its identity with
    /// [`Self::callable_type`].
    #[must_use]
    pub fn immediate_members(&self) -> Vec<Self> {
        if self.tokens.len() < 3
            || !matches!(
                self.tokens.first(),
                Some(TypeToken::Open(_) | TypeToken::OpenDeclared(_) | TypeToken::OpenCallable(_))
            )
        {
            return Vec::new();
        }
        let mut members = Vec::new();
        let mut start = 1_usize;
        let mut depth = 0_usize;
        for index in 1..self.tokens.len().saturating_sub(1) {
            match &self.tokens[index] {
                TypeToken::Open(_) | TypeToken::OpenDeclared(_) | TypeToken::OpenCallable(_) => {
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

    /// Reports whether every member slice of this constructed type re-decodes.
    ///
    /// [`Self::immediate_members`] skips a slice it cannot decode, so a caller that must not miss a
    /// member — the collection member rule, for example — checks this first. A descriptor this crate
    /// builds always re-decodes every slice, because only the constructors and the parser build
    /// descriptors; a descriptor that cannot be fully read is refused by its caller rather than
    /// trusted, so the check stays fail-closed if a token-level constructor is ever added.
    #[must_use]
    pub(crate) fn all_member_slices_decode(&self) -> bool {
        if !matches!(
            self.tokens.first(),
            Some(TypeToken::Open(_) | TypeToken::OpenDeclared(_) | TypeToken::OpenCallable(_))
        ) {
            return true;
        }
        // An opener shape must carry its closing token and at least one member position; a shorter
        // or unclosed opener sequence is refused as unreadable rather than trusted, so the
        // fail-closed guarantee does not depend on every constructor appending `Close`.
        if self.tokens.len() < 3 || self.tokens.last() != Some(&TypeToken::Close) {
            return false;
        }
        let mut start = 1_usize;
        let mut depth = 0_usize;
        for index in 1..self.tokens.len().saturating_sub(1) {
            match &self.tokens[index] {
                TypeToken::Open(_) | TypeToken::OpenDeclared(_) | TypeToken::OpenCallable(_) => {
                    depth = depth.saturating_add(1);
                }
                TypeToken::Close => depth = depth.saturating_sub(1),
                TypeToken::Comma if depth == 0 => {
                    if Self::from_token_slice(&self.tokens[start..index]).is_none() {
                        return false;
                    }
                    start = index.saturating_add(1);
                }
                _ => {}
            }
        }
        Self::from_token_slice(
            self.tokens
                .get(start..self.tokens.len().saturating_sub(1))
                .unwrap_or_default(),
        )
        .is_some()
    }

    /// Reports whether this type names a collection type kind anywhere inside it.
    ///
    /// The walk reads each descriptor's own immediate members iteratively, so no nesting depth hides
    /// a collection, and a descriptor whose member slices do not all re-decode is reported as naming
    /// one: the predicate is fail-closed, so an unreadable slice can never hide a collection member.
    /// `GNT-39.4-map-type-form-recognition` through `GNT-39.7-range-step-contract` publish the three
    /// collection kinds; this predicate decides no admission and publishes no behavior of its own.
    #[must_use]
    pub fn contains_collection_type(&self) -> bool {
        let mut pending = vec![self.clone()];
        while let Some(current) = pending.pop() {
            if matches!(
                current.kind(),
                TypeKind::Map | TypeKind::Set | TypeKind::Range
            ) || !current.all_member_slices_decode()
            {
                return true;
            }
            pending.extend(current.immediate_members());
        }
        false
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
                TypeToken::OpenCallable(kind) => {
                    output.push_str(TypeKind::Callable.wire_name());
                    output.push('<');
                    output.push_str(kind.canonical_name());
                    output.push(',');
                }
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
            TypeToken::OpenCallable(_) => TypeKind::Callable,
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

/// Maps one collection identity refusal onto the descriptor refusal its own rule published.
///
/// The key rule of `GNT-39.1-admitted-collection-keys` and the unadmitted-member rule of
/// `GNT-39.4` through `GNT-39.6` are distinct clause-owned refusals, so the algebra reports which of
/// them refused rather than collapsing both into one spelling.
fn collection_refusal(refusal: CollectionError) -> TypeDescriptorError {
    match refusal.code() {
        CollectionDiagnosticCode::InvalidKey => TypeDescriptorError::InvalidCollectionKey,
        CollectionDiagnosticCode::DuplicateKey
        | CollectionDiagnosticCode::NonClaimAsGuarantee
        | CollectionDiagnosticCode::UnadmittedType => TypeDescriptorError::InvalidCollectionMember,
    }
}

/// Rejection of an ill-formed constructed type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TypeDescriptorError {
    /// `Option<Unit>` and an immediate nested `Option` are wire-ambiguous.
    InvalidOptionMember,
    /// A tuple has fewer than two members.
    TupleArity,
    /// A `Map` key member or `Set` element member is not an admitted collection key type.
    InvalidCollectionKey,
    /// A `Map` value member or `Range` element member names a collection type this edition does not
    /// admit as a value type.
    InvalidCollectionMember,
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
            Self::InvalidCollectionKey => {
                "collection key member is not an admitted collection key type"
            }
            Self::InvalidCollectionMember => "collection member is not an admitted value type",
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
    Map,
    Set,
    Range,
    Tuple,
    Callable(CallableKind),
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
                ContainerKind::Option
                | ContainerKind::List
                | ContainerKind::Set
                | ContainerKind::Range => {
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
                ContainerKind::Map => match (frame.members.len(), delimiter) {
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
                ContainerKind::Callable(_) => match delimiter {
                    Some(b',') => self.cursor += 1,
                    Some(b'>') if !frame.members.is_empty() => {
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
            ("Map<", ContainerKind::Map),
            ("Set<", ContainerKind::Set),
            ("Range<", ContainerKind::Range),
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
        // A callable introducer declares its reuse kind before any member, so the
        // kind marker is consumed here and the ordered parameter and result types
        // follow as ordinary members.
        if self.source[self.cursor..].starts_with("Callable<") {
            self.cursor += "Callable<".len();
            let end = self.source[self.cursor..]
                .find([',', '>'])
                .map_or(self.source.len(), |offset| self.cursor + offset);
            let kind = self
                .source
                .get(self.cursor..end)
                .and_then(|name| CallableKind::from_canonical_name(name).ok())
                .ok_or(TypeDescriptorError::InvalidCanonicalString)?;
            if self.source.as_bytes().get(end) != Some(&b',') {
                return Err(TypeDescriptorError::InvalidCanonicalString);
            }
            self.cursor = end + 1;
            self.frames.push(ContainerFrame {
                kind: ContainerKind::Callable(kind),
                members: Vec::new(),
            });
            return Ok(());
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
            ContainerKind::Map => {
                let mut members = frame.members.into_iter();
                let key = members
                    .next()
                    .ok_or(TypeDescriptorError::InvalidCanonicalString)?;
                let value = members
                    .next()
                    .ok_or(TypeDescriptorError::InvalidCanonicalString)?;
                TypeDescriptor::map(key, value)?
            }
            ContainerKind::Set => TypeDescriptor::set(
                frame
                    .members
                    .into_iter()
                    .next()
                    .ok_or(TypeDescriptorError::InvalidCanonicalString)?,
            )?,
            ContainerKind::Range => TypeDescriptor::range(
                frame
                    .members
                    .into_iter()
                    .next()
                    .ok_or(TypeDescriptorError::InvalidCanonicalString)?,
            )?,
            ContainerKind::Tuple => TypeDescriptor::tuple(frame.members)?,
            ContainerKind::Callable(kind) => {
                let mut members = frame.members;
                let result = members
                    .pop()
                    .ok_or(TypeDescriptorError::InvalidCanonicalString)?;
                TypeDescriptor::callable(kind, members, result)
            }
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
    use crate::callable::{CallableKind, CallableLimits, CallableType};
    use crate::generated::TypeKind;

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

    #[test]
    fn callable_types_spell_and_recover_one_identity() {
        let thunk =
            TypeDescriptor::callable(CallableKind::Function, Vec::new(), TypeDescriptor::INT);
        assert_eq!(thunk.canonical_string(), "Callable<Fn,Int>");
        assert_eq!(thunk.kind(), TypeKind::Callable);
        assert_eq!(thunk.declared_path(), None);
        assert!(!thunk.contains_sealed_boundary());
        assert_eq!(thunk.immediate_members(), [TypeDescriptor::INT]);

        let handler = TypeDescriptor::callable(
            CallableKind::FunctionOnce,
            vec![TypeDescriptor::INT, TypeDescriptor::STRING],
            TypeDescriptor::BOOL,
        );
        assert_eq!(
            handler.canonical_string(),
            "Callable<FnOnce,Int,String,Bool>"
        );
        assert_eq!(
            handler.immediate_members(),
            [
                TypeDescriptor::INT,
                TypeDescriptor::STRING,
                TypeDescriptor::BOOL
            ]
        );
        assert_eq!(
            handler.callable_type(),
            Some(
                CallableType::new(
                    CallableKind::FunctionOnce,
                    vec!["Int".to_owned(), "String".to_owned()],
                    "Bool",
                    CallableLimits::default(),
                )
                .unwrap_or_else(|_| unreachable!("the declared shape is within default budgets"))
            )
        );
        assert_ne!(handler.canonical_string(), thunk.canonical_string());
        assert_eq!(TypeDescriptor::INT.callable_type(), None);
        assert_eq!(TypeDescriptor::STRING.callable_type(), None);
    }

    #[test]
    fn callable_descriptors_round_trip_and_reject_malformed_spellings() {
        for spelling in [
            "Callable<Fn,Int>",
            "Callable<FnMut,Int,String,Bool>",
            "Callable<FnOnce,List<crate::domain::Report>,Option<String>>",
            "Callable<Fn,Callable<Fn,Int>,Bool>",
        ] {
            assert_eq!(
                TypeDescriptor::from_canonical_string_with_depth_limit(spelling, 16)
                    .map(|descriptor| descriptor.canonical_string()),
                Ok(spelling.to_owned())
            );
        }
        for spelling in [
            "Callable",
            "callable<Fn,Int>",
            "Callable<>",
            "Callable<Fn>",
            "Callable<Fnn,Int>",
            "Callable<Fn,>",
            "Callable<Fn,,Int>",
            "Callable<Fn,Int",
            "Callable<Fn,Int>>",
            "Callable<Fn,Int ,Bool>",
        ] {
            assert_eq!(
                TypeDescriptor::from_canonical_string_with_depth_limit(spelling, 16),
                Err(TypeDescriptorError::InvalidCanonicalString)
            );
        }
        assert_eq!(
            TypeDescriptor::from_canonical_string_with_depth_limit("Callable<Fn,List<Int>>", 1),
            Err(TypeDescriptorError::ConstructedTypeDepth {
                limit: 1,
                observed: 2,
            })
        );
    }

    #[test]
    fn callable_members_report_sealed_boundaries() {
        let sealed = TypeDescriptor::callable(
            CallableKind::Function,
            vec![TypeDescriptor::DECISION],
            TypeDescriptor::INT,
        );
        assert!(sealed.contains_sealed_boundary());
        assert_eq!(sealed.canonical_string(), "Callable<Fn,Decision,Int>");
        let wrapped = TypeDescriptor::list(sealed);
        assert!(wrapped.contains_sealed_boundary());
        assert!(
            !TypeDescriptor::callable(CallableKind::Function, Vec::new(), TypeDescriptor::BOOL)
                .contains_sealed_boundary()
        );
    }
}
