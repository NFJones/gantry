//! Iterative strict JSON decoding over one retained immutable input buffer.

use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::ops::Range;
use std::sync::Arc;

/// Finite limits enforced while decoding one JSON text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JsonLimits {
    /// Maximum admitted raw bytes before UTF-8 decoding.
    pub maximum_bytes: u64,
    /// Maximum JSON-tree depth, where the root has depth one.
    pub maximum_nesting_depth: u64,
    /// Maximum JSON value nodes, including the root and scalar leaves.
    pub maximum_nodes: u64,
    /// Maximum Unicode scalar values in any decoded JSON String value.
    pub maximum_string_scalars: u64,
    /// Maximum members in any decoded JSON array value.
    pub maximum_list_items: u64,
}

/// Stable index of one value in a [`StrictJsonDocument`].
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct JsonNodeId(usize);

impl JsonNodeId {
    /// Returns the zero-based arena index.
    #[must_use]
    pub const fn index(self) -> usize {
        self.0
    }
}

/// One exact RFC 8259 decimal token backed by the admitted input bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExactDecimal {
    input: Arc<[u8]>,
    range: Range<usize>,
}

impl ExactDecimal {
    /// Returns the exact admitted number spelling.
    #[must_use]
    pub fn lexeme(&self) -> &str {
        std::str::from_utf8(&self.input[self.range.clone()])
            .unwrap_or_else(|_| unreachable!("strict JSON input is valid UTF-8"))
    }

    /// Normalizes an exactly integral token into Gantry's inclusive `Int` range.
    pub fn to_gantry_int(&self) -> Result<i64, NumberError> {
        decimal_to_int(self.lexeme())
    }

    /// Correctly rounds the token to finite binary64 and normalizes negative zero.
    pub fn to_gantry_float(&self) -> Result<f64, NumberError> {
        if compare_decimal_magnitude(self.lexeme(), "1.7976931348623157e308") == Ordering::Greater {
            return Err(NumberError::OutOfRange);
        }
        let parsed = self
            .lexeme()
            .parse::<f64>()
            .map_err(|_| NumberError::OutOfRange)?;
        if !parsed.is_finite() {
            return Err(NumberError::OutOfRange);
        }
        Ok(if parsed == 0.0 { 0.0 } else { parsed })
    }

    /// Compares two exact mathematical decimal values without binary64 rounding.
    #[must_use]
    pub fn numeric_cmp(&self, other: &Self) -> Ordering {
        compare_decimals(self.lexeme(), other.lexeme())
    }
}

/// One node in the strict JSON arena.
#[derive(Clone, Debug, PartialEq)]
pub enum JsonNode {
    /// JSON `null`.
    Null,
    /// JSON Boolean.
    Bool(bool),
    /// Exact JSON number token.
    Number(ExactDecimal),
    /// Decoded Unicode scalar sequence.
    String(Arc<str>),
    /// Ordered array members.
    Array(Vec<JsonNodeId>),
    /// Authored object members after duplicate-name rejection.
    Object(Vec<(Arc<str>, JsonNodeId)>),
}

/// One complete strict JSON text and its arena-backed logical tree.
#[derive(Clone, Debug, PartialEq)]
pub struct StrictJsonDocument {
    input: Arc<[u8]>,
    nodes: Vec<JsonNode>,
    root: JsonNodeId,
}

impl StrictJsonDocument {
    /// Decodes exactly one RFC 8259 JSON text while enforcing byte, depth, and
    /// node limits before returning any partial document.
    pub fn decode(bytes: impl Into<Arc<[u8]>>, limits: JsonLimits) -> Result<Self, JsonError> {
        let input = bytes.into();
        let observed = u64::try_from(input.len()).ok();
        if observed.is_none_or(|observed| observed > limits.maximum_bytes) {
            return Err(JsonError::ResourceLimit {
                kind: JsonLimitKind::Bytes,
                limit: limits.maximum_bytes,
                observed,
            });
        }
        std::str::from_utf8(&input).map_err(|_| JsonError::InvalidUtf8)?;
        Decoder::new(input, limits).decode()
    }

    /// Returns the retained exact input bytes.
    #[must_use]
    pub fn input(&self) -> &[u8] {
        &self.input
    }

    /// Returns the root value identifier.
    #[must_use]
    pub const fn root(&self) -> JsonNodeId {
        self.root
    }

    /// Resolves one arena node.
    #[must_use]
    pub fn node(&self, id: JsonNodeId) -> Option<&JsonNode> {
        self.nodes.get(id.0)
    }

    /// Returns all nodes in deterministic construction order.
    #[must_use]
    pub fn nodes(&self) -> &[JsonNode] {
        &self.nodes
    }
}

/// Exact-number normalization failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NumberError {
    /// The exact mathematical value is not integral.
    NonIntegral,
    /// The exact value is outside the selected Gantry numeric domain.
    OutOfRange,
}

/// Portable strict-JSON resource counter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JsonLimitKind {
    /// Raw input bytes.
    Bytes,
    /// JSON-tree nesting depth.
    NestingDepth,
    /// JSON value nodes.
    Nodes,
    /// Unicode scalar values in one JSON String value.
    StringScalars,
    /// Members in one JSON array value.
    ListItems,
}

/// Strict JSON decoding failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JsonError {
    /// Raw bytes are not UTF-8.
    InvalidUtf8,
    /// No JSON value was present.
    Empty,
    /// Input violates RFC 8259 syntax at the reported byte offset.
    Syntax {
        /// First byte offset at which the syntax cannot continue.
        offset: usize,
    },
    /// Non-whitespace bytes follow the single root value.
    TrailingData {
        /// First trailing non-whitespace byte offset.
        offset: usize,
    },
    /// One object repeats a decoded member name.
    DuplicateMember {
        /// Repeated decoded member name.
        name: Arc<str>,
        /// Opening quote byte offset of the repeated name.
        offset: usize,
    },
    /// A Unicode escape contains an unpaired surrogate.
    UnpairedSurrogate {
        /// Backslash byte offset of the invalid surrogate escape.
        offset: usize,
    },
    /// A configured finite counter was exceeded.
    ResourceLimit {
        /// Counter that failed.
        kind: JsonLimitKind,
        /// Configured maximum.
        limit: u64,
        /// First rejected observed count when representable.
        observed: Option<u64>,
    },
}

#[derive(Debug)]
enum Frame {
    Array {
        node: JsonNodeId,
        state: ArrayState,
    },
    Object {
        node: JsonNodeId,
        state: ObjectState,
        names: BTreeSet<Arc<str>>,
        pending_name: Option<Arc<str>>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ArrayState {
    ValueOrEnd,
    Value,
    CommaOrEnd,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ObjectState {
    NameOrEnd,
    Name,
    Colon,
    Value,
    CommaOrEnd,
}

struct Decoder {
    input: Arc<[u8]>,
    limits: JsonLimits,
    cursor: usize,
    nodes: Vec<JsonNode>,
    root: Option<JsonNodeId>,
    stack: Vec<Frame>,
}

impl Decoder {
    fn new(input: Arc<[u8]>, limits: JsonLimits) -> Self {
        Self {
            input,
            limits,
            cursor: 0,
            nodes: Vec::new(),
            root: None,
            stack: Vec::new(),
        }
    }

    fn decode(mut self) -> Result<StrictJsonDocument, JsonError> {
        self.skip_whitespace();
        if self.cursor == self.input.len() {
            return Err(JsonError::Empty);
        }
        self.parse_value()?;
        while !self.stack.is_empty() {
            self.advance_frame()?;
        }
        self.skip_whitespace();
        if self.cursor != self.input.len() {
            return Err(JsonError::TrailingData {
                offset: self.cursor,
            });
        }
        let root = self.root.ok_or(JsonError::Empty)?;
        Ok(StrictJsonDocument {
            input: self.input,
            nodes: self.nodes,
            root,
        })
    }

    fn advance_frame(&mut self) -> Result<(), JsonError> {
        self.skip_whitespace();
        let Some(frame) = self.stack.last() else {
            return Ok(());
        };
        let array_state = match frame {
            Frame::Array { state, .. } => Some(*state),
            Frame::Object { .. } => None,
        };
        if let Some(state) = array_state {
            match state {
                ArrayState::ValueOrEnd if self.peek() == Some(b']') => {
                    self.cursor += 1;
                    self.stack.pop();
                }
                ArrayState::ValueOrEnd | ArrayState::Value => self.parse_value()?,
                ArrayState::CommaOrEnd if self.peek() == Some(b',') => {
                    self.cursor += 1;
                    let Some(Frame::Array { state, .. }) = self.stack.last_mut() else {
                        return Err(self.syntax());
                    };
                    *state = ArrayState::Value;
                }
                ArrayState::CommaOrEnd if self.peek() == Some(b']') => {
                    self.cursor += 1;
                    self.stack.pop();
                }
                ArrayState::CommaOrEnd => return Err(self.syntax()),
            }
            return Ok(());
        }

        let object_state = match self.stack.last() {
            Some(Frame::Object { state, .. }) => *state,
            _ => return Err(self.syntax()),
        };
        match object_state {
            ObjectState::NameOrEnd if self.peek() == Some(b'}') => {
                self.cursor += 1;
                self.stack.pop();
            }
            ObjectState::NameOrEnd | ObjectState::Name => {
                let offset = self.cursor;
                let name = self.parse_string(false)?;
                let Some(Frame::Object {
                    state,
                    names,
                    pending_name,
                    ..
                }) = self.stack.last_mut()
                else {
                    return Err(JsonError::Syntax { offset });
                };
                if !names.insert(name.clone()) {
                    return Err(JsonError::DuplicateMember { name, offset });
                }
                *pending_name = Some(name);
                *state = ObjectState::Colon;
            }
            ObjectState::Colon if self.peek() == Some(b':') => {
                self.cursor += 1;
                let Some(Frame::Object { state, .. }) = self.stack.last_mut() else {
                    return Err(self.syntax());
                };
                *state = ObjectState::Value;
            }
            ObjectState::Colon => return Err(self.syntax()),
            ObjectState::Value => self.parse_value()?,
            ObjectState::CommaOrEnd if self.peek() == Some(b',') => {
                self.cursor += 1;
                let Some(Frame::Object { state, .. }) = self.stack.last_mut() else {
                    return Err(self.syntax());
                };
                *state = ObjectState::Name;
            }
            ObjectState::CommaOrEnd if self.peek() == Some(b'}') => {
                self.cursor += 1;
                self.stack.pop();
            }
            ObjectState::CommaOrEnd => return Err(self.syntax()),
        }
        Ok(())
    }

    fn parse_value(&mut self) -> Result<(), JsonError> {
        self.skip_whitespace();
        let depth = u64::try_from(self.stack.len())
            .ok()
            .and_then(|depth| depth.checked_add(1));
        if depth.is_none_or(|depth| depth > self.limits.maximum_nesting_depth) {
            return Err(JsonError::ResourceLimit {
                kind: JsonLimitKind::NestingDepth,
                limit: self.limits.maximum_nesting_depth,
                observed: depth,
            });
        }
        let node = match self.peek() {
            Some(b'n') => {
                self.consume_literal(b"null")?;
                JsonNode::Null
            }
            Some(b't') => {
                self.consume_literal(b"true")?;
                JsonNode::Bool(true)
            }
            Some(b'f') => {
                self.consume_literal(b"false")?;
                JsonNode::Bool(false)
            }
            Some(b'"') => JsonNode::String(self.parse_string(true)?),
            Some(b'-' | b'0'..=b'9') => {
                let range = self.parse_number()?;
                JsonNode::Number(ExactDecimal {
                    input: self.input.clone(),
                    range,
                })
            }
            Some(b'[') => {
                self.cursor += 1;
                JsonNode::Array(Vec::new())
            }
            Some(b'{') => {
                self.cursor += 1;
                JsonNode::Object(Vec::new())
            }
            _ => return Err(self.syntax()),
        };
        let opens_array = matches!(node, JsonNode::Array(_));
        let opens_object = matches!(node, JsonNode::Object(_));
        let id = self.push_node(node)?;
        self.attach(id)?;
        if opens_array {
            self.stack.push(Frame::Array {
                node: id,
                state: ArrayState::ValueOrEnd,
            });
        } else if opens_object {
            self.stack.push(Frame::Object {
                node: id,
                state: ObjectState::NameOrEnd,
                names: BTreeSet::new(),
                pending_name: None,
            });
        }
        Ok(())
    }

    fn attach(&mut self, id: JsonNodeId) -> Result<(), JsonError> {
        let offset = self.cursor;
        let Some(parent) = self.stack.last_mut() else {
            if self.root.replace(id).is_some() {
                return Err(JsonError::Syntax { offset });
            }
            return Ok(());
        };
        match parent {
            Frame::Array { node, state }
                if matches!(*state, ArrayState::ValueOrEnd | ArrayState::Value) =>
            {
                let Some(JsonNode::Array(items)) = self.nodes.get_mut(node.0) else {
                    return Err(self.syntax());
                };
                let observed = u64::try_from(items.len())
                    .ok()
                    .and_then(|count| count.checked_add(1));
                if observed.is_none_or(|observed| observed > self.limits.maximum_list_items) {
                    return Err(JsonError::ResourceLimit {
                        kind: JsonLimitKind::ListItems,
                        limit: self.limits.maximum_list_items,
                        observed,
                    });
                }
                items.push(id);
                *state = ArrayState::CommaOrEnd;
            }
            Frame::Object {
                node,
                state,
                pending_name,
                ..
            } if *state == ObjectState::Value => {
                let name = pending_name.take().ok_or(JsonError::Syntax { offset })?;
                let Some(JsonNode::Object(members)) = self.nodes.get_mut(node.0) else {
                    return Err(JsonError::Syntax { offset });
                };
                members.push((name, id));
                *state = ObjectState::CommaOrEnd;
            }
            _ => return Err(JsonError::Syntax { offset }),
        }
        Ok(())
    }

    fn push_node(&mut self, node: JsonNode) -> Result<JsonNodeId, JsonError> {
        let observed = u64::try_from(self.nodes.len())
            .ok()
            .and_then(|count| count.checked_add(1));
        if observed.is_none_or(|observed| observed > self.limits.maximum_nodes) {
            return Err(JsonError::ResourceLimit {
                kind: JsonLimitKind::Nodes,
                limit: self.limits.maximum_nodes,
                observed,
            });
        }
        let id = JsonNodeId(self.nodes.len());
        self.nodes.push(node);
        Ok(id)
    }

    fn parse_string(&mut self, enforce_scalar_limit: bool) -> Result<Arc<str>, JsonError> {
        if self.peek() != Some(b'"') {
            return Err(self.syntax());
        }
        self.cursor += 1;
        let mut output = String::new();
        let mut segment = self.cursor;
        loop {
            let Some(byte) = self.peek() else {
                return Err(self.syntax());
            };
            match byte {
                b'"' => {
                    self.push_string_segment(&mut output, segment, self.cursor)?;
                    self.cursor += 1;
                    if enforce_scalar_limit {
                        let observed = u64::try_from(output.chars().count()).ok();
                        if observed
                            .is_none_or(|observed| observed > self.limits.maximum_string_scalars)
                        {
                            return Err(JsonError::ResourceLimit {
                                kind: JsonLimitKind::StringScalars,
                                limit: self.limits.maximum_string_scalars,
                                observed,
                            });
                        }
                    }
                    return Ok(Arc::from(output));
                }
                b'\\' => {
                    self.push_string_segment(&mut output, segment, self.cursor)?;
                    self.cursor += 1;
                    self.parse_escape(&mut output)?;
                    segment = self.cursor;
                }
                0x00..=0x1f => return Err(self.syntax()),
                _ => self.cursor += 1,
            }
        }
    }

    fn push_string_segment(
        &self,
        output: &mut String,
        start: usize,
        end: usize,
    ) -> Result<(), JsonError> {
        let segment =
            std::str::from_utf8(&self.input[start..end]).map_err(|_| JsonError::InvalidUtf8)?;
        output.push_str(segment);
        Ok(())
    }

    fn parse_escape(&mut self, output: &mut String) -> Result<(), JsonError> {
        let Some(escaped) = self.peek() else {
            return Err(self.syntax());
        };
        self.cursor += 1;
        match escaped {
            b'"' => output.push('"'),
            b'\\' => output.push('\\'),
            b'/' => output.push('/'),
            b'b' => output.push('\u{0008}'),
            b'f' => output.push('\u{000c}'),
            b'n' => output.push('\n'),
            b'r' => output.push('\r'),
            b't' => output.push('\t'),
            b'u' => {
                let offset = self.cursor.saturating_sub(2);
                let first = self.parse_hex_quad()?;
                let scalar = if (0xd800..=0xdbff).contains(&first) {
                    if self.input.get(self.cursor..self.cursor.saturating_add(2)) != Some(b"\\u") {
                        return Err(JsonError::UnpairedSurrogate { offset });
                    }
                    self.cursor += 2;
                    let second = self.parse_hex_quad()?;
                    if !(0xdc00..=0xdfff).contains(&second) {
                        return Err(JsonError::UnpairedSurrogate { offset });
                    }
                    0x1_0000 + (((u32::from(first) - 0xd800) << 10) | (u32::from(second) - 0xdc00))
                } else if (0xdc00..=0xdfff).contains(&first) {
                    return Err(JsonError::UnpairedSurrogate { offset });
                } else {
                    u32::from(first)
                };
                output.push(char::from_u32(scalar).ok_or(JsonError::UnpairedSurrogate { offset })?);
            }
            _ => return Err(self.syntax()),
        }
        Ok(())
    }

    fn parse_hex_quad(&mut self) -> Result<u16, JsonError> {
        let mut value = 0_u16;
        for _ in 0..4 {
            let Some(byte) = self.peek() else {
                return Err(self.syntax());
            };
            let digit = match byte {
                b'0'..=b'9' => u16::from(byte - b'0'),
                b'a'..=b'f' => u16::from(byte - b'a') + 10,
                b'A'..=b'F' => u16::from(byte - b'A') + 10,
                _ => return Err(self.syntax()),
            };
            value = value.saturating_mul(16).saturating_add(digit);
            self.cursor += 1;
        }
        Ok(value)
    }

    fn parse_number(&mut self) -> Result<Range<usize>, JsonError> {
        let start = self.cursor;
        if self.peek() == Some(b'-') {
            self.cursor += 1;
        }
        match self.peek() {
            Some(b'0') => {
                self.cursor += 1;
                if self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                    return Err(self.syntax());
                }
            }
            Some(b'1'..=b'9') => self.consume_digits(),
            _ => return Err(self.syntax()),
        }
        if self.peek() == Some(b'.') {
            self.cursor += 1;
            if !self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                return Err(self.syntax());
            }
            self.consume_digits();
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.cursor += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.cursor += 1;
            }
            if !self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                return Err(self.syntax());
            }
            self.consume_digits();
        }
        Ok(start..self.cursor)
    }

    fn consume_digits(&mut self) {
        while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
            self.cursor += 1;
        }
    }

    fn consume_literal(&mut self, expected: &[u8]) -> Result<(), JsonError> {
        if self
            .input
            .get(self.cursor..self.cursor.saturating_add(expected.len()))
            != Some(expected)
        {
            return Err(self.syntax());
        }
        self.cursor += expected.len();
        Ok(())
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.cursor += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.cursor).copied()
    }

    fn syntax(&self) -> JsonError {
        JsonError::Syntax {
            offset: self.cursor,
        }
    }
}

fn decimal_to_int(lexeme: &str) -> Result<i64, NumberError> {
    let value = decimal_view(lexeme);
    if value.digits.is_empty() {
        return Ok(0);
    }
    if value.scale < 0 {
        return Err(NumberError::NonIntegral);
    }
    let appended = usize::try_from(value.scale).map_err(|_| NumberError::OutOfRange)?;
    if value.digits.len().saturating_add(appended) > 16 {
        return Err(NumberError::OutOfRange);
    }
    let mut magnitude = 0_u64;
    for digit in &value.digits {
        magnitude = magnitude
            .checked_mul(10)
            .and_then(|value| value.checked_add(u64::from(*digit - b'0')))
            .ok_or(NumberError::OutOfRange)?;
    }
    for _ in 0..appended {
        magnitude = magnitude.checked_mul(10).ok_or(NumberError::OutOfRange)?;
    }
    const MAXIMUM: u64 = 9_007_199_254_740_991;
    if magnitude > MAXIMUM {
        return Err(NumberError::OutOfRange);
    }
    let magnitude = i64::try_from(magnitude).map_err(|_| NumberError::OutOfRange)?;
    Ok(if value.negative {
        -magnitude
    } else {
        magnitude
    })
}

struct DecimalView {
    negative: bool,
    digits: Vec<u8>,
    scale: i128,
}

fn decimal_view(lexeme: &str) -> DecimalView {
    let bytes = lexeme.as_bytes();
    let negative = bytes.first() == Some(&b'-');
    let unsigned = if negative { &bytes[1..] } else { bytes };
    let exponent_index = unsigned.iter().position(|byte| matches!(byte, b'e' | b'E'));
    let significand = &unsigned[..exponent_index.unwrap_or(unsigned.len())];
    let exponent = exponent_index
        .map(|index| parse_exponent_saturating(&unsigned[index + 1..]))
        .unwrap_or(0);
    let fraction_len = significand
        .iter()
        .position(|byte| *byte == b'.')
        .map(|index| significand.len().saturating_sub(index + 1))
        .unwrap_or(0);
    let mut digits = significand
        .iter()
        .copied()
        .filter(|byte| *byte != b'.')
        .collect::<Vec<_>>();
    let leading = digits
        .iter()
        .position(|byte| *byte != b'0')
        .unwrap_or(digits.len());
    digits.drain(..leading);
    let trailing = digits
        .iter()
        .rev()
        .take_while(|byte| **byte == b'0')
        .count();
    digits.truncate(digits.len().saturating_sub(trailing));
    let fraction_len = i128::try_from(fraction_len).unwrap_or(i128::MAX);
    let trailing = i128::try_from(trailing).unwrap_or(i128::MAX);
    let scale = exponent
        .saturating_sub(fraction_len)
        .saturating_add(trailing);
    DecimalView {
        negative: negative && !digits.is_empty(),
        digits,
        scale,
    }
}

fn compare_decimals(left: &str, right: &str) -> Ordering {
    let left = decimal_view(left);
    let right = decimal_view(right);
    match (left.negative, right.negative) {
        (true, false) => Ordering::Less,
        (false, true) => Ordering::Greater,
        (true, true) => compare_views_magnitude(&right, &left),
        (false, false) => compare_views_magnitude(&left, &right),
    }
}

fn compare_decimal_magnitude(left: &str, right: &str) -> Ordering {
    compare_views_magnitude(&decimal_view(left), &decimal_view(right))
}

fn compare_views_magnitude(left: &DecimalView, right: &DecimalView) -> Ordering {
    if left.digits.is_empty() || right.digits.is_empty() {
        return left.digits.len().cmp(&right.digits.len());
    }
    let left_digits = i128::try_from(left.digits.len()).unwrap_or(i128::MAX);
    let right_digits = i128::try_from(right.digits.len()).unwrap_or(i128::MAX);
    let left_exponent = left.scale.saturating_add(left_digits.saturating_sub(1));
    let right_exponent = right.scale.saturating_add(right_digits.saturating_sub(1));
    match left_exponent.cmp(&right_exponent) {
        Ordering::Equal => {
            let count = left.digits.len().max(right.digits.len());
            (0..count)
                .map(|index| left.digits.get(index).copied().unwrap_or(b'0'))
                .cmp((0..count).map(|index| right.digits.get(index).copied().unwrap_or(b'0')))
        }
        ordering => ordering,
    }
}

fn parse_exponent_saturating(bytes: &[u8]) -> i128 {
    let (negative, digits) = match bytes.first() {
        Some(b'-') => (true, &bytes[1..]),
        Some(b'+') => (false, &bytes[1..]),
        _ => (false, bytes),
    };
    let mut magnitude = 0_i128;
    for digit in digits {
        let Some(next) = magnitude
            .checked_mul(10)
            .and_then(|value| value.checked_add(i128::from(*digit - b'0')))
        else {
            return if negative { i128::MIN } else { i128::MAX };
        };
        magnitude = next;
    }
    if negative { -magnitude } else { magnitude }
}

#[cfg(test)]
mod tests {
    use super::{JsonError, JsonLimitKind, JsonLimits, JsonNode, NumberError, StrictJsonDocument};

    fn limits(depth: u64, nodes: u64) -> JsonLimits {
        JsonLimits {
            maximum_bytes: 1_000_000,
            maximum_nesting_depth: depth,
            maximum_nodes: nodes,
            maximum_string_scalars: 1_000_000,
            maximum_list_items: 1_000_000,
        }
    }

    #[test]
    fn strict_decoder_preserves_exact_numbers_and_rejects_ambiguous_json() {
        let document = StrictJsonDocument::decode(
            &br#" {"integer":1.0e0,"text":"\uD834\uDD1E","values":[true,null]} "#[..],
            limits(4, 7),
        )
        .unwrap_or_else(|error| panic!("valid strict JSON failed: {error:?}"));
        let JsonNode::Object(members) = document
            .node(document.root())
            .unwrap_or_else(|| unreachable!("root exists"))
        else {
            unreachable!("root is an object")
        };
        let number = members
            .iter()
            .find(|(name, _)| name.as_ref() == "integer")
            .and_then(|(_, id)| document.node(*id));
        assert!(
            matches!(number, Some(JsonNode::Number(value)) if value.lexeme() == "1.0e0" && value.to_gantry_int() == Ok(1))
        );
        assert!(matches!(
            StrictJsonDocument::decode(&br#"{"x":1,"x":2}"#[..], limits(2, 3)),
            Err(JsonError::DuplicateMember { .. })
        ));
        assert!(matches!(
            StrictJsonDocument::decode(&br#""\uD800""#[..], limits(1, 1)),
            Err(JsonError::UnpairedSurrogate { .. })
        ));
        assert!(matches!(
            StrictJsonDocument::decode(&b"null true"[..], limits(1, 2)),
            Err(JsonError::TrailingData { .. })
        ));
    }

    #[test]
    fn depth_and_node_limits_fail_at_the_first_rejected_value() {
        assert!(StrictJsonDocument::decode(&b"[[null]]"[..], limits(3, 3)).is_ok());
        assert!(matches!(
            StrictJsonDocument::decode(&b"[[null]]"[..], limits(2, 3)),
            Err(JsonError::ResourceLimit {
                kind: JsonLimitKind::NestingDepth,
                limit: 2,
                observed: Some(3)
            })
        ));
        assert!(matches!(
            StrictJsonDocument::decode(&b"[null,true]"[..], limits(2, 2)),
            Err(JsonError::ResourceLimit {
                kind: JsonLimitKind::Nodes,
                limit: 2,
                observed: Some(3)
            })
        ));
    }

    #[test]
    fn string_and_list_limits_are_recursive_and_exact() {
        let mut exact = limits(3, 5);
        exact.maximum_string_scalars = 2;
        exact.maximum_list_items = 2;
        assert!(StrictJsonDocument::decode("[[\"é\",\"\"] ]".as_bytes(), exact).is_ok());

        let mut string_limited = exact;
        string_limited.maximum_string_scalars = 1;
        assert!(matches!(
            StrictJsonDocument::decode("[\"éx\"]".as_bytes(), string_limited),
            Err(JsonError::ResourceLimit {
                kind: JsonLimitKind::StringScalars,
                limit: 1,
                observed: Some(2)
            })
        ));

        let mut list_limited = exact;
        list_limited.maximum_list_items = 1;
        assert!(matches!(
            StrictJsonDocument::decode(&b"[null,true]"[..], list_limited),
            Err(JsonError::ResourceLimit {
                kind: JsonLimitKind::ListItems,
                limit: 1,
                observed: Some(2)
            })
        ));
    }

    #[test]
    fn exact_numeric_normalization_handles_boundaries_and_hostile_exponents() {
        fn number(source: &str) -> super::ExactDecimal {
            let document = StrictJsonDocument::decode(source.as_bytes(), limits(1, 1))
                .unwrap_or_else(|error| panic!("number failed: {source}: {error:?}"));
            let Some(JsonNode::Number(value)) = document.node(document.root()) else {
                unreachable!("fixture is a number")
            };
            value.clone()
        }

        for source in ["1", "1.0", "1e0", "100e-2"] {
            assert_eq!(number(source).to_gantry_int(), Ok(1));
        }
        assert_eq!(number("1.5").to_gantry_int(), Err(NumberError::NonIntegral));
        assert_eq!(
            number("9007199254740991").to_gantry_int(),
            Ok(9_007_199_254_740_991)
        );
        assert_eq!(
            number("9007199254740992").to_gantry_int(),
            Err(NumberError::OutOfRange)
        );
        assert_eq!(number("-0").to_gantry_float(), Ok(0.0));
        assert_eq!(
            number("1e-999999999999999999999999999999999999").to_gantry_float(),
            Ok(0.0)
        );
        assert_eq!(
            number("1.79769313486231571e308").to_gantry_float(),
            Err(NumberError::OutOfRange)
        );
        assert_eq!(
            number("1e999999999999999999999999999999999999").to_gantry_float(),
            Err(NumberError::OutOfRange)
        );
    }

    #[test]
    fn deeply_nested_arrays_decode_without_native_recursion() {
        let depth = 10_000;
        let mut source = "[".repeat(depth);
        source.push_str("null");
        source.push_str(&"]".repeat(depth));
        let document = StrictJsonDocument::decode(
            source.as_bytes(),
            JsonLimits {
                maximum_bytes: u64::try_from(source.len())
                    .unwrap_or_else(|_| unreachable!("fixture length fits")),
                maximum_nesting_depth: depth as u64 + 1,
                maximum_nodes: depth as u64 + 1,
                maximum_string_scalars: 1,
                maximum_list_items: 1,
            },
        );
        assert!(document.is_ok());
    }
}
