//! Scalar and binary foundation values (SPEC.md Section 35).
//!
//! This module is the pure analyzer declaration model for `Never`, `Char`,
//! fixed-width integers, `Byte`, `Bytes`, and `ByteBuffer`. It is portable: no
//! host representation, target pointer width, byte order, allocator, or spare
//! capacity is observable, and no operation depends on a process locale.

use std::cmp::Ordering;
use std::fmt;

/// A declared fixed width in bits.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ScalarWidth {
    /// Eight-bit width.
    W8,
    /// Sixteen-bit width.
    W16,
    /// Thirty-two-bit width.
    W32,
    /// Sixty-four-bit width.
    W64,
}

impl ScalarWidth {
    /// Every declared width, in declaration order.
    pub const ALL: [Self; 4] = [Self::W8, Self::W16, Self::W32, Self::W64];

    /// Bits named by this width.
    #[must_use]
    pub const fn bits(self) -> u32 {
        match self {
            Self::W8 => 8,
            Self::W16 => 16,
            Self::W32 => 32,
            Self::W64 => 64,
        }
    }

    /// Whole octets occupied by one value of this width.
    #[must_use]
    pub const fn octets(self) -> usize {
        (self.bits() / 8) as usize
    }
}

/// One declared scalar or binary kind.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ScalarKind {
    /// The non-value with no normal completion.
    Never,
    /// One Unicode scalar value.
    Char,
    /// One signed fixed-width integer.
    Signed(ScalarWidth),
    /// One unsigned fixed-width integer.
    Unsigned(ScalarWidth),
    /// One logical octet, distinct from `Unsigned(W8)`.
    Byte,
    /// An immutable octet sequence.
    Bytes,
    /// A logically mutable octet buffer with an initialized prefix.
    ByteBuffer,
}

impl ScalarKind {
    /// Every declared kind, in declaration order.
    pub const ALL: [Self; 13] = [
        Self::Never,
        Self::Char,
        Self::Signed(ScalarWidth::W8),
        Self::Signed(ScalarWidth::W16),
        Self::Signed(ScalarWidth::W32),
        Self::Signed(ScalarWidth::W64),
        Self::Unsigned(ScalarWidth::W8),
        Self::Unsigned(ScalarWidth::W16),
        Self::Unsigned(ScalarWidth::W32),
        Self::Unsigned(ScalarWidth::W64),
        Self::Byte,
        Self::Bytes,
        Self::ByteBuffer,
    ];

    /// Canonical spelling of this kind.
    #[must_use]
    pub const fn canonical_name(self) -> &'static str {
        match self {
            Self::Never => "Never",
            Self::Char => "Char",
            Self::Signed(ScalarWidth::W8) => "Int8",
            Self::Signed(ScalarWidth::W16) => "Int16",
            Self::Signed(ScalarWidth::W32) => "Int32",
            Self::Signed(ScalarWidth::W64) => "Int64",
            Self::Unsigned(ScalarWidth::W8) => "UInt8",
            Self::Unsigned(ScalarWidth::W16) => "UInt16",
            Self::Unsigned(ScalarWidth::W32) => "UInt32",
            Self::Unsigned(ScalarWidth::W64) => "UInt64",
            Self::Byte => "Byte",
            Self::Bytes => "Bytes",
            Self::ByteBuffer => "ByteBuffer",
        }
    }

    /// Whether this kind admits values at all.
    #[must_use]
    pub const fn is_value(self) -> bool {
        !matches!(self, Self::Never)
    }

    /// Declared element width, when the kind names one.
    #[must_use]
    pub const fn width(self) -> Option<ScalarWidth> {
        match self {
            Self::Signed(width) | Self::Unsigned(width) => Some(width),
            _ => None,
        }
    }

    /// Whether the kind names one of the fixed-width integers.
    #[must_use]
    pub const fn is_integer(self) -> bool {
        matches!(self, Self::Signed(_) | Self::Unsigned(_))
    }

    /// Canonical encoding of one value of this kind, when one exists.
    #[must_use]
    pub const fn canonical_encoding(self) -> Option<&'static str> {
        match self {
            Self::Never => None,
            Self::Char => Some("utf8-scalar"),
            Self::Signed(_) | Self::Unsigned(_) | Self::Byte => {
                Some("twos-complement-little-endian")
            }
            Self::Bytes | Self::ByteBuffer => Some("octet-sequence"),
        }
    }
}

/// Frozen scalar diagnostic vocabulary, one spelling per owning clause.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ScalarDiagnosticCode {
    /// `GNT-35.1`: a declared width or kind shape is invalid.
    InvalidWidth,
    /// `GNT-35.2`: a literal or canonical text is malformed.
    InvalidLiteral,
    /// `GNT-35.3`: checked arithmetic would leave the declared range.
    OverflowRefused,
    /// `GNT-35.4`: division or remainder used a zero divisor.
    DivisionByZero,
    /// `GNT-35.5`: a shift amount is out of range.
    InvalidShift,
    /// `GNT-35.6`: a character value is not a Unicode scalar value.
    InvalidChar,
    /// `GNT-35.7`: an octet sequence or text is not canonical.
    NoncanonicalEncoding,
    /// `GNT-35.8`: a buffer index or length is out of range.
    BufferBounds,
    /// `GNT-35.8`: a shared buffer was mutated.
    BufferSharedMutation,
    /// `GNT-35.9`: two values of different scalar kinds were compared.
    CrossWidthComparison,
    /// `GNT-35.10`: an allocation charge exceeds the declared quota.
    QuotaExceeded,
    /// `GNT-35.11`: storage strategies diverged observably.
    StorageStrategyDivergence,
    /// `GNT-35.12`: a `Never` value was constructed, encoded, or journaled.
    NeverConstructed,
    /// `GNT-35.12`: a non-claim was presented as a guarantee.
    NonClaimAsGuarantee,
}

impl ScalarDiagnosticCode {
    /// Every frozen code, in clause order.
    pub const ALL: [Self; 14] = [
        Self::InvalidWidth,
        Self::InvalidLiteral,
        Self::OverflowRefused,
        Self::DivisionByZero,
        Self::InvalidShift,
        Self::InvalidChar,
        Self::NoncanonicalEncoding,
        Self::BufferBounds,
        Self::BufferSharedMutation,
        Self::CrossWidthComparison,
        Self::QuotaExceeded,
        Self::StorageStrategyDivergence,
        Self::NeverConstructed,
        Self::NonClaimAsGuarantee,
    ];

    /// Frozen diagnostic spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidWidth => "scalar-invalid-width",
            Self::InvalidLiteral => "scalar-invalid-literal",
            Self::OverflowRefused => "scalar-overflow-refused",
            Self::DivisionByZero => "scalar-division-by-zero",
            Self::InvalidShift => "scalar-invalid-shift",
            Self::InvalidChar => "scalar-invalid-char",
            Self::NoncanonicalEncoding => "scalar-noncanonical-encoding",
            Self::BufferBounds => "scalar-buffer-bounds",
            Self::BufferSharedMutation => "scalar-buffer-shared-mutation",
            Self::CrossWidthComparison => "scalar-cross-width-comparison",
            Self::QuotaExceeded => "scalar-quota-exceeded",
            Self::StorageStrategyDivergence => "scalar-storage-strategy-divergence",
            Self::NeverConstructed => "scalar-never-constructed",
            Self::NonClaimAsGuarantee => "scalar-non-claim-as-guarantee",
        }
    }

    /// Owning clause identifier.
    #[must_use]
    pub const fn clause(self) -> &'static str {
        match self {
            Self::InvalidWidth => "GNT-35.1",
            Self::InvalidLiteral => "GNT-35.2",
            Self::OverflowRefused => "GNT-35.3",
            Self::DivisionByZero => "GNT-35.4",
            Self::InvalidShift => "GNT-35.5",
            Self::InvalidChar => "GNT-35.6",
            Self::NoncanonicalEncoding => "GNT-35.7",
            Self::BufferBounds | Self::BufferSharedMutation => "GNT-35.8",
            Self::CrossWidthComparison => "GNT-35.9",
            Self::QuotaExceeded => "GNT-35.10",
            Self::StorageStrategyDivergence => "GNT-35.11",
            Self::NeverConstructed | Self::NonClaimAsGuarantee => "GNT-35.12",
        }
    }
}

/// One refused scalar operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScalarError {
    code: ScalarDiagnosticCode,
    detail: String,
}

impl ScalarError {
    /// Refusal carrying its frozen code.
    #[must_use]
    pub fn new(code: ScalarDiagnosticCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }

    /// Frozen diagnostic code.
    #[must_use]
    pub const fn code(&self) -> ScalarDiagnosticCode {
        self.code
    }

    /// Human-readable detail; diagnostics remain the authority.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl fmt::Display for ScalarError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code.as_str(), self.detail)
    }
}

impl std::error::Error for ScalarError {}

/// Explicit overflow policy for one arithmetic operation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum OverflowMode {
    /// Refuse the operation instead of wrapping (the default).
    Refuse,
    /// Wrap modulo the declared width.
    Wrapping,
    /// Clamp to the declared range.
    Saturating,
}

impl OverflowMode {
    /// Every declared mode.
    pub const ALL: [Self; 3] = [Self::Refuse, Self::Wrapping, Self::Saturating];

    /// Canonical spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Refuse => "refuse",
            Self::Wrapping => "wrapping",
            Self::Saturating => "saturating",
        }
    }
}

/// One fixed-width integer value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IntegerValue {
    kind: ScalarKind,
    value: i128,
}

impl IntegerValue {
    /// Inclusive range of one integer kind.
    #[must_use]
    pub fn bounds(kind: ScalarKind) -> Option<(i128, i128)> {
        let width = kind.width()?;
        let bits = i128::from(width.bits());
        Some(match kind {
            ScalarKind::Signed(_) => (-(1i128 << (bits - 1)), (1i128 << (bits - 1)) - 1),
            _ => (0, (1i128 << bits) - 1),
        })
    }

    /// Whether a value lies inside the declared range of a kind.
    #[must_use]
    pub fn in_range(kind: ScalarKind, value: i128) -> bool {
        Self::bounds(kind).is_some_and(|(low, high)| value >= low && value <= high)
    }

    /// Parses canonical decimal text for an integer kind.
    pub fn parse(kind: ScalarKind, text: &str) -> Result<Self, ScalarError> {
        if !kind.is_value() {
            return Err(ScalarError::new(
                ScalarDiagnosticCode::NeverConstructed,
                "Never admits no value",
            ));
        }
        if !kind.is_integer() {
            return Err(ScalarError::new(
                ScalarDiagnosticCode::InvalidLiteral,
                format!("{} is not a fixed-width integer", kind.canonical_name()),
            ));
        }
        let value = Self::parse_canonical_text(kind, text)?;
        let parsed = Self { kind, value };
        if parsed.to_canonical_string() != text {
            return Err(ScalarError::new(
                ScalarDiagnosticCode::InvalidLiteral,
                format!("{text} is not the canonical spelling of its value"),
            ));
        }
        Ok(parsed)
    }

    /// Constructs a value that is known to lie inside the declared range.
    pub fn new(kind: ScalarKind, value: i128) -> Result<Self, ScalarError> {
        if !kind.is_integer() {
            return Err(ScalarError::new(
                ScalarDiagnosticCode::InvalidWidth,
                format!("{} is not a fixed-width integer", kind.canonical_name()),
            ));
        }
        if !Self::in_range(kind, value) {
            return Err(ScalarError::new(
                ScalarDiagnosticCode::OverflowRefused,
                format!("{value} leaves the range of {}", kind.canonical_name()),
            ));
        }
        Ok(Self { kind, value })
    }

    fn parse_canonical_text(kind: ScalarKind, text: &str) -> Result<i128, ScalarError> {
        let (negative, digits) = match text.strip_prefix('-') {
            Some(rest) => (true, rest),
            None => (false, text),
        };
        let malformed = digits.is_empty()
            || !digits.bytes().all(|byte| byte.is_ascii_digit())
            || (digits.len() > 1 && digits.starts_with('0'))
            || (negative && digits == "0")
            || (text.starts_with('+'))
            || (negative && !matches!(kind, ScalarKind::Signed(_)));
        if malformed {
            return Err(ScalarError::new(
                ScalarDiagnosticCode::InvalidLiteral,
                format!(
                    "{text} is not canonical decimal text for {}",
                    kind.canonical_name()
                ),
            ));
        }
        let magnitude: i128 = digits.parse().map_err(|_| {
            ScalarError::new(
                ScalarDiagnosticCode::InvalidLiteral,
                format!("{text} does not denote a fixed-width integer"),
            )
        })?;
        let value = if negative { -magnitude } else { magnitude };
        if !Self::in_range(kind, value) {
            return Err(ScalarError::new(
                ScalarDiagnosticCode::InvalidLiteral,
                format!("{text} leaves the range of {}", kind.canonical_name()),
            ));
        }
        Ok(value)
    }

    /// Declared kind of this value.
    #[must_use]
    pub const fn kind(self) -> ScalarKind {
        self.kind
    }

    /// Exact numeric value.
    #[must_use]
    pub const fn value(self) -> i128 {
        self.value
    }

    /// Canonical decimal spelling.
    #[must_use]
    pub fn to_canonical_string(self) -> String {
        self.value.to_string()
    }

    fn settle(self, exact: i128, mode: OverflowMode, operation: &str) -> Result<Self, ScalarError> {
        if Self::in_range(self.kind, exact) {
            return Ok(Self {
                kind: self.kind,
                value: exact,
            });
        }
        match mode {
            OverflowMode::Refuse => Err(ScalarError::new(
                ScalarDiagnosticCode::OverflowRefused,
                format!(
                    "{operation} leaves the range of {}",
                    self.kind.canonical_name()
                ),
            )),
            OverflowMode::Wrapping => {
                let width = self.kind.width().map_or(64, ScalarWidth::bits);
                let modulus = 1i128 << width;
                let wrapped = match self.kind {
                    ScalarKind::Signed(_) => {
                        (exact + (modulus >> 1)).rem_euclid(modulus) - (modulus >> 1)
                    }
                    _ => exact.rem_euclid(modulus),
                };
                Ok(Self {
                    kind: self.kind,
                    value: wrapped,
                })
            }
            OverflowMode::Saturating => {
                let (low, high) = Self::bounds(self.kind).ok_or_else(|| {
                    ScalarError::new(
                        ScalarDiagnosticCode::InvalidWidth,
                        "saturating arithmetic requires a declared width",
                    )
                })?;
                Ok(Self {
                    kind: self.kind,
                    value: exact.clamp(low, high),
                })
            }
        }
    }

    fn same_kind(self, other: Self, operation: &str) -> Result<(), ScalarError> {
        if self.kind == other.kind {
            Ok(())
        } else {
            Err(ScalarError::new(
                ScalarDiagnosticCode::CrossWidthComparison,
                format!(
                    "{operation} refuses {} against {}",
                    self.kind.canonical_name(),
                    other.kind.canonical_name()
                ),
            ))
        }
    }

    /// Addition under an explicit overflow mode.
    pub fn add(self, other: Self, mode: OverflowMode) -> Result<Self, ScalarError> {
        self.same_kind(other, "addition")?;
        self.settle(self.value + other.value, mode, "addition")
    }

    /// Subtraction under an explicit overflow mode.
    pub fn subtract(self, other: Self, mode: OverflowMode) -> Result<Self, ScalarError> {
        self.same_kind(other, "subtraction")?;
        self.settle(self.value - other.value, mode, "subtraction")
    }

    /// Multiplication under an explicit overflow mode.
    pub fn multiply(self, other: Self, mode: OverflowMode) -> Result<Self, ScalarError> {
        self.same_kind(other, "multiplication")?;
        self.settle(self.value * other.value, mode, "multiplication")
    }

    /// Quotient truncating toward zero; a zero divisor is refused.
    pub fn divide(self, other: Self, mode: OverflowMode) -> Result<Self, ScalarError> {
        self.same_kind(other, "division")?;
        if other.value == 0 {
            return Err(ScalarError::new(
                ScalarDiagnosticCode::DivisionByZero,
                "division by zero",
            ));
        }
        self.settle(self.value / other.value, mode, "division")
    }

    /// Remainder whose sign follows the dividend; a zero divisor is refused.
    pub fn remainder(self, other: Self, mode: OverflowMode) -> Result<Self, ScalarError> {
        self.same_kind(other, "remainder")?;
        if other.value == 0 {
            return Err(ScalarError::new(
                ScalarDiagnosticCode::DivisionByZero,
                "remainder by zero",
            ));
        }
        self.settle(self.value % other.value, mode, "remainder")
    }

    /// Left shift; the amount must be strictly less than the declared width.
    pub fn shift_left(self, amount: u32, mode: OverflowMode) -> Result<Self, ScalarError> {
        let width = self.kind.width().map_or(64, ScalarWidth::bits);
        if amount >= width {
            return Err(ScalarError::new(
                ScalarDiagnosticCode::InvalidShift,
                format!("shift amount {amount} is not below the declared width {width}"),
            ));
        }
        self.settle(self.value << amount, mode, "left shift")
    }

    /// Right shift, arithmetic for signed kinds and logical for unsigned kinds.
    pub fn shift_right(self, amount: u32) -> Result<Self, ScalarError> {
        let width = self.kind.width().map_or(64, ScalarWidth::bits);
        if amount >= width {
            return Err(ScalarError::new(
                ScalarDiagnosticCode::InvalidShift,
                format!("shift amount {amount} is not below the declared width {width}"),
            ));
        }
        Ok(Self {
            kind: self.kind,
            value: self.value >> amount,
        })
    }

    /// Total order within one scalar kind; different kinds are refused.
    pub fn compare(self, other: Self) -> Result<Ordering, ScalarError> {
        self.same_kind(other, "comparison")?;
        Ok(self.value.cmp(&other.value))
    }

    /// Stable hash over the canonical spelling and declared kind.
    #[must_use]
    pub fn stable_hash(self) -> u64 {
        let mut hash = 0xcbf2_9ce4_8422_2325_u64;
        for byte in self
            .kind
            .canonical_name()
            .bytes()
            .chain(b":".iter().copied())
            .chain(self.to_canonical_string().bytes())
        {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        hash
    }
}

/// One octet value, distinct from `Unsigned(W8)`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ByteValue(u8);

impl ByteValue {
    /// Builds an octet from an exact numeric value.
    pub fn new(value: i128) -> Result<Self, ScalarError> {
        u8::try_from(value).map(Self).map_err(|_| {
            ScalarError::new(
                ScalarDiagnosticCode::InvalidLiteral,
                format!("{value} is not a logical octet"),
            )
        })
    }

    /// Parses canonical decimal text for one octet.
    pub fn parse(text: &str) -> Result<Self, ScalarError> {
        if text.is_empty()
            || !text.bytes().all(|byte| byte.is_ascii_digit())
            || (text.len() > 1 && text.starts_with('0'))
        {
            return Err(ScalarError::new(
                ScalarDiagnosticCode::InvalidLiteral,
                format!("{text} is not canonical decimal text for Byte"),
            ));
        }
        let magnitude: u16 = text.parse().map_err(|_| {
            ScalarError::new(
                ScalarDiagnosticCode::InvalidLiteral,
                format!("{text} is not a logical octet"),
            )
        })?;
        Self::new(i128::from(magnitude))
    }

    /// Exact octet value.
    #[must_use]
    pub const fn value(self) -> u8 {
        self.0
    }

    /// Canonical decimal spelling.
    #[must_use]
    pub fn to_canonical_string(self) -> String {
        self.0.to_string()
    }
}

/// One Unicode scalar value.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CharValue(char);

impl CharValue {
    /// Builds a character from a code point, refusing non-scalar values.
    pub fn new(code_point: u32) -> Result<Self, ScalarError> {
        char::from_u32(code_point).map(Self).ok_or_else(|| {
            ScalarError::new(
                ScalarDiagnosticCode::InvalidChar,
                format!("U+{code_point:04X} is not a Unicode scalar value"),
            )
        })
    }

    /// Code point of this character.
    #[must_use]
    pub const fn code_point(self) -> u32 {
        self.0 as u32
    }

    /// Canonical text of this character.
    #[must_use]
    pub fn to_canonical_string(self) -> String {
        self.0.to_string()
    }

    /// Canonical UTF-8 octets of this character.
    #[must_use]
    pub fn utf8_octets(self) -> Vec<u8> {
        let mut buffer = [0_u8; 4];
        self.0.encode_utf8(&mut buffer).as_bytes().to_vec()
    }
}

/// An immutable octet sequence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BytesValue {
    octets: Vec<u8>,
}

impl BytesValue {
    /// Seals an octet sequence as an immutable value.
    #[must_use]
    pub fn from_octets(octets: Vec<u8>) -> Self {
        Self { octets }
    }

    /// Parses canonical lowercase hexadecimal text of even length.
    pub fn parse_canonical_text(text: &str) -> Result<Self, ScalarError> {
        let canonical = !text.is_empty()
            && text.len().is_multiple_of(2)
            && text
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        if !canonical {
            return Err(ScalarError::new(
                ScalarDiagnosticCode::NoncanonicalEncoding,
                format!("{text} is not canonical lowercase hexadecimal"),
            ));
        }
        let mut octets = Vec::with_capacity(text.len() / 2);
        let bytes = text.as_bytes();
        let mut index = 0;
        while index < bytes.len() {
            let high = hex_digit(bytes[index])?;
            let low = hex_digit(bytes[index + 1])?;
            octets.push((high << 4) | low);
            index += 2;
        }
        let value = Self { octets };
        if value.to_canonical_text() != text {
            return Err(ScalarError::new(
                ScalarDiagnosticCode::NoncanonicalEncoding,
                format!("{text} is not the canonical spelling of its octets"),
            ));
        }
        Ok(value)
    }

    /// Canonical lowercase hexadecimal text.
    #[must_use]
    pub fn to_canonical_text(&self) -> String {
        let mut text = String::with_capacity(self.octets.len() * 2);
        for octet in &self.octets {
            text.push(char::from_digit(u32::from(octet >> 4), 16).unwrap_or('0'));
            text.push(char::from_digit(u32::from(octet & 0x0f), 16).unwrap_or('0'));
        }
        text
    }

    /// Octet count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.octets.len()
    }

    /// Whether the sequence is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.octets.is_empty()
    }

    /// One octet by position; out-of-range positions are refused.
    pub fn octet(&self, index: usize) -> Result<u8, ScalarError> {
        self.octets.get(index).copied().ok_or_else(|| {
            ScalarError::new(
                ScalarDiagnosticCode::BufferBounds,
                format!("octet {index} is beyond the {} sealed octets", self.len()),
            )
        })
    }

    /// Decodes the sequence as canonical UTF-8 text; invalid sequences are refused.
    pub fn decode_utf8(&self) -> Result<String, ScalarError> {
        String::from_utf8(self.octets.clone()).map_err(|_| {
            ScalarError::new(
                ScalarDiagnosticCode::NoncanonicalEncoding,
                "octets are not well-formed UTF-8",
            )
        })
    }

    /// Bare octets, in canonical order.
    #[must_use]
    pub fn as_octets(&self) -> &[u8] {
        &self.octets
    }
}

fn hex_digit(byte: u8) -> Result<u8, ScalarError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(ScalarError::new(
            ScalarDiagnosticCode::NoncanonicalEncoding,
            format!("0x{byte:02x} is not a lowercase hexadecimal digit"),
        )),
    }
}

/// Declared allocation quota for buffers and sealed octet sequences.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScalarQuota {
    max_octets: usize,
    used_octets: usize,
}

impl ScalarQuota {
    /// Quota admitting exactly `max_octets` live octets.
    #[must_use]
    pub const fn new(max_octets: usize) -> Self {
        Self {
            max_octets,
            used_octets: 0,
        }
    }

    /// Quota already charged for a known number of live octets.
    #[must_use]
    pub const fn charged(max_octets: usize, used_octets: usize) -> Self {
        Self {
            max_octets,
            used_octets: if used_octets < max_octets {
                used_octets
            } else {
                max_octets
            },
        }
    }

    /// Declared ceiling.
    #[must_use]
    pub const fn max_octets(&self) -> usize {
        self.max_octets
    }

    /// Live octets charged against this quota.
    #[must_use]
    pub const fn used_octets(&self) -> usize {
        self.used_octets
    }

    /// Charges octets before mutation, refusing past the declared ceiling.
    pub fn reserve(&mut self, octets: usize) -> Result<(), ScalarError> {
        let requested = self.used_octets.checked_add(octets).ok_or_else(|| {
            ScalarError::new(
                ScalarDiagnosticCode::QuotaExceeded,
                "quota arithmetic overflowed",
            )
        })?;
        if requested > self.max_octets {
            return Err(ScalarError::new(
                ScalarDiagnosticCode::QuotaExceeded,
                format!(
                    "{requested} octets exceed the declared quota of {}",
                    self.max_octets
                ),
            ));
        }
        self.used_octets = requested;
        Ok(())
    }

    /// Releases previously charged octets.
    pub fn release(&mut self, octets: usize) {
        self.used_octets = self.used_octets.saturating_sub(octets);
    }
}

/// Physical storage strategy; nonsemantic, never observable in source behavior.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum StorageStrategy {
    /// Copy eagerly on duplication.
    EagerCopy,
    /// Share until a write follows an alias.
    CopyOnWrite,
    /// Reuse owned storage in place.
    Reuse,
}

impl StorageStrategy {
    /// Every declared strategy.
    pub const ALL: [Self; 3] = [Self::EagerCopy, Self::CopyOnWrite, Self::Reuse];

    /// Canonical spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EagerCopy => "eager-copy",
            Self::CopyOnWrite => "copy-on-write",
            Self::Reuse => "reuse",
        }
    }

    /// Nonsemantic physical work: copying octets on duplication.
    #[must_use]
    pub const fn duplication_work(self, octets: usize) -> usize {
        match self {
            Self::EagerCopy => octets,
            Self::CopyOnWrite | Self::Reuse => 0,
        }
    }

    /// Nonsemantic physical work: copying octets on a write after aliasing.
    #[must_use]
    pub const fn write_work(self, octets: usize) -> usize {
        match self {
            Self::CopyOnWrite => octets,
            Self::EagerCopy | Self::Reuse => 0,
        }
    }
}

/// A logically mutable octet buffer with an initialized prefix.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ByteBufferValue {
    strategy: StorageStrategy,
    octets: Vec<u8>,
    quota: ScalarQuota,
    aliased: bool,
    physical_work: usize,
}

impl ByteBufferValue {
    /// Empty buffer charged against a declared quota.
    #[must_use]
    pub const fn new(strategy: StorageStrategy, quota: ScalarQuota) -> Self {
        Self {
            strategy,
            octets: Vec::new(),
            quota,
            aliased: false,
            physical_work: 0,
        }
    }

    /// Buffer holding a known initialized prefix.
    pub fn with_octets(
        strategy: StorageStrategy,
        mut quota: ScalarQuota,
        octets: Vec<u8>,
    ) -> Result<Self, ScalarError> {
        quota.reserve(octets.len())?;
        Ok(Self {
            strategy,
            octets,
            quota,
            aliased: false,
            physical_work: 0,
        })
    }

    /// Physical strategy of this buffer.
    #[must_use]
    pub const fn strategy(&self) -> StorageStrategy {
        self.strategy
    }

    /// Initialized prefix.
    #[must_use]
    pub fn octets(&self) -> &[u8] {
        &self.octets
    }

    /// Initialized length.
    #[must_use]
    pub fn len(&self) -> usize {
        self.octets.len()
    }

    /// Whether the initialized prefix is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.octets.is_empty()
    }

    /// ScalarQuota state, which is semantic and identical across strategies.
    #[must_use]
    pub const fn quota(&self) -> ScalarQuota {
        self.quota
    }

    /// Nonsemantic physical work performed so far.
    #[must_use]
    pub const fn physical_work(&self) -> usize {
        self.physical_work
    }

    fn exclusive(&self) -> Result<(), ScalarError> {
        if self.aliased {
            Err(ScalarError::new(
                ScalarDiagnosticCode::BufferSharedMutation,
                "mutation requires unique ownership of the buffer",
            ))
        } else {
            Ok(())
        }
    }

    /// Appends one octet after charging the quota.
    pub fn append(&mut self, octet: u8) -> Result<(), ScalarError> {
        self.exclusive()?;
        self.quota.reserve(1)?;
        self.physical_work += self.strategy.write_work(self.octets.len());
        self.octets.push(octet);
        Ok(())
    }

    /// Appends a slice of octets after charging the quota.
    pub fn extend(&mut self, octets: &[u8]) -> Result<(), ScalarError> {
        self.exclusive()?;
        self.quota.reserve(octets.len())?;
        self.physical_work += self.strategy.write_work(self.octets.len());
        self.octets.extend_from_slice(octets);
        Ok(())
    }

    /// Truncates to a shorter length, releasing the released charge.
    pub fn truncate(&mut self, length: usize) -> Result<(), ScalarError> {
        self.exclusive()?;
        if length > self.octets.len() {
            return Err(ScalarError::new(
                ScalarDiagnosticCode::BufferBounds,
                format!(
                    "truncation to {length} exceeds the {} initialized octets",
                    self.len()
                ),
            ));
        }
        let released = self.octets.len() - length;
        self.octets.truncate(length);
        self.quota.release(released);
        Ok(())
    }

    /// Splits the buffer at a position inside the initialized prefix.
    pub fn split_off(&mut self, at: usize) -> Result<Self, ScalarError> {
        self.exclusive()?;
        if at > self.octets.len() {
            return Err(ScalarError::new(
                ScalarDiagnosticCode::BufferBounds,
                format!(
                    "split position {at} exceeds the {} initialized octets",
                    self.len()
                ),
            ));
        }
        let tail = self.octets.split_off(at);
        let ceiling = self.quota.max_octets();
        self.quota = ScalarQuota::charged(ceiling, self.octets.len());
        let tail_quota = ScalarQuota::charged(ceiling, tail.len());
        Ok(Self {
            strategy: self.strategy,
            octets: tail,
            quota: tail_quota,
            aliased: false,
            physical_work: 0,
        })
    }

    /// Consuming freeze into an immutable value; aliased buffers are refused.
    pub fn freeze(self) -> Result<BytesValue, ScalarError> {
        self.exclusive()?;
        Ok(BytesValue::from_octets(self.octets))
    }

    /// Deep copy that is independent of this buffer.
    #[must_use]
    pub fn independent_copy(&self) -> Self {
        Self {
            strategy: self.strategy,
            octets: self.octets.clone(),
            quota: self.quota,
            aliased: false,
            physical_work: self.physical_work + self.strategy.duplication_work(self.octets.len()),
        }
    }

    /// Alias sharing storage with this buffer; mutation of either is refused.
    #[must_use]
    pub fn alias(&self) -> Self {
        Self {
            strategy: self.strategy,
            octets: self.octets.clone(),
            quota: self.quota,
            aliased: true,
            physical_work: self.physical_work + self.strategy.duplication_work(self.octets.len()),
        }
    }
}

/// Section 35 clause identifiers, in order.
pub const SCALAR_CLAUSES: [&str; 13] = [
    "GNT-35.0-scalar-and-binary-foundation",
    "GNT-35.1-declared-widths-and-identity",
    "GNT-35.2-literal-formation-and-canonical-text",
    "GNT-35.3-checked-arithmetic-and-overflow-modes",
    "GNT-35.4-division-remainder-and-signed-semantics",
    "GNT-35.5-shifts-and-numeric-bounds",
    "GNT-35.6-char-values-and-unicode-scalars",
    "GNT-35.7-bytes-and-canonical-encoding",
    "GNT-35.8-bytebuffer-mutation-and-freezing",
    "GNT-35.9-equality-order-and-stable-hash",
    "GNT-35.10-allocation-quotas-and-cancellation",
    "GNT-35.11-storage-strategy-equivalence-and-round-trips",
    "GNT-35.12-scalar-and-binary-non-claims",
];

/// One non-claim this section refuses to convert into a guarantee.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ScalarNonClaimName {
    /// Raw memory or address space.
    RawMemory,
    /// Spare capacity or allocator observability.
    SpareCapacity,
    /// Uninitialized storage.
    UninitializedStorage,
    /// Pointer, FFI, or target layout.
    TargetLayout,
    /// Source literal parsing or formatting policy.
    SourceLiteralPolicy,
    /// Presentation formatting.
    PresentationFormatting,
    /// Implicit arbitrary-precision semantics.
    ArbitraryPrecision,
    /// Codecs, compression, or cryptography.
    CodecsAndCryptography,
}

impl ScalarNonClaimName {
    /// Every declared non-claim, in declaration order.
    pub const ALL: [Self; 8] = [
        Self::RawMemory,
        Self::SpareCapacity,
        Self::UninitializedStorage,
        Self::TargetLayout,
        Self::SourceLiteralPolicy,
        Self::PresentationFormatting,
        Self::ArbitraryPrecision,
        Self::CodecsAndCryptography,
    ];

    /// Canonical spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RawMemory => "raw-memory",
            Self::SpareCapacity => "spare-capacity",
            Self::UninitializedStorage => "uninitialized-storage",
            Self::TargetLayout => "target-layout",
            Self::SourceLiteralPolicy => "source-literal-policy",
            Self::PresentationFormatting => "presentation-formatting",
            Self::ArbitraryPrecision => "arbitrary-precision",
            Self::CodecsAndCryptography => "codecs-and-cryptography",
        }
    }
}

/// One recorded non-claim assertion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScalarNonClaimAssertion {
    /// Non-claim being asserted.
    pub name: ScalarNonClaimName,
    /// Whether the assertion presents the non-claim as a guarantee.
    pub claims_as_guarantee: bool,
}

/// Verifies that every non-claim is asserted and none is presented as a guarantee.
pub fn check_scalar_non_claims(assertions: &[ScalarNonClaimAssertion]) -> Result<(), ScalarError> {
    for name in ScalarNonClaimName::ALL {
        let asserted = assertions.iter().find(|entry| entry.name == name);
        match asserted {
            None => {
                return Err(ScalarError::new(
                    ScalarDiagnosticCode::NonClaimAsGuarantee,
                    format!("non-claim {} is not asserted", name.as_str()),
                ));
            }
            Some(entry) if entry.claims_as_guarantee => {
                return Err(ScalarError::new(
                    ScalarDiagnosticCode::NonClaimAsGuarantee,
                    format!("non-claim {} is presented as a guarantee", name.as_str()),
                ));
            }
            Some(_) => {}
        }
    }
    Ok(())
}
