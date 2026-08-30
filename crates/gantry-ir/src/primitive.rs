//! Deterministic primitive vocabulary evaluated by the runtime machine.

/// Numeric comparison operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Comparison {
    /// Strictly less than.
    Less,
    /// Less than or equal.
    LessOrEqual,
    /// Strictly greater than.
    Greater,
    /// Greater than or equal.
    GreaterOrEqual,
}

/// Closed deterministic operation set for the sequential machine foundation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Primitive {
    /// Boolean negation.
    Not,
    /// Numeric negation preserving the operand type.
    Negate,
    /// Numeric addition or exact String concatenation.
    Add,
    /// Numeric subtraction.
    Subtract,
    /// Numeric multiplication.
    Multiply,
    /// Numeric division.
    Divide,
    /// Integer remainder.
    Remainder,
    /// Numeric comparison.
    Compare(Comparison),
    /// Exact deep equality.
    Equal,
    /// Exact deep inequality.
    NotEqual,
    /// Exact Int-to-Float conversion.
    IntToFloat,
    /// Optional exact Float-to-Int conversion.
    FloatToInt,
    /// Canonical scalar rendering.
    ToString,
    /// List item count.
    ListLength,
    /// Unicode scalar count.
    StringLength,
    /// String emptiness.
    StringIsEmpty,
    /// Exact contiguous String containment.
    StringContains,
    /// Exact String prefix test.
    StringStartsWith,
    /// Exact String suffix test.
    StringEndsWith,
    /// Unicode 16 whitespace trim at both ends.
    StringTrim,
    /// Unicode 16 whitespace trim at the start.
    StringTrimStart,
    /// Unicode 16 whitespace trim at the end.
    StringTrimEnd,
    /// Unicode 16 full lowercase mapping.
    StringLowercase,
    /// Unicode 16 full uppercase mapping.
    StringUppercase,
    /// Exact nonoverlapping replacement.
    StringReplace,
    /// Exact nonoverlapping splitting.
    StringSplit,
    /// Exact Boolean parsing.
    StringParseBool,
    /// Exact Gantry Int parsing.
    StringParseInt,
    /// Exact finite binary64 parsing.
    StringParseFloat,
    /// Join List<String> with one exact separator.
    StringListJoin,
}

impl Primitive {
    /// Returns the exact number of completed operands consumed by this primitive.
    #[must_use]
    pub const fn arity(self) -> usize {
        match self {
            Self::Not
            | Self::Negate
            | Self::IntToFloat
            | Self::FloatToInt
            | Self::ToString
            | Self::ListLength
            | Self::StringLength
            | Self::StringIsEmpty
            | Self::StringTrim
            | Self::StringTrimStart
            | Self::StringTrimEnd
            | Self::StringLowercase
            | Self::StringUppercase
            | Self::StringParseBool
            | Self::StringParseInt
            | Self::StringParseFloat => 1,
            Self::Add
            | Self::Subtract
            | Self::Multiply
            | Self::Divide
            | Self::Remainder
            | Self::Compare(_)
            | Self::Equal
            | Self::NotEqual
            | Self::StringContains
            | Self::StringStartsWith
            | Self::StringEndsWith
            | Self::StringSplit
            | Self::StringListJoin => 2,
            Self::StringReplace => 3,
        }
    }
}
