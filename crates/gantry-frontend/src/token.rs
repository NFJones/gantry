//! Authored lexical tokens shared by the parser and prompt scanner.

use std::sync::Arc;

use gantry_core::source::SourceSpan;

use crate::prompt::PromptTemplate;

/// One nontrivia source token or the final zero-width boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Token {
    kind: TokenKind,
    span: SourceSpan,
}

impl Token {
    /// Constructs a token with its exact authored byte span.
    #[must_use]
    pub const fn new(kind: TokenKind, span: SourceSpan) -> Self {
        Self { kind, span }
    }

    /// Returns the lexical classification and retained token value.
    #[must_use]
    pub const fn kind(&self) -> &TokenKind {
        &self.kind
    }

    /// Returns the exact source bytes occupied by this token.
    #[must_use]
    pub const fn span(&self) -> &SourceSpan {
        &self.span
    }
}

/// Closed lexical token classes consumed by the surface parser.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TokenKind {
    /// An exact, non-reserved identifier spelling.
    Identifier(Arc<str>),
    /// A reserved source word.
    ReservedWord(ReservedWord),
    /// An exact decimal integer-literal spelling.
    IntegerLiteral(Arc<str>),
    /// A parser-requested directive integer with unchanged boundaries.
    DirectiveInteger(Arc<str>),
    /// An exact decimal floating-literal spelling.
    FloatLiteral(Arc<str>),
    /// An ordinary quoted string after escape decoding.
    StringLiteral(Arc<str>),
    /// A raw string body with authored content preserved.
    RawStringLiteral(Arc<str>),
    /// One parser-requested prompt template and its interpolation islands.
    PromptTemplate(PromptTemplate),
    /// A fixed punctuation or operator token.
    Punctuation(Punctuation),
    /// The zero-width boundary after the final source scalar.
    EndOfFile,
}

/// Fixed punctuation and operators, classified by maximal munch.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Punctuation {
    /// `(`.
    LeftParenthesis,
    /// `)`.
    RightParenthesis,
    /// `{`.
    LeftBrace,
    /// `}`.
    RightBrace,
    /// `[`.
    LeftBracket,
    /// `]`.
    RightBracket,
    /// `,`.
    Comma,
    /// `;`.
    Semicolon,
    /// `:`.
    Colon,
    /// `::`.
    PathSeparator,
    /// `.`.
    Dot,
    /// `->`.
    ThinArrow,
    /// `=>`.
    FatArrow,
    /// `=`.
    Equal,
    /// `==`.
    EqualEqual,
    /// `!`.
    Bang,
    /// `!=`.
    NotEqual,
    /// `<`.
    Less,
    /// `<=`.
    LessEqual,
    /// `>`.
    Greater,
    /// `>=`.
    GreaterEqual,
    /// `&&`.
    AndAnd,
    /// `||`.
    OrOr,
    /// `+`.
    Plus,
    /// `+=`.
    PlusEqual,
    /// `-`.
    Minus,
    /// `-=`.
    MinusEqual,
    /// `*`.
    Star,
    /// `*=`.
    StarEqual,
    /// `/`.
    Slash,
    /// `/=`.
    SlashEqual,
    /// `%`.
    Percent,
    /// `%=`.
    PercentEqual,
    /// The reserved one-character `_` token.
    Underscore,
}

impl Punctuation {
    /// Returns the exact authored spelling.
    #[must_use]
    pub const fn spelling(self) -> &'static str {
        match self {
            Self::LeftParenthesis => "(",
            Self::RightParenthesis => ")",
            Self::LeftBrace => "{",
            Self::RightBrace => "}",
            Self::LeftBracket => "[",
            Self::RightBracket => "]",
            Self::Comma => ",",
            Self::Semicolon => ";",
            Self::Colon => ":",
            Self::PathSeparator => "::",
            Self::Dot => ".",
            Self::ThinArrow => "->",
            Self::FatArrow => "=>",
            Self::Equal => "=",
            Self::EqualEqual => "==",
            Self::Bang => "!",
            Self::NotEqual => "!=",
            Self::Less => "<",
            Self::LessEqual => "<=",
            Self::Greater => ">",
            Self::GreaterEqual => ">=",
            Self::AndAnd => "&&",
            Self::OrOr => "||",
            Self::Plus => "+",
            Self::PlusEqual => "+=",
            Self::Minus => "-",
            Self::MinusEqual => "-=",
            Self::Star => "*",
            Self::StarEqual => "*=",
            Self::Slash => "/",
            Self::SlashEqual => "/=",
            Self::Percent => "%",
            Self::PercentEqual => "%=",
            Self::Underscore => "_",
        }
    }
}

/// One reserved word from the Gantry v1 source grammar.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ReservedWord(&'static str);

impl ReservedWord {
    /// Classifies an exact identifier spelling after maximal-munch scanning.
    #[must_use]
    pub fn from_spelling(value: &str) -> Option<Self> {
        Some(Self(match value {
            "action" => "action",
            "agent" => "agent",
            "agents" => "agents",
            "as" => "as",
            "attempt" => "attempt",
            "Bool" => "Bool",
            "break" => "break",
            "continue" => "continue",
            "crate" => "crate",
            "Decision" => "Decision",
            "decide" => "decide",
            "default" => "default",
            "detach" => "detach",
            "discard" => "discard",
            "effects" => "effects",
            "else" => "else",
            "enum" => "enum",
            "Err" => "Err",
            "false" => "false",
            "Float" => "Float",
            "fn" => "fn",
            "fork" => "fork",
            "for" => "for",
            "idempotent" => "idempotent",
            "if" => "if",
            "impl" => "impl",
            "in" => "in",
            "inline" => "inline",
            "Int" => "Int",
            "join" => "join",
            "joinall" => "joinall",
            "let" => "let",
            "limit" => "limit",
            "List" => "List",
            "loop" => "loop",
            "match" => "match",
            "mod" => "mod",
            "mut" => "mut",
            "new" => "new",
            "non_idempotent" => "non_idempotent",
            "None" => "None",
            "null" => "null",
            "Ok" => "Ok",
            "OperationError" => "OperationError",
            "Option" => "Option",
            "prompt" => "prompt",
            "pure" => "pure",
            "read_only" => "read_only",
            "Result" => "Result",
            "return" => "return",
            "retry_limit" => "retry_limit",
            "self" => "self",
            "session" => "session",
            "Some" => "Some",
            "spawn" => "spawn",
            "String" => "String",
            "struct" => "struct",
            "super" => "super",
            "Self" => "Self",
            "trait" => "trait",
            "true" => "true",
            "Tuple" => "Tuple",
            "unbounded" => "unbounded",
            "Unit" => "Unit",
            "until" => "until",
            "use" => "use",
            "using" => "using",
            "when" => "when",
            "where" => "where",
            "while" => "while",
            "with" => "with",
            _ => return None,
        }))
    }

    /// Returns the exact case-sensitive spelling.
    #[must_use]
    pub const fn spelling(self) -> &'static str {
        self.0
    }
}
