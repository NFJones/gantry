//! Bounded handwritten lexer and contextual prompt-template scanner.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use gantry_core::portable::{DiagnosticCategory, DiagnosticSeverity};
use gantry_core::source::{
    ByteSpan, DiagnosticCode, DiagnosticMetadata, DiagnosticPhase, FrontendResourceLimit,
    SourceCounters, SourceRecord, SourceSpan, SpanError, StructuredDiagnostic,
};
use gantry_core::unicode;

use crate::prompt::{InterpolationIsland, PromptDelimiter, PromptTemplate};
use crate::token::{Punctuation, ReservedWord, Token, TokenKind};

/// Parser-selected classification for the next lexical token.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum LexContext {
    /// Ordinary source tokenization.
    #[default]
    Ordinary,
    /// Reclassify a valid separator-free decimal integer as a directive value.
    DirectiveInteger,
    /// Scan a quoted, raw, or block string as one contextual prompt template.
    PromptTemplate,
}

/// One forward-only scanner over an immutable source record.
pub struct Lexer<'a> {
    record: &'a SourceRecord,
    text: &'a str,
    counters: &'a mut SourceCounters,
    offset: usize,
}

impl<'a> Lexer<'a> {
    /// Validates UTF-8 and starts scanning at the first source scalar.
    pub fn new(
        record: &'a SourceRecord,
        counters: &'a mut SourceCounters,
    ) -> Result<Self, LexError> {
        let text = match record.text() {
            Ok(text) => text,
            Err(error) => {
                counters
                    .charge_diagnostic()
                    .map_err(LexError::ResourceLimit)?;
                let start = usize::try_from(error.valid_up_to).map_err(|_| LexError::Invariant)?;
                let end = error
                    .error_len
                    .and_then(|length| error.valid_up_to.checked_add(length))
                    .and_then(|value| usize::try_from(value).ok())
                    .unwrap_or_else(|| record.bytes().len());
                return Err(Self::diagnostic_for(
                    record,
                    "invalid-source-utf8",
                    "source is not valid UTF-8",
                    start,
                    end,
                )?);
            }
        };
        Ok(Self {
            record,
            text,
            counters,
            offset: 0,
        })
    }

    /// Scans one nontrivia token or the zero-width end boundary.
    pub fn next(&mut self, context: LexContext) -> Result<Token, LexError> {
        if self.offset == 0 && self.text.starts_with('\u{feff}') {
            self.offset += '\u{feff}'.len_utf8();
        }
        self.skip_trivia()?;
        let start = self.offset;
        if start == self.text.len() {
            return Ok(Token::new(TokenKind::EndOfFile, self.span(start, start)?));
        }

        // Invalid maximal occurrences count before their lexical diagnostic.
        self.counters
            .charge_tokens(1)
            .map_err(LexError::ResourceLimit)?;
        let kind = if context == LexContext::PromptTemplate && self.is_prompt_start() {
            self.scan_prompt_template()?
        } else {
            self.scan_ordinary(context)?
        };
        Ok(Token::new(kind, self.span(start, self.offset)?))
    }

    /// Returns the next unread byte offset.
    #[must_use]
    pub const fn offset(&self) -> usize {
        self.offset
    }

    fn scan_ordinary(&mut self, context: LexContext) -> Result<TokenKind, LexError> {
        if self.raw_prefix().is_some() {
            return self.scan_raw_string().map(TokenKind::RawStringLiteral);
        }
        if self.starts_with("\"") {
            return self.scan_quoted_string().map(TokenKind::StringLiteral);
        }
        let Some(current) = self.current_char() else {
            return Ok(TokenKind::EndOfFile);
        };
        if current.is_ascii_digit() {
            return self.scan_number(context);
        }
        if current == '_' || unicode::is_xid_start(current) {
            return self.scan_identifier();
        }
        if let Some(punctuation) = self.scan_punctuation() {
            return Ok(TokenKind::Punctuation(punctuation));
        }

        let start = self.offset;
        self.advance_char();
        if current == '\u{feff}' {
            self.fail(
                "unexpected-byte-order-mark",
                "a byte-order mark is permitted only at the start of a source file",
                start,
                self.offset,
            )
        } else {
            self.fail(
                "invalid-character",
                "source contains a scalar that cannot begin a Gantry token",
                start,
                self.offset,
            )
        }
    }

    fn scan_identifier(&mut self) -> Result<TokenKind, LexError> {
        let start = self.offset;
        let first = self.current_char().ok_or(LexError::Invariant)?;
        if first == '_' {
            self.advance_char();
            if self
                .current_char()
                .is_none_or(|value| !unicode::is_xid_continue(value))
            {
                return Ok(TokenKind::Punctuation(Punctuation::Underscore));
            }
        } else {
            self.advance_char();
        }
        while self
            .current_char()
            .is_some_and(|value| value == '_' || unicode::is_xid_continue(value))
        {
            self.advance_char();
        }
        let spelling = self.slice(start, self.offset)?;
        Ok(match ReservedWord::from_spelling(spelling) {
            Some(word) => TokenKind::ReservedWord(word),
            None => TokenKind::Identifier(Arc::from(spelling)),
        })
    }

    fn scan_number(&mut self, context: LexContext) -> Result<TokenKind, LexError> {
        let start = self.offset;
        let leading_zero = self.starts_with("0");
        self.advance_ascii();
        if leading_zero
            && self
                .current_byte()
                .is_some_and(|byte| byte.is_ascii_digit() || byte == b'_')
        {
            self.consume_number_candidate();
            return self.fail(
                "invalid-number",
                "a numeric integral part cannot contain a leading zero",
                start,
                self.offset,
            );
        }
        self.scan_decimal_tail(start)?;

        let mut float = false;
        if self.starts_with(".")
            && self
                .byte_at(self.offset.saturating_add(1))
                .is_some_and(|byte| byte.is_ascii_digit())
        {
            float = true;
            self.offset += 1;
            self.advance_ascii();
            self.scan_decimal_tail(start)?;
        }
        if self
            .current_byte()
            .is_some_and(|byte| matches!(byte, b'e' | b'E'))
        {
            float = true;
            self.offset += 1;
            if self
                .current_byte()
                .is_some_and(|byte| matches!(byte, b'+' | b'-'))
            {
                self.offset += 1;
            }
            if self
                .current_byte()
                .is_none_or(|byte| !byte.is_ascii_digit())
            {
                self.consume_number_candidate();
                return self.fail(
                    "invalid-number",
                    "a numeric exponent requires at least one decimal digit",
                    start,
                    self.offset,
                );
            }
            self.advance_ascii();
            self.scan_decimal_tail(start)?;
        }
        if self
            .current_char()
            .is_some_and(|value| value == '_' || unicode::is_xid_start(value))
        {
            self.consume_number_candidate();
            return self.fail(
                "invalid-number",
                "numeric literals do not admit suffixes",
                start,
                self.offset,
            );
        }

        let spelling: Arc<str> = Arc::from(self.slice(start, self.offset)?);
        Ok(if float {
            TokenKind::FloatLiteral(spelling)
        } else if context == LexContext::DirectiveInteger && !spelling.contains('_') {
            TokenKind::DirectiveInteger(spelling)
        } else {
            TokenKind::IntegerLiteral(spelling)
        })
    }

    fn scan_decimal_tail(&mut self, token_start: usize) -> Result<(), LexError> {
        loop {
            match self.current_byte() {
                Some(byte) if byte.is_ascii_digit() => self.offset += 1,
                Some(b'_') => {
                    self.offset += 1;
                    if self
                        .current_byte()
                        .is_none_or(|byte| !byte.is_ascii_digit())
                    {
                        self.consume_number_candidate();
                        return self.fail(
                            "invalid-number",
                            "numeric separators must occur between decimal digits",
                            token_start,
                            self.offset,
                        );
                    }
                    self.offset += 1;
                }
                _ => return Ok(()),
            }
        }
    }

    fn consume_number_candidate(&mut self) {
        while self.current_byte().is_some_and(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'+' | b'-')
        }) {
            self.offset += 1;
        }
    }

    fn scan_quoted_string(&mut self) -> Result<Arc<str>, LexError> {
        let start = self.offset;
        self.offset += 1;
        let mut decoded = String::new();
        loop {
            let Some(current) = self.current_char() else {
                return self.fail(
                    "unterminated-string",
                    "quoted string has no closing delimiter",
                    start,
                    self.offset,
                );
            };
            match current {
                '"' => {
                    self.offset += 1;
                    return Ok(Arc::from(decoded));
                }
                '\\' => decoded.push(self.scan_escape()?),
                '\n' | '\r' => {
                    let invalid = self.offset;
                    self.advance_char();
                    return self.fail(
                        "literal-line-terminator",
                        "quoted strings require escaped line terminators",
                        invalid,
                        self.offset,
                    );
                }
                '\u{feff}' => {
                    let invalid = self.offset;
                    self.advance_char();
                    return self.fail(
                        "unexpected-byte-order-mark",
                        "a byte-order mark is not permitted inside a string",
                        invalid,
                        self.offset,
                    );
                }
                value => {
                    decoded.push(value);
                    self.advance_char();
                }
            }
        }
    }

    fn scan_escape(&mut self) -> Result<char, LexError> {
        let start = self.offset;
        self.offset += 1;
        let Some(suffix) = self.current_char() else {
            return self.fail(
                "invalid-string-escape",
                "string escape is incomplete",
                start,
                self.offset,
            );
        };
        let simple = match suffix {
            '\\' => Some('\\'),
            '"' => Some('"'),
            'n' => Some('\n'),
            'r' => Some('\r'),
            't' => Some('\t'),
            '0' => Some('\0'),
            _ => None,
        };
        if let Some(value) = simple {
            self.advance_char();
            return Ok(value);
        }
        if suffix != 'u' {
            self.advance_char();
            return self.fail(
                "invalid-string-escape",
                "string contains an unsupported escape",
                start,
                self.offset,
            );
        }
        self.offset += 1;
        if !self.starts_with("{") {
            return self.fail(
                "invalid-unicode-escape",
                "Unicode escape requires an opening brace",
                start,
                self.offset,
            );
        }
        self.offset += 1;
        let digits_start = self.offset;
        while self
            .current_byte()
            .is_some_and(|byte| byte.is_ascii_hexdigit())
            && self.offset.saturating_sub(digits_start) < 6
        {
            self.offset += 1;
        }
        let digit_count = self.offset.saturating_sub(digits_start);
        if digit_count == 0 || !self.starts_with("}") {
            while self
                .current_byte()
                .is_some_and(|byte| byte.is_ascii_hexdigit())
            {
                self.offset += 1;
            }
            if self.starts_with("}") {
                self.offset += 1;
            }
            return self.fail(
                "invalid-unicode-escape",
                "Unicode escape requires one through six hexadecimal digits",
                start,
                self.offset,
            );
        }
        let digits = self.slice(digits_start, self.offset)?.to_owned();
        self.offset += 1;
        let value = u32::from_str_radix(&digits, 16).map_err(|_| LexError::Invariant)?;
        match char::from_u32(value) {
            Some(value) => Ok(value),
            None => self.fail(
                "invalid-unicode-escape",
                "Unicode escape does not identify a scalar value",
                start,
                self.offset,
            ),
        }
    }

    fn scan_raw_string(&mut self) -> Result<Arc<str>, LexError> {
        let start = self.offset;
        let (hashes, body_start) = self.raw_prefix().ok_or(LexError::Invariant)?;
        self.offset = body_start;
        loop {
            if self.raw_closes(hashes) {
                let body = Arc::from(self.slice(body_start, self.offset)?);
                self.offset += 1 + hashes;
                return Ok(body);
            }
            let Some(current) = self.current_char() else {
                return self.fail(
                    "unterminated-raw-string",
                    "raw string has no matching closing delimiter",
                    start,
                    self.offset,
                );
            };
            if current == '\u{feff}' {
                let invalid = self.offset;
                self.advance_char();
                return self.fail(
                    "unexpected-byte-order-mark",
                    "a byte-order mark is not permitted inside a raw string",
                    invalid,
                    self.offset,
                );
            }
            self.advance_char();
        }
    }

    fn scan_prompt_template(&mut self) -> Result<TokenKind, LexError> {
        let template_start = self.offset;
        let (delimiter, hashes) = if self.starts_with("\"\"\"") {
            self.offset += 3;
            if !self.consume_line_terminator() {
                return self.fail(
                    "invalid-block-prompt",
                    "a block prompt must begin with a line terminator",
                    template_start,
                    self.offset,
                );
            }
            (PromptDelimiter::Block, 0)
        } else if let Some((hashes, body_start)) = self.raw_prefix() {
            self.offset = body_start;
            (PromptDelimiter::Raw, hashes)
        } else {
            self.offset += 1;
            (PromptDelimiter::Quoted, 0)
        };

        let mut literals = vec![String::new()];
        let mut interpolations = Vec::new();
        let mut block_line_only_indent = delimiter == PromptDelimiter::Block;
        let mut block_indent_start = 0;
        let mut closing_indent = None;

        loop {
            if delimiter == PromptDelimiter::Quoted && self.starts_with("\"") {
                self.offset += 1;
                break;
            }
            if delimiter == PromptDelimiter::Raw && self.raw_closes(hashes) {
                self.offset += 1 + hashes;
                break;
            }
            if delimiter == PromptDelimiter::Block && self.starts_with("\"\"\"") {
                if !block_line_only_indent {
                    return self.fail(
                        "invalid-block-prompt",
                        "a block prompt closing delimiter must be first after indentation",
                        self.offset,
                        self.offset + 3,
                    );
                }
                let current = literals.last_mut().ok_or(LexError::Invariant)?;
                closing_indent = Some(current[block_indent_start..].to_owned());
                current.truncate(block_indent_start);
                strip_final_line_terminator(current);
                self.offset += 3;
                break;
            }
            let Some(current) = self.current_char() else {
                return self.fail(
                    "unterminated-prompt-template",
                    "prompt template has no matching closing delimiter",
                    template_start,
                    self.offset,
                );
            };
            if current == '\u{feff}' {
                let invalid = self.offset;
                self.advance_char();
                return self.fail(
                    "unexpected-byte-order-mark",
                    "a byte-order mark is not permitted inside a prompt template",
                    invalid,
                    self.offset,
                );
            }
            if self.starts_with("$$") {
                literals.last_mut().ok_or(LexError::Invariant)?.push('$');
                self.offset += 2;
                block_line_only_indent = false;
                continue;
            }
            if self.starts_with("${") {
                self.offset += 2;
                let island_start = self.offset;
                let tokens = self.scan_interpolation()?;
                let island_end = self.offset.saturating_sub(1);
                let source = Arc::from(self.slice(island_start, island_end)?);
                interpolations.push(InterpolationIsland::new(
                    source,
                    self.span(island_start, island_end)?,
                    tokens,
                ));
                literals.push(String::new());
                block_line_only_indent = false;
                block_indent_start = 0;
                continue;
            }
            if current == '\\' && delimiter != PromptDelimiter::Raw {
                let escape_start = self.offset;
                let decoded = self.scan_escape()?;
                let literal = literals.last_mut().ok_or(LexError::Invariant)?;
                if delimiter == PromptDelimiter::Block {
                    literal.push_str(self.slice(escape_start, self.offset)?);
                } else {
                    literal.push(decoded);
                }
                block_line_only_indent = false;
                continue;
            }
            if delimiter == PromptDelimiter::Quoted && matches!(current, '\n' | '\r') {
                let invalid = self.offset;
                self.advance_char();
                return self.fail(
                    "literal-line-terminator",
                    "quoted prompt templates require escaped line terminators",
                    invalid,
                    self.offset,
                );
            }

            let literal = literals.last_mut().ok_or(LexError::Invariant)?;
            if delimiter == PromptDelimiter::Block && matches!(current, '\n' | '\r') {
                if current == '\r' && self.starts_with("\r\n") {
                    literal.push_str("\r\n");
                    self.offset += 2;
                } else {
                    literal.push(current);
                    self.advance_char();
                }
                block_line_only_indent = true;
                block_indent_start = literal.len();
            } else {
                literal.push(current);
                self.advance_char();
                if delimiter == PromptDelimiter::Block
                    && block_line_only_indent
                    && !matches!(current, ' ' | '\t')
                {
                    block_line_only_indent = false;
                }
            }
        }

        let literals = match delimiter {
            PromptDelimiter::Block => {
                let indent = closing_indent.ok_or(LexError::Invariant)?;
                let dedented = match dedent_block_literals(&literals, interpolations.len(), &indent)
                {
                    Ok(literals) => literals,
                    Err(BlockDedentError) => {
                        return self.fail(
                            "invalid-block-prompt-indentation",
                            "every nonblank block-prompt line must begin with the closing indentation",
                            template_start,
                            self.offset,
                        );
                    }
                };
                dedented
                    .into_iter()
                    .map(|literal| decode_validated_escapes(&literal))
                    .collect::<Result<Vec<_>, _>>()?
            }
            PromptDelimiter::Quoted | PromptDelimiter::Raw => {
                literals.into_iter().map(Arc::from).collect()
            }
        };
        Ok(TokenKind::PromptTemplate(PromptTemplate::new(
            delimiter,
            literals,
            interpolations,
        )))
    }

    fn scan_interpolation(&mut self) -> Result<Vec<Token>, LexError> {
        let island_start = self.offset.saturating_sub(2);
        let mut tokens = Vec::new();
        let mut expected = Vec::new();
        loop {
            self.skip_trivia()?;
            if self.offset == self.text.len() {
                return self.fail(
                    "unclosed-interpolation",
                    "prompt interpolation has no closing brace",
                    island_start,
                    self.offset,
                );
            }
            if self.starts_with("}") && expected.is_empty() {
                self.offset += 1;
                return Ok(tokens);
            }
            let start = self.offset;
            self.counters
                .charge_tokens(1)
                .map_err(LexError::ResourceLimit)?;
            let kind = self.scan_ordinary(LexContext::Ordinary)?;
            if let TokenKind::Punctuation(punctuation) = kind {
                match punctuation {
                    Punctuation::LeftParenthesis => expected.push(Punctuation::RightParenthesis),
                    Punctuation::LeftBracket => expected.push(Punctuation::RightBracket),
                    Punctuation::LeftBrace => expected.push(Punctuation::RightBrace),
                    Punctuation::RightParenthesis
                    | Punctuation::RightBracket
                    | Punctuation::RightBrace
                        if expected.pop() != Some(punctuation) =>
                    {
                        return self.fail(
                            "mismatched-interpolation-delimiter",
                            "prompt interpolation contains a mismatched delimiter",
                            start,
                            self.offset,
                        );
                    }
                    _ => {}
                }
            }
            tokens.push(Token::new(kind, self.span(start, self.offset)?));
        }
    }

    fn skip_trivia(&mut self) -> Result<(), LexError> {
        loop {
            while self
                .current_char()
                .is_some_and(|value| matches!(value, ' ' | '\t' | '\r' | '\n'))
            {
                self.advance_char();
            }
            if self.starts_with("//") {
                self.offset += 2;
                while let Some(value) = self.current_char() {
                    if matches!(value, '\r' | '\n') {
                        break;
                    }
                    if value == '\u{feff}' {
                        let invalid = self.offset;
                        self.advance_char();
                        self.counters
                            .charge_tokens(1)
                            .map_err(LexError::ResourceLimit)?;
                        return self.fail(
                            "unexpected-byte-order-mark",
                            "a byte-order mark is permitted only at the start of a source file",
                            invalid,
                            self.offset,
                        );
                    }
                    self.advance_char();
                }
                self.consume_line_terminator();
                continue;
            }
            if self.starts_with("/*") {
                let start = self.offset;
                self.offset += 2;
                let mut depth = 1_u64;
                while depth != 0 {
                    if self.starts_with("/*") {
                        depth = depth.checked_add(1).ok_or(LexError::Invariant)?;
                        self.offset += 2;
                    } else if self.starts_with("*/") {
                        depth -= 1;
                        self.offset += 2;
                    } else if let Some(value) = self.current_char() {
                        let invalid = self.offset;
                        self.advance_char();
                        if value == '\u{feff}' {
                            self.counters
                                .charge_tokens(1)
                                .map_err(LexError::ResourceLimit)?;
                            return self.fail(
                                "unexpected-byte-order-mark",
                                "a byte-order mark is permitted only at the start of a source file",
                                invalid,
                                self.offset,
                            );
                        }
                    } else {
                        self.counters
                            .charge_tokens(1)
                            .map_err(LexError::ResourceLimit)?;
                        return self.fail(
                            "unterminated-block-comment",
                            "nested block comment has no closing delimiter",
                            start,
                            self.offset,
                        );
                    }
                }
                continue;
            }
            return Ok(());
        }
    }

    fn scan_punctuation(&mut self) -> Option<Punctuation> {
        const FIXED: &[(&str, Punctuation)] = &[
            ("::", Punctuation::PathSeparator),
            ("->", Punctuation::ThinArrow),
            ("=>", Punctuation::FatArrow),
            ("==", Punctuation::EqualEqual),
            ("!=", Punctuation::NotEqual),
            ("<=", Punctuation::LessEqual),
            (">=", Punctuation::GreaterEqual),
            ("&&", Punctuation::AndAnd),
            ("||", Punctuation::OrOr),
            ("+=", Punctuation::PlusEqual),
            ("-=", Punctuation::MinusEqual),
            ("*=", Punctuation::StarEqual),
            ("/=", Punctuation::SlashEqual),
            ("%=", Punctuation::PercentEqual),
            ("(", Punctuation::LeftParenthesis),
            (")", Punctuation::RightParenthesis),
            ("{", Punctuation::LeftBrace),
            ("}", Punctuation::RightBrace),
            ("[", Punctuation::LeftBracket),
            ("]", Punctuation::RightBracket),
            (",", Punctuation::Comma),
            (";", Punctuation::Semicolon),
            (":", Punctuation::Colon),
            (".", Punctuation::Dot),
            ("=", Punctuation::Equal),
            ("!", Punctuation::Bang),
            ("<", Punctuation::Less),
            (">", Punctuation::Greater),
            ("+", Punctuation::Plus),
            ("-", Punctuation::Minus),
            ("*", Punctuation::Star),
            ("/", Punctuation::Slash),
            ("%", Punctuation::Percent),
        ];
        FIXED.iter().find_map(|(spelling, punctuation)| {
            self.starts_with(spelling).then(|| {
                self.offset += spelling.len();
                *punctuation
            })
        })
    }

    fn raw_prefix(&self) -> Option<(usize, usize)> {
        if !self.starts_with("r") {
            return None;
        }
        let mut cursor = self.offset + 1;
        while self.byte_at(cursor) == Some(b'#') {
            cursor += 1;
        }
        (self.byte_at(cursor) == Some(b'"')).then_some((cursor - self.offset - 1, cursor + 1))
    }

    fn raw_closes(&self, hashes: usize) -> bool {
        self.byte_at(self.offset) == Some(b'"')
            && (0..hashes).all(|index| self.byte_at(self.offset + 1 + index) == Some(b'#'))
    }

    fn is_prompt_start(&self) -> bool {
        self.starts_with("\"") || self.raw_prefix().is_some()
    }

    fn consume_line_terminator(&mut self) -> bool {
        if self.starts_with("\r\n") {
            self.offset += 2;
            true
        } else if self.starts_with("\n") || self.starts_with("\r") {
            self.offset += 1;
            true
        } else {
            false
        }
    }

    fn current_char(&self) -> Option<char> {
        self.text.get(self.offset..)?.chars().next()
    }

    fn advance_char(&mut self) {
        if let Some(value) = self.current_char() {
            self.offset += value.len_utf8();
        }
    }

    fn advance_ascii(&mut self) {
        self.offset = self.offset.saturating_add(1);
    }

    fn current_byte(&self) -> Option<u8> {
        self.byte_at(self.offset)
    }

    fn byte_at(&self, offset: usize) -> Option<u8> {
        self.text.as_bytes().get(offset).copied()
    }

    fn starts_with(&self, value: &str) -> bool {
        self.text
            .get(self.offset..)
            .is_some_and(|remaining| remaining.starts_with(value))
    }

    fn slice(&self, start: usize, end: usize) -> Result<&str, LexError> {
        self.text.get(start..end).ok_or(LexError::Invariant)
    }

    fn span(&self, start: usize, end: usize) -> Result<SourceSpan, LexError> {
        let start = u64::try_from(start).map_err(|_| LexError::Invariant)?;
        let end = u64::try_from(end).map_err(|_| LexError::Invariant)?;
        let bytes = ByteSpan::new(start, end).map_err(LexError::Span)?;
        SourceSpan::new(self.record, bytes).map_err(LexError::Span)
    }

    fn fail<T>(
        &mut self,
        code: &'static str,
        message: &'static str,
        start: usize,
        end: usize,
    ) -> Result<T, LexError> {
        Err(self.make_diagnostic(code, message, start, end)?)
    }

    fn make_diagnostic(
        &mut self,
        code: &'static str,
        message: &'static str,
        start: usize,
        end: usize,
    ) -> Result<LexError, LexError> {
        self.counters
            .charge_diagnostic()
            .map_err(LexError::ResourceLimit)?;
        Self::diagnostic_for(self.record, code, message, start, end)
    }

    fn diagnostic_for(
        record: &SourceRecord,
        code: &'static str,
        message: &'static str,
        start: usize,
        end: usize,
    ) -> Result<LexError, LexError> {
        let start = u64::try_from(start).map_err(|_| LexError::Invariant)?;
        let end = u64::try_from(end).map_err(|_| LexError::Invariant)?;
        let bytes = ByteSpan::new(start, end).map_err(LexError::Span)?;
        let primary = SourceSpan::new(record, bytes).map_err(LexError::Span)?;
        let code = DiagnosticCode::new(code).map_err(|_| LexError::Invariant)?;
        let diagnostic = StructuredDiagnostic::new(
            DiagnosticMetadata {
                phase: DiagnosticPhase::Lexical,
                severity: DiagnosticSeverity::Error,
                category: DiagnosticCategory::Lexical,
                code,
            },
            message,
            Some(primary),
            Vec::new(),
            BTreeMap::new(),
        )
        .map_err(|_| LexError::Invariant)?;
        Ok(LexError::Diagnostic(diagnostic))
    }
}

/// Deterministic lexical failure or configured resource rejection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LexError {
    /// A stable source-backed lexical diagnostic.
    Diagnostic(StructuredDiagnostic),
    /// A token or diagnostic activity limit was exceeded.
    ResourceLimit(FrontendResourceLimit),
    /// A source span could not be represented.
    Span(SpanError),
    /// An internal lexer invariant was violated.
    Invariant,
}

impl fmt::Display for LexError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Diagnostic(diagnostic) => formatter.write_str(diagnostic.code.as_str()),
            Self::ResourceLimit(error) => error.fmt(formatter),
            Self::Span(error) => error.fmt(formatter),
            Self::Invariant => formatter.write_str("lexer invariant failure"),
        }
    }
}

impl std::error::Error for LexError {}

fn strip_final_line_terminator(value: &mut String) {
    if value.ends_with("\r\n") {
        value.truncate(value.len().saturating_sub(2));
    } else if value.ends_with(['\r', '\n']) {
        value.truncate(value.len().saturating_sub(1));
    }
}

#[derive(Clone, Copy)]
enum BlockPart {
    Character(usize, char),
    Island,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BlockDedentError;

fn dedent_block_literals(
    literals: &[String],
    interpolation_count: usize,
    indent: &str,
) -> Result<Vec<String>, BlockDedentError> {
    let mut output = vec![String::new(); literals.len()];
    let mut line = Vec::new();
    for (literal_index, literal) in literals.iter().enumerate() {
        let mut characters = literal.chars().peekable();
        while let Some(value) = characters.next() {
            if matches!(value, '\r' | '\n') {
                emit_dedented_line(&line, indent, &mut output)?;
                line.clear();
                output[literal_index].push(value);
                if value == '\r' && characters.peek() == Some(&'\n') {
                    output[literal_index].push('\n');
                    characters.next();
                }
            } else {
                line.push(BlockPart::Character(literal_index, value));
            }
        }
        if literal_index < interpolation_count {
            line.push(BlockPart::Island);
        }
    }
    emit_dedented_line(&line, indent, &mut output)?;
    Ok(output)
}

fn emit_dedented_line(
    line: &[BlockPart],
    indent: &str,
    output: &mut [String],
) -> Result<(), BlockDedentError> {
    let blank = line
        .iter()
        .all(|part| matches!(part, BlockPart::Character(_, value) if matches!(value, ' ' | '\t')));
    if blank {
        return Ok(());
    }
    let indent_chars = indent.chars().collect::<Vec<_>>();
    for (index, expected) in indent_chars.iter().enumerate() {
        if !matches!(line.get(index), Some(BlockPart::Character(_, actual)) if actual == expected) {
            return Err(BlockDedentError);
        }
    }
    for part in line.iter().skip(indent_chars.len()) {
        if let BlockPart::Character(index, value) = part {
            output.get_mut(*index).ok_or(BlockDedentError)?.push(*value);
        }
    }
    Ok(())
}

fn decode_validated_escapes(value: &str) -> Result<Arc<str>, LexError> {
    let mut output = String::new();
    let mut offset = 0;
    while offset < value.len() {
        let current = value[offset..].chars().next().ok_or(LexError::Invariant)?;
        if current != '\\' {
            output.push(current);
            offset += current.len_utf8();
            continue;
        }
        offset += 1;
        let suffix = value[offset..].chars().next().ok_or(LexError::Invariant)?;
        match suffix {
            '\\' => output.push('\\'),
            '"' => output.push('"'),
            'n' => output.push('\n'),
            'r' => output.push('\r'),
            't' => output.push('\t'),
            '0' => output.push('\0'),
            'u' => {
                offset += 2;
                let close = value[offset..].find('}').ok_or(LexError::Invariant)? + offset;
                let scalar = u32::from_str_radix(&value[offset..close], 16)
                    .map_err(|_| LexError::Invariant)?;
                output.push(char::from_u32(scalar).ok_or(LexError::Invariant)?);
                offset = close + 1;
                continue;
            }
            _ => return Err(LexError::Invariant),
        }
        offset += suffix.len_utf8();
    }
    Ok(Arc::from(output))
}

#[cfg(test)]
mod tests {
    use gantry_core::portable::FrontendResourceCode;
    use gantry_core::source::{SourceLimits, SourceSnapshotBuilder};

    use super::{LexContext, LexError, Lexer};
    use crate::{PromptDelimiter, Punctuation, TokenKind};

    fn with_lexer<T>(source: &str, token_limit: u64, test: impl FnOnce(&mut Lexer<'_>) -> T) -> T {
        let limits = SourceLimits::new(1, 100_000, 100_000, token_limit, 32)
            .unwrap_or_else(|_| unreachable!("positive limits"));
        let mut builder = SourceSnapshotBuilder::new(limits);
        assert!(builder.add_file("main.gnt", source.as_bytes()).is_ok());
        let mut snapshot = builder.finish();
        let (records, counters) = snapshot.records_and_counters_mut();
        let record = records
            .first()
            .unwrap_or_else(|| unreachable!("one source"));
        let mut lexer =
            Lexer::new(record, counters).unwrap_or_else(|_| unreachable!("valid UTF-8"));
        test(&mut lexer)
    }

    #[test]
    fn scans_unicode_identifiers_numbers_comments_and_maximal_punctuation() {
        with_lexer(
            "\u{feff}/* outer /* inner */ */ prompt α_2 1_000 2.5e+2 :: -> _",
            16,
            |lexer| {
                assert!(matches!(
                    lexer.next(LexContext::Ordinary).map(|token| token.kind().clone()),
                    Ok(TokenKind::ReservedWord(word)) if word.spelling() == "prompt"
                ));
                assert!(matches!(
                    lexer.next(LexContext::Ordinary).map(|token| token.kind().clone()),
                    Ok(TokenKind::Identifier(value)) if &*value == "α_2"
                ));
                assert!(matches!(
                    lexer.next(LexContext::Ordinary).map(|token| token.kind().clone()),
                    Ok(TokenKind::IntegerLiteral(value)) if &*value == "1_000"
                ));
                assert!(matches!(
                    lexer.next(LexContext::Ordinary).map(|token| token.kind().clone()),
                    Ok(TokenKind::FloatLiteral(value)) if &*value == "2.5e+2"
                ));
                assert!(matches!(
                    lexer
                        .next(LexContext::Ordinary)
                        .map(|token| token.kind().clone()),
                    Ok(TokenKind::Punctuation(Punctuation::PathSeparator))
                ));
                assert!(matches!(
                    lexer
                        .next(LexContext::Ordinary)
                        .map(|token| token.kind().clone()),
                    Ok(TokenKind::Punctuation(Punctuation::ThinArrow))
                ));
                assert!(matches!(
                    lexer
                        .next(LexContext::Ordinary)
                        .map(|token| token.kind().clone()),
                    Ok(TokenKind::Punctuation(Punctuation::Underscore))
                ));
            },
        );
    }

    #[test]
    fn directive_context_reclassifies_without_changing_boundaries() {
        with_lexer("123 1_2", 4, |lexer| {
            assert!(matches!(
                lexer.next(LexContext::DirectiveInteger).map(|token| token.kind().clone()),
                Ok(TokenKind::DirectiveInteger(value)) if &*value == "123"
            ));
            assert!(matches!(
                lexer.next(LexContext::DirectiveInteger).map(|token| token.kind().clone()),
                Ok(TokenKind::IntegerLiteral(value)) if &*value == "1_2"
            ));
        });
    }

    #[test]
    fn prompt_scan_balances_nested_tokens_and_applies_dollar_escapes() {
        with_lexer("\"a $$ $${name} $$${Some(\"draft\")} z\"", 16, |lexer| {
            let token = lexer
                .next(LexContext::PromptTemplate)
                .unwrap_or_else(|_| unreachable!("valid prompt"));
            let TokenKind::PromptTemplate(template) = token.kind() else {
                unreachable!("prompt token")
            };
            assert_eq!(template.delimiter(), PromptDelimiter::Quoted);
            assert_eq!(template.literals(), &["a $ ${name} $".into(), " z".into()]);
            assert_eq!(template.interpolations().len(), 1);
            assert_eq!(template.interpolations()[0].source(), "Some(\"draft\")");
            assert_eq!(template.interpolations()[0].tokens().len(), 4);
        });
    }

    #[test]
    fn block_prompt_uses_closing_indent_and_structural_newlines() {
        with_lexer("\"\"\"\n  first\n    second\\nline\n  \"\"\"", 4, |lexer| {
            let token = lexer
                .next(LexContext::PromptTemplate)
                .unwrap_or_else(|_| unreachable!("valid block prompt"));
            let TokenKind::PromptTemplate(template) = token.kind() else {
                unreachable!("prompt token")
            };
            assert_eq!(template.delimiter(), PromptDelimiter::Block);
            assert_eq!(template.literals(), &["first\n  second\nline".into()]);
        });
    }

    #[test]
    fn malformed_occurrences_charge_tokens_before_diagnostics() {
        with_lexer("01", 4, |lexer| {
            let error = lexer.next(LexContext::Ordinary);
            assert!(matches!(
                error,
                Err(LexError::Diagnostic(ref diagnostic)) if diagnostic.code.as_str() == "invalid-number"
            ));
        });

        with_lexer("x y", 1, |lexer| {
            assert!(lexer.next(LexContext::Ordinary).is_ok());
            assert!(matches!(
                lexer.next(LexContext::Ordinary),
                Err(LexError::ResourceLimit(error))
                    if error.code == FrontendResourceCode::SourceTokenLimit
                        && error.observed == Some(2)
            ));
        });
    }

    #[test]
    fn nested_comment_failure_is_bounded_and_source_backed() {
        with_lexer("/* one /* two */", 4, |lexer| {
            assert!(matches!(
                lexer.next(LexContext::Ordinary),
                Err(LexError::Diagnostic(ref diagnostic))
                    if diagnostic.code.as_str() == "unterminated-block-comment"
                        && diagnostic.primary.as_ref().is_some_and(|span| span.bytes().start() == 0)
            ));
        });
    }

    #[test]
    fn authored_escape_and_block_indent_failures_are_diagnostics() {
        with_lexer("\"\\u{D800}\"", 4, |lexer| {
            assert!(matches!(
                lexer.next(LexContext::Ordinary),
                Err(LexError::Diagnostic(ref diagnostic))
                    if diagnostic.code.as_str() == "invalid-unicode-escape"
            ));
        });

        with_lexer("\"\"\"\n short\n  \"\"\"", 4, |lexer| {
            assert!(matches!(
                lexer.next(LexContext::PromptTemplate),
                Err(LexError::Diagnostic(ref diagnostic))
                    if diagnostic.code.as_str() == "invalid-block-prompt-indentation"
            ));
        });
    }

    #[test]
    fn noninitial_byte_order_marks_are_rejected_inside_trivia() {
        for source in ["// hidden \u{feff}\nvalue", "/* hidden \u{feff} */ value"] {
            with_lexer(source, 4, |lexer| {
                assert!(matches!(
                    lexer.next(LexContext::Ordinary),
                    Err(LexError::Diagnostic(ref diagnostic))
                        if diagnostic.code.as_str() == "unexpected-byte-order-mark"
                ));
            });
        }
    }
}
