//! Explicit-stack predictive parser for the Gantry v1 surface grammar.
//!
//! The parser first performs parser-aware tokenization for contextual prompt
//! templates and directive integers, then executes grammar tasks from an
//! explicit work stack. Source-controlled nesting therefore grows owned
//! vectors instead of the native call stack.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use gantry_core::portable::{DiagnosticCategory, DiagnosticSeverity};
use gantry_core::source::{
    ByteSpan, DiagnosticCode, DiagnosticMetadata, DiagnosticPhase, FrontendResourceLimit,
    SourceCounters, SourceRecord, SourceSpan, SpanError, StructuredDiagnostic,
};

use crate::ast::{NodeId, SyntaxForm, SyntaxNode, SyntaxTree};
use crate::lexer::{LexContext, LexError, Lexer};
use crate::token::{Punctuation, Token, TokenKind};

/// One completed syntax phase for a source module.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParseOutcome {
    recovered_tree: Option<SyntaxTree>,
    diagnostics: Vec<StructuredDiagnostic>,
}

impl ParseOutcome {
    /// Returns the syntax tree only when lexical and syntax validation passed.
    #[must_use]
    pub const fn tree(&self) -> Option<&SyntaxTree> {
        if self.diagnostics.is_empty() {
            self.recovered_tree.as_ref()
        } else {
            None
        }
    }

    /// Returns successfully recovered syntax even when another item produced
    /// a diagnostic.
    ///
    /// Package discovery uses this only to follow file-module declarations
    /// whose complete syntax parsed before or after another malformed item.
    #[must_use]
    pub const fn recovered_tree(&self) -> Option<&SyntaxTree> {
        self.recovered_tree.as_ref()
    }

    /// Returns deterministic lexical or syntax diagnostics in source order.
    #[must_use]
    pub fn diagnostics(&self) -> &[StructuredDiagnostic] {
        &self.diagnostics
    }

    /// Returns whether the source module is syntactically valid.
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.diagnostics.is_empty() && self.recovered_tree.is_some()
    }
}

/// Resource or invariant failure that prevents a completed syntax judgment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParseError {
    /// A shared frontend activity limit was exceeded after retaining the
    /// deterministic diagnostic prefix produced before exhaustion.
    ResourceLimit {
        /// Exact portable limit outcome.
        error: FrontendResourceLimit,
        /// Diagnostics retained before the next diagnostic exceeded its cap.
        diagnostics: Vec<StructuredDiagnostic>,
    },
    /// A source span could not be represented.
    Span(SpanError),
    /// An internal parser invariant was violated.
    Invariant,
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ResourceLimit { error, .. } => error.fmt(formatter),
            Self::Span(error) => error.fmt(formatter),
            Self::Invariant => formatter.write_str("parser invariant failure"),
        }
    }
}

impl std::error::Error for ParseError {}

/// Parser entry point bound to one immutable source and activity counters.
pub struct Parser<'a> {
    record: &'a SourceRecord,
    counters: &'a mut SourceCounters,
}

impl<'a> Parser<'a> {
    /// Creates a syntax parser for one selected source record.
    pub fn new(record: &'a SourceRecord, counters: &'a mut SourceCounters) -> Self {
        Self { record, counters }
    }

    /// Lexes and parses the complete `module_source` production.
    pub fn parse_module(self) -> Result<ParseOutcome, ParseError> {
        let (tokens, lexical_diagnostics) = tokenize(self.record, self.counters)?;
        if !lexical_diagnostics.is_empty() {
            return Ok(ParseOutcome {
                recovered_tree: None,
                diagnostics: lexical_diagnostics,
            });
        }
        Machine::new(self.record, self.counters, tokens).parse_module()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TemplateState {
    Normal,
    AfterOperation,
    Modifiers(usize),
    Template,
}

fn tokenize(
    record: &SourceRecord,
    counters: &mut SourceCounters,
) -> Result<(Vec<Token>, Vec<StructuredDiagnostic>), ParseError> {
    let mut lexer = match Lexer::new(record, counters) {
        Ok(lexer) => lexer,
        Err(LexError::Diagnostic(diagnostic)) => return Ok((Vec::new(), vec![diagnostic])),
        Err(error) => return Err(map_lex_error(error)),
    };
    let mut tokens = Vec::new();
    let mut diagnostics = Vec::new();
    let mut template_state = TemplateState::Normal;
    loop {
        let directive = tokens.len() >= 2
            && token_is_word(&tokens[tokens.len() - 2], "retry_limit")
            || tokens.len() >= 2 && token_is_word(&tokens[tokens.len() - 2], "limit");
        let directive = directive
            && token_is_punctuation(
                tokens
                    .last()
                    .unwrap_or_else(|| unreachable!("two prior tokens")),
                Punctuation::Equal,
            );
        let context = match template_state {
            TemplateState::AfterOperation | TemplateState::Template => LexContext::PromptTemplate,
            _ if directive => LexContext::DirectiveInteger,
            _ => LexContext::Ordinary,
        };
        let token = match lexer.next(context) {
            Ok(token) => token,
            Err(LexError::Diagnostic(diagnostic)) => {
                diagnostics.push(diagnostic);
                template_state = TemplateState::Normal;
                continue;
            }
            Err(LexError::ResourceLimit(error)) => {
                return Err(ParseError::ResourceLimit { error, diagnostics });
            }
            Err(error) => return Err(map_lex_error(error)),
        };
        let end = matches!(token.kind(), TokenKind::EndOfFile);
        template_state = match template_state {
            TemplateState::Normal
                if token_is_word(&token, "prompt") || token_is_word(&token, "decide") =>
            {
                TemplateState::AfterOperation
            }
            TemplateState::AfterOperation
                if token_is_punctuation(&token, Punctuation::LeftParenthesis) =>
            {
                TemplateState::Modifiers(1)
            }
            TemplateState::AfterOperation => TemplateState::Normal,
            TemplateState::Modifiers(depth)
                if token_is_punctuation(&token, Punctuation::LeftParenthesis) =>
            {
                TemplateState::Modifiers(depth.saturating_add(1))
            }
            TemplateState::Modifiers(depth)
                if token_is_punctuation(&token, Punctuation::RightParenthesis) && depth == 1 =>
            {
                TemplateState::Template
            }
            TemplateState::Modifiers(depth)
                if token_is_punctuation(&token, Punctuation::RightParenthesis) =>
            {
                TemplateState::Modifiers(depth.saturating_sub(1))
            }
            TemplateState::Modifiers(depth) => TemplateState::Modifiers(depth),
            TemplateState::Template => TemplateState::Normal,
            TemplateState::Normal => TemplateState::Normal,
        };
        tokens.push(token);
        if end {
            break;
        }
    }
    Ok((tokens, diagnostics))
}

fn map_lex_error(error: LexError) -> ParseError {
    match error {
        LexError::ResourceLimit(error) => ParseError::ResourceLimit {
            error,
            diagnostics: Vec::new(),
        },
        LexError::Span(error) => ParseError::Span(error),
        LexError::Diagnostic(_) | LexError::Invariant => ParseError::Invariant,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BlockKind {
    Ordinary,
    Value,
    Statement,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExpressionMode {
    Ordinary,
    Interpolation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BinaryClass {
    Ordinary,
    Equality,
    Ordering,
}

#[derive(Clone, Debug)]
enum Task {
    Finish,
    Item,
    ItemList,
    MethodList,
    ValueType,
    TupleTypeTail {
        count: usize,
    },
    Block(BlockKind),
    BlockContents(BlockKind),
    AfterBlockExpression(BlockKind),
    Statement,
    Expression {
        minimum_precedence: u8,
        mode: ExpressionMode,
        control_boundary: bool,
    },
    BinaryTail {
        minimum_precedence: u8,
        mode: ExpressionMode,
        control_boundary: bool,
        equality_seen: bool,
        ordering_seen: bool,
    },
    Prefix {
        mode: ExpressionMode,
        control_boundary: bool,
    },
    PostfixTail {
        mode: ExpressionMode,
    },
    Primary {
        mode: ExpressionMode,
        control_boundary: bool,
    },
    ParenthesizedTail {
        mode: ExpressionMode,
    },
    ExpressionList {
        closing: Punctuation,
        mode: ExpressionMode,
        count: usize,
        minimum: usize,
    },
    IdentifierList {
        closing: Punctuation,
        count: usize,
        minimum: usize,
    },
    StructFields {
        mode: ExpressionMode,
        count: usize,
    },
    Pattern,
    PatternList {
        count: usize,
    },
    PatternPathTail,
    PromptTail {
        allow_result_annotation: bool,
    },
    UsingList {
        count: usize,
    },
    MatchArms {
        statement: bool,
        count: usize,
    },
    MatchArmBody {
        statement: bool,
    },
    IfTail,
    ExpectWord(&'static str),
    ExpectIdentifier,
    ExpectPunctuation(Punctuation),
    ParsePath,
}

#[derive(Clone)]
struct OpenNode {
    form: SyntaxForm,
    children: Vec<NodeId>,
    start: u64,
}

struct Machine<'a> {
    record: &'a SourceRecord,
    counters: &'a mut SourceCounters,
    tokens: Vec<Token>,
    position: usize,
    nodes: Vec<SyntaxNode>,
    open: Vec<OpenNode>,
    tasks: Vec<Task>,
    diagnostics: Vec<StructuredDiagnostic>,
}

impl<'a> Machine<'a> {
    fn new(record: &'a SourceRecord, counters: &'a mut SourceCounters, tokens: Vec<Token>) -> Self {
        Self {
            record,
            counters,
            tokens,
            position: 0,
            nodes: Vec::new(),
            open: Vec::new(),
            tasks: Vec::new(),
            diagnostics: Vec::new(),
        }
    }

    fn parse_module(mut self) -> Result<ParseOutcome, ParseError> {
        self.begin(SyntaxForm::Module);
        while !self.at_end() {
            let nodes_before = self.nodes.len();
            let children_before = self
                .open
                .first()
                .map(|node| node.children.len())
                .ok_or(ParseError::Invariant)?;
            self.tasks.push(Task::Item);
            if let Err(fault) = self.run_tasks() {
                self.nodes.truncate(nodes_before);
                let root = self.open.first_mut().ok_or(ParseError::Invariant)?;
                root.children.truncate(children_before);
                self.open.truncate(1);
                self.tasks.clear();
                self.push_syntax_diagnostic(fault)?;
                self.recover_item();
            }
        }
        self.consume_current().map_err(|_| ParseError::Invariant)?;
        let root = self.finish()?;
        Ok(ParseOutcome {
            recovered_tree: Some(SyntaxTree::new(self.nodes, root)),
            diagnostics: self.diagnostics,
        })
    }

    fn run_tasks(&mut self) -> Result<(), SyntaxFault> {
        while let Some(task) = self.tasks.pop() {
            self.run_task(task)?;
        }
        Ok(())
    }

    fn run_tasks_above(&mut self, base: usize) -> Result<(), SyntaxFault> {
        while self.tasks.len() > base {
            let task = self.tasks.pop().ok_or_else(|| self.invariant_fault())?;
            self.run_task(task)?;
        }
        Ok(())
    }

    fn run_task(&mut self, task: Task) -> Result<(), SyntaxFault> {
        match task {
            Task::Finish => {
                self.finish().map_err(|_| self.invariant_fault())?;
            }
            Task::Item => self.parse_item()?,
            Task::ItemList => self.parse_item_list()?,
            Task::MethodList => self.parse_method_list()?,
            Task::ValueType => self.parse_value_type()?,
            Task::TupleTypeTail { count } => self.parse_tuple_type_tail(count)?,
            Task::Block(kind) => self.parse_block(kind)?,
            Task::BlockContents(kind) => self.parse_block_contents(kind)?,
            Task::AfterBlockExpression(kind) => self.after_block_expression(kind)?,
            Task::Statement => self.parse_statement()?,
            Task::Expression {
                minimum_precedence,
                mode,
                control_boundary,
            } => self.parse_expression(minimum_precedence, mode, control_boundary),
            Task::BinaryTail {
                minimum_precedence,
                mode,
                control_boundary,
                equality_seen,
                ordering_seen,
            } => self.parse_binary_tail(
                minimum_precedence,
                mode,
                control_boundary,
                equality_seen,
                ordering_seen,
            )?,
            Task::Prefix {
                mode,
                control_boundary,
            } => self.parse_prefix(mode, control_boundary)?,
            Task::PostfixTail { mode } => self.parse_postfix_tail(mode)?,
            Task::Primary {
                mode,
                control_boundary,
            } => self.parse_primary(mode, control_boundary)?,
            Task::ParenthesizedTail { mode } => self.parse_parenthesized_tail(mode)?,
            Task::ExpressionList {
                closing,
                mode,
                count,
                minimum,
            } => self.parse_expression_list(closing, mode, count, minimum)?,
            Task::IdentifierList {
                closing,
                count,
                minimum,
            } => self.parse_identifier_list(closing, count, minimum)?,
            Task::StructFields { mode, count } => self.parse_struct_fields(mode, count)?,
            Task::Pattern => self.parse_pattern()?,
            Task::PatternList { count } => self.parse_pattern_list(count)?,
            Task::PatternPathTail => self.parse_pattern_path_tail()?,
            Task::PromptTail {
                allow_result_annotation,
            } => self.parse_prompt_tail(allow_result_annotation)?,
            Task::UsingList { count } => self.parse_using_list(count)?,
            Task::MatchArms { statement, count } => self.parse_match_arms(statement, count)?,
            Task::MatchArmBody { statement } => self.parse_match_arm_body(statement)?,
            Task::IfTail => self.parse_if_tail()?,
            Task::ExpectWord(word) => {
                self.expect_word(word)?;
            }
            Task::ExpectIdentifier => {
                self.expect_identifier()?;
            }
            Task::ExpectPunctuation(punctuation) => {
                self.expect_punctuation(punctuation)?;
            }
            Task::ParsePath => self.parse_path()?,
        }
        Ok(())
    }

    fn parse_item(&mut self) -> Result<(), SyntaxFault> {
        if self.at_word("agents") {
            self.begin(SyntaxForm::AgentsDeclaration);
            self.tasks.push(Task::Finish);
            self.push_identifier_list(Punctuation::RightBrace);
            self.tasks
                .push(Task::ExpectPunctuation(Punctuation::LeftBrace));
            self.tasks.push(Task::ExpectWord("agents"));
        } else if self.at_word("default") {
            self.begin(SyntaxForm::DefaultAgentDeclaration);
            self.tasks.push(Task::Finish);
            self.tasks
                .push(Task::ExpectPunctuation(Punctuation::Semicolon));
            self.tasks.push(Task::ExpectIdentifier);
            self.tasks.push(Task::ExpectPunctuation(Punctuation::Equal));
            self.tasks.push(Task::ExpectWord("agent"));
            self.tasks.push(Task::ExpectWord("default"));
        } else if self.at_word("mod") {
            self.begin(SyntaxForm::ModuleDeclaration);
            self.tasks.push(Task::Finish);
            self.consume_word("mod")?;
            self.expect_identifier()?;
            if self.at_punctuation(Punctuation::Semicolon) {
                self.consume_current()?;
            } else {
                self.expect_punctuation(Punctuation::LeftBrace)?;
                self.tasks
                    .push(Task::ExpectPunctuation(Punctuation::RightBrace));
                self.tasks.push(Task::ItemList);
            }
        } else if self.at_word("use") {
            self.begin(SyntaxForm::UseDeclaration);
            self.tasks.push(Task::Finish);
            self.tasks
                .push(Task::ExpectPunctuation(Punctuation::Semicolon));
            self.tasks.push(Task::ParsePath);
            self.tasks.push(Task::ExpectWord("use"));
        } else if self.at_word("struct") {
            self.parse_struct_declaration()?;
        } else if self.at_word("enum") {
            self.parse_enum_declaration()?;
        } else if self.at_word("action") {
            self.parse_action_declaration()?;
        } else if self.at_word("fn") || self.at_word("pure") {
            self.parse_function_declaration(SyntaxForm::FunctionDeclaration)?;
        } else if self.at_word("impl") {
            self.begin(SyntaxForm::ImplDeclaration);
            self.tasks.push(Task::Finish);
            self.tasks
                .push(Task::ExpectPunctuation(Punctuation::RightBrace));
            self.tasks.push(Task::MethodList);
            self.tasks
                .push(Task::ExpectPunctuation(Punctuation::LeftBrace));
            self.tasks.push(Task::ParsePath);
            self.tasks.push(Task::ExpectWord("impl"));
        } else {
            return Err(self.expected("package item"));
        }
        Ok(())
    }

    fn parse_item_list(&mut self) -> Result<(), SyntaxFault> {
        if !self.at_punctuation(Punctuation::RightBrace) {
            self.tasks.push(Task::ItemList);
            self.tasks.push(Task::Item);
        }
        Ok(())
    }

    fn parse_method_list(&mut self) -> Result<(), SyntaxFault> {
        if !self.at_punctuation(Punctuation::RightBrace) {
            if !self.at_word("fn") && !self.at_word("pure") {
                return Err(self.expected("method declaration or `}`"));
            }
            self.tasks.push(Task::MethodList);
            self.parse_function_declaration(SyntaxForm::MethodDeclaration)?;
        }
        Ok(())
    }

    fn parse_struct_declaration(&mut self) -> Result<(), SyntaxFault> {
        self.begin(SyntaxForm::StructDeclaration);
        self.consume_word("struct")?;
        self.expect_identifier()?;
        self.expect_punctuation(Punctuation::LeftBrace)?;
        while !self.at_punctuation(Punctuation::RightBrace) {
            self.begin(SyntaxForm::StructField);
            self.expect_identifier()?;
            self.expect_punctuation(Punctuation::Colon)?;
            if self.at_end() {
                return Err(self.expected("struct field or `}`"));
            }
            let base = self.tasks.len();
            self.tasks.push(Task::ValueType);
            self.run_tasks_above(base)?;
            if self.at_punctuation(Punctuation::Equal) {
                self.consume_current()?;
                self.parse_field_default()?;
            }
            self.finish().map_err(|_| self.invariant_fault())?;
            if !self.consume_if_punctuation(Punctuation::Comma)? {
                break;
            }
        }
        self.expect_punctuation(Punctuation::RightBrace)?;
        self.finish().map_err(|_| self.invariant_fault())?;
        Ok(())
    }

    fn parse_field_default(&mut self) -> Result<(), SyntaxFault> {
        if self.at_punctuation(Punctuation::Minus) {
            self.consume_current()?;
            if self.at_integer() || self.at_float() {
                self.consume_current()?;
                return Ok(());
            }
            return Err(self.expected("numeric field default"));
        }
        if self.at_integer()
            || self.at_float()
            || self.at_string()
            || self.at_word("true")
            || self.at_word("false")
            || self.at_word("None")
        {
            self.consume_current()?;
        } else if self.at_punctuation(Punctuation::LeftParenthesis)
            && self.peek_punctuation(1, Punctuation::RightParenthesis)
        {
            self.consume_current()?;
            self.consume_current()?;
        } else {
            return Err(self.expected("field default"));
        }
        Ok(())
    }

    fn parse_enum_declaration(&mut self) -> Result<(), SyntaxFault> {
        self.begin(SyntaxForm::EnumDeclaration);
        self.consume_word("enum")?;
        self.expect_identifier()?;
        self.expect_punctuation(Punctuation::LeftBrace)?;
        let mut count = 0_usize;
        loop {
            if self.at_punctuation(Punctuation::RightBrace) {
                if count == 0 {
                    return Err(self.expected("enum variant"));
                }
                break;
            }
            self.begin(SyntaxForm::EnumVariant);
            self.expect_identifier()?;
            if self.consume_if_punctuation(Punctuation::LeftParenthesis)? {
                let base = self.tasks.len();
                self.tasks
                    .push(Task::ExpectPunctuation(Punctuation::RightParenthesis));
                self.tasks.push(Task::ValueType);
                self.run_tasks_above(base)?;
            }
            self.finish().map_err(|_| self.invariant_fault())?;
            count = count.saturating_add(1);
            if !self.consume_if_punctuation(Punctuation::Comma)? {
                break;
            }
        }
        self.expect_punctuation(Punctuation::RightBrace)?;
        self.finish().map_err(|_| self.invariant_fault())?;
        Ok(())
    }

    fn parse_action_declaration(&mut self) -> Result<(), SyntaxFault> {
        self.begin(SyntaxForm::ActionDeclaration);
        self.tasks.push(Task::Finish);
        self.tasks
            .push(Task::ExpectPunctuation(Punctuation::Semicolon));
        self.consume_word("action")?;
        if !(self.at_word("read_only")
            || self.at_word("idempotent")
            || self.at_word("non_idempotent"))
        {
            return Err(self.expected("action recovery class"));
        }
        self.consume_current()?;
        self.expect_identifier()?;
        self.expect_punctuation(Punctuation::LeftParenthesis)?;
        self.parse_parameter_list(false)?;
        self.expect_punctuation(Punctuation::RightParenthesis)?;
        if self.consume_if_punctuation(Punctuation::ThinArrow)? {
            self.tasks.push(Task::ValueType);
        }
        Ok(())
    }

    fn parse_function_declaration(&mut self, form: SyntaxForm) -> Result<(), SyntaxFault> {
        self.begin(form);
        self.tasks.push(Task::Finish);
        self.tasks.push(Task::Block(BlockKind::Ordinary));
        if self.at_word("pure") {
            self.consume_current()?;
        }
        self.expect_word("fn")?;
        self.expect_identifier()?;
        self.expect_punctuation(Punctuation::LeftParenthesis)?;
        let method = matches!(
            self.open.last().map(|node| &node.form),
            Some(SyntaxForm::MethodDeclaration)
        );
        self.parse_parameter_list(method)?;
        self.expect_punctuation(Punctuation::RightParenthesis)?;
        if self.consume_if_punctuation(Punctuation::ThinArrow)? {
            self.tasks.push(Task::ValueType);
        }
        Ok(())
    }

    fn parse_parameter_list(&mut self, method: bool) -> Result<(), SyntaxFault> {
        if self.at_punctuation(Punctuation::RightParenthesis) {
            if method {
                return Err(self.expected("method receiver"));
            }
            return Ok(());
        }
        if method {
            self.begin(SyntaxForm::Parameter);
            if self.at_word("mut") {
                self.consume_current()?;
            }
            self.expect_word("self")?;
            self.finish().map_err(|_| self.invariant_fault())?;
            if !self.consume_if_punctuation(Punctuation::Comma)? {
                return Ok(());
            }
            if self.at_punctuation(Punctuation::RightParenthesis) {
                return Ok(());
            }
        }
        loop {
            self.begin(SyntaxForm::Parameter);
            if self.at_word("mut") {
                self.consume_current()?;
            }
            self.expect_identifier()?;
            self.expect_punctuation(Punctuation::Colon)?;
            let base = self.tasks.len();
            self.tasks.push(Task::Finish);
            self.tasks.push(Task::ValueType);
            self.run_tasks_above(base)?;
            if !self.consume_if_punctuation(Punctuation::Comma)?
                || self.at_punctuation(Punctuation::RightParenthesis)
            {
                break;
            }
        }
        Ok(())
    }

    fn parse_value_type(&mut self) -> Result<(), SyntaxFault> {
        self.begin(SyntaxForm::ValueType);
        self.tasks.push(Task::Finish);
        if self.at_word("Option") || self.at_word("List") {
            self.consume_current()?;
            self.expect_punctuation(Punctuation::Less)?;
            self.tasks
                .push(Task::ExpectPunctuation(Punctuation::Greater));
            self.tasks.push(Task::ValueType);
        } else if self.at_word("Result") {
            self.consume_current()?;
            self.expect_punctuation(Punctuation::Less)?;
            self.tasks
                .push(Task::ExpectPunctuation(Punctuation::Greater));
            self.tasks.push(Task::ValueType);
            self.tasks.push(Task::ExpectPunctuation(Punctuation::Comma));
            self.tasks.push(Task::ValueType);
        } else if self.at_word("Tuple") {
            self.consume_current()?;
            self.expect_punctuation(Punctuation::Less)?;
            self.tasks.push(Task::TupleTypeTail { count: 0 });
        } else if self.at_builtin_type() {
            self.consume_current()?;
        } else {
            self.tasks.push(Task::ParsePath);
        }
        Ok(())
    }

    fn parse_tuple_type_tail(&mut self, count: usize) -> Result<(), SyntaxFault> {
        if count == 0 {
            self.tasks.push(Task::TupleTypeTail { count: 1 });
            self.tasks.push(Task::ValueType);
            return Ok(());
        }
        if self.at_punctuation(Punctuation::Greater) {
            if count < 2 {
                return Err(self.expected("at least two tuple member types"));
            }
            self.consume_current()?;
        } else {
            self.expect_punctuation(Punctuation::Comma)?;
            if self.at_punctuation(Punctuation::Greater) {
                if count < 2 {
                    return Err(self.expected("at least two tuple member types"));
                }
                self.consume_current()?;
                return Ok(());
            }
            self.tasks.push(Task::TupleTypeTail {
                count: count.saturating_add(1),
            });
            self.tasks.push(Task::ValueType);
        }
        Ok(())
    }

    fn parse_path(&mut self) -> Result<(), SyntaxFault> {
        self.begin(SyntaxForm::Path);
        if self.at_identifier() {
            self.consume_current()?;
        } else if self.at_word("crate") || self.at_word("self") {
            self.consume_current()?;
            self.expect_punctuation(Punctuation::PathSeparator)?;
            self.expect_identifier()?;
        } else if self.at_word("super") {
            self.consume_current()?;
            self.expect_punctuation(Punctuation::PathSeparator)?;
            while self.at_word("super") && self.peek_punctuation(1, Punctuation::PathSeparator) {
                self.consume_current()?;
                self.consume_current()?;
            }
            self.expect_identifier()?;
        } else {
            return Err(self.expected("qualified path"));
        }
        while self.consume_if_punctuation(Punctuation::PathSeparator)? {
            self.expect_identifier()?;
        }
        self.finish().map_err(|_| self.invariant_fault())?;
        Ok(())
    }

    fn push_identifier_list(&mut self, closing: Punctuation) {
        self.tasks.push(Task::IdentifierList {
            closing,
            count: 0,
            minimum: 1,
        });
    }

    fn begin(&mut self, form: SyntaxForm) {
        let start = self.current().span().bytes().start();
        self.open.push(OpenNode {
            form,
            children: Vec::new(),
            start,
        });
    }

    fn finish(&mut self) -> Result<NodeId, ParseError> {
        let open = self.open.pop().ok_or(ParseError::Invariant)?;
        let end = open
            .children
            .last()
            .and_then(|child| self.nodes.get(child.index()))
            .map(|child| child.span().bytes().end())
            .unwrap_or(open.start);
        let span = self.span(open.start, end)?;
        let id = NodeId(self.nodes.len());
        self.nodes
            .push(SyntaxNode::new(open.form, span, open.children));
        if let Some(parent) = self.open.last_mut() {
            parent.children.push(id);
        }
        Ok(id)
    }

    fn consume_current(&mut self) -> Result<(), SyntaxFault> {
        let token = self.current().clone();
        let id = NodeId(self.nodes.len());
        self.nodes.push(SyntaxNode::new(
            SyntaxForm::Token(token.kind().clone()),
            token.span().clone(),
            Vec::new(),
        ));
        let Some(parent) = self.open.last_mut() else {
            return Err(self.invariant_fault());
        };
        parent.children.push(id);
        self.position = self.position.saturating_add(1);
        Ok(())
    }

    fn expect_word(&mut self, word: &'static str) -> Result<(), SyntaxFault> {
        if !self.at_word(word) {
            return Err(self.expected(word));
        }
        self.consume_current()
    }

    fn consume_word(&mut self, word: &'static str) -> Result<(), SyntaxFault> {
        self.expect_word(word)
    }

    fn expect_identifier(&mut self) -> Result<(), SyntaxFault> {
        if !self.at_identifier() {
            return Err(self.expected("identifier"));
        }
        self.consume_current()
    }

    fn expect_punctuation(&mut self, punctuation: Punctuation) -> Result<(), SyntaxFault> {
        if !self.at_punctuation(punctuation) {
            return Err(self.expected(punctuation.spelling()));
        }
        self.consume_current()
    }

    fn consume_if_punctuation(&mut self, punctuation: Punctuation) -> Result<bool, SyntaxFault> {
        if self.at_punctuation(punctuation) {
            self.consume_current()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn current(&self) -> &Token {
        self.tokens.get(self.position).unwrap_or_else(|| {
            self.tokens
                .last()
                .unwrap_or_else(|| unreachable!("EOF token"))
        })
    }

    fn at_end(&self) -> bool {
        matches!(self.current().kind(), TokenKind::EndOfFile)
    }

    fn at_word(&self, word: &str) -> bool {
        token_is_word(self.current(), word)
    }

    fn at_identifier(&self) -> bool {
        matches!(self.current().kind(), TokenKind::Identifier(_))
    }

    fn at_integer(&self) -> bool {
        matches!(
            self.current().kind(),
            TokenKind::IntegerLiteral(_) | TokenKind::DirectiveInteger(_)
        )
    }

    fn at_float(&self) -> bool {
        matches!(self.current().kind(), TokenKind::FloatLiteral(_))
    }

    fn at_string(&self) -> bool {
        matches!(
            self.current().kind(),
            TokenKind::StringLiteral(_) | TokenKind::RawStringLiteral(_)
        )
    }

    fn at_punctuation(&self, punctuation: Punctuation) -> bool {
        token_is_punctuation(self.current(), punctuation)
    }

    fn peek_punctuation(&self, distance: usize, punctuation: Punctuation) -> bool {
        self.tokens
            .get(self.position.saturating_add(distance))
            .is_some_and(|token| token_is_punctuation(token, punctuation))
    }

    fn at_builtin_type(&self) -> bool {
        [
            "Unit",
            "Bool",
            "Int",
            "Float",
            "String",
            "Decision",
            "OperationError",
        ]
        .iter()
        .any(|word| self.at_word(word))
    }

    fn expected(&self, expected: &'static str) -> SyntaxFault {
        SyntaxFault {
            expected,
            span: self.current().span().clone(),
            encountered: token_description(self.current().kind()),
        }
    }

    fn invariant_fault(&self) -> SyntaxFault {
        self.expected("valid parser state")
    }

    fn push_syntax_diagnostic(&mut self, fault: SyntaxFault) -> Result<(), ParseError> {
        if let Err(error) = self.counters.charge_diagnostic() {
            return Err(ParseError::ResourceLimit {
                error,
                diagnostics: self.diagnostics.clone(),
            });
        }
        let diagnostic = StructuredDiagnostic::new(
            DiagnosticMetadata {
                phase: DiagnosticPhase::Syntax,
                severity: DiagnosticSeverity::Error,
                category: DiagnosticCategory::Syntax,
                code: DiagnosticCode::new("unexpected-token").map_err(|_| ParseError::Invariant)?,
            },
            "source token does not satisfy the Gantry grammar",
            Some(fault.span),
            Vec::new(),
            BTreeMap::from([
                (Arc::from("encountered"), fault.encountered),
                (Arc::from("expected"), Arc::from(fault.expected)),
            ]),
        )
        .map_err(|_| ParseError::Invariant)?;
        self.diagnostics.push(diagnostic);
        Ok(())
    }

    fn recover_item(&mut self) {
        let mut brace_depth = 0_usize;
        while !self.at_end() {
            if self.at_punctuation(Punctuation::LeftBrace) {
                brace_depth = brace_depth.saturating_add(1);
            } else if self.at_punctuation(Punctuation::RightBrace) {
                brace_depth = brace_depth.saturating_sub(1);
                self.position = self.position.saturating_add(1);
                if brace_depth == 0 {
                    break;
                }
                continue;
            } else if self.at_punctuation(Punctuation::Semicolon) && brace_depth == 0 {
                self.position = self.position.saturating_add(1);
                break;
            }
            self.position = self.position.saturating_add(1);
        }
    }

    fn span(&self, start: u64, end: u64) -> Result<SourceSpan, ParseError> {
        let bytes = ByteSpan::new(start, end).map_err(ParseError::Span)?;
        SourceSpan::new(self.record, bytes).map_err(ParseError::Span)
    }

    fn parse_block(&mut self, kind: BlockKind) -> Result<(), SyntaxFault> {
        self.begin(SyntaxForm::Block);
        self.expect_punctuation(Punctuation::LeftBrace)?;
        self.tasks.push(Task::Finish);
        self.tasks
            .push(Task::ExpectPunctuation(Punctuation::RightBrace));
        self.tasks.push(Task::BlockContents(kind));
        Ok(())
    }

    fn parse_block_contents(&mut self, kind: BlockKind) -> Result<(), SyntaxFault> {
        if self.at_punctuation(Punctuation::RightBrace) {
            return if kind == BlockKind::Value {
                Err(self.expected("value-producing trailing expression"))
            } else {
                Ok(())
            };
        }
        if self.starts_statement() {
            self.tasks.push(Task::BlockContents(kind));
            self.tasks.push(Task::Statement);
            return Ok(());
        }
        self.tasks.push(Task::AfterBlockExpression(kind));
        self.tasks.push(Task::Expression {
            minimum_precedence: 0,
            mode: ExpressionMode::Ordinary,
            control_boundary: false,
        });
        Ok(())
    }

    fn after_block_expression(&mut self, kind: BlockKind) -> Result<(), SyntaxFault> {
        if self.consume_if_punctuation(Punctuation::Semicolon)? {
            self.wrap_last_child(SyntaxForm::ExpressionStatement)?;
            self.tasks.push(Task::BlockContents(kind));
            Ok(())
        } else if self.at_punctuation(Punctuation::RightBrace) {
            if kind == BlockKind::Statement {
                Err(self.expected("`;` after expression statement"))
            } else {
                Ok(())
            }
        } else {
            Err(self.expected("`;` or `}`"))
        }
    }

    fn parse_statement(&mut self) -> Result<(), SyntaxFault> {
        if self.at_word("let") {
            self.begin(SyntaxForm::LetStatement);
            self.tasks.push(Task::Finish);
            self.tasks
                .push(Task::ExpectPunctuation(Punctuation::Semicolon));
            self.tasks.push(Task::Expression {
                minimum_precedence: 0,
                mode: ExpressionMode::Ordinary,
                control_boundary: false,
            });
            self.tasks.push(Task::ExpectPunctuation(Punctuation::Equal));
            self.tasks.push(Task::ValueType);
            self.tasks.push(Task::ExpectPunctuation(Punctuation::Colon));
            self.consume_current()?;
            if self.at_word("mut") {
                self.consume_current()?;
                self.expect_identifier()?;
            } else if self.at_identifier() {
                self.consume_current()?;
            } else if self.at_punctuation(Punctuation::LeftParenthesis) {
                self.tasks.push(Task::Pattern);
            } else {
                return Err(self.expected("binding name or tuple pattern"));
            }
        } else if self.at_word("discard") {
            self.begin(SyntaxForm::DiscardStatement);
            self.tasks.push(Task::Finish);
            self.tasks
                .push(Task::ExpectPunctuation(Punctuation::Semicolon));
            self.tasks.push(Task::Expression {
                minimum_precedence: 0,
                mode: ExpressionMode::Ordinary,
                control_boundary: false,
            });
            self.consume_current()?;
        } else if self.at_word("return") {
            self.begin(SyntaxForm::ReturnStatement);
            self.consume_current()?;
            self.tasks.push(Task::Finish);
            self.tasks
                .push(Task::ExpectPunctuation(Punctuation::Semicolon));
            if !self.at_punctuation(Punctuation::Semicolon) {
                self.tasks.push(Task::Expression {
                    minimum_precedence: 0,
                    mode: ExpressionMode::Ordinary,
                    control_boundary: false,
                });
            }
        } else if self.at_word("break") || self.at_word("continue") {
            let form = if self.at_word("break") {
                SyntaxForm::BreakStatement
            } else {
                SyntaxForm::ContinueStatement
            };
            self.begin(form);
            self.tasks.push(Task::Finish);
            self.tasks
                .push(Task::ExpectPunctuation(Punctuation::Semicolon));
            self.consume_current()?;
        } else if self.at_word("spawn") {
            self.begin(SyntaxForm::SpawnStatement);
            self.consume_current()?;
            self.expect_identifier()?;
            self.tasks.push(Task::Finish);
            self.tasks.push(Task::Block(BlockKind::Ordinary));
            if self.consume_if_punctuation(Punctuation::ThinArrow)? {
                self.tasks.push(Task::ValueType);
            }
        } else if self.at_word("detach") {
            self.begin(SyntaxForm::DetachStatement);
            self.tasks.push(Task::Finish);
            self.tasks
                .push(Task::ExpectPunctuation(Punctuation::Semicolon));
            self.tasks
                .push(Task::ExpectPunctuation(Punctuation::RightParenthesis));
            self.tasks.push(Task::ExpectIdentifier);
            self.tasks
                .push(Task::ExpectPunctuation(Punctuation::LeftParenthesis));
            self.consume_current()?;
        } else if self.at_word("if") {
            self.begin(SyntaxForm::IfStatement);
            self.consume_current()?;
            self.tasks.push(Task::Finish);
            self.tasks.push(Task::IfTail);
            self.tasks.push(Task::Block(BlockKind::Statement));
            self.push_condition();
        } else if self.at_word("loop") || self.at_word("while") || self.at_word("for") {
            self.parse_pretest_loop()?;
        } else if self.at_word("until") {
            self.begin(SyntaxForm::UntilStatement);
            self.consume_current()?;
            self.push_loop_modifiers()?;
            self.tasks.push(Task::Finish);
            self.tasks
                .push(Task::ExpectPunctuation(Punctuation::Semicolon));
            self.tasks.push(Task::Expression {
                minimum_precedence: 0,
                mode: ExpressionMode::Ordinary,
                control_boundary: false,
            });
            self.tasks.push(Task::ExpectWord("when"));
            self.tasks.push(Task::Block(BlockKind::Statement));
        } else if self.at_word("with") || self.at_word("session") {
            let form = if self.at_word("with") {
                SyntaxForm::WithStatement
            } else {
                SyntaxForm::SessionStatement
            };
            self.begin(form);
            if self.at_word("with") {
                self.consume_current()?;
                self.expect_identifier()?;
            } else {
                self.consume_current()?;
                self.expect_punctuation(Punctuation::LeftParenthesis)?;
                self.expect_session_directive()?;
                self.expect_punctuation(Punctuation::RightParenthesis)?;
            }
            self.tasks.push(Task::Finish);
            self.tasks.push(Task::Block(BlockKind::Statement));
        } else if self.at_word("match") {
            self.begin(SyntaxForm::MatchStatement);
            self.consume_current()?;
            self.tasks.push(Task::Finish);
            self.tasks
                .push(Task::ExpectPunctuation(Punctuation::RightBrace));
            self.tasks.push(Task::MatchArms {
                statement: true,
                count: 0,
            });
            self.tasks
                .push(Task::ExpectPunctuation(Punctuation::LeftBrace));
            self.tasks.push(Task::Expression {
                minimum_precedence: 0,
                mode: ExpressionMode::Ordinary,
                control_boundary: true,
            });
        } else if self.looks_like_assignment() {
            self.parse_assignment_statement()?;
        } else {
            return Err(self.expected("statement"));
        }
        Ok(())
    }

    fn parse_assignment_statement(&mut self) -> Result<(), SyntaxFault> {
        self.begin(SyntaxForm::AssignmentStatement);
        self.tasks.push(Task::Finish);
        self.tasks
            .push(Task::ExpectPunctuation(Punctuation::Semicolon));
        self.tasks.push(Task::Expression {
            minimum_precedence: 0,
            mode: ExpressionMode::Ordinary,
            control_boundary: false,
        });
        if self.at_word("self") {
            self.consume_current()?;
            self.expect_punctuation(Punctuation::Dot)?;
            self.expect_identifier()?;
        } else {
            self.expect_identifier()?;
        }
        while self.consume_if_punctuation(Punctuation::Dot)? {
            self.expect_identifier()?;
        }
        if !self.at_assignment_operator() {
            return Err(self.expected("assignment operator"));
        }
        self.consume_current()?;
        Ok(())
    }

    fn parse_pretest_loop(&mut self) -> Result<(), SyntaxFault> {
        let form = if self.at_word("loop") {
            SyntaxForm::LoopStatement
        } else if self.at_word("while") {
            SyntaxForm::WhileStatement
        } else {
            SyntaxForm::ForStatement
        };
        self.begin(form);
        let kind = token_description(self.current().kind());
        self.consume_current()?;
        if &*kind != "for" {
            self.push_loop_modifiers()?;
        }
        self.tasks.push(Task::Finish);
        self.tasks.push(Task::Block(BlockKind::Statement));
        if &*kind == "while" {
            self.tasks.push(Task::Expression {
                minimum_precedence: 0,
                mode: ExpressionMode::Ordinary,
                control_boundary: true,
            });
        } else if &*kind == "for" {
            self.expect_identifier()?;
            self.expect_word("in")?;
            self.tasks.push(Task::Expression {
                minimum_precedence: 0,
                mode: ExpressionMode::Ordinary,
                control_boundary: true,
            });
        }
        Ok(())
    }

    fn parse_expression(
        &mut self,
        minimum_precedence: u8,
        mode: ExpressionMode,
        control_boundary: bool,
    ) {
        self.begin(SyntaxForm::Expression);
        self.tasks.push(Task::Finish);
        self.tasks.push(Task::BinaryTail {
            minimum_precedence,
            mode,
            control_boundary,
            equality_seen: false,
            ordering_seen: false,
        });
        self.tasks.push(Task::Prefix {
            mode,
            control_boundary,
        });
    }

    fn current_binary_operator(&self) -> Option<(u8, BinaryClass)> {
        let punctuation = match self.current().kind() {
            TokenKind::Punctuation(punctuation) => *punctuation,
            _ => return None,
        };
        Some(match punctuation {
            Punctuation::OrOr => (1, BinaryClass::Ordinary),
            Punctuation::AndAnd => (2, BinaryClass::Ordinary),
            Punctuation::EqualEqual | Punctuation::NotEqual => (3, BinaryClass::Equality),
            Punctuation::Less
            | Punctuation::LessEqual
            | Punctuation::Greater
            | Punctuation::GreaterEqual => (4, BinaryClass::Ordering),
            Punctuation::Plus | Punctuation::Minus => (5, BinaryClass::Ordinary),
            Punctuation::Star | Punctuation::Slash | Punctuation::Percent => {
                (6, BinaryClass::Ordinary)
            }
            _ => return None,
        })
    }

    fn parse_binary_tail(
        &mut self,
        minimum_precedence: u8,
        mode: ExpressionMode,
        control_boundary: bool,
        equality_seen: bool,
        ordering_seen: bool,
    ) -> Result<(), SyntaxFault> {
        let Some((precedence, class)) = self.current_binary_operator() else {
            return Ok(());
        };
        if precedence < minimum_precedence {
            return Ok(());
        }
        if (class == BinaryClass::Equality && equality_seen)
            || (class == BinaryClass::Ordering && ordering_seen)
        {
            return Err(self.expected("parenthesized non-associative comparison"));
        }
        self.wrap_last_child(SyntaxForm::BinaryExpression)?;
        self.consume_current()?;
        self.tasks.push(Task::BinaryTail {
            minimum_precedence,
            mode,
            control_boundary,
            equality_seen: equality_seen || class == BinaryClass::Equality,
            ordering_seen: ordering_seen || class == BinaryClass::Ordering,
        });
        self.tasks.push(Task::Expression {
            minimum_precedence: precedence.saturating_add(1),
            mode,
            control_boundary,
        });
        Ok(())
    }

    fn parse_prefix(
        &mut self,
        mode: ExpressionMode,
        control_boundary: bool,
    ) -> Result<(), SyntaxFault> {
        if self.at_punctuation(Punctuation::Bang) || self.at_punctuation(Punctuation::Minus) {
            self.begin(SyntaxForm::UnaryExpression);
            self.consume_current()?;
            self.tasks.push(Task::Finish);
            self.tasks.push(Task::Prefix {
                mode,
                control_boundary,
            });
            return Ok(());
        }
        let complete = mode == ExpressionMode::Ordinary
            && [
                "prompt", "decide", "action", "attempt", "match", "join", "joinall", "with",
                "session",
            ]
            .iter()
            .any(|word| self.at_word(word));
        if !complete {
            self.tasks.push(Task::PostfixTail { mode });
        }
        self.tasks.push(Task::Primary {
            mode,
            control_boundary,
        });
        Ok(())
    }

    fn parse_postfix_tail(&mut self, mode: ExpressionMode) -> Result<(), SyntaxFault> {
        if self.consume_if_punctuation(Punctuation::Dot)? {
            self.wrap_last_child(SyntaxForm::PostfixExpression)?;
            if self.at_identifier() || self.at_word("join") || self.at_integer() {
                self.consume_current()?;
            } else {
                return Err(self.expected("postfix member name"));
            }
            self.tasks.push(Task::PostfixTail { mode });
        } else if self.consume_if_punctuation(Punctuation::LeftParenthesis)? {
            self.wrap_last_child(SyntaxForm::PostfixExpression)?;
            self.tasks.push(Task::PostfixTail { mode });
            self.tasks.push(Task::ExpressionList {
                closing: Punctuation::RightParenthesis,
                mode,
                count: 0,
                minimum: 0,
            });
        } else if self.consume_if_punctuation(Punctuation::LeftBracket)? {
            self.wrap_last_child(SyntaxForm::PostfixExpression)?;
            self.tasks.push(Task::PostfixTail { mode });
            self.tasks
                .push(Task::ExpectPunctuation(Punctuation::RightBracket));
            self.tasks.push(Task::Expression {
                minimum_precedence: 0,
                mode,
                control_boundary: false,
            });
        }
        Ok(())
    }

    fn parse_primary(
        &mut self,
        mode: ExpressionMode,
        control_boundary: bool,
    ) -> Result<(), SyntaxFault> {
        if self.at_integer()
            || self.at_float()
            || self.at_string()
            || self.at_word("true")
            || self.at_word("false")
            || self.at_word("None")
            || (self.at_word("self") && !self.peek_punctuation(1, Punctuation::PathSeparator))
        {
            self.consume_current()?;
        } else if self.at_word("Some") || self.at_word("Ok") || self.at_word("Err") {
            self.consume_current()?;
            self.expect_punctuation(Punctuation::LeftParenthesis)?;
            self.tasks
                .push(Task::ExpectPunctuation(Punctuation::RightParenthesis));
            self.tasks.push(Task::Expression {
                minimum_precedence: 0,
                mode,
                control_boundary: false,
            });
        } else if self.at_punctuation(Punctuation::LeftParenthesis) {
            self.consume_current()?;
            if self.consume_if_punctuation(Punctuation::RightParenthesis)? {
                return Ok(());
            }
            self.tasks.push(Task::ParenthesizedTail { mode });
            self.tasks.push(Task::Expression {
                minimum_precedence: 0,
                mode,
                control_boundary: false,
            });
        } else if self.at_punctuation(Punctuation::LeftBracket) {
            self.begin(SyntaxForm::ListExpression);
            self.consume_current()?;
            self.tasks.push(Task::Finish);
            self.tasks.push(Task::ExpressionList {
                closing: Punctuation::RightBracket,
                mode,
                count: 0,
                minimum: 0,
            });
        } else if mode == ExpressionMode::Ordinary && self.at_word("prompt") {
            self.parse_prompt_expression(false)?;
        } else if mode == ExpressionMode::Ordinary && self.at_word("decide") {
            self.parse_prompt_expression(true)?;
        } else if mode == ExpressionMode::Ordinary && self.at_word("action") {
            self.parse_action_expression()?;
        } else if mode == ExpressionMode::Ordinary && self.at_word("attempt") {
            self.begin(SyntaxForm::AttemptExpression);
            self.consume_current()?;
            self.tasks.push(Task::Finish);
            if self.at_word("prompt") {
                self.parse_prompt_expression(false)?;
            } else if self.at_word("decide") {
                self.parse_prompt_expression(true)?;
            } else if self.at_word("action") {
                self.parse_action_expression()?;
            } else {
                return Err(self.expected("prompt, decide, or action operation"));
            }
        } else if mode == ExpressionMode::Ordinary && self.at_word("match") {
            self.begin(SyntaxForm::MatchExpression);
            self.consume_current()?;
            self.tasks.push(Task::Finish);
            self.tasks
                .push(Task::ExpectPunctuation(Punctuation::RightBrace));
            self.tasks.push(Task::MatchArms {
                statement: false,
                count: 0,
            });
            self.tasks
                .push(Task::ExpectPunctuation(Punctuation::LeftBrace));
            self.tasks.push(Task::Expression {
                minimum_precedence: 0,
                mode,
                control_boundary: true,
            });
        } else if mode == ExpressionMode::Ordinary && self.at_word("join") {
            self.begin(SyntaxForm::JoinExpression);
            self.consume_current()?;
            self.expect_punctuation(Punctuation::LeftParenthesis)?;
            self.tasks.push(Task::Finish);
            self.tasks.push(Task::IdentifierList {
                closing: Punctuation::RightParenthesis,
                count: 0,
                minimum: 1,
            });
        } else if mode == ExpressionMode::Ordinary && self.at_word("joinall") {
            self.begin(SyntaxForm::JoinAllExpression);
            self.consume_current()?;
            self.expect_punctuation(Punctuation::LeftParenthesis)?;
            self.expect_punctuation(Punctuation::RightParenthesis)?;
            self.finish().map_err(|_| self.invariant_fault())?;
        } else if mode == ExpressionMode::Ordinary
            && (self.at_word("with") || self.at_word("session"))
        {
            self.parse_context_expression()?;
        } else if self.at_identifier()
            || self.at_word("crate")
            || self.at_word("super")
            || (self.at_word("self") && self.peek_punctuation(1, Punctuation::PathSeparator))
        {
            self.parse_path()?;
            if !control_boundary && self.at_punctuation(Punctuation::LeftBrace) {
                self.begin(SyntaxForm::StructExpression);
                self.expect_punctuation(Punctuation::LeftBrace)?;
                self.tasks.push(Task::Finish);
                self.tasks.push(Task::StructFields { mode, count: 0 });
            }
        } else {
            return Err(self.expected("expression"));
        }
        Ok(())
    }

    fn parse_prompt_expression(&mut self, decide: bool) -> Result<(), SyntaxFault> {
        self.begin(if decide {
            SyntaxForm::DecideExpression
        } else {
            SyntaxForm::PromptExpression
        });
        self.consume_current()?;
        if self.consume_if_punctuation(Punctuation::LeftParenthesis)? {
            self.begin(SyntaxForm::ModifierList);
            let mut count = 0_usize;
            while !self.at_punctuation(Punctuation::RightParenthesis) {
                if count > 0 {
                    self.expect_punctuation(Punctuation::Comma)?;
                    if self.at_punctuation(Punctuation::RightParenthesis) {
                        break;
                    }
                }
                self.begin(SyntaxForm::Modifier);
                if self.at_word("session") {
                    self.consume_current()?;
                    self.expect_punctuation(Punctuation::Equal)?;
                    self.expect_session_directive()?;
                } else if self.at_word("retry_limit") {
                    self.consume_current()?;
                    self.expect_punctuation(Punctuation::Equal)?;
                    if !self.at_integer() {
                        return Err(self.expected("directive integer"));
                    }
                    self.consume_current()?;
                } else {
                    return Err(self.expected("prompt modifier"));
                }
                self.finish().map_err(|_| self.invariant_fault())?;
                count = count.saturating_add(1);
            }
            if count == 0 {
                return Err(self.expected("prompt modifier"));
            }
            self.expect_punctuation(Punctuation::RightParenthesis)?;
            self.finish().map_err(|_| self.invariant_fault())?;
        }
        let TokenKind::PromptTemplate(template) = self.current().kind() else {
            return Err(self.expected("prompt template"));
        };
        let interpolations = template.interpolations().to_vec();
        for interpolation in &interpolations {
            self.validate_interpolation(interpolation)?;
        }
        self.consume_current()?;
        self.tasks.push(Task::Finish);
        self.tasks.push(Task::PromptTail {
            allow_result_annotation: !decide,
        });
        Ok(())
    }

    fn validate_interpolation(
        &mut self,
        interpolation: &crate::prompt::InterpolationIsland,
    ) -> Result<(), SyntaxFault> {
        let eof_span = self
            .span(
                interpolation.span().bytes().end(),
                interpolation.span().bytes().end(),
            )
            .map_err(|_| self.invariant_fault())?;
        let mut tokens = interpolation.tokens().to_vec();
        tokens.push(Token::new(TokenKind::EndOfFile, eof_span));
        let mut machine = Machine::new(self.record, self.counters, tokens);
        machine.begin(SyntaxForm::InterpolationExpression);
        machine.tasks.push(Task::Finish);
        machine.tasks.push(Task::Expression {
            minimum_precedence: 0,
            mode: ExpressionMode::Interpolation,
            control_boundary: false,
        });
        machine.run_tasks()?;
        if !machine.at_end() {
            return Err(machine.expected("end of interpolation"));
        }
        let Some(root_index) = machine.nodes.len().checked_sub(1) else {
            return Err(machine.invariant_fault());
        };
        if !matches!(
            machine.nodes.get(root_index).map(SyntaxNode::form),
            Some(SyntaxForm::InterpolationExpression)
        ) {
            return Err(self.invariant_fault());
        }
        let base = self.nodes.len();
        for node in machine.nodes {
            let mut children = Vec::with_capacity(node.children().len());
            for child in node.children() {
                children.push(NodeId::from_index(
                    base.checked_add(child.index())
                        .ok_or_else(|| self.invariant_fault())?,
                ));
            }
            self.nodes.push(SyntaxNode::new(
                node.form().clone(),
                node.span().clone(),
                children,
            ));
        }
        let root = NodeId::from_index(
            base.checked_add(root_index)
                .ok_or_else(|| self.invariant_fault())?,
        );
        let Some(parent) = self.open.last_mut() else {
            return Err(self.invariant_fault());
        };
        parent.children.push(root);
        Ok(())
    }

    fn parse_prompt_tail(&mut self, allow_result_annotation: bool) -> Result<(), SyntaxFault> {
        if self.at_word("using") {
            self.begin(SyntaxForm::UsingClause);
            self.consume_current()?;
            self.expect_punctuation(Punctuation::LeftBrace)?;
            self.tasks.push(Task::PromptTail {
                allow_result_annotation,
            });
            self.tasks.push(Task::Finish);
            self.tasks
                .push(Task::ExpectPunctuation(Punctuation::RightBrace));
            self.tasks.push(Task::UsingList { count: 0 });
        } else if self.consume_if_punctuation(Punctuation::ThinArrow)? {
            if !allow_result_annotation {
                return Err(self.expected("no result annotation after `decide`"));
            }
            self.tasks.push(Task::ValueType);
        }
        Ok(())
    }

    fn parse_using_list(&mut self, count: usize) -> Result<(), SyntaxFault> {
        if self.at_punctuation(Punctuation::RightBrace) {
            return if count == 0 {
                Err(self.expected("named prompt input"))
            } else {
                Ok(())
            };
        }
        if count > 0 {
            self.expect_punctuation(Punctuation::Comma)?;
            if self.at_punctuation(Punctuation::RightBrace) {
                return Ok(());
            }
        }
        self.begin(SyntaxForm::NamedInput);
        self.expect_identifier()?;
        self.tasks.push(Task::UsingList {
            count: count.saturating_add(1),
        });
        self.tasks.push(Task::Finish);
        if self.consume_if_punctuation(Punctuation::Colon)? {
            self.tasks.push(Task::Expression {
                minimum_precedence: 0,
                mode: ExpressionMode::Interpolation,
                control_boundary: false,
            });
        }
        Ok(())
    }

    fn parse_action_expression(&mut self) -> Result<(), SyntaxFault> {
        self.begin(SyntaxForm::ActionExpression);
        self.consume_current()?;
        if self.consume_if_punctuation(Punctuation::LeftParenthesis)? {
            self.begin(SyntaxForm::ModifierList);
            self.begin(SyntaxForm::Modifier);
            self.expect_word("retry_limit")?;
            self.expect_punctuation(Punctuation::Equal)?;
            if !self.at_integer() {
                return Err(self.expected("directive integer"));
            }
            self.consume_current()?;
            self.finish().map_err(|_| self.invariant_fault())?;
            self.expect_punctuation(Punctuation::RightParenthesis)?;
            self.finish().map_err(|_| self.invariant_fault())?;
        }
        self.parse_path()?;
        self.expect_punctuation(Punctuation::LeftParenthesis)?;
        self.tasks.push(Task::Finish);
        self.tasks.push(Task::ExpressionList {
            closing: Punctuation::RightParenthesis,
            mode: ExpressionMode::Ordinary,
            count: 0,
            minimum: 0,
        });
        Ok(())
    }

    fn parse_context_expression(&mut self) -> Result<(), SyntaxFault> {
        let with = self.at_word("with");
        self.begin(if with {
            SyntaxForm::WithExpression
        } else {
            SyntaxForm::SessionExpression
        });
        self.consume_current()?;
        if with {
            self.expect_identifier()?;
        } else {
            self.expect_punctuation(Punctuation::LeftParenthesis)?;
            self.expect_session_directive()?;
            self.expect_punctuation(Punctuation::RightParenthesis)?;
        }
        self.tasks.push(Task::Finish);
        self.tasks.push(Task::Block(BlockKind::Value));
        Ok(())
    }

    fn parse_pattern(&mut self) -> Result<(), SyntaxFault> {
        self.begin(SyntaxForm::Pattern);
        self.tasks.push(Task::Finish);
        if self.at_punctuation(Punctuation::Underscore)
            || self.at_identifier()
            || self.at_word("None")
        {
            self.consume_current()?;
            if self.at_punctuation(Punctuation::PathSeparator) {
                self.tasks.push(Task::PatternPathTail);
            }
        } else if self.at_word("Some") || self.at_word("Ok") || self.at_word("Err") {
            self.consume_current()?;
            self.expect_punctuation(Punctuation::LeftParenthesis)?;
            self.tasks
                .push(Task::ExpectPunctuation(Punctuation::RightParenthesis));
            self.tasks.push(Task::Pattern);
        } else if self.at_word("OperationError") {
            self.consume_current()?;
            self.expect_punctuation(Punctuation::PathSeparator)?;
            self.expect_identifier()?;
            if self.consume_if_punctuation(Punctuation::LeftParenthesis)? {
                self.tasks
                    .push(Task::ExpectPunctuation(Punctuation::RightParenthesis));
                self.tasks.push(Task::Pattern);
            }
        } else if self.at_word("crate") || self.at_word("self") || self.at_word("super") {
            self.consume_current()?;
            self.expect_punctuation(Punctuation::PathSeparator)?;
            if self.at_word("super") {
                while self.at_word("super") && self.peek_punctuation(1, Punctuation::PathSeparator)
                {
                    self.consume_current()?;
                    self.consume_current()?;
                }
            }
            self.expect_identifier()?;
            self.tasks.push(Task::PatternPathTail);
        } else if self.consume_if_punctuation(Punctuation::LeftParenthesis)? {
            self.tasks.push(Task::PatternList { count: 0 });
        } else {
            return Err(self.expected("pattern"));
        }
        Ok(())
    }

    fn parse_pattern_path_tail(&mut self) -> Result<(), SyntaxFault> {
        while self.consume_if_punctuation(Punctuation::PathSeparator)? {
            self.expect_identifier()?;
        }
        if self.consume_if_punctuation(Punctuation::LeftParenthesis)? {
            self.tasks
                .push(Task::ExpectPunctuation(Punctuation::RightParenthesis));
            self.tasks.push(Task::Pattern);
        }
        Ok(())
    }

    fn parse_pattern_list(&mut self, count: usize) -> Result<(), SyntaxFault> {
        if self.at_punctuation(Punctuation::RightParenthesis) {
            if count < 2 {
                return Err(self.expected("at least two tuple patterns"));
            }
            self.consume_current()?;
            return Ok(());
        }
        if count > 0 {
            self.expect_punctuation(Punctuation::Comma)?;
            if self.at_punctuation(Punctuation::RightParenthesis) {
                if count < 2 {
                    return Err(self.expected("second tuple pattern"));
                }
                self.consume_current()?;
                return Ok(());
            }
        }
        self.tasks.push(Task::PatternList {
            count: count.saturating_add(1),
        });
        self.tasks.push(Task::Pattern);
        Ok(())
    }

    fn parse_match_arms(&mut self, statement: bool, count: usize) -> Result<(), SyntaxFault> {
        if self.at_punctuation(Punctuation::RightBrace) {
            return if count == 0 {
                Err(self.expected("match arm"))
            } else {
                Ok(())
            };
        }
        if count > 0 {
            self.expect_punctuation(Punctuation::Comma)?;
            if self.at_punctuation(Punctuation::RightBrace) {
                return Ok(());
            }
        }
        self.begin(SyntaxForm::MatchArm);
        self.tasks.push(Task::MatchArms {
            statement,
            count: count.saturating_add(1),
        });
        self.tasks.push(Task::Finish);
        self.tasks.push(Task::MatchArmBody { statement });
        self.tasks
            .push(Task::ExpectPunctuation(Punctuation::FatArrow));
        self.tasks.push(Task::Pattern);
        Ok(())
    }

    fn parse_match_arm_body(&mut self, statement: bool) -> Result<(), SyntaxFault> {
        if statement {
            self.tasks.push(Task::Block(BlockKind::Statement));
        } else if self.at_punctuation(Punctuation::LeftBrace) {
            self.tasks.push(Task::Block(BlockKind::Value));
        } else {
            self.tasks.push(Task::Expression {
                minimum_precedence: 0,
                mode: ExpressionMode::Ordinary,
                control_boundary: false,
            });
        }
        Ok(())
    }

    fn parse_if_tail(&mut self) -> Result<(), SyntaxFault> {
        if !self.at_word("else") {
            return Ok(());
        }
        self.consume_current()?;
        if self.at_word("if") {
            self.consume_current()?;
            self.tasks.push(Task::IfTail);
            self.tasks.push(Task::Block(BlockKind::Statement));
            self.push_condition();
        } else {
            self.tasks.push(Task::Block(BlockKind::Statement));
        }
        Ok(())
    }

    fn parse_parenthesized_tail(&mut self, mode: ExpressionMode) -> Result<(), SyntaxFault> {
        if self.consume_if_punctuation(Punctuation::Comma)? {
            self.wrap_last_child(SyntaxForm::TupleExpression)?;
            self.tasks.push(Task::ExpressionList {
                closing: Punctuation::RightParenthesis,
                mode,
                count: 0,
                minimum: 1,
            });
        } else {
            self.expect_punctuation(Punctuation::RightParenthesis)?;
        }
        Ok(())
    }

    fn parse_expression_list(
        &mut self,
        closing: Punctuation,
        mode: ExpressionMode,
        count: usize,
        minimum: usize,
    ) -> Result<(), SyntaxFault> {
        if self.at_punctuation(closing) {
            if count < minimum {
                return Err(self.expected("additional expression"));
            }
            self.consume_current()?;
            return Ok(());
        }
        if count > 0 {
            self.expect_punctuation(Punctuation::Comma)?;
            if self.at_punctuation(closing) {
                self.consume_current()?;
                return Ok(());
            }
        }
        self.tasks.push(Task::ExpressionList {
            closing,
            mode,
            count: count.saturating_add(1),
            minimum,
        });
        self.tasks.push(Task::Expression {
            minimum_precedence: 0,
            mode,
            control_boundary: false,
        });
        Ok(())
    }

    fn parse_identifier_list(
        &mut self,
        closing: Punctuation,
        count: usize,
        minimum: usize,
    ) -> Result<(), SyntaxFault> {
        if self.at_punctuation(closing) {
            if count < minimum {
                return Err(self.expected("identifier"));
            }
            self.consume_current()?;
            return Ok(());
        }
        if count > 0 {
            self.expect_punctuation(Punctuation::Comma)?;
            if self.at_punctuation(closing) {
                self.consume_current()?;
                return Ok(());
            }
        }
        self.expect_identifier()?;
        self.tasks.push(Task::IdentifierList {
            closing,
            count: count.saturating_add(1),
            minimum,
        });
        Ok(())
    }

    fn parse_struct_fields(
        &mut self,
        mode: ExpressionMode,
        count: usize,
    ) -> Result<(), SyntaxFault> {
        if self.at_punctuation(Punctuation::RightBrace) {
            self.consume_current()?;
            return Ok(());
        }
        if count > 0 {
            self.expect_punctuation(Punctuation::Comma)?;
            if self.at_punctuation(Punctuation::RightBrace) {
                self.consume_current()?;
                return Ok(());
            }
        }
        self.begin(SyntaxForm::FieldInitializer);
        self.expect_identifier()?;
        self.tasks.push(Task::StructFields {
            mode,
            count: count.saturating_add(1),
        });
        self.tasks.push(Task::Finish);
        if self.consume_if_punctuation(Punctuation::Colon)? {
            self.tasks.push(Task::Expression {
                minimum_precedence: 0,
                mode,
                control_boundary: false,
            });
        }
        Ok(())
    }

    fn wrap_last_child(&mut self, form: SyntaxForm) -> Result<(), SyntaxFault> {
        let Some(parent) = self.open.last_mut() else {
            return Err(self.invariant_fault());
        };
        let Some(child) = parent.children.pop() else {
            return Err(SyntaxFault {
                expected: "completed child expression",
                span: self.current().span().clone(),
                encountered: token_description(self.current().kind()),
            });
        };
        let span = self
            .nodes
            .get(child.index())
            .ok_or_else(|| self.invariant_fault())?
            .span()
            .clone();
        let id = NodeId(self.nodes.len());
        self.nodes.push(SyntaxNode::new(form, span, vec![child]));
        let Some(parent) = self.open.last_mut() else {
            return Err(self.invariant_fault());
        };
        parent.children.push(id);
        Ok(())
    }

    fn starts_statement(&mut self) -> bool {
        [
            "let", "discard", "return", "break", "continue", "spawn", "detach", "if", "loop",
            "while", "until", "for",
        ]
        .iter()
        .any(|word| self.at_word(word))
            || self.looks_like_assignment()
            || ((self.at_word("with") || self.at_word("session") || self.at_word("match"))
                && self.ambiguous_statement_parses())
    }

    fn looks_like_assignment(&self) -> bool {
        let mut cursor = self.position;
        if token_at_word(&self.tokens, cursor, "self") {
            cursor = cursor.saturating_add(1);
            if !token_at_punctuation(&self.tokens, cursor, Punctuation::Dot) {
                return false;
            }
            cursor = cursor.saturating_add(1);
        }
        if !matches!(
            self.tokens.get(cursor).map(Token::kind),
            Some(TokenKind::Identifier(_))
        ) {
            return false;
        }
        cursor = cursor.saturating_add(1);
        while token_at_punctuation(&self.tokens, cursor, Punctuation::Dot)
            && matches!(
                self.tokens.get(cursor.saturating_add(1)).map(Token::kind),
                Some(TokenKind::Identifier(_))
            )
        {
            cursor = cursor.saturating_add(2);
        }
        self.tokens
            .get(cursor)
            .is_some_and(|token| is_assignment_operator(token.kind()))
    }

    fn ambiguous_statement_parses(&mut self) -> bool {
        let position = self.position;
        let nodes_len = self.nodes.len();
        let open = self.open.clone();
        let tasks = std::mem::take(&mut self.tasks);
        let result = self.parse_statement().and_then(|()| self.run_tasks());
        self.position = position;
        self.nodes.truncate(nodes_len);
        self.open = open;
        self.tasks = tasks;
        result.is_ok()
    }

    fn at_assignment_operator(&self) -> bool {
        is_assignment_operator(self.current().kind())
    }

    fn push_condition(&mut self) {
        if self.at_word("let") {
            self.tasks.push(Task::Expression {
                minimum_precedence: 0,
                mode: ExpressionMode::Ordinary,
                control_boundary: true,
            });
            self.tasks.push(Task::ExpectPunctuation(Punctuation::Equal));
            self.tasks.push(Task::Pattern);
            self.tasks.push(Task::ExpectWord("let"));
        } else {
            self.tasks.push(Task::Expression {
                minimum_precedence: 0,
                mode: ExpressionMode::Ordinary,
                control_boundary: true,
            });
        }
    }

    fn push_loop_modifiers(&mut self) -> Result<(), SyntaxFault> {
        if !self.consume_if_punctuation(Punctuation::LeftParenthesis)? {
            return Ok(());
        }
        self.begin(SyntaxForm::ModifierList);
        let mut count = 0_usize;
        while !self.at_punctuation(Punctuation::RightParenthesis) {
            if count > 0 {
                self.expect_punctuation(Punctuation::Comma)?;
                if self.at_punctuation(Punctuation::RightParenthesis) {
                    break;
                }
            }
            self.begin(SyntaxForm::Modifier);
            if self.at_word("session") {
                self.consume_current()?;
                self.expect_punctuation(Punctuation::Equal)?;
                self.expect_session_directive()?;
            } else if self.at_word("limit") {
                self.consume_current()?;
                self.expect_punctuation(Punctuation::Equal)?;
                if self.at_word("unbounded") || self.at_integer() {
                    self.consume_current()?;
                } else {
                    return Err(self.expected("loop limit"));
                }
            } else {
                return Err(self.expected("loop modifier"));
            }
            self.finish().map_err(|_| self.invariant_fault())?;
            count = count.saturating_add(1);
        }
        if count == 0 {
            return Err(self.expected("loop modifier"));
        }
        self.expect_punctuation(Punctuation::RightParenthesis)?;
        self.finish().map_err(|_| self.invariant_fault())?;
        Ok(())
    }

    fn expect_session_directive(&mut self) -> Result<(), SyntaxFault> {
        if self.at_word("inline") || self.at_word("fork") || self.at_word("new") {
            self.consume_current()
        } else {
            Err(self.expected("session directive"))
        }
    }
}

#[derive(Clone, Debug)]
struct SyntaxFault {
    expected: &'static str,
    span: SourceSpan,
    encountered: Arc<str>,
}

fn token_is_word(token: &Token, word: &str) -> bool {
    matches!(token.kind(), TokenKind::ReservedWord(value) if value.spelling() == word)
}

fn token_is_punctuation(token: &Token, punctuation: Punctuation) -> bool {
    matches!(token.kind(), TokenKind::Punctuation(value) if *value == punctuation)
}

fn token_at_word(tokens: &[Token], index: usize, word: &str) -> bool {
    tokens
        .get(index)
        .is_some_and(|token| token_is_word(token, word))
}

fn token_at_punctuation(tokens: &[Token], index: usize, punctuation: Punctuation) -> bool {
    tokens
        .get(index)
        .is_some_and(|token| token_is_punctuation(token, punctuation))
}

fn is_assignment_operator(kind: &TokenKind) -> bool {
    matches!(
        kind,
        TokenKind::Punctuation(
            Punctuation::Equal
                | Punctuation::PlusEqual
                | Punctuation::MinusEqual
                | Punctuation::StarEqual
                | Punctuation::SlashEqual
                | Punctuation::PercentEqual
        )
    )
}

fn token_description(kind: &TokenKind) -> Arc<str> {
    Arc::from(match kind {
        TokenKind::Identifier(_) => "identifier",
        TokenKind::ReservedWord(word) => word.spelling(),
        TokenKind::IntegerLiteral(_) => "integer literal",
        TokenKind::DirectiveInteger(_) => "directive integer",
        TokenKind::FloatLiteral(_) => "float literal",
        TokenKind::StringLiteral(_) => "string literal",
        TokenKind::RawStringLiteral(_) => "raw string literal",
        TokenKind::PromptTemplate(_) => "prompt template",
        TokenKind::Punctuation(punctuation) => punctuation.spelling(),
        TokenKind::EndOfFile => "end of file",
    })
}

#[cfg(test)]
mod tests {
    use gantry_core::portable::FrontendResourceCode;
    use gantry_core::source::{SourceLimits, SourceSnapshotBuilder};

    use super::{ParseError, Parser};
    use crate::SyntaxForm;

    fn parse_result(
        source: &str,
        token_limit: u64,
        diagnostic_limit: u64,
    ) -> Result<super::ParseOutcome, ParseError> {
        let limits = SourceLimits::new(1, 2_000_000, 2_000_000, token_limit, diagnostic_limit)
            .unwrap_or_else(|_| unreachable!("positive limits"));
        let mut builder = SourceSnapshotBuilder::new(limits);
        assert!(builder.add_file("main.gnt", source.as_bytes()).is_ok());
        let mut snapshot = builder.finish();
        let (records, counters) = snapshot.records_and_counters_mut();
        let record = records
            .first()
            .unwrap_or_else(|| unreachable!("one source"));
        Parser::new(record, counters).parse_module()
    }

    fn parse(source: &str, token_limit: u64, diagnostic_limit: u64) -> super::ParseOutcome {
        parse_result(source, token_limit, diagnostic_limit)
            .unwrap_or_else(|error| panic!("syntax phase failed: {error}"))
    }

    #[test]
    fn parses_authored_order_declarations_operations_and_control_flow() {
        let source = r#"
agents { worker, reviewer }
default agent = worker;
struct Request { topic: String, dry_run: Bool = false }
enum Outcome { Ready(String), Cancelled }
action read_only lookup(topic: String) -> String;
fn main(request: Request) -> String {
    let result: String = prompt(session = new, retry_limit = 2)
        "Find ${request.topic}." using { request } -> String;
    if request.dry_run {
        return result;
    } else {
        action(retry_limit = 1) lookup(result);
    }
}
"#;
        let outcome = parse(source, 512, 16);
        assert!(outcome.is_valid(), "{:?}", outcome.diagnostics());
        let tree = outcome.tree().unwrap_or_else(|| unreachable!("valid tree"));
        assert_eq!(
            tree.node(tree.root())
                .map(|node| node.span().bytes().start()),
            Some(1)
        );
        assert!(
            tree.nodes()
                .iter()
                .any(|node| matches!(node.form(), SyntaxForm::PromptExpression))
        );
        assert!(
            tree.nodes()
                .iter()
                .any(|node| matches!(node.form(), SyntaxForm::IfStatement))
        );
    }

    #[test]
    fn syntax_phase_preserves_semantically_invalid_declarations() {
        let outcome = parse(
            "struct Duplicate { value: Int, value: Int }\nfn main() { missing_name; }",
            128,
            8,
        );
        assert!(outcome.is_valid(), "{:?}", outcome.diagnostics());
    }

    #[test]
    fn reports_deterministic_source_backed_recovery_prefix() {
        let outcome = parse(
            "struct Broken { value Int; }\naction read_only missing( -> String;\nfn good() {}",
            128,
            8,
        );
        assert!(!outcome.is_valid());
        assert!(outcome.diagnostics().len() >= 2);
        assert!(outcome.diagnostics().iter().all(|diagnostic| {
            diagnostic.code.as_str() == "unexpected-token" && diagnostic.primary.is_some()
        }));
        assert!(
            outcome
                .diagnostics()
                .windows(2)
                .all(|pair| pair[0].primary <= pair[1].primary)
        );
    }

    #[test]
    fn diagnostic_exhaustion_returns_the_retained_prefix() {
        let result = parse_result(
            "struct Broken { value Int; }\naction read_only missing( -> String;\nfn good() {}",
            128,
            1,
        );
        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("the second diagnostic must exceed the activity limit"),
        };
        let ParseError::ResourceLimit { error, diagnostics } = error else {
            panic!("expected a diagnostic resource limit");
        };
        assert_eq!(error.code, FrontendResourceCode::DiagnosticCountLimit);
        assert_eq!(error.limit, 1);
        assert_eq!(error.observed, Some(2));
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].code.as_str(), "unexpected-token");
    }

    #[test]
    fn precedence_and_nonassociative_comparisons_follow_the_grammar() {
        let valid = parse("fn main() -> Int { 1 + 2 * 3 }", 64, 4);
        assert!(valid.is_valid(), "{:?}", valid.diagnostics());
        let binary_count = valid
            .tree()
            .unwrap_or_else(|| unreachable!("valid tree"))
            .nodes()
            .iter()
            .filter(|node| matches!(node.form(), SyntaxForm::BinaryExpression))
            .count();
        assert_eq!(binary_count, 2);

        let invalid = parse("fn main() -> Bool { 1 < 2 < 3 }", 64, 4);
        assert!(!invalid.is_valid());
        assert_eq!(invalid.diagnostics().len(), 1);
    }

    #[test]
    fn deeply_nested_types_and_grouping_use_explicit_work_stacks() {
        let depth = 4_000;
        let mut source = String::from("fn deep(value: ");
        source.push_str(&"Option<".repeat(depth));
        source.push_str("Int");
        source.push_str(&">".repeat(depth));
        source.push_str(") -> Int { ");
        source.push_str(&"(".repeat(depth));
        source.push('1');
        source.push_str(&")".repeat(depth));
        source.push_str(" }");
        let outcome = parse(&source, 30_000, 4);
        assert!(outcome.is_valid(), "{:?}", outcome.diagnostics());
    }

    #[test]
    fn tuple_types_defaults_and_complete_expression_boundaries_are_exact() {
        for source in [
            "struct Values { pair: Tuple<Int, String>, triple: Tuple<Int, String, Bool,>, negative: Int = -1 }",
            "fn main() -> Tuple<Int, Int> { (1, 2) }",
            "fn main() { for value in [1, 2] { discard value; } }",
        ] {
            let outcome = parse(source, 256, 8);
            assert!(outcome.is_valid(), "{source}: {:?}", outcome.diagnostics());
        }

        for source in [
            "struct Bad { value: Tuple<Int> }",
            "struct Bad { value: Int = -false }",
            "fn main() { discard attempt joinall(); }",
            "fn main() { for(limit = 1) value in [1] {} }",
        ] {
            let outcome = parse(source, 256, 8);
            assert!(!outcome.is_valid(), "unexpectedly accepted {source}");
        }
    }
}
