//! Arena-backed surface syntax preserving authored order and exact spans.
//!
//! Syntax ownership is deliberately nonrecursive: child relationships use
//! stable arena indices, so deeply nested admitted source cannot overflow the
//! native stack merely while dropping or moving its syntax tree.

use gantry_core::source::SourceSpan;

use crate::token::TokenKind;

/// Stable index of one node inside a [`SyntaxTree`].
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NodeId(pub(crate) usize);

impl NodeId {
    /// Constructs an identifier for an existing arena index.
    ///
    /// Callers must still resolve the result through [`SyntaxTree::node`]; an
    /// out-of-range index is not admitted by the tree.
    #[must_use]
    pub const fn from_index(index: usize) -> Self {
        Self(index)
    }

    /// Returns the zero-based arena index.
    #[must_use]
    pub const fn index(self) -> usize {
        self.0
    }
}

/// One authored-order, arena-backed package syntax tree.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyntaxTree {
    nodes: Vec<SyntaxNode>,
    root: NodeId,
}

impl SyntaxTree {
    /// Constructs a tree from a complete arena and its module root.
    pub(crate) fn new(nodes: Vec<SyntaxNode>, root: NodeId) -> Self {
        Self { nodes, root }
    }

    /// Returns the module root.
    #[must_use]
    pub const fn root(&self) -> NodeId {
        self.root
    }

    /// Returns all nodes in deterministic construction order.
    #[must_use]
    pub fn nodes(&self) -> &[SyntaxNode] {
        &self.nodes
    }

    /// Resolves one node index.
    #[must_use]
    pub fn node(&self, id: NodeId) -> Option<&SyntaxNode> {
        self.nodes.get(id.0)
    }
}

/// One syntax form or retained nontrivia token.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyntaxNode {
    form: SyntaxForm,
    span: SourceSpan,
    children: Vec<NodeId>,
}

impl SyntaxNode {
    /// Constructs one arena node.
    pub(crate) fn new(form: SyntaxForm, span: SourceSpan, children: Vec<NodeId>) -> Self {
        Self {
            form,
            span,
            children,
        }
    }

    /// Returns the grammar form or retained token.
    #[must_use]
    pub const fn form(&self) -> &SyntaxForm {
        &self.form
    }

    /// Returns the exact end-exclusive source span.
    #[must_use]
    pub const fn span(&self) -> &SourceSpan {
        &self.span
    }

    /// Returns child nodes in authored order.
    #[must_use]
    pub fn children(&self) -> &[NodeId] {
        &self.children
    }
}

/// Grammar classification retained by the surface syntax tree.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SyntaxForm {
    /// Complete source module.
    Module,
    /// `agents` declaration.
    AgentsDeclaration,
    /// `default agent` declaration.
    DefaultAgentDeclaration,
    /// File or inline `mod` declaration.
    ModuleDeclaration,
    /// `use` declaration.
    UseDeclaration,
    /// `struct` declaration.
    StructDeclaration,
    /// Struct field declaration.
    StructField,
    /// `enum` declaration.
    EnumDeclaration,
    /// Enum variant declaration.
    EnumVariant,
    /// `action` declaration.
    ActionDeclaration,
    /// Free workflow declaration.
    FunctionDeclaration,
    /// Inherent implementation declaration.
    ImplDeclaration,
    /// Inherent method declaration.
    MethodDeclaration,
    /// Parameter declaration.
    Parameter,
    /// Qualified source path.
    Path,
    /// Value type syntax.
    ValueType,
    /// Ordinary, value-producing, or statement-only block.
    Block,
    /// `let` statement.
    LetStatement,
    /// Assignment statement.
    AssignmentStatement,
    /// Bare expression statement.
    ExpressionStatement,
    /// `discard` statement.
    DiscardStatement,
    /// `return` statement.
    ReturnStatement,
    /// `break` statement.
    BreakStatement,
    /// `continue` statement.
    ContinueStatement,
    /// `spawn` statement.
    SpawnStatement,
    /// `detach` statement.
    DetachStatement,
    /// Statement-only `with` context.
    WithStatement,
    /// Statement-only `session` context.
    SessionStatement,
    /// `if` statement and its branches.
    IfStatement,
    /// Effect-only `match` statement.
    MatchStatement,
    /// `loop` statement.
    LoopStatement,
    /// `while` statement.
    WhileStatement,
    /// `until` statement.
    UntilStatement,
    /// `for` statement.
    ForStatement,
    /// Binding or match pattern.
    Pattern,
    /// Complete expression.
    Expression,
    /// Unary expression.
    UnaryExpression,
    /// Binary expression.
    BinaryExpression,
    /// Postfix field, call, or index expression.
    PostfixExpression,
    /// Struct constructor expression.
    StructExpression,
    /// Struct field initializer.
    FieldInitializer,
    /// List expression.
    ListExpression,
    /// Tuple expression.
    TupleExpression,
    /// Model `prompt` expression.
    PromptExpression,
    /// Model `decide` expression.
    DecideExpression,
    /// Harness `action` expression.
    ActionExpression,
    /// `attempt` expression.
    AttemptExpression,
    /// Value-producing `match` expression.
    MatchExpression,
    /// One match arm.
    MatchArm,
    /// Named `join` expression.
    JoinExpression,
    /// `joinall()` expression.
    JoinAllExpression,
    /// Value-producing `with` context.
    WithExpression,
    /// Value-producing `session` context.
    SessionExpression,
    /// Prompt, action, or loop modifier list.
    ModifierList,
    /// One modifier.
    Modifier,
    /// Prompt `using` input list.
    UsingClause,
    /// One prompt named input.
    NamedInput,
    /// One contextual interpolation expression.
    InterpolationExpression,
    /// Retained nontrivia lexical token.
    Token(TokenKind),
}
