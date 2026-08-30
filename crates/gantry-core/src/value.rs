//! Persistent logical values with representation-independent, depth-safe operations.
//!
//! Values are immutable logical trees. Private `Arc`-backed nodes may form a
//! directed acyclic graph through shared subvalues, but sharing is never part
//! of equality, hashing, canonical encoding, or the public API. Aggregate
//! construction and root replacement compute the complete logical JSON-tree
//! metrics before a value can be published.

use std::cmp::Ordering;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, RwLock};

use crate::canonical_json::CanonicalJson;
use crate::numeric::{GantryFloat, GantryInt};
use crate::schema::{SchemaError, SchemaValidator, ValidationError};
use crate::strict_json::{JsonError, JsonLimits, StrictJsonDocument};

/// The normative default limits for one admitted logical value.
pub const DEFAULT_VALUE_LIMITS: ValueLimits = ValueLimits {
    maximum_nesting_depth: 256,
    maximum_nodes: 1_048_576,
    maximum_string_scalars: 1_048_576,
    maximum_list_items: 65_536,
};

/// Finite positive limits for one logical value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValueLimits {
    maximum_nesting_depth: u64,
    maximum_nodes: u64,
    maximum_string_scalars: u64,
    maximum_list_items: u64,
}

impl ValueLimits {
    /// Constructs a limit set, rejecting zero because every configured value
    /// limit is required to be positive.
    #[must_use]
    pub const fn new(
        maximum_nesting_depth: u64,
        maximum_nodes: u64,
        maximum_string_scalars: u64,
        maximum_list_items: u64,
    ) -> Option<Self> {
        if maximum_nesting_depth == 0
            || maximum_nodes == 0
            || maximum_string_scalars == 0
            || maximum_list_items == 0
        {
            None
        } else {
            Some(Self {
                maximum_nesting_depth,
                maximum_nodes,
                maximum_string_scalars,
                maximum_list_items,
            })
        }
    }

    /// Returns the maximum JSON-tree depth, where the root has depth one.
    #[must_use]
    pub const fn maximum_nesting_depth(self) -> u64 {
        self.maximum_nesting_depth
    }

    /// Returns the maximum logical JSON value-node count.
    #[must_use]
    pub const fn maximum_nodes(self) -> u64 {
        self.maximum_nodes
    }

    /// Returns the maximum Unicode-scalar count of any logical String.
    #[must_use]
    pub const fn maximum_string_scalars(self) -> u64 {
        self.maximum_string_scalars
    }

    /// Returns the maximum item count of any logical List.
    #[must_use]
    pub const fn maximum_list_items(self) -> u64 {
        self.maximum_list_items
    }
}

/// Exact representation-independent metrics for one logical value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValueMetrics {
    /// Maximum JSON-tree depth, where the root has depth one.
    pub nesting_depth: u64,
    /// JSON value-node count, counting a shared subtree at every occurrence.
    pub nodes: u64,
    /// Largest Unicode-scalar count among logical String values.
    pub maximum_string_scalars: u64,
    /// Largest item count among logical List values.
    pub maximum_list_items: u64,
}

impl ValueMetrics {
    const SCALAR: Self = Self {
        nesting_depth: 1,
        nodes: 1,
        maximum_string_scalars: 0,
        maximum_list_items: 0,
    };
}

/// A portable per-value limit that rejected a complete candidate value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValueLimitKind {
    /// Logical JSON-tree nesting depth.
    NestingDepth,
    /// Logical JSON value-node count.
    Nodes,
    /// Unicode scalar values in one logical String.
    StringScalars,
    /// Members in one logical List.
    ListItems,
}

/// Failure while constructing, copying, or replacing a logical value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ValueError {
    /// One complete candidate exceeds an effective value limit.
    ResourceLimit {
        /// Counter that rejected the value.
        kind: ValueLimitKind,
        /// Effective configured maximum.
        limit: u64,
        /// Exact first rejected aggregate count when representable.
        observed: Option<u64>,
    },
    /// A tuple has fewer than two members.
    TupleArity,
    /// A declared type, field, or variant name is empty.
    EmptyName,
    /// A struct repeats one field name.
    DuplicateField(String),
    /// A sealed Decision rationale is empty.
    EmptyDecisionRationale,
    /// An OperationError message or operation identity is empty.
    EmptyOperationErrorText,
    /// A replacement path does not match the value at the reported segment.
    InvalidPath {
        /// Zero-based path-segment index.
        segment: usize,
    },
}

/// Failure while bridging a normalized logical value to schema validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ValueSchemaError {
    /// The canonical logical value could not be admitted under the supplied limits.
    Json(JsonError),
    /// The compiled generated schema could not be evaluated.
    Schema(SchemaError),
}

/// The source-visible kind of a logical value.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ValueKind {
    /// The sole `Unit` value.
    Unit,
    /// A Boolean.
    Bool,
    /// An exact Gantry integer.
    Int,
    /// A finite normalized binary64 value.
    Float,
    /// A Unicode scalar sequence.
    String,
    /// An ordered homogeneous list.
    List,
    /// An ordered fixed-arity tuple.
    Tuple,
    /// A declared named-field struct.
    Struct,
    /// A declared tagged enum.
    Enum,
    /// An absent or present option.
    Option,
    /// An `Ok` or `Err` result.
    Result,
    /// A sealed model Decision.
    Decision,
    /// A sealed OperationError.
    OperationError,
}

/// One component of an immutable root-replacement route.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ValuePathSegment {
    /// One List item.
    ListItem(usize),
    /// One Tuple member.
    TupleMember(usize),
    /// One named Struct field.
    StructField(String),
    /// The payload of a declared Enum variant.
    EnumPayload,
    /// The present member of an Option.
    OptionValue,
    /// The payload of a Result.
    ResultValue,
}

/// Complete sealed OperationError content.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OperationErrorValue {
    /// A hook declined with a bounded diagnostic.
    Declined(String),
    /// Structured output was exhausted without an accepted value.
    InvalidOutput,
    /// A provider failed with a bounded diagnostic.
    ProviderFailure(String),
    /// An operation timed out with a bounded diagnostic.
    Timeout(String),
    /// Policy denied an operation with a bounded diagnostic.
    PolicyDenied(String),
    /// Integration cancelled an operation with a bounded diagnostic.
    Cancelled(String),
    /// A non-idempotent action has an unknown outcome.
    UnknownOutcome {
        /// Stable logical operation identity.
        operation_id: String,
        /// Bounded diagnostic.
        message: String,
    },
}

/// Borrowed, representation-neutral content of a sealed OperationError.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationErrorView<'a> {
    /// A hook declined with a bounded diagnostic.
    Declined(&'a str),
    /// Structured output was exhausted without an accepted value.
    InvalidOutput,
    /// A provider failed with a bounded diagnostic.
    ProviderFailure(&'a str),
    /// An operation timed out with a bounded diagnostic.
    Timeout(&'a str),
    /// Policy denied an operation with a bounded diagnostic.
    PolicyDenied(&'a str),
    /// Integration cancelled an operation with a bounded diagnostic.
    Cancelled(&'a str),
    /// A non-idempotent action has an unknown outcome.
    UnknownOutcome {
        /// Stable logical operation identity.
        operation_id: &'a str,
        /// Bounded diagnostic.
        message: &'a str,
    },
}

/// Borrowed logical content without allocation identities or sharing details.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum LogicalValueView<'a> {
    /// The sole Unit value.
    Unit,
    /// A Boolean value.
    Bool(bool),
    /// An exact Gantry integer.
    Int(GantryInt),
    /// A finite normalized binary64 value.
    Float(GantryFloat),
    /// A Unicode scalar sequence.
    String(&'a str),
    /// An ordered homogeneous list with the reported item count.
    List(usize),
    /// An ordered fixed-arity tuple with the reported member count.
    Tuple(usize),
    /// A declared struct and its field count.
    Struct {
        /// Canonical declared type name.
        type_name: &'a str,
        /// Number of complete normalized fields.
        field_count: usize,
    },
    /// A declared enum variant.
    Enum {
        /// Canonical declared type name.
        type_name: &'a str,
        /// Selected variant name.
        variant: &'a str,
        /// Whether the selected variant carries a payload.
        has_payload: bool,
    },
    /// An Option value.
    Option {
        /// Whether the Option is `Some`.
        is_some: bool,
    },
    /// A Result value.
    Result {
        /// Whether the Result is `Ok` rather than `Err`.
        is_ok: bool,
    },
    /// A sealed model Decision.
    Decision {
        /// Boolean judgment.
        decision: bool,
        /// Nonempty rationale.
        rationale: &'a str,
    },
    /// A sealed OperationError.
    OperationError(OperationErrorView<'a>),
}

/// One finite persistent logical value.
///
/// Cloning creates an independent logical value while immutable backing may be
/// shared. The private representation has no public allocation identity.
pub struct LogicalValue {
    root: Option<Arc<ValueNode>>,
}

impl Clone for LogicalValue {
    fn clone(&self) -> Self {
        Self {
            root: Some(Arc::clone(self.node_arc())),
        }
    }
}

impl std::fmt::Debug for LogicalValue {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LogicalValue")
            .field("kind", &self.kind())
            .field("metrics", &self.metrics())
            .finish_non_exhaustive()
    }
}

impl Drop for LogicalValue {
    fn drop(&mut self) {
        if let Some(root) = self.root.take() {
            release_iteratively(root);
        }
    }
}

impl PartialEq for LogicalValue {
    fn eq(&self, other: &Self) -> bool {
        values_equal(self.node_arc(), other.node_arc())
    }
}

impl Eq for LogicalValue {}

impl Hash for LogicalValue {
    fn hash<H: Hasher>(&self, state: &mut H) {
        hash_value(self.node_arc(), state);
    }
}

impl LogicalValue {
    /// Constructs the sole Unit value.
    #[must_use]
    pub fn unit() -> Self {
        Self::new_node(NodeKind::Unit, ValueMetrics::SCALAR)
    }

    /// Constructs one Boolean value.
    #[must_use]
    pub fn boolean(value: bool) -> Self {
        Self::new_node(NodeKind::Bool(value), ValueMetrics::SCALAR)
    }

    /// Constructs one exact Gantry Int.
    #[must_use]
    pub fn integer(value: GantryInt) -> Self {
        Self::new_node(NodeKind::Int(value), ValueMetrics::SCALAR)
    }

    /// Constructs one finite normalized Gantry Float.
    #[must_use]
    pub fn float(value: GantryFloat) -> Self {
        Self::new_node(NodeKind::Float(value), ValueMetrics::SCALAR)
    }

    /// Constructs one bounded String.
    pub fn string(value: impl Into<String>, limits: ValueLimits) -> Result<Self, ValueError> {
        let value = value.into();
        let scalar_count = u64::try_from(value.chars().count()).ok();
        let metrics = ValueMetrics {
            maximum_string_scalars: scalar_count.unwrap_or(u64::MAX),
            ..ValueMetrics::SCALAR
        };
        validate_metrics(metrics, limits)?;
        Ok(Self::new_node(NodeKind::String(Arc::from(value)), metrics))
    }

    /// Constructs one bounded ordered List.
    pub fn list(values: Vec<Self>, limits: ValueLimits) -> Result<Self, ValueError> {
        let item_count = u64::try_from(values.len()).ok();
        let metrics = aggregate_metrics(values.iter(), 1, 1, 0, item_count.unwrap_or(u64::MAX));
        validate_metrics(metrics, limits)?;
        Ok(Self::new_node(NodeKind::List(take_roots(values)), metrics))
    }

    /// Constructs one fixed-arity Tuple.
    pub fn tuple(values: Vec<Self>, limits: ValueLimits) -> Result<Self, ValueError> {
        if values.len() < 2 {
            return Err(ValueError::TupleArity);
        }
        let metrics = aggregate_metrics(values.iter(), 1, 1, 0, 0);
        validate_metrics(metrics, limits)?;
        Ok(Self::new_node(NodeKind::Tuple(take_roots(values)), metrics))
    }

    /// Constructs one complete declared Struct in declaration-field order.
    pub fn structure(
        type_name: impl Into<String>,
        fields: Vec<(String, Self)>,
        limits: ValueLimits,
    ) -> Result<Self, ValueError> {
        let type_name = nonempty_name(type_name.into())?;
        let mut names = fields.iter().map(|(name, _)| name).collect::<Vec<_>>();
        if names.iter().any(|name| name.is_empty()) {
            return Err(ValueError::EmptyName);
        }
        names.sort_unstable();
        if let Some(pair) = names.windows(2).find(|pair| pair[0] == pair[1]) {
            return Err(ValueError::DuplicateField(pair[0].clone()));
        }
        let metrics = aggregate_metrics(fields.iter().map(|(_, value)| value), 1, 1, 0, 0);
        validate_metrics(metrics, limits)?;
        let fields = fields
            .into_iter()
            .map(|(name, mut value)| (Arc::from(name), value.take_root()))
            .collect();
        Ok(Self::new_node(
            NodeKind::Struct {
                type_name: Arc::from(type_name),
                fields,
            },
            metrics,
        ))
    }

    /// Constructs one declared Enum value.
    pub fn enumeration(
        type_name: impl Into<String>,
        variant: impl Into<String>,
        payload: Option<Self>,
        limits: ValueLimits,
    ) -> Result<Self, ValueError> {
        let type_name = nonempty_name(type_name.into())?;
        let variant = nonempty_name(variant.into())?;
        let variant_scalars = u64::try_from(variant.chars().count()).unwrap_or(u64::MAX);
        let metrics = tagged_metrics(payload.as_ref(), variant_scalars);
        validate_metrics(metrics, limits)?;
        Ok(Self::new_node(
            NodeKind::Enum {
                type_name: Arc::from(type_name),
                variant: Arc::from(variant),
                payload: payload.map(|mut value| value.take_root()),
            },
            metrics,
        ))
    }

    /// Constructs the absent `None` value.
    #[must_use]
    pub fn none() -> Self {
        Self::new_node(NodeKind::Option(None), ValueMetrics::SCALAR)
    }

    /// Constructs a present Option without adding a JSON-tree wrapper.
    pub fn some(mut value: Self, limits: ValueLimits) -> Result<Self, ValueError> {
        validate_metrics(value.metrics(), limits)?;
        let metrics = value.metrics();
        Ok(Self::new_node(
            NodeKind::Option(Some(value.take_root())),
            metrics,
        ))
    }

    /// Constructs an `Ok` Result payload.
    pub fn ok(mut value: Self, limits: ValueLimits) -> Result<Self, ValueError> {
        let metrics = tagged_metrics(Some(&value), 2);
        validate_metrics(metrics, limits)?;
        Ok(Self::new_node(
            NodeKind::Result {
                is_ok: true,
                value: value.take_root(),
            },
            metrics,
        ))
    }

    /// Constructs an `Err` Result payload.
    pub fn err(mut value: Self, limits: ValueLimits) -> Result<Self, ValueError> {
        let metrics = tagged_metrics(Some(&value), 3);
        validate_metrics(metrics, limits)?;
        Ok(Self::new_node(
            NodeKind::Result {
                is_ok: false,
                value: value.take_root(),
            },
            metrics,
        ))
    }

    /// Constructs a sealed Decision with a nonempty bounded rationale.
    pub fn decision(
        decision: bool,
        rationale: impl Into<String>,
        limits: ValueLimits,
    ) -> Result<Self, ValueError> {
        let rationale = rationale.into();
        if rationale.is_empty() {
            return Err(ValueError::EmptyDecisionRationale);
        }
        let rationale_scalars = u64::try_from(rationale.chars().count()).unwrap_or(u64::MAX);
        let metrics = ValueMetrics {
            nesting_depth: 2,
            nodes: 3,
            maximum_string_scalars: rationale_scalars,
            maximum_list_items: 0,
        };
        validate_metrics(metrics, limits)?;
        Ok(Self::new_node(
            NodeKind::Decision {
                decision,
                rationale: Arc::from(rationale),
            },
            metrics,
        ))
    }

    /// Constructs one sealed OperationError value.
    pub fn operation_error(
        error: OperationErrorValue,
        limits: ValueLimits,
    ) -> Result<Self, ValueError> {
        let (node, metrics) = operation_error_node(error)?;
        validate_metrics(metrics, limits)?;
        Ok(Self::new_node(node, metrics))
    }

    /// Returns the source-visible value kind.
    #[must_use]
    pub fn kind(&self) -> ValueKind {
        self.node_arc().kind.value_kind()
    }

    /// Returns borrowed logical content without exposing physical node identity.
    #[must_use]
    pub fn view(&self) -> LogicalValueView<'_> {
        match &self.node_arc().kind {
            NodeKind::Unit => LogicalValueView::Unit,
            NodeKind::Bool(value) => LogicalValueView::Bool(*value),
            NodeKind::Int(value) => LogicalValueView::Int(*value),
            NodeKind::Float(value) => LogicalValueView::Float(*value),
            NodeKind::String(value) => LogicalValueView::String(value),
            NodeKind::List(values) => LogicalValueView::List(values.len()),
            NodeKind::Tuple(values) => LogicalValueView::Tuple(values.len()),
            NodeKind::Struct { type_name, fields } => LogicalValueView::Struct {
                type_name,
                field_count: fields.len(),
            },
            NodeKind::Enum {
                type_name,
                variant,
                payload,
            } => LogicalValueView::Enum {
                type_name,
                variant,
                has_payload: payload.is_some(),
            },
            NodeKind::Option(value) => LogicalValueView::Option {
                is_some: value.is_some(),
            },
            NodeKind::Result { is_ok, .. } => LogicalValueView::Result { is_ok: *is_ok },
            NodeKind::Decision {
                decision,
                rationale,
            } => LogicalValueView::Decision {
                decision: *decision,
                rationale,
            },
            NodeKind::OperationError(value) => LogicalValueView::OperationError(value.view()),
        }
    }

    /// Returns exact logical metrics independent of physical sharing.
    #[must_use]
    pub fn metrics(&self) -> ValueMetrics {
        self.node_arc().metrics
    }

    /// Validates this complete logical value against another effective limit set.
    pub fn validate(&self, limits: ValueLimits) -> Result<(), ValueError> {
        validate_metrics(self.metrics(), limits)
    }

    /// Returns a String value's scalar sequence.
    #[must_use]
    pub fn as_string(&self) -> Option<&str> {
        match &self.node_arc().kind {
            NodeKind::String(value) => Some(value),
            _ => None,
        }
    }

    /// Returns the number of direct aggregate members, when applicable.
    #[must_use]
    pub fn aggregate_len(&self) -> Option<usize> {
        match &self.node_arc().kind {
            NodeKind::List(values) | NodeKind::Tuple(values) => Some(values.len()),
            NodeKind::Struct { fields, .. } => Some(fields.len()),
            _ => None,
        }
    }

    /// Returns one List or Tuple member as an independent logical copy.
    #[must_use]
    pub fn member(&self, index: usize) -> Option<Self> {
        let values = match &self.node_arc().kind {
            NodeKind::List(values) | NodeKind::Tuple(values) => values,
            _ => return None,
        };
        values
            .get(index)
            .map(|value| Self::from_arc(Arc::clone(value)))
    }

    /// Returns one Struct field as an independent logical copy.
    #[must_use]
    pub fn field(&self, name: &str) -> Option<Self> {
        let NodeKind::Struct { fields, .. } = &self.node_arc().kind else {
            return None;
        };
        fields
            .iter()
            .find(|(candidate, _)| candidate.as_ref() == name)
            .map(|(_, value)| Self::from_arc(Arc::clone(value)))
    }

    /// Returns an Enum payload, present Option member, or Result payload.
    #[must_use]
    pub fn payload(&self) -> Option<Self> {
        let value = match &self.node_arc().kind {
            NodeKind::Enum {
                payload: Some(value),
                ..
            }
            | NodeKind::Option(Some(value))
            | NodeKind::Result { value, .. } => value,
            _ => return None,
        };
        Some(Self::from_arc(Arc::clone(value)))
    }

    /// Creates a physically detached aggregate tree with the same logical value.
    ///
    /// The traversal is iterative and counts shared subvalues at every logical
    /// occurrence. Immutable String storage may remain shared.
    pub fn detached_copy(&self, limits: ValueLimits) -> Result<Self, ValueError> {
        self.validate(limits)?;
        let mut work = vec![CopyTask::Visit(self.node_arc())];
        let mut results = Vec::<Arc<ValueNode>>::new();
        while let Some(task) = work.pop() {
            match task {
                CopyTask::Visit(node) => {
                    let (header, children) = CopyHeader::from_node(node);
                    work.push(CopyTask::Build(header));
                    for child in children.into_iter().rev() {
                        work.push(CopyTask::Visit(child));
                    }
                }
                CopyTask::Build(header) => {
                    let child_count = header.child_count();
                    let start = results
                        .len()
                        .checked_sub(child_count)
                        .unwrap_or_else(|| unreachable!("copy traversal retains child results"));
                    let children = results.split_off(start);
                    results.push(Arc::new(header.build(children)));
                }
            }
        }
        let root = results
            .pop()
            .unwrap_or_else(|| unreachable!("one root copy is produced"));
        Ok(Self::from_arc(root))
    }

    /// Returns RFC 8785 bytes and SHA-256 for this normalized logical value.
    #[must_use]
    pub fn canonical_json(&self) -> CanonicalJson {
        CanonicalJson::from_encoded_bytes(encode_canonical(self))
    }

    /// Validates this normalized value with the generated-schema kernel.
    ///
    /// Canonical encoding, strict admission, and schema traversal are all
    /// iterative. The supplied JSON limits are checked before validation.
    pub fn validate_schema(
        &self,
        validator: &SchemaValidator,
        limits: JsonLimits,
    ) -> Result<Vec<ValidationError>, ValueSchemaError> {
        let canonical = self.canonical_json();
        let document = StrictJsonDocument::decode(canonical.bytes(), limits)
            .map_err(ValueSchemaError::Json)?;
        validator
            .validate(&document)
            .map_err(ValueSchemaError::Schema)
    }

    /// Path-copies one route and validates the complete replacement before return.
    pub fn replaced(
        &self,
        path: &[ValuePathSegment],
        replacement: &Self,
        limits: ValueLimits,
    ) -> Result<Self, ValueError> {
        replacement.validate(limits)?;
        if path.is_empty() {
            return Ok(replacement.clone());
        }

        let mut current = self.node_arc().as_ref();
        let mut ancestors = Vec::<(&ValueNode, &ValuePathSegment)>::with_capacity(path.len());
        for (index, segment) in path.iter().enumerate() {
            let Some(child) = child_for_segment(current, segment) else {
                return Err(ValueError::InvalidPath { segment: index });
            };
            ancestors.push((current, segment));
            current = child;
        }

        let mut candidate = Arc::clone(replacement.node_arc());
        for (parent, segment) in ancestors.into_iter().rev() {
            candidate = Arc::new(parent.replacing_known_child(segment, candidate));
        }
        let candidate = Self::from_arc(candidate);
        candidate.validate(limits)?;
        Ok(candidate)
    }

    fn new_node(kind: NodeKind, metrics: ValueMetrics) -> Self {
        Self::from_arc(Arc::new(ValueNode { kind, metrics }))
    }

    fn from_arc(root: Arc<ValueNode>) -> Self {
        Self { root: Some(root) }
    }

    fn node_arc(&self) -> &Arc<ValueNode> {
        self.root
            .as_ref()
            .unwrap_or_else(|| unreachable!("a live logical value retains one root"))
    }

    fn take_root(&mut self) -> Arc<ValueNode> {
        self.root
            .take()
            .unwrap_or_else(|| unreachable!("a live logical value retains one root"))
    }
}

/// A thread-safe mutable binding root with atomic replacement publication.
#[derive(Debug)]
pub struct ValueRoot {
    value: RwLock<LogicalValue>,
}

impl ValueRoot {
    /// Creates one root after validating its initial complete value.
    pub fn new(value: LogicalValue, limits: ValueLimits) -> Result<Self, ValueError> {
        value.validate(limits)?;
        Ok(Self {
            value: RwLock::new(value),
        })
    }

    /// Returns an independent logical snapshot of the current root.
    #[must_use]
    pub fn snapshot(&self) -> LogicalValue {
        self.value
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Builds and validates a path-copied candidate before one atomic publish.
    ///
    /// A failure leaves the previous root unchanged and observable.
    pub fn replace(
        &self,
        path: &[ValuePathSegment],
        replacement: &LogicalValue,
        limits: ValueLimits,
    ) -> Result<LogicalValue, ValueError> {
        let mut root = self
            .value
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let candidate = root.replaced(path, replacement, limits)?;
        *root = candidate.clone();
        Ok(candidate)
    }
}

struct ValueNode {
    kind: NodeKind,
    metrics: ValueMetrics,
}

enum NodeKind {
    Unit,
    Bool(bool),
    Int(GantryInt),
    Float(GantryFloat),
    String(Arc<str>),
    List(Vec<Arc<ValueNode>>),
    Tuple(Vec<Arc<ValueNode>>),
    Struct {
        type_name: Arc<str>,
        fields: Vec<(Arc<str>, Arc<ValueNode>)>,
    },
    Enum {
        type_name: Arc<str>,
        variant: Arc<str>,
        payload: Option<Arc<ValueNode>>,
    },
    Option(Option<Arc<ValueNode>>),
    Result {
        is_ok: bool,
        value: Arc<ValueNode>,
    },
    Decision {
        decision: bool,
        rationale: Arc<str>,
    },
    OperationError(OperationErrorNode),
}

enum OperationErrorNode {
    Declined(Arc<str>),
    InvalidOutput,
    ProviderFailure(Arc<str>),
    Timeout(Arc<str>),
    PolicyDenied(Arc<str>),
    Cancelled(Arc<str>),
    UnknownOutcome {
        operation_id: Arc<str>,
        message: Arc<str>,
    },
}

impl OperationErrorNode {
    fn view(&self) -> OperationErrorView<'_> {
        match self {
            Self::Declined(message) => OperationErrorView::Declined(message),
            Self::InvalidOutput => OperationErrorView::InvalidOutput,
            Self::ProviderFailure(message) => OperationErrorView::ProviderFailure(message),
            Self::Timeout(message) => OperationErrorView::Timeout(message),
            Self::PolicyDenied(message) => OperationErrorView::PolicyDenied(message),
            Self::Cancelled(message) => OperationErrorView::Cancelled(message),
            Self::UnknownOutcome {
                operation_id,
                message,
            } => OperationErrorView::UnknownOutcome {
                operation_id,
                message,
            },
        }
    }
}

impl NodeKind {
    fn value_kind(&self) -> ValueKind {
        match self {
            Self::Unit => ValueKind::Unit,
            Self::Bool(_) => ValueKind::Bool,
            Self::Int(_) => ValueKind::Int,
            Self::Float(_) => ValueKind::Float,
            Self::String(_) => ValueKind::String,
            Self::List(_) => ValueKind::List,
            Self::Tuple(_) => ValueKind::Tuple,
            Self::Struct { .. } => ValueKind::Struct,
            Self::Enum { .. } => ValueKind::Enum,
            Self::Option(_) => ValueKind::Option,
            Self::Result { .. } => ValueKind::Result,
            Self::Decision { .. } => ValueKind::Decision,
            Self::OperationError(_) => ValueKind::OperationError,
        }
    }
}

impl ValueNode {
    fn replacing_known_child(
        &self,
        segment: &ValuePathSegment,
        replacement: Arc<ValueNode>,
    ) -> Self {
        let kind = match (&self.kind, segment) {
            (NodeKind::List(values), ValuePathSegment::ListItem(index)) => {
                let mut values = values.clone();
                values[*index] = replacement;
                NodeKind::List(values)
            }
            (NodeKind::Tuple(values), ValuePathSegment::TupleMember(index)) => {
                let mut values = values.clone();
                values[*index] = replacement;
                NodeKind::Tuple(values)
            }
            (NodeKind::Struct { type_name, fields }, ValuePathSegment::StructField(name)) => {
                let mut fields = fields.clone();
                let (_, value) = fields
                    .iter_mut()
                    .find(|(candidate, _)| candidate.as_ref() == name)
                    .unwrap_or_else(|| unreachable!("replacement path was prevalidated"));
                *value = replacement;
                NodeKind::Struct {
                    type_name: Arc::clone(type_name),
                    fields,
                }
            }
            (
                NodeKind::Enum {
                    type_name,
                    variant,
                    payload: Some(_),
                },
                ValuePathSegment::EnumPayload,
            ) => NodeKind::Enum {
                type_name: Arc::clone(type_name),
                variant: Arc::clone(variant),
                payload: Some(replacement),
            },
            (NodeKind::Option(Some(_)), ValuePathSegment::OptionValue) => {
                NodeKind::Option(Some(replacement))
            }
            (NodeKind::Result { is_ok, .. }, ValuePathSegment::ResultValue) => NodeKind::Result {
                is_ok: *is_ok,
                value: replacement,
            },
            _ => unreachable!("replacement path was prevalidated"),
        };
        let metrics = metrics_for_kind(&kind);
        Self { kind, metrics }
    }

    fn into_children(self) -> Vec<Arc<ValueNode>> {
        match self.kind {
            NodeKind::List(values) | NodeKind::Tuple(values) => values,
            NodeKind::Struct { fields, .. } => fields.into_iter().map(|(_, value)| value).collect(),
            NodeKind::Enum { payload, .. } | NodeKind::Option(payload) => {
                payload.into_iter().collect()
            }
            NodeKind::Result { value, .. } => vec![value],
            NodeKind::Unit
            | NodeKind::Bool(_)
            | NodeKind::Int(_)
            | NodeKind::Float(_)
            | NodeKind::String(_)
            | NodeKind::Decision { .. }
            | NodeKind::OperationError(_) => Vec::new(),
        }
    }
}

fn nonempty_name(value: String) -> Result<String, ValueError> {
    if value.is_empty() {
        Err(ValueError::EmptyName)
    } else {
        Ok(value)
    }
}

fn take_roots(values: Vec<LogicalValue>) -> Vec<Arc<ValueNode>> {
    values
        .into_iter()
        .map(|mut value| value.take_root())
        .collect()
}

fn aggregate_metrics<'a>(
    children: impl IntoIterator<Item = &'a LogicalValue>,
    wrapper_depth: u64,
    own_nodes: u64,
    own_string_scalars: u64,
    own_list_items: u64,
) -> ValueMetrics {
    aggregate_node_metrics(
        children.into_iter().map(LogicalValue::metrics),
        wrapper_depth,
        own_nodes,
        own_string_scalars,
        own_list_items,
    )
}

fn aggregate_node_metrics(
    children: impl IntoIterator<Item = ValueMetrics>,
    wrapper_depth: u64,
    own_nodes: u64,
    own_string_scalars: u64,
    own_list_items: u64,
) -> ValueMetrics {
    let mut metrics = ValueMetrics {
        nesting_depth: wrapper_depth,
        nodes: own_nodes,
        maximum_string_scalars: own_string_scalars,
        maximum_list_items: own_list_items,
    };
    for child in children {
        metrics.nesting_depth = metrics
            .nesting_depth
            .max(child.nesting_depth.saturating_add(wrapper_depth));
        metrics.nodes = metrics.nodes.saturating_add(child.nodes);
        metrics.maximum_string_scalars = metrics
            .maximum_string_scalars
            .max(child.maximum_string_scalars);
        metrics.maximum_list_items = metrics.maximum_list_items.max(child.maximum_list_items);
    }
    metrics
}

fn tagged_metrics(payload: Option<&LogicalValue>, variant_scalars: u64) -> ValueMetrics {
    let mut metrics = aggregate_node_metrics(
        payload.into_iter().map(LogicalValue::metrics),
        1,
        2,
        variant_scalars,
        0,
    );
    metrics.nesting_depth = metrics.nesting_depth.max(2);
    metrics
}

fn metrics_for_kind(kind: &NodeKind) -> ValueMetrics {
    match kind {
        NodeKind::Unit | NodeKind::Bool(_) | NodeKind::Int(_) | NodeKind::Float(_) => {
            ValueMetrics::SCALAR
        }
        NodeKind::String(value) => ValueMetrics {
            maximum_string_scalars: u64::try_from(value.chars().count()).unwrap_or(u64::MAX),
            ..ValueMetrics::SCALAR
        },
        NodeKind::List(values) => aggregate_node_metrics(
            values.iter().map(|value| value.metrics),
            1,
            1,
            0,
            u64::try_from(values.len()).unwrap_or(u64::MAX),
        ),
        NodeKind::Tuple(values) => {
            aggregate_node_metrics(values.iter().map(|value| value.metrics), 1, 1, 0, 0)
        }
        NodeKind::Struct { fields, .. } => {
            aggregate_node_metrics(fields.iter().map(|(_, value)| value.metrics), 1, 1, 0, 0)
        }
        NodeKind::Enum {
            variant, payload, ..
        } => {
            let mut metrics = aggregate_node_metrics(
                payload.iter().map(|value| value.metrics),
                1,
                2,
                u64::try_from(variant.chars().count()).unwrap_or(u64::MAX),
                0,
            );
            metrics.nesting_depth = metrics.nesting_depth.max(2);
            metrics
        }
        NodeKind::Option(Some(value)) => value.metrics,
        NodeKind::Option(None) => ValueMetrics::SCALAR,
        NodeKind::Result { is_ok, value } => {
            aggregate_node_metrics([value.metrics], 1, 2, if *is_ok { 2 } else { 3 }, 0)
        }
        NodeKind::Decision { rationale, .. } => ValueMetrics {
            nesting_depth: 2,
            nodes: 3,
            maximum_string_scalars: u64::try_from(rationale.chars().count()).unwrap_or(u64::MAX),
            maximum_list_items: 0,
        },
        NodeKind::OperationError(error) => operation_error_metrics(error),
    }
}

fn validate_metrics(metrics: ValueMetrics, limits: ValueLimits) -> Result<(), ValueError> {
    for (kind, observed, limit) in [
        (
            ValueLimitKind::NestingDepth,
            metrics.nesting_depth,
            limits.maximum_nesting_depth,
        ),
        (ValueLimitKind::Nodes, metrics.nodes, limits.maximum_nodes),
        (
            ValueLimitKind::StringScalars,
            metrics.maximum_string_scalars,
            limits.maximum_string_scalars,
        ),
        (
            ValueLimitKind::ListItems,
            metrics.maximum_list_items,
            limits.maximum_list_items,
        ),
    ] {
        if observed > limit {
            return Err(ValueError::ResourceLimit {
                kind,
                limit,
                observed: Some(observed),
            });
        }
    }
    Ok(())
}

fn operation_error_node(
    value: OperationErrorValue,
) -> Result<(NodeKind, ValueMetrics), ValueError> {
    let node = match value {
        OperationErrorValue::Declined(message) => {
            OperationErrorNode::Declined(nonempty_error_text(message)?)
        }
        OperationErrorValue::InvalidOutput => OperationErrorNode::InvalidOutput,
        OperationErrorValue::ProviderFailure(message) => {
            OperationErrorNode::ProviderFailure(nonempty_error_text(message)?)
        }
        OperationErrorValue::Timeout(message) => {
            OperationErrorNode::Timeout(nonempty_error_text(message)?)
        }
        OperationErrorValue::PolicyDenied(message) => {
            OperationErrorNode::PolicyDenied(nonempty_error_text(message)?)
        }
        OperationErrorValue::Cancelled(message) => {
            OperationErrorNode::Cancelled(nonempty_error_text(message)?)
        }
        OperationErrorValue::UnknownOutcome {
            operation_id,
            message,
        } => OperationErrorNode::UnknownOutcome {
            operation_id: nonempty_error_text(operation_id)?,
            message: nonempty_error_text(message)?,
        },
    };
    let metrics = operation_error_metrics(&node);
    Ok((NodeKind::OperationError(node), metrics))
}

fn nonempty_error_text(value: String) -> Result<Arc<str>, ValueError> {
    if value.is_empty() {
        Err(ValueError::EmptyOperationErrorText)
    } else {
        Ok(Arc::from(value))
    }
}

fn operation_error_metrics(value: &OperationErrorNode) -> ValueMetrics {
    let (variant, payload_scalars, nodes, depth) = match value {
        OperationErrorNode::Declined(message) => ("Declined", scalar_count(message), 3, 2),
        OperationErrorNode::InvalidOutput => ("InvalidOutput", 0, 2, 2),
        OperationErrorNode::ProviderFailure(message) => {
            ("ProviderFailure", scalar_count(message), 3, 2)
        }
        OperationErrorNode::Timeout(message) => ("Timeout", scalar_count(message), 3, 2),
        OperationErrorNode::PolicyDenied(message) => ("PolicyDenied", scalar_count(message), 3, 2),
        OperationErrorNode::Cancelled(message) => ("Cancelled", scalar_count(message), 3, 2),
        OperationErrorNode::UnknownOutcome {
            operation_id,
            message,
        } => (
            "UnknownOutcome",
            scalar_count(operation_id).max(scalar_count(message)),
            5,
            3,
        ),
    };
    ValueMetrics {
        nesting_depth: depth,
        nodes,
        maximum_string_scalars: scalar_count(variant).max(payload_scalars),
        maximum_list_items: 0,
    }
}

fn scalar_count(value: &str) -> u64 {
    u64::try_from(value.chars().count()).unwrap_or(u64::MAX)
}

fn child_for_segment<'a>(node: &'a ValueNode, segment: &ValuePathSegment) -> Option<&'a ValueNode> {
    let child = match (&node.kind, segment) {
        (NodeKind::List(values), ValuePathSegment::ListItem(index))
        | (NodeKind::Tuple(values), ValuePathSegment::TupleMember(index)) => values.get(*index),
        (NodeKind::Struct { fields, .. }, ValuePathSegment::StructField(name)) => fields
            .iter()
            .find(|(candidate, _)| candidate.as_ref() == name)
            .map(|(_, value)| value),
        (NodeKind::Enum { payload, .. }, ValuePathSegment::EnumPayload)
        | (NodeKind::Option(payload), ValuePathSegment::OptionValue) => payload.as_ref(),
        (NodeKind::Result { value, .. }, ValuePathSegment::ResultValue) => Some(value),
        _ => None,
    }?;
    Some(child)
}

fn release_iteratively(root: Arc<ValueNode>) {
    let mut work = vec![root];
    while let Some(node) = work.pop() {
        if let Ok(node) = Arc::try_unwrap(node) {
            work.extend(node.into_children());
        }
    }
}

fn values_equal(left: &Arc<ValueNode>, right: &Arc<ValueNode>) -> bool {
    let mut work = vec![(left.as_ref(), right.as_ref())];
    while let Some((left, right)) = work.pop() {
        if std::ptr::eq(left, right) {
            continue;
        }
        match (&left.kind, &right.kind) {
            (NodeKind::Unit, NodeKind::Unit) => {}
            (NodeKind::Bool(left), NodeKind::Bool(right)) if left == right => {}
            (NodeKind::Int(left), NodeKind::Int(right)) if left == right => {}
            (NodeKind::Float(left), NodeKind::Float(right)) if left == right => {}
            (NodeKind::String(left), NodeKind::String(right)) if left == right => {}
            (NodeKind::List(left), NodeKind::List(right))
            | (NodeKind::Tuple(left), NodeKind::Tuple(right)) => {
                if !push_equal_children(left, right, &mut work) {
                    return false;
                }
            }
            (
                NodeKind::Struct {
                    type_name: left_name,
                    fields: left,
                },
                NodeKind::Struct {
                    type_name: right_name,
                    fields: right,
                },
            ) => {
                if left_name != right_name || left.len() != right.len() {
                    return false;
                }
                for ((left_name, left), (right_name, right)) in left.iter().zip(right).rev() {
                    if left_name != right_name {
                        return false;
                    }
                    work.push((left, right));
                }
            }
            (
                NodeKind::Enum {
                    type_name: left_name,
                    variant: left_variant,
                    payload: left,
                },
                NodeKind::Enum {
                    type_name: right_name,
                    variant: right_variant,
                    payload: right,
                },
            ) if left_name == right_name && left_variant == right_variant => {
                if !push_equal_options(left, right, &mut work) {
                    return false;
                }
            }
            (NodeKind::Option(left), NodeKind::Option(right)) => {
                if !push_equal_options(left, right, &mut work) {
                    return false;
                }
            }
            (
                NodeKind::Result {
                    is_ok: left_ok,
                    value: left,
                },
                NodeKind::Result {
                    is_ok: right_ok,
                    value: right,
                },
            ) if left_ok == right_ok => work.push((left, right)),
            (
                NodeKind::Decision {
                    decision: left_decision,
                    rationale: left_rationale,
                },
                NodeKind::Decision {
                    decision: right_decision,
                    rationale: right_rationale,
                },
            ) if left_decision == right_decision && left_rationale == right_rationale => {}
            (NodeKind::OperationError(left), NodeKind::OperationError(right))
                if operation_errors_equal(left, right) => {}
            _ => return false,
        }
    }
    true
}

fn push_equal_children<'a>(
    left: &'a [Arc<ValueNode>],
    right: &'a [Arc<ValueNode>],
    work: &mut Vec<(&'a ValueNode, &'a ValueNode)>,
) -> bool {
    if left.len() != right.len() {
        return false;
    }
    work.extend(
        left.iter()
            .zip(right)
            .rev()
            .map(|(left, right)| (left.as_ref(), right.as_ref())),
    );
    true
}

fn push_equal_options<'a>(
    left: &'a Option<Arc<ValueNode>>,
    right: &'a Option<Arc<ValueNode>>,
    work: &mut Vec<(&'a ValueNode, &'a ValueNode)>,
) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(left), Some(right)) => {
            work.push((left, right));
            true
        }
        _ => false,
    }
}

fn operation_errors_equal(left: &OperationErrorNode, right: &OperationErrorNode) -> bool {
    match (left, right) {
        (OperationErrorNode::Declined(left), OperationErrorNode::Declined(right))
        | (OperationErrorNode::ProviderFailure(left), OperationErrorNode::ProviderFailure(right))
        | (OperationErrorNode::Timeout(left), OperationErrorNode::Timeout(right))
        | (OperationErrorNode::PolicyDenied(left), OperationErrorNode::PolicyDenied(right))
        | (OperationErrorNode::Cancelled(left), OperationErrorNode::Cancelled(right)) => {
            left == right
        }
        (OperationErrorNode::InvalidOutput, OperationErrorNode::InvalidOutput) => true,
        (
            OperationErrorNode::UnknownOutcome {
                operation_id: left_id,
                message: left_message,
            },
            OperationErrorNode::UnknownOutcome {
                operation_id: right_id,
                message: right_message,
            },
        ) => left_id == right_id && left_message == right_message,
        _ => false,
    }
}

fn hash_value<H: Hasher>(root: &Arc<ValueNode>, state: &mut H) {
    let mut work = vec![root.as_ref()];
    while let Some(node) = work.pop() {
        node.kind.value_kind().hash(state);
        match &node.kind {
            NodeKind::Unit => {}
            NodeKind::Bool(value) => value.hash(state),
            NodeKind::Int(value) => value.hash(state),
            NodeKind::Float(value) => value.get().to_bits().hash(state),
            NodeKind::String(value) => value.hash(state),
            NodeKind::List(values) | NodeKind::Tuple(values) => {
                values.len().hash(state);
                work.extend(values.iter().rev().map(AsRef::as_ref));
            }
            NodeKind::Struct { type_name, fields } => {
                type_name.hash(state);
                fields.len().hash(state);
                for (name, value) in fields.iter().rev() {
                    name.hash(state);
                    work.push(value);
                }
            }
            NodeKind::Enum {
                type_name,
                variant,
                payload,
            } => {
                type_name.hash(state);
                variant.hash(state);
                payload.is_some().hash(state);
                work.extend(payload.iter().map(AsRef::as_ref));
            }
            NodeKind::Option(value) => {
                value.is_some().hash(state);
                work.extend(value.iter().map(AsRef::as_ref));
            }
            NodeKind::Result { is_ok, value } => {
                is_ok.hash(state);
                work.push(value);
            }
            NodeKind::Decision {
                decision,
                rationale,
            } => {
                decision.hash(state);
                rationale.hash(state);
            }
            NodeKind::OperationError(error) => hash_operation_error(error, state),
        }
    }
}

fn hash_operation_error<H: Hasher>(value: &OperationErrorNode, state: &mut H) {
    match value {
        OperationErrorNode::Declined(message) => (0_u8, message).hash(state),
        OperationErrorNode::InvalidOutput => 1_u8.hash(state),
        OperationErrorNode::ProviderFailure(message) => (2_u8, message).hash(state),
        OperationErrorNode::Timeout(message) => (3_u8, message).hash(state),
        OperationErrorNode::PolicyDenied(message) => (4_u8, message).hash(state),
        OperationErrorNode::Cancelled(message) => (5_u8, message).hash(state),
        OperationErrorNode::UnknownOutcome {
            operation_id,
            message,
        } => (6_u8, operation_id, message).hash(state),
    }
}

enum EncodeTask<'a> {
    Node(&'a ValueNode),
    Byte(u8),
    String(&'a str),
}

enum ObjectValue<'a> {
    Node(&'a ValueNode),
    String(&'a str),
    Bool(bool),
    StringPair(&'a str, &'a str),
}

fn encode_canonical(value: &LogicalValue) -> Vec<u8> {
    let mut output = Vec::new();
    let mut work = vec![EncodeTask::Node(value.node_arc())];
    while let Some(task) = work.pop() {
        match task {
            EncodeTask::Byte(byte) => output.push(byte),
            EncodeTask::String(value) => push_json_string(&mut output, value),
            EncodeTask::Node(node) => match &node.kind {
                NodeKind::Unit => output.extend_from_slice(b"null"),
                NodeKind::Bool(true) => output.extend_from_slice(b"true"),
                NodeKind::Bool(false) => output.extend_from_slice(b"false"),
                NodeKind::Int(value) => {
                    output.extend_from_slice(value.get().to_string().as_bytes())
                }
                NodeKind::Float(value) => {
                    output.extend_from_slice(value.canonical_string().as_bytes());
                }
                NodeKind::String(value) => push_json_string(&mut output, value),
                NodeKind::List(values) | NodeKind::Tuple(values) => {
                    push_array(&mut output, &mut work, values);
                }
                NodeKind::Struct { fields, .. } => {
                    push_object(
                        &mut output,
                        &mut work,
                        fields
                            .iter()
                            .map(|(name, value)| (name.as_ref(), ObjectValue::Node(value)))
                            .collect(),
                    );
                }
                NodeKind::Enum {
                    variant, payload, ..
                } => push_tagged(&mut output, &mut work, variant, payload.as_deref()),
                NodeKind::Option(None) => output.extend_from_slice(b"null"),
                NodeKind::Option(Some(value)) => work.push(EncodeTask::Node(value)),
                NodeKind::Result { is_ok, value } => push_tagged(
                    &mut output,
                    &mut work,
                    if *is_ok { "Ok" } else { "Err" },
                    Some(value),
                ),
                NodeKind::Decision {
                    decision,
                    rationale,
                } => push_object(
                    &mut output,
                    &mut work,
                    vec![
                        ("decision", ObjectValue::Bool(*decision)),
                        ("rationale", ObjectValue::String(rationale)),
                    ],
                ),
                NodeKind::OperationError(error) => {
                    push_operation_error(&mut output, &mut work, error);
                }
            },
        }
    }
    output
}

fn push_array<'a>(
    output: &mut Vec<u8>,
    work: &mut Vec<EncodeTask<'a>>,
    values: &'a [Arc<ValueNode>],
) {
    output.push(b'[');
    work.push(EncodeTask::Byte(b']'));
    for (index, value) in values.iter().enumerate().rev() {
        work.push(EncodeTask::Node(value));
        if index > 0 {
            work.push(EncodeTask::Byte(b','));
        }
    }
}

fn push_tagged<'a>(
    output: &mut Vec<u8>,
    work: &mut Vec<EncodeTask<'a>>,
    variant: &'a str,
    payload: Option<&'a ValueNode>,
) {
    let mut members = vec![("variant", ObjectValue::String(variant))];
    if let Some(payload) = payload {
        members.push(("value", ObjectValue::Node(payload)));
    }
    push_object(output, work, members);
}

fn push_operation_error<'a>(
    output: &mut Vec<u8>,
    work: &mut Vec<EncodeTask<'a>>,
    value: &'a OperationErrorNode,
) {
    let (variant, payload) = match value {
        OperationErrorNode::Declined(message) => ("Declined", Some(ObjectValue::String(message))),
        OperationErrorNode::InvalidOutput => ("InvalidOutput", None),
        OperationErrorNode::ProviderFailure(message) => {
            ("ProviderFailure", Some(ObjectValue::String(message)))
        }
        OperationErrorNode::Timeout(message) => ("Timeout", Some(ObjectValue::String(message))),
        OperationErrorNode::PolicyDenied(message) => {
            ("PolicyDenied", Some(ObjectValue::String(message)))
        }
        OperationErrorNode::Cancelled(message) => ("Cancelled", Some(ObjectValue::String(message))),
        OperationErrorNode::UnknownOutcome {
            operation_id,
            message,
        } => (
            "UnknownOutcome",
            Some(ObjectValue::StringPair(operation_id, message)),
        ),
    };
    let mut members = vec![("variant", ObjectValue::String(variant))];
    if let Some(payload) = payload {
        members.push(("value", payload));
    }
    push_object(output, work, members);
}

fn push_object<'a>(
    output: &mut Vec<u8>,
    work: &mut Vec<EncodeTask<'a>>,
    mut members: Vec<(&'a str, ObjectValue<'a>)>,
) {
    members.sort_by(|left, right| utf16_cmp(left.0, right.0));
    output.push(b'{');
    work.push(EncodeTask::Byte(b'}'));
    for (index, (name, value)) in members.into_iter().enumerate().rev() {
        push_object_value(work, value);
        work.push(EncodeTask::Byte(b':'));
        work.push(EncodeTask::String(name));
        if index > 0 {
            work.push(EncodeTask::Byte(b','));
        }
    }
}

fn push_object_value<'a>(work: &mut Vec<EncodeTask<'a>>, value: ObjectValue<'a>) {
    match value {
        ObjectValue::Node(value) => work.push(EncodeTask::Node(value)),
        ObjectValue::String(value) => work.push(EncodeTask::String(value)),
        ObjectValue::Bool(value) => work.push(EncodeTask::Node(if value {
            static TRUE_NODE: ValueNode = ValueNode {
                kind: NodeKind::Bool(true),
                metrics: ValueMetrics::SCALAR,
            };
            &TRUE_NODE
        } else {
            static FALSE_NODE: ValueNode = ValueNode {
                kind: NodeKind::Bool(false),
                metrics: ValueMetrics::SCALAR,
            };
            &FALSE_NODE
        })),
        ObjectValue::StringPair(left, right) => {
            work.push(EncodeTask::Byte(b']'));
            work.push(EncodeTask::String(right));
            work.push(EncodeTask::Byte(b','));
            work.push(EncodeTask::String(left));
            work.push(EncodeTask::Byte(b'['));
        }
    }
}

fn utf16_cmp(left: &str, right: &str) -> Ordering {
    left.encode_utf16().cmp(right.encode_utf16())
}

fn push_json_string(output: &mut Vec<u8>, value: &str) {
    output.push(b'"');
    for scalar in value.chars() {
        match scalar {
            '"' => output.extend_from_slice(b"\\\""),
            '\\' => output.extend_from_slice(b"\\\\"),
            '\u{08}' => output.extend_from_slice(b"\\b"),
            '\u{09}' => output.extend_from_slice(b"\\t"),
            '\u{0a}' => output.extend_from_slice(b"\\n"),
            '\u{0c}' => output.extend_from_slice(b"\\f"),
            '\u{0d}' => output.extend_from_slice(b"\\r"),
            value if value <= '\u{1f}' => {
                output.extend_from_slice(format!("\\u{:04x}", value as u32).as_bytes());
            }
            value => {
                let mut encoded = [0_u8; 4];
                output.extend_from_slice(value.encode_utf8(&mut encoded).as_bytes());
            }
        }
    }
    output.push(b'"');
}

enum CopyTask<'a> {
    Visit(&'a ValueNode),
    Build(CopyHeader),
}

enum CopyHeader {
    Unit(ValueMetrics),
    Bool(bool, ValueMetrics),
    Int(GantryInt, ValueMetrics),
    Float(GantryFloat, ValueMetrics),
    String(Arc<str>, ValueMetrics),
    List(usize, ValueMetrics),
    Tuple(usize, ValueMetrics),
    Struct(Arc<str>, Vec<Arc<str>>, ValueMetrics),
    Enum(Arc<str>, Arc<str>, bool, ValueMetrics),
    Option(bool, ValueMetrics),
    Result(bool, ValueMetrics),
    Decision(bool, Arc<str>, ValueMetrics),
    OperationError(OperationErrorCopy, ValueMetrics),
}

enum OperationErrorCopy {
    Declined(Arc<str>),
    InvalidOutput,
    ProviderFailure(Arc<str>),
    Timeout(Arc<str>),
    PolicyDenied(Arc<str>),
    Cancelled(Arc<str>),
    UnknownOutcome(Arc<str>, Arc<str>),
}

impl CopyHeader {
    fn from_node(node: &ValueNode) -> (Self, Vec<&ValueNode>) {
        let metrics = node.metrics;
        match &node.kind {
            NodeKind::Unit => (Self::Unit(metrics), Vec::new()),
            NodeKind::Bool(value) => (Self::Bool(*value, metrics), Vec::new()),
            NodeKind::Int(value) => (Self::Int(*value, metrics), Vec::new()),
            NodeKind::Float(value) => (Self::Float(*value, metrics), Vec::new()),
            NodeKind::String(value) => (Self::String(Arc::clone(value), metrics), Vec::new()),
            NodeKind::List(values) => (
                Self::List(values.len(), metrics),
                values.iter().map(AsRef::as_ref).collect(),
            ),
            NodeKind::Tuple(values) => (
                Self::Tuple(values.len(), metrics),
                values.iter().map(AsRef::as_ref).collect(),
            ),
            NodeKind::Struct { type_name, fields } => (
                Self::Struct(
                    Arc::clone(type_name),
                    fields.iter().map(|(name, _)| Arc::clone(name)).collect(),
                    metrics,
                ),
                fields.iter().map(|(_, value)| value.as_ref()).collect(),
            ),
            NodeKind::Enum {
                type_name,
                variant,
                payload,
            } => (
                Self::Enum(
                    Arc::clone(type_name),
                    Arc::clone(variant),
                    payload.is_some(),
                    metrics,
                ),
                payload.iter().map(AsRef::as_ref).collect(),
            ),
            NodeKind::Option(value) => (
                Self::Option(value.is_some(), metrics),
                value.iter().map(AsRef::as_ref).collect(),
            ),
            NodeKind::Result { is_ok, value } => (Self::Result(*is_ok, metrics), vec![value]),
            NodeKind::Decision {
                decision,
                rationale,
            } => (
                Self::Decision(*decision, Arc::clone(rationale), metrics),
                Vec::new(),
            ),
            NodeKind::OperationError(error) => (
                Self::OperationError(OperationErrorCopy::from_node(error), metrics),
                Vec::new(),
            ),
        }
    }

    fn child_count(&self) -> usize {
        match self {
            Self::List(count, _) | Self::Tuple(count, _) => *count,
            Self::Struct(_, names, _) => names.len(),
            Self::Enum(_, _, present, _) | Self::Option(present, _) => usize::from(*present),
            Self::Result(_, _) => 1,
            Self::Unit(_)
            | Self::Bool(_, _)
            | Self::Int(_, _)
            | Self::Float(_, _)
            | Self::String(_, _)
            | Self::Decision(_, _, _)
            | Self::OperationError(_, _) => 0,
        }
    }

    fn build(self, mut children: Vec<Arc<ValueNode>>) -> ValueNode {
        let (kind, metrics) = match self {
            Self::Unit(metrics) => (NodeKind::Unit, metrics),
            Self::Bool(value, metrics) => (NodeKind::Bool(value), metrics),
            Self::Int(value, metrics) => (NodeKind::Int(value), metrics),
            Self::Float(value, metrics) => (NodeKind::Float(value), metrics),
            Self::String(value, metrics) => (NodeKind::String(value), metrics),
            Self::List(_, metrics) => (NodeKind::List(children), metrics),
            Self::Tuple(_, metrics) => (NodeKind::Tuple(children), metrics),
            Self::Struct(type_name, names, metrics) => (
                NodeKind::Struct {
                    type_name,
                    fields: names.into_iter().zip(children).collect(),
                },
                metrics,
            ),
            Self::Enum(type_name, variant, present, metrics) => (
                NodeKind::Enum {
                    type_name,
                    variant,
                    payload: present.then(|| children.remove(0)),
                },
                metrics,
            ),
            Self::Option(present, metrics) => (
                NodeKind::Option(present.then(|| children.remove(0))),
                metrics,
            ),
            Self::Result(is_ok, metrics) => (
                NodeKind::Result {
                    is_ok,
                    value: children.remove(0),
                },
                metrics,
            ),
            Self::Decision(decision, rationale, metrics) => (
                NodeKind::Decision {
                    decision,
                    rationale,
                },
                metrics,
            ),
            Self::OperationError(error, metrics) => {
                (NodeKind::OperationError(error.into_node()), metrics)
            }
        };
        ValueNode { kind, metrics }
    }
}

impl OperationErrorCopy {
    fn from_node(value: &OperationErrorNode) -> Self {
        match value {
            OperationErrorNode::Declined(message) => Self::Declined(Arc::clone(message)),
            OperationErrorNode::InvalidOutput => Self::InvalidOutput,
            OperationErrorNode::ProviderFailure(message) => {
                Self::ProviderFailure(Arc::clone(message))
            }
            OperationErrorNode::Timeout(message) => Self::Timeout(Arc::clone(message)),
            OperationErrorNode::PolicyDenied(message) => Self::PolicyDenied(Arc::clone(message)),
            OperationErrorNode::Cancelled(message) => Self::Cancelled(Arc::clone(message)),
            OperationErrorNode::UnknownOutcome {
                operation_id,
                message,
            } => Self::UnknownOutcome(Arc::clone(operation_id), Arc::clone(message)),
        }
    }

    fn into_node(self) -> OperationErrorNode {
        match self {
            Self::Declined(message) => OperationErrorNode::Declined(message),
            Self::InvalidOutput => OperationErrorNode::InvalidOutput,
            Self::ProviderFailure(message) => OperationErrorNode::ProviderFailure(message),
            Self::Timeout(message) => OperationErrorNode::Timeout(message),
            Self::PolicyDenied(message) => OperationErrorNode::PolicyDenied(message),
            Self::Cancelled(message) => OperationErrorNode::Cancelled(message),
            Self::UnknownOutcome(operation_id, message) => OperationErrorNode::UnknownOutcome {
                operation_id,
                message,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    use std::sync::Arc;

    use super::{
        DEFAULT_VALUE_LIMITS, LogicalValue, OperationErrorValue, ValueError, ValueKind,
        ValueLimitKind, ValueLimits, ValuePathSegment, ValueRoot,
    };
    use crate::numeric::{GantryFloat, GantryInt};

    fn limits(depth: u64, nodes: u64) -> ValueLimits {
        ValueLimits::new(depth, nodes, 1_000_000, 1_000_000)
            .unwrap_or_else(|| unreachable!("test limits are positive"))
    }

    #[test]
    fn canonical_values_cover_scalars_aggregates_and_tagged_forms() {
        let maximum = DEFAULT_VALUE_LIMITS;
        let report = LogicalValue::structure(
            "crate::Report",
            vec![
                (
                    "count".to_owned(),
                    LogicalValue::integer(
                        GantryInt::new(3).unwrap_or_else(|| unreachable!("fixture is in range")),
                    ),
                ),
                (
                    "values".to_owned(),
                    LogicalValue::list(
                        vec![
                            LogicalValue::float(
                                GantryFloat::new(-0.0)
                                    .unwrap_or_else(|| unreachable!("fixture is finite")),
                            ),
                            LogicalValue::boolean(true),
                        ],
                        maximum,
                    )
                    .unwrap_or_else(|error| panic!("list failed: {error:?}")),
                ),
            ],
            maximum,
        )
        .unwrap_or_else(|error| panic!("struct failed: {error:?}"));
        assert_eq!(
            report.canonical_json().bytes(),
            br#"{"count":3,"values":[0,true]}"#
        );

        let tagged =
            LogicalValue::enumeration("crate::Status", "Ready", Some(report.clone()), maximum)
                .unwrap_or_else(|error| panic!("enum failed: {error:?}"));
        assert_eq!(
            tagged.canonical_json().bytes(),
            br#"{"value":{"count":3,"values":[0,true]},"variant":"Ready"}"#
        );

        let present = LogicalValue::some(report, maximum)
            .unwrap_or_else(|error| panic!("option failed: {error:?}"));
        let result = LogicalValue::ok(present, maximum)
            .unwrap_or_else(|error| panic!("result failed: {error:?}"));
        assert_eq!(result.kind(), ValueKind::Result);
        assert!(
            std::str::from_utf8(result.canonical_json().bytes())
                .is_ok_and(|value| value.ends_with(",\"variant\":\"Ok\"}"))
        );

        let error = LogicalValue::operation_error(
            OperationErrorValue::UnknownOutcome {
                operation_id: "operation:1".to_owned(),
                message: "indeterminate".to_owned(),
            },
            maximum,
        )
        .unwrap_or_else(|failure| panic!("operation error failed: {failure:?}"));
        assert_eq!(
            error.canonical_json().bytes(),
            br#"{"value":["operation:1","indeterminate"],"variant":"UnknownOutcome"}"#
        );
    }

    #[test]
    fn logical_metrics_count_shared_occurrences_and_enforce_exact_limits() {
        let leaf = LogicalValue::string("é", DEFAULT_VALUE_LIMITS)
            .unwrap_or_else(|error| panic!("string failed: {error:?}"));
        let shared = LogicalValue::list(vec![leaf.clone(), leaf], DEFAULT_VALUE_LIMITS)
            .unwrap_or_else(|error| panic!("list failed: {error:?}"));
        assert_eq!(shared.metrics().nesting_depth, 2);
        assert_eq!(shared.metrics().nodes, 3);
        assert_eq!(shared.metrics().maximum_string_scalars, 1);
        assert_eq!(shared.metrics().maximum_list_items, 2);
        assert_eq!(
            shared.validate(limits(2, 2)),
            Err(ValueError::ResourceLimit {
                kind: ValueLimitKind::Nodes,
                limit: 2,
                observed: Some(3),
            })
        );
        let string_limit = ValueLimits::new(2, 3, 1, 2)
            .unwrap_or_else(|| unreachable!("fixture limits are positive"));
        assert_eq!(shared.validate(string_limit), Ok(()));
        assert!(matches!(
            LogicalValue::string(
                "éx",
                ValueLimits::new(1, 1, 1, 1)
                    .unwrap_or_else(|| unreachable!("fixture limits are positive"))
            ),
            Err(ValueError::ResourceLimit {
                kind: ValueLimitKind::StringScalars,
                observed: Some(2),
                ..
            })
        ));
    }

    #[test]
    fn copies_and_atomic_replacement_preserve_deep_nonaliasing() {
        let maximum = DEFAULT_VALUE_LIMITS;
        let inner = LogicalValue::structure(
            "crate::Inner",
            vec![("value".to_owned(), LogicalValue::boolean(false))],
            maximum,
        )
        .unwrap_or_else(|error| panic!("inner failed: {error:?}"));
        let original =
            LogicalValue::structure("crate::Outer", vec![("inner".to_owned(), inner)], maximum)
                .unwrap_or_else(|error| panic!("outer failed: {error:?}"));
        let independent = original.clone();
        let root = ValueRoot::new(original, maximum)
            .unwrap_or_else(|error| panic!("root failed: {error:?}"));
        let updated = root
            .replace(
                &[
                    ValuePathSegment::StructField("inner".to_owned()),
                    ValuePathSegment::StructField("value".to_owned()),
                ],
                &LogicalValue::boolean(true),
                maximum,
            )
            .unwrap_or_else(|error| panic!("replacement failed: {error:?}"));
        assert_eq!(
            independent.canonical_json().bytes(),
            br#"{"inner":{"value":false}}"#
        );
        assert_eq!(
            updated.canonical_json().bytes(),
            br#"{"inner":{"value":true}}"#
        );

        let before_failure = root.snapshot();
        let failure = root.replace(
            &[ValuePathSegment::StructField("inner".to_owned())],
            &LogicalValue::list(vec![LogicalValue::unit(), LogicalValue::unit()], maximum)
                .unwrap_or_else(|error| panic!("replacement fixture failed: {error:?}")),
            limits(2, 2),
        );
        assert!(matches!(failure, Err(ValueError::ResourceLimit { .. })));
        assert_eq!(root.snapshot(), before_failure);
    }

    #[test]
    fn equality_hash_copy_encoding_and_reclamation_are_depth_safe() {
        let depth = 20_000_u64;
        let maximum = ValueLimits::new(depth + 1, depth + 1, 1, 1)
            .unwrap_or_else(|| unreachable!("fixture limits are positive"));
        let mut value = LogicalValue::unit();
        for level in 0..depth {
            value = LogicalValue::list(vec![value], maximum)
                .unwrap_or_else(|error| panic!("level {level} failed: {error:?}"));
        }
        assert_eq!(value.metrics().nesting_depth, depth + 1);
        assert_eq!(value.metrics().nodes, depth + 1);

        let copy = value
            .detached_copy(maximum)
            .unwrap_or_else(|error| panic!("copy failed: {error:?}"));
        assert_eq!(value, copy);
        assert_eq!(value.canonical_json(), copy.canonical_json());
        let mut left_hash = DefaultHasher::new();
        value.hash(&mut left_hash);
        let mut right_hash = DefaultHasher::new();
        copy.hash(&mut right_hash);
        assert_eq!(left_hash.finish(), right_hash.finish());

        let thread_value = Arc::new(copy);
        let other = Arc::clone(&thread_value);
        std::thread::spawn(move || assert_eq!(other.metrics().nodes, depth + 1))
            .join()
            .unwrap_or_else(|_| panic!("value thread panicked"));
        drop(thread_value);
        drop(value);
    }
}
