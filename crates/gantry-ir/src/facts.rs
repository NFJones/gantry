//! Source-backed static sites and analyzer facts consumed by lowering.

use std::fmt;
use std::sync::Arc;

use gantry_core::portable::TaskHandleState;
use gantry_core::source::SourceSpan;

use crate::generated::{OperationSiteKind, RecoveryClass, TaskControlSiteKind};
use crate::{CanonicalPath, CanonicalSignature, EffectSet, TypeDescriptor};

/// Structural position of a canonical site within one workflow.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StructuralPosition(Arc<[u64]>);

impl StructuralPosition {
    /// Constructs one nonempty structural route.
    pub fn new(components: Vec<u64>) -> Result<Self, SiteContractError> {
        if components.is_empty() {
            return Err(SiteContractError::EmptyStructuralPosition);
        }
        Ok(Self(Arc::from(components)))
    }

    /// Returns the ordered zero-based structural components.
    #[must_use]
    pub fn components(&self) -> &[u64] {
        &self.0
    }
}

/// Stable static site identity independent of source spans and physical paths.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StaticSiteId {
    workflow: CanonicalPath,
    position: StructuralPosition,
}

impl StaticSiteId {
    /// Binds a structural position to its canonical workflow.
    #[must_use]
    pub const fn new(workflow: CanonicalPath, position: StructuralPosition) -> Self {
        Self { workflow, position }
    }

    /// Returns the canonical containing workflow path.
    #[must_use]
    pub const fn workflow(&self) -> &CanonicalPath {
        &self.workflow
    }

    /// Returns the canonical structural position.
    #[must_use]
    pub const fn position(&self) -> &StructuralPosition {
        &self.position
    }
}

/// One direct workflow-call edge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CallEdge {
    /// Canonical call-site identity.
    pub site: StaticSiteId,
    /// Canonical callee path.
    pub callee: CanonicalPath,
    /// Authored source location retained outside canonical IR identity.
    pub source: SourceSpan,
}

/// One direct integration-operation site.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationSite {
    /// Canonical static site identity.
    pub id: StaticSiteId,
    /// Prompt, decision, or action classification.
    pub kind: OperationSiteKind,
    /// Exact static result type.
    pub result: TypeDescriptor,
    /// Required only for action sites.
    pub recovery: Option<RecoveryClass>,
    /// Authored source location retained by the source map.
    pub source: SourceSpan,
}

impl OperationSite {
    /// Validates recovery-class presence against the operation kind.
    pub fn new(
        id: StaticSiteId,
        kind: OperationSiteKind,
        result: TypeDescriptor,
        recovery: Option<RecoveryClass>,
        source: SourceSpan,
    ) -> Result<Self, SiteContractError> {
        if matches!(kind, OperationSiteKind::Action) != recovery.is_some() {
            return Err(SiteContractError::RecoveryClassMismatch);
        }
        Ok(Self {
            id,
            kind,
            result,
            recovery,
            source,
        })
    }
}

/// One direct task-control site.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskControlSite {
    /// Canonical static site identity.
    pub id: StaticSiteId,
    /// Spawn, join, joinall, or detach classification.
    pub kind: TaskControlSiteKind,
    /// Authored source location retained by the source map.
    pub source: SourceSpan,
}

/// One analyzer-owned task-handle ownership fact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnershipFact {
    /// Exact authored handle name.
    pub handle: Arc<str>,
    /// Static ownership state at the recorded program point.
    pub state: TaskHandleState,
    /// Source location establishing the fact.
    pub source: SourceSpan,
}

/// Complete portable facts for one workflow before canonical lowering.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkflowFacts {
    /// Canonical workflow path.
    pub path: CanonicalPath,
    /// Canonical callable signature.
    pub signature: CanonicalSignature,
    /// Least-fixed-point inferred effect summary.
    pub effects: EffectSet,
    /// Direct call edges in structural-site order.
    pub calls: Vec<CallEdge>,
    /// Direct operation sites in structural-site order.
    pub operations: Vec<OperationSite>,
    /// Direct task-control sites in structural-site order.
    pub task_controls: Vec<TaskControlSite>,
}

impl WorkflowFacts {
    /// Constructs facts only when every site list is strictly ordered and local.
    pub fn new(
        path: CanonicalPath,
        signature: CanonicalSignature,
        effects: EffectSet,
        calls: Vec<CallEdge>,
        operations: Vec<OperationSite>,
        task_controls: Vec<TaskControlSite>,
    ) -> Result<Self, SiteContractError> {
        validate_sites(&path, calls.iter().map(|site| &site.site))?;
        validate_sites(&path, operations.iter().map(|site| &site.id))?;
        validate_sites(&path, task_controls.iter().map(|site| &site.id))?;
        Ok(Self {
            path,
            signature,
            effects,
            calls,
            operations,
            task_controls,
        })
    }
}

/// Rejection of malformed portable analyzer facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SiteContractError {
    /// A structural site position has no components.
    EmptyStructuralPosition,
    /// An action lacks a recovery class or another operation has one.
    RecoveryClassMismatch,
    /// Sites are duplicated, out of order, or belong to another workflow.
    NoncanonicalSiteOrder,
}

impl fmt::Display for SiteContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::EmptyStructuralPosition => "structural position is empty",
            Self::RecoveryClassMismatch => "operation recovery class does not match its kind",
            Self::NoncanonicalSiteOrder => "static sites are not in canonical workflow order",
        })
    }
}

impl std::error::Error for SiteContractError {}

fn validate_sites<'a>(
    workflow: &CanonicalPath,
    sites: impl Iterator<Item = &'a StaticSiteId>,
) -> Result<(), SiteContractError> {
    let mut previous = None;
    for site in sites {
        if site.workflow() != workflow || previous.is_some_and(|prior: &StaticSiteId| prior >= site)
        {
            return Err(SiteContractError::NoncanonicalSiteOrder);
        }
        previous = Some(site);
    }
    Ok(())
}
