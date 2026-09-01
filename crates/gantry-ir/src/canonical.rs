//! Canonical IR and source-map artifacts over analyzer-owned facts.

use std::sync::Arc;

use gantry_core::source::SourceSpan;

use crate::artifact::{
    ArtifactEncodingError, ArtifactLimits, BoundedArtifact, CanonicalArtifactEncoder,
};
use crate::generated::{
    ArtifactKind, CoreForm, OperationSiteKind, RecoveryClass, TaskControlSiteKind,
};
use crate::{
    CanonicalPath, CanonicalSignature, ConcreteIdentity, ConcreteSourceMapEntry, EffectSet,
    GenericAnalysisFacts, Predicate, StructuralPosition, TraitReference, TypeDescriptor,
};

/// Portable static operation metadata retained by one canonical operation node.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalOperationSite {
    /// Prompt, decision, or harness-action classification.
    pub kind: OperationSiteKind,
    /// Canonical action path, present only for harness actions.
    pub action: Option<CanonicalPath>,
    /// Declared recovery class, present only for harness actions.
    pub recovery: Option<RecoveryClass>,
    /// Decoded prompt-template literal segments in source order.
    pub template_segments: Vec<Arc<str>>,
    /// Zero-based interpolation inputs in source evaluation order.
    pub interpolation_inputs: Vec<u64>,
    /// Named-input names in source evaluation order.
    pub named_input_names: Vec<Arc<str>>,
    /// Named-input expression positions in source evaluation order.
    pub named_inputs: Vec<StructuralPosition>,
}

/// Portable static task metadata retained by one canonical task-control node.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalTaskControlSite {
    /// Spawn, named join, joinall, or background transfer.
    pub kind: TaskControlSiteKind,
    /// Exact statically selected handles in declaration or source order.
    pub handles: Vec<Arc<str>>,
}

/// One typed node in the desugared canonical core language.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalNode {
    /// Structural position within the containing workflow.
    pub position: StructuralPosition,
    /// Exact desugared core form.
    pub form: CoreForm,
    /// Exact static result type.
    pub ty: TypeDescriptor,
    /// Child positions in semantic evaluation order.
    pub children: Vec<StructuralPosition>,
    /// Operation metadata, present only for operation nodes.
    pub operation: Option<CanonicalOperationSite>,
    /// Task metadata, present only for spawn, join, and background-transfer nodes.
    pub task_control: Option<CanonicalTaskControlSite>,
}

/// One canonical workflow independent of source spelling and source spans.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalWorkflow {
    /// Canonical workflow path.
    pub path: CanonicalPath,
    /// Canonical callable signature.
    pub signature: CanonicalSignature,
    /// Least-fixed-point effect summary.
    pub effects: EffectSet,
    /// Desugared nodes in structural-position order.
    pub nodes: Vec<CanonicalNode>,
}

impl CanonicalWorkflow {
    /// Constructs one workflow only when node identities are strictly ordered.
    pub fn new(
        path: CanonicalPath,
        signature: CanonicalSignature,
        effects: EffectSet,
        nodes: Vec<CanonicalNode>,
    ) -> Result<Self, IrArtifactError> {
        if nodes
            .windows(2)
            .any(|pair| pair[0].position >= pair[1].position)
        {
            return Err(IrArtifactError::NoncanonicalOrder);
        }
        Ok(Self {
            path,
            signature,
            effects,
            nodes,
        })
    }
}

/// One complete bounded canonical-IR artifact and execution-package identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalIr {
    workflows: Vec<CanonicalWorkflow>,
    generic: GenericAnalysisFacts,
    artifact: BoundedArtifact,
}

impl CanonicalIr {
    /// Encodes workflows in canonical path order under the IR byte limit.
    pub fn new(
        workflows: Vec<CanonicalWorkflow>,
        limits: ArtifactLimits,
    ) -> Result<Self, IrArtifactError> {
        Self::with_generic_facts(workflows, GenericAnalysisFacts::empty(), limits)
    }

    /// Encodes workflows and generic analysis facts under the IR byte limit.
    pub fn with_generic_facts(
        workflows: Vec<CanonicalWorkflow>,
        generic: GenericAnalysisFacts,
        limits: ArtifactLimits,
    ) -> Result<Self, IrArtifactError> {
        if workflows
            .windows(2)
            .any(|pair| pair[0].path >= pair[1].path)
        {
            return Err(IrArtifactError::NoncanonicalOrder);
        }
        let artifact =
            encode_ir(&workflows, &generic, limits).map_err(IrArtifactError::Encoding)?;
        Ok(Self {
            workflows,
            generic,
            artifact,
        })
    }

    /// Returns workflows in canonical path order.
    #[must_use]
    pub fn workflows(&self) -> &[CanonicalWorkflow] {
        &self.workflows
    }

    /// Returns canonically ordered generic facts and the closed projection.
    #[must_use]
    pub const fn generic_facts(&self) -> &GenericAnalysisFacts {
        &self.generic
    }

    /// Returns canonical bytes and their accepted execution-package identity.
    #[must_use]
    pub const fn artifact(&self) -> &BoundedArtifact {
        &self.artifact
    }
}

/// One source-map entry linking a structural site to authored bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceMapEntry {
    /// Canonical containing workflow.
    pub workflow: CanonicalPath,
    /// Structural position independent of physical source location.
    pub position: StructuralPosition,
    /// Exact authored source span from the immutable snapshot.
    pub source: SourceSpan,
}

/// One complete bounded source-map artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalSourceMap {
    entries: Vec<SourceMapEntry>,
    generic_entries: Vec<ConcreteSourceMapEntry>,
    artifact: BoundedArtifact,
}

impl CanonicalSourceMap {
    /// Encodes entries ordered by workflow and structural position.
    pub fn new(
        entries: Vec<SourceMapEntry>,
        limits: ArtifactLimits,
    ) -> Result<Self, IrArtifactError> {
        Self::with_generic_entries(entries, Vec::new(), limits)
    }

    /// Encodes structural and multi-origin generic entries in canonical order.
    pub fn with_generic_entries(
        entries: Vec<SourceMapEntry>,
        generic_entries: Vec<ConcreteSourceMapEntry>,
        limits: ArtifactLimits,
    ) -> Result<Self, IrArtifactError> {
        if entries.windows(2).any(|pair| {
            (&pair[0].workflow, &pair[0].position) >= (&pair[1].workflow, &pair[1].position)
        }) || generic_entries.windows(2).any(|pair| {
            pair[0].node().canonical_string().as_bytes()
                >= pair[1].node().canonical_string().as_bytes()
        }) {
            return Err(IrArtifactError::NoncanonicalOrder);
        }
        let artifact = encode_source_map(&entries, &generic_entries, limits)
            .map_err(IrArtifactError::Encoding)?;
        Ok(Self {
            entries,
            generic_entries,
            artifact,
        })
    }

    /// Returns entries in canonical structural order.
    #[must_use]
    pub fn entries(&self) -> &[SourceMapEntry] {
        &self.entries
    }

    /// Returns multi-origin generic entries in concrete-identity order.
    #[must_use]
    pub fn generic_entries(&self) -> &[ConcreteSourceMapEntry] {
        &self.generic_entries
    }

    /// Returns the complete bounded source-map bytes.
    #[must_use]
    pub const fn artifact(&self) -> &BoundedArtifact {
        &self.artifact
    }
}

/// Rejection while assembling canonical IR or source-map artifacts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IrArtifactError {
    /// Workflows, nodes, or map entries are duplicated or out of order.
    NoncanonicalOrder,
    /// Complete canonical bytes were empty or exceeded their portable limit.
    Encoding(ArtifactEncodingError),
}

impl std::fmt::Display for IrArtifactError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoncanonicalOrder => {
                formatter.write_str("IR records are not canonically ordered")
            }
            Self::Encoding(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for IrArtifactError {}

fn encode_ir(
    workflows: &[CanonicalWorkflow],
    generic: &GenericAnalysisFacts,
    limits: ArtifactLimits,
) -> Result<BoundedArtifact, ArtifactEncodingError> {
    let mut output = CanonicalArtifactEncoder::new(ArtifactKind::CanonicalIr, limits);
    output.push_str("{\"canonical_ir\":{\"major\":1,\"minor\":0},\"concrete_effects\":[")?;
    for (index, effect) in generic.concrete_effects().iter().enumerate() {
        if index > 0 {
            output.push_byte(b',')?;
        }
        output.push_str("{\"callable\":")?;
        push_json_string(&mut output, effect.callable.as_str())?;
        output.push_str(",\"effects\":[")?;
        push_effects(&mut output, effect.effects)?;
        output.push_str("]}")?;
    }
    output.push_str("],\"executable_projection\":{\"callables\":[")?;
    for (index, callable) in generic.executable().callables().iter().enumerate() {
        if index > 0 {
            output.push_byte(b',')?;
        }
        output.push_str("{\"direct_calls\":[")?;
        for (call_index, callee) in callable.direct_calls().iter().enumerate() {
            if call_index > 0 {
                output.push_byte(b',')?;
            }
            push_json_string(&mut output, callee.as_str())?;
        }
        output.push_str("],\"effects\":[")?;
        push_effects(&mut output, *callable.effects())?;
        output.push_str("],\"identity\":")?;
        push_json_string(&mut output, callable.identity().as_str())?;
        output.push_str(",\"signature\":")?;
        push_json_string(&mut output, callable.signature().as_str())?;
        output.push_byte(b'}')?;
    }
    output.push_str("],\"types\":[")?;
    for (index, descriptor) in generic.executable().types().iter().enumerate() {
        if index > 0 {
            output.push_byte(b',')?;
        }
        push_json_string(&mut output, &descriptor.canonical_string())?;
    }
    output.push_str("]},\"implementations\":[")?;
    for (index, implementation) in generic.implementations().iter().enumerate() {
        if index > 0 {
            output.push_byte(b',')?;
        }
        output.push_str("{\"identity\":")?;
        push_json_string(&mut output, implementation.identity().as_str())?;
        output.push_str(",\"parameter_count\":\"")?;
        output.push_str(&implementation.parameter_count().to_string())?;
        output.push_str("\",\"predicates\":[")?;
        push_predicates(&mut output, implementation.predicates())?;
        output.push_str("],\"receiver\":")?;
        push_json_string(&mut output, implementation.receiver().as_str())?;
        if let Some(trait_reference) = implementation.trait_reference() {
            output.push_str(",\"trait\":")?;
            push_trait_reference(&mut output, trait_reference)?;
        }
        output.push_byte(b'}')?;
    }
    output.push_str("],\"instantiations\":[")?;
    for (index, instantiation) in generic.instantiations().iter().enumerate() {
        if index > 0 {
            output.push_byte(b',')?;
        }
        output.push_str("{\"arguments\":[")?;
        for (argument_index, argument) in instantiation.arguments().iter().enumerate() {
            if argument_index > 0 {
                output.push_byte(b',')?;
            }
            push_json_string(&mut output, &argument.canonical_string())?;
        }
        output.push_str("],\"concrete\":")?;
        push_concrete_identity(&mut output, instantiation.concrete())?;
        output.push_str(",\"kind\":")?;
        push_json_string(&mut output, instantiation.kind().wire_name())?;
        output.push_str(",\"template\":")?;
        push_json_string(&mut output, instantiation.template().as_str())?;
        output.push_byte(b'}')?;
    }
    output.push_str("],\"resolved_calls\":[")?;
    for (index, call) in generic.resolved_calls().iter().enumerate() {
        if index > 0 {
            output.push_byte(b',')?;
        }
        output.push_str("{\"callee\":")?;
        push_json_string(&mut output, call.callee.as_str())?;
        output.push_str(",\"position\":")?;
        push_position(&mut output, call.site.position())?;
        if let Some(implementation) = &call.selected_implementation {
            output.push_str(",\"selected_implementation\":")?;
            push_json_string(&mut output, implementation.as_str())?;
        }
        output.push_str(",\"workflow\":")?;
        push_json_string(&mut output, call.site.workflow().as_str())?;
        output.push_byte(b'}')?;
    }
    output.push_str("],\"templates\":[")?;
    for (index, template) in generic.templates().iter().enumerate() {
        if index > 0 {
            output.push_byte(b',')?;
        }
        output.push_str("{\"conservative_effects\":[")?;
        push_effects(&mut output, *template.conservative_effects())?;
        output.push_str("],\"identity\":")?;
        push_json_string(&mut output, template.identity().as_str())?;
        output.push_str(",\"kind\":")?;
        push_json_string(&mut output, template.kind().wire_name())?;
        output.push_str(",\"parameter_count\":\"")?;
        output.push_str(&template.parameter_count().to_string())?;
        output.push_str("\",\"predicates\":[")?;
        push_predicates(&mut output, template.predicates())?;
        output.push_str("]}")?;
    }
    output.push_str("],\"traits\":[")?;
    for (index, contract) in generic.traits().iter().enumerate() {
        if index > 0 {
            output.push_byte(b',')?;
        }
        output.push_str("{\"methods\":[")?;
        for (method_index, method) in contract.methods().iter().enumerate() {
            if method_index > 0 {
                output.push_byte(b',')?;
            }
            output.push_str("{\"effects\":[")?;
            push_effects(&mut output, *method.effects())?;
            output.push_str("],\"mutable_receiver\":")?;
            output.push_str(if method.mutable_receiver() {
                "true"
            } else {
                "false"
            })?;
            output.push_str(",\"name\":")?;
            push_json_string(&mut output, method.name())?;
            output.push_str(",\"parameter_count\":\"")?;
            output.push_str(&method.parameter_count().to_string())?;
            output.push_str("\",\"parameters\":[")?;
            for (parameter_index, parameter) in method.parameters().iter().enumerate() {
                if parameter_index > 0 {
                    output.push_byte(b',')?;
                }
                push_json_string(&mut output, parameter.as_str())?;
            }
            output.push_str("],\"predicates\":[")?;
            push_predicates(&mut output, method.predicates())?;
            output.push_str("],\"result\":")?;
            push_json_string(&mut output, method.result().as_str())?;
            output.push_byte(b'}')?;
        }
        output.push_str("],\"parameter_count\":\"")?;
        output.push_str(&contract.parameter_count().to_string())?;
        output.push_str("\",\"path\":")?;
        push_json_string(&mut output, contract.path().as_str())?;
        output.push_str(",\"predicates\":[")?;
        push_predicates(&mut output, contract.predicates())?;
        output.push_str("]}")?;
    }
    output.push_str("],\"workflows\":[")?;
    for (workflow_index, workflow) in workflows.iter().enumerate() {
        if workflow_index > 0 {
            output.push_byte(b',')?;
        }
        output.push_str("{\"effects\":[")?;
        for (effect_index, effect) in workflow.effects.iter().enumerate() {
            if effect_index > 0 {
                output.push_byte(b',')?;
            }
            push_json_string(&mut output, effect.wire_name())?;
        }
        output.push_str("],\"nodes\":[")?;
        for (node_index, node) in workflow.nodes.iter().enumerate() {
            if node_index > 0 {
                output.push_byte(b',')?;
            }
            output.push_str("{\"children\":[")?;
            for (child_index, child) in node.children.iter().enumerate() {
                if child_index > 0 {
                    output.push_byte(b',')?;
                }
                push_position(&mut output, child)?;
            }
            output.push_str("],\"form\":")?;
            push_json_string(&mut output, node.form.wire_name())?;
            if let Some(operation) = &node.operation {
                output.push_str(",\"operation\":{")?;
                if let Some(action) = &operation.action {
                    output.push_str("\"action\":")?;
                    push_json_string(&mut output, action.as_str())?;
                    output.push_byte(b',')?;
                }
                output.push_str("\"interpolation_inputs\":[")?;
                for (input_index, input) in operation.interpolation_inputs.iter().enumerate() {
                    if input_index > 0 {
                        output.push_byte(b',')?;
                    }
                    output.push_byte(b'\"')?;
                    output.push_str(&input.to_string())?;
                    output.push_byte(b'\"')?;
                }
                output.push_str("],\"kind\":")?;
                push_json_string(&mut output, operation.kind.wire_name())?;
                output.push_str(",\"named_input_names\":[")?;
                for (input_index, input) in operation.named_input_names.iter().enumerate() {
                    if input_index > 0 {
                        output.push_byte(b',')?;
                    }
                    push_json_string(&mut output, input)?;
                }
                output.push_byte(b']')?;
                output.push_str(",\"named_inputs\":[")?;
                for (input_index, input) in operation.named_inputs.iter().enumerate() {
                    if input_index > 0 {
                        output.push_byte(b',')?;
                    }
                    push_position(&mut output, input)?;
                }
                output.push_byte(b']')?;
                if let Some(recovery) = operation.recovery {
                    output.push_str(",\"recovery\":")?;
                    push_json_string(&mut output, recovery.wire_name())?;
                }
                output.push_str(",\"template_segments\":[")?;
                for (segment_index, segment) in operation.template_segments.iter().enumerate() {
                    if segment_index > 0 {
                        output.push_byte(b',')?;
                    }
                    push_json_string(&mut output, segment)?;
                }
                output.push_byte(b']')?;
                output.push_byte(b'}')?;
            }
            output.push_str(",\"position\":")?;
            push_position(&mut output, &node.position)?;
            if let Some(task_control) = &node.task_control {
                output.push_str(",\"task_control\":{\"handles\":[")?;
                for (handle_index, handle) in task_control.handles.iter().enumerate() {
                    if handle_index > 0 {
                        output.push_byte(b',')?;
                    }
                    push_json_string(&mut output, handle)?;
                }
                output.push_str("],\"kind\":")?;
                push_json_string(&mut output, task_control.kind.wire_name())?;
                output.push_byte(b'}')?;
            }
            output.push_str(",\"type\":")?;
            push_json_string(&mut output, &node.ty.canonical_string())?;
            output.push_byte(b'}')?;
        }
        output.push_str("],\"path\":")?;
        push_json_string(&mut output, workflow.path.as_str())?;
        output.push_str(",\"signature\":")?;
        push_json_string(&mut output, workflow.signature.as_str())?;
        output.push_byte(b'}')?;
    }
    output.push_str("]}")?;
    output.finish()
}

fn encode_source_map(
    entries: &[SourceMapEntry],
    generic_entries: &[ConcreteSourceMapEntry],
    limits: ArtifactLimits,
) -> Result<BoundedArtifact, ArtifactEncodingError> {
    let mut output = CanonicalArtifactEncoder::new(ArtifactKind::SourceMap, limits);
    output.push_str("{\"entries\":[")?;
    for (index, entry) in entries.iter().enumerate() {
        if index > 0 {
            output.push_byte(b',')?;
        }
        output.push_str("{\"end\":\"")?;
        output.push_str(&entry.source.bytes().end().to_string())?;
        output.push_byte(b'"')?;
        output.push_str(",\"path\":")?;
        push_json_string(&mut output, entry.source.source().package_path().as_str())?;
        output.push_str(",\"position\":")?;
        push_position(&mut output, &entry.position)?;
        output.push_str(",\"start\":\"")?;
        output.push_str(&entry.source.bytes().start().to_string())?;
        output.push_byte(b'"')?;
        output.push_str(",\"workflow\":")?;
        push_json_string(&mut output, entry.workflow.as_str())?;
        output.push_byte(b'}')?;
    }
    output.push_str("],\"generic_entries\":[")?;
    for (index, entry) in generic_entries.iter().enumerate() {
        if index > 0 {
            output.push_byte(b',')?;
        }
        output.push_str("{\"declaration\":")?;
        push_span(&mut output, entry.declaration())?;
        output.push_str(",\"node\":")?;
        push_concrete_identity(&mut output, entry.node())?;
        output.push_str(",\"origins\":[")?;
        for (origin_index, origin) in entry.origins().origins().iter().enumerate() {
            if origin_index > 0 {
                output.push_byte(b',')?;
            }
            push_span(&mut output, origin)?;
        }
        output.push_str("]}")?;
    }
    output.push_str("],\"source_map\":{\"major\":1,\"minor\":0}}")?;
    output.finish()
}

fn push_effects(
    output: &mut CanonicalArtifactEncoder,
    effects: EffectSet,
) -> Result<(), ArtifactEncodingError> {
    for (index, effect) in effects.iter().enumerate() {
        if index > 0 {
            output.push_byte(b',')?;
        }
        push_json_string(output, effect.wire_name())?;
    }
    Ok(())
}

fn push_trait_reference(
    output: &mut CanonicalArtifactEncoder,
    trait_reference: &TraitReference,
) -> Result<(), ArtifactEncodingError> {
    output.push_str("{\"arguments\":[")?;
    for (index, argument) in trait_reference.arguments().iter().enumerate() {
        if index > 0 {
            output.push_byte(b',')?;
        }
        push_json_string(output, argument.as_str())?;
    }
    output.push_str("],\"path\":")?;
    push_json_string(output, trait_reference.path().as_str())?;
    output.push_byte(b'}')?;
    Ok(())
}

fn push_predicates(
    output: &mut CanonicalArtifactEncoder,
    predicates: &[Predicate],
) -> Result<(), ArtifactEncodingError> {
    for (index, predicate) in predicates.iter().enumerate() {
        if index > 0 {
            output.push_byte(b',')?;
        }
        output.push_str("{\"receiver\":")?;
        push_json_string(output, predicate.receiver().as_str())?;
        output.push_str(",\"trait\":")?;
        push_trait_reference(output, predicate.trait_reference())?;
        output.push_byte(b'}')?;
    }
    Ok(())
}

fn push_concrete_identity(
    output: &mut CanonicalArtifactEncoder,
    identity: &ConcreteIdentity,
) -> Result<(), ArtifactEncodingError> {
    output.push_str("{\"kind\":")?;
    push_json_string(
        output,
        match identity {
            ConcreteIdentity::DeclaredType(_) => "declared-type",
            ConcreteIdentity::Callable(_) => "callable",
        },
    )?;
    output.push_str(",\"value\":")?;
    push_json_string(output, &identity.canonical_string())?;
    output.push_byte(b'}')?;
    Ok(())
}

fn push_span(
    output: &mut CanonicalArtifactEncoder,
    span: &SourceSpan,
) -> Result<(), ArtifactEncodingError> {
    output.push_str("{\"end\":\"")?;
    output.push_str(&span.bytes().end().to_string())?;
    output.push_str("\",\"path\":")?;
    push_json_string(output, span.source().package_path().as_str())?;
    output.push_str(",\"start\":\"")?;
    output.push_str(&span.bytes().start().to_string())?;
    output.push_str("\"}")?;
    Ok(())
}

fn push_position(
    output: &mut CanonicalArtifactEncoder,
    position: &StructuralPosition,
) -> Result<(), ArtifactEncodingError> {
    output.push_byte(b'[')?;
    for (index, component) in position.components().iter().enumerate() {
        if index > 0 {
            output.push_byte(b',')?;
        }
        output.push_byte(b'"')?;
        output.push_str(&component.to_string())?;
        output.push_byte(b'"')?;
    }
    output.push_byte(b']')?;
    Ok(())
}

fn push_json_string(
    output: &mut CanonicalArtifactEncoder,
    value: &str,
) -> Result<(), ArtifactEncodingError> {
    output.push_byte(b'"')?;
    for scalar in value.chars() {
        match scalar {
            '"' => output.push_str("\\\"")?,
            '\\' => output.push_str("\\\\")?,
            '\u{08}' => output.push_str("\\b")?,
            '\u{0c}' => output.push_str("\\f")?,
            '\n' => output.push_str("\\n")?,
            '\r' => output.push_str("\\r")?,
            '\t' => output.push_str("\\t")?,
            value if value <= '\u{1f}' => {
                output.push_str(&format!("\\u{:04x}", value as u32))?;
            }
            value => output.push_str(value.encode_utf8(&mut [0; 4]))?,
        }
    }
    output.push_byte(b'"')?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use gantry_core::source::{ByteSpan, SourceLimits, SourceSnapshotBuilder, SourceSpan};

    use super::{
        CanonicalIr, CanonicalNode, CanonicalOperationSite, CanonicalSourceMap, CanonicalWorkflow,
        SourceMapEntry,
    };
    use crate::generated::{ArtifactKind, CoreForm, Effect, OperationSiteKind};
    use crate::{
        ArtifactLimits, CanonicalPath, CanonicalSignature, EffectSet, StructuralPosition,
        TypeDescriptor,
    };

    fn limits(limit: u64) -> ArtifactLimits {
        ArtifactLimits {
            package_source_manifest_bytes: limit,
            canonical_ir_bytes: limit,
            source_map_bytes: limit,
            generated_schema_bytes: limit,
        }
    }

    #[test]
    fn canonical_ir_excludes_source_locations_and_preserves_effect_order() {
        let path = CanonicalPath::new("crate::main")
            .unwrap_or_else(|_| unreachable!("constant path is canonical"));
        let signature = CanonicalSignature::function(&path, &[], &TypeDescriptor::UNIT);
        let mut effects = EffectSet::default();
        assert!(effects.insert(Effect::Attempt));
        assert!(effects.insert(Effect::Prompt));
        let node = CanonicalNode {
            position: StructuralPosition::new(vec![0])
                .unwrap_or_else(|_| unreachable!("position is nonempty")),
            form: CoreForm::Operation,
            ty: TypeDescriptor::UNIT,
            children: Vec::new(),
            operation: Some(CanonicalOperationSite {
                kind: OperationSiteKind::Prompt,
                action: None,
                recovery: None,
                template_segments: Vec::new(),
                interpolation_inputs: Vec::new(),
                named_input_names: Vec::new(),
                named_inputs: Vec::new(),
            }),
            task_control: None,
        };
        let workflow = CanonicalWorkflow::new(path, signature, effects, vec![node]);
        assert!(workflow.is_ok());
        let ir = CanonicalIr::new(
            vec![workflow.unwrap_or_else(|_| unreachable!("checked above"))],
            limits(4_096),
        );
        assert!(ir.is_ok());
        let ir = ir.unwrap_or_else(|_| unreachable!("checked above"));
        assert_eq!(ir.artifact().kind(), ArtifactKind::CanonicalIr);
        let text = std::str::from_utf8(ir.artifact().canonical_bytes());
        assert!(text.is_ok_and(|text| {
            text.contains("\"effects\":[\"prompt\",\"attempt\"]") && !text.contains("main.gnt")
        }));
    }

    #[test]
    fn source_map_retains_exact_bytes_outside_ir_identity() {
        let source_limits =
            SourceLimits::new(1, 64, 64, 1, 1).unwrap_or_else(|_| unreachable!("positive limits"));
        let mut builder = SourceSnapshotBuilder::new(source_limits);
        let source = builder.add_file("main.gnt", b"fn main() {}");
        assert!(source.is_ok());
        let snapshot = builder.finish();
        let record = snapshot
            .get(&source.unwrap_or_else(|_| unreachable!("checked above")))
            .unwrap_or_else(|| unreachable!("source is retained"));
        let span = SourceSpan::new(
            record,
            ByteSpan::new(3, 7).unwrap_or_else(|_| unreachable!("ordered span")),
        )
        .unwrap_or_else(|_| unreachable!("span is in bounds"));
        let entry = SourceMapEntry {
            workflow: CanonicalPath::new("crate::main")
                .unwrap_or_else(|_| unreachable!("constant path is canonical")),
            position: StructuralPosition::new(vec![0])
                .unwrap_or_else(|_| unreachable!("position is nonempty")),
            source: span,
        };
        let map = CanonicalSourceMap::new(vec![entry], limits(4_096));
        assert!(map.is_ok());
        let map = map.unwrap_or_else(|_| unreachable!("checked above"));
        assert_eq!(map.artifact().kind(), ArtifactKind::SourceMap);
        assert!(
            std::str::from_utf8(map.artifact().canonical_bytes()).is_ok_and(|text| {
                text.contains("\"path\":\"main.gnt\"")
                    && text.contains("\"start\":\"3\"")
                    && text.contains("\"position\":[\"0\"]")
            })
        );
    }
}
