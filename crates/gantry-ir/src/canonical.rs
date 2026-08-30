//! Canonical IR and source-map artifacts over analyzer-owned facts.

use gantry_core::source::SourceSpan;

use crate::artifact::{
    ArtifactEncodingError, ArtifactLimits, BoundedArtifact, CanonicalArtifactEncoder,
};
use crate::generated::{ArtifactKind, CoreForm};
use crate::{CanonicalPath, CanonicalSignature, EffectSet, StructuralPosition, TypeDescriptor};

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
    artifact: BoundedArtifact,
}

impl CanonicalIr {
    /// Encodes workflows in canonical path order under the IR byte limit.
    pub fn new(
        workflows: Vec<CanonicalWorkflow>,
        limits: ArtifactLimits,
    ) -> Result<Self, IrArtifactError> {
        if workflows
            .windows(2)
            .any(|pair| pair[0].path >= pair[1].path)
        {
            return Err(IrArtifactError::NoncanonicalOrder);
        }
        let artifact = encode_ir(&workflows, limits).map_err(IrArtifactError::Encoding)?;
        Ok(Self {
            workflows,
            artifact,
        })
    }

    /// Returns workflows in canonical path order.
    #[must_use]
    pub fn workflows(&self) -> &[CanonicalWorkflow] {
        &self.workflows
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
    artifact: BoundedArtifact,
}

impl CanonicalSourceMap {
    /// Encodes entries ordered by workflow and structural position.
    pub fn new(
        entries: Vec<SourceMapEntry>,
        limits: ArtifactLimits,
    ) -> Result<Self, IrArtifactError> {
        if entries.windows(2).any(|pair| {
            (&pair[0].workflow, &pair[0].position) >= (&pair[1].workflow, &pair[1].position)
        }) {
            return Err(IrArtifactError::NoncanonicalOrder);
        }
        let artifact = encode_source_map(&entries, limits).map_err(IrArtifactError::Encoding)?;
        Ok(Self { entries, artifact })
    }

    /// Returns entries in canonical structural order.
    #[must_use]
    pub fn entries(&self) -> &[SourceMapEntry] {
        &self.entries
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
    limits: ArtifactLimits,
) -> Result<BoundedArtifact, ArtifactEncodingError> {
    let mut output = CanonicalArtifactEncoder::new(ArtifactKind::CanonicalIr, limits);
    output.push_str("{\"canonical_ir\":{\"major\":1,\"minor\":0},\"workflows\":[")?;
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
            output.push_str(",\"position\":")?;
            push_position(&mut output, &node.position)?;
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
    output.push_str("],\"source_map\":{\"major\":1,\"minor\":0}}")?;
    output.finish()
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
        CanonicalIr, CanonicalNode, CanonicalSourceMap, CanonicalWorkflow, SourceMapEntry,
    };
    use crate::generated::{ArtifactKind, CoreForm, Effect};
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
