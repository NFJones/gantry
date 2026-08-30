//! Canonical declaration-type resolution and recursive-type validation.
//!
//! The pass consumes arena-backed syntax in construction order, so nested
//! annotations and declared-type graphs are processed with explicit work
//! collections rather than native recursion. Body expression typing, pattern
//! coverage, and completion analysis remain later stages of the same crate.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use gantry_core::portable::{DiagnosticCategory, DiagnosticSeverity};
use gantry_core::source::{
    DiagnosticCode, DiagnosticMetadata, DiagnosticPhase, SourceSpan, StructuredDiagnostic,
};
use gantry_frontend::{
    CompletedSyntaxPhase, NodeId, ParsedSource, SyntaxForm, SyntaxTree, TokenKind,
};
use gantry_ir::generated::TypeKind;
use gantry_ir::{TypeDescriptor, TypeDescriptorError};

use crate::bodies::check_package_bodies;
use crate::{
    AnalysisError, AnalysisStatus, PackageStructure, Symbol, SymbolId, SymbolKind, TypeFact,
    TypedPackage, analyze_package_structure,
};

/// One declared-type reference within a source annotation.
#[derive(Clone, Debug)]
struct DeclaredUse {
    target: SymbolId,
    guarded: bool,
    span: SourceSpan,
}

/// One edge in the declared struct/enum dependency graph.
#[derive(Clone, Debug)]
struct TypeEdge {
    target: SymbolId,
    guarded: bool,
    span: SourceSpan,
}

/// Resolves and validates package declaration types without performing body
/// expression typing, ownership inference, effects, or lowering.
pub fn analyze_package_types(phase: &CompletedSyntaxPhase) -> Result<TypedPackage, AnalysisError> {
    let structure = analyze_package_structure(phase)?;
    let mut diagnostics = structure.diagnostics().to_vec();
    let mut type_diagnostics = Vec::new();
    let mut facts = Vec::new();
    let mut facts_by_source = Vec::new();

    for source in phase.parsed_sources() {
        let parsed = resolve_source_types(source, &structure, &mut type_diagnostics)?;
        facts.extend(parsed.values().cloned());
        facts_by_source.push(parsed);
    }

    check_recursive_declarations(
        phase.parsed_sources(),
        &structure,
        &facts_by_source,
        &mut type_diagnostics,
    )?;
    check_sealed_boundaries(
        phase.parsed_sources(),
        &structure,
        &facts_by_source,
        &mut type_diagnostics,
    )?;
    check_impl_targets(phase.parsed_sources(), &structure, &mut type_diagnostics)?;
    check_entry_and_field_defaults(
        phase.parsed_sources(),
        &structure,
        &facts_by_source,
        &mut type_diagnostics,
    )?;
    check_package_bodies(
        phase.parsed_sources(),
        &facts_by_source,
        &structure,
        &mut type_diagnostics,
    )?;

    facts.sort_by(|left, right| left.span.cmp(&right.span));
    facts.dedup_by(|left, right| left.span == right.span);
    diagnostics.append(&mut type_diagnostics);
    diagnostics.sort();
    diagnostics.dedup();

    let mut counters = phase.snapshot().counters().clone();
    let mut retained = Vec::with_capacity(diagnostics.len());
    for diagnostic in diagnostics {
        if let Err(error) = counters.charge_diagnostic() {
            return Err(AnalysisError::ResourceLimit {
                error,
                diagnostics: retained,
            });
        }
        retained.push(diagnostic);
    }
    let status = if retained
        .iter()
        .any(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error)
    {
        AnalysisStatus::Invalid
    } else {
        AnalysisStatus::Valid
    };
    Ok(TypedPackage {
        status,
        structure,
        types: facts,
        diagnostics: retained,
        counters,
    })
}

/// Resolves every value-type node in arena construction order. Child type
/// nodes are completed before the parent that owns them.
fn resolve_source_types(
    source: &ParsedSource,
    structure: &PackageStructure,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<BTreeMap<NodeId, TypeFact>, AnalysisError> {
    let references = structure
        .references()
        .iter()
        .map(|reference| (reference.span.clone(), reference.target))
        .collect::<BTreeMap<_, _>>();
    let symbols = structure
        .symbols()
        .iter()
        .map(|symbol| (symbol.id, symbol))
        .collect::<BTreeMap<_, _>>();
    let mut resolved = BTreeMap::<NodeId, TypeFact>::new();

    for (index, node) in source.tree().nodes().iter().enumerate() {
        if !matches!(node.form(), SyntaxForm::ValueType) {
            continue;
        }
        let id = NodeId::from_index(index);
        if let Some(descriptor) = resolve_type_node(
            source.tree(),
            id,
            &resolved,
            &references,
            &symbols,
            diagnostics,
        )? {
            resolved.insert(
                id,
                TypeFact {
                    span: node.span().clone(),
                    descriptor,
                },
            );
        }
    }
    Ok(resolved)
}

/// Resolves one type node after all nested member nodes have been processed.
fn resolve_type_node(
    tree: &SyntaxTree,
    id: NodeId,
    resolved: &BTreeMap<NodeId, TypeFact>,
    references: &BTreeMap<SourceSpan, SymbolId>,
    symbols: &BTreeMap<SymbolId, &Symbol>,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<Option<TypeDescriptor>, AnalysisError> {
    let node = tree.node(id).ok_or(AnalysisError::Invariant)?;
    let word = direct_reserved_word(tree, id)?;
    let members = node
        .children()
        .iter()
        .copied()
        .filter(|child| {
            tree.node(*child)
                .is_some_and(|node| matches!(node.form(), SyntaxForm::ValueType))
        })
        .map(|child| resolved.get(&child).map(|fact| fact.descriptor.clone()))
        .collect::<Option<Vec<_>>>();

    let descriptor = match word.as_deref() {
        Some("Unit") => Some(TypeDescriptor::UNIT),
        Some("Bool") => Some(TypeDescriptor::BOOL),
        Some("Int") => Some(TypeDescriptor::INT),
        Some("Float") => Some(TypeDescriptor::FLOAT),
        Some("String") => Some(TypeDescriptor::STRING),
        Some("Decision") => Some(TypeDescriptor::DECISION),
        Some("OperationError") => Some(TypeDescriptor::OPERATION_ERROR),
        Some("Option") => {
            let Some(mut members) = members else {
                return Ok(None);
            };
            let member = members.pop().ok_or(AnalysisError::Invariant)?;
            match TypeDescriptor::option(member) {
                Ok(descriptor) => Some(descriptor),
                Err(TypeDescriptorError::InvalidOptionMember) => {
                    diagnostics.push(type_diagnostic(
                        "invalid-option-type",
                        "Option has an ambiguous immediate member type",
                        node.span().clone(),
                        [("type", "Option")],
                    )?);
                    None
                }
                Err(TypeDescriptorError::TupleArity) => return Err(AnalysisError::Invariant),
            }
        }
        Some("List") => {
            let Some(mut members) = members else {
                return Ok(None);
            };
            Some(TypeDescriptor::list(
                members.pop().ok_or(AnalysisError::Invariant)?,
            ))
        }
        Some("Result") => {
            let Some(members) = members else {
                return Ok(None);
            };
            if members.len() != 2 {
                return Err(AnalysisError::Invariant);
            }
            Some(TypeDescriptor::result(
                members[0].clone(),
                members[1].clone(),
            ))
        }
        Some("Tuple") => {
            let Some(members) = members else {
                return Ok(None);
            };
            TypeDescriptor::tuple(members).ok()
        }
        Some(_) => return Err(AnalysisError::Invariant),
        None => {
            let path = node
                .children()
                .iter()
                .filter_map(|child| tree.node(*child))
                .find(|child| matches!(child.form(), SyntaxForm::Path));
            let Some(path) = path else {
                return Err(AnalysisError::Invariant);
            };
            let Some(target) = references.get(path.span()).copied() else {
                return Ok(None);
            };
            let symbol = symbols.get(&target).ok_or(AnalysisError::Invariant)?;
            if !matches!(symbol.kind, SymbolKind::Struct | SymbolKind::Enum) {
                diagnostics.push(type_diagnostic(
                    "expected-type",
                    "a type annotation resolves to a non-type item",
                    path.span().clone(),
                    [("canonical_path", symbol.path.as_str())],
                )?);
                None
            } else {
                Some(TypeDescriptor::declared(symbol.path.clone()))
            }
        }
    };
    Ok(descriptor)
}

/// Validates self recursion guards and rejects every cycle involving multiple
/// declared types or an enum payload.
fn check_recursive_declarations(
    sources: &[ParsedSource],
    structure: &PackageStructure,
    facts: &[BTreeMap<NodeId, TypeFact>],
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<(), AnalysisError> {
    let references = structure
        .references()
        .iter()
        .map(|reference| (reference.span.clone(), reference.target))
        .collect::<BTreeMap<_, _>>();
    let symbol_by_span = structure
        .symbols()
        .iter()
        .map(|symbol| (symbol.span.clone(), symbol))
        .collect::<BTreeMap<_, _>>();
    let symbol_by_id = structure
        .symbols()
        .iter()
        .map(|symbol| (symbol.id, symbol))
        .collect::<BTreeMap<_, _>>();
    let mut graph = BTreeMap::<SymbolId, Vec<TypeEdge>>::new();

    for (source_index, source) in sources.iter().enumerate() {
        let resolved = facts.get(source_index).ok_or(AnalysisError::Invariant)?;
        for node in source.tree().nodes() {
            if !matches!(
                node.form(),
                SyntaxForm::StructDeclaration | SyntaxForm::EnumDeclaration
            ) {
                continue;
            }
            let Some(name_span) = direct_identifier_span(source.tree(), node)? else {
                return Err(AnalysisError::Invariant);
            };
            let Some(owner) = symbol_by_span.get(&name_span).copied() else {
                continue;
            };
            for member in node.children().iter().copied() {
                let Some(member_node) = source.tree().node(member) else {
                    return Err(AnalysisError::Invariant);
                };
                if !matches!(
                    member_node.form(),
                    SyntaxForm::StructField | SyntaxForm::EnumVariant
                ) {
                    continue;
                }
                for type_node in member_node.children().iter().copied().filter(|child| {
                    source
                        .tree()
                        .node(*child)
                        .is_some_and(|node| matches!(node.form(), SyntaxForm::ValueType))
                }) {
                    if !resolved.contains_key(&type_node) {
                        continue;
                    }
                    for usage in declared_uses(source.tree(), type_node, &references)? {
                        if symbol_by_id.get(&usage.target).is_some_and(|symbol| {
                            matches!(symbol.kind, SymbolKind::Struct | SymbolKind::Enum)
                        }) {
                            graph.entry(owner.id).or_default().push(TypeEdge {
                                target: usage.target,
                                guarded: usage.guarded,
                                span: usage.span,
                            });
                        }
                    }
                }
            }
        }
    }

    for (owner, edges) in &graph {
        let owner_symbol = symbol_by_id.get(owner).ok_or(AnalysisError::Invariant)?;
        for edge in edges {
            if edge.target == *owner {
                if owner_symbol.kind == SymbolKind::Enum {
                    diagnostics.push(type_diagnostic(
                        "recursive-enum",
                        "an enum payload recursively contains its declaring enum",
                        edge.span.clone(),
                        [("canonical_path", owner_symbol.path.as_str())],
                    )?);
                } else if !edge.guarded {
                    diagnostics.push(type_diagnostic(
                        "unguarded-recursive-type",
                        "a self-recursive struct field is not guarded by Option or List",
                        edge.span.clone(),
                        [("canonical_path", owner_symbol.path.as_str())],
                    )?);
                }
            } else if reaches(edge.target, *owner, &graph) {
                diagnostics.push(type_diagnostic(
                    "recursive-type-cycle",
                    "a cycle contains more than one declared type",
                    edge.span.clone(),
                    [("canonical_path", owner_symbol.path.as_str())],
                )?);
            }
        }
    }
    Ok(())
}

/// Collects declared references under one annotation with explicit guard
/// state propagated through Option and List nodes.
fn declared_uses(
    tree: &SyntaxTree,
    root: NodeId,
    references: &BTreeMap<SourceSpan, SymbolId>,
) -> Result<Vec<DeclaredUse>, AnalysisError> {
    let mut uses = Vec::new();
    let mut work = vec![(root, false)];
    while let Some((id, guarded)) = work.pop() {
        let node = tree.node(id).ok_or(AnalysisError::Invariant)?;
        let word = direct_reserved_word(tree, id)?;
        let nested_guard = guarded || matches!(word.as_deref(), Some("Option" | "List"));
        for child in node.children().iter().rev().copied() {
            let child_node = tree.node(child).ok_or(AnalysisError::Invariant)?;
            match child_node.form() {
                SyntaxForm::ValueType => work.push((child, nested_guard)),
                SyntaxForm::Path => {
                    if let Some(target) = references.get(child_node.span()).copied() {
                        uses.push(DeclaredUse {
                            target,
                            guarded,
                            span: child_node.span().clone(),
                        });
                    }
                }
                _ => {}
            }
        }
    }
    Ok(uses)
}

/// Returns whether the declared-type graph can reach one target.
fn reaches(start: SymbolId, target: SymbolId, graph: &BTreeMap<SymbolId, Vec<TypeEdge>>) -> bool {
    let mut work = vec![start];
    let mut seen = BTreeSet::new();
    while let Some(current) = work.pop() {
        if current == target {
            return true;
        }
        if !seen.insert(current) {
            continue;
        }
        if let Some(edges) = graph.get(&current) {
            work.extend(edges.iter().map(|edge| edge.target));
        }
    }
    false
}

/// Rejects sealed Decision and OperationError types at operation and package
/// entry boundaries while retaining them for ordinary declarations.
fn check_sealed_boundaries(
    sources: &[ParsedSource],
    structure: &PackageStructure,
    facts: &[BTreeMap<NodeId, TypeFact>],
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<(), AnalysisError> {
    let root_main = structure
        .symbols()
        .iter()
        .find(|symbol| symbol.path.as_str() == "crate::main");
    if root_main.is_none() || root_main.is_some_and(|symbol| symbol.kind != SymbolKind::Function) {
        let span = structure
            .modules()
            .first()
            .map(|module| module.span.clone())
            .ok_or(AnalysisError::Invariant)?;
        diagnostics.push(type_diagnostic(
            "invalid-entry-point",
            "the root module must declare exactly one function named main",
            span,
            [] as [(&str, &str); 0],
        )?);
    }

    for (source_index, source) in sources.iter().enumerate() {
        let resolved = facts.get(source_index).ok_or(AnalysisError::Invariant)?;
        for node in source.tree().nodes() {
            let context = match node.form() {
                SyntaxForm::ActionDeclaration => Some("action-result"),
                SyntaxForm::PromptExpression => Some("prompt-result"),
                SyntaxForm::FunctionDeclaration
                    if root_main.is_some_and(|main| {
                        direct_identifier_span(source.tree(), node)
                            .ok()
                            .flatten()
                            .is_some_and(|span| span == main.span)
                    }) =>
                {
                    Some("entry")
                }
                _ => None,
            };
            let Some(context) = context else {
                continue;
            };
            let type_nodes = if context == "entry" {
                descendant_type_roots(source.tree(), node)?
            } else {
                node.children()
                    .iter()
                    .copied()
                    .filter(|child| {
                        source
                            .tree()
                            .node(*child)
                            .is_some_and(|node| matches!(node.form(), SyntaxForm::ValueType))
                    })
                    .collect()
            };
            for type_node in type_nodes {
                let Some(fact) = resolved.get(&type_node) else {
                    continue;
                };
                if fact.descriptor.contains_sealed_boundary() {
                    diagnostics.push(type_diagnostic(
                        "sealed-type-boundary",
                        "Decision or OperationError is not permitted at this boundary",
                        fact.span.clone(),
                        [
                            ("context", context.to_owned()),
                            ("type", fact.descriptor.canonical_string()),
                        ],
                    )?);
                }
            }
        }
    }
    Ok(())
}

/// Requires every inherent implementation target to resolve to a package struct.
fn check_impl_targets(
    sources: &[ParsedSource],
    structure: &PackageStructure,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<(), AnalysisError> {
    let references = structure
        .references()
        .iter()
        .map(|reference| (reference.span.clone(), reference.target))
        .collect::<BTreeMap<_, _>>();
    let symbols = structure
        .symbols()
        .iter()
        .map(|symbol| (symbol.id, symbol))
        .collect::<BTreeMap<_, _>>();
    for source in sources {
        for implementation in source
            .tree()
            .nodes()
            .iter()
            .filter(|node| matches!(node.form(), SyntaxForm::ImplDeclaration))
        {
            let Some(path) = implementation
                .children()
                .iter()
                .filter_map(|child| {
                    let node = source.tree().node(*child)?;
                    matches!(node.form(), SyntaxForm::Path).then_some(node)
                })
                .next()
            else {
                return Err(AnalysisError::Invariant);
            };
            let Some(target) = references.get(path.span()) else {
                continue;
            };
            let symbol = symbols.get(target).ok_or(AnalysisError::Invariant)?;
            if symbol.kind != SymbolKind::Struct {
                diagnostics.push(type_diagnostic(
                    "invalid-impl-target",
                    "an inherent implementation target is not a package struct",
                    path.span().clone(),
                    [("canonical_path", symbol.path.as_str())],
                )?);
            }
        }
    }
    Ok(())
}

/// Validates the root entry arity and every source field default against its
/// exact declared scalar or optional-member type.
fn check_entry_and_field_defaults(
    sources: &[ParsedSource],
    structure: &PackageStructure,
    facts: &[BTreeMap<NodeId, TypeFact>],
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<(), AnalysisError> {
    let root_main = structure.symbols().iter().find(|symbol| {
        symbol.path.as_str() == "crate::main" && symbol.kind == SymbolKind::Function
    });

    for (source_index, source) in sources.iter().enumerate() {
        let resolved = facts.get(source_index).ok_or(AnalysisError::Invariant)?;
        for node in source.tree().nodes() {
            match node.form() {
                SyntaxForm::FunctionDeclaration
                    if root_main.is_some_and(|main| {
                        direct_identifier_span(source.tree(), node)
                            .ok()
                            .flatten()
                            .is_some_and(|span| span == main.span)
                    }) =>
                {
                    let parameters =
                        node.children()
                            .iter()
                            .filter(|child| {
                                source.tree().node(**child).is_some_and(|node| {
                                    matches!(node.form(), SyntaxForm::Parameter)
                                })
                            })
                            .count();
                    if parameters > 1 {
                        diagnostics.push(type_diagnostic(
                            "invalid-entry-point",
                            "the root main function accepts more than one parameter",
                            node.span().clone(),
                            [("parameter_count", parameters.to_string())],
                        )?);
                    }
                }
                SyntaxForm::StructField => {
                    let Some(type_node) = node.children().iter().copied().find(|child| {
                        source
                            .tree()
                            .node(*child)
                            .is_some_and(|node| matches!(node.form(), SyntaxForm::ValueType))
                    }) else {
                        return Err(AnalysisError::Invariant);
                    };
                    let Some(fact) = resolved.get(&type_node) else {
                        continue;
                    };
                    if has_direct_punctuation(
                        source.tree(),
                        node,
                        gantry_frontend::Punctuation::Equal,
                    ) && !field_default_matches(source.tree(), node, &fact.descriptor)?
                    {
                        diagnostics.push(type_diagnostic(
                            "invalid-field-default",
                            "a field default does not exactly match its declared type",
                            node.span().clone(),
                            [("type", fact.descriptor.canonical_string())],
                        )?);
                    }
                }
                _ => {}
            }
        }
    }
    Ok(())
}

fn field_default_matches(
    tree: &SyntaxTree,
    field: &gantry_frontend::SyntaxNode,
    declared: &TypeDescriptor,
) -> Result<bool, AnalysisError> {
    let equal = field
        .children()
        .iter()
        .position(|child| {
            tree.node(*child).is_some_and(|node| {
                matches!(
                    node.form(),
                    SyntaxForm::Token(TokenKind::Punctuation(gantry_frontend::Punctuation::Equal))
                )
            })
        })
        .ok_or(AnalysisError::Invariant)?;
    let tokens = field
        .children()
        .get(equal.saturating_add(1)..)
        .unwrap_or_default()
        .iter()
        .filter_map(|child| tree.node(*child))
        .map(gantry_frontend::SyntaxNode::form)
        .collect::<Vec<_>>();
    let is_unit = tokens.iter().any(|form| {
        matches!(
            form,
            SyntaxForm::Token(TokenKind::Punctuation(
                gantry_frontend::Punctuation::LeftParenthesis
            ))
        )
    });
    let scalar = tokens.iter().find_map(|form| match form {
        SyntaxForm::Token(TokenKind::IntegerLiteral(_)) => Some(TypeKind::Int),
        SyntaxForm::Token(TokenKind::FloatLiteral(_)) => Some(TypeKind::Float),
        SyntaxForm::Token(TokenKind::StringLiteral(_) | TokenKind::RawStringLiteral(_)) => {
            Some(TypeKind::String)
        }
        SyntaxForm::Token(TokenKind::ReservedWord(word))
            if matches!(word.spelling(), "true" | "false") =>
        {
            Some(TypeKind::Bool)
        }
        _ => None,
    });
    let is_none = tokens.iter().any(|form| {
        matches!(
            form,
            SyntaxForm::Token(TokenKind::ReservedWord(word)) if word.spelling() == "None"
        )
    });
    if declared.kind() == TypeKind::Option {
        if is_none {
            return Ok(true);
        }
        return Ok(declared
            .immediate_members()
            .first()
            .is_some_and(|member| scalar == Some(member.kind())));
    }
    Ok((is_unit && declared.kind() == TypeKind::Unit) || scalar == Some(declared.kind()))
}

fn has_direct_punctuation(
    tree: &SyntaxTree,
    node: &gantry_frontend::SyntaxNode,
    punctuation: gantry_frontend::Punctuation,
) -> bool {
    node.children().iter().any(|child| {
        tree.node(*child).is_some_and(|node| {
            matches!(
                node.form(),
                SyntaxForm::Token(TokenKind::Punctuation(value)) if *value == punctuation
            )
        })
    })
}

/// Returns outer annotation nodes below a declaration without traversing its
/// executable block.
fn descendant_type_roots(
    tree: &SyntaxTree,
    declaration: &gantry_frontend::SyntaxNode,
) -> Result<Vec<NodeId>, AnalysisError> {
    let mut roots = Vec::new();
    let mut work = declaration
        .children()
        .iter()
        .rev()
        .copied()
        .collect::<Vec<_>>();
    while let Some(id) = work.pop() {
        let node = tree.node(id).ok_or(AnalysisError::Invariant)?;
        if matches!(node.form(), SyntaxForm::Block) {
            continue;
        }
        if matches!(node.form(), SyntaxForm::ValueType) {
            roots.push(id);
            continue;
        }
        work.extend(node.children().iter().rev().copied());
    }
    Ok(roots)
}

/// Returns a direct reserved-word token from one syntax node.
fn direct_reserved_word(tree: &SyntaxTree, id: NodeId) -> Result<Option<String>, AnalysisError> {
    let node = tree.node(id).ok_or(AnalysisError::Invariant)?;
    Ok(node
        .children()
        .iter()
        .filter_map(|child| tree.node(*child))
        .find_map(|child| match child.form() {
            SyntaxForm::Token(TokenKind::ReservedWord(word)) => Some(word.spelling().to_owned()),
            _ => None,
        }))
}

/// Returns the first direct identifier span from one declaration-like node.
fn direct_identifier_span(
    tree: &SyntaxTree,
    node: &gantry_frontend::SyntaxNode,
) -> Result<Option<SourceSpan>, AnalysisError> {
    Ok(node
        .children()
        .iter()
        .filter_map(|child| tree.node(*child))
        .find_map(|child| match child.form() {
            SyntaxForm::Token(TokenKind::Identifier(_)) => Some(child.span().clone()),
            _ => None,
        }))
}

/// Constructs one source-backed type-category diagnostic.
fn type_diagnostic<K, V, const N: usize>(
    code: &str,
    message: &str,
    primary: SourceSpan,
    fields: [(K, V); N],
) -> Result<StructuredDiagnostic, AnalysisError>
where
    K: AsRef<str>,
    V: AsRef<str>,
{
    let fields = fields
        .into_iter()
        .map(|(key, value)| (Arc::from(key.as_ref()), Arc::from(value.as_ref())))
        .collect::<BTreeMap<_, _>>();
    StructuredDiagnostic::new(
        DiagnosticMetadata {
            phase: DiagnosticPhase::Analysis,
            severity: DiagnosticSeverity::Error,
            category: DiagnosticCategory::Type,
            code: DiagnosticCode::new(code).map_err(|_| AnalysisError::Invariant)?,
        },
        message,
        Some(primary),
        Vec::new(),
        fields,
    )
    .map_err(|_| AnalysisError::Invariant)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use gantry_core::source::SourceLimits;
    use gantry_frontend::validate_package_syntax;

    use super::analyze_package_types;
    use crate::AnalysisStatus;

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    struct TempDirectory(PathBuf);

    impl TempDirectory {
        fn new() -> Self {
            let suffix = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "gantry-type-analysis-{}-{suffix}",
                std::process::id()
            ));
            assert!(fs::create_dir(&path).is_ok());
            Self(path)
        }

        fn write(&self, source: &str) {
            assert!(fs::write(self.0.join("main.gnt"), source).is_ok());
        }
    }

    impl Drop for TempDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn analyze(source: &str) -> crate::TypedPackage {
        let root = TempDirectory::new();
        root.write(source);
        let limits = SourceLimits::new(4, 65_536, 65_536, 65_536, 64)
            .unwrap_or_else(|_| unreachable!("positive limits"));
        let syntax = validate_package_syntax(&root.0, limits)
            .unwrap_or_else(|error| panic!("syntax failed: {error:?}"));
        analyze_package_types(&syntax)
            .unwrap_or_else(|error| panic!("type analysis failed: {error:?}"))
    }

    #[test]
    fn canonical_annotations_and_guarded_self_recursion_are_resolved() {
        let package = analyze(
            "struct Node { next: Option<Node>, values: List<Result<String,Int>> }\nfn main(value: Node) -> Node { value }",
        );
        assert_eq!(package.status(), AnalysisStatus::Valid);
        let descriptors = package
            .types()
            .iter()
            .map(|fact| fact.descriptor.canonical_string())
            .collect::<Vec<_>>();
        assert!(descriptors.contains(&"Option<crate::Node>".to_owned()));
        assert!(descriptors.contains(&"List<Result<String,Int>>".to_owned()));
        assert!(descriptors.contains(&"crate::Node".to_owned()));
    }

    #[test]
    fn invalid_options_cycles_and_sealed_boundaries_are_diagnosed() {
        let package = analyze(
            "struct Bad { value: Option<Unit> }\nstruct Left { right: Right }\nstruct Right { left: Left }\nenum Recursive { Next(Recursive) }\nfn main(value: Decision) -> OperationError { value }",
        );
        assert_eq!(package.status(), AnalysisStatus::Invalid);
        let codes = package
            .diagnostics()
            .iter()
            .map(|diagnostic| diagnostic.code.as_str())
            .collect::<Vec<_>>();
        assert!(codes.contains(&"invalid-option-type"));
        assert!(codes.contains(&"recursive-type-cycle"));
        assert!(codes.contains(&"recursive-enum"));
        assert!(codes.contains(&"sealed-type-boundary"));
    }

    #[test]
    fn body_types_and_completion_must_match_declared_results() {
        let mismatch = analyze("fn main() -> Int { \"wrong\" }");
        assert_eq!(mismatch.status(), AnalysisStatus::Invalid);
        assert!(
            mismatch
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code.as_str() == "type-mismatch")
        );

        let incomplete = analyze("fn main(flag: Bool) -> Int { if flag { return 1; } }");
        assert_eq!(incomplete.status(), AnalysisStatus::Invalid);
        assert!(
            incomplete
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code.as_str() == "missing-result")
        );

        let unreachable = analyze("fn main() { return; let value: Int = 1; }");
        assert_eq!(unreachable.status(), AnalysisStatus::Invalid);
        assert!(
            unreachable
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code.as_str() == "unreachable-source")
        );
    }

    #[test]
    fn option_matches_are_typed_nonredundant_and_exhaustive() {
        let valid = analyze(
            "fn main(value: Option<Int>) -> Int { match value { Some(item) => item, None => 0 } }",
        );
        assert_eq!(
            valid.status(),
            AnalysisStatus::Valid,
            "{:?}",
            valid.diagnostics()
        );

        let missing =
            analyze("fn main(value: Option<Int>) -> Int { match value { Some(item) => item } }");
        assert_eq!(missing.status(), AnalysisStatus::Invalid);
        assert!(
            missing
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code.as_str() == "nonexhaustive-match")
        );

        let redundant =
            analyze("fn main(value: Option<Int>) -> Int { match value { _ => 1, None => 0 } }");
        assert_eq!(redundant.status(), AnalysisStatus::Invalid);
        assert!(
            redundant
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code.as_str() == "redundant-pattern")
        );
    }

    #[test]
    fn primitives_conditions_and_numeric_literals_have_exact_types() {
        let valid =
            analyze("fn compare(left: Int, right: Int) -> Bool { left + right == 3 } fn main() {}");
        assert_eq!(
            valid.status(),
            AnalysisStatus::Valid,
            "{:?}",
            valid.diagnostics()
        );

        let mixed = analyze("fn main() -> Int { 1 + \"wrong\" }");
        assert_eq!(mixed.status(), AnalysisStatus::Invalid);
        assert!(
            mixed
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code.as_str() == "invalid-primitive")
        );

        let condition = analyze("fn main() { if 1 {} }");
        assert_eq!(condition.status(), AnalysisStatus::Invalid);
        assert!(
            condition
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code.as_str() == "condition-type")
        );

        let range = analyze("fn main() -> Int { 9007199254740992 }");
        assert_eq!(range.status(), AnalysisStatus::Invalid);
        assert!(
            range
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code.as_str() == "integer-literal-out-of-range")
        );
    }

    #[test]
    fn workflow_calls_enforce_signature_arity_and_argument_types() {
        let valid =
            analyze("fn identity(value: Int) -> Int { value } fn main() -> Int { identity(1) }");
        assert_eq!(
            valid.status(),
            AnalysisStatus::Valid,
            "{:?}",
            valid.diagnostics()
        );

        let arity =
            analyze("fn identity(value: Int) -> Int { value } fn main() -> Int { identity() }");
        assert_eq!(arity.status(), AnalysisStatus::Invalid);
        assert!(
            arity
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code.as_str() == "call-arity")
        );

        let argument = analyze(
            "fn identity(value: Int) -> Int { value } fn main() -> Int { identity(\"wrong\") }",
        );
        assert_eq!(argument.status(), AnalysisStatus::Invalid);
        assert!(
            argument
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code.as_str() == "call-argument-type")
        );
    }

    #[test]
    fn omitted_results_remain_unit_when_parameters_are_typed() {
        let package = analyze("fn helper(value: Int) {} fn main(flag: Bool) {}");
        assert_eq!(
            package.status(),
            AnalysisStatus::Valid,
            "{:?}",
            package.diagnostics()
        );
    }

    #[test]
    fn aggregate_constructors_use_exact_expected_member_types() {
        let valid = analyze(
            r#"
struct Pair { left: Int, right: Option<String> = None }
fn main() -> Pair {
    let tuple: Tuple<Int,String> = (1, "value");
    let list: List<Int> = [];
    let optional: Option<Int> = Some(1);
    Pair { left: tuple[0] }
}
"#,
        );
        assert_eq!(
            valid.status(),
            AnalysisStatus::Valid,
            "{:?}",
            valid.diagnostics()
        );

        let invalid = analyze(
            r#"
struct Pair { left: Int }
fn main() -> Pair {
    let list: List<Int> = [1, "wrong"];
    let optional: Option<Int> = Some("wrong");
    Pair { left: "wrong", extra: 1 }
}
"#,
        );
        assert_eq!(invalid.status(), AnalysisStatus::Invalid);
        let codes = invalid
            .diagnostics()
            .iter()
            .map(|diagnostic| diagnostic.code.as_str())
            .collect::<Vec<_>>();
        assert!(codes.contains(&"aggregate-member-type"));
        assert!(codes.contains(&"unknown-struct-field"));
    }

    #[test]
    fn tuple_patterns_if_let_and_loops_propagate_types_and_completion() {
        let valid = analyze(
            r#"
fn evaluate(value: Option<Tuple<Int,String>>, values: List<Int>) -> Int {
    let (first, _): Tuple<Int,String> = (1, "value");
    if let Some((number, _)) = value {
        return number;
    }
    for item in values {
        if item > first {
            return item;
        }
    }
    first
}
fn main() {}
"#,
        );
        assert_eq!(
            valid.status(),
            AnalysisStatus::Valid,
            "{:?}",
            valid.diagnostics()
        );

        let invalid = analyze(
            r#"
fn evaluate(value: Option<Int>, values: Int) -> Int {
    if let Some(item) = value {
        let wrong: String = item;
    }
    for item in values {
        return item;
    }
    0
}
fn main() {}
"#,
        );
        assert_eq!(invalid.status(), AnalysisStatus::Invalid);
        let codes = invalid
            .diagnostics()
            .iter()
            .map(|diagnostic| diagnostic.code.as_str())
            .collect::<Vec<_>>();
        assert!(codes.contains(&"type-mismatch"));
        assert!(codes.contains(&"for-source-type"));
    }

    #[test]
    fn result_and_enum_constructors_and_patterns_are_exact() {
        let valid = analyze(
            r#"
enum Outcome { Ready(Int), Empty }
fn evaluate(result: Result<Int,String>, outcome: Outcome) -> Int {
    let ok: Result<Int,String> = Ok(1);
    let err: Result<Int,String> = Err("bad");
    let made: Outcome = Outcome::Ready(2);
    let first: Int = match result { Ok(value) => value, Err(_) => 0 };
    match outcome { Outcome::Ready(value) => value + first, Outcome::Empty => first }
}
fn main() {}
"#,
        );
        assert_eq!(
            valid.status(),
            AnalysisStatus::Valid,
            "{:?}",
            valid.diagnostics()
        );

        let invalid = analyze(
            r#"
enum Outcome { Ready(Int), Empty }
fn evaluate(result: Result<Int,String>, outcome: Outcome) -> Int {
    let wrong_result: Result<Int,String> = Ok("wrong");
    let wrong_enum: Outcome = Outcome::Ready("wrong");
    let incomplete: Int = match result { Ok(value) => value };
    match outcome { Outcome::Ready(value) => value }
}
fn main() {}
"#,
        );
        assert_eq!(invalid.status(), AnalysisStatus::Invalid);
        let codes = invalid
            .diagnostics()
            .iter()
            .map(|diagnostic| diagnostic.code.as_str())
            .collect::<Vec<_>>();
        assert!(codes.contains(&"aggregate-member-type"));
        assert!(codes.contains(&"nonexhaustive-match"));
    }

    #[test]
    fn entry_arity_and_field_defaults_are_checked_exactly() {
        let valid = analyze(
            r#"
struct Config {
    unit: Unit = (),
    count: Int = 1,
    optional: Option<String> = None,
}
fn main(value: Config) -> Config { value }
"#,
        );
        assert_eq!(
            valid.status(),
            AnalysisStatus::Valid,
            "{:?}",
            valid.diagnostics()
        );

        let invalid = analyze(
            r#"
struct Bad {
    unit: Int = (),
    count: String = 1,
    absent: Int = None,
}
fn main(first: Int, second: Int) {}
"#,
        );
        assert_eq!(invalid.status(), AnalysisStatus::Invalid);
        let codes = invalid
            .diagnostics()
            .iter()
            .map(|diagnostic| diagnostic.code.as_str())
            .collect::<Vec<_>>();
        assert!(codes.contains(&"invalid-field-default"));
        assert!(codes.contains(&"invalid-entry-point"));
    }

    #[test]
    fn assignment_receiver_scope_and_loop_limits_are_checked() {
        let valid = analyze(
            r#"
struct Counter { value: Int }
impl Counter { fn increment(mut self) -> Counter { self.value += 1; self } }
fn helper() { let mut count: Int = 1; count += 1; loop(limit = 1) { break; } }
fn main() {}
"#,
        );
        assert_eq!(
            valid.status(),
            AnalysisStatus::Valid,
            "{:?}",
            valid.diagnostics()
        );

        let invalid = analyze(
            r#"
struct Counter { value: Int }
impl Counter { fn bad(self) { self.value = 1; } }
fn helper() {
    let count: Int = 1;
    count = 2;
    loop(limit = 0) { break; }
    continue;
}
fn main() { self; }
"#,
        );
        assert_eq!(invalid.status(), AnalysisStatus::Invalid);
        let codes = invalid
            .diagnostics()
            .iter()
            .map(|diagnostic| diagnostic.code.as_str())
            .collect::<Vec<_>>();
        assert!(codes.contains(&"immutable-assignment"));
        assert!(codes.contains(&"receiver-scope"));
        assert!(codes.contains(&"invalid-loop-limit"));
        assert!(codes.contains(&"invalid-control-transfer"));
    }

    #[test]
    fn method_calls_and_struct_field_projections_use_receiver_types() {
        let valid = analyze(
            r#"
struct Counter { value: Int }
impl Counter { fn add(self, amount: Int) -> Int { self.value + amount } }
fn evaluate(counter: Counter) -> Int { counter.add(2) }
fn main() {}
"#,
        );
        assert_eq!(
            valid.status(),
            AnalysisStatus::Valid,
            "{:?}",
            valid.diagnostics()
        );

        let invalid = analyze(
            r#"
struct Counter { value: Int }
struct Other { value: Int }
impl Counter { fn add(self, amount: Int) -> Int { self.value + amount } }
fn evaluate(counter: Counter, other: Other) {
    let missing: Int = counter.add();
    let wrong: Int = counter.add("bad");
    let unknown: Int = other.add(1);
}
fn main() {}
"#,
        );
        assert_eq!(invalid.status(), AnalysisStatus::Invalid);
        let codes = invalid
            .diagnostics()
            .iter()
            .map(|diagnostic| diagnostic.code.as_str())
            .collect::<Vec<_>>();
        assert!(codes.contains(&"call-arity"));
        assert!(codes.contains(&"call-argument-type"));
        assert!(codes.contains(&"unknown-member"));
    }

    #[test]
    fn expression_statements_require_unit_or_explicit_discard() {
        let valid = analyze(
            r#"
fn unit() {}
fn value() -> Int { 1 }
fn check() {
    unit();
    discard value();
    let retained: Int = 1;
    discard retained;
}
fn main() {}
"#,
        );
        assert_eq!(
            valid.status(),
            AnalysisStatus::Valid,
            "{:?}",
            valid.diagnostics()
        );

        let invalid = analyze(
            r#"
fn value() -> Int { 1 }
fn check() { value(); }
fn main() {}
"#,
        );
        assert_eq!(invalid.status(), AnalysisStatus::Invalid);
        assert!(
            invalid
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code.as_str() == "discard-required")
        );
    }

    #[test]
    fn impl_targets_are_package_structs() {
        let valid = analyze(
            r#"
struct Counter { value: Int }
impl Counter { fn get_value(self) -> Int { self.value } }
fn main() {}
"#,
        );
        assert_eq!(
            valid.status(),
            AnalysisStatus::Valid,
            "{:?}",
            valid.diagnostics()
        );

        let invalid = analyze(
            r#"
enum Choice { Ready }
fn helper() {}
impl Choice { fn enum_method(self) {} }
impl helper { fn function_method(self) {} }
fn main() {}
"#,
        );
        assert_eq!(invalid.status(), AnalysisStatus::Invalid);
        let codes = invalid
            .diagnostics()
            .iter()
            .map(|diagnostic| diagnostic.code.as_str())
            .collect::<Vec<_>>();
        assert!(codes.contains(&"invalid-impl-target"));
    }

    #[test]
    fn contextual_blocks_and_statement_matches_propagate_completion() {
        let valid = analyze(
            r#"
agents { worker }
fn through_agent() -> Int { with worker { return 1; } }
fn through_session() -> Int { session(inline) { return 2; } }
fn select(value: Option<Int>) -> Int {
    match value { Some(item) => { return item; }, None => { return 0; }, }
}
fn main() {}
"#,
        );
        assert_eq!(
            valid.status(),
            AnalysisStatus::Valid,
            "{:?}",
            valid.diagnostics()
        );

        let invalid = analyze(
            r#"
fn check(value: Option<Int>) {
    match value {
        Some(item) => { let wrong: String = item; },
        Some(_) => {},
    }
}
fn main() {}
"#,
        );
        assert_eq!(invalid.status(), AnalysisStatus::Invalid);
        let codes = invalid
            .diagnostics()
            .iter()
            .map(|diagnostic| diagnostic.code.as_str())
            .collect::<Vec<_>>();
        assert!(codes.contains(&"type-mismatch"));
        assert!(codes.contains(&"redundant-pattern"));
        assert!(codes.contains(&"nonexhaustive-match"));
    }

    #[test]
    fn operation_expressions_use_declared_results_and_action_signatures() {
        let valid = analyze(
            r#"
action read_only lookup(value: Int) -> String;
fn operate(value: Int) -> Result<String,OperationError> {
    let generated: String = prompt "Generate a value." -> String;
    let judgment: Decision = decide "Is the value acceptable?";
    let loaded: String = action lookup(value);
    discard generated;
    discard judgment;
    attempt action lookup(value)
}
fn main() {}
"#,
        );
        assert_eq!(
            valid.status(),
            AnalysisStatus::Valid,
            "{:?}",
            valid.diagnostics()
        );

        let invalid = analyze(
            r#"
action read_only lookup(value: Int) -> String;
fn operate() {
    let generated: Int = prompt "Generate a value." -> String;
    let judgment: Bool = decide "Is the value acceptable?";
    let loaded: String = action lookup("wrong");
}
fn main() {}
"#,
        );
        assert_eq!(invalid.status(), AnalysisStatus::Invalid);
        let codes = invalid
            .diagnostics()
            .iter()
            .map(|diagnostic| diagnostic.code.as_str())
            .collect::<Vec<_>>();
        assert!(codes.contains(&"type-mismatch"));
        assert!(codes.contains(&"call-argument-type"));
    }

    #[test]
    fn compile_time_boolean_facts_and_loop_kinds_refine_completion() {
        let valid = analyze(
            r#"
fn literal_true() -> Int { if true { return 1; } }
fn literal_false() -> Int { if false {} else { return 2; } }
fn composed() -> Int { if !(true && false) { return 3; } }
fn forever() -> Int { loop { return 4; } }
fn post_test() -> Int { until { return 5; } when false; }
fn main() {}
"#,
        );
        assert_eq!(
            valid.status(),
            AnalysisStatus::Valid,
            "{:?}",
            valid.diagnostics()
        );

        let invalid = analyze(
            r#"
fn excluded() -> Int { if false { return 1; } }
fn pretest() -> Int { while false { return 2; } }
fn main() {}
"#,
        );
        assert_eq!(invalid.status(), AnalysisStatus::Invalid);
        assert_eq!(
            invalid
                .diagnostics()
                .iter()
                .filter(|diagnostic| diagnostic.code.as_str() == "missing-result")
                .count(),
            2
        );
    }

    #[test]
    fn sealed_builtins_unary_operators_and_list_indices_are_typed() {
        let valid = analyze(
            r#"
fn evaluate(text: String, items: List<Int>, number: Int, float: Float) -> Bool {
    let text_len: Int = text.len();
    let contains: Bool = text.contains("x");
    let item_count: Int = items.len();
    let converted: Float = number.to_float();
    let integral: Option<Int> = float.to_int();
    let projected: Int = items[number];
    discard item_count;
    discard converted;
    discard integral;
    discard projected;
    !false && -number < text_len
}
fn main() {}
"#,
        );
        assert_eq!(
            valid.status(),
            AnalysisStatus::Valid,
            "{:?}",
            valid.diagnostics()
        );

        let invalid = analyze(
            r#"
fn evaluate(text: String, items: List<Int>) {
    let wrong_argument: Bool = text.contains(1);
    let wrong_index: Int = items["zero"];
    let wrong_unary: String = !text;
    let wrong_receiver: Bool = items.contains("x");
}
fn main() {}
"#,
        );
        assert_eq!(invalid.status(), AnalysisStatus::Invalid);
        let codes = invalid
            .diagnostics()
            .iter()
            .map(|diagnostic| diagnostic.code.as_str())
            .collect::<Vec<_>>();
        assert!(codes.contains(&"call-argument-type"));
        assert!(codes.contains(&"projection-index-type"));
        assert!(codes.contains(&"invalid-primitive"), "{codes:?}");
        assert!(codes.contains(&"unknown-member"));
    }

    #[test]
    fn constructors_and_patterns_require_unambiguous_compatible_types() {
        let invalid = analyze(
            r#"
struct Pair { left: Int }
fn check(value: Int) {
    let duplicate: Pair = Pair { left: 1, left: 2 };
    discard Some(1);
    discard None;
    discard Ok(1);
    match value { Some(_) => {} }
}
fn main() {}
"#,
        );
        assert_eq!(invalid.status(), AnalysisStatus::Invalid);
        let codes = invalid
            .diagnostics()
            .iter()
            .map(|diagnostic| diagnostic.code.as_str())
            .collect::<Vec<_>>();
        assert!(codes.contains(&"duplicate-struct-field"), "{codes:?}");
        assert!(codes.contains(&"ambiguous-constructor-type"), "{codes:?}");
        assert!(codes.contains(&"incompatible-pattern"), "{codes:?}");
    }

    #[test]
    fn callable_kinds_and_enum_constructor_shapes_are_exact() {
        let invalid = analyze(
            r#"
enum Choice { Empty, Value(Int) }
action read_only lookup(value: Int) -> String;
fn helper() {}
fn check() {
    let ordinary: String = lookup(1);
    action helper();
    let missing: Choice = Choice::Value;
    let extra: Choice = Choice::Empty(1);
}
fn main() {}
"#,
        );
        assert_eq!(invalid.status(), AnalysisStatus::Invalid);
        let codes = invalid
            .diagnostics()
            .iter()
            .map(|diagnostic| diagnostic.code.as_str())
            .collect::<Vec<_>>();
        assert!(codes.contains(&"invalid-call-target"), "{codes:?}");
        assert!(codes.contains(&"invalid-action-target"), "{codes:?}");
        assert!(codes.contains(&"invalid-enum-constructor"), "{codes:?}");
    }

    #[test]
    fn value_contexts_and_sealed_types_obey_exact_semantics() {
        let valid = analyze(
            r#"
agents { worker }
fn contexts() -> Int { with worker { session(inline) { 1 } } }
fn inspect(error: OperationError) -> String {
    match error {
        OperationError::Declined(message) => message,
        OperationError::InvalidOutput => "invalid",
        OperationError::ProviderFailure(message) => message,
        OperationError::Timeout(message) => message,
        OperationError::PolicyDenied(message) => message,
        OperationError::Cancelled(message) => message,
        OperationError::UnknownOutcome((operation_id, _)) => operation_id,
    }
}
fn main() {}
"#,
        );
        assert_eq!(
            valid.status(),
            AnalysisStatus::Valid,
            "{:?}",
            valid.diagnostics()
        );

        let invalid = analyze(
            r#"
fn sealed(mut decision: Decision) {
    decision.decision = false;
    match decision { _ => {} }
}
fn main() {}
"#,
        );
        assert_eq!(invalid.status(), AnalysisStatus::Invalid);
        let codes = invalid
            .diagnostics()
            .iter()
            .map(|diagnostic| diagnostic.code.as_str())
            .collect::<Vec<_>>();
        assert!(codes.contains(&"sealed-value-operation"), "{codes:?}");
    }

    #[test]
    fn spawned_blocks_match_their_declared_results() {
        let valid = analyze(
            r#"
fn check() {
    spawn first -> Int { 1 }
    spawn second { return; }
}
fn main() {}
"#,
        );
        assert_eq!(
            valid.status(),
            AnalysisStatus::Valid,
            "{:?}",
            valid.diagnostics()
        );

        let invalid = analyze(
            r#"
fn check() {
    spawn wrong -> String { 2 }
    spawn missing -> Int {}
}
fn main() {}
"#,
        );
        assert_eq!(invalid.status(), AnalysisStatus::Invalid);
        let codes = invalid
            .diagnostics()
            .iter()
            .map(|diagnostic| diagnostic.code.as_str())
            .collect::<Vec<_>>();
        assert!(codes.contains(&"type-mismatch"), "{codes:?}");
        assert!(codes.contains(&"missing-result"), "{codes:?}");
    }

    #[test]
    fn deep_types_and_long_declaration_graphs_are_stack_safe() {
        let depth = 512;
        let descriptor = format!("{}Int{}", "List<".repeat(depth), ">".repeat(depth));
        let deep = analyze(&format!(
            "struct Deep {{ value: {descriptor} }}\nfn main() {{}}"
        ));
        assert_eq!(
            deep.status(),
            AnalysisStatus::Valid,
            "{:?}",
            deep.diagnostics()
        );
        assert!(
            deep.types()
                .iter()
                .any(|fact| fact.descriptor.canonical_string() == descriptor)
        );

        let declarations = (0..256)
            .map(|index| {
                if index == 255 {
                    format!("struct Node{index} {{ value: Int }}")
                } else {
                    format!("struct Node{index} {{ next: Node{} }}", index + 1)
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        let graph = analyze(&format!("{declarations}\nfn main() {{}}"));
        assert_eq!(
            graph.status(),
            AnalysisStatus::Valid,
            "{:?}",
            graph.diagnostics()
        );
    }

    #[test]
    fn let_and_if_let_patterns_require_compatible_shapes() {
        let invalid = analyze(
            r#"
fn check(value: Int) {
    let (left, right): Int = 1;
    if let Some(item) = value {
        discard item;
    }
}
fn main() {}
"#,
        );
        assert_eq!(invalid.status(), AnalysisStatus::Invalid);
        assert_eq!(
            invalid
                .diagnostics()
                .iter()
                .filter(|diagnostic| diagnostic.code.as_str() == "incompatible-pattern")
                .count(),
            2,
            "{:?}",
            invalid.diagnostics()
        );
    }
}
