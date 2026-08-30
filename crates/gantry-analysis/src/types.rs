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
use gantry_ir::{ArtifactLimits, TypeDescriptor, TypeDescriptorError};

use crate::bodies::check_package_bodies;
use crate::effects::analyze_workflow_facts;
use crate::lowering::{LoweringError, lower_package_artifacts, lower_package_manifest};
use crate::schemas::{SchemaAnalysisError, analyze_generated_schemas};
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
    analyze_package_types_with_artifact_limits(phase, ArtifactLimits::MAXIMUM)
}

/// Resolves and validates a package while enforcing the supplied analyzer
/// artifact limits during generated-schema construction.
pub fn analyze_package_types_with_artifact_limits(
    phase: &CompletedSyntaxPhase,
    artifact_limits: ArtifactLimits,
) -> Result<TypedPackage, AnalysisError> {
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
    let body_types = check_package_bodies(
        phase.parsed_sources(),
        &facts_by_source,
        &structure,
        &mut type_diagnostics,
    )?;
    let (workflows, actions) = analyze_workflow_facts(
        phase.parsed_sources(),
        &facts_by_source,
        &structure,
        &mut type_diagnostics,
    )?;
    let has_semantic_errors = diagnostics
        .iter()
        .chain(&type_diagnostics)
        .any(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error);
    let schema_result = if has_semantic_errors {
        Ok((None, None))
    } else {
        analyze_generated_schemas(
            phase.parsed_sources(),
            &facts_by_source,
            &structure,
            &workflows,
            artifact_limits,
        )
    };

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
    let (entry, schemas) = match schema_result {
        Ok(inventory) => inventory,
        Err(SchemaAnalysisError::ResourceLimit(error)) => {
            return Err(AnalysisError::ResourceLimit {
                error,
                diagnostics: retained,
            });
        }
        Err(SchemaAnalysisError::Invariant) => return Err(AnalysisError::Invariant),
    };
    let (manifest, canonical_ir, source_map) = if status == AnalysisStatus::Valid {
        let artifacts = match lower_package_artifacts(
            phase.snapshot(),
            phase.parsed_sources(),
            &body_types,
            &workflows,
            artifact_limits,
        ) {
            Ok(artifacts) => artifacts,
            Err(LoweringError::ResourceLimit(error)) => {
                return Err(AnalysisError::ResourceLimit {
                    error,
                    diagnostics: retained,
                });
            }
            Err(LoweringError::Invariant) => return Err(AnalysisError::Invariant),
        };
        (
            Some(artifacts.manifest),
            Some(artifacts.canonical_ir),
            Some(artifacts.source_map),
        )
    } else {
        let manifest = if phase.module_resolution_issues().is_empty() {
            match lower_package_manifest(phase.snapshot(), artifact_limits) {
                Ok(manifest) => Some(manifest),
                Err(LoweringError::ResourceLimit(_)) => None,
                Err(LoweringError::Invariant) => return Err(AnalysisError::Invariant),
            }
        } else {
            None
        };
        (manifest, None, None)
    };
    Ok(TypedPackage {
        status,
        structure,
        types: facts,
        workflows,
        actions,
        entry,
        schemas,
        manifest,
        canonical_ir,
        source_map,
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

    use gantry_core::portable::FrontendResourceCode;
    use gantry_core::source::SourceLimits;
    use gantry_frontend::validate_package_syntax;
    use gantry_ir::ArtifactLimits;

    use super::{analyze_package_types, analyze_package_types_with_artifact_limits};
    use crate::{AnalysisError, AnalysisStatus};

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
        let syntax = syntax(source);
        analyze_package_types(&syntax)
            .unwrap_or_else(|error| panic!("type analysis failed: {error:?}"))
    }

    fn syntax(source: &str) -> gantry_frontend::CompletedSyntaxPhase {
        let root = TempDirectory::new();
        root.write(source);
        let limits = SourceLimits::new(4, 65_536, 65_536, 65_536, 64)
            .unwrap_or_else(|_| unreachable!("positive limits"));
        validate_package_syntax(&root.0, limits)
            .unwrap_or_else(|error| panic!("syntax failed: {error:?}"))
    }

    #[test]
    fn valid_packages_include_bounded_ir_source_map_and_manifest_artifacts() {
        let package = analyze("fn main() {}");
        assert_eq!(
            package.status(),
            AnalysisStatus::Valid,
            "{:?}",
            package.diagnostics()
        );

        let manifest = package
            .manifest()
            .unwrap_or_else(|| unreachable!("valid package has a source manifest"));
        assert_eq!(manifest.files().len(), 1);
        assert_eq!(manifest.files()[0].package_path().as_str(), "main.gnt");

        let ir = package
            .canonical_ir()
            .unwrap_or_else(|| unreachable!("valid package has canonical IR"));
        assert_eq!(ir.workflows().len(), 1);
        assert_eq!(ir.workflows()[0].path.as_str(), "crate::main");
        assert_eq!(
            ir.workflows()[0].signature.as_str(),
            "fn crate::main()->Unit"
        );

        let source_map = package
            .source_map()
            .unwrap_or_else(|| unreachable!("valid package has a source map"));
        assert_eq!(source_map.entries().len(), ir.workflows()[0].nodes.len());
    }

    #[test]
    fn source_invalid_packages_expose_only_complete_audit_provenance() {
        let complete = analyze("fn main() -> Int { \"wrong\" }");
        assert_eq!(complete.status(), AnalysisStatus::Invalid);
        assert!(complete.manifest().is_some());
        assert!(complete.canonical_ir().is_none());
        assert!(complete.source_map().is_none());

        let root = TempDirectory::new();
        root.write("mod absent; fn main() {}");
        let syntax = validate_package_syntax(
            &root.0,
            SourceLimits::new(4, 65_536, 65_536, 65_536, 64)
                .unwrap_or_else(|_| unreachable!("positive limits")),
        )
        .unwrap_or_else(|error| panic!("syntax failed: {error:?}"));
        let incomplete = analyze_package_types(&syntax)
            .unwrap_or_else(|error| panic!("analysis failed operationally: {error:?}"));
        assert_eq!(incomplete.status(), AnalysisStatus::Invalid);
        assert!(incomplete.manifest().is_none());
        assert!(incomplete.canonical_ir().is_none());
        assert!(incomplete.source_map().is_none());
    }

    #[test]
    fn canonical_ir_ignores_cosmetic_source_but_artifact_limits_remain_exact() {
        fn artifacts(source: &str) -> (Vec<u8>, Vec<u8>) {
            let package = analyze(source);
            assert_eq!(
                package.status(),
                AnalysisStatus::Valid,
                "{:?}",
                package.diagnostics()
            );
            let ir = package
                .canonical_ir()
                .unwrap_or_else(|| unreachable!("valid package has canonical IR"))
                .artifact()
                .canonical_bytes()
                .to_vec();
            let manifest = package
                .manifest()
                .unwrap_or_else(|| unreachable!("valid package has a source manifest"))
                .artifact()
                .canonical_bytes()
                .to_vec();
            (ir, manifest)
        }

        let compact = artifacts("fn main() { discard prompt \"x\" -> String; }");
        let cosmetic = artifacts(
            r#"
// Cosmetic source changes affect provenance, not canonical IR.
fn main() {
    discard prompt "x" -> String;
}
"#,
        );
        assert_eq!(compact.0, cosmetic.0);
        assert_ne!(compact.1, cosmetic.1);

        let semantic = artifacts("fn main() { discard prompt \"different\" -> String; }");
        assert_ne!(compact.0, semantic.0);

        let root = TempDirectory::new();
        root.write("fn main() {}");
        let syntax = validate_package_syntax(
            &root.0,
            SourceLimits::new(4, 65_536, 65_536, 65_536, 64)
                .unwrap_or_else(|_| unreachable!("positive limits")),
        )
        .unwrap_or_else(|error| panic!("syntax failed: {error:?}"));
        let result = analyze_package_types_with_artifact_limits(
            &syntax,
            ArtifactLimits {
                canonical_ir_bytes: 1,
                ..ArtifactLimits::MAXIMUM
            },
        );
        assert!(matches!(
            result,
            Err(AnalysisError::ResourceLimit { error, diagnostics })
                if error.code == FrontendResourceCode::CanonicalIrByteLimit
                    && diagnostics.is_empty()
        ));
    }

    #[test]
    fn canonical_lowering_preserves_operation_and_task_control_sites() {
        let package = analyze(
            r#"
fn helper() -> String { "value" }
fn main() {
    discard helper();
    discard prompt "Generate." -> String;
    spawn task { return; }
    discard join(task);
}
"#,
        );
        assert_eq!(
            package.status(),
            AnalysisStatus::Valid,
            "{:?}",
            package.diagnostics()
        );

        let facts = package
            .workflows()
            .iter()
            .find(|workflow| workflow.path.as_str() == "crate::main")
            .unwrap_or_else(|| unreachable!("main workflow facts are present"));
        let ir = package
            .canonical_ir()
            .unwrap_or_else(|| unreachable!("valid package has canonical IR"));
        let main = ir
            .workflows()
            .iter()
            .find(|workflow| workflow.path.as_str() == "crate::main")
            .unwrap_or_else(|| unreachable!("main workflow is present"));
        let nodes = &main.nodes;
        for call in &facts.calls {
            assert!(nodes.iter().any(|node| {
                node.position == *call.site.position()
                    && node.form == gantry_ir::generated::CoreForm::Call
                    && node.ty == gantry_ir::TypeDescriptor::STRING
            }));
        }
        for operation in &facts.operations {
            assert!(nodes.iter().any(|node| {
                node.position == *operation.id.position()
                    && node.form == gantry_ir::generated::CoreForm::Operation
            }));
        }
        for control in &facts.task_controls {
            let form = match control.kind.wire_name() {
                "spawn" => gantry_ir::generated::CoreForm::Spawn,
                "join" | "joinall" => gantry_ir::generated::CoreForm::Join,
                "detach" => gantry_ir::generated::CoreForm::BackgroundTransfer,
                _ => unreachable!("closed task-control kind"),
            };
            assert!(
                nodes
                    .iter()
                    .any(|node| { node.position == *control.id.position() && node.form == form })
            );
        }

        let source_map = package
            .source_map()
            .unwrap_or_else(|| unreachable!("valid package has a source map"));
        assert_eq!(
            source_map
                .entries()
                .iter()
                .filter(|entry| entry.workflow.as_str() == "crate::main")
                .count(),
            nodes.len()
        );
    }

    #[test]
    fn canonical_lowering_covers_core_forms_and_exact_operation_order() {
        let package = analyze(
            r#"
agents { worker }
default agent = worker;
action read_only inspect(value: Int) -> String;
struct Holder { item: Int }
fn helper(value: Int) -> Int { return value; }
fn main(flag: Bool) -> Int {
    let mut value: Int = 1;
    let holder: Holder = Holder { item: value };
    value = holder.item;
    value = helper(value);
    if flag { value = 2; } else { value = 3; }
    loop(limit = 1) { break; }
    with worker { session(inline) { discard attempt action inspect(value); } }
    spawn joined -> Int { value }
    value = join(joined);
    spawn background { return; }
    detach(background);
    discard prompt "${value}" using { chosen: value } -> String;
    value
}
"#,
        );
        assert_eq!(
            package.status(),
            AnalysisStatus::Valid,
            "{:?}",
            package.diagnostics()
        );

        let ir = package
            .canonical_ir()
            .unwrap_or_else(|| unreachable!("valid package has canonical IR"));
        let forms = ir
            .workflows()
            .iter()
            .flat_map(|workflow| workflow.nodes.iter().map(|node| node.form))
            .collect::<std::collections::BTreeSet<_>>();
        for expected in [
            gantry_ir::generated::CoreForm::Aggregate,
            gantry_ir::generated::CoreForm::Assignment,
            gantry_ir::generated::CoreForm::Attempt,
            gantry_ir::generated::CoreForm::BackgroundTransfer,
            gantry_ir::generated::CoreForm::Branch,
            gantry_ir::generated::CoreForm::Call,
            gantry_ir::generated::CoreForm::CancellationCheck,
            gantry_ir::generated::CoreForm::Join,
            gantry_ir::generated::CoreForm::Literal,
            gantry_ir::generated::CoreForm::Loop,
            gantry_ir::generated::CoreForm::Operation,
            gantry_ir::generated::CoreForm::Projection,
            gantry_ir::generated::CoreForm::Return,
            gantry_ir::generated::CoreForm::Sequence,
            gantry_ir::generated::CoreForm::SessionScope,
            gantry_ir::generated::CoreForm::Spawn,
            gantry_ir::generated::CoreForm::Variable,
            gantry_ir::generated::CoreForm::WithScope,
        ] {
            assert!(forms.contains(&expected), "missing {expected:?}: {forms:?}");
        }

        for facts in package.workflows() {
            let workflow = ir
                .workflows()
                .iter()
                .find(|workflow| workflow.path == facts.path)
                .unwrap_or_else(|| unreachable!("fact workflow has lowered IR"));
            assert_eq!(
                workflow
                    .nodes
                    .iter()
                    .filter(|node| node.form == gantry_ir::generated::CoreForm::Operation)
                    .map(|node| node.position.clone())
                    .collect::<Vec<_>>(),
                facts
                    .operations
                    .iter()
                    .map(|operation| operation.id.position().clone())
                    .collect::<Vec<_>>()
            );
        }

        let main = ir
            .workflows()
            .iter()
            .find(|workflow| workflow.path.as_str() == "crate::main")
            .unwrap_or_else(|| unreachable!("main workflow is lowered"));
        let action = main
            .nodes
            .iter()
            .filter_map(|node| node.operation.as_ref())
            .find(|operation| operation.kind.wire_name() == "action")
            .unwrap_or_else(|| unreachable!("action operation is retained"));
        assert_eq!(
            action.action.as_ref().map(gantry_ir::CanonicalPath::as_str),
            Some("crate::inspect")
        );
        assert_eq!(
            action.recovery.map(|recovery| recovery.wire_name()),
            Some("read_only")
        );

        let prompt = main
            .nodes
            .iter()
            .filter_map(|node| node.operation.as_ref())
            .find(|operation| operation.kind.wire_name() == "prompt")
            .unwrap_or_else(|| unreachable!("prompt operation is retained"));
        assert_eq!(prompt.interpolation_inputs, [0]);
        assert_eq!(prompt.named_inputs.len(), 1);

        assert_eq!(
            main.nodes
                .iter()
                .filter_map(|node| node.task_control.as_ref())
                .map(|task| (
                    task.kind.wire_name(),
                    task.handles.iter().map(AsRef::as_ref).collect::<Vec<_>>()
                ))
                .collect::<Vec<_>>(),
            [
                ("spawn", vec!["joined"]),
                ("join", vec!["joined"]),
                ("spawn", vec!["background"]),
                ("detach", vec!["background"]),
            ]
        );
    }

    #[test]
    fn analyzer_artifact_limits_are_exact_at_every_lowering_boundary() {
        let phase = syntax("fn main() { discard prompt \"bounded\" -> String; }");
        let baseline = analyze_package_types(&phase)
            .unwrap_or_else(|error| panic!("baseline analysis failed: {error:?}"));
        let lengths = [
            (
                baseline
                    .manifest()
                    .unwrap_or_else(|| unreachable!("manifest is present"))
                    .artifact()
                    .canonical_bytes()
                    .len(),
                FrontendResourceCode::PackageSourceManifestByteLimit,
            ),
            (
                baseline
                    .canonical_ir()
                    .unwrap_or_else(|| unreachable!("IR is present"))
                    .artifact()
                    .canonical_bytes()
                    .len(),
                FrontendResourceCode::CanonicalIrByteLimit,
            ),
            (
                baseline
                    .source_map()
                    .unwrap_or_else(|| unreachable!("source map is present"))
                    .artifact()
                    .canonical_bytes()
                    .len(),
                FrontendResourceCode::SourceMapByteLimit,
            ),
        ];

        for (index, (length, code)) in lengths.into_iter().enumerate() {
            let length =
                u64::try_from(length).unwrap_or_else(|_| unreachable!("artifact length fits"));
            let limits = |limit| {
                let mut limits = ArtifactLimits::MAXIMUM;
                match index {
                    0 => limits.package_source_manifest_bytes = limit,
                    1 => limits.canonical_ir_bytes = limit,
                    2 => limits.source_map_bytes = limit,
                    _ => unreachable!("three lowering artifacts"),
                }
                limits
            };
            let at = analyze_package_types_with_artifact_limits(&phase, limits(length));
            assert!(at.is_ok(), "{code:?} must fit at its exact length");
            let above = analyze_package_types_with_artifact_limits(
                &phase,
                limits(length.saturating_add(1)),
            );
            assert!(above.is_ok(), "{code:?} must fit one byte above");
            let below = analyze_package_types_with_artifact_limits(
                &phase,
                limits(length.saturating_sub(1)),
            );
            assert!(matches!(
                below,
                Err(AnalysisError::ResourceLimit { error, diagnostics })
                    if error.code == code
                        && error.limit == length.saturating_sub(1)
                        && diagnostics.is_empty()
            ));
        }

        assert_eq!(
            baseline
                .manifest()
                .unwrap_or_else(|| unreachable!("manifest is present"))
                .artifact()
                .sha256_hex()
                .len(),
            64
        );
        assert_eq!(
            baseline
                .canonical_ir()
                .unwrap_or_else(|| unreachable!("IR is present"))
                .artifact()
                .sha256_hex()
                .len(),
            64
        );
        assert_eq!(
            baseline
                .source_map()
                .unwrap_or_else(|| unreachable!("source map is present"))
                .artifact()
                .sha256_hex()
                .len(),
            64
        );
    }

    #[test]
    fn large_lowering_traversals_are_iterative_and_complete() {
        let statement_count = 4_096;
        let mut source = String::from("fn main() { let mut value: Int = 0;");
        source.push_str(&"value = value;".repeat(statement_count));
        source.push('}');
        let package = analyze(&source);
        assert_eq!(
            package.status(),
            AnalysisStatus::Valid,
            "{:?}",
            package.diagnostics()
        );
        let workflow = &package
            .canonical_ir()
            .unwrap_or_else(|| unreachable!("IR is present"))
            .workflows()[0];
        assert!(workflow.nodes.len() > statement_count);
        assert!(
            workflow
                .nodes
                .windows(2)
                .all(|pair| pair[0].position < pair[1].position)
        );
        assert_eq!(
            package
                .source_map()
                .unwrap_or_else(|| unreachable!("source map is present"))
                .entries()
                .len(),
            workflow.nodes.len()
        );
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
    discard join(first);
    discard join(second);
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

    #[test]
    fn workflow_facts_include_direct_and_transitive_effects() {
        let package = analyze(
            r#"
action read_only inspect() -> String;
fn leaf() {
    discard prompt "Generate." -> String;
    discard action inspect();
}
fn wrapper() { leaf(); }
pure fn invalid() { wrapper(); }
pure fn clean() {}
fn main() {}
"#,
        );
        assert_eq!(package.status(), AnalysisStatus::Invalid);
        assert!(
            package
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code.as_str() == "impure-workflow")
        );

        let workflows = package
            .workflows()
            .iter()
            .map(|workflow| {
                (
                    workflow.path.as_str(),
                    workflow
                        .effects
                        .iter()
                        .map(|effect| effect.wire_name())
                        .collect::<Vec<_>>(),
                    workflow.calls.len(),
                    workflow.operations.len(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            workflows,
            [
                ("crate::clean", vec![], 0, 0),
                ("crate::invalid", vec!["prompt", "action(read_only)"], 1, 0,),
                ("crate::leaf", vec!["prompt", "action(read_only)"], 0, 2,),
                ("crate::main", vec![], 0, 0),
                ("crate::wrapper", vec!["prompt", "action(read_only)"], 1, 0,),
            ]
        );
        let contributors = package
            .workflows()
            .iter()
            .map(|workflow| {
                (
                    workflow.path.as_str(),
                    workflow
                        .action_contributors
                        .iter()
                        .map(|contributor| {
                            (
                                contributor.site.workflow().as_str(),
                                contributor.action.as_str(),
                                contributor.recovery.wire_name(),
                            )
                        })
                        .collect::<Vec<_>>(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            contributors,
            [
                ("crate::clean", vec![]),
                (
                    "crate::invalid",
                    vec![("crate::leaf", "crate::inspect", "read_only")],
                ),
                (
                    "crate::leaf",
                    vec![("crate::leaf", "crate::inspect", "read_only")],
                ),
                ("crate::main", vec![]),
                (
                    "crate::wrapper",
                    vec![("crate::leaf", "crate::inspect", "read_only")],
                ),
            ]
        );
    }

    #[test]
    fn workflow_facts_include_methods_and_method_call_effects() {
        let package = analyze(
            r#"
struct Worker { value: Int }
impl Worker {
    fn leaf(self) { discard prompt "Generate." -> String; }
    fn wrapper(self) { self.leaf(); }
}
pure fn invalid(worker: Worker) { worker.wrapper(); }
fn main() {}
"#,
        );
        assert_eq!(package.status(), AnalysisStatus::Invalid);
        assert!(
            package
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code.as_str() == "impure-workflow")
        );

        let workflows = package
            .workflows()
            .iter()
            .map(|workflow| {
                (
                    workflow.path.as_str(),
                    workflow.signature.as_str(),
                    workflow
                        .effects
                        .iter()
                        .map(|effect| effect.wire_name())
                        .collect::<Vec<_>>(),
                    workflow.calls.len(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            workflows,
            [
                (
                    "<crate::Worker>::leaf",
                    "fn <crate::Worker>::leaf(self)->Unit",
                    vec!["prompt"],
                    0,
                ),
                (
                    "<crate::Worker>::wrapper",
                    "fn <crate::Worker>::wrapper(self)->Unit",
                    vec!["prompt"],
                    1,
                ),
                (
                    "crate::invalid",
                    "fn crate::invalid(crate::Worker)->Unit",
                    vec!["prompt"],
                    1,
                ),
                ("crate::main", "fn crate::main()->Unit", vec![], 0,),
            ]
        );
    }

    #[test]
    fn workflow_effects_are_stable_across_scc_and_declaration_order() {
        fn projected(source: &str) -> Vec<(String, Vec<&'static str>, Vec<String>)> {
            let package = analyze(source);
            assert_eq!(
                package.status(),
                AnalysisStatus::Valid,
                "{:?}",
                package.diagnostics()
            );
            package
                .workflows()
                .iter()
                .map(|workflow| {
                    (
                        workflow.path.to_string(),
                        workflow
                            .effects
                            .iter()
                            .map(|effect| effect.wire_name())
                            .collect(),
                        workflow
                            .calls
                            .iter()
                            .map(|call| call.callee.to_string())
                            .collect(),
                    )
                })
                .collect()
        }

        let first = projected(
            r#"
action read_only inspect() -> Unit;
fn alpha() { beta(); }
fn beta() { gamma(); }
fn gamma() { alpha(); action inspect(); }
fn main() {}
"#,
        );
        let reordered = projected(
            r#"
fn gamma() { alpha(); action inspect(); }
fn main() {}
fn beta() { gamma(); }
action read_only inspect() -> Unit;
fn alpha() { beta(); }
"#,
        );
        assert_eq!(first, reordered);
        assert_eq!(
            first,
            [
                (
                    "crate::alpha".to_owned(),
                    vec!["action(read_only)"],
                    vec!["crate::beta".to_owned()],
                ),
                (
                    "crate::beta".to_owned(),
                    vec!["action(read_only)"],
                    vec!["crate::gamma".to_owned()],
                ),
                (
                    "crate::gamma".to_owned(),
                    vec!["action(read_only)"],
                    vec!["crate::alpha".to_owned()],
                ),
                ("crate::main".to_owned(), vec![], vec![]),
            ]
        );
    }

    #[test]
    fn deep_effect_schema_and_ownership_graphs_are_stack_safe() {
        let call_depth = 256;
        let mut callables = (0..call_depth)
            .map(|index| {
                if index + 1 == call_depth {
                    format!("fn step{index}() {{ discard prompt \"done\" -> Unit; }}")
                } else {
                    format!("fn step{index}() {{ step{}(); }}", index + 1)
                }
            })
            .collect::<Vec<_>>();
        callables.push("fn main() { step0(); }".to_owned());
        let calls = analyze(&callables.join("\n"));
        assert_eq!(
            calls.status(),
            AnalysisStatus::Valid,
            "{:?}",
            calls.diagnostics()
        );
        assert!(calls.workflows().iter().all(|workflow| {
            workflow.path.as_str() == "crate::main"
                || workflow
                    .effects
                    .iter()
                    .any(|effect| effect.wire_name() == "prompt")
        }));

        let schema_depth = 256;
        let descriptor = format!(
            "{}String{}",
            "List<".repeat(schema_depth),
            ">".repeat(schema_depth)
        );
        let schemas = analyze(&format!(
            "fn main(value: {descriptor}) -> {descriptor} {{ value }}"
        ));
        assert_eq!(
            schemas.status(),
            AnalysisStatus::Valid,
            "{:?}",
            schemas.diagnostics()
        );
        assert_eq!(
            schemas.schemas().map(|object| object.entries().len()),
            Some(1)
        );

        let handle_count = 256;
        let mut ownership = String::from("fn controls() {\n");
        for index in 0..handle_count {
            ownership.push_str(&format!("spawn task{index} {{ return; }}\n"));
        }
        ownership.push_str("discard joinall();\n}\nfn main() {}\n");
        let ownership = analyze(&ownership);
        assert_eq!(
            ownership.status(),
            AnalysisStatus::Valid,
            "{:?}",
            ownership.diagnostics()
        );
        let joinall = ownership
            .workflows()
            .iter()
            .find(|workflow| workflow.path.as_str() == "crate::controls")
            .and_then(|workflow| {
                workflow
                    .task_controls
                    .iter()
                    .find(|site| site.kind.wire_name() == "joinall")
            })
            .unwrap_or_else(|| unreachable!("joinall site is present"));
        assert_eq!(joinall.handles.len(), handle_count);
    }

    #[test]
    fn entry_inventory_retains_exact_bounded_generated_schemas() {
        let package = analyze(
            r#"
fn main(values: List<Int>) -> Option<String> {
    discard values;
    None
}
"#,
        );
        assert_eq!(
            package.status(),
            AnalysisStatus::Valid,
            "{:?}",
            package.diagnostics()
        );

        let entry = package
            .entry()
            .unwrap_or_else(|| unreachable!("valid package has an entry inventory"));
        assert_eq!(entry.path.as_str(), "crate::main");
        assert_eq!(
            entry.parameter.as_ref().map(|ty| ty.canonical_string()),
            Some("List<Int>".to_owned())
        );
        assert_eq!(entry.result.canonical_string(), "Option<String>");

        let schemas = package
            .schemas()
            .unwrap_or_else(|| unreachable!("entry boundaries require schemas"));
        assert_eq!(
            schemas
                .entries()
                .iter()
                .map(|(ty, schema)| (
                    ty.canonical_string(),
                    std::str::from_utf8(schema).unwrap_or_else(|_| unreachable!("schema is UTF-8"))
                ))
                .collect::<Vec<_>>(),
            [
                (
                    "List<Int>".to_owned(),
                    "{\"$schema\":\"https://json-schema.org/draft/2020-12/schema\",\"items\":{\"maximum\":9007199254740991,\"minimum\":-9007199254740991,\"type\":\"integer\"},\"type\":\"array\"}",
                ),
                (
                    "Option<String>".to_owned(),
                    "{\"$schema\":\"https://json-schema.org/draft/2020-12/schema\",\"anyOf\":[{\"type\":\"null\"},{\"type\":\"string\"}]}",
                ),
            ]
        );
    }

    #[test]
    fn declared_schemas_include_reachable_defs_defaults_and_exact_limits() {
        let source = r#"
enum Choice { Empty, Number(Int) }
struct Report { choice: Choice, note: Option<String> = "fallback" }
fn main(value: Report) -> Report { value }
"#;
        let package = analyze(source);
        assert_eq!(
            package.status(),
            AnalysisStatus::Valid,
            "{:?}",
            package.diagnostics()
        );
        let schemas = package
            .schemas()
            .unwrap_or_else(|| unreachable!("entry boundaries require schemas"));
        assert_eq!(schemas.entries().len(), 1);
        assert_eq!(schemas.entries()[0].0.canonical_string(), "crate::Report");
        assert_eq!(
            std::str::from_utf8(&schemas.entries()[0].1),
            Ok(concat!(
                "{\"$defs\":{",
                "\"657e379315699414210b6d15b0da71d04a728697c220ea85f85795c9b27a9f87\":",
                "{\"additionalProperties\":false,\"properties\":{",
                "\"choice\":{\"$ref\":\"#/$defs/d1439d073a2f85be47d37f944e1bfd35fbe9a32bdba66cd73807801470415a28\"},",
                "\"note\":{\"anyOf\":[{\"type\":\"null\"},{\"type\":\"string\"}],\"default\":\"fallback\"}",
                "},\"required\":[\"choice\"],\"type\":\"object\"},",
                "\"d1439d073a2f85be47d37f944e1bfd35fbe9a32bdba66cd73807801470415a28\":",
                "{\"oneOf\":[",
                "{\"additionalProperties\":false,\"properties\":{\"variant\":{\"const\":\"Empty\",\"type\":\"string\"}},\"required\":[\"variant\"],\"type\":\"object\"},",
                "{\"additionalProperties\":false,\"properties\":{\"value\":{\"maximum\":9007199254740991,\"minimum\":-9007199254740991,\"type\":\"integer\"},\"variant\":{\"const\":\"Number\",\"type\":\"string\"}},\"required\":[\"variant\",\"value\"],\"type\":\"object\"}",
                "]}},",
                "\"$ref\":\"#/$defs/657e379315699414210b6d15b0da71d04a728697c220ea85f85795c9b27a9f87\",",
                "\"$schema\":\"https://json-schema.org/draft/2020-12/schema\"}"
            ))
        );

        let root = TempDirectory::new();
        root.write(source);
        let syntax = validate_package_syntax(
            &root.0,
            SourceLimits::new(4, 65_536, 65_536, 65_536, 64)
                .unwrap_or_else(|_| unreachable!("positive limits")),
        )
        .unwrap_or_else(|error| panic!("syntax failed: {error:?}"));
        let result = analyze_package_types_with_artifact_limits(
            &syntax,
            ArtifactLimits {
                generated_schema_bytes: 1,
                ..ArtifactLimits::MAXIMUM
            },
        );
        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("the generated schema object must exceed one byte"),
        };
        assert!(matches!(
            error,
            AnalysisError::ResourceLimit { error, diagnostics }
                if error.code == FrontendResourceCode::GeneratedSchemaByteLimit
                    && diagnostics.is_empty()
        ));
    }

    #[test]
    fn workflow_facts_record_task_controls_and_composite_effects() {
        let package = analyze(
            r#"
action idempotent write(value: Int) -> Unit;
fn controls() {
    spawn joined { return; }
    discard join(joined);
    spawn background { return; }
    detach(background);
    discard joinall();
    session(new) {}
    discard attempt action write(1);
}
fn main() {}
"#,
        );
        assert_eq!(
            package.status(),
            AnalysisStatus::Valid,
            "{:?}",
            package.diagnostics()
        );
        let controls = package
            .workflows()
            .iter()
            .find(|workflow| workflow.path.as_str() == "crate::controls")
            .unwrap_or_else(|| unreachable!("controls workflow is present"));
        assert_eq!(
            controls
                .effects
                .iter()
                .map(|effect| effect.wire_name())
                .collect::<Vec<_>>(),
            [
                "action(idempotent)",
                "spawn",
                "join",
                "background",
                "session",
                "attempt",
            ]
        );
        assert_eq!(
            controls
                .task_controls
                .iter()
                .map(|site| site.kind.wire_name())
                .collect::<Vec<_>>(),
            ["spawn", "join", "spawn", "detach", "joinall"]
        );
        assert_eq!(controls.operations.len(), 1);
        assert_eq!(
            controls.operations[0]
                .action
                .as_ref()
                .map(gantry_ir::CanonicalPath::as_str),
            Some("crate::write")
        );
        assert_eq!(
            package
                .actions()
                .iter()
                .map(|action| (
                    action.path.as_str(),
                    action.signature.as_str(),
                    action.recovery.wire_name(),
                    action.result.canonical_string(),
                ))
                .collect::<Vec<_>>(),
            [(
                "crate::write",
                "action[idempotent] crate::write(value:Int)->Unit",
                "idempotent",
                "Unit".to_owned(),
            )]
        );
    }

    #[test]
    fn task_control_sites_retain_static_handle_membership() {
        let package = analyze(
            r#"
fn controls() {
    spawn zebra -> Int { 1 }
    spawn alpha -> Int { 2 }
    detach(zebra);
    let values: Int = joinall();
    discard values;
}
fn main() {}
"#,
        );
        assert_eq!(
            package.status(),
            AnalysisStatus::Valid,
            "{:?}",
            package.diagnostics()
        );
        let controls = package
            .workflows()
            .iter()
            .find(|workflow| workflow.path.as_str() == "crate::controls")
            .unwrap_or_else(|| unreachable!("controls workflow is present"));
        assert_eq!(
            controls
                .task_controls
                .iter()
                .map(|site| {
                    (
                        site.kind.wire_name(),
                        site.handles.iter().map(AsRef::as_ref).collect::<Vec<_>>(),
                    )
                })
                .collect::<Vec<_>>(),
            [
                ("spawn", vec!["zebra"]),
                ("spawn", vec!["alpha"]),
                ("detach", vec!["zebra"]),
                ("joinall", vec!["alpha"]),
            ]
        );
    }

    #[test]
    fn joinall_membership_excludes_handles_consumed_on_every_path() {
        let package = analyze(
            r#"
fn controls(flag: Bool) -> String {
    spawn consumed -> Int { 1 }
    spawn selected -> String { "selected" }
    if flag {
        discard join(consumed);
    } else {
        detach(consumed);
    }
    joinall()
}
fn main() {}
"#,
        );
        assert_eq!(
            package.status(),
            AnalysisStatus::Valid,
            "{:?}",
            package.diagnostics()
        );
        let controls = package
            .workflows()
            .iter()
            .find(|workflow| workflow.path.as_str() == "crate::controls")
            .unwrap_or_else(|| unreachable!("controls workflow is present"));
        let joinall = controls
            .task_controls
            .iter()
            .find(|site| site.kind.wire_name() == "joinall")
            .unwrap_or_else(|| unreachable!("joinall site is present"));
        assert_eq!(
            joinall
                .handles
                .iter()
                .map(AsRef::as_ref)
                .collect::<Vec<_>>(),
            ["selected"]
        );
    }

    #[test]
    fn straight_line_task_handles_are_consumed_exactly_once() {
        let valid = analyze(
            r#"
fn controls() {
    spawn joined -> Int { 1 }
    let value: Int = join(joined);
    discard value;
    spawn background { return; }
    detach(background);
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
fn leaked() { spawn task { return; } }
fn repeated() { spawn task { return; } discard join(task); detach(task); }
fn duplicate() { spawn task { return; } discard join(task, task); }
fn foreign() {
    spawn parent { return; }
    spawn child { discard join(parent); }
    discard joinall();
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
        assert!(codes.contains(&"unconsumed-task-handle"), "{codes:?}");
        assert!(codes.contains(&"consumed-task-handle"), "{codes:?}");
        assert!(codes.contains(&"duplicate-task-handle"), "{codes:?}");
        assert!(codes.contains(&"foreign-task-handle"), "{codes:?}");
    }

    #[test]
    fn task_ownership_merges_all_control_flow_paths() {
        let valid = analyze(
            r#"
fn controls(flag: Bool) {
    spawn task { return; }
    if flag {
        discard join(task);
    } else {
        detach(task);
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
fn controls(flag: Bool) {
    spawn task { return; }
    if flag {
        discard join(task);
    }
}
fn main() {}
"#,
        );
        assert_eq!(invalid.status(), AnalysisStatus::Invalid);
        assert!(
            invalid
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code.as_str() == "inconsistent-task-ownership"),
            "{:?}",
            invalid.diagnostics()
        );
    }

    #[test]
    fn task_ownership_tracks_early_return_paths() {
        let valid = analyze(
            r#"
fn controls(flag: Bool) {
    spawn task { return; }
    if flag {
        discard join(task);
        return;
    }
    discard join(task);
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
fn controls(flag: Bool) {
    spawn task { return; }
    if flag { return; }
    discard join(task);
}
fn main() {}
"#,
        );
        assert_eq!(invalid.status(), AnalysisStatus::Invalid);
        assert!(
            invalid
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code.as_str() == "unconsumed-task-handle"),
            "{:?}",
            invalid.diagnostics()
        );
    }

    #[test]
    fn task_ownership_tracks_loop_transfer_paths() {
        let valid = analyze(
            r#"
fn controls(flags: List<Bool>) {
    for flag in flags {
        spawn task { return; }
        if flag {
            discard join(task);
            continue;
        }
        detach(task);
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
fn controls(flags: List<Bool>) {
    for flag in flags {
        spawn task { return; }
        if flag { continue; }
        discard join(task);
    }
}
fn main() {}
"#,
        );
        assert_eq!(invalid.status(), AnalysisStatus::Invalid);
        assert!(
            invalid
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code.as_str() == "unconsumed-task-handle"),
            "{:?}",
            invalid.diagnostics()
        );
    }

    #[test]
    fn task_ownership_flows_through_nested_contexts_and_branches() {
        let package = analyze(
            r#"
agents { worker }
default agent = worker;
fn controls(first: Bool, second: Bool) {
    spawn nested { return; }
    if first {
        if second { discard join(nested); } else { detach(nested); }
    } else {
        discard join(nested);
    }
    spawn scoped { return; }
    with worker { session(inline) { discard join(scoped); } }
}
fn main() {}
"#,
        );
        assert_eq!(
            package.status(),
            AnalysisStatus::Valid,
            "{:?}",
            package.diagnostics()
        );
    }

    #[test]
    fn task_ownership_checks_handles_declared_in_nested_branches() {
        let invalid = analyze(
            r#"
fn controls(flag: Bool) {
    if flag {
        spawn leaked { return; }
    } else {
        spawn consumed { return; }
        discard join(consumed);
    }
}
fn main() {}
"#,
        );
        assert_eq!(invalid.status(), AnalysisStatus::Invalid);
        assert!(
            invalid
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code.as_str() == "unconsumed-task-handle"),
            "{:?}",
            invalid.diagnostics()
        );

        let foreign = analyze(
            r#"
fn controls(flag: Bool) {
    spawn parent { return; }
    if flag {
        spawn child { discard join(parent); }
        discard join(child);
    }
    discard join(parent);
}
fn main() {}
"#,
        );
        assert_eq!(foreign.status(), AnalysisStatus::Invalid);
        assert!(
            foreign
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code.as_str() == "foreign-task-handle"),
            "{:?}",
            foreign.diagnostics()
        );
    }

    #[test]
    fn task_ownership_flows_through_value_contexts_and_matches() {
        let package = analyze(
            r#"
agents { worker }
default agent = worker;
fn matched(value: Option<Int>) -> Int {
    spawn task -> Int { 1 }
    match value {
        Some(_) => join(task),
        None => join(task),
    }
}
fn scoped() -> Int {
    spawn task -> Int { 1 }
    with worker { session(inline) { join(task) } }
}
fn main() {}
"#,
        );
        assert_eq!(
            package.status(),
            AnalysisStatus::Valid,
            "{:?}",
            package.diagnostics()
        );
    }

    #[test]
    fn task_ownership_flows_through_call_arguments() {
        let valid = analyze(
            r#"
fn consume(value: Int) { discard value; }
fn controls() {
    spawn task -> Int { 1 }
    consume(join(task));
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
fn consume(value: Int) { discard value; }
fn controls() {
    spawn task -> Int { 1 }
    consume(join(task));
    discard join(task);
}
fn main() {}
"#,
        );
        assert_eq!(invalid.status(), AnalysisStatus::Invalid);
        assert!(
            invalid
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code.as_str() == "consumed-task-handle"),
            "{:?}",
            invalid.diagnostics()
        );
    }

    #[test]
    fn join_results_follow_static_handle_membership() {
        let valid = analyze(
            r#"
fn named() -> Tuple<Int,String> {
    spawn first -> Int { 1 }
    spawn second -> String { "two" }
    join(first, second)
}
fn scoped() -> List<Int> {
    spawn first -> Int { 1 }
    spawn second -> Int { 2 }
    joinall()
}
fn empty() { discard joinall(); }
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
fn wrong() {
    spawn task -> Int { 1 }
    let value: String = join(task);
}
fn mixed() {
    spawn unit { return; }
    spawn value -> Int { 1 }
    discard joinall();
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
        assert!(codes.contains(&"mixed-task-results"), "{codes:?}");
    }

    #[test]
    fn task_ownership_is_checked_through_matches_and_loops() {
        let valid = analyze(
            r#"
fn matched(value: Option<Int>) {
    spawn task { return; }
    match value {
        Some(_) => { discard join(task); },
        None => { detach(task); },
    }
}
fn loop_local(values: List<Int>) {
    for value in values {
        spawn task { return; }
        discard join(task);
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
fn partial(value: Option<Int>) {
    spawn task { return; }
    match value {
        Some(_) => { discard join(task); },
        None => {},
    }
}
fn loop_consume(flag: Bool) {
    spawn task { return; }
    while flag { discard join(task); }
}
fn loop_leak(values: List<Int>) {
    for value in values { spawn task { return; } }
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
        assert!(codes.contains(&"inconsistent-task-ownership"), "{codes:?}");
        assert!(codes.contains(&"unconsumed-task-handle"), "{codes:?}");
    }
}
